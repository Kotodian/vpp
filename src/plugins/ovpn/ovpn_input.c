/*
 * ovpn_input.c - OpenVPN input node
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/udp/udp_local.h>
#include <ovpn/ovpn.h>
#include <ovpn/ovpn_packet.h>
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_handshake.h>

/* Input node next indices */
typedef enum
{
  OVPN_INPUT_NEXT_HANDOFF_HANDSHAKE,
  OVPN_INPUT_NEXT_HANDOFF_DATA,
  OVPN_INPUT_NEXT_IP4_INPUT,
  OVPN_INPUT_NEXT_IP6_INPUT,
  OVPN_INPUT_NEXT_HANDSHAKE,
  OVPN_INPUT_NEXT_DROP,
  OVPN_INPUT_N_NEXT,
} ovpn_input_next_t;

/* Error codes */
typedef enum
{
  OVPN_INPUT_ERROR_NONE,
  OVPN_INPUT_ERROR_TOO_SHORT,
  OVPN_INPUT_ERROR_INVALID_OPCODE,
  OVPN_INPUT_ERROR_PEER_NOT_FOUND,
  OVPN_INPUT_ERROR_DECRYPT_FAILED,
  OVPN_INPUT_ERROR_REPLAY,
  OVPN_INPUT_ERROR_NO_CRYPTO,
  OVPN_INPUT_N_ERROR,
} ovpn_input_error_t;

static char *ovpn_input_error_strings[] = {
  [OVPN_INPUT_ERROR_NONE] = "No error",
  [OVPN_INPUT_ERROR_TOO_SHORT] = "Packet too short",
  [OVPN_INPUT_ERROR_INVALID_OPCODE] = "Invalid opcode",
  [OVPN_INPUT_ERROR_PEER_NOT_FOUND] = "Peer not found",
  [OVPN_INPUT_ERROR_DECRYPT_FAILED] = "Decryption failed",
  [OVPN_INPUT_ERROR_REPLAY] = "Replay detected",
  [OVPN_INPUT_ERROR_NO_CRYPTO] = "No crypto context",
};

/* Trace data */
typedef struct
{
  u8 opcode;
  u8 key_id;
  u32 peer_id;
  u32 packet_id;
  u32 sw_if_index;
  u16 packet_len;
  u8 next_index;
  u8 error;
} ovpn_input_trace_t;

static u8 *
format_ovpn_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_input_trace_t *t = va_arg (*args, ovpn_input_trace_t *);

  s = format (s, "ovpn-input: opcode %U key_id %u peer_id %u",
	      format_ovpn_opcode, t->opcode, t->key_id, t->peer_id);
  s = format (s, "\n  packet_id %u len %u sw_if_index %u", t->packet_id,
	      t->packet_len, t->sw_if_index);
  s = format (s, "\n  next %u error %u", t->next_index, t->error);

  return s;
}

always_inline uword
ovpn_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		   vlib_frame_t *frame, u8 is_ip6)
{
  ovpn_main_t *omp = &ovpn_main;
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 thread_index = vm->thread_index;
  f64 now = vlib_time_now (vm);
  ovpn_per_thread_crypto_t *ptd = ovpn_crypto_get_ptd (thread_index);

  /* Packet IDs for replay tracking (indexed by buffer position) */
  u32 packet_ids[VLIB_FRAME_SIZE];
  ovpn_crypto_context_t *crypto_contexts[VLIB_FRAME_SIZE];
  ovpn_peer_t *peers[VLIB_FRAME_SIZE];
  /* NAT/float: track remote addresses for address change detection */
  ip_address_t remote_addrs[VLIB_FRAME_SIZE];
  u16 remote_ports[VLIB_FRAME_SIZE];
  u32 decrypt_count = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  /* Initialize tracking arrays */
  clib_memset (peers, 0, sizeof (peers));

  /* Reset per-thread crypto state for batch processing */
  ovpn_crypto_reset_ptd (ptd);

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0 = b[0];
      ovpn_input_error_t error = OVPN_INPUT_ERROR_NONE;
      ovpn_input_next_t next0 = OVPN_INPUT_NEXT_DROP;
      u8 *data;
      u32 len;
      u8 op_byte, opcode, key_id;
      u32 peer_id = 0;
      u32 packet_id = 0;
      ovpn_peer_t *peer = NULL;
      ovpn_crypto_context_t *crypto = NULL;
      int rv;

      /* Get packet data - buffer should point to OpenVPN payload (after UDP)
       */
      data = vlib_buffer_get_current (b0);
      len = b0->current_length;

      /* Check minimum length */
      if (PREDICT_FALSE (len < OVPN_OP_SIZE))
	{
	  error = OVPN_INPUT_ERROR_TOO_SHORT;
	  goto trace;
	}

      /* Parse opcode and key_id */
      op_byte = data[0];
      opcode = ovpn_op_get_opcode (op_byte);
      key_id = ovpn_op_get_key_id (op_byte);

      /* Validate opcode */
      if (PREDICT_FALSE (!ovpn_opcode_is_valid (opcode)))
	{
	  error = OVPN_INPUT_ERROR_INVALID_OPCODE;
	  goto trace;
	}

      /* Handle based on packet type */
      if (ovpn_opcode_is_data (opcode))
	{
	  /*
	   * Data channel packet
	   */
	  if (opcode == OVPN_OP_DATA_V2)
	    {
	      /* DATA_V2 has peer_id in header */
	      if (PREDICT_FALSE (len < OVPN_DATA_V2_MIN_SIZE + OVPN_TAG_SIZE))
		{
		  error = OVPN_INPUT_ERROR_TOO_SHORT;
		  goto trace;
		}

	      ovpn_data_v2_header_t *hdr = (ovpn_data_v2_header_t *) data;
	      peer_id = ovpn_data_v2_get_peer_id (hdr);

	      /*
	       * NAT/float: Extract remote address for address change detection.
	       * This is done even for DATA_V2 to support NAT rebinding.
	       */
	      u32 ip_offset = vnet_buffer (b0)->ip.save_rewrite_length;
	      if (ip_offset > 0 && ip_offset < b0->current_data)
		{
		  u8 *ip_hdr = vlib_buffer_get_current (b0) -
			       (b0->current_data - ip_offset);
		  u8 version = (ip_hdr[0] >> 4) & 0xf;
		  u32 buf_idx = b - bufs;

		  if (version == 4)
		    {
		      ip4_header_t *ip4 = (ip4_header_t *) ip_hdr;
		      udp_header_t *udp = (udp_header_t *) (ip4 + 1);
		      ip_address_set (&remote_addrs[buf_idx], &ip4->src_address,
				      AF_IP4);
		      remote_ports[buf_idx] =
			clib_net_to_host_u16 (udp->src_port);
		    }
		  else if (version == 6)
		    {
		      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;
		      udp_header_t *udp = (udp_header_t *) (ip6 + 1);
		      ip_address_set (&remote_addrs[buf_idx], &ip6->src_address,
				      AF_IP6);
		      remote_ports[buf_idx] =
			clib_net_to_host_u16 (udp->src_port);
		    }
		}
	    }
	  else
	    {
	      /* DATA_V1 - lookup peer by remote endpoint (outer IP:port) */
	      if (PREDICT_FALSE (len < OVPN_DATA_V1_MIN_SIZE + OVPN_TAG_SIZE))
		{
		  error = OVPN_INPUT_ERROR_TOO_SHORT;
		  goto trace;
		}

	      /*
	       * Extract remote address from outer IP header.
	       * The buffer was advanced past UDP, use saved offset to find IP.
	       */
	      ip_address_t remote_addr;
	      u16 remote_port = 0;
	      u32 ip_offset = vnet_buffer (b0)->ip.save_rewrite_length;
	      u32 buf_idx = b - bufs;

	      if (ip_offset > 0 && ip_offset < b0->current_data)
		{
		  u8 *ip_hdr = vlib_buffer_get_current (b0) -
			       (b0->current_data - ip_offset);
		  u8 version = (ip_hdr[0] >> 4) & 0xf;

		  if (version == 4)
		    {
		      ip4_header_t *ip4 = (ip4_header_t *) ip_hdr;
		      udp_header_t *udp = (udp_header_t *) (ip4 + 1);
		      ip_address_set (&remote_addr, &ip4->src_address, AF_IP4);
		      remote_port = clib_net_to_host_u16 (udp->src_port);
		    }
		  else if (version == 6)
		    {
		      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;
		      udp_header_t *udp = (udp_header_t *) (ip6 + 1);
		      ip_address_set (&remote_addr, &ip6->src_address, AF_IP6);
		      remote_port = clib_net_to_host_u16 (udp->src_port);
		    }
		  else
		    {
		      error = OVPN_INPUT_ERROR_PEER_NOT_FOUND;
		      goto trace;
		    }

		  /* Store remote address for NAT/float detection */
		  ip_address_copy (&remote_addrs[buf_idx], &remote_addr);
		  remote_ports[buf_idx] = remote_port;

		  /* Lookup peer by remote endpoint */
		  peer = ovpn_peer_lookup_by_remote (
		    &omp->multi_context.peer_db, &remote_addr, remote_port);
		  if (peer)
		    peer_id = peer->peer_id;
		}

	      if (PREDICT_FALSE (!peer))
		{
		  error = OVPN_INPUT_ERROR_PEER_NOT_FOUND;
		  goto trace;
		}
	    }

	  /* Lookup peer by peer_id (for DATA_V2 path) */
	  if (!peer)
	    peer = ovpn_peer_get (&omp->multi_context.peer_db, peer_id);
	  if (PREDICT_FALSE (!peer))
	    {
	      error = OVPN_INPUT_ERROR_PEER_NOT_FOUND;
	      goto trace;
	    }

	  /*
	   * Check peer state - only process data for established peers.
	   * Peer might be deleted or in handshake state.
	   */
	  if (PREDICT_FALSE (!ovpn_peer_is_established (peer)))
	    {
	      error = OVPN_INPUT_ERROR_PEER_NOT_FOUND;
	      goto trace;
	    }

	  /*
	   * Check if we need to handoff to peer's assigned thread
	   * Assign current thread if peer has no assigned thread yet
	   */
	  if (PREDICT_FALSE (peer->input_thread_index == ~0))
	    {
	      /* First packet for this peer - assign current thread */
	      ovpn_peer_assign_thread (peer, thread_index);
	    }

	  if (PREDICT_FALSE (thread_index != peer->input_thread_index))
	    {
	      /* Handoff to the peer's assigned thread */
	      next0 = OVPN_INPUT_NEXT_HANDOFF_DATA;
	      goto trace;
	    }

	  /*
	   * Get crypto context for this key_id using bihash (lock-free).
	   */
	  crypto = ovpn_peer_get_crypto_by_key_id (&omp->multi_context.peer_db,
						   peer_id, key_id);
	  if (PREDICT_FALSE (!crypto || !crypto->is_valid))
	    {
	      error = OVPN_INPUT_ERROR_NO_CRYPTO;
	      goto trace;
	    }

	  /* Prepare decrypt operation (supports chained buffers) */
	  u32 buf_idx = b - bufs;
	  rv = ovpn_crypto_decrypt_prepare (vm, ptd, crypto, b0, buf_idx,
					    &packet_id);
	  if (PREDICT_FALSE (rv < 0))
	    {
	      if (rv == -4)
		error = OVPN_INPUT_ERROR_REPLAY;
	      else
		error = OVPN_INPUT_ERROR_DECRYPT_FAILED;
	      goto trace;
	    }

	  /* Store context for post-processing after batch crypto */
	  packet_ids[buf_idx] = packet_id;
	  crypto_contexts[buf_idx] = crypto;
	  peers[buf_idx] = peer;
	  decrypt_count++;

	  /* Mark for pending decryption - will be updated after batch */
	  next0 = OVPN_INPUT_NEXT_IP4_INPUT; /* Placeholder, will be fixed up */
	}
      else if (ovpn_opcode_is_control (opcode))
	{
	  /*
	   * Control channel packet (handshake)
	   * Must be processed on main thread (thread 0)
	   */
	  if (thread_index != 0)
	    {
	      /* Handoff to main thread */
	      next0 = OVPN_INPUT_NEXT_HANDOFF_HANDSHAKE;
	      goto trace;
	    }

	  /* We're on main thread - process handshake */
	  next0 = OVPN_INPUT_NEXT_HANDSHAKE;
	}

    trace:
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ovpn_input_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->opcode = opcode;
	  t->key_id = key_id;
	  t->peer_id = peer_id;
	  t->packet_id = packet_id;
	  t->sw_if_index = peer ? peer->sw_if_index : ~0;
	  t->packet_len = len;
	  t->next_index = next0;
	  t->error = error;
	}

      if (error != OVPN_INPUT_ERROR_NONE)
	{
	  b0->error = node->errors[error];
	  next0 = OVPN_INPUT_NEXT_DROP;
	}

      next[0] = next0;

      /* Next iteration */
      from += 1;
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  /*
   * Batch process all decrypt operations
   * This handles both single-buffer and chained-buffer crypto
   */
  if (decrypt_count > 0)
    {
      ovpn_crypto_decrypt_process (vm, node, ptd, bufs, nexts,
				   OVPN_INPUT_NEXT_DROP);

      /*
       * Post-process decrypted packets:
       * - Update replay windows
       * - Advance buffers past headers
       * - Determine inner packet type
       * - Update statistics
       */
      for (u32 i = 0; i < frame->n_vectors; i++)
	{
	  /* Skip packets that weren't queued for decryption */
	  if (!peers[i])
	    continue;

	  /* Skip packets that failed decryption */
	  if (nexts[i] == OVPN_INPUT_NEXT_DROP)
	    continue;

	  vlib_buffer_t *b0 = bufs[i];
	  ovpn_peer_t *peer = peers[i];
	  ovpn_crypto_context_t *crypto = crypto_contexts[i];
	  u32 packet_id = packet_ids[i];
	  vlib_buffer_t *lb;
	  u8 *data;
	  u32 aad_len = sizeof (ovpn_data_v2_header_t);

	  /* Update replay window */
	  ovpn_crypto_update_replay (crypto, packet_id);

	  /*
	   * NAT/float: Check if remote address changed.
	   * Only queue update after successful decrypt (authentication).
	   */
	  if (ip_address_cmp (&peer->remote_addr, &remote_addrs[i]) != 0 ||
	      peer->remote_port != remote_ports[i])
	    {
	      /* Queue address update - will be applied by control plane */
	      ovpn_peer_queue_address_update (peer, &remote_addrs[i],
					      remote_ports[i]);
	    }

	  /* Find last buffer in chain */
	  lb = b0;
	  while (lb->flags & VLIB_BUFFER_NEXT_PRESENT)
	    lb = vlib_get_buffer (vm, lb->next_buffer);

	  /* Advance buffer past header to plaintext */
	  vlib_buffer_advance (b0, aad_len);

	  /* Remove tag from chain length */
	  vlib_buffer_chain_increase_length (b0, lb, -OVPN_TAG_SIZE);

	  /* Update peer statistics */
	  ovpn_peer_update_rx (peer, now, vlib_buffer_length_in_chain (vm, b0));

	  /* Set sw_if_index for the tunnel interface */
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = peer->sw_if_index;

	  /* Determine inner packet type and route to IP input */
	  data = vlib_buffer_get_current (b0);
	  if (PREDICT_TRUE (b0->current_length >= 1))
	    {
	      u8 ip_version = (data[0] >> 4);
	      if (ip_version == 4)
		nexts[i] = OVPN_INPUT_NEXT_IP4_INPUT;
	      else if (ip_version == 6)
		nexts[i] = OVPN_INPUT_NEXT_IP6_INPUT;
	      else
		{
		  b0->error = node->errors[OVPN_INPUT_ERROR_DECRYPT_FAILED];
		  nexts[i] = OVPN_INPUT_NEXT_DROP;
		}
	    }
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, vlib_frame_vector_args (frame), nexts,
			       frame->n_vectors);

  return frame->n_vectors;
}

/*
 * Handshake node next indices
 */
typedef enum
{
  OVPN_HANDSHAKE_NEXT_DROP,
  OVPN_HANDSHAKE_NEXT_IP4_LOOKUP,
  OVPN_HANDSHAKE_NEXT_IP6_LOOKUP,
  OVPN_HANDSHAKE_N_NEXT,
} ovpn_handshake_next_t;

/*
 * Handshake node error codes
 */
typedef enum
{
  OVPN_HANDSHAKE_ERROR_NONE,
  OVPN_HANDSHAKE_ERROR_PROCESSED,
  OVPN_HANDSHAKE_ERROR_INVALID,
  OVPN_HANDSHAKE_ERROR_HMAC_FAILED,
  OVPN_HANDSHAKE_ERROR_NO_PENDING,
  OVPN_HANDSHAKE_N_ERROR,
} ovpn_handshake_error_t;

static char *ovpn_handshake_error_strings[] = {
  [OVPN_HANDSHAKE_ERROR_NONE] = "No error",
  [OVPN_HANDSHAKE_ERROR_PROCESSED] = "Processed",
  [OVPN_HANDSHAKE_ERROR_INVALID] = "Invalid packet",
  [OVPN_HANDSHAKE_ERROR_HMAC_FAILED] = "HMAC verification failed",
  [OVPN_HANDSHAKE_ERROR_NO_PENDING] = "No pending connection",
};

/*
 * Handshake trace data
 */
typedef struct
{
  u8 opcode;
  u8 key_id;
  ip46_address_t src_addr;
  ip46_address_t dst_addr;
  u16 src_port;
  u16 dst_port;
  u8 is_ip6;
  int result;
} ovpn_handshake_trace_t;

static u8 *
format_ovpn_handshake_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_handshake_trace_t *t = va_arg (*args, ovpn_handshake_trace_t *);

  s = format (s, "ovpn-handshake: opcode %U key_id %u result %d",
	      format_ovpn_opcode, t->opcode, t->key_id, t->result);
  if (t->is_ip6)
    s = format (s, "\n  src %U:%u dst %U:%u", format_ip6_address,
		&t->src_addr.ip6, t->src_port, format_ip6_address,
		&t->dst_addr.ip6, t->dst_port);
  else
    s = format (s, "\n  src %U:%u dst %U:%u", format_ip4_address,
		&t->src_addr.ip4, t->src_port, format_ip4_address,
		&t->dst_addr.ip4, t->dst_port);

  return s;
}

/*
 * Handshake node - handles control channel processing
 * This node runs on main thread (thread 0) only
 */
static uword
ovpn_handshake_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame, u8 is_ip4)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_processed = 0;

  /* Assert we're on main thread */
  ASSERT (vm->thread_index == 0);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0 = b[0];
      u16 next0 = OVPN_HANDSHAKE_NEXT_DROP;
      ip_address_t src_addr, dst_addr;
      u16 src_port, dst_port;
      u8 is_ip6 = 0;
      int rv;
      u8 opcode = 0, key_id = 0;
      u8 *data;

      /* Get opcode from first byte */
      data = vlib_buffer_get_current (b0);
      if (b0->current_length >= 1)
	{
	  opcode = ovpn_op_get_opcode (data[0]);
	  key_id = ovpn_op_get_key_id (data[0]);
	}

      /*
       * Extract IP addresses and ports from the original packet
       * The buffer was advanced past UDP, so we need to go back
       * to find the IP header
       */
      {
	/* Check if this was an IPv6 packet based on buffer flags or offset */
	u32 ip_offset;

	/* Go back to find IP header - this depends on how the packet arrived
	 */
	/* For UDP local delivery, the sw_if_index and other metadata are set
	 */
	ip_offset = vnet_buffer (b0)->ip.save_rewrite_length;

	/* Try to determine if IPv4 or IPv6 based on version field */
	if (ip_offset > 0 && ip_offset < b0->current_data)
	  {
	    u8 *start =
	      vlib_buffer_get_current (b0) - (b0->current_data - ip_offset);
	    u8 version = (start[0] >> 4) & 0xf;

	    if (version == 4)
	      {
		ip4_header_t *ip4 = (ip4_header_t *) start;
		udp_header_t *udp = (udp_header_t *) (ip4 + 1);

		ip_address_set (&src_addr, &ip4->src_address, AF_IP4);
		ip_address_set (&dst_addr, &ip4->dst_address, AF_IP4);
		src_port = clib_net_to_host_u16 (udp->src_port);
		dst_port = clib_net_to_host_u16 (udp->dst_port);
		is_ip6 = 0;
	      }
	    else if (version == 6)
	      {
		ip6_header_t *ip6 = (ip6_header_t *) start;
		udp_header_t *udp = (udp_header_t *) (ip6 + 1);

		ip_address_set (&src_addr, &ip6->src_address, AF_IP6);
		ip_address_set (&dst_addr, &ip6->dst_address, AF_IP6);
		src_port = clib_net_to_host_u16 (udp->src_port);
		dst_port = clib_net_to_host_u16 (udp->dst_port);
		is_ip6 = 1;
	      }
	    else
	      {
		/* Cannot determine - use saved metadata if available */
		clib_memset (&src_addr, 0, sizeof (src_addr));
		clib_memset (&dst_addr, 0, sizeof (dst_addr));
		src_port = 0;
		dst_port = 0;
	      }
	  }
	else
	  {
	    /* Fallback - cannot determine addresses */
	    clib_memset (&src_addr, 0, sizeof (src_addr));
	    clib_memset (&dst_addr, 0, sizeof (dst_addr));
	    src_port = 0;
	    dst_port = 0;
	  }
      }

      /* Process the handshake packet */
      rv = ovpn_handshake_process_packet (vm, b0, &src_addr, src_port,
					  &dst_addr, dst_port, is_ip6);

      if (rv >= 0)
	{
	  n_processed++;
	  /* TODO: If we need to send a response, queue it here */
	}

      /* Always drop the incoming control packet after processing */
      next0 = OVPN_HANDSHAKE_NEXT_DROP;

      /* Trace */
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ovpn_handshake_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->opcode = opcode;
	  t->key_id = key_id;
	  t->is_ip6 = is_ip6;
	  t->result = rv;
	  if (is_ip6)
	    {
	      clib_memcpy (&t->src_addr.ip6, &src_addr.ip.ip6,
			   sizeof (ip6_address_t));
	      clib_memcpy (&t->dst_addr.ip6, &dst_addr.ip.ip6,
			   sizeof (ip6_address_t));
	    }
	  else
	    {
	      t->src_addr.ip4.as_u32 = src_addr.ip.ip4.as_u32;
	      t->dst_addr.ip4.as_u32 = dst_addr.ip.ip4.as_u32;
	    }
	  t->src_port = src_port;
	  t->dst_port = dst_port;
	}

      next[0] = next0;
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, node->node_index,
			       OVPN_HANDSHAKE_ERROR_PROCESSED, n_processed);

  return frame->n_vectors;
}

VLIB_NODE_FN (ovpn4_handshake_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_handshake_node_fn (vm, node, frame, 1);
}

VLIB_NODE_FN (ovpn6_handshake_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_handshake_node_fn (vm, node, frame, 0);
}

VLIB_NODE_FN (ovpn4_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_input_inline (vm, node, frame, 0 /* is_ip6 */);
}

VLIB_NODE_FN (ovpn6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_input_inline (vm, node, frame, 1 /* is_ip6 */);
}

VLIB_REGISTER_NODE (ovpn4_handshake_node) = {
  .name = "ovpn4-handshake",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_handshake_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_HANDSHAKE_N_ERROR,
  .error_strings = ovpn_handshake_error_strings,
  .n_next_nodes = OVPN_HANDSHAKE_N_NEXT,
  .next_nodes = {
    [OVPN_HANDSHAKE_NEXT_DROP] = "error-drop",
    [OVPN_HANDSHAKE_NEXT_IP4_LOOKUP] = "ip4-lookup",
  },
};

VLIB_REGISTER_NODE (ovpn6_handshake_node) = {
  .name = "ovpn6-handshake",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_handshake_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_HANDSHAKE_N_ERROR,
  .error_strings = ovpn_handshake_error_strings,
  .n_next_nodes = OVPN_HANDSHAKE_N_NEXT,
  .next_nodes = {
    [OVPN_HANDSHAKE_NEXT_DROP] = "error-drop",
    [OVPN_HANDSHAKE_NEXT_IP6_LOOKUP] = "ip6-lookup",
  },
};

VLIB_REGISTER_NODE (ovpn4_input_node) = {
  .name = "ovpn4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_INPUT_N_ERROR,
  .error_strings = ovpn_input_error_strings,
  .n_next_nodes = OVPN_INPUT_N_NEXT,
  .next_nodes = {
    [OVPN_INPUT_NEXT_HANDOFF_HANDSHAKE] = "ovpn4-handshake-handoff",
    [OVPN_INPUT_NEXT_HANDOFF_DATA] = "ovpn4-input-data-handoff",
    [OVPN_INPUT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [OVPN_INPUT_NEXT_IP6_INPUT] = "ip6-input-no-checksum",
    [OVPN_INPUT_NEXT_HANDSHAKE] = "ovpn4-handshake",
    [OVPN_INPUT_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ovpn6_input_node) = {
  .name = "ovpn6-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_INPUT_N_ERROR,
  .error_strings = ovpn_input_error_strings,
  .n_next_nodes = OVPN_INPUT_N_NEXT,
  .next_nodes = {
    [OVPN_INPUT_NEXT_HANDOFF_HANDSHAKE] = "ovpn6-handshake-handoff",
    [OVPN_INPUT_NEXT_HANDOFF_DATA] = "ovpn6-input-data-handoff",
    [OVPN_INPUT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [OVPN_INPUT_NEXT_IP6_INPUT] = "ip6-input-no-checksum",
    [OVPN_INPUT_NEXT_HANDSHAKE] = "ovpn6-handshake",
    [OVPN_INPUT_NEXT_DROP] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
