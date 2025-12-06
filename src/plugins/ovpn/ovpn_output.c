/*
 * ovpn_output.c - OpenVPN output node
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
#include <vnet/adj/adj.h>
#include <ovpn/ovpn.h>
#include <ovpn/ovpn_packet.h>
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_crypto.h>

/* Output node next indices */
typedef enum
{
  OVPN_OUTPUT_NEXT_IP4_LOOKUP,
  OVPN_OUTPUT_NEXT_IP6_LOOKUP,
  OVPN_OUTPUT_NEXT_DROP,
  OVPN_OUTPUT_N_NEXT,
} ovpn_output_next_t;

/* Error codes */
typedef enum
{
  OVPN_OUTPUT_ERROR_NONE,
  OVPN_OUTPUT_ERROR_PEER_NOT_FOUND,
  OVPN_OUTPUT_ERROR_NO_CRYPTO,
  OVPN_OUTPUT_ERROR_ENCRYPT_FAILED,
  OVPN_OUTPUT_ERROR_NO_BUFFER_SPACE,
  OVPN_OUTPUT_N_ERROR,
} ovpn_output_error_t;

static char *ovpn_output_error_strings[] = {
  [OVPN_OUTPUT_ERROR_NONE] = "No error",
  [OVPN_OUTPUT_ERROR_PEER_NOT_FOUND] = "Peer not found",
  [OVPN_OUTPUT_ERROR_NO_CRYPTO] = "No crypto context",
  [OVPN_OUTPUT_ERROR_ENCRYPT_FAILED] = "Encryption failed",
  [OVPN_OUTPUT_ERROR_NO_BUFFER_SPACE] = "No buffer space",
};

/* Trace data */
typedef struct
{
  u32 peer_id;
  u32 packet_id;
  u32 sw_if_index;
  u16 inner_len;
  u16 outer_len;
  u8 next_index;
  u8 error;
} ovpn_output_trace_t;

static u8 *
format_ovpn_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_output_trace_t *t = va_arg (*args, ovpn_output_trace_t *);

  s = format (s, "ovpn-output: peer_id %u packet_id %u", t->peer_id,
	      t->packet_id);
  s = format (s, "\n  sw_if_index %u inner_len %u outer_len %u",
	      t->sw_if_index, t->inner_len, t->outer_len);
  s = format (s, "\n  next %u error %u", t->next_index, t->error);

  return s;
}

/*
 * TX function called from the ovpn interface
 * This encrypts packets and sends them to the peer
 */
always_inline uword
ovpn_output_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame)
{
  ovpn_main_t *omp = &ovpn_main;
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  f64 now = vlib_time_now (vm);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0 = b[0];
      ovpn_output_error_t error = OVPN_OUTPUT_ERROR_NONE;
      ovpn_output_next_t next0 = OVPN_OUTPUT_NEXT_DROP;
      ovpn_peer_t *peer = NULL;
      ovpn_crypto_context_t *crypto = NULL;
      u32 sw_if_index;
      u32 peer_id = 0;
      u32 packet_id = 0;
      u16 inner_len, outer_len = 0;
      int rv;

      inner_len = b0->current_length;
      sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];

      /*
       * Lookup peer for this interface
       * For now, assume single peer per interface (P2P mode)
       * TODO: For multi-client mode, lookup by destination IP
       */
      ovpn_peer_t *p;
      pool_foreach (p, omp->multi_context.peer_db.peers)
	{
	  if (p->sw_if_index == sw_if_index &&
	      p->state == OVPN_PEER_STATE_ESTABLISHED)
	    {
	      peer = p;
	      break;
	    }
	}

      if (PREDICT_FALSE (!peer))
	{
	  error = OVPN_OUTPUT_ERROR_PEER_NOT_FOUND;
	  goto trace;
	}

      peer_id = peer->peer_id;

      /* Get crypto context */
      crypto = ovpn_peer_get_crypto (peer);
      if (PREDICT_FALSE (!crypto || !crypto->is_valid))
	{
	  error = OVPN_OUTPUT_ERROR_NO_CRYPTO;
	  goto trace;
	}

      /* Get current key_id */
      u8 key_id = peer->keys[peer->current_key_slot].key_id;

      /*
       * Encrypt the packet
       * ovpn_crypto_encrypt will:
       * 1. Prepend OpenVPN header (opcode + peer_id + packet_id)
       * 2. Encrypt the payload
       * 3. Append authentication tag
       */
      rv = ovpn_crypto_encrypt (vm, crypto, b0, peer_id, key_id);
      if (PREDICT_FALSE (rv < 0))
	{
	  error = OVPN_OUTPUT_ERROR_ENCRYPT_FAILED;
	  goto trace;
	}

      packet_id = crypto->packet_id_send - 1; /* Was just incremented */

      /*
       * Prepend UDP + IP header (rewrite)
       */
      if (PREDICT_FALSE (!peer->rewrite || peer->rewrite_len == 0))
	{
	  error = OVPN_OUTPUT_ERROR_NO_BUFFER_SPACE;
	  goto trace;
	}

      /* Check buffer space for rewrite */
      if (PREDICT_FALSE (b0->current_data < (i16) peer->rewrite_len))
	{
	  error = OVPN_OUTPUT_ERROR_NO_BUFFER_SPACE;
	  goto trace;
	}

      /* Prepend the rewrite (IP + UDP headers) */
      vlib_buffer_advance (b0, -(i32) peer->rewrite_len);
      clib_memcpy_fast (vlib_buffer_get_current (b0), peer->rewrite,
			peer->rewrite_len);

      outer_len = b0->current_length;

      /* Fix up IP and UDP lengths */
      if (peer->is_ipv6)
	{
	  ip6_header_t *ip6 = vlib_buffer_get_current (b0);
	  udp_header_t *udp = (udp_header_t *) (ip6 + 1);

	  ip6->payload_length =
	    clib_host_to_net_u16 (outer_len - sizeof (ip6_header_t));
	  udp->length = ip6->payload_length;

	  next0 = OVPN_OUTPUT_NEXT_IP6_LOOKUP;
	}
      else
	{
	  ip4_header_t *ip4 = vlib_buffer_get_current (b0);
	  udp_header_t *udp = (udp_header_t *) (ip4 + 1);

	  ip4->length = clib_host_to_net_u16 (outer_len);
	  ip4->checksum = ip4_header_checksum (ip4);

	  udp->length =
	    clib_host_to_net_u16 (outer_len - sizeof (ip4_header_t));

	  next0 = OVPN_OUTPUT_NEXT_IP4_LOOKUP;
	}

      /* Update peer statistics */
      ovpn_peer_update_tx (peer, now, outer_len);

    trace:
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ovpn_output_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->peer_id = peer_id;
	  t->packet_id = packet_id;
	  t->sw_if_index = sw_if_index;
	  t->inner_len = inner_len;
	  t->outer_len = outer_len;
	  t->next_index = next0;
	  t->error = error;
	}

      if (error != OVPN_OUTPUT_ERROR_NONE)
	{
	  b0->error = node->errors[error];
	  next0 = OVPN_OUTPUT_NEXT_DROP;
	}

      next[0] = next0;

      /* Next iteration */
      from += 1;
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, vlib_frame_vector_args (frame), nexts,
			       frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (ovpn_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_output_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (ovpn_output_node) = {
  .name = "ovpn-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_OUTPUT_N_ERROR,
  .error_strings = ovpn_output_error_strings,
  .n_next_nodes = OVPN_OUTPUT_N_NEXT,
  .next_nodes = {
    [OVPN_OUTPUT_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [OVPN_OUTPUT_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [OVPN_OUTPUT_NEXT_DROP] = "error-drop",
  },
};

/*
 * Interface TX function - called when packets are sent through the ovpn interface
 * This is registered as the device TX function
 */
VNET_DEVICE_CLASS_TX_FN (ovpn_device_class)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  /* Simply forward to the output node */
  return ovpn_output_inline (vm, node, frame);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
