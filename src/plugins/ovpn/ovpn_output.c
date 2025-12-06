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
  OVPN_OUTPUT_NEXT_HANDOFF,
  OVPN_OUTPUT_NEXT_INTERFACE_OUTPUT,
  OVPN_OUTPUT_NEXT_ERROR,
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
  u32 adj_index;
  u32 packet_id;
  u16 inner_len;
  u16 outer_len;
  u8 next_index;
  u8 error;
} ovpn_output_trace_t;

static u8 *
format_ovpn4_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_output_trace_t *t = va_arg (*args, ovpn_output_trace_t *);

  s = format (s, "ovpn4-output: peer_id %u adj_index %u packet_id %u",
	      t->peer_id, t->adj_index, t->packet_id);
  s = format (s, "\n  inner_len %u outer_len %u", t->inner_len, t->outer_len);
  s = format (s, "\n  next %u error %u", t->next_index, t->error);

  return s;
}

static u8 *
format_ovpn6_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_output_trace_t *t = va_arg (*args, ovpn_output_trace_t *);

  s = format (s, "ovpn6-output: peer_id %u adj_index %u packet_id %u",
	      t->peer_id, t->adj_index, t->packet_id);
  s = format (s, "\n  inner_len %u outer_len %u", t->inner_len, t->outer_len);
  s = format (s, "\n  next %u error %u", t->next_index, t->error);

  return s;
}

/*
 * Common output inline function
 * Encrypts packets and prepares them for adj-midchain-tx
 */
always_inline uword
ovpn_output_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, u8 is_ip4)
{
  ovpn_main_t *omp = &ovpn_main;
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  f64 now = vlib_time_now (vm);
  u32 last_adj_index = ~0;
  u32 last_peer_id = ~0;
  ovpn_peer_t *peer = NULL;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0 = b[0];
      ovpn_output_error_t error = OVPN_OUTPUT_ERROR_NONE;
      ovpn_output_next_t next0 = OVPN_OUTPUT_NEXT_ERROR;
      ovpn_crypto_context_t *crypto = NULL;
      u32 adj_index;
      u32 peer_id = 0;
      u32 packet_id = 0;
      u16 inner_len, outer_len = 0;
      int rv;

      inner_len = b0->current_length;

      /* Get adjacency index from buffer */
      adj_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];

      /* Lookup peer by adjacency index (cached) */
      if (PREDICT_FALSE (adj_index != last_adj_index))
	{
	  peer_id = ovpn_peer_get_by_adj_index (adj_index);
	  if (peer_id != ~0 && peer_id != last_peer_id)
	    {
	      peer = ovpn_peer_get (&omp->multi_context.peer_db, peer_id);
	      last_peer_id = peer_id;
	    }
	  else if (peer_id == ~0)
	    {
	      peer = NULL;
	    }
	  last_adj_index = adj_index;
	}
      else
	{
	  peer_id = last_peer_id;
	}

      if (PREDICT_FALSE (!peer || peer->state != OVPN_PEER_STATE_ESTABLISHED))
	{
	  error = OVPN_OUTPUT_ERROR_PEER_NOT_FOUND;
	  goto trace;
	}

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
      rv = ovpn_crypto_encrypt (vm, crypto, b0, peer->peer_id, key_id);
      if (PREDICT_FALSE (rv < 0))
	{
	  error = OVPN_OUTPUT_ERROR_ENCRYPT_FAILED;
	  goto trace;
	}

      packet_id = crypto->packet_id_send - 1; /* Was just incremented */
      outer_len = b0->current_length;

      /*
       * The rewrite (IP + UDP headers) is already applied by adj-midchain
       * We just need to fix up the length fields
       */
      if (is_ip4)
	{
	  ip4_header_t *ip4 = vlib_buffer_get_current (b0);
	  udp_header_t *udp = (udp_header_t *) (ip4 + 1);
	  u16 old_len = ip4->length;
	  u16 new_len = clib_host_to_net_u16 (outer_len);

	  /* Update IP length with checksum fixup */
	  ip_csum_t sum = ip4->checksum;
	  sum = ip_csum_update (sum, old_len, new_len, ip4_header_t, length);
	  ip4->checksum = ip_csum_fold (sum);
	  ip4->length = new_len;

	  /* Update UDP length */
	  udp->length =
	    clib_host_to_net_u16 (outer_len - sizeof (ip4_header_t));
	}
      else
	{
	  ip6_header_t *ip6 = vlib_buffer_get_current (b0);
	  udp_header_t *udp = (udp_header_t *) (ip6 + 1);

	  ip6->payload_length =
	    clib_host_to_net_u16 (outer_len - sizeof (ip6_header_t));
	  udp->length = ip6->payload_length;
	}

      /* Update peer statistics */
      ovpn_peer_update_tx (peer, now, outer_len);

      /* Send to adj-midchain-tx */
      next0 = OVPN_OUTPUT_NEXT_INTERFACE_OUTPUT;

    trace:
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ovpn_output_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->peer_id = peer_id;
	  t->adj_index = adj_index;
	  t->packet_id = packet_id;
	  t->inner_len = inner_len;
	  t->outer_len = outer_len;
	  t->next_index = next0;
	  t->error = error;
	}

      if (error != OVPN_OUTPUT_ERROR_NONE)
	{
	  b0->error = node->errors[error];
	  next0 = OVPN_OUTPUT_NEXT_ERROR;
	}

      next[0] = next0;

      /* Next iteration */
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, vlib_frame_vector_args (frame), nexts,
			       frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (ovpn4_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_output_inline (vm, node, frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (ovpn6_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_output_inline (vm, node, frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (ovpn4_output_node) = {
  .name = "ovpn4-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn4_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_OUTPUT_N_ERROR,
  .error_strings = ovpn_output_error_strings,
  .n_next_nodes = OVPN_OUTPUT_N_NEXT,
  .next_nodes = {
    [OVPN_OUTPUT_NEXT_HANDOFF] = "ovpn4-output-handoff",
    [OVPN_OUTPUT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
    [OVPN_OUTPUT_NEXT_ERROR] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ovpn6_output_node) = {
  .name = "ovpn6-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn6_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_OUTPUT_N_ERROR,
  .error_strings = ovpn_output_error_strings,
  .n_next_nodes = OVPN_OUTPUT_N_NEXT,
  .next_nodes = {
    [OVPN_OUTPUT_NEXT_HANDOFF] = "ovpn6-output-handoff",
    [OVPN_OUTPUT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
    [OVPN_OUTPUT_NEXT_ERROR] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
