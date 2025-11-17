/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
 *
 * Copyright (c) <current-year> <your-organization>
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
#include "ovpn/ovpn_channel.h"
#include "ovpn/ovpn_reliable.h"
#include "picotls.h"
#include "vnet/crypto/crypto.h"
#include <ovpn/private.h>
#include <vlib/node_funcs.h>
#include <vlib/threads.h>
#include <vnet/udp/udp_local.h>
#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <ovpn/ovpn.h>
#include <ovpn/ovpn_message.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} ovpn_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_ovpn_trace (u8 *s, va_list *args)
{
  return s;
}

vlib_node_registration_t ovpn_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_ovpn_error                                                    \
  _ (NONE, "No error")                                                        \
  _ (MALFORMED, "Malformed data")                                             \
  _ (UNKNOWN_OPCODE, "Unknown opcode")                                        \
  _ (SSL_HANDSHAKE_FAILED, "SSL handshake failed")                            \
  _ (FAILED_TO_ALLOCATE_BUFFER, "Failed to allocate buffer")

typedef enum
{
#define _(sym, str) OVPN_ERROR_##sym,
  foreach_ovpn_error
#undef _
    OVPN_N_ERROR,
} ovpn_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *ovpn_error_strings[] = {
#define _(sym, string) string,
  foreach_ovpn_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  OVPN_NEXT_IP_LOOKUP,
  OVPN_NEXT_HANDOFF_HANDSHAKE,
  OVPN_NEXT_DROP,
  OVPN_N_NEXT,
} ovpn_next_t;

#define foreach_ovpn_handoff_error _ (CONGESTION_DROP, "congestion drop")

typedef enum
{
#define _(sym, str) OVPN_HANDOFF_ERROR_##sym,
  foreach_ovpn_handoff_error
#undef _
    OVPN_HANDOFF_N_ERROR,
} ovpn_handoff_error_t;

static char *ovpn_handoff_error_strings[] = {
#define _(sym, string) string,
  foreach_ovpn_handoff_error
#undef _
};

typedef enum
{
  OVPN_HANDOFF_HANDSHAKE,
  OVPN_HANDOFF_INP_DATA,
  OVPN_HANDOFF_OUT_TUN,
} ovpn_handoff_mode_t;

typedef struct ovpn_handoff_trace_t_
{
  u32 next_worker_index;
} ovpn_handoff_trace_t;

static u8 *
format_ovpn_handoff_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_handoff_trace_t *t = va_arg (*args, ovpn_handoff_trace_t *);
  s = format (s, "ovpn handoff: next-worker %d", t->next_worker_index);
  return s;
}

always_inline ovpn_session_error_t
ovpn_create_session (ip46_address_t remote_addr, u8 is_ip4, u32 *sess_index)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_session_t *sess;
  BVT (clib_bihash_kv) kv;
  kv.key[0] = remote_addr.as_u64[0];
  kv.key[1] = remote_addr.as_u64[1];
  kv.value = ~0ULL;

  if (!BV (clib_bihash_search_inline) (&omp->session_hash, &kv))
    return OVPN_SESSION_ERROR_SESSION_ALREADY_EXISTS;

  pool_get (omp->sessions, sess);
  *sess_index = sess - omp->sessions;
  ovpn_session_init (omp->vlib_main, sess, *sess_index, &remote_addr, is_ip4);

  kv.value = *sess_index;
  BV (clib_bihash_add_del) (&omp->session_hash, &kv, 1);
  tw_timer_start_2t_1w_2048sl (&omp->sessions_timer_wheel, *sess_index, 0,
			       OVN_SESSION_EXPIRED_TIMEOUT);
  return OVPN_SESSION_ERROR_NONE;
}

always_inline ovpn_session_error_t
ovpn_find_session (ip46_address_t *remote_addr, u32 *sess_index)
{
  ovpn_main_t *omp = &ovpn_main;
  BVT (clib_bihash_kv) kv;
  kv.key[0] = remote_addr->as_u64[0];
  kv.key[1] = remote_addr->as_u64[1];
  kv.value = ~0ULL;

  if (!BV (clib_bihash_search_inline) (&omp->session_hash, &kv))
    return OVPN_SESSION_ERROR_SESSION_NOT_FOUND;

  *sess_index = kv.value;
  return OVPN_SESSION_ERROR_NONE;
}

always_inline void
ovpn_activate_session (ovpn_session_t *sess)
{
  ovpn_main_t *omp = &ovpn_main;
  sess->state = OVPN_SESSION_STATE_ACTIVE;
  tw_timer_stop_2t_1w_2048sl (&omp->sessions_timer_wheel, sess->index);
  tw_timer_start_2t_1w_2048sl (&omp->sessions_timer_wheel, sess->index, 0,
			       OVN_SESSION_EXPIRED_TIMEOUT);
}

always_inline void
ovpn_free_channel (vlib_main_t *vm, ovpn_channel_t *ch)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_reliable_queue_t *queue;
  queue = pool_elt_at_index (omp->reliable_queues, ch->reliable_queue_index);
  u32 *pkt_id;
  vec_foreach (pkt_id, ch->client_acks)
    {
      ovpn_reliable_dequeue_pkt (vm, queue, *pkt_id);
      tw_timer_stop_2t_1w_2048sl (
	&omp->queues_timer_wheel,
	ovpn_reliable_get_timer_handle (queue, *pkt_id));
    }
  ovpn_reliable_queue_free (queue);
  ovpn_channel_free (ch);
  pool_put_index (omp->channels, ch->index);
  pool_put (omp->channels, ch);
  ovpn_channel_free (ch);
  pool_put (omp->channels, ch);
}

always_inline void
ovpn_free_session (vlib_main_t *vm, ovpn_session_t *sess)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_channel_t *ch;
  BVT (clib_bihash_kv) kv;
  kv.key[0] = sess->remote_addr.as_u64[0];
  kv.key[1] = sess->remote_addr.as_u64[1];
  kv.value = sess->index;
  if (!pool_is_free_index (omp->channels, sess->channel_index))
    {
      ch = pool_elt_at_index (omp->channels, sess->channel_index);
      ovpn_free_channel (vm, ch);
      sess->channel_index = ~0;
    }
  BV (clib_bihash_add_del) (&omp->session_hash, &kv, 0);
  ovpn_session_free (sess);
  pool_put (omp->sessions, sess);
}

always_inline void
ovpn_create_channel (ovpn_session_t *sess, ip46_address_t *remote_addr,
		     u8 is_ip4, u64 remote_session_id, u32 *ch_index)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_channel_t *ch;
  u32 index = ~0;
  pool_get (omp->channels, ch);
  index = ch - omp->channels;
  ovpn_channel_init (omp->vlib_main, ch, omp->ptls_ctx, remote_session_id,
		     remote_addr, is_ip4, index);
  *ch_index = index;
  sess->channel_index = index;
  tw_timer_start_2t_1w_2048sl (&omp->channels_timer_wheel, index, 0,
			       OVN_CHANNEL_EXPIRED_TIMEOUT);
}
always_inline void
ovpn_set_channel_state (vlib_main_t *vm, ovpn_channel_t *ch,
			ovpn_channel_state_t state)
{
  ovpn_main_t *omp = &ovpn_main;
  ch->state = state;
  if (ch->state != OVPN_CHANNEL_STATE_CLOSED)
    {
      tw_timer_stop_2t_1w_2048sl (&omp->channels_timer_wheel, ch->index);
      tw_timer_start_2t_1w_2048sl (&omp->channels_timer_wheel, ch->index, 0,
				   OVN_CHANNEL_EXPIRED_TIMEOUT);
    }
}

always_inline void
ovpn_create_reliable_queue (ovpn_channel_t *ch, u32 *reliable_queue_index)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_reliable_queue_t *queue;
  pool_get (omp->reliable_queues, queue);
  *reliable_queue_index = queue - omp->reliable_queues;
  ovpn_reliable_queue_init (omp->vlib_main, queue, ch->index,
			    *reliable_queue_index);
}

always_inline void
ovpn_prepend_rewrite (vlib_main_t *vm, vlib_buffer_t *b0,
		      ip46_address_t *remote_addr, u16 remote_port, u8 is_ip4)
{
  ovpn_main_t *omp = &ovpn_main;
  if (is_ip4)
    {
      ip4_udp_header_t *hdr4;

      vlib_buffer_advance (b0, -sizeof (*hdr4));
      hdr4 = vlib_buffer_get_current (b0);

      clib_memcpy_fast (&hdr4->ip4.src_address, &omp->local_addr,
			sizeof (ip4_address_t));
      clib_memcpy_fast (&hdr4->ip4.dst_address, remote_addr,
			sizeof (ip4_address_t));
      hdr4->ip4.protocol = IP_PROTOCOL_UDP;

      hdr4->udp.src_port = clib_host_to_net_u16 (UDP_DST_PORT_ovpn);
      hdr4->udp.dst_port = clib_host_to_net_u16 (remote_port);
      hdr4->udp.length =
	clib_host_to_net_u16 (b0->current_length - sizeof (ip4_header_t));

      ip4_header_set_len_w_chksum (&hdr4->ip4,
				   clib_host_to_net_u16 (b0->current_length));
    }
  else
    {
      ip6_udp_header_t *hdr6;

      vlib_buffer_advance (b0, -sizeof (*hdr6));
      hdr6 = vlib_buffer_get_current (b0);

      clib_memcpy_fast (&hdr6->ip6.src_address, &omp->local_addr,
			sizeof (ip6_address_t));
      clib_memcpy_fast (&hdr6->ip6.dst_address, remote_addr,
			sizeof (ip6_address_t));
      hdr6->ip6.protocol = IP_PROTOCOL_UDP;
      hdr6->ip6.dst_address = remote_addr->ip6;

      hdr6->udp.src_port = clib_host_to_net_u16 (UDP_DST_PORT_ovpn);
      hdr6->udp.dst_port = clib_host_to_net_u16 (remote_port);
      hdr6->udp.length =
	clib_host_to_net_u16 (b0->current_length - sizeof (ip6_header_t));
    }
}

always_inline void
ovpn_reliable_enqueue_packet (vlib_main_t *vm, u8 is_ip4, vlib_buffer_t *b0,
			      ovpn_reliable_queue_t *queue)
{
  ovpn_main_t *omp = &ovpn_main;
  u32 pkt_id = ovpn_reliable_queue_pkt (
    vm, queue, is_ip4, vlib_buffer_get_current (b0), b0->current_length);
  tw_timer_start_2t_1w_2048sl (&omp->queues_timer_wheel, queue->index, pkt_id,
			       OVN_RELIABLE_RETRANS_TIMEOUT);
}

always_inline void
ovpn_ip46_enqueue_packet (vlib_main_t *vm, u8 is_ip4, u32 bi0)
{
  vlib_frame_t *f = 0;
  u32 lookup_node_index =
    is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index;
  f = vlib_get_frame_to_node (vm, lookup_node_index);
  /* f can not be NULL here - frame allocation failure causes panic */
  u32 *to_next = vlib_frame_vector_args (f);
  f->n_vectors = 1;
  to_next[0] = bi0;
  vlib_put_frame_to_node (vm, lookup_node_index, f);
}

always_inline void
ovpn_create_ctrl_frame (vlib_main_t *vm, ovpn_channel_t *ch, u8 opcode,
			u32 *replay_pkt_id, u32 *pkt_id, u8 *payload,
			u32 payload_len, u32 *bi0)
{
  vlib_buffer_t *b0;
  ovpn_msg_hdr_t *msg_header;
  ovpn_ctrl_msg_hdr_t *ctrl_msg_hdr;
  u32 *acks;
  u8 *buf;
  u8 hmac[20];
  u32 pkt_len = 0;
  if (vlib_buffer_alloc (vm, bi0, 1) != 1)
    {
      clib_warning ("Failed to allocate buffer");
      return;
    }
  b0 = vlib_get_buffer (vm, *bi0);
  buf = vlib_buffer_get_current (b0);

  /* message header */
  msg_header = (ovpn_msg_hdr_t *) buf;
  msg_header->opcode = opcode;
  msg_header->key_id = 0;

  /* ctrl header */
  ctrl_msg_hdr = (ovpn_ctrl_msg_hdr_t *) (buf + sizeof (ovpn_msg_hdr_t));

  /* local session id */
  ctrl_msg_hdr->session_id = clib_host_to_net_u64 (ch->session_id);

  /* TODO: generate hmac */
  clib_memset_u8 (hmac, 0, 20);
  clib_memcpy_fast (ctrl_msg_hdr->hmac, hmac, 20);

  /* replay packet id */
  ctrl_msg_hdr->replay_packet_id = clib_host_to_net_u32 (*replay_pkt_id);
  (*replay_pkt_id)++;

  /* timestamp */
  ctrl_msg_hdr->timestamp = clib_host_to_net_u32 (unix_time_now ());

  /* acks len */
  ctrl_msg_hdr->acks_len = vec_len (ch->client_acks);

  /* acks */
  acks = (u32 *) (buf + sizeof (ovpn_ctrl_msg_hdr_t));
  for (u8 i = 0; i < ctrl_msg_hdr->acks_len; i++)
    {
      *acks = clib_host_to_net_u32 (ch->client_acks[i]);
      acks++;
    }
  vec_reset_length (ch->client_acks);
  buf += sizeof (ovpn_ctrl_msg_hdr_t) + ctrl_msg_hdr->acks_len * sizeof (u32);

  if (pkt_id != NULL)
    {
      clib_memcpy_fast (buf, pkt_id, sizeof (u32));
      buf += sizeof (u32);
    }

  /* payload */
  if (PREDICT_FALSE (payload_len > 0))
    {
      clib_memcpy_fast (buf, payload, payload_len);
      buf += payload_len;
    }

  pkt_len += sizeof (ovpn_msg_hdr_t) + sizeof (ovpn_ctrl_msg_hdr_t) +
	     ctrl_msg_hdr->acks_len * sizeof (u32);
  if (pkt_id != NULL)
    {
      pkt_len += sizeof (u32);
    }
  if (payload_len > 0)
    {
      pkt_len += payload_len;
    }
  /* update buffer length */
  b0->current_length = pkt_len;
}

always_inline void
ovpn_create_ctrl_ack_v1 (vlib_main_t *vm, u32 *bi0, ovpn_channel_t *ch,
			 u32 *replay_pkt_id)
{
  vlib_buffer_t *b0;
  ovpn_msg_hdr_t *msg_header;
  ovpn_ctrl_msg_hdr_t *ctrl_msg_hdr;
  ovpn_ctrl_msg_ack_v1_t *ctrl_msg_ack_v1;
  u32 *acks;
  u8 *buf;
  u8 hmac[20];
  if (vlib_buffer_alloc (vm, bi0, 1) != 1)
    {
      clib_warning ("Failed to allocate buffer");
      return;
    }
  b0 = vlib_get_buffer (vm, *bi0);
  buf = vlib_buffer_get_current (b0);

  /* message header */
  msg_header = (ovpn_msg_hdr_t *) buf;
  msg_header->opcode = OVPN_OPCODE_TYPE_P_ACK_V1;
  msg_header->key_id = 0;

  /* ctrl header */
  ctrl_msg_hdr = (ovpn_ctrl_msg_hdr_t *) (buf + sizeof (ovpn_msg_hdr_t));

  /* local session id */
  ctrl_msg_hdr->session_id = clib_host_to_net_u64 (ch->session_id);

  /* TODO: generate hmac */
  clib_memset_u8 (hmac, 0, 20);
  clib_memcpy_fast (ctrl_msg_hdr->hmac, hmac, 20);

  /* replay packet id */
  ctrl_msg_hdr->replay_packet_id = clib_host_to_net_u32 (*replay_pkt_id);
  (*replay_pkt_id)++;

  /* acks len */
  ctrl_msg_hdr->acks_len = vec_len (ch->client_acks);

  /* acks */
  acks = (u32 *) (buf + sizeof (ovpn_ctrl_msg_hdr_t));
  for (u8 i = 0; i < ctrl_msg_hdr->acks_len; i++)
    {
      *acks = clib_host_to_net_u32 (ch->client_acks[i]);
      acks++;
    }
  vec_reset_length (ch->client_acks);

  /* payload */
  buf += sizeof (ovpn_ctrl_msg_hdr_t) + ctrl_msg_hdr->acks_len * sizeof (u32);
  /* remote session id */
  ctrl_msg_ack_v1 = (ovpn_ctrl_msg_ack_v1_t *) buf;
  ctrl_msg_ack_v1->session_id = clib_host_to_net_u64 (ch->remote_session_id);

  /* update buffer length */
  b0->current_length = sizeof (ovpn_msg_hdr_t) + sizeof (ovpn_ctrl_msg_hdr_t) +
		       ctrl_msg_hdr->acks_len * sizeof (u32) +
		       sizeof (ovpn_ctrl_msg_ack_v1_t);
}

always_inline void
ovpn_ack_recv_pkt (vlib_main_t *vm, ovpn_channel_t *ch,
		   ovpn_reliable_queue_t *queue, ovpn_reliable_pkt_t *pkt,
		   ip46_address_t *remote_addr, u16 remote_port, u8 is_ip4)
{
  ovpn_main_t *omp = &ovpn_main;
  u32 bi0 = ~0;
  vlib_buffer_t *b0;
  ch = pool_elt_at_index (omp->channels, queue->channel_index);
  vec_add1 (ch->client_acks, pkt->pkt_id);
  ovpn_create_ctrl_ack_v1 (vm, &bi0, ch, &queue->replay_packet_id);
  b0 = vlib_get_buffer (vm, bi0);
  ovpn_prepend_rewrite (vm, b0, remote_addr, remote_port, is_ip4);
  ovpn_ip46_enqueue_packet (vm, is_ip4, bi0);
  ovpn_reliable_ack_recv_pkt (vm, queue, pkt->pkt_id);
}

always_inline void
ovpn_handle_hard_reset_client_v2 (vlib_main_t *vm, uword *event_data)
{
  u32 bi0 = ~0;
  vlib_buffer_t *b0;
  ovpn_main_t *omp = &ovpn_main;
  ovpn_ctrl_event_hard_reset_client_v2_t *event =
    (ovpn_ctrl_event_hard_reset_client_v2_t *) event_data[0];
  ovpn_ctrl_msg_server_hard_reset_v2_t ctrl_msg;
  u32 session_index = ~0;
  u32 channel_index = ~0;
  u32 reliable_queue_index = ~0;
  ovpn_session_t *sess;
  ovpn_channel_t *ch;
  ovpn_reliable_queue_t *queue;

  ovpn_session_error_t error =
    ovpn_create_session (event->remote_addr, event->is_ip4, &session_index);
  if (error == OVPN_SESSION_ERROR_SESSION_ALREADY_EXISTS)
    {
      sess = pool_elt_at_index (omp->sessions, session_index);
      if (PREDICT_FALSE (sess->channel_index != ~0))
	{
	  clib_warning ("Session channel index is not free");
	  goto done;
	}
    }
  else if (error != OVPN_SESSION_ERROR_NONE)
    {
      clib_warning ("Failed to create session: %d", error);
      goto done;
    }
  else
    {
      sess = pool_elt_at_index (omp->sessions, session_index);
    }
  ovpn_create_channel (sess, &event->remote_addr, event->is_ip4,
		       event->remote_session_id, &channel_index);
  ch = pool_elt_at_index (omp->channels, channel_index);

  /* create reliable queue */
  ovpn_create_reliable_queue (ch, &reliable_queue_index);
  queue = pool_elt_at_index (omp->reliable_queues, reliable_queue_index);

  /* set channel and reliable queue index */
  sess->channel_index = channel_index;
  ch->reliable_queue_index = reliable_queue_index;

  /* send hard reset server v2 */
  ctrl_msg.remote_session_id = clib_host_to_net_u64 (event->remote_session_id);
  ovpn_create_ctrl_frame (vm, ch,
			  OVPN_OPCODE_TYPE_P_CONTROL_HARD_RESET_SERVER_V2,
			  &queue->replay_packet_id, &queue->next_send_pkt_id,
			  (u8 *) &ctrl_msg, sizeof (ctrl_msg), &bi0);
  b0 = vlib_get_buffer (vm, bi0);
  ovpn_prepend_rewrite (vm, b0, &event->remote_addr, event->client_port,
			event->is_ip4);
  ovpn_ip46_enqueue_packet (vm, event->is_ip4, bi0);
  ovpn_reliable_enqueue_packet (vm, event->is_ip4, b0, queue);

done:
  clib_mem_free (event);
}

always_inline void
ovpn_handle_ack_v1 (vlib_main_t *vm, uword *event_data)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_session_t *sess;
  ovpn_channel_t *ch;
  ovpn_reliable_queue_t *queue;
  ovpn_ctrl_event_ack_v1_t *event = (ovpn_ctrl_event_ack_v1_t *) event_data[0];
  u32 session_index = ~0;
  ovpn_session_error_t error =
    ovpn_find_session (&event->remote_addr, &session_index);
  if (error != OVPN_SESSION_ERROR_NONE)
    {
      clib_warning ("Failed to find session: %d", error);
      goto done;
    }
  sess = pool_elt_at_index (omp->sessions, session_index);
  if (PREDICT_FALSE (sess->state != OVPN_SESSION_STATE_HANDSHAKING))
    {
      clib_warning ("Session is not in handshaking state");
      goto done;
    }
  if (PREDICT_FALSE (pool_is_free_index (omp->channels, sess->channel_index)))
    {
      clib_warning ("Channel is not found");
      goto done;
    }
  ch = pool_elt_at_index (omp->channels, sess->channel_index);
  if (PREDICT_FALSE (ch->remote_session_id != event->remote_session_id))
    {
      clib_warning ("Remote session id does not match");
      goto done;
    }
  if (PREDICT_FALSE (ch->session_id != event->session_id))
    {
      clib_warning ("Session id does not match");
      goto done;
    }
  queue = pool_elt_at_index (omp->reliable_queues, ch->reliable_queue_index);
  u32 *pkt_id;
  if (event->acks_len > 0)
    {
      vec_foreach (pkt_id, event->acks)
	{
	  ovpn_reliable_dequeue_pkt (vm, queue, *pkt_id);
	  tw_timer_stop_2t_1w_2048sl (
	    &omp->queues_timer_wheel,
	    ovpn_reliable_get_timer_handle (queue, *pkt_id));
	}
      vec_free (event->acks);
    }
  if (ch->state == OVPN_CHANNEL_STATE_INIT)
    {
      ch->state = OVPN_CHANNEL_STATE_SSL_HANDSHAKE;
      sess->state = OVPN_SESSION_STATE_HANDSHAKING;
    }

done:
  clib_mem_free (event);
}

always_inline ovpn_error_t
ovpn_send_ssl_handshake_response (vlib_main_t *vm, ip46_address_t *remote_addr,
				  u16 remote_port, u8 is_ip4,
				  ovpn_channel_t *ch,
				  ovpn_reliable_queue_t *queue, u8 *payload,
				  u32 payload_len)
{
  u32 bi0 = ~0;
  vlib_buffer_t *b0;
  ovpn_create_ctrl_frame (vm, ch, OVPN_OPCODE_TYPE_P_CONTROL_V1,
			  &queue->replay_packet_id, &queue->next_send_pkt_id,
			  payload, payload_len, &bi0);
  b0 = vlib_get_buffer (vm, bi0);
  ovpn_prepend_rewrite (vm, b0, remote_addr, remote_port, is_ip4);
  ovpn_ip46_enqueue_packet (vm, is_ip4, bi0);
  ovpn_reliable_enqueue_packet (vm, is_ip4, b0, queue);
  return OVPN_ERROR_NONE;
}

always_inline ovpn_error_t
ovpn_handle_ssl_handshake (vlib_main_t *vm, ip46_address_t *remote_addr,
			   u32 pkt_id, u16 remote_port, u8 is_ip4,
			   u64 remote_session_id, u8 *data, u32 data_len)
{
  ovpn_main_t *omp = &ovpn_main;
  u32 sess_index = ~0;
  ovpn_session_t *sess;
  ovpn_channel_t *ch;
  ovpn_reliable_queue_t *queue;
  ovpn_reliable_pkt_t *pkt = NULL;
  ovpn_error_t error = OVPN_ERROR_NONE;
  int rv;

  /* 找 session */
  if (ovpn_find_session (remote_addr, &sess_index) != OVPN_SESSION_ERROR_NONE)
    {
      error = OVPN_ERROR_SSL_HANDSHAKE_FAILED;
      goto done;
    }
  sess = pool_elt_at_index (omp->sessions, sess_index);

  /* 验证 channel */
  if (PREDICT_FALSE (pool_is_free_index (omp->channels, sess->channel_index)))
    goto done;
  ch = pool_elt_at_index (omp->channels, sess->channel_index);
  if (PREDICT_FALSE (ch->remote_session_id != remote_session_id))
    goto done;
  if (PREDICT_FALSE (sess->state != OVPN_SESSION_STATE_HANDSHAKING))
    {
      error = OVPN_ERROR_SSL_HANDSHAKE_FAILED;
      goto done;
    }
  if (PREDICT_FALSE (ch->state != OVPN_CHANNEL_STATE_SSL_HANDSHAKE))
    {
      error = OVPN_ERROR_SSL_HANDSHAKE_FAILED;
      goto done;
    }

  /* 把收到的 pkt 入队（重复包非致命，-1/其它负值视为失败） */
  queue = pool_elt_at_index (omp->reliable_queues, ch->reliable_queue_index);
  rv = ovpn_reliable_queue_recv_pkt (vm, queue, pkt_id, data, data_len);
  if (rv < 0)
    {
      /* 内存/其它严重错误 */
      error = OVPN_ERROR_SSL_HANDSHAKE_FAILED;
      goto done;
    }

  /* 开始按序 dequeue 并处理；目标是一直尝试 dequeue 直到空 */
  ovpn_reliable_dequeue_recv_pkt (vm, queue, &pkt);

  while (pkt != NULL)
    {
      /* 如果已经被 ack 过，向对端 ack（确保对端知道）并继续下一个 pkt */
      if (pkt->recv.acked)
	{
	  ovpn_ack_recv_pkt (vm, ch, queue, pkt, remote_addr, remote_port,
			     is_ip4);
	  ovpn_reliable_dequeue_recv_pkt (vm, queue, &pkt);
	  continue;
	}

      /* 对当前 pkt 的 data 进行连续消费（类似 socket recvbuf 的 roff/consumed
       * 逻辑） */
      {
	size_t roff = 0;
	int hs_ret = PTLS_ERROR_IN_PROGRESS;

	/* 当握手仍需要并且当前 pkt 还有未消费的数据时，反复调用 ptls_handshake
	 */
	while (hs_ret == PTLS_ERROR_IN_PROGRESS && roff < pkt->data_len)
	  {
	    ptls_buffer_t wbuf;
	    ptls_buffer_init (&wbuf, NULL, 0);

	    size_t consumed = pkt->data_len - roff;
	    hs_ret = ptls_handshake (ch->tls, &wbuf, pkt->data + roff,
				     &consumed, NULL);
	    /* consumed 表示本次调用消费了多少输入 */
	    roff += consumed;

	    /* 如果 ptls 写了响应到 wbuf，要立刻发送（按帧分片） */
	    if (wbuf.off > 0)
	      {
		size_t remaining = wbuf.off;
		uint8_t *resp = (uint8_t *) wbuf.base;
		while (remaining > 0)
		  {
		    u32 chunk = (remaining > OVPN_FRAME_SIZE) ?
				  OVPN_FRAME_SIZE :
				  (u32) remaining;
		    ovpn_send_ssl_handshake_response (vm, remote_addr,
						      remote_port, is_ip4, ch,
						      queue, resp, chunk);
		    resp += chunk;
		    remaining -= chunk;
		  }
	      }

	    ptls_buffer_dispose (&wbuf);

	    /* 如果握手完成（hs_ret == 0）或出错（hs_ret < 0 且 !=
	     * IN_PROGRESS），退出内循环处理结果 */
	  } /* end inner handshake loop */

	/* 根据握手结果处理 */
	if (hs_ret == 0)
	  {

	    if (PREDICT_TRUE (ptls_handshake_is_complete (ch->tls)))
	      {
		/* 可在此处生成 key material（TODO） */
		/* 握手成功：更新状态并激活 session */
		ovpn_set_channel_state (
		  vm, ch, OVPN_CHANNEL_STATE_SSL_HANDSHAKE_FINISHED);
		ovpn_activate_session (sess);
	      }

	    /* 握手成功后我们可以选择：1) 忽略并丢弃该 pkt；2)
	       继续处理队列中的下一个 pkt
	       目前选择退出循环（握手完成），如果你希望继续处理队列可将 break
	       改为 ovpn_reliable_dequeue_recv_pkt(...) 继续。 */
	    break;
	  }
	else if (hs_ret == PTLS_ERROR_IN_PROGRESS)
	  {
	    /*
	     * 表示：我们已经消费了这个 pkt 的全部输入（roff ==
	     * pkt->data_len）， 但握手仍未完成，需要等待更多来自对端的数据 ——
	     * 我们发送了上面 wbuf 中的响应（如果有） 然后 ack 这个
	     * pkt（告诉对端已收到）并继续 dequeue 下一个输入 pkt。
	     */
	    ovpn_ack_recv_pkt (vm, ch, queue, pkt, remote_addr, remote_port,
			       is_ip4);
	    ovpn_reliable_dequeue_recv_pkt (vm, queue, &pkt);
	    continue; /* 继续外层 while 以处理下一个 pkt（或退出如果没有） */
	  }
	else
	  {
	    /* 其它错误：握手失败，关闭 channel 并返回错误 */
	    ch->state = OVPN_CHANNEL_STATE_CLOSED;
	    error = OVPN_ERROR_SSL_HANDSHAKE_FAILED;
	    goto done;
	  }
      } /* end pkt handling block */
    } /* end while pkt */

done:
  return error;
}

always_inline void
ovpn_handle_session_expired (vlib_main_t *vm, uword *event_data)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_session_t *sess = pool_elt_at_index (omp->sessions, event_data[0]);
  ovpn_free_session (vm, sess);
}

always_inline void
ovpn_handle_channel_expired (vlib_main_t *vm, uword *event_data)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_channel_t *ch = pool_elt_at_index (omp->channels, event_data[0]);
  ovpn_free_channel (vm, ch);
}

always_inline void
ovpn_handle_reliable_send_queue_expired (vlib_main_t *vm, uword *event_data)
{
  ovpn_main_t *omp = &ovpn_main;
  u32 bi0 = ~0;
  vlib_buffer_t *b0;
  ovpn_reliable_send_queue_event_t *event =
    (ovpn_reliable_send_queue_event_t *) event_data[0];
  ovpn_reliable_queue_t *queue =
    pool_elt_at_index (omp->reliable_queues, event->queue_index);
  ovpn_reliable_pkt_t *pkt = NULL;
  if (ovpn_reliable_retransmit_pkt (vm, queue, event->pkt_id, &pkt) == 0)
    {
      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  clib_warning ("Failed to allocate buffer");
	  goto done;
	}
      if (pkt == NULL)
	{
	  goto done;
	}
      b0 = vlib_get_buffer (vm, bi0);
      clib_memcpy_fast (vlib_buffer_get_current (b0), pkt->data,
			pkt->data_len);
      ovpn_ip46_enqueue_packet (vm, pkt->send.is_ip4, bi0);
      tw_timer_start_2t_1w_2048sl (&omp->queues_timer_wheel, queue->index,
				   event->pkt_id,
				   OVN_RELIABLE_RETRANS_TIMEOUT);
    }
done:
  clib_mem_free (event);
}

static uword
ovpn_timer_process (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame)
{
  ovpn_main_t *omp = &ovpn_main;
  f64 now;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 1.0);
      now = vlib_time_now (vm);
      tw_timer_expire_timers_2t_1w_2048sl (&omp->sessions_timer_wheel, now);
      tw_timer_expire_timers_2t_1w_2048sl (&omp->channels_timer_wheel, now);
      tw_timer_expire_timers_2t_1w_2048sl (&omp->queues_timer_wheel, now);
    }
  return 0;
}

static uword
ovpn_ctrl_process (vlib_main_t *vm, vlib_node_runtime_t *node,
		   vlib_frame_t *frame)
{
  uword *event_data = 0;
  uword event_type;
  int i;

  while (1)
    {
      vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, (uword **) &event_data);

      switch (event_type)
	{
	case OVPN_CTRL_EVENT_TYPE_HARD_RESET_CLIENT_V2:
	  for (i = 0; i < vec_len (event_data); i++)
	    ovpn_handle_hard_reset_client_v2 (vm, event_data);
	  break;
	case OVPN_CTRL_EVENT_TYPE_ACK_V1:
	  for (i = 0; i < vec_len (event_data); i++)
	    ovpn_handle_ack_v1 (vm, event_data);
	  break;
	case OVPN_CTRL_EVENT_TYPE_SESSION_EXPIRED:
	  for (i = 0; i < vec_len (event_data); i++)
	    ovpn_handle_session_expired (vm, event_data);
	  break;
	case OVPN_CTRL_EVENT_TYPE_CHANNEL_EXPIRED:
	  for (i = 0; i < vec_len (event_data); i++)
	    ovpn_handle_channel_expired (vm, event_data);
	  break;
	case OVPN_CTRL_EVENT_TYPE_RELIABLE_SEND_QUEUE_EXPIRED:
	  for (i = 0; i < vec_len (event_data); i++)
	    ovpn_handle_reliable_send_queue_expired (vm, event_data);
	  break;
	default:
	  clib_warning ("Unexpected event type %d", event_type);
	  break;
	}
      vec_reset_length (event_data);
    }
  return 0;
}

always_inline uword
ovpn_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		   vlib_frame_t *frame, u8 is_ip4)
{
  u32 n_left_from, *from, *to_next;
  ovpn_next_t next_index;
  ovpn_main_t *omp = &ovpn_main;
  clib_thread_index_t thread_index = vlib_get_thread_index ();

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = OVPN_NEXT_DROP;
	  u32 error0 = OVPN_ERROR_NONE;
	  ovpn_msg_hdr_t *msg_hdr0;
	  ip4_header_t *ip40 = NULL;
	  ip6_header_t *ip60 = NULL;
	  udp_header_t *udp0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  msg_hdr0 = vlib_buffer_get_current (b0);
	  u8 *payload = (u8 *) msg_hdr0 + sizeof (ovpn_msg_hdr_t);
	  udp0 = (udp_header_t *) ((u8 *) msg_hdr0 - sizeof (udp_header_t));

	  if (PREDICT_FALSE (udp0->dst_port !=
			       clib_host_to_net_u16 (UDP_DST_PORT_ovpn) ||
			     ip46_address_is_zero (&omp->local_addr)))
	    {
	      next0 = OVPN_NEXT_DROP;
	      error0 = OVPN_ERROR_NONE;
	      goto done0;
	    }

	  if (is_ip4)
	    {
	      ip40 = (ip4_header_t *) ((u8 *) udp0 - sizeof (ip4_header_t));
	    }
	  else
	    {
	      ip60 = (ip6_header_t *) ((u8 *) udp0 - sizeof (ip6_header_t));
	    }
	  if (PREDICT_TRUE (msg_hdr0->opcode == OVPN_OPCODE_TYPE_P_DATA_V1))
	    {
	      // TODO: handle data
	    }
	  else if (PREDICT_FALSE (
		     msg_hdr0->opcode ==
		     OVPN_OPCODE_TYPE_P_CONTROL_HARD_RESET_CLIENT_V1))
	    {
	      ovpn_ctrl_msg_hdr_t *ctrl_msg_hdr0 =
		(ovpn_ctrl_msg_hdr_t *) payload;
	      ovpn_ctrl_msg_client_hard_reset_v2_t *data =
		(ovpn_ctrl_msg_client_hard_reset_v2_t
		   *) (payload + sizeof (ovpn_ctrl_msg_hdr_t) +
		       ctrl_msg_hdr0->acks_len * sizeof (u32));
	      ovpn_ctrl_event_hard_reset_client_v2_t *ctrl_event0 =
		clib_mem_alloc (
		  sizeof (ovpn_ctrl_event_hard_reset_client_v2_t));

	      clib_memset (ctrl_event0, 0,
			   sizeof (ovpn_ctrl_event_hard_reset_client_v2_t));

	      /* client port */
	      ctrl_event0->client_port = clib_net_to_host_u16 (udp0->src_port);

	      /* remote address */
	      ctrl_event0->is_ip4 = is_ip4;
	      if (is_ip4)
		{
		  clib_memcpy_fast (&ctrl_event0->remote_addr,
				    &ip40->src_address,
				    sizeof (ip46_address_t));
		}
	      else
		{
		  clib_memcpy_fast (&ctrl_event0->remote_addr,
				    &ip60->src_address,
				    sizeof (ip46_address_t));
		}

	      /* remote session id */
	      ctrl_event0->remote_session_id =
		clib_net_to_host_u64 (ctrl_msg_hdr0->session_id);

	      /* hmac */
	      clib_memcpy_fast (&ctrl_event0->hmac, ctrl_msg_hdr0->hmac, 20);

	      /* acks */
	      ctrl_event0->pkt_id = clib_net_to_host_u32 (data->pkt_id);

	      vlib_process_signal_event_mt (
		vm, omp->ctrl_node_index,
		OVPN_CTRL_EVENT_TYPE_HARD_RESET_CLIENT_V2,
		(uword) ctrl_event0);
	    }
	  else if (PREDICT_FALSE (msg_hdr0->opcode ==
				  OVPN_OPCODE_TYPE_P_CONTROL_SOFT_RESET_V1))
	    {
	      // TODO: handle soft reset
	    }
	  else if (PREDICT_FALSE (msg_hdr0->opcode ==
				  OVPN_OPCODE_TYPE_P_ACK_V1))
	    {
	      ovpn_ctrl_msg_hdr_t *ctrl_msg_hdr0 =
		(ovpn_ctrl_msg_hdr_t *) payload;
	      u32 *acks = (u32 *) (payload + sizeof (ovpn_ctrl_msg_hdr_t));
	      ovpn_ctrl_msg_ack_v1_t *data =
		(ovpn_ctrl_msg_ack_v1_t *) (payload +
					    sizeof (ovpn_ctrl_msg_hdr_t) +
					    ctrl_msg_hdr0->acks_len *
					      sizeof (u32));
	      ovpn_ctrl_event_ack_v1_t *ctrl_event0 =
		clib_mem_alloc (sizeof (ovpn_ctrl_event_ack_v1_t));
	      clib_memset (ctrl_event0, 0, sizeof (ovpn_ctrl_event_ack_v1_t));

	      /* remote address */
	      if (is_ip4)
		{
		  clib_memcpy_fast (&ctrl_event0->remote_addr,
				    &ip40->src_address,
				    sizeof (ip46_address_t));
		}
	      else
		{
		  clib_memcpy_fast (&ctrl_event0->remote_addr,
				    &ip60->src_address,
				    sizeof (ip46_address_t));
		}

	      /* remote session id(Server side) */
	      ctrl_event0->remote_session_id =
		clib_net_to_host_u64 (ctrl_msg_hdr0->session_id);

	      /* hmac */
	      clib_memcpy_fast (&ctrl_event0->hmac, ctrl_msg_hdr0->hmac, 20);

	      if (ctrl_msg_hdr0->acks_len > 0)
		{
		  vec_validate_init_empty (ctrl_event0->acks,
					   ctrl_msg_hdr0->acks_len - 1, ~0);
		  for (u8 i = 0; i < ctrl_msg_hdr0->acks_len; i++)
		    {
		      ctrl_event0->acks[i] = clib_net_to_host_u32 (acks[i]);
		      acks++;
		    }
		}
	      /* session id(Client side) */
	      ctrl_event0->session_id =
		clib_net_to_host_u64 (data->session_id);

	      vlib_process_signal_event_mt (vm, omp->ctrl_node_index,
					    OVPN_CTRL_EVENT_TYPE_ACK_V1,
					    (uword) ctrl_event0);
	    }
	  else if (PREDICT_FALSE (msg_hdr0->opcode ==
				  OVPN_OPCODE_TYPE_P_CONTROL_V1))
	    {
	      if (thread_index != 0)
		{
		  next0 = OVPN_NEXT_HANDOFF_HANDSHAKE;
		}
	      else
		{
		  ovpn_ctrl_msg_hdr_t *ctrl_msg_hdr0 =
		    (ovpn_ctrl_msg_hdr_t *) payload;
		  payload += sizeof (ovpn_ctrl_msg_hdr_t) +
			     ctrl_msg_hdr0->acks_len * sizeof (u32);
		  ovpn_ctrl_msg_control_v1_t *ctrl_msg_control_v1 =
		    (ovpn_ctrl_msg_control_v1_t *) payload;
		  /* packet id*/
		  u32 pkt_id = ctrl_msg_control_v1->pkt_id;
		  payload += sizeof (ovpn_ctrl_msg_control_v1_t);

		  u32 payload_len =
		    b0->current_length - sizeof (ovpn_ctrl_msg_hdr_t) -
		    ctrl_msg_hdr0->acks_len * sizeof (u32) + sizeof (u32);

		  if (payload_len < 0)
		    {
		      b0->error = node->errors[OVPN_ERROR_MALFORMED];
		      goto done0;
		    }

		  if (is_ip4)
		    {
		      ip40 =
			(ip4_header_t *) ((u8 *) udp0 - sizeof (ip4_header_t));
		      // handle ssl handshake
		      ovpn_handle_ssl_handshake (
			vm, (ip46_address_t *) &ip40->src_address,
			clib_net_to_host_u32 (pkt_id),
			clib_net_to_host_u16 (udp0->src_port), 1,
			clib_net_to_host_u64 (ctrl_msg_hdr0->session_id),
			payload, payload_len);
		    }
		  else
		    {
		      ip60 =
			(ip6_header_t *) ((u8 *) udp0 - sizeof (ip6_header_t));
		      // handle ssl handshake
		      ovpn_handle_ssl_handshake (
			vm, (ip46_address_t *) &ip60->src_address,
			clib_net_to_host_u32 (pkt_id),
			clib_net_to_host_u16 (udp0->src_port), 0,
			clib_net_to_host_u64 (ctrl_msg_hdr0->session_id),
			payload, payload_len);
		    }
		}
	    }
	  else
	    {
	      error0 = OVPN_ERROR_UNKNOWN_OPCODE;
	    }

	done0:
	  b0->error = node->errors[error0];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      ovpn_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next0;
	    }
	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return n_left_from;
}

always_inline uword
ovpn_handoff_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame, ovpn_handoff_mode_t mode,
		     u32 fq_index)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 n_enq, n_left_from, *from;
  ovpn_main_t *omp = &ovpn_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);
  ti = thread_indices;
  b = bufs;

  while (n_left_from > 0)
    {
      if (mode == OVPN_HANDOFF_HANDSHAKE)
	{
	  ti[0] = 0;
	}
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ovpn_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->next_worker_index = ti[0];
	}
      n_left_from -= 1;
      ti += 1;
      b += 1;
    }
  n_enq = vlib_buffer_enqueue_to_thread (vm, node, omp->in4_index, from,
					 thread_indices, frame->n_vectors, 1);
  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 OVPN_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);
  return n_enq;
}

VLIB_NODE_FN (ovpn4_handoff_handshake_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff_inline (vm, node, frame, OVPN_HANDOFF_HANDSHAKE,
			      omp->in4_index);
}

VLIB_NODE_FN (ovpn6_handoff_handshake_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff_inline (vm, node, frame, OVPN_HANDOFF_HANDSHAKE,
			      omp->in6_index);
}

VLIB_NODE_FN (ovpn4_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_input_inline (vm, node, frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (ovpn6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_input_inline (vm, node, frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (ovpn_timer_process_node) = {
  .function = ovpn_timer_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ovpn-timer-process",
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (ovpn_ctrl_process_node) = {
  .function = ovpn_ctrl_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ovpn-ctrl-process",
  .n_next_nodes = 0,
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ovpn4_handoff_handshake_node) = {
  .name = "ovpn4-handoff-handshake",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ovpn_handoff_error_strings),
  .error_strings = ovpn_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ovpn6_handoff_handshake_node) = {
  .name = "ovpn6-handoff-handshake",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ovpn_handoff_error_strings),
  .error_strings = ovpn_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (ovpn4_input_node) = 
{
  .name = "ovpn4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(ovpn_error_strings),
  .error_strings = ovpn_error_strings,

  .n_next_nodes = OVPN_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [OVPN_NEXT_IP_LOOKUP] = "ovpn4-handoff-handshake",
        [OVPN_NEXT_HANDOFF_HANDSHAKE] = "ovpn4-handoff-handshake",
        [OVPN_NEXT_DROP] = "error-drop",
  },
};
#endif /* CLIB_MARCH_VARIANT */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (ovpn6_input_node) = 
{
  .name = "ovpn6-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(ovpn_error_strings),
  .error_strings = ovpn_error_strings,

  .n_next_nodes = OVPN_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [OVPN_NEXT_IP_LOOKUP] = "ip6-lookup",
        [OVPN_NEXT_HANDOFF_HANDSHAKE] = "ovpn6-handoff-handshake",
        [OVPN_NEXT_DROP] = "error-drop",
  },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
