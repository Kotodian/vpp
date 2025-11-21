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
#include <vnet/ip/ip_types.h>
#include <vnet/crypto/crypto.h>
#include <vnet/ip/ip46_address.h>
#include <vppinfra/vec_bootstrap.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <ovpn/ovpn_channel.h>
#include <ovpn/ovpn_reliable.h>
#include <picotls.h>
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
#include <ovpn/ovpn_if.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} ovpn_trace_t;

/* packet trace format function */
#ifndef CLIB_MARCH_VARIANT
static u8 *
format_ovpn_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_trace_t *t = va_arg (*args, ovpn_trace_t *);

  s = format (s, "ovpn: sw_if_index %d, next_index %d", t->sw_if_index,
	      t->next_index);
  return s;
}
#endif /* CLIB_MARCH_VARIANT */

#define foreach_ovpn_error                                                    \
  _ (NONE, "No error")                                                        \
  _ (MALFORMED, "Malformed data")                                             \
  _ (UNKNOWN_OPCODE, "Unknown opcode")                                        \
  _ (SSL_HANDSHAKE_FAILED, "SSL handshake failed")                            \
  _ (INVALID_KEY_METHOD, "Invalid key method")                                \
  _ (FAILED_TO_ALLOCATE_BUFFER, "Failed to allocate buffer")                  \
  _ (DECRYPT_FAILED, "Failed to decrypt data")                                \
  _ (HMAC_CHECK_FAILED, "HMAC check failed")

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
  OVPN_NEXT_IP4_INPUT,
  OVPN_NEXT_IP6_INPUT,
  OVPN_NEXT_HANDOFF_HANDSHAKE,
  OVPN_NEXT_HANDOFF_DATA,
  OVPN_NEXT_OUTPUT,
  OVPN_NEXT_DROP,
  OVPN_N_NEXT,
} ovpn_input_next_t;

#define foreach_ovpn_handoff_error _ (CONGESTION_DROP, "congestion drop")

typedef enum
{
#define _(sym, str) OVPN_HANDOFF_ERROR_##sym,
  foreach_ovpn_handoff_error
#undef _
    OVPN_HANDOFF_N_ERROR,
} ovpn_handoff_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *ovpn_handoff_error_strings[] = {
#define _(sym, string) string,
  foreach_ovpn_handoff_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

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

#ifndef CLIB_MARCH_VARIANT
static u8 *
format_ovpn_handoff_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_handoff_trace_t *t = va_arg (*args, ovpn_handoff_trace_t *);
  s = format (s, "ovpn handoff: next-worker %d", t->next_worker_index);
  return s;
}
#endif /* CLIB_MARCH_VARIANT */

typedef struct ovpn_output_trace_t_
{
} ovpn_output_trace_t;

#ifndef CLIB_MARCH_VARIANT
static u8 *
format_ovpn_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  return s;
}
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  OVPN_NEXT_OUTPUT_HANDOFF,
  OVPN_NEXT_OUTPUT_INTERFACE,
  OVPN_NEXT_OUTPUT_DROP,
  OVPN_OUTPUT_N_NEXT,
} ovpn_output_next_t;

always_inline void
ovpn_calculate_hmac (u8 *key, u8 *data, u32 len, u8 *out)
{
  unsigned int out_len;
  HMAC (EVP_sha256 (), key, 256, data, len, out, &out_len);
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
  ovpn_main_t *omp = &ovpn_main;

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

  /* Calculate HMAC */
  if (omp->psk_set)
    ovpn_calculate_hmac (omp->psk, buf, pkt_len, hmac);
  clib_memcpy_fast (ctrl_msg_hdr->hmac, hmac, 20);
}

always_inline void
ovpn_create_channel (ovpn_session_t *sess, ip46_address_t *remote_addr,
		     u8 is_ip4, u64 remote_session_id, index_t *ch_index)
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
			       (u64) OVN_CHANNEL_EXPIRED_TIMEOUT);
}
always_inline void
ovpn_set_channel_state (ovpn_channel_t *ch, ovpn_channel_state_t state)
{
  ovpn_main_t *omp = &ovpn_main;
  ch->state = state;
  if (ch->state != OVPN_CHANNEL_STATE_CLOSED)
    {
      tw_timer_update_2t_1w_2048sl (&omp->channels_timer_wheel, ch->index,
				    (u64) OVN_CHANNEL_EXPIRED_TIMEOUT);
    }
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

  vlib_worker_thread_barrier_sync (omp->vlib_main);

  pool_get_aligned (omp->sessions, sess, CLIB_CACHE_LINE_BYTES);
  *sess_index = sess - omp->sessions;
  ovpn_session_init (omp->vlib_main, sess, *sess_index, &remote_addr, is_ip4);

  kv.value = *sess_index;
  BV (clib_bihash_add_del) (&omp->session_hash, &kv, 1);
  tw_timer_start_2t_1w_2048sl (&omp->sessions_timer_wheel, *sess_index, 0,
			       (u64) OVN_SESSION_EXPIRED_TIMEOUT);

  vlib_worker_thread_barrier_release (omp->vlib_main);

  return OVPN_SESSION_ERROR_NONE;
}

always_inline ovpn_session_error_t
ovpn_find_session (ip46_address_t *remote_addr, index_t *sess_index)
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
ovpn_activate_session (ovpn_session_t *sess, ovpn_channel_t *ch)
{
  ovpn_main_t *omp = &ovpn_main;
  vlib_main_t *vm = omp->vlib_main;

  /* Register key to crypto engine */
  ovpn_key2_t *key2 = pool_elt_at_index (omp->key2s, sess->key2_index);
  key2->recv_key_index =
    vnet_crypto_key_add (vm, VNET_CRYPTO_ALG_CHACHA20_POLY1305,
			 key2->keys[OVPN_KEY_DIR_TO_SERVER].cipher,
			 sizeof (key2->keys[OVPN_KEY_DIR_TO_SERVER].cipher));
  key2->send_key_index =
    vnet_crypto_key_add (vm, VNET_CRYPTO_ALG_CHACHA20_POLY1305,
			 key2->keys[OVPN_KEY_DIR_TO_CLIENT].cipher,
			 sizeof (key2->keys[OVPN_KEY_DIR_TO_CLIENT].cipher));

  vlib_worker_thread_barrier_sync (vm);
  ovpn_if_add_peer (&omp->if_instance, &omp->tunnel_ip_pool, sess->index,
		    &sess->peer_index);
  ovpn_set_channel_state (ch, OVPN_CHANNEL_STATE_SSL_HANDSHAKE_FINISHED);
  sess->state = OVPN_SESSION_STATE_ACTIVE;

  tw_timer_update_2t_1w_2048sl (&omp->sessions_timer_wheel, sess->index,
				(u64) OVN_SESSION_EXPIRED_TIMEOUT);

  vlib_worker_thread_barrier_release (vm);
}

always_inline void
ovpn_free_channel (vlib_main_t *vm, ovpn_channel_t *ch)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_reliable_queue_t *queue;
  queue = pool_elt_at_index (omp->reliable_queues, ch->reliable_queue_index);
  ovpn_reliable_pkt_t *pkt;
  pool_foreach (pkt, queue->unacked_pkts)
    {
      tw_timer_stop_2t_1w_2048sl (
	&omp->queues_timer_wheel,
	ovpn_reliable_get_timer_handle (queue, pkt->pkt_id));
      ovpn_reliable_dequeue_pkt (vm, queue, pkt->pkt_id);
    }
  if (ch->key_source_index != ~0 &&
      !pool_is_free_index (omp->key_sources, ch->key_source_index))
    {
      ovpn_key_source_t *ks =
	pool_elt_at_index (omp->key_sources, ch->key_source_index);
      ovpn_secure_zero_memory (ks->pre_master_secret, 48);
      ovpn_secure_zero_memory (ks->client_prf_seed_master_secret, 32);
      ovpn_secure_zero_memory (ks->client_prf_seed_key_expansion, 32);
      ovpn_secure_zero_memory (ks->server_prf_seed_master_secret, 32);
      ovpn_secure_zero_memory (ks->server_prf_seed_key_expansion, 32);
      pool_put (omp->key_sources, ks);
    }
  ovpn_reliable_queue_free (queue);
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
  vlib_worker_thread_barrier_sync (vm);

  BV (clib_bihash_add_del) (&omp->session_hash, &kv, 0);
  if (!pool_is_free_index (omp->channels, sess->channel_index))
    {
      ch = pool_elt_at_index (omp->channels, sess->channel_index);
      ovpn_free_channel (vm, ch);
      sess->channel_index = ~0;
    }
  if (!pool_is_free_index (omp->key2s, sess->key2_index))
    {
      ovpn_key2_t *key2 = pool_elt_at_index (omp->key2s, sess->key2_index);
      ovpn_secure_zero_memory (key2->keys, sizeof (key2->keys));
      vnet_crypto_key_del (vm, key2->recv_key_index);
      vnet_crypto_key_del (vm, key2->send_key_index);
      pool_put (omp->key2s, key2);
      sess->key2_index = ~0;
    }
  sess->input_thread_index = ~0;
  ovpn_if_remove_peer (&omp->if_instance, sess->peer_index);

  ovpn_session_free (sess);
  pool_put (omp->sessions, sess);

  vlib_worker_thread_barrier_release (vm);
}

always_inline void
ovpn_create_reliable_queue (ovpn_channel_t *ch, index_t *reliable_queue_index)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_reliable_queue_t *queue;
  pool_get (omp->reliable_queues, queue);
  *reliable_queue_index = queue - omp->reliable_queues;
  ovpn_reliable_queue_init (omp->vlib_main, queue, ch->index,
			    *reliable_queue_index);
}

always_inline void
ovpn_prepend_rewrite (vlib_buffer_t *b0, ip46_address_t *remote_addr,
		      u16 remote_port, u8 is_ip4)
{
  ovpn_main_t *omp = &ovpn_main;
  if (is_ip4)
    {
      ip4_udp_header_t *hdr4;

      vlib_buffer_advance (b0, -sizeof (*hdr4));
      hdr4 = vlib_buffer_get_current (b0);

      ip46_address_set_ip4 (&omp->src_ip, &hdr4->ip4.src_address);
      ip46_address_set_ip4 (remote_addr, &hdr4->ip4.dst_address);
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

      ip46_address_set_ip6 (&omp->src_ip, &hdr6->ip6.src_address);
      ip46_address_set_ip6 (remote_addr, &hdr6->ip6.dst_address);
      hdr6->ip6.protocol = IP_PROTOCOL_UDP;

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
ovpn_send_reliable_pkt (vlib_main_t *vm, ovpn_reliable_queue_t *queue,
			u8 is_ip4, u32 bi0, ip46_address_t *remote_addr,
			u16 remote_port)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  ovpn_prepend_rewrite (b0, remote_addr, remote_port, is_ip4);
  ovpn_ip46_enqueue_packet (vm, is_ip4, bi0);
  ovpn_reliable_enqueue_packet (vm, is_ip4, b0, queue);
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
  /* OpenVPN uses HMAC-SHA1 or SHA256. For now we zero it out.
   * Real implementation should use vnet_crypto to compute HMAC
   * using the integrity key derived during handshake.
   */
  ovpn_main_t *omp = &ovpn_main;
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

  /* Calculate HMAC */
  if (omp->psk_set)
    ovpn_calculate_hmac (omp->psk, buf, b0->current_length, hmac);
  clib_memcpy_fast (ctrl_msg_hdr->hmac, hmac, 20);
}

always_inline void
ovpn_create_key_negotiation_response (ovpn_key_source_t *ks, u8 **output,
				      u32 *output_len)
{
  ovpn_main_t *omp = &ovpn_main;
  u8 *buf;
  u8 literal[4];
  u16 options_length = clib_host_to_net_u16 (omp->options_length);

  clib_memset (literal, 0, 4);

  /* Literal 0 4 bytes */
  vec_resize (buf, 4 + 1 + 32 + 32 + 2 + omp->options_length + 1);
  clib_memcpy_fast (buf, literal, 4);
  /* Key method type 1 byte */
  buf[4] = 2;
  /* Key source 32 bytes + 32 bytes */
  clib_memcpy_fast (buf + 5 + 32, ks->server_prf_seed_master_secret, 32);
  clib_memcpy_fast (buf + 5 + 32 + 32, ks->server_prf_seed_key_expansion, 32);

  /* options*/
  clib_memcpy_fast (buf + 5 + 32 + 32 + 2, &options_length, 2);
  clib_memcpy_fast (buf + 5 + 32 + 32 + 2, omp->options, omp->options_length);
  /* null terminator */
  buf[5 + 32 + 32 + 2 + omp->options_length] = 0;

  /* TODO: username and password */

  *output = buf;
  *output_len = vec_len (buf);
}

always_inline void
ovpn_send_ack_recv_pkt (vlib_main_t *vm, ovpn_channel_t *ch,
			ovpn_reliable_queue_t *queue, ovpn_reliable_pkt_t *pkt,
			ip46_address_t *remote_addr, u16 remote_port,
			u8 is_ip4)
{
  ovpn_main_t *omp = &ovpn_main;
  u32 bi0 = ~0;
  ch = pool_elt_at_index (omp->channels, queue->channel_index);
  vec_add1 (ch->client_acks, pkt->pkt_id);
  ovpn_create_ctrl_ack_v1 (vm, &bi0, ch, &queue->replay_packet_id);
  ovpn_send_reliable_pkt (vm, queue, is_ip4, bi0, remote_addr, remote_port);
  ovpn_reliable_ack_recv_pkt (vm, queue, pkt->pkt_id);
}

always_inline void
ovpn_consume_queue_bytes (vlib_main_t *vm, ovpn_channel_t *ch,
			  ovpn_reliable_queue_t *queue,
			  ovpn_reliable_pkt_t **pktp, size_t bytes,
			  ip46_address_t *remote_addr, u16 remote_port,
			  u8 is_ip4)
{
  if (bytes == 0 || pktp == NULL || *pktp == NULL)
    return;

  ovpn_reliable_pkt_t *pkt = *pktp;

  while (bytes > 0 && pkt != NULL)
    {
      size_t pkt_remain = pkt->data_len - pkt->recv.consumed;
      size_t advance = (bytes < pkt_remain) ? bytes : pkt_remain;
      pkt->recv.consumed += advance;
      bytes -= advance;

      if (pkt->recv.consumed == pkt->data_len)
	{
	  ovpn_send_ack_recv_pkt (vm, ch, queue, pkt, remote_addr, remote_port,
				  is_ip4);
	  ovpn_reliable_get_recv_pkt (queue, pkt->pkt_id + 1, &pkt);
	}
    }

  *pktp = pkt;
}

always_inline ovpn_handshake_buffer_t *
ovpn_get_handshake_buffer (ovpn_channel_t *ch)
{
  return &ch->hs_buf;
}

always_inline void
ovpn_handshake_buffer_append_pkt (ovpn_handshake_buffer_t *hs,
				  ovpn_reliable_pkt_t *pkt)
{
  if (pkt == NULL)
    return;

  u32 remain = pkt->data_len - pkt->recv.consumed;
  vec_add (hs->data, pkt->data + pkt->recv.consumed, remain);
}

always_inline void
ovpn_handshake_buffer_trim (ovpn_handshake_buffer_t *hs, u32 bytes)
{
  if (bytes == 0 || hs->data == NULL)
    return;

  u32 len = vec_len (hs->data);
  if (bytes >= len)
    {
      vec_free (hs->data);
      hs->data = NULL;
      hs->offset = 0;
      return;
    }

  vec_delete (hs->data, bytes, 0);
  hs->offset = 0;
}

always_inline void
ovpn_handshake_buffer_reset (ovpn_handshake_buffer_t *hs)
{
  vec_free (hs->data);
  hs->data = NULL;
  hs->offset = 0;
  hs->pkt = NULL;
}

always_inline ovpn_error_t
ovpn_send_ctrl_server_reset_v2 (vlib_main_t *vm, ip46_address_t *remote_addr,
				u16 remote_port, u8 is_ip4, ovpn_channel_t *ch,
				ovpn_reliable_queue_t *queue,
				u64 remote_session_id)
{
  u32 bi0 = ~0;
  ovpn_ctrl_msg_server_hard_reset_v2_t ctrl_msg;
  ctrl_msg.remote_session_id = clib_host_to_net_u64 (remote_session_id);
  ovpn_create_ctrl_frame (vm, ch,
			  OVPN_OPCODE_TYPE_P_CONTROL_HARD_RESET_SERVER_V2,
			  &queue->replay_packet_id, &queue->next_send_pkt_id,
			  (u8 *) &ctrl_msg, sizeof (ctrl_msg), &bi0);
  ovpn_send_reliable_pkt (vm, queue, is_ip4, bi0, remote_addr, remote_port);
  return OVPN_ERROR_NONE;
}

always_inline void
ovpn_handle_hard_reset_client_v2 (vlib_main_t *vm, uword event_data)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_ctrl_event_hard_reset_client_v2_t *event =
    (ovpn_ctrl_event_hard_reset_client_v2_t *) event_data;
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
  ovpn_send_ctrl_server_reset_v2 (vm, &event->remote_addr, event->client_port,
				  event->is_ip4, ch, queue,
				  event->remote_session_id);
done:
  clib_mem_free (event);
}

always_inline void
ovpn_handle_ack_v1 (vlib_main_t *vm, uword event_data)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_session_t *sess;
  ovpn_channel_t *ch;
  ovpn_reliable_queue_t *queue;
  ovpn_ctrl_event_ack_v1_t *event = (ovpn_ctrl_event_ack_v1_t *) event_data;
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
	  u32 handle = ovpn_reliable_get_timer_handle (queue, *pkt_id);
	  if (!tw_timer_handle_is_free_2t_1w_2048sl (&omp->queues_timer_wheel,
						     handle))
	    {
	      tw_timer_stop_2t_1w_2048sl (&omp->queues_timer_wheel, handle);
	    }
	}
      vec_free (event->acks);
    }
  if (ch->state == OVPN_CHANNEL_STATE_INIT)
    {
      ovpn_set_channel_state (ch, OVPN_CHANNEL_STATE_SSL_HANDSHAKE);
      sess->state = OVPN_SESSION_STATE_HANDSHAKING;
    }

done:
  clib_mem_free (event);
}

always_inline ovpn_error_t
ovpn_send_ctrl_v1_response (vlib_main_t *vm, ip46_address_t *remote_addr,
			    u16 remote_port, u8 is_ip4, ovpn_channel_t *ch,
			    ovpn_reliable_queue_t *queue, u8 *payload,
			    u32 payload_len)
{
  u32 bi0 = ~0;
  ovpn_create_ctrl_frame (vm, ch, OVPN_OPCODE_TYPE_P_CONTROL_V1,
			  &queue->replay_packet_id, &queue->next_send_pkt_id,
			  payload, payload_len, &bi0);
  ovpn_send_reliable_pkt (vm, queue, is_ip4, bi0, remote_addr, remote_port);
  return OVPN_ERROR_NONE;
}

always_inline void
ovpn_send_tls_output (vlib_main_t *vm, ovpn_channel_t *ch,
		      ovpn_reliable_queue_t *queue,
		      ip46_address_t *remote_addr, u16 remote_port, u8 is_ip4,
		      ptls_buffer_t *wbuf)
{
  if (wbuf->off == 0)
    return;

  size_t remaining = wbuf->off;
  u8 *resp = (u8 *) wbuf->base;

  while (remaining > 0)
    {
      u32 chunk =
	(remaining > OVPN_FRAME_SIZE) ? OVPN_FRAME_SIZE : (u32) remaining;
      ovpn_send_ctrl_v1_response (vm, remote_addr, remote_port, is_ip4, ch,
				  queue, resp, chunk);
      resp += chunk;
      remaining -= chunk;
    }
}

always_inline ovpn_error_t
ovpn_handle_key_negotiation (ovpn_channel_t *ch, u8 *payload, u32 payload_len,
			     u32 *key2_index)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_error_t error = OVPN_ERROR_NONE;
  ovpn_key_source_t *ks = NULL;
  ovpn_key2_t *key2 = NULL;
  u16 options_string_length = 0;
  u16 username_length = 0;
  // u8 *username = NULL;
  u16 password_length = 0;
  // u8 *password = NULL;

  /* Literal 0 4 bytes */
  if (payload_len < 4)
    {
      return OVPN_ERROR_MALFORMED;
    }
  payload += 4;
  payload_len -= 4;

  /* key_method type 1 byte */
  if (payload_len < 1)
    {
      return OVPN_ERROR_MALFORMED;
    }
  u8 key_method = *payload;
  if (key_method != 2)
    {
      return OVPN_ERROR_INVALID_KEY_METHOD;
    }
  payload += 1;
  payload_len -= 1;

  /* key_source, 48 bytes + 32 bytes + 32 bytes */
  if (payload_len < OVPN_KEY_SOURCE_LENGTH)
    {
      return OVPN_ERROR_MALFORMED;
    }

  pool_get (omp->key_sources, ks);
  ks->index = ks - omp->key_sources;
  clib_memcpy_fast (ks->pre_master_secret, payload, 48);
  payload += 48;
  payload_len -= 48;

  clib_memcpy_fast (ks->client_prf_seed_master_secret, payload, 32);
  payload += 32;
  payload_len -= 32;

  clib_memcpy_fast (&ks->client_prf_seed_key_expansion, payload, 32);
  payload += 32;
  payload_len -= 32;

  /* options_string_length,  */
  clib_memcpy_fast (&options_string_length, payload, payload_len);
  options_string_length = clib_net_to_host_u16 (options_string_length);
  payload += options_string_length;
  payload_len -= options_string_length;
  /* null terminator */
  options_string_length -= 1;

  if (payload_len > 0)
    {
      clib_memcpy_fast (&username_length, payload, payload_len);
      username_length = clib_net_to_host_u16 (username_length);
      if (username_length > payload_len)
	{
	  error = OVPN_ERROR_MALFORMED;
	  goto error;
	}
      // username = payload;
      payload += username_length;
      payload_len -= username_length;
      /* null terminator */
      username_length -= 1;

      if (payload_len > 0)
	{
	  clib_memcpy_fast (&password_length, payload, payload_len);
	  password_length = clib_net_to_host_u16 (password_length);
	  if (password_length > payload_len)
	    {
	      error = OVPN_ERROR_MALFORMED;
	      goto error;
	    }
	  // password = payload;
	  payload += password_length;
	  payload_len -= password_length;
	  /* null terminator */
	  password_length -= 1;
	}
    }

  pool_get (omp->key2s, key2);
  if (!ovpn_channel_derive_key_material_server (ch, ks, key2))
    {
      error = OVPN_ERROR_SSL_HANDSHAKE_FAILED;
      goto error;
    }
  *key2_index = key2 - omp->key2s;

error:
  if (error != OVPN_ERROR_NONE)
    {
      if (ks != NULL)
	{
	  pool_put (omp->key_sources, ks);
	}
      if (key2 != NULL)
	{
	  pool_put (omp->key2s, key2);
	}
    }
  return error;
}

always_inline ovpn_error_t
ovpn_handle_key_negotiation_pkt (vlib_main_t *vm, ovpn_channel_t *ch,
				 ovpn_reliable_queue_t *queue,
				 ovpn_reliable_pkt_t **pktp, u8 *data,
				 size_t data_len, ip46_address_t *remote_addr,
				 u16 remote_port, u8 is_ip4,
				 ovpn_session_t *sess,
				 size_t *consumed_out) /* <- 新增 */
{
  ovpn_error_t error = OVPN_ERROR_NONE;
  ovpn_main_t *omp = &ovpn_main;
  ptls_buffer_t plaintext_buf;
  ptls_buffer_init (&plaintext_buf, NULL, 0);

  size_t input_off = 0;

  while (input_off < data_len)
    {
      size_t consumed = data_len - input_off;
      int rv =
	ptls_receive (ch->tls, &plaintext_buf, data + input_off, &consumed);
      input_off += consumed;

      if (rv != 0)
	{
	  error = OVPN_ERROR_SSL_HANDSHAKE_FAILED;
	  goto cleanup;
	}
    }

  /* 按实际 ptls_receive 消耗的字节数更新 queue/pkt 的 consumed 并发送
   * ACK（ovpn_consume_queue_bytes 内部更新）*/
  ovpn_consume_queue_bytes (vm, ch, queue, pktp, input_off, remote_addr,
			    remote_port, is_ip4);

  /* --- 立即对已经完全消费的 pkt 发送 ACK 并前进队列 --- */
  /* pktp 是指向当前 pkt 指针的指针，ovpn_consume_queue_bytes 可能已经更新
   * pkt->recv.consumed */
  while (*pktp != NULL && (*pktp)->recv.consumed >= (*pktp)->data_len)
    {
      ovpn_reliable_dequeue_recv_pkt (vm, queue, pktp); /* 前进到下一个 pkt */
    }

  if (plaintext_buf.off > 0)
    {
      error = ovpn_handle_key_negotiation (
	ch, plaintext_buf.base, plaintext_buf.off, &sess->key2_index);

      if (error != OVPN_ERROR_NONE)
	goto cleanup;

      ovpn_key_source_t *ks =
	pool_elt_at_index (omp->key_sources, ch->key_source_index);

      u8 *resp = NULL;
      u32 rlen = 0;
      ovpn_create_key_negotiation_response (ks, &resp, &rlen);

      ptls_buffer_t encbuf;
      ptls_buffer_init (&encbuf, NULL, 0);

      ptls_send (ch->tls, &encbuf, resp, rlen);

      if (encbuf.off > 0)
	ovpn_send_tls_output (vm, ch, queue, remote_addr, remote_port, is_ip4,
			      &encbuf);

      ptls_buffer_dispose (&encbuf);
      vec_free (resp);

      ovpn_activate_session (sess, ch);
      ovpn_set_channel_state (ch, OVPN_CHANNEL_STATE_CLOSED);
    }

cleanup:
  if (consumed_out)
    *consumed_out =
      input_off; /* 告知调用者从传入 data（传入起点）共消费了多少字节 */

  ptls_buffer_dispose (&plaintext_buf);
  return error;
}

always_inline ovpn_error_t
ovpn_handle_handshake (vlib_main_t *vm, ip46_address_t *remote_addr,
		       u32 pkt_id, u16 remote_port, u8 is_ip4,
		       u64 remote_session_id, u8 *data, u32 data_len,
		       u32 acks_len, u32 *acks)
{
  ovpn_main_t *omp = &ovpn_main;
  u32 sess_index = ~0;
  ovpn_session_t *sess;
  ovpn_channel_t *ch;
  ovpn_reliable_queue_t *queue;
  ovpn_error_t error = OVPN_ERROR_NONE;

  if (ovpn_find_session (remote_addr, &sess_index))
    return OVPN_ERROR_SSL_HANDSHAKE_FAILED;

  sess = pool_elt_at_index (omp->sessions, sess_index);

  if (pool_is_free_index (omp->channels, sess->channel_index))
    return OVPN_ERROR_SSL_HANDSHAKE_FAILED;

  ch = pool_elt_at_index (omp->channels, sess->channel_index);

  if (ch->remote_session_id != remote_session_id ||
      sess->state != OVPN_SESSION_STATE_HANDSHAKING ||
      (ch->state != OVPN_CHANNEL_STATE_SSL_HANDSHAKE &&
       ch->state != OVPN_CHANNEL_STATE_SSL_HANDSHAKE_FINISHED))
    return OVPN_ERROR_SSL_HANDSHAKE_FAILED;

  queue = pool_elt_at_index (omp->reliable_queues, ch->reliable_queue_index);
  ovpn_handshake_buffer_t *hs = ovpn_get_handshake_buffer (ch);
  hs->offset = 0;

  if (acks_len > 0)
    {
      for (u32 i = 0; i < acks_len; i++)
	{
	  u32 pkt_id = acks[i];
	  ovpn_reliable_dequeue_pkt (vm, queue, pkt_id);
	  u32 handle = ovpn_reliable_get_timer_handle (queue, pkt_id);
	  if (!tw_timer_handle_is_free_2t_1w_2048sl (&omp->queues_timer_wheel,
						     handle))
	    {
	      tw_timer_stop_2t_1w_2048sl (&omp->queues_timer_wheel, handle);
	    }
	}
    }

  // reliable receive
  int rv = ovpn_reliable_queue_recv_pkt (vm, queue, pkt_id, data, data_len);
  if (rv < 0)
    return OVPN_ERROR_SSL_HANDSHAKE_FAILED;

  if (rv == 2)
    return OVPN_ERROR_NONE;

  ovpn_reliable_dequeue_recv_pkt (vm, queue, &hs->pkt);

  // 进入循环处理每个 pkt
  while (hs->pkt != NULL)
    {
      ovpn_handshake_buffer_append_pkt (hs, hs->pkt);

      bool handshake_done = ptls_handshake_is_complete (ch->tls);

      if (handshake_done)
	{
	  // 已握手，直接做 OpenVPN key negotiation
	  size_t consumed_from_hsbuf = 0;
	  error = ovpn_handle_key_negotiation_pkt (
	    vm, ch, queue, &hs->pkt, hs->data, vec_len (hs->data), remote_addr,
	    remote_port, is_ip4, sess, &consumed_from_hsbuf);

	  if (error != OVPN_ERROR_NONE)
	    {
	      ovpn_handshake_buffer_reset (hs);
	      return error;
	    }

	  ovpn_handshake_buffer_trim (hs, consumed_from_hsbuf);

	  if (sess->state == OVPN_SESSION_STATE_ACTIVE)
	    {
	      ovpn_handshake_buffer_reset (hs);
	      return error;
	    }

	  ovpn_reliable_dequeue_recv_pkt (vm, queue, &hs->pkt);

	  continue;
	}
      else
	{
	  // handshake 未完成
	  while (hs->offset < vec_len (hs->data))
	    {
	      size_t pending = vec_len (hs->data) - hs->offset;
	      ptls_buffer_t wbuf;
	      ptls_buffer_init (&wbuf, NULL, 0);

	      size_t consumed = pending;
	      int hs_ret = ptls_handshake (
		ch->tls, &wbuf, hs->data + hs->offset, &consumed, NULL);

	      hs->offset += consumed;

	      // 更新 ACK / queue
	      ovpn_consume_queue_bytes (vm, ch, queue, &hs->pkt, consumed,
					remote_addr, remote_port, is_ip4);

	      // 输出 handshake 数据
	      if (wbuf.off > 0)
		ovpn_send_tls_output (vm, ch, queue, remote_addr, remote_port,
				      is_ip4, &wbuf);

	      ptls_buffer_dispose (&wbuf);

	      if (hs_ret == 0 && ptls_handshake_is_complete (ch->tls))
		{
		  ovpn_set_channel_state (
		    ch, OVPN_CHANNEL_STATE_SSL_HANDSHAKE_FINISHED);

		  // 剩余数据进入 key negotiation
		  if (hs->offset < vec_len (hs->data))
		    break; // 下次循环处理 key negotiation
		}
	      else if (hs_ret != PTLS_ERROR_IN_PROGRESS)
		{
		  ovpn_set_channel_state (ch, OVPN_CHANNEL_STATE_CLOSED);
		  ovpn_handshake_buffer_reset (hs);
		  return OVPN_ERROR_SSL_HANDSHAKE_FAILED;
		}

	      if (hs_ret == PTLS_ERROR_IN_PROGRESS)
		break;
	    }

	  // 清除已消费数据
	  if (hs->offset > 0)
	    ovpn_handshake_buffer_trim (hs, hs->offset);

	  ovpn_reliable_dequeue_recv_pkt (vm, queue, &hs->pkt);
	}
    }

  return error;
}

always_inline void
ovpn_handle_session_expired (vlib_main_t *vm, uword event_data)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_session_t *sess = pool_elt_at_index (omp->sessions, event_data);
  ovpn_free_session (vm, sess);
}

always_inline void
ovpn_handle_session_keepalive (vlib_main_t *vm, uword event_data)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_session_t *sess = pool_elt_at_index (omp->sessions, event_data);
  tw_timer_update_2t_1w_2048sl (&omp->sessions_timer_wheel, sess->index,
				(u64) OVN_SESSION_EXPIRED_TIMEOUT);
}

always_inline void
ovpn_handle_channel_expired (vlib_main_t *vm, uword event_data)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_channel_t *ch = pool_elt_at_index (omp->channels, event_data);
  ovpn_free_channel (vm, ch);
}

always_inline void
ovpn_handle_reliable_send_queue_expired (vlib_main_t *vm, uword event_data)
{
  ovpn_main_t *omp = &ovpn_main;
  u32 bi0 = ~0;
  vlib_buffer_t *b0;
  ovpn_reliable_queue_t *queue;
  ovpn_reliable_pkt_t *pkt = NULL;
  ovpn_reliable_send_queue_event_t *event =
    (ovpn_reliable_send_queue_event_t *) event_data;

  if (pool_is_free_index (omp->reliable_queues, event->queue_index))
    goto done;
  queue = pool_elt_at_index (omp->reliable_queues, event->queue_index);
  if (ovpn_reliable_retransmit_pkt (vm, queue, event->pkt_id, &pkt) == 0)
    {
      if (pkt == NULL)
	{
	  goto done;
	}
      if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
	{
	  clib_warning ("Failed to allocate buffer");
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
	    ovpn_handle_hard_reset_client_v2 (vm, event_data[i]);
	  break;
	case OVPN_CTRL_EVENT_TYPE_ACK_V1:
	  for (i = 0; i < vec_len (event_data); i++)
	    ovpn_handle_ack_v1 (vm, event_data[i]);
	  break;
	case OVPN_CTRL_EVENT_TYPE_SESSION_EXPIRED:
	  for (i = 0; i < vec_len (event_data); i++)
	    ovpn_handle_session_expired (vm, event_data[i]);
	  break;
	case OVPN_CTRL_EVENT_TYPE_SESSION_KEEPALIVE:
	  for (i = 0; i < vec_len (event_data); i++)
	    ovpn_handle_session_keepalive (vm, event_data[i]);
	  break;
	case OVPN_CTRL_EVENT_TYPE_CHANNEL_EXPIRED:
	  for (i = 0; i < vec_len (event_data); i++)
	    ovpn_handle_channel_expired (vm, event_data[i]);
	  break;
	case OVPN_CTRL_EVENT_TYPE_RELIABLE_SEND_QUEUE_EXPIRED:
	  for (i = 0; i < vec_len (event_data); i++)
	    ovpn_handle_reliable_send_queue_expired (vm, event_data[i]);
	  break;
	default:
	  clib_warning ("Unexpected event type %d", event_type);
	  break;
	}
      vec_reset_length (event_data);
    }
  return 0;
}

static_always_inline void
ovpn_input_process_ops (vlib_main_t *vm, vlib_node_runtime_t *node,
			vnet_crypto_op_t *ops, vlib_buffer_t **b, u16 *nexts,
			u16 drop_next)
{
  u32 n_ops = vec_len (ops);
  vnet_crypto_op_t *op = ops;

  if (n_ops == 0)
    return;

  u32 n_fail = n_ops - vnet_crypto_process_ops (vm, op, n_ops);

  while (n_fail)
    {
      ASSERT (op - ops < n_ops);
      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  u32 data_idx = op->user_data;
	  b[data_idx]->error = node->errors[OVPN_ERROR_DECRYPT_FAILED];
	  nexts[data_idx] = drop_next;
	  n_fail--;
	}
      op++;
    }
}

static_always_inline void
ovpn_input_process_chained_ops (vlib_main_t *vm, vlib_node_runtime_t *node,
				vnet_crypto_op_t *ops, vlib_buffer_t **b,
				u16 *nexts, vnet_crypto_op_chunk_t *chunks,
				u16 drop_next)
{
  u32 n_ops = vec_len (ops);
  vnet_crypto_op_t *op = ops;

  if (n_ops == 0)
    return;

  u32 n_fail = n_ops - vnet_crypto_process_chained_ops (vm, op, chunks, n_ops);

  while (n_fail)
    {
      ASSERT (op - ops < n_ops);
      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  u32 data_idx = op->user_data;
	  b[data_idx]->error = node->errors[OVPN_ERROR_DECRYPT_FAILED];
	  nexts[data_idx] = drop_next;
	  n_fail--;
	}
      op++;
    }
}

static_always_inline void
ovpn_input_chain_crypto (vlib_main_t *vm, ovpn_per_thread_data_t *ptd,
			 vlib_buffer_t *b, u32 start_offset, u32 data_len,
			 u16 *n_chunks)
{
  vlib_buffer_t *cb = b;
  u32 offset = start_offset;
  u32 remaining = data_len;
  u16 count = 0;

  while (remaining)
    {
      while (offset >= cb->current_length)
	{
	  ASSERT (cb->flags & VLIB_BUFFER_NEXT_PRESENT);
	  offset -= cb->current_length;
	  cb = vlib_get_buffer (vm, cb->next_buffer);
	}

      vnet_crypto_op_chunk_t *ch;
      vec_add2 (ptd->chunks, ch, 1);
      count += 1;

      u32 avail = cb->current_length - offset;
      u32 len = clib_min (avail, remaining);
      ch->src = ch->dst = vlib_buffer_get_current (cb) + offset;
      ch->len = len;

      remaining -= len;
      offset = 0;

      if (remaining == 0)
	break;

      ASSERT (cb->flags & VLIB_BUFFER_NEXT_PRESENT);
      cb = vlib_get_buffer (vm, cb->next_buffer);
    }

  if (n_chunks)
    *n_chunks = count;
}

always_inline uword
ovpn_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		   vlib_frame_t *frame, u8 is_ip4)
{
  ovpn_main_t *omp = &ovpn_main;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  ovpn_per_thread_data_t *ptd =
    vec_elt_at_index (omp->per_thread_data, thread_index);
  const u16 drop_next = OVPN_NEXT_DROP;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vlib_buffer_t *data_bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t *data_last[VLIB_FRAME_SIZE];
  u16 data_nexts[VLIB_FRAME_SIZE];
  u32 data_bi[VLIB_FRAME_SIZE];
  u16 other_nexts[VLIB_FRAME_SIZE];
  u32 other_bi[VLIB_FRAME_SIZE];
  u16 n_data = 0, n_other = 0;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  vec_reset_length (ptd->crypto_ops);
  vec_reset_length (ptd->chained_crypto_ops);
  vec_reset_length (ptd->chunks);

  while (n_left_from > 0)
    {
      if (n_left_from > 2)
	{
	  u8 *p;
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  p = vlib_buffer_get_current (b[1]);
	  CLIB_PREFETCH (p, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (vlib_buffer_get_tail (b[1]), CLIB_CACHE_LINE_BYTES,
			 LOAD);
	}

      vlib_buffer_t *b0 = b[0];
      u32 bi0 = from[b - bufs];
      u32 error0 = OVPN_ERROR_NONE;
      u16 next0 = OVPN_NEXT_DROP;
      bool enqueue_data = false;
      ovpn_msg_hdr_t *msg_hdr0 = vlib_buffer_get_current (b0);
      u8 *payload = (u8 *) msg_hdr0 + sizeof (ovpn_msg_hdr_t);
      udp_header_t *udp0 =
	(udp_header_t *) ((u8 *) msg_hdr0 - sizeof (udp_header_t));

      if (PREDICT_FALSE (udp0->dst_port !=
			   clib_host_to_net_u16 (UDP_DST_PORT_ovpn) ||
			 !omp->enabled))
	goto enqueue_other;

      ip46_address_t remote_addr;
      if (is_ip4)
	{
	  ip4_header_t *ip40 =
	    (ip4_header_t *) ((u8 *) udp0 - sizeof (ip4_header_t));
	  ip46_address_set_ip4 (&remote_addr, &ip40->src_address);
	}
      else
	{
	  ip6_header_t *ip60 =
	    (ip6_header_t *) ((u8 *) udp0 - sizeof (ip6_header_t));
	  ip46_address_set_ip6 (&remote_addr, &ip60->src_address);
	}

      if (PREDICT_TRUE (msg_hdr0->opcode == OVPN_OPCODE_TYPE_P_DATA_V1))
	{
	  ovpn_session_t *sess = NULL;
	  u32 sess_index = ~0;

	  if (ovpn_find_session (&remote_addr, &sess_index) !=
	      OVPN_SESSION_ERROR_NONE)
	    goto enqueue_other;

	  sess = pool_elt_at_index (omp->sessions, sess_index);
	  if (sess->state != OVPN_SESSION_STATE_ACTIVE)
	    goto enqueue_other;

	  if (PREDICT_FALSE (sess->input_thread_index == ~0))
	    {
	      clib_atomic_cmp_and_swap (&sess->input_thread_index, ~0,
					thread_index);
	    }

	  if (sess->input_thread_index != thread_index)
	    {
	      next0 = OVPN_NEXT_HANDOFF_DATA;
	      goto enqueue_other;
	    }

	  ovpn_key2_t *key2 = pool_elt_at_index (omp->key2s, sess->key2_index);
	  if (key2 == NULL)
	    goto enqueue_other;

	  if (PREDICT_FALSE (key2->recv_key_index == ~0))
	    {
	      error0 = OVPN_ERROR_DECRYPT_FAILED;
	      goto enqueue_other;
	    }

	  vlib_buffer_t *lb = b0;
	  u16 n_bufs = 1;

	  if (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      n_bufs = vlib_buffer_chain_linearize (vm, b0);
	      if (PREDICT_FALSE (n_bufs == 0))
		{
		  error0 = OVPN_ERROR_FAILED_TO_ALLOCATE_BUFFER;
		  goto enqueue_other;
		}

	      if (n_bufs > 1)
		{
		  vlib_buffer_t *before_last = b0;
		  while (lb->flags & VLIB_BUFFER_NEXT_PRESENT)
		    {
		      before_last = lb;
		      lb = vlib_get_buffer (vm, lb->next_buffer);
		    }

		  if (PREDICT_FALSE (lb->current_length < OVPN_DATA_TAG_LEN))
		    {
		      u32 len_diff = OVPN_DATA_TAG_LEN - lb->current_length;

		      before_last->current_length -= len_diff;
		      if (before_last == b0)
			before_last->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;

		      vlib_buffer_advance (lb, (signed) -len_diff);
		      clib_memcpy_fast (vlib_buffer_get_current (lb),
					vlib_buffer_get_tail (before_last),
					len_diff);
		    }
		}
	    }

	  msg_hdr0 = vlib_buffer_get_current (b0);
	  payload = (u8 *) msg_hdr0 + sizeof (ovpn_msg_hdr_t);
	  u32 total_len = vlib_buffer_length_in_chain (vm, b0);
	  if (PREDICT_FALSE (total_len <= sizeof (ovpn_msg_hdr_t)))
	    {
	      error0 = OVPN_ERROR_MALFORMED;
	      goto enqueue_other;
	    }
	  u32 payload_len_total = total_len - sizeof (ovpn_msg_hdr_t);
	  if (payload_len_total <= (OVPN_DATA_IV_LEN + OVPN_DATA_TAG_LEN))
	    {
	      error0 = OVPN_ERROR_MALFORMED;
	      goto enqueue_other;
	    }

	  u8 *iv = payload;
	  u8 *ciphertext = payload + OVPN_DATA_IV_LEN;
	  u32 ciphertext_len_total =
	    payload_len_total - OVPN_DATA_IV_LEN - OVPN_DATA_TAG_LEN;
	  u8 *tag = vlib_buffer_get_tail (lb) - OVPN_DATA_TAG_LEN;
	  u32 ciphertext_offset =
	    (u32) (ciphertext - (u8 *) vlib_buffer_get_current (b0));

	  u32 data_idx = n_data;
	  data_bufs[data_idx] = b0;
	  data_last[data_idx] = lb;
	  data_bi[data_idx] = bi0;

	  data_nexts[data_idx] = OVPN_NEXT_DROP;

	  vnet_crypto_op_t **ops =
	    (lb != b0) ? &ptd->chained_crypto_ops : &ptd->crypto_ops;
	  vnet_crypto_op_t *op;
	  vec_add2_aligned (ops[0], op, 1, CLIB_CACHE_LINE_BYTES);
	  vnet_crypto_op_init (op, VNET_CRYPTO_OP_CHACHA20_POLY1305_DEC);
	  op->key_index = key2->recv_key_index;
	  op->iv = iv;
	  op->tag = tag;
	  op->tag_len = OVPN_DATA_TAG_LEN;
	  op->aad = (u8 *) msg_hdr0;
	  op->aad_len = sizeof (*msg_hdr0);
	  op->user_data = data_idx;

	  if (lb != b0)
	    {
	      op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
	      op->chunk_index = vec_len (ptd->chunks);
	      ovpn_input_chain_crypto (vm, ptd, b0, ciphertext_offset,
				       ciphertext_len_total, &op->n_chunks);
	    }
	  else
	    {
	      op->src = ciphertext;
	      op->dst = ciphertext;
	      op->len = ciphertext_len_total;
	    }

	  enqueue_data = true;
	  b0->error = node->errors[OVPN_ERROR_NONE];
	  n_data += 1;
	  vlib_process_signal_event_mt (vm, omp->timer_node_index,
					OVPN_CTRL_EVENT_TYPE_SESSION_KEEPALIVE,
					(uword) sess->index);
	  goto next_packet;
	}

      /* Verify HMAC for control packets */
      ovpn_ctrl_msg_hdr_t *ctrl_msg_hdr0 = (ovpn_ctrl_msg_hdr_t *) payload;
      u8 received_hmac[20];
      u8 calculated_hmac[20];
      u8 zero_hmac[20] = { 0 };

      clib_memcpy_fast (received_hmac, ctrl_msg_hdr0->hmac, 20);
      clib_memcpy_fast (ctrl_msg_hdr0->hmac, zero_hmac, 20);
      if (omp->psk_set)
	ovpn_calculate_hmac (omp->psk, (u8 *) msg_hdr0, b0->current_length,
			     calculated_hmac);

      if (PREDICT_FALSE (clib_memcmp (received_hmac, calculated_hmac, 20) !=
			 0))
	{
	  error0 = OVPN_ERROR_HMAC_CHECK_FAILED;
	  goto enqueue_other;
	}

      if (PREDICT_FALSE (msg_hdr0->opcode ==
			 OVPN_OPCODE_TYPE_P_CONTROL_HARD_RESET_CLIENT_V1))
	{
	  ovpn_ctrl_msg_client_hard_reset_v2_t *data =
	    (ovpn_ctrl_msg_client_hard_reset_v2_t *) (payload +
						      sizeof (
							ovpn_ctrl_msg_hdr_t) +
						      ctrl_msg_hdr0->acks_len *
							sizeof (u32));
	  ovpn_ctrl_event_hard_reset_client_v2_t *ctrl_event0 =
	    clib_mem_alloc (sizeof (ovpn_ctrl_event_hard_reset_client_v2_t));

	  clib_memset (ctrl_event0, 0,
		       sizeof (ovpn_ctrl_event_hard_reset_client_v2_t));

	  ctrl_event0->client_port = clib_net_to_host_u16 (udp0->src_port);
	  ctrl_event0->is_ip4 = is_ip4;
	  ip46_address_copy (&ctrl_event0->remote_addr, &remote_addr);
	  ctrl_event0->remote_session_id =
	    clib_net_to_host_u64 (ctrl_msg_hdr0->session_id);
	  clib_memcpy_fast (&ctrl_event0->hmac, ctrl_msg_hdr0->hmac, 20);
	  ctrl_event0->pkt_id = clib_net_to_host_u32 (data->pkt_id);

	  vlib_process_signal_event_mt (
	    vm, omp->ctrl_node_index,
	    OVPN_CTRL_EVENT_TYPE_HARD_RESET_CLIENT_V2, (uword) ctrl_event0);
	}
      else if (PREDICT_FALSE (msg_hdr0->opcode ==
			      OVPN_OPCODE_TYPE_P_CONTROL_SOFT_RESET_V1))
	{
	  /* TODO: handle soft reset */
	}
      else if (PREDICT_FALSE (msg_hdr0->opcode == OVPN_OPCODE_TYPE_P_ACK_V1))
	{
	  u32 *acks = (u32 *) (payload + sizeof (ovpn_ctrl_msg_hdr_t));
	  ovpn_ctrl_msg_ack_v1_t *data =
	    (ovpn_ctrl_msg_ack_v1_t *) (payload +
					sizeof (ovpn_ctrl_msg_hdr_t) +
					ctrl_msg_hdr0->acks_len *
					  sizeof (u32));
	  ovpn_ctrl_event_ack_v1_t *ctrl_event0 =
	    clib_mem_alloc (sizeof (ovpn_ctrl_event_ack_v1_t));
	  clib_memset (ctrl_event0, 0, sizeof (ovpn_ctrl_event_ack_v1_t));

	  ip46_address_copy (&ctrl_event0->remote_addr, &remote_addr);
	  ctrl_event0->remote_session_id =
	    clib_net_to_host_u64 (ctrl_msg_hdr0->session_id);
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

	  ctrl_event0->session_id = clib_net_to_host_u64 (data->session_id);

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
	      goto enqueue_other;
	    }

	  u32 *acks = (u32 *) (payload + sizeof (ovpn_ctrl_msg_hdr_t));
	  payload += sizeof (ovpn_ctrl_msg_hdr_t) +
		     ctrl_msg_hdr0->acks_len * sizeof (u32);
	  ovpn_ctrl_msg_control_v1_t *ctrl_msg_control_v1 =
	    (ovpn_ctrl_msg_control_v1_t *) payload;
	  u32 pkt_id = ctrl_msg_control_v1->pkt_id;
	  payload += sizeof (ovpn_ctrl_msg_control_v1_t);

	  i32 payload_len =
	    (i32) b0->current_length - (i32) sizeof (ovpn_ctrl_msg_hdr_t) -
	    (i32) ctrl_msg_hdr0->acks_len * (i32) sizeof (u32) +
	    (i32) sizeof (u32);

	  if (payload_len < 0)
	    {
	      error0 = OVPN_ERROR_MALFORMED;
	      goto enqueue_other;
	    }

	  if (is_ip4)
	    {
	      ip4_header_t *ip40 =
		(ip4_header_t *) ((u8 *) udp0 - sizeof (ip4_header_t));
	      ovpn_handle_handshake (
		vm, (ip46_address_t *) &ip40->src_address,
		clib_net_to_host_u32 (pkt_id),
		clib_net_to_host_u16 (udp0->src_port), 1,
		clib_net_to_host_u64 (ctrl_msg_hdr0->session_id), payload,
		(u32) payload_len, ctrl_msg_hdr0->acks_len, acks);
	    }
	  else
	    {
	      ip6_header_t *ip60 =
		(ip6_header_t *) ((u8 *) udp0 - sizeof (ip6_header_t));
	      ovpn_handle_handshake (
		vm, (ip46_address_t *) &ip60->src_address,
		clib_net_to_host_u32 (pkt_id),
		clib_net_to_host_u16 (udp0->src_port), 0,
		clib_net_to_host_u64 (ctrl_msg_hdr0->session_id), payload,
		(u32) payload_len, ctrl_msg_hdr0->acks_len, acks);
	    }
	}
      else
	{
	  error0 = OVPN_ERROR_UNKNOWN_OPCODE;
	}

    enqueue_other:
      if (!enqueue_data)
	{
	  b0->error = node->errors[error0];
	  other_bi[n_other] = bi0;
	  other_nexts[n_other] = next0;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      ovpn_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next0;
	      t->sw_if_index = ~0;
	    }

	  n_other += 1;
	}

    next_packet:
      b += 1;
      n_left_from -= 1;
    }

  ovpn_input_process_ops (vm, node, ptd->crypto_ops, data_bufs, data_nexts,
			  drop_next);
  ovpn_input_process_chained_ops (vm, node, ptd->chained_crypto_ops, data_bufs,
				  data_nexts, ptd->chunks, drop_next);

  b = data_bufs;
  vlib_buffer_t **data_lb = data_last;
  u16 *data_next = data_nexts;
  u32 remaining = n_data;
  while (remaining > 0)
    {
      if (data_next[0] != drop_next)
	{
	  ovpn_msg_hdr_t *msg_hdr0 =
	    (ovpn_msg_hdr_t *) vlib_buffer_get_current (b[0]);

	  vlib_buffer_advance (b[0], sizeof (*msg_hdr0) + OVPN_DATA_IV_LEN);
	  vlib_buffer_chain_increase_length (b[0], data_lb[0],
					     -(i32) OVPN_DATA_TAG_LEN);

	  vlib_buffer_advance (b[0], sizeof (u32));
	  b[0]->current_length -= sizeof (u32);

	  u8 *ip_hdr = vlib_buffer_get_current (b[0]);
	  u8 ip_ver = ip_hdr[0] >> 4;
	  if (ip_ver == 4)
	    data_next[0] = OVPN_NEXT_IP4_INPUT;
	  else if (ip_ver == 6)
	    data_next[0] = OVPN_NEXT_IP6_INPUT;
	}

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  ovpn_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->next_index = data_next[0];
	  /* We can try to find the session again or pass it down, but for
	   * now let's just set it to ~0 or we need to store it in the buffer
	   * ctx
	   */
	  t->sw_if_index = ~0; // TODO: retrieve sw_if_index from session
	}

      b += 1;
      data_lb += 1;
      data_next += 1;
      remaining -= 1;
    }

  if (n_other)
    vlib_buffer_enqueue_to_next (vm, node, other_bi, other_nexts, n_other);

  if (n_data)
    vlib_buffer_enqueue_to_next (vm, node, data_bi, data_nexts, n_data);

  return frame->n_vectors;
}

always_inline uword
ovpn_handoff_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame, ovpn_handoff_mode_t mode, u8 is_ip4,
		     u32 fq_index)
{
  ovpn_main_t *omp = &ovpn_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 n_enq, n_left_from, *from;
  ip4_header_t *ip40 = NULL;
  ip6_header_t *ip60 = NULL;
  ip46_address_t remote_addr;
  u32 sess_index = ~0;
  ovpn_session_t *sess = NULL;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);
  ti = thread_indices;
  b = bufs;

  if (is_ip4)
    {
      udp_header_t *udp0 =
	(udp_header_t *) ((u8 *) vlib_buffer_get_current (b[0]) -
			  sizeof (udp_header_t));
      ip40 = (ip4_header_t *) ((u8 *) udp0 - sizeof (ip4_header_t));
      ip46_address_set_ip4 (&remote_addr, &ip40->src_address);
    }
  else
    {
      udp_header_t *udp0 =
	(udp_header_t *) ((u8 *) vlib_buffer_get_current (b[0]) -
			  sizeof (udp_header_t));
      ip60 = (ip6_header_t *) ((u8 *) udp0 - sizeof (ip6_header_t));
      ip46_address_set_ip6 (&remote_addr, &ip60->src_address);
    }

  while (n_left_from > 0)
    {
      if (mode == OVPN_HANDOFF_HANDSHAKE)
	{
	  ti[0] = 0;
	}
      else if (mode == OVPN_HANDOFF_INP_DATA)
	{
	  ovpn_find_session (&remote_addr, &sess_index);
	  sess = pool_elt_at_index (omp->sessions, sess_index);
	  if (sess == NULL || sess->input_thread_index == ~0)
	    {
	      ti[0] = 0;
	    }
	  else
	    {
	      ti[0] = sess->input_thread_index;
	    }
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
  n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, from,
					 thread_indices, frame->n_vectors, 1);
  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 OVPN_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);
  return n_enq;
}

always_inline uword
ovpn_output_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, u8 is_ip4)
{
  ovpn_main_t *omp = &ovpn_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  vlib_buffer_t *data_bufs[VLIB_FRAME_SIZE];
  u32 data_bi[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u16 n_data = 0;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  ovpn_per_thread_data_t *ptd =
    vec_elt_at_index (omp->per_thread_data, thread_index);

  vlib_get_buffers (vm, from, bufs, n_left_from);
  vec_reset_length (ptd->crypto_ops);
  vec_reset_length (ptd->chained_crypto_ops);
  vec_reset_length (ptd->chunks);

  while (n_left_from > 0)
    {
      if (n_left_from > 2)
	{
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  CLIB_PREFETCH (vlib_buffer_get_current (b[2]), CLIB_CACHE_LINE_BYTES,
			 LOAD);
	}

      vlib_buffer_t *b0 = b[0];
      u32 bi0 = from[b - bufs];
      u32 sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
      ovpn_if_t *ovpni;
      ovpn_session_t *sess;
      ovpn_peer_t *peer;
      u32 next0 = OVPN_NEXT_DROP;

      if (sw_if_index0 != omp->if_instance.sw_if_index)
	{
	  goto next;
	}
      ovpni = &omp->if_instance;

      if (PREDICT_FALSE (pool_elts (ovpni->peers) == 0))
	{
	  goto next;
	}

      if (pool_elts (ovpni->peers) == 1)
	{
	  peer = pool_elt_at_index (ovpni->peers, 0);
	}
      else
	{
	  /* Multi-peer lookup based on destination IP */
	  ip46_address_t dst_ip;
	  if (is_ip4)
	    {
	      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
	      ip46_address_set_ip4 (&dst_ip, &ip4->dst_address);
	    }
	  else
	    {
	      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
	      ip46_address_set_ip6 (&dst_ip, &ip6->dst_address);
	    }

	  peer = NULL;
	  ovpn_peer_t *p;
	  pool_foreach (p, ovpni->peers)
	    {
	      if (ip46_address_is_equal (&p->ip, &dst_ip))
		{
		  peer = p;
		  break;
		}
	    }

	  if (peer == NULL)
	    {
	      /* Peer not found for destination IP */
	      goto next;
	    }
	}

      if (PREDICT_FALSE (pool_is_free_index (omp->sessions, peer->sess_index)))
	{
	  goto next;
	}
      sess = pool_elt_at_index (omp->sessions, peer->sess_index);

      if (PREDICT_FALSE (sess->state != OVPN_SESSION_STATE_ACTIVE))
	{
	  goto next;
	}

      if (PREDICT_FALSE (sess->input_thread_index == ~0))
	{
	  clib_atomic_cmp_and_swap (&sess->input_thread_index, ~0,
				    thread_index);
	}

      if (sess->input_thread_index != thread_index)
	{
	  next0 = OVPN_NEXT_OUTPUT_HANDOFF;
	  goto next;
	}

      ovpn_key2_t *key2 = pool_elt_at_index (omp->key2s, sess->key2_index);
      if (PREDICT_FALSE (key2->send_key_index == ~0))
	{
	  goto next;
	}

      /* Add OpenVPN header space */
      vlib_buffer_advance (b0, -(word) (sizeof (ovpn_msg_hdr_t) +
					OVPN_DATA_IV_LEN + OVPN_DATA_TAG_LEN));

      /* Fill OpenVPN header */
      ovpn_msg_hdr_t *msg_hdr0 = vlib_buffer_get_current (b0);
      msg_hdr0->opcode = OVPN_OPCODE_TYPE_P_DATA_V1;
      msg_hdr0->key_id = 0;

      u8 *iv = (u8 *) (msg_hdr0 + 1);
      u8 *tag = iv + OVPN_DATA_IV_LEN;
      u8 *payload = tag + OVPN_DATA_TAG_LEN;

      /* Generate IV */
      RAND_bytes (iv, OVPN_DATA_IV_LEN);

      /* Prepare crypto op */
      vnet_crypto_op_t *op;
      vec_add2_aligned (ptd->crypto_ops, op, 1, CLIB_CACHE_LINE_BYTES);
      vnet_crypto_op_init (op, VNET_CRYPTO_OP_CHACHA20_POLY1305_ENC);
      op->key_index = key2->send_key_index;
      op->iv = iv;
      op->tag = tag;
      op->tag_len = OVPN_DATA_TAG_LEN;
      op->aad = (u8 *) msg_hdr0;
      op->aad_len = sizeof (ovpn_msg_hdr_t);
      op->src = payload;
      op->dst = payload;
      op->len = b0->current_length - sizeof (ovpn_msg_hdr_t) -
		OVPN_DATA_IV_LEN - OVPN_DATA_TAG_LEN;
      op->user_data = n_data;

      /* Encapsulate UDP/IP */
      ovpn_prepend_rewrite (b0, &sess->remote_addr, UDP_DST_PORT_ovpn,
			    sess->is_ip4);

      if (sess->is_ip4)
	{
	  next0 = OVPN_NEXT_IP4_INPUT; /* Should be output really, but reusing
					  input nodes for now? */
	  /* Actually we should send to ip4-lookup or interface output */
	  /* For now let's assume we send to ip4-lookup */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~0;
	}
      else
	{
	  next0 = OVPN_NEXT_IP6_INPUT;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~0;
	}

      data_bufs[n_data] = b0;
      data_bi[n_data] = bi0;
      n_data++;

    next:
      next[0] = next0;
      next++;
      b++;
      n_left_from--;
    }

  if (n_data > 0)
    {
      vlib_buffer_t **b = data_bufs;
      ovpn_input_process_ops (vm, node, ptd->crypto_ops, b, nexts,
			      OVPN_NEXT_DROP);
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_NODE_FN (ovpn4_handoff_data_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff_inline (vm, node, frame, OVPN_HANDOFF_INP_DATA, 1,
			      omp->in4_index);
}
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_NODE_FN (ovpn6_handoff_data_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff_inline (vm, node, frame, OVPN_HANDOFF_INP_DATA, 0,
			      omp->in6_index);
}
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_NODE_FN (ovpn4_handoff_handshake_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff_inline (vm, node, frame, OVPN_HANDOFF_HANDSHAKE, 1,
			      omp->in4_index);
}
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_NODE_FN (ovpn6_handoff_handshake_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff_inline (vm, node, frame, OVPN_HANDOFF_HANDSHAKE, 0,
			      omp->in6_index);
}
/* *INDENT-ON* */

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
vlib_node_registration_t ovpn_timer_process_node;
vlib_node_registration_t ovpn_ctrl_process_node;
vlib_node_registration_t ovpn4_input_node;
vlib_node_registration_t ovpn6_input_node;
vlib_node_registration_t ovpn4_output_node;
vlib_node_registration_t ovpn6_output_node;
vlib_node_registration_t ovpn4_handoff_handshake_node;
vlib_node_registration_t ovpn4_handoff_data_node;
vlib_node_registration_t ovpn6_handoff_handshake_node;
vlib_node_registration_t ovpn6_handoff_data_node;
vlib_node_registration_t ovpn4_handoff_output_node;
vlib_node_registration_t ovpn6_handoff_output_node;
#endif /* CLIB_MARCH_VARIANT */
VLIB_NODE_FN (ovpn4_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_input_inline (vm, node, frame, /* is_ip4 */ 1);
}
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_NODE_FN (ovpn6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_input_inline (vm, node, frame, /* is_ip4 */ 0);
}
/* *INDENT-ON* */

/* *IDENT-OFF* */
VLIB_NODE_FN (ovpn4_handoff_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff_inline (vm, node, frame, OVPN_HANDOFF_OUT_TUN, 1,
			      omp->out4_index);
}
/* *INDENT-ON* */

/* *IDENT-OFF* */
VLIB_NODE_FN (ovpn6_handoff_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff_inline (vm, node, frame, OVPN_HANDOFF_OUT_TUN, 0,
			      omp->out6_index);
}
/* *INDENT-ON* */

/* *IDENT-OFF* */
VLIB_NODE_FN (ovpn4_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_output_inline (vm, node, frame, /* is_ip4 */ 1);
}
/* *INDENT-ON* */

/* *IDENT-OFF* */
VLIB_NODE_FN (ovpn6_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_output_inline (vm, node, frame, /* is_ip4 */ 0);
}
/* *INDENT-ON* */

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
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
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */

/* *INDENT-OFF* */
/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
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

VLIB_REGISTER_NODE (ovpn4_handoff_data_node) = {
  .name = "ovpn4-handoff-data",
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

VLIB_REGISTER_NODE (ovpn6_handoff_data_node) = {
  .name = "ovpn6-handoff-data",
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

VLIB_REGISTER_NODE (ovpn4_handoff_output_node) = {
  .name = "ovpn4-handoff-output-tun",
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

VLIB_REGISTER_NODE (ovpn6_handoff_output_node) = {
  .name = "ovpn6-handoff-output-tun",
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
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (ovpn4_input_node) = 
{
  .name = "ovpn4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(ovpn_error_strings),
  .error_strings = ovpn_error_strings,

  .n_next_nodes = OVPN_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [OVPN_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
        [OVPN_NEXT_IP6_INPUT] = "ip6-input-no-checksum",
        [OVPN_NEXT_HANDOFF_HANDSHAKE] = "ovpn4-handoff-handshake",
        [OVPN_NEXT_HANDOFF_DATA] = "ovpn4-handoff-data",
        [OVPN_NEXT_DROP] = "error-drop",
  },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (ovpn6_input_node) = 
{
  .name = "ovpn6-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(ovpn_error_strings),
  .error_strings = ovpn_error_strings,

  .n_next_nodes = OVPN_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [OVPN_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
        [OVPN_NEXT_IP6_INPUT] = "ip6-input-no-checksum",
        [OVPN_NEXT_HANDOFF_HANDSHAKE] = "ovpn6-handoff-handshake",
        [OVPN_NEXT_HANDOFF_DATA] = "ovpn6-handoff-data",
        [OVPN_NEXT_DROP] = "error-drop",
  },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (ovpn4_output_node) = 
{
  .name = "ovpn4-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(ovpn_error_strings),
  .error_strings = ovpn_error_strings,

  .n_next_nodes = OVPN_OUTPUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [OVPN_NEXT_OUTPUT_HANDOFF] = "ovpn4-handoff-output-tun",
        [OVPN_NEXT_OUTPUT_INTERFACE] = "adj-midchain-tx",
        [OVPN_NEXT_OUTPUT_DROP] = "error-drop",
  },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (ovpn6_output_node) = 
{
  .name = "ovpn6-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(ovpn_error_strings),
  .error_strings = ovpn_error_strings,

  .n_next_nodes = OVPN_OUTPUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [OVPN_NEXT_OUTPUT_HANDOFF] = "ovpn6-handoff-output-tun",
        [OVPN_NEXT_OUTPUT_INTERFACE] = "adj-midchain-tx",
        [OVPN_NEXT_OUTPUT_DROP] = "error-drop",
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
