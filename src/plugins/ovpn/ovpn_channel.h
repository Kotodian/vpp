/*
 * ovpn_channel.h - ovpn channel header file
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>.
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

#ifndef __included_ovpn_channel_h__
#define __included_ovpn_channel_h__

#include <picotls.h>
#include <picotls/openssl.h>
#include <vlib/vlib.h>
#include <stddef.h>
#include <vnet/ip/ip46_address.h>
#include <openssl/ssl.h>

#define OVN_CHANNEL_EXPIRED_TIMEOUT (1 * 60) /* 1 minute */

/*
 * Recv P_CONTROL_HARD_RESET_CLIENT_V2: Init: Initial State
 * Send P_CONTROL_HARD_RESET_SERVER_V2: SSL_HANDSHAKE Start
 * TLS Handshake Success: Active
 * Recv PushRequest And Send PushReply: Closed
 */
#define foreach_ovpn_channel_state                                            \
  _ (INIT, "Init")                                                            \
  _ (SSL_HANDSHAKE, "SSL Handshake")                                          \
  _ (SSL_HANDSHAKE_FINISHED, "SSL Handshake Finished")                        \
  _ (ACTIVE, "Active")                                                        \
  _ (CLOSED, "Closed")

typedef enum ovpn_channel_state
{
#define _(sym, str) OVPN_CHANNEL_STATE_##sym,
  foreach_ovpn_channel_state
#undef _
    OVPN_CHANNEL_STATE_N_STATE,
} ovpn_channel_state_t;

typedef struct ovpn_channel
{
  u32 index;
  u64 seed;
  u64 session_id;
  u64 remote_session_id;
  u32 remote_addr;
  u8 is_ip4;
  ovpn_channel_state_t state;
  u32 *client_acks;
  ptls_t *tls;
  u32 reliable_queue_index;
  f64 expired_time;
} ovpn_channel_t;

void ovpn_channel_init (vlib_main_t *vm, ovpn_channel_t *ch,
			ptls_context_t *ssl_ctx, u64 remote_session_id,
			ip46_address_t *remote_addr, u8 is_ip4, u32 ch_index);
void ovpn_channel_derive_key_material (ovpn_channel_t *ch, u8 key[32]);
void ovpn_channel_free (ovpn_channel_t *ch);

#endif /* __included_ovpn_channel_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
