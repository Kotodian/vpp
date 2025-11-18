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
#include <openssl/md5.h>

#define OVN_CHANNEL_EXPIRED_TIMEOUT (1 * 60) /* 1 minute */
#define OVPN_KEY_SOURCE_LENGTH	    48 + 32 + 32

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

#define MAX_CIPHER_KEY_LENGTH 32
#define MAX_HMAC_KEY_LENGTH   20

typedef struct ovpn_key
{
  uint8_t cipher[MAX_CIPHER_KEY_LENGTH];
  uint8_t hmac[MAX_HMAC_KEY_LENGTH];
} ovpn_key_t;

typedef struct ovpn_key2
{
  int n;
#define OVPN_KEY_DIR_TO_CLIENT 0
#define OVPN_KEY_DIR_TO_SERVER 1
  ovpn_key_t keys[2]; // keys[0] = server->client, keys[1] = client->server
} ovpn_key2_t;

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
  u32 key_source_index;
} ovpn_channel_t;

typedef struct ovpn_key_source
{
  u32 index;
  u8 pre_master_secret[48];
  u8 client_prf_seed_master_secret[32];
  u8 client_prf_seed_key_expansion[32];
  u8 server_prf_seed_master_secret[32];
  u8 server_prf_seed_key_expansion[32];
} ovpn_key_source_t;

void ovpn_channel_init (vlib_main_t *vm, ovpn_channel_t *ch,
			ptls_context_t *ssl_ctx, u64 remote_session_id,
			ip46_address_t *remote_addr, u8 is_ip4, u32 ch_index);
bool ovpn_channel_derive_key_material_server (ovpn_channel_t *ch,
					      ovpn_key_source_t *ks,
					      ovpn_key2_t *key2);
void ovpn_channel_free (ovpn_channel_t *ch);

#endif /* __included_ovpn_channel_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
