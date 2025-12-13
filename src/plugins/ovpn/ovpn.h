/*
 * ovpn.h - ovpn header file
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
#ifndef __included_ovpn_h__
#define __included_ovpn_h__

#include <ovpn/ovpn_reliable.h>
#include <ovpn/ovpn_ssl.h>
#include <ovpn/ovpn_crypto.h>
#include <vnet/ip/ip_types.h>
#include <ovpn/ovpn_options.h>
#include <picotls.h>
#include <picotls/openssl.h>
#include <ovpn/ovpn_session_id.h>
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_handshake.h>

/* Forward declaration for pending connection */
typedef struct ovpn_pending_connection_t_ ovpn_pending_connection_t;

/*
 * Pending connection database for handling initial handshakes
 */
typedef struct ovpn_pending_db_t_
{
  /* Pool of pending connections */
  ovpn_pending_connection_t *connections;

  /* Hash: remote addr -> pending connection index */
  uword *pending_by_remote;

  /* Timeout for pending connections (default 60 seconds) */
  f64 timeout;

} ovpn_pending_db_t;

typedef struct ovpn_multi_context_t_
{
  /* Peer database for data channel */
  ovpn_peer_db_t peer_db;

  /* Pending connections database for initial handshakes */
  ovpn_pending_db_t pending_db;
} ovpn_multi_context_t;

typedef struct ovpn_main_t_
{
  ovpn_options_t options;

  /* Picotls context */
  ptls_context_t *ptls_ctx;

  /* TLS-Crypt context for control channel encryption */
  ovpn_tls_crypt_t tls_crypt;

  /* TLS-Auth context for control channel authentication (with replay protection) */
  ovpn_tls_auth_t tls_auth;

  /* Cipher algorithm for data channel */
  ovpn_cipher_alg_t cipher_alg;

  /* UDP registration */
  u8 is_enabled;

  /* Node indices */
  u32 ovpn4_input_node_index;
  u32 ovpn6_input_node_index;
  u32 ovpn4_output_node_index;
  u32 ovpn6_output_node_index;

  /* Frame queue indices for handoff */
  u32 in4_fq_index;
  u32 in6_fq_index;
  u32 out4_fq_index;
  u32 out6_fq_index;

  /* Multi-instance context */
  ovpn_multi_context_t multi_context;

  /* For convenience */
  vlib_main_t *vm;
  vnet_main_t *vnm;
} ovpn_main_t;

extern ovpn_main_t ovpn_main;

#endif /* __included_ovpn_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */