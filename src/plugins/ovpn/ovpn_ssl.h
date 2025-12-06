/*
 * ovpn_ssl.h - ovpn ssl header file
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

#ifndef __included_ovpn_ssl_h__
#define __included_ovpn_ssl_h__

#include <vlib/vlib.h>
#include <ovpn/ovpn_buffer.h>
#include <ovpn/ovpn_crypto.h>
#include <picotls.h>

/**
 * Container for one half of random material to be used in %key method 2
 * data channel key generation.
 */
typedef struct ovpn_key_source_t_
{
  u8 pre_master[48]; /**< Random used for master secret
		      *   generation, provided only by client
		      *   OpenVPN peer. */
  u8 rnd1[32];	     /**< Seed used for master secret
		      *   generation, provided by both client
		      *   and server. */
  u8 rnd2[32];	     /**< Seed used for key expansion, provided
		      *   by both client and server. */
} ovpn_key_source_t;

/**
 * Container for both halves of random material to be used in %key method
 * 2 \ref key_generation "data channel key generation".
 * @ingroup control_processor
 */

typedef struct ovpn_key_source2_t_
{
  u32 index;
  ovpn_key_source_t client; /**< Random provided by client. */
  ovpn_key_source_t server; /**< Random provided by server */
} ovpn_key_source2_t;

/**
 * Allocate a new key source structure
 * @return The pointer to the new key source structure
 */
ovpn_key_source2_t *ovpn_key_source2_alloc (void);

/**
 * Free a key source structure
 * @param key_src2 The pointer to the key source structure to free
 */
void ovpn_key_source2_free (ovpn_key_source2_t *key_src2);

/**
 * Derive data channel keys from TLS session
 *
 * OpenVPN key derivation uses the TLS master secret to derive:
 * - Encryption key (server -> client)
 * - Encryption key (client -> server)
 * - Implicit IV for each direction
 *
 * For server mode, we use:
 * - encrypt_key = server_to_client key
 * - decrypt_key = client_to_server key
 *
 * @param tls The picotls context
 * @param keys Output key material structure
 * @param cipher_alg The cipher algorithm to determine key length
 * @param is_server 1 if we are the server, 0 if client
 * @return 0 on success, <0 on error
 */
int ovpn_derive_data_channel_keys (ptls_t *tls, ovpn_key_material_t *keys,
				   ovpn_cipher_alg_t cipher_alg, int is_server);

#endif /* __included_ovpn_ssl_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */