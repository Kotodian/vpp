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
#include <vnet/fib/fib_source.h>
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

/*
 * Per-instance OpenVPN context
 * Each instance represents a separate OpenVPN server with its own:
 * - Local address and port binding
 * - TLS/crypto configuration
 * - Peer database
 * - FIB table for independent routing
 */
typedef struct ovpn_instance_t_
{
  /* Instance identification */
  u32 instance_id; /* Pool index */
  u32 sw_if_index; /* Associated interface sw_if_index */

  /* Network binding */
  ip_address_t local_addr; /* Local IP address */
  u16 local_port;	   /* Local UDP port */
  u8 is_ipv6;		   /* IPv4 or IPv6 mode */

  /* Per-instance FIB tables (independent routing per instance) */
  u32 fib_index4; /* IPv4 FIB table index */
  u32 fib_index6; /* IPv6 FIB table index */
  u32 fib_table_id; /* User-specified table ID (used for both) */

  /* Per-instance options */
  ovpn_options_t options;

  /* Per-instance TLS context */
  ptls_context_t *ptls_ctx;

  /* Per-instance control channel security */
  ovpn_tls_crypt_t tls_crypt;
  ovpn_tls_crypt_v2_t tls_crypt_v2;
  ovpn_tls_auth_t tls_auth;

  /* Per-instance data channel cipher */
  ovpn_cipher_alg_t cipher_alg;

  /* Per-instance peer management */
  ovpn_multi_context_t multi_context;

  /* State */
  u8 is_active;

} ovpn_instance_t;

typedef struct ovpn_main_t_
{
  /* Pool of OpenVPN instances */
  ovpn_instance_t *instances;

  /* Lookup: port -> instance_id (simple since each port is unique) */
  u32 *instance_id_by_port;

  /* Lookup: sw_if_index -> instance_id */
  uword *instance_by_sw_if_index;

  /* Node indices (shared across all instances) */
  u32 ovpn4_input_node_index;
  u32 ovpn6_input_node_index;
  u32 ovpn4_output_node_index;
  u32 ovpn6_output_node_index;

  /* Frame queue indices for handoff (shared) */
  u32 in4_fq_index;
  u32 in6_fq_index;
  u32 out4_fq_index;
  u32 out6_fq_index;

  /* FIB source for high-priority routes (shared) */
  fib_source_t fib_src_hi;

  /* For convenience */
  vlib_main_t *vm;
  vnet_main_t *vnm;
} ovpn_main_t;

extern ovpn_main_t ovpn_main;

/*
 * Instance management functions
 */

/* Get instance by pool index */
always_inline ovpn_instance_t *
ovpn_instance_get (u32 instance_id)
{
  ovpn_main_t *omp = &ovpn_main;
  if (pool_is_free_index (omp->instances, instance_id))
    return NULL;
  return pool_elt_at_index (omp->instances, instance_id);
}

/* Get instance by UDP port (fast path for input node) */
always_inline ovpn_instance_t *
ovpn_instance_get_by_port (u16 port)
{
  ovpn_main_t *omp = &ovpn_main;
  if (vec_len (omp->instance_id_by_port) <= port)
    return NULL;
  u32 instance_id = omp->instance_id_by_port[port];
  if (instance_id == ~0)
    return NULL;
  return pool_elt_at_index (omp->instances, instance_id);
}

/* Get instance by sw_if_index */
always_inline ovpn_instance_t *
ovpn_instance_get_by_sw_if_index (u32 sw_if_index)
{
  ovpn_main_t *omp = &ovpn_main;
  uword *p = hash_get (omp->instance_by_sw_if_index, sw_if_index);
  if (!p)
    return NULL;
  return pool_elt_at_index (omp->instances, p[0]);
}

/* Instance create/delete (implemented in ovpn.c) */
int ovpn_instance_create (vlib_main_t *vm, ip_address_t *local_addr,
			  u16 local_port, u32 table_id,
			  ovpn_options_t *options, u32 *instance_id_out,
			  u32 *sw_if_index_out);

int ovpn_instance_delete (vlib_main_t *vm, u32 sw_if_index);

#endif /* __included_ovpn_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */