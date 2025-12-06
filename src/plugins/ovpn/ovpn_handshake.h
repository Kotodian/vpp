/*
 * ovpn_handshake.h - OpenVPN control channel handshake
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

#ifndef __included_ovpn_handshake_h__
#define __included_ovpn_handshake_h__

#include <vlib/vlib.h>
#include <vnet/ip/ip_types.h>
#include <ovpn/ovpn_session_id.h>
#include <ovpn/ovpn_reliable.h>
#include <ovpn/ovpn_packet.h>

/*
 * Pending connection state
 *
 * When we receive P_CONTROL_HARD_RESET_CLIENT_V2, we create a pending
 * connection and send P_CONTROL_HARD_RESET_SERVER_V2 with ACK.
 * The connection becomes established when we receive P_ACK_V1.
 */
typedef enum
{
  OVPN_PENDING_STATE_INITIAL = 0,
  OVPN_PENDING_STATE_SENT_RESET, /* Sent server reset, waiting for ACK */
  OVPN_PENDING_STATE_ESTABLISHED, /* Received ACK, ready for TLS */
} ovpn_pending_state_t;

typedef struct ovpn_pending_connection_t_
{
  /* State */
  ovpn_pending_state_t state;

  /* Remote address and port */
  ip_address_t remote_addr;
  u16 remote_port;

  /* Session IDs */
  ovpn_session_id_t local_session_id;  /* Our session ID */
  ovpn_session_id_t remote_session_id; /* Client's session ID */

  /* Key ID from initial packet */
  u8 key_id;

  /* Packet ID tracking */
  u32 packet_id_send; /* Next packet ID to send */
  u32 packet_id_recv; /* Expected packet ID to receive */

  /* ACK tracking */
  ovpn_reliable_ack_t recv_ack; /* Packet IDs we need to ACK */
  ovpn_reliable_ack_t sent_ack; /* Packet IDs we sent, waiting for ACK */

  /* Timestamps */
  f64 created_time;
  f64 last_activity;
  f64 timeout; /* When this pending connection expires */

  /* Buffer index for storing response packet */
  u32 response_buf_index;

  /* Reliable send structure for retransmission */
  ovpn_reliable_t *send_reliable;

} ovpn_pending_connection_t;

/* Forward declaration - actual definition in ovpn.h */
struct ovpn_pending_db_t_;
typedef struct ovpn_pending_db_t_ ovpn_pending_db_t;

/*
 * HMAC context for tls-auth
 * Uses SHA256 by default
 */
#define OVPN_HMAC_KEY_SIZE 64
#define OVPN_HMAC_SIZE	   32 /* SHA256 output */

typedef struct ovpn_tls_auth_t_
{
  u8 enabled;
  u8 key[OVPN_HMAC_KEY_SIZE];
  u8 key_len;
  /* Key direction: 0 = normal, 1 = inverse */
  u8 key_direction;
} ovpn_tls_auth_t;

/*
 * Initialize pending connection database
 */
void ovpn_pending_db_init (ovpn_pending_db_t *db);

/*
 * Free pending connection database
 */
void ovpn_pending_db_free (ovpn_pending_db_t *db);

/*
 * Create a new pending connection
 * Returns pointer to pending connection, or NULL on error
 */
ovpn_pending_connection_t *
ovpn_pending_connection_create (ovpn_pending_db_t *db,
				const ip_address_t *remote_addr,
				u16 remote_port,
				const ovpn_session_id_t *remote_session_id,
				u8 key_id);

/*
 * Find pending connection by remote address
 */
ovpn_pending_connection_t *
ovpn_pending_connection_lookup (ovpn_pending_db_t *db,
				const ip_address_t *remote_addr,
				u16 remote_port);

/*
 * Delete pending connection
 */
void ovpn_pending_connection_delete (ovpn_pending_db_t *db,
				     ovpn_pending_connection_t *pending);

/*
 * Delete expired pending connections
 */
void ovpn_pending_db_expire (ovpn_pending_db_t *db, f64 now);

/*
 * Hash key generation for remote address lookup
 */
always_inline u64
ovpn_pending_remote_hash_key (const ip_address_t *addr, u16 port)
{
  u64 key = 0;
  if (addr->version == AF_IP4)
    {
      key = ((u64) addr->ip.ip4.as_u32 << 16) | port;
    }
  else
    {
      /* For IPv6, use a simpler hash */
      key = addr->ip.ip6.as_u64[0] ^ addr->ip.ip6.as_u64[1];
      key = (key << 16) | port;
    }
  return key;
}

/*
 * Build and send P_CONTROL_HARD_RESET_SERVER_V2 response
 * Returns 0 on success, <0 on error
 */
int ovpn_handshake_send_server_reset (vlib_main_t *vm,
				      ovpn_pending_connection_t *pending,
				      vlib_buffer_t *response_buf);

/*
 * Process incoming control packet
 * Called from handshake node
 */
int ovpn_handshake_process_packet (vlib_main_t *vm, vlib_buffer_t *b,
				   const ip_address_t *src_addr, u16 src_port,
				   const ip_address_t *dst_addr, u16 dst_port,
				   u8 is_ip6);

/*
 * HMAC verification for tls-auth
 * Returns 1 if HMAC is valid, 0 if invalid
 */
int ovpn_handshake_verify_hmac (const u8 *data, u32 len,
				const ovpn_tls_auth_t *auth);

/*
 * Generate HMAC for outgoing control packet
 */
void ovpn_handshake_generate_hmac (u8 *data, u32 len, u8 *hmac_out,
				   const ovpn_tls_auth_t *auth);

#endif /* __included_ovpn_handshake_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
