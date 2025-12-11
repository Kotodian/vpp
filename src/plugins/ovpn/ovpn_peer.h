/*
 * ovpn_peer.h - OpenVPN peer management
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

#ifndef __included_ovpn_peer_h__
#define __included_ovpn_peer_h__

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/adj/adj.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_session_id.h>
#include <ovpn/ovpn_packet.h>
#include <ovpn/ovpn_reliable.h>
#include <ovpn/ovpn_buffer.h>
#include <picotls.h>

/* Peer state */
typedef enum
{
  OVPN_PEER_STATE_INITIAL = 0,
  OVPN_PEER_STATE_HANDSHAKE,
  OVPN_PEER_STATE_ESTABLISHED,
  OVPN_PEER_STATE_REKEYING,
  OVPN_PEER_STATE_DEAD,
} ovpn_peer_state_t;

/* Key slot indices */
#define OVPN_KEY_SLOT_PRIMARY	0
#define OVPN_KEY_SLOT_SECONDARY 1
#define OVPN_KEY_SLOT_COUNT	2

/*
 * Per-peer key state
 * Each peer can have up to 2 active keys for seamless rekeying
 */
typedef struct ovpn_peer_key_t_
{
  ovpn_crypto_context_t crypto;
  u8 key_id;
  u8 is_active;
  f64 created_at;
  f64 expires_at;
} ovpn_peer_key_t;

/*
 * TLS handshake state for a peer
 * Used during the TLS negotiation phase
 */
typedef enum
{
  OVPN_TLS_STATE_INITIAL = 0,
  OVPN_TLS_STATE_HANDSHAKE,
  OVPN_TLS_STATE_ESTABLISHED,
  OVPN_TLS_STATE_ERROR,
} ovpn_tls_state_t;

/* Forward declaration for key_source2 */
struct ovpn_key_source2_t_;

typedef struct ovpn_peer_tls_t_
{
  /* TLS state */
  ovpn_tls_state_t state;

  /* Picotls context for this peer */
  ptls_t *tls;

  /* Key ID for this handshake */
  u8 key_id;

  /* Reliable layer for control channel */
  ovpn_reliable_t *send_reliable;
  ovpn_reliable_t *recv_reliable;

  /* ACK tracking */
  ovpn_reliable_ack_t recv_ack; /* Packet IDs we need to ACK */
  ovpn_reliable_ack_t sent_ack; /* Our packet IDs waiting for ACK */
  ovpn_reliable_ack_t lru_acks; /* Recently ACKed packet IDs */

  /* Buffers for TLS data */
  ovpn_reli_buffer_t plaintext_read_buf;
  ovpn_reli_buffer_t plaintext_write_buf;
  ovpn_reli_buffer_t ack_write_buf;

  /* Next packet ID to send */
  u32 packet_id_send;

  /*
   * Key Method 2 state
   * Holds random material exchanged between client and server
   */
  struct ovpn_key_source2_t_ *key_src2;

  /* Flags for key exchange state */
  u8 key_method_sent : 1;     /* We have sent our key method data */
  u8 key_method_received : 1; /* We have received peer's key method data */
  u8 use_tls_ekm : 1;	      /* Use TLS-EKM instead of PRF for key derivation */

  /*
   * Negotiated data channel cipher from client options
   * This is determined from the "cipher" option in the client's
   * Key Method 2 options string during negotiation.
   */
  u8 negotiated_cipher_alg; /* ovpn_cipher_alg_t */

  /* Client's options string (parsed from Key Method 2 data) */
  char *peer_options;

} ovpn_peer_tls_t;

/*
 * OpenVPN peer structure
 */
typedef struct ovpn_peer_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Peer identification */
  u32 peer_id;			       /* 24-bit peer ID for DATA_V2 packets */
  ovpn_session_id_t session_id;	       /* Our session ID */
  ovpn_session_id_t remote_session_id; /* Peer's session ID */

  /* Remote endpoint */
  ip_address_t remote_addr;
  u16 remote_port;
  u8 is_ipv6;

  /* Associated interface */
  u32 sw_if_index;

  /* Peer state */
  ovpn_peer_state_t state;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  /* Key slots for data channel crypto */
  ovpn_peer_key_t keys[OVPN_KEY_SLOT_COUNT];
  u8 current_key_slot; /* Which slot is currently active */

  /* TLS handshake context (allocated during handshake, freed after) */
  ovpn_peer_tls_t *tls_ctx;

  /* Virtual IP assigned to this peer (for server mode) */
  ip_address_t virtual_ip;
  u8 virtual_ip_set;

  /* Timers */
  f64 last_rx_time;
  f64 last_tx_time;
  f64 established_time;

  /* Rekey state */
  f64 rekey_interval;	 /* Seconds between rekeys (0 = disabled) */
  f64 next_rekey_time;	 /* When to initiate next rekey */
  f64 last_rekey_time;	 /* When last rekey completed */
  u8 rekey_key_id;	 /* Key ID for current/pending rekey */
  u8 rekey_initiated;	 /* 1 if we initiated the rekey */
  u8 pending_key_slot;	 /* Key slot for pending rekey keys */

  /* Statistics */
  u64 rx_bytes;
  u64 tx_bytes;
  u64 rx_packets;
  u64 tx_packets;

  /* Rewrite data for output */
  u8 *rewrite;
  u32 rewrite_len;

  /* Adjacency for reaching this peer */
  adj_index_t adj_index;

  /* FIB table */
  u32 fib_index;

  /* Thread index for input processing (first thread that sees this peer) */
  u32 input_thread_index;

} ovpn_peer_t;

/*
 * Assign thread index to peer if not already assigned
 * Returns the assigned thread index
 */
always_inline u32
ovpn_peer_assign_thread (ovpn_peer_t *peer, u32 thread_index)
{
  /* Use compare-and-swap to assign thread only once */
  u32 unassigned = ~0;
  __atomic_compare_exchange_n (&peer->input_thread_index, &unassigned,
			       thread_index, 0, __ATOMIC_RELAXED,
			       __ATOMIC_RELAXED);
  return peer->input_thread_index;
}

/*
 * Peer database
 */
typedef struct ovpn_peer_db_t_
{
  /* Pool of peers */
  ovpn_peer_t *peers;

  /* Lookup by peer_id (direct index, peer_id = pool index) */
  /* For large deployments, might need a hash table */

  /* Lookup by remote address + port */
  uword *peer_index_by_remote; /* hash of ip:port -> peer index */

  /* Lookup by virtual IP */
  uword *peer_index_by_virtual_ip;

  /* Next peer_id to allocate */
  u32 next_peer_id;

  /* Associated interface sw_if_index */
  u32 sw_if_index;

} ovpn_peer_db_t;

/*
 * Global mapping from adjacency index to peer index
 * Used by output nodes to find the peer for a given adjacency
 */
extern u32 *ovpn_peer_by_adj_index;

/*
 * Lookup peer by adjacency index
 */
always_inline u32
ovpn_peer_get_by_adj_index (adj_index_t ai)
{
  if (ai >= vec_len (ovpn_peer_by_adj_index))
    return ~0;
  return ovpn_peer_by_adj_index[ai];
}

/*
 * Associate a peer with an adjacency index
 */
void ovpn_peer_adj_index_add (u32 peer_id, adj_index_t ai);

/*
 * Remove peer-adjacency association
 */
void ovpn_peer_adj_index_del (adj_index_t ai);

/*
 * Stack the peer's adjacency to reach the endpoint
 */
void ovpn_peer_adj_stack (ovpn_peer_t *peer, adj_index_t ai);

/*
 * Initialize peer database
 */
void ovpn_peer_db_init (ovpn_peer_db_t *db, u32 sw_if_index);

/*
 * Free peer database
 */
void ovpn_peer_db_free (ovpn_peer_db_t *db);

/*
 * Create a new peer
 * Returns peer_id on success, ~0 on failure
 */
u32 ovpn_peer_create (ovpn_peer_db_t *db, const ip_address_t *remote_addr,
		      u16 remote_port);

/*
 * Delete a peer
 */
void ovpn_peer_delete (ovpn_peer_db_t *db, u32 peer_id);

/*
 * Lookup peer by peer_id
 */
always_inline ovpn_peer_t *
ovpn_peer_get (ovpn_peer_db_t *db, u32 peer_id)
{
  if (pool_is_free_index (db->peers, peer_id))
    return NULL;
  return pool_elt_at_index (db->peers, peer_id);
}

/*
 * Lookup peer by remote address and port
 */
ovpn_peer_t *ovpn_peer_lookup_by_remote (ovpn_peer_db_t *db,
					 const ip_address_t *addr, u16 port);

/*
 * Lookup peer by virtual IP
 */
ovpn_peer_t *ovpn_peer_lookup_by_virtual_ip (ovpn_peer_db_t *db,
					     const ip_address_t *addr);

/*
 * Set peer crypto key
 */
int ovpn_peer_set_key (vlib_main_t *vm, ovpn_peer_t *peer, u8 key_slot,
		       ovpn_cipher_alg_t cipher_alg,
		       const ovpn_key_material_t *keys, u8 key_id);

/*
 * Get active crypto context for peer
 */
always_inline ovpn_crypto_context_t *
ovpn_peer_get_crypto (ovpn_peer_t *peer)
{
  return &peer->keys[peer->current_key_slot].crypto;
}

/*
 * Get crypto context by key_id
 */
ovpn_crypto_context_t *ovpn_peer_get_crypto_by_key_id (ovpn_peer_t *peer,
						       u8 key_id);

/*
 * Update peer activity timestamp
 */
always_inline void
ovpn_peer_update_rx (ovpn_peer_t *peer, f64 now, u32 bytes)
{
  peer->last_rx_time = now;
  peer->rx_bytes += bytes;
  peer->rx_packets++;
}

always_inline void
ovpn_peer_update_tx (ovpn_peer_t *peer, f64 now, u32 bytes)
{
  peer->last_tx_time = now;
  peer->tx_bytes += bytes;
  peer->tx_packets++;
}

/*
 * Build rewrite for peer (UDP + outer IP header)
 */
int ovpn_peer_build_rewrite (ovpn_peer_t *peer, const ip_address_t *local_addr,
			     u16 local_port);

/*
 * Format peer for display
 */
u8 *format_ovpn_peer (u8 *s, va_list *args);

/*
 * Initialize TLS handshake context for a peer
 * Called when transitioning to HANDSHAKE state
 * Returns 0 on success, <0 on error
 */
int ovpn_peer_tls_init (ovpn_peer_t *peer, ptls_context_t *ptls_ctx,
			u8 key_id);

/*
 * Free TLS handshake context
 * Called when handshake completes or fails
 */
void ovpn_peer_tls_free (ovpn_peer_t *peer);

/*
 * Process incoming TLS data from control channel
 * Returns: >0 if TLS data was produced for sending
 *          0 if no data to send
 *          <0 on error
 */
int ovpn_peer_tls_process (ovpn_peer_t *peer, u8 *data, u32 len);

/*
 * Get TLS data to send on control channel
 * Returns pointer to data and sets len, or NULL if no data
 */
u8 *ovpn_peer_tls_get_sendbuf (vlib_main_t *vm, ovpn_peer_t *peer, u32 *len);

/*
 * Check if TLS handshake is complete
 */
always_inline int
ovpn_peer_tls_is_established (ovpn_peer_t *peer)
{
  return peer->tls_ctx && peer->tls_ctx->state == OVPN_TLS_STATE_ESTABLISHED;
}

/*
 * Start a rekey for an established peer
 * Allocates TLS context and transitions to REKEYING state
 * Returns 0 on success, <0 on error
 */
int ovpn_peer_start_rekey (vlib_main_t *vm, ovpn_peer_t *peer,
			   ptls_context_t *ptls_ctx, u8 key_id);

/*
 * Complete a rekey - activate new keys and retire old ones
 * Called after TLS handshake completes during rekey
 * Returns 0 on success, <0 on error
 */
int ovpn_peer_complete_rekey (vlib_main_t *vm, ovpn_peer_t *peer,
			      ovpn_cipher_alg_t cipher_alg);

/*
 * Get the next key_id for rekey
 * Cycles through 0-7 (3 bits)
 */
always_inline u8
ovpn_peer_next_key_id (ovpn_peer_t *peer)
{
  u8 current_key_id = peer->keys[peer->current_key_slot].key_id;
  return (current_key_id + 1) & OVPN_OP_KEY_ID_MASK;
}

/*
 * Check if peer needs rekey based on time
 */
always_inline int
ovpn_peer_needs_rekey (ovpn_peer_t *peer, f64 now)
{
  if (peer->state != OVPN_PEER_STATE_ESTABLISHED)
    return 0;
  if (peer->rekey_interval <= 0)
    return 0;
  return now >= peer->next_rekey_time;
}

/*
 * Hash key for remote address lookup
 */
always_inline u64
ovpn_peer_remote_hash_key (const ip_address_t *addr, u16 port)
{
  u64 key = port;
  if (addr->version == AF_IP4)
    {
      key |= ((u64) addr->ip.ip4.as_u32) << 16;
    }
  else
    {
      /* For IPv6, use lower 48 bits */
      key |= ((u64) addr->ip.ip6.as_u64[0]) << 16;
    }
  return key;
}

/*
 * Send ping packet to peer
 * Used for keepalive - sends encrypted ping magic pattern on data channel
 */
void ovpn_peer_send_ping (vlib_main_t *vm, ovpn_peer_t *peer);

#endif /* __included_ovpn_peer_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
