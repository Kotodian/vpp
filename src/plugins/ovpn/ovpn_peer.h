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
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_24_8.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_session_id.h>
#include <ovpn/ovpn_packet.h>
#include <ovpn/ovpn_reliable.h>
#include <ovpn/ovpn_buffer.h>
#include <picotls.h>

/*
 * Synchronization for multi-threaded access
 *
 * Race conditions addressed:
 * 1. Peer add/delete - control plane modifies while data plane reads
 * 2. Rekey - key slots change while data plane uses them
 * 3. Peer lookup - hash table modified during lookup
 *
 * Strategy:
 * - Generation counter: detect stale peer references
 * - Soft delete: mark DEAD, defer actual free until safe
 * - Bihash for key lookup: lock-free (peer_id, key_id) -> crypto context
 * - Worker barrier for peer add/delete operations
 */

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

  /* Peer state - use atomic access */
  volatile ovpn_peer_state_t state;

  /*
   * Generation counter for detecting stale references.
   * Incremented on significant state changes (delete, rekey complete).
   * Data plane can check if peer changed since lookup.
   */
  volatile u32 generation;

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

  /* Bytes/packets since last rekey (for reneg-bytes/reneg-pkts) */
  u64 bytes_since_rekey;
  u64 packets_since_rekey;

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

  /*
   * Bihash for lock-free lookup by remote address + port.
   * Key: 24 bytes (ip_address_t + port padded)
   * Value: peer_id
   * Used for P_DATA_V1 and handshake packets.
   */
  clib_bihash_24_8_t remote_hash;

  /* Lookup by virtual IP (control plane only, not performance critical) */
  uword *peer_index_by_virtual_ip;

  /*
   * Bihash for lock-free key lookup by (peer_id, key_id).
   * Key: (peer_id << 8) | key_id
   * Value: pointer to ovpn_peer_key_t
   * Provides lock-free concurrent access for data plane crypto lookups.
   */
  clib_bihash_8_8_t key_hash;

  /* Next peer_id to allocate */
  u32 next_peer_id;

  /* Associated interface sw_if_index */
  u32 sw_if_index;

  /*
   * Global generation counter.
   * Incremented on any structural change to help detect stale state.
   */
  u32 generation;

  /*
   * NOTE: Peer add/delete operations use worker thread barrier
   * (vlib_worker_thread_barrier_sync/release) for synchronization.
   * This pauses all worker threads, ensuring no stale references.
   * No spinlock needed - barrier provides stronger guarantee.
   */

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
 * MUST be called with worker barrier held (vlib_worker_thread_barrier_sync)
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
 * Atomic state access functions
 */
always_inline ovpn_peer_state_t
ovpn_peer_get_state (ovpn_peer_t *peer)
{
  return __atomic_load_n (&peer->state, __ATOMIC_ACQUIRE);
}

always_inline void
ovpn_peer_set_state (ovpn_peer_t *peer, ovpn_peer_state_t state)
{
  __atomic_store_n (&peer->state, state, __ATOMIC_RELEASE);
}

always_inline int
ovpn_peer_is_valid (ovpn_peer_t *peer)
{
  ovpn_peer_state_t state = ovpn_peer_get_state (peer);
  return state != OVPN_PEER_STATE_DEAD && state != OVPN_PEER_STATE_INITIAL;
}

/*
 * Generation counter functions
 */
always_inline u32
ovpn_peer_get_generation (ovpn_peer_t *peer)
{
  return __atomic_load_n (&peer->generation, __ATOMIC_ACQUIRE);
}

always_inline void
ovpn_peer_increment_generation (ovpn_peer_t *peer)
{
  __atomic_add_fetch (&peer->generation, 1, __ATOMIC_RELEASE);
}

/*
 * Bihash key helper for (peer_id, key_id) -> crypto context lookup
 */
always_inline u64
ovpn_peer_key_hash_key (u32 peer_id, u8 key_id)
{
  return ((u64) peer_id << 8) | key_id;
}

/*
 * Check if peer is usable by data plane
 * Returns 1 if peer is in a valid state for data processing
 */
always_inline int
ovpn_peer_is_established (ovpn_peer_t *peer)
{
  ovpn_peer_state_t state = ovpn_peer_get_state (peer);
  return state == OVPN_PEER_STATE_ESTABLISHED ||
	 state == OVPN_PEER_STATE_REKEYING;
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
 * Set peer crypto key (updates bihash for lock-free lookup)
 */
int ovpn_peer_set_key (vlib_main_t *vm, ovpn_peer_db_t *db, ovpn_peer_t *peer,
		       u8 key_slot, ovpn_cipher_alg_t cipher_alg,
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
 * Get crypto context by key_id using bihash lookup
 */
ovpn_crypto_context_t *ovpn_peer_get_crypto_by_key_id (ovpn_peer_db_t *db,
						       u32 peer_id, u8 key_id);

/*
 * Update peer activity timestamp
 */
always_inline void
ovpn_peer_update_rx (ovpn_peer_t *peer, f64 now, u32 bytes)
{
  peer->last_rx_time = now;
  peer->rx_bytes += bytes;
  peer->rx_packets++;
  /* Track for reneg-bytes/reneg-pkts */
  peer->bytes_since_rekey += bytes;
  peer->packets_since_rekey++;
}

always_inline void
ovpn_peer_update_tx (ovpn_peer_t *peer, f64 now, u32 bytes)
{
  peer->last_tx_time = now;
  peer->tx_bytes += bytes;
  peer->tx_packets++;
  /* Track for reneg-bytes/reneg-pkts */
  peer->bytes_since_rekey += bytes;
  peer->packets_since_rekey++;
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
 * Cleanup expired keys for a peer
 * Called by periodic timer to remove "lame duck" keys after transition window
 * Returns number of keys cleaned up
 */
int ovpn_peer_cleanup_expired_keys (vlib_main_t *vm, ovpn_peer_db_t *db,
				    ovpn_peer_t *peer, f64 now);

/*
 * Cleanup expired keys for all peers in database
 * Called by periodic timer process
 * Returns number of keys cleaned up
 */
int ovpn_peer_db_cleanup_expired_keys (vlib_main_t *vm, ovpn_peer_db_t *db,
				       f64 now);

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
int ovpn_peer_complete_rekey (vlib_main_t *vm, ovpn_peer_db_t *db,
			      ovpn_peer_t *peer, ovpn_cipher_alg_t cipher_alg);

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
 * Check if peer needs rekey based on time, bytes, or packets
 * Following OpenVPN: reneg-sec, reneg-bytes, reneg-pkts
 */
always_inline int
ovpn_peer_needs_rekey (ovpn_peer_t *peer, f64 now, u64 reneg_bytes,
		       u64 reneg_pkts)
{
  if (peer->state != OVPN_PEER_STATE_ESTABLISHED)
    return 0;
  if (peer->rekey_initiated)
    return 0; /* Already rekeying */

  /* Check time-based rekey (reneg-sec) */
  if (peer->rekey_interval > 0 && now >= peer->next_rekey_time)
    return 1;

  /* Check bytes-based rekey (reneg-bytes) */
  if (reneg_bytes > 0 && peer->bytes_since_rekey >= reneg_bytes)
    return 1;

  /* Check packets-based rekey (reneg-pkts) */
  if (reneg_pkts > 0 && peer->packets_since_rekey >= reneg_pkts)
    return 1;

  return 0;
}

/*
 * Build 24-byte key for remote address bihash lookup
 * Key structure: [ip_address (16 bytes)] [port (2 bytes)] [is_ipv6 (1 byte)] [padding (5 bytes)]
 */
always_inline void
ovpn_peer_remote_hash_make_key (clib_bihash_kv_24_8_t *kv,
				const ip_address_t *addr, u16 port)
{
  clib_memset (kv, 0, sizeof (*kv));
  if (addr->version == AF_IP4)
    {
      /* IPv4: store in first 4 bytes */
      kv->key[0] = addr->ip.ip4.as_u32;
      kv->key[1] = port;
      kv->key[2] = 0; /* is_ipv6 = 0 */
    }
  else
    {
      /* IPv6: store full 16 bytes */
      kv->key[0] = addr->ip.ip6.as_u64[0];
      kv->key[1] = addr->ip.ip6.as_u64[1];
      kv->key[2] = ((u64) port) | (1ULL << 16); /* port + is_ipv6 flag */
    }
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
