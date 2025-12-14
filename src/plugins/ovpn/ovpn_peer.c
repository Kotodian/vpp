/*
 * ovpn_peer.c - OpenVPN peer management implementation
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

#include <ovpn/ovpn.h>
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_ssl.h>
#include <ovpn/ovpn_session_id.h>
#include <ovpn/ovpn_handshake.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_if.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/fib/fib_table.h>
#include <picotls/openssl.h>

/* Global mapping from adjacency index to peer index */
u32 *ovpn_peer_by_adj_index;

/* Control channel buffer sizes */
#define OVPN_TLS_BUF_SIZE     4096
#define OVPN_TLS_RELIABLE_CAP 8

void
ovpn_peer_db_init (ovpn_peer_db_t *db, u32 sw_if_index)
{
  clib_memset (db, 0, sizeof (*db));
  db->sw_if_index = sw_if_index;
  db->peer_index_by_virtual_ip = hash_create (0, sizeof (uword));
  db->next_peer_id = 1; /* Start from 1, 0 is reserved */

  /* Initialize bihash for remote address -> peer_id lookup (lock-free) */
  clib_bihash_init_24_8 (&db->remote_hash, "ovpn peer remote hash",
			 1024 /* nbuckets */, 64 << 10 /* memory_size */);

  /* Initialize bihash for (peer_id, key_id) -> crypto context lookup */
  clib_bihash_init_8_8 (&db->key_hash, "ovpn peer key hash",
			1024 /* nbuckets */, 64 << 10 /* memory_size */);

  /* Initialize bihash for session ID -> peer_id lookup (NAT/float support) */
  clib_bihash_init_8_8 (&db->session_hash, "ovpn peer session hash",
			1024 /* nbuckets */, 64 << 10 /* memory_size */);
}

void
ovpn_peer_db_free (ovpn_peer_db_t *db)
{
  ovpn_peer_t *peer;

  pool_foreach (peer, db->peers)
    {
      /* Free crypto contexts */
      for (int i = 0; i < OVPN_KEY_SLOT_COUNT; i++)
	{
	  if (peer->keys[i].crypto.is_valid)
	    ovpn_crypto_context_free (&peer->keys[i].crypto);
	}
      /* Free rewrite */
      vec_free (peer->rewrite);
    }

  pool_free (db->peers);
  hash_free (db->peer_index_by_virtual_ip);

  /* Free bihashes */
  clib_bihash_free_24_8 (&db->remote_hash);
  clib_bihash_free_8_8 (&db->key_hash);
  clib_bihash_free_8_8 (&db->session_hash);

  clib_memset (db, 0, sizeof (*db));
}

u32
ovpn_peer_create (ovpn_peer_db_t *db, const ip_address_t *remote_addr,
		  u16 remote_port)
{
  ovpn_peer_t *peer;
  u32 peer_id;
  clib_bihash_kv_24_8_t kv;

  /* Check if peer already exists */
  peer = ovpn_peer_lookup_by_remote (db, remote_addr, remote_port);
  if (peer)
    return peer->peer_id; /* Return existing peer */

  /* Allocate new peer */
  pool_get_zero (db->peers, peer);
  peer_id = peer - db->peers;

  /* Ensure peer_id fits in 24 bits */
  if (peer_id > OVPN_MAX_PEER_ID)
    {
      pool_put (db->peers, peer);
      return ~0;
    }

  peer->peer_id = peer_id;
  peer->state = OVPN_PEER_STATE_INITIAL;
  peer->sw_if_index = db->sw_if_index;
  peer->generation = 0;

  /* Set remote address */
  ip_address_copy (&peer->remote_addr, remote_addr);
  peer->remote_port = remote_port;
  peer->is_ipv6 = (remote_addr->version == AF_IP6);

  /* Generate session ID */
  ovpn_session_id_generate (&peer->session_id);

  /* Add to session ID hash for NAT/float lookup */
  ovpn_peer_add_to_session_hash (db, peer);

  /* Initialize timestamps */
  peer->last_rx_time = vlib_time_now (vlib_get_main ());
  peer->last_tx_time = peer->last_rx_time;

  /* Initialize adjacency index */
  peer->adj_index = ADJ_INDEX_INVALID;

  /* Thread index unassigned - will be set on first packet */
  peer->input_thread_index = ~0;

  /* Add to remote address bihash (lock-free) */
  ovpn_peer_remote_hash_make_key (&kv, remote_addr, remote_port);
  kv.value = peer_id;
  clib_bihash_add_del_24_8 (&db->remote_hash, &kv, 1 /* is_add */);

  return peer_id;
}

/*
 * Delete a peer
 *
 * IMPORTANT: Caller MUST hold worker barrier (vlib_worker_thread_barrier_sync)
 * to ensure no data plane workers are accessing this peer.
 */
void
ovpn_peer_delete (ovpn_peer_db_t *db, u32 peer_id)
{
  ovpn_peer_t *peer;
  clib_bihash_kv_8_8_t kv;
  clib_bihash_kv_24_8_t kv24;

  peer = ovpn_peer_get (db, peer_id);
  if (!peer)
    return;

  /*
   * Mark peer as DEAD first.
   * Any data plane code that somehow runs (shouldn't happen with barrier)
   * will see DEAD state and skip processing.
   */
  ovpn_peer_set_state (peer, OVPN_PEER_STATE_DEAD);
  ovpn_peer_increment_generation (peer);

  /* Remove from remote address bihash */
  ovpn_peer_remote_hash_make_key (&kv24, &peer->remote_addr, peer->remote_port);
  clib_bihash_add_del_24_8 (&db->remote_hash, &kv24, 0 /* is_add */);

  /* Remove from session ID hash */
  if (ovpn_session_id_defined (&peer->session_id))
    {
      kv.key = *(u64 *) peer->session_id.id;
      clib_bihash_add_del_8_8 (&db->session_hash, &kv, 0 /* is_add */);
    }

  /* Remove from virtual IP hash if set */
  if (peer->virtual_ip_set)
    {
      u64 vip_key;
      if (peer->virtual_ip.version == AF_IP4)
	vip_key = peer->virtual_ip.ip.ip4.as_u32;
      else
	vip_key = peer->virtual_ip.ip.ip6.as_u64[0] ^
		  peer->virtual_ip.ip.ip6.as_u64[1];
      hash_unset (db->peer_index_by_virtual_ip, vip_key);
    }

  /* Free TLS context if exists */
  if (peer->tls_ctx)
    ovpn_peer_tls_free (peer);

  /* Remove key entries from bihash and free crypto contexts */
  for (int i = 0; i < OVPN_KEY_SLOT_COUNT; i++)
    {
      if (peer->keys[i].is_active)
	{
	  kv.key = ovpn_peer_key_hash_key (peer_id, peer->keys[i].key_id);
	  clib_bihash_add_del_8_8 (&db->key_hash, &kv, 0 /* is_add */);
	}
      if (peer->keys[i].crypto.is_valid)
	ovpn_crypto_context_free (&peer->keys[i].crypto);
    }

  /* Free rewrite */
  vec_free (peer->rewrite);

  /* Release adjacency */
  if (peer->adj_index != ADJ_INDEX_INVALID)
    adj_unlock (peer->adj_index);

  /* Increment database generation */
  db->generation++;

  /* Return to pool */
  pool_put (db->peers, peer);
}

/*
 * Lookup peer by remote address + port (lock-free via bihash)
 * Used for P_DATA_V1 packets and handshake.
 */
ovpn_peer_t *
ovpn_peer_lookup_by_remote (ovpn_peer_db_t *db, const ip_address_t *addr,
			    u16 port)
{
  clib_bihash_kv_24_8_t kv, value;

  ovpn_peer_remote_hash_make_key (&kv, addr, port);
  if (clib_bihash_search_24_8 (&db->remote_hash, &kv, &value) == 0)
    {
      u32 peer_id = (u32) value.value;
      if (peer_id < pool_elts (db->peers))
	return pool_elt_at_index (db->peers, peer_id);
    }
  return NULL;
}

ovpn_peer_t *
ovpn_peer_lookup_by_virtual_ip (ovpn_peer_db_t *db, const ip_address_t *addr)
{
  uword *p;
  u64 key;

  if (addr->version == AF_IP4)
    key = addr->ip.ip4.as_u32;
  else
    key = addr->ip.ip6.as_u64[0] ^ addr->ip.ip6.as_u64[1];

  p = hash_get (db->peer_index_by_virtual_ip, key);
  if (!p)
    return NULL;

  return pool_elt_at_index (db->peers, p[0]);
}

/*
 * Add peer to session ID hash
 */
void
ovpn_peer_add_to_session_hash (ovpn_peer_db_t *db, ovpn_peer_t *peer)
{
  clib_bihash_kv_8_8_t kv;

  if (!ovpn_session_id_defined (&peer->session_id))
    return;

  kv.key = *(u64 *) peer->session_id.id;
  kv.value = peer->peer_id;
  clib_bihash_add_del_8_8 (&db->session_hash, &kv, 1 /* is_add */);
}

/*
 * Lookup peer by session ID (NAT/float support)
 */
ovpn_peer_t *
ovpn_peer_lookup_by_session_id (ovpn_peer_db_t *db,
				const ovpn_session_id_t *session_id)
{
  clib_bihash_kv_8_8_t kv, value;

  if (!ovpn_session_id_defined (session_id))
    return NULL;

  kv.key = *(u64 *) session_id->id;
  if (clib_bihash_search_8_8 (&db->session_hash, &kv, &value) == 0)
    {
      u32 peer_id = (u32) value.value;
      if (!pool_is_free_index (db->peers, peer_id))
	return pool_elt_at_index (db->peers, peer_id);
    }
  return NULL;
}

/*
 * Update peer remote address (NAT/float support)
 *
 * IMPORTANT: Caller MUST hold worker barrier (vlib_worker_thread_barrier_sync)
 * to ensure no data plane workers are accessing this peer.
 */
int
ovpn_peer_update_remote (ovpn_peer_db_t *db, ovpn_peer_t *peer,
			 const ip_address_t *new_addr, u16 new_port)
{
  clib_bihash_kv_24_8_t kv;

  /* Check if address actually changed */
  if (ip_address_cmp (&peer->remote_addr, new_addr) == 0 &&
      peer->remote_port == new_port)
    return 0; /* No change */

  /* Log the address change */
  clib_warning ("ovpn: peer %u address changed from %U:%u to %U:%u",
		peer->peer_id, format_ip_address, &peer->remote_addr,
		peer->remote_port, format_ip_address, new_addr, new_port);

  /* Remove old entry from remote_hash */
  ovpn_peer_remote_hash_make_key (&kv, &peer->remote_addr, peer->remote_port);
  clib_bihash_add_del_24_8 (&db->remote_hash, &kv, 0 /* is_add */);

  /* Update peer fields */
  ip_address_copy (&peer->remote_addr, new_addr);
  peer->remote_port = new_port;
  peer->is_ipv6 = (new_addr->version == AF_IP6);

  /* Add new entry to remote_hash */
  ovpn_peer_remote_hash_make_key (&kv, new_addr, new_port);
  kv.value = peer->peer_id;
  clib_bihash_add_del_24_8 (&db->remote_hash, &kv, 1 /* is_add */);

  /* Rebuild rewrite buffer with new destination */
  if (peer->rewrite)
    {
      ovpn_if_t *oif = ovpn_if_get_from_sw_if_index (peer->sw_if_index);
      if (oif)
	ovpn_peer_build_rewrite (peer, &oif->local_addr, oif->local_port);
    }

  /* Increment generation to signal data plane */
  ovpn_peer_increment_generation (peer);

  /* Clear pending update flag */
  __atomic_store_n (&peer->pending_addr_update, 0, __ATOMIC_RELEASE);

  return 0;
}

/*
 * Queue a pending address update for a peer
 * Called from data plane - must be lock-free
 */
void
ovpn_peer_queue_address_update (ovpn_peer_t *peer, const ip_address_t *new_addr,
				u16 new_port)
{
  /* Only queue if not already pending */
  if (__atomic_load_n (&peer->pending_addr_update, __ATOMIC_ACQUIRE))
    return;

  /* Store new address */
  ip_address_copy (&peer->pending_remote_addr, new_addr);
  peer->pending_remote_port = new_port;

  /* Set flag atomically */
  __atomic_store_n (&peer->pending_addr_update, 1, __ATOMIC_RELEASE);
}

/*
 * Apply pending address updates for all peers
 * Called from control plane timer with worker barrier held.
 */
int
ovpn_peer_db_apply_pending_updates (vlib_main_t *vm, ovpn_peer_db_t *db)
{
  ovpn_peer_t *peer;
  int count = 0;

  pool_foreach (peer, db->peers)
    {
      if (__atomic_load_n (&peer->pending_addr_update, __ATOMIC_ACQUIRE))
	{
	  ovpn_peer_update_remote (db, peer, &peer->pending_remote_addr,
				   peer->pending_remote_port);
	  count++;
	}
    }

  return count;
}

/*
 * Set peer crypto key
 *
 * Updates bihash for lock-free data plane lookup.
 * Must be called from main thread or with worker barrier held.
 */
int
ovpn_peer_set_key (vlib_main_t *vm, ovpn_peer_db_t *db, ovpn_peer_t *peer,
		   u8 key_slot, ovpn_cipher_alg_t cipher_alg,
		   const ovpn_key_material_t *keys, u8 key_id,
		   u32 replay_window)
{
  ovpn_peer_key_t *pkey;
  clib_bihash_kv_8_8_t kv;
  int rv;

  if (key_slot >= OVPN_KEY_SLOT_COUNT)
    return -1;

  pkey = &peer->keys[key_slot];

  /* Remove old bihash entry if key was active */
  if (pkey->is_active)
    {
      kv.key = ovpn_peer_key_hash_key (peer->peer_id, pkey->key_id);
      clib_bihash_add_del_8_8 (&db->key_hash, &kv, 0 /* is_add */);
    }

  /* Free existing crypto context if any */
  if (pkey->crypto.is_valid)
    ovpn_crypto_context_free (&pkey->crypto);

  /* Initialize new key */
  rv = ovpn_crypto_context_init (&pkey->crypto, cipher_alg, keys,
				 replay_window);
  if (rv < 0)
    return rv;

  pkey->key_id = key_id;
  pkey->is_active = 1;
  pkey->created_at = vlib_time_now (vm);
  pkey->expires_at = 0; /* Set by caller based on config */

  /* Add new entry to bihash for lock-free lookup */
  kv.key = ovpn_peer_key_hash_key (peer->peer_id, key_id);
  kv.value = (u64) (uword) pkey;
  clib_bihash_add_del_8_8 (&db->key_hash, &kv, 1 /* is_add */);

  /* Increment generation to signal key change */
  ovpn_peer_increment_generation (peer);

  return 0;
}

/*
 * Get crypto context by key_id using bihash lookup (lock-free)
 */
ovpn_crypto_context_t *
ovpn_peer_get_crypto_by_key_id (ovpn_peer_db_t *db, u32 peer_id, u8 key_id)
{
  clib_bihash_kv_8_8_t kv, value;

  kv.key = ovpn_peer_key_hash_key (peer_id, key_id);

  if (clib_bihash_search_8_8 (&db->key_hash, &kv, &value) == 0)
    {
      ovpn_peer_key_t *pkey = (ovpn_peer_key_t *) (uword) value.value;
      if (pkey->is_active && pkey->crypto.is_valid)
	return &pkey->crypto;
    }

  return NULL;
}

int
ovpn_peer_build_rewrite (ovpn_peer_t *peer, const ip_address_t *local_addr,
			 u16 local_port)
{
  u8 *rewrite = NULL;

  if (peer->is_ipv6)
    {
      ip6_header_t *ip6;
      udp_header_t *udp;

      vec_validate (rewrite,
		    sizeof (ip6_header_t) + sizeof (udp_header_t) - 1);

      ip6 = (ip6_header_t *) rewrite;
      udp = (udp_header_t *) (ip6 + 1);

      ip6->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (0x60000000);
      ip6->payload_length = 0; /* Set per-packet */
      ip6->protocol = IP_PROTOCOL_UDP;
      ip6->hop_limit = 64;
      clib_memcpy_fast (&ip6->src_address, &local_addr->ip.ip6,
			sizeof (ip6_address_t));
      clib_memcpy_fast (&ip6->dst_address, &peer->remote_addr.ip.ip6,
			sizeof (ip6_address_t));

      udp->src_port = clib_host_to_net_u16 (local_port);
      udp->dst_port = clib_host_to_net_u16 (peer->remote_port);
      udp->length = 0;	 /* Set per-packet */
      udp->checksum = 0; /* Optional for IPv6 */
    }
  else
    {
      ip4_header_t *ip4;
      udp_header_t *udp;

      vec_validate (rewrite,
		    sizeof (ip4_header_t) + sizeof (udp_header_t) - 1);

      ip4 = (ip4_header_t *) rewrite;
      udp = (udp_header_t *) (ip4 + 1);

      ip4->ip_version_and_header_length = 0x45;
      ip4->tos = 0;
      ip4->length = 0; /* Set per-packet */
      ip4->fragment_id = 0;
      ip4->flags_and_fragment_offset = 0;
      ip4->ttl = 64;
      ip4->protocol = IP_PROTOCOL_UDP;
      ip4->checksum = 0; /* Computed per-packet or offloaded */
      clib_memcpy_fast (&ip4->src_address, &local_addr->ip.ip4,
			sizeof (ip4_address_t));
      clib_memcpy_fast (&ip4->dst_address, &peer->remote_addr.ip.ip4,
			sizeof (ip4_address_t));

      udp->src_port = clib_host_to_net_u16 (local_port);
      udp->dst_port = clib_host_to_net_u16 (peer->remote_port);
      udp->length = 0;	 /* Set per-packet */
      udp->checksum = 0; /* Computed per-packet or offloaded */
    }

  /* Free old rewrite */
  vec_free (peer->rewrite);

  peer->rewrite = rewrite;
  peer->rewrite_len = vec_len (rewrite);

  return 0;
}

u8 *
format_ovpn_peer (u8 *s, va_list *args)
{
  ovpn_peer_t *peer = va_arg (*args, ovpn_peer_t *);
  const char *state_str;

  switch (peer->state)
    {
    case OVPN_PEER_STATE_INITIAL:
      state_str = "initial";
      break;
    case OVPN_PEER_STATE_HANDSHAKE:
      state_str = "handshake";
      break;
    case OVPN_PEER_STATE_ESTABLISHED:
      state_str = "established";
      break;
    case OVPN_PEER_STATE_REKEYING:
      state_str = "rekeying";
      break;
    case OVPN_PEER_STATE_DEAD:
      state_str = "dead";
      break;
    default:
      state_str = "unknown";
      break;
    }

  s = format (s, "peer %u [%s]", peer->peer_id, state_str);
  s = format (s, "\n  remote: %U:%u", format_ip_address, &peer->remote_addr,
	      peer->remote_port);

  if (peer->virtual_ip_set)
    s = format (s, "\n  virtual-ip: %U", format_ip_address, &peer->virtual_ip);

  s = format (s, "\n  rx: %lu packets, %lu bytes", peer->rx_packets,
	      peer->rx_bytes);
  s = format (s, "\n  tx: %lu packets, %lu bytes", peer->tx_packets,
	      peer->tx_bytes);

  for (int i = 0; i < OVPN_KEY_SLOT_COUNT; i++)
    {
      if (peer->keys[i].is_active)
	{
	  s = format (s, "\n  key[%d]: id=%u valid=%d", i,
		      peer->keys[i].key_id, peer->keys[i].crypto.is_valid);
	}
    }

  return s;
}

/*
 * Initialize TLS handshake context for a peer
 */
int
ovpn_peer_tls_init (ovpn_peer_t *peer, ptls_context_t *ptls_ctx, u8 key_id)
{
  ovpn_peer_tls_t *tls_ctx;

  /* Free existing context if any */
  if (peer->tls_ctx)
    ovpn_peer_tls_free (peer);

  /* Allocate TLS context */
  tls_ctx = clib_mem_alloc (sizeof (ovpn_peer_tls_t));
  if (!tls_ctx)
    return -1;

  clib_memset (tls_ctx, 0, sizeof (*tls_ctx));

  tls_ctx->state = OVPN_TLS_STATE_INITIAL;
  tls_ctx->key_id = key_id;
  tls_ctx->packet_id_send = 0;

  /* Initialize reliable structures for control channel */
  tls_ctx->send_reliable = clib_mem_alloc (sizeof (ovpn_reliable_t));
  if (!tls_ctx->send_reliable)
    goto error;
  ovpn_reliable_init (tls_ctx->send_reliable, OVPN_TLS_BUF_SIZE,
		      128 /* header offset */, OVPN_TLS_RELIABLE_CAP,
		      0 /* hold */);
  ovpn_reliable_set_timeout (tls_ctx->send_reliable, 2.0);

  tls_ctx->recv_reliable = clib_mem_alloc (sizeof (ovpn_reliable_t));
  if (!tls_ctx->recv_reliable)
    goto error;
  ovpn_reliable_init (tls_ctx->recv_reliable, OVPN_TLS_BUF_SIZE,
		      0 /* header offset */, OVPN_TLS_RELIABLE_CAP,
		      0 /* hold */);

  /* Create picotls server context */
  tls_ctx->tls = ptls_new (ptls_ctx, 1 /* is_server */);
  if (!tls_ctx->tls)
    goto error;

  /* Allocate key source for Key Method 2 exchange */
  tls_ctx->key_src2 = ovpn_key_source2_alloc ();
  if (!tls_ctx->key_src2)
    goto error;

  /* Initialize key exchange flags */
  tls_ctx->key_method_sent = 0;
  tls_ctx->key_method_received = 0;
  tls_ctx->use_tls_ekm = 0; /* Default to PRF method for compatibility */

  tls_ctx->state = OVPN_TLS_STATE_HANDSHAKE;
  peer->tls_ctx = tls_ctx;

  return 0;

error:
  if (tls_ctx->key_src2)
    ovpn_key_source2_free (tls_ctx->key_src2);
  if (tls_ctx->send_reliable)
    {
      ovpn_reliable_free (tls_ctx->send_reliable);
      clib_mem_free (tls_ctx->send_reliable);
    }
  if (tls_ctx->recv_reliable)
    {
      ovpn_reliable_free (tls_ctx->recv_reliable);
      clib_mem_free (tls_ctx->recv_reliable);
    }
  clib_mem_free (tls_ctx);
  return -1;
}

/*
 * Free TLS handshake context
 */
void
ovpn_peer_tls_free (ovpn_peer_t *peer)
{
  ovpn_peer_tls_t *tls_ctx = peer->tls_ctx;

  if (!tls_ctx)
    return;

  /* Free picotls context */
  if (tls_ctx->tls)
    ptls_free (tls_ctx->tls);

  /* Free key source */
  if (tls_ctx->key_src2)
    ovpn_key_source2_free (tls_ctx->key_src2);

  /* Free peer options string */
  if (tls_ctx->peer_options)
    clib_mem_free (tls_ctx->peer_options);

  /* Free reliable structures */
  if (tls_ctx->send_reliable)
    {
      ovpn_reliable_free (tls_ctx->send_reliable);
      clib_mem_free (tls_ctx->send_reliable);
    }
  if (tls_ctx->recv_reliable)
    {
      ovpn_reliable_free (tls_ctx->recv_reliable);
      clib_mem_free (tls_ctx->recv_reliable);
    }

  clib_mem_free (tls_ctx);
  peer->tls_ctx = NULL;
}

/*
 * Process incoming TLS data from control channel
 *
 * This function handles both:
 * 1. TLS handshake data (before handshake completes)
 * 2. TLS application data (after handshake completes, e.g., Key Method 2)
 *
 * Returns: >0 if TLS data was produced for sending
 *          0 if no data to send
 *          <0 on error
 */
int
ovpn_peer_tls_process (ovpn_peer_t *peer, u8 *data, u32 len)
{
  ovpn_peer_tls_t *tls_ctx = peer->tls_ctx;
  ptls_buffer_t sendbuf;
  int ret;

  if (!tls_ctx || !tls_ctx->tls)
    return -1;

  /* Initialize send buffer */
  ptls_buffer_init (&sendbuf, "", 0);

  /*
   * If TLS handshake is not yet complete, use ptls_handshake
   * Otherwise, use ptls_receive to decrypt application data
   */
  if (tls_ctx->state != OVPN_TLS_STATE_ESTABLISHED)
    {
      /* TLS handshake phase */
      size_t consumed = len;
      ret = ptls_handshake (tls_ctx->tls, &sendbuf, data, &consumed, NULL);

      if (ret == 0)
	{
	  /* Handshake complete */
	  tls_ctx->state = OVPN_TLS_STATE_ESTABLISHED;

	  /*
	   * There may be application data following the handshake in the same
	   * buffer. Process any remaining data with ptls_receive.
	   */
	  if (consumed < len)
	    {
	      ptls_buffer_t plaintext;
	      ptls_buffer_init (&plaintext, "", 0);

	      size_t remaining = len - consumed;
	      int recv_ret = ptls_receive (tls_ctx->tls, &plaintext,
					   data + consumed, &remaining);

	      if (recv_ret == 0 && plaintext.off > 0)
		{
		  /* Store decrypted data in plaintext read buffer */
		  ovpn_buf_write (&tls_ctx->plaintext_read_buf, plaintext.base,
				  plaintext.off);
		}
	      /* Ignore recv_ret errors here - handshake succeeded,
	       * remaining data may be incomplete record */
	      ptls_buffer_dispose (&plaintext);
	    }
	}
      else if (ret == PTLS_ERROR_IN_PROGRESS)
	{
	  /* Handshake still in progress - this is normal */
	  ret = 0;
	}
      else if (ret < 0)
	{
	  /* Error */
	  tls_ctx->state = OVPN_TLS_STATE_ERROR;
	  ptls_buffer_dispose (&sendbuf);
	  return -1;
	}
    }
  else
    {
      /*
       * TLS handshake already complete - decrypt application data
       * This is used for Key Method 2 data exchange
       *
       * ptls_receive returns:
       *   0 on success (check plaintext.off for data length)
       *   negative on error
       */
      ptls_buffer_t plaintext;
      ptls_buffer_init (&plaintext, "", 0);

      size_t consumed = len;
      ret = ptls_receive (tls_ctx->tls, &plaintext, data, &consumed);

      if (ret != 0)
	{
	  /* Error decrypting */
	  ptls_buffer_dispose (&plaintext);
	  ptls_buffer_dispose (&sendbuf);
	  return -1;
	}

      /* ret == 0: success, check if we got any plaintext */
      if (plaintext.off > 0)
	{
	  /* Store decrypted data in plaintext read buffer */
	  ovpn_buf_write (&tls_ctx->plaintext_read_buf, plaintext.base,
			  plaintext.off);
	  ret = plaintext.off;
	}
      else
	{
	  /* No complete record yet, need more data */
	  ret = 0;
	}

      ptls_buffer_dispose (&plaintext);
    }

  /* If we have data to send, queue it in the reliable layer */
  if (sendbuf.off > 0)
    {
      ovpn_reli_buffer_t *buf =
	ovpn_reliable_get_buf_output_sequenced (tls_ctx->send_reliable);
      if (buf)
	{
	  /* Copy TLS data to reliable buffer */
	  ovpn_buf_init (buf, 128); /* Leave room for headers */
	  ovpn_buf_write (buf, sendbuf.base, sendbuf.off);
	  ovpn_reliable_mark_active_outgoing (tls_ctx->send_reliable, buf,
					      OVPN_OP_CONTROL_V1);
	  ret = sendbuf.off;
	}
    }

  ptls_buffer_dispose (&sendbuf);
  return ret;
}

/*
 * Get TLS data to send on control channel
 */
u8 *
ovpn_peer_tls_get_sendbuf (vlib_main_t *vm, ovpn_peer_t *peer, u32 *len)
{
  ovpn_peer_tls_t *tls_ctx = peer->tls_ctx;
  ovpn_reli_buffer_t *buf;
  u8 opcode;

  if (!tls_ctx)
    return NULL;

  if (!ovpn_reliable_can_send (vm, tls_ctx->send_reliable))
    return NULL;

  buf = ovpn_reliable_send (vm, tls_ctx->send_reliable, &opcode);
  if (!buf)
    return NULL;

  *len = OVPN_BLEN (buf);
  return OVPN_BPTR (buf);
}

/*
 * Start a rekey for an established peer
 */
int
ovpn_peer_start_rekey (vlib_main_t *vm, ovpn_peer_t *peer,
		       ptls_context_t *ptls_ctx, u8 key_id)
{
  int rv;

  /* Can only rekey from ESTABLISHED state */
  if (peer->state != OVPN_PEER_STATE_ESTABLISHED)
    return -1;

  /* Cannot start rekey if one is already in progress */
  if (peer->tls_ctx)
    return -2;

  /* Initialize TLS context for rekey */
  rv = ovpn_peer_tls_init (peer, ptls_ctx, key_id);
  if (rv < 0)
    return rv;

  /* Set up rekey state */
  peer->rekey_key_id = key_id;
  peer->pending_key_slot =
    (peer->current_key_slot == OVPN_KEY_SLOT_PRIMARY) ? OVPN_KEY_SLOT_SECONDARY
						      : OVPN_KEY_SLOT_PRIMARY;

  /* Transition to REKEYING state */
  peer->state = OVPN_PEER_STATE_REKEYING;

  return 0;
}

/*
 * Complete a rekey - activate new keys
 */
int
ovpn_peer_complete_rekey (vlib_main_t *vm, ovpn_peer_db_t *db,
			  ovpn_peer_t *peer, ovpn_cipher_alg_t cipher_alg)
{
  ovpn_key_material_t keys;
  int rv;
  f64 now = vlib_time_now (vm);
  ovpn_peer_tls_t *tls_ctx = peer->tls_ctx;

  /* Must be in REKEYING state with TLS context */
  if (peer->state != OVPN_PEER_STATE_REKEYING || !tls_ctx)
    return -1;

  /* TLS handshake must be complete */
  if (!ovpn_peer_tls_is_established (peer))
    return -2;

  /* Key Method 2 data must be exchanged */
  if (!tls_ctx->key_method_sent || !tls_ctx->key_method_received)
    return -3;

  /* Derive new keys using Key Method 2 */
  rv = ovpn_derive_data_channel_keys_v2 (
    tls_ctx->tls, tls_ctx->key_src2, peer->remote_session_id.id,
    peer->session_id.id, &keys, cipher_alg, 1 /* is_server */,
    tls_ctx->use_tls_ekm);

  if (rv < 0)
    {
      clib_memset (&keys, 0, sizeof (keys));
      return -4;
    }

  /* Install new keys in the pending slot */
  extern ovpn_main_t ovpn_main;
  rv = ovpn_peer_set_key (vm, db, peer, peer->pending_key_slot, cipher_alg,
			  &keys, peer->rekey_key_id,
			  ovpn_main.options.replay_window);

  /* Securely clear key material */
  clib_memset (&keys, 0, sizeof (keys));

  if (rv < 0)
    return -5;

  /*
   * Old key transitions to "lame duck" state.
   * Keep it active during the transition window to decrypt in-flight packets.
   * The periodic timer will cleanup when expires_at is reached.
   */
  u8 old_slot = peer->current_key_slot;
  ovpn_peer_key_t *old_key = &peer->keys[old_slot];

  /* Set expiration time for old key (lame duck) */
  extern ovpn_main_t ovpn_main;
  f64 transition_window = (f64) ovpn_main.options.transition_window;
  if (transition_window <= 0)
    transition_window = 60.0; /* Default 60 seconds */
  old_key->expires_at = now + transition_window;

  /* Old key remains active until it expires - can still decrypt packets */

  /* Switch to new keys for encryption */
  peer->current_key_slot = peer->pending_key_slot;

  /* Update timestamps */
  peer->last_rekey_time = now;
  if (peer->rekey_interval > 0)
    peer->next_rekey_time = now + peer->rekey_interval;

  /* Reset bytes/packets counters for reneg-bytes/reneg-pkts */
  peer->bytes_since_rekey = 0;
  peer->packets_since_rekey = 0;

  /* Free TLS context */
  ovpn_peer_tls_free (peer);

  /* Return to ESTABLISHED state */
  peer->state = OVPN_PEER_STATE_ESTABLISHED;
  peer->rekey_initiated = 0;

  return 0;
}

/*
 * Associate a peer with an adjacency index
 */
void
ovpn_peer_adj_index_add (u32 peer_id, adj_index_t ai)
{
  vec_validate_init_empty (ovpn_peer_by_adj_index, ai, ~0);
  ovpn_peer_by_adj_index[ai] = peer_id;
}

/*
 * Remove peer-adjacency association
 */
void
ovpn_peer_adj_index_del (adj_index_t ai)
{
  if (ai < vec_len (ovpn_peer_by_adj_index))
    ovpn_peer_by_adj_index[ai] = ~0;
}

/*
 * Stack the peer's adjacency to reach the endpoint
 */
void
ovpn_peer_adj_stack (ovpn_peer_t *peer, adj_index_t ai)
{
  fib_protocol_t fib_proto;
  u32 fib_index;

  if (peer->is_ipv6)
    fib_proto = FIB_PROTOCOL_IP6;
  else
    fib_proto = FIB_PROTOCOL_IP4;

  fib_index = fib_table_find (fib_proto, peer->fib_index);

  if (fib_index != ~0)
    {
      fib_prefix_t dst = {
	.fp_len = peer->is_ipv6 ? 128 : 32,
	.fp_proto = fib_proto,
      };

      if (peer->is_ipv6)
	dst.fp_addr.ip6 = peer->remote_addr.ip.ip6;
      else
	dst.fp_addr.ip4 = peer->remote_addr.ip.ip4;

      adj_midchain_delegate_stack (ai, fib_index, &dst);
    }
}

/*
 * Cleanup expired keys for a peer
 *
 * Removes "lame duck" keys whose transition window has expired.
 * Keys are removed from the bihash and crypto context is freed.
 */
int
ovpn_peer_cleanup_expired_keys (vlib_main_t *vm, ovpn_peer_db_t *db,
				ovpn_peer_t *peer, f64 now)
{
  clib_bihash_kv_8_8_t kv;
  int cleaned = 0;

  for (int i = 0; i < OVPN_KEY_SLOT_COUNT; i++)
    {
      ovpn_peer_key_t *pkey = &peer->keys[i];

      /* Skip inactive keys or keys that haven't expired yet */
      if (!pkey->is_active)
	continue;

      /* Skip the current key slot (always keep it) */
      if (i == peer->current_key_slot)
	continue;

      /* Check if key has expired */
      if (pkey->expires_at > 0 && now >= pkey->expires_at)
	{
	  /* Remove from bihash */
	  kv.key = ovpn_peer_key_hash_key (peer->peer_id, pkey->key_id);
	  clib_bihash_add_del_8_8 (&db->key_hash, &kv, 0 /* is_add */);

	  /* Free crypto context */
	  if (pkey->crypto.is_valid)
	    ovpn_crypto_context_free (&pkey->crypto);

	  /* Mark as inactive */
	  pkey->is_active = 0;
	  pkey->expires_at = 0;

	  cleaned++;
	}
    }

  return cleaned;
}

/*
 * Cleanup expired keys for all peers in database
 */
int
ovpn_peer_db_cleanup_expired_keys (vlib_main_t *vm, ovpn_peer_db_t *db, f64 now)
{
  ovpn_peer_t *peer;
  int total_cleaned = 0;

  pool_foreach (peer, db->peers)
    {
      /* Skip dead peers */
      if (peer->state == OVPN_PEER_STATE_DEAD)
	continue;

      total_cleaned += ovpn_peer_cleanup_expired_keys (vm, db, peer, now);
    }

  return total_cleaned;
}

/*
 * Send ping packet to peer
 * Encrypts the OpenVPN ping magic pattern and sends on data channel
 */
void
ovpn_peer_send_ping (vlib_main_t *vm, ovpn_peer_t *peer)
{
  extern vlib_node_registration_t ip4_lookup_node;
  extern vlib_node_registration_t ip6_lookup_node;
  extern const u8 ovpn_ping_string[OVPN_PING_STRING_SIZE];

  ovpn_crypto_context_t *crypto;
  vlib_buffer_t *b;
  u32 bi;
  int rv;

  /* Must be established with valid crypto */
  if (peer->state != OVPN_PEER_STATE_ESTABLISHED)
    return;

  crypto = ovpn_peer_get_crypto (peer);
  if (!crypto || !crypto->is_valid)
    return;

  /* Allocate buffer */
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return;

  b = vlib_get_buffer (vm, bi);

  /* Leave room for IP + UDP headers */
  u32 hdr_space = peer->is_ipv6 ? sizeof (ip6_header_t) + sizeof (udp_header_t)
				: sizeof (ip4_header_t) + sizeof (udp_header_t);
  b->current_data = hdr_space;
  b->current_length = 0;

  /* Write ping magic pattern as payload */
  u8 *payload = vlib_buffer_put_uninit (b, OVPN_PING_STRING_SIZE);
  clib_memcpy_fast (payload, ovpn_ping_string, OVPN_PING_STRING_SIZE);

  /* Get key_id from current key slot */
  u8 key_id = peer->keys[peer->current_key_slot].key_id;

  /* Encrypt the ping packet (adds DATA_V2 header and tag) */
  rv = ovpn_crypto_encrypt (vm, crypto, b, peer->peer_id, key_id);
  if (rv < 0)
    {
      vlib_buffer_free_one (vm, bi);
      return;
    }

  /* Prepend IP + UDP headers using the peer's rewrite template */
  if (!peer->rewrite || peer->rewrite_len == 0)
    {
      vlib_buffer_free_one (vm, bi);
      return;
    }

  /* Push the rewrite (IP + UDP header) */
  u8 *hdr = vlib_buffer_push_uninit (b, peer->rewrite_len);
  clib_memcpy_fast (hdr, peer->rewrite, peer->rewrite_len);

  /* Fix up lengths in headers */
  u16 total_len = b->current_length;

  if (peer->is_ipv6)
    {
      ip6_header_t *ip6 = (ip6_header_t *) hdr;
      udp_header_t *udp = (udp_header_t *) (ip6 + 1);

      ip6->payload_length =
	clib_host_to_net_u16 (total_len - sizeof (ip6_header_t));
      udp->length = ip6->payload_length;
    }
  else
    {
      ip4_header_t *ip4 = (ip4_header_t *) hdr;
      udp_header_t *udp = (udp_header_t *) (ip4 + 1);

      ip4->length = clib_host_to_net_u16 (total_len);
      udp->length =
	clib_host_to_net_u16 (total_len - sizeof (ip4_header_t));
      ip4->checksum = ip4_header_checksum (ip4);
    }

  /* Set flags for locally originated packet */
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  /* Enqueue to IP lookup */
  vlib_frame_t *f;
  u32 *to_next;

  if (peer->is_ipv6)
    f = vlib_get_frame_to_node (vm, ip6_lookup_node.index);
  else
    f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);

  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;

  if (peer->is_ipv6)
    vlib_put_frame_to_node (vm, ip6_lookup_node.index, f);
  else
    vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);

  /* Update TX timestamp */
  peer->last_tx_time = vlib_time_now (vm);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
