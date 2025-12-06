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

#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_ssl.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <picotls/openssl.h>

/* Control channel buffer sizes */
#define OVPN_TLS_BUF_SIZE     4096
#define OVPN_TLS_RELIABLE_CAP 8

void
ovpn_peer_db_init (ovpn_peer_db_t *db, u32 sw_if_index)
{
  clib_memset (db, 0, sizeof (*db));
  db->sw_if_index = sw_if_index;
  db->peer_index_by_remote = hash_create (0, sizeof (uword));
  db->peer_index_by_virtual_ip = hash_create (0, sizeof (uword));
  db->next_peer_id = 1; /* Start from 1, 0 is reserved */
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
  hash_free (db->peer_index_by_remote);
  hash_free (db->peer_index_by_virtual_ip);
  clib_memset (db, 0, sizeof (*db));
}

u32
ovpn_peer_create (ovpn_peer_db_t *db, const ip_address_t *remote_addr,
		  u16 remote_port)
{
  ovpn_peer_t *peer;
  u32 peer_id;
  u64 remote_key;

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

  /* Set remote address */
  ip_address_copy (&peer->remote_addr, remote_addr);
  peer->remote_port = remote_port;
  peer->is_ipv6 = (remote_addr->version == AF_IP6);

  /* Generate session ID */
  ovpn_session_id_generate (&peer->session_id);

  /* Initialize timestamps */
  peer->last_rx_time = vlib_time_now (vlib_get_main ());
  peer->last_tx_time = peer->last_rx_time;

  /* Initialize adjacency index */
  peer->adj_index = ADJ_INDEX_INVALID;

  /* Thread index unassigned - will be set on first packet */
  peer->input_thread_index = ~0;

  /* Add to remote address hash */
  remote_key = ovpn_peer_remote_hash_key (remote_addr, remote_port);
  hash_set (db->peer_index_by_remote, remote_key, peer_id);

  return peer_id;
}

void
ovpn_peer_delete (ovpn_peer_db_t *db, u32 peer_id)
{
  ovpn_peer_t *peer;
  u64 remote_key;

  peer = ovpn_peer_get (db, peer_id);
  if (!peer)
    return;

  /* Remove from remote hash */
  remote_key =
    ovpn_peer_remote_hash_key (&peer->remote_addr, peer->remote_port);
  hash_unset (db->peer_index_by_remote, remote_key);

  /* Remove from virtual IP hash if set */
  if (peer->virtual_ip_set)
    {
      u64 vip_key = ovpn_peer_remote_hash_key (&peer->virtual_ip, 0);
      hash_unset (db->peer_index_by_virtual_ip, vip_key);
    }

  /* Free crypto contexts */
  for (int i = 0; i < OVPN_KEY_SLOT_COUNT; i++)
    {
      if (peer->keys[i].crypto.is_valid)
	ovpn_crypto_context_free (&peer->keys[i].crypto);
    }

  /* Free rewrite */
  vec_free (peer->rewrite);

  /* Release adjacency */
  if (peer->adj_index != ADJ_INDEX_INVALID)
    adj_unlock (peer->adj_index);

  /* Return to pool */
  pool_put (db->peers, peer);
}

ovpn_peer_t *
ovpn_peer_lookup_by_remote (ovpn_peer_db_t *db, const ip_address_t *addr,
			    u16 port)
{
  uword *p;
  u64 key;

  key = ovpn_peer_remote_hash_key (addr, port);
  p = hash_get (db->peer_index_by_remote, key);
  if (!p)
    return NULL;

  return pool_elt_at_index (db->peers, p[0]);
}

ovpn_peer_t *
ovpn_peer_lookup_by_virtual_ip (ovpn_peer_db_t *db, const ip_address_t *addr)
{
  uword *p;
  u64 key;

  key = ovpn_peer_remote_hash_key (addr, 0);
  p = hash_get (db->peer_index_by_virtual_ip, key);
  if (!p)
    return NULL;

  return pool_elt_at_index (db->peers, p[0]);
}

int
ovpn_peer_set_key (vlib_main_t *vm, ovpn_peer_t *peer, u8 key_slot,
		   ovpn_cipher_alg_t cipher_alg,
		   const ovpn_key_material_t *keys, u8 key_id)
{
  ovpn_peer_key_t *pkey;
  int rv;

  if (key_slot >= OVPN_KEY_SLOT_COUNT)
    return -1;

  pkey = &peer->keys[key_slot];

  /* Free existing key if any */
  if (pkey->crypto.is_valid)
    ovpn_crypto_context_free (&pkey->crypto);

  /* Initialize new key */
  rv = ovpn_crypto_context_init (&pkey->crypto, cipher_alg, keys);
  if (rv < 0)
    return rv;

  pkey->key_id = key_id;
  pkey->is_active = 1;
  pkey->created_at = vlib_time_now (vm);
  pkey->expires_at = 0; /* Set by caller based on config */

  return 0;
}

ovpn_crypto_context_t *
ovpn_peer_get_crypto_by_key_id (ovpn_peer_t *peer, u8 key_id)
{
  for (int i = 0; i < OVPN_KEY_SLOT_COUNT; i++)
    {
      if (peer->keys[i].is_active && peer->keys[i].key_id == key_id)
	return &peer->keys[i].crypto;
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

  tls_ctx->state = OVPN_TLS_STATE_HANDSHAKE;
  peer->tls_ctx = tls_ctx;

  return 0;

error:
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

  /* Feed data to TLS */
  size_t consumed = len;
  ret = ptls_handshake (tls_ctx->tls, &sendbuf, data, &consumed, NULL);

  if (ret == 0)
    {
      /* Handshake complete */
      tls_ctx->state = OVPN_TLS_STATE_ESTABLISHED;
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
ovpn_peer_complete_rekey (vlib_main_t *vm, ovpn_peer_t *peer,
			  ovpn_cipher_alg_t cipher_alg)
{
  ovpn_key_material_t keys;
  int rv;
  f64 now = vlib_time_now (vm);

  /* Must be in REKEYING state with TLS context */
  if (peer->state != OVPN_PEER_STATE_REKEYING || !peer->tls_ctx)
    return -1;

  /* TLS handshake must be complete */
  if (!ovpn_peer_tls_is_established (peer))
    return -2;

  /* Derive new keys from TLS session */
  rv = ovpn_derive_data_channel_keys (peer->tls_ctx->tls, &keys, cipher_alg,
				      1 /* is_server */);
  if (rv < 0)
    {
      clib_memset (&keys, 0, sizeof (keys));
      return -3;
    }

  /* Install new keys in the pending slot */
  rv = ovpn_peer_set_key (vm, peer, peer->pending_key_slot, cipher_alg, &keys,
			  peer->rekey_key_id);

  /* Securely clear key material */
  clib_memset (&keys, 0, sizeof (keys));

  if (rv < 0)
    return -4;

  /* Free old key in the slot we're about to switch from */
  u8 old_slot = peer->current_key_slot;

  /* Switch to new keys */
  peer->current_key_slot = peer->pending_key_slot;

  /* Mark old keys as inactive (but keep them for a grace period) */
  peer->keys[old_slot].is_active = 0;

  /* Update timestamps */
  peer->last_rekey_time = now;
  if (peer->rekey_interval > 0)
    peer->next_rekey_time = now + peer->rekey_interval;

  /* Free TLS context */
  ovpn_peer_tls_free (peer);

  /* Return to ESTABLISHED state */
  peer->state = OVPN_PEER_STATE_ESTABLISHED;
  peer->rekey_initiated = 0;

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
