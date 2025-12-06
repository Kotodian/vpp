/*
 * ovpn_handshake.c - OpenVPN control channel handshake
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
#include <ovpn/ovpn_handshake.h>
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_packet.h>
#include <ovpn/ovpn_ssl.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip4_forward.h>
#include <vnet/ip/ip6_forward.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/* Default timeout for pending connections (60 seconds) */
#define OVPN_PENDING_TIMEOUT 60.0

/* Maximum pending connections */
#define OVPN_MAX_PENDING 1024

/* Control packet buffer size */
#define OVPN_CONTROL_BUF_SIZE 2048

/* Forward declarations */
static int ovpn_handshake_send_pending_packets (vlib_main_t *vm,
						ovpn_pending_connection_t *pending,
						u8 is_ip6);

static int ovpn_handshake_send_peer_packets (vlib_main_t *vm,
					     ovpn_peer_t *peer, u8 is_ip6);

/*
 * Initialize pending connection database
 */
void
ovpn_pending_db_init (ovpn_pending_db_t *db)
{
  clib_memset (db, 0, sizeof (*db));
  db->pending_by_remote = hash_create (0, sizeof (uword));
  db->timeout = OVPN_PENDING_TIMEOUT;
}

/*
 * Free pending connection database
 */
void
ovpn_pending_db_free (ovpn_pending_db_t *db)
{
  ovpn_pending_connection_t *pending;

  pool_foreach (pending, db->connections)
    {
      if (pending->send_reliable)
	ovpn_reliable_free (pending->send_reliable);
    }

  pool_free (db->connections);
  hash_free (db->pending_by_remote);
  clib_memset (db, 0, sizeof (*db));
}

/*
 * Create a new pending connection
 */
ovpn_pending_connection_t *
ovpn_pending_connection_create (ovpn_pending_db_t *db,
				const ip_address_t *remote_addr,
				u16 remote_port,
				const ovpn_session_id_t *remote_session_id,
				u8 key_id)
{
  ovpn_pending_connection_t *pending;
  u64 remote_key;
  f64 now = vlib_time_now (vlib_get_main ());

  /* Check if already exists */
  pending = ovpn_pending_connection_lookup (db, remote_addr, remote_port);
  if (pending)
    {
      /* Update existing pending connection */
      pending->last_activity = now;
      ovpn_session_id_copy (&pending->remote_session_id, remote_session_id);
      pending->key_id = key_id;
      pending->state = OVPN_PENDING_STATE_INITIAL;
      return pending;
    }

  /* Check limit */
  if (pool_elts (db->connections) >= OVPN_MAX_PENDING)
    return NULL;

  /* Allocate new pending connection */
  pool_get_zero (db->connections, pending);

  pending->state = OVPN_PENDING_STATE_INITIAL;
  ip_address_copy (&pending->remote_addr, remote_addr);
  pending->remote_port = remote_port;
  ovpn_session_id_copy (&pending->remote_session_id, remote_session_id);
  pending->key_id = key_id;

  /* Generate our session ID */
  ovpn_session_id_generate (&pending->local_session_id);

  /* Initialize packet IDs */
  pending->packet_id_send = 0;
  pending->packet_id_recv = 0;

  /* Initialize ACK structures */
  pending->recv_ack.len = 0;
  pending->sent_ack.len = 0;

  /* Set timestamps */
  pending->created_time = now;
  pending->last_activity = now;
  pending->timeout = now + db->timeout;

  /* Initialize reliable send structure */
  pending->send_reliable = clib_mem_alloc (sizeof (ovpn_reliable_t));
  ovpn_reliable_init (pending->send_reliable, OVPN_CONTROL_BUF_SIZE,
		      128 /* header offset */, 4 /* array_size */,
		      0 /* hold */);
  ovpn_reliable_set_timeout (pending->send_reliable, 2.0);

  /* Add to hash */
  remote_key = ovpn_pending_remote_hash_key (remote_addr, remote_port);
  hash_set (db->pending_by_remote, remote_key, pending - db->connections);

  return pending;
}

/*
 * Find pending connection by remote address
 */
ovpn_pending_connection_t *
ovpn_pending_connection_lookup (ovpn_pending_db_t *db,
				const ip_address_t *remote_addr,
				u16 remote_port)
{
  uword *p;
  u64 key;

  key = ovpn_pending_remote_hash_key (remote_addr, remote_port);
  p = hash_get (db->pending_by_remote, key);
  if (!p)
    return NULL;

  return pool_elt_at_index (db->connections, p[0]);
}

/*
 * Delete pending connection
 */
void
ovpn_pending_connection_delete (ovpn_pending_db_t *db,
				ovpn_pending_connection_t *pending)
{
  u64 remote_key;

  if (!pending)
    return;

  /* Remove from hash */
  remote_key =
    ovpn_pending_remote_hash_key (&pending->remote_addr, pending->remote_port);
  hash_unset (db->pending_by_remote, remote_key);

  /* Free reliable structure */
  if (pending->send_reliable)
    {
      ovpn_reliable_free (pending->send_reliable);
      pending->send_reliable = NULL;
    }

  /* Return to pool */
  pool_put (db->connections, pending);
}

/*
 * Delete expired pending connections
 */
void
ovpn_pending_db_expire (ovpn_pending_db_t *db, f64 now)
{
  ovpn_pending_connection_t *pending;
  u32 *indices_to_delete = NULL;

  pool_foreach (pending, db->connections)
    {
      if (now > pending->timeout)
	{
	  vec_add1 (indices_to_delete, pending - db->connections);
	}
    }

  for (int i = 0; i < vec_len (indices_to_delete); i++)
    {
      pending = pool_elt_at_index (db->connections, indices_to_delete[i]);
      ovpn_pending_connection_delete (db, pending);
    }

  vec_free (indices_to_delete);
}

/*
 * Build control packet header
 * Format: opcode | session_id | ack_array | packet_id | payload
 */
static int
ovpn_build_control_header (ovpn_reli_buffer_t *buf, u8 opcode, u8 key_id,
			   const ovpn_session_id_t *session_id,
			   ovpn_reliable_ack_t *ack,
			   const ovpn_session_id_t *ack_session_id)
{
  u8 op_byte;

  /* Write opcode + key_id */
  op_byte = ovpn_op_compose (opcode, key_id);
  if (!ovpn_buf_write_u8 (buf, op_byte))
    return -1;

  /* Write our session ID */
  if (!ovpn_session_id_write (session_id, buf))
    return -1;

  /* Write ACK array */
  if (ack && ack->len > 0)
    {
      /* Write ACK count */
      if (!ovpn_buf_write_u8 (buf, ack->len))
	return -1;

      /* Write packet IDs */
      for (int i = 0; i < ack->len; i++)
	{
	  u32 net_pid = clib_host_to_net_u32 (ack->packet_id[i]);
	  if (!ovpn_buf_write (buf, &net_pid, sizeof (net_pid)))
	    return -1;
	}

      /* Write remote session ID for ACK */
      if (!ovpn_session_id_write (ack_session_id, buf))
	return -1;
    }
  else
    {
      /* No ACKs */
      if (!ovpn_buf_write_u8 (buf, 0))
	return -1;
    }

  return 0;
}

/*
 * Build and send P_CONTROL_HARD_RESET_SERVER_V2 response
 */
int
ovpn_handshake_send_server_reset (vlib_main_t *vm,
				  ovpn_pending_connection_t *pending,
				  vlib_buffer_t *response_buf)
{
  ovpn_reli_buffer_t *buf;
  u8 opcode = OVPN_OP_CONTROL_HARD_RESET_SERVER_V2;

  /* Get a buffer from reliable layer */
  buf = ovpn_reliable_get_buf_output_sequenced (pending->send_reliable);
  if (!buf)
    return -1;

  /* Build control header with ACK for client's HARD_RESET */
  if (ovpn_build_control_header (buf, opcode, pending->key_id,
				 &pending->local_session_id,
				 &pending->recv_ack,
				 &pending->remote_session_id) < 0)
    return -1;

  /* Mark as active for retransmission */
  ovpn_reliable_mark_active_outgoing (pending->send_reliable, buf, opcode);

  /* Clear the ACKs we just sent */
  pending->recv_ack.len = 0;

  /* Update state */
  pending->state = OVPN_PENDING_STATE_SENT_RESET;

  return 0;
}

/*
 * Parse control packet header
 */
static int
ovpn_parse_control_header (ovpn_reli_buffer_t *buf, u8 *opcode, u8 *key_id,
			   ovpn_session_id_t *session_id,
			   ovpn_reliable_ack_t *ack,
			   ovpn_session_id_t *ack_session_id, u32 *packet_id)
{
  u8 op_byte;
  int n;

  /* Read opcode + key_id */
  n = ovpn_buf_read_u8 (buf);
  if (n < 0)
    return -1;
  op_byte = (u8) n;

  *opcode = ovpn_op_get_opcode (op_byte);
  *key_id = ovpn_op_get_key_id (op_byte);

  /* Read session ID */
  if (!ovpn_session_id_read (session_id, buf))
    return -1;

  /* Parse ACK array */
  if (!ovpn_reliable_ack_parse (buf, ack, ack_session_id))
    return -1;

  /* For non-ACK packets, read packet ID */
  if (*opcode != OVPN_OP_ACK_V1)
    {
      if (!ovpn_reliable_ack_read_packet_id (buf, packet_id))
	return -1;
    }

  return 0;
}

/*
 * HMAC verification for tls-auth
 * For now, just a stub that always returns 1 (valid)
 * TODO: Implement actual HMAC verification when tls-auth is configured
 */
int
ovpn_handshake_verify_hmac (const u8 *data, u32 len,
			    const ovpn_tls_auth_t *auth)
{
  if (!auth || !auth->enabled)
    return 1; /* No tls-auth configured, always valid */

  /* TODO: Implement HMAC-SHA256 verification */
  /* For tls-auth, the HMAC covers the entire control packet */

  return 1;
}

/*
 * Generate HMAC for outgoing control packet
 */
void
ovpn_handshake_generate_hmac (u8 *data, u32 len, u8 *hmac_out,
			      const ovpn_tls_auth_t *auth)
{
  if (!auth || !auth->enabled)
    return;

  /* TODO: Implement HMAC-SHA256 generation */
}

/*
 * Send control packets from pending connection's reliable buffer
 * Allocates vlib_buffer, builds IP/UDP headers, copies payload, sends to IP lookup
 */
static int
ovpn_handshake_send_pending_packets (vlib_main_t *vm,
				     ovpn_pending_connection_t *pending,
				     u8 is_ip6)
{
  ovpn_reli_buffer_t *buf;
  u8 opcode;
  vlib_buffer_t *b;
  u32 bi;
  u32 n_sent = 0;

  /* Schedule packets for immediate sending */
  ovpn_reliable_schedule_now (vm, pending->send_reliable);

  /* Send all packets that are ready */
  while (ovpn_reliable_can_send (vm, pending->send_reliable))
    {
      buf = ovpn_reliable_send (vm, pending->send_reliable, &opcode);
      if (!buf)
	break;

      /* Allocate vlib buffer */
      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	return -1;

      b = vlib_get_buffer (vm, bi);

      /* Calculate required header space */
      u32 ip_hdr_size = is_ip6 ? sizeof (ip6_header_t) : sizeof (ip4_header_t);
      u32 udp_hdr_size = sizeof (udp_header_t);
      u32 total_hdr_size = ip_hdr_size + udp_hdr_size;

      /* Position buffer to leave room for IP/UDP headers */
      vlib_buffer_advance (b, -(i32) total_hdr_size);

      /* Get payload area (after headers) */
      u8 *payload = vlib_buffer_get_current (b) + total_hdr_size;
      u32 payload_len = OVPN_BLEN (buf);

      /* Copy control packet data */
      clib_memcpy_fast (payload, OVPN_BPTR (buf), payload_len);

      /* Build UDP header */
      udp_header_t *udp;
      if (is_ip6)
	{
	  ip6_header_t *ip6 = vlib_buffer_get_current (b);

	  /* Build IPv6 header */
	  clib_memset (ip6, 0, sizeof (*ip6));
	  ip6->ip_version_traffic_class_and_flow_label =
	    clib_host_to_net_u32 (0x60000000);
	  ip6->payload_length =
	    clib_host_to_net_u16 (udp_hdr_size + payload_len);
	  ip6->protocol = IP_PROTOCOL_UDP;
	  ip6->hop_limit = 64;

	  /* Set addresses (swap src/dst from pending connection) */
	  /* Our address is the original destination, client is src */
	  clib_memcpy (&ip6->src_address, &pending->remote_addr.ip.ip6,
		       sizeof (ip6_address_t));
	  /* For now, use remote as both src and dst - will be fixed by routing */

	  udp = (udp_header_t *) (ip6 + 1);
	}
      else
	{
	  ip4_header_t *ip4 = vlib_buffer_get_current (b);

	  /* Build IPv4 header */
	  clib_memset (ip4, 0, sizeof (*ip4));
	  ip4->ip_version_and_header_length = 0x45;
	  ip4->ttl = 64;
	  ip4->protocol = IP_PROTOCOL_UDP;
	  ip4->length =
	    clib_host_to_net_u16 (ip_hdr_size + udp_hdr_size + payload_len);

	  /* Set addresses - swap src/dst */
	  ip4->dst_address.as_u32 = pending->remote_addr.ip.ip4.as_u32;
	  /* src_address will be filled by IP output based on routing */

	  ip4->checksum = ip4_header_checksum (ip4);

	  udp = (udp_header_t *) (ip4 + 1);
	}

      /* Build UDP header */
      udp->dst_port = clib_host_to_net_u16 (pending->remote_port);
      udp->src_port = clib_host_to_net_u16 (1194); /* OpenVPN default port */
      udp->length = clib_host_to_net_u16 (udp_hdr_size + payload_len);
      udp->checksum = 0; /* TODO: compute checksum if needed */

      /* Set buffer length */
      b->current_length = total_hdr_size + payload_len;

      /* Set flags for IP output */
      b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

      /* Enqueue to IP lookup */
      vlib_frame_t *f;
      u32 *to_next;

      if (is_ip6)
	{
	  f = vlib_get_frame_to_node (vm, ip6_lookup_node.index);
	}
      else
	{
	  f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
	}

      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi;
      f->n_vectors = 1;

      if (is_ip6)
	{
	  vlib_put_frame_to_node (vm, ip6_lookup_node.index, f);
	}
      else
	{
	  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
	}

      n_sent++;
    }

  return n_sent;
}

/*
 * Send control packets from peer's TLS reliable buffer
 * Similar to pending packets but uses peer's TLS context
 */
static int
ovpn_handshake_send_peer_packets (vlib_main_t *vm, ovpn_peer_t *peer,
				  u8 is_ip6)
{
  ovpn_peer_tls_t *tls_ctx = peer->tls_ctx;
  ovpn_reli_buffer_t *buf;
  u8 opcode;
  vlib_buffer_t *b;
  u32 bi;
  u32 n_sent = 0;

  if (!tls_ctx || !tls_ctx->send_reliable)
    return 0;

  /* Schedule packets for immediate sending */
  ovpn_reliable_schedule_now (vm, tls_ctx->send_reliable);

  /* Send all packets that are ready */
  while (ovpn_reliable_can_send (vm, tls_ctx->send_reliable))
    {
      buf = ovpn_reliable_send (vm, tls_ctx->send_reliable, &opcode);
      if (!buf)
	break;

      /* Allocate vlib buffer */
      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	return -1;

      b = vlib_get_buffer (vm, bi);

      /* Calculate required header space */
      u32 ip_hdr_size = is_ip6 ? sizeof (ip6_header_t) : sizeof (ip4_header_t);
      u32 udp_hdr_size = sizeof (udp_header_t);
      u32 total_hdr_size = ip_hdr_size + udp_hdr_size;

      /* Build control packet header:
       * opcode | session_id | ack_array | packet_id | payload
       */
      u8 ctrl_hdr[128];
      u32 ctrl_hdr_len = 0;

      /* Opcode + key_id */
      ctrl_hdr[ctrl_hdr_len++] =
	ovpn_op_compose (opcode, tls_ctx->key_id);

      /* Our session ID (8 bytes) */
      clib_memcpy (&ctrl_hdr[ctrl_hdr_len], peer->session_id.id,
		   OVPN_SID_SIZE);
      ctrl_hdr_len += OVPN_SID_SIZE;

      /* ACK array */
      if (tls_ctx->recv_ack.len > 0)
	{
	  ctrl_hdr[ctrl_hdr_len++] = tls_ctx->recv_ack.len;
	  for (u32 i = 0; i < tls_ctx->recv_ack.len; i++)
	    {
	      u32 net_pid =
		clib_host_to_net_u32 (tls_ctx->recv_ack.packet_id[i]);
	      clib_memcpy (&ctrl_hdr[ctrl_hdr_len], &net_pid, sizeof (u32));
	      ctrl_hdr_len += sizeof (u32);
	    }
	  /* Remote session ID for ACK */
	  clib_memcpy (&ctrl_hdr[ctrl_hdr_len], peer->remote_session_id.id,
		       OVPN_SID_SIZE);
	  ctrl_hdr_len += OVPN_SID_SIZE;
	  tls_ctx->recv_ack.len = 0; /* Clear ACKs */
	}
      else
	{
	  ctrl_hdr[ctrl_hdr_len++] = 0; /* No ACKs */
	}

      /* Packet ID (for non-ACK packets) */
      if (opcode != OVPN_OP_ACK_V1)
	{
	  u32 net_pid = clib_host_to_net_u32 (tls_ctx->packet_id_send++);
	  clib_memcpy (&ctrl_hdr[ctrl_hdr_len], &net_pid, sizeof (u32));
	  ctrl_hdr_len += sizeof (u32);
	}

      u32 payload_len = OVPN_BLEN (buf);
      u32 total_ctrl_len = ctrl_hdr_len + payload_len;

      /* Position buffer to leave room for IP/UDP headers */
      vlib_buffer_advance (b, -(i32) total_hdr_size);

      /* Get payload area (after headers) */
      u8 *pkt_data = vlib_buffer_get_current (b) + total_hdr_size;

      /* Copy control header */
      clib_memcpy_fast (pkt_data, ctrl_hdr, ctrl_hdr_len);
      /* Copy TLS payload */
      clib_memcpy_fast (pkt_data + ctrl_hdr_len, OVPN_BPTR (buf), payload_len);

      /* Build UDP header */
      udp_header_t *udp;
      if (is_ip6)
	{
	  ip6_header_t *ip6 = vlib_buffer_get_current (b);

	  clib_memset (ip6, 0, sizeof (*ip6));
	  ip6->ip_version_traffic_class_and_flow_label =
	    clib_host_to_net_u32 (0x60000000);
	  ip6->payload_length =
	    clib_host_to_net_u16 (udp_hdr_size + total_ctrl_len);
	  ip6->protocol = IP_PROTOCOL_UDP;
	  ip6->hop_limit = 64;

	  clib_memcpy (&ip6->dst_address, &peer->remote_addr.ip.ip6,
		       sizeof (ip6_address_t));

	  udp = (udp_header_t *) (ip6 + 1);
	}
      else
	{
	  ip4_header_t *ip4 = vlib_buffer_get_current (b);

	  clib_memset (ip4, 0, sizeof (*ip4));
	  ip4->ip_version_and_header_length = 0x45;
	  ip4->ttl = 64;
	  ip4->protocol = IP_PROTOCOL_UDP;
	  ip4->length = clib_host_to_net_u16 (ip_hdr_size + udp_hdr_size +
					      total_ctrl_len);

	  ip4->dst_address.as_u32 = peer->remote_addr.ip.ip4.as_u32;

	  ip4->checksum = ip4_header_checksum (ip4);

	  udp = (udp_header_t *) (ip4 + 1);
	}

      udp->dst_port = clib_host_to_net_u16 (peer->remote_port);
      udp->src_port = clib_host_to_net_u16 (1194);
      udp->length = clib_host_to_net_u16 (udp_hdr_size + total_ctrl_len);
      udp->checksum = 0;

      b->current_length = total_hdr_size + total_ctrl_len;
      b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

      /* Enqueue to IP lookup */
      vlib_frame_t *f;
      u32 *to_next;

      if (is_ip6)
	{
	  f = vlib_get_frame_to_node (vm, ip6_lookup_node.index);
	}
      else
	{
	  f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
	}

      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi;
      f->n_vectors = 1;

      if (is_ip6)
	{
	  vlib_put_frame_to_node (vm, ip6_lookup_node.index, f);
	}
      else
	{
	  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
	}

      n_sent++;
    }

  return n_sent;
}

/*
 * Process incoming control packet
 */
int
ovpn_handshake_process_packet (vlib_main_t *vm, vlib_buffer_t *b,
			       const ip_address_t *src_addr, u16 src_port,
			       const ip_address_t *dst_addr, u16 dst_port,
			       u8 is_ip6)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_pending_db_t *pending_db = &omp->multi_context.pending_db;
  ovpn_peer_db_t *peer_db = &omp->multi_context.peer_db;
  ovpn_pending_connection_t *pending;
  ovpn_peer_t *peer;
  ovpn_reli_buffer_t buf;
  u8 opcode, key_id;
  ovpn_session_id_t session_id, ack_session_id;
  ovpn_reliable_ack_t ack;
  u32 packet_id = 0;
  u8 *data;
  u32 len;
  int rv = 0;

  data = vlib_buffer_get_current (b);
  len = b->current_length;

  /* Set up buffer for parsing */
  ovpn_buf_set_read (&buf, data, 0);
  buf.len = len;
  buf.offset = 0;

  /* Parse control packet header */
  if (ovpn_parse_control_header (&buf, &opcode, &key_id, &session_id, &ack,
				 &ack_session_id, &packet_id) < 0)
    {
      return -1;
    }

  /* Check if we have an existing peer for this address */
  peer = ovpn_peer_lookup_by_remote (peer_db, src_addr, src_port);

  /* No established peer - check pending connections */
  pending = ovpn_pending_connection_lookup (pending_db, src_addr, src_port);

  /* Handle based on opcode */
  switch (opcode)
    {
    case OVPN_OP_CONTROL_HARD_RESET_CLIENT_V1:
    case OVPN_OP_CONTROL_HARD_RESET_CLIENT_V2:
    case OVPN_OP_CONTROL_HARD_RESET_CLIENT_V3:
      {
	/*
	 * Client is initiating connection
	 * 1. Verify HMAC if tls-auth is configured
	 * 2. Create/update pending connection
	 * 3. Send P_CONTROL_HARD_RESET_SERVER_V2 with ACK
	 */

	/* Verify HMAC (returns 1 if valid or if tls-auth not configured) */
	if (!ovpn_handshake_verify_hmac (data, len, NULL))
	  {
	    /* HMAC verification failed */
	    return -2;
	  }

	/* Create or update pending connection */
	pending = ovpn_pending_connection_create (pending_db, src_addr,
						  src_port, &session_id,
						  key_id);
	if (!pending)
	  {
	    return -3;
	  }

	/* Record the packet ID we need to ACK */
	ovpn_reliable_ack_acknowledge_packet_id (&pending->recv_ack,
						 packet_id);

	/* Build server reset response in reliable buffer */
	rv = ovpn_handshake_send_server_reset (vm, pending, NULL);
	if (rv < 0)
	  {
	    ovpn_pending_connection_delete (pending_db, pending);
	    return rv;
	  }

	/* Actually send the packet out */
	rv = ovpn_handshake_send_pending_packets (vm, pending, is_ip6);
	if (rv < 0)
	  {
	    ovpn_pending_connection_delete (pending_db, pending);
	    return rv;
	  }

	pending->last_activity = vlib_time_now (vm);
	break;
      }

    case OVPN_OP_CONTROL_SOFT_RESET_V1:
      {
	/*
	 * Client is requesting a rekey
	 * Only valid for established peers
	 */
	if (!peer)
	  {
	    /* No established peer for soft reset */
	    return -20;
	  }

	if (peer->state != OVPN_PEER_STATE_ESTABLISHED)
	  {
	    /* Peer not in correct state for rekey */
	    return -21;
	  }

	/* Start rekey process */
	rv = ovpn_peer_start_rekey (vm, peer, omp->ptls_ctx, key_id);
	if (rv < 0)
	  {
	    return -22;
	  }

	/* Record that client initiated the rekey */
	peer->rekey_initiated = 0; /* We're responding to client's rekey */

	/* Record packet ID for ACK */
	ovpn_reliable_ack_acknowledge_packet_id (&peer->tls_ctx->recv_ack,
						 packet_id);

	/* Send SOFT_RESET response with ACK */
	{
	  ovpn_reli_buffer_t *buf;
	  buf = ovpn_reliable_get_buf_output_sequenced (
	    peer->tls_ctx->send_reliable);
	  if (buf)
	    {
	      ovpn_buf_init (buf, 128);
	      ovpn_reliable_mark_active_outgoing (peer->tls_ctx->send_reliable,
						  buf,
						  OVPN_OP_CONTROL_SOFT_RESET_V1);
	    }
	}

	/* Send response */
	ovpn_handshake_send_peer_packets (vm, peer, is_ip6);

	rv = 1;
	break;
      }

    case OVPN_OP_ACK_V1:
      {
	/*
	 * Handle ACKs for:
	 * 1. Pending connections (acknowledging our HARD_RESET_SERVER)
	 * 2. Peers in TLS handshake (acknowledging our TLS packets)
	 */

	/* First check if this is an ACK for a peer in TLS handshake */
	if (peer && peer->tls_ctx && peer->tls_ctx->send_reliable)
	  {
	    /* Verify ACK is for our session */
	    if (ovpn_session_id_equal (&ack_session_id, &peer->session_id))
	      {
		/* Process ACKs - remove acknowledged packets */
		ovpn_reliable_send_purge (peer->tls_ctx->send_reliable, &ack);
		rv = 0;
	      }
	    break;
	  }

	if (!pending)
	  {
	    /* No pending connection or peer for this ACK */
	    return -4;
	  }

	if (pending->state != OVPN_PENDING_STATE_SENT_RESET)
	  {
	    /* Not expecting ACK in this state */
	    return -5;
	  }

	/* Verify ACK is for our session */
	if (!ovpn_session_id_equal (&ack_session_id,
				    &pending->local_session_id))
	  {
	    return -6;
	  }

	/* Process ACKs - remove acknowledged packets from send_reliable */
	ovpn_reliable_send_purge (pending->send_reliable, &ack);

	/* Check if our HARD_RESET_SERVER was acknowledged */
	if (ovpn_reliable_empty (pending->send_reliable))
	  {
	    /*
	     * All our packets were ACKed - connection established!
	     * Now create the real peer and start TLS handshake
	     */
	    u32 peer_id;

	    pending->state = OVPN_PENDING_STATE_ESTABLISHED;

	    /* Create the real peer */
	    peer_id = ovpn_peer_create (peer_db, src_addr, src_port);
	    if (peer_id == ~0)
	      {
		ovpn_pending_connection_delete (pending_db, pending);
		return -7;
	      }

	    peer = ovpn_peer_get (peer_db, peer_id);
	    if (!peer)
	      {
		ovpn_pending_connection_delete (pending_db, pending);
		return -8;
	      }

	    /* Copy session IDs to peer */
	    ovpn_session_id_copy (&peer->session_id,
				  &pending->local_session_id);
	    ovpn_session_id_copy (&peer->remote_session_id,
				  &pending->remote_session_id);

	    /* Set peer state to handshake */
	    peer->state = OVPN_PEER_STATE_HANDSHAKE;

	    /* Initialize TLS context for this peer */
	    if (omp->ptls_ctx)
	      {
		int tls_rv =
		  ovpn_peer_tls_init (peer, omp->ptls_ctx, pending->key_id);
		if (tls_rv < 0)
		  {
		    ovpn_peer_delete (peer_db, peer_id);
		    ovpn_pending_connection_delete (pending_db, pending);
		    return -9;
		  }
	      }

	    /* Clean up pending connection */
	    ovpn_pending_connection_delete (pending_db, pending);

	    rv = 1; /* Success - peer created */
	  }
	break;
      }

    case OVPN_OP_CONTROL_V1:
      {
	/*
	 * TLS handshake data
	 * This packet contains TLS records for the handshake or rekey
	 */
	u8 *tls_data;
	u32 tls_len;

	/* Check if we have a peer with active TLS context */
	if (peer && peer->tls_ctx)
	  {
	    /* Get the TLS payload (after control header) */
	    tls_data = OVPN_BPTR (&buf);
	    tls_len = OVPN_BLEN (&buf);

	    /* Record packet ID for ACK */
	    ovpn_reliable_ack_acknowledge_packet_id (&peer->tls_ctx->recv_ack,
						     packet_id);

	    /* Process TLS data */
	    rv = ovpn_peer_tls_process (peer, tls_data, tls_len);

	    /* Send response if TLS produced data */
	    if (rv > 0)
	      {
		ovpn_handshake_send_peer_packets (vm, peer, is_ip6);
	      }

	    /* Check if TLS handshake completed */
	    if (ovpn_peer_tls_is_established (peer))
	      {
		/*
		 * TLS handshake complete!
		 * Handle based on current state (initial or rekey)
		 */
		if (peer->state == OVPN_PEER_STATE_REKEYING)
		  {
		    /*
		     * Rekey TLS handshake complete
		     * Install new keys and return to ESTABLISHED
		     */
		    int key_rv;

		    key_rv = ovpn_peer_complete_rekey (vm, peer, omp->cipher_alg);
		    if (key_rv == 0)
		      {
			rv = 3; /* Rekey complete */
		      }
		    else
		      {
			/* Rekey failed - peer stays in REKEYING state */
			/* Could try again or transition to error state */
			peer->state = OVPN_PEER_STATE_ESTABLISHED;
			ovpn_peer_tls_free (peer);
			rv = -13;
		      }
		  }
		else
		  {
		    /*
		     * Initial TLS handshake complete
		     * Derive data channel keys and transition to ESTABLISHED
		     */
		    ovpn_key_material_t keys;
		    int key_rv;

		    /* Derive keys from TLS session */
		    key_rv = ovpn_derive_data_channel_keys (
		      peer->tls_ctx->tls, &keys, omp->cipher_alg,
		      1 /* is_server */);

		    if (key_rv == 0)
		      {
			/* Set up crypto context for this peer */
			key_rv =
			  ovpn_peer_set_key (vm, peer, OVPN_KEY_SLOT_PRIMARY,
					    omp->cipher_alg, &keys,
					    peer->tls_ctx->key_id);
		      }

		    if (key_rv == 0)
		      {
			f64 now = vlib_time_now (vm);

			peer->state = OVPN_PEER_STATE_ESTABLISHED;
			peer->established_time = now;
			peer->current_key_slot = OVPN_KEY_SLOT_PRIMARY;

			/* Set up rekey timer from options */
			if (omp->options.renegotiate_seconds > 0)
			  {
			    peer->rekey_interval =
			      (f64) omp->options.renegotiate_seconds;
			    peer->next_rekey_time = now + peer->rekey_interval;
			  }

			/* Build rewrite for output path (IP/UDP headers) */
			ovpn_peer_build_rewrite (peer, dst_addr, dst_port);

			/* Free TLS context - no longer needed */
			ovpn_peer_tls_free (peer);

			rv = 2; /* Handshake complete */
		      }
		    else
		      {
			/* Key derivation failed */
			peer->state = OVPN_PEER_STATE_DEAD;
			rv = -12;
		      }

		    /* Securely clear key material */
		    clib_memset (&keys, 0, sizeof (keys));
		  }
	      }

	    break;
	  }

	/* If peer exists but no TLS context, peer is already established */
	if (peer && peer->state == OVPN_PEER_STATE_ESTABLISHED)
	  {
	    /*
	     * Client sent P_CONTROL_V1 but no rekey in progress
	     * This could be a late packet or client initiating rekey
	     * without SOFT_RESET - start rekey if we have valid key_id
	     */
	    break;
	  }

	/* Check pending connection */
	if (!pending)
	  {
	    return -10;
	  }

	/* For pending connections, we shouldn't receive CONTROL_V1 yet */
	return -11;
      }

    default:
      /* Unknown or unsupported opcode for handshake */
      return -10;
    }

  return rv;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
