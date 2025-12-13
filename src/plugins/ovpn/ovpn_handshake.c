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
#include <ovpn/ovpn_options.h>
#include <ovpn/ovpn_crypto.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip4_forward.h>
#include <vnet/ip/ip6_forward.h>
#include <arpa/inet.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

/* Default timeout for pending connections (60 seconds) */
#define OVPN_PENDING_TIMEOUT 60.0

/* Maximum pending connections */
#define OVPN_MAX_PENDING 1024

/* Control packet buffer size */
#define OVPN_CONTROL_BUF_SIZE 2048

/* Forward declarations */
static int ovpn_handshake_send_pending_packets (vlib_main_t *vm,
						ovpn_pending_connection_t *pending,
						const ip_address_t *local_addr,
						u16 local_port, u8 is_ip6,
						const ovpn_tls_auth_t *auth,
						ovpn_tls_crypt_t *tls_crypt);

static int ovpn_handshake_send_peer_packets (vlib_main_t *vm,
					     ovpn_peer_t *peer,
					     const ip_address_t *local_addr,
					     u16 local_port, u8 is_ip6,
					     const ovpn_tls_auth_t *auth,
					     ovpn_tls_crypt_t *tls_crypt);

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
	{
	  ovpn_reliable_free (pending->send_reliable);
	  clib_mem_free (pending->send_reliable);
	}
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
      clib_mem_free (pending->send_reliable);
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
 * Helper function to compute HMAC-SHA256 using EVP_MAC API (OpenSSL 3.0+)
 */
static int
ovpn_hmac_sha256 (const u8 *key, u32 key_len, const u8 *data, u32 data_len,
		  u8 *out, size_t *out_len)
{
  EVP_MAC *mac = NULL;
  EVP_MAC_CTX *ctx = NULL;
  OSSL_PARAM params[2];
  int ok = 0;

  mac = EVP_MAC_fetch (NULL, "HMAC", NULL);
  if (!mac)
    return 0;

  ctx = EVP_MAC_CTX_new (mac);
  if (!ctx)
    {
      EVP_MAC_free (mac);
      return 0;
    }

  params[0] = OSSL_PARAM_construct_utf8_string (OSSL_MAC_PARAM_DIGEST,
						(char *) "SHA256", 0);
  params[1] = OSSL_PARAM_construct_end ();

  if (!EVP_MAC_init (ctx, key, key_len, params))
    goto done;
  if (!EVP_MAC_update (ctx, data, data_len))
    goto done;
  if (!EVP_MAC_final (ctx, out, out_len, OVPN_HMAC_SIZE))
    goto done;

  ok = (*out_len == OVPN_HMAC_SIZE);

done:
  EVP_MAC_CTX_free (ctx);
  EVP_MAC_free (mac);
  return ok;
}

/*
 * TLS-Auth unwrap: verify HMAC and check replay protection
 *
 * TLS-Auth packet format (after opcode byte):
 *   [HMAC (32)] [packet_id (4)] [net_time (4)] [session_id...payload]
 *
 * The HMAC covers: packet_id || net_time || session_id...payload
 */
int
ovpn_tls_auth_unwrap (ovpn_tls_auth_t *ctx, const u8 *wrapped, u32 wrapped_len,
		      u8 *plaintext, u32 plaintext_buf_len)
{
  u8 computed_hmac[OVPN_HMAC_SIZE];
  size_t hmac_len = 0;
  u32 packet_id;
  u32 plain_len;

  if (!ctx || !ctx->enabled || !wrapped || !plaintext)
    return -1;

  /* Check minimum size: HMAC + packet_id + net_time */
  if (wrapped_len < OVPN_TLS_AUTH_OVERHEAD)
    return -2;

  plain_len = wrapped_len - OVPN_TLS_AUTH_OVERHEAD;
  if (plaintext_buf_len < plain_len)
    return -2;

  /* Parse header */
  const ovpn_tls_auth_header_t *hdr = (const ovpn_tls_auth_header_t *) wrapped;
  packet_id = clib_net_to_host_u32 (hdr->packet_id);

  /* Check replay BEFORE HMAC verification (optimization) */
  if (!ovpn_tls_auth_check_replay (ctx, packet_id))
    return -4; /* Replay detected */

  /*
   * Compute HMAC over: packet_id || net_time || session_id...payload
   * (everything after the HMAC field)
   */
  const u8 *hmac_data = wrapped + OVPN_HMAC_SIZE;
  u32 hmac_data_len = wrapped_len - OVPN_HMAC_SIZE;

  if (!ovpn_hmac_sha256 (ctx->key, ctx->key_len, hmac_data, hmac_data_len,
			 computed_hmac, &hmac_len))
    return -3;

  /* Verify HMAC using constant-time comparison */
  if (CRYPTO_memcmp (hdr->hmac, computed_hmac, OVPN_HMAC_SIZE) != 0)
    return -3; /* HMAC verification failed */

  /* Update replay window AFTER successful verification */
  ovpn_tls_auth_update_replay (ctx, packet_id);

  /* Copy plaintext (session_id...payload) after stripping header */
  const u8 *payload = wrapped + OVPN_TLS_AUTH_OVERHEAD;
  clib_memcpy_fast (plaintext, payload, plain_len);

  return plain_len;
}

/*
 * TLS-Auth wrap: add HMAC and packet_id/net_time for outgoing packets
 */
int
ovpn_tls_auth_wrap (ovpn_tls_auth_t *ctx, const u8 *plaintext, u32 plain_len,
		    u8 *wrapped, u32 wrapped_buf_len)
{
  u32 wrapped_len;
  size_t hmac_len = 0;

  if (!ctx || !ctx->enabled || !plaintext || !wrapped)
    return -1;

  wrapped_len = plain_len + OVPN_TLS_AUTH_OVERHEAD;
  if (wrapped_buf_len < wrapped_len)
    return -2;

  ovpn_tls_auth_header_t *hdr = (ovpn_tls_auth_header_t *) wrapped;

  /* Get next packet ID */
  u32 packet_id = ctx->packet_id_send++;
  u32 net_time = (u32) unix_time_now ();

  hdr->packet_id = clib_host_to_net_u32 (packet_id);
  hdr->net_time = clib_host_to_net_u32 (net_time);

  /* Copy plaintext after header */
  clib_memcpy_fast (wrapped + OVPN_TLS_AUTH_OVERHEAD, plaintext, plain_len);

  /*
   * Compute HMAC over: packet_id || net_time || plaintext
   */
  const u8 *hmac_data = wrapped + OVPN_HMAC_SIZE;
  u32 hmac_data_len = wrapped_len - OVPN_HMAC_SIZE;

  if (!ovpn_hmac_sha256 (ctx->key, ctx->key_len, hmac_data, hmac_data_len,
			 hdr->hmac, &hmac_len))
    return -3;

  return wrapped_len;
}

/*
 * Legacy HMAC verification for tls-auth (simple, no replay protection)
 * @deprecated Use ovpn_tls_auth_unwrap instead
 */
int
ovpn_handshake_verify_hmac (const u8 *data, u32 len,
			    const ovpn_tls_auth_t *auth)
{
  if (!auth || !auth->enabled)
    return 1; /* No tls-auth configured, always valid */

  if (len < OVPN_HMAC_SIZE)
    return 0;

  u32 signed_len = len - OVPN_HMAC_SIZE;
  u8 digest[OVPN_HMAC_SIZE];
  size_t digest_len = 0;

  if (!ovpn_hmac_sha256 (auth->key, auth->key_len, data, signed_len, digest,
			 &digest_len))
    return 0;

  if (digest_len < OVPN_HMAC_SIZE)
    return 0;

  /* Compare with trailing HMAC using constant-time comparison */
  return CRYPTO_memcmp (digest, data + signed_len, OVPN_HMAC_SIZE) == 0;
}

/*
 * Generate HMAC for outgoing control packet
 * @deprecated Use ovpn_tls_auth_wrap instead
 */
void
ovpn_handshake_generate_hmac (u8 *data, u32 len, u8 *hmac_out,
			      const ovpn_tls_auth_t *auth)
{
  if (!auth || !auth->enabled)
    return;

  size_t digest_len = 0;
  ovpn_hmac_sha256 (auth->key, auth->key_len, data, len, hmac_out, &digest_len);
}

/*
 * TLS-Crypt implementation
 *
 * TLS-Crypt uses a 2048-bit (256 byte) pre-shared key that contains:
 *   Bytes   0- 63: Direction 1 HMAC key (we use first 32 bytes for SHA256)
 *   Bytes  64-127: Direction 2 HMAC key
 *   Bytes 128-191: Direction 1 Cipher key (we use first 32 bytes for AES-256)
 *   Bytes 192-255: Direction 2 Cipher key
 *
 * Note: OpenVPN static key files contain 16 lines of 16 hex bytes each = 256
 * bytes
 */

/*
 * Parse a hex string into binary
 * Returns number of bytes parsed, or -1 on error
 */
static int
ovpn_parse_hex_line (const char *hex, u8 *out, int max_len)
{
  int i = 0;
  while (*hex && i < max_len)
    {
      /* Skip whitespace */
      while (*hex == ' ' || *hex == '\t' || *hex == '\r' || *hex == '\n')
	hex++;

      if (*hex == '\0' || *hex == '-')
	break;

      /* Parse two hex digits */
      u8 val = 0;
      for (int j = 0; j < 2; j++)
	{
	  char c = *hex++;
	  if (c >= '0' && c <= '9')
	    val = (val << 4) | (c - '0');
	  else if (c >= 'a' && c <= 'f')
	    val = (val << 4) | (c - 'a' + 10);
	  else if (c >= 'A' && c <= 'F')
	    val = (val << 4) | (c - 'A' + 10);
	  else if (c == '\0' || c == '\n' || c == '\r')
	    {
	      hex--; /* Back up, we're at end of line */
	      break;
	    }
	  else
	    return -1; /* Invalid hex character */
	}
      out[i++] = val;
    }
  return i;
}

/*
 * Parse TLS-Crypt key from raw key data
 * Supports both PEM format (with -----BEGIN/END----- markers) and raw binary
 */
int
ovpn_tls_crypt_parse_key (const u8 *key_data, u32 key_len,
			  ovpn_tls_crypt_t *ctx, u8 is_server)
{
  u8 raw_key[OVPN_TLS_CRYPT_KEY_SIZE];
  u32 raw_key_len = 0;

  if (!key_data || !ctx || key_len == 0)
    return -1;

  clib_memset (ctx, 0, sizeof (*ctx));

  /* Check if this is a PEM-formatted key file */
  const char *begin_marker = "-----BEGIN OpenVPN Static key V1-----";
  const char *end_marker = "-----END OpenVPN Static key V1-----";

  const char *begin = strstr ((const char *) key_data, begin_marker);
  const char *end = strstr ((const char *) key_data, end_marker);

  if (begin && end && end > begin)
    {
      /* PEM format - parse hex lines between markers */
      const char *ptr = begin + strlen (begin_marker);

      while (ptr < end && raw_key_len < OVPN_TLS_CRYPT_KEY_SIZE)
	{
	  /* Skip to next line */
	  while (ptr < end && (*ptr == '\n' || *ptr == '\r'))
	    ptr++;

	  if (ptr >= end)
	    break;

	  /* Skip comment lines and empty lines */
	  if (*ptr == '#' || *ptr == '\n' || *ptr == '\r')
	    {
	      while (ptr < end && *ptr != '\n')
		ptr++;
	      continue;
	    }

	  /* Parse hex line (16 bytes per line typically) */
	  int parsed =
	    ovpn_parse_hex_line (ptr, raw_key + raw_key_len,
				 OVPN_TLS_CRYPT_KEY_SIZE - raw_key_len);
	  if (parsed > 0)
	    raw_key_len += parsed;

	  /* Move to next line */
	  while (ptr < end && *ptr != '\n')
	    ptr++;
	}
    }
  else if (key_len >= OVPN_TLS_CRYPT_KEY_SIZE)
    {
      /* Raw binary format */
      clib_memcpy_fast (raw_key, key_data, OVPN_TLS_CRYPT_KEY_SIZE);
      raw_key_len = OVPN_TLS_CRYPT_KEY_SIZE;
    }
  else
    {
      return -2; /* Invalid key format or too short */
    }

  if (raw_key_len < OVPN_TLS_CRYPT_KEY_SIZE)
    {
      return -3; /* Key too short */
    }

  /*
   * Key layout (256 bytes total = 2048 bits):
   *   0- 63: Direction 1 HMAC key (64 bytes, but we use first 32 for SHA256)
   *  64-127: Direction 2 HMAC key
   * 128-191: Direction 1 Cipher key (64 bytes, but we use first 32 for AES-256)
   * 192-255: Direction 2 Cipher key
   *
   * For server mode:
   *   - Encrypt (server->client): use direction 1 keys
   *   - Decrypt (client->server): use direction 2 keys
   *
   * For client mode:
   *   - Encrypt (client->server): use direction 2 keys
   *   - Decrypt (server->client): use direction 1 keys
   */
  if (is_server)
    {
      /* Server: encrypt with dir1, decrypt with dir2 */
      clib_memcpy_fast (ctx->encrypt_hmac_key, raw_key,
			OVPN_TLS_CRYPT_HMAC_SIZE);
      clib_memcpy_fast (ctx->decrypt_hmac_key, raw_key + 64,
			OVPN_TLS_CRYPT_HMAC_SIZE);
      clib_memcpy_fast (ctx->encrypt_cipher_key, raw_key + 128,
			OVPN_TLS_CRYPT_CIPHER_SIZE);
      clib_memcpy_fast (ctx->decrypt_cipher_key, raw_key + 192,
			OVPN_TLS_CRYPT_CIPHER_SIZE);
    }
  else
    {
      /* Client: encrypt with dir2, decrypt with dir1 */
      clib_memcpy_fast (ctx->encrypt_hmac_key, raw_key + 64,
			OVPN_TLS_CRYPT_HMAC_SIZE);
      clib_memcpy_fast (ctx->decrypt_hmac_key, raw_key,
			OVPN_TLS_CRYPT_HMAC_SIZE);
      clib_memcpy_fast (ctx->encrypt_cipher_key, raw_key + 192,
			OVPN_TLS_CRYPT_CIPHER_SIZE);
      clib_memcpy_fast (ctx->decrypt_cipher_key, raw_key + 128,
			OVPN_TLS_CRYPT_CIPHER_SIZE);
    }

  ctx->enabled = 1;
  ctx->packet_id_send = 1; /* Start from 1, 0 is invalid */

  /* Securely clear the raw key */
  clib_memset (raw_key, 0, sizeof (raw_key));

  return 0;
}

/*
 * Compute HMAC-SHA256 for TLS-Crypt using EVP_MAC API (OpenSSL 3.0+)
 */
static int
ovpn_tls_crypt_hmac (const u8 *key, const u8 *data, u32 len, u8 *out)
{
  EVP_MAC *mac = NULL;
  EVP_MAC_CTX *ctx = NULL;
  OSSL_PARAM params[2];
  size_t out_len = 0;
  int ok = 0;

  mac = EVP_MAC_fetch (NULL, "HMAC", NULL);
  if (!mac)
    return -1;

  ctx = EVP_MAC_CTX_new (mac);
  if (!ctx)
    {
      EVP_MAC_free (mac);
      return -1;
    }

  params[0] = OSSL_PARAM_construct_utf8_string (OSSL_MAC_PARAM_DIGEST,
						(char *) "SHA256", 0);
  params[1] = OSSL_PARAM_construct_end ();

  if (!EVP_MAC_init (ctx, key, OVPN_TLS_CRYPT_HMAC_SIZE, params))
    goto done;
  if (!EVP_MAC_update (ctx, data, len))
    goto done;
  if (!EVP_MAC_final (ctx, out, &out_len, OVPN_TLS_CRYPT_HMAC_SIZE))
    goto done;

  ok = (out_len == OVPN_TLS_CRYPT_HMAC_SIZE);

done:
  EVP_MAC_CTX_free (ctx);
  EVP_MAC_free (mac);
  return ok ? 0 : -1;
}

/*
 * AES-256-CTR encrypt/decrypt (same operation for CTR mode)
 */
static int
ovpn_tls_crypt_aes_ctr (const u8 *key, const u8 *iv, const u8 *in, u32 in_len,
			u8 *out)
{
  EVP_CIPHER_CTX *ctx = NULL;
  int out_len = 0;
  int final_len = 0;
  int ok = 0;

  ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    return -1;

  if (!EVP_EncryptInit_ex (ctx, EVP_aes_256_ctr (), NULL, key, iv))
    goto done;

  if (!EVP_EncryptUpdate (ctx, out, &out_len, in, in_len))
    goto done;

  if (!EVP_EncryptFinal_ex (ctx, out + out_len, &final_len))
    goto done;

  ok = 1;

done:
  EVP_CIPHER_CTX_free (ctx);
  return ok ? (out_len + final_len) : -1;
}

/*
 * Build the IV for AES-256-CTR from packet_id
 * IV format: [packet_id (4 bytes, network order)][zeros (12 bytes)]
 */
static void
ovpn_tls_crypt_build_iv (u32 packet_id, u8 *iv)
{
  clib_memset (iv, 0, OVPN_TLS_CRYPT_IV_SIZE);
  u32 net_packet_id = clib_host_to_net_u32 (packet_id);
  clib_memcpy_fast (iv, &net_packet_id, sizeof (u32));
}

/*
 * Wrap (encrypt + authenticate) a control channel packet using TLS-Crypt
 *
 * TLS-Crypt wrapped packet format:
 *   [HMAC(32)][packet_id(4)][net_time(4)][encrypted payload]
 *
 * The HMAC is computed over: packet_id || net_time || encrypted_payload
 * The encryption covers the entire plaintext using the packet_id as IV
 */
int
ovpn_tls_crypt_wrap (const ovpn_tls_crypt_t *ctx, const u8 *plaintext,
		     u32 plain_len, u8 *wrapped, u32 wrapped_buf_len)
{
  u8 iv[OVPN_TLS_CRYPT_IV_SIZE];
  u8 hmac_input[2048 + 8]; /* packet_id + net_time + encrypted */
  u32 hmac_input_len;
  u32 wrapped_len;
  u8 *encrypted;
  int rv;

  if (!ctx || !ctx->enabled || !plaintext || !wrapped)
    return -1;

  /* Check buffer size */
  wrapped_len = OVPN_TLS_CRYPT_OVERHEAD + plain_len;
  if (wrapped_buf_len < wrapped_len)
    return -2;

  if (plain_len > sizeof (hmac_input) - 8)
    return -3; /* Plaintext too large */

  /* Get next packet ID */
  u32 packet_id = ctx->packet_id_send;
  /* Note: caller should increment packet_id_send after successful wrap */

  /* Get current time */
  u32 net_time = (u32) unix_time_now ();

  /* Build IV from packet_id */
  ovpn_tls_crypt_build_iv (packet_id, iv);

  /* Position output pointer after HMAC */
  ovpn_tls_crypt_header_t *hdr = (ovpn_tls_crypt_header_t *) wrapped;
  hdr->packet_id = clib_host_to_net_u32 (packet_id);
  hdr->net_time = clib_host_to_net_u32 (net_time);

  /* Encrypt the plaintext */
  encrypted = wrapped + OVPN_TLS_CRYPT_OVERHEAD;
  rv = ovpn_tls_crypt_aes_ctr (ctx->encrypt_cipher_key, iv, plaintext,
			       plain_len, encrypted);
  if (rv < 0)
    return -4;

  /* Build HMAC input: packet_id || net_time || encrypted_payload */
  u32 net_packet_id = clib_host_to_net_u32 (packet_id);
  u32 net_net_time = clib_host_to_net_u32 (net_time);
  clib_memcpy_fast (hmac_input, &net_packet_id, 4);
  clib_memcpy_fast (hmac_input + 4, &net_net_time, 4);
  clib_memcpy_fast (hmac_input + 8, encrypted, plain_len);
  hmac_input_len = 8 + plain_len;

  /* Compute HMAC and write to header */
  rv = ovpn_tls_crypt_hmac (ctx->encrypt_hmac_key, hmac_input, hmac_input_len,
			    hdr->hmac);
  if (rv < 0)
    return -5;

  return wrapped_len;
}

/*
 * Unwrap (verify + decrypt) a control channel packet using TLS-Crypt
 * This function includes replay protection checking and updates the
 * replay window on success.
 */
int
ovpn_tls_crypt_unwrap (ovpn_tls_crypt_t *ctx, const u8 *wrapped,
		       u32 wrapped_len, u8 *plaintext, u32 plaintext_buf_len)
{
  u8 iv[OVPN_TLS_CRYPT_IV_SIZE];
  u8 computed_hmac[OVPN_TLS_CRYPT_HMAC_SIZE];
  u8 hmac_input[2048 + 8];
  u32 hmac_input_len;
  u32 plain_len;
  int rv;

  if (!ctx || !ctx->enabled || !wrapped || !plaintext)
    return -1;

  /* Check minimum wrapped packet size */
  if (wrapped_len < OVPN_TLS_CRYPT_OVERHEAD)
    return -2;

  plain_len = wrapped_len - OVPN_TLS_CRYPT_OVERHEAD;
  if (plaintext_buf_len < plain_len)
    return -3;

  if (plain_len > sizeof (hmac_input) - 8)
    return -4; /* Packet too large */

  /* Parse header */
  const ovpn_tls_crypt_header_t *hdr =
    (const ovpn_tls_crypt_header_t *) wrapped;
  u32 packet_id = clib_net_to_host_u32 (hdr->packet_id);
  u32 net_time = clib_net_to_host_u32 (hdr->net_time);
  const u8 *encrypted = wrapped + OVPN_TLS_CRYPT_OVERHEAD;

  /* Sanity check packet_id */
  if (packet_id == 0)
    return -5; /* Invalid packet ID */

  /*
   * Replay protection check (BEFORE HMAC verification for efficiency)
   * Note: This is safe because we do the full HMAC check below.
   * An attacker cannot forge packets without the key.
   */
  if (!ovpn_tls_crypt_check_replay (ctx, packet_id))
    return -9; /* Replay detected */

  /* Build HMAC input: packet_id || net_time || encrypted_payload */
  u32 net_packet_id = clib_host_to_net_u32 (packet_id);
  u32 net_net_time = clib_host_to_net_u32 (net_time);
  clib_memcpy_fast (hmac_input, &net_packet_id, 4);
  clib_memcpy_fast (hmac_input + 4, &net_net_time, 4);
  clib_memcpy_fast (hmac_input + 8, encrypted, plain_len);
  hmac_input_len = 8 + plain_len;

  /* Compute HMAC */
  rv = ovpn_tls_crypt_hmac (ctx->decrypt_hmac_key, hmac_input, hmac_input_len,
			    computed_hmac);
  if (rv < 0)
    return -6;

  /* Verify HMAC using constant-time comparison */
  if (CRYPTO_memcmp (hdr->hmac, computed_hmac, OVPN_TLS_CRYPT_HMAC_SIZE) != 0)
    return -7; /* HMAC verification failed */

  /* Build IV from packet_id */
  ovpn_tls_crypt_build_iv (packet_id, iv);

  /* Decrypt the payload */
  rv = ovpn_tls_crypt_aes_ctr (ctx->decrypt_cipher_key, iv, encrypted,
			       plain_len, plaintext);
  if (rv < 0)
    return -8;

  /*
   * Update replay window AFTER successful verification
   * This ensures we don't update the window for forged packets
   */
  ovpn_tls_crypt_update_replay (ctx, packet_id);

  /* Suppress unused variable warning */
  (void) net_time;

  return plain_len;
}

/*
 * Send control packets from pending connection's reliable buffer
 * Allocates vlib_buffer, builds IP/UDP headers, copies payload, sends to IP lookup
 */
static int
ovpn_handshake_send_pending_packets (vlib_main_t *vm,
				     ovpn_pending_connection_t *pending,
				     const ip_address_t *local_addr,
				     u16 local_port, u8 is_ip6,
				     const ovpn_tls_auth_t *auth,
				     ovpn_tls_crypt_t *tls_crypt)
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

      /* Apply TLS-Crypt or TLS-Auth wrapping */
      if (tls_crypt && tls_crypt->enabled)
	{
	  /* TLS-Crypt: encrypt and authenticate the control packet */
	  u8 wrapped[2048 + OVPN_TLS_CRYPT_OVERHEAD];
	  int wrapped_len =
	    ovpn_tls_crypt_wrap (tls_crypt, payload, payload_len, wrapped,
				 sizeof (wrapped));
	  if (wrapped_len < 0)
	    {
	      vlib_buffer_free_one (vm, bi);
	      return -2;
	    }

	  /* Copy wrapped packet back to payload area */
	  clib_memcpy_fast (payload, wrapped, wrapped_len);
	  payload_len = wrapped_len;

	  /* Increment packet ID for next wrap */
	  tls_crypt->packet_id_send++;
	}
      else if (auth && auth->enabled)
	{
	  /* TLS-Auth: append HMAC */
	  u8 *hmac = payload + payload_len;
	  ovpn_handshake_generate_hmac (payload, payload_len, hmac, auth);
	  payload_len += OVPN_HMAC_SIZE;
	}

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
	  if (local_addr)
	    clib_memcpy (&ip6->src_address, &local_addr->ip.ip6,
			 sizeof (ip6_address_t));
	  clib_memcpy (&ip6->dst_address, &pending->remote_addr.ip.ip6,
		       sizeof (ip6_address_t));

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
	  if (local_addr)
	    ip4->src_address.as_u32 = local_addr->ip.ip4.as_u32;

	  ip4->checksum = ip4_header_checksum (ip4);

	  udp = (udp_header_t *) (ip4 + 1);
	}

      /* Build UDP header */
      udp->dst_port = clib_host_to_net_u16 (pending->remote_port);
      udp->src_port = clib_host_to_net_u16 (local_port ? local_port : 1194);
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
				  const ip_address_t *local_addr,
				  u16 local_port, u8 is_ip6,
				  const ovpn_tls_auth_t *auth,
				  ovpn_tls_crypt_t *tls_crypt)
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

      /* Apply TLS-Crypt or TLS-Auth wrapping */
      if (tls_crypt && tls_crypt->enabled)
	{
	  /* TLS-Crypt: encrypt and authenticate the control packet */
	  u8 wrapped[2048 + OVPN_TLS_CRYPT_OVERHEAD];
	  int wrapped_len =
	    ovpn_tls_crypt_wrap (tls_crypt, pkt_data, total_ctrl_len, wrapped,
				 sizeof (wrapped));
	  if (wrapped_len < 0)
	    {
	      vlib_buffer_free_one (vm, bi);
	      return -2;
	    }

	  /* Copy wrapped packet back to payload area */
	  clib_memcpy_fast (pkt_data, wrapped, wrapped_len);
	  total_ctrl_len = wrapped_len;

	  /* Increment packet ID for next wrap */
	  tls_crypt->packet_id_send++;
	}
      else if (auth && auth->enabled)
	{
	  /* TLS-Auth: append HMAC */
	  u8 *hmac = pkt_data + total_ctrl_len;
	  ovpn_handshake_generate_hmac (pkt_data, total_ctrl_len, hmac, auth);
	  total_ctrl_len += OVPN_HMAC_SIZE;
	}

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

	  if (local_addr)
	    clib_memcpy (&ip6->src_address, &local_addr->ip.ip6,
			 sizeof (ip6_address_t));
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
	  if (local_addr)
	    ip4->src_address.as_u32 = local_addr->ip.ip4.as_u32;

	  ip4->checksum = ip4_header_checksum (ip4);

	  udp = (udp_header_t *) (ip4 + 1);
	}

      udp->dst_port = clib_host_to_net_u16 (peer->remote_port);
      udp->src_port = clib_host_to_net_u16 (local_port ? local_port : 1194);
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

  /*
   * Control channel packet authentication and replay protection
   *
   * Both TLS-Crypt and TLS-Auth use a TWO packet_id scheme:
   * 1. Wrapper packet_id: In the TLS-Crypt/TLS-Auth header for REPLAY PROTECTION
   * 2. Message packet_id: Inside the control packet for RELIABLE ORDERING
   *
   * The wrapper layer handles authentication and anti-replay.
   * The reliable layer handles ordering and retransmission.
   */

  /* Check if TLS-Crypt is enabled - it takes precedence over TLS-Auth */
  if (omp->tls_crypt.enabled)
    {
      /*
       * TLS-Crypt packet format:
       *   [HMAC (32)] [packet_id (4)] [net_time (4)] [encrypted payload]
       *
       * The unwrap function:
       * 1. Checks replay protection (wrapper packet_id)
       * 2. Verifies HMAC
       * 3. Decrypts payload
       * 4. Updates replay window
       */
      u8 plaintext[2048];
      int plain_len =
	ovpn_tls_crypt_unwrap (&omp->tls_crypt, data, len, plaintext,
			       sizeof (plaintext));
      if (plain_len < 0)
	{
	  if (plain_len == -9)
	    return -5; /* Replay detected */
	  return -2;   /* TLS-Crypt unwrap failed */
	}

      /* Copy plaintext back to buffer */
      clib_memcpy_fast (data, plaintext, plain_len);
      len = plain_len;
      b->current_length = len;
    }
  else if (omp->tls_auth.enabled)
    {
      /*
       * TLS-Auth packet format (after opcode byte):
       *   [HMAC (32)] [packet_id (4)] [net_time (4)] [session_id...payload]
       *
       * The unwrap function:
       * 1. Checks replay protection (wrapper packet_id)
       * 2. Verifies HMAC
       * 3. Strips HMAC + packet_id + net_time
       * 4. Updates replay window
       */
      u8 plaintext[2048];
      int plain_len =
	ovpn_tls_auth_unwrap (&omp->tls_auth, data, len, plaintext,
			      sizeof (plaintext));
      if (plain_len < 0)
	{
	  if (plain_len == -4)
	    return -5; /* Replay detected */
	  return -2;   /* TLS-Auth unwrap failed */
	}

      /* Copy plaintext back to buffer */
      clib_memcpy_fast (data, plaintext, plain_len);
      len = plain_len;
      b->current_length = len;
    }

  clib_memset (&ack_session_id, 0, sizeof (ack_session_id));

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
	 * Client is initiating connection or reconnecting
	 *
	 * If peer already exists for this remote address, it means client
	 * is reconnecting. We need to:
	 * 1. Delete the existing peer (clean up old state)
	 * 2. Create a new pending connection
	 * 3. Send P_CONTROL_HARD_RESET_SERVER_V2 with ACK
	 */

	/* Check if peer already exists - client is reconnecting */
	if (peer)
	  {
	    /*
	     * Client sent HARD_RESET but we have existing peer.
	     * This is a reconnection scenario - delete the old peer.
	     *
	     * Use worker barrier to ensure no data plane workers are
	     * accessing this peer during deletion.
	     */
	    u32 old_peer_id = peer->peer_id;

	    vlib_worker_thread_barrier_sync (vm);
	    ovpn_peer_delete (peer_db, old_peer_id);
	    vlib_worker_thread_barrier_release (vm);

	    peer = NULL; /* Peer no longer valid */
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
	ovpn_tls_crypt_t *tls_crypt_ptr =
	  omp->tls_crypt.enabled ? &omp->tls_crypt : NULL;
	ovpn_tls_auth_t *tls_auth_ptr =
	  omp->tls_auth.enabled ? &omp->tls_auth : NULL;
	rv = ovpn_handshake_send_pending_packets (vm, pending, dst_addr,
						  dst_port, is_ip6, tls_auth_ptr,
						  tls_crypt_ptr);
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
	{
	  ovpn_tls_crypt_t *tls_crypt_ptr =
	    omp->tls_crypt.enabled ? &omp->tls_crypt : NULL;
	  ovpn_tls_auth_t *tls_auth_ptr =
	    omp->tls_auth.enabled ? &omp->tls_auth : NULL;
	  ovpn_handshake_send_peer_packets (vm, peer, dst_addr, dst_port,
					    is_ip6, tls_auth_ptr, tls_crypt_ptr);
	}

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
	 * P_CONTROL_V1 packet handling depends on peer state:
	 *
	 * 1. HANDSHAKE/REKEYING state (tls_ctx exists):
	 *    - TLS handshake data that must be processed in order
	 *    - Use reliable layer to buffer out-of-order packets
	 *
	 * 2. ESTABLISHED state (tls_ctx is NULL):
	 *    - Control messages like PUSH_REQUEST, ping, etc.
	 *    - Process directly without reliable buffering
	 */
	u8 *tls_data;
	u32 tls_len;

	/* First check: peer in ESTABLISHED state without TLS context */
	if (peer && peer->state == OVPN_PEER_STATE_ESTABLISHED &&
	    !peer->tls_ctx)
	  {
	    /*
	     * Client sent P_CONTROL_V1 to an established peer
	     * This could be:
	     * 1. PUSH_REQUEST - client requesting pushed options
	     * 2. Ping packet - keepalive
	     * 3. Other control message
	     *
	     * Process the TLS payload as a control message
	     */
	    u8 *ctrl_data = OVPN_BPTR (&buf);
	    u32 ctrl_len = OVPN_BLEN (&buf);

	    if (ctrl_len > 0)
	      {
		u8 response[512];
		u32 response_len = sizeof (response);

		int msg_rv = ovpn_control_message_process (
		  vm, peer, ctrl_data, ctrl_len, response, &response_len);

		if (msg_rv > 0 && response_len > 0)
		  {
		    /*
		     * Need to send response over TLS
		     * Since peer is established, we need to re-encrypt with TLS
		     * For now, we'll allocate a temporary TLS context to send
		     * the response
		     *
		     * TODO: Implement proper control message response sending
		     * for established peers. This requires:
		     * 1. Encrypting with TLS
		     * 2. Sending via control channel
		     */
		    rv = msg_rv;
		  }
	      }
	    break;
	  }

	/* Second check: peer in HANDSHAKE or REKEYING state with TLS context */
	if (peer && peer->tls_ctx &&
	    (peer->state == OVPN_PEER_STATE_HANDSHAKE ||
	     peer->state == OVPN_PEER_STATE_REKEYING))
	  {
	    ovpn_peer_tls_t *tls_ctx = peer->tls_ctx;
	    ovpn_reliable_t *recv_rel = tls_ctx->recv_reliable;

	    /* Record packet ID for ACK */
	    ovpn_reliable_ack_acknowledge_packet_id (&tls_ctx->recv_ack,
						     packet_id);

	    /* Check for replay/duplicate */
	    if (!ovpn_reliable_not_replay (recv_rel, packet_id))
	      {
		/* Duplicate or old packet - ignore but still ACK */
		rv = 0;
		break;
	      }

	    /* Check if packet would break sequentiality (too far ahead) */
	    if (!ovpn_reliable_wont_break_sequentiality (recv_rel, packet_id))
	      {
		/* Packet ID too far ahead - cannot buffer */
		rv = -14;
		break;
	      }

	    /* Store packet in receive reliable buffer */
	    ovpn_reli_buffer_t *recv_buf = ovpn_reliable_get_buf (recv_rel);
	    if (!recv_buf)
	      {
		/* No space in receive buffer */
		rv = -15;
		break;
	      }

	    /* Copy payload to reliable buffer */
	    tls_data = OVPN_BPTR (&buf);
	    tls_len = OVPN_BLEN (&buf);
	    ovpn_buf_init (recv_buf, 0);
	    ovpn_buf_write (recv_buf, tls_data, tls_len);

	    /* Mark as active incoming */
	    ovpn_reliable_mark_active_incoming (recv_rel, recv_buf, packet_id,
						opcode);

	    /*
	     * Process all in-sequence packets from the receive buffer
	     */
	    ovpn_reliable_entry_t *entry;
	    while ((entry = ovpn_reliable_get_entry_sequenced (recv_rel)) !=
		   NULL)
	      {
		ovpn_reli_buffer_t *seq_buf = ovpn_buf_get (entry->buf_index);
		tls_data = OVPN_BPTR (seq_buf);
		tls_len = OVPN_BLEN (seq_buf);

		/* Process TLS data */
		rv = ovpn_peer_tls_process (peer, tls_data, tls_len);

		/* Mark entry as processed and advance sequence */
		ovpn_reliable_mark_deleted (recv_rel, seq_buf);

		/* Send response if TLS produced data */
		if (rv > 0)
		  {
		    ovpn_tls_crypt_t *tls_crypt_ptr =
		      omp->tls_crypt.enabled ? &omp->tls_crypt : NULL;
		    ovpn_tls_auth_t *tls_auth_ptr =
		      omp->tls_auth.enabled ? &omp->tls_auth : NULL;
		    ovpn_handshake_send_peer_packets (
		      vm, peer, dst_addr, dst_port, is_ip6, tls_auth_ptr,
		      tls_crypt_ptr);
		  }

		/* Check if TLS handshake completed */
		if (ovpn_peer_tls_is_established (peer))
		  {
		    /*
		     * TLS handshake complete!
		     *
		     * Now we need to exchange Key Method 2 data over the
		     * encrypted TLS channel. The sequence is:
		     * 1. Client sends key_method_2 data (pre_master + randoms)
		     * 2. Server receives and sends its own randoms
		     * 3. Both sides derive keys from combined random material
		     *
		     * The decrypted Key Method 2 data is stored in
		     * tls_ctx->plaintext_read_buf by ovpn_peer_tls_process().
		     */

		    /* Try to read client's Key Method 2 data from decrypted
		     * plaintext buffer */
		    u8 *km_data = OVPN_BPTR (&tls_ctx->plaintext_read_buf);
		    u32 km_len = OVPN_BLEN (&tls_ctx->plaintext_read_buf);

		    if (!tls_ctx->key_method_received && km_len > 0)
		      {
			char *peer_opts = NULL;
			int km_rv = ovpn_key_method_2_read (
			  km_data, km_len, tls_ctx->key_src2,
			  1 /* is_server */, &peer_opts);
			if (km_rv > 0)
			  {
			    tls_ctx->key_method_received = 1;
			    tls_ctx->peer_options = peer_opts;

			    /*
			     * Negotiate data channel cipher from client options
			     *
			     * The client sends its supported ciphers via:
			     * 1. IV_CIPHERS=cipher1:cipher2:... (OpenVPN 2.5+)
			     * 2. cipher <name> in options string (legacy)
			     *
			     * We select the first cipher that both support.
			     */
			    ovpn_cipher_alg_t negotiated_cipher =
			      OVPN_CIPHER_ALG_NONE;

			    if (peer_opts)
			      {
				/* Try to extract IV_CIPHERS first (modern
				 * clients) */
				char *iv_ciphers =
				  ovpn_options_string_extract_option (
				    peer_opts, "IV_CIPHERS");
				if (iv_ciphers)
				  {
				    /*
				     * IV_CIPHERS format: cipher1:cipher2:cipher3
				     * Select first cipher that matches our
				     * supported list
				     */
				    char *cipher_list = iv_ciphers;
				    char *cipher_name;
				    char *saveptr = NULL;

				    while ((cipher_name = strtok_r (
					      cipher_list, ":", &saveptr)) !=
					   NULL)
				      {
					cipher_list = NULL;
					ovpn_cipher_alg_t alg =
					  ovpn_crypto_cipher_alg_from_name (
					    cipher_name);
					if (alg != OVPN_CIPHER_ALG_NONE)
					  {
					    negotiated_cipher = alg;
					    break;
					  }
				      }
				    clib_mem_free (iv_ciphers);
				  }

				/* Fall back to legacy "cipher" option */
				if (negotiated_cipher == OVPN_CIPHER_ALG_NONE)
				  {
				    char *cipher_opt =
				      ovpn_options_string_extract_option (
					peer_opts, "cipher");
				    if (cipher_opt)
				      {
					negotiated_cipher =
					  ovpn_crypto_cipher_alg_from_name (
					    cipher_opt);
					clib_mem_free (cipher_opt);
				      }
				  }

				/* Check for key-derivation tls-ekm support */
				char *key_deriv =
				  ovpn_options_string_extract_option (
				    peer_opts, "key-derivation");
				if (key_deriv)
				  {
				    if (strcmp (key_deriv, "tls-ekm") == 0)
				      tls_ctx->use_tls_ekm = 1;
				    clib_mem_free (key_deriv);
				  }
			      }

			    /*
			     * Use negotiated cipher if valid, otherwise fall
			     * back to server's configured cipher
			     */
			    if (negotiated_cipher != OVPN_CIPHER_ALG_NONE)
			      tls_ctx->negotiated_cipher_alg = negotiated_cipher;
			    else
			      tls_ctx->negotiated_cipher_alg = omp->cipher_alg;
			  }
		      }

		    /* Send our Key Method 2 data if not already sent */
		    if (!tls_ctx->key_method_sent &&
			tls_ctx->key_method_received)
		      {
			u8 km_buf[512];
			char options_buf[512];

			/* Build server options string with negotiated cipher
			 * and virtual IP */
			const char *cipher_name =
			  ovpn_cipher_alg_to_name (tls_ctx->negotiated_cipher_alg);

			/*
			 * Pass virtual IP if assigned to this peer
			 * The virtual_ip field should have been set during IP
			 * pool allocation
			 */
			int opt_len = ovpn_options_string_build_server (
			  options_buf, sizeof (options_buf), cipher_name,
			  tls_ctx->use_tls_ekm, peer->peer_id,
			  peer->virtual_ip_set ? &peer->virtual_ip : NULL,
			  NULL /* netmask - use default */);

			int km_len = ovpn_key_method_2_write (
			  km_buf, sizeof (km_buf), tls_ctx->key_src2,
			  peer->session_id.id, 1 /* is_server */,
			  opt_len > 0 ? options_buf : NULL);

			if (km_len > 0)
			  {
			    /* Send Key Method 2 data over TLS */
			    ptls_buffer_t sendbuf;
			    ptls_buffer_init (&sendbuf, "", 0);

			    int tls_rv = ptls_send (tls_ctx->tls, &sendbuf,
						   km_buf, km_len);
			    if (tls_rv == 0 && sendbuf.off > 0)
			      {
				/* Queue TLS data for sending */
				ovpn_reli_buffer_t *out_buf =
				  ovpn_reliable_get_buf_output_sequenced (
				    tls_ctx->send_reliable);
				if (out_buf)
				  {
				    ovpn_buf_init (out_buf, 128);
				    ovpn_buf_write (out_buf, sendbuf.base,
						   sendbuf.off);
				    ovpn_reliable_mark_active_outgoing (
				      tls_ctx->send_reliable, out_buf,
				      OVPN_OP_CONTROL_V1);
				    tls_ctx->key_method_sent = 1;
				  }
			      }
			    ptls_buffer_dispose (&sendbuf);
			  }
		      }

		    /* Check if key exchange is complete */
		    if (tls_ctx->key_method_sent && tls_ctx->key_method_received)
		      {
			/*
			 * Key Method 2 exchange complete!
			 * Now derive data channel keys.
			 */
			ovpn_cipher_alg_t cipher_alg =
			  (ovpn_cipher_alg_t) tls_ctx->negotiated_cipher_alg;

			if (peer->state == OVPN_PEER_STATE_REKEYING)
			  {
			    /*
			     * Rekey TLS handshake complete
			     * Install new keys and return to ESTABLISHED
			     */
			    int key_rv;

			    key_rv = ovpn_peer_complete_rekey (vm, peer_db, peer,
							      cipher_alg);
			    if (key_rv == 0)
			      {
				rv = 3; /* Rekey complete */
			      }
			    else
			      {
				/* Rekey failed - peer stays in REKEYING state
				 */
				peer->state = OVPN_PEER_STATE_ESTABLISHED;
				ovpn_peer_tls_free (peer);
				rv = -13;
			      }
			  }
			else
			  {
			    /*
			     * Initial TLS handshake complete
			     * Derive data channel keys and transition to
			     * ESTABLISHED
			     */
			    ovpn_key_material_t keys;
			    int key_rv;

			    /* Derive keys using Key Method 2 with negotiated
			     * cipher */
			    key_rv = ovpn_derive_data_channel_keys_v2 (
			      tls_ctx->tls, tls_ctx->key_src2,
			      peer->remote_session_id.id, peer->session_id.id,
			      &keys, cipher_alg, 1 /* is_server */,
			      tls_ctx->use_tls_ekm);

			    if (key_rv == 0)
			      {
				/* Set up crypto context for this peer */
				key_rv = ovpn_peer_set_key (
				  vm, peer_db, peer, OVPN_KEY_SLOT_PRIMARY,
				  cipher_alg, &keys, tls_ctx->key_id);
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
				    peer->next_rekey_time =
				      now + peer->rekey_interval;
				  }

				/* Build rewrite for output path (IP/UDP
				 * headers) */
				ovpn_peer_build_rewrite (peer, dst_addr,
							 dst_port);

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
		  }
	      } /* end while (get_entry_sequenced) */

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
 * OpenVPN ping string - magic byte pattern for keepalive
 */
const u8 ovpn_ping_string[OVPN_PING_STRING_SIZE] = { 0x2a, 0x18, 0x7b, 0xf3,
						    0x64, 0x1e, 0xb4, 0xcb };

/*
 * Build PUSH_REPLY message for a peer
 *
 * Format: "PUSH_REPLY,option1,option2,...,END"
 *
 * Common options:
 *   - route <network> <netmask> [gateway]
 *   - route-gateway <gateway>
 *   - ifconfig <local> <remote>
 *   - dhcp-option DNS <server>
 *   - redirect-gateway [flags]
 *   - ping <seconds>
 *   - ping-restart <seconds>
 *   - peer-id <id>
 */
int
ovpn_build_push_reply (ovpn_peer_t *peer, char *buf, u32 buf_len)
{
  extern ovpn_main_t ovpn_main;
  ovpn_main_t *omp = &ovpn_main;
  int offset = 0;
  int written;

  if (!buf || buf_len < 64)
    return -1;

  /* Start with PUSH_REPLY */
  written = snprintf (buf + offset, buf_len - offset, "PUSH_REPLY");
  if (written < 0 || (u32) written >= buf_len - offset)
    return -1;
  offset += written;

  /* Add ifconfig if virtual IP is assigned */
  if (peer->virtual_ip_set && !ip_address_is_zero (&peer->virtual_ip))
    {
      if (peer->virtual_ip.version == AF_IP4)
	{
	  u8 ip_str[INET_ADDRSTRLEN];
	  inet_ntop (AF_INET, &peer->virtual_ip.ip.ip4, (char *) ip_str,
		     sizeof (ip_str));

	  /* TUN mode: ifconfig <local-ip> <remote-ip> */
	  written = snprintf (buf + offset, buf_len - offset,
			      ",ifconfig %s 10.8.0.1", ip_str);
	  if (written < 0 || (u32) written >= buf_len - offset)
	    return -2;
	  offset += written;
	}
      else
	{
	  u8 ip_str[INET6_ADDRSTRLEN];
	  inet_ntop (AF_INET6, &peer->virtual_ip.ip.ip6, (char *) ip_str,
		     sizeof (ip_str));

	  written = snprintf (buf + offset, buf_len - offset,
			      ",ifconfig-ipv6 %s/64 ::", ip_str);
	  if (written < 0 || (u32) written >= buf_len - offset)
	    return -2;
	  offset += written;
	}
    }

  /* Add peer-id for DATA_V2 format */
  written =
    snprintf (buf + offset, buf_len - offset, ",peer-id %u", peer->peer_id);
  if (written < 0 || (u32) written >= buf_len - offset)
    return -3;
  offset += written;

  /* Add ping/ping-restart for keepalive from configuration */
  u32 ping_interval =
    omp->options.keepalive_ping > 0 ? omp->options.keepalive_ping : 10;
  u32 ping_timeout =
    omp->options.keepalive_timeout > 0 ? omp->options.keepalive_timeout : 60;

  written = snprintf (buf + offset, buf_len - offset, ",ping %u,ping-restart %u",
		      ping_interval, ping_timeout);
  if (written < 0 || (u32) written >= buf_len - offset)
    return -4;
  offset += written;

  /* Add topology setting (subnet mode for TUN) */
  written = snprintf (buf + offset, buf_len - offset, ",topology subnet");
  if (written < 0 || (u32) written >= buf_len - offset)
    return -5;
  offset += written;

  /* Null terminate */
  if ((u32) offset < buf_len)
    buf[offset] = '\0';

  return offset;
}

/*
 * Process control channel message (after TLS decryption)
 *
 * These messages are plaintext strings sent over the encrypted TLS channel.
 * After the TLS handshake and Key Method 2 exchange, the client may send
 * additional control messages like PUSH_REQUEST.
 */
int
ovpn_control_message_process (vlib_main_t *vm, ovpn_peer_t *peer,
			      const u8 *data, u32 len, u8 *response,
			      u32 *response_len)
{
  /* Check for PUSH_REQUEST */
  if (len >= sizeof (OVPN_MSG_PUSH_REQUEST) - 1 &&
      clib_memcmp (data, OVPN_MSG_PUSH_REQUEST,
		   sizeof (OVPN_MSG_PUSH_REQUEST) - 1) == 0)
    {
      /*
       * Client is requesting pushed configuration options
       * Build and send PUSH_REPLY
       */
      int reply_len =
	ovpn_build_push_reply (peer, (char *) response, *response_len);
      if (reply_len > 0)
	{
	  *response_len = reply_len;
	  return 1; /* Response should be sent */
	}
      return -1; /* Failed to build reply */
    }

  /* Check for ping (magic byte pattern) */
  if (ovpn_is_ping_packet (data, len))
    {
      /*
       * Respond with the same ping pattern (echo)
       * This keeps the connection alive
       */
      if (*response_len >= OVPN_PING_STRING_SIZE)
	{
	  clib_memcpy_fast (response, ovpn_ping_string, OVPN_PING_STRING_SIZE);
	  *response_len = OVPN_PING_STRING_SIZE;
	  return 1; /* Response should be sent */
	}
      return 0; /* No space for response */
    }

  /* Check for OCC string (Options Compatibility Check) */
  if (len >= sizeof (OVPN_OCC_STRING) - 1 &&
      clib_memcmp (data, OVPN_OCC_STRING, sizeof (OVPN_OCC_STRING) - 1) == 0)
    {
      /* OCC messages are informational, no response needed */
      return 0;
    }

  /* Unknown message - no response */
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
