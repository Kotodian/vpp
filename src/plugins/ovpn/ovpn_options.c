/*
 * options.c - ovpn options implementation file
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

#include <ovpn/ovpn_options.h>
#include <ovpn/ovpn_crypto.h>
#include <vnet/ip/ip.h>
#include <arpa/inet.h>

bool
ovpn_string_defined_equal (const char *s1, const char *s2)
{
  if (s1 && s2)
    {
      return !clib_strcmp (s1, s2);
    }
  else
    {
      return 0;
    }
}

u8
ovpn_options_cmp_equal_safe (char *actual, const char *expected,
			     size_t actual_n)
{
  u8 ret = 1;

  if (actual_n > 0)
    {
      actual[actual_n - 1] = 0;
      if (clib_strncmp (actual, expected, 2) == 0)
	{
	  // TODO:
	}
      else
	{
	  ret = !clib_strcmp (actual, expected);
	}
    }
  return ret;
}

u8
ovpn_options_cmp_equal (char *actual, const char *expected)
{
  return ovpn_options_cmp_equal_safe (actual, expected, strlen (actual) + 1);
}

char *
ovpn_options_string_extract_option (const char *options_string,
				    const char *opt_name)
{
  char *ret = NULL;
  const size_t opt_name_len = strlen (opt_name);

  const char *p = options_string;
  while (p)
    {
      if (clib_strncmp (p, opt_name, opt_name_len) == 0 &&
	  strlen (p) > (opt_name_len + 1) && p[opt_name_len] == ' ')
	{
	  /* option found, extract value */
	  const char *start = &p[opt_name_len + 1];
	  const char *end = strchr (p, ',');
	  size_t value_len = end ? end - start : strlen (start);
	  ret = clib_mem_alloc (value_len + 1);
	  clib_memcpy_fast (ret, start, value_len);
	  ret[value_len] = '\0';
	  break;
	}
      p = strchr (p, ',');
      if (p)
	{
	  p++;
	}
    }
  return ret;
}

/*
 * Parse client's ifconfig option from options string
 *
 * Clients can specify their desired virtual IP using:
 *   "ifconfig <ip> <netmask>" (IPv4)
 *   "ifconfig-ipv6 <ip>/<prefix> <remote>" (IPv6)
 *
 * @param options_string Client's options string from Key Method 2
 * @param virtual_ip Output: parsed virtual IP address
 * @return 0 on success (IP extracted), <0 if not found or invalid
 */
int
ovpn_options_parse_client_ifconfig (const char *options_string,
				    ip_address_t *virtual_ip)
{
  char *ifconfig_value = NULL;
  int ret = -1;

  if (!options_string || !virtual_ip)
    return -1;

  clib_memset (virtual_ip, 0, sizeof (*virtual_ip));

  /* Try IPv4 ifconfig first */
  ifconfig_value = ovpn_options_string_extract_option (options_string, "ifconfig");
  if (ifconfig_value)
    {
      /* Format: "ifconfig <ip> <netmask>" - extract first IP */
      char ip_str[INET_ADDRSTRLEN];
      char *space = strchr (ifconfig_value, ' ');
      size_t ip_len;

      if (space)
	ip_len = space - ifconfig_value;
      else
	ip_len = strlen (ifconfig_value);

      if (ip_len < sizeof (ip_str))
	{
	  clib_memcpy_fast (ip_str, ifconfig_value, ip_len);
	  ip_str[ip_len] = '\0';

	  if (inet_pton (AF_INET, ip_str, &virtual_ip->ip.ip4) == 1)
	    {
	      virtual_ip->version = AF_IP4;
	      ret = 0;
	    }
	}
      clib_mem_free (ifconfig_value);
      if (ret == 0)
	return ret;
    }

  /* Try IPv6 ifconfig-ipv6 */
  ifconfig_value =
    ovpn_options_string_extract_option (options_string, "ifconfig-ipv6");
  if (ifconfig_value)
    {
      /* Format: "ifconfig-ipv6 <ip>/<prefix> <remote>" - extract IP */
      char ip_str[INET6_ADDRSTRLEN];
      char *slash = strchr (ifconfig_value, '/');
      char *space = strchr (ifconfig_value, ' ');
      size_t ip_len;

      /* Find end of IP (either / or space or end of string) */
      if (slash)
	ip_len = slash - ifconfig_value;
      else if (space)
	ip_len = space - ifconfig_value;
      else
	ip_len = strlen (ifconfig_value);

      if (ip_len < sizeof (ip_str))
	{
	  clib_memcpy_fast (ip_str, ifconfig_value, ip_len);
	  ip_str[ip_len] = '\0';

	  if (inet_pton (AF_INET6, ip_str, &virtual_ip->ip.ip6) == 1)
	    {
	      virtual_ip->version = AF_IP6;
	      ret = 0;
	    }
	}
      clib_mem_free (ifconfig_value);
    }

  return ret;
}

/*
 * Check if an IP address is within the configured pool range
 *
 * @param ip IP address to check
 * @param pool_start Start of IP pool
 * @param pool_end End of IP pool
 * @return 1 if IP is within range, 0 otherwise
 */
int
ovpn_options_ip_in_pool (const ip_address_t *ip, const ip_address_t *pool_start,
			 const ip_address_t *pool_end)
{
  if (!ip || !pool_start || !pool_end)
    return 0;

  /* Pool must be configured */
  if (ip_address_is_zero (pool_start) || ip_address_is_zero (pool_end))
    return 1; /* No pool configured, accept any IP */

  /* Version must match */
  if (ip->version != pool_start->version ||
      ip->version != pool_end->version)
    return 0;

  if (ip->version == AF_IP4)
    {
      u32 ip_val = clib_net_to_host_u32 (ip->ip.ip4.as_u32);
      u32 start_val = clib_net_to_host_u32 (pool_start->ip.ip4.as_u32);
      u32 end_val = clib_net_to_host_u32 (pool_end->ip.ip4.as_u32);

      return (ip_val >= start_val && ip_val <= end_val);
    }
  else
    {
      /* IPv6: compare as two 64-bit values */
      u64 ip_hi = clib_net_to_host_u64 (ip->ip.ip6.as_u64[0]);
      u64 ip_lo = clib_net_to_host_u64 (ip->ip.ip6.as_u64[1]);
      u64 start_hi = clib_net_to_host_u64 (pool_start->ip.ip6.as_u64[0]);
      u64 start_lo = clib_net_to_host_u64 (pool_start->ip.ip6.as_u64[1]);
      u64 end_hi = clib_net_to_host_u64 (pool_end->ip.ip6.as_u64[0]);
      u64 end_lo = clib_net_to_host_u64 (pool_end->ip.ip6.as_u64[1]);

      /* Check if ip >= pool_start */
      if (ip_hi < start_hi || (ip_hi == start_hi && ip_lo < start_lo))
	return 0;

      /* Check if ip <= pool_end */
      if (ip_hi > end_hi || (ip_hi == end_hi && ip_lo > end_lo))
	return 0;

      return 1;
    }
}

void
ovpn_options_init (ovpn_options_t *opts)
{
  clib_memset (opts, 0, sizeof (ovpn_options_t));
  /* Network */
  opts->listen_port = 1194;
  opts->proto = IP_PROTOCOL_UDP;

  /* Tunnel device related */
  opts->dev_name = "tun0";
  opts->sw_if_index = ~0;
  opts->mtu = 1420;
  opts->is_tun = 1;

  /* Replay protection */
  opts->replay_protection = 1;
  opts->replay_window = OVPN_DEFAULT_SEQ_BACKTRACK;
  opts->replay_time = OVPN_DEFAULT_TIME_BACKTRACK;

  /* Negotiation */
  opts->renegotiate_seconds = 3600;
  opts->handshake_window = 60;
  opts->transition_window = 3600;
}

/*
 * Cipher algorithm to name mapping
 */
const char *
ovpn_cipher_alg_to_name (u8 cipher_alg)
{
  switch (cipher_alg)
    {
    case 1: /* OVPN_CIPHER_ALG_AES_128_GCM */
      return "AES-128-GCM";
    case 2: /* OVPN_CIPHER_ALG_AES_256_GCM */
      return "AES-256-GCM";
    case 3: /* OVPN_CIPHER_ALG_CHACHA20_POLY1305 */
      return "CHACHA20-POLY1305";
    default:
      return NULL;
    }
}

/*
 * Build server options string for Key Method 2
 *
 * Format: "V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto UDPv4,
 *          cipher AES-256-GCM,auth [digest],keysize 256,key-method 2,
 *          tls-server,peer-id 0,ifconfig x.x.x.x y.y.y.y"
 *
 * Modern OpenVPN (2.5+) also supports:
 *   - "key-derivation tls-ekm" for RFC5705 key export
 *   - Negotiated cipher from IV_CIPHERS
 *   - "ifconfig" for pushing virtual IP to client
 */
int
ovpn_options_string_build_server (char *buf, u32 buf_len,
				  const char *cipher_name, u8 use_tls_ekm,
				  u32 peer_id, const ip_address_t *virtual_ip,
				  const ip_address_t *virtual_netmask)
{
  int offset = 0;
  int written;

  if (!buf || buf_len < 64)
    return -1;

  /*
   * Build the options string
   * Format follows OpenVPN protocol specification
   */

  /* Start with version and basic tunnel options */
  written = snprintf (buf + offset, buf_len - offset,
		      "V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto UDPv4");
  if (written < 0 || (u32) written >= buf_len - offset)
    return -2;
  offset += written;

  /* Add cipher if specified */
  if (cipher_name)
    {
      written =
	snprintf (buf + offset, buf_len - offset, ",cipher %s", cipher_name);
      if (written < 0 || (u32) written >= buf_len - offset)
	return -3;
      offset += written;
    }

  /* Add key method */
  written = snprintf (buf + offset, buf_len - offset, ",key-method 2");
  if (written < 0 || (u32) written >= buf_len - offset)
    return -4;
  offset += written;

  /* Server role indicator */
  written = snprintf (buf + offset, buf_len - offset, ",tls-server");
  if (written < 0 || (u32) written >= buf_len - offset)
    return -5;
  offset += written;

  /* Key derivation method (TLS-EKM if supported) */
  if (use_tls_ekm)
    {
      written =
	snprintf (buf + offset, buf_len - offset, ",key-derivation tls-ekm");
      if (written < 0 || (u32) written >= buf_len - offset)
	return -6;
      offset += written;
    }

  /* Peer ID */
  written = snprintf (buf + offset, buf_len - offset, ",peer-id %u", peer_id);
  if (written < 0 || (u32) written >= buf_len - offset)
    return -7;
  offset += written;

  /*
   * Virtual IP assignment (ifconfig push)
   * Format: "ifconfig <client-ip> <netmask>" for TUN mode
   * This tells the client what IP address to configure on its tunnel interface
   */
  if (virtual_ip && !ip_address_is_zero (virtual_ip))
    {
      if (virtual_ip->version == AF_IP4)
	{
	  /* IPv4: ifconfig <ip> <netmask> */
	  u8 ip_str[INET_ADDRSTRLEN];
	  u8 netmask_str[INET_ADDRSTRLEN];

	  inet_ntop (AF_INET, &virtual_ip->ip.ip4, (char *) ip_str,
		     sizeof (ip_str));

	  if (virtual_netmask && !ip_address_is_zero (virtual_netmask))
	    {
	      inet_ntop (AF_INET, &virtual_netmask->ip.ip4,
			 (char *) netmask_str, sizeof (netmask_str));
	    }
	  else
	    {
	      /* Default to /24 netmask */
	      snprintf ((char *) netmask_str, sizeof (netmask_str),
			"255.255.255.0");
	    }

	  written = snprintf (buf + offset, buf_len - offset,
			      ",ifconfig %s %s", ip_str, netmask_str);
	  if (written < 0 || (u32) written >= buf_len - offset)
	    return -8;
	  offset += written;
	}
      else
	{
	  /* IPv6: ifconfig-ipv6 <ip>/<prefix> <remote-ip> */
	  u8 ip_str[INET6_ADDRSTRLEN];

	  inet_ntop (AF_INET6, &virtual_ip->ip.ip6, (char *) ip_str,
		     sizeof (ip_str));

	  /* Default to /64 prefix for IPv6 */
	  written = snprintf (buf + offset, buf_len - offset,
			      ",ifconfig-ipv6 %s/64 ::", ip_str);
	  if (written < 0 || (u32) written >= buf_len - offset)
	    return -9;
	  offset += written;
	}
    }

  /* Null terminate */
  if ((u32) offset < buf_len)
    buf[offset] = '\0';

  return offset + 1; /* Include null terminator in length */
}

/*
 * Convert a single hex character to its value
 */
static inline int
hex_char_to_val (u8 c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/*
 * Parse OpenVPN static key file format.
 *
 * OpenVPN static.key format:
 * -----BEGIN OpenVPN Static key V1-----
 * <16 lines of 32 hex characters each = 256 bytes>
 * -----END OpenVPN Static key V1-----
 *
 * @param key_data Raw file contents
 * @param key_len Length of key_data
 * @param key_out Output buffer (must be at least OVPN_STATIC_KEY_SIZE bytes)
 * @return 0 on success, <0 on error
 */
int
ovpn_parse_static_key (const u8 *key_data, u32 key_len, u8 *key_out)
{
  const char *begin_marker = "-----BEGIN OpenVPN Static key V1-----";
  const char *end_marker = "-----END OpenVPN Static key V1-----";
  const u8 *p, *end;
  const u8 *hex_start = NULL;
  u32 out_idx = 0;

  if (!key_data || !key_out || key_len < 64)
    return -1;

  /* Find the begin marker */
  p = key_data;
  end = key_data + key_len;

  while (p < end)
    {
      if (*p == '-' && (end - p) >= (i64) strlen (begin_marker))
	{
	  if (clib_strncmp ((char *) p, begin_marker, strlen (begin_marker)) ==
	      0)
	    {
	      /* Skip past the marker and newline */
	      p += strlen (begin_marker);
	      while (p < end && (*p == '\n' || *p == '\r'))
		p++;
	      hex_start = p;
	      break;
	    }
	}
      p++;
    }

  if (!hex_start)
    return -2; /* Begin marker not found */

  /* Parse hex data until end marker */
  p = hex_start;
  while (p < end && out_idx < OVPN_STATIC_KEY_SIZE)
    {
      /* Check for end marker */
      if (*p == '-')
	{
	  if ((end - p) >= (i64) strlen (end_marker) &&
	      clib_strncmp ((char *) p, end_marker, strlen (end_marker)) == 0)
	    break;
	}

      /* Skip whitespace and newlines */
      if (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t')
	{
	  p++;
	  continue;
	}

      /* Parse hex byte (two characters) */
      if (p + 1 < end)
	{
	  int hi = hex_char_to_val (*p);
	  int lo = hex_char_to_val (*(p + 1));

	  if (hi < 0 || lo < 0)
	    return -3; /* Invalid hex character */

	  key_out[out_idx++] = (u8) ((hi << 4) | lo);
	  p += 2;
	}
      else
	{
	  return -4; /* Odd number of hex characters */
	}
    }

  if (out_idx != OVPN_STATIC_KEY_SIZE)
    return -5; /* Wrong key size */

  return 0;
}

/*
 * Set up static key crypto context for a peer.
 *
 * OpenVPN static key layout (256 bytes / 2048 bits):
 *   Direction 0 (encrypt for server -> client):
 *     Bytes 0-63: cipher key (32 bytes) + HMAC key (32 bytes)
 *   Direction 1 (encrypt for client -> server):
 *     Bytes 64-127: cipher key (32 bytes) + HMAC key (32 bytes)
 *   Direction 2:
 *     Bytes 128-191: cipher key (32 bytes) + HMAC key (32 bytes)
 *   Direction 3:
 *     Bytes 192-255: cipher key (32 bytes) + HMAC key (32 bytes)
 *
 * For AEAD ciphers (AES-GCM, ChaCha20-Poly1305):
 *   - Use 32 bytes for cipher key
 *   - Use first 8 bytes of HMAC key area as implicit IV
 *   - No separate HMAC (AEAD provides authentication)
 *
 * Direction parameter:
 *   - 0 = normal (server mode): encrypt with dir 0, decrypt with dir 1
 *   - 1 = inverse (client mode): encrypt with dir 1, decrypt with dir 0
 *
 * @param ctx Crypto context to initialize
 * @param cipher_alg Cipher algorithm (must be AEAD)
 * @param static_key 256-byte static key
 * @param direction 0=normal (server), 1=inverse (client)
 * @param replay_window Replay protection window size
 * @return 0 on success, <0 on error
 */
int
ovpn_setup_static_key_crypto (ovpn_crypto_context_t *ctx,
			      ovpn_cipher_alg_t cipher_alg,
			      const u8 *static_key, u8 direction,
			      u32 replay_window)
{
  ovpn_key_material_t keys;
  u32 cipher_encrypt_offset, cipher_decrypt_offset;
  u32 hmac_encrypt_offset, hmac_decrypt_offset;

  if (!ctx || !static_key)
    return -1;

  /* Validate cipher algorithm */
  if (cipher_alg != OVPN_CIPHER_ALG_AES_128_GCM &&
      cipher_alg != OVPN_CIPHER_ALG_AES_256_GCM &&
      cipher_alg != OVPN_CIPHER_ALG_CHACHA20_POLY1305 &&
      cipher_alg != OVPN_CIPHER_ALG_AES_256_CBC)
    return -2;

  clib_memset (&keys, 0, sizeof (keys));

  /*
   * OpenVPN static key layout (256 bytes = 2 x 128-byte key structures):
   *
   *   struct key {
   *     uint8_t cipher[64];  // cipher key material
   *     uint8_t hmac[64];    // HMAC key material
   *   };
   *   struct key2 {
   *     struct key keys[2];
   *   };
   *
   * Layout:
   *   - bytes 0-63:    keys[0].cipher
   *   - bytes 64-127:  keys[0].hmac
   *   - bytes 128-191: keys[1].cipher
   *   - bytes 192-255: keys[1].hmac
   *
   * For direction 0 (server / KEY_DIRECTION_NORMAL):
   *   - Encrypt with keys[0] (cipher @ 0, hmac @ 64)
   *   - Decrypt with keys[1] (cipher @ 128, hmac @ 192)
   *
   * For direction 1 (client / KEY_DIRECTION_INVERSE):
   *   - Encrypt with keys[1] (cipher @ 128, hmac @ 192)
   *   - Decrypt with keys[0] (cipher @ 0, hmac @ 64)
   */
  if (direction == 0)
    {
      /* Server: encrypt with keys[0], decrypt with keys[1] */
      cipher_encrypt_offset = 0;    /* keys[0].cipher */
      hmac_encrypt_offset = 64;     /* keys[0].hmac */
      cipher_decrypt_offset = 128;  /* keys[1].cipher */
      hmac_decrypt_offset = 192;    /* keys[1].hmac */
    }
  else
    {
      /* Client: encrypt with keys[1], decrypt with keys[0] */
      cipher_encrypt_offset = 128;  /* keys[1].cipher */
      hmac_encrypt_offset = 192;    /* keys[1].hmac */
      cipher_decrypt_offset = 0;    /* keys[0].cipher */
      hmac_decrypt_offset = 64;     /* keys[0].hmac */
    }

  /* Set key size based on cipher */
  if (cipher_alg == OVPN_CIPHER_ALG_AES_128_GCM)
    keys.key_len = 16;
  else
    keys.key_len = 32;

  /* Copy cipher keys */
  clib_memcpy (keys.encrypt_key, static_key + cipher_encrypt_offset,
	       keys.key_len);
  clib_memcpy (keys.decrypt_key, static_key + cipher_decrypt_offset,
	       keys.key_len);

  if (OVPN_CIPHER_IS_AEAD (cipher_alg))
    {
      /*
       * For AEAD: use bytes 32-39 (after cipher key) as implicit IV
       * This is the first 8 bytes of what would be the HMAC key area
       */
      clib_memcpy (keys.encrypt_implicit_iv,
		   static_key + cipher_encrypt_offset + 32,
		   OVPN_IMPLICIT_IV_LEN);
      clib_memcpy (keys.decrypt_implicit_iv,
		   static_key + cipher_decrypt_offset + 32,
		   OVPN_IMPLICIT_IV_LEN);
    }
  else
    {
      /*
       * For CBC: copy HMAC keys from subkeys 2 and 3
       * HMAC key is 32 bytes (SHA-256 key size)
       */
      keys.hmac_key_len = OVPN_DATA_HMAC_KEY_SIZE;
      clib_memcpy (keys.encrypt_hmac_key, static_key + hmac_encrypt_offset,
		   keys.hmac_key_len);
      clib_memcpy (keys.decrypt_hmac_key, static_key + hmac_decrypt_offset,
		   keys.hmac_key_len);
    }

  /* Initialize the crypto context */
  return ovpn_crypto_context_init (ctx, cipher_alg, &keys, replay_window);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
