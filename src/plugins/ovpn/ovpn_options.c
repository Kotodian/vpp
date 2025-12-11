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
	  ret = clib_mem_alloc (value_len);
	  clib_memcpy_fast (ret, start, value_len);
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
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
