/*
 * options.h - ovpn options header file
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
#ifndef __included_ovpn_options_h__
#define __included_ovpn_options_h__

#include <vnet/ip/ip_types.h>
#include <vnet/fib/fib_types.h>
#include <vlib/vlib.h>

#define OVPN_DEFAULT_SEQ_BACKTRACK  64
#define OVPN_DEFAULT_TIME_BACKTRACK 15

typedef struct ovpn_options_t_
{

  /* Network */
  u16 listen_port;
  /* Only support UDP */
  u32 proto;

  /* Tunnel device related*/
  char *dev_name;
  u32 sw_if_index; /* Software interface index */
  fib_prefix_t server_addr;
  u16 mtu;
  u8 is_tun;

  /* TLS */
  u8 *ca_cert;
  u8 *server_cert;
  u8 *server_key;
  u8 *dh_params;
  u8 *cipher_name;
  u8 *auth_name;

  /* Replay */
  u8 replay_protection;
  u32 replay_window;
  u32 replay_time;

  /* Negotiation */
  u32 renegotiate_seconds;  /* Renegotiate data channel key after n seconds */
  u64 renegotiate_bytes;    /* Renegotiate after n bytes transferred (0=disabled) */
  u64 renegotiate_packets;  /* Renegotiate after n packets (0=disabled) */
  u32 handshake_window;     /* TLS handshake must complete within n seconds */
  u32 transition_window;    /* Old key allowed to live n seconds after new key */
  u32 tls_timeout;          /* Control channel packet retransmit timeout */

  /* Client*/
  ip_address_t pool_start;
  ip_address_t pool_end;
  u32 max_clients;

  /* Keepalive */
  u32 keepalive_ping;
  u32 keepalive_timeout;

  /* Optional*/
  u8 *tls_crypt_key;
  u8 *tls_crypt_v2_key;  /* TLS-Crypt-V2 server key */
  u8 *tls_auth_key;
} ovpn_options_t;

bool string_defined_equal (const char *s1, const char *s2);
void ovpn_options_init (ovpn_options_t *opts);

u8 ovpn_options_cmp_equal_safe (char *actual, const char *expected,
				size_t actual_n);

/*
 * Compare two strings, returning 1 if they are equal, 0 otherwise.
 */
u8 ovpn_options_cmp_equal (char *actual, const char *expected);

/**
 * Given an OpenVPN options string, extract the value of an option.
 *
 * @param options_string Zero-terminated, comma-separated options string
 * @param opt_name The name of the option to extract
 * @return The value of the option, or NULL if the option is not found, You
 * should free the returned string using clib_mem_free().
 */
char *ovpn_options_string_extract_option (const char *options_string,
					  const char *opt_name);

/**
 * Build the server's options string to send to the client in Key Method 2.
 *
 * The options string contains the negotiated cipher, virtual IP assignment,
 * and other settings that the client needs to know about.
 *
 * @param buf Buffer to write options string into
 * @param buf_len Length of buffer
 * @param cipher_name Name of negotiated cipher (e.g., "AES-256-GCM")
 * @param use_tls_ekm Whether to use TLS-EKM for key derivation
 * @param peer_id Peer ID for this connection
 * @param virtual_ip Virtual IP address to assign to client (can be NULL)
 * @param virtual_netmask Netmask for the virtual IP (can be NULL)
 * @return Length of options string written (including null terminator),
 *         or < 0 on error
 */
int ovpn_options_string_build_server (char *buf, u32 buf_len,
				      const char *cipher_name, u8 use_tls_ekm,
				      u32 peer_id, const ip_address_t *virtual_ip,
				      const ip_address_t *virtual_netmask);

/**
 * Get cipher name string from cipher algorithm enum
 */
const char *ovpn_cipher_alg_to_name (u8 cipher_alg);

#endif /* __included_ovpn_options_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
