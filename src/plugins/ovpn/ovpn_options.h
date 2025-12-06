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
  u32 renegotiate_seconds;
  u32 handshake_window;
  u32 transition_window;

  /* Client*/
  ip_address_t pool_start;
  ip_address_t pool_end;
  u32 max_clients;

  /* Keepalive */
  u32 keepalive_ping;
  u32 keepalive_timeout;

  /* Optional*/
  u8 *tls_crypt_key;
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
 * should free the returned string using clib_free().
 */
char *ovpn_string_extract_option (const char *options_string,
				  const char *opt_name);

#endif /* __included_ovpn_options_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */