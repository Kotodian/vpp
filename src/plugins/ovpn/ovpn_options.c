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
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
