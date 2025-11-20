/*
 * ovpn_if.h - ovpn interface header file
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>.
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

#ifndef __included_ovpn_if_h__
#define __included_ovpn_if_h__

#include <stdbool.h>
#include "vnet/ip/ip46_address.h"
#include "vnet/ip/ip_types.h"
#include <vlib/vlib.h>

typedef struct ovpn_if_t_
{
  u32 sw_if_index;
  u32 ip_pool_index;

  /* Source IP address for originated packets */
  ip46_address_t src_ip;
} ovpn_if_t;

typedef struct ovpn_ip_pool
{
  ip_prefix_t prefix;
  ip46_address_t next_ip;
  ip46_address_t last_ip;
} ovpn_ip_pool_t;

always_inline void
ovpn_ip_pool_init (ovpn_ip_pool_t *pool, ip_prefix_t prefix)
{
  ip4_address_t max_ip4;
  ip6_address_t max_ip6;
  pool->prefix = prefix;
  ip_prefix_normalize (&pool->prefix);

  if (ip_prefix_version (&pool->prefix) == AF_IP4)
    {
      ip46_address_set_ip4 (&pool->next_ip, &ip_prefix_v4 (&pool->prefix));
      ip4_prefix_max_address_host_order (&ip_prefix_v4 (&pool->prefix),
					 ip_prefix_len (&pool->prefix),
					 &max_ip4);
      max_ip4.as_u32 = clib_host_to_net_u32 (max_ip4.as_u32);
      ip46_address_set_ip4 (&pool->last_ip, &max_ip4);
    }
  else
    {
      ip46_address_set_ip6 (&pool->next_ip, &ip_prefix_v6 (&pool->prefix));
      ip6_prefix_max_address_host_order (&ip_prefix_v6 (&pool->prefix),
					 ip_prefix_len (&pool->prefix),
					 &max_ip6);
      max_ip6.as_u64[0] = clib_host_to_net_u64 (max_ip6.as_u64[0]);
      max_ip6.as_u64[1] = clib_host_to_net_u64 (max_ip6.as_u64[1]);
      ip46_address_set_ip6 (&pool->last_ip, &max_ip6);
    }
}

static_always_inline int
ovpn_ip_pool_compare (ip_address_family_t af, const ip46_address_t *a,
		      const ip46_address_t *b)
{
  if (af == AF_IP4)
    {
      u32 ah = clib_net_to_host_u32 (a->ip4.as_u32);
      u32 bh = clib_net_to_host_u32 (b->ip4.as_u32);
      if (ah < bh)
	return -1;
      if (ah > bh)
	return 1;
      return 0;
    }

  u64 a_hi = clib_net_to_host_u64 (a->as_u64[0]);
  u64 b_hi = clib_net_to_host_u64 (b->as_u64[0]);
  if (a_hi < b_hi)
    return -1;
  if (a_hi > b_hi)
    return 1;

  u64 a_lo = clib_net_to_host_u64 (a->as_u64[1]);
  u64 b_lo = clib_net_to_host_u64 (b->as_u64[1]);
  if (a_lo < b_lo)
    return -1;
  if (a_lo > b_lo)
    return 1;

  return 0;
}

always_inline bool
ovpn_ip_pool_alloc (ovpn_ip_pool_t *pool, ip46_address_t *result)
{
  ip_address_family_t af = ip_prefix_version (&pool->prefix);

  int cmp = ovpn_ip_pool_compare (af, &pool->next_ip, &pool->last_ip);
  if (result)
    ip46_address_copy (result, &pool->next_ip);

  if (cmp == 0)
    {
      if (af == AF_IP4)
	ip46_address_set_ip4 (&pool->next_ip, &ip_prefix_v4 (&pool->prefix));
      else
	ip46_address_set_ip6 (&pool->next_ip, &ip_prefix_v6 (&pool->prefix));
      return true;
    }

  if (af == AF_IP4)
    ip4_address_increment (&pool->next_ip.ip4);
  else
    ip6_address_increment (&pool->next_ip.ip6);

  if (ovpn_ip_pool_compare (af, &pool->next_ip, &pool->last_ip) > 0)
    {
      if (af == AF_IP4)
	ip46_address_set_ip4 (&pool->next_ip, &ip_prefix_v4 (&pool->prefix));
      else
	ip46_address_set_ip6 (&pool->next_ip, &ip_prefix_v6 (&pool->prefix));
    }

  return true;
}

#endif /* __included_ovpn_if_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
