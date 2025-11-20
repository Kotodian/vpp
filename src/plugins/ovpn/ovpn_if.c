/*
 * ovpn_if.c - ovpn interface
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

#include "vnet/ip/ip46_address.h"
#include "vnet/ip/ip_types.h"
#include <vnet/ip/ip_interface.h>
#include <vnet/adj/adj_midchain.h>
#include <ovpn/ovpn_if.h>
#include <ovpn/ovpn.h>

/* pool of interfaces */
ovpn_if_t *ovpn_if_pool;

/* bitmap of Allocated OVPN_ITF instances */
static uword *ovpn_if_instances;

/* vector of interfaces key'd on their sw_if_index */
index_t *ovpn_if_index_by_sw_if_index;

/* vector of interfaces key'd on their tunnel ip */
uword *ovpn_if_index_by_tunnel_ip;

static u8 *
format_ovpn_if_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  ovpn_if_t *ovpni = ovpn_if_get (dev_instance);
  return format (s, "ovpn%d", ovpni->user_instance);
}

u8 *
format_ovpn_if (u8 *s, va_list *args)
{
  index_t ovpnii = va_arg (*args, index_t);
  ovpn_if_t *ovpni = ovpn_if_get (ovpnii);
  return format (s, "[%d] %U src:%U", ovpnii, format_vnet_sw_if_index_name,
		 vnet_get_main (), ovpni->sw_if_index);
}

index_t
ovpn_if_find_by_sw_if_index (u32 sw_if_index)
{
  if (vec_len (ovpn_if_index_by_sw_if_index) <= sw_if_index)
    return INDEX_INVALID;
  u32 ti = ovpn_if_index_by_sw_if_index[sw_if_index];
  if (ti == ~0)
    return INDEX_INVALID;
  return (ti);
}

static clib_error_t *
ovpn_if_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags;

  hw_flags =
    (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP ? VNET_HW_INTERFACE_FLAG_LINK_UP :
					       0);
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return (NULL);
}

void
ovpn_if_update_adj (vnet_main_t *vnm, u32 sw_if_index, adj_index_t ai)
{
  adj_nbr_midchain_update_rewrite (ai, NULL, NULL, ADJ_FLAG_NONE, NULL);
}

VNET_DEVICE_CLASS (ovpn_if_device_class) = {
  .name = "OpenVPN Tunnel",
  .format_device_name = format_ovpn_if_name,
  .admin_up_down_function = ovpn_if_admin_up_down,
};

VNET_HW_INTERFACE_CLASS (ovpn_hw_interface_class) = {
  .name = "OpenVPN",
  .update_adjacency = ovpn_if_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

/*
 * Maintain a bitmap of allocated ovpn_if instance numbers.
 */
#define OVPN_ITF_MAX_INSTANCE (16 * 1024)

static u32
ovpn_if_instance_alloc (u32 want)
{
  /*
   * Check for dynamically allocated instance number.
   */
  if (~0 == want)
    {
      u32 bit;

      bit = clib_bitmap_first_clear (ovpn_if_instances);
      if (bit >= OVPN_ITF_MAX_INSTANCE)
	{
	  return ~0;
	}
      ovpn_if_instances = clib_bitmap_set (ovpn_if_instances, bit, 1);
      return bit;
    }

  if (want >= OVPN_ITF_MAX_INSTANCE)
    {
      return ~0;
    }

  if (clib_bitmap_get (ovpn_if_instances, want))
    {
      return ~0;
    }

  ovpn_if_instances = clib_bitmap_set (ovpn_if_instances, want, 1);

  return want;
}

static int
ovpn_if_instance_free (u32 instance)
{
  if (instance >= OVPN_ITF_MAX_INSTANCE)
    {
      return -1;
    }
  if (clib_bitmap_get (ovpn_if_instances, instance) == 0)
    {
      return -1;
    }

  ovpn_if_instances = clib_bitmap_set (ovpn_if_instances, instance, 0);
  return 0;
}

int
ovpn_if_create (u32 user_instance, const ip46_address_t *tunnel_ip, u8 is_ip4,
		index_t *sw_if_indexp, index_t sess_index)
{
  ovpn_main_t *omp = &ovpn_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 instance, hw_if_index;
  vnet_hw_interface_t *hi;
  ovpn_if_t *ovpni;
  ip4_address_fib_t ip4_af;
  ip6_address_fib_t ip6_af;

  ASSERT (sw_if_indexp);

  *sw_if_indexp = (u32) ~0;

  instance = ovpn_if_instance_alloc (user_instance);
  if (instance == ~0)
    return VNET_API_ERROR_INVALID_REGISTRATION;

  pool_get_zero (ovpn_if_pool, ovpni);

  ovpni->user_instance = instance;

  hw_if_index =
    vnet_register_interface (vnm, ovpn_if_device_class.index, instance,
			     ovpn_hw_interface_class.index, instance);
  hi = vnet_get_hw_interface (vnm, hw_if_index);
  ovpni->sw_if_index = *sw_if_indexp = hi->sw_if_index;

  vec_validate_init_empty (ovpn_if_index_by_sw_if_index, hi->sw_if_index,
			   INDEX_INVALID);
  ovpn_if_index_by_sw_if_index[hi->sw_if_index] = instance;
  ovpni->sw_if_index = *sw_if_indexp = hi->sw_if_index;
  ovpni->sess_index = sess_index;
  if (is_ip4)
    {
      ip4_addr_fib_init (&ip4_af, &tunnel_ip->ip4, 0);
      ip4_prefix_max_address_host_order (&ip4_af.ip4_addr, 32,
					 &ip4_af.ip4_addr);
      ip_interface_address_add (omp->ip4_lm, hi->sw_if_index, &ip4_af, 32,
				&ovpni->tunnel_ip_index);
    }
  else
    {
      ip6_addr_fib_init (&ip6_af, &tunnel_ip->ip6, 0);
      ip6_prefix_max_address_host_order (&ip6_af.ip6_addr, 128,
					 &ip6_af.ip6_addr);
      ip_interface_address_add (omp->ip6_lm, hi->sw_if_index, &ip6_af, 128,
				&ovpni->tunnel_ip_index);
    }

  vnet_set_interface_l3_output_node (vnm->vlib_main, hi->sw_if_index,
				     (u8 *) "tunnel-output");
  vnet_feature_enable_disable ("ip4-output", "ovpn4-output-tun",
			       hi->sw_if_index, 1, 0, 0);
  vnet_feature_enable_disable ("ip6-output", "ovpn6-output-tun",
			       hi->sw_if_index, 1, 0, 0);

  return 0;
}

int
ovpn_if_delete (u32 sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  ovpn_if_t *ovpni;
  index_t ovpnii = ovpn_if_find_by_sw_if_index (sw_if_index);
  vnet_hw_interface_t *hi;
  hi = vnet_get_hw_interface (vnm, sw_if_index);
  if (ovpnii == INDEX_INVALID)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  ovpni = ovpn_if_get (ovpnii);
  if (ovpni == NULL)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX_2;
  if (ovpn_if_instance_free (ovpni->user_instance) < 0)
    return VNET_API_ERROR_INVALID_VALUE;
  vnet_delete_hw_interface (vnm, hi->hw_if_index);
  pool_put (ovpn_if_pool, ovpni);
  return 0;
}