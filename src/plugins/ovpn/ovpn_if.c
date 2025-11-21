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

#include <vnet/ip/ip_interface.h>
#include <vnet/adj/adj_midchain.h>
#include <ovpn/ovpn_if.h>
#include <ovpn/ovpn.h>

static u8 *
format_ovpn_if_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "ovpn%d", dev_instance);
}

u8 *
format_ovpn_if (u8 *s, va_list *args)
{
  index_t ovpnii = va_arg (*args, index_t);
  ovpn_main_t *omp = &ovpn_main;
  ovpn_if_t *ovpni = &omp->if_instance;
  return format (s, "[%d] %U src:%U", ovpnii, format_vnet_sw_if_index_name,
		 vnet_get_main (), ovpni->sw_if_index);
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

int
ovpn_if_create (index_t *sw_if_indexp)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 hw_if_index;
  vnet_hw_interface_t *hi;

  ASSERT (sw_if_indexp);

  *sw_if_indexp = (u32) ~0;

  hw_if_index = vnet_register_interface (vnm, ovpn_if_device_class.index, 0,
					 ovpn_hw_interface_class.index, 0);
  hi = vnet_get_hw_interface (vnm, hw_if_index);
  *sw_if_indexp = hi->sw_if_index;

  vnet_set_interface_l3_output_node (vnm->vlib_main, hi->sw_if_index,
				     (u8 *) "tunnel-output");
  vnet_feature_enable_disable ("ip4-output", "ovpn4-output-tun",
			       hi->sw_if_index, 1, 0, 0);
  vnet_feature_enable_disable ("ip6-output", "ovpn6-output-tun",
			       hi->sw_if_index, 1, 0, 0);

  return 0;
}

int
ovpn_if_delete (ovpn_if_t *ovpnii, index_t sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi;
  /* pool_free (ovpnii); - single instance, no pool */
  hi = vnet_get_hw_interface (vnm, sw_if_index);
  vnet_delete_hw_interface (vnm, hi->hw_if_index);
  return 0;
}

int
ovpn_if_add_peer (ovpn_if_t *ovpnii, ovpn_ip_pool_t *ip_pool, u32 sess_index,
		  u32 *index)
{
  ovpn_peer_t *peer;
  ip46_address_t ip;
  pool_get (ovpnii->peers, peer);
  ovpn_ip_pool_alloc (ip_pool, &ip);
  *index = peer - ovpnii->peers;
  ovpn_peer_init (peer, *index, &ip, sess_index);
  return 0;
}

int
ovpn_if_remove_peer (ovpn_if_t *ovpnii, u32 peer_index)
{
  if (pool_is_free_index (ovpnii->peers, peer_index))
    return -1;
  pool_put_index (ovpnii->peers, peer_index);
  return 0;
}