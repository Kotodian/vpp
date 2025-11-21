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

static index_t
ovpn_if_peer_walk (ovpn_if_t *ovpni, ovpn_if_peer_walk_cb_t fn, void *data)
{
  index_t peeri, val;
  hash_foreach (peeri, val, ovpni->peers, {
    if (WALK_STOP == fn (peeri, data))
      return peeri;
  });
  return INDEX_INVALID;
}

void
ovpn_if_update_adj (vnet_main_t *vnm, u32 sw_if_index, adj_index_t ai)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_if_t *ovpni = &omp->if_instance;

  adj_nbr_midchain_update_rewrite (ai, NULL, NULL, ADJ_FLAG_NONE, NULL);

  ovpn_if_peer_walk (ovpni, ovpn_peer_if_adj_change, &ai);
}

VNET_DEVICE_CLASS (ovpn_if_device_class) = {
  .name = "OpenVPN Tunnel",
  .format_device_name = format_ovpn_if_name,
  .admin_up_down_function = ovpn_if_admin_up_down,
};

VNET_HW_INTERFACE_CLASS (ovpn_hw_interface_class) = {
  .name = "OpenVPN",
  .update_adjacency = ovpn_if_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_NBMA,
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

always_inline u8 *
ovpn_build_rewrite (ip46_address_t *src, u16 src_port, ip46_address_t *dst,
		    u16 dst_port, u8 is_ip4)
{
  if (ip46_address_is_zero (dst) || 0 == dst_port)
    return NULL;

  u8 *rewrite = NULL;
  if (is_ip4)
    {
      ip4_udp_header_t *hdr;

      vec_validate (rewrite, sizeof (ip4_udp_ovpn_header_t) - 1);

      hdr = (ip4_udp_header_t *) rewrite;
      hdr->ip4.ip_version_and_header_length = 0x45;
      hdr->ip4.ttl = 64;
      hdr->ip4.src_address = src->ip4;
      hdr->ip4.dst_address = dst->ip4;
      hdr->ip4.protocol = IP_PROTOCOL_UDP;
      hdr->ip4.checksum = ip4_header_checksum (&hdr->ip4);

      hdr->udp.src_port = clib_host_to_net_u16 (src_port);
      hdr->udp.dst_port = clib_host_to_net_u16 (dst_port);
      hdr->udp.checksum = 0;
    }
  else
    {
      ip6_udp_header_t *hdr;

      vec_validate (rewrite, sizeof (ip6_udp_header_t) - 1);
      hdr = (ip6_udp_header_t *) rewrite;
      hdr->ip6.ip_version_traffic_class_and_flow_label = 0x60;
      ip6_address_copy (&hdr->ip6.src_address, &src->ip6);
      ip6_address_copy (&hdr->ip6.dst_address, &dst->ip6);
      hdr->ip6.protocol = IP_PROTOCOL_UDP;
      hdr->ip6.hop_limit = 64;
      hdr->udp.src_port = clib_host_to_net_u16 (src_port);
      hdr->udp.dst_port = clib_host_to_net_u16 (dst_port);
      hdr->udp.checksum = 0;
    }

  return rewrite;
}

int
ovpn_if_add_peer (ovpn_if_t *ovpnii, ovpn_ip_pool_t *ip_pool, u32 sess_index,
		  u32 *index, ip46_address_t *src, ip46_address_t *dst,
		  u16 dst_port, u8 is_ip4)
{
  ovpn_peer_t *peer;
  ip46_address_t ip;
  u8 *rewrite;
  pool_get (ovpnii->peers, peer);
  ovpn_ip_pool_alloc (ip_pool, &ip);
  ovpn_peer_create (index, &ip, ovpn_ip_pool_is_ip4 (ip_pool), src, dst,
		    dst_port, is_ip4, sess_index);
  rewrite = ovpn_build_rewrite (src, UDP_DST_PORT_ovpn, dst, dst_port, is_ip4);
  peer->rewrite = rewrite;
  hash_set (ovpnii->peers, *index, *index);
  return 0;
}

int
ovpn_if_remove_peer (ovpn_if_t *ovpnii, u32 peer_index)
{
  hash_unset (ovpnii->peers, peer_index);
  ovpn_peer_delete (peer_index);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */