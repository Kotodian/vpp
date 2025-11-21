/*
 * ovpn_peer.c - ovpn peer implementation file
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
#include <vnet/adj/adj.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/fib/fib_table.h>
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_if.h>

ovpn_peer_t *ovpn_peer_pool;
index_t *ovpn_peer_by_adj_index;

int
ovpn_peer_create (u32 *index, ip46_address_t *tunnel_ip, u8 tunnel_is_ip4,
		  ip46_address_t *src, ip46_address_t *dst, u16 dst_port,
		  u8 is_ip4, u32 sess_index)
{
  ovpn_peer_t *peer;
  pool_get (ovpn_peer_pool, peer);
  *index = peer - ovpn_peer_pool;
  peer->index = *index;
  peer->sess_index = sess_index;
  ip46_address_copy (&peer->tunnel_ip, tunnel_ip);
  peer->tunnel_is_ip4 = tunnel_is_ip4;
  ip46_address_copy (&peer->src.addr, src);
  peer->src.port = UDP_DST_PORT_ovpn;
  ip46_address_copy (&peer->dst.addr, dst);
  peer->dst.port = dst_port;
  peer->is_ip4 = is_ip4;
  peer->input_thread_index = ~0;
  peer->output_thread_index = ~0;
  peer->rewrite = NULL;
  return 0;
}

int
ovpn_peer_delete (index_t peeri)
{
  ovpn_peer_t *peer;
  peer = ovpn_peer_get (peeri);
  if (peer->rewrite)
    vec_free (peer->rewrite);
  pool_put_index (ovpn_peer_pool, peeri);
  return 0;
}

ovpn_peer_t *
ovpn_peer_get (index_t peeri)
{
  return pool_elt_at_index (ovpn_peer_pool, peeri);
}

always_inline bool
ovpn_peer_can_send (ovpn_peer_t *peer)
{
  return peer && peer->rewrite && peer->sess_index != INDEX_INVALID;
}

void
ovpn_peer_adj_reset_stacking (adj_index_t ai)
{
  adj_midchain_delegate_remove (ai);
}

void
ovpn_peer_adj_stack (ovpn_peer_t *peer, adj_index_t ai)
{
  ip_adjacency_t *adj;
  u32 sw_if_index;
  fib_protocol_t fib_proto;

  if (!adj_is_valid (ai))
    return;

  adj = adj_get (ai);
  sw_if_index = adj->rewrite_header.sw_if_index;
  u8 is_ip4 = ip46_address_is_ip4 (&peer->src.addr);
  fib_proto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  if (!vnet_sw_interface_is_admin_up (vnet_get_main (), sw_if_index) ||
      !ovpn_peer_can_send (peer))
    {
      ovpn_peer_adj_reset_stacking (ai);
    }
  else
    {
      fib_prefix_t dst = {
	.fp_len = is_ip4 ? 32 : 128,
	.fp_proto = fib_proto,
	.fp_addr = peer->dst.addr,
      };
      u32 fib_index;

      fib_index = fib_table_find (fib_proto, 0);

      adj_midchain_delegate_stack (ai, fib_index, &dst);
    }
}

static void
ovpn_peer_66_fixup (vlib_main_t *vm, const ip_adjacency_t *adj,
		    vlib_buffer_t *b, const void *data)
{
  u8 iph_offset = 0;
  ip6_header_t *ip6_out;
  ip6_header_t *ip6_in;

  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  ip6_out = vlib_buffer_get_current (b);
  iph_offset = vnet_buffer (b)->ip.save_rewrite_length;
  ip6_in = vlib_buffer_get_current (b) + iph_offset;

  ip6_out->ip_version_traffic_class_and_flow_label =
    ip6_in->ip_version_traffic_class_and_flow_label;
}

static void
ovpn_peer_46_fixup (vlib_main_t *vm, const ip_adjacency_t *adj,
		    vlib_buffer_t *b, const void *data)
{
  u8 iph_offset = 0;
  ip6_header_t *ip6_out;
  ip4_header_t *ip4_in;

  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  ip6_out = vlib_buffer_get_current (b);
  iph_offset = vnet_buffer (b)->ip.save_rewrite_length;
  ip4_in = vlib_buffer_get_current (b) + iph_offset;

  u32 vtcfl = 0x4 << 28;
  vtcfl |= ip4_in->tos << 20;
  vtcfl |= vnet_buffer (b)->ip.flow_hash & 0x000fffff;

  ip6_out->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (vtcfl);
}

adj_midchain_fixup_t
ovpn_peer_get_fixup (ovpn_peer_t *peer, vnet_link_t lt)
{
  if (!ip46_address_is_ip4 (&peer->dst.addr))
    {
      if (lt == VNET_LINK_IP4)
	return (ovpn_peer_46_fixup);
      if (lt == VNET_LINK_IP6)
	return (ovpn_peer_66_fixup);
    }
  return (NULL);
}

walk_rc_t
ovpn_peer_if_adj_change (index_t peeri, void *data)
{
  adj_index_t *adj_index = data;
  ovpn_peer_t *peer;
  adj_midchain_fixup_t fixup;

  peer = pool_elt_at_index (ovpn_peer_pool, peeri);
  ovpn_peer_adj_stack (peer, *adj_index);
  vec_validate_init_empty (ovpn_peer_by_adj_index, *adj_index, INDEX_INVALID);
  ovpn_peer_by_adj_index[*adj_index] = peeri;
  fixup = ovpn_peer_get_fixup (peer, adj_get_link_type (*adj_index));
  adj_nbr_midchain_update_rewrite (*adj_index, fixup, NULL,
				   ADJ_FLAG_MIDCHAIN_IP_STACK,
				   vec_dup (peer->rewrite));
  ovpn_peer_adj_stack (peer, *adj_index);

  return (WALK_STOP);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */