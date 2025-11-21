/*
 * ovpn_peer.h - ovpn peer header file
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

#ifndef __included_ovpn_peer_h__
#define __included_ovpn_peer_h__

#include "vnet/adj/adj.h"
#include <vnet/udp/udp_local.h>
#include <ovpn/ovpn_message.h>
#include <vnet/ip/ip.h>
#include <vlib/vlib.h>

typedef struct ip4_udp_ovpn_header
{
  ip4_udp_header_t ip4_udp;
  ovpn_msg_hdr_t ovpn_msg_hdr;
  u8 iv[OVPN_DATA_IV_LEN];
  u8 data[];
} __clib_packed ip4_udp_ovpn_header_t;

typedef struct ip6_udp_ovpn_header
{
  ip6_udp_header_t ip6_udp;
  ovpn_msg_hdr_t ovpn_msg_hdr;
  u8 iv[OVPN_DATA_IV_LEN];
  u8 data[];
} __clib_packed ip6_udp_ovpn_header_t;

typedef struct ovpn_peer_endpoint
{
  ip46_address_t addr;
  u16 port;
} ovpn_peer_endpoint_t;

typedef struct ovpn_peer
{
  u32 index;

  u32 input_thread_index;
  u32 output_thread_index;
  u32 sess_index;

  /* tunnel ip */
  u8 tunnel_is_ip4;
  ip46_address_t tunnel_ip;

  /* Peer addresses */
  u8 is_ip4;
  ovpn_peer_endpoint_t src;
  ovpn_peer_endpoint_t dst;

  /* rewrite built from address information */
  u8 *rewrite;
} ovpn_peer_t;

int ovpn_peer_create (u32 *index, ip46_address_t *tunnel_ip, u8 tunnel_is_ip4,
		      ip46_address_t *src, ip46_address_t *dst, u16 dst_port,
		      u8 is_ip4, u32 sess_index);
int ovpn_peer_delete (index_t peeri);
ovpn_peer_t *ovpn_peer_get (index_t peeri);
void ovpn_peer_adj_stack (ovpn_peer_t *peer, adj_index_t ai);
void ovpn_peer_adj_reset_stacking (adj_index_t ai);
adj_midchain_fixup_t ovpn_peer_get_fixup (ovpn_peer_t *peer, vnet_link_t lt);
walk_rc_t ovpn_peer_if_adj_change (index_t peeri, void *data);

extern index_t *ovpn_peer_by_adj_index;

always_inline index_t
ovpn_peer_get_by_adj_index (adj_index_t ai)
{
  if (ai == ADJ_INDEX_INVALID)
    return INDEX_INVALID;
  if (ai >= vec_len (ovpn_peer_by_adj_index))
    return INDEX_INVALID;
  return ovpn_peer_by_adj_index[ai];
}

#endif /* __included_ovpn_peer_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
