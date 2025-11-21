
/*
 * ovpn.h - skeleton vpp engine plug-in header file
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
#ifndef __included_ovpn_h__
#define __included_ovpn_h__

#include <ovpn/ovpn_channel.h>
#include <ovpn/ovpn_if.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.h>
#include <ovpn/ovpn_session.h>
#include <ovpn/ovpn_reliable.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>
#include <ovpn/private.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* Control Plane */
  ovpn_ip_pool_t tunnel_ip_pool;
  ip46_address_t src_ip;
  ovpn_if_t if_instance;
  u8 psk[256];
  u8 psk_set;
  u8 enabled;

  /* options */
  u8 *options;
  u32 options_length;

  /* local SSL context */
  ptls_context_t *ptls_ctx;

  /* Node Index */
  u32 ctrl_node_index;
  u32 timer_node_index;
  u32 in4_index;
  u32 in6_index;
  u32 out4_index;
  u32 out6_index;

  /* session lookup table */
  BVT (clib_bihash) session_hash;
  ovpn_session_t *sessions;
  tw_timer_wheel_2t_1w_2048sl_t sessions_timer_wheel;
  /* key2 */
  ovpn_key2_t *key2s;

  /* channel */
  ovpn_channel_t *channels;

  tw_timer_wheel_2t_1w_2048sl_t channels_timer_wheel;

  /* key source */
  ovpn_key_source_t *key_sources;

  /* reliable queue */
  ovpn_reliable_queue_t *reliable_queues;
  tw_timer_wheel_2t_1w_2048sl_t queues_timer_wheel;

  /* per thread data */
  ovpn_per_thread_data_t *per_thread_data;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ip_lookup_main_t *ip4_lm;
  ip_lookup_main_t *ip6_lm;
} ovpn_main_t;

extern ovpn_main_t ovpn_main;

extern vlib_node_registration_t ovpn_timer_process_node;
extern vlib_node_registration_t ovpn_ctrl_process_node;
extern vlib_node_registration_t ovpn4_input_node;
extern vlib_node_registration_t ovpn6_input_node;

#endif /* __included_ovpn_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
