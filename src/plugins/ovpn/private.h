/*
 * private.h - ovpn private header file
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
#ifndef __included_ovpn_private_h__
#define __included_ovpn_private_h__

#include <vnet/ip/ip.h>

#define foreach_ovpn_ctrl_event_type                                          \
  _ (HARD_RESET_CLIENT_V2, "Hard reset client v2")                            \
  _ (SOFT_RESET_V1, "Soft reset v1")                                          \
  _ (CONTROL_V1, "Control v1")                                                \
  _ (ACK_V1, "Ack v1")                                                        \
  _ (SESSION_EXPIRED, "Session expired")                                      \
  _ (CHANNEL_EXPIRED, "Channel expired")                                      \
  _ (RELIABLE_SEND_QUEUE_EXPIRED, "Reliable send queue expired")

typedef enum ovpn_ctrl_event_type
{
#define _(sym, str) OVPN_CTRL_EVENT_TYPE_##sym,
  foreach_ovpn_ctrl_event_type
#undef _
    OVPN_CTRL_EVENT_TYPE_N_TYPE,
} ovpn_ctrl_event_type_t;

typedef struct ovpn_ctrl_event_hard_reset_client_v2
{
  u8 hmac[20];
  ip46_address_t remote_addr;
  u8 is_ip4;
  u64 remote_session_id;
  u32 pkt_id;
  u16 client_port;
} ovpn_ctrl_event_hard_reset_client_v2_t;

typedef struct ovpn_ctrl_event_ack_v1
{
  u8 hmac[20];
  ip46_address_t remote_addr;
  u64 remote_session_id;
  u64 session_id;
  u32 *acks;
  u8 acks_len;
} ovpn_ctrl_event_ack_v1_t;

typedef struct ovpn_reliable_send_queue_event
{
  u32 queue_index;
  u32 pkt_id;
} ovpn_reliable_send_queue_event_t;

#endif /* __included_ovpn_private_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
