/*
 * ovpn_message.h - ovpn message header file
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

#ifndef __included_ovpn_message_h__
#define __included_ovpn_message_h__

#define OVPN_FRAME_SIZE 100

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <stddef.h>

#define foreach_ovpn_opcode_type                                              \
  _ (P_CONTROL_HARD_RESET_CLIENT_V1, 1)                                       \
  _ (P_CONTROL_HARD_RESET_SERVER_V1, 2)                                       \
  _ (P_CONTROL_SOFT_RESET_V1, 3)                                              \
  _ (P_CONTROL_V1, 4)                                                         \
  _ (P_ACK_V1, 5)                                                             \
  _ (P_DATA_V1, 6)                                                            \
  _ (P_CONTROL_HARD_RESET_CLIENT_V2, 7)                                       \
  _ (P_CONTROL_HARD_RESET_SERVER_V2, 8)

typedef enum ovpn_opcode_type
{
#define _(k, v) OVPN_OPCODE_TYPE_##k = (v),
  foreach_ovpn_opcode_type
#undef _
    OVPN_OPCODE_TYPE_N_TYPE,
} ovpn_opcode_type_t;

typedef struct ip4_udp_header_t_
{
  ip4_header_t ip4;
  udp_header_t udp;
} __clib_packed ip4_udp_header_t;

typedef struct ip6_udp_header_t_
{
  ip6_header_t ip6;
  udp_header_t udp;
} __clib_packed ip6_udp_header_t;

typedef CLIB_PACKED (struct ovpn_msg_hdr {
  u8 opcode : 5;
  u8 key_id : 3;
}) ovpn_msg_hdr_t;

#define OVPN_DATA_PACKET_ID_LEN 8
#define OVPN_DATA_IV_LEN	    12
#define OVPN_DATA_TAG_LEN	    16

typedef CLIB_PACKED (struct ovpn_data_hdr {
  u64 packet_id;
}) ovpn_data_hdr_t;

/*
  session_id: 8 bytes
  hmac: 20 bytes
  replay_packet_id: 4 bytes
  timestamp: 4 bytes
  acks_len: 1 byte
*/

typedef CLIB_PACKED (struct ovpn_ctrl_msg_hdr {
  u64 session_id;
  u8 hmac[20];
  u32 replay_packet_id;
  u32 timestamp;
  u8 acks_len;
}) ovpn_ctrl_msg_hdr_t;

typedef CLIB_PACKED (struct ovpn_ctrl_msg_client_hard_reset_v2 {
  u32 pkt_id;
}) ovpn_ctrl_msg_client_hard_reset_v2_t;

typedef CLIB_PACKED (struct ovpn_ctrl_msg_server_hard_reset_v2 {
  u64 remote_session_id;
}) ovpn_ctrl_msg_server_hard_reset_v2_t;

typedef CLIB_PACKED (struct ovpn_ctrl_msg_ack_v1 {
  u64 session_id;
}) ovpn_ctrl_msg_ack_v1_t;

typedef CLIB_PACKED (struct ovpn_ctrl_msg_control_v1 {
  u32 pkt_id;
}) ovpn_ctrl_msg_control_v1_t;

always_inline void
ip4_header_set_len_w_chksum (ip4_header_t *ip4, u16 len)
{
  ip_csum_t sum = ip4->checksum;
  u16 old = ip4->length;
  u16 new = len;

  sum = ip_csum_update (sum, old, new, ip4_header_t, length);
  ip4->checksum = ip_csum_fold (sum);
  ip4->length = new;
}

#endif /* __included_ovpn_message_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
