/*
 * ovpn_reliable.h - ovpn reliable header file
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

#ifndef __included_ovpn_reliable_h__
#define __included_ovpn_reliable_h__

#include <vlib/vlib.h>

#define OVN_RELIABLE_MAX_RETRIES     3
#define OVN_RELIABLE_RETRANS_TIMEOUT 2 /* 2 seconds */
#define OVPN_RELIABLE_MAX_RECV_SIZE  10

/* Control packet can only be sent by main thread */
typedef struct ovpn_reliable_pkt
{
  u32 pkt_id;
  union
  {
    struct
    {
      u8 is_ip4;
      u8 retries;
      u8 reserved[3];
    } send;

    struct
    {
      u8 acked;
      u32 consumed;
    } recv;
  };

  u8 *data;
  u32 data_len;
} ovpn_reliable_pkt_t;

typedef struct ovpn_reliable_queue
{
  u32 index;
  u32 channel_index;

  /* recv pkts */
  u32 replay_packet_id;
  uword *recv_pkts_wnd_keys;
  ovpn_reliable_pkt_t *recv_pkts_wnd;
  u32 next_recv_pkt_id;

  /* send pkts */
  uword *unacked_pkts_by_pkt_id;
  ovpn_reliable_pkt_t *unacked_pkts;
  u32 unacked_pkts_len;
  u32 next_send_pkt_id;

  f64 retrans_time;
} ovpn_reliable_queue_t;

/* Send packets functions */
void ovpn_reliable_queue_init (vlib_main_t *vm, ovpn_reliable_queue_t *queue,
			       u32 channel_index, u32 index);
void ovpn_reliable_queue_free (ovpn_reliable_queue_t *queue);
u32 ovpn_reliable_queue_pkt (vlib_main_t *vm, ovpn_reliable_queue_t *queue,
			     u8 is_ip4, u8 *data, u32 data_len);
void ovpn_reliable_dequeue_pkt (vlib_main_t *vm, ovpn_reliable_queue_t *queue,
				u32 pkt_id);
always_inline u32
ovpn_reliable_get_timer_handle (ovpn_reliable_queue_t *queue, u32 pkt_id)
{
  u32 handle = (pkt_id << 31) | queue->index;
  return handle;
}
always_inline void
ovpn_reliable_get_pkt_id_and_queue_index (u32 handle, u32 *pkt_id,
					  u32 *queue_index)
{
  *pkt_id = handle >> 31;
  *queue_index = handle & 0x7FFFFFFF;
}
int ovpn_reliable_retransmit_pkt (vlib_main_t *vm,
				  ovpn_reliable_queue_t *queue, u32 pkt_id,
				  ovpn_reliable_pkt_t **pkt);

/* Recv packets functions */
int ovpn_reliable_queue_recv_pkt (vlib_main_t *vm,
				  ovpn_reliable_queue_t *queue, u32 pkt_id,
				  u8 *data, u32 data_len);

void ovpn_reliable_dequeue_recv_pkt (vlib_main_t *vm,
				     ovpn_reliable_queue_t *queue,
				     ovpn_reliable_pkt_t **pkt);

void ovpn_reliable_get_recv_pkt (ovpn_reliable_queue_t *queue, u32 pkt_id,
				 ovpn_reliable_pkt_t **pkt);

void ovpn_reliable_expire_recv_pkt (vlib_main_t *vm,
				    ovpn_reliable_queue_t *queue, u32 pkt_id);

void ovpn_reliable_ack_recv_pkt (vlib_main_t *vm, ovpn_reliable_queue_t *queue,
				 u32 pkt_id);

#endif /* __included_ovpn_reliable_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
