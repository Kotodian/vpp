/*
 * ovpn_reliable.c - ovpn reliable source file
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

#include "vppinfra/pool.h"
#include <ovpn/ovpn_reliable.h>

void
ovpn_reliable_queue_init (vlib_main_t *vm, ovpn_reliable_queue_t *queue,
			  u32 channel_index, u32 index)
{
  clib_memset (queue, 0, sizeof (ovpn_reliable_queue_t));
  queue->index = index;
  queue->channel_index = channel_index;
  queue->retrans_time = vlib_time_now (vm) + OVN_RELIABLE_RETRANS_TIMEOUT;
  queue->next_recv_pkt_id = 1;
  queue->recv_pkts_wnd_keys = NULL;
  queue->unacked_pkts_by_pkt_id = NULL;
  queue->recv_pkts_wnd = NULL;
  queue->unacked_pkts = NULL;
  queue->next_send_pkt_id = 0;
}
always_inline void
ovpn_reliable_free_pkt (ovpn_reliable_queue_t *queue, ovpn_reliable_pkt_t *pkt,
			u8 is_ack)
{
  vec_free (pkt->data);
  if (is_ack)
    {
      hash_unset (queue->unacked_pkts_by_pkt_id, &pkt->pkt_id);
      pool_put (queue->unacked_pkts, pkt);
    }
  else
    {
      hash_unset (queue->recv_pkts_wnd_keys, &pkt->pkt_id);
      pool_put (queue->recv_pkts_wnd, pkt);
    }
}

void
ovpn_reliable_queue_free (ovpn_reliable_queue_t *queue)
{
  if (queue->recv_pkts_wnd != NULL)
    {
      ovpn_reliable_pkt_t *pkt;
      pool_foreach (pkt, queue->recv_pkts_wnd)
	{
	  ovpn_reliable_free_pkt (queue, pkt, 0);
	}
      pool_free (queue->recv_pkts_wnd);
    }
  if (queue->recv_pkts_wnd_keys != NULL)
    hash_free (queue->recv_pkts_wnd_keys);
  if (queue->unacked_pkts_by_pkt_id != NULL)
    hash_free (queue->unacked_pkts_by_pkt_id);
  if (queue->unacked_pkts != NULL)
    pool_free (queue->unacked_pkts);
}

u32
ovpn_reliable_queue_pkt (vlib_main_t *vm, ovpn_reliable_queue_t *queue,
			 u8 is_ip4, u8 *data, u32 data_len)
{
  ovpn_reliable_pkt_t *pkt;
  pool_get (queue->unacked_pkts, pkt);
  u32 index = pkt - queue->unacked_pkts;
  if (queue->next_send_pkt_id == ~0)
    queue->next_send_pkt_id = 0;
  pkt->pkt_id = queue->next_send_pkt_id++;
  pkt->send.is_ip4 = is_ip4;
  pkt->data_len = data_len;
  clib_memset (pkt->send.reserved, 0, 3);
  vec_validate_init_empty (pkt->data, data_len - 1, ~0);
  clib_memcpy_fast (pkt->data, data, data_len);
  pkt->send.retries = 0;
  hash_set (queue->unacked_pkts_by_pkt_id, &pkt->pkt_id, index);
  return pkt->pkt_id;
}

void
ovpn_reliable_dequeue_pkt (vlib_main_t *vm, ovpn_reliable_queue_t *queue,
			   u32 pkt_id)
{
  uword *p = NULL;
  u32 index = ~0;

  p = hash_get (queue->unacked_pkts_by_pkt_id, &pkt_id);
  if (p == NULL)
    return;
  index = p[0];
  ovpn_reliable_pkt_t *pkt = pool_elt_at_index (queue->unacked_pkts, index);
  ovpn_reliable_free_pkt (queue, pkt, 0);
}

int
ovpn_reliable_retransmit_pkt (vlib_main_t *vm, ovpn_reliable_queue_t *queue,
			      u32 pkt_id, ovpn_reliable_pkt_t **pkt)
{
  uword *p = NULL;
  u32 index = ~0;
  p = hash_get (queue->unacked_pkts_by_pkt_id, &pkt_id);
  if (p == NULL)
    return -1;
  index = p[0];
  if (index == ~0)
    return -1;
  *pkt = pool_elt_at_index (queue->unacked_pkts, index);
  (*pkt)->send.retries++;
  if ((*pkt)->send.retries > OVN_RELIABLE_MAX_RETRIES)
    {
      ovpn_reliable_free_pkt (queue, *pkt, 1);
      *pkt = NULL;
      return -1;
    }
  return 0;
}

/*
  -1: drop: TODO handle replay
  0: queued
  1: received
  2: received and acked
*/
int
ovpn_reliable_queue_recv_pkt (vlib_main_t *vm, ovpn_reliable_queue_t *queue,
			      u32 pkt_id, u8 *data, u32 data_len)
{
  ovpn_reliable_pkt_t *expired_pkt;
  ovpn_reliable_pkt_t *new_pkt = NULL;
  uword *p = NULL;
  p = hash_get (queue->recv_pkts_wnd_keys, &pkt_id);
  if (p != NULL)
    {
      new_pkt = pool_elt_at_index (queue->recv_pkts_wnd, p[0]);
      if (new_pkt->recv.acked)
	return 2;
      return 1;
    }

  if (pool_elts (queue->recv_pkts_wnd) >= OVPN_RELIABLE_MAX_RECV_SIZE)
    {
      for (u32 i = 0; i < OVPN_RELIABLE_MAX_RECV_SIZE / 2; i++)
	{
	  if (!pool_is_free_index (queue->recv_pkts_wnd, i))
	    {
	      expired_pkt = pool_elt_at_index (queue->recv_pkts_wnd, i);
	      ovpn_reliable_free_pkt (queue, expired_pkt, 0);
	    }
	}
    }
  pool_get (queue->recv_pkts_wnd, new_pkt);
  if (new_pkt == NULL)
    return -1;
  new_pkt->pkt_id = pkt_id;
  new_pkt->recv.acked = 0;
  new_pkt->recv.consumed = 0;
  new_pkt->data_len = data_len;
  vec_validate_init_empty (new_pkt->data, data_len - 1, ~0);
  clib_memcpy_fast (new_pkt->data, data, data_len);
  hash_set (queue->recv_pkts_wnd_keys, &pkt_id,
	    (uword) (new_pkt - queue->recv_pkts_wnd));
  return 0;
}

void
ovpn_reliable_dequeue_recv_pkt (vlib_main_t *vm, ovpn_reliable_queue_t *queue,
				ovpn_reliable_pkt_t **pkt)
{
  *pkt = NULL;

  while (1)
    {
      uword *p =
	hash_get (queue->recv_pkts_wnd_keys, &queue->next_recv_pkt_id);
      if (p == NULL)
	return;

      ovpn_reliable_pkt_t *cur =
	pool_elt_at_index (queue->recv_pkts_wnd, p[0]);

      if (cur->recv.consumed < cur->data_len)
	{
	  *pkt = cur;
	  return;
	}

      /* 当前 pkt 已消费完，推进 next_recv_pkt_id */
      queue->next_recv_pkt_id += 1;
    }
}

void
ovpn_reliable_ack_recv_pkt (vlib_main_t *vm, ovpn_reliable_queue_t *queue,
			    u32 pkt_id)
{
  uword *p = NULL;
  p = hash_get (queue->recv_pkts_wnd_keys, &pkt_id);
  if (p == NULL)
    return;
  ovpn_reliable_pkt_t *pkt = pool_elt_at_index (queue->recv_pkts_wnd, p[0]);
  ASSERT (pkt->recv.consumed < pkt->data_len);
  pkt->recv.acked = 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
