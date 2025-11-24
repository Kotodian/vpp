/*
 * ovpn_timer.c - OpenVPN timer callback
 *
 * Copyright (c) <current-year> <your-organization>
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

#include <ovpn/ovpn_reliable.h>
#include <ovpn/ovpn.h>
#include <ovpn/private.h>
#include <ovpn/ovpn_timer.h>
#include <vlib/threads.h>
#include <vppinfra/clib.h>
#include <vppinfra/pool.h>
#include <vppinfra/time.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

void
ovpn_expired_sessions_callback (u32 *expired_timers)
{
  ovpn_main_t *omp = &ovpn_main;
  int i;
  u32 pool_index;
  vlib_main_t *vm = vlib_get_main ();

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      pool_index = expired_timers[i] & 0x7FFFFFFF;
      vlib_process_signal_event_mt (vm, omp->timer_node_index,
				    OVPN_CTRL_EVENT_TYPE_SESSION_EXPIRED,
				    pool_index);
    }
}

void
ovpn_expired_channels_callback (u32 *expired_timers)
{
  ovpn_main_t *omp = &ovpn_main;
  int i;
  u32 pool_index;
  vlib_main_t *vm = vlib_get_main ();

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      pool_index = expired_timers[i] & 0x7FFFFFFF;
      vlib_process_signal_event_mt (vm, omp->timer_node_index,
				    OVPN_CTRL_EVENT_TYPE_CHANNEL_EXPIRED,
				    pool_index);
    }
}

void
ovpn_expired_reliable_queues_callback (u32 *expired_timers)
{
  ovpn_main_t *omp = &ovpn_main;
  int i;
  u32 pool_index, pkt_id;
  vlib_main_t *vm = vlib_get_main ();

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      ovpn_reliable_send_queue_event_t *event =
	clib_mem_alloc (sizeof (ovpn_reliable_send_queue_event_t));

      ovpn_reliable_get_pkt_id_and_queue_index (expired_timers[i], &pkt_id,
						&pool_index);
      vlib_process_signal_event_mt (
	vm, omp->timer_node_index,
	OVPN_CTRL_EVENT_TYPE_RELIABLE_SEND_QUEUE_EXPIRED, (uword) event);
    }
}

void
ovpn_expired_reliable_recv_queues_callback (u32 *expired_timers)
{
  ovpn_main_t *omp = &ovpn_main;
  int i;
  u32 pool_index, pkt_id;
  vlib_main_t *vm = vlib_get_main ();

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      ovpn_reliable_recv_queue_event_t *event =
	clib_mem_alloc (sizeof (ovpn_reliable_recv_queue_event_t));

      ovpn_reliable_get_pkt_id_and_queue_index (expired_timers[i], &pkt_id,
						&pool_index);
      vlib_process_signal_event_mt (
	vm, omp->timer_node_index,
	OVPN_CTRL_EVENT_TYPE_RELIABLE_RECV_QUEUE_EXPIRED, (uword) event);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
