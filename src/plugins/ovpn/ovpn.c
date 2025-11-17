/*
 * ovpn.c - skeleton vpp engine plug-in
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

#include <ovpn/ovpn_session.h>
#include "vlib/threads.h"
#include <vppinfra/clib.h>
#include <vppinfra/pool.h>
#include <vppinfra/time.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>
#include <vnet/udp/udp.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ovpn/ovpn.h>
#include <ovpn/private.h>
#include <ovpn/ovpn_reliable.h>
#include <ovpn/ovpn_message.h>
#include <ovpn/ovpn_channel.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>
#include <ovpn/ovpn_timer.h>

ovpn_main_t ovpn_main;

static clib_error_t *
ovpn_init (vlib_main_t *vm)
{
  ovpn_main_t *omp = &ovpn_main;
  clib_error_t *error = 0;

  omp->vlib_main = vm;
  omp->vnet_main = vnet_get_main ();
  clib_memset (&omp->local_addr, 0, sizeof (ip46_address_t));

  omp->in4_index = vlib_frame_queue_main_init (ovpn4_input_node.index, 0);
  omp->in6_index = vlib_frame_queue_main_init (ovpn6_input_node.index, 0);

  /* Initialize session */
  BV (clib_bihash_init) (&omp->session_hash, "ovpn session hash table",
			 OVPN_SESSION_HASH_BUCKETS, OVPN_SESSION_HASH_MEMORY);
  tw_timer_wheel_init_2t_1w_2048sl (&omp->sessions_timer_wheel,
				    ovpn_expired_sessions_callback, 1.0, ~0);

  /* Initialize channel */
  tw_timer_wheel_init_2t_1w_2048sl (&omp->channels_timer_wheel,
				    ovpn_expired_channels_callback, 1.0, ~0);

  /* Initialize reliable queue */
  tw_timer_wheel_init_2t_1w_2048sl (
    &omp->queues_timer_wheel, ovpn_expired_reliable_queues_callback, 1.0, ~0);

  /* TODO: Initialize SSL context */

  /* Process Node */
  omp->ctrl_node_index = ovpn_ctrl_process_node.index;
  omp->timer_node_index = ovpn_timer_process_node.index;

  udp_register_dst_port (vm, UDP_DST_PORT_ovpn, ovpn4_input_node.index, 1);
  udp_register_dst_port (vm, UDP_DST_PORT_ovpn6, ovpn6_input_node.index, 0);

  return error;
}

VLIB_INIT_FUNCTION (ovpn_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "OpenVPN (UDP)",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
