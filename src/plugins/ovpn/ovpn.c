/*
 * ovpn.c - ovpn plugin
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
#include <vlib/threads.h>
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
#include <ovpn/ovpn_if.h>

ovpn_main_t ovpn_main;

static int
ovpn_enable (vlib_main_t *vm, ip46_address_t *src_addr, ip_prefix_t *prefix,
	     u8 *psk)
{
  ovpn_main_t *omp = &ovpn_main;

  omp->src_ip = *src_addr;
  ovpn_ip_pool_init (&omp->tunnel_ip_pool, *prefix);
  if (psk)
    {
      clib_memcpy_fast (omp->psk, psk, 256);
      omp->psk_set = 1;
    }
  omp->enabled = 1;

  return 0;
}

static clib_error_t *
ovpn_enable_cmd (vlib_main_t *vm, unformat_input_t *input,
		 vlib_cli_command_t *cmd)
{
  ovpn_main_t *omp = &ovpn_main;
  ip46_address_t src_addr;
  ip_prefix_t prefix;
  clib_error_t *error = NULL;
  u8 *psk = 0;
  u8 psk_set = 0;
  clib_memset (&src_addr, 0, sizeof (ip46_address_t));

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "src %U", unformat_ip46_address, &src_addr))
	;
      else if (unformat (input, "tunnel-ip %U", unformat_ip_prefix, &prefix))
	;
      else if (unformat (input, "tls-auth-key %U", unformat_hex_string, &psk))
	psk_set = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (omp->enabled)
    {
      goto done;
    }

  if (ip46_address_is_zero (&src_addr))
    {
      error = clib_error_return (0, "Source address is required");
      goto done;
    }

  if (psk_set)
    {
      if (vec_len (psk) != 256)
	{
	  error = clib_error_return (0, "PSK must be 256 bytes");
	  vec_free (psk);
	  goto done;
	}
    }

  ovpn_enable (vm, &src_addr, &prefix, psk);

  vec_free (psk);

done:
  return error;
}

VLIB_CLI_COMMAND (ovpn_cli_enable_command, static) = {
  .path = "ovpn enable",
  .short_help = "ovpn enable <src-ip> tunnel-ip <tunnel-prefix> [tls-auth-key "
		"<hex-string>]",
  .function = ovpn_enable_cmd,
};

static clib_error_t *
ovpn_init (vlib_main_t *vm)
{
  ovpn_main_t *omp = &ovpn_main;
  omp->ip4_lm = &ip4_main.lookup_main;
  omp->ip6_lm = &ip6_main.lookup_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error = 0;

  omp->vlib_main = vm;
  omp->vnet_main = vnet_get_main ();
  omp->enabled = 0;
  omp->psk_set = 0;
  clib_memset (&omp->src_ip, 0, sizeof (ip46_address_t));
  vec_validate_aligned (omp->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  omp->in4_index = vlib_frame_queue_main_init (ovpn4_input_node.index, 0);
  omp->in6_index = vlib_frame_queue_main_init (ovpn6_input_node.index, 0);
  /*
   * TODO: Initialize SSL context
   * 从配置文件中加载SSL证书和密钥以及
   * OpenVPN配置
   */

  /* Initialize session */
  BV (clib_bihash_init)
  (&omp->session_hash, "ovpn session hash table", OVPN_SESSION_HASH_BUCKETS,
   OVPN_SESSION_HASH_MEMORY);
  tw_timer_wheel_init_2t_1w_2048sl (&omp->sessions_timer_wheel,
				    ovpn_expired_sessions_callback, 1.0, ~0);

  /* Initialize channel */
  tw_timer_wheel_init_2t_1w_2048sl (&omp->channels_timer_wheel,
				    ovpn_expired_channels_callback, 1.0, ~0);

  /* Initialize reliable queue */
  tw_timer_wheel_init_2t_1w_2048sl (
    &omp->queues_timer_wheel, ovpn_expired_reliable_queues_callback, 1.0, ~0);

  /* Process Node */
  omp->ctrl_node_index = ovpn_ctrl_process_node.index;
  omp->timer_node_index = ovpn_timer_process_node.index;

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
