/*
 * ovpn_channel.c - ovpn channel source file
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

#include "picotls.h"
#include "picotls/openssl.h"
#include <vppinfra/random.h>
#include <ovpn/ovpn_channel.h>

void
ovpn_channel_init (vlib_main_t *vm, ovpn_channel_t *ch,
		   ptls_context_t *ssl_ctx, u64 remote_session_id,
		   ip46_address_t *remote_addr, u8 is_ip4, u32 ch_index)
{
  clib_memset (ch, 0, sizeof (ovpn_channel_t));
  ch->index = ch_index;
  ch->seed = 0x1badf00d;
  ch->state = OVPN_CHANNEL_STATE_INIT;
  ch->expired_time = vlib_time_now (vm) + OVN_CHANNEL_EXPIRED_TIMEOUT;
  ch->tls = ptls_new (ssl_ctx, 1);
  ch->session_id = random_u64 (&ch->seed);
  ch->remote_session_id = remote_session_id;
  ch->is_ip4 = is_ip4;
  clib_memcpy_fast (&ch->remote_addr, remote_addr, sizeof (ip46_address_t));
}

void
ovpn_channel_derive_key_material (ovpn_channel_t *ch, u8 key[32])
{
}

void
ovpn_channel_free (ovpn_channel_t *ch)
{
  ptls_free (ch->tls);
  vec_free (ch->client_acks);
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
