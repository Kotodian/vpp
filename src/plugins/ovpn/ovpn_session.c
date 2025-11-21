/*
 * ovpn_session.c - ovpn session source file
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

#include <ovpn/ovpn_session.h>

void
ovpn_session_init (vlib_main_t *vm, ovpn_session_t *sess, u32 index,
		   ip46_address_t *remote_addr, u8 is_ip4)
{
  clib_memset (sess, 0, sizeof (ovpn_session_t));
  sess->index = index;
  sess->state = OVPN_SESSION_STATE_NEW;
  sess->channel_index = ~0;
  clib_memcpy_fast (&sess->remote_addr, remote_addr, sizeof (ip46_address_t));
  sess->is_ip4 = is_ip4;
  sess->key2_index = ~0;
  sess->input_thread_index = ~0;
  sess->peer_index = ~0;
}

void
ovpn_session_free (ovpn_session_t *sess)
{
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
