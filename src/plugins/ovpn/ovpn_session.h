/*
 * ovpn_session.h - ovpn session header file
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

#ifndef __included_ovpn_session_h__
#define __included_ovpn_session_h__

#include "vnet/ip/ip46_address.h"
#include <vlib/vlib.h>
#include <stddef.h>

#define OVPN_SESSION_HASH_BUCKETS   1024
#define OVPN_SESSION_HASH_MEMORY    0
#define OVN_SESSION_EXPIRED_TIMEOUT (120 * 60) /* 2 minutes */

#define foreach_ovpn_session_error                                            \
  _ (NONE, "No error")                                                        \
  _ (SESSION_NOT_FOUND, "Session not found")                                  \
  _ (SESSION_ALREADY_EXISTS, "Session already exists")

typedef enum ovpn_session_error
{
#define _(sym, str) OVPN_SESSION_ERROR_##sym,
  foreach_ovpn_session_error
#undef _
    OVPN_SESSION_N_ERROR,
} ovpn_session_error_t;

#define foreach_ovpn_session_state                                            \
  _ (NEW, "New")                                                              \
  _ (HANDSHAKING, "Handshaking")                                              \
  _ (ACTIVE, "Active")                                                        \
  _ (REKEYING, "Reykeing")

typedef enum ovpn_session_state
{
#define _(sym, str) OVPN_SESSION_STATE_##sym,
  foreach_ovpn_session_state
#undef _
    OVPN_SESSION_N_STATE,
} ovpn_session_state_t;

typedef struct ovpn_session_t
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  ip46_address_t remote_addr;
  ovpn_session_state_t state;
  u32 channel_index;
  u32 index;
  u32 key2_index;
  u32 peer_index;
  u32 input_thread_index;
  u8 is_ip4;
} ovpn_session_t;

void ovpn_session_init (vlib_main_t *vm, ovpn_session_t *session, u32 index,
			ip46_address_t *remote_addr, u8 is_ip4);

void ovpn_session_free (ovpn_session_t *session);

#endif /* __included_ovpn_session_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
