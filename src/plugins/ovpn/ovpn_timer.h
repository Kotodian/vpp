/*
 * ovpn_timer.h - OpenVPN timer callback
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
#ifndef __included_ovpn_timer_h__
#define __included_ovpn_timer_h__

#include <vppinfra/clib.h>

void ovpn_expired_sessions_callback (u32 *expired_timers);
void ovpn_expired_channels_callback (u32 *expired_timers);
void ovpn_expired_reliable_queues_callback (u32 *expired_timers);
void ovpn_expired_reliable_recv_queues_callback (u32 *expired_timers);

#endif /* __included_ovpn_timer_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */