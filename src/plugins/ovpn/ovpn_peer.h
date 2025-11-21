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

#include <vnet/ip/ip.h>
#include <vlib/vlib.h>

typedef struct ovpn_peer_endpoint
{
  ip46_address_t addr;
  u16 port;
} ovpn_peer_endpoint_t;

typedef struct ovpn_peer
{
  u32 index;
  u32 sess_index;
  ip46_address_t ip;
} ovpn_peer_t;

static inline void
ovpn_peer_init (ovpn_peer_t *peer, u32 index, ip46_address_t *ip,
		u32 sess_index)
{
  peer->index = index;
  peer->sess_index = sess_index;
  ip46_address_copy (ip, &peer->ip);
}
