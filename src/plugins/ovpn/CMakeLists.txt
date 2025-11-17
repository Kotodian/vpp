
# Copyright (c) <current-year> <your-organization>
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

vpp_find_path(PICOTLS_INCLUDE_DIR NAMES picotls.h)
vpp_find_library(PICOTLS_CORE_LIBRARY NAMES "libpicotls-core.a")
vpp_find_library(PICOTLS_OPENSSL_LIBRARY NAMES "libpicotls-openssl.a")

list (APPEND PICOTLS_LINK_LIBRARIES
    ${PICOTLS_CORE_LIBRARY}
    ${PICOTLS_OPENSSL_LIBRARY}
)

include_directories(${PICOTLS_INCLUDE_DIR})

add_vpp_plugin(ovpn
  SOURCES
  ovpn.c
  ovpn_node.c
  ovpn_timer.c
  ovpn_session.c 
  ovpn_channel.c
  ovpn_reliable.c
  ovpn.h
  ovpn_message.h
  ovpn_channel.h
  ovpn_reliable.h
  ovpn_session.h
  ovpn_timer.h
  ovpn_if.h
  private.h


  LINK_LIBRARIES ${PICOTLS_LINK_LIBRARIES} ${OPENSSL_LIBRARIES}

  MULTIARCH_SOURCES
  ovpn_node.c
)
