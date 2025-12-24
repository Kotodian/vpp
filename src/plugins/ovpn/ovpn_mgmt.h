/*
 * ovpn_mgmt.h - OpenVPN management interface (UDP based via VPP session layer)
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>
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

#ifndef __included_ovpn_mgmt_h__
#define __included_ovpn_mgmt_h__

#include <vlib/vlib.h>
#include <vnet/ip/ip_types.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>

/*
 * OpenVPN Management Interface (UDP based)
 *
 * This implements the OpenVPN management interface protocol over UDP
 * using VPP's native session layer (no Linux kernel networking).
 *
 * See: https://openvpn.net/community-docs/management-interface.html
 */

/* Maximum length of a single command line */
#define OVPN_MGMT_MAX_CMD_LEN 4096

/* Maximum UDP datagram size */
#define OVPN_MGMT_MAX_DGRAM_SIZE 65536

/* Maximum number of management clients tracked per instance */
#define OVPN_MGMT_MAX_CLIENTS 32

/* Client timeout (seconds) - remove inactive clients */
#define OVPN_MGMT_CLIENT_TIMEOUT 300

/* Default management port */
#define OVPN_MGMT_DEFAULT_PORT 7505

/* Real-time notification types */
typedef enum
{
  OVPN_MGMT_NOTIFY_NONE = 0,
  OVPN_MGMT_NOTIFY_BYTECOUNT,	  /* >BYTECOUNT:bytes_in,bytes_out */
  OVPN_MGMT_NOTIFY_BYTECOUNT_CLI, /* >BYTECOUNT_CLI:cid,bytes_in,bytes_out */
  OVPN_MGMT_NOTIFY_CLIENT,	  /* >CLIENT:event,... */
  OVPN_MGMT_NOTIFY_ECHO,	  /* >ECHO:timestamp,string */
  OVPN_MGMT_NOTIFY_FATAL,	  /* >FATAL:message */
  OVPN_MGMT_NOTIFY_HOLD,	  /* >HOLD:state */
  OVPN_MGMT_NOTIFY_INFO,	  /* >INFO:message */
  OVPN_MGMT_NOTIFY_LOG,		  /* >LOG:timestamp,flags,message */
  OVPN_MGMT_NOTIFY_STATE,	  /* >STATE:timestamp,state,desc,... */
} ovpn_mgmt_notify_type_t;

/* Client events for >CLIENT notification */
typedef enum
{
  OVPN_MGMT_CLIENT_CONNECT = 0,	    /* New client connected */
  OVPN_MGMT_CLIENT_DISCONNECT,	    /* Client disconnected */
  OVPN_MGMT_CLIENT_REAUTH,	    /* Client reauthenticating */
  OVPN_MGMT_CLIENT_ESTABLISHED,	    /* Client connection established */
  OVPN_MGMT_CLIENT_ADDRESS,	    /* Client address changed */
  OVPN_MGMT_CLIENT_CR_RESPONSE,	    /* Challenge-response received */
  OVPN_MGMT_CLIENT_PF,		    /* Packet filter update */
} ovpn_mgmt_client_event_t;

/* State values for >STATE notification */
typedef enum
{
  OVPN_MGMT_STATE_CONNECTING = 0,
  OVPN_MGMT_STATE_WAIT,
  OVPN_MGMT_STATE_AUTH,
  OVPN_MGMT_STATE_GET_CONFIG,
  OVPN_MGMT_STATE_ASSIGN_IP,
  OVPN_MGMT_STATE_ADD_ROUTES,
  OVPN_MGMT_STATE_CONNECTED,
  OVPN_MGMT_STATE_RECONNECTING,
  OVPN_MGMT_STATE_EXITING,
  OVPN_MGMT_STATE_RESOLVE,
  OVPN_MGMT_STATE_TCP_CONNECT,
} ovpn_mgmt_state_t;

/* Log message flags */
typedef enum
{
  OVPN_MGMT_LOG_FLAG_INFO = 0x1,    /* I - informational */
  OVPN_MGMT_LOG_FLAG_WARN = 0x2,    /* W - warning */
  OVPN_MGMT_LOG_FLAG_ERROR = 0x4,   /* E - error */
  OVPN_MGMT_LOG_FLAG_DEBUG = 0x8,   /* D - debug */
  OVPN_MGMT_LOG_FLAG_FATAL = 0x10,  /* F - fatal */
  OVPN_MGMT_LOG_FLAG_NOTICE = 0x20, /* N - notice */
} ovpn_mgmt_log_flags_t;

/* Per-client notification settings */
typedef struct ovpn_mgmt_notify_settings_t_
{
  /* bytecount notification interval (seconds, 0=disabled) */
  u32 bytecount_interval;

  /* State notification enabled */
  u8 state_enabled : 1;

  /* Log notification enabled */
  u8 log_enabled : 1;

  /* Echo notification enabled */
  u8 echo_enabled : 1;

  /* Hold notification enabled */
  u8 hold_enabled : 1;

  /* Log verbosity level (0-15) */
  u8 log_verbosity;

} ovpn_mgmt_notify_settings_t;

/*
 * Management client tracked by remote IP:port
 * Since UDP is connectionless, we track "clients" by their address
 */
typedef struct ovpn_mgmt_client_t_
{
  /* Client key: remote address and port */
  ip_address_t remote_addr;
  u16 remote_port;

  /* Associated instance ID */
  u32 instance_id;

  /* Notification settings for this client */
  ovpn_mgmt_notify_settings_t notify;

  /* Last activity time */
  f64 last_activity_time;

  /* Last bytecount notification time */
  f64 last_bytecount_time;

  /* Client authenticated (if password required) */
  u8 authenticated;

} ovpn_mgmt_client_t;

/* Log entry for history */
typedef struct ovpn_mgmt_log_entry_t_
{
  f64 timestamp;
  u8 flags;
  u8 *message;
} ovpn_mgmt_log_entry_t;

/* State entry for history */
typedef struct ovpn_mgmt_state_entry_t_
{
  f64 timestamp;
  ovpn_mgmt_state_t state;
  u8 *description;
  ip_address_t local_ip;
  ip_address_t remote_ip;
} ovpn_mgmt_state_entry_t;

/* Per-instance management context */
typedef struct ovpn_mgmt_t_
{
  /* Instance ID this management context belongs to */
  u32 instance_id;

  /* Local binding */
  ip_address_t bind_addr;
  u16 bind_port;

  /* Session layer app index */
  u32 app_index;

  /* UDP session handle for listening */
  session_handle_t udp_session_handle;

  /* Hash table: remote_addr:port -> client index */
  uword *client_by_key;

  /* Pool of tracked clients */
  ovpn_mgmt_client_t *clients;

  /* Password for management authentication (NULL=no auth) */
  u8 *password;

  /* Hold flag - if set, daemon waits for "hold release" before starting */
  u8 hold;

  /* Current state */
  ovpn_mgmt_state_t state;

  /* Log history (ring buffer) */
  ovpn_mgmt_log_entry_t *log_history;
  u32 log_history_size;
  u32 log_history_head;
  u32 log_history_count;

  /* State history (ring buffer) */
  ovpn_mgmt_state_entry_t *state_history;
  u32 state_history_size;
  u32 state_history_head;
  u32 state_history_count;

  /* Echo buffer (ring buffer) */
  u8 **echo_history;
  f64 *echo_timestamps;
  u32 echo_history_size;
  u32 echo_history_head;
  u32 echo_history_count;

  /* Is management interface active */
  u8 is_active;

} ovpn_mgmt_t;

/* Global management state */
typedef struct ovpn_mgmt_main_t_
{
  /* Pool of management contexts (one per instance with mgmt enabled) */
  ovpn_mgmt_t *contexts;

  /* Lookup: instance_id -> mgmt context index */
  uword *context_by_instance_id;

  /* For convenience */
  vlib_main_t *vm;

  /* Session layer app attached */
  u8 app_attached;

  /* Global app index for all management interfaces */
  u32 app_index;

} ovpn_mgmt_main_t;

extern ovpn_mgmt_main_t ovpn_mgmt_main;

/*
 * Management interface API
 */

/*
 * Enable management interface for an OpenVPN instance (UDP only)
 *
 * @param vm vlib_main_t pointer
 * @param instance_id OpenVPN instance ID
 * @param bind_addr IP address to bind to (NULL for any)
 * @param bind_port UDP port to listen on
 * @param password Management password (NULL for no authentication)
 * @return 0 on success, <0 on error
 */
int ovpn_mgmt_enable (vlib_main_t *vm, u32 instance_id,
		      const ip_address_t *bind_addr, u16 bind_port,
		      const u8 *password);

/*
 * Disable management interface for an instance
 *
 * @param vm vlib_main_t pointer
 * @param instance_id OpenVPN instance ID
 * @return 0 on success, <0 on error
 */
int ovpn_mgmt_disable (vlib_main_t *vm, u32 instance_id);

/*
 * Get management context for an instance
 *
 * @param instance_id OpenVPN instance ID
 * @return Management context or NULL if not enabled
 */
ovpn_mgmt_t *ovpn_mgmt_get_by_instance (u32 instance_id);

/*
 * Send notification to all connected management clients
 *
 * @param mgmt Management context
 * @param type Notification type
 * @param format printf-style format string
 * @param ... Format arguments
 */
void ovpn_mgmt_notify (ovpn_mgmt_t *mgmt, ovpn_mgmt_notify_type_t type,
		       const char *format, ...);

/*
 * Send client event notification
 *
 * @param mgmt Management context
 * @param event Client event type
 * @param peer_id Peer ID
 * @param common_name Client common name
 * @param real_addr Client real address
 */
void ovpn_mgmt_notify_client_event (ovpn_mgmt_t *mgmt,
				    ovpn_mgmt_client_event_t event,
				    u32 peer_id, const char *common_name,
				    const ip_address_t *real_addr,
				    u16 real_port);

/*
 * Send state change notification
 *
 * @param mgmt Management context
 * @param state New state
 * @param description State description
 * @param local_ip Local IP (for CONNECTED state)
 * @param remote_ip Remote IP (for CONNECTED state)
 */
void ovpn_mgmt_notify_state_change (ovpn_mgmt_t *mgmt, ovpn_mgmt_state_t state,
				    const char *description,
				    const ip_address_t *local_ip,
				    const ip_address_t *remote_ip);

/*
 * Log a message and send to management clients
 *
 * @param mgmt Management context
 * @param flags Log message flags
 * @param format printf-style format string
 * @param ... Format arguments
 */
void ovpn_mgmt_log (ovpn_mgmt_t *mgmt, u8 flags, const char *format, ...);

/*
 * Add echo message to history
 *
 * @param mgmt Management context
 * @param message Echo message string
 */
void ovpn_mgmt_echo (ovpn_mgmt_t *mgmt, const u8 *message);

/*
 * Process bytecount notifications
 * Called periodically to send bandwidth updates to clients
 *
 * @param mgmt Management context
 * @param now Current time
 */
void ovpn_mgmt_process_bytecount (ovpn_mgmt_t *mgmt, f64 now);

/*
 * Set hold state
 *
 * @param mgmt Management context
 * @param hold 1 to enable hold, 0 to disable
 */
void ovpn_mgmt_set_hold (ovpn_mgmt_t *mgmt, u8 hold);

/*
 * Release hold (called when client sends "hold release")
 *
 * @param mgmt Management context
 */
void ovpn_mgmt_hold_release (ovpn_mgmt_t *mgmt);

/*
 * Format helpers
 */
u8 *format_ovpn_mgmt_state (u8 *s, va_list *args);
u8 *format_ovpn_mgmt_log_flags (u8 *s, va_list *args);

/*
 * Initialize management subsystem
 *
 * @param vm vlib_main_t pointer
 */
void ovpn_mgmt_init (vlib_main_t *vm);

/* For compatibility - these now call ovpn_mgmt_enable */
#define ovpn_mgmt_enable_tcp(vm, inst, addr, port, pw)                        \
  ovpn_mgmt_enable (vm, inst, addr, port, pw)
#define ovpn_mgmt_enable_unix(vm, inst, path, pw)                             \
  (-1) /* Unix socket not supported in UDP-only mode */

#endif /* __included_ovpn_mgmt_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
