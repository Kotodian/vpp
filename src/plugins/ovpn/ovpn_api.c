/*
 * ovpn_api.c - OpenVPN Binary API implementation
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>
#include <vlibapi/api.h>

#include <ovpn/ovpn.api_enum.h>
#include <ovpn/ovpn.api_types.h>

#include <ovpn/ovpn.h>
#include <ovpn/ovpn_if.h>
#include <ovpn/ovpn_mgmt.h>

#define REPLY_MSG_ID_BASE omp->msg_id_base
#include <vlibapi/api_helper_macros.h>

typedef struct
{
  u16 msg_id_base;
} ovpn_api_main_t;

static ovpn_api_main_t ovpn_api_main;

/*
 * Handler for ovpn_interface_create
 */
static void
vl_api_ovpn_interface_create_t_handler (vl_api_ovpn_interface_create_t *mp)
{
  vl_api_ovpn_interface_create_reply_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;
  ovpn_main_t *om = &ovpn_main;
  ip_address_t local_addr;
  ovpn_options_t options;
  u32 instance_id = ~0;
  u32 sw_if_index = ~0;
  int rv = 0;

  /* Initialize options */
  ovpn_options_init (&options);

  /* Decode local address */
  ip_address_decode2 (&mp->local_addr, &local_addr);

  /* Set device name if provided */
  if (mp->dev_name[0] != 0)
    {
      /* mp->dev_name is a fixed-size array, use format to create a vec */
      options.dev_name = (char *) format (0, "%s", mp->dev_name);
    }

  /* Set TUN/TAP mode (default is TUN) */
  options.is_tun = mp->is_tun;

  /* Handle crypto mode */
  switch (mp->crypto_mode)
    {
    case OVPN_CRYPTO_MODE_STATIC_KEY:
      {
	/* Allocate and copy static key */
	options.static_key = clib_mem_alloc (OVPN_STATIC_KEY_SIZE);
	clib_memcpy (options.static_key, mp->static_key, OVPN_STATIC_KEY_SIZE);
	options.static_key_direction = mp->static_key_direction;
	options.static_key_mode = 1;
      }
      break;

    case OVPN_CRYPTO_MODE_TLS:
    case OVPN_CRYPTO_MODE_TLS_AUTH:
    case OVPN_CRYPTO_MODE_TLS_CRYPT:
      {
	/* Parse variable-length certificates and keys */
	u8 *ptr = mp->certs_and_keys;
	u32 ca_len = clib_net_to_host_u32 (mp->ca_cert_len);
	u32 cert_len = clib_net_to_host_u32 (mp->server_cert_len);
	u32 key_len = clib_net_to_host_u32 (mp->server_key_len);
	u32 tls_auth_len = clib_net_to_host_u32 (mp->tls_auth_key_len);
	u32 tls_crypt_len = clib_net_to_host_u32 (mp->tls_crypt_key_len);

	if (ca_len > 0)
	  {
	    vec_validate (options.ca_cert, ca_len - 1);
	    clib_memcpy (options.ca_cert, ptr, ca_len);
	    ptr += ca_len;
	  }

	if (cert_len > 0)
	  {
	    vec_validate (options.server_cert, cert_len - 1);
	    clib_memcpy (options.server_cert, ptr, cert_len);
	    ptr += cert_len;
	  }

	if (key_len > 0)
	  {
	    vec_validate (options.server_key, key_len - 1);
	    clib_memcpy (options.server_key, ptr, key_len);
	    ptr += key_len;
	  }

	if (mp->crypto_mode == OVPN_CRYPTO_MODE_TLS_AUTH && tls_auth_len > 0)
	  {
	    vec_validate (options.tls_auth_key, tls_auth_len - 1);
	    clib_memcpy (options.tls_auth_key, ptr, tls_auth_len);
	    ptr += tls_auth_len;
	  }

	if (mp->crypto_mode == OVPN_CRYPTO_MODE_TLS_CRYPT && tls_crypt_len > 0)
	  {
	    vec_validate (options.tls_crypt_key, tls_crypt_len - 1);
	    clib_memcpy (options.tls_crypt_key, ptr, tls_crypt_len);
	  }
      }
      break;

    default:
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  /* Create the instance */
  rv = ovpn_instance_create (
    om->vm, &local_addr, clib_net_to_host_u16 (mp->local_port),
    clib_net_to_host_u32 (mp->table_id), &options, &instance_id, &sw_if_index);

done:
  /* Free options memory on failure */
  if (rv != 0)
    {
      vec_free (options.dev_name);
      vec_free (options.ca_cert);
      vec_free (options.server_cert);
      vec_free (options.server_key);
      vec_free (options.tls_auth_key);
      vec_free (options.tls_crypt_key);
      if (options.static_key)
	clib_mem_free (options.static_key);
    }

  REPLY_MACRO2 (VL_API_OVPN_INTERFACE_CREATE_REPLY, ({
		  rmp->sw_if_index = clib_host_to_net_u32 (sw_if_index);
		  rmp->instance_id = clib_host_to_net_u32 (instance_id);
		}));
}

/*
 * Handler for ovpn_interface_delete
 */
static void
vl_api_ovpn_interface_delete_t_handler (vl_api_ovpn_interface_delete_t *mp)
{
  vl_api_ovpn_interface_delete_reply_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = ovpn_instance_delete (vlib_get_main (),
			     clib_net_to_host_u32 (mp->sw_if_index));

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_OVPN_INTERFACE_DELETE_REPLY);
}

/*
 * Walk context for interface dump
 */
typedef struct ovpn_interface_dump_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} ovpn_interface_dump_ctx_t;

/*
 * Send interface details
 */
static void
ovpn_send_interface_details (ovpn_instance_t *instance,
			     ovpn_interface_dump_ctx_t *ctx)
{
  vl_api_ovpn_interface_details_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;

  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
  rmp->_vl_msg_id =
    clib_host_to_net_u16 (VL_API_OVPN_INTERFACE_DETAILS + omp->msg_id_base);
  rmp->context = ctx->context;

  /* Fill interface details */
  rmp->interface.sw_if_index = clib_host_to_net_u32 (instance->sw_if_index);
  rmp->interface.instance_id = clib_host_to_net_u32 (instance->instance_id);
  ip_address_encode2 (&instance->local_addr, &rmp->interface.local_addr);
  rmp->interface.local_port = clib_host_to_net_u16 (instance->local_port);
  rmp->interface.table_id = clib_host_to_net_u32 (instance->fib_table_id);

  /* Determine crypto mode */
  if (instance->options.static_key_mode)
    rmp->interface.crypto_mode = OVPN_CRYPTO_MODE_STATIC_KEY;
  else if (instance->tls_crypt.enabled)
    rmp->interface.crypto_mode = OVPN_CRYPTO_MODE_TLS_CRYPT;
  else if (instance->tls_auth.enabled)
    rmp->interface.crypto_mode = OVPN_CRYPTO_MODE_TLS_AUTH;
  else
    rmp->interface.crypto_mode = OVPN_CRYPTO_MODE_TLS;

  /* Copy device name */
  if (instance->options.dev_name)
    {
      strncpy ((char *) rmp->interface.dev_name, instance->options.dev_name,
	       sizeof (rmp->interface.dev_name) - 1);
    }

  /* Count peers */
  rmp->num_peers =
    clib_host_to_net_u32 (pool_elts (instance->multi_context.peer_db.peers));

  vl_api_send_msg (ctx->reg, (u8 *) rmp);
}

/*
 * Handler for ovpn_interface_dump
 */
static void
vl_api_ovpn_interface_dump_t_handler (vl_api_ovpn_interface_dump_t *mp)
{
  vl_api_registration_t *reg;
  ovpn_main_t *om = &ovpn_main;
  ovpn_instance_t *instance;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == NULL)
    return;

  ovpn_interface_dump_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);

  if (sw_if_index == ~0)
    {
      /* Dump all instances */
      pool_foreach (instance, om->instances)
	{
	  if (instance->is_active)
	    ovpn_send_interface_details (instance, &ctx);
	}
    }
  else
    {
      /* Dump specific instance */
      instance = ovpn_instance_get_by_sw_if_index (sw_if_index);
      if (instance && instance->is_active)
	ovpn_send_interface_details (instance, &ctx);
    }
}

/*
 * Walk context for peer dump
 */
typedef struct ovpn_peer_dump_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
  u32 instance_id;
} ovpn_peer_dump_ctx_t;

/*
 * Send peer details
 */
static void
ovpn_send_peer_details (ovpn_peer_t *peer, u32 instance_id,
			ovpn_peer_dump_ctx_t *ctx)
{
  vl_api_ovpn_peers_details_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;

  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
  rmp->_vl_msg_id =
    clib_host_to_net_u16 (VL_API_OVPN_PEERS_DETAILS + omp->msg_id_base);
  rmp->context = ctx->context;

  /* Fill peer details */
  rmp->peer.peer_id = clib_host_to_net_u32 (peer->peer_id);
  rmp->peer.instance_id = clib_host_to_net_u32 (instance_id);
  rmp->peer.sw_if_index = clib_host_to_net_u32 (peer->sw_if_index);
  ip_address_encode2 (&peer->remote_addr, &rmp->peer.remote_addr);
  rmp->peer.remote_port = clib_host_to_net_u16 (peer->remote_port);

  if (peer->virtual_ip_set)
    ip_address_encode2 (&peer->virtual_ip, &rmp->peer.virtual_ip);

  rmp->peer.state = (vl_api_ovpn_api_peer_state_t) peer->state;
  rmp->peer.rx_bytes = clib_host_to_net_u64 (peer->rx_bytes);
  rmp->peer.tx_bytes = clib_host_to_net_u64 (peer->tx_bytes);
  rmp->peer.rx_packets = clib_host_to_net_u64 (peer->rx_packets);
  rmp->peer.tx_packets = clib_host_to_net_u64 (peer->tx_packets);
  rmp->peer.established_time = peer->established_time;
  rmp->peer.last_rx_time = peer->last_rx_time;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);
}

/*
 * Handler for ovpn_peers_dump
 */
static void
vl_api_ovpn_peers_dump_t_handler (vl_api_ovpn_peers_dump_t *mp)
{
  vl_api_registration_t *reg;
  ovpn_main_t *om = &ovpn_main;
  ovpn_instance_t *instance;
  ovpn_peer_t *peer;
  u32 sw_if_index;
  u32 peer_id;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == NULL)
    return;

  ovpn_peer_dump_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  peer_id = clib_net_to_host_u32 (mp->peer_id);

  if (sw_if_index == ~0)
    {
      /* Dump peers from all instances */
      pool_foreach (instance, om->instances)
	{
	  if (!instance->is_active)
	    continue;

	  ctx.instance_id = instance->instance_id;

	  if (peer_id == ~0)
	    {
	      /* All peers in this instance */
	      pool_foreach (peer, instance->multi_context.peer_db.peers)
		{
		  if (peer->state != OVPN_PEER_STATE_DEAD)
		    ovpn_send_peer_details (peer, instance->instance_id, &ctx);
		}
	    }
	  else
	    {
	      /* Specific peer */
	      peer = ovpn_peer_get (&instance->multi_context.peer_db, peer_id);
	      if (peer && peer->state != OVPN_PEER_STATE_DEAD)
		ovpn_send_peer_details (peer, instance->instance_id, &ctx);
	    }
	}
    }
  else
    {
      /* Dump peers from specific instance */
      instance = ovpn_instance_get_by_sw_if_index (sw_if_index);
      if (instance && instance->is_active)
	{
	  ctx.instance_id = instance->instance_id;

	  if (peer_id == ~0)
	    {
	      /* All peers */
	      pool_foreach (peer, instance->multi_context.peer_db.peers)
		{
		  if (peer->state != OVPN_PEER_STATE_DEAD)
		    ovpn_send_peer_details (peer, instance->instance_id, &ctx);
		}
	    }
	  else
	    {
	      /* Specific peer */
	      peer = ovpn_peer_get (&instance->multi_context.peer_db, peer_id);
	      if (peer && peer->state != OVPN_PEER_STATE_DEAD)
		ovpn_send_peer_details (peer, instance->instance_id, &ctx);
	    }
	}
    }
}

/*
 * Handler for ovpn_peer_remove
 */
static void
vl_api_ovpn_peer_remove_t_handler (vl_api_ovpn_peer_remove_t *mp)
{
  vl_api_ovpn_peer_remove_reply_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;
  ovpn_main_t *om = &ovpn_main;
  ovpn_instance_t *instance;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  u32 peer_id = clib_net_to_host_u32 (mp->peer_id);

  instance = ovpn_instance_get_by_sw_if_index (sw_if_index);
  if (!instance || !instance->is_active)
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto done;
    }

  /* Use worker barrier for safe peer deletion */
  vlib_worker_thread_barrier_sync (om->vm);
  ovpn_peer_delete (&instance->multi_context.peer_db, peer_id);
  vlib_worker_thread_barrier_release (om->vm);

done:
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_OVPN_PEER_REMOVE_REPLY);
}

/*
 * Handler for ovpn_mgmt_enable_tcp
 */
static void
vl_api_ovpn_mgmt_enable_tcp_t_handler (vl_api_ovpn_mgmt_enable_tcp_t *mp)
{
  vl_api_ovpn_mgmt_enable_tcp_reply_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;
  ip_address_t bind_addr;
  u8 *password = NULL;
  int rv = 0;

  u32 instance_id = clib_net_to_host_u32 (mp->instance_id);
  u16 bind_port = clib_net_to_host_u16 (mp->bind_port);

  ip_address_decode2 (&mp->bind_addr, &bind_addr);

  /* Extract password if provided */
  if (mp->password[0] != 0)
    password = (u8 *) mp->password;

  rv = ovpn_mgmt_enable_tcp (vlib_get_main (), instance_id, &bind_addr,
			     bind_port, password);

  REPLY_MACRO (VL_API_OVPN_MGMT_ENABLE_TCP_REPLY);
}

/*
 * Handler for ovpn_mgmt_enable_unix
 * Note: Unix socket mode is no longer supported. This handler always returns
 * an error. Use ovpn_mgmt_enable_tcp (UDP mode via VPP session layer) instead.
 */
static void
vl_api_ovpn_mgmt_enable_unix_t_handler (vl_api_ovpn_mgmt_enable_unix_t *mp)
{
  vl_api_ovpn_mgmt_enable_unix_reply_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;
  int rv;

  /* Unix socket mode not supported - use UDP mode instead */
  (void) mp;
  rv = VNET_API_ERROR_UNIMPLEMENTED;

  REPLY_MACRO (VL_API_OVPN_MGMT_ENABLE_UNIX_REPLY);
}

/*
 * Handler for ovpn_mgmt_disable
 */
static void
vl_api_ovpn_mgmt_disable_t_handler (vl_api_ovpn_mgmt_disable_t *mp)
{
  vl_api_ovpn_mgmt_disable_reply_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;
  int rv = 0;

  u32 instance_id = clib_net_to_host_u32 (mp->instance_id);

  rv = ovpn_mgmt_disable (vlib_get_main (), instance_id);

  REPLY_MACRO (VL_API_OVPN_MGMT_DISABLE_REPLY);
}

/*
 * Walk context for management dump
 */
typedef struct ovpn_mgmt_dump_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} ovpn_mgmt_dump_ctx_t;

/*
 * Send management details
 */
static void
ovpn_send_mgmt_details (ovpn_mgmt_t *mgmt, ovpn_mgmt_dump_ctx_t *ctx)
{
  vl_api_ovpn_mgmt_details_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;

  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
  rmp->_vl_msg_id =
    clib_host_to_net_u16 (VL_API_OVPN_MGMT_DETAILS + omp->msg_id_base);
  rmp->context = ctx->context;

  rmp->status.instance_id = clib_host_to_net_u32 (mgmt->instance_id);
  ip_address_encode2 (&mgmt->bind_addr, &rmp->status.bind_addr);
  rmp->status.bind_port = clib_host_to_net_u16 (mgmt->bind_port);
  rmp->status.num_clients = clib_host_to_net_u32 (pool_elts (mgmt->clients));
  rmp->status.password_required = (mgmt->password != NULL);
  rmp->status.hold = mgmt->hold;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);
}

/*
 * Handler for ovpn_mgmt_dump
 */
static void
vl_api_ovpn_mgmt_dump_t_handler (vl_api_ovpn_mgmt_dump_t *mp)
{
  vl_api_registration_t *reg;
  ovpn_mgmt_main_t *mm = &ovpn_mgmt_main;
  ovpn_mgmt_t *mgmt;
  u32 instance_id;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == NULL)
    return;

  ovpn_mgmt_dump_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  instance_id = clib_net_to_host_u32 (mp->instance_id);

  if (instance_id == ~0)
    {
      /* Dump all management interfaces */
      pool_foreach (mgmt, mm->contexts)
	{
	  if (mgmt->is_active)
	    ovpn_send_mgmt_details (mgmt, &ctx);
	}
    }
  else
    {
      /* Dump specific instance */
      mgmt = ovpn_mgmt_get_by_instance (instance_id);
      if (mgmt && mgmt->is_active)
	ovpn_send_mgmt_details (mgmt, &ctx);
    }
}

/* Setup API message handlers */
#include <ovpn/ovpn.api.c>

static clib_error_t *
ovpn_api_hookup (vlib_main_t *vm)
{
  ovpn_api_main_t *omp = &ovpn_api_main;
  omp->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (ovpn_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
