/*
 * ovpn_if.c - OpenVPN interface implementation
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
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/adj/adj_midchain.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <ovpn/ovpn_if.h>
#include <ovpn/ovpn.h>

ovpn_if_main_t ovpn_if_main;

/* Device class instance counter */
static u32 ovpn_instance_counter = 0;

/* Get OpenVPN interface from sw_if_index */
ovpn_if_t *
ovpn_if_get_from_sw_if_index (u32 sw_if_index)
{
  ovpn_if_main_t *oim = &ovpn_if_main;
  uword *p;

  p = hash_get (oim->ovpn_if_index_by_sw_if_index, sw_if_index);
  if (p == 0)
    return NULL;

  return pool_elt_at_index (oim->ovpn_ifs, p[0]);
}

/* Format OpenVPN interface name */
u8 *
format_ovpn_if_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  ovpn_if_main_t *oim = &ovpn_if_main;
  ovpn_if_t *oif = pool_elt_at_index (oim->ovpn_ifs, dev_instance);

  if (oif->name && vec_len (oif->name) > 0)
    return format (s, "%s", oif->name);
  else
    return format (s, "ovpn%u", dev_instance);
}

/* Format OpenVPN interface details */
u8 *
format_ovpn_if (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  ovpn_if_main_t *oim = &ovpn_if_main;
  ovpn_if_t *oif = pool_elt_at_index (oim->ovpn_ifs, dev_instance);

  if (oif->name && vec_len (oif->name) > 0)
    s = format (s, "%s", oif->name);
  else
    s = format (s, "ovpn%u", dev_instance);

  s = format (s, "\n  Mode: %s", oif->is_tun ? "TUN (L3)" : "TAP (L2)");

  if (ip_address_is_zero (&oif->local_addr) == 0)
    s = format (s, "\n  Local:  %U:%u", format_ip_address, &oif->local_addr,
		oif->local_port);

  if (ip_address_is_zero (&oif->remote_addr) == 0)
    s = format (s, "\n  Remote: %U:%u", format_ip_address, &oif->remote_addr,
		oif->remote_port);

  return s;
}

/* Unformat OpenVPN interface name */
uword
unformat_ovpn_if (unformat_input_t *input, va_list *args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 instance;

  if (unformat (input, "ovpn%u", &instance))
    {
      *result = instance;
      return 1;
    }
  return 0;
}

/* Device class admin up/down function */
static clib_error_t *
ovpn_if_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
		   VNET_HW_INTERFACE_FLAG_LINK_UP :
		   0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);
  return 0;
}

/*
 * Update adjacency callback for OpenVPN interface
 * Converts neighbor adjacencies into midchain adjacencies that
 * will be processed by the OpenVPN output nodes
 */
static void
ovpn_if_update_adj (vnet_main_t *vnm, u32 sw_if_index, adj_index_t ai)
{
  ovpn_main_t *omp = &ovpn_main;
  ovpn_peer_t *peer;
  ip_adjacency_t *adj;

  adj = adj_get (ai);

  /*
   * Convert any neighbour adjacency that has a next-hop reachable through
   * the ovpn interface into a midchain. This is to avoid sending ARP/ND to
   * resolve the next-hop address via the ovpn interface.
   */
  adj_nbr_midchain_update_rewrite (ai, NULL, NULL, ADJ_FLAG_NONE, NULL);

  /*
   * Find a peer that matches the adjacency's next-hop
   * For OpenVPN, we look for an established peer on this interface
   */
  pool_foreach (peer, omp->multi_context.peer_db.peers)
    {
      if (peer->sw_if_index != sw_if_index)
	continue;
      if (peer->state != OVPN_PEER_STATE_ESTABLISHED)
	continue;

      /*
       * Check if this peer's virtual IP matches the adjacency next-hop
       * or if we're in P2P mode (any packet goes to the single peer)
       */
      int match = 0;

      if (peer->virtual_ip_set)
	{
	  /* Check if next-hop matches virtual IP */
	  if (adj->ia_nh_proto == FIB_PROTOCOL_IP4 && !peer->virtual_ip.version)
	    {
	      if (ip4_address_compare (&adj->sub_type.nbr.next_hop.ip4,
				       &peer->virtual_ip.ip.ip4) == 0)
		match = 1;
	    }
	  else if (adj->ia_nh_proto == FIB_PROTOCOL_IP6 &&
		   peer->virtual_ip.version)
	    {
	      if (ip6_address_compare (&adj->sub_type.nbr.next_hop.ip6,
				       &peer->virtual_ip.ip.ip6) == 0)
		match = 1;
	    }
	}
      else
	{
	  /* P2P mode - accept any destination */
	  match = 1;
	}

      if (match)
	{
	  /* Associate this adjacency with the peer */
	  ovpn_peer_adj_index_add (peer->peer_id, ai);

	  /* Update the midchain with the peer's rewrite */
	  adj_nbr_midchain_update_rewrite (ai, NULL, NULL,
					   ADJ_FLAG_MIDCHAIN_IP_STACK,
					   vec_dup (peer->rewrite));

	  /* Stack the adjacency */
	  ovpn_peer_adj_stack (peer, ai);
	  break;
	}
    }
}

/* Register OpenVPN device class */
VNET_DEVICE_CLASS (ovpn_device_class) = {
  .name = "OpenVPN",
  .format_device_name = format_ovpn_if_name,
  .format_device = format_ovpn_if,
  .admin_up_down_function = ovpn_if_admin_up_down,
};

/* Register OpenVPN hardware interface class */
VNET_HW_INTERFACE_CLASS (ovpn_hw_interface_class) = {
  .name = "OpenVPN",
  .update_adjacency = ovpn_if_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_NBMA,
};

/* Create OpenVPN interface */
int
ovpn_if_create (vlib_main_t *vm __attribute__ ((unused)), u8 *name, u8 is_tun,
		u16 mtu, u32 *sw_if_indexp)
{
  ovpn_if_main_t *oim = &ovpn_if_main;
  vnet_main_t *vnm = oim->vnet_main;
  ovpn_if_t *oif;
  vnet_eth_interface_registration_t eir = {};
  u32 dev_instance;
  u32 hw_if_index;
  u8 address[6] = {
    [0] = 0x02, /* locally administered */
    [1] = 0xfe,
  };

  /* Allocate interface instance */
  pool_get_zero (oim->ovpn_ifs, oif);
  dev_instance = oif - oim->ovpn_ifs;
  oif->dev_instance = dev_instance;
  oif->user_instance = ovpn_instance_counter++;
  oif->is_tun = is_tun;

  /* Store custom interface name */
  if (name && vec_len (name) > 0)
    {
      oif->name = vec_dup (name);
    }
  else
    {
      /* Generate default name if not provided */
      oif->name = format (0, "ovpn%u", dev_instance);
    }

  /* Generate MAC address */
  address[5] = dev_instance & 0xff;
  address[4] = (dev_instance >> 8) & 0xff;
  address[3] = (dev_instance >> 16) & 0xff;
  address[2] = (dev_instance >> 24) & 0xff;

  if (is_tun)
    {
      /* TUN mode - create as hardware interface with ovpn_hw_interface_class */
      vnet_hw_interface_t *hi;

      hw_if_index =
	vnet_register_interface (vnm, ovpn_device_class.index, dev_instance,
				 ovpn_hw_interface_class.index, dev_instance);

      hi = vnet_get_hw_interface (vnm, hw_if_index);
      oif->hw_if_index = hw_if_index;
      oif->sw_if_index = hi->sw_if_index;
    }
  else
    {
      /* TAP mode - create as ethernet interface */
      eir.dev_class_index = ovpn_device_class.index;
      eir.dev_instance = dev_instance;
      eir.address = address;
      hw_if_index = vnet_eth_register_interface (vnm, &eir);

      vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
      oif->hw_if_index = hw_if_index;
      oif->sw_if_index = hi->sw_if_index;
    }

  /* Rename hardware interface to use custom name */
  if (oif->name && vec_len (oif->name) > 0)
    {
      vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
      vec_free (hi->name);
      hi->name = vec_dup (oif->name);
    }

  /* Set MTU on interface */
  vnet_sw_interface_set_mtu (vnm, oif->sw_if_index, mtu);

  /* Enable interface */
  vnet_sw_interface_set_flags (vnm, oif->sw_if_index,
			       VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  /* Add to hash table */
  hash_set (oim->ovpn_if_index_by_sw_if_index, oif->sw_if_index, dev_instance);

  if (sw_if_indexp)
    *sw_if_indexp = oif->sw_if_index;

  return 0;
}

/* Delete OpenVPN interface */
int
ovpn_if_delete (vlib_main_t *vm __attribute__ ((unused)), u32 sw_if_index)
{
  ovpn_if_main_t *oim = &ovpn_if_main;
  vnet_main_t *vnm = oim->vnet_main;
  ovpn_if_t *oif;

  oif = ovpn_if_get_from_sw_if_index (sw_if_index);
  if (!oif)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Disable interface */
  vnet_sw_interface_set_flags (vnm, sw_if_index, 0);

  /* Delete hardware interface */
  vnet_delete_hw_interface (vnm, oif->hw_if_index);

  /* Remove from hash table */
  hash_unset (oim->ovpn_if_index_by_sw_if_index, sw_if_index);

  /* Free interface name */
  if (oif->name)
    vec_free (oif->name);

  /* Free pool element */
  pool_put (oim->ovpn_ifs, oif);

  return 0;
}

/* Set local address */
int
ovpn_if_set_local_addr (u32 sw_if_index, ip_address_t *addr)
{
  ovpn_if_t *oif = ovpn_if_get_from_sw_if_index (sw_if_index);

  if (!oif)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  ip_address_copy (&oif->local_addr, addr);
  oif->is_ipv6 = (addr->version == AF_IP6);

  return 0;
}

/* Set remote address */
int
ovpn_if_set_remote_addr (u32 sw_if_index, ip_address_t *addr)
{
  ovpn_if_t *oif = ovpn_if_get_from_sw_if_index (sw_if_index);

  if (!oif)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  ip_address_copy (&oif->remote_addr, addr);

  return 0;
}

/* CLI command to create OpenVPN interface */
static clib_error_t *
ovpn_if_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd __attribute__ ((unused)))
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = 0;
  u8 is_tun = 1;
  u16 mtu = 1420; /* Default MTU */
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected interface name");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %s", &name))
	;
      else if (unformat (line_input, "tun"))
	is_tun = 1;
      else if (unformat (line_input, "tap"))
	is_tun = 0;
      else if (unformat (line_input, "mtu %u", &mtu))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = ovpn_if_create (vm, name, is_tun, mtu, &sw_if_index);

  if (rv < 0)
    {
      error = clib_error_return (0, "failed to create OpenVPN interface");
      goto done;
    }

  vlib_cli_output (vm, "Created OpenVPN interface: %U (sw_if_index %u)",
		   format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index,
		   sw_if_index);

done:
  vec_free (name);
  unformat_free (line_input);
  return error;
}

/* CLI command to delete OpenVPN interface */
static clib_error_t *
ovpn_if_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd __attribute__ ((unused)))
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected interface");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "interface not specified");
      goto done;
    }

  rv = ovpn_if_delete (vm, sw_if_index);

  if (rv < 0)
    {
      error = clib_error_return (0, "failed to delete OpenVPN interface");
      goto done;
    }

  vlib_cli_output (vm, "Deleted OpenVPN interface");

done:
  unformat_free (line_input);
  return error;
}

/* CLI command: create ovpn interface */
VLIB_CLI_COMMAND (ovpn_if_create_command, static) = {
  .path = "create ovpn interface",
  .short_help = "create ovpn interface name <name> [tun|tap] [mtu <size>]",
  .function = ovpn_if_create_command_fn,
};

/* CLI command: delete ovpn interface */
VLIB_CLI_COMMAND (ovpn_if_delete_command, static) = {
  .path = "delete ovpn interface",
  .short_help = "delete ovpn interface <interface>",
  .function = ovpn_if_delete_command_fn,
};

/* Initialize OpenVPN interface subsystem */
static clib_error_t *
ovpn_if_init (vlib_main_t *vm)
{
  ovpn_if_main_t *oim = &ovpn_if_main;

  oim->vlib_main = vm;
  oim->vnet_main = vnet_get_main ();
  oim->ovpn_if_index_by_sw_if_index = hash_create (0, sizeof (uword));

  return 0;
}

VLIB_INIT_FUNCTION (ovpn_if_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
