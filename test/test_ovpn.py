#!/usr/bin/env python3
"""OpenVPN plugin tests"""

import unittest
import os
from vpp_interface import VppInterface
from vpp_papi import VppEnum
from asfframework import tag_run_solo
from framework import VppTestCase

"""
OpenVPN plugin test module.

Tests the OpenVPN Binary API functionality including:
- Interface creation and deletion
- Static key mode configuration
- Interface dump operations
"""

# OpenVPN static key size (256 bytes)
OVPN_STATIC_KEY_SIZE = 256


def generate_static_key():
    """Generate a random 256-byte static key for testing."""
    return os.urandom(OVPN_STATIC_KEY_SIZE)


class VppOvpnInterface(VppInterface):
    """
    VPP OpenVPN interface
    """

    def __init__(
        self,
        test,
        src,
        port,
        static_key=None,
        static_key_direction=0,
        table_id=0,
        dev_name="",
    ):
        super(VppOvpnInterface, self).__init__(test)
        self.src = src
        self.port = port
        self.static_key = static_key if static_key else generate_static_key()
        self.static_key_direction = static_key_direction
        self.table_id = table_id
        self.dev_name = dev_name
        self.instance_id = None

    def add_vpp_config(self):
        """Add OpenVPN interface to VPP configuration."""
        r = self.test.vapi.ovpn_interface_create(
            local_addr=self.src,
            local_port=self.port,
            table_id=self.table_id,
            dev_name=self.dev_name,
            crypto_mode=0,  # OVPN_CRYPTO_MODE_STATIC_KEY
            static_key=self.static_key,
            static_key_direction=self.static_key_direction,
            ca_cert_len=0,
            server_cert_len=0,
            server_key_len=0,
            tls_auth_key_len=0,
            tls_crypt_key_len=0,
            certs_and_keys=b"",
        )
        self.set_sw_if_index(r.sw_if_index)
        self.instance_id = r.instance_id
        self.test.registry.register(self, self.test.logger)
        return self

    def remove_vpp_config(self):
        """Remove OpenVPN interface from VPP configuration."""
        self.test.vapi.ovpn_interface_delete(sw_if_index=self._sw_if_index)

    def query_vpp_config(self):
        """Query VPP configuration for this interface."""
        ts = self.test.vapi.ovpn_interface_dump(sw_if_index=0xFFFFFFFF)
        for t in ts:
            if (
                t.interface.sw_if_index == self._sw_if_index
                and t.interface.local_port == self.port
            ):
                return True
        return False

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "ovpn-%d" % self._sw_if_index


@tag_run_solo
class TestOvpnInterfaceCreate(VppTestCase):
    """OpenVPN Interface Create Test"""

    @classmethod
    def setUpClass(cls):
        super(TestOvpnInterfaceCreate, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        super(TestOvpnInterfaceCreate, cls).tearDownClass()

    def test_ovpn_interface_create_delete(self):
        """OpenVPN interface create and delete"""
        # Create interface
        ovpn_if = VppOvpnInterface(
            self,
            src=self.pg0.local_ip4,
            port=1194,
        )
        ovpn_if.add_vpp_config()

        # Verify interface was created
        self.assertTrue(ovpn_if.query_vpp_config())
        self.assertIsNotNone(ovpn_if.instance_id)

        # Configure IP and bring up
        ovpn_if.admin_up()
        ovpn_if.config_ip4()

        # Verify interface is in dump
        dump = self.vapi.ovpn_interface_dump(sw_if_index=0xFFFFFFFF)
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0].interface.local_port, 1194)
        self.assertEqual(
            dump[0].interface.crypto_mode,
            VppEnum.vl_api_ovpn_crypto_mode_t.OVPN_CRYPTO_MODE_STATIC_KEY,
        )

        # Delete interface
        ovpn_if.remove_vpp_config()

        # Verify interface was deleted
        dump = self.vapi.ovpn_interface_dump(sw_if_index=0xFFFFFFFF)
        self.assertEqual(len(dump), 0)


@tag_run_solo
class TestOvpnMultipleInterfaces(VppTestCase):
    """OpenVPN Multiple Interfaces Test"""

    @classmethod
    def setUpClass(cls):
        super(TestOvpnMultipleInterfaces, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        super(TestOvpnMultipleInterfaces, cls).tearDownClass()

    def test_ovpn_multiple_interfaces(self):
        """OpenVPN multiple interfaces"""
        interfaces = []

        # Create multiple interfaces
        for i in range(3):
            ovpn_if = VppOvpnInterface(
                self,
                src=self.pg0.local_ip4,
                port=1194 + i,
            )
            ovpn_if.add_vpp_config()
            ovpn_if.admin_up()
            interfaces.append(ovpn_if)

        # Verify all interfaces exist
        dump = self.vapi.ovpn_interface_dump(sw_if_index=0xFFFFFFFF)
        self.assertEqual(len(dump), 3)

        # Verify each interface
        ports = set(d.interface.local_port for d in dump)
        self.assertEqual(ports, {1194, 1195, 1196})

        # Clean up
        for ovpn_if in interfaces:
            ovpn_if.remove_vpp_config()

        # Verify all deleted
        dump = self.vapi.ovpn_interface_dump(sw_if_index=0xFFFFFFFF)
        self.assertEqual(len(dump), 0)


@tag_run_solo
class TestOvpnInterfaceDump(VppTestCase):
    """OpenVPN Interface Dump Test"""

    @classmethod
    def setUpClass(cls):
        super(TestOvpnInterfaceDump, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        super(TestOvpnInterfaceDump, cls).tearDownClass()

    def test_ovpn_interface_dump_specific(self):
        """OpenVPN interface dump specific interface"""
        # Create two interfaces
        ovpn_if1 = VppOvpnInterface(
            self,
            src=self.pg0.local_ip4,
            port=1194,
        )
        ovpn_if1.add_vpp_config()

        ovpn_if2 = VppOvpnInterface(
            self,
            src=self.pg0.local_ip4,
            port=1195,
        )
        ovpn_if2.add_vpp_config()

        # Dump all
        dump = self.vapi.ovpn_interface_dump(sw_if_index=0xFFFFFFFF)
        self.assertEqual(len(dump), 2)

        # Dump specific interface
        dump = self.vapi.ovpn_interface_dump(sw_if_index=ovpn_if1.sw_if_index)
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0].interface.local_port, 1194)

        dump = self.vapi.ovpn_interface_dump(sw_if_index=ovpn_if2.sw_if_index)
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0].interface.local_port, 1195)

        # Clean up
        ovpn_if1.remove_vpp_config()
        ovpn_if2.remove_vpp_config()


@tag_run_solo
class TestOvpnPeersDump(VppTestCase):
    """OpenVPN Peers Dump Test"""

    @classmethod
    def setUpClass(cls):
        super(TestOvpnPeersDump, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        super(TestOvpnPeersDump, cls).tearDownClass()

    def test_ovpn_peers_dump_empty(self):
        """OpenVPN peers dump (empty)"""
        # Create interface
        ovpn_if = VppOvpnInterface(
            self,
            src=self.pg0.local_ip4,
            port=1194,
        )
        ovpn_if.add_vpp_config()
        ovpn_if.admin_up()

        # Dump peers - should be empty
        dump = self.vapi.ovpn_peers_dump(sw_if_index=0xFFFFFFFF)
        self.assertEqual(len(dump), 0)

        # Clean up
        ovpn_if.remove_vpp_config()


@tag_run_solo
class TestOvpnStaticKey(VppTestCase):
    """OpenVPN Static Key Test"""

    @classmethod
    def setUpClass(cls):
        super(TestOvpnStaticKey, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        super(TestOvpnStaticKey, cls).tearDownClass()

    def test_ovpn_static_key_mode(self):
        """OpenVPN static key mode configuration"""
        # Generate a static key
        static_key = generate_static_key()

        # Create interface with static key
        ovpn_if = VppOvpnInterface(
            self,
            src=self.pg0.local_ip4,
            port=1194,
            static_key=static_key,
            static_key_direction=0,
        )
        ovpn_if.add_vpp_config()
        ovpn_if.admin_up()
        ovpn_if.config_ip4()

        # Verify static key mode
        dump = self.vapi.ovpn_interface_dump(sw_if_index=ovpn_if.sw_if_index)
        self.assertEqual(len(dump), 1)
        self.assertEqual(
            dump[0].interface.crypto_mode,
            VppEnum.vl_api_ovpn_crypto_mode_t.OVPN_CRYPTO_MODE_STATIC_KEY,
        )

        # Clean up
        ovpn_if.remove_vpp_config()


@tag_run_solo
class TestOvpnDifferentPorts(VppTestCase):
    """OpenVPN Different Ports Test"""

    @classmethod
    def setUpClass(cls):
        super(TestOvpnDifferentPorts, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        super(TestOvpnDifferentPorts, cls).tearDownClass()

    def test_ovpn_different_ports(self):
        """OpenVPN interfaces on different ports"""
        ports = [1194, 443, 8080, 51820]
        interfaces = []

        for port in ports:
            ovpn_if = VppOvpnInterface(
                self,
                src=self.pg0.local_ip4,
                port=port,
            )
            ovpn_if.add_vpp_config()
            ovpn_if.admin_up()
            interfaces.append(ovpn_if)

        # Verify all ports are registered
        dump = self.vapi.ovpn_interface_dump(sw_if_index=0xFFFFFFFF)
        self.assertEqual(len(dump), len(ports))

        dump_ports = set(d.interface.local_port for d in dump)
        self.assertEqual(dump_ports, set(ports))

        # Clean up
        for ovpn_if in interfaces:
            ovpn_if.remove_vpp_config()


@tag_run_solo
class TestOvpnFibTable(VppTestCase):
    """OpenVPN FIB Table Test"""

    @classmethod
    def setUpClass(cls):
        super(TestOvpnFibTable, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    @classmethod
    def tearDownClass(cls):
        super(TestOvpnFibTable, cls).tearDownClass()

    def test_ovpn_interface_with_table_id(self):
        """OpenVPN interface with custom FIB table"""
        # Create a custom FIB table
        table_id = 10
        self.vapi.ip_table_add_del(is_add=1, table={"table_id": table_id})

        # Create interface in custom table
        ovpn_if = VppOvpnInterface(
            self,
            src=self.pg0.local_ip4,
            port=1194,
            table_id=table_id,
        )
        ovpn_if.add_vpp_config()
        ovpn_if.admin_up()

        # Verify table_id in dump
        dump = self.vapi.ovpn_interface_dump(sw_if_index=ovpn_if.sw_if_index)
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0].interface.table_id, table_id)

        # Clean up
        ovpn_if.remove_vpp_config()
        self.vapi.ip_table_add_del(is_add=0, table={"table_id": table_id})


if __name__ == "__main__":
    unittest.main(testRunner=unittest.TextTestRunner(verbosity=2))
