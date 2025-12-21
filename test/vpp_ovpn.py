"""
OpenVPN VPP test helper classes and utilities.
"""

import os
import struct
from vpp_interface import VppInterface
from vpp_object import VppObject

# OpenVPN constants
OVPN_STATIC_KEY_SIZE = 256

# Crypto modes (must match ovpn.api)
OVPN_CRYPTO_MODE_STATIC_KEY = 0
OVPN_CRYPTO_MODE_TLS = 1
OVPN_CRYPTO_MODE_TLS_AUTH = 2
OVPN_CRYPTO_MODE_TLS_CRYPT = 3

# Peer states (must match ovpn.api)
OVPN_API_PEER_STATE_INITIAL = 0
OVPN_API_PEER_STATE_HANDSHAKE = 1
OVPN_API_PEER_STATE_ESTABLISHED = 2
OVPN_API_PEER_STATE_REKEYING = 3
OVPN_API_PEER_STATE_DEAD = 4


def generate_static_key():
    """Generate a random 256-byte static key for testing."""
    return os.urandom(OVPN_STATIC_KEY_SIZE)


def parse_static_key_file(content):
    """
    Parse OpenVPN static key file format.

    Format:
    -----BEGIN OpenVPN Static key V1-----
    <16 lines of 32 hex characters each = 256 bytes>
    -----END OpenVPN Static key V1-----

    Args:
        content: String content of the static key file

    Returns:
        bytes: 256-byte static key
    """
    lines = content.strip().split("\n")
    hex_data = ""
    in_key = False

    for line in lines:
        line = line.strip()
        if "BEGIN OpenVPN Static key" in line:
            in_key = True
            continue
        if "END OpenVPN Static key" in line:
            break
        if in_key and line and not line.startswith("#"):
            hex_data += line

    return bytes.fromhex(hex_data)


def generate_static_key_file():
    """
    Generate a static key in OpenVPN file format.

    Returns:
        tuple: (raw_key_bytes, file_content_string)
    """
    key = generate_static_key()
    hex_lines = []
    for i in range(0, len(key), 16):
        hex_lines.append(key[i : i + 16].hex())

    content = "-----BEGIN OpenVPN Static key V1-----\n"
    content += "\n".join(hex_lines) + "\n"
    content += "-----END OpenVPN Static key V1-----\n"

    return key, content


class VppOvpnInterface(VppInterface):
    """
    VPP OpenVPN interface helper class.

    Provides methods to create, configure, and manage OpenVPN interfaces
    in VPP through the Binary API.
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
        crypto_mode=OVPN_CRYPTO_MODE_STATIC_KEY,
        ca_cert=None,
        server_cert=None,
        server_key=None,
        tls_auth_key=None,
        tls_crypt_key=None,
    ):
        """
        Initialize OpenVPN interface.

        Args:
            test: VppTestCase instance
            src: Local IP address string
            port: Local UDP port number
            static_key: 256-byte static key (auto-generated if None)
            static_key_direction: Key direction (0 or 1)
            table_id: FIB table ID
            dev_name: Device name (optional)
            crypto_mode: Crypto mode (OVPN_CRYPTO_MODE_*)
            ca_cert: CA certificate (PEM format, for TLS modes)
            server_cert: Server certificate (PEM format)
            server_key: Server private key (PEM format)
            tls_auth_key: TLS-Auth key (for TLS_AUTH mode)
            tls_crypt_key: TLS-Crypt key (for TLS_CRYPT mode)
        """
        super(VppOvpnInterface, self).__init__(test)
        self.src = src
        self.port = port
        self.table_id = table_id
        self.dev_name = dev_name
        self.crypto_mode = crypto_mode
        self.instance_id = None

        # Static key mode
        self.static_key = static_key if static_key else generate_static_key()
        self.static_key_direction = static_key_direction

        # TLS mode
        self.ca_cert = ca_cert
        self.server_cert = server_cert
        self.server_key = server_key
        self.tls_auth_key = tls_auth_key
        self.tls_crypt_key = tls_crypt_key

    def add_vpp_config(self):
        """Add OpenVPN interface to VPP configuration."""
        # Build certs_and_keys for TLS modes
        certs_and_keys = b""
        ca_cert_len = 0
        server_cert_len = 0
        server_key_len = 0
        tls_auth_key_len = 0
        tls_crypt_key_len = 0

        if self.crypto_mode != OVPN_CRYPTO_MODE_STATIC_KEY:
            if self.ca_cert:
                ca_data = (
                    self.ca_cert.encode()
                    if isinstance(self.ca_cert, str)
                    else self.ca_cert
                )
                ca_cert_len = len(ca_data)
                certs_and_keys += ca_data

            if self.server_cert:
                cert_data = (
                    self.server_cert.encode()
                    if isinstance(self.server_cert, str)
                    else self.server_cert
                )
                server_cert_len = len(cert_data)
                certs_and_keys += cert_data

            if self.server_key:
                key_data = (
                    self.server_key.encode()
                    if isinstance(self.server_key, str)
                    else self.server_key
                )
                server_key_len = len(key_data)
                certs_and_keys += key_data

            if self.crypto_mode == OVPN_CRYPTO_MODE_TLS_AUTH and self.tls_auth_key:
                tls_auth_key_len = len(self.tls_auth_key)
                certs_and_keys += self.tls_auth_key

            if self.crypto_mode == OVPN_CRYPTO_MODE_TLS_CRYPT and self.tls_crypt_key:
                tls_crypt_key_len = len(self.tls_crypt_key)
                certs_and_keys += self.tls_crypt_key

        r = self.test.vapi.ovpn_interface_create(
            local_addr=self.src,
            local_port=self.port,
            table_id=self.table_id,
            dev_name=self.dev_name,
            crypto_mode=self.crypto_mode,
            static_key=self.static_key,
            static_key_direction=self.static_key_direction,
            ca_cert_len=ca_cert_len,
            server_cert_len=server_cert_len,
            server_key_len=server_key_len,
            tls_auth_key_len=tls_auth_key_len,
            tls_crypt_key_len=tls_crypt_key_len,
            certs_and_keys=certs_and_keys,
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

    def get_peers(self):
        """Get list of peers connected to this interface."""
        return self.test.vapi.ovpn_peers_dump(sw_if_index=self._sw_if_index)

    def get_peer_count(self):
        """Get number of peers connected to this interface."""
        dump = self.test.vapi.ovpn_interface_dump(sw_if_index=self._sw_if_index)
        if dump:
            return dump[0].num_peers
        return 0

    def remove_peer(self, peer_id):
        """Remove a specific peer from this interface."""
        self.test.vapi.ovpn_peer_remove(
            sw_if_index=self._sw_if_index, peer_id=peer_id
        )

    def __str__(self):
        return self.object_id()

    def object_id(self):
        return "ovpn-%d" % self._sw_if_index


class VppOvpnPeer(VppObject):
    """
    Represents an OpenVPN peer in VPP tests.

    Note: In OpenVPN, peers are typically created dynamically when
    clients connect, not via API. This class is mainly for test
    verification purposes.
    """

    def __init__(self, test, interface, peer_id):
        """
        Initialize peer reference.

        Args:
            test: VppTestCase instance
            interface: VppOvpnInterface this peer belongs to
            peer_id: Peer ID
        """
        self._test = test
        self.interface = interface
        self.peer_id = peer_id

    def query_vpp_config(self):
        """Check if peer exists in VPP."""
        peers = self._test.vapi.ovpn_peers_dump(
            sw_if_index=self.interface.sw_if_index, peer_id=self.peer_id
        )
        return len(peers) > 0

    def remove_vpp_config(self):
        """Remove peer from VPP."""
        self._test.vapi.ovpn_peer_remove(
            sw_if_index=self.interface.sw_if_index, peer_id=self.peer_id
        )

    def get_stats(self):
        """Get peer statistics."""
        peers = self._test.vapi.ovpn_peers_dump(
            sw_if_index=self.interface.sw_if_index, peer_id=self.peer_id
        )
        if peers:
            peer = peers[0].peer
            return {
                "rx_bytes": peer.rx_bytes,
                "tx_bytes": peer.tx_bytes,
                "rx_packets": peer.rx_packets,
                "tx_packets": peer.tx_packets,
                "state": peer.state,
            }
        return None

    def object_id(self):
        return "ovpn-peer-%d-%d" % (self.interface.sw_if_index, self.peer_id)
