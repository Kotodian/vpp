package main

import (
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterOvpnTests(
		OvpnInterfaceCreateTest,
		OvpnShowCommandsTest,
	)
	RegisterOvpnSoloTests(
		OvpnClientConnectivityTest,
	)
}

// OvpnInterfaceCreateTest tests basic OpenVPN interface creation in VPP
func OvpnInterfaceCreateTest(s *OvpnSuite) {
	vpp := s.Containers.Vpp.VppInstance

	// Test creating OpenVPN interface
	s.Log("Creating OpenVPN interface...")
	result := vpp.Vppctl("ovpn create local " + s.VppOvpnAddr() + " port " + s.Ports.Ovpn)
	s.Log("Create result: " + result)

	// Verify interface was created
	result = vpp.Vppctl("show interface")
	s.Log("Interfaces: " + result)
	s.AssertContains(result, "ovpn0", "OpenVPN interface should be created")

	// Set interface up
	result = vpp.Vppctl("set interface state ovpn0 up")
	s.Log("Set state result: " + result)

	// Verify interface is up
	result = vpp.Vppctl("show interface ovpn0")
	s.Log("Interface status: " + result)
	s.AssertContains(result, "up", "OpenVPN interface should be up")

	// Test deleting interface
	result = vpp.Vppctl("ovpn delete interface ovpn0")
	s.Log("Delete result: " + result)

	// Verify interface was deleted
	result = vpp.Vppctl("show interface")
	s.AssertNotContains(result, "ovpn0", "OpenVPN interface should be deleted")
}

// OvpnShowCommandsTest tests the show commands for OpenVPN plugin
func OvpnShowCommandsTest(s *OvpnSuite) {
	vpp := s.Containers.Vpp.VppInstance

	// Create interface first
	result := vpp.Vppctl("ovpn create local " + s.VppOvpnAddr() + " port " + s.Ports.Ovpn)
	s.Log("Create result: " + result)

	// Configure IP and bring up
	vpp.Vppctl("set interface ip address ovpn0 " + s.TunnelServerIP() + "/24")
	vpp.Vppctl("set interface state ovpn0 up")

	// Test show ovpn interface
	result = vpp.Vppctl("show ovpn interface")
	s.Log("Show ovpn interface: " + result)
	// Should show the interface info (even if empty/minimal output)
	s.AssertNotEqual("", result, "show ovpn interface should return output")

	// Test show ovpn peers (should be empty initially)
	result = vpp.Vppctl("show ovpn peers")
	s.Log("Show ovpn peers: " + result)
	// Empty is OK, just verify command works

	// Test show ovpn stats
	result = vpp.Vppctl("show ovpn stats")
	s.Log("Show ovpn stats: " + result)
}

// OvpnClientConnectivityTest tests connectivity with a real OpenVPN client
// This is a solo test because it requires more time and resources
func OvpnClientConnectivityTest(s *OvpnSuite) {
	vpp := s.Containers.Vpp.VppInstance

	// Copy static key to VPP container
	s.Log("Copying static key to VPP container...")
	s.CopyStaticKeyToVpp()

	// Configure VPP OpenVPN interface with static key
	s.Log("Configuring VPP OpenVPN with static key...")
	s.ConfigureVppOvpnStaticKey("/tmp/static.key")

	// Show initial state
	s.Log("VPP OpenVPN interface: " + s.ShowOvpnInterface())

	// Debug: Show VPP interfaces and their state
	s.Log("=== VPP INTERFACES ===")
	s.Log(vpp.Vppctl("show interface"))
	s.Log("=== VPP INTERFACE ADDRESSES ===")
	s.Log(vpp.Vppctl("show interface address"))

	// Show registered UDP ports - this is critical
	s.Log("=== VPP UDP PORTS (verify ovpn4-input is registered) ===")
	udpPorts := vpp.Vppctl("show udp ports")
	s.Log(udpPorts)

	// Debug: Show Linux network state from VPP container
	netInfo, _ := s.Containers.Vpp.Exec(false, "ip addr show")
	s.Log("=== LINUX NETWORK INTERFACES ===\n" + netInfo)

	// Add static ARP entry for Linux TAP interface (needed for VPP to send responses)
	s.Log("Adding static ARP entry...")
	arpCmd := "set ip neighbor " + s.Interfaces.OvpnTap.Peer.Name() + " " +
		s.Interfaces.OvpnTap.Ip4AddressString() + " " +
		s.Interfaces.OvpnTap.HwAddress.String()
	s.Log("ARP command: " + arpCmd)
	vpp.Vppctl(arpCmd)

	// Enable VPP tracing on virtio-input (the only node that reliably supports tracing)
	s.Log("Enabling VPP trace on virtio-input...")
	vpp.Vppctl("trace add virtio-input 100")

	// Create and start OpenVPN client container
	s.Log("Starting OpenVPN client container...")
	s.Containers.OpenVpnClient.Run()

	// Debug: Show client's network state
	clientNet, _ := s.Containers.OpenVpnClient.Exec(false, "ip addr show")
	s.Log("=== OPENVPN CLIENT INTERFACES ===\n" + clientNet)

	// Debug: Test basic ping from client to VPP TAP IP before OpenVPN
	s.Log("Testing basic connectivity from client to VPP TAP...")
	pingResult, _ := s.Containers.OpenVpnClient.Exec(false, "ping -c 2 -W 2 %s", s.VppOvpnAddr())
	s.Log("Ping to VPP TAP (" + s.VppOvpnAddr() + "): " + pingResult)

	// Debug: Test UDP connectivity with nc and verify via VPP trace
	s.Log("=== UDP CONNECTIVITY TEST ===")
	vpp.Vppctl("clear trace")

	// Send a test UDP packet to VPP's OpenVPN port
	s.Log("Sending test UDP packet to " + s.VppOvpnAddr() + ":" + s.Ports.Ovpn)
	udpTest, _ := s.Containers.OpenVpnClient.Exec(false, "bash -c 'echo test | nc -u -w1 %s %s'", s.VppOvpnAddr(), s.Ports.Ovpn)
	s.Log("nc result: " + udpTest)

	// Give VPP time to process
	time.Sleep(500 * time.Millisecond)

	// Check VPP trace and interface counters
	s.Log("=== VPP TRACE AFTER UDP TEST ===")
	s.Log(vpp.Vppctl("show trace"))
	s.Log("=== VPP INTERFACE COUNTERS ===")
	s.Log(vpp.Vppctl("show interface"))
	s.Log("=== VPP ERRORS ===")
	s.Log(vpp.Vppctl("show errors"))

	vpp.Vppctl("clear trace")

	// Create client configuration
	s.Log("Creating OpenVPN client config...")
	s.CreateOpenVpnClientConfig()

	// Start OpenVPN client
	s.Log("Starting OpenVPN client...")
	err := s.StartOpenVpnClient()
	s.AssertNil(err, "Failed to start OpenVPN client")

	// Wait for tunnel to establish
	s.Log("Waiting for tunnel to establish...")
	err = s.WaitForTunnel(30 * time.Second)
	if err != nil {
		// Log debug info on failure
		s.Log("=== TUNNEL ESTABLISHMENT FAILED ===")
		s.CollectOvpnLogs()
		s.Log("VPP peers: " + s.ShowOvpnPeers())
		s.Log("=== VPP TRACE ===\n" + vpp.Vppctl("show trace"))
		s.Log("=== VPP ERRORS ===\n" + vpp.Vppctl("show errors"))
	}
	s.AssertNil(err, "Tunnel should establish")

	// Show peer status
	s.Log("VPP OpenVPN peers: " + s.ShowOvpnPeers())

	// Test connectivity through tunnel
	s.Log("Testing connectivity through tunnel...")
	err = s.PingThroughTunnel(s.TunnelServerIP())
	if err != nil {
		s.Log("=== PING THROUGH TUNNEL FAILED ===")
		s.CollectOvpnLogs()
		s.Log("=== VPP TRACE ===\n" + vpp.Vppctl("show trace"))
		s.Log("=== VPP ERRORS ===\n" + vpp.Vppctl("show errors"))
		s.Log("=== VPP INTERFACES ===\n" + vpp.Vppctl("show interface"))
		s.Log("=== VPP NODE COUNTERS ===\n" + vpp.Vppctl("show node counters"))
	}
	s.AssertNil(err, "Should be able to ping through tunnel")

	s.Log("OpenVPN connectivity test PASSED")
}
