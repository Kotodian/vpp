package hst

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

var ovpnTests = map[string][]func(s *OvpnSuite){}
var ovpnSoloTests = map[string][]func(s *OvpnSuite){}

// OvpnSuite tests OpenVPN plugin functionality
type OvpnSuite struct {
	HstSuite
	Interfaces struct {
		Tap     *NetInterface // TAP for tunnel inner traffic
		OvpnTap *NetInterface // TAP for encrypted OpenVPN traffic
	}
	Containers struct {
		Vpp           *Container
		OpenVpnClient *Container
	}
	Ports struct {
		Ovpn string // OpenVPN UDP port
	}
}

func RegisterOvpnTests(tests ...func(s *OvpnSuite)) {
	ovpnTests[GetTestFilename()] = tests
}

func RegisterOvpnSoloTests(tests ...func(s *OvpnSuite)) {
	ovpnSoloTests[GetTestFilename()] = tests
}

func (s *OvpnSuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("ovpn")
	s.LoadContainerTopology("ovpn")
	s.Interfaces.Tap = s.GetInterfaceByName("htaphost")
	s.Interfaces.OvpnTap = s.GetInterfaceByName("ovpnhost")
	s.Containers.Vpp = s.GetContainerByName("vpp")
	s.Containers.OpenVpnClient = s.GetContainerByName("openvpn-client")
	s.Ports.Ovpn = s.GeneratePort()
}

func (s *OvpnSuite) SetupTest() {
	s.HstSuite.SetupTest()

	// Configure VPP with OpenVPN plugin
	vpp, _ := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus)

	s.AssertNil(vpp.Start())

	// Create TAP interfaces in VPP
	s.AssertNil(vpp.CreateTap(s.Interfaces.Tap, false, 1), "failed to create inner tap interface")
	s.AssertNil(vpp.CreateTap(s.Interfaces.OvpnTap, false, 2), "failed to create ovpn tap interface")

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *OvpnSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	if CurrentSpecReport().Failed() {
		s.CollectOvpnLogs()
	}
}

// CollectOvpnLogs collects OpenVPN client logs on test failure
func (s *OvpnSuite) CollectOvpnLogs() {
	if s.Containers.OpenVpnClient == nil {
		return
	}
	logs, err := s.Containers.OpenVpnClient.Exec(false, "cat /tmp/openvpn/client.log")
	if err == nil {
		s.Log("OpenVPN client logs:\n" + logs)
	}
}

// VppAddr returns the VPP tunnel endpoint IP address
func (s *OvpnSuite) VppAddr() string {
	return s.Interfaces.Tap.Peer.Ip4AddressString()
}

// VppOvpnAddr returns the VPP OpenVPN UDP endpoint address
func (s *OvpnSuite) VppOvpnAddr() string {
	return s.Interfaces.OvpnTap.Peer.Ip4AddressString()
}

// ClientOvpnAddr returns the OpenVPN client address (for encrypted traffic)
func (s *OvpnSuite) ClientOvpnAddr() string {
	return s.Interfaces.OvpnTap.Ip4AddressString()
}

// TunnelServerIP returns the server-side tunnel IP (inside tunnel)
func (s *OvpnSuite) TunnelServerIP() string {
	return "10.8.0.1"
}

// TunnelClientIP returns the client-side tunnel IP (inside tunnel)
func (s *OvpnSuite) TunnelClientIP() string {
	return "10.8.0.2"
}

// ConfigureVppOvpn configures the OpenVPN plugin in VPP
func (s *OvpnSuite) ConfigureVppOvpn() {
	vpp := s.Containers.Vpp.VppInstance

	// Create OpenVPN interface
	// ovpn create local <ip> port <port> [secret <key>]
	cmd := fmt.Sprintf("ovpn create local %s port %s",
		s.VppOvpnAddr(), s.Ports.Ovpn)
	s.Log("VPP command: " + cmd)
	result := vpp.Vppctl(cmd)
	s.Log("Result: " + result)

	// Configure tunnel IP address
	cmd = fmt.Sprintf("set interface ip address ovpn0 %s/24", s.TunnelServerIP())
	s.Log("VPP command: " + cmd)
	result = vpp.Vppctl(cmd)
	s.Log("Result: " + result)

	// Bring up the interface
	result = vpp.Vppctl("set interface state ovpn0 up")
	s.Log("Interface state: " + result)
}

// CopyStaticKeyToVpp copies the static key file to the VPP container
func (s *OvpnSuite) CopyStaticKeyToVpp() {
	staticKey, err := os.ReadFile("./resources/openvpn/static.key")
	s.AssertNil(err, "failed to read static.key")
	s.Containers.Vpp.CreateFile("/tmp/static.key", string(staticKey))
}

// ConfigureVppOvpnStaticKey configures VPP OpenVPN with static key
func (s *OvpnSuite) ConfigureVppOvpnStaticKey(keyFile string) {
	vpp := s.Containers.Vpp.VppInstance

	// Create OpenVPN interface with static key
	cmd := fmt.Sprintf("ovpn create local %s port %s secret %s",
		s.VppOvpnAddr(), s.Ports.Ovpn, keyFile)
	s.Log("VPP command: " + cmd)
	result := vpp.Vppctl(cmd)
	s.Log("Result: " + result)

	// Configure tunnel IP address
	cmd = fmt.Sprintf("set interface ip address ovpn0 %s/24", s.TunnelServerIP())
	s.Log("VPP command: " + cmd)
	result = vpp.Vppctl(cmd)
	s.Log("Result: " + result)

	// Bring up the interface
	result = vpp.Vppctl("set interface state ovpn0 up")
	s.Log("Interface state: " + result)
}

// CreateOpenVpnClientConfig creates the OpenVPN client configuration
func (s *OvpnSuite) CreateOpenVpnClientConfig() {
	values := struct {
		ServerAddress  string
		ServerPort     string
		ClientTunnelIP string
		ServerTunnelIP string
	}{
		ServerAddress:  s.VppOvpnAddr(),
		ServerPort:     s.Ports.Ovpn,
		ClientTunnelIP: s.TunnelClientIP(),
		ServerTunnelIP: s.TunnelServerIP(),
	}

	// Create log and config directories in container
	s.Containers.OpenVpnClient.Exec(false, "mkdir -p /tmp/openvpn")
	s.Containers.OpenVpnClient.Exec(false, "mkdir -p /etc/openvpn")

	// Copy static key from resources to container
	staticKey, err := os.ReadFile("./resources/openvpn/static.key")
	s.AssertNil(err, "failed to read static.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/static.key", string(staticKey))

	// Create client config from template
	s.Containers.OpenVpnClient.CreateConfigFromTemplate(
		"/etc/openvpn/client.conf",
		"./resources/openvpn/client.conf.template",
		values,
	)
}

// StartOpenVpnClient starts the OpenVPN client process
func (s *OvpnSuite) StartOpenVpnClient() error {
	// Start OpenVPN in background using ExecServer (detached mode)
	s.Containers.OpenVpnClient.ExecServer(false,
		"openvpn --config /etc/openvpn/client.conf")

	// Wait for tunnel to establish
	s.Log("Waiting for OpenVPN tunnel to establish...")
	time.Sleep(5 * time.Second)

	return nil
}

// WaitForTunnel waits for the OpenVPN tunnel interface to come up
func (s *OvpnSuite) WaitForTunnel(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		output, err := s.Containers.OpenVpnClient.Exec(false, "ip link show tun0")
		// TUN interfaces typically show "state DOWN" or "state UNKNOWN"
		// even when they're up, so check for the UP flag instead
		if err == nil && strings.Contains(output, ",UP") {
			s.Log("Tunnel interface is up")
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("tunnel interface did not come up within %v", timeout)
}

// PingThroughTunnel pings through the OpenVPN tunnel
func (s *OvpnSuite) PingThroughTunnel(targetIP string) error {
	output, err := s.Containers.OpenVpnClient.Exec(false,
		"ping -c 3 -W 5 %s", targetIP)
	s.Log("Ping output: " + output)
	if err != nil {
		return fmt.Errorf("ping failed: %v", err)
	}
	if !strings.Contains(output, "3 received") && !strings.Contains(output, "3 packets received") {
		return fmt.Errorf("ping did not receive all packets")
	}
	return nil
}

// ShowOvpnPeers shows OpenVPN peer information from VPP
func (s *OvpnSuite) ShowOvpnPeers() string {
	vpp := s.Containers.Vpp.VppInstance
	// show ovpn peers doesn't exist yet, use show ovpn
	return vpp.Vppctl("show ovpn")
}

// ShowOvpnInterface shows OpenVPN interface information from VPP
func (s *OvpnSuite) ShowOvpnInterface() string {
	vpp := s.Containers.Vpp.VppInstance
	return vpp.Vppctl("show ovpn interface")
}

var _ = Describe("OvpnSuite", Ordered, ContinueOnFailure, Label("Ovpn"), func() {
	var s OvpnSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	for filename, tests := range ovpnTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				s.Log(testName + ": BEGIN")
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})

var _ = Describe("OvpnSuiteSolo", Ordered, ContinueOnFailure, Serial, Label("Ovpn"), func() {
	var s OvpnSuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	for filename, tests := range ovpnSoloTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				s.Log(testName + ": BEGIN")
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
