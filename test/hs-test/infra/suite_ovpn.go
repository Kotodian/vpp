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

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func readFileWithFallback(paths ...string) ([]byte, error) {
	var lastErr error
	for _, p := range paths {
		if p == "" {
			continue
		}
		b, err := os.ReadFile(p)
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// StartVppWithOvpnConfig starts VPP with an OpenVPN configuration in startup.conf
func (s *OvpnSuite) StartVppWithOvpnConfig(ovpnConfig Stanza) {
	vpp, _ := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus, ovpnConfig)
	AssertNil(vpp.Start())

	// Create TAP interfaces in VPP
	AssertNil(vpp.CreateTap(s.Interfaces.Tap, false, 1), "failed to create inner tap interface")
	AssertNil(vpp.CreateTap(s.Interfaces.OvpnTap, false, 2), "failed to create ovpn tap interface")
}

// StartVppBasic starts VPP without OpenVPN configuration (for basic tests)
func (s *OvpnSuite) StartVppBasic() {
	vpp, _ := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus)
	AssertNil(vpp.Start())

	// Create TAP interfaces in VPP
	AssertNil(vpp.CreateTap(s.Interfaces.Tap, false, 1), "failed to create inner tap interface")
	AssertNil(vpp.CreateTap(s.Interfaces.OvpnTap, false, 2), "failed to create ovpn tap interface")
}

// GetOvpnStaticKeyConfig returns a Stanza for OpenVPN static key mode
func (s *OvpnSuite) GetOvpnStaticKeyConfig(instanceName, keyPath string) Stanza {
	var config Stanza
	config.NewStanza("openvpn").
		NewStanza(fmt.Sprintf("instance %s", instanceName)).
		Append(fmt.Sprintf("local %s", s.VppOvpnAddr())).
		Append(fmt.Sprintf("port %s", s.Ports.Ovpn)).
		Append("dev ovpn0").
		Append("dev-type tun").
		Append(fmt.Sprintf("secret %s", keyPath)).
		Append("cipher AES-256-CBC").
		Close().
		Close()
	return config
}

// GetOvpnStaticKeyTapConfig returns a Stanza for OpenVPN static key mode with TAP (L2)
func (s *OvpnSuite) GetOvpnStaticKeyTapConfig(instanceName, keyPath string) Stanza {
	var config Stanza
	config.NewStanza("openvpn").
		NewStanza(fmt.Sprintf("instance %s", instanceName)).
		Append(fmt.Sprintf("local %s", s.VppOvpnAddr())).
		Append(fmt.Sprintf("port %s", s.Ports.Ovpn)).
		Append("dev ovpn0").
		Append("dev-type tap").
		Append(fmt.Sprintf("secret %s", keyPath)).
		Append("cipher AES-256-CBC").
		Close().
		Close()
	return config
}

// GetOvpnTlsAuthConfig returns a Stanza for OpenVPN TLS-Auth mode
func (s *OvpnSuite) GetOvpnTlsAuthConfig(instanceName string) Stanza {
	var config Stanza
	config.NewStanza("openvpn").
		NewStanza(fmt.Sprintf("instance %s", instanceName)).
		Append(fmt.Sprintf("local %s", s.VppOvpnAddr())).
		Append(fmt.Sprintf("port %s", s.Ports.Ovpn)).
		Append("dev ovpn0").
		Append("dev-type tun").
		Append("ca /tmp/ca.crt").
		Append("cert /tmp/server.crt").
		Append("key /tmp/server.key").
		Append("tls-auth /tmp/ta.key").
		Close().
		Close()
	return config
}

// GetOvpnTlsAuthWithFragmentConfig returns a Stanza for OpenVPN TLS-Auth mode with fragmentation
func (s *OvpnSuite) GetOvpnTlsAuthWithFragmentConfig(instanceName string, fragmentSize int) Stanza {
	var config Stanza
	config.NewStanza("openvpn").
		NewStanza(fmt.Sprintf("instance %s", instanceName)).
		Append(fmt.Sprintf("local %s", s.VppOvpnAddr())).
		Append(fmt.Sprintf("port %s", s.Ports.Ovpn)).
		Append("dev ovpn0").
		Append("dev-type tun").
		Append("ca /tmp/ca.crt").
		Append("cert /tmp/server.crt").
		Append("key /tmp/server.key").
		Append("tls-auth /tmp/ta.key").
		Append(fmt.Sprintf("fragment %d", fragmentSize)).
		Close().
		Close()
	return config
}

// GetOvpnTlsAuthRekeyConfig returns a Stanza for OpenVPN TLS-Auth mode with short rekey interval
func (s *OvpnSuite) GetOvpnTlsAuthRekeyConfig(instanceName string, renegSec int) Stanza {
	var config Stanza
	config.NewStanza("openvpn").
		NewStanza(fmt.Sprintf("instance %s", instanceName)).
		Append(fmt.Sprintf("local %s", s.VppOvpnAddr())).
		Append(fmt.Sprintf("port %s", s.Ports.Ovpn)).
		Append("dev ovpn0").
		Append("dev-type tun").
		Append("ca /tmp/ca.crt").
		Append("cert /tmp/server.crt").
		Append("key /tmp/server.key").
		Append("tls-auth /tmp/ta.key").
		Append(fmt.Sprintf("reneg-sec %d", renegSec)).
		Close().
		Close()
	return config
}

// SetupVppOvpnTlsAuthWithFragment sets up VPP with TLS-Auth and fragmentation
func (s *OvpnSuite) SetupVppOvpnTlsAuthWithFragment(fragmentSize int) {
	s.CopyTlsCertsToVpp()
	s.CopyTlsAuthKeyToVpp()

	ovpnConfig := s.GetOvpnTlsAuthWithFragmentConfig("tls-auth-frag-server", fragmentSize)
	Log("OpenVPN startup config with fragment:\n" + ovpnConfig.ToString())

	s.StartVppWithOvpnConfig(ovpnConfig)
	s.ConfigureOvpnInterface()
}

// SetupVppOvpnTlsAuthRekey sets up VPP with TLS-Auth and short rekey interval
func (s *OvpnSuite) SetupVppOvpnTlsAuthRekey(renegSec int) {
	s.CopyTlsCertsToVpp()
	s.CopyTlsAuthKeyToVpp()

	ovpnConfig := s.GetOvpnTlsAuthRekeyConfig("tls-auth-rekey-server", renegSec)
	Log("OpenVPN startup config with rekey:\n" + ovpnConfig.ToString())

	s.StartVppWithOvpnConfig(ovpnConfig)
	s.ConfigureOvpnInterface()
}

// CreateOpenVpnTlsAuthRekeyClientConfig creates OpenVPN TLS-Auth client config with short rekey
func (s *OvpnSuite) CreateOpenVpnTlsAuthRekeyClientConfig(renegSec int) {
	serverAddr := s.VppOvpnAddr()
	serverPort := s.Ports.Ovpn

	// Create log and config directories in container
	s.Containers.OpenVpnClient.Exec(false, "mkdir -p /tmp/openvpn")
	s.Containers.OpenVpnClient.Exec(false, "mkdir -p /etc/openvpn")

	// Copy CA certificate
	caCert, err := os.ReadFile("./resources/openvpn/tls/ca.crt")
	AssertNil(err, "failed to read ca.crt")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/ca.crt", string(caCert))

	// Copy client certificate
	clientCert, err := os.ReadFile("./resources/openvpn/tls/client.crt")
	AssertNil(err, "failed to read client.crt")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.crt", string(clientCert))

	// Copy client key
	clientKey, err := os.ReadFile("./resources/openvpn/tls/client.key")
	AssertNil(err, "failed to read client.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.key", string(clientKey))

	// Copy TLS-Auth key
	taKey, err := os.ReadFile("./resources/openvpn/tls/ta.key")
	AssertNil(err, "failed to read ta.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/ta.key", string(taKey))

	// Create client config with short rekey interval
	// Use tls-client for TLS mode but not pull/client to use manual ifconfig
	clientConf := fmt.Sprintf(`# OpenVPN TLS-Auth client with rekey
dev tun
proto udp
remote %s %s
resolv-retry infinite
nobind
persist-key
persist-tun
tls-client

# TLS configuration
ca /etc/openvpn/ca.crt
cert /etc/openvpn/client.crt
key /etc/openvpn/client.key
tls-auth /etc/openvpn/ta.key 1

# Cipher and auth
cipher AES-256-GCM
auth SHA256

# Short rekey interval for testing
reneg-sec %d

# Manual tunnel IP configuration (peer-to-peer style)
ifconfig %s %s

# Verbosity
verb 5

# Log file
log /tmp/openvpn/client.log
status /tmp/openvpn/status.log 5
`, serverAddr, serverPort, renegSec, s.TunnelClientIP(), s.TunnelServerIP())

	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.conf", clientConf)
}

// GetOvpnTlsAuthWithPushConfig returns a Stanza for OpenVPN TLS-Auth mode with push options
func (s *OvpnSuite) GetOvpnTlsAuthWithPushConfig(instanceName string) Stanza {
	var config Stanza
	config.NewStanza("openvpn").
		NewStanza(fmt.Sprintf("instance %s", instanceName)).
		Append(fmt.Sprintf("local %s", s.VppOvpnAddr())).
		Append(fmt.Sprintf("port %s", s.Ports.Ovpn)).
		Append("dev ovpn0").
		Append("dev-type tun").
		Append("ca /tmp/ca.crt").
		Append("cert /tmp/server.crt").
		Append("key /tmp/server.key").
		Append("tls-auth /tmp/ta.key").
		// Push options for client
		Append("route 10.0.0.0 255.0.0.0").
		Append("dhcp-option DNS 8.8.8.8").
		Append("dhcp-option DNS 8.8.4.4").
		Append("dhcp-option DOMAIN vpn.example.com").
		Append("push persist-tun").
		Append("keepalive 10 60").
		Close().
		Close()
	return config
}

// GetOvpnTlsCryptConfig returns a Stanza for OpenVPN TLS-Crypt mode
func (s *OvpnSuite) GetOvpnTlsCryptConfig(instanceName string) Stanza {
	var config Stanza
	config.NewStanza("openvpn").
		NewStanza(fmt.Sprintf("instance %s", instanceName)).
		Append(fmt.Sprintf("local %s", s.VppOvpnAddr())).
		Append(fmt.Sprintf("port %s", s.Ports.Ovpn)).
		Append("dev ovpn0").
		Append("dev-type tun").
		Append("ca /tmp/ca.crt").
		Append("cert /tmp/server.crt").
		Append("key /tmp/server.key").
		Append("tls-crypt /tmp/tc.key").
		Close().
		Close()
	return config
}

// GetOvpnTlsCryptV2Config returns a Stanza for OpenVPN TLS-Crypt-V2 mode
func (s *OvpnSuite) GetOvpnTlsCryptV2Config(instanceName string) Stanza {
	var config Stanza
	config.NewStanza("openvpn").
		NewStanza(fmt.Sprintf("instance %s", instanceName)).
		Append(fmt.Sprintf("local %s", s.VppOvpnAddr())).
		Append(fmt.Sprintf("port %s", s.Ports.Ovpn)).
		Append("dev ovpn0").
		Append("dev-type tun").
		Append("ca /tmp/ca.crt").
		Append("cert /tmp/server.crt").
		Append("key /tmp/server.key").
		Append("tls-crypt-v2 /tmp/tls-crypt-v2-server.key").
		Close().
		Close()
	return config
}

// GetOvpnStaticKeyWithPushConfig returns a Stanza for OpenVPN with push options
func (s *OvpnSuite) GetOvpnStaticKeyWithPushConfig(instanceName, keyPath string) Stanza {
	var config Stanza
	config.NewStanza("openvpn").
		NewStanza(fmt.Sprintf("instance %s", instanceName)).
		Append(fmt.Sprintf("local %s", s.VppOvpnAddr())).
		Append(fmt.Sprintf("port %s", s.Ports.Ovpn)).
		Append("dev ovpn0").
		Append("dev-type tun").
		Append(fmt.Sprintf("secret %s", keyPath)).
		Append("cipher AES-256-CBC").
		// Push options - use route directive and simple push options
		Append("route 10.0.0.0 255.0.0.0").
		Append("dhcp-option DNS 8.8.8.8").
		Append("push persist-tun").
		Append("keepalive 10 60").
		Close().
		Close()
	return config
}

// GetOvpnStaticKeyWithDhcpConfig returns a Stanza for OpenVPN with DHCP options
func (s *OvpnSuite) GetOvpnStaticKeyWithDhcpConfig(instanceName, keyPath string) Stanza {
	var config Stanza
	config.NewStanza("openvpn").
		NewStanza(fmt.Sprintf("instance %s", instanceName)).
		Append(fmt.Sprintf("local %s", s.VppOvpnAddr())).
		Append(fmt.Sprintf("port %s", s.Ports.Ovpn)).
		Append("dev ovpn0").
		Append("dev-type tun").
		Append(fmt.Sprintf("secret %s", keyPath)).
		Append("cipher AES-256-CBC").
		// DHCP options
		Append("dhcp-option DNS 8.8.8.8").
		Append("dhcp-option DNS 8.8.4.4").
		Append("dhcp-option DOMAIN vpn.example.com").
		// Route options
		Append("route 10.0.0.0 255.0.0.0").
		Close().
		Close()
	return config
}

// GetOvpnStaticKeyWithDataCiphersConfig returns a Stanza for OpenVPN with data-ciphers
func (s *OvpnSuite) GetOvpnStaticKeyWithDataCiphersConfig(instanceName, keyPath string) Stanza {
	var config Stanza
	config.NewStanza("openvpn").
		NewStanza(fmt.Sprintf("instance %s", instanceName)).
		Append(fmt.Sprintf("local %s", s.VppOvpnAddr())).
		Append(fmt.Sprintf("port %s", s.Ports.Ovpn)).
		Append("dev ovpn0").
		Append("dev-type tun").
		Append(fmt.Sprintf("secret %s", keyPath)).
		// Data ciphers for negotiation
		Append("data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305").
		Append("data-ciphers-fallback AES-256-CBC").
		Close().
		Close()
	return config
}

// GetOvpnStaticKeyWithMssfixConfig returns a Stanza for OpenVPN with mssfix option
func (s *OvpnSuite) GetOvpnStaticKeyWithMssfixConfig(instanceName, keyPath string, mssfixValue int) Stanza {
	var config Stanza
	config.NewStanza("openvpn").
		NewStanza(fmt.Sprintf("instance %s", instanceName)).
		Append(fmt.Sprintf("local %s", s.VppOvpnAddr())).
		Append(fmt.Sprintf("port %s", s.Ports.Ovpn)).
		Append("dev ovpn0").
		Append("dev-type tun").
		Append(fmt.Sprintf("secret %s", keyPath)).
		Append("cipher AES-256-CBC").
		Append(fmt.Sprintf("mssfix %d", mssfixValue)).
		Close().
		Close()
	return config
}

// GetOvpnFullFeaturedConfig returns a Stanza with all new options enabled
func (s *OvpnSuite) GetOvpnFullFeaturedConfig(instanceName, keyPath string) Stanza {
	var config Stanza
	config.NewStanza("openvpn").
		NewStanza(fmt.Sprintf("instance %s", instanceName)).
		Append(fmt.Sprintf("local %s", s.VppOvpnAddr())).
		Append(fmt.Sprintf("port %s", s.Ports.Ovpn)).
		Append("dev ovpn0").
		Append("dev-type tun").
		Append(fmt.Sprintf("secret %s", keyPath)).
		Append("cipher AES-256-CBC").
		// Data ciphers
		Append("data-ciphers AES-256-GCM:AES-128-GCM").
		Append("data-ciphers-fallback AES-256-CBC").
		// DHCP options
		Append("dhcp-option DNS 8.8.8.8").
		Append("dhcp-option DOMAIN vpn.test.local").
		// Routes
		Append("route 172.16.0.0 255.255.0.0").
		// Simple push options (without quotes)
		Append("push persist-tun").
		// Keepalive
		Append("keepalive 10 60").
		Close().
		Close()
	return config
}

// SetupVppOvpnWithPush sets up VPP with OpenVPN push options via startup.conf
func (s *OvpnSuite) SetupVppOvpnWithPush(keyFile string) {
	s.CopyStaticKeyToVpp()
	ovpnConfig := s.GetOvpnStaticKeyWithPushConfig("push-server", keyFile)
	Log("OpenVPN startup config with push:\n" + ovpnConfig.ToString())
	s.StartVppWithOvpnConfig(ovpnConfig)
	s.ConfigureOvpnInterface()
}

// SetupVppOvpnWithDhcp sets up VPP with OpenVPN DHCP options via startup.conf
func (s *OvpnSuite) SetupVppOvpnWithDhcp(keyFile string) {
	s.CopyStaticKeyToVpp()
	ovpnConfig := s.GetOvpnStaticKeyWithDhcpConfig("dhcp-server", keyFile)
	Log("OpenVPN startup config with DHCP:\n" + ovpnConfig.ToString())
	s.StartVppWithOvpnConfig(ovpnConfig)
	s.ConfigureOvpnInterface()
}

// SetupVppOvpnWithDataCiphers sets up VPP with OpenVPN data-ciphers via startup.conf
func (s *OvpnSuite) SetupVppOvpnWithDataCiphers(keyFile string) {
	s.CopyStaticKeyToVpp()
	ovpnConfig := s.GetOvpnStaticKeyWithDataCiphersConfig("cipher-server", keyFile)
	Log("OpenVPN startup config with data-ciphers:\n" + ovpnConfig.ToString())
	s.StartVppWithOvpnConfig(ovpnConfig)
	s.ConfigureOvpnInterface()
}

// SetupVppOvpnFullFeatured sets up VPP with all new OpenVPN options
func (s *OvpnSuite) SetupVppOvpnFullFeatured(keyFile string) {
	s.CopyStaticKeyToVpp()
	ovpnConfig := s.GetOvpnFullFeaturedConfig("full-featured-server", keyFile)
	Log("OpenVPN startup config (full featured):\n" + ovpnConfig.ToString())
	s.StartVppWithOvpnConfig(ovpnConfig)
	s.ConfigureOvpnInterface()
}

// SetupVppOvpnWithMssfix sets up VPP with OpenVPN mssfix option via startup.conf
func (s *OvpnSuite) SetupVppOvpnWithMssfix(keyFile string, mssfixValue int) {
	s.CopyStaticKeyToVpp()
	ovpnConfig := s.GetOvpnStaticKeyWithMssfixConfig("mssfix-server", keyFile, mssfixValue)
	Log("OpenVPN startup config with mssfix:\n" + ovpnConfig.ToString())
	s.StartVppWithOvpnConfig(ovpnConfig)
	s.ConfigureOvpnInterface()
}

// SetupVppOvpnTap sets up VPP with OpenVPN TAP mode via startup.conf
func (s *OvpnSuite) SetupVppOvpnTap(keyFile string) {
	s.CopyStaticKeyToVpp()
	ovpnConfig := s.GetOvpnStaticKeyTapConfig("tap-server", keyFile)
	Log("OpenVPN startup config (TAP mode):\n" + ovpnConfig.ToString())
	s.StartVppWithOvpnConfig(ovpnConfig)
	s.ConfigureOvpnTapInterface()
}

// ConfigureOvpnTapInterface configures the OpenVPN TAP interface for L2/bridging
func (s *OvpnSuite) ConfigureOvpnTapInterface() {
	vpp := s.Containers.Vpp.VppInstance

	// For TAP mode, configure IP address on the interface
	// This enables VPP to respond to ARP requests for this IP
	cmd := fmt.Sprintf("set interface ip address ovpn0 %s/24", s.TunnelServerIP())
	Log("VPP command: " + cmd)
	result := vpp.Vppctl(cmd)
	Log("Result: " + result)

	// Bring up the interface
	result = vpp.Vppctl("set interface state ovpn0 up")
	Log("Interface state: " + result)

	// Show interface details
	Log("=== TAP Interface Details ===")
	Log(vpp.Vppctl("show interface ovpn0"))
	Log(vpp.Vppctl("show interface ovpn0 address"))
}

// CreateOpenVpnTapClientConfig creates the OpenVPN TAP mode client configuration
func (s *OvpnSuite) CreateOpenVpnTapClientConfig() {
	serverAddr := s.VppOvpnAddr()
	serverPort := s.Ports.Ovpn

	// Create log and config directories in container
	s.Containers.OpenVpnClient.Exec(false, "mkdir -p /tmp/openvpn")
	s.Containers.OpenVpnClient.Exec(false, "mkdir -p /etc/openvpn")

	// Copy static key
	staticKey, err := os.ReadFile("./resources/openvpn/static.key")
	AssertNil(err, "failed to read static.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/static.key", string(staticKey))

	// Create client config for TAP mode
	// For TAP mode, ifconfig uses: ifconfig ip netmask (not peer IP like TUN)
	clientConf := fmt.Sprintf(`# OpenVPN TAP mode client configuration
dev tap
proto udp
remote %s %s
resolv-retry infinite
nobind
persist-key
persist-tun

# Static key mode
secret /etc/openvpn/static.key

# Cipher and HMAC authentication
cipher AES-256-CBC
auth SHA256

# Configure interface IP (for ARP testing)
# TAP mode uses: ifconfig ip netmask
ifconfig %s 255.255.255.0

# Verbosity
verb 5

# Log file
log /tmp/openvpn/client.log
status /tmp/openvpn/status.log 10
`, serverAddr, serverPort, s.TunnelClientIP())

	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.conf", clientConf)
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
		Log("OpenVPN client logs:\n" + logs)
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

// ConfigureOvpnInterface configures the OpenVPN interface IP address and state
func (s *OvpnSuite) ConfigureOvpnInterface() {
	vpp := s.Containers.Vpp.VppInstance

	// Configure tunnel IP address
	cmd := fmt.Sprintf("set interface ip address ovpn0 %s/24", s.TunnelServerIP())
	Log("VPP command: " + cmd)
	result := vpp.Vppctl(cmd)
	Log("Result: " + result)

	// Bring up the interface
	result = vpp.Vppctl("set interface state ovpn0 up")
	Log("Interface state: " + result)
}

// CopyStaticKeyToVpp copies the static key file to the VPP container
func (s *OvpnSuite) CopyStaticKeyToVpp() {
	staticKey, err := os.ReadFile("./resources/openvpn/static.key")
	AssertNil(err, "failed to read static.key")
	s.Containers.Vpp.CreateFile("/tmp/static.key", string(staticKey))
}

// SetupVppOvpnStaticKey sets up VPP with OpenVPN static key mode via startup.conf
func (s *OvpnSuite) SetupVppOvpnStaticKey(keyFile string) {
	// Copy static key to container before VPP starts
	s.CopyStaticKeyToVpp()

	// Get OpenVPN configuration for startup.conf
	ovpnConfig := s.GetOvpnStaticKeyConfig("static-key-server", keyFile)
	Log("OpenVPN startup config:\n" + ovpnConfig.ToString())

	// Start VPP with OpenVPN configuration
	s.StartVppWithOvpnConfig(ovpnConfig)

	// Configure interface IP and state
	s.ConfigureOvpnInterface()
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
	AssertNil(err, "failed to read static.key")
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
	Log("Waiting for OpenVPN tunnel to establish...")
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
			Log("Tunnel interface is up")
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("tunnel interface did not come up within %v", timeout)
}

// WaitForTapTunnel waits for the OpenVPN TAP tunnel interface to come up
func (s *OvpnSuite) WaitForTapTunnel(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		output, err := s.Containers.OpenVpnClient.Exec(false, "ip link show tap0")
		// TAP interfaces show ",UP" when configured
		if err == nil && strings.Contains(output, ",UP") {
			Log("TAP tunnel interface is up")
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("TAP tunnel interface did not come up within %v", timeout)
}

// PingThroughTunnel pings through the OpenVPN tunnel
func (s *OvpnSuite) PingThroughTunnel(targetIP string) error {
	output, err := s.Containers.OpenVpnClient.Exec(false,
		"ping -c 3 -W 5 %s", targetIP)
	Log("Ping output: " + output)
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

// CopyTlsCertsToVpp copies TLS certificates to the VPP container
func (s *OvpnSuite) CopyTlsCertsToVpp() {
	// Copy CA certificate
	caCert, err := os.ReadFile("./resources/openvpn/tls/ca.crt")
	AssertNil(err, "failed to read ca.crt")
	s.Containers.Vpp.CreateFile("/tmp/ca.crt", string(caCert))

	// Copy server certificate
	serverCert, err := os.ReadFile("./resources/openvpn/tls/server.crt")
	AssertNil(err, "failed to read server.crt")
	s.Containers.Vpp.CreateFile("/tmp/server.crt", string(serverCert))

	// Copy server key
	serverKey, err := os.ReadFile("./resources/openvpn/tls/server.key")
	AssertNil(err, "failed to read server.key")
	s.Containers.Vpp.CreateFile("/tmp/server.key", string(serverKey))
}

// CopyTlsAuthKeyToVpp copies the TLS-Auth key to the VPP container
func (s *OvpnSuite) CopyTlsAuthKeyToVpp() {
	taKey, err := os.ReadFile("./resources/openvpn/tls/ta.key")
	AssertNil(err, "failed to read ta.key")
	s.Containers.Vpp.CreateFile("/tmp/ta.key", string(taKey))
}

// SetupVppOvpnTlsAuth sets up VPP with OpenVPN TLS-Auth mode via startup.conf
func (s *OvpnSuite) SetupVppOvpnTlsAuth() {
	// Copy TLS certificates and keys to container before VPP starts
	s.CopyTlsCertsToVpp()
	s.CopyTlsAuthKeyToVpp()

	// Get OpenVPN TLS-Auth configuration for startup.conf
	ovpnConfig := s.GetOvpnTlsAuthConfig("tls-auth-server")
	Log("OpenVPN startup config:\n" + ovpnConfig.ToString())

	// Start VPP with OpenVPN configuration
	s.StartVppWithOvpnConfig(ovpnConfig)

	// Configure interface IP and state
	s.ConfigureOvpnInterface()
}

// SetupVppOvpnTlsAuthWithPush sets up VPP with OpenVPN TLS-Auth mode and push options
func (s *OvpnSuite) SetupVppOvpnTlsAuthWithPush() {
	// Copy TLS certificates and keys to container before VPP starts
	s.CopyTlsCertsToVpp()
	s.CopyTlsAuthKeyToVpp()

	// Get OpenVPN TLS-Auth configuration with push options
	ovpnConfig := s.GetOvpnTlsAuthWithPushConfig("tls-auth-push-server")
	Log("OpenVPN startup config with push:\n" + ovpnConfig.ToString())

	// Start VPP with OpenVPN configuration
	s.StartVppWithOvpnConfig(ovpnConfig)

	// Configure interface IP and state
	s.ConfigureOvpnInterface()
}

// CreateOpenVpnTlsAuthPullClientConfig creates the OpenVPN TLS-Auth client config with pull mode
// This enables PUSH_REQUEST/PUSH_REPLY functionality testing
func (s *OvpnSuite) CreateOpenVpnTlsAuthPullClientConfig() {
	values := struct {
		ServerAddress string
		ServerPort    string
	}{
		ServerAddress: s.VppOvpnAddr(),
		ServerPort:    s.Ports.Ovpn,
	}

	// Create log and config directories in container
	s.Containers.OpenVpnClient.Exec(false, "mkdir -p /tmp/openvpn")
	s.Containers.OpenVpnClient.Exec(false, "mkdir -p /etc/openvpn")

	// Copy CA certificate
	caCert, err := os.ReadFile("./resources/openvpn/tls/ca.crt")
	AssertNil(err, "failed to read ca.crt")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/ca.crt", string(caCert))

	// Copy client certificate
	clientCert, err := os.ReadFile("./resources/openvpn/tls/client.crt")
	AssertNil(err, "failed to read client.crt")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.crt", string(clientCert))

	// Copy client key
	clientKey, err := os.ReadFile("./resources/openvpn/tls/client.key")
	AssertNil(err, "failed to read client.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.key", string(clientKey))

	// Copy TLS-Auth key
	taKey, err := os.ReadFile("./resources/openvpn/tls/ta.key")
	AssertNil(err, "failed to read ta.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/ta.key", string(taKey))

	// Create client config from template with pull mode
	s.Containers.OpenVpnClient.CreateConfigFromTemplate(
		"/etc/openvpn/client.conf",
		"./resources/openvpn/tls-auth-pull-client.conf.template",
		values,
	)
}

// CreateOpenVpnTlsAuthClientConfig creates the OpenVPN TLS-Auth client configuration
func (s *OvpnSuite) CreateOpenVpnTlsAuthClientConfig() {
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

	// Copy CA certificate
	caCert, err := os.ReadFile("./resources/openvpn/tls/ca.crt")
	AssertNil(err, "failed to read ca.crt")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/ca.crt", string(caCert))

	// Copy client certificate
	clientCert, err := os.ReadFile("./resources/openvpn/tls/client.crt")
	AssertNil(err, "failed to read client.crt")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.crt", string(clientCert))

	// Copy client key
	clientKey, err := os.ReadFile("./resources/openvpn/tls/client.key")
	AssertNil(err, "failed to read client.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.key", string(clientKey))

	// Copy TLS-Auth key
	taKey, err := os.ReadFile("./resources/openvpn/tls/ta.key")
	AssertNil(err, "failed to read ta.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/ta.key", string(taKey))

	// Create client config from template
	s.Containers.OpenVpnClient.CreateConfigFromTemplate(
		"/etc/openvpn/client.conf",
		"./resources/openvpn/tls-auth-client.conf.template",
		values,
	)
}

// CreateOpenVpnTlsAuthFragmentClientConfig creates the OpenVPN TLS-Auth client config with fragmentation
func (s *OvpnSuite) CreateOpenVpnTlsAuthFragmentClientConfig(fragmentSize int) {
	values := struct {
		ServerAddress  string
		ServerPort     string
		ClientTunnelIP string
		ServerTunnelIP string
		FragmentSize   int
	}{
		ServerAddress:  s.VppOvpnAddr(),
		ServerPort:     s.Ports.Ovpn,
		ClientTunnelIP: s.TunnelClientIP(),
		ServerTunnelIP: s.TunnelServerIP(),
		FragmentSize:   fragmentSize,
	}

	// Create log and config directories in container
	s.Containers.OpenVpnClient.Exec(false, "mkdir -p /tmp/openvpn")
	s.Containers.OpenVpnClient.Exec(false, "mkdir -p /etc/openvpn")

	// Copy CA certificate
	caCert, err := os.ReadFile("./resources/openvpn/tls/ca.crt")
	AssertNil(err, "failed to read ca.crt")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/ca.crt", string(caCert))

	// Copy client certificate
	clientCert, err := os.ReadFile("./resources/openvpn/tls/client.crt")
	AssertNil(err, "failed to read client.crt")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.crt", string(clientCert))

	// Copy client key
	clientKey, err := os.ReadFile("./resources/openvpn/tls/client.key")
	AssertNil(err, "failed to read client.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.key", string(clientKey))

	// Copy TLS-Auth key
	taKey, err := os.ReadFile("./resources/openvpn/tls/ta.key")
	AssertNil(err, "failed to read ta.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/ta.key", string(taKey))

	// Create client config from template with fragment
	s.Containers.OpenVpnClient.CreateConfigFromTemplate(
		"/etc/openvpn/client.conf",
		"./resources/openvpn/tls-auth-frag-client.conf.template",
		values,
	)
}

// PingThroughTunnelWithSize pings through the tunnel with a specific payload size
func (s *OvpnSuite) PingThroughTunnelWithSize(targetIP string, payloadSize int) error {
	output, err := s.Containers.OpenVpnClient.Exec(false,
		"ping -c 3 -W 5 -s %d %s", payloadSize, targetIP)
	Log("Ping output (size " + fmt.Sprintf("%d", payloadSize) + "): " + output)
	if err != nil {
		return fmt.Errorf("ping failed: %v", err)
	}
	if !strings.Contains(output, "3 received") && !strings.Contains(output, "3 packets received") {
		return fmt.Errorf("ping did not receive all packets")
	}
	return nil
}

// CopyTlsCryptKeyToVpp copies the TLS-Crypt key to the VPP container
func (s *OvpnSuite) CopyTlsCryptKeyToVpp() {
	tcKey, err := os.ReadFile("./resources/openvpn/tls/tc.key")
	AssertNil(err, "failed to read tc.key")
	s.Containers.Vpp.CreateFile("/tmp/tc.key", string(tcKey))
}

// SetupVppOvpnTlsCrypt sets up VPP with OpenVPN TLS-Crypt mode via startup.conf
func (s *OvpnSuite) SetupVppOvpnTlsCrypt() {
	// Copy TLS certificates and keys to container before VPP starts
	s.CopyTlsCertsToVpp()
	s.CopyTlsCryptKeyToVpp()

	// Get OpenVPN TLS-Crypt configuration for startup.conf
	ovpnConfig := s.GetOvpnTlsCryptConfig("tls-crypt-server")
	Log("OpenVPN startup config:\n" + ovpnConfig.ToString())

	// Start VPP with OpenVPN configuration
	s.StartVppWithOvpnConfig(ovpnConfig)

	// Configure interface IP and state
	s.ConfigureOvpnInterface()
}

// CopyTlsCryptV2ServerKeyToVpp copies the TLS-Crypt-V2 server key to VPP container
func (s *OvpnSuite) CopyTlsCryptV2ServerKeyToVpp() {
	serverKey, err := readFileWithFallback(
		"./resources/openvpn/tls/tls-crypt-v2-server.key",
		"./resources/openvpn/tls/tls-crypt-v2-server.key.bak",
	)
	AssertNil(err, "failed to read tls-crypt-v2-server.key")
	s.Containers.Vpp.CreateFile("/tmp/tls-crypt-v2-server.key", string(serverKey))
}

// SetupVppOvpnTlsCryptV2 sets up VPP with OpenVPN TLS-Crypt-V2 mode via startup.conf
func (s *OvpnSuite) SetupVppOvpnTlsCryptV2() {
	// Copy TLS certificates and keys to container before VPP starts
	s.CopyTlsCertsToVpp()
	s.CopyTlsCryptV2ServerKeyToVpp()

	// Get OpenVPN TLS-Crypt-V2 configuration for startup.conf
	ovpnConfig := s.GetOvpnTlsCryptV2Config("tls-crypt-v2-server")
	Log("OpenVPN TLS-Crypt-V2 startup config:\n" + ovpnConfig.ToString())

	// Start VPP with OpenVPN configuration
	s.StartVppWithOvpnConfig(ovpnConfig)

	// Configure interface IP and state
	s.ConfigureOvpnInterface()
}

// CreateOpenVpnTlsCryptClientConfig creates the OpenVPN TLS-Crypt client configuration
func (s *OvpnSuite) CreateOpenVpnTlsCryptClientConfig() {
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

	// Copy CA certificate
	caCert, err := os.ReadFile("./resources/openvpn/tls/ca.crt")
	AssertNil(err, "failed to read ca.crt")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/ca.crt", string(caCert))

	// Copy client certificate
	clientCert, err := os.ReadFile("./resources/openvpn/tls/client.crt")
	AssertNil(err, "failed to read client.crt")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.crt", string(clientCert))

	// Copy client key
	clientKey, err := os.ReadFile("./resources/openvpn/tls/client.key")
	AssertNil(err, "failed to read client.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.key", string(clientKey))

	// Copy TLS-Crypt key
	tcKey, err := os.ReadFile("./resources/openvpn/tls/tc.key")
	AssertNil(err, "failed to read tc.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/tc.key", string(tcKey))

	// Create client config from template
	s.Containers.OpenVpnClient.CreateConfigFromTemplate(
		"/etc/openvpn/client.conf",
		"./resources/openvpn/tls-crypt-client.conf.template",
		values,
	)
}

// CreateOpenVpnTlsCryptV2ClientConfig creates the OpenVPN TLS-Crypt-V2 client configuration
func (s *OvpnSuite) CreateOpenVpnTlsCryptV2ClientConfig() {
	serverAddr := s.VppOvpnAddr()
	serverPort := s.Ports.Ovpn

	// Create log and config directories in container
	s.Containers.OpenVpnClient.Exec(false, "mkdir -p /tmp/openvpn")
	s.Containers.OpenVpnClient.Exec(false, "mkdir -p /etc/openvpn")

	// Copy CA certificate
	caCert, err := os.ReadFile("./resources/openvpn/tls/ca.crt")
	AssertNil(err, "failed to read ca.crt")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/ca.crt", string(caCert))

	// Copy client certificate
	clientCert, err := os.ReadFile("./resources/openvpn/tls/client.crt")
	AssertNil(err, "failed to read client.crt")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.crt", string(clientCert))

	// Copy client key
	clientKey, err := os.ReadFile("./resources/openvpn/tls/client.key")
	AssertNil(err, "failed to read client.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.key", string(clientKey))

	// Copy TLS-Crypt-V2 client key
	v2ClientKey, err := readFileWithFallback(
		"./resources/openvpn/tls/tls-crypt-v2-client.key",
		"./resources/openvpn/tls/tls-crypt-v2-client.key.bak",
	)
	AssertNil(err, "failed to read tls-crypt-v2-client.key")
	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/tls-crypt-v2-client.key", string(v2ClientKey))

	// Create client config for TLS-Crypt-V2
	clientConf := fmt.Sprintf(`# OpenVPN TLS-Crypt-V2 client configuration
dev tun
proto udp
remote %s %s
resolv-retry infinite
nobind
persist-key
persist-tun
tls-client

# TLS configuration
ca /etc/openvpn/ca.crt
cert /etc/openvpn/client.crt
key /etc/openvpn/client.key

# TLS-Crypt-V2 client key (unique per-client wrapped key)
tls-crypt-v2 /etc/openvpn/tls-crypt-v2-client.key

# Cipher and auth
cipher AES-256-GCM
auth SHA256

# Manual tunnel IP configuration
ifconfig %s %s

# Verbosity
verb 5

# Log file
log /tmp/openvpn/client.log
status /tmp/openvpn/status.log 5
`, serverAddr, serverPort, s.TunnelClientIP(), s.TunnelServerIP())

	s.Containers.OpenVpnClient.CreateFile("/etc/openvpn/client.conf", clientConf)
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
				Log(testName + ": BEGIN")
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
				Log(testName + ": BEGIN")
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
