# OpenVPN Plugin Integration Test Design

## Overview

This document describes the integration test strategy for the VPP OpenVPN plugin using VPP's Go-based host stack test framework (`test-c/hs-test/`).

## Implementation Status

### Completed

| Component | File | Description |
|-----------|------|-------------|
| Container Topology | `topo-containers/ovpn.yaml` | Defines VPP and OpenVPN client containers |
| Network Topology | `topo-network/ovpn.yaml` | Defines TAP interfaces for tunnel traffic |
| Dockerfile | `docker/Dockerfile.openvpn` | OpenVPN client container image |
| Test Suite | `infra/suite_ovpn.go` | Go test suite with helper methods |
| Test Cases | `ovpn_test.go` | Integration test implementations |
| Static Key | `resources/openvpn/static.key` | Test static key (DO NOT USE IN PRODUCTION) |
| Client Config | `resources/openvpn/client.conf.template` | OpenVPN client configuration template |
| Build Script | `script/build-images.sh` | Updated to build OpenVPN image |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Test Host                                 │
│  ┌─────────────────────┐      ┌─────────────────────────────┐  │
│  │   VPP Container     │      │   OpenVPN Client Container  │  │
│  │  ┌───────────────┐  │      │  ┌───────────────────────┐  │  │
│  │  │  VPP Process  │  │      │  │  openvpn process      │  │  │
│  │  │  ┌─────────┐  │  │      │  │  ┌─────────────────┐  │  │  │
│  │  │  │ovpn0    │  │  │      │  │  │tun0             │  │  │  │
│  │  │  │10.8.0.1 │  │  │      │  │  │10.8.0.2         │  │  │  │
│  │  │  └────┬────┘  │  │      │  │  └────────┬────────┘  │  │  │
│  │  │       │       │  │      │  │           │           │  │  │
│  │  │  ┌────┴────┐  │  │      │  │  ┌────────┴────────┐  │  │  │
│  │  │  │tap1     │  │  │      │  │  │UDP socket       │  │  │  │
│  │  │  │10.10.2.x│──┼──┼──────┼──┼──│10.10.2.y        │  │  │  │
│  │  │  └─────────┘  │  │      │  │  └─────────────────┘  │  │  │
│  │  └───────────────┘  │      │  └───────────────────────┘  │  │
│  └─────────────────────┘      └─────────────────────────────┘  │
│              │                              │                   │
│       ┌──────┴──────────────────────────────┴────────┐         │
│       │           Linux Network Stack                 │         │
│       │         (TAP interfaces, bridges)             │         │
│       └───────────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

## Test Cases

### 1. OvpnInterfaceCreateTest

**Purpose:** Verify basic OpenVPN interface lifecycle in VPP.

**Steps:**
1. Create OpenVPN interface via VPP CLI
2. Verify interface appears in `show interface`
3. Set interface state to UP
4. Verify interface is UP
5. Delete interface
6. Verify interface is removed

**Expected Result:** Interface can be created, configured, and deleted without errors.

### 2. OvpnShowCommandsTest

**Purpose:** Verify show commands work correctly.

**Steps:**
1. Create and configure OpenVPN interface
2. Run `show ovpn interface`
3. Run `show ovpn peers`
4. Run `show ovpn stats`

**Expected Result:** All show commands execute without errors.

### 3. OvpnClientConnectivityTest (Solo)

**Purpose:** Verify end-to-end connectivity with real OpenVPN client.

**Steps:**
1. Configure VPP OpenVPN interface
2. Start OpenVPN client container
3. Wait for tunnel establishment (tun0 interface UP)
4. Ping through tunnel from client to VPP
5. Verify peer appears in VPP

**Expected Result:** Ping succeeds, demonstrating full tunnel connectivity.

## Running the Tests

### Prerequisites

1. VPP built with OpenVPN plugin
2. Docker installed and running
3. Go 1.21+ installed

### Build Test Infrastructure

```bash
cd test-c/hs-test
make build
```

### Run All OpenVPN Tests

```bash
make test LABEL=Ovpn
```

### Run Specific Test

```bash
make test TEST=OvpnInterfaceCreateTest
```

### Debug Mode

```bash
make test-debug LABEL=Ovpn
```

## File Structure

```
test-c/hs-test/
├── docker/
│   └── Dockerfile.openvpn          # OpenVPN client image
├── infra/
│   └── suite_ovpn.go               # Test suite implementation
├── resources/
│   └── openvpn/
│       ├── static.key              # Test static key
│       ├── client.conf.template    # Client config template
│       └── test_connectivity.sh    # Helper script
├── script/
│   └── build-images.sh             # Updated for openvpn image
├── topo-containers/
│   └── ovpn.yaml                   # Container definitions
├── topo-network/
│   └── ovpn.yaml                   # Network topology
└── ovpn_test.go                    # Test implementations
```

## Suite Helper Methods

The `OvpnSuite` provides these helper methods:

| Method | Description |
|--------|-------------|
| `VppAddr()` | Returns VPP's inner tunnel IP |
| `VppOvpnAddr()` | Returns VPP's OpenVPN UDP endpoint |
| `ClientOvpnAddr()` | Returns client's UDP endpoint |
| `TunnelServerIP()` | Returns server tunnel IP (10.8.0.1) |
| `TunnelClientIP()` | Returns client tunnel IP (10.8.0.2) |
| `ConfigureVppOvpn()` | Configures VPP OpenVPN interface |
| `ConfigureVppOvpnStaticKey()` | Configures VPP with static key |
| `CreateOpenVpnClientConfig()` | Creates client config from template |
| `StartOpenVpnClient()` | Starts OpenVPN client process |
| `WaitForTunnel()` | Waits for tunnel interface to come up |
| `PingThroughTunnel()` | Tests ping through tunnel |
| `ShowOvpnPeers()` | Returns `show ovpn peers` output |
| `ShowOvpnInterface()` | Returns `show ovpn interface` output |
| `CollectOvpnLogs()` | Collects client logs on failure |

## Future Enhancements

### Phase 2: Control Channel Tests

- TLS handshake verification
- Certificate-based authentication
- Session renegotiation (soft reset)
- Key rotation (rekey)

### Phase 3: Advanced Tests

- Multiple peers
- NAT traversal (float)
- Performance benchmarks
- Memory leak detection
- Error injection

## Configuration Notes

### Static Key Mode

The tests use static key mode for simplicity:
- No TLS handshake required
- No certificates needed
- Suitable for basic connectivity testing

### Network Addressing

| Network | Purpose | Range |
|---------|---------|-------|
| Network 1 | Inner tunnel traffic | 10.10.1.0/24 |
| Network 2 | Encrypted UDP traffic | 10.10.2.0/24 |
| Tunnel | Inside tunnel | 10.8.0.0/24 |

### Port Allocation

OpenVPN UDP port is dynamically allocated by the test framework to avoid conflicts.

## Troubleshooting

### Tunnel Not Establishing

1. Check VPP logs: `show logging`
2. Check OpenVPN client logs: `/tmp/openvpn/client.log`
3. Verify network connectivity between containers
4. Check firewall rules

### Build Failures

1. Ensure VPP is built: `make build` in VPP root
2. Rebuild test images: `make build FORCE_BUILD=true`
3. Check Docker daemon is running

### Test Timeouts

Increase timeout: `make test TIMEOUT=10` (10 minutes)
