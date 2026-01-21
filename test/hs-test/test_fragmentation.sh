#!/bin/bash

# OpenVPN Fragmentation Test
# Uses TAP interface, interrupt mode, and tests large packet fragmentation
#
# SAFETY:
# - Uses TAP interface (isolated from host network)
# - Does NOT affect your SSH connection
# - Does NOT restart docker service
# - Does NOT delete any containers not belonging to this test
# - Uses interrupt mode (not poll mode)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPP_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VPP_BIN="$VPP_ROOT/build-root/install-vpp_debug-native/vpp/bin/vpp"
VPPCTL="$VPP_ROOT/build-root/install-vpp_debug-native/vpp/bin/vppctl"
VPP_LIB="$VPP_ROOT/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu"
VPP_PLUGINS="$VPP_LIB/vpp_plugins"

export LD_LIBRARY_PATH="$VPP_LIB:$LD_LIBRARY_PATH"

# Test configuration
TEST_PREFIX="ovpn-frag"
TAP_NAME="vpptap-frag"

# Network config (isolated - won't affect your SSH)
VPP_IP="10.200.100.1"
LINUX_IP="10.200.100.2"
VPP_TUNNEL_IP="10.9.0.1"
CLIENT_TUNNEL_IP="10.9.0.2"
OVPN_PORT="11951"

# Fragmentation config - small fragment size to force fragmentation
FRAGMENT_SIZE=200

TLS_DIR="/tmp/${TEST_PREFIX}-tls"
VPP_RUN_DIR="/tmp/${TEST_PREFIX}-vpp"
CLIENT_PID_FILE="/tmp/${TEST_PREFIX}-client.pid"

cleanup() {
    echo ""
    echo "=== Cleaning up ==="

    # Kill OpenVPN client if running
    if [ -f "$CLIENT_PID_FILE" ]; then
        kill $(cat $CLIENT_PID_FILE) 2>/dev/null || true
        rm -f $CLIENT_PID_FILE
    fi
    pkill -f "openvpn.*${TEST_PREFIX}" 2>/dev/null || true

    # Kill VPP instance (only our specific one)
    if [ -f "$VPP_RUN_DIR/run/vpp.pid" ]; then
        kill $(cat $VPP_RUN_DIR/run/vpp.pid) 2>/dev/null || true
    fi

    # Remove TAP interface
    ip link del $TAP_NAME 2>/dev/null || true

    rm -rf $VPP_RUN_DIR
    echo "Cleanup done"
}

trap cleanup EXIT

# Check VPP is built
[ ! -f "$VPP_BIN" ] && echo "ERROR: Build VPP first with 'make build'" && exit 1

# Check openvpn is installed
if ! command -v openvpn &> /dev/null; then
    echo "ERROR: openvpn not installed. Install with: apt-get install openvpn"
    exit 1
fi

# Clean previous test artifacts
cleanup 2>/dev/null || true
sleep 1

echo "========================================"
echo "  OpenVPN Fragmentation Test"
echo "========================================"
echo "Fragment size: $FRAGMENT_SIZE bytes"
echo "Mode: Interrupt (not poll)"
echo "Network: TAP interface (safe for SSH)"
echo ""

echo "=== Setting up TLS certificates ==="
rm -rf $TLS_DIR && mkdir -p $TLS_DIR
CERTS_SRC="$SCRIPT_DIR/resources/openvpn/tls"
if [ -d "$CERTS_SRC" ]; then
    cp $CERTS_SRC/ca.crt $CERTS_SRC/server.crt $CERTS_SRC/server.key $TLS_DIR/
    cp $CERTS_SRC/client.crt $CERTS_SRC/client.key $CERTS_SRC/ta.key $TLS_DIR/
    chmod 600 $TLS_DIR/*.key
    echo "Certificates copied from $CERTS_SRC"
else
    echo "ERROR: TLS certificates not found at $CERTS_SRC"
    exit 1
fi

echo ""
echo "=== Creating VPP config (interrupt mode) ==="
rm -rf $VPP_RUN_DIR && mkdir -p $VPP_RUN_DIR/run

cat > $VPP_RUN_DIR/startup.conf << EOF
unix {
  nodaemon
  cli-listen $VPP_RUN_DIR/run/cli.sock
  cli-no-pager
  log $VPP_RUN_DIR/vpp.log
  full-coredump
  runtime-dir $VPP_RUN_DIR/run
  pidfile $VPP_RUN_DIR/run/vpp.pid
}

api-segment { prefix ${TEST_PREFIX} }

# Interrupt mode configuration
cpu {
  main-core 1
  workers 0
}

# No poll-sleep-usec means interrupt mode
# (poll mode would have: poll-sleep-usec 100)

buffers {
  buffers-per-numa 16384
}

plugins {
  path $VPP_PLUGINS
  plugin default { enable }
  plugin dpdk_plugin.so { disable }
}

logging {
  default-log-level debug
  class ovpn/all { level debug }
}

openvpn {
  instance frag-test-server {
    local $VPP_IP
    port $OVPN_PORT
    dev ovpn0
    dev-type tun
    server 10.9.0.0 255.255.255.0
    ca $TLS_DIR/ca.crt
    cert $TLS_DIR/server.crt
    key $TLS_DIR/server.key
    tls-auth $TLS_DIR/ta.key
    fragment $FRAGMENT_SIZE
    mssfix $FRAGMENT_SIZE
    keepalive 10 60
  }
}
EOF

echo "Fragment size configured: $FRAGMENT_SIZE bytes"

echo ""
echo "=== Starting VPP ==="
$VPP_BIN -c $VPP_RUN_DIR/startup.conf &
sleep 5

if [ ! -f "$VPP_RUN_DIR/run/vpp.pid" ]; then
    echo "ERROR: VPP failed to start"
    echo "=== VPP Log ==="
    cat $VPP_RUN_DIR/vpp.log 2>/dev/null || echo "(no log)"
    exit 1
fi

VPP_PID=$(cat $VPP_RUN_DIR/run/vpp.pid)
echo "VPP started with PID: $VPP_PID"

VPPCTL_CMD="$VPPCTL -s $VPP_RUN_DIR/run/cli.sock"

# Create TAP interface
echo ""
echo "=== Configuring VPP interfaces ==="
$VPPCTL_CMD create tap id 0 host-if-name $TAP_NAME host-ip4-addr $LINUX_IP/24
$VPPCTL_CMD set interface ip address tap0 $VPP_IP/24
$VPPCTL_CMD set interface state tap0 up

$VPPCTL_CMD set interface ip address ovpn0 $VPP_TUNNEL_IP/24
$VPPCTL_CMD set interface state ovpn0 up

echo ""
echo "=== VPP Interfaces ==="
$VPPCTL_CMD show interface
echo ""
echo "=== OpenVPN Configuration ==="
$VPPCTL_CMD show ovpn interface

echo ""
echo "=== Linux TAP interface ==="
ip addr show $TAP_NAME

echo ""
echo "=== Testing connectivity ==="
ping -c 1 -W 2 $VPP_IP && echo "Host -> VPP: OK" || {
    echo "ERROR: Cannot reach VPP"
    exit 1
}

echo ""
echo "=== Starting OpenVPN client ==="
CLIENT_CONF="/tmp/${TEST_PREFIX}-client.conf"

cat > $CLIENT_CONF << EOF
dev tun
proto udp
remote $VPP_IP $OVPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
ca $TLS_DIR/ca.crt
cert $TLS_DIR/client.crt
key $TLS_DIR/client.key
tls-auth $TLS_DIR/ta.key 1
tls-client
cipher AES-256-GCM
auth SHA256
pull
fragment $FRAGMENT_SIZE
mssfix $FRAGMENT_SIZE
keepalive 10 60
verb 4
EOF

# Start OpenVPN client
openvpn --config $CLIENT_CONF --log /tmp/${TEST_PREFIX}-client.log &
echo $! > $CLIENT_PID_FILE
CLIENT_PID=$(cat $CLIENT_PID_FILE)
echo "OpenVPN client started with PID: $CLIENT_PID"

echo "Waiting for tunnel to establish (60s)..."
TUNNEL_UP=0
for i in $(seq 1 60); do
    sleep 1
    # Check if client received ifconfig (tunnel IP assigned)
    if grep -q "PUSH: Received" /tmp/${TEST_PREFIX}-client.log 2>/dev/null; then
        echo "Tunnel configuration received!"
        TUNNEL_UP=1
        sleep 2  # Give it a moment to configure the interface
        break
    fi
    if [ $((i % 10)) -eq 0 ]; then
        echo " $i seconds..."
    else
        echo -n "."
    fi
done
echo ""

echo ""
echo "=== OpenVPN Client Log (last 30 lines) ==="
tail -30 /tmp/${TEST_PREFIX}-client.log 2>/dev/null || echo "(no log yet)"

echo ""
echo "=== VPP OpenVPN Status ==="
$VPPCTL_CMD show ovpn interface
$VPPCTL_CMD show ovpn peers

echo ""
echo "=== Host Tunnel Interface ==="
ip addr show tun0 2>/dev/null || echo "tun0 not found"

# Check if tunnel is up (client received push config)
if [ "$TUNNEL_UP" -eq 1 ] && ip addr show tun0 2>/dev/null | grep -q "inet"; then
    # Get the actual tunnel IP assigned to the client's tun0
    TUN_IP=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d/ -f1)
    echo ""
    echo "Client tunnel IP: $TUN_IP"
    echo ""
    echo "========================================"
    echo "  Fragmentation Tests"
    echo "========================================"
    echo ""

    echo "Test 1: Small ping (no fragmentation needed)"
    echo "  Sending 64-byte ping..."
    ping -c 3 -s 64 $VPP_TUNNEL_IP && echo "  Result: PASS" || echo "  Result: FAIL"

    echo ""
    echo "Test 2: Medium ping (should fragment into ~3 pieces)"
    echo "  Sending 500-byte ping (fragment size: $FRAGMENT_SIZE)..."
    ping -c 3 -s 500 $VPP_TUNNEL_IP && echo "  Result: PASS" || echo "  Result: FAIL"

    echo ""
    echo "Test 3: Large ping (should fragment into ~5 pieces)"
    echo "  Sending 1000-byte ping..."
    ping -c 3 -s 1000 $VPP_TUNNEL_IP && echo "  Result: PASS" || echo "  Result: FAIL"

    echo ""
    echo "Test 4: Very large ping (should fragment into ~7+ pieces)"
    echo "  Sending 1400-byte ping..."
    ping -c 3 -s 1400 $VPP_TUNNEL_IP && echo "  Result: PASS" || echo "  Result: FAIL"

    echo ""
    echo "=== VPP Statistics ==="
    $VPPCTL_CMD show ovpn stats 2>/dev/null || $VPPCTL_CMD show errors | grep -i ovpn || echo "(no stats command)"

    echo ""
    echo "=== Error Counters ==="
    $VPPCTL_CMD show errors | grep -i ovpn || echo "No OpenVPN errors"

    echo ""
    echo "========================================"
    echo "  All Fragmentation Tests Complete!"
    echo "========================================"
else
    echo ""
    echo "WARNING: Tunnel not fully established"
    echo ""
    echo "=== Debugging Info ==="
    echo "VPP peers:"
    $VPPCTL_CMD show ovpn peers
    echo ""
    echo "Client log (last 50 lines):"
    tail -50 /tmp/${TEST_PREFIX}-client.log
    echo ""
    echo "VPP log (last 50 lines):"
    tail -50 $VPP_RUN_DIR/vpp.log
fi

echo ""
echo "=== Interactive Mode ==="
echo "Commands for debugging:"
echo "  VPP CLI:      $VPPCTL_CMD"
echo "  Client log:   tail -f /tmp/${TEST_PREFIX}-client.log"
echo "  VPP log:      tail -f $VPP_RUN_DIR/vpp.log"
echo ""
echo "Press Enter to cleanup and exit..."
read -r
