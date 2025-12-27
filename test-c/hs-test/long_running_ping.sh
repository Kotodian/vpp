#!/bin/bash

# Long-running ping test for OpenVPN
# Monitor with: docker logs -f ovpn-ping-test

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPP_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VPP_BIN="$VPP_ROOT/build-root/install-vpp_debug-native/vpp/bin/vpp"
VPPCTL="$VPP_ROOT/build-root/install-vpp_debug-native/vpp/bin/vppctl"
VPP_LIB="$VPP_ROOT/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu"
VPP_PLUGINS="$VPP_LIB/vpp_plugins"

export LD_LIBRARY_PATH="$VPP_LIB:$LD_LIBRARY_PATH"

# Network config
TAP_NAME="vpptap0"
VPP_IP="10.200.0.1"
LINUX_IP="10.200.0.2"
VPP_TUNNEL_IP="10.8.0.1"
CLIENT_TUNNEL_IP="10.8.0.2"
OVPN_PORT="11940"

CLIENT_CONTAINER="ovpn-client"
PING_CONTAINER="ovpn-ping-test"
TLS_DIR="/tmp/ovpn-tls-longrun"
VPP_RUN_DIR="/tmp/vpp-ovpn-longrun"

cleanup() {
    echo ""
    echo "Cleaning up..."
    docker rm -f $CLIENT_CONTAINER 2>/dev/null || true
    docker rm -f $PING_CONTAINER 2>/dev/null || true
    pkill -9 vpp 2>/dev/null || true
    sleep 1
    rm -rf $VPP_RUN_DIR
    echo "Done"
}

trap cleanup EXIT

[ ! -f "$VPP_BIN" ] && echo "ERROR: Build VPP first" && exit 1

pkill -9 vpp 2>/dev/null || true
docker rm -f $CLIENT_CONTAINER 2>/dev/null || true
docker rm -f $PING_CONTAINER 2>/dev/null || true
sleep 1

echo "=== Copying TLS certs from test resources ==="
rm -rf $TLS_DIR && mkdir -p $TLS_DIR
CERTS_SRC="$SCRIPT_DIR/resources/openvpn/tls"
cp $CERTS_SRC/ca.crt $CERTS_SRC/server.crt $CERTS_SRC/server.key $TLS_DIR/
cp $CERTS_SRC/client.crt $CERTS_SRC/client.key $CERTS_SRC/ta.key $TLS_DIR/

echo "=== Creating VPP config ==="
rm -rf $VPP_RUN_DIR && mkdir -p $VPP_RUN_DIR/run

cat > $VPP_RUN_DIR/startup.conf << EOF
unix {
  nodaemon
  cli-listen $VPP_RUN_DIR/run/cli.sock
  cli-no-pager
  log $VPP_RUN_DIR/vpp.log
}
api-segment { prefix vpp-ovpn-test }
cpu { main-core 0 }
plugins {
  path $VPP_PLUGINS
  plugin default { enable }
  plugin dpdk_plugin.so { disable }
}
logging { default-log-level debug }
openvpn {
  instance tls-auth-server {
    local $VPP_IP
    port $OVPN_PORT
    dev ovpn0
    dev-type tun
    server 10.8.0.0 255.255.255.0
    ca $TLS_DIR/ca.crt
    cert $TLS_DIR/server.crt
    key $TLS_DIR/server.key
    tls-auth $TLS_DIR/ta.key
  }
}
EOF

echo "=== Starting VPP ==="
$VPP_BIN -c $VPP_RUN_DIR/startup.conf &
VPP_PID=$!
echo "VPP PID: $VPP_PID"
sleep 5

if ! kill -0 $VPP_PID 2>/dev/null; then
    echo "VPP failed:"
    cat $VPP_RUN_DIR/vpp.log
    exit 1
fi

VPPCTL_CMD="$VPPCTL -s $VPP_RUN_DIR/run/cli.sock"

echo "=== Creating TAP interface ==="
$VPPCTL_CMD create tap id 0 host-if-name $TAP_NAME host-ip4-addr $LINUX_IP/24
$VPPCTL_CMD set interface ip address tap0 $VPP_IP/24
$VPPCTL_CMD set interface state tap0 up

$VPPCTL_CMD set interface ip address ovpn0 $VPP_TUNNEL_IP/24
$VPPCTL_CMD set interface state ovpn0 up

echo ""
echo "=== VPP Interfaces ==="
$VPPCTL_CMD show interface
echo ""
$VPPCTL_CMD show ovpn

echo ""
echo "=== Linux TAP interface ==="
ip addr show $TAP_NAME

echo ""
echo "=== Testing connectivity ==="
ping -c 2 $VPP_IP && echo "Host -> VPP OK" || echo "Host -> VPP FAIL"

echo "=== Starting OpenVPN Client ==="
CLIENT_CONF="/tmp/openvpn-client-longrun"
rm -rf $CLIENT_CONF && mkdir -p $CLIENT_CONF

cat > $CLIENT_CONF/client.conf << EOF
dev tun
proto udp
remote $VPP_IP $OVPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
ca /etc/openvpn/tls/ca.crt
cert /etc/openvpn/tls/client.crt
key /etc/openvpn/tls/client.key
tls-auth /etc/openvpn/tls/ta.key 1
tls-client
cipher AES-256-GCM
auth SHA256
pull
keepalive 10 60
verb 4
EOF

# Start OpenVPN client container - logs visible via docker logs
docker run -d --name $CLIENT_CONTAINER \
    --network host \
    --privileged \
    -v $CLIENT_CONF:/etc/openvpn/conf:ro \
    -v $TLS_DIR:/etc/openvpn/tls:ro \
    ubuntu:24.04 \
    bash -c "
        apt-get update -qq && apt-get install -y -qq openvpn iproute2 iputils-ping >/dev/null 2>&1
        mkdir -p /dev/net && mknod /dev/net/tun c 10 200 2>/dev/null || true
        echo '=== Starting OpenVPN client ==='
        openvpn --config /etc/openvpn/conf/client.conf
    "

echo "Waiting for tunnel (25s)..."
sleep 25

echo ""
echo "=== OpenVPN Client logs ==="
docker logs $CLIENT_CONTAINER 2>&1 | tail -30

echo ""
echo "=== VPP Status ==="
$VPPCTL_CMD show ovpn
$VPPCTL_CMD show interface ovpn0
$VPPCTL_CMD show errors

# Start ping container - this is what you monitor with docker logs
echo ""
echo "=== Starting ping container ==="
docker run -d --name $PING_CONTAINER \
    --network host \
    --privileged \
    ubuntu:24.04 \
    bash -c "
        apt-get update -qq && apt-get install -y -qq iputils-ping >/dev/null 2>&1
        echo '=========================================='
        echo '  OpenVPN Ping Test Started'
        echo '  Target: $VPP_TUNNEL_IP (VPP tunnel)'
        echo '  Time: '\$(date)
        echo '=========================================='
        echo ''

        success=0
        fail=0
        n=0

        while true; do
            n=\$((n+1))
            result=\$(ping -c 1 -W 2 $VPP_TUNNEL_IP 2>&1)
            if echo \"\$result\" | grep -q 'bytes from'; then
                success=\$((success+1))
                latency=\$(echo \"\$result\" | grep 'time=' | sed 's/.*time=\([0-9.]*\).*/\1/')
                if [ \$((n % 10)) -eq 0 ]; then
                    echo \"[\$(date '+%Y-%m-%d %H:%M:%S')] #\$n OK  latency=\${latency}ms  (success:\$success fail:\$fail)\"
                fi
            else
                fail=\$((fail+1))
                echo \"[\$(date '+%Y-%m-%d %H:%M:%S')] #\$n FAIL (success:\$success fail:\$fail)\"
            fi
            sleep 1
        done
    "

echo ""
echo "======================================================="
echo "  Long-running Ping Test Started!"
echo "======================================================="
echo ""
echo "  Monitor ping:        docker logs -f $PING_CONTAINER"
echo "  Monitor OpenVPN:     docker logs -f $CLIENT_CONTAINER"
echo ""
echo "  VPP CLI:             $VPPCTL_CMD"
echo "  VPP log:             tail -f $VPP_RUN_DIR/vpp.log"
echo ""
echo "  Stop test:           docker rm -f $PING_CONTAINER $CLIENT_CONTAINER; pkill vpp"
echo ""
echo "======================================================="
echo ""

# Keep script running so cleanup trap works on Ctrl+C
echo "Press Ctrl+C to stop and cleanup..."
while true; do
    sleep 60
    # Periodic status
    echo ""
    echo "[$(date '+%H:%M:%S')] === Status Check ==="
    docker logs --tail 3 $PING_CONTAINER 2>/dev/null || echo "Ping container not running"
    $VPPCTL_CMD show errors 2>/dev/null | grep -v "^$" | head -5 || true
done
