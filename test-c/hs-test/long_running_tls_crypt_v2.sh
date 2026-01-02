#!/bin/bash

# Long-running TLS-Crypt-V2 OpenVPN test
# VPP with TAP interface, OpenVPN client in Docker

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

CLIENT_CONTAINER="openvpn-client-tlscryptv2"
TLS_DIR="/tmp/ovpn-tls-crypt-v2"
VPP_RUN_DIR="/tmp/vpp-tls-crypt-v2-longrun"

cleanup() {
    echo ""
    echo "Cleaning up..."
    docker rm -f $CLIENT_CONTAINER 2>/dev/null || true
    pkill -9 vpp 2>/dev/null || true
    sleep 1
    rm -rf $VPP_RUN_DIR
    echo "Done"
}

trap cleanup EXIT

[ ! -f "$VPP_BIN" ] && echo "ERROR: Build VPP first" && exit 1

pkill -9 vpp 2>/dev/null || true
sleep 1

echo "=== Copying TLS certs from test resources ==="
rm -rf $TLS_DIR && mkdir -p $TLS_DIR
CERTS_SRC="$SCRIPT_DIR/resources/openvpn/tls"
cp $CERTS_SRC/ca.crt $CERTS_SRC/server.crt $CERTS_SRC/server.key $TLS_DIR/
cp $CERTS_SRC/client.crt $CERTS_SRC/client.key $TLS_DIR/
cp $CERTS_SRC/tls-crypt-v2-server.key $TLS_DIR/
cp $CERTS_SRC/tls-crypt-v2-client.key $TLS_DIR/

echo "=== Creating VPP config ==="
rm -rf $VPP_RUN_DIR && mkdir -p $VPP_RUN_DIR/run

cat > $VPP_RUN_DIR/startup.conf << EOF
unix {
  nodaemon
  cli-listen $VPP_RUN_DIR/run/cli.sock
  cli-no-pager
  log $VPP_RUN_DIR/vpp.log
}
api-segment { prefix vpp-tls-crypt-v2 }
cpu { main-core 0 }
plugins {
  path $VPP_PLUGINS
  plugin default { enable }
  plugin dpdk_plugin.so { disable }
}
logging { default-log-level debug }
openvpn {
  instance tls-crypt-v2-server {
    local $VPP_IP
    port $OVPN_PORT
    dev ovpn0
    dev-type tun
    server 10.8.0.0 255.255.255.0
    ca $TLS_DIR/ca.crt
    cert $TLS_DIR/server.crt
    key $TLS_DIR/server.key
    tls-crypt-v2 $TLS_DIR/tls-crypt-v2-server.key
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

# Configure tunnel interface
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

echo "=== Starting OpenVPN Client with TLS-Crypt-V2 ==="
docker rm -f $CLIENT_CONTAINER 2>/dev/null || true

CLIENT_CONF="/tmp/openvpn-client-tlscryptv2"
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
tls-crypt-v2 /etc/openvpn/tls/tls-crypt-v2-client.key
tls-client
cipher AES-256-GCM
pull
keepalive 10 60
verb 5
log /tmp/openvpn.log
EOF

docker run -d --name $CLIENT_CONTAINER \
    --network host \
    --privileged \
    -v $CLIENT_CONF:/etc/openvpn/conf:ro \
    -v $TLS_DIR:/etc/openvpn/tls:ro \
    ubuntu:24.04 \
    bash -c "
        apt-get update -qq && apt-get install -y -qq openvpn iproute2 iputils-ping >/dev/null 2>&1
        mkdir -p /dev/net && mknod /dev/net/tun c 10 200 2>/dev/null || true
        openvpn --config /etc/openvpn/conf/client.conf
    "

echo "Waiting for tunnel (20s)..."
sleep 20

echo ""
echo "=== Status ==="
echo "OpenVPN log:"
docker exec $CLIENT_CONTAINER tail -30 /tmp/openvpn.log 2>/dev/null || true

echo ""
echo "VPP:"
$VPPCTL_CMD show ovpn
$VPPCTL_CMD show interface ovpn0
$VPPCTL_CMD show errors

echo ""
echo "======================================================="
echo "  TLS-Crypt-V2 Long-Running Environment"
echo "======================================================="
echo "  VPP Tunnel:    $VPP_TUNNEL_IP"
echo "  Client Tunnel: $CLIENT_TUNNEL_IP"
echo "  VPP CLI:       $VPPCTL_CMD"
echo "======================================================="
echo ""
echo "Continuous ping... (Ctrl+C to stop)"
echo ""

success=0; fail=0; n=0
while true; do
    n=$((n+1))
    if docker exec $CLIENT_CONTAINER ping -c 1 -W 2 $VPP_TUNNEL_IP >/dev/null 2>&1; then
        success=$((success+1))
        [ $((n % 10)) -eq 0 ] && echo "[$(date +%H:%M:%S)] #$n OK (ok:$success fail:$fail)"
    else
        fail=$((fail+1))
        echo "[$(date +%H:%M:%S)] #$n FAIL (ok:$success fail:$fail)"
        [ $((fail % 5)) -eq 1 ] && {
            echo "--- debug ---"
            docker exec $CLIENT_CONTAINER tail -5 /tmp/openvpn.log 2>/dev/null || true
            $VPPCTL_CMD show errors 2>/dev/null | grep -v "^$" | head -5 || true
            echo "-------------"
        }
    fi
    sleep 1
done
