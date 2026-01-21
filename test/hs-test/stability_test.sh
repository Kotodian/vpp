#!/bin/bash
# OpenVPN Production Deployment Script
# VPP 作为 OpenVPN 服务端，与标准 OpenVPN 客户端对接

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPP_ROOT="/root/c/src/github.com/FDio/vpp"
VPP_BUILD="${VPP_ROOT}/build-root/build-vpp_debug-native/vpp"
SHARED_DIR="/tmp/hs-test/shared"
OVPN_PORT="1194"

# Network configuration
DOCKER_NETWORK="ovpn-net"
VPP_IP="172.20.0.2"
CLIENT_IP="172.20.0.3"
SUBNET="172.20.0.0/24"

# Tunnel IPs (点对点隧道)
VPP_TUNNEL_IP="10.10.1.1"
CLIENT_TUNNEL_IP="10.10.1.2"

echo "=== OpenVPN Production Deployment ==="

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    docker rm -f vpp-server openvpn-client 2>/dev/null || true
    docker network rm ${DOCKER_NETWORK} 2>/dev/null || true
}

trap cleanup EXIT
cleanup 2>/dev/null || true

mkdir -p "$SHARED_DIR"

# Create Docker network
echo "Creating Docker network..."
docker network create --subnet=${SUBNET} ${DOCKER_NETWORK} 2>/dev/null || true

# Create VPP startup config - 使用 openvpn 块配置，带 ifconfig 设置点对点路由
echo "Creating VPP config..."
cat > "${SHARED_DIR}/startup.conf" << EOF
unix {
  nodaemon
  cli-listen /tmp/vpp/cli.sock
  log /tmp/vpp/vpp.log
  full-coredump
}
api-segment {
  prefix vpp
}
cpu {
  main-core 1
  workers 0
}
plugins {
  path /vpp/lib/vpp_plugins
  plugin default { disable }
  plugin ovpn_plugin.so { enable }
  plugin af_packet_plugin.so { enable }
  plugin ping_plugin.so { enable }
  plugin crypto_sw_scheduler_plugin.so { enable }
  plugin crypto_openssl_plugin.so { enable }
}
logging {
  default-log-level debug
}
openvpn {
  instance server {
    local ${VPP_IP}
    port ${OVPN_PORT}
    dev ovpn0
    dev-type tun
    secret /opt/openvpn/static.key
    cipher AES-256-CBC
    ifconfig ${VPP_TUNNEL_IP} ${CLIENT_TUNNEL_IP}
  }
}
EOF

# Start VPP container
echo "Starting VPP container..."
docker run -d --name vpp-server \
    --privileged \
    --network ${DOCKER_NETWORK} \
    --ip ${VPP_IP} \
    -v "${VPP_BUILD}/bin:/vpp/bin:ro" \
    -v "${VPP_BUILD}/lib/x86_64-linux-gnu:/vpp/lib:ro" \
    -v "${SHARED_DIR}:/tmp/vpp" \
    -v "${SCRIPT_DIR}/resources/openvpn:/opt/openvpn:ro" \
    --device /dev/net/tun:/dev/net/tun \
    -e LD_LIBRARY_PATH=/vpp/lib \
    ubuntu:24.04 \
    sleep infinity

sleep 2

# Install dependencies and start VPP
echo "Installing VPP dependencies and starting VPP..."
docker exec vpp-server bash -c "apt-get update -qq && apt-get install -y -qq libunwind8 libnuma1 libssl3 iproute2 > /dev/null 2>&1"
docker exec -d vpp-server bash -c "LD_LIBRARY_PATH=/vpp/lib /vpp/bin/vpp -c /tmp/vpp/startup.conf"
sleep 5

# Check if VPP started
if ! docker exec vpp-server pgrep vpp > /dev/null; then
    echo "ERROR: VPP failed to start!"
    docker exec vpp-server cat /tmp/vpp/vpp.log 2>/dev/null || true
    exit 1
fi
echo "VPP started successfully"

# Configure VPP to capture eth0 traffic
echo "Configuring VPP network..."
VPPCTL="docker exec vpp-server bash -c 'LD_LIBRARY_PATH=/vpp/lib /vpp/bin/vppctl -s /tmp/vpp/cli.sock'"

# 创建 host-interface 接管 eth0
eval $VPPCTL \"create host-interface name eth0\"
eval $VPPCTL \"set interface ip address host-eth0 ${VPP_IP}/24\"
eval $VPPCTL \"set interface state host-eth0 up\"

echo ""
echo "VPP interfaces:"
eval $VPPCTL \"show interface addr\"
echo ""
echo "VPP OpenVPN status:"
eval $VPPCTL \"show ovpn\"

# Start OpenVPN client container  
echo ""
echo "Starting OpenVPN client container..."
docker run -d --name openvpn-client \
    --cap-add=NET_ADMIN \
    --device=/dev/net/tun \
    --network ${DOCKER_NETWORK} \
    --ip ${CLIENT_IP} \
    -v "${SHARED_DIR}:/tmp/openvpn" \
    -v "${SCRIPT_DIR}/resources/openvpn:/opt/openvpn:ro" \
    ubuntu:22.04 \
    sleep infinity

sleep 2

# Install and start OpenVPN client
echo "Installing OpenVPN client..."
docker exec openvpn-client bash -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openvpn iputils-ping iproute2 > /dev/null 2>&1"

echo "Starting OpenVPN client..."
docker exec -d openvpn-client openvpn \
    --remote ${VPP_IP} \
    --port ${OVPN_PORT} \
    --dev tun \
    --proto udp \
    --nobind \
    --secret /opt/openvpn/static.key \
    --cipher AES-256-CBC \
    --auth SHA256 \
    --ifconfig ${CLIENT_TUNNEL_IP} ${VPP_TUNNEL_IP} \
    --log /tmp/openvpn/openvpn.log \
    --verb 4

sleep 10

echo ""
echo "=== Deployment Status ==="
echo ""
echo "OpenVPN client log:"
docker exec openvpn-client tail -5 /tmp/openvpn/openvpn.log 2>/dev/null || echo "No log yet"

echo ""
echo "VPP OpenVPN peers:"
eval $VPPCTL \"show ovpn\"

echo ""
echo "=== Ping Test ==="
docker exec openvpn-client ping -c 3 ${VPP_TUNNEL_IP} || echo "Ping failed"

echo ""
echo "=== Deployment Complete ==="
echo ""
echo "Docker Network: ${DOCKER_NETWORK} (${SUBNET})"
echo "VPP Server:     vpp-server (${VPP_IP}, tunnel: ${VPP_TUNNEL_IP})"
echo "OpenVPN Client: openvpn-client (${CLIENT_IP}, tunnel: ${CLIENT_TUNNEL_IP})"
echo ""
echo "Commands:"
echo "  VPP CLI:     docker exec -it vpp-server bash -c 'LD_LIBRARY_PATH=/vpp/lib /vpp/bin/vppctl -s /tmp/vpp/cli.sock'"
echo "  VPP Logs:    docker exec vpp-server cat /tmp/vpp/vpp.log"
echo "  OVPN Logs:   docker exec openvpn-client cat /tmp/openvpn/openvpn.log"
echo "  Test ping:   docker exec openvpn-client ping -c 3 ${VPP_TUNNEL_IP}"
echo ""
echo "Press Ctrl+C to stop and cleanup..."

while true; do
    sleep 30
    if ! docker exec vpp-server pgrep vpp > /dev/null 2>&1; then
        echo "WARNING: VPP stopped! Logs:"
        docker exec vpp-server tail -20 /tmp/vpp/vpp.log 2>/dev/null || true
        break
    fi
done
