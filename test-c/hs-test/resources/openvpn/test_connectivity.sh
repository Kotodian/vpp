#!/bin/bash
# Test connectivity through OpenVPN tunnel

set -e

TARGET_IP="${1:-10.8.0.1}"
TIMEOUT="${2:-30}"
INTERVAL="${3:-1}"

echo "Testing connectivity to $TARGET_IP..."

# Wait for tunnel interface to come up
echo "Waiting for tunnel interface..."
for i in $(seq 1 $TIMEOUT); do
    if ip link show tun0 2>/dev/null | grep -q "state UP"; then
        echo "Tunnel interface is up"
        break
    fi
    sleep $INTERVAL
done

# Check if tun0 exists
if ! ip link show tun0 2>/dev/null; then
    echo "ERROR: tun0 interface not found"
    exit 1
fi

# Try to ping
echo "Pinging $TARGET_IP..."
if ping -c 3 -W 5 $TARGET_IP; then
    echo "SUCCESS: Connectivity test passed"
    exit 0
else
    echo "FAILED: Cannot reach $TARGET_IP"
    exit 1
fi
