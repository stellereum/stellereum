#!/bin/sh
# Keep SSH tunnels open from the RPC origin host to the other validators' local
# RPC ports, so nginx (deploy/nginx/rpc-lb.conf) can fail over between them.
#
# The nodes bind RPC to 127.0.0.1 on purpose: nothing is exposed to the
# internet, the tunnel terminates inside the origin host, and nginx is the only
# listener the public proxy can reach.
#
# Usage:
#   rpc-lb-tunnels.sh            run in the foreground (systemd Type=simple)
#   rpc-lb-tunnels.sh --check    verify all local tunnel ports answer
#
# Tunnels:
#   8551 -> node D 127.0.0.1:8545
#   8552 -> node C 127.0.0.1:8545
# (node A is local, nginx reaches 127.0.0.1:8545 directly)
set -u

D_HOST="${STELL_LB_D_HOST:-root@138.124.102.200}"
C_HOST="${STELL_LB_C_HOST:-root@213.21.246.5}"
C_PORT="${STELL_LB_C_SSH_PORT:-2222}"
D_PORT="${STELL_LB_D_SSH_PORT:-22}"

check_port() {
    port="$1"
    body=$(curl -s -m 4 -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$port" \
        -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}' 2>/dev/null)
    [ "$body" = "200" ] && printf '  %s ok\n' "$port" || printf '  %s DOWN (%s)\n' "$port" "$body"
}

if [ "${1:-}" = "--check" ]; then
    echo "rpc-lb tunnels:"
    check_port 8545
    check_port 8551
    check_port 8552
    exit 0
fi

echo "[rpc-lb] starting tunnels (D:8551, C:8552)"
# ServerAlive keeps a NAT idle-timeout from silently blackholing the socket;
# ExitOnForwardFailure makes a failed bind loud instead of a silent dead port.
exec ssh -N \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -o StrictHostKeyChecking=accept-new \
    -L "127.0.0.1:8551:127.0.0.1:8545" -p "$D_PORT" "$D_HOST" &
D_PID=$!
exec ssh -N \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -o StrictHostKeyChecking=accept-new \
    -L "127.0.0.1:8552:127.0.0.1:8545" -p "$C_PORT" "$C_HOST" &
C_PID=$!

trap 'kill $D_PID $C_PID 2>/dev/null' TERM INT
wait
