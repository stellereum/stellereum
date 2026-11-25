#!/bin/sh
# Keep SSH tunnels open so nginx on node A (deploy/nginx/rpc-lb.conf) can load
# balance and fail over across multiple validators without exposing any node's
# JSON-RPC port to the internet.
#
# Modes:
#   rpc-lb-tunnels.sh --reverse           Run on mainserver (holds SSH keys and
#                                         local node B on 127.0.0.1:8546). Opens
#                                         reverse tunnels to node A:
#                                           nodeA:8551 -> mainserver:8546 (node B)
#                                           nodeA:8552 -> mainserver:18552 -> nodeD:8545
#   rpc-lb-tunnels.sh --reverse --check   Verify mainserver + node A tunnel ports
#   rpc-lb-tunnels.sh                     Legacy forward mode (run on origin host)
#   rpc-lb-tunnels.sh --check             Verify local 8545/8551/8552 on origin host
set -u

A_HOST="${STELL_LB_A_HOST:-root@212.113.103.105}"
A_PORT="${STELL_LB_A_SSH_PORT:-22}"
D_HOST="${STELL_LB_D_HOST:-root@138.124.102.200}"
D_PORT="${STELL_LB_D_SSH_PORT:-22}"
C_HOST="${STELL_LB_C_HOST:-root@213.21.246.5}"
C_PORT="${STELL_LB_C_SSH_PORT:-2222}"

B_LOCAL_RPC="${STELL_LB_B_RPC:-127.0.0.1:8546}"
D_STAGE_PORT="${STELL_LB_D_STAGE_PORT:-18552}"
RECONNECT_SEC="${STELL_LB_RECONNECT_SEC:-5}"

MODE="forward"
DO_CHECK=0
for arg in "$@"; do
    case "$arg" in
        --reverse) MODE="reverse" ;;
        --check)   DO_CHECK=1 ;;
        -h|--help)
            echo "Usage: $0 [--reverse] [--check]"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

check_local_port() {
    label="$1"
    addr="$2"
    code=$(curl -s -m 4 -o /dev/null -w '%{http_code}' -X POST "http://$addr" \
        -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}' 2>/dev/null || echo "000")
    if [ "$code" = "200" ]; then
        printf '  %-24s ok (200)\n' "$label ($addr)"
        return 0
    fi
    printf '  %-24s DOWN (%s)\n' "$label ($addr)" "$code"
    return 1
}

check_remote_port() {
    label="$1"
    port="$2"
    code=$(ssh -o BatchMode=yes -o ConnectTimeout=5 -p "$A_PORT" "$A_HOST" \
        "curl -s -m 4 -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:$port -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stell_blockNumber\",\"params\":[]}'" \
        2>/dev/null || echo "000")
    if [ "$code" = "200" ]; then
        printf '  %-24s ok (200)\n' "$label (nodeA:$port)"
        return 0
    fi
    printf '  %-24s DOWN (%s)\n' "$label (nodeA:$port)" "$code"
    return 1
}

if [ "$DO_CHECK" -eq 1 ]; then
    rc=0
    if [ "$MODE" = "reverse" ]; then
        echo "rpc-lb reverse tunnels (mainserver -> nodeA):"
        check_local_port "node B local" "$B_LOCAL_RPC" || rc=1
        check_local_port "node D stage" "127.0.0.1:$D_STAGE_PORT" || rc=1
        check_remote_port "node A local" 8545 || rc=1
        check_remote_port "node B rev" 8551 || rc=1
        check_remote_port "node D rev" 8552 || rc=1
    else
        echo "rpc-lb tunnels (local):"
        check_local_port "backend 8545" "127.0.0.1:8545" || rc=1
        check_local_port "backend 8551" "127.0.0.1:8551" || rc=1
        check_local_port "backend 8552" "127.0.0.1:8552" || rc=1
    fi
    exit "$rc"
fi

run_tunnel_loop() {
    name="$1"
    shift
    ssh_pid=""
    stop_loop=0
    trap 'stop_loop=1; [ -n "$ssh_pid" ] && kill "$ssh_pid" 2>/dev/null; exit 0' TERM INT
    while [ "$stop_loop" -eq 0 ]; do
        ssh -N -T \
            -o BatchMode=yes \
            -o ExitOnForwardFailure=yes \
            -o ServerAliveInterval=15 \
            -o ServerAliveCountMax=3 \
            -o TCPKeepAlive=yes \
            -o ConnectTimeout=10 \
            -o StrictHostKeyChecking=accept-new \
            "$@" &
        ssh_pid=$!
        wait "$ssh_pid"
        rc=$?
        ssh_pid=""
        [ "$stop_loop" -eq 1 ] && break
        echo "[rpc-lb] $name exited (rc=$rc); reconnecting in ${RECONNECT_SEC}s" >&2
        sleep "$RECONNECT_SEC" &
        wait $! 2>/dev/null || true
    done
}

if [ "$MODE" = "reverse" ]; then
    echo "[rpc-lb] starting reverse tunnels (nodeA:8551 -> $B_LOCAL_RPC, nodeA:8552 -> 127.0.0.1:$D_STAGE_PORT -> $D_HOST:8545)"
    run_tunnel_loop "D-stage" -L "127.0.0.1:${D_STAGE_PORT}:127.0.0.1:8545" -p "$D_PORT" "$D_HOST" &
    P1=$!
    run_tunnel_loop "B->A:8551" -R "127.0.0.1:8551:${B_LOCAL_RPC}" -p "$A_PORT" "$A_HOST" &
    P2=$!
    run_tunnel_loop "D->A:8552" -R "127.0.0.1:8552:127.0.0.1:${D_STAGE_PORT}" -p "$A_PORT" "$A_HOST" &
    P3=$!

    trap 'kill "$P1" "$P2" "$P3" 2>/dev/null; wait 2>/dev/null; exit 0' TERM INT
    wait
    exit 0
fi

echo "[rpc-lb] starting forward tunnels (D:8551, C:8552)"
run_tunnel_loop "D:8551" -L "127.0.0.1:8551:127.0.0.1:8545" -p "$D_PORT" "$D_HOST" &
D_PID=$!
run_tunnel_loop "C:8552" -L "127.0.0.1:8552:127.0.0.1:8545" -p "$C_PORT" "$C_HOST" &
C_PID=$!

trap 'kill "$D_PID" "$C_PID" 2>/dev/null; wait 2>/dev/null; exit 0' TERM INT
wait
