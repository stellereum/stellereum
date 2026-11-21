#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp/opencode}/liveness-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"

cat >"$tmp/bin/date" <<'EOF'
#!/usr/bin/env bash
n=0
[[ ! -f "$FAKE_CLOCK" ]] || read -r n <"$FAKE_CLOCK"
printf '%s\n' "$((n + 1))" >"$FAKE_CLOCK"
printf '%s\n' "$n"
EOF
cat >"$tmp/bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$tmp/bin/curl" <<'EOF'
#!/usr/bin/env bash
payload=""
url="${!#}"
while (($#)); do
    if [[ "$1" == --data ]]; then payload="$2"; shift; fi
    shift
done
[[ "$url" != */health ]] || { printf '{}'; exit 0; }
case "$url" in
    fake://down) exit 7 ;;
    fake://invalid-json) printf '{'; exit 0 ;;
    fake://rpc-error) printf '{"error":{"code":-1}}'; exit 0 ;;
    fake://bad-height) printf '{"result":"not-a-height"}'; exit 0 ;;
    fake://overflow) printf '{"result":"0xffffffffffffffff"}'; exit 0 ;;
    fake://late-down)
        read -r n <"$FAKE_CLOCK"
        (( n < 3 )) || exit 7 ;;
esac
if [[ "$payload" == *stell_blockNumber* ]]; then
    read -r n <"$FAKE_CLOCK"
    printf '{"result":"0x%x"}' "$((n + 16))"
elif [[ "$payload" == *stell_getBlock* ]]; then
    case "$url" in
        fake://different) printf '{"result":{"hash":"different"}}' ;;
        fake://no-hash) printf '{"result":{}}' ;;
        *) printf '{"result":{"hash":"same"}}' ;;
    esac
else
    printf '{"result":"0x0"}'
fi
EOF
chmod +x "$tmp/bin/"*

run_case() {
    local label="$1" expected_code="$2" expected_text="$3"
    shift 3
    local output code
    rm -f "$tmp/clock"
    set +e
    output="$(PATH="$tmp/bin:$PATH" FAKE_CLOCK="$tmp/clock" \
        bash "$root/scripts/cluster_liveness.sh" --interval 1 --window 2 "$@" 2>&1)"
    code=$?
    set -e
    if [[ "$code" != "$expected_code" || "$output" != *"$expected_text"* ]]; then
        printf 'FAIL %s: exit=%s expected=%s; missing or unexpected output: %s\n%s\n' \
            "$label" "$code" "$expected_code" "$expected_text" "$output" >&2
        exit 1
    fi
    printf 'PASS %s (exit %s): %s\n' "$label" "$code" "$expected_text"
}

run_case 'legacy partial reachability' 0 'reachable=1/2' \
    --rpcs 'A=fake://good,B=fake://down'
run_case 'minimum rejects partial reachability' 1 'reason=reachable_endpoints_1_below_minimum_2' \
    --rpcs 'A=fake://good,B=fake://down' --min-reachable 2
run_case 'minimum accepts enough endpoints' 0 'LIVENESS_RESULT=OK' \
    --rpcs 'A=fake://good,B=fake://good' --min-reachable 2
for bad in invalid-json rpc-error bad-height overflow late-down; do
    run_case "minimum rejects $bad" 1 'reachable=1/2' \
        --rpcs "A=fake://good,B=fake://$bad" --min-reachable 2
done
run_case 'all endpoints down' 1 'reachable=0/2' \
    --rpcs 'A=fake://down,B=fake://down' --min-reachable 2
run_case 'zero minimum invalid' 64 '--min-reachable must' \
    --rpcs 'A=fake://good' --min-reachable 0
run_case 'non-integer minimum invalid' 64 '--min-reachable must' \
    --rpcs 'A=fake://good' --min-reachable nope
run_case 'impossible minimum invalid' 64 '--min-reachable' \
    --rpcs 'A=fake://good' --min-reachable 2
run_case 'oversized minimum invalid' 64 '--min-reachable' \
    --rpcs 'A=fake://good' --min-reachable 999999999999999999999999999999
run_case 'hash mismatch wins over unmet minimum' 2 'reason=block_hash_mismatch_at_common_height' \
    --rpcs 'A=fake://good,B=fake://different,C=fake://down' --min-reachable 3
run_case 'missing hash does not prove agreement' 0 'LIVENESS_RESULT=OK' \
    --rpcs 'A=fake://good,B=fake://no-hash' --min-reachable 2

watch_case() {
    local label="$1" expected_code="$2" expected_line="$3" expected_metric="$4"
    shift 4
    local output code
    rm -f "$tmp/clock" "$tmp/watch.log" "$tmp/watch.prom"
    set +e
    output="$(PATH="$tmp/bin:$PATH" FAKE_CLOCK="$tmp/clock" \
        bash "$root/scripts/cluster_liveness_watch.sh" --once --interval 1 --window 2 \
        --journal 'true' --clock 'printf yes' \
        --log "$tmp/watch.log" --textfile "$tmp/watch.prom" "$@" 2>&1)"
    code=$?
    set -e
    if [[ "$code" != "$expected_code" || "$output" != *"$expected_line"* ]] ||
       ! grep -Fq "$expected_line" "$tmp/watch.log" ||
       ! grep -Fxq "stell_cluster_liveness_ok $expected_metric" "$tmp/watch.prom"; then
        printf 'FAIL watcher %s: exit=%s expected=%s\n%s\n' "$label" "$code" "$expected_code" "$output" >&2
        exit 1
    fi
    printf 'PASS watcher %s (exit %s)\n' "$label" "$code"
}

watch_case 'default allows partial reachability' 0 'LIVENESS_RESULT=OK' 1 \
    --rpcs 'A=fake://good,B=fake://down'
watch_case 'minimum forwarded' 1 'reason=reachable_endpoints_1_below_minimum_2' 0 \
    --rpcs 'A=fake://good,B=fake://down' --min-reachable 2
watch_case 'minimum met' 0 'LIVENESS_RESULT=OK' 1 \
    --rpcs 'A=fake://good,B=fake://good' --min-reachable 2
watch_case 'hash mismatch wins' 2 'LIVENESS_RESULT=DIVERGED' 0 \
    --rpcs 'A=fake://good,B=fake://different,C=fake://down' --min-reachable 3
watch_case 'missing hash permits OK' 0 'LIVENESS_RESULT=OK' 1 \
    --rpcs 'A=fake://good,B=fake://no-hash' --min-reachable 2
watch_case 'invalid minimum fails closed' 1 'reason=runner_error_rc_64' 0 \
    --rpcs 'A=fake://good' --min-reachable 2
