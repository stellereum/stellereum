# justfile — HDAE clean commands (needs `just`; else call scripts/ directly).
# Every recipe maps 1:1 to a shell script so agents without `just` lose nothing.

# full strict gate (clippy + fmt-advisory + all tests + sim harness)
gate-all:
    ./scripts/verify_testnet_ideal.sh

# fast gate: lib tests only for the big crate, everything else full
gate-fast:
    ./scripts/verify_testnet_ideal.sh --fast

# gate a single crate dir, e.g. `just gate-crate stellereum`
gate-crate name:
    cd {{name}} && cargo clippy --all-targets -- -D warnings && cargo test --no-fail-fast

# 4-node deterministic sim harness (the virtual testnet)
sim-local:
    cd stellereum && cargo test --test consensus_liveness_harness --no-fail-fast
    cd stellereum && cargo test --test proposal_refire_tests --no-fail-fast

# remote bench stub: runs the tempo harness against a live RPC (read-only)
bench-remote rpc="http://127.0.0.1:8546":
    cd stellereum && cargo test --test block_tempo_lan --no-fail-fast

# regenerate machine status
status:
    ./scripts/harness_status.sh

# fake-code scan only
scan:
    ./scripts/verify_testnet_ideal.sh --no-sim --fast | head -5 || true
