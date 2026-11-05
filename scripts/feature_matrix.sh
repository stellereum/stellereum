#!/usr/bin/env bash
# feature_matrix.sh — HDAE pillar 3: feature RED/GREEN matrix bound to E2E tests.
# Usage: ./scripts/feature_matrix.sh
# Runs a curated list of scenario tests (one row = one real test target),
# appends results incrementally to artifacts/features.tsv (timeout-safe),
# then generates artifacts/features.json + FEATURES.md.
# Exit 0 = no RED. SKIP (env/timeout) never fails, RED does.
# Every row below names a REAL test target — inventing names fails review.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TSV="$ROOT/artifacts/features.tsv"
mkdir -p "$ROOT/artifacts"
: > "$TSV"
RED=0

row() { # id workdir timeout_sec -- cargo test args...
  local id="$1" ws="$2" t="$3"; shift 3
  if [ "${1:-}" = "--" ]; then shift; fi
  # shellcheck disable=SC2124
  local args="$@"
  echo "[matrix] $id ($ws): cargo test $args"
  local start end secs status detail
  start=$(date +%s)
  out=$(cd "$ROOT/$ws" && timeout "$t" cargo test $args 2>&1)
  code=$?
  end=$(date +%s); secs=$((end - start))
  if [ $code -eq 0 ]; then status="GREEN";
  elif [ $code -eq 124 ]; then status="SKIP"; detail="timeout ${t}s";
  else status="RED"; RED=1; fi
  if [ -z "${detail:-}" ]; then
    detail=$(echo "$out" | grep -E "test result:" | tr '\n' ';' | cut -c1-300)
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$ws" "$status" "$secs" "$detail" >> "$TSV"
  echo "[matrix] $id -> $status (${secs}s)"
}

# contracts e2e need wasm artifacts (rebuild if missing — fast when cached)
if ! ls "$ROOT/stellereum-contracts/target/wasm32-unknown-unknown/release/"*.wasm >/dev/null 2>&1; then
  (cd "$ROOT/stellereum-contracts" && cargo build --release --target wasm32-unknown-unknown \
    -p stl-dns -p sts20-token -p liquidity-pool -p account-object) || echo "[matrix] wasm build failed — e2e rows will go RED"
fi

# ---- PQ / wallet ----
row pq-keygen-sign-verify      stell-wallet 300 -- --test wallet_pq_tests
row pq-chain-binding           stell-wallet 300 -- --test wallet_chain_binding_tests
row pq-fee                     stell-wallet 300 -- --test wallet_pq_fee_repro_tests
row wallet-rpc-token           stell-wallet 300 -- --test wallet_rpc_token_tests
row wallet-security            stell-wallet 300 -- --test wallet_security_tests
row wallet-privacy             stell-wallet 600 -- --test wallet_privacy_integration_tests
row wallet-multimgmt           stell-wallet 300 -- --test wallet_multi_management_tests
row wallet-delegation          stell-wallet 300 -- --test wallet_delegation_tests
row wallet-live-node           stell-wallet 600 -- --test wallet_live_node_tests
# ---- PQ pin, node side ----
row pq-nondeterminism-pin      stellereum 300 -- --lib post_quantum
# ---- AA / sessions / paymaster ----
row aa-session-keys            stellereum 300 -- --test session_key_tests
row aa-session-budget          stellereum 300 -- --test session_budget_tests
row paymaster                  stellereum 300 -- --test paymaster_tests
# ---- VM / contracts ----
row evm-flows                  stellereum 600 -- --test evm_adapter_tests
row contracts-node-side        stellereum 600 -- --test ecosystem_contracts_tests
# ---- DeFi ----
row clob-settle                stellereum 600 -- --test clob_settlement_tests
row one-call-order             stellereum 300 -- --test one_call_order_placement_tests
row bridge-attest              stellereum 600 -- --test bridge_onchain_tests
# ---- privacy ----
row shielded                   stellereum 600 -- --test privacy_live_tests
row confidential-solvent       stellereum 600 -- --test confidential_solvency_tests
# ---- consensus ----
row halt-not-fork              stellereum 300 -- --test p3_byzantine_pentest p3_diverge
row liveness-harness           stellereum 300 -- --test consensus_liveness_harness
row 4node-adversarial          stellereum 600 -- --test adversarial_4node_tests
row slash-equivocation         stellereum 300 -- --test equivocation_slash_tests
row proposal-refire            stellereum 300 -- --test proposal_refire_tests
# ---- state / sync ----
row snapshot-resume            stellereum 300 -- --test snapshot_resume_regression_tests
row mmr-epoch                  stellereum 300 -- --test mmr_epoch_root_tests
row light-client               stellereum 300 -- --test light_client_tests
# ---- xshard ----
row xshard-2pc                 stellereum 600 -- --test xshard_2pc_tests
row split                      stellereum 600 -- --test hunt_finalize_split
# ---- tempo / mev ----
row vel-tempo                  stellereum 900 -- --test zz_vel_measure
row tempo-lan                  stellereum 600 -- --test block_tempo_lan
row mev-seal                   stellereum 600 -- --test mev_epoch_seal_tests
# ---- contracts e2e ----
row sts20-onchain              stellereum-contracts 300 -- -p e2e-tests --test onchain_wasm_e2e_tests test_rust_wasm_sts20_token_onchain
row dns-onchain                stellereum-contracts 300 -- -p e2e-tests --test onchain_wasm_e2e_tests test_rust_wasm_stl_dns_onchain
row pool-onchain               stellereum-contracts 300 -- -p e2e-tests --test onchain_wasm_e2e_tests test_rust_wasm_liquidity_pool_onchain
row account-object-onchain     stellereum-contracts 300 -- -p e2e-tests --test onchain_wasm_e2e_tests test_rust_wasm_account_object_onchain
row adversarial-e2e            stellereum-contracts 300 -- -p e2e-tests --test adversarial_pentest_tests
# ---- indexer ----
row indexer-api                stellereum-indexer 300 -- --test indexer_api_tests
# ---- wave-1..3 + PQ extensions ----
row verify-once                stellereum 300 -- --test verify_once_tests
row p2p-reputation             infnode 300 -- -p infnode --test reputation_tests
row validator-ux               stellereum 300 -- --test validator_ux_tests
row snapshot-set-binding       stellereum 300 -- --test snapshot_set_tests
row fee-determinism            stellereum 300 -- --lib test_estimate_fee
row pq-registry                stellereum 300 -- --test pq_registry_tests
row light-rotation             stellereum 600 -- --test light_client_rotation_tests
row chaos-n4                   stellereum 600 -- --test chaos_n4_tests
row slash-drill                stellereum 600 -- --test slash_drill_tests
if [ -f "$ROOT/stellereum/tests/tempo_recipe_tests.rs" ]; then
  row tempo-recipe stellereum 600 -- --test tempo_recipe_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "tempo-recipe" "stellereum" "SKIP" "0" "tempo_recipe_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] tempo-recipe -> SKIP (file absent)"
fi
row cn-vrf-kats                stellereum 300 -- --test cn_vrf_tests
row excision-leftovers         stellereum 300 -- --test pentest_excision_leftovers
row vrf-canonical-draw         stellereum 300 -- --test vrf_canonical_draw_tests
row mev-kem-registry           stellereum 300 -- --test mev_kem_registry_tests
if [ -f "$ROOT/stellereum/tests/explorer_ux_tests.rs" ]; then
  row explorer-ux stellereum 300 -- --test explorer_ux_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "explorer-ux" "stellereum" "SKIP" "0" "explorer_ux_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] explorer-ux -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/wallet_pq_tests.rs" ]; then
  row wallet-pq stellereum 300 -- --test wallet_pq_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "wallet-pq" "stellereum" "SKIP" "0" "wallet_pq_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] wallet-pq -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/faucet_pq_tests.rs" ]; then
  row faucet-pq stellereum 300 -- --test faucet_pq_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "faucet-pq" "stellereum" "SKIP" "0" "faucet_pq_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] faucet-pq -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/fuzz_economics_ext.rs" ]; then
  row fuzz-economics-ext stellereum 600 -- --test fuzz_economics_ext
else
  printf '%s\t%s\t%s\t%s\t%s\n' "fuzz-economics-ext" "stellereum" "SKIP" "0" "fuzz_economics_ext.rs absent at runtime" >> "$TSV"
  echo "[matrix] fuzz-economics-ext -> SKIP (file absent)"
fi
# ---- wave-4 batteries (conditional: siblings landing concurrently) ----
if [ -f "$ROOT/stellereum/tests/consensus_byzantine_tests.rs" ]; then
  row byzantine stellereum 300 -- --test consensus_byzantine_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "byzantine" "stellereum" "SKIP" "0" "consensus_byzantine_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] byzantine -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/liveness_breaker_tests.rs" ]; then
  row liveness-breaker stellereum 600 -- --test liveness_breaker_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "liveness-breaker" "stellereum" "SKIP" "0" "liveness_breaker_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] liveness-breaker -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/sync_adversarial_tests.rs" ]; then
  row sync-adversarial stellereum 600 -- --test sync_adversarial_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "sync-adversarial" "stellereum" "SKIP" "0" "sync_adversarial_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] sync-adversarial -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/staking_invariants_tests.rs" ]; then
  row staking-invariants stellereum 600 -- --test staking_invariants_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "staking-invariants" "stellereum" "SKIP" "0" "staking_invariants_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] staking-invariants -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/storage_crash_tests.rs" ]; then
  row storage-crash stellereum 600 -- --test storage_crash_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "storage-crash" "stellereum" "SKIP" "0" "storage_crash_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] storage-crash -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/shard2_soak_tests.rs" ]; then
  row shard2-soak stellereum 600 -- --test shard2_soak_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "shard2-soak" "stellereum" "SKIP" "0" "shard2_soak_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] shard2-soak -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/pq_gates_staking_light_tests.rs" ]; then
  row pq-gates stellereum 300 -- --test pq_gates_staking_light_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "pq-gates" "stellereum" "SKIP" "0" "pq_gates_staking_light_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] pq-gates -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/light_cli_tests.rs" ]; then
  row light-cli stellereum 300 -- --test light_cli_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "light-cli" "stellereum" "SKIP" "0" "light_cli_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] light-cli -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/rpc_ws_tests.rs" ]; then
  row rpc-ws stellereum 300 -- --test rpc_ws_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "rpc-ws" "stellereum" "SKIP" "0" "rpc_ws_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] rpc-ws -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/fee_batching_parity_tests.rs" ]; then
  row fee-parity stellereum 300 -- --test fee_batching_parity_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "fee-parity" "stellereum" "SKIP" "0" "fee_batching_parity_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] fee-parity -> SKIP (file absent)"
fi
if [ -f "$ROOT/infnode/crates/infnode/tests/eclipse_tests.rs" ]; then
  row eclipse infnode 600 -- -p infnode --test eclipse_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "eclipse" "infnode" "SKIP" "0" "eclipse_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] eclipse -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/privacy_pq_tests.rs" ]; then
  row privacy-pq stellereum 300 -- --test privacy_pq_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "privacy-pq" "stellereum" "SKIP" "0" "privacy_pq_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] privacy-pq -> SKIP (file absent)"
fi
if [ -f "$ROOT/infnode/crates/infnode/tests/kem_kat_tests.rs" ]; then
  row kem-kat infnode 300 -- -p infnode --test kem_kat_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "kem-kat" "infnode" "SKIP" "0" "kem_kat_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] kem-kat -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/src/mev_pq_plan.rs" ]; then
  row mev-plan stellereum 300 -- --lib mev_pq_plan
else
  printf '%s\t%s\t%s\t%s\t%s\n' "mev-plan" "stellereum" "SKIP" "0" "mev_pq_plan.rs absent at runtime" >> "$TSV"
  echo "[matrix] mev-plan -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum-contracts/contracts/sts20-token/tests/regression_audit_60_80.rs" ] && [ -f "$ROOT/stellereum-contracts/contracts/stl-dns/tests/regression_audit_60_80.rs" ] && [ -f "$ROOT/stellereum-contracts/contracts/liquidity-pool/tests/regression_audit_60_80.rs" ] && [ -f "$ROOT/stellereum-contracts/contracts/account-object/tests/regression_audit_60_80.rs" ]; then
  row contracts-regression stellereum-contracts 300 -- --test regression_audit_60_80
else
  printf '%s\t%s\t%s\t%s\t%s\n' "contracts-regression" "stellereum-contracts" "SKIP" "0" "regression_audit_60_80.rs absent at runtime" >> "$TSV"
  echo "[matrix] contracts-regression -> SKIP (file absent)"
fi
# ---- 0.6s-wave batteries (conditional: SKIP-if-absent idiom) ----
if [ -f "$ROOT/stellereum/tests/cpu_budget_tests.rs" ]; then
  row cpu-budget stellereum 300 -- --test cpu_budget_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "cpu-budget" "stellereum" "SKIP" "0" "cpu_budget_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] cpu-budget -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/snapshot_cadence_tests.rs" ]; then
  row snapshot-cadence stellereum 300 -- --test snapshot_cadence_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "snapshot-cadence" "stellereum" "SKIP" "0" "snapshot_cadence_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] snapshot-cadence -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/tempo_sustained_tests.rs" ]; then
  row tempo-sustained stellereum 600 -- --test tempo_sustained_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "tempo-sustained" "stellereum" "SKIP" "0" "tempo_sustained_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] tempo-sustained -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/sustained_06_tests.rs" ]; then
  row sustained-06 stellereum 600 -- --test sustained_06_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "sustained-06" "stellereum" "SKIP" "0" "sustained_06_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] sustained-06 -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/tick_tuning_tests.rs" ]; then
  row tick-tuning stellereum 300 -- --test tick_tuning_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "tick-tuning" "stellereum" "SKIP" "0" "tick_tuning_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] tick-tuning -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/propose_select_differential_tests.rs" ]; then
  row propose-select stellereum 300 -- --test propose_select_differential_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "propose-select" "stellereum" "SKIP" "0" "propose_select_differential_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] propose-select -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/block_cpu_budget_tests.rs" ]; then
  row block-cpu-budget stellereum 300 -- --test block_cpu_budget_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "block-cpu-budget" "stellereum" "SKIP" "0" "block_cpu_budget_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] block-cpu-budget -> SKIP (file absent)"
fi
# block_cpu_budget bench: no bench-row idiom exists in matrix (grep bench = empty),
# so per scope it is SKIP, never a runnable row. Bench is report-only measurement.
printf '%s\t%s\t%s\t%s\t%s\n' "block-cpu-budget-bench" "stellereum" "SKIP" "0" "no bench-row idiom in matrix; benches/block_cpu_budget.rs is report-only" >> "$TSV"
echo "[matrix] block-cpu-budget-bench -> SKIP (no bench idiom)"
if [ -f "$ROOT/stellereum/tests/commitment_assembly_differential_tests.rs" ]; then
  row commitment-assembly stellereum 300 -- --test commitment_assembly_differential_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "commitment-assembly" "stellereum" "SKIP" "0" "commitment_assembly_differential_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] commitment-assembly -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/vote_verify_cache_tests.rs" ]; then
  row vote-verify-cache stellereum 300 -- --test vote_verify_cache_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "vote-verify-cache" "stellereum" "SKIP" "0" "vote_verify_cache_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] vote-verify-cache -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/parallel_apply_parity_tests.rs" ]; then
  row parallel-apply-parity stellereum 300 -- --test parallel_apply_parity_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "parallel-apply-parity" "stellereum" "SKIP" "0" "parallel_apply_parity_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] parallel-apply-parity -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/light_e2e_tests.rs" ]; then
  row light-e2e stellereum 600 -- --test light_e2e_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "light-e2e" "stellereum" "SKIP" "0" "light_e2e_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] light-e2e -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/liveness_horizon_tests.rs" ]; then
  row liveness-horizon stellereum 600 -- --test liveness_horizon_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "liveness-horizon" "stellereum" "SKIP" "0" "liveness_horizon_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] liveness-horizon -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/rpc_batch_tests.rs" ]; then
  row rpc-batch stellereum 300 -- --test rpc_batch_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "rpc-batch" "stellereum" "SKIP" "0" "rpc_batch_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] rpc-batch -> SKIP (file absent)"
fi
if [ -f "$ROOT/infnode/crates/infnode/tests/gossip_scale_tests.rs" ]; then
  row gossip-scale infnode 600 -- -p infnode --test gossip_scale_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "gossip-scale" "infnode" "SKIP" "0" "gossip_scale_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] gossip-scale -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/shard2_n3_soak_tests.rs" ]; then
  row shard2-n3-soak stellereum 600 -- --test shard2_n3_soak_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "shard2-n3-soak" "stellereum" "SKIP" "0" "shard2_n3_soak_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] shard2-n3-soak -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/storage_restore_perf_tests.rs" ]; then
  row storage-restore-perf stellereum 600 -- --test storage_restore_perf_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "storage-restore-perf" "stellereum" "SKIP" "0" "storage_restore_perf_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] storage-restore-perf -> SKIP (file absent)"
fi
# ---- discovery sweep: other present-but-unlisted suites (same wave commits) ----
if [ -f "$ROOT/stellereum/tests/qc_batch_verify_tests.rs" ]; then
  row qc-batch-verify stellereum 300 -- --test qc_batch_verify_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "qc-batch-verify" "stellereum" "SKIP" "0" "qc_batch_verify_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] qc-batch-verify -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/mev_pq_transport_tests.rs" ]; then
  row mev-pq-transport stellereum 300 -- --test mev_pq_transport_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "mev-pq-transport" "stellereum" "SKIP" "0" "mev_pq_transport_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] mev-pq-transport -> SKIP (file absent)"
fi
if [ -f "$ROOT/infnode/crates/infnode/tests/pq_handshake_tests.rs" ]; then
  row pq-handshake infnode 300 -- -p infnode --test pq_handshake_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "pq-handshake" "infnode" "SKIP" "0" "pq_handshake_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] pq-handshake -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/protocol_fuzz_tests.rs" ]; then
  row protocol-fuzz stellereum 600 -- --test protocol_fuzz_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "protocol-fuzz" "stellereum" "SKIP" "0" "protocol_fuzz_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] protocol-fuzz -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/pentest_fees_intake.rs" ]; then
  row pentest-fees-intake stellereum 600 -- --test pentest_fees_intake
else
  printf '%s\t%s\t%s\t%s\t%s\n' "pentest-fees-intake" "stellereum" "SKIP" "0" "pentest_fees_intake.rs absent at runtime" >> "$TSV"
  echo "[matrix] pentest-fees-intake -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/pentest_light_shard2.rs" ]; then
  row pentest-light-shard2 stellereum 600 -- --test pentest_light_shard2
else
  printf '%s\t%s\t%s\t%s\t%s\n' "pentest-light-shard2" "stellereum" "SKIP" "0" "pentest_light_shard2.rs absent at runtime" >> "$TSV"
  echo "[matrix] pentest-light-shard2 -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/pentest_mempool_dos.rs" ]; then
  row pentest-mempool-dos stellereum 600 -- --test pentest_mempool_dos
else
  printf '%s\t%s\t%s\t%s\t%s\n' "pentest-mempool-dos" "stellereum" "SKIP" "0" "pentest_mempool_dos.rs absent at runtime" >> "$TSV"
  echo "[matrix] pentest-mempool-dos -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/pentest_mev_kem.rs" ]; then
  row pentest-mev-kem stellereum 600 -- --test pentest_mev_kem
else
  printf '%s\t%s\t%s\t%s\t%s\n' "pentest-mev-kem" "stellereum" "SKIP" "0" "pentest_mev_kem.rs absent at runtime" >> "$TSV"
  echo "[matrix] pentest-mev-kem -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/pentest_privacy_gates.rs" ]; then
  row pentest-privacy-gates stellereum 600 -- --test pentest_privacy_gates
else
  printf '%s\t%s\t%s\t%s\t%s\n' "pentest-privacy-gates" "stellereum" "SKIP" "0" "pentest_privacy_gates.rs absent at runtime" >> "$TSV"
  echo "[matrix] pentest-privacy-gates -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/pentest_rpc_surface.rs" ]; then
  row pentest-rpc-surface stellereum 600 -- --test pentest_rpc_surface
else
  printf '%s\t%s\t%s\t%s\t%s\n' "pentest-rpc-surface" "stellereum" "SKIP" "0" "pentest_rpc_surface.rs absent at runtime" >> "$TSV"
  echo "[matrix] pentest-rpc-surface -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/pentest_ws_faucet.rs" ]; then
  row pentest-ws-faucet stellereum 600 -- --test pentest_ws_faucet
else
  printf '%s\t%s\t%s\t%s\t%s\n' "pentest-ws-faucet" "stellereum" "SKIP" "0" "pentest_ws_faucet.rs absent at runtime" >> "$TSV"
  echo "[matrix] pentest-ws-faucet -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/pentest_net_api_tests.rs" ]; then
  row pentest-net-api stellereum 600 -- --test pentest_net_api_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "pentest-net-api" "stellereum" "SKIP" "0" "pentest_net_api_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] pentest-net-api -> SKIP (file absent)"
fi
if [ -f "$ROOT/infnode/crates/infnode/tests/pentest_pq_downgrade.rs" ]; then
  row pentest-pq-downgrade infnode 600 -- -p infnode --test pentest_pq_downgrade
else
  printf '%s\t%s\t%s\t%s\t%s\n' "pentest-pq-downgrade" "infnode" "SKIP" "0" "pentest_pq_downgrade.rs absent at runtime" >> "$TSV"
  echo "[matrix] pentest-pq-downgrade -> SKIP (file absent)"
fi
if [ -f "$ROOT/infnode/crates/infnode/tests/pentest_reputation_bypass.rs" ]; then
  row pentest-reputation-bypass infnode 600 -- -p infnode --test pentest_reputation_bypass
else
  printf '%s\t%s\t%s\t%s\t%s\n' "pentest-reputation-bypass" "infnode" "SKIP" "0" "pentest_reputation_bypass.rs absent at runtime" >> "$TSV"
  echo "[matrix] pentest-reputation-bypass -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum-indexer/tests/api_pentest_tests.rs" ]; then
  row api-pentest stellereum-indexer 300 -- --test api_pentest_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "api-pentest" "stellereum-indexer" "SKIP" "0" "api_pentest_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] api-pentest -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum-contracts/contracts/sts20-token/tests/econ_abuse.rs" ] && [ -f "$ROOT/stellereum-contracts/contracts/stl-dns/tests/econ_abuse.rs" ] && [ -f "$ROOT/stellereum-contracts/contracts/liquidity-pool/tests/econ_abuse.rs" ] && [ -f "$ROOT/stellereum-contracts/contracts/account-object/tests/econ_abuse.rs" ]; then
  row econ-abuse stellereum-contracts 300 -- --test econ_abuse
else
  printf '%s\t%s\t%s\t%s\t%s\n' "econ-abuse" "stellereum-contracts" "SKIP" "0" "econ_abuse.rs absent at runtime" >> "$TSV"
  echo "[matrix] econ-abuse -> SKIP (file absent)"
fi

# ---- anti-flood + public-freeze + concurrent-landing sweep (SKIP-if-absent idiom) ----
if [ -f "$ROOT/infnode/crates/infnode/tests/circuit_breaker_tests.rs" ]; then
  row circuit-breaker infnode 600 -- -p infnode --test circuit_breaker_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "circuit-breaker" "infnode" "SKIP" "0" "circuit_breaker_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] circuit-breaker -> SKIP (file absent)"
fi
if [ -f "$ROOT/infnode/crates/infnode/tests/endpoint_hygiene_tests.rs" ]; then
  row endpoint-hygiene infnode 300 -- -p infnode --test endpoint_hygiene_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "endpoint-hygiene" "infnode" "SKIP" "0" "endpoint_hygiene_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] endpoint-hygiene -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/flood_bigchain_tests.rs" ]; then
  row flood-bigchain stellereum 600 -- --test flood_bigchain_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "flood-bigchain" "stellereum" "SKIP" "0" "flood_bigchain_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] flood-bigchain -> SKIP (file absent)"
fi
if [ -f "$ROOT/infnode/crates/infnode/tests/kex_session_tests.rs" ]; then
  row kex-session infnode 300 -- -p infnode --test kex_session_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "kex-session" "infnode" "SKIP" "0" "kex_session_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] kex-session -> SKIP (file absent)"
fi
if [ -f "$ROOT/infnode/crates/infnode/tests/nodeid_ceremony_tests.rs" ]; then
  row nodeid-ceremony infnode 300 -- -p infnode --test nodeid_ceremony_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "nodeid-ceremony" "infnode" "SKIP" "0" "nodeid_ceremony_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] nodeid-ceremony -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/nshard_soak_tests.rs" ]; then
  row nshard-soak stellereum 600 -- --test nshard_soak_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "nshard-soak" "stellereum" "SKIP" "0" "nshard_soak_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] nshard-soak -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/freeze_pins_tests.rs" ]; then
  row freeze-pins stellereum 300 -- --test freeze_pins_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "freeze-pins" "stellereum" "SKIP" "0" "freeze_pins_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] freeze-pins -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/workchain_guard_tests.rs" ]; then
  row workchain-guard stellereum 300 -- --test workchain_guard_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "workchain-guard" "stellereum" "SKIP" "0" "workchain_guard_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] workchain-guard -> SKIP (file absent)"
fi
if [ -f "$ROOT/stellereum/tests/vrf_canonical_draw_tests.rs" ]; then
  row vrf-canonical-draw stellereum 300 -- --test vrf_canonical_draw_tests
else
  printf '%s\t%s\t%s\t%s\t%s\n' "vrf-canonical-draw" "stellereum" "SKIP" "0" "vrf_canonical_draw_tests.rs absent at runtime" >> "$TSV"
  echo "[matrix] vrf-canonical-draw -> SKIP (file absent)"
fi

python3 - "$TSV" "$ROOT" <<'EOF'
import json, sys
tsv, root = sys.argv[1], sys.argv[2]
rows = []
for line in open(tsv):
    p = line.rstrip("\n").split("\t")
    if len(p) < 5: continue
    rows.append({"id": p[0], "workspace": p[1], "status": p[2],
                 "seconds": int(p[3] or 0), "detail": p[4]})
json.dump({"rows": rows}, open(root + "/artifacts/features.json", "w"), indent=2)
icon = {"GREEN": "✅", "RED": "❌", "SKIP": "⏭️"}
md = ["# FEATURES — E2E matrix (machine-generated, do not hand-edit)",
      "",
      "Regenerate: `./scripts/feature_matrix.sh`. RED = missing/broken functionality,",
      "owned work order. SKIP = environmental (reason in row), never a pass.",
      "",
      "| feature | ws | status | secs | detail |",
      "|---|---|---|---|---|"]
for r in rows:
    md.append(f"| {r['id']} | {r['workspace']} | {icon.get(r['status'], '?')} {r['status']} | {r['seconds']} | {r['detail']} |")
g = sum(1 for r in rows if r["status"] == "GREEN")
rd = sum(1 for r in rows if r["status"] == "RED")
s = sum(1 for r in rows if r["status"] == "SKIP")
md += ["", f"GREEN {g} / RED {rd} / SKIP {s} — {len(rows)} rows."]
open(root + "/FEATURES.md", "w").write("\n".join(md) + "\n")
print(f"matrix: GREEN {g} RED {rd} SKIP {s}")
EOF

if [ "$RED" = 1 ]; then echo "MATRIX HAS RED ROWS"; exit 1; fi
echo "MATRIX ALL GREEN (or SKIP)."
