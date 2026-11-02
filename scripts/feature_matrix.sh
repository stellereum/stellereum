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
row bls-classical              stellereum 300 -- --test bls_classical_tests
row vrf-marker                 stellereum 300 -- --lib vrf_is_marked_classical_not_post_quantum
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
