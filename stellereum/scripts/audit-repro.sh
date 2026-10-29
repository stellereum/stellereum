#!/usr/bin/env bash
# audit-repro.sh — reproduce the audit-relevant facts about this tree.
#
# ONE COMMAND, one SUMMARY table. An external auditor can clone the tree, run
# this script, and get the same numbers we measured — the same suites, the same
# pass/fail verdicts, the same rustc, the same commit — without asking us for
# anything.
#
#   ./scripts/audit-repro.sh                 # full run
#   ./scripts/audit-repro.sh --quick         # shorter fuzz smoke, same suites
#   ./scripts/audit-repro.sh --no-fuzz       # skip the fuzz smoke entirely
#   ./scripts/audit-repro.sh --only SUITE    # run one suite (repeatable)
#   ./scripts/audit-repro.sh --runs N        # fuzz runs per target
#
# EXIT CODE: 0 when every suite that ran passed (and the fuzz smoke found
# nothing), 1 otherwise. A suite that could not be RUN (missing target,
# compile error) is reported as ERROR and also fails the run — a suite that
# silently does not exist is worse than a red one.
#
# Nothing here mutates the repository. The fuzz smoke writes only into
# fuzz/corpus/<target>/ and fuzz/artifacts/<target>/.

set -u -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

QUICK=0
DO_FUZZ=1
DO_BUILD=1
FUZZ_RUNS="${STELL_AUDIT_FUZZ_RUNS:-20000}"
FUZZ_MAX_LEN="${STELL_AUDIT_FUZZ_MAX_LEN:-4096}"
FUZZ_MAX_TOTAL_TIME="${STELL_AUDIT_FUZZ_MAX_TOTAL_TIME:-60}"
ONLY_SUITES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) QUICK=1; FUZZ_RUNS=2000; FUZZ_MAX_TOTAL_TIME=20; shift ;;
    --no-fuzz) DO_FUZZ=0; shift ;;
    --no-build) DO_BUILD=0; shift ;;
    --only) shift; ONLY_SUITES+=("${1:-}"); shift ;;
    --runs) shift; FUZZ_RUNS="${1:-20000}"; shift ;;
    -h|--help) sed -n '2,24p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# --------------------------------------------------------------------------
# Suite catalogue.
#
# Every suite here is a REGRESSION PIN for a security property, or the fuzz
# smoke. The second field is the `cargo test --test <target>` target; the
# third is what the suite pins.
# --------------------------------------------------------------------------

SUITES=(
  "lib|--lib|unit tests in src/ (the crate's own module tests)"
  "adversarial_regression|adversarial_regression_tests|every closed finding's original attack, replayed literally"
  "adversarial_4node|adversarial_4node_tests|4-validator Byzantine scenarios (equivocation, round inflation, withheld QC)"
  "adversarial_economic|adversarial_economic_tests|double-dip, commission front-run, dust, self-dealing"
  "historical_attacks|historical_attacks_tests|the historical attack corpus"
  "vuln_bundle|vuln_bundle_tests|the bundled vulnerability regressions"
  "consensus_reaudit|consensus_reaudit_tests|consensus re-audit: invalidations, lock rescue, QC rounds, snapshot anchor"
  "consensus_security|consensus_security_tests|consensus security properties"
  "consensus_audit_hardening|consensus_audit_hardening_tests|consensus audit hardening"
  "consensus_rephase|consensus_rephase_tests|consensus re-phase behaviour"
  "adopt_prevote|adopt_prevote_tests|the adopt-prevote path"
  "proposal_refire|proposal_refire_tests|proposal re-fire"
  "attack_round3|attack_round3_tests|the round-3 attack suite"
  "byzantine_fault|byzantine_fault_tests|Byzantine fault scenarios"
  "equivocation_slash|equivocation_slash_tests|equivocation slashing"
  "slashing_rotation|slashing_rotation_tests|slashing + validator rotation"
  "quorum_fragility|quorum_fragility_tests|quorum fragility"
  "validator_set_quorum|validator_set_quorum_tests|validator-set quorum"
  "validator_set_freshness|validator_set_freshness_tests|validator-set freshness"
  "observer_recovery|observer_and_recovery_tests|the observer (fail-closed) arm"
  "observer_return|observer_return_without_copy_tests|the observer arm never returns to voting by itself"
  "failure_fee_contract|failure_fee_contract_tests|the F-01 failure-fee contract (4 cases)"
  "apply_floor|apply_floor_tests|the consensus fee floor"
  "state_root_completeness|state_root_completeness_tests|every consensus-visible subsystem moves the state root"
  "genesis_root|genesis_root_known_answer_tests|the pinned genesis root known-answer vector"
  "block_hash_binding|block_hash_binding_tests|the block hash binds its body"
  "block_state_root_binding|block_state_root_binding_tests|the block binds the state root"
  "state_sync_closeout|audit_state_sync_closeout_tests|snapshot/sync domain-restore closure"
  "restore_root_verification|restore_root_verification_tests|the restore path verifies the root"
  "fuzz_decoder|fuzz_decoder_tests|deterministic decoder fuzzing (stable toolchain)"
  "fuzz_certificate_decoder|fuzz_certificate_decoder_tests|deterministic certificate-decoder fuzzing"
  "fuzz_consensus_stress|fuzz_consensus_stress|consensus stress under fuzzed input"
  "pq_audit_closure|pq_audit_closure_tests|post-quantum audit closure"
  "pq_uqc_power_quorum|pq_uqc_power_quorum_tests|µQC network-anchored power quorum"
  "pq_equivocation_report|pq_equivocation_report_tests|PQ equivocation reporting"
  "pure_pq_enforcement|pure_pq_enforcement_tests|pure-PQ enforcement (fail-closed scheme refusal)"
  "post_quantum_audit|post_quantum_audit_tests|post-quantum audit suite"
  "post_quantum_svm|post_quantum_svm_tests|post-quantum signatures in the SVM path"
  "mev_pq|mev_pq_tests|MEV + post-quantum interaction"
  "mev_preemption|mev_preemption_tests|MEV preemption mechanics"
  "bridge_onchain|bridge_onchain_tests|bridge on-chain deposit/withdrawal path"
  "bridge_challenge|bridge_challenge_tests|bridge challenge/fraud-proof path"
  "bridge_dispute|bridge_dispute_tests|bridge dispute resolution"
  "bridge_persistence|bridge_persistence_tests|bridge replay-set persistence across restarts"
  "bridge_zk_gate|bridge_zk_gate_tests|bridge zk-proof gate"
  "bridge_adapters|bridge_adapters_tests|TON/EVM/Solana deposit-proof adapters"
  "audit_closure_bridge|audit_closure_bridge_tests|bridge audit closure"
  "sharding_topology|sharding_topology_tests|address->shard rule, split/merge, trie migration"
  "sharding_m1|sharding_m1_tests|sharding milestone 1"
  "sharding_m2|sharding_m2_tests|sharding milestone 2"
  "sharding_m3|sharding_m3_tests|sharding milestone 3"
  "cross_shard_anchor|cross_shard_anchor_tests|the cross-shard anchor"
  "cross_shard_e2e_pq|cross_shard_e2e_pq_tests|cross-shard end-to-end with PQ signatures"
  "xshard_replay|xshard_replay_tests|cross-shard replay protection"
  "xshard_2pc|xshard_2pc_tests|cross-shard two-phase commit"
  "mempool_econ|mempool_econ_tests|mempool economics (fee priority, nonce gaps)"
  "mempool_mev_audit_closure|mempool_mev_audit_closure_tests|mempool + MEV audit closure (F-02..F-08)"
  "chain_mempool_security|chain_mempool_security_tests|chain <-> mempool interaction"
  "staking_audit_closure|staking_audit_closure_tests|staking audit closure"
  "staking_rewards_pool|staking_rewards_pool_tests|the reward pool accounting"
  "audit_closure_oracle_gov|audit_closure_oracle_gov_tests|oracle + governance audit closure"
  "audit_closure_privacy|audit_closure_privacy_tests|confidential-transaction audit closure"
  "confidential_preverify|confidential_preverify_tests|range-proof pre-verification"
  "confidential_solvency|confidential_solvency_tests|shielded-pool solvency"
  "audit_rpc_evm_closeout|audit_rpc_evm_closeout|RPC + EVM closeout (incl. the light-client tripwire)"
  "network_audit_close|network_audit_close_tests|network audit closure"
  "transport_audit_fixes|transport_audit_fixes|transport audit fixes"
  "node_keys_security|node_keys_security_tests|key handling at rest"
  "node_keys_hardening|node_keys_hardening_tests|key handling hardening"
  "stl57_audit_pentest|stl57_audit_pentest_tests|address-format pentest"
  "light_client|light_client_tests|the light client"
  "light_client_wiring|light_client_wiring_tests|the light client's wiring tripwire"
  "evm_adapter|evm_adapter_tests|the EVM facade (RLP, chain-id binding, strict layers)"
  "svm_atomicity|svm_atomicity_tests|SVM atomicity (no partial effects)"
  "clob_atomicity|clob_atomicity|CLOB atomicity"
  "orderbook_griefing|orderbook_griefing_tests|orderbook griefing"
  "token_security|token_security_tests|token security"
  "token_adversarial|token_adversarial_tests|token adversarial cases"
  "memory_bounds|memory_bounds_tests|memory bounds"
)

# Fuzz targets: <name>|<what it decodes>
FUZZ_TARGETS=(
  "frame_decode|infnode Frame::decode (the network entry point)"
  "consensus_msg_decode|ConsensusMsg::decode + parse_incoming/parse_tx_incoming"
  "transaction_decode|sharding::Transaction bincode decode"
  "block_decode|sharding::Block bincode decode (incl. the order/shard commitments)"
  "cert_envelope_decode|µQC / epoch CEC / BLS QC certificate envelopes + the two PQ signature envelopes"
  "evm_raw_tx_decode|the hand-rolled EVM RLP decoder (eth_sendRawTransaction input)"
  "peer_msg_decode|the cross-shard message decoder + the epoch-seal gossip frames"
)

# --------------------------------------------------------------------------
# Bookkeeping
# --------------------------------------------------------------------------

SUMMARY_FILE="$(mktemp)"
FAILED=0
SKIPPED=0
ERRORED=0
trap 'rm -f "$SUMMARY_FILE"' EXIT

now_ms() { date +%s%3N; }
fmt_ms() {
  local ms="$1"
  if [[ "$ms" -lt 1000 ]]; then printf '%sms' "$ms"
  else printf '%d.%02ds' "$((ms / 1000))" "$(( (ms % 1000) / 10 ))"; fi
}

# suite_name | passed | failed | ignored | duration_ms | verdict | note
record() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" >> "$SUMMARY_FILE"
}

should_run() {
  local name="$1"
  [[ ${#ONLY_SUITES[@]} -eq 0 ]] && return 0
  local s
  for s in "${ONLY_SUITES[@]}"; do [[ "$s" == "$name" ]] && return 0; done
  return 1
}

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# --------------------------------------------------------------------------
# 0. Provenance — the three facts an auditor checks first
# --------------------------------------------------------------------------

say "PROVENANCE"

COMMIT="$(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
COMMIT_SHORT="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
COMMIT_DATE="$(git log -1 --format=%cI 2>/dev/null || echo 'unknown')"
COMMIT_SUBJECT="$(git log -1 --format=%s 2>/dev/null || echo 'unknown')"
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
RUSTC_VERSION="$(rustc --version 2>/dev/null || echo 'unknown')"
CARGO_VERSION="$(cargo --version 2>/dev/null || echo 'unknown')"
NIGHTLY_VERSION="$(cargo +nightly --version 2>/dev/null || echo 'not installed')"
DIRTY_COUNT="$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
# A fingerprint of the actual working-tree sources, so "the tree we measured"
# can be identified even while it is being edited under us.
tree_fingerprint() {
  find src tests fuzz -name '*.rs' -type f 2>/dev/null | LC_ALL=C sort | xargs sha256sum 2>/dev/null | sha256sum | cut -c1-16
}
TREE_FINGERPRINT="$(tree_fingerprint)"
SRC_LOC="$(cat src/*.rs 2>/dev/null | wc -l | tr -d ' ')"
MODULES="$(grep -c '^pub mod ' src/lib.rs 2>/dev/null || echo '?')"
CORPUS_TOTAL="$(find fuzz/corpus -type f 2>/dev/null | wc -l | tr -d ' ')"

echo "  commit            : $COMMIT ($COMMIT_SHORT)"
echo "  commit date       : $COMMIT_DATE"
echo "  commit subject    : $COMMIT_SUBJECT"
echo "  branch            : $BRANCH"
echo "  working tree      : ${DIRTY_COUNT} changed path(s) (uncommitted edits present: $([ "$DIRTY_COUNT" -gt 0 ] && echo yes || echo no))"
echo "  source fingerprint: $TREE_FINGERPRINT  (sha256 over src/ tests/ fuzz/ *.rs)"
echo "  src/ size         : ${SRC_LOC} lines across $(ls src/*.rs 2>/dev/null | wc -l | tr -d ' ') files, ${MODULES} modules"
echo "  rustc             : $RUSTC_VERSION"
echo "  cargo             : $CARGO_VERSION"
echo "  nightly (fuzz)    : $NIGHTLY_VERSION"

# --------------------------------------------------------------------------
# 1. Build
# --------------------------------------------------------------------------

if [[ $DO_BUILD -eq 1 ]]; then
  say "BUILD (cargo build --tests --all-targets)"
  BUILD_START="$(now_ms)"
  BUILD_LOG="$(mktemp)"
  if cargo build --tests --all-targets > "$BUILD_LOG" 2>&1; then
    BUILD_VERDICT=ok
  else
    BUILD_VERDICT=FAILED
    FAILED=1
  fi
  BUILD_MS=$(( $(now_ms) - BUILD_START ))
  record "build (cargo build --tests --all-targets)" "-" "-" "-" "$BUILD_MS" "$BUILD_VERDICT" "compile of every test binary"
  echo "  build: $BUILD_VERDICT  ($(fmt_ms "$BUILD_MS"))"
  if [[ "$BUILD_VERDICT" != "ok" ]]; then
    echo "--- last 40 lines of the build log ---"
    tail -40 "$BUILD_LOG"
    echo "--- the failing test targets ---"
    grep -E '^error' -A 3 "$BUILD_LOG" | head -30
  fi
  rm -f "$BUILD_LOG"
fi

# --------------------------------------------------------------------------
# 2. Suites
# --------------------------------------------------------------------------

say "SUITES"

for entry in "${SUITES[@]}"; do
  name="${entry%%|*}"; rest="${entry#*|}"
  target="${rest%%|*}"; desc="${rest#*|}"
  should_run "$name" || continue

  printf '  %-30s ' "$name"
  log="$(mktemp)"
  start="$(now_ms)"
  if [[ "$target" == "--lib" ]]; then
    cargo test --lib --no-fail-fast > "$log" 2>&1
  else
    cargo test --no-fail-fast --test "$target" > "$log" 2>&1
  fi
  rc=$?
  dur=$(( $(now_ms) - start ))

  # The last `test result:` line is the aggregate of the binary.
  line="$(grep -E '^test result:' "$log" | tail -1)"
  passed="$(printf '%s' "$line" | sed -n 's/.*ok\. \([0-9]*\) passed.*/\1/p')"
  failed="$(printf '%s' "$line" | sed -n 's/.*; \([0-9]*\) failed.*/\1/p')"
  ignored="$(printf '%s' "$line" | sed -n 's/.*; \([0-9]*\) ignored.*/\1/p')"
  [[ -z "$passed" ]] && passed="-"
  [[ -z "$failed" ]] && failed="-"
  [[ -z "$ignored" ]] && ignored="-"

  if [[ $rc -eq 0 && ( "$failed" == "0" || -z "$failed" ) ]]; then
    verdict=ok
    printf 'PASS  %4s passed  (%s)\n' "$passed" "$(fmt_ms "$dur")"
  elif [[ $rc -eq 0 && "$failed" == "-" ]]; then
    # The binary compiled and ran but produced no `test result:` line: the
    # target does not exist (cargo would have failed) or it has no tests.
    verdict="ok(no-target)"
    printf 'SKIP  (no test target matched)\n'
  else
    if grep -qE 'error\[E[0-9]+\]|could not compile|error: aborting' "$log"; then
      verdict=ERROR
      ERRORED=$(( ERRORED + 1 ))
      printf 'ERROR (did not compile)  (%s)\n' "$(fmt_ms "$dur")"
      grep -E 'error\[E[0-9]+\]|could not compile' -A 4 "$log" | head -8 | sed 's/^/        /'
    else
      verdict=FAILED
      printf 'FAIL  %s passed, %s failed  (%s)\n' "$passed" "$failed" "$(fmt_ms "$dur")"
      grep -E '^(test .* FAILED|failures:)' "$log" | head -12 | sed 's/^/        /'
    fi
    FAILED=1
  fi
  record "$name" "$passed" "$failed" "$ignored" "$dur" "$verdict" "$desc"
  rm -f "$log"
done

# --------------------------------------------------------------------------
# 3. Fuzz smoke
# --------------------------------------------------------------------------

if [[ $DO_FUZZ -eq 1 ]]; then
  say "FUZZ SMOKE (cargo fuzz run, ${FUZZ_RUNS} runs / target, max_len ${FUZZ_MAX_LEN})"

  if ! cargo +nightly --version > /dev/null 2>&1; then
    echo "  nightly toolchain is NOT installed — fuzz smoke SKIPPED (not a failure)"
    record "fuzz smoke" "-" "-" "-" 0 "SKIP" "no nightly toolchain"
    SKIPPED=$(( SKIPPED + 1 ))
  elif ! cargo fuzz --version > /dev/null 2>&1; then
    echo "  cargo-fuzz is NOT installed — fuzz smoke SKIPPED (not a failure)"
    record "fuzz smoke" "-" "-" "-" 0 "SKIP" "cargo-fuzz not installed"
    SKIPPED=$(( SKIPPED + 1 ))
  else
    for entry in "${FUZZ_TARGETS[@]}"; do
      tgt="${entry%%|*}"; desc="${entry#*|}"
      should_run "fuzz:$tgt" || should_run "fuzz" || continue
      printf '  %-30s ' "fuzz:$tgt"
      log="$(mktemp)"
      start="$(now_ms)"
      ( cd fuzz && cargo +nightly fuzz run "$tgt" -- \
          -runs="$FUZZ_RUNS" -max_len="$FUZZ_MAX_LEN" -max_total_time="$FUZZ_MAX_TOTAL_TIME" ) \
          > "$log" 2>&1
      rc=$?
      dur=$(( $(now_ms) - start ))
      if [[ $rc -eq 0 ]]; then
        verdict=ok
        runs="$(grep -oE 'Done [0-9]+ runs?' "$log" | tail -1 | grep -oE '[0-9]+' | head -1)"
        [[ -z "$runs" ]] && runs="-"
        printf 'PASS  %6s runs  (%s)\n' "$runs" "$(fmt_ms "$dur")"
        record "fuzz:$tgt" "$runs" "0" "0" "$dur" "ok" "$desc"
      else
        # A build failure of the FUZZ BINARY is usually a transient: the tree
        # may be being edited while this script runs. Retry once before
        # declaring the target red.
        if grep -q "failed to build fuzz script\|could not compile" "$log"; then
          echo -n "retry(1) "
          sleep 15
          start="$(now_ms)"
          ( cd fuzz && cargo +nightly fuzz run "$tgt" -- \
              -runs="$FUZZ_RUNS" -max_len="$FUZZ_MAX_LEN" -max_total_time="$FUZZ_MAX_TOTAL_TIME" ) \
              > "$log" 2>&1
          rc=$?
          dur=$(( $(now_ms) - start ))
        fi
        if [[ $rc -eq 0 ]]; then
          verdict=ok
          runs="$(grep -oE 'Done [0-9]+ runs?' "$log" | tail -1 | grep -oE '[0-9]+' | head -1)"
          [[ -z "$runs" ]] && runs="-"
          printf 'PASS  %6s runs  (%s)\n' "$runs" "$(fmt_ms "$dur")"
          record "fuzz:$tgt" "$runs" "0" "0" "$dur" "ok" "$desc"
        else
          verdict=FAILED
          FAILED=1
          printf 'FAIL  (%s)\n' "$(fmt_ms "$dur")"
          grep -E 'ERROR|SUMMARY|panicked|assertion|error\[' "$log" | head -12 | sed 's/^/        /'
          record "fuzz:$tgt" "-" "-" "-" "$dur" "FAILED" "$desc"
        fi
      fi
      rm -f "$log"
    done
  fi
fi

# --------------------------------------------------------------------------
# 4. SUMMARY
# --------------------------------------------------------------------------

say "SUMMARY"

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_MS=0
printf '%-36s %8s %8s %8s %10s  %s\n' "SUITE" "PASSED" "FAILED" "IGNORED" "DURATION" "VERDICT"
printf '%s\n' "-----------------------------------------------------------------------------------------------"
while IFS=$'\t' read -r sname spass sfail sig dur verdict note; do
  printf '%-36s %8s %8s %8s %10s  %s\n' "$sname" "$spass" "$sfail" "$sig" "$(fmt_ms "$dur")" "$verdict"
  if [[ "$spass" =~ ^[0-9]+$ ]]; then TOTAL_PASS=$(( TOTAL_PASS + spass )); fi
  if [[ "$sfail" =~ ^[0-9]+$ ]]; then TOTAL_FAIL=$(( TOTAL_FAIL + sfail )); fi
  TOTAL_MS=$(( TOTAL_MS + dur ))
done < "$SUMMARY_FILE"
printf '%s\n' "-----------------------------------------------------------------------------------------------"
printf '%-36s %8s %8s %8s %10s\n' "TOTAL" "$TOTAL_PASS" "$TOTAL_FAIL" "-" "$(fmt_ms "$TOTAL_MS")"

FINGERPRINT_END="$(tree_fingerprint)"
echo
echo "commit            : $COMMIT"
echo "commit date       : $COMMIT_DATE"
echo "source fingerprint: $TREE_FINGERPRINT (start of this run)"
echo "                   $FINGERPRINT_END (end of this run)"
if [[ "$TREE_FINGERPRINT" != "$FINGERPRINT_END" ]]; then
  echo "                   *** THE TREE CHANGED DURING THIS RUN ***"
  echo "                   *** the numbers below mix two trees; re-run on a settled tree ***"
fi
echo "src/ lines        : $SRC_LOC"
echo "rustc             : $RUSTC_VERSION"
echo "cargo             : $CARGO_VERSION"
echo "nightly (fuzz)    : $NIGHTLY_VERSION"

echo
echo "Fuzz corpus sizes (files):"
for entry in "${FUZZ_TARGETS[@]}"; do
  tgt="${entry%%|*}"
  n="$(find "fuzz/corpus/$tgt" -type f 2>/dev/null | wc -l | tr -d ' ')"
  printf '  %-36s %s\n' "fuzz/corpus/$tgt" "$n"
done
printf '  %-36s %s\n' "fuzz/corpus (TOTAL)" "$CORPUS_TOTAL"

if [[ $SKIPPED -gt 0 || $ERRORED -gt 0 ]]; then
  echo
  echo "NOTE: $SKIPPED component(s) SKIPPED, $ERRORED suite(s) ERRORED (see the table)."
  echo "      A skipped or errored component is NOT a pass."
fi

echo
if [[ $FAILED -eq 0 ]]; then
  echo "RESULT: PASS — every suite that ran is green, and the fuzz smoke found nothing."
  exit 0
fi
echo "RESULT: FAIL — at least one suite is red or did not compile (see the table)."
exit 1
