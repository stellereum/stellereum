# VRF / BLS Activation Runbook (read-only review, no live ops)

Status: DEFAULT-OFF gates verified by tests, NOT activated on any live network.
Scope: `stellereum/src/vrf.rs`, `stellereum/src/bls.rs`,
`stellereum/src/consensus.rs` (gated election call sites),
`stellereum/src/main.rs` (`Commands::Run` startup gates), `docs/specs/02_CRYPTO_AND_PQ.md`,
`stellereum/docs/PLAN-VRF.md`, `stellereum/docs/PLAN-POP.md`.
Every claim below cites the code it was read from. Anything not found in code is
marked UNVERIFIED. Do NOT run activation against a live stand from this file alone.

Test evidence: `cargo test -p stellereum --test vrf_sortition_gate_tests
--test bls_pop_tests --test bls_qc_compat_tests --test bls_tests` → 35/35 pass
(6 + 11 + 14 + 4; full lines in §7). `cargo clippy -p stellereum --all-targets --
-D warnings` → clean (0 warnings, 0 errors; §8).

## 1. What each env var does + defaults

### VRF sortition gate

| Var | Defined | Default | Accepted values | Effect |
|---|---|---|---|---|
| `STELL_VRF_ACTIVATION_HEIGHT` | `stellereum/src/vrf.rs:87` (`VRF_ACTIVATION_HEIGHT_ENV`) | `VrfActivation::Disabled` (enum default, `stellereum/src/vrf.rs:103-109`, `Default` impl) | Missing / empty / unparsable → `Disabled`; otherwise `FromHeight(h)` for `u64` `h` (`stellereum/src/vrf.rs:132-150`) | `is_active_at(height)` is `false` when `Disabled`, else `height >= h` (`stellereum/src/vrf.rs:111-118`); `boundary()` is `None` / `Some(h)` (`stellereum/src/vrf.rs:120-127`) |

Details:

- Parse mirrors the XPC pattern: trim, drop empty, `parse::<u64>()`
  (`stellereum/src/vrf.rs:132-140`; cf. `xpc_activation_from_env` in
  `stellereum/src/main.rs:2599-2616`).
- Unparsable value does NOT fail startup: it prints
  `[vrf] STELL_VRF_ACTIVATION_HEIGHT={v:?} is not a height: VRF sortition stays INACTIVE`
  to stderr and returns `Disabled` (`stellereum/src/vrf.rs:141-147`).
- Post-activation seed (only used when gate is active AND a verified output is
  supplied): `vrf_election_seed(output, height, round) =
  BLAKE3(VRF_ELECTION_DOMAIN || output || height-le || round-le)`
  (`stellereum/src/vrf.rs:467-473`), domain `STELL_SORTITION_VRF_V1`
  (`stellereum/src/vrf.rs:83`), disjoint from `STELL_SORTITION_V5`.
- Proof machinery (context, not activation): deterministic Schnorr
  `vrf_prove` / `vrf_verify` (`stellereum/src/vrf.rs:396-443`), registry-bound
  `verify_vrf_seed_for_validator` (`stellereum/src/vrf.rs:452-459`), beacon
  `beacon_genesis` / `beacon_next` (`stellereum/src/vrf.rs:484-503`), lottery
  `lottery_threshold` (`stellereum/src/vrf.rs:517-541`), counters
  `vrf_bindings_registered` (`stellereum/src/vrf.rs:588-591`).

### BLS PoP strict-parse gate

| Var | Defined | Default | Accepted values | Effect |
|---|---|---|---|---|
| `STELL_BLS_POP_REQUIRED` | `stellereum/src/bls.rs:481` (`BLS_POP_REQUIRED_ENV`) | OFF (unset / anything but the on-literals → `false`, `stellereum/src/bls.rs:486-490`) | `bls_flag_on(raw)`: `matches!(raw.trim(), "1" \| "true" \| "TRUE" \| "on" \| "ON")` (`stellereum/src/bls.rs:545-547`); shares the literal set with the QC flag so the two gates never disagree on "enabled" (`stellereum/src/bls.rs:483-484`) | Selects the registry parser in `QcBlsConfig::from_env` (`stellereum/src/bls.rs:605-648`, branch at `stellereum/src/bls.rs:614-638`): ON → `parse_registry_entries_strict_pop` for file AND inline; OFF → legacy `parse_registry_entries` byte-identically (`stellereum/src/bls.rs:610-624`) |

Details:

- Strict contract (`stellereum/src/bls.rs:941-1025`): an entry inserts ONLY as
  3-token `<ed_hex> <bls_hex> <pop_hex>` with a 96-byte non-identity G2 PoP that
  verifies under `bls_verify_pop(pk, ed)` for that pair; everything else
  (bare 2-token legacy, non-hex, wrong lengths, non-curve key, malformed PoP,
  PoP over another preimage) is skipped + `tracing::warn!` + `rejected += 1` +
  `note_bls_pop_rejected()`. No v1 fallback for malformed third tokens
  (`stellereum/src/bls.rs:1005-1020`). Refused keys never enter the registry, so
  `canonical_keys` can never count them (`stellereum/src/bls.rs:953-958`).
- Lenient v2 reader `parse_registry_entries_v2` (`stellereum/src/bls.rs:873-939`)
  is NOT reached from `from_env` today; it is the accept-new/emit-old reference
  (2-token → `legacy`, valid 3-token → `pop_verified`, bad → `rejected`).
- Per-parse outcome: `BlsRegistryStats { pop_verified, legacy, rejected }`
  (`stellereum/src/bls.rs:846-857`); process-wide migration counters
  `bls_registry_migration_counts() -> (pop_verified, legacy, rejected)`
  (`stellereum/src/bls.rs:1050-1057`), atomics (`stellereum/src/bls.rs:1031-1033`).
- PoP crypto: DST `STELL_BLS_POP_V1` (`stellereum/src/bls.rs:816`), preimage
  `DST || ed_id(32)` (`stellereum/src/bls.rs:826-831`), `bls_sign_pop` /
  `bls_verify_pop` (`stellereum/src/bls.rs:836-844`).

### BLS QC path (adjacent gates, not the PoP gate)

| Var | Defined | Default | Effect |
|---|---|---|---|
| `STELL_BLS_QC` | `stellereum/src/bls.rs:470` (`BLS_QC_ENV`) | OFF | `QcBlsConfig.enabled` (`stellereum/src/bls.rs:606-608`); `refuse_bls_qc_if_enabled()` returns `Ok` when off, `Err` (loud refusal) when on (`stellereum/src/bls.rs:515-534`) |
| `STELL_BLS_KEYS_FILE` | `stellereum/src/bls.rs:472` | unset (no registry) | File of `<ed> <bls>` lines read in `from_env` (`stellereum/src/bls.rs:616-630`); unreadable → `tracing::warn!` + BLS path disabled for that process |
| `STELL_BLS_KEYS` | `stellereum/src/bls.rs:474` | unset | Inline `ed:bls,...` registry (`stellereum/src/bls.rs:631-638`) |
| `STELL_BLS_SK_SEED` | `stellereum/src/bls.rs:476` | `None` (no local BLS signing) | 64-hex-char seed → `BlsSecretKey::from_seed` (`stellereum/src/bls.rs:639-642`); `local_vote_key()` (`stellereum/src/bls.rs:673-675`); `local_vote_bls_sign` returns `None` (pre-BLS bytes) when disabled/unconfigured (`stellereum/src/bls.rs:747-753`) |

Startup enforcement: `Commands::Run` calls
`stellereum::bls::refuse_bls_qc_if_enabled()?` (`stellereum/src/main.rs:7095-7101`,
inside `Commands::Run`, `stellereum/src/main.rs:6920`), so `STELL_BLS_QC=1`
refuses to start with the no-PoP registry message naming proof-of-possession /
PoP (`stellereum/src/bls.rs:522-533`, `eprintln!` + `tracing::error!`).

### Separate BLS height mechanism (do not confuse with the flag gates)

- `DEFAULT_BLS_ACTIVATION_HEIGHT: u64 = 10_000` (`stellereum/src/bls.rs:52`),
  `is_bls_active(height, activation_height) = height >= activation_height`
  (`stellereum/src/bls.rs:55-57`).
- `HybridCertificate::is_format_valid(activation_height)` (`stellereum/src/bls.rs:428-435`):
  pre-activation must be `Ed25519`, post-activation must be `BlsAggregate`.
- This `HybridCertificate` soft-fork model is exercised in `tests/bls_tests.rs`
  (`test_soft_fork_activation_height`) and is DISTINCT from the live
  `QuorumCertificate` BLS-envelope + `STELL_BLS_QC` flag path. There is no code
  wiring `DEFAULT_BLS_ACTIVATION_HEIGHT` into live QC verification — UNVERIFIED
  beyond the `HybridCertificate` type itself.

## 2. Activation order (which height gating, how heights propagate)

1. VRF election switch (phase-1 state: NOT LIVE).
   - The gated election exists: `derive_sortition_committee_gated` /
     `sortition_seed_gated` (`stellereum/src/consensus.rs:871-993`). Rule:
     `Disabled`, pre-activation height, or `None` output → v5 parent-hash
     `sortition_seed` (`stellereum/src/consensus.rs:980-993`); active height +
     `Some(verified_output)` → `vrf_election_seed` (`stellereum/src/consensus.rs:987-990`).
   - Live callers are PINNED to `Disabled + None`: the `derive_sortition_committee`
     wrapper (`stellereum/src/consensus.rs:839-855`, pinned at `:852-853`), the
     µQC signer-recovery path (`stellereum/src/consensus.rs:2446-2458`), the
     `micro_cert_valid_signers` path (`stellereum/src/consensus.rs:2753-2763`), and
     `verify_micro_cert` (`stellereum/src/consensus.rs:2854-2864`).
   - There is NO `STELL_VRF_ACTIVATION_HEIGHT` read in `stellereum/src/main.rs`
     (verified by grep: only `xpc_activation_from_env` at `main.rs:2599` and its
     single use at `main.rs:2870`; `vrf_activation_from_env` lives only in
     `stellereum/src/vrf.rs:132`). So setting the env var today changes NO live
     consensus bytes — the configured activation and the winning ticket's verified
     output still need phase-3 threading at the four call sites above (their own
     comments say exactly this).
   - Consequently there is NO height-propagation code to document: how `H_vrf`
     propagates to every node is UNVERIFIED (no implementation). The plan specifies
     it as a consensus-visible boundary every node must configure identically, like
     `XpcActivation` (`stellereum/src/main.rs:2595-2598` comment; `PLAN-VRF` §4),
     with pre-`H_vrf` history verifying under v5 forever and `h >= H_vrf` old nodes
     halting loudly — but that is specified in `stellereum/docs/PLAN-VRF.md:79-91`,
     not coded.
2. BLS PoP strict parse (phase-1 state: parser built + gated, refusal unchanged).
   - No height. Effective at process start: `QcBlsConfig::from_env` reads the flag
     once per process construction, and `qc_bls()` caches it process-wide behind a
     `OnceLock` (`stellereum/src/bls.rs:723-736`). Changing `STELL_BLS_POP_REQUIRED`
     or the registry files requires a restart to take effect (no hot-reload path in
     code).
   - Order: (a) operators generate PoPs offline (`bls_sign_pop`), append third tokens,
     (b) set `STELL_BLS_POP_REQUIRED=1` (accepted literals only) on every verifier,
     (c) restart. Mixed strict/lenient registries do not fork QC verification today
     because counting BLS power is still hard-refused (next step).
   - The startup refusal is UNCHANGED by the PoP gate: `refuse_bls_qc_if_enabled`
     still refuses ANY `STELL_BLS_QC=1` (`stellereum/src/bls.rs:515-534`,
     `tests/bls_pop_tests.rs:301-331`). Phase 2 is specified to replace it with
     "refuse unless every entry carries a valid PoP"
     (`stellereum/docs/PLAN-POP.md:49-63`), but that replacement is NOT in code.
3. BLS QC counting (not activated; blocked by design).
   - Even with a full-PoP registry, `STELL_BLS_QC=1` refuses at startup
     (`stellereum/src/main.rs:7101`). Default-off nodes verify exactly as before
     through the Ed25519 list; production never strips the Ed25519 list, so
     flag-off nodes still accept flag-on nodes' certificates through the fallback
     (`stellereum/src/bls.rs:441-463` header comment; `tests/bls_qc_compat_tests.rs`
     compat + fallback cases).

## 3. How to verify activation on a live network

VRF:

- Startup/log lines: the ONLY VRF log line in code is the stderr warning on a
  malformed `STELL_VRF_ACTIVATION_HEIGHT`
  (`stellereum/src/vrf.rs:141-145`). There is no "VRF active at height H" banner,
  no activation metric, and no RPC exposing `VrfActivation` — UNVERIFIED beyond the
  absence in code (grep over `stellereum/src/main.rs`, `stellereum/src/rpc.rs` finds
  no VRF activation plumbing). Concretely: after phase-3 threading lands, verify by
  (a) asserting every node exports the SAME `STELL_VRF_ACTIVATION_HEIGHT`, and
  (b) comparing `sortition_seed_gated` / committee outputs at `H_vrf - 1` (must equal
  v5) vs `H_vrf` (must equal `vrf_election_seed`) — the exact assertion shape is
  already coded in `stellereum/tests/vrf_sortition_gate_tests.rs:82-200`.
- Counters: `vrf_bindings_registered()` (`stellereum/src/vrf.rs:588-591`) counts
  verified-and-registered bindings in-process; readiness is bindings for 100% of
  voting power per `stellereum/docs/PLAN-VRF.md:63-65`. No RPC exposes it —
  UNVERIFIED as a live-network check.

BLS PoP / QC:

- Startup refusal line (proves the fail-closed gate still holds): starting with
  `STELL_BLS_QC=1` must exit via the `Commands::Run` gate
  (`stellereum/src/main.rs:7101`) printing the `[bls] REFUSING: STELL_BLS_QC=1 ...`
  message (`stellereum/src/bls.rs:522-533`) to both stderr and `tracing::error!`.
- Registry parse warnings: `tracing::warn!` lines `bls: registry ... skipped` /
  `bls: registry PoP ...` (`stellereum/src/bls.rs:688-718` v1,
  `stellereum/src/bls.rs:886-932` v2, `stellereum/src/bls.rs:972-1019` strict).
  Exact operator-visible strings for the strict gate: `registry without PoP refused
  (strict PoP gate)` and `registry PoP missing or invalid (strict PoP gate)`
  (`stellereum/src/bls.rs:972-979`, `:1012-1016`).
- Migration readiness: per-parse `BlsRegistryStats` + process counters
  `bls_registry_migration_counts()` (`stellereum/src/bls.rs:1050-1057`); phase-2
  readiness reads as `legacy == 0 && rejected == 0` with
  `pop_verified == validator count` (`stellereum/src/bls.rs:1047-1049`,
  `stellereum/docs/PLAN-POP.md:57-58`). No RPC/log sink exposes these counters on a
  live node — UNVERIFIED beyond calling the function in-process.
- RPC: no RPC method in `stellereum/src/rpc.rs` references BLS PoP/QC state
  (verified by grep: zero hits for `vrf|bls_pop|qc_bls`). Any "which RPC to check"
  answer is therefore UNVERIFIED — there is currently no RPC to check.

## 4. Rollback (unset → deterministic pre-activation behavior preserved?)

- VRF: unset/empty/garbage `STELL_VRF_ACTIVATION_HEIGHT` → `Disabled`
  (`stellereum/src/vrf.rs:137-147`). `sortition_seed_gated(..., Disabled, _)`
  returns `sortition_seed` and `derive_sortition_committee_gated(..., Disabled, _)`
  runs the identical draw loop (`stellereum/src/consensus.rs:871-993`). Call sites
  already pass `Disabled + None`, so rollback is a restart with the var unset; no
  state to unwind (registry rows are inert metadata, `PLAN-VRF` §7). The claim is
  pinned by the sweep test (`stellereum/tests/vrf_sortition_gate_tests.rs:98-124`)
  and the fixed vectors (`:92-96`, `:167-195`).
- BLS PoP: unset `STELL_BLS_POP_REQUIRED` (or any off-spelling `0/false/no/""`,
  pinned in `stellereum/tests/bls_pop_tests.rs:292-296`) → `bls_pop_required() ==
  false` → `from_env` runs the pre-PoP v1 reader on both file and inline sources
  (`stellereum/src/bls.rs:622-637`). Legacy 2-token entries are accepted exactly as
  before (`stellereum/tests/bls_pop_tests.rs:240-299`). Rollback is a restart with
  the var unset; PoP third tokens are inert metadata to the v1 reader.
- BLS QC: unset `STELL_BLS_QC` (or anything but `1/true/TRUE/on/ON`,
  `stellereum/src/bls.rs:545-547`) → `refuse_bls_qc_if_enabled() == Ok`
  (`stellereum/src/bls.rs:515-520`), `QcBlsConfig.enabled == false`, votes stay
  64-byte plain Ed25519 (`stellereum/tests/bls_qc_compat_tests.rs:503-514`),
  certificates carry no envelope and verify through the Ed25519 quorum
  (`:612-630`). Note the asymmetry: `bls_pop_tests` also shows `"yes"` counts as
  OFF for the POP gate while `bls_qc` tests show `"yes"` as OFF for the QC gate —
  both are OFF, consistent; only the literal lists in code are authoritative.
- Post-activation rollback (AFTER a flag-day height with finalized blocks) is NOT a
  restart: it is a pre-activation snapshot + binary rollback at standard flag-day
  cost (`stellereum/docs/PLAN-VRF.md:111-118`, `stellereum/docs/PLAN-POP.md:109-116`).
  No code implements an automatic unwind — UNVERIFIED beyond the plan text.

## 5. Known risks

1. Pre-activation byte-identity is a TEST claim, not a proof. Pinned by: VRF fixed
   vectors + Disabled sweep (`stellereum/tests/vrf_sortition_gate_tests.rs:82-152`;
   pins `PIN_SEED_PARENT_9_2`, `PIN_COMM_PRE_*`, `PIN_VRF_OUTPUT`,
   `PIN_ELECTION_SEED_H1M`, `PIN_COMM_POST_*` at `:27-42`); BLS golden pre-change
   certificate bytes + roundtrip (`stellereum/tests/bls_qc_compat_tests.rs:33-63`,
   `:193-232`); flag-off vote bytes stay 64-byte plain
   (`:503-514`); strict-off registry keeps legacy entries
   (`stellereum/tests/bls_pop_tests.rs:240-299`). If phase 3 threads activation,
   the tests listed in `stellereum/docs/PLAN-VRF.md:36-41` MUST be re-pinned
   deliberately — silent vector drift is the failure mode.
2. VRF proofs are deterministic-Schnorr, NOT audited ECVRF. Stated in-code as the
   SECURITY SCOPE (`stellereum/src/vrf.rs:332-347`): unforgeability without the
   secret + determinism hold, but ECVRF review (ciphersuite separation,
   hash-to-curve, batch rules) has NOT happened. Do not present as ECVRF
   (`docs/specs/02_CRYPTO_AND_PQ.md:16` already warns this).
3. Uniform-height configuration is consensus-critical and unenforced. `VrfActivation`
   is documented as "every node of a deployment must configure the same value, like
   `XpcActivation`" (`stellereum/src/vrf.rs:100-101`); `QcBlsConfig.canonical_keys`
   requires the same registry on every verifier or the aggregate falls back
   (`stellereum/src/bls.rs:650-670`). No code compares peers' heights/registries —
   divergence at activation is a flag-day halt by design (`PLAN-VRF` §4, `PLAN-POP`
   §4), not a handled error.
4. VRF activation plumbing does not exist yet. `vrf_activation_from_env` is dead code
   from consensus's perspective (no caller outside tests); all four live call sites
   pass `Disabled + None`. Setting the env var without the phase-3 binary is a
   no-op, and shipping the phase-3 binary without unanimous upgrade forks the chain
   at `H_vrf` (old nodes halt loudly — expected, `PLAN-VRF` §4).
5. BLS QC counting is unsound on the current registry and correctly refused. The
   bare `<ed> <bls>` format has no PoP, enabling rogue-key forgery
   (`stellereum/src/bls.rs:492-514`); the gate must be DELETED only when replaced
   by the PoP-conditional check, never weakened (`stellereum/docs/PLAN-POP.md:24`
   bright line). The `HybridCertificate` height gate (`stellereum/src/bls.rs:52-57`,
   `:428-435`) must not be mistaken for QC activation.
6. Registry parsing is warn-and-skip, not fail-closed at load. A typo'd registry
   yields an empty/partial map + warnings, then per-certificate fallback to Ed25519
   (safe direction for liveness, but silent BLS-power loss). Meter with
   `BlsRegistryStats` / `bls_registry_migration_counts`, not with startup exit codes
   (only the QC flag refuses at startup).
7. Secret hygiene: `VrfSecret` and `QcBlsConfig.local_vote_seed` are zeroized on drop
   (`stellereum/src/vrf.rs:223-227`, `stellereum/src/bls.rs:586-599`) and the config
   `Debug` redacts the seed (`stellereum/src/bls.rs:573-585`); `BlsSecretKey` is
   deliberately not `Clone`/`Debug` (`stellereum/src/bls.rs:59-78`). Cloned configs
   still copy the seed (`stellereum/src/bls.rs:566-570` comment) — keep them
   short-lived and out of logs/RPC. Counter atomics use `Relaxed` ordering
   (`stellereum/src/vrf.rs:584-591`, `stellereum/src/bls.rs:1031-1057`): fine for
   metering, not a synchronization primitive.
8. UNVERIFIED items: live-network RPC/log verification hooks for VRF activation and
   PoP migration (§3); exact `H_vrf` / `H_bls` values and governance announcement
   procedure (no heights are scheduled in code); remote-signer VRF proof transport
   (specified only, `PLAN-VRF` §2 row 6).

## 6. Exact wiring reference (file:line)

- `stellereum/src/vrf.rs:87` env name; `:96-150` gate type + parse; `:467-473`
  election seed; `:452-459` registry-bound mint; `:484-503` beacon; `:517-541`
  threshold; `:588-591` meter.
- `stellereum/src/consensus.rs:839-855` un-gated wrapper (pins `Disabled`);
  `:871-946` gated committee; `:967-993` gated seed; `:2450-2458`, `:2755-2763`,
  `:2856-2864` pinned live call sites.
- `stellereum/src/bls.rs:52-57` BLS height helper; `:428-435` hybrid format gate;
  `:470-481` env names; `:486-490` PoP flag; `:515-534` QC refusal; `:545-547`
  flag literals; `:605-648` `from_env`; `:873-939` v2 parse; `:959-1025` strict
  parse; `:1047-1057` migration counters.
- `stellereum/src/main.rs:2599-2616` XPC pattern (VRF has no equivalent);
  `:6920` `Commands::Run`; `:7095-7101` BLS QC startup gate.
- Specs: `docs/specs/02_CRYPTO_AND_PQ.md:12-16,40-41` (BLS no-PoP gap, VRF gated
  status); `stellereum/docs/PLAN-VRF.md` (phases, §2 breaking surface, §4
  activation, §7 rollback); `stellereum/docs/PLAN-POP.md` (same structure).

## 7. Test results (paste)

Command (run in `stellereum/`):

`cargo test -p stellereum --test vrf_sortition_gate_tests --test bls_pop_tests
--test bls_qc_compat_tests --test bls_tests`

Result: 35 passed, 0 failed.

```text
Running tests/bls_pop_tests.rs (target/debug/deps/bls_pop_tests-34909edeb54b0e0c)
running 6 tests
test bls_qc_startup_refusal_is_unchanged ... ok
test pop_missing_refused_under_strict_gate ... ok
test default_off_path_still_accepts_legacy_registry ... ok
test pop_valid_accepts_under_strict_gate ... ok
test pop_garbage_refused_under_strict_gate ... ok
test rogue_key_scenario_fails_closed ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Running tests/bls_qc_compat_tests.rs (target/debug/deps/bls_qc_compat_tests-c4b8acdbb2c00eab)
running 11 tests
test vote_envelope_roundtrip_and_flag_off_bytes_unchanged ... ok
test certificate_roundtrip_keeps_the_envelope_intact ... ok
test new_augmented_certificate_decodes_under_old_layout_and_passes_legacy_verify ... ok
test golden_old_certificate_decodes_and_verifies_under_new_code ... ok
test marker_id_counts_for_nothing_and_legacy_skips_it ... ok
test bls_path_ignores_a_garbage_ed25519_list ... ok
test strict_bls_path_rejects_tampered_insufficient_and_mis_bound_aggregates ... ok
test vote_set_certificate_attaches_and_verifies_end_to_end ... ok
test bls_only_certificate_fails_closed_under_old_code_and_flag_off_new_code ... ok
test mixed_bls_and_ed25519_sides_do_not_fork ... ok
test any_bls_failure_falls_back_to_the_ed25519_list ... ok
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Running tests/bls_tests.rs (target/debug/deps/bls_tests-a2690f650923e8f5)
running 14 tests
test test_empty_aggregate_is_refused ... ok
test test_signer_bitvector_downtime_tracking ... ok
test test_out_of_range_signer_is_refused ... ok
test test_key_from_seed_is_deterministic ... ok
test test_aggregate_with_zero_signed_participants_is_refused ... ok
test test_soft_fork_activation_height ... ok
test test_public_key_and_signature_round_trip_bytes ... ok
test test_duplicate_signer_in_aggregate_is_refused ... ok
test test_rogue_key_attack_needs_the_bitvector ... ok
test test_aggregate_verifies_only_for_the_exact_participant_set ... ok
test test_single_bls_sign_and_verify ... ok
test test_bitmask_oversize_and_handbuilt_identity_fail_closed ... ok
test test_bls_aggregate_signatures_n_validators ... ok
test test_aggregate_is_one_signature_regardless_of_signer_count ... ok
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Running tests/vrf_sortition_gate_tests.rs (target/debug/deps/vrf_sortition_gate_tests-f0d205a2d9164f11)
running 4 tests
test post_activation_uses_vrf_seed ... ok
test unverified_vrf_proof_refuses ... ok
test pre_activation_output_byte_identical_to_today ... ok
test determinism_across_repeated_runs ... ok
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

No test-only fixes were needed. No `src/` logic was changed. If a failure appears
later, diagnose root cause at `file:line` and report without changing consensus
logic; test-only corrections require proof the test (not the gate) is wrong.

## 8. Clippy gate (report only)

`cargo clippy -p stellereum --all-targets -- -D warnings` → `Finished dev profile`,
0 warnings, 0 errors. No `--fix` was run.
