# VRF Activation Plan (flag-height rollout — NOT activated, no live ops)

Status: DRAFT plan. `STELL_VRF_ACTIVATION_HEIGHT` is DEFAULT-OFF and no live
network has an activation height scheduled. Phase-3 threading entry points are
BUILT (trailing serde-defaulted `vrf_beacon` seal, pure assembly/verify
variants, `None`→legacy fallback); the LIVE consensus call sites still pin
`Disabled`+`None` (reported gap §2 — threading them is a consensus change and
is NOT done here). Do not set the env on any live stand from this file alone.

Scope lock: env/plumbing verification + activation plan + tests. No
consensus-logic changes, no crypto changes, no live ops. Default-off behavior
stays byte-identical (pinned by tests §6).

Related: `docs/VRF_BLS_ACTIVATION.md` (gate reference + 35-test evidence),
`docs/PROPOSER_REWORK.md` §5 (rollout-shape precedent: local-cluster →
testnet → canary → fleet, with finals-rate / stale-share / view-change
telemetry), `stellereum/docs/PLAN-VRF.md` (phase plan, §4 activation, §7
rollback), tests `vrf_phase3_threading_tests.rs` + `vrf_activation_tests.rs`.

## 1. End-to-end wiring as BUILT (read-only recon)

| # | Link | file:line | State |
|---|---|---|---|
| 1 | Env name | `stellereum/src/vrf.rs:87` | `STELL_VRF_ACTIVATION_HEIGHT` |
| 2 | Parse (trim, drop empty, `parse::<u64>`; garbage → stderr warn + `Disabled`) | `stellereum/src/vrf.rs:132-150` | Built, default-off |
| 3 | Startup read + carry into runtime | `stellereum/src/main.rs:2734-2736` (wrapper), `stellereum/src/main.rs:3026-3051` (carry + log) | CLOSED by this task: `run_consensus_node` binds `vrf_activation_from_env()` once, stores via `ValidatorRuntime::with_vrf_activation` (`stellereum/src/runtime.rs:1678`), then logs `ARMED from height H` / `inactive`. Safe no-op: no live consensus path reads `rt.vrf_activation` yet |
| 4 | Runtime proof seam (secret lives here, mints proof, self-verifies, else `None`) | `stellereum/src/runtime.rs:1693-1740` (`with_vrf_secret_seed`, `vrf_beacon_seal_for`) | Built; default `None` → legacy |
| 5 | Assembly (pure): seal verifies vs registry + outputs match → embed + elect VRF, else legacy `None` bytes | `stellereum/src/consensus.rs:2563-2763` (`certificate_with_parent_vrf`; election `2646-2679`) | Built; legacy alias `certificate_with_parent` pins `Disabled`+`None` (`2527-2541`) |
| 6 | Wire: unsealed → canonical envelope (today's bytes); sealed → `MAGIC \|\| bincode(cert)`; canonical decode → `None`; bincode fallback → seal | `stellereum/src/consensus.rs:3274-3314`, `1159-1261` | Built, byte-identical default-off |
| 7 | Verify/attribution (shared `vrf_output_for_cert` rule: none/pre-activation/missing-registry/unknown-key → legacy; known-key + bad proof/output → REFUSE) | `stellereum/src/consensus.rs:1123-1147`, `2960-3169` (`micro_cert_valid_signers_with_vrf`, `verify_micro_cert_with_vrf`) | Built as entry points |
| 8 | Live verify/attribution call sites | `stellereum/src/consensus.rs:2901-2910` (`pq_path_verify` in `verify_unified`), `3455-3462` (`signers_set`) — both pin `Disabled`+`None` | OPEN gap (REPORTED, not implemented): threading needs runtime activation + a live VRF registry (no loader exists) at every verifier — consensus behavior change |
| 9 | Live assembly call sites (`HeightConsensus` prevote/precommit paths) | `stellereum/src/consensus.rs:4227,4310,4347,4434` via `certificate_with_parent` | OPEN gap (REPORTED): `HeightConsensus::new` carries no activation/registry/seal; threading needs struct + constructor + mint-at-proposal plumbing — consensus change |
| 10 | VRF secret provisioning (no env/file loader; `vrf_secret_seed` default `None`) | `stellereum/src/runtime.rs:657,995` (field/default); no `STELL_VRF_*SECRET*` in `src/` | OPEN gap (REPORTED): needs a secret-file env + `node_keys`-grade loading before any activation; remote-signer deployments can never mint (see §7) |
| 11 | VRF registry distribution (no file/env/RPC loader; no global registry) | `stellereum/src/vrf.rs:292-330` (type only); zero `register()` callers in `src/main.rs` | OPEN gap (REPORTED): verifiers need identical Falcon-bound registries before H; no distribution path exists |

Fallback correctness (proofs absent): `vrf_beacon_seal_for` returns `None`
when `Disabled`/pre-activation/seedless/self-verify-fail (`runtime.rs:1725-1738`);
assembly with `None`/missing-registry/unknown-key compiles legacy
(`consensus.rs:2653-2679`); verify with `None`/ignorable seal uses the legacy
draw (`vrf_output_for_cert` `Ok(None)`); forged seals refuse fail-closed
(`Err` → `false`/`None`). Pinned by the fallback matrix (§6).

## 2. Gaps closed vs open (this task)

CLOSED (safe, default-off-preserving, byte-identical when unset):
- Startup value → runtime carry (`main.rs:3045-3048`): was parsed-and-logged
  but dropped; now stored on the runtime. No live reader yet → zero behavior
  delta. Proven by the unchanged default-off suites (§6).
- Stale comment claiming phase-3 "blocked" updated to name the built entry
  points and the still-pinned live sites.

OPEN (require consensus behavior change — REPORTED, not implemented):
- Gaps 8–11 above. Threading any of them changes elections at armed heights
  (the intended flag-day fork shape: old nodes halt loudly at H, `PLAN-VRF`
  §4). Each needs its own spec + audit + coordinated upgrade; landing them
  silently here would violate the frozen-core rule.

## 3. Flag-height selection criteria (how to pick H)

1. Chain height: pick `H = head + upgrade_window` where `upgrade_window`
   covers binary rollout + registry distribution + soak (see §4). Never a past
   or imminent height; never reuse a height any node already finalized past.
2. Upgrade window minimums (all must hold before H is even proposed):
   - 100% of voting power runs the phase-3 binary (verified by version poll).
   - 100% of voting power has identical `STELL_VRF_ACTIVATION_HEIGHT=H`
     (config attestation per node — no code compares peers' heights).
   - 100% of voting power registered in every verifier's Falcon-bound VRF
     registry (`vrf_bindings_registered` / registry audit per node;
     readiness = bindings for 100% of power, `PLAN-VRF` §“readiness”).
   - VRF secret provisioned on every locally-signing validator (gap 10 open
     until a loader exists — H MUST NOT be scheduled before it lands).
3. Remote-signer deployments excluded until §7 closes (they mint `None` and
   would force legacy fallback at/above H — safe for liveness, but the
   election would not actually switch).
4. Fresh-chain exception: `FromHeight(0)` (genesis-armed) is valid only for a
   NEW chain where every node starts from the same genesis config.
5. Governance: announce H + binary hash + registry hash out-of-band; abort the
   flag-day (not the code) if any criterion regresses before H.

## 4. Rollout order + observe + abort criteria

Order (each stage gates the next; no skips):
1. Local cluster (multi-node, Docker/ideal harness): set `H = head + N`
   (e.g. +500), run past H, confirm sealed certs verify and committees switch
   per `sortition_seed_gated` expectations. Fast-iteration abort allowed.
2. Single testnet node: arm H on ONE node, restart, confirm startup
   `ARMED from height H` log + legacy bytes pre-H (no divergence while
   `height < H` — mixed config is safe pre-H by construction).
3. All testnet nodes: identical env + registry everywhere, cross H together.
4. Observe (minimum one full committee-rotation window past H):
   - finals rate (blocks/hour) vs 24h pre-H baseline;
   - stale-vote share (RX-logged one-round-stale fraction);
   - view-change rate (per `PROPOSER_REWORK.md` §4 precedent: track
     view-changes per finalized height, target ≈3.0/final at tight base);
   - `grace_extends`-class counters where applicable; VRF-specific: seal
     presence rate on post-H certs (expect ~100% once proposers mint), legacy
     fallback rate (expect ~0% except remote-signer/seedless nodes), forged-seal
     refusals (expect 0; any is an incident).
5. Abort criteria (ANY triggers rollback §5 + incident review):
   - finals rate drops >20% vs baseline for >30 min post-H;
   - view-change rate doubles vs baseline for >30 min;
   - stale-share rises >0.10 absolute vs baseline;
   - ANY forged-seal refusal on a post-H cert (fail-closed working = the
     network stalls on forgeries by design — investigate, do not relax);
   - ANY node finalizes a different committee for the same post-H height
     (config/registry divergence — halt flag-day, compare `H` + registry hashes).
6. Live canary only after testnet holds green for ≥1 week; fleet only after
   canary holds ≥1 week. No live ops from this file alone (explicit human order
   required per repo constitution).

## 5. Rollback

- Pre-H rollback (env unset + restart): unset `STELL_VRF_ACTIVATION_HEIGHT`,
  restart. Unset/empty/garbage → `Disabled` (`vrf.rs:137-147`);
  `sortition_seed_gated(..., Disabled, _)` = `sortition_seed` and the gated
  committee runs the identical draw loop (`consensus.rs:980-993`). No state to
  unwind (seal field absent = `None`; registry rows inert metadata).
- Wire compat both directions:
  - Old binary + new cert: unsealed new certs are today's canonical bytes
    (verify unchanged); sealed certs travel as `MAGIC||bincode` — old binaries
    without the seal field fall back to the classical Ed25519 quorum (µQC is
    an accelerator; the full-set path stays authoritative). At small N the
    sealed cert ALSO verifies legacy (full-set committee coincides); at
    diverged draws old nodes refuse the VRF committee (expected flag-day halt,
    not a silent fork) — see matrix §6.
  - New binary + old cert: canonical/JSON old bytes decode to `None` and
    verify legacy even at armed heights with a live registry (pinned §6).
- Post-H rollback (finalized blocks exist at/above H): NOT a restart — it is a
  pre-activation snapshot + binary rollback at standard flag-day cost
  (`PLAN-VRF` §7, `PLAN-POP` §“post-activation rollback”). No code unwinds it.

## 6. Mixed-version matrix (test pins — every cell cited)

| Cell | Expectation | Pinned by |
|---|---|---|
| Default-off (env unset): gated == legacy over sweep | byte-identical schedules | `vrf_activation_tests.rs:115-167` |
| Boundary: below H legacy even with valid output; at/above H verified output switches seed; at/above + `None` falls back | gate decides | `vrf_activation_tests.rs:171-242` |
| Determinism (same key+height ⇒ same proof/output/committee) | pure functions | `vrf_activation_tests.rs:246-301`, `vrf_phase3_threading_tests.rs:512-566` |
| Assembly↔verify agreement post-H (proposer seal → verifier same committee; entropy actually switched) | VRF path engaged | `vrf_phase3_threading_tests.rs:149-208` |
| Pre-H byte-identity (struct + canonical envelope + pinned deterministic-prefix vector) | legacy bytes | `vrf_phase3_threading_tests.rs:212-285` |
| Fallback: None/armed+Disabled/armed+no-registry/unknown-key → legacy verifies; forged proof bytes → assembly legacy BUT verify REFUSES; swapped output → REFUSE; old JSON (field absent) → `None`, verifies legacy at armed H | fail-closed matrix | `vrf_phase3_threading_tests.rs:296-508` |
| H-boundary exact (H-1 seal ignored assembly+verify; H embeds) — NEW | height gate, not presence | `vrf_phase3_threading_tests.rs: activation_boundary_exact_h_minus_one_vs_h` |
| Old WIRE bytes (canonical envelope) verify legacy at armed H with live registry — NEW | new-node + old-cert | `vrf_phase3_threading_tests.rs: old_wire_bytes_verify_legacy_at_armed_height` |
| No-uniqueness (two valid proofs, two outputs; verifier accepts either; election = f(verified output)) | no uniqueness assumed | `vrf_phase3_threading_tests.rs:585-713` |
| Scale divergence (N=65: committees differ; sealed verifies new, REFUSES legacy) | flag-day shape | `vrf_phase3_threading_tests.rs:722-776` |
| Runtime seam (Disabled→None; armed+seedless→None; armed+seeded→mint+self-verify; pre-H→None; `FromHeight(0)` arms genesis) | secret-side fallback | `vrf_phase3_threading_tests.rs:783-841` |
| Small-N sealed cert verifies legacy too (compat) | mixed-version overlap | `vrf_phase3_threading_tests.rs:205-207` |
| Adversarial (forged proofs/PoPs, replay, wrong-key, tampered seed, rogue BLS, mixed envelopes, oversized, boundary heights) | all refuse, no panic | `vrf_bls_adversarial_tests.rs` (9 tests) |
| Pre-change golden bytes / flag-off vote bytes / strict-off legacy registry | wire compat | `bls_qc_compat_tests.rs`, `bls_pop_tests.rs` (see `VRF_BLS_ACTIVATION.md` §7) |

## 7. Remote-signer gap status

OPEN. The remote-signer handle (`ValidatorSigner`/`Signer`,
`remote_signer.rs:861-1000`) is Ed25519-only: it signs vote bytes but cannot
produce VRF proofs (same HSM-gap class as the documented Falcon gap,
`remote_signer.rs:880-885`). `vrf_beacon_seal_for` never consults it and no
VRF material is derived from Ed25519 keys (`runtime.rs:1711-1718`). A
remote-signer deployment with no local VRF seed gets `None` → legacy fallback
(pinned: `runtime_proof_seal_mint…` armed-naked case), so activation would
never actually switch its elections. REQUIRED before scheduling H on such
deployments: a VRF-capable signer (or an approved local-seed provisioning
story with `node_keys`-grade file protections) + the gap-10 loader.

## 8. Audit prerequisites checklist (all must be YES before H is scheduled)

- [ ] Gaps 8–11 (§1) threaded behind spec + audit note + full gate (or H stays
      unscheduled — an armed env with unthreaded verifiers is a no-op, not an
      activation).
- [ ] Secret loader exists (gap 10): env/file name, 0600/0700 + passphrase
      story, zeroize-on-drop held, no getter, no log/RPC exposure.
- [ ] Registry distribution exists (gap 11): identical file on every verifier,
      hash-announced, warn-and-skip audited (typo ⇒ BLS-power-style silent
      fallback, metered by `BlsRegistryStats`-equivalent / binding counters).
- [ ] ECVRF review complete OR the deterministic-Schnorr scope warning
      (`vrf.rs:332-347`) explicitly re-accepted for the flag-day (currently
      NOT audited ECVRF — do not present as ECVRF, `specs/02_CRYPTO_AND_PQ.md:16`).
- [ ] Uniform-`H` enforcement story (config attestation; divergence = loud halt,
      `vrf.rs:100-101`) signed off by operators.
- [ ] Testnet crossed H and held §4 telemetry green ≥1 week; canary ≥1 week.
- [ ] Rollback snapshot taken immediately pre-H; rollback command rehearsed.
- [ ] Gates green at the release commit: `cargo clippy -p stellereum
      --all-targets -- -D warnings` → 0/0; all VRF/BLS/sortition suites green
      (paste outputs in the release record, not here).
