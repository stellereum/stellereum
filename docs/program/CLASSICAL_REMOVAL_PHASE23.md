# CLASSICAL REMOVAL — PHASE 2 + PHASE 3 FLAG-DAY DESIGN (binding)

Scope: the 25 pure-PQ holes in `docs/CLASSICAL_INVENTORY.md` (read first).
Phase 1 (test-only/dead-code/BLS) is out of scope here.
Rule: NEVER modify existing files for this design; this doc is NEW-FILE-ONLY.

Status: DESIGN (no code, no live ops). Any H below is PROPOSED, not scheduled.

## §0 Coverage map (25/25 inventory holes)

- Phase-2 table (P2-1..P2-17): all §D wallet/RPC/default holes (4/4) + all
  app-verifier §C holes gated (contract, contract_source, oracle, bridge) +
  gate-first (no deletion) for slash/MEV/Ristretto/light-quorum/VRF-adjacent.
- Phase-3 table (P3-1..P3-11): deletion + re-ceremony for every hole,
  incl. the 8 gate-first rows from Phase 2.
- Never-remove list (inventory §"MUST NEVER") respected throughout: rotation
  ed-announcement stays (`pq_registry.rs:594-604`); refusal gates stay
  (`bls.rs:546`, `main.rs:7576`, `sharding.rs:3407`, `mempool.rs:1846`,
  `state_engine.rs:113,155`); legacy-draw fallbacks stay until H
  (`consensus.rs:1098-1147`); identity formats stay until re-ceremony.

## §1 PHASE 2 — code-level defaults + pure-PQ gates (NO consensus risk)

Principle: mirror `zkml.rs:845-850,936-939` (pure-PQ gate inside the
verifier, fail-closed). No height, no wire change: behavior changes ONLY
when `is_pure_pq_enforced()` (`post_quantum.rs:71`, `STELL_PURE_PQ=1`)
is already on — and in pure-PQ mode the mempool/verify path already refuses
classical (`sharding.rs:3407,3416`, `mempool.rs:1846`), so gating these
call sites cannot fork the chain. Migration shape per row is either
PQ-first-write (new artifacts are PQ; old still read) or hard cut at the
CLI default (scripts must opt back explicitly).

| ID | Current (file:line) | Target | Migration | Test to prove it | Risk |
|---|---|---|---|---|---|
| P2-1 | `wallet.rs:505-506` `from_seed` builds `SigningKey` (ed default); address = ed pubkey | PQ-first constructors (Falcon default; ed only via explicit `unbound_legacy_*`-style hatch, cf. `wallet.rs:614-617` precedent) | PQ-first-write | New: `from_seed` returns Falcon address; old test `wallet.rs:988` updated + compat pin for ed hatch | low — wallet-local, no wire |
| P2-2 | `wallet.rs:548-654` `create_*` → `Transaction::sign` (`sharding.rs:2485`); bound variants exist (`:621-640`) but are not the default | `create_bound_*` becomes the default; unbound `create_*` warns + meters (`stell_unbound_tx_total`, `metrics.rs:144`) | dual-write → default flip | `bound_envelope_wrong_chain_fails` passes; unbound emits metric (`tests/vp2_verify.rs:725,753` pattern) | low — warn+meter precedent exists (chain-binding phase 1) |
| P2-3 | `main.rs:6921-6922,6969-6970` `--scheme default_value="ed25519"`; loader `main.rs:739-778` | default `falcon` (explicit `--scheme ed25519` still works, loud warn) | hard cut at default | CLI test: no `--scheme` → Falcon envelope; `--scheme ed25519` works with warn | med — breaks operator scripts assuming ed25519; reason: default change, not consensus |
| P2-4 | `stell-wallet/src/client.rs:601-687` stealth send (Schnorr-stealth), `:763-933` ed sign fns; `use` at `:15` | PQ-first-write in wallet client; stealth kept working until P3-5 re-ceremony (classical ciphertext still decryptable) | PQ-first-write | wallet e2e test: new sends verify under `STELL_PURE_PQ=1` | low — client-side |
| P2-5 | `stellereum-sdk/src/lib.rs:32,78-114` caller-picks-scheme key ctors (default-risk) | docs + ctor rename so the no-arg path is Falcon; ed ctor explicitly named | PQ-first-write | sdk test: default ctor yields `PqScheme::Falcon512` (`post_quantum.rs:125-141`) | low — SDK-side |
| P2-6 | `contract.rs:1346-1389` WASM host `ed25519_verify` precompile (no gate) | gate on `is_pure_pq_enforced()`: return `0` (false) in pure-PQ unless contract allowlisted; PQ-verify host fn is a P3/lead follow-up (name TBD — do NOT invent) | hard cut in pure-PQ only | `test_host_ed25519_verify_valid_and_invalid` (`contract.rs:2562`) + new pure-PQ test: returns 0 | med — contracts using the precompile break under pure-PQ until migrated; reason: app-layer, deterministic per node |
| P2-7 | `contract_source.rs:290-296` `verify_register_signature` ed-only; called from `rpc.rs:7008` | accept Falcon/Hybrid registration sig when `is_pure_pq_enforced()`; ed path kept otherwise | dual-read | register with Falcon key verifies; ed still verifies when not enforced | low — registration-time only |
| P2-8 | `oracle.rs:129-148` ed `sign`, `:151-163` `verify`, `:242` admit (`commit_feed`), `:622` pull-verify (UNVERIFIED line — inventory claim, re-grep before coding) | PQ publisher keys: `verify` tries registered PQ key first, ed only when not enforced; admit (`:242`) refuses ed-signed feeds in pure-PQ | dual-read → hard cut in pure-PQ | feed signed by Falcon commits; ed-signed feed refused under `STELL_PURE_PQ=1` | med — oracle operators must rotate publisher keys; reason: no consensus change, but liveness of price feeds depends on operator action |
| P2-9 | `bridge.rs:564-594` `verify_quorum_signatures` ed-only; callers `:793,:1368,:1606`, adapters `bridge_adapters.rs:657,1045,1070` | PQ-aware quorum verify (per-signer scheme from committed `validator_pq_keys`, cf. `staking.rs:953`); ed only when not enforced | dual-read | quorum of Falcon sigs verifies; mixed set counts correctly | med — bridge operators re-key; reason: same as P2-8 |
| P2-10 | `staking.rs:2474-2484` `get_pq_key` falls back to `Ed25519(validator_id)` | GATE-FIRST: when enforced and no PQ key registered → return `None` (caller fail-closes) instead of ed fallback. NO deletion yet (P3-2) | gate (no migration; unregistered validators already unslashable-by-PQ — surfaces as loud WARN) | pure-PQ test: unregistered validator → `None`, no ed key material | low — pure-PQ only; non-enforced path byte-identical |
| P2-11 | `staking.rs:2694-2700` + `svm.rs:1024-1026` PQ-equiv evidence ed fallback | GATE-FIRST: refuse ed-scheme evidence when enforced (`Err(InvalidSignature)` path already exists, `staking.rs:2736`) | gate | pure-PQ test: ed-fallback evidence refused; Falcon evidence slashes | low — same reasoning as P2-10 |
| P2-12 | `consensus.rs:394-432` `verify_proposer_signature` ed fallthrough (`:432`) | GATE-FIRST: when enforced, skip the `:432` ed fallthrough (return false unless Falcon path hit) | gate | pure-PQ test: ed-only proposal fails `verify_proposer_signature` | low — enforced-mode only; mirrors `consensus.rs:1646` audit pattern |
| P2-13 | `mev.rs:500-517` `commit_blind_round` ed sign, `:580-604` `verify_round_commitment` ed, `:686-734` `commit_block_order`/`verify_block_order` | GATE-FIRST: refuse ed commitments when enforced; PQ commitment scheme is P3-6 follow-up | gate | pure-PQ test: ed blind commitment refused | low — mempool-local pipeline (`mev.rs:611-624`) |
| P2-14 | `mev_epoch.rs:1458-1492` `OrderCommitment::sign/verify` ed (`:1486-1491`) | GATE-FIRST: refuse ed order commitments when enforced; DKG transport (`:1060-1103` X25519) untouched until P3-6 | gate | pure-PQ test: ed order commitment `verify()` errs | low — same as P2-13 |
| P2-15 | `crypto_privacy.rs:212-294` Ristretto Schnorr sign/verify (stealth auth, §9) | GATE-FIRST for new: fresh shielded notes SHOULD be PQ (follow-up scheme); existing notes keep verifying (no fund lock). Refusal of NEW classical notes when enforced | PQ-first-write (new notes) | pure-PQ test: new classical stealth auth refused; old note still spends | med — wallet/UX flow change, no consensus fork (enforced-mode only) |
| P2-16 | `light_client.rs:582-620` `verify_validator_quorum` ed `verify_strict` (`:607`), `:624-628` `sign_with` ed | GATE-FIRST: refuse classical-only quorums when enforced; `sign_with` gains Falcon variant (follow-up), ed kept otherwise | gate | pure-PQ test: ed-only header quorum refused; Falcon quorum accepted | med — light clients must ship PQ keys + checkpoints re-anchored; reason: off-chain verification, no chain fork |
| P2-17 | `zkml.rs:431-432` `default_scheme()=Ed25519`, `:497` legacy default pair | fail-closed serde: require explicit scheme (no silent Ed25519) | hard cut (version the envelope) | old bytes without scheme fields fail to parse; explicit-scheme bytes pass | low-med — old serialized grants without scheme stop parsing; reason: explicit versioning |

Phase-2 rollout: land gates behind the EXISTING `is_pure_pq_enforced()`
switch — no new env, no height. Precondition: none beyond current pure-PQ
testnet practice (`scripts/local-cluster.sh:174` sets `STELL_PURE_PQ=1`).

## §2 PHASE 3 — flag-day protocol (consensus + transport + identity)

### 2.0 H-shape (chosen — mirrors `STELL_VRF_ACTIVATION_HEIGHT` precedent)

New env `STELL_PQ_ONLY_HEIGHT` (PROPOSED name — lead decision, NOT an
existing var). Shape copied from `vrf.rs:128,162-216`:

- `Disabled` default (unset/empty/garbage → `Disabled`,
  cf. `vrf.rs:198-215`); `FromHeight(H)` arms refusal for heights `>= H`
  (`is_active_at`, cf. `vrf.rs:179-184`).
- Startup carry + log, cf. `main.rs:3096-3105`: `ARMED from height H …`
  vs `inactive …`. Consensus-visible: EVERY node MUST configure the same H
  (cf. `vrf.rs:163-167`).
- Verify/attribution rule mirrors `vrf_output_for_cert`
  (`consensus.rs:1123-1147`): pre-H → legacy behavior (seal/flag not even
  read, byte-identical); at/above H with registry-known keys → PQ-only;
  at/above H with missing registry/unknown key → legacy fallback ONLY
  during the mixed-net window (see §2.3), then refuse.
- Rollback mirrors `VRF_ACTIVATION_PLAN.md:111-130` + `PLAN-VRF.md:117`:
  pre-H = unset env + restart (no state to unwind); post-H with finalized
  blocks at/above H = pre-activation snapshot + binary rollback at
  standard flag-day cost (no code unwinds it).
- Why this shape: `STELL_VRF_ACTIVATION_HEIGHT` (`vrf.rs:128`),
  `STELL_XPC_ACTIVATION_HEIGHT` (`scripts/local-cluster.sh:41,165`,
  `main.rs:2723` pattern), `STELL_CHAIN_BIND_ACTIVATION_HEIGHT`
  (`docs/PLAN-BINDING.md:56`, `main.rs:3072-3080`) all use it; operators
  already know the drill.

### 2.1 Preconditions (ALL must hold before H is even proposed)

1. 100% of voting power runs the Phase-3 binary (version poll;
   `stell_build_info` labels, `metrics.rs:125,1145-1154`).
2. 100% of voting power has identical `STELL_PQ_ONLY_HEIGHT=H` (config
   attestation per node — no code compares peers' heights).
3. 100% of voting power registered with Falcon keys in every verifier's
   committed `validator_pq_keys` (`staking.rs:953`, digest-pinned
   `commitment.rs:1014-1031`) — readiness = bindings for 100% of power.
   Gate on registry-coverage metric (FOLLOW-UP — no such metric exists;
   closest existing: `stell_validator_set_size/power/quorum`
   `metrics.rs:105-110`, `stell_getValidators` fragile flag
   `staking.rs:776,2025`).
4. VRF secret provisioned on every locally-signing validator; remote-signer
   deployments excluded until P3-3 lands (cf. `VRF_ACTIVATION_PLAN.md:70-73`).
5. PQ transport ready signal per node (FOLLOW-UP metric; until then:
   operator checklist attestation — new `node.yaml` + PQ `identity.pq` +
   DNS TXT staged, §2.4).
6. Rollback snapshot taken immediately pre-H; rollback command rehearsed.

### 2.2 The H activation (what changes at H, per work item)

| ID | Deletion / ceremony (file:line) | Post-H behavior |
|---|---|---|
| P3-1 | ed-free votes: `consensus.rs:1589-1598` `Vote::sign` always-ed arm, `runtime.rs:5804-5836` `sign_bytes`/`make_vote`, verify arms `consensus.rs:1642-1778` ed branches | votes carry PQ only; ed-only votes refused at all heights `>= H` |
| P3-2 | PQ-only slashing: delete `staking.rs:2480-2481` fallback, `:2697-2700` fallback, `:2321` `a.verify()\|\|b.verify()` ed path, `consensus.rs:432` fallthrough, `svm.rs:1025-1026` fallback | slashing for unregistered validators burns 0 with loud WARN (documented, not silent); registered path unchanged |
| P3-3 | Falcon/Hybrid remote signer (HSM gap `remote_signer.rs:880-885`; ed-only `remote_signer.rs:326,426,454,530,827,933`) | remote signer speaks PQ; `falcon.key` file protections (`node_keys.rs:554-565` pattern) enforced for PQ material |
| P3-4 | VRF ECVRF (`vrf.rs:1359,1397`, classical per `vrf.rs:150-156` `VRF_IS_POST_QUANTUM=false`) → PQ sortition; remove legacy-draw fallback (`consensus.rs:1123-1147`) at H | election is PQ-only at/above H |
| P3-5 | Ristretto removal (`crypto_privacy.rs:8-11,213-294`; `wallet.rs:509-544` stealth derivation) | PQ confidential path only (scheme = lead follow-up); old notes spent via one-time migration window, then refused |
| P3-6 | MEV DKG X25519→PQ-KEM (`mev_epoch.rs:1060-1103`, `stellereum/Cargo.toml:14`); PQ KEM in tree: NONE (inventory §A) — ML-KEM wiring is a lead follow-up | PQ DKG + PQ order commitments only |
| P3-7 | secp256k1 EVM settlement removal (`evm_adapter.rs:797-825`, `k256` use `:26`); admission gate `sharding.rs:3407` STAYS until H (never-remove) | PQ settlement auth or drop EVM-settlement path |
| P3-8 | node identity re-ceremony: `node_keys.rs:627-630` seed→ed+X25519, `keyring.rs:178-181` `id()=blake3(ed_pub)[..20]`, `dns_seeds.rs:113-115` `DiscoveredPeer{ed_pub,x_pub}` | PQ node keys, new NodeId derivation, DNS record version bump; old `identity.key` format / `inf1:` ids / `ed`/`x` TXT fields frozen, not reinterpreted |
| P3-9 | transport: `node.rs:7080-7105` ed-cert `build_tls`, `:7108-7182` `PinnedVerifier`, QUIC KEX via ring/rustls/quinn (inventory `infnode/Cargo.toml:21,22,25,28,29` — re-verify exact lines before coding), `proto.rs:246` frame auth, `:104` X25519 KDF + `node.rs:6806-6870` box/unbox, `mailbox.rs:114-121`, reputation/rewards/config (`reputation.rs:1,8-9`, `rewards.rs:250`, `config.rs:27-28,60-77`), infmail NFT/TON (`web.rs:5598-5622,6640-6649`, `nft/derive.rs:16-20`) — mostly UNVERIFIED line precision, re-grep before coding | PQ-TLS (hybrid-KEM KEX + PQ certs), PQ frame signatures, PQ E2E; old SPKI pins rejected at/above H |
| P3-10 | ed tx ctors deleted (`sharding.rs:2485-2692` `Transaction::sign*` ed arms); `wallet.rs:614-617` legacy hatch closed | chain-bound PQ envelopes only |
| P3-11 | operator defaults hard cut: `--scheme` ed arm removed (`main.rs:754-762`); `identity.key`-only load removed (`main.rs:842-843`, `node_keys.rs:571-638`); devnet `simulator.rs:313 derive_keypair` → PQ | no classical key path remains in the binary |

### 2.3 Mixed-net rules during the window (H announced, not yet reached)

- `height < H`: mixed versions fully interoperable (legacy behavior
  byte-identical; new seals/fields ignored by old binaries or carried
  additively — VRF precedent `VRF_ACTIVATION_PLAN.md:119-126`).
- `height >= H`: upgraded nodes enforce PQ-only; non-upgraded nodes halt
  loudly (expected flag-day halt, NOT a silent fork —
  `PLAN-VRF.md:91` shape). No cross-H979-style silent divergence: refusal
  is loud (`InvalidSignature`/fail-closed `Err`, cf. `staking.rs:2736`).
- Stall criterion: finals-rate drop >20% vs 24h baseline for >30 min, or
  ANY forged-seal-equivalent refusal storm, or two nodes finalizing
  different committees for the same post-H height → halt flag-day,
  compare H + registry hashes, roll back per §2.0 (pre-H: unset+restart;
  post-H: snapshot+binary).

### 2.4 Per-operator re-ceremony checklist (Phase 3)

1. `keys init` (PQ variant — follow-up CLI): generates PQ identity; old
   `identity.key`/`e2e.key` (`node_keys.rs:571-638`) kept read-only for
   pre-H replay, never reused post-H.
2. `node.yaml`: add PQ stanza (key paths, PQ peer pins); `domain:` stays
   (federation `federation.rs:21` pattern) but validator TXT upgraded to
   PQ record version (old `ed_pub`-bound `validator_txt`,
   `federation.rs:149-151`, frozen).
3. Publish new DNS TXT (PQ id + PQ pub); keep old `ed`/`x` TXT until H.
4. Replace TLS pins: distribute new PQ SPKI pins out-of-band; old ed SPKI
   pins (`node.rs:7108-7182` semantics) revoked at H.
5. Register Falcon validator key on-chain (`pq_register_key`,
   `staking.rs:2509-2535`); verify inclusion via `stell_getValidators` /
   `stell_getValidatorStatus` (existing RPCs, `staking.rs:263,776`).
6. Restart with identical `STELL_PQ_ONLY_HEIGHT=H` + registry file;
   confirm startup `ARMED from height H` log (pattern `main.rs:3099-3101`).

### 2.5 Post-H verification (PQ-only proof)

Use EXISTING RPCs/metrics only (grep-verified). Anything else is a
lead follow-up, NOT claimed:

- `stell_getValidators` (+ `fragile` flag, `staking.rs:776,2025`) and
  `stell_getValidatorStatus` (`staking.rs:263`): 100% PQ-keyed set.
- `stell_getFinalizedHeader` / `stell_getFinalizedCheckpoint`
  (`light_client.rs:16`, `light_client_cli.rs:279`): finality keeps
  advancing post-H (alt: `stell_consensus_height`, `metrics.rs:70`).
- `stell_consensus_round` (`metrics.rs:68`) + `stell_nil_rounds_total`
  (`:128`) + `stell_proposer_missed_total` (`:134`): liveness baseline
  holds (VRF-plan §4 telemetry pattern).
- `stell_fork_total` (`:78`), `stell_divergence_total` (`:82`),
  `stell_weak_qc_refused_total` (`:88`): 0 increase across H (no silent
  fork; divergence alarm is the W10.1 precedent).
- `stell_unbound_refused_total` (`:151`): pattern precedent for refusal
  metering — classical-refusal series should read analogously.
- FOLLOW-UPS (do not exist; lead to schedule): PQ-registry coverage RPC
  (e.g. `pq_bindings_registered` a la `VRF_ACTIVATION_PLAN.md:69`),
  classical-refusal counter (per-scheme `refused_total`), PQ-transport
  ready signal (TLS/KEX/certs all-PQ attestation per peer).

## §3 Honest residual list (what stays classical AFTER Phase 3, and why)

1. ed-signed PQ-key rotation announcements (`pq_registry.rs:594-604`) —
   STAYS by design (never-remove): a validator with no PQ key yet can only
   announce via its consensus (ed) key; replacement needs an equally
   compromise-resilient ceremony (lead decision), never bare deletion.
2. Hybrid signatures' ed half (`post_quantum.rs:141,519,542-548`) — STAYS:
   Hybrid IS dual by definition; removing ed from Hybrid = deleting Hybrid.
3. TLS CA roots / WebPKI chain-of-trust — RESIDUAL: even with PQ-KEM KEX +
   PQ certs, any path that chains to public CA roots verifies classical
   (RSA/ECDSA) signatures. Full fix = private PQ PKI (lead/org decision).
   (Stack: `rustls`+`ring`+`quinn`+`native-tls`,
   `docs/CLASSICAL_INVENTORY.md:24-27`.)
4. DNSSEC + DNS-over-HTTPS resolver trust (`federation.rs:11`,
   `dns.google`) — RESIDUAL: DNSSEC signatures are classical; a
   resolver/parent-zone compromise redirects discovery (mitigated only by
   pinned-key trust anchors, `federation.rs:191-211` pattern).
5. Hardware RNG / CPU TRNG trust (`OsRng` call sites: `mev_epoch.rs:1100`,
   `crypto_privacy.rs:217`; symmetric use is Grover-only and FINE) —
   RESIDUAL only in the supply-chain sense: a backdoored TRNG breaks
   everything regardless of PQ. No code fix; procurement assumption.
6. HSM/KMS firmware + remote-signer transport TLS (`remote_signer.rs:73-78`
   `https_only` guidance) — RESIDUAL: HSM-internal algorithms and the
   signer link's TLS are vendor/classical-controlled until PQ HSMs ship.
7. Falcon-512 vs NIST ML-DSA agility (`post_quantum.rs:153-157` ML-DSA-44
   DISABLED/refused; `specs/02_CRYPTO_AND_PQ.md:16`) — RESIDUAL risk, not
   classical crypto: the PQ layer itself is non-standard Falcon. Migration
   to ML-DSA is a future ceremony, not this flag-day.

NOT residuals (commonly misread): SHA-2/SHA-3/SHAKE/BLAKE3, AES/ChaCha/
Poly1305, HMAC/TOTP, Argon2id, `OsRng` output use — Grover-only/symmetric,
fine at 256-bit (inventory §scope, lines 5-7).

## §4 REPORT

- Hole count covered: **25/25** inventory holes — Phase 2 gates/migrates
  **17 rows** (P2-1..P2-17; 9 pure defaults/RPC + 8 gate-first for
  slash/MEV/Ristretto/light-quorum/proposer/VRF-adjacent); Phase 3
  deletes/re-ceremonies **all 25** via **11 work items** (P3-1..P3-11).
- H-shape chosen: **`STELL_PQ_ONLY_HEIGHT` (PROPOSED name),
  `Disabled`-default / `FromHeight(H)` env gate with pre-H byte-identity,
  startup ARMED/inactive log, config-attestation uniformity, unset+restart
  pre-H rollback and snapshot+binary post-H rollback** — direct mirror of
  the `STELL_VRF_ACTIVATION_HEIGHT` precedent (`vrf.rs:128,162-216`,
  `consensus.rs:1123-1147`, `main.rs:3096-3105`,
  `docs/VRF_ACTIVATION_PLAN.md:58-130`).
- Residuals: **7** (rotation ed-announcement by design, Hybrid ed half by
  definition, TLS CA roots, DNSSEC/resolver trust, TRNG supply chain, HSM
  transport/firmware, Falcon-vs-ML-DSA agility).
- Lead follow-ups (names NOT invented as existing): PQ-registry coverage
  RPC + metric, classical-refusal counter, PQ-transport ready signal,
  PQ contract-verify host fn, ML-KEM DKG wiring, PQ VRF/sortition +
  PQ confidential + PQ remote-signer schemes, `node.yaml`/DNS/TLS-pin
  PQ record formats, `stell-wallet`/SDK PQ-first API renames.
