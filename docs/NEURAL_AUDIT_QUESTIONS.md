# Neural-audit questions — exact list (code truth, no guessing)

Target: `docs/PQ_CN_VRF_SPEC.md` (701 lines). Assumptions under test: A1 Falcon-512
EUF-CMA (`stellereum/src/post_quantum.rs:1190+`, verified by `:2319`), A2 SHAKE-256
random oracle (NIST-KAT-pinned `:2450`), A3 32-byte OS nonce secrecy per
(validator, epoch). Answer each with PASS/FAIL + file:line or UNVERIFIED.

## 1. CN-VRF soundness (§2 of the spec)

- Q1.1 (§2.1 pseudorandomness): does beta's preimage (`CNVRF_BETA_DST || nonce ||
  alpha || validator_id || epoch_N`, 122 B) give 256-bit pre-reveal hiding under
  A2+A3, with Grover reducing it to ~128 bits — still above the Falcon L1 bar,
  so the hash is not the weak link? Is the ECVRF contrast (Shor-broken,
  inventory §C) stated correctly?
- Q1.2 (§2.2 uniqueness): is it true that randomized Falcon `pi`
  (`post_quantum.rs:2135-2144`, fresh bytes per call) does NOT break uniqueness
  because beta is hashed from the MESSAGE, never from `pi`? Is this the exact
  inversion of the MAYO-combiner failure (`PQ_VRF_FRONTIER_V2.md:246-278`)?
  Confirm: N valid `pi` for one open message ⇒ identical beta.
- Q1.3 (§2.3 nonce reuse across alphas): is one-nonce-per-epoch opened against
  MANY alphas safe under A2 alone (distinct RO queries, committer cannot choose
  chain-determined alphas)? Is the FORBIDDEN case (cross-epoch reuse) actually
  refused by epoch binding + guard 4a (`VERIFY` §1.6)? Is first-committed-wins
  (§3.2) the correct resolution for double-commit (ignored, never slashed)?
- Q1.4 (§2.4 commit-hiding): does the N−1 commit / N use lookahead rule
  actually precede alpha existence (`sortition_seed(parent_hash_h,h,r)`,
  `consensus.rs:1059`)? Quantify the residual: pre-existing proposer parent-hash
  grind (`consensus.rs:910-928`, costed in `vrf.rs:1540-1569`) — does CN-VRF
  strictly shrink it (nonce fixed pre-grind, non-proposers lose all influence)?
- Q1.5 (§2.5 abort bias — see also §2 below): is "no reveal ⇒ absent for that
  draw, no late-reveal history rewrite" enforceable given reveal-validity windowing
  (guard 4a + O3)? Confirm deliberate abort must NOT touch the 5%
  `slash_equivocation_verified` arm (`staking.rs:2292`, `EQUIVOCATION_SLASH_BPS=500`
  at `staking.rs:231`) — downtime path only.
- Q1.6 (§2.6 commit-time grinding): is "many candidate nonces at commit time give
  no edge" valid when all epoch-N alphas are unknown at commit (uniform unknowns
  under A2), with abort (§2.5) as the single unified residual?
- Q1.7 (§2.7 fork safety + replay): do different parent hashes ⇒ independent
  betas (no cross-fork edge), identical parents ⇒ identical beta (agreement, not
  bug)? Are cross-epoch replay (epoch in all preimages + guard 4a) and cross-chain
  replay (`chain_id` + guard 4b vs `consensus_chain_id()`, `consensus.rs:63`)
  both refused fail-closed?
- Q1.8 (§2.8 nonce-leak blast radius): is early-leak impact bounded to
  pre-reveal ticket knowledge only (no forgery without the Falcon sk per A1, no
  retrospective change per §2.2), sized by the O3 reveal window?
- Q1.9 (§2.9 rotation interplay): does recovery reduce exactly to the existing
  PQ rotation lifecycle (`pq_announce_rotation`/`pq_apply_due_rotations`,
  `staking.rs:2547,2605`; delay `PQ_ROTATION_DELAY_HEIGHTS = 7_200`,
  `pq_registry.rs:97`; depth `PQ_KEY_HISTORY_LIMIT = 2`, `pq_registry.rs:106`;
  verifier reads `pq_active_key` at draw height, `staking.rs:2630`)? Is the
  7,200-height compromised-key window identical to today's vote-signing residual?

## 2. Abort economics (adversarial pricing)

- Q2.1: price one skipped draw exactly: `note_missed_heights` (`staking.rs:2784`;
  `DOWNTIME_MISS_THRESHOLD = 10`, `staking.rs:237`) charged via
  `apply_downtime_slash_with_set` (`state_engine.rs:7083`): 1/10th of a 0.1% slash
  (`DOWNTIME_SLASH_BPS = 10`, `staking.rs:235`) + jail progress (`cooldown = 100`,
  `staking.rs:240`) + forfeited election chance. Sustained selective abort ⇒
  full downtime ejection (attack self-terminates). Is this price sufficient, or is
  a dedicated CN-VRF miss counter required (spec O5, default reuse-as-is)?
- Q2.2: confirm the production charge path is `state_engine.rs:6437-6468`
  (`apply_block_transition`), NOT the consensus-view primitive
  `apply_downtime_slashes` (`runtime.rs:5983`, tests/hand-built `hc` only) — a
  future implementer wiring charges into the runtime primitive breaks
  determinism (cf. `staking.rs:2235-2243` evidence-must-ride-the-block rule, §3.2).
- Q2.3: is there any profitable abort threshold (e.g. abort only top-decile
  unfavorable draws) where expected bias gain exceeds 1/10th-slash + jail
  accrual? Show the inequality or declare it UNVERIFIED.

## 3. Commit-reveal parameters (lead decisions O1–O10, no guessing)

- Q3.1 (O1 epoch): what is `EPOCH_LEN`, and where is the epoch-boundary
  function? Chain reasons in heights/rounds (`consensus.rs:939-955`); spec admits
  no epoch constant is pinned — confirm or supply.
- Q3.2 (O2 combiner): per-draw beta consumption vs beacon-chained seed
  (`beacon_next`, `vrf.rs:1492`)? Who publishes the winning beta per height, and
  what is the missing/forged-reveal fallback (legacy draw per
  `vrf_output_for_cert` matrix `consensus.rs:1123-1147`, or stall)?
- Q3.3 (O3 reveal timing): must reveals land BEFORE the draw height
  (lead-time) or alongside the block (self-reveal)? Size the §2.8 leak bound.
- Q3.4 (O4 vehicle): new `OpCode` vs block-carried section (§3.2 recommends
  block-carried + staking hooks, mirroring `pq_registry.rs:27-40`)? Wire-format
  decision with canonical order (sorted by (validator, epoch), cf.
  `canonicalize_equivocation_evidence`, `state_engine.rs:7143-7151`).
- Q3.5 (O5 calibration): as-is downtime price sufficient for selective-abort
  bias (see §2), or dedicated counter? Default: reuse-as-is.
- Q3.6 (O6 custody): where do the epoch nonce (reveal path) and Falcon key
  (signer) live separately; file posture `0600` (precedent `vrf.rs:360-421`)?
- Q3.7 (O7 persistence): `CnVrfCommitments: BTreeMap<(ValidatorId, epoch_N),
  CommitmentRecord>` (§3.1) — committed-state home (with `DomainSnapshot`
  fallback, `pq_registry.rs:62-72`) or caller-held side map through audit?
- Q3.8 (O8 SHAKE path): hand-rolled sponge (`post_quantum.rs:657-744`,
  KAT-pinned `:2450`) vs audited SHAKE crate (new dependency, supply-chain call)?
- Q3.9 (O9 genesis): how are validators committed for the FIRST epoch after
  activation (activation height as one-epoch lookahead-0 deadline with
  reduced-hiding caveat, or wait one full epoch)?
- Q3.10 (O10 lookahead): pipeline depth — strictly one live commitment (at most
  one epoch lookahead, §3.1)? Confirm.
- Q3.11 (byte budgets, assert exact): `CommitCarrier ≤ 738 B`, `RevealCarrier
  ≤ 770 B`, `pi == 666 B` (`FALCON512_SIG_LEN`, `post_quantum.rs:109`),
  `nonce/c/beta/alpha == 32 B`; length checks first refusal
  (`post_quantum.rs:423-430` precedent). KAT vectors per spec §4 items 1–9.

## 4. Classical-path leftovers (from `docs/CLASSICAL_INVENTORY.md`, file:line)

Auditor nets: for each row, verdict KEEP-safe / GATE-missing / REMOVE-now.
HOLE = verifies classically even in pure-PQ mode.

- Q4.1 Consensus-adjacent HOLES (§C): `staking.rs:2477-2484` ed fallback for
  unregistered keys; `staking.rs:2698-2730` + `staking.rs:2317`
  (`slash_equivocation_verified`) ed slash paths; `consensus.rs:394-432`
  proposer-slash ed fallthrough; `svm.rs:1005-1070` (`:1025`) on-chain report ed
  fallback; `remote_signer.rs:104-105,326,426,454,530,827,933` ed-only + `:880`
  HSM gap; `vrf.rs:1359,1397` ECVRF (RFC 9381, `VRF_PROOF_LEN = 80`,
  `vrf.rs:148`, output 32 B); `crypto_privacy.rs:8-11,213,232,237,242,277,282,293`
  Ristretto/Schnorr; `mev.rs:50,504-520,596,691` blind commitments;
  `mev_epoch.rs:70-78,1060,1078,1086,1257,1334,1351,1405,1458,1480` ed→x25519 DKG
  + DH seal; `light_client.rs:146,582-615,624` quorum trust; `contract.rs:1377-1386`
  WASM `ed25519_verify` precompile; `contract_source.rs:290-296` registration sig;
  `oracle.rs:6,146,151-162,242,622` feed auth; `bridge.rs:18,564-582`
  (+`bridge_adapters.rs:19`) quorum evidence.
- Q4.2 Wallet/SDK/RPC defaults HOLES (§D): `wallet.rs:15,495-506,548-654,894,925`
  ed-first constructors; `main.rs:6921,6969` CLI `--scheme ed25519 (default)` +
  `:739-780,:823-843` key loading; `stell-wallet/src/client.rs:15,601-687,763-933`
  stealth + sign; `stellereum-sdk/src/lib.rs:32,78-114` caller-picks-scheme;
  `zkml.rs:432,497,646-647` serde-missing-defaults-classical (+`:845-935` gates).
- Q4.3 Identity/transport HOLES (§E, largest blast radius): `node_keys.rs:627-630`
  (`:558` doc); `dns_seeds.rs:113-115` (`:20`); `node.rs:7080-7105` ed TLS certs
  (CN=`inf1-<edhex>`) + `:7108-7182` `PinnedVerifier` (ring `:7167-7181`) +
  `:1126` ephemeral X25519 KEX + `:1139,:1168,:1696,:1987,:6242,:6311,:6394,:1968,:1267`
  handshake/authorship + `:6806-6870` E2E box; `proto.rs:2,:246` frame auth +
  `:104` X25519 E2E KDF; `keyring.rs:3,7,178,257-263` NodeId-from-ed;
  `mailbox.rs:8,10,114-121`; `reputation.rs:1,8-9`, `rewards.rs:250`,
  `config.rs:27-28,60-77`; `infmail nft/lsb.rs:12,56`, `nft/derive.rs:9,11,16-20`,
  `web.rs:5598-5622,6640-6649`; `Cargo.toml` classical crates
  (`stellereum/Cargo.toml:13-14,31,41,49`; `infnode/Cargo.toml:17,21-22,25,28-29,40`;
  `stell-wallet :21-22`; `sdk :15`).
- Q4.4 MUST-NEVER-REMOVE verification (inventory §"MUST NEVER"): dual-stack
  `verify_ed25519` (`post_quantum.rs:554`) + `PqScheme::Ed25519` (Hybrid half +
  rotation alias); ed-signed rotation bootstrap (`pq_registry.rs:594-604` —
  replace ONLY with equally compromise-resilient ceremony, never bare delete);
  legacy-draw/`vrf_output_for_cert` fallbacks (`consensus.rs:1098-1133` — remove
  only after height-gated PQ-election universality); `staking.rs:2477` fallback
  + ed slash paths (gate on registry coverage first); BLS startup-refusal
  (`bls.rs:546`, `main.rs:7576`) + default-OFF until BLS deletion lands;
  `identity.key`/`inf1:`/DNS-TXT/pinned-SPKI formats (flag day = ceremony);
  `sharding.rs:3407` + `mempool.rs:1846` + `state_engine.rs:113,155` enforcement
  (strengthen only); compat pin `consensus.rs:6944` until ed QC path deleted.

## 5. Wire-compat at H (constants verified in tree)

- Q5.1 Handshake H: `PQ_CLASSICAL_REFUSE_AFTER_HEIGHT: u64 = 300_000`
  (`infnode/crates/infnode/src/proto.rs:395`); refuse rule `:400`
  (`height >= H`); enforcement `:701-749` (`:713,716,746` refuse strings);
  env `STELL_INF_PQ_HANDSHAKE` default-ON, explicit `=0` opts out pre-H only
  (`:312,:344-363,:580`); mixed-window WARN + counter `:425-426`; `PeerConfig`
  doc (`config.rs:33`). Is pre-H mixed behavior observably WARN-loud, and is
  post-H refusal fail-closed on both sides (tests
  `pq_handshake_tests.rs:1027,1042,1089,1141`)?
- Q5.2 MEV-transport H: `PQ_TRANSPORT_H_ACTIVATION_HEIGHT: u64 = 10_000`
  (`stellereum/src/mev_epoch.rs:1191`); gate `is_pq_transport_active`
  (`:1198`); default `PREFER_PQ_MEV_TRANSPORT = false` (`:1175`); pre-H PQ-leg
  only on explicit prefer (`:1751-1782`). Does post-H activation change what is
  encrypted vs the documented classical remainders (Ristretto sealed-tx,
  stealth, snapshot-e2e, P2P TLS, RemoteSigner)?
- Q5.3 Identity: `pq-identity.key` auto-gen 0600 (`keyring.rs:285,300,385,449-460`;
  `PQ_IDENTITY_FILE`, `PqKeys::load_or_generate`; tests assert 0600 at
  `pq_handshake_tests.rs:701-706,1203-1208`); NodeId derivation UNCHANGED
  (flag-day separate, `keyring.rs:178`). Is running PQ crypto under a
  classical-derived NodeId sound for the audit window, and what breaks at the
  NodeId re-ceremony (peer pins, DNS-TXT `ed`/`x`, stored mail keys)?
- Q5.4 Rotation: `PQ_ROTATION_DELAY_HEIGHTS = 7_200` (`pq_registry.rs:97`) —
  does every auditor-net scenario (commit/verify/rotate mid-epoch, spec §4
  item 8) hold under a deterministic agreed delay (`pq_registry.rs:94-96`)?

## 6. Out of scope (do NOT audit — reasons)

- BLS / ECVRF — `STELL_BLS_QC=1` hard-refused at startup (`bls.rs:546`,
  caller `main.rs:7576`), default OFF (`bls.rs:501,588`); ECVRF marked classical
  (`vrf.rs:156` `VRF_IS_POST_QUANTUM = false`) and dead for consensus
  (parent-hash draw is THE mechanism, GAPS §1). Reason: classical legacy, no live
  path; code-removal (inventory Phase-1 item 2) is cosmetic, not consensus.
- Workchain / 2PC — parked behind single-predicate gate (`SHARD_REGISTRY_ENV`,
  `sharding.rs:379`; `from_env_or`, `:424`; `is_sharded()`, `:439`; extras-loop
  filter, `main.rs:8111`); default boot single-shard, UNPARK diff = 0 code files
  (`WORKCHAIN_DECISION.md` §§2,5). Reason: unreachable on default path; live-soak
  never happened; auditing it now prices ops risk as code risk.
- CN-VRF wiring — does not exist (spec-only, `PQ_CN_VRF_SPEC.md:1-10`; sandbox
  KATs only behind default-off posture; wiring FORBIDDEN pre-audit per spec §5
  gate 4 + GAPS §4.1 + `PQ_VRF_FRONTIER_V2.md:274-278`). Reason: nothing to
  audit yet; audit the spec (§1 above), not a phantom implementation.
- Transport flag-H exploitation — implemented (Q5.1–Q5.2 constants + tests) but
  live multi-operator exploitation ahead (GAPS §4.2: re-ceremony for external
  operators unwired). Reason: code is reviewable now, production behavior is not
  yet observable; mark findings PROVISIONAL-UNTIL-LIVE.
