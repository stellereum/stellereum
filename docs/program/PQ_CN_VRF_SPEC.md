# Committed-Nonce VRF (CN-VRF) — Specification (HDAE, no implementation)

Status: SPEC ONLY. No code written, no existing file modified. Consensus
wiring is FORBIDDEN before external audit (see §7). This spec uses existing
primitives only: Falcon-512 EUF-CMA signatures + SHAKE-256, zero new
cryptographic assumptions.

Lead-dictated construction: two-phase per-validator verifiable randomness.
COMMIT in epoch N−1, OPEN+PROVE in epoch N. Pseudocode and byte layouts only;
no implementation code.

Prior context: `docs/PQ_VRF_FRONTIER_V2.md` (LaV ~10.3 KB rejected as
brute-force, SPHINCS+ ~8 KB rejected as brute-force, DeuringVRF ~256 B
proof tracked only — unaudited, new OMIP assumption — never for consensus).
Context: `docs/CLASSICAL_INVENTORY.md` (ECVRF is classical/Shor-breakable;
sortition must not consume it on the PQ path).

Primitive sources of truth (byte sizes and API shapes come from these, not
from memory):

- `stellereum/src/post_quantum.rs:103` `FALCON512_PUBKEY_LEN = 897`
- `stellereum/src/post_quantum.rs:109` `FALCON512_SIG_LEN = 666`
- `stellereum/src/post_quantum.rs:2106`
  `FalconKeypair::sign(&self, message: &[u8]) -> Vec<u8>` (randomized:
  fresh OS entropy mixed per signature, `:2175-2187`; two calls with the
  same message and seed produce DIFFERENT valid signatures, `:2135-2144`)
- `stellereum/src/post_quantum.rs:520`
  `verify_pq_signature(scheme, pubkey, message, signature) -> bool`
- `stellereum/src/post_quantum.rs:2319` `verify_falcon512` (FIPS 206 engine)
- `stellereum/src/post_quantum.rs:2450`
  `test_shake256_matches_the_nist_test_vectors` (hand-rolled SHAKE-256
  pinned against NIST KATs — the sponge this spec's hashes assume)
- `stellereum/src/pq_registry.rs:97` `PQ_ROTATION_DELAY_HEIGHTS = 7_200`
- `stellereum/src/vrf.rs:1359`
  `vrf_prove(secret: &VrfSecret, alpha: &[u8]) -> VrfProof`
- `stellereum/src/vrf.rs:1397`
  `vrf_verify(vrf_pk: &[u8; 32], alpha: &[u8], proof: &VrfProof) -> Option<[u8; 32]>`
- `stellereum/src/vrf.rs:148` `VRF_PROOF_LEN = 80` (proof bytes; output 32 B)
- `stellereum/src/consensus.rs:1059`
  `sortition_seed(prev_block_hash, height, round) -> [u8; 32]`
- `stellereum/src/staking.rs:2292` `slash_equivocation_verified`
  (5% burn, `EQUIVOCATION_SLASH_BPS = 500`, `staking.rs:231`)
- `stellereum/src/staking.rs:2784` `note_missed_heights`
  (`DOWNTIME_MISS_THRESHOLD = 10`, `staking.rs:237`;
  `DOWNTIME_SLASH_BPS = 10` = 0.1%, `staking.rs:235`;
  `DOWNTIME_PENALTY_COOLDOWN = 100`, `staking.rs:240`)
- `stellereum/src/state_engine.rs:7083` `apply_downtime_slash_with_set`
  (production downtime path)

---

## 1. Exact byte-level formats

### 1.1 Notation

- `||` = byte concatenation. All integers little-endian (`u64le`),
  matching the consensus envelope convention
  (`height u64le`, `consensus.rs:1151-1156`).
- `SHAKE256(dom || fields, 32)` = 32-byte squeeze of SHAKE-256 over the
  domain tag concatenated with the fields in the stated order.
- `chain_id` = `consensus_chain_id()` (`consensus.rs:63`), `u64`, 8 bytes LE.
- `validator_id` = 32-byte consensus validator id (the bytes that ARE the
  ed25519 identity / the `ValidatorId`; cf. `staking.rs:2474-2485` fallback).
- `epoch_N` = `u64`, 8 bytes LE. Epoch = a fixed run of heights of length
  `EPOCH_LEN` (value TBD by lead — open question O1). `epoch(N)` covers
  heights `[N*EPOCH_LEN, (N+1)*EPOCH_LEN)`.
- `alpha` = 32-byte per-draw input (see §1.5). Fixed 32 bytes wherever it
  appears in a preimage.
- `nonce` = 32 fresh OS-random bytes per (validator, epoch), kept secret
  until reveal.

### 1.2 Domain separation tags (proposed, all ASCII, all distinct by suffix)

| Tag | Value | Used in |
|---|---|---|
| `CNVRF_COMMIT_DST` | `b"STELL_CNVRF_COMMIT_V1"` | commitment preimage |
| `CNVRF_OPEN_DST` | `b"STELL_CNVRF_OPEN_V1"` | Falcon-signed open message |
| `CNVRF_BETA_DST` | `b"STELL_CNVRF_BETA_V1"` | beta derivation |

Rationale: three different cryptographic roles (hiding commitment, signed
statement, pseudorandom output) must never collide even if field layouts
were ever confused. Distinct tags give defense-in-depth on top of distinct
field orders. All tags carry the `STELL_` + `_V1` convention already used
by `VRF_BEACON_DOMAIN` (`vrf.rs:94`), `VRF_BINDING_DST` (`vrf.rs:104`),
`PQ_ROTATION_ANNOUNCE_DST` (`pq_registry.rs:119`). The `_V1` suffix reserves
algorithm agility without breaking deployed parsers (a `V2` tag is a
different preimage, never a re-interpretation).

### 1.3 Commitment preimage (epoch N−1)

```text
commit_preimage =
    CNVRF_COMMIT_DST            (20 B)
 || chain_id                    (8 B, u64le)
 || validator_id                (32 B)
 || epoch_N                     (8 B, u64le)
 || nonce                       (32 B)
                                total: 100 B
c = SHAKE256(commit_preimage, 32)   (32 B)
```

Commit carrier published in epoch N−1 (see §4 for commit/open vehicle):

```text
CommitCarrier {
    validator_id : [u8; 32],
    epoch_N      : u64,          // the FUTURE epoch this commits to
    c            : [u8; 32],     // the commitment above
    sig          : [u8; 666],   // Falcon-512 sig over commit_preimage
                                //   by the validator's REGISTERED PQ key
                                //   (pq_active_key at commit height)
}
```

Order rationale: domain first (streaming parsers reject cross-protocol
bytes early), then the three binding coordinates
(chain → validator → epoch, widest scope to narrowest), then the secret
last (mirrors `pq_rotation_announcement_preimage`: DST || validator ||
scheme || pubkey || effective_height, `pq_registry.rs:578-591`).

### 1.4 Open message + proof (epoch N, per input alpha)

```text
open_message(alpha) =
    CNVRF_OPEN_DST              (18 B)
 || chain_id                    (8 B, u64le)
 || validator_id                (32 B)
 || epoch_N                     (8 B, u64le)
 || nonce                       (32 B)
 || alpha                       (32 B)
                                total: 130 B
pi = Falcon_Sign(sk, open_message(alpha))   (666 B, randomized — EVERY call
                                yields fresh bytes; post_quantum.rs:2135-2144)
beta = SHAKE256(CNVRF_BETA_DST || nonce || alpha || validator_id || epoch_N, 32)
                                preimage total: 18+32+32+32+8 = 122 B
```

Reveal carrier published in epoch N per draw:

```text
RevealCarrier {
    validator_id : [u8; 32],
    epoch_N      : u64,
    nonce        : [u8; 32],
    alpha        : [u8; 32],     // echoed; verifier checks it equals the
                                //   canonical alpha for this draw (see §1.5)
    pi           : [u8; 666],   // Falcon-512 sig over open_message(alpha)
}
```

Order rationale: nonce BEFORE alpha in both preimages. The nonce is the
long-term epoch secret; placing it first means any truncation or
field-confusion analysis always meets the secret before the public input.
`beta` additionally binds `validator_id || epoch_N` AFTER alpha so a beta
can never be transplanted across validators or epochs even if a verifier
skipped a check (fail-closed layering: the verify algorithm in §1.6 checks
anyway).

### 1.5 Alpha source (chosen)

**Chosen alpha:** the canonical per-(height, round) sortition seed already
computed by consensus:

```text
alpha(h, r) = sortition_seed(parent_hash_h, h, r)
            = BLAKE3("STELL_SORTITION_V5" || parent_hash_h || h || r)
```

i.e. `consensus.rs:1059` `sortition_seed`, whose inputs are the committed
parent block hash plus height and round. Verifiers recompute it from the
block header; no new beacon, no new gossip field, no new entropy source.

Why unpredictable at commit time: the commitment is published in epoch
N−1, while `parent_hash_h` for any draw height `h` in epoch N does not
exist until the parent of `h` is proposed — strictly after the commit is
final. The committer therefore cannot know ANY epoch-N alpha when choosing
the nonce (commit-hiding holds information-theoretically until reveal,
computationally via SHAKE-256 hiding afterwards). The residual proposer
grind (a proposer varying the parent hash to re-roll the committee,
documented at `consensus.rs:910-928`) is PRE-EXISTING and UNCHANGED by this
spec: it is the status-quo cost quantified in `vrf.rs:1540-1569`
(`expected_draws_to_*`), and post-commit the committer's nonce is fixed so
parent-hash search cannot be combined with nonce search (§2.5). No new
grinding surface is introduced; everyone-else's tickets become ungrindable.

Authoritative draw call-site today: `derive_sortition_committee`
(`consensus.rs:939`) via `sortition_seed` (`consensus.rs:1059`); the gated
variant is `derive_sortition_committee_gated` / `sortition_seed_gated`
(`consensus.rs:971` / `consensus.rs:1080`). The phase-3 precedent for
feeding a verified output into the same draw is `vrf_output_for_cert`
(`consensus.rs:1123`), whose seed input is
`sortition_seed(&cert.sortition_parent, cert.height, cert.round)`
(`consensus.rs:1142`) — exactly the alpha shape proposed here.

### 1.6 VERIFY (fail-closed, all three checks mandatory, any failure ⇒ refuse)

Pseudocode (check order fixed: cheapest structural checks first):

```text
VERIFY(pk, c_stored, epoch_N, alpha_canonical, nonce, pi):
    1. recompute c' = SHAKE256(commit_preimage(chain_id, validator_id,
                                epoch_N, nonce));  if c' != c_stored → REFUSE
    2. recompute open_message(chain_id, validator_id, epoch_N, nonce,
                                alpha_canonical);   // NOTE: canonical alpha,
                                // not the echoed one
       if Falcon_Verify(pk, open_message, pi) != true → REFUSE
    3. recompute beta = SHAKE256(beta_preimage(nonce, alpha_canonical,
                                validator_id, epoch_N))
    4. additional refusals (replay guards):
       a. epoch_N != current_epoch(height) → REFUSE (cross-epoch replay)
       b. chain_id != consensus_chain_id() → REFUSE (cross-chain replay)
       c. pk != pq_active_key(validator, height) → REFUSE (stale/superseded
          key; height-indexed read, pq_registry.rs:488 precedent)
       d. alpha_echo != alpha_canonical → REFUSE (alpha substitution)
    5. output beta
```

### 1.7 Byte budget (arithmetic from `post_quantum.rs` constants)

Per-reveal gossip bytes (worst case, all refs explicit):

```text
nonce            32
pi (Falcon-512) 666   (FALCON512_SIG_LEN, post_quantum.rs:109)
validator_id     32
epoch_N           8
alpha (echoed)   32
                       ─────
total            770 B < 1024 B (1 KiB)  ✓
```

Per-commitment carrier bytes:

```text
c                32
sig (Falcon-512)666
validator_id     32
epoch_N           8
                       ─────
total            738 B < 1024 B (1 KiB)  ✓
```

Local recomputation only (never transmitted): commitment preimage 100 B,
open message 130 B, beta preimage 122 B, beta 32 B. Comparison point: ECVRF
proof envelope is 80 B proof + 32 B output (`vrf.rs:148`, `vrf.rs:1249`),
but ECVRF is classical and unusable on the PQ path
(`VRF_IS_POST_QUANTUM = false`, `vrf.rs:156`); LaV-class PQ VRF proofs are
~10.3 KB (frontier dossier). CN-VRF's 770 B reveal sits between, using only
deployed primitives.

---

## 2. Security argument (per property: claim + explicit assumption + residual)

Assumption base for the WHOLE spec (no others admitted): (A1) Falcon-512 is
EUF-CMA (the FIPS 206 sampler/signer at `post_quantum.rs:1190+`, verified
by `verify_falcon512`, `post_quantum.rs:2319`); (A2) SHAKE-256 is a random
oracle (hiding + pseudorandomness; sponge pinned by NIST KATs at
`post_quantum.rs:2450`); (A3) each nonce is 32 fresh OS-random bytes,
sampled once per (validator, epoch) and kept secret until its reveal.
Violation of A3 is operator error, bounded in §2.7.

### 2.1 Pseudorandomness

Claim: before reveal, no observer without the nonce can distinguish beta
from random; after reveal, beta is bound to (nonce, alpha) and was
unpredictable to everyone but the committer before that point.

- Assumption: A2 (RO) + A3 (nonce secrecy until reveal). Beta's preimage
  contains 256 secret bits; RO output on an unknown input is uniform.
- Residual: post-reveal beta is PUBLIC (it is the election ticket — public
  by design). Early-leak impact is bounded in §2.7. Quantum note: Grover
  halves the 256-bit preimage strength to ~128 bits — still above the
  Falcon-512 NIST Level 1 bar, so the hash is not the weak link. (Contrast
  with ECVRF, broken end-to-end by Shor — inventory §C.)

### 2.2 Uniqueness-per-commitment

Claim: for a fixed commitment `c` (hence fixed nonce, binding §2.3) and a
fixed (key, alpha), there is exactly ONE beta that verifies.

- Mechanism, not assumption: `VERIFY` recomputes beta deterministically
  from (nonce, alpha_canonical, validator_id, epoch_N). Falcon signatures
  are RANDOMIZED (`post_quantum.rs:2135-2144`: same message signs to
  different `pi` each call), so `pi` is NOT unique — but `pi` is only a
  WITNESS. Uniqueness lives in beta, which does not depend on `pi` bytes.
  Any number of valid `pi` for the same open message recompute the SAME
  beta. This is the exact inversion of the MAYO-combiner failure
  (frontier Card 5 / §246-278: signature non-uniqueness ⇒ output
  grindability); here signature malleability is harmless because the output
  is hashed from the MESSAGE, not the signature.
- Assumption: A1 (a forged `pi` for an uncommitted nonce must not verify).
- Residual: NONE on uniqueness given A1+A2. Uniqueness is per
  (commitment, alpha), not per key globally — by design (see nonce reuse).

### 2.3 Nonce reuse across alphas — ALLOWED by design, proof of safety

Claim: one nonce may (and SHOULD — one commit covers the epoch) be opened
against MANY alphas (every slot/round draw of epoch N). This is safe.

- Proof sketch: betas for distinct alphas are distinct RO queries
  (`...|| nonce || alpha_1 ||...` vs `...|| nonce || alpha_2 ||...`).
  Under A2, outputs for distinct inputs are independent uniform strings:
  knowledge of beta_1 gives zero advantage in predicting beta_2 (RO
  independence), and the committer gains nothing by "choosing" alphas —
  alphas are chain-determined (§1.5), not committer-chosen. Reuse does not
  leak the nonce either (preimage resistance under A2).
- What is FORBIDDEN: nonce reuse across EPOCHS (epoch_N is in all three
  preimages; a reused nonce in epoch M≠N fails check 1 because the stored
  commitment for M differs, and fails guard 4a). One commitment = one
  epoch = one nonce. Double-commit (two `c` for one validator in one
  epoch) is resolved by FIRST-COMMITTED-WINS (see §3.2); the second is
  ignored, never slashed (no equivocation — a commitment is not a vote).
- Assumption: A2 only. No signature assumption involved in reuse safety.

### 2.4 Unbiasability / commit-hiding (commit precedes alpha knowledge)

Claim: at commit time (epoch N−1) the committer cannot bias their epoch-N
tickets, because the alphas do not exist yet.

- Mechanism: lookahead rule — commit in epoch N−1, use in N. The alpha for
  draw (h, r) in epoch N is `sortition_seed(parent_hash_h, h, r)`
  (`consensus.rs:1059`); `parent_hash_h` is created by the proposal of h−1,
  which postdates every epoch-(N−1) commitment once the epoch boundary is
  final. At commit, the set of future alphas is information-theoretically
  undetermined (many possible future chains), so no nonce choice can be
  conditioned on them.
- Assumption: A2 (hiding: `c` leaks nothing about the nonce; binding:
  the committer cannot find a second nonce for the same `c` — second
  preimage resistance).
- Residual: the PRE-EXISTING proposer parent-hash grind
  (`consensus.rs:910-928`) persists: a validator who ALSO proposes a
  parent can re-roll alphas AFTER commit. This is status-quo bias with
  status-quo cost (each candidate parent must be a valid proposal; the
  network-anchored quorum, `consensus.rs:921-924`, still gates the
  certificate). CN-VRF strictly shrinks the surface: non-proposers lose
  ALL influence over others' tickets, and a proposer's grind can no longer
  be amplified by nonce choice (nonce fixed pre-grind). Quantitative grind
  bounds carry over from `vrf.rs:1540-1569`.

### 2.5 Abort bias (withhold reveal ⇒ treated absent + slashed)

Claim: a committer who withholds (nonce, pi) for an unfavorable alpha
cannot re-roll; the draw treats them as ABSENT for that slot, and absence
is punished by the EXISTING downtime machinery.

- Mechanism: no reveal ⇒ no beta ⇒ the validator contributes no ticket to
  that draw (fail-closed absence, same as a missed vote). There is no
  "late reveal changes history" path: reveals are valid only in their
  epoch (guard 4a, §1.6) and only before the draw they feed (see O3).
- Assumption: none cryptographic — economic (A4): missing participation
  costs more in expectation than the bias it buys.
- Residual / attacker cost per aborted slot (EXISTING fns, no new slashing):
  absence accrues the standard downtime streak via
  `StakingLedger::note_missed_heights` (`staking.rs:2784`), charged in
  block application through `apply_downtime_slash_with_set`
  (`state_engine.rs:7083`; consensus-view primitive only at
  `runtime.rs:5983`). Calibration from pinned constants: 10 CONSECUTIVE
  misses ⇒ 0.1% burn (`DOWNTIME_SLASH_BPS = 10`, `DOWNTIME_MISS_THRESHOLD
  = 10`, `staking.rs:235-237`) + jail with cooldown 100
  (`DOWNTIME_PENALTY_COOLDOWN = 100`, `staking.rs:240`). So selective abort
  costs 1/10th of a 0.1%-slash + jail progress PER skipped draw, plus the
  forfeited election chance for that draw. Sustained bias (abort every
  unfavorable draw) converges to full downtime ejection — the attack
  self-terminates. Deliberate abort is NOT equivocation (no conflicting
  signed votes), so the 5% `slash_equivocation_verified` arm
  (`staking.rs:2292`) does NOT apply — state this explicitly so a future
  implementer does not mis-wire it; the abort path is downtime-only.
- Open calibration (O5): whether abort-driven absence should ALSO feed a
  dedicated miss counter is a lead decision; default is reuse-as-is.

### 2.6 Commit-time grinding (trying many nonces at commit gives no edge)

Claim: sampling many candidate nonces before committing yields no
selectable advantage.

- Proof sketch: at commit time all epoch-N alphas are unknown (§2.4), so
  the committer evaluates candidate nonces against NO realizable
  objective — every candidate's future betas are uniform unknowns under A2.
  Formally, for any fixed future alpha, beta(nonce, alpha) is uniform over
  nonce choice; maximizing over k nonces gives the same distribution as
  one draw for each INDIVIDUAL future alpha, and alphas cannot be jointly
  optimized without knowing them. The only post-hoc lever is abort (§2.5),
  priced above.
- Assumption: A2 (RO). Note this holds EVEN THOUGH Falcon signing is
  randomized — signing randomness never enters beta.
- Residual: NONE beyond abort bias (§2.5), which is the single unified
  residual for all post-commit strategy.

### 2.7 Fork safety (same nonce on two forks) + replay refusal

Claim: revealing the same nonce on fork A gives no advantage on fork B.

- Mechanism: beta binds alpha, and alpha binds the parent hash (§1.5).
  Forks with different parents produce different alphas ⇒ independent
  betas (RO, §2.3). Forks sharing the identical parent hash at (h, r)
  produce the SAME beta — but then the election input is identical, so
  both forks agree on the ticket; there is nothing to exploit (the ticket
  is public post-reveal on both forks equally).
- Cross-epoch replay: `epoch_N` in all preimages + guard 4a — a reveal
  from epoch N verifies ONLY in epoch N. Refused otherwise.
- Cross-chain replay: `chain_id` in all preimages + guard 4b against
  `consensus_chain_id()` (`consensus.rs:63`). A testnet reveal never
  verifies on mainnet even with identical heights/hashes.
- Assumption: A1+A2. No fork-choice assumption: safety holds fork by fork.
- Residual: an operator who reveals early on fork A makes beta known to
  fork-B observers slightly earlier — same bound as §2.8, no cross-fork
  amplification because neither fork's future alphas leak.

### 2.8 Pre-reveal nonce-leak impact (bounded)

Claim: if a nonce leaks early (operator error, compromised log), the ONLY
consequence is early beta KNOWLEDGE for epoch-N draws — no forgery, no
retrospective change.

- Mechanism: beta is publicly computable from (nonce, alpha); whoever
  holds the nonce can compute epoch-N betas as alphas appear. But they
  cannot forge `pi` without the Falcon secret key (A1), so they cannot
  impersonate the validator's reveal; and they cannot ALTER any beta
  (uniqueness, §2.2). The leak's blast radius is exactly: observers know
  that validator's tickets before the validator reveals them. Since tickets
  become public at reveal anyway, the harm is bounded to the reveal
  lead-time window (see O3 for reveal timing) — no stake effect, no
  slashing confusion, no cross-epoch spill (epoch binding).
- Assumption: A1 holds even when A3 fails (key secrecy ≠ nonce secrecy;
  the Falcon key must live in the signer, the nonce only in the reveal
  path — operational separation is a deployment requirement, O6).
- Residual: targeted timing games (e.g. a leaked ticket tells an attacker
  whether a victim will be elected next slot) — bounded, public-soon
  information, comparable to the existing parent-hash-visibility window.

### 2.9 Key compromise + rotation interplay

Claim: CN-VRF adds no new long-term key material; compromise response is
exactly the EXISTING PQ rotation lifecycle.

- Mechanism: reveals are authorized by the validator's REGISTERED Falcon
  key (`pq_active_key(validator, height)`, `staking.rs:2630`, height-indexed
  via `pq_registry.rs:488`). If the Falcon key is compromised, the attacker
  can sign opens for the CURRENT epoch's committed nonce — but cannot
  rewrite the commitment (first-committed-wins, §3.2) and cannot mint
  tickets for other validators. Recovery = `pq_announce_rotation` +
  `pq_apply_due_rotations` (`staking.rs:2547`, `staking.rs:2605`) with the
  standard exit-window delay `PQ_ROTATION_DELAY_HEIGHTS = 7_200`
  (`pq_registry.rs:97`): the compromised key stays authoritative for the
  delay window (old votes in flight keep verifying under it — same
  reasoning as `pq_registry.rs:85-97`), then the new key takes over.
  History depth `PQ_KEY_HISTORY_LIMIT = 2` (`pq_registry.rs:106`) covers
  late-arriving reveals under the retired key (verifier resolves the key
  AT THE DRAW HEIGHT, never "current head key" — the `pq_active_key`
  contract).
- Assumption: rotation delay honesty (deterministic const, agreed by all
  nodes — `pq_registry.rs:94-96`).
- Residual: during the 7,200-height window the compromised key still
  authorizes reveals — identical residual to compromised vote-signing
  today; CN-VRF neither worsens nor fixes it. The rotation announcement
  itself stays ed25519-signed by design (`pq_registry.rs:594-604`,
  inventory KEEP — never remove: rotation must survive PQ-key compromise).

---

## 3. State machine + integration points (no code; file:line refs)

### 3.1 Where commitments live (registry-adjacent state)

New deterministic map, mirroring the `PqRegistry` precedent
(`pq_registry.rs:250`, `BTreeMap`, never `HashMap`, for identical iteration
on every node):

```text
CnVrfCommitments: BTreeMap<(ValidatorId, epoch_N), CommitmentRecord>
CommitmentRecord {
    c              : [u8; 32],
    commit_height  : u64,        // height that carried the commit (first wins)
    revealed       : bool,       // set once a valid reveal lands (O3 timing)
}
```

Placement: alongside `PqRegistry` (caller-held, threaded through the
staking hooks — NOT embedded in `StakingLedger` until the persistence
wiring lands, exactly the `pq_registry.rs:62-72` posture: hooks mirror
into committed maps, reads do not depend on apply timing). Committed-state
embedding (genesis root untouched until specified) is lead wiring, O7.

Lifecycle per (validator, epoch): ABSENT → COMMITTED (first valid commit
carrier in epoch N−1 window) → REVEALED (valid reveal in epoch N) or
EXPIRED (epoch N ends without reveal ⇒ treated absent, §2.5). No other
transitions. Double-commit in the same epoch: second ignored (not an
offense). Commit for a PAST or CURRENT epoch: refused (backdating rule,
mirroring `ActivationInPast`, `pq_registry.rs:146-149`). Commit for
epoch > N_current+1: refused (at most one epoch lookahead).

### 3.2 Commit/open vehicle: staking-hook calls, NOT a new transaction type

Decision (mirrors the `pq_registry.rs:27-40` "chosen shape" rationale):
registration COULD be a validator-signed key-announcement transaction (new
`OpCode`, new mempool admission, new block-application branch — most
invasive: touches SVM wire enums and every admission path). The hooks in
`StakingLedger` (`pq_register_key`, `pq_announce_rotation`,
`pq_apply_rotation`, `pq_apply_due_rotations`, `pq_active_key`,
`staking.rs:2509-2640`) are the least invasive fit: the commitment state
machine lives in the new module (pure, deterministic, `BTreeMap` order),
membership checks + commitment mirroring live in the ledger, and a future
opcode only needs to (1) verify the carrier signature with
`verify_pq_signature` (`post_quantum.rs:520`) and (2) call the hook —
exactly how `rotate_key` leaves caller-auth to its opcode handler today
(`pq_registry.rs:37-39`).

Determinism constraint (from the equivocation-wiring precedent,
`staking.rs:2235-2243`): commitment/reveal evidence MUST travel INSIDE the
block as verifiable content so every node derives the same store from the
same block. Gossip-observed reveals must NEVER drive state (same reason
`ValidatorRuntime::apply_equivocation_slashes` stays dead:
non-deterministic across nodes). Concretely: commit carriers and reveal
carriers ride block bodies (transaction payload or dedicated
block-carried section — lead choice, O4); block application verifies and
applies them in canonical order (sorted by (validator, epoch), mirroring
`canonicalize_equivocation_evidence` ordering,
`state_engine.rs:7143-7151`).

### 3.3 Verification call-sites (vrf.rs API mirror)

Proposed exact signatures (signatures only — bodies are the implementation
agent's work, post-audit):

```text
cnvrf_commit(sk: &FalconKeypair, chain_id: u64, validator_id: &[u8; 32],
             epoch_N: u64, nonce: &[u8; 32]) -> (CommitCarrier)
// signs commit_preimage (§1.3) with the registered Falcon key.

cnvrf_open(sk: &FalconKeypair, chain_id: u64, validator_id: &[u8; 32],
           epoch_N: u64, nonce: &[u8; 32], alpha: &[u8; 32]) -> RevealCarrier
// signs open_message(alpha) (§1.4). Randomized under the hood
// (post_quantum.rs:2106), but beta is signature-independent (§2.2).

cnvrf_verify(pk: &[u8], commitment: &[u8; 32], chain_id: u64,
            validator_id: &[u8; 32], epoch_N: u64, alpha: &[u8; 32],
            nonce: &[u8; 32], pi: &[u8]) -> Option<[u8; 32]>
// the §1.6 algorithm. Returns Some(beta) on full pass, None fail-closed
// on ANY failure (mirrors vrf_verify's Option-return, vrf.rs:1397-1401).
// pk MUST be the pq_active_key-at-height read (staking.rs:2630), never a
// caller-supplied key.

cnvrf_beta(nonce: &[u8; 32], alpha: &[u8; 32], validator_id: &[u8; 32],
           epoch_N: u64) -> [u8; 32]
// pure beta recomputation (no key). Used by verifiers after pi checks.
```

Byte lengths pinned: `CommitCarrier` on-wire ≤ 738 B, `RevealCarrier`
on-wire ≤ 770 B (§1.7); `pi` is EXACTLY `FALCON512_SIG_LEN = 666`
(`post_quantum.rs:109`); `nonce`/`c`/`beta`/`alpha` are EXACTLY 32 B.
Length checks are the first refusal in every path (the envelope-strictness
precedent: `post_quantum.rs:423-430`).

### 3.4 Election consumption (swap point)

Today: `derive_sortition_committee_gated` (`consensus.rs:971`) draws from
`sortition_seed_gated` (`consensus.rs:1080`), which is the parent-hash seed
unless a registry-verified VRF output is supplied. CN-VRF plugs into the
SAME gate shape: a post-activation election seed derived from verified
betas (e.g. `BLAKE3(domain || beta_h || height || round)` per draw, or a
beacon chain `beacon_next(prev, beta)` per `vrf.rs:1492` — exact combiner
is O2) replaces the `verified_vrf_output` input. The per-draw alpha stays
`sortition_seed(parent_hash, h, r)` (`consensus.rs:1059`); what changes is
that each validator's ticket is their verified beta for that alpha instead
of the shared parent-hash ticket — the same stake-weighted draw machinery,
different (keyed, ungrindable) entropy. The legacy-draw fallback matrix
(`vrf_output_for_cert`, `consensus.rs:1123-1147`: refuse forged, fall back
on missing) is the template for the CN-VRF missing/forged-reveal matrix.
NO wiring lands before audit (§7).

### 3.5 Abort / missing-reveal handling in block application

Missing reveal for a committed validator at draw (h, r) = absence for that
draw. Absence flows into the EXISTING downtime path, charged by:

- `state_engine.rs:7083` `apply_downtime_slash_with_set` (production:
  verifies the QC, builds the signer set, calls `note_missed_heights`,
  debits `STAKING_POOL` by `burned`);
- `staking.rs:2784` `note_missed_heights` (streak accounting; 10
  consecutive ⇒ 0.1% slash + jail);
- `runtime.rs:5983` `apply_downtime_slashes` is the CONSENSUS-VIEW
  primitive only (tests/hand-built `hc`), NOT the production path — a
  future implementer must charge misses in `apply_block_transition`
  (the `state_engine.rs:6437-6468` transition order), never in the runtime
  primitive.

No new slash function, no new BPS constant, no equivocation-arm reuse
(§2.5). If the lead later wants abort-specific calibration, it is a
parameter change to existing thresholds, not a new offense type (O5).

---

## 4. Test plan for the future implementation agent (post-audit only)

All vectors use FIXED seeds/keys/nonces (deterministicKATs). Every case
asserts byte-exact equality or byte-exact refusal (`None` / `Err`, never
"looks plausible").

1. **Determinism:** fixed (sk, nonce, alpha) ⇒ identical `c`, `pi`-witness
   set aside, identical `beta` across 100 runs and across processes.
   (Falcon `pi` bytes MUST VARY run to run — assert non-equality of two
   `pi` for the same message, pinning randomized signing per
   `post_quantum.rs:2135-2144` — while beta stays fixed.)
2. **Binding mutations:** flip one bit in each preimage field (domain,
   chain_id, validator_id, epoch, nonce, alpha) ⇒ commitment mismatch
   (check 1) or signature refusal (check 2) or beta mismatch; assert
   `None` in all 6×2 positions. Truncate/extend every length-pinned field
   by ±1 byte ⇒ refuse.
3. **Signature substitution:** valid `pi` from a DIFFERENT Falcon key over
   the same open message ⇒ refuse (A1 end-to-end through
   `verify_pq_signature`, `post_quantum.rs:520`). Valid `pi` over a
   different alpha with the same nonce ⇒ refuse (check 2 binds alpha).
4. **Cross-epoch replay:** reveal valid in epoch N re-submitted in epoch
   N+1 (same bytes) ⇒ refuse (guard 4a). Commitment for epoch N
   re-submitted as commitment for N+1 ⇒ different `c`, no match ⇒ refuse.
5. **Cross-chain replay:** same bytes with `chain_id` 5757 vs 777 (the
   `sharding.rs:6907-6908` main/alt test pair shape) ⇒ refuse (guard 4b).
6. **Abort path:** committed validator with no reveal for draws
   h..h+9 ⇒ `note_missed_heights` streak reaches 10 ⇒ 0.1% burn + jail
   (assert exact `DOWNTIME_SLASH_BPS` math: `before * 10 / 10_000`);
   single-height absence ⇒ streak+1, zero burn (assert 0, cf.
   `state_engine.rs:6467`).
7. **Fork-reuse:** same nonce revealed under forks with different parent
   hashes ⇒ different alphas ⇒ different betas, both verify under their
   own fork's alpha (assert beta_A ≠ beta_B, both `Some`). Same parent
   hash on both forks ⇒ identical beta (assert equal — agreement, not a
   bug).
8. **Rotation interplay:** reveal verified under key-at-draw-height with a
   rotation announced mid-epoch: pre-effective-height draws verify under
   old key, post-effective draws under new key (`pq_active_key`,
   `staking.rs:2630`; delay `PQ_ROTATION_DELAY_HEIGHTS = 7_200`).
   Superseded-key reveal (history depth 2) verifies; third-rotation-old
   key refuses.
9. **KAT sizes:** assert `CommitCarrier ≤ 738 B`, `RevealCarrier ≤ 770 B`,
   `pi.len() == 666`, `beta.len() == 32` — byte-exact, sourced to
   `post_quantum.rs:103-111`.

---

## 5. Phase gate (binding)

1. **Spec review by lead** (this file). No implementation starts on spec
   comments — spec is amended first.
2. **Sandbox implementation behind default-off flag** (mirroring the
   `VrfActivation::Disabled`-default posture, `vrf.rs:169-175`, and the
   `STELL_VRF_ACTIVATION_HEIGHT` env pattern, `vrf.rs:126`): KATs +
   metering only, no consensus import, no wire change.
3. **EXTERNAL audit REQUIRED** (cryptographer review of §2 + implementation;
   the `docs/PQ_VRF_FRONTIER_V2.md:274-278` combiner warning applies in
   full: no in-house blessing of soundness-critical choices).
4. **Consensus wiring FORBIDDEN before passed audit.** Any wiring PR
   without an audit note fails review (AGENTS.md §7 frozen core; the
   lead's no-unaudited-crypto rule).

---

## 6. Open questions (no guessing — lead decides)

- **O1. Epoch definition.** What is `EPOCH_LEN` in heights, and where is
  the epoch boundary function? The chain today reasons in heights/rounds
  (`consensus.rs:939-955`); no epoch-length constant was pinned in this
  pass. UNVERIFIED whether an epoch concept already exists elsewhere.
- **O2. Election combiner.** Per-draw beta consumption vs. beacon-chained
  seed (`vrf.rs:1492` `beacon_next` precedent)? Who publishes the winning
  beta per height, and what is the missing-beta fallback (legacy draw per
  the `consensus.rs:1123-1147` matrix, or stall)?
- **O3. Reveal timing.** Must reveals land before the draw height (reveal
  lead-time), or alongside the block (self-reveal)? Early-reveal window
  sizes the §2.8 leak bound.
- **O4. Carrier vehicle.** New `OpCode` vs. block-carried section for
  commit/reveal carriers (§3.2 recommends block-carried + staking hooks,
  but the exact envelope is a wire-format decision for lead).
- **O5. Abort calibration.** Is the as-is downtime price (0.1% per 10
  consecutive + jail, `staking.rs:235-240`) sufficient for selective-abort
  bias, or is a dedicated CN-VRF miss counter wanted? Default: reuse as-is.
- **O6. Nonce custody.** Where is the epoch nonce generated/stored
  (validator signer vs. reveal helper), and what is the file-permission
  posture (the `0600` precedent: `vrf.rs:360-421` secret-file loading)?
- **O7. Persistence.** Does `CnVrfCommitments` (§3.1) get a committed-state
  home (with a `DomainSnapshot` fallback per the `pq_registry.rs:62-72`
  precedent), or stay a caller-held side map through audit?
- **O8. SHAKE-256 implementation path.** The tree carries a hand-rolled
  sponge (`post_quantum.rs:657-744`, NIST-KAT-pinned at `:2450`) because
  the Falcon C archive needs it. Should CN-VRF hashes use that module, or
  an audited SHAKE crate (new dependency — supply-chain decision for
  lead)? No new crypto either way (SHAKE-256 is SHAKE-256), but the code
  path matters for audit scope.
- **O9. Genesis/bootstrap.** How do validators commit for the FIRST epoch
  after activation (no N−1 exists)? Options: activation height itself acts
  as the commit deadline for epoch 0 (lookahead = 0 for one epoch, with
  the reduced-hiding caveat documented), or activation waits one full
  epoch. Lead call.
- **O10. Multi-epoch lookahead.** Is committing for epoch N+1 while epoch
  N is active allowed (pipeline depth 1), or strictly one live commitment?
  Spec says at most one epoch lookahead (§3.1); confirm.

---

*End of spec. Total open questions: 10. No implementation code. No
existing file modified. Audit before wiring.*
