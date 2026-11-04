# VRF Grinding: Measurement + Remote-Signer Closure Design

Status: **measurement + design only — no production crypto changes.**
Scope: `tests/vrf_grinding_measure_tests.rs` (new) + this file. Zero `src/` changes.

## 1. Construction under test

Deterministic-Schnorr VRF (`src/vrf.rs:336-348`, SECURITY SCOPE):

- `vrf_prove` (`src/vrf.rs:499-511`): `s = scalar(seed)`,
  `k = H(secret || seed_input)`, `R = kG`,
  `c = H(R || pk || seed_input)`, `z = k + c·s`,
  `output = BLAKE3(R || pk || seed)`, proof = `(R, z)`.
- `vrf_verify` (`src/vrf.rs:518-546`): checks `zG == R + c·PK` and re-derives
  `output` from the proof bytes. Fail-closed on every tamper class.

### 1.1 Degrees of freedom (exact)

For a fixed `(secret, seed_input)` pair:

| Component | Grinder-controlled? |
|---|---|
| `seed_input` (beacon / `sortition_seed` output, `src/consensus.rs:1059`) | NO — fixed by the chain; the holder cannot change it |
| secret scalar `s` (hence `pk`) | NO as a per-draw variable — fixed per key; key grinding (registering many keys) is one-binding-per-validator-id, Falcon-signed (`VrfBinding`, `src/vrf.rs:240-290`) and publicly visible, so it is not a per-input search |
| challenge `c` / output structure | NO — pinned by verification equations |
| **nonce `k`** | **YES — the entire surface.** `vrf_prove` derives one deterministic `k`, but `vrf_verify` accepts ANY nonzero `k'`: `R' = k'G`, `c' = H(R', pk, seed)`, `z' = k' + c's` always satisfies the Schnorr equation and mints a verifying `output' = BLAKE3(R' \|\| pk \|\| seed)` |

So the grinder's search space is the full 256-bit nonce field: **every fresh
`k'` is one fresh i.i.d.-uniform output candidate at the cost of one scalar
mul + two hashes.** There is no second degree of freedom and no need for one:
the nonce alone gives unlimited valid proofs per input. This is what the audit
test `documented_gap_no_uniqueness_second_valid_proof_exists`
(`tests/vrf_audit_tests.rs:381-425`) demonstrates once; the measurement below
quantifies best-of-N selection over it.

Only the secret holder can grind their OWN ticket (forging another
validator's ticket still needs their secret). The bias is selfish, not
universal — but sortition fairness is exactly about selfish bias.

## 2. Measurement

Method (`tests/vrf_grinding_measure_tests.rs`): K=16 keys × M=16 inputs = 256
trials. Per pair: one honest `vrf_prove` plus 32 alternate proofs minted with
fresh nonces (test-local replica of the `src/vrf.rs` derivation with a fresh
nonce tag — same domains, same equations; every alternate asserts
`vrf_verify == Some`). Grinder strategy: keep the MINIMUM ticket, where
`ticket = u128::from_le_bytes(output[0..16])` (matches the 128-bit
`lottery_threshold` model, `src/vrf.rs:620-644`). Committee model:
equal-stake sets n ∈ {3,4,8,16}, one expected seat,
threshold = `lottery_threshold(1, n, 1)`; elected ⟺ `ticket < threshold`.
Closed form: `P_best(N) = 1-(1-p)^N`, `p = threshold/2^128`.
Chi-square over 16 bins keyed on `output[15]` high nibble (`output[15]` is the
ticket's most significant byte — the byte min-selection pressures hardest;
binning the LSB would hide the skew, found empirically during measurement).

### 2.1 Raw output (pasted)

```
[grinding] 320 extra proofs in 44ms => 139313ns/proof (distinct-output rate 320/320)
[grinding] honest output chi-square (15 dof, K*M=256): 20.75
[grinding] best-of-2 chosen-output chi-square (15 dof): 121.25 (bin0 share=0.117)
[grinding] best-of-8 chosen-output chi-square (15 dof): 791.75 (bin0 share=0.387)
[grinding] best-of-32 chosen-output chi-square (15 dof): 2927.12 (bin0 share=0.875)
[grinding] set n=3: threshold=113427455640312821154458202477256070485 p_honest=0.333333
[grinding]   honest measured P(elected)=0.2617 closed-form p=0.3333
[grinding]   best-of-2: measured P=0.5469 closed-form=0.5556 lift=x2.09
[grinding]   best-of-8: measured P=0.9609 closed-form=0.9610 lift=x3.67
[grinding]   best-of-32: measured P=1.0000 closed-form=1.0000 lift=x3.82
[grinding] set n=4: threshold=85070591730234615865843651857942052864 p_honest=0.250000
[grinding]   honest measured P(elected)=0.1992 closed-form p=0.2500
[grinding]   best-of-2: measured P=0.4375 closed-form=0.4375 lift=x2.20
[grinding]   best-of-8: measured P=0.9141 closed-form=0.8999 lift=x4.59
[grinding]   best-of-32: measured P=1.0000 closed-form=0.9999 lift=x5.02
[grinding] set n=8: threshold=42535295865117307932921825928971026432 p_honest=0.125000
[grinding]   honest measured P(elected)=0.1211 closed-form p=0.1250
[grinding]   best-of-2: measured P=0.2422 closed-form=0.2344 lift=x2.00
[grinding]   best-of-8: measured P=0.6250 closed-form=0.6564 lift=x5.16
[grinding]   best-of-32: measured P=0.9805 closed-form=0.9861 lift=x8.10
[grinding] set n=16: threshold=21267647932558653966460912964485513216 p_honest=0.062500
[grinding]   honest measured P(elected)=0.0625 closed-form p=0.0625
[grinding]   best-of-2: measured P=0.1172 closed-form=0.1211 lift=x1.88
[grinding]   best-of-8: measured P=0.3867 closed-form=0.4033 lift=x6.19
[grinding]   best-of-32: measured P=0.8750 closed-form=0.8732 lift=x14.00
```

(`cargo test --test vrf_grinding_measure_tests -- --nocapture`; timing from a
dev-profile run, deps at opt-level 3 — machine-dependent, order of ~10^2 µs.)

### 2.2 Reading

- **Uniformity destroyed.** Honest outputs: χ²=20.75 on 15 dof (uniform).
  Best-of-N minima: χ² = 121 / 792 / 2927 for N = 2 / 8 / 32, with 11.7% /
  38.7% / 87.5% of chosen outputs in the bottom bin (uniform expectation
  6.25%). Even ONE extra proof visibly skews the distribution.
- **Measured tracks closed form to ±0.03.** The `1-(1-p)^N` model is
  predictive, so the table below (closed form) can be trusted beyond the
  measured grid.
- **Lift is large at every committee size.** Best-of-2 ≈ doubles election
  probability everywhere (1.9–2.2x). Best-of-8: 3.7x (n=3) up to 6.2x
  (n=16). Best-of-32: near-certain election at n ≤ 8 (98–100%), 87.5%
  (14.0x lift) at n=16.
- **Grinding is free.** ~139 µs per extra proof ⇒ best-of-32 costs ~4.5 ms
  per input on ordinary hardware. No economic, timing, or protocol barrier:
  32 sequential scalar muls fit inside any block tempo.

## 3. Verdict: grinding breaks sortition fairness at these committee sizes

**Yes — at ALL measured sizes (n = 3..16), and the math says small committees
are not safer.** For `p ≪ 1/N`, `1-(1-p)^N ≈ Np`: best-of-N multiplies a
small validator's election chance by ~N. The relative advantage GROWS as
committees get larger relative to stake share (14.0x at n=16 vs 3.8x at n=3
for N=32), while the absolute outcome saturates to certainty at small n. There
is no committee-size threshold where the bias becomes negligible — the
scaling law forbids it.

Consequences for the phase-3 lottery (`docs/PLAN-VRF.md` §2–3):

1. The deterministic-Schnorr construction MUST NOT back the lottery at any
   committee size. A rational validator grinds every draw (4.5 ms for a 14x
   advantage is not a decision), so the equilibrium is universal grinding:
   the lottery degrades to "whoever grinds most wins most," i.e. the exact
   parent-hash-style search phase 3 was meant to remove.
2. Detection is statistical, not cryptographic. Only the chosen proof is
   gossiped (`VrfBeaconSeal`, `src/consensus.rs:528-535`); a grinder's
   win-rate anomaly is visible over many heights but no single proof is
   provably ground — so "slash the grinder" cannot be the security boundary.
3. Zero live impact TODAY: phase 1 is metering + math; the election ignores
   the registry (pinned by `phase1_sortition_election_ignores_vrf_registry`,
   `src/vrf.rs:846-883`). This verdict is a precondition on phase-3
   activation, not an incident.

## 4. Remote-signer VRF closure design (no implementation)

Goal: a VRF-capable signer such that the nonce never exists as a grindable
loop on the validator host — the signer mints the ONE ticket per input, and
the host cannot mint a second. Shape mirrors `src/remote_signer.rs` exactly;
all names below are proposed (nothing is coded).

### 4.1 Traits (mirror `Signer` / `SignerTransport`)

```rust
// Mirrors `Signer` (src/remote_signer.rs:321-338): object-safe, Send+Sync,
// minimal surface, byte-exact contract, NO fallback ever.
pub trait VrfSigner: Send + Sync {
    fn vrf_public_key(&self) -> [u8; 32];
    fn vrf_prove(&self, seed_input: &[u8; 32]) -> Result<VrfProof, VrfSignerError>;
    // Provided: verify a proof against the pinned key (cannot be subtly
    // pointed at another key). Mirrors `Signer::verify` (src/remote_signer.rs:332-337).
    fn vrf_verify_own(&self, seed_input: &[u8; 32], proof: &VrfProof) -> bool { ... }
}

// Mirrors `SignerTransport` (src/remote_signer.rs:449-455): the network seam,
// testable without a socket/KMS/HSM.
pub trait VrfSignerTransport: Send + Sync {
    fn vrf_public_key(&self) -> Result<[u8; 32], VrfSignerError>;
    fn vrf_prove(&self, seed_input: &[u8; 32]) -> Result<VrfProof, VrfSignerError>;
}

// Closed, payload-free error enum mirroring `SignerError`
// (src/remote_signer.rs:192-206): Transport{Request,Timeout,Rejected{status},
// UnreadableBody} / MalformedResponse{BadJson,MissingField,NotHex,BodyTooLarge}
// / BadKeyLength{got} / BadProofLength{got} / SigningFailed{EmptyInput,
// ProofInvalid, UnusableKey} / MalformedKey / PolicyRefused{reason-class only}.
// Carries no key material, no proof bytes. `seed_input` is public
// (beacon-derived) and MAY appear in logs; secrets MUST NOT.
```

### 4.2 `RemoteVrfSigner` (mirror `RemoteSigner`, `src/remote_signer.rs:479-553`)

- Holds `transport: Arc<dyn VrfSignerTransport>` + pinned `[u8; 32]` VRF key
  only — no secret, no seed (mirrors `src/remote_signer.rs:479-482`).
- `new(transport)`: resolves the key, checks width AND that it decompresses to
  a non-identity Ristretto point (`VrfPublicKey::from_bytes`,
  `src/vrf.rs:163-176`); fails closed otherwise (mirrors
  `src/remote_signer.rs:491-501`).
- `vrf_prove(seed_input)`: the one outside call; verifies the returned proof
  against the PINNED key via `vrf_verify` (`src/vrf.rs:518-546`) AND checks
  the `output` field matches the proof bytes; `ProofInvalid` otherwise
  (mirrors the re-verify in `src/remote_signer.rs:530-553`). Empty input
  refused (mirrors `SigningFailureKind::EmptyMessage`).
- `ValidatorVrfSigner { Local(VrfSecret-handle), Remote(RemoteVrfSigner) }`
  enum + `vrf_signer_from_env()` reading e.g. `STELL_VRF_SIGNER_URL` /
  `STELL_VRF_SIGNER_TOKEN`, mirroring `ValidatorSigner`
  (`src/remote_signer.rs:887-959`) and `validator_signer_from_env`
  (`src/remote_signer.rs:984-999`).
- HTTP transport mirrors `HttpSignerTransport` (`src/remote_signer.rs:623+`):
  `GET /vrf_public_key → {"vrf_public_key": hex}`,
  `POST /vrf_prove {"seed_input": hex} → {"proof": [64], "output": [32]}`,
  same hardening (timeout `DEFAULT_TIMEOUT`, no redirects, no proxy-from-env,
  `MAX_RESPONSE_BYTES` cap, redacted `Debug`).

### 4.3 The actual closure: single-shot policy lives SERVER-SIDE

A client-side trait alone does NOT close grinding — a network oracle the
holder can query N times is just slower grinding. The closure is the
signer-side policy, which is the point of moving the key out of the host:

- The signer keeps the set of served `seed_input`s per key and **refuses a
  second `vrf_prove` for an already-served input** (`PolicyRefused`), or
  equivalently rate-limits to one proof per input per key. One input ⇒ one
  ticket ⇒ best-of-N with N=1 ⇒ honest distribution (χ²≈15, lift 1.0x).
- This is enforceable ONLY for keys whose host copy is destroyed at
  enrollment (same trust assumption as the Ed25519 remote signer,
  `src/remote_signer.rs:27-32`, `67-94`): a holder keeping a local key copy
  can still grind locally. The closure therefore binds only compliant
  operators — it is defense-in-depth, NOT a substitute for uniqueness
  (§5).

### 4.4 Message flow + integration points

1. Consensus builds `seed_input = sortition_seed(parent, height, round)`
   (`src/consensus.rs:1059-1065`) — or the post-activation
   `vrf_election_seed` (`src/vrf.rs:571-576`). Unchanged preimage contract
   (cf. `docs/PLAN-VRF.md` §2 row 6: `vote_sign_bytes` UNCHANGED).
2. Proposer path (beside `Vote::sign`, `src/consensus.rs:1554-1585`) calls
   `vrf_signer.vrf_prove(seed_input)` OFF the async runtime
   (`spawn_blocking`; cf. threading rule `src/remote_signer.rs:99-102`) and
   packs the envelope into `VrfBeaconSeal::new(validator_id, proof)`
   (`src/consensus.rs:537-543`).
3. Gossip carries the seal beside the vote halves (envelope change per
   `docs/PLAN-VRF.md` §2 rows 3–5).
4. Verifier re-derives `seed_input` from the certificate's OWN
   `(sortition_parent, height, round)` and calls
   `VrfBeaconSeal::verified_output(registry, seed_input)`
   (`src/consensus.rs:548-560`) →
   `verify_vrf_seed_for_validator` (`src/vrf.rs:554-562`) →
   `vrf_verify` (`src/vrf.rs:518-546`); accepts ANY verifying proof and the
   election is a pure function of the verified output (no-uniqueness
   assumption already documented, `src/consensus.rs:524-526`).
5. ECVRF swap (phase 2) keeps this whole interface: `seed_input: [u8;32]`
   in, `VrfProof` out — only the signer/prover bodies change, matching the
   plan that the swap keeps "THESE signatures" (`src/vrf.rs:341-346`).

### 4.5 Fallback when unavailable: fail closed, never substitute

Mirrors remote-signer rule 1 (`src/remote_signer.rs:27-32`, `475-478`):

- Signer unreachable / refuses / proof fails pin-check ⇒ `vrf_prove`
  returns `Err`, the node emits NO seal for that input, and it cannot
  propose or cast a lottery vote that round. Stall + loud error + alert.
- Explicitly FORBIDDEN fallbacks: (a) minting with a local key copy
  (re-opens the full best-of-N surface silently — the classic rollout
  fiction); (b) falling back to the parent-hash draw for that height
  (re-opens proposer grinding AND forks against nodes that halted).
- Liveness note: per-height stall instead of re-roll is already the beacon
  design (`beacon_next` chains published outputs only, `src/vrf.rs:596-606`;
  `docs/PLAN-VRF.md` §5), so a signer outage stalls the height rather than
  weakening it — consistent, not new.

## 5. Recommendation

1. **Require the audited ECVRF swap (RFC 9381 family, `docs/PLAN-VRF.md`
   phase 2) before ANY lottery activation — at every committee size, with no
   "tolerate with cap" option.** A client-side cap on N is unenforceable:
   verification accepts any valid proof (`src/consensus.rs:524-526`), so a
   cap is a request the adversary ignores. Uniqueness (exactly one verifiable
   output per `(pk, input)`) makes best-of-N cryptographically impossible and
   zeroes the lift regardless of compute — it is the only complete fix, and
   §2 shows the bias is otherwise certain, cheap, and size-independent.
2. **Build the §4 remote-signer VRF closure as defense-in-depth, not as the
   fix.** With single-shot server policy it reduces compliant operators to
   N=1 even under the Schnorr construction, and it stays useful post-ECVRF
   (key hygiene, HSM story for the VRF key alongside the Ed25519 one). But it
   cannot bind a holder who kept a local copy — so it must never be cited as
   the reason to activate the lottery on Schnorr.
3. **Until ECVRF lands: keep phase-1 posture** (no election effect; registry
   + gossip + metering only). The measured numbers are the activation gate:
   re-run `tests/vrf_grinding_measure_tests.rs` against the ECVRF backend at
   swap time and expect best-of-N ≡ honest (lift 1.0x) by construction.

## 6. Gates

- `cargo clippy -p stellereum --all-targets -- -D warnings` → 0 warnings
  (this change's files; full-package gate is green once unrelated
  in-progress worker files land — see task report).
- `cargo test --test vrf_grinding_measure_tests` → 3 passed
  (`grinding_nonce_is_the_only_degree_of_freedom`,
  `grinding_best_of_n_distribution_and_committee_lift`,
  `grinding_cost_per_extra_proof`).
- `src/` untouched: `git status` shows only
  `tests/vrf_grinding_measure_tests.rs` + `docs/VRF_GRINDING.md` from this task.
