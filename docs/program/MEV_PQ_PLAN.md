# MEV PQ Migration Plan — epoch DKG + X25519

Status: DESIGN ONLY. No wiring, no activation. Prototype lives unwired in
`stellereum/src/mev_pq_plan.rs` (9 KATs, `std`-only mechanics model, never called by production).

## 1. What the DKG produces and who consumes it (one line)

Feldman-VSS DKG over Ristretto255 produces per-epoch `(P_e, member Shamir shares, transcript root)`,
consumed by wallet sealing (`seal_transaction`), threshold partials (`compute/combine_partials`,
`unseal_transaction`), the proposer path (`runtime.rs:3336`), the sealed pool (`mempool.rs`),
`MevFrame::Dkg` gossip, and the block commitment checked by light clients.

## 2. X25519's role (classical, narrow)

X25519 encrypts ONLY the DKG share packages in transit (`encrypt/decrypt_share_package`,
`mev_epoch.rs:1094-1136`, DH at `:1102`/`:1120`; keys derived `:1060-1089`). It is NOT the
sealing primitive (Ristretto DH `e * P_e` + XChaCha), NOT the threshold arithmetic (X25519
clamping is non-linear, `:49-56`), and NOT the node E2E channel (`node_keys.rs:629-630`).

## 3. Ranked replacement

1. **Falcon-authenticated PQ-KEM transport swap (RECOMMENDED).** Keep Feldman VSS + Ristretto
   threshold byte-for-byte; replace X25519 package encryption with a PQ KEM encaps and sign
   contributions with Falcon-512 (`vrf.rs` `VrfBinding` / `cn_vrf.rs` pattern). Fits the
   production/consumption shape exactly: same `P_e`, same partials, same unseal path.
2. **Falcon commit-reveal for the epoch seed only (SUPPLEMENT).** CN-VRF-shaped commit in
   epoch N-1 / open in N replaces `EPOCH_SEED_DOMAIN` determinism; removes input-bias surface
   but has no threshold property — cannot unseal anything alone.
3. **Pure hash-DRB replacing the DKG (REJECTED).** A DRB yields public randomness, not a
   threshold-shared secret; it cannot make `t`-of-`n` partials for arbitrary ephemerals.

## 4. Migration phases

0. **Design (THIS DOC + unwired prototype).** Done: audit, ranking, KAT mechanics shape.
1. **Prototype (tree, still unwired).** Re-implement `mev_pq_plan.rs` mechanics against real
   BLAKE3/SHAKE-256 + Falcon-512 behind `#[cfg(test)]`; KATs pinned to NIST vectors.
2. **External audit.** PQ-KEM choice (ML-KEM-768), Falcon binding preimage, transcript domain
   separation, and the "exact contributor set" invariant re-proven for the new transport.
3. **Wiring behind flag.** `mod mev_pq_plan` + dual-path DKG (classical default; PQ transport
   opt-in per epoch, negotiated via `EpochKeyAnnouncement` version bit, never silent).
4. **Activation.** Flag-on epoch with rollback criterion: any `finalize` divergence vs classical
   path aborts PQ for that epoch (fail-closed, same as `epoch_key_diverged` today).

## 5. Blast radius if X25519 is cut TODAY (no replacement)

- `ingest` fails closed (no decryptable share packages) → `can_finalize` false → no
  `EpochKeyMaterial`, no `P_e`.
- Wallets cannot seal (`stell_epochKey` empty); proposer falls back to the plain path;
  sealed pool stalls; `MevFrame::Dkg` gossip is dead weight.
- Chain LIVENESS preserved (plain path + fail-closed drops), MEV PRIVACY lost entirely.
- `committee_for` breaks too (`enc_pk` derivation has no source). Cutting without Rank-1
  in place is a privacy kill-switch, not a migration.

## 6. Decision points for the lead

- D1: PQ KEM choice (ML-KEM-768 vs alternatives) — key/signature sizes ride every gossip frame.
- D2: Falcon binding preimage — must cover `(epoch, index, commitments, packages)` like
  `canonical_bytes` does today, or contributions become malleable.
- D3: Dual-path negotiation — where the version bit lives (announcement vs block commitment).
- D4: Activation gate — which audit + testnet soak counts as sufficient (mirror `cn_vrf.rs` spec §7).
- D5: `e2e.key` transport (`node_keys.rs`) is OUT of scope here — separate PQ track
  (`docs/PQ_TRANSPORT_PLAN.md`).
