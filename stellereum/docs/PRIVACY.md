# Stellereum privacy: prototypes, not a live path

Transparent is the base layer and the ONLY live path. There is no
confidential-transfer feature on chain: `src/crypto_privacy.rs` (Pedersen
commitments, Ristretto stealth, range proofs) is deleted, and the three
shielded RPC arms (`stell_shieldedTransfer`, `stell_shieldedBalance`,
`stell_unshield`) are removed from dispatch (the RPC audit gate counts 140
public methods — 143 minus those 3; `src/rpc.rs:18824-18828`). Anything that
still names them is stale.

What exists instead are three UNWIRED prototypes — research code that no
production path calls, kept out of `lib.rs` and audit-gated before any
wiring. Privacy, if it ever ships, is sender/recipient UNLINKABILITY only.
There is NO amount-hiding anywhere: every design below reveals
`(serial, value, blinding)` at spend time so the operator can recompute the
commitment. Do not document, promise, or wire these as amount-hiding.

## 1. HashPool: stealth-via-KEM + CoinJoin batches (`src/hashpool.rs:1-80`)

Hash commitments with NO Merkle paths, over primitives already in-tree
(ML-KEM-768 + SHAKE-256 + Falcon-512 owner signatures):

- STEALTH (hash+KEM, no DH group): the sender encapsulates to the
  recipient's ML-KEM-768 key; the stealth address is
  `SHAKE256("STELL_HP_STEALTH_V1" || ss || index_be64)`.
  The recipient scans by decapsulation trial.
- NOTES: `C = SHAKE256("STELL_HP_COMMIT_V1" || chain || value || blinding
  || stealth)`, `Nf = SHAKE256("STELL_HP_NULL_V1" || serial)`. The pool is a
  map `C -> (stealth, Nf_expected)` plus a spent set. Spend reveals exactly
  `(serial, value, blinding)`; the verifier recomputes `C` with the STORED
  stealth, checks presence, checks the serial-bound nullifier, marks spent.
- COINJOIN batch: N same-denomination inputs + M same-denomination outputs +
  K Falcon-512 owner signatures, conservation `sum_in == sum_out + fee`,
  canonical ordering (inputs/outputs sorted by commitment; anything else is
  refused).

Privacy LIMITATION (`src/hashpool.rs:65-73`): the pool operator learns the
`value` (and `blinding`, `stealth`) of every note AT SPEND TIME. Unlinkability
comes only from fresh stealth addresses per note plus CoinJoin ambiguity —
NOT amount hiding. There is deliberately no encrypted-value or range-proof
machinery (that would be new crypto, which is forbidden).

Operator model (`src/hashpool.rs:75-81`): membership is a direct map lookup of
the recomputed `C` — no paths, no proofs. The operator sees linkable
`(C, stealth)` registrations at deposit and full openings at spend.

Wiring status: declared in `lib.rs` (`pub mod hashpool`, test access),
but NOTHING in production calls it and the apply gate is default-OFF
(`HASH_POOL_ENABLED = false`, `src/state_engine.rs:1016`).

## 2. SilentPay: non-interactive KEM stealth (`src/silentpay.rs:1-78`)

Same note/commitment domains as HashPool (byte-identical tags, cross-verify
KAT), plus a forward-secret recipient ratchet (`chain <- SHAKE256(chain ||
ss)`, `index += 1` per note). Privacy LIMITATION is identical
(`src/silentpay.rs:73-78`): recipient unlinkability via fresh chain-bound
stealth addresses per note, NOT amount hiding. Lockstep LIMITATION: sender and
recipient `(chain, index)` mirrors must match; lost/reordered notes
desynchronize the pair (detectable, fail-closed). Resync transport is OUT OF
SCOPE for the prototype. Wiring status: same as HashPool — declared in
`lib.rs` (`pub mod silentpay`, test access), nothing in production calls it
(`SILENT_PAY_ENABLED = false`, `src/lib.rs:49`).

## 3. Dandelion relay policy (`src/dandelion.rs:1-17`)

Network-layer complement to on-chain stealth: transactions first travel a
short random "stem" (one peer per hop, geometric length, default mean 4 at
`p_continue = 0.8`) then diffuse ("fluff"), so a fluff-phase observer sees a
random relayer, not the originator's IP. Policy ONLY — pure function, no I/O,
no sockets, not registered in `lib.rs`; wiring into gossip is audit-gated
(`docs/DANDELION_PLAN.md`).

## 4. Apply gate: default-OFF (`src/state_engine.rs:983-991`)

`HASH_POOL_ENABLED: bool = false` in every build — while off, no HashPool
trie key is ever written and the apply path is byte-identical (proven by
`tests/hashpool_wiring_tests.rs`). Entry points refuse LOUDLY with
`HashPoolOpError::Disabled` (never a silent skip). Production flips this const
only with a spec update + audit. The wire is frozen: blocks carry NO HashPool
bytes; ops travel via the explicit `HashPoolBlockOps` sidecar, never inside
`Transaction`/`Block`.

## Explicit non-goals

- **No private-by-default.** Transparent stays the base AND the only live
  path; every prototype above is opt-in research, default-OFF.
- **No anonymity set, no RingCT.** The sender of a live transaction is always
  public (`tx.from` + nonce + public gas payment). Prototypes unlink
  recipients/relayers; they do not hide who paid the fee.
- **No amount-hiding, no range proofs, no viewing-key flow.** The old
  `stell_shieldedBalance` viewing-key flow described RPC arms that no longer
  exist. Amounts are public at spend BY DESIGN in every prototype.
- **No new cryptography.** No new curves, no new proof systems. Range
  enforcement has nothing to enforce: there is no confidential-values feature
  left to range-check.
- **No shielded-balances RPC.** Nothing sums hidden balances because nothing
  hides balances.
