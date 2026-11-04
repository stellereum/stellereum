# PAYMASTER v1 — sponsored (gasless) transactions

Status: implemented (consensus). `sponsor != from` routes the fee to the
sponsor; `sponsor == from` fee-routes as plain.

## 1. What it is

A funded sponsor account declares `sponsor + sponsor_sig` on a transaction.
Nodes verify BOTH signatures:

- the USER's signature authorizes the ACTION (and binds the sponsor grant, so
  the grant cannot be swapped after signing);
- the SPONSOR's signature authorizes the FEE for THIS exact transaction (it
  commits to the tx core fields plus the caps, so the grant cannot be grafted
  onto another transaction).

Result:

- the fee (base + gas + failure-fee on revert) debits ONLY the sponsor;
- the user's balance moves ONLY by the value (`amount` + payload value
  movements) — the sponsor pays FEE, never value;
- the USER's nonce advances on success AND on attributable failure
  (anti-replay); the sponsor's nonce NEVER advances;
- the sponsor sets a per-tx fee cap (`max_fee_per_tx`), an expiry
  (`valid_until`, Unix seconds) and an allowlist (`allowed_targets`, empty =
  any recipient).

v1 composes ONLY with a plain legacy ed25519 inner signature. A sponsor
envelope on a session-keyed, chain-bound, PQ or EVM transaction is refused
fail-closed (`SponsorBadGrant`). (An explicit priority bid in the struct field
composes fine — it is not an inner envelope; it binds both signatures and the
fee math. Pinned by `sponsored_priority_bid_composes`.)

## 2. Wire format (wire-compatible)

No new field on `Transaction`/`Block`. The envelope rides the pre-existing
`signature: Vec<u8>` field as a TRAILING suffix:

```
inner_sig_blob ++ bincode(SponsorAuthorization) ++ len_be32 ++ b"SP1"
```

exactly like the priority-fee envelope before it. Consequences:

- every pre-sponsor persisted block still decodes byte-for-byte (bincode 1.3
  never sees a new struct field);
- an old node rejects the longer blob at `Signature::from_slice` (64 bytes
  expected) — fail-closed;
- `compute_tx_hash` mixes in `SPONSOR_COMMITMENT_TAG` + the auth ONLY when a
  sponsor envelope is present, so a legacy (no-sponsor) transaction hashes
  byte-identically to before (pinned by
  `paymaster_tests::legacy_wire_bytes_are_pinned`).

`SponsorAuthorization` (`#[serde(default)]` on the forward-compat
`allowed_targets`: older encodings/JSON wallets that omit the field decode as
"no allowlist"):

| field | meaning |
| --- | --- |
| `sponsor: [u8;32]` | funded account debited the fee (ed25519: the address IS the pubkey) |
| `max_fee_per_tx: u64` | hard ceiling on the fee execution may charge (`max(gas_limit, floor) + surcharge`); over-cap refuses at admission, propose AND apply |
| `valid_until: u64` | the grant authorizes nothing after this (admission clock at entry, block timestamp at propose/apply) |
| `allowed_targets: Vec<[u8;32]>` | recipient allowlist, empty = any; capped at `SPONSOR_MAX_TARGETS` (64; longer fails closed at parse) |
| `chain_id: u64` | replay-protection domain, committed into BOTH signatures |
| `sponsor_sig: Vec<u8>` | 64B ed25519 over `sponsor_message` (domain `SPONSOR_FEE_V1`) |

The USER's signed message (`signing_message`) commits to the FULL auth
(including `sponsor_sig`); the SPONSOR's message (`sponsor_message`) commits
to sponsor + from/to/amount/gas_limit/nonce/shards + payload commitment +
priority bid + caps + allowlist + chain id. Neither side can be swapped after
signing.

## 3. Invariants (and exactly how each holds)

### 3.1 Admission fee coverage (anti-DoS) → the SPONSOR's balance

`Mempool::insert` (the single choke point every admission funnels through —
RPC, faucet arms, gossip ingest, runtime `add_tx`, mempool restore):

1. malformed suffix → `SponsorBadGrant`; non-64B inner → `SponsorBadGrant`;
   bad sponsor signature → `SponsorBadSignature` (named, never a generic
   `BadSignature` for a sponsor-side problem);
2. policy at the admission clock: expired → `SponsorExpired`, allowlist
   miss → `SponsorOutOfScope`, fee above cap → `SponsorCapExceeded`;
3. coverage on SPLIT legs: the user must cover `amount` (else legacy
   `InsufficientBalance`); the sponsor must cover
   `max(gas_limit, floor) + surcharge` (else `SponsorInsufficientBalance`).
   Callers carry the sponsor head via
   `AdmissionCtx::with_sponsor_balance` (read from the engine exactly like
   the sender balance); a sponsored transaction WITHOUT a head is refused
   fail-closed — it can never ride on the user's balance alone;
4. joint reservation (F-03, both legs): `reserved[user] += amount` AND
   `reserved[sponsor] += gas_limit + surcharge` (pure legs, so claim and
   release agree even if the penalty map moves between them). One funding
   backs exactly the slots it can jointly pay for.

Per-sender quota stays counted on the user; there is deliberately NO
per-sponsor quota in v1 — the sponsor's joint reservation across ALL
sponsored txs bounds total exposure, plus their off-chain signing policy.

### 3.2 Failure-fee policy → the SPONSOR is debited

`commit_native`, the `fail_with_floor!` macro (both execution loops), the
parallel-plain planner (`plan_plain_tx`) and `charge_failure_fee_and_commit`
(single path) all branch on the effective grant:

- success: user `balance -= amount (+ vm_out)`, `nonce += 1`; sponsor
  `balance -= fee`;
- attributable failure the sponsor CAN cover: sponsor `balance -= fee`,
  user `nonce += 1` (a sponsored failure is not free to replay);
- attributable failure the sponsor CANNOT cover (missing sponsor, balance
  below the fee, or zero fee): NOTHING moves — no debit, no nonce (the grief
  rule, applied to the fee-payer leg).

The user's balance is NEVER touched for the fee (not base, not gas, not
failure-fee) on any path. `fees_collected` (proposer credit) sums the same
fees regardless of payer, so value is conserved.

### 3.3 Nonce model → the USER

Only the user's nonce advances (success + attributable failure). The sponsor
account's nonce is snapshotted for the undo log and never incremented. A
replay is a user-nonce mismatch → unattributable → moves nothing (no second
fee from the sponsor). Pinned by `sponsored_replay_moves_nothing`.

### 3.4 No double-spend → the SPONSOR reservation

Four layers, all required because each covers a different window:

1. admission joint reservation (3.1) — pool-wide;
2. block admission simulation (`sponsor_sim` map in
   `apply_block_parallel_fees`) — one sponsor funding backs exactly the
   sponsored slots of THIS block it can jointly pay for; a missing sponsor
   admits nothing;
3. commit-time re-check under the accounts lock (`commit_native`) — a
   concurrent commit that moved either leg since admission refuses instead
   of overdrawing;
4. wave scheduling (`extract_access_keys` emits `Account(sponsor)`) — two
   transactions sharing a sponsor never land in one parallel wave; the
   compare-and-swap snapshot covers the sponsor account, so a balance that
   moved underneath aborts the wave into the sequential path.

The D2 failure-penalty mirror stays keyed on the USER (whose nonce advances
and whose failure history it prices); the sponsor is protected by their
explicit per-tx cap, not by the penalty.

## 4. Mid-mempool revoke (admission + proposer re-check — specified)

v1 has NO on-chain sponsor registry, so "revoke" is economic, and it is
handled at three deterministic gates (all on the BLOCK timestamp, never the
wall clock):

1. **admission** (`insert`, §3.1) — policy + coverage at entry;
2. **proposer re-check** (`ValidatorRuntime::propose`, sealed loop + plain
   filter) — the grant's policy (expiry/allowlist/cap) AND both funding legs
   are re-verified against the block timestamp and the filter's simulated
   balances, SKIP-only (never a hard reject: selection stays a pure function
   of the same inputs on every node). A sponsor that spent its balance down
   after admission, or a grant that expired, is SKIPPED here (counted in the
   `sponsor=` rejection census) and again at apply;
3. **apply** (block admission simulation + `commit_native` lock re-check) —
   the same predicates against committed state.

The mempool sweeps (`evict_unexecutable`, `sweep_expired`) additionally
reclaim slots whose sponsor leg went uncoverable against the caller-supplied
view (an unknown sponsor never deletes — the proposer skip is the backstop).
Pinned by `mid_mempool_spend_down_is_re_refused`.

## 5. Caps (and what they do NOT do)

- `max_fee_per_tx` is checked against `max(gas_limit, floor) + surcharge` —
  the fee execution will ACTUALLY charge, not the declared limit — so a
  below-floor declaration cannot smuggle an over-cap fee past the sponsor.
- Per-epoch / total spend is enforced by the sponsor's own signing policy
  (they sign each grant) plus the mempool's joint reservation, NOT by
  consensus state in v1. There is deliberately NO global on-chain sponsor
  budget: "unforeseen block" overspend (two in-cap txs jointly exceeding the
  sponsor balance) is stopped at admission by the joint reservation
  (pinned by `joint_reservation_stops_unforeseen_block_overspend`), and any
  remainder at propose/apply by the same split accounting.

Abuse cases and their stops:

| abuse | stop |
| --- | --- |
| sponsor drain via victim failures (buggy/malicious user burns sponsor funds on reverts) | every failure costs AT MOST `max_fee_per_tx`, each consumes the user nonce (unreplayable); pinned by `sponsor_drain_via_victim_failures_is_capped` |
| replay (same sponsored bytes resubmitted) | user nonce mismatch → unattributable → nothing moves; pinned |
| mid-mempool revoke (sponsor spends down / grant expires after admission) | proposer re-check + apply simulation + sweeps; pinned |
| unforeseen block (joint overspend within caps) | joint reservation refuses the second at admission; propose/apply re-check; pinned |
| grant grafting (sponsor auth moved to another tx, or tx fields changed under the grant) | user message binds the full auth; sponsor message binds the tx core + caps; BOTH sigs verified; tamper → `SponsorBadSignature`/`BadSignature` |
| session/PQ/EVM/chain-bound inner with a sponsor envelope | refused (`SponsorBadGrant`): v1 sponsors plain legacy ed25519 only |
| unfunded sponsor spam (no sponsor behind the fee) | `SponsorInsufficientBalance` (fail-closed without a sponsor head); never occupies pool space |

## 6. Wallet / SDK hook

`Transaction::sign_with_sponsor(user_key, sponsor_key, to, amount, gas_limit,
nonce, source_shard, target_shard, payload, priority_fee_per_gas,
max_fee_per_tx, valid_until, allowed_targets, chain_id)`:

1. the sponsor signs FIRST (`sponsor_message` over the tx core + caps);
2. the user signs the action + the grant binding (`signing_message` over the
   core + the full auth).

Signing ORDER is load-bearing (the user's message commits to
`sponsor_sig`). Submit the bincode-serialized transaction hex to
`stell_sendRawTransaction` unchanged — admission reads the envelope from the
signature field. See `docs/RPC.md` §4 (sponsored transactions) for the
wallet flow and error table.

## 7. Risks and non-goals (v1)

- No per-epoch / total on-chain budget: a sponsor that signs MANY grants can
  still be drained up to (#grants × cap) + failures. Sponsors MUST cap
  `max_fee_per_tx`, expire grants tightly, scope `allowed_targets`, and stop
  signing when exposure is reached. This is the documented v1 contract, not
  a bug.
- No on-chain revocation registry: "revoke" = stop signing + spend down.
  In-flight grants remain valid until expiry (bounded by `valid_until`).
- No composition with session keys / PQ / EVM / chain envelopes.
- Restore path: mempool restore re-reads the sponsor head from committed
  state; a restart with a spent-down sponsor drops the tx (fail-closed;
  the sender re-gossips).
- The team-vesting gate applies to the user's post-value balance (the fee is
  the sponsor's and never counts against the user's lock).

## 8. Files

- envelope / verify / policy / signing: `src/sharding.rs`
  (`SponsorAuthorization`, `sign_with_sponsor`, `sponsor_message`,
  `verify_sponsor_sig`, `check_sponsor_policy`, `sponsored_grant`,
  `fee_payer`, hash/commitment branches);
- admission / reservation / sweeps: `src/mempool.rs` (`AdmissionCtx::
  sponsor_balance`, `MempoolError::Sponsor*`, `sponsor_fee_cost`,
  `sponsored_pure_legs`, `fee_payers`);
- execution: `src/state_engine.rs` (`apply_sponsored_failure_fee_to_map`,
  `commit_native` legs, `plan_plain_tx` sponsor arm, block admission
  `sponsor_sim`, `fail_with_floor!` branch, `sponsor_balance_of`);
- propose: `src/runtime.rs` (fee-payer snapshot, sealed + plain sponsor
  re-check, `sponsor=` census);
- entry points: `src/rpc.rs`, `src/explorer.rs` (faucet-internal txs need no
  head), `src/main.rs` (gossip/overlay), `ValidatorRuntime::add_tx`;
- conflict keys: `src/parallel_exec.rs` (`Account(sponsor)`);
- tests: `tests/paymaster_tests.rs` (20 tests: success, failure, 6 named
  refusals, self-sponsored, golden wire/hash, 5 abuse, malformed,
  chain-id).
