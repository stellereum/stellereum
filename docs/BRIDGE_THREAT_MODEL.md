# Teleport bridge threat model

Status: **descriptive security document; no code changes**. Written 2026-11-20
against the working tree of `/home/imm/stellereum-project`. Every behavioural
claim carries a `file:line` citation. Where the code does **not** implement a
mitigation this document says **NOT IMPLEMENTED**; it does not describe an
intended design as if it existed.

Pinned inputs (line numbers were verified against these bytes):

| File | SHA-256 |
| --- | --- |
| `stellereum/src/bridge.rs` | `ce8b97e5bc67207452ea241b97a6058d9775f882520dab7e9f7d409731c0703c` |
| `stellereum/src/bridge_adapters.rs` | `8fd717aa2670e8d01c1cbe658f5ab2dc42f5b9dab14748cf14b2078908426432` |
| `stellereum/src/state_engine/settlement.rs` | `334a04c70f6d1ca2081e41547a1dfb61ccbd4bd54f13289e0bf36dfa98a197c6` |
| `stellereum/src/native_api.rs` | `c639979e29f39ddd696e356e0fa62c3e3ea1c2250f51b22761b716191886ff11` |

In scope: the four named routes (`Ton`, `Arbitrum`, `Ethereum`, `Solana`), the
native state machine, settlement, the RPC/read surfaces that expose it, and the
offline release models in `bridge.rs`. Out of scope: any foreign-chain contract
(not in this repository), any external bridge, and any feature that does not
exist today.

Severity scale used in this document:

| Level | Meaning |
| --- | --- |
| **S0 Critical** | Direct loss or permanent freeze of user funds with no extraordinary precondition (a single unauthenticated caller, or one mis-set node), or a consensus split. |
| **S1 High** | Loss/freeze requiring a threshold coalition, an operator mistake, or a foreign-chain reorg; or systemic liveness failure. |
| **S2 Medium** | Griefing, targeted censorship, state bloat, or a misleading view with no direct loss. |
| **S3 Low** | Estimation/UX/documentation defects. |

---

## 0. Executive summary

The bridge is **relayer-attested on every inbound path**, and the outbound
local leg is **not attested at all**. There is no light client, no committed
foreign header, and no foreign-chain proof whose trust root is anything other
than 2/3 of the *current bonded validator set*. The "SPV" adapter
path (BoC cell chain / Patricia-trie receipt / binary Merkle proof) verifies a
real inclusion proof, but the root it opens against is a quorum-signed
`StoredHeader` whose `height`, `prev_hash` and `tx_root` are unconstrained
transaction bytes (`stellereum/src/bridge_adapters.rs:644-665`,
`:670-691`). Its leaves are also Stellereum's own canonical encodings, not the
foreign chain's native event encoding (`stellereum/src/bridge_adapters.rs:143-192`;
module honesty ledger `:48-64`). The evidence path therefore reduces to the same
2/3 trust assumption as the quorum path, plus extra bytes.

Three properties of the *current* implementation dominate the risk picture:

1. **The outbound leg is not implemented and is not linked to the chain.**
   `BridgeIntent::Release` is authorized by **nobody**: any payer can flip
   `executed` on any matured request (`stellereum/src/bridge.rs:1484-1490`,
   `:932-951`). It moves no coins (`stellereum/src/state_engine/settlement.rs:1672-1684`).
   The actual foreign payout is a library model (`MultisigRelayer`,
   `TonMultisigReleaseOrder`, `EvmReleaseOrder`) with **no production caller**
   in this repository, and its replay set is daemon memory
   (`stellereum/src/bridge.rs:1912-1916`, `:1896-1901`). Refund after a late
   foreign payout is therefore a real double-spend window, bounded only by
   operator discipline (`stellereum/src/bridge.rs:312-329`).
2. **The quorum's keys are not committed state.** `verify_quorum_signatures`
   resolves each signer's Falcon key through a process-global map populated at
   node startup from the local key file and the `STELL_PEER_PQ_KEYS`
   environment variable (`stellereum/src/consensus/rotation.rs:8-10`,
   `:109-112`; `stellereum/src/node/consensus_driver.rs:283-328`). Two nodes can
   disagree about the same block's bridge verdict, and a poisoned local key
   table forges quorum on that node.
3. **Inbound deposits have no timeout and no trust-minimized exit.** If the
   quorum never attests, nothing on this chain can credit, refund, or expire
   the claim; the evidence path still needs a quorum over the header
   (`stellereum/src/bridge_adapters.rs:644-665`). The user's only exit is on the
   foreign chain, which this repository does not implement.

The dispute layer is materially stronger than the outbound leg: it is
fail-closed, pays no bounty on missing evidence, and has a randomized
conservation test (`stellereum/tests/audit_closure_bridge_tests.rs:924`). Its
weak points are that a challenge cannot claw back funds the recipient already
spent (`stellereum/src/state_engine/settlement.rs:1737-1748`) and that evidence
is verified against the **current** validator set, not the set at deposit time,
so a key rotation can leave a challenged deposit unresolvable by its recipient
unless the current quorum re-attests it.

---

## 1. Inventory of every bridge path that exists today

### 1.1 The intent set (the complete state machine)

`BridgeIntent` has eight variants (`stellereum/src/bridge.rs:232-377`), pinned
to bincode discriminants `0..=7` (`stellereum/src/bridge.rs:2669-2725`). The VM
performs only cheap shape checks
(`stellereum/src/svm.rs:2843-2861`; `BridgeIntent::validate`
`stellereum/src/bridge.rs:385-456`); every policy check that needs committed
state runs in `BridgeState::plan` at settlement
(`stellereum/src/bridge.rs:1294-1805`), called from
`stellereum/src/state_engine/settlement.rs:1665-1666` and reached from
`stellereum/src/state_engine/apply.rs:760-770`, `:893-926`.

| ID | Intent | What it does natively | Auth in code | Quorum | Timeout / window |
| --- | --- | --- | --- | --- | --- |
| B-1 | `Deposit` + `Attest` | mint `amount` to `recipient` | in-payload 2/3 attestation | yes, 2/3 distinct Falcon | none |
| B-2 | `Deposit` + `DepositProof` | mint `amount` to `recipient` | SPV/quorum evidence | yes, 2/3 over header | confirmation depth only |
| B-3 | `Attest` / `DepositProof` alone | nothing (inert) | n/a | n/a | n/a |
| B-4 | `Withdraw` | debit payer, park in `BRIDGE_ESCROW` | tx payer | no | `unlock_at` (1 h if >= 50k STELL) |
| B-5 | `Release` | flip `executed` (no coins move) | **none** | **no** | `now >= unlock_at` |
| B-6 | `Refund` | return parked amount, delete request | original sender only | no | `now >= unlock_at + 24 h` |
| B-7 | `Challenge` | claw deposit back to escrow, lock bond | any payer + bond | no | deposit age <= 24 h |
| B-8 | `Resolve` (confirm) | return amount + bond to recipient | verifiable evidence | evidence-defined | none once open |
| B-9 | `Resolve` (revoke) | pay bond + reward, burn remainder | quorum retraction | yes, 2/3 | none once open |
| B-10 | `Resolve` (no evidence) | defer, then refuse | any payer | no | bounded by `deposit + 28 h` |
| B-11 | external release order | none on this chain | relayer threshold (offline model) | 2/3 relayer keys | caller-set `expires_at` |

### B-1 Inbound deposit, quorum path

- **Entry.** `BridgeState::plan` `Deposit` arm
  (`stellereum/src/bridge.rs:1368-1400`), which calls
  `TeleportBridgeEngine::process_deposit`
  (`stellereum/src/bridge.rs:830-882`).
- **Attestation.** `Attest` intents are merged by `source_tx_hash`
  (`stellereum/src/bridge.rs:1332-1343`) and counted over
  `deposit_signing_message = source_tx_hash || recipient || asset || amount ||
  chain_discriminant` (`stellereum/src/bridge.rs:769-782`; chain binding added
  for C8 at `:775-781`). `asset` is always `"STELL"`
  (`LIVE_DEPOSIT_ASSET`, `:177`; `deposit_event` `:485-506`).
- **Who attests / quorum.** The committed staking validator set
  (`stellereum/src/state_engine/apply.rs:877-881`). Threshold
  `bridge_threshold(n) = max(1, ceil(2n/3))`
  (`stellereum/src/bridge.rs:534-546`). Only DISTINCT signers whose
  **registered Falcon-512 key** verifies count; duplicates count once; an
  unknown signer aborts the whole bundle with `Err`
  (`stellereum/src/bridge.rs:598-633`). An empty validator set refuses all
  deposits (`stellereum/src/bridge.rs:1306-1314`, `:603-605`).
- **What is trusted.** That `>= threshold` of the bonded set honestly observed
  the foreign deposit. The transaction does not prove existence on the source
  chain: the preimage contains only the claimed tuple.
- **Timeout.** None. `Deposit` has no deadline and no cancel/expire variant
  (`stellereum/src/bridge.rs:232-377`).
- **Reorg.** The credit and the replay entry are committed to the state root in
  the block that carries the transaction
  (`stellereum/src/state_engine/settlement.rs:1791-1797`;
  `stellereum/src/commitment.rs:1497-1510`). There is **no Stellereum finality
  gate** on the credit: it applies during block application, not when the block
  is final (`stellereum/src/state_engine/apply.rs:893-926`). A reorg restores
  the per-height bridge snapshot (`stellereum/src/storage.rs:1260-1262`,
  `:3142-3146`) together with the accounts snapshot, so the native mint is
  rolled back, but an off-chain actor that acted on the unfinalized credit is
  not. Foreign-chain reorgs are not observed at all in this path.

### B-2 Inbound deposit, adapter-evidence path

- **Entry.** The `process_deposit` error arm
  (`stellereum/src/bridge.rs:1401-1469`), then
  `bridge_adapters::verify_evidence`
  (`stellereum/src/bridge_adapters.rs:1094-1131`).
- **Evidence kinds.** `QuorumAttested`, `TonCell`, `EvmReceipt`, `SolanaTx`,
  and the always-failing `ZkProofPlaceholder`
  (`stellereum/src/bridge_adapters.rs:483-533`).
- **Who attests / quorum.** Every SPV variant carries its own `StoredHeader`
  plus `header_signatures`; `check_header` requires the **same 2/3 distinct
  Falcon quorum** over `StoredHeader::signing_message`
  (`stellereum/src/bridge_adapters.rs:644-665`; header format `:207-251`).
  There is no second, independent trust root.
- **Depth.** `check_depth` computes `finalized_* - header.height` from numbers
  supplied **inside the evidence** (`stellereum/src/bridge_adapters.rs:670-691`,
  fields at `:498-500`, `:510-512`, `:523-525`). TON 12, Ethereum 64,
  Arbitrum 32, Solana 32 (`stellereum/src/bridge.rs:143`, `:2070-2071`;
  `stellereum/src/bridge_adapters.rs:96`), dispatched at
  `stellereum/src/bridge_adapters.rs:1113-1126`.
- **What the proof actually proves.** TON: the BoC parses, every cell hash
  re-verifies, the root equals `header.tx_root`, and the decoded bytes equal
  Stellereum's own TON leaf (`stellereum/src/bridge_adapters.rs:768-800`,
  leaf `:143-150`). EVM: the receipt bytes equal Stellereum's own canonical
  receipt and open under `header.tx_root` through the compressed Patricia trie
  (`stellereum/src/bridge_adapters.rs:889-913`, encodings `:153-182`).
  Solana: Stellereum's own leaf opens under a binary SHA-256 Merkle root
  (`stellereum/src/bridge_adapters.rs:994-1001`, leaf `:185-192`). None of
  these is the foreign chain's native event encoding; the module says so
  explicitly (`stellereum/src/bridge_adapters.rs:48-64`). Consequently the
  proof binds the claim to a **quorum-signed root**, not to a foreign block.
- **Timeout.** None.
- **Reorg.** `Height`/`prev_hash` linkage is not checked on-chain. `HeaderStore`
  enforces linkage only on the off-chain watcher side and is explicitly *not*
  consulted by consensus (`stellereum/src/bridge_adapters.rs:261-264`,
  `:285-308`). A quorum can sign a header at any height with any `prev_hash`
  and claim any `finalized_*`, so the depth constants are only as meaningful as
  the quorum's honesty.
- **Challengeability.** Evidence-path deposits are recorded with
  `via_quorum = false` (`stellereum/src/bridge.rs:1461-1468`) and can never be
  challenged (`stellereum/src/bridge.rs:1513-1517`). A forged evidence-path
  deposit is therefore *uncontestable* once credited.

### B-3 `Attest` and `DepositProof` as standalone intents

Both are inert when not paired with a `Deposit` of the same hash
(`stellereum/src/bridge.rs:1786-1793`). They commit nothing and move nothing.
`Attest` has no signature-count cap in `validate` beyond non-empty
(`stellereum/src/bridge.rs:411-419`), while evidence is capped at 1024 header
signatures (`stellereum/src/bridge_adapters.rs:557-565`); the wire size cap
bounds the practical blast radius (`stellereum/src/network.rs:3216`).

### B-4 Outbound withdraw (park)

- **Entry.** `Withdraw` arm (`stellereum/src/bridge.rs:1472-1483`), engine
  `request_withdrawal` (`stellereum/src/bridge.rs:885-929`), effect `Park`
  (`stellereum/src/bridge.rs:1000-1002`).
- **Authorization.** The transaction payer (`tx.from`). No attestation, no
  destination proof; `target_address` must merely be non-empty
  (`stellereum/src/bridge.rs:406-408`).
- **Limits.** Hourly withdrawal window 500,000 STELL, saturating
  (`stellereum/src/bridge.rs:33-35`, `:900-902`); large withdrawals
  >= 50,000 STELL get `unlock_at = now + 1 h`, small ones `unlock_at = now`
  (`stellereum/src/bridge.rs:904-908`). Pass-1 settlement enforces the payer's
  balance and the transaction floor (`stellereum/src/state_engine/settlement.rs:1737-1757`).
- **Trust.** That `tx.from` owns the debited balance (ordinary signature
  check). Nothing about the destination chain is validated.
- **Reorg.** Parked balance and queue entry are committed state
  (`stellereum/src/bridge.rs:1038-1077`) and restored per height
  (`stellereum/src/storage.rs:3142-3146`). A pre-finality reorg rolls the park
  back; there is no cross-chain effect yet, so the native half is consistent.

### B-5 Release (local finalize)

- **Entry.** `Release` arm (`stellereum/src/bridge.rs:1484-1490`), engine
  `finalize_withdrawal` (`stellereum/src/bridge.rs:932-951`).
- **Authorization.** **None.** `plan` does not pass the payer to
  `finalize_withdrawal`; the only checks are: request exists, `!executed`,
  `now >= unlock_at` (`stellereum/src/bridge.rs:932-947`). `validate` returns
  `Ok(())` unconditionally (`stellereum/src/bridge.rs:420-425`).
- **Coin movement.** None. Settlement treats a state-only plan specially and
  writes the domain without an account pass
  (`stellereum/src/state_engine/settlement.rs:1672-1684`).
- **What `executed` means.** Only "this side considers the request finalized".
  It does not record a foreign payout, a transaction hash, or a recipient
  (`stellereum/src/bridge.rs:510-519`).
- **Timeout.** None after `unlock_at`; a request may be released at any later
  block, repeatedly attempted (second attempt refused).
- **Reorg.** The flip is committed state and is restored with the domain.

### B-6 Refund

- **Entry.** `Refund` arm (`stellereum/src/bridge.rs:1491-1502`), engine
  `refund_withdrawal` (`stellereum/src/bridge.rs:956-984`), effect `Unpark`
  (`stellereum/src/bridge.rs:1003-1005`).
- **Authorization.** `req.sender == payer` (`stellereum/src/bridge.rs:969-971`).
- **Conditions.** `!executed` (`:966-968`) and `now >= unlock_at + 24 h`
  (`:972-978`). The request is **deleted** (`:980`), which is the replay guard;
  a later `Release` fails as unknown.
- **What it ignores.** The foreign leg. There is no payout receipt to consult,
  so a late external payment after a refund pays twice
  (`stellereum/src/bridge.rs:312-329`).
- **Reorg.** Unpark and deletion are committed and restored with the domain.

### B-7 Challenge

- **Entry.** `Challenge` arm (`stellereum/src/bridge.rs:1503-1568`).
- **Authorization.** Any payer that can fund the bond. `payer` becomes
  `Dispute::challenger` (`:1549`).
- **Preconditions.** A `DepositRecord` exists; `via_quorum` is true; not
  already disputed; `now - deposited_at <= 24 h`; no open dispute for the hash
  (`stellereum/src/bridge.rs:1510-1537`).
- **Bond.** `max(1 STELL, 1% of amount)` (`challenge_bond_for`,
  `stellereum/src/bridge.rs:83-86`; constants `:61-63`).
- **Effects.** `Park { bond }` from the payer, then `Clawback { account:
  recipient, amount }` into escrow (`stellereum/src/bridge.rs:1563-1567`).
  Settlement applies both in one delta map; if the recipient no longer holds
  the amount, **the whole transaction fails** and no dispute is opened
  (`stellereum/src/state_engine/settlement.rs:1714-1719`, `:1737-1748`).
- **Timeout.** Deposit must be <= 24 h old; the dispute itself has a 1 h
  deadline before a no-evidence `Resolve` starts deferring
  (`DISPUTE_WINDOW_SECS`, `stellereum/src/bridge.rs:105`).
- **Reorg.** Record, dispute and bond are committed and restored together per
  height; a reorg can also remove the deposit, after which a challenge tx is
  refused as unknown.

### B-8 Resolve: confirm (false challenge)

- **Entry.** `Resolve` arm, `confirmed_by_math || (confirmed_by_testimony &&
  !fraud_proven)` branch (`stellereum/src/bridge.rs:1684-1706`).
- **Evidence.** Any `DepositProof` bundle in the same payload that verifies for
  the **exact** claim `(chain, source_tx_hash, recipient, amount)`
  (`stellereum/src/bridge.rs:1593-1660`). Math outranks testimony; unverifiable
  evidence is not fraud (`:1635-1637`, `:1651-1660`).
- **Payout.** Clawed `amount` + challenger `bond` to the recipient
  (`stellereum/src/bridge.rs:1702-1706`).
- **Deadline.** None; a false challenge can be answered at any time while the
  dispute is open.
- **Authorization.** Any payer may submit the resolve; the evidence authorizes
  the outcome.

### B-9 Resolve: revoke (verified fraud)

- **Entry.** `fraud_proven` branch (`stellereum/src/bridge.rs:1707-1746`).
- **Evidence.** A quorum **retraction** over
  `STELL_BRIDGE_DEPOSIT_FAILURE_V1 || hash || recipient || amount || chain`,
  verified through the same 2/3 distinct rule
  (`stellereum/src/bridge.rs:807-820`;
  `stellereum/src/bridge_adapters.rs:1034-1048`). This is the only fraud proof
  the layer has; a challenger without quorum keys cannot forge it.
- **Payout.** `bond + reward` to the challenger, burn `amount - reward`;
  `reward = min(amount, max(1, 10% of amount))`
  (`stellereum/src/bridge.rs:95-98`, `:1722-1741`). Conservation is exact:
  `bond + reward + (amount - reward) == amount + bond`
  (`stellereum/src/bridge.rs:1718-1721`).
- **Authorization.** Any payer; the retraction authorizes the outcome.

### B-10 Resolve: defer / refuse (no evidence)

- **Entry.** `now >= dispute.deadline` branch
  (`stellereum/src/bridge.rs:1747-1778`).
- **Behavior.** If the deferral bound is not exhausted, push the deadline one
  window out and move no coins (`:1760-1767`). Past the bound, return `Err`
  (the transaction fails, no payout, dispute stays open) (`:1768-1777`).
- **Bound.** `deposited_at + 24 h + 4 * 1 h` (`:1753-1759`;
  `MAX_RESOLVE_DEFERRALS = 3`, `:126-128`).
- **Important.** A dispute that nobody resolves is never auto-resolved: the
  bound only applies when a `Resolve` is attempted. The clawed amount and the
  bond stay in escrow indefinitely.

### B-11 External release models (no production caller)

- **Types.** `MultisigRelayer` (`stellereum/src/bridge.rs:1912-1971`),
  `TonMultisigReleaseOrder` (`:2022-2063`), `EvmReleaseOrder` (`:2152-2219`).
- **Authorization.** `MultisigRelayer::try_release` requires `!released.contains(op_id)`,
  a non-empty validator set, and `count_signers >= threshold`
  (`stellereum/src/bridge.rs:1950-1970`). `TonMultisigReleaseOrder::is_approved`
  and `EvmReleaseOrder::is_approved` check expiry and the same threshold
  (`:2058-2063`, `:2203-2219`). The EVM order refuses non-EVM chains to stop a
  signature transplant through the `"UNK"` tag (`:2207-2217`).
- **What is signed.** TON: `"TON_MULTISIG_RELEASE_V1" || op_id || recipient
  || amount || expires_at` (`:2047-2055`). EVM: `"EVM_TELEPORT_RELEASE_V1" ||
  chain tag || op_id || token || recipient || amount || nonce || expires_at`
  (`:2186-2201`).
- **State.** `released` is an in-memory `HashSet<[u8; 32]>` keyed by `op_id`
  only, with no chain component and no persistence path in this repository
  (`stellereum/src/bridge.rs:1912-1916`). The doc comment states the operator
  rule and the double-pay risk (`:1896-1910`).
- **Call sites.** `grep -rn "try_release\\|is_approved" stellereum/src` finds
  only definitions and tests; there is **no production caller** in this
  repository. The external leg is therefore NOT IMPLEMENTED here; the
  `executed` flag has no on-chain consumer.
- **Reorg / timeout.** Not applicable on this chain: the order is an off-chain
  object with a caller-set `expires_at`; the native chain neither stores nor
  expires it.

### B-12 Read / observability paths

| Surface | Entry | Reads | Trust |
| --- | --- | --- | --- |
| `stell_bridgeDeposit` | `stellereum/src/rpc/reads.rs:1763-1822` | one `DepositRecord` | committed state, no auth in handler |
| `stell_bridgeDispute` | `stellereum/src/rpc/reads.rs:1823-1853` | one `Dispute` | committed state |
| `stell_bridgeDepositPrepare` | `stellereum/src/native_api.rs:1499-1551` | replay/record preconditions | prepares bytes only; no state write |
| `stell_bridgeWithdraw` | `stellereum/src/native_api.rs:1553-1593` | escrow mirror for display | prepares bytes only |
| `stell_bridgeStatus` | `stellereum/src/native_api.rs:1595-1647` | deposit or withdrawal by hash/id | committed state |
| `stell_bridgeAttestStatus` | `stellereum/src/native_api.rs:1722-1802` | admission path + dispute | committed state; reports a settled quorum, not a partial count |
| `stell_bridgeReleaseEstimate` | `stellereum/src/native_api.rs:1804-1881` | `escrow_balance`, `unlock_at`, `executed`, wall clock | **estimate only** |
| `stell_bridgeDeposits` | `stellereum/src/native_api.rs:1883-1949` | paginated records by recipient | committed state |

The native namespace is dispatched from the read path
(`stellereum/src/rpc/reads.rs:2885-2899`); the handlers themselves perform no
authorization. These surfaces have **no attestation, no quorum, no timeout and
no reorg behaviour of their own**: `prepare` methods return unsigned bytes and
never write; `status`/`attest`/`estimate`/history read committed state (plus a
wall clock for countdowns) and cannot change a verdict. `display_now_secs()` is
wall clock
(`stellereum/src/native_api.rs:1672-1674`, backed by
`stellereum/src/zkml.rs:175-180`), while every authoritative deadline is
compared against `block.timestamp` in settlement (see the `clock_note` at
`stellereum/src/native_api.rs:1877`).

### B-13 Offline watcher models (not wired to consensus)

`TonWatcher` (`stellereum/src/bridge.rs:1828-1886`) and `EvmWatcher`
(`stellereum/src/bridge.rs:2091-2147`) track a monotonically advancing head,
require a hard confirmation depth, refuse a transaction ahead of the head
(`:1855-1864`, `:2117-2123`), and dedup by hash or `(tx_hash, log_index)`.
They are **offline models**: the adapter module states this directly
(`stellereum/src/bridge_adapters.rs:3-8`), and a repository-wide grep finds no
production call site outside `bridge.rs` and tests. They do not protect the
live consensus path.

### 1.2 What is *not* a bridge path (to prevent over-claiming)

- The zk-proof gate in `process_deposit` is **vacuous on the consensus path**:
  `deposit_event` always sets `zk_proof: None`
  (`stellereum/src/bridge.rs:485-506`), and `BridgeState::engine` rebuilds an
  empty model registry (`:1245-1250`). It is live only for an operator-seeded
  offline engine (`:698-720`). "Bridge deposits are zk-gated" is false on the
  live path; the code says so (`:463-471`).
- There is no on-chain per-chain reserve, collateralization, or proof of
  reserves. The bridge-specific bounds are the cumulative 100M STELL mint cap
  and the hourly window (`stellereum/src/bridge.rs:41-46`, `:735-749`); on top
  of them the global supply cap is reserved by `reserve_mint_nano`
  (`stellereum/src/state_engine/settlement.rs:1759-1769`).
- There is no bridge-specific pause or emergency stop in `bridge.rs`.

---

## 2. Assets and actors

### 2.1 Assets

| Asset | Where it lives | Who can take it / freeze it |
| --- | --- | --- |
| Native STELL supply (minted by deposits) | ordinary account balances | a 2/3 attester coalition, bounded by 100M cumulative and 500k/hour (`stellereum/src/bridge.rs:41-46`) |
| Escrowed STELL | `BRIDGE_ESCROW` account `[0xB7; 32]` (`stellereum/src/bridge.rs:169`) | refund, dispute-payout and burn paths only; release never debits it (I-3, I-4) |
| Challenge bonds | escrow, `Dispute::bond` | locked until a `Resolve`; can be locked forever if nobody resolves |
| Dispute payouts | escrow | confirm/revoke rules (`stellereum/src/bridge.rs:1684-1746`) |
| Foreign-chain assets (wSTELL jetton, ERC-20, etc.) | outside this repository | a 2/3 relayer coalition via off-chain release orders; **no code here enforces it** |
| Refund right (liveness) | `pending_withdrawals` entry, unexecuted | any payer can extinguish it with `Release` (B-5) |
| Replay-set / state-root integrity | committed domain | a non-deterministic quorum verdict can split the chain (A-3) |
| Foreign deposit (user's source-chain funds) | foreign chain | frozen if no attestation ever arrives (A-4) |

### 2.2 Actors

| Actor | Capability | Alone | Needs N-of-M |
| --- | --- | --- | --- |
| Any account / tx payer | submit any intent; pay gas; post a bond | `Withdraw`, `Release`, `Refund` (sender only), `Challenge`, `Resolve` (with evidence), reads | — |
| Deposit recipient | receives minted STELL; may spend immediately | spend before a challenge lands | — |
| Bonded validator / attester | sign deposits, headers, retractions, release orders | withhold (censor); one signature is 1 distinct | 2/3 to mint, revoke, or release externally |
| Node operator | chooses local Falcon key file, `STELL_PEER_PQ_KEYS`, data dir, clock | poison this node's quorum verdict; desync its state root | a 2/3 stake coalition to change the committed set |
| Off-chain relayer (not in repo) | persist/replay `released`; choose when to broadcast a signed order | delay, censor, double-broadcast after restart | 2/3 keys to sign a new order |
| Challenger / watcher | freeze a quorum-path deposit for the bond | freeze for at least one window, indefinitely if nobody resolves; cost = bond | evidence/quorum to resolve |
| Oracle publisher | **no bridge role** | nothing in the bridge reads a price | — |
| Governance / staking | changes the bonded validator set | changes the bridge quorum immediately (no snapshot) | — |

### 2.3 Single actor vs threshold

- **One compromised attester (n >= 2).** Cannot mint: one distinct signature is
  below `ceil(2n/3)`. Can withhold, and can leak the claim. At `n = 1` the
  threshold is 1 (`stellereum/src/bridge.rs:534-536`) and a single key mints,
  releases and revokes alone; there is no configuration guard against `n = 1`.
- **One compromised relayer process (keys not compromised).** Can censor,
  reorder, refuse to broadcast, and lose the in-memory `released` set on
  restart; cannot forge a signature.
- **One compromised node operator.** Can register a false Falcon key for any
  validator id on **that node** (`STELL_PEER_PQ_KEYS`,
  `stellereum/src/node/consensus_driver.rs:308-328`), making that node accept a
  forged quorum and reject honest ones. If the node proposes, the resulting
  block's state root differs from honest nodes.
- **A 2/3 attester coalition.** Mints up to the cap, signs any header/root,
  retracts any deposit, and signs arbitrary external release orders.
- **One unauthenticated caller.** Can close the refund window on any matured
  withdrawal (B-5/A-13).
- **One challenger with a bond.** Can freeze a quorum-path deposit for at
  least one dispute window, and indefinitely if nobody resolves; costs the
  bond, returned plus compensation on confirm.

---

## 3. Attack catalog

Each entry states the precondition, the steps, the impact, the mitigation that
exists **today** (with citations), the residual risk, and the test that should
exist. `EXISTS` means a test in this repository already pins the property;
`SHOULD EXIST` means it does not.

Coverage of the required catalog:

| Required attack | Entry |
| --- | --- |
| Double-spend of a release | A-1 |
| Replay across shards/chains | A-2 |
| Forged attestation/quorum | A-3 |
| Stuck deposit with no timeout exit | A-4 |
| Griefing by never-attesting | A-5 |
| Reorg during the dispute window | A-6 |
| Oracle manipulation of the release estimate | A-7 (no oracle exists) |
| Key compromise of an attester | A-8 |
| Cross-shard escrow inconsistency | A-9 |
| Refund-after-release theft | A-10 |
| Unpunishable fraud after the funds move | A-11 |
| Uncontestable evidence-path forgery | A-12 |
| Unauthenticated `Release` / refund freeze | A-13 |
| Committed-state bloat | A-14 |

### A-1 Double-spend of a release (external leg paid twice) — **S0 once a relayer is deployed; the external leg is not in this tree**

**Precondition.** A parked withdrawal exists; a relayer signs a foreign release
order; the relayer's dedup state is memory-only
(`stellereum/src/bridge.rs:1912-1916`).

**Steps.**
1. User calls `Withdraw`; amount is parked (`stellereum/src/bridge.rs:1472-1483`).
2. At `unlock_at`, a relayer signs `EvmReleaseOrder` / `TonMultisigReleaseOrder`
   and broadcasts; the foreign chain pays.
3. The relayer restarts, or a second instance lacks the record, and signs or
   re-broadcasts the same `op_id`. `MultisigRelayer::released` was wiped
   (`stellereum/src/bridge.rs:1896-1901`).
4. If the foreign contract does not dedup on `op_id`, it pays again. The native
   chain cannot see either payment, so nothing fails closed.

**Impact.** The bridge's foreign reserve is drained; the native `executed` flag
is unrelated to how many times the foreign leg paid.

**Current mitigation.**
- A second **local** `Release` is refused (`stellereum/src/bridge.rs:938-940`;
  test `stellereum/tests/bridge_onchain_tests.rs:402-504`).
- `MultisigRelayer::try_release` refuses a repeated `op_id` in memory
  (`stellereum/src/bridge.rs:1956-1958`).
- The operator rule to persist and re-check is documented
  (`stellereum/src/bridge.rs:1896-1910`).

**Residual.** **NOT IMPLEMENTED**: a durable, chain-scoped release receipt.
`released` is not committed state, not persisted by any code in this repository,
and keyed by `op_id` alone. There is no production caller to enforce the rule.
Any deployed relayer is one restart away from a double-pay unless it
independently journals and queries the foreign contract.

**Tests.** EXISTS: local double-release refusal
(`stellereum/tests/bridge_onchain_tests.rs:402-504`). SHOULD EXIST: a restart /
double-broadcast test with a persisted `released` set; a test that the release
order's `op_id` is derived from `(chain, req_id)` and that a replay on another
chain is refused.

### A-2 Replay across shards / chains — **S1 (theft blocked; liveness/DoS residual)**

**Precondition.** The same `source_tx_hash` is claimed on two chains, or an
`op_id` is reused across chains.

**Steps (deposit).**
1. A real deposit exists on chain A with hash `H`.
2. Attacker submits `Deposit { chain: B, source_tx_hash: H, ... }` with a
   quorum or evidence for chain B.
3. The replay set is keyed by `H` alone (`stellereum/src/bridge.rs:1041`), so
   the second claim is refused with `bridge deposit rejected: ...`
   (`stellereum/src/bridge.rs:831-836`, `:1405-1407`). This is fail-closed: no
   double mint, but also no way to credit a legitimate chain-B deposit that
   happens to share a 32-byte hash. A 2/3 quorum cannot override it.

**Steps (release).** `MultisigRelayer.released` is keyed by `op_id` only
(`stellereum/src/bridge.rs:1915`), and `op_id` has no specified derivation from
`(chain, req_id)` (`:2022-2029`, `:2152-2161`). Reusing an `op_id` across chains
blocks a legitimate release (fail-closed), and a foreign contract that dedups
only by `op_id` may reject a valid order.

**Impact.** No theft through the deposit path: the hash-only key is
conservative. Cross-chain `op_id` reuse is a liveness/DoS defect, and a
same-hash collision on a legitimate foreign deposit is permanently
uncreditable.

**Current mitigation.**
- Committed replay set, both deposit paths
  (`stellereum/src/bridge.rs:831-836`, `:1405-1407`, `:1453`).
- Chain bound into the deposit preimage
  (`stellereum/src/bridge.rs:775-781`).
- EVM order binds a chain tag and refuses non-EVM chains
  (`stellereum/src/bridge.rs:2189-2193`, `:2207-2217`).
- Shard gate for bridge intents (`stellereum/src/state_engine/apply.rs:887-891`).

**Residual.** The replay set cannot distinguish two chains by design. A
chain-scoped `op_id` is **NOT IMPLEMENTED**.

**Tests.** EXISTS: same-block and later-block replay
(`stellereum/tests/bridge_onchain_tests.rs:348`;
`stellereum/tests/bridge_oracle_audit_tests.rs:157`); workchain-sourced
refusal and replay (`stellereum/tests/bridge_onchain_tests.rs:1534`, `:1674`);
EVM order refuses a non-EVM chain
(`stellereum/tests/bridge_oracle_audit_tests.rs:586`). SHOULD EXIST: the same
hash claimed on two chains credits exactly one and refuses the other
deterministically; `op_id` includes the chain.

### A-3 Forged attestation / quorum — **S1 (S0 on a single-node deployment, or if the poisoned node's block is finalized)**

**Precondition.** The attacker can get a Falcon key counted for a validator id
that is in the committed set. Two routes exist: (a) `>= 2/3` of the bonded keys
are compromised (then this is A-8), or (b) one node's local PQ registry is
poisoned, and that node is used to propose or to judge a block.

**Steps.**
1. The operator sets `STELL_PEER_PQ_KEYS` to an attacker-controlled key under a
   validator's Ed id, or a local key file is replaced
   (`stellereum/src/node/consensus_driver.rs:283-328`).
2. `get_validator_pq_key(id)` returns the attacker key on that node
   (`stellereum/src/consensus/rotation.rs:109-112`).
3. A deposit carrying attacker Falcon signatures for enough poisoned ids to
   reach `bridge_threshold` is admitted on that node
   (`stellereum/src/bridge.rs:574-588`, `:618-631`).
4. Honest nodes resolve the real keys and refuse the same transaction. If the
   poisoned node proposes the block, its state root diverges; if honest nodes
   are a quorum, the block is rejected and the poisoned node forks or stalls.

**Impact.** On the poisoned node: forged mint. Across the network: a consensus
split or a halt (the bridge verdict is part of the state root,
`stellereum/src/commitment.rs:1497-1510`).

**Current mitigation.**
- DISTINCT signer counting, one vote per id
  (`stellereum/src/bridge.rs:606-631`).
- An unknown signer aborts the entire bundle with `Err`
  (`stellereum/src/bridge.rs:612-617`).
- Only a registered Falcon-512 key counts; Ed25519 never does
  (`stellereum/src/bridge.rs:618-629`).
- Empty validator set fails closed
  (`stellereum/src/bridge.rs:1306-1314`, `:603-605`).
- Validator **ids** are the committed staking set
  (`stellereum/src/state_engine/apply.rs:877-881`).

**Residual.** **NOT IMPLEMENTED**: committed PQ key material. The registry is a
process-global `RwLock<HashMap>` populated from local configuration
(`stellereum/src/consensus/rotation.rs:5-10`), and the protocol documentation
states there is no on-chain registry (`stellereum/src/pq_registry.rs:5-7`). The
bridge uses the **head** key (`get_validator_pq_key`), not the height-indexed
`pq_key_at_height` (`stellereum/src/consensus/rotation.rs:64-76`), so a rotation
is not resolved at the deposit's height. Two nodes with the same committed
state can reach different bridge verdicts.

**Tests.** EXISTS: outsider/forged signatures refused at engine and plan
(`stellereum/tests/bridge_oracle_audit_tests.rs:96`); duplicate signer counts
once (`stellereum/src/bridge.rs:2837-2860`); unknown key fails closed
(`stellereum/src/bridge.rs:2863-2887`); Ed signatures never count
(`stellereum/src/bridge.rs:2889-2911`); pure-PQ refusal
(`stellereum/src/bridge.rs:2732-2774`). SHOULD EXIST: two engines with identical
committed state but different local PQ registries must reach the **same**
verdict (this currently fails by construction); the bridge verdict must not
depend on an environment variable.

### A-4 Stuck deposit with no timeout exit — **S1**

**Precondition.** A user sends funds to the bridge address on a foreign chain.

**Steps.**
1. The deposit lands on TON/Ethereum/Arbitrum/Solana.
2. No relayer ever attests (offline, censoring, or no key configured).
3. There is no `Deposit` timeout, cancel, or expiry variant
   (`stellereum/src/bridge.rs:232-377`), and no committed "pending inbound"
   record: the chain only learns of the deposit when a quorum authorizes it.
4. The evidence path is not an exit: it still requires a 2/3 quorum over the
   header (`stellereum/src/bridge_adapters.rs:644-665`).

**Impact.** The user's source-chain funds are frozen with no native claim and
no on-chain remedy. The only possible exit is a refund on the foreign bridge
contract, which is outside this repository and is not part of this design.

**Current mitigation.** None. The deposit must be quorum-attested; that is a
security property, but it is not an exit.

**Residual.** **NOT IMPLEMENTED**: inbound timeout/refund, or a permissionless
fallback proof. Any claim that users can recover a stuck deposit from this chain
is false.

**Tests.** SHOULD EXIST: a test that no code path credits without quorum (the
converse is already covered by `sub_quorum_deposit_is_refused...`,
`stellereum/tests/bridge_onchain_tests.rs:205`), plus a runbook test/doc that
pins the foreign-side refund as the only exit.

### A-5 Griefing by never-attesting — **S1**

**Precondition.** A coalition of at least `n - threshold + 1` validators (just
over one third for large `n`; 2 of 3 when `n = 3`) wants to censor a specific
claim, or enough validators are offline to keep a claim below threshold.

**Steps.**
1. The claim is otherwise valid (real foreign deposit, correct tuple).
2. The coalition withholds signatures for that `source_tx_hash` only.
3. The deposit never reaches `bridge_threshold`
   (`stellereum/src/bridge.rs:574-588`); other deposits still pass.
4. As in A-4, there is no timeout and no alternate proof path.

**Impact.** Targeted, repeatable censorship of chosen depositors; funds frozen
on the source chain. No native loss, but a credible bridge cannot tolerate it.

**Current mitigation.** None beyond the threshold: 2/3 liveness is assumed.
There is no fraud proof of non-attestation, no challenge for "you should have
signed", and no fallback.

**Residual.** **NOT IMPLEMENTED**. The threshold makes the coalition described
above a censor; the code is explicit that a sub-quorum claim is refused
(`stellereum/src/bridge.rs:1401-1413`).

**Tests.** EXISTS: sub-quorum deposit credits nothing
(`stellereum/tests/bridge_onchain_tests.rs:205`, `:252`). SHOULD EXIST: a
property test that every `Credit` is preceded by a verifying quorum (A-5 is a
liveness gap, not a soundness gap, and should be documented as such).

### A-6 Reorg during the dispute window — **S1**

**Precondition.** A bridge transition lands in a Stellereum block that is later
reorged before finality, or a foreign chain reorgs deeper than the confirmation
constant after a credit.

**Steps (Stellereum reorg).**
1. A deposit is credited in block `H`; a relayer observes `executed`/`confirmed`
   (or a watcher sees the credit) and acts externally.
2. A competing branch wins; the engine is restored to the per-height accounts
   snapshot and the per-height bridge snapshot
   (`stellereum/src/storage.rs:3142-3146`, `:1767-1770`).
3. The native mint, replay entry, dispute and bond are rolled back; the
   external action is not. If the same source transaction is re-claimed on the
   canonical branch, it credits again (correct for the native ledger) while the
   first external action may already have paid.

**Steps (foreign reorg).**
1. A quorum signs a header at height `h` with `finalized_* = f`, satisfying
   `f - h >= min_confirmations` (`stellereum/src/bridge_adapters.rs:670-691`).
2. The foreign chain reorgs `h` away.
3. Nothing on this chain observes it; the credit stands. Only a challenge on a
   quorum-path deposit can claw it back, and only while the recipient still
   holds the funds (A-11).

**Impact.** External payment without a surviving native debit (or vice versa);
a dispute outcome that reverses after an off-chain actor treated it as final.

**Current mitigation.**
- Committed bridge domain + per-height snapshots
  (`stellereum/src/storage.rs:1245-1262`, `:3142-3146`;
  `stellereum/src/commitment.rs:1497-1510`).
- BFT finality means a finalized block cannot be reorged without more than one
  third of the stake equivocating.
- The rollback of a failed payload is all-or-nothing
  (`stellereum/src/state_engine/settlement.rs:1823-1869`).

**Residual.** **NOT IMPLEMENTED**: a finality gate on credit, a finality-aware
relayer rule, or a reorg-aware dispute clock. `deposited_at` is the block
timestamp of an unfinalized block (`stellereum/src/bridge.rs:1397`). Restoring
accounts and the bridge domain is two separate sled-tree reads/writes, so a
crash between them can leave the replay set and the balances at different
heights (`stellereum/src/storage.rs:3142-3146`).

**Tests.** EXISTS: dispute state is committed in the root
(`stellereum/tests/bridge_dispute_tests.rs:838`); the replay set survives
snapshot/restore (`stellereum/tests/bridge_persistence_tests.rs:190`).
SHOULD EXIST: credit in an unfinalized branch then reorg -> native mint,
replay entry and open dispute all roll back and the same foreign tx can be
re-claimed exactly once; a crash between the accounts restore and the bridge
restore must fail closed on boot.

### A-7 Oracle manipulation of the release estimate — **S3 (not applicable to the amount)**

**Precondition.** A wallet or bot treats `stell_bridgeReleaseEstimate` as
authoritative.

**Steps.** There is no price oracle in the bridge at all: a repository-wide
grep finds no `oracle` reference in `bridge.rs`, `bridge_adapters.rs`, or the
bridge handlers. The estimate is computed from committed
`escrow_balance`, `unlock_at`, `executed`, and `now_secs()`
(`stellereum/src/native_api.rs:1824-1839`). The amount is the parked nano-STELL
amount, fixed at `Withdraw` time (`stellereum/src/bridge.rs:885-929`). An
attacker cannot change it by moving an oracle price.

**Impact.** A caller can be misled about readiness (wall-clock skew), but
settlement re-checks the block clock (`stellereum/src/bridge.rs:942-947`) and
the actual balances (`stellereum/src/state_engine/settlement.rs:1737-1748`), so
a wrong estimate is refused, not paid. `escrow_funded` is per-request
(`stellereum/src/native_api.rs:1835`), not an aggregate coverage check, so it
can read true while the sum of obligations is larger; settlement still fails
closed.

**Current mitigation.** The response labels the estimates and states that
settlement uses the block timestamp (`stellereum/src/native_api.rs:1877`).

**Residual.** **NOT IMPLEMENTED**: a block-height-based estimate. The mirror can
also be stale after a non-atomic restore (see I-3b and A-6). No fund-loss path.

**Tests.** EXISTS: estimate before/after unlock
(`stellereum/src/native_api.rs:3076`). SHOULD EXIST: a test that a wall clock
far in the future cannot make a `Release` or `Refund` apply, and that the
estimate reports the block-clock values it claims to.

### A-8 Key compromise of an attester — **S1 (S0 at n = 1 or >= 2/3)**

**Precondition.** One validator's Falcon-512 private key is compromised.

**Steps.**
1. The attacker signs any `deposit_signing_message`, header, retraction, or
   release order for that validator id.
2. One signature is one distinct signer; with `n = 1` the threshold is 1 and
   the attacker mints alone (`stellereum/src/bridge.rs:534-536`). With `n >= 2`
   the attacker needs `threshold - 1` more keys.
3. With a quorum, the attacker can also sign a **retraction** of an honest
   deposit (`stellereum/src/bridge.rs:807-820`) and revoke it, or sign a header
   for a nonexistent foreign block (A-12).

**Impact.** Below threshold: denial and metadata leakage. At/above threshold:
minting up to the 100M cumulative cap (rate-shaped), arbitrary foreign releases,
and reversible honest deposits.

**Current mitigation.**
- Distinct-Falcon counting and per-claim preimages
  (`stellereum/src/bridge.rs:574-633`, `:769-782`).
- Deposit caps and the challenge window
  (`stellereum/src/bridge.rs:735-749`, `:1503-1568`).
- The retraction needs the same 2/3 (`stellereum/src/bridge.rs:1671-1677`).

**Residual.** **NOT IMPLEMENTED**: bridge-specific slashing for double
attestation or conflicting attestation/retraction. A validator can sign two
different deposits at the same height with no on-chain consequence (the replay
set dedups by source hash, not by signer behaviour). There is no bridge key
rotation that keeps a dispute's evidence valid (section 5.5). `n = 1` is
accepted by configuration and is a single point of failure.

**Tests.** EXISTS: one distinct signer cannot release
(`stellereum/src/bridge.rs:2856-2859`); duplicate signing counts once
(`stellereum/src/bridge.rs:2837-2855`). SHOULD EXIST: conflicting attestations
by one validator are detectable and slashable; `n = 1` is refused at bridge
configuration time.

### A-9 Cross-shard escrow inconsistency — **S1**

**Precondition.** Sharding is enabled and bridge intents can be applied by
more than one engine, or two nodes disagree on the node-local
`cross_shard_enabled` flag.

**Steps.**
1. The bridge domain (escrow, replay set, counters, disputes) is per-engine
   state; each engine has its own `bridge` lock
   (`stellereum/src/state_engine/accounts.rs:2173-2184`).
2. The only shard gate is conditional on a **node-local** flag:
   `!bridge_intents.is_empty() && self.cross_shard_enabled() &&
   tx.source_shard != MASTERCHAIN_SHARD`
   (`stellereum/src/state_engine/apply.rs:887-891`).
3. A node with the flag off settles a workchain-sourced bridge transaction; a
   node with it on refuses it. The state roots diverge. The same file's own
   rule for actor sends says a consensus rule must not depend on that flag
   (`stellereum/src/state_engine/apply.rs:465-468`).
4. Even with the flag on, a sender can sign `source_shard = MASTERCHAIN` (the
   field is in the signed preimage,
   `stellereum/src/sharding/transaction.rs:1319-1330`), so the gate trusts a
   signed claim rather than a routing check. A masterchain proposer must
   independently validate `tx_belongs_to_shard`
   (`stellereum/src/runtime/consensus_step.rs:349-368`;
   `stellereum/src/sharding/topology.rs:399-401`).

**Impact.** A double credit against per-engine state if the same intent is
settled on two engines; a consensus split; or a debit applied to the wrong
shard's balance map.

**Current mitigation.**
- Masterchain-only gate (when the flag is on).
- Proposal-time shard scope check and `tx_belongs_to_shard`.
- Domain committed to the state root.

**Residual.** **NOT IMPLEMENTED**: an unconditional, consensus-state rule that
the bridge domain exists on exactly one shard. The gate's dependence on a
process flag is exactly the class of bug the actor-send comment warns about.
Single-shard mode is the only mode with a test.

**Tests.** EXISTS: workchain bridge intents are refused with cross-shard on
(`stellereum/tests/bridge_onchain_tests.rs:1534`), and a workchain replay stays
refused (`:1674`). SHOULD EXIST: the same block applied on an engine with the
flag on and one with it off yields the same state root; bridge intents are
rejected on every shard except the masterchain by construction.

### A-10 Refund-after-release theft — **S0 once a relayer is deployed; the external leg is not in this tree**

**Precondition.** A withdrawal is not locally `executed` at
`unlock_at + 24 h`, while a relayer has signed (or will sign) a foreign payout.

**Steps.**
1. `Withdraw` parks the amount (`stellereum/src/bridge.rs:1472-1483`).
2. A relayer prepares a foreign release but does not call the local `Release`
   (different operator, crash, deliberate delay), or the local `Release` is
   delayed.
3. At `unlock_at + 24 h` the sender calls `Refund`; the request is deleted and
   the native amount is returned (`stellereum/src/bridge.rs:956-984`,
   `:1491-1502`).
4. The relayer later broadcasts the still-valid signed foreign order; the
   foreign chain pays. Both legs have now paid.

**Impact.** Double spend of the parked amount per request. The flow is shaped
by the 500k STELL/h withdrawal window and the 1 h lock on requests >= 50k
STELL, but unreleased requests accumulate across hours, and the loss lands on
the foreign reserve, not on other parkers' balances.

**Current mitigation.**
- `Refund` refuses an `executed` request (`stellereum/src/bridge.rs:966-968`).
- Deleting the request makes a later local `Release` fail
  (`stellereum/src/bridge.rs:980`; test `stellereum/tests/audit_closure_bridge_tests.rs:1248`).
- The relayer is *told* to re-check existence/non-execution at broadcast
  (`stellereum/src/bridge.rs:1903-1910`).

**Residual.** **NOT IMPLEMENTED**: an on-chain release receipt. The chain
cannot distinguish "refunded and never paid" from "refunded after the foreign
leg paid". The window is bounded only by operator discipline
(`stellereum/src/bridge.rs:312-329`). This is the single most likely
fund-loss path in a real deployment.

**Tests.** EXISTS: local release-then-refund and refund-then-release are both
refused (`stellereum/tests/audit_closure_bridge_tests.rs:1209`, `:1248`;
sender/grace guards `:1300`). SHOULD EXIST: refund is refused when a foreign
payout receipt exists; a crash-injection test for "order signed, crash before
broadcast, refund, then broadcast".

### A-11 Challenge cannot claw back spent funds — **S1**

**Precondition.** A fraudulent **quorum-path** deposit has been credited and
the recipient has moved the funds.

**Steps.**
1. A 2/3 coalition credits recipient `R` with `amount`
   (`stellereum/src/bridge.rs:1368-1400`).
2. `R` immediately moves the credited funds out, keeping its balance below
   `amount` (a fresh account that forwards everything works).
3. A watcher submits `Challenge`; settlement's Pass 1 tries to debit `R` and
   fails, so the whole transaction (including the bond) fails
   (`stellereum/src/state_engine/settlement.rs:1714-1719`, `:1737-1748`).
4. No dispute exists, so there is no `Resolve` path and no burn.

**Impact.** Proven or suspected fraud is unpunishable once the funds move; the
minted supply stays. The only remaining bound is the 100M cumulative cap.

**Current mitigation.**
- Challenge is available for 24 h after deposit
  (`stellereum/src/bridge.rs:129-131`, `:1524-1529`).
- Clawback is atomic and fail-closed; it never partially freezes.

**Residual.** **NOT IMPLEMENTED**: an automatic hold of quorum-path deposits
for the challenge window (so the funds cannot be spent before the window
closes), or a debt/slashing model. The current design makes the challenge a
race against the recipient.

**Tests.** EXISTS: a challenge without bond cover is refused
(`stellereum/tests/bridge_dispute_tests.rs:760`). SHOULD EXIST: a challenge of a
deposit whose recipient already spent it is refused, and the supply invariant
records the unrecoverable mint; or a hold-period test that makes the challenge
winnable.

### A-12 Forged SPV header / depth spoof — **S1 (same power as a quorum, but uncontestable and disguised as a proof)**

**Precondition.** A quorum (or one poisoned registry, A-3) signs a header that
does not correspond to any foreign block, or a real header at a false height.

**Steps.**
1. Construct `StoredHeader { chain, height: 0, prev_hash: arbitrary,
   tx_root: H(custom leaf) }`.
2. Sign it with 2/3 distinct Falcon keys; put `finalized_seqno/number/slot =
   u64::MAX` in the evidence.
3. `check_header` passes (chain matches, quorum verifies)
   (`stellereum/src/bridge_adapters.rs:644-665`); `check_depth` passes because
   `height` is 0 and `finalized` is huge (`:670-691`).
4. The TON BoC / EVM MPT / Solana Merkle proof opens the custom leaf under
   `tx_root` (`:768-800`, `:889-913`, `:994-1001`).
5. The deposit credits; `via_quorum = false`, so no `Challenge` is allowed
   (`stellereum/src/bridge.rs:1461-1468`, `:1513-1517`).

**Impact.** Minting for a deposit that never happened, up to the caps, with no
dispute path. This is the same power as a 2/3 quorum on the plain path, but it
is *uncontestable* and it looks like a cryptographic proof in logs, which
invites operators to trust it more than they should.

**Current mitigation.**
- The header needs the same 2/3 quorum
  (`stellereum/src/bridge_adapters.rs:644-665`).
- Chain-tag match and domain-separated custom leaves
  (`:143-192`, `:217-224`).
- Depth-ahead refusal (`:679-683`).
- Deposit caps (`stellereum/src/bridge.rs:735-749`).

**Residual.** **NOT IMPLEMENTED**: header linkage (`prev_hash`), a committed
foreign head, foreign validator signatures, or a challenge for evidence-path
deposits. There is no walk of the header chain on-chain; `HeaderStore` is
off-chain only (`stellereum/src/bridge_adapters.rs:261-264`).

**Tests.** EXISTS: tampered TON/EVM/Solana evidence refused
(`stellereum/tests/bridge_adapters_tests.rs:400`, `:527`, `:627`); header ahead
of the finalized head refused
(`stellereum/tests/bridge_oracle_audit_tests.rs:524`); deterministic
verification (`stellereum/tests/bridge_adapters_tests.rs:746`). SHOULD EXIST: a
header whose `prev_hash`/`height` does not chain to a committed anchor is
refused; evidence-path deposits are challengeable (or the docs state they are
trusted exactly like a quorum).

### A-13 Unauthenticated `Release` closes the refund — **S1**

**Precondition.** Any matured withdrawal (small ones mature immediately).

**Steps.**
1. Attacker observes a pending request, or waits for `unlock_at`.
2. Submits `Release { req_id }` from any account. `plan` does not pass the
   payer to `finalize_withdrawal` (`stellereum/src/bridge.rs:1484-1490`;
   engine `:932-951`).
3. `executed = true`; the sender's `Refund` now fails
   (`stellereum/src/bridge.rs:966-968`).
4. If the relayer never pays the foreign leg, the funds are frozen: the request
   is never deleted, and there is no "unrelease" intent.

**Impact.** Any matured withdrawal can be converted from "refundable" to
"permanently relayer-dependent" for the price of gas. Direct theft only if a
relayer treats `executed` as sufficient authorization (it should not, but the
code provides no other signal).

**Current mitigation.** None. `Release` deliberately does not move coins, so
there is no direct native theft, but the refund right is extinguishable.

**Residual.** **NOT IMPLEMENTED**: sender or relayer authorization on
`Release`, or a paid/unpaid state distinct from `executed`.

**Tests.** `grep` finds no test for a stranger releasing a matured withdrawal;
SHOULD EXIST: `release_by_stranger_is_refused_or_does_not_close_refund`.

### A-14 Committed-state bloat (DoS) — **S2**

**Precondition.** Any funded account.

**Steps.**
1. Submit a dust `Withdraw` with a `target_address` near the 1 MiB wire cap;
   `validate` only checks non-empty (`stellereum/src/bridge.rs:406-408`), and
   the string is committed (`stellereum/src/commitment.rs:1559`).
2. Repeat; each withdrawal also creates a `pending_withdrawals` entry, and each
   deposit creates a permanent `deposit_records` entry; resolved disputes are
   kept forever (`stellereum/src/bridge.rs:1067-1076`).
3. With a compromised quorum, manufacture many deposits; `deposit_records`
   grows without bound.

**Impact.** State growth and digest cost; no direct loss. The wire cap bounds a
single transaction (`stellereum/src/network.rs:3216`), not the lifetime state.

**Current mitigation.** Gas, the hourly rate limit, and the wire cap. Evidence
has explicit caps (`stellereum/src/bridge_adapters.rs:82-96`); the `Attest`
vector does not (`stellereum/src/bridge.rs:411-419`).

**Residual.** **NOT IMPLEMENTED**: a length cap on `target_address`, a cap on
`Attest` signatures, or pruning of old records/disputes.

**Tests.** EXISTS: evidence size caps
(`stellereum/tests/bridge_adapters_tests.rs:761`). SHOULD EXIST: the same cap
test for `Attest` and `target_address`; a bound on retained records.

---

## 4. Invariants that must always hold

Each invariant is stated so it can be encoded as a property test over a
sequence of `(BridgeState, Vec<BridgeIntent>, validators, payer, timestamp)`
transitions. `HOLDS` means the code enforces it today; `PARTIAL` means it holds
only under a precondition; `NOT IMPLEMENTED` means a test would fail or cannot
be written without new state.

### I-1 Supply conservation

`total_supply == genesis_allocation + Σ(credits) - Σ(burns)`, and no account
balance is negative.

- **Status:** HOLDS for the deposit/challenge/resolve paths, pinned by a
  randomized sequence test (`stellereum/tests/audit_closure_bridge_tests.rs:924-973`);
  the test does not generate withdrawals or refunds.
- **Test form:** a `proptest`-style generator over deposits, challenges,
  resolves, withdrawals, refunds and burns; after every step assert
  `ledger.supply() == initial + minted - burned` and `balances >= 0`.
  The existing test is deterministic; widen it to arbitrary sequences and
  include the evidence path.

### I-2 One credit per source transaction

`∀ hash: |{ Credit | source_tx_hash == hash }| <= 1`, across chains, shards,
restarts and reorgs.

- **Status:** HOLDS. The replay set is committed
  (`stellereum/src/bridge.rs:1041`), checked on both deposit paths
  (`:831-836`, `:1405-1407`), and persists across snapshot/restore
  (`stellereum/src/storage.rs:1245-1262`;
  `stellereum/tests/bridge_persistence_tests.rs:190`).
- **Test form:** apply the same `(chain, hash, recipient, amount)` twice in one
  payload and in later blocks; exactly one `Credit` effect; the second attempt
  returns `Err`; repeat after a snapshot/restore and after a reorg.

### I-3 Escrow accounting

Let `E` be the `BRIDGE_ESCROW` account balance and `M` the committed
`escrow_balance` mirror.

- **I-3a:** `E == Σ(Park) - Σ(Unpark) - Σ(Burn) + Σ(Clawback)` over all
  applied effects.
  **Status:** HOLDS by construction: a single delta map
  (`stellereum/src/state_engine/settlement.rs:1686-1728`), with Pass-1
  non-negativity (`:1737-1748`).
- **I-3b:** `M == E` after every settlement and every restore.
  **Status:** PARTIAL. Settlement re-derives `M` from the account
  (`:1784-1788`); `restore_bridge` installs stored bytes without re-deriving
  (`stellereum/src/state_engine/accounts.rs:2209-2240`), so a non-atomic
  accounts/bridge restore can leave them inconsistent.
- **Test form:** after every step assert I-3a and I-3b; inject a crash between
  the two restore trees and require boot to fail closed or re-derive.

### I-4 Escrow covers outstanding obligations

`E >= Σ{ req.amount | req ∈ pending_withdrawals, !req.executed }
    + Σ{ d.amount + d.bond | d ∈ disputes, !d.resolved }`.

- **Status:** HOLDS by construction. `Release` never debits escrow
  (`stellereum/src/state_engine/settlement.rs:1672-1684`), `Refund` debits only
  the request it deletes (`:1706-1713`), and `Burn` is bounded by the clawed
  amount (`:1721-1726`). It is **not asserted anywhere**.
- **Test form:** a sequence property over withdraw/refund/challenge/resolve;
  recompute both sides of the inequality from the committed maps after each
  step. Note the corollary: released amounts stay in escrow forever (no sweep
  intent exists), so escrow accumulates them and decreases only on refund, a
  dispute payout, or a revoke burn.

### I-5 At most one release per withdrawal

`∀ req_id: the number of transitions that set executed=true is <= 1`, and after
`executed=true` a `Refund` returns `Err`.

- **Status:** HOLDS (`stellereum/src/bridge.rs:938-940`, `:966-968`; tests
  `stellereum/tests/bridge_onchain_tests.rs:402-504`,
  `stellereum/tests/audit_closure_bridge_tests.rs:1209`, `:1248`).
- **Test form:** two `Release` intents in one payload and in later blocks; the
  second returns `Err`; a `Refund` after release returns `Err`.

### I-6 No credit without a verifying authorization

`∀ Credit(chain, hash, recipient, amount): the same payload carried either a
2/3 attestation over exactly that tuple, or an evidence bundle that verifies
for exactly that tuple.`

- **Status:** HOLDS for the in-payload relation
  (`stellereum/src/bridge.rs:1373-1377`, `:1416-1449`; the echo is re-checked at
  `:1430-1438`). **NOT IMPLEMENTED** for the stronger statement "a finalized
  foreign event": the attestation's truth is the quorum's word (A-3/A-12).
- **Test form:** for every generated `Credit`, keep the payload and assert a
  verifying bundle exists; then a second property that no bundle with a
  different `(recipient, amount, chain, hash)` admits the deposit
  (`stellereum/tests/bridge_oracle_audit_tests.rs:96` is a special case).

### I-7 No release without a payout authorization

`∀ Release(req_id): the transaction carried a relayer quorum receipt binding
(chain, req_id, amount, recipient, op_id), or the request's sender authorized
it.`

- **Status:** **NOT IMPLEMENTED.** `Release` has no authorization at all
  (`stellereum/src/bridge.rs:1484-1490`, `:932-951`). The valid invariant today
  is only I-5. This is the invariant commonly stated as "no release without a
  finalized attestation"; it is false in the current tree and must be written
  as a target, not as a property that passes.

### I-8 Revoke conservation

On a revoked dispute with amount `a`, bond `b`, reward `r = min(a, max(1,
a*1000/10000))`: `payouts == b + r`, `burn == a - r`, `payouts + burn == a + b`.

- **Status:** HOLDS (`stellereum/src/bridge.rs:95-98`, `:1722-1741`; test
  `stellereum/tests/audit_closure_bridge_tests.rs:442`, `:924`).
- **Test form:** for all `a` (with `b = challenge_bond_for(a)`), assert the
  identity and that the escrow delta sums to zero; include `a = 1`,
  `a = u64::MAX`, and `b` at both the floor and the 1% scale.

### I-9 Challenge payout is bounded by what it froze

`payout_confirm <= amount + bond`; `payout_revoke + burn <= amount + bond`; no
dispute pays from another dispute's escrow.

- **Status:** HOLDS (`stellereum/src/bridge.rs:1693-1706`, `:1722-1736`).
- **Test form:** randomized challenge/resolve sequences, asserting the sum of
  payouts attributable to a dispute never exceeds its `amount + bond`, and
  that `Burn` never exceeds `amount`.

### I-10 Monotone mint counters, with an honest unwind

`total_minted` increases only by a credit and decreases only by the burned
amount of a verified revoke; it never goes below zero and never regains
headroom for the finder reward.

- **Status:** PARTIAL. `note_revoke(burn)` is saturating
  (`stellereum/src/bridge.rs:751-766`), which can under-count after a window
  roll (documented, not a safety break). The no-free-headroom property is
  pinned by `stellereum/src/bridge.rs:2471-2520`.
- **Test form:** the P5 cycle test generalized over amounts and window resets;
  assert `total_minted` never exceeds `BRIDGE_MINT_CAP_NANO` and that a
  revoke+re-deposit cycle never recovers the full deposit.

### I-11 Cross-node determinism

Two nodes with the same committed state, the same validator set and the same
transactions reach the same bridge verdict and the same state root, regardless
of local configuration.

- **Status:** **NOT IMPLEMENTED** as stated. The Falcon key registry is local
  (`stellereum/src/consensus/rotation.rs:5-10`, `:109-112`;
  `stellereum/src/node/consensus_driver.rs:283-328`), and the bridge resolves the
  head key, not a height-indexed committed key (`:64-76`).
- **Test form:** two engines with identical `BridgeState` and identical
  `validators` but different `PQ_VALIDATOR_KEYS`; apply the same deposit and
  assert the same result. Today this test would fail; it is the gate for the
  fix.

### I-12 Bridge domain lives on exactly one shard

No engine other than the masterchain can apply a bridge intent, independent of
node-local flags.

- **Status:** PARTIAL. It holds when `cross_shard_enabled()` is true and the tx
  names a workchain (`stellereum/src/state_engine/apply.rs:887-891`); it is not
  a consensus rule, and it depends on a process flag (A-9).
- **Test form:** apply the same bridge payload on an engine with the flag on
  and one with it off; require identical results and identical roots.

---

## 5. What is not modelled yet, and what it would cost to close

Costs are engineering estimates (design + implementation + tests + review),
not commitments. They assume one engineer familiar with the crate.

### 5.1 Threshold attestations

Today each deposit carries individual Falcon-512 signatures and the verifier
counts distinct registered keys (`stellereum/src/bridge.rs:574-633`). There is
no aggregate/threshold signature, so the wire and verification cost is O(n) per
deposit, and `Attest` has no count cap (`:411-419`). The threshold is a count of
keys, not a cryptographic threshold.

**Cost to close:** 2-4 engineer-weeks for a threshold/aggregate scheme, but it
changes the signed preimage and the frozen bridge wire format; add an audit and
a migration. A cheaper intermediate (cap `Attest`, reject signatures beyond
`MAX_HEADER_SIGNATURES`) is hours.

### 5.2 Light-client proofs of the foreign chain

There is no committed header chain for TON, Ethereum, Arbitrum or Solana. The
current "SPV" evidence carries its own header and its own quorum
(`stellereum/src/bridge_adapters.rs:483-533`, `:644-665`); the leaves are
Stellereum's own encodings (`:143-192`), not foreign events. Closing this means
per-chain light clients:

- Ethereum: sync-committee / header-chain verification and real RLP receipt
  decoding (MPT keys are currently `sha256(tag || hash || log_index)`,
  `stellereum/src/bridge_adapters.rs:153-159`, not Ethereum's
  `keccak(rlp(index))`).
- Arbitrum: the rollup's own finality/assertion model, not a 32-block constant.
- TON: shard-block cell layout, masterchain finality, real transaction parsing
  (today the BoC must decode to our leaf, `:768-800`).
- Solana: PoH/bank hash and transaction Merkle layout (today a binary tree over
  our leaves, `:994-1001`).
- A committed header store in consensus state, with fork choice and per-chain
  validator-set anchoring.

**Cost to close:** 3-6 months for one chain, 6-12 months for all four routes,
plus an external audit. This is the only way to remove the 2/3 trust
assumption, and it is a different architecture, not a fix in `bridge.rs`.

### 5.3 Economic finality of the source chain

The depth constants are policy numbers (TON 12, Ethereum 64, Arbitrum 32,
Solana 32; `stellereum/src/bridge.rs:143`, `:2070-2071`;
`stellereum/src/bridge_adapters.rs:96`), and the finalized head is supplied by
the evidence (`:498-500`, `:510-512`, `:523-525`). There is no source-chain
finality oracle, no bond for a reorg, and no slashing for attesting a reorged
block.

**Cost to close:** 3-6 engineer-weeks for a bond/slashing design once a
light-client or an attested finality oracle exists; without 5.2 it is only a
stronger quorum promise, not economic finality.

### 5.4 On-chain release receipt / foreign payout proof

Nothing on this chain records that the external leg paid. `executed` is a local
flag (`stellereum/src/bridge.rs:510-519`), the relayer's `released` set is
memory (`:1912-1916`), and a refund can race a late payout (A-10).

**Cost to close:** 2-4 engineer-weeks for a new intent/state field plus a
migration, a relayer protocol change, and a frozen-core review. This is the
highest value per week in the whole list.

### 5.5 Bridge-specific validator set and key rotation

The bridge uses the entire bonded staking set
(`stellereum/src/state_engine/apply.rs:877-881`) and a node-local key registry
(A-3). There is no per-deposit snapshot of the set, so a challenge or resolve
after a rotation verifies evidence against the new set: old attestations can
become "unknown signer" and a challenged deposit can become unconfirmable by
its recipient alone
(`stellereum/src/bridge.rs:1597-1677`; the threshold is recomputed from the
current `validators`).

**Cost to close:** 2-4 engineer-weeks to store the set/PQ keys at deposit time
on `DepositRecord` and resolve keys at that height. It touches staking and the
frozen bridge state layout, so it needs a spec and a migration.

### 5.6 Censorship-resistant inbound fallback

A-4/A-5 have no on-chain exit. A fallback that does not trust the quorum
requires 5.2 (a foreign inclusion proof), or a permissionless challenge with a
source-chain proof. Within the current architecture there is no honest fix;
the correct move is to document the foreign-side refund as the only exit and
treat quorum liveness as a hard operational requirement.

**Cost to close:** cannot be closed inside the current architecture; depends on
5.2. Documentation/runbook work: 1-2 days.

### 5.7 Relayer economics and operations

No relayer daemon, no bridge fee model, no bridge-specific monitoring, and no
key-ceremony procedure exists in this repository. `MultisigRelayer`,
`TonMultisigReleaseOrder` and `EvmReleaseOrder` are models only (B-11). A
production deployment needs a durable journal, a chain-scoped `op_id`, a
pre-broadcast existence/paid check, and an incident runbook.

**Cost to close:** 3-5 engineer-weeks for a minimal daemon plus a runbook; the
on-chain half is 5.4.

### 5.8 Smaller omissions

- `target_address` is unvalidated beyond non-empty (A-14).
- `Attest` has no signature cap (A-14).
- Resolved disputes and deposit records are never pruned
  (`stellereum/src/bridge.rs:1067-1076`).
- No fuzz target for the bridge evidence decoders (the `fuzz/` directory has
  block/cert/consensus/EVM-raw-tx/frame/peer/transaction targets, not
  BoC/MPT/Merkle).
- The SVM comment at `stellereum/src/svm.rs:2855-2856` says quorum, replay and
  rate limit are "NOT enforced yet"; they are enforced at settlement
  (`stellereum/src/bridge.rs:1294-1805`). The comment is stale and misleading
  to an auditor.
- `BridgeState::plan` can be called with a `Deposit` and a `Challenge` for the
  same hash in one payload (`stellereum/src/bridge.rs:1503-1517`); the checks
  are sound, but the interaction deserves a test.

---

## 6. Prioritized follow-ups for the fix wave

Ordered by "loss of funds" first, then freeze, then consensus, then
hardening. Each item cites the attack(s) it closes and an estimated size
(S = days, M = 1-3 weeks, L = 3+ weeks). Nothing here proposes an EVM
contract, an external bridge, or a feature outside the current architecture.

### P0 - loss of funds

1. **On-chain release receipt and idempotent payout (L).**
   Add committed state binding `(chain, req_id, amount, recipient, op_id)` to a
   relayer-quorum-signed "paid" transition; make `Refund` consult it and make
   the relayer require it before broadcasting. Closes A-1 and A-10; makes I-7
   implementable. Touches frozen bridge state: spec + migration + audit.
2. **Commit the bridge validator set and PQ keys, or snapshot them per
   deposit/dispute (L).** Resolve keys from committed state at the relevant
   height instead of the process-global registry. Closes A-3, A-8's rotation
   half, and I-11. If full commitment is too large for this wave, store the
   set and key hashes on `DepositRecord`/`Dispute` and verify against that.
3. **Authorize `Release` (S).** Until the receipt exists, at minimum require
   `payer == req.sender` (or a relayer quorum) so a stranger cannot close the
   refund window. Closes A-13.
4. **Make the refund/payout race explicit (M).** Persist the relayer's signed
   order journal, re-check on-chain existence and `executed` immediately before
   broadcast, and add a "signed but not broadcast" recovery procedure. This is
   the operator-side half of A-1/A-10; without item 1 it is the only mitigation.
5. **Make the shard gate unconditional (S).** Remove `cross_shard_enabled()`
   from the bridge rule; reject bridge intents unless
   `tx.source_shard == MASTERCHAIN_SHARD` and the block is the masterchain.
   Closes A-9.

### P1 - freeze and liveness

6. **Snapshot the validator set at deposit time and verify challenge/resolve
   evidence against it (M).** Closes the rotation freeze identified in 5.5 and
   prevents old attestations becoming "unknown signer".
7. **Anchor headers: require `prev_hash` linkage to a committed anchor and
   clamp `finalized_*` to a committed head (M).** Closes the cheapest form of
   A-12 and makes the depth constants meaningful. A full light client remains
   5.2.
8. **Decide and document the inbound exit (S).** Either implement a
   foreign-side refund guarantee (outside this crate) or state in the operator
   runbook and user docs that a deposit with no quorum has no native exit.
   Closes the documentation half of A-4/A-5.
9. **Bound committed state (S).** Cap `target_address` per chain, cap `Attest`
   signatures at `MAX_HEADER_SIGNATURES`, and prune/limit resolved disputes and
   old deposit records. Closes A-14.
10. **Add property tests for reorg and escrow coverage (M).** I-3/I-4/I-5/I-6
    over randomized sequences, plus a crash between the accounts restore and
    the bridge restore. Closes the untested half of A-6/A-9.

### P2 - operability and hardening

11. **Ship prepare paths and watcher tooling for `Challenge`/`Resolve` (M).**
    Today only deposit/withdraw/status/attest-status/estimate/history are
    exposed (`stellereum/src/native_api.rs:230-285`); there is no prepare for
    either dispute intent, so a dispute must be hand-built. A watcher cannot
    operate the layer it is supposed to protect.
12. **Bridge-specific slashing / double-attestation evidence (M).** Detect a
    validator signing two conflicting claims or a claim and a retraction.
    Closes the unpunished half of A-8.
13. **Fuzz the evidence decoders (S/M).** Add BoC, MPT and binary-Merkle targets
    under `stellereum/fuzz/fuzz_targets/`; the TON BoC parser is the known
    allocation amplifier (see `stellereum/docs/audits/KNOWN_ISSUES.md:600`
    and KI-35).
14. **Fix the stale SVM comment (S).** `stellereum/src/svm.rs:2855-2856` says
    quorum/replay/rate limits are not enforced; they are, at settlement. Stale
    security comments cause bad audit conclusions.
15. **Add the missing tests named in section 3** (A-1 restart/double-broadcast,
    A-2 cross-chain hash, A-3 registry divergence, A-6 reorg, A-10 crash
    injection, A-13 stranger release).
16. **Link this document from the docs index (S).** `docs/README.md` lists the
    audit/threat-model set; add `docs/BRIDGE_THREAT_MODEL.md` there so it is
    found before bridge code is touched again.

---

## Appendix A - verification method

Every symbol cited above **as existing** exists in the tree; names introduced
under `SHOULD EXIST` are proposals, not code. The inventory was produced with:

```sh
cd stellereum
rg -n "BridgeIntent::|BridgeEffect::|fn plan|fn process_deposit|fn finalize_withdrawal|fn refund_withdrawal" src/bridge.rs
rg -n "fn verify_evidence|fn check_header|fn check_depth|fn verify_deposit|fn verify_quorum_retraction" src/bridge_adapters.rs
rg -n "settle_bridge_native|BridgeEffect::" src/state_engine/settlement.rs src/state_engine/apply.rs
rg -n "stell_bridge" src/native_api.rs src/rpc/reads.rs src/rpc/streams.rs
rg -n "try_release|is_approved|EvmReleaseOrder|TonMultisigReleaseOrder" src tests
rg -n "register_validator_pq_key|get_validator_pq_key" src/consensus/rotation.rs src/node/consensus_driver.rs
```

The "no production caller" claim for the release models is the absence of
matches outside `src/bridge.rs` and `tests/`:

```sh
cd stellereum
rg -n "try_release|is_approved" src --glob '!bridge.rs'
# (no output)
```

Line references can drift. The SHA-256 pins at the top of this document are the
authoritative check: if a file's hash differs, re-grep before trusting a line
number.

## Appendix B - top 5 risks

| # | Risk | Severity | Primary citation |
| --- | --- | --- | --- |
| 1 | Outbound release is unauthenticated, unlinked to the foreign payout, and the refund-after-payout window is bounded only by operator discipline | **S0 Critical once a relayer is deployed** | `stellereum/src/bridge.rs:1484-1490`, `:1896-1916`; `stellereum/tests/audit_closure_bridge_tests.rs:1209` |
| 2 | Deposit and evidence verification root in a node-local, non-committed Falcon key registry; two nodes can disagree and a poisoned node can forge quorum | **S1 High (S0 on a single-node deployment)** | `stellereum/src/bridge.rs:574-633`; `stellereum/src/consensus/rotation.rs:5-10`, `:109-112`; `stellereum/src/node/consensus_driver.rs:283-328` |
| 3 | The "SPV" path still requires 2/3 over an arbitrary, unlinked `StoredHeader`, with custom leaf encodings and evidence-supplied finality; those deposits are unchallengeable | **S1 High** | `stellereum/src/bridge_adapters.rs:644-691`, `:143-192`; `stellereum/src/bridge.rs:1461-1468`, `:1513-1517` |
| 4 | The attester set is the whole bonded validator set with no epoch snapshot; a 2/3 coalition mints to the cap and a rotation can leave a challenged deposit resolvable only by the current quorum | **S1 High** | `stellereum/src/state_engine/apply.rs:877-881`; `stellereum/src/bridge.rs:1597-1677` |
| 5 | Inbound deposits have no timeout or trust-minimized exit; slightly over one third of the set (2 of 3 at n=3) can censor a chosen claim indefinitely | **S1 High** | `stellereum/src/bridge.rs:232-377`, `:1401-1413`; `stellereum/src/bridge_adapters.rs:644-665` |

---

## Addendum 2026-11-26 (post-Ruleset-v7)

> **Dated addendum. Every section above this line is the 2026-11-20 pin and is kept
> byte-intact.** This addendum does not rewrite the original findings; it records what the
> bridge code looks like now, which original statements are obsolete, and which findings are
> still open. Current claims below were read from the working tree at HEAD
> `ab0adbf086779a5638459e58d7e6a5e9949ffdad` on 2026-11-26; no test or `cargo` command was run
> for this addendum.

### Addendum A — Why this addendum exists: the original pin is pre-R4/R5

The original pin is **pre-R4/R5** in the sense that matters for this document: it was written on
2026-11-20, before the unified R1..R4 gate activation that shipped as **Ruleset v7** (2026-11-22,
deployed in the R5 wave — `docs/OPEN_DEFECTS.md:251`, `docs/RULESET_V7.md`). The bridge V2
release-authorization, retraction-precedence, refund-tombstone and committed height-indexed PQ-key
code documented below is not the code that was pinned: `bridge.rs` and `bridge_adapters.rs` both
have different SHA-256 hashes now (Addendum E), and `docs/OPEN_DEFECTS.md:167-168` records the
bridge fixes as v7 work.

Precision note: `protocol.rs` dates the R4 ruleset bump to 2026-11-19, one day before the original
pin. If "R4" means that ruleset bump, the pin is post-R4. It is unambiguously **pre-R5/v7** and
pre every bridge V2 change. Either way, the `file:line` citations in the body above are
historical and must not be used to audit the current tree.

### Addendum B — The bridge code as it exists now (exact `file:line`)

All paths are relative to `stellereum/src/`. Line numbers are for the working-tree file whose
hash is in Addendum E.

**Entry points and dispatch**

| Item | Location |
|---|---|
| Cheap VM-side validation (height-less; delegates at height 0) | `bridge.rs:596-608` (`BridgeIntent::validate`) |
| Height-indexed validation | `bridge.rs:610-734` (`BridgeIntent::validate_at_height`) |
| Target-address length check | `bridge.rs:68-90` (`validate_bridge_target_address_len`), called at `bridge.rs:640-643` and `bridge.rs:2069-2074` |
| PRE-V2 compatibility planner (height 0, legacy lookup) | `bridge.rs:1785-1804` (`BridgeState::plan`) |
| Current planner (height, chain id, committed PQ lookup) | `bridge.rs:1806-2579` (`BridgeState::plan_at_height`) |
| Settlement wiring (the only production caller) | `state_engine/settlement.rs:2094-2120` (`settle_bridge_native` → `plan_at_height` at `:2109`) |
| V2 activation predicate | `bridge.rs:318-327` (`bridge_v2_active_at`); constant `bridge.rs:294` (`BRIDGE_V2_ACTIVATION_HEIGHT = 0`) |
| Height-indexed quorum helper | `bridge.rs:935-1010` (`verify_quorum_signatures_at_height`, `distinct_falcon_signers_at_height`) |
| Payout-receipt verifier | `bridge.rs:2582-2646` (`verify_release_receipt_v2`) |
| Receipt signing preimage | `bridge.rs:152-168` (`release_receipt_signing_message_v2`, domain `STELL_BRIDGE_RELEASE_RECEIPT_V2` at `:99`) |
| Max receipt age | `bridge.rs:329-336` (`MAX_BRIDGE_ATTESTATION_AGE_HEIGHTS = PQ_EVIDENCE_RETENTION_HEIGHTS = 720_000`) |

**Release / refund / challenge / resolve behaviour**

| Behaviour | Location |
|---|---|
| `Release` arm; pre-v2 legacy finalize vs v2 receipt-gated release | `bridge.rs:2082-2167` |
| Bare `Release` fails closed at v2 (`verified payout receipt required`) | `bridge.rs:2091-2122` |
| Receipt must bind req_id/chain/address/amount, be fresh, not replay | `bridge.rs:2123-2153`, verifier `:2600-2645` |
| `processed_payout_txs` replay guard | `bridge.rs:1476`, checked `:2618-2620`, inserted `:2153` |
| `Refund` arm with durable tombstone | `bridge.rs:2168-2239`; tombstone insert `:2234` |
| Late `ReleaseProof` after refund fails (`Withdrawal already refunded`) | `bridge.rs:2097-2099`, `:2186-2188` |
| Refund rate-window accounting fix | `bridge.rs:2218-2233` (only subtract if the request was counted in the current window) |
| `Challenge` arm | `bridge.rs:2241-2313` |
| Challengeability of evidence-path deposits at v2 | `bridge.rs:2251-2263` (the `!v2 && !record.via_quorum` guard is bypassed at/after v2, so every admitted deposit is challengeable) |
| `Resolve` arm | `bridge.rs:2315-2549` |
| Truth grading (math/testimony/retraction) | `bridge.rs:2356-2440` |
| Quorum `RETRACTION` check | `bridge.rs:2424-2434` (`bridge_adapters::verify_quorum_retraction_at_height`) |
| V2 precedence: retraction beats any confirm bucket | `bridge.rs:2441-2447` |
| Retraction verifier / preimage | `bridge_adapters.rs:1273-1305`; domain `STELL_BRIDGE_DEPOSIT_FAILURE_V1` at `bridge.rs:1177-1192` |
| Adapter evidence verifier | `bridge_adapters.rs:1375-1410` (`verify_evidence_at_height`) |
| V2 adapter header domain | `bridge_adapters.rs:210` (`STELL_BRIDGE_HEADER_V2`) |
| Attestation signature cap | `bridge.rs:646-663`; `MAX_HEADER_SIGNATURES = 1024` at `bridge_adapters.rs:92` |

**`BRIDGE_TARGET_ADDRESS_CAP_HEIGHT` specifically**

| Item | Location |
|---|---|
| Constant (`u64::MAX`, INERT) | `chain_spec.rs:100-115` |
| Active predicate | `chain_spec.rs:408` (`bridge_target_address_cap_active_at`) |
| Limit (`128` UTF-8 bytes) | `bridge.rs:60-66` (`MAX_BRIDGE_TARGET_ADDRESS_BYTES`) |
| Enforcement in `validate_at_height` | `bridge.rs:640-643` |
| Enforcement in `plan_at_height` (the settlement path that parks) | `bridge.rs:2069-2074` |
| Not enforced on release/refund | `Release`/`Refund` arms `bridge.rs:2082-2239` never inspect `target_address.len()` |

At the current compiled value the cap is a **no-op**: a 1 MiB address still parks. The code
exists at both validation layers, so arming the constant is a one-line consensus change, but it
is not armed on this chain.

### Addendum C — Status of the original bridge findings

**C.1 Closed in code but still INERT behind activation**

Only one bridge hardening is in this category: the **target-address cap**. The code is present
at both `validate_at_height` and `plan_at_height`, but `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT =
u64::MAX` (`chain_spec.rs:115`), so the on-chain vector from A-14 (arbitrary-length
`target_address` parked into consensus state for zero bridge value) remains open. `Release` and
`Refund` also remain length-agnostic, so any pre-activation oversized parked request would still
be releasable/refundable unless an explicit migration is specified
(`stellereum/docs/specs/ACTIVATION_BATCH_1.md:151-184`).

Everything else that the v7 bridge work **fully** closed is **active from height 0**, not inert,
because `BRIDGE_V2_ACTIVATION_HEIGHT = 0` (`bridge.rs:294`). The `Attest` path is the exception:
it is active but only partially closed (C.2).

**C.2 Closed or partially closed in code, ACTIVE at height 0 (`BRIDGE_V2_ACTIVATION_HEIGHT = 0`)**

| Original finding | Current closure | Residual |
|---|---|---|
| **A-1** double-spend of a release (external leg paid twice) | `Release` requires a `ReleaseProof`; `external_tx_hash` is unique via `processed_payout_txs`; a late proof after refund fails. `bridge.rs:2082-2166`, `:2591-2646`. | The foreign payout is still an off-chain relayer action; no relayer daemon exists in this repo. The chain can now *detect* a duplicate receipt, but the foreign contract must still dedup and the relayer must journal. |
| **A-10** refund-after-release theft | `Refund` writes `refunded_withdrawals`; a release/receipt after that fails loudly. `bridge.rs:2168-2239`. | Same external-leg caveat as A-1; a crash between foreign payout and on-chain receipt is still an operator-discipline window. |
| **A-13** unauthenticated `Release` closes the refund | At v2 a bare `Release` fails closed (`verified payout receipt required`). `bridge.rs:2091-2122`. | Pre-v2 replay keeps the legacy rule for historical blocks only. |
| **A-3** forged attestation / node-local key registry — **only partially closed** | The v2 receipt, evidence and retraction paths use the committed height-indexed `PqKeyLookup` (`&staking_ledger, &pq_registry`): `bridge.rs:1844-1851`, `:935-1010`; `state_engine/settlement.rs:2104-2119`. **The plain `Deposit` + `Attest` quorum path does not**: `plan_at_height` calls `process_deposit` (`bridge.rs:1962`), which calls the pre-v2 wrapper `verify_quorum_signatures` at height 0 (`bridge.rs:1208-1218`, wrapper `:899-917`), which reads process-global `consensus::pq_key_at_height` (`bridge.rs:887-897`; `consensus/rotation.rs:43-81`). | The `Attest` path still resolves at height 0 through the process-global mirror, not the passed committed lookup; a rotation or a divergent mirror can change the verdict for the same payload. The original "poisoned local key table" vector is narrowed (an untracked validator fails closed at a lifecycle-active height) but **not eliminated for attestations**. Key lifecycle retention is also bounded at 720 000 heights. |
| **A-12** "unchallengeable evidence-path deposit" half | At v2 every admitted deposit is challengeable within `CHALLENGE_MAX_AGE_SECS`, including `DepositProof` deposits. `bridge.rs:2251-2263`. | The other half — header linkage (`prev_hash`), a committed foreign head, foreign validator signatures — is **still NOT IMPLEMENTED**. The adapter still verifies a quorum-signed `StoredHeader`, not a trustless foreign light client. |
| **A-14** unattested state bloat, `Attest` half | `validate_at_height` caps `Attest` signatures at `MAX_HEADER_SIGNATURES = 1024`. `bridge.rs:646-663`. | `target_address` cap is inert (C.1); deposit records and resolved disputes are still never pruned (`bridge.rs:1067-1076` in the original pin; no pruning arm was found in the current `plan_at_height`). |
| **I-7** no release without a payout authorization | Now implemented on-chain via `ReleaseProof` + receipt verification. `bridge.rs:2082-2166`. | As A-1/A-10. |

> **Do not quote `docs/OPEN_DEFECTS.md:168` as "A-3 closed" without reading
> `process_deposit`.** The registry says `BRIDGE-PQ-HEIGHT-KEY` is fixed because
> `plan_at_height` uses the height-indexed evidence/retraction verifiers. That is true for those
> paths, but the ordinary `Deposit`+`Attest` quorum path still calls the pre-v2 wrapper at
> height 0 (`bridge.rs:1208-1218`). A differential test (two nodes, two key tables, same
> attestation payload, compare verdict and `state_root`) is the missing proof. This addendum did
> not run it; the residual is reported as **open / `UNVERIFIED`**, not as closed.

**C.3 Still open (unchanged by v7)**

| Finding | Why it is still open | Current citation |
|---|---|---|
| **A-4 / A-5** no timeout or trust-minimized exit for an inbound deposit | `Deposit` still has no deadline/cancel/expire variant; the only exit remains the foreign chain. | `BridgeIntent` variants `bridge.rs:532-595`; `plan_at_height` deposit arm `bridge.rs:1953-2063`. |
| **A-11** a challenge cannot claw back funds the recipient already spent | Pass-1 balance failure still fails the whole challenge; there is no hold period or debt model. | `state_engine/settlement.rs` bridge settlement path (unchanged in this read); `bridge.rs:2304-2313` parks the bond before the clawback. |
| **A-12** header linkage / committed foreign head | Still a quorum-signed arbitrary `StoredHeader`; no `prev_hash` walk on-chain. | `bridge_adapters.rs:1375-1410` and the adapter header path; `bridge_adapters.rs:210` only binds `chain_id`/kind/finalized head. |
| **A-14** pruning of deposit records/resolved disputes | No prune/limit arm in `plan_at_height`. | `bridge.rs:2567-2578` writes the maps back without a prune. |
| **5.5** per-deposit validator-set snapshot | The set is still the whole current bonded set; a rotation can strand a challenged deposit. | `state_engine/settlement.rs:2094-2119` passes the current `validators`. |
| **5.7** relayer daemon / journal / fee model | Still no production relayer in this repository. | `MultisigRelayer` / `TonMultisigReleaseOrder` / `EvmReleaseOrder` remain library models. |

### Addendum D — What the rest of the original document still gets right

* The bridge is **quorum-attested on inbound paths** and the "SPV" path still reduces to the
  same 2/3 trust root (original §0). The new domain separation and receipt binding raise the
  cost of cross-context replay; they do not create a trustless foreign light client.
* The **foreign leg is still not linked to the native chain** by a proof. v7 adds an on-chain
  *receipt* that the relayer quorum signs, but a receipt is testimony, not a foreign-chain
  inclusion proof.
* The **2/3 quorum assumption** and the `B < W/3` safety assumption are unchanged. The
  receipt/evidence/retraction paths now use committed keys at a height; the plain
  `Deposit`+`Attest` path does not (C.2). Either way the bridge still trusts 2/3 of the set.
* `docs/BRIDGE_THREAT_MODEL.md` remains the right threat catalog. Use its attack IDs (A-1…A-14)
  and invariants (I-1…I-12); use this addendum only for current status and line numbers.

### Addendum E — Provenance and how to re-verify

Current SHA-256 (working tree, 2026-11-26):

| File | SHA-256 |
|---|---|
| `stellereum/src/bridge.rs` | `427f47bb2d68b2235b49dc04f461cef979a459bbeb8bc01ee6dcb1573f0b3c1c` |
| `stellereum/src/bridge_adapters.rs` | `dfeddd114dccb62069053a5c0b4e640ab7921e6f9ffd1b04c8b98dd4a25e9fb4` |
| `stellereum/src/state_engine/settlement.rs` | `dcd2474555fd2f5483612845b8ec42eb2e929ec06dcd898f5389eea63bb844c4` |
| `stellereum/src/pq_registry.rs` | `511d7cc72b8663042a3fa61f7fb2d0f58206134033e5f47fe376b48864d5a89f` |
| `stellereum/src/chain_spec.rs` (working tree; dirty) | `49a2dbf8cffd4b470adade2a3b449ff686a76fed0ec5095eab4e827f5f5fce28` |
| `stellereum/src/consensus/rotation.rs` | `bf791f67736edbc650f675d702f87fcd6f3998a127ada16cd582cb52613e7c4d` |

Re-grep before trusting a line number:

```sh
cd /home/imm/stellereum-project/stellereum
rg -n "fn plan_at_height|fn plan\b|fn validate_at_height|BRIDGE_TARGET_ADDRESS_CAP_HEIGHT|MAX_BRIDGE_TARGET_ADDRESS_BYTES" src/bridge.rs src/chain_spec.rs
rg -n "fn verify_quorum_retraction_at_height|fn verify_evidence_at_height|BRIDGE_HEADER_SIGN_DOMAIN_V2" src/bridge_adapters.rs
rg -n "plan_at_height|PqKeyLookup" src/state_engine/settlement.rs
```

Candidate regression suites (not run for this addendum; names from `docs/OPEN_DEFECTS.md` and the
tree):

```sh
cargo test --locked -p stellereum --test bridge_dispute_tests
cargo test --locked -p stellereum --test bridge_challenge_tests
cargo test --locked -p stellereum --test h9_bridge_target_address_cap
cargo test --locked -p stellereum --test activation_gate_bridge_target_address_cap_tests
```

`docs/OPEN_DEFECTS.md:167-168` records `bridge_dispute_tests` 12/12 and
`bridge_challenge_tests` 5/5 for the local (pre-deployment) fixes; that is a recorded result,
not a re-run. The target-address test file is uncommitted work in this snapshot, so treat its
status as `UNVERIFIED` until run.

**What did not change in this addendum:** every byte above the `## Addendum 2026-11-26` heading.
The original pin, severity scale, attack catalog and appendices remain as written on 2026-11-20.
