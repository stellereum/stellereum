# Sharding: the address→shard rule, the split/merge thresholds, and the
# migration plan

Status: the rule and the thresholds below are **published constants** in
`src/sharding.rs` (`ROUTING_RULE`, `MIN_ACCOUNTS_PER_SHARD`, `MAX_SHARDS`,
`SHARD_SPLIT_LOAD_THRESHOLD`, `SHARD_MERGE_LOAD_THRESHOLD`, `MAX_PREFIX_BITS`).
Where this document and the code disagree, the code is the bug.

Scope: the address→shard routing rule, the dynamic split/merge state machine,
the trie migration procedure, and the RPC surface that publishes them.

---

## 0. What is DEMONSTRATED and what is only DESIGNED

Read this section before quoting anything about sharding.

| | Status | Evidence |
| --- | --- | --- |
| The address→shard rule (longest-prefix match, `-1:` masterchain form) | **DEMONSTRATED** | `cargo test --lib sharding`, `tests/sharding_topology_tests.rs` |
| The split state machine: trigger, account re-assignment, balance conservation | **DEMONSTRATED** (synthetic account set, in-process) | `sharding::topology_tests`, `tests/sharding_topology_tests.rs` |
| The merge state machine: the inverse of the split, balance conservation | **DEMONSTRATED** (synthetic account set, in-process) | `sharding::topology_tests`, `tests/sharding_topology_tests.rs` |
| The trie migration procedure (every account leaf moved into exactly one child trie, fail-closed on an unclassified key) | **DEMONSTRATED** (over a real `PatriciaTrie`) | `tests/sharding_topology_tests.rs` |
| The convergence property (no split/merge oscillation) | **DEMONSTRATED** | `sharding::topology_tests::the_topology_converges_and_never_oscillates`, `tests/sharding_topology_tests.rs` |
| The published thresholds and the RPC surface | **DEMONSTRATED** | `stell_getShards` (`sharding` section), `stell_getShardTopology` |
| The **shard-head commitment** in masterchain blocks (the TON `shard_hashes` model) | **DEMONSTRATED** (unit + integration tests over the block path) | `sharding::shard_header_commitment_tests`, `runtime::masterchain_block_commits_workchain_shard_headers_and_roots` |
| The **epoch-MMR root** in masterchain blocks (V5 Tier-2: one MMR root per 128-block epoch, §8) | **DEMONSTRATED** (unit tests over the MMR, the block commitment and the chain helper) | `mmr` unit tests, `sharding::epoch_mmr_root_keeps_legacy_hashes_and_moves_hash_when_set`, `chain::epoch_mmr_root_covers_a_fully_finalized_epoch` |
| **Cross-shard atomic commit (2PC)** for native value transfers: prepare / vote / commit, a monotone committed state machine, a two-sided abort | **DEMONSTRATED** (in-process, two shards) | `tests/xshard_2pc_tests.rs`, `xshard2pc` unit tests, `docs/SHARDING.md` §6 |
| **A split on the live testnet / mainnet** | **DESIGNED — NOT PERFORMED** | — |
| **A cross-node state migration over the network** (shipping the migrated trie to the new shard's validators) | **DESIGNED — NOT PERFORMED** | — |
| **A split driven by a live consensus event** | **DESIGNED — NOT PERFORMED** | — |

The split/merge path is exercised by an **integration test over a synthetic
account set**; a **live-network split has not been performed**. The shard
migration is a **local state operation** in this codebase: the state is
re-partitioned in-process, and shipping it to other nodes is not implemented.

### 0.1 Live status 2026-10-25 — workchain triage (S4-retry3, read-only)

Shard 1 is **FINALIZING but EMPTY and DEGRADED**; the masterchain is
**STALLED**. Do not quote shard 1 as "live production traffic".

| shard | tip (pre-restart 18:48–18:49Z) | 15-min finalized | rate | state_root | user txs |
| --- | --- | --- | --- | --- | --- |
| 0 masterchain | A/B/C 305831, D 305788 (43 behind) | **0 on all nodes** (last finalize 17:34:38Z, ~79 min stall) | 0/s | A `01b036c7…` DIVERGED vs network `9c339918…` (B/C/indexer agree) | indexer: 60 txs EVER on shard 0, latest in block 302925 (~3k blocks ago); recent 100 blocks all `txs: 0` |
| 1 workchain | A/C 162700, B 162699, D 161821 (879 behind) | A 48, C 50, B ~141/30min, D **0** | ~3.2/min (~0.05/s, ~0.27% of the 20/s `MIN_BLOCK_MS=50` ceiling) | `54852fd2e9b4…` FROZEN across #162687–162711 (24+ heights) → empty blocks | **zero demonstrated**: indexer has **zero shard-1 rows by construction** (`syncer.rs` reads `/api/blocks`, masterchain only, `shard_id` defaults 0); no RPC exposes shard-1 bodies (`rpc.rs:record_block` serves one chain; `stell_getBlock*` is masterchain-window only); mempool 0 on B/C |

Rejection storm (30-min, pre-restart): A 464 masterchain-height + 440
shard-1-height rejects (167 `wrong proposer` on shard 1,
`runtime.rs:4381`/`4798`; `stale round` `runtime.rs:4771`; masterchain
`state root does not match our state` `runtime.rs:4216`, `omits the downtime
evidence` `runtime.rs:3990`, `wrong height` from D's stale proposals);
B 64 `wrong proposer` + 151 `stale round`; C 66 + 183; D 0 finalized,
10,408 `rejecting peer chain: proposer holds no schedule slot`
(`sync.rs:818`) + 1,361 `REFUSING snapshot` /30min, load 8.48 on 1 vCPU,
disk 100% full (`/dev/vda2 9.4G/9.8G`).

Hosts: A/C/D are **1 vCPU** (`nproc=1`; B is 12 vCPU). A disk 97% full,
D disk 100% full, C 70%, inodes 30–37% (sweeper recovered from the 100%
incident). `STELL_SHARDS=0,1` on all four (two consensuses on 1 vCPU —
`OPERATIONS.md` §1: "1 vCPU will not carry two consensuses", measured
−25% throughput). `STELL_WORKCHAIN_OBSERVER=1` on C/D. All four nodes
restarted together 18:51:26–29Z by the supervisor during diagnosis
(no operator restart; post-restart RPC reports shard-1 `tip_height: 0`
until the first post-restart finalize).

Verdict 2026-10-25: **PARK shard 1** (procedure in the triage report, not
executed). Unpark only when: hosts ≥4 vCPU, disks <80%, masterchain
finalizing, D synced to tip, and real user demand exists. Until then the
explorer must show shard 1 as `parked / empty / degraded`, never as
healthy throughput.

---

## 1. The address→shard rule

The rule has exactly three parts. It is implemented once, in
`src/sharding.rs`, and every consumer goes through it:

- `ShardTopology::route` / `sharding::route_shard` — the rule itself;
- `sharding::split_shard_prefix` — the `<shard>:<addr>` address FORM;
- `rpc::resolve_shard_for_address` — the RPC wrapper that applies it.

Consumers: `stell_estimateFee` (the `target_shard` it simulates for),
`stell_runGetMethod` (the `shard` it reports), the SVM's cross-shard message
routing (`Svm::route_contract_messages_with_topology`), and the topology's own
account ownership.

### 1.1 The masterchain

The masterchain is shard **0** and is addressed **EXPLICITLY**, in the TON
style `-1:<addr>`:

```
-1:EQCt...        ->  the masterchain (shard 0)
0:EQCt...         ->  the masterchain as well (shard 0 IS the masterchain id)
N:EQCt...         ->  workchain shard N, named explicitly
<bare address>    ->  a WORKCHAIN address, routed by the prefix rule
```

**A bare 32-byte address NEVER routes to the masterchain.** The masterchain
holds the global state (consensus, staking, governance); a bare address is a
workchain address and is routed by prefix. This is the one rule that must not
be guessed: a client that wants to move value on the masterchain has to say
so.

### 1.2 The workchain rule (longest prefix match)

A workchain address belongs to the shard whose **routing prefix** is the
**longest prefix** of the address's leading bits.

- A shard's routing prefix is the **top `prefix_len` bits of the address's
  first 8 bytes**, held left-aligned in a `u64` (`ShardDescriptor::prefix`).
  This is the same definition TON uses for its workchain shard prefixes.
- The most specific (longest) matching prefix wins.
- **Ties are broken by the SMALLEST shard id.** The rule is therefore a pure
  function of the shard set: two nodes with the same topology route an address
  to the same shard, with no coordination and no lookup.
- If no prefix matches (only possible in a degenerate topology), the address
  goes to the **lowest workchain shard id**; with no workchain shard at all,
  to the masterchain.

Worked example (the starting topology, one workchain shard):

```
shard 1: prefix_len = 0, prefix = 0x0000000000000000   (matches everything)
shard 0: the masterchain — never a prefix candidate
```

After one split of shard 1:

```
shard 2: prefix_len = 1, prefix = 0x0000000000000000   (bit 0 == 0)
shard 3: prefix_len = 1, prefix = 0x8000000000000000   (bit 0 == 1)
```

so `address[0] < 0x80` routes to shard 2 and `address[0] >= 0x80` routes to
shard 3.

### 1.3 How the rule changes on a split and on a merge

The rule itself never changes — only the **prefix length** does:

- **Split**: the parent's prefix grows by exactly **one bit**. The address's
  bit at the new depth (`split_bit`, 0-based from the most significant bit of
  byte 0) decides the child: bit `0` → child 0, bit `1` → child 1. Child 0
  keeps the parent's prefix with the new bit cleared; child 1 has it set.
  The parent's prefix length was `L`, the children's is `L + 1`.
- **Merge**: the two siblings' deepest bit is **removed**. The merged shard's
  prefix is the common prefix of the two, with prefix length `L - 1`, and it
  covers exactly the range the two children covered together.

The routing rule therefore changes only **at a transition**, never
continuously, and the transition is atomic from a client's point of view: an
address is either routed by the parent's prefix or by the children's, and
never by a mixture.

**Shard ids are never reused.** A merge allocates a NEW id for the merged
shard, so a late cross-shard message addressed to a retired id can never be
mistaken for the merged shard.

### 1.4 The prefix length

`MAX_PREFIX_BITS = 60`: the routing prefix can be at most 60 bits deep, which
is the width of the advertised shard space (2^60). A split that would exceed
it is refused (`SplitRefusal::PrefixTooDeep`).

---

## 2. The published thresholds

| Constant | Value | Meaning |
| --- | --- | --- |
| `MIN_ACCOUNTS_PER_SHARD` | **100** | A shard must own at least this many accounts to be split. A shard below it does not pay for its own consensus overhead. |
| `MAX_SHARDS` | **16** | The hard cap on the number of shards, masterchain included. `check_and_split` refuses to grow past it. |
| `MAX_PREFIX_BITS` | **60** | The maximum routing-prefix depth, in bits. |
| `SHARD_SPLIT_LOAD_THRESHOLD` | **500** | A shard whose recorded load (txs per window) reaches this is split-eligible. |
| `SHARD_MERGE_LOAD_THRESHOLD` | **50** | Two sibling shards whose combined load is at most this are merge-eligible. |
| `MAX_WORKCHAIN_SHARD_SPACE` | **2^60 = 1_152_921_504_606_846_976** | The **advertised** workchain shard space. Not the shipped capacity — see below. |

### 2.1 The advertised space vs the shipped cap — the honesty note

The prefix-routing scheme admits a theoretical space of **2^60** workchain
shards. That is the **address space**, not a capacity. What this network
**ships** is a hard cap of **16 shards**, enforced in code
(`ShardTopology::check_and_split` → `SplitRefusal::ShardCapReached`).

This is the same distinction TON draws publicly: it advertises 2^60 shards and
ships a cap of 16. The rule we follow is the industry one — **state the
advertised number and the shipped cap separately, and never let the first be
read as the second.**

### 2.2 The split trigger

A shard splits when **all** of these hold:

1. it is not the masterchain;
2. the shard cap (`MAX_SHARDS`) is not reached;
3. its routing prefix is not already at `MAX_PREFIX_BITS`;
4. it owns at least `MIN_ACCOUNTS_PER_SHARD` accounts;
5. its recorded load is at least `SHARD_SPLIT_LOAD_THRESHOLD`.

### 2.3 The merge trigger

Two shards merge when **all** of these hold:

1. both exist, neither is the masterchain, and both belong to the same
   workchain;
2. they are **siblings**: they share every routing bit but the deepest one,
   so together they cover exactly one parent range;
3. their combined recorded load is at most `SHARD_MERGE_LOAD_THRESHOLD`.

### 2.4 Why the topology cannot oscillate

Two facts make split/merge oscillation impossible:

1. **The load thresholds are disjoint.** A split needs a load of at least
   500; a merge needs a combined load of at most 50. No shard state can be
   both split-eligible and merge-eligible.
2. **A split conserves the load in SUM.** The parent's load is divided
   between its children (child 0 gets the floor, child 1 the remainder), so
   the children's combined load is exactly the parent's. A shard that has
   just split therefore still carries a load of at least 500 and is **not**
   merge-eligible.

The consequence: after a split the topology is a **fixed point** until new
load arrives, and after a merge the merged shard carries at most 50 and is
**not** split-eligible. Both are asserted by the tests.

---

## 3. The split and the merge, step by step

### 3.1 The split (executable)

`ShardTopology::check_and_split(shard_id)`:

1. evaluate the published trigger (§2.2); refuse with a named reason if it
   does not fire;
2. `DynamicShardManager::check_and_split` computes the two children: the
   prefix grows by one bit, the ids are allocated monotonically;
3. **the parent's accounts are re-assigned**: for each account, the bit of
   its address at the new depth decides the child (0 → child 0, 1 → child 1);
4. **the parent's load is divided** between the children (floor / remainder),
   so the sum is preserved;
5. a `MigrationPlan` is produced: the source and target shards, the split
   bit, the account count, the digest of the source account set, the digest
   of each target account set, and the balances before and after.

The plan's digests let a verifier check that the move was the planned one:
`source_digest` is the SHA-256 over the sorted source addresses, and
`target_digests` the same over each child.

### 3.2 The trie migration (the MIGRATION PLAN)

The account re-assignment above is the *account-level* migration. The
*trie-level* migration moves the actual state.

The state trie holds more than account leaves. It also holds **namespaced
derived keys**:

| key | meaning | owner |
| --- | --- | --- |
| the raw address | the account leaf | the account itself |
| `sha256("STELL_CONTRACT_CODE" ‖ addr)` | the contract code hash | the contract account |
| `sha256("STELL_CONTRACT_ABI" ‖ addr)` | the contract's ABI manifest | the contract account |
| `sha256("STS_BAL" ‖ token_id ‖ holder)` | a token balance | the HOLDER account |
| `sha256("STS_SUPPLY" ‖ token_id)` | a token's total supply | the token's MINTER |

Those derived keys are hashes, so **the owner cannot be recovered from the
key alone**. The migration therefore carries an explicit
**`MigrationManifest`**: a sorted `(trie key → owning address)` map, built by
the shard that owns the state (`InMemoryStateEngine::shard_migration_manifest`).

`TrieMigration::execute_split(parent_trie)` then does, deterministically:

1. every key of the parent trie is classified by the manifest;
2. the owner's address decides the child, by the split bit;
3. **a key the manifest does not classify ABORTS the migration**
   (`MigrationError::UnclassifiedKey`) — the split fails closed instead of
   silently dropping state;
4. **the consensus commitment key is NOT migrated.** It is a digest over the
   whole state, so each child shard recomputes its own from its own state;
   migrating the parent's digest would make the child claim a root it does
   not have.

`TrieMigration::verify_split(parent, child0, child1)` then checks that every
parent key is in **exactly one** child with the **same value**, that neither
child holds a foreign key, and that the balances conserve.

`TrieMigration::execute_merge(child0, child1)` / `verify_merge` are the
inverse: the parent holds every key of both children with the same value,
and nothing else.

### 3.3 The merge (the inverse)

`ShardTopology::check_and_merge(a, b)`:

1. evaluate the published trigger (§2.3);
2. the two siblings are replaced by one parent whose prefix is their common
   prefix with the deepest bit removed (a **new** shard id);
3. **both children's accounts move to the parent** — the union, sorted;
4. the parent's load is the children's combined load;
5. a `MigrationPlan` with `direction = Merge` is produced.

The total balance is conserved, and the routing rule routes every account
back to the merged parent (its prefix covers exactly the range the two
children covered together).

### 3.4 The topology invariants

`ShardTopology::verify_invariants()` checks, after every transition:

- every account is owned by **exactly one** shard;
- the routing rule resolves every account **to the shard that owns it** (the
  rule and the ownership can never drift apart);
- every owned address falls **inside its shard's routing prefix**.

---

## 4. The RPC surface

### `stell_getShards` — the `sharding` section

`stell_getShards` now carries a `sharding` object next to the shard heads:

```json
{"method":"stell_getShards","params":{}}
→ {"result":{
     "shards":[ ... ],
     "total_shards":2,
     "routing_prefix_bits":1,
     "sharding":{
       "rule_id":"workchain-prefix-v1",
       "rule":"masterchain only via the -1: address form; workchain addresses route to the shard with the LONGEST matching routing prefix (ties broken by the smallest shard id); a split adds one routing bit, a merge removes the deepest one",
       "prefix_bits":1,
       "masterchain_shard":0,
       "base_workchain_shard":1,
       "masterchain_address_form":"-1:<addr>",
       "min_accounts_per_shard":100,
       "max_shards":16,
       "split_load_threshold":500,
       "merge_load_threshold":50,
       "max_prefix_bits":60,
       "max_workchain_shard_space":1152921504606846976,
       "active_shards":2
     }
   }}
```

### `stell_getShardTopology` — the full topology

```json
{"method":"stell_getShardTopology","params":{}}
→ {"result":{
     "parameters":{ ...the same object as above... },
     "shards":[
       {"shard_id":0,"shard_type":"masterchain","workchain_id":-1,
        "prefix":0,"prefix_len":0,"prefix_bits":"",
        "accounts":0,"balance":0,"tx_load":0},
       {"shard_id":1,"shard_type":"workchain","workchain_id":0,
        "prefix":0,"prefix_len":0,"prefix_bits":"",
        "accounts":2000,"balance":1000000,"tx_load":601}
     ],
     "transitions":1,
     "total_accounts":2000,
     "total_balance":1000000
   }}
```

`prefix_bits` is the routing prefix as a bit string (most significant first),
so a client can verify the routing rule by hand.

### `stell_estimateFee` and `stell_runGetMethod` use the rule

Both resolve the address through the same rule:

- `stell_estimateFee` reports the `target_shard` it simulated for, computed
  by the rule (an explicit `target_shard` parameter or an explicitly named
  shard in the address form wins over the rule — an explicit pin is a pin).
- `stell_runGetMethod` reports `shard`, `local_shard` and `shard_is_local` in
  its response, so a client can tell whether the shard it asked about is the
  shard it is talking to. A node that does not hold the shard answers from
  its own state and says so — it never fabricates another shard's state.

---

## 5. The shard-head commitment (TON `shard_hashes`)

A **masterchain** block commits to the latest finalized header of every
**workchain** shard: which shard, at which height, which block hash, which
state root and when.

```text
ShardHeaderCommitment {
    shard_id   : u32   BE   // never the masterchain itself
    height     : u64   BE
    block_hash : [u8; 32]
    state_root : [u8; 32]
    timestamp  : u64   BE
}
```

The set is mixed into the block hash under the tag **`SHARDHDR`**, length
prefixed, in **ascending shard-id order**. The commitment rides INSIDE the
block body, so it is covered by `Block::compute_hash` and therefore signed by
the BFT quorum.

Why it matters: a validator can prove *"shard 1 was at height 42 with THIS
state root"* from a single masterchain block, without ever having seen the
source shard's chain. That is what makes cross-shard proofs possible — an
inbound message's `source_state_root` is checked against the **committed** shard
head instead of against a locally trusted root.

The rules a validator enforces (`runtime::check_shard_header_commitments`):

- **only a masterchain block may publish shard heads** — a workchain block
  that carries them is refused;
- the set must be **canonical**: strictly ascending shard ids, no duplicates,
  and no entry for the masterchain itself (a block cannot commit to its own
  head). The order matters because the set is hashed as a *sequence*: two byte
  orders of the same set would be two different block hashes, and a proposer
  could equivocate with them;
- the set must not **contradict this node's own finalized headers**: if we
  finalized shard S at height H with hash X, a proposal committing shard S at
  height H with a different hash or root is refused — that is a shard-chain
  equivocation dressed up as a commitment.

A node that has not finalized that shard yet has nothing to contradict, so the
proposal is accepted; the commitment is still checked by the quorum that signs
the block.

**Backward compatibility.** The field is the LAST one of the block, so a block
persisted before it existed simply ends its byte stream one field early. The
self-describing formats use `serde(default)`, and the bincode path uses a
tolerant reader that reads a missing trailing field as "this block predates
the commitment". The field is ALWAYS encoded (never skipped) because bincode
is positional — omitting it would make every nested block misread the next
element's bytes as the missing field. The cost is 8 bytes per block (an empty
length prefix), and the block **hash** is untouched, because the commitment is
mixed in only for a non-empty set.

The full specification (and the invariants) is in
[`../PROTOCOL.md` §5.1](../PROTOCOL.md).

---

## 6. Cross-shard atomic commit: the two-phase commit (2PC)

Status: **implemented and regression-tested** for the case of a transfer
between two shards of this codebase (`src/xshard2pc.rs`, the state machine;
`tests/xshard_2pc_tests.rs`, the adversarial tests). The legacy
outbox/inbox/ack/bounce flow is **unchanged** and still runs for the
transfers produced before the activation height.

### 6.0 The gap this closes

The M2/M3 cross-shard flow is a **one-way** pipeline:

```text
  SOURCE S                          TARGET T
  commit Transfer  ──────────────▶  commit Transfer  (credits the recipient)
        │                                   │
        │                                   └── ack ──▶ S commits the ack
        └── timeout (64 heights) ──▶ commit Bounce (refunds the sender)
```

Both decisions are taken by the **source shard alone**, and the target's
credit happens **before** the source learns that it happened. A malicious
(Byzantine) source shard can therefore observe the credit on the target and
then bounce the very same transfer: the value is minted on the target AND
refunded on the source — **a cross-shard double spend**. The design is safe
only while the source shard is honest, which is exactly the production
blocker the audit lists.

### 6.1 The state machine

Each side owns a record per transfer, keyed by the **transaction hash** (the
transfer's stable identity across every phase and on both shards). The phase
is **monotone**: it moves `Prepared → Committed | Aborted` exactly once and
never back.

```text
                        SOURCE S                                TARGET T
                  ┌──────────────────────┐                ┌──────────────────────┐
                  │                      │                │                      │
   (no record) ──▶│      PREPARED        │── PREPARE ───▶│      PREPARED        │
                  │  (the value is       │   (proof of   │  (voted YES: it will │
                  │   ESCROWED here)     │    the source) │   credit on COMMIT)  │
                  │      │               │                │        │             │
                  │      │               │                │        │  PREPARE-ACK│
                  │      │               │◀───────────────┼────────┘   (vote)    │
                  │      │               │                │                      │
                  │      │ PREPARE-ACK   │                │        │             │
                  │      ▼               │                │        │ COMMIT      │
                  │      │               │── COMMIT ─────▶│        ▼             │
                  │   COMMITTED          │                │   COMMITTED           │
                  │ (the escrow is       │                │ (the recipient is    │
                  │  RELEASED: the value │                │  CREDITED, once)     │
                  │  belongs to T now)   │                │                      │
                  │      │               │                │        │             │
                  │      │ ABORT-ACK     │                │        │ ABORT-REQ  │
                  │      ▼               │◀───────────────┼────────┘             │
                  │   ABORTED            │  (the target's │   ABORTED            │
                  │ (the escrow is       │   authorisation│  (the target never   │
                  │  REFUNDED to the     │   - only ever  │   prepared: NO credit)│
                  │  sender)             │   issued when  │                      │
                  │      │               │   it never     │                      │
                   └──────┴───────────────┘   prepared)    └──────────────────────┘
```

The PREPARE travels **twice** in the happy path, and the second one carries
a different proof:

- the **opening** PREPARE goes out with the block that escrows the value
  (the transaction is in that block) and proves the SENDER's account leaf —
  "the sender had the funds";
- the **re-published** PREPARE goes out while the source waits for the vote
  (one height after the prepare, then every `XPC_REPREPARE_INTERVAL = 8`
  heights) and proves the source's own PREPARED leaf — "the value is already
  escrowed here". It exists for the case where the opening PREPARE never
  arrived; the target treats it exactly like the opening one (a second
  PREPARE for a transfer it already prepared is a no-op).

The rules that make the decision **atomic and unambiguous**:

| rule | where |
| --- | --- |
| the target NEVER credits on a bare transfer — only on a COMMIT, and only if it is already PREPARED | `xshard2pc::target_on_commit` |
| the target NEVER aborts a transfer it has prepared (a participant that voted YES must commit) | `xshard2pc::target_on_abort_request` |
| the source may ONLY abort with the target's authorisation, and the target can never give one for a transfer it prepared | `xshard2pc::source_on_abort_ack` + the proof check |
| a committed transfer is never refunded; an aborted transfer is never credited | the monotone phase |
| the recipient is credited EXACTLY ONCE; the escrow is refunded EXACTLY ONCE | the phase transition, in the state engine |

The **peer's vote is unforgeable**. Every 2PC control record carries a
Merkle inclusion proof of the peer's 2PC state leaf
(`sha256("XSHARD2PC" ‖ tx_hash)` → `phase ‖ tx_hash`) at the peer's
committed state root, and that root is **anchored** (the C1 rule) to a
locally finalized header of the peer's shard. A malicious source shard
cannot forge the target's ABORT-ACK: it would need the target's quorum to
have committed an ABORTED record that the target — having voted YES — never
writes.

The `trusted` shortcut (a locally-produced message that skips the inclusion
proof) is **ignored** for every 2PC record — exactly like the legacy
transfer's `verify_inclusion_strict` does. A 2PC control record moves value
(the COMMIT credits the recipient, the ABORT-ACK refunds the escrow), so its
proof is ALWAYS checked against the peer's committed state root.

### 6.1.1 What the validators check

A shard with more than one validator checks every 2PC record in a proposal
before it votes (`runtime::xpc_outbound_admissible` for the records this
shard publishes, `runtime::xpc_admissible` for the records it consumes). The
rules are:

| record | the validator demands |
| --- | --- |
| PREPARE (the **opening** one) | the TRANSACTION is in this block (so the escrow debit happens in the same block) **and** the record proves the SENDER's account leaf against the block's own state root |
| PREPARE (the **re-published** one) | this shard holds the transfer's PREPARED record **and** the record proves that leaf against the block's own state root (the PREPARED leaf IS the escrow) |
| PREPARE-ACK | the target's PREPARED leaf, anchored to a finalized header of the target shard |
| COMMIT | the source's PREPARED or COMMITTED leaf, anchored |
| ABORT-REQUEST | the source's PREPARED or COMMITTED leaf, anchored, **and** the prepare window has elapsed |
| ABORT-ACK | the target's ABORTED leaf, anchored |

A proposer that invents a vote the shard never made, or that publishes a
PREPARE it cannot back with the matching proof, is **refused** — the block
does not reach the votes.

### 6.2 The failure and recovery rules

| failure | what happens | is it safe? |
| --- | --- | --- |
| the PREPARE is lost in flight | the source RE-PUBLISHES it (one height after the prepare, then every `XPC_REPREPARE_INTERVAL = 8` heights) and the transfer completes; if the target never answers at all, the prepare window elapses → the source asks the target to abort → the target (which never prepared) records ABORTED and authorises the refund | yes: the value is either transferred or refunded, never both |
| the target is unreachable | the transfer stays ESCROWED (neither credited nor refunded) until the target answers | yes, but it is a **liveness loss** — the price of not letting the source decide unilaterally |
| the target prepares, then CRASHES | its PREPARED record is committed; after the restart it re-derives the PREPARE-ACK from that record and the exchange continues | yes: the same decision, because the decision lives in the committed record |
| the source prepares, then CRASHES | its PREPARED record (and the escrow) are committed; after the restart it resumes the handshake and reaches COMMIT | yes: the same decision, and the escrow is never refunded |
| the source prepares, the target votes YES, the source CRASHES before it consumes the vote | the target keeps re-deriving the vote from its committed state; the restarted source consumes it and commits | yes |
| the target votes YES and then refuses to credit (Byzantine target) | the source has already committed (the escrow is released), so its timeout path CANNOT refund; the value is **burned** | yes: a liveness loss, **not** a double spend |
| the source tries to BOUNCE after a successful prepare (Byzantine source) | the legacy bounce is never emitted for a 2PC transfer (it is not in the source's produced set, so the linkage rule refuses it), and the 2PC abort needs the target's authorisation the target will never give | yes: **this is the attack the audit describes, and it is blocked** |
| a PREPARE / COMMIT is replayed | the phase is monotone, so a replayed record is a no-op; the credit happens once | yes |

**The recovery rules in one sentence**: the decision lives in the COMMITTED
state, and the outbound records are DERIVED from it — so a node that crashes
at any point re-derives exactly the same records and reaches the same
decision. The intermediate states are committed in three places: the state
trie leaf (the proof the peer verifies), the `XSHARD_2PC_V1` commitment
domain (the digest) and the persisted replay snapshot (the restart).

**What "persisted" means.** The 2PC records are part of the cross-shard
replay blob (`CrossShardReplaySnapshot::xpc`), so they travel with every
persisted snapshot and with the local checkpoint: a node that restarts
mid-2PC restores the record, re-inserts its state-trie leaf (the peer's
proofs of this shard's vote keep verifying) and resumes to the SAME
decision. A blob persisted before the 2PC existed is still readable — the
field is the last one and a missing trailing field decodes as "no 2PC
record" (`de_xpc_records`).

### 6.3 The activation switch

The 2PC is **off by default** and switched on by a **chain-height
boundary**:

```bash
# every cross-shard transfer PRODUCED at height 4200 or later runs the 2PC
STELL_XPC_ACTIVATION_HEIGHT=4200 ./stellereum …
```

```rust
// the same switch, in-process
cluster.with_xpc_activation(stellereum::xshard2pc::XpcActivation::FromHeight(4200));
```

- Unset (the default) → the **legacy** flow for every transfer. That is the
  mode the already-deployed chain state runs in, and the mode the pre-2PC
  integration tests exercise.
- `0` → the 2PC from genesis (a fresh chain).
- A transfer produced **before** the boundary keeps running the legacy flow
  to completion, so the two protocols never interleave on one transfer.
- The boundary is **consensus-visible** (it decides which protocol a
  transfer takes), so every node of a shard must be configured with the same
  value.

### 6.4 What is still missing (the honest part)

- **The liveness cost is real**: an unreachable target leaves the value
  escrowed forever. The protocol refuses to refund without the target's
  authorisation, and that authorisation is exactly what a dead target cannot
  give. A production deployment therefore wants a **governance-level
  sweeper** (a time-locked refund authorised by a quorum of the shard set,
  not by the source alone) — that is a different protocol (a 3PC / lease
  expiry) and is **not** implemented here.
- **Multi-target transfers are not implemented**: the 2PC here is a
  coordinator (the source) and ONE participant (the target). The
  "quorum of PREPARE-ACKs" of a many-target transfer would need the source
  to collect one vote per target and to commit only when all of them are in
  — the state machine generalises (`XpcRecord` is per transfer), but the
  collector is not written.
- **The vote is proven against the peer's committed state, not against a
  per-validator quorum certificate.** The proof plus the anchored state root
  is what makes the vote unforgeable (the peer's quorum signed the block
  that carries that state), so the guarantee is the peer's BFT quorum — but
  there is no separate "vote object" a light client could check without the
  peer's chain.
- **The activation switch is an operator setting, not a governance
  parameter.** It is consensus-visible, so a misconfiguration splits the
  shard; a governance parameter would remove that footgun.
- **The escrow itself is proven through the source's own consensus.** The
  COMMIT carries a proof of the source's PREPARED record, and that record is
  written only for a transfer whose transaction REALLY applied (a refused
  transaction escrows nothing and leaves no record — see
  `a_refused_escrow_leaves_no_prepared_record`). So the credit on the target
  is backed by "the source's quorum committed an escrow of exactly this
  transfer". What is NOT proven is the sender's identity or intent: the
  transaction is signed, but a Byzantine source shard can still decide to
  escrow a transfer its own users never asked for. That is a property of the
  source's consensus, not of the 2PC.
- **A single shard's 2PC is not exercised by the multi-shard soak tests.**
  The protocol is verified in-process (two shards, two validators, the
  adversarial cases); the live four-node deployment has not been run with the
  switch armed.

### 6.5 Reproducing this

```bash
# the 2PC tests (the happy path, both crash recoveries, the two adversarial
# cases, the replay case, the two-validator validation path, the lost-PREPARE
# re-publication, the activation boundary and the committed state)
cargo test --test xshard_2pc_tests

# the state machine's own unit tests
cargo test --lib xshard2pc

# the legacy flow, which must stay green
cargo test --test cross_shard_e2e_pq_tests --test xshard_replay_tests \
            --test sequencer_m3_tests --test sharding_m3_tests
```

---

## 8. Epoch MMR roots (V5 Tier-2, shipped)

The V5 master spec (§3.2) promises a Merkle-Mountain-Range epoch root every
128 blocks ("Tier 2: the full validator set signs the MMR epoch root"). That
structure now exists (`src/mmr.rs`); Tier-2 finality itself still runs on
precommit-QC checkpoints, exactly as before. The full rule is specified in
[`../PROTOCOL.md` §6.4](../PROTOCOL.md); this section states the sharding
half of it.

*What it proves.* Inclusion of a finalized block hash under the epoch root:
"height H of epoch E is part of the finalized chain". A verifier pins ONE
32-byte root per epoch instead of 128 checkpoints.

*What still relies on QC checkpoints.* Finality itself: the MMR root is an
inclusion commitment *under* finality, not a finality mechanism. A root is
only as trustworthy as the quorum signatures over the block hash that
carries it (`stell_getFinalizedCheckpoint`, sync, `precommit_qc`).

*Sharding rules.* Only a **masterchain** block carries the commitment, and
only the **first block of an epoch** (height `E*128`, `E > 0`, committing
epoch `E-1`): a workchain block or a non-boundary height with a non-zero
root is refused, and a zero root ("not committed") is always valid. A
validator that knows the epoch's 128 bodies recomputes the root and refuses
a mismatch; one that does not know them yet accepts (contradict-if-able,
the same rule as the shard-head commitments in §5).

*Compatibility.* The field is the LAST one of the block, decoded tolerantly
on the store path, and mixed into the block hash ONLY when non-zero — every
pre-existing block keeps its hash byte-for-byte. Non-zero roots begin only
after a coordinated all-validators upgrade. See `Block::mmr_epoch_root` for
the full argument.

*RPC.* `stell_getEpochRoot { epoch | height }` recomputes the root from this
node's finalized headers and answers
`{epoch, start_height, end_height, mmr_root, peaks}` (plus `complete`,
`leaves`, and the quorum-signed `committed_root` when the committing
boundary header is known). A light client checks the answer against the
signed commitment and verifies inclusion proofs with
`light_client::verify_mmr_inclusion`.

```bash
# the MMR itself (append 1..129 incl. the 128-boundary, prove/verify each,
# tampered proofs refuse)
cargo test --lib mmr

# the block commitment (legacy hash unchanged, zero root hashes identically)
cargo test --lib sharding

# the chain helper (a fully finalized epoch commits, a partial one does not)
cargo test --lib chain
```

---

## 7. Reproducing this

```bash
# the unit tests (rule, triggers, split/merge, cap, convergence)
cargo test --lib sharding

# the integration test: split + merge over a synthetic account set, with a
# real trie, plus the RPC surface
cargo test --test sharding_topology_tests

# the cost benchmark: split / migrate / verify / merge for N accounts
cargo run --release --example sharding_split_merge_bench -- 1000 10000 100000
```

The benchmark prints, per account count, the in-process cost of the account
re-assignment, the trie migration, the verification and the merge. It does
**not** include the consensus cost of shipping the migrated state between
nodes — that part is not implemented (§0).
