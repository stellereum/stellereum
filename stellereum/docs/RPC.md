# Stellereum JSON-RPC reference

Complete reference for the node's JSON-RPC 2.0 surface. Every `stell_*` method
that exists in `src/rpc.rs` is documented here; nothing is documented that is not
in the dispatch match arm.

For running a node, see [`../testnet/README.md`](../testnet/README.md). For
operating one, see [`OPERATIONS.md`](OPERATIONS.md).

---

## 1. Transport

| | |
| --- | --- |
| Protocol | HTTP/1.1, `POST` only |
| Endpoint | `/` on `STELL_RPC_LISTEN` (default `127.0.0.1:8545`) |
| Second endpoint | `/rpc` on `STELL_EXPLORER_LISTEN` (default `127.0.0.1:8080`) — the same router, nested, and behind the gateway's rate limiter and CORS |
| Content type | any; the body is read as a string and parsed with `serde_json` |
| Max body | 1 MiB (`MAX_RPC_BODY`). Larger → `-32600 "request too large"` |
| Rate limit | standalone RPC: **300 req/s per IP** (`STELL_STANDALONE_RATE_LIMIT`, default `STANDALONE_RATE_LIMIT_DEFAULT = 300`; the legacy `STELL_RPC_RATE_LIMIT_PER_SEC` is honoured when the new name is unset). The gateway nests the same router under its own **30 req/s per IP** limiter (`STELL_RATE_LIMIT_PER_SEC`). Both are in-process fixed windows — a speed bump, not access control. |
| Auth | none on reads and none on submission: `stell_sendRawTransaction` / `eth_sendRawTransaction` are **open submission by design** (a caller can only submit a validly signed, funded, nonce-sane tx; the tx authenticates itself). Gated by `STELL_RPC_AUTH_TOKEN` (when set): `stell_mempoolDump`, `stell_submitPriceFeed`, `stell_pmmBuy`, `stell_pmmSell`, the three governance writes `stell_submitProposal`, `stell_vote`, `stell_executeProposal`, and the two wallet SIGN arms `stell_signMessage`, `stell_signTypedData` (they sign with the node's key — testing/devnet only; the VERIFY arms are public). `stell_faucet` requires the separate `STELL_FAUCET_TOKEN` and is **fail-closed**: an enabled faucet with no token refuses to dispense. |

There is exactly one route in the router — `("/", post(rpc_handler))` — so
`GET /`, or a POST to any other path, returns 404. `/health`, `/healthz`,
`/readyz`, `/metrics` and `/api/*` live on the explorer port, not here. The
router also serves the two streaming transports, `GET /ws` (WebSocket) and
`GET /events` (SSE) — see §11.

### Request shape

```json
{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":{}}
```

- `jsonrpc` is accepted and ignored.
- `id` is optional; it is echoed back, or `null` if you omitted it.
- `params` is optional; omitting it is equivalent to `null`. Most methods accept
  the bare string form as well as the object form — see the per-method notes,
  because it is not uniform.

### Response shape

Success: `{"jsonrpc":"2.0","id":<id>,"result":<value>}`
Failure: `{"jsonrpc":"2.0","id":<id>,"error":{"code":<int>,"message":"<text>"}}`

The `id` on an error is always present, including for errors raised before the
request is parsed.

### Batch requests are refused

A JSON-array body is rejected with `-32600 "batch requests are not supported:
send requests individually"` (empty arrays too). The old behavior executed
only the first element and silently dropped the rest — never rely on it.

### Error codes

| code | meaning | when |
| --- | --- | --- |
| `-32700` | parse error | body is not valid JSON |
| `-32600` | invalid request | no `method` field, wrong shape, empty batch, or body over 1 MiB |
| `-32601` | method not found | unknown method name; also `stell_faucet` when the faucet is disabled |
| `-32602` | invalid params | missing address/token/validator, bad hex, wrong length, undecodable `tx`, block outside the recent window, unknown proposal id, `tx` over the size cap, unknown subscription topic, too many `storage_keys` |
| `-32000` | chain error | bad signature, mempool rejection, faucet limit reached, faucet transfer not admitted, subscription budget exhausted, estimate-fee budget exhausted |
| `-32001` | unauthorized | `stell_mempoolDump` / `stell_submitPriceFeed` / `stell_pmmBuy` / `stell_pmmSell` / `stell_submitProposal` / `stell_vote` / `stell_executeProposal` without a valid `STELL_RPC_AUTH_TOKEN` (when one is set), or `stell_faucet` without a valid `STELL_FAUCET_TOKEN` |
| `-32003` | refused by state | the native namespace: committed state refuses the operation (insufficient balance, paused token, thin bond, replayed bridge deposit, revoked session key, …) |
| `-32004` | not available | `stell_getBlock` for a height outside the recent window, `stell_getShards` for a height above this node's tip, `stell_getProof` for a historical height this node does not serve, an unknown token / validator / pair / session key / asset |

`-32000` messages are prefixed by the mempool layer, e.g.
`"rejected: offered fee is below the base fee"`. The suffix is
`MempoolError`'s `Display`: `invalid transaction signature`,
`transaction already in mempool`, `sender exceeds mempool quota`,
`mempool is full and tx fee is too low`, `sender cannot pay amount + gas_limit`,
`offered fee is below the base fee`.

### Value encodings used throughout

- **Addresses, token ids, hashes**: 32-byte hex, `0x` prefix optional. All the
  address parsers strip `0x` and reject anything that is not exactly 32 bytes
  with `-32600` (batches are refused; send requests individually).
- **Balances, fees, supply**: **decimal strings**, not numbers. These are `u64`
  in nano-STELL and do not survive a JavaScript `Number`.
- **Block height** (`stell_blockNumber`): a hex string, `"0x2a"` for 42. Note
  that `stell_getBlock` takes the height as a JSON **number**, not a hex string.
- **Merkle proofs**: JSON arrays of integers, not hex — `serde`'s default
  serialisation for `[u8; 32]`. `proof` is `null` when the key is not in the
  trie (e.g. an account that does not exist).

---

## 2. Chain and node information

### `stell_chainId`

Parameters: none.

```json
{"jsonrpc":"2.0","id":1,"method":"stell_chainId"}
→ {"jsonrpc":"2.0","id":1,"result":5757}
```

A JSON number: this node's effective chain id — `STELL_CHAIN_ID` when it
parses to a non-zero `u64`, else the default 5757 (`zkml::DEFAULT_CHAIN_ID`;
`effective_chain_id()` in `src/zkml.rs`, wired into `RpcState` in
`src/main.rs`). `eth_chainId` / `net_version` serve the same effective id
(`0x`-hex / decimal), and receipt/tx views carry it too, so one deployment
never misidentifies itself to wallets. Signature *verification* deliberately
pins the 5757 constant (`CHAIN_ID` in `src/evm_adapter.rs`) rather than the
env: every node that admits the same raw bytes must reach the same verdict,
and a per-process env read at each verification site would let validators
with different environments admit different tx sets. A deployment on another
chain id changes the constant at build/deploy time, identically on all nodes.

### `stell_nodeId`

Parameters: none.

```json
→ {"result":"inf1:1a2b3c...  (40 hex chars)"}
```

The infnode node id, `inf1:` followed by 20 bytes of hex. This is
`blake3(own ed25519 public key)[..20]`, derived from the key in
`keys/identity.key` — so it is stable across restarts and **different for every
node**. It is not an account address; use `stell_getBalance` for accounts.

### `stell_blockNumber`

Parameters: none.

```json
→ {"result":"0x2a"}
```

The current **finalized** height as a lowercase hex string with an `0x` prefix.
Updated by the consensus loop at each finalization.

### `stell_syncing`

Parameters: none.

```json
→ {"result":false}
```

True while a recent verified peer sighting names a height above ours
(vantage-local; sightings older than 5 minutes are ignored). See "Stalled vs
syncing" in [`OPERATIONS.md`](OPERATIONS.md).

### `stell_getStateRoot`

Parameters: none.

```json
→ {"result":"<64 hex chars>"}
```

The current Patricia trie root. The root commits to native balances, STS token
balances and supply, contract code hashes, and — under the single key
`sha256("STELL_CONSENSUS_COMMITMENT_V1")` — a digest over the staking ledger,
order books, order escrow, the PMM, contracts, **governance** and the **oracle
feed** (`COMMITMENT_VERSION = 5`; governance joined in version 3, the oracle in
version 4). The bridge is committed as its escrow account (an ordinary trie
account) plus a **conditional** bridge domain (replay set, withdrawal queue,
rate-limit window, escrow mirror) that contributes digest bytes only once a
deposit or withdrawal has landed. See `../../PROTOCOL.md` §1.

Two consequences worth knowing before you build tooling on it:

- Reading it has a **side effect on first read after a mutation**: the commitment
  digest is recomputed and written into the trie if it changed (PROTOCOL.md I3).
  It is not a pure read.
- The non-trie subsystems are committed **as one digest**, not per key. A client
  can therefore prove a native balance against this root, but cannot prove a
  single staking entry or orderbook level. That is a documented gap
  (PROTOCOL.md §7), not an oversight in the RPC layer.

This is the right method for checking that two nodes are on the same chain: pair
it with `stell_blockNumber`, because height alone proves nothing.

### `stell_latestBlocks`

Parameters: none.

```json
→ {"result":[
     {"height":42,"hash":"<64 hex>","txs":3,"timestamp":1758800000},
     {"height":41,"hash":"<64 hex>","txs":0,"timestamp":1758799996}
   ]}
```

Newest first, capped at **100 entries** (`MAX_RECENT_BLOCKS`); older entries are
dropped from this in-memory window. Empty array before the first finalization.

This is a rolling window, not a store: it is not persisted, and a restarted node
rebuilds it as it produces blocks. It is a convenience feed, not a queryable
chain.

### `stell_getBlock`

Parameters: `{"height": <number>}`.

```json
{"method":"stell_getBlock","params":{"height":42}}
→ {"result":{"height":42,"hash":"<64 hex>","txs":3,"timestamp":1758800000}}
```

Errors: `-32004 "block not available yet"` for well-formed but unknown heights (`-32602` is malformed params only).

**Searches the same 100-entry window as `stell_latestBlocks` and nothing else.**
There is no block-hash lookup, no transaction search, and no pagination. There is
no way to read a block body over RPC at all: the summary carries only the hash
and the transaction count. Block bodies live in the node's sled store at
`./data/store` and on the P2P network under the `stell_blocks` bucket, neither of
which is exposed here.

`height` must be a JSON number. A hex string (`"0x2a"`) is read as
`params["height"].as_u64()` → `None`, which is compared against the window and
yields the "not found" error rather than a type error.

### `stell_getBlockTransactions`

Parameters: `{"height": <number>}` (or the bare number form).

```json
{"method":"stell_getBlockTransactions","params":{"height":42}}
→ {"result":{"height":42,"txs":[
    {"tx_hash":"<64 hex>","index":0,"status":"success",
     "gas_limit":"1000","fee_charged":"1000","raw_tx":"<hex>"}
  ]}}
```

- **Read.** No token.
- The transactions of one block, served from the **same receipt index** as
  `stell_getTransactionReceipt` — the index is filed by the single real
  application on finalize *and* on adopt, so any node serves adopted heights.
- `status` is `"success"` or `"failed"`. `index` is the position within the
  block. `gas_limit` and `fee_charged` are decimal strings; `fee_charged` is
  what the transaction was actually debited (0 for a failed transaction under
  the F-01 failure-fee rule — see `PROTOCOL.md` §4c).
- `raw_tx` is present only when the receipt carries it (the hex of the
  bincode-serialised transaction).
- Errors: `-32602 "missing height"` when no height is given;
  `-32004 "block transactions not available yet (height not adopted/replicated on this node)"`
  for a height this node has not committed or adopted. An **empty** `txs` array
  means "this block is known and has zero transactions" — never "unknown".

### `stell_getShards`

Parameters: none, or `{"height": <number>}` (optional).

```json
{"method":"stell_getShards","params":{}}
→ {"result":{
     "shards":[
       {"shard_id":0,"type":"masterchain","tip_height":285028,
        "tip_hash":"<64 hex>","state_root":"<64 hex>","local":true},
       {"shard_id":1,"type":"workchain","tip_height":63400,
        "tip_hash":"<64 hex>","state_root":"<64 hex>","local":false}
     ],
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

The **shard topology** — the analogue of TON's `liteServer.getShards` and
Near's `shard_layout`. A wallet or an indexer asks the node which shards exist,
what kind of chain each one is, and where its head is, instead of assuming one
global chain and guessing which one holds an account.

- `shard_id` — `0` is the masterchain (global state, consensus), `>= 1` are
  workchain shards.
- `type` — `"masterchain"` or `"workchain"`.
- `tip_height` / `tip_hash` / `state_root` — the head this node **committed**
  for that shard: the height, the block hash and the state root after applying
  it. `tip_hash` and `state_root` are `null` when the node has no committed
  head for that shard.
- `local` — `true` for the shard this node's own engine runs.
- `total_shards` — how many shards are listed.
- `routing_prefix_bits` — `ceil(log2(total_shards))`: how many bits of an
  address's routing prefix a client needs to pick a shard. One shard needs no
  routing bit (the pre-sharding single-chain layout), two need exactly one.
- `sharding` — the **published sharding parameters** and the
  **address→shard rule**: the rule id and its text, the routing prefix length
  the topology uses, the masterchain shard id, the base workchain shard id,
  the masterchain address form (`-1:<addr>`), and the thresholds
  (`min_accounts_per_shard`, `max_shards`, `split_load_threshold`,
  `merge_load_threshold`, `max_prefix_bits`).

**`max_shards` is the shipped capacity; `max_workchain_shard_space` is the
advertised address space (2^60).** They are different numbers on purpose and
are reported separately: the advertised space is not a capacity. See
[`docs/SHARDING.md`](SHARDING.md) for the full rule.

Every head comes from the node's own **finalized-header registry**, which is
written only by the block-application paths (finalize / adopt / walk) and never
from gossip, RPC or DHT blobs — so a listed tip is a head this node applied,
the same trust basis as `stell_getStateRoot`. A shard the node has not
committed anything for is **not listed** (a miss, never a zeroed entry).

The shard *set* is a property of the network configuration, not of a height,
and no per-height history of it is kept. `height` is therefore a **bound, not
a selector**: a height at or below this node's tip is accepted and answered
with the current topology, and a height **above** the tip is refused with
`-32004 "requested height N is above this node's tip (M)"` rather than
answered with a head the node has not committed.

### `stell_getShardTopology`

Parameters: none.

```json
{"method":"stell_getShardTopology","params":{}}
→ {"result":{
     "parameters":{ ...the same object as stell_getShards' "sharding"... },
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

The **layout** of the address space, as opposed to `stell_getShards`, which
reports the committed heads. `prefix_bits` is the routing prefix as a bit
string (most significant first), so a client can verify the routing rule by
hand: the longest matching prefix wins, ties broken by the smallest shard id.
`accounts`, `balance` and `tx_load` are the shard's account count, the
balance it holds and its recorded load (txs per window) — the load is what
the split/merge triggers read. `transitions` is how many split/merge
transitions the topology has applied.


### `stell_getInvalidations`

Parameters: none, or `{"limit": <number>}` (optional).

```json
{"method":"stell_getInvalidations","params":{}}
→ {"result":{
     "invalidations":[
       {"height":42,"reason":"candidate branch superseded at height 42",
        "orphaned_blocks":["<64 hex>"],"orphaned_count":1}
     ],
     "count":1
   }}
```

The **block invalidation feed**: the blocks this node told the world about and
then could **not** keep. A block is invalidated when

- a competing candidate branch lost the fork-choice (another block was
  finalized at that height), or
- a reorg rolled a branch back.

- `height` — the height of the **lowest** orphaned block, i.e. the first
  height a consumer has to re-sync from.
- `orphaned_blocks` — the block hashes, **tip-first** (the order the chain
  unwound them). Never applied: BFT finality forbids rolling back an applied
  block, so these blocks were only ever *candidates*.
- `reason` — human-readable. Not a machine contract; the machine contract is
  `orphaned_blocks` + `height`.
- `count` — how many signals the answer carries.

`limit` caps how many of the most recent signals are returned (`0` / absent =
the whole window). The window is bounded (**64 entries**,
`MAX_INVALIDATION_WINDOW`), so an unbounded answer is bounded by construction.
It is a rolling window, not a store: it is not persisted, and a restarted node
starts empty.

The push side of the same feed is the `invalidations` subscription topic
(`stell_subscribe` with `["invalidations"]`), delivered over the WebSocket
(`/ws`) and SSE (`/events`) transports. `stell_invalidationFeed` is accepted
as an alias of this method.

---

## 3. Accounts and state

### `stell_getBalance`

Parameters: either the bare string form or `{"address": "<hex>"}`.

```json
{"method":"stell_getBalance","params":"3b0c...  (64 hex chars)"}
→ {"result":{"balance":"5000","nonce":2}}
```

`balance` is nano-STELL as a decimal string; `nonce` is a JSON number. An
account that does not exist returns `{"balance":"0","nonce":0}` — absence is not
distinguishable from an empty account, and no account is created.

### `stell_getBalanceSpv`

Parameters: `{"address": "<hex>"}` — **object form only.** The bare string form
returns `-32602 "missing address"` here, unlike `stell_getBalance`.

```json
→ {"result":{
     "address":"<64 hex>",
     "balance":"5000",
     "nonce":2,
     "stateRoot":"<64 hex>",
     "proof":{"key":[...],"value_hash":[...],"leaf_hash":[...],
              "path":[{"sibling_is_right":true,"sibling_hash":[...],
                       "branch_prefix":[...],"skip":3,"branch_bit":0}, ...]}
   }}
```

Everything `stell_getBalance` returns, plus the state root and a Merkle
inclusion proof against it. `proof` is `null` for an account with no trie entry.

`branch_prefix` is a legacy field kept for wire compatibility and is unused by
the compressed trie model — ignore it when verifying. The proof verifies against
`stateRoot` as returned in the *same* response, so this is a consistency check,
not a light client: the node hands you the root it believes. For a proof you
can check against a root *you* trust, use `stell_getProof` below.

### `stell_getProof`

Parameters: `{"address": "<hex | Stl57>", "storage_keys": ["<hex>", ...],
"block_height": <u64>}` — `storage_keys` and `block_height` are optional.

```json
→ {"result":{
     "address":"<64 hex>",
     "balance":1000000000000,
     "nonce":5,
     "account_proof":["<hex node>", ...],
     "storage_proofs":[{"key":"<64 hex>","value":"<hex>|null",
                         "exists":true,"proof":["<hex node>", ...]}, ...],
     "state_root":"<64 hex>",
     "stateRoot":"<64 hex>",
     "height":42,
     "exists":true
   }}
```

Merkle **inclusion and exclusion** proofs against the node's state root.

Unlike `stell_getBalanceSpv` (whose proof verifies against whatever root the
caller supplies), this endpoint exists to be checked against a *trusted* root:
the proofs and the root come from the same state snapshot, and the proof
carries the leaf value it commits to, so a verifier recomputes the leaf hash
from the proof's own bytes instead of believing the server's numbers.

- `account_proof` is an inclusion proof when the account is in the state, and
  an **exclusion proof** when it is not — "this account does not exist" is a
  provable claim here, not a shrug.
- `storage_keys` are raw 32-byte state-trie keys (hex). This chain has no EVM
  storage trie, so there is nothing else they could mean. At most 32 per
  request.
- `block_height` is accepted only for the height the node currently serves;
  a different height returns `-32004` ("historical state is not available on
  this node") rather than today's proof under an old label.
- The address accepts both hex and the branded `Stl57...` form.
- An exclusion proof names the leaf it diverged from (`witness_key` and its
  value in the leaf node). That is ordinary public state — the same leaf any
  full node would show you — but it is worth knowing before you publish an
  answer.

**Proof wire format.** `account_proof` and each `proof` are hex nodes, leaf
first:

```
leaf node   : 4C | kind(1) | div_kind(1) | div_step(2 BE)
              | key(32) | witness_key(32) | value_len(4 BE) | value | leaf_hash(32)
branch node : 42 | skip(2 BE) | bit(1) | flags(1) | sibling_hash(32)
```

`kind` is `00` (inclusion) or `01` (exclusion); `flags` bit 0 is "the sibling
sits on the right". The leaf hash is
`blake3("L" ‖ key ‖ len(value) ‖ value)` and a branch hash is
`blake3("B" ‖ skip_be ‖ bit ‖ left ‖ right)`.

`crate::light_client::LightClient::verify_proof_answer` parses this form and
checks it against a finalized header's state root.

### `stell_getArchiveProof`

Parameters: `{"address": "<hex | Stl57>", "key": "<hex>", "height": <u64>}` —
`key` is optional.

```json
→ {"result":{
     "height":40,
     "state_root":"<64 hex>",
     "key":"<64 hex>",
     "value":"<hex>|null",
     "proof":["<hex node>", ...],
     "proof_type":"inclusion"|"exclusion"
   }}
```

A per-key proof against a **historical** state root: what key `K` held at
height `H`, long after the node pruned its live trie forward. The proof is
rebuilt from the node's persisted snapshot history, never from the live
trie, and verifies with `cpat2::ArchiveProof::verify` (the same leaf/branch
wire format as `stell_getProof`).

- Without `key` the account leaf itself (`address`) is proven. With `key`
  any raw 32-byte state-trie slot is proven: an STS balance cell
  (`sha256("STS_BAL" ‖ token_id ‖ account)`), an STS supply cell, a
  contract code hash, a contract ABI manifest, or the consensus-commitment
  digest leaf. See the slot model in `src/storage.rs`.
- `value` is `null` with `proof_type: "exclusion"` when the key did not
  exist at that height — absence is proven, not asserted.
- Only **snapshot heights** are servable (snapshots are taken every
  `STELL_SNAPSHOT_INTERVAL` heights, not every height). An unknown height,
  a pruned height, or a height above the tip returns `-32004` — never an
  empty answer, never a live-trie proof relabeled as history.
- Domains folded into the consensus commitment digest (staking entries,
  orderbook levels, contract storage slots, ...) have **no per-key proof**:
  the trie holds one leaf for all of them. The node proves the digest, not
  the entry.

`crate::light_client::LightClient::verify_archive_proof` checks the proof
against a finalized historical root — pair every call with
`stell_getHistoricalRoot`, whose QC the client checks against its own
validator set.

### `stell_getHistoricalRoot`

Parameters: `{"height": <u64>}`.

```json
→ {"result":{
     "height":40,
     "state_root":"<64 hex>",
     "stateRoot":"<64 hex>",
     "anchor_height":41,
     "anchor_hash":"<64 hex>",
     "prev_hash":"<64 hex>",
     "cert":{"height":41,"round":0,"kind":"Precommit",
             "block_hash":"<64 hex>",
             "signatures":[{"validator":"<64 hex>","signature":"<hex>"}, ...]},
     "finalized":true
   }}
```

The authenticated historical root: the post-`height` state root together
with the quorum certificate that commits to it. The root is the
`state_root` of the finalized block at `height + 1` (a header commits to
the state **before** its own block), and `cert` is that block's precommit
QC, in the same shape as `stell_getFinalizedHeader` so the client reuses
one parser (`Checkpoint::from_historical_root_json` +
`Checkpoint::verify`, then `LightClient::advance_to_checkpoint`).

Fail closed: a height above the tip, an unknown height, or a height whose
anchoring body's QC was pruned returns `-32004`. A header record alone
never authenticates — it carries no certificate.

### `stell_getFinalizedHeader`

Parameters: `{"height": <u64>}`.

```json
→ {"result":{
     "height":42,
     "block_hash":"<64 hex>",
     "prev_hash":"<64 hex>",
     "state_root":"<64 hex>",
     "proposer":"<64 hex>",
     "timestamp":1700000000,
     "cert":{"height":42,"round":0,"kind":"Precommit",
             "block_hash":"<64 hex>",
             "signatures":[{"validator":"<64 hex>","signature":"<hex>"}, ...]}
   }}
```

The finalized header at that height **with the precommit quorum certificate
that decided it**. This is what makes a served proof meaningful: the root a
proof authenticates against is only trustworthy if a quorum committed to it,
and the certificate is the evidence.

Chain convention: a header commits to the state **before** its own block, so
the `state_root` here is the root of the state at `height - 1`. The node's
live proofs are served against the current state, so the header that commits
to them is the one at `height + 1`.

A height outside the node's retained window (the most recent 512) returns
`-32004` ("not available on this node") — never a fabricated header.

### `stell_getFinalizedCheckpoint`

Parameters: none.

The node's LIGHT CLIENT anchor: its newest finalized header with the quorum
certificate that decided it. A client that verifies the certificate against
its **own** (out-of-band) validator set has a TRUSTED root and can re-anchor
here. The anchor only ever moves forward.

### `stell_zkmlCapabilities`

Parameters: none.

The machine-readable statement of what the zkML opcodes actually offer. Read
it instead of trusting a name: `zero_knowledge`, `succinct`, `hiding` and
`trusted_setup` are all `false`, `sound` is `true`, and each opcode says what
it really does, what it trusts and how much work the verifier does. The
on-chain inference check is a **re-execution attestation**, not a
zero-knowledge proof (audit W8.3 / production blocker A5).

### The external verifier

```sh
stellereum light-client --from http://127.0.0.1:8545 \
  --verify <address hex> --validators validators.json
```

Fetches the proof, fetches the header at `height + 1` (the header that
COMMITS to the served root), verifies that header's quorum certificate
against the **out-of-band** validator set you pinned, and only then checks
the Merkle proof. The server's word is never enough: a root it made up, a
certificate signed by keys that are not validators, and a proof from another
chain are all refused. See `docs/OPERATIONS.md` §12.1.

### `stell_tokenBalance`

Parameters: `{"token": "<hex>", "account": "<hex>"}`.

```json
→ {"result":"1000"}
```

STS token balance as a decimal string, in the token's own units. Errors:
`-32602 "missing token/account"`. Note that a parameter that is present but
unparseable is treated as missing here (`and_then(parse_hash)`), so you get the
same error for a typo as for an absent field.

### `stell_tokenSupply`

Parameters: `{"token": "<hex>"}`.

```json
→ {"result":"1000"}
```

Total supply as a decimal string. An unknown token id returns `"0"`, not an
error.

### `stell_tokenResolve`

Parameters: `{"creator": "<hex>", "name": "<string>", "symbol": "<string>"}`.

```json
{"method":"stell_tokenResolve",
 "params":{"creator":"<64 hex>","name":"Tether USD","symbol":"wUSDT"}}
→ {"result":{"token":"<64 hex>"}}
```

Read-only **id discovery** for tokens created on chain: the create-transaction
receipt carries no token id, and the id commits the registry nonce (so it is
not predictable off chain), so a client resolves by the
`(creator, name, symbol)` it chose at creation.

Both `name` and `symbol` are **required**: an empty name widens the
collision/phishing surface, and a real token always carries both. A missing
one is `-32602 "missing name/symbol"`; an unknown creator is `-32602 "missing
creator"`; a token that does not exist is `-32004 "token not found"`.

### `stell_tokenBalanceSpv`

Parameters: `{"token": "<hex>", "account": "<hex>"}`.

```json
→ {"result":{
     "balance":"1000",
     "stateRoot":"<64 hex>",
     "key":"<64 hex>",
     "proof":{...}
   }}
```

The same proof structure as `stell_getBalanceSpv`, keyed by
`sha256("STS_BAL" ‖ token_id ‖ account)` — which is the `key` field returned, so
a verifier does not have to re-derive the namespacing to check it. The
namespacing itself is a protocol constant (PROTOCOL.md §1.1); this method is the
only place the node hands it to you precomputed.

### `stell_listTokens`

Parameters: none.

```json
→ {"result":{"tokens":["<64 hex>"],"total":1,"offset":0}}
```

Every token id in the registry, as hex. Paginated: `limit` (default 100, max
1000) + `offset`. Use `stell_tokenResolve` (`creator`+`name`+`symbol`) to find
the id of a token you created. There is no metadata method: name,
symbol, decimals, minter and supply cap are not exposed over RPC. To read
`decimals` you have to out-of-band agree on it — the CLI and the PMM treat
USDT as 6 decimals and everything else as 9.

---

## 4. Transactions

### `stell_getTransactionReceipt`

Parameters: `{"hash": "<hex>"}` or the bare string form.

```json
{"method":"stell_getTransactionReceipt","params":"<64 hex>"}
→ {"result":{
     "tx_hash":"<64 hex>",
     "height":77,
     "block_hash":"<64 hex>",
     "index":0,
     "status":"success",
     "gas_limit":"1000",
     "fee_charged":"1000",
     "raw_tx":"<hex>",
     "contract_address":"<64 hex>",
     "contract_address_stl57":"EQ…",
     "return_value":42,
     "gas_used":280000,
     "events":[
       {"contract":"<64 hex>","contract_stl57":"EQ…",
        "topic":"Transfer","value":"1000"}
     ]
   }}
```

`status` is `"success"` or `"failed"`. `index` is the position within the block.
`gas_limit` is a decimal string. `confirmations` is `head - height + 1` under
the node's current finalized head (1 at finality — see the "Confirmations"
tiers below); it grows as the chain extends, so a client that caches the
receipt must recompute depth itself or re-poll.

**The outcome fields.** A receipt carries the *outcome* of the transaction, not
just its inclusion:

- `fee_charged` — what the sender was actually debited, in nano-STELL, as a
  decimal string. It is **0 for a failed transaction under the F-01 rule** when
  the failure is not attributable (a replay or a nonce gap); an attributable
  failure pays the failure fee (see `PROTOCOL.md` §4c).
- `return_value` — the contract call's return value (a JSON number) or `null`
  for a plain transfer.
- `gas_used` — the gas the execution actually consumed, as a JSON number.
- `events` — the contract events the transaction emitted. Each event is
  `{contract, contract_stl57, topic, value}`; `topic` is the event name (or
  topic id) and `value` is the event payload as a string.
- `contract_address` / `contract_address_stl57` — the contract the transaction
  deployed or called, when it was one.

`return_value`, `gas_used` and `events` are present only on a receipt that has
them (the fields are omitted, not nulled, when absent).

**If the hash is not in the index**, the same method answers with a *different
shape* rather than an error:

```json
→ {"result":{"status":"pending"}}    // still in this node's mempool
→ {"result":{"status":"unknown"}}    // not here at all
```

So a client must handle three result shapes from one method, and `pending`
only knows about **this node's** mempool. On a multi-validator network a
transaction in a peer's mempool reads as `unknown` here. There is no way to ask
another node. `gas_limit` is what the transaction *offered*; `fee_charged` is
what it was charged.

The index is bounded at 50,000 receipts (`MAX_RECEIPTS`) and evicts oldest-first,
so a receipt for an old transaction is `unknown` rather than an error.

Statuses are captured at the single point where a block is actually applied and
are never recomputed — re-deriving a verdict from post-state would report every
successful transaction as failed, because the nonce has already moved
(PROTOCOL.md I8).

### `stell_getTransactionStatus`

Parameters: `{"hash": "<hex>"}` or the bare string form.

```json
→ {"result":{"status":"success","height":77,"confirmations":3}}
→ {"result":{"status":"failed","height":77,"confirmations":3}}
→ {"result":{"status":"pending","height":null,"confirmations":0}}
→ {"result":{"status":"unknown","height":null,"confirmations":null}}
```

The same information as the receipt, reduced to a four-valued status, the
height, and the confirmation depth. Unified vocabulary across
receipt/status/explorer: `success` (formerly `mined`), `failed`, `pending`,
`unknown`. `height` is `null` unless the transaction was included.
`confirmations` is `head - height + 1` for an included transaction (the
inclusion block counts as 1), `0` for a mempool-pending transaction
(accepted locally, finalized nowhere), and `null` for `unknown` (this node
holds no verdict at all).

A cheap liveness poll, but see the `pending`-is-local caveat above.

### Confirmations: what one confirmation MEANS here (read before you pick a number)

This chain has **single-block BFT finality**: a block is final when it
carries a **precommit quorum certificate** of at least
`quorum_power() = floor(2·total_power/3) + 1` (`OPERATIONS.md` §5;
`stell_getValidators` reports the live `quorum`). There is no probabilistic
tail to wait out — **one confirmation IS final**, and a finalized block is
never rolled back (the invalidation feed below only ever covers
*candidate* branches that lost, never applied blocks).

So "N confirmations" on Stellereum means "N finalized blocks on top of the
inclusion block", and it buys **depth against operational risk** (a stale
read, a lagging node, an indexer that has not caught up) — not safety
against reorganization. Recommended floors per value tier:

| tier | recommended confirmations | rationale |
| --- | --- | --- |
| dust / test drips | **1** (finalized inclusion) | finality already holds; `success` at `height` is enough |
| ordinary payments (< 1k STELL) | **2–3** | one extra block proves the network kept finalizing *after* your tx (liveness, not safety) |
| large transfers / bridge releases (≥ 50k STELL, the 1 h time-lock band) | **10+** and a cross-node `stell_getStateRoot` match | bridge settlement is what attackers target; confirm the root on two independent nodes, not just the count |
| exchange / custodian crediting | **30+** and the receipt's `block_hash` re-fetched from a second node | protects against your *own* node's stale view, never against a chain reorg (there is none past finality) |

Poll with `stell_getTransactionStatus` / `stell_getTransactionReceipt`
(status `success` + `confirmations`), and cross-check depth with
`stell_blockNumber` (all hex heights; §2) when you do not trust one node's
arithmetic. A receipt that reads `unknown` after previously reading
`pending` means the tx left *this node's* mempool without being included
(evicted or never gossiped here) — re-submit, do not assume
failure.

**Where to watch reorganizations and invalidations.** Finalized blocks
never reorg, but *candidate* branches do: the feed is
`stell_getInvalidations` (rolling **64-entry** window,
`MAX_INVALIDATION_WINDOW`, §2 — a restarted node starts empty) and the
`invalidations` push topic over `stell_subscribe` on the WebSocket (`/ws`)
and SSE (`/events`) transports (§2, §11). Each signal names the lowest
orphaned height (`height`) and the unwound hashes tip-first
(`orphaned_blocks`) — re-sync consumers from that height. The explorer
surfaces the same vocabulary (`success` / `failed` / `pending` / `unknown`)
and should link this section wherever it renders a confirmation count.

### `stell_sendRawTransaction`

Parameters: `{"tx": "<hex>"}`. No token: submission is open by design (see
§1 Transport).

```json
{"method":"stell_sendRawTransaction",
 "params":{"tx":"<hex of bincode(Transaction)>"}}
→ {"result":"<64 hex tx hash>"}
```

`tx` is the bincode serialisation of the `Transaction` struct, hex encoded, with
an optional `0x` prefix. The struct is
`{ from, to, amount, gas_limit, nonce, source_shard, target_shard, signature,
payload }` with `payload` defaulting to empty. The signature covers the payload,
so it cannot be swapped after signing.

This is a write-shaped method alongside the faucet, the signed-payload arms
(`stell_submitPriceFeed`, `stell_pmmBuy`, `stell_pmmSell`) and the EVM
`eth_sendRawTransaction`, and it is worth being precise
about what it does and does not do: it **validates and admits** a transaction to
the mempool. It cannot forge a signature and it cannot bypass admission — bad
signatures are rejected before the mempool is touched. But admission is not
finality. `add_checked` verifies the signature, enforces the base fee, checks
that the sender can cover `amount + gas_limit`, rejects duplicates, enforces the
per-sender quota, and evicts the lowest-fee entry if the pool is full. **Far-future
nonces are rejected up front** (nonce-gap fail-fast, window 16): a transaction
whose nonce jumps ahead of the on-chain nonce is refused here instead of sitting
in the pool forever behind an unreachable head. A transaction with a stale nonce
is still accepted here and then skipped by the block producer, which requires a
contiguous per-sender nonce sequence. Watch `stell_getTransactionStatus` rather than
assuming success means inclusion.

No token is checked on this method, even when `STELL_RPC_AUTH_TOKEN` is set:
the transaction authenticates itself via its signature, and spam is bounded by
the per-IP limiters plus pool caps. (The token gates `stell_mempoolDump` and
the signed-payload arms listed above.)

Errors:

| code | condition |
| --- | --- |
| `-32602 "missing tx"` | no `tx` parameter |
| `-32602 "bad hex: …"` | `tx` is not hex |
| `-32602 "transaction too large"` | decoded `tx` over 1 MiB |
| `-32602 "decode: …"` | hex decoded but not a valid bincode `Transaction` |
| `-32000 "invalid transaction signature"` | the signature does not verify |
| `-32000 "rejected: …"` | any `MempoolError` from admission, e.g. `sender cannot pay amount + gas_limit`, or a nonce-gap refusal |

On success the transaction is also pushed to P2P gossip, so it is forwarded to
peers without waiting for them to see it in a block.

### Sponsored transactions (gasless path, paymaster v1)

A sponsored transaction moves value FROM the user while the FEE (base + gas +
failure-fee on revert) is paid by a third-party SPONSOR. The envelope rides
the existing `signature` field (`inner_sig ++ bincode(auth) ++ len ++ "SP1"`),
so submission is byte-identical to the flow above: build, serialize, hex,
`stell_sendRawTransaction`. Nothing else changes on the wire.

Wallet building flow (see `docs/PAYMASTER.md` for the full contract):

1. The user constructs the action exactly as today (`to`, `amount`,
   `gas_limit`, `nonce`, shards, payload, priority bid) and agrees caps with
   the sponsor off-chain: `max_fee_per_tx` (hard ceiling on the fee),
   `valid_until` (Unix seconds), `allowed_targets` (recipient allowlist,
   empty = any), `chain_id` (5757 on this deployment).
2. The SPONSOR signs first: `sponsor_message` commits to the tx core plus the
   caps, so the grant cannot be grafted onto another transaction.
3. The USER signs second: `signing_message` commits to the action plus the
   FULL grant (including `sponsor_sig`), so the grant cannot be swapped after
   signing. Signing order is load-bearing.
4. SDK hook: `Transaction::sign_with_sponsor(user_key, sponsor_key, to,
   amount, gas_limit, nonce, source_shard, target_shard, payload,
   priority_fee_per_gas, max_fee_per_tx, valid_until, allowed_targets,
   chain_id)` performs steps 2–3 in the required order and returns a
   submittable `Transaction`. `sponsor == from` fee-routes as plain (the user
   pays their own fee; both signatures are still verified).
5. Submit via `stell_sendRawTransaction` and watch
   `stell_getTransactionStatus` as usual. The receipt's `fee_charged` is what
   the SPONSOR paid; the user's balance moves only by the value.

v1 composes ONLY with a plain legacy ed25519 inner signature (no
session-key, chain-bound, PQ or EVM inner). A sponsored transaction whose
sponsor cannot cover the fee is refused BEFORE pool entry and never occupies
mempool space.

Sponsor-specific admission errors (all `-32000 "rejected: …"`):

| condition | message |
| --- | --- |
| malformed suffix or unsupported inner composition | `invalid sponsor grant` |
| sponsor signature does not verify (BOTH sigs are required) | `invalid sponsor signature` |
| grant past `valid_until` | `sponsor grant has expired` |
| `to` not in `allowed_targets` | `sponsor grant does not cover this recipient (allowlist)` |
| fee above `max_fee_per_tx` | `sponsor grant per-tx fee cap does not cover this transaction's fee` |
| sponsor cannot cover the fee (or no sponsor balance carried) | `sponsor cannot pay the transaction fee` |

Execution semantics for wallets to display: on success the sponsor is
debited the fee and the user nonce advances; on attributable failure the
sponsor pays the failure fee and the user nonce STILL advances (the failure
is not replayable); a failure the sponsor cannot cover moves NOTHING (no
fee, no nonce). The sponsor nonce never advances.

Mempool limits come from `Mempool::default()` and are overridable by env:
50,000 transactions (`STELL_MEMPOOL_CAP`) and 1,024 pending per sender
(`STELL_MEMPOOL_PER_SENDER`). A block is bounded separately at
10,000 transactions (`MAX_BLOCK_TXS`) and 500,000,000 total gas (`MAX_BLOCK_GAS`
in `src/runtime.rs`).

### Chain-binding rollout (unbound → bound admission)

A transaction signature by default covers **no chain id**: the same signed
bytes verify on any chain that shares the key (testnet signatures replay on
mainnet). The bound envelope exists (`Transaction::sign_with_chain_id`,
session grants, PQ chain binding, EVM `chain_id`), but nothing forced its
use — so the rollout is phased, and every phase is observable:

| phase | node behavior | wallet behavior | how to tell |
| --- | --- | --- | --- |
| **1 — warn+meter (live now)** | unbound txs are **admitted**; every one logs a `tracing::warn!` (`[mempool] admitting UNBOUND …`) and increments `stell_unbound_tx_total` | `pay`/`stake` default to **bound** envelopes; `--unbound-legacy` recovers the old bytes with a loud warning (`unbound_legacy_*` in `src/wallet.rs`) | scrape `stell_unbound_tx_total`; `rate(...[5m]) > 0` means unbound traffic is still flowing |
| **2 — default-bound wallets** | unchanged (phase-1 metering) | **all** wallet paths default to bound; PQ envelopes bind via `new_*_with_chain` | the counter goes flat at the wallet upgrade |
| **3 — require bound** | admission **refuses** unbound (`verify_signature_for_chain(id, true)`), like the strict check wallets already run locally | no change needed | counter flat at zero; refusals surface as `-32000 rejected` |

Until phase 3, integrators should treat a non-zero `stell_unbound_tx_total`
as "replayable traffic this node accepted" and prefer bound construction
(`chain_id` 5757 on this deployment, resolved live from the node when
possible — the wallet never hard-codes it). Session-keyed and EVM-settled
transactions are bound by construction and never touch the meter.

### `eth_estimateGas` (floor-aware admission estimate)

Parameters: `[{to, data, ...}]` (same call object as `eth_call`).

```json
{"method":"eth_estimateGas","params":[{"to":"0x3535...","data":"0xaabbccdd"}]}
→ {"result":"0x445c0"}
```

This is an **admission** estimate, not execution metering: EVM calldata is
never executed (plain-transfer settlement; contract creation is rejected), and
`gas_price` / `max_fee_per_gas` on the EVM views are display-only. The node
returns `max(pure EVM figure, live admission floor)`, where the pure figure is
21k (transfer) / 53k (creation) + 4 per zero calldata byte + 16 per non-zero
byte, and the floor is the mempool `base_fee` served read-only as
`stell_baseFee`. A wallet that forwards this figure is never told a number the
same node would reject for under-declared gas.

### EVM / `net_*` / `web3_*` compatibility surface

The node serves a read-only EVM-compatible view plus the standard `net_*` /
`web3_*` network labels so wallets, explorers and EVM tooling can connect
without a Stellereum adapter. All of these are **live in the `POST /`
dispatch** (`src/rpc.rs` → `src/evm_adapter.rs`); they never mutate state.
`eth_sendRawTransaction` is the one write: it converts the signed EVM bytes
to a Stellereum transaction and admits it through the same mempool gate as
`stell_sendRawTransaction` (open submission by design — the signature, nonce
and solvency authenticate the caller).

| method | params | result |
| --- | --- | --- |
| `eth_chainId` | — | `"0x167d"` (effective chain id as `0x`-hex) |
| `net_version` | — | `"5757"` (same id, decimal) |
| `web3_clientVersion` | — | client string |
| `net_listening` | — | bool |
| `net_peerCount` | — | `"0x2"` testnet-known default (no live peer table on this path) |
| `eth_syncing` | — | bool (true while a recent verified peer height is above ours) |
| `eth_gasPrice` | — | display-only `0x`-hex (admission floor lives in `stell_baseFee`) |
| `eth_maxPriorityFeePerGas` | — | display-only `0x`-hex |
| `eth_estimateGas` | `[{to, data, …}]` | `max(pure EVM figure, live admission floor)` as `0x`-hex (see above) |
| `eth_feeHistory` | EIP-1559 `feeHistory` params | fee-history object for the finalized head |
| `eth_getCode` | `[address, block]` | deployed code or `"0x"` |
| `eth_getBalance` | `[address, block]` | balance as `0x`-hex (nano-STELL × 10⁹ wei mapping) |
| `eth_getTransactionCount` | `[address, block]` | nonce as `0x`-hex |
| `eth_blockNumber` | — | finalized height as `0x`-hex |
| `eth_getBlockByNumber` | `[block, full_txs?]` | block view or `null` |
| `eth_getBlockByHash` | `[hash, full_txs?]` | block view or `null` |
| `eth_getTransactionReceipt` | `[hash]` | receipt view or `null` |
| `eth_getTransactionByHash` | `[hash]` | tx view or `null` |
| `eth_getBlockTransactionCountByHash` | `[hash]` | count as `0x`-hex or `null` |
| `eth_getBlockTransactionCountByNumber` | `[block]` | count as `0x`-hex or `null` |
| `eth_getTransactionByBlockHashAndIndex` | `[hash, index]` | tx view or `null` |
| `eth_getTransactionByBlockNumberAndIndex` | `[block, index]` | tx view or `null` |
| `eth_getUncleCountByBlockHash` | `[hash]` | `"0x0"` for a known block, `null` for unknown (no uncles on this chain) |
| `eth_getUncleCountByBlockNumber` | `[block]` | `"0x0"` for a known block, `null` for unknown |
| `eth_getUncleByBlockHashAndIndex` | `[hash, index]` | `null` (no uncles) |
| `eth_getUncleByBlockNumberAndIndex` | `[block, index]` | `null` (no uncles) |
| `eth_call` | `[{to, data, …}, block]` | ERC-20 stub result (`0x…0001`, `u128::MAX` for allowance) or `"0x"` for unknown selectors — never executed |
| `eth_newBlockFilter` | — | new filter id (`0x`-hex) |
| `eth_newPendingTransactionFilter` | — | new filter id (`0x`-hex) |
| `eth_newFilter` | filter object | new filter id (`0x`-hex) |
| `eth_getFilterChanges` | `[id]` | pending hashes / logs since last poll (bounded) |
| `eth_getFilterLogs` | `[id]` | pending logs (bounded) |
| `eth_uninstallFilter` | `[id]` | bool |
| `eth_getLogs` | filter object | matching contract events (bounded) |
| `eth_getStorageAt` | `[address, slot, block]` | storage word as `0x`-hex |
| `eth_sendRawTransaction` | `[signed bytes]` | EVM keccak hash on admission (L1 leg admitted first, then the EVM intent) |

Unknown EVM selectors return `"0x"`; unknown block/tx hashes return `null`
(JSON-RPC success with a null result), never an invented block. Filter ids
are 64-bit random `0x`-hex and expire after `FILTER_TTL_SECS` (300 s); at
most `MAX_ACTIVE_FILTERS` (10 000) live filters with at most
`MAX_PENDING_PER_FILTER` (1 000) pending entries each.

### `stell_faucet`

Parameters: `{"address": "<hex>"}` or the bare string form, plus an optional
`{"amount": <number>}`.

```json
{"method":"stell_faucet","params":{"address":"<64 hex>"}}
→ {"result":{
     "credited_nano":"10000000000",
     "recipient":"<64 hex>",
     "tx_hash":"<64 hex>",
     "shard":1
   }}
```

`credited_nano` is a decimal string, **not** the amount you asked for. The drip
is 10 STELL by default (`STELL_FAUCET_DRIP_STELL` overrides it) and the lifetime
cap per address is 1000 STELL, hardcoded where the `Faucet` is constructed.
`amount` is clamped down to the drip, and
then down to whatever remains of the lifetime cap. Asking for `u64::MAX` gets you
one drip, not an error.

**Which shard the drip lands on.** The drip is always a *same-shard* transfer
(`source_shard == target_shard`) on the shard the RECIPIENT lives on, resolved
by the documented address→shard rule (`ROUTING_RULE`, `route_shard`):
* `-1:<hex>` (or `0:<hex>`) names a **masterchain** account explicitly → the
  drip executes on shard 0. This is the form to fund for the
  drip→consolidate→stake onboarding flow: staking happens on the masterchain.
* a bare 64-hex address is a **workchain** address → the drip executes on the
  workchain shard the routing prefix selects. A bare address NEVER routes to
  the masterchain.
* `N:<hex>` names workchain shard N explicitly.

On a sharded node (`STELL_SHARDS=0,1`) the faucet serves ONLY its own shard's
recipients: a drip for any other shard is refused at admission (see errors
below), never queued. A sharded proposer drops every transaction whose
`source_shard` is not its own shard, so queuing a cross-shard drip would only
leave it `pending` forever while burning the faucet's nonce sequence — the
live failure this rule fixes. Fund a workchain address from the faucet serving
that workchain shard.

**Funding requirement.** The faucet signs from ONE genesis-funded account (the
`STELL_FAUCET_KEY` / `STELL_FAUCET_KEY_FILE` seed, shared byte-for-byte by
every node — it is part of the genesis root). That account is funded on the
masterchain genesis AND on every workchain genesis (`fund_shard_genesis`), so
each shard's faucet draws on its own shard's funding with its own nonce
sequence. A faucet with no genesis funding on its shard admits drips it can
never pay for: keep the key configured on every shard the faucet serves.

Errors:

| code | condition |
| --- | --- |
| `-32601 "faucet is disabled on this node"` | `STELL_FAUCET` is not `1`/`true` on this node — the default |
| `-32602 "missing address"` / `"invalid address: …"` | no address, not 32 bytes, or a malformed `-1:`/`N:` prefix |
| `-32000 "faucet limit reached for this address"` | the 1000 STELL lifetime cap for that address is spent |
| `-32000 "faucet on shard S cannot serve an address on shard T …"` | sharded node, recipient lives on another shard — fund it from that shard's faucet instead. The refusal burns NO nonce and reserves NO cap: the next servable drip keeps its exact nonce |
| `-32000 "faucet transfer rejected: …"` | the transfer could not be admitted to the mempool |

**Three things about this method that are not obvious.**

It does not write balances. It signs an ordinary transfer from the pre-funded
genesis faucet account and puts it in the mempool, so the value movement goes
through consensus. That is deliberate: writing balances directly would be
node-local state, which is exactly the class of non-determinism the state root
is supposed to prevent.

The returned `tx_hash` is a *pending* transaction. It can sit in the mempool
without ever being included. The faucet's `next_nonce` and per-address
`dispensed` totals are **persisted** under the meta key `faucet_state_v1` on
every mutation and loaded at startup (`Faucet::with_persist`, `src/rpc.rs`),
then clamped down (never up) to the on-chain nonce. They are still **not part of
consensus state**, so an unsynced or forked node can still diverge from the
chain; but they no longer reset to 0 on a clean restart as they once did. A
corrupt stored record fails closed to empty so it cannot mint extra credit.

It is covered by `STELL_FAUCET_TOKEN` (fail-closed without it) on BOTH the
RPC method and the gateway route, plus a per-IP budget (20 drips/hour) and the
per-address lifetime cap. The gateway route is `POST /api/faucet/:address`
(GET returns 405); both paths reconcile nonces. The standalone RPC has the
same 30/s/IP limiter as the gateway plus request timeouts.

---

## 5. Staking

Staking happens **inside transactions**, not through `stell_*` writes: the
opcodes are `SysCallStake` (bond / top-up), `SysCallDelegate`,
`SysCallUnbond`, `SysCallBeginUndelegate` / `SysCallUndelegate`
(withdraw matured), `SysCallClaimRewards` /
`SysCallClaimDelegatorRewards`, and `SysCallRotateValidatorKey`
(`src/svm.rs`). The supported builder is `stell-wallet`
(`stake`/`delegate`/`unbond`/`begin-unbond`/`withdraw-unbond`/`claim-rewards`/`rotate-key`;
see `docs/VALIDATOR_ONBOARDING.md` §7–§11 for the exact flow). Two facts
integrators get wrong:

- **Commission is set once, at bond time** — from `--commission-bps N`
  on the wallet `stake` command when given (`SysCallStakeWithCommission`),
  else from governance (`ctx.default_commission_bps`,
  `DEFAULT_COMMISSION_BPS` = 1000 bps = 10 %, `src/staking.rs:232`) — and
  the ledger has **no setter**: it is immutable afterwards, and a top-up
  keeps the registered rate. A passed `SetDefaultCommissionBps`
  governance action prices **new** bonds only.
- **No user-level multisig / threshold accounts** (explicit non-goal,
  `KNOWN_ISSUES.md` §J D-11): one key authorizes one transaction. The only
  "multisig" in the tree is the *bridge relayer* 2/3 quorum
  (`src/bridge.rs`), not user custody. Workaround: split funds across
  accounts, delegate via scoped session grants, rotate with
  `SysCallRotateValidatorKey`.

### `stell_stakeOf`

Parameters: `{"validator": "<hex>"}`.

```json
→ {"result":{"total":"1000000000","self_bond":"1000000000","delegated":"0"}}
```

All decimal strings. `total` = `self_bond + delegated` as the ledger computes
it. An unknown validator returns all three as `"0"`, not an error. Errors:
`-32602 "missing validator"`.

Read from the **state engine's** staking ledger, not from a node-local copy. The
validator set is re-derived from that ledger at every height boundary
(PROTOCOL.md I7), so a value that existed only on one node would make that node
propose a different chain.

### `stell_getValidators`

Parameters: none.

```json
→ {"result":{
     "validators":[{"validator":"<64 hex>","power":"1"}],
     "total_power":"2",
     "quorum":"2",
     "fragile":false,
     "fragile_reason":null
   }}
```

The active set with each member's power, the total, and the quorum threshold.
All three are decimal strings.

- `fragile` — `true` when the quorum needs **100 %** of the set, i.e. when a
  single halt stops the chain. It is the quorum-safety detector (advisory, it
  fails open: a `false` never blocks anything).
- `fragile_reason` — `null` when healthy, otherwise a human-readable string
  naming the condition (for example an `N = 3` equal-stake set, whose quorum is
  3/3).

Read `quorum` before you rely on any assumption about how many nodes a network
needs. It is `floor(2 × total_power / 3) + 1`, which with unit power gives
1 for one validator, **2 for two, 3 for three** (not the two-of-three you would
guess), and 3 for four. A zero-power or empty set returns `18446744073709551615`
(`u64::MAX`) — the set is deliberately unable to reach quorum, so a broken
validator list stalls the chain instead of letting one node finalize everything
unilaterally.

Genesis validators are bonded at 1000 STELL each (power 1) by `fund_genesis`, so
a freshly started network reports exactly the ids in your `validators:` YAML
list. The set is capped at **250 active validators**
(`MAX_ACTIVE_VALIDATORS`, TON-style Elector cap).

---

## 6. Governance

Every governance method reads or writes the **state engine's** `Governance`
object: the RPC `governance` handle is cloned from `shared_gov`, which is
`state_engine.governance_handle()` (`src/main.rs`), the same object that
consensus persists and restores. Governance **is** in the consensus commitment
digest as of `COMMITMENT_VERSION = 3` (commit `9a93ef0`), alongside the
staking ledger, tokens, order books, escrow, PMM and contracts, and the oracle
feed was added in version 4. Two nodes on the same chain therefore agree on
governance state; these methods are a valid way to compare it.

**The governance surface is four reads and three writes.**

| method | kind | auth token |
| --- | --- | --- |
| `stell_listProposals` | read | no |
| `stell_proposal` | read | no |
| `stell_governanceParams` | read | no |
| `stell_submitProposal` | **write** | **yes** (`STELL_RPC_AUTH_TOKEN`) |
| `stell_vote` | **write** | **yes** (`STELL_RPC_AUTH_TOKEN`) |
| `stell_executeProposal` | **write** | **yes** (`STELL_RPC_AUTH_TOKEN`) |

The three writes are gated **only when `STELL_RPC_AUTH_TOKEN` is configured**
on the node — a node with no token configured accepts them unauthenticated, as
it does for every other method. When a token IS configured, the caller must
present it as `params.token`, `params.apiKey` or an HTTP header
(`Authorization: Bearer <t>` / `Authorization: Token <t>` / `X-Api-Key: <t>` /
`X-Stell-Token: <t>`); the comparison is constant-time. A missing or wrong
token is `-32001 "unauthorized: missing or invalid API token"`.

> **Why `stell_executeProposal` is gated.** It applies the action of a PASSED
> proposal, and one of the actions is `SoftwareUpgrade` — the path that ends in
> an `execve` of a new binary. `stell_submitProposal` and `stell_vote` are
> gated; this one originally was not. The gate is on the **caller**, not on the
> proposal: the proposal still needs its quorum (the ledger decides that), and
> "anyone may execute" (no proposer-only rule) is preserved so a lost proposer
> key cannot brick execution — the operator's token is enough.

### `stell_listProposals`

Parameters: none.

```json
{"method":"stell_listProposals","params":{}}
→ {"result":[
    {"id":0,
     "title":"Raise the base fee",
     "action":"SetBlockReward(10000000000)",
     "status":"Open",
     "voting_end":1758800000,
     "turnout":"0.6",
     "yes":"1000000000000000000",
     "no":"0",
     "abstain":"0"}
  ]}
```

- **Read.** No token.
- Every proposal, sorted by id ascending. An empty array when there are none.
- `action` is the `Debug` formatting of the `GovAction` enum — an unstable
  string, do not parse it.
- `status` is the `Debug` formatting of the status enum: `Open`, `Passed`,
  `Rejected`, `Executed` — also unstable, do not parse it.
- `voting_end` is a unix timestamp (proposals open for **3 days**,
  `GOVERNANCE_VOTING_PERIOD_SECS = 3 * 24 * 3600`).
- The vote weights (`yes`, `no`, `abstain`) and `turnout` are decimal strings.

### `stell_proposal`

Parameters: `{"id": <number>}`. Defaults to `0` if absent, rather than erroring.

```json
→ {"result":{
     "id":1,
     "title":"Raise the base fee",
     "action":"SetBlockReward(10000000000)",
     "status":"Open",
     "voting_end":1758800000,
     "yes":"1000000000000000000",
     "no":"0",
     "abstain":"0",
     "turnout":"0.6"
   }}
```

`status` is the `Debug` formatting of the status enum, e.g. `Open`,
`Passed`, `Rejected`, `Executed` — an unstable string, do not parse it. Vote
totals are decimal strings. `turnout` is a `f64` rendered as a JSON number.

Errors: `-32004 "proposal not found"`.

### `stell_governanceParams`

Parameters: none.

```json
→ {"result":{"quorum_bps":6666,"next_id":2,"applied":0}}
```

`quorum_bps` is in basis points (`GOVERNANCE_QUORUM_BPS = 6666`, i.e. 2/3 of
the frozen electorate; the floor is `GOVERNANCE_QUORUM_FLOOR_BPS = 3333` — a
proposal may not lower the quorum below one third, or governance could be
captured irreversibly), `next_id` is the id the next proposal will get,
`applied` counts proposals that have taken effect.

### `stell_submitProposal`

**WRITE. Requires the auth token** (when `STELL_RPC_AUTH_TOKEN` is set).

Parameters: `{"title": <string>, "type": <string>, ...}`, plus
`{"proposer": "<hex>"}` (optional).

```json
{"method":"stell_submitProposal",
 "params":{"title":"Raise the base fee",
           "type":"set_block_reward",
           "value":10000000000,
           "proposer":"<64 hex>",
           "token":"<api token>"}}
→ {"result":{"proposal_id":0,"status":"Open"}}
```

`type` selects the action. **Every `GovAction` variant has exactly one
canonical action string**, and an **unknown `type` is refused** with `-32602`
— it is never silently turned into a `Signal` (a no-op that carries its text).

| `type` | extra parameters | action |
| --- | --- | --- |
| `set_min_validator_bond` | `value` (**required**) | `SetMinValidatorBond` |
| `set_equivocation_slash_bps` | `value` (**required**) | `SetEquivocationSlashBps` |
| `set_default_commission_bps` | `value` (**required**) | `SetDefaultCommissionBps` |
| `set_block_reward` | `value` (**required**) | `SetBlockReward` |
| `set_pmm_redemption_buffer_bps` | `value` (**required**) | `SetPmmRedemptionBufferBps` |
| `set_governance_quorum_bps` | `value` (**required**) | `SetGovernanceQuorumBps` |
| `signal` | `text` (**required**) | `Signal(text)` |
| `register_oracle_publisher` | `publisher` (**required**, 64 hex) | `RegisterOraclePublisher` |
| `unregister_oracle_publisher` | `publisher` (**required**, 64 hex) | `UnregisterOraclePublisher` |
| `reset_oracle_breaker` | — | `ResetOracleBreaker` |
| `set_min_gas_limit` | `value` (**required**) | `SetMinGasLimit` |
| `software_upgrade` (alias `upgrade`, deprecated) | `name`, `height`, `sha256` (all **required**) | `SoftwareUpgrade{name, height, sha256}` |
| `cancel_upgrade` | — | `CancelUpgrade` |

`value` is an unsigned integer (a JSON number or a decimal string). There are
**no defaults**: a governance parameter is never invented by the node, so a
missing `value` is `-32602 "missing parameter 'value'"`.

`stell_proposal` and `stell_listProposals` answer with an extra
`action_type` field — the canonical action string of the proposal (the same
word the proposer sent as `type`).

> **The oracle actions fail closed at execution.** `register_oracle_publisher`,
> `unregister_oracle_publisher` and `reset_oracle_breaker` are ordinary
> proposals and can be proposed and voted on like any other, but the oracle is
> a separate committed domain: `stell_executeProposal` (which calls
> `Governance::execute`, without the oracle) refuses them with
> `-32000 "execute failed: InvalidAction"` and the proposal stays `Passed`.
> They are applied through `Governance::execute_with_oracle`, which writes
> both domains in one call.

Bounds (enforced by `GovAction::validate`, on **both** the propose and the
execute path):

- `title` — at most **256 bytes** (`MAX_PROPOSAL_TITLE_BYTES`).
- `signal` text — at most **1024 bytes** (`MAX_SIGNAL_BYTES`).
- `set_min_validator_bond` — between `MIN_VALIDATOR_BOND` and
  `MAX_VALIDATOR_BOND` (1,000,000 STELL).
- `set_block_reward` — at most `MAX_BLOCK_REWARD_NANO` (10,000 STELL).
- `set_equivocation_slash_bps`, `set_default_commission_bps`,
  `set_pmm_redemption_buffer_bps` — at most 10,000 bps.
- `set_governance_quorum_bps` — between `GOVERNANCE_QUORUM_FLOOR_BPS`
  (3,333) and 10,000 bps.
- `set_min_gas_limit` — `1 ..= MAX_MIN_GAS_LIMIT` (= `10 * GAS_BASIC_TRANSFER`).
- `register_oracle_publisher` / `unregister_oracle_publisher` — the publisher
  key must be non-zero.
- `software_upgrade` — `name` non-empty, at most 64 bytes, and a **safe path
  segment** (no `/`, no `..`); `height` non-zero; `sha256` non-zero. The name
  becomes the candidate path under `data/upgrades/`, so a name that carries a
  separator is refused.
- the proposer must have **10,000 STELL** of stake
  (`PROPOSAL_MIN_STAKE_NANO`); otherwise `-32000 "propose failed: …"`.

Errors: `-32001` (no/invalid token), `-32602 "missing proposal title"` /
`"missing action type …"` / `"unknown governance action type '…' (known: …)"` /
`"missing parameter 'value'"` / `"missing parameter 'text'"` /
`"missing parameter 'publisher'"` / `"missing parameter 'sha256'"` style
parameter errors, `-32000 "propose failed: …"` for a state refusal.

### `stell_vote`

**WRITE. Requires the auth token** (when `STELL_RPC_AUTH_TOKEN` is set).

Parameters: `{"id": <number>, "voter": "<hex>", "choice": "yes"|"no"|"abstain"}`.

```json
{"method":"stell_vote",
 "params":{"id":0,
           "voter":"<64 hex>",
           "choice":"yes",
           "token":"<api token>"}}
→ {"result":{"voted":true,"proposal_id":0,"weight":"1000000000000"}}
```

- `choice` is case-insensitive and accepts `yes`/`y`/`1`, `no`/`n`/`0`;
  anything else is `Abstain`.
- `weight` is the voting weight recorded, as a decimal string. It is the
  voter's own self-bond plus any stake it delegated OUT, counted once.
- The recorded weight is **locked** in the staking ledger
  (`StakingLedger::lock_governance`), so the backing stake cannot unbond or
  undelegate until the proposal finalises.
- The **electorate** (the quorum base) is frozen at propose time, so a
  yes-voter who undelegates cannot shrink the denominator and flip the verdict.
- A voter may vote **once** per proposal: a second vote is
  `-32000 "vote failed: …"`. Voting after the window closed, or on a proposal
  that is not `Open`, is refused the same way.

Errors: `-32001` (no/invalid token), `-32602 "missing proposal id"` /
`"missing or invalid voter address"`, `-32000 "vote failed: …"`.

### `stell_executeProposal`

**WRITE. Requires the auth token** (when `STELL_RPC_AUTH_TOKEN` is set).

Parameters: `{"id": <number>, "executor": "<hex>"}` (`executor` optional,
defaults to the zero address).

```json
{"method":"stell_executeProposal",
 "params":{"id":0,"executor":"<64 hex>","token":"<api token>"}}
→ {"result":{"executed":true,"applied":{ ... }}}
```

- `applied` is the `AppliedParams` set after the action took effect (the
  governed `min_gas_limit`, `block_reward`, `min_validator_bond`,
  `commission_bps`, `pmm_redemption_buffer_bps`, `governance_quorum_bps`,
  `oracle` publisher actions and the `upgrade_plan`).
- The proposal must be **`Passed`** (quorum reached and `yes > no`); an `Open`
  one is refused with `-32000 "execute failed: …"`.
- There is **no timelock**: execution is allowed as soon as the proposal has
  passed.
- Any account may execute (no proposer-only gate), so a lost proposer key
  cannot brick execution.
- **Oracle actions** (`register_oracle_publisher`, `unregister_oracle_publisher`,
  `reset_oracle_breaker`) cannot be applied through this method: the oracle is
  a separate committed domain, so the action fails closed and the proposal stays
  `Passed` (not `Executed`).

Errors: `-32001` (no/invalid token), `-32602 "missing proposal id"`,
`-32000 "execute failed: …"`.

---

## 7. Mempool, market and bridge reads

### `stell_mempoolSize`

Parameters: none.

```json
→ {"result":3}
```

A JSON number. This is the same `Mempool` object the proposer selects from — it
is shared by reference between the RPC layer and the consensus loop, so the
number is truthful rather than a per-layer fiction.

Interpretation:

- **0 and the height not moving**: the chain is stalled, not busy. Check the
  validator set and quorum.
- **Non-zero and the height not moving**: the producer is refusing these
  transactions. The usual causes are a stale nonce or a balance that no longer
  covers `amount + gas_limit`; each round the proposer evicts what is
  unexecutable and logs `[mempool] evicted N unexecutable transaction(s)`.
- **Pinned at the cap (10,000)**: the pool is full. Only a higher-fee, fully
  funded transaction can displace an existing one.

### `stell_epochKey`

Parameters: none.

```json
→ {"result":{
     "epoch": 7,
     "epoch_blocks": 128,
     "public_key": "<hex, 32 bytes>",
     "committee_hash": "<hex, 32 bytes>",
     "transcript_root": "<hex, 32 bytes>",
     "threshold": 3,
     "contributors": [1, 4],
     "committee": [{"validator_id": "<hex>", "enc_pk": "<hex>", "contributor": true}],
     "commitment": "<hex, 32 bytes>",
     "committed_by_chain": "<hex, 32 bytes>",
     "diverged": false,
     "scheme": "stell-epoch-seal-v1 (ristretto255 threshold ECDH + xchacha20poly1305)"}}
```

The **MEV epoch key** a wallet encrypts to. It is PUBLIC: the epoch's key is
derived by the validator committee through a verifiable DKG, and the wallet
encrypts its transaction to it (an ephemeral X25519 Diffie-Hellman plus
XChaCha20-Poly1305). The ciphertext is what the network carries; the
committee unseals it only after the ordering of the round is committed.

`commitment` is the value the BLOCK carries (`Block::epoch_key_commitment`): a
wallet or a light client checks it against the chain, so it does not have to
trust the node it asked. `committed_by_chain` is the commitment this node
saw in a block; `diverged` is `true` when the node's own key differs from it
(a different validator view at the epoch boundary) — such a node stops
releasing decryption partials.

Errors: `-32010 "no epoch key is available yet: the committee's key generation
has not completed"` when the DKG has not finished for the current epoch (the
plain path keeps working).

### `stell_sendSealedTransaction`

Parameters: `{"payload": "<hex of STX1 ‖ bincode(SealedEnvelope)>"}` (the
`data` parameter is accepted as an alias).

```json
→ {"result":{"tx_hash":"<hex>","sealed":true}}
```

Submits a SEALED transaction. The node stores the **ciphertext** (and the
transparent metadata: sender, nonce, gas limit, priority bid, shards) and
gossips the sealed frame; the plaintext never enters the pool, the gossip or
the DHT.

Errors: `-32602 "refusing the sealed transaction: …"` for a malformed frame
(unknown magic, truncated body, invalid ephemeral curve point, empty or
oversized payload, reserved transaction hash) and `-32011 "sealed transaction
refused: …"` when the pool refuses it (a stale epoch, a duplicate, the
per-sender quota, a full pool).

### `stell_mevStats`

Parameters: none.

```json
→ {"result":{"epoch":7,"sealed":12,"plain":40,"sealed_share":0.23,
             "unsealed":31,"unseal_failures":2,"threshold":3,
             "epoch_key":"<hex>","epoch_key_commitment":"<hex>",
             "committed_epoch_key":"<hex>","diverged":false}}
```

The operator's view of the private path: how many pooled transactions took
the sealed path, how many took the plain path, the sealed share, and how many
sealed transactions were unsealed (or dropped because they could not be
unsealed) so far. The same numbers are exported as the Prometheus gauges
`stell_mempool_sealed` / `stell_mempool_plain` and the counters
`stell_mev_unsealed_total` / `stell_mev_unseal_failed_total`.

### `stell_getEpochRoot`

Parameters: `{"epoch": 3}` (or `{"height": 400}`, which selects the epoch
containing that height, or a bare number, read as an epoch).

```json
→ {"result":{"epoch":3,"start_height":384,"end_height":511,
             "mmr_root":"<hex, 32 bytes>","peaks":["<hex>", …],
             "complete":true,"leaves":128,
             "committed_root":"<hex>|null","committed_in_height":512}}
```

The epoch MMR root (V5 Tier-2, `PROTOCOL.md` §6.4): the
Merkle-Mountain-Range root over the epoch's 128 finalized block hashes,
recomputed here from this node's finalized headers. `peaks` are the mountain
peaks, left-to-right. `complete` is `false` while the epoch is still
finalizing (the root then covers only `leaves` hashes and is NOT the epoch
root). `committed_root` is the quorum-signed commitment carried by the first
masterchain block of the NEXT epoch (`Block::mmr_epoch_root`, `null` when
this node does not know that header yet) — a light client checks `mmr_root`
against it (after verifying that header's QC against its own validator set)
and verifies inclusion proofs with `light_client::verify_mmr_inclusion`,
instead of trusting the serving node.

Errors: `-32602 "missing epoch or height"` with no selector; `-32004` when
this node knows none of the epoch's heights (it keeps the most recent 512
finalized headers).

### `stell_baseFee`

Parameters: none.

```json
→ {"result":{"base_fee":"21000"}}
```

The **admission floor**: the minimum declared `gas_limit` this node currently
accepts into its mempool (and the floor its proposer filter skips below). It is
refreshed from `max(env, governed)` at every finalized height, so a wallet
asserts this **before** blasting, not after its transactions bounce.
`base_fee` is a decimal string.

### `stell_mempoolDump`

**Read, but token-gated** (when `STELL_RPC_AUTH_TOKEN` is set).

Parameters: none.

```json
→ {"result":[{"sender":"aabbccddeeff","nonce":3,"hash":"112233445566"}]}
```

A diagnostic dump of the pending transactions: `(sender prefix, nonce, hash
prefix)`. No signatures, no amounts — but pending mempool contents are
non-public and can aid front-running, so this arm is **fail-closed**: with no
`auth_token` configured it refuses with
`-32001 "unauthorized: stell_mempoolDump is disabled when auth_token is not
configured"`, and with a token configured it demands it.

### `stell_submitPriceFeed`, `stell_pmmBuy`, `stell_pmmSell`

**WRITE-shaped, token-gated** (when `STELL_RPC_AUTH_TOKEN` is set).

Parameters: `{"tx": "<hex of bincode(Transaction)>"}`.

```json
{"method":"stell_submitPriceFeed",
 "params":{"tx":"<hex>","token":"<api token>"}}
→ {"result":"<64 hex tx hash>"}
```

All three are the same **thin admission path**: decode and verify the wrapping
transaction, check the payload actually carries the opcode the method name
promises (`SysCallSubmitPriceFeed` / `SysCallPmmBuy` / `SysCallPmmSell`), and
admit it to the mempool. Nothing else.

They deliberately do **not** write state. A price, a swap or an order only
becomes consensus state when a proposer includes the transaction in a block and
every node re-runs the opcode against `block.timestamp`. Writing here would
make the result node-local — exactly the non-determinism the block-time commit
path exists to prevent.

Errors: `-32001` (no/invalid token), `-32602 "missing tx"` / `"bad hex: …"` /
`"transaction too large"` / `"decode: …"` / `"payload does not carry …"`,
`-32000 "invalid transaction signature"` / `"rejected: …"`.

### `stell_pmmState`

Parameters: none.

```json
→ {"result":{
     "price_micro_usd":250000,
     "minted_nano":"1000000000000",
     "reserve_micro":"500000000",
     "redemption_buffer_micro":"50000000",
     "usable_reserve_micro":"450000000",
     "max_redeemable_stell":"450000000",
     "quote_token":"<64 hex>|null",
     "treasury":"<64 hex>",
     "governed_buffer_bps":300
   }}
```

The committed PMM curve. `governed_buffer_bps` is read from **governance**
(where a passed `SetPmmRedemptionBufferBps` actually lands), not from a copy
the PMM might be holding stale.

### `stell_orderBook`

Parameters: none, or `{"pair": <number>}` (default **1** = STELL/USDT).

```json
→ {"result":{
     "pair":1,
     "best_bid_micro_usd":249000,
     "best_ask_micro_usd":251000,
     "bid_levels":3,
     "ask_levels":2,
     "bids":[{"price_micro_usd":249000,"orders":1,"available_nano_stell":1000000000}],
     "asks":[{"price_micro_usd":251000,"orders":2,"available_nano_stell":2000000000}]
   }}
```

The **committed** book (never a freshly constructed local one — a CLI that
prints a book it just made up is reporting a market that does not exist on any
node). At most **20 levels per side**. Errors: `-32602 "missing or invalid
pair id (must be an integer)"`, `-32004 "unknown pair N"`.

The native namespace's `stell_orderBookSnapshot` answers the same book with a
different (Stl57-friendly) shape; see §9.

### `stell_sessionBudget`

Parameters: `{"session": "<64 hex session pubkey>"}` (also the bare string).

```json
→ {"result":{
     "registered":true,"revoked":false,"valid_until":1758800000,
     "scope":3,"max_gas_spend":1000000,"spent":250000,
     "remaining_gas":750000,"master":"<64 hex>","chain_id":5757
   }}
```

How much of a session key's cumulative gas budget is spent. Read from the
**committed** `SessionKeyRegistry`. An unknown key answers with
`registered: false` and all zeros — not an error.

### `stell_bridgeDeposit` (RPC arm)

Parameters: `{"source_tx_hash": "<hex>"}` or the bare string.

```json
→ {"result":{
     "found":true,
     "recipient":"<64 hex>",
     "amount":"1000000000",
     "chain":"Ton",
     "via_quorum":true,
     "deposited_at":1758800000,
     "disputed":false
   }}
```

The **acceptance record** of an inbound Teleport deposit: recipient, amount,
admission path (quorum vs evidence), age, disputed flag. No record (a
pre-dispute deposit) is `{"found": false}` — "unchallengeable", not "missing".

> **The name is the record read.** `stell_bridgeDeposit` answers the RECORD and
> nothing else. The native namespace's PREPARE of the same deposit is a
> **different method**, `stell_bridgeDepositPrepare` (see §9): one JSON-RPC
> name, one meaning, so the two can never shadow each other and the prepare is
> reachable over JSON-RPC.
>
> A call that carries the PREPARE's parameters (`chain`, `recipient`,
> `amount`) to this method is **refused** with `-32602` and a pointer to
> `stell_bridgeDepositPrepare` — never answered with `{"found": false}`,
> which would look like a real (missing) deposit record.

### `stell_bridgeDispute`

Parameters: `{"dispute_id": "<number>"}` or the bare string.

```json
→ {"result":{
     "found":true,
     "dispute_id":0,
     "source_tx_hash":"<64 hex>",
     "challenger":"<64 hex>",
     "recipient":"<64 hex>",
     "amount":"1000000000",
     "bond":"5000000000",
     "deadline":1758803600,
     "resolved":false,
     "confirmed":false
   }}
```

An open or resolved dispute by id, for watcher dashboards (deadline countdown,
outcome). Unknown id → `{"found": false}`. Errors: `-32602 "missing
dispute_id"` / `"bad dispute_id"`.

---

## 8. Smart contracts

### The ABI manifest

A contract may carry a **typed ABI manifest**: a JSON description of every
method it exports (name, typed parameters, typed return, whether it mutates
state) and every event it emits (typed topics and data). The manifest is
stored with the contract and committed to the state trie next to the code hash
(`sha256("STELL_CONTRACT_ABI" || address)`), so the typed interface of a
contract is discoverable from the state root alone.

```json
{
  "methods": [
    {
      "name": "transfer_direct",
      "params": [
        { "name": "from_id", "type": "u64" },
        { "name": "to_id", "type": "u64" },
        { "name": "amount", "type": "u64" }
      ],
      "returns": "u64",
      "mutates_state": true
    }
  ],
  "events": [
    {
      "name": "Transfer",
      "topics": [{ "name": "amount", "type": "u64" }],
      "data": []
    }
  ]
}
```

Supported types: `i64`, `u64`, `i32`, `bool`, `bytes`, `address`, `string`.

### Wire format ("STELL-ABI v1")

Arguments are encoded canonically — **not** hand-packed into one integer
(`from * 100_000_000 + to * 100_000 + amount`):

```text
args_payload := u32_le(arg_count) || arg_0 || arg_1 || ...
arg_i       := u8(type_tag) || value_payload

calldata     := u32_le(selector) || args_payload
selector     := sha256(method_name)[0..4] read as u32_le

value_payload per type (the type tags are frozen, never renumbered):
  I64     0x01 : 8 bytes, big-endian two's complement
  U64     0x02 : 8 bytes, big-endian
  I32     0x03 : 4 bytes, big-endian two's complement
  Bool    0x04 : 1 byte, 0x00 = false, 0x01 = true
  Bytes   0x05 : u32_le(len) || len raw bytes
  Address 0x06 : 32 raw bytes
  String  0x07 : u32_le(len) || len UTF-8 bytes
```

Fixed-width integers are big-endian so the encoding does not depend on the
host architecture; variable-length payloads are length-prefixed so a decoder
can skip a value without knowing its type.

### `stell_deployContract`

**WRITE-shaped (it deploys and submits a transaction).** No token: the
transaction is signed by the supplied `private_key`.

Two request forms are accepted.

**(a) Direct parameters** — `{code, [init_data|salt], [gas_limit], [private_key], [from], [abi]}`

```json
{"method":"stell_deployContract",
 "params":{"code":"<hex of the WASM module>",
           "init_data":"<hex>",
           "gas_limit":50000000,
           "abi":{"methods":[],"events":[]}}}
→ {"result":{
     "contract_address":"<64 hex>",
     "contract_address_stl57":"EQ…",
     "code_hash":"<64 hex>",
     "tx_hash":"<64 hex>"
   }}
```

- `code` — the hex of the WASM module. At most **2 MiB**
  (`MAX_CONTRACT_CODE_SIZE`); a bigger module is refused by the contract
  registry. `0x` prefix optional.
- `init_data` (alias `salt`) — hex; non-hex is taken as raw bytes.
- `gas_limit` — default **`MAX_CONTRACT_FUEL` = 50,000,000**. This is the
  contract-execution ceiling.
- `private_key` — 32-byte hex Ed25519 seed. **When it is omitted a fresh random
  key is generated**, which is why the resulting `from` address is not yours:
  pass `private_key` (or `from`) for a call you intend to make.
- `from` — the sender address. When omitted it is derived from the signing key.
- `abi` — optional: a JSON manifest (object) or a string containing one. When
  present it is attached to the contract and committed with it (under
  `sha256("STELL_CONTRACT_ABI" ‖ address)`).

**(b) A signed raw transaction** — `{"tx": "<hex of bincode(Transaction)>"}`

```json
{"method":"stell_deployContract","params":{"tx":"<hex>"}}
→ {"result":{"contract_address":"<64 hex>","contract_address_stl57":"EQ…",
             "code_hash":"<64 hex>","tx_hash":"<64 hex>"}}
```

The transaction must carry a `SysCallDeployContract` payload; otherwise
`-32602 "transaction does not contain SysCallDeployContract payload"`. The
address is derived **deterministically** (creator + code + init data), so the
same deploy always yields the same address.

Both forms admit the transaction to the mempool and gossip it, and file a
receipt. The receipt's `contract_address` is the deployed contract.

Errors: `-32602` (missing `code`, bad hex, undecodable `tx`, `private_key` not
32 bytes, invalid `abi`), `-32000 "deploy contract failed: …"`.

### `stell_callContract`

**WRITE-shaped (it executes the call and submits a transaction).** No token.

Parameters: `{contract, method, args, [value], [gas_limit], [private_key], [from]}`.

```json
{"method":"stell_callContract",
 "params":{"contract":"<64 hex>",
           "method":"transfer_direct",
           "args":[1,2,1000],
           "value":0,
           "gas_limit":50000000,
           "private_key":"<64 hex>"}}
→ {"result":{
     "tx_hash":"<64 hex>",
     "status":"success",
     "return_value":1000,
     "gas_used":280000,
     "events":[{"contract":"<64 hex>","contract_stl57":"EQ…",
                "topic":"Transfer","value":"1000"}],
     "outcome":{"status":"success","return_value":1000,
                "gas_used":280000,"events":[…],"error":null}
   }}
```

- `contract` (alias `address`) — the contract address. Accepts the bare
  32-byte hex and the TON-style `<shard>:<addr>` form (`-1:` for the
  masterchain).
- `args` (alias `arg`) — a single value **or an array of one value per
  parameter**. A method with three parameters is called with three arguments,
  no packing. The dispatch is by exact arity: an argument is never dropped.
  At most **8** arguments (`MAX_CONTRACT_CALL_ARGS`) — the same bound on the
  call path and on the read-only getter path.
- `value` — nano-STELL to transfer with the call. The sender is debited and the
  contract credited **immediately** on this node; a sender that cannot cover it
  gets `-32000 "insufficient funds to transfer value: …"`.
- `gas_limit` — default **`MAX_CONTRACT_FUEL` = 50,000,000**.
- `private_key` / `from` — as in `stell_deployContract`; without `private_key`
  a fresh random key is generated.
- `status` — `"success"` or a failure string (e.g. `"reverted"`, `"error"`).
- `outcome` — the same result nested, plus `error` (a string when the call
  failed, `null` otherwise). This is the canonical "what happened" object.

When the contract has an ABI manifest, the manifest is authoritative: the
method must be declared, the number of arguments must match exactly and every
argument must have the declared type. A call that does not match is rejected
with `-32602 "ABI validation failed: …"` **before it touches consensus state**.

Errors: `-32602` (missing `contract` / `method`, bad address, bad `args`,
`ABI validation failed`, `ABI encoding failed`), `-32000` (insufficient funds
for `value`, contract execution failure).

### `stell_runGetMethod`

**READ.** No token. Zero state changes, zero gas.

Parameters: `{address, method, args, [fuel], [height]}`.

```json
{"method":"stell_runGetMethod",
 "params":{"address":"<64 hex>","method":"balance_of","args":[7],"fuel":1000000}}
→ {"result":{
     "success":true,
     "return_value":42,
     "return_bytes":"<hex>",
     "return_typed":42,
     "fuel_used":1200,
     "events":[…],
     "error":null,
     "shard":1,
     "local_shard":0,
     "shard_is_local":false
   }}
```

- `address` — the contract address; accepts the bare form and `<shard>:<addr>`.
- `method` — the getter name. With an ABI manifest the method must be declared
  and the arguments validated against it; the answer then carries a typed
  `return_typed` (number / bool / `0x…` hex string) next to the raw
  `return_value`.
- `args` — the getter's arguments; at most **8** (`MAX_CONTRACT_CALL_ARGS`).
  More is refused with `{"success":false,"error":"too many arguments: at most 8"}`.
- `fuel` — the fuel ceiling for the read. It is clamped to
  **`GET_METHOD_SAFETY_FUEL_LIMIT` = 5,000,000** (an unbounded getter is an
  infinite loop); the default is the same ceiling. A read that exceeds it
  comes back as `{"success":false,"error":"…","fuel_used":…}`.
- `height` — an optional pin. A height **above** this node's finalized height
  is refused with `{"success":false,"error":"pinned block height N exceeds
  current finalized height M","fuel_used":0}`. A height at or below the tip is
  served from the current state (this node keeps no historical state).

The response also carries `shard`, `local_shard` and `shard_is_local`: the
shard the **address→shard rule** resolves the address to, the shard this node
runs, and whether they are the same. The rule is the one published in
[`docs/SHARDING.md`](SHARDING.md) and in `stell_getShards`' `sharding`
section — one rule, one source of truth. A node that does not hold the
shard answers from its own state and says so (`shard_is_local: false`); it
never fabricates another shard's state.

**Failures are answers, not RPC errors.** A missing address, a missing method,
a bad height or an ABI mismatch all come back as
`{"success":false,"error":"…","fuel_used":0}` with a `200 OK` envelope. Only
malformed JSON gets an RPC-level error.

### `stell_getEvents`

**READ.** No token.

Two query forms.

**(a) By transaction** — `{"tx_hash": "<hex>"}` (aliases `txHash`, `hash`; the
bare string form is accepted too):

```json
{"method":"stell_getEvents","params":{"tx_hash":"<64 hex>"}}
→ {"result":[
    {"contract":"<64 hex>","contract_stl57":"EQ…",
     "topic":"Transfer","value":"1000"}
  ]}
```

An unknown transaction is an **empty array**, not an error.

**(b) By contract** — `{"contract": "<hex|address>", [from_block], [to_block], [limit]}`:

```json
{"method":"stell_getEvents",
 "params":{"contract":"<64 hex>","from_block":100,"to_block":200,"limit":100}}
→ {"result":[{…},{…}]}
```

- `from_block` / `to_block` (also `fromBlock` / `toBlock`) — an inclusive height
  range; a hex string (`"0x2a"`) or a decimal string is accepted. Defaults:
  `from_block = 0`, `to_block = u64::MAX`.
- `limit` — the **answer cap**: default and maximum **`MAX_EVENTS_RETURNED` =
  1000**. The answer is always an **array** (the shape never changes), it is
  simply truncated at the cap. The cap exists because the receipt index holds
  up to 50,000 receipts and every receipt can carry up to 256 events
  (`MAX_CONTRACT_EVENTS`), so an unfiltered contract query could otherwise
  answer with millions of events on an unauthenticated read.

Errors: `-32602 "missing 'tx_hash' or 'contract' parameter"`,
`-32602 "invalid contract parameter: must be a string"`,
`-32602 "invalid contract address: …"`.

### `stell_estimateFee`

**READ.** No token, but with its **own, much tighter rate limit** — see the
bounds below.

Parameters: `{from, to, amount, [payload], [source_shard], [target_shard], [max_gas]}`
(or `{"tx": <raw hex>}`).

```json
{"method":"stell_estimateFee",
 "params":{"from":"<64 hex>","to":"<64 hex>","amount":1000}}
→ {"result":{
     "gas_limit":1000,
     "estimated_fee":1000,
     "base_fee":1000,
     "source_shard":0,
     "target_shard":1,
     "is_cross_shard":true,
     "gas_budget":5000000,
     "gas_ceiling":5000000,
     "status":"ok"
   }}
```

- `from` (alias `sender`) and `to` (aliases `recipient` / `contract` /
  `address`) — 32-byte hex or `<shard>:<addr>`.
- `amount` (alias `value`) — nano-STELL.
- `payload` — the payload to simulate (an array of opcode objects).
- `source_shard` — defaults to the shard named in the `from` address form, else
  this node's own shard.
- `target_shard` — resolved by the **same address→shard rule**
  (`docs/SHARDING.md`): an explicit `target_shard` parameter wins, then a shard
  named in the address form (`-1:` / `N:`), and otherwise the routing rule over
  this node's topology. `is_cross_shard` says whether the two shards differ.
- `base_fee` — `max(mempool admission floor, consensus floor,
  GAS_BASIC_TRANSFER)`.
- `estimated_fee` — `max(gas consumed, base_fee) + surcharge`. `gas_limit` is
  the same number.
- `max_gas` — **optional**: the gas budget the simulation runs with. It may
  only **lower** the budget (see the bounds below); the ceiling itself is
  fixed and cannot be raised.
- `gas_budget` / `gas_ceiling` — the budget the simulation actually ran with
  and the fixed ceiling it can never exceed. They are in the answer so a
  caller can see the bound it is working under instead of guessing it.

**The gas ceiling is fixed; the budget is honest.**

The estimate answers "how much gas does this call NEED", so it must simulate
with enough gas to hold the answer:

- the caller's **declared** limit (the transaction's own `gas_limit`) is
  **not** the simulation budget — simulating with it would answer "out of
  gas" instead of the requirement, so it is ignored;
- the simulation runs with the **full ceiling** (`gas_budget` = 5,000,000)
  unless the caller asks for less with `max_gas`;
- a `max_gas` **above** the ceiling is **refused** (`-32602`), never clamped
  silently: the estimate is an unauthenticated read and its cost per request
  has to stay bounded no matter what the caller asks for;
- a `max_gas` **below** `GAS_BASIC_TRANSFER` (280,000) is refused too — it
  cannot hold even a basic transfer.

**Bounds (this is the most expensive read on the node).**

| bound | value | where |
| --- | --- | --- |
| per-IP rate limit | **5 req/s** (`ESTIMATE_FEE_RATE_LIMIT_DEFAULT`), override with `STELL_ESTIMATE_FEE_RATE_LIMIT` | `rpc.rs` |
| simulation gas ceiling | **5,000,000** (`ESTIMATE_FEE_GAS_CEILING`) — FIXED: the simulation's gas limit is never above it, so a pathological payload can never burn the full 50,000,000 contract ceiling on an unauthenticated read. A caller may LOWER it with `max_gas` (≥ `ESTIMATE_FEE_MIN_GAS` = 280,000) | `rpc.rs` |
| request body | 1 MiB (`MAX_RPC_BODY`) | `rpc.rs` |

The estimate clones the **whole** engine state and runs a full SVM execution on
the clone, so it is orders of magnitude more expensive than any other read. It
is deliberately still **unauthenticated** (a wallet must be able to estimate its
fee before it holds a token), which is exactly why it carries a separate,
far tighter budget: the generic per-IP budget is 300/s on the standalone RPC.
Exceeding the estimate budget is
`-32000 "estimate-fee budget exhausted for this IP (the simulation is expensive;
retry shortly)"`.

A simulation that runs out of gas is `-32000 "simulation out of gas"`; a
reverted simulation is `-32000 "simulation reverted: …"`.

> **A code oddity worth knowing.** The clamp is written
> `gas_limit = gas_limit.max(10_000_000).min(ESTIMATE_FEE_GAS_CEILING)`, so the
> `max` is dead: the effective simulation ceiling is **always** exactly
> 5,000,000, whatever the request declared. That is the intended bound, so the
> answers are correct — but a caller cannot raise the ceiling by declaring a
> bigger `gas_limit`, and the expression reads as if it could.

### `stell_getContractAbi`

**READ.** No token.

Parameters: `{"contract": "<hex>"}` (alias `address`).

```json
{"method":"stell_getContractAbi","params":{"contract":"<64 hex>"}}
→ {"result":{
     "contract":"<64 hex>",
     "contract_stl57":"EQ…",
     "abi":{"methods":[…],"events":[…]},
     "abi_json":"{\"methods\":[…],\"events\":[…]}"
   }}
```

- `abi` — the parsed manifest, or `null` when the contract has none (in which
  case `abi_json` is absent).
- `abi_json` — the manifest as the **raw string** the node committed, so a
  client can byte-compare it against what it expects.
- The manifest is committed to the state trie next to the code hash
  (`sha256("STELL_CONTRACT_ABI" ‖ address)`), so the typed interface of a
  contract is discoverable from the state root alone.

Errors: `-32602 "missing 'contract' parameter"`, `-32602 "invalid contract
address: …"`.

### `stell_getContractReceipt`

**READ.** No token.

Parameters: `{"hash": "<hex>"}` or the bare string form.

```json
{"method":"stell_getContractReceipt","params":"<64 hex>"}
→ {"result":{
     "status":"success",
     "return_value":1000,
     "gas_used":280000,
     "events":[{…}],
     "tx_hash":"<64 hex>"
   }}
```

The **contract-shaped** receipt: the outcome of a contract call, without the
block/height/index fields `stell_getTransactionReceipt` carries. An unknown
hash answers `{"status":"pending"}` or `{"status":"unknown"}` exactly like
`stell_getTransactionReceipt` does.

### `stell_verifyContractSource`

**READ.** No token. Strictly read-only: it never mutates state (in particular
it never sets `source_hash` — that is the signed
`stell_registerContractSource` action below).

Recompiles the claimed `.wat` source with the deploy-time pipeline and
compares the rebuilt bytecode hash to the on-chain `code_hash`
(Sourcify-style source verification, audit P2-15).

```json
{"method":"stell_verifyContractSource","params":{
  "contract":"<64 hex>",
  "source":"(module …)",
  "compiler":"wat2wasm-1.0",
  "compiler_flags":""
}}
→ {"result":{
     "contract":"<64 hex>",
     "contract_stl57":"EQ…",
     "verified":true,
     "onchain_code_hash":"<64 hex>",
     "rebuilt_code_hash":"<64 hex>",
     "source_hash":"<64 hex>",
     "compiler":"wat2wasm-1.0",
     "compiler_flags":"",
     "reason":"ok",
     "registered":false,
     "registered_source_hash":""
   }}
```

- `source` — the canonical `.wat` text inline; `source_hex` — hex of the
  same UTF-8 text. One of `source` / `source_hex` / `source_hash` is required.
- `compiler` (default `wat2wasm-1.0`) must name the pipeline this node
  reproduces (`wat-1.0`, `wat2wasm-1.0`, `wat`, `wat2wasm`, `wast-1.0`);
  anything else is REFUSED (`verified: false`), never guessed.
- `compiler_flags` (alias `flags`, default `""`) must be reproducible
  (`""`, `default`, `canonical`, `--canonical`); anything else is REFUSED.
- `source_hash` alone (no source text) answers whether the claimed
  fingerprint equals the registered one — no rebuild is performed
  (`rebuilt_code_hash: null`).
- `verified: false` carries a machine-readable `reason` (`"rebuilt bytecode
  hash does not match…"`, `"unsupported compiler …"`, …). A tampered source,
  an unparseable source and a wrong-compiler claim are all refusals, not errors.
- `source_hash = BLAKE3(source_text)` — the deterministic build fingerprint.

Errors: `-32602 "missing 'contract' parameter"`, `-32602 "invalid contract
address: …"`, `-32602 "contract not found"`, `-32602` on malformed/oversize
source (> 1 MiB).

### `stell_getContractSource`

**READ.** No token. Returns the registered source fingerprint of a contract
(`source_hash` empty + `verified: false` = unverified). The node stores only
the fingerprint, never the text; the verified text lives in the indexer
(`GET /api/v2/contract/:address/source`).

```json
{"method":"stell_getContractSource","params":{"contract":"<64 hex>"}}
→ {"result":{
     "contract":"<64 hex>",
     "contract_stl57":"EQ…",
     "code_hash":"<64 hex>",
     "source_hash":"<64 hex>",
     "verified":true
   }}
```

### `stell_registerContractSource`

**Signed write, no token.** The ONLY state-changing half of source
verification: pins `source_hash` for a contract (committed to the state trie
next to the code hash as `sha256("STELL_CONTRACT_SOURCE" ‖ address)` and
folded into the state digest when present; absent = unverified and
contributes nothing, so legacy roots are unchanged).

Authorization is the contract creator's ed25519 signature over
`b"STELL_REGISTER_SOURCE" ‖ contract ‖ source_hash` — self-authenticating
like `stell_sendRawTransaction` (anyone may submit; only the creator's
signature verifies). Call `stell_verifyContractSource` first and register the
`source_hash` it returns.

```json
{"method":"stell_registerContractSource","params":{
  "contract":"<64 hex>",
  "source_hash":"<64 hex>",
  "signature":"<128 hex>"
}}
→ {"result":{"contract":"<64 hex>","contract_stl57":"EQ…",
             "source_hash":"<64 hex>","registered":true,"verified":true}}
```

Errors: `-32602` on missing/invalid params, unknown contract, or a signature
that does not verify against the contract creator.

**Trust model (what "verified" actually proves).** `verified: true` proves
that the on-chain bytes are byte-identical to what this node's `wat` build
produces from the submitted text with the claimed flags, and that
`source_hash` is the BLAKE3 of exactly that text. It does NOT prove the
source is safe (a verified backdoor is still a backdoor), that it matches any
other compiler version, or anything about past behaviour. Like
Sourcify/NEAR/MultiversX verification, this is a transparency claim, not a
safety certificate.

### Code generation

A JSON manifest is the source of typed client stubs:

```bash
cargo run --bin abi_codegen -- contracts/sts20_token_abi.json --lang both --out-dir target/abi
```

This writes `sts20_token_abi_client.rs` (typed Rust client: one method per
contract method, event decoders) and `sts20_token_abi_client.ts` (the same in
TypeScript, dependency free, implementing the very same wire format).

---

## 9. The native interface namespace

**ONE namespace, ONE shape per method**: a wallet integrates the native
capabilities of Stellereum once and never again. Every method below is a thin,
**fail-closed wrapper over the state engine that already owns the state** — no
new state, no new consensus rules (`src/native_api.rs`).

- **Read methods** answer from committed state. They never invent a value and
  never cache one.
- **Write methods do NOT write.** They answer with the **exact transaction the
  wallet has to sign** — the `OpCode`, its arguments and its gas — after
  checking, against committed state, the preconditions the execution path
  would check anyway. The wallet signs that payload and submits it through
  `stell_sendRawTransaction`; the state moves when (and only when) the
  transaction lands in a block. That is why a write method here cannot fork
  the chain: it produces bytes, not state.

Every refusal is an error, never a guess:

| code | meaning |
| --- | --- |
| `-32602` | a parameter is missing, malformed or out of range |
| `-32004` | the named token / validator / pair / session key / asset does not exist |
| `-32003` | committed state refuses the operation (insufficient balance, paused token, thin bond, replayed bridge deposit, revoked session key, …) |

`stell_nativeApi` returns the manifest of the namespace (methods, kinds,
parameter names) so a client can discover it with a single call.

### Method list

The namespace has **35 methods** in seven domains plus discovery. **No method in
this namespace is token-gated**: a read answers from committed state, and a
"prepare" method answers with bytes to sign — neither touches the chain.

#### Token (NEP-141-like)

| method | kind | params | result |
| --- | --- | --- | --- |
| `stell_tokenTransfer` | prepare | `{token, from, to, amount}` | the transfer to sign (NEP-141 `ft_transfer`); also carries `token`, `from`, `to`, `amount`, `sender_balance`, `decimals`, `symbol` |
| `stell_tokenBalanceOf` | read | `{token, account}` | `{token, token_stl57, account, account_stl57, balance, decimals, symbol, name, total_supply}` |
| `stell_tokenMetadata` | read | `{token}` | `{token, token_stl57, name, symbol, decimals, total_supply, max_supply, minter, paused, description}` |
| `stell_tokenAllowance` | read | `{token, owner, spender}` | `{token, owner, spender, allowance}` |
| `stell_tokenMint` | prepare | `{token, to, amount, [from]}` | the mint to sign (minter authority only); also `minter`, `to`, `amount`, `total_supply`, `max_supply`, `decimals`, `symbol` |
| `stell_tokenBurn` | prepare | `{token, from, amount, [signer]}` | the burn to sign (self-burn by default, minter admin-burn via `signer`); also `from`, `amount`, `balance_before`, `total_supply`, `minter` |
| `stell_tokenApprove` | prepare | `{token, owner, spender, amount}` | the allowance grant to sign; also `owner`, `spender`, `amount`, `previous_allowance` |
| `stell_tokenTransferFrom` | prepare | `{token, from, to, amount, spender}` | the delegated transfer to sign; also `from`, `to`, `spender`, `amount`, `allowance_before`, `sender_balance` |
| `stell_tokenCreate` | prepare | `{creator, name, symbol, decimals, [initial_supply], [max_supply]}` | the creation to sign (the signer becomes the minter); also `creator`, `name`, `symbol`, `decimals`, `initial_supply`, `max_supply`, `note` |

`from` may also be spelled `owner` (NEP-141 vocabulary). A transfer to the
zero address, to self, of amount `0`, of a paused token, or one the sender
cannot cover is `-32003`. The same zero / self / paused / insufficient-balance
guards apply to `stell_tokenBurn` and `stell_tokenTransferFrom`; a
`stell_tokenTransferFrom` additionally needs the allowance to cover the amount
(`-32003` otherwise).
`stell_tokenMint` pins the signer to the ledger minter: an explicit
`from`/`minter` that is not the minter is `-32003`, as are a renounced minter,
a paused token, a zero recipient, amount `0`, and a mint past `max_supply`.
`stell_tokenBurn` defaults to a self-burn (`signer` omitted means the signer
is `from`); naming `signer` (aliases `caller`/`minter`) requests a minter
admin-burn of another account's balance, which the ledger allows
(`TokenActor::burn`: caller == `from` OR caller is the minter). A `signer`
that is neither `from` nor the minter is `-32003`, as is a zero `signer`.
`stell_tokenApprove` is NOT gated on `paused` (allowance bookkeeping, not value
movement — the same rule the ledger pins) and amount `0` revokes.
`stell_tokenCreate` mirrors the ledger's metadata validation (empty or
oversize `name`/`symbol`, `decimals` above 18 are `-32602`; an
`initial_supply` above `max_supply` is `-32003`). The token id commits the
registry nonce and is not predictable: resolve it with `stell_tokenResolve`
(`creator`, `name`, `symbol`) after inclusion. `creator` may also be spelled
`from`, and mint's `from` may also be spelled `minter`.

#### Staking (NEP-171-like)

| method | kind | params | result |
| --- | --- | --- | --- |
| `stell_stakeBond` | prepare | `{validator, amount}` | the self-bond (or top-up) to sign; also `validator`, `amount`, `min_bond`, `top_up` |
| `stell_stakeUnbond` | prepare | `{validator, amount}` | the unbonding to sign; also `cooldown_secs` |
| `stell_stakeWithdraw` | prepare | `{validator}` | the matured self-bond withdrawal to sign; also `withdrawable` |
| `stell_delegate` | prepare | `{validator, amount, [delegator]}` | the delegation to sign; also `min_delegation` |
| `stell_undelegate` | prepare | `{validator, amount, [delegator]}` | the undelegation to sign; also `cooldown_secs` |
| `stell_claimRewards` | prepare | `{validator, [role], [delegator]}` | the rewards claim to sign (`role` = `validator` \| `delegator`); also `claimable` |

The `delegator` arm of `stell_claimRewards` **requires** `delegator`; the
`validator` arm does not. A bond below the minimum (`MIN_VALIDATOR_BOND` plus
the `STELL_MIN_BOND_BUFFER`), a delegation to a non-validator, or a withdrawal
before the unbonding cooldown has elapsed are all `-32003`.

#### Bridge (Teleport)

| method | kind | params | result |
| --- | --- | --- | --- |
| `stell_bridgeDepositPrepare` | prepare | `{chain, source_tx_hash, recipient, amount}` | the deposit claim to sign; also `chain`, `source_tx_hash`, `recipient`, `amount`, `asset` |
| `stell_bridgeWithdraw` | prepare | `{chain, target_address, amount, [sender]}` | the withdrawal request to sign; also `chain`, `target_address`, `amount`, `asset`, `escrow_balance` |
| `stell_bridgeStatus` | read | `{source_tx_hash}` or `{request_id}` | `{found, kind, …}` — the deposit / withdrawal record |
| `stell_bridgeAttestStatus` | read | `{source_tx_hash}` | `{found, attestations, required, remaining, disputed, status, dispute}` — the committed attestation state of a deposit claim |
| `stell_bridgeReleaseEstimate` | read | `{request_id}` | `{found, unlock_at, refund_at, quorum_met, escrow_funded, missing, …}` — release readiness of a parked withdrawal |
| `stell_bridgeDeposits` | read | `{address, [limit]}` | `{address, deposits: [{source_tx_hash, amount, status, dispute, …}], count, total, limit}` — paginated deposit history |

`chain` is `ton` \| `arbitrum` \| `ethereum` \| `solana` (case-insensitive).
A source transaction that was already credited is refused (`-32003`) — that is
the replay guard, and it is the reason a deposit cannot be claimed twice.

> **Why the prepare is not called `stell_bridgeDeposit`.** The node's JSON-RPC
> surface already answers `stell_bridgeDeposit` with the deposit **record** (a
> read, §7), and a JSON-RPC method name may have only ONE meaning — the two
> arms used to collide, and the read (matched first) shadowed the prepare, so
> the prepare was unreachable over JSON-RPC. The prepare therefore carries an
> explicit `Prepare` suffix. The record read is NOT part of this namespace:
> `stell_nativeApi` lists `stell_bridgeDepositPrepare` (kind `prepare`) and
> never `stell_bridgeDeposit`.

#### Full user flow: deposit → attest → release / refund

All six bridge methods are reads or prepare-only: the wallet polls state with
the reads, signs the prepares, and submits via `stell_sendRawTransaction`.
Quorum attestations are VALIDATOR-side: a deposit claim must carry relayer
signatures over `deposit_signing_message` reaching the 2/3 DISTINCT-signer
threshold (`quorum_threshold`, the `(2n+2)/3` bridge-domain curve) counted
against the committed staking set, inside the SAME transaction as the
`Deposit` intent. There is no wallet-callable "attest" write — the truth gate
(W7.1, `src/bridge.rs:738` / `:1517`) is never bypassed, only surfaced.

1. **Deposit.** `stell_bridgeDepositPrepare {chain, source_tx_hash, recipient,
   amount}` → sign → submit. Inclusion mints to `recipient` exactly once (the
   replay set `processed_source_txs` refuses a second claim with `-32003` —
   the double-claim pin).
2. **Track attestation.** `stell_bridgeAttestStatus {source_tx_hash}` reads the
   COMMITTED outcome (the engine stores no partial per-deposit attestation
   count — attestations ride in-payload and are counted at settlement, so a
   pre-commit claim is `found: false`, never an invented count):
   - settled via quorum → `{attestations: required, remaining: 0,
     path: "quorum"}` (admitted BECAUSE the threshold was met);
   - settled via adapter evidence → `{attestations: 0, remaining: 0,
     path: "evidence"}` (math, not testimony — unchallengeable);
   - `disputed: true` + `status: "challenged"` while a dispute is open, with
     `dispute: {dispute_id, deadline, remaining_secs, bond}`; the countdown
     exists ONLY while the dispute is open and is `null` after resolution.
3. **Withdraw.** `stell_bridgeWithdraw {chain, target_address, amount,
   [sender]}` → sign → submit. The coins park in `BRIDGE_ESCROW` and the
   request enters the committed queue.
4. **Release.** `stell_bridgeReleaseEstimate {request_id}` surfaces
   `{unlock_at, refund_at, quorum_met, escrow_funded, missing}`:
   `missing: []` means a `Release` settles; `"timelock"` means `unlock_at` is
   still in the future (estimate vs the wall clock — settlement enforces it
   against the block timestamp); `"already-executed"` / `"escrow-shortfall"` /
   `"no-validator-set"` flag the other unmet conditions. Finalization itself
   is the validator-side `Release` intent at `block.timestamp >= unlock_at`.
5. **Refund (only after `unlock_at + REFUND_GRACE_SECS`, sender-only,
   unexecuted-only).** The request is DELETED (replay-safe by absence). Until
   the on-chain release receipt lands, the relayer MUST re-check request
   existence/non-execution before every foreign payout (audit B3/F-G race).
6. **History.** `stell_bridgeDeposits {address, [limit]}` (default 100, max
   1000) lists that recipient's deposits oldest-first with per-deposit
   `status` (`confirmed` | `challenged` | `revoked`), the open-dispute
   countdown where one exists, and `challengeable_until` for undisputed
   quorum-path deposits still inside the challenge age.

#### Windows and caps (grepped from `src/bridge.rs`)

| rule | value | source |
| --- | --- | --- |
| Large-withdrawal timelock | `unlock_at = now + 3600` (1 h) at or above 50,000 STELL | `:34–35` |
| Hourly withdrawal rate | 500,000 STELL / rolling hour (block clock, saturating) | `:36` |
| Hourly deposit mint rate | 500,000 STELL / rolling hour, both admission paths | `:42` |
| Cumulative mint cap | 100,000,000 STELL (revoke unwinds the burned amount only) | `:47` |
| Refund grace | `refund_at = unlock_at + 24 h`, sender-only, unexecuted-only | `:49` |
| Dispute window | 1 h past the challenge to confirm; evidence-unavailable resolves DEFER (bounded) then refuse — never pay on missing evidence | `:108`, W7.1 `:1517` |
| Challenge age | deposits older than 24 h cannot be challenged | `:134` |
| Challenge bond / finder reward | `max(1 STELL, 1% of amount)` / `10% of amount` out of the clawed-back deposit (never minted) | `:62–64`, `:144` |
| Fraud proof (the ONLY one) | quorum retraction over `deposit_failure_signing_message` | `:738` |
| TON finality | 12 masterchain confirmations | `:146` |

#### Order book (CLOB)

| method | kind | params | result |
| --- | --- | --- | --- |
| `stell_orderBookPlace` | prepare | `{pair, side, price, amount, [trader]}` | the order to sign; also `pair`, `side`, `price`, `amount` |
| `stell_orderBookCancel` | prepare | `{order_id, [pair], [trader]}` | the cancellation to sign; also `pair`, `trader`, `side`, `price`, `amount`, `filled` |
| `stell_placeOrder` | prepare | `{pair, side, price, amount, [order_type], [trader]}` | the order to sign (one-call spelling); also `pair`, `side`, `price`, `amount`, `order_type` |
| `stell_cancelOrder` | prepare | `{order_id, [pair], [trader]}` | the cancellation to sign (one-call spelling); also `pair`, `trader`, `side`, `price`, `amount`, `filled` |
| `stell_orderBookSnapshot` | read | `{pair}` | `{pair, version, seq, best_bid, best_ask, bid_levels, ask_levels, bids, asks, next_order_id}` |

`pair` is `1` (`PAIR_STELL_USDT`), `2` (`PAIR_STELL_TON`) or `3`
(`PAIR_STELL_GRAM`). The legacy `stell_orderBookPlace` defaults an omitted
`pair` to **1**; the one-call `stell_placeOrder` REQUIRES an explicit `pair`
(fail-closed against quoting the wrong book). An unknown pair is `-32004`.
`side` is `buy`/`bid` or `sell`/`ask` (anything else is `-32602`). `price`
and `amount` are unsigned integers in micro-USD and nano-STELL; zero is
`-32003`. `order_type` defaults to `limit` — the only semantics
`SysCallPlaceOrder` encodes, so `market` is refused (`-32003`), never
silently downgraded. Only the trader that placed an order may cancel it
(a named non-owner is `-32003`).

Both prepare spellings answer with the same envelope (`action`,
`gas_limit`, `signer`, `transaction: {op, args}`, `submit_with:
stell_sendRawTransaction`) and NEITHER mutates state: sign `transaction`
(`SysCallPlaceOrder {pair_id, is_buy, price, amount}` /
`SysCallCancelOrder {order_id}`) and submit it — the book moves when (and
only when) the transaction lands in a block.

Escrow semantics (what the block will lock for the signed order): a resting
SELL locks its base STELL (`amount` nano-STELL debited into escrow); a
resting BUY locks its quote in native nano-STELL
(`price * amount / 1_000_000`, the `SysCallPlaceOrder` convention — NOT the
wUSDT convention of the internal `place_order_settled` entry point). When a
`trader` is named, the prepare checks the COMMITTED native balance covers
that lock and refuses with `-32003` otherwise; without a `trader` there is
no signer to check against. The prepare also runs the oracle admission gate
(breaker latch, USDT peg, deviation from the committed price) and refuses
(`-32003`) what execution would revert. A cancel refunds whatever the
escrow record holds, in the asset it was locked in, to the order's owner.

Snapshot versioning (stale-read detection for poll-based quoters):
`version` (aliased as `seq`) is the book's monotonic mutation sequence —
bumped on every accepted placement AND every successful cancellation.
`next_order_id` moves on placement ONLY, so cancel-only activity is
invisible under it: compare `version`, not `next_order_id`. Poll cadence
guidance: block tempo is ~0.4–0.8 s, so polling `stell_orderBookSnapshot`
once per second (or once per head) and re-rendering levels only when
`version` moved is sufficient; there is no streaming orderbook feed, so a
quoter that needs sub-second reaction should poll faster and treat a
`version` jump of more than 1 per interval as contention (re-quote before
sending).

#### Session keys

| method | kind | params | result |
| --- | --- | --- | --- |
| `stell_sessionKeyRegister` | prepare | `{session_pubkey, master, valid_until, max_gas_spend, scope, [max_value_per_tx]}` | the grant to sign, with the exact `grant_message` bytes |
| `stell_sessionKeyRevoke` | prepare | `{session_pubkey, [master]}` | the revocation to sign |
| `stell_sessionKeys` | read | `{[master]}` | `{session_keys: [...], count}` — the committed registry |

`stell_sessionKeyRegister` also returns `grant_message` (`0x…`) and
`grant_message_hex`: the **exact bytes the master must sign**, plus
`chain_id`. Put the signature in `transaction.args.grant.master_signature`
before submitting. A revocation is **terminal**; a session key already
registered to another master is refused.

#### Oracle

| method | kind | params | result |
| --- | --- | --- | --- |
| `stell_oraclePrice` | read | `{asset}` | `{asset, price_micro_usd, timestamp, publisher, breaker_tripped}` |
| `stell_oracleFeeds` | read | `{[asset]}` | `{feeds: [...], count, publishers, breaker_tripped}` |

`price_micro_usd` is a decimal string (micro-USD). `breaker_tripped` is the
latched circuit breaker: a peg/deviation violation latches it, and only a
**passed governance vote** can clear it.

#### Shielded path

| method | kind | params | result |
| --- | --- | --- | --- |
| `stell_shieldedTransfer` | prepare | `{to, amount, [fee], [sender]}` | the shielded transfer to sign (shield entry + `SysCallConfidentialTransfer2`); also `to`, `amount`, `confidential_fee`, `gas_breakdown`, `openings`, `viewing_payload`, `custody_warning` |
| `stell_shieldedBalance` | read | `{viewing_key, [payloads]}` | `{view_pub, coins, coin_count, undecryptable, spendable_sum, chain}` — spendable shielded balance scanned with a viewing key |
| `stell_unshield` | prepare | `{to, amount, inputs, [sender]}` | the shielded exit to sign (pays the signer); also `to`, `amount`, `inputs` |

Transparent stays the base layer: these are the first-class entry/exit arms
over the existing confidential opcodes (`src/native_api.rs`, `src/crypto_privacy.rs`).
Both writes are prepare-only — the wallet signs the returned transaction and
submits it via `stell_sendRawTransaction`. `to` accepts a plain address
(hex or Stl57) or a stealth object `{view_pub, spend_pub}`. Amounts are
decimal strings; blindings in `openings` are spend secrets (store like
private keys). `stell_shieldedBalance` never echoes the viewing key (only the
public `view_pub` is returned); payloads that fail to decrypt are counted in
`undecryptable`, never as zero-valued coins.

#### Discovery

| method | kind | params | result |
| --- | --- | --- | --- |
| `stell_nativeApi` | read | — | the manifest of this namespace |

The manifest is
`{version, namespace, methods: [{name, kind, summary, params, required}], method_count, conventions}`.
`version` is the **native interface contract version** (`NATIVE_API_VERSION`,
currently `"1.0.0"`); it is bumped only when an existing method's *answer
shape* changes — adding a method does not bump it.

### The prepared-transaction shape

Every prepare method answers with the same envelope, so a wallet parses ONE
thing:

```json
{
  "action": "token_transfer",
  "gas_limit": 280000,
  "signer": { "address": "…", "stl57": "EQ…" },
  "transaction": {
    "op": "SysCallTokenTransfer",
    "args": { "token_id": "…", "to": "…", "amount": 1000 }
  },
  "submit_with": "stell_sendRawTransaction"
}
```

`transaction.op` is the `OpCode` variant and `transaction.args` are its
arguments; `signer` is the account whose key must sign. Amounts are decimal
strings (nano-STELL for STELL, the token's base units otherwise).
`submit_with` names the method that submits the signed payload.

### Example

```json
→ {"jsonrpc":"2.0","id":1,"method":"stell_tokenBalanceOf",
   "params":{"token":"aa…","account":"bb…"}}
← {"jsonrpc":"2.0","id":1,"result":{"token":"aa…","account":"bb…",
   "balance":"1000000","decimals":6,"symbol":"wUSDT","name":"Tether USD",
   "total_supply":"1000000"}}
```

An unknown token is `-32004`, never a zero balance: a wallet that reads "0"
for a mistyped token id would show an empty balance instead of a failure.

---

## 10. Quick call reference

| method | kind | token | params | result |
| --- | --- | --- | --- | --- |
| `stell_chainId` | read | — | — | number (`STELL_CHAIN_ID`, default `5757`) |
| `stell_nodeId` | read | — | — | `inf1:<40 hex>` |
| `stell_blockNumber` | read | — | — | hex string |
| `stell_syncing` | read | — | — | bool (true while a recent verified peer is ahead) |
| `stell_getStateRoot` | read | — | — | 64 hex chars |
| `stell_latestBlocks` | read | — | — | array, newest first, ≤100 |
| `stell_getBlock` | read | — | `height` (number) | summary, or `-32004` if unknown |
| `stell_getBlockTransactions` | read | — | `{height}` | `{height, txs}` or `-32004` |
| `stell_getShards` | read | — | — or `height` (number, optional) | `{shards, total_shards, routing_prefix_bits, sharding}` |
| `stell_getShardTopology` | read | — | — | `{parameters, shards, transitions, total_accounts, total_balance}` |
| `stell_getInvalidations` | read | — | — or `limit` (number, optional) | `{invalidations, count}` (≤64 signals; `stell_invalidationFeed` is an alias) |
| `stell_getBalance` | read | — | address (bare or object) | `{balance, nonce}` |
| `stell_getBalanceSpv` | read | — | `{address}` | above + `stateRoot`, `proof` |
| `stell_getProof` | read | — | `{address, [storage_keys], [block_height]}` | `{address, balance, nonce, account_proof, storage_proofs, state_root, height, exists}` |
| `stell_getArchiveProof` | read | — | `{address, [key], height}` | `{height, state_root, key, value|null, proof, proof_type}` or `-32004` |
| `stell_getHistoricalRoot` | read | — | `{height}` | `{height, state_root, anchor_height, anchor_hash, prev_hash, cert, finalized}` or `-32004` |
| `stell_tokenBalance` | read | — | `{token, account}` | decimal string |
| `stell_tokenSupply` | read | — | `{token}` | decimal string |
| `stell_tokenBalanceSpv` | read | — | `{token, account}` | `balance`, `stateRoot`, `key`, `proof` |
| `stell_tokenResolve` | read | — | `{creator, name, symbol}` | `{token}` or `-32004` |
| `stell_listTokens` | read | — | `{limit, offset}` | `{tokens, total, offset}` (limit default 100, max 1000) |
| `stell_getTransactionReceipt` | read | — | hash (bare or object) | receipt, or `{status}` |
| `stell_getTransactionStatus` | read | — | hash (bare or object) | `{status, height}` |
| `stell_sendRawTransaction` | write (open) | — | `{tx}` | tx hash hex |
| `stell_faucet` | write | faucet token | `{address, [amount]}` | `{credited_nano, recipient, tx_hash}` |
| `stell_submitPriceFeed` | write | **yes** | `{tx}` | tx hash hex |
| `stell_pmmBuy` / `stell_pmmSell` | write | **yes** | `{tx}` | tx hash hex |
| `stell_pmmState` | read | — | — | the committed PMM curve |
| `stell_orderBook` | read | — | `{pair}` | the committed book (≤20 levels/side) |
| `stell_sessionBudget` | read | — | `{session}` | the session key's gas budget |
| `stell_bridgeDeposit` | read | — | `{source_tx_hash}` | the deposit record (`found`) — the RECORD read; the prepare is `stell_bridgeDepositPrepare` |
| `stell_bridgeDepositPrepare` | read | — | `{chain, source_tx_hash, recipient, amount}` | the deposit claim to sign (native namespace, §9) |
| `stell_bridgeAttestStatus` | read | — | `{source_tx_hash}` | the committed attestation state of a deposit claim (native namespace, §9) |
| `stell_bridgeReleaseEstimate` | read | — | `{request_id}` | release readiness of a parked withdrawal (native namespace, §9) |
| `stell_bridgeDeposits` | read | — | `{address, [limit]}` | paginated deposit history with per-deposit status (native namespace, §9) |
| `stell_bridgeDispute` | read | — | `{dispute_id}` | the dispute record (`found`) |
| `stell_mempoolSize` | read | — | — | number |
| `stell_mempoolDump` | read | **yes** | — | array of `{sender, nonce, hash}` |
| `stell_baseFee` | read | — | — | `{base_fee}` |
| `stell_epochKey` | read | — | — | `{epoch, public_key, committee_hash, threshold, commitment, …}` (the MEV epoch key a wallet encrypts to) |
| `stell_sendSealedTransaction` | **write** | — | `{payload}` (hex of the sealed frame) | `{tx_hash, sealed}` |
| `stell_mevStats` | read | — | — | `{epoch, sealed, plain, sealed_share, unsealed, unseal_failures, …}` |
| `stell_getEpochRoot` | read | — | `{epoch}` (or `{height}`, or a bare epoch number) | `{epoch, start_height, end_height, mmr_root, peaks, complete, leaves, committed_root, committed_in_height}` (the V5 Tier-2 epoch MMR root) |
| `stell_estimateFee` | read | — (own 5/s budget) | `{from, to, amount, …, [max_gas]}` | `{gas_limit, estimated_fee, base_fee, source_shard, target_shard, is_cross_shard, gas_budget, gas_ceiling}` |
| `stell_stakeOf` | read | — | `{validator}` | `{total, self_bond, delegated}` |
| `stell_getValidators` | read | — | — | `{validators, total_power, quorum, fragile, fragile_reason}` |
| `stell_listProposals` | read | — | — | array of proposals |
| `stell_proposal` | read | — | `{id}` | proposal, or `-32004` |
| `stell_governanceParams` | read | — | — | `{quorum_bps, next_id, applied}` |
| `stell_submitProposal` | **write** | **yes** | `{title, type, …}` (an unknown `type` is refused) | `{proposal_id, status}` |
| `stell_vote` | **write** | **yes** | `{id, voter, choice}` | `{voted, proposal_id, weight}` |
| `stell_executeProposal` | **write** | **yes** | `{id, [executor]}` | `{executed, applied}` |
| `stell_deployContract` | write (open) | — | `{code, [salt], [abi], …}` or `{tx}` | `{contract_address, contract_address_stl57, code_hash, tx_hash}` |
| `stell_callContract` | write (open) | — | `{contract, method, args, …}` | `{tx_hash, status, return_value, gas_used, events, outcome}` |
| `stell_runGetMethod` | read | — | `{address, method, args, [fuel], [height]}` | `{success, return_value, return_typed, shard, local_shard, shard_is_local, …}` |
| `stell_getContractAbi` | read | — | `{contract}` | `{contract, contract_stl57, abi, abi_json}` |
| `stell_getContractReceipt` | read | — | hash | `{status, return_value, gas_used, events, tx_hash}` |
| `stell_verifyContractSource` | read | — | `{contract, [source], [source_hex], [source_hash], [compiler], [compiler_flags]}` | `{verified, onchain_code_hash, rebuilt_code_hash, source_hash, reason, …}` |
| `stell_getContractSource` | read | — | `{contract}` | `{contract, contract_stl57, code_hash, source_hash, verified}` |
| `stell_registerContractSource` | write (signed) | — | `{contract, source_hash, signature}` | `{contract, source_hash, registered}` |
| `stell_getEvents` | read | — | `{tx_hash}` or `{contract, from_block, to_block, limit}` | array of events (≤1000) |
| `stell_subscribe` | write-ish | — | topic | subscription id (32 hex chars) |
| `stell_unsubscribe` | write-ish | — | subscription id | bool |
| `stell_getSubscriptions` | read | — | — | array of subscriptions |
| `stell_signMessage` | sign (node key, devnet-only) | **yes** | `{message}` xor `{message_hex}`, `[chain_id]` | `{address, scheme, scheme_id, signature, preimage, chain_id}` |
| `stell_verifyMessage` | read | — | `{address, message\|message_hex, signature, [chain_id]}` | `{valid, address, scheme, scheme_id, chain_id}` |
| `stell_signTypedData` | sign (node key, devnet-only) | **yes** | `{contract, method, [args], [value], [nonce], [chain_id]}` | `{address, scheme, scheme_id, signature, canonical, chain_id}` |
| `stell_verifyTypedData` | read | — | `{address, contract, method, [args], [value], [nonce], [chain_id], signature}` | `{valid, address, scheme, scheme_id, canonical}` |
| `stell_nativeApi` | read | — | — | the native-namespace manifest (35 methods) |
| `stell_token*` (9) | read / prepare | — | see §9 | see §9 |
| `stell_stake*` / `stell_delegate` / `stell_undelegate` / `stell_claimRewards` | prepare | — | see §9 | see §9 |
| `stell_bridge*` (6) | read / prepare | — | see §9 | see §9 |
| `stell_orderBook*` (5) | read / prepare | — | see §9 | see §9 |
| `stell_sessionKey*` (3) | read / prepare | — | see §9 | see §9 |
| `stell_oracle*` (2) | read | — | see §9 | see §9 |
| `stell_shielded*` / `stell_unshield` (3) | read / prepare | — | see §9 | see §9 |

---

## 11. Streaming subscriptions

The node can **push** notifications instead of making a client poll. Two
transports carry the same notification stream:

| transport | endpoint | method | notes |
| --- | --- | --- | --- |
| WebSocket | `GET /ws` on the RPC listener (`STELL_RPC_LISTEN`) | HTTP upgrade | JSON-RPC **in**, notifications **out**. The socket speaks the same dialect as the HTTP endpoint, so any method (including `stell_subscribe` / `stell_unsubscribe`) can be called over it. |
| SSE | `GET /events` on the RPC listener **and** on the gateway (`STELL_EXPLORER_LISTEN`) | HTTP GET | `text/event-stream`; the fallback for a browser that cannot open a WebSocket. |

Both are served by the same router as the JSON-RPC endpoint
(`rpc::router`), and the gateway mounts the very same SSE handler on
`/events` so a browser can `EventSource("/events")`.

### Topics

| topic | aliases | payload |
| --- | --- | --- |
| `newHeads` | `new_heads`, `heads` | a newly finalized head of **this node's** chain |
| `newTxs` | `new_txs`, `transactions` | the transactions included in a finalized block |
| `invalidations` | `invalidation`, `reorgs` | a block-invalidation signal (the blocks this node told the world about and then could not keep) |
| `events` | `logs`, `contractEvents` | a contract event, optionally filtered by contract address and topic ids |

The `events` topic accepts a filter object:

```json
{"type":"events","contract":"<64 hex>","topics":["Transfer","0xabc…"]}
```

`contract` is the canonical 32-byte hex of the contract to watch (omitted =
all contracts). `topics` is a list of event topic ids / names (empty = all). A
filter compares byte-exact against the events the chain emits.

The `invalidations` topic is the **push side** of `stell_getInvalidations` — the
honest counterpart of `newHeads`. The blocks named in a signal were never
applied (BFT finality forbids rolling back an applied block), so the signal
tells a subscriber "that block you were told about is not on the chain".

### `stell_subscribe`

**Register a subscription and get its id.**

Parameters: the topic, in any of three forms:

```json
{"method":"stell_subscribe","params":["newHeads"]}
{"method":"stell_subscribe","params":{"type":"events","contract":"<64 hex>"}}
{"method":"stell_subscribe","params":"newTxs"}
→ {"result":"<32 hex chars>"}
```

- The id is **16 random bytes, hex-encoded** (32 characters,
  `SUBSCRIPTION_ID_BYTES = 16`).
- Unknown topic → `-32602 "unknown subscription type: <x>"`. A missing topic →
  `-32602 "missing subscription type"`.

**Bounds (DoS limits).**

| bound | value |
| --- | --- |
| live subscriptions per node | **4096** (`MAX_SUBSCRIPTIONS`) |
| live subscriptions per client (IP) | **64** (`MAX_SUBSCRIPTIONS_PER_CLIENT`) |
| lifetime of a detached subscription | **3600 s** (`SUBSCRIPTION_TTL_SECS`) |

Exceeding the global cap is `-32000 "subscription limit reached (4096 live
subscriptions)"`; exceeding the per-client cap is `-32000 "per-client
subscription limit reached (64 live subscriptions for this client)"`. The
per-client cap exists because the global cap is **global**: without it one
client could take the whole registry and deny the service to every other
subscriber.

### `stell_unsubscribe`

Parameters: `{"subscription": "<id>"}` (also `params[0]`, or the bare string).

```json
{"method":"stell_unsubscribe","params":{"subscription":"<32 hex>"}}
→ {"result":true}
```

`true` when the subscription existed, `false` when the id was unknown —
idempotent, like the EVM `eth_uninstallFilter`. A missing id is `-32602
"missing subscription id"`.

### `stell_getSubscriptions`

Parameters: none.

```json
{"method":"stell_getSubscriptions","params":{}}
→ {"result":[
    {"id":"<32 hex>","topic":{"type":"newHeads"},"created_at":1758800000,
     "attached":true,"client":"203.0.113.7"}
  ]}
```

- `topic` — the subscription's topic, tagged: `{"type":"newHeads"}`,
  `{"type":"newTxs"}`, `{"type":"invalidations"}` or
  `{"type":"events","contract":"…","topics":[…]}`.
- `created_at` — unix seconds.
- `attached` — `true` while a transport (WebSocket / SSE) is streaming this
  subscription; an attached subscription is not swept by the TTL.
- `client` — the creating client's IP, when the transport could attribute it.
  Present for the per-client budget.

### The notification shape

Both transports emit exactly the same object:

```json
{"subscription":"<32 hex>","result":{ … }}
```

- WebSocket: one JSON text frame per notification.
- SSE: `data: {"subscription":"…","result":{…}}\n\n`, with a 15-second
  keep-alive comment.

Delivery is **best effort**: a transport that is not attached, or that lags
behind the in-process fan-out (capacity 1024), simply misses the notification.
The publisher never blocks on a slow subscriber. A client that must not miss
anything should re-check `stell_blockNumber` after a gap.

### The SSE transport in detail

`GET /events` accepts query parameters:

| parameter | meaning |
| --- | --- |
| `sub_id` | serve an **existing** subscription (created earlier over HTTP or over the WebSocket). `404` when the id is unknown. |
| `topics` | create the subscriptions to serve: `newHeads,newTxs,invalidations,events` (comma separated). Defaults to `newHeads` when nothing is given. |
| `contract` | the contract filter for the `events` topic |
| `event_topics` | the topic filter for the `events` topic |

The ids of the subscriptions the stream serves are returned in the
`x-stell-subscription-id` response header (comma separated). A subscription
created by the SSE stream is **removed when the stream closes**; one attached
through `sub_id` is only *detached* (it keeps existing).

### The WebSocket transport in detail

`GET /ws` upgrades to a WebSocket. The upgrade request's credentials are
honoured exactly like on the HTTP endpoint: the API token in the headers gates
the same methods, and the peer address feeds the per-IP limits. **A WebSocket
must never be a way around the auth gate.**

A subscription created on a socket is pushed to that socket and **dies with
it**: when the connection closes, every subscription it created is removed.

---

## 12. Read-only HTTP gateway

Served on `STELL_EXPLORER_LISTEN` (default `127.0.0.1:8080`), all `GET`, all
behind a per-IP fixed-window rate limiter (`STELL_RATE_LIMIT_PER_SEC`, default
30 req/s, HTTP 429 above that), all with `access-control-allow-origin: *`. The
JSON-RPC router is nested at `/rpc` on the same listener and the same limiter.

| route | returns |
| --- | --- |
| `/` | the explorer HTML page (a static string that calls the API below with `fetch`) |
| `/health` | `{"status":"ok","service":"stellereum-gateway"}` (legacy alias) |
| `/healthz` | `{"status":"ok","service":"stellereum-gateway"}` — liveness probe: cheap by design (no locks, no state reads), always 200 when the process answers HTTP. Use `/readyz` to ask whether the node is actually useful (`src/explorer.rs:745-750`) |
| `/readyz` | readiness probe: 200 when ready, 503 with the same body when not. Body: `{"ready":bool,"failed_checks":[...],"height":N,"peers":P,"secs_since_finalized":S|null,"max_stall_secs":30,"min_peers":1}` where `failed_checks` ⊆ `no_peers,no_finality,finality_stalled,height_zero,height_stalled` (`src/explorer.rs:752-771`; thresholds `STELL_READY_MAX_STALL_SECS`/`STELL_READY_MIN_PEERS`). Example ready: `{"ready":true,"failed_checks":[],"height":194,"peers":1,"secs_since_finalized":2,"max_stall_secs":30,"min_peers":1}`. Example stalled: `{"ready":false,"failed_checks":["no_peers","finality_stalled","height_stalled"],"height":194,"peers":0,"secs_since_finalized":187,"max_stall_secs":30,"min_peers":1}` |
| `/metrics` | Prometheus text: the consensus registry (`stell_consensus_round/height`, `stell_block_interval_seconds`, `stell_consensus_votes_total{kind}`, `stell_peer_latency_seconds{peer}`, `stell_fork_total`, `stell_mempool_size`, `stell_block_txs`, `stell_state_root_commits_total`, `stell_validator_set_size`) plus gateway gauges `stellereum_block_height`, `stellereum_mempool_size`, `stellereum_contracts_total`, `stellereum_tokens_total`, `stell_ready` (1 = `/readyz` ready, 0 = not; `src/explorer.rs:808-849`). Example scrape tail: `stellereum_block_height 194`, `stellereum_mempool_size 3`, `stell_ready 1` (see `OPERATIONS.md` §9 for a full example) |
| `/api/stats` | `chain_id`, `node_id`, `height`, `mempool`, `state_root`, `contracts` |
| `/api/blocks` | same array as `stell_latestBlocks` |
| `/api/balance/:address` | `{address, balance, nonce}` |
| `/api/spv/:address` | `address`, `balance`, `nonce`, `state_root`, `proof` |
| `POST /api/faucet/:address` | a faucet drip; 404 if disabled, 400 on a bad address, 405 on GET, 429 on caps/exhaustion, 503 if the transfer could not be admitted |
| `/api/contracts` | `{contracts: [<hex>, ...], total, offset}` (limit default 100, max 1000) |
| `/rpc` | the JSON-RPC router (`POST`) |

Note the key-name difference: the gateway uses `state_root` and `/api/spv`
returns a `proof`, while the JSON-RPC methods use `stateRoot`. They are separate
handlers, not aliases.

The gateway is a *read* surface with exactly one exception (`/api/faucet`), and
it serves the JSON-RPC router, including `stell_sendRawTransaction`, at `/rpc`.
Rate limiting is per IP and in-process, so it is a speed bump, not access
control. Put a reverse proxy with real authentication in front of anything
public.

---

## 13. Wallet message signing (the standard)

The full standard lives in [`WALLET_SIGNING.md`](WALLET_SIGNING.md); this
section is the RPC binding. The standard covers how a wallet signs a MESSAGE
or a contract call — never transactions (different preimage, different
domain) and never addresses (unchanged).

### `stell_signMessage` (node key, testing/devnet ONLY)

**WRITE. Requires the auth token** (when `STELL_RPC_AUTH_TOKEN` is set — the
same gate as `stell_mempoolDump` and the signed-payload arms).

Parameters: `{"message": "<utf8>"}` XOR `{"message_hex": "<hex>"}`, plus
optional `{"chain_id": <u64>}` (default: this node's chain id) and
`{"token": "<api token>"}`.

```json
{"method":"stell_signMessage","params":{"message":"hello stellereum","token":"<api token>"}}
→ {"result":{
     "address":"2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
     "scheme":"Ed25519","scheme_id":1,
     "signature":"01010020… (standard envelope hex)",
     "preimage":"5374656c… (what was signed, hex)",
     "chain_id":5757}}
```

It signs with the NODE's Ed25519 key (wired to the validator/identity key at
startup). A node with no signing key configured refuses fail-closed with
`-32000`. Production wallets MUST sign locally (`stellereum wallet sign` or
the library) and never ship keys to a node.

### `stell_verifyMessage` (public, no auth)

Parameters: `{"address": "<hex>", "message"|"message_hex": …, "signature":
"<hex envelope>", ["chain_id"]}`.

```json
→ {"result":{"valid":true,"address":"<hex>","scheme":"Ed25519","scheme_id":1,"chain_id":5757}}
```

Accepts all three live schemes (Ed25519, Falcon-512, Hybrid). `valid: false`
for a wrong chain, a tampered message, a wrong address — a MALFORMED envelope
is instead `-32602 "bad signature envelope: …"`.

### `stell_signTypedData` / `stell_verifyTypedData`

The structured form: the wallet displays the canonical JSON of
`{contract, method, args, value, nonce, chain_id}` and signs THAT, so the user
sees exactly what they authorize (EIP-712-style readable signing).

```json
{"method":"stell_signTypedData",
 "params":{"contract":"<64 hex>","method":"transfer",
           "args":{"to":"alice","amount":100},
           "value":"1000","nonce":"7","token":"<api token>"}}
→ {"result":{
     "address":"<hex>","scheme":"Ed25519","scheme_id":1,
     "signature":"<hex envelope>",
     "canonical":"{\"args\":{\"amount\":100,\"to\":\"alice\"},\"chain_id\":\"5757\",…}",
     "chain_id":5757}}
```

`args` accepts any JSON (default `null`); `value`/`nonce` accept a number or a
decimal string (default `"0"`); `chain_id` defaults to this node's. Key order
in `args` does not matter — it is re-encoded canonically (sorted,
whitespace-free) before signing and before verifying. Display `canonical` to
the user; it is the exact bytes the signature commits to.

Errors mirror the message arms: the SIGN arm needs the token (when one is
configured) and a configured node key; the VERIFY arm is public and answers
`{"valid":…}` with the locally re-encoded `canonical` beside it.
