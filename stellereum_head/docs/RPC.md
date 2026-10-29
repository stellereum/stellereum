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
| Auth | none on reads and none on submission: `stell_sendRawTransaction` / `eth_sendRawTransaction` are **open submission by design** (a caller can only submit a validly signed, funded, nonce-sane tx; the tx authenticates itself). Gated by `STELL_RPC_AUTH_TOKEN` (when set): `stell_mempoolDump`, `stell_submitPriceFeed`, `stell_pmmBuy`, `stell_pmmSell`. `stell_faucet` requires the separate `STELL_FAUCET_TOKEN` and is **fail-closed**: an enabled faucet with no token refuses to dispense. |

There is exactly one route in the router — `("/", post(rpc_handler))` — so
`GET /`, or a POST to any other path, returns 404. `/health`, `/healthz`,
`/readyz`, `/metrics` and `/api/*` live on the explorer port, not here.

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
| `-32602` | invalid params | missing address/token/validator, bad hex, wrong length, undecodable `tx`, block outside the recent window, unknown proposal id, `tx` over the size cap |
| `-32000` | chain error | bad signature, mempool rejection, faucet limit reached, faucet transfer not admitted |
| `-32001` | unauthorized | `stell_mempoolDump` / `stell_submitPriceFeed` / `stell_pmmBuy` / `stell_pmmSell` without a valid `STELL_RPC_AUTH_TOKEN` (when one is set), or `stell_faucet` without a valid `STELL_FAUCET_TOKEN` |

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
  (PROTOCOL.md §5), not an oversight in the RPC layer.

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
not a light client: the node hands you the root it believes. There is no light
client in the codebase (PROTOCOL.md §5).

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
     "gas_limit":"1000"
   }}
```

`status` is `"success"` or `"failed"`. `index` is the position within the block.
`gas_limit` is a decimal string.

**If the hash is not in the index**, the same method answers with a *different
shape* rather than an error:

```json
→ {"result":{"status":"pending"}}    // still in this node's mempool
→ {"result":{"status":"unknown"}}    // not here at all
```

So a client must handle three result shapes from one method, and `pending`
only knows about **this node's** mempool. On a multi-validator network a
transaction in a peer's mempool reads as `unknown` here. There is no way to ask
another node. `gas_limit` is what the transaction *offered*; there is no gas
used and no fee collected in the receipt.

The index is bounded at 50,000 receipts (`MAX_RECEIPTS`) and evicts oldest-first,
so a receipt for an old transaction is `unknown` rather than an error.

Statuses are captured at the single point where a block is actually applied and
are never recomputed — re-deriving a verdict from post-state would report every
successful transaction as failed, because the nonce has already moved
(PROTOCOL.md I8).

### `stell_getTransactionStatus`

Parameters: `{"hash": "<hex>"}` or the bare string form.

```json
→ {"result":{"status":"success","height":77}}
→ {"result":{"status":"failed","height":77}}
→ {"result":{"status":"pending","height":null}}
→ {"result":{"status":"unknown","height":null}}
```

The same information as the receipt, reduced to a four-valued status and the
height. Unified vocabulary across receipt/status/explorer: `success`
(formerly `mined`), `failed`, `pending`, `unknown`. `height` is `null`
unless the transaction was included.

A cheap liveness poll, but see the `pending`-is-local caveat above.

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

Mempool limits, all fixed in `Mempool::default()` and not configurable:
10,000 transactions, 256 pending per sender. A block is bounded separately at
10,000 transactions and 120,000,000 total gas.

### `eth_estimateGas` (floor-aware admission estimate)

Parameters: `[{to, data, ...}]` (same call object as `eth_call`).

```json
{"method":"eth_estimateGas","params":[{"to":"0x3535...","data":"0xaabbccdd"}]}
→ {"result":"0x5248"}
```

This is an **admission** estimate, not execution metering: EVM calldata is
never executed (plain-transfer settlement; contract creation is rejected), and
`gas_price` / `max_fee_per_gas` on the EVM views are display-only. The node
returns `max(pure EVM figure, live admission floor)`, where the pure figure is
21k (transfer) / 53k (creation) + 4 per zero calldata byte + 16 per non-zero
byte, and the floor is the mempool `base_fee` served read-only as
`stell_baseFee`. A wallet that forwards this figure is never told a number the
same node would reject for under-declared gas.

### `stell_faucet`

Parameters: `{"address": "<hex>"}` or the bare string form, plus an optional
`{"amount": <number>}`.

```json
{"method":"stell_faucet","params":{"address":"<64 hex>"}}
→ {"result":{
     "credited_nano":"100000000000",
     "recipient":"<64 hex>",
     "tx_hash":"<64 hex>"
   }}
```

`credited_nano` is a decimal string, **not** the amount you asked for. The drip
is 10 STELL by default (`STELL_FAUCET_DRIP_STELL` overrides it) and the lifetime
cap per address is 1000 STELL, hardcoded where the `Faucet` is constructed.
`amount` is clamped down to the drip, and
then down to whatever remains of the lifetime cap. Asking for `u64::MAX` gets you
one drip, not an error.

Errors:

| code | condition |
| --- | --- |
| `-32601 "faucet is disabled on this node"` | `STELL_FAUCET` is not `1`/`true` on this node — the default |
| `-32602 "missing address"` / `"bad hex: …"` | no address, or not 32 bytes |
| `-32000 "faucet limit reached for this address"` | the 1000 STELL lifetime cap for that address is spent |
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
     "quorum":"2"
   }}
```

The active set with each member's power, the total, and the quorum threshold.
All three are decimal strings.

Read `quorum` before you rely on any assumption about how many nodes a network
needs. It is `floor(2 × total_power / 3) + 1`, which with unit power gives
1 for one validator, **2 for two, 3 for three** (not the two-of-three you would
guess), and 3 for four. A zero-power or empty set returns `18446744073709551615`
(`u64::MAX`) — the set is deliberately unable to reach quorum, so a broken
validator list stalls the chain instead of letting one node finalize everything
unilaterally.

Genesis validators are bonded at 1000 STELL each (power 1) by `fund_genesis`, so
a freshly started network reports exactly the ids in your `validators:` YAML
list.

---

## 6. Governance

Both governance methods read the **state engine's** `Governance` object: the RPC
`governance` handle is cloned from `shared_gov`, which is `state_engine.governance_handle()`
(`src/main.rs`), the same object that consensus persists and restores. Governance
**is** in the consensus commitment digest as of `COMMITMENT_VERSION = 3`
(commit `9a93ef0`), alongside the staking ledger, tokens, order books, escrow,
PMM and contracts, and the oracle feed was added in version 4. Two nodes on the
same chain therefore agree on governance state; these methods are a valid way to
compare it.

### `stell_proposal`

Parameters: `{"id": <number>}`. Defaults to `0` if absent, rather than erroring.

```json
→ {"result":{
     "id":1,
     "title":"Raise the base fee",
     "status":"Active",
     "yes":"1000000000000000000",
     "no":"0",
     "abstain":"0",
     "turnout":"0.6"
   }}
```

`status` is the `Debug` formatting of the status enum, e.g. `Active`,
`Passed`, `Rejected`, `Defeated` — an unstable string, do not parse it. Vote
totals are decimal strings. `turnout` is a `f64` rendered as a JSON number.

Errors: `-32602 "proposal not found"`.

### `stell_governanceParams`

Parameters: none.

```json
→ {"result":{"quorum_bps":3334,"next_id":2,"applied":0}}
```

`quorum_bps` is in basis points, `next_id` is the id the next proposal will get,
`applied` counts proposals that have taken effect.

There are **no governance write methods on the RPC surface.** A proposal cannot
be created, voted on, or executed over JSON-RPC with this binary. The other
`stell_*`-adjacent functionality (order books, oracle, bridge, PMM, contracts)
exists only in the `orderbook` / `oracle` / `bridge` / `pmm` CLI subcommands, and
those operate on freshly constructed in-process objects rather than on node
state — they print results and exit without touching the running node.

---

## 7. Mempool

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

---

## 8. Quick call reference

| method | params | result |
| --- | --- | --- |
| `stell_chainId` | — | number (`STELL_CHAIN_ID`, default `5757`) |
| `stell_nodeId` | — | `inf1:<40 hex>` |
| `stell_blockNumber` | — | hex string |
| `stell_syncing` | — | bool (true while a recent verified peer is ahead) |
| `stell_getStateRoot` | — | 64 hex chars |
| `stell_latestBlocks` | — | array, newest first, ≤100 |
| `stell_getBlock` | `height` (number) | summary, or `-32004` if unknown |
| `stell_getBalance` | address (bare or object) | `{balance, nonce}` |
| `stell_getBalanceSpv` | `{address}` | above + `stateRoot`, `proof` |
| `stell_tokenBalance` | `{token, account}` | decimal string |
| `stell_tokenSupply` | `{token}` | decimal string |
| `stell_tokenBalanceSpv` | `{token, account}` | `balance`, `stateRoot`, `key`, `proof` |
| `stell_listTokens` | `{limit, offset}` | `{tokens, total, offset}` (limit default 100, max 1000) |
| `stell_getTransactionReceipt` | hash (bare or object) | receipt, or `{status}` |
| `stell_getTransactionStatus` | hash (bare or object) | `{status, height}` |
| `stell_sendRawTransaction` | `{tx, [token]}` | tx hash hex |
| `stell_faucet` | `{address, [amount]}` | `{credited_nano, recipient, tx_hash}` |
| `stell_stakeOf` | `{validator}` | `{total, self_bond, delegated}` |
| `stell_getValidators` | — | `{validators, total_power, quorum}` |
| `stell_proposal` | `{id}` | proposal, or `-32602` |
| `stell_governanceParams` | — | `{quorum_bps, next_id, applied}` |
| `stell_mempoolSize` | — | number |

---

## 9. Read-only HTTP gateway

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
