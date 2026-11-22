---
title: JSON-RPC reference
description: Every stell_* method, transport rules, encodings, batching, auth and curl recipes.
outline: deep
---

# JSON-RPC reference

The node exposes a JSON-RPC 2.0 surface over HTTP `POST /`. It is the complete `stell_*` method reference plus the `eth_*` / `net_*` / `web3_*` compatibility surface.

::: tip One rule for integrators
Addresses, token ids and hashes are 32-byte hex. Balances, fees and supply are
**decimal strings** in nano-STELL. Block height from `stell_blockNumber` is a
**hex string**, but `stell_getBlock` takes a JSON **number**. These three
inconsistencies are real and are documented per method.
:::

## Transport

| | |
| --- | --- |
| Protocol | HTTP/1.1, `POST` only |
| Endpoint | `/` on `STELL_RPC_LISTEN` (default `127.0.0.1:8545`) |
| Second endpoint | `/rpc` on `STELL_EXPLORER_LISTEN` (default `127.0.0.1:8080`), same router, behind the gateway limiter and CORS |
| Content type | any; the body is read as a string and parsed with `serde_json` |
| Max body | 1 MiB (`MAX_RPC_BODY`); larger → `-32600 "request too large"` |
| Rate limit | standalone RPC **300 req/s per IP** (`STELL_STANDALONE_RATE_LIMIT`); gateway **30 req/s per IP** (`STELL_RATE_LIMIT_PER_SEC`) |
| Auth | reads and `stell_sendRawTransaction` are open; see the [auth matrix](#auth-matrix) |
| Other routes | `GET /ws` (WebSocket) and `GET /events` (SSE) on the same listener |

There is exactly one HTTP route in the router — `("/", post(rpc_handler))` —
so `GET /` returns 405 and a POST to any other path returns 404. `/health`, `/healthz`,
`/readyz`, `/metrics` and `/api/*` live on the **explorer/gateway** port, not
the RPC port.

Rate limiting is a speed bump, not access control. Put a reverse proxy with
real authentication in front of anything public.

## Request and response

```json
{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":{}}
```

```json
{"jsonrpc":"2.0","id":1,"result":"0x2a"}
```

- `jsonrpc` is accepted and ignored.
- `id` is optional; it is echoed, or `null` if omitted.
- `params` is optional; omitting it is equivalent to `null`. Many methods
  accept a bare string or bare number as well as an object. Per-method notes
  say which, because it is **not uniform**.
- An error always carries the `id`, including errors raised before parsing.

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"missing address"}}
```

### Batch requests

A JSON-array body is a batch:

- at most **64** items (`MAX_RPC_BATCH_ITEMS`);
- at most **1 MiB** total (`MAX_RPC_BATCH_BYTES`).

More of either refuses the **whole** batch with `-32600`. Each item is
dispatched independently with its own auth check, rate budget and error shape.
Responses come back in request order. Notifications (missing or `null` `id`)
get no response entry; an all-notification batch answers `204 No Content`.

## Error codes

| code | meaning | typical cause |
| --- | --- | --- |
| `-32700` | parse error | body is not valid JSON |
| `-32600` | invalid request | no `method`, wrong shape, empty/oversize batch, body over 1 MiB |
| `-32601` | method not found | unknown method; `stell_faucet` when the faucet is disabled |
| `-32602` | invalid params | missing address/token/validator, bad hex, wrong length, undecodable `tx`, block outside the recent window, unknown proposal id, oversize `tx`, unknown subscription topic, too many `storage_keys` |
| `-32000` | chain error | bad signature, mempool rejection, faucet limit, subscription budget exhausted, estimate-fee budget exhausted |
| `-32001` | unauthorized | a gated write without a valid token, or a fail-closed write with no token configured |
| `-32003` | refused by state | native namespace: committed state refuses (insufficient balance, paused token, thin bond, replayed deposit, revoked session) |
| `-32004` | not available | block/tx/proposal/token/validator/pair/session/asset not known, or a historical height this node does not serve |
| `-32010` | no epoch key yet | the MEV committee DKG has not completed for the current epoch |
| `-32011` | sealed transaction refused | stale epoch, duplicate, per-sender quota, full pool |

The complete string catalog, including faucet refusal reasons and mempool
messages, is on [Errors](/api/errors).

## Value encodings

| Kind | Encoding | Example |
| --- | --- | --- |
| Address, token id, hash | 32-byte hex, `0x` optional | `"3b0c…"` |
| Balance, fee, supply | **decimal string**, nano-STELL | `"1000000000"` |
| Block height (`stell_blockNumber`) | lowercase hex string | `"0x2a"` |
| Block height (`stell_getBlock`) | JSON **number** | `42` |
| Nonce | JSON number | `2` |
| Merkle proof nodes | hex nodes, leaf first | `"4c00…"` |
| `proof` when key absent | `null` | `null` |

All address parsers strip `0x` and reject anything that is not exactly 32 bytes
with `-32602`.

## Chain and node

| Method | Params | Returns | Notes |
| --- | --- | --- | --- |
| `stell_chainId` | — | JSON number | effective id, default `5757` |
| `stell_nodeId` | — | `"inf1:<40 hex>"` | `blake3(ed25519 pubkey)[..20]`, stable per node, **not** an account |
| `stell_blockNumber` | — | hex string | **finalized** height |
| `stell_syncing` | — | bool | true while a recent verified peer sighting is above us (5 min TTL) |
| `stell_getStateRoot` | — | 64 hex | Patricia root; see the caveats below |
| `stell_latestBlocks` | — | array, newest first | rolling window, max 100, not persisted |
| `stell_getBlock` | `{height:number}` | `{height,hash,txs,timestamp}` | same 100-entry window only; no block body |
| `stell_getBlockTransactions` | `{height:number}` | `{height,txs:[…]}` | receipt-index backed; empty array means “known, zero txs” |
| `stell_getShards` | — or `{height?:number}` | `{shards,total_shards,routing_prefix_bits,sharding}` | committed heads; `height` is a **bound**, not a selector |
| `stell_getShardTopology` | — | `{parameters,shards,transitions,total_accounts,total_balance}` | address-space layout, not heads |
| `stell_getInvalidations` | — or `{limit?:number}` | `{invalidations,count}` | rolling 64-signal window; alias `stell_invalidationFeed` |
| `stell_zkmlCapabilities` | — | capability object | machine-readable truth: zkML is re-execution, not ZK |
| `stell_nativeApi` | — | manifest | discovery for the [native namespace](#native-interface-namespace) |

### `stell_getStateRoot` caveats

The root commits to native balances, STS balances and supply, contract code
hashes and — under one key, `sha256("STELL_CONSENSUS_COMMITMENT_V1")` — a
digest over staking, order books, escrow, PMM, contracts, governance and the
oracle feed (`COMMITMENT_VERSION = 5`).

Two consequences:

1. Reading it has a **side effect on first read after a mutation**: the
   commitment digest is recomputed and written if it changed. It is not a pure
   read.
2. The non-trie subsystems are committed **as one digest**, not per key. A
   client can prove a native balance against this root, but cannot prove a
   single staking entry or orderbook level. Use `stell_getProof` for account
   state; the domain gap is documented.

Pair it with `stell_blockNumber` when comparing nodes. Height alone proves
nothing; same height + different root is a split.

## Accounts, state and proofs

| Method | Params | Returns | Notes |
| --- | --- | --- | --- |
| `stell_getBalance` | bare address or `{address}` | `{balance,nonce}` | missing account → `{"balance":"0","nonce":0}` |
| `stell_getBalanceSpv` | `{address}` **object only** | balance + `stateRoot` + `proof` | `proof:null` for no trie entry; validates against the returned root |
| `stell_getProof` | `{address,storage_keys?,block_height?}` | `{address,balance,nonce,account_proof,storage_proofs,state_root,stateRoot,height,exists}` | inclusion **and exclusion** proofs; max 32 storage keys |
| `stell_getArchiveProof` | `{address,key?,height}` | `{height,state_root,key,value,proof,proof_type}` | only snapshot heights; unknown/pruned → `-32004` |
| `stell_getHistoricalRoot` | `{height}` | root + anchoring QC | fail-closed above tip / pruned |
| `stell_getFinalizedHeader` | `{height}` | header + precommit cert | retained window: most recent 512 |
| `stell_getFinalizedCheckpoint` | — | newest header + QC | light-client anchor; only moves forward |
| `stell_getAddressHistory` | `{address,from_height?,to_height?,role?,cursor?,limit?}` | `{address,items,next_cursor}` | durable `tx_by_addr` merged with the fresh receipt window; `role` = `all｜sender｜recipient` |
| `stell_getTokenAccountsByOwner` | `{owner,token?,include_zero?,cursor?,limit?}` | `{owner,owner_stl57,items,next_cursor}` | keyset pagination; `limit` max 200 |
| `stell_getProgramAccounts` | `{program:"token"｜"contract"｜"system",…}` | `{program,items,next_cursor,…}` | bounded analogue; unfiltered `system` dump is refused |

::: warning Proof trust model
`stell_getBalanceSpv` verifies against the root the **same response** carries.
That is a consistency check, not a light client. For a proof you can check
against a root **you** trust, use `stell_getProof` plus
`stell_getHistoricalRoot` / `stell_getFinalizedHeader` and verify the quorum
certificate against an out-of-band validator set.
:::

`stell_getProof` wire format (hex nodes, leaf first):

```text
leaf   : 4C | kind(1) | div_kind(1) | div_step(2 BE)
         | key(32) | witness_key(32) | value_len(4 BE) | value | leaf_hash(32)
branch : 42 | skip(2 BE) | bit(1) | flags(1) | sibling_hash(32)
```

`kind` is `00` inclusion or `01` exclusion; `flags` bit 0 means “sibling is
on the right”. The leaf hash is `blake3("L" ‖ key ‖ len(value) ‖ value)` and a
branch hash is `blake3("B" ‖ skip_be ‖ bit ‖ left ‖ right)`.

## Tokens and programs

| Method | Params | Returns | Notes |
| --- | --- | --- | --- |
| `stell_tokenBalance` | `{token,account}` | decimal string | token base units |
| `stell_tokenSupply` | `{token}` | decimal string | unknown token → `"0"` |
| `stell_tokenResolve` | `{creator,name,symbol}` | `{token}` | id commits the registry nonce; not predictable off-chain |
| `stell_tokenBalanceSpv` | `{token,account}` | balance + root + `key` + proof | key is `sha256("STS_BAL" ‖ token ‖ account)` |
| `stell_listTokens` | `{limit?,offset?}` | `{tokens,total,offset}` | limit default 100, max 1000 |
| `stell_getTokenAccountsByOwner` | see above | holdings page | includes metadata |
| `stell_getProgramAccounts` | see above | filtered accounts | `with_proof` caps at 16 |

There is **no token metadata method** on the base RPC surface: name, symbol,
decimals, minter and supply cap are not exposed there. The native namespace’s
`stell_tokenMetadata` does expose them. The CLI and PMM treat USDT as 6
decimals and everything else as 9; agree out-of-band.

## Transactions and receipts

| Method | Params | Returns | Notes |
| --- | --- | --- | --- |
| `stell_getTransactionReceipt` | bare hash or `{hash}` | receipt, or `{status:"pending"｜"unknown"}` | three result shapes; index bounded at 50,000 |
| `stell_getTransactionStatus` | bare hash or `{hash}` | `{status,height,confirmations}` | statuses `success｜failed｜pending｜unknown` |
| `stell_getTransactionByHash` | `{hash}` | richer tx view or `{status:"pending"｜"unknown"}` | resolves EVM-format hashes too |
| `stell_sendRawTransaction` | `{tx}` | tx hash hex | **open submission**; validates and admits, not finality |
| `stell_sendSealedTransaction` | `{payload}` | `{tx_hash,sealed}` | sealed frame `STX1 ‖ bincode(SealedEnvelope)`; `data` alias |
| `stell_estimateFee` | `{from,to,amount,…}` or `{tx}` | estimate object | own **5 req/s** budget; fixed 5M simulation ceiling |
| `stell_baseFee` | — | `{base_fee}` | admission floor, decimal string |
| `stell_faucet` | `{address,amount?}` | `{credited_nano,recipient,tx_hash,shard}` | separate faucet token; 2 STELL drip, 20 per IP-hour, 50 STELL lifetime (the public gateway path adds a 45-min per-address cooldown) |
| `stell_getEvents` | `{tx_hash}` or `{contract,from_block?,to_block?,limit?}` | array, ≤1000 | unknown tx → empty array |
| `stell_getContractReceipt` | bare hash or `{hash}` | contract-shaped outcome | no block/height/index fields |

### Receipt outcome fields

A committed receipt carries the **outcome**, not just inclusion:

- `status` — `success` or `failed`;
- `gas_limit` — what the transaction offered;
- `fee_charged` — what it was actually debited (`0` for an unattributable
  failure under the F-01 rule);
- `return_value`, `gas_used`, `events` — present only when the transaction
  produced them;
- `contract_address` / `contract_address_stl57` — when it deployed or called a
  contract.

If the hash is not in the index, the method answers with a **different shape**
rather than an error: `{"status":"pending"}` if it is in **this node's**
mempool, `{"status":"unknown"}` if this node holds no verdict. On a
multi-validator network a transaction in a peer's mempool reads as `unknown`
here.

### Confirmations

This chain has **single-block BFT finality**: a block is final when it carries
a precommit quorum certificate of at least `floor(2·total_power/3) + 1`.
**One confirmation is final.** “N confirmations” buys depth against
operational risk (a stale read, a lagging node), not against reorganization.

| Tier | Recommended | Why |
| --- | --- | --- |
| dust / test drips | 1 | finality already holds |
| ordinary payments (< 1k STELL) | 2–3 | proves the network kept finalizing after your tx |
| large transfers / bridge releases (≥ 50k STELL) | 10+ and a cross-node `stell_getStateRoot` match | settlement is the target |
| exchange / custodian crediting | 30+ and the `block_hash` re-fetched from a second node | protects against your own node's stale view |

Poll with `stell_getTransactionStatus` or `stell_getTransactionReceipt`.
Finalized blocks never reorg; **candidate** branches do — watch
`stell_getInvalidations` and the `invalidations` topic.

## Staking and validator lifecycle

| Method | Params | Returns | Notes |
| --- | --- | --- | --- |
| `stell_stakeOf` | `{validator}` | `{total,self_bond,delegated}` | decimal strings; unknown validator → zeros |
| `stell_getValidators` | — | `{validators,total_power,quorum,fragile,fragile_reason}` | active set, power, quorum |
| `stell_getValidatorStatus` | `{validator}` | `{known,jailed,jailed_at_height,release_height,in_set,self_bond,commission_bps,withdrawal_address,rotation_seq,pending_commission,last_commission_change_height}` | the operator's view |
| `stell_getPqKey` | `{validator,height?}` | active PQ key + pending rotation | height defaults to tip; future height → `-32004` |
| `stell_getPqRegistryStatus` | — | `{count,delay_heights,history_limit}` | rotation delay is a protocol constant |

Staking **writes** happen inside transactions, not through `stell_*` write
methods. The opcodes are `SysCallStake`, `SysCallStakeWithCommission`,
`SysCallDelegate`, `SysCallUnbond`, `SysCallBeginUndelegate` /
`SysCallUndelegate`, `SysCallClaimRewards` /
`SysCallClaimDelegatorRewards` and `SysCallRotateValidatorKey`. Use the
`stellereum validator …` CLI or the native prepare methods.

### Quorum math

`quorum = floor(2 × total_power / 3) + 1`. With unit power:

| Validators | Quorum |
| --- | --- |
| 1 | 1 |
| 2 | 2 |
| 3 | 3 |
| 4 | 3 |
| 5 | 4 |

Two- and three-validator networks halt on a single outage. A zero-power or
empty set returns `18446744073709551615` (`u64::MAX`), so a broken validator
list stalls the chain instead of letting one node finalize alone.

`fragile: true` means quorum needs **100 %** of the set. It is advisory and
fails open: `false` never blocks anything.

## Governance

Every governance method reads or writes the state engine's `Governance`
object, the same object consensus persists. Governance is in the commitment
digest (`COMMITMENT_VERSION = 5`), so two nodes on one chain agree on it.

| Method | Kind | Token | Params | Returns |
| --- | --- | --- | --- | --- |
| `stell_listProposals` | read | — | — | array of proposals |
| `stell_proposal` | read | — | `{id}` (defaults 0) | proposal, or `-32004` |
| `stell_governanceParams` | read | — | — | `{quorum_bps,next_id,applied}` |
| `stell_submitProposal` | **write** | **always** | `{title,type,…}` | `{proposal_id,status}` |
| `stell_vote` | **write** | **always** | `{id,voter,choice}` | `{voted,proposal_id,weight}` |
| `stell_executeProposal` | **write** | **always** | `{id,executor?}` | `{executed,applied}` |

The three writes require a valid token on **every** bind, loopback included.
With no token configured they refuse with `-32001` instead of serving. This is
deliberate: `stell_executeProposal` can apply a `SoftwareUpgrade`, which ends
in an `execve` of a new binary.

### Proposal action types

`type` selects the action. An unknown `type` is refused (`-32602`); it is never
silently turned into a `Signal`.

| `type` | Extra params | Action |
| --- | --- | --- |
| `set_min_validator_bond` | `value` | `SetMinValidatorBond` |
| `set_equivocation_slash_bps` | `value` | `SetEquivocationSlashBps` |
| `set_default_commission_bps` | `value` | `SetDefaultCommissionBps` |
| `set_block_reward` | `value` | `SetBlockReward` |
| `set_pmm_redemption_buffer_bps` | `value` | `SetPmmRedemptionBufferBps` |
| `set_governance_quorum_bps` | `value` | `SetGovernanceQuorumBps` |
| `signal` | `text` | `Signal(text)` |
| `register_oracle_publisher` | `publisher` (64 hex) | `RegisterOraclePublisher` |
| `unregister_oracle_publisher` | `publisher` (64 hex) | `UnregisterOraclePublisher` |
| `reset_oracle_breaker` | — | `ResetOracleBreaker` |
| `set_min_gas_limit` | `value` | `SetMinGasLimit` |
| `software_upgrade` (alias `upgrade`) | `name`, `height`, `sha256` | `SoftwareUpgrade{name,height,sha256}` |
| `cancel_upgrade` | — | `CancelUpgrade` |

`value` is an unsigned integer (JSON number or decimal string). There are **no
defaults**: a missing `value` is `-32602 "missing parameter 'value'"`.

Bounds (enforced on propose **and** execute):

- title ≤ 256 bytes; signal text ≤ 1024 bytes;
- `set_min_validator_bond` between `MIN_VALIDATOR_BOND` and 1,000,000 STELL;
- `set_block_reward` ≤ 10,000 STELL;
- bps actions ≤ 10,000; `set_governance_quorum_bps` between 3,333 and 10,000;
- `set_min_gas_limit` in `1..=10 × GAS_BASIC_TRANSFER`;
- oracle publisher key non-zero;
- `software_upgrade`: non-empty name ≤ 64 bytes, safe path segment (no `/`,
  no `..`), non-zero height, non-zero sha256;
- the proposer needs 10,000 STELL of stake (`PROPOSAL_MIN_STAKE_NANO`).

Voting is open for **3 days** (`GOVERNANCE_VOTING_PERIOD_SECS`). Quorum is
`quorum_bps = 6666` (2/3 of the frozen electorate); the floor is 3,333. A
passed action is timelocked for `GOV_TIMELOCK_HEIGHTS = 90_000` before it can
execute. `stell_executeProposal` has no proposer-only gate, so a lost proposer
key cannot brick execution.

::: warning Oracle actions fail closed at RPC execution
`register_oracle_publisher`, `unregister_oracle_publisher` and
`reset_oracle_breaker` can be proposed and voted on, but
`stell_executeProposal` calls `Governance::execute` **without** the oracle and
refuses them with `-32000 "execute failed: InvalidAction"`. They are applied by
the block-carried governance sweep (`execute_with_oracle`), which writes both
domains in one call.
:::

## Mempool, market and bridge

| Method | Params | Returns | Notes |
| --- | --- | --- | --- |
| `stell_mempoolSize` | — | number | same pool the proposer selects from |
| `stell_mempoolDump` | — | `[{sender,nonce,hash}]` | **token-gated, fail-closed**; disabled without `STELL_RPC_AUTH_TOKEN` |
| `stell_epochKey` | — | epoch public key + committee + commitment | wallet encrypts sealed txs to it; `-32010` before DKG completes |
| `stell_mevStats` | — | `{epoch,sealed,plain,sealed_share,unsealed,unseal_failures,…}` | operator view of the sealed path |
| `stell_getEpochRoot` | `{epoch}` / `{height}` / bare epoch | `{epoch,start_height,end_height,mmr_root,peaks,complete,leaves,committed_root,…}` | epoch MMR root over 128 finalized hashes |
| `stell_pmmState` | — | committed PMM curve | `governed_buffer_bps` read from governance |
| `stell_orderBook` | — or `{pair}` | committed book | pair default 1 = STELL/USDT; ≤20 levels/side |
| `stell_sessionBudget` | `{session}` or bare | budget object | committed registry; unknown key → `registered:false` |
| `stell_bridgeDeposit` | `{source_tx_hash}` or bare | deposit **record** | no record → `{found:false}`; the prepare is a different method |
| `stell_bridgeDispute` | `{dispute_id}` or bare | dispute record | unknown id → `{found:false}` |
| `stell_submitPriceFeed` | `{tx}` | tx hash | classical feed: the admission arm checks `verify()`, which is hardcoded false, so it admits nothing that can commit; use the PQ arm |
| `stell_submitPqPriceFeed` | `{tx}` | tx hash | PQ feed with a real Falcon verify; this is the path that commits |
| `stell_pmmBuy` / `stell_pmmSell` | `{tx}` | tx hash | thin admission; the swap applies in a block |
| `stell_sessionKeys` | `{master?}` | `{session_keys,count}` | committed registry |

These are **thin admission paths**. They decode and verify the wrapping
transaction, check that the payload carries the opcode the method name
promises, and admit it. They do not write state. A price, swap or order becomes
consensus state only when a proposer includes the transaction and every node
re-runs the opcode.

::: warning Naming collision, resolved
`stell_bridgeDeposit` answers the **record** and nothing else. The prepare is
`stell_bridgeDepositPrepare`. A call carrying prepare parameters
(`chain`, `recipient`, `amount`) to the record method is refused with `-32602`
and a pointer, never answered with `{"found":false}`.
:::

### Bridge windows and caps

| Rule | Value |
| --- | --- |
| Large-withdrawal timelock | `unlock_at = now + 3600` at or above 50,000 STELL |
| Hourly withdrawal rate | 500,000 STELL / rolling hour |
| Hourly deposit mint rate | 500,000 STELL / rolling hour |
| Cumulative mint cap | 100,000,000 STELL |
| Refund grace | `unlock_at + 24 h`, sender-only, unexecuted-only |
| Dispute window | 1 h past the challenge |
| Challenge age | deposits older than 24 h cannot be challenged |
| Challenge bond | `max(1 STELL, 1%)`; finder reward 10 % of the clawed-back deposit |
| TON finality | 12 masterchain confirmations |

## Smart contracts

| Method | Kind | Token | Params | Returns |
| --- | --- | --- | --- | --- |
| `stell_deployContract` | **preview only** | **always** | `{code,gas_limit?,abi?}` or `{tx}` | `{contract_address,contract_address_stl57,code_hash,tx_hash}` |
| `stell_callContract` | **preview only** | **always** | `{contract,method,args,value?,gas_limit?}` | `{tx_hash,status,return_value,gas_used,events,outcome}` |
| `stell_runGetMethod` | read | — | `{address,method,args?,fuel?,height?}` | `{success,return_value,return_typed,fuel_used,events,error,shard,local_shard,shard_is_local}` |
| `stell_getContractAbi` | read | — | `{contract}` | `{contract,contract_stl57,abi,abi_json}` |
| `stell_getContractReceipt` | read | — | bare hash or `{hash}` | contract-shaped receipt |
| `stell_verifyContractSource` | read | — | `{contract,source｜source_hex｜source_hash,compiler?,compiler_flags?}` | `{verified,onchain_code_hash,rebuilt_code_hash,source_hash,reason,…}` |
| `stell_getContractSource` | read | — | `{contract}` | fingerprint only; text lives in the indexer |
| `stell_registerContractSource` | signed write | — | `{contract,source_hash,signature}` | `{contract,source_hash,registered,verified}` |

`stell_deployContract` and `stell_callContract` **never admit** anything. They
predict against a clone and drop the transaction. `private_key` / `from` are
refused with `-32602`; sign locally and submit the sealed transaction through
`stell_sendRawTransaction`. Both require the auth token on every bind.

`stell_runGetMethod` is a true read: zero state changes, zero gas. Failures are
**answers**, not RPC errors: a missing address, a bad height or an ABI mismatch
returns `{"success":false,"error":"…","fuel_used":0}` with a 200 envelope. Its
fuel is clamped to `GET_METHOD_SAFETY_FUEL_LIMIT = 5,000,000`.

### ABI manifest

A contract may carry a typed ABI manifest committed to the state trie next to
its code hash (`sha256("STELL_CONTRACT_ABI" ‖ address)`). Supported types:
`i64`, `u64`, `i32`, `bool`, `bytes`, `address`, `string`.

Wire format (`STELL-ABI v1`):

```text
args_payload := u32_le(arg_count) ‖ arg_0 ‖ arg_1 ‖ …
arg_i        := u8(type_tag) ‖ value_payload
calldata     := u32_le(selector) ‖ args_payload
selector     := sha256(method_name)[0..4] as u32_le

I64 0x01: 8 B BE two's complement      U64 0x02: 8 B BE
I32 0x03: 4 B BE two's complement      Bool 0x04: 1 B (0/1)
Bytes 0x05: u32_le(len) ‖ bytes        Address 0x06: 32 raw bytes
String 0x07: u32_le(len) ‖ UTF-8
```

`stell_getContractAbi` returns both the parsed manifest and the raw
`abi_json` string, so a client can byte-compare it.

### Source verification trust model

`verified: true` proves the on-chain bytes are byte-identical to what **this
node's** `wat` pipeline produces from the submitted text with the claimed
flags, and that `source_hash` is the BLAKE3 of exactly that text. It does
**not** prove the source is safe, that it matches another compiler version, or
anything about past behavior. It is a transparency claim, not a safety
certificate.

## Native interface namespace

**One namespace, one shape per method.** Every method is a thin, fail-closed
wrapper over the state engine that already owns the state. No new state, no new
consensus rules.

- **Reads** answer from committed state and never invent a value.
- **Prepare** methods do **not** write. They answer with the exact transaction
  the wallet has to sign — opcode, arguments and gas — after checking the
  preconditions execution would check. The wallet signs and submits through
  `stell_sendRawTransaction`.
- **No method in this namespace is token-gated.**

Refusals: `-32602` invalid params, `-32004` unknown object, `-32003` committed
state refuses.

`stell_nativeApi` returns the manifest:
`{version,namespace,methods,method_count,conventions}`. `version` is
`"1.0.0"` and is bumped only when an existing answer shape changes.
The live manifest has **32 methods** (the older RPC.md says 35; the manifest
is authoritative).

### Token (NEP-141-like)

| Method | Kind | Params | Result |
| --- | --- | --- | --- |
| `stell_tokenTransfer` | prepare | `{token,from,to,amount}` | transfer to sign + balances/decimals/symbol |
| `stell_tokenBalanceOf` | read | `{token,account}` | full balance + metadata |
| `stell_tokenMetadata` | read | `{token}` | name, symbol, decimals, supply, minter, paused |
| `stell_tokenAllowance` | read | `{token,owner,spender}` | allowance |
| `stell_tokenMint` | prepare | `{token,to,amount,from?}` | mint to sign (minter only) |
| `stell_tokenBurn` | prepare | `{token,from,amount,signer?}` | burn; admin-burn via `signer` |
| `stell_tokenApprove` | prepare | `{token,owner,spender,amount}` | approval; amount 0 revokes |
| `stell_tokenTransferFrom` | prepare | `{token,from,to,amount,spender}` | delegated transfer |
| `stell_tokenCreate` | prepare | `{creator,name,symbol,decimals,initial_supply?,max_supply?}` | creation; caller becomes minter |

`from` may be spelled `owner`; mint’s `from` may be `minter`. Zero recipient,
self-transfer, zero amount, paused token and insufficient balance are `-32003`.
Token ids commit the registry nonce; resolve with `stell_tokenResolve` after
inclusion.

### Staking (NEP-171-like)

| Method | Kind | Params | Result |
| --- | --- | --- | --- |
| `stell_stakeBond` | prepare | `{validator,amount}` | self-bond/top-up + min bond |
| `stell_stakeUnbond` | prepare | `{validator,amount}` | unbond + cooldown |
| `stell_stakeWithdraw` | prepare | `{validator}` | matured self-bond withdrawal |
| `stell_delegate` | prepare | `{validator,amount,delegator?}` | delegation |
| `stell_undelegate` | prepare | `{validator,amount,delegator?}` | undelegation |
| `stell_claimRewards` | prepare | `{validator,role?,delegator?}` | validator or delegator claim |

A bond below the minimum, a delegation to a non-validator, or a withdrawal
before cooldown is `-32003`.

### Bridge (Teleport)

| Method | Kind | Params | Result |
| --- | --- | --- | --- |
| `stell_bridgeDepositPrepare` | prepare | `{chain,source_tx_hash,recipient,amount}` | deposit claim + asset |
| `stell_bridgeWithdraw` | prepare | `{chain,target_address,amount,sender?}` | withdrawal + escrow balance |
| `stell_bridgeStatus` | read | `{source_tx_hash}` or `{request_id}` | `{found,kind,…}` |
| `stell_bridgeAttestStatus` | read | `{source_tx_hash}` | attestations/required/remaining/status |
| `stell_bridgeReleaseEstimate` | read | `{request_id}` | `{found,unlock_at,refund_at,quorum_met,escrow_funded,missing}` |
| `stell_bridgeDeposits` | read | `{address,limit?}` | paginated deposit history |

`chain` is `ton`, `arbitrum`, `ethereum` or `solana` (case-insensitive). A
source transaction already credited is refused `-32003`: that is the replay
guard.

### Order book (CLOB)

| Method | Kind | Params | Result |
| --- | --- | --- | --- |
| `stell_orderBookPlace` | prepare | `{pair,side,price,amount,trader?}` | order to sign |
| `stell_orderBookCancel` | prepare | `{order_id,pair?,trader?}` | cancellation |
| `stell_placeOrder` | prepare | `{pair,side,price,amount,order_type?,trader?}` | one-call order; `pair` required |
| `stell_cancelOrder` | prepare | `{order_id,pair?,trader?}` | one-call cancel |
| `stell_orderBookSnapshot` | read | `{pair}` | `{pair,version,seq,best_bid,best_ask,bids,asks,next_order_id}` |

`pair` 1 = STELL/USDT, 2 = STELL/TON, 3 = STELL/GRAM. `side` is `buy`/`bid`
or `sell`/`ask`; zero price/amount is `-32003`. `order_type` defaults to
`limit`; `market` is refused. Only the placing trader may cancel.

Poll `version`, not `next_order_id`: cancels bump `version` but not the order
id. There is no streaming orderbook feed.

### Session keys

| Method | Kind | Params | Result |
| --- | --- | --- | --- |
| `stell_sessionKeyRegister` | prepare | `{session_pubkey,master,valid_until,max_gas_spend,scope,max_value_per_tx?}` | grant to sign + exact `grant_message` |
| `stell_sessionKeyRevoke` | prepare | `{session_pubkey,master?}` | revocation to sign |
| `stell_sessionKeys` | read | `{master?}` | committed registry |

See [Session keys](/sdk/session-keys).

### Oracle

| Method | Kind | Params | Result |
| --- | --- | --- | --- |
| `stell_oraclePrice` | read | `{asset}` | `{asset,price_micro_usd,timestamp,publisher,breaker_tripped}` |
| `stell_oracleFeeds` | read | `{asset?}` | `{feeds,count,publishers,breaker_tripped}` |

`price_micro_usd` is a decimal string. `breaker_tripped` is latched; only a
passed governance vote clears it.

## Subscriptions

| Method | Params | Returns |
| --- | --- | --- |
| `stell_subscribe` | topic string, object, or `[{…}]` | 32-hex subscription id |
| `stell_unsubscribe` | `{subscription}` / `params[0]` / bare | bool (idempotent) |
| `stell_getSubscriptions` | — | array of subscription records |

Topics: `newHeads`, `newTxs`, `invalidations`, `events` (with optional
`contract` and `topics` filters). Full transport behavior, limits and
reconnect guidance: [WebSocket and SSE](/api/websocket-sse).

## Wallet signing

| Method | Auth | Params |
| --- | --- | --- |
| `stell_signMessage` | token + loopback + dev key | `{message｜message_hex,chain_id?,token?}` |
| `stell_verifyMessage` | public | `{address,message｜message_hex,signature,chain_id?}` |
| `stell_signTypedData` | token + loopback + dev key | `{contract,method,args?,value?,nonce?,chain_id?,token?}` |
| `stell_verifyTypedData` | public | `{address,contract,method,args?,value?,nonce?,chain_id?,signature}` |

The sign arms use the **node's** key and are testing/devnet only. Production
wallets sign locally. The standard is documented in
[Wallet signing](/sdk/wallets-and-signing).

## EVM compatibility surface

All methods are live in the `POST /` dispatch and never mutate state, except
`eth_sendRawTransaction` (which admits through the same mempool gate). Unknown
selectors return `"0x"`; unknown block/tx hashes return `null`, never an
invented block.

| Method | Params | Result |
| --- | --- | --- |
| `eth_chainId` | — | `"0x167d"` |
| `net_version` | — | `"5757"` |
| `web3_clientVersion` | — | client string |
| `net_listening` | — | bool |
| `net_peerCount` | — | `"0x2"` (testnet-known default; no live peer table on this path) |
| `eth_syncing` | — | bool |
| `eth_gasPrice` | — | display-only hex |
| `eth_maxPriorityFeePerGas` | — | display-only hex |
| `eth_estimateGas` | `[{to,data,…}]` | `max(pure EVM, admission floor)` hex |
| `eth_feeHistory` | EIP-1559 params | fee history for the finalized head |
| `eth_getCode` | `[address,block]` | code or `"0x"` |
| `eth_getBalance` | `[address,block]` | `0x`-hex wei mapping |
| `eth_getTransactionCount` | `[address,block]` | nonce hex |
| `eth_blockNumber` | — | finalized height hex |
| `eth_getBlockByNumber` / `ByHash` | `[block/hash,full]` | block view or `null` |
| `eth_getTransactionReceipt` / `ByHash` | `[hash]` | receipt/tx view or `null` |
| `eth_getBlockTransactionCountBy…` | `[hash/block]` | count hex or `null` |
| `eth_getTransactionByBlock…AndIndex` | `[hash/block,index]` | tx view or `null` |
| `eth_getUncle*` | — | `"0x0"` / `null` (no uncles) |
| `eth_call` | `[{to,data},block]` | ERC-20 stub or `"0x"`; never executed |
| `eth_newBlockFilter` / `newPendingTransactionFilter` / `newFilter` | — / filter | filter id |
| `eth_getFilterChanges` / `getFilterLogs` | `[id]` | bounded results |
| `eth_uninstallFilter` | `[id]` | bool |
| `eth_getLogs` | filter | matching contract events (bounded) |
| `eth_getStorageAt` | `[address,slot,block]` | storage word hex |
| `eth_sendRawTransaction` | `[signed bytes]` | EVM keccak hash on admission |
| `stell_getEvmBinding` | `[address]` | binding record |
| `stell_evmBindingSubmit` | `{pqPublicKey,evmAddress,bindingSignature,evmSignature,txSignature,…}` | tx hash |
| `stell_evmCarrierSubmit` | `{raw evm bytes,pqPublicKey,intentSignature,txSignature,…}` | tx hash |

Filter ids are 64-bit random hex and expire after **300 s**
(`FILTER_TTL_SECS`). At most **10,000** live filters with **1,000** pending
entries each.

EVM write semantics: a bare EIP-155/1559 intent cannot move value. The EVM
address must be bound to a PQ account with a 65-byte secp256k1 proof of
possession, then settled by a `SysCallEvmCarrier` PQ1 transaction whose nonce
and value match the intent. Contract creation and calldata are refused because
there is no EVM interpreter or EVM state trie.

## Auth matrix

| Class | Methods | Behavior |
| --- | --- | --- |
| Open reads | almost all `stell_*` reads, `eth_*` reads, `stell_verify*` | no token |
| Open submission | `stell_sendRawTransaction`, `eth_sendRawTransaction` | no token; the signature authenticates |
| Token when configured | `stell_submitPriceFeed`, `stell_submitPqPriceFeed`, `stell_pmmBuy`, `stell_pmmSell` | open when `STELL_RPC_AUTH_TOKEN` unset, required when set |
| Fail-closed without token | `stell_mempoolDump`, `stell_signMessage`, `stell_signTypedData` | `-32001` even on loopback |
| **Always token** | `stell_submitProposal`, `stell_vote`, `stell_executeProposal`, `stell_deployContract`, `stell_callContract` | valid token on **every** bind, loopback included |
| Separate faucet token | `stell_faucet` | `STELL_FAUCET_TOKEN`; fail-closed if enabled without it |

Tokens are accepted as `params.token`, `params.apiKey` or an HTTP header.
Token comparison is constant-time.

## Twelve curl recipes

```bash
RPC=http://127.0.0.1:8545
rpc() { curl -s -X POST "$RPC" -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-\{\}}}"; }
```

### 1. Chain id

```bash
rpc stell_chainId
# {"jsonrpc":"2.0","id":1,"result":5757}
```

### 2. Finalized height

```bash
rpc stell_blockNumber
# {"result":"0x2a"}
```

### 3. State root (compare across nodes)

```bash
rpc stell_getStateRoot
# {"result":"<64 hex>"}
```

### 4. Account balance and nonce

```bash
rpc stell_getBalance '{"address":"<64 hex>"}'
# {"result":{"balance":"5000","nonce":2}}
```

### 5. Validator set and quorum

```bash
rpc stell_getValidators
# {"result":{"validators":[{"validator":"<64 hex>","power":"1"}],
#            "total_power":"2","quorum":"2","fragile":false,"fragile_reason":null}}
```

### 6. A block and its transactions

```bash
rpc stell_getBlock '{"height":42}'
rpc stell_getBlockTransactions '{"height":42}'
```

### 7. A receipt / status

```bash
rpc stell_getTransactionReceipt '"<64 hex tx hash>"'
rpc stell_getTransactionStatus '"<64 hex tx hash>"'
# {"result":{"status":"success","height":77,"confirmations":3}}
```

### 8. Submit a signed transaction

```bash
rpc stell_sendRawTransaction '{"tx":"<hex of bincode(Transaction)>"}'
# {"result":"<64 hex tx hash>"}
```

### 9. Estimate the fee

```bash
rpc stell_estimateFee '{"from":"<hex>","to":"<hex>","amount":1000}'
# {"result":{"gas_limit":1000,"estimated_fee":1000,"base_fee":1000,
#            "source_shard":0,"target_shard":1,"is_cross_shard":true,
#            "gas_budget":5000000,"gas_ceiling":5000000,"status":"ok"}}
```

### 10. Faucet drip (masterchain form)

```bash
rpc stell_faucet '{"address":"-1:<64 hex>","token":"<faucet token>"}'
# {"result":{"credited_nano":"2000000000","recipient":"<64 hex>",
#            "tx_hash":"<64 hex>","shard":0}}
```

### 11. Governance parameters and proposals

```bash
rpc stell_governanceParams
rpc stell_listProposals
rpc stell_proposal '{"id":0}'
```

### 12. Native namespace discovery and a read

```bash
rpc stell_nativeApi
rpc stell_tokenBalanceOf '{"token":"<64 hex>","account":"<64 hex>"}'
```

## Next

Continue with [WebSocket & SSE](/api/websocket-sse) for push notifications, or [Indexer REST](/api/indexer-rest) for historical queries. [Errors](/api/errors) explains every refusal code.
