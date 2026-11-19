# Concepts

## Accounts and addresses

An account is a 32-byte key with `balance (u64 nano-STELL) ‖ nonce`
committed in the Patricia trie (`PROTOCOL.md` §1.1). 1 STELL =
1 000 000 000 nano-STELL (9 decimals). A missing account reads as
`{"balance":"0","nonce":0}` — absence is indistinguishable from empty
(`docs/RPC.md` §3, `stell_getBalance`).

Three spellings, one key (`src/address.rs`):

| Form | Example | Notes |
| --- | --- | --- |
| raw/hex | `1e6281…8920a` (`0x` optional) | what RPC takes everywhere |
| branded | `Stl57…` (also `stl57…`, `STL57…`) | Base58 + 4-byte BLAKE3 checksum (`STELLEREUM_ADDRESS_CHECKSUM_V1`); typo-detecting, homoglyph-rejecting |
| EVM-compat | `0x…` 20-byte via adapter | EVM JSON-RPC served (`eth_chainId` = `0x167d` = 5757); value transfers need a PQ binding + carrier, calldata/contract calls are **not executed** (see “EVM compatibility” below) |

`Stl57` = Stellereum L1, chain id 5757 (`src/address.rs:4`). RPC accepts
hex and `Stl57` for proofs; receipts carry both (`contract_address` +
`contract_address_stl57`).

## EVM compatibility (MetaMask)

A secp256k1 signature is **never** a consensus credential here. The EVM
write path is a two-part PQ statement:

1. **Binding** — `SysCallBindEvmAddress` records `EVM address (20) → PQ
   account (32)`, Falcon-signed by the PQ key over
   `keccak256("STELL_EVM_BIND_V1" || chain_id || evm || pq)`.
2. **Carrier** — a normal PQ1 transaction whose `SysCallEvmCarrier` payload
   carries the canonical EIP-155/EIP-1559 bytes, the bound Falcon key, and
   that key's signature over `keccak256(evm_tx)`. `tx.from` is the bound PQ
   account, `tx.to` the recipient's bound PQ account, `tx.amount` the value
   in nano-STELL, and `tx.nonce` the EVM nonce. Both Falcon statements must
   verify; the secp256k1 signature inside the EVM bytes is advisory (routing
   and UI only).

What MetaMask can do: add the chain (`eth_chainId` 5757), read balances and
nonces (a bound 20-byte address resolves to its PQ account), and track a
value transfer once a wallet supplies the Falcon carrier signatures via the
optional `carrier` parameter on `eth_sendRawTransaction` (or
`stell_evmCarrierSubmit`). What it cannot do: move value on its own (no
binding = honest `full-pq-admission` refusal), deploy a contract, or call
contract bytecode — contract creation and any calldata are refused with
`evm-contract-execution-unsupported` because there is no EVM interpreter or
EVM state trie. Use the native SVM (`stell_deployContract` /
`stell_callContract`) for contracts.

Honest limitations: the binding is a PQ-signed routing statement, **not** a
proof of possession of the EVM (secp256k1) key — first claim wins, so an
unbound address can be claimed by any PQ key (a naming/hijack grief, reviewed
as C1 in `docs/PENTEST2_API.md`). The binding index is a node-local
routing/replay index, **not** part of the state root, and it is process-local:
this wave does not
wire a bootstrap replay from committed blocks, so a restarted node starts with
an empty index until bindings are re-observed (balances can under-report and a
carrier can be refused until then). Consensus re-checks the pure signatures at
execution, so a stale or empty index can change admission/routing and what
`eth_getBalance` reports, never whether money moves. The EVM gas field is only
a resource cap; admission prices the carrier separately
(`EVM_CARRIER_SURCHARGE_GAS = 30_000` on top of the base/PQ-activation floor),
while execution charges the Stell gas schedule, not EVM gas. The 30k surcharge
is an **admission floor**, not a separate execution debit.

## Shards and the routing rule

One rule, one implementation (`sharding::route_shard`, `src/sharding.rs`;
published as `ROUTING_RULE`, id `workchain-prefix-v1`):

- Shard **0 is the masterchain**, addressed **explicitly** TON-style:
  `-1:<addr>` (or `0:<addr>`). **A bare 32-byte address never routes to
  the masterchain** — it is a workchain address.
- A workchain address routes to the shard whose routing prefix (top
  `prefix_len` bits of the first 8 bytes, TON definition) is the
  **longest match**; ties break by **smallest shard id**.
- A split grows the prefix by exactly one bit; a merge removes the
  deepest bit. Shard ids are never reused.

Examples (`docs/SHARDING.md` §1.2): one workchain shard (prefix_len 0)
matches everything; after a split, `address[0] < 0x80` → child 0,
`>= 0x80` → child 1. Published thresholds: `MIN_ACCOUNTS_PER_SHARD=100`,
`MAX_SHARDS=16` (shipped cap), `MAX_PREFIX_BITS=60` (advertised space
2⁶⁰ — address space, not capacity), split at load 500, merge at combined
load ≤ 50. Chain id default **5757** (`zkml::DEFAULT_CHAIN_ID`;
`EVM_CHAIN_ID` asserts equal to the EVM adapter constant).

- TODO (live split): no split has ever run on a live network
  (`SHARDING.md` §0). Verify: `cargo test --test sharding_topology_tests`.

## Transaction lifecycle

`build → simulate → submit → receipt → finality`:

1. **Build:** `{from,to,amount,gas_limit,nonce,source_shard,target_shard,
   signature,payload}`; signature covers the payload
   (`docs/RPC.md` §4). Nonce must be contiguous per sender; far-future
   nonces (gap > 16) are refused at admission.
2. **Simulate:** `stell_estimateFee` (floor-aware; reports `target_shard`)
   and `eth_estimateGas` = `max(pure EVM figure, live admission floor)`.
3. **Submit:** `stell_sendRawTransaction {"tx":"<hex of bincode>"}` —
   open submission by design; admission checks signature, base fee,
   `amount+gas_limit` solvency, duplicates, per-sender quota (1024) and
   pool cap (50 000). Blocks hold ≤ 10 000 txs and ≤ 500 000 000 gas
   (`src/runtime.rs:28,52`).
4. **Receipt:** `stell_getTransactionReceipt` → `success|failed` (+height,
   `fee_charged`, `return_value`, `gas_used`, `events`) or
   `pending|unknown` (this node's mempool only). Verdicts are recorded at
   apply time, never recomputed (`PROTOCOL.md` I8).
5. **Finality:** precommit quorum `floor(2·power/3)+1` in one block —
   **one confirmation is final**; finalized blocks never roll back.

## Fees

Floor = `max(STELL_MIN_GAS_LIMIT env, governed min_gas_limit)`; the same
consensus floor prices admission and proposal validation so they cannot
drift (`PROTOCOL.md` §4c). Pinned gas costs (`src/svm.rs`):

| Op | Cost (nano-STELL gas units) |
| --- | --- |
| basic transfer | **280 000** (`GAS_BASIC_TRANSFER`) |
| order place / cancel | 1 200 / **100** |
| contract call / +per arg | 1 000 / 10 |
| contract deploy | 2 000 + 2/byte |
| stake bond / unbond / claim | 2 000 / 800 / 600 |

Failure fee (F-01, `PROTOCOL.md` §4c): refused at admission → pays
nothing; replay/nonce-gap → nothing (not attributable); attributable
failure the sender can cover → `max(gas_limit, floor)+surcharge` **and
nonce +1**; attributable failure it cannot cover → nothing moves at all
(no-pay-no-state-change).

## Finality, confirmations, invalidations

Single-block BFT finality: a block carrying a precommit quorum is final.
"N confirmations" = N finalized blocks on top — depth against operational
risk (stale reads, lagging indexer), not reorg safety. Floors
(`docs/RPC.md` §4): dust 1 · ordinary payments 2–3 · large/bridge 10+ with
a two-node `stell_getStateRoot` match · custodian crediting 30+ with a
second-node receipt check. Candidate branches that lose fork-choice are
reported via `stell_getInvalidations` (64-entry rolling window,
`MAX_INVALIDATION_WINDOW`) and the `invalidations` push topic — re-sync
consumers from the reported height. Poll status with
`stell_getTransactionStatus`; `pending → unknown` means "left this node's
mempool unincluded", not "failed" — re-submit.
