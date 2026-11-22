# stellereum-indexer

Rust indexer for Stellereum: syncs chain data into SQLite (WAL) and serves a
paginated REST v2 API plus an SSE stream for blocks, transactions, accounts,
tokens, contracts, events, validators, and shard topology.

[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-orange)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-blue)](Cargo.toml)
[![Network](https://img.shields.io/badge/network-testnet-yellow)](https://docs.stellereum.org/get-started/networks)
[![Audit](https://img.shields.io/badge/audit-none%20yet-red)](https://docs.stellereum.org/security/status)

## What it is / what it is not

- **Is** a read-optimized cache: a background syncer writes blocks, transactions,
  token balances, contracts, and decoded events into SQLite, and Axum serves
  explorer-friendly pages over them.
- **Is** multi-shard aware at the schema level: the sharded chain tables
  (`blocks`, `transactions`, `contract_events`, `token_balances`, `contracts`)
  carry `shard_id`, and the local shard is fully indexed. Non-local shards
  currently get **header-only** coverage — the committed head is recorded, but
  their transactions and events are not backfilled.
- **Is not** consensus software and proves nothing. A `200` from the indexer is
  not a consensus proof; verify money-relevant state against the node.
- **Is not** an authenticated public service. Reads have no auth, CORS is
  permissive, and the HTTP server binds `0.0.0.0:8088`; put it behind a proxy
  before exposing it.
- **Is not** a WebSocket or Prometheus service. It exposes SSE only and has
  **no** `/health`, `/healthz`, `/readyz`, or `/metrics` route.

## Install and build

```bash
cd stellereum-indexer

cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

The crate depends on the in-tree node crate for shared chain types, so a clean
build compiles the node library. There is no separate configuration file; all
runtime settings are environment variables.

## Quickstart

### Run next to a node

The indexer expects a local node with the default endpoints:

- JSON-RPC: `http://127.0.0.1:8545` (`STELL_RPC_LISTEN`)
- explorer/HTTP gateway: `http://127.0.0.1:8080` (`STELL_EXPLORER_LISTEN`),
  which serves `/api/blocks` and `/events`

Start the node first, then:

```bash
cd stellereum-indexer

INDEXER_DB_PATH=./indexer.db \
INDEXER_NODE_URL=http://127.0.0.1:8080 \
INDEXER_RPC_URL=http://127.0.0.1:8545 \
INDEXER_PORT=8088 \
./target/release/stellereum-indexer
```

The syncer starts in the background. On an empty database it backfills the
local shard from height 0 in bounded batches (64 blocks per tick, 8 concurrent
fetches), then follows the node's SSE feed with an HTTP backfill fallback.

### Query it

```bash
curl -s http://127.0.0.1:8088/api/v2/status
curl -s 'http://127.0.0.1:8088/api/v2/blocks?limit=2'
curl -s 'http://127.0.0.1:8088/api/v2/account/<address>/txs?limit=10'
```

`/api/v2/status` is the readiness probe:

```json
{
  "ok": true,
  "chain_id": 5757,
  "tip_height": 194,
  "node_tip_height": 195,
  "lag": 1,
  "synced": true,
  "last_sync_at": 1758800000,
  "last_error": null,
  "version": "0.1.0-pq-fips206",
  "time": 1758800002
}
```

`synced` means the indexed tip is within two blocks of the node tip **and** the
last successful sync is no older than 60 seconds. `ok: true` alone only means
the process answers.

### SSE

```bash
curl -N 'http://127.0.0.1:8088/api/v2/stream?topics=newHeads,newTxs,events'
```

The stream is server-sent events only. Persist each event's `seq` and reconnect
with `?after_seq=<seq>`; if the cursor is older than the replay window the
server answers `410` and you must backfill through REST.

## Storage

SQLite is opened in WAL mode with `synchronous = NORMAL` and
`foreign_keys = ON`. The schema is created and migrated in `src/db.rs`:

| Table | Contents |
| --- | --- |
| `blocks` | One row per `(shard_id, height)`: hash, timestamp, tx count, proposer, state root. |
| `transactions` | Transactions keyed by hash, with shard, block height/index, from/to, amount, fee, gas, status. |
| `accounts` | Address activity counters (`tx_count`, first/last seen height). |
| `contract_events` | Raw topics/data plus ABI-decoded `event_name` and `decoded_json`. |
| `verified_contract_sources` | Source text stored only after the node confirms a rebuild. |
| `token_balances` | STS-20-style balances keyed by `(shard_id, token_id, owner)`. |
| `contracts` | Deployed WASM contracts with creator, code hash, deploy height, ABI flag. |

The database is a cache. Deleting it and resyncing is safe; it is not the
source of truth and has no consensus role.

## API surface

All routes are `GET` except the contract-source verification POST. Canonical
routes are under `/api/v2`; legacy `/api/...` aliases exist for explorer
compatibility. `limit` is clamped to the route maximum, `offset` is capped at
`1_000_000`, and `cursor` cannot be combined with a non-zero `offset`.

### Network and status

| Route | Description |
| --- | --- |
| `GET /api/v2/overview` | Explorer overview: supply split, transaction stats, network summary, latest events. Presentation data in part. |
| `GET /api/v2/stats` | Chain id, tip, shard count, validator count, TPS, block time, totals. |
| `GET /api/v2/price` | Fixed testnet presentation price; not a chain value. |
| `GET /api/v2/status` | Health/readiness (`tip_height`, `lag`, `synced`, `last_error`). |
| `GET /api/v2/stats/charts` | Hourly and daily chart series. |

### Blocks and transactions

| Route | Description |
| --- | --- |
| `GET /api/v2/blocks?limit&offset&cursor&shard_id` | Paginated block summaries; keyset cursor for deep history. |
| `GET /api/v2/block/:param?shard_id` | Block by decimal height, block hash, or `shard:height`; includes transactions. |
| `GET /api/v2/txs?limit&offset&cursor` | Recent transactions. |
| `GET /api/v2/tx/:hash` | One transaction by 32-byte hash (hex or `0x`-hex). |

### Accounts and tokens

| Route | Description |
| --- | --- |
| `GET /api/v2/account/:address` | Address summary (`address`, `address_0x`, `stl57`, tx count, status). |
| `GET /api/v2/account/:address/txs?limit&offset&cursor` | Address transaction history. |
| `GET /api/v2/account/:address/tokens?token&include_zero&shard_id&limit&cursor` | Token holdings with metadata. |
| `GET /api/v2/token/:token/holders?include_zero&shard_id&limit&cursor` | Holder page for one token. |
| `GET /api/v2/tokens?limit&offset&cursor` | Native STELL plus indexed/listed tokens. |
| `GET /api/v2/whales` | Top active addresses derived from indexed transactions. |

### Contracts and events

| Route | Description |
| --- | --- |
| `GET /api/v2/contracts?limit&offset&cursor` | Indexed contracts with event/tx counts and an `events_url`. |
| `GET /api/v2/program/:program/accounts?...` | Bounded program-account page; filters include token, owner, creator, balance, slots, shard, and proofs. |
| `GET /api/v2/contract/:address/events?from_block&to_block&limit&offset&cursor` | Events emitted by one contract. |
| `GET /api/v2/tx/:hash/events` | Events emitted by one transaction. |
| `GET /api/v2/events?from_block&to_block&contract&limit&offset&cursor` | Filtered event feed. |
| `POST /api/v2/contract/:address/verify` | Verify contract source; disabled unless `INDEXER_VERIFY_TOKEN` is set. |
| `GET /api/v2/contract/:address/source` | Verified source text. |
| `GET /api/v2/verified` | Static verified-contract catalogue (presentation data). |
| `GET /api/v2/verified/stats` | Static verified counts by language/category (presentation data). |

### Live proxies, search and stream

| Route | Description |
| --- | --- |
| `GET /api/v2/shards?address=` | Proxies the node's `stell_getShards` and merges indexed shard stats; optionally routes an address. |
| `GET /api/v2/validators` | Live proxy to `stell_getValidators`; `503` if the node RPC is down. |
| `GET /api/v2/staking` | Staking summary derived from the live validator set; presentation fields are defaults. |
| `GET /api/v2/search?q=` | Tries shard-qualified height, height, tx hash, block hash, then address. |
| `GET /api/v2/stream` | SSE feed: `topics`/`kind`, `contract`, `address`, `shard_id`, `after_seq`. |

SSE bounds: 256 concurrent clients, broadcast capacity 1024, replay window 512
events, at most 256 replayed events per attach, and a 300-second idle timeout.
A client over the limit gets `503`; a replay cursor older than the window gets
`410`.

## Configuration

| Environment variable | Default | Description |
| --- | --- | --- |
| `INDEXER_DB_PATH` | `indexer.db` | SQLite database path (relative to the working directory). |
| `INDEXER_NODE_URL` | `http://127.0.0.1:8080` | Node explorer/HTTP gateway; used for `/api/blocks` and `/events`. |
| `INDEXER_RPC_URL` | `http://127.0.0.1:8545` | Node JSON-RPC; used for shards, blocks, receipts, ABIs, and live proxies. |
| `INDEXER_PORT` | `8088` | HTTP listen port; binds `0.0.0.0`. |
| `INDEXER_VERIFY_TOKEN` | unset | When set, enables `POST /api/v2/contract/:address/verify` and requires the token. Unset means default-deny. |

There is no `INDEXER_RPC_AUTH_TOKEN`; the indexer does not add a bearer token to
node RPC calls. Keep the node RPC on loopback or front it with a proxy.

## Testing

```bash
cd stellereum-indexer

cargo test
cargo clippy --all-targets -- -D warnings
```

The suite covers the SQLite lifecycle/WAL mode, pagination and keyset cursors,
injection and deep-offset refusals, reorg replacement/cleanup, SSE filtering and
replay, and concurrent read hammering. It is an independent test process and
does not use the node crate's serial-lib wrapper; it can run alongside other
workspace suites.

## Documentation

- [Indexer REST reference](https://docs.stellereum.org/api/indexer-rest)
- [JSON-RPC reference](https://docs.stellereum.org/api/json-rpc)
- [WebSocket and SSE](https://docs.stellereum.org/api/websocket-sse)
- [Monitoring](https://docs.stellereum.org/nodes/monitoring)
- [Security policy](SECURITY.md)
- [License](LICENSE) — MIT OR Apache-2.0
  ([MIT](LICENSE-MIT), [Apache-2.0](LICENSE-APACHE))

## Status

Testnet only. No external audit. The indexer is a convenience cache, not a
proof system, and some explorer fields (price, parts of overview/verified) are
presentation data.

Known limits today:

- Non-local shards are header-only: the committed head is recorded, but their
  transactions and events are not indexed. With a two-shard node, shard 1 is
  header-only in the indexer.
- No `/health`, `/healthz`, `/readyz`, or `/metrics` route. Use
  `/api/v2/status` for readiness; node-gateway monitoring is a separate service.
- No WebSocket transport and no read authentication.

Before public exposure: an external audit, an authenticating/rate-limiting
proxy, and an explicit retention policy for the SQLite cache.
