---
title: Indexer REST
description: The stellereum-indexer REST v2 API — routes, pagination, health, SSE and documented limits.
outline: deep
---

# Indexer REST API

`stellereum-indexer` is a separate Rust service that syncs chain data into
SQLite (WAL) and serves a queryable HTTP API. It is what the explorer reads. It
is **not** consensus software and its answers are not proofs.

| | |
| --- | --- |
| Default bind | `0.0.0.0:8088` (`INDEXER_PORT`) |
| Database | `indexer.db` (`INDEXER_DB_PATH`), SQLite WAL |
| Node RPC | `INDEXER_RPC_URL`, default `http://127.0.0.1:8545` |
| Node gateway | `INDEXER_NODE_URL`, default `http://127.0.0.1:8080` |
| Verify endpoint | enabled only when `INDEXER_VERIFY_TOKEN` is set (default-deny) |
| CORS | permissive (`*`) |
| Version | `0.1.0-pq-fips206` |

::: danger Testnet software
No external audit. The indexer is a read surface and a convenience cache. Do not
treat a 200 from the indexer as a consensus proof; verify balances and state
roots against the node when money is involved.
:::

## Start

```bash
cd stellereum-indexer
cargo build --release

INDEXER_DB_PATH=/var/lib/stell/indexer.db \
INDEXER_RPC_URL=http://127.0.0.1:8545 \
INDEXER_NODE_URL=http://127.0.0.1:8080 \
INDEXER_PORT=8088 \
INDEXER_VERIFY_TOKEN=<long-random-token> \
./target/release/stellereum-indexer
```

The syncer starts in the background and fills the ABI cache from
`stell_getContractAbi`, so contract events can be decoded.

## Health and readiness

::: warning There is no `/health` or `/metrics` on the indexer
The indexer router exposes **no** `/health`, `/healthz`, `/readyz` or
`/metrics` route. Use `GET /api/v2/status` as its health/readiness probe.
Prometheus metrics (`/metrics`) and `/healthz` / `/readyz` belong to the
**node gateway** on `STELL_EXPLORER_LISTEN`; see
[Monitoring](/nodes/monitoring).
:::

`GET /api/v2/status` (alias `/api/status`) answers `200` with:

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

| Field | Meaning |
| --- | --- |
| `tip_height` | indexer's highest indexed block |
| `node_tip_height` | the node's tip at the last sync |
| `lag` | `node_tip_height - tip_height` |
| `synced` | `tip + 2 >= node_tip` **and** the last sync is fresh (≤60 s) |
| `last_sync_at` | Unix seconds of the last successful sync |
| `last_error` | last sync error, or `null` |

`ok:true` only means the process answers. Use `synced`, `lag` and
`last_sync_at` for readiness. A growing `lag` with a fresh `last_sync_at` means
the indexer is falling behind; a stale `last_sync_at` means it is stuck.

## Response conventions

- All routes are `GET` except
  `POST /api/v2/contract/:address/verify`.
- Success is `200` with a JSON object or array.
- Missing objects are `404` with `{"error":"…"}` (for example
  `{"error":"Block not found"}`).
- Bad input is `400` with `{"error":"…"}`.
- Internal failures are `500` with `{"error":"…"}`; internal details are not
  leaked beyond the message.
- `limit` is clamped to the route's maximum. An `offset` above **1,000,000** is
  refused with `400 {"error":"offset exceeds cap 1000000"}`.
- `cursor` and a non-zero `offset` cannot be combined
  (`400 {"error":"cannot combine cursor and nonzero offset"}`).

## Pagination

The v2 API uses **keyset cursors** for deep history. Offset pagination still
works for shallow pages, but cursors are stable under concurrent inserts.

| Parameter | Meaning |
| --- | --- |
| `limit` | page size; route maximum shown below |
| `offset` | shallow offset, `0..=1_000_000` |
| `cursor` | opaque keyset cursor from `next_cursor` |

Rules:

1. First request: omit both `cursor` and `offset` (or use `offset=0`).
2. Next page: send **only** `cursor=<next_cursor>`.
3. Stop when `next_cursor` is `null` or `has_more` is `false`.
4. Do not parse cursors; they are opaque and route-specific.

Page shape varies by route but always includes `limit`, `offset` (or 0),
`next_cursor` and usually `has_more`.

| Route family | Default | Max |
| --- | --- | --- |
| blocks, transactions, account actions | 50 | 200 |
| tokens, contracts | 50–100 | 200 |
| events | 100 | 200 |
| program accounts | 50 | 100 (16 with `with_proof`) |
| stream replay | — | 256 per attach burst |

## Routes

### Network and status

| Route | Returns |
| --- | --- |
| `GET /api/v2/overview` | explorer overview: supply, tx stats, network, ABI/event summary, latest events |
| `GET /api/v2/stats` | chain id, tip, shards, validator count, TPS, block tempo, totals |
| `GET /api/v2/price` | **presentation** price object (fixed testnet value) |
| `GET /api/v2/status` | health/sync status (above) |
| `GET /api/v2/stats/charts` | hourly/daily chart series |

::: warning Presentation data is not chain state
`/api/v2/price`, parts of `/api/v2/overview` (supply split, market cap), and
the `/api/v2/verified` catalog are **indexer presentation data**, some of it
hard-coded for the testnet explorer. They are not consensus values and must
not be used for accounting. Read balances, supply and validators from the node
RPC.
:::

### Blocks

| Route | Returns |
| --- | --- |
| `GET /api/v2/blocks?limit&offset&cursor&shard_id` | `{blocks,shard_id,limit,offset,next_cursor,has_more}` |
| `GET /api/v2/block/:param?shard_id` | `{block,transactions}` |

`:param` accepts:

- a decimal height (`194`);
- a block hash;
- a shard-qualified height (`1:194`).

Missing block → `404 {"error":"Block not found"}`.

### Transactions

| Route | Returns |
| --- | --- |
| `GET /api/v2/txs?limit&offset&cursor` | `{transactions,limit,offset,next_cursor,has_more}` |
| `GET /api/v2/tx/:hash` | `{transaction}` |

`:hash` accepts a 32-byte hex hash (with or without `0x`) and an EVM-format
hash. Missing → `404 {"error":"Transaction not found"}`.

### Accounts

| Route | Returns |
| --- | --- |
| `GET /api/v2/account/:address` | `{address,address_0x,stl57,tx_count,status}` |
| `GET /api/v2/account/:address/txs?limit&offset&cursor` | `{address,actions,transactions,limit,offset,next_cursor,has_more}` |
| `GET /api/v2/account/:address/tokens?token&include_zero&shard_id&limit&cursor` | token holdings with metadata |
| `GET /api/v2/token/:token/holders?include_zero&shard_id&limit&cursor` | holders page |

Addresses are normalized: 64-hex, `0x`-prefixed and `Stl57…` forms are
accepted.

### Tokens and contracts

| Route | Returns |
| --- | --- |
| `GET /api/v2/tokens?limit&offset&cursor` | native STELL plus `stell_listTokens` entries |
| `GET /api/v2/whales?limit&offset` | large-transfer list, as indexed |
| `GET /api/v2/contracts?limit&offset&cursor` | indexed contracts with `event_count`, `tx_count`, `first_block`, `last_block`, `events_url` |
| `GET /api/v2/program/:program/accounts?...` | bounded program-account page |
| `GET /api/v2/verified` | verified-contract catalog (presentation) |
| `GET /api/v2/verified/stats` | counts by language/category (presentation) |

`/api/v2/program/:program/accounts` accepts `program` in the path and filters:

```text
token, contract, owner, creator, min_balance,
slot_from, slot_to, with_proof, source, shard_id, limit, cursor
```

The unfiltered `system` dump is refused; supply a filter.

### Events

| Route | Returns |
| --- | --- |
| `GET /api/v2/contract/:address/events?from_block&to_block&limit&offset&cursor` | events of one contract |
| `GET /api/v2/tx/:hash/events` | events of one transaction |
| `GET /api/v2/events?from_block&to_block&contract&limit&offset&cursor` | filtered events |

Event shape:

```json
{
  "tx_hash": "<64 hex>",
  "block_height": 194,
  "log_index": 0,
  "contract": "<64 hex>",
  "contract_stl57": "Stl57…",
  "topic0": "<64 hex>",
  "topics": ["…"],
  "data": { },
  "event_name": "Transfer",
  "decoded": true,
  "args": { "topics": { }, "data": { } }
}
```

`decoded` is true when the ABI cache knows the contract; `args` is then the
named fields. Without an ABI, the raw `topics` and `data` are still returned.

### Search

`GET /api/v2/search?q=<term>` tries, in order:

1. shard-qualified height (`1:194`);
2. decimal height;
3. transaction hash;
4. block hash;
5. account address.

It returns one of:

```json
{"type":"block","result":{…}}
{"type":"transaction","result":{…}}
{"type":"account","address":"…","address_0x":"…","stl57":"…","tx_count":3}
```

or `404 {"error":"No match found"}`. A missing `q` is
`400 {"error":"missing query parameter 'q'"}`.

### Contract source verification

`POST /api/v2/contract/:address/verify` is **default-deny**: with
`INDEXER_VERIFY_TOKEN` unset, the route is disabled. When enabled, the request
must carry the token (for example `Authorization: Bearer <token>`). The body
contains the claimed source, compiler and flags; the indexer re-runs the
verification and stores the verified source.

`GET /api/v2/contract/:address/source` returns the verified source text. The
node stores only the fingerprint; the **text** lives here.

::: tip Trust model
Source verification proves the on-chain bytes match a rebuild of the submitted
text with the claimed compiler and flags. It does **not** prove the source is
safe or that it matches another compiler version. Read
[JSON-RPC § source verification](/api/json-rpc#source-verification-trust-model).
:::

### Shards

`GET /api/v2/shards?address=<address>` proxies the node's
`stell_getShardTopology` / `stell_getShards` and, when `address` is supplied,
adds which shard that address routes to. This is a **live proxy**, not a
historical index.

## SSE stream

`GET /api/v2/stream` is the indexer's own server-sent-events feed. It is a
higher-level feed than the node's `stell_subscribe` stream.

| Parameter | Meaning |
| --- | --- |
| `topics` (alias `kind`) | `newHeads,newTxs,events,invalidations`; default `newHeads` |
| `contract` | contract filter |
| `address` | address filter |
| `shard_id` | shard filter |
| `after_seq` | replay from this sequence number |

Limits:

| Bound | Value |
| --- | --- |
| Concurrent SSE clients | **256** (`MAX_INDEXER_SSE_CLIENTS`) |
| Broadcast capacity | **1024** |
| Replay window | **512** events |
| Replay burst per attach | **256** events |
| Idle timeout | **300 s** |

Replay semantics:

- `after_seq=N` replays events with `seq > N` that match the filter, up to 256.
- If `N` is older than the replay window, the server answers
  `410 {"error":"replay cursor expired; backfill via REST API","oldest_available_seq":M}`.
- If the live consumer lags out of the broadcast buffer, the server emits a
  `lagged` event with `{lagged,oldest_available_seq,action:"backfill_required"}`.

Example:

```bash
curl -N 'http://127.0.0.1:8088/api/v2/stream?topics=newHeads,events&contract=0x…&after_seq=0'
```

```ts
const es = new EventSource(
  "http://127.0.0.1:8088/api/v2/stream?topics=newHeads,newTxs",
);
es.onmessage = (e) => {
  const ev = JSON.parse(e.data); // { seq, topic, shard_id, height, payload, … }
  // Persist ev.seq as your cursor; reconnect with ?after_seq=ev.seq.
};
```

The stream is **best effort** across disconnects. Persist `seq` and backfill
through REST when the replay window has expired.

## Legacy aliases

The router mounts both the v2 paths and an older `/api/...` spelling of the
same handlers. They are aliases, not a second API:

| Legacy | v2 |
| --- | --- |
| `/api/overview`, `/api/stats`, `/api/price`, `/api/status` | `/api/v2/...` |
| `/api/blocks/latest` | `/api/v2/blocks` |
| `/api/blocks/:param` | `/api/v2/block/:param` |
| `/api/transactions/latest` | `/api/v2/txs` |
| `/api/transactions/:hash` | `/api/v2/tx/:hash` |
| `/api/accounts/:address` and `/actions` / `/activity` | `/api/v2/account/:address` and `/txs` |
| `/api/validators`, `/api/staking`, `/api/tokens`, `/api/whales`, `/api/shards` | `/api/v2/...` |
| `/api/verified`, `/api/verified/stats` | `/api/v2/...` |
| `/api/search` | `/api/v2/search` |

New clients should use `/api/v2/`. The aliases exist for the explorer and old
links.

## Error handling

| Status | Body | Cause |
| --- | --- | --- |
| `400` | `{"error":"…"}` | bad address/hash/cursor, `offset` too deep, cursor+offset |
| `404` | `{"error":"Block not found"}` etc. | object absent |
| `405` | — | non-GET on a GET route |
| `410` | `{"error":"replay cursor expired…"}` | SSE replay too old |
| `500` | `{"error":"…"}` | database/indexer failure |
| `503` | `{"error":"stream client limit reached",…}` | too many SSE clients |
| `503` | `{"error":"live validator set is not available from node RPC",…}` | node RPC down for `/validators` or `/staking` |

Retry `500`/`503` with backoff. Do not retry `400`/`404`; fix the request.

## Validators and staking

`GET /api/v2/validators` and `GET /api/v2/staking` are **live proxies** to the
node's `stell_getValidators`, not historical indexer tables. They return `503`
when the node RPC is unreachable. Fields such as `apy`, `uptime`,
`commission_bps` and stake limits in this response are presentation defaults,
not chain values; read `stell_stakeOf` and `stell_getValidatorStatus` for the
committed answer.

## Limits

- The indexer is a cache. It can lag, miss an event, or serve a stale page
  during re-sync.
- It is not a light client and verifies no proofs.
- It does not expose Prometheus metrics or `/health*`; use
  `/api/v2/status` and the node gateway.
- Some explorer fields are hard-coded presentation data.
- `/api/v2/verify` is disabled unless explicitly enabled with a token.
- Deep history depends on the indexer's retention, not the node's.
- No WebSocket transport; SSE only.
- No authentication on reads. Do not expose it publicly without a proxy.

## Next

For consensus-grade reads, use [JSON-RPC](/api/json-rpc). For push notifications straight from the node, use [WebSocket & SSE](/api/websocket-sse).
