---
title: WebSocket and SSE
description: Push notifications from the node — stell_subscribe, topics, transports, limits and reconnect.
outline: deep
---

# WebSocket and SSE

The node can **push** notifications instead of making a client poll. Two
transports carry the same notification stream:

| Transport | Endpoint | Method | Notes |
| --- | --- | --- | --- |
| WebSocket | `GET /ws` on `STELL_RPC_LISTEN` (default `127.0.0.1:8545`) | HTTP upgrade | JSON-RPC **in**, notifications **out**. The socket speaks the same dialect as HTTP, so any method can be called over it, including `stell_subscribe`. |
| SSE | `GET /events` on the RPC listener **and** on the gateway (`STELL_EXPLORER_LISTEN`, default `127.0.0.1:8080`) | HTTP GET | `text/event-stream`; the fallback for a browser that cannot open a WebSocket. |

Both are served by the same router as the JSON-RPC endpoint. The gateway mounts
the same SSE handler on `/events`, so a browser can `new EventSource("/events")`.

::: warning There is no `eth_subscribe`
The node refuses `eth_subscribe`. Use `stell_subscribe` on one of these two
transports. The TypeScript SDK does not implement the framing; use a raw
WebSocket/EventSource.
:::

## Topics

| Topic | Aliases | Payload |
| --- | --- | --- |
| `newHeads` | `new_heads`, `heads` | a newly finalized head of **this node's** chain |
| `newTxs` | `new_txs`, `transactions` | the transactions included in a finalized block |
| `invalidations` | `invalidation`, `reorgs` | a block-invalidation signal (blocks this node announced and could not keep) |
| `events` | `logs`, `contractEvents` | a contract event, optionally filtered by contract and topic |

The `events` topic accepts a filter object:

```json
{"type":"events","contract":"<64 hex>","topics":["Transfer","0xabc…"]}
```

- `contract` is the canonical 32-byte hex; omitted = all contracts.
- `topics` is a list of event topic ids or names; empty = all.
- Filters compare **byte-exact** against emitted events.

`invalidations` is the push side of `stell_getInvalidations`. The blocks it
names were **never applied** (BFT finality forbids rolling back an applied
block). The signal means “that block you were told about is not on the chain”.
Re-sync consumers from the lowest orphaned height.

## `stell_subscribe`

Register a subscription and get its id. Three parameter forms are accepted:

```json
{"jsonrpc":"2.0","id":1,"method":"stell_subscribe","params":["newHeads"]}
{"jsonrpc":"2.0","id":1,"method":"stell_subscribe","params":{"type":"events","contract":"<64 hex>"}}
{"jsonrpc":"2.0","id":1,"method":"stell_subscribe","params":"newTxs"}
```

```json
{"jsonrpc":"2.0","id":1,"result":"<32 hex chars>"}
```

The id is **16 random bytes, hex-encoded** (32 characters). Unknown topic →
`-32602 "unknown subscription type: <x>"`; missing topic →
`-32602 "missing subscription type"`.

::: tip You can create a subscription over plain HTTP
`stell_subscribe` returns the id over `POST /`, then attach that id to an SSE
stream with `?sub_id=…`. The subscription exists before a transport is
attached, and survives the stream closing (it is only *detached*).
:::

## Bounds (DoS limits)

| Bound | Value |
| --- | --- |
| Live subscriptions per node | **4096** (`MAX_SUBSCRIPTIONS`) |
| Live subscriptions per client (IP) | **64** (`MAX_SUBSCRIPTIONS_PER_CLIENT`) |
| Lifetime of a detached subscription | **3600 s** (`SUBSCRIPTION_TTL_SECS`) |
| In-process fan-out capacity | **1024** notifications |

Exceeding the global cap is
`-32000 "subscription limit reached (4096 live subscriptions)"`. Exceeding the
per-client cap is
`-32000 "per-client subscription limit reached (64 live subscriptions for this client)"`.

The per-client cap exists because the global cap is global: without it one
client could take the whole registry and deny service to every other
subscriber.

## Notification shape

Both transports emit exactly the same object:

```json
{"subscription":"<32 hex>","result":{ … }}
```

- WebSocket: one JSON text frame per notification.
- SSE: `data: {"subscription":"…","result":{…}}\n\n`, with a **15-second**
  keep-alive comment.

Example `newHeads`:

```json
{"subscription":"9f2c…","result":{
  "height":194,
  "hash":"<64 hex>",
  "shard_id":0,
  "tx_count":3,
  "timestamp":1758800000,
  "finality":"finalized",
  "prev_hash":"<64 hex>",
  "state_root":"<64 hex>",
  "proposer":"<64 hex>"
}}
```

`prev_hash`, `state_root` and `proposer` are `null` only when this node has no
quorum-certified header for that height — an explicit “not available”, never a
fabricated root.

Example `events`:

```json
{"subscription":"1a77…","result":{
  "contract":"<64 hex>",
  "topics":["Transfer"],
  "data":"00000000000003e8",
  "block_height":194,
  "tx_hash":"<64 hex>"
}}
```

`topics` contains the event topic ids/names the chain emitted (the filter
matches byte-exact against them); `data` is the payload as hex. The richer
decoded event shape is the indexer's job (see
[Indexer REST](/api/indexer-rest#events)), not the node notification.

Delivery is **best effort**. A transport that is not attached, or that lags
behind the in-process fan-out (capacity 1024), simply misses the notification.
The publisher never blocks on a slow subscriber.

::: danger A subscriber that must not miss anything has to re-check
After any gap, reconnect or suspected lag, call `stell_blockNumber` and
`stell_getStateRoot` and re-sync from the last height you fully processed.
Notifications are a latency optimization, not a durable log.
:::

## `stell_unsubscribe`

```json
{"jsonrpc":"2.0","id":1,"method":"stell_unsubscribe","params":{"subscription":"<32 hex>"}}
```

```json
{"jsonrpc":"2.0","id":1,"result":true}
```

`true` when the subscription existed, `false` when the id was unknown —
idempotent, like `eth_uninstallFilter`. A missing id is
`-32602 "missing subscription id"`.

## `stell_getSubscriptions`

```json
{"jsonrpc":"2.0","id":1,"method":"stell_getSubscriptions","params":{}}
```

```json
{"result":[
  {"id":"<32 hex>","topic":{"type":"newHeads"},"created_at":1758800000,
   "attached":true,"client":"203.0.113.7"}
]}
```

- `topic` is tagged: `{"type":"newHeads"}`, `{"type":"newTxs"}`,
  `{"type":"invalidations"}` or
  `{"type":"events","contract":"…","topics":[…]}`.
- `attached` is true while a transport is streaming it; attached
  subscriptions are not swept by the TTL.
- `client` is the creating IP when the transport could attribute it.

## SSE in detail

`GET /events` accepts query parameters:

| Parameter | Meaning |
| --- | --- |
| `sub_id` | serve an **existing** subscription. `404` when unknown. |
| `topics` | create subscriptions to serve: `newHeads,newTxs,invalidations,events` (comma separated). Defaults to `newHeads`. |
| `contract` | contract filter for the `events` topic |
| `event_topics` | topic filter for the `events` topic |

The ids the stream serves are returned in the `x-stell-subscription-id`
response header (comma separated).

Lifecycle:

- a subscription **created by the stream** is removed when the stream closes;
- one attached through `sub_id` is only **detached** and keeps existing until
  its TTL expires.

### curl

```bash
curl -N 'http://127.0.0.1:8545/events?topics=newHeads,newTxs'
```

```text
: keep-alive

data: {"subscription":"9f2c…","result":{"height":194,…}}

: keep-alive
```

### Browser

```ts
const es = new EventSource("http://127.0.0.1:8080/events?topics=newHeads,events&contract=0x…");

es.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  console.log(msg.subscription, msg.result);
};

es.onerror = () => {
  // EventSource reconnects automatically, but a NEW stream creates NEW
  // subscriptions. Re-subscribe explicitly if you need stable ids.
};
```

::: warning EventSource reconnect creates new subscriptions
A stream-created subscription dies with the stream. If you rely on a stable id
across reconnects, create it first with `stell_subscribe` and attach it with
`?sub_id=…`; the id then survives the disconnect (detached, TTL 3600 s).
:::

## WebSocket in detail

`GET /ws` upgrades to a WebSocket. The upgrade request's credentials are
honoured exactly like the HTTP endpoint: the API token in headers gates the
same methods and the peer address feeds the per-IP limits. **A WebSocket must
never be a way around the auth gate.**

A subscription created on a socket is pushed to that socket and **dies with
it**: when the connection closes, every subscription it created is removed.

### `websocat`

```bash
websocat ws://127.0.0.1:8545/ws
```

Then send:

```json
{"jsonrpc":"2.0","id":1,"method":"stell_subscribe","params":["newHeads"]}
```

### Browser

```ts
const ws = new WebSocket("ws://127.0.0.1:8545/ws");

ws.onopen = () => {
  ws.send(JSON.stringify({
    jsonrpc: "2.0", id: 1,
    method: "stell_subscribe", params: ["newHeads"],
  }));
};

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.id === 1) {
    console.log("subscription id", msg.result);
    return;
  }
  console.log("head", msg.result.height);
};
```

## Reconnect strategy

Because delivery is best effort and subscriptions are transport-scoped, a
correct client keeps its own cursor.

```ts
type Cursor = { height: number; stateRoot: string | null };

async function onHead(result: any, cursor: Cursor, rpc: (m: string, p?: any) => Promise<any>) {
  if (result.height > cursor.height + 1) {
    // Gap: the socket missed at least one head, or we were disconnected.
    const head = await rpc("stell_blockNumber");
    const root = await rpc("stell_getStateRoot");
    console.warn("gap", cursor.height, "->", parseInt(head, 16));
    // Re-sync blocks/receipts from cursor.height + 1, then continue.
    cursor.stateRoot = root;
  }
  cursor.height = result.height;
}
```

Recommended policy:

1. **Persist** the last fully processed height and its state root.
2. On connect, subscribe, then call `stell_blockNumber` and
   `stell_getStateRoot`. If the height jumped past your cursor, backfill from
   REST/`stell_getBlockTransactions` or the indexer before trusting the stream.
3. Treat a **height decrease** or a **state-root change at the same height** as
   a fault: stop, compare against a second node, and re-sync. Finalized blocks
   do not reorg; a different root at the same height is a split or a bad node.
4. On `invalidations`, re-sync from the lowest orphaned height. These blocks
   were candidates, never applied.
5. On `-32000` subscription-limit errors, close idle sockets and unsubscribe
   what you no longer need. Do not open more sockets to “spread” the limit; the
   per-client cap is per IP.
6. Reconnect with jittered exponential backoff (for example 1 s, 2 s, 4 s,
   capped at 30 s) and re-create subscriptions explicitly.

### Choosing a transport

| Situation | Use |
| --- | --- |
| Browser, simple fan-out | SSE via `EventSource` |
| Browser behind a proxy that buffers `text/event-stream` | WebSocket |
| Server-side, need to call methods on the same socket | WebSocket |
| Server-side, one-way feed, easy HTTP tooling | SSE with `curl -N` |
| Need a stable id across reconnects | `stell_subscribe` over HTTP + SSE `sub_id` |
| Need history/backfill | [Indexer REST](/api/indexer-rest), not the stream |

## Indexer SSE

The indexer has a separate, higher-level stream at
`GET /api/v2/stream` on port `8088`. It supports `topics`, `contract`,
`address`, `shard_id` and an `after_seq` replay cursor, with a bounded
512-event replay window and 256 concurrent clients. See
[Indexer REST](/api/indexer-rest#sse-stream).

It is **not** the node's `stell_subscribe` stream and does not share ids.

## Limits and failure modes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `-32602 unknown subscription type` | typo / unsupported alias | use `newHeads`, `newTxs`, `invalidations`, `events` |
| `-32000 subscription limit reached (4096 …)` | global registry full | unsubscribe stale ids; detached ids expire after 3600 s |
| `-32000 per-client subscription limit reached (64 …)` | one IP created too many | reuse ids; one socket can carry many subscriptions |
| SSE `404` on `?sub_id=` | id unknown or TTL expired | create a new subscription |
| Notifications stop but socket is open | slow consumer / fan-out lag | reconnect and re-sync from your cursor |
| `eth_subscribe` → `-32601` | not implemented | use `stell_subscribe` |

## Next

For historical and aggregate data, use [Indexer REST](/api/indexer-rest). [JSON-RPC](/api/json-rpc) documents each method and its parameter shape.
