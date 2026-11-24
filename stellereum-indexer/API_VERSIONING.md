# Indexer API versioning policy

The indexer serves one handler set under two path prefixes:

| Prefix | Status | Response headers |
| --- | --- | --- |
| `/api/v2/...` | Canonical | none added |
| `/api/...` | Legacy alias, deprecated | `Deprecation: true`, `Sunset: Wed, 30 Jun 2027 00:00:00 GMT`, `Link: </api/v2>; rel="successor-version"` |

Both prefixes are built from the same router (`create_router` in `src/server.rs`)
and nested twice, so a handler cannot exist on only one prefix. The relative
path set is the union of the historical v2 spellings (`/blocks`, `/tx/:hash`,
`/txs`, `/account/:address`, ...) and the historical legacy spellings
(`/blocks/latest`, `/transactions/:hash`, `/transactions/latest`,
`/accounts/:address`, ...). During the migration window both spellings work
under both prefixes; clients should move to the v2 spellings listed in the
README.

The legacy headers are added by a middleware applied only to the `/api` nest.
They change no status code and no response body.

## What v2 means

v2 is the current contract. Relative to the historical legacy surface it is:

1. **An explicit version in the path** (`/api/v2/...`), so a future breaking
   change can ship as `/api/v3` while v2 keeps its current behaviour.
2. **Shard-qualified transaction keyset cursors** (below). This is the only
   wire-format change; every other response shape is unchanged.

## Transaction keyset cursor

Transaction history is ordered by `(block_height, tx_index, shard_id)` in
descending order. `(block_height, tx_index)` is unique only inside one shard, so
the cursor now carries the shard:

* v2 (emitted): `"<shard>:<block_height>:<tx_index>"`;
* legacy (still accepted): `"<block_height>:<tx_index>"`.

`parse_tx_cursor_v2` accepts both forms. A legacy cursor parses with
`shard_id = None` and keeps the pre-v2 predicate
(`block_height < h OR (block_height = h AND tx_index < i)`). For single-shard
data that paginates exactly as before. On multi-shard data with equal
`(height, index)` rows, a legacy cursor cannot distinguish the rows and may
repeat or skip one; that is the old behaviour, preserved intentionally so old
clients do not change meaning. New cursors always carry the shard, so
round-tripping `next_cursor` is duplicate-free and skip-free across shards.

Malformed cursors are still rejected with `400 Bad Request` and
`{"error": "..."}`; the error class did not change.

This applies to:

* `GET /api/v2/txs` (`get_recent_txs`);
* `GET /api/v2/account/:address/txs` and the legacy account-activity aliases
  (`get_account_actions`).

Both handlers call `Database::get_account_txs_keyset`, which now:

* selects the row's `shard_id`;
* adds `shard_id DESC` as the final `ORDER BY` tie-breaker;
* appends `shard_id < ?` to the keyset predicate when the cursor carries a
  shard;
* emits `"<shard>:<height>:<tx_index>"` in `next_cursor`.

The offset-paginated `get_account_txs` uses the same total order (including
`shard_id DESC`) so cursor and offset pages agree. A supporting index,
`idx_tx_block_txindex_shard`, is created by the schema migration.

## Compatibility commitments

* Existing `/api/...` clients keep working until the sunset date; only the
  response headers are new.
* Existing response bodies, field names, `limit` clamps, and offset caps are
  unchanged, apart from the transaction `next_cursor` value described above.
* A client may keep using a legacy two-field transaction cursor indefinitely
  before sunset; the indexer re-emits the v2 three-field form, and clients
  should treat `next_cursor` as opaque.
* `GET /api/v2/blocks` already used a shard-aware block cursor
  (`<height>` when filtered by shard, `<height>:<shard>` otherwise); that is
  unchanged.

## Retirement

`Sunset: Wed, 30 Jun 2027 00:00:00 GMT` is the announced retirement date for
the `/api/...` alias. After it, the legacy nest is removed and `/api/...`
requests return `404`; `/api/v2/...` is unaffected. The date is a constant
(`LEGACY_API_SUNSET` in `src/server.rs`) so the header and this document stay in
sync.

Migration checklist for clients:

1. Change the prefix from `/api/...` to `/api/v2/...`.
2. Switch legacy path spellings to the v2 spellings in the README.
3. Treat `next_cursor` as opaque and pass it back unchanged.
4. Stop sending `offset` together with `cursor` (still `400`).
