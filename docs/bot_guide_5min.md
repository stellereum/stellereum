# Trading bot in 5 minutes (session keys)

Run a scoped, budgeted, revocable trading bot: the master key funds and
delegates, the bot key only trades, and one master transaction kills the bot
key when you are done. Working code: `../examples/bot_session_demo.rs` (run
it first - every step below is demonstrated there with live output).

## 0. Prerequisites

- Rust toolchain that builds this repo (`cargo build --example bot_session_demo`).
- No network needed for the demo: it runs against an embedded local sim
  (the same `InMemoryStateEngine` + `apply_transaction` consensus path the
  node and `Commands::Sim` use, minus P2P). For a live node you need its RPC
  URL plus a funded master account (see §1).
- No new dependencies: the demo uses only crates already in `Cargo.toml`
  (`tokio`, `serde_json`, `bincode`, `hex`, `blake3`, `ureq`, `anyhow`, ...).

## 1. Fund an account (faucet)

The **master** pays for everything the bot does (gas + order escrow), so the
**master** - never the session key - must hold funds.

Testnet faucet (see `RPC.md` §`stell_faucet`):

```sh
curl -X POST $STELL_RPC_URL -d '{
  "jsonrpc":"2.0","id":1,"method":"stell_faucet",
  "params":{"address":"<MASTER_PUBKEY_64_HEX>"}
}'
# -> {"result":{"credited_nano":"10000000000","recipient":"...","tx_hash":"..."}}
```

Facts that bite: the drip is 10 STELL by default (`STELL_FAUCET_DRIP_STELL`
overrides it) with a 1000 STELL lifetime cap per
address; the faucet is **fail-closed** (needs `STELL_FAUCET=1` plus a
`STELL_FAUCET_TOKEN` on the node, otherwise it refuses); the returned
`tx_hash` is a *pending* mempool transaction, not finality - poll
`stell_getTransactionStatus` until `success`. Gateway alternative:
`POST /api/faucet/:address` on the explorer port. Node setup lives in
`../testnet/README.md`.

## 2. Run the demo

```sh
cargo run --example bot_session_demo            # embedded local sim, offline, asserts the security demo
cargo run --example bot_session_demo -- --dry-run  # print every step, send nothing
STELL_RPC_URL=http://127.0.0.1:8545 cargo run --example bot_session_demo -- --rpc $STELL_RPC_URL
```

What you will see (each line also explains WHY):

1. Fresh master + session keypairs generated at runtime (nothing on disk).
2. Master signs a delegation grant: trade-only scope (`SCOPE_SVM_PAYLOAD`),
   expiry now+1h, `max_gas_spend = 5000`, `max_value_per_tx = 1000`,
   `chain_id = 5757` - with a one-line meaning per field.
3. Bot (session key only) submits a SELL order on STELL/USDT and polls its
   receipt. Numbers to expect: `spent = 1200` (`GAS_ORDER_PLACE`),
   `remaining_gas = 3800`.
4. Bot reads its budget (stubbed `stell_sessionBudget` - see §5).
5. Master revokes on chain; the bot's retry **fails** with
   `session key delegation rejected: session key has been revoked`
   (asserted in code - this is the security demo).

## 3. The 5 core concepts in plain words

1. **Master vs session key.** The master owns the money and signs grants;
   the bot holds only a session key and can never touch the master key.
   On chain, `tx.from` is still the master (its account pays), but the
   *signature* is the bot's, over message + grant (`Transaction::sign_with_session`).
2. **Scope.** A bitmask of what the grant allows: `SCOPE_TRANSFER` (bit 0)
   = plain transfers with an empty payload; `SCOPE_SVM_PAYLOAD` (bit 1) =
   anything carrying a payload (orderbook, token, staking ...); plus
   `SCOPE_ACTOR_SEND` for actor-mailbox sends. A trading bot gets exactly
   `SCOPE_SVM_PAYLOAD` - enough for `SysCallPlaceOrder`, useless for
   anything else. `SCOPE_ALL` (`u64::MAX`) exists; do not use it for bots.
3. **Expiry.** `valid_until` is a unix timestamp checked against the
   *block* timestamp (deterministic across nodes, never wall-clock in
   consensus). The grant dies by itself even if you forget to revoke it.
4. **Budget.** `max_gas_spend` is cumulative across ALL transactions under
   the grant and never refills. Only *applied* transactions consume it -
   a refused transaction costs the grant nothing. The registry record (not
   the re-presented grant) is the source of truth, so a bot cannot reset
   its own budget by replaying the grant.
5. **Revoke.** One master-signed transaction carrying
   `SysCallRevokeSession { session_pubkey }` sets `revoked = true`
   terminally - nothing ever sets it back, and it is committed into the
   state root (survives restarts/restores). After that, mempool admission,
   the proposer filter and execution all refuse the key. A *session* key
   can never revoke (the gate rejects delegated revokes), so a leaked bot
   key cannot kill your other bots - or survive its own death.

## 4. Common mistakes (each with the one-line fix)

1. **Granting `SCOPE_ALL`.** A compromised bot key can then do anything the
   master can except revoke. *Fix: grant exactly the bits the bot needs -
   `SCOPE_SVM_PAYLOAD` for a trading bot (`src/zkml.rs`, `SCOPE_*`).*
2. **Forgetting expiry (`valid_until` far future / `u64::MAX`).** A leaked
   key stays valid until you notice and revoke. *Fix: shortest expiry the
   strategy tolerates (e.g. now+1h) and re-issue grants on a schedule
   (`SessionKeyAuthorization::sign_delegation`).*
3. **Funding the session key directly instead of via the master allowance.**
   `tx.from` is always the master account - money sent to the session
   address just sits there, unusable by the bot, while the bot's
   transactions fail with `Insufficient balance`. *Fix: fund the master;
   the session key never needs a balance (demo step `[faucet]`).*
4. **Oversized `max_value_per_tx`.** The cap covers `tx.amount` per single
   transaction - set it to millions and one buggy order payload path can
   move millions. *Fix: cap at the largest single trade size plus a small
   margin (demo: 1000).*
5. **Revoking a key that never traded and assuming it worked.** An unused
   grant has no registry record, so plain `SysCallRevokeSession` fails
   closed with `unknown session key: nothing to revoke`. *Fix: publish-then-
   revoke (carry a matching `SysCallPublishSessionGrant` in the same master
   payload so the tombstone path applies), or simply let the short expiry
   kill it - see `note_tombstone` in `src/zkml.rs` and the payload path in
   `src/state_engine.rs`.*
6. **Treating mempool admission as finality.** `stell_sendRawTransaction`
   checks signature/fees/quota but NOT the nonce sequence - a stale-nonce
   bot tx is accepted, then silently dropped by the block producer.
   *Fix: track the master-account nonce yourself and poll
   `stell_getTransactionStatus`/`stell_getTransactionReceipt` until
   `success` (demo step `[b]`).*

## 5. Integration gap: `stell_sessionBudget`

At the time of writing **no `stell_sessionBudget` method exists** on the
node (checked the `src/rpc.rs` dispatch match and `RPC.md` - a companion
agent owns it). The demo therefore reads the budget through a
clearly-marked STUB (`STUB-START`/`STUB-END` in
`../examples/bot_session_demo.rs`) with the exact agreed contract:

- method `stell_sessionBudget`, params `{"session": "<64-hex>"}`;
- result `{"registered": bool, "revoked": bool, "valid_until": u64,
  "scope": u64, "max_gas_spend": u64, "spent": u64,
  "remaining_gas": u64, "master": "<64-hex>"}`.

The `--rpc` path already tries the real method first (`rpc_session_budget`)
and falls back to the stub with a printed gap notice, so no demo logic
changes when the method lands - only the data source does.

## 6. Where to read next (real files)

- Grant, scope bits, registry, budget math, tombstones: `src/zkml.rs`
  (`SessionKeyAuthorization`, `SCOPE_*`, `SessionKeyRegistry::check`,
  `note_applied`, `note_tombstone`).
- Envelope signing, scope derivation, stateless policy:
  `src/sharding.rs` (`Transaction::sign_with_session`,
  `required_scope`, `check_session_policy`).
- The full gate (registry + chain-id + no-delegated-revoke) and apply path:
  `src/state_engine.rs` (`session_gate_with`, `apply_transaction`).
- Opcode costs and the revoke handler: `src/svm.rs`
  (`GAS_*`, `SysCallPlaceOrder`, `SysCallRevokeSession`,
  `SysCallPublishSessionGrant`).
- One-line grant helper: `src/wallet.rs` (`delegate_bot_session`).
- RPC surface + faucet semantics: `src/rpc.rs`, `RPC.md`.
- Pinned invariants (expiry/scope/budget/revocation/persistence):
  `tests/session_registry_tests.rs`, `tests/session_key_tests.rs`.
- CLOB semantics + escrow: `src/orderbook.rs`; PMM (for a market-making
  bot next step): `src/pmm.rs`; running a node: `../testnet/README.md`.
