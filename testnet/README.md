# Stellereum public testnet

How to stand up, verify and use a public testnet from this binary.

Everything below was taken from the code, not from the design docs. Where the
two disagree, this file and `../../PROTOCOL.md` both say the code is the bug.

---

## 0. Read this before you start: three ways a testnet silently splits

These are the failure modes that cost people a weekend. All three are real
behaviours of this code, and all three are silent unless you check for them.

**(a) The faucet key must be identical on every node.**
`src/main.rs` derives a faucet account from `STELL_FAUCET_KEY` and credits
`GENESIS_FAUCET_BALANCE` (1,000,000 STELL) to it during genesis. That account is
part of the genesis state, and the genesis state root is the chain's
fingerprint. A node with a different key funds a different account, computes a
different genesis root, and finalizes its own blocks forever. Nothing detects
it: there is no genesis handshake, and block sync rejects the peer chain at the
first state-root comparison — which both nodes log as a single line among
thousands.

**Gotcha inside the gotcha:** an undecodable key is not an error. The key is
hex-decoded and, on failure, funding is skipped silently. A typo produces a node
with no faucet account, whose genesis root then differs from every correctly
configured node. This is why `genesis.env` ships with an invalid placeholder: it
cannot be started by accident, and the chain is forced to be configured
deliberately.

**(b) The validator set is derived from the YAML, and a short list is a
different chain.** `build_validator_set` produces
`{self} ∪ {peers whose node-id is in validators}`. The funded accounts at
genesis are exactly that set, so an asymmetric `validators:` list means an
asymmetric genesis root. Both nodes must list *every* validator id, and each must
carry a `peers:` entry with that node's `ed-pub`. A node that forgets a peer runs
solo, without saying so.

Note that `validators:` holds node ids (20-byte `inf1:` ids) while the account
that gets funded is the peer's `ed-pub` (32 bytes). They are different values.

**(c) Each node needs its own working directory.** `./data` and `./keys` are
resolved relative to the current directory, and the block store is `./data/store`.
Two nodes started from the same directory share one identity key and one
database. Give each node its own directory and run it from there.

**Retention, fourth item and not optional.** `STELL_ARCHIVE` defaults to on, but
write it out anyway. Archive keeps every block body forever. A node in prune
mode (`STELL_ARCHIVE=0` plus an explicit `STELL_KEEP_BLOCKS`) drops the body of
anything older than `height - keep_blocks`, irreversibly; header records survive,
so the chain can still be walked, but the block can never be re-executed. An
archive node on the default settings filled about 2.9 GB of `./data/store` in
the first day of running the current code. See `../docs/OPERATIONS.md`.

---

## 1. Prerequisites

- Rust toolchain able to build the workspace (`edition 2021`, `wasmi 2`,
  `sled 0.34`, `axum 0.7`, `tokio` with the `full` feature).
- The `infnode` crate at the path `Cargo.toml` points it at
  (`/home/imm/infnode/crates/infnode`). It is a path dependency,
  not a registry crate, so the node cannot be built without that checkout
  present. In Docker the build context must contain both directories.
- One host per node for anything you care about. Two nodes on one host works and
  is the layout used below, but they need distinct ports and distinct working
  directories.
- Nothing else. No faucet service, no key server, no genesis generator: the
  genesis state is computed in-process from the config and the environment.

Ports used in this walkthrough (all must differ per node on a single host):

| purpose | node A | node B | env var |
| --- | --- | --- | --- |
| QUIC P2P | 9410 | 9411 | `listen:` in the YAML |
| JSON-RPC | 8545 | 8546 | `STELL_RPC_LISTEN` |
| explorer / gateway | 8080 | 8081 | `STELL_EXPLORER_LISTEN` |
| infnode metrics | 9401 | 9402 | `metrics-listen:` in the YAML |

QUIC is **UDP**. `9410/udp` must be open inbound on every node; the JSON-RPC and
explorer ports are TCP.

---

## 2. Build

```sh
cd /path/to/stellereum
cargo build --release --bin stellereum
```

The binary lands at `./target/release/stellereum`. Add `--locked` if you want
`Cargo.lock` honoured exactly — worth doing for a testnet, since a different
dependency build is a different binary and the genesis constants are compiled
into it.

---

## 3. Generate the shared faucet key, once

```sh
# 32 bytes, hex, no 0x prefix
od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
```

Write that value into `testnet/genesis.env`, replacing the `STELL_FAUCET_KEY`
placeholder. Ship the same file — or the same value — to every node. Derive the
account it controls if you want to inspect it:

```sh
./target/release/stellereum wallet address --from-key <THE_HEX_YOU_GENERATED>
```

The address is the public key; the CLI derives it from the seed. Querying with
the seed itself silently returns a fresh, empty account.

---

## 4. Create the per-node working directories

```sh
cd /path/to/stellereum
mkdir -p testnet/a testnet/b
```

Nothing else. The node creates `./data` and `./keys` itself on first start;
`keys/identity.key` is the consensus validator key, and reusing it is what keeps
a node's validator identity stable across restarts.

---

## 5. Bootstrap the identities (one extra start, then wipe)

This is the fiddly part, and the reason is (b): you cannot know a peer's
`node-id` / `ed-pub` / `x-pub` until it has generated a key, and the first start
with incomplete config writes a *solo* genesis root into the data directory that
the fingerprint guard will then refuse to accept.

1. Start node A once, alone, and read its identity from the log:

   ```sh
   cd testnet/a
   set -a; . ../genesis.env; set +a
   ../../target/release/stellereum run --config ../node-a.yaml --shard 1
   ```

   Look for:

   ```
   NODE IDENTITY: id=inf1:<40 hex> ed=<64 hex> x=<64 hex> listen=0.0.0.0:9410
   ```

   The `id=` value goes into both YAML files' `validators:` lists. The `ed=`
   value goes into node B's `peers:` entry. Stop it (Ctrl-C) once you have the
   line.

2. Start node B the same way from `testnet/b` and read its identity.

3. Fill in all four `PLACEHOLDER_*` values in `node-a.yaml` and `node-b.yaml`.

4. **Wipe both data directories.** Not optional:

   ```sh
   cd /path/to/stellereum
   rm -rf testnet/a/data testnet/a/keys testnet/b/data testnet/b/keys
   ```

   Why: the first start recorded a genesis state root computed from a *solo*
   validator set. The completed config produces a different root, and the guard
   in `src/main.rs` compares the two and `bail!`s. Keeping `./data` gives you a
   node that refuses to start with a message that does not mention the config
   file you just edited. Keeping `./keys` is a separate decision: it preserves the
   identity, so you can keep it if the identity has not changed, but wiping both
   is the simple path and generates fresh validator keys.

   A node that has never run has nothing to compare against and will therefore
   happily start on the wrong chain. The guard is a restart guard, not a
   network-level check.

---

## 6. Start the nodes

One terminal per node. Each sources the *same* env file from its own working
directory.

```sh
# terminal 1
cd /path/to/stellereum/testnet/a
set -a; . ../genesis.env; set +a
../../target/release/stellereum run --config ../node-a.yaml --shard 1
```

```sh
# terminal 2
cd /path/to/stellereum/testnet/b
set -a; . ../genesis.env; set +a
../../target/release/stellereum run --config ../node-b.yaml --shard 1
```

`set -a` matters: the node reads `std::env::var`, so unexported shell variables
are invisible to it and the faucet key silently goes missing.

Flags, all of which exist:

| flag | default | meaning |
| --- | --- | --- |
| `run --config <path>` | `config.yaml` | infnode YAML; if the path does not exist the node logs "Running in local memory mode" and starts **no** P2P, no RPC and no explorer |
| `run --shard <n>` | `0` | shard id; 0 = Masterchain, 1 = Base Workchain |

`--shard` selects the P2P height namespace (`stell:height:<shard>`) and the shard
a faucet transaction is tagged with. It does **not** enter the state root and the
state engine does not validate it, but both nodes should use the same value or
they will look for each other under different keys. The published Dockerfile
uses `--shard 1`.

---

## 7. Check that the two nodes are on the same chain

The check is the pair (finalized height, state root). Height alone proves
nothing: a node that is running a private chain also has a rising height.

```sh
rpc() { curl -s -X POST "$1" -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-\{\}}}"; }

A=http://127.0.0.1:8545
B=http://127.0.0.1:8546

rpc $A stell_blockNumber
rpc $B stell_blockNumber
```

Both should return the same hex string (`"0x2a"` for height 42). Let it run for
a minute and compare again — a single sample can be taken between blocks.

```sh
rpc $A stell_getStateRoot
rpc $B stell_getStateRoot
```

These must be byte-identical 64-char hex strings. If they are not, and the
heights match, you have two chains: the usual cause is (a) or (b) above. The
`/api/stats` gateway route returns the state root together with the height and
the mempool size in one request, which is a cheaper thing to poll:

```sh
curl -s http://127.0.0.1:8080/api/stats
```

Confirm the validator set itself agrees — both nodes should report the same list,
the same `total_power` and the same `quorum`:

```sh
rpc $A stell_getValidators
rpc $B stell_getValidators
```

Then confirm the faucet is funded *identically*, which is the specific thing that
(a) breaks:

```sh
FAUCET_ADDR=$(./target/release/stellereum wallet address --from-key "$STELL_FAUCET_KEY")
rpc $A stell_getBalance "{\"address\":\"$FAUCET_ADDR\"}"   # {"balance":"1000000000000000","nonce":0}
rpc $B stell_getBalance "{\"address\":\"$FAUCET_ADDR\"}"
```

Both must show 1,000,000,000,000,000 nano-STELL and nonce 0. A zero on one node
means that node skipped the faucet credit: check `STELL_FAUCET_KEY` there, and
expect a split.

Sanity check on the logs:

```
Genesis: funded 2 validator account(s); state root <root>
Consensus: 2 validator(s), quorum power 2, proposer for height 1 = true
[sync] caught up N blocks to height M
[consensus] FINALIZED block #N <hash> (state root <root>)
```

If you see `quorum power 0` or a set size of 1 where you expected 2, the
`validators:` / `peers:` entries did not match and that node is running solo.

Full method-by-method reference: `../docs/RPC.md`.

---

## 8. Submit a transaction

### 8.1 Fund an address with the faucet

The faucet does not write balances. It signs an ordinary transfer from the
pre-funded genesis faucet account into the mempool, so the value movement is
decided by consensus like any other transaction. Enable it on **one** node
(`STELL_FAUCET=1` in that node's environment) — the key is what must be shared,
the flag is not.

```sh
NEWKEY=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
ADDR=$(./target/release/stellereum wallet address --from-key "$NEWKEY")

curl -s -X POST http://127.0.0.1:8080/api/faucet/$ADDR
# {"status":"pending","credited_nano":"10000000000","recipient":"...","tx_hash":"..."}
```

or over JSON-RPC on the node that has `STELL_FAUCET=1`:

```sh
rpc $A stell_faucet "{\"address\":\"$ADDR\"}"
```

Limits are set where the `Faucet` is constructed: **10 STELL** per request by
default (`STELL_FAUCET_DRIP_STELL` overrides the drip), **1000 STELL lifetime
total per recipient address** (hardcoded cap). Requesting more
than a drip is clamped down to a drip. Once the cap is spent, the method answers
`-32000 "faucet limit reached for this address"` (or HTTP 429 on the gateway).
On a node without `STELL_FAUCET=1`, `stell_faucet` answers
`-32601 "faucet is disabled on this node"`.

The drip is a transaction, not a write, so watch it land:

```sh
rpc $A stell_getTransactionStatus "{\"hash\":\"$TXHASH\"}"   # pending -> success | failed
rpc $A stell_getBalance       "{\"address\":\"$ADDR\"}"
```

### 8.2 Send with the CLI wallet

```sh
./target/release/stellereum wallet send \
  --from-key  "$NEWKEY" \
  --to        "$RECIPIENT" \
  --amount    1000000 \
  --rpc       http://127.0.0.1:8545 \
  --verbose
```

`--amount` is in **nano-STELL** (1 STELL = 1,000,000,000 nano-STELL). `--to` is
a 32-byte hex address. The CLI reads the account's real nonce from
`stell_getBalance` before signing — pin it with `--nonce` only if you know what
you are doing. Add `--dry-run` to print the signed transaction and stop. Use
`wallet address --from-key <seed>` first if you are unsure which address a seed
controls; the address is the public key, and the CLI derives it for you.

Two things to know about the CLI sender:

- It signs with `gas_limit = 1000` (hardcoded in `src/main.rs`), which is BELOW
  the default mempool floor of 280,000 (`STELL_MIN_GAS_LIMIT` defaults to
  `GAS_BASIC_TRANSFER`), so against a default-configured node the CLI send is
  rejected with `FeeTooLow` ("offered fee is below the base fee") — lower
  `STELL_MIN_GAS_LIMIT` on a dev node or sign the transaction yourself with a
  `gas_limit` of at least 280,000. It stamps `source_shard = 1` with `--target-shard`
  defaulting to 1. The state engine does not validate shard fields, so this is
  bookkeeping, not a routing decision.
- **It cannot authenticate.** If you set `STELL_RPC_AUTH_TOKEN` on the node, the
  CLI has no flag to send a token and `stell_sendRawTransaction` will answer
  `-32001 "unauthorized"`. Either leave the token unset on the RPC port the CLI
  points at, or submit by hand:

  ```sh
  curl -s -X POST http://127.0.0.1:8545 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stell_sendRawTransaction\",
         \"params\":{\"tx\":\"$RAW_HEX\",\"token\":\"$STELL_RPC_AUTH_TOKEN\"}}"
  ```

`stell_sendRawTransaction` takes `tx` = hex of the bincode-serialised
`Transaction`, optionally `0x`-prefixed. Bad signatures are rejected before the
mempool is touched, and a rejected transaction is never admitted.

### 8.3 Check the mempool is not lying

```sh
rpc $A stell_mempoolSize
```

This is the same `Mempool` object the proposer selects from, so the number is
truthful. If transactions sit at a non-zero size and the height does not move,
the producer's admission filter is rejecting them — a stale nonce, or a balance
that no longer covers `amount + gas_limit`. Unexecutable transactions are evicted
each round and you will see `[mempool] evicted N unexecutable transaction(s)`.

---

## 9. Explorer and metrics

```sh
curl -s http://127.0.0.1:8080/health        # {"status":"ok","service":"stellereum-gateway"}
curl -s http://127.0.0.1:8080/api/stats     # chain_id, node_id, height, mempool, state_root, contracts
curl -s http://127.0.0.1:8080/metrics       # stellereum_block_height, _mempool_size, _contracts_total, _tokens_total
```

The whole gateway surface is behind a per-IP fixed-window rate limiter,
`STELL_RATE_LIMIT_PER_SEC` requests per second, default 30; over that you get
HTTP 429. The JSON-RPC router is also mounted at `/rpc` on the explorer port, so
`http://127.0.0.1:8080/rpc` is a second way in — and it shares the same rate
limit, and CORS is `*` on every gateway response.

infnode's transport counters are a separate endpoint,
`metrics-listen:` in the YAML (`infnode_connections_active`,
`infnode_reconnects_total`, `infnode_messages_delivered_total`, …).

---

## 10. Take it down cleanly

Ctrl-C is handled: the node flushes and logs `Stellereum Node shutting down
cleanly.`

Never `kill -9` a validator if you can avoid it. The node persists finalized
blocks, the finalized head, and a consensus safety checkpoint (height, round,
locked value), and on restart it restores the lock so it cannot double-vote a
height it already locked. An unclean stop loses at most the blocks since the
last background flush, but it does not break consensus safety.

---

## 11. Quick reference: local, no P2P at all

For a single-machine smoke test with no network, `sim` runs the whole stack
in-process with three generated validators and no persistence:

```sh
./target/release/stellereum sim --blocks 5
```

It prints a table of per-block activity and exits. It shares no code path with
the real consensus loop, so it proves the subsystems are wired up and says
nothing about whether two real nodes agree.
