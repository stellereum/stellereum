# Stellereum load-test harness

Standalone, repeatable load generator for the node's real JSON-RPC. It builds
**valid full-PQ transactions** (Falcon-512, PQ1 envelopes, chain-id bound,
deterministic per-sender nonces), measures the wave, and prints a report.

**The harness is dry-run by default. It sends nothing unless `--allow-live` is
present. Known live-cluster hosts additionally require `--operator-order`.**

The Wave-2 procedure, funding math and stop conditions live in
[`docs/LOADTEST_RUNBOOK.md`](../../docs/LOADTEST_RUNBOOK.md).

---

## 1. Safety model

| Situation | Behaviour |
|---|---|
| no `--allow-live` | **dry run only** (keygen, sign, serialize, decode, hash; no network) |
| `--dry-run` | same, even if other flags are present (cannot combine with `--allow-live`) |
| `--allow-live` + loopback URL | sends to the local test node |
| `--allow-live` + non-loopback URL | refuses unless `--allow-remote` |
| `--allow-live` + one of `212.113.103.105`, `213.21.246.5`, `138.124.102.200`, `178.155.74.242`, `77.110.96.68`, `rpc.stellereum.org` | refuses unless `--operator-order` |
| `--preflight-only` / `--print-senders` | reads chain id, base fee and sender balances; sends **no** transaction |
| `--print-all-senders` | same reads, then prints every address one per line plus `SENDERS_TOTAL=<n>`; exits 0 even when unfunded |

The gate is pure: hostnames are compared literally and never resolved, so DNS
cannot change the verdict. `--operator-order` is an explicit acknowledgement of
the AGENTS.md §6 rule ("live cluster is read-mostly; no transactions without an
explicit human order"), not a bypass for an accidental `--allow-live`.

The harness only calls `stell_sendRawTransaction` plus read methods. It never
calls the faucet, staking, governance, contract-preview or key operations, and
it never funds an account itself.

### Deterministic senders are public test keys

`--seed` (default `stellereum-loadtest-v1`) derives every sender from
`blake3("STELL_LOADTEST_SENDER_V1" || seed || index)`. This makes the address
set repeatable so an operator can fund it once. The keys are therefore public
by construction: **never fund them on a value-bearing network.**

---

## 2. Build

```bash
cd /home/imm/stellereum-project
cargo build --release --offline \
  --manifest-path scripts/loadtest/loadtest/Cargo.toml
```

The binary is `scripts/loadtest/loadtest/target/release/stell-loadtest`.

### Why the crate is standalone / how Falcon signing is borrowed

The crate has its own empty `[workspace]` table, so it never joins the node
workspace and never modifies `stellereum/Cargo.toml` or `Cargo.lock`.

At the time of writing, the node tree is **mid-refactor**: `post_quantum.rs`
removed the classical scheme variants while `wallet.rs` / `wallet_signing.rs`
still reference them, so `stellereum` as a whole does not compile and cannot be
used as a path dependency. The harness therefore includes the node's own
sources **verbatim** with `#[path]`:

* `stellereum/src/post_quantum.rs` → Falcon-512 keygen/sign/verify, address
  derivation, the implicit key registry, the PQ1 scheme ids;
* `stellereum/src/sharding/envelope.rs` → the exact PQ1 framing, explicit and
  implicit constructors, salt and chain-id bytes.

Only the empty-payload `Transaction` container and its signed/hash preimage are
mirrored in `src/wire.rs`, field for field from
`stellereum/src/sharding/transaction.rs`; the tests pin the exact wire lengths
(1708 B explicit, 795 B implicit) and the 131-byte chain-bound preimage. When
the node tree compiles again, the harness can be switched to
`stellereum = { path = "../../../stellereum" }` without changing any wire
logic; `wire.rs` exists because that is not possible today.

---

## 3. Local self-test (no node)

```bash
./scripts/loadtest/loadtest/target/release/stell-loadtest --dry-run --senders 4
```

It performs, in order:

1. deterministic Falcon-512 keygen for every sender;
2. construction of an explicit (activation) transaction;
3. signing of the exact chain-bound preimage;
4. serialization with the node's bincode configuration;
5. decode with the node's bounded decoder;
6. signature verification;
7. hash equality across the roundtrip;
8. an implicit steady-state transaction verified against a local registry;
9. a batch of `--dry-run-count` transactions with unique hashes and contiguous
   per-sender nonces.

It prints the first transaction's sender, fields, envelope sizes, signing
message length, signing digest, wire length, tx hash and the full wire hex.
Exit code 0 means all local checks passed.

---

## 4. Live preflight (read-only)

```bash
./scripts/loadtest/loadtest/target/release/stell-loadtest \
  --allow-live --preflight-only --url http://127.0.0.1:8545 --senders 64
```

This reads `stell_chainId`, `eth_chainId`, `stell_baseFee`,
`stell_blockNumber`, `stell_getValidators`, and `stell_getBalance` for every
sender. When the set is funded it prints every deterministic address, its
on-chain nonce and balance, and it refuses to start a live wave when any
sender is below one transaction's cost (`amount + gas_limit + activation
surcharge`).

Fund the printed addresses from a testnet faucet/treasury, then rerun.

### Funding a large sender set (one address per line)

`--preflight-only` still exits 3 (funding failure) as soon as any sender is
short, and its refusal block only shows the first 50 addresses. To obtain the
complete 256-address set for funding, use the roster mode:

```bash
./scripts/loadtest/loadtest/target/release/stell-loadtest \
  --allow-live --print-all-senders --url http://127.0.0.1:8545 --senders 256 \
  | tee /tmp/opencode/senders-256.txt
```

Output shape:

```
0x<64 hex chars>
0x<64 hex chars>
...
SENDERS_TOTAL=256

sender[  0] 0x... nonce=0 balance=...
...
```

The address lines are machine-readable (`grep '^0x'`, then `wc -l` must equal
the `SENDERS_TOTAL=` value). The human summary follows after the total line.
`--print-all-senders` sends no transaction and returns 0 even when every
sender is unfunded; it always prints the whole set.

---

## 5. Live run

Local node (safe default URL):

```bash
./scripts/loadtest/loadtest/target/release/stell-loadtest \
  --allow-live \
  --url http://127.0.0.1:8545 \
  --senders 64 --rate 60 --duration 900 \
  --json-out /tmp/opencode/wave-60.json
```

A remote **test** node (not the live cluster):

```bash
... --allow-live --allow-remote --url http://203.0.113.10:8545 ...
```

The live cluster, only with a human order:

```bash
... --allow-live --allow-remote --operator-order \
    --url https://rpc.stellereum.org \
    --watch-url https://rpc.stellereum.org ...
```

Every flag and its default is in `--help`. The most important ones:

| Flag | Meaning |
|---|---|
| `--rate` | target accepted submissions per second |
| `--duration` | sending window in seconds |
| `--senders` | keypairs / sender threads |
| `--inflight-per-sender` | accepted-but-unexecuted nonces per sender, **max 4** (node `NONCE_FUTURE_WINDOW`) |
| `--max-inflight` | global concurrent HTTP requests (0 = senders) |
| `--pq-mode` | `auto` = explicit activation then implicit; `explicit`/`implicit` pin one mode |
| `--gas-limit` | fixed gas limit; 0 = `stell_baseFee + surcharge + --gas-margin` |
| `--recipient` | `self` (default), `sink`, or a 32-byte hex address |
| `--watch-url` | height-lag watcher, repeatable |
| `--stall-seconds` | abort when no new block for N seconds (default 30) |
| `--max-lag-blocks` | abort when watch heights differ by more than N (default 500) |
| `--backlog-stop-size` | abort when mempool stays above N for `--backlog-stop-secs` |
| `--metrics-url` | optional Prometheus endpoint for the node's own interval histogram |

### What one wave does

* One OS thread per sender. A sender's nonces are strictly sequential; at most
  four accepted nonces may be outstanding (the node rejects `nonce >
  head + 4` as a gap).
* A global token bucket enforces `--rate`; a global semaphore bounds concurrent
  requests to `--max-inflight`.
* **A retry always resends the cached signed bytes for the same nonce.** It
  never re-signs the nonce and never advances it, so a transport retry cannot
  double-spend a nonce. A duplicate response counts as accepted.
* `auto` sends the first nonce per sender as an explicit envelope (897-byte
  Falcon public key, +45,000 gas activation surcharge), waits until that nonce
  is included, then omits the public key. If the node lost its in-memory
  registry (restart) and rejects an implicit signature, the same nonce is
  re-signed explicitly.
* After the window: drain (wait for accepted nonces to become on-chain nonces),
  receipt sampling, final block/mempool snapshot, report.

---

## 6. Node method map (discovered from the source)

| Purpose | Method | Params |
|---|---|---|
| submit | `stell_sendRawTransaction` | `{"tx": "0x<bincode(Transaction)>"}` |
| chain id | `stell_chainId` / `eth_chainId` | `[]` (decimal / hex result) |
| height | `stell_blockNumber` | `[]` (hex string) |
| base fee | `stell_baseFee` | `[]` → `{"base_fee":"280000"}` |
| balances/nonce | `stell_getBalance` | `{"address":"0x..."}` |
| block detail | `stell_getBlock` | `{"height":N}` → `{height,hash,txs,timestamp}` |
| recent blocks | `stell_latestBlocks` | `{"limit":256}` |
| mempool | `stell_mempoolSize` | `[]` |
| validators | `stell_getValidators` | `[]` |
| receipt/status | `stell_getTransactionReceipt` / `stell_getTransactionStatus` | `{"hash":"..."}` |

There is **no** `stell_getBlockByNumber`; the node's method is
`stell_getBlock({"height":N})`. `stell_blockNumber` returns a hex quantity,
while balance and base fee are decimal strings.

---

## 7. Reading the output

```
submitted (unique signed txs): 54001
accepted: 54000   failed: 0   duplicates: 0   retries: 3   429s: 0   unresolved: 0
achieved accepted rate: 60.00 tx/s
included (on-chain nonce delta): 54000   included rate: 60.00 tx/s   backlog after drain: 0
block time observed (s): n=900 min=0.802 p50=1.001 p95=1.204 p99=1.402 max=2.110 mean=1.003 s
tx per block: n=900 min=40 p50=60 p95=61 p99=62 max=64 mean=60.00
node-reported interval (1 s timestamps): ...
```

* **submitted** — unique signed transactions (one per nonce); retries are not
  counted again.
* **accepted** — RPC `result` or an idempotent duplicate. It is *mempool*
  acceptance, not execution.
* **failed** — terminal RPC rejection (bad signature, fee too low, insufficient
  balance, nonce gap, mempool full, ...). The first error is printed.
* **duplicates** — a retry whose first response was lost; safe and expected in
  small numbers.
* **429s** — per-IP rate-limit responses. A large number means
  `STELL_STANDALONE_RATE_LIMIT` is below the target rate.
* **unresolved** — submitted-but-never-answered (a stop condition fired with a
  request in flight). Non-zero forces `FAIL`; it is not silently dropped.
* **achieved accepted tx/s** — accepted / actual sending window.
* **included** — sum of on-chain nonce advances for the sender set after drain.
  This is the authoritative "made it into blocks" count.
* **backlog after drain** — accepted but not executed. Non-zero is a FAIL.
* **block time** — wall-clock arrival intervals of new `stell_blockNumber`
  heights, sampled every `--poll-ms`. Percentiles are over the sending window.
* **tx per block** — `stell_getBlock(...).txs` for every new height, including
  zero-transaction blocks.
* **node-reported interval** — consecutive `stell_latestBlocks` timestamps.
  They are whole seconds, so this is a coarse cross-check; use the observed
  block time for sub-second percentiles.
* **node metrics interval** — optional `--metrics-url` mean from
  `stell_block_interval_seconds_{sum,count}`.
* **verdict** — `PASS` (acceptance within `--fail-ratio` and zero backlog),
  `FAIL` (rejections or backlog), `ABORTED` (a stop condition fired).

Exit codes: `0` PASS, `1` FAIL, `2` usage/safety refusal, `3` preflight
funding failure, `4` ABORTED by a stop condition.

---

## 8. Limits (honest)

* Empty-payload native transfers only. Non-empty SVM payloads would need the
  node's `Vec<OpCode>` encoding; `encode_wire` refuses them rather than guess.
* One in-flight signed byte string per sender at a time; parallelism comes from
  more senders. The node's four-nonce window is respected.
* Block-time percentiles are measured at `--poll-ms` resolution (default 200 ms)
  and the first interval includes poller startup; both are visible in the
  sample count.
* The default node budget is 300 standalone RPC requests/second per IP. A
  500 tx/s wave from one IP needs the operator to raise
  `STELL_STANDALONE_RATE_LIMIT` on the target (restart required). The harness
  warns above 250 tx/s and reports 429s instead of hiding them.
* The receipt sample is a bounded sample of last-tx hashes, not a full receipt
  scan; the exact included count comes from nonce deltas.
