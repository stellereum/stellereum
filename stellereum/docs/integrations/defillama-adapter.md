# DeFiLlama TVL adapter — Stellereum Testnet (chain 5757)

Status: design + validated probe. Live-checked 2026-10-14 against the dev
node with exactly two RPC probes (`stell_chainId` -> `5757`,
`stell_getValidators` -> 3 validators, powers `"1874531430003"` /
`"2000000000000"` / `"2000000000000"` nano). Everything else below was
validated offline (see section 5).

Ground truth: `docs/RPC.md`, `src/rpc.rs` dispatch arms, `src/client_ip.rs`,
`src/tokenomics.rs`, `src/staking.rs`, `src/pmm.rs`. Two places where
`docs/RPC.md` / `docs/OPERATIONS.md` are stale are called out in section 6 —
code wins over docs.

Public edge assumed by this adapter: `https://rpc.stellereum.org` behind
`docs/integrations/nginx-rpc.conf` (30 req/s/IP, 1 MiB body cap, POST-only).
The adapter makes ~1+N sequential calls (N = validator count); well under
the limiter. It never sends batch arrays (node refuses them, `-32600`).

---

## 1. TVL methodology (what counts, what does not — yet)

| Component | RPC reads | Status |
| --- | --- | --- |
| Staking-secured TVL | `stell_getValidators` -> per-validator `stell_stakeOf.total`, summed in nano-STELL | **COUNTED** (this adapter's TVL) |
| PMM reserves / treasury | `stell_pmmState` (`reserve_micro`, `treasury`, `minted_nano`, ...) | Reported only, NOT added (stable-vs-native denomination + redemption-buffer methodology undecided) |
| CLOB / orderbook escrow | `stell_orderBook` (`{"pair": N}`, default pair `1`; `available_nano_stell` per level) | Reported only, NOT added (escrow-vs-outstanding double-count risk undecided) |
| Bridge escrow | — | NOT counted AND not countable: **no aggregate bridge-escrow read exists**. Only per-record lookups `stell_bridgeDeposit` (`source_tx_hash`) and `stell_bridgeDispute` (`dispute_id`) exist (`src/rpc.rs`). A bridge term needs either a new RPC method (node change, out of scope) or manual reconciliation of known deposit records. |
| Price | — | No STELL feed exists. Adapter reports native STELL; the USD leg uses an explicit `STELL_USD = 1` stub in the JS skeleton (handoff doc `EVM_CHAINLIST_PR.md` section 4) and `--stell-usd` in the probe. Never present stub-USD as a valuation. |

Units: every amount on the wire is a **decimal string in nano-STELL**
(`1 STELL = 1_000_000_000 nano`, 9 decimals per `src/tokenomics.rs`,
`src/pmm.rs`, `MIN_VALIDATOR_BOND = 1000 * 1e9` in `src/staking.rs`). Parse
with `BigInt` / `int()`, never `Number` / `float`. This matches
`docs/integrations/chainlist.json` (`nativeCurrency.decimals: 9`, ledger
truth; the 18-decimal EVM presentation waits for the future EVM shim and its
9<->18 conversion — see that file's `_comment`).

## 2. Exact RPC methods used

Transport for all: `POST /` (or `POST /rpc` on the `:8080` gateway),
`{"jsonrpc":"2.0","id":1,"method":"<m>","params":{...}}`.
Success: `{"jsonrpc":"2.0","id":1,"result":...}`;
error: `{"jsonrpc":"2.0","id":<id>,"error":{"code":<int>,"message":"..."}}`.

### `stell_getValidators` (params: none)

```json
{"jsonrpc":"2.0","id":1,"method":"stell_getValidators","params":{}}
```

Result (field order irrelevant; **ignore unknown fields** — live nodes add
`"fragile":false` / `"fragile_reason":null`, undocumented in `docs/RPC.md`):

```json
{"result":{
  "validators":[
    {"validator":"<64 hex>","power":"1874531430003"},
    {"validator":"<64 hex>","power":"2000000000000"}
  ],
  "total_power":"5874531430003",
  "quorum":"3916354286669"
}}
```

`power` / `total_power` are decimal nano-STELL strings. `quorum` is
`floor(2*total_power/3)+1` (so 2-of-2 and 3-of-3 at small sets — a halted
2-validator chain yields no TVL movement, correctly). `power` is a fallback
only (see next method).

### `stell_stakeOf` (params: `{"validator": "<64 hex>"}`)

```json
{"jsonrpc":"2.0","id":1,"method":"stell_stakeOf","params":{"validator":"<64 hex>"}}
→ {"result":{"total":"1000000000","self_bond":"1000000000","delegated":"0"}}
```

`total = self_bond + delegated` as the ledger computes it; unknown validator
-> all `"0"` (not an error); missing validator -> `-32602`. TVL sums `total`
over the validator set from `stell_getValidators`.

### `stell_pmmState` (params: none; informational)

Returns `price_micro_usd`, `minted_nano`, `reserve_micro`,
`redemption_buffer_micro`, `usable_reserve_micro`, `max_redeemable_stell`,
`quote_token`, `treasury`, `governed_buffer_bps` (`src/rpc.rs`). Pure read of
the committed curve. Reported, not summed.

### `stell_orderBook` (params: `{"pair": <int>}`, default pair `1`; informational)

Returns `best_bid/ask_micro_usd`, `bid/ask_levels`, and up to 20 levels per
side with `available_nano_stell` (unfilled amounts). Unknown pair ->
`-32004`. Reported, not summed.

### `stell_bridgeDeposit` / `stell_bridgeDispute` (informational, per-record)

`{"source_tx_hash": "<64 hex>"}` -> `{"found": bool, ...amount...}` (absent
record = unchallengeable pre-dispute deposit, not an error);
`{"dispute_id": "<u64-as-string>"}` -> `{"found": bool, ...}`. No
enumeration, no totals — hence no bridge term in TVL.

> `stell_bridgeDeposit` is the **record read**. The deposit CLAIM (the
> transaction a wallet has to sign) is a different method,
> `stell_bridgeDepositPrepare` — one JSON-RPC name, one meaning. Do not send
> the prepare's parameters (`chain`, `recipient`, `amount`) to the read: it
> refuses them with `-32602` rather than answering `{"found": false}`.

## 3. Submission artifact (DeFiLlama repo) vs this repo's probe

- The file filed upstream (`DefiLlama/DefiLlama-Adapters`,
  `projects/stellereum/index.js`, Node >= 18, no new deps) is the JS skeleton
  in handoff doc `EVM_CHAINLIST_PR.md` section 4: `stell_getValidators` ->
  per-validator `stell_stakeOf.total` sum -> `nano / 1e9`, `tether` output
  with the `STELL_USD = 1` stub TODO, `timetravel: false`. That skeleton is
  unchanged by this pack; its BigInt-last parsing already matches section 2.
- The runnable equivalent that validates the SAME reads against the live
  node is `scripts/tvl_probe.py` (stdlib only). Source is embedded below so
  this doc is self-contained; the script file is the canonical copy.

```python
# (embedded copy of scripts/tvl_probe.py — see that file for the runnable
# version; behaviour is identical)
#
# Core parsing (the part validated offline):
#
#   NANO_PER_STELL = 1_000_000_000
#
#   def parse_validators(result):
#       entries = result.get("validators") or []
#       validators = [(e["validator"], int(e.get("power", "0"))) for e in entries if e.get("validator")]
#       return validators, int(result.get("total_power", "0") or "0"), ...
#
#   def parse_stake_total(result):
#       return int(result.get("total", "0") or "0")
#
#   def fmt_nano(nano):
#       return "%d.%09d" % (nano // NANO_PER_STELL, nano % NANO_PER_STELL)
#
# Flow: stell_chainId (expect 5757, warn otherwise) -> stell_getValidators
# -> stell_stakeOf per validator (power fallback per-validator on single-read
# failure, logged) -> print nano + STELL + USD-stub. Optional --pmm,
# --orderbook PAIR_ID, --bridge-deposit HASH print raw reads with
# "reported, not added" notes. --self-test runs offline fixtures.
```

## 4. curl examples (for the operator; each is one POST, no batches)

```sh
RPC=https://rpc.stellereum.org   # or http://127.0.0.1:8545 locally

# Chain id (expect {"result":5757}):
curl -s -X POST "$RPC" -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_chainId","params":{}}'

# Validator set (powers are decimal nano strings; ignore fragile/* fields):
curl -s -X POST "$RPC" -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_getValidators","params":{}}'

# Bonded total for one validator from the set above:
curl -s -X POST "$RPC" -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_stakeOf","params":{"validator":"<64 hex>"}}'

# PMM snapshot (informational):
curl -s -X POST "$RPC" -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_pmmState","params":{}}'

# Orderbook depth, pair 1 (informational):
curl -s -X POST "$RPC" -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_orderBook","params":{"pair":1}}'

# One bridge deposit record (informational; {"found":false} is a valid answer):
curl -s -X POST "$RPC" -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_bridgeDeposit","params":{"source_tx_hash":"<64 hex>"}}'

# Batch refusal demo (expect -32600; adapter must never do this):
curl -s -X POST "$RPC" -H 'content-type: application/json' \
  --data '[{"jsonrpc":"2.0","id":1,"method":"stell_chainId","params":{}}]'
```

## 5. Validation performed (2026-10-14, no builds, minimal live traffic)

- Live (2 probes total, budget respected): `stell_chainId` -> `5757`;
  `stell_getValidators` -> shape in section 2 with 3 validators and extra
  `fragile` / `fragile_reason` fields. Parser handles both.
- Offline: `python3 scripts/tvl_probe.py --self-test` -> `SELF_TEST_OK`
  (live-captured fixture, empty-set, `stakeOf` shapes, float-free formatting,
  loud failure on bad shapes); `python3 -m py_compile scripts/tvl_probe.py`.
- `python3 -m json.tool docs/integrations/chainlist.json` passes; schema
  invariants (chainId/networkId 5757, `0x167d`, rpc https/no-trailing-slash,
  shortName spaceless, no `redFlags`) re-checked after stripping `_`-keys.
- `nginx -t` against a wrapper including `docs/integrations/nginx-rpc.conf`
  passes (nginx 1.28.3); `/healthz` carries no `limit_req`, body cap `1m`,
  TLS paths commented stubs.
- Markdown self-consistency: ports (8545/8080), 30/s/IP edge budget,
  9-decimal nano units, method/param shapes, and the no-batch /
  no-contract-exec limits are stated identically here,
  in `docs/integrations/nginx-rpc.conf`, `docs/integrations/chainlist.json`
  (`_comment`), and `scripts/tvl_probe.py --help`.

## 6. Stale-doc corrections found while grounding (code wins)

- `docs/RPC.md` section 6 says bridge/PMM/orderbook exist "only in CLI
  subcommands" — stale: `src/rpc.rs` serves `stell_pmmState`,
  `stell_orderBook`, `stell_bridgeDeposit`, `stell_bridgeDispute`,
  `stell_pmmBuy/Sell`, `stell_submitPriceFeed`. There is still NO aggregate
  bridge-escrow read and NO contract-execution method, which is what matters
  for TVL/Chainlist disclosures.
- `docs/OPERATIONS.md` section 6 says the RPC port "is not rate limited" —
  stale: `src/rpc.rs serve()` applies a per-IP limiter (default 300/s,
  `STELL_STANDALONE_RATE_LIMIT`; gateway `:8080` stays 30/s). Edge still
  enforces 30/s/IP per this pack.
- `docs/RPC.md` section 5 omits the `fragile` / `fragile_reason` fields that
  `stell_getValidators` returns live. Consumers must ignore unknown fields
  (this adapter and the probe do).

## 7. Open placeholders for the operator

1. `STELL_USD` price stub (= 1): replace with a CoinGecko/DEX feed after STELL
   lists; until then TVL is honest only in native STELL.
2. Bridge-escrow TVL term: needs a new aggregate RPC read (node change) or an
   audited off-chain reconciler over known `source_tx_hash` records.
3. PMM/orderbook inclusion: decide denomination (`reserve_micro` is micro-USD,
   escrow is nano-STELL) and prove no double-count with staking/bridge terms.
4. DeFiLlama PR metadata: `start` = unix time of testnet genesis (handoff
   skeleton carries a TODO placeholder); methodology text in section 1.
5. Chainlist PR is BLOCKED on the EVM shim (`eth_chainId` -> `0x167d`) — see
   `docs/integrations/chainlist.json` `_comment` and handoff doc
   `EVM_CHAINLIST_PR.md` section 2. Do not file early.
6. Edge deploy: TLS cert paths + optional CDN trusted-proxy ranges in
   `docs/integrations/nginx-rpc.conf`; mirror CDN ranges into the node's
   `STELL_TRUSTED_PROXY_CIDRS` or rate-limit/faucet buckets see the CDN only.
