# Quickstart

This walkthrough takes you from a clean checkout to a finalized post-quantum transfer on the public testnet. It uses only commands and RPC methods that exist in the repository.

**Time:** about 15 minutes. **Cost:** testnet STELL only.

::: warning Testnet only
The faucet pays test STELL with no value. The network has no external audit. Do not reuse keys that protect real assets.
:::

## 0. Prerequisites

- Linux or macOS with a recent stable Rust toolchain and `git`.
- `curl` and a shell.
- An address you control on the recipient side (create one in step 2).

Build the node binary from the repository:

```sh
git clone https://github.com/stellereum/stellereum.git
cd stellereum
cargo build --release --bin stellereum
./target/release/stellereum --help
```

The binary exposes the `keys`, `wallet`, `validator`, `gov`, `run`, `node-bootstrap` and related subcommands. Put it on your `PATH` for the rest of the walkthrough:

```sh
export PATH="$PWD/target/release:$PATH"
```

## 1. Create node key material

`keys init` creates the node identity, ML-KEM-768 transport keys, the Falcon-512 P2P identity, and the consensus Falcon-512 key. It is idempotent: existing keys are loaded, never overwritten. Keys are written `0600` in a `0700` directory.

```sh
export STELL_KEY_PASSPHRASE='use-a-long-unique-passphrase'
stellereum keys init --keys-dir ./keys
```

Expected output starts with one line:

```text
NODE IDENTITY: id=… kem_ek=… pq_pub=… falcon=…
keys dir: ./keys (0700), files 0600
falcon key: ./keys/falcon.key
```

The `falcon=` value is the consensus public key. The matching encrypted private key is `./keys/falcon.key`; it is the node's consensus Falcon key. Validator registration additionally binds a cold withdrawal key and a hot voting key (see [Validator setup](/nodes/validator)). Keep the passphrase out of shell history in real deployments.

::: tip Key files and wallet commands
`wallet send-pq` and the validator transaction commands accept a **32-byte Falcon seed** (`--falcon-seed`) or, where documented, a Falcon key file (`--falcon-key-file`). The seed form is the simplest for a testnet walkthrough. The `keys init` key file is the operator form used by nodes and validators.
:::

## 2. Create a throwaway wallet key and derive its address

For the transfer loop, create a dedicated seed-backed wallet. A 32-byte seed deterministically derives the same Falcon-512 key and the same PQ address every time.

```sh
export STELL_SENDER_SEED=$(openssl rand -hex 32)
export STELL_RECIPIENT_SEED=$(openssl rand -hex 32)

stellereum wallet sign \
  --scheme falcon \
  --falcon-seed "$STELL_SENDER_SEED" \
  --message "derive my testnet address" \
  --chain-id 5757
```

The command signs locally and prints, among other fields:

```text
  Address:   <64 hex characters>
```

Capture the two addresses:

```sh
SENDER=$(stellereum wallet sign --falcon-seed "$STELL_SENDER_SEED" \
  --message "derive my testnet address" --chain-id 5757 | awk '/Address:/{print $2}')
RECIPIENT=$(stellereum wallet sign --falcon-seed "$STELL_RECIPIENT_SEED" \
  --message "derive my testnet address" --chain-id 5757 | awk '/Address:/{print $2}')
echo "sender=$SENDER"; echo "recipient=$RECIPIENT"
```

The address is **not** the seed and **not** the Falcon public key. It is `BLAKE3("STL_ADDR_V4" ‖ 0x02 ‖ falcon_pubkey ‖ salt)` with the default 16-byte zero salt. See [Addresses](/get-started/addresses).

::: danger Treat the seed as the account
Anyone with `STELL_SENDER_SEED` can spend the account. This is a throwaway testnet seed; never use this pattern for value you care about.
:::

## 3. Fund the sender from the faucet

Open the faucet:

```text
https://faucet-testnet.stellereum.org
```

Paste the **sender** address (`$SENDER`, 64 hex characters) and request a drip. The testnet faucet policy is:

| Limit | Value |
| --- | --- |
| Amount per drip | **2 STELL** |
| Cooldown per address | **45 minutes** |
| Requests per IP | **20 per hour** |
| Lifetime cap per address | **50 STELL** |

The web form is the supported path. The public endpoint is `POST /api/faucet-public/<address>` and is Turnstile-gated: a request without a valid `cf-turnstile-response` is refused, so a scripted request needs a token obtained from the challenge. The equivalent request shape is:

```sh
curl -sS -X POST "https://faucet-testnet.stellereum.org/api/faucet-public/$SENDER" \
  -H 'content-type: application/json' \
  -d '{"cf-turnstile-response":"<token from the challenge>"}'
```

A successful response reports the credited amount, the recipient and the drip transaction hash. A refusal tells you which policy was hit (`cooldown`, hourly budget, or lifetime cap); it does not consume the sender's funds.

Wait a moment, then read the account:

```sh
curl -sS https://rpc.stellereum.org \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_getBalance","params":{"address":"'"$SENDER"'"}}'
```

Expected shape:

```json
{"jsonrpc":"2.0","id":1,"result":{"balance":"2000000000","nonce":0}}
```

`2000000000` nano-STELL is 2 STELL. If the balance is still zero, the drip transaction may not have been included yet; check the faucet response and retry the read.

## 4. Send a post-quantum transfer

Send 0.1 STELL to the recipient. `--amount` is always nano-STELL; 0.1 STELL is `100000000`.

```sh
stellereum wallet send-pq \
  --falcon-seed "$STELL_SENDER_SEED" \
  --to "$RECIPIENT" \
  --amount 100000000 \
  --rpc https://rpc.stellereum.org \
  --chain-id 5757
```

Expected output:

```text
PQ Transaction Signed (Falcon-512, explicit PQ1 envelope):
  Hash:   <tx hash>
  From:   <sender address>
  To:     <recipient address>
  Amount: 100000000 nano-STELL
  Nonce:  0
  Target Shard: 0
  Chain Id: 5757 (signature bound)
  Submitted, mempool tx hash: <tx hash>
```

`wallet send-pq` builds an explicit `PQ1` envelope and refuses to submit a transaction that does not verify. Use it for value transfers on a pure-PQ network. Plain `wallet send` builds a legacy classical transaction shape and is refused by a pure-PQ node with `invalid transaction signature`.

The CLI sets `gas_limit` to `GAS_BASIC_TRANSFER` (280,000) plus the PQ activation surcharge (45,000). The node charges the live base fee on top. Read the current floor with:

```sh
curl -sS https://rpc.stellereum.org \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_baseFee","params":[]}'
```

## 5. Read the transfer back from RPC

Use the hash printed by `wallet send-pq`:

```sh
export TX_HASH='<tx hash from step 4>'

curl -sS https://rpc.stellereum.org \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_getTransactionReceipt","params":{"hash":"'"$TX_HASH"'"}}'
```

A finalized transfer returns a receipt with:

| Field | Meaning |
| --- | --- |
| `status` | `success` or `failed` |
| `height` | Inclusion height |
| `fee_charged` | Fee debited, in nano-STELL |
| `gas_limit`, `gas_used` | Gas cap and consumption |
| `confirmations` | Finalized depth; `1` already means final |
| `block_hash`, `index` | Inclusion location |

Check both balances:

```sh
for A in "$SENDER" "$RECIPIENT"; do
  curl -sS https://rpc.stellereum.org -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"stell_getBalance","params":{"address":"'"$A"'"}}'
  echo
done
```

The recipient is credited **exactly** the transfer amount. The sender is debited the amount plus the charged fee. A missing or `unknown` status means the transaction is not in this node's receipt window, not that it failed; re-submit or query another node.

## 6. What you just proved

You have:

- generated a Falcon-512 wallet key and derived its 32-byte PQ address;
- received test STELL from the faucet within the published policy;
- signed and submitted an explicit `PQ1` transaction bound to chain 5757;
- read a finalized receipt and both account balances from JSON-RPC.

One finalized block is final. You do not need to wait for a confirmation count for correctness; extra confirmations are an operational choice against stale reads or a lagging indexer.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `offered fee is below the base fee` | Read `stell_baseFee` and raise the gas limit above the live floor. |
| `nonce gap` | The sender has another pending transaction. Wait for inclusion, or pass the account's current nonce explicitly with `--nonce`. |
| `invalid transaction signature` | You used plain `wallet send` on a pure-PQ node. Use `wallet send-pq` with the Falcon seed that owns the funded address. |
| `refusing to submit: built PQ transaction does not verify` | The seed or address derivation is wrong. Re-derive the address with `wallet sign` and fund **that** address. |
| Faucet says cooldown | One drip per address per 45 minutes. Wait, or fund a different address. |
| Faucet says lifetime cap | The address has received its 50 STELL testnet lifetime maximum. Use a fresh address. |
| Balance is `0` after a drip | The drip may still be in the mempool. Re-read `stell_getBalance`; the faucet response includes the drip hash. |

## Next

Continue with [Architecture](/get-started/architecture) to see where the transaction went, then [Accounts & fees](/core-concepts/accounts-and-fees) for nonces and the failure rule. [Smart contracts](/contracts/overview) is the next step if you want to deploy code.
