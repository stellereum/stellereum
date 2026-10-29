> **⚠️ Unaudited testnet — do not use real funds.** This code has passed internal audits and penetration tests, but no independent external audit has been completed yet. It is published for testnet use and review only; do not trust it with real funds or mainnet keys until an external audit is done.

# infmail-valid-backend

The InfMail network validator. Everything for the owner in one place: **mail API, TON smart contracts, NFT card generator, Go/Zig tools**.

## Structure

```
crates/infmail/     Rust — mail API (64 routes), SMTP/IMAP bridge, contract indexer
crates/infnode/     Rust — network layer (QUIC+DHT+storage), used as a dependency
contracts/          TON Tolk — smart contracts (registry, storage, NftCollection, NftItem)
nft/                Node.js — NFT card generator (canvas + designs.ts + LSB)
tools-src/          Go/Zig — tool sources (payouts, watcher, obs, chunkcheck)
Makefile            all commands
```

## Quick start

```bash
git clone https://github.com/immtes/infmail-valid-backend && cd infmail-valid-backend

# owner env (required):
export INFNODE_VALIDATOR_KEY=<your secret, >=16 chars>
export INFNODE_REWARDS=1
export INFNODE_REWARD_POOL_TON=0.1
export INFNODE_VALIDATOR_FEE_PERCENT=30

make start
```

Builds `infmail`, creates a validator config and starts it. `make tools` additionally builds Go/Zig tools from `tools-src/`.

## Federation (DNS TXT)

The validator is confirmed by its domain via DNS TXT: `infnode announce --domain X --advertise IP:port` prints the record (`_infnode.{domain}` TXT `infnode-validator=inf1:{node_id}:{ed_pub}:{ip}`). Nodes with `domain` in their config verify the validator and refuse to start if not confirmed (strict mode).

## Mail API

`crates/infmail/src/web.rs` — auth, mail/send, inbox, files, 2FA, NFT, web3, subscriptions.

## Contracts

`contracts/*.tolk` (Tolk, TON). Deployed contract addresses — in env:

```
REGISTRY_CONTRACT_ADDRESS=EQB_Y-LRJvZU7oBFSgVeP8CZM9fWe8VHcr3W9qO0y6dDJXHm
STORAGE_CONTRACT_ADDRESS=kQBwVBK0Pm1ZHgGczc38a5vhT5oEed6Gujml9f_lNMnByjWT
NFT_COLLECTION_ADDRESS=kQB5Y4R7OzRTfy1sfSpSfWccRfzuALtGhysikPz3CVRHUOk_
```

## NFT cards

`nft/` — service :9200, draws cards and embeds the LSB signature.

```bash
cd nft && npm install
NFT_CARD_PORT=9200 node server.js
```

## Commands

| Command | What |
|---------|------|
| `make build` | build `infmail` |
| `make start` | build + create config + start |
| `make tools` | build Go/Zig: payouts, watcher, obs, chunkcheck |
| `make tools-run` | run obs :9100 (background) |
| `make status` | node and peer status |
| `make clean` | remove generated files |

## Consensus (sub-validators)

`infnode consensus --config node.yaml` — the master hashes the state, requests Ed25519 signatures from sub-validators and checks the quorum `ceil(2/3·N)` (1 of 1 with a single validator, 2 of 3 with three). Result — `consensus.json`.

## Checks

```bash
./target/release/infnode stats --config ./node-data/node.yaml
./target/release/infnode audit-kv --kv ./node-data/kv.json
./tools/bin/infmail-payouts --dry-run --last=5    # Distribute TON drafts
./tools/bin/infmail-chunkcheck ./node-data        # chunk integrity
curl http://127.0.0.1:9100/metrics                # Prometheus (obs)
```

## Security

- The validator is confirmed by `INFNODE_VALIDATOR_KEY` — no one else can become a validator
- Nodes connect but get discovery-only rights until approved by the owner
- Mail is E2E-encrypted — storage nodes hold ciphertext
- Fair rewards: proof-of-storage, 0-30% fee, nodes ≥70%

## P3 — NFT-owner-bound encryption keys

Web3 (NFT) accounts derive their x25519 encryption key from the wallet signature
(Ed25519), so changing wallet ownership makes old messages unreadable.

**Backend** (`crates/infmail/src/nft/derive.rs` + `web.rs:web3_save_keys`):

- `POST /api/v1/web3/derive-keys {signature}` — returns `{x_pub, epoch, secure:true}`. Deterministic (same sig → same key).
- `POST /api/v1/web3/save-keys` (auth) — saves `x_pub` on the account; the server cross-checks that it matches the signature.

After saving, incoming external mail is encrypted with the wallet-bound `x_pub` (`web.rs:keys_get`).

**E2E test** (`crates/infmail/src/nft/derive.rs::p3_e2e_encrypt_decrypt_via_signature`) covers the full encrypt→decrypt cycle and proves a different wallet cannot decrypt.

## Related repos

- **Node** (for people): `infnode-node`
- **Frontend** (website): `infmail-frontend`
