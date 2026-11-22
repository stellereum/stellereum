# Networks

Stellereum currently has one public network: **testnet**. There is no mainnet endpoint, and testnet state may be reset.

## Endpoints

| Service | URL | Notes |
| --- | --- | --- |
| JSON-RPC | `https://rpc.stellereum.org` | POST-only JSON-RPC; native `stell_*` namespace plus a read-only EVM adapter |
| Explorer | `https://explorer.stellereum.org` | Block, account and transaction views |
| Indexer API | `https://explorer.stellereum.org/api/v2` | REST API served by the explorer/indexer stack |
| Testnet application | `https://testnet.stellereum.org` | Testnet onboarding and faucet entry point |
| Faucet | `https://faucet-testnet.stellereum.org` | 2 STELL per drip; 45-minute cooldown; 20 requests/hour/IP; 50 STELL lifetime per address |
| Documentation | `https://docs.stellereum.org` | This site |

The RPC endpoint is not a REST API. A `GET /` returns `405`; send a JSON-RPC `POST` with `content-type: application/json`.

## Network parameters

| Parameter | Value |
| --- | --- |
| Network name | Stellereum Testnet |
| Chain ID | **5757** (`0x167d`) |
| Native currency | STELL |
| Decimals | **9** (1 STELL = 1,000,000,000 nano-STELL) |
| Consensus ruleset | **v7** |
| Fork ID | **`0x3ae00ebc`** |
| Block tempo | Configured by operators with `STELL_MIN_BLOCK_MS=400` |
| Finality | One finalized block is final |
| Signatures | Falcon-512 (PQ1 transaction envelope; Falcon votes) |
| Transport | ML-KEM-768 |
| Addresses | 32 bytes; 64-character hex (`0x` optional) or `Stl57…` display |
| Live shards | `{0}` — masterchain shard 0 |
| Supported shard set | `{0,1}` (shard 1 parked on the public network) |

::: warning Fork ID matters
Ruleset v7 nodes refuse a consensus handshake with a v6 peer (`ForkMismatch`). If a node reports a different fork id, it is not on this network. Do not point it at testnet data.
:::

## Verify the endpoint

```sh
RPC=https://rpc.stellereum.org

curl -sS "$RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_chainId","params":[]}'
# {"jsonrpc":"2.0","id":1,"result":5757}

curl -sS "$RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}'
# {"jsonrpc":"2.0","id":1,"result":"0x…"}  (hex string)

curl -sS "$RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_getValidators","params":[]}'
```

If `stell_chainId` is not `5757`, stop. You are talking to the wrong network.

## Add the network to a wallet

A Stellereum wallet must be able to sign **Falcon-512** transactions inside a `PQ1` envelope. Configure it with:

| Field | Value |
| --- | --- |
| RPC URL | `https://rpc.stellereum.org` |
| Chain ID | `5757` |
| Currency symbol | `STELL` |
| Decimals | `9` |
| Address format | 32-byte hex (64 characters) or `Stl57…` |
| Signature scheme | Falcon-512 (no Ed25519 / secp256k1 transaction lane) |
| Explorer | `https://explorer.stellereum.org` |

The CLI reads the RPC and chain id per command, so no global network file is required:

```sh
stellereum wallet send-pq \
  --falcon-seed "$STELL_SENDER_SEED" \
  --to "$RECIPIENT" \
  --amount 100000000 \
  --rpc https://rpc.stellereum.org \
  --chain-id 5757
```

### EVM-compatible wallets

Stellereum is **non-EVM**. The node serves a read-only EVM adapter on the same endpoint for chain identity, balances and read-only routing, and `eth_chainId` returns `0x167d` (5757). That does **not** make MetaMask or another secp256k1 wallet a signer for Stellereum:

- There is no EVM interpreter and no EVM state trie.
- Contract creation and calldata execution are refused with `evm-contract-execution-unsupported`.
- A value transfer needs a PQ binding plus a Falcon carrier signature; the secp256k1 signature inside the EVM bytes is advisory only.

Use a native Falcon-512 wallet or the CLI for value. Use the read-only EVM adapter only for tooling that needs chain-id and read-only state.

## Endpoint roles

| Consumer | Should use |
| --- | --- |
| Wallet, CLI, contract tooling | `https://rpc.stellereum.org` JSON-RPC |
| Block explorer UI | `https://explorer.stellereum.org` |
| Indexed history, aggregate queries | `https://explorer.stellereum.org/api/v2` |
| Faucet | `https://faucet-testnet.stellereum.org` |
| Node-to-node P2P | infnode QUIC/UDP, port `9410` by default; not an HTTP endpoint |

The indexer is a separate consumer of chain data. It can lag the RPC tip. For balances and receipts that must reflect finality, query the RPC; for historical or aggregate queries, query the indexer and treat its height as a snapshot.

## Next

Next, [Addresses](/get-started/addresses) explains how a Falcon key becomes a 32-byte address; the [Quickstart](/get-started/quickstart) runs the full faucet-to-receipt loop.
