# stellereum-sdk (Rust client)

Thin, client-only SDK for the live Stellereum chain. It builds and signs real
Falcon-512 `PQ1` transactions, mints `SF1` session grants, and talks to the
node's `stell_*` JSON-RPC surface.

Full reference (fees, lifecycle, errors, honest non-support table, node
line references): [`../docs/SDK.md`](../docs/SDK.md).

> Testnet software. No external audit. The key file is plaintext JSON at mode
> 0600 — protect it or wrap it in the OS keystore.

## Why this crate does not depend on the node

A wallet must not link tokio/axum/sled/wasmi and the whole RPC state. This
crate reimplements only the wire pieces it mints (PQ1 envelope, the supported
opcodes, signing preimages, EVM intent decoding and the fork-id mirror) and pins every byte against the node in the optional
`node-parity` test suite. The node is an **optional** dependency:

```bash
cargo test                     # thin client tests (no node crate)
cargo test --features node-parity   # + byte-for-byte parity with the node
```

## Quickstart

```rust
use stellereum_sdk::prelude::*;

fn main() -> Result<(), stellereum_sdk::SdkError> {
    let key = FalconKeypair::generate()?;
    key.save_key_file(std::path::Path::new("wallet.json"))?;

    let mut wallet = Wallet::connect(
        FalconKeypair::load_key_file(std::path::Path::new("wallet.json"))?,
        "http://127.0.0.1:8545",
    );

    let signed = wallet.transfer([0x22; 32], 1_000_000)?; // fills nonce + chain id + fee
    let outcome = wallet.submit(&signed, &RetryPolicy::default())?;
    let receipt = wallet.rpc().wait_for_receipt(
        &outcome.tx_hash,
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(1),
    )?;
    println!("{} {:?}", outcome.tx_hash, receipt.status);
    Ok(())
}
```

## Shapes

| Builder | Payload |
| --- | --- |
| `TxBuilder::transfer(to, amount)` | empty (native value transfer) |
| `TxBuilder::contract_call(contract, method, args, value)` | `SysCallCallContractArgs` |
| `TxBuilder::stake(validator, amount)` | `SysCallStake` |
| `TxBuilder::unjail(validator, top_up)` | optional `SysCallStake` + `SysCallUnjail` |
| `TxBuilder::gov_propose(id, title, action, height)` | `SysCallGovPropose` |
| `TxBuilder::gov_vote(id, choice, height)` | `SysCallGovVote` |
| `EvmBindingBuilder::new(identity, evm, proof)?` | `SysCallBindEvmAddress` (requires the 65-byte proof) |
| `EvmCarrierBuilder::new(identity, raw_evm_tx, to_pq)?` | `SysCallEvmCarrier` (nonce/value from the intent) |

Every builder runs the protocol/fork guard first: `ProtocolIdentity::local()`
is chain 5757, protocol 1.0, ruleset v5, fork id `0x9d59096b`. A foreign chain
id is `SdkError::ChainIdMismatch`; a foreign fork id is
`SdkError::ForkIdMismatch`. Configure the node's identity with
`.identity(identity)` (or `Wallet::with_identity`).

Honest limits: the carrier is a value transfer only (no EVM contract calls),
and the EVM binding is first-committed-wins.

> The SDK key file is PQClean Falcon-512 material. The node operator's
> `FalconKeypair::to_bytes` container is a different (expanded polynomial)
> private-key layout and is not importable; public keys and signatures are
> interoperable.

Chainable: `.nonce(n)`, `.chain_id(id)`, `.base_fee(n)`, `.gas_limit(n)`,
`.priority_fee_per_gas(n)`, `.shards(s, t)`, `.implicit()`, `.unbound()`
(testing only), `.to(addr)`. Then `.sign(&key)` or
`.sign_with_session(&session_key, &grant)`.

`SignedTx`: `.to_hex()`, `.tx_hash_hex()`, `.verify()`, `.from()`, `.nonce()`,
`.gas_limit()`, `.chain_id()`, `.payload_bytes()`.

`RpcClient`: `.account`, `.nonce`, `.base_fee`, `.validators`, `.block`,
`.receipt`, `.estimate_fee`, `.send_with_retry`, `.wait_for_receipt`,
`.send_and_wait`.

`Wallet`: `.transfer`, `.contract_call`, `.stake`, `.unjail`, `.evm_binding`, `.evm_carrier`, `.gov_propose`, `.gov_vote`, `.submit`,
`.submit_and_wait`, `.next_nonce`, `.reset_nonce`.

## Signing helper CLI

```bash
cargo run --bin stellereum-sdk-cli -- keygen --out wallet.json
cargo run --bin stellereum-sdk-cli -- address --key wallet.json
cargo run --bin stellereum-sdk-cli -- sign --key wallet.json < request.json
cargo run --bin stellereum-sdk-cli -- serve --key wallet.json --listen 127.0.0.1:8787
```

`serve` is the localhost helper used by the TypeScript package. It is plain
HTTP on loopback; set `STELL_SDK_SIGNER_TOKEN` to require a bearer token.

## Gate

```bash
cargo test
cargo test --features node-parity
cargo clippy --all-targets -- -D warnings
```

## License

MIT OR Apache-2.0.
