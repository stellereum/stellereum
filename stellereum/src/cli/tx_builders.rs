use ed25519_dalek::SigningKey;
use std::path::PathBuf;

use stellereum::bridge::TeleportBridgeEngine;
use stellereum::sharding::Transaction;
use stellereum::zkml::SessionKeyAuthorization;

/// Declared gas budget for a CLI-built payload transaction.
///
/// Never below the opcode's own cost, and never below the default admission
/// base fee: a transaction the mempool refuses on arrival can never reach a
/// block, so the cheapest useful budget is the larger of the two.
pub(crate) fn cli_tx_gas(opcode_gas: u64) -> u64 {
    opcode_gas.max(stellereum::svm::GAS_BASIC_TRANSFER)
}

pub(crate) fn falcon_pq_address(kp: &stellereum::post_quantum::FalconKeypair) -> [u8; 32] {
    stellereum::post_quantum::derive_pq_address(
        stellereum::post_quantum::PqScheme::Falcon512,
        &kp.public_key,
        &stellereum::post_quantum::DEFAULT_SALT,
    )
}

pub(crate) fn falcon_from_hex_seed(
    raw: &str,
    what: &str,
) -> anyhow::Result<stellereum::post_quantum::FalconKeypair> {
    let seed = zeroize::Zeroizing::new(parse_wallet_seed(raw, what)?);
    Ok(stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed))
}

#[allow(clippy::too_many_arguments)]
// GATE: explicit PQ payload tx builder mirrors Transaction::new_pq_explicit; callers supply full tx fields.
pub(crate) fn sign_pq_explicit_payload(
    pq_key: &stellereum::post_quantum::FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
    payload: Vec<stellereum::svm::OpCode>,
) -> Transaction {
    sign_pq_explicit_payload_inner(
        pq_key,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        payload,
        None,
    )
}

/// Chain-bound variant of [`sign_pq_explicit_payload`].
///
/// The signature covers `Transaction::signing_message_for_chain(chain_id)` and
/// the PQ1 envelope carries the same `chain_id`, so admission after
/// `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` accepts it and a replay on another
/// chain fails the cryptographic check. The unbound function above is kept
/// byte-identical for scripts that still run against a pre-activation chain.
#[allow(clippy::too_many_arguments)]
// GATE: chain-bound PQ payload builder (same shape as the unbound one plus chain_id).
pub(crate) fn sign_pq_explicit_payload_with_chain(
    pq_key: &stellereum::post_quantum::FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
    payload: Vec<stellereum::svm::OpCode>,
    chain_id: u64,
) -> Transaction {
    sign_pq_explicit_payload_inner(
        pq_key,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        payload,
        Some(chain_id),
    )
}

#[allow(clippy::too_many_arguments)]
// GATE: single signing body for the bound and unbound PQ payload builders.
fn sign_pq_explicit_payload_inner(
    pq_key: &stellereum::post_quantum::FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
    payload: Vec<stellereum::svm::OpCode>,
    chain_id: Option<u64>,
) -> Transaction {
    let from = falcon_pq_address(pq_key);
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let env = match chain_id {
        Some(cid) => {
            let msg = tx.signing_message_for_chain(cid);
            let sig = pq_key.sign(&msg);
            stellereum::sharding::PqSignatureEnvelope::new_explicit_with_chain(
                stellereum::post_quantum::PqScheme::Falcon512,
                pq_key.public_key.clone(),
                sig,
                stellereum::post_quantum::DEFAULT_SALT,
                cid,
            )
        }
        None => {
            let msg = tx.signing_message();
            let sig = pq_key.sign(&msg);
            stellereum::sharding::PqSignatureEnvelope::new_explicit(
                stellereum::post_quantum::PqScheme::Falcon512,
                pq_key.public_key.clone(),
                sig,
            )
        }
    };
    tx.signature = env.encode();
    tx
}

/// Chain-bound PQ transfer (same shape as `rpc::sign_pq_explicit_transfer`).
///
/// The CLI keeps its own copy so `wallet send` / `wallet send-pq` can bind the
/// signature without touching the faucet's public helper. Empty payload; the
/// envelope is always explicit (no implicit-key registry state needed).
#[allow(clippy::too_many_arguments)]
// GATE: transfer builder mirrors the faucet-shaped transaction plus chain_id.
pub(crate) fn sign_pq_explicit_transfer_with_chain(
    pq_key: &stellereum::post_quantum::FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
    chain_id: u64,
) -> Transaction {
    sign_pq_explicit_payload_with_chain(
        pq_key,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        Vec::new(),
        chain_id,
    )
}

/// Build the transaction that places an order on the committed book.
///
/// The order lives only as this payload; the book it lands in is the one every
/// node derives from the block, not a local copy.
pub(crate) fn build_place_order_tx(
    trader: &stellereum::post_quantum::FalconKeypair,
    pair: u32,
    is_buy: bool,
    price: u64,
    amount: u64,
    nonce: u64,
) -> Transaction {
    build_place_order_tx_inner(trader, pair, is_buy, price, amount, nonce, None)
}

/// Chain-bound variant of [`build_place_order_tx`].
#[allow(clippy::too_many_arguments)]
// GATE: order builder (same shape as the unbound one plus chain_id).
pub(crate) fn build_place_order_tx_with_chain(
    trader: &stellereum::post_quantum::FalconKeypair,
    pair: u32,
    is_buy: bool,
    price: u64,
    amount: u64,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    build_place_order_tx_inner(trader, pair, is_buy, price, amount, nonce, Some(chain_id))
}

#[allow(clippy::too_many_arguments)]
// GATE: single body for the bound and unbound place-order builders.
fn build_place_order_tx_inner(
    trader: &stellereum::post_quantum::FalconKeypair,
    pair: u32,
    is_buy: bool,
    price: u64,
    amount: u64,
    nonce: u64,
    chain_id: Option<u64>,
) -> Transaction {
    let from = falcon_pq_address(trader);
    let gas = cli_tx_gas(stellereum::svm::GAS_ORDER_PLACE)
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    let payload = vec![stellereum::svm::OpCode::SysCallPlaceOrder {
        pair_id: pair,
        is_buy,
        price,
        amount,
    }];
    match chain_id {
        Some(cid) => {
            sign_pq_explicit_payload_with_chain(trader, from, 0, gas, nonce, 1, 1, payload, cid)
        }
        None => sign_pq_explicit_payload(trader, from, 0, gas, nonce, 1, 1, payload),
    }
}

/// Build the transaction that cancels an order on the committed book.
///
/// The pair is not carried: `SysCallCancelOrder` resolves the order by id
/// against every book at block time, so a wrong `--pair` cannot strand a
/// cancellation the way a locally-scoped lookup could.
pub(crate) fn build_cancel_order_tx(
    trader: &stellereum::post_quantum::FalconKeypair,
    order_id: u64,
    nonce: u64,
) -> Transaction {
    build_cancel_order_tx_inner(trader, order_id, nonce, None)
}

/// Chain-bound variant of [`build_cancel_order_tx`].
pub(crate) fn build_cancel_order_tx_with_chain(
    trader: &stellereum::post_quantum::FalconKeypair,
    order_id: u64,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    build_cancel_order_tx_inner(trader, order_id, nonce, Some(chain_id))
}

fn build_cancel_order_tx_inner(
    trader: &stellereum::post_quantum::FalconKeypair,
    order_id: u64,
    nonce: u64,
    chain_id: Option<u64>,
) -> Transaction {
    let from = falcon_pq_address(trader);
    let gas = cli_tx_gas(stellereum::svm::GAS_ORDER_CANCEL)
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    let payload = vec![stellereum::svm::OpCode::SysCallCancelOrder { order_id }];
    match chain_id {
        Some(cid) => {
            sign_pq_explicit_payload_with_chain(trader, from, 0, gas, nonce, 1, 1, payload, cid)
        }
        None => sign_pq_explicit_payload(trader, from, 0, gas, nonce, 1, 1, payload),
    }
}

/// Build the transaction that publishes a master-signed session grant on chain.
///
/// The grant rides in the payload, so it is bound into the transaction hash
/// and retrievable from the receipt: a delegation becomes a committed record
/// instead of a printout. Note the pair `(pair, order_id)` of the cancel is
/// carried by the opcode alone - the book is looked up by id at block time.
#[cfg(test)]
pub(crate) fn build_session_grant_tx(
    master: &stellereum::post_quantum::FalconKeypair,
    grant: &SessionKeyAuthorization,
    nonce: u64,
) -> Transaction {
    build_session_grant_tx_inner(master, grant, nonce, None)
}

/// Chain-bound variant of [`build_session_grant_tx`].
///
/// The grant itself already commits to `grant.chain_id`; binding the wrapping
/// transaction to the same id keeps the published delegation usable after
/// chain-binding activation.
pub(crate) fn build_session_grant_tx_with_chain(
    master: &stellereum::post_quantum::FalconKeypair,
    grant: &SessionKeyAuthorization,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    build_session_grant_tx_inner(master, grant, nonce, Some(chain_id))
}

fn build_session_grant_tx_inner(
    master: &stellereum::post_quantum::FalconKeypair,
    grant: &SessionKeyAuthorization,
    nonce: u64,
    chain_id: Option<u64>,
) -> Transaction {
    let from = falcon_pq_address(master);
    let gas = cli_tx_gas(stellereum::svm::GAS_PUBLISH_SESSION_GRANT)
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    let payload = vec![stellereum::svm::OpCode::SysCallPublishSessionGrant(
        Box::new(grant.clone()),
    )];
    match chain_id {
        Some(cid) => {
            sign_pq_explicit_payload_with_chain(master, from, 0, gas, nonce, 1, 1, payload, cid)
        }
        None => sign_pq_explicit_payload(master, from, 0, gas, nonce, 1, 1, payload),
    }
}

/// Build the transaction that carries one or more teleport-bridge intents.
///
/// TRANSPORT + NATIVE LEG + POLICY: every intent rides in the payload, so it is
/// bound into the tx hash and reaches every node through a block. A DEPOSIT is
/// always built as the pair `[Attest, Deposit]` - `BridgeState::plan` counts the
/// attestations carried by the SAME transaction as the claim they authorize and
/// refuses a claim without a 2/3 quorum of the committed relayer set, so a
/// deposit submitted alone is refused by every block. Settlement then runs the
/// §8 policy and only moves coins when it passes.
///
/// Gas is priced PER OPCODE, so a two-op payload declares two bridge budgets
/// (still floored by the admission base fee).
pub(crate) fn build_bridge_intent_tx(
    signer: &stellereum::post_quantum::FalconKeypair,
    intents: &[stellereum::bridge::BridgeIntent],
    nonce: u64,
) -> Transaction {
    build_bridge_intent_tx_inner(signer, intents, nonce, None)
}

/// Chain-bound variant of [`build_bridge_intent_tx`].
pub(crate) fn build_bridge_intent_tx_with_chain(
    signer: &stellereum::post_quantum::FalconKeypair,
    intents: &[stellereum::bridge::BridgeIntent],
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    build_bridge_intent_tx_inner(signer, intents, nonce, Some(chain_id))
}

fn build_bridge_intent_tx_inner(
    signer: &stellereum::post_quantum::FalconKeypair,
    intents: &[stellereum::bridge::BridgeIntent],
    nonce: u64,
    chain_id: Option<u64>,
) -> Transaction {
    assert!(
        !intents.is_empty(),
        "a bridge transaction always carries at least one intent"
    );
    let from = falcon_pq_address(signer);
    let gas = cli_tx_gas(stellereum::svm::GAS_BRIDGE_INTENT * intents.len() as u64)
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    let payload: Vec<stellereum::svm::OpCode> = intents
        .iter()
        .map(|i| stellereum::svm::OpCode::SysCallBridge(Box::new(i.clone())))
        .collect();
    match chain_id {
        Some(cid) => {
            sign_pq_explicit_payload_with_chain(signer, from, 0, gas, nonce, 1, 1, payload, cid)
        }
        None => sign_pq_explicit_payload(signer, from, 0, gas, nonce, 1, 1, payload),
    }
}

/// Build the LIVE unjail transaction (pentest F7).
///
/// The ledger's `unjail` is height-gated: it only succeeds at/after
/// `release_height` AND when the self-bond is back at MIN+buffer. This
/// builder emits, in ONE PQ-enveloped payload:
///
///   1. `SysCallStake { validator, amount }` when `top_up` is supplied
///      (the ledger routes an existing validator through `add_bond`; the VM
///      funds it from the signer and moves it into `STAKING_POOL`), then
///   2. `SysCallUnjail { validator }`, applied by the block at
///      `block.height` with the same signature/fee rules as every other
///      transaction.
///
/// A `top_up` below the governed minimum is refused by the VM (same rule as
/// any other stake), so callers that need to climb back to MIN+buffer must
/// pass at least the current minimum. Without `top_up` the payload is a
/// single unjail, which is correct when the bond already cleared the floor.
///
/// Gas is priced PER OPCODE and floored by the admission base fee, exactly
/// like `build_bridge_intent_tx`.
/// Default declared gas limit for an unjail transaction (with optional self-bond top-up).
pub(crate) fn unjail_default_gas(top_up: Option<u64>) -> u64 {
    let mut opcode_gas = stellereum::svm::GAS_STAKE_UNBOND;
    if let Some(amount) = top_up {
        assert!(
            amount > 0,
            "a top-up must be positive; omit --top-up instead of passing zero"
        );
        opcode_gas = opcode_gas.saturating_add(stellereum::svm::GAS_STAKE_BOND);
    }
    cli_tx_gas(opcode_gas).saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS)
}

#[allow(dead_code)] // GATE: convenience wrapper pinned by cli_chain_binding_tests and unit tests.
pub(crate) fn build_unjail_tx(
    signer: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    top_up: Option<u64>,
    nonce: u64,
) -> Transaction {
    build_unjail_tx_inner(signer, validator, top_up, nonce, None, None)
}

/// Variant of [`build_unjail_tx`] allowing an explicit gas override (`gas = default_gas.max(gas_override.unwrap_or(0))`).
pub(crate) fn build_unjail_tx_with_gas(
    signer: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    top_up: Option<u64>,
    nonce: u64,
    gas_override: Option<u64>,
) -> Transaction {
    build_unjail_tx_inner(signer, validator, top_up, nonce, None, gas_override)
}

/// Chain-bound variant of [`build_unjail_tx`].
#[allow(dead_code)] // GATE: convenience wrapper pinned by cli_chain_binding_tests and unit tests.
pub(crate) fn build_unjail_tx_with_chain(
    signer: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    top_up: Option<u64>,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    build_unjail_tx_inner(signer, validator, top_up, nonce, Some(chain_id), None)
}

/// Chain-bound variant of [`build_unjail_tx`] with an explicit gas override
/// (`gas = default_gas.max(gas_override.unwrap_or(0))`) for elevated D2 fee floors.
pub(crate) fn build_unjail_tx_with_chain_and_gas(
    signer: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    top_up: Option<u64>,
    nonce: u64,
    chain_id: u64,
    gas_override: Option<u64>,
) -> Transaction {
    build_unjail_tx_inner(
        signer,
        validator,
        top_up,
        nonce,
        Some(chain_id),
        gas_override,
    )
}

fn build_unjail_tx_inner(
    signer: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    top_up: Option<u64>,
    nonce: u64,
    chain_id: Option<u64>,
    gas_override: Option<u64>,
) -> Transaction {
    let from = falcon_pq_address(signer);
    let mut payload = Vec::new();
    if let Some(amount) = top_up {
        assert!(
            amount > 0,
            "a top-up must be positive; omit --top-up instead of passing zero"
        );
        payload.push(stellereum::svm::OpCode::SysCallStake { validator, amount });
    }
    payload.push(stellereum::svm::OpCode::SysCallUnjail { validator });
    let default_gas = unjail_default_gas(top_up);
    let gas = default_gas.max(gas_override.unwrap_or(0));
    let master = stellereum::sharding::MASTERCHAIN_SHARD;
    match chain_id {
        Some(cid) => sign_pq_explicit_payload_with_chain(
            signer, from, 0, gas, nonce, master, master, payload, cid,
        ),
        None => sign_pq_explicit_payload(signer, from, 0, gas, nonce, master, master, payload),
    }
}

/// Resolve the validator/relayer keys that will attest a deposit claim.
///
/// Helpers for `wallet sign` / `wallet verify` (WALLET SIGNATURE STANDARD).
///
/// The wallet signs LOCALLY: the key material never leaves this machine and
/// is never sent to a node. `stell_signMessage` exists for testing/devnet
/// only; production wallets use these commands (or the library directly).
///
/// Parse a 32-byte hex seed (optional `0x` prefix).
pub(crate) fn parse_wallet_seed(raw: &str, what: &str) -> anyhow::Result<[u8; 32]> {
    let clean = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = zeroize::Zeroizing::new(
        hex::decode(clean).map_err(|e| anyhow::anyhow!("Invalid {what} hex: {e}"))?,
    );
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} must be 32 bytes, got {} bytes", bytes.len()))
}

/// Resolve a 32-byte Falcon-512 hex seed from `--falcon-seed-file`, `--falcon-seed`,
/// or the `STELL_FALCON_SEED` environment variable, zeroizing all read buffers.
pub(crate) fn resolve_falcon_seed(
    falcon_seed: Option<String>,
    falcon_seed_file: Option<PathBuf>,
) -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
    use zeroize::{Zeroize, Zeroizing};
    if let Some(path) = falcon_seed_file {
        let mut raw = Zeroizing::new(std::fs::read_to_string(&path).map_err(|e| {
            anyhow::anyhow!("cannot read falcon seed file {}: {e}", path.display())
        })?);
        let trimmed = Zeroizing::new(raw.trim().to_string());
        raw.zeroize();
        return Ok(Zeroizing::new(parse_wallet_seed(&trimmed, "falcon seed")?));
    }
    if let Some(mut raw) = falcon_seed {
        let trimmed = Zeroizing::new(raw.trim().to_string());
        raw.zeroize();
        return Ok(Zeroizing::new(parse_wallet_seed(&trimmed, "falcon seed")?));
    }
    if let Ok(mut env_val) = std::env::var("STELL_FALCON_SEED") {
        let trimmed = Zeroizing::new(env_val.trim().to_string());
        env_val.zeroize();
        if !trimmed.is_empty() {
            return Ok(Zeroizing::new(parse_wallet_seed(&trimmed, "falcon seed")?));
        }
    }
    anyhow::bail!(
        "missing falcon seed: pass --falcon-seed-file <path>, --falcon-seed <hex>, or set STELL_FALCON_SEED"
    );
}

/// Parse a 32-byte hex address (optional `0x` prefix).
pub(crate) fn parse_wallet_address(raw: &str) -> anyhow::Result<[u8; 32]> {
    parse_wallet_seed(raw, "address")
}

/// Build the wallet signing key the `sign` commands use.
///
/// Falcon-512 is the ONLY scheme: `--falcon-key-file` (a stored key,
/// preferred), `--falcon-seed-file`, `--falcon-seed`, or `STELL_FALCON_SEED`.
/// The classical `ed25519` and `hybrid` schemes are REMOVED and refused by
/// name; `--from-key` (an Ed25519 seed) is refused too, never silently
/// ignored.
pub(crate) fn resolve_wallet_signing_key(
    scheme: &str,
    from_key: Option<String>,
    falcon_key_file: Option<PathBuf>,
    falcon_seed: Option<String>,
    falcon_seed_file: Option<PathBuf>,
) -> anyhow::Result<stellereum::wallet_signing::WalletSigningKey> {
    use stellereum::wallet_signing::WalletSigningKey;
    if from_key.is_some() {
        anyhow::bail!(
            "--from-key (classical Ed25519 seed) is REMOVED: pass Falcon-512 material \
             with --falcon-key-file, --falcon-seed-file, or --falcon-seed"
        );
    }
    let load_falcon = || -> anyhow::Result<stellereum::post_quantum::FalconKeypair> {
        if let Some(path) = falcon_key_file.as_ref() {
            return stellereum::node_keys::load_falcon_key(path)
                .map_err(|e| anyhow::anyhow!("cannot load falcon key {}: {e}", path.display()));
        }
        let seed = resolve_falcon_seed(falcon_seed, falcon_seed_file)?;
        Ok(stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed))
    };
    match scheme {
        "falcon" => Ok(WalletSigningKey::Falcon {
            keypair: load_falcon()?,
        }),
        "ed25519" | "hybrid" => anyhow::bail!(
            "scheme '{scheme}' is REMOVED: classical Ed25519/Hybrid signing no longer \
             exists; only 'falcon' is accepted"
        ),
        other => anyhow::bail!("unknown scheme '{other}': expected 'falcon'"),
    }
}

/// Parse the structured typed-data fields the `sign-typed-data` /
/// `verify-typed-data` commands take.
pub(crate) fn parse_wallet_typed_data(
    contract: &str,
    method: &str,
    args: Option<&str>,
    value: u64,
    nonce: u64,
    chain_id: u64,
) -> anyhow::Result<stellereum::wallet_signing::TypedCallData> {
    let contract_bytes = parse_wallet_seed(contract, "contract address")?;
    let args_value = match args {
        None => serde_json::Value::Null,
        Some(raw) => {
            serde_json::from_str(raw).map_err(|e| anyhow::anyhow!("Invalid --args JSON: {e}"))?
        }
    };
    stellereum::wallet_signing::TypedCallData::new(
        &contract_bytes,
        method,
        args_value,
        value,
        nonce,
        chain_id,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// The quorum is counted at settlement against the COMMITTED staking set, so
/// only seeds whose public key is a bonded validator actually count. What the
/// CLI can offer is what the operator has on this machine:
///
///  * every `--attest-key` (32-byte hex seed, repeatable) - explicit wins;
///  * otherwise the local stand's node key at `<keys_dir>/identity.key`, the
///    very key `run` loads and `fund_genesis` bonds (a solo/dev stand has one
///    bonded validator, so `(1*2+2)/3 = 1` - that one signature IS the quorum).
///
/// FAILS LOUD instead of submitting an unattested claim: under §8 policy every
/// block refuses one, so a "successful" submission would be a deposit that
/// never credits and only fails later, where the operator cannot see why.
pub(crate) struct AttestKey {
    pub(crate) validator_id: [u8; 32],
    pub(crate) falcon: stellereum::post_quantum::FalconKeypair,
}

impl std::fmt::Debug for AttestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestKey")
            .field("validator_id", &hex::encode(self.validator_id))
            .finish_non_exhaustive()
    }
}

pub(crate) fn resolve_attest_keys(
    explicit: &[String],
    keys_dir: &std::path::Path,
) -> anyhow::Result<Vec<AttestKey>> {
    let mut keys: Vec<AttestKey> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in explicit {
        let clean = raw.strip_prefix("0x").unwrap_or(raw);
        let bytes =
            hex::decode(clean).map_err(|e| anyhow::anyhow!("invalid --attest-key hex: {e}"))?;
        let seed: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
            anyhow::anyhow!(
                "--attest-key must be a 32-byte hex seed, got {} bytes",
                b.len()
            )
        })?;
        let seed = zeroize::Zeroizing::new(seed);
        let k = SigningKey::from_bytes(&seed);
        let validator_id = k.verifying_key().to_bytes();
        if seen.insert(validator_id) {
            let falcon = stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed);
            keys.push(AttestKey {
                validator_id,
                falcon,
            });
        }
    }

    let mut default_err: Option<String> = None;
    // FULL-PQ: the default attestation key is the consensus-only Ed25519
    // `validator.key` (migrated once from the legacy identity.key). infnode
    // node identity is PQ and carries no Ed signing key.
    let has_consensus_key =
        keys_dir.join("validator.key").exists() || keys_dir.join("identity.key").exists();
    if keys.is_empty() && has_consensus_key {
        match stellereum::node_keys::load_or_generate_consensus_key(keys_dir) {
            Ok(consensus_key) => {
                let validator_id = consensus_key.verifying_key().to_bytes();
                let falcon_path = keys_dir.join("falcon.key");
                let falcon_res = if falcon_path.exists() {
                    stellereum::node_keys::load_falcon_key(&falcon_path)
                        .map_err(|e| format!("falcon key at {}: {e}", falcon_path.display()))
                } else {
                    let seed = zeroize::Zeroizing::new(consensus_key.to_bytes());
                    Ok(stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed))
                };
                match falcon_res {
                    Ok(falcon) => keys.push(AttestKey {
                        validator_id,
                        falcon,
                    }),
                    Err(e) => default_err = Some(e),
                }
            }
            Err(e) => default_err = Some(format!("identity key at {}: {e}", keys_dir.display())),
        }
    }

    if keys.is_empty() {
        let hint = default_err.map(|e| format!(" ({e})")).unwrap_or_default();
        anyhow::bail!(
            "no attestation key available{hint}: pass --attest-key <hex seed> once per bonded \
             validator you hold - a deposit without a 2/3 quorum of the committed relayer set \
             is refused by every block"
        );
    }
    Ok(keys)
}

/// Assemble the `BridgeIntent::Attest` bundle that authorizes `deposit`.
///
/// The signers cover `TeleportBridgeEngine::deposit_signing_message` of the
/// deposit - the exact message `BridgeState::plan` verifies at settlement,
/// against the committed staking set, counting DISTINCT validators. Duplicated
/// seeds are collapsed: the quorum counts validators, not signatures.
pub(crate) fn attest_for(
    deposit: &stellereum::bridge::BridgeIntent,
    keys: &[AttestKey],
) -> anyhow::Result<stellereum::bridge::BridgeIntent> {
    let source_tx_hash = match deposit {
        stellereum::bridge::BridgeIntent::Deposit { source_tx_hash, .. } => *source_tx_hash,
        other => anyhow::bail!("attestations only pair with a deposit intent, not {other:?}"),
    };
    if keys.is_empty() {
        anyhow::bail!("an attestation bundle must carry at least one signature");
    }
    let event = deposit
        .deposit_event(Vec::new())
        .expect("a Deposit always yields its event");
    let msg = TeleportBridgeEngine::deposit_signing_message(&event);
    let mut seen = std::collections::HashSet::new();
    let mut signatures = Vec::with_capacity(keys.len());
    for k in keys {
        if seen.insert(k.validator_id) {
            let sig = k.falcon.sign(&msg);
            if sig.len() != stellereum::post_quantum::FALCON512_SIG_LEN {
                anyhow::bail!(
                    "Falcon-512 attestation signature failed closed (got {} bytes)",
                    sig.len()
                );
            }
            signatures.push((k.validator_id, sig));
        }
    }
    Ok(stellereum::bridge::BridgeIntent::Attest {
        source_tx_hash,
        signatures,
    })
}

/// Maximum JSON-RPC response size accepted by CLI commands (16 MiB).
pub(crate) const MAX_CLI_RPC_BYTES: usize = 16 * 1024 * 1024;

/// Bounded HTTP agent for CLI JSON-RPC requests: 15s timeout, no redirects,
/// and no ambient `HTTP_PROXY`/`HTTPS_PROXY` pickup. Plain `http://` remains
/// allowed so localhost / 127.0.0.1 node RPC and tests work unchanged.
pub(crate) fn cli_http_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(15))
        .redirects(0)
        .try_proxy_from_env(false)
        .build()
}

fn cli_read_json_response_with_cap(
    resp: ureq::Response,
    rpc: &str,
    max_bytes: usize,
) -> anyhow::Result<serde_json::Value> {
    use std::io::Read as _;
    let status = resp.status();
    if (300..400).contains(&status) {
        anyhow::bail!("refusing HTTP redirect (status {status}) from {rpc}");
    }
    if !(200..300).contains(&status) {
        anyhow::bail!("unexpected HTTP status {status} from {rpc}");
    }
    let mut buf = Vec::new();
    resp.into_reader()
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut buf)?;
    if buf.len() > max_bytes {
        anyhow::bail!("RPC response from {rpc} exceeded maximum allowed size of {max_bytes} bytes");
    }
    Ok(serde_json::from_slice(&buf)?)
}

/// Read a JSON response body from `resp`, refusing HTTP redirects / unexpected
/// non-2xx statuses and capping the read at [`MAX_CLI_RPC_BYTES`].
pub(crate) fn cli_read_json_response(
    resp: ureq::Response,
    rpc: &str,
) -> anyhow::Result<serde_json::Value> {
    cli_read_json_response_with_cap(resp, rpc, MAX_CLI_RPC_BYTES)
}

/// POST a JSON-RPC request body to `rpc` using [`cli_http_agent`] and parse the
/// bounded JSON response.
pub(crate) fn cli_post_json(rpc: &str, body: &str) -> anyhow::Result<serde_json::Value> {
    let resp = cli_http_agent().post(rpc).send_string(body)?;
    cli_read_json_response(resp, rpc)
}

/// Query a node for an account's nonce, so consecutive CLI submissions do not
/// replay each other. The address is the PUBLIC key - querying with the seed
/// silently returns a fresh account every time.
pub(crate) fn rpc_account_nonce(rpc: &str, account: &[u8; 32]) -> anyhow::Result<u64> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "stell_getBalance",
        "params": { "address": hex::encode(account) }
    })
    .to_string();
    let resp = cli_post_json(rpc, &body)?;
    if let Some(e) = resp.get("error") {
        anyhow::bail!("RPC error: {e}");
    }
    resp["result"]
        .get("nonce")
        .and_then(|n| n.as_u64())
        .ok_or_else(|| anyhow::anyhow!("node did not return an account nonce"))
}

/// Submit a signed transaction to a node's mempool.
///
/// This is only admission: the node verifies the signature and the balance and
/// gossips it, and the transaction becomes state when a proposer includes it
/// in a block. Nothing is written by this call.
pub(crate) fn rpc_submit_tx(
    rpc: &str,
    method: &str,
    tx: &Transaction,
    token: Option<&str>,
) -> anyhow::Result<String> {
    let raw = hex::encode(bincode::serialize(tx)?);
    let mut params = serde_json::json!({ "tx": raw });
    if let Some(t) = token {
        params["token"] = serde_json::json!(t);
    }
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params
    })
    .to_string();
    let resp = cli_post_json(rpc, &body)?;
    if let Some(e) = resp.get("error") {
        anyhow::bail!("rejected by node: {e}");
    }
    Ok(resp["result"].as_str().unwrap_or("?").to_string())
}

/// Parse a `--chain` / `--target-chain` string into the bridge's own enum, so
/// a typo is refused here instead of silently becoming some other chain.
pub(crate) fn parse_supported_chain(
    raw: &str,
) -> anyhow::Result<stellereum::bridge::SupportedChain> {
    use stellereum::bridge::SupportedChain;
    Ok(match raw.to_lowercase().as_str() {
        "ton" => SupportedChain::Ton,
        "arbitrum" => SupportedChain::Arbitrum,
        "ethereum" | "eth" => SupportedChain::Ethereum,
        "solana" => SupportedChain::Solana,
        other => anyhow::bail!("unknown chain {other:?} (expected ton|arbitrum|ethereum|solana)"),
    })
}

/// True when a chain-binding activation height is scheduled (the production
/// constant or, in debug builds, `STELL_CHAIN_BIND_ACTIVATION_HEIGHT`).
///
/// The CLI cannot know the node's committed height before it connects, so a
/// scheduled activation is treated as "binding required": an unresolvable
/// chain id is an error rather than an unbound signature that the node will
/// refuse at admission.
pub(crate) fn chain_binding_scheduled() -> bool {
    stellereum::chain_binding::ChainBindingActivation::from_chain_spec().height
        != stellereum::chain_binding::CHAIN_BINDING_NEVER
}

/// Resolve the chain id a CLI transaction must be bound to.
///
/// * `explicit` (`--chain-id`) always wins.
/// * Otherwise ask the node via `stell_chainId`.
/// * If the RPC is unavailable / returns an error:
///   - with chain binding scheduled, FAIL CLOSED (never bind to `0`, never
///     fall back to an unbound signature the chain will reject);
///   - with binding not scheduled, return `None` so the pre-activation
///     unbound transaction shape is preserved byte-for-byte for existing
///     scripts.
///
/// Offline use (`--dry-run` without a reachable node) must therefore pass
/// `--chain-id` once activation is scheduled.
pub(crate) fn resolve_chain_id(rpc: &str, explicit: Option<u64>) -> anyhow::Result<Option<u64>> {
    if let Some(chain_id) = explicit {
        return Ok(Some(chain_id));
    }

    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "stell_chainId", "params": []
    })
    .to_string();
    let scheduled = chain_binding_scheduled();
    let failure = |detail: String| -> anyhow::Result<Option<u64>> {
        if scheduled {
            anyhow::bail!(
                "cannot resolve chain id from {rpc}: {detail}; chain binding is scheduled, so \
                 pass --chain-id <id> (an unbound transaction would be refused at admission)"
            );
        }
        eprintln!(
            "warning: cannot resolve chain id from {rpc}: {detail}; \
             building an UNBOUND transaction (admitted only while chain binding is inactive)"
        );
        Ok(None)
    };

    let resp: serde_json::Value = match cli_http_agent().post(rpc).send_string(&body) {
        Ok(resp) => match cli_read_json_response(resp, rpc) {
            Ok(json) => json,
            Err(e) => return failure(format!("invalid JSON response: {e}")),
        },
        Err(e) => return failure(format!("RPC unavailable: {e}")),
    };
    if let Some(e) = resp.get("error") {
        return failure(format!("RPC error: {e}"));
    }
    match resp.get("result").and_then(|v| v.as_u64()) {
        Some(chain_id) => Ok(Some(chain_id)),
        None => failure("node did not return a chain id".to_string()),
    }
}

/// Resolve the sender nonce: an explicit `--nonce`, or the account's current
/// on-chain nonce from the node.
pub(crate) fn resolve_nonce(
    rpc: &str,
    account: &[u8; 32],
    nonce: Option<u64>,
) -> anyhow::Result<u64> {
    match nonce {
        Some(n) => Ok(n),
        None => rpc_account_nonce(rpc, account),
    }
}

/// Resolve a Falcon-512 keypair from either a key file (`--*-key-file`) or a
/// 32-byte hex seed (`--*-seed`).
pub(crate) fn resolve_falcon_keypair(
    key_file: Option<PathBuf>,
    seed_hex: Option<String>,
    what: &str,
) -> anyhow::Result<stellereum::post_quantum::FalconKeypair> {
    if let Some(path) = key_file {
        return stellereum::node_keys::load_falcon_key(&path)
            .map_err(|e| anyhow::anyhow!("cannot load {what} key {}: {e}", path.display()));
    }
    if let Some(raw) = seed_hex {
        return falcon_from_hex_seed(&raw, what);
    }
    anyhow::bail!("missing {what} key: pass key file or 32-byte hex seed");
}

/// Resolve a Falcon-512 keypair from `--falcon-key-file`, `--falcon-seed-file`,
/// `--falcon-seed`, or `STELL_FALCON_SEED`.
pub(crate) fn resolve_falcon_keypair_with_seed_file(
    key_file: Option<PathBuf>,
    seed_hex: Option<String>,
    seed_file: Option<PathBuf>,
    what: &str,
) -> anyhow::Result<stellereum::post_quantum::FalconKeypair> {
    if let Some(path) = key_file {
        return stellereum::node_keys::load_falcon_key(&path)
            .map_err(|e| anyhow::anyhow!("cannot load {what} key {}: {e}", path.display()));
    }
    let seed = resolve_falcon_seed(seed_hex, seed_file)?;
    Ok(stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed))
}

/// Resolve an explicit `--chain-id` or query `stell_chainId` fail-closed.
/// Used by W3 PQ validator lifecycle commands where PoP signatures always bind
/// `chain_id`.
pub(crate) fn resolve_required_chain_id(rpc: &str, explicit: Option<u64>) -> anyhow::Result<u64> {
    if let Some(cid) = explicit {
        return Ok(cid);
    }
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "stell_chainId", "params": []
    })
    .to_string();
    let resp = cli_http_agent()
        .post(rpc)
        .send_string(&body)
        .map_err(|e| anyhow::anyhow!("cannot resolve chain_id from {rpc}: {e}; pass --chain-id"))?;
    let resp = cli_read_json_response(resp, rpc)
        .map_err(|e| anyhow::anyhow!("invalid stell_chainId JSON from {rpc}: {e}"))?;
    if let Some(e) = resp.get("error") {
        anyhow::bail!("stell_chainId error from {rpc}: {e}");
    }
    resp.get("result")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("node at {rpc} did not return chain_id; pass --chain-id"))
}

/// Build a chain-bound `OpCode 59: SysCallRegisterValidator` transaction with
/// Falcon-512 PoP signed by `voting_key` at `rotation_seq = 0`.
pub(crate) fn build_register_validator_tx_with_chain(
    withdrawal_key: &stellereum::post_quantum::FalconKeypair,
    voting_key: &stellereum::post_quantum::FalconKeypair,
    amount: u64,
    commission_bps: u64,
    nonce: u64,
    chain_id: u64,
) -> (Transaction, [u8; 32]) {
    let withdrawal_address = falcon_pq_address(withdrawal_key);
    let validator_id = stellereum::pq_registry::derive_validator_id(
        chain_id,
        &withdrawal_address,
        &voting_key.public_key,
    );
    let pop_msg = stellereum::pq_registry::pq_voting_key_pop_preimage(
        chain_id,
        &validator_id,
        &withdrawal_address,
        0,
        stellereum::post_quantum::PqScheme::Falcon512,
        &voting_key.public_key,
    );
    let voting_pop = voting_key.sign(&pop_msg);
    let op = stellereum::svm::OpCode::SysCallRegisterValidator(Box::new(
        stellereum::svm::RegisterValidatorPayload {
            amount,
            commission_bps,
            withdrawal_address,
            voting_scheme: stellereum::post_quantum::PqScheme::Falcon512.id(),
            voting_pubkey: voting_key.public_key.clone(),
            voting_pop,
        },
    ));
    let gas = cli_tx_gas(stellereum::svm::opcode_gas(&op))
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    let tx = sign_pq_explicit_payload_with_chain(
        withdrawal_key,
        withdrawal_address,
        0,
        gas,
        nonce,
        stellereum::sharding::MASTERCHAIN_SHARD,
        stellereum::sharding::MASTERCHAIN_SHARD,
        vec![op],
        chain_id,
    );
    (tx, validator_id)
}

/// Build a chain-bound `OpCode 60: SysCallRotateVotingKey` transaction
/// (announce with Falcon-512 PoP when `new_voting_key` is `Some`, or cancel
/// when `None`).
pub(crate) fn build_rotate_voting_key_tx_with_chain(
    withdrawal_key: &stellereum::post_quantum::FalconKeypair,
    validator_id: [u8; 32],
    rotation_seq: u64,
    new_voting_key: Option<&stellereum::post_quantum::FalconKeypair>,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    let withdrawal_address = falcon_pq_address(withdrawal_key);
    let payload = match new_voting_key {
        Some(new_kp) => {
            let pop_msg = stellereum::pq_registry::pq_voting_key_pop_preimage(
                chain_id,
                &validator_id,
                &withdrawal_address,
                rotation_seq,
                stellereum::post_quantum::PqScheme::Falcon512,
                &new_kp.public_key,
            );
            let pop_signature = new_kp.sign(&pop_msg);
            stellereum::svm::RotateVotingKeyPayload {
                validator_id,
                rotation_seq,
                new_scheme: stellereum::post_quantum::PqScheme::Falcon512.id(),
                new_pubkey: new_kp.public_key.clone(),
                pop_signature,
                cancel: false,
            }
        }
        None => stellereum::svm::RotateVotingKeyPayload {
            validator_id,
            rotation_seq,
            new_scheme: 0,
            new_pubkey: Vec::new(),
            pop_signature: Vec::new(),
            cancel: true,
        },
    };
    let op = stellereum::svm::OpCode::SysCallRotateVotingKey(Box::new(payload));
    let gas = cli_tx_gas(stellereum::svm::opcode_gas(&op))
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    sign_pq_explicit_payload_with_chain(
        withdrawal_key,
        withdrawal_address,
        0,
        gas,
        nonce,
        stellereum::sharding::MASTERCHAIN_SHARD,
        stellereum::sharding::MASTERCHAIN_SHARD,
        vec![op],
        chain_id,
    )
}

/// Build a chain-bound `OpCode 61: SysCallChangeWithdrawal` transaction with
/// Falcon-512 PoP signed by `new_withdrawal_key`.
pub(crate) fn build_change_withdrawal_tx_with_chain(
    current_withdrawal_key: &stellereum::post_quantum::FalconKeypair,
    validator_id: [u8; 32],
    new_withdrawal_key: &stellereum::post_quantum::FalconKeypair,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    let current_withdrawal_address = falcon_pq_address(current_withdrawal_key);
    let new_withdrawal_address = falcon_pq_address(new_withdrawal_key);
    let pop_msg = stellereum::staking::pq_withdrawal_pop_preimage(
        chain_id,
        &validator_id,
        &current_withdrawal_address,
        &new_withdrawal_address,
    );
    let new_withdrawal_pop = new_withdrawal_key.sign(&pop_msg);
    let op = stellereum::svm::OpCode::SysCallChangeWithdrawal(Box::new(
        stellereum::svm::ChangeWithdrawalPayload {
            validator_id,
            new_withdrawal_address,
            new_withdrawal_scheme: stellereum::post_quantum::PqScheme::Falcon512.id(),
            new_withdrawal_pubkey: new_withdrawal_key.public_key.clone(),
            new_withdrawal_salt: stellereum::post_quantum::DEFAULT_SALT,
            new_withdrawal_pop,
        },
    ));
    let gas = cli_tx_gas(stellereum::svm::opcode_gas(&op))
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    sign_pq_explicit_payload_with_chain(
        current_withdrawal_key,
        current_withdrawal_address,
        0,
        gas,
        nonce,
        stellereum::sharding::MASTERCHAIN_SHARD,
        stellereum::sharding::MASTERCHAIN_SHARD,
        vec![op],
        chain_id,
    )
}

/// Build a chain-bound `OpCode 62: SysCallClaimWithdrawal` transaction signed
/// by `withdrawal_key` (`ctx.sender`) and attested by `voting_key`.
pub(crate) fn build_claim_withdrawal_tx_with_chain(
    withdrawal_key: &stellereum::post_quantum::FalconKeypair,
    validator_id: [u8; 32],
    voting_key: &stellereum::post_quantum::FalconKeypair,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    let withdrawal_address = falcon_pq_address(withdrawal_key);
    let claim_msg = stellereum::staking::pq_claim_withdrawal_preimage(
        chain_id,
        &validator_id,
        &withdrawal_address,
    );
    let voting_sig = voting_key.sign(&claim_msg);
    let op = stellereum::svm::OpCode::SysCallClaimWithdrawal(Box::new(
        stellereum::svm::ClaimWithdrawalPayload {
            validator_id,
            withdrawal_address,
            voting_sig,
        },
    ));
    let gas = cli_tx_gas(stellereum::svm::opcode_gas(&op))
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    sign_pq_explicit_payload_with_chain(
        withdrawal_key,
        withdrawal_address,
        0,
        gas,
        nonce,
        stellereum::sharding::MASTERCHAIN_SHARD,
        stellereum::sharding::MASTERCHAIN_SHARD,
        vec![op],
        chain_id,
    )
}

/// Build a chain-bound `OpCode 63: SysCallAnnounceCommission` transaction.
pub(crate) fn build_announce_commission_tx_with_chain(
    withdrawal_key: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    new_bps: u64,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    let withdrawal_address = falcon_pq_address(withdrawal_key);
    let op = stellereum::svm::OpCode::SysCallAnnounceCommission { validator, new_bps };
    let gas = cli_tx_gas(stellereum::svm::opcode_gas(&op))
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    sign_pq_explicit_payload_with_chain(
        withdrawal_key,
        withdrawal_address,
        0,
        gas,
        nonce,
        stellereum::sharding::MASTERCHAIN_SHARD,
        stellereum::sharding::MASTERCHAIN_SHARD,
        vec![op],
        chain_id,
    )
}

/// Build a chain-bound `OpCode 64: SysCallApplyCommission` transaction.
pub(crate) fn build_apply_commission_tx_with_chain(
    withdrawal_key: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    let withdrawal_address = falcon_pq_address(withdrawal_key);
    let op = stellereum::svm::OpCode::SysCallApplyCommission { validator };
    let gas = cli_tx_gas(stellereum::svm::opcode_gas(&op))
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    sign_pq_explicit_payload_with_chain(
        withdrawal_key,
        withdrawal_address,
        0,
        gas,
        nonce,
        stellereum::sharding::MASTERCHAIN_SHARD,
        stellereum::sharding::MASTERCHAIN_SHARD,
        vec![op],
        chain_id,
    )
}

/// Parse a CLI governance vote choice string (`yes`, `no`, `abstain`, case-insensitive).
pub(crate) fn parse_vote_choice(raw: &str) -> anyhow::Result<stellereum::governance::VoteChoice> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "yes" => Ok(stellereum::governance::VoteChoice::Yes),
        "no" => Ok(stellereum::governance::VoteChoice::No),
        "abstain" => Ok(stellereum::governance::VoteChoice::Abstain),
        other => anyhow::bail!("invalid vote choice '{other}': expected yes, no, or abstain"),
    }
}

/// Build a chain-bound `OpCode::SysCallGovPropose` transaction on the masterchain shard.
#[allow(clippy::too_many_arguments)]
// GATE: explicit PQ1 chain-bound governance proposal builder requires all tx and proposal parameters.
pub(crate) fn build_gov_propose_tx_with_chain(
    proposer: &stellereum::post_quantum::FalconKeypair,
    proposal_id: u64,
    title: String,
    action: stellereum::governance::GovAction,
    height_observed: u64,
    nonce: u64,
    chain_id: u64,
) -> anyhow::Result<Transaction> {
    let from = falcon_pq_address(proposer);
    let op = stellereum::governance::Governance::gov_propose_opcode(
        proposal_id,
        title,
        action,
        height_observed,
    )
    .map_err(|e| anyhow::anyhow!("invalid governance proposal: {e}"))?;
    let gas = cli_tx_gas(stellereum::svm::opcode_gas(&op))
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    Ok(sign_pq_explicit_payload_with_chain(
        proposer,
        from,
        0,
        gas,
        nonce,
        stellereum::sharding::MASTERCHAIN_SHARD,
        stellereum::sharding::MASTERCHAIN_SHARD,
        vec![op],
        chain_id,
    ))
}

/// Build a chain-bound `OpCode::SysCallGovVote` transaction on the masterchain shard.
pub(crate) fn build_gov_vote_tx_with_chain(
    voter: &stellereum::post_quantum::FalconKeypair,
    proposal_id: u64,
    choice: stellereum::governance::VoteChoice,
    height_observed: u64,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    let from = falcon_pq_address(voter);
    let op =
        stellereum::governance::Governance::gov_vote_opcode(proposal_id, choice, height_observed);
    let gas = cli_tx_gas(stellereum::svm::opcode_gas(&op))
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    sign_pq_explicit_payload_with_chain(
        voter,
        from,
        0,
        gas,
        nonce,
        stellereum::sharding::MASTERCHAIN_SHARD,
        stellereum::sharding::MASTERCHAIN_SHARD,
        vec![op],
        chain_id,
    )
}

fn build_masterchain_op_tx_with_chain(
    signer: &stellereum::post_quantum::FalconKeypair,
    op: stellereum::svm::OpCode,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    let from = falcon_pq_address(signer);
    let gas = cli_tx_gas(stellereum::svm::opcode_gas(&op))
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    sign_pq_explicit_payload_with_chain(
        signer,
        from,
        0,
        gas,
        nonce,
        stellereum::sharding::MASTERCHAIN_SHARD,
        stellereum::sharding::MASTERCHAIN_SHARD,
        vec![op],
        chain_id,
    )
}

/// Build a chain-bound `OpCode::SysCallStake` transaction on the masterchain shard.
pub(crate) fn build_stake_tx_with_chain(
    withdrawal_key: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    amount: u64,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    build_masterchain_op_tx_with_chain(
        withdrawal_key,
        stellereum::svm::OpCode::SysCallStake { validator, amount },
        nonce,
        chain_id,
    )
}

/// Build a chain-bound `OpCode::SysCallUnbond` transaction on the masterchain shard.
pub(crate) fn build_unbond_tx_with_chain(
    withdrawal_key: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    amount: u64,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    build_masterchain_op_tx_with_chain(
        withdrawal_key,
        stellereum::svm::OpCode::SysCallUnbond { validator, amount },
        nonce,
        chain_id,
    )
}

/// Build a chain-bound `OpCode::SysCallWithdrawSelfBond` transaction on the masterchain shard.
pub(crate) fn build_withdraw_self_bond_tx_with_chain(
    withdrawal_key: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    build_masterchain_op_tx_with_chain(
        withdrawal_key,
        stellereum::svm::OpCode::SysCallWithdrawSelfBond { validator },
        nonce,
        chain_id,
    )
}

/// Build a chain-bound `OpCode::SysCallDelegate` transaction on the masterchain shard.
pub(crate) fn build_delegate_tx_with_chain(
    delegator_key: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    amount: u64,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    build_masterchain_op_tx_with_chain(
        delegator_key,
        stellereum::svm::OpCode::SysCallDelegate { validator, amount },
        nonce,
        chain_id,
    )
}

/// Build a chain-bound `OpCode::SysCallBeginUndelegate` transaction on the masterchain shard.
pub(crate) fn build_begin_undelegate_tx_with_chain(
    delegator_key: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    amount: u64,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    build_masterchain_op_tx_with_chain(
        delegator_key,
        stellereum::svm::OpCode::SysCallBeginUndelegate { validator, amount },
        nonce,
        chain_id,
    )
}

/// Build a chain-bound `OpCode::SysCallUndelegate` (withdraw matured delegation) transaction on the masterchain shard.
pub(crate) fn build_withdraw_delegation_tx_with_chain(
    delegator_key: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    build_masterchain_op_tx_with_chain(
        delegator_key,
        stellereum::svm::OpCode::SysCallUndelegate { validator },
        nonce,
        chain_id,
    )
}

/// Build a chain-bound rewards claim transaction (`SysCallClaimRewards` or `SysCallClaimDelegatorRewards`).
pub(crate) fn build_claim_rewards_tx_with_chain(
    signer_key: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    delegator: bool,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    let op = if delegator {
        stellereum::svm::OpCode::SysCallClaimDelegatorRewards { validator }
    } else {
        stellereum::svm::OpCode::SysCallClaimRewards { validator }
    };
    build_masterchain_op_tx_with_chain(signer_key, op, nonce, chain_id)
}

/// Build a Falcon-512 PQ1 `OpCode::SysCallDeployContract` transaction.
pub(crate) fn build_contract_deploy_tx(
    deployer: &stellereum::post_quantum::FalconKeypair,
    code: Vec<u8>,
    nonce: u64,
    gas_limit: Option<u64>,
    chain_id: Option<u64>,
) -> anyhow::Result<Transaction> {
    if code.is_empty() {
        anyhow::bail!("contract WASM bytecode cannot be empty");
    }
    if code.len() > stellereum::contract::MAX_CONTRACT_CODE_SIZE {
        anyhow::bail!(
            "contract WASM bytecode ({} bytes) exceeds maximum {} bytes",
            code.len(),
            stellereum::contract::MAX_CONTRACT_CODE_SIZE
        );
    }
    let from = falcon_pq_address(deployer);
    let opcode_gas = stellereum::svm::contract_deploy_gas(code.len());
    let default_gas =
        cli_tx_gas(opcode_gas).saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    let gas = default_gas.max(gas_limit.unwrap_or(0));
    let master = stellereum::sharding::MASTERCHAIN_SHARD;
    let payload = vec![stellereum::svm::OpCode::SysCallDeployContract { code }];
    Ok(match chain_id {
        Some(cid) => sign_pq_explicit_payload_with_chain(
            deployer, from, 0, gas, nonce, master, master, payload, cid,
        ),
        None => sign_pq_explicit_payload(deployer, from, 0, gas, nonce, master, master, payload),
    })
}

/// Parse `--method` and optional `--args` / `--calldata` into either
/// `OpCode::SysCallCallContract` (single `i64`) or `OpCode::SysCallCallContractArgs`
/// (0 args, multi-arg, STELL-ABI v1 `AbiValue`-encoded calldata, or raw hex calldata).
pub(crate) fn parse_contract_call_opcode_with_calldata(
    contract: [u8; 32],
    method: &str,
    args: Option<&str>,
    calldata_hex: Option<&str>,
) -> anyhow::Result<stellereum::svm::OpCode> {
    if let Some(raw_cd) = calldata_hex {
        if args.is_some_and(|s| !s.trim().is_empty()) {
            anyhow::bail!("--args and --calldata cannot be combined");
        }
        if method.is_empty() {
            anyhow::bail!("contract method name cannot be empty");
        }
        if method.len() > stellereum::svm::MAX_CONTRACT_METHOD_LEN {
            anyhow::bail!(
                "contract method name ({} bytes) exceeds maximum {} bytes",
                method.len(),
                stellereum::svm::MAX_CONTRACT_METHOD_LEN
            );
        }
        let trimmed = raw_cd.trim();
        let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        let calldata =
            hex::decode(stripped).map_err(|e| anyhow::anyhow!("invalid --calldata hex: {e}"))?;
        if calldata.len() > stellereum::svm::MAX_CONTRACT_CALLDATA_BYTES {
            anyhow::bail!(
                "raw calldata ({} bytes) exceeds maximum {} bytes",
                calldata.len(),
                stellereum::svm::MAX_CONTRACT_CALLDATA_BYTES
            );
        }
        return Ok(stellereum::svm::OpCode::SysCallCallContractArgs {
            contract,
            method: method.as_bytes().to_vec(),
            args: Vec::new(),
            calldata,
        });
    }
    parse_contract_call_opcode(contract, method, args)
}

/// Parse `--method` and optional `--args` into either `OpCode::SysCallCallContract`
/// (single `i64`) or `OpCode::SysCallCallContractArgs` (0 args, multi-arg, or
/// STELL-ABI v1 `AbiValue`-encoded calldata).
pub(crate) fn parse_contract_call_opcode(
    contract: [u8; 32],
    method: &str,
    args: Option<&str>,
) -> anyhow::Result<stellereum::svm::OpCode> {
    if method.is_empty() {
        anyhow::bail!("contract method name cannot be empty");
    }
    if method.len() > stellereum::svm::MAX_CONTRACT_METHOD_LEN {
        anyhow::bail!(
            "contract method name ({} bytes) exceeds maximum {} bytes",
            method.len(),
            stellereum::svm::MAX_CONTRACT_METHOD_LEN
        );
    }
    let method_bytes = method.as_bytes().to_vec();
    let Some(raw) = args.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(stellereum::svm::OpCode::SysCallCallContractArgs {
            contract,
            method: method_bytes,
            args: Vec::new(),
            calldata: Vec::new(),
        });
    };
    if let Ok(single_arg) = raw.parse::<i64>() {
        return Ok(stellereum::svm::OpCode::SysCallCallContract {
            contract,
            method: method_bytes,
            arg: single_arg,
        });
    }
    let json_val: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| anyhow::anyhow!("invalid --args (expected i64 or JSON): {e}"))?;
    let abi_values = match json_val {
        serde_json::Value::Null => {
            return Ok(stellereum::svm::OpCode::SysCallCallContractArgs {
                contract,
                method: method_bytes,
                args: Vec::new(),
                calldata: Vec::new(),
            });
        }
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in &items {
                out.push(
                    stellereum::contract_abi::AbiValue::from_json_value(item)
                        .map_err(|e| anyhow::anyhow!("invalid contract argument: {e}"))?,
                );
            }
            out
        }
        other => vec![stellereum::contract_abi::AbiValue::from_json_value(&other)
            .map_err(|e| anyhow::anyhow!("invalid contract argument: {e}"))?],
    };
    if abi_values.len() > stellereum::contract_abi::MAX_ABI_ARGS {
        anyhow::bail!(
            "too many contract call arguments: got {}, maximum is {}",
            abi_values.len(),
            stellereum::contract_abi::MAX_ABI_ARGS
        );
    }
    let mut scalars = Vec::with_capacity(abi_values.len());
    let mut calldata = Vec::with_capacity(4 + abi_values.len() * 9);
    calldata.extend_from_slice(&(abi_values.len() as u32).to_le_bytes());
    for val in &abi_values {
        scalars.push(val.as_i64().unwrap_or(0));
        let encoded = val
            .encode()
            .map_err(|e| anyhow::anyhow!("failed to encode contract argument: {e}"))?;
        calldata.extend_from_slice(&encoded);
    }
    if calldata.len() > stellereum::svm::MAX_CONTRACT_CALLDATA_BYTES {
        anyhow::bail!(
            "encoded calldata ({} bytes) exceeds maximum {} bytes",
            calldata.len(),
            stellereum::svm::MAX_CONTRACT_CALLDATA_BYTES
        );
    }
    Ok(stellereum::svm::OpCode::SysCallCallContractArgs {
        contract,
        method: method_bytes,
        args: scalars,
        calldata,
    })
}

/// Build a Falcon-512 PQ1 contract call transaction.
pub(crate) fn build_contract_call_tx(
    caller: &stellereum::post_quantum::FalconKeypair,
    contract: [u8; 32],
    op: stellereum::svm::OpCode,
    value: u64,
    nonce: u64,
    gas_limit: Option<u64>,
    chain_id: Option<u64>,
) -> Transaction {
    let opcode_gas = stellereum::svm::opcode_gas(&op);
    let default_gas =
        cli_tx_gas(opcode_gas).saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    let gas = default_gas.max(gas_limit.unwrap_or(0));
    let master = stellereum::sharding::MASTERCHAIN_SHARD;
    let payload = vec![op];
    match chain_id {
        Some(cid) => sign_pq_explicit_payload_with_chain(
            caller, contract, value, gas, nonce, master, master, payload, cid,
        ),
        None => {
            sign_pq_explicit_payload(caller, contract, value, gas, nonce, master, master, payload)
        }
    }
}

/// True when a `host:port` listen address resolves strictly to loopback.
pub(crate) fn is_loopback_listen_addr(listen: &str) -> bool {
    let trimmed = listen.trim();
    if let Ok(sock) = trimmed.parse::<std::net::SocketAddr>() {
        return sock.ip().is_loopback();
    }
    if let Some((host, _port)) = trimmed.rsplit_once(':') {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.eq_ignore_ascii_case("localhost") {
            return true;
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return ip.is_loopback();
        }
    }
    trimmed.eq_ignore_ascii_case("localhost")
}

/// Enforce fail-closed remote-signer startup policy:
/// 1. Refuse non-loopback binds over plaintext HTTP unless `--allow-insecure-http`.
/// 2. Require a non-empty bearer token via `--token-file`, `--token`, or `STELL_REMOTE_SIGNER_TOKEN`.
pub(crate) fn validate_remote_signer_serve_policy(
    listen: &str,
    token: Option<String>,
    token_file: Option<PathBuf>,
    allow_insecure_http: bool,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    use zeroize::{Zeroize, Zeroizing};
    if !is_loopback_listen_addr(listen) && !allow_insecure_http {
        anyhow::bail!(
            "refusing to bind remote-signer on non-loopback address '{listen}' without TLS: \
             bind loopback (127.0.0.1 / [::1]) behind a TLS/mTLS terminator or pass \
             --allow-insecure-http explicitly"
        );
    }
    if let Some(path) = token_file {
        let mut raw = Zeroizing::new(std::fs::read_to_string(&path).map_err(|e| {
            anyhow::anyhow!(
                "cannot read remote-signer token file {}: {e}",
                path.display()
            )
        })?);
        let trimmed = Zeroizing::new(raw.trim().to_string());
        raw.zeroize();
        if trimmed.is_empty() {
            anyhow::bail!("remote-signer token file {} is empty", path.display());
        }
        return Ok(trimmed);
    }
    if let Some(mut raw) = token {
        let trimmed = Zeroizing::new(raw.trim().to_string());
        raw.zeroize();
        if trimmed.is_empty() {
            anyhow::bail!("remote-signer --token cannot be empty");
        }
        return Ok(trimmed);
    }
    if let Ok(mut env_val) = std::env::var(stellereum::remote_signer::REMOTE_SIGNER_TOKEN_ENV) {
        let trimmed = Zeroizing::new(env_val.trim().to_string());
        env_val.zeroize();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    anyhow::bail!(
        "refusing to start remote-signer without a bearer token: pass --token-file <PATH>, \
         --token <TOKEN>, or set {}",
        stellereum::remote_signer::REMOTE_SIGNER_TOKEN_ENV
    );
}

#[cfg(test)]
mod unjail_builder_tests {
    use super::*;

    #[test]
    fn unjail_builder_emits_optional_top_up_then_unjail() {
        let kp = stellereum::post_quantum::FalconKeypair::generate_from_seed(0x71);
        let validator = [0x99u8; 32];

        // No top-up: one unjail op on masterchain shard (0, 0), signed envelope verifies.
        let tx = build_unjail_tx(&kp, validator, None, 3);
        assert_eq!(tx.source_shard, stellereum::sharding::MASTERCHAIN_SHARD);
        assert_eq!(tx.target_shard, stellereum::sharding::MASTERCHAIN_SHARD);
        assert_eq!(tx.payload.len(), 1);
        assert!(matches!(
            tx.payload[0],
            stellereum::svm::OpCode::SysCallUnjail { validator: v } if v == validator
        ));
        assert!(tx.verify_signature());

        // With a top-up: stake FIRST, then unjail, same envelope rules and masterchain routing.
        let tx = build_unjail_tx(&kp, validator, Some(5_000_000_000), 4);
        assert_eq!(tx.source_shard, stellereum::sharding::MASTERCHAIN_SHARD);
        assert_eq!(tx.target_shard, stellereum::sharding::MASTERCHAIN_SHARD);
        assert_eq!(tx.payload.len(), 2);
        assert!(matches!(
            tx.payload[0],
            stellereum::svm::OpCode::SysCallStake { validator: v, amount }
                if v == validator && amount == 5_000_000_000
        ));
        assert!(matches!(
            tx.payload[1],
            stellereum::svm::OpCode::SysCallUnjail { validator: v } if v == validator
        ));
        assert!(tx.verify_signature());
        assert_eq!(tx.nonce, 4);
    }

    #[test]
    fn parse_vote_choice_accepts_case_insensitive_and_rejects_invalid() {
        assert_eq!(
            parse_vote_choice("YES").unwrap(),
            stellereum::governance::VoteChoice::Yes
        );
        assert_eq!(
            parse_vote_choice("No").unwrap(),
            stellereum::governance::VoteChoice::No
        );
        assert_eq!(
            parse_vote_choice("abstain").unwrap(),
            stellereum::governance::VoteChoice::Abstain
        );
        assert!(parse_vote_choice("maybe").is_err());
    }

    #[test]
    fn gov_and_validator_builders_route_on_masterchain_and_verify() {
        let kp = stellereum::post_quantum::FalconKeypair::generate_from_seed(0x82);
        let validator = [0x44u8; 32];
        let cid = stellereum::consensus::consensus_chain_id();

        let action = stellereum::governance::gov_action_from_params(
            "signal",
            &serde_json::json!({ "text": "upgrade check" }),
        )
        .unwrap();
        let propose_tx =
            build_gov_propose_tx_with_chain(&kp, 7, "Signal #7".into(), action, 42, 1, cid)
                .unwrap();
        assert_eq!(
            propose_tx.source_shard,
            stellereum::sharding::MASTERCHAIN_SHARD
        );
        assert_eq!(
            propose_tx.target_shard,
            stellereum::sharding::MASTERCHAIN_SHARD
        );
        assert!(propose_tx.verify_signature_for_chain(cid, true));
        assert!(matches!(
            &propose_tx.payload[0],
            stellereum::svm::OpCode::SysCallGovPropose {
                proposal_id: 7,
                height_observed: 42,
                ..
            }
        ));

        let vote_tx = build_gov_vote_tx_with_chain(
            &kp,
            7,
            stellereum::governance::VoteChoice::Yes,
            43,
            2,
            cid,
        );
        assert_eq!(
            vote_tx.source_shard,
            stellereum::sharding::MASTERCHAIN_SHARD
        );
        assert_eq!(
            vote_tx.target_shard,
            stellereum::sharding::MASTERCHAIN_SHARD
        );
        assert!(vote_tx.verify_signature_for_chain(cid, true));
        assert!(matches!(
            vote_tx.payload[0],
            stellereum::svm::OpCode::SysCallGovVote {
                proposal_id: 7,
                choice: stellereum::governance::VoteChoice::Yes,
                height_observed: 43,
            }
        ));

        let stake_tx = build_stake_tx_with_chain(&kp, validator, 1_000_000_000, 3, cid);
        assert!(stake_tx.verify_signature_for_chain(cid, true));
        assert!(matches!(
            stake_tx.payload[0],
            stellereum::svm::OpCode::SysCallStake { validator: v, amount: 1_000_000_000 } if v == validator
        ));

        let unbond_tx = build_unbond_tx_with_chain(&kp, validator, 500_000_000, 4, cid);
        assert!(unbond_tx.verify_signature_for_chain(cid, true));
        assert!(matches!(
            unbond_tx.payload[0],
            stellereum::svm::OpCode::SysCallUnbond { validator: v, amount: 500_000_000 } if v == validator
        ));

        let withdraw_tx = build_withdraw_self_bond_tx_with_chain(&kp, validator, 5, cid);
        assert!(withdraw_tx.verify_signature_for_chain(cid, true));
        assert!(matches!(
            withdraw_tx.payload[0],
            stellereum::svm::OpCode::SysCallWithdrawSelfBond { validator: v } if v == validator
        ));

        let del_tx = build_delegate_tx_with_chain(&kp, validator, 2_000_000_000, 6, cid);
        assert!(del_tx.verify_signature_for_chain(cid, true));
        assert!(matches!(
            del_tx.payload[0],
            stellereum::svm::OpCode::SysCallDelegate { validator: v, amount: 2_000_000_000 } if v == validator
        ));

        let begin_undel_tx =
            build_begin_undelegate_tx_with_chain(&kp, validator, 1_000_000_000, 7, cid);
        assert!(begin_undel_tx.verify_signature_for_chain(cid, true));
        assert!(matches!(
            begin_undel_tx.payload[0],
            stellereum::svm::OpCode::SysCallBeginUndelegate { validator: v, amount: 1_000_000_000 } if v == validator
        ));

        let withdraw_del_tx = build_withdraw_delegation_tx_with_chain(&kp, validator, 8, cid);
        assert!(withdraw_del_tx.verify_signature_for_chain(cid, true));
        assert!(matches!(
            withdraw_del_tx.payload[0],
            stellereum::svm::OpCode::SysCallUndelegate { validator: v } if v == validator
        ));

        let claim_val_tx = build_claim_rewards_tx_with_chain(&kp, validator, false, 9, cid);
        assert!(claim_val_tx.verify_signature_for_chain(cid, true));
        assert!(matches!(
            claim_val_tx.payload[0],
            stellereum::svm::OpCode::SysCallClaimRewards { validator: v } if v == validator
        ));

        let claim_del_tx = build_claim_rewards_tx_with_chain(&kp, validator, true, 10, cid);
        assert!(claim_del_tx.verify_signature_for_chain(cid, true));
        assert!(matches!(
            claim_del_tx.payload[0],
            stellereum::svm::OpCode::SysCallClaimDelegatorRewards { validator: v } if v == validator
        ));
    }

    #[test]
    fn unjail_tx_gas_override_floors_at_default_and_respects_higher_budget() {
        let kp = stellereum::post_quantum::FalconKeypair::generate_from_seed(0x91);
        let validator = [0x55u8; 32];
        let cid = stellereum::consensus::consensus_chain_id();
        let default_gas = unjail_default_gas(None);

        let tx_default = build_unjail_tx_with_chain_and_gas(&kp, validator, None, 1, cid, None);
        assert_eq!(tx_default.gas_limit, default_gas);
        assert!(tx_default.verify_signature_for_chain(cid, true));

        let tx_low = build_unjail_tx_with_chain_and_gas(&kp, validator, None, 1, cid, Some(100));
        assert_eq!(tx_low.gas_limit, default_gas);

        let tx_high =
            build_unjail_tx_with_chain_and_gas(&kp, validator, None, 2, cid, Some(1_300_000));
        assert_eq!(tx_high.gas_limit, 1_300_000);
        assert!(tx_high.verify_signature_for_chain(cid, true));

        let tx_unbound_high =
            build_unjail_tx_with_gas(&kp, validator, Some(5_000_000_000), 3, Some(650_000));
        assert_eq!(tx_unbound_high.gas_limit, 650_000);
        assert!(tx_unbound_high.verify_signature());
    }

    #[test]
    fn resolve_falcon_seed_supports_file_cli_and_env() {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().expect("env lock");
        let prev = std::env::var_os("STELL_FALCON_SEED");
        std::env::remove_var("STELL_FALCON_SEED");

        let seed_hex = "22".repeat(32);
        let dir = std::env::temp_dir().join(format!("stell-seed-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("falcon.seed");
        std::fs::write(&path, format!("  {seed_hex}\n")).expect("write seed");

        let from_file = resolve_falcon_seed(None, Some(path.clone())).expect("from file");
        assert_eq!(*from_file, [0x22u8; 32]);

        let from_cli = resolve_falcon_seed(Some(seed_hex.clone()), None).expect("from cli");
        assert_eq!(*from_cli, [0x22u8; 32]);

        std::env::set_var("STELL_FALCON_SEED", &seed_hex);
        let from_env = resolve_falcon_seed(None, None).expect("from env");
        assert_eq!(*from_env, [0x22u8; 32]);

        std::env::remove_var("STELL_FALCON_SEED");
        assert!(resolve_falcon_seed(None, None).is_err());

        if let Some(v) = prev {
            std::env::set_var("STELL_FALCON_SEED", v);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_http_agent_accepts_loopback_json_and_refuses_redirects_and_oversize_bodies() {
        use std::io::{Read as _, Write as _};

        // 1. Loopback HTTP 200 OK JSON succeeds.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().unwrap();
        let h_ok = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req_buf = [0u8; 1024];
                let _ = stream.read(&mut req_buf);
                let body = r#"{"jsonrpc":"2.0","id":1,"result":42}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        let ok_json = cli_post_json(&format!("http://{addr}"), "{}").expect("loopback 200 OK");
        assert_eq!(ok_json["result"], 42);
        h_ok.join().expect("ok server thread");

        // 2. HTTP 302 redirect is refused without following.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().unwrap();
        let h_redir = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req_buf = [0u8; 1024];
                let _ = stream.read(&mut req_buf);
                let resp = "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        let err_redir =
            cli_post_json(&format!("http://{addr}"), "{}").expect_err("redirect must be refused");
        assert!(
            err_redir.to_string().contains("redirect"),
            "unexpected redirect error: {err_redir}"
        );
        h_redir.join().expect("redirect server thread");

        // 3. Oversized JSON response is refused at the bounded reader cap.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().unwrap();
        let h_big = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut req_buf = [0u8; 1024];
                let _ = stream.read(&mut req_buf);
                let body = format!(r#"{{"pad":"{}"}}"#, "a".repeat(64));
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        let url = format!("http://{addr}");
        let raw_resp = cli_http_agent()
            .post(&url)
            .send_string("{}")
            .expect("200 response");
        let err_big = cli_read_json_response_with_cap(raw_resp, &url, 32)
            .expect_err("oversize body must be refused");
        assert!(
            err_big
                .to_string()
                .contains("exceeded maximum allowed size"),
            "unexpected cap error: {err_big}"
        );
        h_big.join().expect("oversize server thread");
    }
}
