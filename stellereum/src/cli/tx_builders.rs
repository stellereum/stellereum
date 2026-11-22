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
pub(crate) fn build_unjail_tx(
    signer: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    top_up: Option<u64>,
    nonce: u64,
) -> Transaction {
    build_unjail_tx_inner(signer, validator, top_up, nonce, None)
}

/// Chain-bound variant of [`build_unjail_tx`].
pub(crate) fn build_unjail_tx_with_chain(
    signer: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    top_up: Option<u64>,
    nonce: u64,
    chain_id: u64,
) -> Transaction {
    build_unjail_tx_inner(signer, validator, top_up, nonce, Some(chain_id))
}

fn build_unjail_tx_inner(
    signer: &stellereum::post_quantum::FalconKeypair,
    validator: [u8; 32],
    top_up: Option<u64>,
    nonce: u64,
    chain_id: Option<u64>,
) -> Transaction {
    let from = falcon_pq_address(signer);
    let mut payload = Vec::new();
    let mut opcode_gas = stellereum::svm::GAS_STAKE_UNBOND;
    if let Some(amount) = top_up {
        assert!(
            amount > 0,
            "a top-up must be positive; omit --top-up instead of passing zero"
        );
        payload.push(stellereum::svm::OpCode::SysCallStake { validator, amount });
        opcode_gas = opcode_gas.saturating_add(stellereum::svm::GAS_STAKE_BOND);
    }
    payload.push(stellereum::svm::OpCode::SysCallUnjail { validator });
    let gas =
        cli_tx_gas(opcode_gas).saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    match chain_id {
        Some(cid) => {
            sign_pq_explicit_payload_with_chain(signer, from, 0, gas, nonce, 1, 1, payload, cid)
        }
        None => sign_pq_explicit_payload(signer, from, 0, gas, nonce, 1, 1, payload),
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
    let bytes = hex::decode(clean).map_err(|e| anyhow::anyhow!("Invalid {what} hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow::anyhow!("{what} must be 32 bytes, got {} bytes", b.len()))
}

/// Parse a 32-byte hex address (optional `0x` prefix).
pub(crate) fn parse_wallet_address(raw: &str) -> anyhow::Result<[u8; 32]> {
    parse_wallet_seed(raw, "address")
}

/// Build the wallet signing key the `sign` commands use.
///
/// Falcon-512 is the ONLY scheme: `--falcon-key-file` (a stored key,
/// preferred) or `--falcon-seed` (deterministic, dev/test reproducibility).
/// The classical `ed25519` and `hybrid` schemes are REMOVED and refused by
/// name; `--from-key` (an Ed25519 seed) is refused too, never silently
/// ignored.
pub(crate) fn resolve_wallet_signing_key(
    scheme: &str,
    from_key: Option<String>,
    falcon_key_file: Option<PathBuf>,
    falcon_seed: Option<String>,
) -> anyhow::Result<stellereum::wallet_signing::WalletSigningKey> {
    use stellereum::wallet_signing::WalletSigningKey;
    if from_key.is_some() {
        anyhow::bail!(
            "--from-key (classical Ed25519 seed) is REMOVED: pass Falcon-512 material \
             with --falcon-key-file or --falcon-seed"
        );
    }
    let load_falcon = || -> anyhow::Result<stellereum::post_quantum::FalconKeypair> {
        if let Some(path) = falcon_key_file.as_ref() {
            return stellereum::node_keys::load_falcon_key(path)
                .map_err(|e| anyhow::anyhow!("cannot load falcon key {}: {e}", path.display()));
        }
        if let Some(seed_hex) = falcon_seed.as_ref() {
            let seed = parse_wallet_seed(seed_hex, "falcon seed")?;
            return Ok(stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&seed));
        }
        anyhow::bail!(
            "scheme '{scheme}' needs a Falcon-512 key: pass --falcon-key-file or --falcon-seed"
        )
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
    let resp: serde_json::Value = ureq::post(rpc).send_string(&body)?.into_json()?;
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
    let resp: serde_json::Value = ureq::post(rpc).send_string(&body)?.into_json()?;
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

    let resp: serde_json::Value = match ureq::post(rpc).send_string(&body) {
        Ok(resp) => match resp.into_json() {
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
    let resp: serde_json::Value = ureq::post(rpc)
        .send_string(&body)
        .map_err(|e| anyhow::anyhow!("cannot resolve chain_id from {rpc}: {e}; pass --chain-id"))?
        .into_json()
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

#[cfg(test)]
mod unjail_builder_tests {
    use super::*;

    #[test]
    fn unjail_builder_emits_optional_top_up_then_unjail() {
        let kp = stellereum::post_quantum::FalconKeypair::generate_from_seed(0x71);
        let validator = falcon_pq_address(&kp);

        // No top-up: one unjail op, signed envelope verifies.
        let tx = build_unjail_tx(&kp, validator, None, 3);
        assert_eq!(tx.payload.len(), 1);
        assert!(matches!(
            tx.payload[0],
            stellereum::svm::OpCode::SysCallUnjail { validator: v } if v == validator
        ));
        assert!(tx.verify_signature());

        // With a top-up: stake FIRST, then unjail, same envelope rules.
        let tx = build_unjail_tx(&kp, validator, Some(5_000_000_000), 4);
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
}
