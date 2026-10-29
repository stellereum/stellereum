//! Session keys phase 0+1: golden byte-compatibility, envelope verification,
//! tamper/graft resistance, admission & execution policy, and
//! propose-filter/apply parity.
//!
//! Two invariants are pinned here above everything else:
//!   1. BINCODE VERDICT: the delegation rides INSIDE `Transaction::signature`
//!      (`64B session sig || b"SK1" || bincode(grant)`), so `Transaction` /
//!      `Block` gained no field and every persisted legacy byte string still
//!      decodes, verifies and hashes exactly as before.
//!   2. CLOCK: every consensus decision (propose selection, execution) uses
//!      the BLOCK timestamp, never wall time. Mempool admission is node-local
//!      policy and gets an explicit `AdmissionCtx`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::ValidatorSet;
use stellereum::mempool::{AdmissionCtx, Mempool, MempoolError};
use stellereum::post_quantum::{FalconKeypair, PqScheme, HYBRID_PUBKEY_LEN, HYBRID_SIG_LEN};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, SessionPolicyError, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::zkml::{
    make_hybrid_pubkey, sign_falcon512, sign_hybrid, SessionKeyAuthorization, SessionKeyRegistry,
    SessionRegistryError, SessionSpendSim, SCOPE_ALL, SCOPE_SVM_PAYLOAD, SCOPE_TRANSFER,
};

// ============================================================================
// Golden vectors — captured from the PRE-session-key implementation and
// re-verified byte-for-byte after the change. If any of these moves, legacy
// blocks no longer rehash to their voted hashes.
// ============================================================================

/// `SigningKey::from_bytes(&[7u8; 32]).verifying_key()`
const GOLDEN_PUBKEY: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
/// `Transaction::sign(&sk7, [9u8;32], 1000, 50, 3, 1, 1).signing_message()`
const GOLDEN_SIGNING_MSG: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c090909090909090909090909090909090909090909090909090909090909090900000000000003e80000000000000032000000000000000300000001000000015041594c4f4144000000080000000000000000";
/// Exactly 115 bytes — the length `scripts/tps_load.py --self-test` asserts.
/// Exactly 64-byte signature — the length a pre-envelope node's
/// `Signature::from_slice` requires.
const GOLDEN_SIG: &str = "ec92a88d6c30df1625df08d1172e2baecf20964110ce727278849ee953418106c995e7ac322958b6ea6910abe8a7c55f709d5fe935ae09a53fa099b843dee806";
/// bincode(Transaction) of the golden tx — 176 bytes (python asserts 176).
const GOLDEN_TX_BYTES: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0909090909090909090909090909090909090909090909090909090909090909e8030000000000003200000000000000030000000000000001000000010000004000000000000000ec92a88d6c30df1625df08d1172e2baecf20964110ce727278849ee953418106c995e7ac322958b6ea6910abe8a7c55f709d5fe935ae09a53fa099b843dee8060000000000000000";
const GOLDEN_TX_HASH: &str = "5396c8cb4dbfe9f745a51980a892adf059ad6a10737e4ba1d9d2291b72c8fc85";
/// The block hash MOVED when the chain id was bound into the block preimage
/// (`STELLEREUM_BLOCK_V3` || chain_id || ...). The value below is the hash of
/// the SAME block under the default chain id 5757 — the block body is
/// untouched, only the commitment to the network changed.
const GOLDEN_BLOCK_HASH: &str = "68e8c8dc7c0de7915e9d6eb620c1b25f80fb6216fa929a283a856ad2ab37d6d2";
/// The hash of the SAME body under the CURRENT commitment scheme, i.e. with
/// the transaction-ORDER commitment mixed in (`"ORDROOT1" || order_merkle_root`).
///
/// DERIVED, NOT COPIED: `derive_block_hash` below recomputes the documented
/// preimage by hand, and the test asserts that this constant is exactly that
/// hash (and that `Block::compute_hash` agrees with it). It differs from
/// [`GOLDEN_BLOCK_HASH`] because the block identity now covers the ORDER of
/// the transactions, not only their content.
const GOLDEN_BLOCK_HASH_CURRENT: &str =
    "d99da6dfb000ba16bbe606f3affdb9b8c915ccd26b3df40992172ecc4551dd86";
/// bincode(Block) around the golden tx (height 1, state_root 0x02*32,
/// timestamp 1_700_000_000, proposer = golden pubkey, one validator sig).
const GOLDEN_BLOCK_BYTES: &str = "000000000100000000000000000000000000000000000000000000000000000000000000000000000000000002020202020202020202020202020202020202020202020202020202020202020100000000000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0909090909090909090909090909090909090909090909090909090909090909e8030000000000003200000000000000030000000000000001000000010000004000000000000000ec92a88d6c30df1625df08d1172e2baecf20964110ce727278849ee953418106c995e7ac322958b6ea6910abe8a7c55f709d5fe935ae09a53fa099b843dee8060000000000000000000000000000000000f1536500000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0100000000000000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c40000000000000003d12d67dfedc7232b0bef033e5182e4dfde39cb6255567a82e0eee1e76b4bd9c25be7ce4374cca6fd75128f79201c184069972b9b753a89f62b3cd887c4a470300";
/// Payload tx golden: `sign_with_payload(&sk7, [9u8;32], 5, 700, 8, 1, 2, [Push(42)])`
const GOLDEN_PAYLOAD_TX_HASH: &str =
    "1c0dd4788cffddce81eca80d10a3d054cc88b5f2b965e72609ef555ae3723958";

const CHAIN_ID: u64 = 5757;

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("golden hex")
}

fn h32(s: &str) -> [u8; 32] {
    h(s).try_into().expect("golden 32-byte hex")
}

fn golden_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn grant(
    master: &SigningKey,
    session: &SigningKey,
    valid_until: u64,
    max_gas_spend: u64,
    scope: u64,
    max_value_per_tx: u64,
) -> SessionKeyAuthorization {
    SessionKeyAuthorization::sign_delegation(
        master,
        session.verifying_key().to_bytes(),
        valid_until,
        max_gas_spend,
        scope,
        max_value_per_tx,
        CHAIN_ID,
    )
}

#[allow(clippy::too_many_arguments)]
fn session_tx(
    session: &SigningKey,
    delegation: SessionKeyAuthorization,
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    payload: Vec<OpCode>,
) -> Transaction {
    Transaction::sign_with_session(
        session, delegation, [1u8; 32], amount, gas_limit, nonce, 1, 1, payload,
    )
}

/// Re-encode a mutated grant into an existing envelope, keeping the leading
/// 64-byte session signature: exactly what a middleman on the wire can do.
fn rewrap(tx: &Transaction, d: &SessionKeyAuthorization) -> Transaction {
    let mut t = tx.clone();
    let mut sig = tx.signature[..64].to_vec();
    sig.extend_from_slice(b"SK1");
    sig.extend_from_slice(&bincode::serialize(d).expect("grant serializes"));
    t.signature = sig;
    t
}

/// A modelled PRE-session-key node: one 64-byte Ed25519 signature by
/// `tx.from` over the legacy signing message (no delegation, no commitment).
/// This is what an old node running the old code does with a new envelope —
/// it must reject it (fail-closed at `Signature::from_slice`, length != 64).
fn pre_envelope_node_verify(tx: &Transaction) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&tx.from) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&tx.signature) else {
        return false; // envelope is ~250 bytes: rejected on LENGTH alone
    };
    let mut msg = Vec::with_capacity(115);
    msg.extend_from_slice(&tx.from);
    msg.extend_from_slice(&tx.to);
    msg.extend_from_slice(&tx.amount.to_be_bytes());
    msg.extend_from_slice(&tx.gas_limit.to_be_bytes());
    msg.extend_from_slice(&tx.nonce.to_be_bytes());
    msg.extend_from_slice(&tx.source_shard.to_be_bytes());
    msg.extend_from_slice(&tx.target_shard.to_be_bytes());
    msg.extend_from_slice(b"PAYLOAD");
    let payload = bincode::serialize(&tx.payload).expect("payload serializes");
    msg.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    msg.extend_from_slice(&payload);
    vk.verify(&msg, &sig).is_ok()
}

async fn funded_state(owner: [u8; 32], balance: u64) -> Arc<InMemoryStateEngine> {
    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(AccountState::new(owner, balance)).await;
    st
}

// ============================================================================
// 1-3. Golden byte-compatibility: legacy txs, legacy blocks, python client
// ============================================================================

#[test]
fn legacy_tx_bytes_decode_verify_and_hash_are_unchanged() {
    let sk = golden_key();
    let raw = h(GOLDEN_TX_BYTES);

    // Decode the bytes written by the OLD implementation.
    let tx: Transaction = bincode::deserialize(&raw).expect("legacy tx must still decode");
    assert_eq!(tx.from, h32(GOLDEN_PUBKEY));
    assert_eq!(tx.to, [9u8; 32]);
    assert_eq!(tx.amount, 1000);
    assert_eq!(tx.gas_limit, 50);
    assert_eq!(tx.nonce, 3);
    assert_eq!(tx.source_shard, 1);
    assert_eq!(tx.target_shard, 1);
    assert!(tx.payload.is_empty());
    assert_eq!(tx.signature, h(GOLDEN_SIG));
    assert_eq!(tx.signature.len(), 64, "legacy signatures are bare 64-byte");

    // Byte-identical re-encode, unchanged signing message, unchanged verify,
    // unchanged hash.
    assert_eq!(
        bincode::serialize(&tx).unwrap(),
        raw,
        "re-encode must be byte-identical"
    );
    assert_eq!(
        hex::encode(tx.signing_message()),
        GOLDEN_SIGNING_MSG,
        "legacy signing message must be byte-identical"
    );
    assert!(tx.verify_signature(), "legacy signature must still verify");
    assert!(pre_envelope_node_verify(&tx));
    assert!(!tx.is_session_keyed());
    assert_eq!(
        tx.check_session_policy(0),
        Ok(()),
        "policy is a no-op for legacy"
    );
    assert_eq!(
        hex::encode(tx.compute_tx_hash()),
        GOLDEN_TX_HASH,
        "legacy tx hash must be byte-identical"
    );

    // And signing with the old API still produces exactly those bytes.
    let fresh = Transaction::sign(&sk, [9u8; 32], 1000, 50, 3, 1, 1);
    assert_eq!(bincode::serialize(&fresh).unwrap(), raw);

    // Payload-carrying legacy tx too (payload commitment untouched).
    let ptx =
        Transaction::sign_with_payload(&sk, [9u8; 32], 5, 700, 8, 1, 2, vec![OpCode::Push(42)]);
    assert_eq!(hex::encode(ptx.compute_tx_hash()), GOLDEN_PAYLOAD_TX_HASH);
}

/// Re-derive a block hash from the DOCUMENTED preimage, independently of
/// `Block::compute_hash`:
///
/// ```text
/// SHA256( "STELLEREUM_BLOCK_V3"
///      || chain_id (8, BE)                       <- the chain-id binding
///      || shard_id (4, BE)
///      || height (8, BE)
///      || prev_hash (32)
///      || state_root (32)
///      || n_txs (4, BE) || tx_hash[0..n] (32 each)
///      || [ "ORDROOT1" (8) || order_merkle_root (32) ]   (only if non-zero)
///      || n_cross_shard_out (4, BE)               (the ids follow here)
///      || timestamp (8, BE)
///      || proposer (32) )
/// ```
///
/// The golden vectors above are DERIVED through this function, so a change in
/// the commitment scheme shows up as a DERIVATION mismatch, not as a silently
/// copied constant.
#[allow(clippy::too_many_arguments)]
// GATE: test helper derives golden block hashes from all header fields; bundling would hide the derivation.
fn derive_block_hash(
    chain_id: u64,
    shard_id: u32,
    height: u64,
    prev_hash: &[u8; 32],
    state_root: &[u8; 32],
    tx_hashes: &[[u8; 32]],
    order_merkle_root: &[u8; 32],
    cross_shard_ids: &[[u8; 32]],
    timestamp: u64,
    proposer: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"STELLEREUM_BLOCK_V3");
    h.update(chain_id.to_be_bytes());
    h.update(shard_id.to_be_bytes());
    h.update(height.to_be_bytes());
    h.update(prev_hash);
    h.update(state_root);
    h.update((tx_hashes.len() as u32).to_be_bytes());
    for t in tx_hashes {
        h.update(t);
    }
    if order_merkle_root != &[0u8; 32] {
        h.update(b"ORDROOT1");
        h.update(order_merkle_root);
    }
    h.update((cross_shard_ids.len() as u32).to_be_bytes());
    for m in cross_shard_ids {
        h.update(m);
    }
    h.update(timestamp.to_be_bytes());
    h.update(proposer);
    h.finalize().into()
}

#[test]
fn legacy_block_rehash_is_unchanged() {
    let sk = golden_key();
    let tx: Transaction = bincode::deserialize(&h(GOLDEN_TX_BYTES)).unwrap();
    let raw_block = h(GOLDEN_BLOCK_BYTES);

    // The persisted legacy block still decodes... The shard-head set and the
    // order Merkle root were APPENDED to the block layout AFTER this body was
    // persisted, so the body ends its byte stream one field early. The STORE
    // tolerates exactly that shape (`with_legacy_block_tolerance`); the WIRE
    // path stays strict (fail closed), so a truncated message can never be
    // reinterpreted as a valid block.
    let block: Block =
        stellereum::sharding::with_legacy_block_tolerance(|| bincode::deserialize(&raw_block))
            .expect("legacy block must still decode");
    assert_eq!(block.height, 1);
    assert_eq!(block.shard_id, MASTERCHAIN_SHARD);
    assert_eq!(block.timestamp, 1_700_000_000);
    assert_eq!(block.transactions.len(), 1);
    assert!(
        block.shard_headers.is_empty(),
        "a legacy body commits to no shard head"
    );
    assert_eq!(
        block.order_merkle_root, [0u8; 32],
        "a legacy body carries no order commitment"
    );

    // ...and rehashes to the vote it was cast for.
    assert_eq!(
        hex::encode(block.compute_hash()),
        GOLDEN_BLOCK_HASH,
        "legacy block rehash must be byte-identical"
    );
    // DERIVED, not copied: the golden value is the hash of the documented
    // preimage (recomputed here by hand).
    assert_eq!(
        hex::encode(derive_block_hash(
            CHAIN_ID,
            block.shard_id,
            block.height,
            &block.prev_hash,
            &block.state_root,
            &[tx.compute_tx_hash()],
            &block.order_merkle_root,
            &[],
            block.timestamp,
            &block.proposer,
        )),
        GOLDEN_BLOCK_HASH,
        "the golden block hash must be the hash of the documented preimage"
    );

    // Rebuild it from scratch the way the current code does: the BODY is the
    // same, but the order commitment is now derived from it - so the CURRENT
    // hash of the same body is DIFFERENT (the block identity covers the order
    // of the transactions, not only their content).
    let order_txs = vec![tx.clone()];
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&order_txs);
    let mut rebuilt = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [2u8; 32],
        transactions: order_txs,
        cross_shard_out: vec![],
        timestamp: 1_700_000_000,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    };
    rebuilt.sign_block(&sk);
    assert_eq!(
        hex::encode(rebuilt.compute_hash()),
        GOLDEN_BLOCK_HASH_CURRENT,
        "the current scheme hashes the same body differently (order commitment)"
    );
    // ... and that value is derived from the documented preimage too.
    assert_eq!(
        hex::encode(derive_block_hash(
            CHAIN_ID,
            MASTERCHAIN_SHARD,
            1,
            &[0u8; 32],
            &[2u8; 32],
            &[tx.compute_tx_hash()],
            &order_merkle_root,
            &[],
            1_700_000_000,
            &sk.verifying_key().to_bytes(),
        )),
        GOLDEN_BLOCK_HASH_CURRENT,
        "the current golden hash must be the hash of the documented preimage"
    );
    // The compatibility property that matters: the legacy body (no order
    // commitment) still hashes to the hash the chain voted for.
    let mut rebuilt_legacy = rebuilt.clone();
    rebuilt_legacy.order_merkle_root = [0u8; 32];
    assert_eq!(
        hex::encode(rebuilt_legacy.compute_hash()),
        GOLDEN_BLOCK_HASH,
        "the legacy body must still rehash to its voted hash"
    );

    // The shard-head set (TON `shard_hashes`), the order Merkle root, the
    // epoch-key commitment, the canonical downtime-evidence slot
    // (`last_qc`, W10.5) and the epoch-MMR root (V5 Tier-2) were APPENDED to
    // the block layout, so the legacy bytes are the untouched PREFIX of the
    // encoding and the re-encoding adds exactly their bytes (8 for the empty
    // shard-head set + 32 for the order root + 32 for the epoch-key
    // commitment + 1 for the `None` last_qc + 32 for the zero epoch-MMR
    // root). The HASH is what the
    // chain agrees on.
    //
    // The proposer's signature is the ONE thing that cannot be carried over:
    // it signs the block hash, and the hash moved. Pinning the legacy
    // signature back in isolates the LAYOUT change from the HASH change.
    let mut rebuilt_with_legacy_sig = rebuilt.clone();
    rebuilt_with_legacy_sig.validator_signatures = block.validator_signatures.clone();
    let re = bincode::serialize(&rebuilt_with_legacy_sig).unwrap();
    assert_eq!(
        &re[..raw_block.len()],
        &raw_block[..],
        "the legacy bytes must be the untouched prefix of the encoding"
    );
    assert_eq!(
        re.len(),
        raw_block.len() + 73 + 32,
        "only the empty shard-head set (8B), the order root (32B), the epoch-key \
         commitment (32B), the None last_qc byte (1B, W10.5 canonical downtime evidence) \
         and the zero epoch-MMR root (32B, V5 Tier-2) are appended"
    );
    assert!(rebuilt.verify_proposer_signature());
}

/// Mirrors `python3 scripts/tps_load.py --self-test` (which must keep
/// passing without touching scripts/): the exact signing message layout,
/// bincode offsets and ed25519 round-trip the python client asserts.
#[test]
fn python_tps_load_self_test_layout_still_verifies() {
    let sk = golden_key();
    let pubkey = sk.verifying_key().to_bytes();
    let to = {
        let mut t = [0u8; 32];
        for (i, b) in t.iter_mut().enumerate() {
            *b = i as u8;
        }
        t
    };
    // python: signing_message(pub, to, 1, 1, 7, 0, 0)
    let tx = Transaction::sign(&sk, to, 1, 1, 7, 0, 0);
    let msg = tx.signing_message();
    assert_eq!(msg.len(), 115, "python asserts a 115-byte signing message");

    // ed25519 round-trip, tamper rejected — python does the same with `cryptography`.
    let sig = sk.sign(&msg);
    assert!(sk.verifying_key().verify(&msg, &sig).is_ok());
    let mut bad = msg.clone();
    bad[0] ^= 0xFF;
    assert!(sk.verifying_key().verify(&bad, &sig).is_err());

    // python: bincode_encode_tx -> BINCODE_TX_LEN_EMPTY, field offsets.
    let raw = bincode::serialize(&tx).unwrap();
    assert_eq!(raw.len(), 176, "python asserts a 176-byte tx");
    assert_eq!(&raw[..32], &pubkey);
    assert_eq!(&raw[32..64], &to);
    assert_eq!(u64::from_le_bytes(raw[64..72].try_into().unwrap()), 1); // amount
    assert_eq!(u64::from_le_bytes(raw[72..80].try_into().unwrap()), 1); // gas
    assert_eq!(u64::from_le_bytes(raw[80..88].try_into().unwrap()), 7); // nonce
    assert_eq!(u32::from_le_bytes(raw[88..92].try_into().unwrap()), 0); // src shard
    assert_eq!(u32::from_le_bytes(raw[92..96].try_into().unwrap()), 0); // dst shard
    assert_eq!(u64::from_le_bytes(raw[96..104].try_into().unwrap()), 64); // sig len
    assert_eq!(&raw[104..168], sig.to_bytes().as_slice());
    assert_eq!(u64::from_le_bytes(raw[168..176].try_into().unwrap()), 0); // empty payload
}

// ============================================================================
// 4-5. Envelope round-trip + the modelled old node
// ============================================================================

#[test]
fn pre_envelope_node_rejects_envelopes_but_still_accepts_legacy() {
    let master = key();
    let session = key();
    let legacy = Transaction::sign(&master, [1u8; 32], 10, 1_000, 0, 1, 1);
    let envelope = session_tx(
        &session,
        grant(
            &master,
            &session,
            4_000_000_000,
            10_000,
            SCOPE_ALL,
            u64::MAX,
        ),
        10,
        1_000,
        1,
        vec![OpCode::Push(1)],
    );

    // The old node accepts what it always accepted...
    assert!(legacy.verify_signature());
    assert!(pre_envelope_node_verify(&legacy));
    // ...and rejects the envelope outright: its signature is 64B ++ "SK1" ++
    // bincode(grant), so `Signature::from_slice` (64 bytes expected) fails
    // before any message is even considered. Fail-closed, no ambiguity.
    assert!(envelope.is_session_keyed());
    assert!(envelope.signature.len() > 64);
    assert!(!pre_envelope_node_verify(&envelope));
    // The new node accepts both forms.
    assert!(legacy.verify_signature());
    assert!(envelope.verify_signature());
}

#[test]
fn session_envelope_roundtrip_verifies_singly_and_in_batches() {
    let master = key();
    let session = key();
    let d = grant(
        &master,
        &session,
        4_000_000_000,
        10_000,
        SCOPE_ALL,
        u64::MAX,
    );

    let plain_payload_tx = session_tx(&session, d.clone(), 10, 1_000, 0, vec![]);
    let payload_tx = session_tx(
        &session,
        d,
        5,
        2_000,
        1,
        vec![OpCode::Push(1), OpCode::Push(2)],
    );

    for tx in [&plain_payload_tx, &payload_tx] {
        assert!(tx.verify_signature(), "envelope must verify");
        assert!(tx.is_session_keyed());
        assert_eq!(
            tx.from,
            master.verifying_key().to_bytes(),
            "tx.from stays the master"
        );
        let parsed = tx.delegation().expect("envelope parses back");
        assert_eq!(parsed.master_address, master.verifying_key().to_bytes());
        assert_eq!(parsed.session_pubkey, session.verifying_key().to_bytes());
        assert_eq!(parsed.chain_id, CHAIN_ID);
        assert!(parsed.verify_signature(), "master grant verifies");
        assert_eq!(tx.check_session_policy(1_000_000), Ok(()));
        assert!(Transaction::verify_signatures_batch(std::slice::from_ref(
            tx
        )));

        // bincode round-trip of the envelope transaction itself.
        let bytes = bincode::serialize(tx).unwrap();
        let back: Transaction = bincode::deserialize(&bytes).unwrap();
        assert_eq!(bytes, bincode::serialize(&back).unwrap());
        assert!(back.verify_signature());
        assert_eq!(back.compute_tx_hash(), tx.compute_tx_hash());
        assert_eq!(back.signing_message(), tx.signing_message());
    }

    let batch = [plain_payload_tx, payload_tx];
    assert!(Transaction::verify_signatures_batch(&batch));
    assert!(Transaction::verify_signatures_batch_parallel(&batch));
}

// ============================================================================
// 6-7. Tamper: every delegation field, every tx field, commitment presence
// ============================================================================

#[test]
fn flipping_any_delegation_field_breaks_verification() {
    let master = key();
    let session = key();
    let tx = session_tx(
        &session,
        grant(
            &master,
            &session,
            4_000_000_000,
            10_000,
            SCOPE_ALL,
            u64::MAX,
        ),
        10,
        1_000,
        0,
        vec![OpCode::Push(7)],
    );
    assert!(tx.verify_signature(), "untampered baseline");

    #[allow(clippy::type_complexity)]
    // GATE: table-driven test cases enumerate full mutator/case tuples inline for readability.
    let mutators: Vec<(&str, Box<dyn Fn(&mut SessionKeyAuthorization)>)> = vec![
        ("master_address", Box::new(|d| d.master_address[0] ^= 0xFF)),
        ("session_pubkey", Box::new(|d| d.session_pubkey[0] ^= 0xFF)),
        ("valid_until", Box::new(|d| d.valid_until += 1)),
        ("max_gas_spend", Box::new(|d| d.max_gas_spend += 1)),
        // not covered by the master's grant sig, but covered by the SESSION
        // signature via the grant commitment in the signed message
        ("gas_spent", Box::new(|d| d.gas_spent += 1)),
        ("scope", Box::new(|d| d.scope ^= 1)),
        (
            "max_value_per_tx",
            Box::new(|d| d.max_value_per_tx = d.max_value_per_tx.wrapping_sub(1)),
        ),
        ("chain_id", Box::new(|d| d.chain_id ^= 1)),
        (
            "master_signature",
            Box::new(|d| d.master_signature[0] ^= 0xFF),
        ),
    ];
    for (name, mutate) in &mutators {
        let mut d = tx.delegation().unwrap();
        mutate(&mut d);
        let tampered = rewrap(&tx, &d);
        assert!(
            tampered.is_session_keyed(),
            "{name}: envelope must still parse"
        );
        assert!(
            !tampered.verify_signature(),
            "flipping {name} must break verification"
        );
        // ...and admission sees it as a bad grant or at least a failure.
        assert!(
            tampered.check_session_policy(1_000_000).is_err() || !tampered.verify_signature(),
            "flipping {name} must be rejected"
        );
    }

    // The session signature itself.
    let mut sig_tampered = tx.clone();
    sig_tampered.signature[0] ^= 0xFF;
    assert!(
        !sig_tampered.verify_signature(),
        "flipping the session sig must fail"
    );

    // Transaction fields are inside the signed message too.
    let mut amount = tx.clone();
    amount.amount += 1;
    assert!(!amount.verify_signature(), "amount tamper must fail");
    let mut nonce = tx.clone();
    nonce.nonce += 1;
    assert!(!nonce.verify_signature(), "nonce tamper must fail");
    let mut gas = tx.clone();
    gas.gas_limit += 1;
    assert!(!gas.verify_signature(), "gas_limit tamper must fail");
    let mut to = tx.clone();
    to.to[0] ^= 0xFF;
    assert!(!to.verify_signature(), "recipient tamper must fail");
    let mut shard = tx.clone();
    shard.target_shard = 2;
    assert!(!shard.verify_signature(), "shard tamper must fail");
    let mut payload = tx.clone();
    payload.payload.push(OpCode::Nop);
    assert!(!payload.verify_signature(), "payload tamper must fail");
}

#[test]
fn legacy_messages_and_hashes_carry_no_delegation_commitment() {
    let master = key();
    let session = key();
    let legacy = Transaction::sign(&master, [1u8; 32], 10, 1_000, 0, 1, 1);
    let envelope = session_tx(
        &session,
        grant(
            &master,
            &session,
            4_000_000_000,
            10_000,
            SCOPE_ALL,
            u64::MAX,
        ),
        10,
        1_000,
        0,
        vec![],
    );
    assert_eq!(legacy.from, envelope.from, "same fields, same sender");

    // Conditional commitment: the legacy message/hash are untouched, the
    // envelope's carry the grant.
    let has_session = |v: &[u8]| v.windows(7).any(|w| w == b"SESSION");
    assert!(
        !has_session(&legacy.signing_message()),
        "legacy message has no commitment"
    );
    assert!(
        has_session(&envelope.signing_message()),
        "envelope message commits the grant"
    );
    assert_ne!(legacy.signing_message(), envelope.signing_message());
    assert_ne!(legacy.compute_tx_hash(), envelope.compute_tx_hash());

    // Swapping the grant for another one (even minted to the SAME session
    // key) changes the signed message, so the session signature dies.
    let d2 = grant(&master, &session, 4_000_000_000, 9_999, SCOPE_ALL, u64::MAX);
    let swapped = rewrap(&envelope, &d2);
    assert!(
        !swapped.verify_signature(),
        "a swapped grant must invalidate the signature"
    );
}

// ============================================================================
// 8-9. Batch verify (mixed) and the graft attack
// ============================================================================

#[test]
fn mixed_plain_and_session_batches_verify() {
    let m1 = key();
    let m2 = key();
    let s1 = key();
    let s2 = key();
    let legacy_a = Transaction::sign(&m1, [1u8; 32], 10, 1_000, 0, 1, 1);
    let session_a = session_tx(
        &s1,
        grant(&m1, &s1, 4_000_000_000, 10_000, SCOPE_ALL, u64::MAX),
        20,
        1_000,
        1,
        vec![OpCode::Push(3)],
    );
    let legacy_b = Transaction::sign(&m1, [1u8; 32], 5, 500, 2, 1, 1);
    let session_b = session_tx(
        &s2,
        grant(&m2, &s2, 4_000_000_000, 10_000, SCOPE_ALL, u64::MAX),
        7,
        500,
        0,
        vec![],
    );
    let good = vec![
        legacy_a.clone(),
        session_a.clone(),
        legacy_b.clone(),
        session_b.clone(),
    ];
    assert!(Transaction::verify_signatures_batch(&good));
    assert!(Transaction::verify_signatures_batch_parallel(&good));
    assert!(good.iter().all(|t| t.verify_signature()));

    // 1. tampered session tx
    let mut c = good.clone();
    c[1].amount ^= 1;
    assert!(
        !Transaction::verify_signatures_batch(&c),
        "tampered session tx must fail"
    );

    // 2. tampered legacy tx
    let mut c = good.clone();
    c[2].nonce ^= 1;
    assert!(
        !Transaction::verify_signatures_batch(&c),
        "tampered legacy tx must fail"
    );

    // 3. tampered grant inside an envelope (master signature broken)
    let mut c = good.clone();
    let mut d = c[3].delegation().unwrap();
    d.master_signature[0] ^= 0xFF;
    c[3] = rewrap(&c[3], &d);
    assert!(
        !Transaction::verify_signatures_batch(&c),
        "tampered grant must fail the batch"
    );

    // 4. grafted envelope (grant minted for another master)
    let mut c = good.clone();
    let attacker = key();
    let attacker_session = key();
    let d_att = grant(
        &attacker,
        &attacker_session,
        4_000_000_000,
        10_000,
        SCOPE_ALL,
        u64::MAX,
    );
    c[0] = rewrap(&c[0], &d_att);
    assert!(
        !Transaction::verify_signatures_batch(&c),
        "grafted envelope must fail the batch"
    );

    // 5. parallel variant agrees on a corrupted batch
    let mut c = good.clone();
    c[0].amount ^= 1;
    assert!(!Transaction::verify_signatures_batch_parallel(&c));
}

#[test]
fn grafting_a_session_envelope_onto_a_victim_plain_tx_is_rejected() {
    let victim = key();
    let attacker = key();
    let attacker_session = key();
    let victim_pub = victim.verifying_key().to_bytes();
    let plain = Transaction::sign(&victim, [1u8; 32], 10, 1_000, 0, 1, 1);
    let now = 1_000_000u64;
    let mut mp = Mempool::new(16, 16);

    // (1) The full-strength graft: the attacker uses THEIR OWN valid grant,
    // correctly signed by THEIR session key over the grafted message. The
    // signature machinery is entirely happy — the only thing that stops it is
    // `delegation.master_address == tx.from`.
    let d_att = grant(
        &attacker,
        &attacker_session,
        4_000_000_000,
        10_000,
        SCOPE_ALL,
        u64::MAX,
    );
    let mut grafted = plain.clone();
    // placeholder envelope so the signing message commits the grant
    let mut placeholder = vec![0u8; 64];
    placeholder.extend_from_slice(b"SK1");
    placeholder.extend_from_slice(&bincode::serialize(&d_att).unwrap());
    grafted.signature = placeholder;
    let msg = grafted.signing_message();
    let sig = attacker_session.sign(&msg);
    let mut envelope = sig.to_bytes().to_vec();
    envelope.extend_from_slice(b"SK1");
    envelope.extend_from_slice(&bincode::serialize(&d_att).unwrap());
    grafted.signature = envelope;

    assert_eq!(grafted.from, victim_pub, "the victim is still the sender");
    assert!(
        grafted.is_session_keyed(),
        "the graft parses as an envelope"
    );
    assert!(
        !grafted.verify_signature(),
        "master_address != tx.from must reject"
    );
    assert_eq!(
        grafted.check_session_policy(now),
        Err(SessionPolicyError::BadGrant),
        "policy names the grafted grant"
    );
    assert!(!pre_envelope_node_verify(&grafted));
    assert_eq!(
        mp.add_checked_ctx(grafted.clone(), u64::MAX, AdmissionCtx::new(now)),
        Err(MempoolError::SessionBadGrant),
        "mempool classifies the graft as a bad grant"
    );

    // (2) A grant that CLAIMS the victim as master but was minted by the
    // attacker: master_address now matches, the master's signature does not.
    let mut d_spoof = grant(
        &attacker,
        &attacker_session,
        4_000_000_000,
        10_000,
        SCOPE_ALL,
        u64::MAX,
    );
    d_spoof.master_address = victim_pub;
    let spoofed = rewrap(&plain, &d_spoof);
    assert_eq!(spoofed.delegation().unwrap().master_address, victim_pub);
    assert!(!spoofed.verify_signature(), "forged master grant must fail");
    assert_eq!(
        spoofed.check_session_policy(now),
        Err(SessionPolicyError::BadGrant)
    );
    assert_eq!(
        mp.add_checked_ctx(spoofed, u64::MAX, AdmissionCtx::new(now)),
        Err(MempoolError::SessionBadGrant)
    );

    // (3) The lazy graft: append junk bytes to the victim's legacy signature.
    let mut junk = plain.clone();
    junk.signature.extend_from_slice(&[1, 2, 3, 4]);
    assert!(
        !junk.verify_signature(),
        "64B + junk must fail (length != 64)"
    );
    assert!(
        !pre_envelope_node_verify(&junk),
        "and an old node rejects it too"
    );
    assert_eq!(
        mp.add_checked_ctx(junk, u64::MAX, AdmissionCtx::new(now)),
        Err(MempoolError::BadSignature)
    );

    // The victim's untouched transaction is still perfectly valid.
    assert!(plain.verify_signature());
    assert!(mp
        .add_checked_ctx(plain, u64::MAX, AdmissionCtx::new(now))
        .is_ok());
}

// ============================================================================
// 10. Admission: expiry / scope / value / budget / grant
// ============================================================================

#[test]
fn admission_rejects_expired_out_of_scope_over_value_exhausted_and_bad_grants() {
    let master = key();
    let session = key();
    let now = 1_000_000u64;
    let ctx = AdmissionCtx::new(now);
    let balance = 10_000_000u64;
    let mut mp = Mempool::new(100, 100);

    // A fully valid session transfer is admitted.
    let valid = session_tx(
        &session,
        grant(&master, &session, now + 100, 10_000, SCOPE_ALL, u64::MAX),
        10,
        1_000,
        0,
        vec![],
    );
    assert!(mp.add_checked_ctx(valid.clone(), balance, ctx).is_ok());

    // Expiry: valid at valid_until, expired one second later (block-clock
    // semantics are identical: `now > valid_until`).
    let expiring = session_tx(
        &session,
        grant(&master, &session, now, 10_000, SCOPE_ALL, u64::MAX),
        10,
        1_000,
        1,
        vec![],
    );
    assert!(
        mp.add_checked_ctx(expiring.clone(), balance, AdmissionCtx::new(now))
            .is_ok(),
        "valid at the boundary"
    );
    assert_eq!(
        mp.add_checked_ctx(expiring.clone(), balance, AdmissionCtx::new(now + 1)),
        Err(MempoolError::SessionExpired),
        "expired one second later"
    );

    // Scope: a payload-only grant cannot authorize a plain transfer.
    let out_of_scope = session_tx(
        &session,
        grant(
            &master,
            &session,
            now + 100,
            10_000,
            SCOPE_SVM_PAYLOAD,
            u64::MAX,
        ),
        10,
        1_000,
        2,
        vec![],
    );
    assert_eq!(
        mp.add_checked_ctx(out_of_scope, balance, ctx),
        Err(MempoolError::SessionOutOfScope)
    );
    // ...and the reverse: a payload tx under a transfer-only grant.
    let payload_only = session_tx(
        &session,
        grant(
            &master,
            &session,
            now + 100,
            10_000,
            SCOPE_TRANSFER,
            u64::MAX,
        ),
        10,
        1_000,
        3,
        vec![OpCode::Push(1)],
    );
    assert_eq!(
        mp.add_checked_ctx(payload_only, balance, ctx),
        Err(MempoolError::SessionOutOfScope)
    );

    // Value cap: amount above max_value_per_tx.
    let over_value = session_tx(
        &session,
        grant(&master, &session, now + 100, 10_000, SCOPE_ALL, 100),
        101,
        1_000,
        4,
        vec![],
    );
    assert_eq!(
        mp.add_checked_ctx(over_value, balance, ctx),
        Err(MempoolError::SessionOutOfScope)
    );

    // Budget: declared gas_limit beyond the grant's remaining budget.
    let over_budget = session_tx(
        &session,
        grant(&master, &session, now + 100, 500, SCOPE_ALL, u64::MAX),
        10,
        1_000,
        5,
        vec![],
    );
    assert_eq!(
        mp.add_checked_ctx(over_budget, balance, ctx),
        Err(MempoolError::SessionRevoked)
    );
    // Exactly the budget is fine (boundary).
    let exact_budget = session_tx(
        &session,
        grant(&master, &session, now + 100, 1_000, SCOPE_ALL, u64::MAX),
        10,
        1_000,
        6,
        vec![],
    );
    assert!(mp.add_checked_ctx(exact_budget, balance, ctx).is_ok());

    // Bad grant: master signature tampered with.
    let mut bad_grant = session_tx(
        &session,
        grant(&master, &session, now + 100, 10_000, SCOPE_ALL, u64::MAX),
        10,
        1_000,
        7,
        vec![],
    );
    let mut d = bad_grant.delegation().unwrap();
    d.master_signature[0] ^= 0xFF;
    bad_grant = rewrap(&bad_grant, &d);
    assert_eq!(
        mp.add_checked_ctx(bad_grant, balance, ctx),
        Err(MempoolError::SessionBadGrant)
    );

    // Not every failure is a grant failure: a corrupted SESSION signature
    // with an intact grant still fails as a plain bad signature.
    let mut bad_sig = session_tx(
        &session,
        grant(&master, &session, now + 100, 10_000, SCOPE_ALL, u64::MAX),
        10,
        1_000,
        8,
        vec![],
    );
    bad_sig.signature[10] ^= 0xFF;
    assert_eq!(
        mp.add_checked_ctx(bad_sig, balance, ctx),
        Err(MempoolError::BadSignature)
    );

    assert_eq!(mp.len(), 3, "valid + boundary + exact-budget admitted");
}

// ============================================================================
// 11. Propose filter and apply parity (same predicate, same block clock)
// ============================================================================

#[tokio::test]
async fn propose_filter_and_apply_agree_on_session_transactions() {
    let master = key();
    let session = key();
    let master_pub = master.verifying_key().to_bytes();
    let state = funded_state(master_pub, 10_000_000).await;
    let vset = ValidatorSet::from_list(vec![(master_pub, 1)]);
    let mut rt = ValidatorRuntime::new(master.clone(), vset, state.clone(), 1);
    assert!(rt.is_proposer());

    let admit_at = 1_000_000u64;
    let block_ts = 2_000_000u64;
    let balance = 10_000_000u64;

    let plain = Transaction::sign(&master, [1u8; 32], 10, 1_000, 0, 1, 1);
    let good = session_tx(
        &session,
        grant(&master, &session, 5_000_000, 1_000_000, SCOPE_ALL, u64::MAX),
        20,
        2_000,
        1,
        vec![],
    );
    // Admitted at `admit_at`, expired by `block_ts`.
    let expired = session_tx(
        &session,
        grant(&master, &session, 1_500_000, 1_000_000, SCOPE_ALL, u64::MAX),
        30,
        3_000,
        2,
        vec![],
    );

    let mut mp = rt.mempool.write().await;
    for tx in [&plain, &good, &expired] {
        mp.add_checked_ctx(tx.clone(), balance, AdmissionCtx::new(admit_at))
            .expect("all three admit at admit_at");
    }
    drop(mp);
    assert_eq!(rt.mempool.read().await.len(), 3);

    let block = rt
        .propose(block_ts)
        .await
        .expect("fresh propose must succeed");
    assert_eq!(block.timestamp, block_ts);

    // The filter predicate, evaluated independently.
    let want = [&plain, &good, &expired]
        .iter()
        .map(|t| t.check_session_policy(block_ts).is_ok())
        .collect::<Vec<_>>();
    assert_eq!(want, vec![true, true, false]);

    let selected: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .map(|t| t.compute_tx_hash())
        .collect();
    assert_eq!(
        block.transactions.len(),
        2,
        "expired grant must be filtered out"
    );
    assert!(selected.contains(&plain.compute_tx_hash()));
    assert!(selected.contains(&good.compute_tx_hash()));
    assert!(!selected.contains(&expired.compute_tx_hash()));

    // PARITY A: apply exactly what the filter selected — everything applies.
    let fresh = funded_state(master_pub, 10_000_000).await;
    let (_, _, _, status, _) = fresh
        .apply_block_parallel_fees(&block.transactions, block_ts)
        .await;
    assert_eq!(status, vec![true, true], "selected txs must all apply");

    // PARITY B: apply the UNFILTERED set (a hostile proposer's block) — the
    // per-transaction verdicts must equal the filter predicate exactly.
    let hostile = vec![plain.clone(), good.clone(), expired.clone()];
    let (_, _, _, status_all, _) = state.apply_block_parallel_fees(&hostile, block_ts).await;
    assert_eq!(
        status_all, want,
        "apply verdicts == propose-filter verdicts"
    );

    // And nothing of the expired grant's sender was debited by PARITY B's
    // rejected transaction (nonces 0,1 moved; expired moved nothing).
    let acct = state.get_account(&master_pub).await.unwrap();
    assert!(
        acct.balance < 10_000_000,
        "the two accepted txs moved value"
    );
}

// ============================================================================
// 12-13. Execution: empty-payload bypass closed, all four dimensions re-checked
// ============================================================================

#[tokio::test]
async fn empty_payload_session_transfer_is_checked_at_execution() {
    let master = key();
    let session = key();
    let master_pub = master.verifying_key().to_bytes();

    // A PLAIN (empty payload) session transfer — the shape that used to sail
    // past the session hook because execute_payload early-returns before it.
    let expired_tx = session_tx(
        &session,
        grant(&master, &session, 1_500_000, 10_000, SCOPE_ALL, u64::MAX),
        10,
        1_000,
        0,
        vec![],
    );
    assert!(expired_tx.payload.is_empty());

    // Single-transaction path.
    let state = funded_state(master_pub, 1_000_000).await;
    let err = state
        .apply_transaction(&expired_tx, 2_000_000)
        .await
        .expect_err("an expired grant must not execute");
    assert!(
        err.contains("session key delegation"),
        "the rejection must name the delegation: {err}"
    );
    assert_eq!(
        state.get_account(&master_pub).await.unwrap().balance,
        1_000_000,
        "a rejected grant must move nothing"
    );

    // Live block path.
    let (applied, failed, _, status, _) = state
        .apply_block_parallel_fees(std::slice::from_ref(&expired_tx), 2_000_000)
        .await;
    assert_eq!(status, vec![false], "block path must refuse it too");
    assert_eq!((applied, failed), (0, 1));
    assert_eq!(
        state.get_account(&master_pub).await.unwrap().balance,
        1_000_000
    );

    // Inside the validity window the identical transaction executes and moves
    // value (nothing else about it changed).
    let valid_tx = session_tx(
        &session,
        grant(&master, &session, 5_000_000, 10_000, SCOPE_ALL, u64::MAX),
        10,
        1_000,
        0,
        vec![],
    );
    state
        .apply_transaction(&valid_tx, 2_000_000)
        .await
        .expect("a valid session transfer must execute");
    assert!(
        state.get_account(&master_pub).await.unwrap().balance < 1_000_000,
        "the valid transfer must have paid amount + gas"
    );
    assert_eq!(
        state.get_account(&[1u8; 32]).await.unwrap().balance,
        10,
        "recipient received the amount"
    );
}

#[tokio::test]
async fn block_apply_rejects_every_failed_grant_dimension() {
    // Five independent masters (so nonces never interact) sharing one
    // session key — every transaction is a plain empty-payload transfer.
    let session = key();
    let masters: Vec<SigningKey> = (0..5).map(|_| key()).collect();
    let block_ts = 2_000_000u64;

    let txs = vec![
        // 0: expired at block_ts
        session_tx(
            &session,
            grant(
                &masters[0],
                &session,
                1_500_000,
                10_000,
                SCOPE_ALL,
                u64::MAX,
            ),
            10,
            1_000,
            0,
            vec![],
        ),
        // 1: payload-only scope, empty payload => out of scope
        session_tx(
            &session,
            grant(
                &masters[1],
                &session,
                5_000_000,
                10_000,
                SCOPE_SVM_PAYLOAD,
                u64::MAX,
            ),
            10,
            1_000,
            0,
            vec![],
        ),
        // 2: amount above max_value_per_tx
        session_tx(
            &session,
            grant(&masters[2], &session, 5_000_000, 10_000, SCOPE_ALL, 5),
            10,
            1_000,
            0,
            vec![],
        ),
        // 3: gas_limit above the remaining budget
        session_tx(
            &session,
            grant(&masters[3], &session, 5_000_000, 500, SCOPE_ALL, u64::MAX),
            10,
            1_000,
            0,
            vec![],
        ),
        // 4: fully valid
        session_tx(
            &session,
            grant(
                &masters[4],
                &session,
                5_000_000,
                10_000,
                SCOPE_ALL,
                u64::MAX,
            ),
            10,
            1_000,
            0,
            vec![],
        ),
    ];

    let state = Arc::new(InMemoryStateEngine::new());
    for m in &masters {
        state
            .update_account(AccountState::new(m.verifying_key().to_bytes(), 1_000_000))
            .await;
    }

    let (applied, failed, _, status, _) = state.apply_block_parallel_fees(&txs, block_ts).await;
    assert_eq!(
        status,
        vec![false, false, false, false, true],
        "expired / out-of-scope / over-value / over-budget refused; valid applied"
    );
    assert_eq!((applied, failed), (1, 4));

    // Execution verdict == the policy predicate at the block timestamp, for
    // every transaction (this is the parity the proposer filter relies on).
    for (i, tx) in txs.iter().enumerate() {
        assert_eq!(
            tx.check_session_policy(block_ts).is_ok(),
            status[i],
            "policy predicate and apply verdict must agree for tx {i}"
        );
    }

    // Every refused grant moved nothing; the accepted one paid.
    for m in &masters[..4] {
        assert_eq!(
            state
                .get_account(&m.verifying_key().to_bytes())
                .await
                .unwrap()
                .balance,
            1_000_000,
            "a refused grant must move nothing"
        );
    }
    assert!(
        state
            .get_account(&masters[4].verifying_key().to_bytes())
            .await
            .unwrap()
            .balance
            < 1_000_000
    );
}

// ============================================================================
// Post-Quantum & Hybrid Session Keys (Phase V5 Master Spec Section 1 & 6)
// ============================================================================

#[test]
fn test_falcon512_signed_session_grant_creation_and_verification() {
    let falcon_master_fk = FalconKeypair::generate_from_seed(0x11);
    let session = key();
    let session_pk = session.verifying_key().to_bytes();
    let now = 1_000_000u64;

    // Create a Falcon-512 master signed grant with Ed25519 session key
    let grant = SessionKeyAuthorization::sign_delegation_falcon512(
        &falcon_master_fk,
        PqScheme::Ed25519,
        &session_pk,
        now + 10_000,
        50_000,
        SCOPE_ALL,
        1_000,
        CHAIN_ID,
    );

    assert_eq!(grant.master_scheme, PqScheme::Falcon512);
    assert_eq!(grant.session_scheme, PqScheme::Ed25519);
    assert!(grant.is_post_quantum());
    assert!(!grant.is_pure_ed25519());
    assert_eq!(grant.master_pubkey(), falcon_master_fk.public_key());
    assert_eq!(grant.session_pubkey, session_pk);
    assert!(
        grant.verify_signature(),
        "Falcon-512 master signature must verify"
    );
    assert!(grant.verify_at(now));

    // Bincode serialize and deserialize roundtrip
    let bytes = bincode::serialize(&grant).expect("grant must serialize");
    let back: SessionKeyAuthorization =
        bincode::deserialize(&bytes).expect("grant must deserialize");
    assert_eq!(grant, back);
    assert!(
        back.verify_signature(),
        "deserialized Falcon-512 grant signature must verify"
    );

    // Tampering master_signature invalidates
    let mut bad_sig = grant.clone();
    bad_sig.master_signature[0] ^= 0xFF;
    assert!(!bad_sig.verify_signature());

    // Tampering master_address invalidates
    let mut bad_addr = grant.clone();
    bad_addr.master_address[0] ^= 0xFF;
    assert!(!bad_addr.verify_signature());

    // Tampering valid_until invalidates
    let mut bad_time = grant.clone();
    bad_time.valid_until += 1;
    assert!(!bad_time.verify_signature());

    // Tampering scope invalidates
    let mut bad_scope = grant.clone();
    bad_scope.scope ^= 1;
    assert!(!bad_scope.verify_signature());

    // Tampering max_gas_spend invalidates
    let mut bad_gas = grant.clone();
    bad_gas.max_gas_spend += 1;
    assert!(!bad_gas.verify_signature());

    // Tampering max_value_per_tx invalidates
    let mut bad_val = grant.clone();
    bad_val.max_value_per_tx += 1;
    assert!(!bad_val.verify_signature());

    // Tampering chain_id invalidates
    let mut bad_chain = grant.clone();
    bad_chain.chain_id ^= 1;
    assert!(!bad_chain.verify_signature());

    // Tampering master_pubkey invalidates
    let mut bad_pk = grant.clone();
    if let Some(pk) = bad_pk.master_pubkey.as_mut() {
        pk[10] ^= 0xFF;
    }
    assert!(!bad_pk.verify_signature());
}

#[test]
fn test_hybrid_signed_session_grant_creation_and_verification() {
    let ed_master = key();
    let falcon_master_fk = FalconKeypair::generate_from_seed(0x22);
    let session = key();
    let session_pk = session.verifying_key().to_bytes();
    let now = 1_000_000u64;

    // Create a Hybrid (Ed25519 + Falcon-512) master signed grant
    let grant = SessionKeyAuthorization::sign_delegation_hybrid(
        &ed_master,
        &falcon_master_fk,
        PqScheme::Ed25519,
        &session_pk,
        now + 5_000,
        100_000,
        SCOPE_TRANSFER,
        500,
        CHAIN_ID,
    );

    assert_eq!(grant.master_scheme, PqScheme::Hybrid);
    assert_eq!(grant.session_scheme, PqScheme::Ed25519);
    assert!(grant.is_post_quantum());
    assert!(!grant.is_pure_ed25519());
    assert_eq!(grant.master_pubkey().len(), HYBRID_PUBKEY_LEN);
    assert_eq!(grant.master_signature.len(), HYBRID_SIG_LEN);
    assert!(
        grant.verify_signature(),
        "Hybrid master signature must verify"
    );
    assert!(grant.verify_at(now));

    // Bincode serialize and deserialize roundtrip
    let bytes = bincode::serialize(&grant).expect("hybrid grant must serialize");
    let back: SessionKeyAuthorization =
        bincode::deserialize(&bytes).expect("hybrid grant must deserialize");
    assert_eq!(grant, back);
    assert!(
        back.verify_signature(),
        "deserialized Hybrid grant signature must verify"
    );

    // Tampering Ed25519 part of signature (first 64 bytes) breaks verification
    let mut bad_ed_sig = grant.clone();
    bad_ed_sig.master_signature[0] ^= 0xFF;
    assert!(
        !bad_ed_sig.verify_signature(),
        "corrupted ed25519 half of hybrid sig must fail"
    );

    // Tampering Falcon-512 part of signature (subsequent 666 bytes) breaks verification
    let mut bad_f_sig = grant.clone();
    bad_f_sig.master_signature[64] ^= 0xFF;
    assert!(
        !bad_f_sig.verify_signature(),
        "corrupted falcon half of hybrid sig must fail"
    );

    // Tampering master_address breaks verification
    let mut bad_addr = grant.clone();
    bad_addr.master_address[0] ^= 0xFF;
    assert!(!bad_addr.verify_signature());

    // Tampering valid_until breaks verification
    let mut bad_time = grant.clone();
    bad_time.valid_until += 1;
    assert!(!bad_time.verify_signature());
}

#[test]
fn test_pq_session_key_spending_limits_expiry_and_scope_enforcement() {
    let falcon_master_fk = FalconKeypair::generate_from_seed(0x33);
    let falcon_session_fk = FalconKeypair::generate_from_seed(0x44);
    let now = 2_000_000u64;

    // Both master and session keys are Falcon-512 post-quantum keys
    let mut grant = SessionKeyAuthorization::sign_delegation_falcon512(
        &falcon_master_fk,
        PqScheme::Falcon512,
        falcon_session_fk.public_key(),
        now + 1_000,
        10_000,
        SCOPE_TRANSFER,
        500,
        CHAIN_ID,
    );

    assert_eq!(grant.master_scheme, PqScheme::Falcon512);
    assert_eq!(grant.session_scheme, PqScheme::Falcon512);
    assert!(grant.verify_signature());

    // Test verify_session_signature for PQ session key
    let tx_msg = b"Transaction Payload to be signed by Falcon-512 session key";
    let valid_sig = sign_falcon512(&falcon_session_fk, tx_msg);
    assert!(
        grant.verify_session_signature(tx_msg, &valid_sig),
        "Falcon-512 session signature must verify"
    );

    let mut bad_tx_sig = valid_sig.clone();
    bad_tx_sig[0] ^= 0xAA;
    assert!(
        !grant.verify_session_signature(tx_msg, &bad_tx_sig),
        "Corrupted session signature must fail"
    );
    assert!(
        !grant.verify_session_signature(b"different message", &valid_sig),
        "Session signature on wrong message must fail"
    );

    // 1. Spending limits via verify_and_spend_gas:
    assert_eq!(grant.remaining_gas(), 10_000);
    assert!(grant.verify_and_spend_gas(3_000, now).is_ok());
    assert_eq!(grant.gas_spent, 3_000);
    assert_eq!(grant.remaining_gas(), 7_000);

    assert!(grant.verify_and_spend_gas(7_000, now).is_ok());
    assert_eq!(grant.gas_spent, 10_000);
    assert_eq!(grant.remaining_gas(), 0);

    // Over budget returns Err
    let err = grant
        .verify_and_spend_gas(1, now)
        .expect_err("budget exhausted");
    assert!(err.contains("Session key gas limit exceeded"), "{err}");

    // 2. Expiry via verify_and_spend_gas:
    let mut fresh_grant = SessionKeyAuthorization::sign_delegation_falcon512(
        &falcon_master_fk,
        PqScheme::Falcon512,
        falcon_session_fk.public_key(),
        now + 100,
        10_000,
        SCOPE_TRANSFER,
        500,
        CHAIN_ID,
    );
    assert!(
        fresh_grant.verify_and_spend_gas(100, now + 100).is_ok(),
        "valid at boundary"
    );
    let exp_err = fresh_grant
        .verify_and_spend_gas(100, now + 101)
        .expect_err("expired");
    assert!(exp_err.contains("expired"), "{exp_err}");

    // 3. Registry enforcement: spending limits, expiry, scope under PQ session key
    let reg_grant = SessionKeyAuthorization::sign_delegation_falcon512(
        &falcon_master_fk,
        PqScheme::Falcon512,
        falcon_session_fk.public_key(),
        now + 500,
        5_000,
        SCOPE_TRANSFER,
        200,
        CHAIN_ID,
    );
    let mut registry = SessionKeyRegistry::default();
    let mut sim = SessionSpendSim::default();

    // Check with valid params succeeds
    assert!(registry
        .check(&reg_grant, 100, 1_000, SCOPE_TRANSFER, now, &mut sim)
        .is_ok());

    // Register on apply
    registry.note_applied(&reg_grant, 1_000);
    assert_eq!(registry.len(), 1);
    let rec = registry.get(&reg_grant.session_pubkey).expect("registered");
    assert_eq!(rec.gas_spent, 1_000);
    assert_eq!(rec.max_gas_spend, 5_000);

    // Scope enforcement: SCOPE_SVM_PAYLOAD rejected
    let mut sim2 = SessionSpendSim::default();
    assert_eq!(
        registry.check(&reg_grant, 100, 500, SCOPE_SVM_PAYLOAD, now, &mut sim2),
        Err(SessionRegistryError::OutOfScope)
    );

    // Value cap enforcement: amount 201 > max_value_per_tx (200) rejected
    assert_eq!(
        registry.check(&reg_grant, 201, 500, SCOPE_TRANSFER, now, &mut sim2),
        Err(SessionRegistryError::OutOfScope)
    );

    // Expiry enforcement: past valid_until rejected
    assert_eq!(
        registry.check(&reg_grant, 100, 500, SCOPE_TRANSFER, now + 501, &mut sim2),
        Err(SessionRegistryError::Expired)
    );

    // Spending limits in registry:
    // Spent 1_000, max 5_000 -> 4_000 remaining. Asking for 4_001 fails
    assert_eq!(
        registry.check(&reg_grant, 100, 4_001, SCOPE_TRANSFER, now, &mut sim2),
        Err(SessionRegistryError::BudgetExhausted)
    );
    // Asking for 4_000 succeeds
    assert!(registry
        .check(&reg_grant, 100, 4_000, SCOPE_TRANSFER, now, &mut sim2)
        .is_ok());
}

#[test]
fn test_revocation_of_pq_session_keys() {
    let falcon_master_fk = FalconKeypair::generate_from_seed(0x55);
    let falcon_session_fk = FalconKeypair::generate_from_seed(0x66);
    let now = 3_000_000u64;

    let grant = SessionKeyAuthorization::sign_delegation_falcon512(
        &falcon_master_fk,
        PqScheme::Falcon512,
        falcon_session_fk.public_key(),
        now + 1_000,
        10_000,
        SCOPE_ALL,
        1_000,
        CHAIN_ID,
    );

    let mut registry = SessionKeyRegistry::default();
    let mut sim = SessionSpendSim::default();

    // Key is initially not revoked
    assert!(!registry.is_revoked(&grant.session_pubkey));
    assert!(registry
        .check(&grant, 50, 500, SCOPE_TRANSFER, now, &mut sim)
        .is_ok());

    // Apply first transaction: registered in registry
    registry.note_applied(&grant, 500);
    assert!(!registry.is_revoked(&grant.session_pubkey));

    // Master revokes the PQ session key
    registry
        .entries
        .get_mut(&grant.session_pubkey)
        .unwrap()
        .revoked = true;
    assert!(registry.is_revoked(&grant.session_pubkey));

    // After revocation, registry.check fails terminal with Revoked
    let mut sim2 = SessionSpendSim::default();
    assert_eq!(
        registry.check(&grant, 50, 500, SCOPE_TRANSFER, now, &mut sim2),
        Err(SessionRegistryError::Revoked)
    );

    // Preventive revocation ("tombstone") of an unused PQ session key
    let unused_session_fk = FalconKeypair::generate_from_seed(0x77);
    let unused_grant = SessionKeyAuthorization::sign_delegation_falcon512(
        &falcon_master_fk,
        PqScheme::Falcon512,
        unused_session_fk.public_key(),
        now + 1_000,
        10_000,
        SCOPE_ALL,
        1_000,
        CHAIN_ID,
    );

    // Place tombstone
    registry.note_tombstone(unused_grant.session_pubkey, unused_grant.master_address);
    assert!(registry.is_revoked(&unused_grant.session_pubkey));

    // Even on first presentation, tombstoned PQ grant is rejected with Revoked
    assert_eq!(
        registry.check(&unused_grant, 50, 500, SCOPE_TRANSFER, now, &mut sim2),
        Err(SessionRegistryError::Revoked)
    );
}

#[test]
fn test_hybrid_session_key_signing_and_verification() {
    let master = key();
    let ed_session = key();
    let falcon_session_fk = FalconKeypair::generate_from_seed(0x88);
    let hybrid_session_pk = make_hybrid_pubkey(
        &ed_session.verifying_key().to_bytes(),
        falcon_session_fk.public_key(),
    );
    let now = 1_000_000u64;

    let grant = SessionKeyAuthorization::sign_delegation_ed25519_master(
        &master,
        PqScheme::Hybrid,
        &hybrid_session_pk,
        now + 1_000,
        10_000,
        SCOPE_ALL,
        1_000,
        CHAIN_ID,
    );

    assert_eq!(grant.master_scheme, PqScheme::Ed25519);
    assert_eq!(grant.session_scheme, PqScheme::Hybrid);
    assert!(grant.verify_signature());

    let msg = b"Transaction signed by hybrid session key";
    let hybrid_sig = sign_hybrid(&ed_session, &falcon_session_fk, msg);
    assert!(grant.verify_session_signature(msg, &hybrid_sig));

    // Tampering either half of hybrid session sig fails
    let mut bad_ed = hybrid_sig.clone();
    bad_ed[0] ^= 0xFF;
    assert!(!grant.verify_session_signature(msg, &bad_ed));

    let mut bad_falcon = hybrid_sig.clone();
    bad_falcon[64] ^= 0xFF;
    assert!(!grant.verify_session_signature(msg, &bad_falcon));
}

#[test]
fn test_ed25519_grant_bincode_encoding_backward_compatibility() {
    let master = key();
    let session = key();
    let d = grant(
        &master,
        &session,
        4_000_000_000,
        10_000,
        SCOPE_ALL,
        u64::MAX,
    );
    assert!(d.is_pure_ed25519());
    assert!(!d.is_post_quantum());

    let ser = bincode::serialize(&d).expect("serialization succeeds");
    let size = bincode::serialized_size(&d).expect("size check succeeds");
    assert_eq!(ser.len(), size as usize);
    assert_eq!(ser.len(), 184); // 32 + 32 + 8*6 + 8 + 64 = 184 bytes

    let back: SessionKeyAuthorization =
        bincode::deserialize(&ser).expect("deserialization succeeds");
    assert_eq!(d, back);
    assert!(back.is_pure_ed25519());
    assert!(back.verify_signature());

    let tx = session_tx(&session, d, 10, 1_000, 0, vec![]);
    assert!(tx.is_session_keyed());
    assert!(tx.verify_signature());
}

#[test]
fn test_falcon512_master_delegated_tx_end_to_end() {
    let falcon_master_fk = FalconKeypair::generate_from_seed(0x99);
    let session = key();
    let session_pk = session.verifying_key().to_bytes();
    let now = 1_000_000u64;

    let grant = SessionKeyAuthorization::sign_delegation_falcon512(
        &falcon_master_fk,
        PqScheme::Ed25519,
        &session_pk,
        now + 10_000,
        50_000,
        SCOPE_ALL,
        1_000,
        CHAIN_ID,
    );

    // Build envelope transaction under Falcon-512 master
    let tx = session_tx(&session, grant.clone(), 100, 2_000, 0, vec![]);
    assert!(tx.is_session_keyed());
    assert_eq!(tx.from, grant.master_address);
    assert!(
        tx.verify_signature(),
        "Transaction with Falcon-512 master grant must verify"
    );
}
