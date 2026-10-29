//! §9 confidential transfers on the LIVE block path.
//!
//! `tests/privacy_onchain_tests.rs` pins the engine in isolation: it calls
//! `ConfidentialState::apply_transfer` and `commitment_digest_with_confidential`
//! directly. Nothing there proves the shielded ledger is reachable from a
//! block - that the appended `OpCode::SysCallConfidentialTransfer` is actually
//! executed by the VM, that the engine commits the working copy back, and that
//! the conditional confidential domain reaches `get_state_root()`.
//!
//! These tests drive the opcode through `apply_block_transition` and pin:
//!
//! 1. a balanced transfer applies, rewrites the shielded balances/spent set and
//!    moves the state root;
//! 2. a forged (unbalanced) transfer is rejected and moves NOTHING - not the
//!    shielded ledger, not the root, not the nonce;
//! 3. the same input commitment cannot be spent twice, across blocks;
//! 4. holding a signed transaction without a block cannot move the root, and a
//!    block carrying it can;
//! 5. two nodes applying the same payload reach the same root;
//! 6. the fold itself: the trie's commitment leaf equals the
//!    confidential-aware digest while the shielded ledger is empty (zero bytes,
//!    `commitment_digest` byte-identical) and differs from it once it is not.
//!
//! Plus the fail-closed shape of the opcode outside the block path: a direct
//! `Svm::execute` caller has no ledger to offer, so the syscall reverts.

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;

use stellereum::commitment::{
    commitment_digest, commitment_digest_with_confidential, commitment_key,
};
use stellereum::crypto_privacy::{
    confidential_digest, ConfidentialState, ConfidentialTransfer, PedersenCommitment, RangeProof,
    ZERO_COMMITMENT,
};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, Svm, VmContext, VmExecutionResult};

mod support;
use support::{assert_refused_tx_paid_failure_fee, failure_fee};

/// A fixed, realistic block timestamp (never 0: 0 is exactly the timestamp bug
/// `tests/live_block_path_tests.rs` exists to prevent).
const BLOCK_TS: u64 = 1_760_000_000;
/// The shielded account the transfers credit. Deliberately NOT a funded
/// transparent account: the shielded ledger is keyed by its own addresses.
const RECIPIENT: [u8; 32] = [0x22; 32];

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sender_of(seed: u8) -> [u8; 32] {
    key(seed).verifying_key().to_bytes()
}

/// A valid one-in/one-out transfer: input (value + fee), output (value), both
/// with the SAME blinding, so `C_in - C_out == fee*G` exactly. Deterministic on
/// purpose: two calls build byte-identical commitments, which is what lets a
/// test replay the SAME inputs in a later block to try to double-spend them.
fn balanced_transfer(value: u64, fee: u64) -> ConfidentialTransfer {
    let r = Scalar::from(0x5EED_u64);
    let c_in = PedersenCommitment::commit(value + fee, &r);
    let c_out = PedersenCommitment::commit(value, &r);
    ConfidentialTransfer::new(vec![c_in], vec![c_out], fee)
}

/// An UNBALANCED transfer: 100 in, 1_000 out, no fee. The group equation is
/// off by 900*G, so conservation must refuse it before anything is written.
fn forged_transfer() -> ConfidentialTransfer {
    let r = Scalar::from(3u64);
    ConfidentialTransfer::new(
        vec![PedersenCommitment::commit(100, &r)],
        vec![PedersenCommitment::commit(1_000, &r)],
        0,
    )
}

/// Range proofs for a balanced transfer (values known: input value+fee,
/// output value, same blinding). Auto width per value (audit: speed) — all
/// test values fit 32 bits, so these exercise the default path; one case
/// below pins explicit 64-bit proofs as the whale-compat path.
fn prove_transfer(
    transfer: &ConfidentialTransfer,
    in_value: u64,
    out_value: u64,
    blinding: Scalar,
) -> (Vec<RangeProof>, Vec<RangeProof>) {
    let r = blinding;
    let ins = transfer
        .input_commitments
        .iter()
        .map(|c| RangeProof::prove_auto(c, in_value, &r))
        .collect();
    let outs = transfer
        .output_commitments
        .iter()
        .map(|c| RangeProof::prove_auto(c, out_value, &r))
        .collect();
    (ins, outs)
}

fn confidential_tx(
    sk: &SigningKey,
    recipient: [u8; 32],
    transfer: ConfidentialTransfer,
    in_value: u64,
    out_value: u64,
    blinding: Scalar,
    nonce: u64,
) -> Transaction {
    let (input_ranges, output_ranges) = prove_transfer(&transfer, in_value, out_value, blinding);
    let shield_in = transfer.input_commitments[0];
    Transaction::sign_with_payload(
        sk,
        // The transparent leg is empty: value moves shield-entry -> shielded
        // transfer inside the payload; only gas is reserved natively.
        [0xEE; 32],
        0,
        // Exact gas: shield + transfer2 at auto 32-bit widths.
        // The single-tx path charges gas_used while the block path charges
        // the declared limit (documented design) — pinning path EQUIVALENCE
        // needs them equal.
        stellereum::svm::GAS_CONFIDENTIAL_SHIELD
            + stellereum::svm::GAS_CONFIDENTIAL_TRANSFER2
            + 2 * stellereum::svm::GAS_CONFIDENTIAL_T2_PER_COMMITMENT
            + 64 * stellereum::svm::GAS_CONFIDENTIAL_T2_PER_BIT,
        nonce,
        1,
        1,
        vec![
            OpCode::SysCallConfidentialShield {
                commitment: shield_in.commitment,
                amount: in_value,
                blinding: blinding.to_bytes(),
            },
            OpCode::SysCallConfidentialTransfer2 {
                recipient,
                transfer: Box::new(transfer),
                input_ranges,
                output_ranges,
            },
        ],
    )
}

/// A block carrying `txs`. No QC (so no downtime slash, deterministically) and
/// no block reward: whatever moves the root here moved because of the payload.
fn block(proposer: [u8; 32], height: u64, txs: Vec<Transaction>) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: BLOCK_TS + height,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    }
}

/// A proposer that is NOT the sender.
///
/// WHY A SEPARATE PROPOSER: the block path pays the collected fees to the
/// block's proposer. With the sender as its own proposer the failure fee
/// (F-01 / SEC-07) would be debited from the sender and credited straight
/// back to it - the sender's balance would not move and the "a refusal is
/// not free" policy would be invisible. With a distinct proposer the fee is
/// visibly PAID BY THE SENDER (and earned by the proposer), which is what the
/// F-01 contract says.
const PROPOSER: [u8; 32] = [0xF1; 32];

async fn funded_engine(seed: u8, balance: u64) -> (InMemoryStateEngine, [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let addr = sender_of(seed);
    engine
        .update_account(AccountState::new(addr, balance))
        .await;
    (engine, addr)
}

/// The value the trie actually holds under the commitment key - the leaf that
/// makes the non-trie subsystems part of the state root.
async fn committed_digest(engine: &InMemoryStateEngine) -> Vec<u8> {
    engine
        .state_trie
        .read()
        .await
        .get(&commitment_key())
        .expect("the commitment digest must be written into the trie")
        .to_vec()
}

// ===========================================================================
// 1. A balanced transfer applies through the live block path.
// ===========================================================================

#[tokio::test]
async fn valid_confidential_transfer_applies_on_the_live_block_path() {
    let (engine, sender) = funded_engine(0x11, 1_000_000).await;
    let genesis_root = engine.get_state_root().await;
    assert!(
        engine.confidential_read().await.is_empty(),
        "a fresh chain has no shielded history"
    );

    let transfer = balanced_transfer(1_480, 20);
    let input = transfer.input_commitments[0];
    let output = transfer.output_commitments[0];
    let tx = confidential_tx(
        &key(0x11),
        RECIPIENT,
        transfer.clone(),
        1_480 + 20,
        1_480,
        Scalar::from(0x5EED_u64),
        0,
    );

    let out = engine
        .apply_block_transition(&block(sender, 1, vec![tx]), 0)
        .await;
    assert_eq!(
        (out.applied, out.failed),
        (1, 0),
        "the confidential payload applies: {out:?}"
    );
    assert_eq!(out.status, vec![true]);

    let state = engine.confidential_read().await;
    assert!(!state.is_empty(), "the shielded ledger now has history");
    assert_eq!(
        state.balance(&sender),
        ZERO_COMMITMENT.sub(&input).unwrap(),
        "the signer is debited by exactly the input commitment"
    );
    assert_eq!(
        state.balance(&RECIPIENT),
        ZERO_COMMITMENT.add(&output).unwrap(),
        "the recipient is credited by exactly the output commitment"
    );
    assert!(
        state.is_spent(&input.commitment),
        "the input joins the spent set"
    );
    assert_eq!(state.total_fees, 20, "the fee total advances");
    drop(state);

    // The transaction is still an ordinary transaction: the plain fee moved and
    // the nonce advanced, so the root would move anyway. The point below is the
    // fold: the trie's commitment leaf must now be the CONFIDENTIAL-aware
    // digest, and must differ from the digest of every other subsystem alone.
    let root_after = engine.get_state_root().await;
    assert_ne!(
        root_after, genesis_root,
        "a shielded transfer must move the root"
    );

    let leaf = committed_digest(&engine).await;
    let shielded = engine.confidential_read().await.clone();
    let snapshot = engine.commitment_snapshot().await;
    assert_eq!(
        leaf,
        commitment_digest_with_confidential(&snapshot, &shielded),
        "the committed digest is the confidential-aware one"
    );
    assert_ne!(
        leaf,
        commitment_digest(&snapshot),
        "a non-empty shielded ledger must be visible in the commitment"
    );
}

// ===========================================================================
// 2. A forged balance is rejected and moves nothing.
// ===========================================================================

#[tokio::test]
async fn forged_confidential_transfer_is_rejected_without_moving_state() {
    let (engine, sender) = funded_engine(0x22, 1_000_000).await;
    let root_before = engine.get_state_root().await;
    let leaf_before = committed_digest(&engine).await;

    // Admitted (funded, correct nonce) so the PAYLOAD is what refuses it -
    // otherwise this would only prove admission works.
    // Proofs over the FORGED blinding (r=3): individually valid (both values
    // fit 32 bits) — the equation itself must fail, not the proofs.
    let forged = forged_transfer();
    let tx = confidential_tx(
        &key(0x22),
        RECIPIENT,
        forged,
        100,
        1000,
        Scalar::from(3u64),
        0,
    );
    let fee = failure_fee(&engine, &tx).await;
    let out = engine
        .apply_block_transition(&block(PROPOSER, 1, vec![tx.clone()]), 0)
        .await;

    assert_eq!(
        (out.applied, out.failed),
        (0, 1),
        "the forged transfer must be rejected: {out:?}"
    );
    assert_eq!(out.status, vec![false], "receipt says failed");
    // F-01 / SEC-07: the refusal is ATTRIBUTABLE (the payload ran and the
    // conservation check refused it), so the sender pays the failure fee -
    // its DECLARED limit on this path - and its nonce is consumed. A free
    // failure is a free DoS and a free replay.
    assert_eq!(
        out.fees_collected, fee,
        "a rejected transaction pays the failure fee"
    );
    assert_ne!(fee, 0, "a refusal is never free");

    let state = engine.confidential_read().await;
    assert!(
        state.is_empty(),
        "a rejected transfer must not write a balance, a spent input or a fee"
    );
    assert_eq!(
        confidential_digest(&state),
        confidential_digest(&ConfidentialState::new()),
        "the shielded digest is untouched"
    );
    drop(state);

    // The VALUE did not move: the sender lost exactly the failure fee and
    // nothing else - no shielded coin was minted, burned or transferred.
    assert_ne!(PROPOSER, sender, "the proposer must not be the sender");
    assert_refused_tx_paid_failure_fee(&engine, &tx, fee, 1_000_000, 0).await;
    assert_eq!(
        engine.get_account(&PROPOSER).await.unwrap().balance,
        fee,
        "the failure fee was paid to the block's proposer - it left the sender"
    );

    let root_after = engine.get_state_root().await;
    assert_ne!(
        root_after, root_before,
        "F-01: the failure fee is a state change, so the root moves"
    );
    assert_eq!(
        committed_digest(&engine).await,
        leaf_before,
        "but the COMMITTED domains (the shielded ledger included) are byte-identical: \
         nothing but the fee moved"
    );
}

// ===========================================================================
// 3. The same input commitment cannot be spent twice - across blocks.
// ===========================================================================

#[tokio::test]
async fn double_spend_is_rejected_across_blocks() {
    let (engine, sender) = funded_engine(0x33, 1_000_000).await;
    let input = balanced_transfer(500, 10).input_commitments[0];

    // Block 1: the real spend.
    //
    // The proposer is NOT the sender (see `PROPOSER`): the block path pays
    // the collected fees to the proposer, so a self-proposing sender would
    // get its own fee back and the "a refusal is not free" policy would be
    // invisible. Every block here uses a distinct proposer so the fee the
    // sender pays is directly observable in its balance.
    let first = confidential_tx(
        &key(0x33),
        RECIPIENT,
        balanced_transfer(500, 10),
        500 + 10,
        500,
        Scalar::from(0x5EED_u64),
        0,
    );
    let out1 = engine
        .apply_block_transition(&block(PROPOSER, 1, vec![first]), 0)
        .await;
    assert_eq!((out1.applied, out1.failed), (1, 0), "{out1:?}");

    let root1 = engine.get_state_root().await;
    let shielded1 = {
        let state = engine.confidential_read().await;
        assert!(state.is_spent(&input.commitment));
        confidential_digest(&state)
    };

    // Block 2: the SAME transfer, one nonce later. The commitments are
    // deterministic, so this really is the same input commitment being offered
    // again - the nullifier set must catch it.
    let replay = confidential_tx(
        &key(0x33),
        RECIPIENT,
        balanced_transfer(500, 10),
        500 + 10,
        500,
        Scalar::from(0x5EED_u64),
        1,
    );
    let fee = failure_fee(&engine, &replay).await;
    let balance_after_block1 = engine.get_account(&sender).await.unwrap().balance;
    let proposer_after_block1 = engine.get_account(&PROPOSER).await.unwrap().balance;
    let out2 = engine
        .apply_block_transition(&block(PROPOSER, 2, vec![replay.clone()]), 0)
        .await;
    assert_eq!(
        (out2.applied, out2.failed),
        (0, 1),
        "the replay must be rejected: {out2:?}"
    );
    assert_eq!(out2.status, vec![false]);

    let state = engine.confidential_read().await;
    assert_eq!(
        confidential_digest(&state),
        shielded1,
        "a rejected double-spend must leave the shielded digest where it was"
    );
    assert_eq!(
        state.spent.len(),
        1,
        "the spent set grows by exactly the one real spend"
    );
    assert_eq!(state.total_fees, 10, "the rejected replay adds no fee");
    drop(state);

    // F-01 / SEC-07: the refused replay is attributable - it got past
    // admission and the nullifier set caught it - so the sender pays the
    // failure fee and its nonce is consumed. The shielded ledger is
    // byte-identical (asserted above), but the sender's leaf changed, so the
    // root moves. (The fee is VISIBLE in the sender's balance only because
    // the block's proposer is somebody else - see `PROPOSER`.)
    assert_refused_tx_paid_failure_fee(&engine, &replay, fee, balance_after_block1, 1).await;
    assert_eq!(
        engine.get_account(&PROPOSER).await.unwrap().balance,
        proposer_after_block1 + fee,
        "the failure fee was paid to the block's proposer - it left the sender"
    );
    assert_ne!(
        engine.get_state_root().await,
        root1,
        "the failure fee is a state change: the root moves"
    );
}

// ===========================================================================
// 4. The root moves because of the BLOCK, never because of a held transaction.
// ===========================================================================

#[tokio::test]
async fn holding_a_transaction_without_a_block_does_not_move_the_root() {
    let (engine, sender) = funded_engine(0x44, 1_000_000).await;
    let root0 = engine.get_state_root().await;
    let leaf0 = committed_digest(&engine).await;

    // Signed, verified, sitting in hand - and nothing about it has touched
    // consensus state. A transaction is a claim, not an effect.
    let tx = confidential_tx(
        &key(0x44),
        RECIPIENT,
        balanced_transfer(900, 5),
        900 + 5,
        900,
        Scalar::from(0x5EED_u64),
        0,
    );
    assert!(tx.verify_signature(), "the held transaction is valid");

    assert_eq!(
        engine.get_state_root().await,
        root0,
        "holding a signed confidential transaction must not move the root"
    );
    assert!(engine.confidential_read().await.is_empty());
    assert_eq!(committed_digest(&engine).await, leaf0);

    // The BLOCK is what applies it.
    let out = engine
        .apply_block_transition(&block(sender, 1, vec![tx]), 0)
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");
    assert!(!engine.confidential_read().await.is_empty());
    assert_ne!(
        engine.get_state_root().await,
        root0,
        "the block that carries it moves the root"
    );
}

// ===========================================================================
// 5. Two nodes, the same payload, the same root.
// ===========================================================================

#[tokio::test]
async fn two_nodes_applying_the_same_payload_reach_the_same_root() {
    let (node_a, sender) = funded_engine(0x55, 1_000_000).await;
    let (node_b, _) = funded_engine(0x55, 1_000_000).await;
    assert_eq!(
        node_a.get_state_root().await,
        node_b.get_state_root().await,
        "identical genesis: identical roots"
    );

    // Deterministic signing + deterministic commitments: building the block
    // twice yields the same bytes, exactly like two nodes gossiping one block.
    let block_a = block(
        sender,
        1,
        vec![confidential_tx(
            &key(0x55),
            RECIPIENT,
            balanced_transfer(1_234, 56),
            1_234 + 56,
            1_234,
            Scalar::from(0x5EED_u64),
            0,
        )],
    );
    let block_b = block_a.clone();

    let out_a = node_a.apply_block_transition(&block_a, 0).await;
    let out_b = node_b.apply_block_transition(&block_b, 0).await;
    assert_eq!((out_a.applied, out_a.failed), (1, 0), "{out_a:?}");
    assert_eq!((out_b.applied, out_b.failed), (1, 0), "{out_b:?}");

    let root_a = node_a.get_state_root().await;
    let root_b = node_b.get_state_root().await;
    assert_eq!(root_a, root_b, "same payload => same state root");
    assert_eq!(
        root_a,
        node_a.get_state_root().await,
        "the root is stable across reads"
    );

    let shielded_a = {
        let s = node_a.confidential_read().await.clone();
        confidential_digest(&s)
    };
    let shielded_b = {
        let s = node_b.confidential_read().await.clone();
        confidential_digest(&s)
    };
    assert_eq!(
        shielded_a, shielded_b,
        "same payload => same shielded digest"
    );
    assert_eq!(
        committed_digest(&node_a).await,
        committed_digest(&node_b).await,
        "same payload => same committed digest"
    );
}

// ===========================================================================
// 6. The fold is conditional: empty writes ZERO bytes into the digest.
// ===========================================================================

#[tokio::test]
async fn the_committed_digest_folds_the_shielded_domain_conditionally() {
    let (engine, sender) = funded_engine(0x66, 1_000_000).await;

    // Empty shielded ledger: the leaf in the trie is byte-for-byte the digest
    // of the OTHER subsystems alone. That equality is what lets this domain
    // join the commitment without bumping COMMITMENT_VERSION or re-pinning the
    // genesis KAT (`tests/genesis_root_known_answer_tests.rs`).
    engine.get_state_root().await;
    let snapshot = engine.commitment_snapshot().await;
    assert_eq!(
        committed_digest(&engine).await,
        commitment_digest(&snapshot),
        "an empty shielded ledger must contribute zero bytes to the digest"
    );
    drop(snapshot);

    // ...and the moment it is used, the leaf becomes the confidential-aware
    // digest - the fold point is live, not merely present in the source.
    let tx = confidential_tx(
        &key(0x66),
        RECIPIENT,
        balanced_transfer(1, 1),
        1 + 1,
        1,
        Scalar::from(0x5EED_u64),
        0,
    );
    let out = engine
        .apply_block_transition(&block(sender, 1, vec![tx]), 0)
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");

    let snapshot = engine.commitment_snapshot().await;
    let shielded = engine.confidential_read().await.clone();
    assert!(!shielded.is_empty());
    assert_eq!(
        committed_digest(&engine).await,
        commitment_digest_with_confidential(&snapshot, &shielded)
    );
    assert_ne!(
        committed_digest(&engine).await,
        commitment_digest(&snapshot),
        "a used shielded ledger must be visible in the commitment"
    );
}

// ===========================================================================
// 7. Outside the block path the opcode fails closed.
// ===========================================================================

#[test]
fn direct_svm_execution_without_a_ledger_reverts() {
    let sender = sender_of(0x77);
    let mut ctx = VmContext {
        sender,
        balance: 1_000_000,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        zkml_proof: None,
        timestamp: BLOCK_TS,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: None,
        token_events: Vec::new(),
        contracts: None,
        staking: None,
        pmm: None,
        min_validator_bond: stellereum::staking::MIN_VALIDATOR_BOND,
        default_commission_bps: stellereum::staking::DEFAULT_COMMISSION_BPS,
        payouts: Vec::new(),
        oracle: None,
    };
    let ops = vec![OpCode::SysCallConfidentialTransfer {
        recipient: RECIPIENT,
        transfer: Box::new(balanced_transfer(10, 1)),
    }];

    // V1 is DISABLED (audit 2026-10-06 F-A): fail closed with the migration
    // pointer, ledger or not.
    match Svm::execute(&ops, 1_000_000, &mut ctx) {
        VmExecutionResult::Reverted(msg) => {
            assert!(msg.contains("disabled"), "unexpected revert reason: {msg}")
        }
        other => panic!("expected a revert, got {other:?}"),
    }

    // V2 without a ledger still fails closed (no state to apply against).
    let t2 = balanced_transfer(10, 1);
    let (ir, or_) = prove_transfer(&t2, 11, 10, Scalar::from(0x5EED_u64));
    let ops2 = vec![OpCode::SysCallConfidentialTransfer2 {
        recipient: RECIPIENT,
        transfer: Box::new(t2),
        input_ranges: ir,
        output_ranges: or_,
    }];
    match Svm::execute(&ops2, 1_000_000, &mut ctx) {
        VmExecutionResult::Reverted(msg) => assert!(
            msg.contains("confidential state not available"),
            "unexpected revert reason: {msg}"
        ),
        other => panic!("expected a revert, got {other:?}"),
    }
}

// ===========================================================================
// 8. The single-transaction path and the block path cannot disagree.
// ===========================================================================

#[tokio::test]
async fn single_tx_path_and_block_path_agree_on_the_shielded_ledger() {
    // ONE tx through both paths (audit 2026-10-06: range proofs randomize
    // per build, so two builds are different txs with different hashes —
    // identical INPUTS is the premise being pinned, not identical builds).
    let transfer = balanced_transfer(777, 33);
    let tx = confidential_tx(
        &key(0x88),
        RECIPIENT,
        transfer,
        777 + 33,
        777,
        Scalar::from(0x5EED_u64),
        0,
    );

    let single = InMemoryStateEngine::new();
    let live = InMemoryStateEngine::new();
    for e in [&single, &live] {
        e.update_account(AccountState::new(sender_of(0x88), 1_000_000))
            .await;
    }

    single
        .apply_transaction(&tx, BLOCK_TS)
        .await
        .expect("the single-tx path applies the transfer");
    let (applied, failed, _, _, _) = live
        .apply_block_parallel_fees(std::slice::from_ref(&tx), BLOCK_TS)
        .await;
    assert_eq!((applied, failed), (1, 0));

    let shielded_single = single.confidential_read().await.clone();
    let shielded_live = live.confidential_read().await.clone();
    assert_eq!(
        shielded_single, shielded_live,
        "both paths must reach the same shielded ledger"
    );
    assert_eq!(
        single.get_state_root().await,
        live.get_state_root().await,
        "both paths must commit identical state"
    );
}

// ===========================================================================
// F-A enforced loop (audit 2026-10-06): shield -> transfer2 -> unshield,
// plus every refusal.
// ===========================================================================

fn shield_tx(sk: &SigningKey, amount: u64, blinding: Scalar, nonce: u64) -> Transaction {
    use stellereum::crypto_privacy::PedersenCommitment;
    let c = PedersenCommitment::commit(amount, &blinding);
    Transaction::sign_with_payload(
        sk,
        [0xEE; 32],
        0,
        50_000,
        nonce,
        1,
        1,
        vec![OpCode::SysCallConfidentialShield {
            commitment: c.commitment,
            amount,
            blinding: blinding.to_bytes(),
        }],
    )
}

fn unshield_tx(sk: &SigningKey, openings: Vec<(u64, Scalar)>, nonce: u64) -> Transaction {
    use stellereum::crypto_privacy::{PedersenCommitment, UnshieldInput};
    let inputs = openings
        .iter()
        .map(|(amount, b)| {
            let c = PedersenCommitment::commit(*amount, b);
            UnshieldInput {
                commitment: c.commitment,
                amount: *amount,
                blinding: b.to_bytes(),
            }
        })
        .collect();
    Transaction::sign_with_payload(
        sk,
        [0xEE; 32],
        0,
        50_000,
        nonce,
        1,
        1,
        vec![OpCode::SysCallConfidentialUnshield { inputs }],
    )
}

#[tokio::test]
async fn enforced_loop_shield_transfer_unshield_moves_native_both_ways() {
    let (engine, sender) = funded_engine(0x71, 10_000_000).await;
    let r = Scalar::from(0xBEEF_u64);
    let c = stellereum::crypto_privacy::PedersenCommitment::commit(100_000, &r);

    // 1. Shield 100k native -> owned commitment. Escrow credited.
    let out = engine
        .apply_block_transition(
            &block(sender, 1, vec![shield_tx(&key(0x71), 100_000, r, 0)]),
            0,
        )
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");
    assert_eq!(
        engine.confidential_read().await.owned.get(&c.commitment),
        Some(&sender),
        "shield records ownership to the sender"
    );
    let escrow = engine
        .get_account(&stellereum::crypto_privacy::SHIELD_ESCROW)
        .await
        .unwrap();
    assert_eq!(escrow.balance, 100_000, "escrow backs the shielded coin");

    // 2. Transfer the shielded coin to RECIPIENT (fresh outputs, proven).
    // Same blinding both sides (like `balanced_transfer`): the equation
    // needs (r_in - r_out)*H == 0, so conservation holds exactly.
    let c_out = stellereum::crypto_privacy::PedersenCommitment::commit(99_900, &r);
    let t = stellereum::crypto_privacy::ConfidentialTransfer::new(vec![c], vec![c_out], 100);
    let ir = vec![RangeProof::prove(&c, 100_000, &r, 32)];
    let or_ = vec![RangeProof::prove(&c_out, 99_900, &r, 32)];
    let ttx = Transaction::sign_with_payload(
        &key(0x71),
        [0xEE; 32],
        0,
        50_000,
        1,
        1,
        1,
        vec![OpCode::SysCallConfidentialTransfer2 {
            recipient: RECIPIENT,
            transfer: Box::new(t),
            input_ranges: ir,
            output_ranges: or_,
        }],
    );
    let out = engine
        .apply_block_transition(&block(sender, 2, vec![ttx]), 0)
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");
    assert_eq!(
        engine
            .confidential_read()
            .await
            .owned
            .get(&c_out.commitment),
        Some(&RECIPIENT),
        "output owned by the recipient"
    );

    // 3. Unshield is impossible for the sender now (it owns nothing).
    let bad = unshield_tx(&key(0x71), vec![(99_900, r)], 2);
    let out = engine
        .apply_block_transition(&block(sender, 3, vec![bad]), 0)
        .await;
    assert_eq!(
        (out.applied, out.failed),
        (0, 1),
        "sender owns nothing: {out:?}"
    );
}

#[tokio::test]
async fn shield_rejects_wrong_opening_and_unshield_rejects_strangers() {
    let (engine, sender) = funded_engine(0x72, 10_000_000).await;
    let r = Scalar::from(7u64);

    // Wrong amount for the commitment.
    let c = stellereum::crypto_privacy::PedersenCommitment::commit(5_000, &r);
    let lie = Transaction::sign_with_payload(
        &key(0x72),
        [0xEE; 32],
        0,
        50_000,
        0,
        1,
        1,
        vec![OpCode::SysCallConfidentialShield {
            commitment: c.commitment,
            amount: 9_999,
            blinding: r.to_bytes(),
        }],
    );
    // F-01 / SEC-07: the refusal is attributable, so it pays the failure fee
    // and CONSUMES THE NONCE - the honest shield below is therefore signed
    // with nonce 1.
    //
    // The block's proposer is NOT the sender (see `PROPOSER`): the block path
    // pays the collected fees to the proposer, so a self-proposing sender
    // would get its own failure fee straight back and the "a refusal is not
    // free" policy would be invisible in the balance. With a distinct
    // proposer the fee the sender pays is directly observable.
    let lie_fee = failure_fee(&engine, &lie).await;
    let before_lie = engine.get_account(&sender).await.unwrap().balance;
    let out = engine
        .apply_block_transition(&block(PROPOSER, 1, vec![lie.clone()]), 0)
        .await;
    assert_eq!(
        (out.applied, out.failed),
        (0, 1),
        "opening must match: {out:?}"
    );
    assert_refused_tx_paid_failure_fee(&engine, &lie, lie_fee, before_lie, 0).await;
    assert_eq!(
        engine.get_account(&PROPOSER).await.unwrap().balance,
        lie_fee,
        "the failure fee was paid to the block's proposer - it left the sender"
    );

    // Honest shield, then a STRANGER tries to unshield it by naming it.
    let ok = shield_tx(&key(0x72), 5_000, r, 1);
    let out = engine
        .apply_block_transition(&block(PROPOSER, 1, vec![ok]), 0)
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");
    let stranger = unshield_tx(&key(0x73), vec![(5_000, r)], 0);
    // Fund the stranger natively so admission passes and the PAYLOAD refuses.
    engine
        .update_account(stellereum::state_engine::AccountState::new(
            sender_of(0x73),
            1_000_000,
        ))
        .await;
    let stranger_fee = failure_fee(&engine, &stranger).await;
    let before_stranger = engine.get_account(&sender_of(0x73)).await.unwrap().balance;
    let out = engine
        .apply_block_transition(&block(PROPOSER, 2, vec![stranger.clone()]), 0)
        .await;
    assert_eq!(
        (out.applied, out.failed),
        (0, 1),
        "stranger cannot exit another's coin: {out:?}"
    );
    // The stranger's refusal is not free either - it pays its failure fee and
    // burns its nonce, and takes nothing of the shielded coin.
    assert_refused_tx_paid_failure_fee(&engine, &stranger, stranger_fee, before_stranger, 0).await;
    assert_eq!(
        engine.get_account(&sender_of(0x73)).await.unwrap().balance,
        before_stranger - stranger_fee,
        "the stranger gained nothing from the refusal"
    );
}

#[tokio::test]
async fn unshield_releases_exact_native_and_drains_escrow() {
    let (engine, sender) = funded_engine(0x74, 10_000_000).await;
    let r = Scalar::from(0xCAFE_u64);
    let before = engine.get_account(&sender).await.unwrap().balance;

    // Shield 50k.
    let out = engine
        .apply_block_transition(
            &block(sender, 1, vec![shield_tx(&key(0x74), 50_000, r, 0)]),
            0,
        )
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");

    // Exit the same coin: exact native back, escrow drained.
    let exit = unshield_tx(&key(0x74), vec![(50_000, r)], 1);
    let out = engine
        .apply_block_transition(&block(sender, 2, vec![exit]), 0)
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");
    let escrow = engine
        .get_account(&stellereum::crypto_privacy::SHIELD_ESCROW)
        .await
        .unwrap();
    assert_eq!(
        escrow.balance, 0,
        "every shielded coin exited: escrow empty"
    );
    let after = engine.get_account(&sender).await.unwrap().balance;
    // Exact round-trip: -50k shield +50k exit -100k gas +100k proposer reward
    // (the test proposer IS the sender, so fees come back). No creation, no
    // destruction — the escrow assert above is the conservation proof.
    assert_eq!(after, before, "native round-trips exactly: {after}");

    // The coin is spent: exiting again fails.
    let again = unshield_tx(&key(0x74), vec![(50_000, r)], 2);
    let out = engine
        .apply_block_transition(&block(sender, 3, vec![again]), 0)
        .await;
    assert_eq!(
        (out.applied, out.failed),
        (0, 1),
        "double-exit refused: {out:?}"
    );
}

#[tokio::test]
async fn engine_restore_upgrades_v1_confidential_snapshot() {
    use stellereum::crypto_privacy::ConfidentialStateV1;
    // Persist a V1-shape ledger through the real restore path.
    let v1 = ConfidentialStateV1 {
        balances: [(sender_of(0x75), stellereum::crypto_privacy::ZERO_COMMITMENT)]
            .into_iter()
            .collect(),
        spent: Default::default(),
        total_fees: 0,
    };
    let bytes = bincode::serialize(&v1).expect("v1 serializes");
    let engine = InMemoryStateEngine::new();
    engine
        .restore_confidential(&bytes)
        .await
        .expect("upgrade restore");
    let state = engine.confidential_read().await;
    assert!(state.owned.is_empty());
    assert_eq!(state.total_fees, 0);
}

#[tokio::test]
async fn unshield_rejects_duplicate_inputs_without_paying_double() {
    // CRITICAL regression (audit 2026-10-06): the same coin listed twice
    // paid out 2X from pooled escrow. Must revert, escrow untouched.
    let (engine, sender) = funded_engine(0x75, 10_000_000).await;
    let r = Scalar::from(0xD9u64);
    let out = engine
        .apply_block_transition(
            &block(sender, 1, vec![shield_tx(&key(0x75), 50_000, r, 0)]),
            0,
        )
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");
    let esc_before = engine
        .get_account(&stellereum::crypto_privacy::SHIELD_ESCROW)
        .await
        .unwrap()
        .balance;
    let dbl = unshield_tx(&key(0x75), vec![(50_000, r), (50_000, r)], 1);
    let out = engine
        .apply_block_transition(&block(sender, 2, vec![dbl]), 0)
        .await;
    assert_eq!(
        (out.applied, out.failed),
        (0, 1),
        "duplicate inputs must revert: {out:?}"
    );
    let esc_after = engine
        .get_account(&stellereum::crypto_privacy::SHIELD_ESCROW)
        .await
        .unwrap()
        .balance;
    assert_eq!(esc_after, esc_before, "no double-pay from escrow");
}

#[tokio::test]
async fn reshield_live_commitment_is_refused() {
    // Follow-up verifier: the is_owned gate had zero test coverage.
    let (engine, sender) = funded_engine(0x76, 10_000_000).await;
    let r = Scalar::from(0xBE5_u64);
    let ok = shield_tx(&key(0x76), 50_000, r, 0);
    let out = engine
        .apply_block_transition(&block(sender, 1, vec![ok]), 0)
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");
    // Same opening again: already shielded, not a second coin.
    let dup = shield_tx(&key(0x76), 50_000, r, 1);
    let out = engine
        .apply_block_transition(&block(sender, 2, vec![dup]), 0)
        .await;
    assert_eq!(
        (out.applied, out.failed),
        (0, 1),
        "re-shield must revert: {out:?}"
    );
}

#[tokio::test]
async fn transfer2_to_protocol_account_is_refused() {
    // Follow-up verifier: outputs to vaults freeze forever.
    use stellereum::crypto_privacy::{PedersenCommitment, RangeProof, SHIELD_ESCROW};
    let (engine, sender) = funded_engine(0x77, 10_000_000).await;
    let r = Scalar::from(0x5EED_u64);
    let c_in = PedersenCommitment::commit(810, &r);
    let c_out = PedersenCommitment::commit(777, &r);
    // Fund first via shield so only the recipient rule fires.
    let s = shield_tx(&key(0x77), 810, r, 0);
    let out = engine
        .apply_block_transition(&block(sender, 1, vec![s]), 0)
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");
    let t = stellereum::crypto_privacy::ConfidentialTransfer::new(vec![c_in], vec![c_out], 33);
    let ir = vec![RangeProof::prove(&c_in, 810, &r, 64)];
    let or_ = vec![RangeProof::prove(&c_out, 777, &r, 64)];
    let tx = Transaction::sign_with_payload(
        &key(0x77),
        [0xEE; 32],
        0,
        50_000,
        1,
        1,
        1,
        vec![OpCode::SysCallConfidentialTransfer2 {
            recipient: SHIELD_ESCROW,
            transfer: Box::new(t),
            input_ranges: ir,
            output_ranges: or_,
        }],
    );
    let out = engine
        .apply_block_transition(&block(sender, 2, vec![tx]), 0)
        .await;
    assert_eq!(
        (out.applied, out.failed),
        (0, 1),
        "vault recipient must revert: {out:?}"
    );
}
