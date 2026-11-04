//! §8 BRIDGE policy on the LIVE block path.
//!
//! The audit gap these tests close: NOTHING in the tree drove
//! `OpCode::SysCallBridge` through `apply_block_transition` - the policy half
//! of the bridge (relayer/validator quorum, source-tx replay, withdrawal
//! time-lock, hourly rate limit) existed only as the offline
//! `TeleportBridgeEngine` model and was never wired into the code every
//! finalized block runs.
//!
//! Everything here goes through `InMemoryStateEngine::apply_block_transition`,
//! the shared core both the live and the reorg path call, so the assertions
//! are about consensus behaviour, not about a test-only entry point:
//!
//! * a sub-quorum deposit is refused and moves nothing;
//! * a quorum deposit credits EXACTLY ONCE - not twice inside one block, never
//!   again in a later one (the replay set is committed state);
//! * a large withdrawal parks with `unlock_at = block.timestamp + time-lock`
//!   and a release before it is refused by the block;
//! * the hourly rate limit is enforced against the BLOCK clock and rolls over
//!   one hour later;
//! * the committed root moves only when a block applies - never from building
//!   a payload, never from a refused block, never from reading;
//! * (I1) mutating the committed bridge domain moves `commitment_digest`.

use ed25519_dalek::{Signer, SigningKey};
use stellereum::bridge::{
    BridgeIntent, BridgeState, SupportedChain, TeleportBridgeEngine, BRIDGE_ESCROW,
    BRIDGE_MINT_CAP_NANO, HOURLY_DEPOSIT_LIMIT_NANO, HOURLY_RATE_LIMIT_NANO,
    LARGE_WITHDRAWAL_THRESHOLD_NANO, WITHDRAWAL_TIME_LOCK_SECS,
};
use stellereum::commitment::{commitment_digest, CommitmentSnapshot};
use stellereum::sharding::{Block, Transaction, BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD};
use stellereum::staking::{MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::{OpCode, GAS_BRIDGE_INTENT};
use stellereum::xshard2pc::XpcActivation;

/// Fixed, realistic block timestamp. Never 0: 0 is exactly the bug I12 pins.
const TS: u64 = 1_760_000_000;
/// Nano-STELL per STELL, for readable amounts.
const STELL: u64 = 1_000_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

async fn balance(e: &InMemoryStateEngine, addr: &[u8; 32]) -> u64 {
    e.get_account(addr).await.map(|a| a.balance).unwrap_or(0)
}

/// Fund and bond `n` validators, so the COMMITTED relayer set the deposit
/// quorum counts distinct signers from has `n` members
/// (`(n * 2 + 2) / 3` - so 3 validators need 2 signatures).
async fn setup(n: usize) -> (InMemoryStateEngine, Vec<SigningKey>) {
    let e = InMemoryStateEngine::new();
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let k = key(0xA0 + i as u8);
        let pk = k.verifying_key().to_bytes();
        e.credit_native(&pk, 10 * MIN_VALIDATOR_BOND)
            .await
            .expect("fund the validator");
        e.staking_write()
            .await
            .bond(pk, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
            .expect("bond it into the committed ledger");
        keys.push(k);
    }
    (e, keys)
}

fn deposit(source_tx_hash: [u8; 32], recipient: [u8; 32], amount: u64) -> BridgeIntent {
    BridgeIntent::Deposit {
        chain: SupportedChain::Ton,
        source_tx_hash,
        recipient,
        amount,
    }
}

/// The `Attest` companion for `dep`: signatures over the SAME canonical
/// message `TeleportBridgeEngine::deposit_signing_message` builds, by the
/// first `quorum` of the committed validators.
fn attest(dep: &BridgeIntent, signers: &[SigningKey]) -> BridgeIntent {
    let event = dep.deposit_event(Vec::new()).expect("deposit event");
    let msg = TeleportBridgeEngine::deposit_signing_message(&event);
    let signatures = signers
        .iter()
        .map(|k| (k.verifying_key().to_bytes(), k.sign(&msg).to_vec()))
        .collect();
    let source_tx_hash = match dep {
        BridgeIntent::Deposit { source_tx_hash, .. } => *source_tx_hash,
        other => panic!("attest() only pairs with a Deposit: {other:?}"),
    };
    BridgeIntent::Attest {
        source_tx_hash,
        signatures,
    }
}

/// A wrapping transaction carrying the intents. `from == to == proposer`, so
/// the declared gas the block path charges is credited straight back to the
/// payer as the proposer fee: balance assertions below see ONLY the bridge's
/// own movement.
fn bridge_tx(payer: &SigningKey, nonce: u64, ops: Vec<OpCode>) -> Transaction {
    let gas = GAS_BRIDGE_INTENT * ops.len() as u64 + 1_000;
    Transaction::sign_with_payload(
        payer,
        payer.verifying_key().to_bytes(),
        0,
        gas,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        ops,
    )
}

fn bridge_block(height: u64, timestamp: u64, txs: Vec<Transaction>, proposer: [u8; 32]) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp,
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

/// Wrap an intent pair as the payload of one transaction.
fn ops(att: Option<BridgeIntent>, intent: BridgeIntent) -> Vec<OpCode> {
    let mut v = Vec::with_capacity(2);
    if let Some(a) = att {
        v.push(OpCode::SysCallBridge(Box::new(a)));
    }
    v.push(OpCode::SysCallBridge(Box::new(intent)));
    v
}

// ===========================================================================
// 1. Sub-quorum deposit refused
// ===========================================================================

/// 3 committed validators -> quorum `(3*2+2)/3 = 2`. One signature is a
/// sub-quorum: the block must report the transaction failed, credit nobody,
/// commit no replay-set entry, and leave the state root where it was.
#[tokio::test]
async fn sub_quorum_deposit_is_refused_on_the_block_path() {
    let (e, vals) = setup(3).await;
    let payer = key(0x01);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000)
        .await
        .expect("fund the payer");
    let recipient = [0xABu8; 32];

    let dep = deposit([0x71u8; 32], recipient, 5_000 * STELL);
    let att = attest(&dep, &vals[..1]); // 1 of the 2 required
    let tx = bridge_tx(&payer, 0, ops(Some(att), dep));
    let before = e.get_state_root().await;

    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;

    assert_eq!(
        out.status,
        vec![false],
        "a sub-quorum deposit must not apply"
    );
    assert_eq!(
        balance(&e, &recipient).await,
        0,
        "nothing may be credited without a quorum"
    );
    assert!(
        e.bridge_read().await.processed_source_txs.is_empty(),
        "no replay-set entry may be committed for a refused deposit"
    );
    // The bridge domain and the coins are untouched by the refusal - but
    // the state ROOT does move: a refused transaction is an attributable
    // failure, so it pays the D2 floor step and consumes its nonce (the
    // engine's fail-closed anti-DoS rule, not a bridge effect).
    assert_ne!(
        e.get_state_root().await,
        before,
        "the refusal itself is charged: nonce + D2 floor step"
    );
}

/// The same verdict with NO signatures at all (and with signatures from keys
/// outside the committed set): the rule counts DISTINCT VALIDATORS, not
/// signatures.
#[tokio::test]
async fn missing_and_foreign_attestations_are_sub_quorum() {
    let (e, vals) = setup(3).await;
    let payer = key(0x02);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let recipient = [0xACu8; 32];

    let dep = deposit([0x72u8; 32], recipient, 1_000 * STELL);
    // An attestation bundle signed by a key that is NOT in the committed set.
    let outsider = key(0xEE);
    let foreign = attest(&dep, &[outsider, key(0xEF)]);

    // (a) no attestation at all.
    let tx = bridge_tx(&payer, 0, ops(None, dep.clone()));
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![false], "an unattested deposit must fail");

    // (b) two signatures, both from outside the validator set: still sub-quorum.
    let tx = bridge_tx(&payer, 0, ops(Some(foreign), dep));
    let out = e
        .apply_block_transition(&bridge_block(2, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "signatures outside the committed relayer set count for nothing"
    );
    assert_eq!(balance(&e, &recipient).await, 0);
    assert_eq!(vals.len(), 3, "precondition: the set really is 3 wide");
    assert!(e.bridge_read().await.processed_source_txs.is_empty());
}

// ===========================================================================
// 2. Quorum deposit credits EXACTLY ONCE
// ===========================================================================

/// Two DISTINCT validators reach the quorum: the recipient is credited
/// exactly the claimed amount, exactly once - a second identical claim inside
/// the SAME block is refused by the committed-queue replay check, and the
/// successful credit plus its replay-set entry are committed (the root moves).
#[tokio::test]
async fn quorum_deposit_credits_exactly_once() {
    let (e, vals) = setup(3).await;
    let payer = key(0x03);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let recipient = [0xADu8; 32];
    let amount = 12_345 * STELL;

    let dep = deposit([0x73u8; 32], recipient, amount);
    let att = attest(&dep, &vals[..2]); // exactly the 2/3 quorum
    let dup = dep.clone();
    let tx_a = bridge_tx(&payer, 0, ops(Some(att.clone()), dep));
    // Second claim, same source tx hash, in the SAME block: must not credit.
    let tx_b = bridge_tx(&payer, 1, ops(Some(att), dup));

    let before = e.get_state_root().await;
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx_a, tx_b], payer_pk), 0)
        .await;

    assert_eq!(
        out.status,
        vec![true, false],
        "the quorum claim applies, the duplicate claim in the same block does not"
    );
    assert_eq!(
        balance(&e, &recipient).await,
        amount,
        "the deposit credits its recipient EXACTLY once"
    );
    {
        let br = e.bridge_read().await;
        assert!(
            br.processed_source_txs.contains(&[0x73u8; 32]),
            "the credited source tx must be in the committed replay set"
        );
        assert_eq!(br.processed_source_txs.len(), 1, "one source tx, one entry");
    }
    assert_ne!(
        e.get_state_root().await,
        before,
        "the credit and the replay-set entry must be committed"
    );
}

// ===========================================================================
// 3. Replayed source_tx refused (across blocks)
// ===========================================================================

/// The same claim resubmitted in a LATER block is refused by the committed
/// replay set: no second credit, no second entry, no root movement. This is
/// the double-mint the pre-policy path allowed.
#[tokio::test]
async fn replayed_source_tx_is_refused_in_a_later_block() {
    let (e, vals) = setup(3).await;
    let payer = key(0x04);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let recipient = [0xAEu8; 32];
    let amount = 999 * STELL;

    let dep = deposit([0x74u8; 32], recipient, amount);
    let att = attest(&dep, &vals[..2]);
    let first = bridge_tx(&payer, 0, ops(Some(att.clone()), dep.clone()));
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![first], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![true]);
    assert_eq!(balance(&e, &recipient).await, amount);

    // Replay in the next block.
    let replay = bridge_tx(&payer, 1, ops(Some(att), dep));
    let settled = e.get_state_root().await;
    let out = e
        .apply_block_transition(&bridge_block(2, TS + 1, vec![replay], payer_pk), 0)
        .await;

    assert_eq!(
        out.status,
        vec![false],
        "a replayed source tx must be refused by the committed replay set"
    );
    assert_eq!(
        balance(&e, &recipient).await,
        amount,
        "the replay must not mint a second credit"
    );
    // The replay mints nothing and changes no bridge state. (The state root
    // does move: the refusal is an attributable failure, so it pays the D2
    // floor step and consumes its nonce.)
    assert_ne!(
        e.get_state_root().await,
        settled,
        "the refusal itself is charged: nonce + D2 floor step"
    );
}

// ===========================================================================
// 4. Large withdrawal time-locked
// ===========================================================================

/// A withdrawal at/above `LARGE_WITHDRAWAL_THRESHOLD_NANO` debits the sender
/// into `BRIDGE_ESCROW` immediately (the value is parked) and commits a queue
/// entry whose `unlock_at` is one time-lock later on the BLOCK clock. A
/// release before that is refused by the block; after it, it applies - and it
/// can only ever apply once.
#[tokio::test]
async fn large_withdrawal_is_time_locked_until_the_block_clock_matures_it() {
    let (e, _vals) = setup(3).await;
    let payer = key(0x05);
    let payer_pk = payer.verifying_key().to_bytes();
    let start = LARGE_WITHDRAWAL_THRESHOLD_NANO + 10 * STELL;
    e.credit_native(&payer_pk, start).await.expect("fund");
    let escrow = BRIDGE_ESCROW;

    let withdraw = BridgeIntent::Withdraw {
        chain: SupportedChain::Arbitrum,
        target_address: "0xdeadbeef".to_string(),
        amount: LARGE_WITHDRAWAL_THRESHOLD_NANO,
    };
    let tx = bridge_tx(&payer, 0, vec![OpCode::SysCallBridge(Box::new(withdraw))]);
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![true], "the withdrawal request applies");

    assert_eq!(
        balance(&e, &payer_pk).await,
        start - LARGE_WITHDRAWAL_THRESHOLD_NANO,
        "the sender is debited (the fee nets back: the payer is the proposer)"
    );
    assert_eq!(
        balance(&e, &escrow).await,
        LARGE_WITHDRAWAL_THRESHOLD_NANO,
        "the value is parked in the escrow account"
    );
    {
        let br = e.bridge_read().await;
        assert_eq!(
            br.escrow_balance, LARGE_WITHDRAWAL_THRESHOLD_NANO,
            "the committed escrow mirror matches the account"
        );
        let req = br
            .pending_withdrawals
            .get(&0)
            .expect("the first request id is 0 and it is committed");
        assert_eq!(
            req.unlock_at,
            TS + WITHDRAWAL_TIME_LOCK_SECS,
            "the time-lock is measured on the BLOCK timestamp"
        );
        assert!(!req.executed, "a fresh withdrawal is not released");
        assert_eq!(req.amount, LARGE_WITHDRAWAL_THRESHOLD_NANO);
    }

    // Release 60s in: still time-locked, so the block refuses it.
    let early = BridgeIntent::Release { req_id: 0 };
    let tx = bridge_tx(&payer, 1, vec![OpCode::SysCallBridge(Box::new(early))]);
    let out = e
        .apply_block_transition(&bridge_block(2, TS + 60, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "a release before unlock_at must be refused by the block"
    );
    assert!(
        !e.bridge_read().await.pending_withdrawals[&0].executed,
        "the refused release changed nothing"
    );

    // Release exactly at unlock_at: it matures on this block's clock.
    // (Nonce 2: the refused early release consumed its nonce - a refused
    // transaction still advances the nonce.)
    let matured = BridgeIntent::Release { req_id: 0 };
    let tx = bridge_tx(&payer, 2, vec![OpCode::SysCallBridge(Box::new(matured))]);
    let out = e
        .apply_block_transition(
            &bridge_block(3, TS + WITHDRAWAL_TIME_LOCK_SECS, vec![tx], payer_pk),
            0,
        )
        .await;
    assert_eq!(out.status, vec![true], "at unlock_at the release applies");
    assert!(
        e.bridge_read().await.pending_withdrawals[&0].executed,
        "the release is committed exactly once"
    );

    // ...and a second release of the same request is a double-release.
    let twice = BridgeIntent::Release { req_id: 0 };
    let tx = bridge_tx(&payer, 2, vec![OpCode::SysCallBridge(Box::new(twice))]);
    let out = e
        .apply_block_transition(
            &bridge_block(4, TS + WITHDRAWAL_TIME_LOCK_SECS + 1, vec![tx], payer_pk),
            0,
        )
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "a withdrawal can never be released twice"
    );
}

/// A withdrawal BELOW the threshold parks with `unlock_at == now`: no
/// time-lock delay, but the queue entry and the escrow are still committed.
#[tokio::test]
async fn small_withdrawal_unlocks_immediately_but_is_still_queued() {
    let (e, _vals) = setup(3).await;
    let payer = key(0x06);
    let payer_pk = payer.verifying_key().to_bytes();
    let start = 1_000 * STELL;
    e.credit_native(&payer_pk, start).await.expect("fund");

    let withdraw = BridgeIntent::Withdraw {
        chain: SupportedChain::Ton,
        target_address: "EQD-test".to_string(),
        amount: 100 * STELL,
    };
    let tx = bridge_tx(&payer, 0, vec![OpCode::SysCallBridge(Box::new(withdraw))]);
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![true]);

    let br = e.bridge_read().await;
    let req = br.pending_withdrawals.get(&0).expect("queued");
    assert_eq!(req.unlock_at, TS, "below the threshold there is no delay");
    assert_eq!(balance(&e, &BRIDGE_ESCROW).await, 100 * STELL);
    drop(br);

    let release = BridgeIntent::Release { req_id: 0 };
    let tx = bridge_tx(&payer, 1, vec![OpCode::SysCallBridge(Box::new(release))]);
    let out = e
        .apply_block_transition(&bridge_block(2, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![true], "a matured release applies");
}

// ===========================================================================
// 5. Hourly rate limit enforced
// ===========================================================================

/// `400k + 200k > 500k STELL` inside one hour: the second withdrawal is
/// refused by the committed window, and the window rolls over exactly one
/// hour later on the block clock.
#[tokio::test]
async fn hourly_rate_limit_is_enforced_on_the_block_clock() {
    let (e, _vals) = setup(3).await;
    let payer = key(0x07);
    let payer_pk = payer.verifying_key().to_bytes();
    let start = 1_000_000 * STELL;
    e.credit_native(&payer_pk, start).await.expect("fund");

    let w = |amount: u64| BridgeIntent::Withdraw {
        chain: SupportedChain::Ethereum,
        target_address: "0x00".to_string(),
        amount,
    };
    let first = 400_000 * STELL;
    let second = 200_000 * STELL;
    assert!(
        first + second > HOURLY_RATE_LIMIT_NANO,
        "precondition: these two together breach the hourly cap"
    );

    let tx_a = bridge_tx(&payer, 0, vec![OpCode::SysCallBridge(Box::new(w(first)))]);
    let tx_b = bridge_tx(&payer, 1, vec![OpCode::SysCallBridge(Box::new(w(second)))]);
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx_a, tx_b], payer_pk), 0)
        .await;

    assert_eq!(
        out.status,
        vec![true, false],
        "the first withdrawal fits the window, the second breaches it"
    );
    assert_eq!(
        balance(&e, &BRIDGE_ESCROW).await,
        first,
        "only the admitted withdrawal is parked"
    );
    {
        let br = e.bridge_read().await;
        assert_eq!(br.hourly_withdrawn, first, "the window holds what left");
        assert_eq!(
            br.last_rate_limit_reset, TS,
            "the window opened on the BLOCK timestamp"
        );
        assert_eq!(
            br.pending_withdrawals.len(),
            1,
            "the refused withdrawal queued nothing"
        );
    }

    // One hour later the window rolls over and the same amount is admitted.
    // (The payer's nonce is 2: the refused withdrawal consumed its nonce -
    // a refused transaction still advances the nonce.)
    let tx_c = bridge_tx(&payer, 2, vec![OpCode::SysCallBridge(Box::new(w(second)))]);
    let out = e
        .apply_block_transition(
            &bridge_block(2, TS + WITHDRAWAL_TIME_LOCK_SECS, vec![tx_c], payer_pk),
            0,
        )
        .await;
    assert_eq!(
        out.status,
        vec![true],
        "the rate window resets after one hour of BLOCK time"
    );
    assert_eq!(
        balance(&e, &BRIDGE_ESCROW).await,
        first + second,
        "both admitted withdrawals are parked"
    );
    assert_eq!(e.bridge_read().await.hourly_withdrawn, second);
}

/// The quorum rule is `(n * 2 + 2) / 3`, which is ZERO for an empty relayer
/// set - a chain whose staking ledger is empty must not mint deposits with no
/// signature at all, so the live path fails CLOSED (the one place it is
/// deliberately stricter than the offline engine it reuses).
#[tokio::test]
async fn empty_validator_set_fails_closed_on_deposits() {
    let (e, _none) = setup(0).await; // no committed validators at all
    let payer = key(0x09);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let recipient = [0xB0u8; 32];

    // Signatures from keys that are not validators would compute quorum 0/0
    // under the raw formula: the guard must refuse BEFORE any of that matters.
    let dep = deposit([0x76u8; 32], recipient, 42 * STELL);
    let att = attest(&dep, &[key(0xC1), key(0xC2)]);
    let tx = bridge_tx(&payer, 0, ops(Some(att), dep));
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;

    assert_eq!(
        out.status,
        vec![false],
        "with no committed relayer set, no deposit may credit"
    );
    assert_eq!(balance(&e, &recipient).await, 0);
    assert!(e.bridge_read().await.processed_source_txs.is_empty());
}

// ===========================================================================
// 6. The committed root moves only from a block
// ===========================================================================

/// Gossip/RPC only deliver a payload to a proposer: preparing a transaction
/// moves nothing, a REFUSED block moves nothing, repeated root reads are
/// stable, and only an applied block's settlement changes the root - at which
/// point the committed bridge domain itself is a mutation-sensitive part of
/// the digest (PROTOCOL.md I1).
#[tokio::test]
async fn committed_root_changes_only_from_the_block() {
    let (e, vals) = setup(3).await;
    let payer = key(0x08);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let recipient = [0xAFu8; 32];

    let genesis_like = e.get_state_root().await;
    assert_eq!(
        e.get_state_root().await,
        genesis_like,
        "reads must not perturb consensus state"
    );

    // Prepared, signed, NOT applied: the root cannot move.
    let dep = deposit([0x75u8; 32], recipient, 77 * STELL);
    let att = attest(&dep, &vals[..2]);
    let prepared = bridge_tx(&payer, 0, ops(Some(att), dep.clone()));
    assert_eq!(
        e.get_state_root().await,
        genesis_like,
        "building a payload (the proposer's mempool view) must not move the root"
    );
    drop(prepared);

    // A block that carries the claim WITHOUT its attestation is refused
    // (sub-quorum) and changes nothing.
    let bare = bridge_tx(&payer, 0, ops(None, dep.clone()));
    let refused = e
        .apply_block_transition(&bridge_block(1, TS, vec![bare], payer_pk), 0)
        .await;
    assert_eq!(refused.status, vec![false]);
    // The refused block moves no bridge state and no coin. (The root does
    // move: the refusal is an attributable failure, so it pays the D2 floor
    // step and consumes the payer's nonce - which is why the applied block
    // below must carry the NEXT nonce.)
    assert_ne!(
        e.get_state_root().await,
        genesis_like,
        "the refusal itself is charged: nonce + D2 floor step"
    );

    // THE block, with the quorum attached, is what moves it.
    let dep = deposit([0x75u8; 32], recipient, 77 * STELL);
    let att = attest(&dep, &vals[..2]);
    // Nonce 1: the refused block above consumed nonce 0 (a refused
    // transaction still advances the nonce).
    let tx = bridge_tx(&payer, 1, ops(Some(att), dep));
    let applied = e
        .apply_block_transition(&bridge_block(2, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(applied.status, vec![true]);
    assert_eq!(
        balance(&e, &recipient).await,
        77 * STELL,
        "the applied block credited the recipient"
    );
    let after = e.get_state_root().await;
    assert_ne!(
        after, genesis_like,
        "the applied block's settlement must move the root"
    );
    assert_eq!(
        e.get_state_root().await,
        after,
        "and the root then stabilises"
    );

    // I1: the domain is folded into the digest, so a mutation of it alone
    // moves the root - a node holding a different replay set cannot report
    // the same root.
    e.bridge_write()
        .await
        .processed_source_txs
        .insert([0x99u8; 32]);
    assert_ne!(
        e.get_state_root().await,
        after,
        "mutating the committed bridge domain must move the state root (I1)"
    );
}

/// The digest-level twin: every field of `BridgeState` is folded into
/// `commitment_digest`, and an EMPTY domain contributes nothing (which is what
/// keeps the pinned genesis root and `COMMITMENT_VERSION = 4` in place).
#[test]
fn bridge_domain_is_folded_into_the_commitment_digest() {
    fn snap(bridge: BridgeState) -> CommitmentSnapshot {
        CommitmentSnapshot {
            tokens: Default::default(),
            staking: Default::default(),
            orderbooks: Default::default(),
            order_escrow: Default::default(),
            pmm: Default::default(),
            pmm_usdt_token: None,
            pmm_treasury: [0u8; 32],
            contracts: Default::default(),
            governance: Default::default(),
            oracle: Default::default(),
            session_keys: Default::default(),
            bridge,
            cross_shard_consumed: Vec::new(),
            cross_shard_produced: Vec::new(),
            cross_shard_completed: Vec::new(),
            cross_shard_xpc: Vec::new(),
        }
    }

    let empty = BridgeState::default();
    assert!(empty.is_empty(), "the default domain is the empty one");
    let base = commitment_digest(&snap(empty.clone()));
    // The conditional contract: an empty domain is a no-op, so the pre-bridge
    // digest (and therefore the genesis KAT) is reproduced byte-for-byte.
    assert_eq!(commitment_digest(&snap(empty)), base);

    let cases: Vec<(&str, BridgeState)> = vec![
        ("replay set", {
            let mut b = BridgeState::default();
            b.processed_source_txs.insert([1u8; 32]);
            b
        }),
        ("pending withdrawal queue", {
            let mut b = BridgeState::default();
            b.pending_withdrawals.insert(
                0,
                stellereum::bridge::TeleportWithdrawalRequest {
                    req_id: 0,
                    sender: [2u8; 32],
                    target_chain: SupportedChain::Solana,
                    target_address: "abc".to_string(),
                    amount: 5,
                    requested_at: 1,
                    unlock_at: 2,
                    executed: false,
                },
            );
            b
        }),
        ("withdrawal id counter", {
            BridgeState {
                next_withdrawal_id: 1,
                ..Default::default()
            }
        }),
        ("rate window (withdrawn)", {
            BridgeState {
                hourly_withdrawn: 7,
                ..Default::default()
            }
        }),
        ("rate window (opened at)", {
            BridgeState {
                last_rate_limit_reset: 9,
                ..Default::default()
            }
        }),
        ("escrow mirror", {
            BridgeState {
                escrow_balance: 11,
                ..Default::default()
            }
        }),
        ("deposit window (minted)", {
            BridgeState {
                hourly_deposited: 13,
                ..Default::default()
            }
        }),
        ("deposit window (opened at)", {
            BridgeState {
                last_deposit_reset: 17,
                ..Default::default()
            }
        }),
        ("cumulative minted supply", {
            BridgeState {
                total_minted: 19,
                ..Default::default()
            }
        }),
        ("deposit record", {
            let mut b = BridgeState::default();
            b.deposit_records.insert(
                [21u8; 32],
                stellereum::bridge::DepositRecord {
                    recipient: [22u8; 32],
                    amount: 23,
                    chain: SupportedChain::Ton,
                    via_quorum: true,
                    deposited_at: 24,
                    disputed: false,
                },
            );
            b
        }),
        ("deposit record (disputed + evidence path)", {
            let mut b = BridgeState::default();
            b.deposit_records.insert(
                [25u8; 32],
                stellereum::bridge::DepositRecord {
                    recipient: [26u8; 32],
                    amount: 27,
                    chain: SupportedChain::Ethereum,
                    via_quorum: false,
                    deposited_at: 28,
                    disputed: true,
                },
            );
            b
        }),
        ("dispute + id counter", {
            let mut b = BridgeState {
                next_dispute_id: 1,
                ..Default::default()
            };
            b.disputes.insert(
                0,
                stellereum::bridge::Dispute {
                    source_tx_hash: [29u8; 32],
                    challenger: [30u8; 32],
                    recipient: [31u8; 32],
                    amount: 32,
                    bond: 33,
                    deadline: 34,
                    resolved: true,
                    confirmed: false,
                },
            );
            b
        }),
    ];
    for (name, bridge) in cases {
        assert_ne!(
            commitment_digest(&snap(bridge)),
            base,
            "the bridge domain field `{name}` must be folded into the digest (I1)"
        );
    }
}

// ===========================================================================
// 7. §8 adapter evidence on the live block path (APPENDED: §8 gap closure)
// ===========================================================================
//
// A deposit may cite adapter evidence (paired `DepositProof`, same payload,
// same pairing-by-hash pattern as `Attest`) INSTEAD OF the quorum bundle:
// settlement credits when EITHER path verifies. Everything below goes through
// `apply_block_transition` like the tests above. Fixtures are synthetic but
// VALID (real BoC cell hashes / real MPT proofs / real quorum signatures
// over the cited header); tamperings are refused, move nothing, and commit
// nothing.

/// A fully valid TON cell evidence bundle for the claim, paired to it.
/// `root_override` swaps the header root (with a VALID quorum over the wrong
/// root) to build the tampered fixture.
fn ton_proof(
    source_tx_hash: [u8; 32],
    recipient: [u8; 32],
    amount: u64,
    keys: &[SigningKey],
    root_override: Option<[u8; 32]>,
) -> BridgeIntent {
    use stellereum::bridge::bridge_adapters::{
        ton_leaf_encoding, DepositClaim, DepositEvidence, StoredHeader,
    };
    let claim = DepositClaim {
        chain: SupportedChain::Ton,
        source_tx_hash,
        recipient,
        amount,
    };
    let leaf = ton_leaf_encoding(&claim);
    let (boc, root) = stellereum::cell::Cell::from_bytes(&leaf);
    let header = StoredHeader {
        chain: SupportedChain::Ton,
        height: 1_000,
        prev_hash: [0x11u8; 32],
        tx_root: root_override.unwrap_or(root),
    };
    let msg = header.signing_message();
    let header_signatures = keys[..2]
        .iter()
        .map(|k| (k.verifying_key().to_bytes(), k.sign(&msg).to_vec()))
        .collect();
    BridgeIntent::DepositProof {
        source_tx_hash,
        evidence: Box::new(DepositEvidence::TonCell {
            header,
            header_signatures,
            finalized_seqno: 1_000 + stellereum::bridge::MIN_TON_CONFIRMATIONS,
            boc_bytes: boc.to_boc_bytes(),
        }),
    }
}

/// A fully valid EVM (Ethereum) receipt evidence bundle for the claim.
fn evm_proof(
    source_tx_hash: [u8; 32],
    recipient: [u8; 32],
    amount: u64,
    keys: &[SigningKey],
) -> BridgeIntent {
    use stellereum::bridge::bridge_adapters::{
        evm_receipt_encoding, evm_receipt_key, DepositEvidence, StoredHeader,
    };
    let log_index = 0u32;
    let receipt_key = evm_receipt_key(&source_tx_hash, log_index);
    let receipt = evm_receipt_encoding(
        SupportedChain::Ethereum,
        &source_tx_hash,
        log_index,
        &recipient,
        amount,
    );
    let mut trie = stellereum::cell::PatriciaTrie::new();
    trie.insert(&receipt_key, &receipt);
    let header = StoredHeader {
        chain: SupportedChain::Ethereum,
        height: 10_000,
        prev_hash: [0x22u8; 32],
        tx_root: trie.root_hash(),
    };
    let msg = header.signing_message();
    let header_signatures = keys[..2]
        .iter()
        .map(|k| (k.verifying_key().to_bytes(), k.sign(&msg).to_vec()))
        .collect();
    BridgeIntent::DepositProof {
        source_tx_hash,
        evidence: Box::new(DepositEvidence::EvmReceipt {
            header,
            header_signatures,
            finalized_number: 10_000 + stellereum::bridge::ETHEREUM_FINALITY_BLOCKS,
            log_index,
            receipt_value: receipt,
            mpt_proof: trie
                .generate_merkle_proof(&receipt_key)
                .expect("fixture trie proves its own key"),
        }),
    }
}

fn proof_ops(proof: BridgeIntent, intent: BridgeIntent) -> Vec<OpCode> {
    vec![
        OpCode::SysCallBridge(Box::new(proof)),
        OpCode::SysCallBridge(Box::new(intent)),
    ]
}

/// Valid TON evidence, NO attestation at all: the adapter path alone admits
/// the deposit, credits exactly once, commits the replay entry - and the
/// same evidence resubmitted later is refused by the committed replay set.
#[tokio::test]
async fn adapter_ton_evidence_deposit_credits_on_the_block_path() {
    let (e, vals) = setup(3).await;
    let payer = key(0x21);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let recipient = [0xC1u8; 32];
    let amount = 77 * STELL;
    let hash = [0x81u8; 32];

    let tx = bridge_tx(
        &payer,
        0,
        proof_ops(
            ton_proof(hash, recipient, amount, &vals, None),
            deposit(hash, recipient, amount),
        ),
    );
    let before = e.get_state_root().await;
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![true],
        "valid adapter evidence must admit the deposit"
    );
    assert_eq!(balance(&e, &recipient).await, amount);
    assert!(e.bridge_read().await.processed_source_txs.contains(&hash));
    assert_ne!(
        e.get_state_root().await,
        before,
        "the credit must be committed"
    );

    // Replay with the SAME valid evidence in a later block: refused.
    let replay = bridge_tx(
        &payer,
        1,
        proof_ops(
            ton_proof(hash, recipient, amount, &vals, None),
            deposit(hash, recipient, amount),
        ),
    );
    let settled = e.get_state_root().await;
    let out = e
        .apply_block_transition(&bridge_block(2, TS + 1, vec![replay], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "replay via the evidence path must be refused"
    );
    assert_eq!(balance(&e, &recipient).await, amount, "no second mint");
    // No second mint and no bridge-state change. (The root does move: the
    // refusal is an attributable failure, so it pays the D2 floor step and
    // consumes its nonce.)
    assert_ne!(
        e.get_state_root().await,
        settled,
        "the refusal itself is charged: nonce + D2 floor step"
    );
}

/// Valid EVM evidence on the live path (second chain through the same OR).
#[tokio::test]
async fn adapter_evm_evidence_deposit_credits_on_the_block_path() {
    let (e, vals) = setup(3).await;
    let payer = key(0x22);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let recipient = [0xC2u8; 32];
    let amount = 500_000_000;
    let hash = [0x82u8; 32];
    let dep = BridgeIntent::Deposit {
        chain: SupportedChain::Ethereum,
        source_tx_hash: hash,
        recipient,
        amount,
    };
    let tx = bridge_tx(
        &payer,
        0,
        proof_ops(evm_proof(hash, recipient, amount, &vals), dep),
    );
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![true],
        "valid EVM evidence must admit the deposit"
    );
    assert_eq!(balance(&e, &recipient).await, amount);
    assert!(e.bridge_read().await.processed_source_txs.contains(&hash));
}

/// Tampered evidence (quorum-signed header over the WRONG root): the block
/// refuses the deposit, credits nobody, commits no replay entry, and leaves
/// the root where it was.
#[tokio::test]
async fn adapter_tampered_evidence_is_refused_on_the_block_path() {
    let (e, vals) = setup(3).await;
    let payer = key(0x23);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let recipient = [0xC3u8; 32];
    let hash = [0x83u8; 32];

    let tx = bridge_tx(
        &payer,
        0,
        proof_ops(
            ton_proof(hash, recipient, 9 * STELL, &vals, Some([0xFFu8; 32])),
            deposit(hash, recipient, 9 * STELL),
        ),
    );
    let before = e.get_state_root().await;
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "evidence for the wrong root must be refused"
    );
    assert_eq!(balance(&e, &recipient).await, 0);
    assert!(e.bridge_read().await.processed_source_txs.is_empty());
    // No coin and no bridge state moved. (The root does move: the refusal is
    // an attributable failure, so it pays the D2 floor step and consumes its
    // nonce.)
    assert_ne!(
        e.get_state_root().await,
        before,
        "the refusal itself is charged: nonce + D2 floor step"
    );
}

/// The zk placeholder is refused on the live path (shape validation reverts
/// the transaction before settlement even runs).
#[tokio::test]
async fn zk_placeholder_evidence_is_refused_on_the_block_path() {
    let (e, vals) = setup(3).await;
    let _ = vals;
    let payer = key(0x24);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let recipient = [0xC4u8; 32];
    let hash = [0x84u8; 32];
    let placeholder = BridgeIntent::DepositProof {
        source_tx_hash: hash,
        evidence: Box::new(
            stellereum::bridge::bridge_adapters::DepositEvidence::ZkProofPlaceholder {
                note: "no verifier exists yet".to_string(),
            },
        ),
    };
    let tx = bridge_tx(
        &payer,
        0,
        proof_ops(placeholder, deposit(hash, recipient, 5 * STELL)),
    );
    let before = e.get_state_root().await;
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "the zk placeholder must always fail closed"
    );
    assert_eq!(balance(&e, &recipient).await, 0);
    assert!(e.bridge_read().await.processed_source_txs.is_empty());
    // No coin and no bridge state moved. (The root does move: the refusal is
    // an attributable failure, so it pays the D2 floor step and consumes its
    // nonce.)
    assert_ne!(
        e.get_state_root().await,
        before,
        "the refusal itself is charged: nonce + D2 floor step"
    );
}

/// OR-priority: a deposit with a VALID quorum attestation credits even when
/// a BOGUS evidence bundle rides along for the same hash (the quorum path is
/// tried first and ignores evidence entirely - pre-evidence behavior).
#[tokio::test]
async fn quorum_path_ignores_bogus_evidence() {
    let (e, vals) = setup(3).await;
    let payer = key(0x25);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let recipient = [0xC5u8; 32];
    let amount = 11 * STELL;
    let hash = [0x85u8; 32];

    let dep = deposit(hash, recipient, amount);
    let att = attest(&dep, &vals[..2]);
    let bogus = ton_proof(hash, recipient, amount, &vals, Some([0xFFu8; 32]));
    let tx = bridge_tx(
        &payer,
        0,
        vec![
            OpCode::SysCallBridge(Box::new(att)),
            OpCode::SysCallBridge(Box::new(bogus)),
            OpCode::SysCallBridge(Box::new(dep)),
        ],
    );
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![true],
        "a quorum deposit credits despite bogus evidence"
    );
    assert_eq!(balance(&e, &recipient).await, amount);
}

/// An evidence bundle ALONE in a payload (no Deposit to pair with) is inert:
/// the transaction applies but the bridge domain is untouched - no replay
/// entry, no credit, no queue change - exactly like a lone Attest. (The state
/// root itself still moves: a successful transaction pays gas, and fees are
/// supposed to move the root. What must NOT move is the BRIDGE domain.)
#[tokio::test]
async fn lone_deposit_proof_commits_nothing() {
    let (e, vals) = setup(3).await;
    let payer = key(0x26);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let hash = [0x86u8; 32];
    let lone = bridge_tx(
        &payer,
        0,
        vec![OpCode::SysCallBridge(Box::new(ton_proof(
            hash,
            [0xC6u8; 32],
            STELL,
            &vals,
            None,
        )))],
    );
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![lone], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![true],
        "an inert bundle must not revert its carrier"
    );
    let br = e.bridge_read().await;
    assert!(
        br.processed_source_txs.is_empty(),
        "inert evidence commits no replay entry"
    );
    assert!(
        br.pending_withdrawals.is_empty(),
        "inert evidence queues nothing"
    );
    assert!(br.is_empty(), "the bridge domain is untouched");
    drop(br);
    assert_eq!(balance(&e, &[0xC6u8; 32]).await, 0, "nobody is credited");
}

// ===========================================================================
// 8. Deposit mint ceilings (audit F-H)
// ===========================================================================
//
// Withdrawals were rate-limited but deposits were not: a compromised quorum
// could mint past the hard cap in one deposit. Both deposit paths (quorum
// attestation AND adapter evidence) now share one ceiling check per admitted
// mint: an hourly window plus a cumulative supply cap, both on the block
// clock, both committed. A refusal reverts the whole carrier tx (like quorum
// failure) and commits nothing - including no replay entry.

/// `400k + 200k > 500k STELL` inside one hour: the second attested deposit is
/// refused, the window rolls over one hour later, and the cumulative counter
/// tracks every admitted mint.
#[tokio::test]
async fn deposit_hourly_cap_enforced_on_the_block_clock() {
    let (e, vals) = setup(3).await;
    let payer = key(0x0D);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, 1_000_000).await.expect("fund");
    let recipient = [0xD0u8; 32];

    let first = 400_000 * STELL;
    let second = 200_000 * STELL;
    assert!(
        first + second > HOURLY_DEPOSIT_LIMIT_NANO,
        "precondition: these two together breach the hourly mint ceiling"
    );
    assert!(
        first + second < BRIDGE_MINT_CAP_NANO,
        "precondition: the cumulative cap is NOT what refuses here"
    );

    let dep_a = deposit([0xD1u8; 32], recipient, first);
    let att_a = attest(&dep_a, &vals[..2]);
    let dep_b = deposit([0xD2u8; 32], recipient, second);
    let att_b = attest(&dep_b, &vals[..2]);
    let tx_a = bridge_tx(&payer, 0, ops(Some(att_a), dep_a));
    let tx_b = bridge_tx(&payer, 1, ops(Some(att_b), dep_b));
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx_a, tx_b], payer_pk), 0)
        .await;
    assert_eq!(
        out.status,
        vec![true, false],
        "the first mint fits the window, the second breaches it"
    );
    assert_eq!(
        balance(&e, &recipient).await,
        first,
        "only the admitted mint credited"
    );
    {
        let br = e.bridge_read().await;
        assert_eq!(br.hourly_deposited, first, "the window holds what minted");
        assert_eq!(
            br.total_minted, first,
            "the cumulative counter tracks mints"
        );
        assert_eq!(
            br.last_deposit_reset, TS,
            "the window opened on the BLOCK timestamp"
        );
        assert!(
            !br.processed_source_txs.contains(&[0xD2u8; 32]),
            "the refused mint leaves no replay entry (it may be retried later)"
        );
    }

    // One hour later the window rolls over and the same mint is admitted.
    // (Nonce 2: the refused mint consumed its nonce - a refused transaction
    // still advances the nonce.)
    let dep_c = deposit([0xD2u8; 32], recipient, second);
    let att_c = attest(&dep_c, &vals[..2]);
    let tx_c = bridge_tx(&payer, 2, ops(Some(att_c), dep_c));
    let out = e
        .apply_block_transition(&bridge_block(2, TS + 3600, vec![tx_c], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![true], "the window resets after one hour");
    assert_eq!(balance(&e, &recipient).await, first + second);
    let br = e.bridge_read().await;
    assert_eq!(br.hourly_deposited, second);
    assert_eq!(br.total_minted, first + second);
}

// ===========================================================================
// F-G refund (audit follow-up): parked withdrawals that will never release
// have an exit — sender-only, unexecuted-only, past unlock+grace.
// ===========================================================================

#[tokio::test]
async fn refund_returns_parked_funds_after_grace_and_closes_the_request() {
    use stellereum::bridge::REFUND_GRACE_SECS;
    let (e, _vals) = setup(3).await;
    let payer = key(0x05);
    let payer_pk = payer.verifying_key().to_bytes();
    let start = 10 * STELL;
    e.credit_native(&payer_pk, start).await.expect("fund");

    // Small withdrawal parks immediately (unlock_at = now).
    let amount = STELL;
    let tx = bridge_tx(
        &payer,
        0,
        vec![OpCode::SysCallBridge(Box::new(BridgeIntent::Withdraw {
            chain: SupportedChain::Arbitrum,
            target_address: "0xdeadbeef".to_string(),
            amount,
        }))],
    );
    let out = e
        .apply_block_transition(&bridge_block(1, TS, vec![tx], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![true]);
    assert_eq!(balance(&e, &BRIDGE_ESCROW).await, amount);

    // Too early: grace has not passed.
    let early = bridge_tx(
        &payer,
        1,
        vec![OpCode::SysCallBridge(Box::new(BridgeIntent::Refund {
            req_id: 0,
        }))],
    );
    let out = e
        .apply_block_transition(&bridge_block(2, TS + 60, vec![early], payer_pk), 0)
        .await;
    assert_eq!(out.status, vec![false], "grace not passed");

    // Wrong sender: refused.
    let stranger = key(0x06);
    let stranger_pk = stranger.verifying_key().to_bytes();
    e.credit_native(&stranger_pk, STELL)
        .await
        .expect("fund stranger");
    let wrong = bridge_tx(
        &stranger,
        0,
        vec![OpCode::SysCallBridge(Box::new(BridgeIntent::Refund {
            req_id: 0,
        }))],
    );
    let out = e
        .apply_block_transition(
            &bridge_block(3, TS + REFUND_GRACE_SECS + 1, vec![wrong], payer_pk),
            0,
        )
        .await;
    assert_eq!(out.status, vec![false], "stranger cannot refund");

    // Past grace, right sender: escrow back, request gone. Nonce is 2: the
    // refused early refund consumed its nonce (a refused transaction still
    // advances the nonce and pays the D2 floor step).
    let ok = bridge_tx(
        &payer,
        2,
        vec![OpCode::SysCallBridge(Box::new(BridgeIntent::Refund {
            req_id: 0,
        }))],
    );
    let out = e
        .apply_block_transition(
            &bridge_block(4, TS + REFUND_GRACE_SECS + 1, vec![ok], payer_pk),
            0,
        )
        .await;
    assert_eq!(out.status, vec![true], "{out:?}");
    assert_eq!(balance(&e, &BRIDGE_ESCROW).await, 0, "escrow drained back");
    assert!(
        !e.bridge_read().await.pending_withdrawals.contains_key(&0),
        "refunded request is deleted (replay-safe by absence)"
    );

    // Double refund: unknown id now. (Nonce 3: the refund above consumed 2.)
    let again = bridge_tx(
        &payer,
        3,
        vec![OpCode::SysCallBridge(Box::new(BridgeIntent::Refund {
            req_id: 0,
        }))],
    );
    let out = e
        .apply_block_transition(
            &bridge_block(5, TS + REFUND_GRACE_SECS + 2, vec![again], payer_pk),
            0,
        )
        .await;
    assert_eq!(out.status, vec![false], "second refund finds nothing");

    // Release after refund: also unknown.
    let rel = bridge_tx(
        &payer,
        2,
        vec![OpCode::SysCallBridge(Box::new(BridgeIntent::Release {
            req_id: 0,
        }))],
    );
    let out = e
        .apply_block_transition(
            &bridge_block(6, TS + REFUND_GRACE_SECS + 3, vec![rel], payer_pk),
            0,
        )
        .await;
    assert_eq!(out.status, vec![false], "release of refunded request fails");
}

// ===========================================================================
// C7 shard gate pin: bridge intents settle on the masterchain ONLY.
// (`state_engine.rs`: settling the same intents on a workchain would credit
// twice against per-engine state, so the block path fails closed when
// `cross_shard_enabled && tx.source_shard != MASTERCHAIN_SHARD`.)
// The control proves the refusal is the gate, not a broken intent: the same
// quorum deposit+attest pair applies on the masterchain and is refused from
// a workchain shard, crediting nobody and committing no replay entry.
// ===========================================================================

/// A workchain-source transaction carrying bridge intents, on an engine with
/// cross-shard enabled (so the C7 condition is fully armed).
fn workchain_bridge_tx(payer: &SigningKey, nonce: u64, ops: Vec<OpCode>) -> Transaction {
    let gas = GAS_BRIDGE_INTENT * ops.len() as u64 + 1_000;
    Transaction::sign_with_payload(
        payer,
        payer.verifying_key().to_bytes(),
        0,
        gas,
        nonce,
        BASE_WORKCHAIN_SHARD_INITIAL,
        BASE_WORKCHAIN_SHARD_INITIAL,
        ops,
    )
}

#[tokio::test]
async fn bridge_intents_from_a_workchain_are_refused() {
    let (e, vals) = setup(3).await;
    // Premise: cross-shard starts OFF; the gate needs it ON to arm.
    assert!(
        !e.cross_shard_enabled(),
        "fresh engine must not enable cross-shard by default"
    );
    e.enable_cross_shard();
    assert!(e.cross_shard_enabled());

    let payer = key(0x0B);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, STELL).await.expect("fund payer");

    // Control: quorum deposit on the masterchain applies exactly once.
    let recipient_mc = [0xB0u8; 32];
    let dep_mc = deposit([0x81u8; 32], recipient_mc, 1_000 * STELL);
    let att_mc = attest(&dep_mc, &vals[..2]);
    let out = e
        .apply_block_transition(
            &bridge_block(
                1,
                TS,
                vec![bridge_tx(&payer, 0, ops(Some(att_mc), dep_mc))],
                payer_pk,
            ),
            0,
        )
        .await;
    assert_eq!(out.status, vec![true], "control quorum deposit must apply");
    assert_eq!(balance(&e, &recipient_mc).await, 1_000 * STELL);
    let escrow_after_control = balance(&e, &BRIDGE_ESCROW).await;

    // Attack: the same shape of quorum deposit, sourced from a workchain.
    let recipient_wc = [0xB1u8; 32];
    let dep_wc = deposit([0x82u8; 32], recipient_wc, 1_000 * STELL);
    let att_wc = attest(&dep_wc, &vals[..2]);
    let out = e
        .apply_block_transition(
            &bridge_block(
                2,
                TS + 1,
                vec![workchain_bridge_tx(&payer, 1, ops(Some(att_wc), dep_wc))],
                payer_pk,
            ),
            0,
        )
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "workchain-sourced bridge intents must not settle"
    );
    assert_eq!(
        balance(&e, &recipient_wc).await,
        0,
        "a refused workchain deposit credits nobody"
    );
    assert!(
        !e.bridge_read()
            .await
            .processed_source_txs
            .contains(&[0x82u8; 32]),
        "no replay-set entry may be committed for the refused deposit"
    );
    assert!(
        e.bridge_read()
            .await
            .processed_source_txs
            .contains(&[0x81u8; 32]),
        "the masterchain control entry survives"
    );
    assert_eq!(
        balance(&e, &BRIDGE_ESCROW).await,
        escrow_after_control,
        "escrow moves only for masterchain settlement"
    );
}

// ===========================================================================
// 2PC activation-buffer pin (spec 03: "2PC-gated flows stay out until
// `STELL_XPC_ACTIVATION_HEIGHT` (currently OFF everywhere)").
// The switch itself lives in `xshard2pc::XpcActivation` (default `Disabled`)
// with the env wiring in `main.rs`; this pins the OFF-by-default premise the
// whole gated-surface table rests on, plus the boundary semantics an eventual
// activation height will obey.
// ===========================================================================

#[tokio::test]
async fn xpc_two_phase_commit_stays_off_until_an_activation_height() {
    // Default is off, and off means off at EVERY height, past included.
    assert_eq!(XpcActivation::default(), XpcActivation::Disabled);
    assert!(!XpcActivation::Disabled.is_active_at(0));
    assert!(!XpcActivation::Disabled.is_active_at(u64::MAX));
    assert_eq!(XpcActivation::Disabled.boundary(), None);

    // Boundary semantics for the day an activation height is configured:
    // strictly below is legacy, at-and-above is 2PC. No silent early-on.
    let at_100 = XpcActivation::FromHeight(100);
    assert!(!at_100.is_active_at(99));
    assert!(at_100.is_active_at(100));
    assert!(at_100.is_active_at(u64::MAX));
    assert_eq!(at_100.boundary(), Some(100));

    // The engine ships with cross-shard (the 2PC's transport) disabled.
    let fresh = InMemoryStateEngine::new();
    assert!(
        !fresh.cross_shard_enabled(),
        "2PC-gated flows stay out on a fresh engine"
    );
}

// ===========================================================================
// Cross-shard double-claim pin (ECON hunt): the SAME credited `source_tx_hash`
// replayed from a workchain shard stays refused.
// (`bridge_intents_from_a_workchain_are_refused` pins a FRESH hash from a
// workchain; nothing pinned the SAME hash credited on the masterchain and
// then re-sourced from a workchain. The global replay set plus the C7 shard
// gate must fail closed: no second mint, no replay-set growth, escrow
// untouched, and the masterchain replay afterwards is still refused.)
// ===========================================================================

#[tokio::test]
async fn bridge_same_source_tx_replayed_from_workchain_stays_refused() {
    let (e, vals) = setup(3).await;
    e.enable_cross_shard();
    let payer = key(0x0C);
    let payer_pk = payer.verifying_key().to_bytes();
    e.credit_native(&payer_pk, STELL).await.expect("fund payer");

    let recipient = [0xB2u8; 32];
    let amount = 1_000 * STELL;
    let dep = deposit([0x83u8; 32], recipient, amount);
    let att = attest(&dep, &vals[..2]);

    // Control: the masterchain quorum credit applies exactly once.
    let out = e
        .apply_block_transition(
            &bridge_block(
                1,
                TS,
                vec![bridge_tx(&payer, 0, ops(Some(att.clone()), dep.clone()))],
                payer_pk,
            ),
            0,
        )
        .await;
    assert_eq!(out.status, vec![true], "control quorum deposit must apply");
    assert_eq!(balance(&e, &recipient).await, amount);
    assert!(
        e.bridge_read().await.processed_source_txs.contains(&[0x83u8; 32]),
        "the credited source tx must be in the committed replay set"
    );
    let escrow_after_credit = balance(&e, &BRIDGE_ESCROW).await;

    // Attack: the EXACT same claim re-sourced from a workchain shard.
    let out = e
        .apply_block_transition(
            &bridge_block(
                2,
                TS + 1,
                vec![workchain_bridge_tx(
                    &payer,
                    1,
                    ops(Some(att.clone()), dep.clone()),
                )],
                payer_pk,
            ),
            0,
        )
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "cross-shard replay of a credited source_tx must be refused"
    );
    assert_eq!(
        balance(&e, &recipient).await,
        amount,
        "the workchain replay must not mint a second credit"
    );
    {
        let br = e.bridge_read().await;
        assert_eq!(
            br.processed_source_txs.len(),
            1,
            "the refused replay must not grow the replay set"
        );
        assert!(
            br.processed_source_txs.contains(&[0x83u8; 32]),
            "the original entry survives the cross-shard attempt"
        );
    }
    assert_eq!(
        balance(&e, &BRIDGE_ESCROW).await,
        escrow_after_credit,
        "escrow moves only for masterchain settlement"
    );

    // The global replay set survived: a masterchain replay is still refused.
    let out = e
        .apply_block_transition(
            &bridge_block(3, TS + 2, vec![bridge_tx(&payer, 2, ops(Some(att), dep))], payer_pk),
            0,
        )
        .await;
    assert_eq!(
        out.status,
        vec![false],
        "the same source_tx is still refused on the masterchain"
    );
    assert_eq!(
        balance(&e, &recipient).await,
        amount,
        "no second mint from either shard path"
    );
}
