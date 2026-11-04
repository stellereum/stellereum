//! ADVERSARIAL RE-VERIFICATION: re-exploit every closed finding class against the
//! CURRENT code, asserting each original attack now FAILS.
//!
//! Each test reconstructs the ORIGINAL attack as literally as possible (shapes
//! taken from the hunt_*.rs regressions) and asserts refusal: revert / Err /
//! None, with state untouched and the staking pool solvent.
//!
//! If ANY attack still succeeds, that is a REGRESSION OF A FIX: the test is
//! written to assert the exploit and is marked LIVE-BYPASS. Do not soften it.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::Arc;

use stellereum::consensus::{HeightConsensus, QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::orderbook::{OrderSide, OrderType};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::staking::{MIN_VALIDATOR_BOND, REWARDS_POOL, STAKING_POOL, STELL_MIN_BOND_BUFFER};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::sync::{collect_missing_blocks, validate_sync_chain};
use stellereum::token::{TokenMetadata, TokenOp};

const NANO: u64 = 1_000_000_000;

/// Bond floor every bond in this file must clear: bare-MIN bonds are refused.
fn floor() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}

fn stell(n: u64) -> u64 {
    n * NANO
}

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn bh(n: u8) -> [u8; 32] {
    [n; 32]
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}

fn svm_tx(key: &SigningKey, nonce: u64, gas: u64, payload: Vec<OpCode>) -> Transaction {
    Transaction::sign_with_payload(key, [0xEE; 32], 0, gas, nonce, 0, 1, payload)
}

async fn bal(e: &InMemoryStateEngine, a: &[u8; 32]) -> u64 {
    e.get_account(a).await.map(|x| x.balance).unwrap_or(0)
}

fn mkblock(signer: &SigningKey, h: u64, prev: [u8; 32], root: [u8; 32]) -> Block {
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: h,
        prev_hash: prev,
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_000,
        proposer: id(signer),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
    };
    b.sign_block(signer);
    b
}

fn precommit_qc(
    ks: &[SigningKey],
    idx: &[usize],
    height: u64,
    hash: [u8; 32],
) -> QuorumCertificate {
    QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures: idx
            .iter()
            .map(|&i| {
                let v = Vote::sign(&ks[i], height, 0, VoteKind::Precommit, Some(hash));
                (v.voter, v.signature)
            })
            .collect(),
    }
}

// ===========================================================================
// 1a. Stranger claims another validator's rewards (src/svm.rs SysCallClaimRewards
//     owner check). Original: payout beneficiary was ctx.sender with no owner check.
// ===========================================================================

#[tokio::test]
async fn adv_stranger_cannot_claim_anothers_rewards() {
    let e = InMemoryStateEngine::new();
    let victim = SigningKey::generate(&mut OsRng);
    let victim_addr = id(&victim);
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = id(&attacker);

    e.update_account(AccountState::new(victim_addr, stell(10_000) + 10_000))
        .await;
    e.apply_transaction(
        &svm_tx(
            &victim,
            0,
            20_000,
            vec![OpCode::SysCallStake {
                validator: victim_addr,
                amount: stell(10_000),
            }],
        ),
        0,
    )
    .await
    .expect("victim bond");
    assert_eq!(bal(&e, &STAKING_POOL).await, stell(10_000));

    e.staking_write()
        .await
        .distribute_reward(victim_addr, stell(500))
        .unwrap();
    // E2: back the accrual the way the block mint does (bare ledger entries
    // with no pool coins must not pay).
    e.credit_native(&REWARDS_POOL, stell(500))
        .await
        .expect("back the accrual");

    e.update_account(AccountState::new(attacker_addr, 100_000))
        .await;
    let before = bal(&e, &attacker_addr).await;
    let err = e
        .apply_transaction(
            &svm_tx(
                &attacker,
                0,
                10_000,
                vec![OpCode::SysCallClaimRewards {
                    validator: victim_addr,
                }],
            ),
            0,
        )
        .await
        .expect_err("stranger claim must be refused");
    assert!(
        err.contains("only the validator"),
        "refusal must be the auth check: {err}"
    );

    // The claim was REFUSED, so the transaction failed: under the anti-DoS
    // policy (SEC-07) a failed transaction still pays its failure fee and
    // advances its nonce. The attacker's OWN gas is burned - that is the point
    // of the policy - but they gain NO rewards and the victim's accrual and
    // the staking pool are untouched.
    let after = bal(&e, &attacker_addr).await;
    assert!(
        after < before,
        "the failed claim must not gain the attacker anything"
    );
    assert_eq!(
        before - after,
        10_000,
        "the failure fee is the declared gas limit"
    );
    assert_eq!(
        bal(&e, &STAKING_POOL).await,
        stell(10_000),
        "pool untouched"
    );
    assert_eq!(
        e.staking_read().await.validators[&victim_addr].pending_rewards,
        stell(500),
        "victim reward intact"
    );
    assert!(
        bal(&e, &STAKING_POOL).await >= stell(10_000),
        "POOL SOLVENT"
    );

    // Positive control: the owner can still claim.
    e.apply_transaction(
        &svm_tx(
            &victim,
            1,
            2_000,
            vec![OpCode::SysCallClaimRewards {
                validator: victim_addr,
            }],
        ),
        0,
    )
    .await
    .expect("owner claim works");
    assert_eq!(
        e.staking_read().await.validators[&victim_addr].pending_rewards,
        0
    );
}

// ===========================================================================
// 1b. Stranger force-unbonds (src/svm.rs SysCallUnbond owner check).
// ===========================================================================

#[tokio::test]
async fn adv_stranger_cannot_force_unbond() {
    let e = InMemoryStateEngine::new();
    let honest = SigningKey::generate(&mut OsRng);
    let honest_addr = id(&honest);
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = id(&attacker);

    e.update_account(AccountState::new(honest_addr, floor() + 20_000))
        .await;
    e.apply_transaction(
        &svm_tx(
            &honest,
            0,
            20_000,
            vec![OpCode::SysCallStake {
                validator: honest_addr,
                amount: floor(),
            }],
        ),
        0,
    )
    .await
    .unwrap();
    assert!(e
        .staking_read()
        .await
        .to_validator_set()
        .validators
        .contains_key(&honest_addr));

    e.update_account(AccountState::new(attacker_addr, 20_000))
        .await;
    let err = e
        .apply_transaction(
            &svm_tx(
                &attacker,
                0,
                20_000,
                vec![OpCode::SysCallUnbond {
                    validator: honest_addr,
                    amount: floor(),
                }],
            ),
            0,
        )
        .await
        .expect_err("force-unbond must be refused");
    assert!(
        err.contains("only the validator"),
        "refusal must be the auth check: {err}"
    );

    let l = e.staking_read().await;
    assert_eq!(l.validators[&honest_addr].self_bond, floor());
    assert!(l.to_validator_set().validators.contains_key(&honest_addr));
    assert!(l.unbonding.is_empty(), "no unbonding entry created");
    drop(l);
    assert_eq!(bal(&e, &STAKING_POOL).await, floor(), "pool solvent");

    // Positive control: owner may still unbond.
    e.apply_transaction(
        &svm_tx(
            &honest,
            1,
            10_000,
            vec![OpCode::SysCallUnbond {
                validator: honest_addr,
                amount: floor(),
            }],
        ),
        0,
    )
    .await
    .expect("owner unbond works");
}

// ===========================================================================
// 1b2. Stranger rotates another validator's key (SysCallRotateValidatorKey
//      owner check) + owner rotation moves the whole record live.
// ===========================================================================

#[tokio::test]
async fn adv_stranger_cannot_rotate_anothers_key_but_owner_can() {
    let e = InMemoryStateEngine::new();
    let honest = SigningKey::generate(&mut OsRng);
    let honest_addr = id(&honest);
    let fresh = SigningKey::generate(&mut OsRng);
    let fresh_addr = id(&fresh);
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = id(&attacker);

    e.update_account(AccountState::new(honest_addr, floor() + 100_000))
        .await;
    e.apply_transaction(
        &svm_tx(
            &honest,
            0,
            20_000,
            vec![OpCode::SysCallStake {
                validator: honest_addr,
                amount: floor(),
            }],
        ),
        0,
    )
    .await
    .unwrap();
    assert!(e
        .staking_read()
        .await
        .to_validator_set()
        .validators
        .contains_key(&honest_addr));

    // A delegator rides along, so rotation must carry foreign positions too.
    let delegator = SigningKey::generate(&mut OsRng);
    let delegator_addr = id(&delegator);
    e.update_account(AccountState::new(
        delegator_addr,
        MIN_VALIDATOR_BOND + 20_000,
    ))
    .await;
    e.apply_transaction(
        &svm_tx(
            &delegator,
            0,
            20_000,
            vec![OpCode::SysCallDelegate {
                validator: honest_addr,
                amount: 2_000_000_000,
            }],
        ),
        0,
    )
    .await
    .unwrap();

    e.update_account(AccountState::new(attacker_addr, 20_000))
        .await;
    let err = e
        .apply_transaction(
            &svm_tx(
                &attacker,
                0,
                20_000,
                vec![OpCode::SysCallRotateValidatorKey {
                    old_validator: honest_addr,
                    new_validator: fresh_addr,
                }],
            ),
            0,
        )
        .await
        .expect_err("stranger rotation must be refused");
    assert!(
        err.contains("only the old validator key"),
        "refusal must be the auth check: {err}"
    );
    assert!(e.staking_read().await.validators.contains_key(&honest_addr));
    assert!(!e.staking_read().await.validators.contains_key(&fresh_addr));

    // Owner rotates: record, delegation and validator-set membership move.
    e.apply_transaction(
        &svm_tx(
            &honest,
            1,
            20_000,
            vec![OpCode::SysCallRotateValidatorKey {
                old_validator: honest_addr,
                new_validator: fresh_addr,
            }],
        ),
        0,
    )
    .await
    .expect("owner rotation works");
    {
        let l = e.staking_read().await;
        assert!(!l.validators.contains_key(&honest_addr), "old key is gone");
        assert!(l.validators.contains_key(&fresh_addr), "new key validates");
        assert_eq!(
            l.delegations.get(&(fresh_addr, delegator_addr)).copied(),
            Some(2_000_000_000),
            "delegation follows the record"
        );
        assert!(l.to_validator_set().validators.contains_key(&fresh_addr));
        assert!(!l.to_validator_set().validators.contains_key(&honest_addr));
    }

    // Rotating onto an existing validator refuses (no merging, ever).
    let other = SigningKey::generate(&mut OsRng);
    let other_addr = id(&other);
    e.update_account(AccountState::new(other_addr, floor() + 20_000))
        .await;
    e.apply_transaction(
        &svm_tx(
            &other,
            0,
            20_000,
            vec![OpCode::SysCallStake {
                validator: other_addr,
                amount: floor(),
            }],
        ),
        0,
    )
    .await
    .unwrap();
    // The rotated key needs gas money of its own to transact.
    e.update_account(AccountState::new(fresh_addr, 100_000))
        .await;
    let err = e
        .apply_transaction(
            &svm_tx(
                &fresh,
                0,
                20_000,
                vec![OpCode::SysCallRotateValidatorKey {
                    old_validator: fresh_addr,
                    new_validator: other_addr,
                }],
            ),
            0,
        )
        .await
        .expect_err("rotation onto a live validator must be refused");
    assert!(
        err.contains("rotate failed"),
        "refusal must come from the ledger: {err}"
    );
}

// ===========================================================================
// 1c. Stranger cancels another's order (src/svm.rs SysCallCancelOrder +
//     src/state_engine.rs cancel_order_settled owner check).
// ===========================================================================

#[tokio::test]
async fn adv_stranger_cannot_cancel_anothers_order() {
    let e = InMemoryStateEngine::new();
    let minter = [0xF0; 32];
    let usdt = e
        .create_token(
            minter,
            TokenMetadata {
                name: "wUSDT".into(),
                symbol: "wUSDT".into(),
                decimals: 6,
                total_supply: 0,
                max_supply: Some(u64::MAX),
                minter,
                paused: false,
                description: String::new(),
            },
            0,
        )
        .await
        .unwrap();
    e.pmm_init_usdt(usdt, 1_000_000_000_000).await;

    let victim = SigningKey::generate(&mut OsRng);
    let victim_addr = id(&victim);
    let attacker = SigningKey::generate(&mut OsRng);
    let attacker_addr = id(&attacker);
    e.update_account(AccountState::new(victim_addr, 1_000 * NANO))
        .await;
    e.update_account(AccountState::new(attacker_addr, 10 * NANO))
        .await;
    e.token_execute(
        &usdt,
        minter,
        TokenOp::Mint {
            to: victim_addr,
            amount: 1_000_000_000,
        },
    )
    .await
    .unwrap();

    let pair = 1u32;
    let (order_id, _) = e
        .place_order_settled(
            pair,
            victim_addr,
            OrderSide::Buy,
            OrderType::Limit,
            250_000,
            500 * NANO,
            0,
        )
        .await
        .expect("victim order");
    assert!(
        e.order_escrow_read().await.get(&(pair, order_id)).is_some(),
        "escrow locked"
    );

    let res = e
        .apply_transaction(
            &svm_tx(
                &attacker,
                0,
                1_000_000,
                vec![OpCode::SysCallCancelOrder { order_id }],
            ),
            0,
        )
        .await;
    assert!(res.is_err(), "stranger cancel must be refused: {res:?}");

    let still = e
        .orderbooks_read()
        .await
        .books
        .get(&pair)
        .map(|b| {
            b.bids
                .values()
                .flat_map(|v| v.iter())
                .any(|o| o.order_id == order_id)
        })
        .unwrap_or(false);
    assert!(still, "victim order survives");
    assert!(
        e.order_escrow_read().await.get(&(pair, order_id)).is_some(),
        "escrow untouched"
    );

    // Positive control: owner cancel still refunds.
    assert!(e
        .cancel_order_settled(pair, order_id, victim_addr)
        .await
        .expect("owner cancel")
        .is_some());
}

// ===========================================================================
// 2a. Sync a chain signed only by non-members (src/sync.rs validate_sync_chain
//     + src/consensus.rs QuorumCertificate::verify membership check).
// ===========================================================================

#[tokio::test]
async fn adv_sync_refuses_chain_signed_only_by_non_members() {
    let real = keys(4);
    let vs = vset(&real);
    let our_last = [0x11u8; 32];
    let root = InMemoryStateEngine::new().get_state_root().await;

    // Attacker throwaway keys: zero power, not validators.
    let atk = keys(3);
    for k in &atk {
        assert_eq!(vs.power_of(&id(k)), 0);
    }

    // Variant A: bare throwaway signatures, no decision proof at all.
    let mut prev = our_last;
    let mut chain_a = vec![];
    for i in 0..8u64 {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 8 + i,
            prev_hash: prev,
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: i,
            proposer: id(&atk[0]),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        b.sign_block(&atk[0]);
        for k in atk.iter().skip(1) {
            use ed25519_dalek::Signer;
            b.validator_signatures
                .push((id(k), k.sign(&b.compute_hash()).to_bytes().to_vec()));
        }
        prev = b.compute_hash();
        chain_a.push(b);
    }
    let r = validate_sync_chain(&chain_a, 8, our_last, &vs);
    assert!(
        r.is_err(),
        "non-member chain without QC must be refused: {r:?}"
    );

    // Variant B (literal membership attack): attacker forges its own "QC" whose
    // signers are all non-members. Power counted = 0 < quorum.
    let mut prev = our_last;
    let mut chain_b = vec![];
    for i in 0..4u64 {
        let mut b = mkblock(&atk[0], 8 + i, prev, root);
        let bh = b.compute_hash();
        b.precommit_qc = Some(QuorumCertificate {
            height: 8 + i,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            signatures: atk
                .iter()
                .map(|k| {
                    let v = Vote::sign(k, 8 + i, 0, VoteKind::Precommit, Some(bh));
                    (v.voter, v.signature)
                })
                .collect(),
        });
        prev = b.compute_hash();
        chain_b.push(b);
    }
    let r = validate_sync_chain(&chain_b, 8, our_last, &vs);
    assert!(r.is_err(), "non-member QC must be refused: {r:?}");
    assert!(r.unwrap_err().contains("validator quorum"));
}

// ===========================================================================
// 2b. Sync with power below quorum: genuine members but only 1-of-4.
// ===========================================================================

#[tokio::test]
async fn adv_sync_refuses_power_below_quorum() {
    let ks = keys(4);
    let vs = vset(&ks);
    assert_eq!(vs.quorum_power(), 3);
    let our_last = [0x11u8; 32];
    let root = InMemoryStateEngine::new().get_state_root().await;

    let mut prev = our_last;
    let mut chain = vec![];
    for i in 0..3u64 {
        let mut b = mkblock(&ks[0], 8 + i, prev, root);
        let bh = b.compute_hash();
        // Only ONE genuine member signed: power 1 < quorum 3.
        b.precommit_qc = Some(precommit_qc(&ks, &[0], 8 + i, bh));
        assert!(!b.precommit_qc.as_ref().unwrap().verify(&vs));
        prev = b.compute_hash();
        chain.push(b);
    }
    let r = validate_sync_chain(&chain, 8, our_last, &vs);
    assert!(r.is_err(), "below-quorum chain must be refused: {r:?}");

    // Positive control: 3-of-4 QCs pass. F8: the block's proposer must be the
    // one the schedule names for its height/round.
    let mut prev = our_last;
    let mut good = vec![];
    for i in 0..3u64 {
        let h = 8 + i;
        let sched = vs.proposer_for(h, 0).expect("non-empty set has a proposer");
        let signer = ks
            .iter()
            .find(|k| id(k) == sched)
            .expect("proposer is a member");
        let mut b = mkblock(signer, h, prev, root);
        let bh = b.compute_hash();
        b.precommit_qc = Some(precommit_qc(&ks, &[0, 1, 2], h, bh));
        prev = b.compute_hash();
        good.push(b);
    }
    validate_sync_chain(&good, 8, our_last, &vs).expect("quorum chain passes");
}

// ===========================================================================
// 3. Finalize a block hash the node never received (src/runtime.rs try_finalize
//    block-presence guard). Genuine 3-of-4 prevote+precommit quorums exist, but
//    the body was never delivered.
// ===========================================================================

#[tokio::test]
async fn adv_cannot_finalize_a_block_never_received() {
    let ks = keys(4);
    let vs = vset(&ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st.clone(), 1);

    let phantom = blake3::hash(b"attacker-chosen-block-contents").into();
    for k in ks.iter().take(3) {
        rt.on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(phantom)))
            .unwrap();
    }
    assert!(
        rt.hc.try_prevote_quorum().is_some(),
        "prevote quorum exists"
    );
    for k in ks.iter().take(3) {
        rt.on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(phantom)))
            .unwrap();
    }
    assert!(
        !rt.blocks.contains_key(&phantom),
        "precondition: no block body"
    );

    assert_eq!(
        rt.try_finalize().await,
        None,
        "must not finalize an absent block"
    );
    assert!(rt.finalized.is_empty(), "nothing committed");
    assert_eq!(rt.height(), 1, "height does not advance");
    assert_eq!(rt.applied_txs, 0, "nothing applied");
}

// ===========================================================================
// 4a. Decide on precommits with NO prevotes (src/consensus.rs try_precommit_quorum
//     prevote precondition). Block IS present to isolate the quorum check.
// ===========================================================================

#[tokio::test]
async fn adv_cannot_decide_on_precommits_with_no_prevotes() {
    let ks = keys(4);
    let vs = vset(&ks);
    // Block IS present (isolates the quorum check from the presence check).
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st.clone(), 1);
    let held = mkblock(&ks[0], 1, [0u8; 32], st.get_state_root().await);
    let held_hash = held.compute_hash();
    rt.blocks.insert(held_hash, held);
    // Three genuine precommits, ZERO prevotes.
    for k in ks.iter().take(3) {
        rt.on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(held_hash)))
            .unwrap();
    }
    assert!(rt.hc.prevote_qc.is_empty(), "precondition: zero prevotes");
    assert_eq!(
        rt.try_finalize().await,
        None,
        "precommits alone must not decide"
    );
    assert!(rt.finalized.is_empty());
    assert_eq!(rt.height(), 1);
}

// ===========================================================================
// 4b. Prevotes for A + precommits for B must not decide.
// ===========================================================================

#[tokio::test]
async fn adv_cannot_decide_when_prevotes_and_precommits_disagree() {
    let ks = keys(4);
    let vs = vset(&ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st.clone(), 1);

    let a = bh(0xA1);
    let b = bh(0xB2);
    for k in ks.iter().take(3) {
        rt.on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(a)))
            .unwrap();
    }
    for k in ks.iter().take(3) {
        rt.on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(b)))
            .unwrap();
    }
    let blk = mkblock(&ks[0], 1, [0u8; 32], st.get_state_root().await);
    let blk_hash = blk.compute_hash();
    rt.blocks.insert(blk_hash, blk);
    // Even if the precommit target were held, quorums disagree -> no decision.
    assert_eq!(rt.try_finalize().await, None);
    assert!(rt.finalized.is_empty());
    assert_eq!(rt.height(), 1);
}

// ===========================================================================
// 4c. Decide against an existing lock must fail.
// ===========================================================================

#[tokio::test]
async fn adv_cannot_decide_against_an_existing_lock() {
    let ks = keys(4);
    let vs = vset(&ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st.clone(), 1);

    rt.hc.locked = Some((bh(0xA1), 0));
    let b = bh(0xB2);
    for k in ks.iter().take(3) {
        rt.on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(b)))
            .unwrap();
    }
    for k in ks.iter().take(3) {
        rt.on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(b)))
            .unwrap();
    }
    let blk = mkblock(&ks[0], 1, [0u8; 32], st.get_state_root().await);
    rt.blocks.insert(blk.compute_hash(), blk);
    assert_eq!(
        rt.try_finalize().await,
        None,
        "locked node must not decide a conflict"
    );
    assert!(rt.finalized.is_empty());
    assert_eq!(rt.height(), 1);
}

// ===========================================================================
// 5. Round-counter DoS (src/consensus.rs advance_to_round +1/message):
//    single far-future message, and the 500-message walk.
// ===========================================================================

#[test]
fn adv_single_far_future_round_buys_at_most_one() {
    let ks = keys(4);
    let mut hc = HeightConsensus::new(1, vset(&ks));
    hc.advance_to_round(u32::MAX);
    assert_eq!(hc.round, 1, "one datagram buys at most one round");
}

#[test]
fn adv_five_hundred_far_future_rounds_buy_at_most_500() {
    use stellereum::consensus::MAX_ROUND_AHEAD;
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(1, vs.clone());
    for i in 0..500u32 {
        hc.advance_to_round((i + 1) * MAX_ROUND_AHEAD);
    }
    assert_eq!(
        hc.round, 500,
        "one round per message, never 1000 per message"
    );
    assert!(hc.round < 500 * MAX_ROUND_AHEAD);

    // The node still follows the honest network at its own round.
    let r = hc.round;
    let proposer = vs.proposer_for(1, r).unwrap();
    hc.receive_proposal(proposer, bh(2)).unwrap();
    for k in ks.iter() {
        hc.add_prevote(Vote::sign(k, 1, r, VoteKind::Prevote, Some(bh(2))))
            .unwrap();
    }
    assert!(hc.try_prevote_quorum().is_some());
}

// ===========================================================================
// Adopt-path helpers: a valid height-1 block + genuine 3-of-4 precommit QC.
// ===========================================================================

async fn adopt_fixture(ks: &[SigningKey]) -> (ValidatorRuntime, Block, [u8; 32]) {
    let vs = vset(ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st.clone(), 1);
    let proposer_id = vs.proposer_for(1, 0).unwrap();
    let pk = ks.iter().find(|k| id(k) == proposer_id).unwrap().clone();
    let block = mkblock(&pk, 1, [0u8; 32], st.get_state_root().await);
    let hash = block.compute_hash();
    let _ = &mut rt;
    (rt, block, hash)
}

// 6a. Adopt with a prevote-kind cert (src/runtime.rs kind check).
#[tokio::test]
async fn adv_adopt_refuses_prevote_kind_cert() {
    let ks = keys(4);
    let (mut rt, block, hash) = adopt_fixture(&ks).await;
    let cert = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash: Some(hash),
        signatures: ks
            .iter()
            .take(3)
            .map(|k| {
                let v = Vote::sign(k, 1, 0, VoteKind::Prevote, Some(hash));
                (v.voter, v.signature)
            })
            .collect(),
    };
    assert!(cert.verify(&rt.validators), "prevote QC self-consistent");
    let r = rt.adopt_committed(1, block, cert).await;
    assert!(r.is_err(), "prevote cert must not finalize: {r:?}");
    assert!(r.unwrap_err().contains("not a precommit quorum"));
    assert!(rt.finalized.is_empty());
    assert_eq!(rt.height(), 1);
}

// 6b. Adopt with cert height != block height (src/runtime.rs height binding).
#[tokio::test]
async fn adv_adopt_refuses_wrong_height_cert() {
    let ks = keys(4);
    let (mut rt, block, hash) = adopt_fixture(&ks).await;
    let cert = QuorumCertificate {
        height: 999,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures: ks
            .iter()
            .take(3)
            .map(|k| {
                let v = Vote::sign(k, 999, 0, VoteKind::Precommit, Some(hash));
                (v.voter, v.signature)
            })
            .collect(),
    };
    assert!(cert.verify(&rt.validators));
    let r = rt.adopt_committed(1, block, cert).await;
    assert!(r.is_err(), "wrong-height cert must not finalize: {r:?}");
    assert!(r.unwrap_err().contains("certificate is for height"));
    assert!(rt.finalized.is_empty());
}

// 6c. Adopt with a non-scheduled proposer (src/runtime.rs proposer check).
#[tokio::test]
async fn adv_adopt_refuses_non_scheduled_proposer() {
    let ks = keys(4);
    let vs = vset(&ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st.clone(), 1);

    let real = vs.proposer_for(1, 0).unwrap();
    let imposter = ks.iter().find(|k| id(k) != real).unwrap().clone();
    let block = mkblock(&imposter, 1, [0u8; 32], st.get_state_root().await);
    let hash = block.compute_hash();
    let cert = precommit_qc(&ks, &[0, 1, 2], 1, hash);
    assert!(cert.verify(&vs));
    let r = rt.adopt_committed(1, block, cert).await;
    assert!(r.is_err(), "imposter block must not be adopted: {r:?}");
    assert!(r.unwrap_err().contains("not the expected proposer"));
    assert!(rt.finalized.is_empty());
}

// 6d. Adopt with a fabricated state root (src/runtime.rs state-root binding).
#[tokio::test]
async fn adv_adopt_refuses_fabricated_state_root() {
    let ks = keys(4);
    let (mut rt, mut block, hash) = adopt_fixture(&ks).await;
    block.state_root = [0xABu8; 32];
    // Re-sign after mutating the header so the failure is the root, not the sig.
    let proposer = block.proposer;
    let pk = ks.iter().find(|k| id(k) == proposer).unwrap().clone();
    block.validator_signatures.clear();
    block.sign_block(&pk);
    let hash2 = block.compute_hash();
    let _ = hash;
    let cert = precommit_qc(&ks, &[0, 1, 2], 1, hash2);
    let r = rt.adopt_committed(1, block, cert).await;
    assert!(r.is_err(), "fabricated root must be refused: {r:?}");
    assert!(r.unwrap_err().contains("parent state root"));
    assert!(rt.finalized.is_empty());
}

// 6e. Adopt with a caller-nominated validator set: cert valid under the
//     attacker's set, worthless under the node's own set (src/runtime.rs uses
//     self.validators; no set parameter exists).
#[tokio::test]
async fn adv_adopt_uses_only_the_local_validator_set() {
    let ks = keys(4);
    let real = vset(&ks);
    let attacker = SigningKey::generate(&mut OsRng);
    let forged = ValidatorSet::from_list(vec![(id(&attacker), 1)]);

    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &real, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), real.clone(), st.clone(), 1);
    let proposer_id = real.proposer_for(1, 0).unwrap();
    let pk = ks.iter().find(|k| id(k) == proposer_id).unwrap().clone();
    let block = mkblock(&pk, 1, [0u8; 32], st.get_state_root().await);
    let hash = block.compute_hash();
    let v = Vote::sign(&attacker, 1, 0, VoteKind::Precommit, Some(hash));
    let cert = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures: vec![(v.voter, v.signature)],
    };
    assert!(!cert.verify(&real), "worthless against the real set");
    assert!(cert.verify(&forged), "valid against the attacker set");

    let r = rt.adopt_committed(1, block, cert).await;
    assert!(r.is_err(), "one-key cert must not finalize: {r:?}");
    assert!(r.unwrap_err().contains("validator quorum"));
    assert!(rt.finalized.is_empty());
}

// ===========================================================================
// 7a. Replay one equivocation pair N times (src/consensus.rs VoteSet dedup):
//     still exactly ONE evidence tuple, ONE bounded slash.
// ===========================================================================

#[tokio::test]
async fn adv_equivocation_replay_does_not_compound() {
    let ks = keys(4);
    let vs = vset(&ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, 1_000_000_000_000_000).await;
    let pool_before = bal(&st, &STAKING_POOL).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st.clone(), 1);
    let victim = ks[3].clone();
    let vid = id(&victim);

    let a = Vote::sign(&victim, 1, 0, VoteKind::Prevote, Some(bh(0xA1)));
    let b = Vote::sign(&victim, 1, 0, VoteKind::Prevote, Some(bh(0xA2)));
    for _ in 0..200u32 {
        rt.on_prevote(a.clone()).unwrap();
        rt.on_prevote(b.clone()).unwrap();
    }
    assert_eq!(
        rt.hc.equivocations().len(),
        1,
        "one pair -> one evidence tuple, not 400"
    );

    let self_before = st.staking_read().await.validators[&vid].self_bond;
    let burned = rt.apply_equivocation_slashes().await;
    let l = st.staking_read().await;
    assert!(burned > 0, "the single equivocation is still punished once");
    assert_eq!(
        l.validators[&vid].total_slashed, burned,
        "exactly one slash applied"
    );
    assert_eq!(l.total_burned, burned, "global counter agrees");
    // Design intent is 5%: 200 rebroadcasts must not confiscate the bond.
    assert!(
        l.validators[&vid].self_bond > self_before / 2,
        "bond survives a 200x replay: {} -> {}",
        self_before,
        l.validators[&vid].self_bond
    );
    drop(l);
    let _ = pool_before;
}

// ===========================================================================
// 7b. Downtime-slash replay of an old height (src/staking.rs note_missed_heights
//     height guard): re-applying an old certificate burns nothing more.
// ===========================================================================

#[test]
fn adv_downtime_slash_cannot_replay_an_old_height() {
    use stellereum::staking::StakingLedger;
    let mut l = StakingLedger::new();
    let v = [0x09u8; 32];
    l.bond(v, floor(), 0).unwrap();
    let never = |_: &[u8; 32]| false;
    let eligible = vec![v];

    // Drive the outage until the slash fires.
    let mut slash_height = 0u64;
    let mut first_burn = 0u64;
    for h in 1..=100_000u64 {
        let b = l.note_missed_heights(h, &never, &eligible);
        if b > 0 {
            slash_height = h;
            first_burn = b;
            break;
        }
    }
    assert!(slash_height > 0, "the outage eventually slashes");
    let slashed_after_first = l.validators[&v].total_slashed;
    assert_eq!(slashed_after_first, first_burn);

    // Replay OLD heights over and over: the documented no-op.
    for _ in 0..50u64 {
        let b = l.note_missed_heights(1, &never, &eligible);
        assert_eq!(
            b, 0,
            "replaying height 1 after a slash at {slash_height} must burn 0"
        );
        let b2 = l.note_missed_heights(slash_height, &never, &eligible);
        assert_eq!(b2, 0, "replaying the slash height itself must burn 0");
    }
    assert_eq!(
        l.validators[&v].total_slashed, slashed_after_first,
        "no additional stake burned by replays"
    );
}

// ===========================================================================
// 8. Unauthenticated faucet drip fails closed without a token (src/rpc.rs
//    stell_faucet: enabled faucet + no STELL_FAUCET_TOKEN => refuse).
//    Reached over real HTTP via the public router.
// ===========================================================================

#[tokio::test]
async fn adv_faucet_without_token_dispenses_nothing() {
    use std::sync::atomic::AtomicU64;
    use stellereum::mempool::Mempool;
    use stellereum::rpc::{router, Faucet, ReceiptIndex, RpcState};
    use tokio::sync::RwLock;

    let engine = Arc::new(InMemoryStateEngine::new());
    let key_seed = [0x11u8; 32];
    let faucet = Faucet::new(key_seed, 1, 100, 1_000_000);
    let faucet_addr = faucet.account();
    engine
        .update_account(AccountState::new(faucet_addr, 1_000_000))
        .await;

    // Enabled faucet, but the operator never set STELL_FAUCET_TOKEN.
    let st = Arc::new(RpcState {
        engine: engine.clone(),
        mempool: Arc::new(RwLock::new(Mempool::default())),
        height: Arc::new(AtomicU64::new(42)),
        node_id: "adv-test".to_string(),
        chain_id: 777,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: Some(Arc::new(faucet)),
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router(st).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let who = [0x42u8; 32];
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "stell_faucet",
        "params": { "address": hex::encode(who) }
    })
    .to_string();
    let url = format!("http://{addr}/");
    let resp_text = tokio::task::spawn_blocking(move || {
        ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map(|r| r.into_string().unwrap_or_default())
    })
    .await
    .unwrap()
    .unwrap_or_default();
    server.abort();

    let v: serde_json::Value = serde_json::from_str(&resp_text).expect("json rpc reply");
    let msg = v.get("error").map(|e| e.to_string()).unwrap_or_default();
    assert!(
        msg.contains("refusing to dispense") || msg.contains("faucet is enabled"),
        "fail-closed refusal expected, got: {resp_text}"
    );
    assert!(
        engine.get_account(&who).await.is_none(),
        "no account may be created by an unauthenticated drip"
    );
    assert_eq!(
        engine.get_account(&faucet_addr).await.unwrap().balance,
        1_000_000,
        "treasury untouched"
    );
}

// ===========================================================================
// 9. Grafted vote-signatures instead of a QC (src/sync.rs requires the attached
//    precommit QC; src/sharding.rs: vote sigs are over vote_sign_bytes, never
//    over the block hash). Feed blocks whose validator_signatures are real
//    quorum vote-signatures grafted as block signatures, with no QC.
// ===========================================================================

#[tokio::test]
async fn adv_grafted_vote_signatures_are_not_a_decision_proof() {
    let ks = keys(4);
    let vs = vset(&ks);
    let our_last = [0x11u8; 32];
    let root = InMemoryStateEngine::new().get_state_root().await;

    // Direct unit fact: a real quorum's vote signatures do NOT verify as block
    // signatures, because the signed message differs.
    let probe = mkblock(&ks[0], 8, our_last, root);
    let probe_hash = probe.compute_hash();
    let mut grafted = probe.clone();
    // Keep the proposer's genuine block signature (so the proposer check passes
    // and the QC check is what refuses), and graft a quorum of real vote
    // signatures alongside it.
    for k in ks.iter().take(3) {
        let v = Vote::sign(k, 8, 0, VoteKind::Precommit, Some(probe_hash));
        grafted.validator_signatures.push((v.voter, v.signature));
    }
    assert!(
        !grafted.verify_validator_quorum(&vs),
        "grafted vote-sigs must not count as block signatures"
    );

    // Full sync path: chain carrying grafted sigs and NO precommit QC.
    let map: HashMap<[u8; 32], Block> = {
        let mut m = HashMap::new();
        let mut prev = our_last;
        for i in 0..4u64 {
            let mut g = mkblock(&ks[0], 8 + i, prev, root);
            let h = g.compute_hash();
            for k in ks.iter().take(3) {
                let v = Vote::sign(k, 8 + i, 0, VoteKind::Precommit, Some(h));
                g.validator_signatures.push((v.voter, v.signature));
            }
            g.precommit_qc = None;
            prev = g.compute_hash();
            m.insert(prev, g);
        }
        m
    };
    // Rebuild ordered chain oldest-first for the validator.
    let mut ordered: Vec<Block> = map.values().cloned().collect();
    ordered.sort_by_key(|b| b.height);
    assert_eq!(ordered.len(), 4);
    let r = validate_sync_chain(&ordered, 8, our_last, &vs);
    assert!(
        r.is_err(),
        "grafted chain without QC must be refused: {r:?}"
    );
    assert!(r.unwrap_err().contains("no decision proof"));

    // collect_missing_blocks still resolves such a chain off the peer (fetch is
    // mechanical); the refusal happens at validation, not fetch.
    let head = ordered.last().unwrap().compute_hash();
    let fetched = collect_missing_blocks(head, our_last, 100, |h| {
        let b = map.get(&h).cloned();
        async move { b }
    })
    .await
    .expect("fetch resolves");
    assert_eq!(fetched.len(), 4);
    assert!(validate_sync_chain(&fetched, 8, our_last, &vs).is_err());
}
