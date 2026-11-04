//! HUNT: `validate_sync_chain` verifies a SIGNATURE COUNT where the caller means
//! VOTING POWER, and never checks that a signer is a validator at all.
//!
//! Targets:
//!   src/main.rs:220-234        quorum_power() -> `Some(q as usize)` -> validate_sync_chain
//!   src/sync.rs:65-98          validate_sync_chain
//!   src/sharding.rs:524-547    Block::verify_signatures(required_quorum: usize)
//!   src/main.rs:65-82          build_validator_set: EVERY validator gets power 1
//!
//! This is exactly the CometBFT post-mortem class the hunt brief describes. The
//! caller reasons in terms of a QUORUM (2/3 of power). The callee counts ED25519
//! signatures from a flat list of byte strings. The two are never cross-checked:
//! `verify_signatures` has no `ValidatorSet` parameter at all, so a signature from
//! a key that has never held a single unit of stake counts exactly like a
//! validator's. No error is raised, because nothing is being checked.
//!
//! And because `build_validator_set` assigns power 1 to every validator, the
//! production network's `quorum_power()` is a small integer that plugs straight
//! into a signature counter. `required_quorum = 3` on a 4-validator network.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::Arc;
use stellereum::consensus::ValidatorSet;
use stellereum::sharding::Block;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::sync::{collect_missing_blocks, validate_sync_chain};

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}
fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn block(h: u64, prev: [u8; 32], root: [u8; 32], proposer: &SigningKey) -> Block {
    let mut b = Block {
        shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
        height: h,
        prev_hash: prev,
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: h,
        proposer: proposer.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(proposer);
    b
}

// ===========================================================================
// FINDING 6 (CRITICAL): a peer with ZERO stake feeds a whole fabricated history
// ===========================================================================

#[tokio::test]
async fn hunt_finding_6_sync_accepts_a_chain_signed_only_by_throwaway_keys() {
    use ed25519_dalek::Signer;

    // ---- The victim: a real node with 4 real validators, all power 1. ----
    let real_keys = keys(4);
    let vs = vset(&real_keys);
    assert_eq!(vs.len(), 4);
    let quorum_power = vs.quorum_power();
    assert_eq!(
        quorum_power, 3,
        "production power is 1 per validator (main.rs:65-82)"
    );
    // main.rs:227 -- a POWER figure is used directly as a SIGNATURE COUNT.
    let required_quorum: usize = quorum_power as usize;
    println!(
        "[FINDING 6] real set: {} validators, quorum_power = {}",
        vs.len(),
        quorum_power
    );
    println!("[FINDING 6] main.rs passes required_quorum = {required_quorum} SIGNATURES");

    let engine = Arc::new(InMemoryStateEngine::new());
    let user = real_keys[0].verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(user, 1_000_000))
        .await;
    let our_root = engine.get_state_root().await;
    let our_height = 7u64;
    let mut our_finalized: Vec<(u64, [u8; 32])> = vec![];
    let our_last = [0x11u8; 32]; // our last finalized block hash
    our_finalized.push((our_height, our_last));

    // ---- The attacker: 3 throwaway keys, zero stake, not in any validator set. ----
    let attacker_keys = keys(3);
    for k in &attacker_keys {
        assert_eq!(
            vs.power_of(&k.verifying_key().to_bytes()),
            0,
            "attacker key has no power"
        );
    }
    println!(
        "[FINDING 6] attacker holds {} keys, total voting power = 0",
        attacker_keys.len()
    );

    // ---- Forge 500 blocks continuing OUR chain, with no transactions. ----
    let n_forged = 500u64;
    let mut prev = our_last;
    let mut chain: Vec<Block> = vec![];
    for i in 0..n_forged {
        let mut b = block(our_height + 1 + i, prev, our_root, &attacker_keys[0]);
        // Three "co-signatures" from throwaway keys standing in for a validator quorum.
        for k in attacker_keys.iter().skip(1) {
            b.validator_signatures.push((
                k.verifying_key().to_bytes(),
                k.sign(&b.compute_hash()).to_bytes().to_vec(),
            ));
        }
        prev = b.compute_hash();
        chain.push(b);
    }
    let head = prev;

    // ---- main.rs: the node fetches the chain by walking back from the peer's head. ----
    let fetched = {
        let map: HashMap<[u8; 32], Block> = chain
            .iter()
            .map(|b| (b.compute_hash(), b.clone()))
            .collect();
        collect_missing_blocks(head, our_last, 200_000, |h| {
            let b = map.get(&h).cloned();
            async move { b }
        })
        .await
        .expect("the forged chain resolves cleanly")
    };
    assert_eq!(fetched.len() as u64, n_forged);
    println!("[FINDING 6] fetched {n_forged} blocks from the peer, starting at our own hash");

    // ---- main.rs:234 validate_sync_chain ----
    let first = fetched[0].height;
    // The validator set is now passed instead of a head count. Membership is
    // checked and the threshold is a fraction of stake, so the forged chain - whose
    // signers are not in the set - is refused. This assertion is the regression.
    let v = validate_sync_chain(&fetched, first, our_last, &vs);
    println!("[FINDING 6 FIXED] validate_sync_chain against the honest set = {v:?}");
    assert!(
        v.is_err(),
        "a chain signed outside the validator set must be refused: {v:?}"
    );
}

// ===========================================================================
// FINDING 7 (HIGH): the reverse failure -- real staking powers make sync dead
// ===========================================================================

#[test]
fn hunt_finding_7_quorum_power_is_used_as_a_signature_count_so_sync_is_dead() {
    use stellereum::staking::MIN_VALIDATOR_BOND;

    // A realistic bonded validator: MIN_VALIDATOR_BOND = 1_000 STELL = 1e12 nano.
    let real_keys = keys(4);
    let bonded = ValidatorSet::from_list(
        real_keys
            .iter()
            .map(|k| (k.verifying_key().to_bytes(), MIN_VALIDATOR_BOND))
            .collect(),
    );
    assert_eq!(bonded.total_power(), 4 * MIN_VALIDATOR_BOND);
    let q = bonded.quorum_power();
    println!(
        "[FINDING 7] bonded 4-validator set: total_power = {}",
        bonded.total_power()
    );
    println!("[FINDING 7] quorum_power = {q}");
    // main.rs would turn this into required_quorum = q, a COUNT of signatures.
    println!("[FINDING 7] main.rs would require {q} distinct Ed25519 signatures per block");
    assert!(
        q > 1_000_000_000_000,
        "no block can ever carry a quadrillion signatures: block sync is permanently broken on a staking network"
    );
    // And this is the same set that QuorumCertificate::verify scores by POWER,
    // where 3 of 4 signatures is a genuine quorum. Two different meanings of the
    // same word, in the same codebase, on the same chain.
    let bh = [0x33u8; 32];
    let sigs: Vec<(stellereum::consensus::ValidatorId, Vec<u8>)> = real_keys
        .iter()
        .take(3)
        .map(|k| {
            let v = stellereum::consensus::Vote::sign(
                k,
                1,
                0,
                stellereum::consensus::VoteKind::Precommit,
                Some(bh),
            );
            (v.voter, v.signature)
        })
        .collect();
    let qc = stellereum::consensus::QuorumCertificate {
        height: 1,
        round: 0,
        kind: stellereum::consensus::VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: sigs,
    };
    assert!(
        qc.verify(&bonded),
        "3 of 4 bonded validators is a real quorum"
    );
    println!("[FINDING 7] ...yet 3 signatures would be judged a SUFFICIENT but for the count: required_quorum would be {q}");
}

// ===========================================================================
// FINDING 8 (HIGH): fund_genesis silently discards a failed bond (`let _ =`)
// ===========================================================================

#[tokio::test]
async fn hunt_finding_8_fund_genesis_silently_leaves_an_empty_validator_set() {
    use stellereum::staking::{StakingLedger, MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};

    let ks = keys(4);
    let vs = vset(&ks);

    // A genesis allocation SMALLER than one validator bond. The node funds the
    // accounts, then calls `bond(min(GENESIS_VALIDATOR_BOND, balance))` -- which is
    // below the MIN+buffer floor, so it returns Err(BondBelowMinimum)...
    let engine = Arc::new(InMemoryStateEngine::new());
    let poor = 999_999_999_999u64; // one nano-STELL short of MIN_VALIDATOR_BOND
    assert!(poor < MIN_VALIDATOR_BOND);
    stellereum::runtime::fund_genesis(&engine, &vs, poor).await;

    // ...and `let _ = ledger.bond(...)` at src/runtime.rs:60 throws the error away.
    let derived = engine.staking_read().await.to_validator_set();
    println!("[FINDING 8] balance {poor} < MIN_VALIDATOR_BOND {MIN_VALIDATOR_BOND}");
    println!(
        "[FINDING 8] ledger.validators = {}",
        engine.staking_read().await.validators.len()
    );
    println!(
        "[FINDING 8] to_validator_set() = {} validators, total_power = {}",
        derived.len(),
        derived.total_power()
    );
    assert!(derived.is_empty(), "no validator was ever bonded");
    assert_eq!(
        derived.quorum_power(),
        u64::MAX,
        "quorum is unreachable: the chain stalls"
    );

    let bal = engine
        .get_account(&ks[0].verifying_key().to_bytes())
        .await
        .unwrap()
        .balance;
    // Under SEC-ECON-01 (P0-5 fix), the genesis bond is debited to STELL_POOL.
    // GATE (LEAD a: legacy branch removed — strict-only, no env toggle): the
    // bond is ALWAYS debited, so the funded account holds 0 and the pool
    // holds the full bonded sum.
    {
        assert_eq!(bal, 0);
        let pool = engine
            .get_account(&stellereum::staking::STAKING_POOL)
            .await
            .unwrap()
            .balance;
        assert_eq!(pool, poor * 4);
    }

    // sanity: a sufficient balance does bond (at least MIN+buffer since the
    // bond floor refuses bare-MIN bonds)
    let ok = Arc::new(InMemoryStateEngine::new());
    stellereum::runtime::fund_genesis(&ok, &vs, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER).await;
    let good = ok.staking_read().await.to_validator_set();
    println!(
        "[FINDING 8] with balance == MIN+buffer: {} validators bonded",
        good.len()
    );
    assert_eq!(good.len(), 4);
    let _ = StakingLedger::new();
}
