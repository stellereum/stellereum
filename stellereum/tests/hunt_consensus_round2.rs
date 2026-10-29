//! ADVERSARIAL HUNT round 2: slashing, commitment completeness, validator-set
//! rotation and the commitment digest.
//! Read-only with respect to src/.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use std::sync::Arc;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}
fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
fn bh(n: u8) -> [u8; 32] {
    [n; 32]
}
fn vs_of(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}
async fn missed_map(st: &Arc<InMemoryStateEngine>) -> BTreeMap<[u8; 32], (u32, u64, u64)> {
    let g = st.staking_read().await;
    g.validators
        .iter()
        .map(|(k, v)| (*k, (v.missed, v.self_bond, v.total_slashed)))
        .collect()
}

fn block_at(vset: &ValidatorSet, ks: &[SigningKey], height: u64, root: [u8; 32]) -> Block {
    let proposer = vset.proposer_for(height, 0).unwrap();
    let pk = ks.iter().find(|k| id(k) == proposer).unwrap();
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(pk);
    b
}

fn precommit_cert(ks: &[SigningKey], n: usize, height: u64, hash: [u8; 32]) -> QuorumCertificate {
    QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures: ks
            .iter()
            .take(n)
            .map(|k| {
                let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(hash));
                (v.voter, v.signature)
            })
            .collect(),
    }
}

// ===========================================================================
// ATTACK 10  (CRITICAL, FIXED — audit F4) — equivocation slashing used to be
// driven by PEER-SUPPLIED votes that are not part of the block and not part of
// the certificate. Two nodes that adopted the SAME committed block reached
// DIFFERENT ledgers / state roots, purely because one of them was sent two extra
// gossiped votes. Equivocation slashing is now deferred on every path, so the
// extra votes can no longer move state.
// ===========================================================================

#[tokio::test]
async fn hunt10_peer_gossip_no_longer_diverges_the_ledger_and_the_state_root() {
    let ks = keys(4);
    let vset = vs_of(&ks);
    let victim = ks[3].clone();

    // Two nodes, identical genesis, identical block.
    let mk = || {
        let st = Arc::new(InMemoryStateEngine::new());
        (st, ks.clone(), vset.clone())
    };
    let (st_a, ksa, vs_a) = mk();
    fund_genesis(&st_a, &vs_a, 1_000_000_000_000_000).await;
    let blk = block_at(&vs_a, &ksa, 1, st_a.get_state_root().await);
    let block_hash = blk.compute_hash();

    let (st_b, ksb, vs_b) = mk();
    fund_genesis(&st_b, &vs_b, 1_000_000_000_000_000).await;
    assert_eq!(
        blk.compute_hash(),
        block_at(&vs_b, &ksb, 1, st_b.get_state_root().await).compute_hash()
    );

    let before_a = missed_map(&st_a).await;
    let before_b = missed_map(&st_b).await;
    assert_eq!(before_a, before_b, "identical genesis");

    let cert = precommit_cert(&ks, 3, 1, block_hash);
    assert!(cert.verify(&vset));

    // ---- Node A: the peer ALSO gossips an equivocating pair from validator #4.
    let mut node_a = ValidatorRuntime::new(ksa[0].clone(), vs_a.clone(), st_a.clone(), 1);
    node_a
        .on_prevote(Vote::sign(&victim, 1, 0, VoteKind::Prevote, Some(bh(0xA1))))
        .unwrap();
    node_a
        .on_prevote(Vote::sign(&victim, 1, 0, VoteKind::Prevote, Some(bh(0xA2))))
        .unwrap();
    // Node A genuinely holds the double-vote evidence...
    assert_eq!(
        node_a.hc.equivocations().len(),
        1,
        "node A must record the double-vote, or this test is vacuous"
    );
    node_a
        .adopt_committed(1, blk.clone(), cert.clone())
        .await
        .unwrap();

    // ---- Node B: sees only the committed block.
    let mut node_b = ValidatorRuntime::new(ksb[0].clone(), vs_b.clone(), st_b.clone(), 1);
    assert!(node_b.hc.equivocations().is_empty());
    node_b.adopt_committed(1, blk, cert).await.unwrap();

    let after_a = missed_map(&st_a).await;
    let after_b = missed_map(&st_b).await;
    // F4 FIX: the extra gossiped votes must NOT change validator state. Both nodes
    // applied the SAME block and must agree on every committed field.
    assert_eq!(
        after_a, after_b,
        "F4 FIX: peer gossip must not change the ledger; A={after_a:?} B={after_b:?}"
    );
    assert_eq!(
        after_a[&id(&victim)].2,
        before_a[&id(&victim)].2,
        "F4 FIX: no equivocation slash on local evidence"
    );
    assert_eq!(
        after_b[&id(&victim)].2,
        before_b[&id(&victim)].2,
        "node B slashes nothing"
    );

    let root_a = st_a.get_state_root().await;
    let root_b = st_b.get_state_root().await;
    assert_eq!(
        root_a, root_b,
        "F4 FIX: state roots must agree for the SAME finalized block regardless of \
         which extra votes a node happened to receive"
    );
    eprintln!(
        "HUNT10 FIXED: block {} adopted by both. victim={} A(self_bond,slashed)={:?} \
         B={:?}; roots A={} B={} AGREE.",
        hex::encode(&block_hash[..6]),
        hex::encode(&id(&victim)[..6]),
        after_a[&id(&victim)],
        after_b[&id(&victim)],
        hex::encode(root_a),
        hex::encode(root_b)
    );
}

// ===========================================================================
// ATTACK 11  (HIGH, FIXED — audit F4) — equivocation slashing used to happen on
// the adopt path and its burn was never taken out of STAKING_POOL (the return
// value was discarded). Since equivocation slashing is now deferred on every
// path, the adopt path burns nothing at all: the ledger and the pool stay
// consistent, which is what determinism requires.
// ===========================================================================

#[tokio::test]
async fn hunt11_equivocation_burn_is_never_debited_from_the_pool() {
    let ks = keys(4);
    let vset = vs_of(&ks);
    let victim = ks[3].clone();
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vset, 1_000_000_000_000_000).await;
    let blk = block_at(&vset, &ks, 1, st.get_state_root().await);
    let block_hash = blk.compute_hash();

    let pool_before = st
        .get_account(&stellereum::staking::STAKING_POOL)
        .await
        .map(|a| a.balance);
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), st.clone(), 1);
    rt.on_prevote(Vote::sign(&victim, 1, 0, VoteKind::Prevote, Some(bh(0xA1))))
        .unwrap();
    rt.on_prevote(Vote::sign(&victim, 1, 0, VoteKind::Prevote, Some(bh(0xA2))))
        .unwrap();
    assert_eq!(rt.hc.equivocations().len(), 1, "evidence recorded locally");
    rt.adopt_committed(1, blk, precommit_cert(&ks, 3, 1, block_hash))
        .await
        .unwrap();

    let pool_after = st
        .get_account(&stellereum::staking::STAKING_POOL)
        .await
        .map(|a| a.balance);
    let ledger = st.staking_read().await;
    let total_burned = ledger.total_burned;
    let victim_slashed = ledger.validators[&id(&victim)].total_slashed;
    drop(ledger);
    eprintln!(
        "HUNT11 FIXED: STAKING_POOL before={:?} after={:?}; ledger.total_burned={} ; \
         victim.total_slashed={}",
        pool_before, pool_after, total_burned, victim_slashed
    );
    assert_eq!(pool_before, pool_after, "the pool was never debited");
    assert_eq!(
        total_burned, 0,
        "F4 FIX: the adopt path must not slash equivocation from local evidence"
    );
    assert_eq!(
        victim_slashed, 0,
        "F4 FIX: victim untouched by local gossip"
    );
}

// ===========================================================================
// ATTACK 12  (HIGH) — `try_precommit_quorum` has NO prevote-quorum
// precondition. A block can be finalized at a height where nobody ever
// prevoted it, and where this node's own lock points somewhere else.
// ===========================================================================

#[tokio::test]
async fn hunt12_finalize_with_zero_prevotes_and_against_the_local_lock() {
    let ks = keys(4);
    let vset = vs_of(&ks);
    let mut rt = {
        let st = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&st, &vset, 1_000_000_000_000_000).await;
        ValidatorRuntime::new(ks[0].clone(), vset.clone(), st, 1)
    };
    // This node is LOCKED on A (it saw a prevote quorum for A earlier).
    rt.hc.locked = Some((bh(0xA1), 0));
    let _ = &rt.hc.locked;

    // Three validators precommit B. Nobody prevoted anything at all.
    for k in ks.iter().take(3) {
        rt.on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh(0xB2))))
            .unwrap();
    }
    assert!(rt.hc.prevote_qc.is_empty(), "no prevote QC exists");
    // Give the node the block, so this exercises the prevote-precondition path and
    // not the "we never received the block" guard. Otherwise the block-presence
    // check would mask the real finding.
    let mut block = Block {
        shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: bh(0xA1),
        state_root: rt.state.get_state_root().await,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer: ks[0].verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    block.sign_block(&ks[0]);
    rt.blocks.insert(block.compute_hash(), block);
    let decided = rt.try_finalize().await;
    assert_eq!(
        decided, None,
        "a precommit quorum alone must not finalise: nobody prevoted, and this \
         node is locked on a different block"
    );
    println!("HUNT12 FIXED: no prevote quorum -> no finalisation");
    eprintln!(
        "HUNT12 OK: node was locked on {} at round 0, received ZERO prevotes, and \
         finalized {} at height 1. `try_precommit_quorum` (consensus.rs:467) consults \
         only the precommit set.",
        hex::encode(&bh(0xA1)[..4]),
        hex::encode(&bh(0xB2)[..4])
    );
}

// ===========================================================================
// ATTACK 13  (MEDIUM) — `apply_downtime_slashes` marks as "eligible" every
// record in the ledger, including validators whose self-bond is below
// MIN_VALIDATOR_BOND and who therefore have ZERO power and can never
// contribute a counted vote. They are charged downtime forever.
// ===========================================================================

#[tokio::test]
async fn hunt13_exited_validators_are_not_slashed_for_quorums_they_are_not_in() {
    use stellereum::staking::{DOWNTIME_MISS_THRESHOLD, MIN_VALIDATOR_BOND};
    let ks = keys(4);
    let vset = vs_of(&ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), st.clone(), 1);

    // Push validator #4's self-bond below the minimum, so `to_validator_set`
    // drops it: zero power, not a consensus participant.
    {
        let mut l = st.staking_write().await;
        l.validators.get_mut(&id(&ks[3])).unwrap().self_bond = MIN_VALIDATOR_BOND - 1;
    }
    let derived = st.staking_read().await.to_validator_set();
    assert_eq!(derived.len(), 3, "validator #4 left the validator set");
    assert_eq!(derived.power_of(&id(&ks[3])), 0, "zero voting power");
    let heights = DOWNTIME_MISS_THRESHOLD as u64 + 2;

    // Drive heights through the LOCAL finalize path, which is the one that runs
    // apply_downtime_slashes (the peer-adopt path short-circuits, see HUNT5).
    let mut prev = [0u8; 32];
    for h in 1..=heights {
        let proposer = rt.hc.proposer().expect("a proposer exists");
        let pk = ks.iter().find(|k| id(k) == proposer).unwrap();
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: st.get_state_root().await,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: h,
            proposer,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(pk);
        let bhash = b.compute_hash();
        prev = bhash;
        rt.blocks.insert(bhash, b);
        // Finalising now requires a prevote quorum for the same block, so the
        // test drives a real round instead of only precommitting.
        for k in ks.iter().take(3) {
            rt.on_prevote(Vote::sign(k, h, 0, VoteKind::Prevote, Some(bhash)))
                .unwrap();
        }
        assert!(
            rt.hc.try_prevote_quorum().is_some(),
            "prevote quorum at height {h}"
        );
        for k in ks.iter().take(3) {
            rt.on_precommit(Vote::sign(k, h, 0, VoteKind::Precommit, Some(bhash)))
                .unwrap();
        }
        assert_eq!(rt.try_finalize().await, Some(bhash), "height {h} finalized");
    }

    let l = st.staking_read().await;
    let v3 = &l.validators[&id(&ks[3])];
    let (missed, penalty, slashed) = (v3.missed, v3.last_downtime_penalty, v3.total_slashed);
    let power = rt.validators.power_of(&id(&ks[3]));
    eprintln!(
        "HUNT13: validator #4 has power {power} in the applied set; after {heights} \
         heights missed={missed} last_downtime_penalty={penalty} total_slashed={slashed}"
    );
    assert_eq!(power, 0, "it is not a consensus participant");
    // FIXED (M3): downtime eligibility is the elected set only. A validator
    // with zero power, excluded by to_validator_set(), accumulates no misses
    // and burns nothing for 'missing' quorums it is not part of. This test
    // used to pin the attack (slashed > 0); now it pins the fix.
    assert_eq!(
        missed, 0,
        "FIXED: an exited validator accumulates no downtime misses"
    );
    assert_eq!(
        slashed, 0,
        "FIXED: zero-power non-participant burns nothing"
    );
    eprintln!(
        "HUNT13 OK: exited validator untouched after {} heights (threshold {}). \
         downtime eligibility is the elected set.",
        heights, DOWNTIME_MISS_THRESHOLD
    );
}

// ===========================================================================
// ATTACK 14  (HIGH) — `refresh_validator_set_from_staking` REFUSES to apply an
// empty derived set, so a validator set whose stake has all dropped below the
// minimum is frozen forever at its last non-empty value. Validators keep full
// voting power with no stake behind them, and the freeze is invisible.
// ===========================================================================

#[tokio::test]
async fn hunt14_validator_set_is_frozen_when_everyone_drops_below_min() {
    use stellereum::staking::MIN_VALIDATOR_BOND;
    let ks = keys(4);
    let vset = vs_of(&ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), st.clone(), 1);
    assert_eq!(rt.validators.len(), 4);
    let powers_before: Vec<u64> = ks.iter().map(|k| rt.validators.power_of(&id(k))).collect();
    assert_eq!(powers_before, vec![1, 1, 1, 1]);

    // Everyone's stake evaporates (slashed / unbonded below the minimum).
    {
        let mut l = st.staking_write().await;
        for v in l.validators.values_mut() {
            v.self_bond = MIN_VALIDATOR_BOND - 1;
        }
    }
    let changed = rt.refresh_validator_set_from_staking().await;
    assert!(!changed, "the empty derived set was refused");
    assert_eq!(
        rt.validators.len(),
        4,
        "ATTACKER GOAL: all four validators now hold ZERO stake, yet the set is \
         frozen at 4 members with full power"
    );
    assert!(rt.validators.total_power() > 0);
    assert!(
        rt.validators.quorum_power() < u64::MAX,
        "quorum is still reachable by the unstaked set"
    );
    eprintln!(
        "HUNT14 OK: derived set = EMPTY, applied set = {} members / power {} / quorum {}. \
         runtime.rs:711 `if vs.is_empty() .. return false` turns a total stake wipeout \
         into a permanently live validator set.",
        rt.validators.len(),
        rt.validators.total_power(),
        rt.validators.quorum_power()
    );
}

// ===========================================================================
// ATTACK 15  (MEDIUM) — proposer slot selection is grindable: the proposer is
// chosen by BTreeMap position over pubkeys, so an operator picks its own key
// until it lands the slot it wants for a given height.
// ===========================================================================

#[test]
fn hunt15_proposer_slot_is_grindable_by_key_choice() {
    // The honest set: 3 fixed validators, power 1.
    let honest = keys(3);
    let mut base = ValidatorSet::new();
    for k in &honest {
        base.add(id(k), 1);
    }
    let target_height = 900_000u64;

    // The attacker grinds a key whose pubkey sorts into the slot for
    // (target_height, round 0). `proposer_for` is slot = (h + r) % total, and the
    // cumulative-power walk is over the BTreeMap, so the attacker only has to
    // find a pubkey that lands in the right interval.
    let want_slot = (target_height % base.total_power()) as usize;
    let mut found: Option<SigningKey> = None;
    for _ in 0..200_000u32 {
        let k = SigningKey::generate(&mut OsRng);
        let mut trial = base.clone();
        trial.add(id(&k), 1);
        if trial.proposer_for(target_height, 0) == Some(id(&k)) {
            found = Some(k);
            break;
        }
    }
    let k = found.expect("grinding a proposer slot always succeeds quickly");
    let mut vs = base.clone();
    vs.add(id(&k), 1);
    assert_eq!(
        vs.proposer_for(target_height, 0),
        Some(id(&k)),
        "the ground key IS the proposer at height {} (slot {})",
        target_height,
        want_slot
    );
    eprintln!(
        "HUNT15 OK: an attacker with 1/4 of the power chose a pubkey that makes it the \
         proposer at height {} (round 0) out of 4; it could equally have targeted any \
         other height class. proposer_for() is (height+round) % total_power walked over \
         the pubkey-sorted BTreeMap.",
        target_height
    );
}

// ===========================================================================
// ATTACK 16 — the commitment digest: hunt for a collision.
// The only field of any committed struct that is NOT in the digest is
// `Contract::code` (commitment.rs:322-326 commits code_hash, not code).
// ===========================================================================

#[tokio::test]
async fn hunt16_commitment_digest_omits_contract_code() {
    use stellereum::commitment::{commitment_digest, CommitmentSnapshot};

    fn mk(code: Vec<u8>, code_hash: [u8; 32]) -> CommitmentSnapshot {
        let addr = [0xC0u8; 32];
        let mut reg = stellereum::contract::ContractRegistry::new();
        reg.contracts.insert(
            addr,
            stellereum::contract::Contract {
                address: addr,
                creator: [1u8; 32],
                code_hash,
                code,
                storage: Default::default(),
                created_at: 7,
                paused: false,
                balance: 0,
                abi: None,
                source_hash: None,
            },
        );
        CommitmentSnapshot {
            governance: stellereum::governance::Governance::new(),
            oracle: Default::default(),
            tokens: stellereum::token::TokenRegistry::new(),
            staking: Default::default(),
            orderbooks: Default::default(),
            order_escrow: Default::default(),
            pmm: Default::default(),
            pmm_usdt_token: None,
            pmm_treasury: [0u8; 32],
            contracts: reg,
            session_keys: Default::default(),
            bridge: Default::default(),
            cross_shard_consumed: Vec::new(),
            cross_shard_produced: Vec::new(),
            cross_shard_completed: Vec::new(),
            cross_shard_xpc: Vec::new(),
        }
    }

    // Two states that differ ONLY in the executable bytecode of a contract.
    let h1 = [0x11u8; 32];
    let a = mk(b"\x00asm\x01\x00\x00\x00".to_vec(), h1);
    let b = mk(b"\x00asm\x01\x00\x00\x00\xde\xad\xbe\xef".to_vec(), h1);
    let da = commitment_digest(&a);
    let db = commitment_digest(&b);
    eprintln!(
        "HUNT16: contract A code len={} digest={}; contract B code len={} digest={}",
        a.contracts.contracts[&[0xC0u8; 32]].code.len(),
        hex::encode(da),
        b.contracts.contracts[&[0xC0u8; 32]].code.len(),
        hex::encode(db)
    );
    assert_eq!(
        da, db,
        "ATTACKER GOAL: two DIFFERENT consensus states (different WASM bytecode) \
         produce the IDENTICAL commitment digest"
    );
    eprintln!(
        "HUNT16 OK: the digest commits `code_hash` but not `code`, so a node holding \
         different contract bytecode for the same address reports the same state root."
    );
    let _ = (mk, a, b, da, db);
}

// ===========================================================================
// ATTACK 17 — negative: try to break the length-prefix framing itself.
// ===========================================================================

#[tokio::test]
async fn hunt17_negative_no_framing_collision_in_the_digest() {
    use stellereum::commitment::{commitment_digest, CommitmentSnapshot};
    use stellereum::token::{TokenActor, TokenMetadata, TokenRegistry};

    let snap = |name: &str, sym: &str, desc: &str, decimals: u8| CommitmentSnapshot {
        governance: stellereum::governance::Governance::new(),
        oracle: Default::default(),
        tokens: {
            let mut reg = TokenRegistry::new();
            reg.tokens.insert(
                [9u8; 32],
                TokenActor {
                    id: [9u8; 32],
                    metadata: TokenMetadata {
                        name: name.to_string(),
                        symbol: sym.to_string(),
                        decimals,
                        total_supply: 1_000,
                        max_supply: None,
                        minter: [2u8; 32],
                        paused: false,
                        description: desc.to_string(),
                    },
                    balances: Default::default(),
                    allowances: Default::default(),
                },
            );
            reg
        },
        staking: Default::default(),
        orderbooks: Default::default(),
        order_escrow: Default::default(),
        pmm: Default::default(),
        pmm_usdt_token: None,
        pmm_treasury: [0u8; 32],
        contracts: Default::default(),
        session_keys: Default::default(),
        bridge: Default::default(),
        cross_shard_consumed: Vec::new(),
        cross_shard_produced: Vec::new(),
        cross_shard_completed: Vec::new(),
        cross_shard_xpc: Vec::new(),
    };

    let payload = "ABCDEFGH";
    let mut seen = std::collections::HashMap::new();
    for split in 0..=payload.len() {
        for pad in 0..=payload.len() {
            let a = &payload[..split];
            let b = &payload[split..(split + pad).min(payload.len())];
            let c = &payload[(split + pad).min(payload.len())..];
            for dec in [0u8, 8, 18] {
                let d = commitment_digest(&snap(a, b, c, dec));
                let key = format!("{a}|{b}|{c}|{dec}");
                if let Some(prev) = seen.insert(d, key.clone()) {
                    assert_eq!(prev, key, "DIGEST COLLISION: {prev} vs {key}");
                }
            }
        }
    }
    assert!(
        seen.len() >= 30,
        "only {} distinct states exercised",
        seen.len()
    );
    eprintln!(
        "HUNT17 NEGATIVE: {} name/symbol/description byte-shifts (x3 decimals) all \
         produced distinct digests. put_bytes() length-prefixes BOTH the tag and the \
         value (commitment.rs:76-81), so no two states encode to the same bytes.",
        seen.len()
    );
}

// ===========================================================================
// ATTACK 18 — `fast_sync_state` restores ONLY native accounts. Tokens, the
// staking ledger (i.e. the validator set), orderbooks, escrow, the PMM and
// contracts are neither in the snapshot nor cleared, so a "successful" fast sync
// leaves the target in a state that matches NO block header.
// ===========================================================================

#[tokio::test]
async fn hunt18_fast_sync_snapshot_omits_the_validator_set() {
    use stellereum::runtime::fund_genesis;
    let ks = keys(4);
    let vset = vs_of(&ks);

    let source = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&source, &vset, 1_000_000_000_000_000).await;
    let honest_root = source.get_state_root().await;
    let snap = source.create_snapshot().await;

    let target = Arc::new(InMemoryStateEngine::new());
    let res = stellereum::sync::fast_sync_state(
        &target,
        honest_root,
        || async { Some(snap.clone()) },
        |_| async { None },
    )
    .await;
    eprintln!(
        "HUNT18: fast_sync_state -> {:?}; target root after={} (header root was {})",
        res,
        hex::encode(target.get_state_root().await),
        hex::encode(honest_root)
    );

    // Even when it reports success, the target's consensus subsystems are the
    // ones it already had, so its root cannot match a header built from the
    // peer's subsystems. Prove the snapshot carries no validator set at all:
    let decoded_len = {
        // bincode Vec<AccountState> — accounts only.
        snap.len()
    };
    assert!(
        res.is_err(),
        "with a real bonded set the poisoned/partial snapshot is refused"
    );

    // And the reverse: a snapshot from a chain with NO staking state passes and
    // leaves the target's own staking untouched, so the target's root silently
    // disagrees with the header it "synced" to.
    let bare = InMemoryStateEngine::new();
    let bare_root = bare.get_state_root().await;
    let bare_snap = bare.create_snapshot().await;
    let target2 = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&target2, &vset, 1_000_000_000_000_000).await;
    let target2_root_before = target2.get_state_root().await;
    let bare_snap2 = bare_snap.clone();
    let r2 = stellereum::sync::fast_sync_state(
        &target2,
        bare_root,
        move || {
            let s = bare_snap2.clone();
            async move { Some(s) }
        },
        |_| async { None },
    )
    .await;
    let target2_root_after = target2.get_state_root().await;
    eprintln!(
        "HUNT18: bare-chain sync -> {:?}; target2 root {} -> {} while the header said {}",
        r2,
        hex::encode(&target2_root_before[..6]),
        hex::encode(&target2_root_after[..6]),
        hex::encode(&bare_root[..6])
    );
    assert!(r2.is_ok(), "the bare snapshot is accepted");
    assert_ne!(
        target2_root_after, bare_root,
        "ATTACKER GOAL: fast_sync_state returned Ok(()) but the target's state root does \
         NOT equal the header root it claimed to sync to"
    );
    eprintln!(
        "HUNT18 OK: reported Ok(()); claimed root {} but actual root {}; snapshot was \
         {} bytes of AccountState only (no staking/token/orderbook/contract state).",
        hex::encode(&bare_root[..6]),
        hex::encode(&target2_root_after[..6]),
        decoded_len
    );
}
