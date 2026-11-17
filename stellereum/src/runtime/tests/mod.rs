use super::*;
use crate::consensus::{Vote, VoteKind};
use crate::sharding::MASTERCHAIN_SHARD;
use crate::state_engine::AccountState;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[tokio::test]
async fn c2_timed_validation_verdict_identical_and_stages_named() {
    // TASK 5: timed path must accept/refuse EXACTLY like the untimed path,
    // while naming the slow stage.
    let key = SigningKey::generate(&mut OsRng);
    let me = key.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(me, 1)]);
    let mut rt = ValidatorRuntime::new(key, validators, funded_state(me).await, 1);
    let root = rt.state.get_state_root().await;
    let mut block = rt.propose(1_700_000_001).await.expect("propose");
    block.state_root = root;
    let plain = rt.validate_proposal_unaligned(&block, root);
    let (timed, stages) = rt.validate_proposal_timed(&block, root);
    assert_eq!(plain.is_ok(), timed.is_ok(), "verdicts must agree");
    let names: Vec<&str> = stages.iter().map(|(s, _)| s.as_str()).collect();
    for want in [
        "proposer_sig_verify",
        "state_root_check",
        "order_commit",
        "tx_batch_verify",
        "fee_floor_mempool",
    ] {
        assert!(
            names.contains(&want),
            "stage {want} must be attributed, got {names:?}"
        );
    }
    // A corrupt block is refused by BOTH paths identically.
    let mut bad = block.clone();
    bad.state_root = [0xFF; 32];
    assert!(rt.validate_proposal_unaligned(&bad, root).is_err());
    let (timed_bad, _) = rt.validate_proposal_timed(&bad, root);
    assert!(timed_bad.is_err());
}

#[tokio::test]
async fn c2_slow_validation_meter_and_log_name_slow_stage() {
    let key = SigningKey::generate(&mut OsRng);
    let me = key.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(me, 1)]);
    let mut rt = ValidatorRuntime::new(key, validators, funded_state(me).await, 1);
    assert_eq!(rt.slow_validation_total, 0);
    // Fast validation: no meter.
    rt.note_validation_timing(&[
        ("proposer_sig_verify".into(), 5),
        ("tx_batch_verify".into(), 10),
    ]);
    assert_eq!(rt.slow_validation_total, 0);
    // Slow validation: meter + names the slow stage (trie vs sigs vs mempool).
    rt.note_validation_timing(&[
        ("proposer_sig_verify".into(), 20),
        ("state_root_check".into(), 900),
        ("tx_batch_verify".into(), 30),
        ("fee_floor_mempool".into(), 10),
    ]);
    assert_eq!(rt.slow_validation_total, 1);
    assert_eq!(rt.validation_last_stages.len(), 4);
    let slowest = rt
        .validation_last_stages
        .iter()
        .max_by_key(|(_, ms)| *ms)
        .unwrap();
    assert_eq!(slowest.0, "state_root_check");
}

/// C2 ACCEPTANCE: 4-node harness (live-like powers C1470/B1999/A1999/D2000,
/// quorum 4980 of 7468) with ONE 5x-slow member (D) finalizes 20
/// consecutive blocks with <= 2 view-changes per block.
///
/// The slow member's proposal arrives one round late (it cannot keep a
/// 3.5s round on 1 vCPU): the first round for its slots times out nil,
/// the adaptive deterministic timeout then covers the late arrival and
/// the NEXT round finalizes. Every other proposer's slot finalizes in
/// round 0. This exercises the real `propose` / `on_proposal` /
/// prevote / precommit / `try_finalize` paths on every node, not a stub.
#[tokio::test]
async fn c2_acceptance_20_blocks_one_slow_member_max_2_view_changes() {
    // Deterministic keys: same harness, same schedule, every run.
    let seeds: [u8; 4] = [0x0C, 0x0B, 0x0A, 0x0D]; // C, B, A, D
    let powers: [u64; 4] = [1470, 1999, 1999, 2000];
    let keys: Vec<SigningKey> = seeds
        .iter()
        .map(|s| SigningKey::from_bytes(&[*s; 32]))
        .collect();
    let ids: Vec<ValidatorId> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let slow_id = ids[3]; // D: largest power, 1 vCPU, historically nil-voting
    let validators = ValidatorSet::from_list(
        ids.iter()
            .zip(powers.iter())
            .map(|(id, p)| (*id, *p))
            .collect(),
    );
    assert_eq!(validators.total_power(), 7468);
    assert_eq!(validators.quorum_power(), 4979); // floor(2*7468/3)+1
    assert!(
        7468 - 2000 >= validators.quorum_power(),
        "any single nil-voter is survivable"
    );
    assert!(
        2000 + 1999 < validators.quorum_power(),
        "any TWO nil-voters stall (needs >=3 of 4)"
    );

    let mut nodes: Vec<ValidatorRuntime> = Vec::new();
    for (i, k) in keys.iter().enumerate() {
        let st = Arc::new(InMemoryStateEngine::new());
        crate::runtime::fund_genesis(&st, &validators, 1_000_000).await;
        // FULL-PQ: votes only verify with a Falcon half, so every node
        // carries a persisted Falcon key (deterministic per test).
        let fk = FalconKeypair::generate_from_seed(0xC0 + i as u8);
        let mut rt =
            ValidatorRuntime::new(k.clone(), validators.clone(), st, 1).with_falcon_key(fk);
        rt.hc.set_parent_hash([0u8; 32]);
        nodes.push(rt);
    }
    // Sanity: deterministic timeout really does extend slow-proposer rounds.
    let base = 3500u64;
    assert!(crate::consensus::deterministic_round_timeout_ms(base, 0, 4) > base);

    let mut table: Vec<(u64, u32)> = Vec::new(); // (height, view_changes)
    let mut ts: u64 = 1_700_000_000;
    for h in 1u64..=20 {
        ts += 1;
        debug_assert!(
            nodes.iter().all(|n| n.hc.height == h),
            "heights must stay in lockstep"
        );
        let mut view_changes: u32 = 0;
        // If the slot proposer is the slow member, burn exactly ONE nil
        // round first (its 5x-slow proposal cannot land in time), then
        // finalize in the next round under the adaptive timeout.
        let proposer0 = nodes[0]
            .hc
            .validators
            .proposer_for(h, nodes[0].hc.round)
            .unwrap();
        let slow_slot = proposer0 == slow_id;
        if slow_slot {
            for n in nodes.iter_mut() {
                n.next_round(); // classified nil + proposer-miss inside hc
            }
            view_changes += 1;
        }
        // Propose at the (possibly advanced) round.
        let r = nodes[0].hc.round;
        let pidx = nodes
            .iter()
            .position(|n| n.validators.proposer_for(h, r) == Some(n.id))
            .expect("proposer");
        let block = nodes[pidx]
            .propose(ts)
            .await
            .expect("proposer failed to propose");
        let bh = block.compute_hash();
        let pid = nodes[pidx].id;
        for (i, n) in nodes.iter_mut().enumerate() {
            if i != pidx {
                n.on_proposal(pid, block.clone(), r)
                    .await
                    .expect("proposal rejected");
            }
        }
        let prevotes: Vec<Vote> = nodes.iter().filter_map(|n| n.make_prevote()).collect();
        assert!(!prevotes.is_empty());
        for v in &prevotes {
            for n in nodes.iter_mut() {
                let _ = n.on_prevote(v.clone());
            }
        }
        let precommits: Vec<Vote> = nodes
            .iter_mut()
            .filter_map(|n| n.make_precommit())
            .collect();
        assert!(
            !precommits.is_empty(),
            "polka must yield precommits at h={h}"
        );
        for v in &precommits {
            for n in nodes.iter_mut() {
                let _ = n.on_precommit(v.clone());
            }
        }
        for n in nodes.iter_mut() {
            let got = n.try_finalize().await;
            assert_eq!(got, Some(bh), "all 4 nodes must finalize h={h}");
        }
        assert!(
            view_changes <= 2,
            "h={h}: {} view changes (>2)",
            view_changes
        );
        table.push((h, view_changes));
    }
    // Measured acceptance table (also printed for the report).
    println!("C2 ACCEPTANCE heights/rounds-per-block (slow=D 5x):");
    for (h, vc) in &table {
        println!("height={h} view_changes={vc}");
    }
    assert_eq!(table.len(), 20);
    assert!(table.iter().all(|(_, vc)| *vc <= 2));
    let slow_slots = table.iter().filter(|(_, vc)| *vc == 1).count();
    assert!(
        slow_slots >= 1,
        "the slow member must own slots in 20 heights (hash schedule)"
    );
}

async fn funded_state(owner: [u8; 32]) -> Arc<InMemoryStateEngine> {
    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(AccountState::new(owner, 10_000_000))
        .await;
    st
}

/// P3-CLOCK: the deterministic timestamp gate (`check_block_timestamp`)
/// is monotone vs the parent and bounded +1h ahead. A Byzantine proposer
/// with a skewed clock can fast-forward VM time (unbonding, sessions,
/// dispute windows) only inside this envelope -- never backwards, never
/// by more than one jump per block, never past an unknown parent.
fn gate_block(height: u64, prev: [u8; 32], ts: u64, proposer: [u8; 32]) -> Block {
    Block {
        shard_id: crate::sharding::MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: ts,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        cnvrf_v3: None,
    }
}

#[tokio::test]
async fn p3_timestamp_gate_monotone_and_bounded() {
    let key = SigningKey::generate(&mut OsRng);
    let me = key.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(me, 1)]);
    let mut rt = ValidatorRuntime::new(key, validators, funded_state(me).await, 2);

    // Parent at height 1 with timestamp 1_000_000.
    let parent = gate_block(1, [0u8; 32], 1_000_000, me);
    let parent_hash = parent.compute_hash();
    rt.blocks.insert(parent_hash, parent);

    // Same timestamp: monotone OK.
    assert!(rt
        .check_block_timestamp(&gate_block(2, parent_hash, 1_000_000, me))
        .is_ok());
    // Exactly one max jump ahead: OK (the envelope's edge).
    assert!(rt
        .check_block_timestamp(&gate_block(
            2,
            parent_hash,
            1_000_000 + MAX_TIMESTAMP_JUMP_SECS,
            me
        ))
        .is_ok());
    // One second past the envelope: refused.
    assert!(rt
        .check_block_timestamp(&gate_block(
            2,
            parent_hash,
            1_000_000 + MAX_TIMESTAMP_JUMP_SECS + 1,
            me
        ))
        .is_err());
    // Backwards: refused.
    assert!(rt
        .check_block_timestamp(&gate_block(2, parent_hash, 999_999, me))
        .is_err());
    // Missing timestamp: refused.
    assert!(rt
        .check_block_timestamp(&gate_block(2, parent_hash, 0, me))
        .is_err());
    // Unknown parent: fail-closed, never skipped.
    assert!(rt
        .check_block_timestamp(&gate_block(2, [0xEE; 32], 1_000_000, me))
        .is_err());
}

#[tokio::test]
async fn p3_timestamp_gate_genesis_anchor() {
    let key = SigningKey::generate(&mut OsRng);
    let me = key.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(me, 1)]);
    let rt = ValidatorRuntime::new(key, validators, funded_state(me).await, 1);
    // Height 1 off the zero parent: any non-zero timestamp is past the
    // anchor (the forward-jump bound does not apply to genesis).
    assert!(rt
        .check_block_timestamp(&gate_block(1, [0u8; 32], 1_700_000_000, me))
        .is_ok());
    assert!(rt
        .check_block_timestamp(&gate_block(1, [0u8; 32], 0, me))
        .is_err());
}

/// Regression: the RPC layer and the consensus loop once had SEPARATE
/// mempools, so a transaction submitted over RPC was never selected by the
/// proposer (it was only ever filled from the P2P overlay) and on a
/// single-validator node it was never included at all. A shared mempool
/// makes a submitted transaction the same object the proposer picks up.
#[tokio::test]
async fn rpc_mempool_is_the_mempool_the_proposer_uses() {
    let key = SigningKey::generate(&mut OsRng);
    let me = key.verifying_key().to_bytes();
    // FULL-PQ: the sender is a Falcon-512 identity; the classical
    // `Transaction::sign` fixture is refused at admission.
    const SENDER_SEED: u8 = 0xA1;
    let state = pq_funded_state(SENDER_SEED, 10_000_000).await;
    let validators = ValidatorSet::from_list(vec![(me, 1)]);

    // This is the handle the RPC layer writes to.
    let shared = Arc::new(tokio::sync::RwLock::new(crate::mempool::Mempool::default()));
    let rt = ValidatorRuntime::new(key.clone(), validators, state, 1).with_mempool(shared.clone());

    let tx = pq_tx(SENDER_SEED, [1u8; 32], 10, 1_000, 0);
    let balance = rt
        .state
        .get_account(&tx.from)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);

    // Submit exactly the way the RPC handler does...
    shared
        .write()
        .await
        .add_checked(tx.clone(), balance)
        .unwrap();
    assert_eq!(
        shared.read().await.len(),
        1,
        "the RPC's mempool must hold it"
    );

    // ...and the proposer must select that very same transaction.
    let selected = rt.mempool.read().await.select_bounded(100, 30_000_000);
    assert_eq!(
        selected.len(),
        1,
        "proposer must see the transaction submitted over RPC"
    );
    assert_eq!(selected[0].compute_tx_hash(), tx.compute_tx_hash());

    // And a confirmed transaction leaves both views empty.
    rt.mempool
        .write()
        .await
        .prune_confirmed(&[tx.compute_tx_hash()]);
    assert!(rt.mempool.read().await.is_empty());
    assert!(
        shared.read().await.is_empty(),
        "RPC view must not keep a confirmed tx"
    );
}

#[test]
fn missing_sender_accounts_names_exactly_the_race_arrivals() {
    // Pure helper for the r0-fullness refresh: only senders the snapshot
    // missed are returned, in pool order, deterministically.
    let mut snap = std::collections::HashMap::new();
    snap.insert([1u8; 32], (0u64, 100u64));
    let pool = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    assert_eq!(
        missing_sender_accounts(&snap, &pool),
        vec![[2u8; 32], [3u8; 32]]
    );
    assert!(missing_sender_accounts(&snap, &[[1u8; 32]]).is_empty());
    assert!(missing_sender_accounts(&std::collections::HashMap::new(), &[]).is_empty());
}

#[tokio::test]
async fn demanded_demand_survives_transient_revalidation_failure() {
    // Lock-hint rescue liveness: a demand must be consumed exactly once —
    // on successful serve — never on a failed re-validation. Dropping it
    // on a transient failure costs a full hint round-trip (the peer only
    // re-hints on its next nil prevote) while the round keeps timing out.
    let valkey = SigningKey::generate(&mut OsRng);
    let me = valkey.verifying_key().to_bytes();
    let peer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(me, 1), (peer, 1)]);
    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(AccountState::new(me, 100_000_000)).await;
    // Falconize the proposer: production `propose` pushes BOTH halves,
    // and serve-time re-validation refuses Ed-only blocks.
    let fk = FalconKeypair::generate_from_seed(0xB1);
    let mut rt = ValidatorRuntime::new(valkey.clone(), validators, st, 1).with_falcon_key(fk);
    while rt.hc.proposer() != Some(me) {
        rt.next_round();
    }
    let body = rt.propose(1_000).await.expect("proposer must propose");
    let h = body.compute_hash();
    // Reopen the propose gate (the fresh path self-recorded a proposal).
    rt.hc.proposal = None;
    // The peer is stuck on our body and says so with a nil prevote hint.
    rt.note_lock_hint(rt.hc.height, VoteKind::Prevote, None, Some(h));
    assert!(rt.demanded.contains(&h), "hint must record the demand");
    // Corrupt the stored copy so the serve-time re-validation fails.
    rt.blocks
        .get_mut(&h)
        .expect("body must be stored")
        .state_root = [9u8; 32];
    rt.hc.proposal = None;
    let _ = rt.propose(1_000).await;
    assert!(
        rt.demanded.contains(&h),
        "transient re-validation failure must not consume the demand"
    );
    // Repair the stored copy: the still-queued demand serves exactly once.
    let root = rt.state.get_state_root().await;
    rt.blocks
        .get_mut(&h)
        .expect("body must be stored")
        .state_root = root;
    rt.hc.proposal = None;
    let served = rt.propose(1_000).await.expect("repaired demand must serve");
    assert_eq!(
        served.compute_hash(),
        h,
        "must re-propose the demanded body verbatim"
    );
    assert!(
        rt.demanded.is_empty(),
        "successful serve consumes the demand one-shot"
    );
}

/// The `lock_hint` envelope is SIGNATURE-EXTERNAL (review dim 5): it
/// rides beside the vote in `ConsensusMsg::Vote { vote, locked }` and is
/// NOT covered by `vote_sign_bytes`, so anyone can attach any hash to
/// anyone's nil prevote. This pins the mitigations that keep that safe:
/// only same-height nil prevotes naming OUR OWN height-H bodies are
/// recorded (anything else — foreign bodies, value votes, precommits,
/// wrong heights — is dropped), the set is bounded (8) and
/// height-scoped, and serving re-validates the body before proposing it
/// (pinned by `demanded_demand_survives_transient_revalidation_failure`).
/// A forged hint can therefore at most make us re-propose our own
/// already-validated body — a wasted proposal, never a fork and never a
/// foreign body under our slot.
#[tokio::test]
async fn lock_hint_envelope_is_untrusted_and_mitigated() {
    let valkey = SigningKey::generate(&mut OsRng);
    let me = valkey.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(me, 1)]);
    let mut rt = ValidatorRuntime::new(valkey.clone(), validators, funded_state(me).await, 1);
    assert!(rt.is_proposer());

    // One genuine own body at this height.
    let body = rt.propose(1_000).await.expect("sole proposer must propose");
    let ours = body.compute_hash();
    rt.hc.proposal = None;
    let h = rt.hc.height;

    // A forged hint for a FOREIGN body (never authored, never held) is
    // dropped: serving it would re-propose somebody else's block under
    // OUR slot, which every receiver rejects.
    rt.note_lock_hint(h, VoteKind::Prevote, None, Some([0xF0; 32]));
    assert!(rt.demanded.is_empty(), "foreign-body hints must be dropped");

    // A hint on a VALUE vote (not nil) is dropped: only nil prevotes
    // carry rescue requests.
    rt.note_lock_hint(h, VoteKind::Prevote, Some(ours), Some(ours));
    assert!(rt.demanded.is_empty(), "value-vote hints must be dropped");

    // A hint on a PRECOMMIT is dropped: rescue rides nil prevotes only.
    rt.note_lock_hint(h, VoteKind::Precommit, None, Some(ours));
    assert!(rt.demanded.is_empty(), "precommit hints must be dropped");

    // A hint for a WRONG height is dropped (and must not wipe this
    // height's demands — the scope reset only runs for the live height).
    rt.note_lock_hint(h, VoteKind::Prevote, None, Some(ours));
    assert!(
        rt.demanded.contains(&ours),
        "genuine hint must record the demand"
    );
    rt.note_lock_hint(h + 1, VoteKind::Prevote, None, Some(ours));
    assert!(
        rt.demanded.contains(&ours),
        "wrong-height hints must neither record nor wipe live demands"
    );
    rt.demanded.clear();

    // The genuine shape records.
    rt.note_lock_hint(h, VoteKind::Prevote, None, Some(ours));
    assert!(rt.demanded.contains(&ours));
    rt.demanded.clear();

    // The set is bounded: 9 distinct own bodies, 8 slots. Build them by
    // proposing across rounds (each propose stores its body; the
    // timestamp varies so the bodies hash distinctly).
    let mut bodies = vec![ours];
    for i in 1..9u64 {
        rt.next_round();
        rt.hc.proposal = None;
        let b = rt.propose(1_000 + i).await.expect("must keep proposing");
        bodies.push(b.compute_hash());
        rt.hc.proposal = None;
    }
    assert_eq!(bodies.len(), 9);
    for bh in &bodies {
        rt.note_lock_hint(h, VoteKind::Prevote, None, Some(*bh));
    }
    assert_eq!(
        rt.demanded.len(),
        8,
        "hint spam must not grow the demand set without bound"
    );
}

#[tokio::test]
async fn r0_proposal_packs_the_full_available_mempool_deterministically() {
    // Regression for the live partial-then-retry shape (r0 52tx, r2 200tx
    // from the same pool): the proposer must pack everything available at
    // select time, and rebuilding must yield the identical set.
    //
    // NOTE on scale: sequences are 10 deep per sender; the pass budget
    // lives in mempool.rs (`select_for_block_multi`, 64 passes) — an
    // adversarial fee-hash order completes one nonce per pass per sender,
    // so only chains deeper than 64 per sender select partially. This test
    // pins the proposer-side contract.
    let valkey = SigningKey::generate(&mut OsRng);
    let me = valkey.verifying_key().to_bytes();
    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(AccountState::new(me, 100_000_000)).await;
    let validators = ValidatorSet::from_list(vec![(me, 1)]);
    let mut rt = ValidatorRuntime::new(valkey.clone(), validators, st, 1);
    assert!(rt.is_proposer());

    // 5 senders x 10 contiguous nonces = 50 executable txs.
    // FULL-PQ: implicit Falcon-512 senders (domain-separated seeds);
    // classical `Transaction::sign` fixtures are refused at admission.
    let mut senders = Vec::new();
    for i in 0..5u8 {
        let seed = 0x10 + i;
        let (from, _pk) = pq_pair(seed);
        rt.state
            .update_account(AccountState::new(from, 100_000_000))
            .await;
        senders.push(seed);
    }
    for seed in &senders {
        for i in 0..10u64 {
            rt.add_tx(pq_tx(*seed, [1u8; 32], 10, 280_000, i)).await;
        }
    }
    assert_eq!(rt.mempool.read().await.len(), 50);

    let first = rt.propose(1_000).await.expect("sole proposer must propose");
    assert_eq!(
        first.transactions.len(),
        50,
        "r0 must carry the full available mempool, not a partial prefix"
    );
    // Deterministic rebuild: the same pool yields the same ordered set.
    let second = rt.propose(1_000).await.expect("rebuild must also propose");
    let h1: Vec<[u8; 32]> = first
        .transactions
        .iter()
        .map(|t| t.compute_tx_hash())
        .collect();
    let h2: Vec<[u8; 32]> = second
        .transactions
        .iter()
        .map(|t| t.compute_tx_hash())
        .collect();
    assert_eq!(h1, h2, "packing snapshot must be deterministic");
}

fn signer_keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

/// FULL-PQ fixtures (PQ excision conversion).
///
/// Mirrors the rpc.rs / state_engine.rs `pq_pair` / `pq_tx` idioms:
/// an implicit Falcon-512 envelope with the key pre-registered globally
/// (idempotent), so there is no activation surcharge and fee / balance /
/// nonce assertions match the old classical fixtures exactly. Classical
/// `Transaction::sign` outputs are refused by the Pure PQ mempool, so
/// every fixture that must be admitted uses these.
fn pq_pair(seed: u8) -> ([u8; 32], Vec<u8>) {
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = crate::post_quantum::derive_pq_address(
        crate::post_quantum::PqScheme::Falcon512,
        &pk,
        &crate::post_quantum::DEFAULT_SALT,
    );
    Transaction::global_implicit_registry()
        .register(
            from,
            crate::post_quantum::PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        )
        .expect("PQ test key must register");
    (from, pk)
}

/// FULL-PQ replacement for `Transaction::sign(sk, to, amount, gas, nonce,
/// 1, 1)` in tests: same shape, implicit Falcon-512 envelope.
fn pq_tx(seed: u8, to: [u8; 32], amount: u64, gas: u64, nonce: u64) -> Transaction {
    let (from, pk) = pq_pair(seed);
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = crate::sharding::PqSignatureEnvelope::new_implicit(
        crate::post_quantum::PqScheme::Falcon512,
        sig,
    )
    .encode();
    tx
}

/// A funded state for one PQ sender (replaces `funded_state(classical)`).
async fn pq_funded_state(seed: u8, balance: u64) -> Arc<InMemoryStateEngine> {
    let (from, _pk) = pq_pair(seed);
    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(AccountState::new(from, balance)).await;
    st
}

/// Falcon vote minting (mirrors `consensus::tests::fvote`): a classical
/// `Vote::sign` no longer verifies under FULL-PQ, so every hand-driven
/// quorum in these tests uses this.
fn fvote(
    sk: &SigningKey,
    fk: &FalconKeypair,
    height: Height,
    round: Round,
    kind: VoteKind,
    bh: Option<BlockHash>,
) -> Vote {
    Vote::sign_with_falcon(sk, fk, height, round, kind, bh)
}

/// FULL-PQ cluster: runtimes with persisted Falcon keys (votes only
/// verify with a Falcon half now) over one shared validator set,
/// assembled as `Cluster { nodes }` so `broadcast_tx` / `run_height` are
/// reused unchanged. `falcon_base` domain-separates the per-test keys.
fn falcon_cluster(
    val_keys: &[SigningKey],
    states: Vec<Arc<InMemoryStateEngine>>,
    falcon_base: u8,
) -> Cluster {
    let validators = ValidatorSet::from_list(
        val_keys
            .iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let nodes = val_keys
        .iter()
        .zip(states)
        .enumerate()
        .map(|(i, (k, st))| {
            let fk = FalconKeypair::generate_from_seed(falcon_base.wrapping_add(i as u8));
            ValidatorRuntime::new(k.clone(), validators.clone(), st, 1).with_falcon_key(fk)
        })
        .collect();
    Cluster { nodes }
}

/// FULL-PQ QC (mirrors `sync::tests::pq_cert_for`): Ed list for
/// membership/power plus a Falcon µQC envelope for crypto — exactly what
/// `QuorumCertificate::verify` requires. `parent` must be the block's
/// `prev_hash` (chain binding). `signers` selects which keys sign (a
/// missing signer is the offline-member shape).
fn pq_cert_for(
    vs: &ValidatorSet,
    keys: &[SigningKey],
    fks: &[FalconKeypair],
    height: Height,
    round: Round,
    bh: BlockHash,
    parent: BlockHash,
) -> crate::consensus::QuorumCertificate {
    let mut set = crate::consensus::VoteSet::new();
    for (sk, fk) in keys.iter().zip(fks.iter()) {
        let v = fvote(sk, fk, height, round, VoteKind::Precommit, Some(bh));
        set.add(v, vs, height, round, VoteKind::Precommit)
            .expect("falcon vote must ingest");
    }
    set.certificate_with_parent(Some(bh), vs, Some(&parent))
        .expect("quorum must compile a Falcon µQC")
}

/// Falcon keypairs for `keys`, registered globally so hand-minted votes
/// verify (mirrors `consensus::tests::vset_with_falcon`).
fn falcon_for_keys(keys: &[SigningKey], base: u8) -> Vec<FalconKeypair> {
    keys.iter()
        .enumerate()
        .map(|(i, k)| {
            let fk = FalconKeypair::generate_from_seed(base.wrapping_add(i as u8));
            crate::consensus::register_validator_pq_key(
                k.verifying_key().to_bytes(),
                crate::post_quantum::PqScheme::Falcon512,
                fk.public_key.clone(),
            );
            fk
        })
        .collect()
}

#[tokio::test]
async fn cluster_finalizes_blocks_and_applies_state() {
    let val_keys = signer_keys(4);
    // FULL-PQ: the user is a Falcon-512 sender; the classical
    // `Transaction::sign` fixture is refused at admission.
    const USER_SEED: u8 = 0xB0;
    let (from, _pk) = pq_pair(USER_SEED);
    let to = [9u8; 32];

    // Each validator gets its OWN identical state
    let mut states = Vec::new();
    for _ in &val_keys {
        states.push(pq_funded_state(USER_SEED, 10_000_000).await);
    }
    let mut cluster = falcon_cluster(&val_keys, states, 0xF0);

    // 3 heights, one tx each. The gas limit clears the admission floor
    // (the runtime's default pool carries the operator's floor).
    for h in 0..3u64 {
        let tx = pq_tx(USER_SEED, to, 1_000, 280_000, h);
        cluster.broadcast_tx(tx).await;
        let bh = cluster.run_height(1_000 + h).await;

        // every node finalized the same block at this height
        for n in &cluster.nodes {
            assert_eq!(n.finalized.last().unwrap().1, bh);
            assert_eq!(n.finalized.last().unwrap().0, h + 1);
        }
    }

    // all nodes converged to the same state root and balances
    let roots: Vec<[u8; 32]> = {
        let mut v = Vec::new();
        for n in &cluster.nodes {
            v.push(n.state_root().await);
        }
        v
    };
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "nodes diverged on state root"
    );

    for n in &cluster.nodes {
        assert_eq!(n.applied_txs, 3, "each node applied 3 txs");
        let sender = n.state.get_account(&from).await.unwrap();
        let recipient = n.state.get_account(&to).await.unwrap();
        // Each transaction moves 1_000 AND pays its declared gas limit.
        assert_eq!(sender.balance, 10_000_000 - 3_000 - 3 * 280_000);
        assert_eq!(recipient.balance, 3_000);
    }
}

#[tokio::test]
async fn cluster_survives_one_byzantine_validator() {
    // 4 validators, quorum = 3. Simulate one validator going silent.
    let val_keys = signer_keys(4);
    // FULL-PQ sender + Falcon-keyed runtimes (votes and admission both
    // refuse classical fixtures now).
    const USER_SEED: u8 = 0xB1;
    let mut states = Vec::new();
    for _ in &val_keys {
        states.push(pq_funded_state(USER_SEED, 10_000_000).await);
    }
    let mut cluster = falcon_cluster(&val_keys, states, 0xE0);

    let tx = pq_tx(USER_SEED, [9u8; 32], 500, 0, 0);
    cluster.broadcast_tx(tx).await;

    // Silence the LAST validator: it never contributes prevotes/precommits.
    // We emulate this by running the round manually with only 3 voters.
    let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
    let block = cluster.nodes[proposer_idx].propose(1_000).await.unwrap();
    let bh = block.compute_hash();
    let proposer_id = cluster.nodes[proposer_idx].id;
    for (i, n) in cluster.nodes.iter_mut().enumerate() {
        if i != proposer_idx {
            let r = n.hc.round;
            n.on_proposal(proposer_id, block.clone(), r).await.unwrap();
        }
    }

    // only the first 3 (a quorum) vote
    let prevotes: Vec<Vote> = cluster
        .nodes
        .iter()
        .take(3)
        .filter_map(|n| n.make_prevote())
        .collect();
    assert_eq!(prevotes.len(), 3);
    for v in &prevotes {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_prevote(v.clone());
        }
    }
    let precommits: Vec<Vote> = cluster
        .nodes
        .iter_mut()
        .take(3)
        .filter_map(|n| n.make_precommit())
        .collect();
    assert_eq!(precommits.len(), 3);
    for v in &precommits {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_precommit(v.clone());
        }
    }
    // 3-of-4 is a quorum -> the first 3 nodes finalize despite the 4th being silent
    let mut finalized_count = 0;
    for n in cluster.nodes.iter_mut().take(3) {
        if n.try_finalize().await == Some(bh) {
            finalized_count += 1;
        }
    }
    assert_eq!(finalized_count, 3, "quorum must finalize with 1/4 offline");
}

#[tokio::test]
async fn no_finality_without_quorum() {
    let val_keys = signer_keys(4);
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();
    let mut nodes = Vec::new();
    for k in &val_keys {
        nodes.push((k.clone(), funded_state(from).await));
    }
    let mut cluster = Cluster::new(nodes);

    let tx = Transaction::sign(&user, [9u8; 32], 1, 0, 0, 1, 1);
    cluster.broadcast_tx(tx).await;

    let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
    let block = cluster.nodes[proposer_idx].propose(1_000).await.unwrap();
    let proposer_id = cluster.nodes[proposer_idx].id;
    for (i, n) in cluster.nodes.iter_mut().enumerate() {
        if i != proposer_idx {
            let r = n.hc.round;
            n.on_proposal(proposer_id, block.clone(), r).await.unwrap();
        }
    }
    // only 2 of 4 vote -> below quorum 3
    let prevotes: Vec<Vote> = cluster
        .nodes
        .iter()
        .take(2)
        .filter_map(|n| n.make_prevote())
        .collect();
    for v in &prevotes {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_prevote(v.clone());
        }
    }
    let precommits: Vec<Vote> = cluster
        .nodes
        .iter_mut()
        .take(2)
        .filter_map(|n| n.make_precommit())
        .collect();
    for v in &precommits {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_precommit(v.clone());
        }
    }
    for n in cluster.nodes.iter_mut() {
        assert_eq!(
            n.try_finalize().await,
            None,
            "must not finalize without quorum"
        );
    }
}

/// Unlabeled `stell_block_interval_seconds_count` sample from a scrape.
fn block_interval_count(text: &str) -> f64 {
    text.lines()
        .find(|l| l.starts_with("stell_block_interval_seconds_count "))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse::<f64>().ok())
        .expect("block-interval _count sample must be present")
}

/// HDAE calibration-emission: every verified ingested vote and every live
/// commit populates its series (workspace-root FIXES.md §2.12), forged
/// votes emit nothing, and consensus decisions are unchanged.
///
/// Thresholds/logic untouched: this drives the production paths
/// (`on_prevote` / `on_precommit` / `try_finalize`) and asserts on the
/// scraped registry only. Counter/histogram deltas use `>=` because the
/// process-global registry is shared with concurrently running tests and
/// every series here is add-only (monotone), so a concurrent test can
/// only raise a delta, never lower one.
#[tokio::test]
async fn metrics_vote_ingest_and_commit_interval_populate() {
    // Cold (metrics-disabled equivalent): a fresh registry declares the
    // families but carries no samples — scraping a disabled/unwired node
    // is a safe no-op, never an error and never phantom data.
    let cold = crate::metrics::Registry::shared().render();
    assert!(cold.contains("stell_consensus_votes_total{kind=\"prevote\"} 0"));
    assert!(cold.contains("stell_consensus_votes_total{kind=\"precommit\"} 0"));
    assert!(cold.contains("stell_block_interval_seconds_count 0"));
    assert!(cold.contains("# TYPE stell_peer_latency_seconds histogram"));
    assert!(
        !cold.contains("stell_peer_latency_seconds_count"),
        "no peer series before any probe"
    );

    let g = crate::metrics::global();
    let snap_before = g.snapshot();
    let count_before = block_interval_count(&g.render());

    // 4 validators, quorum 3. Falcon-keyed cluster: classical fixtures
    // are refused by admission now.
    let val_keys = signer_keys(4);
    const USER_SEED: u8 = 0xB3;
    let mut states = Vec::new();
    for _ in &val_keys {
        states.push(pq_funded_state(USER_SEED, 10_000_000).await);
    }
    let mut cluster = falcon_cluster(&val_keys, states, 0xE0);

    let tx = pq_tx(USER_SEED, [9u8; 32], 500, 0, 0);
    cluster.broadcast_tx(tx).await;

    let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
    let block = cluster.nodes[proposer_idx].propose(1_000).await.unwrap();
    let bh = block.compute_hash();
    let proposer_id = cluster.nodes[proposer_idx].id;
    for (i, n) in cluster.nodes.iter_mut().enumerate() {
        if i != proposer_idx {
            let r = n.hc.round;
            n.on_proposal(proposer_id, block.clone(), r).await.unwrap();
        }
    }
    // 3-of-4 quorum votes fanned out to every node: 3 x 4 ingest events
    // per kind, all verified member votes at the same height.
    let prevotes: Vec<Vote> = cluster
        .nodes
        .iter()
        .take(3)
        .filter_map(|n| n.make_prevote())
        .collect();
    assert_eq!(prevotes.len(), 3);
    for v in &prevotes {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_prevote(v.clone());
        }
    }
    let precommits: Vec<Vote> = cluster
        .nodes
        .iter_mut()
        .take(3)
        .filter_map(|n| n.make_precommit())
        .collect();
    assert_eq!(precommits.len(), 3);
    for v in &precommits {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_precommit(v.clone());
        }
    }

    // Emit -> scrape -> assert: both vote series present with sane values.
    let snap_after_votes = g.snapshot();
    assert!(
        snap_after_votes.votes_prevote - snap_before.votes_prevote >= 12.0,
        "each fanned-out prevote must be counted: {} -> {}",
        snap_before.votes_prevote,
        snap_after_votes.votes_prevote
    );
    assert!(
        snap_after_votes.votes_precommit - snap_before.votes_precommit >= 12.0,
        "each fanned-out precommit must be counted: {} -> {}",
        snap_before.votes_precommit,
        snap_after_votes.votes_precommit
    );
    let text = g.render();
    assert!(
        text.contains("stell_consensus_votes_total{kind=\"prevote\"}"),
        "prevote series missing:\n{text}"
    );
    assert!(
        text.contains("stell_consensus_votes_total{kind=\"precommit\"}"),
        "precommit series missing:\n{text}"
    );

    // Forged votes are a metrics no-op: tampered signature and non-member
    // voter both fail verification, so `observe_peer_vote` returns false
    // and control never reaches the emission line behind the gate.
    // (No global-counter assertions: the registry is shared with other
    // tests, so exact-zero is not assertable — the load-bearing gate is
    // the verified==false return pinned here.)
    let mut forged = prevotes[0].clone();
    assert!(!forged.signature.is_empty());
    forged.signature[0] ^= 0xFF;
    assert!(
        !cluster.nodes[0].observe_peer_vote(&forged),
        "tampered vote must not verify, hence never emit"
    );
    let outsider = SigningKey::generate(&mut OsRng);
    let height = cluster.nodes[0].hc.height;
    let round = cluster.nodes[0].hc.round;
    let alien = crate::consensus::Vote::sign(
        &outsider,
        height,
        round,
        crate::consensus::VoteKind::Prevote,
        None,
    );
    assert!(
        !cluster.nodes[0].observe_peer_vote(&alien),
        "non-member vote must not count, hence never emit"
    );

    // Commit on 3 nodes: the decision itself proves metrics did not affect
    // consensus, and the interval series must advance once per commit.
    let mut finalized_count = 0;
    for n in cluster.nodes.iter_mut().take(3) {
        if n.try_finalize().await == Some(bh) {
            finalized_count += 1;
        }
    }
    assert_eq!(
        finalized_count, 3,
        "quorum must finalize (emission must not affect consensus)"
    );
    let text = g.render();
    let count_after = block_interval_count(&text);
    assert!(
        count_after - count_before >= 3.0,
        "one interval sample per live commit: {count_before} -> {count_after}"
    );
    assert!(
        text.contains("stell_block_interval_seconds_bucket"),
        "interval buckets missing:\n{text}"
    );
}

#[tokio::test]
async fn proposal_validation_rejects_tampering() {
    let val_keys = signer_keys(4);
    // FULL-PQ sender + Falcon-keyed runtimes.
    const USER_SEED: u8 = 0xB2;
    let mut states = Vec::new();
    for _ in &val_keys {
        states.push(pq_funded_state(USER_SEED, 10_000_000).await);
    }
    let mut cluster = falcon_cluster(&val_keys, states, 0xD0);
    // The gas limit must clear the admission floor (the runtime's default
    // pool carries the operator's floor, exactly like the node's own).
    let tx = pq_tx(USER_SEED, [9u8; 32], 100, 280_000, 0);
    cluster.broadcast_tx(tx).await;

    let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
    let block = cluster.nodes[proposer_idx].propose(1).await.unwrap();
    let receiver_idx = (proposer_idx + 1) % cluster.nodes.len();
    let receiver = &cluster.nodes[receiver_idx];

    // The expected root is the state the block builds on: ours, right now.
    // Using the block's own value here would make the check vacuous, which is
    // exactly how it went unchecked in the first place.
    let root = receiver.state.get_state_root().await;
    assert_eq!(
        block.state_root, root,
        "a genuine block from the proposer must carry the shared state root"
    );

    // genuine block passes
    assert!(receiver.validate_proposal(&block, root).is_ok());

    // wrong height
    let mut b1 = block.clone();
    b1.height = 999;
    assert!(
        receiver.validate_proposal(&b1, root).is_err(),
        "wrong height must be rejected"
    );

    // wrong proposer
    let mut b2 = block.clone();
    b2.proposer = [0xEE; 32];
    assert!(
        receiver.validate_proposal(&b2, root).is_err(),
        "wrong proposer must be rejected"
    );

    // tampered tx signature
    let mut b3 = block.clone();
    if let Some(t) = b3.transactions.first_mut() {
        t.signature[0] ^= 0xFF;
    }
    assert!(
        receiver.validate_proposal(&b3, root).is_err(),
        "bad tx signature must be rejected"
    );

    // oversized block (count check happens before signatures)
    let mut b4 = block.clone();
    b4.transactions = (0..MAX_BLOCK_TXS + 1)
        .map(|i| Transaction {
            from: [0u8; 32],
            to: [0u8; 32],
            amount: 0,
            gas_limit: 0,
            nonce: i as u64,
            source_shard: 1,
            target_shard: 1,
            signature: vec![],
            payload: vec![],
            priority_fee_per_gas: 0,
        })
        .collect();
    assert!(
        receiver.validate_proposal(&b4, root).is_err(),
        "oversized block must be rejected"
    );

    // forged proposer signature: correct proposer FIELD, but the block is
    // signed by an attacker key -> authenticity check must reject it.
    use ed25519_dalek::Signer;
    let attacker = SigningKey::generate(&mut OsRng);
    let mut b5 = block.clone();
    let h = b5.compute_hash();
    let forged_sig = attacker.sign(&h).to_vec();
    b5.validator_signatures = vec![(attacker.verifying_key().to_bytes(), forged_sig)];
    assert!(
        receiver.validate_proposal(&b5, root).is_err(),
        "forged proposer signature must be rejected"
    );
}

/// MEV: the transaction ORDER is a CONSENSUS commitment, not a local note.
///
/// A block whose transaction order was changed AFTER it was signed must be
/// refused by the validators: the order root inside the signed hash no
/// longer matches the body, so the quorum's signature no longer covers
/// what the proposer is offering.
#[tokio::test]
async fn tampered_transaction_order_is_rejected() {
    let val_keys = signer_keys(4);
    // FULL-PQ sender + Falcon-keyed runtimes.
    const USER_SEED: u8 = 0xB3;
    let mut states = Vec::new();
    for _ in &val_keys {
        states.push(pq_funded_state(USER_SEED, 10_000_000).await);
    }
    let mut cluster = falcon_cluster(&val_keys, states, 0xC1);
    // Two transactions from the SAME sender (consecutive nonces) so both
    // are eligible and the ORDER is observable.
    let tx1 = pq_tx(USER_SEED, [9u8; 32], 100, 280_000, 0);
    let tx2 = pq_tx(USER_SEED, [8u8; 32], 200, 280_000, 1);
    cluster.broadcast_tx(tx1).await;
    cluster.broadcast_tx(tx2).await;

    let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
    let block = cluster.nodes[proposer_idx].propose(1).await.unwrap();
    assert_eq!(
        block.transactions.len(),
        2,
        "the proposer must pack both transactions"
    );
    // The proposer committed to the order it packed, and the commitment is
    // the very value every validator re-computes.
    assert_eq!(
        block.order_merkle_root,
        crate::mev::compute_order_merkle_root(&block.transactions),
        "the proposer must set the order root over the exact list it packed"
    );

    let receiver_idx = (proposer_idx + 1) % cluster.nodes.len();
    let receiver = &cluster.nodes[receiver_idx];
    let root = receiver.state.get_state_root().await;
    assert!(
        receiver.validate_proposal(&block, root).is_ok(),
        "the genuine block must be accepted"
    );

    // TAMPER: swap the two transactions, keeping the signed order
    // commitment (and the signature) exactly as the proposer made them.
    let mut tampered = block.clone();
    tampered.transactions.swap(0, 1);
    assert_ne!(
        tampered.compute_hash(),
        block.compute_hash(),
        "the tampered body is a different block"
    );
    let err = receiver
        .validate_proposal(&tampered, root)
        .expect_err("a reordered block must be refused");
    assert!(
        err.contains("order root"),
        "the ORDER commitment must be the reason for the refusal: {err}"
    );

    // A block that claims a root which is not the root of its body is
    // refused for the same reason (a proposer cannot zero the commitment
    // out to slip a reordered body through).
    let mut zeroed = block.clone();
    zeroed.order_merkle_root = [0u8; 32];
    let err = receiver
        .validate_proposal(&zeroed, root)
        .expect_err("a block without the order commitment must be refused");
    assert!(
        err.contains("order root"),
        "a missing order commitment must be refused: {err}"
    );
}

/// The proposer sets the order root over the EXACT list it packed, and
/// the validators accept that block — the commitment is satisfied by the
/// honest path (it must not be a rule that only rejects).
#[tokio::test]
async fn proposer_sets_the_order_root_over_the_packed_list() {
    let val_keys = signer_keys(4);
    // FULL-PQ sender + Falcon-keyed runtimes.
    const USER_SEED: u8 = 0xB4;
    let mut states = Vec::new();
    for _ in &val_keys {
        states.push(pq_funded_state(USER_SEED, 10_000_000).await);
    }
    let mut cluster = falcon_cluster(&val_keys, states, 0xC2);
    let tx = pq_tx(USER_SEED, [9u8; 32], 100, 280_000, 0);
    cluster.broadcast_tx(tx).await;

    let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
    let block = cluster.nodes[proposer_idx].propose(1).await.unwrap();
    assert_eq!(block.transactions.len(), 1);
    assert_eq!(
        block.order_merkle_root,
        crate::mev::compute_order_merkle_root(&block.transactions)
    );
    // The root is inside the signed hash: the quorum signs the ORDER.
    let receiver_idx = (proposer_idx + 1) % cluster.nodes.len();
    let receiver = &cluster.nodes[receiver_idx];
    let root = receiver.state.get_state_root().await;
    assert!(receiver.validate_proposal(&block, root).is_ok());
    assert!(receiver.validate_proposal(&block, root).is_ok());
}

/// A block with NO transactions commits to no order: the root is the
/// all-zero value, on every node, deterministically.
#[tokio::test]
async fn empty_block_carries_the_empty_order_root() {
    let val_keys = signer_keys(4);
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();
    let mut nodes = Vec::new();
    for k in &val_keys {
        nodes.push((k.clone(), funded_state(from).await));
    }
    let mut cluster = Cluster::new(nodes);

    let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
    let block = cluster.nodes[proposer_idx].propose(1).await.unwrap();
    assert!(block.transactions.is_empty());
    assert_eq!(block.order_merkle_root, [0u8; 32]);
    assert_eq!(
        block.order_merkle_root,
        crate::mev::compute_order_merkle_root(&block.transactions)
    );
}

#[tokio::test]
async fn reorg_restores_state_and_applies_new_chain() {
    use crate::chain::ChainManager;
    use crate::sharding::MASTERCHAIN_SHARD;

    let user = SigningKey::generate(&mut OsRng);
    // FULL-PQ: transfers are implicit Falcon-512 transactions; the
    // block bodies are still signed classically (`mk` unchanged).
    const USER_SEED: u8 = 0xB5;
    let (from, _pk) = pq_pair(USER_SEED);
    let b_addr = [0xB0u8; 32];
    let c_addr = [0xC0u8; 32];

    let state = Arc::new(InMemoryStateEngine::new());
    state
        .update_account(AccountState::new(from, 1_000_000))
        .await;

    let mk = |height: u64, prev: [u8; 32], txs: Vec<Transaction>, sk: &SigningKey| {
        let order_merkle_root = crate::mev::compute_order_merkle_root(&txs);
        let mut blk = Block {
            shard_id: MASTERCHAIN_SHARD,
            height,
            prev_hash: prev,
            state_root: [0u8; 32],
            transactions: txs,
            cross_shard_out: vec![],
            timestamp: height,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root,
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            cnvrf_v3: None,
        };
        blk.sign_block(sk);
        blk
    };

    let genesis = mk(0, [0u8; 32], vec![], &user);
    let mut cm = ChainManager::new(genesis);
    let g = cm.best_head();

    // Checkpoint = finalized (genesis) state.
    let cs = ChainState::new(state.clone());
    let mut cs = cs;
    cs.save_checkpoint().await;

    // Canonical chain A: two transfers of 100 to B.
    let blk1 = mk(1, g, vec![pq_tx(USER_SEED, b_addr, 100, 0, 0)], &user);
    let b1 = cm.insert(blk1.clone());
    let blk2 = mk(2, b1, vec![pq_tx(USER_SEED, b_addr, 100, 0, 1)], &user);
    let b2 = cm.insert(blk2.clone());
    cm.recompute_canonical();
    assert_eq!(cm.best_head(), b2);
    cs.apply_block(&blk1).await;
    cs.apply_block(&blk2).await;
    assert_eq!(state.get_account(&from).await.unwrap().balance, 999_800);
    assert_eq!(state.get_account(&b_addr).await.unwrap().balance, 200);

    // Longer fork B: three transfers of 50 to C.
    let f1 = mk(1, g, vec![pq_tx(USER_SEED, c_addr, 50, 0, 0)], &user);
    let fb1 = cm.insert(f1.clone());
    let f2 = mk(2, fb1, vec![pq_tx(USER_SEED, c_addr, 50, 0, 1)], &user);
    let fb2 = cm.insert(f2.clone());
    let f3 = mk(3, fb2, vec![pq_tx(USER_SEED, c_addr, 50, 0, 2)], &user);
    let fb3 = cm.insert(f3.clone());

    // Plan from canonical (b2) to the longer fork head (fb3).
    let plan = cm.reorg_plan(&fb3).unwrap().unwrap();
    assert_eq!(plan.rollback.len(), 2);
    assert_eq!(plan.apply.len(), 3);

    // Apply the reorg: state must reflect the new chain, not the old one.
    cs.reorg(&cm.tree, &plan).await;
    assert_eq!(
        state.get_account(&from).await.unwrap().balance,
        999_850,
        "from: -150 only"
    );
    assert_eq!(
        state.get_account(&c_addr).await.unwrap().balance,
        150,
        "C has the new transfers"
    );
    assert!(
        state.get_account(&b_addr).await.is_none(),
        "B's rolled-back transfers must be gone"
    );
}

/// The state-level reorg also REPORTS what it rolled back: the signal
/// is what the RPC layer publishes to the subscribers.
#[tokio::test]
async fn the_state_reorg_reports_the_rolled_back_blocks() {
    use crate::chain::ChainManager;
    use crate::sharding::MASTERCHAIN_SHARD;

    let user = SigningKey::generate(&mut OsRng);
    let state = Arc::new(InMemoryStateEngine::new());
    // The tag makes every block distinct (it lands in the state root,
    // which the block hash commits to).
    let mk = |height: u64, prev: [u8; 32], tag: u8| {
        let mut blk = Block {
            shard_id: MASTERCHAIN_SHARD,
            height,
            prev_hash: prev,
            state_root: [tag; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: height,
            proposer: user.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            cnvrf_v3: None,
        };
        blk.sign_block(&user);
        blk
    };
    let genesis = mk(0, [0u8; 32], 0x00);
    let mut cm = ChainManager::new(genesis);
    let g = cm.best_head();
    let a1 = cm.insert(mk(1, g, 0xA1));
    let _a2 = cm.insert(mk(2, a1, 0xA2));
    cm.recompute_canonical();
    let b1 = cm.insert(mk(1, g, 0xB1));
    let b2 = cm.insert(mk(2, b1, 0xB2));
    let b3 = cm.insert(mk(3, b2, 0xB3));
    let plan = cm.reorg_plan(&b3).unwrap().unwrap();
    assert_eq!(plan.rollback.len(), 2, "A2 and A1 are rolled back");

    let mut cs = ChainState::new(state);
    let signal = cs.reorg_with_signal(&cm.tree, &plan).await;
    assert_eq!(
        signal.orphaned_blocks, plan.rollback,
        "the rolled-back blocks"
    );
    assert_eq!(signal.height, 1, "the first invalidated height");
    assert!(signal.reason.contains("reorg"));
}

// ------------------------------------------------------------------
// Fork-choice: candidates, reorg and invalidation signals
// ------------------------------------------------------------------

/// A signed block for the fork-choice tests. `tag` makes every block
/// distinct (it lands in the state root and in the transaction).
fn fork_block(height: u64, prev: [u8; 32], tag: u8, sk: &SigningKey) -> Block {
    use crate::sharding::MASTERCHAIN_SHARD;
    let tx = Transaction {
        from: [tag; 32],
        to: [0u8; 32],
        amount: tag as u64,
        gas_limit: 0,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: vec![],
        payload: vec![],
        priority_fee_per_gas: 0,
    };
    let transactions = vec![tx];
    let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root: [tag; 32],
        transactions,
        cross_shard_out: vec![],
        timestamp: height,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        cnvrf_v3: None,
    };
    b.sign_block(sk);
    b
}

/// A runtime with an invalidation sink that collects what is published.
fn runtime_with_sink(
    key: SigningKey,
    state: Arc<InMemoryStateEngine>,
) -> (
    ValidatorRuntime,
    Arc<std::sync::Mutex<Vec<crate::chain::InvalidationSignal>>>,
) {
    let me = key.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(me, 1)]);
    let rt = ValidatorRuntime::new(key, validators, state, 1);
    let seen: Arc<std::sync::Mutex<Vec<crate::chain::InvalidationSignal>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = seen.clone();
    (
        rt.with_invalidation_sink(Arc::new(move |sig: crate::chain::InvalidationSignal| {
            sink.lock().unwrap().push(sig);
        })),
        seen,
    )
}

/// The live-node contract: a competing candidate is recorded BEFORE
/// finality, and when another block is finalized at that height the
/// candidate is invalidated and the signal is published.
#[tokio::test]
async fn a_competing_candidate_is_invalidated_when_another_block_is_finalized() {
    let key = SigningKey::generate(&mut OsRng);
    let state = Arc::new(InMemoryStateEngine::new());
    let (mut rt, seen) = runtime_with_sink(key.clone(), state);

    // A finalized block anchors the fork-choice tree.
    let f1 = fork_block(1, [0u8; 32], 0xF1, &key);
    let f1h = f1.compute_hash();
    rt.note_finalized_block(&f1);
    assert_eq!(rt.chain.finalized_height, 1);

    // Two competing candidates at height 2, both extending the
    // finalized head.
    let c1 = fork_block(2, f1h, 0xC1, &key);
    let c2 = fork_block(2, f1h, 0xC2, &key);
    assert!(
        rt.record_candidate_block(&c1),
        "a valid candidate must be recorded"
    );
    assert!(rt.record_candidate_block(&c2));
    assert_eq!(rt.chain.candidates_at(2).len(), 2);

    // A third block at height 2 is finalized: the candidates lost.
    let w = fork_block(2, f1h, 0xA7, &key);
    rt.note_finalized_block(&w);

    let published = seen.lock().unwrap().clone();
    assert_eq!(published.len(), 2, "one signal per lost branch");
    let mut orphaned: Vec<[u8; 32]> = published
        .iter()
        .flat_map(|s| s.orphaned_blocks.clone())
        .collect();
    orphaned.sort();
    let mut expected = vec![c1.compute_hash(), c2.compute_hash()];
    expected.sort();
    assert_eq!(orphaned, expected, "both candidates are invalidated");
    assert!(published.iter().all(|s| s.height == 2));
    assert!(
        !orphaned.contains(&w.compute_hash()),
        "the finalized block was applied, it is not orphaned"
    );
    assert!(
        rt.chain.candidates.is_empty(),
        "the lost branches are pruned"
    );
}

/// A LONGER candidate branch wins the fork-choice: the reorg plan is
/// executed (the head moves, the losing branch is invalidated) and the
/// state is untouched -- the candidates were never applied.
#[tokio::test]
async fn a_longer_candidate_branch_executes_the_reorg_plan() {
    let key = SigningKey::generate(&mut OsRng);
    let state = Arc::new(InMemoryStateEngine::new());
    let (mut rt, seen) = runtime_with_sink(key.clone(), state.clone());

    let f1 = fork_block(1, [0u8; 32], 0xF1, &key);
    let f1h = f1.compute_hash();
    rt.note_finalized_block(&f1);

    // Branch A: one block at height 2.
    let a1 = fork_block(2, f1h, 0xA1, &key);
    let a1h = a1.compute_hash();
    assert!(rt.record_candidate_block(&a1));
    // The fork-choice adopts the first candidate (nothing to roll back).
    let first = rt
        .run_fork_choice()
        .expect("the first candidate is adopted");
    assert!(first.plan.rollback.is_empty());
    assert!(first.invalidations.is_empty(), "nothing was orphaned yet");

    // Branch B: two blocks -> LONGER.
    let b1 = fork_block(2, f1h, 0xB1, &key);
    let b1h = b1.compute_hash();
    let b2 = fork_block(3, b1h, 0xB2, &key);
    let b2h = b2.compute_hash();
    assert!(rt.record_candidate_block(&b1));
    assert!(rt.record_candidate_block(&b2));

    let root_before = state.get_state_root().await;
    let outcome = rt.run_fork_choice().expect("a longer branch must reorg");
    assert_eq!(outcome.plan.rollback, vec![a1h], "branch A is rolled back");
    assert_eq!(outcome.plan.apply, vec![b1h, b2h], "branch B is applied");
    assert_eq!(outcome.invalidations.len(), 1);
    assert_eq!(outcome.invalidations[0].orphaned_blocks, vec![a1h]);
    assert_eq!(
        outcome.invalidations[0].height, 2,
        "the first invalidated height"
    );
    // The signal reached the transport.
    assert_eq!(seen.lock().unwrap().len(), 1);
    // The state is untouched: a candidate was never applied.
    assert_eq!(state.get_state_root().await, root_before);
}

/// A competitor at the SAME height does NOT invalidate anything: the
/// finalization (the quorum) decides which one is on the chain, so both
/// stay live candidates until it does. Announcing the loser early
/// would be a lie — it may still be the block the chain finalizes.
#[tokio::test]
async fn a_same_height_competitor_does_not_invalidate_the_first_candidate() {
    let key = SigningKey::generate(&mut OsRng);
    let state = Arc::new(InMemoryStateEngine::new());
    let (mut rt, seen) = runtime_with_sink(key.clone(), state);

    let f1 = fork_block(1, [0u8; 32], 0xF1, &key);
    let f1h = f1.compute_hash();
    rt.note_finalized_block(&f1);

    let c1 = fork_block(2, f1h, 0xC1, &key);
    let c2 = fork_block(2, f1h, 0xC2, &key);
    assert!(rt.record_candidate_block(&c1));
    rt.run_fork_choice();
    assert!(rt.record_candidate_block(&c2));
    assert!(
        rt.run_fork_choice().is_none(),
        "a same-height competitor is not a reorg"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "nothing is invalidated before the finalization decides"
    );
    assert_eq!(rt.chain.candidates_at(2).len(), 2, "both stay live");

    // The chain finalizes a third block at that height: now both lost.
    let w = fork_block(2, f1h, 0xA7, &key);
    rt.note_finalized_block(&w);
    let published = seen.lock().unwrap().clone();
    assert_eq!(published.len(), 2, "both candidates lost the fork-choice");
}

/// A candidate that arrives for an ALREADY finalized height can never
/// be applied: it is invalidated on the spot, not silently dropped.
#[tokio::test]
async fn a_candidate_below_the_finalized_height_is_invalidated_on_the_spot() {
    let key = SigningKey::generate(&mut OsRng);
    let state = Arc::new(InMemoryStateEngine::new());
    let (mut rt, seen) = runtime_with_sink(key.clone(), state);

    let f1 = fork_block(1, [0u8; 32], 0xF1, &key);
    let f1h = f1.compute_hash();
    rt.note_finalized_block(&f1);

    // A block at the finalized height (it lost the fork-choice).
    let late = fork_block(1, [0u8; 32], 0xA1, &key);
    assert!(
        !rt.record_candidate_block(&late),
        "it must not become a candidate"
    );
    let published = seen.lock().unwrap().clone();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].orphaned_blocks, vec![late.compute_hash()]);
    assert_eq!(published[0].height, 1);
    let _ = f1h;
}

/// The block that WAS finalized is never announced as invalidated: it
/// was applied, and a retraction would be a lie to every client that
/// follows this chain.
#[tokio::test]
async fn the_finalized_block_is_not_announced_as_invalidated() {
    let key = SigningKey::generate(&mut OsRng);
    let state = Arc::new(InMemoryStateEngine::new());
    let (mut rt, seen) = runtime_with_sink(key.clone(), state);

    let f1 = fork_block(1, [0u8; 32], 0xF1, &key);
    rt.note_finalized_block(&f1);
    // The same block comes back (gossip replay): it is the finalized one,
    // so it must not be announced as invalidated.
    assert!(!rt.record_candidate_block(&f1));
    assert!(
        seen.lock().unwrap().is_empty(),
        "an applied block is never announced as invalidated"
    );
}

/// Audit F5: `replay_historical_block` must verify a historical precommit QC
/// against the validator set in force AT THAT HEIGHT, not the node's current
/// (post-rotation / config) set. During replay the engine is already at the
/// block's committed pre-state, so the staking ledger there IS the height's
/// set -- this test proves replay consults it by making the two sets disjoint.
#[tokio::test]
async fn replay_verifies_qc_against_the_height_set_not_the_current_set() {
    use crate::staking::{MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};

    // The set in force at the replayed height: bonded in the engine ledger.
    let historical = signer_keys(3);
    let engine = Arc::new(InMemoryStateEngine::new());
    {
        let mut ledger = engine.staking_write().await;
        for k in &historical {
            ledger
                .bond(
                    k.verifying_key().to_bytes(),
                    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER,
                    0,
                )
                .unwrap();
        }
    }
    let historical_vs = engine.staking_read().await.to_validator_set();
    assert_eq!(
        historical_vs.len(),
        3,
        "precondition: ledger holds the height's set"
    );

    // The runtime's current set is DIFFERENT. If replay verified against this
    // one it would reject a genuine historical certificate.
    let decoy = signer_keys(3);
    let decoy_vs = ValidatorSet::from_list(
        decoy
            .iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let mut rt = ValidatorRuntime::new(historical[0].clone(), decoy_vs, engine.clone(), 1);

    let root = engine.get_state_root().await;
    let mut block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer: historical[0].verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        cnvrf_v3: None,
    };
    block.sign_block(&historical[0]);
    let bh = block.compute_hash();
    // FULL-PQ: the historical certificate is a Falcon µQC compiled from
    // genuine Falcon votes (mirrors `sync::tests::pq_cert_for`); a
    // classical `Vote::sign` QC no longer verifies. The parent is the
    // block's `prev_hash` (chain binding).
    let fks = falcon_for_keys(&historical, 0xA0);
    block.precommit_qc = Some(pq_cert_for(
        &historical_vs,
        &historical,
        &fks,
        1,
        0,
        bh,
        [0u8; 32],
    ));

    rt.replay_historical_block(&block)
        .await
        .expect("replay must verify the QC against the height's ledger-derived set");
    // And the rotation afterwards installs that same set.
    assert_eq!(rt.validators.len(), 3);
}

/// Audit F10: a prevote quorum from an OLDER round must not be turned into a
/// precommit at the current round. `try_prevote_quorum` still inspects the
/// lookback window (so a late quorum can decide), but `make_precommit` must
/// only act on a QC formed in the round we are actually in.
#[tokio::test]
async fn make_precommit_stamps_the_polka_round_not_the_local_round() {
    let ks = signer_keys(2);
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let me = ks[0].verifying_key().to_bytes();
    let state = funded_state(me).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state, 1);
    let h = rt.hc.height;
    let target = [0x42u8; 32];

    // A full prevote quorum for `target` at round 0.
    // FULL-PQ: Falcon votes (classical `Vote::sign` is rejected).
    let fks = falcon_for_keys(&ks, 0xA0);
    for (k, fk) in ks.iter().zip(fks.iter()) {
        rt.on_prevote(fvote(k, fk, h, 0, VoteKind::Prevote, Some(target)))
            .unwrap();
    }
    // Move on to round 1 BEFORE precommitting: the round-0 QC is now
    // BEHIND us. We still precommit -- but stamped with round 0, the round
    // the polka formed in (Tendermint). Casting at our own round 1 would
    // file the vote into a different bucket than the peer's, and with the
    // two nodes routinely one round apart neither side's precommit ever
    // matched (31 of 180 wasted rounds on the live stand: a full prevote
    // QC whose precommit leg never landed).
    rt.next_round();
    assert_eq!(rt.hc.round, 1);
    let pc_old = rt
        .make_precommit()
        .expect("a polka behind us must still be precommitted");
    assert_eq!(
        pc_old.round, 0,
        "precommit is stamped with the POLKA's round"
    );
    assert_eq!(pc_old.block_hash, Some(target));
    assert_eq!(
        rt.hc.locked,
        Some((target, 0)),
        "the lock records the polka round, not the local round"
    );
    // Recasting for the same polka round is a duplicate, not a new vote:
    // main.rs dedups on (height, vote.round), and here we simply observe
    // that the same bytes come back (idempotent for the receiver).
    let again = rt.make_precommit().expect("idempotent re-cast");
    assert_eq!(again.round, 0);
    assert_eq!(again.block_hash, Some(target));

    // A polka in a NEWER round supersedes: we now precommit at round 1.
    for (k, fk) in ks.iter().zip(fks.iter()) {
        rt.on_prevote(fvote(k, fk, h, 1, VoteKind::Prevote, Some(target)))
            .unwrap();
    }
    let pc = rt
        .make_precommit()
        .expect("current-round QC must precommit");
    assert_eq!(pc.round, 1);
    assert_eq!(pc.block_hash, Some(target));
}

#[tokio::test]
async fn parallel_exec_configuration_and_preservation() {
    let ks = signer_keys(1);
    let me = ks[0].verifying_key().to_bytes();
    let vs = ValidatorSet::from_list(vec![(me, 1)]);
    let state = funded_state(me).await;

    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state.clone(), 1);
    assert!(!rt.parallel_exec, "default parallel_exec is false");
    assert!(!rt.is_parallel_exec_enabled(), "default is disabled");
    assert!(
        !rt.state.is_parallel_exec_enabled(),
        "state default is disabled"
    );

    // Enable parallel execution
    rt = rt.with_parallel_exec(true);
    assert!(rt.parallel_exec);
    assert!(rt.is_parallel_exec_enabled());
    assert!(rt.state.is_parallel_exec_enabled());

    // Temporarily clear on state directly; runtime preserves / restores it on propose
    rt.state.set_parallel_exec(false);
    assert!(!rt
        .state
        .parallel_exec
        .load(std::sync::atomic::Ordering::Acquire));
    let _ = rt.propose(1_000_000).await;
    assert!(
        rt.state.is_parallel_exec_enabled(),
        "propose preserves parallel exec on state"
    );

    // Set to false via runtime
    rt.set_parallel_exec(false);
    assert!(!rt.parallel_exec);
    assert!(!rt.is_parallel_exec_enabled());
    assert!(!rt.state.is_parallel_exec_enabled());

    // Re-enable and verify apply_and_advance preserves it
    rt = rt.with_parallel_exec(true);
    rt.state.set_parallel_exec(false);
    let blk = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: rt.state.get_state_root().await,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_000_000,
        proposer: me,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        cnvrf_v3: None,
    };
    rt.apply_and_advance(blk.compute_hash(), &blk).await;
    assert!(
        rt.state.is_parallel_exec_enabled(),
        "apply_and_advance preserves parallel exec on state"
    );
}

#[tokio::test]
async fn validator_runtime_with_falcon_key_produces_falcon_votes_and_proposals() {
    let key = SigningKey::generate(&mut OsRng);
    let me = key.verifying_key().to_bytes();
    let vs = ValidatorSet::from_list(vec![(me, 1)]);
    let state = funded_state(me).await;

    let fk = FalconKeypair::generate_from_seed(0x42);
    let mut rt = ValidatorRuntime::new(key.clone(), vs.clone(), state.clone(), 1)
        .with_falcon_key(fk.clone());

    assert!(rt.falcon_key.is_some());
    assert_eq!(rt.falcon_key.as_ref().unwrap().public_key, fk.public_key);

    // 1. propose FIRST, then prevote the proposal.
    //
    // A prevote cast BEFORE the proposal exists is a NIL prevote, and a
    // nil quorum is not a polka: the precommit follows a quorum of
    // prevotes FOR A BLOCK (a nil quorum is a timeout, and precommitting
    // it used to shadow the real polka). So the precommit leg of this
    // test needs a real target, and the test's subject — the Falcon half
    // of the vote — rides on the prevote of the proposal.
    let block = rt.propose(1_000_000).await.expect("propose must succeed");

    // 2. make_prevote produces vote with Falcon signature
    let prevote = rt.make_prevote().expect("prevote must be produced");
    assert_eq!(
        prevote.block_hash,
        Some(block.compute_hash()),
        "the prevote must be for the proposal we just made"
    );
    let falcon_sig = prevote
        .falcon_signature()
        .expect("vote must carry Falcon signature");
    assert_eq!(falcon_sig.len(), crate::post_quantum::FALCON512_SIG_LEN);

    let msg = crate::consensus::vote_sign_bytes(1, 0, VoteKind::Prevote, &prevote.block_hash);
    assert!(crate::post_quantum::verify_pq_signature(
        crate::post_quantum::PqScheme::Falcon512,
        &fk.public_key,
        &msg,
        falcon_sig,
    ));
    assert!(prevote.verify(), "vote with Falcon signature must verify");

    // 3. the proposal is signed with the Falcon key too
    let falcon_id = fk.validator_id();
    let proposal_msg = block.compute_hash();

    let falcon_prop_sig = block
        .validator_signatures
        .iter()
        .find(|(id, _)| *id == falcon_id)
        .map(|(_, sig)| sig)
        .expect("block validator signatures must contain Falcon signature");

    assert!(crate::post_quantum::verify_pq_signature(
        crate::post_quantum::PqScheme::Falcon512,
        &fk.public_key,
        &proposal_msg,
        falcon_prop_sig,
    ));

    // 4. make_precommit with polka produces precommit with Falcon signature
    assert!(rt.on_prevote(prevote).is_ok());
    let precommit = rt.make_precommit().expect("precommit must be produced");
    let pc_falcon_sig = precommit
        .falcon_signature()
        .expect("precommit must carry Falcon signature");
    let pc_msg =
        crate::consensus::vote_sign_bytes(1, 0, VoteKind::Precommit, &precommit.block_hash);
    assert!(crate::post_quantum::verify_pq_signature(
        crate::post_quantum::PqScheme::Falcon512,
        &fk.public_key,
        &pc_msg,
        pc_falcon_sig,
    ));
    assert!(precommit.verify());
}

#[tokio::test]
async fn validator_runtime_falcon_votes_form_uqc_and_verify_unified() {
    let val_keys = signer_keys(4);
    // FULL-PQ sender (the known Pure-PQ-unwrap site: a classical
    // `Transaction::sign` fixture is refused at `add_checked`).
    const USER_SEED: u8 = 0xB6;
    let to = [9u8; 32];

    let mut nodes = Vec::new();
    for k in &val_keys {
        nodes.push((k.clone(), pq_funded_state(USER_SEED, 10_000_000).await));
    }

    let validators = ValidatorSet::from_list(
        nodes
            .iter()
            .map(|(k, _)| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );

    let mut runtimes: Vec<ValidatorRuntime> = nodes
        .into_iter()
        .enumerate()
        .map(|(i, (k, st))| {
            let fk = FalconKeypair::generate_from_seed((i + 1) as u8);
            ValidatorRuntime::new(k, validators.clone(), st, 1).with_falcon_key(fk)
        })
        .collect();

    let tx = pq_tx(USER_SEED, to, 1_000, 280_000, 0);
    for rt in &runtimes {
        rt.mempool
            .write()
            .await
            .add_checked(tx.clone(), 10_000_000)
            .unwrap();
    }

    // 1. Propose from designated proposer
    let proposer_idx = runtimes
        .iter()
        .position(|rt| rt.is_proposer())
        .expect("must have proposer");
    let block = runtimes[proposer_idx]
        .propose(1_000)
        .await
        .expect("propose must succeed");
    let bh = block.compute_hash();

    // Ingest proposal on all nodes
    let proposer_id = runtimes[proposer_idx].id;
    for rt in &mut runtimes {
        assert!(rt.on_proposal(proposer_id, block.clone(), 0).await.is_ok());
    }

    // 2. Prevote
    let mut prevotes = Vec::new();
    for rt in &runtimes {
        let v = rt.make_prevote().expect("make_prevote");
        assert!(v.falcon_signature().is_some());
        prevotes.push(v);
    }

    for rt in &mut runtimes {
        for v in &prevotes {
            assert!(rt.on_prevote(v.clone()).is_ok());
        }
        let (polka_round, target) = rt.hc.try_prevote_quorum_at().expect("polka must form");
        assert_eq!(target, Some(bh));
        let prevote_qc = rt
            .hc
            .prevote_qc
            .get(&polka_round)
            .expect("prevote QC must exist");
        assert!(
            prevote_qc
                .signatures
                .iter()
                .any(|(voter, _)| *voter == crate::consensus::PQ_UQC_MARKER_ID),
            "prevote QC must contain PQ_UQC_MARKER_ID"
        );
        assert!(prevote_qc.verify_unified(&validators));
    }

    // 3. Precommit
    let mut precommits = Vec::new();
    for rt in &mut runtimes {
        let v = rt.make_precommit().expect("make_precommit");
        assert!(v.falcon_signature().is_some());
        precommits.push(v);
    }

    for rt in &mut runtimes {
        for v in &precommits {
            assert!(rt.on_precommit(v.clone()).is_ok());
        }
        let decided = rt
            .hc
            .try_precommit_quorum()
            .expect("precommit quorum must decide");
        assert_eq!(decided, bh);
        let precommit_qc = rt
            .hc
            .precommit_qc
            .as_ref()
            .expect("precommit QC must exist");
        assert!(
            precommit_qc
                .signatures
                .iter()
                .any(|(voter, _)| *voter == crate::consensus::PQ_UQC_MARKER_ID),
            "precommit QC must contain PQ_UQC_MARKER_ID"
        );
        assert!(precommit_qc.verify_unified(&validators));
        assert!(precommit_qc.verify(&validators));
    }

    // 4. Finalize the block across all nodes
    for rt in &mut runtimes {
        let finalized = rt.try_finalize().await.expect("finalization must succeed");
        assert_eq!(finalized, bh);
        assert!(rt.finalized.contains(&(1, bh)));
    }
}

#[tokio::test]
async fn test_sec01_adopt_lock_superseded_by_equal_or_higher_round_qc() {
    let ks = signer_keys(4);
    let me = ks[0].verifying_key().to_bytes();
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let st = funded_state(me).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st, 1);

    let fks = falcon_for_keys(&ks, 0xA0);
    let make_block = |round: Round, root: [u8; 32]| -> Block {
        let proposer = vs.proposer_for(1, round).unwrap();
        let idx = ks
            .iter()
            .position(|k| k.verifying_key().to_bytes() == proposer)
            .unwrap();
        let pk = &ks[idx];
        let fk = &fks[idx];
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_000_000,
            proposer,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            cnvrf_v3: None,
        };
        b.sign_block(pk);
        // Falconize: the proposer half under the derived Falcon address
        // (registered for this Ed id by `falcon_for_keys` above),
        // mirroring the runtime proposal path.
        {
            let hash = b.compute_hash();
            let falcon_id = fk.validator_id();
            let falcon_sig = fk.sign(&hash);
            b.validator_signatures.push((falcon_id, falcon_sig));
        }
        b
    };

    let make_qc = |round: Round, bh: BlockHash| -> crate::consensus::QuorumCertificate {
        // FULL-PQ: the certificate is a Falcon µQC compiled from genuine
        // votes (a classical `Vote::sign` QC fails `verify` before the
        // lock check is ever reached). The parent is the block's
        // `prev_hash` (chain binding); all fixture blocks extend [0; 32].
        pq_cert_for(&vs, &ks, &fks, 1, round, bh, [0u8; 32])
    };

    let root = rt.state.get_state_root().await;
    rt.hc.round = 1;
    let blk0 = make_block(0, root);
    let bh0 = blk0.compute_hash();

    // 1. Lock taken at round 1 prevents adopting an older round 0 block contradicting the lock
    let locked_block = [0xAAu8; 32];
    assert_ne!(locked_block, bh0);
    rt.hc.locked = Some((locked_block, 1));
    let cert0 = make_qc(0, bh0);
    let res = rt.adopt_committed(1, blk0.clone(), cert0).await;
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("lock"));

    // 2. A certificate at the SAME round as the lock but for a DIFFERENT
    //    block is a genuine safety conflict (two conflicting polkas in one
    //    round need >1/3 Byzantine power) and must be refused.
    rt.hc.locked = Some((locked_block, 1));
    let cert_same = make_qc(1, bh0);
    let res = rt.adopt_committed(1, blk0.clone(), cert_same).await;
    assert!(
        res.is_err(),
        "same-round conflicting certificate must be refused"
    );
    assert!(res.unwrap_err().contains("lock"));

    // 3. A certificate from a STRICTLY LATER round proves the network moved
    //    on without us, so the lock is superseded and the canonical commit
    //    must be adopted (the pre-SEC-01 test refused it and partitioned
    //    the node from the chain). The block is the ROUND-2 proposer's:
    //    the adopt path checks the proposer against the certificate's
    //    round, so the block and the certificate must agree on it.
    let blk2 = make_block(2, root);
    let bh2 = blk2.compute_hash();
    assert_ne!(locked_block, bh2);
    rt.hc.locked = Some((locked_block, 1));
    let cert2 = make_qc(2, bh2);
    let res = rt.adopt_committed(1, blk2, cert2).await;
    assert_eq!(res, Ok(bh2));
}

// ---------------------------------------------------------------------
// Validator-set synchronization between the masterchain and its
// workchains (the audit's "validator set gap").
//
// The masterchain owns the staking registry; a workchain has none of its
// own. The two share the master's ledger through
// `ValidatorRuntime::master_staking`, so a rotation on the masterchain
// (bond / unbond / slash) is adopted by the workchain's consensus at the
// next height boundary — no node restart, no second registry.
// ---------------------------------------------------------------------

/// A masterchain + workchain pair in one process, sharing the master's
/// staking registry. The workchain's own ledger stays EMPTY (there is no
/// staking registry on a workchain) and it starts on the config-defined
/// set, exactly like a real workchain.
async fn masterchain_and_workchain(
    me: ValidatorId,
    newcomer: ValidatorId,
) -> (
    Arc<InMemoryStateEngine>,
    MasterStakingLedger,
    ValidatorRuntime,
    ValidatorRuntime,
) {
    let master_engine = Arc::new(InMemoryStateEngine::new());
    let master_handle = master_engine.staking_handle();
    let workchain_engine = Arc::new(InMemoryStateEngine::new());
    let registry = ShardRegistry::from_ids([MASTERCHAIN_SHARD, 1]);
    let config_set = ValidatorSet::from_list(vec![(me, 1)]);
    let key = SigningKey::generate(&mut OsRng);

    let master = ValidatorRuntime::new(key.clone(), config_set.clone(), master_engine.clone(), 1)
        .with_shard(MASTERCHAIN_SHARD, registry.clone())
        .with_master_staking(master_handle.clone());
    let workchain = ValidatorRuntime::new(key, config_set, workchain_engine.clone(), 1)
        .with_shard(1, registry)
        .with_master_staking(master_handle.clone());

    // The workchain's own registry is empty BY DESIGN — the masterchain
    // owns the staking registry. This is the state the audit found.
    assert!(
        workchain_engine
            .staking_read()
            .await
            .to_validator_set()
            .is_empty(),
        "a workchain must not seed a staking ledger of its own"
    );
    let _ = newcomer;
    (master_engine, master_handle, master, workchain)
}

/// Advance the test runtime across the height boundary, exactly like the
/// live finalize/adopt paths do: the staged validator-set change becomes
/// in-force at the new height (W10.5 activation boundary).
fn advance_test_height(rt: &mut ValidatorRuntime) {
    rt.hc.height += 1;
    rt.install_due_validator_set();
    rt.hc.validators = rt.validators.clone();
}

/// A bond on the masterchain and an unbond are both adopted by the
/// workchain's consensus set, live, with no node restart — at the NEXT
/// height boundary (W10.5: staged at ledger-height L, in force from L+1;
/// never mid-flight).
#[tokio::test]
async fn workchain_adopts_the_masterchain_bond_and_unbond_rotation() {
    let me = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let newcomer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let bond = crate::staking::required_bond_floor_nano();
    let (master_engine, _handle, mut master, mut workchain) =
        masterchain_and_workchain(me, newcomer).await;

    // The masterchain's registry: one bonded validator.
    master_engine
        .staking_write()
        .await
        .bond(me, bond, 0)
        .expect("the masterchain bond must be accepted");

    // 1. The workchain STAGES the masterchain's set (its config-defined
    //    set stays in force for the height in progress).
    let h = workchain.hc.height;
    assert!(
        workchain.refresh_validator_set_from_staking().await,
        "the workchain must stage the masterchain's validator set"
    );
    assert_eq!(
        workchain.validators.validators.get(&me),
        Some(&1),
        "the in-force set must not jump mid-flight"
    );
    assert_eq!(
        workchain.pending_validators.as_ref().map(|(a, _)| *a),
        Some(h + 1),
        "the change activates at the next height boundary"
    );
    // ... and the set in force is height-pinned: H still votes the old
    // set, H+1 the new one.
    assert_eq!(
        workchain.validator_set_for_height(h).validators.get(&me),
        Some(&1)
    );
    assert_eq!(
        workchain
            .validator_set_for_height(h + 1)
            .validators
            .get(&me),
        Some(&bond)
    );
    // Across the boundary the staged set becomes in-force — consensus
    // view and bookkeeping copy together.
    advance_test_height(&mut workchain);
    assert_eq!(workchain.validators.validators.get(&me), Some(&bond));
    assert_eq!(workchain.hc.validators.validators.get(&me), Some(&bond));
    // The masterchain itself derives exactly the same set.
    assert!(master.refresh_validator_set_from_staking().await);
    advance_test_height(&mut master);
    assert_eq!(
        master.validators.validators,
        workchain.validators.validators
    );

    // 2. A NEW validator bonds on the masterchain: the workchain stages
    //    it, with the bonded stake as its voting power, in force next.
    master_engine
        .staking_write()
        .await
        .bond(newcomer, bond, 0)
        .expect("the newcomer bond must be accepted");
    let h = workchain.hc.height;
    assert!(
        workchain.refresh_validator_set_from_staking().await,
        "a masterchain bond must rotate the workchain's set"
    );
    assert!(
        !workchain.validators.validators.contains_key(&newcomer),
        "the newcomer must not join mid-flight"
    );
    assert_eq!(
        workchain
            .validator_set_for_height(h + 1)
            .validators
            .get(&newcomer),
        Some(&bond)
    );
    advance_test_height(&mut workchain);
    assert_eq!(workchain.validators.validators.get(&newcomer), Some(&bond));
    assert_eq!(
        workchain.hc.validators.validators.get(&newcomer),
        Some(&bond)
    );
    assert_eq!(workchain.validators.total_power(), 2 * bond);
    assert!(master.refresh_validator_set_from_staking().await);
    advance_test_height(&mut master);
    assert_eq!(
        master.validators.validators,
        workchain.validators.validators
    );

    // 3. The newcomer unbonds on the masterchain: the workchain drops it
    //    from its set (and from the consensus view) at the next boundary.
    master_engine
        .staking_write()
        .await
        .unbond(newcomer, bond, 0)
        .expect("the unbond must be accepted");
    assert!(
        workchain.refresh_validator_set_from_staking().await,
        "a masterchain unbond must rotate the workchain's set"
    );
    assert!(
        workchain.validators.validators.contains_key(&newcomer),
        "the unbonded validator stays in force until the boundary"
    );
    advance_test_height(&mut workchain);
    assert!(
        !workchain.validators.validators.contains_key(&newcomer),
        "the unbonded validator must leave the workchain's set"
    );
    assert!(
        !workchain.hc.validators.validators.contains_key(&newcomer),
        "the unbonded validator must leave the workchain's consensus view"
    );

    // 4. The rotated set is in force from the NEXT height — the boundary
    //    the apply path installs it at, with no restart in between.
    assert_eq!(
        crate::sharding::validator_set_adoption_height(workchain.hc.height),
        workchain.hc.height + 1
    );
    assert!(!workchain.is_validator_set_stale());
}

/// A slash on the masterchain is transmitted to the workchain as well:
/// the slashed validator's voting power in the workchain's set is the
/// post-slash stake, not the pre-slash one — from the NEXT height
/// boundary (W10.5: staged, never mid-flight).
#[tokio::test]
async fn workchain_adopts_the_masterchain_slash_rotation() {
    let me = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let newcomer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let bond = crate::staking::required_bond_floor_nano();
    let (master_engine, _handle, _master, mut workchain) =
        masterchain_and_workchain(me, newcomer).await;

    master_engine
        .staking_write()
        .await
        .bond(me, bond, 0)
        .expect("the masterchain bond must be accepted");
    master_engine
        .staking_write()
        .await
        .bond(newcomer, bond, 0)
        .expect("the newcomer bond must be accepted");
    assert!(workchain.refresh_validator_set_from_staking().await);
    advance_test_height(&mut workchain);
    assert_eq!(workchain.validators.total_power(), 2 * bond);

    // Slash the newcomer by 10%: its stake falls below the minimum bond,
    // so it leaves the elected set. The workchain must see THAT set, not
    // the pre-slash one — from the next boundary, not mid-flight.
    let burned = master_engine
        .staking_write()
        .await
        .slash(newcomer, 1_000)
        .expect("the slash must be accepted");
    assert!(burned > 0, "the slash must burn stake");
    assert!(
        workchain.refresh_validator_set_from_staking().await,
        "a masterchain slash must rotate the workchain's set"
    );
    assert!(
        workchain.validators.validators.contains_key(&newcomer),
        "the slashed validator stays in force until the boundary"
    );
    advance_test_height(&mut workchain);
    assert!(
        !workchain.validators.validators.contains_key(&newcomer),
        "the slashed validator must leave the workchain's set"
    );
    assert_eq!(
        workchain.validators.validators.get(&me),
        Some(&bond),
        "the untouched validator keeps its full power"
    );
}

/// Periodic workchain repair (R3 CODE-TAILS sweep): a workchain that stops
/// finalizing — the wedged shard-1 state — never reaches any
/// height-advance path, so without an advance-free re-read its set can
/// never converge. `refresh_workchain_set_from_master` is that re-read:
/// a masterchain rotation stages the new set with NO finalize, NO adopt,
/// NO walk and NO height advance anywhere in between, and the next
/// boundary installs it. The masterchain (and un-wired runtimes) are a
/// silent no-op.
#[tokio::test]
async fn workchain_periodic_master_reread_converges_without_any_finalize() {
    let me = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let newcomer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let bond = crate::staking::required_bond_floor_nano();
    let (master_engine, _handle, mut master, mut workchain) =
        masterchain_and_workchain(me, newcomer).await;

    // A bond lands on the masterchain while the workchain is wedged: it
    // finalizes nothing, advances nothing, walks nothing.
    master_engine
        .staking_write()
        .await
        .bond(me, bond, 0)
        .expect("the masterchain bond must be accepted");
    let wedged_height = workchain.hc.height;

    // The periodic repair — no height-advance path involved — stages the
    // master set.
    assert!(
        workchain.refresh_workchain_set_from_master().await,
        "the periodic repair must pick up the masterchain rotation"
    );
    assert_eq!(
        workchain.hc.height, wedged_height,
        "the repair must not move the height by itself"
    );
    assert_eq!(
        workchain.validators.validators.get(&me),
        Some(&1),
        "the in-force set must not jump mid-flight"
    );
    assert_eq!(
        workchain.pending_validators.as_ref().map(|(a, _)| *a),
        Some(wedged_height + 1),
        "the rotation stages at the next height boundary"
    );
    // A quiet interval changes nothing and reports nothing.
    assert!(
        !workchain.refresh_workchain_set_from_master().await,
        "a converged repair must be silent"
    );
    // The next boundary — however the node gets there — installs it.
    advance_test_height(&mut workchain);
    assert_eq!(
        workchain.validators.validators.get(&me),
        Some(&bond),
        "the boundary installs the master set the repair staged"
    );
    assert_eq!(
        workchain
            .validator_set_for_height(wedged_height + 1)
            .validators,
        workchain.validators.validators,
    );

    // Non-workchains are a silent no-op: the masterchain never reads a
    // foreign registry, wired handle or not.
    master_engine
        .staking_write()
        .await
        .bond(newcomer, bond, 0)
        .expect("the newcomer bond must be accepted");
    assert!(
        !master.refresh_workchain_set_from_master().await,
        "the masterchain must ignore the periodic workchain repair"
    );
    assert!(
        !master.validators.validators.contains_key(&newcomer),
        "the masterchain's own set moves only on its own refresh"
    );
}

/// Post-restart wedge repair: a refresh can move the runtime's in-force
/// set without moving heights (restore from a lagging domains snapshot,
/// then a live-ledger refresh), stranding the consensus copy on the older
/// set. The node then schedules different proposers from converged peers
/// and no height ever advances to rebuild the copy (observed live:
/// #388561 with one node on the post-change set vs the rest on the
/// pre-change one). `resync_consensus_set_to_runtime` realigns the copy
/// without any finalize/adopt/walk; a second call is a silent no-op.
#[tokio::test]
async fn consensus_copy_resyncs_to_runtime_without_height_advance() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::sync::Arc;
    let me = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let other = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let state = Arc::new(InMemoryStateEngine::new());
    let old_set = ValidatorSet::from_list(vec![(me, 100), (other, 100)]);
    let key = SigningKey::generate(&mut OsRng);
    let mut rt = ValidatorRuntime::new(key, old_set, state, 10);
    let wedged_height = rt.hc.height;
    // Simulate the wedge: the runtime set moved (live-ledger refresh)
    // while the consensus height — and its copy — did not.
    let new_set = ValidatorSet::from_list(vec![(me, 100), (other, 90)]);
    rt.validators = new_set.clone();
    assert_ne!(
        rt.hc.validators.validators, rt.validators.validators,
        "the test must start wedged"
    );
    assert!(rt.resync_consensus_set_to_runtime(), "the resync must fire");
    assert_eq!(rt.hc.height, wedged_height, "no height may move");
    assert_eq!(rt.hc.validators.validators, new_set.validators);
    assert!(
        !rt.resync_consensus_set_to_runtime(),
        "a converged copy must be silent"
    );
    // The copy now schedules exactly like a fresh node on the new set.
    for round in [0u32, 1, 7, 64] {
        rt.hc.round = round;
        assert_eq!(
            rt.hc.proposer(),
            new_set.proposer_for(wedged_height, round),
            "round {round} must schedule identically"
        );
    }
}

/// CN-VRF v3 ACTIVE end-to-end: the epoch-beacon schedule replaces the
/// parent-hash schedule, blocks carry commit carriers for the next epoch,
/// and every node still converges on one state root.
///
/// Below the gate (`CNVRF_V3_ACTIVATION_HEIGHT = u64::MAX`) this suite exercises
/// the same code through `set_cnvrf_v3_activation_height_for_tests(0)`, which
/// flips BOTH the runtime override and the engine override — the production
/// gate constant stays frozen.
#[tokio::test]
async fn cnvrf_v3_active_schedule_converges_and_carries_commits() {
    let keys = signer_keys(3);
    let validators = ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let states: Vec<Arc<InMemoryStateEngine>> = (0..keys.len())
        .map(|_| Arc::new(InMemoryStateEngine::new()))
        .collect();
    for st in &states {
        crate::runtime::fund_genesis(st, &validators, 1_000_000).await;
    }
    let mut cluster = falcon_cluster(&keys, states, 0xD0);
    for n in cluster.nodes.iter_mut() {
        n.set_cnvrf_v3_activation_height_for_tests(0);
        n.set_cnvrf_v3_vdf_steps(64);
        n.hc.set_parent_hash([0u8; 32]);
        assert!(
            n.cnvrf_v3_is_active_at(1),
            "gate must be active for the test"
        );
    }

    let mut ts = 1_700_000_000u64;
    let mut committed_seen = 0usize;
    for _ in 1u64..=6 {
        ts += 1;
        let bh = cluster.run_height(ts).await;
        for n in cluster.nodes.iter() {
            assert!(
                n.finalized.last().is_some_and(|(_, h)| *h == bh),
                "every node must finalize the same hash"
            );
        }
        if let Some((_, block, _)) = cluster.nodes[0].last_decision.clone() {
            if let Some(payload) = block.cnvrf_v3.as_ref() {
                committed_seen += payload.commits.len();
            }
        }
    }
    assert!(
        committed_seen > 0,
        "active CN-VRF v3 proposals must carry epoch N+1 commit carriers"
    );

    let roots: Vec<_> = {
        let mut v = Vec::new();
        for n in cluster.nodes.iter() {
            v.push(n.state.get_state_root().await);
        }
        v
    };
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "all nodes must converge on one state root, got {roots:?}"
    );
    // The commits actually landed in the engine's on-chain state.
    let mirror = cluster.nodes[0].state.cnvrf_v3_read().await.clone();
    for n in cluster.nodes.iter() {
        assert!(
            mirror.get_record(&n.id, 1).is_some(),
            "every validator's epoch-1 commitment must be recorded on-chain"
        );
    }
}

/// An active CN-VRF v3 proposal whose commit carrier is not admissible
/// (wrong epoch / forged signature) must be REFUSED by validation instead of
/// being silently ignored by the transition.
#[tokio::test]
async fn cnvrf_v3_active_rejects_inadmissible_commit_payload() {
    let key = SigningKey::generate(&mut OsRng);
    let me = key.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(me, 1)]);
    let mut rt = ValidatorRuntime::new(key, validators, funded_state(me).await, 1)
        .with_falcon_key(FalconKeypair::generate_from_seed(0xE7));
    rt.set_cnvrf_v3_activation_height_for_tests(0);
    rt.set_cnvrf_v3_vdf_steps(64);

    let root = rt.state.get_state_root().await;
    let mut block = rt.propose(1_700_000_500).await.expect("propose");
    block.state_root = root;

    // A commit for the CURRENT epoch is stale by construction.
    let fk = FalconKeypair::generate_from_seed(0xE8);
    let secret = [7u8; crate::cn_vrf::V3_LINK_LEN];
    let chain = crate::cn_vrf::CnVrfV3Chain::generate(rt.cnvrf_v3_chain_id, &me, 0, &secret);
    let stale = chain.commit_carrier(&fk);
    let mut payload = block
        .cnvrf_v3
        .clone()
        .unwrap_or(crate::sharding::CnVrfV3BlockPayload {
            reveal: None,
            commits: Vec::new(),
            epoch_vdf: None,
        });
    payload.commits.push(stale);
    block.cnvrf_v3 = Some(payload);
    assert!(
        rt.validate_proposal_unaligned(&block, root).is_err(),
        "a stale-epoch commit carrier must be refused"
    );
}
