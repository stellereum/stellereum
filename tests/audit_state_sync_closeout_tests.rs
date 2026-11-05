//! Audit closeout (`audit-state-sync.md`): per-finding regression pins for the
//! state-engine / storage / sync / commitment / sharding surface.
//!
//! Every test below lives in THIS new file only — no shared test was edited.
//! Findings whose fix lies outside the allowed files (F3 faucet guard in
//! `main.rs`, F9 stale chaos expectation in `parallel_exec`) are NOT fixed
//! here; they are reported in the final message as deferred with reasoning.

use ed25519_dalek::SigningKey;
use stellereum::sharding::{
    Block, CrossShardKey, CrossShardReplaySnapshot, Transaction, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{memory_bounds, AccountState, InMemoryStateEngine};
use stellereum::storage::{
    check_validator_set_freshness, check_validator_set_freshness_with_lag, decode_domain_snapshot,
    load_full_state_into, persist_push_policy, DomainSnapshot, PersistJob, PersistPushPolicy,
    Storage, PERSIST_BLOCKING_WAIT_MS, PERSIST_QUEUE_CAP,
};
use stellereum::sync::{
    chunk_batch_for_blob, fast_sync_state, plan_chunk_batches, snapshot_blob_budget_ms,
};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "stell-audit-closeout-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn skey(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn id_of(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// FULL-PQ sender address for a seed: implicit Falcon-512, registered
/// globally (no activation surcharge).
fn pq_id(seed: u8) -> [u8; 32] {
    use stellereum::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("PQ test key must register");
    from
}

/// FULL-PQ replacement for `Transaction::sign` in fixtures.
fn pq_tx(seed: u8, to: [u8; 32], amount: u64, gas: u64, nonce: u64) -> Transaction {
    use stellereum::post_quantum::{PqScheme, PqSignatureEnvelope};
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = pq_id(seed);
    let mut t = Transaction {
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
    let msg = t.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    t.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    t
}

fn fabric_key(a: u8, b: u8) -> CrossShardKey {
    CrossShardKey {
        source_shard: MASTERCHAIN_SHARD,
        finalized_in_block: [a; 32],
        msg_id: [b; 32],
    }
}

fn test_block(height: u64, prev: [u8; 32], proposer: [u8; 32], state_root: [u8; 32]) -> Block {
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_760_000_000 + height,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    }
}

// ===========================================================================
// F1: boot restores the FULL replay snapshot (produced/completed included)
// ===========================================================================

/// Build an engine with funded user + a NON-EMPTY replay set on all three
/// legs, all at a deterministic root.
async fn engine_with_replay(user: [u8; 32]) -> (InMemoryStateEngine, CrossShardReplaySnapshot) {
    let e = InMemoryStateEngine::new();
    e.update_account(AccountState::new(user, 1_000_000)).await;
    let tx = Transaction::sign(&skey(90), [0x99; 32], 50, 10, 0, MASTERCHAIN_SHARD, 1);
    let tx_hash = tx.compute_tx_hash();
    let replay = CrossShardReplaySnapshot {
        engine_consumed: vec![fabric_key(0xE1, 0xE2)],
        runtime_consumed: vec![fabric_key(0xE3, 0xE4)],
        produced: vec![(tx_hash, tx, 7)],
        completed: vec![[0xC7; 32]],
        xpc: vec![],
    };
    e.restore_cross_shard_replay(&replay).await;
    (e, replay)
}

async fn store_paired_snapshot(
    store: &Storage,
    engine: &InMemoryStateEngine,
    height: u64,
    replay: Option<&CrossShardReplaySnapshot>,
) -> [u8; 32] {
    let root = engine.get_state_root().await;
    let snap = engine.create_snapshot().await;
    let staking = engine.staking_read().await.clone();
    let gov = engine.governance_read().await.clone();
    let dom = DomainSnapshot::capture(engine, &staking, &gov).await;
    let dom_bytes = bincode::serialize(&dom).unwrap();
    store.put_state(height, &snap).unwrap();
    store.put_domains(height, &dom_bytes).unwrap();
    store
        .put_session_keys(height, &engine.session_keys_snapshot().await)
        .unwrap();
    store
        .put_bridge(height, &engine.bridge_snapshot().await)
        .unwrap();
    store
        .put_zkml_models(height, &engine.zkml_models_snapshot().await)
        .unwrap();
    if let Some(r) = replay {
        store
            .put_cross_shard(height, &bincode::serialize(r).unwrap())
            .unwrap();
    }
    // Anchor at H+1 committing the post-H state (the rule
    // `expected_restore_root` enforces).
    let anchor = test_block(height + 1, [0xA0; 32], [0xB0; 32], root);
    store.put_block(&anchor).unwrap();
    root
}

#[tokio::test]
async fn f1_boot_restores_full_replay_sets() {
    let user = [0x66u8; 32];
    let (src, replay) = engine_with_replay(user).await;
    let dir = tmpdir("f1-full");
    let store = Storage::open(&dir).expect("open");
    let root = store_paired_snapshot(&store, &src, 11, Some(&replay)).await;

    let live = InMemoryStateEngine::new();
    let loaded = load_full_state_into(&store, &live)
        .await
        .expect("paired snapshot must load")
        .expect("must be Some");
    assert_eq!(loaded.0, 11);
    // ALL THREE legs survive the restart — the pre-fix loader restored only
    // `engine_consumed`, dropping produced/completed (and the runtime half).
    assert!(
        live.is_cross_shard_consumed(&replay.engine_consumed[0])
            .await
    );
    assert!(
        live.is_cross_shard_consumed(&replay.runtime_consumed[0])
            .await
    );
    assert_eq!(
        live.cross_shard_consumed_len().await,
        2,
        "both consumed halves install"
    );
    assert_eq!(
        live.cross_shard_produced_len().await,
        1,
        "produced survives restart"
    );
    assert!(
        live.is_cross_shard_completed(&replay.completed[0]).await,
        "completed survives restart"
    );
    assert_eq!(
        live.get_state_root().await,
        root,
        "root covers the full replay set"
    );
}

#[tokio::test]
async fn f1_boot_missing_cross_shard_blob_is_refused() {
    // Stored snapshot WITHOUT the replay blob, but the anchor commits replay
    // state: the loader must refuse (root mismatch), never install empty.
    let user = [0x66u8; 32];
    let (src, replay) = engine_with_replay(user).await;
    let _ = replay;
    let dir = tmpdir("f1-missing");
    let store = Storage::open(&dir).expect("open");
    let root_before = src.get_state_root().await;
    store_paired_snapshot(&store, &src, 11, None).await;

    let live = InMemoryStateEngine::new();
    let err = format!(
        "{:?}",
        load_full_state_into(&store, &live)
            .await
            .expect_err("must refuse")
    );
    assert!(
        err.contains("mismatch"),
        "refusal must name the root mismatch: {err}"
    );
    // Fail-closed: live engine untouched (still empty, root != stored root).
    assert!(live.get_account(&user).await.is_none());
    assert_ne!(live.get_state_root().await, root_before);
}

// ===========================================================================
// F2: drop-policy classifier + queue constants
// ===========================================================================

#[test]
fn f2_push_policy_classes() {
    let key = skey(1);
    let proposer = id_of(&key);
    let mk_block = || Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
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
    // Prune is the ONLY droppable class (re-scheduled next cadence).
    assert_eq!(
        persist_push_policy(&PersistJob::Prune { keep_from: 9 }),
        PersistPushPolicy::DropFirst
    );
    // Everything carrying consensus-relevant data waits out a bounded drain.
    assert_eq!(
        persist_push_policy(&PersistJob::Block(mk_block())),
        PersistPushPolicy::BoundedWait
    );
    assert_eq!(
        persist_push_policy(&PersistJob::State {
            height: 1,
            snapshot: vec![]
        }),
        PersistPushPolicy::BoundedWait
    );
    assert_eq!(
        persist_push_policy(&        PersistJob::Domains {
            height: 1,
            bytes: vec![],
            session_keys: vec![],
            bridge: vec![],
            zkml_models: vec![],
            cross_shard: vec![],
        }),
        PersistPushPolicy::BoundedWait
    );
    assert_eq!(
        persist_push_policy(&PersistJob::Finalized {
            height: 1,
            hash: [0u8; 32]
        }),
        PersistPushPolicy::BoundedWait
    );
    assert_eq!(
        persist_push_policy(&PersistJob::Receipts {
            height: 1,
            hash: [0u8; 32],
            txs: vec![],
            statuses: vec![],
            fees: vec![],
            events: vec![],
        }),
        PersistPushPolicy::BoundedWait
    );
    assert_eq!(
        persist_push_policy(&PersistJob::Consensus(Box::default())),
        PersistPushPolicy::BoundedWait
    );
    assert_eq!(
        persist_push_policy(&PersistJob::Flush),
        PersistPushPolicy::BoundedWait
    );
    // Audit numbers pinned: 8192-cap queue, 200ms bounded wait (deadlock-free
    // by the producer→writer→disk proof on `push`).
    assert_eq!(PERSIST_QUEUE_CAP, 8192);
    assert_eq!(PERSIST_BLOCKING_WAIT_MS, 200);
}

// ===========================================================================
// Prune safety: pruned data is never live-needed
// ===========================================================================

#[tokio::test]
async fn prune_safety_pruned_data_never_live_needed() {
    let dir = tmpdir("prune-safe");
    let store = Storage::open(&dir).expect("open");
    let key = skey(7);
    let proposer = id_of(&key);
    // Bodies at 0..12.
    let mut hashes = Vec::new();
    let mut prev = [0u8; 32];
    for h in 0..12u64 {
        let b = test_block(h, prev, proposer, [h as u8; 32]);
        prev = store.put_block(&b).expect("put");
        hashes.push(prev);
    }
    // Tip pointer at 11.
    store.set_finalized(11, &hashes[11]).unwrap();
    // Paired snapshot at 11 + a young domains row at 3 (prune fodder).
    let user = [0x11u8; 32];
    let engine = InMemoryStateEngine::new();
    engine
        .update_account(AccountState::new(user, 500_000))
        .await;
    store_paired_snapshot(&store, &engine, 11, None).await;
    store.put_domains(3, b"old").unwrap();
    store.put_cross_shard(3, b"old").unwrap();

    // Prune bodies below 8 (boundary rule height+1<keep_from keeps 7..).
    let removed = store.prune_blocks_below(8).unwrap();
    assert_eq!(
        removed, 7,
        "heights 0..=6 go, 7.. stay (boundary keeps the link)"
    );
    // Kept bodies verify; pruned bodies are honest misses, never fabrications.
    for h in 7..12u64 {
        let got = store.committed_body(h, &hashes[h as usize]).unwrap();
        assert!(got.is_some(), "kept body {h} must verify");
        assert_eq!(got.unwrap().compute_hash(), hashes[h as usize]);
    }
    for h in 0..7u64 {
        assert!(
            store
                .committed_body(h, &hashes[h as usize])
                .unwrap()
                .is_none(),
            "pruned body {h} must read as an honest miss"
        );
        assert!(
            store.header_at(h).unwrap().is_some(),
            "headers survive bodies at {h} (walk/replay anchor intact)"
        );
    }
    // Tip pointer + paired snapshot survive the prune.
    assert_eq!(store.finalized().unwrap(), Some((11, hashes[11])));
    let (paired_h, _) = store
        .latest_paired_snapshot()
        .unwrap()
        .expect("paired survives");
    assert_eq!(paired_h, 11);
    // Domain-window prune drops the young rows, keeps the paired height.
    store.prune_domains_below(5).unwrap();
    assert!(store.domain_at(3).unwrap().is_none());
    assert!(store.cross_shard_at(3).unwrap().is_none());
    assert!(store.domain_at(11).unwrap().is_some());
}

// ===========================================================================
// Freshness gates: both directions (honest-muted votes, stale does not)
// ===========================================================================

#[test]
fn freshness_gate_both_directions() {
    // Honest + fresh: lag 0 votes.
    assert!(check_validator_set_freshness_with_lag(100, 100, 300).is_ok());
    // Honest-muted: ledger slightly old but inside the ring still votes.
    assert!(check_validator_set_freshness_with_lag(100, 50, 300).is_ok());
    // Boundary is inclusive: lag == max votes.
    assert!(check_validator_set_freshness_with_lag(400, 100, 300).is_ok());
    // Stale: lag max+1 is refused for quorum use (must run observer).
    let err = check_validator_set_freshness_with_lag(401, 100, 300).unwrap_err();
    assert!(err.contains("STALE"), "stale refusal must say STALE: {err}");
    // Ledger AHEAD of state (label corruption) is refused, never trusted.
    let err = check_validator_set_freshness_with_lag(100, 101, 300).unwrap_err();
    assert!(err.contains("AHEAD"), "ahead refusal must say AHEAD: {err}");
    // Env-default entry point agrees on the unambiguous cases regardless of
    // any operator override (lag 0 always fresh; ahead always stale).
    assert!(check_validator_set_freshness(500, 500).is_ok());
    assert!(check_validator_set_freshness(500, 501).is_err());
}

// ===========================================================================
// Crash-tail detector: unpaired snapshot tail is refused, never resumed
// ===========================================================================

#[tokio::test]
async fn crash_tail_unpaired_snapshot_refused() {
    let dir = tmpdir("crash-tail");
    let store = Storage::open(&dir).expect("open");
    // Genuine fresh dir: nothing stored → Ok(None) (fresh start, not an error).
    let fresh = InMemoryStateEngine::new();
    assert!(load_full_state_into(&store, &fresh)
        .await
        .unwrap()
        .is_none());

    // Crash between the two snapshot jobs: state@9 with no domains@9.
    let user = [0x22u8; 32];
    let engine = InMemoryStateEngine::new();
    engine.update_account(AccountState::new(user, 10_000)).await;
    store.put_state(9, &engine.create_snapshot().await).unwrap();
    let live = InMemoryStateEngine::new();
    let err = format!(
        "{:?}",
        load_full_state_into(&store, &live)
            .await
            .expect_err("half snapshot")
    );
    assert!(
        err.contains("both") || err.contains("half") || err.contains("paired"),
        "must refuse the unpaired tail loudly, never resume on half: {err}"
    );
    assert!(
        live.get_account(&user).await.is_none(),
        "refusal leaves live state untouched"
    );
}

// ===========================================================================
// Domain upgrade path: current round-trips, garbage fails closed
// ===========================================================================

#[tokio::test]
async fn domain_upgrade_current_roundtrips_garbage_fails() {
    let engine = InMemoryStateEngine::new();
    let staking = engine.staking_read().await.clone();
    let gov = engine.governance_read().await.clone();
    let dom = DomainSnapshot::capture(&engine, &staking, &gov).await;
    let bytes = bincode::serialize(&dom).unwrap();
    let back = decode_domain_snapshot(&bytes).expect("current shape decodes directly");
    assert_eq!(back.staking.total_burned, dom.staking.total_burned);
    // Truncated/corrupt bytes are a hard error, never a defaulted snapshot.
    assert!(decode_domain_snapshot(&[0xDE, 0xAD, 0xBE, 0xEF]).is_err());
    assert!(decode_domain_snapshot(&[]).is_err());
}

// ===========================================================================
// Genesis bond_genesis airtightness: only fund_genesis may call
// ===========================================================================

#[test]
fn bond_genesis_callers_only_fund_genesis() {
    let srcdir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut calls: Vec<(String, usize, String)> = Vec::new();
    for entry in std::fs::read_dir(&srcdir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        for (i, line) in text.lines().enumerate() {
            if !line.contains("bond_genesis(") {
                continue;
            }
            let t = line.trim_start();
            // Definitions, doc comments and prose are not calls.
            if t.starts_with("///") || t.starts_with("//") || t.starts_with('*') {
                continue;
            }
            if t.contains("fn bond_genesis") || t.contains("bond_genesis`") {
                continue;
            }
            calls.push((
                path.file_name().unwrap().to_string_lossy().into_owned(),
                i + 1,
                line.trim().to_owned(),
            ));
        }
    }
    assert_eq!(
        calls.len(),
        1,
        "exactly one bond_genesis call site may exist (fund_genesis): {calls:?}"
    );
    assert_eq!(
        calls[0].0, "runtime.rs",
        "the call must live in runtime.rs: {calls:?}"
    );
    // The call must sit inside `fund_genesis`: nearest preceding fn item.
    let text = std::fs::read_to_string(srcdir.join("runtime.rs")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let call_line = calls[0].1;
    let mut enclosing = String::new();
    for line in lines[..call_line - 1].iter().rev() {
        let t = line.trim_start();
        if t.starts_with("pub async fn ") || t.starts_with("pub fn ") || t.starts_with("fn ") {
            enclosing = t.to_owned();
            break;
        }
    }
    assert!(
        enclosing.contains("fund_genesis"),
        "bond_genesis must be called from fund_genesis, found in: {enclosing}"
    );
}

// ===========================================================================
// F5 economics: slash-after-reward net outcome pinned (deterministic edge)
// ===========================================================================

#[tokio::test]
async fn f5_slash_after_reward_net_outcome_pinned() {
    use stellereum::consensus::{Vote, VoteKind};
    use stellereum::staking::{
        DOWNTIME_SLASH_BPS, MIN_VALIDATOR_BOND, REWARDS_POOL, STAKING_POOL, UNBONDING_PERIOD_SECS,
    };

    // POLICY (W10.5 canonical downtime evidence + V-P34 fail-closed QC):
    // downtime attribution reads `block.last_qc` (the proposer-chosen QC for
    // height-1, verified against the pre-transition set) and an unverifiable
    // QC moves no stake. The pre-W10.5 shape (empty-sig `precommit_qc` as the
    // 10th miss) is therefore correctly refused with slash 0. This pin keeps
    // the F5 economics (slash burns bonded only, reward survives, maturation
    // intact, deterministic) under a GENUINE QC: a second witness with
    // quorum-alone power signs height 9 omitting the victim, casting the 10th
    // miss for height-9 evidence carried by the height-10 block.
    let w_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let w: [u8; 32] = w_key.verifying_key().to_bytes();
    const W_POWER: u64 = 10 * MIN_VALIDATOR_BOND;

    async fn prepared_engine(w_key: &SigningKey, w: [u8; 32]) -> (InMemoryStateEngine, [u8; 32]) {
        let v = [0xEBu8; 32];
        let e = InMemoryStateEngine::new();
        // Bond victim 2x MIN + witness quorum-alone power.
        e.staking_write()
            .await
            .bond(v, 2 * MIN_VALIDATOR_BOND, 0)
            .unwrap();
        e.staking_write().await.bond(w, W_POWER, 0).unwrap();
        // Native legs the transition touches (else debits fail — ignored but
        // counted — and the test would pin noise instead of economics).
        e.update_account(AccountState::new(STAKING_POOL, u64::MAX / 2))
            .await;
        e.update_account(AccountState::new(REWARDS_POOL, 0)).await;
        e.update_account(AccountState::new(v, 1_000_000)).await;
        // Unbond 0.5x MIN now: leaves slashable immediately (pool-separation
        // proof), matures at TS+PERIOD inside the transition's step 4.
        const TS: u64 = 1_760_000_000;
        e.staking_write()
            .await
            .unbond(v, MIN_VALIDATOR_BOND / 2, TS)
            .unwrap();
        // 9 recorded misses for the victim (threshold 10): the witness signs
        // every height, so only the victim's streak grows.
        let _ = w_key;
        for h in 1..10u64 {
            let burned =
                e.staking_write()
                    .await
                    .note_missed_heights(h, &|id: &[u8; 32]| *id == w, &[v, w]);
            assert_eq!(burned, 0, "threshold not yet reached at height {h}");
        }
        (e, v)
    }

    const TS: u64 = 1_760_000_000;
    const REWARD: u64 = 1_000_000_000;
    let slashable = 2 * MIN_VALIDATOR_BOND - MIN_VALIDATOR_BOND / 2;
    let expected_slash = slashable / 1000; // DOWNTIME_SLASH_BPS = 10 → /1000
    assert_eq!(DOWNTIME_SLASH_BPS, 10);

    async fn apply_once(
        w_key: &SigningKey,
        w: [u8; 32],
    ) -> (
        InMemoryStateEngine,
        stellereum::state_engine::BlockTransitionOutcome,
    ) {
        use stellereum::consensus::{
            register_validator_pq_key, VoteSet,
        };
        use stellereum::post_quantum::{FalconKeypair, PqScheme};
        let (e, v) = prepared_engine(w_key, w).await;
        // Genuine height-9 QC signed by the witness alone (quorum-alone power,
        // omits the victim): verifies under the pre-transition set and casts
        // the victim's 10th miss. FULL-PQ: Falcon-half vote + compiled µQC
        // envelope (a raw ed entry carries no power).
        let w_fk = FalconKeypair::generate_from_seed(0xF5);
        register_validator_pq_key(w, PqScheme::Falcon512, w_fk.public_key.clone());
        let vote = Vote::sign_with_falcon(w_key, &w_fk, 9, 0, VoteKind::Precommit, None);
        assert!(vote.verify(), "witness vote must verify");
        let set0 = e.staking_read().await.to_validator_set();
        let mut vs = VoteSet::new();
        vs.add(vote, &set0, 9, 0, VoteKind::Precommit)
            .expect("genuine witness vote admits");
        let qc = vs
            .certificate_with_parent(None, &set0, Some(&[0u8; 32]))
            .expect("quorum-alone witness compiles a µQC");
        {
            let set = e.staking_read().await.to_validator_set();
            assert!(
                qc.verify(&set),
                "height-9 witness QC must verify under the pre-transition set"
            );
        }
        let block = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 10,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: TS + UNBONDING_PERIOD_SECS,
            proposer: v,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: Some(qc),
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        let out = e.apply_block_transition(&block, REWARD).await;
        (e, out)
    }

    let (e1, out1) = apply_once(&w_key, w).await;
    // Slash fired exactly once, at 0.1% of the post-unbond slashable total.
    assert_eq!(
        out1.slashed, expected_slash,
        "slash burns bonded stake only"
    );
    // Reward was paid DESPITE the same-block slash (pool separation: reward
    // mints to pending_rewards, slash burns bonded) — the deterministic
    // economic edge F5 documents, pinned so any reorder attempt must update it.
    let ledger = e1.staking_read().await;
    let rec = ledger.validators.get(&[0xEBu8; 32]).unwrap();
    assert_eq!(
        rec.pending_rewards, REWARD,
        "same-block reward survives the slash"
    );
    assert_eq!(
        rec.self_bond,
        slashable - expected_slash,
        "slash took bonded stake only"
    );
    assert_eq!(rec.total_slashed, expected_slash);
    assert_eq!(
        ledger.withdrawable_of(&[0xEBu8; 32]),
        MIN_VALIDATOR_BOND / 2,
        "matured unbonding is intact — maturation-vs-slash order is a no-op"
    );
    drop(ledger);

    // Determinism (not-a-fork proof): an identically prepared engine applying
    // the identical block roots identically.
    let (e2, out2) = apply_once(&w_key, w).await;
    assert_eq!(out2.slashed, out1.slashed);
    assert_eq!(e2.get_state_root().await, e1.get_state_root().await);
}

// ===========================================================================
// Fast-path / sequential fee parity (floor_base on both engines)
// ===========================================================================

#[tokio::test]
async fn fee_parity_fast_path_and_sequential_charge_floor() {
    const FLOOR: u64 = 500_000;
    const BAL: u64 = 10_000_000;
    const TS: u64 = 1_760_000_000;
    // 10 independent underpriced plain transfers: the batch shape exercises
    // the multi-wave path (incl. the plain fast path), the singles exercise
    // the sequential loop — both must charge max(declared, floor_base).
    // FULL-PQ: implicit Falcon-512 (registered globally; no surcharge).
    let senders: Vec<u8> = (0..10u8).map(|i| 0x30 + i).collect();
    let txs: Vec<Transaction> = senders
        .iter()
        .map(|s| pq_tx(*s, [0xB0; 32], 1_000, 100, 0))
        .collect();

    let batch_engine = InMemoryStateEngine::new();
    batch_engine.governance_write().await.applied.min_gas_limit = Some(FLOOR);
    for k in &senders {
        batch_engine
            .update_account(AccountState::new(pq_id(*k), BAL))
            .await;
    }
    let (_, _, collected, status, fees) = batch_engine.apply_block_parallel_fees(&txs, TS).await;
    assert_eq!(status, vec![true; 10]);
    assert_eq!(fees, vec![FLOOR; 10], "batch path must charge the floor");
    assert_eq!(collected, FLOOR * 10);

    // Same transactions, one per sequential application: identical per-tx fee.
    for (k, tx) in senders.iter().zip(txs.iter()) {
        let e = InMemoryStateEngine::new();
        e.governance_write().await.applied.min_gas_limit = Some(FLOOR);
        e.update_account(AccountState::new(pq_id(*k), BAL)).await;
        let (_, _, _, s, f) = e
            .apply_block_parallel_fees(std::slice::from_ref(tx), TS)
            .await;
        assert_eq!(s, vec![true]);
        assert_eq!(f, vec![FLOOR], "sequential path must charge the same floor");
    }
}

// ===========================================================================
// Memory caps: eviction never drops consensus-critical data
// ===========================================================================

#[test]
fn memory_caps_eviction_reloads_from_disk_never_attests() {
    // Bounded LRU past cap: coldest evicted LOUDLY (counted), survivors
    // readable, evicted re-served from disk via the loader.
    let mut c = memory_bounds::BoundedLruCache::new("test", 2);
    c.insert([0x01u8; 32], 10u64);
    c.insert([0x02u8; 32], 20u64);
    assert_eq!(c.evictions(), 0);
    c.insert([0x03u8; 32], 30u64);
    assert_eq!(c.len(), 2);
    assert_eq!(c.evictions(), 1, "eviction is counted (loud path exists)");
    // Evicted key reloads from disk: no consensus data lost while a loader
    // (the disk side) can serve it.
    let reloaded = c.get_or_load([0x01u8; 32], |_| Ok::<_, String>(Some(10u64)));
    assert_eq!(reloaded, Some(10u64));
    // Loader FAILURE reads as a miss (fail-open-to-None), which is safe ONLY
    // because no caller treats None as a positive attestation (see the
    // fail-open audit on the module docs): PQ admission refuses on None,
    // body fetch refetches on None.
    let mut c2 = memory_bounds::BoundedLruCache::new("test2", 1);
    let miss: Option<u64> = c2.get_or_load([0x09u8; 32], |_| Err::<_, String>("disk down".into()));
    assert_eq!(miss, None);
    let miss2: Option<u64> = c2.get_or_load([0x09u8; 32], |_| Ok::<_, String>(None));
    assert_eq!(miss2, None);
}

#[test]
fn memory_caps_vote_history_prune_preserves_lock() {
    let mut h: memory_bounds::VoteRoundHistory<Vec<u8>> = memory_bounds::VoteRoundHistory::new();
    h.set_lock([0xABu8; 32], 3);
    for r in 1..=6u64 {
        h.insert(r, vec![r as u8]);
    }
    h.advance_to(6);
    // Window current-2..=current: at most 3 buckets, old ones dropped…
    assert!(h.len() <= 3, "history stays bounded: {}", h.len());
    assert!(h.get(1).is_none() && h.get(2).is_none() && h.get(3).is_none());
    // …while the Tendermint lock survives the prune untouched.
    assert_eq!(h.lock_info(), Some(([0xABu8; 32], 3)));
    // New height drops every bucket (no cross-height accumulation).
    h.reset_for_height();
    assert!(h.is_empty());
}

#[test]
fn memory_caps_watermark_is_warn_only_pure() {
    assert!(!memory_bounds::accounts_over_watermark(0));
    assert!(memory_bounds::accounts_over_watermark(u64::MAX));
    assert_eq!(
        memory_bounds::estimate_accounts_bytes(5_000_000),
        5_000_000 * 384,
        "5M accounts ≈ 1.9GiB hot state (the warn-at-OOM datum)"
    );
    assert!(
        memory_bounds::snapshot_chunk_accounts() >= 1,
        "chunk size clamps to ≥1"
    );
}

// ===========================================================================
// Snapshot chunked streaming bounds + validate-then-commit (F10)
// ===========================================================================

#[tokio::test]
async fn chunked_roundtrip_validate_then_commit_and_preserve_twin() {
    // Source with 5 accounts → 3 chunks at per=2 (streaming bound: peak ≈
    // one chunk, not full state).
    let src = InMemoryStateEngine::new();
    for i in 0..5u8 {
        src.update_account(AccountState::new([0x40 + i; 32], 1000 + i as u64))
            .await;
    }
    let chunks = src.create_snapshot_chunked(Some(2)).await;
    assert_eq!(chunks.len(), 3, "5 accounts at 2/chunk stream as 3 chunks");

    // Reorg twin installs; root matches the monolithic restore.
    let reorg = InMemoryStateEngine::new();
    reorg
        .restore_snapshot_chunked(&chunks)
        .await
        .expect("valid chunks install");
    let mono = InMemoryStateEngine::new();
    mono.restore_snapshot(&src.create_snapshot().await)
        .await
        .unwrap();
    assert_eq!(reorg.get_state_root().await, mono.get_state_root().await);

    // Poisoned middle chunk: Err AND live state untouched (F10 fix — the old
    // code wiped map+trie+replay before decoding).
    let victim = InMemoryStateEngine::new();
    let keep = [0x77u8; 32];
    victim
        .update_account(AccountState::new(keep, 999_999))
        .await;
    victim
        .restore_cross_shard_consumed(&[fabric_key(1, 2)])
        .await;
    let root_before = victim.get_state_root().await;
    let mut bad = chunks.clone();
    bad[1] = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let err = victim
        .restore_snapshot_chunked(&bad)
        .await
        .expect_err("poisoned chunk");
    assert!(err.contains('1'), "error names the chunk index: {err}");
    assert_eq!(victim.get_account(&keep).await.unwrap().balance, 999_999);
    assert_eq!(victim.cross_shard_consumed_len().await, 1);
    assert_eq!(victim.get_state_root().await, root_before);

    // Preserve twin: accounts replaced, replay sets kept — root equals the
    // monolithic preserve-restore of the same inputs.
    let keeper = InMemoryStateEngine::new();
    keeper.update_account(AccountState::new(keep, 1)).await;
    keeper
        .restore_cross_shard_consumed(&[fabric_key(3, 4)])
        .await;
    keeper
        .restore_snapshot_chunked_preserve_replay_sets(&chunks)
        .await
        .expect("preserve installs");
    assert_eq!(
        keeper.cross_shard_consumed_len().await,
        1,
        "replay preserved"
    );
    assert!(keeper.is_cross_shard_consumed(&fabric_key(3, 4)).await);
    let reference = InMemoryStateEngine::new();
    reference
        .restore_snapshot_preserve_replay_sets(&src.create_snapshot().await)
        .await
        .unwrap();
    reference
        .restore_cross_shard_consumed(&[fabric_key(3, 4)])
        .await;
    assert_eq!(
        keeper.get_state_root().await,
        reference.get_state_root().await,
        "chunked preserve twin roots identically to the monolithic preserve path"
    );
}

#[test]
fn chunk_streaming_bounds_pure() {
    // Batch planner: exact tiling, no drops, no overlaps, zero-width safe.
    assert_eq!(plan_chunk_batches(10, 4), vec![(0, 4), (4, 8), (8, 10)]);
    assert!(plan_chunk_batches(0, 4).is_empty());
    assert_eq!(plan_chunk_batches(3, 0), vec![(0, 1), (1, 2), (2, 3)]);
    // Large blobs assemble strictly serially (one chunk stream on weak nodes).
    assert_eq!(chunk_batch_for_blob(50), 1);
    assert_eq!(chunk_batch_for_blob(8), 4);
    // Whole-blob budget grows with size (slow-but-moving links survive).
    assert!(snapshot_blob_budget_ms(10) > snapshot_blob_budget_ms(5));
}

// ===========================================================================
// F7: pq_keys blob installs on the sync path (fetch-set == install-set)
// ===========================================================================

#[tokio::test]
async fn f7_pq_keys_blob_installs_on_sync() {
    use stellereum::post_quantum::{derive_pq_address, PqScheme};
    // M-03: the blob entry must validate against its account leaf
    // (blake3(pk) == leaf pubkey_hash AND derive == address), so the test
    // pins a REAL key: the leaf carries the hash, the blob carries the key.
    let scheme = PqScheme::Falcon512;
    let pk = Transaction::sample_falcon512_pubkey(0xF7);
    let salt = [0x01u8; 16];
    let addr = derive_pq_address(scheme, &pk, &salt);
    let akey = [b"a:".to_vec(), addr.to_vec()].concat();
    let aval = bincode::serialize(&(scheme, pk.clone(), salt)).unwrap();
    let blob = bincode::serialize(&vec![(akey, aval)]).unwrap();
    // Leaf WITHOUT the key (proves the restore installs it): balance +
    // scheme + pinned hash, synced to the trie via update_account.
    let mut leaf = AccountState::new(addr, 1_000_000);
    leaf.scheme = scheme;
    leaf.pubkey_hash = Some(*blake3::hash(&pk).as_bytes());

    // Direct restore: corrupt bytes fail closed, good bytes pin the key.
    let e = InMemoryStateEngine::new();
    assert!(e.restore_pq_keys(&[0xDE, 0xAD]).await.is_err());
    e.update_account(leaf.clone()).await;
    e.restore_pq_keys(&blob).await.expect("pq blob installs");
    let (got_scheme, got) = e
        .get_pinned_pubkey(&addr)
        .expect("key pinned after restore");
    assert_eq!(got_scheme, scheme);
    assert_eq!(got, pk);
    assert_eq!(
        e.get_pinned_pubkey_with_salt(&addr),
        Some((scheme, pk.clone(), salt)),
        "restore preserves the pinned salt"
    );

    // Sync path: the blob travels beside the snapshot and lands on the target
    // WITHOUT moving the root (keys are not in the digest; they ride the
    // accounts snapshot's pinned pubkey_hash).
    let src = InMemoryStateEngine::new();
    let user = [0x52u8; 32];
    src.update_account(AccountState::new(user, 777_000)).await;
    src.update_account(leaf).await;
    let root = src.get_state_root().await;
    let snap = src.create_snapshot().await;
    let target = InMemoryStateEngine::new();
    fast_sync_state(
        &target,
        root,
        || async { Some(snap.clone()) },
        |kind: &'static str| {
            let blob = blob.clone();
            async move {
                if kind == "pq_keys" {
                    Some(blob)
                } else {
                    None
                }
            }
        },
    )
    .await
    .expect("sync with pq blob verifies");
    assert_eq!(target.get_state_root().await, root);
    assert_eq!(
        target.get_pinned_pubkey_with_salt(&addr),
        Some((scheme, pk.clone(), salt)),
        "pq keys installed with pinned salt, not skipped"
    );
}

// ===========================================================================
// F11: receipt fallback matches the block path (live paths pass explicit fees)
// ===========================================================================

#[tokio::test]
async fn receipts_short_fees_match_block_path() {
    let dir = tmpdir("receipts-f11");
    let store = Storage::open(&dir).expect("open");
    let k = skey(0x11);
    let tx0 = Transaction::sign(&k, [0xB0; 32], 0, 600_000, 0, 1, 1);
    let tx1 = Transaction::sign(&k, [0xB0; 32], 0, 700_000, 1, 1, 1);
    let txs = vec![tx0.clone(), tx1.clone()];
    let hash = [0x77u8; 32];
    // Truncated fees (one entry for two txs): success falls back to the
    // BLOCK-path charge (declared gas_limit), exactly what commit_native took.
    store
        .put_receipts_for_block(5, &hash, &txs, &[true, true], &[600_000])
        .unwrap();
    let r0 = store
        .get_receipt(&tx0.compute_tx_hash())
        .unwrap()
        .expect("r0");
    let r1 = store
        .get_receipt(&tx1.compute_tx_hash())
        .unwrap()
        .expect("r1");
    assert_eq!(r0.fee_charged, 600_000, "explicit fee filed verbatim");
    assert_eq!(
        r1.fee_charged, 700_000,
        "short-fees success falls back to gas_limit (block path)"
    );
    // Short statuses fail closed (missing = failed) with zero fee (fees short
    // too, so the failure fallback — 0-on-fail — applies, not an explicit fee).
    store
        .put_receipts_for_block(6, &hash, &txs, &[true], &[600_000])
        .unwrap();
    let r1b = store
        .get_receipt(&tx1.compute_tx_hash())
        .unwrap()
        .expect("r1b");
    assert!(!r1b.success);
    assert_eq!(r1b.fee_charged, 0);
}

// ===========================================================================
// F8: finalized single-key blob survives a torn legacy write
// ===========================================================================

#[test]
fn finalized_blob_survives_half_written_legacy_keys() {
    let dir = tmpdir("finalized-f8");
    let store = Storage::open(&dir).expect("open");
    assert_eq!(store.finalized().unwrap(), None);
    store.set_finalized(7, &[9u8; 32]).unwrap();
    assert_eq!(store.finalized().unwrap(), Some((7, [9u8; 32])));
    // Simulate a crash torn BETWEEN the legacy keys: height garbage, hash
    // intact. The single-key blob still reports the complete pointer.
    store.set_meta("finalized_height", b"torn").unwrap();
    assert_eq!(
        store.finalized().unwrap(),
        Some((7, [9u8; 32])),
        "blob outlives a torn legacy pair"
    );
    // And a rotted blob falls back to the legacy pair instead of bricking.
    store.set_meta("finalized_blob", b"junk").unwrap();
    store
        .set_meta("finalized_height", &7u64.to_be_bytes())
        .unwrap();
    assert_eq!(
        store.finalized().unwrap(),
        Some((7, [9u8; 32])),
        "legacy pair backs a rotted blob"
    );
    // Open-time sweep is a no-op on a clean store (idempotent, never deletes).
    assert_eq!(store.sweep_dangling_indexes().unwrap(), 0);
    drop(store); // release the sled lock before reopening the same dir
    let reopened = Storage::open(&dir).expect("reopen");
    assert_eq!(reopened.finalized().unwrap(), Some((7, [9u8; 32])));
}

// ===========================================================================
// F4 residue: tail-anchor refuses forgery-shaped inputs (comment pins trust)
// ===========================================================================

#[tokio::test]
async fn tail_anchor_refuses_gaps_and_empty() {
    use stellereum::consensus::ValidatorSet;
    use stellereum::sync::verify_snapshot_anchor_tail;
    let vset = ValidatorSet::from_list(vec![([0x01u8; 32], 1)]);
    // No header at height 0 to anchor on.
    let err = verify_snapshot_anchor_tail(0, &vset, |_| async { None })
        .await
        .unwrap_err();
    assert!(err.contains("height 0"), "empty anchor refused: {err}");
    // Missing window header is a refusal, never a skip (unverifiable tail).
    let err = verify_snapshot_anchor_tail(100, &vset, |_| async { None })
        .await
        .unwrap_err();
    assert!(err.contains("no header"), "gap refused fail-closed: {err}");
}
