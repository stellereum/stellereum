use super::blocks::{LegacyStoredReceipt, LegacyStoredReceiptWithFee};
use super::*;
use crate::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use crate::state_engine::{AccountState, InMemoryStateEngine};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn tmp() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "stell_store_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ))
}

fn block(height: u64, prev: [u8; 32], signer: &SigningKey, tx: Option<Transaction>) -> Block {
    let transactions: Vec<Transaction> = tx.into_iter().collect();
    let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root: [height as u8; 32],
        transactions,
        cross_shard_out: vec![],
        timestamp: height,
        proposer: signer.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        cnvrf_v3: None,
        round: 0,
    };
    b.sign_block(signer);
    b
}

#[test]
fn block_store_roundtrip_and_height_index() {
    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    let sk = SigningKey::generate(&mut OsRng);

    let b0 = block(0, [0u8; 32], &sk, None);
    let h0 = st.put_block(&b0).unwrap();
    let b1 = block(1, h0, &sk, None);
    let h1 = st.put_block(&b1).unwrap();

    assert_eq!(st.block_count().expect("count"), 2);
    let got = st.get_block(&h1).unwrap().unwrap();
    assert_eq!(got.height, 1);
    assert_eq!(st.hashes_at_height(1).unwrap(), vec![h1]);
    assert_eq!(st.hashes_at_height(5).unwrap().len(), 0);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn finalized_meta_roundtrip() {
    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    assert!(st.finalized().unwrap().is_none());
    st.set_finalized(7, &[9u8; 32]).unwrap();
    let (h, hash) = st.finalized().unwrap().unwrap();
    assert_eq!(h, 7);
    assert_eq!(hash, [9u8; 32]);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn consensus_checkpoint_roundtrip() {
    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    assert!(st.consensus().unwrap().is_none());
    let cp = ConsensusCheckpoint {
        height: 11,
        round: 2,
        locked_hash: Some([7u8; 32]),
        locked_round: 1,
        finalized_height: 10,
        finalized_hash: [9u8; 32],
    };
    st.set_consensus(&cp).unwrap();
    let got = st.consensus().unwrap().unwrap();
    assert_eq!(got.height, 11);
    assert_eq!(got.round, 2);
    assert_eq!(got.locked_hash, Some([7u8; 32]));
    assert_eq!(got.finalized_height, 10);
    std::fs::remove_dir_all(&dir).ok();
}

/// FINDING C: the write-ahead vote watermark is a SEPARATE durable record
/// (one fsynced meta key), so it survives a crash between the vote and the
/// next consensus checkpoint. The checkpoint stays at round 0 while the
/// watermark says round 300 — which is exactly the state a restart must
/// restore from.
#[test]
fn vote_watermark_survives_a_crash_before_the_checkpoint() {
    let dir = tmp();
    {
        let st = Storage::open(&dir).unwrap();
        st.set_consensus(&ConsensusCheckpoint {
            height: 7,
            round: 0,
            locked_hash: None,
            locked_round: 0,
            finalized_height: 6,
            finalized_hash: [3u8; 32],
        })
        .unwrap();
        let mut wm = VoteWatermark::default();
        wm.note(VoteWatermarkEntry {
            height: 7,
            round: 300,
            kind: 0,
            target: Some([4u8; 32]),
            shard_id: 1,
        });
        st.persist_vote_watermark(&wm).unwrap();
    }
    let st = Storage::open(&dir).unwrap();
    let wm = st.vote_watermark().unwrap().unwrap();
    assert_eq!(wm.floor_round(7), Some(300));
    assert_eq!(wm.prevote_at(7).unwrap().shard_id, 1);
    // The checkpoint rewrite path cannot erase it (separate key).
    st.set_consensus(&ConsensusCheckpoint {
        height: 8,
        round: 0,
        locked_hash: None,
        locked_round: 0,
        finalized_height: 7,
        finalized_hash: [5u8; 32],
    })
    .unwrap();
    assert_eq!(
        st.vote_watermark().unwrap().unwrap().floor_round(7),
        Some(300)
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn state_snapshot_roundtrip_and_prune() {
    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    st.put_state(1, b"one").unwrap();
    st.put_state(2, b"two").unwrap();
    st.put_state(3, b"three").unwrap();
    assert_eq!(st.latest_state().unwrap().unwrap(), (3, b"three".to_vec()));
    // Key-only read used by the upgrade-halt boot guard: same height as
    // `latest_state`, without materialising the snapshot value.
    assert_eq!(st.latest_state_height().unwrap(), Some(3));
    let pruned = st.prune_state_below(3).unwrap();
    assert_eq!(pruned, 2);
    assert_eq!(st.latest_state().unwrap().unwrap(), (3, b"three".to_vec()));
    assert_eq!(st.latest_state_height().unwrap(), Some(3));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn async_persistence_writes_blocks_and_state() {
    let dir = tmp();
    let st = Arc::new(Storage::open(&dir).unwrap());
    let ap = AsyncPersistence::start(st.clone());
    let sk = SigningKey::generate(&mut OsRng);

    let b = block(0, [0u8; 32], &sk, None);
    let bh = b.compute_hash();
    ap.enqueue_block(b);
    ap.enqueue_finalized(0, bh);

    // snapshot of an engine with one funded account
    let engine = InMemoryStateEngine::new();
    let who = sk.verifying_key().to_bytes();
    engine.update_account(AccountState::new(who, 42)).await;
    ap.snapshot_state(&engine, 0).await;

    // flush barrier: everything enqueued before it must be durable
    ap.request_flush();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert!(
        st.get_block(&bh).unwrap().is_some(),
        "block must be persisted"
    );
    assert_eq!(st.finalized().unwrap().unwrap().0, 0);
    assert!(
        st.latest_state().unwrap().is_some(),
        "state must be persisted"
    );

    std::fs::remove_dir_all(&dir).ok();
}

fn fast_drain_cfg() -> ShutdownDrainConfig {
    ShutdownDrainConfig {
        cap: std::time::Duration::from_secs(5),
        poll: std::time::Duration::from_millis(1),
        log_every: std::time::Duration::from_secs(60),
        settle_grace: std::time::Duration::from_millis(1),
    }
}

#[tokio::test]
async fn shutdown_drain_returns_at_once_when_queue_empty() {
    let out = wait_for_persist_drain_with(|| 0, fast_drain_cfg()).await;
    assert_eq!(
        out,
        ShutdownDrainOutcome {
            drained: true,
            last_pending: 0
        }
    );
}

#[tokio::test]
async fn shutdown_drain_waits_until_queue_empties() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let depth = Arc::new(AtomicU64::new(3));
    let writer = depth.clone();
    tokio::spawn(async move {
        for _ in 0..3 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            writer.fetch_sub(1, Ordering::Relaxed);
        }
    });
    let out = wait_for_persist_drain_with(|| depth.load(Ordering::Relaxed), fast_drain_cfg()).await;
    assert_eq!(
        out,
        ShutdownDrainOutcome {
            drained: true,
            last_pending: 0
        }
    );
}

#[tokio::test]
async fn shutdown_drain_caps_when_queue_never_empties() {
    let cfg = ShutdownDrainConfig {
        cap: std::time::Duration::from_millis(50),
        ..fast_drain_cfg()
    };
    let start = std::time::Instant::now();
    let out = wait_for_persist_drain_with(|| 7, cfg).await;
    assert_eq!(
        out,
        ShutdownDrainOutcome {
            drained: false,
            last_pending: 7
        }
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "cap must bound the wait"
    );
}

#[tokio::test]
async fn async_persistence_pending_starts_empty() {
    let dir = tmp();
    let st = Arc::new(Storage::open(&dir).unwrap());
    let ap = AsyncPersistence::start(st);
    assert_eq!(ap.pending(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn load_state_restores_balances() {
    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    let engine = InMemoryStateEngine::new();
    let who = [7u8; 32];
    engine.update_account(AccountState::new(who, 1234)).await;
    let snap = engine.create_snapshot().await;
    st.put_state(5, &snap).unwrap();

    let engine2 = InMemoryStateEngine::new();
    let h = load_state_into(&st, &engine2).await.unwrap();
    assert_eq!(h, Some(5));
    assert_eq!(engine2.get_account(&who).await.unwrap().balance, 1234);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn full_state_restore_preserves_accounts_tokens_and_contracts() {
    use crate::token::TokenMetadata;

    // (func (export "double") (param i64) (result i64) local.get 0; i64.const 2; i64.mul)
    const DOUBLE_WASM: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60, 0x01, 0x7e, 0x01,
        0x7e, 0x03, 0x02, 0x01, 0x00, 0x07, 0x0a, 0x01, 0x06, 0x64, 0x6f, 0x75, 0x62, 0x6c, 0x65,
        0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x42, 0x02, 0x7e, 0x0b,
    ];

    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    let engine = InMemoryStateEngine::new();
    let who = [7u8; 32];
    engine.update_account(AccountState::new(who, 5_000)).await;

    let meta = TokenMetadata {
        name: "Wrapped".into(),
        symbol: "W".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: [0u8; 32],
        paused: false,
        description: String::new(),
    };
    let tid = engine.create_token(who, meta, 1_000).await.unwrap();
    let caddr = engine
        .deploy_contract(who, DOUBLE_WASM.to_vec(), 0)
        .await
        .unwrap();

    // Persist accounts + domains at height 9.
    st.put_state(9, &engine.create_snapshot().await).unwrap();
    let snap = DomainSnapshot::capture(
        &engine,
        &crate::staking::StakingLedger::new(),
        &crate::governance::Governance::new(),
    )
    .await;
    st.put_domains(9, &bincode::serialize(&snap).unwrap())
        .unwrap();

    // Restore into a fresh engine.
    let engine2 = InMemoryStateEngine::new();
    let loaded = load_full_state_into(&st, &engine2).await.unwrap().unwrap();
    assert_eq!(loaded.0, 9);
    assert_eq!(engine2.get_account(&who).await.unwrap().balance, 5_000);
    assert_eq!(
        engine2.token_balance(&tid, &who).await,
        1_000,
        "token registry restored"
    );
    assert!(
        engine2.get_contract(&caddr).await.is_some(),
        "contract registry restored"
    );
    // SPV proof for the restored token balance still verifies against the root.
    assert!(engine2.get_token_balance_proof(&tid, &who).await.is_some());

    std::fs::remove_dir_all(&dir).ok();
}

/// Snapshot label/content binding (restart crash-loop regression).
///
/// Live shape: a snapshot labeled S must hold ONLY post-S state, because
/// the boot check (`verify_restored_root`) compares it against
/// `header(S+1).state_root`. The old poll-time cross-shard capture read a
/// replay set advanced by later heights and persisted it under label S;
/// the restored engine then rooted differently from the anchor and every
/// restart died with `restore root mismatch`. The fix (main.rs snapshot
/// block) captures the replay bytes at submit quiescence and reuses them
/// verbatim at poll, so this test pins the healthy end-to-end shape:
/// persist a fully consistent snapshot for S (accounts, domains, aux AND
/// the replay set, all captured pre-apply), anchor it with the S+1 header
/// committing to the pre-apply root, advance the live engine with a REAL
/// block apply, then reboot-load from the store and require the verify to
/// pass. Non-empty replay sets throughout: empty sets are
/// digest-invisible and would make this test vacuous.
#[tokio::test]
async fn snapshot_at_s_verifies_after_real_apply_to_s_plus_1() {
    use crate::sharding::{CrossShardKey, CrossShardReplaySnapshot};

    const S: u64 = 100;
    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    let sk = SigningKey::generate(&mut OsRng);

    // Live engine at post-S state, with NON-EMPTY replay sets.
    let engine = InMemoryStateEngine::new();
    let who = [11u8; 32];
    engine
        .update_account(AccountState::new(who, 1_000_000))
        .await;
    engine
        .restore_cross_shard_replay(&CrossShardReplaySnapshot {
            engine_consumed: vec![CrossShardKey {
                source_shard: 1,
                finalized_in_block: [2u8; 32],
                msg_id: [3u8; 32],
            }],
            completed: vec![[4u8; 32]],
            ..Default::default()
        })
        .await;
    let root_s = engine.get_state_root().await;

    // Capture the FULL snapshot exactly as the live path does (accounts +
    // domains + every aux domain + the replay set, all pre-apply).
    let accounts = clone_account_snapshot(&engine).await;
    let state_bytes = serialize_off_tick(accounts).await.expect("encode accounts");
    let staking = engine.staking_read().await.clone();
    let gov = engine.governance_read().await.clone();
    let domains = DomainSnapshot::capture(&engine, &staking, &gov).await;
    let domain_bytes = serialize_off_tick(domains).await.expect("encode domains");
    let session_keys = engine.session_keys_snapshot().await;
    let bridge = engine.bridge_snapshot().await;
    let zkml_models = engine.zkml_models_snapshot().await;
    let cross_shard = {
        let mut engine_consumed = engine.cross_shard_consumed_snapshot().await;
        engine_consumed.sort();
        let mut completed = engine.cross_shard_completed_snapshot().await;
        completed.sort();
        let xpc = engine.xpc_snapshot().await;
        bincode::serialize(&CrossShardReplaySnapshot {
            engine_consumed,
            completed,
            xpc,
            ..Default::default()
        })
        .expect("encode cross-shard")
    };
    st.put_state(S, &state_bytes).unwrap();
    st.put_domains(S, &domain_bytes).unwrap();
    st.put_session_keys(S, &session_keys).unwrap();
    st.put_bridge(S, &bridge).unwrap();
    st.put_zkml_models(S, &zkml_models).unwrap();
    st.put_cross_shard(S, &cross_shard).unwrap();

    // Anchor: the S+1 header commits to the PRE-apply (post-S) root — the
    // proposer rule `expected_restore_root` relies on.
    let mut anchor = block(S + 1, [9u8; 32], &sk, None);
    anchor.state_root = root_s;
    let anchor_hash = anchor.compute_hash();
    st.put_header(&BlockHeaderRecord::of(&anchor)).unwrap();
    st.set_finalized(S + 1, &anchor_hash).unwrap();

    // Advance the live engine with a REAL block apply (the block reward
    // moves the root) plus newer replay activity, the way S+1
    // finalization would: the persisted snapshot must stay S-pinned
    // regardless.
    let mut next = block(S + 1, [9u8; 32], &sk, None);
    next.state_root = root_s;
    engine.apply_block_transition(&next, 500).await;
    engine
        .restore_cross_shard_replay(&CrossShardReplaySnapshot {
            engine_consumed: vec![CrossShardKey {
                source_shard: 1,
                finalized_in_block: [5u8; 32],
                msg_id: [6u8; 32],
            }],
            completed: vec![[7u8; 32]],
            ..Default::default()
        })
        .await;
    assert_ne!(
        engine.get_state_root().await,
        root_s,
        "the S+1 apply must move the live root, or the test proves nothing"
    );

    // Reboot: fresh engine, load from the store, verify must pass.
    let fresh = InMemoryStateEngine::new();
    let loaded = load_full_state_into(&st, &fresh)
        .await
        .expect("consistent snapshot S must restore");
    assert_eq!(loaded.map(|(h, _, _)| h), Some(S));
    assert_eq!(fresh.get_state_root().await, root_s);

    std::fs::remove_dir_all(&dir).ok();
}

/// Mixed-height snapshot must fail the restore verify: accounts/domains at
/// S, replay bytes from post-S+1 activity, label S. This is the exact
/// persisted shape the old poll-time cross-shard capture produced (see the
/// test above for the fixed shape). `load_full_state_into` must refuse it
/// with `restore root mismatch` instead of installing a forked engine.
#[tokio::test]
async fn mixed_height_cross_shard_snapshot_fails_restore_verify() {
    use crate::sharding::{CrossShardKey, CrossShardReplaySnapshot};

    const S: u64 = 100;
    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    let sk = SigningKey::generate(&mut OsRng);

    let engine = InMemoryStateEngine::new();
    let who = [11u8; 32];
    engine
        .update_account(AccountState::new(who, 1_000_000))
        .await;
    engine
        .restore_cross_shard_replay(&CrossShardReplaySnapshot {
            engine_consumed: vec![CrossShardKey {
                source_shard: 1,
                finalized_in_block: [2u8; 32],
                msg_id: [3u8; 32],
            }],
            completed: vec![[4u8; 32]],
            ..Default::default()
        })
        .await;
    let root_s = engine.get_state_root().await;

    // Accounts/domains/aux captured at S (pre-apply), exactly as live.
    let accounts = clone_account_snapshot(&engine).await;
    let state_bytes = serialize_off_tick(accounts).await.expect("encode accounts");
    let staking = engine.staking_read().await.clone();
    let gov = engine.governance_read().await.clone();
    let domains = DomainSnapshot::capture(&engine, &staking, &gov).await;
    let domain_bytes = serialize_off_tick(domains).await.expect("encode domains");
    let session_keys = engine.session_keys_snapshot().await;
    let bridge = engine.bridge_snapshot().await;
    let zkml_models = engine.zkml_models_snapshot().await;
    let cross_shard_s = {
        let mut engine_consumed = engine.cross_shard_consumed_snapshot().await;
        engine_consumed.sort();
        let mut completed = engine.cross_shard_completed_snapshot().await;
        completed.sort();
        let xpc = engine.xpc_snapshot().await;
        bincode::serialize(&CrossShardReplaySnapshot {
            engine_consumed,
            completed,
            xpc,
            ..Default::default()
        })
        .expect("encode cross-shard")
    };

    // S+1 activity moves the engine on (real apply + newer replay set).
    let mut next = block(S + 1, [9u8; 32], &sk, None);
    next.state_root = root_s;
    engine.apply_block_transition(&next, 500).await;
    engine
        .restore_cross_shard_replay(&CrossShardReplaySnapshot {
            engine_consumed: vec![CrossShardKey {
                source_shard: 1,
                finalized_in_block: [5u8; 32],
                msg_id: [6u8; 32],
            }],
            completed: vec![[7u8; 32]],
            ..Default::default()
        })
        .await;
    // Replay bytes captured AFTER the advance (the old poll-time bug).
    let cross_shard_newer = {
        let mut engine_consumed = engine.cross_shard_consumed_snapshot().await;
        engine_consumed.sort();
        let mut completed = engine.cross_shard_completed_snapshot().await;
        completed.sort();
        let xpc = engine.xpc_snapshot().await;
        bincode::serialize(&CrossShardReplaySnapshot {
            engine_consumed,
            completed,
            xpc,
            ..Default::default()
        })
        .expect("encode cross-shard")
    };
    assert_ne!(
        cross_shard_newer, cross_shard_s,
        "the replay set must advance, or the mixed-height shape is vacuous"
    );

    // Persisted under label S with the S+1 anchor, like the old bug did.
    st.put_state(S, &state_bytes).unwrap();
    st.put_domains(S, &domain_bytes).unwrap();
    st.put_session_keys(S, &session_keys).unwrap();
    st.put_bridge(S, &bridge).unwrap();
    st.put_zkml_models(S, &zkml_models).unwrap();
    st.put_cross_shard(S, &cross_shard_newer).unwrap();
    let mut anchor = block(S + 1, [9u8; 32], &sk, None);
    anchor.state_root = root_s;
    st.put_header(&BlockHeaderRecord::of(&anchor)).unwrap();
    st.set_finalized(S + 1, &anchor.compute_hash()).unwrap();

    let fresh = InMemoryStateEngine::new();
    let err = load_full_state_into(&st, &fresh)
        .await
        .expect_err("mixed-height snapshot must be refused");
    assert!(
        err.to_string()
            .contains(&format!("restore root mismatch at height {S}")),
        "unexpected error: {err}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn pre_e2_domain_snapshot_upgrades_staking_counters_to_zero() {
    use crate::staking::{
        StakingLedger, StakingLedgerV1, MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER,
    };

    // A ledger with real content, as a pre-E2 node would have held it.
    let val = [0xA1u8; 32];
    let delegator = [0xB2u8; 32];
    let mut ledger = StakingLedger::new();
    ledger
        .bond(val, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
        .unwrap();
    ledger.delegate(delegator, val, 2_000_000_000).unwrap();
    ledger.slash(val, 1_000).unwrap(); // 10%: total_burned is non-zero
    assert!(ledger.total_burned > 0);

    // The CURRENT shape round-trips through the primary path untouched.
    let fresh = DomainSnapshot {
        staking: ledger.clone(),
        ..Default::default()
    };
    let fresh_bytes = bincode::serialize(&fresh).unwrap();
    let back = decode_domain_snapshot(&fresh_bytes).unwrap();
    assert_eq!(back.staking.total_burned, ledger.total_burned);
    assert_eq!(back.staking.rewards_pool, 0);
    assert_eq!(back.staking.rewards_minted, 0);

    // The OLD shape: same six staking fields, no rewards counters, no
    // governance locks — byte-identical to what a pre-E2 node wrote.
    let old = DomainSnapshotV1 {
        tokens: fresh.tokens.clone(),
        contracts: fresh.contracts.clone(),
        orderbooks: fresh.orderbooks.clone(),
        pmm: fresh.pmm.clone(),
        pmm_usdt_token: fresh.pmm_usdt_token,
        pmm_treasury: fresh.pmm_treasury,
        order_escrow: fresh.order_escrow.clone(),
        staking: StakingLedgerV1 {
            validators: ledger.validators.clone(),
            delegations: ledger.delegations.clone(),
            delegator_rewards: ledger.delegator_rewards.clone(),
            unbonding: ledger.unbonding.clone(),
            withdrawable: ledger.withdrawable.clone(),
            total_burned: ledger.total_burned,
        },
        governance: fresh.governance.clone(),
        oracle: fresh.oracle.clone(),
    };
    let old_bytes = bincode::serialize(&old).unwrap();
    // The old bytes genuinely do NOT decode as the current struct (this
    // is the brick the fallback exists for — without it the restore path
    // hard-errors on every pre-E2 data directory).
    assert!(
        bincode::deserialize::<DomainSnapshot>(&old_bytes).is_err(),
        "pre-E2 bytes must fail the direct decode, or the fallback is untested"
    );
    // ... but the restore helper upgrades them.
    let up = decode_domain_snapshot(&old_bytes).unwrap();
    assert_eq!(up.staking.validators, ledger.validators, "bonds survive");
    assert_eq!(
        up.staking.delegations, ledger.delegations,
        "positions survive"
    );
    assert_eq!(
        up.staking.delegator_rewards, ledger.delegator_rewards,
        "reward entries survive"
    );
    assert_eq!(up.staking.unbonding, ledger.unbonding, "unbondings survive");
    assert_eq!(
        up.staking.withdrawable, ledger.withdrawable,
        "matured funds survive"
    );
    assert_eq!(
        up.staking.total_burned, ledger.total_burned,
        "burn history survives"
    );
    assert_eq!(up.staking.rewards_pool, 0, "new counter starts at zero");
    assert_eq!(up.staking.rewards_minted, 0, "new counter starts at zero");
    assert!(up.staking.locked_governance.is_empty(), "no phantom locks");
    assert_eq!(
        up.governance.next_id, fresh.governance.next_id,
        "sibling domains survive"
    );
    assert_eq!(
        up.governance.quorum_bps, fresh.governance.quorum_bps,
        "sibling domains survive"
    );
    assert_eq!(
        up.governance.proposals.len(),
        fresh.governance.proposals.len(),
        "sibling domains survive"
    );
}

/// The pre-lazy-accumulator snapshot shape (V3) upgrades with an EMPTY
/// accumulator and EMPTY checkpoints — EXACT, because the eager
/// implementation materialised every delegator reward at distribution
/// time, so there is no lazy state to reconstruct.
#[test]
fn pre_lazy_accumulator_domain_snapshot_upgrades_with_empty_accumulator() {
    use crate::staking::{
        StakingLedger, StakingLedgerV3, MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER,
    };

    let val = [0xA3u8; 32];
    let delegator = [0xB4u8; 32];
    let mut ledger = StakingLedger::new();
    ledger
        .bond(val, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
        .unwrap();
    ledger.delegate(delegator, val, 2_000_000_000).unwrap();
    ledger.distribute_reward(val, 1_000_000_000).unwrap();
    // The lazy path keeps the reward UNSETTLED (that is the whole point):
    // it lives in the accumulator, not in the map.
    assert!(ledger.delegator_rewards.is_empty());
    assert_eq!(ledger.reward_accumulators.len(), 1);

    let fresh = DomainSnapshot {
        staking: ledger.clone(),
        ..Default::default()
    };
    let fresh_bytes = bincode::serialize(&fresh).unwrap();
    let back = decode_domain_snapshot(&fresh_bytes).unwrap();
    assert_eq!(
        back.staking.reward_accumulators.len(),
        1,
        "the accumulator survives"
    );

    // The OLD shape: the ledger WITHOUT the two lazy maps — byte-identical
    // to what a pre-upgrade node wrote.
    let old = DomainSnapshotV3 {
        tokens: fresh.tokens.clone(),
        contracts: fresh.contracts.clone(),
        orderbooks: fresh.orderbooks.clone(),
        pmm: fresh.pmm.clone(),
        pmm_usdt_token: fresh.pmm_usdt_token,
        pmm_treasury: fresh.pmm_treasury,
        order_escrow: fresh.order_escrow.clone(),
        staking: StakingLedgerV3 {
            validators: ledger.validators.clone(),
            delegations: ledger.delegations.clone(),
            delegator_rewards: ledger.delegator_rewards.clone(),
            unbonding: ledger.unbonding.clone(),
            withdrawable: ledger.withdrawable.clone(),
            total_burned: ledger.total_burned,
            rewards_pool: ledger.rewards_pool,
            rewards_minted: ledger.rewards_minted,
            locked_governance: ledger.locked_governance.clone(),
            pq_equivocation_dedup: ledger.pq_equivocation_dedup.clone(),
            equivocation_dedup: ledger.equivocation_dedup.clone(),
            validator_pq_keys: ledger.validator_pq_keys.clone(),
            min_validator_bond: ledger.min_validator_bond,
            vesting_schedules: ledger.vesting_schedules.clone(),
        },
        governance: fresh.governance.clone(),
        oracle: fresh.oracle.clone(),
    };
    let old_bytes = bincode::serialize(&old).unwrap();
    assert!(
        bincode::deserialize::<DomainSnapshot>(&old_bytes).is_err(),
        "pre-lazy-accumulator bytes must fail the direct decode, or the fallback \
         is untested"
    );
    // ... but the restore helper upgrades them.
    let up = decode_domain_snapshot(&old_bytes).unwrap();
    assert_eq!(up.staking.validators, ledger.validators, "bonds survive");
    assert_eq!(
        up.staking.delegations, ledger.delegations,
        "positions survive"
    );
    assert_eq!(
        up.staking.rewards_minted, ledger.rewards_minted,
        "the mint counter survives"
    );
    assert!(
        up.staking.reward_accumulators.is_empty(),
        "no phantom accumulator: the eager ledger had none"
    );
    assert!(
        up.staking.delegator_reward_checkpoints.is_empty(),
        "no phantom checkpoints: the eager ledger had none"
    );
}

// ==================== Adopter replication: verified bodies + durable receipts ===

fn repl_block(height: u64, signer: &SigningKey, tx: Option<Transaction>) -> Block {
    block(height, [height as u8; 32], signer, tx)
}

#[test]
fn verified_body_ingest_rejects_tamper_and_stores_honest() {
    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let b = repl_block(9, &sk, None);
    let h = b.compute_hash();
    // Honest: stored.
    st.put_verified_block(&b, &h).unwrap();
    assert!(st.get_block(&h).unwrap().is_some());
    // Tampered body under the committed hash: rejected, nothing overwritten.
    let mut tampered = b.clone();
    tampered.timestamp ^= 0x01;
    assert!(st.put_verified_block(&tampered, &h).is_err());
    let kept = st.get_block(&h).unwrap().unwrap();
    assert_eq!(
        kept.timestamp, b.timestamp,
        "tamper must not overwrite the committed body"
    );
    // Filed under a wrong hash: rejected too.
    assert!(st.put_verified_block(&b, &[0xEEu8; 32]).is_err());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn receipts_are_durable_and_height_indexed() {
    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let from = sk.verifying_key().to_bytes();
    let tx = Transaction::sign(&sk, from, 10, 1, 0, 0, 0);
    let b = repl_block(11, &sk, Some(tx.clone()));
    let bh = b.compute_hash();
    st.put_block(&b).unwrap();
    let n = st
        .put_receipts_for_block(11, &bh, &b.transactions, &[true], &[1])
        .unwrap();
    assert_eq!(n, 1);
    let got = st
        .get_receipt(&tx.compute_tx_hash())
        .unwrap()
        .expect("receipt filed");
    assert_eq!(
        (got.height, got.block_hash, got.index, got.success),
        (11, bh, 0, true)
    );
    assert_eq!(
        got.fee_charged, 1,
        "actual charged fee is filed, not just the limit"
    );
    assert_eq!(st.receipt_count().unwrap(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn legacy_receipts_decode_with_honest_fee_mapping() {
    // Receipts written before `fee_charged` existed still decode, with the
    // fee mapped to what the block path actually charged then.
    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    for (hash, success) in [([1u8; 32], true), ([2u8; 32], false)] {
        let legacy = LegacyStoredReceipt {
            tx_hash: hash,
            height: 3,
            block_hash: [0xAA; 32],
            index: 0,
            success,
            gas_limit: 560,
        };
        st.receipts
            .insert(hash, bincode::serialize(&legacy).unwrap())
            .unwrap();
    }
    let ok = st
        .get_receipt(&[1u8; 32])
        .unwrap()
        .expect("legacy success decodes");
    assert_eq!(
        ok.fee_charged, 560,
        "legacy success charged the declared limit"
    );
    assert_eq!(ok.gas_limit, 560, "limit is preserved");
    assert!(ok.events.is_empty(), "legacy receipt has empty events");
    let bad = st
        .get_receipt(&[2u8; 32])
        .unwrap()
        .expect("legacy failure decodes");
    assert_eq!(bad.fee_charged, 0, "legacy failure charged nothing");
    assert!(bad.events.is_empty(), "legacy receipt has empty events");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn legacy_receipts_with_fee_decode_with_empty_events() {
    // Receipts written with fee_charged but before `events` existed (7 fields)
    // must decode cleanly with empty events.
    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    let hash = [3u8; 32];
    let legacy = LegacyStoredReceiptWithFee {
        tx_hash: hash,
        height: 4,
        block_hash: [0xBB; 32],
        index: 1,
        success: true,
        gas_limit: 1000,
        fee_charged: 500,
    };
    st.receipts
        .insert(hash, bincode::serialize(&legacy).unwrap())
        .unwrap();

    let r = st
        .get_receipt(&hash)
        .unwrap()
        .expect("7-field receipt decodes");
    assert_eq!(r.height, 4);
    assert_eq!(r.fee_charged, 500);
    assert_eq!(r.gas_limit, 1000);
    assert!(r.events.is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn receipts_persist_and_decode_contract_events() {
    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let from = sk.verifying_key().to_bytes();
    let tx = Transaction::sign(&sk, from, 10, 1, 0, 0, 0);
    let bh = [0xCC; 32];
    let contract = [0x55; 32];
    let events = vec![vec![crate::contract::ContractEvent {
        contract,
        topic: 1234,
        value: 5678,
    }]];

    let n = st
        .put_receipts_for_block_with_events(
            12,
            &bh,
            std::slice::from_ref(&tx),
            &[true],
            &[100],
            &events,
        )
        .unwrap();
    assert_eq!(n, 1);

    let r = st
        .get_receipt(&tx.compute_tx_hash())
        .unwrap()
        .expect("receipt exists");
    assert_eq!(r.height, 12);
    assert_eq!(r.events.len(), 1);
    assert_eq!(r.events[0].contract, contract);
    assert_eq!(r.events[0].topic, 1234);
    assert_eq!(r.events[0].value, 5678);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn adopter_ends_with_byte_identical_bodies_and_receipts_as_proposer() {
    // Proposer commits a body + its single-apply receipt set; the adopter
    // replicates via hash-verified ingest + locally-filed receipts and must
    // hold byte-identical artifacts (no txs=0, no missing receipts).
    let dir_p = tmp();
    let dir_a = tmp();
    let proposer = Storage::open(&dir_p).unwrap();
    let adopter = Storage::open(&dir_a).unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, sk.verifying_key().to_bytes(), 50, 1, 7, 0, 0);
    let b = repl_block(21, &sk, Some(tx.clone()));
    let bh = b.compute_hash();
    proposer.put_block(&b).unwrap();
    proposer
        .put_receipts_for_block(21, &bh, &b.transactions, &[true], &[1])
        .unwrap();

    // Wire-equivalent: proposer bytes -> adopter verifies against committed hash.
    let wire = bincode::serialize(&b).unwrap();
    let fetched: Block = bincode::deserialize(&wire).unwrap();
    adopter.put_verified_block(&fetched, &bh).unwrap();
    adopter
        .put_receipts_for_block(21, &bh, &fetched.transactions, &[true], &[1])
        .unwrap();

    let pb = proposer.get_block(&bh).unwrap().unwrap();
    let ab = adopter
        .committed_body(21, &bh)
        .unwrap()
        .expect("adopter holds the body");
    assert_eq!(
        bincode::serialize(&pb).unwrap(),
        bincode::serialize(&ab).unwrap(),
        "byte equality"
    );
    assert_eq!(ab.transactions.len(), 1, "no txs=0 view on the adopter");
    let pr = proposer
        .get_receipt(&tx.compute_tx_hash())
        .unwrap()
        .unwrap();
    let ar = adopter.get_receipt(&tx.compute_tx_hash()).unwrap().unwrap();
    assert_eq!(pr, ar, "identical receipts");
    std::fs::remove_dir_all(&dir_p).ok();
    std::fs::remove_dir_all(&dir_a).ok();
}

#[tokio::test]
async fn load_full_state_into_wires_pq_keys_tree() {
    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    let engine = InMemoryStateEngine::new();
    let who = [8u8; 32];
    engine.update_account(AccountState::new(who, 10_000)).await;
    st.put_state(1, &engine.create_snapshot().await).unwrap();
    let snap = DomainSnapshot::capture(
        &engine,
        &crate::staking::StakingLedger::new(),
        &crate::governance::Governance::new(),
    )
    .await;
    st.put_domains(1, &bincode::serialize(&snap).unwrap())
        .unwrap();

    let engine2 = InMemoryStateEngine::new();
    assert!(engine2.pq_tree.read().unwrap().is_none());
    load_full_state_into(&st, &engine2).await.unwrap().unwrap();
    assert!(
        engine2.pq_tree.read().unwrap().is_some(),
        "load_full_state_into must attach pq_keys tree"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn load_full_state_into_hydrates_global_implicit_key_registry() {
    use crate::post_quantum::{derive_pq_address, PqScheme};

    let dir = tmp();
    let st = Storage::open(&dir).unwrap();
    let engine = InMemoryStateEngine::new();

    let scheme = PqScheme::Falcon512;
    let pubkey = crate::sharding::Transaction::sample_falcon512_pubkey(0x9A);
    let salt = [0x55u8; 16];
    let address = derive_pq_address(scheme, &pubkey, &salt);

    // Verify that before loading state, this specific address is not in the registry
    let registry = crate::sharding::global_implicit_key_registry();
    assert!(
        registry.lookup(&address).is_none(),
        "unregistered key must not exist prior to hydration"
    );

    // Store persistent key directly into st.pq_keys
    st.put_pq_key(&address, scheme, &pubkey, &salt).unwrap();
    assert_eq!(st.pq_key_count(), 2); // address and pk_hash entries

    // Setup snapshot so load_full_state_into succeeds
    engine
        .update_account(AccountState::new(address, 100_000))
        .await;
    st.put_state(1, &engine.create_snapshot().await).unwrap();
    let snap = DomainSnapshot::capture(
        &engine,
        &crate::staking::StakingLedger::new(),
        &crate::governance::Governance::new(),
    )
    .await;
    st.put_domains(1, &bincode::serialize(&snap).unwrap())
        .unwrap();

    let engine2 = InMemoryStateEngine::new();
    let (height, _, _) = load_full_state_into(&st, &engine2)
        .await
        .unwrap()
        .expect("state restored");
    assert_eq!(height, 1);

    // Verify that GLOBAL_IMPLICIT_KEY_REGISTRY has been hydrated from storage.pq_keys
    let looked_up = registry.lookup(&address);
    assert_eq!(
        looked_up,
        Some((scheme, pubkey.clone())),
        "load_full_state_into must hydrate GLOBAL_IMPLICIT_KEY_REGISTRY from storage.pq_keys"
    );

    // Verify that engine2 reads the key from the attached pq_keys tree
    assert_eq!(
        engine2.get_pinned_pubkey(&address),
        Some((scheme, pubkey)),
        "attached pq_keys tree must be readable via engine2"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn pq_keys_backup_export_and_import() {
    use crate::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};

    let dir1 = tmp();
    let st1 = Storage::open(&dir1).unwrap();
    let scheme = PqScheme::Falcon512;
    let pubkey = crate::sharding::Transaction::sample_falcon512_pubkey(0x4B);
    let address = derive_pq_address(scheme, &pubkey, &DEFAULT_SALT);

    st1.put_pq_key(&address, scheme, &pubkey, &DEFAULT_SALT)
        .unwrap();
    assert_eq!(st1.pq_key_count(), 2);

    let exported = st1.export_pq_keys().unwrap();
    assert_eq!(exported.len(), 2);

    let dir2 = tmp();
    let st2 = Storage::open(&dir2).unwrap();
    assert_eq!(st2.pq_key_count(), 0);

    st2.import_pq_keys(&exported).unwrap();
    assert_eq!(st2.pq_key_count(), 2);
    assert_eq!(st2.get_pq_key(&address).unwrap(), Some((scheme, pubkey)));

    std::fs::remove_dir_all(&dir1).ok();
    std::fs::remove_dir_all(&dir2).ok();
}

#[tokio::test]
async fn cnvrf_v3_snapshot_roundtrip_verify_and_prune() {
    use crate::cn_vrf::{CnVrfV3Chain, EPOCH_LEN};
    use crate::consensus::FalconKeypair;
    use crate::staking::CnVrfAbortCounter;
    use crate::state_engine::CnVrfV3EngineSnapshot;

    let dir = tmp();
    let st = Arc::new(Storage::open(&dir).unwrap());
    let sk = SigningKey::generate(&mut OsRng);

    // Build an engine with non-empty account + non-empty CN-VRF v3 state
    // across all three sub-fields (v3_state, abort_state, epoch_beacons).
    let engine = InMemoryStateEngine::new();
    let who = [0x33u8; 32];
    engine.update_account(AccountState::new(who, 7_500)).await;

    let val_kp = FalconKeypair::generate_from_seed(77);
    let val_id = sk.verifying_key().to_bytes();
    let chain = CnVrfV3Chain::generate(engine.chain_id, &val_id, 1, &[0x5Bu8; 48]);
    let carrier = chain.commit_carrier(&val_kp);
    {
        let mut v3 = engine.cnvrf_v3_write().await;
        v3.admit_commit(&carrier, 0, engine.chain_id, val_kp.public_key())
            .expect("valid commit");
        let rev = chain.reveal_for_slot(0).expect("slot 0 reveal");
        v3.apply_slot_reveal(engine.chain_id, &val_id, EPOCH_LEN, Some(&rev));
    }
    {
        let mut abort = engine.cnvrf_abort_write().await;
        abort.counters.insert(
            val_id,
            CnVrfAbortCounter {
                misses: 2,
                recovery_streak: 1,
            },
        );
    }
    {
        let mut beacons = engine.epoch_vdf_beacons_write().await;
        beacons.insert(1, [0x42u8; 48]);
    }

    let expected_snap = engine.cnvrf_v3_snapshot().await;
    assert!(!expected_snap.is_empty());
    let root_10 = engine.get_state_root().await;

    // Persist via AsyncPersistence::snapshot_domains + enqueue_state at H=10,
    // and anchor H=11 with root_10.
    const H: u64 = 10;
    let ap = AsyncPersistence::start(st.clone());
    ap.enqueue_state(H, engine.create_snapshot().await);
    ap.snapshot_domains(
        &engine,
        &crate::staking::StakingLedger::new(),
        &crate::governance::Governance::new(),
        H,
    )
    .await;
    ap.request_flush();
    for _ in 0..200 {
        if st.cnvrf_v3_at(H).unwrap().is_some() && st.domain_at(H).unwrap().is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(st.cnvrf_v3_at(H).unwrap().is_some(), "cnvrf_v3 persisted");

    let mut anchor = block(H + 1, [0x99u8; 32], &sk, None);
    anchor.state_root = root_10;
    let anchor_hash = anchor.compute_hash();
    st.put_header(&BlockHeaderRecord::of(&anchor)).unwrap();
    st.set_finalized(H + 1, &anchor_hash).unwrap();

    // Full restore into a fresh engine must match root and CnVrfV3EngineSnapshot.
    let fresh = InMemoryStateEngine::new();
    let (loaded_h, _, _) = load_full_state_into(&st, &fresh)
        .await
        .expect("load_full_state_into must verify")
        .expect("snapshot must exist");
    assert_eq!(loaded_h, H);
    assert_eq!(fresh.get_state_root().await, root_10);
    assert_eq!(fresh.cnvrf_v3_snapshot().await, expected_snap);

    // Direct verify_restored_root on an engine with accounts+domains restored
    // (even without manually calling restore_cnvrf_v3_snapshot) restores & passes.
    let direct = InMemoryStateEngine::new();
    direct
        .restore_snapshot_preserve_replay_sets(&st.get_state(H).unwrap().unwrap())
        .await
        .unwrap();
    let dom = decode_domain_snapshot(&st.domain_at(H).unwrap().unwrap()).unwrap();
    dom.apply(&direct).await;
    st.verify_restored_root(&direct, H)
        .await
        .expect("verify_restored_root must restore cnvrf_v3 and pass");
    assert_eq!(direct.cnvrf_v3_snapshot().await, expected_snap);

    // Enqueue path + prune behavior:
    // Add a stale unreferenced cnvrf_v3 row at height 5 and a newer snapshot at height 20.
    let stale_bytes = bincode::serialize(&CnVrfV3EngineSnapshot::default()).unwrap();
    ap.enqueue_cnvrf_v3(5, stale_bytes.clone());
    ap.request_flush();
    for _ in 0..200 {
        if st.cnvrf_v3_at(5).unwrap().is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(st.cnvrf_v3_at(5).unwrap().is_some());

    st.put_state(20, &engine.create_snapshot().await).unwrap();
    st.put_domains(20, &st.domain_at(H).unwrap().unwrap())
        .unwrap();
    st.put_cnvrf_v3(20, &st.cnvrf_v3_at(H).unwrap().unwrap())
        .unwrap();

    // Prune below 15: height 5 (unretained) is dropped; height 10 (still in
    // state/domains) is retained; height 20 is retained.
    let pruned_cnvrf = st.prune_cnvrf_v3_below(15).unwrap();
    assert_eq!(pruned_cnvrf, 1);
    assert!(st.cnvrf_v3_at(5).unwrap().is_none());
    assert!(st.cnvrf_v3_at(H).unwrap().is_some());
    assert!(st.cnvrf_v3_at(20).unwrap().is_some());

    // After state/domains at H=10 are pruned via prune_state_below + prune_domains_below,
    // cnvrf_v3 at H=10 is also pruned cleanly while H=20 survives.
    assert_eq!(st.prune_state_below(15).unwrap(), 1);
    assert_eq!(st.prune_domains_below(15).unwrap(), 1);
    assert!(st.cnvrf_v3_at(H).unwrap().is_none());
    assert!(st.cnvrf_v3_at(20).unwrap().is_some());

    drop(ap);
    drop(st);
    std::fs::remove_dir_all(&dir).ok();
}

#[cfg(test)]
mod archive_proof_tests {
    //! Per-key archive proofs served from the persisted snapshot history.
    use super::super::*;
    use crate::consensus::{FalconKeypair, QuorumCertificate, ValidatorSet, Vote, VoteKind};
    use crate::sharding::{Block, MASTERCHAIN_SHARD};
    use crate::state_engine::{AccountState, InMemoryStateEngine};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn tmp() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "stell_archive_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ))
    }

    /// FULL-PQ QC (mirrors `consensus::tests::fvote` + `VoteSet::certificate`
    /// idiom): Ed list for membership/power plus Falcon µQC envelope for
    /// crypto — exactly what `QuorumCertificate::verify` requires.
    fn pq_cert_for(
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        parent: [u8; 32],
        vs: &ValidatorSet,
        keys: &[(SigningKey, FalconKeypair)],
    ) -> QuorumCertificate {
        let mut set = crate::consensus::VoteSet::new();
        for (sk, fk) in keys {
            let v = Vote::sign_with_falcon(
                sk,
                fk,
                height,
                round,
                VoteKind::Precommit,
                Some(block_hash),
            );
            set.add(v, vs, height, round, VoteKind::Precommit)
                .expect("falcon vote must ingest");
        }
        set.certificate_with_parent(Some(block_hash), vs, Some(&parent))
            .expect("quorum must compile a Falcon µQC")
    }

    fn test_block(height: u64, prev: [u8; 32], state_root: [u8; 32], signer: &SigningKey) -> Block {
        let order_merkle_root = crate::mev::compute_order_merkle_root(&[]);
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height,
            prev_hash: prev,
            state_root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: height,
            proposer: signer.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root,
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            cnvrf_v3: None,
            round: 0,
        };
        b.sign_block(signer);
        b
    }

    /// A finalized two-block chain with a full snapshot at height `H`:
    /// engine state (two funded accounts) + domains + aux domains persisted,
    /// header+QC-anchored at `H + 1`.
    struct Fixture {
        dir: std::path::PathBuf,
        store: Storage,
        height: u64,
        tip: u64,
        root: [u8; 32],
        account_a: [u8; 32],
        missing: [u8; 32],
        validator: SigningKey,
        falcon: FalconKeypair,
    }

    async fn fixture() -> Fixture {
        let dir = tmp();
        let store = Storage::open(&dir).unwrap();
        let validator = SigningKey::generate(&mut OsRng);
        // Deterministic Falcon key per validator id would collide across
        // parallel tests sharing the global PQ registry; generate fresh and
        // register under this fixture's unique Ed id.
        let falcon = FalconKeypair::generate();
        crate::consensus::register_validator_pq_key(
            validator.verifying_key().to_bytes(),
            crate::post_quantum::PqScheme::Falcon512,
            falcon.public_key.clone(),
        );

        let engine = InMemoryStateEngine::new();
        let account_a = [0xA1u8; 32];
        let account_b = [0xB2u8; 32];
        engine
            .update_account(AccountState::new(account_a, 1_000))
            .await;
        engine.update_account(AccountState::new(account_b, 7)).await;
        let root = engine.get_state_root().await;

        let height = 10u64;
        let tip = height + 1;
        store
            .put_state(height, &engine.create_snapshot().await)
            .unwrap();
        let domains = DomainSnapshot::capture(
            &engine,
            &crate::staking::StakingLedger::new(),
            &crate::governance::Governance::new(),
        )
        .await;
        store
            .put_domains(height, &bincode::serialize(&domains).unwrap())
            .unwrap();
        store
            .put_session_keys(height, &engine.session_keys_snapshot().await)
            .unwrap();
        store
            .put_bridge(height, &engine.bridge_snapshot().await)
            .unwrap();
        store
            .put_zkml_models(height, &engine.zkml_models_snapshot().await)
            .unwrap();

        // Block H (pre-state, arbitrary) and the anchoring block H+1 whose
        // state_root is the post-H root and whose QC authenticates it.
        let b_h = test_block(height, [0u8; 32], [0xAAu8; 32], &validator);
        let h_h = store.put_block(&b_h).unwrap();
        let mut b_next = test_block(tip, h_h, root, &validator);
        let h_next = b_next.compute_hash();
        let vs = ValidatorSet::from_list(vec![(validator.verifying_key().to_bytes(), 1)]);
        b_next.precommit_qc = Some(pq_cert_for(
            tip,
            0,
            h_next,
            h_h,
            &vs,
            &[(validator.clone(), falcon.clone())],
        ));
        store.put_block(&b_next).unwrap();
        store.set_finalized(tip, &h_next).unwrap();

        Fixture {
            dir,
            store,
            height,
            tip,
            root,
            account_a,
            missing: [0xEEu8; 32],
            validator,
            falcon,
        }
    }

    #[test]
    fn archive_slot_keys_match_the_live_trie_derivations() {
        // The slot model must name the SAME keys the live trie commits, or an
        // archive proof would be about a key the chain never wrote.
        let addr = [0x11u8; 32];
        let token = [0x22u8; 32];
        assert_eq!(archive_slot_key(&ArchiveSlot::Account(addr)), addr);
        assert_eq!(
            archive_slot_key(&ArchiveSlot::TokenBalance {
                token_id: token,
                account: addr
            }),
            crate::state_engine::token_balance_key(&token, &addr)
        );
        assert_eq!(
            archive_slot_key(&ArchiveSlot::TokenSupply(token)),
            crate::state_engine::token_supply_key(&token)
        );
        assert_eq!(
            archive_slot_key(&ArchiveSlot::ContractCode(addr)),
            crate::state_engine::contract_key(&addr)
        );
        assert_eq!(
            archive_slot_key(&ArchiveSlot::ContractAbi(addr)),
            crate::state_engine::contract_abi_key(&addr)
        );
        assert_eq!(
            archive_slot_key(&ArchiveSlot::CommitmentDigest),
            crate::commitment::commitment_key()
        );
    }

    #[tokio::test]
    async fn archive_proof_served_from_snapshot_verifies_after_restart() {
        let f = fixture().await;
        // "Restart": drop everything but the directory, reopen the store.
        let dir = f.dir.clone();
        let (height, tip, root, account_a) = (f.height, f.tip, f.root, f.account_a);
        drop(f);
        // GUARD policy: restart-reopen is timing-sensitive under full-parallel
        // `cargo test` (sled lock file may linger briefly after drop on loaded
        // CI hosts). Retry the reopen with backoff instead of asserting on the
        // first WouldBlock; this pins test-only flakiness, not storage logic.
        let mut store = None;
        for _ in 0..20 {
            match Storage::open(&dir) {
                Ok(s) => {
                    store = Some(s);
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
            }
        }
        let store = store.expect("storage must reopen after restart (retried 2s)");

        let proof = store
            .serve_archive_proof(height, &account_a, tip)
            .await
            .unwrap();
        assert_eq!(proof.height, height);
        assert_eq!(proof.state_root, root);
        assert!(
            proof.verify(),
            "archive proof must verify against the historical root"
        );
        // The proven leaf carries the account that was snapshotted.
        let value = proof.value.expect("inclusion proof carries the value");
        assert!(value.len() >= 16);
        assert_eq!(u64::from_be_bytes(value[0..8].try_into().unwrap()), 1_000);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn archive_exclusion_proof_verifies_for_a_key_absent_at_that_height() {
        let f = fixture().await;
        let proof = f
            .store
            .serve_archive_proof(f.height, &f.missing, f.tip)
            .await
            .unwrap();
        assert_eq!(proof.proof_type, crate::cpat2::ArchiveProofType::Exclusion);
        assert_eq!(proof.value, None);
        assert_eq!(proof.state_root, f.root);
        assert!(
            proof.verify(),
            "exclusion proof must verify against the historical root"
        );
        std::fs::remove_dir_all(&f.dir).ok();
    }

    #[tokio::test]
    async fn archive_proof_for_a_pruned_height_is_refused_not_fabricated() {
        let f = fixture().await;
        // Age the chain: a snapshot at a later height, then prune below it.
        // (Pruning never drops the LATEST snapshot, so the prune must have
        // something newer to keep.)
        let engine = InMemoryStateEngine::new();
        engine
            .update_account(AccountState::new([0x77u8; 32], 5))
            .await;
        let later = f.height + 10;
        f.store
            .put_state(later, &engine.create_snapshot().await)
            .unwrap();
        let domains = DomainSnapshot::capture(
            &engine,
            &crate::staking::StakingLedger::new(),
            &crate::governance::Governance::new(),
        )
        .await;
        f.store
            .put_domains(later, &bincode::serialize(&domains).unwrap())
            .unwrap();
        assert!(f.store.prune_state_below(later).unwrap() > 0);
        assert!(f.store.prune_domains_below(later).unwrap() > 0);

        let err = f
            .store
            .serve_archive_proof(f.height, &f.account_a, later)
            .await
            .expect_err("a pruned height must be refused");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("pruned") || msg.contains("no state snapshot"),
            "refusal must say the height is pruned, got: {msg}"
        );
        std::fs::remove_dir_all(&f.dir).ok();
    }

    #[tokio::test]
    async fn archive_proofs_fail_closed_above_the_tip_and_at_unknown_heights() {
        let f = fixture().await;
        let err = f
            .store
            .serve_archive_proof(f.tip + 100, &f.account_a, f.tip)
            .await
            .expect_err("above-tip height must be refused");
        assert!(format!("{err:?}").contains("above the tip"));

        // Inside the retained span but never snapshotted (snapshots are
        // periodic, not per height).
        let err = f
            .store
            .serve_archive_proof(f.height + 1, &f.account_a, f.tip)
            .await
            .expect_err("a non-snapshot height must be refused");
        assert!(format!("{err:?}").contains("no snapshot"));

        let err = f
            .store
            .historical_root(f.tip + 100, f.tip)
            .expect_err("historical root above the tip must be refused");
        assert!(format!("{err:?}").contains("above the tip"));
        std::fs::remove_dir_all(&f.dir).ok();
    }

    #[test]
    fn historical_root_is_authenticated_by_the_quorum_certificate() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let f = rt.block_on(fixture());
        let record = f.store.historical_root(f.height, f.tip).unwrap();
        assert_eq!(record.height, f.height);
        assert_eq!(record.state_root, f.root);
        assert_eq!(record.anchor_height, f.height + 1);
        assert!(record.finalized);

        // The anchor's QC verifies against the validator set that decided
        // it — this is what makes the root trustworthy, and it is checked
        // client-side against the client's OWN set.
        let val_id = f.validator.verifying_key().to_bytes();
        // Re-pin the Falcon key: the PQ registry is process-global and other
        // parallel tests may have registered other ids (never this id, which
        // is unique per fixture) — this keeps the verify path on this
        // fixture's key.
        crate::consensus::register_validator_pq_key(
            val_id,
            crate::post_quantum::PqScheme::Falcon512,
            f.falcon.public_key.clone(),
        );
        let vset = ValidatorSet::from_list(vec![(val_id, 1)]);
        assert!(
            record.cert.verify(&vset),
            "the anchoring QC must carry a real quorum of the validator set"
        );
        // Bound to the anchor: a QC for another block must not authenticate
        // this root.
        let mut wrong = record.cert.clone();
        wrong.block_hash = Some([0x99u8; 32]);
        assert!(!wrong.verify(&vset));
        std::fs::remove_dir_all(&f.dir).ok();
    }

    #[test]
    fn historical_root_without_a_retained_qc_is_refused() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let f = rt.block_on(fixture());
        // Simulate a pruned body: the header record survives body pruning,
        // the body (and hence the QC) does not. A header alone must not
        // authenticate.
        let anchor = f.height + 1;
        let removed = f.store.prune_blocks_below(anchor + 2).unwrap();
        assert!(removed > 0, "the prune must take the anchoring body");
        assert!(
            f.store.header_at(anchor).unwrap().is_some(),
            "the header record survives body pruning"
        );
        let err = f
            .store
            .historical_root(f.height, f.tip)
            .expect_err("a QC-less anchor must be refused");
        assert!(
            format!("{err:?}").contains("quorum certificate"),
            "refusal must name the missing QC, got: {err:?}"
        );
        std::fs::remove_dir_all(&f.dir).ok();
    }
}

#[cfg(test)]
mod persist_policy_tests {
    //! Audit F2 (mainnet blocker): a full persist queue must never silently
    //! drop a consensus-critical job. These pin the classifier AND the
    //! current-thread deferred-drain path (the one that used to drop
    //! immediately).
    use super::super::*;
    use crate::state_engine::InMemoryStateEngine;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Async-aware twin of `SERIAL` for the two tests that must `await` while
    /// holding the guard.
    fn serial_async() -> &'static tokio::sync::Mutex<()> {
        static SERIAL_ASYNC: std::sync::OnceLock<tokio::sync::Mutex<()>> =
            std::sync::OnceLock::new();
        SERIAL_ASYNC.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "stell_persist_policy_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn handle_with_capacity(
        dir: &std::path::Path,
        cap: usize,
    ) -> (AsyncPersistence, tokio::sync::mpsc::Receiver<PersistJob>) {
        let storage = Arc::new(Storage::open(dir).expect("temp storage opens"));
        let (tx, rx) = tokio::sync::mpsc::channel::<PersistJob>(cap);
        (
            AsyncPersistence {
                tx,
                storage,
                queue_depth: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    #[test]
    fn consensus_and_finalized_are_critical_wait_not_bounded_wait() {
        assert_eq!(
            persist_push_policy(&PersistJob::Consensus(Box::default())),
            PersistPushPolicy::CriticalWait
        );
        assert_eq!(
            persist_push_policy(&PersistJob::Finalized {
                height: 7,
                hash: [7u8; 32]
            }),
            PersistPushPolicy::CriticalWait
        );
        assert_eq!(
            persist_push_policy(&PersistJob::Prune { keep_from: 3 }),
            PersistPushPolicy::DropFirst
        );
        // Everything else stays bounded-wait (never drop-first).
        assert_eq!(
            persist_push_policy(&PersistJob::Flush),
            PersistPushPolicy::BoundedWait
        );
        // Every critical class has a documented, non-empty consequence.
        for job in [
            PersistJob::Consensus(Box::default()),
            PersistJob::Finalized {
                height: 1,
                hash: [1u8; 32],
            },
        ] {
            assert!(!persist_drop_consequence(&job).is_empty());
            assert!(!persist_job_label(&job).is_empty());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_queue_defers_critical_job_then_delivers_it() {
        // ASYNC-AWARE serialisation (a std guard across an await is both a
        // clippy error and a real hazard: it may drop on another thread).
        let _g = serial_async().lock().await;
        let dir = tmpdir("defer");
        let (ap, mut rx) = handle_with_capacity(&dir, 1);
        // One job fills the single slot; the writer is not running (we hold
        // the only receiver), so the next push hits `Full`.
        ap.enqueue_finalized(1, [1u8; 32]);
        let before = crate::metrics::global().snapshot().persist_queue_dropped;
        ap.enqueue_finalized(2, [2u8; 32]);
        // The old current-thread path dropped this synchronously.
        assert_eq!(
            crate::metrics::global().snapshot().persist_queue_dropped,
            before,
            "a critical job must never be dropped before its bounded drain"
        );
        // Free the slot: the deferred send must complete and deliver height 2.
        let first = rx.recv().await.expect("first job");
        assert!(matches!(first, PersistJob::Finalized { height: 1, .. }));
        let second = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("deferred critical send must not hang")
            .expect("deferred critical job delivered");
        assert!(matches!(second, PersistJob::Finalized { height: 2, .. }));
        assert_eq!(
            crate::metrics::global().snapshot().persist_queue_dropped,
            before,
            "delivered critical job is not a drop"
        );
        drop(ap);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn critical_drop_after_budget_is_counted_never_silent() {
        let _g = serial_async().lock().await;
        let dir = tmpdir("counted");
        let (ap, _rx) = handle_with_capacity(&dir, 1);
        ap.enqueue_finalized(1, [1u8; 32]);
        let before = crate::metrics::global().snapshot().persist_queue_dropped;
        ap.enqueue_finalized(2, [2u8; 32]);
        // Never drain: the deferred send must expire and COUNT the loss.
        tokio::time::sleep(std::time::Duration::from_millis(
            PERSIST_BLOCKING_WAIT_MS.saturating_mul(3),
        ))
        .await;
        let after = crate::metrics::global().snapshot().persist_queue_dropped;
        assert_eq!(
            after - before,
            1.0,
            "a critical job that expires its bounded drain must be counted once"
        );
        drop(ap);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn queue_depth_gauge_counts_successful_push_only() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmpdir("depth");
        let (ap, _rx) = handle_with_capacity(&dir, 2);
        assert_eq!(ap.pending(), 0);
        ap.enqueue_finalized(1, [1u8; 32]);
        assert_eq!(ap.pending(), 1, "accepted job increments the gauge");
        drop(ap);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn snapshot_domains_persists_pq_registry_and_latest_paired_skips_missing_pq_tail() {
        let dir = tmpdir("pq_snap_domains");
        let st = Arc::new(Storage::open(&dir).expect("open storage"));
        let engine = InMemoryStateEngine::new();
        let vid = [0x44u8; 32];
        let pk = crate::sharding::Transaction::sample_falcon512_pubkey(0x44);
        {
            let mut reg = engine.pq_registry_write().await;
            reg.adopt_legacy_key_at(vid, crate::post_quantum::PqScheme::Falcon512, pk, 0, true)
                .expect("seed pq key");
        }
        let ledger = engine.staking_read().await.clone();
        let gov = engine.governance_read().await.clone();

        let ap = AsyncPersistence::start(Arc::clone(&st));
        ap.snapshot_state(&engine, 10).await;
        ap.snapshot_domains(&engine, &ledger, &gov, 10).await;
        let _ = wait_for_persist_drain(|| ap.pending()).await;
        let _ = st.flush();

        // Simulate an older incomplete tail at height 20 missing pq_registry:
        // `latest_paired_snapshot` must skip 20 and return the complete 10.
        ap.snapshot_state(&engine, 20).await;
        let snap20 = DomainSnapshot::capture(&engine, &ledger, &gov).await;
        ap.enqueue_domains(
            20,
            bincode::serialize(&snap20).unwrap(),
            vec![],
            vec![],
            vec![],
            vec![],
        );
        let _ = wait_for_persist_drain(|| ap.pending()).await;
        let _ = st.flush();

        let paired = st
            .latest_paired_snapshot()
            .expect("latest_paired_snapshot")
            .expect("some paired");
        assert_eq!(
            paired.0, 10,
            "paired snapshot with pq_registry must win over incomplete tail"
        );
        assert!(st.pq_registry_at(10).expect("read pq 10").is_some());

        let restored_engine = InMemoryStateEngine::new();
        let (rh, _, _) = load_full_state_into(&st, &restored_engine)
            .await
            .expect("load_full_state_into")
            .expect("some state");
        assert_eq!(rh, 10);
        assert_eq!(
            restored_engine.get_state_root().await,
            engine.get_state_root().await
        );
        drop(ap);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
