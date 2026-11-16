use super::apply::sweep_gov_finalize;
use super::*;
use crate::sharding::{
    FinalizedHeaderRegistry, ShardHeaderCommitment, ShardRegistry, MASTERCHAIN_SHARD,
};
use rand::rngs::OsRng;

const SHARD1: ShardId = 1;

/// Domain-separation seed for the VEL-1 pool sender (shared by the pool
/// helper and the pack-filter fixture so both address the same sender).
const VEL1_POOL_SEED: u8 = 0xE1;

/// A funded state engine for the test validator (same shape as the
/// helper of the main test module, which is private to it).
async fn funded_state(owner: [u8; 32]) -> Arc<InMemoryStateEngine> {
    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(crate::state_engine::AccountState::new(owner, 10_000_000))
        .await;
    st
}

/// FULL-PQ sender (mirrors the main test module's `pq_pair` idiom):
/// implicit Falcon-512 envelope, key pre-registered globally, so
/// admission and packing behave exactly like the old classical fixture.
fn pq_pair(seed: u8) -> ([u8; 32], Vec<u8>) {
    let pk = crate::sharding::Transaction::sample_falcon512_pubkey(seed);
    let from = crate::post_quantum::derive_pq_address(
        crate::post_quantum::PqScheme::Falcon512,
        &pk,
        &crate::post_quantum::DEFAULT_SALT,
    );
    crate::sharding::Transaction::global_implicit_registry()
        .register(
            from,
            crate::post_quantum::PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        )
        .expect("PQ test key must register");
    (from, pk)
}

/// FULL-PQ replacement for `Transaction::sign` in this module.
fn pq_tx(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
) -> crate::sharding::Transaction {
    let (from, pk) = pq_pair(seed);
    let mut tx = crate::sharding::Transaction {
        from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard: crate::sharding::MASTERCHAIN_SHARD,
        target_shard: crate::sharding::MASTERCHAIN_SHARD,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = crate::sharding::Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = crate::sharding::PqSignatureEnvelope::new_implicit(
        crate::post_quantum::PqScheme::Falcon512,
        sig,
    )
    .encode();
    tx
}

/// Falcon vote minting (mirrors `consensus::tests::fvote`).
fn fvote(
    sk: &SigningKey,
    fk: &crate::post_quantum::FalconKeypair,
    height: crate::consensus::Height,
    round: crate::consensus::Round,
    kind: crate::consensus::VoteKind,
    bh: Option<[u8; 32]>,
) -> crate::consensus::Vote {
    crate::consensus::Vote::sign_with_falcon(sk, fk, height, round, kind, bh)
}

/// FULL-PQ QC (mirrors `sync::tests::pq_cert_for`): `parent` must be the
/// block's `prev_hash` (chain binding).
fn pq_cert_for(
    vs: &crate::consensus::ValidatorSet,
    keys: &[SigningKey],
    fks: &[crate::post_quantum::FalconKeypair],
    height: u64,
    bh: [u8; 32],
    parent: [u8; 32],
) -> crate::consensus::QuorumCertificate {
    let mut set = crate::consensus::VoteSet::new();
    for (sk, fk) in keys.iter().zip(fks.iter()) {
        let v = fvote(
            sk,
            fk,
            height,
            0,
            crate::consensus::VoteKind::Precommit,
            Some(bh),
        );
        set.add(v, vs, height, 0, crate::consensus::VoteKind::Precommit)
            .expect("falcon vote must ingest");
    }
    set.certificate_with_parent(Some(bh), vs, Some(&parent))
        .expect("quorum must compile a Falcon µQC")
}

fn workchain_block(height: u64, root: [u8; 32]) -> Block {
    Block {
        shard_id: SHARD1,
        height,
        prev_hash: [0x11; 32],
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_000_000 + height,
        proposer: [0x33; 32],
        validator_signatures: vec![],
        precommit_qc: None,
        last_qc: None,
        shard_headers: vec![],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
    }
}

/// A masterchain block must commit to the latest finalized header of
/// every workchain shard: the shard id, the height, the block hash, the
/// state root and the timestamp.
#[tokio::test]
async fn masterchain_block_commits_workchain_shard_headers_and_roots() {
    let key = SigningKey::generate(&mut OsRng);
    let me = key.verifying_key().to_bytes();
    let state = funded_state(me).await;
    let validators = ValidatorSet::from_list(vec![(me, 1)]);

    // One process, two shards: the masterchain and one workchain shard.
    let shard_registry = ShardRegistry::from_ids([MASTERCHAIN_SHARD, SHARD1]);
    let hdrs: Arc<std::sync::RwLock<FinalizedHeaderRegistry>> =
        Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));

    let mut rt = ValidatorRuntime::new(key.clone(), validators, state, 1)
        .with_shard(MASTERCHAIN_SHARD, shard_registry)
        .with_finalized_headers(hdrs.clone());

    // The workchain shard finalized a block: the masterchain must publish
    // its head in every block it produces.
    let shard_block = workchain_block(7, [0x22; 32]);
    {
        let mut reg = hdrs.write().expect("registry lock");
        reg.note_finalized_commitment(ShardHeaderCommitment {
            shard_id: SHARD1,
            height: shard_block.height,
            block_hash: shard_block.compute_hash(),
            state_root: shard_block.state_root,
            timestamp: shard_block.timestamp,
        });
    }

    let block = rt
        .propose(1_700_000_100)
        .await
        .expect("propose must succeed");
    assert_eq!(block.shard_id, MASTERCHAIN_SHARD);
    assert_eq!(
        block.shard_headers.len(),
        1,
        "the masterchain must publish the workchain shard head"
    );
    let head = &block.shard_headers[0];
    assert_eq!(head.shard_id, SHARD1);
    assert_eq!(head.height, 7);
    assert_eq!(head.block_hash, shard_block.compute_hash());
    assert_eq!(head.state_root, shard_block.state_root);
    assert_eq!(head.timestamp, shard_block.timestamp);
    assert!(block.shard_headers_canonical());
    assert_eq!(block.shard_head(SHARD1).map(|h| h.height), Some(7));

    // The commitment is CRYPTOGRAPHICALLY BOUND: the same body without the
    // shard head hashes differently, so a quorum signature over this block
    // signs the shard roots. A tampered root must move the hash too.
    let mut without = block.clone();
    without.shard_headers.clear();
    assert_ne!(block.compute_hash(), without.compute_hash());

    let mut tampered = block.clone();
    tampered.shard_headers[0].state_root = [0xEE; 32];
    assert_ne!(block.compute_hash(), tampered.compute_hash());
}

/// A workchain block commits to nothing but its own body: only the
/// masterchain publishes shard heads.
#[tokio::test]
async fn workchain_block_publishes_no_shard_heads() {
    let key = SigningKey::generate(&mut OsRng);
    let me = key.verifying_key().to_bytes();
    let state = funded_state(me).await;
    let validators = ValidatorSet::from_list(vec![(me, 1)]);

    let shard_registry = ShardRegistry::from_ids([MASTERCHAIN_SHARD, SHARD1]);
    let hdrs: Arc<std::sync::RwLock<FinalizedHeaderRegistry>> =
        Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));
    {
        let mut reg = hdrs.write().expect("registry lock");
        reg.note_finalized_commitment(ShardHeaderCommitment {
            shard_id: SHARD1,
            height: 7,
            block_hash: [0x44; 32],
            state_root: [0x55; 32],
            timestamp: 1_700_000_007,
        });
    }

    let mut rt = ValidatorRuntime::new(key.clone(), validators, state, 1)
        .with_shard(SHARD1, shard_registry)
        .with_finalized_headers(hdrs);

    let block = rt
        .propose(1_700_000_100)
        .await
        .expect("propose must succeed");
    assert_eq!(block.shard_id, SHARD1);
    assert!(
        block.shard_headers.is_empty(),
        "a workchain block must not publish shard heads"
    );
}

/// A validator refuses a masterchain block whose shard-head set is not
/// canonical, and one that contradicts a header it already finalized.
#[tokio::test]
async fn validator_refuses_a_contradicting_shard_head() {
    let key = SigningKey::generate(&mut OsRng);
    let me = key.verifying_key().to_bytes();
    let state = funded_state(me).await;
    let validators = ValidatorSet::from_list(vec![(me, 1)]);
    let shard_registry = ShardRegistry::from_ids([MASTERCHAIN_SHARD, SHARD1]);
    let hdrs: Arc<std::sync::RwLock<FinalizedHeaderRegistry>> =
        Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));

    // Falconize the proposer: production `propose` pushes BOTH halves,
    // and `validate_proposal` refuses Ed-only blocks.
    let fk = crate::post_quantum::FalconKeypair::generate_from_seed(0xC7);
    let mut rt = ValidatorRuntime::new(key.clone(), validators, state, 1)
        .with_shard(MASTERCHAIN_SHARD, shard_registry)
        .with_finalized_headers(hdrs.clone())
        .with_falcon_key(fk.clone());

    let shard_block = workchain_block(7, [0x22; 32]);
    {
        let mut reg = hdrs.write().expect("registry lock");
        reg.note_finalized_commitment(ShardHeaderCommitment {
            shard_id: SHARD1,
            height: shard_block.height,
            block_hash: shard_block.compute_hash(),
            state_root: shard_block.state_root,
            timestamp: shard_block.timestamp,
        });
    }

    let root = rt.state.get_state_root().await;
    let good = rt
        .propose(1_700_000_100)
        .await
        .expect("propose must succeed");
    assert!(rt.validate_proposal(&good, root).is_ok());

    // A head that contradicts the header we finalized at the same height
    // (same height, different root) is an equivocation: refused.
    let mut forged = good.clone();
    forged.shard_headers[0].state_root = [0x99; 32];
    forged.validator_signatures.clear();
    forged.sign_block(&key);
    // Falconize the re-signed body (same envelope as `propose`).
    {
        let hash = forged.compute_hash();
        let falcon_id = fk.validator_id();
        let falcon_sig = fk.sign(&hash);
        forged.validator_signatures.push((falcon_id, falcon_sig));
    }
    let err = rt
        .validate_proposal(&forged, root)
        .expect_err("a contradicting shard head must be refused");
    assert!(err.contains("contradicts"), "got: {err}");

    // A NON-canonical set (descending shard ids) is refused as well.
    let mut unsorted = good.clone();
    unsorted.shard_headers.clear();
    unsorted.shard_headers.push(ShardHeaderCommitment {
        shard_id: 2,
        height: 1,
        block_hash: [0x01; 32],
        state_root: [0x02; 32],
        timestamp: 1,
    });
    unsorted.shard_headers.push(ShardHeaderCommitment {
        shard_id: 1,
        height: 1,
        block_hash: [0x03; 32],
        state_root: [0x04; 32],
        timestamp: 1,
    });
    unsorted.validator_signatures.clear();
    unsorted.sign_block(&key);
    // Falconize the re-signed body (same envelope as `propose`).
    {
        let hash = unsorted.compute_hash();
        let falcon_id = fk.validator_id();
        let falcon_sig = fk.sign(&hash);
        unsorted.validator_signatures.push((falcon_id, falcon_sig));
    }
    let err = rt
        .validate_proposal(&unsorted, root)
        .expect_err("a non-canonical shard head set must be refused");
    assert!(err.contains("canonical"), "got: {err}");
}

/// A single-shard process (the default registry) publishes no shard head
/// at all, so its block hashes stay byte-identical to the pre-sharding
/// ones.
#[tokio::test]
async fn single_shard_process_publishes_no_shard_heads() {
    let key = SigningKey::generate(&mut OsRng);
    let me = key.verifying_key().to_bytes();
    let state = funded_state(me).await;
    let validators = ValidatorSet::from_list(vec![(me, 1)]);
    let mut rt = ValidatorRuntime::new(key.clone(), validators, state, 1);
    let block = rt
        .propose(1_700_000_100)
        .await
        .expect("propose must succeed");
    assert!(block.shard_headers.is_empty());
}

/// W10.5 heal (2026-10-25): snapshot-sync jumps consensus to a verified
/// boundary but leaves the light client anchored at genesis (expecting
/// block 1), so the body walk refuses the whole tail and the node never
/// converges. `reanchor_light_client_at_snapshot` must move the anchor
/// AT the boundary (from the boundary block's own QC) so the tail
/// verifies; a boundary block WITHOUT a QC must leave the stale anchor
/// alone (fail closed — the walk still refuses).
#[tokio::test]
async fn snapshot_jump_reanchors_light_client_for_tail_walk() {
    use crate::consensus::QuorumCertificate;

    fn qc_for(
        vs: &crate::consensus::ValidatorSet,
        ks: &[SigningKey],
        fks: &[crate::post_quantum::FalconKeypair],
        height: u64,
        bh: [u8; 32],
        parent: [u8; 32],
    ) -> QuorumCertificate {
        pq_cert_for(vs, ks, fks, height, bh, parent)
    }

    fn empty_block(height: u64, prev: [u8; 32], root: [u8; 32], proposer: [u8; 32]) -> Block {
        Block {
            shard_id: crate::sharding::MASTERCHAIN_SHARD,
            height,
            prev_hash: prev,
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + height,
            proposer,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: crate::mev::compute_order_merkle_root(&[]),
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        }
    }

    let ks: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let ids: Vec<[u8; 32]> = ks.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let vs = ValidatorSet::from_list(ids.iter().map(|id| (*id, 1_000_000)).collect());
    let me = ids[0];
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), funded_state(me).await, 1);
    // FULL-PQ: register Falcon keys so the hand-minted µQC verifies (a
    // classical `Vote::sign` QC no longer does).
    let fks: Vec<crate::post_quantum::FalconKeypair> = ks
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let fk = crate::post_quantum::FalconKeypair::generate_from_seed(0xA0 + i as u8);
            crate::consensus::register_validator_pq_key(
                k.verifying_key().to_bytes(),
                crate::post_quantum::PqScheme::Falcon512,
                fk.public_key.clone(),
            );
            fk
        })
        .collect();
    let genesis_root = rt.state.get_state_root().await;
    rt.set_light_client(vs.clone(), genesis_root)
        .expect("anchor at genesis");

    // The boundary block at height 50 with a real 3/3 precommit QC.
    let boundary = 50u64;
    let mut blk = empty_block(boundary, [0x11; 32], genesis_root, ids[0]);
    let bh = blk.compute_hash();
    let qc = qc_for(&vs, &ks, &fks, boundary, bh, [0x11; 32]);
    assert!(qc.verify(&vs), "test QC must verify");
    blk.precommit_qc = Some(qc);

    // The tail block right after the boundary, also fully certified.
    // Like every real block it carries ONLY its proposer's block-hash
    // signature (votes sign `vote_sign_bytes`, never the block hash), so
    // its block-signature power (1M) is far below quorum (2M+1) — while
    // its precommit QC is a full 3/3.
    let mut tail = empty_block(boundary + 1, bh, genesis_root, ids[1]);
    tail.sign_block(&ks[1]);
    let th = tail.compute_hash();
    tail.precommit_qc = Some(qc_for(&vs, &ks, &fks, boundary + 1, th, bh));

    // Simulate the snapshot jump: finalized head + consensus move, but
    // the light client is still at genesis.
    rt.finalized.push((boundary, bh));
    rt.hc.height = boundary + 1;
    assert!(rt.light_client().unwrap().tip_height() < boundary);

    // The tail is refused before the re-anchor (genesis anchor, gap)...
    let refused = crate::sync::verify_synced_blocks_against_anchor_with_sets(
        rt.light_client().unwrap(),
        std::slice::from_ref(&tail),
        &|_| Some(vs.clone()),
    );
    assert!(refused.is_err(), "tail must be refused on the stale anchor");

    // ...and accepted after it. (The strict per-header check still
    // refuses the single-proposer block signature — pinning the protocol
    // reality the finality-only probe path works around.)
    let strict = crate::light_client::LightHeader::of_block(&tail).expect("tail carries a QC");
    assert!(
        strict.verify(&vs).is_err(),
        "a single proposer signature must not pass the block-signature quorum"
    );
    rt.reanchor_light_client_at_snapshot(boundary, &blk);
    assert_eq!(
        rt.light_client().unwrap().tip_height(),
        boundary,
        "anchor must sit AT the boundary"
    );
    crate::sync::verify_synced_blocks_against_anchor_with_sets(
        rt.light_client().unwrap(),
        std::slice::from_ref(&tail),
        &|_| Some(vs.clone()),
    )
    .expect("tail must verify after the re-anchor");

    // Fail-closed: a boundary block without a QC leaves the anchor alone.
    let mut rt2 = ValidatorRuntime::new(ks[0].clone(), vs.clone(), funded_state(me).await, 1);
    rt2.set_light_client(vs.clone(), genesis_root)
        .expect("anchor at genesis");
    rt2.finalized.push((boundary, bh));
    let bare = empty_block(boundary, [0x11; 32], genesis_root, ids[0]);
    rt2.reanchor_light_client_at_snapshot(boundary, &bare);
    assert_eq!(
        rt2.light_client().unwrap().tip_height(),
        0,
        "a QC-less boundary block must not move the anchor"
    );
}

// ========================================================================
// VEL-1 bounded proposer-prebuild: reuse ≡ fresh, staleness fail-safe
// ========================================================================

async fn vel1_runtime_with_pool(key: &SigningKey, ntxs: u64) -> (ValidatorRuntime, [u8; 32]) {
    let txs: Vec<crate::sharding::Transaction> = (0..ntxs)
        .map(|nonce| pq_tx(VEL1_POOL_SEED, [0x77u8; 32], 1_000, 21_000, nonce))
        .collect();
    vel1_runtime_with_cloned_pool(key, &txs).await
}

/// A runtime pre-loaded with CLONES of one caller-built pool.
///
/// PQ necessity: Falcon-512 signing is randomized (FIPS 206), so two
/// independently minted pools from the same seed carry different
/// signature bytes (hence different tx hashes). Sharing one pool makes
/// the reuse-vs-fresh inputs identical BY CONSTRUCTION — the property
/// under test (same inputs ⇒ same selection) — instead of relying on
/// the classical era's deterministic Ed25519 regeneration.
async fn vel1_runtime_with_cloned_pool(
    key: &SigningKey,
    txs: &[crate::sharding::Transaction],
) -> (ValidatorRuntime, [u8; 32]) {
    let me = key.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(me, 1)]);
    let state = Arc::new(InMemoryStateEngine::new());
    // FULL-PQ: the pool sender is a Falcon-512 identity; classical
    // `Transaction::sign` outputs are refused at admission, so the pool
    // would stay empty.
    let (pq_from, _pk) = pq_pair(VEL1_POOL_SEED);
    state
        .update_account(crate::state_engine::AccountState::new(pq_from, 10_000_000))
        .await;
    let mut rt = ValidatorRuntime::new(key.clone(), validators, state, 1);
    for tx in txs {
        rt.add_tx(tx.clone()).await;
    }
    (rt, pq_from)
}

/// Reuse is byte-identical to a fresh build when nothing changed, and the
/// cache never leaks across heights (stale ⇒ fresh path, no panic).
#[tokio::test]
async fn vel1_prebuild_reuse_is_byte_identical_to_fresh() {
    const TS: u64 = 1_700_000_001;
    // Same deterministic key for both runtimes: identical state, pool
    // and timestamp, so any selection divergence is a reuse bug.
    let key = SigningKey::generate(&mut OsRng);
    // A: prebuild during the idle window, then propose (reuse path).
    // The pool is minted ONCE and cloned into both runtimes (Falcon
    // signing is randomized, so independent minting would differ in
    // signature bytes and the inputs would not be identical).
    let txs: Vec<crate::sharding::Transaction> = (0..8u64)
        .map(|n| pq_tx(VEL1_POOL_SEED, [0x77u8; 32], 1_000, 21_000, n))
        .collect();
    let (mut a, _) = vel1_runtime_with_cloned_pool(&key, &txs).await;
    let h = a.hc.height;
    assert!(!a.has_prebuild_for(h), "no prebuild before the idle window");
    a.prebuild_next_proposal(TS).await;
    assert!(
        a.has_prebuild_for(h),
        "idle-window prebuild must cache this height"
    );
    let ba = a
        .propose(TS)
        .await
        .expect("reuse-path propose must succeed");
    // B: no prebuild, straight to propose (fresh path).
    let (mut b, _) = vel1_runtime_with_cloned_pool(&key, &txs).await;
    assert!(!b.has_prebuild_for(h));
    let bb = b
        .propose(TS)
        .await
        .expect("fresh-path propose must succeed");
    // Same inputs ⇒ same selection, same header, same block hash.
    // (The pool is shared and proposer signing is deterministic, so
    // even the signatures agree; any divergence here is a reuse bug,
    // not nondeterminism.)
    assert_eq!(
        ba.transactions.len(),
        8,
        "all 8 funded contiguous txs must pack, reuse path"
    );
    assert_eq!(
        ba.transactions
            .iter()
            .map(|t| t.compute_tx_hash())
            .collect::<Vec<_>>(),
        bb.transactions
            .iter()
            .map(|t| t.compute_tx_hash())
            .collect::<Vec<_>>(),
        "reuse path must select exactly the fresh path's transactions in order"
    );
    assert_eq!(
        ba.compute_hash(),
        bb.compute_hash(),
        "reuse block must be byte-identical to the fresh block"
    );
    // The cache is height-scoped: a different height never reuses.
    assert!(
        !a.has_prebuild_for(h + 1),
        "no cross-height reuse without a prebuild"
    );
}

/// Staleness fail-safe: state that moved under the prebuild (funds spent
/// elsewhere ⇒ the parent changed) only shrinks the reuse — the block
/// still builds and still validates. No invalid proposal, no panic.
#[tokio::test]
async fn vel1_prebuild_stale_state_degrades_to_valid_block() {
    const TS: u64 = 1_700_000_002;
    let key = SigningKey::generate(&mut OsRng);
    let (mut rt, me) = vel1_runtime_with_pool(&key, 6).await;
    // Falconize the proposer: production `propose` pushes BOTH halves,
    // and `validate_proposal_unaligned` refuses Ed-only blocks.
    let fk = crate::post_quantum::FalconKeypair::generate_from_seed(0xC8);
    rt = rt.with_falcon_key(fk);
    let h = rt.hc.height;
    rt.prebuild_next_proposal(TS).await;
    assert!(rt.has_prebuild_for(h));
    // Drain the sender elsewhere: every cached tx is now unfunded vs
    // live state (the "parent changed under the prebuild" shape).
    rt.state
        .update_account(crate::state_engine::AccountState::new(me, 0))
        .await;
    let b = rt
        .propose(TS)
        .await
        .expect("stale prebuild must still propose");
    let root = rt.state.get_state_root().await;
    assert!(
        b.transactions.is_empty(),
        "unfunded cached txs must be dropped by revalidation, got {}",
        b.transactions.len()
    );
    rt.validate_proposal_unaligned(&b, root)
        .expect("stale-prebuild block must still validate");
}

/// The pack predicate rejects exactly the invalid shapes (pins the
/// factored filter: admission-parity, no silent acceptance).
#[tokio::test]
async fn vel1_pack_filter_accepts_valid_rejects_invalid() {
    const TS: u64 = 1_700_000_003;
    let key = SigningKey::generate(&mut OsRng);
    let (rt, me) = vel1_runtime_with_pool(&key, 0).await;
    let state_root = rt.state.get_state_root().await;
    let (base_fee, penalties) = {
        let pool = rt.mempool.read().await;
        (pool.base_fee, pool.penalty_snapshot())
    };
    let session_keys = rt.state.session_keys_read().await.clone();
    let mut accounts = HashMap::new();
    accounts.insert(me, (0u64, 10_000_000u64));
    let ctx = PackFilterCtx::new(
        TS,
        false,
        crate::sharding::MASTERCHAIN_SHARD,
        base_fee,
        penalties,
        session_keys,
        accounts,
        crate::zkml::SessionSpendSim::default(),
        HashSet::new(),
    );
    let to = [0x77u8; 32];
    // FULL-PQ fixture: the funded sender is the VEL-1 Falcon-512 pool
    // identity (same property, PQ envelope — the filter never checks
    // signatures, only nonce continuity and the fee floor).
    let good = pq_tx(VEL1_POOL_SEED, to, 1_000, 21_000, 0);
    assert!(
        ValidatorRuntime::pack_filter_accept(&ctx, &good),
        "funded nonce-0 tx must pass"
    );
    // Consumed: the same tx re-checked now fails the nonce (state moved).
    let gap = pq_tx(VEL1_POOL_SEED, to, 1_000, 21_000, 5);
    assert!(
        !ValidatorRuntime::pack_filter_accept(&ctx, &gap),
        "nonce gap must be skipped"
    );
    let _ = state_root;
}

/// Loaded-size differential (500 txs, multi-sender): reuse ≡ fresh at
/// scale, with wall-clock timings printed for the report (host ms; the
/// harness models the virtual-ms effect separately).
#[tokio::test]
async fn vel1_prebuild_loaded_pool_reuse_matches_fresh() {
    const TS: u64 = 1_700_000_004;
    // FULL-PQ: 10 Falcon-512 senders (domain-separated seeds); the
    // classical `SigningKey` fixtures are refused at admission, so the
    // loaded pool would stay empty.
    const BASE_SEED: u8 = 0x50;
    let valkey = SigningKey::generate(&mut OsRng);
    let me = valkey.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(me, 1)]);
    let mk = || {
        let state = Arc::new(InMemoryStateEngine::new());
        ValidatorRuntime::new(valkey.clone(), validators.clone(), state, 1)
    };
    let mut a = mk();
    let mut b = mk();
    // One shared pool: Falcon signing is randomized, so each runtime
    // must receive CLONES of the same mint (see the reuse test) for the
    // inputs to be identical.
    let pool: Vec<crate::sharding::Transaction> = (0..10u8)
        .flat_map(|s| {
            let seed = BASE_SEED + s;
            (0..50u64).map(move |n| pq_tx(seed, [0x77u8; 32], 1_000, 21_000, n))
        })
        .collect();
    for rt in [&mut a, &mut b] {
        for s in 0..10u8 {
            let (from, _pk) = pq_pair(BASE_SEED + s);
            rt.state
                .update_account(crate::state_engine::AccountState::new(from, 100_000_000))
                .await;
        }
        for tx in &pool {
            rt.add_tx(tx.clone()).await;
        }
    }
    // Reuse path: prebuild first, then time propose.
    a.prebuild_next_proposal(TS).await;
    assert!(a.has_prebuild_for(a.hc.height));
    let t0 = std::time::Instant::now();
    let ba = a.propose(TS).await.expect("reuse propose");
    let reuse_ms = t0.elapsed().as_secs_f64() * 1000.0;
    // Fresh path: straight to propose, timed.
    let t0 = std::time::Instant::now();
    let bb = b.propose(TS).await.expect("fresh propose");
    let fresh_ms = t0.elapsed().as_secs_f64() * 1000.0;
    println!(
        "[vel1] loaded-pool propose fresh={fresh_ms:.2}ms reuse={reuse_ms:.2}ms txs={}",
        bb.transactions.len()
    );
    assert_eq!(ba.transactions.len(), bb.transactions.len());
    assert_eq!(
        ba.compute_hash(),
        bb.compute_hash(),
        "loaded reuse must match fresh"
    );
    assert!(!bb.transactions.is_empty(), "loaded pool must pack");
}

/// Cap truncation keeps a valid prefix and respects every block cap.
#[test]
fn vel1_truncate_to_block_caps_keeps_valid_prefix() {
    use crate::sharding::Transaction;
    let key = SigningKey::generate(&mut OsRng);
    let to = [0x77u8; 32];
    let mut txs: Vec<Transaction> = (0..10u64)
        .map(|n| {
            Transaction::sign(
                &key,
                to,
                1,
                1_000_000,
                n,
                crate::sharding::MASTERCHAIN_SHARD,
                crate::sharding::MASTERCHAIN_SHARD,
            )
        })
        .collect();
    // Within caps: untouched.
    let mut ok = txs.clone();
    ValidatorRuntime::truncate_to_block_caps(&mut ok);
    assert_eq!(ok.len(), 10);
    // Force over gas late in the list: truncation keeps the valid prefix.
    txs[8].gas_limit = u64::MAX / 2;
    let mut over = txs.clone();
    ValidatorRuntime::truncate_to_block_caps(&mut over);
    assert_eq!(
        over.len(),
        8,
        "over-cap selection must truncate to the fitting prefix"
    );
    assert_eq!(
        over[0].compute_tx_hash(),
        txs[0].compute_tx_hash(),
        "truncation must keep the prefix (nonce contiguity)"
    );
    let mut empty: Vec<Transaction> = Vec::new();
    ValidatorRuntime::truncate_to_block_caps(&mut empty);
    assert!(empty.is_empty());
}

/// C-02/P0: the live-path sweep finalizes due proposals at the decided
/// height — locks release and the 7200-height timelock schedules.
/// // GATE: proves the `sweep_gov_finalize` wiring; extends, never weakens.
#[tokio::test]
async fn sweep_gov_finalize_releases_locks_and_schedules_timelock() {
    use crate::governance::{
        GovAction, ProposalStatus, VoteChoice, GOVERNANCE_VOTING_PERIOD_SECS, GOV_TIMELOCK_HEIGHTS,
        PROPOSAL_MIN_STAKE_NANO,
    };
    let state = Arc::new(InMemoryStateEngine::new());
    let proposer = [0xA1u8; 32];
    let voter = [0xB2u8; 32];
    {
        let mut ledger = state.staking_write().await;
        ledger.bond(proposer, PROPOSAL_MIN_STAKE_NANO, 0).unwrap();
        ledger.bond(voter, PROPOSAL_MIN_STAKE_NANO, 0).unwrap();
    }
    let pid = {
        let mut gov = state.governance_write().await;
        let mut ledger = state.staking_write().await;
        let id = gov
            .propose(
                &mut ledger,
                proposer,
                "t".into(),
                GovAction::Signal("s".into()),
                0,
            )
            .expect("propose");
        gov.vote(&mut ledger, proposer, id, VoteChoice::Yes, 1)
            .expect("proposer vote");
        gov.vote(&mut ledger, voter, id, VoteChoice::Yes, 1)
            .expect("voter vote");
        id
    };
    // Locks are held before finalization (the C-02 grief: never released).
    {
        let ledger = state.staking_read().await;
        assert!(ledger.locked_governance_of(&proposer) > 0);
        assert!(ledger.locked_governance_of(&voter) > 0);
    }
    // Not due yet (voting window still open): the sweep leaves it Open.
    let now_due = GOVERNANCE_VOTING_PERIOD_SECS + 1;
    let early = sweep_gov_finalize(&state, 999, GOVERNANCE_VOTING_PERIOD_SECS - 1).await;
    assert!(early.is_empty());
    assert_eq!(
        state.governance_read().await.get(pid).unwrap().status,
        ProposalStatus::Open
    );
    // Due at the decided height: finalized, locks released, timelock set.
    let pass_height = 41_000u64;
    let done = sweep_gov_finalize(&state, pass_height, now_due).await;
    assert_eq!(done, vec![pid]);
    assert_eq!(
        state.governance_read().await.get(pid).unwrap().status,
        ProposalStatus::Passed
    );
    assert!(
        state.staking_read().await.locked_governance.is_empty(),
        "finalize must release every gov lock"
    );
    assert_eq!(
        state.governance_read().await.executable_height_of(pid),
        Some(pass_height + GOV_TIMELOCK_HEIGHTS)
    );
    // Idempotent: a second sweep at a later height is a no-op.
    let again = sweep_gov_finalize(&state, pass_height + 1, now_due).await;
    assert!(again.is_empty());
}

/// Serializes the env-touching gate tests below: the escape hatch is
/// process-global, so the set/restore in the escape test must never
/// overlap the unset expectation of the refuse test (parallel lib tests
/// share one process).
static GOV_GATE_ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_gate_env() -> std::sync::MutexGuard<'static, ()> {
    GOV_GATE_ENV_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Build a runtime with `n` bonded stakers (>= propose minimum) and an
/// attached governance engine. The runtime's in-force validator set has
/// exactly `n` members, which is what the write guard reads.
async fn gate_test_runtime(n: usize) -> (ValidatorRuntime, Vec<ValidatorId>) {
    use crate::governance::{Governance, PROPOSAL_MIN_STAKE_NANO};
    let keys: Vec<SigningKey> = (0..n)
        .map(|i| SigningKey::from_bytes(&[(i as u8).wrapping_add(1); 32]))
        .collect();
    let ids: Vec<ValidatorId> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let vs = ValidatorSet::from_list(ids.iter().map(|id| (*id, 1)).collect());
    let state = Arc::new(InMemoryStateEngine::new());
    {
        let mut ledger = state.staking_write().await;
        for id in &ids {
            ledger
                .bond(
                    *id,
                    PROPOSAL_MIN_STAKE_NANO,
                    crate::staking::DEFAULT_COMMISSION_BPS,
                )
                .expect("test bond must succeed");
        }
    }
    let rt =
        ValidatorRuntime::new(keys[0].clone(), vs, state, 1).with_governance(Governance::new());
    (rt, ids)
}

/// Solo runtime (1 validator): propose + vote go through (existing
/// behavior preserved). Passes with or without the escape env, so no
/// env guard is needed.
#[tokio::test]
async fn gov_write_gate_solo_allows_propose_and_vote() {
    use crate::governance::{GovAction, VoteChoice};
    let (mut rt, ids) = gate_test_runtime(1).await;
    let pid = rt
        .gov_propose(ids[0], "t".into(), GovAction::Signal("s".into()), 0)
        .expect("solo propose must succeed");
    rt.gov_vote(ids[0], pid, VoteChoice::Yes, 1)
        .expect("solo vote must succeed");
}

/// Multi-node runtime (3 validators): propose AND vote are refused as
/// multi-node — the vote refusal proves the gate runs BEFORE any
/// proposal lookup (an unknown id would otherwise fail as
/// `UnknownProposal`, hiding the real reason).
#[tokio::test]
async fn gov_write_gate_multi_node_refuses_propose_and_vote() {
    use crate::governance::{GovAction, GovError, VoteChoice, GOV_MULTINODE_WRITES_ENV};
    // Built BEFORE arming the env guard: construction touches no env,
    // and the guard must never be held across an await.
    let (mut rt, ids) = gate_test_runtime(3).await;
    {
        let _guard = lock_gate_env();
        let saved = std::env::var(GOV_MULTINODE_WRITES_ENV).ok();
        std::env::remove_var(GOV_MULTINODE_WRITES_ENV);
        let propose_err = rt
            .gov_propose(ids[0], "t".into(), GovAction::Signal("s".into()), 0)
            .expect_err("multi-node propose must be refused");
        match &propose_err {
            GovError::MultiNodeRefused(msg) => assert!(
                msg.contains(GOV_MULTINODE_WRITES_ENV),
                "refusal must name the escape env, got: {msg}"
            ),
            other => panic!("expected MultiNodeRefused, got: {other:?}"),
        }
        let vote_err = rt
            .gov_vote(ids[0], 999_999, VoteChoice::Yes, 1)
            .expect_err("multi-node vote must be refused");
        assert!(
            matches!(vote_err, GovError::MultiNodeRefused(_)),
            "vote must fail at the gate, not at lookup; got: {vote_err:?}"
        );
        match saved {
            Some(v) => std::env::set_var(GOV_MULTINODE_WRITES_ENV, v),
            None => std::env::remove_var(GOV_MULTINODE_WRITES_ENV),
        }
    }
}

/// Escape hatch: with `STELL_GOV_ALLOW_MULTINODE_WRITES=1` the same
/// 3-validator runtime proposes and votes (re-allowed explicitly).
#[tokio::test]
async fn gov_write_gate_escape_reallows_multi_node() {
    use crate::governance::{GovAction, VoteChoice, GOV_MULTINODE_WRITES_ENV};
    // Built BEFORE arming the env guard: construction touches no env,
    // and the guard must never be held across an await.
    let (mut rt, ids) = gate_test_runtime(3).await;
    {
        let _guard = lock_gate_env();
        let saved = std::env::var(GOV_MULTINODE_WRITES_ENV).ok();
        std::env::set_var(GOV_MULTINODE_WRITES_ENV, "1");
        let pid = rt
            .gov_propose(ids[0], "t".into(), GovAction::Signal("s".into()), 0)
            .expect("escaped propose must succeed");
        rt.gov_vote(ids[0], pid, VoteChoice::Yes, 1)
            .expect("escaped vote must succeed");
        match saved {
            Some(v) => std::env::set_var(GOV_MULTINODE_WRITES_ENV, v),
            None => std::env::remove_var(GOV_MULTINODE_WRITES_ENV),
        }
    }
}
