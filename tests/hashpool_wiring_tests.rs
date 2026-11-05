//! HashPool APPLY wiring tests (default-OFF gate).
//!
//! Exercises the `state_engine.rs` HashPool sub-state through the crate's own
//! types (`stellereum::hashpool`, `stellereum::state_engine`) — no
//! path-included copy: these tests prove the REAL wiring, while
//! `tests/hashpool_tests.rs` keeps pinning the unwired prototype shapes.
//!
//! Gate contract under test (`state_engine::HASH_POOL_ENABLED = false`, no
//! env knob):
//! * OFF (default): every `apply_hashpool_*` entry point refuses with
//!   `HashPoolOpError::Disabled` (nothing read, nothing written) and
//!   `apply_block_transition_with_hashpool` skips the sidecar wholesale —
//!   the base outcome and the state root equal the plain
//!   `apply_block_transition` path exactly.
//! * ON (tests only, via `enable_hashpool_for_tests`): deposits register
//!   commitments, spends consume nullifiers (double-spend refused),
//!   CoinJoin batches verify (real Falcon-512) conservation and apply, and
//!   state roots reflect pool ops deterministically.

use stellereum::hashpool::{
    CoinJoinBatch, HashPool, HpError, OutputNote, SpendOpening, coinjoin_build, coinjoin_sig_msg,
    coinjoin_verify, note_commit, note_nullifier,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme, verify_pq_signature};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::{
    HashPoolApplyOutcome, HashPoolBlockOps, HashPoolDepositOp, HashPoolOpError, HashPoolSpendOp,
    InMemoryStateEngine, HASH_POOL_ENABLED,
};

// Compile-time pin: flipping the gate const breaks this suite's build.
const _: () = assert!(!HASH_POOL_ENABLED, "wiring gate must default to OFF");

// ---------------------------------------------------------------------------
// Helpers (same shapes as `tests/hashpool_tests.rs`, rebuilt here against
// the crate types so the wiring — not a copy — is exercised).
// ---------------------------------------------------------------------------

fn kem_seed(byte: u8) -> [u8; 64] {
    [byte; 64]
}

fn ek_bytes(seed_byte: u8) -> Vec<u8> {
    use ml_kem::{
        MlKem768,
        kem::{FromSeed, KeyExport},
    };
    let seed: ml_kem::Seed = kem_seed(seed_byte).into();
    let (_, ek) = MlKem768::from_seed(&seed);
    ek.to_bytes().as_slice().to_vec()
}

fn falcon(seed_byte: u8) -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&[seed_byte; 32])
}

fn falcon_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    verify_pq_signature(PqScheme::Falcon512, pk, msg, sig)
}

const DENOM: u64 = 25;

/// Fresh engine chain id (whatever the binary defaults to with no env set).
fn engine_chain() -> u64 {
    InMemoryStateEngine::new().chain_id
}

/// Fund an enabled engine's pool with `n` denomination-`DENOM` notes.
/// Returns the spend openings plus one Falcon owner key per note.
async fn fund_engine(
    engine: &InMemoryStateEngine,
    chain: u64,
    n: usize,
) -> (Vec<SpendOpening>, Vec<FalconKeypair>) {
    let mut openings = Vec::with_capacity(n);
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let ek = ek_bytes(0x10 + i as u8);
        let randomness = [(0xA0 + i as u8); 32];
        let (_, stealth) =
            stellereum::hashpool::stealth_encap(&ek, i as u64, &randomness).expect("encap");
        let blinding = [(0xB0 + i as u8); 32];
        let serial = [(0xC0 + i as u8); 32];
        let c = note_commit(chain, DENOM, &blinding, &stealth);
        let nf = note_nullifier(&serial);
        engine
            .apply_hashpool_deposit(c, stealth, nf)
            .await
            .expect("deposit applies while gate is on");
        openings.push(SpendOpening { serial, value: DENOM, blinding, stealth });
        keys.push(falcon(0xD0 + i as u8));
    }
    (openings, keys)
}

/// Sign the canonical message for (`openings`, `outputs`, `fee`) with `keys`.
fn sign_canonical(
    chain: u64,
    openings: &[SpendOpening],
    outputs: &[OutputNote],
    fee: u64,
    keys: &[FalconKeypair],
) -> Vec<(SpendOpening, Vec<u8>, Vec<u8>)> {
    let mut in_cs: Vec<[u8; 32]> = openings
        .iter()
        .map(|o| note_commit(chain, o.value, &o.blinding, &o.stealth))
        .collect();
    in_cs.sort();
    let mut in_nfs: Vec<[u8; 32]> = openings.iter().map(|o| note_nullifier(&o.serial)).collect();
    in_nfs.sort();
    let mut out_pairs: Vec<([u8; 32], [u8; 32])> = outputs
        .iter()
        .map(|o| (note_commit(chain, o.value, &o.blinding, &o.stealth), note_nullifier(&o.serial)))
        .collect();
    out_pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let out_cs: Vec<[u8; 32]> = out_pairs.iter().map(|(c, _)| *c).collect();
    let out_nfs: Vec<[u8; 32]> = out_pairs.iter().map(|(_, n)| *n).collect();
    let msg = coinjoin_sig_msg(chain, &in_cs, &in_nfs, &out_cs, &out_nfs, fee);
    openings
        .iter()
        .zip(keys.iter())
        .map(|(o, k)| (o.clone(), k.public_key.clone(), k.sign(&msg)))
        .collect()
}

fn fresh_outputs(n: usize) -> Vec<OutputNote> {
    (0..n)
        .map(|i| OutputNote {
            value: DENOM,
            blinding: [(0xE0 + i as u8); 32],
            stealth: [(0xF0 + i as u8); 32],
            serial: [(0x08 + i as u8); 32],
        })
        .collect()
}

/// Minimal deterministic block (no transactions): enough for
/// `apply_block_transition`, whose evidence fields are all `None`/zero.
fn empty_block(height: u64) -> Block {
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        timestamp: 1000 + height,
        proposer: [0xCC; 32],
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// OFF: the const default + loud refusals + byte-identical block path.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gate_is_off_by_default() {
    let engine = InMemoryStateEngine::new();
    assert!(
        !engine.hashpool_enabled(),
        "fresh engine must not have the pool live"
    );
    assert_eq!(engine.hashpool_len().await, 0);
    assert_eq!(engine.hashpool_spent_len().await, 0);
}

#[tokio::test]
async fn off_path_refuses_without_touching_state() {
    let engine = InMemoryStateEngine::new();
    let root_before = engine.get_state_root().await;
    let c = [0x11u8; 32];
    assert_eq!(
        engine.apply_hashpool_deposit(c, [0x22u8; 32], [0x33u8; 32]).await,
        Err(HashPoolOpError::Disabled)
    );
    assert_eq!(
        engine
            .apply_hashpool_spend(&c, &[0x44u8; 32], DENOM, &[0x55u8; 32])
            .await,
        Err(HashPoolOpError::Disabled)
    );
    let batch = CoinJoinBatch {
        chain_id: engine.chain_id,
        fee: 0,
        inputs: vec![],
        outputs: vec![],
    };
    assert_eq!(
        engine.apply_hashpool_batch(&batch).await,
        Err(HashPoolOpError::Disabled)
    );
    assert_eq!(engine.hashpool_len().await, 0);
    assert!(!engine.hashpool_contains(&c).await);
    assert_eq!(
        engine.get_state_root().await, root_before,
        "refused ops must not move the state root"
    );
}

#[tokio::test]
async fn off_path_block_sidecar_is_byte_identical() {
    // Same block on two fresh engines: plain path vs sidecar path with a
    // NON-EMPTY sidecar while the gate is off. Outcomes and roots must match
    // exactly; the sidecar reports a wholesale skip.
    let chain = engine_chain();
    let ek = ek_bytes(0x10);
    let (_, stealth) =
        stellereum::hashpool::stealth_encap(&ek, 0, &[0xA0u8; 32]).expect("encap");
    let blinding = [0xB0u8; 32];
    let serial = [0xC0u8; 32];
    let c = note_commit(chain, DENOM, &blinding, &stealth);
    let ops = HashPoolBlockOps {
        deposits: vec![HashPoolDepositOp { commitment: c, stealth, nullifier: note_nullifier(&serial) }],
        spends: vec![HashPoolSpendOp { commitment: c, serial, value: DENOM, blinding }],
        batches: vec![],
    };

    let plain = InMemoryStateEngine::new();
    let block = empty_block(1);
    let base = plain.apply_block_transition(&block, 0).await;
    let root_plain = plain.get_state_root().await;

    let wired = InMemoryStateEngine::new();
    let (base2, hp) = wired
        .apply_block_transition_with_hashpool(&block, 0, &ops)
        .await;
    assert_eq!(base, base2, "base outcome must equal the plain path");
    assert!(
        hp.skipped_gate_off,
        "sidecar must report a wholesale skip while off"
    );
    assert_eq!(
        hp,
        HashPoolApplyOutcome { skipped_gate_off: true, ..Default::default() },
        "no op may be counted while off"
    );
    assert_eq!(wired.hashpool_len().await, 0);
    assert_eq!(
        wired.get_state_root().await, root_plain,
        "state root must equal the plain path exactly while off"
    );
}

// ---------------------------------------------------------------------------
// ON (tests only): deposits, spends, double-spend refusal, batches,
// conservation, deterministic roots.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deposit_registers_and_root_moves_deterministically() {
    let a = InMemoryStateEngine::new();
    a.enable_hashpool_for_tests().await;
    assert!(a.hashpool_enabled());
    let chain = a.chain_id;
    let bare = a.get_state_root().await;

    let ek = ek_bytes(0x10);
    let (_, stealth) =
        stellereum::hashpool::stealth_encap(&ek, 0, &[0xA0u8; 32]).expect("encap");
    let blinding = [0xB0u8; 32];
    let serial = [0xC0u8; 32];
    let c = note_commit(chain, DENOM, &blinding, &stealth);
    let nf = note_nullifier(&serial);
    a.apply_hashpool_deposit(c, stealth, nf).await.expect("deposit");
    assert!(a.hashpool_contains(&c).await);
    assert_eq!(a.hashpool_len().await, 1);
    let moved = a.get_state_root().await;
    assert_ne!(moved, bare, "pool ops must move the state root when on");

    // Duplicate registration is refused; root does not move again.
    assert_eq!(
        a.apply_hashpool_deposit(c, stealth, nf).await,
        Err(HashPoolOpError::Pool(HpError::DuplicateDeposit))
    );
    assert_eq!(a.get_state_root().await, moved);

    // Determinism: a second engine with the same ops derives the same root.
    let b = InMemoryStateEngine::new();
    b.enable_hashpool_for_tests().await;
    b.apply_hashpool_deposit(c, stealth, nf).await.expect("deposit");
    assert_eq!(
        b.get_state_root().await, moved,
        "same ops must derive the same root on every node"
    );
}

#[tokio::test]
async fn spend_consumes_and_double_spend_refused() {
    let engine = InMemoryStateEngine::new();
    engine.enable_hashpool_for_tests().await;
    let chain = engine.chain_id;
    let (openings, _) = fund_engine(&engine, chain, 1).await;
    let o = &openings[0];
    let c = note_commit(chain, o.value, &o.blinding, &o.stealth);
    let nf = note_nullifier(&o.serial);

    let spent = engine
        .apply_hashpool_spend(&c, &o.serial, o.value, &o.blinding)
        .await
        .expect("first spend applies");
    assert_eq!(spent, nf);
    assert!(engine.hashpool_is_spent(&nf).await);
    assert_eq!(engine.hashpool_spent_len().await, 1);

    // Same nullifier twice: refused.
    assert_eq!(
        engine.apply_hashpool_spend(&c, &o.serial, o.value, &o.blinding).await,
        Err(HashPoolOpError::Pool(HpError::AlreadySpent))
    );
    // Serial substitution on the same note: refused (serial bound at deposit).
    assert_eq!(
        engine
            .apply_hashpool_spend(&c, &[0x04u8; 32], o.value, &o.blinding)
            .await,
        Err(HashPoolOpError::Pool(HpError::SerialMismatch))
    );
    // Tampered value: recomputation misses.
    assert_eq!(
        engine.apply_hashpool_spend(&c, &o.serial, o.value + 1, &o.blinding).await,
        Err(HashPoolOpError::Pool(HpError::CommitmentMismatch))
    );
}

#[tokio::test]
async fn batch_verifies_conservation_and_applies() {
    let engine = InMemoryStateEngine::new();
    engine.enable_hashpool_for_tests().await;
    let chain = engine.chain_id;
    let (openings, keys) = fund_engine(&engine, chain, 4).await;
    let outputs = fresh_outputs(4);
    let spends = sign_canonical(chain, &openings, &outputs, 0, &keys);
    let batch = coinjoin_build(chain, spends, outputs.clone(), 0).expect("build");

    // Conservation pinned: 4x25 in == 4x25 out + 0 fee.
    let sum_in: u64 = batch.inputs.iter().map(|i| i.opening.value).sum();
    let sum_out: u64 = batch.outputs.iter().map(|o| o.value).sum();
    assert_eq!((sum_in, sum_out, batch.fee), (100, 100, 0));

    // Direct verify-then-apply through the engine (real Falcon-512).
    coinjoin_verify(
        &{
            // Cross-check against a pristine pool copy: the engine pool must
            // verify the batch before it applies it.
            let mut p = HashPool::new(chain);
            for o in &openings {
                p.deposit(
                    note_commit(chain, o.value, &o.blinding, &o.stealth),
                    o.stealth,
                    note_nullifier(&o.serial),
                )
                .expect("deposit");
            }
            p
        },
        &batch,
        &falcon_verify,
    )
    .expect("batch verifies against identical pool state");
    engine.apply_hashpool_batch(&batch).await.expect("apply");
    assert_eq!(engine.hashpool_len().await, 8);
    assert_eq!(engine.hashpool_spent_len().await, 4);
    for o in &outputs {
        assert!(engine.hashpool_contains(&note_commit(chain, o.value, &o.blinding, &o.stealth)).await);
        assert!(!engine.hashpool_is_spent(&note_nullifier(&o.serial)).await);
    }
    // Inputs are now spent: note-level re-spend is refused too.
    let first = &batch.inputs[0];
    assert_eq!(
        engine
            .apply_hashpool_spend(
                &first.commitment,
                &first.opening.serial,
                DENOM,
                &first.opening.blinding
            )
            .await,
        Err(HashPoolOpError::Pool(HpError::AlreadySpent))
    );
}

#[tokio::test]
async fn unbalanced_batch_refused_state_untouched() {
    let engine = InMemoryStateEngine::new();
    engine.enable_hashpool_for_tests().await;
    let chain = engine.chain_id;
    let (openings, keys) = fund_engine(&engine, chain, 4).await;
    let before = engine.get_state_root().await;

    // Uniform but short: 4x25 in vs 3x25 out, fee 0 — build itself refuses.
    let short = fresh_outputs(3);
    let spends = sign_canonical(chain, &openings, &short, 0, &keys);
    assert_eq!(
        coinjoin_build(chain, spends, short, 0),
        Err(HpError::Unbalanced { sum_in: 100, sum_out: 75, fee: 0 })
    );

    // A structurally valid batch whose signature is broken is refused at
    // apply time and changes nothing.
    let outputs = fresh_outputs(4);
    let mut spends = sign_canonical(chain, &openings, &outputs, 0, &keys);
    spends[2].2[10] ^= 0x01;
    let bad = coinjoin_build(chain, spends, outputs, 0).expect("build");
    assert_eq!(
        engine.apply_hashpool_batch(&bad).await,
        Err(HashPoolOpError::Pool(HpError::BadSignature))
    );
    assert_eq!(engine.hashpool_len().await, 4);
    assert_eq!(engine.hashpool_spent_len().await, 0);
    assert_eq!(
        engine.get_state_root().await, before,
        "refused batch must leave pool and root untouched"
    );
}

#[tokio::test]
async fn block_sidecar_applies_ops_in_order() {
    let engine = InMemoryStateEngine::new();
    engine.enable_hashpool_for_tests().await;
    let chain = engine.chain_id;

    // Build deposits sidecar-first: 4 funded notes, then a batch spending
    // all 4 into 4 fresh outputs, all inside ONE block transition.
    let mut deposits = Vec::new();
    let mut openings = Vec::new();
    let mut keys = Vec::new();
    for i in 0..4 {
        let ek = ek_bytes(0x10 + i as u8);
        let randomness = [(0xA0 + i as u8); 32];
        let (_, stealth) =
            stellereum::hashpool::stealth_encap(&ek, i as u64, &randomness).expect("encap");
        let blinding = [(0xB0 + i as u8); 32];
        let serial = [(0xC0 + i as u8); 32];
        let c = note_commit(chain, DENOM, &blinding, &stealth);
        deposits.push(HashPoolDepositOp {
            commitment: c,
            stealth,
            nullifier: note_nullifier(&serial),
        });
        openings.push(SpendOpening { serial, value: DENOM, blinding, stealth });
        keys.push(falcon(0xD0 + i as u8));
    }
    let outputs = fresh_outputs(4);
    let spends = sign_canonical(chain, &openings, &outputs, 0, &keys);
    let batch = coinjoin_build(chain, spends, outputs.clone(), 0).expect("build");
    let ops = HashPoolBlockOps { deposits, spends: vec![], batches: vec![batch] };

    let block = empty_block(1);
    let (base, hp) = engine.apply_block_transition_with_hashpool(&block, 0, &ops).await;
    assert_eq!((base.applied, base.failed), (0, 0));
    assert_eq!(
        hp,
        HashPoolApplyOutcome {
            deposits_applied: 4,
            batches_applied: 1,
            ..Default::default()
        }
    );
    assert_eq!(engine.hashpool_len().await, 8);
    assert_eq!(engine.hashpool_spent_len().await, 4);

    // Determinism across nodes: an identical engine applying the identical
    // block + sidecar derives the identical root.
    let mirror = InMemoryStateEngine::new();
    mirror.enable_hashpool_for_tests().await;
    let (base_b, hp_b) = mirror.apply_block_transition_with_hashpool(&block, 0, &ops).await;
    assert_eq!(base, base_b);
    assert_eq!(hp, hp_b);
    assert_eq!(
        mirror.get_state_root().await,
        engine.get_state_root().await,
        "identical block + sidecar must derive the identical root"
    );
}
