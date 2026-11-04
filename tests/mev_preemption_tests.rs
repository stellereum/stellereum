//! MEV preemption on the REAL path (passport §6).
//!
//! What is wired (see `src/mev.rs` module docs for the full honest split):
//! * seal at admission — every transaction entering `Mempool::insert` is sealed
//!   under the node's blind-round key and kept as an envelope keyed by tx hash;
//! * unseal at block build — `ValidatorRuntime::propose` re-opens every
//!   selected envelope and requires a byte-exact match before the transaction
//!   may enter a block;
//! * order commitment at build + verification at apply — the build signs the
//!   exact execution order, and `try_finalize` refuses to execute a block whose
//!   order (or commitment) does not match.
//!
//! What is deferred (threshold share release, client-side round-public-key
//! sealing, sealed gossip) is documented in `src/mev.rs` and deliberately
//! absent here: it needs wire slots that do not exist, and faking it locally
//! would be security theater.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::mempool::Mempool;
use stellereum::mev::{MevPreemptionEngine, OrderVerdict, SealVerdict};
use stellereum::runtime::Cluster;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

fn engine_with() -> Arc<InMemoryStateEngine> {
    Arc::new(InMemoryStateEngine::new())
}

async fn seed(st: &InMemoryStateEngine, from: [u8; 32]) {
    st.update_account(AccountState::new(from, 10_000_000)).await;
}

/// Two honest validators, quorum 2, one funded user. Enough for finalize.
async fn cluster_of_two(from: [u8; 32]) -> Cluster {
    let keys: Vec<SigningKey> = (0..2).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let nodes: Vec<_> = keys.iter().map(|k| (k.clone(), engine_with())).collect();
    let mut cluster = Cluster::new(nodes);
    for n in cluster.nodes.iter_mut() {
        seed(&n.state, from).await;
    }
    cluster
}

/// What to tamper with between vote collection and finalize.
#[derive(Clone, Copy)]
enum Tamper {
    /// Corrupt the proposer's build-time commitment signature.
    BreakCommitmentSignature,
    /// Reverse the transaction order in the proposer's stored block body.
    ReorderStoredBody,
}

/// Replicates `Cluster::run_height` with a tamper hook between vote
/// collection and finalize.
async fn run_height_tampered(cluster: &mut Cluster, timestamp: u64, tamper: Tamper) {
    let proposer_idx = cluster
        .nodes
        .iter()
        .position(|n| n.is_proposer())
        .expect("no proposer for this height");
    let block = cluster.nodes[proposer_idx]
        .propose(timestamp)
        .await
        .expect("proposer failed to propose");
    let bh = block.compute_hash();
    let proposer_id = cluster.nodes[proposer_idx].id;
    for (i, n) in cluster.nodes.iter_mut().enumerate() {
        if i != proposer_idx {
            let r = n.hc.round;
            n.on_proposal(proposer_id, block.clone(), r)
                .await
                .expect("proposal rejected");
        }
    }
    let prevotes: Vec<_> = cluster
        .nodes
        .iter()
        .filter_map(|n| n.make_prevote())
        .collect();
    for v in &prevotes {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_prevote(v.clone());
        }
    }
    let precommits: Vec<_> = cluster
        .nodes
        .iter_mut()
        .filter_map(|n| n.make_precommit())
        .collect();
    for v in &precommits {
        for n in cluster.nodes.iter_mut() {
            let _ = n.on_precommit(v.clone());
        }
    }
    // ---- tamper point: votes are collected, finalize has not run ----
    match tamper {
        Tamper::BreakCommitmentSignature => {
            let p = &mut cluster.nodes[proposer_idx];
            let mut pool = p.mempool.write().await;
            let commit = pool
                .mev
                .order_commits
                .get_mut(&(1, bh))
                .expect("proposer committed an order at build");
            commit.validator_shares[0].1[0] ^= 0xFF;
        }
        Tamper::ReorderStoredBody => {
            let p = &mut cluster.nodes[proposer_idx];
            let body = p.blocks.get_mut(&bh).expect("proposer has its own body");
            assert_eq!(
                body.transactions.len(),
                2,
                "need two transactions to reorder"
            );
            body.transactions.reverse();
        }
    }
    for n in cluster.nodes.iter_mut() {
        let _ = n.try_finalize().await;
    }
}

#[tokio::test]
async fn sealed_admission_unseals_to_the_same_transaction() {
    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, [9u8; 32], 100, 10, 0, 1, 1);

    // Admission through the real pool seals the transaction...
    let mut mp = Mempool::new(16, 16);
    let h = mp.add(tx.clone()).unwrap();
    assert!(
        mp.mev.pool_envelopes.contains_key(&h),
        "admission must leave a sealed envelope behind"
    );

    // ...and the envelope opens to the exact admitted bytes.
    assert_eq!(mp.mev.verify_pool_tx(&tx), SealVerdict::Match);
    let env = mp
        .mev
        .pool_envelopes
        .get(&h)
        .expect("envelope present")
        .clone();
    let unsealed = mp
        .mev
        .unseal_transaction(&env)
        .expect("round key must open our own seal");
    assert_eq!(unsealed, bincode::serialize(&tx).unwrap());

    // The recovered bytes ARE the transaction: reparse, verify the signature,
    // and the byte stream is stable under a second roundtrip.
    let reparsed: Transaction = bincode::deserialize(&unsealed).expect("roundtrip decodes");
    assert_eq!(bincode::serialize(&reparsed).unwrap(), unsealed);
    assert!(
        reparsed.verify_signature(),
        "unsealed transaction must still be valid"
    );
    assert_eq!(reparsed.from, tx.from);
    assert_eq!(reparsed.to, tx.to);
    assert_eq!(reparsed.amount, tx.amount);
    assert_eq!(reparsed.nonce, tx.nonce);
    assert_eq!(reparsed.gas_limit, tx.gas_limit);
}

#[tokio::test]
async fn sealed_then_unsealed_tx_executes_identically_to_a_direct_one() {
    let sk = SigningKey::generate(&mut OsRng);
    let from = sk.verifying_key().to_bytes();
    let to = [9u8; 32];
    let direct = Transaction::sign(&sk, to, 1_000, 0, 0, 1, 1);

    // Seal/unseal the SAME logical transaction through the mempool path.
    let mut mp = Mempool::new(16, 16);
    let h = mp.add(direct.clone()).unwrap();
    let env = mp.mev.pool_envelopes.get(&h).expect("envelope").clone();
    let unsealed = mp.mev.unseal_transaction(&env).expect("unseal");
    let via_seal: Transaction = bincode::deserialize(&unsealed).expect("decode");

    // Two identical engines, one block each: direct vs sealed-then-unsealed.
    use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
    let make_block = |tx: Transaction, state_root: [u8; 32]| {
        let __order_txs = vec![tx];
        let order_merkle_root = stellereum::mev::compute_order_merkle_root(&__order_txs);
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root,
            transactions: __order_txs,
            cross_shard_out: vec![],
            timestamp: 1_000,
            proposer: [1u8; 32],
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root,
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(&SigningKey::from_bytes(&[7u8; 32]));
        b
    };

    let s1 = InMemoryStateEngine::new();
    let s2 = InMemoryStateEngine::new();
    seed(&s1, from).await;
    seed(&s2, from).await;
    let root_before = s1.get_state_root().await;
    assert_eq!(root_before, s2.get_state_root().await, "identical genesis");

    let out1 = s1
        .apply_block_transition(&make_block(direct, root_before), 0)
        .await;
    let out2 = s2
        .apply_block_transition(&make_block(via_seal, root_before), 0)
        .await;

    assert_eq!(out1.applied, 1, "direct transaction must apply");
    assert_eq!(
        out2.applied, 1,
        "sealed-then-unsealed transaction must apply"
    );
    assert!(out1.status[0] && out2.status[0], "both must succeed");
    assert_eq!(
        s1.get_state_root().await,
        s2.get_state_root().await,
        "a transaction that went through seal/unseal must execute identically"
    );
}

#[tokio::test]
async fn mutated_pool_copy_and_tampered_ciphertext_fail_the_unseal_gate() {
    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, [9u8; 32], 100, 10, 0, 1, 1);

    // Case 1: the ciphertext in the engine is tampered with.
    let mut mp = Mempool::new(16, 16);
    let h = mp.add(tx.clone()).unwrap();
    {
        let env = mp.mev.pool_envelopes.get_mut(&h).expect("envelope");
        env.encrypted_payload[0] ^= 0xFF;
    }
    assert_eq!(
        mp.mev.verify_pool_tx(&tx),
        SealVerdict::UnsealFailed,
        "a tampered envelope must not open"
    );

    // Case 2: the POOL copy is mutated after admission. The mutation is in the
    // signature field, which `compute_tx_hash` does NOT cover, so the lookup
    // still hits the envelope — and the byte comparison catches it.
    let mut mp2 = Mempool::new(16, 16);
    let h2 = mp2.add(tx.clone()).unwrap();
    let mut mutated = tx.clone();
    mutated.signature[0] ^= 0xFF;
    assert_eq!(
        mutated.compute_tx_hash(),
        h2,
        "a signature-only mutation must not change the lookup key"
    );
    assert_eq!(
        mp2.mev.verify_pool_tx(&mutated),
        SealVerdict::Mismatch,
        "a pooled copy mutated after admission must be refused"
    );
    // The pristine copy still matches: only the mutated one is refused.
    assert_eq!(mp2.mev.verify_pool_tx(&tx), SealVerdict::Match);
}

#[tokio::test]
async fn build_order_commitment_matches_and_tampering_fails() {
    let mut engine = MevPreemptionEngine::new();
    let key = SigningKey::generate(&mut OsRng);
    let sk = SigningKey::generate(&mut OsRng);
    let tx1 = Transaction::sign(&sk, [1u8; 32], 100, 0, 0, 1, 1);
    let tx2 = Transaction::sign(&sk, [2u8; 32], 100, 0, 1, 1, 1);
    let bh = [0xD0u8; 32];

    // No commitment yet: nothing to enforce (a node that did not build this
    // block must not be gated on someone else's order).
    assert_eq!(
        engine.verify_block_order(5, bh, &[tx1.clone(), tx2.clone()]),
        OrderVerdict::NoCommit
    );

    engine.commit_block_order(
        5,
        bh,
        &[tx1.clone(), tx2.clone()],
        std::slice::from_ref(&key),
    );
    assert_eq!(
        engine.verify_block_order(5, bh, &[tx1.clone(), tx2.clone()]),
        OrderVerdict::Match
    );
    // Reordered execution of the same transactions is a different order and
    // must be refused.
    assert_eq!(
        engine.verify_block_order(5, bh, &[tx2.clone(), tx1.clone()]),
        OrderVerdict::Mismatch
    );
    // A subset / different set is likewise not the committed order.
    assert_eq!(
        engine.verify_block_order(5, bh, std::slice::from_ref(&tx1)),
        OrderVerdict::Mismatch
    );
    // Another height, or another block hash at this height, has no
    // commitment: consensus decides those, the local gate does not.
    assert_eq!(
        engine.verify_block_order(6, bh, &[tx1.clone(), tx2.clone()]),
        OrderVerdict::NoCommit
    );
    assert_eq!(
        engine.verify_block_order(5, [0xEE; 32], &[tx1.clone(), tx2.clone()]),
        OrderVerdict::NoCommit
    );

    // A second build at the same height (fresh round) keeps BOTH commitments:
    // whichever body the network decides must find its own.
    let bh2 = [0xD1u8; 32];
    engine.commit_block_order(
        5,
        bh2,
        std::slice::from_ref(&tx1),
        std::slice::from_ref(&key),
    );
    assert_eq!(
        engine.verify_block_order(5, bh, &[tx1.clone(), tx2.clone()]),
        OrderVerdict::Match
    );
    assert_eq!(
        engine.verify_block_order(5, bh2, std::slice::from_ref(&tx1)),
        OrderVerdict::Match
    );
    assert_eq!(
        engine.verify_block_order(5, bh2, &[tx1.clone(), tx2.clone()]),
        OrderVerdict::Mismatch,
        "the other build's order must not pass under this block hash"
    );

    // Tamper the COMMITMENT's signature: the root still matches, but the
    // commitment no longer carries a valid distinct-signer signature.
    {
        let c = engine.order_commits.get_mut(&(5, bh)).unwrap();
        c.validator_shares[0].1[0] ^= 0xFF;
    }
    assert_eq!(
        engine.verify_block_order(5, bh, &[tx1.clone(), tx2.clone()]),
        OrderVerdict::BadCommitment,
        "a commitment whose signature was tampered with must not verify"
    );
    // Restore the signature, then tamper the committed root itself: the
    // block's recomputed root no longer matches the commitment.
    {
        let c = engine.order_commits.get_mut(&(5, bh)).unwrap();
        c.validator_shares[0].1[0] ^= 0xFF;
        c.merkle_root = [0x5Au8; 32];
    }
    assert_eq!(
        engine.verify_block_order(5, bh, &[tx1.clone(), tx2.clone()]),
        OrderVerdict::Mismatch,
        "a commitment whose root was tampered with must not match"
    );
}

#[tokio::test]
async fn finalize_warns_but_converges_on_tampered_build_commitment() {
    // Policy change (audit 2026-10-06): a build-order mismatch is logged LOUD
    // but no longer refuses finalization — execution is deterministic from the
    // voted body, so every node reaches the same root either way, while the
    // old refusal stalled ONLY the builder at H as everyone else moved on.
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();
    let mut cluster = cluster_of_two(from).await;
    cluster
        .broadcast_tx(Transaction::sign(&user, [9u8; 32], 500, 0, 0, 1, 1))
        .await;

    let proposer_idx = cluster
        .nodes
        .iter()
        .position(|n| n.is_proposer())
        .expect("proposer");
    let root_before = cluster.nodes[proposer_idx].state_root().await;

    run_height_tampered(&mut cluster, 1_000, Tamper::BreakCommitmentSignature).await;

    let proposer = &cluster.nodes[proposer_idx];
    assert_eq!(
        proposer.finalized.len(),
        1,
        "the proposer finalizes despite the tampered commitment (warn-only gate)"
    );
    assert_ne!(
        proposer.state_root().await,
        root_before,
        "the voted body is applied deterministically"
    );
    // Both validators converge on the same root — no split.
    for n in cluster.nodes.iter() {
        assert_eq!(n.finalized.len(), 1, "honest nodes still finalize");
        assert_eq!(
            n.state_root().await,
            proposer.state_root().await,
            "roots converge"
        );
    }
}

#[tokio::test]
async fn finalize_refuses_a_reordered_block_body() {
    // Unchanged refusal (audit 2026-10-06): here the STORED body itself no
    // longer hashes to the decided hash — executing it would finalize a
    // different state than the quorum (a split), unlike a mere commitment
    // mismatch where the body is byte-identical everywhere. Refuse.
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();
    let mut cluster = cluster_of_two(from).await;
    cluster
        .broadcast_tx(Transaction::sign(&user, [9u8; 32], 100, 0, 0, 1, 1))
        .await;
    cluster
        .broadcast_tx(Transaction::sign(&user, [8u8; 32], 100, 0, 1, 1, 1))
        .await;

    let proposer_idx = cluster
        .nodes
        .iter()
        .position(|n| n.is_proposer())
        .expect("proposer");
    let root_before = cluster.nodes[proposer_idx].state_root().await;

    run_height_tampered(&mut cluster, 1_000, Tamper::ReorderStoredBody).await;

    let proposer = &cluster.nodes[proposer_idx];
    assert!(
        proposer.finalized.is_empty(),
        "the proposer must refuse to execute a body that no longer matches the decided hash"
    );
    assert_eq!(
        proposer.state_root().await,
        root_before,
        "nothing may have been applied"
    );
}

#[tokio::test]
async fn persisted_pool_roundtrip_reseals_on_restore() {
    let sk = SigningKey::generate(&mut OsRng);
    let from = sk.verifying_key().to_bytes();
    let tx = Transaction::sign(&sk, [9u8; 32], 100, 10, 0, 1, 1);

    let mut mp = Mempool::new(16, 16);
    mp.add(tx.clone()).unwrap();
    let path = std::env::temp_dir().join(format!(
        "stell_mev_mempool_{}_{}.bin",
        std::process::id(),
        1
    ));
    mp.save(&path);
    assert!(path.exists(), "pool with pending txs must persist");

    // Restore into a FRESH pool (as a node restart does): `load_into`
    // re-runs admission, which re-seals under the new engine instance.
    let st = InMemoryStateEngine::new();
    st.update_account(AccountState::new(from, 10_000_000)).await;
    let mut mp2 = Mempool::new(16, 16);
    let kept = mp2
        .load_into(&path, &st, stellereum::mempool::AdmissionCtx::wall_now())
        .await;
    assert_eq!(kept, 1, "the persisted transaction must be restored");
    let restored = mp2.all();
    assert_eq!(restored.len(), 1);
    assert_eq!(
        mp2.mev.verify_pool_tx(&restored[0]),
        SealVerdict::Match,
        "a restored transaction must re-seal and match"
    );
    let selected = mp2.select(1);
    assert_eq!(
        bincode::serialize(&selected[0]).unwrap(),
        bincode::serialize(&tx).unwrap(),
        "the restored pool selects byte-identical transactions"
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn cluster_finalizes_normally_with_sealing_and_commitments_active() {
    // The gates above must never fire on the honest path: this is the control.
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();
    let keys: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let nodes: Vec<_> = keys.iter().map(|k| (k.clone(), engine_with())).collect();
    let mut cluster = Cluster::new(nodes);
    for n in cluster.nodes.iter_mut() {
        seed(&n.state, from).await;
    }
    for h in 0..3u64 {
        cluster
            .broadcast_tx(Transaction::sign(&user, [9u8; 32], 1_000, 0, h, 1, 1))
            .await;
        cluster.run_height(1_000 + h).await;
        for n in &cluster.nodes {
            assert_eq!(n.finalized.last().unwrap().0, h + 1, "every node finalizes");
            assert_eq!(n.applied_txs, h + 1, "every transaction executed");
        }
    }
    let mut roots = Vec::new();
    for n in &cluster.nodes {
        roots.push(n.state_root().await);
    }
    assert!(roots.windows(2).all(|w| w[0] == w[1]), "nodes converged");
    // Sealing happened on every node for every admitted transaction, and
    // pruning dropped the envelopes together with their transactions.
    for n in &cluster.nodes {
        let pool = n.mempool.read().await;
        assert_eq!(
            pool.len(),
            pool.mev.pool_envelopes.len(),
            "every pooled tx has exactly one envelope"
        );
    }
}
