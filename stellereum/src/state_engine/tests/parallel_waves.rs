use super::*;
use crate::post_quantum::{derive_pq_address, PqScheme};
use crate::sharding::Transaction;

/// W5.3 (concurrent waves): the same wave, applied 20 times, must
/// reproduce the SAME state root bit for bit.
///
/// The fixture is 16 DISJOINT plain transfers, so the scheduler puts all
/// of them into a single wave and the wave is executed CONCURRENTLY
/// (planned on the rayon pool, merged conflict-free). If the concurrent
/// path were order-dependent, one of these 20 runs would drift.
#[tokio::test]
async fn test_parallel_wave_execution_is_deterministic() {
    // At least `PARALLEL_WAVE_MIN_TX` senders, so the wave really takes
    // the CONCURRENT path.
    const SENDERS: usize = 48;

    // FULL-PQ: senders are Falcon-512 seeds (distinct per sender);
    // recipients are deterministic addresses (they never sign).
    let seeds: Vec<u8> = (0..SENDERS).map(|i| (0x20 + i) as u8).collect();
    let recipients: Vec<[u8; 32]> = (0..SENDERS)
        .map(|i| {
            let mut b = [0xEu8; 32];
            b[0..8]
                .copy_from_slice(&(0x9E00_0000_0000_0000u64.wrapping_add(i as u64)).to_be_bytes());
            b
        })
        .collect();

    let txs: Vec<Transaction> = seeds
        .iter()
        .zip(recipients.iter())
        .enumerate()
        .map(|(i, (s, to))| pq_tx(*s, *to, 100 + i as u64, 10, 0).0)
        .collect();

    // The fixture must really be ONE wave, otherwise the concurrent path
    // would not be exercised at all.
    let waves = crate::parallel_exec::DisjointScheduler::schedule(&txs);
    assert_eq!(waves.len(), 1, "the fixture must schedule into one wave");
    assert_eq!(waves[0].len(), txs.len());

    let mut roots: Vec<crate::cell::CellHash> = Vec::new();
    for run in 0..20u32 {
        let engine = InMemoryStateEngine::new().with_parallel_exec(true);
        for s in &seeds {
            let (addr, _) = pq_pair(*s);
            engine
                .update_account(AccountState::new(addr, 1_000_000))
                .await;
        }
        let res = engine.apply_block_parallel_fees(&txs, 1_700_000_000).await;
        assert_eq!(res.0, txs.len(), "run {run}: every transfer must apply");
        assert_eq!(res.1, 0, "run {run}: no transfer may fail");
        roots.push(engine.get_state_root().await);
    }
    for (run, root) in roots.iter().enumerate() {
        assert_eq!(
            *root, roots[0],
            "run {run} produced a different state root: the wave is not deterministic"
        );
    }
}

/// W5.3 (concurrent waves): the INTRA-WAVE ORDER does not change the
/// final state.
///
/// The same set of disjoint transfers is applied in 20 different block
/// orders (each order is a different wave composition), and every order
/// must produce the identical state root: the wave's final state is the
/// merge of disjoint per-transaction plans, so it cannot depend on the
/// order the plans were computed or applied in.
#[tokio::test]
async fn test_parallel_wave_order_independence() {
    // At least `PARALLEL_WAVE_MIN_TX` senders, so the waves really take
    // the CONCURRENT path.
    const SENDERS: usize = 40;

    // FULL-PQ: senders are Falcon-512 seeds (distinct per sender).
    let seeds: Vec<u8> = (0..SENDERS).map(|i| (0x40 + i) as u8).collect();
    let recipients: Vec<[u8; 32]> = (0..SENDERS)
        .map(|i| {
            let mut b = [0xEBu8; 32];
            b[0..8]
                .copy_from_slice(&(0xBE00_0000_0000_0000u64.wrapping_add(i as u64)).to_be_bytes());
            b
        })
        .collect();

    let base: Vec<Transaction> = seeds
        .iter()
        .zip(recipients.iter())
        .enumerate()
        .map(|(i, (s, to))| pq_tx(*s, *to, 7 + i as u64, 10, 0).0)
        .collect();

    let mut roots: Vec<crate::cell::CellHash> = Vec::new();
    for perm in 0..20usize {
        let mut txs = base.clone();
        let n = txs.len();
        txs.rotate_left(perm % n);
        if perm % 2 == 1 {
            txs.reverse();
        }

        let engine = InMemoryStateEngine::new().with_parallel_exec(true);
        for s in &seeds {
            let (addr, _) = pq_pair(*s);
            engine
                .update_account(AccountState::new(addr, 1_000_000))
                .await;
        }
        let res = engine.apply_block_parallel_fees(&txs, 1_700_000_000).await;
        assert_eq!(res.0, txs.len(), "perm {perm}: every transfer must apply");
        assert_eq!(res.1, 0, "perm {perm}: no transfer may fail");
        roots.push(engine.get_state_root().await);
    }
    for (perm, root) in roots.iter().enumerate() {
        assert_eq!(
            *root, roots[0],
            "order {perm} produced a different state root: the wave depends on the intra-wave order"
        );
    }
}

/// W5.3: the concurrent wave path and the sequential path must agree
/// BIT for bit - same statuses, same fees, same state root.
#[tokio::test]
async fn test_concurrent_wave_matches_sequential_path() {
    // At least `PARALLEL_WAVE_MIN_TX` senders per wave, so the waves
    // really take the CONCURRENT path.
    // FULL-PQ: senders are Falcon-512 seeds (distinct per sender).
    let seeds: Vec<u8> = (0..40).map(|i| (0x60 + i) as u8).collect();
    let recipients: Vec<[u8; 32]> = (0..40)
        .map(|i| {
            let mut b = [0xECu8; 32];
            b[0..8]
                .copy_from_slice(&(0xC000_0000_0000_0000u64.wrapping_add(i as u64)).to_be_bytes());
            b
        })
        .collect();

    // Two rounds per sender: the second round conflicts with the first
    // (same sender), so the block schedules into several waves.
    let mut txs: Vec<Transaction> = Vec::new();
    for nonce in 0..2u64 {
        for (i, s) in seeds.iter().enumerate() {
            txs.push(pq_tx(*s, recipients[i], 50 + nonce * 10 + i as u64, 10, nonce).0);
        }
    }
    // A transaction that cannot pay: it must fail on BOTH paths, with
    // the same F-01 failure fee.
    txs.push(pq_tx(0x7F, recipients[0], 1, 10, 0).0);

    let seq = InMemoryStateEngine::new().with_parallel_exec(false);
    let par = InMemoryStateEngine::new().with_parallel_exec(true);
    for engine in [&seq, &par] {
        for s in &seeds {
            let (addr, _) = pq_pair(*s);
            engine
                .update_account(AccountState::new(addr, 1_000_000))
                .await;
        }
    }

    let res_seq = seq.apply_block_parallel_fees(&txs, 1_700_000_000).await;
    let res_par = par.apply_block_parallel_fees(&txs, 1_700_000_000).await;

    assert_eq!(res_seq.0, res_par.0, "applied count");
    assert_eq!(res_seq.1, res_par.1, "failed count");
    assert_eq!(res_seq.2, res_par.2, "fees collected");
    assert_eq!(res_seq.3, res_par.3, "status vector");
    assert_eq!(res_seq.4, res_par.4, "fee vector");
    assert_eq!(seq.get_state_root().await, par.get_state_root().await);
}

/// W5.3: the finer wave granularity must not change the OUTCOME.
///
/// Two transactions on DIFFERENT tokens now share a wave (the token
/// registry is keyed by token id, so the two transfers touch disjoint
/// state). The block must still produce exactly the sequential result:
/// same statuses, same fees, same token balances, same state root.
#[tokio::test]
async fn test_distinct_tokens_share_a_wave_and_match_sequential() {
    use crate::token::{TokenMetadata, TokenOp, ZERO_ADDRESS};

    fn meta(name: &str, symbol: &str) -> TokenMetadata {
        TokenMetadata {
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals: 6,
            total_supply: 0,
            max_supply: None,
            minter: ZERO_ADDRESS,
            paused: false,
            description: String::new(),
        }
    }

    // FULL-PQ: token actors are Falcon-512 seeds (recipients are fixed
    // addresses; they never sign).
    let (minter_addr, _minter_pk) = pq_pair(0x80);
    let (a_addr, _a_pk) = pq_pair(0x81);
    let (b_addr, _b_pk) = pq_pair(0x82);
    let recipient_a = [0xEAu8; 32];
    let recipient_b = [0xEEu8; 32];

    let seq = InMemoryStateEngine::new().with_parallel_exec(false);
    let par = InMemoryStateEngine::new().with_parallel_exec(true);
    for engine in [&seq, &par] {
        for addr in [minter_addr, a_addr, b_addr] {
            engine
                .update_account(AccountState::new(addr, 10_000_000))
                .await;
        }
    }

    // Two DISTINCT tokens.
    let token_1 = seq
        .create_token(minter_addr, meta("Alpha", "ALPHA"), 1_000_000)
        .await
        .unwrap();
    let token_2 = seq
        .create_token(minter_addr, meta("Beta", "BETA"), 1_000_000)
        .await
        .unwrap();
    let _ = par
        .create_token(minter_addr, meta("Alpha", "ALPHA"), 1_000_000)
        .await
        .unwrap();
    let _ = par
        .create_token(minter_addr, meta("Beta", "BETA"), 1_000_000)
        .await
        .unwrap();
    for engine in [&seq, &par] {
        engine
            .token_execute(
                &token_1,
                minter_addr,
                TokenOp::Transfer {
                    to: a_addr,
                    amount: 20_000,
                },
            )
            .await
            .unwrap();
        engine
            .token_execute(
                &token_2,
                minter_addr,
                TokenOp::Transfer {
                    to: b_addr,
                    amount: 30_000,
                },
            )
            .await
            .unwrap();
    }

    // One transfer per token: with the per-resource keys these two
    // transactions are DISJOINT and land in the SAME wave.
    let (tx_a, _, _) = pq_tx_payload(
        0x81,
        recipient_a,
        0,
        500_000,
        0,
        vec![crate::svm::OpCode::SysCallTokenTransfer {
            token_id: token_1,
            to: recipient_a,
            amount: 5_000,
        }],
    );
    let (tx_b, _, _) = pq_tx_payload(
        0x82,
        recipient_b,
        0,
        500_000,
        0,
        vec![crate::svm::OpCode::SysCallTokenTransfer {
            token_id: token_2,
            to: recipient_b,
            amount: 4_000,
        }],
    );
    let txs = vec![tx_a, tx_b];

    let waves = crate::parallel_exec::DisjointScheduler::schedule(&txs);
    assert_eq!(waves.len(), 1, "two different tokens must share one wave");
    assert_eq!(waves[0], vec![0, 1]);

    let res_seq = seq.apply_block_parallel_fees(&txs, 1_700_000_000).await;
    let res_par = par.apply_block_parallel_fees(&txs, 1_700_000_000).await;
    assert_eq!(res_seq.0, 2);
    assert_eq!(res_par.0, 2);
    assert_eq!(res_seq.1, 0);
    assert_eq!(res_par.1, 0);
    assert_eq!(res_seq.3, res_par.3);
    assert_eq!(res_seq.4, res_par.4);
    assert_eq!(seq.get_state_root().await, par.get_state_root().await);

    assert_eq!(seq.token_balance(&token_1, &a_addr).await, 15_000);
    assert_eq!(par.token_balance(&token_1, &a_addr).await, 15_000);
    assert_eq!(seq.token_balance(&token_2, &b_addr).await, 26_000);
    assert_eq!(par.token_balance(&token_2, &b_addr).await, 26_000);
    assert_eq!(par.token_balance(&token_1, &recipient_a).await, 5_000);
    assert_eq!(par.token_balance(&token_2, &recipient_b).await, 4_000);
}

// ==================================================================
// W6.6: the F-01 failure fee contract
// ==================================================================

/// THE failure-fee contract, pinned (audit W6.6, item 1; FEE-01):
/// * an ATTRIBUTABLE failure the sender can pay for: the failure fee is
///   charged and their nonce is consumed - the attempt is not free (the
///   "free failure" DoS). The fee is `max(min(declared limit, intrinsic
///   envelope), consensus floor) + surcharge` (FEE-01: the declared limit is
///   a budget, not a price);
/// * an attributable failure the sender CANNOT pay for: NOTHING moves -
///   no fee, no nonce, no dust burn. A transaction whose fee they cannot
///   cover was never going to run, and charging their remaining balance
///   for it would be a griefing surface, not a safety property;
/// * a REPLAY or a GAP: nothing moves (not attributable);
/// * and the SINGLE-TX path and the BLOCK path agree on all of it.
#[tokio::test]
async fn failure_fee_contract_is_identical_on_both_paths() {
    // FULL-PQ: implicit Falcon-512 (no surcharge, so the fee assertions
    // match the old classical fixtures exactly).
    const FLOOR: u64 = 100_000;
    let fee_seed = 0x21u8;
    let (from, _fee_pk) = pq_pair(fee_seed);

    // 1. An AFFORDABLE failure: the fee is charged, the nonce advances.
    {
        let engine = InMemoryStateEngine::new();
        engine
            .update_account(AccountState::new(from, 1_000_000))
            .await;
        // A payload that reverts (the token does not exist).
        let (tx, _, _) = pq_tx_payload(
            fee_seed,
            [0x44; 32],
            0,
            200_000,
            0,
            vec![crate::svm::OpCode::SysCallTokenTransfer {
                token_id: [0xAB; 32],
                to: [0x44; 32],
                amount: 1,
            }],
        );
        let (_, failed, _, status, fees) =
            engine.apply_block_parallel_fees(&[tx], 1_700_000_000).await;
        assert_eq!((failed, status), (1, vec![false]));
        // FEE-01: the failure fee is the intrinsic envelope (capped at the
        // 200 000 declaration) — the same 200 000 here, because the
        // declaration is BELOW the intrinsic.
        assert_eq!(fees, vec![200_000], "the intrinsic failure fee is charged");
        let acc = engine.get_account(&from).await.unwrap();
        assert_eq!(acc.balance, 1_000_000 - 200_000);
        assert_eq!(acc.nonce, 1, "the failure consumes the nonce");
    }

    // 2. An UNCOVERABLE failure: nothing moves at all (no dust burn).
    {
        let engine = InMemoryStateEngine::new();
        // Only 1_000 left against a 200_000 declared fee.
        engine.update_account(AccountState::new(from, 1_000)).await;
        let (tx, _, _) = pq_tx_payload(
            fee_seed,
            [0x44; 32],
            0,
            200_000,
            0,
            vec![crate::svm::OpCode::SysCallTokenTransfer {
                token_id: [0xAB; 32],
                to: [0x44; 32],
                amount: 1,
            }],
        );
        let (_, failed, _, status, fees) =
            engine.apply_block_parallel_fees(&[tx], 1_700_000_000).await;
        assert_eq!((failed, status), (1, vec![false]));
        assert_eq!(fees, vec![0], "an uncoverable failure pays nothing");
        let acc = engine.get_account(&from).await.unwrap();
        assert_eq!(acc.balance, 1_000, "the dust is NOT burned");
        assert_eq!(acc.nonce, 0, "no pay, no advance");
    }

    // 3. A REPLAY (a stale nonce) moves nothing.
    {
        let engine = InMemoryStateEngine::new();
        engine
            .update_account(AccountState::new(from, 1_000_000))
            .await;
        let (tx, _, _) = pq_tx_payload(
            fee_seed,
            [0x44; 32],
            0,
            200_000,
            0,
            vec![crate::svm::OpCode::SysCallTokenTransfer {
                token_id: [0xAB; 32],
                to: [0x44; 32],
                amount: 1,
            }],
        );
        // Advance the nonce out of band, then replay the old transaction.
        engine
            .update_account(AccountState {
                address: from,
                balance: 1_000_000,
                nonce: 7,
                ..AccountState::new(from, 0)
            })
            .await;
        let (_, failed, _, status, fees) =
            engine.apply_block_parallel_fees(&[tx], 1_700_000_000).await;
        assert_eq!((failed, status), (1, vec![false]));
        assert_eq!(fees, vec![0], "a replay pays nothing");
        let acc = engine.get_account(&from).await.unwrap();
        assert_eq!(acc.balance, 1_000_000, "a replay moves nothing");
        assert_eq!(acc.nonce, 7, "a replay does not advance the nonce");
    }

    // 4. The SINGLE-TX path and the BLOCK path agree on a failing
    //    transaction (the equivalence the project pins in
    //    `tests/live_block_path_tests.rs`).
    {
        let (tx, _, _) = pq_tx_payload(
            fee_seed,
            [0x44; 32],
            0,
            200_000,
            0,
            vec![crate::svm::OpCode::SysCallTokenTransfer {
                token_id: [0xAB; 32],
                to: [0x44; 32],
                amount: 1,
            }],
        );
        let single = InMemoryStateEngine::new();
        let block = InMemoryStateEngine::new();
        single
            .update_account(AccountState::new(from, 1_000_000))
            .await;
        block
            .update_account(AccountState::new(from, 1_000_000))
            .await;

        assert!(
            single.apply_transaction(&tx, 1_700_000_000).await.is_err(),
            "the single-tx path must refuse it too"
        );
        let _ = block.apply_block_parallel_fees(&[tx], 1_700_000_000).await;

        let a = single.get_account(&from).await.unwrap();
        let b = block.get_account(&from).await.unwrap();
        assert_eq!(
            (a.balance, a.nonce),
            (b.balance, b.nonce),
            "both paths must leave the same sender state"
        );
        assert_eq!(
            single.get_state_root().await,
            block.get_state_root().await,
            "both paths must commit identical state"
        );
    }
    let _ = FLOOR;
}

// ==================================================================
// W6.6: the D2 consensus penalty must travel with the state
// ==================================================================

/// The D2 penalty enters the CONSENSUS fee floor, so it is
/// consensus-critical state: it MUST be part of the snapshot. A node that
/// restored only the accounts would hold an EMPTY penalty map while a node
/// that applied the blocks holds the real one - and the two would then
/// charge DIFFERENT fees for the same transaction, i.e. end up with
/// DIFFERENT state roots (a consensus split triggered by nothing more
/// exotic than a restart or a snapshot sync).
#[tokio::test]
async fn snapshot_carries_the_d2_penalty_so_a_restored_node_agrees() {
    // FULL-PQ: implicit Falcon-512 (no surcharge).
    let engine = InMemoryStateEngine::new();
    let penalty_seed = 0x91u8;
    let (alice_addr, _alice_pk) = pq_pair(penalty_seed);
    engine
        .update_account(AccountState::new(alice_addr, 10_000_000))
        .await;

    // A transaction that fails at execution records the failure (the D2
    // mirror), which is what raises the sender's floor.
    let (fail, _, _) = pq_tx_payload(
        penalty_seed,
        [0x77; 32],
        0,
        50_000,
        0,
        vec![crate::svm::OpCode::Transfer {
            recipient: [0xCC; 32],
            amount: 1,
        }],
    );
    let (_, failed, _, status, fees) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&fail), 1_700_000_000)
        .await;
    assert_eq!(failed, 1, "the transaction must fail");
    assert_eq!(status, vec![false]);
    assert_eq!(fees, vec![50_000], "a failure still pays its fee");

    // The floor of the penalized sender is now the penalty.
    let (floor_before, _) = engine.consensus_floor_parts(&fail).await;
    assert!(
        floor_before >= crate::mempool::FAILED_SENDER_PENALTY,
        "the failure must have raised the consensus floor (floor={floor_before})"
    );

    // Snapshot, restore into a fresh engine: the penalty MUST come with it.
    let snap = engine.create_snapshot().await;
    let restored = InMemoryStateEngine::new();
    restored.restore_snapshot(&snap).await.expect("restore");
    let (floor_after, _) = restored.consensus_floor_parts(&fail).await;
    assert_eq!(
        floor_after, floor_before,
        "a restored node must charge the SAME floor as a node that applied the blocks"
    );

    // ...and therefore the SAME fee for the same transaction.
    let restored_alice = restored.get_account(&alice_addr).await.unwrap();
    let live_alice = engine.get_account(&alice_addr).await.unwrap();
    assert_eq!(restored_alice.balance, live_alice.balance);
    assert_eq!(restored_alice.nonce, live_alice.nonce);
    assert_eq!(
        restored.get_state_root().await,
        engine.get_state_root().await,
        "a restored node must have the same state root"
    );

    // The chunked snapshot carries it too.
    let chunks = engine.create_snapshot_chunked(Some(2)).await;
    let chunked = InMemoryStateEngine::new();
    chunked
        .restore_snapshot_chunked(&chunks)
        .await
        .expect("chunked restore");
    let (chunk_floor, _) = chunked.consensus_floor_parts(&fail).await;
    assert_eq!(
        chunk_floor, floor_before,
        "the chunked snapshot must carry the penalty as well"
    );
}

/// The LEGACY snapshot shape (a bare `Vec<AccountState>`, written before
/// the penalty existed) must still decode - with an empty penalty.
#[tokio::test]
async fn legacy_account_snapshot_still_decodes() {
    use ed25519_dalek::SigningKey;
    let engine = InMemoryStateEngine::new();
    let alice = SigningKey::from_bytes(&[6u8; 32]);
    let addr = alice.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(addr, 1_000_000))
        .await;
    // The legacy shape: the bare account vector.
    let legacy = bincode::serialize(&vec![AccountState::new(addr, 1_000_000)]).unwrap();
    let restored = InMemoryStateEngine::new();
    restored
        .restore_snapshot(&legacy)
        .await
        .expect("a legacy snapshot must still restore");
    let acc = restored.get_account(&addr).await.expect("account restored");
    assert_eq!(acc.balance, 1_000_000);
}

// ==================================================================
// W6.6: the OPTIMISTIC (CAS) parallel wave path vs the sequential path
// ==================================================================

/// A deterministic xorshift RNG, so a failing property run is
/// reproducible.
struct WaveRng(u64);
impl WaveRng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// THE property (audit W6.6, item 7): the optimistic concurrent wave must
/// leave EXACTLY the state the sequential path leaves - same balances,
/// same nonces, same per-transaction verdicts, same fees, same state root.
///
/// The concurrent path plans a wave from a SNAPSHOT and merges it under a
/// compare-and-swap check; the sequential path applies the same
/// transactions one at a time against the live map. Any difference in the
/// two is a consensus split waiting to happen (the state root is what the
/// validators agree on).
///
/// The wave must be big enough to actually take the CONCURRENT path
/// (`PARALLEL_WAVE_MIN_TX` = 32 transactions in one wave), which is why
/// this test uses 40+ disjoint senders per round - the pre-existing
/// equivalence tests only ever produced waves of 10, i.e. they never
/// exercised the optimistic path at all.
#[tokio::test]
async fn parallel_wave_matches_sequential_for_randomized_blocks() {
    for round in 0..8u64 {
        let mut rng = WaveRng(0x9E37_79B9_7F4A_7C15 ^ round.wrapping_mul(0x1234_5678));
        // 40 senders -> one wave of 40 disjoint plain transfers, above the
        // concurrent threshold.
        // FULL-PQ: senders are Falcon-512 seeds (distinct per index within
        // the round); recipients stay rng-derived addresses (never sign).
        let n_senders = 40usize + (rng.below(10) as usize);
        let seeds: Vec<u8> = (0..n_senders)
            .map(|i| ((round as usize * 64 + i) % 256) as u8)
            .collect();
        let recipients: Vec<[u8; 32]> = (0..n_senders)
            .map(|_| {
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&rng.next().to_le_bytes());
                b
            })
            .collect();

        let seq = InMemoryStateEngine::new();
        let par = InMemoryStateEngine::new();
        seq.set_parallel_exec(false);
        par.set_parallel_exec(true);

        const BAL: u64 = 10_000_000;
        for s in &seeds {
            let (addr, _) = pq_pair(*s);
            seq.update_account(AccountState::new(addr, BAL)).await;
            par.update_account(AccountState::new(addr, BAL)).await;
        }

        // Random plain transfers. Every sender sends ONE transaction in
        // this round, so all of them are mutually disjoint and land in a
        // single wave; a few of them are SELF transfers and a few are
        // deliberately unaffordable (they must fail identically on both
        // paths - and pay the same failure fee).
        let mut txs = Vec::with_capacity(n_senders);
        for (i, s) in seeds.iter().enumerate() {
            let (self_addr, _) = pq_pair(*s);
            let amount = 1 + rng.below(1_000);
            let to = match rng.below(10) {
                0 => self_addr,
                _ => recipients[i],
            };
            let gas = 10 + rng.below(100);
            txs.push(pq_tx(*s, to, amount, gas, 0).0);
        }
        // One transaction that cannot be afforded: it must fail on both
        // paths, pay the SAME failure fee and consume the SAME nonce.
        txs.push(pq_tx(seeds[0], recipients[0], u64::MAX / 2, 10, 1).0);

        // The concurrent path is only taken for a wave of at least
        // `PARALLEL_WAVE_MIN_TX` plain transactions - assert the shape
        // first, so this test can never silently degrade into "the
        // sequential fallback was compared with itself".
        let waves = crate::parallel_exec::DisjointScheduler::schedule(&txs);
        assert!(
            waves.iter().any(|w| w.len() >= 32),
            "the test must produce a wave big enough for the CONCURRENT path (waves: {:?})",
            waves.iter().map(|w| w.len()).collect::<Vec<_>>()
        );

        let res_seq = seq.apply_block_parallel_fees(&txs, 1_700_000_000).await;
        let res_par = par.apply_block_parallel_fees(&txs, 1_700_000_000).await;

        assert_eq!(
            res_seq.0, res_par.0,
            "applied count differs (round {round})"
        );
        assert_eq!(res_seq.1, res_par.1, "failed count differs (round {round})");
        assert_eq!(
            res_seq.2, res_par.2,
            "fees collected differ (round {round})"
        );
        assert_eq!(
            res_seq.3, res_par.3,
            "per-transaction status differs (round {round})"
        );
        assert_eq!(
            res_seq.4, res_par.4,
            "per-transaction fee differs (round {round})"
        );

        // Every account must end in exactly the same state.
        for s in &seeds {
            let (addr, _) = pq_pair(*s);
            let a = seq.get_account(&addr).await;
            let b = par.get_account(&addr).await;
            assert_eq!(
                a.as_ref().map(|x| (x.balance, x.nonce)),
                b.as_ref().map(|x| (x.balance, x.nonce)),
                "account {addr:02x?} differs (round {round})"
            );
        }
        for r in &recipients {
            let a = seq.get_account(r).await;
            let b = par.get_account(r).await;
            assert_eq!(
                a.as_ref().map(|x| (x.balance, x.nonce)),
                b.as_ref().map(|x| (x.balance, x.nonce)),
                "recipient differs (round {round})"
            );
        }
        assert_eq!(
            seq.get_state_root().await,
            par.get_state_root().await,
            "the state root differs between the sequential and the parallel path (round {round})"
        );
    }
}

/// Two CONFLICTING transactions must never land in the same wave, and the
/// scheduler must preserve their relative order (the sequential result
/// depends on it).
#[test]
fn scheduler_never_places_conflicting_transactions_in_one_wave() {
    use ed25519_dalek::SigningKey;
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let other = SigningKey::from_bytes(&[9u8; 32]);
    let me = sk.verifying_key().to_bytes();
    let him = other.verifying_key().to_bytes();

    let txs = vec![
        Transaction::sign(&sk, him, 10, 10, 0, 1, 1),
        Transaction::sign(&other, me, 10, 10, 0, 1, 1),
        Transaction::sign(&sk, him, 10, 10, 1, 1, 1),
        Transaction::sign(&other, me, 10, 10, 1, 1, 1),
    ];
    let waves = crate::parallel_exec::DisjointScheduler::schedule(&txs);
    for (i, wave) in waves.iter().enumerate() {
        for &a in wave {
            for &b in wave {
                if a == b {
                    continue;
                }
                let ka = crate::parallel_exec::extract_access_keys(&txs[a]);
                let kb = crate::parallel_exec::extract_access_keys(&txs[b]);
                assert!(
                    ka.iter().all(|x| !kb.contains(x)),
                    "transactions {a} and {b} share a resource key but share wave {i}"
                );
            }
        }
    }
    // The relative order of every conflicting pair must be preserved.
    let wave_of = |idx: usize| {
        waves
            .iter()
            .position(|w| w.contains(&idx))
            .expect("every tx is in a wave")
    };
    assert!(wave_of(0) < wave_of(2), "same-sender order must be kept");
    assert!(wave_of(1) < wave_of(3), "the shared recipient orders them");
    assert!(wave_of(0) < wave_of(1), "the shared recipient orders them");
}

/// Fork-288000 regression helpers: build a REAL Falcon-512-signed explicit
/// PQ self-transfer (the live trigger shape: dust amount, canonical
/// sharding envelope with DEFAULT_SALT, as `Faucet::build_transfer`
/// emits) from a deterministic test keypair.
fn fork288000_signed_self_transfer(
    seed: u8,
    amount: u64,
    gas_limit: u64,
    nonce: u64,
) -> (Transaction, [u8; 32], Vec<u8>) {
    let scheme = PqScheme::Falcon512;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = crate::post_quantum::DEFAULT_SALT;
    let from = derive_pq_address(scheme, &pk, &salt);
    let mut tx = Transaction {
        from,
        to: from,
        amount,
        gas_limit,
        nonce,
        source_shard: 0,
        target_shard: 0,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature =
        crate::sharding::PqSignatureEnvelope::new_explicit(scheme, pk.clone(), sig).encode();
    assert!(tx.is_pq_activation());
    assert!(tx.verify_signature());
    (tx, from, pk)
}

/// FORK-288000 (a) PARITY: two engines with byte-identical committed
/// pre-state (long-registered Falcon512 faucet-style account) apply the
/// same explicit-PQ self-transfer block and MUST reach identical
/// verdicts, fees, balances, nonces and state roots. If this holds, a
/// same-block/different-verdict fork cannot come from the execution
/// function itself — only from inputs that differ between the nodes.
#[tokio::test]
async fn fork288000_explicit_pq_self_transfer_parity() {
    let (tx, from, pk) = fork288000_signed_self_transfer(0x11, 1_000, 350_000, 0);
    let fund = 995_999_999_000_000u64;

    let mut results = Vec::new();
    for _ in 0..2 {
        let engine = InMemoryStateEngine::new();
        engine.credit_native(&from, fund).await.unwrap();
        engine
            .pin_pubkey(
                from,
                PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            )
            .await
            .unwrap();
        let pre_root = engine.get_state_root().await;
        let (applied, failed, _fees_collected, status, fees) = engine
            .apply_block_parallel_fees(std::slice::from_ref(&tx), 1_700_000_000)
            .await;
        let acc = engine.get_account(&from).await.unwrap();
        let root = engine.get_state_root().await;
        results.push((
            applied,
            failed,
            status,
            fees,
            acc.balance,
            acc.nonce,
            pre_root,
            root,
        ));
    }

    assert_eq!(results[0].7, results[1].7, "pre-state roots must match");
    let (applied, failed, status, fees, balance, nonce, _pre, root) = &results[0];
    assert_eq!((*applied, *failed), (1, 0));
    assert_eq!(status.as_slice(), &[true]);
    // Fee shape of the live C-side receipt, FEE-01: the BILLED gas —
    // `min(gas_limit, measured + intrinsic)` = the 280 000 intrinsic
    // envelope for an empty-payload transfer, not the declared 350 000 —
    // plus the additive PQ surcharge.
    assert_eq!(
        fees.as_slice(),
        &[crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS]
    );
    assert_eq!(*nonce, 1);
    // Self-transfer: the dust amount returns to the sender, so only the
    // fee (billed gas + PQ surcharge) leaves the account.
    assert_eq!(
        *balance,
        fund - crate::svm::GAS_BASIC_TRANSFER - crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
    );
    assert_eq!(
        results[0], results[1],
        "identical pre-state must give identical verdicts"
    );
    let _ = root;
}

/// FORK-288000 (b) REPLAY SHAPE: re-applying a consumed nonce is an
/// admission refusal — `(failed, fee 0)` with state UNTOUCHED. This is
/// the only receipt shape a rich existing sender with a valid signature
/// can produce without moving funds.
#[tokio::test]
async fn fork288000_replay_nonce_refused_zero_fee_untouched() {
    let (tx, from, pk) = fork288000_signed_self_transfer(0x22, 1_000, 350_000, 0);
    let fund = 10_000_000_000u64;
    let engine = InMemoryStateEngine::new();
    engine.credit_native(&from, fund).await.unwrap();
    engine
        .pin_pubkey(
            from,
            PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        )
        .await
        .unwrap();

    let (applied, failed, _, status, _fees) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&tx), 1_700_000_000)
        .await;
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(status.as_slice(), &[true]);
    let mid = engine.get_account(&from).await.unwrap();

    // Second application of the same bytes = replayed nonce.
    let (applied2, failed2, _, status2, fees2) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&tx), 1_700_000_000)
        .await;
    assert_eq!((applied2, failed2), (0, 1));
    assert_eq!(status2.as_slice(), &[false]);
    assert_eq!(
        fees2.as_slice(),
        &[0],
        "a replay moves nothing and files fee 0"
    );
    let after = engine.get_account(&from).await.unwrap();
    assert_eq!((after.balance, after.nonce), (mid.balance, mid.nonce));
}

/// FORK-288000 (c) CONFLICT SHAPE: a pre-existing conflicting PQ
/// registration fails the tx closed with the floor fee charged and the
/// nonce consumed — `(failed, fee > 0)`, never `(failed, 0)`.
#[tokio::test]
async fn fork288000_conflicting_pin_fails_closed_with_fee() {
    let (tx, from, pk) = fork288000_signed_self_transfer(0x33, 1_000, 350_000, 0);
    let fund = 10_000_000_000u64;
    let engine = InMemoryStateEngine::new();
    engine.credit_native(&from, fund).await.unwrap();
    engine
        .pin_pubkey(
            from,
            PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        )
        .await
        .unwrap();
    // Silently diverged metadata (the fork hypothesis): same address,
    // different registered key hash.
    {
        let mut map = engine.accounts.write().await;
        map.get_mut(&from).unwrap().pubkey_hash = Some([0x99; 32]);
    }

    let (applied, failed, _, status, fees) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&tx), 1_700_000_000)
        .await;
    assert_eq!((applied, failed), (0, 1));
    assert_eq!(status.as_slice(), &[false]);
    // FEE-01: an attributable failure pays the intrinsic envelope (capped at
    // the 350 000 declaration) plus the additive PQ surcharge — never the
    // whole declared limit. It is still a POSITIVE fee, so the failure is
    // not free (the property this test exists for).
    assert_eq!(
        fees.as_slice(),
        &[crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS],
        "an attributable post-admission failure still pays the floor"
    );
    let after = engine.get_account(&from).await.unwrap();
    assert_eq!(after.nonce, 1);
    assert_eq!(
        after.balance,
        fund - crate::svm::GAS_BASIC_TRANSFER - crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
    );
}

/// FORK-288000 (d) ATOMICITY: `commit_native` must never leave a
/// half-applied transaction behind. The post-commit PQ pin writes to the
/// node-local `pq_keys` sled tree — the only fallible step after the
/// balance/nonce mutation lands. When that write fails, the mutation
/// must be rolled back so a refused commit moves nothing (today it
/// leaks the debit + nonce advance while reporting `Err`, i.e. the
/// `(failed, fee 0)` + mutated-state shape seen live on B).
///
/// The failure is injected by dropping the attached `pq_keys` tree out
/// from under the engine (`Db::drop_tree`): the engine's handle then
/// refuses inserts with a loud `CollectionNotFound` error instead of
/// touching disk — the same `Err` shape a failed disk write produces
/// (verified: a matrixed probe asserts `insert` errors post-drop).
#[tokio::test]
async fn fork288000_post_commit_pin_failure_moves_nothing() {
    let dir = std::env::temp_dir().join(format!(
        "stell_fork288000_dropped_pq_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = sled::Config::new().path(&dir).open().unwrap();
    let tree = db.open_tree("pq_keys").unwrap();
    assert!(tree.insert(b"probe", b"probe").is_ok());

    let engine = InMemoryStateEngine::new();
    engine.attach_pq_tree(tree);
    // Inject the write failure now: every later `pq_keys` insert errors.
    assert!(db.drop_tree("pq_keys").is_ok());

    let scheme = PqScheme::Falcon512;
    let seed = 0x44;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = crate::post_quantum::DEFAULT_SALT;
    let from = derive_pq_address(scheme, &pk, &salt);
    let fund = 10_000_000_000u64;
    engine.credit_native(&from, fund).await.unwrap();

    let mut tx = Transaction {
        from,
        to: from,
        amount: 1_000,
        gas_limit: 350_000,
        nonce: 0,
        source_shard: 0,
        target_shard: 0,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature =
        crate::sharding::PqSignatureEnvelope::new_explicit(scheme, pk.clone(), sig).encode();
    assert!(tx.is_pq_activation());

    let pre = engine.get_account(&from).await.unwrap();
    let res = engine
        .commit_native(&tx, tx.gas_limit, &[], &[], &[], 1_700_000_000)
        .await;
    assert!(res.is_err(), "pin write failure must refuse the commit");
    let after = engine.get_account(&from).await.unwrap();
    assert_eq!(
        (after.balance, after.nonce),
        (pre.balance, pre.nonce),
        "a refused commit must not debit or advance the nonce"
    );
    assert_eq!(
        (after.scheme, after.pubkey_hash),
        (pre.scheme, pre.pubkey_hash),
        "a refused commit must not leak PQ pin metadata either"
    );

    drop(engine);
    drop(db);
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-BEFORE (T1): a sponsored plain transfer whose third-party SPONSOR is
/// also the RECIPIENT (`auth.sponsor == tx.to`) used to overwrite the fee
/// debit: the plan pushed `(sponsor, sbal - fail_fee)` and then
/// `(to, sbal + amount)`, and `commit_plain_plan` applies absolute values, so
/// the last write won and minted `fail_fee` out of thin air (the proposer was
/// still credited it). The parallel path now emits ONE final write,
/// `(sbal - fee) + amount`, exactly like the sequential `apply.rs`.
#[tokio::test]
async fn parallel_sponsored_tx_sponsor_equals_recipient_matches_sequential() {
    use crate::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
    use crate::sharding::{SponsorAuthorization, SPONSOR_SIG_TAG};

    const TS: u64 = 1_700_000_000;
    const USER_BAL: u64 = 1_000_000;
    const SPONSOR_BAL: u64 = 1_000_000;

    let user = FalconKeypair::generate_from_seed_bytes(&[0x71u8; 32]);
    let sponsor = FalconKeypair::generate_from_seed_bytes(&[0x72u8; 32]);
    let from = derive_pq_address(PqScheme::Falcon512, &user.public_key, &DEFAULT_SALT);
    // The recipient IS the sponsor's address: the pathological split.
    let to = derive_pq_address(PqScheme::Falcon512, &sponsor.public_key, &DEFAULT_SALT);
    // Implicit user envelope (the key is pre-registered): the tx is a PLAIN
    // transfer, so it takes `plan_plain_tx` (an explicit activation envelope
    // would route through `commit_native` instead).
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &user.public_key, &DEFAULT_SALT)
        .expect("PQ test key must register");

    let amount = 1_000u64;
    let gas = crate::svm::GAS_BASIC_TRANSFER;

    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit: gas,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let mut auth = SponsorAuthorization {
        sponsor: to,
        max_fee_per_tx: 100_000_000,
        valid_until: TS + 1_000_000,
        allowed_targets: vec![to],
        chain_id: crate::zkml::effective_chain_id(),
        sponsor_sig: Vec::new(),
        sponsor_scheme: Some(PqScheme::Falcon512),
        sponsor_pubkey: Some(sponsor.public_key.clone()),
        sponsor_salt: Some(DEFAULT_SALT),
    };
    // The sponsor signs FIRST; the user then signs the action bound to the
    // full grant (including this sponsor signature).
    auth.sponsor_sig = sponsor.sign(&tx.sponsor_message(&auth));
    let suffix = {
        let body = bincode::serialize(&auth).expect("grant serializes");
        let mut out = Vec::with_capacity(body.len() + 7);
        out.extend_from_slice(&body);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(SPONSOR_SIG_TAG);
        out
    };
    // Provisional inner envelope so `signing_message` sees the grant.
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, vec![0u8; 666]).encode();
    tx.signature.extend_from_slice(&suffix);
    let user_msg = tx.signing_message();
    let user_sig = user.sign(&user_msg);
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, user_sig).encode();
    tx.signature.extend_from_slice(&suffix);

    assert_eq!(tx.sponsored_grant().expect("third-party grant").sponsor, to);
    assert!(
        !tx.is_pq_activation(),
        "fixture must take the plain planner"
    );

    let seq = InMemoryStateEngine::new();
    let par = InMemoryStateEngine::new().with_parallel_exec(true);
    seq.update_account(AccountState::new(from, USER_BAL)).await;
    seq.update_account(AccountState::new(to, SPONSOR_BAL)).await;
    par.update_account(AccountState::new(from, USER_BAL)).await;
    par.update_account(AccountState::new(to, SPONSOR_BAL)).await;

    let txs = [tx];
    let r_seq = seq.apply_block_parallel_fees(&txs, TS).await;
    let r_par = par.apply_block_parallel_fees(&txs, TS).await;
    assert_eq!(r_seq.0, 1, "sequential: sponsored transfer applies");
    assert_eq!(r_par.0, 1, "parallel: sponsored transfer applies");
    assert_eq!(r_seq.1, 0);
    assert_eq!(r_par.1, 0);
    assert_eq!(r_seq.2, r_par.2, "fees_collected must match");
    let fee = r_seq.4[0];
    assert!(fee > 0, "the fee leg must be charged");

    let seq_user = seq.get_account(&from).await.expect("user account");
    let par_user = par.get_account(&from).await.expect("user account");
    let seq_sponsor = seq.get_account(&to).await.expect("sponsor account");
    let par_sponsor = par.get_account(&to).await.expect("sponsor account");

    // Exactly the sequential formula: fee debited FIRST, amount credited after.
    assert_eq!(seq_user.balance, USER_BAL - amount);
    assert_eq!(seq_sponsor.balance, (SPONSOR_BAL - fee) + amount);
    assert_eq!(par_user.balance, seq_user.balance);
    assert_eq!(par_sponsor.balance, seq_sponsor.balance);
    assert_eq!(par_user.nonce, 1);
    assert_eq!(par_sponsor.nonce, seq_sponsor.nonce);
    assert_eq!(
        seq.get_state_root().await,
        par.get_state_root().await,
        "parallel_exec must be bit-identical to the sequential path"
    );
    // Value conservation: no `fail_fee` was minted.
    assert_eq!(
        par_user.balance + par_sponsor.balance + r_par.2,
        USER_BAL + SPONSOR_BAL,
        "the fee must move to fees_collected, not be printed"
    );
}
