//! Wave 13 differential parity tests: Phase 13a (parallel Token, Market,
//! Staking) & Phase 13b (Block-STM `ContractMvMemory` for WASM contracts) vs
//! sequential `parallel_exec=false` execution.
//!
//! Asserts bit-exact `(applied, failed, fees_collected, status, tx_fees, events)`
//! and `seq.get_state_root().await == par.get_state_root().await` across every
//! workload, collision fallback, exhaustion race, STM contention/retry, and
//! randomized mixed block.

use stellereum::contract::{ContractCallContext, ContractError, ContractEvent, ContractRegistry};
use stellereum::orderbook::{
    OrderSide, OrderType, PAIR_STELL_GRAM, PAIR_STELL_TON, PAIR_STELL_USDT,
};
use stellereum::parallel_exec::DisjointScheduler;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, PqSignatureEnvelope, DEFAULT_SALT,
};
use stellereum::sharding::Transaction;
use stellereum::staking::{
    required_bond_floor_nano, DEFAULT_COMMISSION_BPS, MIN_DELEGATION, REWARDS_POOL, STAKING_POOL,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER, MAX_CONTRACT_CALLDATA_BYTES};
use stellereum::token::{TokenMetadata, TokenOp, ZERO_ADDRESS};
use stellereum::tokenomics::TeamVestingSchedule;

const TS: u64 = 1_700_001_000;
const STELL_NANO: u64 = 1_000_000_000;
const BAL: u64 = 100_000 * STELL_NANO;

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0);
        self.next() % n
    }
}

fn det_seed(id: u64) -> [u8; 32] {
    let mut seed = [0xA7u8; 32];
    seed[..8].copy_from_slice(&id.to_le_bytes());
    seed[8..16].copy_from_slice(&0x517C_C1B7_2722_0A95u64.to_le_bytes());
    seed
}

fn det_kp(id: u64) -> (FalconKeypair, [u8; 32]) {
    let kp = FalconKeypair::generate_from_seed_bytes(&det_seed(id));
    let addr = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(addr, PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
        .expect("PQ test key must register");
    (kp, addr)
}

fn addr_of(id: u64) -> [u8; 32] {
    det_kp(id).1
}

fn pq_tx(
    id: u64,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
    payload: Vec<OpCode>,
) -> Transaction {
    let (kp, from) = det_kp(id);
    let mut t = Transaction {
        from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = t.signing_message();
    let sig = kp.sign(&msg);
    t.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    t
}

fn token_meta(name: &str, symbol: &str) -> TokenMetadata {
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

async fn assert_full_parity(
    seq: &InMemoryStateEngine,
    par: &InMemoryStateEngine,
    txs: &[Transaction],
    addrs: &[([u8; 32], &str)],
    case: &str,
) -> (
    usize,
    usize,
    u64,
    Vec<bool>,
    Vec<u64>,
    Vec<Vec<ContractEvent>>,
) {
    let r_seq = seq.apply_block_parallel_fees_with_events(txs, TS).await;
    let r_par = par.apply_block_parallel_fees_with_events(txs, TS).await;
    assert_eq!(r_seq.0, r_par.0, "{case}: applied count");
    assert_eq!(r_seq.1, r_par.1, "{case}: failed count");
    assert_eq!(r_seq.2, r_par.2, "{case}: fees_collected");
    assert_eq!(r_seq.3, r_par.3, "{case}: status vec");
    assert_eq!(r_seq.4, r_par.4, "{case}: tx_fees vec");
    assert_eq!(r_seq.5, r_par.5, "{case}: events vec");
    for &(addr, label) in addrs {
        let a = seq.get_account(&addr).await;
        let b = par.get_account(&addr).await;
        match (a, b) {
            (Some(sa), Some(pa)) => {
                assert_eq!(sa.balance, pa.balance, "{case}: balance {label}");
                assert_eq!(sa.nonce, pa.nonce, "{case}: nonce {label}");
                assert_eq!(sa.inbox, pa.inbox, "{case}: inbox {label}");
            }
            (None, None) => {}
            _ => panic!("{case}: account existence diverged for {label}"),
        }
    }
    let seq_root = seq.get_state_root().await;
    let par_root = par.get_state_root().await;
    if seq_root != par_root {
        let s_snap = seq.capture_state_snapshot().await;
        let p_snap = par.capture_state_snapshot().await;
        assert_eq!(
            s_snap.accounts.len(),
            p_snap.accounts.len(),
            "{case}: accounts len"
        );
        for (sa, pa) in s_snap.accounts.iter().zip(p_snap.accounts.iter()) {
            assert_eq!(sa.address, pa.address, "{case}: account addr");
            assert_eq!(
                sa.balance, pa.balance,
                "{case}: account bal {:?}",
                sa.address
            );
            assert_eq!(sa.nonce, pa.nonce, "{case}: account nonce {:?}", sa.address);
        }
        assert_eq!(s_snap.penalty, p_snap.penalty, "{case}: penalties");
        assert_eq!(
            seq.tokens_read().await.tokens.len(),
            par.tokens_read().await.tokens.len(),
            "{case}: tokens len"
        );
        for (id, st) in &seq.tokens_read().await.tokens {
            let pt = par.tokens_read().await.tokens.get(id).unwrap().clone();
            assert_eq!(st.balances, pt.balances, "{case}: token balances");
            assert_eq!(st.allowances, pt.allowances, "{case}: token allowances");
        }
        assert_eq!(
            seq.staking_read().await.validators,
            par.staking_read().await.validators,
            "{case}: validators"
        );
        assert_eq!(
            seq.staking_read().await.delegations,
            par.staking_read().await.delegations,
            "{case}: delegations"
        );
        assert_eq!(
            seq.staking_read().await.rewards_pool,
            par.staking_read().await.rewards_pool,
            "{case}: rewards_pool"
        );
        assert_eq!(
            seq.order_escrow_read().await.len(),
            par.order_escrow_read().await.len(),
            "{case}: escrow len"
        );
        assert_eq!(
            seq.orderbooks_read().await.books.len(),
            par.orderbooks_read().await.books.len(),
            "{case}: books len"
        );
        let par_books = par.orderbooks_read().await;
        for (pid, sb) in &seq.orderbooks_read().await.books {
            let pb = par_books.books.get(pid).unwrap();
            assert_eq!(
                sb.next_order_id, pb.next_order_id,
                "{case}: book {pid} next_order_id"
            );
            assert_eq!(sb.bids.len(), pb.bids.len(), "{case}: book {pid} bids len");
            assert_eq!(sb.asks.len(), pb.asks.len(), "{case}: book {pid} asks len");
        }
        let par_contracts = par.contracts_read().await;
        for (caddr, sc) in &seq.contracts_read().await.contracts {
            let pc = par_contracts.contracts.get(caddr).unwrap();
            assert_eq!(sc.storage, pc.storage, "{case}: contract storage");
            assert_eq!(sc.balance, pc.balance, "{case}: contract balance");
        }
        panic!("{case}: all inspected domains matched, so state_trie/commitment itself diverged: seq={seq_root:?} par={par_root:?}");
    }
    assert_eq!(
        seq_root, par_root,
        "{case}: state_root must be bit-identical"
    );
    r_par
}

#[tokio::test]
async fn w13_100_disjoint_token_ops_single_token_parity() {
    let seq = InMemoryStateEngine::new().with_parallel_exec(false);
    let par = InMemoryStateEngine::new().with_parallel_exec(true);

    let minter = addr_of(9000);
    for e in [&seq, &par] {
        e.update_account(AccountState::new(minter, BAL)).await;
    }
    let tid_seq = seq
        .create_token(minter, token_meta("Wave13Token", "W13"), 10_000_000)
        .await
        .unwrap();
    let tid_par = par
        .create_token(minter, token_meta("Wave13Token", "W13"), 10_000_000)
        .await
        .unwrap();
    assert_eq!(tid_seq, tid_par);
    let tid = tid_seq;

    let mut txs = Vec::with_capacity(100);
    let mut watched: Vec<([u8; 32], &str)> = vec![(minter, "minter")];

    // 40 disjoint Transfer ops: some exact zero-drain, some insufficient balance failures.
    for k in 0..40u64 {
        let sender_id = 100 + k * 2;
        let rcpt_id = 101 + k * 2;
        let sender = addr_of(sender_id);
        let rcpt = addr_of(rcpt_id);
        watched.push((sender, "transfer_sender"));
        watched.push((rcpt, "transfer_rcpt"));
        for e in [&seq, &par] {
            e.update_account(AccountState::new(sender, BAL)).await;
            e.token_execute(
                &tid,
                minter,
                TokenOp::Transfer {
                    to: sender,
                    amount: 1_000,
                },
            )
            .await
            .unwrap();
        }
        let amount = if k % 5 == 0 {
            1_000 // exact zero drain -> removes balance map entry
        } else if k % 7 == 0 {
            1_500 // insufficient token balance -> reverts + fail_with_floor!
        } else {
            250 + k
        };
        txs.push(pq_tx(
            sender_id,
            rcpt,
            0,
            500_000,
            0,
            vec![OpCode::SysCallTokenTransfer {
                token_id: tid,
                to: rcpt,
                amount,
            }],
        ));
    }

    // 30 disjoint TransferFrom ops: distinct (owner, spender, recipient) triples.
    for k in 0..30u64 {
        let owner_id = 1_000 + k * 3;
        let spender_id = 1_001 + k * 3;
        let rcpt_id = 1_002 + k * 3;
        let owner = addr_of(owner_id);
        let spender = addr_of(spender_id);
        let rcpt = addr_of(rcpt_id);
        watched.push((owner, "tf_owner"));
        watched.push((spender, "tf_spender"));
        watched.push((rcpt, "tf_rcpt"));
        for e in [&seq, &par] {
            e.update_account(AccountState::new(spender, BAL)).await;
            e.token_execute(
                &tid,
                minter,
                TokenOp::Transfer {
                    to: owner,
                    amount: 800,
                },
            )
            .await
            .unwrap();
            e.token_execute(
                &tid,
                owner,
                TokenOp::Approve {
                    spender,
                    amount: 500,
                },
            )
            .await
            .unwrap();
        }
        let amount = if k % 4 == 0 {
            500 // drains allowance to 0 -> removes allowance entry
        } else if k % 9 == 0 {
            600 // exceeds allowance -> reverts
        } else {
            200 + k
        };
        txs.push(pq_tx(
            spender_id,
            rcpt,
            0,
            500_000,
            0,
            vec![OpCode::SysCallTokenTransferFrom {
                token_id: tid,
                from: owner,
                to: rcpt,
                amount,
            }],
        ));
    }

    // 30 disjoint Approve ops: some non-zero, some 0 (clear allowance).
    for k in 0..30u64 {
        let owner_id = 2_000 + k * 2;
        let spender_id = 2_001 + k * 2;
        let owner = addr_of(owner_id);
        let spender = addr_of(spender_id);
        watched.push((owner, "app_owner"));
        watched.push((spender, "app_spender"));
        for e in [&seq, &par] {
            e.update_account(AccountState::new(owner, BAL)).await;
            if k % 3 == 0 {
                e.token_execute(
                    &tid,
                    owner,
                    TokenOp::Approve {
                        spender,
                        amount: 999,
                    },
                )
                .await
                .unwrap();
            }
        }
        let amount = if k % 3 == 0 { 0 } else { 1_000 + k };
        txs.push(pq_tx(
            owner_id,
            spender,
            0,
            500_000,
            0,
            vec![OpCode::SysCallTokenApprove {
                token_id: tid,
                spender,
                amount,
            }],
        ));
    }

    assert_eq!(txs.len(), 100);
    let waves = DisjointScheduler::schedule_v2(&txs, true, true);
    assert_eq!(
        waves.len(),
        1,
        "100 disjoint token ops on ONE token must schedule into 1 wave"
    );

    let (applied, failed, ..) =
        assert_full_parity(&seq, &par, &txs, &watched, "100_disjoint_token_ops").await;
    assert!(applied > 80 && failed > 5);

    let seq_actor = seq.tokens_read().await.get(&tid).unwrap().clone();
    let par_actor = par.tokens_read().await.get(&tid).unwrap().clone();
    assert_eq!(seq_actor.balances, par_actor.balances);
    assert_eq!(seq_actor.allowances, par_actor.allowances);
    assert_eq!(
        seq_actor.metadata.total_supply,
        par_actor.metadata.total_supply
    );
}

#[tokio::test]
async fn w13_multipair_place_order_and_shared_maker_collision_parity() {
    let seq = InMemoryStateEngine::new().with_parallel_exec(false);
    let par = InMemoryStateEngine::new().with_parallel_exec(true);

    let minter = addr_of(9100);
    let shared_maker_id = 3001u64;
    let shared_maker = addr_of(shared_maker_id);
    let maker_p3 = addr_of(3002);
    let taker_p1_id = 3010u64;
    let taker_p2_id = 3011u64;
    let taker_p3_id = 3012u64;
    let taker_p4_id = 3013u64;
    let wusdt_maker_id = 3020u64;
    let wusdt_maker = addr_of(wusdt_maker_id);
    let wusdt_taker_p1_id = 3021u64;
    let wusdt_taker_p2_id = 3022u64;

    let watched = vec![
        (minter, "minter"),
        (shared_maker, "shared_maker"),
        (maker_p3, "maker_p3"),
        (addr_of(taker_p1_id), "taker_p1"),
        (addr_of(taker_p2_id), "taker_p2"),
        (addr_of(taker_p3_id), "taker_p3"),
        (addr_of(taker_p4_id), "taker_p4"),
        (wusdt_maker, "wusdt_maker"),
        (addr_of(wusdt_taker_p1_id), "wusdt_taker_p1"),
        (addr_of(wusdt_taker_p2_id), "wusdt_taker_p2"),
    ];

    for e in [&seq, &par] {
        for &(a, _) in &watched {
            e.update_account(AccountState::new(a, BAL)).await;
        }
        let usdt = e
            .create_token(minter, token_meta("Wrapped USDT", "wUSDT"), 1_000_000_000)
            .await
            .unwrap();
        e.pmm_init_usdt(usdt, 1_000_000_000).await;
        e.token_execute(
            &usdt,
            minter,
            TokenOp::Transfer {
                to: wusdt_maker,
                amount: 100_000_000,
            },
        )
        .await
        .unwrap();

        // Resting native-SVM sell orders from shared_maker on PAIR 1 and PAIR 2
        // (via apply_transaction so escrow + book match live consensus path).
        let mk1 = pq_tx(
            shared_maker_id,
            shared_maker,
            0,
            500_000,
            0,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_USDT,
                is_buy: false,
                price: 1_000_000,
                amount: 50_000,
            }],
        );
        let mk2 = pq_tx(
            shared_maker_id,
            shared_maker,
            0,
            500_000,
            1,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_TON,
                is_buy: false,
                price: 1_000_000,
                amount: 50_000,
            }],
        );
        let mk3 = pq_tx(
            3002,
            maker_p3,
            0,
            500_000,
            0,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_GRAM,
                is_buy: false,
                price: 1_000_000,
                amount: 40_000,
            }],
        );
        for mk in [&mk1, &mk2, &mk3] {
            e.apply_transaction(mk, TS).await.unwrap();
        }

        // Resting wUSDT-escrowed buy orders on PAIR 1 and PAIR 2 from wusdt_maker
        // to test cross-pair wUSDT release + collision fallback.
        e.place_order_settled(
            PAIR_STELL_USDT,
            wusdt_maker,
            OrderSide::Buy,
            OrderType::Limit,
            1_000_000,
            2 * STELL_NANO,
            TS,
        )
        .await
        .unwrap();
        e.place_order_settled(
            PAIR_STELL_TON,
            wusdt_maker,
            OrderSide::Buy,
            OrderType::Limit,
            1_000_000,
            2 * STELL_NANO,
            TS,
        )
        .await
        .unwrap();
    }

    // One wave across pairs 1, 2, 3, 4:
    // - taker_p1 buys on PAIR 1 (fills shared_maker!)
    // - taker_p2 buys on PAIR 2 (collides on shared_maker -> fallback!)
    // - taker_p3 buys on PAIR 3 (fills maker_p3 + rests remainder)
    // - taker_p4 places resting order on pair 4
    // - wusdt_taker_p1 & wusdt_taker_p2 sell into wusdt_maker's bids across pairs 1 & 2
    //   (wait: same pair 1/2 conflicts with taker_p1/p2 across waves, so put wusdt takers on pairs 10/11 or in wave 2).
    let tx_p1 = pq_tx(
        taker_p1_id,
        addr_of(taker_p1_id),
        0,
        500_000,
        0,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: PAIR_STELL_USDT,
            is_buy: true,
            price: 1_000_000,
            amount: 30_000,
        }],
    );
    let tx_p2 = pq_tx(
        taker_p2_id,
        addr_of(taker_p2_id),
        0,
        500_000,
        0,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: PAIR_STELL_TON,
            is_buy: true,
            price: 1_000_000,
            amount: 25_000,
        }],
    );
    let tx_p3 = pq_tx(
        taker_p3_id,
        addr_of(taker_p3_id),
        0,
        500_000,
        0,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: PAIR_STELL_GRAM,
            is_buy: true,
            price: 1_000_000,
            amount: 60_000, // fills 40_000 and rests 20_000
        }],
    );
    let tx_p4 = pq_tx(
        taker_p4_id,
        addr_of(taker_p4_id),
        0,
        500_000,
        0,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: 4,
            is_buy: false,
            price: 2_000_000,
            amount: 10_000,
        }],
    );
    // Sell into wUSDT-escrowed maker orders on PAIR 1 and PAIR 2 (wave 2).
    let tx_w1 = pq_tx(
        wusdt_taker_p1_id,
        addr_of(wusdt_taker_p1_id),
        0,
        500_000,
        0,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: PAIR_STELL_USDT,
            is_buy: false,
            price: 1_000_000,
            amount: STELL_NANO,
        }],
    );
    let tx_w2 = pq_tx(
        wusdt_taker_p2_id,
        addr_of(wusdt_taker_p2_id),
        0,
        500_000,
        0,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: PAIR_STELL_TON,
            is_buy: false,
            price: 1_000_000,
            amount: STELL_NANO,
        }],
    );

    let txs = vec![tx_p1, tx_p2, tx_p3, tx_p4, tx_w1, tx_w2];
    let waves = DisjointScheduler::schedule_v2(&txs, true, true);
    assert_eq!(waves[0], vec![0, 1, 2, 3]);
    assert_eq!(waves[1], vec![4, 5]);

    let (applied, failed, ..) =
        assert_full_parity(&seq, &par, &txs, &watched, "multipair_clob_and_collision").await;
    assert_eq!(applied, 6);
    assert_eq!(failed, 0);

    assert_eq!(
        *seq.order_escrow_read().await,
        *par.order_escrow_read().await
    );
    for pair in [PAIR_STELL_USDT, PAIR_STELL_TON, PAIR_STELL_GRAM, 4] {
        let sb = seq.orderbooks_read().await.get_book(pair).cloned().unwrap();
        let pb = par.orderbooks_read().await.get_book(pair).cloned().unwrap();
        assert_eq!(sb.next_order_id, pb.next_order_id);
        assert_eq!(sb.get_best_bid_ask(), pb.get_best_bid_ask());
    }
}

#[tokio::test]
async fn w13_multivalidator_staking_and_rewards_pool_race_parity() {
    let seq = InMemoryStateEngine::new().with_parallel_exec(false);
    let par = InMemoryStateEngine::new().with_parallel_exec(true);

    // 4 validators with cold withdrawal addresses (`pq_lifecycle` active at height 0).
    let val_ids: Vec<[u8; 32]> = (1..=4u8).map(|i| [0xB0 + i; 32]).collect();
    let owner_ids: Vec<u64> = (4001..=4004u64).collect();
    let delegator_ids: Vec<u64> = (4011..=4014u64).collect();

    let mut watched: Vec<([u8; 32], &str)> = vec![
        (STAKING_POOL, "staking_pool"),
        (REWARDS_POOL, "rewards_pool"),
    ];
    for &id in owner_ids.iter().chain(delegator_ids.iter()) {
        watched.push((addr_of(id), "staking_actor"));
    }

    // Both engines bond identically, so the pending-reward snapshot from the
    // first engine is reused for the second. `Option` keeps the loop body free
    // of both `unused_assignments` (immutable single assignment) and
    // `cannot assign twice` (mutable re-assignment) complaints.
    let mut pending_snapshot: Option<(u64, u64)> = None;

    for e in [&seq, &par] {
        e.update_account(AccountState::new(STAKING_POOL, 50_000 * STELL_NANO))
            .await;
        for &id in owner_ids.iter().chain(delegator_ids.iter()) {
            e.update_account(AccountState::new(addr_of(id), BAL)).await;
        }
        {
            let mut ledger = e.staking_write().await;
            for (idx, &vid) in val_ids.iter().enumerate() {
                let owner = addr_of(owner_ids[idx]);
                ledger
                    .bond_with_withdrawal(
                        vid,
                        required_bond_floor_nano() + 1_000 * STELL_NANO,
                        DEFAULT_COMMISSION_BPS,
                        owner,
                    )
                    .unwrap();
                ledger
                    .delegate(addr_of(delegator_ids[idx]), vid, 500 * STELL_NANO)
                    .unwrap();
                ledger.distribute_reward(vid, 100 * STELL_NANO).unwrap();
            }
            let v1 = ledger.validators[&val_ids[0]].pending_rewards;
            let v2 = ledger.validators[&val_ids[1]].pending_rewards;
            // Tight rewards_pool: v1 fits, v2 exhausts the pool!
            ledger.rewards_pool = v1 + v2 - 1;
            pending_snapshot.get_or_insert((v1, v2));
        }
        let (v1, v2) = pending_snapshot.expect("ledger block always sets the snapshot");
        e.update_account(AccountState::new(REWARDS_POOL, v1 + v2 - 1))
            .await;
    }

    // Single wave touching 4 distinct validators:
    // - tx 0: owner_0 claims v1 rewards (SUCCEEDS; leaves v2 - 1 in rewards_pool)
    // - tx 1: owner_1 claims v2 rewards (FAILS rewards_pool exhaustion race -> fail_with_floor!)
    // - tx 2: delegator_2 delegates to v3 (SUCCEEDS)
    // - tx 3: delegator_3 begins undelegating from v4 (SUCCEEDS, appends unbonding)
    let txs = vec![
        pq_tx(
            owner_ids[0],
            addr_of(owner_ids[0]),
            0,
            500_000,
            0,
            vec![OpCode::SysCallClaimRewards {
                validator: val_ids[0],
            }],
        ),
        pq_tx(
            owner_ids[1],
            addr_of(owner_ids[1]),
            0,
            500_000,
            0,
            vec![OpCode::SysCallClaimRewards {
                validator: val_ids[1],
            }],
        ),
        pq_tx(
            delegator_ids[2],
            addr_of(delegator_ids[2]),
            0,
            500_000,
            0,
            vec![OpCode::SysCallDelegate {
                validator: val_ids[2],
                amount: 10 * MIN_DELEGATION,
            }],
        ),
        pq_tx(
            delegator_ids[3],
            addr_of(delegator_ids[3]),
            0,
            500_000,
            0,
            vec![OpCode::SysCallBeginUndelegate {
                validator: val_ids[3],
                amount: 50 * STELL_NANO,
            }],
        ),
    ];

    let waves = DisjointScheduler::schedule_v2(&txs, true, true);
    assert_eq!(waves.len(), 1);
    assert_eq!(waves[0], vec![0, 1, 2, 3]);

    let (applied, failed, ..) =
        assert_full_parity(&seq, &par, &txs, &watched, "staking_rewards_race").await;
    assert_eq!(applied, 3);
    assert_eq!(failed, 1);

    let sl = seq.staking_read().await;
    let pl = par.staking_read().await;
    assert_eq!(sl.rewards_pool, pl.rewards_pool);
    assert_eq!(sl.unbonding, pl.unbonding);
    assert_eq!(sl.validators, pl.validators);
    assert_eq!(sl.delegations, pl.delegations);
}

fn stm_test_contract_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "host" "sload" (func $sload (param i64) (result i64)))
          (import "host" "sstore" (func $sstore (param i64 i64)))
          (import "host" "emit" (func $emit (param i64 i64)))
          (import "host" "send_message" (func $send_message (param i64 i64 i64 i64 i64 i64) (result i64)))
          (memory (export "memory") 1)
          (func (export "set_slot") (param $slot i64) (param $val i64) (result i64)
            (call $sstore (local.get $slot) (local.get $val))
            (call $emit (local.get $slot) (local.get $val))
            (call $sload (local.get $slot)))
          (func (export "inc_hot") (param $delta i64) (result i64)
            (local $cur i64)
            (local.set $cur (call $sload (i64.const 0)))
            (local.set $cur (i64.add (local.get $cur) (local.get $delta)))
            (call $sstore (i64.const 0) (local.get $cur))
            (call $emit (i64.const 0) (local.get $cur))
            (local.get $cur))
          (func (export "trap_if_zero") (param $slot i64) (result i64)
            (if (i64.eqz (call $sload (local.get $slot)))
              (then (unreachable)))
            (call $sstore (local.get $slot) (i64.add (call $sload (local.get $slot)) (i64.const 10)))
            (call $emit (local.get $slot) (call $sload (local.get $slot)))
            (call $sload (local.get $slot)))
          (func (export "send_ping") (param $val i64) (result i64)
            (i64.store (i32.const 0) (i64.const 0x1111111111111111))
            (i64.store (i32.const 8) (i64.const 0x2222222222222222))
            (i64.store (i32.const 16) (i64.const 0x3333333333333333))
            (i64.store (i32.const 24) (i64.const 0x4444444444444444))
            (call $emit (i64.const 99) (local.get $val))
            (call $send_message (i64.const 0) (i64.const 32) (local.get $val) (i64.const 64) (i64.const 0) (i64.const 1))))"#,
    )
    .expect("stm test wat must compile")
}

#[tokio::test]
async fn w13_50_contract_calls_stm_disjoint_and_hot_slot_retry_parity() {
    let code = stm_test_contract_wasm();
    let creator = addr_of(9200);

    // Part A: 50 disjoint-slot calls on the SAME contract (pre-initialized slots 100..150).
    {
        let seq = InMemoryStateEngine::new().with_parallel_exec(false);
        let par = InMemoryStateEngine::new().with_parallel_exec(true);
        let mut watched: Vec<([u8; 32], &str)> = vec![(creator, "creator")];

        let mut caddr = [0u8; 32];
        for e in [&seq, &par] {
            e.update_account(AccountState::new(creator, BAL)).await;
            let addr = e.deploy_contract(creator, code.clone(), TS).await.unwrap();
            caddr = addr;
            // Pre-populate slots 100..150 so disjoint writes don't contend on StorageLen.
            for k in 0..50i64 {
                e.call_contract_args(&addr, "set_slot", &[100 + k, 1], 1_000_000)
                    .await
                    .unwrap();
            }
        }

        let mut txs = Vec::with_capacity(50);
        for k in 0..50u64 {
            let sid = 5_000 + k;
            let saddr = addr_of(sid);
            watched.push((saddr, "disjoint_caller"));
            for e in [&seq, &par] {
                e.update_account(AccountState::new(saddr, BAL)).await;
            }
            // `to` is the caller (a self-send): the contract is addressed by
            // the syscall, and a self-send keeps the STM scheduler from
            // serialising every call on the shared contract account.
            txs.push(pq_tx(
                sid,
                saddr,
                0,
                1_000_000,
                0,
                vec![OpCode::SysCallCallContractArgs {
                    contract: caddr,
                    method: b"set_slot".to_vec(),
                    args: vec![100 + k as i64, 1_000 + k as i64],
                    calldata: Vec::new(),
                }],
            ));
        }

        let waves = DisjointScheduler::schedule_v2(&txs, true, true);
        assert_eq!(waves.len(), 1, "STM schedules all 50 into 1 wave");

        let (applied, failed, ..) =
            assert_full_parity(&seq, &par, &txs, &watched, "stm_50_disjoint_slots").await;
        assert_eq!(applied, 50);
        assert_eq!(failed, 0);
        assert_eq!(
            seq.get_contract(&caddr).await.unwrap().storage,
            par.get_contract(&caddr).await.unwrap().storage
        );
    }

    // Part B: 50 hot-slot & conditional-trap & outbound-message calls on the SAME contract.
    {
        let seq = InMemoryStateEngine::new().with_parallel_exec(false);
        let par = InMemoryStateEngine::new().with_parallel_exec(true);
        let mut rcpt = [0u8; 32];
        rcpt[0..8].copy_from_slice(&0x1111111111111111u64.to_le_bytes());
        rcpt[8..16].copy_from_slice(&0x2222222222222222u64.to_le_bytes());
        rcpt[16..24].copy_from_slice(&0x3333333333333333u64.to_le_bytes());
        rcpt[24..32].copy_from_slice(&0x4444444444444444u64.to_le_bytes());

        let mut watched: Vec<([u8; 32], &str)> = vec![(creator, "creator"), (rcpt, "msg_rcpt")];
        let mut caddr = [0u8; 32];
        for e in [&seq, &par] {
            e.update_account(AccountState::new(creator, BAL)).await;
            e.update_account(AccountState::new(rcpt, 0)).await;
            let addr = e.deploy_contract(creator, code.clone(), TS).await.unwrap();
            caddr = addr;
            e.update_account(AccountState::new(addr, 10_000)).await;
        }
        watched.push((caddr, "contract_acct"));

        let mut txs = Vec::with_capacity(50);
        for k in 0..50u64 {
            let sid = 5_200 + k;
            let saddr = addr_of(sid);
            watched.push((saddr, "hot_caller"));
            for e in [&seq, &par] {
                e.update_account(AccountState::new(saddr, BAL)).await;
            }
            let op = if k == 0 {
                // tx 0 writes slot 0 = 5
                OpCode::SysCallCallContract {
                    contract: caddr,
                    method: b"inc_hot".to_vec(),
                    arg: 5,
                }
            } else if k == 1 {
                // tx 1 traps in Round 0 if slot 0 == 0, succeeds on retry after tx 0!
                OpCode::SysCallCallContract {
                    contract: caddr,
                    method: b"trap_if_zero".to_vec(),
                    arg: 0,
                }
            } else if k == 2 || k == 3 {
                OpCode::SysCallCallContractArgs {
                    contract: caddr,
                    method: b"send_ping".to_vec(),
                    args: vec![1_000],
                    calldata: Vec::new(),
                }
            } else if k == 49 {
                // Deliberate OOG failure on contract call
                OpCode::SysCallCallContract {
                    contract: caddr,
                    method: b"inc_hot".to_vec(),
                    arg: 1,
                }
            } else {
                OpCode::SysCallCallContract {
                    contract: caddr,
                    method: b"inc_hot".to_vec(),
                    arg: 1,
                }
            };
            let gas = if k == 49 { 100 } else { 1_000_000 };
            txs.push(pq_tx(sid, saddr, 0, gas, 0, vec![op]));
        }

        let waves = DisjointScheduler::schedule_v2(&txs, true, true);
        assert_eq!(waves.len(), 1);

        let (applied, failed, ..) =
            assert_full_parity(&seq, &par, &txs, &watched, "stm_50_hot_slot_retry").await;
        assert_eq!(applied, 49);
        assert_eq!(failed, 1);
        assert_eq!(
            seq.get_contract(&caddr).await.unwrap().storage,
            par.get_contract(&caddr).await.unwrap().storage
        );
    }
}

#[tokio::test]
async fn w13_randomized_mixed_block_parity() {
    let wasm = stm_test_contract_wasm();

    for round in 0..4u64 {
        let mut rng = SplitMix64(0xCAFE_BABE_1337_0000 ^ round.wrapping_mul(0x9E37_79B9));
        let seq = InMemoryStateEngine::new().with_parallel_exec(false);
        let par = InMemoryStateEngine::new().with_parallel_exec(true);

        let minter = addr_of(9500);
        let creator = addr_of(9501);
        let shared_maker_id = 9502u64;
        let shared_maker = addr_of(shared_maker_id);
        let validators: Vec<[u8; 32]> = (0..4u8).map(|i| [0xD0 + i; 32]).collect();
        let val_owners: Vec<u64> = (9510..9514u64).collect();

        let mut watched: Vec<([u8; 32], &str)> = vec![
            (minter, "minter"),
            (creator, "creator"),
            (shared_maker, "shared_maker"),
            (STAKING_POOL, "staking_pool"),
            (REWARDS_POOL, "rewards_pool"),
        ];

        for e in [&seq, &par] {
            e.update_account(AccountState::new(minter, BAL)).await;
            e.update_account(AccountState::new(creator, BAL)).await;
            e.update_account(AccountState::new(shared_maker, BAL)).await;
            e.update_account(AccountState::new(STAKING_POOL, 50_000 * STELL_NANO))
                .await;
            for &vo in &val_owners {
                e.update_account(AccountState::new(addr_of(vo), BAL)).await;
            }
        }

        let tid = seq
            .create_token(minter, token_meta("MixTok", "MIX"), 100_000_000)
            .await
            .unwrap();
        let tid_par = par
            .create_token(minter, token_meta("MixTok", "MIX"), 100_000_000)
            .await
            .unwrap();
        assert_eq!(tid, tid_par);

        let caddr_seq = seq
            .deploy_contract(creator, wasm.clone(), TS)
            .await
            .unwrap();
        let caddr_par = par
            .deploy_contract(creator, wasm.clone(), TS)
            .await
            .unwrap();
        assert_eq!(caddr_seq, caddr_par);
        let caddr = caddr_seq;

        for e in [&seq, &par] {
            for k in 0..32i64 {
                e.call_contract_args(&caddr, "set_slot", &[k, 1], 1_000_000)
                    .await
                    .unwrap();
            }
            {
                let mut l = e.staking_write().await;
                for (idx, &v) in validators.iter().enumerate() {
                    l.bond_with_withdrawal(
                        v,
                        required_bond_floor_nano() + 1_000 * STELL_NANO,
                        DEFAULT_COMMISSION_BPS,
                        addr_of(val_owners[idx]),
                    )
                    .unwrap();
                    l.distribute_reward(v, 50 * STELL_NANO).unwrap();
                }
                let total_r = l.rewards_pool;
                drop(l);
                e.update_account(AccountState::new(REWARDS_POOL, total_r))
                    .await;
            }
            // Pre-seed resting orders for shared_maker on PAIR 1 & PAIR 2.
            for (nonce, pair) in [PAIR_STELL_USDT, PAIR_STELL_TON].into_iter().enumerate() {
                let mk = pq_tx(
                    shared_maker_id,
                    shared_maker,
                    0,
                    500_000,
                    nonce as u64,
                    vec![OpCode::SysCallPlaceOrder {
                        pair_id: pair,
                        is_buy: false,
                        price: 1_000_000,
                        amount: 100_000,
                    }],
                );
                e.apply_transaction(&mk, TS).await.unwrap();
            }
        }

        const N_ACTORS: usize = 48;
        let mut nonces = vec![0u64; N_ACTORS];
        let mut txs = Vec::with_capacity(64);

        for step in 0..64usize {
            let actor_idx = (rng.below(N_ACTORS as u64)) as usize;
            let actor_id = 6_000 + actor_idx as u64;
            let actor_addr = addr_of(actor_id);
            let rcpt_addr = addr_of(7_000 + rng.below(200));
            watched.push((actor_addr, "mix_actor"));
            watched.push((rcpt_addr, "mix_rcpt"));

            for e in [&seq, &par] {
                if e.get_account(&actor_addr).await.is_none() {
                    e.update_account(AccountState::new(actor_addr, BAL)).await;
                    e.token_execute(
                        &tid,
                        minter,
                        TokenOp::Transfer {
                            to: actor_addr,
                            amount: 5_000,
                        },
                    )
                    .await
                    .unwrap();
                }
            }

            let fail_roll = rng.below(100);
            let nonce = if fail_roll < 5 {
                nonces[actor_idx] + 2 // nonce gap
            } else if fail_roll < 9 && nonces[actor_idx] > 0 {
                nonces[actor_idx] - 1 // replay
            } else {
                let n = nonces[actor_idx];
                nonces[actor_idx] += 1;
                n
            };

            let kind = rng.below(10);
            let (to, amount, gas, payload) = match kind {
                // Plain transfer
                0..=1 => (rcpt_addr, 1 + rng.below(1_000), GAS_BASIC_TRANSFER, vec![]),
                // Token transfer (with occasional insufficient balance & trailing post-Halt op)
                2..=3 => {
                    let amt = if fail_roll >= 90 {
                        50_000
                    } else {
                        10 + rng.below(200)
                    };
                    let mut ops = vec![OpCode::SysCallTokenTransfer {
                        token_id: tid,
                        to: rcpt_addr,
                        amount: amt,
                    }];
                    if step % 3 == 0 {
                        ops.push(OpCode::Halt);
                        ops.push(OpCode::SysCallTokenTransfer {
                            token_id: tid,
                            to: rcpt_addr,
                            amount: 999_999,
                        });
                    }
                    (rcpt_addr, 0, 500_000, ops)
                }
                // Token approve
                4 => (
                    rcpt_addr,
                    0,
                    500_000,
                    vec![OpCode::SysCallTokenApprove {
                        token_id: tid,
                        spender: rcpt_addr,
                        amount: if step % 2 == 0 { 0 } else { 500 },
                    }],
                ),
                // Multi-pair CLOB PlaceOrder (including shared maker across PAIR 1 & PAIR 2)
                5..=6 => {
                    let pair = match rng.below(4) {
                        0 => PAIR_STELL_USDT,
                        1 => PAIR_STELL_TON,
                        2 => PAIR_STELL_GRAM,
                        _ => 4,
                    };
                    (
                        actor_addr,
                        0,
                        500_000,
                        vec![OpCode::SysCallPlaceOrder {
                            pair_id: pair,
                            is_buy: rng.below(2) == 0,
                            price: 1_000_000,
                            amount: 100 + rng.below(500),
                        }],
                    )
                }
                // Staking Delegate
                7 => (
                    actor_addr,
                    0,
                    500_000,
                    vec![OpCode::SysCallDelegate {
                        validator: validators[rng.below(validators.len() as u64) as usize],
                        amount: MIN_DELEGATION,
                    }],
                ),
                // Contract CallContract / CallContractArgs (disjoint + hot slot + OOG + Halt)
                _ => {
                    let gas = if (85..90).contains(&fail_roll) {
                        100 // OOG
                    } else {
                        1_000_000
                    };
                    let mut ops = if step % 2 == 0 {
                        vec![OpCode::SysCallCallContractArgs {
                            contract: caddr,
                            method: b"set_slot".to_vec(),
                            args: vec![rng.below(16) as i64, step as i64],
                            calldata: Vec::new(),
                        }]
                    } else {
                        vec![OpCode::SysCallCallContract {
                            contract: caddr,
                            method: b"inc_hot".to_vec(),
                            arg: 1,
                        }]
                    };
                    if step % 4 == 0 {
                        ops.push(OpCode::Halt);
                        ops.push(OpCode::SysCallDeployContract { code: wasm.clone() });
                    }
                    (actor_addr, 0, gas, ops)
                }
            };

            txs.push(pq_tx(actor_id, to, amount, gas, nonce, payload));
        }

        // Also include validator owner ClaimRewards in the mixed block
        for (idx, &vo) in val_owners.iter().enumerate() {
            watched.push((addr_of(vo), "val_owner"));
            txs.push(pq_tx(
                vo,
                addr_of(vo),
                0,
                500_000,
                0,
                vec![OpCode::SysCallClaimRewards {
                    validator: validators[idx],
                }],
            ));
        }

        let (applied, failed, ..) =
            assert_full_parity(&seq, &par, &txs, &watched, &format!("mixed_round_{round}")).await;
        assert!(applied > 0 && failed > 0);
        assert_eq!(
            seq.get_contract(&caddr).await.unwrap().storage,
            par.get_contract(&caddr).await.unwrap().storage
        );
    }
}

#[tokio::test]
async fn w13_token_commit_native_failure_syncs_aux_trie_parity() {
    let seq = InMemoryStateEngine::new().with_parallel_exec(false);
    let par = InMemoryStateEngine::new().with_parallel_exec(true);

    let minter = addr_of(9700);
    let sender_a_id = 9701u64;
    let rcpt_a_id = 9702u64;
    let sender_b_id = 9703u64;
    let rcpt_b_id = 9704u64;
    let sender_a = addr_of(sender_a_id);
    let rcpt_a = addr_of(rcpt_a_id);
    let sender_b = addr_of(sender_b_id);
    let rcpt_b = addr_of(rcpt_b_id);

    let sched = TeamVestingSchedule::new(TS);
    let mut tid = [0u8; 32];
    for e in [&seq, &par] {
        e.update_account(AccountState::new(minter, BAL)).await;
        e.update_account(AccountState::new(sender_a, BAL)).await;
        // Exact vesting floor balance: passes precheck + plan_token_tx,
        // then commit_native fails once fee drops balance below locked floor.
        e.update_account(AccountState::new(sender_b, sched.total_allocation))
            .await;
        e.staking_write()
            .await
            .vesting_schedules
            .insert(sender_b, sched.clone());
        tid = e
            .create_token(minter, token_meta("AuxSync", "AUX"), 100_000)
            .await
            .unwrap();
        for acct in [sender_a, sender_b] {
            e.token_execute(
                &tid,
                minter,
                TokenOp::Transfer {
                    to: acct,
                    amount: 1_000,
                },
            )
            .await
            .unwrap();
        }
    }

    let txs = vec![
        pq_tx(
            sender_a_id,
            rcpt_a,
            0,
            500_000,
            0,
            vec![OpCode::SysCallTokenTransfer {
                token_id: tid,
                to: rcpt_a,
                amount: 400,
            }],
        ),
        pq_tx(
            sender_b_id,
            rcpt_b,
            0,
            500_000,
            0,
            vec![OpCode::SysCallTokenTransfer {
                token_id: tid,
                to: rcpt_b,
                amount: 400,
            }],
        ),
    ];

    let waves = DisjointScheduler::schedule_v2(&txs, true, true);
    assert_eq!(waves, vec![vec![0, 1]]);

    let watched = [
        (minter, "minter"),
        (sender_a, "sender_a"),
        (rcpt_a, "rcpt_a"),
        (sender_b, "sender_b"),
        (rcpt_b, "rcpt_b"),
    ];
    let (applied, failed, ..) = assert_full_parity(
        &seq,
        &par,
        &txs,
        &watched,
        "token_commit_native_err_sync_aux_trie",
    )
    .await;
    assert_eq!(applied, 1);
    assert_eq!(failed, 1);
}

#[tokio::test]
async fn w13_market_contract_cross_domain_same_wave_parity() {
    let seq = InMemoryStateEngine::new().with_parallel_exec(false);
    let par = InMemoryStateEngine::new().with_parallel_exec(true);
    let wasm = stm_test_contract_wasm();

    let minter = addr_of(9710);
    let creator = addr_of(9711);
    let taker1_id = 9712u64;
    let taker2_id = 9713u64;
    let caller1_id = 9714u64;
    let caller2_id = 9715u64;

    let mut rcpt = [0u8; 32];
    rcpt[0..8].copy_from_slice(&0x1111111111111111u64.to_le_bytes());
    rcpt[8..16].copy_from_slice(&0x2222222222222222u64.to_le_bytes());
    rcpt[16..24].copy_from_slice(&0x3333333333333333u64.to_le_bytes());
    rcpt[24..32].copy_from_slice(&0x4444444444444444u64.to_le_bytes());

    let mut caddr = [0u8; 32];
    for e in [&seq, &par] {
        e.update_account(AccountState::new(minter, BAL)).await;
        e.update_account(AccountState::new(creator, BAL)).await;
        e.update_account(AccountState::new(rcpt, 0)).await;
        for id in [taker1_id, taker2_id, caller1_id, caller2_id] {
            e.update_account(AccountState::new(addr_of(id), BAL)).await;
        }
        let usdt = e
            .create_token(minter, token_meta("Wrapped USDT", "wUSDT"), 1_000_000_000)
            .await
            .unwrap();
        e.pmm_init_usdt(usdt, 1_000_000_000).await;

        let addr = e.deploy_contract(creator, wasm.clone(), TS).await.unwrap();
        caddr = addr;
        // Fund contract with 20_000; two resting sell orders escrow 5_000 each -> 10_000 left.
        e.update_account(AccountState::new(addr, 20_000)).await;
        e.place_order_settled(
            PAIR_STELL_USDT,
            addr,
            OrderSide::Sell,
            OrderType::Limit,
            1_000_000,
            5_000,
            TS,
        )
        .await
        .unwrap();
        e.place_order_settled(
            PAIR_STELL_TON,
            addr,
            OrderSide::Sell,
            OrderType::Limit,
            1_000_000,
            5_000,
            TS,
        )
        .await
        .unwrap();
    }

    // Single wave:
    // tx 0: Market fill credits caddr +5_000 (10_000 -> 15_000)
    // tx 1: CallContract outbound send debits caddr -12_000 (needs the +5_000 credit! -> 3_000)
    // tx 2: Market fill credits caddr +5_000 after tx 1's debit (3_000 -> 8_000)
    // tx 3: CallContract outbound send debits caddr -6_000 (8_000 -> 2_000)
    let txs = vec![
        pq_tx(
            taker1_id,
            addr_of(taker1_id),
            0,
            500_000,
            0,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_USDT,
                is_buy: true,
                price: 1_000_000,
                amount: 5_000,
            }],
        ),
        pq_tx(
            caller1_id,
            addr_of(caller1_id),
            0,
            1_000_000,
            0,
            vec![OpCode::SysCallCallContractArgs {
                contract: caddr,
                method: b"send_ping".to_vec(),
                args: vec![12_000],
                calldata: Vec::new(),
            }],
        ),
        pq_tx(
            taker2_id,
            addr_of(taker2_id),
            0,
            500_000,
            0,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_TON,
                is_buy: true,
                price: 1_000_000,
                amount: 5_000,
            }],
        ),
        pq_tx(
            caller2_id,
            addr_of(caller2_id),
            0,
            1_000_000,
            0,
            vec![OpCode::SysCallCallContractArgs {
                contract: caddr,
                method: b"send_ping".to_vec(),
                args: vec![6_000],
                calldata: Vec::new(),
            }],
        ),
    ];

    let waves = DisjointScheduler::schedule_v2(&txs, true, true);
    assert_eq!(waves, vec![vec![0, 1, 2, 3]]);

    let watched = [
        (caddr, "contract"),
        (rcpt, "rcpt"),
        (addr_of(taker1_id), "taker1"),
        (addr_of(taker2_id), "taker2"),
        (addr_of(caller1_id), "caller1"),
        (addr_of(caller2_id), "caller2"),
    ];
    let (applied, failed, ..) =
        assert_full_parity(&seq, &par, &txs, &watched, "market_contract_cross_domain").await;
    assert_eq!(applied, 4);
    assert_eq!(failed, 0);
    assert_eq!(
        seq.get_account(&rcpt).await.unwrap().inbox,
        par.get_account(&rcpt).await.unwrap().inbox
    );
}

fn unroutable_send_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "host" "send_message" (func $send_message (param i64 i64 i64 i64 i64 i64) (result i64)))
          (memory (export "memory") 1)
          (func (export "send_bad") (param $val i64) (result i64)
            (i64.store (i32.const 0) (i64.const 0x1111111111111111))
            (i64.store (i32.const 8) (i64.const 0x2222222222222222))
            (i64.store (i32.const 16) (i64.const 0x3333333333333333))
            (i64.store (i32.const 24) (i64.const 0x4444444444444444))
            (i32.store (i32.const 64) (i32.const 0x474e4950))
            (call $send_message (i64.const 0) (i64.const 32) (local.get $val) (i64.const 64) (i64.const 4) (i64.const 1))))"#,
    )
    .expect("unroutable send wat must compile")
}

#[tokio::test]
async fn w13_unroutable_outbound_value_resets_contract_balance_parity() {
    let seq = InMemoryStateEngine::new().with_parallel_exec(false);
    let par = InMemoryStateEngine::new().with_parallel_exec(true);
    let wasm = unroutable_send_wasm();

    let creator = addr_of(9720);
    let caller1_id = 9721u64;
    let caller2_id = 9722u64;
    let mut caddr = [0u8; 32];
    for e in [&seq, &par] {
        e.update_account(AccountState::new(creator, BAL)).await;
        e.update_account(AccountState::new(addr_of(caller1_id), BAL))
            .await;
        e.update_account(AccountState::new(addr_of(caller2_id), BAL))
            .await;
        let addr = e.deploy_contract(creator, wasm.clone(), TS).await.unwrap();
        caddr = addr;
        e.update_account(AccountState::new(addr, 10_000)).await;
    }

    let txs = vec![
        pq_tx(
            caller1_id,
            addr_of(caller1_id),
            0,
            1_000_000,
            0,
            vec![OpCode::SysCallCallContract {
                contract: caddr,
                method: b"send_bad".to_vec(),
                arg: 8_000,
            }],
        ),
        pq_tx(
            caller2_id,
            addr_of(caller2_id),
            0,
            1_000_000,
            0,
            vec![OpCode::SysCallCallContract {
                contract: caddr,
                method: b"send_bad".to_vec(),
                arg: 8_000,
            }],
        ),
    ];

    let waves = DisjointScheduler::schedule_v2(&txs, true, true);
    assert_eq!(waves, vec![vec![0, 1]]);

    let watched = [
        (caddr, "contract"),
        (addr_of(caller1_id), "caller1"),
        (addr_of(caller2_id), "caller2"),
    ];
    let (applied, failed, ..) = assert_full_parity(
        &seq,
        &par,
        &txs,
        &watched,
        "unroutable_outbound_balance_resync",
    )
    .await;
    assert_eq!(applied, 2);
    assert_eq!(failed, 0);
}

#[test]
fn w13_contract_registry_rejects_oversized_calldata() {
    let mut reg = ContractRegistry::new();
    let creator = [0x31u8; 32];
    let addr = reg
        .deploy(creator, stm_test_contract_wasm(), TS)
        .expect("deploy must succeed");
    let ctx = ContractCallContext {
        caller: creator,
        value: 0,
        block_time: TS,
        block_hash: [0u8; 32],
    };

    let oversized = vec![0xAAu8; MAX_CONTRACT_CALLDATA_BYTES + 1];
    let err_legacy = reg
        .call_with_context_args_calldata(&addr, "set_slot", &[1, 2], &oversized, 1_000_000, &ctx)
        .unwrap_err();
    assert!(matches!(err_legacy, ContractError::AbiMismatch(_)));

    let err_hardened = reg
        .call_with_context_args_calldata_hardened_at(
            &addr,
            "set_slot",
            &[1, 2],
            &oversized,
            1_000_000,
            &ctx,
            creator,
            creator,
            true,
            0,
        )
        .unwrap_err();
    assert!(matches!(err_hardened, ContractError::AbiMismatch(_)));

    let exact = vec![0xBBu8; MAX_CONTRACT_CALLDATA_BYTES];
    let ok = reg
        .call_with_context_args_calldata_hardened_at(
            &addr,
            "set_slot",
            &[1, 42],
            &exact,
            1_000_000,
            &ctx,
            creator,
            creator,
            true,
            0,
        )
        .expect("exact MAX_CONTRACT_CALLDATA_BYTES must succeed");
    assert_eq!(ok.result, 42);
}

#[tokio::test]
async fn w13_deploy_contract_with_abi_only_block_matches_sequential_trie() {
    struct AbiGateGuard;
    impl Drop for AbiGateGuard {
        fn drop(&mut self) {
            stellereum::chain_spec::set_contract_abi_onchain_activation_override(None);
        }
    }
    let _guard = AbiGateGuard;
    stellereum::chain_spec::set_contract_abi_onchain_activation_override(Some(0));

    let seq = InMemoryStateEngine::new().with_parallel_exec(false);
    let par = InMemoryStateEngine::new().with_parallel_exec(true);
    let wasm = stm_test_contract_wasm();
    let abi_json = br#"{"methods":[{"name":"set_slot","params":[{"name":"k","type":"i64"},{"name":"v","type":"i64"}],"returns":"i64","mutates_state":true}],"events":[]}"#.to_vec();

    let deployer_id = 9750u64;
    let deployer = addr_of(deployer_id);
    for e in [&seq, &par] {
        e.update_account(AccountState::new(deployer, BAL)).await;
    }

    let expected_caddr = stellereum::contract::contract_address(&deployer, 0);
    let gas_limit =
        stellereum::svm::contract_deploy_with_abi_gas(wasm.len(), abi_json.len()) + 500_000;
    let tx = pq_tx(
        deployer_id,
        deployer,
        0,
        gas_limit,
        0,
        vec![OpCode::SysCallDeployContractWithAbi {
            code: wasm,
            abi_json: abi_json.clone(),
        }],
    );

    let (applied, failed, ..) = assert_full_parity(
        &seq,
        &par,
        &[tx],
        &[(deployer, "deployer"), (expected_caddr, "contract")],
        "deploy_contract_with_abi_only_block",
    )
    .await;
    assert_eq!(applied, 1);
    assert_eq!(failed, 0);

    let seq_abi = seq
        .get_contract_abi_json(&expected_caddr)
        .await
        .expect("sequential contract ABI must be persisted");
    let par_abi = par
        .get_contract_abi_json(&expected_caddr)
        .await
        .expect("parallel contract ABI must be persisted");
    assert_eq!(seq_abi, par_abi);

    let code_key = stellereum::state_engine::contract_key(&expected_caddr);
    let abi_key = stellereum::state_engine::contract_abi_key(&expected_caddr);
    let seq_code_leaf = seq
        .state_trie
        .read()
        .await
        .get(&code_key)
        .map(|b| b.to_vec());
    let par_code_leaf = par
        .state_trie
        .read()
        .await
        .get(&code_key)
        .map(|b| b.to_vec());
    let seq_abi_leaf = seq
        .state_trie
        .read()
        .await
        .get(&abi_key)
        .map(|b| b.to_vec());
    let par_abi_leaf = par
        .state_trie
        .read()
        .await
        .get(&abi_key)
        .map(|b| b.to_vec());
    assert!(
        seq_code_leaf.is_some(),
        "contract code trie leaf must exist"
    );
    assert!(seq_abi_leaf.is_some(), "contract ABI trie leaf must exist");
    assert_eq!(
        seq_code_leaf, par_code_leaf,
        "parallel deploy-with-abi code trie leaf must match sequential"
    );
    assert_eq!(
        seq_abi_leaf, par_abi_leaf,
        "parallel deploy-with-abi ABI trie leaf must match sequential"
    );
}
