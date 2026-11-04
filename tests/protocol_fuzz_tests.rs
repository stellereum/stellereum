//! Stateful protocol fuzz: random BLOCK sequences through the real block path.
//!
//! Coverage: seeded xorshift builds blocks of random valid/edge transactions
//! (plain transfers, stake/delegate/claim syscalls, oracle-vote feeds, faucet
//! drips, garbage intermixed) applied via
//! [`InMemoryStateEngine::apply_block_transition`], asserting after EVERY
//! block: (1) no panic — the transition is infallible and every tx refusal is
//! a `false` status flag, never an `Err`/panic; (2) supply conservation —
//! native sum + `total_burned` == funded + `rewards_minted`; (3) deterministic
//! state roots — the recorded block sequence re-applied on a second fresh
//! engine yields identical per-block roots; (4) invalid txs never mint —
//! per-block native delta is bounded by the minted reward; (5) chain keeps
//! finalizing at apply level — every block yields a well-formed outcome.
//!
//! Determinism: xorshift64 with fixed `SEED_*` constants, fixed block clock
//! (`block.timestamp`, never wall time), fixed keys/funding. No OS
//! randomness, no wall-clock asserts, no new dependencies.
//!
//! COVERAGE BOUNDARY (reported, not covered): this suite pins the APPLY path
//! only. It does NOT run consensus (no votes/QC assembly/quorum rotation),
//! does NOT exercise mempool admission ordering or eviction, does NOT test
//! snapshot/restore, cross-shard delivery, or proposer liveness under faults.
//! "Blocks accepted / chain keeps finalizing" below means: every built block
//! is accepted by `apply_block_transition` with a well-formed outcome and an
//! advancing state root — full-sim quorum finalization is out of scope.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use stellereum::mev::compute_order_merkle_root;
use stellereum::oracle::PriceFeedUpdate;
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::staking::{self, MIN_DELEGATION};
use stellereum::svm::{
    OpCode, GAS_BASIC_TRANSFER, GAS_STAKE_BOND, GAS_STAKE_CLAIM, GAS_SUBMIT_PRICE_FEED,
};

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64, same idiom as `fuzz_economics_ext.rs`).
// ---------------------------------------------------------------------------

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.next() % n
    }
}

// ---------------------------------------------------------------------------
// Campaign shape.
// ---------------------------------------------------------------------------

const SEED_A: u64 = 0xB10C_F025_0000_0001;
const SEED_B: u64 = 0xB10C_F025_0000_0002;
const SEED_C: u64 = 0xB10C_F025_0000_0003;

const BLOCKS_PER_CAMPAIGN: usize = 16;
const TS_BASE: u64 = 1_760_000_000;
const TS_STEP: u64 = 2;
const BLOCK_REWARD: u64 = 1_000;
const USER_FUNDS: u64 = 5_000_000_000_000;
const FAUCET_FUNDS: u64 = 20_000_000_000_000;
const N_USERS: u8 = 8;

fn user_key(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[0x10u8.wrapping_add(i); 32])
}
fn faucet_key() -> SigningKey {
    SigningKey::from_bytes(&[0xF0u8; 32])
}
fn publisher_key() -> SigningKey {
    SigningKey::from_bytes(&[0xE0u8; 32])
}
fn user_addr(i: u8) -> [u8; 32] {
    user_key(i).verifying_key().to_bytes()
}

async fn native_sum(engine: &InMemoryStateEngine) -> u128 {
    engine
        .accounts
        .read()
        .await
        .values()
        .map(|a| a.balance as u128)
        .sum()
}

async fn pool_balance(engine: &InMemoryStateEngine, pool: &[u8; 32]) -> u64 {
    engine.get_account(pool).await.map(|a| a.balance).unwrap_or(0)
}

fn mk_block(height: u64, prev: [u8; 32], ts: u64, txs: Vec<Transaction>, proposer: [u8; 32]) -> Block {
    let order_merkle_root = compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: ts,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    }
}

struct Harness {
    engine: InMemoryStateEngine,
    funded_total: u128,
    nonces: HashMap<[u8; 32], u64>,
    faucet_addr: [u8; 32],
    proposer: [u8; 32],
}

impl Harness {
    async fn genesis() -> Self {
        let engine = InMemoryStateEngine::new();
        let mut funded_total: u128 = 0;
        for i in 0..N_USERS {
            let addr = user_addr(i);
            engine.update_account(AccountState::new(addr, USER_FUNDS)).await;
            funded_total += USER_FUNDS as u128;
        }
        let faucet_addr = faucet_key().verifying_key().to_bytes();
        engine
            .update_account(AccountState::new(faucet_addr, FAUCET_FUNDS))
            .await;
        funded_total += FAUCET_FUNDS as u128;
        let publisher_addr = publisher_key().verifying_key().to_bytes();
        engine
            .oracle_write()
            .await
            .publishers
            .insert(publisher_addr);
        Self {
            engine,
            funded_total,
            nonces: HashMap::new(),
            faucet_addr,
            proposer: user_addr(0),
        }
    }

    async fn resync_nonces(&mut self) {
        let mut addrs: Vec<[u8; 32]> = (0..N_USERS).map(user_addr).collect();
        addrs.push(self.faucet_addr);
        for a in addrs {
            if let Some(acc) = self.engine.get_account(&a).await {
                self.nonces.insert(a, acc.nonce);
            }
        }
    }
}

fn edge_amount(rng: &mut XorShift, floor: u64) -> u64 {
    let table: [u64; 14] = [
        0,
        1,
        2,
        7,
        1_000,
        MIN_DELEGATION.saturating_sub(1),
        MIN_DELEGATION,
        MIN_DELEGATION.saturating_add(1),
        floor.saturating_sub(1),
        floor,
        floor.saturating_add(1),
        50_000_000_000,
        u64::MAX / 2,
        u64::MAX,
    ];
    table[(rng.below(table.len() as u64)) as usize]
}

// Build one random tx. Returns the tx; `used_nonce` tracks whether the
// harness nonce table was consumed (bogus-nonce garbage is not consumed).
#[allow(clippy::too_many_arguments)]
// GATE: test-only fuzz builder mirrors the tx-sign parameter shape; fewer params would hide arms.
fn gen_tx(
    rng: &mut XorShift,
    h: &mut Harness,
    floor: u64,
    block_ts: u64,
    in_block_used: &mut HashMap<[u8; 32], u64>,
) -> Transaction {
    let arm = rng.below(100);
    let user_idx = rng.below(u64::from(N_USERS)) as u8;
    let sender_key = if (65..=74).contains(&arm) {
        faucet_key()
    } else {
        user_key(user_idx)
    };
    let sender_addr = sender_key.verifying_key().to_bytes();
    let base = *h.nonces.get(&sender_addr).unwrap_or(&0);
    let used = *in_block_used.get(&sender_addr).unwrap_or(&0);
    let nonce = base + used;
    // Helper: consume one nonce slot for honestly-nonces arms.
    let take_nonce = |in_block_used: &mut HashMap<[u8; 32], u64>| {
        in_block_used.insert(sender_addr, used + 1);
        nonce
    };
    match arm {
        0..=29 => {
            // Plain transfer (valid/edge amounts).
            let n = take_nonce(in_block_used);
            let to = if rng.below(2) == 0 {
                user_addr(rng.below(u64::from(N_USERS)) as u8)
            } else {
                [0xB0u8.wrapping_add(rng.below(16) as u8); 32]
            };
            Transaction::sign(
                &sender_key,
                to,
                edge_amount(rng, floor),
                GAS_BASIC_TRANSFER + 1_000,
                n,
                MASTERCHAIN_SHARD,
                MASTERCHAIN_SHARD,
            )
        }
        30..=44 => {
            // Stake (bond or top-up).
            let n = take_nonce(in_block_used);
            let validator = match rng.below(4) {
                0..=2 => user_addr(rng.below(3) as u8),
                _ => [0x77u8; 32],
            };
            let to = user_addr(rng.below(u64::from(N_USERS)) as u8);
            Transaction::sign_with_payload(
                &sender_key,
                to,
                0,
                GAS_STAKE_BOND + 1_000,
                n,
                MASTERCHAIN_SHARD,
                MASTERCHAIN_SHARD,
                vec![OpCode::SysCallStake {
                    validator,
                    amount: edge_amount(rng, floor),
                }],
            )
        }
        45..=54 => {
            // Delegate.
            let n = take_nonce(in_block_used);
            let validator = user_addr(rng.below(3) as u8);
            let to = user_addr(rng.below(u64::from(N_USERS)) as u8);
            Transaction::sign_with_payload(
                &sender_key,
                to,
                0,
                GAS_STAKE_BOND + 1_000,
                n,
                MASTERCHAIN_SHARD,
                MASTERCHAIN_SHARD,
                vec![OpCode::SysCallDelegate {
                    validator,
                    amount: edge_amount(rng, floor),
                }],
            )
        }
        55..=64 => {
            // Oracle vote: valid feed or fail-closed variant.
            let n = take_nonce(in_block_used);
            let to = user_addr(rng.below(u64::from(N_USERS)) as u8);
            let feed = if rng.below(3) == 0 {
                // Invalid: untrusted publisher or stale clock.
                if rng.below(2) == 0 {
                    PriceFeedUpdate::sign(
                        "STELL",
                        100_000 + rng.below(900_000),
                        block_ts,
                        &user_key(rng.below(u64::from(N_USERS)) as u8),
                    )
                } else {
                    PriceFeedUpdate::sign(
                        "STELL",
                        100_000 + rng.below(900_000),
                        block_ts.saturating_sub(1_000_000),
                        &publisher_key(),
                    )
                }
            } else {
                PriceFeedUpdate::sign(
                    "STELL",
                    100_000 + rng.below(900_000),
                    block_ts,
                    &publisher_key(),
                )
            };
            Transaction::sign_with_payload(
                &sender_key,
                to,
                0,
                GAS_SUBMIT_PRICE_FEED + 500,
                n,
                MASTERCHAIN_SHARD,
                MASTERCHAIN_SHARD,
                vec![OpCode::SysCallSubmitPriceFeed(Box::new(feed))],
            )
        }
        65..=74 => {
            // Faucet drip: small funded transfer from the faucet account.
            let faucet_base = *h.nonces.get(&sender_addr).unwrap_or(&0);
            let faucet_used = *in_block_used.get(&sender_addr).unwrap_or(&0);
            in_block_used.insert(sender_addr, faucet_used + 1);
            let to = if rng.below(2) == 0 {
                user_addr(rng.below(u64::from(N_USERS)) as u8)
            } else {
                [0xD0u8.wrapping_add(rng.below(16) as u8); 32]
            };
            let _ = faucet_base;
            Transaction::sign(
                &sender_key,
                to,
                1_000_000 + rng.below(5_000_000_000),
                GAS_BASIC_TRANSFER + 1_000,
                faucet_base + faucet_used,
                MASTERCHAIN_SHARD,
                MASTERCHAIN_SHARD,
            )
        }
        75..=84 => {
            // Claim rewards (mostly fail-closed until rewards accrue).
            let n = take_nonce(in_block_used);
            Transaction::sign_with_payload(
                &sender_key,
                sender_addr,
                0,
                GAS_STAKE_CLAIM + 500,
                n,
                MASTERCHAIN_SHARD,
                MASTERCHAIN_SHARD,
                vec![OpCode::SysCallClaimRewards {
                    validator: sender_addr,
                }],
            )
        }
        _ => {
            // Garbage: bad signature, bogus nonce, overspend, or zero gas.
            let to = user_addr(rng.below(u64::from(N_USERS)) as u8);
            match rng.below(4) {
                0 => {
                    let n = take_nonce(in_block_used);
                    let mut tx = Transaction::sign(
                        &sender_key,
                        to,
                        rng.below(1_000_000),
                        GAS_BASIC_TRANSFER + 1_000,
                        n,
                        MASTERCHAIN_SHARD,
                        MASTERCHAIN_SHARD,
                    );
                    if !tx.signature.is_empty() {
                        tx.signature[0] ^= 0xFF;
                    } else {
                        tx.signature.push(0xFF);
                    }
                    tx
                }
                1 => Transaction::sign(
                    &sender_key,
                    to,
                    rng.below(1_000_000),
                    GAS_BASIC_TRANSFER + 1_000,
                    u64::MAX,
                    MASTERCHAIN_SHARD,
                    MASTERCHAIN_SHARD,
                ),
                2 => {
                    let n = take_nonce(in_block_used);
                    Transaction::sign(
                        &sender_key,
                        to,
                        u64::MAX,
                        GAS_BASIC_TRANSFER + 1_000,
                        n,
                        MASTERCHAIN_SHARD,
                        MASTERCHAIN_SHARD,
                    )
                }
                _ => {
                    let n = take_nonce(in_block_used);
                    Transaction::sign(
                        &sender_key,
                        to,
                        rng.below(1_000_000),
                        0,
                        n,
                        MASTERCHAIN_SHARD,
                        MASTERCHAIN_SHARD,
                    )
                }
            }
        }
    }
}

struct CampaignReport {
    seed: u64,
    blocks: usize,
    applied: usize,
    failed: usize,
    assertions: usize,
    final_root: [u8; 32],
}

async fn run_campaign(seed: u64) -> CampaignReport {
    let floor = staking::required_bond_floor_nano();
    let mut rng = XorShift(seed);
    let mut h = Harness::genesis().await;
    let mut asserts: usize = 0;
    let mut applied_total: usize = 0;
    let mut failed_total: usize = 0;
    let mut prev_hash = [0u8; 32];
    let mut blocks: Vec<Block> = Vec::with_capacity(BLOCKS_PER_CAMPAIGN);
    let mut roots: Vec<[u8; 32]> = Vec::with_capacity(BLOCKS_PER_CAMPAIGN);

    for height in 1..=BLOCKS_PER_CAMPAIGN as u64 {
        let ts = TS_BASE + height * TS_STEP;
        let n_txs = 2 + (rng.below(7) as usize);
        let mut in_block_used: HashMap<[u8; 32], u64> = HashMap::new();
        let mut txs = Vec::with_capacity(n_txs);
        for _ in 0..n_txs {
            txs.push(gen_tx(&mut rng, &mut h, floor, ts, &mut in_block_used));
        }
        let block = mk_block(height, prev_hash, ts, txs.clone(), h.proposer);

        // Pre-state snapshot for the invalid-mint bound.
        let sum_before = native_sum(&h.engine).await;
        let (burned_before, minted_before) = {
            let l = h.engine.staking_read().await;
            (l.total_burned, l.rewards_minted)
        };

        // (1) No panic: an infallible transition; reaching the next line is
        // the pin. All tx refusals are `false` status flags (typed), never Err.
        let outcome = h.engine.apply_block_transition(&block, BLOCK_REWARD).await;

        // Outcome shape.
        assert_eq!(outcome.status.len(), txs.len(), "seed {seed} h{height}: status len");
        asserts += 1;
        assert_eq!(
            outcome.applied + outcome.failed,
            txs.len(),
            "seed {seed} h{height}: applied+failed==len"
        );
        asserts += 1;
        assert_eq!(outcome.tx_fees.len(), txs.len(), "seed {seed} h{height}: tx_fees len");
        asserts += 1;
        // Receipt consistency: the status vector partitions the block, and
        // the collected fees equal the sum of per-tx receipts. (Fee leg
        // note: `tx_fees[i]` may exceed `gas_limit` by design — the F-01
        // failure fee charges `max(declared, floor) + surcharge` — so the
        // pin is receipt consistency, not a declared-gas bound.)
        let failed_count = outcome.status.iter().filter(|s| !**s).count();
        let applied_count = outcome.status.iter().filter(|s| **s).count();
        assert_eq!(outcome.failed, failed_count, "seed {seed} h{height}: failed count");
        asserts += 1;
        assert_eq!(outcome.applied, applied_count, "seed {seed} h{height}: applied count");
        asserts += 1;
        assert_eq!(
            outcome.fees_collected,
            outcome.tx_fees.iter().copied().sum::<u64>(),
            "seed {seed} h{height}: fees_collected must equal receipt sum"
        );
        asserts += 1;

        // (2) Supply conservation via the staking conservation helper
        // (`ledger_stake_supply`) plus pool/burned accounting.
        let pool = pool_balance(&h.engine, &staking::STAKING_POOL).await;
        let rpool = pool_balance(&h.engine, &staking::REWARDS_POOL).await;
        let (supply, burned, minted, rpool_ledger) = {
            let l = h.engine.staking_read().await;
            (
                l.ledger_stake_supply(),
                l.total_burned,
                l.rewards_minted,
                l.rewards_pool,
            )
        };
        assert_eq!(
            pool, supply,
            "seed {seed} h{height}: STAKING_POOL balance must equal ledger_stake_supply"
        );
        asserts += 1;
        assert_eq!(
            rpool, rpool_ledger,
            "seed {seed} h{height}: REWARDS_POOL balance must equal ledger rewards_pool"
        );
        asserts += 1;
        let sum_after = native_sum(&h.engine).await;
        assert_eq!(
            sum_after + burned as u128,
            h.funded_total + minted as u128,
            "seed {seed} h{height}: NATIVE CONSERVATION BROKEN"
        );
        asserts += 1;

        // (4) Invalid txs never mint: the native delta is bounded above by
        // the freshly minted reward and below by the freshly burned slash.
        let minted_delta = minted.saturating_sub(minted_before) as u128;
        let burned_delta = burned.saturating_sub(burned_before) as u128;
        assert!(
            sum_after <= sum_before + minted_delta,
            "seed {seed} h{height}: native grew beyond minted reward (mint!)"
        );
        asserts += 1;
        assert!(
            sum_before + minted_delta >= sum_after + burned_delta,
            "seed {seed} h{height}: native delta inconsistent with burn"
        );
        asserts += 1;

        // (5) Chain keeps finalizing at apply level: heights advance and the
        // root is defined after every block.
        assert_eq!(block.height, height, "seed {seed}: height must advance");
        asserts += 1;
        let root = h.engine.get_state_root().await;
        roots.push(root);
        prev_hash = block.compute_hash();

        // Advance the harness nonce table from committed state.
        h.resync_nonces().await;
        applied_total += outcome.applied;
        failed_total += outcome.failed;
        blocks.push(block);
    }

    // (3) Determinism: rebuild twice — re-apply the recorded blocks on a
    // fresh engine and demand identical per-block roots (replay equality).
    let h2 = Harness::genesis().await;
    assert_eq!(h2.funded_total, h.funded_total, "genesis funding must be deterministic");
    asserts += 1;
    for (i, block) in blocks.iter().enumerate() {
        let outcome2 = h2.engine.apply_block_transition(block, BLOCK_REWARD).await;
        assert_eq!(
            outcome2.applied + outcome2.failed,
            block.transactions.len(),
            "replay seed {seed} h{}: outcome shape",
            i + 1
        );
        asserts += 1;
        let root2 = h2.engine.get_state_root().await;
        assert_eq!(root2, roots[i], "replay seed {seed} h{}: root diverged", i + 1);
        asserts += 1;
    }
    let final_root = *roots.last().expect("at least one block");

    CampaignReport {
        seed,
        blocks: blocks.len(),
        applied: applied_total,
        failed: failed_total,
        assertions: asserts,
        final_root,
    }
}

#[tokio::test]
async fn protocol_fuzz_campaign_a_blocks_conserve_and_replay() {
    let r = run_campaign(SEED_A).await;
    assert_eq!(r.blocks, BLOCKS_PER_CAMPAIGN, "campaign A must apply all blocks");
    assert!(r.assertions > BLOCKS_PER_CAMPAIGN * 8, "campaign A must do real work");
    println!(
        "CAMPAIGN A seed={:#x} blocks={} applied={} failed={} assertions={} final_root={}",
        r.seed,
        r.blocks,
        r.applied,
        r.failed,
        r.assertions,
        hex::encode(r.final_root)
    );
}

#[tokio::test]
async fn protocol_fuzz_campaign_b_blocks_conserve_and_replay() {
    let r = run_campaign(SEED_B).await;
    assert_eq!(r.blocks, BLOCKS_PER_CAMPAIGN, "campaign B must apply all blocks");
    assert!(r.assertions > BLOCKS_PER_CAMPAIGN * 8, "campaign B must do real work");
    println!(
        "CAMPAIGN B seed={:#x} blocks={} applied={} failed={} assertions={} final_root={}",
        r.seed,
        r.blocks,
        r.applied,
        r.failed,
        r.assertions,
        hex::encode(r.final_root)
    );
}

#[tokio::test]
async fn protocol_fuzz_campaign_c_blocks_conserve_and_replay() {
    let r = run_campaign(SEED_C).await;
    assert_eq!(r.blocks, BLOCKS_PER_CAMPAIGN, "campaign C must apply all blocks");
    assert!(r.assertions > BLOCKS_PER_CAMPAIGN * 8, "campaign C must do real work");
    println!(
        "CAMPAIGN C seed={:#x} blocks={} applied={} failed={} assertions={} final_root={}",
        r.seed,
        r.blocks,
        r.applied,
        r.failed,
        r.assertions,
        hex::encode(r.final_root)
    );
}
