//! Mempool / fee-market / MEV / emission audit closure
//! (audit-mempool.md + audit-staking I1/O1, mission bundle).
//!
//! Pins every mission-scope finding NOT already pinned by a sibling suite:
//!
//! * F-02 `add_tx` carries the on-chain head, so the insert-level gap
//!   fail-fast holds on the runtime admission path too (RPC/gossip/restore
//!   pre-checks + `vuln_bundle` insert-level pin stay as defense in depth);
//! * F-03 reservation release on evict (claim-backed, not a leak);
//! * F-05 within-window gap squatting is bounded and self-draining via
//!   `sweep_expired`; executable txs are never swept;
//! * F-06/W2/W3 surcharge mirrors: admission floor, reservation unit and
//!   pack/validate/apply charge the SAME `amount+gas(+45k?)` cost under the
//!   SAME `is_pq_activation` predicate (activation admitted only at/above
//!   floor+surcharge);
//! * F-07 pack-vs-admission balance parity at formula level;
//! * F-10 replay protection (hash dedup; same-(sender,nonce) coexistence is
//!   documented implicit RBF, first-executed-wins);
//! * F-11 fee-market honesty (static floor, no dynamic component; EVM fee
//!   fields decorative);
//! * F-08/MEv stance: seal enforced at build (mismatch dropped), order
//!   commitment detection-only (mismatch converges, vote-gate deferred with
//!   documented preconditions);
//! * mev_v4 parked behind an explicit default-off flag (no removal, no
//!   wiring — product decision);
//! * I1 emission schedule intentionally dead (banner, owner decree) with the
//!   flat reward pinned live.
//!
//! Deliberately NOT duplicated here: F-01 validate/apply floor
//! (`apply_floor_tests`), F-03 quota + F-04 2x churn (`mempool_econ_tests`),
//! F-02 insert-level (`vuln_bundle_tests`), PQ activation vectors
//! (`post_quantum_audit_tests`), MEV preemption suites (`mev_preemption_*`,
//! `mev_pq_tests`). F-09 faucet discipline lives in `rpc`/`explorer`
//! (outside this mission's file list): residual is a corrupted-durable-state
//! gapped nonce that `insert` now ALSO refuses whenever the head is carried
//! — benign, self-healing via restart clamp-down; tracked, not re-tested.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;

use stellereum::consensus::ValidatorSet;
use stellereum::mempool::{AdmissionCtx, Mempool, MempoolError, PQ_ACTIVATION_SURCHARGE_GAS};
use stellereum::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{PqSignatureEnvelope, Transaction};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const STELL: u64 = 1_000_000_000;
fn key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}
fn transfer(k: &SigningKey, to: [u8; 32], amount: u64, gas: u64, nonce: u64) -> Transaction {
    Transaction::sign(k, to, amount, gas, nonce, 1, 1)
}

// ============================================================================
// F-02 — add_tx enforces the gap at the choke point
// ============================================================================

/// `ValidatorRuntime::add_tx` carries the sender's on-chain nonce into
/// `insert`, so a far-future nonce is refused on the runtime path itself —
/// not just at the RPC/gossip pre-checks. In-window nonces still admit.
#[tokio::test]
async fn f02_add_tx_refuses_gapped_nonce() {
    let k = key();
    let me = k.verifying_key().to_bytes();
    let vs = ValidatorSet::from_list(vec![(me, 1)]);
    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(AccountState::new(me, 100 * STELL)).await;
    let mut rt = ValidatorRuntime::new(k.clone(), vs, st, 1);

    rt.add_tx(transfer(&k, [9u8; 32], 1, 1_000, 32)).await;
    assert_eq!(
        rt.mempool.read().await.len(),
        0,
        "nonce 32 vs on-chain 0 (window 16) must not pool"
    );
    rt.add_tx(transfer(&k, [9u8; 32], 1, 1_000, 0)).await;
    assert_eq!(rt.mempool.read().await.len(), 1, "head nonce admits");
    rt.add_tx(transfer(&k, [9u8; 32], 1, 1_000, 32)).await;
    assert_eq!(
        rt.mempool.read().await.len(),
        1,
        "gap past the advanced head still refused; pooled head untouched"
    );
}

// ============================================================================
// F-03 — reservation is claim-backed: evict releases, re-admit works
// ============================================================================

/// Eviction (fee, expiry, or explicit remove) releases the sender's reserved
/// cost, so the reservation table cannot leak quota or funds.
#[test]
fn f03_eviction_releases_reservation() {
    let sk = key();
    let me = sk.verifying_key().to_bytes();
    // Pool of exactly 1: the second admission must evict at >= 2x.
    let mut mp = Mempool::new(1, 64);
    let cost = |fee: u64| 100 + fee;
    mp.add_checked(transfer(&sk, [1u8; 32], 100, 1_000, 0), 50_000_000)
        .unwrap();
    assert_eq!(mp.reserved_for(&me), cost(1_000));

    let sk2 = key();
    mp.add_checked(transfer(&sk2, [2u8; 32], 100, 2_000, 0), 50_000_000)
        .expect("2x bid evicts");
    assert_eq!(mp.len(), 1, "pool holds exactly the evictor");
    assert_eq!(
        mp.reserved_for(&me),
        0,
        "evicted sender's reservation is fully released"
    );
    // And the released sender can re-enter with fresh funding math.
    mp.add_checked(transfer(&sk, [1u8; 32], 100, 4_000, 1), 50_000_000)
        .expect("released funds are re-admittable");
    assert_eq!(mp.len(), 1);
}

// ============================================================================
// F-05 — within-window gaps are bounded and self-draining
// ============================================================================

/// A within-window gap (nonce 5 vs head 0) admits — that is normal queuing,
/// not an attack — but it stays unexecutable and is swept once old, while an
/// executable head-tx of the same age is never swept.
#[test]
fn f05_windowed_gap_admits_then_drains_executable_survives() {
    let sk = key();
    let exec = transfer(&sk, [1u8; 32], 10, 1_000, 0);
    let gapped = transfer(&sk, [1u8; 32], 10, 1_000, 5);
    let mut mp = Mempool::new(100, 100);
    let ctx = AdmissionCtx::new(1_000).with_onchain_nonce(0);
    mp.add_checked_ctx(exec, 50_000_000, ctx).unwrap();
    mp.add_checked_ctx(gapped, 50_000_000, ctx).unwrap();
    assert_eq!(mp.len(), 2, "windowed gap (5 <= 0+16) is admitted");

    // Far past the TTL, against the same funded account at nonce 0.
    let now = 1_000 + Mempool::STUCK_TX_TTL_SECS + 1;
    let swept = mp.sweep_expired(now, |_| Some((0u64, 50_000_000u64)));
    assert_eq!(swept, 1, "only the gap-stuck tx drains");
    assert_eq!(mp.len(), 1, "the executable head survives any age");
}

// ============================================================================
// F-06 / W2 / W3 / F-07 — one surcharge, one predicate, one cost
// ============================================================================

/// Build a real Falcon-512 explicit-key (activation) transaction.
fn activation_tx(gas_limit: u64, nonce: u64) -> (Transaction, [u8; 32]) {
    let seed = 0xA0u8;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    let mut tx = Transaction {
        from,
        to: [0xB0; 32],
        amount: 0,
        gas_limit,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk, sig).encode();
    assert!(tx.is_pq_activation(), "fixture must be an activation tx");
    (tx, from)
}

/// The three mirrors agree on ONE formula: admission floor, reservation
/// unit and execution charge are all `amount + gas (+45k iff activation)`
/// under the same predicate. A degenerate implicit envelope (pubkey bytes
/// present but implicit) is consistently NON-activation on both sides.
#[test]
fn f06_single_cost_formula_plain_and_activation() {
    // Plain tx: no surcharge anywhere.
    let sk = key();
    let plain = transfer(&sk, [1u8; 32], 100, 1_000, 0);
    assert!(!plain.is_pq_activation());
    assert_eq!(Mempool::tx_cost(&plain), 100 + 1_000);
    let mp = Mempool::new(10, 10).with_base_fee(500);
    assert_eq!(
        mp.effective_floor_for_tx(&plain),
        500,
        "plain floor is exactly base + penalty(0) + surcharge(0)"
    );

    // Activation tx: +45k in BOTH the floor and the cost unit.
    let (act, _) = activation_tx(50_000, 0);
    assert_eq!(
        Mempool::tx_cost(&act),
        50_000 + PQ_ACTIVATION_SURCHARGE_GAS,
        "reservation unit carries the surcharge (W3)"
    );
    assert_eq!(
        mp.effective_floor_for_tx(&act),
        500 + PQ_ACTIVATION_SURCHARGE_GAS,
        "admission floor carries the same surcharge (W2)"
    );

    // Admission parity: floor+surcharge−1 refused, floor+surcharge admitted.
    let mut mp2 = Mempool::new(10, 10).with_base_fee(500);
    let (short, from) = activation_tx(500 + PQ_ACTIVATION_SURCHARGE_GAS - 1, 0);
    assert_eq!(
        mp2.add_checked(short, 50_000_000),
        Err(MempoolError::FeeTooLow),
        "F-07 class: under-surcharge activation never packs because it never pools"
    );
    let (exact, _) = activation_tx(500 + PQ_ACTIVATION_SURCHARGE_GAS, 0);
    let rich = 500 + PQ_ACTIVATION_SURCHARGE_GAS + 1_000_000;
    mp2.add_checked(exact, rich)
        .expect("exact floor+surcharge admits");
    assert_eq!(
        mp2.reserved_for(&from),
        500 + PQ_ACTIVATION_SURCHARGE_GAS + PQ_ACTIVATION_SURCHARGE_GAS
    );
}

/// Pack-vs-admission balance parity (F-07): the proposer must skip what
/// apply would refuse. The pack filter's `cost` and admission's `tx_cost`
/// are the same function of the same inputs, so the 45k-wide band that
/// used to pack-but-fail is closed by construction.
#[test]
fn f07_pack_cost_equals_admission_cost() {
    let (act, _) = activation_tx(1_000_000, 0);
    // Admission's single cost unit already includes the surcharge; the pack
    // filter computes `amount + gas (+45k iff activation)` identically —
    // assert the shared unit here (the filter itself is covered live by the
    // apply-floor pack/apply parity suites).
    assert_eq!(
        Mempool::tx_cost(&act),
        act.amount + act.gas_limit + PQ_ACTIVATION_SURCHARGE_GAS
    );
    let sk = key();
    let plain = transfer(&sk, [1u8; 32], 7, 8, 0);
    assert_eq!(Mempool::tx_cost(&plain), 7 + 8);
}

// ============================================================================
// F-10 — replay protection; F-11 — static floor honesty
// ============================================================================

/// Same bytes re-admitted → `Duplicate`. Same (sender, nonce), different
/// payload → both pool (documented implicit-RBF coexistence; execution
/// applies the first and skips the other — no explicit rule, pinned here
/// as admission behavior only).
#[test]
fn f10_replay_duplicate_refused_same_nonce_coexists() {
    let sk = key();
    let mut mp = Mempool::new(100, 100);
    let t1 = transfer(&sk, [1u8; 32], 100, 1_000, 0);
    mp.add_checked(t1.clone(), 50_000_000).unwrap();
    assert_eq!(
        mp.add_checked(t1, 50_000_000),
        Err(MempoolError::Duplicate),
        "replay by hash is refused"
    );
    // Same (sender, nonce), different amount → different hash, coexists.
    let t2 = transfer(&sk, [2u8; 32], 200, 1_000, 0);
    mp.add_checked(t2, 50_000_000)
        .expect("replacement coexists in pool");
    assert_eq!(
        mp.len(),
        2,
        "implicit-RBF pair both pooled; execution picks first"
    );
}

/// The floor is static: no clock, no pressure feed, no hidden dynamic term.
/// Same tx + same pool state ⇒ same verdict at any wall-clock; the only
/// additive terms are the explicit base and the explicit D2 penalty.
#[test]
fn f11_floor_is_static_explicit_terms_only() {
    let sk = key();
    let tx = transfer(&sk, [1u8; 32], 10, 600, 0);
    let mp = Mempool::new(100, 100).with_base_fee(600);
    assert_eq!(mp.effective_floor(&tx.from), 600);
    assert_eq!(mp.effective_floor_for_tx(&tx), 600, "no dynamic component");
    // Floor-1 refused, floor admitted: the auction starts exactly at base.
    let mut mp2 = Mempool::new(100, 100).with_base_fee(600);
    assert_eq!(
        mp2.add_checked(transfer(&sk, [1u8; 32], 10, 599, 0), 50_000_000),
        Err(MempoolError::FeeTooLow)
    );
    mp2.add_checked(tx, 50_000_000).expect("at-floor admits");
}

// ============================================================================
// MEV stance (F-08): seal enforced, order detected, vote-gate deferred
// ============================================================================

/// Seal-at-admission binds the exact bytes: match passes; mutating a
/// NON-hashed field (the signature is outside `compute_tx_hash`, inside the
/// sealed bincode) breaks the byte binding → `Mismatch`, which the build
/// drops fail-closed; mutating a HASHED field changes tx identity → no
/// envelope under the new hash → `NotSealed`, the documented
/// availability pass-through for restored pools (checked, never executed
/// blind — and a re-keyed tx still faces admission/balance/nonce gates).
/// Unknown txs are `NotSealed`. Order commitment matches its own build,
/// mismatches on reorder, and is `NoCommit` for blocks this node never
/// built (vote-gate deferred — detection only, warn-and-converge).
#[test]
fn mev_seal_enforced_order_detected_vote_gate_deferred() {
    use stellereum::mev::{MevPreemptionEngine, OrderVerdict, SealVerdict};
    let mut engine = MevPreemptionEngine::new();
    let sk = key();
    let tx = transfer(&sk, [7u8; 32], 5, 500, 0);
    let hash = tx.compute_tx_hash();
    let bytes = bincode::serialize(&tx).unwrap();

    engine.seal_admitted(&hash, &bytes);
    assert_eq!(engine.verify_pool_tx(&tx), SealVerdict::Match);
    // Signature-only mutation: same hash, different sealed bytes → Mismatch.
    let mut resig = tx.clone();
    resig.signature[0] ^= 0xFF;
    assert_eq!(resig.compute_tx_hash(), hash, "sig is outside the tx hash");
    assert_eq!(
        engine.verify_pool_tx(&resig),
        SealVerdict::Mismatch,
        "same-hash mutation must never reach a block (build drops it)"
    );
    // Amount mutation: new identity, no envelope → NotSealed pass-through.
    let mut mutated = tx.clone();
    mutated.amount += 1;
    assert_ne!(mutated.compute_tx_hash(), hash);
    assert_eq!(engine.verify_pool_tx(&mutated), SealVerdict::NotSealed);
    let stranger = transfer(&key(), [7u8; 32], 5, 500, 0);
    assert_eq!(engine.verify_pool_tx(&stranger), SealVerdict::NotSealed);

    // Order commitment: build-time match, reorder mismatch, foreign NoCommit.
    let signer = SigningKey::generate(&mut OsRng);
    let txs = vec![tx.clone(), stranger.clone()];
    engine.commit_block_order(9, [0xBu8; 32], &txs, &[signer]);
    assert_eq!(
        engine.verify_block_order(9, [0xBu8; 32], &txs),
        OrderVerdict::Match
    );
    assert_eq!(
        engine.verify_block_order(9, [0xBu8; 32], &[stranger, tx]),
        OrderVerdict::Mismatch,
        "reorder is DETECTED (warn-and-converge at finalize, vote-gate deferred)"
    );
    assert_eq!(
        engine.verify_block_order(9, [0xCu8; 32], &txs),
        OrderVerdict::NoCommit,
        "blocks this node never built carry no local commitment"
    );
}

// ============================================================================
// mev_v4: parked, default-off, no wiring (product decision)
// ============================================================================

/// The dead engine stays parked: the flag is explicit, default-off for every
/// spelling except exact opt-in, and nothing in the node reads it yet (no
/// wiring by decree — the flag only PERMITS a future gated call site).
#[test]
fn mev_v4_stays_parked_and_default_off() {
    use stellereum::mev_v4::{mev_v4_enabled, MEV_V4_ENV};
    assert_eq!(MEV_V4_ENV, "STELL_MEV_V4");
    let prev = std::env::var(MEV_V4_ENV).ok();
    std::env::remove_var(MEV_V4_ENV);
    assert!(!mev_v4_enabled(), "unset must stay parked");
    for v in ["0", "false", "", "yes", "on", "2"] {
        std::env::set_var(MEV_V4_ENV, v);
        assert!(!mev_v4_enabled(), "spelling {v:?} must stay parked");
    }
    std::env::set_var(MEV_V4_ENV, "1");
    assert!(mev_v4_enabled(), "explicit opt-in reads back on");
    match prev {
        Some(v) => std::env::set_var(MEV_V4_ENV, v),
        None => std::env::remove_var(MEV_V4_ENV),
    }
}

// ============================================================================
// I1 — emission schedule dead by decree, flat reward live
// ============================================================================

/// The schedule divides by N (per-member-every-block semantics): wired
/// per-proposer it would underpay N×, so it stays dead. The live path is
/// the flat 0.317 STELL proposer reward, consistent with the 350M cap the
/// ledger enforces.
#[test]
fn flat_block_reward_is_live_and_schedule_is_dead() {
    use stellereum::staking::REWARDS_EMISSION_CAP;
    use stellereum::tokenomics::{StakingEmissionSchedule, TokenAllocation, BLOCK_REWARD_NANO};
    assert_eq!(
        BLOCK_REWARD_NANO, 317_000_000,
        "flat 0.317 STELL is the live reward"
    );
    let sched = StakingEmissionSchedule::default();
    assert_eq!(
        sched.calculate_block_reward(3),
        BLOCK_REWARD_NANO / 3,
        "schedule pays 0.317/N — N× underpay per-proposer, must never be wired there"
    );
    assert_eq!(sched.calculate_block_reward(0), 0);
    assert_eq!(
        TokenAllocation::default().validator_rewards,
        REWARDS_EMISSION_CAP,
        "allocation and ledger cap agree on the 350M ceiling"
    );
    // Cap horizon sanity at the live flat rate (200 ms tokenomics clock).
    let blocks = REWARDS_EMISSION_CAP / BLOCK_REWARD_NANO;
    assert!(
        blocks > 1_000_000_000,
        "cap must span >1B blocks at flat rate"
    );
}
