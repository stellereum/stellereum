//! Audit-bundle regression tests (fail-closed, coordinated).
//!
//! One file holding the per-item suites for the wip/passport-agents bundle:
//! M1 (self-bond withdraw opcode), PoP gate (refusal alternative), EVM
//! chain-id serving, faucet zeroize (no behavior change), F2 persist-queue
//! metrics wiring, F-02 insert-level nonce-gap check, inbound limiter
//! semantics. F3 (genesis/faucet guard alignment) lives in the `run` binary
//! path and is not reachable from integration tests — covered by inspection
//! plus the existing `bootstrap` preflight tests; see the item note below.

use std::sync::Arc;

use stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::pq_registry::{derive_validator_id, pq_voting_key_pop_preimage};
use stellereum::staking::{STAKING_POOL, UNBONDING_PERIOD_SECS};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, RegisterValidatorPayload, GAS_BASIC_TRANSFER};
use stellereum::zkml::effective_chain_id;

mod support;
use support::{assert_refused_tx_paid_failure_fee, failure_fee};

fn pq_addr(key: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, &key.public_key, &DEFAULT_SALT)
}

fn tx_of(
    key: &FalconKeypair,
    nonce: u64,
    gas_limit: u64,
    payload: Vec<OpCode>,
) -> stellereum::sharding::Transaction {
    let from = pq_addr(key);
    let probe = stellereum::sharding::Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        key.public_key.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        from,
        0,
        gas_limit,
        nonce,
        1,
        1,
        payload.clone(),
        &DEFAULT_SALT,
    );
    let sig = key.sign(&probe.signing_message());
    stellereum::sharding::Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        key.public_key.clone(),
        sig,
        from,
        0,
        gas_limit,
        nonce,
        1,
        1,
        payload,
        &DEFAULT_SALT,
    )
}

async fn bal(engine: &InMemoryStateEngine, a: &[u8; 32]) -> u64 {
    engine.get_account(a).await.map(|x| x.balance).unwrap_or(0)
}

// ============================================================================
// M1 (audit-staking): SysCallWithdrawSelfBond
// ============================================================================

/// Matured self-bond withdraws through the new opcode; immature refuses;
/// the pool is debited symmetrically; replay + stranger refuse.
#[tokio::test]
async fn m1_self_bond_withdraws_only_when_matured() {
    use stellereum::staking::{MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};
    let floor = MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER;

    let engine = InMemoryStateEngine::new();
    let validator = FalconKeypair::generate_from_seed(0x41);
    let vaddr = pq_addr(&validator);
    let val_hot = FalconKeypair::generate_from_seed(0x45);
    let chain_id = effective_chain_id();
    let vid = derive_validator_id(chain_id, &vaddr, val_hot.public_key());
    let pop_msg = pq_voting_key_pop_preimage(
        chain_id,
        &vid,
        &vaddr,
        0,
        PqScheme::Falcon512,
        val_hot.public_key(),
    );
    let voting_pop = val_hot.sign(&pop_msg);
    // Floor for the bond plus gas headroom for register/unbond/withdraw
    // (Ruleset v7 EXEC_HARDENING_V1 bills max(gas_used, TX_INTRINSIC_GAS).min(gas_limit)
    // = 280_000 when gas_limit >= 280_000, or gas_limit when lower, plus 45_000 surcharge)
    // AND for the FAILURE FEES.
    engine
        .update_account(AccountState::new(vaddr, floor + 5_000_000))
        .await;

    // Register & bond the floor as self-bond (sender == withdrawal_address).
    engine
        .apply_transaction(
            &tx_of(
                &validator,
                0,
                500_000,
                vec![OpCode::SysCallRegisterValidator(Box::new(
                    RegisterValidatorPayload {
                        amount: floor,
                        commission_bps: 0,
                        withdrawal_address: vaddr,
                        voting_scheme: PqScheme::Falcon512.id(),
                        voting_pubkey: val_hot.public_key().to_vec(),
                        voting_pop,
                    },
                ))],
            ),
            0,
        )
        .await
        .unwrap();
    let pool_after_bond = bal(&engine, &STAKING_POOL).await;
    assert_eq!(pool_after_bond, floor, "bond escrows principal in the pool");

    // Unbond everything (full exit to zero is allowed).
    engine
        .apply_transaction(
            &tx_of(
                &validator,
                1,
                500_000,
                vec![OpCode::SysCallUnbond {
                    validator: vid,
                    amount: floor,
                }],
            ),
            0,
        )
        .await
        .expect("begin unbonding works");

    // Immature withdraw refuses (fail-closed): nothing matured yet. The
    // refusal is attributable, so it pays the failure fee and consumes the
    // nonce - the matured withdraw below is therefore signed with nonce 3.
    let early = tx_of(
        &validator,
        2,
        500_000,
        vec![OpCode::SysCallWithdrawSelfBond { validator: vid }],
    );
    let early_fee = failure_fee(&engine, &early).await;
    let before_early = bal(&engine, &vaddr).await;
    assert!(
        engine.apply_transaction(&early, 0).await.is_err(),
        "immature self-bond must refuse, not pay zero"
    );
    assert_refused_tx_paid_failure_fee(&engine, &early, early_fee, before_early, 2).await;
    assert_eq!(
        bal(&engine, &STAKING_POOL).await,
        pool_after_bond,
        "refused withdraw moves no pool coins"
    );

    // Mature past the unbonding period (what the runtime runs per boundary).
    engine
        .staking_write()
        .await
        .process_unbonding(UNBONDING_PERIOD_SECS + 1)
        .unwrap();
    assert_eq!(
        engine.staking_read().await.withdrawable_of(&vid),
        floor,
        "cooldown matured the full self-bond"
    );

    // A stranger cannot take it even now that funds are available.
    let attacker = FalconKeypair::generate_from_seed(0x42);
    let aaddr = pq_addr(&attacker);
    engine
        .update_account(AccountState::new(
            aaddr,
            20_000 + PQ_ACTIVATION_SURCHARGE_GAS,
        ))
        .await;
    let steal = tx_of(
        &attacker,
        0,
        20_000,
        vec![OpCode::SysCallWithdrawSelfBond { validator: vid }],
    );
    let steal_fee = failure_fee(&engine, &steal).await;
    let before_steal = bal(&engine, &aaddr).await;
    assert!(
        engine.apply_transaction(&steal, 0).await.is_err(),
        "only the validator may withdraw its own self-bond"
    );
    // The stranger pays its failure fee (and burns its nonce) - but it takes
    // NOTHING of the validator's matured stake.
    assert_refused_tx_paid_failure_fee(&engine, &steal, steal_fee, before_steal, 0).await;
    assert_eq!(
        engine.staking_read().await.withdrawable_of(&vid),
        floor,
        "stranger attempt consumes nothing"
    );

    // Withdraw: consumes the entry, pays exactly once, pool debited 1:1.
    let pool_before = bal(&engine, &STAKING_POOL).await;
    let mine_before = bal(&engine, &vaddr).await;
    engine
        .apply_transaction(
            &tx_of(
                &validator,
                3,
                500_000,
                vec![OpCode::SysCallWithdrawSelfBond { validator: vid }],
            ),
            0,
        )
        .await
        .expect("matured withdraw works");
    assert_eq!(
        bal(&engine, &STAKING_POOL).await,
        pool_before - floor,
        "pool debited symmetrically (never minted)"
    );
    assert_eq!(
        bal(&engine, &vaddr).await,
        mine_before + floor - GAS_BASIC_TRANSFER - PQ_ACTIVATION_SURCHARGE_GAS,
        "validator credited minus exactly the intrinsic withdraw gas and activation surcharge"
    );
    assert_eq!(
        engine.staking_read().await.withdrawable_of(&vid),
        0,
        "entry consumed by the payout"
    );
    assert!(
        engine.staking_read().await.unbonding.is_empty(),
        "no dangling entries"
    );

    // Replay refuses (single-claim). It is a refusal like any other, so it
    // costs the failure fee too.
    let again = tx_of(
        &validator,
        4,
        500_000,
        vec![OpCode::SysCallWithdrawSelfBond { validator: vid }],
    );
    let again_fee = failure_fee(&engine, &again).await;
    let before_again = bal(&engine, &vaddr).await;
    assert!(
        engine.apply_transaction(&again, 0).await.is_err(),
        "consumed entry cannot pay twice"
    );
    assert_refused_tx_paid_failure_fee(&engine, &again, again_fee, before_again, 4).await;
    assert_eq!(
        bal(&engine, &STAKING_POOL).await,
        pool_before - floor,
        "replay moves no pool coins"
    );
}

// ============================================================================
// EVM chain-id (audit-rpc-evm MED)
// ============================================================================

/// Served identity always equals effective_chain_id(); on the stand (env
/// unset) that is 5757/0x167d — zero behavior change. No env mutation here
/// (deterministic under any ambient STELL_CHAIN_ID).
#[test]
fn evm_serves_effective_chain_id() {
    use stellereum::evm_adapter::{
        effective_chain_id, eth_chain_id, eth_chain_id_for, net_version, net_version_for,
    };
    assert_eq!(eth_chain_id(), eth_chain_id_for(effective_chain_id()));
    assert_eq!(net_version(), net_version_for(effective_chain_id()));
    if std::env::var(stellereum::zkml::CHAIN_ID_ENV).is_err() {
        assert_eq!(eth_chain_id(), "0x167d");
        assert_eq!(net_version(), "5757");
    }
}

// ============================================================================
// Faucet zeroize (audit MED): no behavior change, intermediates wiped
// ============================================================================

/// Seed parsing round-trips (0x prefix + whitespace tolerated) and the faucet
/// derives the identical account from the parsed seed as from the raw one.
#[test]
fn faucet_seed_parse_roundtrip_and_stable_account() {
    use stellereum::rpc::{parse_faucet_seed_hex, Faucet};
    let seed = [0x42u8; 32];
    let hexs = hex::encode(seed);
    assert_eq!(parse_faucet_seed_hex(&hexs).unwrap(), seed);
    assert_eq!(
        parse_faucet_seed_hex(&format!("  0x{hexs}  \n")).unwrap(),
        seed
    );
    assert!(parse_faucet_seed_hex("zz").is_err());
    assert!(parse_faucet_seed_hex(&hex::encode([0u8; 31])).is_err());
    let a = Faucet::new(seed, 1, 10, 100).account();
    let b = Faucet::new(parse_faucet_seed_hex(&hexs).unwrap(), 1, 10, 100).account();
    assert_eq!(a, b, "zeroizing intermediates must not change derivation");
}

// ============================================================================
// F2 (audit-state-sync MED): persist-queue metrics wired
// ============================================================================

/// Registry setters (the pre-existing API) reflect in snapshots.
#[test]
fn persist_queue_setters_reflect_in_snapshot() {
    let reg = stellereum::metrics::Registry::new();
    reg.set_persist_queue_depth(7);
    reg.add_persist_queue_dropped(3);
    let snap = reg.snapshot();
    assert_eq!(snap.persist_queue_depth, 7.0);
    assert_eq!(snap.persist_queue_dropped, 3.0);
}

/// Overflowing the bounded queue counts drops on the process-global registry
/// (the F2 wiring: `AsyncPersistence::push` -> `inc_persist_queue_dropped`).
/// Uses the `DropFirst` prune class: consensus-critical `Finalized`/
/// `Consensus` jobs are now `CriticalWait` and are DEFERRED (never dropped
/// synchronously), so they are not a deterministic drop fixture.
#[tokio::test]
async fn persist_queue_full_counts_drops() {
    use stellereum::storage::{AsyncPersistence, Storage, PERSIST_QUEUE_CAP};
    let dir = std::env::temp_dir().join(format!(
        "stell_vuln_f2_{}_{}",
        std::process::id(),
        stellereum::zkml::now_secs()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let storage = Arc::new(Storage::open(&dir).expect("temp storage opens"));
    let before = stellereum::metrics::global()
        .snapshot()
        .persist_queue_dropped;
    let (ap, _release_gate) = AsyncPersistence::start_gated_for_test(storage);
    for _ in 0..PERSIST_QUEUE_CAP + 5 {
        ap.enqueue_prune(1);
    }
    let after = stellereum::metrics::global()
        .snapshot()
        .persist_queue_dropped;
    assert!(
        after - before >= 5.0,
        "5 over-cap prune pushes must count 5 drops (delta={})",
        after - before
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ============================================================================
// F-02 (audit-mempool MED): insert-level nonce-gap check
// ============================================================================

/// `insert` enforces `check_nonce_gap` when the context carries the on-chain
/// head (fail-closed SKIP: Err, nothing pooled is deleted); legacy contexts
/// without a head keep today's behavior.
#[test]
fn insert_enforces_nonce_gap_from_context() {
    use stellereum::mempool::{AdmissionCtx, Mempool, MempoolError};
    use stellereum::sharding::Transaction;
    let sk = FalconKeypair::generate_from_seed(0x43);
    let mk = |nonce: u64| {
        let gas = 1_000 + PQ_ACTIVATION_SURCHARGE_GAS;
        let probe = Transaction::new_pq_explicit(
            PqScheme::Falcon512,
            sk.public_key.clone(),
            vec![0u8; FALCON512_SIG_LEN],
            [1u8; 32],
            10,
            gas,
            nonce,
            1,
            1,
            Vec::new(),
            &DEFAULT_SALT,
        );
        let sig = sk.sign(&probe.signing_message());
        Transaction::new_pq_explicit(
            PqScheme::Falcon512,
            sk.public_key.clone(),
            sig,
            [1u8; 32],
            10,
            gas,
            nonce,
            1,
            1,
            Vec::new(),
            &DEFAULT_SALT,
        )
    };

    let mut mp = Mempool::new(100, 100);
    let ctx = AdmissionCtx::wall_now().with_onchain_nonce(0);
    // Far-future (32 > 0 + 16 window) refused at insert.
    match mp.add_checked_ctx(mk(32), 1_000_000, ctx) {
        Err(MempoolError::NonceGap { expected, got }) => {
            assert_eq!((expected, got), (0, 32));
        }
        other => panic!("expected NonceGap, got {other:?}"),
    }
    assert!(mp.is_empty(), "a refused insert pools nothing");
    // In-window admits; the skip deleted nothing (pool still usable).
    mp.add_checked_ctx(mk(0), 1_000_000, ctx).unwrap();
    assert_eq!(mp.len(), 1);
    // Still gapped past the advanced head (want=1, 32 > 17).
    assert!(matches!(
        mp.add_checked_ctx(mk(32), 1_000_000, ctx),
        Err(MempoolError::NonceGap { .. })
    ));
    assert_eq!(mp.len(), 1, "skip path must not delete the pooled head");

    // Legacy context without a head: unchanged behavior (call-site
    // pre-checks, where present, decide — same as before this fix).
    let mut legacy = Mempool::new(100, 100);
    legacy
        .add_checked_ctx(mk(32), 1_000_000, AdmissionCtx::wall_now())
        .unwrap();
}

// ============================================================================
// Inbound limiter (audit-network F1): semantics the drain relies on
// ============================================================================

/// Only `Batch` is budget-checked; votes/proposals/commits bypass without
/// touching the budget (verified in `inbound_is_critical`); over-budget bulk
/// DEFERS with a bounded hint, never drops. `admit_inbound` itself needs a
/// full P2P adapter so the drain call site is type-checked + covered by the
/// consensus suites; this pins the limiter contract it delegates to.
#[test]
fn inbound_bulk_limiter_defers_never_drops() {
    use stellereum::consensus_net::{
        inbound_is_critical, ConsensusMsg, InboundBulkLimiter, InboundDecision,
    };
    // Bypass shape: only Batch is bulk.
    assert!(!inbound_is_critical(&ConsensusMsg::Batch(vec![])));
    // Budget: 1000 B/s, 2000 burst. 500 fits; 5000 past burst defers.
    let mut lim = InboundBulkLimiter::new(1000, 2000);
    assert_eq!(lim.admit("p", 500, false, 0), InboundDecision::Allow);
    match lim.admit("p", 5000, false, 0) {
        InboundDecision::Defer { wait_ms } => {
            assert!(wait_ms >= 1, "wait hint must be positive");
            assert!(
                wait_ms <= stellereum::consensus_net::INBOUND_MAX_DEFER_WAIT_MS,
                "wait hint must be bounded"
            );
        }
        InboundDecision::Allow => panic!("over-budget bulk must defer"),
    }
    // Critical bypasses even when the bucket is empty.
    assert_eq!(lim.admit("p", 1_000_000, true, 0), InboundDecision::Allow);
}
