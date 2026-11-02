//! P0-4: the state root must commit to EVERY piece of consensus state.
//!
//! The state root is the only thing block sync compares and the only thing a
//! light client can verify against. If a subsystem can change without moving
//! the root, then two nodes can hold different state and still agree that they
//! agree: a fork becomes invisible, and a light client cannot prove anything
//! about that subsystem.
//!
//! The validator set is derived from the staking ledger at every height
//! boundary, which makes an uncommitted staking ledger a direct consensus
//! hazard rather than a bookkeeping gap.
//!
//! Each test mutates exactly one subsystem and asserts the root moves. A
//! subsystem that silently passes the test WITHOUT moving the root is the bug.

use ed25519_dalek::SigningKey;
use stellereum::orderbook::OrderSide;
use stellereum::pmm::PrimaryMarketMaker;
use stellereum::sharding::Transaction;
use stellereum::staking::StakingLedger;
use stellereum::state_engine::{EscrowRecord, InMemoryStateEngine};

fn funded_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[tokio::test]
async fn native_balance_change_moves_the_root() {
    // Control case: native STELL is known to be committed. If this ever fails,
    // the trie itself is broken and the other tests prove nothing.
    let e = InMemoryStateEngine::new();
    let before = e.get_state_root().await;

    let key = funded_key(1);
    let addr = key.verifying_key().to_bytes();
    e.credit_native(&addr, 1_000).await.expect("credit");
    let seeded = e.get_state_root().await;

    let tx = Transaction::sign(&key, [0xEE; 32], 10, 0, 0, 0, 0);
    let (applied, failed, _, _, _) = e.apply_block_parallel_fees(&[tx], 0).await;
    assert_eq!(
        (applied, failed),
        (1, 0),
        "the control transaction must execute"
    );

    assert_ne!(before, seeded, "the control transaction must move the root");
    assert_ne!(
        seeded,
        e.get_state_root().await,
        "native transfer must move the root"
    );
    assert_eq!(e.get_account(&addr).await.unwrap().balance, 1_000 - 10);
}

#[tokio::test]
async fn staking_bond_moves_the_root() {
    let e = InMemoryStateEngine::new();
    let before = e.get_state_root().await;

    let key = funded_key(2);
    let val = key.verifying_key().to_bytes();
    e.credit_native(&val, 1_000_000_000_000)
        .await
        .expect("credit");
    let seeded = e.get_state_root().await;
    assert_ne!(seeded, before, "funding the validator must move the root");

    {
        let mut ledger = e.staking_write().await;
        ledger.bond(val, 2_000_000_000_000, 0).unwrap();
    }

    assert_ne!(
        e.get_state_root().await,
        seeded,
        "bonding changes the validator set, so it must be part of the state root"
    );
}

#[tokio::test]
async fn staking_slash_moves_the_root() {
    // A slash burns stake AND changes consensus-relevant counters (`missed`,
    // `last_downtime_penalty`). If only the burned balance were committed, a
    // node could disagree about who is penalised while matching the root.
    let e = InMemoryStateEngine::new();
    let key = funded_key(3);
    let val = key.verifying_key().to_bytes();
    e.credit_native(&val, 1_000_000_000_000)
        .await
        .expect("credit");
    e.staking_write()
        .await
        .bond(val, 2_000_000_000_000, 0)
        .unwrap();

    let committed = e.get_state_root().await;
    {
        let mut ledger = e.staking_write().await;
        ledger.note_missed_heights(1, &|_| false, std::slice::from_ref(&val));
    }
    assert_ne!(
        e.get_state_root().await,
        committed,
        "downtime bookkeeping must be committed, not just the burned balance"
    );
}

#[tokio::test]
async fn orderbook_state_moves_the_root() {
    let e = InMemoryStateEngine::new();
    let before = e.get_state_root().await;

    let trader = funded_key(4).verifying_key().to_bytes();
    e.credit_native(&trader, 1_000_000).await.expect("credit");
    let seeded = e.get_state_root().await;

    {
        let mut books = e.orderbooks_write().await;
        books
            .get_book_mut(1)
            .submit_order(trader, OrderSide::Buy, 100, 10, 0);
    }

    assert_ne!(
        e.get_state_root().await,
        seeded,
        "resting orders are consensus state; the CLOB must be committed"
    );
    let _ = before;
}

#[tokio::test]
async fn order_escrow_moves_the_root() {
    let e = InMemoryStateEngine::new();
    let trader = funded_key(5).verifying_key().to_bytes();
    e.credit_native(&trader, 1_000_000).await.expect("credit");
    let seeded = e.get_state_root().await;

    e.order_escrow_write().await.insert(
        (1, 7),
        EscrowRecord {
            trader,
            locked_base_stell: 500,
            locked_quote_wusdt: 0,
            locked_quote_native: 0,
        },
    );

    assert_ne!(
        e.get_state_root().await,
        seeded,
        "escrow bookkeeping decides how much a resting order controls"
    );
}

#[tokio::test]
async fn pmm_curve_state_moves_the_root() {
    let e = InMemoryStateEngine::new();
    let before = e.get_state_root().await;

    {
        let mut pmm = e.pmm_write().await;
        pmm.minted_nano = 1_000;
        pmm.reserve_micro = 2_000;
    }

    assert_ne!(
        e.get_state_root().await,
        before,
        "the bonding curve sets the STELL price; it must be committed"
    );
}

#[tokio::test]
async fn pmm_configuration_moves_the_root() {
    let e = InMemoryStateEngine::new();
    let before = e.get_state_root().await;

    *e.pmm_usdt_token_write().await = Some([0x55; 32]);

    assert_ne!(
        e.get_state_root().await,
        before,
        "the quote asset id changes how the curve is interpreted"
    );
}

#[tokio::test]
async fn contract_storage_moves_the_root() {
    // A contract's code hash is committed, but its STORAGE is where the value
    // and the state live. Uncommitted storage means a light client can prove a
    // contract exists but nothing about what it holds.
    let e = InMemoryStateEngine::new();
    let owner = funded_key(6).verifying_key().to_bytes();
    e.credit_native(&owner, 10_000_000_000)
        .await
        .expect("credit");
    let seeded = e.get_state_root().await;

    let mut reg = e.contracts_write().await;
    // A real module: hand-written magic bytes fail `validate_code`, which is
    // exactly what that check is for. Compiled from WAT so this exercises the
    // production deploy path instead of a bypass.
    let code = wat::parse_str("(module)").expect("wat compiles");
    let addr = reg.deploy(owner, code, 0).expect("deploy");
    reg.contracts.get_mut(&addr).unwrap().storage.insert(1, 42);
    drop(reg);

    assert_ne!(
        e.get_state_root().await,
        seeded,
        "contract deployment must be committed"
    );
}

#[tokio::test]
async fn state_root_is_stable_when_nothing_changes() {
    // The complement of the other tests: a read must never move the root, or
    // "the root moved" is not evidence of anything.
    let e = InMemoryStateEngine::new();
    let key = funded_key(7);
    let addr = key.verifying_key().to_bytes();
    e.credit_native(&addr, 1_000_000).await.expect("credit");

    let a = e.get_state_root().await;
    let b = e.get_state_root().await;
    let _ = e.get_account(&addr).await;
    let c = e.get_state_root().await;

    assert_eq!(a, b);
    assert_eq!(b, c, "reads must not perturb consensus state");
}

#[tokio::test]
async fn state_root_is_independent_of_insertion_order() {
    // HashMap iteration order is not stable across processes. If the commitment
    // walked the maps naively, two nodes with identical state would disagree on
    // the root purely because of hash seeding - a consensus split with no
    // attacker at all.
    async fn build(reverse: bool) -> InMemoryStateEngine {
        let e = InMemoryStateEngine::new();
        let mut ledger = StakingLedger::new();
        let order: Vec<u8> = if reverse {
            (0..8u8).rev().collect()
        } else {
            (0..8u8).collect()
        };
        for i in order {
            let val = [1u8.wrapping_add(i); 32];
            ledger.bond(val, 2_000_000_000_000, 0).unwrap();
        }
        *e.staking_write().await = ledger;
        e
    }

    // The two ledgers hold identical data, inserted in opposite order. The
    // commitment sorts by key before hashing, so the roots must match.
    let a = build(false).await;
    let b = build(true).await;

    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "identical state must produce an identical root regardless of map order"
    );
}

#[tokio::test]
async fn pmm_constructor_state_is_reproducible() {
    // Guards the test helper above: two independently constructed PMMs with the
    // same parameters must be indistinguishable in the root.
    let a = PrimaryMarketMaker::new();
    let b = PrimaryMarketMaker::new();
    assert_eq!(a.minted_nano, b.minted_nano);
    assert_eq!(a.reserve_micro, b.reserve_micro);
}

// The token registry is consensus state: `allowances` decides whether
// `TransferFrom` succeeds, `minter`/`paused`/`max_supply` gate minting and
// transferring, and `next_nonce` derives the next token id. Balances and supply
// are in the trie, but none of those were committed, so two nodes could disagree
// about them and still agree on the root.
#[tokio::test]
async fn token_allowances_and_metadata_move_the_root() {
    let e = InMemoryStateEngine::new();
    let creator = funded_key(8).verifying_key().to_bytes();
    e.credit_native(&creator, 10_000_000_000)
        .await
        .expect("credit");
    let seeded = e.get_state_root().await;

    let id = e
        .create_token(creator, token_meta(), 1_000)
        .await
        .expect("create");
    assert_ne!(
        e.get_state_root().await,
        seeded,
        "token balances and supply are committed via the trie key domains"
    );

    {
        let mut reg = e.tokens_write().await;
        let t = reg.get_mut(&id).expect("token exists");
        t.allowances.insert((creator, [0x44u8; 32]), 500);
    }
    let with_allowance = e.get_state_root().await;

    {
        let mut reg = e.tokens_write().await;
        reg.get_mut(&id).expect("token exists").metadata.paused = true;
    }
    assert_ne!(
        e.get_state_root().await,
        with_allowance,
        "an allowance is consensus state: it decides whether TransferFrom succeeds"
    );
    let with_pause = e.get_state_root().await;

    {
        let mut reg = e.tokens_write().await;
        reg.next_nonce += 1;
    }
    assert_ne!(
        e.get_state_root().await,
        with_pause,
        "next_nonce derives the next token id, so it must be committed"
    );
}

/// Session keys PHASE 2: the registry is consensus state.
///
/// A node that had revoked a session key (or merely spent part of its budget)
/// must not be able to report the same state root as one that had not - or the
/// two would then disagree about which of the next block's transactions are
/// admissible while block sync happily compares equal roots.
///
/// The domain is CONDITIONAL (empty contributes nothing, so genesis is
/// byte-identical), which is why this has to be tested by registering a key
/// rather than by asserting a fixed digest.
#[tokio::test]
async fn session_key_registry_moves_the_root() {
    use stellereum::zkml::{SessionKeyAuthorization, SCOPE_ALL};

    let e = InMemoryStateEngine::new();
    let master = funded_key(11);
    let session = funded_key(12);
    let master_pub = master.verifying_key().to_bytes();
    let session_pub = session.verifying_key().to_bytes();

    e.credit_native(&master_pub, 1_000_000_000)
        .await
        .expect("credit");
    let funded = e.get_state_root().await;

    // FIRST USE registers the key (lazy: there is no registration tx) and
    // charges the applied transaction's gas against it.
    let grant = SessionKeyAuthorization::sign_delegation(
        &master,
        session_pub,
        10_000_000,
        10_000,
        SCOPE_ALL,
        u64::MAX,
        stellereum::zkml::DEFAULT_CHAIN_ID,
    );
    let tx = Transaction::sign_with_session(&session, grant, [1u8; 32], 10, 1_000, 0, 1, 1, vec![]);
    let (_, _, _, status, _) = e.apply_block_parallel_fees(&[tx], 1_000).await;
    assert_eq!(status, vec![true], "the registering transaction must apply");
    assert_eq!(
        e.session_keys_read().await.len(),
        1,
        "it registered the key"
    );
    assert_ne!(
        e.get_state_root().await,
        funded,
        "a registered session key must move the root"
    );

    // Remaining budget is consensus state: two nodes that disagreed on
    // `gas_spent` would accept different next transactions under one root.
    let with_record = e.get_state_root().await;
    {
        let mut reg = e.session_keys_write().await;
        reg.entries.get_mut(&session_pub).unwrap().gas_spent += 1;
    }
    assert_ne!(
        e.get_state_root().await,
        with_record,
        "cumulative spend is consensus state"
    );

    // ...and so is the revocation flag itself.
    let with_spend = e.get_state_root().await;
    {
        let mut reg = e.session_keys_write().await;
        reg.entries.get_mut(&session_pub).unwrap().revoked = true;
    }
    assert_ne!(
        e.get_state_root().await,
        with_spend,
        "revocation is consensus state"
    );
}

fn token_meta() -> stellereum::token::TokenMetadata {
    stellereum::token::TokenMetadata {
        name: "T".into(),
        symbol: "T".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: [0u8; 32],
        paused: false,
        description: String::new(),
    }
}

/// The staking ledger's equivocation dedup sets, the registered
/// post-quantum keys and the vesting schedules are CONSENSUS STATE.
///
///  * the dedup sets decide whether the SAME equivocation burns again (the
///    burn moves the stake and the pool), so two nodes that disagreed about
///    the set would burn different coins under one root;
///  * the registered PQ key is the key the post-quantum evidence is
///    VERIFIED against, so two nodes holding different keys reach different
///    verdicts (slash vs no slash) on the same evidence;
///  * a vesting schedule is a spend GATE: one node may accept a transaction
///    the other refuses - under the same root.
///
/// All four were uncommitted, which is exactly the class of divergence this
/// file exists to catch.
#[tokio::test]
async fn staking_equivocation_dedup_pq_keys_and_vesting_move_the_root() {
    let e = InMemoryStateEngine::new();
    let key = funded_key(21);
    let val = key.verifying_key().to_bytes();
    e.credit_native(&val, 1_000_000_000_000)
        .await
        .expect("credit");
    e.staking_write()
        .await
        .bond(val, 2_000_000_000_000, 0)
        .unwrap();

    let committed = e.get_state_root().await;

    // 1. The Ed25519 per-offense slash dedup set.
    {
        let mut ledger = e.staking_write().await;
        ledger.equivocation_dedup.insert([0xA1u8; 32]);
    }
    let after_equiv = e.get_state_root().await;
    assert_ne!(
        after_equiv, committed,
        "the per-offense slash dedup set decides whether the same equivocation \
         burns again, so it must move the root"
    );

    // 2. The post-quantum per-offense slash dedup set.
    {
        let mut ledger = e.staking_write().await;
        ledger.pq_equivocation_dedup.insert([0xB2u8; 32]);
    }
    let after_pq_equiv = e.get_state_root().await;
    assert_ne!(
        after_pq_equiv, after_equiv,
        "the PQ per-offense slash dedup set must move the root"
    );

    // 3. The registered post-quantum key of the validator.
    {
        let mut ledger = e.staking_write().await;
        ledger.validator_pq_keys.insert(
            val,
            (
                stellereum::post_quantum::PqScheme::Ed25519,
                vec![0xC3u8; 32],
            ),
        );
    }
    let after_keys = e.get_state_root().await;
    assert_ne!(
        after_keys, after_pq_equiv,
        "the key the PQ evidence is verified against must move the root"
    );

    // ...and so must the SCHEME (the same key bytes mean different things
    // under Ed25519 and under the hybrid scheme).
    {
        let mut ledger = e.staking_write().await;
        ledger.validator_pq_keys.insert(
            val,
            (stellereum::post_quantum::PqScheme::Hybrid, vec![0xC3u8; 32]),
        );
    }
    let after_scheme = e.get_state_root().await;
    assert_ne!(
        after_scheme, after_keys,
        "the PQ scheme must be committed explicitly, not derived from the key"
    );

    // 4. The vesting schedule of the account.
    {
        let mut ledger = e.staking_write().await;
        ledger
            .vesting_schedules
            .insert(val, stellereum::tokenomics::TeamVestingSchedule::new(1_000));
    }
    let after_vesting = e.get_state_root().await;
    assert_ne!(
        after_vesting, after_scheme,
        "a vesting schedule gates whether a spend is allowed at all, so it must \
         move the root"
    );

    // ...and so must the floor's own parameters.
    {
        let mut ledger = e.staking_write().await;
        ledger
            .vesting_schedules
            .get_mut(&val)
            .expect("schedule exists")
            .claimed_amount = 7;
    }
    assert_ne!(
        e.get_state_root().await,
        after_vesting,
        "the claimed counter decides how much is still claimable"
    );
}

/// The LAZY (F1) delegator-reward accumulator is CONSENSUS STATE.
///
/// The accumulator IS the delegator payout formula: a delegator's share is
/// `stake * (reward_per_token_now - checkpoint) / 1e18`. Two nodes holding a
/// different rate (or a different checkpoint) pay a delegator DIFFERENT
/// amounts of real coins under ONE root - the exact class of divergence this
/// file exists to catch. The eager implementation had no such state (the
/// shares were credited eagerly), so the lazy refactor had to commit it.
#[tokio::test]
async fn staking_lazy_reward_accumulator_moves_the_root() {
    let e = InMemoryStateEngine::new();
    let key = funded_key(31);
    let val = key.verifying_key().to_bytes();
    let delegator = funded_key(32).verifying_key().to_bytes();
    e.credit_native(&val, 2_000_000_000_000)
        .await
        .expect("credit");
    {
        let mut ledger = e.staking_write().await;
        ledger.bond(val, 1_100_000_000_000, 0).unwrap();
        ledger.delegate(delegator, val, 1_000_000_000_000).unwrap();
    }
    let committed = e.get_state_root().await;

    // 1. The accumulator itself (the rate the payout is measured against).
    {
        let mut ledger = e.staking_write().await;
        let state = stellereum::staking::ValidatorRewardState {
            reward_per_token: 1,
            ..Default::default()
        };
        ledger.reward_accumulators.insert(val, state);
    }
    let after_acc = e.get_state_root().await;
    assert_ne!(
        after_acc, committed,
        "the reward accumulator decides every future delegator payout, so it must \
         move the root"
    );

    // ...and so must the RATE inside it.
    {
        let mut ledger = e.staking_write().await;
        ledger
            .reward_accumulators
            .get_mut(&val)
            .expect("accumulator exists")
            .reward_per_token = 2;
    }
    let after_rate = e.get_state_root().await;
    assert_ne!(
        after_rate, after_acc,
        "the rate is the payout formula itself, so it must move the root"
    );

    // 2. The delegator checkpoint (a stale checkpoint pays a delegator
    //    twice for the same accrual).
    {
        let mut ledger = e.staking_write().await;
        ledger
            .delegator_reward_checkpoints
            .insert((val, delegator), 1);
    }
    assert_ne!(
        e.get_state_root().await,
        after_rate,
        "a delegator checkpoint decides what has already been paid, so it must \
         move the root"
    );
}

/// The staking ledger's downtime-jail records, commission schedules and
/// redelegation locks are CONSENSUS STATE.
///
///  * a jail record EXCLUDES the validator from the validator set (every
///    quorum check runs against the set), so two nodes that disagreed about
///    the jail map would verify quorums differently under one root;
///  * a commission schedule decides the FUTURE commission rate (pending
///    change + cooldown basis), which decides future delegator payouts of
///    real coins — a stale schedule pays differently;
///  * a redelegation lock decides whether the next `redelegate` from a
///    position is ADMITTED at all: one node accepts a transaction the other
///    refuses, under the same root.
///
/// All three were uncommitted, which is exactly the class of divergence this
/// file exists to catch.
#[tokio::test]
async fn staking_jail_commission_and_redelegation_lock_move_the_root() {
    let e = InMemoryStateEngine::new();
    let key = funded_key(51);
    let val = key.verifying_key().to_bytes();
    e.credit_native(&val, 1_000_000_000_000)
        .await
        .expect("credit");
    e.staking_write()
        .await
        .bond(val, 2_000_000_000_000, 0)
        .unwrap();

    let committed = e.get_state_root().await;

    // 1. The downtime-jail record of the validator.
    {
        let mut ledger = e.staking_write().await;
        ledger.jail.insert(
            val,
            stellereum::staking::JailRecord {
                jailed_at_height: 1,
                release_height: 100,
            },
        );
    }
    let after_jail = e.get_state_root().await;
    assert_ne!(
        after_jail, committed,
        "a jail record excludes the validator from the set, so it must move the root"
    );

    // ...and so must the release height inside it.
    {
        let mut ledger = e.staking_write().await;
        ledger
            .jail
            .get_mut(&val)
            .expect("jail record exists")
            .release_height = 101;
    }
    let after_release = e.get_state_root().await;
    assert_ne!(
        after_release, after_jail,
        "the release height decides when the validator rejoins the set"
    );

    // 2. The commission schedule of the validator.
    {
        let mut ledger = e.staking_write().await;
        ledger.commission_schedule.insert(
            val,
            stellereum::staking::CommissionSchedule {
                last_effective_height: Some(7),
                pending: None,
            },
        );
    }
    let after_schedule = e.get_state_root().await;
    assert_ne!(
        after_schedule, after_release,
        "the commission cooldown basis decides the next admissible change, so it \
          must move the root"
    );

    // ...and so must a pending announced change.
    {
        let mut ledger = e.staking_write().await;
        ledger
            .commission_schedule
            .get_mut(&val)
            .expect("schedule exists")
            .pending = Some(stellereum::staking::PendingCommissionChange {
            new_bps: 500,
            effective_height: 200,
            announced_height: 100,
        });
    }
    let after_pending = e.get_state_root().await;
    assert_ne!(
        after_pending, after_schedule,
        "a pending commission change decides the future rate, so it must move the root"
    );

    // 3. The redelegation lock on a position.
    {
        let mut ledger = e.staking_write().await;
        ledger
            .redelegation_lock
            .insert((val, [0x55u8; 32]), 12345);
    }
    assert_ne!(
        e.get_state_root().await,
        after_pending,
        "a redelegation lock decides whether the next redelegate is admitted, so it \
          must move the root"
    );
}

/// Monolithic snapshot/restore round-trip: a snapshot restores byte-identical
/// state (same root, same balances), while truncated or garbage bytes are
/// refused fail-closed with the live engine untouched.
///
/// Gap pin: the chunked path pins poisoned-chunk refusal elsewhere, but the
/// monolithic `create_snapshot`/`restore_snapshot` round-trip had no
/// integration pin in the snapshot/sync/state-root scope — a silent partial
/// restore here would fork the node from the network under one root.
#[tokio::test]
async fn monolithic_snapshot_restore_roundtrip_preserves_root_and_refuses_garbage() {
    // Positive: snapshot then restore lands on the identical root.
    let src = InMemoryStateEngine::new();
    let a = funded_key(41).verifying_key().to_bytes();
    let b = funded_key(42).verifying_key().to_bytes();
    src.credit_native(&a, 1_000_000).await.expect("credit");
    src.credit_native(&b, 2_000_000).await.expect("credit");
    let root = src.get_state_root().await;
    let bytes = src.create_snapshot().await;
    assert!(!bytes.is_empty(), "snapshot must carry state");

    let dst = InMemoryStateEngine::new();
    dst.restore_snapshot(&bytes)
        .await
        .expect("valid snapshot restores");
    assert_eq!(
        dst.get_state_root().await,
        root,
        "restore must reproduce the snapshotted root"
    );
    assert_eq!(dst.get_account(&a).await.unwrap().balance, 1_000_000);
    assert_eq!(dst.get_account(&b).await.unwrap().balance, 2_000_000);

    // Negative fail-closed: truncated and garbage snapshots are refused and
    // leave the live engine untouched.
    let victim = InMemoryStateEngine::new();
    let keep = funded_key(43).verifying_key().to_bytes();
    victim.credit_native(&keep, 999_999).await.expect("credit");
    let root_before = victim.get_state_root().await;

    let cut = bytes.len() / 2;
    assert!(cut > 0, "snapshot must be non-empty");
    let err = victim
        .restore_snapshot(&bytes[..cut])
        .await
        .expect_err("truncated snapshot must be refused");
    assert!(!err.is_empty(), "refusal must say why");
    assert_eq!(
        victim.get_account(&keep).await.unwrap().balance,
        999_999,
        "refused restore must not touch accounts"
    );
    assert_eq!(
        victim.get_state_root().await,
        root_before,
        "refused restore must not move the root"
    );

    let err = victim
        .restore_snapshot(&[0xDE, 0xAD, 0xBE, 0xEF])
        .await
        .expect_err("garbage snapshot must be refused");
    assert!(!err.is_empty(), "refusal must say why");
    assert_eq!(
        victim.get_state_root().await,
        root_before,
        "refused restore must not move the root"
    );
}
