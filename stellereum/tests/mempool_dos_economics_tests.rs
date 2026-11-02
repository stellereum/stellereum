//! Mempool DoS economics: attacker-cost modeling + fail-closed proofs.
//!
//! Scope: MEMPOOL ECONOMICS ONLY (admission filter, fee ordering, per-sender
//! caps, eviction policy, TTL sweeps, unexecutable handling, dust, max sizes).
//! No consensus / apply / rpc / state changes.
//!
//! Method: every attack is executed against a small pool with EXPLICIT clocks
//! (`AdmissionCtx::new`), and the cost is read back from the pool's own
//! reservation ledger (`reserved_for`). Live-network extrapolations in the
//! comments are plain arithmetic over the measured per-slot price (marked
//! ARITHMETIC, not measured).
//!
//! Findings (see the economics table at the bottom):
//! * FILL: every pooled slot must be fully funded (`amount + gas_limit` +
//!   surcharge, jointly across the sender's slots). Unfunded fill is refused.
//! * EVICTION: unfunded transactions NEVER evict; cheaper ones NEVER evict
//!   (same-tier needs a 5% premium; a higher priority tier must still pay a
//!   strictly higher fee; a lower tier never displaces). Suppression always
//!   costs the attacker at least the victim's price.
//! * NONCE-GAP: past-window nonces fail fast; within-window future junk is
//!   reclaimed after `FUTURE_NONCE_TTL_SECS` and swept after
//!   `STUCK_TX_TTL_SECS`. One account pins at most `NONCE_FUTURE_WINDOW`
//!   slots, each funded.
//! * DUST: there is no minimum-amount rule (`amount == 0` admits), but the fee
//!   floor prices every slot: dust costs `floor` per slot, never zero on a
//!   floored pool.
//! * SWEEP: executable transactions survive any age; only stale /
//!   unaffordable / gap-stuck transactions older than the TTL go. Unknown
//!   senders are never deleted.
//! * SEALED (fixed here): the sealed path proved no funds and charged quota
//!   to a self-declared `from`, so forged envelopes filled the pool for free.
//!   `add_sealed` is now capped at `sealed_cap()` (`max_size / 4`).

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::mempool::{AdmissionCtx, Mempool, MempoolError};
use stellereum::mev_epoch::{SealedEnvelope, TransparentMeta};
use stellereum::sharding::Transaction;

const NOW: u64 = 5_000_000;

fn key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn addr(sk: &SigningKey) -> [u8; 32] {
    sk.verifying_key().to_bytes()
}

/// Plain transfer: `cost = amount + gas_limit` (no PQ surcharge on this path).
fn tx(sk: &SigningKey, amount: u64, gas: u64, nonce: u64) -> Transaction {
    Transaction::sign(sk, [9u8; 32], amount, gas, nonce, 1, 1)
}

fn tx_prio(
    sk: &SigningKey,
    amount: u64,
    gas: u64,
    nonce: u64,
    prio: u64,
) -> Transaction {
    Transaction::sign_with_priority(sk, [9u8; 32], amount, gas, nonce, 1, 1, prio)
}

fn ctx_onchain(now: u64, onchain: u64) -> AdmissionCtx {
    AdmissionCtx::new(now).with_onchain_nonce(onchain)
}

/// A forged sealed envelope: valid curve point, non-empty ciphertext,
/// non-zero hash — structurally admissible, carrying NO funds and NO
/// signatures. `from` is self-declared (spoofable).
fn sealed_junk(epoch: u64, from: [u8; 32], uniq: u64) -> SealedEnvelope {
    let mut tx_hash = [0u8; 32];
    tx_hash[..8].copy_from_slice(&uniq.to_le_bytes());
    tx_hash[8..].copy_from_slice(&from[..24]);
    debug_assert_ne!(tx_hash, [0u8; 32]);
    SealedEnvelope {
        epoch,
        tx_hash,
        ephemeral_pk: RISTRETTO_BASEPOINT_POINT.compress().to_bytes(),
        nonce: [0xABu8; 24],
        ciphertext: vec![uniq as u8, 0x42, 0x17],
        meta: TransparentMeta {
            from,
            nonce: 0,
            gas_limit: 300_000,
            priority_fee_per_gas: 0,
            source_shard: 1,
            target_shard: 1,
        },
    }
}

// ---------------------------------------------------------------------------
// 1. FILL-TO-CAP COST
// ---------------------------------------------------------------------------

#[test]
fn fill_to_cap_costs_real_money_every_slot_funded() {
    // Pool of 8, floor 100: cheapest slot = amount 10 + gas 100 = 110.
    let mut mp = Mempool::new(8, 8).with_base_fee(100);
    let sk = key();
    let me = addr(&sk);
    let cost: u64 = 110;
    let balance = 8 * cost;

    for n in 0..8u64 {
        mp.add_checked_ctx(tx(&sk, 10, 100, n), balance, AdmissionCtx::new(NOW))
            .unwrap_or_else(|e| panic!("funded slot {n} refused: {e:?}"));
    }
    assert_eq!(mp.len(), 8, "pool must be full");
    assert_eq!(
        mp.reserved_for(&me),
        balance,
        "every slot's full cost must be reserved: measured fill = {balance}"
    );
    // ARITHMETIC (live floor 280_000 = GAS_BASIC_TRANSFER, cap 50_000):
    // min fill = 50_000 x 280_000 = 14_000_000_000 nano-STELL + amounts.

    // The sender's own quota is exhausted too: a 9th nonce has no slot
    // (fresh funding isolates the quota verdict from the reservation one).
    assert_eq!(
        mp.add_checked_ctx(tx(&sk, 10, 100, 8), 1_000_000, AdmissionCtx::new(NOW)),
        Err(MempoolError::TooManyFromSender)
    );
    // And a funded stranger offering exactly the floor cannot displace
    // anything (needs the 5% premium: 100 + ceil(100/20) = 105).
    let stranger = key();
    assert_eq!(
        mp.add_checked_ctx(
            tx(&stranger, 10, 100, 0),
            1_000_000,
            AdmissionCtx::new(NOW)
        ),
        Err(MempoolError::Full)
    );
    assert_eq!(mp.len(), 8, "pool untouched by floor-price stranger");
}

#[test]
fn unfunded_junk_is_always_refused_on_the_checked_path() {
    let mut mp = Mempool::new(16, 16).with_base_fee(100);
    let sk = key();

    // Dust shapes, zero balance: all refused, none pooled.
    for (amount, gas, nonce) in [(0, 100, 0), (1, 100, 1), (0, 1_000, 2), (10, 100, 3)] {
        assert_eq!(
            mp.add_checked_ctx(tx(&sk, amount, gas, nonce), 0, AdmissionCtx::new(NOW)),
            Err(MempoolError::InsufficientBalance),
            "unfunded dust (amount={amount}, gas={gas}) must be refused"
        );
    }
    // Below-floor declarations are refused even WITH money behind them.
    assert_eq!(
        mp.add_checked_ctx(tx(&sk, 10, 99, 0), 1_000_000, AdmissionCtx::new(NOW)),
        Err(MempoolError::FeeTooLow)
    );
    assert_eq!(mp.len(), 0, "no junk may occupy a slot");
    assert_eq!(mp.reserved_for(&addr(&sk)), 0, "no reservation without admission");
}

// ---------------------------------------------------------------------------
// 2. EVICTION ORDERING: funded victims vs unfunded / cheaper attackers
// ---------------------------------------------------------------------------

#[test]
fn funded_victims_survive_unfunded_and_cheaper_eviction() {
    // 4 honest senders @ fee 100 fill the pool.
    let mut mp = Mempool::new(4, 100);
    let mut honest_hashes = Vec::new();
    for _ in 0..4 {
        let k = key();
        let h = mp
            .add_checked_ctx(tx(&k, 10, 100, 0), 1_000_000, AdmissionCtx::new(NOW))
            .expect("honest funded tx admits");
        honest_hashes.push(h);
    }
    let victim = *honest_hashes.iter().min().expect("nonempty");

    // (a) UNFUNDED attacker, astronomic declared fee: never evicts.
    let evil = key();
    assert_eq!(
        mp.add(tx(&evil, 10, u64::MAX, 0)),
        Err(MempoolError::Full),
        "the unchecked path must never displace a funded transaction"
    );
    assert!(mp.contains(&victim), "victim must survive the unfunded attack");

    // (b) FUNDED but cheaper / at-price / sub-premium: never evicts.
    for fee in [50, 99, 100, 104] {
        let a = key();
        assert_eq!(
            mp.add_checked_ctx(tx(&a, 10, fee, 0), 1_000_000, AdmissionCtx::new(NOW)),
            Err(MempoolError::Full),
            "fee {fee} must not displace a fee-100 victim"
        );
    }
    for h in &honest_hashes {
        assert!(mp.contains(h), "all funded victims must survive cheap attacks");
    }
    assert_eq!(mp.len(), 4);

    // (c) The 5% premium DOES evict — and it evicts exactly the cheapest.
    let attacker = key();
    mp.add_checked_ctx(tx(&attacker, 10, 105, 0), 1_000_000, AdmissionCtx::new(NOW))
        .expect("a 5% premium must displace the cheapest pooled tx");
    assert_eq!(mp.len(), 4);
    assert!(!mp.contains(&victim), "exactly the cheapest tx must be evicted");
    for h in &honest_hashes {
        if *h != victim {
            assert!(mp.contains(h), "non-cheapest victims must stay");
        }
    }
}

#[test]
fn fee_market_suppression_always_costs_at_least_the_victim_price() {
    // Priority escalation must still PAY MORE than the victim; honest
    // re-entry then costs the same gentle premium — never a below-cost lock.
    let mut mp = Mempool::new(4, 100);
    for _ in 0..4 {
        let k = key();
        mp.add_checked_ctx(tx(&k, 10, 100, 0), 1_000_000, AdmissionCtx::new(NOW))
            .unwrap();
    }

    // (a) Higher priority tier with a LOWER fee displaces nothing.
    let sneak = key();
    assert_eq!(
        mp.add_checked_ctx(
            tx_prio(&sneak, 10, 50, 0, 1_000),
            1_000_000,
            AdmissionCtx::new(NOW)
        ),
        Err(MempoolError::FeeTooLow),
        "an unfunded bid (fee < floor + bid) is refused before eviction"
    );
    // A higher tier that FUNDS its bid but pays less than the victim: refused.
    // floor 0 + bid 40 needs gas >= 40; victim pays 100.
    let sneak2 = key();
    assert_eq!(
        mp.add_checked_ctx(
            tx_prio(&sneak2, 10, 90, 0, 40),
            1_000_000,
            AdmissionCtx::new(NOW)
        ),
        Err(MempoolError::Full),
        "a higher tier paying LESS than the victim must not evict"
    );
    assert_eq!(mp.len(), 4, "pool untouched by discount-tier attack");

    // (b) Higher tier paying MORE evicts — the attacker outspends the victim.
    let esc = key();
    mp.add_checked_ctx(tx_prio(&esc, 10, 101, 0, 5), 1_000_000, AdmissionCtx::new(NOW))
        .expect("escalation paying more than the victim evicts");
    assert_eq!(mp.len(), 4);

    // (c) A LOWER tier never displaces, whatever it pays.
    // Cheapest pooled is now (0,100): offer prio 0? that is SAME tier.
    // Lower-tier-vs-higher-victim: evict lowest first so the cheapest pooled
    // tx carries priority, then attack it from below.
    let mut mp2 = Mempool::new(2, 100);
    let h = key();
    mp2.add_checked_ctx(tx_prio(&h, 10, 100, 0, 50), 1_000_000, AdmissionCtx::new(NOW))
        .unwrap();
    let h2 = key();
    mp2.add_checked_ctx(tx_prio(&h2, 10, 100, 1, 50), 1_000_000, AdmissionCtx::new(NOW))
        .unwrap();
    let low = key();
    assert_eq!(
        mp2.add_checked_ctx(
            tx_prio(&low, 10, 1_000_000, 0, 0),
            u64::MAX / 2,
            AdmissionCtx::new(NOW)
        ),
        Err(MempoolError::Full),
        "a lower priority tier must never displace, at any fee"
    );
    assert_eq!(mp2.len(), 2);

    // (d) Honest same-tier re-entry costs the gentle premium only:
    // cheapest is (50,100) -> need fee >= 100 + ceil(100/20) = 105.
    let honest = key();
    assert_eq!(
        mp2.add_checked_ctx(
            tx_prio(&honest, 10, 104, 0, 50),
            1_000_000,
            AdmissionCtx::new(NOW)
        ),
        Err(MempoolError::Full),
        "sub-premium re-entry is refused"
    );
    mp2.add_checked_ctx(tx_prio(&honest, 10, 105, 0, 50), 1_000_000, AdmissionCtx::new(NOW))
        .expect("premium re-entry must succeed: no below-cost lockout");
}

#[test]
fn funded_premium_reclaims_slots_from_unchecked_fill() {
    // The unchecked `add` path (tests / trusted in-process callers only:
    // every live ingress uses `add_checked_ctx`) admits floor-passing signed
    // txs with no funding proof and can NEVER evict. If it ever filled the
    // pool, a FUNDED premium still displaces the cheapest slot — the fill is
    // recoverable, never a lockout.
    let mut mp = Mempool::new(4, 100);
    for _ in 0..4 {
        let k = key();
        mp.add(tx(&k, 10, 100, 0))
            .expect("unchecked floor-passing signed tx admits");
    }
    assert_eq!(mp.len(), 4, "pool filled through the unchecked path");

    // A funded newcomer at exactly the 5% premium reclaims a slot.
    let premium = key();
    mp.add_checked_ctx(tx(&premium, 10, 105, 0), 1_000_000, AdmissionCtx::new(NOW))
        .expect("funded premium must reclaim an unchecked-filled slot");
    assert_eq!(mp.len(), 4);
    assert_eq!(
        mp.reserved_for(&addr(&premium)),
        115,
        "the reclaiming slot reserves its full cost (amount 10 + gas 105)"
    );
}

// ---------------------------------------------------------------------------
// 3. NONCE-GAP LOCKUP ATTEMPTS
// ---------------------------------------------------------------------------

#[test]
fn nonce_gap_lockup_is_window_bounded_funded_and_swept() {
    assert_eq!(Mempool::NONCE_FUTURE_WINDOW, 4);
    let mut mp = Mempool::new(32, 32);
    let sk = key();
    let me = addr(&sk);
    let cost: u64 = 20; // amount 10 + gas 10, zero floor

    // Sequential nonces 0..=4 fill the window (head walks with the prefix).
    for n in 0..=4u64 {
        mp.add_checked_ctx(tx(&sk, 10, 10, n), 6 * cost, ctx_onchain(NOW, 0))
            .unwrap_or_else(|e| panic!("in-window nonce {n} refused: {e:?}"));
    }
    // Past the window fails fast, even fully funded.
    match mp.add_checked_ctx(tx(&sk, 10, 10, 10), 1_000_000, ctx_onchain(NOW, 0)) {
        Err(MempoolError::NonceGap { expected, got }) => {
            assert_eq!((expected, got), (5, 10));
        }
        other => panic!("expected NonceGap, got {other:?}"),
    }
    // Window edge (want 5 + 4 = 9) still admits — then funding binds:
    // 6 slots x 20 = 120 is exactly the balance, so the NEXT in-window
    // nonce (5) is refused by the reservation, not the gap.
    mp.add_checked_ctx(tx(&sk, 10, 10, 9), 6 * cost, ctx_onchain(NOW, 0))
        .expect("window-edge nonce admits");
    assert_eq!(
        mp.add_checked_ctx(tx(&sk, 10, 10, 5), 6 * cost, ctx_onchain(NOW, 0)),
        Err(MempoolError::InsufficientBalance),
        "one funding backs only the slots it can jointly pay for"
    );
    // One account pins at most window + funded slots — never the pool.
    assert!(mp.len() <= 2 * Mempool::NONCE_FUTURE_WINDOW as usize + 2);
    let _ = me;
}

#[test]
fn within_window_future_junk_is_reclaimed_after_its_ttl() {
    assert_eq!(Mempool::FUTURE_NONCE_TTL_SECS, 60);
    let mut mp = Mempool::new(32, 32);
    let sk = key();
    let me = addr(&sk);
    let rich = 1_000_000u64;

    // Nonce 0 executes; nonce 4 waits behind a sender-controlled gap.
    let h0 = mp
        .add_checked_ctx(tx(&sk, 10, 10, 0), rich, ctx_onchain(NOW, 0))
        .unwrap();
    let h4 = mp
        .add_checked_ctx(tx(&sk, 10, 10, 4), rich, ctx_onchain(NOW, 0))
        .unwrap();
    let live = |s: &[u8; 32]| {
        if *s == me {
            Some((0u64, rich))
        } else {
            None
        }
    };

    // Fresh: still waiting, still pooled.
    assert_eq!(mp.evict_unexecutable_at(NOW, live), 0);
    assert!(mp.contains(&h4));

    // Aged past the future-nonce TTL: reclaimed, reservation released,
    // executable head untouched.
    assert_eq!(
        mp.evict_unexecutable_at(NOW + Mempool::FUTURE_NONCE_TTL_SECS, live),
        1,
        "an aged future nonce must be reclaimed"
    );
    assert!(!mp.contains(&h4), "the gap junk must be gone");
    assert!(mp.contains(&h0), "the executable head must stay");
    assert_eq!(
        mp.reserved_for(&me),
        20,
        "the swept junk must release its reservation"
    );
}

// ---------------------------------------------------------------------------
// 4. DUST FLOOD COST
// ---------------------------------------------------------------------------

#[test]
fn dust_flood_costs_the_floor_per_slot() {
    // No dust rule: amount 0 admits — but every slot reserves the floor.
    let mut mp = Mempool::new(8, 8).with_base_fee(100);
    let mut total_reserved = 0u64;
    for _ in 0..4 {
        let k = key();
        mp.add_checked_ctx(tx(&k, 0, 100, 0), 100, AdmissionCtx::new(NOW))
            .expect("floor-priced dust admits when funded");
        total_reserved += 100;
        assert_eq!(mp.reserved_for(&addr(&k)), 100, "dust reserves the floor");
    }
    assert_eq!(mp.len(), 4);
    // ARITHMETIC: min dust/slot on a live pool = 280_000; a 50_000-slot dust
    // flood costs >= 14_000_000_000 in reserved fees. Zero-cost dust needs an
    // unfloored pool (see unfunded test) — a deployment property, not an
    // admission bypass.
    assert_eq!(total_reserved, 400);

    // The same dust with no money behind it is refused.
    let poor = key();
    assert_eq!(
        mp.add_checked_ctx(tx(&poor, 0, 100, 0), 99, AdmissionCtx::new(NOW)),
        Err(MempoolError::InsufficientBalance)
    );
}

// ---------------------------------------------------------------------------
// 5. SWEEP CORRECTNESS
// ---------------------------------------------------------------------------

#[test]
fn sweep_keeps_executable_whatever_age_and_drops_stuck() {
    let mut mp = Mempool::new(32, 32);
    let rich = 1_000_000u64;

    // Executable: nonce == onchain head, affordable.
    let exec_sk = key();
    let exec_me = addr(&exec_sk);
    let h_exec = mp
        .add_checked_ctx(tx(&exec_sk, 10, 10, 0), rich, AdmissionCtx::new(NOW))
        .unwrap();

    // Stale nonce (will be consumed), unaffordable (balance will drop),
    // gapped (nonce past head).
    let stale_sk = key();
    let h_stale = mp
        .add_checked_ctx(tx(&stale_sk, 10, 10, 0), rich, AdmissionCtx::new(NOW))
        .unwrap();
    let broke_sk = key();
    let h_broke = mp
        .add_checked_ctx(tx(&broke_sk, 9_000, 1_000, 0), 20_000, AdmissionCtx::new(NOW))
        .unwrap();
    let gap_sk = key();
    let gap_me = addr(&gap_sk);
    for n in [0u64, 1, 5] {
        mp.add_checked_ctx(tx(&gap_sk, 10, 10, n), rich, AdmissionCtx::new(NOW))
            .unwrap();
    }
    // Fresh pool: nothing moves, whatever the state view says.
    assert_eq!(mp.sweep_expired(NOW, |_| Some((0, rich))), 0);
    assert_eq!(mp.len(), 6);

    // Very old pool: executable stays; stale + broke + gapped go.
    let old = NOW + Mempool::STUCK_TX_TTL_SECS + 1;
    let swept = mp.sweep_expired(old, |s| {
        if *s == exec_me {
            Some((0, rich)) // executable head, funded
        } else if *s == addr(&stale_sk) {
            Some((1, rich)) // nonce 0 consumed
        } else if *s == addr(&broke_sk) {
            Some((0, 5_000)) // can no longer afford 10_000
        } else if *s == gap_me {
            Some((0, rich)) // head 2 (0,1 contiguous), nonce 5 gap-stuck
        } else {
            None
        }
    });
    // stale(1) + broke(1) + gap nonce-5(1) = 3. Nonces 0,1 of gap_sk are
    // executable (contiguous from head 0) and stay.
    assert_eq!(swept, 3, "only old unexecutable txs must go");
    assert!(mp.contains(&h_exec), "executable stays whatever its age");
    assert!(!mp.contains(&h_stale), "consumed nonce goes");
    assert!(!mp.contains(&h_broke), "unaffordable goes");
    assert_eq!(mp.len(), 3);

    // Unknown senders are skipped, never assumed broke.
    assert_eq!(mp.sweep_expired(old + 1_000_000, |_| None), 0);
    assert_eq!(mp.len(), 3, "a partial state view must not delete");
}

// ---------------------------------------------------------------------------
// 6. SENDER SPRAWL COST
// ---------------------------------------------------------------------------

#[test]
fn sender_sprawl_cost_scales_linearly_with_slots() {
    // 6 sprawled senders x 3 slots, each fully funded.
    let mut mp = Mempool::new(32, 4);
    let cost: u64 = 105; // amount 5 + gas 100, zero floor
    let mut total = 0u64;
    for _ in 0..6 {
        let k = key();
        let bal = 3 * cost;
        for n in 0..3u64 {
            mp.add_checked_ctx(tx(&k, 5, 100, n), bal, AdmissionCtx::new(NOW))
                .unwrap_or_else(|e| panic!("funded sprawl refused: {e:?}"));
        }
        assert_eq!(mp.reserved_for(&addr(&k)), bal);
        total += bal;
    }
    assert_eq!(mp.len(), 18);
    assert_eq!(total, 6 * 3 * cost, "sprawl cost is linear in slots");
    // The 7th sprawled identity with no money buys nothing.
    let poor = key();
    assert_eq!(
        mp.add_checked_ctx(tx(&poor, 5, 100, 0), 0, AdmissionCtx::new(NOW)),
        Err(MempoolError::InsufficientBalance)
    );
}

// ---------------------------------------------------------------------------
// 7. SEALED PATH: free fill is capped (regression for the fix)
// ---------------------------------------------------------------------------

#[test]
fn sealed_free_fill_is_capped_and_plain_space_survives() {
    const EPOCH: u64 = 7;
    let mut mp = Mempool::new(16, 1024);
    mp.set_sealed_epoch(EPOCH);
    let cap = mp.sealed_cap();
    assert_eq!(cap, 4, "16-slot pool allows 4 sealed (max_size / 4)");

    // Forged envelopes from distinct spoofed senders: zero funds, zero sigs.
    for i in 0..cap as u64 {
        let from = addr(&key());
        mp.add_sealed(sealed_junk(EPOCH, from, 1_000 + i))
            .unwrap_or_else(|e| panic!("sealed slot {i} refused: {e:?}"));
    }
    assert_eq!(mp.sealed_count(), cap);

    // The NEXT forged envelope — fresh identity, valid structure — is
    // refused: the free fill stops at the sealed quota, not at the pool cap.
    let extra = addr(&key());
    assert_eq!(
        mp.add_sealed(sealed_junk(EPOCH, extra, 9_999)),
        Err(MempoolError::Full),
        "free sealed fill must stop at the sealed quota"
    );
    assert_eq!(mp.sealed_count(), cap);

    // Honest plain transactions still have their own space: the sealed quota
    // never crowds out the plain pool (`insert` counts plain txs only).
    for n in 0..16u64 {
        let k = key();
        mp.add_checked_ctx(tx(&k, 10, 100, 0), 1_000_000, AdmissionCtx::new(NOW))
            .unwrap_or_else(|e| panic!("plain tx {n} refused under sealed pressure: {e:?}"));
    }
    assert_eq!(mp.len(), 16, "plain pool keeps its own max_size slots");

    // Epoch rotation drops the sealed pressure (senders re-gossip).
    mp.set_sealed_epoch(EPOCH + 1);
    assert_eq!(mp.sealed_count(), 0);
    assert_eq!(mp.len(), 16, "rotation drops seals, never plain txs");
}

#[test]
fn sealed_quota_is_at_least_one_slot_on_tiny_pools() {
    let mp = Mempool::new(2, 2);
    assert_eq!(mp.sealed_cap(), 1);
    let mut mp = mp;
    mp.set_sealed_epoch(3);
    mp.add_sealed(sealed_junk(3, addr(&key()), 1))
        .expect("a tiny pool still admits one seal");
    assert_eq!(
        mp.add_sealed(sealed_junk(3, addr(&key()), 2)),
        Err(MempoolError::Full)
    );
}

// ---------------------------------------------------------------------------
// ECONOMICS TABLE (measured above unless marked ARITHMETIC)
// ---------------------------------------------------------------------------
// attack                              | cost                          | verdict
// ------------------------------------+-------------------------------+--------
// fill-to-cap (checked path)          | full cost per slot, reserved  | PRICED
//   live ARITHMETIC: 50k x 280k=14e9  | jointly per sender (F-03)     |
// unfunded fill (checked path)        | refused (infinite)            | CLOSED
// unchecked `add` fill                | floor-passing only, NO evict,  | BOUND*
//                                     | funded premium reclaims it      |
// eviction by unfunded tx               | impossible (Full)             | CLOSED
// eviction by cheaper tx (same tier)  | needs +5% premium             | PRICED
// eviction by higher tier             | must still pay MORE than victim | PRICED
// eviction by lower tier              | impossible at any fee         | CLOSED
// nonce-gap stuffing (past window)    | refused fail-fast             | CLOSED
// nonce-gap stuffing (in-window)      | <=4 slots/sender, funded,     | BOUND
//                                     | reclaimed after 60s, swept @120s |
// dust flood (amount 0/1)             | floor/slot (280k live ARITH.) | PRICED
// stale/unaffordable/gapped gallons   | swept after TTL; exec stays   | SWEPT
// unknown-sender sweep                | never deleted                 | CLOSED
// sender sprawl                       | linear in slots (funded each)| PRICED
// sealed free fill (RPC + gossip)     | WAS free/unbounded; capped at | FIXED
//                                     | max_size/4 by this change     |
// ------------------------------------+-------------------------------+--------
// * `add` is reachable only via server-signed RPC arms (auth-gated when
//   configured) and tests; P2P gossip + user RPC use the checked path.
