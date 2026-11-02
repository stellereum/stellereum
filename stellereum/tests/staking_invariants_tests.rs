//! Staking invariant state-machine suite (staking 9.0 -> 9.5).
//!
//! Property tests over the NEW validator-UX surfaces (`unjail`, `redelegate`,
//! bounded `announce_commission` / `apply_commission`) with FIXED seeds
//! (xorshift64, const seeds — no unseeded randomness, no wall-clock, no
//! thread_rng). Each test runs a random interleaving of
//! delegate / redelegate / undelegate / unbond / unjail / commission-announce /
//! apply / slash / downtime (plus the supporting lifecycle: add_bond,
//! process_unbonding, withdraw, distribute/claim rewards) over N=200-500 ops
//! and asserts AFTER EVERY op:
//!
//!  1. CONSERVATION: `ledger_stake_supply` + `total_burned` + rewards backing.
//!     Slash/downtime moves supply -> burned 1:1; withdraw pays out 1:1;
//!     distribute mints pool/minted 1:1 with supply untouched; every other
//!     transition (incl. ALL refusals) leaves all four counters byte-identical.
//!  2. JAIL: jailed keys are never in the active set; a successful `unjail`
//!     required release-height reached AND self-bond back at MIN+buffer, and
//!     preserves slash history; jail records only advance on a real penalty.
//!  3. REDELEGATE LOCK: a successful fast-path move requires no live lock on
//!     the source and arms `max(old, now + UNBONDING_PERIOD_SECS)` on arrival;
//!     chaining inside the window is refused with `CooldownNotElapsed`.
//!  4. COMMISSION BOUNDS: announced delta <= 500 bps, absolute cap 100%,
//!     cooldown between effective changes, delay before effect; announcing the
//!     current rate cancels; apply installs exactly the pending rate.
//!  5. MIN-EDGE: no active-set member is ever below MIN; any self-bond below
//!     MIN (reachable only via the slash path or a full exit to zero) is
//!     absent from the set.
//!
//! Seeds: 0x9E3779B97F4A7C15 (balanced, 500 ops), 0xC2B2AE35D7E8F6A1
//! (balanced, 350 ops), 0x165667B19E3779F9 (slash-heavy, 200 ops).

use stellereum::staking::{
    StakingError, StakingLedger, BPS_DENOMINATOR, COMMISSION_CHANGE_COOLDOWN_HEIGHTS,
    COMMISSION_EFFECT_DELAY_HEIGHTS, COMMISSION_MAX_DELTA_BPS, DEFAULT_COMMISSION_BPS,
    DOWNTIME_MISS_THRESHOLD, DOWNTIME_PENALTY_COOLDOWN, DOWNTIME_SLASH_BPS,
    EQUIVOCATION_SLASH_BPS, JAIL_RELEASE_DELAY_HEIGHTS, MIN_DELEGATION, MIN_VALIDATOR_BOND,
    REWARDS_EMISSION_CAP, UNBONDING_PERIOD_SECS, required_bond_floor_nano,
};

// ---------------------------------------------------------------------------
// Deterministic PRNG: xorshift64*, fixed const seeds only.
// ---------------------------------------------------------------------------

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        let s = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state: s }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

fn vid(n: u8) -> [u8; 32] {
    [n; 32]
}

fn del(n: u8) -> [u8; 32] {
    [0xD0 + n; 32]
}

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

/// Unknown key that is never bonded in these tests (drives NotValidator paths).
const UNKNOWN: [u8; 32] = [0xEE; 32];

struct Report {
    ops: usize,
    checks: usize,
    supply: u64,
    burned: u64,
    pool: u64,
    minted: u64,
    jailed: usize,
    active: usize,
}

struct Runner {
    l: StakingLedger,
    rng: XorShift64,
    now: u64,
    height: u64,
    ops: usize,
    checks: usize,
    vids: Vec<[u8; 32]>,
    dels: Vec<[u8; 32]>,
    slash_heavy: bool,
}

impl Runner {
    fn new(seed: u64, slash_heavy: bool) -> Self {
        let mut l = StakingLedger::new();
        let vids: Vec<[u8; 32]> = (1u8..=4).map(vid).collect();
        let dels: Vec<[u8; 32]> = (1u8..=6).map(del).collect();
        // Genesis funding: well above MIN+buffer, varied commissions.
        let commissions = [DEFAULT_COMMISSION_BPS, 0, 5_000, BPS_DENOMINATOR];
        for (i, v) in vids.iter().enumerate() {
            l.bond(*v, stell(2000), commissions[i]).unwrap();
        }
        // Seed delegations so redelegate/undelegate/slash have live positions.
        for (i, d) in dels.iter().enumerate() {
            l.delegate(*d, vids[i % vids.len()], stell(500)).unwrap();
        }
        Self {
            l,
            rng: XorShift64::new(seed),
            now: 0,
            height: 0,
            ops: 0,
            checks: 0,
            vids,
            dels,
            slash_heavy,
        }
    }

    fn snap(&self) -> (u64, u64, u64, u64) {
        (
            self.l.ledger_stake_supply(),
            self.l.total_burned,
            self.l.rewards_pool,
            self.l.rewards_minted,
        )
    }

    fn pick_vid(&mut self, unknown_every: u64) -> [u8; 32] {
        if unknown_every > 0 && self.rng.below(unknown_every) == 0 {
            return UNKNOWN;
        }
        let i = self.rng.below(self.vids.len() as u64) as usize;
        self.vids[i]
    }

    fn pick_del(&mut self) -> [u8; 32] {
        // Occasionally the zero address (ZeroAddress refusal path).
        if self.rng.below(24) == 0 {
            return [0u8; 32];
        }
        let i = self.rng.below(self.dels.len() as u64) as usize;
        self.dels[i]
    }

    /// Stake amounts: mostly 1..=2500 STELL, sometimes dust below MIN_DELEGATION.
    fn stake_amount(&mut self) -> u64 {
        if self.rng.below(10) == 0 {
            self.rng.below(MIN_DELEGATION)
        } else {
            (1 + self.rng.below(2500)) * 1_000_000_000
        }
    }

    fn commission_choice(&mut self, current: u64) -> u64 {
        match self.rng.below(6) {
            0 => current, // cancel path
            1 => {
                let d = 1 + self.rng.below(COMMISSION_MAX_DELTA_BPS);
                if self.rng.below(2) == 0 {
                    current.saturating_add(d).min(BPS_DENOMINATOR)
                } else {
                    current.saturating_sub(d)
                }
            }
            2 => current
                .saturating_add(COMMISSION_MAX_DELTA_BPS + 1 + self.rng.below(2000))
                .min(BPS_DENOMINATOR + 2000), // over-bound (maybe over-cap)
            3 => self.rng.below(BPS_DENOMINATOR + 2001), // arbitrary incl. over-cap
            4 => 0,
            _ => BPS_DENOMINATOR,
        }
    }

    fn slash_bps(&mut self) -> u64 {
        match self.rng.below(5) {
            0 => EQUIVOCATION_SLASH_BPS,
            1 => DOWNTIME_SLASH_BPS,
            2 => BPS_DENOMINATOR,
            3 => 1 + self.rng.below(12_000), // sometimes > 100% (BadSlashBps)
            _ => 1_000,
        }
    }

    // -- individual ops (each: snapshot, execute, per-op asserts) ------------

    fn op_delegate(&mut self) {
        let d = self.pick_del();
        let v = self.pick_vid(10);
        let amount = self.stake_amount();
        let b = self.snap();
        let res = self.l.delegate(d, v, amount);
        let a = self.snap();
        self.ops += 1;
        match res {
            Ok(()) => {
                assert_eq!(a.0, b.0.saturating_add(amount), "delegate must fund supply");
                assert_eq!((a.1, a.2, a.3), (b.1, b.2, b.3));
                self.checks += 2;
            }
            Err(_) => {
                assert_eq!(b, a, "refused delegate must move nothing");
                self.checks += 1;
            }
        }
        self.check_globals();
    }

    fn op_undelegate(&mut self) {
        let d = self.pick_del();
        let v = self.pick_vid(10);
        let amount = self.stake_amount();
        let b = self.snap();
        let res = self.l.undelegate(d, v, amount, self.now);
        let a = self.snap();
        self.ops += 1;
        assert_eq!(b, a, "undelegate (ok or refused) conserves exactly");
        self.checks += 1;
        let _ = res;
        self.check_globals();
    }

    fn op_redelegate(&mut self) {
        let d = self.pick_del();
        let from = self.pick_vid(10);
        let to = if self.rng.below(8) == 0 {
            from // InvalidRedelegation path
        } else {
            self.pick_vid(10)
        };
        let amount = self.stake_amount();
        let pre_from_lock = self.l.redelegation_locked_until(&from, &d);
        let pre_to_lock = self.l.redelegation_locked_until(&to, &d);
        let held = self.l.delegations.get(&(from, d)).copied().unwrap_or(0);
        let b = self.snap();
        let res = self.l.redelegate(d, from, to, amount, self.now);
        let a = self.snap();
        self.ops += 1;
        match res {
            Ok(()) => {
                assert!(
                    self.now >= pre_from_lock,
                    "success requires no live lock on source"
                );
                assert_eq!(
                    self.l.redelegation_locked_until(&to, &d),
                    pre_to_lock.max(self.now.saturating_add(UNBONDING_PERIOD_SECS)),
                    "arrival lock must arm to max(old, now+window)"
                );
                assert_eq!(b, a, "redelegate conserves exactly");
                self.checks += 3;
            }
            Err(e) => {
                assert_eq!(b, a, "refused redelegate must move nothing");
                match e {
                    StakingError::CooldownNotElapsed => {
                        assert!(self.now < pre_from_lock, "cooldown refusal needs live lock")
                    }
                    StakingError::InvalidRedelegation => assert_eq!(from, to),
                    StakingError::InsufficientDelegation => {
                        assert!(amount == 0 || amount > held)
                    }
                    _ => {}
                }
                self.checks += 2;
            }
        }
        self.check_globals();
    }

    fn op_unbond(&mut self) {
        let v = self.pick_vid(10);
        let amount = self.stake_amount();
        let b = self.snap();
        let res = self.l.unbond(v, amount, self.now);
        let a = self.snap();
        self.ops += 1;
        assert_eq!(b, a, "unbond (ok or refused) conserves exactly");
        self.checks += 1;
        let _ = res;
        self.check_globals();
    }

    fn op_process(&mut self) {
        let b = self.snap();
        let res = self.l.process_unbonding(self.now);
        let a = self.snap();
        self.ops += 1;
        assert!(res.is_ok(), "process_unbonding is infallible at test magnitudes");
        assert_eq!(b, a, "maturation only re-keys stake");
        self.checks += 2;
        self.check_globals();
    }

    fn op_withdraw(&mut self) {
        let v = self.pick_vid(10);
        let b = self.snap();
        let res = self.l.withdraw(v);
        let a = self.snap();
        self.ops += 1;
        match res {
            Ok(amt) => {
                assert!(b.0 >= a.0);
                assert_eq!(b.0 - a.0, amt, "withdraw pays out 1:1");
                assert_eq!((a.1, a.2, a.3), (b.1, b.2, b.3));
                self.checks += 2;
            }
            Err(_) => {
                assert_eq!(b, a, "refused withdraw moves nothing");
                self.checks += 1;
            }
        }
        self.check_globals();
    }

    fn op_withdraw_del(&mut self) {
        let d = self.pick_del();
        let v = self.pick_vid(10);
        let b = self.snap();
        let res = self.l.withdraw_delegator(d, v);
        let a = self.snap();
        self.ops += 1;
        match res {
            Ok(amt) => {
                assert!(b.0 >= a.0);
                assert_eq!(b.0 - a.0, amt, "delegator withdraw pays out 1:1");
                assert_eq!((a.1, a.2, a.3), (b.1, b.2, b.3));
                self.checks += 2;
            }
            Err(_) => {
                assert_eq!(b, a, "refused delegator withdraw moves nothing");
                self.checks += 1;
            }
        }
        self.check_globals();
    }

    fn op_slash(&mut self) {
        let v = self.pick_vid(8);
        let bps = self.slash_bps();
        let b = self.snap();
        let res = self.l.slash(v, bps);
        let a = self.snap();
        self.ops += 1;
        match res {
            Ok(burned) => {
                assert_eq!(a.1 - b.1, burned, "burned must be booked");
                assert!(b.0 >= a.0, "slash never inflates supply");
                assert_eq!(b.0 - a.0, burned, "supply falls by exactly burned");
                assert_eq!((a.2, a.3), (b.2, b.3), "slash mints no rewards");
                self.checks += 3;
            }
            Err(e) => {
                assert_eq!(b, a, "refused slash moves nothing");
                if bps > BPS_DENOMINATOR {
                    assert_eq!(e, StakingError::BadSlashBps);
                }
                self.checks += 2;
            }
        }
        self.check_globals();
    }

    /// One downtime height: mask bit i => vids[i] signed.
    fn downtime_once(&mut self, h: u64, mask: u64) {
        let signers: Vec<[u8; 32]> = self
            .vids
            .iter()
            .enumerate()
            .filter(|(i, _)| ((mask >> i) & 1) == 1)
            .map(|(_, v)| *v)
            .collect();
        let eligible = self.vids.clone();
        let pre_pen: Vec<([u8; 32], u64)> = eligible
            .iter()
            .map(|v| {
                (
                    *v,
                    self.l
                        .validators
                        .get(v)
                        .map(|s| s.last_downtime_penalty)
                        .unwrap_or(0),
                )
            })
            .collect();
        let pre_jail: Vec<([u8; 32], Option<stellereum::staking::JailRecord>)> = eligible
            .iter()
            .map(|v| (*v, self.l.jail_record(v)))
            .collect();
        let b = self.snap();
        let sign = |v: &[u8; 32]| signers.contains(v);
        let got = self.l.note_missed_heights(h, &sign, &eligible);
        let a = self.snap();
        self.ops += 1;
        assert!(b.0 >= a.0, "downtime never inflates supply");
        assert_eq!(b.0 - a.0, got, "downtime supply falls by exactly burned");
        assert_eq!(a.1 - b.1, got, "downtime burned must be booked");
        assert_eq!((a.2, a.3), (b.2, b.3), "downtime mints no rewards");
        self.checks += 3;
        for (v, pre) in &pre_pen {
            let post = self
                .l
                .validators
                .get(v)
                .map(|s| s.last_downtime_penalty)
                .unwrap_or(0);
            if post != *pre {
                assert_eq!(post, h, "penalty stamp is the firing height");
                assert!(
                    *pre == 0 || h - *pre >= DOWNTIME_PENALTY_COOLDOWN,
                    "repeat penalty needs the cooldown"
                );
                self.checks += 2;
            }
        }
        for (v, pre) in &pre_jail {
            let post = self.l.jail_record(v);
            match (*pre, post) {
                (None, Some(r)) => {
                    assert!(got > 0, "fresh jail needs a real penalty");
                    assert_eq!(r.jailed_at_height, h);
                    assert_eq!(
                        r.release_height,
                        h.saturating_add(JAIL_RELEASE_DELAY_HEIGHTS)
                    );
                    self.checks += 3;
                }
                (Some(old), Some(cur)) if cur != old => {
                    assert!(got > 0, "jail refresh needs a real penalty");
                    assert_eq!(cur.jailed_at_height, h);
                    assert_eq!(
                        cur.release_height,
                        old.release_height
                            .max(h.saturating_add(JAIL_RELEASE_DELAY_HEIGHTS)),
                        "refresh never shortens release"
                    );
                    self.checks += 3;
                }
                _ => {}
            }
        }
        self.check_globals();
    }

    fn op_downtime(&mut self) {
        // Half the time: targeted 10-height outage of one victim (forces a
        // jail when the cooldown allows); otherwise one noisy height.
        if self.rng.below(2) == 0 {
            let vi = self.rng.below(self.vids.len() as u64) as usize;
            let victim = self.vids[vi];
            let mut mask_all: u64 = 0;
            for i in 0..self.vids.len() {
                if self.vids[i] != victim {
                    mask_all |= 1u64 << i;
                }
            }
            for k in 0..u64::from(DOWNTIME_MISS_THRESHOLD) {
                let h = self.height.saturating_add(k);
                self.downtime_once(h, mask_all);
            }
            self.height = self
                .height
                .saturating_add(u64::from(DOWNTIME_MISS_THRESHOLD));
        } else {
            let mask = self.rng.below(1u64 << self.vids.len());
            self.downtime_once(self.height, mask);
        }
    }

    fn op_unjail(&mut self) {
        let v = self.pick_vid(6);
        let pre_rec = self.l.jail_record(&v);
        let pre_bond = self
            .l
            .validators
            .get(&v)
            .map(|s| s.self_bond)
            .unwrap_or(0);
        let pre_slashed = self
            .l
            .validators
            .get(&v)
            .map(|s| s.total_slashed)
            .unwrap_or(0);
        let b = self.snap();
        let res = self.l.unjail(v, self.height);
        let a = self.snap();
        self.ops += 1;
        match res {
            Ok(()) => {
                let r = pre_rec.expect("success needs a jail record");
                assert!(
                    self.height >= r.release_height,
                    "unjail only after release height"
                );
                assert!(
                    pre_bond >= required_bond_floor_nano(),
                    "unjail only with MIN+buffer intact"
                );
                assert!(!self.l.is_jailed(&v));
                assert_eq!(
                    self.l.validators.get(&v).map(|s| s.missed).unwrap_or(99),
                    0,
                    "unjail resets the downtime streak"
                );
                assert_eq!(
                    self.l
                        .validators
                        .get(&v)
                        .map(|s| s.total_slashed)
                        .unwrap_or(0),
                    pre_slashed,
                    "unjail must never launder slash history"
                );
                assert_eq!(b, a, "unjail moves no stake");
                self.checks += 6;
            }
            Err(e) => {
                assert_eq!(b, a, "refused unjail moves nothing");
                match e {
                    StakingError::NotJailed => assert!(pre_rec.is_none()),
                    StakingError::CooldownNotElapsed => {
                        assert!(self.height < pre_rec.expect("cooldown needs record").release_height)
                    }
                    StakingError::BondBelowMinimum => {
                        assert!(pre_bond < required_bond_floor_nano())
                    }
                    _ => panic!("unexpected unjail error: {e:?}"),
                }
                self.checks += 2;
            }
        }
        self.check_globals();
    }

    fn op_announce(&mut self) {
        let v = self.pick_vid(8);
        let pre_current = self.l.validators.get(&v).map(|s| s.commission_bps);
        let pre_sched = self.l.commission_schedule_of(&v);
        let new_bps = match pre_current {
            Some(c) => self.commission_choice(c),
            None => self.rng.below(BPS_DENOMINATOR + 2),
        };
        let b = self.snap();
        let res = self.l.announce_commission(v, new_bps, self.height);
        let a = self.snap();
        self.ops += 1;
        match res {
            Ok(()) => {
                let cur = pre_current.expect("success needs a validator");
                if new_bps == cur {
                    assert!(
                        self
                            .l
                            .commission_schedule_of(&v)
                            .and_then(|s| s.pending)
                            .is_none(),
                        "re-announcing current cancels pending"
                    );
                } else {
                    assert!(new_bps <= BPS_DENOMINATOR);
                    assert!(new_bps.abs_diff(cur) <= COMMISSION_MAX_DELTA_BPS);
                    if let Some(last) = pre_sched.and_then(|s| s.last_effective_height) {
                        assert!(
                            self.height
                                >= last.saturating_add(COMMISSION_CHANGE_COOLDOWN_HEIGHTS),
                            "announce needs the cooldown"
                        );
                    }
                    let p = self
                        .l
                        .commission_schedule_of(&v)
                        .and_then(|s| s.pending)
                        .expect("success arms pending");
                    assert_eq!(p.new_bps, new_bps);
                    assert_eq!(p.announced_height, self.height);
                    assert_eq!(
                        p.effective_height,
                        self.height.saturating_add(COMMISSION_EFFECT_DELAY_HEIGHTS)
                    );
                    assert_eq!(
                        self.l.validators.get(&v).map(|s| s.commission_bps),
                        Some(cur),
                        "announce moves no rate"
                    );
                }
                assert_eq!(b, a, "announce moves no stake");
                self.checks += 4;
            }
            Err(e) => {
                assert_eq!(b, a, "refused announce moves nothing");
                match e {
                    StakingError::BadCommission => assert!(new_bps > BPS_DENOMINATOR),
                    StakingError::CommissionDeltaExceeded => {
                        let cur = pre_current.expect("delta needs a validator");
                        assert!(new_bps <= BPS_DENOMINATOR);
                        assert!(new_bps.abs_diff(cur) > COMMISSION_MAX_DELTA_BPS);
                    }
                    StakingError::CommissionNotDue => {
                        let last = pre_sched
                            .and_then(|s| s.last_effective_height)
                            .expect("cooldown refusal needs a prior change");
                        assert!(self.height < last.saturating_add(COMMISSION_CHANGE_COOLDOWN_HEIGHTS));
                    }
                    StakingError::NotValidator => assert!(pre_current.is_none()),
                    _ => panic!("unexpected announce error: {e:?}"),
                }
                self.checks += 2;
            }
        }
        self.check_globals();
    }

    fn op_apply(&mut self) {
        let v = self.pick_vid(8);
        let pre_sched = self.l.commission_schedule_of(&v);
        let known = self.l.validators.contains_key(&v);
        let b = self.snap();
        let res = self.l.apply_commission(v, self.height);
        let a = self.snap();
        self.ops += 1;
        match res {
            Ok(()) => {
                let p = pre_sched.and_then(|s| s.pending).expect("success needs pending");
                assert!(
                    self.height >= p.effective_height,
                    "apply only at/after the effective height"
                );
                assert_eq!(
                    self.l.validators.get(&v).map(|s| s.commission_bps),
                    Some(p.new_bps),
                    "apply installs exactly the pending rate"
                );
                let post = self
                    .l
                    .commission_schedule_of(&v)
                    .expect("schedule survives apply");
                assert!(post.pending.is_none());
                assert_eq!(post.last_effective_height, Some(self.height));
                assert_eq!(b, a, "apply moves no stake");
                self.checks += 5;
            }
            Err(e) => {
                assert_eq!(b, a, "refused apply moves nothing");
                match e {
                    StakingError::NotValidator => assert!(!known),
                    StakingError::CommissionNotDue => {
                        let due = pre_sched.and_then(|s| s.pending).is_some_and(|p| {
                            self.height >= p.effective_height
                        });
                        assert!(!due, "not-due refusal needs nothing-due");
                    }
                    _ => panic!("unexpected apply error: {e:?}"),
                }
                self.checks += 2;
            }
        }
        self.check_globals();
    }

    fn op_distribute(&mut self) {
        let v = self.pick_vid(10);
        let reward = if self.rng.below(8) == 0 {
            0
        } else {
            (1 + self.rng.below(200)) * 1_000_000_000
        };
        let b = self.snap();
        let res = self.l.distribute_reward(v, reward);
        let a = self.snap();
        self.ops += 1;
        match res {
            Ok(()) => {
                assert_eq!(a.0, b.0, "rewards mint backing, never supply");
                if reward > 0 {
                    assert_eq!(a.2, b.2.saturating_add(reward), "pool backs the mint");
                    assert_eq!(a.3, b.3.saturating_add(reward), "minted tracks the mint");
                } else {
                    assert_eq!((a.2, a.3), (b.2, b.3), "zero reward mints nothing");
                }
                self.checks += 3;
            }
            Err(_) => {
                assert_eq!(b, a, "refused distribution mints nothing");
                self.checks += 1;
            }
        }
        self.check_globals();
    }

    fn op_claim_val(&mut self) {
        let v = self.pick_vid(10);
        let b = self.snap();
        let res = self.l.claim_validator_rewards(v);
        let a = self.snap();
        self.ops += 1;
        match res {
            Ok(amt) => {
                assert_eq!(b.0, a.0, "claims never touch stake");
                assert_eq!((a.1, a.3), (b.1, b.3));
                assert!(b.2 >= a.2);
                assert_eq!(b.2 - a.2, amt, "pool pays claims 1:1");
                self.checks += 3;
            }
            Err(_) => {
                assert_eq!(b, a, "refused validator claim moves nothing");
                self.checks += 1;
            }
        }
        self.check_globals();
    }

    fn op_claim_del(&mut self) {
        let d = self.pick_del();
        let v = self.pick_vid(10);
        let b = self.snap();
        let amt = self.l.claim_delegator_rewards(d, v);
        let a = self.snap();
        self.ops += 1;
        assert_eq!(b.0, a.0, "claims never touch stake");
        assert_eq!((a.1, a.3), (b.1, b.3));
        assert!(b.2 >= a.2);
        assert_eq!(b.2 - a.2, amt, "pool pays claims 1:1");
        self.checks += 3;
        self.check_globals();
    }

    fn op_add_bond(&mut self) {
        let v = self.pick_vid(10);
        let amount = (1 + self.rng.below(1500)) * 1_000_000_000;
        let b = self.snap();
        let res = self.l.add_bond(v, amount);
        let a = self.snap();
        self.ops += 1;
        match res {
            Ok(()) => {
                assert_eq!(a.0, b.0.saturating_add(amount), "top-up funds supply");
                assert_eq!((a.1, a.2, a.3), (b.1, b.2, b.3));
                self.checks += 2;
            }
            Err(_) => {
                assert_eq!(b, a, "refused top-up moves nothing");
                self.checks += 1;
            }
        }
        self.check_globals();
    }

    // -- global invariants after every op -----------------------------------

    fn check_globals(&mut self) {
        let set = self.l.to_validator_set();
        // (2) jail: jailed keys never in the active set; records sane.
        for (id, rec) in self.l.jail.iter() {
            assert!(
                !set.validators.contains_key(id),
                "jailed validator must never be in the active set"
            );
            assert!(rec.release_height >= rec.jailed_at_height);
        }
        self.checks += 1;
        // (5) MIN-edge: every active member is at/above MIN; every sub-MIN
        // self-bond (slash path or full exit to zero) is out of the set.
        for (id, _power) in set.validators.iter() {
            let sb = self.l.validators.get(id).map(|s| s.self_bond).unwrap_or(0);
            assert!(
                sb >= MIN_VALIDATOR_BOND,
                "active validator below MIN without eject"
            );
        }
        for (id, s) in self.l.validators.iter() {
            if s.self_bond < MIN_VALIDATOR_BOND {
                assert!(
                    !set.validators.contains_key(id),
                    "sub-MIN stake must be ejected from the set"
                );
            }
        }
        self.checks += 1;
        // (4) commission bounds hold globally: rate capped; pending sane.
        for (id, s) in self.l.validators.iter() {
            assert!(s.commission_bps <= BPS_DENOMINATOR, "commission capped at 100%");
            if let Some(p) = self
                .l
                .commission_schedule_of(id)
                .and_then(|sched| sched.pending)
            {
                assert!(p.new_bps <= BPS_DENOMINATOR);
                assert_ne!(p.new_bps, s.commission_bps, "pending differs (else cancelled)");
                assert_eq!(
                    p.effective_height,
                    p.announced_height
                        .saturating_add(COMMISSION_EFFECT_DELAY_HEIGHTS)
                );
            }
        }
        self.checks += 1;
        // (1) rewards backing: pool == validator-pending + accumulator-remaining.
        let pend: u128 = self
            .l
            .validators
            .values()
            .map(|v| u128::from(v.pending_rewards))
            .sum();
        let rem: u128 = self
            .l
            .reward_accumulators
            .values()
            .map(|acc| acc.remaining_rewards)
            .sum();
        assert_eq!(
            u128::from(self.l.rewards_pool),
            pend + rem,
            "rewards pool must exactly back outstanding rewards"
        );
        assert!(self.l.rewards_pool <= self.l.rewards_minted);
        assert!(self.l.rewards_minted <= REWARDS_EMISSION_CAP);
        self.checks += 1;
        // (1) delegation aggregate == per-validator delegated counters.
        for (id, s) in self.l.validators.iter() {
            let mut sum = 0u64;
            for ((w, _), amt) in self.l.delegations.iter() {
                if w == id {
                    sum = sum.saturating_add(*amt);
                }
            }
            assert_eq!(sum, s.delegated, "delegation map/aggregate coherence");
        }
        self.checks += 1;
        // Active-set shape: elected count matches the derived set (below cap).
        assert_eq!(self.l.elected_count(), set.validators.len());
        self.checks += 1;
    }

    fn step(&mut self) {
        // Advance both clocks; occasional big jumps cross the unbonding
        // window, jail delay, and commission delay/cooldown deterministically.
        let dh = 1 + self.rng.below(8);
        self.height = self.height.saturating_add(dh);
        self.now = self
            .now
            .saturating_add(dh.saturating_mul(3).saturating_add(self.rng.below(4000)));
        if self.rng.below(25) == 0 {
            self.height = self.height.saturating_add(8_000);
            self.now = self.now.saturating_add(24_000);
        }
        let kind = if self.slash_heavy {
            match self.rng.below(10) {
                0 | 1 => 7,
                2 | 3 => 8,
                4 => 9,
                5 => 10,
                6 => 11,
                7 => 12,
                8 => 13,
                _ => self.rng.below(16),
            }
        } else {
            self.rng.below(16)
        };
        match kind {
            0 => self.op_delegate(),
            1 => self.op_undelegate(),
            2 => self.op_redelegate(),
            3 => self.op_unbond(),
            4 => self.op_process(),
            5 => self.op_withdraw(),
            6 => self.op_withdraw_del(),
            7 => self.op_slash(),
            8 => self.op_downtime(),
            9 => self.op_unjail(),
            10 => self.op_announce(),
            11 => self.op_apply(),
            12 => self.op_distribute(),
            13 => self.op_claim_val(),
            14 => self.op_claim_del(),
            _ => self.op_add_bond(),
        }
    }

    fn report(&self) -> Report {
        Report {
            ops: self.ops,
            checks: self.checks,
            supply: self.l.ledger_stake_supply(),
            burned: self.l.total_burned,
            pool: self.l.rewards_pool,
            minted: self.l.rewards_minted,
            jailed: self.l.jail.len(),
            active: self.l.to_validator_set().validators.len(),
        }
    }
}

fn run_machine(seed: u64, n_steps: usize, slash_heavy: bool) -> Report {
    let mut r = Runner::new(seed, slash_heavy);
    for _ in 0..n_steps {
        r.step();
    }
    r.report()
}

#[test]
fn invariants_interleaving_balanced_500_ops() {
    let rep = run_machine(0x9E3779B97F4A7C15, 500, false);
    assert!(rep.ops >= 500, "must execute the full program");
    assert!(rep.checks > rep.ops * 5, "per-op invariant density");
    println!(
        "balanced-500 seed=0x9E3779B97F4A7C15 ops={} checks={} supply={} burned={} pool={} minted={} jailed={} active={}",
        rep.ops, rep.checks, rep.supply, rep.burned, rep.pool, rep.minted, rep.jailed,
        rep.active
    );
}

#[test]
fn invariants_interleaving_balanced_350_ops() {
    let rep = run_machine(0xC2B2AE35D7E8F6A1, 350, false);
    assert!(rep.ops >= 350, "must execute the full program");
    assert!(rep.checks > rep.ops * 5, "per-op invariant density");
    println!(
        "balanced-350 seed=0xC2B2AE35D7E8F6A1 ops={} checks={} supply={} burned={} pool={} minted={} jailed={} active={}",
        rep.ops, rep.checks, rep.supply, rep.burned, rep.pool, rep.minted, rep.jailed,
        rep.active
    );
}

#[test]
fn invariants_interleaving_slash_heavy_200_ops() {
    let rep = run_machine(0x165667B19E3779F9, 200, true);
    assert!(rep.ops >= 200, "must execute the full program");
    assert!(rep.checks > rep.ops * 5, "per-op invariant density");
    assert!(rep.burned > 0, "slash-heavy program must actually burn");
    println!(
        "slash-heavy-200 seed=0x165667B19E3779F9 ops={} checks={} supply={} burned={} pool={} minted={} jailed={} active={}",
        rep.ops, rep.checks, rep.supply, rep.burned, rep.pool, rep.minted, rep.jailed,
        rep.active
    );
}

#[test]
fn xorshift_fixed_seeds_are_deterministic() {
    let mut a = XorShift64::new(0x9E3779B97F4A7C15);
    let mut b = XorShift64::new(0x9E3779B97F4A7C15);
    for _ in 0..64 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
    let mut c = XorShift64::new(0xC2B2AE35D7E8F6A1);
    assert_ne!(a.next_u64(), c.next_u64(), "distinct seeds must diverge");
}
