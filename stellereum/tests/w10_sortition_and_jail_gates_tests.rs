//! Wave 9B / Wave 10 activation-gate regressions for:
//! - `SORTITION_UNBIASED_ACTIVATION_HEIGHT` (`W6-A7-7`, `u64::MAX`, INERT):
//!   * Below `H` (`H - 1` / default `u64::MAX`): `select_committee_from_seed_at`,
//!     `derive_sortition_committee_at`, `derive_sortition_committee`,
//!     `committee_for_height`, `proposer_from_digest_at`, and `proposer_for`
//!     preserve 100% byte-identical legacy `%` behavior.
//!   * At `H`: switches to exact 64-bit rejection sampling (`limit = (1u128 << 64) -
//!     ((1u128 << 64) % modulus)`) over non-power-of-two `total_power` and
//!     `total / gcd` proposer ranges, eliminating modulo bias.
//! - `JAIL_BUDGET_V2_ACTIVATION_HEIGHT` (`u64::MAX`, INERT):
//!   * Below `H`: `DOWNTIME_MISS_THRESHOLD` (`42`) slashes and jails immediately
//!     on the 42nd missed height.
//!   * At `H`: `downtime_miss_threshold_at(h)` returns `DOWNTIME_MISS_THRESHOLD_V2`
//!     (`200`, = 80s at 400ms cadence); missing 42..=199 heights does NOT slash or
//!     jail, and missing the 200th height slashes and jails cleanly.

use ed25519_dalek::SigningKey;
use stellereum::chain_spec::{
    current_activation_schedule, jail_budget_v2_activation_height, jail_budget_v2_active_at,
    set_jail_budget_v2_activation_override, set_sortition_unbiased_activation_override,
    sortition_unbiased_activation_height, sortition_unbiased_active_at, ActivationStatus,
    JAIL_BUDGET_V2_ACTIVATION_HEIGHT, SORTITION_UNBIASED_ACTIVATION_HEIGHT,
};
use stellereum::consensus::{
    committee_for_height, derive_sortition_committee, derive_sortition_committee_at,
    register_validator_pq_key, select_committee_from_seed_at, sortition_seed, CommitteeSchedule,
    ValidatorId, ValidatorSet, Vote, VoteKind, VoteSet, PROPOSER_UNBIASED_DOMAIN,
    SORTITION_DRAW_DOMAIN,
};
use stellereum::feature_gates;
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::staking::{
    downtime_miss_threshold_at, StakingLedger, DEFAULT_COMMISSION_BPS, DOWNTIME_MISS_THRESHOLD,
    DOWNTIME_MISS_THRESHOLD_V2, DOWNTIME_SLASH_BPS, JAIL_RELEASE_DELAY_HEIGHTS, MIN_VALIDATOR_BOND,
    STAKING_POOL, STELL_MIN_BOND_BUFFER,
};
use stellereum::state_engine::InMemoryStateEngine;

struct GateResetGuard;

impl Drop for GateResetGuard {
    fn drop(&mut self) {
        set_sortition_unbiased_activation_override(None);
        set_jail_budget_v2_activation_override(None);
    }
}

fn vid(tag: u8) -> ValidatorId {
    let mut id = [0u8; 32];
    id[0] = tag;
    id[31] = tag;
    id
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

fn legacy_committee_ref(
    validators: &ValidatorSet,
    committee_size: u32,
    domain: &str,
    seed: &[u8; 32],
) -> Vec<ValidatorId> {
    let mut pool: Vec<(ValidatorId, u64)> = validators
        .validators
        .iter()
        .filter(|(_, &p)| p > 0)
        .map(|(&id, &p)| (id, p))
        .collect();
    let target_k = (committee_size as usize).min(pool.len());
    if target_k == 0 {
        return Vec::new();
    }
    if target_k == pool.len() {
        let mut ids: Vec<ValidatorId> = pool.into_iter().map(|(id, _)| id).collect();
        ids.sort_unstable();
        return ids;
    }
    let mut selected = Vec::with_capacity(target_k);
    let mut total_power: u64 = pool.iter().fold(0u64, |acc, (_, p)| acc.saturating_add(*p));
    for step in 0..target_k {
        if total_power == 0 || pool.is_empty() {
            break;
        }
        let mut hasher = blake3::Hasher::new_derive_key(domain);
        hasher.update(seed);
        hasher.update(&(step as u32).to_le_bytes());
        let hash = hasher.finalize();
        let rand_val = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap());
        let ticket = rand_val % total_power;
        let mut acc = 0u64;
        let mut chosen_idx = 0;
        for (idx, (_id, power)) in pool.iter().enumerate() {
            acc = acc.saturating_add(*power);
            if ticket < acc {
                chosen_idx = idx;
                break;
            }
        }
        let (winner_id, winner_power) = pool.remove(chosen_idx);
        total_power = total_power.saturating_sub(winner_power);
        selected.push(winner_id);
    }
    selected.sort_unstable();
    selected
}

fn unbiased_committee_ref(
    validators: &ValidatorSet,
    committee_size: u32,
    domain: &str,
    seed: &[u8; 32],
) -> Vec<ValidatorId> {
    let mut pool: Vec<(ValidatorId, u64)> = validators
        .validators
        .iter()
        .filter(|(_, &p)| p > 0)
        .map(|(&id, &p)| (id, p))
        .collect();
    let target_k = (committee_size as usize).min(pool.len());
    if target_k == 0 {
        return Vec::new();
    }
    if target_k == pool.len() {
        let mut ids: Vec<ValidatorId> = pool.into_iter().map(|(id, _)| id).collect();
        ids.sort_unstable();
        return ids;
    }
    let mut selected = Vec::with_capacity(target_k);
    let mut total_power: u64 = pool.iter().fold(0u64, |acc, (_, p)| acc.saturating_add(*p));
    for step in 0..target_k {
        if total_power == 0 || pool.is_empty() {
            break;
        }
        let modulus = total_power as u128;
        let limit = (1u128 << 64) - ((1u128 << 64) % modulus);
        let mut ticket = 0u64;
        let mut found = false;
        let mut last_rand = 0u64;
        for attempt in 0..64u32 {
            let mut hasher = blake3::Hasher::new_derive_key(domain);
            hasher.update(seed);
            hasher.update(&(step as u32).to_le_bytes());
            hasher.update(&attempt.to_le_bytes());
            let hash = hasher.finalize();
            let rand_val = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap());
            last_rand = rand_val;
            if (rand_val as u128) < limit {
                ticket = ((rand_val as u128) % modulus) as u64;
                found = true;
                break;
            }
        }
        if !found {
            ticket = ((last_rand as u128) % modulus) as u64;
        }
        let mut acc = 0u64;
        let mut chosen_idx = 0;
        for (idx, (_id, power)) in pool.iter().enumerate() {
            acc = acc.saturating_add(*power);
            if ticket < acc {
                chosen_idx = idx;
                break;
            }
        }
        let (winner_id, winner_power) = pool.remove(chosen_idx);
        total_power = total_power.saturating_sub(winner_power);
        selected.push(winner_id);
    }
    selected.sort_unstable();
    selected
}

fn legacy_proposer_ref(validators: &ValidatorSet, digest: &[u8; 32]) -> Option<ValidatorId> {
    let total = validators.total_power();
    if total == 0 {
        return None;
    }
    let g = validators
        .validators
        .values()
        .fold(0u64, |acc, &p| gcd(acc, p));
    let g = if g == 0 { 1 } else { g };
    let range = total / g;
    let slot = u64::from_le_bytes(digest[..8].try_into().unwrap()) % range;
    let mut ids: Vec<(&ValidatorId, &u64)> = validators.validators.iter().collect();
    ids.sort_unstable();
    let mut acc = 0u64;
    for (id, power) in ids {
        acc = acc.saturating_add(*power / g);
        if slot < acc {
            return Some(*id);
        }
    }
    validators.validators.keys().next().copied()
}

fn unbiased_proposer_ref(validators: &ValidatorSet, digest: &[u8; 32]) -> Option<ValidatorId> {
    let total = validators.total_power();
    if total == 0 {
        return None;
    }
    let g = validators
        .validators
        .values()
        .fold(0u64, |acc, &p| gcd(acc, p));
    let g = if g == 0 { 1 } else { g };
    let range = total / g;
    let modulus = range as u128;
    let limit = (1u128 << 64) - ((1u128 << 64) % modulus);
    let mut slot = 0u64;
    let mut found = false;
    let mut last_rand = 0u64;
    for attempt in 0..64u32 {
        let mut hasher = blake3::Hasher::new_derive_key(PROPOSER_UNBIASED_DOMAIN);
        hasher.update(digest);
        hasher.update(&attempt.to_le_bytes());
        let hash = hasher.finalize();
        let rand_val = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap());
        last_rand = rand_val;
        if (rand_val as u128) < limit {
            slot = ((rand_val as u128) % modulus) as u64;
            found = true;
            break;
        }
    }
    if !found {
        slot = ((last_rand as u128) % modulus) as u64;
    }
    let mut ids: Vec<(&ValidatorId, &u64)> = validators.validators.iter().collect();
    ids.sort_unstable();
    let mut acc = 0u64;
    for (id, power) in ids {
        acc = acc.saturating_add(*power / g);
        if slot < acc {
            return Some(*id);
        }
    }
    validators.validators.keys().next().copied()
}

#[test]
fn sortition_unbiased_and_jail_budget_v2_gates_default_inert_and_registered() {
    let _guard = GateResetGuard;

    assert_eq!(SORTITION_UNBIASED_ACTIVATION_HEIGHT, u64::MAX);
    assert_eq!(JAIL_BUDGET_V2_ACTIVATION_HEIGHT, u64::MAX);
    assert_eq!(sortition_unbiased_activation_height(), u64::MAX);
    assert_eq!(jail_budget_v2_activation_height(), u64::MAX);

    for h in [0, 1, 1_000, u64::MAX - 1, u64::MAX] {
        assert!(!sortition_unbiased_active_at(h));
        assert!(!jail_budget_v2_active_at(h));
        assert_eq!(downtime_miss_threshold_at(h), DOWNTIME_MISS_THRESHOLD);
    }

    assert_eq!(DOWNTIME_MISS_THRESHOLD, 42);
    assert_eq!(DOWNTIME_MISS_THRESHOLD_V2, 200);

    let schedule = current_activation_schedule();
    for (name, expected_height) in [
        (
            "SORTITION_UNBIASED_ACTIVATION_HEIGHT",
            SORTITION_UNBIASED_ACTIVATION_HEIGHT,
        ),
        (
            "JAIL_BUDGET_V2_ACTIVATION_HEIGHT",
            JAIL_BUDGET_V2_ACTIVATION_HEIGHT,
        ),
    ] {
        let gate = schedule
            .gates
            .iter()
            .find(|g| g.name == name)
            .unwrap_or_else(|| {
                panic!("{name} must be registered in current_activation_schedule()")
            });
        assert_eq!(gate.activation_height, expected_height);
        assert_eq!(gate.status, ActivationStatus::GatedOff);
        assert_eq!(schedule.is_active(name, 0), Some(false));
        assert_eq!(schedule.is_active(name, u64::MAX), Some(false));
    }

    let table = feature_gates::table();
    for (id, symbol) in [
        ("sortition-unbiased", "SORTITION_UNBIASED_ACTIVATION_HEIGHT"),
        ("jail-budget-v2", "JAIL_BUDGET_V2_ACTIVATION_HEIGHT"),
    ] {
        let row = table
            .iter()
            .find(|g| g.id == id)
            .unwrap_or_else(|| panic!("{id} must be registered in feature_gates::table()"));
        assert_eq!(row.symbol, symbol);
        assert_eq!(row.value, u64::MAX);
        assert_eq!(row.status(), "INERT");
        assert_eq!(
            row.test,
            Some("tests/w10_sortition_and_jail_gates_tests.rs")
        );
    }
}

#[test]
fn sortition_unbiased_h_minus_1_vs_h_committee_and_proposer() {
    let _guard = GateResetGuard;
    const H: u64 = 1_500;
    set_sortition_unbiased_activation_override(Some(H));

    // Non-power-of-two validator stakes: total = 3 + 5 + 7 + 11 + 13 = 39 (gcd = 1).
    let mut vs = ValidatorSet::new();
    vs.add(vid(1), 3);
    vs.add(vid(2), 5);
    vs.add(vid(3), 7);
    vs.add(vid(4), 11);
    vs.add(vid(5), 13);
    let parent = [0xAB; 32];

    for round in 0..16u32 {
        let seed_pre = sortition_seed(&parent, H - 1, round);
        let pre_from_seed =
            select_committee_from_seed_at(&vs, 3, SORTITION_DRAW_DOMAIN, &seed_pre, H - 1);
        let pre_derive = derive_sortition_committee(&vs, H - 1, round, 3, &parent);
        let pre_derive_at = derive_sortition_committee_at(&vs, H - 1, round, 3, &parent);
        let pre_sched = committee_for_height(
            &vs,
            H - 1,
            round,
            3,
            Some(&parent),
            CommitteeSchedule::ParentHash,
        );
        let expected_legacy = legacy_committee_ref(&vs, 3, SORTITION_DRAW_DOMAIN, &seed_pre);
        assert_eq!(pre_from_seed, expected_legacy);
        assert_eq!(pre_derive, expected_legacy);
        assert_eq!(pre_derive_at, expected_legacy);
        assert_eq!(pre_sched, expected_legacy);

        let seed_post = sortition_seed(&parent, H, round);
        let post_from_seed =
            select_committee_from_seed_at(&vs, 3, SORTITION_DRAW_DOMAIN, &seed_post, H);
        let post_derive = derive_sortition_committee(&vs, H, round, 3, &parent);
        let post_derive_at = derive_sortition_committee_at(&vs, H, round, 3, &parent);
        let post_sched = committee_for_height(
            &vs,
            H,
            round,
            3,
            Some(&parent),
            CommitteeSchedule::ParentHash,
        );
        let expected_unbiased = unbiased_committee_ref(&vs, 3, SORTITION_DRAW_DOMAIN, &seed_post);
        assert_eq!(post_from_seed, expected_unbiased);
        assert_eq!(post_derive, expected_unbiased);
        assert_eq!(post_derive_at, expected_unbiased);
        assert_eq!(post_sched, expected_unbiased);

        // Proposer selection at H-1 vs H.
        let mut digest = [0u8; 32];
        digest[0..4].copy_from_slice(&round.to_le_bytes());
        digest[4] = 0x7E;
        assert_eq!(
            vs.proposer_from_digest_at(&digest, H - 1),
            legacy_proposer_ref(&vs, &digest)
        );
        assert_eq!(
            vs.proposer_from_digest_at(&digest, H),
            unbiased_proposer_ref(&vs, &digest)
        );

        let mut ph = blake3::Hasher::new_derive_key("STELL_PROPOSER_V1");
        ph.update(&(H - 1).to_le_bytes());
        ph.update(&round.to_le_bytes());
        assert_eq!(
            vs.proposer_for(H - 1, round),
            legacy_proposer_ref(&vs, ph.finalize().as_bytes())
        );

        let mut ph_post = blake3::Hasher::new_derive_key("STELL_PROPOSER_V1");
        ph_post.update(&H.to_le_bytes());
        ph_post.update(&round.to_le_bytes());
        assert_eq!(
            vs.proposer_for(H, round),
            unbiased_proposer_ref(&vs, ph_post.finalize().as_bytes())
        );
    }
}

#[test]
fn sortition_unbiased_rejection_actually_retries_above_limit() {
    let _guard = GateResetGuard;
    const H: u64 = 2_000;
    set_sortition_unbiased_activation_override(Some(H));

    // Construct a validator set with non-power-of-two total_power = (1 << 63) + 1
    // so almost half of all 64-bit draws fall >= limit and MUST be rejected on
    // attempt 0, proving the rejection loop advances to attempt >= 1.
    let v1 = vid(10);
    let v2 = vid(20);
    let p1 = (1u64 << 63) - 10;
    let p2 = 11u64;
    let total = p1 + p2; // (1 << 63) + 1
    assert_eq!(total, (1u64 << 63) + 1);
    let modulus = total as u128;
    let limit = (1u128 << 64) - ((1u128 << 64) % modulus);
    assert_eq!(limit, modulus);

    let mut vs = ValidatorSet::new();
    vs.add(v1, p1);
    vs.add(v2, p2);

    // Deterministically find a digest whose attempt 0 is >= limit (rejected) and
    // attempt 1 is < limit (accepted).
    let mut chosen_digest = None;
    for candidate in 0u64..1024 {
        let mut d = [0u8; 32];
        d[0..8].copy_from_slice(&candidate.to_le_bytes());
        let draw = |attempt: u32| -> u64 {
            let mut h = blake3::Hasher::new_derive_key(PROPOSER_UNBIASED_DOMAIN);
            h.update(&d);
            h.update(&attempt.to_le_bytes());
            u64::from_le_bytes(h.finalize().as_bytes()[0..8].try_into().unwrap())
        };
        let r0 = draw(0);
        let r1 = draw(1);
        if (r0 as u128) >= limit && (r1 as u128) < limit && (r0 % total) != (r1 % total) {
            chosen_digest = Some((d, r1 % total));
            break;
        }
    }
    let (digest, expected_slot) = chosen_digest.expect("must find a digest rejected on attempt 0");
    let expected_proposer = if expected_slot < p1 { v1 } else { v2 };
    assert_eq!(
        vs.proposer_from_digest_at(&digest, H),
        Some(expected_proposer)
    );
    assert_eq!(
        vs.proposer_from_digest_at(&digest, H),
        unbiased_proposer_ref(&vs, &digest)
    );

    // Same proof for committee sortition: find a seed whose step-0 attempt 0 is >= limit.
    let mut chosen_seed = None;
    for candidate in 0u64..1024 {
        let mut s = [0u8; 32];
        s[0..8].copy_from_slice(&candidate.to_le_bytes());
        let draw = |attempt: u32| -> u64 {
            let mut h = blake3::Hasher::new_derive_key(SORTITION_DRAW_DOMAIN);
            h.update(&s);
            h.update(&0u32.to_le_bytes());
            h.update(&attempt.to_le_bytes());
            u64::from_le_bytes(h.finalize().as_bytes()[0..8].try_into().unwrap())
        };
        let r0 = draw(0);
        let r1 = draw(1);
        if (r0 as u128) >= limit && (r1 as u128) < limit {
            chosen_seed = Some(s);
            break;
        }
    }
    let seed = chosen_seed.expect("must find a seed rejected on attempt 0");
    assert_eq!(
        select_committee_from_seed_at(&vs, 1, SORTITION_DRAW_DOMAIN, &seed, H),
        unbiased_committee_ref(&vs, 1, SORTITION_DRAW_DOMAIN, &seed)
    );
}

#[test]
fn jail_budget_v2_h_minus_1_jails_at_42_and_h_jails_at_200() {
    let _guard = GateResetGuard;
    const H: u64 = 1_000;
    set_jail_budget_v2_activation_override(Some(H));

    // Pre-activation (< H): 42 missed heights slashes and jails immediately.
    let honest = vid(1);
    let offline = vid(2);
    let bond = MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER;
    let mut pre_ledger = StakingLedger::new();
    pre_ledger
        .bond(honest, bond, DEFAULT_COMMISSION_BPS)
        .unwrap();
    pre_ledger
        .bond(offline, bond, DEFAULT_COMMISSION_BPS)
        .unwrap();
    let eligible = vec![honest, offline];
    let signer = |v: &ValidatorId| *v == honest;

    for h in 1..DOWNTIME_MISS_THRESHOLD as u64 {
        assert_eq!(pre_ledger.note_missed_heights(h, &signer, &eligible), 0);
        assert!(!pre_ledger.is_jailed(&offline));
    }
    let pre_burned =
        pre_ledger.note_missed_heights(DOWNTIME_MISS_THRESHOLD as u64, &signer, &eligible);
    assert_eq!(pre_burned, bond * DOWNTIME_SLASH_BPS / 10_000);
    assert!(pre_ledger.is_jailed(&offline));
    let pre_jail = pre_ledger.jail_record(&offline).unwrap();
    assert_eq!(pre_jail.jailed_at_height, DOWNTIME_MISS_THRESHOLD as u64);
    assert_eq!(
        pre_jail.release_height,
        DOWNTIME_MISS_THRESHOLD as u64 + JAIL_RELEASE_DELAY_HEIGHTS
    );

    // Post-activation (>= H): missing 42..=199 blocks does NOT jail; 200th block
    // slashes and jails cleanly.
    let mut post_ledger = StakingLedger::new();
    post_ledger
        .bond(honest, bond, DEFAULT_COMMISSION_BPS)
        .unwrap();
    post_ledger
        .bond(offline, bond, DEFAULT_COMMISSION_BPS)
        .unwrap();

    for offset in 0..(DOWNTIME_MISS_THRESHOLD_V2 as u64 - 1) {
        let height = H + offset;
        assert_eq!(downtime_miss_threshold_at(height), 200);
        let burned = post_ledger.note_missed_heights(height, &signer, &eligible);
        assert_eq!(
            burned,
            0,
            "must NOT slash/jail at height {height} (miss #{})",
            offset + 1
        );
        assert!(
            !post_ledger.is_jailed(&offline),
            "must NOT jail at miss #{}",
            offset + 1
        );
        assert_eq!(post_ledger.validators[&offline].missed, (offset + 1) as u32);
    }

    // Confirm specifically at miss #42 and miss #199 no jail occurred.
    assert_eq!(post_ledger.validators[&offline].missed, 199);
    assert!(!post_ledger.is_jailed(&offline));
    assert_eq!(post_ledger.validators[&offline].self_bond, bond);

    // 200th missed block at H + 199 triggers slash + jail.
    let slash_height = H + (DOWNTIME_MISS_THRESHOLD_V2 as u64 - 1);
    let post_burned = post_ledger.note_missed_heights(slash_height, &signer, &eligible);
    assert_eq!(post_burned, bond * DOWNTIME_SLASH_BPS / 10_000);
    assert!(post_ledger.is_jailed(&offline));
    assert_eq!(post_ledger.validators[&offline].missed, 0);
    assert!(!post_ledger.is_jailed(&honest));
    let post_jail = post_ledger.jail_record(&offline).unwrap();
    assert_eq!(post_jail.jailed_at_height, slash_height);
    assert_eq!(
        post_jail.release_height,
        slash_height + JAIL_RELEASE_DELAY_HEIGHTS
    );
}

#[test]
fn jail_budget_v2_crossing_boundary_with_41_pre_misses_waits_for_200() {
    let _guard = GateResetGuard;
    const H: u64 = 1_000;
    set_jail_budget_v2_activation_override(Some(H));

    let honest = vid(11);
    let offline = vid(12);
    let bond = MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER;
    let mut ledger = StakingLedger::new();
    ledger.bond(honest, bond, DEFAULT_COMMISSION_BPS).unwrap();
    ledger.bond(offline, bond, DEFAULT_COMMISSION_BPS).unwrap();
    let eligible = vec![honest, offline];
    let signer = |v: &ValidatorId| *v == honest;

    // 41 misses below H: H - 41 ..= H - 1.
    for h in (H - 41)..H {
        assert_eq!(ledger.note_missed_heights(h, &signer, &eligible), 0);
    }
    assert_eq!(ledger.validators[&offline].missed, 41);
    assert!(!ledger.is_jailed(&offline));

    // Miss #42 lands at H (post-activation): threshold is now 200, so NO slash/jail.
    assert_eq!(ledger.note_missed_heights(H, &signer, &eligible), 0);
    assert_eq!(ledger.validators[&offline].missed, 42);
    assert!(!ledger.is_jailed(&offline));

    // Remaining misses up to 199 do not jail (41 pre-H + 1 at H + 157 at H+1..=H+157 = 199).
    for offset in 1..(200 - 42) {
        assert_eq!(
            ledger.note_missed_heights(H + offset, &signer, &eligible),
            0
        );
        assert!(!ledger.is_jailed(&offline));
    }
    assert_eq!(ledger.validators[&offline].missed, 199);

    // Miss #200 at H + 158 slashes and jails.
    let burned = ledger.note_missed_heights(H + 158, &signer, &eligible);
    assert_eq!(burned, bond * DOWNTIME_SLASH_BPS / 10_000);
    assert!(ledger.is_jailed(&offline));
}

#[tokio::test]
async fn jail_budget_v2_state_engine_apply_downtime_slash_respects_height_gate() {
    let _guard = GateResetGuard;
    const H: u64 = 1_000;
    set_jail_budget_v2_activation_override(Some(H));

    let keys: Vec<SigningKey> = (1..=4).map(|s| SigningKey::from_bytes(&[s; 32])).collect();
    let ids: Vec<ValidatorId> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let offline_id = ids[1];
    let bond = MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER;

    let engine = InMemoryStateEngine::new();
    for id in &ids {
        engine.credit_native(id, bond * 2).await.unwrap();
        engine
            .staking_write()
            .await
            .bond(*id, bond, DEFAULT_COMMISSION_BPS)
            .unwrap();
    }
    engine.credit_native(&STAKING_POOL, bond * 4).await.unwrap();

    let vs = engine.staking_read().await.to_validator_set();
    let fks: Vec<FalconKeypair> = (0..4)
        .map(|i| {
            let fk = FalconKeypair::generate_from_seed(0xD0 + i as u8);
            register_validator_pq_key(ids[i], PqScheme::Falcon512, fk.public_key.clone());
            fk
        })
        .collect();

    let mut vote_set = VoteSet::new();
    for &i in &[0usize, 2, 3] {
        let v = Vote::sign_with_falcon(
            &keys[i],
            &fks[i],
            1,
            0,
            VoteKind::Precommit,
            Some([0xBB; 32]),
        );
        vote_set
            .add(v, &vs, 1, 0, VoteKind::Precommit)
            .expect("falcon vote must ingest");
    }
    let qc = vote_set
        .certificate_with_parent(Some([0xBB; 32]), &vs, Some(&[0u8; 32]))
        .expect("3-of-4 must compile a Falcon uQC");
    assert!(qc.verify(&vs));

    // At H..H+198 (199 misses), state engine must NOT slash or jail.
    for offset in 0..199u64 {
        let burned = engine.apply_downtime_slash(H + offset, Some(&qc)).await;
        assert_eq!(burned, 0);
        assert!(!engine.staking_read().await.is_jailed(&offline_id));
    }

    // At H + 199 (200th miss), state engine slashes and jails cleanly.
    let burned = engine.apply_downtime_slash(H + 199, Some(&qc)).await;
    assert!(burned > 0);
    let ledger = engine.staking_read().await;
    assert!(ledger.is_jailed(&offline_id));
    assert_eq!(ledger.validators[&offline_id].missed, 0);
    assert_eq!(
        ledger.jail_record(&offline_id).unwrap().jailed_at_height,
        H + 199
    );
}
