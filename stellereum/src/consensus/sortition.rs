use super::types::{Height, Round, ValidatorId, ValidatorSet};

/// Consensus-domain quorum floor: `floor(2n/3) + 1` votes (or voting power)
/// out of `n`.
///
/// FREEZE (protocol freeze 2026-11-03): value = BFT safety curve, no env knob
/// ever existed. Change requires spec update + audit note (AGENTS.md §7).
///
/// Domain: PBFT/PQ-BFT finality. It is deliberately NOT the bridge threshold
/// [`crate::bridge::quorum_threshold`] (`floor((2n+2)/3)`, floored at 1): that
/// counts DISTINCT signers of an external cross-chain signer set. The two
/// curves MUST still live in separate functions with separate pins
/// (`bridge::tests::quorum_formulas_are_pinned_per_domain` pins both value
/// lists for n = 1..8), but the safety narrative is exactly the paper result
/// (`papers/01_quorum.md` §3, Theorem 2): under the STRICT threat model
/// `B_w < W/3` the bridge curve `ceil(2n/3)` is the MINIMUM safe threshold
/// `t*(n)`, and this consensus curve `floor(2n/3)+1` coincides with it except
/// at `n % 3 == 0`, where it is exactly one vote MORE conservative. That +1
/// is a deliberate margin, and it is REQUIRED (not redundant) if the model
/// ever admits `B_w = n/3` exactly: at `2t - W = 0` the `ceil` curve stops
/// intersecting honestly (paper §3, Oговорка). So: bridge = exact optimum
/// under `B < W/3`; consensus = optimum + one-vote margin at `3|n`, kept so
/// both the strict and the non-strict model stay safe.
pub fn consensus_quorum_min(n: u64) -> u64 {
    // Audit F4: u128 arithmetic — `(n*2)` panics in debug / wraps in release
    // at absurd powers, and saturating would UNDERESTIMATE the quorum
    // (weakening it). floor(2n/3)+1 always fits u64, computed exactly.
    ((n as u128 * 2) / 3 + 1) as u64
}

/// Strict quorum threshold for micro-committee of size k: floor(2*k/3) + 1.
///
/// FREEZE (protocol freeze 2026-11-03): same consensus-domain curve as
/// [`consensus_quorum_min`]. Change requires spec update + audit note.
///
/// Same consensus-domain curve as [`consensus_quorum_min`]; a zero-size
/// committee is unrepresentable as a real threshold, so it fails closed with
/// `usize::MAX` instead of the formula's 1.
///
/// LEGACY head-count curve: kept for wire/backward-compat inspection and
/// pinned by `bridge::tests::quorum_formulas_are_pinned_per_domain`. Live
/// µQC VERIFICATION does not gate on this anymore — it sums committee voting
/// power against [`pq_micro_quorum_power`].
pub fn pq_micro_quorum_threshold(committee_size: u32) -> usize {
    if committee_size == 0 {
        return usize::MAX;
    }
    consensus_quorum_min(committee_size as u64) as usize
}

/// Power-weighted quorum threshold for a micro-committee: `floor(2*W/3) + 1`
/// over the committee's total voting power `W`.
///
/// FREEZE (protocol freeze 2026-11-03): the LIVE µQC rule. Change requires
/// spec update + audit note (AGENTS.md §7).
///
/// This is the LIVE µQC rule (classical BFT accounting applied to the
/// sortition committee): the verifier sums the powers of the committee
/// members with valid signatures and requires `>=` this value. A zero-power
/// committee is unrepresentable as a real threshold, so it fails closed with
/// `u64::MAX` — exactly like [`ValidatorSet::quorum_power`] for the empty
/// set — and can never be satisfied.
pub fn pq_micro_quorum_power(committee_total_power: u64) -> u64 {
    if committee_total_power == 0 {
        return u64::MAX;
    }
    consensus_quorum_min(committee_total_power)
}

/// Maximum size of the sortition micro-committee (µQC).
///
/// AUDIT W6.5 (committee capture): the cap was hard-coded to `16` in TWO
/// places (the µQC compiler and the µQC verifier). A single, named constant
/// removes the fork hazard of the two drifting apart, and the value itself is
/// raised because a 16-seat committee is a very weak finality target — see
/// [`micro_committee_size`] and [`pq_micro_required_power`].
///
/// 128 seats x 666 B ≈ 85 KB per µQC. The seat count is NOT sized for
/// bandwidth anymore: it is sized for CAPTURE RESISTANCE. Under the
/// conservative with-replacement model (`X ~ Bin(k, α)`, `α = 1/3`) the
/// Chernoff bound `P[X > 2k/3] ≤ exp(−k·D(2/3‖1/3))` with
/// `D(2/3‖1/3) = (1/3)·ln 2 ≈ 0.2310` gives `k ≥ 105` for `2^-40`
/// (`papers/01_quorum.md` §5, `results/q_quorum.json`); `k = 128` clears it
/// with margin (`exp(−128·0.2310) ≈ 1.4e−13 ≈ 2^−42.6`), while `k = 64` only
/// reached ≈ 2^−25 — NOT cryptographically negligible. Capture alone still
/// does not grant finality (the network-anchored quorum of
/// [`pq_micro_required_power`] holds regardless), but a captured committee
/// can censor/sabotage the fast path, so the seats are cheap insurance.
pub const MICRO_COMMITTEE_MAX_SIZE: u32 = 128;

/// Size of the µQC sortition committee for a validator set of `n` members.
///
/// AUDIT W6.5 — WHY THIS IS NOT A CONSTANT:
///
/// The µQC is a *sample* of the validator set, so its finality threshold is
/// `(2/3) x (the committee's share of the network's stake)`. With a fixed
/// 16-seat committee and N = 100 uniformly staked validators, the committee
/// holds only ~16% of the network's stake, so a µQC could be forged by an
/// attacker holding ~11% of the stake (2/3 of 16%) — a ~6x weakening of the
/// network's own 2/3 threshold, and a straight break of the "an attacker with
/// < 1/3 of the stake cannot finalize a block" invariant.
///
/// The seat count is therefore raised to 128 (still `min(N, ...)`): capture
/// resistance, not bandwidth, sizes it — `k = 128` clears the `2^-40` bound
/// (`k ≥ 105` at `α = 1/3`, `papers/01_quorum.md` §5) with margin, and the
/// NETWORK-ANCHORED quorum rule ([`pq_micro_required_power`]) then demands
/// TWO THIRDS of the *network's* stake, not just of the committee's.
///
/// While `N <= MICRO_COMMITTEE_MAX_SIZE` the committee IS the whole validator
/// set (see [`derive_sortition_committee`]): the µQC threshold is then exactly
/// the network threshold and the two-tier finality is indistinguishable from a
/// single-tier one. That is the live configuration (N = 4).
pub fn micro_committee_size(validator_count: usize) -> u32 {
    validator_count.min(MICRO_COMMITTEE_MAX_SIZE as usize) as u32
}

/// µQC quorum threshold in voting POWER: the value the signers' summed power
/// must reach for the certificate to be accepted.
///
/// AUDIT W6.5 (committee capture) + P1 (quorum intersection) — the rule is
///
/// ```text
/// required = max( floor(2 * W_committee / 3) + 1,      // the committee's own 2/3
///                  floor(2 * W_network / 3) + 1 )       // the NETWORK's 2/3 (BFT floor)
/// ```
///
/// The second term is what makes a µQC safe to accept as a FINALITY
/// certificate on its own. Paper `papers/01_quorum.md` §4, Theorems 1–4: a
/// threshold `t` is safe against Byzantine weight `B_w` iff `2t − W > B_w`.
/// The OLD network term `floor(W_network/2) + 1` gives `2T − W ∈ {1, 2}`, so
/// ANY `B_w ≥ 2` breaks it — even though it is a strict majority of the
/// network. Counterexample (`results/q_quorum.json → weighted.explicit_attack`,
/// `W = 100, B = 32`): two conflicting 51-power certs (32 Byzantine + 19
/// honest each, all-Byzantine intersection) BOTH pass `51 = floor(100/2)+1`.
/// Strict majority does NOT imply quorum intersection; only `2t − W > B_w`
/// does. The network term is therefore the same BFT curve as
/// [`consensus_quorum_min`]: `floor(2·W_network/3) + 1`.
///
/// Cross-level safety (paper §4, Corollary 3): with the network term at the
/// BFT floor, a mixed pair (µQC at `T_µ`, full QC at `T_f = floor(2W/3)+1`)
/// satisfies `T_µ + T_f − W ≥ 2·T_f − W > B_w` for every `B_w < W/3`, so no
/// conflicting µQC/full-QC pair can both verify. Enforced fail-closed by
/// [`mixed_quorum_pair_safe`], checked in `verify_micro_cert`.
///
/// * Because the floor is anchored to the NETWORK, a committee that cannot
///   reach it (a small committee of a large network) is REFUSED outright
///   rather than silently accepted at a weakened threshold. The µQC is only
///   an accelerator: the full Ed25519 QC path stays authoritative, so
///   refusing a µQC costs bandwidth, never liveness.
///
/// Compatibility: when the committee is the whole validator set (N <= the
/// committee cap — the live N = 4 network and the N <= 16 test fixtures) the
/// two terms coincide with the old `floor(2W/3)+1` rule, so historic
/// certificates verify byte-for-byte unchanged.
pub fn pq_micro_required_power(committee_total_power: u64, network_total_power: u64) -> u64 {
    if committee_total_power == 0 {
        return u64::MAX;
    }
    let committee_two_thirds = consensus_quorum_min(committee_total_power);
    let network_two_thirds = match network_total_power {
        0 => u64::MAX,
        w => consensus_quorum_min(w),
    };
    committee_two_thirds.max(network_two_thirds)
}

/// C1 split activation height (FIXES §1.7, sketch §4.1, formulas §2.3).
///
/// At/after this height the µQC is ADVISORY-ONLY and never finalizes: the
/// µQC branch of finality verification refuses outright and finality
/// requires the FULL network QC (`pq_full_required_power` over the network's
/// total power, enforced on the epoch/CEC path). Before this height the
/// legacy network-anchored `max` rule ([`pq_micro_required_power`]) applies
/// byte-identically.
///
/// INACTIVE default (`u64::MAX`, unreachable): the lead flips it via
/// governance rollout. Pre-activation behavior is unchanged — proven by the
/// existing QC pins running green unmodified.
pub const QC_SPLIT_ACTIVATION_HEIGHT: u64 = u64::MAX;

/// True once the C1 advisory/finality split is active at `height`.
#[allow(clippy::absurd_extreme_comparisons)]
// GATE: `QC_SPLIT_ACTIVATION_HEIGHT` is deliberately `u64::MAX` (INACTIVE
// default, flipped only by the lead); `>=` is the correct activation
// semantics once it names a reachable height.
pub(super) fn qc_split_active_at(height: Height) -> bool {
    height >= QC_SPLIT_ACTIVATION_HEIGHT
}

/// Advisory µQC threshold (sketch §4.1): `floor(2*W_committee/3) + 1`.
///
/// ADVISORY ONLY — reaching this never finalizes a block. It measures the
/// committee's own two-thirds so a small committee of a large network can
/// still signal (liveness), while finality stays gated on
/// [`pq_full_required_power`]. Fail-closed (`u64::MAX`) on zero committee
/// power, exactly like [`pq_micro_quorum_power`].
pub fn pq_micro_advisory_power(committee_total_power: u64) -> u64 {
    if committee_total_power == 0 {
        return u64::MAX;
    }
    consensus_quorum_min(committee_total_power)
}

/// Finality gate (sketch §4.1): `floor(2*W_network/3) + 1` over the NETWORK.
///
/// Post-activation every finality path requires THIS — never
/// `max(committee, network)`, which is the documented liveness trap: when
/// `W_c < floor(2*W_n/3)+1` the committee alone can never reach the max, so
/// no µQC ever forms. Fail-closed (`u64::MAX`) on zero network power,
/// exactly like [`ValidatorSet::quorum_power`] — the same curve the
/// epoch/CEC finality path already enforces.
pub fn pq_full_required_power(network_total_power: u64) -> u64 {
    if network_total_power == 0 {
        return u64::MAX;
    }
    consensus_quorum_min(network_total_power)
}

/// Fail-closed cross-tier intersection gate: a µQC threshold `t_micro` and a
/// full-QC threshold `t_full` over the same total power `total` can only both
/// certify conflicting blocks if their signer sets can avoid sharing an
/// honest validator. By the inclusion–exclusion lemma
/// (`papers/01_quorum.md` §2, Lemma 1) the guaranteed intersection weight is
/// `t_micro + t_full − total`, so the pair is safe against Byzantine weight
/// up to `total/3` (the strict `B_w < W/3` model, conservative integer form)
/// iff `t_micro + t_full > total + total/3`.
///
/// Returns `false` (refuse) on any degenerate input — zero total, or a
/// threshold at/above the `u64::MAX` fail-closed sentinel — so a caller that
/// wires this in can never accept on missing data. `u128` arithmetic: no
/// overflow at any `u64` input.
///
/// Pins: `(51, 67, 100) → false` (the `W=100, B=32` mixed attack:
/// `51 + 67 − 100 = 18 ≤ 33`), `(67, 67, 100) → true`
/// (`67 + 67 − 100 = 34 > 33`).
pub fn mixed_quorum_pair_safe(t_micro: u64, t_full: u64, total_power: u64) -> bool {
    if total_power == 0 || t_micro == u64::MAX || t_full == u64::MAX {
        return false;
    }
    let (t_mu, t_f, w) = (t_micro as u128, t_full as u128, total_power as u128);
    t_mu + t_f > w + w / 3
}

/// Deterministic BLAKE3 sortition committee selector.
///
/// Selects a subset of validators of size `committee_size` weighted proportionally
/// by validator stake (voting power), without replacement.
/// The resulting committee is returned in canonical sorted order.
///
/// ENTROPY (audit: predictable committee selection). The draw is seeded with
/// the PARENT BLOCK HASH — the hash of the block at `height - 1`, i.e. the
/// `prev_hash` committed in the header of the block at `height`. Without it
/// the ticket for `(height, round, step)` was a pure function of the height
/// and the round, so anybody could compute the committee for every future
/// height ahead of time and aim a DDoS (or a collusion) at a chosen round.
/// With the parent hash in the preimage the committee for a height is only
/// knowable once its parent exists, and it changes completely if the parent
/// changes (a fork re-elects a different committee).
///
/// The seed is `BLAKE3("STELL_SORTITION_V5" || prev_block_hash || height ||
/// round)` and each ticket is `BLAKE3("STELL_SORTITION_V5" || seed || step)`.
///
/// AGREEMENT: every validator of a height MUST pass the SAME parent hash —
/// the one committed in the block header — or they elect different
/// committees and cannot agree on a certificate. The parent hash travels
/// with the certificate ([`PqMicroCertificate::sortition_parent`]) so a
/// verifier re-derives exactly the committee the builders used.
///
/// RESIDUAL RISK — GRINDING (audit W6.5, NOT closed by the parent hash):
/// the parent hash makes the committee UNKNOWABLE IN ADVANCE (nobody can
/// compute the committee of a future height before its parent exists), but
/// it is not UNFORGEABLE: the proposer of the parent block chooses the
/// parent's bytes, hence its hash, hence the committee of the next height.
/// A proposer that can vary the parent hash (a nonce, a timestamp, the tx
/// set) can therefore SEARCH for a favourable committee: each candidate
/// parent hash is a fresh sortition draw, and BLAKE3 is cheap enough
/// (10^9+ draws/s on a GPU) that a capture is a matter of minutes, not
/// years, for an attacker who controls a meaningful share of the set.
///
/// The parent hash is therefore NOT the security boundary — the
/// NETWORK-ANCHORED QUORUM is (see [`pq_micro_required_power`]): a µQC must
/// carry two-thirds of the WHOLE network's stake, so grinding for a
/// favourable committee does not lower the bar an attacker has to clear.
/// Grinding can only pick WHICH honest validators are asked to sign, not
/// manufacture the 2/3-of-the-network the certificate needs. A VRF-based
/// (ungrindable) selection would remove the grinding surface entirely; that
/// is the structural fix and is out of scope here.
///
/// Canonical parent-hash sortition committee selector (v5 draw, byte-pinned).
pub fn derive_sortition_committee(
    validators: &ValidatorSet,
    height: Height,
    round: Round,
    committee_size: u32,
    prev_block_hash: &[u8; 32],
) -> Vec<ValidatorId> {
    if committee_size == 0 || validators.is_empty() || validators.total_power() == 0 {
        return Vec::new();
    }

    // Filter positive-power validators in canonical sorted order (BTreeMap order)
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
    let mut total_power: u64 = pool.iter().map(|(_, p)| *p).sum();

    // Per-(height, round) seed: the parent block hash is the only entropy
    // that is not known before the chain reaches this height.
    let seed = sortition_seed(prev_block_hash, height, round);

    for step in 0..target_k {
        if total_power == 0 || pool.is_empty() {
            break;
        }

        let mut hasher = blake3::Hasher::new_derive_key(SORTITION_DRAW_DOMAIN);
        hasher.update(&seed);
        hasher.update(&(step as u32).to_le_bytes());
        let hash = hasher.finalize();

        let rand_val = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap());
        let ticket = rand_val % total_power;

        let mut acc = 0u64;
        let mut chosen_idx = 0;
        for (idx, (_id, power)) in pool.iter().enumerate() {
            acc += *power;
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

/// Domain separator of the sortition draw (v5 = parent-block entropy).
///
/// Bumped from `STELL_SORTITION_V4` (which hashed `height || round || step`
/// only) so a v5 draw can never be confused with a v4 one.
pub const SORTITION_DRAW_DOMAIN: &str = "STELL_SORTITION_V5";

/// The per-`(height, round)` sortition seed: `BLAKE3("STELL_SORTITION_V5" ||
/// prev_block_hash || height || round)`.
///
/// Exposed so a verifier can prove that two nodes derived the same seed
/// (and therefore the same committee) without re-running the whole draw.
pub fn sortition_seed(prev_block_hash: &[u8; 32], height: Height, round: Round) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SORTITION_DRAW_DOMAIN);
    hasher.update(prev_block_hash);
    hasher.update(&height.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    *hasher.finalize().as_bytes()
}

// ============================================================================
// BEACON DRAW (gated-OFF; parent-hash draw above stays the live default)
// ============================================================================
//
// The parent-hash draw (`derive_sortition_committee`) is grindable: the
// proposer of the parent block chooses its bytes, hence its hash, hence the
// next committee (papers/13_grinding_and_structural_capture.md §A — `1/P_cap`
// is ~0.03 s classically at `k=64`). The structural fix is an ungrindable
// beacon draw seeded by the epoch-bound XMSS-VRF output (`crate::xmss_vrf`,
// sibling workstream: one leaf per epoch, re-signing an epoch burns the leaf
// and is slashable, so the beacon cannot be re-rolled).
//
// This region is PURE draw logic, gated OFF by default:
// [`BEACON_DRAW_ACTIVATION_HEIGHT`] is `u64::MAX`, so
// [`beacon_draw_active_at`] is false at every reachable height and NO caller
// switches draws until the lead flips the constant at rollout. The two live
// call sites that would swap (`micro_cert_valid_signers`,
// `verify_micro_cert`) keep calling `derive_sortition_committee` unchanged.
// Tests below pin the parent-hash draw green unmodified alongside the new one.

/// Activation height of the beacon draw: `u64::MAX` = never (gated OFF).
///
/// The lead flips this to a real height at rollout; until then the
/// parent-hash draw stays the live default and this draw is test-only.
pub const BEACON_DRAW_ACTIVATION_HEIGHT: u64 = u64::MAX;

/// Domain separator of the beacon draw. Distinct from
/// [`SORTITION_DRAW_DOMAIN`] so a beacon draw can never be confused with a
/// parent-hash draw (different entropy, different epoch binding).
pub const BEACON_DRAW_DOMAIN: &str = "STELL_SORTITION_BEACON_V1";

/// True once the beacon draw is live at `height` (never, while the
/// activation constant is `u64::MAX`).
pub fn beacon_draw_active_at(height: Height) -> bool {
    #[allow(clippy::absurd_extreme_comparisons)]
    // GATE: `>=` is the rollout semantic (live at/after the flipped height);
    // the lint fires only because the constant is currently the never-value
    // `u64::MAX`, and goes quiet on its own when the lead flips it.
    {
        height >= BEACON_DRAW_ACTIVATION_HEIGHT
    }
}

/// The per-`(epoch, height, round)` beacon seed:
/// `BLAKE3("STELL_SORTITION_BEACON_V1" || beacon_output || epoch || height || round)`.
///
/// The epoch is bound into the seed (not just the height) so a beacon from
/// one epoch cannot be replayed as the draw of another: the same
/// `beacon_output` at the same height in a different epoch seeds a different
/// draw, and [`beacon_draw_committee`] additionally REFUSES a beacon whose
/// claimed epoch is not the height's epoch.
pub fn beacon_seed(
    beacon_output: &[u8; 32],
    beacon_epoch: u64,
    height: Height,
    round: Round,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(BEACON_DRAW_DOMAIN);
    hasher.update(beacon_output);
    hasher.update(&beacon_epoch.to_le_bytes());
    hasher.update(&height.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Beacon-draw committee selector: same shape as
/// [`derive_sortition_committee`] so callers swap trivially (replace the
/// `prev_block_hash` argument with the `(beacon_output, beacon_epoch)` pair),
/// except for the one extra epoch argument that carries the epoch binding.
///
/// ENTROPY: `beacon_output` MUST be the epoch-bound XMSS-VRF output for
/// `beacon_epoch` (`crate::xmss_vrf`, sibling workstream). It is taken as a
/// parameter — never sampled inside — so the draw is a pure deterministic
/// function of its inputs (no hidden randomness, no clock, no env).
///
/// EPOCH BINDING (fail-closed): the height's epoch is
/// `crate::mev_epoch::epoch_of_height(height)`; a beacon whose claimed
/// `beacon_epoch` differs is REFUSED (empty committee), exactly like an empty
/// set or a zero target. A refused draw elects nobody and therefore can never
/// reach quorum.
///
/// GATED OFF: nothing calls this on any live path until the lead flips
/// [`BEACON_DRAW_ACTIVATION_HEIGHT`]. The parent-hash draw stays canonical.
pub fn beacon_draw_committee(
    validators: &ValidatorSet,
    height: Height,
    round: Round,
    committee_size: u32,
    beacon_output: &[u8; 32],
    beacon_epoch: u64,
) -> Vec<ValidatorId> {
    // Epoch binding first: a beacon from the wrong epoch is not entropy for
    // this height — refuse before touching any stake table.
    if beacon_epoch != crate::mev_epoch::epoch_of_height(height) {
        return Vec::new();
    }
    if committee_size == 0 || validators.is_empty() || validators.total_power() == 0 {
        return Vec::new();
    }

    // Filter positive-power validators in canonical sorted order (BTreeMap order)
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
    let mut total_power: u64 = pool.iter().map(|(_, p)| *p).sum();

    // Same weighted without-replacement ticket loop as the parent-hash draw,
    // but seeded by the epoch-bound beacon instead of the parent hash.
    let seed = beacon_seed(beacon_output, beacon_epoch, height, round);

    for step in 0..target_k {
        if total_power == 0 || pool.is_empty() {
            break;
        }

        let mut hasher = blake3::Hasher::new_derive_key(BEACON_DRAW_DOMAIN);
        hasher.update(&seed);
        hasher.update(&(step as u32).to_le_bytes());
        let hash = hasher.finalize();

        let rand_val = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap());
        let ticket = rand_val % total_power;

        let mut acc = 0u64;
        let mut chosen_idx = 0;
        for (idx, (_id, power)) in pool.iter().enumerate() {
            acc += *power;
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

/// Multiplicative per-round backoff factor of the DETERMINISTIC round timeout.
///
/// Safety role (liveness): under PERSISTENT slowdown (a network stuck in the
/// "slow" state for several rounds) a timeout is evidence of hidden state, so
/// the ladder is geometric with `ρ = 2` — NOT additive `+500ms`. Per the
/// report correction (FIXES §1.8, §2.9): a persistent `ρ ≈ 2` is NOT
/// identifiable (selection bias); the `×2` ladder is a heuristic, not an
/// optimum (`papers/02_liveness.md` §4–§7; rec 1 keeps the 3000ms base for
/// `γ≈2, p50≈660ms, c≈500ms — and replaces the additive rung with `×2`).
/// At base 3000ms the rungs are 3s, 6s, 12s, 24s, then the cap — a wedged
/// round on a slow/Byzantine proposer unwedges far faster than `+500ms` per
/// round. Deterministic on every node (function of round only) so rounds stay
/// synchronized. Bounded by [`DETERMINISTIC_BACKOFF_CAP_MS`].
pub const DETERMINISTIC_BACKOFF_FACTOR: u64 = 2;
/// Cap on the round-driven backoff half of the deterministic timeout.
///
/// Safety role (liveness + DoS bound): keeps a pathological round (round 1M)
/// from installing an unbounded timeout that would stall finality; the cap
/// still exceeds any realistic WAN skew, so honest catch-up is unaffected.
pub const DETERMINISTIC_BACKOFF_CAP_MS: u64 = 10_000;
/// Adaptive extension per unit of proposer missed-streak (ledger `missed`).
///
/// Safety role (liveness): gives a historically slow proposer's rounds extra
/// time instead of timing out a valid proposal; input is committed block
/// content (identical on every node), so the extension cannot desynchronize
/// rounds. Bounded by [`ADAPTIVE_EXTENSION_CAP_MS`].
pub const ADAPTIVE_EXTENSION_PER_MISS_MS: u64 = 500;
/// Hard cap on the adaptive (slow-proposer) extension half.
///
/// Safety role (liveness + DoS bound): bounds how far one proposer's streak
/// can stretch a round, so a grinded `missed` streak cannot park the chain;
/// the cap still covers the observed slow-proposer tail.
pub const ADAPTIVE_EXTENSION_CAP_MS: u64 = 5_000;

/// Consecutive missed proposals per validator that counts as "repeatedly
/// missing" for OBSERVABILITY (M). No protocol punishment — only metering +
/// suspicion-free fast-path re-admission (the counter resets the moment the
/// proposer proposes again). Pinned by test.
pub const PROPOSER_MISS_THRESHOLD_M: u32 = 3;

/// Deterministic round timeout for `(height, round)`.
///
/// CHOICE (1a) adaptive round timeout — and why (1b)/(1c) were rejected:
///
/// * (1a) CHOSEN: extend the timeout for rounds whose scheduled proposer is
///   historically slow. The slowness signal is the staking-ledger `missed`
///   streak for the scheduled proposer — block content, identical on every
///   node that finalized the same prefix — so every honest node computes the
///   SAME extension for the SAME (height, round). Bounded
///   (`ADAPTIVE_EXTENSION_CAP_MS`), deterministic, rounds stay synchronized.
/// * (1b) vote-aggregation grace REJECTED as the primary fix: prevotes for
///   round r are ALREADY counted after the node leaves r (the scan window +
///   the polka ledger keep every round of the height votable — that was the
///   2026-10-21 parked-height fix). Counting r-prevotes toward an r+1 QC
///   would additionally MIX rounds: two different quorums (r for A, r+1 for
///   B) could both "decide" and break quorum intersection. Safety over grace.
/// * (1c, "faster base timeout") REJECTED: shrinking the base from 3.5s buys
///   view-change storms on 1-vCPU members (responder p50 ~660ms leaves no
///   headroom), not throughput.
///
/// INPUTS (exhaustive — anything else is a bug):
///  1. `base_ms` — the frozen canonical base [`FROZEN_ROUND_TIMEOUT_BASE_MS`].
///     MUST match on all validators (documented rollout invariant); there is
///     no per-node env override anymore (protocol freeze 2026-11-03).
///  2. `round` — the round the timeout is FOR (not a local failure count).
///  3. `proposer_missed_streak` — ledger `missed` of the scheduled proposer
///     for (height, round). Deterministic block content, not observation.
///
/// NO wall-clock input: no `Instant::now`, no `SystemTime`, no elapsed, no
/// peer-seen timestamps, no local vote-observation flags. A reader can verify
/// with `grep -n "Instant\|SystemTime" ` on this function: zero hits.
///
/// FREEZE (protocol freeze 2026-11-03): canonical round-timeout base, 3_000 ms.
/// Value = pre-freeze `STELL_ROUND_TIMEOUT_MS` code default (was read in
/// `main.rs` with clamp 200..=3_600_000; the frozen value is inside that
/// range, so default-env behavior is byte-identical). Rationale: this base
/// feeds the same-on-all-nodes ladder (spec
/// `docs/specs/04_NETWORK_AND_CONSENSUS_PHASE2.md` §2) and MUST match on all
/// validators — a per-node env knob for a must-match value is a fork risk.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const FROZEN_ROUND_TIMEOUT_BASE_MS: u64 = 3_000;

pub fn deterministic_round_timeout_ms(
    base_ms: u64,
    round: Round,
    proposer_missed_streak: u32,
) -> u64 {
    // Geometric ladder `T(r) = min(base·2^r, base + CAP)` (paper 02_liveness
    // §6, rec 1): `×DETERMINISTIC_BACKOFF_FACTOR` per round, same ceiling as
    // before (`DETERMINISTIC_BACKOFF_CAP_MS` above the base), so the
    // saturation rung is byte-identical to the old additive cap.
    // `saturating_pow`/`saturating_mul`: `Round = u32` can name absurd rounds
    // (tests pin round 1_000_000) — saturation, never wrap, then the cap.
    let grown = base_ms.saturating_mul(DETERMINISTIC_BACKOFF_FACTOR.saturating_pow(round));
    let backoff_capped = grown.min(base_ms.saturating_add(DETERMINISTIC_BACKOFF_CAP_MS));
    let adaptive = (proposer_missed_streak as u64)
        .saturating_mul(ADAPTIVE_EXTENSION_PER_MISS_MS)
        .min(ADAPTIVE_EXTENSION_CAP_MS);
    // ADAPTIVE BASE (paper 02_liveness §5–§6, formula (2) — NOT implemented):
    // the principled base is `T0 = clamp(0.6·q99_committed, 0.5s, 10s)` where
    // `q99_committed` is a latency-tail quantile committed into epoch state
    // (same on every node — never a local clock). No committed-q99 feed
    // exists yet, so the frozen 3000ms base stays; when the feed lands, it
    // replaces ONLY `base_ms` upstream — this ladder is already multiplicative
    // in the base and needs no further change.
    backoff_capped.saturating_add(adaptive)
}
