//! CN-VRF sandbox KATs — spec §4 (all 9 groups), fixed seeds/keys/nonces,
//! deterministic, no wall-clock. Consensus wiring is FORBIDDEN before external
//! audit; the abort-path group exercises the EXISTING downtime counters
//! through the public `StakingLedger` API (caller-side posture, O5).

use std::collections::BTreeMap;

use stellereum::cn_vrf::{
    BETA_PREIMAGE_LEN, COMMIT_CARRIER_LEN, COMMIT_PREIMAGE_LEN, CNVRF_BETA_DST,
    CNVRF_COMMIT_DST, CNVRF_OPEN_DST, CNVRF_PI_LEN, EPOCH_LEN, OPEN_MESSAGE_LEN,
    REVEAL_CARRIER_LEN, CommitError, CommitOutcome, cnvrf_beta, cnvrf_commit,
    cnvrf_commit_state, cnvrf_draw_absence, cnvrf_expire_before,
    cnvrf_mark_revealed, cnvrf_open, cnvrf_verify, cnvrf_verify_carrier,
    cnvrf_verify_with_resolver, commit_hash, commit_preimage_bytes,
    epoch_of_height, epoch_start_height, first_usable_epoch,
    load_cnvrf_nonce_from_file, open_message_bytes, parse_cnvrf_nonce_hex,
    save_cnvrf_nonce_to_file, shake256_32, shake256_xof,
};
use stellereum::post_quantum::{
    FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN, FalconKeypair,
};
use stellereum::staking::{DOWNTIME_MISS_THRESHOLD, DOWNTIME_SLASH_BPS, StakingLedger};

const CHAIN_MAIN: u64 = 5757;
const CHAIN_ALT: u64 = 777;
const VID: [u8; 32] = [0x11; 32];
const NONCE: [u8; 32] = [0x22; 32];
const ALPHA: [u8; 32] = [0x33; 32];
const EPOCH: u64 = 5;

fn key(seed_byte: u8) -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&[seed_byte; 32])
}

fn flip(mut b: [u8; 32]) -> [u8; 32] {
    b[0] ^= 0x01;
    b
}

// ---------------------------------------------------------------------------
// Sponge pin (O8): our SHAKE-256 matches the NIST vectors pinned at
// post_quantum.rs:2450 (same permutation code path).
// ---------------------------------------------------------------------------

#[test]
fn cnvrf_sponge_matches_nist_kats() {
    assert_eq!(
        hex::encode(shake256_32(b"")),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
    );
    assert_eq!(
        hex::encode(shake256_32(b"abc")),
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
    );
    let mut out64 = [0u8; 64];
    shake256_xof(b"", &mut out64);
    assert_eq!(
        hex::encode(out64),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
         d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
    );
    // Multi-block absorb determinism + sensitivity.
    let long = vec![0xABu8; 200];
    assert_eq!(shake256_32(&long), shake256_32(&long));
    assert_ne!(shake256_32(&long), shake256_32(&[0xABu8; 199]));
}

// ---------------------------------------------------------------------------
// Group 1 — Determinism (spec §4.1): c + beta fixed; pi randomized.
// ---------------------------------------------------------------------------

#[test]
fn cnvrf_group1_determinism_pi_varies_beta_fixed() {
    let sk = key(0xA1);
    let c1 = cnvrf_commit(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE);
    let c2 = cnvrf_commit(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE);
    assert_eq!(c1.c, c2.c, "commitment must be deterministic");
    // NOTE: the commit sig is ALSO a randomized Falcon witness (like pi), so
    // two commit carriers for the same inputs differ in `sig` while `c` is
    // fixed. Both must verify.
    assert_ne!(c1.sig, c2.sig, "commit sig randomized like pi");

    let r1 = cnvrf_open(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA);
    let r2 = cnvrf_open(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA);
    assert_ne!(
        r1.pi, r2.pi,
        "Falcon pi MUST vary run to run (randomized signing)"
    );

    let beta = cnvrf_verify(
        sk.pubkey(),
        &c1.c,
        CHAIN_MAIN,
        &VID,
        EPOCH,
        &ALPHA,
        &NONCE,
        &r1.pi,
    )
    .expect("valid reveal verifies");
    let beta2 = cnvrf_verify(
        sk.pubkey(),
        &c1.c,
        CHAIN_MAIN,
        &VID,
        EPOCH,
        &ALPHA,
        &NONCE,
        &r2.pi,
    )
    .expect("second witness verifies to the SAME beta");
    assert_eq!(beta, beta2, "beta is signature-independent (§2.2)");
    for _ in 0..100 {
        assert_eq!(cnvrf_beta(&NONCE, &ALPHA, &VID, EPOCH), beta);
    }
}

// ---------------------------------------------------------------------------
// Group 2 — Binding mutations, 6 fields x 2 positions (spec §4.2).
// ---------------------------------------------------------------------------

#[test]
fn cnvrf_group2_binding_mutations_6x2() {
    let sk = key(0xA2);
    let commit = cnvrf_commit(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE);
    let reveal = cnvrf_open(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA);
    let ok = || {
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &reveal.pi,
        )
    };
    assert!(ok().is_some(), "baseline must verify");

    // Commit-side (stored c vs mutated coordinate → check-1 or check-2 None).
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN + 1, &VID, EPOCH, &ALPHA, &NONCE, &reveal.pi).is_none(), "chain commit-side");
    let vid2 = flip(VID);
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &vid2, EPOCH, &ALPHA, &NONCE, &reveal.pi).is_none(), "validator commit-side");
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH + 1, &ALPHA, &NONCE, &reveal.pi).is_none(), "epoch commit-side");
    let nonce2 = flip(NONCE);
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &nonce2, &reveal.pi).is_none(), "nonce commit-side");
    let alpha2 = flip(ALPHA);
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &alpha2, &NONCE, &reveal.pi).is_none(), "alpha commit-side (sig refusal)");
    let mut bad_pre = commit_preimage_bytes(CHAIN_MAIN, &VID, EPOCH, &NONCE);
    bad_pre[..CNVRF_OPEN_DST.len()].copy_from_slice(CNVRF_OPEN_DST);
    let bad_c = shake256_32(&bad_pre);
    assert_ne!(bad_c, commit.c, "domain swap must change c");
    assert!(cnvrf_verify(sk.pubkey(), &bad_c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &reveal.pi).is_none(), "domain commit-side");

    // Open-side (mutated reveal input → None). Sanity first: a carrier pair
    // freshly built under the mutated chain verifies (mutations must be
    // tested against the ORIGINAL pair, not a mixed one).
    let commit_b = cnvrf_commit(&sk, CHAIN_MAIN + 1, &VID, EPOCH, &NONCE);
    let reveal_b = cnvrf_open(&sk, CHAIN_MAIN + 1, &VID, EPOCH, &NONCE, &ALPHA);
    assert!(cnvrf_verify(sk.pubkey(), &commit_b.c, CHAIN_MAIN + 1, &VID, EPOCH, &ALPHA, &NONCE, &reveal_b.pi).is_some(), "sanity: re-committed chain verifies");
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &sk.sign(&open_message_bytes(CHAIN_MAIN + 1, &VID, EPOCH, &NONCE, &ALPHA))).is_none(), "chain open-side");
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &sk.sign(&open_message_bytes(CHAIN_MAIN, &vid2, EPOCH, &NONCE, &ALPHA))).is_none(), "validator open-side");
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &sk.sign(&open_message_bytes(CHAIN_MAIN, &VID, EPOCH + 1, &NONCE, &ALPHA))).is_none(), "epoch open-side");
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &sk.sign(&open_message_bytes(CHAIN_MAIN, &VID, EPOCH, &nonce2, &ALPHA))).is_none(), "nonce open-side");
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &sk.sign(&open_message_bytes(CHAIN_MAIN, &VID, EPOCH, &NONCE, &alpha2))).is_none(), "alpha open-side");
    // Domain open-side: pi over a DST-swapped message + beta DST-swap check.
    let mut swapped = open_message_bytes(CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA);
    swapped[..CNVRF_COMMIT_DST.len()].copy_from_slice(CNVRF_COMMIT_DST);
    let pi_swapped = sk.sign(&swapped);
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &pi_swapped).is_none(), "domain open-side");
    assert_ne!(
        cnvrf_beta(&NONCE, &ALPHA, &VID, EPOCH),
        shake256_32(
            &[CNVRF_COMMIT_DST, &NONCE[..], &ALPHA[..], &VID[..], &EPOCH.to_le_bytes()[..]].concat()
        ),
        "beta DST swap must change beta"
    );

    // Length ±1 on every slice-pinned field ⇒ refuse (fixed arrays are
    // type-level; pi/pk are the slice paths).
    let mut pi_short = reveal.pi.to_vec();
    pi_short.truncate(CNVRF_PI_LEN - 1);
    let mut pi_long = reveal.pi.to_vec();
    pi_long.push(0x00);
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &pi_short).is_none());
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &pi_long).is_none());
    assert!(cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &[]).is_none());
    let mut pk_short = sk.pubkey().to_vec();
    pk_short.truncate(FALCON512_PUBKEY_LEN - 1);
    let mut pk_long = sk.pubkey().to_vec();
    pk_long.push(0x00);
    assert!(cnvrf_verify(&pk_short, &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &reveal.pi).is_none());
    assert!(cnvrf_verify(&pk_long, &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &reveal.pi).is_none());
    assert!(cnvrf_verify(&[], &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &reveal.pi).is_none());
}

// ---------------------------------------------------------------------------
// Group 3 — Signature substitution (spec §4.3).
// ---------------------------------------------------------------------------

#[test]
fn cnvrf_group3_signature_substitution() {
    let sk = key(0xA3);
    let other = key(0xB3);
    let commit = cnvrf_commit(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE);
    // Valid pi from a DIFFERENT Falcon key over the same open message.
    let msg = open_message_bytes(CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA);
    let foreign_pi = other.sign(&msg);
    assert_eq!(foreign_pi.len(), FALCON512_SIG_LEN);
    assert!(
        cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &foreign_pi).is_none(),
        "foreign-key pi must refuse (A1 end-to-end)"
    );
    // Valid pi over a DIFFERENT alpha with the same nonce.
    let alpha_other = [0x99u8; 32];
    let reveal_other =
        cnvrf_open(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE, &alpha_other);
    assert!(
        cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &reveal_other.pi).is_none(),
        "pi for another alpha must refuse (check 2 binds alpha)"
    );
    // Sanity: that same pi verifies under its own alpha.
    assert!(
        cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &alpha_other, &NONCE, &reveal_other.pi).is_some()
    );
}

// ---------------------------------------------------------------------------
// Group 4 — Cross-epoch replay (spec §4.4).
// ---------------------------------------------------------------------------

#[test]
fn cnvrf_group4_cross_epoch_replay() {
    let sk = key(0xA4);
    let commit = cnvrf_commit(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE);
    let reveal = cnvrf_open(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA);
    // Same bytes re-submitted in epoch N+1 ⇒ refuse (guard 4a).
    assert!(
        cnvrf_verify_carrier(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH + 1, &reveal, &ALPHA).is_none(),
        "epoch N reveal must refuse in N+1"
    );
    assert!(
        cnvrf_verify_carrier(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &reveal, &ALPHA).is_some(),
        "baseline carrier verifies in N"
    );
    // Commitment for N re-submitted as commitment for N+1 ⇒ different c.
    assert_ne!(
        commit_hash(CHAIN_MAIN, &VID, EPOCH, &NONCE),
        commit_hash(CHAIN_MAIN, &VID, EPOCH + 1, &NONCE)
    );
    // Crypto-level: epoch is bound even without the carrier guard.
    assert!(
        cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH + 1, &ALPHA, &NONCE, &reveal.pi).is_none()
    );
}

// ---------------------------------------------------------------------------
// Group 5 — Cross-chain replay, chain_ids 5757 vs 777 (spec §4.5).
// ---------------------------------------------------------------------------

#[test]
fn cnvrf_group5_cross_chain_replay() {
    let sk = key(0xA5);
    let commit_main = cnvrf_commit(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE);
    let reveal_main = cnvrf_open(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA);
    // Same bytes under the alt chain ⇒ refuse both directions (guard 4b).
    assert!(
        cnvrf_verify(sk.pubkey(), &commit_main.c, CHAIN_ALT, &VID, EPOCH, &ALPHA, &NONCE, &reveal_main.pi).is_none(),
        "mainnet bytes must refuse on alt chain"
    );
    let commit_alt = cnvrf_commit(&sk, CHAIN_ALT, &VID, EPOCH, &NONCE);
    let reveal_alt = cnvrf_open(&sk, CHAIN_ALT, &VID, EPOCH, &NONCE, &ALPHA);
    assert!(
        cnvrf_verify(sk.pubkey(), &commit_alt.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &reveal_alt.pi).is_none(),
        "alt-chain bytes must refuse on main chain"
    );
    assert_ne!(commit_main.c, commit_alt.c, "commitments differ per chain");
    // Beta itself is chain-agnostic by shape (§1.4 has no chain_id) — the
    // chain binding lives in checks 1+2, already asserted above.
    assert!(
        cnvrf_verify(sk.pubkey(), &commit_main.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &reveal_main.pi).is_some()
    );
}

// ---------------------------------------------------------------------------
// Group 6 — Abort path via existing downtime math (spec §4.6, O5 reuse-as-is).
// ---------------------------------------------------------------------------

#[test]
fn cnvrf_group6_abort_path_downtime_math() {
    // Caller-side absence predicate (unit level, no ledger).
    let empty: BTreeMap<([u8; 32], u64), stellereum::cn_vrf::CommitmentRecord> =
        BTreeMap::new();
    assert!(cnvrf_draw_absence(&empty, &VID, EPOCH));
    let mut store = empty;
    let c = commit_hash(CHAIN_MAIN, &VID, EPOCH, &NONCE);
    assert_eq!(
        cnvrf_commit_state(&mut store, &VID, EPOCH, &c, 100, EPOCH - 1),
        Ok(CommitOutcome::Accepted)
    );
    assert!(
        cnvrf_draw_absence(&store, &VID, EPOCH),
        "committed-but-unrevealed = absent for the draw"
    );
    assert!(cnvrf_mark_revealed(&mut store, &VID, EPOCH, EPOCH));
    assert!(!cnvrf_draw_absence(&store, &VID, EPOCH));

    // Ledger level: 10 consecutive absences ⇒ exact 0.1% burn + jail.
    const BOND: u64 = 1_100_000_000_000; // 1100 STELL in nano.
    let v: [u8; 32] = [0xC6; 32];
    let mut ledger = StakingLedger::new();
    ledger.bond(v, BOND, 0).expect("bond must succeed");
    let never = |_: &[u8; 32]| false;
    let one = vec![v];
    // Single-height absence ⇒ streak+1, zero burn.
    assert_eq!(ledger.note_missed_heights(1, &never, &one), 0);
    assert_eq!(ledger.validators[&v].missed, 1);
    assert_eq!(ledger.validators[&v].self_bond, BOND);
    // Full streak h..h+9 ⇒ exactly before*10/10_000 burned.
    let mut ledger2 = StakingLedger::new();
    ledger2.bond(v, BOND, 0).expect("bond must succeed");
    let mut burned_total = 0u64;
    for height in 1..=(DOWNTIME_MISS_THRESHOLD as u64) {
        burned_total += ledger2.note_missed_heights(height, &never, &one);
    }
    assert_eq!(
        burned_total,
        BOND * DOWNTIME_SLASH_BPS / 10_000,
        "exact DOWNTIME_SLASH_BPS math"
    );
    assert_eq!(ledger2.validators[&v].self_bond, BOND - burned_total);
    assert!(
        ledger2.is_jailed(&v),
        "10 consecutive misses jail the validator"
    );
}

// ---------------------------------------------------------------------------
// Group 7 — Fork-reuse (spec §4.7).
// ---------------------------------------------------------------------------

#[test]
fn cnvrf_group7_fork_reuse() {
    let sk = key(0xA7);
    let commit = cnvrf_commit(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE);
    // Different parent hashes ⇒ different alphas ⇒ different betas, both verify.
    let alpha_a = [0xAAu8; 32];
    let alpha_b = [0xBBu8; 32];
    let ra = cnvrf_open(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE, &alpha_a);
    let rb = cnvrf_open(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE, &alpha_b);
    let beta_a = cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &alpha_a, &NONCE, &ra.pi)
        .expect("fork A verifies");
    let beta_b = cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &alpha_b, &NONCE, &rb.pi)
        .expect("fork B verifies");
    assert_ne!(beta_a, beta_b, "distinct fork alphas ⇒ independent betas");
    // Identical parent hash on both forks ⇒ identical beta (agreement, not bug).
    let beta_a2 = cnvrf_verify(sk.pubkey(), &commit.c, CHAIN_MAIN, &VID, EPOCH, &alpha_a, &NONCE, &ra.pi)
        .expect("same alpha re-verifies");
    assert_eq!(beta_a, beta_a2);
}

// ---------------------------------------------------------------------------
// Group 8 — Rotation interplay via mock key-at-height resolver (spec §4.8).
// ---------------------------------------------------------------------------

#[test]
fn cnvrf_group8_rotation_interplay() {
    let old = key(0x01);
    let new = key(0x02);
    let third = key(0x03);
    let old_pk = old.pubkey().to_vec();
    let new_pk = new.pubkey().to_vec();
    let third_pk = third.pubkey().to_vec();
    // Rotation effective at the epoch boundary (delay 7200, pq_registry.rs:97).
    let effective: u64 = epoch_start_height(EPOCH + 1);
    let draw_old = effective - 1;
    let draw_new = effective + 1;

    let commit = cnvrf_commit(&old, CHAIN_MAIN, &VID, EPOCH, &NONCE);
    let reveal_old = cnvrf_open(&old, CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA);
    // New key signs the same open message (post-rotation reveal shape).
    let reveal_new = cnvrf_open(&new, CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA);

    // Mock resolver: pre-effective → old key, post-effective → new key.
    let resolver = |_: [u8; 32], h: u64| -> Option<Vec<u8>> {
        if h < effective {
            Some(old_pk.clone())
        } else {
            Some(new_pk.clone())
        }
    };
    assert!(
        cnvrf_verify_with_resolver(&resolver, &commit.c, CHAIN_MAIN, &VID, EPOCH, draw_old, &ALPHA, &NONCE, &reveal_old.pi).is_some(),
        "pre-effective draws verify under the old key"
    );
    assert!(
        cnvrf_verify_with_resolver(&resolver, &commit.c, CHAIN_MAIN, &VID, EPOCH, draw_old, &ALPHA, &NONCE, &reveal_new.pi).is_none(),
        "new-key reveal refuses pre-effective"
    );
    // Post-effective, the commitment was made under the old key, so the old
    // reveal refuses once the resolver serves the new key (stale key), while
    // a reveal authorized by the new key verifies (same nonce binding).
    let commit_new = cnvrf_commit(&new, CHAIN_MAIN, &VID, EPOCH, &NONCE);
    assert!(
        cnvrf_verify_with_resolver(&resolver, &commit.c, CHAIN_MAIN, &VID, EPOCH, draw_new, &ALPHA, &NONCE, &reveal_old.pi).is_none(),
        "superseded-key reveal refuses post-effective"
    );
    assert!(
        cnvrf_verify_with_resolver(&resolver, &commit_new.c, CHAIN_MAIN, &VID, EPOCH, draw_new, &ALPHA, &NONCE, &reveal_new.pi).is_some(),
        "post-effective draws verify under the new key"
    );
    // History depth 2: a resolver keeping only the two newest keys refuses
    // the oldest (third rotation retires it).
    let resolver2 = |_: [u8; 32], _: u64| -> Option<Vec<u8>> { Some(third_pk.clone()) };
    let reveal_third = cnvrf_open(&third, CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA);
    assert!(
        cnvrf_verify_with_resolver(&resolver2, &commit.c, CHAIN_MAIN, &VID, EPOCH, draw_new, &ALPHA, &NONCE, &reveal_old.pi).is_none(),
        "retired key (beyond history depth) refuses"
    );
    assert!(
        cnvrf_verify_with_resolver(&resolver2, &commit_hash(CHAIN_MAIN, &VID, EPOCH, &NONCE), CHAIN_MAIN, &VID, EPOCH, draw_new, &ALPHA, &NONCE, &reveal_third.pi).is_some()
    );
    // Unresolvable key ⇒ None (fail-closed).
    let resolver_none = |_: [u8; 32], _: u64| -> Option<Vec<u8>> { None };
    assert!(
        cnvrf_verify_with_resolver(&resolver_none, &commit.c, CHAIN_MAIN, &VID, EPOCH, draw_new, &ALPHA, &NONCE, &reveal_old.pi).is_none()
    );
}

// ---------------------------------------------------------------------------
// Group 9 — KAT sizes byte-exact (spec §4.9, sourced post_quantum.rs:103-111).
// ---------------------------------------------------------------------------

#[test]
fn cnvrf_group9_kat_sizes() {
    assert_eq!(FALCON512_PUBKEY_LEN, 897);
    assert_eq!(FALCON512_SIG_LEN, 666);
    assert_eq!(CNVRF_PI_LEN, 666);
    assert_eq!(CNVRF_COMMIT_DST.len(), 21, "normative tag value, not the spec's 20 B print");
    assert_eq!(CNVRF_OPEN_DST.len(), 19, "normative tag value, not the spec's 18 B print");
    assert_eq!(CNVRF_BETA_DST.len(), 19, "normative tag value, not the spec's 18 B print");
    assert_eq!(COMMIT_PREIMAGE_LEN, 101);
    assert_eq!(OPEN_MESSAGE_LEN, 131);
    assert_eq!(BETA_PREIMAGE_LEN, 123);
    assert_eq!(
        commit_preimage_bytes(CHAIN_MAIN, &VID, EPOCH, &NONCE).len(),
        101
    );
    assert_eq!(
        open_message_bytes(CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA).len(),
        131
    );
    let sk = key(0xA9);
    let commit = cnvrf_commit(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE);
    let reveal = cnvrf_open(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA);
    assert_eq!(commit.sig.len(), 666);
    assert_eq!(reveal.pi.len(), 666);
    assert_eq!(commit.encoded_len(), COMMIT_CARRIER_LEN);
    assert_eq!(commit.encoded_len(), 738);
    assert!(commit.encoded_len() < 1024);
    assert_eq!(reveal.encoded_len(), REVEAL_CARRIER_LEN);
    assert_eq!(reveal.encoded_len(), 770);
    assert!(reveal.encoded_len() < 1024);
    let beta = cnvrf_beta(&NONCE, &ALPHA, &VID, EPOCH);
    assert_eq!(beta.len(), 32);
}

// ---------------------------------------------------------------------------
// Lead decisions: O1 epoch geometry, O3 same-block reveal, O6 file custody,
// O7 state machine, O9 activation, O10 one-pending-commitment.
// ---------------------------------------------------------------------------

#[test]
fn cnvrf_epochs_o1_o9() {
    assert_eq!(EPOCH_LEN, 7200);
    assert_eq!(epoch_of_height(0), 0);
    assert_eq!(epoch_of_height(7199), 0);
    assert_eq!(epoch_of_height(7200), 1);
    assert_eq!(epoch_of_height(14399), 1);
    assert_eq!(epoch_of_height(14400), 2);
    assert_eq!(epoch_start_height(1), 7200);
    // epoch(N) covers [N*7200, (N+1)*7200).
    for h in [0, 1, 7199, 7200, 7201, 14399, 14400] {
        let e = epoch_of_height(h);
        assert!(h >= epoch_start_height(e) && h < epoch_start_height(e + 1));
    }
    // O9: activation waits one full epoch.
    assert_eq!(first_usable_epoch(0), 1);
    assert_eq!(first_usable_epoch(7), 8);
    assert_eq!(first_usable_epoch(u64::MAX), u64::MAX, "saturating");
}

#[test]
fn cnvrf_state_machine_o7_o10() {
    let mut store = BTreeMap::new();
    let c = commit_hash(CHAIN_MAIN, &VID, EPOCH, &NONCE);
    // O10: only current_epoch+1 committable.
    assert_eq!(
        cnvrf_commit_state(&mut store, &VID, EPOCH, &c, 10, EPOCH),
        Err(CommitError::StaleOrCurrent),
        "current epoch refused"
    );
    assert_eq!(
        cnvrf_commit_state(&mut store, &VID, EPOCH - 1, &c, 10, EPOCH),
        Err(CommitError::StaleOrCurrent),
        "past epoch refused"
    );
    assert_eq!(
        cnvrf_commit_state(&mut store, &VID, EPOCH + 1, &c, 10, EPOCH - 1),
        Err(CommitError::TooFarAhead),
        "epoch > current+1 refused"
    );
    assert!(store.is_empty());
    // Accept at exactly current+1.
    assert_eq!(
        cnvrf_commit_state(&mut store, &VID, EPOCH, &c, 10, EPOCH - 1),
        Ok(CommitOutcome::Accepted)
    );
    // Double-commit: second ignored, never an offense — record untouched.
    let c2 = flip(c);
    assert_eq!(
        cnvrf_commit_state(&mut store, &VID, EPOCH, &c2, 11, EPOCH - 1),
        Ok(CommitOutcome::IgnoredDuplicate)
    );
    assert_eq!(store[&(VID, EPOCH)].c, c);
    assert_eq!(store[&(VID, EPOCH)].commit_height, 10);
    // O3: same-block reveal allowed — mark in the same epoch, no lead time.
    assert!(!cnvrf_mark_revealed(&mut store, &VID, EPOCH, EPOCH + 1), "wrong epoch never marks");
    assert!(!cnvrf_mark_revealed(&mut store, &[0xFF; 32], EPOCH, EPOCH), "unknown validator never marks");
    assert!(cnvrf_mark_revealed(&mut store, &VID, EPOCH, EPOCH));
    assert!(store[&(VID, EPOCH)].revealed);
    // Expiry: epoch N ends ⇒ EXPIRED; only older entries removed.
    let c_next = commit_hash(CHAIN_MAIN, &VID, EPOCH + 1, &NONCE);
    assert_eq!(
        cnvrf_commit_state(&mut store, &VID, EPOCH + 1, &c_next, 20, EPOCH),
        Ok(CommitOutcome::Accepted)
    );
    assert_eq!(cnvrf_expire_before(&mut store, EPOCH), 0, "current epoch kept");
    assert_eq!(cnvrf_expire_before(&mut store, EPOCH + 1), 1, "past epoch expired");
    assert!(!store.contains_key(&(VID, EPOCH)));
    assert!(store.contains_key(&(VID, EPOCH + 1)));
    assert_eq!(cnvrf_expire_before(&mut store, EPOCH + 1), 0, "idempotent");
}

#[test]
fn cnvrf_nonce_file_custody_o6() {
    let dir = std::env::temp_dir().join(format!(
        "cnvrf_test_{}",
        std::process::id()
    ));
    let path = dir.join("epoch5.nonce");
    let _ = std::fs::remove_dir_all(&dir);
    // Roundtrip with temp dir only.
    save_cnvrf_nonce_to_file(&path, &NONCE).expect("save must succeed");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "signer-side 0600 posture");
    }
    assert_eq!(load_cnvrf_nonce_from_file(&path).expect("load"), NONCE);
    // Insecure permissions refused fail-closed.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod");
        assert!(
            load_cnvrf_nonce_from_file(&path).is_err(),
            "0644 must refuse"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod back");
    }
    // Empty file refused; missing file refused; bad hex refused.
    std::fs::write(&path, "\n  \n").expect("write empty");
    assert!(load_cnvrf_nonce_from_file(&path).is_err());
    assert!(load_cnvrf_nonce_from_file(&dir.join("missing.nonce")).is_err());
    assert!(parse_cnvrf_nonce_hex("0x1234").is_err());
    assert!(parse_cnvrf_nonce_hex(&hex::encode([0u8; 31])).is_err());
    assert_eq!(
        parse_cnvrf_nonce_hex(&format!("0x{}", hex::encode(NONCE))).expect("0x prefix ok"),
        NONCE
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cnvrf_domain_tags_distinct() {
    assert_eq!(CNVRF_COMMIT_DST, b"STELL_CNVRF_COMMIT_V1");
    assert_eq!(CNVRF_OPEN_DST, b"STELL_CNVRF_OPEN_V1");
    assert_eq!(CNVRF_BETA_DST, b"STELL_CNVRF_BETA_V1");
    assert_ne!(CNVRF_COMMIT_DST, CNVRF_OPEN_DST);
    assert_ne!(CNVRF_COMMIT_DST, CNVRF_BETA_DST);
    assert_ne!(CNVRF_OPEN_DST, CNVRF_BETA_DST);
}
