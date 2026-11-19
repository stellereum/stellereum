//! CN-VRF sandbox KATs — spec §4 (all 9 groups), fixed seeds/keys/nonces,
//! deterministic, no wall-clock. Consensus wiring is FORBIDDEN before external
//! audit; the abort-path group exercises the EXISTING downtime counters
//! through the public `StakingLedger` API (caller-side posture, O5).

use std::collections::BTreeMap;

use stellereum::cn_vrf::{
    blake3_xof_48, cnvrf_beta, cnvrf_commit, cnvrf_commit_state, cnvrf_commit_verified_state,
    cnvrf_draw_absence, cnvrf_expire_before, cnvrf_mark_revealed, cnvrf_open, cnvrf_v3_commit,
    cnvrf_v3_verify_commit, cnvrf_v3_verify_reveal, cnvrf_verify, cnvrf_verify_carrier,
    cnvrf_verify_commit, cnvrf_verify_with_resolver, commit_hash, commit_preimage_bytes,
    commit_sig_message_bytes, compute_v3_anchors, derive_v3_epoch_secret, epoch_of_height,
    epoch_raw_seed, epoch_start_height, first_usable_epoch, load_cnvrf_nonce_from_file,
    load_cnvrf_v3_secret, open_message_bytes, parse_cnvrf_nonce_hex, save_cnvrf_nonce_to_file,
    save_cnvrf_v3_secret, shake256_32, shake256_xof, verify_v3_secret_matches_commit, CnVrfError,
    CnVrfV3Chain, CnVrfV3Record, CnVrfV3State, CommitCarrierV3, CommitError, CommitOutcome,
    SlotRevealOutcome, BETA_PREIMAGE_LEN, CNVRF_BETA_DST, CNVRF_COMMIT_DST, CNVRF_COMMIT_SIG_DST,
    CNVRF_OPEN_DST, CNVRF_PI_LEN, COMMIT_CARRIER_LEN, COMMIT_CARRIER_V3_LEN, COMMIT_PREIMAGE_LEN,
    COMMIT_SIG_MESSAGE_LEN, DST_BETA_V3, DST_CHAIN_V3, DST_COMMIT_SIG_V3, DST_EPOCH_RAW_SEED_V3,
    DST_V3_SEED_DERIVE, EPOCH_LEN, OPEN_MESSAGE_LEN, REVEAL_CARRIER_LEN,
    V3_COMMIT_LOOKAHEAD_BLOCKS, V3_LINK_LEN, V3_SEGMENTS, V3_SEGMENT_LEN,
};
use stellereum::post_quantum::{FalconKeypair, FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN};
use stellereum::staking::{StakingLedger, DOWNTIME_MISS_THRESHOLD, DOWNTIME_SLASH_BPS};

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
    assert_eq!(cnvrf_verify_commit(&c1, CHAIN_MAIN, sk.pubkey()), Ok(()));
    assert_eq!(cnvrf_verify_commit(&c2, CHAIN_MAIN, sk.pubkey()), Ok(()));

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
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN + 1,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &reveal.pi
        )
        .is_none(),
        "chain commit-side"
    );
    let vid2 = flip(VID);
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &vid2,
            EPOCH,
            &ALPHA,
            &NONCE,
            &reveal.pi
        )
        .is_none(),
        "validator commit-side"
    );
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH + 1,
            &ALPHA,
            &NONCE,
            &reveal.pi
        )
        .is_none(),
        "epoch commit-side"
    );
    let nonce2 = flip(NONCE);
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &ALPHA,
            &nonce2,
            &reveal.pi
        )
        .is_none(),
        "nonce commit-side"
    );
    let alpha2 = flip(ALPHA);
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &alpha2,
            &NONCE,
            &reveal.pi
        )
        .is_none(),
        "alpha commit-side (sig refusal)"
    );
    let mut bad_pre = commit_preimage_bytes(CHAIN_MAIN, &VID, EPOCH, &NONCE);
    bad_pre[..CNVRF_OPEN_DST.len()].copy_from_slice(CNVRF_OPEN_DST);
    let bad_c = shake256_32(&bad_pre);
    assert_ne!(bad_c, commit.c, "domain swap must change c");
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &bad_c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &reveal.pi
        )
        .is_none(),
        "domain commit-side"
    );

    // Open-side (mutated reveal input → None). Sanity first: a carrier pair
    // freshly built under the mutated chain verifies (mutations must be
    // tested against the ORIGINAL pair, not a mixed one).
    let commit_b = cnvrf_commit(&sk, CHAIN_MAIN + 1, &VID, EPOCH, &NONCE);
    let reveal_b = cnvrf_open(&sk, CHAIN_MAIN + 1, &VID, EPOCH, &NONCE, &ALPHA);
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit_b.c,
            CHAIN_MAIN + 1,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &reveal_b.pi
        )
        .is_some(),
        "sanity: re-committed chain verifies"
    );
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &sk.sign(&open_message_bytes(
                CHAIN_MAIN + 1,
                &VID,
                EPOCH,
                &NONCE,
                &ALPHA
            ))
        )
        .is_none(),
        "chain open-side"
    );
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &sk.sign(&open_message_bytes(
                CHAIN_MAIN, &vid2, EPOCH, &NONCE, &ALPHA
            ))
        )
        .is_none(),
        "validator open-side"
    );
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &sk.sign(&open_message_bytes(
                CHAIN_MAIN,
                &VID,
                EPOCH + 1,
                &NONCE,
                &ALPHA
            ))
        )
        .is_none(),
        "epoch open-side"
    );
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &sk.sign(&open_message_bytes(
                CHAIN_MAIN, &VID, EPOCH, &nonce2, &ALPHA
            ))
        )
        .is_none(),
        "nonce open-side"
    );
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &sk.sign(&open_message_bytes(
                CHAIN_MAIN, &VID, EPOCH, &NONCE, &alpha2
            ))
        )
        .is_none(),
        "alpha open-side"
    );
    // Domain open-side: pi over a DST-swapped message + beta DST-swap check.
    let mut swapped = open_message_bytes(CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA);
    swapped[..CNVRF_COMMIT_DST.len()].copy_from_slice(CNVRF_COMMIT_DST);
    let pi_swapped = sk.sign(&swapped);
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &pi_swapped
        )
        .is_none(),
        "domain open-side"
    );
    assert_ne!(
        cnvrf_beta(&NONCE, &ALPHA, &VID, EPOCH),
        shake256_32(
            &[
                CNVRF_COMMIT_DST,
                &NONCE[..],
                &ALPHA[..],
                &VID[..],
                &EPOCH.to_le_bytes()[..]
            ]
            .concat()
        ),
        "beta DST swap must change beta"
    );

    // Length ±1 on every slice-pinned field ⇒ refuse (fixed arrays are
    // type-level; pi/pk are the slice paths).
    let mut pi_short = reveal.pi.to_vec();
    pi_short.truncate(CNVRF_PI_LEN - 1);
    let mut pi_long = reveal.pi.to_vec();
    pi_long.push(0x00);
    assert!(cnvrf_verify(
        sk.pubkey(),
        &commit.c,
        CHAIN_MAIN,
        &VID,
        EPOCH,
        &ALPHA,
        &NONCE,
        &pi_short
    )
    .is_none());
    assert!(cnvrf_verify(
        sk.pubkey(),
        &commit.c,
        CHAIN_MAIN,
        &VID,
        EPOCH,
        &ALPHA,
        &NONCE,
        &pi_long
    )
    .is_none());
    assert!(cnvrf_verify(
        sk.pubkey(),
        &commit.c,
        CHAIN_MAIN,
        &VID,
        EPOCH,
        &ALPHA,
        &NONCE,
        &[]
    )
    .is_none());
    let mut pk_short = sk.pubkey().to_vec();
    pk_short.truncate(FALCON512_PUBKEY_LEN - 1);
    let mut pk_long = sk.pubkey().to_vec();
    pk_long.push(0x00);
    assert!(cnvrf_verify(
        &pk_short, &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &reveal.pi
    )
    .is_none());
    assert!(
        cnvrf_verify(&pk_long, &commit.c, CHAIN_MAIN, &VID, EPOCH, &ALPHA, &NONCE, &reveal.pi)
            .is_none()
    );
    assert!(cnvrf_verify(
        &[],
        &commit.c,
        CHAIN_MAIN,
        &VID,
        EPOCH,
        &ALPHA,
        &NONCE,
        &reveal.pi
    )
    .is_none());
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
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &foreign_pi
        )
        .is_none(),
        "foreign-key pi must refuse (A1 end-to-end)"
    );
    // Valid pi over a DIFFERENT alpha with the same nonce.
    let alpha_other = [0x99u8; 32];
    let reveal_other = cnvrf_open(&sk, CHAIN_MAIN, &VID, EPOCH, &NONCE, &alpha_other);
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &reveal_other.pi
        )
        .is_none(),
        "pi for another alpha must refuse (check 2 binds alpha)"
    );
    // Sanity: that same pi verifies under its own alpha.
    assert!(cnvrf_verify(
        sk.pubkey(),
        &commit.c,
        CHAIN_MAIN,
        &VID,
        EPOCH,
        &alpha_other,
        &NONCE,
        &reveal_other.pi
    )
    .is_some());
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
        cnvrf_verify_carrier(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH + 1,
            &reveal,
            &ALPHA
        )
        .is_none(),
        "epoch N reveal must refuse in N+1"
    );
    assert!(
        cnvrf_verify_carrier(
            sk.pubkey(),
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &reveal,
            &ALPHA
        )
        .is_some(),
        "baseline carrier verifies in N"
    );
    // Commitment for N re-submitted as commitment for N+1 ⇒ different c.
    assert_ne!(
        commit_hash(CHAIN_MAIN, &VID, EPOCH, &NONCE),
        commit_hash(CHAIN_MAIN, &VID, EPOCH + 1, &NONCE)
    );
    // Crypto-level: epoch is bound even without the carrier guard.
    assert!(cnvrf_verify(
        sk.pubkey(),
        &commit.c,
        CHAIN_MAIN,
        &VID,
        EPOCH + 1,
        &ALPHA,
        &NONCE,
        &reveal.pi
    )
    .is_none());
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
        cnvrf_verify(
            sk.pubkey(),
            &commit_main.c,
            CHAIN_ALT,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &reveal_main.pi
        )
        .is_none(),
        "mainnet bytes must refuse on alt chain"
    );
    let commit_alt = cnvrf_commit(&sk, CHAIN_ALT, &VID, EPOCH, &NONCE);
    let reveal_alt = cnvrf_open(&sk, CHAIN_ALT, &VID, EPOCH, &NONCE, &ALPHA);
    assert!(
        cnvrf_verify(
            sk.pubkey(),
            &commit_alt.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            &ALPHA,
            &NONCE,
            &reveal_alt.pi
        )
        .is_none(),
        "alt-chain bytes must refuse on main chain"
    );
    assert_ne!(commit_main.c, commit_alt.c, "commitments differ per chain");
    // Beta itself is chain-agnostic by shape (§1.4 has no chain_id) — the
    // chain binding lives in checks 1+2, already asserted above.
    assert!(cnvrf_verify(
        sk.pubkey(),
        &commit_main.c,
        CHAIN_MAIN,
        &VID,
        EPOCH,
        &ALPHA,
        &NONCE,
        &reveal_main.pi
    )
    .is_some());
}

// ---------------------------------------------------------------------------
// Group 6 — Abort path via existing downtime math (spec §4.6, O5 reuse-as-is).
// ---------------------------------------------------------------------------

#[test]
fn cnvrf_group6_abort_path_downtime_math() {
    // Caller-side absence predicate (unit level, no ledger).
    let empty: BTreeMap<([u8; 32], u64), stellereum::cn_vrf::CommitmentRecord> = BTreeMap::new();
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
    let beta_a = cnvrf_verify(
        sk.pubkey(),
        &commit.c,
        CHAIN_MAIN,
        &VID,
        EPOCH,
        &alpha_a,
        &NONCE,
        &ra.pi,
    )
    .expect("fork A verifies");
    let beta_b = cnvrf_verify(
        sk.pubkey(),
        &commit.c,
        CHAIN_MAIN,
        &VID,
        EPOCH,
        &alpha_b,
        &NONCE,
        &rb.pi,
    )
    .expect("fork B verifies");
    assert_ne!(beta_a, beta_b, "distinct fork alphas ⇒ independent betas");
    // Identical parent hash on both forks ⇒ identical beta (agreement, not bug).
    let beta_a2 = cnvrf_verify(
        sk.pubkey(),
        &commit.c,
        CHAIN_MAIN,
        &VID,
        EPOCH,
        &alpha_a,
        &NONCE,
        &ra.pi,
    )
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
    // Rotation effective at the epoch boundary (delay 30_000 = one epoch).
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
        cnvrf_verify_with_resolver(
            &resolver,
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            draw_old,
            &ALPHA,
            &NONCE,
            &reveal_old.pi
        )
        .is_some(),
        "pre-effective draws verify under the old key"
    );
    assert!(
        cnvrf_verify_with_resolver(
            &resolver,
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            draw_old,
            &ALPHA,
            &NONCE,
            &reveal_new.pi
        )
        .is_none(),
        "new-key reveal refuses pre-effective"
    );
    // Post-effective, the commitment was made under the old key, so the old
    // reveal refuses once the resolver serves the new key (stale key), while
    // a reveal authorized by the new key verifies (same nonce binding).
    let commit_new = cnvrf_commit(&new, CHAIN_MAIN, &VID, EPOCH, &NONCE);
    assert!(
        cnvrf_verify_with_resolver(
            &resolver,
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            draw_new,
            &ALPHA,
            &NONCE,
            &reveal_old.pi
        )
        .is_none(),
        "superseded-key reveal refuses post-effective"
    );
    assert!(
        cnvrf_verify_with_resolver(
            &resolver,
            &commit_new.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            draw_new,
            &ALPHA,
            &NONCE,
            &reveal_new.pi
        )
        .is_some(),
        "post-effective draws verify under the new key"
    );
    // History depth 2: a resolver keeping only the two newest keys refuses
    // the oldest (third rotation retires it).
    let resolver2 = |_: [u8; 32], _: u64| -> Option<Vec<u8>> { Some(third_pk.clone()) };
    let reveal_third = cnvrf_open(&third, CHAIN_MAIN, &VID, EPOCH, &NONCE, &ALPHA);
    assert!(
        cnvrf_verify_with_resolver(
            &resolver2,
            &commit.c,
            CHAIN_MAIN,
            &VID,
            EPOCH,
            draw_new,
            &ALPHA,
            &NONCE,
            &reveal_old.pi
        )
        .is_none(),
        "retired key (beyond history depth) refuses"
    );
    assert!(cnvrf_verify_with_resolver(
        &resolver2,
        &commit_hash(CHAIN_MAIN, &VID, EPOCH, &NONCE),
        CHAIN_MAIN,
        &VID,
        EPOCH,
        draw_new,
        &ALPHA,
        &NONCE,
        &reveal_third.pi
    )
    .is_some());
    // Unresolvable key ⇒ None (fail-closed).
    let resolver_none = |_: [u8; 32], _: u64| -> Option<Vec<u8>> { None };
    assert!(cnvrf_verify_with_resolver(
        &resolver_none,
        &commit.c,
        CHAIN_MAIN,
        &VID,
        EPOCH,
        draw_new,
        &ALPHA,
        &NONCE,
        &reveal_old.pi
    )
    .is_none());
}

// ---------------------------------------------------------------------------
// Group 9 — KAT sizes byte-exact (spec §4.9, sourced post_quantum.rs:103-111).
// ---------------------------------------------------------------------------

#[test]
fn cnvrf_group9_kat_sizes() {
    assert_eq!(FALCON512_PUBKEY_LEN, 897);
    assert_eq!(FALCON512_SIG_LEN, 666);
    assert_eq!(CNVRF_PI_LEN, 666);
    assert_eq!(
        CNVRF_COMMIT_DST.len(),
        21,
        "normative tag value, not the spec's 20 B print"
    );
    assert_eq!(
        CNVRF_COMMIT_SIG_DST.len(),
        25,
        "commit-sig domain separation tag"
    );
    assert_eq!(
        CNVRF_OPEN_DST.len(),
        19,
        "normative tag value, not the spec's 18 B print"
    );
    assert_eq!(
        CNVRF_BETA_DST.len(),
        19,
        "normative tag value, not the spec's 18 B print"
    );
    assert_eq!(COMMIT_PREIMAGE_LEN, 101);
    assert_eq!(COMMIT_SIG_MESSAGE_LEN, 105);
    assert_eq!(OPEN_MESSAGE_LEN, 131);
    assert_eq!(BETA_PREIMAGE_LEN, 123);
    assert_eq!(
        commit_preimage_bytes(CHAIN_MAIN, &VID, EPOCH, &NONCE).len(),
        101
    );
    assert_eq!(
        commit_sig_message_bytes(CHAIN_MAIN, &VID, EPOCH, &NONCE).len(),
        105
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
    assert_eq!(EPOCH_LEN, 30_000);
    assert_eq!(epoch_of_height(0), 0);
    assert_eq!(epoch_of_height(EPOCH_LEN - 1), 0);
    assert_eq!(epoch_of_height(EPOCH_LEN), 1);
    assert_eq!(epoch_of_height(2 * EPOCH_LEN - 1), 1);
    assert_eq!(epoch_of_height(2 * EPOCH_LEN), 2);
    assert_eq!(epoch_start_height(1), EPOCH_LEN);
    // epoch(N) covers [N*EPOCH_LEN, (N+1)*EPOCH_LEN).
    for h in [
        0,
        1,
        EPOCH_LEN - 1,
        EPOCH_LEN,
        EPOCH_LEN + 1,
        2 * EPOCH_LEN - 1,
        2 * EPOCH_LEN,
    ] {
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
    assert!(
        !cnvrf_mark_revealed(&mut store, &VID, EPOCH, EPOCH + 1),
        "wrong epoch never marks"
    );
    assert!(
        !cnvrf_mark_revealed(&mut store, &[0xFF; 32], EPOCH, EPOCH),
        "unknown validator never marks"
    );
    assert!(cnvrf_mark_revealed(&mut store, &VID, EPOCH, EPOCH));
    assert!(store[&(VID, EPOCH)].revealed);
    // Expiry: epoch N ends ⇒ EXPIRED; only older entries removed.
    let c_next = commit_hash(CHAIN_MAIN, &VID, EPOCH + 1, &NONCE);
    assert_eq!(
        cnvrf_commit_state(&mut store, &VID, EPOCH + 1, &c_next, 20, EPOCH),
        Ok(CommitOutcome::Accepted)
    );
    assert_eq!(
        cnvrf_expire_before(&mut store, EPOCH),
        0,
        "current epoch kept"
    );
    assert_eq!(
        cnvrf_expire_before(&mut store, EPOCH + 1),
        1,
        "past epoch expired"
    );
    assert!(!store.contains_key(&(VID, EPOCH)));
    assert!(store.contains_key(&(VID, EPOCH + 1)));
    assert_eq!(cnvrf_expire_before(&mut store, EPOCH + 1), 0, "idempotent");
}

#[test]
fn cnvrf_nonce_file_custody_o6() {
    let dir = std::env::temp_dir().join(format!("cnvrf_test_{}", std::process::id()));
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
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
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
    assert_eq!(CNVRF_COMMIT_SIG_DST, b"STELL_CNVRF_COMMIT_SIG_V1");
    assert_eq!(CNVRF_OPEN_DST, b"STELL_CNVRF_OPEN_V1");
    assert_eq!(CNVRF_BETA_DST, b"STELL_CNVRF_BETA_V1");
    assert_ne!(CNVRF_COMMIT_DST, CNVRF_COMMIT_SIG_DST);
    assert_ne!(CNVRF_COMMIT_DST, CNVRF_OPEN_DST);
    assert_ne!(CNVRF_COMMIT_DST, CNVRF_BETA_DST);
    assert_ne!(CNVRF_COMMIT_SIG_DST, CNVRF_OPEN_DST);
    assert_ne!(CNVRF_COMMIT_SIG_DST, CNVRF_BETA_DST);
    assert_ne!(CNVRF_OPEN_DST, CNVRF_BETA_DST);
}

#[test]
fn cnvrf_verify_commit_epoch_n_minus_1_and_anti_squatting() {
    let validator_sk = key(0xC1);
    let attacker_sk = key(0xC2);
    // In epoch N-1, verifier has ONLY (carrier, chain_id, pk) — never `nonce`.
    let carrier = cnvrf_commit(&validator_sk, CHAIN_MAIN, &VID, EPOCH, &NONCE);
    assert_eq!(
        cnvrf_verify_commit(&carrier, CHAIN_MAIN, validator_sk.pubkey()),
        Ok(()),
        "valid CommitCarrier verifies in epoch N-1 without knowing nonce"
    );

    // Tampered commitment `c` fails closed.
    let mut bad_c = carrier.clone();
    bad_c.c = flip(bad_c.c);
    assert_eq!(
        cnvrf_verify_commit(&bad_c, CHAIN_MAIN, validator_sk.pubkey()),
        Err(CnVrfError::InvalidCommitSignature),
        "tampered commitment must fail closed"
    );

    // Tampered `epoch_n` fails closed.
    let mut bad_epoch = carrier.clone();
    bad_epoch.epoch_n += 1;
    assert_eq!(
        cnvrf_verify_commit(&bad_epoch, CHAIN_MAIN, validator_sk.pubkey()),
        Err(CnVrfError::InvalidCommitSignature),
        "tampered epoch_n must fail closed"
    );

    // Tampered `validator_id` fails closed.
    let mut bad_vid = carrier.clone();
    bad_vid.validator_id = flip(bad_vid.validator_id);
    assert_eq!(
        cnvrf_verify_commit(&bad_vid, CHAIN_MAIN, validator_sk.pubkey()),
        Err(CnVrfError::InvalidCommitSignature),
        "tampered validator_id must fail closed"
    );

    // Wrong `chain_id` fails closed.
    assert_eq!(
        cnvrf_verify_commit(&carrier, CHAIN_ALT, validator_sk.pubkey()),
        Err(CnVrfError::InvalidCommitSignature),
        "wrong chain_id must fail closed"
    );

    // Tampered `sig` fails closed.
    let mut bad_sig = carrier.clone();
    bad_sig.sig[0] ^= 0x01;
    assert_eq!(
        cnvrf_verify_commit(&bad_sig, CHAIN_MAIN, validator_sk.pubkey()),
        Err(CnVrfError::InvalidCommitSignature),
        "tampered sig must fail closed"
    );

    // Empty / all-zero `sig` fails closed.
    let mut zero_sig = carrier.clone();
    zero_sig.sig = [0u8; FALCON512_SIG_LEN];
    assert_eq!(
        cnvrf_verify_commit(&zero_sig, CHAIN_MAIN, validator_sk.pubkey()),
        Err(CnVrfError::InvalidCommitSignature),
        "all-zero sig must fail closed"
    );

    // Foreign key fails closed.
    assert_eq!(
        cnvrf_verify_commit(&carrier, CHAIN_MAIN, attacker_sk.pubkey()),
        Err(CnVrfError::InvalidCommitSignature),
        "wrong public key must fail closed"
    );

    // Bad public key lengths fail closed.
    let mut pk_short = validator_sk.pubkey().to_vec();
    pk_short.truncate(FALCON512_PUBKEY_LEN - 1);
    let mut pk_long = validator_sk.pubkey().to_vec();
    pk_long.push(0x00);
    assert_eq!(
        cnvrf_verify_commit(&carrier, CHAIN_MAIN, &pk_short),
        Err(CnVrfError::InvalidPublicKeyLength)
    );
    assert_eq!(
        cnvrf_verify_commit(&carrier, CHAIN_MAIN, &pk_long),
        Err(CnVrfError::InvalidPublicKeyLength)
    );
    assert_eq!(
        cnvrf_verify_commit(&carrier, CHAIN_MAIN, &[]),
        Err(CnVrfError::InvalidPublicKeyLength)
    );

    // Anti-squatting: attacker tries to squat (VID, EPOCH) with forged/foreign-signed
    // carriers BEFORE the real validator commits.
    let mut store = BTreeMap::new();
    let forged_by_attacker = cnvrf_commit(&attacker_sk, CHAIN_MAIN, &VID, EPOCH, &[0x99; 32]);
    assert_eq!(
        cnvrf_commit_verified_state(
            &mut store,
            &forged_by_attacker,
            CHAIN_MAIN,
            validator_sk.pubkey(),
            100,
            EPOCH - 1,
        ),
        Err(CnVrfError::InvalidCommitSignature),
        "foreign-signed carrier must not squat slot"
    );
    assert!(store.is_empty(), "failed verify must leave store untouched");

    assert_eq!(
        cnvrf_commit_verified_state(
            &mut store,
            &bad_c,
            CHAIN_MAIN,
            validator_sk.pubkey(),
            100,
            EPOCH - 1,
        ),
        Err(CnVrfError::InvalidCommitSignature),
        "tampered commitment must not squat slot"
    );
    assert!(store.is_empty());

    // State transition rules still apply after signature verification.
    assert_eq!(
        cnvrf_commit_verified_state(
            &mut store,
            &carrier,
            CHAIN_MAIN,
            validator_sk.pubkey(),
            100,
            EPOCH,
        ),
        Err(CnVrfError::CommitState(CommitError::StaleOrCurrent))
    );
    assert!(store.is_empty());

    // Legitimate validator commits successfully into the un-squatted slot.
    assert_eq!(
        cnvrf_commit_verified_state(
            &mut store,
            &carrier,
            CHAIN_MAIN,
            validator_sk.pubkey(),
            101,
            EPOCH - 1,
        ),
        Ok(CommitOutcome::Accepted)
    );
    assert_eq!(store[&(VID, EPOCH)].c, carrier.c);
    assert_eq!(store[&(VID, EPOCH)].commit_height, 101);

    // Duplicate valid commit is ignored without mutating the record.
    let carrier2 = cnvrf_commit(&validator_sk, CHAIN_MAIN, &VID, EPOCH, &NONCE);
    assert_eq!(
        cnvrf_commit_verified_state(
            &mut store,
            &carrier2,
            CHAIN_MAIN,
            validator_sk.pubkey(),
            102,
            EPOCH - 1,
        ),
        Ok(CommitOutcome::IgnoredDuplicate)
    );
    assert_eq!(store[&(VID, EPOCH)].commit_height, 101);
}

#[test]
fn cnvrf_nonce_file_rejects_symlinks_and_loose_perms() {
    let dir = std::env::temp_dir().join(format!("cnvrf_custody_sec_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create test dir");

    let real_path = dir.join("real.nonce");
    save_cnvrf_nonce_to_file(&real_path, &NONCE).expect("save must succeed");
    assert_eq!(
        load_cnvrf_nonce_from_file(&real_path).expect("load 0600"),
        NONCE
    );

    // Overwrite existing file atomically and confirm no leftover temp files.
    let nonce2 = [0x44u8; 32];
    save_cnvrf_nonce_to_file(&real_path, &nonce2).expect("atomic overwrite must succeed");
    assert_eq!(
        load_cnvrf_nonce_from_file(&real_path).expect("load overwritten"),
        nonce2
    );
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, vec!["real.nonce".to_string()]);

    // Directory path refused on load and save.
    assert!(load_cnvrf_nonce_from_file(&dir).is_err());
    assert!(save_cnvrf_nonce_to_file(&dir, &NONCE).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};

        // Symlink pointing to a valid 0600 nonce file must be refused on load AND save.
        let link_path = dir.join("link.nonce");
        symlink(&real_path, &link_path).expect("create symlink");
        assert!(
            load_cnvrf_nonce_from_file(&link_path).is_err(),
            "symlink must be refused on nonce load"
        );
        assert!(
            save_cnvrf_nonce_to_file(&link_path, &NONCE).is_err(),
            "symlink must be refused on nonce save"
        );
        // Target must remain untouched (`nonce2`, not overwritten with `NONCE`).
        assert_eq!(
            load_cnvrf_nonce_from_file(&real_path).expect("target untouched"),
            nonce2
        );

        // Symlinked parent directory must be refused on save.
        let dir_link = dir.join("sub_link");
        let real_sub = dir.join("real_sub");
        std::fs::create_dir_all(&real_sub).expect("create subdir");
        symlink(&real_sub, &dir_link).expect("create dir symlink");
        assert!(
            save_cnvrf_nonce_to_file(&dir_link.join("child.nonce"), &NONCE).is_err(),
            "symlinked parent dir must be refused on save"
        );

        // Loose permissions (any group/other bits: 0o640, 0o604, 0o644, 0o610, 0o601) refused.
        for bad_mode in [0o640u32, 0o604, 0o644, 0o610, 0o601] {
            std::fs::set_permissions(&real_path, std::fs::Permissions::from_mode(bad_mode))
                .expect("chmod bad");
            assert!(
                load_cnvrf_nonce_from_file(&real_path).is_err(),
                "mode 0o{bad_mode:03o} must be refused"
            );
        }

        // Strict owner-only 0o400 and 0o600 accepted.
        for ok_mode in [0o400u32, 0o600] {
            std::fs::set_permissions(&real_path, std::fs::Permissions::from_mode(ok_mode))
                .expect("chmod ok");
            assert_eq!(
                load_cnvrf_nonce_from_file(&real_path).expect("owner-only mode accepted"),
                nonce2
            );
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// CN-VRF v3 tests — 16-segment BLAKE3-XOF-48 reverse hash-chain, state
// machine, cutoff, key rotation migration, fallback seed, and enc2: custody
// ===========================================================================

const V3_SECRET: [u8; V3_LINK_LEN] = [0x5Au8; V3_LINK_LEN];

#[test]
fn cnvrf_v3_constants_dsts_and_blake3_xof_48() {
    assert_eq!(V3_LINK_LEN, 48);
    assert_eq!(V3_SEGMENTS, 16);
    assert_eq!(V3_SEGMENT_LEN, 1_875);
    assert_eq!(V3_SEGMENTS as u64 * V3_SEGMENT_LEN, EPOCH_LEN);
    assert_eq!(V3_COMMIT_LOOKAHEAD_BLOCKS, 682);
    assert_eq!(COMMIT_CARRIER_V3_LEN, 1474);

    let dsts = [
        DST_CHAIN_V3,
        DST_COMMIT_SIG_V3,
        DST_BETA_V3,
        DST_EPOCH_RAW_SEED_V3,
        DST_V3_SEED_DERIVE,
    ];
    for (i, d) in dsts.iter().enumerate() {
        assert!(d.is_ascii(), "DST must be ASCII: {d}");
        assert!(d.ends_with("_V3"), "DST must end with _V3: {d}");
        for (j, other) in dsts.iter().enumerate() {
            if i != j {
                assert_ne!(d, other, "DSTs must be pairwise distinct");
            }
        }
    }

    // Zero-allocation blake3_xof_48 determinism + domain separation.
    let h1 = blake3_xof_48(DST_CHAIN_V3, &[b"hello", b"world"]);
    let h2 = blake3_xof_48(DST_CHAIN_V3, &[b"hello", b"world"]);
    let h3 = blake3_xof_48(DST_BETA_V3, &[b"hello", b"world"]);
    assert_eq!(h1, h2);
    assert_ne!(h1, h3);

    // Master secret derivation is domain-separated and binds chain/validator/epoch.
    let s_a = derive_v3_epoch_secret(b"master-key", CHAIN_MAIN, &VID, EPOCH);
    let s_b = derive_v3_epoch_secret(b"master-key", CHAIN_ALT, &VID, EPOCH);
    let s_c = derive_v3_epoch_secret(b"master-key", CHAIN_MAIN, &VID, EPOCH + 1);
    assert_ne!(&*s_a, &*s_b);
    assert_ne!(&*s_a, &*s_c);
}

#[test]
fn cnvrf_v3_chain_anchors_commit_verify_and_serde() {
    let sk = key(0xD1);
    let other_sk = key(0xD2);
    let chain = CnVrfV3Chain::generate(CHAIN_MAIN, &VID, EPOCH, &V3_SECRET);

    // O(1)-memory compute_v3_anchors matches full CnVrfV3Chain anchors.
    let anchors_o1 = compute_v3_anchors(CHAIN_MAIN, &VID, EPOCH, &V3_SECRET);
    assert_eq!(chain.anchors(), &anchors_o1);
    assert_eq!(chain.root_anchor(), anchors_o1[0]);

    // Slot EPOCH_LEN-1 reveals x_{EPOCH_LEN} = s_{i,N}; slot EPOCH_LEN is out of bounds.
    assert_eq!(chain.reveal_for_slot(EPOCH_LEN - 1), Some(V3_SECRET));
    assert_eq!(chain.reveal_for_slot(EPOCH_LEN), None);
    assert_eq!(
        chain.reveal_for_height(EPOCH * EPOCH_LEN + 42),
        chain.reveal_for_slot(42)
    );
    assert_eq!(chain.reveal_for_height((EPOCH + 1) * EPOCH_LEN), None);

    // CommitCarrierV3 via both cnvrf_v3_commit and CnVrfV3Chain::commit_carrier.
    let carrier = cnvrf_v3_commit(&sk, CHAIN_MAIN, &VID, EPOCH, &V3_SECRET);
    assert_eq!(carrier.anchors, anchors_o1);
    assert_eq!(carrier.encoded_len(), COMMIT_CARRIER_V3_LEN);
    assert_eq!(
        cnvrf_v3_verify_commit(&carrier, CHAIN_MAIN, sk.pubkey()),
        Ok(())
    );

    let carrier2 = chain.commit_carrier(&sk);
    assert_eq!(carrier2.anchors, carrier.anchors);
    assert_eq!(
        cnvrf_v3_verify_commit(&carrier2, CHAIN_MAIN, sk.pubkey()),
        Ok(())
    );

    // Serde round-trip (bincode + JSON) for CommitCarrierV3.
    let bin = bincode::serialize(&carrier).expect("bincode serialize CommitCarrierV3");
    let decoded_bin: CommitCarrierV3 =
        bincode::deserialize(&bin).expect("bincode deserialize CommitCarrierV3");
    assert_eq!(decoded_bin, carrier);

    let json = serde_json::to_string(&carrier).expect("json serialize CommitCarrierV3");
    let decoded_json: CommitCarrierV3 =
        serde_json::from_str(&json).expect("json deserialize CommitCarrierV3");
    assert_eq!(decoded_json, carrier);

    // Fail-closed checks on cnvrf_v3_verify_commit.
    assert_eq!(
        cnvrf_v3_verify_commit(&carrier, CHAIN_ALT, sk.pubkey()),
        Err(CnVrfError::InvalidCommitSignature)
    );
    assert_eq!(
        cnvrf_v3_verify_commit(&carrier, CHAIN_MAIN, other_sk.pubkey()),
        Err(CnVrfError::InvalidCommitSignature)
    );
    assert_eq!(
        cnvrf_v3_verify_commit(
            &carrier,
            CHAIN_MAIN,
            &sk.pubkey()[..FALCON512_PUBKEY_LEN - 1]
        ),
        Err(CnVrfError::InvalidPublicKeyLength)
    );
    let mut zero_sig = carrier.clone();
    zero_sig.sig = [0u8; FALCON512_SIG_LEN];
    assert_eq!(
        cnvrf_v3_verify_commit(&zero_sig, CHAIN_MAIN, sk.pubkey()),
        Err(CnVrfError::InvalidCommitSignature)
    );
    let mut tampered_anchor = carrier.clone();
    tampered_anchor.anchors[15][0] ^= 0x01;
    assert_eq!(
        cnvrf_v3_verify_commit(&tampered_anchor, CHAIN_MAIN, sk.pubkey()),
        Err(CnVrfError::InvalidCommitSignature)
    );
}

#[test]
fn cnvrf_v3_slot_by_slot_skip_ahead_and_replay_rejection() {
    let chain = CnVrfV3Chain::generate(CHAIN_MAIN, &VID, EPOCH, &V3_SECRET);
    let mut rec = CnVrfV3Record {
        anchors: *chain.anchors(),
        head: chain.anchors()[0],
        last_step: 0,
        commit_height: 100,
        anchor_validator_id: VID,
    };

    // Slot 0: 1 step against anchors[0].
    let rev0 = chain.reveal_for_slot(0).unwrap();
    assert_eq!(
        cnvrf_v3_verify_reveal(&rec, CHAIN_MAIN, &VID, EPOCH, 0, &rev0),
        Ok(1)
    );
    rec.head = rev0;
    rec.last_step = 1;

    // Replay of slot 0 fails.
    assert!(cnvrf_v3_verify_reveal(&rec, CHAIN_MAIN, &VID, EPOCH, 0, &rev0).is_err());

    // Skip ahead within segment 0 to slot S-1 (S = V3_SEGMENT_LEN): verifies
    // against head (x_1) in S-1 steps!
    let last0 = V3_SEGMENT_LEN - 1;
    let rev_last0 = chain.reveal_for_slot(last0).unwrap();
    assert_eq!(
        cnvrf_v3_verify_reveal(&rec, CHAIN_MAIN, &VID, EPOCH, last0, &rev_last0),
        Ok(last0)
    );
    rec.head = rev_last0;
    rec.last_step = V3_SEGMENT_LEN;

    // Replay of any earlier slot (< S) fails.
    assert!(cnvrf_v3_verify_reveal(&rec, CHAIN_MAIN, &VID, EPOCH, last0, &rev_last0).is_err());
    assert!(cnvrf_v3_verify_reveal(&rec, CHAIN_MAIN, &VID, EPOCH, 100, &rev_last0).is_err());

    // Cross-segment skip: jump straight to slot 2S-1 (last slot of segment 1):
    // verifies against anchors[1] (x_S) in exactly S steps.
    let last1 = 2 * V3_SEGMENT_LEN - 1;
    let rev_last1 = chain.reveal_for_slot(last1).unwrap();
    assert_eq!(
        cnvrf_v3_verify_reveal(&rec, CHAIN_MAIN, &VID, EPOCH, last1, &rev_last1),
        Ok(V3_SEGMENT_LEN)
    );
    rec.head = rev_last1;
    rec.last_step = 2 * V3_SEGMENT_LEN;

    // Multi-segment jump straight to the very last slot EPOCH_LEN-1
    // (segment 15): verifies against anchors[15] (x_{15S}) in exactly S steps.
    let last_slot = EPOCH_LEN - 1;
    let rev_last = chain.reveal_for_slot(last_slot).unwrap();
    assert_eq!(
        cnvrf_v3_verify_reveal(&rec, CHAIN_MAIN, &VID, EPOCH, last_slot, &rev_last),
        Ok(V3_SEGMENT_LEN)
    );
    rec.head = rev_last;
    rec.last_step = EPOCH_LEN;

    // Out-of-bounds slot EPOCH_LEN rejected; wrong reveal rejected.
    assert!(cnvrf_v3_verify_reveal(&rec, CHAIN_MAIN, &VID, EPOCH, EPOCH_LEN, &rev_last).is_err());
    let mut bad_rev = chain.reveal_for_slot(1000).unwrap();
    bad_rev[0] ^= 0xFF;
    let fresh_rec = CnVrfV3Record {
        anchors: *chain.anchors(),
        head: chain.anchors()[0],
        last_step: 0,
        commit_height: 100,
        anchor_validator_id: VID,
    };
    assert!(cnvrf_v3_verify_reveal(&fresh_rec, CHAIN_MAIN, &VID, EPOCH, 1000, &bad_rev).is_err());
}

#[test]
fn cnvrf_v3_commit_cutoff_lookahead_and_state_machine() {
    let sk = key(0xD3);
    let mut state = CnVrfV3State::new();
    let target_epoch = EPOCH; // epoch 5 starts at 5 * EPOCH_LEN
    let h_freeze = target_epoch * EPOCH_LEN - V3_COMMIT_LOOKAHEAD_BLOCKS;
    let carrier = cnvrf_v3_commit(&sk, CHAIN_MAIN, &VID, target_epoch, &V3_SECRET);

    // Wrong epoch (stale / current / too far ahead) refused.
    assert_eq!(
        state.admit_commit(&carrier, target_epoch * EPOCH_LEN, CHAIN_MAIN, sk.pubkey()),
        Err(CnVrfError::CommitState(CommitError::StaleOrCurrent))
    );
    assert_eq!(
        state.admit_commit(
            &carrier,
            (target_epoch - 2) * EPOCH_LEN,
            CHAIN_MAIN,
            sk.pubkey()
        ),
        Err(CnVrfError::CommitState(CommitError::TooFarAhead))
    );

    // At exactly H_freeze and inside the final V3_COMMIT_LOOKAHEAD_BLOCKS: refused!
    assert_eq!(
        state.admit_commit(&carrier, h_freeze, CHAIN_MAIN, sk.pubkey()),
        Err(CnVrfError::CommitState(CommitError::PastCommitCutoff))
    );
    assert_eq!(
        state.admit_commit(
            &carrier,
            target_epoch * EPOCH_LEN - 1,
            CHAIN_MAIN,
            sk.pubkey()
        ),
        Err(CnVrfError::CommitState(CommitError::PastCommitCutoff))
    );

    // At H_freeze - 1: accepted!
    assert_eq!(
        state.admit_commit(&carrier, h_freeze - 1, CHAIN_MAIN, sk.pubkey()),
        Ok(CommitOutcome::Accepted)
    );
    // First-committed-wins duplicate returns IgnoredDuplicate without overwriting commit_height.
    let carrier_dup = cnvrf_v3_commit(&sk, CHAIN_MAIN, &VID, target_epoch, &[0x99u8; 48]);
    assert_eq!(
        state.admit_commit(&carrier_dup, h_freeze - 2, CHAIN_MAIN, sk.pubkey()),
        Ok(CommitOutcome::IgnoredDuplicate)
    );
    assert_eq!(
        state.get_record(&VID, target_epoch).unwrap().commit_height,
        h_freeze - 1
    );
    assert_eq!(
        state.get_record(&VID, target_epoch).unwrap().anchors,
        carrier.anchors
    );
}

#[test]
fn cnvrf_v3_key_rotation_migration_preserves_anchor_validator_id() {
    let sk_old = key(0xD4);
    let old_id = [0x41u8; 32];
    let new_id = [0x42u8; 32];
    let third_id = [0x43u8; 32];

    let chain = CnVrfV3Chain::generate(CHAIN_MAIN, &old_id, EPOCH, &V3_SECRET);
    let carrier = chain.commit_carrier(&sk_old);

    let mut state = CnVrfV3State::new();
    let commit_height = (EPOCH - 1) * EPOCH_LEN + 100;
    assert_eq!(
        state.admit_commit(&carrier, commit_height, CHAIN_MAIN, sk_old.pubkey()),
        Ok(CommitOutcome::Accepted)
    );

    // Migrate old_id -> new_id for EPOCH onward (simulating StakingLedger::rotate_key).
    state.migrate_validator(&old_id, &new_id, EPOCH);
    assert!(state.get_record(&old_id, EPOCH).is_none());
    let migrated_rec = state.get_record(&new_id, EPOCH).expect("migrated record");
    assert_eq!(migrated_rec.anchor_validator_id, old_id);

    // New validator_id proposes at slot 10 of EPOCH using the pre-committed chain.
    let rev10 = chain.reveal_for_slot(10).unwrap();
    let h10 = EPOCH * EPOCH_LEN + 10;
    assert_eq!(
        state.apply_slot_reveal(CHAIN_MAIN, &new_id, h10, Some(&rev10)),
        SlotRevealOutcome::Revealed { steps: 11 }
    );

    // Double rotation new_id -> third_id still preserves anchor_validator_id == old_id!
    state.migrate_validator(&new_id, &third_id, EPOCH);
    // Cross-segment: the first slot of segment 1 plus 50 verifies against
    // anchors[1] in exactly 51 steps.
    let cross_slot = V3_SEGMENT_LEN + 50;
    let rev_cross = chain.reveal_for_slot(cross_slot).unwrap();
    let h_cross = EPOCH * EPOCH_LEN + cross_slot;
    assert_eq!(
        state.apply_slot_reveal(CHAIN_MAIN, &third_id, h_cross, Some(&rev_cross)),
        SlotRevealOutcome::Revealed { steps: 51 }
    );
    assert_eq!(
        state
            .get_record(&third_id, EPOCH)
            .unwrap()
            .anchor_validator_id,
        old_id
    );
}

#[test]
fn cnvrf_v3_reveal_outcomes_rolling_mix_and_fallback_seed() {
    let sk_a = key(0xE1);
    let sk_b = key(0xE2);
    let id_a = [0xA1u8; 32];
    let id_b = [0xB2u8; 32];
    let id_newcomer = [0xC3u8; 32];

    let secret_a = [0x11u8; V3_LINK_LEN];
    let secret_b = [0x22u8; V3_LINK_LEN];
    let chain_a = CnVrfV3Chain::generate(CHAIN_MAIN, &id_a, EPOCH, &secret_a);
    let chain_b = CnVrfV3Chain::generate(CHAIN_MAIN, &id_b, EPOCH, &secret_b);

    let mut state = CnVrfV3State::new();
    let h_commit = (EPOCH - 1) * EPOCH_LEN + 10;
    assert_eq!(
        state.admit_commit(
            &chain_a.commit_carrier(&sk_a),
            h_commit,
            CHAIN_MAIN,
            sk_a.pubkey()
        ),
        Ok(CommitOutcome::Accepted)
    );
    assert_eq!(
        state.admit_commit(
            &chain_b.commit_carrier(&sk_b),
            h_commit + 1,
            CHAIN_MAIN,
            sk_b.pubkey()
        ),
        Ok(CommitOutcome::Accepted)
    );

    let prev_beacon = [0x77u8; V3_LINK_LEN];
    let freeze_hash = [0x88u8; 32];

    // Zero reveals -> deterministic fallback seed with rolling_mix == [0; 48].
    assert_eq!(state.rolling_mix_for_epoch(EPOCH), [0u8; V3_LINK_LEN]);
    let fallback_seed_1 = epoch_raw_seed(CHAIN_MAIN, EPOCH, &prev_beacon, &freeze_hash, &[0u8; 48]);
    let fallback_seed_2 = epoch_raw_seed(CHAIN_MAIN, EPOCH, &prev_beacon, &freeze_hash, &[0u8; 48]);
    assert_eq!(fallback_seed_1, fallback_seed_2);
    assert_ne!(fallback_seed_1, [0u8; V3_LINK_LEN]);

    // Uncommitted newcomer without reveal -> AbsentNoCommit (admissible).
    let h0 = EPOCH * EPOCH_LEN;
    assert_eq!(
        state.apply_slot_reveal(CHAIN_MAIN, &id_newcomer, h0, None),
        SlotRevealOutcome::AbsentNoCommit
    );
    // Uncommitted newcomer WITH reveal -> UnexpectedReveal (reject block).
    assert_eq!(
        state.apply_slot_reveal(CHAIN_MAIN, &id_newcomer, h0, Some(&[0x01; 48])),
        SlotRevealOutcome::UnexpectedReveal
    );

    // Committed validator omitting reveal -> CommittedMissingReveal.
    assert_eq!(
        state.apply_slot_reveal(CHAIN_MAIN, &id_a, h0, None),
        SlotRevealOutcome::CommittedMissingReveal
    );

    // Committed validator with bogus reveal -> InvalidReveal (and state untouched).
    let bad = [0xFEu8; V3_LINK_LEN];
    assert_eq!(
        state.apply_slot_reveal(CHAIN_MAIN, &id_a, h0, Some(&bad)),
        SlotRevealOutcome::InvalidReveal
    );
    assert_eq!(state.rolling_mix_for_epoch(EPOCH), [0u8; V3_LINK_LEN]);

    // 1 validator reveals -> rolling_mix updated deterministically.
    let rev_a0 = chain_a.reveal_for_slot(0).unwrap();
    assert_eq!(
        state.apply_slot_reveal(CHAIN_MAIN, &id_a, h0, Some(&rev_a0)),
        SlotRevealOutcome::Revealed { steps: 1 }
    );
    let mix_after_1 = state.rolling_mix_for_epoch(EPOCH);
    assert_eq!(state.rolling_mix, mix_after_1);
    assert_ne!(mix_after_1, [0u8; V3_LINK_LEN]);

    let seed_1_val = epoch_raw_seed(CHAIN_MAIN, EPOCH, &prev_beacon, &freeze_hash, &mix_after_1);
    assert_ne!(seed_1_val, fallback_seed_1);

    // 2nd validator reveals -> rolling_mix chains again; identical across two independent nodes.
    let h1 = EPOCH * EPOCH_LEN + 1;
    let rev_b1 = chain_b.reveal_for_slot(1).unwrap();
    assert_eq!(
        state.apply_slot_reveal(CHAIN_MAIN, &id_b, h1, Some(&rev_b1)),
        SlotRevealOutcome::Revealed { steps: 2 }
    );
    let mix_after_2 = state.rolling_mix_for_epoch(EPOCH);
    assert_ne!(mix_after_2, mix_after_1);
    let seed_2_val = epoch_raw_seed(CHAIN_MAIN, EPOCH, &prev_beacon, &freeze_hash, &mix_after_2);
    assert_ne!(seed_2_val, seed_1_val);

    // Expiry drops old epochs cleanly.
    assert_eq!(state.expire_before(EPOCH), 0);
    assert_eq!(state.expire_before(EPOCH + 1), 2);
    assert!(state.get_record(&id_a, EPOCH).is_none());
}

#[test]
fn cnvrf_v3_enc2_secret_custody_and_startup_verify() {
    use std::sync::{Mutex, OnceLock};
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    const ENV_VARS: &[&str] = &[
        "STELL_NODE_PASSPHRASE",
        "STELL_KEY_PASSPHRASE",
        "INFNODE_KEY_PASSPHRASE",
        "STELL_KEY_PLAINTEXT",
        "STELL_KEY_PROMPT",
    ];
    struct EnvRestore(Vec<(&'static str, Option<String>)>);
    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (k, v) in self.0.drain(..) {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }
    let _restore = EnvRestore(
        ENV_VARS
            .iter()
            .map(|&k| (k, std::env::var(k).ok()))
            .collect(),
    );
    for k in ENV_VARS {
        std::env::remove_var(k);
    }

    let dir = std::env::temp_dir().join(format!("cnvrf_v3_custody_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let secret_path = dir.join("epoch5_v3.secret");

    // Without passphrase and without STELL_KEY_PLAINTEXT=1 -> fail-closed!
    assert!(
        save_cnvrf_v3_secret(&secret_path, &V3_SECRET).is_err(),
        "must refuse to write unencrypted v3 secret without passphrase"
    );
    assert!(!secret_path.exists());

    // With STELL_KEY_PASSPHRASE -> encrypted enc2: with 0600 permissions.
    std::env::set_var("STELL_KEY_PASSPHRASE", "v3-test-passphrase-correct");
    save_cnvrf_v3_secret(&secret_path, &V3_SECRET).expect("save encrypted v3 secret");

    let on_disk = std::fs::read_to_string(&secret_path).expect("read raw file");
    assert!(on_disk.starts_with("enc2:"), "must use enc2: format");
    assert!(
        !on_disk.contains(&hex::encode(V3_SECRET)),
        "secret must not leak in ciphertext"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&secret_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "secret file must be 0600");
    }

    // Round-trip load + startup verification against committed anchors.
    let loaded = load_cnvrf_v3_secret(&secret_path).expect("load encrypted v3 secret");
    assert_eq!(*loaded, V3_SECRET);

    let anchors = compute_v3_anchors(CHAIN_MAIN, &VID, EPOCH, &loaded);
    assert!(verify_v3_secret_matches_commit(
        &loaded, CHAIN_MAIN, &VID, EPOCH, &anchors
    ));
    assert!(!verify_v3_secret_matches_commit(
        &loaded, CHAIN_ALT, &VID, EPOCH, &anchors
    ));
    assert!(!verify_v3_secret_matches_commit(
        &[0x00; V3_LINK_LEN],
        CHAIN_MAIN,
        &VID,
        EPOCH,
        &anchors
    ));

    // Wrong passphrase -> fail-closed.
    std::env::set_var("STELL_KEY_PASSPHRASE", "wrong-passphrase");
    assert!(load_cnvrf_v3_secret(&secret_path).is_err());

    // Missing passphrase -> fail-closed.
    std::env::remove_var("STELL_KEY_PASSPHRASE");
    assert!(load_cnvrf_v3_secret(&secret_path).is_err());

    // Loose permissions (0644) -> fail-closed even with right passphrase.
    std::env::set_var("STELL_KEY_PASSPHRASE", "v3-test-passphrase-correct");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_cnvrf_v3_secret(&secret_path).is_err());
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Symlink refused on load and save.
        let link_path = dir.join("link_v3.secret");
        std::os::unix::fs::symlink(&secret_path, &link_path).unwrap();
        assert!(load_cnvrf_v3_secret(&link_path).is_err());
        assert!(save_cnvrf_v3_secret(&link_path, &V3_SECRET).is_err());
    }

    // Explicit STELL_KEY_PLAINTEXT=1 opt-out path works and still enforces 0600.
    std::env::remove_var("STELL_KEY_PASSPHRASE");
    std::env::set_var("STELL_KEY_PLAINTEXT", "1");
    let plain_path = dir.join("epoch5_v3_plain.secret");
    save_cnvrf_v3_secret(&plain_path, &V3_SECRET).expect("save plaintext opt-out");
    let loaded_plain = load_cnvrf_v3_secret(&plain_path).expect("load plaintext opt-out");
    assert_eq!(*loaded_plain, V3_SECRET);

    let _ = std::fs::remove_dir_all(&dir);
}
