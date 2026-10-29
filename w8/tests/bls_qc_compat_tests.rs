//! BLS quorum certificates on the real path (passport §6B).
//!
//! Proves, with golden bytes captured from the PRE-change baseline:
//! * old certificate bytes decode AND verify under the new code (compat);
//! * new certificate bytes decode under the old field layout, and old
//!   verification FAILS CLOSED on a certificate whose only power is the BLS
//!   aggregate (while still accepting an augmented certificate that carries
//!   the Ed25519 quorum — so mixed old/new nodes do not fork);
//! * strict verification: pairing against the full canonical validator
//!   registry, membership by construction, power from the validator set —
//!   tampered/insufficient/mis-bound aggregates reject, and ANY BLS failure
//!   falls back to the Ed25519 list;
//! * activation is flag-gated (default OFF) and two ValidatorRuntimes on
//!   opposite sides of the flag agree on the same chain.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use stellereum::bls::*;
use stellereum::consensus::*;
use std::collections::{BTreeMap, HashSet};

/// bincode(QuorumCertificate) captured from the code BEFORE the BLS envelope
/// existed: height 7, round 1, precommit for block 0xAB*32, signed by the
/// fixed keys `[11u8;32]` and `[22u8;32]`.
///
/// The two Ed25519 signatures were RE-CAPTURED when the vote preimage became
/// chain-bound (`STELLEREUM_BFT_VOTE_V2` || chain_id || ...): the certificate
/// body, the keys and the layout are unchanged, but a signature over the old
/// preimage no longer verifies — which is exactly the cross-chain replay
/// protection the chain id buys.
const GOLDEN_QC_HEX: &str = "0700000000000000010000000100000001abababababababababababababababababababababababababababababababab020000000000000066be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a4000000000000000a12471a7daeb30e312e1cae2b55254ac201f73fb4468e34c18810b0d715d124286fd5612b9f546cd07793daaa9d19016f3497c1c29e17436cf236765488e1100511c34a1a2cb521df16bb246b8de8e7997ce235c7e76b22a3d7503a24819dd8a400000000000000048b81d90ee06da68031f45825a99ddcb859d035e84f34a3e4b7396e55473d4fcb37d41f2950dcd5b0ac21e2e9ef0a776c72f49af546b3c3d3f437a5a02a66400";

fn golden_bytes() -> Vec<u8> {
    hex::decode(GOLDEN_QC_HEX).expect("golden hex")
}

/// Field-for-field mirror of `QuorumCertificate` as it existed BEFORE the BLS
/// envelope was added — the same fields in the same order. Decoding new
/// certificate bytes into this old layout (and re-encoding) is the structural
/// half of the compat proof: the envelope rides inside `signatures`, so the
/// bincode layout never changed in either direction.
#[derive(Serialize, Deserialize)]
struct OldQuorumCertificate {
    height: u64,
    round: u32,
    kind: VoteKind,
    block_hash: Option<BlockHash>,
    signatures: Vec<(ValidatorId, Vec<u8>)>,
}

/// Verbatim baseline `QuorumCertificate::verify` (pre-BLS): exactly what an
/// OLD binary does with decoded certificate bytes — no BLS path, no envelope
/// handling, Ed25519 list only.
fn legacy_verify(cert: &OldQuorumCertificate, validators: &ValidatorSet) -> bool {
    if cert.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
        return false;
    }
    let msg = vote_sign_bytes(cert.height, cert.round, cert.kind, &cert.block_hash);
    let mut seen = HashSet::new();
    let mut candidates: Vec<(VerifyingKey, Signature, u64)> = Vec::new();
    for (voter, sig_bytes) in &cert.signatures {
        if !seen.insert(*voter) {
            continue;
        }
        let vp = validators.power_of(voter);
        if vp == 0 {
            continue;
        }
        let Ok(vk) = VerifyingKey::from_bytes(voter) else { continue };
        let Ok(sig) = Signature::from_slice(sig_bytes) else { continue };
        candidates.push((vk, sig, vp));
    }
    if candidates.is_empty() {
        return false;
    }
    {
        let msgs: Vec<&[u8]> = candidates.iter().map(|_| msg.as_slice()).collect();
        let sigs: Vec<Signature> = candidates.iter().map(|(_, s, _)| *s).collect();
        let keys: Vec<VerifyingKey> = candidates.iter().map(|(k, _, _)| *k).collect();
        if ed25519_dalek::verify_batch(&msgs, &sigs, &keys).is_ok() {
            let power: u64 = candidates.iter().map(|(_, _, p)| p).sum();
            return power >= validators.quorum_power();
        }
    }
    let mut power = 0u64;
    for (vk, sig, vp) in &candidates {
        if vk.verify_strict(&msg, sig).is_ok() {
            power += *vp;
        }
    }
    power >= validators.quorum_power()
}

fn old_layout(bytes: &[u8]) -> OldQuorumCertificate {
    bincode::deserialize(bytes).expect("old layout must decode the same bytes")
}

/// Two-validator fixture: Ed25519 keys (fixed seeds) plus matching BLS keys
/// registered in a `QcBlsConfig`.
struct Fixture {
    ed: Vec<SigningKey>,
    bls: Vec<BlsSecretKey>,
    vs: ValidatorSet,
    registry: BlsKeyRegistry,
}

impl Fixture {
    fn new(n: usize) -> Self {
        let ed: Vec<SigningKey> = (0..n)
            .map(|i| SigningKey::from_bytes(&[(i + 1) as u8 * 7; 32]))
            .collect();
        let bls: Vec<BlsSecretKey> = (0..n)
            .map(|i| BlsSecretKey::from_seed(&[(i + 1) as u8; 32]))
            .collect();
        let vs = ValidatorSet::from_list(
            ed.iter().map(|k| (k.verifying_key().to_bytes(), 1)).collect(),
        );
        let registry: BlsKeyRegistry = ed
            .iter()
            .zip(&bls)
            .map(|(k, b)| (k.verifying_key().to_bytes(), b.public_key()))
            .collect();
        Self { ed, bls, vs, registry }
    }

    fn enabled_config(&self) -> QcBlsConfig {
        QcBlsConfig {
            enabled: true,
            registry: self.registry.clone(),
            local_vote_seed: None,
        }
    }

    /// Build a certificate for `(height, round, kind, target)`. `ed_signers`
    /// chooses who contributes bare Ed25519 signatures; `agg_signers` (when
    /// present) chooses who contributes to the BLS aggregate — they are
    /// deliberately independent so tests can build certificates whose power
    /// lives in only one of the two halves.
    fn cert(
        &self,
        height: u64,
        round: u32,
        kind: VoteKind,
        target: Option<BlockHash>,
        ed_signers: std::ops::Range<usize>,
        agg_signers: Option<std::ops::Range<usize>>,
    ) -> QuorumCertificate {
        let msg = vote_sign_bytes(height, round, kind, &target);
        let mut signatures = Vec::new();
        for i in ed_signers {
            let v = Vote::sign(&self.ed[i], height, round, kind, target);
            signatures.push((self.ed[i].verifying_key().to_bytes(), v.ed25519_signature().to_vec()));
        }
        if let Some(range) = agg_signers {
            let sigs: Vec<_> = range.map(|i| (i, self.bls[i].sign(&msg))).collect();
            let aggregate = aggregate_signatures(&sigs, self.ed.len()).expect("aggregate");
            let payload = encode_qc_bls_envelope(&aggregate, height, round, kind, target);
            signatures.push((BLS_QC_MARKER_ID, payload));
        }
        QuorumCertificate { height, round, kind, block_hash: target, signatures }
    }
}

fn disabled() -> QcBlsGuard {
    set_qc_bls_for_tests(QcBlsConfig::default())
}

// ---------------------------------------------------------------------------
// Golden compatibility
// ---------------------------------------------------------------------------

#[test]
fn golden_old_certificate_decodes_and_verifies_under_new_code() {
    let _gate = disabled();
    let bytes = golden_bytes();
    let qc: QuorumCertificate =
        bincode::deserialize(&bytes).expect("pre-change certificate bytes must decode");
    assert_eq!(qc.height, 7);
    assert_eq!(qc.round, 1);
    assert_eq!(qc.kind, VoteKind::Precommit);
    assert_eq!(qc.block_hash, Some([0xAB; 32]));
    assert_eq!(qc.signatures.len(), 2);

    let k1 = SigningKey::from_bytes(&[11u8; 32]);
    let k2 = SigningKey::from_bytes(&[22u8; 32]);
    let vs = ValidatorSet::from_list(vec![
        (k1.verifying_key().to_bytes(), 1),
        (k2.verifying_key().to_bytes(), 1),
    ]);
    assert!(qc.verify(&vs), "old certificate must verify under the new code");

    // Byte-exact roundtrip: the layout is unchanged, so re-encoding is the
    // same bytes a pre-change binary wrote.
    assert_eq!(bincode::serialize(&qc).unwrap(), bytes, "roundtrip must be byte-identical");

    // The OLD field layout decodes the OLD bytes identically as well — the
    // mirror struct exists to prove the layouts are interchangeable.
    let old = old_layout(&bytes);
    assert_eq!(bincode::serialize(&old).unwrap(), bytes);
    assert!(legacy_verify(&old, &vs), "baseline verifier accepts its own bytes");
}

#[test]
fn new_augmented_certificate_decodes_under_old_layout_and_passes_legacy_verify() {
    let f = Fixture::new(2);
    let _on = set_qc_bls_for_tests(f.enabled_config());
    let bh = [0x22u8; 32];
    // A certificate with BOTH halves: bare Ed25519 quorum + aggregate envelope.
    let qc = f.cert(3, 0, VoteKind::Precommit, Some(bh), 0..2, Some(0..2));
    assert!(
        qc.signatures.iter().any(|(id, _)| *id == BLS_QC_MARKER_ID),
        "production certificate must carry the aggregate envelope"
    );

    let bytes = bincode::serialize(&qc).unwrap();
    // (a) old FIELD LAYOUT decodes the new bytes — structural compat.
    let old = old_layout(&bytes);
    // (b) old VERIFICATION accepts it via the Ed25519 quorum it still carries:
    // an old binary and a new binary accept the SAME certificate, so enabling
    // BLS on part of the network cannot fork it against the rest.
    assert!(
        legacy_verify(&old, &f.vs),
        "old code must keep accepting augmented certificates through the Ed25519 list"
    );
    // (c) and the new code accepts it too.
    assert!(qc.verify(&f.vs));
}

#[test]
fn bls_only_certificate_fails_closed_under_old_code_and_flag_off_new_code() {
    let f = Fixture::new(2);
    // Only ONE Ed25519 signature: below the quorum of 2, so the Ed25519 list
    // alone can never carry this certificate. Power comes only from BLS.
    let bh = [0x33u8; 32];
    let qc = {
        let _on = set_qc_bls_for_tests(f.enabled_config());
        f.cert(4, 0, VoteKind::Precommit, Some(bh), 0..1, Some(0..2))
    };

    // Old code: decodes (same layout), then FAILS CLOSED — it cannot see the
    // aggregate and the Ed25519 list is short.
    let old = old_layout(&bincode::serialize(&qc).unwrap());
    assert!(
        !legacy_verify(&old, &f.vs),
        "old code must reject a certificate whose only power is the BLS aggregate"
    );

    // New code with the flag OFF (the default on the stand): same verdict —
    // the aggregate is not counted, the Ed25519 list is short.
    {
        let _off = disabled();
        assert!(!qc.verify(&f.vs), "flag-off verification must fail closed on a BLS-only certificate");
    }

    // New code with the flag ON and the registry present: strict BLS
    // verification counts the quorum.
    {
        let _on = set_qc_bls_for_tests(f.enabled_config());
        assert!(qc.verify(&f.vs), "flag-on verification must accept the aggregate quorum");
    }
}

// ---------------------------------------------------------------------------
// Strict verification + fallback
// ---------------------------------------------------------------------------

#[test]
fn strict_bls_path_rejects_tampered_insufficient_and_mis_bound_aggregates() {
    let f = Fixture::new(3); // quorum power = 3
    let _on = set_qc_bls_for_tests(f.enabled_config());
    let bh = [0x44u8; 32];
    let msg = vote_sign_bytes(9, 2, VoteKind::Precommit, &Some(bh));

    // Control: full aggregate, NO Ed25519 list at all — must pass strictly.
    let good = {
        let sigs: Vec<_> = (0..3).map(|i| (i, f.bls[i].sign(&msg))).collect();
        aggregate_signatures(&sigs, 3).unwrap()
    };
    let mut qc = QuorumCertificate {
        height: 9,
        round: 2,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: vec![(
            BLS_QC_MARKER_ID,
            encode_qc_bls_envelope(&good, 9, 2, VoteKind::Precommit, Some(bh)),
        )],
    };
    assert!(qc.verify(&f.vs), "a full strict aggregate must verify");

    // Tampered aggregate: one member signed a DIFFERENT message, so the
    // aggregated point no longer satisfies the pairing identity. (This is the
    // tamper a relay can actually achieve — flipping raw point bytes usually
    // lands off-curve and never parses.)
    let bad_sigs: Vec<_> = std::iter::once((0, f.bls[0].sign(b"attacker-message")))
        .chain((1..3).map(|i| (i, f.bls[i].sign(&msg))))
        .collect();
    let tampered = aggregate_signatures(&bad_sigs, 3).unwrap();
    qc.signatures[0].1 =
        encode_qc_bls_envelope(&tampered, 9, 2, VoteKind::Precommit, Some(bh));
    assert!(!qc.verify(&f.vs), "a tampered aggregate must reject");

    // Insufficient: only 2 of 3 validators signed (power 2 < quorum 3).
    let sigs: Vec<_> = (0..2).map(|i| (i, f.bls[i].sign(&msg))).collect();
    let weak = aggregate_signatures(&sigs, 3).unwrap();
    qc.signatures[0].1 = encode_qc_bls_envelope(&weak, 9, 2, VoteKind::Precommit, Some(bh));
    assert!(!qc.verify(&f.vs), "an under-quorum aggregate must reject");

    // Mis-bound: the envelope was created for a DIFFERENT height. The
    // binding check rejects it before any pairing.
    qc.signatures[0].1 = encode_qc_bls_envelope(&good, 10, 2, VoteKind::Precommit, Some(bh));
    assert!(!qc.verify(&f.vs), "an envelope bound to another height must reject");

    // Wrong target block.
    qc.signatures[0].1 = encode_qc_bls_envelope(&good, 9, 2, VoteKind::Precommit, Some([0xEE; 32]));
    assert!(!qc.verify(&f.vs), "an envelope bound to another block must reject");

    // Garbage payload under the marker id: decode fails, falls through, and
    // with no Ed25519 list the certificate rejects.
    qc.signatures[0].1 = vec![0u8; 64];
    assert!(!qc.verify(&f.vs), "a garbage envelope must not verify");
}

#[test]
fn bls_path_ignores_a_garbage_ed25519_list() {
    // Proves the BLS path is what accepted the certificate, not the fallback:
    // the Ed25519 entries are present but garbage, so a fallback would reject.
    let f = Fixture::new(3);
    let _on = set_qc_bls_for_tests(f.enabled_config());
    let bh = [0x55u8; 32];
    let msg = vote_sign_bytes(11, 0, VoteKind::Precommit, &Some(bh));
    let sigs: Vec<_> = (0..3).map(|i| (i, f.bls[i].sign(&msg))).collect();
    let aggregate = aggregate_signatures(&sigs, 3).unwrap();
    let qc = QuorumCertificate {
        height: 11,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: vec![
            (f.ed[0].verifying_key().to_bytes(), vec![0xAB; 64]),
            (
                BLS_QC_MARKER_ID,
                encode_qc_bls_envelope(&aggregate, 11, 0, VoteKind::Precommit, Some(bh)),
            ),
        ],
    };
    assert!(qc.verify(&f.vs), "strict pairing counts; the garbage list never matters");
}

#[test]
fn any_bls_failure_falls_back_to_the_ed25519_list() {
    let f = Fixture::new(3);
    let bh = [0x66u8; 32];

    // Full aggregate + full Ed25519 quorum, flag ON, but the registry is
    // missing one member: the BLS path is unavailable and verification must
    // succeed through the Ed25519 list (liveness never depends on BLS).
    let qc = {
        let _on = set_qc_bls_for_tests(f.enabled_config());
        f.cert(12, 0, VoteKind::Precommit, Some(bh), 0..3, Some(0..3))
    };
    {
        let mut partial = f.enabled_config();
        partial.registry.remove(&f.ed[2].verifying_key().to_bytes());
        let _on = set_qc_bls_for_tests(partial);
        assert!(
            qc.verify(&f.vs),
            "an incomplete registry must fall back to the Ed25519 quorum, not reject"
        );
    }

    // Same certificate, flag OFF entirely: fallback again.
    {
        let _off = disabled();
        assert!(qc.verify(&f.vs), "flag-off verification accepts via the Ed25519 list");
    }

    // A certificate with ONLY an Ed25519 quorum (no aggregate at all — what a
    // non-BLS peer produces) is accepted with the flag ON: mixed producers
    // never fork.
    {
        let _on = set_qc_bls_for_tests(f.enabled_config());
        let plain = f.cert(12, 0, VoteKind::Precommit, Some(bh), 0..3, None);
        assert!(!plain.signatures.iter().any(|(id, _)| *id == BLS_QC_MARKER_ID));
        assert!(plain.verify(&f.vs), "flag-on verification accepts a plain Ed25519 certificate");
    }
}

#[test]
fn certificate_roundtrip_keeps_the_envelope_intact() {
    let f = Fixture::new(3);
    let _on = set_qc_bls_for_tests(f.enabled_config());
    let qc = f.cert(21, 1, VoteKind::Precommit, Some([0x77; 32]), 0..3, Some(0..3));
    let bytes = bincode::serialize(&qc).unwrap();
    let back: QuorumCertificate = bincode::deserialize(&bytes).unwrap();
    assert_eq!(back, qc, "certificate must survive a bincode roundtrip");
    assert!(back.verify(&f.vs));
    // And the old layout decodes the same bytes (structural compat again).
    assert_eq!(bincode::serialize(&old_layout(&bytes)).unwrap(), bytes);
}

#[test]
fn marker_id_counts_for_nothing_and_legacy_skips_it() {
    // The whole compat trick rests on the membership check: the marker id has
    // zero power in any validator set that does not deliberately contain it,
    // so both the old and the new verifier skip the entry before any parse.
    let f = Fixture::new(2);
    assert_eq!(
        f.vs.power_of(&BLS_QC_MARKER_ID),
        0,
        "the marker id must be a non-member of the validator set"
    );
    // Old code: a marker-only certificate decodes (same layout) but never
    // verifies — the entry contributes no Ed25519 power.
    let qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some([1u8; 32]),
        signatures: vec![(BLS_QC_MARKER_ID, vec![1u8, 2u8, 3u8])],
    };
    let bytes = bincode::serialize(&qc).unwrap();
    let old = old_layout(&bytes);
    assert!(!legacy_verify(&old, &f.vs), "old code must skip the marker entry");

    // New code: a non-envelope marker payload also counts for nothing.
    let _on = set_qc_bls_for_tests(f.enabled_config());
    assert!(!qc.verify(&f.vs), "a non-envelope marker entry counts for nothing");
}

// ---------------------------------------------------------------------------
// Vote envelope (the transport that lets certificates aggregate at all)
// ---------------------------------------------------------------------------

#[test]
fn vote_envelope_roundtrip_and_flag_off_bytes_unchanged() {
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let msg = vote_sign_bytes(5, 1, VoteKind::Prevote, &Some([1u8; 32]));

    // Flag OFF (default): byte-identical plain signature.
    {
        let _off = disabled();
        let v = Vote::sign(&sk, 5, 1, VoteKind::Prevote, Some([1u8; 32]));
        assert_eq!(v.signature.len(), 64, "flag-off votes stay plain");
        assert!(v.verify());
        assert!(v.bls_signature().is_none());
    }

    // Flag ON with a local seed: envelope with both halves.
    let seed = [0x42u8; 32];
    {
        let _on = set_qc_bls_for_tests(QcBlsConfig {
            enabled: true,
            registry: BTreeMap::new(),
            local_vote_seed: Some(seed),
        });
        let v = Vote::sign(&sk, 5, 1, VoteKind::Prevote, Some([1u8; 32]));
        assert_eq!(v.signature.len(), VOTE_BLS_PART_LEN, "flag-on votes carry the envelope");
        assert!(v.signature.starts_with(VOTE_BLS_MAGIC));
        assert_eq!(v.ed25519_signature().len(), 64, "the Ed25519 half is bare");
        let bls_half = v.bls_signature().expect("envelope carries a BLS half");
        assert!(v.verify(), "envelope votes must verify under the new code");
        // The BLS half really is a signature over the vote message by the
        // configured local seed's key.
        let cfg_key = BlsSecretKey::from_seed(&seed);
        assert!(cfg_key.public_key().verify(&msg, &BlsSignature::from_bytes(&bls_half).unwrap()));

        // OLD code: `Signature::from_slice` over the whole 176-byte field.
        // Fail closed — this is why the flag must be enabled network-wide.
        assert!(
            Signature::from_slice(&v.signature).is_err(),
            "pre-BLS vote verification must reject envelope bytes"
        );
        // Tamper the Ed25519 half: envelope votes must still fail closed.
        let mut forged = v.clone();
        forged.signature[20] ^= 0xFF;
        assert!(!forged.verify());
    }
}

#[test]
fn vote_set_certificate_attaches_and_verifies_end_to_end() {
    let f = Fixture::new(3);
    let bh = [0x88u8; 32];
    let h = 30u64;
    let msg = vote_sign_bytes(h, 0, VoteKind::Precommit, &Some(bh));

    let make_vote = |i: usize| -> Vote {
        let ed_sig = f.ed[i].sign(&msg).to_vec();
        let bls_sig = f.bls[i].sign(&msg).to_bytes();
        let mut signature = Vec::with_capacity(VOTE_BLS_PART_LEN);
        signature.extend_from_slice(VOTE_BLS_MAGIC);
        signature.extend_from_slice(&ed_sig);
        signature.extend_from_slice(&bls_sig);
        Vote {
            height: h,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            voter: f.ed[i].verifying_key().to_bytes(),
            signature,
        }
    };

    // Flag ON: the certificate produced from envelope votes carries the
    // aggregate, and strict verification passes.
    {
        let _on = set_qc_bls_for_tests(f.enabled_config());
        let mut set = VoteSet::new();
        for i in 0..3 {
            set.add(make_vote(i), &f.vs, h, 0, VoteKind::Precommit).expect("vote accepted");
        }
        let qc = set
            .certificate(Some(bh), &f.vs, &[0u8; 32])
            .expect("quorum reached");
        assert!(
            qc.signatures.iter().any(|(id, _)| *id == BLS_QC_MARKER_ID),
            "aggregation must attach the marker envelope"
        );
        assert!(
            qc.signatures
                .iter()
                .filter(|(id, payload)| *id != BLS_QC_MARKER_ID && payload.len() == 64)
                .count()
                == 3,
            "the Ed25519 list stays bare and complete"
        );
        assert!(qc.verify(&f.vs));
        // A BLS-only view of the same certificate (Ed25519 entries removed)
        // still verifies — the aggregate alone carries the quorum.
        let mut bls_only = qc.clone();
        bls_only.signatures.retain(|(id, _)| *id == BLS_QC_MARKER_ID);
        assert!(bls_only.verify(&f.vs));
    }

    // Flag OFF: the SAME votes produce a certificate with NO envelope —
    // production is gated, not merely verification.
    {
        let _off = disabled();
        let mut set = VoteSet::new();
        for i in 0..3 {
            set.add(make_vote(i), &f.vs, h, 0, VoteKind::Precommit).expect("vote accepted");
        }
        let qc = set
            .certificate(Some(bh), &f.vs, &[0u8; 32])
            .expect("quorum reached");
        assert!(
            !qc.signatures.iter().any(|(id, _)| *id == BLS_QC_MARKER_ID),
            "flag-off certificates must not carry the envelope"
        );
        assert!(qc.verify(&f.vs));
    }
}

// ---------------------------------------------------------------------------
// Mixed mode: two ValidatorRuntimes, opposite sides of the flag, one chain
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mixed_bls_and_ed25519_sides_do_not_fork() {
    use stellereum::runtime::ValidatorRuntime;
    use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
    use stellereum::state_engine::{AccountState, InMemoryStateEngine};

    let f = Fixture::new(2);
    let user = SigningKey::generate(&mut OsRng);
    let from = user.verifying_key().to_bytes();

    let s_bls = std::sync::Arc::new(InMemoryStateEngine::new());
    let s_ed = std::sync::Arc::new(InMemoryStateEngine::new());
    s_bls.update_account(AccountState::new(from, 10_000_000)).await;
    s_ed.update_account(AccountState::new(from, 10_000_000)).await;
    assert_eq!(s_bls.get_state_root().await, s_ed.get_state_root().await);

    // Two ValidatorRuntimes: one we will treat as the BLS-enabled side, one
    // as the Ed25519-only side. Config is process-global, so the sides take
    // turns holding the flag — what must hold is that BOTH accept the SAME
    // certificate bytes and converge on the same state.
    let mut v_bls = ValidatorRuntime::new(f.ed[0].clone(), f.vs.clone(), s_bls, 1);
    let mut v_ed = ValidatorRuntime::new(f.ed[1].clone(), f.vs.clone(), s_ed, 1);

    let root0 = v_bls.state_root().await;
    assert_eq!(root0, v_ed.state_root().await);

    // ---- height 1: certificate WITH the BLS aggregate ----
    let proposer1 = f.vs.proposer_for(1, 0).expect("proposer");
    let key1 = f
        .ed
        .iter()
        .find(|k| k.verifying_key().to_bytes() == proposer1)
        .expect("proposer key")
        .clone();
    let mut b1 = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: root0,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_000,
        proposer: proposer1,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
    
        order_merkle_root: [0u8; 32],
        };
    b1.sign_block(&key1);
    let bh1 = b1.compute_hash();
    let cert_bls = f.cert(1, 0, VoteKind::Precommit, Some(bh1), 0..2, Some(0..2));
    assert!(cert_bls.signatures.iter().any(|(id, _)| *id == BLS_QC_MARKER_ID));

    // BLS side (flag ON): adopts the augmented certificate.
    {
        let _on = set_qc_bls_for_tests(f.enabled_config());
        v_bls.adopt_committed(1, b1.clone(), cert_bls.clone())
            .await
            .expect("BLS side must accept a BLS-carrying certificate");
    }
    // Ed25519 side (flag OFF): adopts the byte-identical certificate through
    // the Ed25519 fallback.
    {
        let _off = disabled();
        v_ed.adopt_committed(1, b1.clone(), cert_bls.clone())
            .await
            .expect("Ed25519 side must accept the same certificate bytes");
    }
    assert_eq!(v_bls.height(), 2, "BLS side advanced");
    assert_eq!(v_ed.height(), 2, "Ed25519 side advanced to the same height");
    let root1_bls = v_bls.state_root().await;
    let root1_ed = v_ed.state_root().await;
    assert_eq!(root1_bls, root1_ed, "no fork after height 1");

    // ---- height 2: certificate WITHOUT the aggregate (plain Ed25519) ----
    let proposer2 = f.vs.proposer_for(2, 0).expect("proposer");
    let key2 = f
        .ed
        .iter()
        .find(|k| k.verifying_key().to_bytes() == proposer2)
        .expect("proposer key")
        .clone();
    let mut b2 = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 2,
        prev_hash: bh1,
        state_root: root1_bls,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 2_000,
        proposer: proposer2,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
    
        order_merkle_root: [0u8; 32],
        };
    b2.sign_block(&key2);
    let bh2 = b2.compute_hash();
    let cert_ed = f.cert(2, 0, VoteKind::Precommit, Some(bh2), 0..2, None);
    assert!(!cert_ed.signatures.iter().any(|(id, _)| *id == BLS_QC_MARKER_ID));

    // BLS side (flag ON) accepts a plain Ed25519 certificate — it never
    // REQUIRES the aggregate.
    {
        let _on = set_qc_bls_for_tests(f.enabled_config());
        v_bls.adopt_committed(2, b2.clone(), cert_ed.clone())
            .await
            .expect("BLS side must accept a plain Ed25519 certificate");
    }
    // Ed25519 side (flag OFF) accepts it the way it always did.
    {
        let _off = disabled();
        v_ed.adopt_committed(2, b2.clone(), cert_ed.clone())
            .await
            .expect("Ed25519 side must accept a plain Ed25519 certificate");
    }
    assert_eq!(v_bls.height(), 3);
    assert_eq!(v_ed.height(), 3);
    assert_eq!(
        v_bls.state_root().await,
        v_ed.state_root().await,
        "opposite sides of the flag converge — no fork in either direction"
    );
}
