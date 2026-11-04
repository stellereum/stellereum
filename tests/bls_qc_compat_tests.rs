//! BLS quorum certificates on the real path (passport §6B) — RETIRED counting.
//!
//! The aggregate-QC counting path is removed: BLS envelopes that remain on
//! the wire decode as inert metadata and are never counted. What this suite
//! still proves, with golden bytes captured from the PRE-change baseline:
//! * old certificate bytes decode AND verify under the new code (compat);
//! * new certificate bytes decode under the old field layout, and old
//!   verification FAILS CLOSED on a marker-only certificate (while still
//!   accepting an augmented certificate that carries the Ed25519 quorum —
//!   so mixed old/new nodes do not fork);
//! * the envelope survives a bincode roundtrip bit-for-bit and the marker id
//!   counts for nothing under both verifiers;
//! * two ValidatorRuntimes fed the same (marker-carrying and plain)
//!   certificate bytes converge on the same chain (no fork in either
//!   direction).
//!
//! Envelopes below are hand-built (single real BLS signature + bitvector):
//! no aggregation exists to mint them, and these tests pin only the wire
//! layer — never counting.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use stellereum::bls::*;
use stellereum::consensus::*;

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
        let Ok(vk) = VerifyingKey::from_bytes(voter) else {
            continue;
        };
        let Ok(sig) = Signature::from_slice(sig_bytes) else {
            continue;
        };
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

/// Hand-build a v1 BLS marker-envelope payload inline (history READ bytes).
///
/// GATE (HDAE wire-EMIT cut): `encode_qc_bls_envelope` is retired (returns
/// empty — no live writer), so READ fixtures no longer call it. The layout
/// below is the frozen v1 history format
/// (`QC_BLS_MAGIC || height || round || kind || block_hash || total || sig || bits`);
/// `decode_qc_bls_envelope` (the kept v1 reader) must keep parsing it.
fn hand_built_bls_envelope(
    height: u64,
    round: u32,
    kind: VoteKind,
    target: Option<BlockHash>,
    total_validators: usize,
    sig: &[u8; 96],
    bits: &[u8],
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(16 + 8 + 4 + 1 + 32 + 4 + 96 + bits.len());
    out.extend_from_slice(QC_BLS_MAGIC);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&round.to_le_bytes());
    out.push(match kind {
        VoteKind::Prevote => 0,
        VoteKind::Precommit => 1,
    });
    match target {
        Some(h) => out.extend_from_slice(&h),
        None => out.extend_from_slice(&[0u8; 32]),
    }
    out.extend_from_slice(&(total_validators as u32).to_le_bytes());
    out.extend_from_slice(sig);
    out.extend_from_slice(bits);
    out
}
struct Fixture {
    ed: Vec<SigningKey>,
    bls: Vec<BlsSecretKey>,
    vs: ValidatorSet,
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
            ed.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        Self { ed, bls, vs }
    }

    /// Build a certificate for `(height, round, kind, target)`. `ed_signers`
    /// chooses who contributes bare Ed25519 signatures; `agg_signers` (when
    /// present) chooses the bitvector of a hand-built HISTORY envelope carrying
    /// one real BLS signature (the first member signs): decode accepts it, and
    /// the new code verifies the certificate through its Ed25519 quorum —
    /// the envelope itself is inert metadata, never counted, never emitted.
    /// GATE (HDAE wire-EMIT cut): the envelope is hand-built READ bytes (see
    /// `hand_built_bls_envelope`); the retired `encode_qc_bls_envelope` (empty)
    /// is NOT used.
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
            signatures.push((
                self.ed[i].verifying_key().to_bytes(),
                v.ed25519_signature().to_vec(),
            ));
        }
        if let Some(range) = agg_signers {
            let mut participants = SignerBitVector::new(self.ed.len());
            for i in range.clone() {
                participants.set(i, true);
            }
            let aggregate = BlsAggregateSignature {
                signature: self.bls[range.start].sign(&msg),
                participants,
            };
            let (sig, bits) = aggregate.to_bytes();
            let payload = hand_built_bls_envelope(
                height,
                round,
                kind,
                target,
                self.ed.len(),
                &sig,
                bits,
            );
            signatures.push((BLS_QC_MARKER_ID, payload));
        }
        QuorumCertificate {
            height,
            round,
            kind,
            block_hash: target,
            signatures,
        }
    }
}

// REMOVED (counting-path config): `Fixture::enabled_config` and the `disabled()`
// test guard wrapped `set_qc_bls_for_tests` — deleted with the counting path.
// There is no flag anymore: every certificate verifies through the Ed25519 list.


// ---------------------------------------------------------------------------
// Golden compatibility
// ---------------------------------------------------------------------------

#[test]
fn golden_old_certificate_decodes_and_verifies_under_new_code() {
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
    assert!(
        qc.verify(&vs),
        "old certificate must verify under the new code"
    );

    // Byte-exact roundtrip: the layout is unchanged, so re-encoding is the
    // same bytes a pre-change binary wrote.
    assert_eq!(
        bincode::serialize(&qc).unwrap(),
        bytes,
        "roundtrip must be byte-identical"
    );

    // The OLD field layout decodes the OLD bytes identically as well — the
    // mirror struct exists to prove the layouts are interchangeable.
    let old = old_layout(&bytes);
    assert_eq!(bincode::serialize(&old).unwrap(), bytes);
    assert!(
        legacy_verify(&old, &vs),
        "baseline verifier accepts its own bytes"
    );
}

#[test]
fn new_augmented_certificate_decodes_under_old_layout_and_passes_legacy_verify() {
    let f = Fixture::new(2);
    let bh = [0x22u8; 32];
    // A certificate with BOTH halves: bare Ed25519 quorum + aggregate envelope.
    // GATE (HDAE wire-EMIT cut): the envelope here is hand-built HISTORY bytes
    // (no live path emits it anymore); the pin is that history bytes still
    // decode under the old layout and both verifiers accept via the Ed25519
    // quorum, so mixed old/new nodes never fork on them.
    let qc = f.cert(3, 0, VoteKind::Precommit, Some(bh), 0..2, Some(0..2));
    assert!(
        qc.signatures.iter().any(|(id, _)| *id == BLS_QC_MARKER_ID),
        "history certificate must carry the aggregate envelope"
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
fn bls_only_certificate_fails_closed_under_old_code_and_new_code() {
    // REMOVED: the flag-ON strict-accept block lived here — counting is gone,
    // so a marker-only certificate (short Ed25519 list) rejects everywhere.
    let f = Fixture::new(2);
    // Only ONE Ed25519 signature: below the quorum of 2, so the Ed25519 list
    // alone can never carry this certificate. The envelope is inert metadata.
    let bh = [0x33u8; 32];
    let qc = f.cert(4, 0, VoteKind::Precommit, Some(bh), 0..1, Some(0..2));

    // Old code: decodes (same layout), then FAILS CLOSED — it cannot see the
    // envelope and the Ed25519 list is short.
    let old = old_layout(&bincode::serialize(&qc).unwrap());
    assert!(
        !legacy_verify(&old, &f.vs),
        "old code must reject a certificate whose only power is the BLS aggregate"
    );

    // New code: same verdict — the envelope is never counted and the Ed25519
    // list is short.
    assert!(
        !qc.verify(&f.vs),
        "new code must fail closed on a marker-only certificate"
    );
}

// ---------------------------------------------------------------------------
// Wire-EMIT retirement pins (HDAE cut): EMIT is gone, READERS stay
// ---------------------------------------------------------------------------

#[test]
fn retired_bls_envelope_encode_emits_empty() {
    // GATE: `encode_qc_bls_envelope` must emit absent/empty — no live writer
    // may produce BLS marker payloads (CLOSED TESTNET: no wire compat needed).
    // The PARSE side (`decode_qc_bls_envelope`) is untouched (history compat).
    let sk = BlsSecretKey::from_seed(&[0x11u8; 32]);
    let mut participants = SignerBitVector::new(2);
    participants.set(0, true);
    let msg = vote_sign_bytes(9, 0, VoteKind::Precommit, &Some([0xAA; 32]));
    let agg = BlsAggregateSignature {
        signature: sk.sign(&msg),
        participants,
    };
    assert!(
        encode_qc_bls_envelope(&agg, 9, 0, VoteKind::Precommit, Some([0xAA; 32])).is_empty(),
        "retired BLS envelope EMIT must be empty"
    );
}

#[test]
fn fixed_v1_history_envelope_bytes_still_parse() {
    // GATE: fixed fixture of v1 envelope bytes (captured from the pre-cut
    // encoder: height 9, round 0, precommit for 0xAA*32, 2 validators both
    // signed, single real BLS signature). Asserts the kept v1 READER parses
    // old-history bytes OK — the storage-compat pin that survives the EMIT cut.
    const V1_ENVELOPE_HEX: &str = "5354454c4c5f51435f424c535f56315f09000000000000000000000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02000000b71b1068608a6250189b14e329b9fd76327e3ecfd43135418707de370afc781bcece9329dc84076c5cd30dbd8bad3afe03c8ff36efc80dc0208faba0aa9f7ad3dfe50d8253b67961de129d506537ffb1768e0e5293d9174848dd846583ffca6c03";
    let payload = hex::decode(V1_ENVELOPE_HEX).expect("fixed v1 fixture hex");
    let (height, round, kind, block_hash, agg) =
        decode_qc_bls_envelope(&payload).expect("v1 history envelope must parse");
    assert_eq!(height, 9);
    assert_eq!(round, 0);
    assert_eq!(kind, VoteKind::Precommit);
    assert_eq!(block_hash, [0xAA; 32]);
    assert_eq!(agg.participants.total_validators(), 2);
    assert_eq!(agg.participants.signed_count(), 2);
    // And the marker id still counts for nothing under a live verifier set.
    let f = Fixture::new(2);
    assert_eq!(f.vs.power_of(&BLS_QC_MARKER_ID), 0);
}

// ---------------------------------------------------------------------------
// Envelope roundtrip + marker inertness
// ---------------------------------------------------------------------------




#[test]
fn certificate_roundtrip_keeps_the_envelope_intact() {
    let f = Fixture::new(3);
    let qc = f.cert(
        21,
        1,
        VoteKind::Precommit,
        Some([0x77; 32]),
        0..3,
        Some(0..3),
    );
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
    assert!(
        !legacy_verify(&old, &f.vs),
        "old code must skip the marker entry"
    );

    // New code: a non-envelope marker payload also counts for nothing.
    assert!(
        !qc.verify(&f.vs),
        "a non-envelope marker entry counts for nothing"
    );
}

// ---------------------------------------------------------------------------
// REMOVED (vote envelope production): `vote_envelope_roundtrip_and_flag_off_bytes_unchanged`
// and `vote_set_certificate_attaches_and_verifies_end_to_end` tested removed
// vote-BLS production (`attach_vote_bls`) and counting — deleted with that code.



// ---------------------------------------------------------------------------
// Mixed envelopes: two ValidatorRuntimes fed marker-carrying and plain bytes
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
    s_bls
        .update_account(AccountState::new(from, 10_000_000))
        .await;
    s_ed.update_account(AccountState::new(from, 10_000_000))
        .await;
    assert_eq!(s_bls.get_state_root().await, s_ed.get_state_root().await);

    // Two ValidatorRuntimes fed the SAME bytes. (No flag exists anymore:
    // the "BLS side" / "Ed25519 side" split below is now two identical
    // verifiers — the pin is that marker-carrying bytes and plain bytes both
    // adopt and converge, i.e. envelopes on the wire fork nothing.)
    let mut v_bls = ValidatorRuntime::new(f.ed[0].clone(), f.vs.clone(), s_bls, 1);
    let mut v_ed = ValidatorRuntime::new(f.ed[1].clone(), f.vs.clone(), s_ed, 1);

    let root0 = v_bls.state_root().await;
    assert_eq!(root0, v_ed.state_root().await);

    // ---- height 1: certificate WITH the BLS aggregate ----
    let proposer1 = f.vs.proposer_for(1, 0).expect("proposer");
    let key1 =
        f.ed.iter()
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
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b1.sign_block(&key1);
    let bh1 = b1.compute_hash();
    let cert_bls = f.cert(1, 0, VoteKind::Precommit, Some(bh1), 0..2, Some(0..2));
    assert!(cert_bls
        .signatures
        .iter()
        .any(|(id, _)| *id == BLS_QC_MARKER_ID));

    // Both sides adopt the marker-carrying certificate through the Ed25519
    // quorum it carries (the envelope is inert metadata).
    {
        v_bls
            .adopt_committed(1, b1.clone(), cert_bls.clone())
            .await
            .expect("first runtime must accept a marker-carrying certificate");
    }
    {
        v_ed.adopt_committed(1, b1.clone(), cert_bls.clone())
            .await
            .expect("second runtime must accept the same certificate bytes");
    }
    assert_eq!(v_bls.height(), 2, "first runtime advanced");
    assert_eq!(v_ed.height(), 2, "second runtime advanced to the same height");
    let root1_bls = v_bls.state_root().await;
    let root1_ed = v_ed.state_root().await;
    assert_eq!(root1_bls, root1_ed, "no fork after height 1");

    // ---- height 2: certificate WITHOUT the envelope (plain Ed25519) ----
    let proposer2 = f.vs.proposer_for(2, 0).expect("proposer");
    let key2 =
        f.ed.iter()
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
        // POLICY (W10.5 canonical downtime evidence): a height-2 block must
        // carry the QC that decided height 1; receivers that know the parent
        // decision refuse an omission. The height-1 BLS-carrying certificate
        // is exactly that evidence.
        last_qc: Some(cert_bls.clone()),
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b2.sign_block(&key2);
    let bh2 = b2.compute_hash();
    let cert_ed = f.cert(2, 0, VoteKind::Precommit, Some(bh2), 0..2, None);
    assert!(!cert_ed
        .signatures
        .iter()
        .any(|(id, _)| *id == BLS_QC_MARKER_ID));

    // Both sides accept the plain Ed25519 certificate the way they always did.
    {
        v_bls
            .adopt_committed(2, b2.clone(), cert_ed.clone())
            .await
            .expect("first runtime must accept a plain Ed25519 certificate");
    }
    {
        v_ed.adopt_committed(2, b2.clone(), cert_ed.clone())
            .await
            .expect("second runtime must accept a plain Ed25519 certificate");
    }
    assert_eq!(v_bls.height(), 3);
    assert_eq!(v_ed.height(), 3);
    assert_eq!(
        v_bls.state_root().await,
        v_ed.state_root().await,
        "both runtimes converge — no fork in either direction"
    );
}
