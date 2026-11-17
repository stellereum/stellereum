//! C1 split producer: the full-network decision certificate (`QC_SPLIT`).
//!
//! ## Why this module exists
//!
//! At/after [`qc_split_active_at`] the µQC is ADVISORY-ONLY: the verifier's
//! µQC branch fails closed, and finality requires a FULL-network QC — the
//! epoch/CEC envelope under [`PQ_QC_MARKER_ID`], whose signer set is the
//! WHOLE validator set (canonically ordered) and whose quorum is
//! [`crate::consensus::pq_full_required_power`] over the NETWORK's total
//! power.
//!
//! The verifier side already existed; without a PRODUCER, activating the gate
//! made every locally decided block carry a certificate its own peers refuse,
//! i.e. it halted finality. This module is that producer.
//!
//! ## Shape of what it builds
//!
//! `QuorumCertificate { height, round, kind, block_hash, signatures: [
//!   (PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&cec))
//! ] }`
//!
//! The CEC envelope holds:
//!  * `committee_size == validators.len()` (the FULL set, not the sortition
//!    subset the µQC uses);
//!  * a bitmask over the canonical SORTED validator ids;
//!  * COMPACT signatures in that same order (one per marked signer);
//!  * `sortition_parent = [0; 32]` — unused by the epoch path (no committee
//!    election, so there is no parent-hash entropy to commit to).
//!
//! Only the marker entry is emitted. The legacy path also emits inert
//! per-voter Ed25519 entries; those carry no power under FULL-PQ and would
//! count against [`MAX_COMMIT_CERT_SIGNERS`], so the decision certificate
//! stays one entry.
//!
//! ## Determinism
//!
//! Signers are emitted in canonical (sorted) validator-id order, independent
//! of the order votes arrived in, so two nodes that saw the same votes in
//! different arrival orders produce BYTE-IDENTICAL certificates. Nothing
//! iterates a `HashMap` in wire order.
//!
//! ## DoS bound
//!
//! [`MAX_COMMIT_CERT_SIGNERS`] is checked against both the validator set and
//! the supplied signer list BEFORE the first signature is verified; an
//! oversized aggregate is refused in O(1) (see
//! [`produce_full_network_certificate_from_signers`]).
//!
//! ## Gate
//!
//! [`QC_SPLIT_ACTIVATION_HEIGHT`] remains `u64::MAX` (frozen off). The
//! active branch is exercised through the thread-scoped test override
//! [`set_qc_split_activation_override`], exactly like the other gates.

use std::collections::HashMap;

use super::engine::VoteSet;
use super::rotation::pq_key_at_height;
use super::sortition::qc_split_active_at;
use super::types::{
    encode_pq_epoch_envelope, verify_falcon_signature, vote_sign_bytes, BlockHash, Height,
    PqMicroCertificate, QuorumCertificate, Round, ValidatorId, ValidatorSet, VoteKind,
    MAX_COMMIT_CERT_SIGNERS, PQ_QC_MARKER_ID,
};
use crate::post_quantum::PqScheme;

/// Optional explicit PQ key map (scheme + public key per validator id).
///
/// `None` resolves keys through the height-indexed committed registry
/// ([`pq_key_at_height`]) — the production source. `Some(map)` is the same
/// override the verifier accepts via
/// [`QuorumCertificate::verify_unified_with_pq_keys`], used by tests and by
/// rotated-key fixtures.
pub type PqKeyMap = HashMap<ValidatorId, (PqScheme, Vec<u8>)>;

/// The decision certificate for a decided height/round/target.
///
/// * Split INACTIVE at the votes' height: byte-identical legacy behavior —
///   [`VoteSet::certificate_with_parent`] (µQC when the votes carry Falcon
///   halves and the parent is known).
/// * Split ACTIVE: the full-network epoch/CEC certificate produced by
///   [`produce_full_network_certificate`]. A µQC is never emitted there
///   (the verifier would refuse it anyway, fail-closed).
///
/// `parent_hash` is only consulted on the legacy branch: the CEC path does
/// not elect a sortition committee, so it needs no parent entropy.
///
/// Returns `None` for an empty/under-quorum aggregate, an oversized set,
/// or when no full-network certificate can be compiled from the votes (e.g.
/// signers without registered Falcon keys). The caller keeps its existing
/// "no decision QC" handling in that case.
pub fn produce_decision_certificate(
    votes: &VoteSet,
    target: Option<BlockHash>,
    validators: &ValidatorSet,
    parent_hash: Option<&[u8; 32]>,
) -> Option<QuorumCertificate> {
    produce_decision_certificate_with_pq_keys(votes, target, validators, parent_hash, None)
}

/// [`produce_decision_certificate`] with explicit PQ key overrides.
pub fn produce_decision_certificate_with_pq_keys(
    votes: &VoteSet,
    target: Option<BlockHash>,
    validators: &ValidatorSet,
    parent_hash: Option<&[u8; 32]>,
    pq_keys: Option<&PqKeyMap>,
) -> Option<QuorumCertificate> {
    let (height, _, _) = votes.scope()?;
    if qc_split_active_at(height) {
        produce_full_network_certificate_with_pq_keys(votes, target, validators, pq_keys)
    } else {
        votes.certificate_with_parent(target, validators, parent_hash)
    }
}

/// Aggregate a [`VoteSet`] into a full-network epoch/CEC certificate.
///
/// The result carries EVERY validator that voted for `target` and has a
/// verifiable Falcon-512 signature — the full signer set, not the µQC
/// committee subset. Signers whose key is unavailable, whose registered
/// scheme is not Falcon-512, or whose signature does not verify are simply
/// not marked (a certificate never attributes an unverified signer); the
/// produced certificate still has to clear
/// [`crate::consensus::pq_full_required_power`] over the network, otherwise
/// `None` is returned.
pub fn produce_full_network_certificate(
    votes: &VoteSet,
    target: Option<BlockHash>,
    validators: &ValidatorSet,
) -> Option<QuorumCertificate> {
    produce_full_network_certificate_with_pq_keys(votes, target, validators, None)
}

/// [`produce_full_network_certificate`] with explicit PQ key overrides.
pub fn produce_full_network_certificate_with_pq_keys(
    votes: &VoteSet,
    target: Option<BlockHash>,
    validators: &ValidatorSet,
    pq_keys: Option<&PqKeyMap>,
) -> Option<QuorumCertificate> {
    // Quorum over the NETWORK comes first: an under-quorum aggregate can
    // never produce a full-network QC, whatever its shape.
    if !votes.quorum_reached(target, validators) {
        return None;
    }
    let (height, round, kind) = votes.scope()?;
    let raw = votes.falcon_signatures_for_target(target);

    // Map each vote's voter id onto a validator id. In the live path they
    // are identical; the address fallback mirrors the legacy producer for
    // deployments whose validator ids are PQ addresses.
    let mut signers: Vec<(ValidatorId, Vec<u8>)> = Vec::with_capacity(raw.len());
    for (voter, sig) in raw {
        if validators.contains(&voter) {
            signers.push((voter, sig));
            continue;
        }
        if let Some((scheme, pk)) = resolve_key(&voter, height, pq_keys) {
            let addr = crate::post_quantum::derive_pq_address(
                scheme,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            );
            if validators.contains(&addr) {
                signers.push((addr, sig));
            }
        }
    }

    produce_full_network_certificate_from_signers(
        height, round, kind, target, validators, &signers, pq_keys,
    )
}

/// Build a full-network epoch/CEC certificate from a canonical signer list.
///
/// This is the `VoteSet`-like entry point: any aggregate that can hand over
/// `(validator id, Falcon-512 signature)` pairs can use it. The input is
/// canonicalized internally (members are visited in sorted validator-id
/// order), so callers need not order it.
///
/// FAIL-CLOSED SHAPE RULES (all before, or independent of, crypto):
///  * an empty validator set, or more validators than
///    [`MAX_COMMIT_CERT_SIGNERS`], is refused;
///  * a signer list longer than [`MAX_COMMIT_CERT_SIGNERS`] is refused
///    BEFORE any signature verification (O(1) DoS gate);
///  * a duplicate signer id is refused (ambiguous aggregate — a `VoteSet`
///    admits at most one vote per voter, so this is a malformed input);
///  * signers outside the validator set are ignored (they lend no power);
///  * each marked signer must have a resolvable Falcon-512 key and a valid
///    signature over the certificate preimage;
///  * the marked signers' summed power must reach
///    [`crate::consensus::pq_full_required_power`] over the network, else
///    `None`.
pub fn produce_full_network_certificate_from_signers(
    height: Height,
    round: Round,
    kind: VoteKind,
    block_hash: Option<BlockHash>,
    validators: &ValidatorSet,
    signers: &[(ValidatorId, Vec<u8>)],
    pq_keys: Option<&PqKeyMap>,
) -> Option<QuorumCertificate> {
    // ANTI-DoS (audit F7 symmetry): the signer list is the only
    // attacker-sized input here. Cap it BEFORE any signature work, and cap
    // the validator set the same way (the CEC bitmask is a full-set bitmask,
    // so an oversized set can never be represented within the wire bound).
    if signers.len() > MAX_COMMIT_CERT_SIGNERS {
        return None;
    }
    let total_validators = validators.len();
    if total_validators == 0 || total_validators > MAX_COMMIT_CERT_SIGNERS {
        return None;
    }
    let committee_size = u32::try_from(total_validators).ok()?;

    // Canonical full-set order: exactly what `epoch_cert_valid_signers`
    // re-derives on the verify side (sorted validator ids).
    let mut ids: Vec<ValidatorId> = validators.validators.keys().copied().collect();
    ids.sort_unstable();

    // Deterministic aggregation: fail closed on a duplicate voter instead of
    // letting an unordered input decide which signature wins.
    let mut by_signer: HashMap<ValidatorId, &[u8]> = HashMap::with_capacity(signers.len());
    for (voter, sig) in signers {
        if !validators.contains(voter) {
            continue;
        }
        if by_signer.insert(*voter, sig.as_slice()).is_some() {
            return None;
        }
    }

    let msg = vote_sign_bytes(height, round, kind, &block_hash);
    let mut bitmask = vec![0u8; ids.len().div_ceil(8)];
    let mut compact_sigs: Vec<Vec<u8>> = Vec::with_capacity(by_signer.len());
    // u128 exactly like the verifier's `verify_epoch_cert` accounting, so an
    // absurd stake total above `u64::MAX` cannot make the producer accept a
    // certificate the verifier then refuses (saturation asymmetry).
    let mut signed_power: u128 = 0;

    for (index, id) in ids.iter().enumerate() {
        let Some(sig) = by_signer.get(id) else {
            continue;
        };
        let Some((scheme, pubkey)) = resolve_key(id, height, pq_keys) else {
            continue;
        };
        // Vote halves are Falcon-512 by construction (`Vote::falcon_signature`)
        // and the verifier requires every marked member's scheme to equal the
        // certificate's, so a member with another scheme must not be marked.
        if scheme != PqScheme::Falcon512 {
            continue;
        }
        if !verify_falcon_signature(&pubkey, &msg, sig) {
            continue;
        }
        bitmask[index / 8] |= 1 << (index % 8);
        compact_sigs.push(sig.to_vec());
        signed_power += validators.power_of(id) as u128;
    }

    // Finality gate: the FULL network's two-thirds, never the committee's.
    // Same curve as `pq_full_required_power` (`floor(2*W/3)+1`), evaluated in
    // u128 exactly like `verify_epoch_cert`.
    let total_power: u128 = validators.validators.values().map(|&p| p as u128).sum();
    let required_power: u128 = (total_power * 2) / 3 + 1;
    if signed_power < required_power {
        return None;
    }

    let cert = PqMicroCertificate::new(
        PqScheme::Falcon512,
        height,
        round,
        committee_size,
        bitmask,
        compact_sigs,
        // The epoch/CEC path elects no committee from a parent hash; the
        // field is wire-compat only and is pinned to zero for determinism.
        [0u8; 32],
    );

    let mut qc = QuorumCertificate {
        height,
        round,
        kind,
        block_hash,
        signatures: Vec::with_capacity(1),
    };
    qc.signatures
        .push((PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&cert)));
    Some(qc)
}

/// Resolve the PQ key a validator signs with at `height` (override first,
/// then the committed height-indexed registry).
fn resolve_key(
    id: &ValidatorId,
    height: Height,
    pq_keys: Option<&PqKeyMap>,
) -> Option<(PqScheme, Vec<u8>)> {
    pq_keys
        .and_then(|m| m.get(id).cloned())
        .or_else(|| pq_key_at_height(id, height))
}
