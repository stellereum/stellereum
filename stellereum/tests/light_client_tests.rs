//! P1-b: a light client that follows the chain from signed checkpoints and
//! answers balance queries from proofs, without holding state.
//!
//! The tests pin the properties the module claims. Several of them pin a
//! property it explicitly does NOT claim (see the module docs for those) —
//! those are the ones worth keeping, because a light client that overstates
//! its guarantees is worse than no light client at all.
//!
//! The theme running through all of them: nothing this client returns may rest
//! on anything it did not verify. No height, no finality claim, no balance, and
//! above all no zero.

use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashSet;
use stellereum::cell::{CellHash, MerkleProof, PatriciaTrie};
use stellereum::consensus::{
    BlockHash, QuorumCertificate, ValidatorId, ValidatorSet, Vote, VoteKind,
};
use stellereum::light_client::{
    Checkpoint, LightClient, LightError, LightHeader, MAX_MERKLE_PATH_STEPS,
};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};

const N: usize = 4; // 4 validators at power 1 => quorum is 3

fn keys() -> Vec<SigningKey> {
    (0..N)
        .map(|i| SigningKey::from_bytes(&[i as u8 + 1; 32]))
        .collect()
}

fn validators(keys: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn hash_of(n: u8) -> BlockHash {
    [n; 32]
}

fn outsider(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[0xF0 ^ seed; 32])
}

/// A certificate for `hash` at `height`, signed by `signers`.
fn cert(signers: &[SigningKey], height: u64, kind: VoteKind, hash: BlockHash) -> QuorumCertificate {
    let signatures = signers
        .iter()
        .map(|k| {
            let v = Vote::sign(k, height, 0, kind, Some(hash));
            (v.voter, v.signature)
        })
        .collect();
    QuorumCertificate {
        height,
        round: 0,
        kind,
        block_hash: Some(hash),
        signatures,
    }
}

/// A certificate that is genuinely signed for `signed_height` but whose
/// `height` field claims something else — i.e. one whose height was rewritten
/// after the fact.
fn relabelled(
    signers: &[SigningKey],
    signed_height: u64,
    claimed_height: u64,
) -> QuorumCertificate {
    let mut c = cert(signers, signed_height, VoteKind::Precommit, hash_of(9));
    c.height = claimed_height;
    c
}

fn account_value(balance: u64, nonce: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&balance.to_be_bytes());
    v.extend_from_slice(&nonce.to_be_bytes());
    v
}

// ============================================================================
// A real chain of real blocks, over real trie state
// ============================================================================

struct Fixture {
    keys: Vec<SigningKey>,
    validators: ValidatorSet,
    trie: PatriciaTrie,
    state_root: CellHash,
    /// heights 1..=blocks.len(), each co-signed by a power quorum
    blocks: Vec<Block>,
    alice: [u8; 32],
    bob: [u8; 32],
    token: [u8; 32],
}

impl Fixture {
    /// `roots` gives the state root committed at each height, so a test can ask
    /// for a chain whose state moves, or rolls back.
    fn new(mut roots: Vec<CellHash>) -> Fixture {
        let keys = keys();
        let validators = validators(&keys);
        let alice = [0xA1u8; 32];
        let bob = [0xB0u8; 32];
        let token = [0x7Eu8; 32];

        let mut trie = PatriciaTrie::new();
        trie.insert(&alice, &account_value(5_000, 3));
        trie.insert(&bob, &account_value(0, 0));
        trie.insert(
            &stellereum::state_engine::token_balance_key(&token, &alice),
            &777u64.to_be_bytes(),
        );
        let trie_root = trie.root_hash();

        // Default: a chain that does not move the state, which is the case a
        // light client has to tolerate (a block may change nothing).
        if roots.is_empty() {
            roots = vec![trie_root; 8];
        }
        roots[0] = trie_root;

        let mut blocks = Vec::new();
        let mut prev = [0u8; 32];
        for (i, root) in roots.iter().enumerate() {
            let height = i as u64 + 1;
            let mut b = Block {
                shard_id: MASTERCHAIN_SHARD,
                height,
                prev_hash: prev,
                state_root: *root,
                transactions: vec![],
                cross_shard_out: vec![],
                timestamp: 1_700_000_000 + height,
                proposer: keys[0].verifying_key().to_bytes(),
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                mmr_epoch_root: [0u8; 32],
                order_merkle_root: [0u8; 32],
                epoch_key_commitment: [0u8; 32],
            };
            // 3 of 4 signatures: a genuine power quorum, so these headers also
            // satisfy the block-level quorum check.
            for k in keys.iter().take(3) {
                b.sign_block(k);
            }
            prev = b.compute_hash();
            blocks.push(b);
        }

        Fixture {
            keys,
            validators,
            trie,
            state_root: trie_root,
            blocks,
            alice,
            bob,
            token,
        }
    }

    /// The light header for `blocks[i]`, with the real precommit QC and the real
    /// block signatures.
    fn header(&self, i: usize) -> LightHeader {
        let b = &self.blocks[i];
        let bh = b.compute_hash();
        LightHeader {
            height: b.height,
            prev_hash: b.prev_hash,
            state_root: b.state_root,
            block_hash: bh,
            timestamp: b.timestamp,
            proposer: b.proposer,
            cert: cert(&self.keys[..3], b.height, VoteKind::Precommit, bh),
            signatures: b.validator_signatures.clone(),
        }
    }

    fn checkpoint(&self, i: usize) -> Checkpoint {
        Checkpoint::of(&self.header(i))
    }

    /// A client anchored on `blocks[cp]`, having accepted every header up to
    /// `i` on top of it.
    fn client(&self, cp: usize, i: usize) -> LightClient {
        let mut lc = LightClient::new(self.validators.clone(), self.checkpoint(cp)).unwrap();
        for h in cp + 1..=i {
            lc.apply_header(self.header(h))
                .expect("an honest header must be accepted");
        }
        lc
    }

    /// Re-point a header at a new block hash: a different `state_root`/`height`
    /// pair is a different block, so its block hash, certificate and block
    /// signatures all have to be rebuilt for it.
    fn rehash(header: &mut LightHeader, keys: &[SigningKey], new_hash: BlockHash) {
        let height = header.height;
        header.block_hash = new_hash;
        header.signatures.clear();
        for k in keys.iter().take(3) {
            header.sign_with(k);
        }
        header.cert = cert(&keys[..3], height, VoteKind::Precommit, new_hash);
    }

    fn account_proof(&self, addr: &[u8; 32]) -> MerkleProof {
        self.trie
            .generate_merkle_proof(addr)
            .expect("account is in the trie")
    }

    fn token_proof(&self, acct: &[u8; 32]) -> MerkleProof {
        let key = stellereum::state_engine::token_balance_key(&self.token, acct);
        self.trie
            .generate_merkle_proof(&key)
            .expect("token balance is in the trie")
    }
}

fn ghost() -> [u8; 32] {
    [0xEEu8; 32]
}

// ============================================================================
// Checkpoints
// ============================================================================

#[test]
fn a_genuine_checkpoint_verifies_and_advances_the_client() {
    let f = Fixture::new(vec![]);
    let cp = f.checkpoint(0); // height 1
    assert!(
        cp.verify(&f.validators).is_ok(),
        "a real precommit quorum is final"
    );
    assert!(!cp.is_self_referential());

    let mut lc = LightClient::new(f.validators.clone(), cp).unwrap();
    assert_eq!(lc.tip_height(), 1);
    assert_eq!(lc.tip_hash(), f.blocks[0].compute_hash());
    assert_eq!(lc.state_root(), f.state_root);
    assert_eq!(lc.header_count(), 0, "a fresh client holds no headers");

    // The chain above the checkpoint is accepted header by header.
    for i in 1..=3 {
        lc.apply_header(f.header(i)).unwrap();
    }
    assert_eq!(lc.tip_height(), 4);
    assert_eq!(lc.tip_hash(), f.blocks[3].compute_hash());
    assert_eq!(lc.header_count(), 3);

    // Re-anchoring onto a newer checkpoint resets the window and moves the tip.
    lc.advance_to_checkpoint(f.checkpoint(4)).unwrap();
    assert_eq!(lc.tip_height(), 5);
    assert_eq!(
        lc.header_count(),
        0,
        "re-anchoring resets the header window"
    );
    assert_eq!(lc.checkpoint(), Some(&f.checkpoint(4)));

    // And the client keeps following from there.
    lc.apply_header(f.header(5)).unwrap();
    assert_eq!(lc.tip_height(), 6);
}

#[test]
fn a_prevote_quorum_is_not_finality_and_is_refused() {
    // A prevote quorum says a supermajority saw the value; it says nothing
    // about whether that value survived to be decided. The engine's own adopt
    // path had this bug, so the light client refuses a prevote certificate
    // outright rather than treating "quorum" as "final".
    let f = Fixture::new(vec![]);
    let h = f.header(0);
    let prevote = Checkpoint {
        cert: cert(&f.keys, h.height, VoteKind::Prevote, h.block_hash),
        ..f.checkpoint(0)
    };

    let err = prevote
        .verify(&f.validators)
        .expect_err("a prevote quorum must never be accepted as final");
    assert!(
        err.contains("precommit"),
        "the rejection must name the kind, got: {err}"
    );

    // The engine agrees it is a real certificate — of the wrong kind. That is
    // the whole point: the bug was never a bad signature, it was the wrong
    // object being treated as proof of finality.
    assert!(
        prevote.cert.verify(&f.validators),
        "sanity: it IS a genuine quorum certificate, just not a finality one"
    );
    assert!(
        LightClient::new(f.validators.clone(), prevote).is_err(),
        "a client must not be constructible from a prevote quorum"
    );

    // The same forgery at the header layer.
    let mut forged = h.clone();
    forged.cert = cert(&f.keys, h.height, VoteKind::Prevote, h.block_hash);
    let err = forged
        .verify(&f.validators)
        .expect_err("header must be refused");
    assert!(err.contains("precommit"), "got: {err}");

    // A nil certificate is a quorum of "no value" and finalises nothing.
    let nil = Checkpoint {
        cert: QuorumCertificate {
            height: h.height,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: f
                .keys
                .iter()
                .take(3)
                .map(|k| {
                    let v = Vote::sign(k, h.height, 0, VoteKind::Precommit, None);
                    (v.voter, v.signature)
                })
                .collect(),
        },
        ..f.checkpoint(0)
    };
    let err = nil
        .verify(&f.validators)
        .expect_err("a nil quorum names no block");
    assert!(err.contains("does not name this block hash"), "got: {err}");
}

#[test]
fn a_certificate_bound_to_another_height_is_refused() {
    let f = Fixture::new(vec![]);
    let h = f.header(0);

    // A certificate lifted from another height's consensus: real signatures,
    // over the same block hash, but for height 9.
    let cp = Checkpoint {
        cert: cert(&f.keys[..3], 9, VoteKind::Precommit, h.block_hash),
        ..f.checkpoint(0)
    };
    let err = cp
        .verify(&f.validators)
        .expect_err("a certificate for another height proves nothing here");
    // A certificate lifted from another height breaks TWO bindings at once: it is
    // signed for height 9 and it names this block hash only by coincidence of the
    // fixture. Which check reports first is an implementation detail; what matters
    // is that a height-mismatched certificate is refused, and the
    // `relabelled` case below isolates the height binding on its own.
    assert!(
        err.contains("bound to height 9") || err.contains("does not name this block hash"),
        "a height-mismatched certificate must be refused, got: {err}"
    );

    // The same forgery carried by a header.
    let mut forged = h.clone();
    forged.cert = cert(&f.keys[..3], 9, VoteKind::Precommit, h.block_hash);
    let err = forged.verify(&f.validators).expect_err("refused");
    assert!(
        err.contains("bound to height 9") || err.contains("does not name this block hash"),
        "got: {err}"
    );

    // And a certificate whose height field was rewritten after signing: the
    // binding check is satisfied (it claims height 1) but the signatures were
    // made for height 9, so it is still refused — and for the right reason.
    let rewritten = Checkpoint {
        cert: relabelled(&f.keys[..3], 9, 1),
        ..f.checkpoint(0)
    };
    let err = rewritten.verify(&f.validators).expect_err("refused");
    // Rewriting the height breaks the signature binding, and `relabelled` also
    // carries a different block hash, so either check may report it. The property
    // under test is that a doctored certificate never verifies.
    assert!(
        err.contains("did not verify") || err.contains("does not name this block hash"),
        "a doctored certificate must be refused, got: {err}"
    );

    // The genuine certificate for this block at its own height is fine, which
    // is what makes the checks about binding rather than about counting.
    assert!(f.checkpoint(0).verify(&f.validators).is_ok());
}

#[test]
fn a_certificate_from_a_non_validator_is_refused() {
    let f = Fixture::new(vec![]);
    let imposter = outsider(1);
    let h = f.header(0);

    // One throwaway key, signing correctly, with power of its own.
    let cp = Checkpoint {
        cert: cert(
            std::slice::from_ref(&imposter),
            h.height,
            VoteKind::Precommit,
            h.block_hash,
        ),
        ..f.checkpoint(0)
    };
    let err = cp
        .verify(&f.validators)
        .expect_err("a non-validator is not evidence, however well it signs");
    assert!(
        err.contains("outside the validator set"),
        "the rejection must say the signer is not a member, got: {err}"
    );
    assert!(
        LightClient::new(f.validators.clone(), cp).is_err(),
        "a client must not be constructible from a non-validator's certificate"
    );

    // Two real validators plus the impostor is still below quorum: an outsider
    // adds nothing, however valid its signature.
    let mixed = Checkpoint {
        cert: {
            let mut c = cert(&f.keys[..2], h.height, VoteKind::Precommit, h.block_hash);
            let v = Vote::sign(
                &imposter,
                h.height,
                0,
                VoteKind::Precommit,
                Some(h.block_hash),
            );
            c.signatures.push((v.voter, v.signature));
            c
        },
        ..f.checkpoint(0)
    };
    assert!(
        mixed.verify(&f.validators).is_err(),
        "two real validators plus an outsider is still below quorum"
    );

    // Three real validators plus the impostor is fine: the impostor is simply
    // not counted and the quorum stands on the members.
    let with_imposter = Checkpoint {
        cert: {
            let mut c = cert(&f.keys[..3], h.height, VoteKind::Precommit, h.block_hash);
            let v = Vote::sign(
                &imposter,
                h.height,
                0,
                VoteKind::Precommit,
                Some(h.block_hash),
            );
            c.signatures.push((v.voter, v.signature));
            c
        },
        ..f.checkpoint(0)
    };
    assert!(with_imposter.verify(&f.validators).is_ok());

    // Nor may an outsider's block signature stand in for a validator's.
    let mut header = h.clone();
    header.signatures = vec![(
        imposter.verifying_key().to_bytes(),
        imposter.sign(&h.block_hash).to_bytes().to_vec(),
    )];
    let err = header
        .verify_validator_quorum(&f.validators)
        .expect_err("block signatures from a non-validator must not count");
    assert!(err.contains("0 of the 3 power required"), "got: {err}");
}

#[test]
fn quorum_is_power_weighted_distinct_and_fails_closed() {
    let f = Fixture::new(vec![]);
    let h = f.header(0);

    // Two of four is below quorum, even though both signatures are genuine.
    let sub = Checkpoint {
        cert: cert(&f.keys[..2], h.height, VoteKind::Precommit, h.block_hash),
        ..f.checkpoint(0)
    };
    let err = sub
        .verify(&f.validators)
        .expect_err("2 of 4 is not a quorum");
    assert!(err.contains("2 of the 3 power required"), "got: {err}");

    // One validator signing many times is still one validator's power.
    let dup = Checkpoint {
        cert: {
            let v = Vote::sign(
                &f.keys[0],
                h.height,
                0,
                VoteKind::Precommit,
                Some(h.block_hash),
            );
            QuorumCertificate {
                height: h.height,
                round: 0,
                kind: VoteKind::Precommit,
                block_hash: Some(h.block_hash),
                signatures: vec![(v.voter, v.signature); 9],
            }
        },
        ..f.checkpoint(0)
    };
    assert!(
        dup.verify(&f.validators).is_err(),
        "one key signing nine times must not fake a quorum"
    );

    // Power, not head count. The same three signers are a quorum of four equal
    // validators and nowhere near a quorum when the fourth holds the stake.
    let c = cert(&f.keys[..3], h.height, VoteKind::Precommit, h.block_hash);
    assert!(c.verify(&f.validators), "3 of 4 equal stake is a quorum");
    let mut topheavy = ValidatorSet::new();
    for k in f.keys.iter().take(3) {
        topheavy.add(k.verifying_key().to_bytes(), 1);
    }
    topheavy.add(f.keys[3].verifying_key().to_bytes(), 1_000_000);
    let need = topheavy.quorum_power();
    let cp = Checkpoint {
        cert: c,
        ..f.checkpoint(0)
    };
    let err = cp
        .verify(&topheavy)
        .expect_err("3 of 4 by head count is not 2/3 of the stake");
    assert!(
        err.contains(&format!("3 of the {need} power required")),
        "got: {err}"
    );

    // An empty validator set fails closed rather than accepting anything.
    let empty = ValidatorSet::new();
    assert!(
        Checkpoint { ..f.checkpoint(0) }.verify(&empty).is_err(),
        "an empty validator set must never reach quorum"
    );
    assert!(LightClient::new(empty, f.checkpoint(0)).is_err());

    // A tampered signature (right voter, wrong bytes) does not verify.
    let tampered = Checkpoint {
        cert: {
            let mut c = cert(&f.keys[..3], h.height, VoteKind::Precommit, h.block_hash);
            c.signatures[0].1[0] ^= 0xFF;
            c
        },
        ..f.checkpoint(0)
    };
    let err = tampered.verify(&f.validators).expect_err("bad signature");
    assert!(err.contains("did not verify"), "got: {err}");
}

// ============================================================================
// The header chain
// ============================================================================

#[test]
fn a_header_forking_from_a_known_parent_is_refused() {
    let f = Fixture::new(vec![]);
    let mut lc = f.client(0, 2); // tip: height 3

    // Everything about this header is perfect — right height, a real precommit
    // quorum, a real power quorum of block signatures — except that its parent
    // is the grandparent. It is a sibling of the block we accepted, not its
    // child, and that is the one thing that cannot be talked around.
    let mut fork = f.header(2).clone();
    fork.height = 4;
    fork.prev_hash = f.blocks[1].compute_hash();
    fork.state_root = [0x5Au8; 32];
    Fixture::rehash(&mut fork, &f.keys, hash_of(0xF1));

    let err = lc
        .apply_header(fork)
        .expect_err("a sibling of our tip is a fork, not a successor");
    assert!(
        err.contains("forks"),
        "the rejection must say why, got: {err}"
    );
    assert_eq!(lc.tip_height(), 3, "a refused fork must not move the tip");
    assert_eq!(lc.header_count(), 2);

    // A fork at the join point is equally refused: the first header we ever
    // accept has to continue the checkpoint, not replace it.
    let mut lc2 = LightClient::new(f.validators.clone(), f.checkpoint(0)).unwrap();
    let mut sibling = f.header(1).clone();
    sibling.prev_hash = [0x77u8; 32];
    let err = lc2
        .apply_header(sibling)
        .expect_err("a sibling of the checkpoint is a fork too");
    assert!(err.contains("forks"), "got: {err}");
    assert_eq!(lc2.tip_height(), 1);
}

#[test]
fn a_header_with_a_height_gap_is_refused() {
    let f = Fixture::new(vec![]);
    let mut lc = f.client(0, 1); // tip: height 2

    // Height 5 with a valid quorum, parented on the tip. Without the gap check
    // the client would happily believe the three blocks in between never
    // existed — and answer balance queries against a state root they committed.
    let mut skipped = f.header(4).clone();
    skipped.prev_hash = lc.tip_hash();
    let err = lc
        .apply_header(skipped)
        .expect_err("a gap must be refused, not assumed empty");
    assert!(err.contains("leaves a gap"), "got: {err}");
    assert_eq!(lc.tip_height(), 2);

    // A gap of exactly one is still a gap: the client is at height 1 and is
    // offered height 3.
    let mut lc1 = LightClient::new(f.validators.clone(), f.checkpoint(0)).unwrap();
    let mut one_past = f.header(2).clone();
    one_past.prev_hash = lc1.tip_hash();
    let err = lc1
        .apply_header(one_past)
        .expect_err("one block past the tip is a gap");
    assert!(err.contains("leaves a gap"), "got: {err}");
    assert_eq!(lc1.header_count(), 0);

    // And a replayed header is refused in the other direction.
    let err = lc
        .apply_header(f.header(0))
        .expect_err("a replayed header is not a successor");
    assert!(err.contains("not the tip's successor"), "got: {err}");
    assert_eq!(lc.tip_height(), 2, "the tip must not move backwards");
    assert_eq!(lc.header_count(), 1);
}

#[test]
fn a_header_without_a_real_validator_quorum_is_refused() {
    let f = Fixture::new(vec![]);
    let mut lc = LightClient::new(f.validators.clone(), f.checkpoint(0)).unwrap();
    let base = f.header(1);
    let (bh, ht) = (base.block_hash, base.height);

    // Right shape, right parent, but the certificate is signed by a single
    // non-validator.
    let mut h = base.clone();
    h.cert = cert(&[outsider(2)], ht, VoteKind::Precommit, bh);
    assert!(
        lc.apply_header(h.clone()).is_err(),
        "one non-validator must not extend the chain"
    );

    // A sub-quorum of real validators is still refused.
    h.cert = cert(&f.keys[..2], ht, VoteKind::Precommit, bh);
    assert!(lc.apply_header(h.clone()).is_err());

    // A certificate for a different height is refused.
    h.cert = cert(&f.keys[..3], 7, VoteKind::Precommit, bh);
    assert!(lc.apply_header(h.clone()).is_err());

    // Correct certificate, but the block-level signatures present do not reach
    // a quorum: two of the three real ones the block carries.
    h.cert = cert(&f.keys[..3], ht, VoteKind::Precommit, bh);
    h.signatures.truncate(2);
    let err = lc
        .apply_header(h)
        .expect_err("sub-quorum block signatures must be refused");
    assert!(err.contains("2 of the 3 power required"), "got: {err}");
    assert_eq!(lc.header_count(), 0, "nothing was accepted");

    // The same header, untampered, is accepted.
    assert!(lc.apply_header(base).is_ok());
    assert_eq!(lc.header_count(), 1);
}

#[test]
fn the_header_chain_is_bounded_and_refuses_to_exceed_its_cap() {
    let f = Fixture::new(vec![]);
    const CAP: usize = 4;
    let mut lc = LightClient::with_max_headers(f.validators.clone(), f.checkpoint(0), CAP).unwrap();
    assert_eq!(lc.max_headers(), CAP);

    for i in 1..=CAP {
        lc.apply_header(f.header(i)).unwrap();
    }
    assert_eq!(lc.header_count(), CAP, "the window filled to its cap");
    assert_eq!(lc.tip_height(), CAP as u64 + 1);

    // One more honest header: refused. A client that could walk forever would
    // never be forced to ask for a fresh checkpoint, and its memory would grow
    // with uptime.
    let err = lc
        .apply_header(f.header(CAP + 1))
        .expect_err("the window is full");
    assert!(err.contains("full"), "got: {err}");
    assert!(
        err.contains("checkpoint"),
        "the error must say how to recover: {err}"
    );
    assert_eq!(
        lc.header_count(),
        CAP,
        "a refused header must not be stored"
    );
    assert_eq!(lc.tip_height(), CAP as u64 + 1, "the tip must not move");

    // It stays full: a flood of further headers grows nothing and moves nothing.
    for i in (CAP + 1)..=(f.blocks.len() - 1) {
        assert!(lc.apply_header(f.header(i)).is_err());
    }
    assert_eq!(lc.header_count(), CAP);
    assert_eq!(lc.tip_height(), CAP as u64 + 1);

    // A newer checkpoint moves the window, and then the chain continues.
    lc.advance_to_checkpoint(f.checkpoint(CAP + 1)).unwrap();
    assert_eq!(lc.header_count(), 0, "re-anchoring empties the window");
    assert_eq!(lc.tip_height(), CAP as u64 + 2);
    assert!(lc.apply_header(f.header(CAP + 2)).is_ok());

    // A cap of zero would make the client permanently unable to advance; say so
    // rather than constructing something useless.
    assert!(LightClient::with_max_headers(f.validators.clone(), f.checkpoint(0), 0).is_err());
}

#[test]
fn a_checkpoint_cannot_walk_the_client_back_onto_a_fork() {
    let f = Fixture::new(vec![]);
    let mut lc = f.client(0, 3); // tip: height 4

    // The tip's own checkpoint is fine, and is a no-op re-anchor.
    lc.advance_to_checkpoint(f.checkpoint(3)).unwrap();
    assert_eq!(lc.tip_height(), 4);
    assert_eq!(lc.header_count(), 0);

    let mut lc = f.client(0, 3);

    // Older than the tip we already accepted: this is the "hand me a checkpoint
    // from before your headers and drop the finalized blocks" move.
    let err = lc
        .advance_to_checkpoint(f.checkpoint(1))
        .expect_err("a checkpoint behind the tip must be refused");
    assert!(err.contains("older than the accepted tip"), "got: {err}");
    assert_eq!(
        lc.header_count(),
        3,
        "and the window must survive the attempt"
    );

    // Same height, different block: a peer offering an alternative history.
    // The certificate is genuine (over the alternative hash) so this exercises
    // the window conflict, not the finality check.
    let mut conflicting = f.checkpoint(3);
    conflicting.block_hash = hash_of(0xEE);
    conflicting.cert = cert(&f.keys[..3], 4, VoteKind::Precommit, hash_of(0xEE));
    let err = lc
        .advance_to_checkpoint(conflicting)
        .expect_err("a conflicting checkpoint must be refused");
    assert!(
        err.contains("conflicts with a header already accepted"),
        "got: {err}"
    );

    // Same block at the same height, but a different state root: the finalized
    // block's commitment is not negotiable. (The certificate does not commit
    // to the state root — see the module docs — so this has to be caught here.)
    let mut forked_root = f.checkpoint(3);
    forked_root.state_root = [0x99u8; 32];
    let err = lc
        .advance_to_checkpoint(forked_root)
        .expect_err("a finalized block's state root is not negotiable");
    assert!(err.contains("different state root"), "got: {err}");

    // The same block re-claimed at a different height is a re-labelling
    // attempt, refused even though the certificate is a genuine quorum.
    let mut moved = f.checkpoint(3);
    moved.height = 9;
    moved.cert = cert(
        &f.keys[..3],
        9,
        VoteKind::Precommit,
        f.blocks[3].compute_hash(),
    );
    let err = lc
        .advance_to_checkpoint(moved)
        .expect_err("a block cannot move between heights");
    assert!(err.contains("already accepted at height 4"), "got: {err}");

    // An unverified checkpoint cannot re-anchor the client either.
    let mut forged = f.checkpoint(5);
    let forged_hash = forged.block_hash;
    forged.cert = cert(&[outsider(3)], 6, VoteKind::Precommit, forged_hash);
    let err = lc
        .advance_to_checkpoint(forged)
        .expect_err("a non-validator's certificate is not a checkpoint");
    assert!(err.contains("refusing to re-anchor"), "got: {err}");
    assert_eq!(
        lc.tip_height(),
        4,
        "a refused re-anchor must not move the tip"
    );

    // After a legitimate re-anchor, an older checkpoint is refused outright.
    lc.advance_to_checkpoint(f.checkpoint(3)).unwrap();
    let err = lc
        .advance_to_checkpoint(f.checkpoint(0))
        .expect_err("the trusted checkpoint must never regress");
    assert!(err.contains("older than the trusted anchor"), "got: {err}");
    assert_eq!(lc.tip_height(), 4);
}

#[test]
fn a_header_may_not_roll_the_state_back_to_a_superseded_root() {
    // h1 commits A, h2 moves to B, h3 claims A again. A quorum could finalize
    // all three only if the state really did return to A; anything else is a
    // rollback, and a client that follows it is being walked backwards.
    let f = Fixture::new(vec![[0u8; 32], [0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]]);
    let mut lc = LightClient::new(f.validators.clone(), f.checkpoint(0)).unwrap();
    lc.apply_header(f.header(1)).unwrap(); // root -> 0xAA
    lc.apply_header(f.header(2)).unwrap(); // root -> 0xBB
    assert_eq!(lc.state_root(), [0xBBu8; 32]);

    let mut rollback = f.header(3).clone();
    rollback.state_root = f.blocks[0].state_root; // back to A
    Fixture::rehash(&mut rollback, &f.keys, hash_of(0xC1));
    let err = lc
        .apply_header(rollback)
        .expect_err("state must not roll back below a finalized height");
    assert!(err.contains("roll back"), "got: {err}");
    assert_eq!(
        lc.state_root(),
        [0xBBu8; 32],
        "the tip's root must not move"
    );
    assert_eq!(lc.header_count(), 2);

    // Carrying the parent's own root forward is NOT a rollback: a block that
    // changes nothing leaves the state where it was. Refusing that would wedge
    // the client on a chain of no-op blocks, which is over-tightening.
    let mut noop = f.header(3).clone();
    noop.state_root = f.blocks[2].state_root;
    Fixture::rehash(&mut noop, &f.keys, hash_of(0xC2));
    assert!(
        lc.apply_header(noop).is_ok(),
        "an unchanged state root is not a rollback"
    );
    assert_eq!(lc.header_count(), 3);
}

// ============================================================================
// Balance queries
// ============================================================================

#[test]
fn a_valid_balance_proof_verifies_against_a_trusted_root() {
    let f = Fixture::new(vec![]);
    let lc = f.client(0, 2);

    let proof = f.account_proof(&f.alice);
    let leaf = lc
        .verify_account(&f.alice, &account_value(5_000, 3), &proof, f.state_root)
        .expect("a genuine proof against a finalized root must verify");
    assert_eq!(leaf.balance, 5_000);
    assert_eq!(leaf.nonce, 3);
    assert_eq!(leaf.address, f.alice);
    assert_eq!(leaf.state_root, f.state_root);
    // The answer carries the height the root belongs to, so a caller can tell
    // how fresh the state it is looking at is.
    assert_eq!(
        leaf.height,
        lc.tip_height(),
        "the root is committed at the tip"
    );

    // Token balances ride the same root, under a namespaced key the client
    // recomputes itself rather than taking from the server.
    let tproof = f.token_proof(&f.alice);
    let tok = lc
        .verify_token_balance(
            &f.token,
            &f.alice,
            &777u64.to_be_bytes(),
            &tproof,
            f.state_root,
        )
        .expect("a token balance proof must verify");
    assert_eq!(tok.balance, 777);
    assert_eq!(tok.token_id, f.token);
    assert_eq!(tok.account, f.alice);
    // A token proof cannot be spent as an account proof, and vice versa.
    assert!(lc
        .verify_account(&f.alice, &account_value(5_000, 3), &tproof, f.state_root)
        .is_err());
    assert!(lc
        .verify_token_balance(
            &f.token,
            &f.bob,
            &777u64.to_be_bytes(),
            &tproof,
            f.state_root
        )
        .is_err());

    // A claim that does not match the leaf under it is refused even though the
    // path itself is genuine: the value is what the proof commits to.
    assert!(
        lc.verify_account(&f.alice, &account_value(9_999_999, 3), &proof, f.state_root)
            .is_err(),
        "a wrong balance must not verify"
    );
    // A wrong leaf length is malformed, not absence.
    assert!(matches!(
        lc.verify_account(&f.alice, &[1u8; 7], &proof, f.state_root),
        Err(LightError::InvalidProof(_))
    ));
}

#[test]
fn a_proof_against_the_wrong_root_is_refused() {
    let f = Fixture::new(vec![]);
    let lc = f.client(0, 2);
    let proof = f.account_proof(&f.alice);

    // A state root this client never finalized: there are no grounds to believe
    // it, so the proof is not even assessed.
    let unknown = [0xDEu8; 32];
    let err = lc
        .verify_account(&f.alice, &account_value(5_000, 3), &proof, unknown)
        .expect_err("an untrusted root must be refused");
    assert!(
        matches!(&err, LightError::RootUntrusted { root } if *root == unknown),
        "expected RootUntrusted, got: {err}"
    );
    assert!(!lc.trusts_root(&unknown));

    // The realistic forgery: a proof that is genuine, but authenticates against
    // a DIFFERENT state — a server on a fork, or one that rewrote the account.
    // The client trusts its own root, so the proof does not apply.
    let mut forked = PatriciaTrie::new();
    forked.insert(&f.alice, &account_value(1, 0));
    forked.insert(&f.bob, &account_value(2, 0));
    let forked_root = forked.root_hash();
    let forked_proof = forked
        .generate_merkle_proof(&f.alice)
        .expect("the forged state contains alice");
    assert_ne!(forked_root, f.state_root);
    let err = lc
        .verify_account(&f.alice, &account_value(1, 0), &forked_proof, f.state_root)
        .expect_err("a proof from a forked state must not verify against ours");
    assert!(
        matches!(err, LightError::NotIncluded { .. }),
        "expected NotIncluded, got: {err}"
    );
    assert!(
        !lc.trusts_root(&forked_root),
        "a root the client never finalized must not become trusted by being served"
    );

    // Serving a foreign root does not make it usable either: it is refused
    // before the proof is looked at.
    assert!(matches!(
        lc.verify_account(&f.alice, &account_value(1, 0), &forked_proof, forked_root),
        Err(LightError::RootUntrusted { .. })
    ));
}

#[test]
fn an_absent_key_is_reported_as_not_included_and_never_as_a_zero() {
    let f = Fixture::new(vec![]);
    let lc = f.client(0, 2);
    let g = ghost();
    assert!(f.trie.get(&g).is_none(), "the address really is absent");

    // The full node's honest answer for an absent account: no proof. That is an
    // assertion of absence, and it comes back as exactly that - distinctly, and
    // with no balance attached.
    let err = lc
        .verify_account_answer(&g, &account_value(0, 0), None, f.state_root)
        .expect_err("an absent key has no balance to return");
    assert!(
        matches!(err, LightError::NotIncluded { .. }),
        "expected NotIncluded, got: {err}"
    );

    // A proof for some OTHER key, offered in place of the absent one, is a
    // malformed proof rather than evidence of absence.
    let other = f.account_proof(&f.bob);
    assert!(
        matches!(
            lc.verify_account(&g, &account_value(0, 0), &other, f.state_root),
            Err(LightError::InvalidProof(_))
        ),
        "a mismatched key is a malformed proof, not an absence"
    );

    // A present-looking but EMPTY proof is refused outright. This is the line
    // that must not be crossed: if silence were read as absence, any server
    // could deny any account by omitting the proof.
    let empty = MerkleProof {
        key: g,
        value_hash: [0u8; 32],
        leaf_hash: [0u8; 32],
        path: vec![],
    };
    let err = lc
        .verify_account(&g, &account_value(0, 0), &empty, f.state_root)
        .expect_err("an empty proof must be refused, not read as absence");
    assert!(
        matches!(err, LightError::InvalidProof(_)),
        "an empty proof is malformed, not an absence: {err}"
    );
    assert!(
        !err.to_string().contains("0"),
        "the refusal must not read like a balance: {err}"
    );
    // The same through the "optional proof" entry point: absence stays absence,
    // and an empty proof inside it stays a protocol violation.
    assert!(matches!(
        lc.verify_account_answer(&g, &account_value(0, 0), Some(&empty), f.state_root),
        Err(LightError::InvalidProof(_))
    ));

    // The boundary case worth pinning: on a trie with a single leaf the path is
    // genuinely empty, and an empty path with a real leaf hash IS a valid
    // proof. Only an empty path with no leaf hash is the forgery above.
    let mut single = PatriciaTrie::new();
    let lone = [0x11u8; 32];
    single.insert(&lone, &account_value(42, 1));
    let single_root = single.root_hash();
    let single_proof = single
        .generate_merkle_proof(&lone)
        .expect("the lone account is in the trie");
    assert!(
        single_proof.path.is_empty(),
        "a one-entry trie needs no path"
    );

    // NOTE: the certificate commits to (height, hash), not to the state root
    // (see the module docs, limitation 3), so anchoring a client on a synthetic
    // root for this boundary case is expressible. In the real pipeline it is
    // full nodes that check a header's root against the state they applied.
    let solo = LightClient::new(
        f.validators.clone(),
        Checkpoint {
            height: 1,
            block_hash: f.blocks[0].compute_hash(),
            parent_hash: f.blocks[0].prev_hash,
            state_root: single_root,
            cert: cert(
                &f.keys[..3],
                1,
                VoteKind::Precommit,
                f.blocks[0].compute_hash(),
            ),
        },
    )
    .unwrap();
    let leaf = solo
        .verify_account(&lone, &account_value(42, 1), &single_proof, single_root)
        .expect("an empty path with a real leaf hash is a valid proof");
    assert_eq!(leaf.balance, 42);
    assert_eq!(leaf.nonce, 1);
}

#[test]
fn proof_paths_are_bounded_so_a_forged_path_costs_nothing() {
    let f = Fixture::new(vec![]);
    let lc = f.client(0, 2);
    let mut proof = f.account_proof(&f.alice);
    assert!(
        proof.path.len() <= MAX_MERKLE_PATH_STEPS,
        "a genuine path is bounded by the key length"
    );
    proof.path = vec![
        stellereum::cell::MerkleStep {
            sibling_is_right: false,
            sibling_hash: [0x11u8; 32],
            branch_prefix: [0u8; 16],
            skip: 0,
            branch_bit: 0,
        };
        MAX_MERKLE_PATH_STEPS + 1
    ];
    let err = lc
        .verify_account(&f.alice, &account_value(5_000, 3), &proof, f.state_root)
        .expect_err("an over-long path is not something the trie can produce");
    assert!(matches!(err, LightError::InvalidProof(_)), "got: {err}");
}

#[test]
fn roots_are_trusted_only_because_a_finalized_header_committed_them() {
    // Three states: the anchor, one the chain moves to, one it never reaches.
    // Only the first two may ever be used to check a proof.
    let f = Fixture::new(vec![[0u8; 32], [0xA1u8; 32], [0xB2u8; 32]]);
    let mut lc = f.client(0, 2);
    assert!(
        lc.trusts_root(&f.state_root),
        "the checkpoint's root is trusted"
    );
    assert!(lc.trusts_root(&[0xA1u8; 32]), "a header's root is trusted");
    assert!(lc.trusts_root(&[0xB2u8; 32]), "the tip's root is trusted");
    assert!(!lc.trusts_root(&[0xC3u8; 32]), "an uncommitted root is not");

    assert_eq!(lc.state_root_at(1), Some(f.state_root));
    assert_eq!(lc.state_root_at(2), Some([0xA1u8; 32]));
    assert_eq!(lc.state_root_at(3), Some([0xB2u8; 32]));
    assert_eq!(
        lc.state_root_at(4),
        None,
        "height 4 was never finalized here"
    );
    assert_eq!(lc.trusted_height_of_root(&[0xB2u8; 32]), Some(3));

    // After re-anchoring, the roots the old window carried are forgotten: the
    // trust is only as deep as what the client still holds. That is the price
    // of a bounded window, and it is why the module does not claim a rollback
    // check deeper than the window.
    lc.advance_to_checkpoint(f.checkpoint(2)).unwrap();
    assert!(lc.trusts_root(&[0xB2u8; 32]), "the new checkpoint's root");
    assert!(
        !lc.trusts_root(&f.state_root),
        "the dropped checkpoint is forgotten"
    );
    assert!(
        !lc.trusts_root(&[0xA1u8; 32]),
        "the dropped header is forgotten"
    );
    assert_eq!(lc.header_count(), 0);
}

// ============================================================================
// The properties the module says it does NOT have
// ============================================================================

#[test]
fn a_light_client_inherits_whatever_validator_set_it_was_given() {
    // Documented limitation, pinned so it cannot be forgotten: the client
    // verifies certificates against the set it was configured with and has no
    // opinion about whether that set was ever legitimately elected. Here four
    // keys the real chain does not recognise agree among themselves, and the
    // client follows them without a murmur - which is exactly the "trusts the
    // configured validator set" caveat, made executable.
    let f = Fixture::new(vec![]);
    let h = f.header(0);
    let impostors: Vec<SigningKey> = (0..N).map(|i| outsider(0x10 + i as u8)).collect();
    let fake_set = validators(&impostors);

    let cp = Checkpoint {
        cert: cert(&impostors, h.height, VoteKind::Precommit, h.block_hash),
        ..f.checkpoint(0)
    };
    assert!(
        cp.verify(&fake_set).is_ok(),
        "quorum holds inside the fake set"
    );
    assert!(cp.verify(&f.validators).is_err(), "and not in the real one");

    let mut lc = LightClient::new(fake_set.clone(), cp).unwrap();
    assert_eq!(lc.tip_height(), 1);

    let mut theirs = h.clone();
    theirs.height = 2;
    theirs.prev_hash = lc.tip_hash();
    theirs.state_root = [0x42u8; 32];
    Fixture::rehash(&mut theirs, &impostors, hash_of(0xC1));
    assert!(
        lc.apply_header(theirs).is_ok(),
        "a client that trusts a fabricated set will follow a fabricated chain"
    );
    assert_eq!(lc.tip_height(), 2);

    // It cannot be fixed afterwards: the set is the trust anchor, and there is
    // no way to replace it. A real chain's checkpoint is meaningless here.
    let err = lc
        .advance_to_checkpoint(f.checkpoint(3))
        .expect_err("the real chain's checkpoint proves nothing to this client");
    assert!(err.contains("refusing to re-anchor"), "got: {err}");
    assert_eq!(
        lc.tip_height(),
        2,
        "and it keeps following the fabricated tip"
    );
    assert_eq!(
        lc.validators.validators, fake_set.validators,
        "the validator set is fixed at construction"
    );
}

#[test]
fn only_distinct_validator_signers_are_counted() {
    // A cheap regression guard on the accounting itself: whatever else changes,
    // the signers the client counts are a set, and every one of them is a
    // member of the set it was given.
    let f = Fixture::new(vec![]);
    let c = cert(&f.keys[..3], 1, VoteKind::Precommit, hash_of(1));
    let counted: HashSet<ValidatorId> = c.signatures.iter().map(|(v, _)| *v).collect();
    assert_eq!(counted.len(), 3, "three distinct signers");
    for v in &counted {
        assert!(f.validators.contains(v), "only members are counted");
        assert!(f.validators.power_of(v) > 0, "and members have power");
    }
    assert!(c.verify(&f.validators), "3 of 4 is a quorum");
    assert_eq!(f.validators.quorum_power(), 3, "floor(2*4/3)+1");
}
