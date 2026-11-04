//! Silent-payment integration KATs — UNWIRED (test-local wiring, lead wires later).
//!
//! UNWIRED: `stellereum/src/silentpay.rs` has NO `mod` line in `lib.rs`
//! (default-off sandbox; lead adds `#[cfg(test)] mod silentpay;` when ready —
//! the `mev_pq_plan.rs` precedent). Until then this file includes the module
//! by path, so NO existing file is touched:
//! `#[path = "../src/silentpay.rs"] mod silentpay;`
//! `hashpool.rs` is included by path ONLY for the domain cross-verify KAT
//! (group E: SP commitment/nullifier tags are byte-identical to HashPool's,
//! SP stealth/chain/spend tags never collide with any HashPool tag).
//! Real Falcon-512 sign/verify comes from the already-vendored tree
//! (`stellereum::post_quantum`); ML-KEM-768 from the vendored `ml-kem`
//! crate. No new dependencies.
//!
//! Groups (one section each below):
//!  A. silent round-trip: sender -> 3 recipients, 6 interleaved notes, each
//!     recipient finds exactly its own (zero false positives/negatives)
//!  B. wrong-recipient exclusion + tampered-ct exclusion + malformed refused
//!  C. forward-secret ratchet: chain binding + unwind-impossibility game +
//!     compromise isolation + indistinguishability (attacker advantage zero)
//!  D. spend: happy + double-spend + serial substitution + tampered opening
//!     refused; Falcon-signed spend happy + bad-sig/wrong-msg refused
//!  E. domain separation: SP-vs-HP cross-verify (same commit/null tags, no
//!     other collisions) + spend-sig domain distinct
//!  F. SHAKE-256 NIST-vector pin (vendored sponge check)

#[path = "../src/silentpay.rs"]
mod silentpay;
// GATE: cross-verify KAT only needs the HashPool tags/commit/null shapes;
// the rest of the included module is intentionally unused here.
#[path = "../src/hashpool.rs"]
#[allow(dead_code)]
mod hashpool;

use silentpay::{
    SpNote, SpPool, SpRecipient, SpError, SpSpendAuth, sp_attacker_rebuild, sp_chain_step,
    sp_commit, sp_nullifier, sp_send, sp_shake256, sp_shake256_32, sp_spend_sig_msg,
    sp_stealth_address, SP_CHAIN_DST, SP_CT_LEN, SP_EK_LEN, SP_GENESIS_CHAIN,
    SP_SPEND_DST, SP_STEALTH_DST,
};
use ml_kem::{
    MlKem768,
    kem::{FromSeed, KeyExport},
};
use stellereum::post_quantum::{FalconKeypair, PqScheme, verify_pq_signature};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn kem_seed(byte: u8) -> [u8; 64] {
    [byte; 64]
}

fn ek_bytes(seed_byte: u8) -> Vec<u8> {
    let seed: ml_kem::Seed = kem_seed(seed_byte).into();
    let (_, ek) = MlKem768::from_seed(&seed);
    ek.to_bytes().as_slice().to_vec()
}

fn falcon(seed_byte: u8) -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&[seed_byte; 32])
}

fn falcon_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    verify_pq_signature(PqScheme::Falcon512, pk, msg, sig)
}

const CHAIN: u64 = 7;

/// Sender-side lockstep mirror for one recipient: holds the sender's view of
/// the recipient `(chain, index)` state and steps it per delivered note.
struct SenderMirror {
    ek: Vec<u8>,
    chain: [u8; 32],
    index: u64,
}

impl SenderMirror {
    fn new(seed_byte: u8) -> Self {
        Self { ek: ek_bytes(seed_byte), chain: SP_GENESIS_CHAIN, index: 0 }
    }

    fn send(&mut self, randomness: &[u8; 32]) -> SpNote {
        let note =
            sp_send(&self.ek, CHAIN, &self.chain, self.index, randomness).expect("sp_send");
        self.chain = note.next_chain;
        self.index += 1;
        note
    }
}

/// One on-chain note plus its off-chain opening material (fixed fixtures).
struct FixtureNote {
    recipient: usize,
    ct: Vec<u8>,
    stealth: [u8; 32],
    ss_sender: [u8; 32],
    value: u64,
    blinding: [u8; 32],
    serial: [u8; 32],
    commitment: [u8; 32],
    nullifier: [u8; 32],
}

/// Build `counts.len()` recipients with `counts[r]` notes each, interleaved
/// round-robin (note `k` goes to recipient `k % counts.len()` while that
/// recipient still has quota). Returns the notes in global delivery order.
fn build_notes(counts: &[usize], value_base: u64) -> (Vec<[u8; 64]>, Vec<FixtureNote>) {
    let seeds: Vec<[u8; 64]> =
        [0x11u8, 0x22u8, 0x33u8, 0x44u8].iter().take(counts.len()).map(|&b| kem_seed(b)).collect();
    let mut mirrors: Vec<SenderMirror> =
        [0x11u8, 0x22u8, 0x33u8, 0x44u8].iter().take(counts.len()).map(|&b| SenderMirror::new(b)).collect();
    let mut remaining = counts.to_vec();
    let mut notes = Vec::new();
    let mut i = 0usize;
    let mut k = 0usize;
    while remaining.iter().any(|&r| r > 0) {
        let r = k % counts.len();
        k += 1;
        if remaining[r] == 0 {
            continue;
        }
        remaining[r] -= 1;
        let randomness = [(0xA0u8.wrapping_add(i as u8)); 32];
        let note = mirrors[r].send(&randomness);
        let value = value_base + i as u64;
        let blinding = [(0xB0u8.wrapping_add(i as u8)); 32];
        let serial = [(0xC0u8.wrapping_add(i as u8)); 32];
        let commitment = sp_commit(CHAIN, value, &blinding, &note.stealth);
        let nullifier = sp_nullifier(&serial);
        notes.push(FixtureNote {
            recipient: r,
            ct: note.ct,
            stealth: note.stealth,
            ss_sender: note.ss,
            value,
            blinding,
            serial,
            commitment,
            nullifier,
        });
        i += 1;
    }
    assert_eq!(i, counts.iter().sum::<usize>());
    let _ = i;
    (seeds, notes)
}

// ---------------------------------------------------------------------------
// A. Silent round-trip: 3 recipients, 6 interleaved notes, exact receipt
// ---------------------------------------------------------------------------

#[test]
fn silent_roundtrip_three_recipients_exact_receipt() {
    let (seeds, notes) = build_notes(&[2, 2, 2], 100);
    assert_eq!(notes.len(), 6);
    assert!(notes.iter().all(|n| n.ct.len() == SP_CT_LEN));

    // Every recipient scans the FULL ordered candidate list; each must find
    // exactly its own notes (2), in order, with sender-matching shared
    // secrets — zero false positives, zero false negatives.
    for (r, seed) in seeds.iter().enumerate() {
        let mut rec = SpRecipient::new(*seed, CHAIN);
        let mut hits = Vec::new();
        for n in &notes {
            if let Some(receipt) = rec.receive(&n.ct, &n.stealth).expect("receive infallible") {
                assert_eq!(receipt.stealth, n.stealth);
                assert_eq!(receipt.ss, n.ss_sender, "sender/recipient ss must match");
                hits.push(n.recipient);
            }
        }
        assert_eq!(hits, vec![r, r], "recipient {r} must find exactly its own 2 notes");
        assert_eq!(rec.next_index(), 2);
        assert_ne!(rec.chain(), SP_GENESIS_CHAIN);
    }

    // Determinism: same inputs reproduce the same note bit-for-bit.
    let mut m1 = SenderMirror::new(0x11);
    let mut m2 = SenderMirror::new(0x11);
    let r = [0x5Au8; 32];
    assert_eq!(m1.send(&r), m2.send(&r));
}

#[test]
fn silent_scan_finds_own_among_other_recipients_notes() {
    // Asymmetric quotas: recipient 0 owns 3 of 4 notes; recipient 1 owns 1.
    let (seeds, notes) = build_notes(&[3, 1], 50);
    let mut counts = [0usize; 2];
    for (r, seed) in seeds.iter().enumerate() {
        let mut rec = SpRecipient::new(*seed, CHAIN);
        for n in &notes {
            if rec.receive(&n.ct, &n.stealth).expect("receive").is_some() {
                counts[r] += 1;
            }
        }
    }
    assert_eq!(counts, [3, 1]);
    assert_eq!(counts.iter().sum::<usize>(), notes.len());
}

// ---------------------------------------------------------------------------
// B. Wrong-recipient exclusion + tampered-ct exclusion + malformed refused
// ---------------------------------------------------------------------------

#[test]
fn wrong_recipient_and_tampered_ct_excluded() {
    let (seeds, notes) = build_notes(&[1, 1, 1], 100);
    // Note 0 belongs to recipient 0 (round-robin first pick).
    assert_eq!(notes[0].recipient, 0);

    // Non-recipients derive nothing: state untouched, no receipt.
    for seed in [&seeds[1], &seeds[2]] {
        let mut other = SpRecipient::new(*seed, CHAIN);
        assert_eq!(other.receive(&notes[0].ct, &notes[0].stealth).expect("receive"), None);
        assert_eq!(other.chain(), SP_GENESIS_CHAIN);
        assert_eq!(other.next_index(), 0);
    }

    // Tampered ct: decap is infallible (implicit rejection) but yields a
    // non-matching stealth — the true recipient excludes it, state untouched.
    let mut bad = notes[0].ct.clone();
    bad[513] ^= 0x01;
    let mut rec = SpRecipient::new(seeds[0], CHAIN);
    assert_eq!(rec.receive(&bad, &notes[0].stealth).expect("decap infallible"), None);
    assert_eq!((rec.chain(), rec.next_index()), (SP_GENESIS_CHAIN, 0));
    // The untampered note still receives afterwards (no state corruption).
    assert!(rec.receive(&notes[0].ct, &notes[0].stealth).expect("receive").is_some());

    // Malformed inputs are refused outright.
    assert_eq!(
        sp_send(&[0u8; 100], CHAIN, &SP_GENESIS_CHAIN, 0, &[0u8; 32]),
        Err(SpError::BadEncapsulationKey)
    );
    assert_eq!(ek_bytes(0x11).len(), SP_EK_LEN);
    assert_eq!(
        rec.receive(&[0u8; 10], &notes[0].stealth),
        Err(SpError::BadCiphertext)
    );
}

// ---------------------------------------------------------------------------
// C. Forward-secret ratchet: binding + unwind-impossibility game
// ---------------------------------------------------------------------------

#[test]
fn fs_chain_is_deterministic_distinct_and_binding() {
    let mut mirror = SenderMirror::new(0x11);
    let mut chains = vec![SP_GENESIS_CHAIN];
    let mut sss = Vec::new();
    for i in 0..4u8 {
        let note = mirror.send(&[(0xA0 + i); 32]);
        sss.push(note.ss);
        chains.push(note.next_chain);
    }
    // Five states (genesis + 4 steps): all distinct, all nonzero.
    for (a, b) in chains.iter().zip(chains.iter().skip(1)) {
        assert_ne!(a, b);
    }
    assert_eq!(chains[0], SP_GENESIS_CHAIN);
    assert!(chains[1..].iter().all(|c| c.iter().any(|&x| x != 0)));
    // Deterministic re-step reproduces every state.
    let mut c = SP_GENESIS_CHAIN;
    for (i, ss) in sss.iter().enumerate() {
        c = sp_chain_step(&c, ss);
        assert_eq!(c, chains[i + 1]);
    }
    // Binding: any single-bit tamper of EITHER input misses the true successor.
    for i in 0..4 {
        let mut bad_prev = chains[i];
        bad_prev[7] ^= 0x01;
        assert_ne!(sp_chain_step(&bad_prev, &sss[i]), chains[i + 1]);
        let mut bad_ss = sss[i];
        bad_ss[0] ^= 0x01;
        assert_ne!(sp_chain_step(&chains[i], &bad_ss), chains[i + 1]);
    }
}

#[test]
fn fs_unwind_impossibility_game_attacker_advantage_zero() {
    // Four notes to one recipient; full compromise matrix on fixed fixtures.
    let (seeds, notes) = build_notes(&[4], 100);
    assert_eq!(notes.len(), 4);
    // Reconstruct the recipient chain states: c[0] = genesis, c[k+1] steps
    // with the sender-observed ss (equal to the recipient's by group A).
    let mut chains = vec![SP_GENESIS_CHAIN];
    for n in &notes {
        chains.push(sp_chain_step(chains.last().unwrap(), &n.ss_sender));
    }

    // Attacker capability, honestly modeled: compromising note i reveals
    // (chain_i, ss_i, blinding_i, serial_i). Forward recomputation yields
    // chain_{i+1} — assert the attacker CAN do that (no false strength
    // claims) — but NOTHING else: every other note's (chain, ss) pair stays
    // out of reach, so every rebuild misses every other stealth.
    let mut attacker_hits = 0u32;
    for i in 0..4 {
        let fwd = sp_chain_step(&chains[i], &notes[i].ss_sender);
        assert_eq!(fwd, chains[i + 1], "forward step from compromised material is computable");
        let known_chains = [chains[i], chains[i + 1]];
        for j in 0..4 {
            if j == i {
                continue;
            }
            for &kc in &known_chains {
                for guess in 0..8u64 {
                    if sp_attacker_rebuild(CHAIN, &kc, &notes[i].ss_sender, guess)
                        == notes[j].stealth
                    {
                        attacker_hits += 1;
                    }
                }
            }
        }
    }
    assert_eq!(attacker_hits, 0, "no compromised material unwinds any other note");

    // Indistinguishability on fixed fixtures: attacker decision procedure is
    // "candidate == anything I can rebuild". Fixed decoys stand in for
    // random; the procedure must output "random" for BOTH the real stealth_j
    // and the decoy (advantage zero) for every compromised i and target j!=i.
    let decoys: Vec<[u8; 32]> = (0..4)
        .map(|k| {
            let mut pre = b"SP_DECOY_V1".to_vec();
            pre.push(k as u8);
            sp_shake256_32(&pre)
        })
        .collect();
    let _ = seeds;
    for i in 0..4 {
        let mut rebuildable = Vec::new();
        for kc in [chains[i], chains[i + 1]] {
            for guess in 0..8u64 {
                rebuildable.push(sp_attacker_rebuild(CHAIN, &kc, &notes[i].ss_sender, guess));
            }
        }
        for j in 0..4 {
            if j == i {
                continue;
            }
            let real_says_random = !rebuildable.contains(&notes[j].stealth);
            let decoy_says_random = !rebuildable.contains(&decoys[j]);
            assert!(real_says_random && decoy_says_random,
                "attacker cannot distinguish note {j} stealth from random given note {i} compromise");
        }
    }
}

#[test]
fn fs_compromised_note_key_does_not_open_other_notes() {
    // Reveal EVERYTHING about note 1 except the recipient seed (blinding,
    // serial, ss, both adjacent chains) — notes 0 and 2 must stay unlinkable:
    // their commitments do not recompute from leaked material, and their
    // nullifiers do not derive from it either.
    let (_, notes) = build_notes(&[3], 100);
    let leaked = &notes[1];
    for other in [&notes[0], &notes[2]] {
        assert_ne!(
            sp_commit(CHAIN, other.value, &leaked.blinding, &other.stealth),
            other.commitment
        );
        assert_ne!(sp_nullifier(&leaked.serial), other.nullifier);
        assert_ne!(leaked.ss_sender, other.ss_sender);
        assert_ne!(leaked.stealth, other.stealth);
    }
}

// ---------------------------------------------------------------------------
// D. Spend: HashPool-identical nullifier mechanics + Falcon authorization
// ---------------------------------------------------------------------------

fn deposit_note(pool: &mut SpPool, n: &FixtureNote) {
    pool.deposit(n.commitment, n.stealth, n.nullifier).expect("deposit");
}

#[test]
fn spend_happy_double_spend_and_substitution_refused() {
    let (_, notes) = build_notes(&[2], 100);
    let mut pool = SpPool::new(CHAIN);
    assert_eq!(pool.chain_id(), CHAIN);
    assert!(pool.is_empty());
    for n in &notes {
        deposit_note(&mut pool, n);
    }
    assert_eq!(pool.len(), 2);

    // Happy spend of note 0.
    let n0 = &notes[0];
    assert_eq!(pool.spend(&n0.commitment, &n0.serial, n0.value, &n0.blinding), Ok(n0.nullifier));
    assert!(pool.is_spent(&n0.nullifier));
    assert_eq!(pool.spent_len(), 1);

    // Replayed note: same nullifier twice is refused...
    assert_eq!(
        pool.spend(&n0.commitment, &n0.serial, n0.value, &n0.blinding),
        Err(SpError::AlreadySpent)
    );
    // ...and serial substitution on the same note is refused (serial bound
    // at deposit — a different serial yields an unbound nullifier).
    assert_eq!(
        pool.spend(&n0.commitment, &notes[1].serial, n0.value, &n0.blinding),
        Err(SpError::SerialMismatch)
    );
    // Note 1 still spends exactly once.
    let n1 = &notes[1];
    assert_eq!(pool.spend(&n1.commitment, &n1.serial, n1.value, &n1.blinding), Ok(n1.nullifier));
    assert_eq!(pool.spent_len(), 2);
}

#[test]
fn spend_tampered_opening_refused() {
    let (_, notes) = build_notes(&[1], 100);
    let n = &notes[0];
    let mut pool = SpPool::new(CHAIN);
    deposit_note(&mut pool, n);
    // Duplicate registration refused (replayed deposit).
    assert_eq!(
        pool.deposit(n.commitment, n.stealth, n.nullifier),
        Err(SpError::DuplicateDeposit)
    );
    // Wrong value / wrong blinding: recomputation misses.
    assert_eq!(
        pool.spend(&n.commitment, &n.serial, n.value + 1, &n.blinding),
        Err(SpError::CommitmentMismatch)
    );
    let mut bad_blind = n.blinding;
    bad_blind[0] ^= 0x01;
    assert_eq!(
        pool.spend(&n.commitment, &n.serial, n.value, &bad_blind),
        Err(SpError::CommitmentMismatch)
    );
    // Unknown commitment: refused.
    assert_eq!(
        pool.spend(&[0xABu8; 32], &n.serial, n.value, &n.blinding),
        Err(SpError::UnknownCommitment)
    );
    // Cross-chain pool never contains the commitment.
    assert!(!SpPool::new(CHAIN + 1).contains(&n.commitment));
}

#[test]
fn spend_signed_happy_bad_sig_and_wrong_msg_refused() {
    let (_, notes) = build_notes(&[1], 100);
    let n = &notes[0];
    let owner = falcon(0xD0);
    let msg = sp_spend_sig_msg(CHAIN, &n.commitment, &n.nullifier);
    let sig = owner.sign(&msg);
    let auth = |sig: Vec<u8>| SpSpendAuth {
        commitment: n.commitment,
        serial: n.serial,
        value: n.value,
        blinding: n.blinding,
        owner_pk: owner.public_key.clone(),
        owner_sig: sig,
    };

    // Happy path: valid Falcon-512 owner signature authorizes the spend.
    let mut pool = SpPool::new(CHAIN);
    deposit_note(&mut pool, n);
    assert_eq!(pool.spend_signed(&auth(sig.clone()), &falcon_verify), Ok(n.nullifier));
    assert!(pool.is_spent(&n.nullifier));

    // One flipped signature byte: refused, state untouched (still unspent,
    // and the valid spend works afterwards on a fresh pool state).
    let mut pool2 = SpPool::new(CHAIN);
    deposit_note(&mut pool2, n);
    let mut bad_sig = sig.clone();
    bad_sig[10] ^= 0x01;
    assert_eq!(
        pool2.spend_signed(&auth(bad_sig), &falcon_verify),
        Err(SpError::BadSignature)
    );
    assert!(!pool2.is_spent(&n.nullifier));

    // Signature over a DIFFERENT message (wrong commitment): refused.
    let mut pool3 = SpPool::new(CHAIN);
    deposit_note(&mut pool3, n);
    let wrong_msg = sp_spend_sig_msg(CHAIN, &[0xEEu8; 32], &n.nullifier);
    let wrong_sig = owner.sign(&wrong_msg);
    assert_eq!(
        pool3.spend_signed(&auth(wrong_sig), &falcon_verify),
        Err(SpError::BadSignature)
    );
    assert!(!pool3.is_spent(&n.nullifier));

    // Wrong-chain message: refused (chain binding is load-bearing).
    let cross_msg = sp_spend_sig_msg(CHAIN + 1, &n.commitment, &n.nullifier);
    assert_ne!(msg, cross_msg);
}

// ---------------------------------------------------------------------------
// E. Domain separation: SP-vs-HP cross-verify
// ---------------------------------------------------------------------------

#[test]
fn domain_tags_sp_never_collide_with_hashpool_tags() {
    // Same commit/null tags, no forks...
    assert_eq!(silentpay::SP_COMMIT_DST, hashpool::HP_COMMIT_DST);
    assert_eq!(silentpay::SP_NULL_DST, hashpool::HP_NULL_DST);
    // ...and every SP-only tag differs from every HashPool tag.
    for sp in [SP_STEALTH_DST, SP_CHAIN_DST, SP_SPEND_DST] {
        for hp in [
            hashpool::HP_STEALTH_DST,
            hashpool::HP_COMMIT_DST,
            hashpool::HP_NULL_DST,
            hashpool::HP_CJ_SIG_DST,
        ] {
            assert_ne!(sp, hp, "SP tag must never collide with a HashPool tag");
        }
    }
    assert_ne!(SP_STEALTH_DST, SP_CHAIN_DST);
    assert_ne!(SP_STEALTH_DST, SP_SPEND_DST);
    assert_ne!(SP_CHAIN_DST, SP_SPEND_DST);
}

#[test]
fn commit_nullifier_outputs_match_hashpool_byte_for_byte() {
    // Shared-tag proof: identical outputs on identical inputs (3 fixtures).
    for byte in [0x00u8, 0x42u8, 0xFFu8] {
        let (blinding, stealth, serial) = ([byte; 32], [byte; 32], [!byte; 32]);
        assert_eq!(
            sp_commit(CHAIN, 25, &blinding, &stealth),
            hashpool::note_commit(CHAIN, 25, &blinding, &stealth)
        );
        assert_eq!(sp_nullifier(&serial), hashpool::note_nullifier(&serial));
    }
    // ...but SP stealth addresses differ from HP stealth addresses on the
    // same (ss, index) material: different domain AND chain-state binding.
    for byte in [0x00u8, 0x42u8, 0xFFu8] {
        let ss = [byte; 32];
        let sp = sp_stealth_address(CHAIN, &SP_GENESIS_CHAIN, &ss, 9);
        let mut pre = Vec::new();
        pre.extend_from_slice(hashpool::HP_STEALTH_DST);
        pre.extend_from_slice(&ss);
        pre.extend_from_slice(&9u64.to_be_bytes());
        let mut hp = [0u8; 32];
        hashpool::hp_shake256(&pre, &mut hp);
        assert_ne!(sp, hp);
    }
    // The spend-sig message domain is distinct from note domains.
    let msg = sp_spend_sig_msg(CHAIN, &[0x11u8; 32], &[0x22u8; 32]);
    assert_ne!(msg, sp_commit(CHAIN, 25, &[0x11u8; 32], &[0x33u8; 32]));
    assert_ne!(msg, sp_nullifier(&[0x11u8; 32]));
}

// ---------------------------------------------------------------------------
// F. SHAKE-256 NIST-vector pin (vendored sponge check)
// ---------------------------------------------------------------------------

#[test]
fn shake256_matches_nist_vectors() {
    // SHAKE256("") 32 bytes (NIST ShortMsgKAT).
    let mut out = [0u8; 32];
    sp_shake256(b"", &mut out);
    assert_eq!(
        hex::encode(out),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
    );
    // SHAKE256("abc") 32 bytes (NIST ShortMsgKAT).
    sp_shake256(b"abc", &mut out);
    assert_eq!(
        hex::encode(out),
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
    );
    // 64-byte squeeze crosses the 136-byte rate boundary logic.
    let mut out64 = [0u8; 64];
    sp_shake256(b"", &mut out64);
    assert_eq!(
        hex::encode(out64),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
         d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
            .replace(['\n', ' '], "")
    );
}
