//! Silent-payment SCAN/RECEIVE wiring tests (default-OFF gate).
//!
//! Exercises the wired read paths through the crate's own types
//! (`stellereum::silentpay`, `stellereum::wallet`, the `lib.rs` read
//! helpers) — no path-included copy: these tests prove the REAL wiring,
//! while `tests/silentpay_tests.rs` keeps pinning the prototype shapes.
//!
//! Gate contract under test (`SILENT_PAY_ENABLED = false`, no env knob):
//! * OFF (default): a fresh `SilentScanner` is disarmed and `scan` returns
//!   empty even for the true owner with well-formed notes; existing
//!   wallet/address behavior is byte-identical (those suites run green
//!   unmodified).
//! * ON (tests only, via `enable_for_tests`): the scanner trial-decaps the
//!   exact `SpRecipient::receive` shape — fresh stealth addresses derive
//!   per spec, the owner finds exactly its own notes (zero FP/FN on fixed
//!   fixtures), wrong keys and tampered ciphertexts are excluded, and
//!   chain binding is enforced.
//!
//! Scope: SCAN/RECEIVE (read) only. No send/spend/funds path is touched.

use stellereum::address::{encode_stl57_address, parse_address};
use stellereum::silentpay::{
    SpNote, SpRecipient, sp_send, sp_shake256_32, sp_stealth_address, SP_CHAIN_DST, SP_CT_LEN,
    SP_GENESIS_CHAIN, SP_SPEND_DST, SP_STEALTH_DST,
};
use stellereum::wallet::{SilentNoteCandidate, SilentScanner};
use stellereum::{
    SILENT_PAY_ENABLED, silent_pay_enabled, silent_stealth_address, silent_stealth_display,
};

// ---------------------------------------------------------------------------
// Fixtures (fixed seeds — deterministic, no entropy)
// ---------------------------------------------------------------------------

const CHAIN_A: u64 = 7;
const CHAIN_B: u64 = 8;

fn kem_seed(byte: u8) -> [u8; 64] {
    [byte; 64]
}

fn ek_bytes(seed_byte: u8) -> Vec<u8> {
    use ml_kem::{
        MlKem768,
        kem::{FromSeed, KeyExport},
    };
    let seed: ml_kem::Seed = kem_seed(seed_byte).into();
    let (_, ek) = MlKem768::from_seed(&seed);
    ek.to_bytes().as_slice().to_vec()
}

/// Sender-side lockstep mirror for one recipient (same discipline as the
/// sandbox KATs: the mirror holds the sender's view of the recipient
/// `(chain, index)` state and steps it per delivered note).
struct SenderMirror {
    ek: Vec<u8>,
    chain: [u8; 32],
    index: u64,
}

impl SenderMirror {
    fn new(seed_byte: u8) -> Self {
        Self { ek: ek_bytes(seed_byte), chain: SP_GENESIS_CHAIN, index: 0 }
    }

    fn send(&mut self, chain_id: u64, randomness: &[u8; 32]) -> SpNote {
        let note =
            sp_send(&self.ek, chain_id, &self.chain, self.index, randomness).expect("sp_send");
        self.chain = note.next_chain;
        self.index += 1;
        note
    }
}

struct FixtureNote {
    recipient: usize,
    ct: Vec<u8>,
    stealth: [u8; 32],
    ss_sender: [u8; 32],
}

/// Build `counts.len()` recipients with `counts[r]` notes each, interleaved
/// round-robin on `chain_id`. Returns the KEM seeds and the notes in global
/// delivery order.
fn build_notes(counts: &[usize], chain_id: u64) -> (Vec<[u8; 64]>, Vec<FixtureNote>) {
    let seed_bytes = [0x11u8, 0x22u8, 0x33u8];
    let seeds: Vec<[u8; 64]> =
        seed_bytes.iter().take(counts.len()).map(|&b| kem_seed(b)).collect();
    let mut mirrors: Vec<SenderMirror> =
        seed_bytes.iter().take(counts.len()).map(|&b| SenderMirror::new(b)).collect();
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
        let randomness = [0xA0u8.wrapping_add(i as u8); 32];
        let note = mirrors[r].send(chain_id, &randomness);
        notes.push(FixtureNote {
            recipient: r,
            ct: note.ct,
            stealth: note.stealth,
            ss_sender: note.ss,
        });
        i += 1;
    }
    assert_eq!(i, counts.iter().sum::<usize>());
    (seeds, notes)
}

fn as_candidates(notes: &[FixtureNote]) -> Vec<SilentNoteCandidate> {
    notes
        .iter()
        .map(|n| SilentNoteCandidate { ct: n.ct.clone(), stealth: n.stealth })
        .collect()
}

// ---------------------------------------------------------------------------
// OFF: the const default + disarmed scanner returns empty.
// ---------------------------------------------------------------------------

#[test]
fn gate_is_off_by_default() {
    // GATE: black_box defeats const-folding; pin must fail loudly if flipped.
    assert!(!std::hint::black_box(SILENT_PAY_ENABLED), "wiring gate must default to OFF");
    assert!(!silent_pay_enabled());
    let scanner = SilentScanner::new(kem_seed(0x11), CHAIN_A);
    assert!(!scanner.is_armed(), "fresh scanner must be disarmed");
}

#[test]
fn off_scan_is_empty_even_for_the_true_owner() {
    // Well-formed notes for the TRUE owner — the disarmed scanner still
    // reports nothing (nothing read, nothing stepped).
    let (seeds, notes) = build_notes(&[2, 2, 2], CHAIN_A);
    assert!(notes.iter().all(|n| n.ct.len() == SP_CT_LEN));
    let candidates = as_candidates(&notes);

    for seed in &seeds {
        let scanner = SilentScanner::new(*seed, CHAIN_A);
        assert!(scanner.scan(&candidates).is_empty());
    }
    // Empty input is empty output (no panic, no allocation surprise).
    let empty: Vec<SilentNoteCandidate> = Vec::new();
    assert!(SilentScanner::new(seeds[0], CHAIN_A).scan(&empty).is_empty());
}

// ---------------------------------------------------------------------------
// ON (tests only): stealth derivation matches the spec preimage byte-for-byte
// ---------------------------------------------------------------------------

#[test]
fn stealth_address_matches_spec_preimage_byte_for_byte() {
    // The exact tags the wiring reuses — pinned as literals, not self-echoes.
    assert_eq!(SP_STEALTH_DST, b"STELL_SP_STEALTH_V1");
    assert_eq!(SP_CHAIN_DST, b"STELL_SP_CHAIN_V1");
    assert_eq!(SP_SPEND_DST, b"STELL_SP_SPEND_V1");

    // Documented 99-byte preimage:
    // `SP_STEALTH_DST || chain_id_be64 || chain(32) || ss(32) || index_be64`.
    for (chain_state, ss, index) in [
        (SP_GENESIS_CHAIN, [0x5Au8; 32], 0u64),
        (SP_GENESIS_CHAIN, [0x5Au8; 32], 1u64),
        ([0x99u8; 32], [0x00u8; 32], 9u64),
    ] {
        let mut pre = Vec::with_capacity(SP_STEALTH_DST.len() + 8 + 32 + 32 + 8);
        pre.extend_from_slice(SP_STEALTH_DST);
        pre.extend_from_slice(&CHAIN_A.to_be_bytes());
        pre.extend_from_slice(&chain_state);
        pre.extend_from_slice(&ss);
        pre.extend_from_slice(&index.to_be_bytes());
        assert_eq!(pre.len(), 99, "frozen stealth-preimage length");
        // The wired helper derives exactly the spec shape (REAL wiring: the
        // `lib.rs` helper over the crate module, no copy).
        assert_eq!(silent_stealth_address(CHAIN_A, &chain_state, &ss, index), sp_shake256_32(&pre));
        assert_eq!(
            silent_stealth_address(CHAIN_A, &chain_state, &ss, index),
            sp_stealth_address(CHAIN_A, &chain_state, &ss, index)
        );
    }

    // Fresh per note: index sensitivity + chain binding at the shape level.
    let a0 = silent_stealth_address(CHAIN_A, &SP_GENESIS_CHAIN, &[0x5Au8; 32], 0);
    let a1 = silent_stealth_address(CHAIN_A, &SP_GENESIS_CHAIN, &[0x5Au8; 32], 1);
    let b0 = silent_stealth_address(CHAIN_B, &SP_GENESIS_CHAIN, &[0x5Au8; 32], 0);
    assert_ne!(a0, a1, "successive notes get fresh addresses");
    assert_ne!(a0, b0, "same material on another chain derives another address");
    // Determinism: same inputs reproduce the same address bit-for-bit.
    assert_eq!(a0, silent_stealth_address(CHAIN_A, &SP_GENESIS_CHAIN, &[0x5Au8; 32], 0));
}

// ---------------------------------------------------------------------------
// ON (tests only): owner scan finds exactly its own notes (0 FP / 0 FN)
// ---------------------------------------------------------------------------

#[test]
fn owner_scan_finds_exactly_own_notes_zero_fp_fn() {
    let (seeds, notes) = build_notes(&[2, 2, 2], CHAIN_A);
    assert_eq!(notes.len(), 6);
    let candidates = as_candidates(&notes);

    for (r, seed) in seeds.iter().enumerate() {
        let mut scanner = SilentScanner::new(*seed, CHAIN_A);
        scanner.enable_for_tests();
        assert!(scanner.is_armed());
        let hits = scanner.scan(&candidates);
        let own: Vec<&FixtureNote> = notes.iter().filter(|n| n.recipient == r).collect();
        assert_eq!(hits.len(), own.len(), "recipient {r} must find exactly its own notes");
        for (hit, note) in hits.iter().zip(own.iter()) {
            assert_eq!(hit.stealth, note.stealth);
            assert_eq!(hit.ss, note.ss_sender, "sender/recipient ss must match");
        }
        // Indices are the recipient's own 0, 1 in order.
        assert_eq!(hits.iter().map(|h| h.index).collect::<Vec<_>>(), vec![0, 1]);
        // Idempotent: a second scan over the same list reports the same hits.
        assert_eq!(scanner.scan(&candidates), hits);
    }

    // Asymmetric quotas: 3 + 1 across two recipients, every note owned once.
    let (seeds2, notes2) = build_notes(&[3, 1], CHAIN_A);
    let candidates2 = as_candidates(&notes2);
    let mut counts = [0usize; 2];
    for (r, seed) in seeds2.iter().enumerate() {
        let mut scanner = SilentScanner::new(*seed, CHAIN_A);
        scanner.enable_for_tests();
        counts[r] = scanner.scan(&candidates2).len();
    }
    assert_eq!(counts, [3, 1]);
    assert_eq!(counts.iter().sum::<usize>(), notes2.len());
}

// ---------------------------------------------------------------------------
// ON (tests only): wrong keys + tampered ct excluded, state untouched
// ---------------------------------------------------------------------------

#[test]
fn wrong_keys_and_tampered_ct_excluded_state_untouched() {
    let (seeds, notes) = build_notes(&[1, 1, 1], CHAIN_A);
    assert_eq!(notes[0].recipient, 0);
    let candidates = as_candidates(&notes);

    // Non-owners of note 0 find nothing through the wired scanner: scan
    // only the note owned by recipient 0 (seeds[1]/seeds[2] own the OTHER
    // notes in the list — the owner test proves they find those — so the
    // full list must NOT be expected empty here).
    for seed in [&seeds[1], &seeds[2]] {
        let mut scanner = SilentScanner::new(*seed, CHAIN_A);
        scanner.enable_for_tests();
        assert!(scanner.scan(&candidates[..1]).is_empty());
    }

    // Fine-grained: the crate receive state is untouched by misses.
    for seed in [&seeds[1], &seeds[2]] {
        let mut other = SpRecipient::new(*seed, CHAIN_A);
        assert_eq!(other.receive(&notes[0].ct, &notes[0].stealth).expect("receive"), None);
        assert_eq!(other.chain(), SP_GENESIS_CHAIN);
        assert_eq!(other.next_index(), 0);
    }

    // Tampered ct: decap is infallible (implicit rejection) but yields a
    // non-matching stealth — the true owner excludes it, state untouched.
    let mut bad = notes[0].ct.clone();
    bad[513] ^= 0x01;
    let mut rec = SpRecipient::new(seeds[0], CHAIN_A);
    assert_eq!(rec.receive(&bad, &notes[0].stealth).expect("decap infallible"), None);
    assert_eq!((rec.chain(), rec.next_index()), (SP_GENESIS_CHAIN, 0));
    // The untampered note still receives afterwards (no state corruption).
    assert!(rec.receive(&notes[0].ct, &notes[0].stealth).expect("receive").is_some());

    // Malformed ct is refused outright (fail-closed, never a false hit).
    assert!(rec.receive(&[0u8; 10], &notes[0].stealth).is_err());

    // The tampered candidate is also excluded at the scanner level.
    let mut tampered = candidates.clone();
    tampered[0].ct = bad;
    let mut scanner = SilentScanner::new(seeds[0], CHAIN_A);
    scanner.enable_for_tests();
    assert!(scanner.scan(&tampered).is_empty());
}

// ---------------------------------------------------------------------------
// ON (tests only): chain binding enforced on scan
// ---------------------------------------------------------------------------

#[test]
fn chain_binding_enforced_on_scan() {
    let (seeds, notes) = build_notes(&[2], CHAIN_A);
    let candidates = as_candidates(&notes);

    // A scanner bound to another chain finds nothing.
    let mut foreign = SilentScanner::new(seeds[0], CHAIN_B);
    foreign.enable_for_tests();
    assert!(foreign.scan(&candidates).is_empty());

    // ... while the chain-matched scanner finds both.
    let mut home = SilentScanner::new(seeds[0], CHAIN_A);
    home.enable_for_tests();
    assert_eq!(home.scan(&candidates).len(), 2);

    // Same at the raw shape level: the recipient state is untouched by
    // cross-chain misses.
    let mut rec = SpRecipient::new(seeds[0], CHAIN_B);
    for n in &notes {
        assert_eq!(rec.receive(&n.ct, &n.stealth).expect("receive"), None);
    }
    assert_eq!((rec.chain(), rec.next_index()), (SP_GENESIS_CHAIN, 0));
}

// ---------------------------------------------------------------------------
// Display: derived stealth round-trips through the unmodified Stl57 codec
// ---------------------------------------------------------------------------

#[test]
fn stealth_display_roundtrips_through_stl57() {
    let (_, notes) = build_notes(&[2], CHAIN_A);
    assert_eq!(notes.len(), 2);
    assert_ne!(notes[0].stealth, notes[1].stealth, "fresh addresses per note");

    // The wired display helper reproduces the genesis note's stealth through
    // the production codec (first note derives off genesis at index 0).
    assert_eq!(
        silent_stealth_display(CHAIN_A, &SP_GENESIS_CHAIN, &notes[0].ss_sender, 0),
        encode_stl57_address(&notes[0].stealth)
    );

    // The codec itself round-trips every derived stealth (unmodified path).
    let texts: Vec<String> =
        notes.iter().map(|n| encode_stl57_address(&n.stealth)).collect();
    for (n, text) in notes.iter().zip(texts.iter()) {
        assert!(text.starts_with("Stl57"), "branded display: {text}");
        assert_eq!(parse_address(text).expect("must parse"), n.stealth);
    }
    assert_ne!(texts[0], texts[1], "distinct notes display distinctly");
}
