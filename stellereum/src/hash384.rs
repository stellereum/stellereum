//! SHAKE256-384 digest utilities (384-bit PQ collision margin).
//!
//! Filled by the hash-384 workstream: 256-bit hashes give ~85.3-bit
//! quantum collision resistance (BHT bound `n/3`); new structures that the
//! workstream controls use 384-bit digests instead. Legacy 256-bit
//! commitments stay byte-identical (history compat).
//!
//! # Honesty note (BHT bound + scope)
//!
//! Quantum collision search (Brassard-Hoyer-Tapp, BHT) costs ~2^(n/3) for an
//! `n`-bit digest, so a system's PQ collision margin is
//! `lambda = min(lambda_sig, n/3)` where `lambda_sig` is the signature /
//! KEM PQ strength (here Falcon-512 / ML-KEM-768) and `n/3` is the hash leg.
//! Concretely: `n = 256` gives `256/3 ~= 85.3` bits of PQ collision
//! security; `n = 384` gives `384/3 = 128` bits. This module raises the
//! *hash leg* to 128 bits; it does NOT raise `lambda_sig`.
//!
//! Where 384-bit material is now used: NOWHERE yet — this module only.
//! There are zero production callers. Legacy 256-bit commitments stay
//! byte-identical: `consensus.rs`, block/tx hashes, trie, MMR, the
//! `blake3`-pinned `dns_seeds.rs` KEM pins (`kem_hash`, `[u8; 32]` wire
//! field), and `pq_registry.rs` (which stores full keys, no fingerprint to
//! migrate) are all UNTOUCHED. Migrating any committed history to 384 bits
//! would be a fork and is explicitly out of scope.
//!
//! # Migration decision (verified, 2026-11-05): NO migration
//!
//! Candidates read first:
//!
//! * `src/dns_seeds.rs:153-164` (`kem_ek_hash`) and `:168-199`
//!   (`verify_kem_ek_against_pin`, `verify_discovered_kem_ek`): the pin is a
//!   `blake3` 32-byte hash carried as `kem_hash=<hex32>` in the DNS TXT wire
//!   record (`src/dns_seeds.rs:12`, `MAX_TXT_RECORD_LEN = 512`). Widening to
//!   48 bytes changes the wire field, the published-operator format, and the
//!   `Option<[u8; 32]>` type — NOT zero wire-compat impact. Rejected.
//! * `src/pq_registry.rs` (whole file read): stores full PQ keys
//!   (`PqScheme` + `pubkey: Vec<u8>`), no hash/fingerprint field exists, so
//!   there is nothing to migrate without inventing a new committed field.
//!   Rejected (no zero-impact target).
//!
//! # Construction (no new deps)
//!
//! `hash384(domain, msg) = SHAKE256(domain || msg)` squeezed to 48 bytes,
//! via the tree sponge `crate::cn_vrf::shake256_xof` (`src/cn_vrf.rs:127`,
//! permutation `crate::post_quantum::keccak_f1600` at `src/post_quantum.rs:582`,
//! rate 136 / pad `0x1F` / final `0x80`). No new crate is added: the
//! `shake v0.1.0` entry in `Cargo.lock:2276` is a TRANSITIVE dep
//! (via `ml-kem -> sha3/shake`) and is NOT in `Cargo.toml` — this module
//! does not import it. Callers must use fixed-length ASCII domain tags
//! (the tree precedent: `SP_STEALTH_DST`, `HP_COMMIT_DST`, `CNVRF_*_DST`);
//! raw `domain || msg` concatenation is ambiguous for variable-length
//! domains, so `hash384_raw` is provided for explicitly-framed preimages.
//!
//! # Provenance (in-tree NIST pins, not re-asserted blindly)
//!
//! The underlying sponge is pinned against the NIST ShortMsgKAT vectors in
//! `src/post_quantum.rs:2166` (`test_shake256_matches_the_nist_test_vectors`)
//! and `tests/cn_vrf_tests.rs:48-53`:
//! `SHAKE256("")` 32B = `46b9dd2b...ed5762f`,
//! `SHAKE256("abc")` 32B = `48336660...e78b5739`, plus a 64-byte squeeze
//! continuity check. The tests below cross-check THIS module against those
//! pins by prefix: a 48-byte XOF squeeze must start with the 32-byte vector
//! and itself be a prefix of the 64-byte squeeze (XOF property).

use crate::cn_vrf::shake256_xof;

/// Output length of [`hash384`] / [`hash384_raw`] / [`Hash384`], in bytes.
pub const HASH384_LEN: usize = 48;

/// PQ collision margin of a 384-bit digest under BHT (`384/3 = 128` bits).
pub const HASH384_PQ_BITS: u32 = 128;

/// PQ collision margin of the legacy 256-bit digests (`256/3 ~= 85.3`,
/// truncated to 85 for integer reporting).
pub const HASH256_PQ_BITS: u32 = 85;

/// SHAKE256 XOF squeeze of exactly [`HASH384_LEN`] bytes over `data`.
///
/// This is the raw primitive: `domain` framing (if any) is the caller's
/// responsibility. Prefer [`hash384`] for domain-separated use.
pub fn hash384_raw(data: &[u8]) -> [u8; 48] {
    let mut out = [0u8; HASH384_LEN];
    shake256_xof(data, &mut out);
    out
}

/// Domain-separated 384-bit digest: `SHAKE256(domain || msg)` (48 bytes).
///
/// `domain` must be a fixed-length tag (tree precedent: `b"STELL_*_V1"`
/// ASCII tags); variable-length domains without their own length prefix
/// make `domain || msg` ambiguous across the boundary. Use [`hash384_raw`]
/// with an explicitly framed preimage if that matters to the caller.
pub fn hash384(domain: &[u8], msg: &[u8]) -> [u8; 48] {
    // One allocation sized to the exact preimage; the squeeze itself is the
    // tree sponge (`crate::cn_vrf::shake256_xof`).
    let mut pre = Vec::with_capacity(domain.len().saturating_add(msg.len()));
    pre.extend_from_slice(domain);
    pre.extend_from_slice(msg);
    hash384_raw(&pre)
}

/// General SHAKE256 XOF squeeze over `data` into `out` (any length).
///
/// Thin alias over the tree sponge for callers that need a non-48-byte
/// squeeze without reimplementing absorb/squeeze.
pub fn hash384_xof(data: &[u8], out: &mut [u8]) {
    shake256_xof(data, out);
}

/// Streaming 384-bit hasher: `new(domain)` + `update(chunk)*` + `finalize()`.
///
/// Trivially correct by construction: it buffers the exact
/// `domain || chunks...` byte string and defers to the one-shot
/// [`hash384`] at `finalize`, so streaming output is byte-identical to the
/// one-shot output over the same bytes. (It does NOT do incremental sponge
/// absorbs — buffering keeps it a one-line audit against the pinned XOF.)
#[derive(Clone, Debug, Default)]
pub struct Hash384 {
    buf: Vec<u8>,
}

impl Hash384 {
    /// Start a digest with `domain` as the leading bytes.
    pub fn new(domain: &[u8]) -> Self {
        let mut buf = Vec::with_capacity(domain.len());
        buf.extend_from_slice(domain);
        Self { buf }
    }

    /// Absorb one more chunk (buffered; see struct docs).
    pub fn update(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Squeeze the 48-byte digest (== [`hash384_raw`] over the buffered bytes).
    pub fn finalize(&self) -> [u8; 48] {
        hash384_raw(&self.buf)
    }

    /// Number of bytes buffered so far (domain + updates).
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True when nothing has been absorbed (only possible with an empty domain
    /// and no updates).
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cn_vrf::{shake256_32, shake256_xof as tree_xof};

    /// In-tree NIST ShortMsgKAT pin (`test_shake256_matches_the_nist_test_vectors`,
    /// `tests/cn_vrf_tests.rs:48`): `SHAKE256("")` 32 bytes out.
    const NIST_EMPTY_32: &str = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";
    /// In-tree NIST ShortMsgKAT pin (`test_shake256_matches_the_nist_test_vectors`,
    /// `tests/cn_vrf_tests.rs:52`): `SHAKE256("abc")` 32 bytes out.
    const NIST_ABC_32: &str = "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739";

    #[test]
    fn output_length_is_48_bytes() {
        assert_eq!(HASH384_LEN, 48);
        let out = hash384(b"STELL_HASH384_TEST_V1", b"hello");
        assert_eq!(out.len(), 48);
        assert_eq!(hash384_raw(b"").len(), 48);
        let h = Hash384::new(b"STELL_HASH384_TEST_V1");
        assert_eq!(h.finalize().len(), 48);
    }

    #[test]
    fn determinism_same_inputs_same_digest() {
        let a = hash384(b"STELL_HASH384_TEST_V1", b"the quick brown fox");
        let b = hash384(b"STELL_HASH384_TEST_V1", b"the quick brown fox");
        assert_eq!(a, b, "one-shot must be deterministic");
        let mut h1 = Hash384::new(b"STELL_HASH384_TEST_V1");
        h1.update(b"the quick ");
        h1.update(b"brown fox");
        let mut h2 = Hash384::new(b"STELL_HASH384_TEST_V1");
        h2.update(b"the quick brown fox");
        assert_eq!(
            h1.finalize(),
            h2.finalize(),
            "streaming must be deterministic"
        );
        // Multi-block absorb (> 136-byte rate) stays deterministic.
        let long = vec![0xABu8; 200];
        assert_eq!(hash384(b"D", &long), hash384(b"D", &long));
    }

    #[test]
    fn domain_separation_and_message_sensitivity() {
        let msg = b"same message";
        let a = hash384(b"STELL_DOMAIN_A_V1", msg);
        let b = hash384(b"STELL_DOMAIN_B_V1", msg);
        assert_ne!(a, b, "different domains must separate");
        let c = hash384(b"", msg);
        assert_ne!(a, c, "empty domain must differ from a tagged one");
        let d1 = hash384(b"STELL_DOMAIN_A_V1", b"message one");
        let d2 = hash384(b"STELL_DOMAIN_A_V1", b"message two");
        assert_ne!(d1, d2, "different messages must differ under one domain");
        assert_ne!(
            hash384(b"STELL_DOMAIN_A_V1", b""),
            hash384(b"STELL_DOMAIN_A_V1", b"\x00"),
            "trailing byte must change the digest"
        );
    }

    #[test]
    fn empty_input_matches_nist_prefix_and_xof_continuity() {
        // hash384(b"", b"") == SHAKE256("") squeezed to 48: its first 32
        // bytes MUST equal the in-tree NIST empty 32-byte pin, and it MUST
        // be a prefix of the 64-byte squeeze (XOF continuity). This
        // transitively pins this module to the NIST vectors without
        // inventing a new 48-byte constant from memory.
        let out48 = hash384(b"", b"");
        assert_eq!(
            hex::encode(&out48[..32]),
            NIST_EMPTY_32,
            "first 32 bytes must equal the NIST empty vector"
        );
        let mut out64 = [0u8; 64];
        tree_xof(b"", &mut out64);
        assert_eq!(
            &out64[..48],
            &out48[..],
            "48-byte squeeze must prefix the 64-byte squeeze"
        );
        // Direct sponge agreement: one-shot == tree XOF at 48 bytes.
        let mut direct = [0u8; 48];
        tree_xof(b"", &mut direct);
        assert_eq!(out48, direct);
        // "abc" through the empty-domain path == SHAKE256("abc") XOF: first
        // 32 bytes equal the in-tree NIST "abc" pin.
        let abc48 = hash384(b"", b"abc");
        assert_eq!(
            hex::encode(&abc48[..32]),
            NIST_ABC_32,
            "first 32 bytes must equal the NIST abc vector"
        );
        assert_eq!(abc48, hash384_raw(b"abc"));
        // Belt-and-braces: the tree's own 32-byte helper agrees too.
        assert_eq!(&shake256_32(b"")[..], &out48[..32]);
        assert_eq!(&shake256_32(b"abc")[..], &abc48[..32]);
    }

    #[test]
    fn streaming_hasher_matches_one_shot_on_split_inputs() {
        let domain = b"STELL_HASH384_STREAM_V1";
        let parts: [&[u8]; 4] = [b"alpha-", b"", b"beta-gamma", b"-delta"];
        let mut cat = Vec::new();
        for p in parts {
            cat.extend_from_slice(p);
        }
        let expect = hash384(domain, &cat);
        let mut h = Hash384::new(domain);
        for p in parts {
            h.update(p);
        }
        assert_eq!(h.finalize(), expect, "split updates must match one-shot");
        // Byte-at-a-time also matches.
        let mut h2 = Hash384::new(domain);
        for b in cat.iter() {
            h2.update(std::slice::from_ref(b));
        }
        assert_eq!(h2.finalize(), expect);
        // Empty-stream edge: empty domain + no updates == SHAKE256("").
        let h0 = Hash384::new(b"");
        assert!(h0.is_empty());
        assert_eq!(h0.len(), 0);
        assert_eq!(h0.finalize(), hash384(b"", b""));
        // Non-empty domain reports its buffered length.
        let h3 = Hash384::new(domain);
        assert!(!h3.is_empty());
        assert_eq!(h3.len(), domain.len());
    }

    #[test]
    fn xof_alias_agrees_with_tree_sponge_at_arbitrary_lengths() {
        // hash384_xof is a thin alias: agreement at 1, 32, 48, 64, 200 bytes.
        for len in [1usize, 32, 48, 64, 200] {
            let mut via_alias = vec![0u8; len];
            let mut via_tree = vec![0u8; len];
            hash384_xof(b"arbitrary preimage", &mut via_alias);
            tree_xof(b"arbitrary preimage", &mut via_tree);
            assert_eq!(via_alias, via_tree, "alias must match tree at len {len}");
        }
        // 48-byte alias output == hash384_raw.
        let mut out = [0u8; 48];
        hash384_xof(b"same bytes", &mut out);
        assert_eq!(out, hash384_raw(b"same bytes"));
    }

    #[test]
    fn distinct_inputs_collide_negligibly_sanity_spot_check() {
        // Not a proof — a smoke check that 256 nearby inputs give 256
        // distinct 48-byte digests (a broken sponge constant would collapse).
        let mut seen = std::collections::BTreeSet::new();
        for i in 0u16..256 {
            let mut msg = b"spot-check ".to_vec();
            msg.extend_from_slice(&i.to_le_bytes());
            assert!(seen.insert(hash384(b"STELL_HASH384_SPOT_V1", &msg)));
        }
        assert_eq!(seen.len(), 256);
    }
}
