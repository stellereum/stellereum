//! Compact block / vote propagation — DESIGN DOC + KAT PROTOTYPE (UNWIRED).
//!
//! # Status: NOT WIRED — read-only design, no wire change
//!
//! This module is intentionally NOT referenced by any `mod` declaration
//! (verified: `grep -rn compact_prop` hits only this file). It compiles
//! standalone via `rustc --test` and depends on nothing but `std`, so it
//! cannot affect the build. Wiring (even test-only `mod`) is a LEAD
//! decision. Per `AGENTS.md` §7 (frozen core: wire format), none of this
//! ships without a spec update + audit note + full gate.
//!
//! # 1. Measured current wire sizes (bincode 1.3.3, = stellereum/Cargo.toml:20)
//!
//! Method: offline harness in /tmp (repo untouched) replicating the EXACT
//! field order/types below with bincode 1.3.3 and serializing. Struct
//! sources: `TransactionWire` (sharding.rs:2356-2369, `ShardId=u32` @:372),
//! `Vote`/`VoteKind` (consensus.rs:1531-1546), `QuorumCertificate`
//! (consensus.rs:2805-2812), `ConsensusMsg` (consensus_net.rs:270-305),
//! `Block` (sharding.rs:4890-5070). Replicated substructures that are empty
//! in the measured case (payload, cross_shard_out, shard_headers, QCs)
//! contribute only their framing bytes, which is exact for those cases.
//!
//! ```text
//! tx plain (Ed25519 64 B sig, empty payload)      176 B  (= 96 fixed + 72 sigvec + 8 payloadvec)
//! tx priority-bid envelope (80 B sig)              192 B
//! vote bare, Some(hash)                            153 B  (= 8+4+4+33+32+72)
//! vote bare, nil                                     121 B
//! vote BLS envelope (176 B sig)                     265 B  (flag-off nodes never emit; bls.rs:47-59)
//! vote Falcon envelope (746 B sig)                  835 B  (post_quantum.rs:109 => 666 B sig)
//! ConsensusMsg::Vote, locked=None (live path)       158 B
//! ConsensusMsg::Vote, locked=Some                    190 B
//! QC(k Ed25519 sigs) = 57 + 104*k B  (k=1:161, 4:473, 7:785, 10:1097, 100:10457)
//! block fixed part (0 txs, 1 proposer sig, no QCs)  350 B
//! ConsensusMsg::Proposal(N) = 366 + 176*N B (16 B msg framing + 350 B header)
//!   N=0:366  N=1:542  N=100:17966  N=428:75694  N=1000:176366
//! Committed{100 txs, qc7}                           18747 B
//! BLS QC envelope fixed header                      161 B  (consensus.rs:271 HEADER)
//!   + bitfield ceil(C/8) B  (C=7:1, 10:2, 100:13, 1000:125)
//! ```
//!
//! Encoding facts the table rests on (bincode 1.3, confirmed by harness):
//! fieldless enum (`VoteKind`, msg discriminant) = u32 LE = 4 B;
//! `Option<T>` tag = 1 B; `Vec` len prefix = u64 LE = 8 B; `[u8;32]` = 32 B
//! raw. E.g. vote = 8+4+4+33+32+(8+64) = 153. ✓
//!
//! # 2. Design
//!
//! ## 2a. Tx short-ids (mempool-synced set)
//! A compact proposal carries `Vec<[u8; 6]>` (`SHORT_ID_LEN = 6`, BIP152
//! width) instead of full transactions. `short_id = FNV-1a-64(salt || txid)`
//! truncated to 48 bits in the prototype; production MUST use
//! `BLAKE3("STELL_SHORTID_V1" || salt || txid)[..6]` — the KAT pins the
//! MECHANICS (derive/match/pack/size math), not the hash choice.
//! `salt` = the proposal's `prev_hash` (fixed before proposal, committed in
//! the header): precomputation across heights is useless, and the salt needs
//! no extra wire bytes. Txs NOT admitted to the public mempool (sealed
//! MEV envelopes — mev_epoch.rs, private / priority-bid-carrying blobs a
//! receiver may lack) are ALWAYS sent full; short-ids name only
//! mempool-admitted txs. Receiver: look up each short-id in the local
//! mempool index; any miss/ambiguity → `BodyPull` request (see 2c).
//! Fail-closed: a short-id NEVER authorises execution — the block hash is
//! still computed over full txs, and a wrong/missing tx fails the hash.
//!
//! ## 2b. QC bitfield + aggregate-ready layout (BLS-off forward-compat)
//! Live reality (BLS-off): `refuse_bls_qc_if_enabled` + bls.rs:47-59 —
//! counting BLS power requires an explicit non-PQ opt-in the lead has NOT
//! defined, so the counted path stays `signatures: Vec<(ValidatorId,
//! Vec<u8>)>` = 57 + 104*k B. The design ADDS (no removal, no wire change
//! yet) a canonical bitfield alongside the list:
//! `bitfield: Vec<u8>`, `bit i` (LSB-first) = signer index `i` in the
//! canonical validator order (sorted `ValidatorId`, same order as
//! `ValidatorSet::proposer_for`'s explicit sort, consensus.rs:1518-1523).
//! Trailing unused bits MUST be zero (fail-closed unpack, mirroring the
//! existing µQC `signers_bitmask` rule and `decode_qc_bls_envelope`'s
//! bitlen check, consensus.rs:291). Uses NOW: downtime attribution and
//! evidence compare bitfields without re-walking sig lists; the verifier
//! keeps counting the Ed25519 list. At a future BLS activation (spec +
//! audit): drop the list, keep `96 B aggregate + bitfield` — QC(100) falls
//! from 10457 B to ~271 B. PQ note: BLS12-381 is classical
//! (`BLS_IS_POST_QUANTUM = false`, bls.rs:80); the aggregate layout is
//! legacy-only and MUST stay gated on that marker.
//!
//! ## 2c. Header-first + body-pull protocol sketch (no wire change yet)
//! Precedent (read-only): `network.rs:541-590` already splits announcement
//! (DHT KV hash) from body (`fetch_blob` by hash), and `consensus_net`
//! gossips `Proposal` fire-and-forget under `MAX_BATCH_ITEMS=32` /
//! `MAX_BATCH_BYTES=512 KiB` / `MAX_CONSENSUS_MSG=32 MiB`
//! (consensus_net.rs:71-88). Sketch:
//!  1. Proposer gossips `CompactProposal{height, round, header(350 B),
//!     short_ids}`.
//!  2. Receiver resolves locally; missing/ambiguous ids → bounded
//!     `BodyPull{block_hash, ids}` to the proposer/peers (cap: e.g. 64 ids
//!     per request, 3 attempts, then fall back to full-proposal fetch).
//!  3. Proposer serves `Body{txs}` (full txs only for requested ids).
//!  4. Only a fully-resolved body enters prevote. `Committed` keeps carrying
//!     the full block + QC (catch-up path, rare — 18747 B @100tx/qc7).
//! Existing compact-ish mechanisms (read-only, no change): gossip `Batch`
//! amortization (P3-H4), proposer-side exact-size trim under
//! `MAX_CONSENSUS_MSG` (runtime.rs:4430-4449), `estimate_tx_wire_bytes`
//! packing heuristic (mempool.rs:2614), µQC bitmask certs
//! (consensus.rs:1203), thin-proposal outbox dedup (main.rs:1320-1335).
//!
//! # 3. Projected savings (arithmetic from §1 measurements)
//!
//! ```text
//! CompactProposal(N, miss m) = 366 + 6*N + m*N*176 B
//!   N=100,  m=0%:    966 B  (-94.6% vs 17966)
//!   N=428,  m=0%:   2934 B  (-96.1% vs 75694)
//!   N=1000, m=0%:   6366 B  (-96.4% vs 176366)
//!   N=100,  m=5%:   1846 B  (-89.7%)
//!   N=428,  m=5%:   6700 B  (-91.1%)
//!   N=1000, m=5%:  15166 B  (-91.4%)
//! QC bitfield hybrid (BLS-off): +ceil(C/8)+1 B overhead NOW (C=100: +14 B)
//! QC @BLS activation, C=100: 271 B vs 10457 B (-97.4%)
//!   (57 fixed + 32 marker + 8 len + 161 envelope + 13 bitfield)
//! ```
//! Votes are untouched by this design (158 B live path stays).
//!
//! # 4. Risks
//! * Mempool-sync assumption: projected savings assume receivers hold the
//!   txs. Sealed/private txs bypass short-ids (always full). A byzantine
//!   proposer can inflate miss rate → body-pull amplification; mitigations:
//!   per-request id caps, attempt bounds, peer down-scoring, and the hard
//!   `MAX_CONSENSUS_MSG` ceiling still applies to every frame.
//! * DoS surface of short-ids: 48-bit ids collide (birthday @1000 txs ≈
//!   9e-10/block, negligible) and an attacker can grind txs that collide
//!   with victim mempool entries (2^48 for a targeted hit — infeasible —
//!   but cheap near-miss spam pollutes indexes). Mitigations: per-height
//!   salt (`prev_hash`), collision ⇒ treat as miss (pull full tx, never
//!   mis-execute), mempool admission fees make grinding cost real,
//!   short-id index lookups O(1) and bounded.
//! * Why no wire change yet: `AGENTS.md` §7 freezes wire format — new
//!   message types need a spec update + audit note + full gate. This file
//!   is the design input to that process, not the change itself.

/// Short-id width in bytes (BIP152 width). 48 bits: birthday collision
/// @1000 txs ≈ 5e5/2^49 ≈ 9e-10 per block — negligible; targeted preimage
/// needs 2^48 trials and the per-height salt kills precomputation.
pub const SHORT_ID_LEN: usize = 6;

/// Mempool-sync miss-rate assumption used by the 5%-column projections.
pub const ASSUMED_MISS_RATE_PCT: usize = 5;

/// Measured bincode-1.3 constants (see module doc §1 for method/sources).
pub const TX_PLAIN_BYTES: usize = 176;
pub const PROPOSAL_FIXED_BYTES: usize = 366;
pub const BLOCK_FIXED_BYTES: usize = 350;
pub const VOTE_MSG_BYTES: usize = 158;
pub const QC_FIXED_BYTES: usize = 57;
pub const QC_ED_SIG_ENTRY_BYTES: usize = 104; // 32 id + 8 len + 64 sig
pub const BLS_ENVELOPE_FIXED_BYTES: usize = 161;

/// Derive a 6-byte short-id: FNV-1a-64 over `salt || txid`, first 6 bytes
/// LE. PROTOTYPE HASH — production must use
/// `BLAKE3("STELL_SHORTID_V1" || salt || txid)[..6]`; the KAT below pins
/// the mechanics (determinism, salt separation, width), which are
/// hash-independent.
pub fn short_id(txid: &[u8; 32], salt: &[u8; 32]) -> [u8; SHORT_ID_LEN] {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001b3;
    let mut h = FNV_OFFSET;
    for b in salt.iter().chain(txid.iter()) {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    let le = h.to_le_bytes();
    let mut out = [0u8; SHORT_ID_LEN];
    out.copy_from_slice(&le[..SHORT_ID_LEN]);
    out
}

/// Pack signer presence bits, LSB-first: validator index `i` (canonical
/// sorted order) sets bit `i % 8` of byte `i / 8`. Unused trailing bits are
/// always zero by construction.
pub fn pack_bitfield(signers: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; signers.len().div_ceil(8)];
    for (i, present) in signers.iter().enumerate() {
        if *present {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// Unpack a bitfield; `None` on length mismatch OR any trailing unused bit
/// set (fail-closed, mirrors the µQC bitmask rule). The round-trip
/// `unpack(pack(x)) == Some(x)` holds for all inputs.
pub fn unpack_bitfield(bits: &[u8], total: usize) -> Option<Vec<bool>> {
    if bits.len() != total.div_ceil(8) {
        return None;
    }
    let mut out = Vec::with_capacity(total);
    for i in 0..total {
        out.push(bits[i / 8] & (1 << (i % 8)) != 0);
    }
    // Trailing-bits-zero check: bits beyond `total` must be clear.
    let used_in_last = total % 8;
    if used_in_last != 0 {
        let mask = !((1u8 << used_in_last) - 1);
        if bits.last().is_some_and(|b| b & mask != 0) {
            return None;
        }
    }
    Some(out)
}

/// Baseline `ConsensusMsg::Proposal` bytes for `n_txs` plain txs
/// (measured: 366 + 176*N).
pub fn baseline_proposal_bytes(n_txs: usize) -> usize {
    PROPOSAL_FIXED_BYTES + n_txs * TX_PLAIN_BYTES
}

/// Compact proposal bytes: header + 6 B/short-id + full bytes for misses.
pub fn compact_proposal_bytes(n_txs: usize, n_missing: usize) -> usize {
    PROPOSAL_FIXED_BYTES + n_txs * SHORT_ID_LEN + n_missing * TX_PLAIN_BYTES
}

/// Live (BLS-off) QC bytes for `n_sigs` Ed25519 signatures: 57 + 104*k.
pub fn qc_bytes_ed(n_sigs: usize) -> usize {
    QC_FIXED_BYTES + n_sigs * QC_ED_SIG_ENTRY_BYTES
}

/// Aggregate-ready QC bytes for a committee of `c` validators at a future
/// BLS activation: fixed + marker entry (32 id + 8 len + 161 envelope +
/// ceil(c/8) bitfield). Counted path stays Ed25519 until then.
pub fn qc_bytes_aggregate_ready(committee: usize) -> usize {
    QC_FIXED_BYTES + 32 + 8 + BLS_ENVELOPE_FIXED_BYTES + committee.div_ceil(8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kat_short_id_vectors() {
        // Independent cross-check: same FNV-1a-64(salt||txid)[..6LE]
        // computed with a Python reference implementation.
        let txid = [0x11u8; 32];
        let salt = [0x22u8; 32];
        assert_eq!(short_id(&txid, &salt), [0xc5, 0x49, 0x0a, 0xe2, 0x9f, 0x4e]);
        // Salt separation: same txid, zero salt differs.
        let zero = [0u8; 32];
        assert_eq!(short_id(&txid, &zero), [0x45, 0x6c, 0xf6, 0x1c, 0x27, 0x5b]);
        // Determinism + avalanche: one-bit txid flip changes the id.
        let mut txid2 = txid;
        txid2[0] ^= 1;
        let a = short_id(&txid, &salt);
        let b = short_id(&txid2, &salt);
        assert_eq!(a, short_id(&txid, &salt));
        assert_ne!(a, b);
        assert_eq!(a.len(), SHORT_ID_LEN);
    }

    #[test]
    fn kat_bitfield_pack_vectors() {
        // LSB-first packing, hand-verified: indices 0,2,8 set =>
        // byte0 = 0b00000101, byte1 = 0b00000001.
        let mut s = vec![false; 10];
        s[0] = true;
        s[2] = true;
        s[8] = true;
        assert_eq!(pack_bitfield(&s), vec![0x05, 0x01]);
        assert_eq!(pack_bitfield(&[]), Vec::<u8>::new());
        assert_eq!(pack_bitfield(&vec![false; 8]), vec![0x00]);
        assert_eq!(pack_bitfield(&vec![true; 8]), vec![0xff]);
        // 100-validator committee, first 7 sign => 13 bytes, byte0 = 0x7f.
        let mut c = vec![false; 100];
        for i in 0..7 {
            c[i] = true;
        }
        let packed = pack_bitfield(&c);
        assert_eq!(packed.len(), 13);
        assert_eq!(packed[0], 0x7f);
        assert!(packed[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn kat_bitfield_unpack_round_trip_and_fail_closed() {
        let mut s = vec![false; 10];
        s[0] = true;
        s[2] = true;
        s[8] = true;
        assert_eq!(unpack_bitfield(&[0x05, 0x01], 10), Some(s));
        // Trailing bit set (bit 2 of byte 1 is index 10, out of range) => None.
        assert_eq!(unpack_bitfield(&[0x05, 0x05], 10), None);
        // Length mismatch => None.
        assert_eq!(unpack_bitfield(&[0x05], 10), None);
        assert_eq!(unpack_bitfield(&[0x05, 0x01, 0x00], 10), None);
        // Empty committee round-trips.
        assert_eq!(unpack_bitfield(&[], 0), Some(vec![]));
    }

    #[test]
    fn kat_size_math_matches_measurements() {
        // Spot-checks against the §1 harness measurements.
        assert_eq!(baseline_proposal_bytes(0), 366);
        assert_eq!(baseline_proposal_bytes(100), 17966);
        assert_eq!(baseline_proposal_bytes(428), 75694);
        assert_eq!(baseline_proposal_bytes(1000), 176366);
        assert_eq!(qc_bytes_ed(1), 161);
        assert_eq!(qc_bytes_ed(7), 785);
        assert_eq!(qc_bytes_ed(100), 10457);
        // Projection columns (§3): m=0 and m=5%.
        assert_eq!(compact_proposal_bytes(100, 0), 966);
        assert_eq!(compact_proposal_bytes(428, 0), 2934);
        assert_eq!(compact_proposal_bytes(1000, 0), 6366);
        assert_eq!(compact_proposal_bytes(100, 5), 1846);
        assert_eq!(compact_proposal_bytes(1000, 50), 15166);
        // Aggregate-ready QC @C=100: 57 + 32 + 8 + 161 + 13 = 271.
        assert_eq!(qc_bytes_aggregate_ready(100), 271);
        assert_eq!(qc_bytes_aggregate_ready(7), 259);
        // Savings are real and large: compact(1000,0) < 4% of baseline.
        assert!(compact_proposal_bytes(1000, 0) * 100 < baseline_proposal_bytes(1000) * 4);
    }
}
