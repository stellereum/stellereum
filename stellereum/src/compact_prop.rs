//! Compact block / vote propagation — DESIGN DOC + KAT PROTOTYPE, FIRST WIRING.
//!
//! # Status: WIRED (read-only inclusion, INACTIVE on the wire)
//!
//! Wired via `consensus_net.rs` (`#[path = "compact_prop.rs"] pub mod
//! compact_prop`, mirroring the `dandelion.rs` precedent): this file now
//! compiles inside the crate and its codec (`encode_compact_qc` /
//! `decode_compact_qc`) backs the compact-µQC gossip frame, but emission AND
//! admission stay gated on `COMPACT_GOSSIP_ACTIVATION_HEIGHT = u64::MAX`, so
//! no node emits or accepts the new frame until the lead flips the const.
//! The file still depends on nothing but `std` and still compiles standalone
//! via `rustc --test`.
//!
//! # 1. Measured current wire sizes (bincode 1.3.3, = stellereum/Cargo.toml:20)
//!
//! Method: offline harness in /tmp (repo untouched) replicating the EXACT
//! field order/types below with bincode 1.3.3 and serializing. Struct
//! sources: `TransactionWire` (sharding.rs `TransactionWire`, `ShardId=u32` @:372),
//! `Vote`/`VoteKind` (`Vote`/`VoteKind` in consensus.rs), `QuorumCertificate`
//! (`QuorumCertificate` in consensus.rs), `ConsensusMsg` (`ConsensusMsg` in
//! consensus_net.rs), `Block` (`Block` in sharding.rs). Replicated substructures that are empty
//! in the measured case (payload, cross_shard_out, shard_headers, QCs)
//! contribute only their framing bytes, which is exact for those cases.
//!
//! ```text
//! tx plain (Ed25519 64 B sig, empty payload)      176 B  (= 96 fixed + 72 sigvec + 8 payloadvec)
//! tx priority-bid envelope (80 B sig)              192 B
//! vote bare, Some(hash)                            153 B  (= 8+4+4+33+32+72)
//! vote bare, nil                                     121 B
//! vote Falcon hybrid envelope (746 B sig)           835 B  (= 8+4+4+33+32+(8+746); sig field = 16 magic + 64 Ed + 666 Falcon per `FALCON512_SIG_LEN` (post_quantum.rs), consensus.rs:214 VOTE_FALCON_PART_LEN)
//! ConsensusMsg::Vote, locked=None (live path)       158 B
//! ConsensusMsg::Vote, locked=Some                    190 B
//! QC(k Ed25519 sigs, refused under pure PQ) = 57 + 104*k B  (k=1:161, 4:473, 7:785, 10:1097, 100:10457)
//! µQC Falcon envelope = 73 + ceil(C/8) + s*670 B  (s sigs; 670 = 4 len + 666 Falcon; layout `PqMicroCertificate` (consensus.rs), formula pinned by pq_qc_sizes_vs_classical; C=4 full-sign: 2754, QC bincode 2851)
//! block fixed part (0 txs, 1 proposer sig, no QCs)  350 B
//! ConsensusMsg::Proposal(N) = 366 + 176*N B (16 B msg framing + 350 B header)
//!   N=0:366  N=1:542  N=100:17966  N=428:75694  N=1000:176366
//! Committed{100 txs, qc7} (classical baseline)    18747 B
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
//! ## 2b. QC bitfield (read-only, no wire change yet)
//! Live reality: the counted path stays `signatures: Vec<(ValidatorId,
//! Vec<u8>)>` = 57 + 104*k B. The design ADDS (no removal, no wire change
//! yet) a canonical bitfield alongside the list:
//! `bitfield: Vec<u8>`, `bit i` (LSB-first) = signer index `i` in the
//! canonical validator order (sorted `ValidatorId`, same order as
//! `ValidatorSet::proposer_for`'s explicit sort).
//! Trailing unused bits MUST be zero (fail-closed unpack, mirroring the
//! existing µQC `signers_bitmask` rule and the PQ envelope bitlen check).
//! Uses NOW: downtime attribution and
//! evidence compare bitfields without re-walking sig lists; the verifier
//! keeps counting the Ed25519 list.
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
//! packing heuristic (mempool.rs `estimate_tx_wire_bytes`), µQC bitmask certs
//! (`PqMicroCertificate::signers_bitmask` in consensus.rs), thin-proposal outbox dedup (main.rs:1320-1335).
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
//! QC bitfield hybrid: +ceil(C/8)+1 B overhead NOW (C=100: +14 B)
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

/// Bincode-1.3 overhead of `Block::cnvrf_v3 == None` (1-byte `Option::None` tag).
pub const CNVRF_V3_ABSENT_OVERHEAD_BYTES: usize = 1;

/// Bincode-1.3 overhead of an active CN-VRF v3 proposer reveal (`Option<[u8; 48]>::Some`:
/// 1-byte `Option::Some` tag + 48-byte BLAKE3-XOF reverse hash-chain link).
pub const CNVRF_V3_REVEAL_OVERHEAD_BYTES: usize = 1 + 48;

/// Bincode-1.3 size of a reveal-only `Some(CnVrfV3BlockPayload)` trailing field
/// (`1` outer `Option::Some` + `49` `reveal` + `8` empty `commits` len + `1` `epoch_vdf: None`).
pub const CNVRF_V3_REVEAL_PAYLOAD_BYTES: usize = 1 + CNVRF_V3_REVEAL_OVERHEAD_BYTES + 8 + 1;

/// Derive a 6-byte short-id: domain-separated BLAKE3 over
/// `b"STELL_COMPACT_SHORT_ID_V1" || salt || txid`, truncated to
/// `SHORT_ID_LEN` bytes.
pub fn short_id(txid: &[u8; 32], salt: &[u8; 32]) -> [u8; SHORT_ID_LEN] {
    let mut h = blake3::Hasher::new();
    h.update(b"STELL_COMPACT_SHORT_ID_V1");
    h.update(salt);
    h.update(txid);
    let digest = h.finalize();
    let mut out = [0u8; SHORT_ID_LEN];
    out.copy_from_slice(&digest.as_bytes()[..SHORT_ID_LEN]);
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

/// Unpack a bitfield; `None` on oversized `total` (`> COMPACT_QC_MAX_COMMITTEE * 16`),
/// length mismatch, OR any trailing unused bit set (fail-closed, mirrors the µQC
/// bitmask rule). All structural checks happen before allocating the output vector.
/// The round-trip `unpack(pack(x)) == Some(x)` holds for all bounded inputs.
pub fn unpack_bitfield(bits: &[u8], total: usize) -> Option<Vec<bool>> {
    if total > COMPACT_QC_MAX_COMMITTEE * 16 {
        return None;
    }
    if bits.len() != total.div_ceil(8) {
        return None;
    }
    // Trailing-bits-zero check before allocation: bits beyond `total` must be clear.
    let used_in_last = total % 8;
    if used_in_last != 0 {
        let mask = !((1u8 << used_in_last) - 1);
        if bits.last().is_some_and(|b| b & mask != 0) {
            return None;
        }
    }
    let mut out = Vec::with_capacity(total);
    for i in 0..total {
        out.push(bits[i / 8] & (1 << (i % 8)) != 0);
    }
    Some(out)
}

/// Baseline `ConsensusMsg::Proposal` bytes for `n_txs` plain txs
/// (measured: 366 + 176*N).
pub fn baseline_proposal_bytes(n_txs: usize) -> usize {
    PROPOSAL_FIXED_BYTES + n_txs * TX_PLAIN_BYTES
}

/// Compact proposal bytes: header + 6 B/short-id + full bytes for misses.
///
/// Note: pre-CN-VRF-v3 baseline header (`PROPOSAL_FIXED_BYTES = 366` /
/// `BLOCK_FIXED_BYTES = 350`) excludes the trailing `Block::cnvrf_v3` field; use
/// [`compact_proposal_bytes_with_cnvrf_v3`] and [`cnvrf_v3_header_overhead_bytes`]
/// to account for the `1 B` absent tag or `49 B` reveal (`59 B` reveal-only payload).
pub fn compact_proposal_bytes(n_txs: usize, n_missing: usize) -> usize {
    PROPOSAL_FIXED_BYTES + n_txs * SHORT_ID_LEN + n_missing * TX_PLAIN_BYTES
}

/// Trailing CN-VRF v3 header overhead in bincode-1.3 bytes (excluding commits and epoch VDF):
/// - `has_payload == false` (`cnvrf_v3: None`): `1 B` (`CNVRF_V3_ABSENT_OVERHEAD_BYTES`)
/// - `has_payload == true, has_reveal == true`: `59 B` (`CNVRF_V3_REVEAL_PAYLOAD_BYTES`,
///   where `49 B` = `CNVRF_V3_REVEAL_OVERHEAD_BYTES` is `Option<[u8; 48]>`)
/// - `has_payload == true, has_reveal == false`: `11 B` (`1 + 1 + 8 + 1`)
pub const fn cnvrf_v3_header_overhead_bytes(has_payload: bool, has_reveal: bool) -> usize {
    if !has_payload {
        CNVRF_V3_ABSENT_OVERHEAD_BYTES
    } else if has_reveal {
        CNVRF_V3_REVEAL_PAYLOAD_BYTES
    } else {
        1 + 1 + 8 + 1
    }
}

/// Compact proposal bytes including the trailing CN-VRF v3 payload framing/reveal overhead
/// (assuming 0 commits and no epoch VDF beacon).
pub const fn compact_proposal_bytes_with_cnvrf_v3(
    n_txs: usize,
    n_missing: usize,
    has_reveal: bool,
) -> usize {
    PROPOSAL_FIXED_BYTES
        + n_txs * SHORT_ID_LEN
        + n_missing * TX_PLAIN_BYTES
        + cnvrf_v3_header_overhead_bytes(has_reveal, has_reveal)
}

/// Classical-baseline QC bytes for `n_sigs` Ed25519 signatures (refused under
/// pure PQ; live path is the Falcon µQC envelope, see §1): 57 + 104*k.
pub fn qc_bytes_ed(n_sigs: usize) -> usize {
    QC_FIXED_BYTES + n_sigs * QC_ED_SIG_ENTRY_BYTES
}

// ---------------------------------------------------------------------------
// Compact µQC gossip envelope (FIRST WIRING — gated, see header).
//
// The live path gossips finality as `ConsensusMsg::Committed` carrying the
// full bincode `QuorumCertificate`: outer framing plus one 32-byte
// `ValidatorId` per signer. The compact frame carries the SAME certificate
// content bitfield-indexed instead: no per-signer ids, no outer struct
// framing. Verification is untouched — the receiver rebuilds the identical
// certificate and runs the unmodified `QuorumCertificate::verify`.
// ---------------------------------------------------------------------------

/// Wire magic of a compact-µQC gossip frame.
///
/// Distinct from every existing magic (`STELL_UQC_PQ_V5_` /
/// `STELL_QC_PQ_V5__` µQC envelopes, `PQ1`, `STDL` dandelion stem,
/// `MLKEM*`, `STX1/STD1/…` epoch seals): old software never emits this
/// prefix, and its bincode-only `ConsensusMsg::decode` fails closed on it
/// (unknown first bytes), so old nodes IGNORE the frame, never choke.
pub const COMPACT_QC_MAGIC: &[u8; 8] = b"STCMQC01";

/// Largest committee a compact frame may name.
///
/// Mirrors `MAX_COMMIT_CERT_SIGNERS` (`consensus.rs:194`): the bitmask and
/// the signature count are both bounded by it, so one frame can never pin a
/// decoder past what the verifier already accepts. This file stays `std`-only
/// (standalone `rustc --test`), hence the local mirror with citation instead
/// of an import.
pub const COMPACT_QC_MAX_COMMITTEE: usize = 4096;

/// Largest single signature a compact frame may carry.
///
/// New DoS bound (no live counterpart: the µQC envelope has no per-sig cap,
/// only the total-frame cap): Falcon-512 signatures are 666 B
/// (`FALCON512_SIG_LEN` in post_quantum.rs), so 2048 B admits the live
/// scheme with headroom while bounding per-sig allocation. Fail-closed:
/// larger sigs refuse the whole frame.
pub const COMPACT_QC_MAX_SIG_BYTES: usize = 2048;

/// Largest compact frame in bytes.
///
/// Mirrors `MAX_CONSENSUS_MSG` (`consensus_net.rs:71`): a gossip frame is
/// still a gossip frame, so the infnode 32 MiB frame cap applies unchanged.
/// Local mirror with citation (file stays `std`-only).
pub const COMPACT_QC_MAX_BYTES: usize = 32 * 1024 * 1024;

/// Falcon-512 wire signature length in bytes (`FALCON512_SIG_LEN` in post_quantum.rs).
/// Cited here so the size projector below stays honest about the live
/// signature width without importing the crate.
pub const COMPACT_QC_SIG_LEN_FALCON: usize = 666;

/// Vote-kind tags on the compact wire: 0 = Prevote, 1 = Precommit.
/// Mirrors `vote_kind_tag` (consensus_net.rs); anything else refuses.
pub const COMPACT_QC_KIND_PREVOTE: u8 = 0;
pub const COMPACT_QC_KIND_PRECOMMIT: u8 = 1;

/// A quorum certificate in compact gossip form: bitfield-indexed signers,
/// signatures only (no per-signer `ValidatorId`s, no bincode struct framing).
///
/// Field-for-field the content of the live `PqMicroCertificate` plus the
/// outer `QuorumCertificate` routing fields (`kind`, `block_hash`) needed to
/// rebuild a verifiable certificate on receipt. Plain owned data, no crate
/// deps (file stays `std`-only); `consensus_net` maps to/from the live types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactQc {
    pub height: u64,
    pub round: u32,
    /// 0 = Prevote, 1 = Precommit (`COMPACT_QC_KIND_*`).
    pub kind_tag: u8,
    pub block_hash: Option<[u8; 32]>,
    /// Raw `PqScheme::id()` (`post_quantum.rs:161`): 1 = Ed25519, 2 =
    /// Falcon512, 4 = Hybrid. Opaque here; `consensus_net` resolves it.
    pub scheme_id: u8,
    pub committee_size: u32,
    pub sortition_parent: [u8; 32],
    /// `ceil(committee_size / 8)` bytes, LSB-first, trailing bits zero
    /// (same rule as the µQC `signers_bitmask`).
    pub bitfield: Vec<u8>,
    /// Exactly one entry per SET bit (compact leg only — no sparse/full
    /// legs; anything else refuses fail-closed).
    pub signatures: Vec<Vec<u8>>,
}

/// Projected compact-frame bytes for a committee of `committee_size` with
/// `n_sigs` signatures of `sig_len` bytes each.
///
/// Layout: `MAGIC(8) || height(8) || round(4) || kind(1) || hash_flag(1) ||`
/// `hash(0|32) || scheme(1) || committee(4) || parent(32) || bitmask_len(4) ||`
/// `bitmask(ceil(C/8)) || sig_count(4) || n * (len(4) + sig)`.
/// The size test pins this projector against measured `encode_compact_qc`
/// output, so drift in either breaks the build loudly.
pub fn compact_qc_bytes(
    committee_size: usize,
    n_sigs: usize,
    sig_len: usize,
    has_hash: bool,
) -> usize {
    8 + 8
        + 4
        + 1
        + 1
        + if has_hash { 32 } else { 0 }
        + 1
        + 4
        + 32
        + 4
        + committee_size.div_ceil(8)
        + 4
        + n_sigs * (4 + sig_len)
}

/// Encode a compact QC gossip frame (canonical layout, see
/// [`compact_qc_bytes`]).
///
/// Fail-closed at encode: non-canonical inputs (`kind_tag > 1`,
/// `committee_size == 0` or over [`COMPACT_QC_MAX_COMMITTEE`], bitfield
/// length mismatch, trailing bits set, `signatures.len()` != set-bit count,
/// empty/oversized sigs, over [`COMPACT_QC_MAX_BYTES`]) return `Err` instead
/// of emitting a frame the decoder (or a peer) would refuse.
pub fn encode_compact_qc(qc: &CompactQc) -> Result<Vec<u8>, String> {
    if qc.kind_tag != COMPACT_QC_KIND_PREVOTE && qc.kind_tag != COMPACT_QC_KIND_PRECOMMIT {
        return Err("compact qc: bad kind tag".to_string());
    }
    if qc.committee_size == 0 || qc.committee_size as usize > COMPACT_QC_MAX_COMMITTEE {
        return Err("compact qc: bad committee size".to_string());
    }
    // Bitfield MUST be canonical: exact length + trailing bits zero. Reuses
    // `unpack_bitfield` (prototype §2b rule) as the validator.
    let present = unpack_bitfield(&qc.bitfield, qc.committee_size as usize)
        .ok_or_else(|| "compact qc: bad bitfield (length or trailing bits)".to_string())?;
    let set_bits = present.iter().filter(|&&b| b).count();
    // Compact leg only: exactly one signature per set bit.
    if qc.signatures.len() != set_bits {
        return Err("compact qc: sig count != set-bit count".to_string());
    }
    for sig in &qc.signatures {
        if sig.is_empty() || sig.len() > COMPACT_QC_MAX_SIG_BYTES {
            return Err("compact qc: bad signature length".to_string());
        }
    }
    let mut out = Vec::with_capacity(
        compact_qc_bytes(
            qc.committee_size as usize,
            qc.signatures.len(),
            qc.signatures.iter().map(|s| s.len()).max().unwrap_or(0),
            qc.block_hash.is_some(),
        )
        .max(8),
    );
    out.extend_from_slice(COMPACT_QC_MAGIC);
    out.extend_from_slice(&qc.height.to_le_bytes());
    out.extend_from_slice(&qc.round.to_le_bytes());
    out.push(qc.kind_tag);
    match &qc.block_hash {
        Some(h) => {
            out.push(1);
            out.extend_from_slice(h);
        }
        None => out.push(0),
    }
    out.push(qc.scheme_id);
    out.extend_from_slice(&qc.committee_size.to_le_bytes());
    out.extend_from_slice(&qc.sortition_parent);
    out.extend_from_slice(&(qc.bitfield.len() as u32).to_le_bytes());
    out.extend_from_slice(&qc.bitfield);
    out.extend_from_slice(&(qc.signatures.len() as u32).to_le_bytes());
    for sig in &qc.signatures {
        out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        out.extend_from_slice(sig);
    }
    if out.len() > COMPACT_QC_MAX_BYTES {
        return Err("compact qc: frame too large".to_string());
    }
    Ok(out)
}

/// Decode a compact QC gossip frame. `None` on ANY malformed input
/// (fail-closed): short buffers, wrong magic, out-of-range kind/hash flags,
/// bad committee size, bitfield length mismatch, set trailing bits, sig
/// count != set-bit count, empty/oversized sigs, truncation, OR trailing
/// bytes past the last signature.
pub fn decode_compact_qc(bytes: &[u8]) -> Option<CompactQc> {
    if bytes.len() < COMPACT_QC_MAGIC.len() || &bytes[..8] != COMPACT_QC_MAGIC {
        return None;
    }
    if bytes.len() > COMPACT_QC_MAX_BYTES {
        return None;
    }
    let mut cursor = 8usize;
    let take = |cursor: &mut usize, n: usize| -> Option<&[u8]> {
        if bytes.len() < *cursor + n {
            return None;
        }
        let s = &bytes[*cursor..*cursor + n];
        *cursor += n;
        Some(s)
    };
    let height = u64::from_le_bytes(take(&mut cursor, 8)?.try_into().ok()?);
    let round = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?);
    let kind_tag = *take(&mut cursor, 1)?.first()?;
    if kind_tag != COMPACT_QC_KIND_PREVOTE && kind_tag != COMPACT_QC_KIND_PRECOMMIT {
        return None;
    }
    let hash_flag = *take(&mut cursor, 1)?.first()?;
    let block_hash = match hash_flag {
        0 => None,
        1 => {
            let s = take(&mut cursor, 32)?;
            let mut h = [0u8; 32];
            h.copy_from_slice(s);
            Some(h)
        }
        _ => return None,
    };
    let scheme_id = *take(&mut cursor, 1)?.first()?;
    let committee_size = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?);
    if committee_size == 0 || committee_size as usize > COMPACT_QC_MAX_COMMITTEE {
        return None;
    }
    let sortition_parent: [u8; 32] = {
        let s = take(&mut cursor, 32)?;
        let mut p = [0u8; 32];
        p.copy_from_slice(s);
        p
    };
    let bitmask_len = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?) as usize;
    if bitmask_len != (committee_size as usize).div_ceil(8) {
        return None;
    }
    let bitfield = take(&mut cursor, bitmask_len)?.to_vec();
    // Canonical-bitfield rule (prototype §2b, via the prototype's own fn):
    // exact length (checked above) + trailing unused bits zero.
    let present = unpack_bitfield(&bitfield, committee_size as usize)?;
    let set_bits = present.iter().filter(|&&b| b).count();
    let sig_count = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?) as usize;
    // Compact leg only (mirrors the strict half of the µQC `is_compact`
    // check): sig count MUST equal the set-bit count.
    if sig_count != set_bits || sig_count > COMPACT_QC_MAX_COMMITTEE {
        return None;
    }
    let mut signatures = Vec::with_capacity(sig_count);
    for _ in 0..sig_count {
        let sig_len = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().ok()?) as usize;
        if sig_len == 0 || sig_len > COMPACT_QC_MAX_SIG_BYTES {
            return None;
        }
        signatures.push(take(&mut cursor, sig_len)?.to_vec());
    }
    // No trailing bytes (mirrors `ConsensusMsg::decode`'s
    // `reject_trailing_bytes`): padding must not ride along.
    if cursor != bytes.len() {
        return None;
    }
    Some(CompactQc {
        height,
        round,
        kind_tag,
        block_hash,
        scheme_id,
        committee_size,
        sortition_parent,
        bitfield,
        signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kat_short_id_vectors() {
        // Independent cross-check against keyed/domain-separated BLAKE3:
        // BLAKE3(b"STELL_COMPACT_SHORT_ID_V1" || salt || txid)[..6].
        let txid = [0x11u8; 32];
        let salt = [0x22u8; 32];
        let expected_salted = {
            let mut h = blake3::Hasher::new();
            h.update(b"STELL_COMPACT_SHORT_ID_V1");
            h.update(&salt);
            h.update(&txid);
            let mut buf = [0u8; SHORT_ID_LEN];
            buf.copy_from_slice(&h.finalize().as_bytes()[..SHORT_ID_LEN]);
            buf
        };
        assert_eq!(short_id(&txid, &salt), expected_salted);
        // Salt separation: same txid, zero salt differs.
        let zero = [0u8; 32];
        let expected_zero = {
            let mut h = blake3::Hasher::new();
            h.update(b"STELL_COMPACT_SHORT_ID_V1");
            h.update(&zero);
            h.update(&txid);
            let mut buf = [0u8; SHORT_ID_LEN];
            buf.copy_from_slice(&h.finalize().as_bytes()[..SHORT_ID_LEN]);
            buf
        };
        assert_eq!(short_id(&txid, &zero), expected_zero);
        assert_ne!(expected_salted, expected_zero);
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
        assert_eq!(pack_bitfield(&[false; 8]), vec![0x00]);
        assert_eq!(pack_bitfield(&[true; 8]), vec![0xff]);
        // 100-validator committee, first 7 sign => 13 bytes, byte0 = 0x7f.
        let mut c = vec![false; 100];
        for b in c.iter_mut().take(7) {
            *b = true;
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
        // Oversized `total` fails closed before allocation (OOM guard).
        let over_cap = COMPACT_QC_MAX_COMMITTEE * 16 + 1;
        let over_bytes = vec![0u8; over_cap.div_ceil(8)];
        assert_eq!(unpack_bitfield(&over_bytes, over_cap), None);
        assert_eq!(unpack_bitfield(&[], usize::MAX), None);
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
        // Savings are real and large: compact(1000,0) < 4% of baseline.
        assert!(compact_proposal_bytes(1000, 0) * 100 < baseline_proposal_bytes(1000) * 4);
    }

    #[test]
    fn cnvrf_v3_header_overhead_accounting() {
        assert_eq!(CNVRF_V3_ABSENT_OVERHEAD_BYTES, 1);
        assert_eq!(CNVRF_V3_REVEAL_OVERHEAD_BYTES, 49);
        assert_eq!(CNVRF_V3_REVEAL_PAYLOAD_BYTES, 59);
        assert_eq!(cnvrf_v3_header_overhead_bytes(false, false), 1);
        assert_eq!(cnvrf_v3_header_overhead_bytes(true, false), 11);
        assert_eq!(cnvrf_v3_header_overhead_bytes(true, true), 59);
        assert_eq!(
            compact_proposal_bytes_with_cnvrf_v3(100, 0, false),
            compact_proposal_bytes(100, 0) + 1
        );
        assert_eq!(
            compact_proposal_bytes_with_cnvrf_v3(100, 0, true),
            compact_proposal_bytes(100, 0) + 59
        );
    }

    /// Deterministic 64-seat compact-QC fixture (structural only — signature
    /// bytes are patterned filler, NOT crypto; verification stays in
    /// `QuorumCertificate::verify` and is never exercised here).
    fn fixture_64_seat(all_sign: bool) -> CompactQc {
        let mut signers = vec![false; 64];
        if all_sign {
            for b in signers.iter_mut() {
                *b = true;
            }
        } else {
            // Quorum of a uniform 64-seat committee: floor(2*64/3)+1 = 43.
            for b in signers.iter_mut().take(43) {
                *b = true;
            }
        }
        let n = signers.iter().filter(|&&b| b).count();
        CompactQc {
            height: 900,
            round: 3,
            kind_tag: COMPACT_QC_KIND_PRECOMMIT,
            block_hash: Some([0xABu8; 32]),
            scheme_id: 2, // Falcon512 (`post_quantum.rs:161`).
            committee_size: 64,
            sortition_parent: [0x77u8; 32],
            bitfield: pack_bitfield(&signers),
            signatures: (0..n)
                .map(|i| vec![(i as u8).wrapping_mul(7).wrapping_add(1); COMPACT_QC_SIG_LEN_FALCON])
                .collect(),
        }
    }

    #[test]
    fn compact_qc_round_trip() {
        for qc in [fixture_64_seat(true), fixture_64_seat(false)] {
            let bytes = encode_compact_qc(&qc).expect("fixture must encode");
            assert_eq!(
                bytes.len(),
                compact_qc_bytes(64, qc.signatures.len(), COMPACT_QC_SIG_LEN_FALCON, true),
                "projector must match measured bytes exactly"
            );
            let back = decode_compact_qc(&bytes).expect("must decode");
            assert_eq!(back, qc);
        }
        // Nil-hash (prevote) frame round-trips too.
        let mut nil = fixture_64_seat(false);
        nil.block_hash = None;
        nil.kind_tag = COMPACT_QC_KIND_PREVOTE;
        let bytes = encode_compact_qc(&nil).expect("nil frame must encode");
        assert_eq!(
            bytes.len(),
            compact_qc_bytes(64, 43, COMPACT_QC_SIG_LEN_FALCON, false)
        );
        assert_eq!(decode_compact_qc(&bytes).expect("must decode"), nil);
    }

    #[test]
    fn compact_qc_tamper_refusal() {
        let qc = fixture_64_seat(true);
        let good = encode_compact_qc(&qc).expect("fixture must encode");
        // Baseline sanity.
        assert!(decode_compact_qc(&good).is_some());
        // Wrong magic (old/new interop: no magic, no parse).
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 0xFF;
        assert_eq!(decode_compact_qc(&bad_magic), None);
        assert_eq!(decode_compact_qc(&[]), None);
        assert_eq!(decode_compact_qc(&good[..7]), None);
        // Every truncation refuses.
        for n in [8usize, 20, 60, 100, 1000] {
            assert_eq!(
                decode_compact_qc(&good[..n.min(good.len() - 1)]),
                None,
                "truncation to {n} must refuse"
            );
        }
        // Trailing byte refuses (no padding rides along).
        let mut padded = good.clone();
        padded.push(0x00);
        assert_eq!(decode_compact_qc(&padded), None);
        // Bad kind / hash flags refuse.
        let mut bad_kind = good.clone();
        bad_kind[8 + 8 + 4] = 2;
        assert_eq!(decode_compact_qc(&bad_kind), None);
        let mut bad_flag = good.clone();
        bad_flag[8 + 8 + 4 + 1] = 2;
        assert_eq!(decode_compact_qc(&bad_flag), None);
        // Trailing bit set in the bitfield refuses (64 seats: no spare bits,
        // so corrupt the length prefix instead: bitmask_len 8 -> 9).
        let bitlen_off = 8 + 8 + 4 + 1 + 1 + 32 + 1 + 4 + 32;
        let mut bad_len = good.clone();
        bad_len[bitlen_off] = 9;
        assert_eq!(decode_compact_qc(&bad_len), None);
        // Non-multiple-of-8 committee exercises the trailing-bit rule: build
        // a 10-seat frame, then set bit 10 (first out-of-range bit).
        let mut s10 = vec![false; 10];
        s10[0] = true;
        s10[9] = true;
        let qc10 = CompactQc {
            height: 1,
            round: 0,
            kind_tag: COMPACT_QC_KIND_PREVOTE,
            block_hash: None,
            scheme_id: 2,
            committee_size: 10,
            sortition_parent: [0u8; 32],
            bitfield: pack_bitfield(&s10),
            signatures: vec![vec![1u8; 64], vec![2u8; 64]],
        };
        let mut b10 = encode_compact_qc(&qc10).expect("10-seat must encode");
        // Bitfield starts after magic(8)+height(8)+round(4)+kind(1)+flag(1)+
        // scheme(1)+committee(4)+parent(32)+len(4) = 63; byte 1 bit 2 = index 10.
        b10[63 + 1] |= 1 << 2;
        assert_eq!(decode_compact_qc(&b10), None);
        // Sig count != set-bit count refuses.
        let mut qc_mismatch = qc.clone();
        qc_mismatch.signatures.pop();
        assert!(encode_compact_qc(&qc_mismatch).is_err());
        // Empty / oversized sigs refuse at encode.
        let mut qc_empty_sig = qc.clone();
        qc_empty_sig.signatures[0].clear();
        assert!(encode_compact_qc(&qc_empty_sig).is_err());
        let mut qc_big_sig = qc.clone();
        qc_big_sig.signatures[0] = vec![0u8; COMPACT_QC_MAX_SIG_BYTES + 1];
        assert!(encode_compact_qc(&qc_big_sig).is_err());
        // Bad committee sizes refuse at encode.
        let mut qc_zero = qc.clone();
        qc_zero.committee_size = 0;
        qc_zero.bitfield = vec![];
        qc_zero.signatures = vec![];
        assert!(encode_compact_qc(&qc_zero).is_err());
        let mut qc_huge = qc.clone();
        qc_huge.committee_size = COMPACT_QC_MAX_COMMITTEE as u32 + 1;
        assert!(encode_compact_qc(&qc_huge).is_err());
        let mut qc_kind = qc.clone();
        qc_kind.kind_tag = 7;
        assert!(encode_compact_qc(&qc_kind).is_err());
    }

    #[test]
    fn compact_qc_size_64_seat_savings() {
        // 64 seats, full-sign, Falcon-512 sigs, block hash present — the live
        // finality shape (µQC over the whole set).
        let qc = fixture_64_seat(true);
        let measured = encode_compact_qc(&qc).expect("fixture must encode").len();
        // Fixed overhead: 8+8+4+1+1+32+1+4+32+4+8+4 = 107; sigs 64*(4+666).
        assert_eq!(measured, 107 + 64 * (4 + COMPACT_QC_SIG_LEN_FALCON));
        assert_eq!(measured, 42987);
        assert_eq!(
            measured,
            compact_qc_bytes(64, 64, COMPACT_QC_SIG_LEN_FALCON, true)
        );
        // Quorum-sign (43 of 64) frame is smaller still.
        let q43 = fixture_64_seat(false);
        let m43 = encode_compact_qc(&q43).expect("must encode").len();
        assert_eq!(m43, 107 + 43 * (4 + COMPACT_QC_SIG_LEN_FALCON));
        assert_eq!(m43, 28917);
        assert!(m43 < measured);
    }
}
