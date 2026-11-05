//! Silent payments (PQ, non-interactive stealth from a one-time on-chain KEM key). UNWIRED.
//!
//! UNWIRED: this file is NOT declared in `lib.rs` (`mod silentpay` does not
//! exist) and NOTHING in production calls it. The `_test-only-later` posture
//! follows the `mev_pq_plan.rs` precedent: to run the KATs without touching
//! `lib.rs`, the integration test includes this file by path
//! (`tests/silentpay_tests.rs`: `#[path = "../src/silentpay.rs"] mod silentpay;`).
//! To wire it for real, the lead adds `#[cfg(test)] mod silentpay;` to
//! `lib.rs` (never a production `mod` before audit) and re-runs the gates.
//! No new dependencies: `ml-kem` (already vendored, `Cargo.toml:59`) + `std`
//! only. The SHAKE-256 sponge below is a self-contained copy of the tree
//! sponge (`post_quantum.rs:573` `keccak_f1600`, absorb/squeeze shape of
//! `cn_vrf.rs:118` `shake256_32`); it is pinned against the NIST vectors in
//! the test file, exactly like `post_quantum.rs:2143` and `hashpool.rs`.
//!
//! # Construction (PQ silent payments WITHOUT interaction or ZK)
//!
//! All primitives already exist in-tree; this file only composes KEM + SHAKE +
//! Falcon-512 (caller-supplied verifier):
//!
//! 1. STEALTH (hash+KEM, no DH group). The recipient publishes ONE ML-KEM-768
//!    encapsulation key (the `pq_registry.rs:492` `get_active_key` read shape —
//!    but this module imports NOTHING from `pq_registry` or `consensus`: the
//!    caller passes the raw `ek_bytes`, exactly 1184 B). The sender runs
//!    `sp_send` (the `from_seed` / `encapsulate_deterministic` / `decapsulate`
//!    idiom pinned in `infnode/crates/infnode/tests/kem_kat_tests.rs:139-177`
//!    and mirrored in `mev_epoch.rs:1365`): encap to `ek_bytes` with explicit
//!    32-byte randomness `m` yields `(ct, ss)`, and the stealth address is
//!    `SHAKE256(SP_STEALTH_DST || chain_be64 || chain_state || ss || index_be64)`.
//!    The recipient scans by decapsulation trial (`SpRecipient::receive`):
//!    decap `ct` with its seed, re-derive with its CURRENT `(chain, index)`,
//!    compare. Only the true recipient's `ss` reproduces the address.
//!
//! 2. NOTES (hash commitments, NO Merkle paths). With `chain_id: u64`,
//!    `value: u64`, `blinding: [u8; 32]`, `stealth: [u8; 32]`, `serial: [u8; 32]`:
//!    `C  = SHAKE256("STELL_HP_COMMIT_V1" || chain_be64 || value_be64 || blinding || stealth)`
//!    `Nf = SHAKE256("STELL_HP_NULL_V1"  || serial)`.
//!    The domain tags are BYTE-IDENTICAL to `hashpool.rs:113-117`
//!    (`HP_COMMIT_DST` / `HP_NULL_DST`) — same tags, no forks; the cross-verify
//!    KAT in `tests/silentpay_tests.rs` asserts output equality with
//!    `hashpool::note_commit` / `hashpool::note_nullifier` on shared inputs.
//!    The pool is `map C -> (stealth, Nf_expected)` plus a spent set of `Nf`.
//!    Spend reveals exactly `(serial, value, blinding)`; the verifier
//!    recomputes `C` with the STORED stealth, checks `C` present, checks
//!    `Nf(serial) == stored Nf` (serial bound at deposit), checks `Nf`
//!    unspent, then marks it spent. A Falcon-512 owner signature over
//!    `sp_spend_sig_msg` additionally authorizes the spend (`spend_signed`);
//!    production passes `post_quantum.rs:521`
//!    `verify_pq_signature(PqScheme::Falcon512, …)` as the closure.
//!
//! 3. FORWARD-SECRET ratchet. Each recipient holds `(chain, next_index)`.
//!    Genesis is `SP_GENESIS_CHAIN` (all zeros); the address preimage commits
//!    to the CURRENT chain state, and every received note steps
//!    `chain <- SHAKE256(SP_CHAIN_DST || chain || ss)` and `index += 1`.
//!    Sender and recipient advance their mirrors in lockstep per delivered
//!    note (see LIMITATION below). A leaked note key (`ss_i`, `blinding_i`,
//!    `serial_i`) plus the chain state at `i` yields the successor chain
//!    `chain_{i+1}` by forward recomputation — but yields NO other note:
//!    earlier chains are preimages (one-way), later chains need later `ss`
//!    values (decap needs the recipient seed), and every other stealth binds
//!    a `(chain, ss, index)` triple the attacker cannot assemble. The FS game
//!    KAT proves the full compromise matrix misses on fixed fixtures.
//!
//! # Lockstep LIMITATION (read before wiring)
//!
//! The sender's `(chain, index)` mirror must match the recipient's state for
//! the note being sent; lost or reordered notes desynchronize the pair (the
//! recipient's scan then misses — detectable, fail-closed, never a false
//! accept). Resync (out-of-band counter, trial window) is OUT OF SCOPE for
//! this prototype: this file pins the SHAPE (chain-bound addresses, FS game,
//! nullifier reuse), not a transport.
//!
//! # Privacy LIMITATION (read before wiring)
//!
//! Same operator model as `hashpool.rs:66-81`: the pool operator learns the
//! `value` (and `blinding`, `stealth`) of every note AT SPEND TIME. Privacy
//! here is recipient UNLINKABILITY via fresh chain-bound stealth addresses
//! per note, NOT amount hiding.
//!
//! # Exact byte layouts (frozen by the KATs)
//!
//! * stealth preimage: `SP_STEALTH_DST || chain_id u64-BE || chain(32) || ss(32) || index u64-BE` (99 B)
//! * chain-step preimage: `SP_CHAIN_DST || prev_chain(32) || ss(32)` (85 B)
//! * commit preimage:  `HP_COMMIT_DST || chain u64-BE || value u64-BE || blinding(32) || stealth(32)` (103 B, hashpool-identical)
//! * null preimage:    `HP_NULL_DST   || serial(32)` (53 B, hashpool-identical)
//! * spend-sig preimage: `SP_SPEND_DST || chain u64-BE || commitment(32) || nullifier(32)` (89 B)
//!
//! # Purity contract
//!
//! This module imports NOTHING from `consensus`, `staking`, `pq_registry`,
//! `post_quantum`, or any wallet/runtime module. `chain_id` is a `u64` param,
//! recipient keys are `&[u8]` params, Falcon verification is a caller-supplied
//! `Fn(&[u8] pk, &[u8] msg, &[u8] sig) -> bool` closure. Key lookups ("which
//! recipient owns this note") are caller-side decap trials, never resolved
//! here.

use std::collections::{BTreeMap, BTreeSet};

use ml_kem::{
    EncapsulationKey768, MlKem768,
    kem::{Decapsulate, FromSeed, Key},
};

// ---------------------------------------------------------------------------
// Domains + sizes
// ---------------------------------------------------------------------------

/// Domain separator of the silent-payment stealth-address preimage.
pub const SP_STEALTH_DST: &[u8] = b"STELL_SP_STEALTH_V1";
/// Domain separator of the forward-secret chain-step preimage.
pub const SP_CHAIN_DST: &[u8] = b"STELL_SP_CHAIN_V1";
/// Domain separator of the Falcon owner-signature message authorizing a spend.
pub const SP_SPEND_DST: &[u8] = b"STELL_SP_SPEND_V1";

/// Domain separator of the note-commitment preimage — BYTE-IDENTICAL to
/// `hashpool.rs` `HP_COMMIT_DST`. Same tags, no forks: silent-payment notes
/// are HashPool-shaped notes by construction.
pub const SP_COMMIT_DST: &[u8] = b"STELL_HP_COMMIT_V1";
/// Domain separator of the nullifier preimage — BYTE-IDENTICAL to
/// `hashpool.rs` `HP_NULL_DST`. Same tags, no forks.
pub const SP_NULL_DST: &[u8] = b"STELL_HP_NULL_V1";

/// Genesis chain state: all zeros. The `chain_id` binding lives in the
/// stealth-address preimage, so distinct chains never share addresses even
/// from the same genesis.
pub const SP_GENESIS_CHAIN: [u8; 32] = [0u8; 32];

/// ML-KEM-768 encapsulation key length (FIPS 203).
pub const SP_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length (FIPS 203).
pub const SP_CT_LEN: usize = 1088;
/// ML-KEM-768 shared-secret length (FIPS 203).
pub const SP_SS_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Errors (fail-closed refusals)
// ---------------------------------------------------------------------------

/// Fail-closed refusal for a silent-payment operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpError {
    /// Encapsulation key is the wrong length or malformed.
    BadEncapsulationKey,
    /// Ciphertext is the wrong length or malformed.
    BadCiphertext,
    /// Commitment already registered (deposit) — no double registration.
    DuplicateDeposit,
    /// Recomputed commitment does not match the claimed one.
    CommitmentMismatch,
    /// Revealed serial does not match the nullifier bound at deposit.
    SerialMismatch,
    /// Nullifier already spent.
    AlreadySpent,
    /// Commitment not present in the pool.
    UnknownCommitment,
    /// A Falcon owner signature did not verify.
    BadSignature,
}

impl std::fmt::Display for SpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpError::BadEncapsulationKey => write!(f, "bad ML-KEM encapsulation key"),
            SpError::BadCiphertext => write!(f, "bad ML-KEM ciphertext"),
            SpError::DuplicateDeposit => write!(f, "commitment already deposited"),
            SpError::CommitmentMismatch => write!(f, "opening does not recompute the commitment"),
            SpError::SerialMismatch => {
                write!(f, "revealed serial does not match the bound nullifier")
            }
            SpError::AlreadySpent => write!(f, "nullifier already spent"),
            SpError::UnknownCommitment => write!(f, "commitment not in pool"),
            SpError::BadSignature => write!(f, "owner signature did not verify"),
        }
    }
}

impl std::error::Error for SpError {}

// ---------------------------------------------------------------------------
// SHAKE-256 (self-contained tree sponge copy; see file header)
// ---------------------------------------------------------------------------

fn sp_keccak_f1600(state: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    const ROTC: [[u32; 5]; 5] = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ];

    let mut a = [[0u64; 5]; 5];
    for x in 0..5 {
        for y in 0..5 {
            a[x][y] = state[x + 5 * y];
        }
    }

    for &rc in RC.iter() {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for slot in a[x].iter_mut() {
                *slot ^= d[x];
            }
        }

        let mut b = [[0u64; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                b[y][(2 * x + 3 * y) % 5] = a[x][y].rotate_left(ROTC[x][y]);
            }
        }

        for x in 0..5 {
            for y in 0..5 {
                a[x][y] = b[x][y] ^ ((!b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);
            }
        }

        a[0][0] ^= rc;
    }

    for x in 0..5 {
        for y in 0..5 {
            state[x + 5 * y] = a[x][y];
        }
    }
}

/// SHAKE-256 XOF squeeze over `data` (136-byte rate, `0x1F` pad, `0x80` final
/// bit — the same sponge as `cn_vrf.rs:126` `shake256_xof`).
pub fn sp_shake256(data: &[u8], out: &mut [u8]) {
    const RATE: usize = 136;
    const WORDS: usize = RATE / 8;
    let mut state = [0u64; 25];
    let mut offset = 0;
    while offset + RATE <= data.len() {
        for (word, chunk) in state
            .iter_mut()
            .take(WORDS)
            .zip(data[offset..offset + RATE].chunks_exact(8))
        {
            let bytes: [u8; 8] = chunk.try_into().expect("chunks_exact(8) yields 8 bytes");
            *word ^= u64::from_le_bytes(bytes);
        }
        sp_keccak_f1600(&mut state);
        offset += RATE;
    }
    let mut block = [0u8; RATE];
    let rem = data.len() - offset;
    block[..rem].copy_from_slice(&data[offset..]);
    block[rem] = 0x1F;
    block[RATE - 1] |= 0x80;
    for (word, chunk) in state.iter_mut().take(WORDS).zip(block.chunks_exact(8)) {
        let bytes: [u8; 8] = chunk.try_into().expect("chunks_exact(8) yields 8 bytes");
        *word ^= u64::from_le_bytes(bytes);
    }
    sp_keccak_f1600(&mut state);
    let mut done = 0;
    while done < out.len() {
        for word in state.iter().take(WORDS) {
            if done >= out.len() {
                return;
            }
            let bytes = word.to_le_bytes();
            let take = core::cmp::min(8, out.len() - done);
            out[done..done + take].copy_from_slice(&bytes[..take]);
            done += take;
        }
        if done < out.len() {
            sp_keccak_f1600(&mut state);
        }
    }
}

/// SHAKE-256 squeeze of exactly 32 bytes.
pub fn sp_shake256_32(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    sp_shake256(data, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Forward-secret chain + stealth addresses (KEM + hash, no DH group)
// ---------------------------------------------------------------------------

/// Step the forward-secret chain:
/// `SHAKE256(SP_CHAIN_DST || prev_chain || ss)`. One-way: `prev_chain` is not
/// recoverable from the output (preimage resistance of the sponge).
pub fn sp_chain_step(prev_chain: &[u8; 32], ss: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(SP_CHAIN_DST.len() + 32 + 32);
    pre.extend_from_slice(SP_CHAIN_DST);
    pre.extend_from_slice(prev_chain);
    pre.extend_from_slice(ss);
    sp_shake256_32(&pre)
}

/// Derive a stealth address bound to the chain state, the KEM shared secret,
/// and the per-recipient note index:
/// `SHAKE256(SP_STEALTH_DST || chain_id_be64 || chain || ss || index_be64)`.
pub fn sp_stealth_address(
    chain_id: u64,
    chain: &[u8; 32],
    ss: &[u8; 32],
    index: u64,
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(SP_STEALTH_DST.len() + 8 + 32 + 32 + 8);
    pre.extend_from_slice(SP_STEALTH_DST);
    pre.extend_from_slice(&chain_id.to_be_bytes());
    pre.extend_from_slice(chain);
    pre.extend_from_slice(ss);
    pre.extend_from_slice(&index.to_be_bytes());
    sp_shake256_32(&pre)
}

/// A sent silent-payment note: the KEM ciphertext (published on-chain), the
/// sender-observed shared secret (kept by the sender mirror to step its chain
/// copy), the stealth address (published on-chain), and the stepped chain
/// (the sender mirror adopts this as its new state — lockstep discipline).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpNote {
    /// ML-KEM-768 ciphertext bytes (1088 B).
    pub ct: Vec<u8>,
    /// KEM shared secret observed by the sender (steps the sender's chain).
    pub ss: [u8; 32],
    /// Stealth address the recipient will re-derive on scan.
    pub stealth: [u8; 32],
    /// `sp_chain_step(chain, &ss)` — the sender's next chain state.
    pub next_chain: [u8; 32],
}

/// Encapsulate to a recipient's one-time-published ML-KEM-768 key and derive
/// the chain-bound stealth address for the CURRENT `(chain, index)` pair.
///
/// `ek_bytes` is the recipient's published 1184-byte encapsulation key;
/// `chain`/`index` are the sender mirror's view of the recipient state;
/// `randomness` is the explicit KEM `m` (production: fresh OS bytes; tests:
/// fixed vectors for determinism). Returns the note; the caller adopts
/// `note.next_chain` and increments its index mirror on delivery.
pub fn sp_send(
    ek_bytes: &[u8],
    chain_id: u64,
    chain: &[u8; 32],
    index: u64,
    randomness: &[u8; 32],
) -> Result<SpNote, SpError> {
    if ek_bytes.len() != SP_EK_LEN {
        return Err(SpError::BadEncapsulationKey);
    }
    let key =
        Key::<EncapsulationKey768>::try_from(ek_bytes).map_err(|_| SpError::BadEncapsulationKey)?;
    let ek = EncapsulationKey768::new(&key).map_err(|_| SpError::BadEncapsulationKey)?;
    let m: ml_kem::B32 = (*randomness).into();
    let (ct, ss) = ek.encapsulate_deterministic(&m);
    let mut ss32 = [0u8; SP_SS_LEN];
    ss32.copy_from_slice(ss.as_slice());
    let stealth = sp_stealth_address(chain_id, chain, &ss32, index);
    let next_chain = sp_chain_step(chain, &ss32);
    Ok(SpNote { ct: ct.as_slice().to_vec(), ss: ss32, stealth, next_chain })
}

/// What an attacker holding a compromised `(chain, ss)` pair (a leaked note
/// key plus the chain state at that note) can compute for a guessed index:
/// the stealth address that pair would yield. The FS game KAT asserts this
/// NEVER equals any other note's real address — the attacker's best
/// reconstruction misses everywhere (advantage zero on fixed fixtures).
pub fn sp_attacker_rebuild(
    chain_id: u64,
    leaked_chain: &[u8; 32],
    leaked_ss: &[u8; 32],
    index_guess: u64,
) -> [u8; 32] {
    sp_stealth_address(chain_id, leaked_chain, leaked_ss, index_guess)
}

/// A received note as observed by the recipient: the decapsulated shared
/// secret (steps the recipient chain), the matched stealth address, and the
/// index it was received at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpReceipt {
    /// Decapsulated KEM shared secret.
    pub ss: [u8; 32],
    /// Matched stealth address.
    pub stealth: [u8; 32],
    /// Per-recipient note index this receipt consumed.
    pub index: u64,
    /// `sp_chain_step(chain, &ss)` — the recipient's next chain state.
    pub next_chain: [u8; 32],
}

/// Silent-payment recipient: the KEM seed (scan capability), the chain it is
/// bound to, and the forward-secret receive state `(chain, next_index)`.
///
/// Trial-receive `receive(ct, claimed_stealth)`: decap `ct` with the seed
/// (FIPS 203 implicit rejection — a tampered `ct` yields the fallback key,
/// hence a non-matching stealth, never an error), re-derive the address with
/// the CURRENT `(chain, next_index)`, compare. On match: step
/// `(chain, next_index)` and return the receipt. On mismatch: state is
/// untouched (`None`). Wrong-length `ct` is refused outright.
#[derive(Clone, Debug)]
pub struct SpRecipient {
    seed: [u8; 64],
    chain_id: u64,
    chain: [u8; 32],
    next_index: u64,
}

impl SpRecipient {
    /// Fresh recipient: genesis chain, index zero.
    pub fn new(seed: [u8; 64], chain_id: u64) -> Self {
        Self { seed, chain_id, chain: SP_GENESIS_CHAIN, next_index: 0 }
    }

    /// Current chain state (exposed for the FS game KATs).
    pub fn chain(&self) -> [u8; 32] {
        self.chain
    }

    /// Next expected per-recipient note index (exposed for the KATs).
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Trial-receive one candidate note. See the struct-level docs.
    pub fn receive(
        &mut self,
        ct: &[u8],
        claimed_stealth: &[u8; 32],
    ) -> Result<Option<SpReceipt>, SpError> {
        if ct.len() != SP_CT_LEN {
            return Err(SpError::BadCiphertext);
        }
        let seed: ml_kem::Seed = self.seed.into();
        let (dk, _) = MlKem768::from_seed(&seed);
        let kem_ct: ml_kem::kem::Ciphertext<MlKem768> =
            ct.try_into().map_err(|_| SpError::BadCiphertext)?;
        let ss = dk.decapsulate(&kem_ct);
        let mut ss32 = [0u8; SP_SS_LEN];
        ss32.copy_from_slice(ss.as_slice());
        let derived = sp_stealth_address(self.chain_id, &self.chain, &ss32, self.next_index);
        if &derived != claimed_stealth {
            return Ok(None);
        }
        let receipt = SpReceipt {
            ss: ss32,
            stealth: derived,
            index: self.next_index,
            next_chain: sp_chain_step(&self.chain, &ss32),
        };
        self.chain = receipt.next_chain;
        self.next_index = self.next_index.wrapping_add(1);
        Ok(Some(receipt))
    }
}

// ---------------------------------------------------------------------------
// Notes: commitments (HashPool-identical shape) + nullifiers
// ---------------------------------------------------------------------------

/// Note commitment — HashPool-identical shape and tag:
/// `SHAKE256(SP_COMMIT_DST || chain_be64 || value_be64 || blinding || stealth)`
/// where `SP_COMMIT_DST == HP_COMMIT_DST` byte-for-byte (same tags, no forks).
pub fn sp_commit(
    chain_id: u64,
    value: u64,
    blinding: &[u8; 32],
    stealth: &[u8; 32],
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(SP_COMMIT_DST.len() + 8 + 8 + 32 + 32);
    pre.extend_from_slice(SP_COMMIT_DST);
    pre.extend_from_slice(&chain_id.to_be_bytes());
    pre.extend_from_slice(&value.to_be_bytes());
    pre.extend_from_slice(blinding);
    pre.extend_from_slice(stealth);
    sp_shake256_32(&pre)
}

/// Note nullifier — HashPool-identical shape and tag:
/// `SHAKE256(SP_NULL_DST || serial)` with `SP_NULL_DST == HP_NULL_DST`.
pub fn sp_nullifier(serial: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(SP_NULL_DST.len() + 32);
    pre.extend_from_slice(SP_NULL_DST);
    pre.extend_from_slice(serial);
    sp_shake256_32(&pre)
}

/// Owner-signature message authorizing a spend:
/// `SHAKE256(SP_SPEND_DST || chain_be64 || commitment || nullifier)`.
/// Binds the exact note and the exact nullifier being released, so a
/// signature cannot be replayed onto a different note or chain.
pub fn sp_spend_sig_msg(
    chain_id: u64,
    commitment: &[u8; 32],
    nullifier: &[u8; 32],
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(SP_SPEND_DST.len() + 8 + 32 + 32);
    pre.extend_from_slice(SP_SPEND_DST);
    pre.extend_from_slice(&chain_id.to_be_bytes());
    pre.extend_from_slice(commitment);
    pre.extend_from_slice(nullifier);
    sp_shake256_32(&pre)
}

// ---------------------------------------------------------------------------
// Pool: map C -> (stealth, bound nullifier) + spent set (HashPool semantics)
// ---------------------------------------------------------------------------

/// A deposited note as stored by the operator: the stealth address (public at
/// deposit) and the nullifier bound at deposit (revealed at spend). The value
/// and blinding are NEVER stored — they stay hidden until the spender reveals
/// the opening. Same shape as `hashpool.rs` `StoredNote`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpStoredNote {
    /// Stealth address the commitment was registered under (public).
    pub stealth: [u8; 32],
    /// Nullifier bound at deposit: only a spend revealing the preimage
    /// `serial` with `sp_nullifier(serial) == nullifier` releases the note.
    pub nullifier: [u8; 32],
}

/// Silent-payment pool: membership by recomputation, no Merkle paths (same
/// operator model and privacy limitation as `hashpool.rs`).
#[derive(Clone, Debug, Default)]
pub struct SpPool {
    chain_id: u64,
    notes: BTreeMap<[u8; 32], SpStoredNote>,
    spent: BTreeSet<[u8; 32]>,
}

/// Caller-supplied Falcon owner-signature verifier: `verify(pk, msg, sig)`.
/// Production passes `post_quantum::verify_pq_signature` partially applied to
/// `PqScheme::Falcon512`; tests pass the same function directly.
pub type SpVerify<'a> = &'a dyn Fn(&[u8], &[u8], &[u8]) -> bool;

/// A Falcon-authorized spend request: the revealed note opening
/// (`commitment`, `serial`, `value`, `blinding` — same shape as the
/// `hashpool.rs` `SpendOpening`, minus `stealth` which the pool resolves
/// from storage instead) plus the owner's Falcon-512 `(pk, sig)` over
/// [`sp_spend_sig_msg`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpSpendAuth {
    /// Claimed commitment (must recompute from the opening + stored stealth).
    pub commitment: [u8; 32],
    /// Note serial (preimage of the bound nullifier).
    pub serial: [u8; 32],
    /// Note value.
    pub value: u64,
    /// Note blinding.
    pub blinding: [u8; 32],
    /// Owner Falcon-512 public key bytes (opaque here; the verify closure
    /// enforces the scheme + length).
    pub owner_pk: Vec<u8>,
    /// Owner signature over [`sp_spend_sig_msg`] for this exact spend.
    pub owner_sig: Vec<u8>,
}

impl SpPool {
    /// Empty pool bound to `chain_id` (commitments bind the chain id, so a
    /// pool only admits notes for its own chain).
    pub fn new(chain_id: u64) -> Self {
        Self { chain_id, notes: BTreeMap::new(), spent: BTreeSet::new() }
    }

    /// Chain id this pool is bound to.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Number of deposited commitments.
    pub fn len(&self) -> usize {
        self.notes.len()
    }

    /// True when no commitment has been deposited.
    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }

    /// Number of spent nullifiers.
    pub fn spent_len(&self) -> usize {
        self.spent.len()
    }

    /// True when `commitment` is registered.
    pub fn contains(&self, commitment: &[u8; 32]) -> bool {
        self.notes.contains_key(commitment)
    }

    /// True when `nullifier` has been spent.
    pub fn is_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.spent.contains(nullifier)
    }

    /// Register a deposit `(commitment, stealth, nullifier)`. The caller
    /// computed `commitment = sp_commit(chain, value, blinding, stealth)` and
    /// `nullifier = sp_nullifier(serial)` off-chain; the pool stores no value
    /// and no blinding. Duplicate commitments are refused.
    pub fn deposit(
        &mut self,
        commitment: [u8; 32],
        stealth: [u8; 32],
        nullifier: [u8; 32],
    ) -> Result<(), SpError> {
        if self.notes.contains_key(&commitment) {
            return Err(SpError::DuplicateDeposit);
        }
        self.notes.insert(commitment, SpStoredNote { stealth, nullifier });
        Ok(())
    }

    /// Spend a note by revealing exactly `(serial, value, blinding)` against a
    /// claimed `commitment`: recompute `C` with the STORED stealth, require
    /// equality + presence, require `sp_nullifier(serial)` to equal the
    /// nullifier bound at deposit, require it unspent, then mark it spent.
    /// Returns the spent nullifier. Same mechanics as `hashpool.rs` `spend`.
    pub fn spend(
        &mut self,
        commitment: &[u8; 32],
        serial: &[u8; 32],
        value: u64,
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], SpError> {
        let stored = self.notes.get(commitment).ok_or(SpError::UnknownCommitment)?;
        let recomputed = sp_commit(self.chain_id, value, blinding, &stored.stealth);
        if &recomputed != commitment {
            return Err(SpError::CommitmentMismatch);
        }
        let nf = sp_nullifier(serial);
        if nf != stored.nullifier {
            return Err(SpError::SerialMismatch);
        }
        if self.spent.contains(&nf) {
            return Err(SpError::AlreadySpent);
        }
        self.spent.insert(nf);
        Ok(nf)
    }

    /// Falcon-authorized spend: verify the owner's signature over
    /// `sp_spend_sig_msg(chain, commitment, Nf(serial))` FIRST (fail-closed,
    /// no state touched on refusal), then delegate to [`SpPool::spend`].
    /// A signature for a different note, nullifier, or chain is refused, and
    /// a refused spend never marks anything spent.
    pub fn spend_signed(
        &mut self,
        auth: &SpSpendAuth,
        verify: SpVerify<'_>,
    ) -> Result<[u8; 32], SpError> {
        let nf = sp_nullifier(&auth.serial);
        let msg = sp_spend_sig_msg(self.chain_id, &auth.commitment, &nf);
        if !verify(&auth.owner_pk, &msg, &auth.owner_sig) {
            return Err(SpError::BadSignature);
        }
        self.spend(&auth.commitment, &auth.serial, auth.value, &auth.blinding)
    }
}
