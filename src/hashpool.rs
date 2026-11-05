//! HashPool — stealth-via-KEM + CoinJoin batches + hash commitments. UNWIRED.
//!
//! UNWIRED: this file is NOT declared in `lib.rs` (`mod hashpool` does not
//! exist) and NOTHING in production calls it. The `_test-only-later` posture
//! follows the `mev_pq_plan.rs` precedent: to run the KATs without touching
//! `lib.rs`, the integration test includes this file by path
//! (`tests/hashpool_tests.rs`: `#[path = "../src/hashpool.rs"] mod hashpool;`).
//! To wire it for real, the lead adds `#[cfg(test)] mod hashpool;` to
//! `lib.rs` (never a production `mod` before audit) and re-runs the gates.
//! No new dependencies: `ml-kem` (already vendored, `Cargo.toml:59`) + `std`
//! only. The SHAKE-256 sponge below is a self-contained copy of the tree
//! sponge (`post_quantum.rs:573` `keccak_f1600`, absorb/squeeze shape of
//! `cn_vrf.rs:118` `shake256_32`); it is pinned against the NIST vectors in
//! the test file, exactly like `post_quantum.rs:2143`.
//!
//! # Construction (lead-designed PQ private transfers WITHOUT ZK)
//!
//! All primitives already exist in-tree; this file only composes them:
//!
//! 1. STEALTH (hash+KEM, no DH group). The recipient publishes an ML-KEM-768
//!    encapsulation key (the `pq_registry.rs:492` `get_active_key` / `:278`
//!    `current_key_of` read shape — but this module imports NOTHING from
//!    `pq_registry` or `consensus`: the caller passes the raw `ek_bytes`,
//!    exactly 1184 B). The sender runs `stealth_encap` (the
//!    `from_seed` / `encapsulate_deterministic` / `decapsulate` idiom pinned
//!    in `infnode/crates/infnode/tests/kem_kat_tests.rs:139-177` and mirrored
//!    in `mev_epoch.rs:1365` `pq_kem_encapsulate_deterministic`):
//!    encap to `ek_bytes` with explicit 32-byte randomness `m` yields
//!    `(ct, ss)`, and the stealth address is
//!    `SHAKE256("STELL_HP_STEALTH_V1" || ss || index_be64)`.
//!    The recipient scans by decapsulation trial (`stealth_scan`): decap `ct`
//!    with each candidate seed, re-derive, compare. No new crypto, no groups.
//!
//! 2. NOTES (hash commitments, NO Merkle paths). With `chain_id: u64`,
//!    `value: u64`, `blinding: [u8; 32]`, `stealth: [u8; 32]`,
//!    `serial: [u8; 32]`:
//!    `C  = SHAKE256("STELL_HP_COMMIT_V1" || chain_be64 || value_be64 || blinding || stealth)`
//!    `Nf = SHAKE256("STELL_HP_NULL_V1"  || serial)`.
//!    The pool is `map C -> (stealth, Nf_expected)` plus a spent set of `Nf`.
//!    Deposit registers `(C, stealth, Nf)` (value stays hidden); spend reveals
//!    exactly `(serial, value, blinding)` and the verifier recomputes `C`
//!    with the STORED stealth, checks `C` present, checks
//!    `Nf(serial) == stored Nf` (the serial is BOUND at deposit: spending the
//!    same note under a different serial is refused, not just same-`Nf`
//!    twice), checks `Nf` unspent, then marks it spent. Membership is by
//!    recomputation — the operator checks `C` is present. There are no Merkle
//!    paths by design (operator model, see below).
//!
//! 3. COINJOIN batch. A uniform-amount batch = N input notes of the SAME
//!    denomination `D` (distinct commitments) + M output notes of the SAME
//!    `D` (distinct stealth addresses, distinct nullifiers) + K Falcon-512
//!    owner signatures (one per input, verified each via a caller-supplied
//!    closure — production passes
//!    `post_quantum.rs:521` `verify_pq_signature(PqScheme::Falcon512, …)`;
//!    test keys come from `post_quantum.rs:1799`
//!    `FalconKeypair::generate_from_seed_bytes`, signatures from `:1864`
//!    `sign`) + explicit `fee` with conservation `sum_in == sum_out + fee`
//!    (checked arithmetic). Flow: `coinjoin_sig_msg` (pure) -> caller signs
//!    per input -> `coinjoin_build` (assembles + sorts deterministically) ->
//!    `coinjoin_verify` (pure, needs `&HashPool` + verify closure) ->
//!    `coinjoin_apply` (mutates: marks inputs spent, registers outputs).
//!    Inputs are sorted by commitment, outputs by commitment; any other order
//!    is refused (`OrderNotCanonical`), so the batch digest is canonical.
//!
//! # Privacy LIMITATION (read before wiring)
//!
//! The pool operator learns the `value` (and `blinding`, `stealth`) of every
//! note AT SPEND TIME — the opening is revealed to recompute `C`. Privacy
//! here is sender/recipient UNLINKABILITY via fresh stealth addresses per
//! note plus CoinJoin ambiguity (N same-denomination notes spent together),
//! NOT amount hiding at spend. There is no encrypted-value or range-proof
//! machinery in this file, deliberately: that would be new crypto, which is
//! forbidden. Do not document or wire this as amount-hiding.
//!
//! # Operator model (no Merkle paths)
//!
//! Unlike a Merkle-tree shielded pool, membership is a direct map lookup of
//! the recomputed `C`. The operator keeps no paths and proves nothing; the
//! cost is that the operator sees linkable `(C, stealth)` registrations at
//! deposit and full openings at spend. Unlinkability comes only from fresh
//! stealth addresses and batch co-spending.
//!
//! # Exact byte layouts (frozen by the KATs)
//!
//! * stealth preimage: `HP_STEALTH_DST || ss(32) || index u64-BE` (75 B)
//! * commit preimage:  `HP_COMMIT_DST  || chain u64-BE || value u64-BE || blinding(32) || stealth(32)` (103 B)
//! * null preimage:    `HP_NULL_DST    || serial(32)` (53 B)
//! * batch sig preimage: `HP_CJ_SIG_DST || chain u64-BE || fee u64-BE ||
//!   n_in u32-BE || n_out u32-BE || sorted in_C… || sorted in_Nf… ||
//!   sorted out_C… || sorted out_Nf…`
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

/// Domain separator of the stealth-address preimage.
pub const HP_STEALTH_DST: &[u8] = b"STELL_HP_STEALTH_V1";
/// Domain separator of the note-commitment preimage.
pub const HP_COMMIT_DST: &[u8] = b"STELL_HP_COMMIT_V1";
/// Domain separator of the nullifier preimage.
pub const HP_NULL_DST: &[u8] = b"STELL_HP_NULL_V1";
/// Domain separator of the CoinJoin owner-signature message.
pub const HP_CJ_SIG_DST: &[u8] = b"STELL_HP_CJ_SIG_V1";

/// ML-KEM-768 encapsulation key length (FIPS 203).
pub const HP_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length (FIPS 203).
pub const HP_CT_LEN: usize = 1088;
/// ML-KEM-768 shared-secret length (FIPS 203).
pub const HP_SS_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Errors (fail-closed refusals)
// ---------------------------------------------------------------------------

/// Fail-closed refusal for a HashPool operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HpError {
    /// Encapsulation key is the wrong length or malformed.
    BadEncapsulationKey,
    /// Ciphertext is the wrong length or malformed.
    BadCiphertext,
    /// Batch carries no inputs or no outputs.
    EmptyBatch,
    /// Input values or output values are not all one denomination.
    NonUniformAmount,
    /// Two outputs share a stealth address.
    DuplicateStealth,
    /// Two notes share a commitment (same note twice in one batch).
    DuplicateNote,
    /// Two outputs share a nullifier (serial reuse across outputs).
    DuplicateNullifier,
    /// Inputs/outputs are not in canonical (sorted-commitment) order.
    OrderNotCanonical,
    /// `sum_in != sum_out + fee` (exact values carried for audit).
    Unbalanced { sum_in: u64, sum_out: u64, fee: u64 },
    /// Arithmetic overflow while summing values.
    Overflow,
    /// Chain id of the batch does not match the pool.
    ChainMismatch,
    /// Commitment already registered (deposit) — no double registration.
    DuplicateDeposit,
    /// Recomputed commitment does not match the claimed one.
    CommitmentMismatch,
    /// Revealed serial does not match the nullifier bound at deposit.
    SerialMismatch,
    /// Nullifier already spent.
    AlreadySpent,
    /// Output nullifier collides with a spent nullifier or an input nullifier.
    NullifierCollision,
    /// Commitment not present in the pool.
    UnknownCommitment,
    /// A Falcon owner signature did not verify.
    BadSignature,
}

impl std::fmt::Display for HpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HpError::BadEncapsulationKey => write!(f, "bad ML-KEM encapsulation key"),
            HpError::BadCiphertext => write!(f, "bad ML-KEM ciphertext"),
            HpError::EmptyBatch => write!(f, "coinjoin batch is empty"),
            HpError::NonUniformAmount => write!(f, "batch amounts are not uniform"),
            HpError::DuplicateStealth => write!(f, "duplicate stealth address in batch"),
            HpError::DuplicateNote => write!(f, "duplicate commitment in batch"),
            HpError::DuplicateNullifier => write!(f, "duplicate nullifier in batch"),
            HpError::OrderNotCanonical => write!(f, "batch order is not canonical"),
            HpError::Unbalanced { sum_in, sum_out, fee } => write!(
                f,
                "unbalanced batch: sum_in {sum_in} != sum_out {sum_out} + fee {fee}"
            ),
            HpError::Overflow => write!(f, "value sum overflowed"),
            HpError::ChainMismatch => write!(f, "batch chain id does not match pool"),
            HpError::DuplicateDeposit => write!(f, "commitment already deposited"),
            HpError::CommitmentMismatch => write!(f, "opening does not recompute the commitment"),
            HpError::SerialMismatch => {
                write!(f, "revealed serial does not match the bound nullifier")
            }
            HpError::AlreadySpent => write!(f, "nullifier already spent"),
            HpError::NullifierCollision => write!(f, "output nullifier collides"),
            HpError::UnknownCommitment => write!(f, "commitment not in pool"),
            HpError::BadSignature => write!(f, "owner signature did not verify"),
        }
    }
}

impl std::error::Error for HpError {}

// ---------------------------------------------------------------------------
// SHAKE-256 (self-contained tree sponge copy; see file header)
// ---------------------------------------------------------------------------

fn hp_keccak_f1600(state: &mut [u64; 25]) {
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
pub fn hp_shake256(data: &[u8], out: &mut [u8]) {
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
        hp_keccak_f1600(&mut state);
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
    hp_keccak_f1600(&mut state);
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
            hp_keccak_f1600(&mut state);
        }
    }
}

/// SHAKE-256 squeeze of exactly 32 bytes.
pub fn hp_shake256_32(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hp_shake256(data, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Stealth addresses (KEM + hash, no DH group)
// ---------------------------------------------------------------------------

/// Derive a stealth address from a KEM shared secret and a note index:
/// `SHAKE256(HP_STEALTH_DST || ss || index_be64)`.
pub fn stealth_address(ss: &[u8; 32], index: u64) -> [u8; 32] {
    let mut pre = Vec::with_capacity(HP_STEALTH_DST.len() + 32 + 8);
    pre.extend_from_slice(HP_STEALTH_DST);
    pre.extend_from_slice(ss);
    pre.extend_from_slice(&index.to_be_bytes());
    hp_shake256_32(&pre)
}

/// Encapsulate to a recipient's ML-KEM-768 key and derive the stealth address.
///
/// `ek_bytes` is the recipient's published 1184-byte encapsulation key (the
/// `pq_registry` read shape, passed as bytes — never resolved here);
/// `randomness` is the explicit KEM `m` (production: fresh OS bytes; tests:
/// fixed vectors for determinism). Returns `(ct_bytes, stealth_addr)`.
pub fn stealth_encap(
    ek_bytes: &[u8],
    index: u64,
    randomness: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), HpError> {
    if ek_bytes.len() != HP_EK_LEN {
        return Err(HpError::BadEncapsulationKey);
    }
    let key =
        Key::<EncapsulationKey768>::try_from(ek_bytes).map_err(|_| HpError::BadEncapsulationKey)?;
    let ek = EncapsulationKey768::new(&key).map_err(|_| HpError::BadEncapsulationKey)?;
    let m: ml_kem::B32 = (*randomness).into();
    let (ct, ss) = ek.encapsulate_deterministic(&m);
    let mut ss32 = [0u8; HP_SS_LEN];
    ss32.copy_from_slice(ss.as_slice());
    Ok((ct.as_slice().to_vec(), stealth_address(&ss32, index)))
}

/// Decapsulate `ct` with the recipient's 64-byte KEM seed and re-derive the
/// stealth address for `index`. Infallible for well-formed `ct` (FIPS 203
/// implicit rejection: a tampered `ct` yields the fallback key, hence a
/// non-matching stealth address — never an error).
pub fn stealth_decap(
    kem_seed: &[u8; 64],
    ct: &[u8],
    index: u64,
) -> Result<[u8; 32], HpError> {
    if ct.len() != HP_CT_LEN {
        return Err(HpError::BadCiphertext);
    }
    let seed: ml_kem::Seed = (*kem_seed).into();
    let (dk, _) = MlKem768::from_seed(&seed);
    let kem_ct: ml_kem::kem::Ciphertext<MlKem768> =
        ct.try_into().map_err(|_| HpError::BadCiphertext)?;
    let ss = dk.decapsulate(&kem_ct);
    let mut ss32 = [0u8; HP_SS_LEN];
    ss32.copy_from_slice(ss.as_slice());
    Ok(stealth_address(&ss32, index))
}

/// Scan `ct` against `seeds` (decap trial per candidate): return the index of
/// the first seed whose derived stealth address equals `expected`, or `None`
/// when no candidate matches (wrong recipients are excluded).
pub fn stealth_scan(
    seeds: &[[u8; 64]],
    ct: &[u8],
    index: u64,
    expected: &[u8; 32],
) -> Option<usize> {
    seeds.iter().position(|seed| {
        stealth_decap(seed, ct, index)
            .map(|got| &got == expected)
            .unwrap_or(false)
    })
}

// ---------------------------------------------------------------------------
// Notes: commitments + nullifiers
// ---------------------------------------------------------------------------

/// Note commitment:
/// `SHAKE256(HP_COMMIT_DST || chain_be64 || value_be64 || blinding || stealth)`.
pub fn note_commit(
    chain_id: u64,
    value: u64,
    blinding: &[u8; 32],
    stealth: &[u8; 32],
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(HP_COMMIT_DST.len() + 8 + 8 + 32 + 32);
    pre.extend_from_slice(HP_COMMIT_DST);
    pre.extend_from_slice(&chain_id.to_be_bytes());
    pre.extend_from_slice(&value.to_be_bytes());
    pre.extend_from_slice(blinding);
    pre.extend_from_slice(stealth);
    hp_shake256_32(&pre)
}

/// Note nullifier: `SHAKE256(HP_NULL_DST || serial)`.
pub fn note_nullifier(serial: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(HP_NULL_DST.len() + 32);
    pre.extend_from_slice(HP_NULL_DST);
    pre.extend_from_slice(serial);
    hp_shake256_32(&pre)
}

// ---------------------------------------------------------------------------
// Pool: map C -> (stealth, bound nullifier) + spent set
// ---------------------------------------------------------------------------

/// A deposited note as stored by the operator: the stealth address (public at
/// deposit) and the nullifier bound at deposit (revealed at spend). The value
/// and blinding are NEVER stored — they stay hidden until the spender reveals
/// the opening.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredNote {
    /// Stealth address the commitment was registered under (public).
    pub stealth: [u8; 32],
    /// Nullifier the deposit bound to this commitment: only a spend revealing
    /// the preimage `serial` with `note_nullifier(serial) == nullifier`
    /// releases the note (serial-substitution refused).
    pub nullifier: [u8; 32],
}

/// HashPool: membership by recomputation, no Merkle paths (see file header
/// for the operator model and the privacy limitation).
#[derive(Clone, Debug, Default)]
pub struct HashPool {
    chain_id: u64,
    notes: BTreeMap<[u8; 32], StoredNote>,
    spent: BTreeSet<[u8; 32]>,
}

impl HashPool {
    /// Empty pool bound to `chain_id` (commitments bind the chain id, so a
    /// pool only admits notes for its own chain).
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            notes: BTreeMap::new(),
            spent: BTreeSet::new(),
        }
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
    /// computed `commitment = note_commit(chain, value, blinding, stealth)`
    /// and `nullifier = note_nullifier(serial)` off-chain; the pool stores no
    /// value and no blinding. Duplicate commitments are refused.
    pub fn deposit(
        &mut self,
        commitment: [u8; 32],
        stealth: [u8; 32],
        nullifier: [u8; 32],
    ) -> Result<(), HpError> {
        if self.notes.contains_key(&commitment) {
            return Err(HpError::DuplicateDeposit);
        }
        self.notes.insert(commitment, StoredNote { stealth, nullifier });
        Ok(())
    }

    /// Spend a note by revealing exactly `(serial, value, blinding)` against
    /// a claimed `commitment`: recompute `C` with the STORED stealth, require
    /// equality + presence, require `note_nullifier(serial)` to equal the
    /// nullifier bound at deposit, require it unspent, then mark it spent.
    /// Returns the spent nullifier.
    pub fn spend(
        &mut self,
        commitment: &[u8; 32],
        serial: &[u8; 32],
        value: u64,
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], HpError> {
        let stored = self.notes.get(commitment).ok_or(HpError::UnknownCommitment)?;
        let recomputed = note_commit(self.chain_id, value, blinding, &stored.stealth);
        if &recomputed != commitment {
            return Err(HpError::CommitmentMismatch);
        }
        let nf = note_nullifier(serial);
        if nf != stored.nullifier {
            return Err(HpError::SerialMismatch);
        }
        if self.spent.contains(&nf) {
            return Err(HpError::AlreadySpent);
        }
        self.spent.insert(nf);
        Ok(nf)
    }
}

// ---------------------------------------------------------------------------
// CoinJoin batches
// ---------------------------------------------------------------------------

/// An input opening revealed by the spender: `(serial, value, blinding)` plus
/// the note's public `stealth` address (known to the depositor and stored in
/// the pool at deposit; needed here so the builder can recompute the real
/// commitment for canonical ordering and signing without pool access).
/// `HashPool::spend` resolves stealth from the map instead — the batch path
/// carries it only as a recomputation input that verification re-checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendOpening {
    /// Note serial (preimage of the bound nullifier).
    pub serial: [u8; 32],
    /// Note value (must equal the batch denomination).
    pub value: u64,
    /// Note blinding.
    pub blinding: [u8; 32],
    /// Note stealth address (public; re-checked against pool storage).
    pub stealth: [u8; 32],
}

/// A new output note created by the batch. `serial` is the FRESH serial whose
/// nullifier is registered for the output at apply time (preimage-resistant,
/// safe to register eagerly); it must be distinct from every other output
/// serial and from every nullifier already spent or consumed in this batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputNote {
    /// Output value (must equal the batch denomination).
    pub value: u64,
    /// Fresh output blinding.
    pub blinding: [u8; 32],
    /// Fresh output stealth address (pairwise distinct across outputs).
    pub stealth: [u8; 32],
    /// Fresh output serial.
    pub serial: [u8; 32],
}

/// A signed batch input: the revealed opening, the claimed commitment it
/// spends, and the owner's Falcon-512 `(pk, sig)` authorizing the spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedInput {
    /// Revealed opening.
    pub opening: SpendOpening,
    /// Claimed commitment (must recompute from the opening + stored stealth).
    pub commitment: [u8; 32],
    /// Owner Falcon-512 public key bytes (opaque here; the verify closure
    /// enforces the scheme + length).
    pub owner_pk: Vec<u8>,
    /// Owner signature over [`coinjoin_sig_msg`] for this batch.
    pub owner_sig: Vec<u8>,
}

/// A canonical CoinJoin batch: inputs sorted by commitment ascending, outputs
/// sorted by commitment ascending. Any other order is refused by the verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinJoinBatch {
    /// Chain id (must match the pool at verify/apply time).
    pub chain_id: u64,
    /// Explicit fee; bound by the owner signatures and the conservation check.
    pub fee: u64,
    /// Signed inputs, sorted by commitment ascending.
    pub inputs: Vec<SignedInput>,
    /// New outputs, sorted by commitment ascending.
    pub outputs: Vec<OutputNote>,
}

fn sum_checked(values: impl Iterator<Item = u64>) -> Result<u64, HpError> {
    let mut acc: u64 = 0;
    for v in values {
        acc = acc.checked_add(v).ok_or(HpError::Overflow)?;
    }
    Ok(acc)
}

fn output_commitment(chain_id: u64, out: &OutputNote) -> [u8; 32] {
    note_commit(chain_id, out.value, &out.blinding, &out.stealth)
}

/// Canonical owner-signature message for a batch:
/// `SHAKE256(HP_CJ_SIG_DST || chain_be64 || fee_be64 || n_in_be32 ||
/// n_out_be32 || sorted in_C… || sorted in_Nf… || sorted out_C… ||
/// sorted out_Nf…)`. Every input owner signs THE SAME message, binding the
/// full input set, the full output set (commitments AND nullifiers, so output
/// serials cannot be swapped after signing), and the fee.
pub fn coinjoin_sig_msg(
    chain_id: u64,
    in_cs: &[[u8; 32]],
    in_nfs: &[[u8; 32]],
    out_cs: &[[u8; 32]],
    out_nfs: &[[u8; 32]],
    fee: u64,
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(
        HP_CJ_SIG_DST.len() + 8 + 8 + 4 + 4 + in_cs.len() * 64 + out_cs.len() * 64,
    );
    pre.extend_from_slice(HP_CJ_SIG_DST);
    pre.extend_from_slice(&chain_id.to_be_bytes());
    pre.extend_from_slice(&fee.to_be_bytes());
    pre.extend_from_slice(&(in_cs.len() as u32).to_be_bytes());
    pre.extend_from_slice(&(out_cs.len() as u32).to_be_bytes());
    for c in in_cs {
        pre.extend_from_slice(c);
    }
    for nf in in_nfs {
        pre.extend_from_slice(nf);
    }
    for c in out_cs {
        pre.extend_from_slice(c);
    }
    for nf in out_nfs {
        pre.extend_from_slice(nf);
    }
    hp_shake256_32(&pre)
}

/// Assemble a canonical batch from revealed openings + output notes.
/// `spends` carries one `(opening, owner_pk, owner_sig)` tuple per input; the
/// caller derived the signed message with [`coinjoin_sig_msg`] over the
/// SORTED input/output commitments and nullifiers (compute them with
/// [`note_commit`] / [`note_nullifier`] from the openings + output notes,
/// sort ascending, then sign — the builder re-derives and sorts identically,
/// so signing order does not matter).
///
/// Structural checks (uniform denomination, distinct stealths/commitments/
/// nullifiers, conservation, canonical sorting) run here AND again in
/// [`coinjoin_verify`] (fail-closed on both paths); signatures are checked
/// only in [`coinjoin_verify`] via the caller-supplied closure.
pub fn coinjoin_build(
    chain_id: u64,
    spends: Vec<(SpendOpening, Vec<u8>, Vec<u8>)>,
    outputs: Vec<OutputNote>,
    fee: u64,
) -> Result<CoinJoinBatch, HpError> {
    if spends.is_empty() || outputs.is_empty() {
        return Err(HpError::EmptyBatch);
    }
    let denom = spends[0].0.value;
    if !spends.iter().all(|(o, _, _)| o.value == denom) {
        return Err(HpError::NonUniformAmount);
    }
    if !outputs.iter().all(|o| o.value == denom) {
        return Err(HpError::NonUniformAmount);
    }

    let sum_in = sum_checked(spends.iter().map(|(o, _, _)| o.value))?;
    let sum_out = sum_checked(outputs.iter().map(|o| o.value))?;
    let needed = sum_out.checked_add(fee).ok_or(HpError::Overflow)?;
    if sum_in != needed {
        return Err(HpError::Unbalanced { sum_in, sum_out, fee });
    }

    // Distinct output stealths (fresh addresses per note — the unlinkability
    // mechanism); pairwise distinctness via sorted adjacency.
    let mut stealths: Vec<[u8; 32]> = outputs.iter().map(|o| o.stealth).collect();
    stealths.sort();
    for w in stealths.windows(2) {
        if w[0] == w[1] {
            return Err(HpError::DuplicateStealth);
        }
    }

    // Distinct output nullifiers (fresh serials per note).
    let out_nfs: Vec<[u8; 32]> = outputs.iter().map(|o| note_nullifier(&o.serial)).collect();
    let mut nfs_sorted = out_nfs.clone();
    nfs_sorted.sort();
    for w in nfs_sorted.windows(2) {
        if w[0] == w[1] {
            return Err(HpError::DuplicateNullifier);
        }
    }

    // Real input commitments (stealth is public and carried in the opening).
    let mut inputs: Vec<SignedInput> = Vec::with_capacity(spends.len());
    for (opening, owner_pk, owner_sig) in spends {
        let commitment = note_commit(chain_id, opening.value, &opening.blinding, &opening.stealth);
        inputs.push(SignedInput { opening, commitment, owner_pk, owner_sig });
    }
    inputs.sort_by(|a, b| a.commitment.cmp(&b.commitment));
    for w in inputs.windows(2) {
        if w[0].commitment == w[1].commitment {
            return Err(HpError::DuplicateNote);
        }
    }

    let mut sorted_outputs = outputs;
    sorted_outputs.sort_by(|a, b| {
        output_commitment(chain_id, a).cmp(&output_commitment(chain_id, b))
    });
    for w in sorted_outputs.windows(2) {
        if output_commitment(chain_id, &w[0]) == output_commitment(chain_id, &w[1]) {
            return Err(HpError::DuplicateNote);
        }
    }

    Ok(CoinJoinBatch { chain_id, fee, inputs, outputs: sorted_outputs })
}

/// Caller-supplied Falcon owner-signature verifier: `verify(pk, msg, sig)`.
/// Production passes `post_quantum::verify_pq_signature` partially applied to
/// `PqScheme::Falcon512`; tests pass the same function directly.
pub type HpVerify<'a> = &'a dyn Fn(&[u8], &[u8], &[u8]) -> bool;

/// Verify a batch against `pool` WITHOUT mutating it. Checks, cheapest first:
/// chain match, non-empty, canonical output order, uniform denomination,
/// distinct stealths/commitments/nullifiers, conservation, then per input:
/// recomputed commitment matches the pool record, nullifier bound matches,
/// nullifier unspent, owner signature verifies over [`coinjoin_sig_msg`]
/// recomputed here from the REAL commitments. Output nullifiers must be
/// fresh (not spent, not colliding with inputs or each other).
pub fn coinjoin_verify(
    pool: &HashPool,
    batch: &CoinJoinBatch,
    verify: HpVerify<'_>,
) -> Result<(), HpError> {
    if batch.chain_id != pool.chain_id {
        return Err(HpError::ChainMismatch);
    }
    if batch.inputs.is_empty() || batch.outputs.is_empty() {
        return Err(HpError::EmptyBatch);
    }

    let denom = batch.inputs[0].opening.value;
    if !batch.inputs.iter().all(|i| i.opening.value == denom) {
        return Err(HpError::NonUniformAmount);
    }
    if !batch.outputs.iter().all(|o| o.value == denom) {
        return Err(HpError::NonUniformAmount);
    }

    let sum_in = sum_checked(batch.inputs.iter().map(|i| i.opening.value))?;
    let sum_out = sum_checked(batch.outputs.iter().map(|o| o.value))?;
    let needed = sum_out.checked_add(batch.fee).ok_or(HpError::Overflow)?;
    if sum_in != needed {
        return Err(HpError::Unbalanced { sum_in, sum_out, fee: batch.fee });
    }

    // Canonical input order: strictly ascending by commitment (the builder
    // sorts; anything else is refused). Checked before any crypto — cheapest
    // structural refusal first.
    for w in batch.inputs.windows(2) {
        if w[0].commitment >= w[1].commitment {
            return Err(HpError::OrderNotCanonical);
        }
    }

    // Recompute input commitments from pool stealths. The claimed commitment
    // must equal the recomputation (caller-supplied stealth must equal stored
    // stealth — substituted stealth fails here, never later).
    let mut in_nfs: Vec<[u8; 32]> = Vec::with_capacity(batch.inputs.len());
    for inp in &batch.inputs {
        let stored = pool
            .notes
            .get(&inp.commitment)
            .ok_or(HpError::UnknownCommitment)?;
        if inp.opening.stealth != stored.stealth {
            return Err(HpError::CommitmentMismatch);
        }
        let recomputed = note_commit(pool.chain_id, inp.opening.value, &inp.opening.blinding, &stored.stealth);
        if recomputed != inp.commitment {
            return Err(HpError::CommitmentMismatch);
        }
        let nf = note_nullifier(&inp.opening.serial);
        if nf != stored.nullifier {
            return Err(HpError::SerialMismatch);
        }
        if pool.spent.contains(&nf) {
            return Err(HpError::AlreadySpent);
        }
        in_nfs.push(nf);
    }
    let mut in_nfs_sorted = in_nfs.clone();
    in_nfs_sorted.sort();
    for w in in_nfs_sorted.windows(2) {
        if w[0] == w[1] {
            return Err(HpError::DuplicateNullifier);
        }
    }

    // Outputs: canonical order by real commitment (strictly ascending),
    // distinct stealths, distinct nullifiers, fresh nullifiers.
    let out_cs: Vec<[u8; 32]> = batch
        .outputs
        .iter()
        .map(|o| output_commitment(pool.chain_id, o))
        .collect();
    // Strictly-sorted check on the batch's own order.
    for w in out_cs.windows(2) {
        if w[0] >= w[1] {
            return Err(HpError::OrderNotCanonical);
        }
    }
    let mut stealths: Vec<[u8; 32]> = batch.outputs.iter().map(|o| o.stealth).collect();
    stealths.sort();
    for w in stealths.windows(2) {
        if w[0] == w[1] {
            return Err(HpError::DuplicateStealth);
        }
    }
    let out_nfs: Vec<[u8; 32]> = batch.outputs.iter().map(|o| note_nullifier(&o.serial)).collect();
    let mut nfs_sorted = out_nfs.clone();
    nfs_sorted.sort();
    for w in nfs_sorted.windows(2) {
        if w[0] == w[1] {
            return Err(HpError::DuplicateNullifier);
        }
    }
    for nf in &out_nfs {
        if pool.spent.contains(nf) {
            return Err(HpError::NullifierCollision);
        }
    }
    for in_nf in &in_nfs {
        if out_nfs.contains(in_nf) {
            return Err(HpError::NullifierCollision);
        }
    }

    // Owner signatures over the canonical message (real commitments, batch
    // order == sorted order, enforced above).
    let in_cs: Vec<[u8; 32]> = batch.inputs.iter().map(|i| i.commitment).collect();
    let mut out_pairs: Vec<([u8; 32], [u8; 32])> =
        out_cs.iter().zip(out_nfs.iter()).map(|(c, n)| (*c, *n)).collect();
    out_pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let out_cs_sorted: Vec<[u8; 32]> = out_pairs.iter().map(|(c, _)| *c).collect();
    let out_nfs_sorted: Vec<[u8; 32]> = out_pairs.iter().map(|(_, n)| *n).collect();
    let msg = coinjoin_sig_msg(
        pool.chain_id,
        &in_cs,
        &in_nfs_sorted,
        &out_cs_sorted,
        &out_nfs_sorted,
        batch.fee,
    );
    for inp in &batch.inputs {
        if !verify(&inp.owner_pk, &msg, &inp.owner_sig) {
            return Err(HpError::BadSignature);
        }
    }

    Ok(())
}

/// Apply a PREVIOUSLY VERIFIED batch: mark input nullifiers spent and register
/// output commitments. Re-checks all state preconditions (membership,
/// recomputation, freshness, conservation, uniformity, canonical order) but
/// NOT signatures — the caller MUST have run [`coinjoin_verify`] first with
/// the real Falcon verifier. Fail-closed when called on an unverified batch.
pub fn coinjoin_apply(pool: &mut HashPool, batch: &CoinJoinBatch) -> Result<(), HpError> {
    if batch.chain_id != pool.chain_id {
        return Err(HpError::ChainMismatch);
    }
    if batch.inputs.is_empty() || batch.outputs.is_empty() {
        return Err(HpError::EmptyBatch);
    }

    // Re-derive everything (same checks as verify minus signatures).
    // Canonical order first (cheapest structural refusal).
    for w in batch.inputs.windows(2) {
        if w[0].commitment >= w[1].commitment {
            return Err(HpError::OrderNotCanonical);
        }
    }
    let mut in_nfs: Vec<[u8; 32]> = Vec::with_capacity(batch.inputs.len());
    for inp in &batch.inputs {
        let stored = pool
            .notes
            .get(&inp.commitment)
            .ok_or(HpError::UnknownCommitment)?;
        if inp.opening.stealth != stored.stealth {
            return Err(HpError::CommitmentMismatch);
        }
        let recomputed = note_commit(pool.chain_id, inp.opening.value, &inp.opening.blinding, &stored.stealth);
        if recomputed != inp.commitment {
            return Err(HpError::CommitmentMismatch);
        }
        let nf = note_nullifier(&inp.opening.serial);
        if nf != stored.nullifier {
            return Err(HpError::SerialMismatch);
        }
        if pool.spent.contains(&nf) {
            return Err(HpError::AlreadySpent);
        }
        in_nfs.push(nf);
    }
    let mut in_nfs_sorted = in_nfs.clone();
    in_nfs_sorted.sort();
    for w in in_nfs_sorted.windows(2) {
        if w[0] == w[1] {
            return Err(HpError::DuplicateNullifier);
        }
    }

    let denom = batch.inputs[0].opening.value;
    if !batch.inputs.iter().all(|i| i.opening.value == denom) {
        return Err(HpError::NonUniformAmount);
    }
    if !batch.outputs.iter().all(|o| o.value == denom) {
        return Err(HpError::NonUniformAmount);
    }
    let sum_in = sum_checked(batch.inputs.iter().map(|i| i.opening.value))?;
    let sum_out = sum_checked(batch.outputs.iter().map(|o| o.value))?;
    let needed = sum_out.checked_add(batch.fee).ok_or(HpError::Overflow)?;
    if sum_in != needed {
        return Err(HpError::Unbalanced { sum_in, sum_out, fee: batch.fee });
    }

    let out_cs: Vec<[u8; 32]> = batch
        .outputs
        .iter()
        .map(|o| output_commitment(pool.chain_id, o))
        .collect();
    for w in out_cs.windows(2) {
        if w[0] >= w[1] {
            return Err(HpError::OrderNotCanonical);
        }
    }
    let out_nfs: Vec<[u8; 32]> = batch.outputs.iter().map(|o| note_nullifier(&o.serial)).collect();
    let mut nfs_sorted = out_nfs.clone();
    nfs_sorted.sort();
    for w in nfs_sorted.windows(2) {
        if w[0] == w[1] {
            return Err(HpError::DuplicateNullifier);
        }
    }
    for nf in &out_nfs {
        if pool.spent.contains(nf) {
            return Err(HpError::NullifierCollision);
        }
    }
    for in_nf in &in_nfs {
        if out_nfs.contains(in_nf) {
            return Err(HpError::NullifierCollision);
        }
    }
    for c in &out_cs {
        if pool.notes.contains_key(c) {
            return Err(HpError::DuplicateDeposit);
        }
    }

    // Mutate: spend inputs, register outputs.
    for nf in &in_nfs {
        pool.spent.insert(*nf);
    }
    for ((out, c), nf) in batch.outputs.iter().zip(out_cs.iter()).zip(out_nfs.iter()) {
        pool.notes.insert(*c, StoredNote { stealth: out.stealth, nullifier: *nf });
    }
    Ok(())
}
