use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

// ---------------------------------------------------------------------------
// Verify-once signature attestation (PERF_PROFILE §6.1).
//
// Intake (mempool admission) already verifies every pooled transaction's
// signature; block apply used to verify the SAME bytes a second time
// (~10ms at 428tx). This cache carries the admission verdict to apply so
// the second verification is skipped when — and ONLY when — the exact same
// bytes under the exact same chain context are presented.
//
// Soundness (fail-closed, adversarial):
// * The record binds tx hash + signer (`from`) + FULL signature bytes +
//   the exact signing-message preimage (sha256). Legacy tx hashes do NOT
//   commit the signature, so the sig binding is load-bearing: any mutated
//   byte (amount, nonce, sig, delegation, sponsor, chain envelope, ...)
//   changes at least one of the three digests and forces full re-verify.
//   PQ1/EVM envelopes are the exception that proves it: their tx hash
//   already folds the FULL signature bytes into its preimage (tags
//   `PQ_ENV` / `EVM_TX`), so the dedicated signature digest is provably
//   redundant there and is replaced by a constant — every mutated byte
//   still changes the tx hash, and therefore the cache key. See
//   `signature_digest`.
// * The record binds the chain domain BOTH ways: the transaction's own
//   `chain_id()` (None for legacy unbound) AND the node's chain id the
//   admission was verified for (`verified_for_chain`). A replay of the same
//   bytes on another chain (different `expected_chain`) misses and is fully
//   re-verified — where the usual chain-id/binding checks still refuse it.
// * The record binds `is_pure_pq_enforced()`: flipping pure-PQ mode forces
//   re-verify instead of replaying a stale classical verdict.
// * PQ-implicit transactions additionally require the key to STILL be in
//   the global implicit registry at use time (a cheap lookup, no crypto);
//   a missing key forces the full path (which heals from pinned state).
// * The cache is node-local only, never on the wire: an adversary cannot
//   forge an attestation, only present bytes. Records are inserted ONLY
//   after a successful cryptographic verification (mempool admission or a
//   full apply verification). Only sizing pressure evicts (whole-map clear,
//   which merely costs re-verification).
// * NOTHING else is skipped: chain-id, chain-binding activation,
//   session/sponsor policy, nonce and balance checks below run for EVERY
//   transaction, attested or not. This only skips the ed25519/PQ/secp256k1
//   cryptographic verification itself.
// ---------------------------------------------------------------------------

/// Maximum attested signatures retained (fail-closed eviction: exceeding it
/// clears the map, forcing re-verification — never a bypass).
const VERIFY_ONCE_CACHE_CAP: usize = 65_536;

/// A verified-signature attestation for one exact transaction under one
/// exact chain context. All digests are sha256.
#[derive(Clone, Debug)]
struct VerifiedSigRecord {
    from: [u8; 32],
    tx_hash: [u8; 32],
    sig_len: usize,
    msg_hash: [u8; 32],
    bound_chain: Option<u64>,
    verified_for_chain: u64,
    pure_pq_enforced: bool,
}

struct VerifyOnceState {
    // Keyed by (tx hash, signature sha256, attesting chain): the same bytes
    // attested on two chains keep two records, so a foreign-chain replay can
    // never evict (or hit) the home-chain attestation.
    map: HashMap<([u8; 32], [u8; 32], u64), VerifiedSigRecord>,
}

fn verify_once_state() -> &'static Mutex<VerifyOnceState> {
    static STATE: OnceLock<Mutex<VerifyOnceState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(VerifyOnceState {
            map: HashMap::new(),
        })
    })
}

static VERIFY_ONCE_HITS: AtomicU64 = AtomicU64::new(0);
static VERIFY_ONCE_MISSES: AtomicU64 = AtomicU64::new(0);
static VERIFY_ONCE_RECORDED: AtomicU64 = AtomicU64::new(0);

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

thread_local! {
    /// Per-thread transaction-hash state (one hasher + one payload scratch
    /// buffer). `Transaction::compute_tx_hash` allocates a fresh `Vec` for the
    /// bincode payload on EVERY call; the block path calls it once per
    /// transaction, so this reuses the allocation. `TxHashBatch::hash_one`
    /// feeds the IDENTICAL update sequence, so hashes are byte-identical.
    static TX_HASHER: RefCell<Option<crate::sharding::TxHashBatch>> = const { RefCell::new(None) };
}

/// `Transaction::compute_tx_hash` without the per-call allocation.
fn tx_hash(tx: &crate::sharding::Transaction) -> [u8; 32] {
    TX_HASHER.with(|cell| {
        let mut slot = cell.borrow_mut();
        let batch = slot.get_or_insert_with(crate::sharding::Transaction::batch_hasher);
        batch.hash_one(tx)
    })
}

/// sha256 of the transaction's FULL signature bytes.
///
/// Skipped (replaced by the all-zero digest) when the transaction hash
/// ALREADY commits those exact bytes: `hash_into` folds `self.signature`
/// verbatim into the preimage for PQ envelopes (`PQ_ENV` tag) and EVM
/// envelopes (`EVM_TX` tag), so any mutation of any signature byte changes
/// `tx_hash` and the cache key still misses. Legacy / sponsored-classical
/// transactions do NOT commit their signature, which is exactly why the
/// separate digest exists for them (and is load-bearing there).
///
/// The map key stays unique per (exact bytes, chain): the verdict for a
/// given transaction is unchanged, only a provably redundant second sha256
/// pass over the same bytes is removed.
#[inline]
fn signature_digest(tx: &crate::sharding::Transaction) -> [u8; 32] {
    if tx.is_pq() || tx.is_evm() {
        [0u8; 32]
    } else {
        sha256_bytes(&tx.signature)
    }
}

/// Record a verified signature attestation. Call ONLY after the transaction's
/// signature has been cryptographically verified (mempool admission or a
/// full apply verification). Fail-closed: recording a bad verdict is the
/// caller's bug, so the single mempool call site sits directly behind its
/// `verify_signature_with_registry` check.
pub fn record_verified_signature(tx: &crate::sharding::Transaction, verified_for_chain: u64) {
    let tx_hash = tx_hash(tx);
    let sig_hash = signature_digest(tx);
    let msg_hash = sha256_bytes(&tx.signing_message());
    let rec = VerifiedSigRecord {
        from: tx.from,
        tx_hash,
        sig_len: tx.signature.len(),
        msg_hash,
        bound_chain: tx.chain_id(),
        verified_for_chain,
        pure_pq_enforced: crate::post_quantum::is_pure_pq_enforced(),
    };
    let mut guard = verify_once_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.map.len() >= VERIFY_ONCE_CACHE_CAP {
        guard.map.clear();
    }
    guard
        .map
        .insert((tx_hash, sig_hash, verified_for_chain), rec);
    VERIFY_ONCE_RECORDED.fetch_add(1, Ordering::Relaxed);
}

/// True iff a valid attestation covers `tx` under `expected_chain`: the EXACT
/// same signer, tx hash, signature bytes and signing preimage were verified
/// before, under the same chain domain and the same pure-PQ mode. Anything
/// else returns false (full re-verification, fail-closed).
pub fn verified_signature_covers(tx: &crate::sharding::Transaction, expected_chain: u64) -> bool {
    // PQ-implicit keys resolve through a mutable registry: require the key
    // to still be present (cheap lookup, no crypto) or force full verify.
    if tx.is_pq_implicit()
        && crate::sharding::Transaction::global_implicit_registry()
            .lookup(&tx.from)
            .is_none()
    {
        VERIFY_ONCE_MISSES.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    // Every digest this attestation binds is computed ONCE, outside the
    // cache lock: the lock used to be held across the signing-preimage
    // sha256, which serialised all cover checks on one mutex. The compared
    // values are unchanged.
    let tx_hash = tx_hash(tx);
    let sig_hash = signature_digest(tx);
    let msg_hash = sha256_bytes(&tx.signing_message());
    let bound_chain = tx.chain_id();
    let pure_pq_enforced = crate::post_quantum::is_pure_pq_enforced();
    let guard = verify_once_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(rec) = guard.map.get(&(tx_hash, sig_hash, expected_chain)) else {
        VERIFY_ONCE_MISSES.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    let covered = rec.from == tx.from
        && rec.tx_hash == tx_hash
        && rec.sig_len == tx.signature.len()
        && rec.msg_hash == msg_hash
        && rec.bound_chain == bound_chain
        && rec.verified_for_chain == expected_chain
        && rec.pure_pq_enforced == pure_pq_enforced;
    if covered {
        VERIFY_ONCE_HITS.fetch_add(1, Ordering::Relaxed);
    } else {
        VERIFY_ONCE_MISSES.fetch_add(1, Ordering::Relaxed);
    }
    covered
}

/// FULL-PQ (no compat, nodes wiped): a transaction is admissible only with
/// a PQ envelope carrying a post-quantum scheme. Classical envelopes (bare
/// ed25519, EVM, or non-PQ scheme ids) are refused at admission, before any
/// floor / nonce / balance effect — no fee, no nonce consumption.
///
/// SESSION-AUTH CARVE-OUT (HDAE session zone): a well-formed session-key
/// envelope (`SK1`/`SF1` framing parsed by `Transaction::delegation`) skips
/// this TRANSPORT gate and falls through to session authorization instead —
/// `verify_signature` (session branch) + `session_gate` — which refuse Ed
/// grants fail-closed and admit Falcon grants. Without the carve-out no
/// delegated transaction could apply at all (a session envelope is not a
/// PQ1 envelope by construction: the session signature scheme differs from
/// the transport framing). This changes no other verdict: non-session
/// transactions take the exact same path as before.
pub(super) fn require_pq_tx_envelope(tx: &crate::sharding::Transaction) -> Result<(), String> {
    if tx.delegation().is_some() {
        return Ok(());
    }
    let Some(env) = tx.pq_envelope() else {
        return Err(
            "Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope"
                .to_string(),
        );
    };
    if !env.scheme.is_post_quantum() {
        return Err(
            "Pure PQ mode: scheme must be post-quantum (Falcon-512; ML-DSA-44 has no verifier)"
                .to_string(),
        );
    }
    Ok(())
}

/// Height-gated variant of [`require_pq_tx_envelope`]: when
/// `wasm_xshard_pmm_hardening_active_at(height)` is true, rejects non-canonical
/// `PQ1` encodings (`salt || key`, salt-free explicit, trailing bytes).
pub(super) fn require_pq_tx_envelope_at_height(
    tx: &crate::sharding::Transaction,
    height: u64,
) -> Result<(), String> {
    if tx.delegation().is_some() {
        return Ok(());
    }
    let Some(env) = tx.pq_envelope_at_height(height) else {
        return Err(
            "Pure PQ mode: classical or non-canonical PQ1 transactions rejected at this height"
                .to_string(),
        );
    };
    if !env.scheme.is_post_quantum() {
        return Err(
            "Pure PQ mode: scheme must be post-quantum (Falcon-512; ML-DSA-44 has no verifier)"
                .to_string(),
        );
    }
    Ok(())
}

/// Resolve per-transaction signature validity for a block: attested
/// transactions skip crypto; every other transaction is verified exactly as
/// before (parallel batch over the unattested subset, scalar fallback per
/// item). Newly verified transactions are attested for future blocks.
/// The returned vector is true iff that transaction's signature is valid.
#[allow(dead_code)] // GATE: kept as legacy pre-height wrapper alongside verify_block_tx_signatures_at_height
pub(super) fn resolve_block_sig_validity(
    txs: &[crate::sharding::Transaction],
    expected_chain: u64,
) -> Vec<bool> {
    resolve_block_sig_validity_inner(txs, expected_chain, None)
}

/// Height-gated variant of [`resolve_block_sig_validity`]: at/after
/// `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT`, non-canonical `PQ1` envelopes
/// are rejected before consulting `verified_signature_covers`.
pub(super) fn verify_block_tx_signatures_at_height(
    txs: &[crate::sharding::Transaction],
    expected_chain: u64,
    height: u64,
) -> Vec<bool> {
    resolve_block_sig_validity_inner(txs, expected_chain, Some(height))
}

fn resolve_block_sig_validity_inner(
    txs: &[crate::sharding::Transaction],
    expected_chain: u64,
    height: Option<u64>,
) -> Vec<bool> {
    let mut out = vec![false; txs.len()];
    let mut need: Vec<usize> = Vec::new();
    for (i, tx) in txs.iter().enumerate() {
        // FULL-PQ: classical (and at >= H non-canonical PQ1) envelopes never
        // reach crypto or the verify-once cache — fail closed here
        // (admission-stage: left false, so the block pre-check skips them
        // with no fee, no nonce, exactly like a bad signature).
        let envelope_ok = match height {
            Some(h) => require_pq_tx_envelope_at_height(tx, h),
            None => require_pq_tx_envelope(tx),
        };
        if envelope_ok.is_err() {
            continue;
        }
        if verified_signature_covers(tx, expected_chain) {
            out[i] = true;
        } else {
            need.push(i);
        }
    }
    if need.is_empty() {
        return out;
    }
    // Batch-verify ONLY the unattested subset: cloning here is a memcpy
    // (~µs), while the crypto it replaces is ~ms. Subset batching is sound
    // because every item verifies against its own message/key (order and
    // membership in the batch never change a per-item verdict).
    let subset: Vec<crate::sharding::Transaction> = need.iter().map(|&i| txs[i].clone()).collect();
    let batch_ok = match height {
        Some(h) => {
            crate::sharding::Transaction::verify_signatures_batch_parallel_at_height(&subset, h)
        }
        None => crate::sharding::Transaction::verify_signatures_batch_parallel(&subset),
    };
    if batch_ok {
        for &i in &need {
            out[i] = true;
            record_verified_signature(&txs[i], expected_chain);
        }
    } else {
        for &i in &need {
            let item_ok = match height {
                Some(h) => txs[i].verify_signature_at_height(h),
                None => txs[i].verify_signature(),
            };
            if item_ok {
                out[i] = true;
                record_verified_signature(&txs[i], expected_chain);
            }
        }
    }
    out
}

/// Verify-once observability (tests and probes): (hits, misses, recorded).
/// Hits = attestations that skipped crypto; misses = full re-verifications.
pub fn verify_once_stats() -> (u64, u64, u64) {
    (
        VERIFY_ONCE_HITS.load(Ordering::Relaxed),
        VERIFY_ONCE_MISSES.load(Ordering::Relaxed),
        VERIFY_ONCE_RECORDED.load(Ordering::Relaxed),
    )
}

/// Reset verify-once counters (tests/probes only; no consensus effect).
pub fn verify_once_reset_stats() {
    VERIFY_ONCE_HITS.store(0, Ordering::Relaxed);
    VERIFY_ONCE_MISSES.store(0, Ordering::Relaxed);
    VERIFY_ONCE_RECORDED.store(0, Ordering::Relaxed);
}

/// Clear all verify-once attestations (tests/probes only; forces re-verify).
pub fn verify_once_clear() {
    verify_once_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .map
        .clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding::Transaction;

    /// The cache is process-global; serialise the cases inside this module.
    static LOCK: Mutex<()> = Mutex::new(());

    fn bare_tx(signature: Vec<u8>, amount: u64) -> Transaction {
        Transaction {
            from: [0x11u8; 32],
            to: [0x22u8; 32],
            amount,
            gas_limit: 50_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature,
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        }
    }

    /// The attestation must bind the EXACT signature bytes on BOTH digest
    /// paths: the classic one (separate sha256 of the signature) and the
    /// optimised one (the signature is already committed by `tx_hash` for
    /// PQ/EVM-framed transactions, so no second pass is made). A one-bit
    /// signature mutation, an amount mutation and a different chain context
    /// all have to miss — i.e. the shortcut removes a hash pass, never a
    /// binding.
    #[test]
    fn attestation_binds_exact_bytes_on_both_digest_paths() {
        let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        verify_once_clear();
        for framed_pq in [false, true] {
            let signature = if framed_pq {
                // PQ1 framing ⇒ `tx_hash` folds the whole signature into its
                // preimage ⇒ `signature_digest` returns the zero digest.
                let mut s = b"PQ1".to_vec();
                s.extend_from_slice(&[0x42u8; 700]);
                s
            } else {
                vec![0x42u8; 64]
            };
            assert_eq!(
                signature_digest(&bare_tx(signature.clone(), 7)),
                if framed_pq {
                    [0u8; 32]
                } else {
                    sha256_bytes(&signature)
                },
                "digest path selection"
            );

            let tx = bare_tx(signature, 7);
            record_verified_signature(&tx, 5);
            assert!(
                verified_signature_covers(&tx, 5),
                "the exact attested bytes must cover"
            );

            let mut bad_sig = tx.clone();
            let last = bad_sig.signature.len() - 1;
            bad_sig.signature[last] ^= 0x01;
            assert!(
                !verified_signature_covers(&bad_sig, 5),
                "one flipped signature bit must miss the attestation"
            );

            let mut bad_amount = tx.clone();
            bad_amount.amount += 1;
            assert!(
                !verified_signature_covers(&bad_amount, 5),
                "an amount mutation must miss the attestation"
            );

            assert!(
                !verified_signature_covers(&tx, 6),
                "the same bytes under another chain context must miss"
            );
        }
        verify_once_clear();
    }
}
