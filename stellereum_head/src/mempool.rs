//! Transaction mempool: fee-priority ordering, bounded size with eviction, and
//! per-sender anti-flood limits. Pure and synchronous; the network layer feeds
//! transactions in and the block producer pulls the highest-fee ones out.

use crate::post_quantum::StatefulImplicitKeyRegistry;
use crate::sharding::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

pub type TxHash = [u8; 32];

/// Maximum out-of-order nonces buffered per unactivated account (§2.3).
pub const MAX_ACTIVATION_BUFFER_NONCES_PER_ACCOUNT: usize = 16;

/// State Rent Surcharge (~45,000 gas) for activation transactions carrying
/// raw post-quantum public keys (§2.2).
pub const PQ_ACTIVATION_SURCHARGE_GAS: u64 = 45_000;

/// Buffers out-of-order nonces for unactivated accounts (up to 16 nonces per account)
/// when Tx2 arrives before Tx1 (Stellereum PQ-BFT v5 spec §2.3).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PendingActivationBuffer {
    /// sender -> (nonce -> Transaction)
    pub(crate) buffered: HashMap<[u8; 32], BTreeMap<u64, Transaction>>,
    /// hash -> (sender, nonce)
    pub(crate) by_hash: HashMap<TxHash, ([u8; 32], u64)>,
    /// hash -> admission wall-clock seconds
    #[serde(default)]
    pub(crate) inserted_at: HashMap<TxHash, u64>,
}

impl PendingActivationBuffer {
    pub const MAX_NONCES_PER_ACCOUNT: usize = MAX_ACTIVATION_BUFFER_NONCES_PER_ACCOUNT;
    pub const MAX_GLOBAL_BUFFERED_TXS: usize = 2048;

    pub fn new() -> Self {
        Self {
            buffered: HashMap::new(),
            by_hash: HashMap::new(),
            inserted_at: HashMap::new(),
        }
    }

    /// Buffer an out-of-order transaction for an unactivated account.
    /// Enforces:
    /// - Minimum fee floor (`tx.gas_limit >= min_fee`) to prevent unmetered spam.
    /// - Global buffer ceiling (`MAX_GLOBAL_BUFFERED_TXS = 2048`) against multi-account memory DoS.
    /// - Up to 16 buffered nonces per unactivated account.
    /// - Deduplication by transaction hash and stale-hash pruning on overwrite.
    pub fn buffer_tx(&mut self, tx: Transaction, min_fee: u64) -> Result<TxHash, MempoolError> {
        self.buffer_tx_with_timestamp(tx, min_fee, crate::zkml::now_secs()).map(|(h, _)| h)
    }

    /// Buffer an out-of-order transaction with an explicit wall-clock timestamp.
    /// Returns the transaction hash and any replaced older transaction for the same nonce.
    pub fn buffer_tx_with_timestamp(
        &mut self,
        tx: Transaction,
        min_fee: u64,
        now_secs: u64,
    ) -> Result<(TxHash, Option<Transaction>), MempoolError> {
        if self.by_hash.len() >= Self::MAX_GLOBAL_BUFFERED_TXS {
            return Err(MempoolError::TooManyFromSender);
        }
        if tx.gas_limit < min_fee {
            return Err(MempoolError::FeeTooLow);
        }
        let hash = tx.compute_tx_hash();
        if self.by_hash.contains_key(&hash) {
            return Err(MempoolError::Duplicate);
        }
        let sender = tx.from;
        let nonce = tx.nonce;
        let account_entry = self.buffered.entry(sender).or_default();
        if account_entry.len() >= Self::MAX_NONCES_PER_ACCOUNT
            && !account_entry.contains_key(&nonce)
        {
            return Err(MempoolError::TooManyFromSender);
        }
        let old_tx = account_entry.insert(nonce, tx);
        if let Some(ref old) = old_tx {
            let old_hash = old.compute_tx_hash();
            self.by_hash.remove(&old_hash);
            self.inserted_at.remove(&old_hash);
        }
        self.by_hash.insert(hash, (sender, nonce));
        self.inserted_at.insert(hash, now_secs);
        Ok((hash, old_tx))
    }

    /// Lookup a buffered transaction by account and nonce.
    pub fn get(&self, account: &[u8; 32], nonce: u64) -> Option<&Transaction> {
        self.buffered.get(account).and_then(|m| m.get(&nonce))
    }

    /// Lookup a buffered transaction by hash.
    pub fn get_by_hash(&self, hash: &TxHash) -> Option<&Transaction> {
        let (sender, nonce) = self.by_hash.get(hash)?;
        self.get(sender, *nonce)
    }

    /// Check if a hash is in the buffer.
    pub fn contains_hash(&self, hash: &TxHash) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Check if an account has any buffered nonces.
    pub fn has_account(&self, account: &[u8; 32]) -> bool {
        self.buffered.get(account).map_or(false, |m| !m.is_empty())
    }

    /// Number of nonces buffered for a specific account.
    pub fn count_for_account(&self, account: &[u8; 32]) -> usize {
        self.buffered.get(account).map_or(0, |m| m.len())
    }

    /// Returns list of buffered nonces for the account in ascending order.
    pub fn nonces_for_account(&self, account: &[u8; 32]) -> Vec<u64> {
        self.buffered
            .get(account)
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Total number of transactions buffered across all accounts.
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Drain all buffered transactions for an account in ascending nonce order.
    pub fn drain_account(&mut self, account: &[u8; 32]) -> Vec<Transaction> {
        let Some(map) = self.buffered.remove(account) else {
            return Vec::new();
        };
        for tx in map.values() {
            let h = tx.compute_tx_hash();
            self.by_hash.remove(&h);
            self.inserted_at.remove(&h);
        }
        map.into_values().collect()
    }

    /// Drain transactions for an account that form a contiguous sequence starting from `start_nonce`.
    pub fn drain_contiguous(&mut self, account: &[u8; 32], mut start_nonce: u64) -> Vec<Transaction> {
        let mut ready = Vec::new();
        if let Some(map) = self.buffered.get_mut(account) {
            while let Some(tx) = map.remove(&start_nonce) {
                let h = tx.compute_tx_hash();
                self.by_hash.remove(&h);
                self.inserted_at.remove(&h);
                ready.push(tx);
                start_nonce = start_nonce.saturating_add(1);
            }
            if map.is_empty() {
                self.buffered.remove(account);
            }
        }
        ready
    }

    /// Remove a single transaction by hash.
    pub fn remove_by_hash(&mut self, hash: &TxHash) -> Option<Transaction> {
        self.inserted_at.remove(hash);
        let (sender, nonce) = self.by_hash.remove(hash)?;
        let tx = self.buffered.get_mut(&sender).and_then(|m| m.remove(&nonce));
        if self.buffered.get(&sender).map_or(false, |m| m.is_empty()) {
            self.buffered.remove(&sender);
        }
        tx
    }

    /// Drain stale entries that have been buffered longer than TTL.
    pub fn drain_stale(&mut self, now_secs: u64, ttl_secs: u64) -> Vec<Transaction> {
        let expired: Vec<TxHash> = self
            .by_hash
            .keys()
            .filter_map(|hash| {
                let inserted = self.inserted_at.get(hash).copied().unwrap_or(now_secs);
                if now_secs.saturating_sub(inserted) >= ttl_secs {
                    Some(*hash)
                } else {
                    None
                }
            })
            .collect();
        let mut out = Vec::with_capacity(expired.len());
        for hash in &expired {
            if let Some(tx) = self.remove_by_hash(hash) {
                out.push(tx);
            }
        }
        out
    }

    /// Prune stale entries that have been buffered longer than TTL.
    pub fn prune_stale(&mut self, now_secs: u64, ttl_secs: u64) -> usize {
        self.drain_stale(now_secs, ttl_secs).len()
    }
}

/// Context every admission path passes in: the time the admission decision is
/// made at. Node-local policy only (mempool entry) — consensus re-checks the
/// same delegation rules against the BLOCK timestamp, which is the
/// deterministic clock (see `Transaction::check_session_policy`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionCtx {
    pub now: u64,
    /// The sender's on-chain nonce, when the caller already read it (F-02).
    /// `insert` enforces [`Mempool::check_nonce_gap`] against this head and
    /// fail-closed SKIPS (returns `Err`, deletes nothing) past-window
    /// nonces — the same fail-fast the RPC/gossip/restore call sites run
    /// before calling in. `None` (every legacy `wall_now()` caller) keeps
    /// exactly today's behavior: those paths' own pre-checks, where present,
    /// remain the enforcement point. Threading it here puts the check at the
    /// single choke point every admission funnels through, so any future
    /// caller that carries the head is enforced without a second pre-check.
    pub onchain_nonce: Option<u64>,
}

impl AdmissionCtx {
    pub fn new(now: u64) -> Self {
        Self { now, onchain_nonce: None }
    }

    /// Admission against the local wall clock. Used by the live admission
    /// paths (RPC, faucet, runtime, gossip, mempool restore) — mempool entry
    /// is node-local policy, exactly like the base fee, and is re-checked at
    /// propose/execute with the block timestamp.
    pub fn wall_now() -> Self {
        Self {
            now: crate::zkml::now_secs(),
            onchain_nonce: None,
        }
    }

    /// Carry the sender's on-chain nonce so [`Mempool::insert`] enforces the
    /// nonce-gap fail-fast itself (F-02). Pure builder: the clock is untouched.
    pub fn with_onchain_nonce(mut self, onchain_nonce: u64) -> Self {
        self.onchain_nonce = Some(onchain_nonce);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MempoolError {
    BadSignature,
    Duplicate,
    TooManyFromSender,
    Full,
    NotFound,
    /// The sender cannot pay `amount + gas_limit` at the time of admission.
    InsufficientBalance,
    /// The offered fee is below the current base fee.
    FeeTooLow,
    /// The nonce is too far ahead of the sender's executable head (audit:
    /// blocks troubles — far-future nonces sat in the pool forever, blocking
    /// empty heights behind them, because nothing rejected them at admission
    /// and nothing evicted them later). Fail fast with a clear reason instead
    /// of clogging the pool: the sender must fill the gap first.
    NonceGap { expected: u64, got: u64 },
    /// The session-key delegation is past `valid_until` at admission time.
    SessionExpired,
    /// The session-key delegation cannot authorize this spend: its remaining
    /// gas budget (`max_gas_spend - gas_spent`) does not cover the declared
    /// `gas_limit`, OR the on-chain session-key registry says the key has been
    /// revoked by its master (phase 2 - the stateful form of the same
    /// "this grant is no longer good for this" verdict; both are terminal for
    /// this transaction).
    SessionRevoked,
    /// The delegation's scope mask does not cover this transaction kind, or
    /// `amount` exceeds `max_value_per_tx`.
    SessionOutOfScope,
    /// The envelope carries an unusable grant: `master_address` is not the
    /// sender, or the master's grant signature is missing/invalid/tampered.
    SessionBadGrant,
    /// Transaction payload or structure is malformed or violates protocol mode.
    Malformed(String),
    /// The transaction alone exceeds the block wire cap (`MAX_BLOCK_WIRE_BYTES`):
    /// no honest packing can ever include it, so admitting it would only let it
    /// occupy pool space (and fee-evict honest transactions) forever. Fail
    /// closed at admission.
    TxTooLarge { wire_bytes: usize, cap: usize },
    /// The transaction alone exceeds the block proof-unit cap
    /// (`MAX_BLOCK_PROOF_UNITS`): packing skips it at every height, so it could
    /// never execute. Fail closed at admission.
    TxTooManyProofs { proof_units: usize, cap: usize },
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MempoolError::BadSignature => "invalid transaction signature",
            MempoolError::Duplicate => "transaction already in mempool",
            MempoolError::TooManyFromSender => "sender exceeds mempool quota",
            MempoolError::Full => "mempool is full and tx fee is too low",
            MempoolError::NotFound => "transaction not found",
            MempoolError::InsufficientBalance => "sender cannot pay amount + gas_limit",
            MempoolError::FeeTooLow => "offered fee is below the base fee",
            MempoolError::NonceGap { expected, got } => {
                return write!(
                    f,
                    "nonce gap: sender can execute {expected}, got {got} (fill the gap first)"
                )
            }
            MempoolError::SessionExpired => "session key delegation has expired",
            MempoolError::SessionRevoked => {
                "session key delegation has been revoked or has no remaining budget"
            }
            MempoolError::SessionOutOfScope => {
                "session key delegation does not cover this transaction"
            }
            MempoolError::SessionBadGrant => "invalid session key delegation grant",
            MempoolError::Malformed(reason) => return write!(f, "malformed transaction: {reason}"),
            MempoolError::TxTooLarge { wire_bytes, cap } => {
                return write!(
                    f,
                    "transaction too large: estimated {wire_bytes} wire bytes exceeds block cap {cap}"
                )
            }
            MempoolError::TxTooManyProofs { proof_units, cap } => {
                return write!(
                    f,
                    "transaction carries {proof_units} proof units, exceeding block cap {cap}"
                )
            }
        };
        write!(f, "{s}")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mempool {
    /// hash -> transaction
    txs: HashMap<TxHash, Transaction>,
    /// (fee, hash) -> hash : ascending, so `.rev()` yields highest fee first
    order: BTreeMap<(u64, TxHash), TxHash>,
    /// sender -> number of pending txs
    per_sender: HashMap<[u8; 32], usize>,
    /// sender -> sum of `tx_cost` over their pooled transactions (audit-mempool
    /// F-03: balance never reserved — one funding backed all 256 per-sender
    /// slots, so a Sybil squatter filled its whole quota with mutually
    /// unaffordable txs. Every admission on the checked path now refuses when
    /// `reserved + new_cost > sender_balance`, so pooled txs are jointly
    /// affordable, not just individually. Maintained in `insert`/`evict`
    /// (the only `txs` mutators); `#[serde(skip)]` like `mev`: the encoded
    /// layout is unchanged, and `load_into` rebuilds it by re-running
    /// admission for every restored tx).
    #[serde(skip)]
    reserved: HashMap<[u8; 32], u64>,
    /// hash -> admission wall-clock seconds (audit: blocks troubles — TTL
    /// eviction for stuck txs; cleaned in `evict` with everything else).
    inserted_at: HashMap<TxHash, u64>,
    pub max_size: usize,
    pub per_sender_limit: usize,
    /// Minimum fee (`gas_limit`) accepted on the checked/network path (A11).
    ///
    /// FEE-MARKET HONESTY (audit F-11, verified as-stated): there is NO
    /// dynamic fee market — this is a STATIC, node-local, gas-unit floor
    /// (`max(STELL_MIN_GAS_LIMIT env, governed min_gas_limit)`, synced every
    /// finalize; a mismatch across validators diverges admission liveness
    /// only, never consensus). Pool-full behavior is a fee AUCTION (evict
    /// lowest iff the newcomer bids ≥2× it), not FIFO. Congestion never
    /// propagates to wallets: `eth_gasPrice`/`eth_feeHistory` serve hardcoded
    /// TESTNET-KNOWN constants (documented in `evm_adapter.rs`, different
    /// units by design, deliberately unmapped) — EVM fee fields are
    /// decorative until a mempool-pressure feed drives them.
    pub base_fee: u64,
    /// Handle on the state engine's ON-CHAIN session-key registry.
    ///
    /// Retained for construction-site/API compatibility, but NO LONGER read on
    /// the synchronous admission path: `try_read` could silently skip the
    /// stateful check under lock contention, which is not a reproducible
    /// admission decision. The authoritative registry check runs in the
    /// proposer filter and in execution (`session_gate`), against the committed
    /// registry and the block clock - see the note in `insert`.
    ///
    /// `#[serde(skip)]` like `mev`: pending transactions persist, the registry
    /// lives in consensus state and is re-read by the consensus paths.
    #[serde(skip)]
    #[allow(dead_code)]
    session_registry: Option<std::sync::Arc<tokio::sync::RwLock<crate::zkml::SessionKeyRegistry>>>,
    /// Node-local MEV preemption engine. Seals every admitted transaction
    /// (envelopes kept inside the engine, keyed by tx hash) so the block build
    /// can re-open and byte-compare it before execution, and records the
    /// build-time order commitment the finalize path verifies.
    ///
    /// `#[serde(skip)]` is deliberate and load-bearing: the field is never
    /// encoded, so the bincode layout of `Mempool` is byte-identical to the
    /// pre-engine format in BOTH directions — existing `data/mempool.bin`
    /// files load unchanged, and files written by this build remain readable
    /// by older binaries. Envelopes and commitments are in-memory evidence:
    /// restored transactions are re-sealed during `load_into` (it re-runs the
    /// admission path), and `SealVerdict::NotSealed` is the defensive case
    /// for a transaction that entered the pool without an envelope.
    #[serde(skip)]
    pub mev: crate::mev::MevPreemptionEngine,
    /// Extra per-sender admission floor after apply failures (D2 free-failure
    /// gate): sender -> penalty added to `base_fee` for their next submissions.
    /// A transaction that FAILS at apply pays nothing (the native commit is
    /// atomic) while its bytes occupied block wire/gas and burned verifier
    /// CPU, so a failing sender is free to retry forever. The runtime feeds
    /// each applied block's verdicts back via `note_apply_feedback`; penalized
    /// senders must post a higher `gas_limit` (a bond in fee form) to re-enter.
    /// Success clears the penalty. Node-local policy exactly like `base_fee`
    /// (never consensus state), so `#[serde(skip)]` like `mev`: the encoded
    /// layout is unchanged and restarts begin unpenalized.
    #[serde(skip)]
    failed_penalty: HashMap<[u8; 32], u64>,
    /// Buffer for out-of-order nonces for unactivated accounts (§2.3).
    #[serde(skip)]
    pub activation_buffer: PendingActivationBuffer,
    /// Optional thread-safe implicit key registry handle. Defaults to global registry if unset.
    #[serde(skip)]
    pub implicit_registry: Option<StatefulImplicitKeyRegistry>,
    /// Optional node-local pure post-quantum mode override.
    #[serde(skip)]
    pub pure_pq_enforced: Option<bool>,
}

/// Bond a previously-failing sender must over-post per re-admission (D2).
/// One basic-transfer fee: doubles the cost of the cheapest retry while
/// staying trivial for any funded honest sender that hit one bad nonce.
pub const FAILED_SENDER_PENALTY: u64 = crate::svm::GAS_BASIC_TRANSFER;
/// Hard ceiling for the accumulated per-sender penalty (D2): repeated
/// failures escalate linearly but never overflow the floor arithmetic and
/// never price out a sender permanently — the worst case is bounded, and one
/// applied transaction clears it entirely.
pub const MAX_FAILED_SENDER_PENALTY: u64 = 10 * crate::svm::GAS_BASIC_TRANSFER;

impl Default for Mempool {
    fn default() -> Self {
        let max_size = std::env::var("STELL_MEMPOOL_CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50_000);
        let per_sender = std::env::var("STELL_MEMPOOL_PER_SENDER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024);
        Self::new(max_size, per_sender)
    }
}

impl Mempool {
    pub fn new(max_size: usize, per_sender_limit: usize) -> Self {
        Self {
            txs: HashMap::new(),
            order: BTreeMap::new(),
            per_sender: HashMap::new(),
            reserved: HashMap::new(),
            inserted_at: HashMap::new(),
            max_size,
            per_sender_limit,
            // No base fee by default; governance/config raises it under load.
            base_fee: 0,
            session_registry: None,
            mev: crate::mev::MevPreemptionEngine::new(),
            failed_penalty: HashMap::new(),
            activation_buffer: PendingActivationBuffer::new(),
            implicit_registry: None,
            pure_pq_enforced: None,
        }
    }

    /// Explicitly configure Pure Post-Quantum mode for this mempool instance.
    pub fn with_pure_pq(mut self, enabled: bool) -> Self {
        self.pure_pq_enforced = Some(enabled);
        self
    }

    /// Magic prefix for versioned mempool files (see `save`).
    pub const MEMPOOL_FILE_MAGIC: &[u8; 4] = b"MP02";
    /// How far ahead of the sender's executable head a nonce may be at
    /// admission (audit: blocks troubles). Rapid sequential submits stay
    /// inside; wild gaps fail fast with `NonceGap` instead of clogging the
    /// pool behind an unreachable head.
    pub const NONCE_FUTURE_WINDOW: u64 = 16;
    /// Wall-clock seconds after which an UNEXECUTABLE tx is swept (audit:
    /// blocks troubles). Executable txs are never touched no matter their
    /// age — only ones the pool could never include.
    pub const STUCK_TX_TTL_SECS: u64 = 1800;
    /// Wire-size packing cap per block (audit: blocks troubles): gas-valid
    /// blocks can exceed what gossip can carry (32MB proposal cap), so the
    /// proposer stops packing at ~24MB estimated wire and leaves headroom.
    /// Estimate, not exact bincode (see `estimate_tx_wire_bytes`).
    pub const MAX_BLOCK_WIRE_BYTES: usize = 24 * 1024 * 1024;
    /// Verified-proof cap per block (audit: blocks troubles): range proofs
    /// and Groth16 verifies serialize on the single apply worker while
    /// `apply_in_flight` blocks the next propose. Bounds worst-case lane
    /// stall per height; gas alone does not (cheap gas, costly verify).
    pub const MAX_BLOCK_PROOF_UNITS: usize = 2048;

    /// Set the base fee (minimum accepted fee). Builder-style.
    pub fn with_base_fee(mut self, base_fee: u64) -> Self {
        self.base_fee = base_fee;
        self
    }

    /// Admission floor for `sender`: `base_fee` plus any failure penalty the
    /// sender is carrying (D2). The proposer filter snapshots this per sender
    /// so pooled retries of a failing sender are skipped until they over-post.
    pub fn effective_floor(&self, sender: &[u8; 32]) -> u64 {
        self.base_fee.saturating_add(self.failed_penalty.get(sender).copied().unwrap_or(0))
    }

    /// Full admission cost of one transaction: `amount + gas_limit`, plus the
    /// State Rent Surcharge for activation txs. This is exactly what execution
    /// charges (`state_engine`), so it is both the single-tx balance check and
    /// the per-sender reservation unit (F-03). Single definition so the two
    /// can never drift apart.
    pub fn tx_cost(tx: &Transaction) -> u64 {
        tx.amount.saturating_add(tx.gas_limit).saturating_add(if tx.is_pq_activation() {
            PQ_ACTIVATION_SURCHARGE_GAS
        } else {
            0
        })
    }

    /// Funds already claimed by `sender`'s pooled transactions (F-03). A new
    /// checked admission is refused when `reserved_for(sender) + tx_cost(new)`
    /// exceeds the sender's balance, so one funding cannot back more slots
    /// than it can jointly pay for.
    pub fn reserved_for(&self, sender: &[u8; 32]) -> u64 {
        self.reserved.get(sender).copied().unwrap_or(0)
    }

    /// Minimum bid that may displace the cheapest pooled transaction
    /// (audit-mempool F-04): at least 2x the lowest fee in the pool.
    ///
    /// Choice rationale (evict-only-at->=2x, NOT a per-sender-per-minute eviction
    /// cap): the premium is deterministic and stateless — no wall-clock, no new
    /// per-sender timestamps for an attacker to grind against, no cross-call
    /// accounting that honest bursts could trip. Full-pool churn that used to
    /// cost fee+1 per displacement now doubles the floor every sweep, so
    /// replacing the pool costs 2x+ the honest total. Honest traffic is
    /// unaffected: this gate runs ONLY when the pool is already full (a
    /// non-full pool admits every floor-passing tx), and a full pool means
    /// genuine congestion where a premium is the honest price signal anyway.
    fn eviction_bid_beats(fee: u64, low_fee: u64) -> bool {
        fee > low_fee && fee >= low_fee.saturating_mul(2)
    }

    /// Admission floor for `tx`: includes failure penalty floor, plus
    /// the State Rent Surcharge (~45,000 gas) if this is an activation
    /// transaction carrying raw public keys.
    pub fn effective_floor_for_tx(&self, tx: &Transaction) -> u64 {
        let base = self.effective_floor(&tx.from);
        if tx.is_pq_activation() {
            base.saturating_add(PQ_ACTIVATION_SURCHARGE_GAS)
        } else {
            base
        }
    }

    /// Attach an explicit thread-safe implicit key registry for post-quantum validation.
    pub fn with_implicit_registry(mut self, registry: StatefulImplicitKeyRegistry) -> Self {
        self.implicit_registry = Some(registry);
        self
    }

    /// Access the active implicit key registry (custom or global singleton).
    pub fn implicit_registry(&self) -> &StatefulImplicitKeyRegistry {
        self.implicit_registry
            .as_ref()
            .unwrap_or_else(|| Transaction::global_implicit_registry())
    }

    /// Explicitly buffer an unactivated transaction in the activation buffer.
    pub fn buffer_activation_tx(&mut self, tx: Transaction) -> Result<TxHash, MempoolError> {
        // PQ activation surcharge: the drain path re-admits through the full
        // `effective_floor_for_tx` check, so flooring the buffer on the bare
        // sender floor admits under-priced activation txs that squat in the
        // 2048-slot global buffer until drain re-prices them. Mirror admission
        // exactly. Node-local policy only (never consensus state), matching
        // the existing floor check direction: fail-closed on spam, no validity
        // rule changes.
        let floor = self.effective_floor_for_tx(&tx);
        self.activation_buffer.buffer_tx(tx, floor)
    }

    /// Process and drain all pending activation transactions for a sender.
    pub fn process_activation_buffer(&mut self, sender: &[u8; 32]) -> Vec<TxHash> {
        let pending = self.activation_buffer.drain_account(sender);
        let mut admitted = Vec::new();
        let ctx = AdmissionCtx::wall_now();
        for tx in pending {
            let hash = tx.compute_tx_hash();
            if self.insert(tx, u64::MAX, false, ctx).is_ok() {
                admitted.push(hash);
            }
        }
        admitted
    }

    /// Check if a transaction is currently waiting in the activation buffer.
    pub fn is_buffered(&self, hash: &TxHash) -> bool {
        self.activation_buffer.contains_hash(hash)
    }

    /// Snapshot of the per-sender failure penalties for the proposer filter,
    /// which is synchronous and cannot consult the pool mid-walk.
    pub fn penalty_snapshot(&self) -> HashMap<[u8; 32], u64> {
        self.failed_penalty.clone()
    }

    /// Feed one applied block's verdicts back into admission policy (D2).    ///
    /// Every `failed` sender's penalty grows by one bond step (capped);
    /// every `succeeded` sender is cleared. Called by the runtime after each
    /// apply with the block's own (sender, status) pairs, so the penalty
    /// tracks exactly the transactions that consumed block space for free.
    /// A sender in both lists (one tx applied, another failed) keeps the
    /// penalty: a failure happened, and the next submission must bond for it.
    pub fn note_apply_feedback(&mut self, failed: &[[u8; 32]], succeeded: &[[u8; 32]]) {
        for s in failed {
            if succeeded.contains(s) {
                continue;
            }
            let e = self.failed_penalty.entry(*s).or_insert(0);
            *e = (*e)
                .saturating_add(FAILED_SENDER_PENALTY)
                .min(MAX_FAILED_SENDER_PENALTY);
        }
        for s in succeeded {
            if !failed.contains(s) {
                self.failed_penalty.remove(s);
            }
        }
    }

    /// Read the per-node admission floor from the environment.
    ///
    /// CONSENSUS WARNING (audit 2026-10-06): this is enforced ONLY at
    /// admission, never in the proposer filter or apply path, and it is read
    /// per process — two validators with different `STELL_MIN_GAS_LIMIT`
    /// silently admit different tx sets (liveness divergence, not a split:
    /// consensus never disagrees, one node just skips). ALL validators MUST
    /// run the identical value; node startup logs the effective floor at
    /// info so a mismatch is visible in the first lines of every journal.
    pub fn read_base_fee_from_env() -> u64 {
        std::env::var("STELL_MIN_GAS_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(crate::svm::GAS_BASIC_TRANSFER)
    }

    /// Attach the engine's session-key registry lock (see
    /// `InMemoryStateEngine::session_keys_handle`). Kept so every node
    /// construction site and the public API stay unchanged; the synchronous
    /// admission path no longer consults it (the authoritative check is the
    /// consensus `session_gate`), so this is currently a no-op for admission.
    pub fn with_session_registry(
        mut self,
        handle: std::sync::Arc<tokio::sync::RwLock<crate::zkml::SessionKeyRegistry>>,
    ) -> Self {
        self.session_registry = Some(handle);
        self
    }

    /// Attach a pre-built MEV preemption engine. Builder-style, so the node
    /// constructs the engine once and hands it to the shared pool instead of a
    /// second engine existing somewhere unused.
    pub fn with_mev_engine(mut self, engine: crate::mev::MevPreemptionEngine) -> Self {
        self.mev = engine;
        self
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Persist pending transactions to disk (mempool survival across restarts).
    /// A restart with an empty mempool is a silent fund-loss: users' and faucet's
    /// valid transactions vanish, nonces gap, and load tests abort. Best-effort:
    /// any IO or decode error yields None and the node starts with an empty
    /// pool (transactions can always be resubmitted; executing a corrupt one
    /// can never happen because every loaded tx is re-admitted below).
    ///
    /// Versioned envelope (audit: blocks troubles): `inserted_at` joined the
    /// struct, so files carry a magic prefix — `b"MP02" + bincode(self)`.
    /// `load_into` reads the prefix and falls back to the legacy bare-bincode
    /// layout, so pre-TTL files restore (with fresh timestamps) instead of
    /// silently vanishing.
    pub fn save(&self, path: &std::path::Path) {
        if self.txs.is_empty() {
            let _ = std::fs::remove_file(path);
            return;
        }
        if let Ok(mut bytes) = bincode::serialize(self) {
            let mut out = Self::MEMPOOL_FILE_MAGIC.to_vec();
            out.append(&mut bytes);
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(path, out);
        }
    }

    /// Load persisted transactions, re-admitting each against CURRENT state
    /// (nonce/balance/signature/quota/grant policy). Stale entries (already
    /// executed while we were down, or invalid under current rules) are
    /// dropped and counted. `ctx` supplies the admission clock (an expired
    /// session-key delegation is not re-admitted at startup).
    /// Returns the number kept.
    pub async fn load_into(
        &mut self,
        path: &std::path::Path,
        accounts: &crate::state_engine::InMemoryStateEngine,
        ctx: AdmissionCtx,
    ) -> usize {
        let Ok(bytes) = std::fs::read(path) else {
            return 0;
        };
        // Versioned envelope with legacy fallback (see `save`): strip the
        // magic if present, else decode the bare pre-TTL layout directly.
        // Legacy entries re-admit with fresh timestamps (their age restarts
        // instead of their txs vanishing).
        let body: &[u8] = match bytes.strip_prefix(Self::MEMPOOL_FILE_MAGIC) {
            Some(b) => b,
            None => &bytes,
        };
        // Pre-TTL layout mirror (no `inserted_at`): bincode cannot skip a
        // missing trailing field, so legacy files decode here explicitly and
        // re-enter with fresh timestamps.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct LegacyMempool {
            txs: HashMap<TxHash, Transaction>,
            order: BTreeMap<(u64, TxHash), TxHash>,
            per_sender: HashMap<[u8; 32], usize>,
            max_size: usize,
            per_sender_limit: usize,
            base_fee: u64,
        }
        let saved: Mempool =
            if let Ok(s) = bincode::deserialize::<Mempool>(body) {
                s
            } else if let Ok(legacy) = bincode::deserialize::<LegacyMempool>(body) {
                let mut m = Mempool::new(
                    legacy.max_size,
                    legacy.per_sender_limit,
                )
                .with_base_fee(legacy.base_fee);
                m.txs = legacy.txs;
                m.order = legacy.order;
                m.per_sender = legacy.per_sender;
                m
            } else {
                return 0;
            };
        let mut kept = 0usize;
        let mut order: Vec<_> = saved.txs.values().cloned().collect();
        // Oldest-nonce-first per sender so a contiguous sequence re-admits in
        // full instead of tripping over its own gaps.
        order.sort_by_key(|t| (t.from, t.nonce));
        for tx in order {
            let acct = accounts.get_account(&tx.from).await;
            let bal = acct.as_ref().map(|a| a.balance).unwrap_or(0);
            let onchain = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
            // Nonce-gap fail-fast, same as the live admission paths (audit:
            // blocks troubles): a restored far-future nonce would sit in the
            // pool forever behind an unreachable head. Sequential re-admits
            // pass: the head advances as the sorted prefix goes in. The head
            // is ALSO carried into `insert` (F-02) so the choke point
            // enforces the same verdict even if this pre-check ever drifts.
            if self.check_nonce_gap(&tx.from, tx.nonce, onchain).is_some() {
                continue;
            }
            if self.insert(tx, bal, true, ctx.with_onchain_nonce(onchain)).is_ok() {
                kept += 1;
            }
        }
        kept
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn contains(&self, hash: &TxHash) -> bool {
        self.txs.contains_key(hash) || self.activation_buffer.contains_hash(hash)
    }

    pub fn get(&self, hash: &TxHash) -> Option<&Transaction> {
        self.txs.get(hash).or_else(|| self.activation_buffer.get_by_hash(hash))
    }

    /// Add a transaction. Validates the signature, rejects duplicates, enforces
    /// the per-sender quota, and — if the pool is full — evicts the lowest-fee
    /// transaction when the new one pays more, else rejects it.
    /// Add a transaction WITHOUT checking the sender's balance.
    ///
    /// This is the legacy entry point kept for tests and trusted in-process
    /// callers. It can never evict an existing transaction (a caller that cannot
    /// prove the sender's balance must not be able to displace others by
    /// declaring a huge `gas_limit` for free). New transactions are only
    /// admitted if there is room, otherwise `MempoolError::Full` is returned.
    /// Session-key policy is evaluated against the local wall clock; the live
    /// admission paths pass an explicit clock via `add_checked`.
    pub fn add(&mut self, tx: Transaction) -> Result<TxHash, MempoolError> {
        self.insert(tx, u64::MAX, false, AdmissionCtx::wall_now())
    }

    /// Add a transaction after checking that `sender_balance` covers
    /// `amount + gas_limit`, against the LOCAL WALL CLOCK for session-key
    /// policy. Convenience wrapper for tests and trusted in-process callers;
    /// the live admission paths (RPC, faucet, runtime, gossip, restore) call
    /// [`Mempool::add_checked_ctx`] and pass an explicit [`AdmissionCtx`].
    pub fn add_checked(
        &mut self,
        tx: Transaction,
        sender_balance: u64,
    ) -> Result<TxHash, MempoolError> {
        self.add_checked_ctx(tx, sender_balance, AdmissionCtx::wall_now())
    }

    /// Add a transaction after checking that `sender_balance` covers
    /// `amount + gas_limit`. Only a fully funded transaction may evict a
    /// cheaper one when the mempool is full — this is the anti-DoS entry point
    /// for the RPC and consensus paths.
    ///
    /// `ctx` carries the admission clock: every admission path (RPC
    /// sendRawTransaction, faucet, runtime `add_tx`, P2P gossip ingest, and
    /// mempool restore) passes it so the session-key delegation's expiry /
    /// scope / value / budget rules are evaluated against an explicit time
    /// rather than a hidden local default.
    pub fn add_checked_ctx(
        &mut self,
        tx: Transaction,
        sender_balance: u64,
        ctx: AdmissionCtx,
    ) -> Result<TxHash, MempoolError> {
        self.insert(tx, sender_balance, true, ctx)
    }

    /// Drop transactions that can never be executed, given the current on-chain
    /// state, and return how many were removed.
    ///
    /// `account` yields the current `(nonce, balance)` of a sender. A pending
    /// transaction is dead when its nonce is already consumed, or when the
    /// sender can no longer afford it. Without this, a transaction with a stale
    /// nonce sat in the mempool forever: it was never included (execution
    /// rejects it) yet never pruned either, so it permanently occupied that
    /// nonce slot and blocked every later transaction from the same account —
    /// the sender could brick their own account with one mistyped nonce, and
    /// the mempool grew without bound as junk accumulated.
    ///
    /// Transactions with a nonce *ahead* of the account are kept: they are
    /// simply waiting for the earlier ones.
    /// Drop transactions that can never execute: consumed nonce or
    /// unaffordable at the snapshot the caller supplies. A sender the
    /// snapshot does not know (`None`) is SKIPPED, never treated as broke:
    /// the account may simply be missing from a partial/pre-height view, and
    /// the proposer filter already skips such senders without deleting them
    /// (audit 2026-10-06: the old `(0,0)` default irreversibly destroyed
    /// valid funded transactions).
    pub fn evict_unexecutable<F>(&mut self, mut account: F) -> usize
    where
        F: FnMut(&[u8; 32]) -> Option<(u64, u64)>,
    {
        let doomed: Vec<TxHash> = self
            .txs
            .values()
            .filter_map(|tx| {
                let (nonce, balance) = account(&tx.from)?;
                let stale_nonce = tx.nonce < nonce;
                let unaffordable = tx.amount.saturating_add(tx.gas_limit) > balance;
                if stale_nonce || unaffordable {
                    Some(tx.compute_tx_hash())
                } else {
                    None
                }
            })
            .collect();
        for h in &doomed {
            // evict() keeps the fee index and the per-sender quota in step;
            // removing straight from `txs` would leak both.
            self.evict(h);
        }
        doomed.len()
    }

    fn insert(
        &mut self,
        tx: Transaction,
        sender_balance: u64,
        check_balance: bool,
        ctx: AdmissionCtx,
    ) -> Result<TxHash, MempoolError> {
        let pure_pq = self
            .pure_pq_enforced
            .unwrap_or_else(crate::post_quantum::is_pure_pq_enforced);
        if pure_pq {
            let Some(env) = tx.pq_envelope() else {
                return Err(MempoolError::Malformed(
                    "Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope".to_string(),
                ));
            };
            if !env.scheme.is_post_quantum() {
                return Err(MempoolError::Malformed(
                    "Pure PQ mode: scheme must be post-quantum (Falcon-512, ML-DSA-44, or Hybrid)".to_string(),
                ));
            }
        }

        // Wire + proof-unit caps FIRST (hunt D1, fail-closed): packing
        // (`select_multi`) can never include a transaction that ALONE exceeds
        // the block's wire or verified-proof budget, yet admission used to
        // accept it. Such a poison tx occupies pool space indefinitely — it is
        // executable-looking (valid sig, funded) so no sweep ever removes it —
        // and can fee-evict honest transactions. Reject before any crypto so
        // oversized junk is also cheap to refuse. The estimators are the same
        // ones packing uses, so admitted ⇒ packable holds by construction.
        let wire_bytes = Self::estimate_tx_wire_bytes(&tx);
        if wire_bytes > Self::MAX_BLOCK_WIRE_BYTES {
            return Err(MempoolError::TxTooLarge {
                wire_bytes,
                cap: Self::MAX_BLOCK_WIRE_BYTES,
            });
        }
        let proof_units = Self::count_tx_proof_units(&tx);
        if proof_units > Self::MAX_BLOCK_PROOF_UNITS {
            return Err(MempoolError::TxTooManyProofs {
                proof_units,
                cap: Self::MAX_BLOCK_PROOF_UNITS,
            });
        }
        // Session-key delegation policy next (expiry / scope / value cap /
        // budget / grant validity), so an unusable grant is reported as such
        // instead of a generic signature failure; the signature check below
        // covers the session signature AND re-covers the master's grant.
        if let Err(e) = tx.check_session_policy(ctx.now) {
            return Err(match e {
                crate::sharding::SessionPolicyError::Expired => MempoolError::SessionExpired,
                crate::sharding::SessionPolicyError::OutOfScope => MempoolError::SessionOutOfScope,
                crate::sharding::SessionPolicyError::BudgetExhausted => {
                    MempoolError::SessionRevoked
                }
                crate::sharding::SessionPolicyError::BadGrant => MempoolError::SessionBadGrant,
            });
        }
        // F-02 nonce-gap fail-fast AT the choke point (audit: blocks
        // troubles): every admission funnels through `insert`, but only the
        // RPC/gossip/restore call sites pre-checked `check_nonce_gap` — any
        // path that forgot (or any future one) admitted far-future nonces
        // that sit behind an unreachable head forever. When the caller
        // carries the on-chain head (`AdmissionCtx::with_onchain_nonce`),
        // enforce here: past-window nonces SKIP admission (`Err`, nothing
        // already pooled is touched, let alone deleted). `None` keeps the
        // legacy behavior (call-site pre-checks, where present, decide).
        // Cheap (one pool scan) and placed BEFORE the signature verify so
        // gapped junk is also cheap to refuse.
        if let Some(onchain) = ctx.onchain_nonce {
            if let Some(gap) = self.check_nonce_gap(&tx.from, tx.nonce, onchain) {
                return Err(gap);
            }
        }
        // PHASE 2 stateful half (revocation, the registered record's ceilings
        // and its cumulative spend) is DELIBERATELY NOT consulted here.
        //
        // Admission used to `try_read` the shared registry and silently SKIP
        // the stateful check whenever the lock was contended (a synchronous
        // `insert` cannot block on a tokio lock and cannot await). That made
        // the same transaction admissible or not depending on lock timing,
        // which is fine only if admission never decides INCLUSION. It does not:
        //
        //   * mempool entry is node-local policy (exactly like the base fee);
        //   * the proposer filter re-runs the full `session_gate` against the
        //     committed registry and the BLOCK clock, and execution re-runs it
        //     again before any state changes - so a revoked or over-budget
        //     grant can never be included, no matter what the pool accepted.
        //
        // Inclusion is therefore reproducible from the block + state alone,
        // which the hard determinism rule requires. What admission enforces is
        // the LOCAL, deterministic half: the carried grant's own signature,
        // expiry, scope, value cap and budget (`check_session_policy` above),
        // which depends only on the transaction and the admission clock.
        //
        // `session_registry` / `with_session_registry` are kept so the node's
        // construction is unchanged and a future async admission path can
        // consult the registry without a lock-timing race; nothing reads the
        // handle on this path any more.
        // If this is an implicit post-quantum transaction for an account that
        // is not yet activated (public key not registered in implicit registry),
        // buffer it in PendingActivationBuffer rather than rejecting.
        if tx.is_pq_implicit() && self.implicit_registry().lookup(&tx.from).is_none() {
            let cost = Self::tx_cost(&tx);
            if check_balance {
                if sender_balance < cost || self.reserved_for(&tx.from).saturating_add(cost) > sender_balance {
                    return Err(MempoolError::InsufficientBalance);
                }
            }
            let floor = self.effective_floor(&tx.from);
            let (hash, old_tx) = self.activation_buffer.buffer_tx_with_timestamp(tx.clone(), floor, ctx.now)?;
            if check_balance {
                if let Some(ref old) = old_tx {
                    let old_cost = Self::tx_cost(old);
                    if let Some(r) = self.reserved.get_mut(&tx.from) {
                        *r = r.saturating_sub(old_cost);
                    }
                }
                *self.reserved.entry(tx.from).or_insert(0) =
                    self.reserved_for(&tx.from).saturating_add(cost);
            }
            return Ok(hash);
        }

        // Fee floor on EVERY admission path (D2): includes failure-penalized floor
        // plus the State Rent Surcharge (~45k gas) if this is an activation tx.
        // Evaluated BEFORE `verify_signature_with_registry` so low-fee / zero-fee
        // transactions NEVER mutate the implicit key registry.
        let floor = self.effective_floor_for_tx(&tx);
        if tx.gas_limit < floor {
            return Err(MempoolError::FeeTooLow);
        }

        if !tx.verify_signature_with_registry(self.implicit_registry()) {
            return Err(MempoolError::BadSignature);
        }
        // Base-fee and balance checks (checked/network path only). The balance
        // check mirrors admission execution (`state_engine` charges
        // amount + gas_limit + PQ_ACTIVATION_SURCHARGE_GAS for activation
        // txs): omitting the surcharge admits txs execution must refuse.
        // F-03 reservation on top: the sender's POOLED claims plus this tx
        // must jointly fit the balance — fail closed with InsufficientBalance
        // when one funding is stretched across many slots. The unchecked path
        // (`check_balance == false`) carries no balance to reserve against and
        // is unchanged (it still can never evict).
        if check_balance {
            let total = Self::tx_cost(&tx);
            if sender_balance < total {
                return Err(MempoolError::InsufficientBalance);
            }
            if self.reserved_for(&tx.from).saturating_add(total) > sender_balance {
                return Err(MempoolError::InsufficientBalance);
            }
        }
        let hash = tx.compute_tx_hash();
        if self.txs.contains_key(&hash) || self.activation_buffer.contains_hash(&hash) {
            return Err(MempoolError::Duplicate);
        }
        let fee = tx.gas_limit;
        let sender = tx.from;

        let sender_count = self.per_sender.get(&sender).copied().unwrap_or(0);
        if sender_count >= self.per_sender_limit {
            return Err(MempoolError::TooManyFromSender);
        }

        if self.txs.len() >= self.max_size {
            // Evict the lowest-fee tx only when the newcomer bids at least 2x
            // it (F-04: fee+1 churn made full-pool displacement linear-cheap).
            // `check_balance` is false for the unchecked `add` path, so an
            // unverifiable sender can never displace honest transactions.
            let lowest = self.order.keys().next().copied();
            match lowest {
                Some((low_fee, low_hash)) if check_balance && Self::eviction_bid_beats(fee, low_fee) => {
                    self.evict(&low_hash);
                }
                _ => return Err(MempoolError::Full),
            }
        }

        // MEV blind round, seal at admission: bind this exact transaction to a
        // sealed envelope before it enters the pool. The block build later
        // re-opens it and requires a byte-exact match (`verify_pool_tx`), so a
        // pooled copy mutated after admission never reaches a block.
        if let Ok(bytes) = bincode::serialize(&tx) {
            self.mev.seal_admitted(&hash, &bytes);
        }
        self.order.insert((fee, hash), hash);
        *self.per_sender.entry(sender).or_insert(0) += 1;
        // F-03: this tx's full execution cost is now claimed against the
        // sender's balance until it leaves the pool (via `evict` below, which
        // is the single removal path for `remove`/`prune_confirmed`/
        // `evict_unexecutable`/`sweep_expired`/fee-eviction).
        *self.reserved.entry(sender).or_insert(0) =
            self.reserved_for(&sender).saturating_add(Self::tx_cost(&tx));
        self.inserted_at.insert(hash, ctx.now);
        self.txs.insert(hash, tx);

        // If this transaction activated the sender, drain any out-of-order nonces
        // that were waiting in the PendingActivationBuffer.
        if self.activation_buffer.has_account(&sender) {
            let pending = self.activation_buffer.drain_account(&sender);
            // Release the reservation that was placed when these txs were buffered.
            // When insert() is called below, it will check balance and reserve freshly.
            if check_balance {
                for p_tx in &pending {
                    let cost = Self::tx_cost(p_tx);
                    if let Some(r) = self.reserved.get_mut(&sender) {
                        *r = r.saturating_sub(cost);
                        if *r == 0 {
                            self.reserved.remove(&sender);
                        }
                    }
                }
            }
            let mut dropped = 0usize;
            for p_tx in pending {
                let pass_balance = if check_balance {
                    sender_balance
                } else {
                    u64::MAX
                };
                if self.insert(p_tx, pass_balance, check_balance, ctx).is_err() {
                    dropped += 1;
                }
            }
            if dropped > 0 {
                tracing::debug!(
                    "activation drain for {} dropped {dropped} re-priceable tx(s)",
                    hex::encode(&sender[..6]),
                );
            }
        }

        Ok(hash)
    }

    /// Gap check for admission (audit: blocks troubles): `nonce` must be
    /// within `NONCE_FUTURE_WINDOW` past the sender's executable head, where
    /// head = mex(onchain nonce, nonces already pooled for this sender).
    /// Returns `Some(NonceGap)` when the tx could never execute until the gap
    /// fills — fail fast instead of clogging the pool behind an unreachable
    /// head. Pure function of caller-supplied state (no locks).
    pub fn check_nonce_gap(
        &self,
        from: &[u8; 32],
        nonce: u64,
        onchain_nonce: u64,
    ) -> Option<MempoolError> {
        let mut pending: Vec<u64> = self
            .txs
            .values()
            .filter(|t| &t.from == from)
            .map(|t| t.nonce)
            .collect();
        if let Some(buffered) = self.activation_buffer.buffered.get(from) {
            pending.extend(buffered.keys().copied());
        }
        pending.sort_unstable();
        let mut want = onchain_nonce;
        for n in pending {
            if n < want {
                continue;
            }
            if n == want {
                want = want.saturating_add(1);
            } else {
                break;
            }
        }
        if nonce > want.saturating_add(Self::NONCE_FUTURE_WINDOW) {
            Some(MempoolError::NonceGap { expected: want, got: nonce })
        } else {
            None
        }
    }

    /// Sweep stuck transactions (audit: blocks troubles): evict entries that
    /// are STILL unexecutable against `account` (stale nonce or unaffordable)
    /// AND older than `STUCK_TX_TTL_SECS`. Executable txs are never touched
    /// no matter their age — this drains clogs, not the pool. Returns evicted
    /// count. Same `account` closure shape as `evict_unexecutable`.
    pub fn sweep_expired<F>(&mut self, now_secs: u64, mut account: F) -> usize
    where
        F: FnMut(&[u8; 32]) -> Option<(u64, u64)>,
    {
        // Per-sender executable heads (mex of onchain + pooled), computed once:
        // a tx past its head can never execute until the gap fills.
        let mut heads: std::collections::HashMap<[u8; 32], u64> = std::collections::HashMap::new();
        {
            let mut by_sender: std::collections::HashMap<[u8; 32], Vec<u64>> =
                std::collections::HashMap::new();
            for tx in self.txs.values() {
                by_sender.entry(tx.from).or_default().push(tx.nonce);
            }
            for (sender, mut nonces) in by_sender {
                nonces.sort_unstable();
                let base = account(&sender).map(|(n, _)| n).unwrap_or(0);
                let mut want = base;
                for n in nonces {
                    if n < want {
                        continue;
                    }
                    if n == want {
                        want = want.saturating_add(1);
                    } else {
                        break;
                    }
                }
                heads.insert(sender, want);
            }
        }
        let doomed: Vec<TxHash> = self
            .txs
            .values()
            .filter_map(|tx| {
                let age = now_secs.saturating_sub(*self.inserted_at.get(&tx.compute_tx_hash()).unwrap_or(&now_secs));
                if age < Self::STUCK_TX_TTL_SECS {
                    return None;
                }
                let (nonce, balance) = account(&tx.from)?;
                let stale_nonce = tx.nonce < nonce;
                let unaffordable = tx.amount.saturating_add(tx.gas_limit) > balance;
                // Gap-stuck: past the executable head with no fill in TTL.
                // The head itself (nonce == onchain and affordable) is kept:
                // it is executable, age notwithstanding.
                let head = heads.get(&tx.from).copied().unwrap_or(nonce);
                let gap = tx.nonce > head;
                if stale_nonce || unaffordable || gap {
                    Some(tx.compute_tx_hash())
                } else {
                    None
                }
            })
            .collect();
        let n = doomed.len();
        for h in &doomed {
            self.evict(h);
        }
        let expired_activation = self.activation_buffer.drain_stale(now_secs, Self::STUCK_TX_TTL_SECS);
        for tx in &expired_activation {
            let cost = Self::tx_cost(tx);
            if let Some(r) = self.reserved.get_mut(&tx.from) {
                *r = r.saturating_sub(cost);
                if *r == 0 {
                    self.reserved.remove(&tx.from);
                }
            }
        }
        let pruned_activation = expired_activation.len();
        n.saturating_add(pruned_activation)
    }

    fn evict(&mut self, hash: &TxHash) {
        // Envelopes follow their transactions: no stale ciphertext may outlive
        // the pool entry it was sealed for (a re-admitted different transaction
        // hashes differently, but leaking entries would still grow memory).
        self.mev.drop_envelope(hash);
        self.inserted_at.remove(hash);
        if let Some(tx) = self.txs.remove(hash) {
            self.order.remove(&(tx.gas_limit, *hash));
            if let Some(c) = self.per_sender.get_mut(&tx.from) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    self.per_sender.remove(&tx.from);
                }
            }
            // F-03: release this tx's claim (saturating: a directly-decoded
            // pool — never the live path, which rebuilds via `load_into` —
            // starts with an empty table and must not underflow).
            if let Some(r) = self.reserved.get_mut(&tx.from) {
                *r = r.saturating_sub(Self::tx_cost(&tx));
                if *r == 0 {
                    self.reserved.remove(&tx.from);
                }
            }
        }
    }

    /// Remove a transaction (e.g. after it is included in a finalized block).
    pub fn remove(&mut self, hash: &TxHash) -> Option<Transaction> {
        let tx = self.txs.get(hash).cloned();
        if tx.is_some() {
            self.evict(hash);
            tx
        } else {
            let act_tx = self.activation_buffer.remove_by_hash(hash);
            if let Some(ref t) = act_tx {
                if let Some(r) = self.reserved.get_mut(&t.from) {
                    *r = r.saturating_sub(Self::tx_cost(t));
                    if *r == 0 {
                        self.reserved.remove(&t.from);
                    }
                }
            }
            act_tx
        }
    }

    /// Remove a batch of confirmed transactions.
    pub fn remove_many(&mut self, hashes: &[TxHash]) {
        for h in hashes {
            self.evict(h);
        }
    }

    /// Select up to `max_txs` highest-fee transactions (for block production).
    pub fn select(&self, max_txs: usize) -> Vec<Transaction> {
        self.order
            .iter()
            .rev()
            .take(max_txs)
            .filter_map(|(_, h)| self.txs.get(h).cloned())
            .collect()
    }

    /// Select highest-fee transactions up to BOTH a tx-count cap and a total gas
    /// cap (A11: a block is bounded by gas, not only by transaction count).
    pub fn select_bounded(&self, max_txs: usize, max_gas: u64) -> Vec<Transaction> {
        let mut out = Vec::with_capacity(max_txs.min(self.txs.len()));
        let mut gas = 0u64;
        for (_, h) in self.order.iter().rev() {
            if out.len() >= max_txs {
                break;
            }
            if let Some(tx) = self.txs.get(h) {
                let g = tx.gas_limit;
                if gas.saturating_add(g) > max_gas {
                    continue; // this tx does not fit; try a cheaper one
                }
                gas = gas.saturating_add(g);
                out.push(tx.clone());
            }
        }
        out
    }

    /// Select up to `max_txs` highest-fee transactions that pass `accept`.
    /// Used by the block producer to skip txs with stale/future nonces, so a
    /// flood of invalid-nonce txs cannot waste block space.
    pub fn select_filtered<F: Fn(&Transaction) -> bool>(&self, max_txs: usize, accept: F) -> Vec<Transaction> {
        let mut out = Vec::with_capacity(max_txs);
        for (_, h) in self.order.iter().rev() {
            if out.len() >= max_txs {
                break;
            }
            if let Some(tx) = self.txs.get(h) {
                if accept(tx) {
                    out.push(tx.clone());
                }
            }
        }
        out
    }

    /// Both caps plus the admission filter.
    ///
    /// `select_bounded` respects the gas budget but takes anything that fits, and
    /// `select_filtered` skips non-executable transactions but ignores the budget.
    /// Neither is what a producer needs: a block can be filled with transactions
    /// that will never execute, and they are paid for exactly like real ones.
    /// Walking the fee order once means the highest-paying executable transaction
    /// still wins when the block is full.
    pub fn select_for_block<F: Fn(&Transaction) -> bool>(
        &self,
        max_txs: usize,
        max_gas: u64,
        accept: F,
    ) -> Vec<Transaction> {
        Self::select_multi(&self.order, &self.txs, max_txs, max_gas, accept, 1)
    }

    /// Multi-pass `select_for_block`: repeats the fee-order walk until a pass
    /// adds nothing (max 64 passes). A single pass skips a transaction whose
    /// nonce is not yet expected and never revisits it, so one out-of-hash-order
    /// nonce starves its whole suffix for the height (observed: 10 contiguous
    /// txs draining 1,3,1,2 per height instead of all at once; and a 200-deep
    /// single-sender chain selecting only 37/200 under a 16-pass cap). Later
    /// passes pick up newly-eligible followers through the SAME stateful
    /// filter, so fee priority is preserved and contiguity completes. Bounded:
    /// 64 passes worst case, each O(pool) (640k cheap ops for a full 10k pool,
    /// ms-scale; the loop exits early on the first fruitless pass, so the cap
    /// only costs when it is making progress).
    pub fn select_for_block_multi<F: Fn(&Transaction) -> bool>(
        &self,
        max_txs: usize,
        max_gas: u64,
        accept: F,
    ) -> Vec<Transaction> {
        Self::select_multi(&self.order, &self.txs, max_txs, max_gas, accept, 64)
    }

    fn select_multi<F: Fn(&Transaction) -> bool>(
        order: &std::collections::BTreeMap<(u64, TxHash), TxHash>,
        txs: &std::collections::HashMap<TxHash, Transaction>,
        max_txs: usize,
        max_gas: u64,
        accept: F,
        passes: usize,
    ) -> Vec<Transaction> {
        let mut out = Vec::with_capacity(max_txs.min(txs.len()));
        let mut gas = 0u64;
        let mut wire = 0usize;
        let mut proofs = 0usize;
        // Snapshot the fee order ONCE into contiguous arrays. Every pass walks
        // the same descending `(fee, hash)` sequence the map walk would yield,
        // but without re-descending tree nodes or re-probing the transaction
        // map per element per pass. The visit order — and therefore the
        // selected set — is unchanged (`&self` borrows both maps immutably, so
        // the precomputed alignment cannot drift mid-selection).
        let fee_order: Vec<(u64, TxHash)> = order.keys().copied().collect();
        let aligned: Vec<Option<&Transaction>> =
            fee_order.iter().map(|(_, h)| txs.get(h)).collect();
        // Transactions a previous pass already took, aligned with `fee_order`:
        // each fee-order position appears at most once (BTreeMap keys are
        // unique), so a positional bit is exactly the old hash-keyed set —
        // rejected ones stay clear and are revisited (their nonce may have
        // become expected), taken ones stay set. One indexed load per element
        // instead of hashing 32 bytes per probe per pass (64 passes x 10k
        // probes at MAX_BLOCK_TXS with scattered fees).
        let mut taken = vec![false; fee_order.len()];
        for _ in 0..passes.max(1) {
            let before = out.len();
            for i in (0..fee_order.len()).rev() {
                if out.len() >= max_txs {
                    break;
                }
                // Only skip what a previous pass already took; rejected ones
                // must be revisited (their nonce may have become expected).
                if taken[i] {
                    continue;
                }
                let Some(tx) = aligned[i] else {
                    continue;
                };
                if !accept(tx) {
                    continue;
                }
                let g = tx.gas_limit;
                if gas.saturating_add(g) > max_gas {
                    // This one does not fit. A cheaper one behind it might, so keep
                    // walking rather than truncating the block here.
                    continue;
                }
                // Wire + proof-unit caps (audit: blocks troubles): gas-valid
                // does not mean gossipable or verifiable-in-time. Skip (do
                // not truncate: a smaller tx behind may still fit).
                let w = Self::estimate_tx_wire_bytes(tx);
                if wire.saturating_add(w) > Self::MAX_BLOCK_WIRE_BYTES {
                    continue;
                }
                let p = Self::count_tx_proof_units(tx);
                if proofs.saturating_add(p) > Self::MAX_BLOCK_PROOF_UNITS {
                    continue;
                }
                gas = gas.saturating_add(g);
                wire = wire.saturating_add(w);
                proofs = proofs.saturating_add(p);
                taken[i] = true;
                out.push(tx.clone());
            }
            if out.len() == before {
                break;
            }
        }
        out
    }

    /// Estimated bincode wire bytes of a transaction for packing (audit:
    /// blocks troubles). Conservative heuristic, not exact serialization:
    /// base envelope + per-opcode shapes (64-bit range proofs dominate at
    /// ~10KB each). Used only to stop packing before the gossipable limit;
    /// exactness does not matter, monotonicity does. (A width-aware estimate
    /// sits stashed — apply only together with a bench-1k recalibration.)
    pub fn estimate_tx_wire_bytes(tx: &Transaction) -> usize {
        use crate::svm::OpCode;
        let mut n = 256usize; // envelope: sigs, hashes, nonces, shards
        // Phase-2 EVM settlement carries the canonical raw (up to 128 KiB) in
        // `signature`: account it honestly so packing still respects the block
        // gossip cap (the base 256 above only covers ~64-byte signatures).
        n += tx.signature.len();
        for op in &tx.payload {
            n += match op {
                OpCode::SysCallConfidentialTransfer2 { input_ranges, output_ranges, .. } => {
                    200 + (input_ranges.len() + output_ranges.len()) * 10_250
                }
                OpCode::SysCallConfidentialTransfer { transfer, .. } => {
                    200 + (transfer.input_commitments.len() + transfer.output_commitments.len()) * 32
                }
                OpCode::SysCallConfidentialShield { .. } => 150,
                OpCode::SysCallConfidentialUnshield { inputs } => 100 + inputs.len() * 96,
                OpCode::SysCallVerifyZkMlIn { proof, .. } => 500 + proof.wire_len(),
                OpCode::SysCallVerifyZkMlSnark { proof, .. } => {
                    500 + proof.public_inputs.len() * 2 + proof.wire_len()
                }
                _ => 200,
            };
        }
        n
    }

    /// Verified-proof units in a transaction for packing (audit: blocks
    /// troubles): counts range proofs + SNARK verifies + zkML re-executions,
    /// the work that serializes on the single apply worker.
    pub fn count_tx_proof_units(tx: &Transaction) -> usize {
        use crate::svm::OpCode;
        tx.payload
            .iter()
            .map(|op| match op {
                OpCode::SysCallConfidentialTransfer2 { input_ranges, output_ranges, .. } => {
                    input_ranges.len() + output_ranges.len()
                }
                OpCode::SysCallVerifyZkMlSnark { .. } => 64, // ~one 64-bit proof of work
                OpCode::SysCallVerifyZkMlIn { .. } => 16,   // re-execution, model-bounded
                _ => 0,
            })
            .sum()
    }

    /// Number of pending transactions that the producer would refuse to include.
    ///
    /// Non-zero means the mempool is holding transactions that cannot execute, so
    /// the block is smaller than the pool. A non-zero value that stays constant
    /// under load is the signature of a flood of unusable transactions.
    pub fn unexecutable_count<F: Fn(&Transaction) -> bool>(&self, accept: F) -> usize {
        self.txs.values().filter(|t| !accept(t)).count()
    }

    /// All pending transactions (unordered).
    pub fn all(&self) -> Vec<Transaction> {
        self.txs.values().cloned().collect()
    }

    /// Distinct senders with pending transactions, in deterministic order.
    ///
    /// The proposer filter needs exactly this set (to snapshot each sender's
    /// account once before the synchronous selection walk). Collecting it here
    /// avoids cloning every transaction just to read their `from` fields.
    pub fn senders(&self) -> std::collections::BTreeSet<[u8; 32]> {
        self.txs.values().map(|t| t.from).collect()
    }

    /// Pending transaction hashes.
    pub fn hashes(&self) -> Vec<TxHash> {
        self.txs.keys().copied().collect()
    }

    /// Drop txs already present in a finalized block (by hash).
    pub fn prune_confirmed(&mut self, confirmed: &[TxHash]) {
        let set: HashSet<TxHash> = confirmed.iter().copied().collect();
        let to_remove: Vec<TxHash> = self.txs.keys().filter(|h| set.contains(*h)).copied().collect();
        for h in to_remove {
            self.evict(&h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding::Transaction;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn multi_pass_select_completes_contiguous_sequences() {
        // Regression: single-pass fee-order selection with a stateful
        // nonce filter starves out-of-hash-order followers (observed: 10
        // contiguous txs draining 1,3,1,2 per height). Multi-pass must take
        // all executable ones regardless of hash order.
        let sk = SigningKey::generate(&mut OsRng);
        let me = sk.verifying_key().to_bytes();
        let mut mp = Mempool::new(100, 100);
        for i in 0..10u64 {
            mp.add_checked(Transaction::sign(&sk, [1u8; 32], 10, 1_000, i, 1, 1), 1_000_000)
                .unwrap();
        }
        let expected = std::cell::Cell::new(0u64);
        let out = mp.select_for_block_multi(100, u64::MAX, |t| {
            if t.from == me && t.nonce == expected.get() {
                expected.set(expected.get() + 1);
                true
            } else {
                false
            }
        });
        assert_eq!(out.len(), 10, "all contiguous txs must be selected");
        let mut nonces: Vec<u64> = out.iter().map(|t| t.nonce).collect();
        nonces.sort_unstable();
        assert_eq!(nonces, (0..10u64).collect::<Vec<_>>());
    }

    #[test]
    fn deep_single_sender_chain_selects_fully() {
        // Regression (live partial-block shape): a 200-deep single-sender
        // chain selected only 37/200 under the old 16-pass cap, because an
        // adversarial fee-hash order completes ~one nonce per pass. The 64-pass
        // budget must drain chains up to 64 deep in one selection.
        let sk = SigningKey::generate(&mut OsRng);
        let me = sk.verifying_key().to_bytes();
        let mut mp = Mempool::new(300, 300);
        for i in 0..50u64 {
            mp.add_checked(Transaction::sign(&sk, [1u8; 32], 10, 1_000, i, 1, 1), 1_000_000)
                .unwrap();
        }
        let expected = std::cell::Cell::new(0u64);
        let out = mp.select_for_block_multi(300, u64::MAX, |t| {
            if t.from == me && t.nonce == expected.get() {
                expected.set(expected.get() + 1);
                true
            } else {
                false
            }
        });
        assert_eq!(out.len(), 50, "a 50-deep chain must select fully");
        let mut nonces: Vec<u64> = out.iter().map(|t| t.nonce).collect();
        nonces.sort_unstable();
        assert_eq!(nonces, (0..50u64).collect::<Vec<_>>());
    }

    #[test]
    fn unexecutable_transactions_are_evicted() {
        let sk = SigningKey::generate(&mut OsRng);
        let me = sk.verifying_key().to_bytes();
        let mut mp = Mempool::new(100, 10);

        // All three are admitted while the account is still solvent — that is
        // the real situation: a transaction becomes unexecutable AFTER it is
        // accepted (the nonce gets consumed, or the balance drops elsewhere).
        let stale = Transaction::sign(&sk, [1u8; 32], 10, 1_000, 0, 1, 1);
        let broke = Transaction::sign(&sk, [1u8; 32], 9_000, 1_000, 1, 1, 1);
        let queued = Transaction::sign(&sk, [1u8; 32], 100, 1_000, 3, 1, 1);
        let queued_hash = queued.compute_tx_hash();
        for tx in [stale, broke, queued] {
            mp.add_checked(tx, 20_000).unwrap();
        }
        assert_eq!(mp.len(), 3);

        // Now the account is at nonce 1 (so nonce 0 is consumed) and can only
        // afford 5_000 (so the 9_000 one is dead); the nonce-3 one must survive.
        let dropped = mp.evict_unexecutable(|s| {
            if *s == me { Some((1, 5_000)) } else { None }
        });
        assert_eq!(dropped, 2, "stale nonce and unaffordable tx must go");
        assert_eq!(mp.len(), 1);
        assert!(mp.contains(&queued_hash), "a future, affordable tx must survive");
        // Evicting must not leak the per-sender quota.
        assert_eq!(mp.per_sender.get(&me).copied().unwrap_or(0), 1);
    }

    #[test]
    fn eviction_skips_unknown_senders_instead_of_killing_them() {
        // Regression (audit 2026-10-06): the old `(0, 0)` default treated a
        // sender missing from the snapshot as broke and irreversibly deleted
        // its funded transactions, while the proposer filter only skips them.
        let sk = SigningKey::generate(&mut OsRng);
        let mut mp = Mempool::new(100, 10);
        let mine = Transaction::sign(&sk, [2u8; 32], 100, 1_000, 0, 1, 1);
        let mine_hash = mine.compute_tx_hash();
        mp.add_checked(mine, 10_000).unwrap();
        // Snapshot knows NOBODY (partial/pre-height view): nothing may die.
        let dropped = mp.evict_unexecutable(|_| None);
        assert_eq!(dropped, 0, "unknown senders are skipped, never evicted");
        assert!(mp.contains(&mine_hash));
    }

    #[test]
    fn eviction_keeps_healthy_mempool_intact() {
        let sk = SigningKey::generate(&mut OsRng);
        let me = sk.verifying_key().to_bytes();
        let mut mp = Mempool::new(100, 10);
        for n in 0..3u64 {
            mp.add_checked(Transaction::sign(&sk, [2u8; 32], 100, 1_000, n, 1, 1), 10_000)
                .unwrap();
        }
        assert_eq!(mp.evict_unexecutable(|s| if *s == me { Some((0, 10_000)) } else { None }), 0);
        assert_eq!(mp.len(), 3, "nothing valid may be dropped");
    }

    fn tx(sk: &SigningKey, to: [u8; 32], fee: u64, nonce: u64) -> Transaction {
        Transaction::sign(sk, to, 10, fee, nonce, 1, 1)
    }

    #[test]
    fn select_returns_highest_fee_first() {
        let sk = key();
        let mut mp = Mempool::new(100, 100);
        mp.add(tx(&sk, [1; 32], 10, 0)).unwrap();
        mp.add(tx(&sk, [1; 32], 100, 1)).unwrap();
        mp.add(tx(&sk, [1; 32], 50, 2)).unwrap();
        let picked = mp.select(2);
        assert_eq!(picked.len(), 2);
        assert_eq!(picked[0].gas_limit, 100);
        assert_eq!(picked[1].gas_limit, 50);
    }

    #[test]
    fn duplicate_rejected() {
        let sk = key();
        let mut mp = Mempool::new(100, 100);
        let t = tx(&sk, [1; 32], 10, 0);
        mp.add(t.clone()).unwrap();
        assert_eq!(mp.add(t), Err(MempoolError::Duplicate));
    }

    #[test]
    fn invalid_signature_rejected() {
        let sk = key();
        let mut mp = Mempool::new(100, 100);
        let mut t = tx(&sk, [1; 32], 10, 0);
        t.amount = 999_999; // tamper after signing
        assert_eq!(mp.add(t), Err(MempoolError::BadSignature));
    }

    #[test]
    fn per_sender_quota_enforced() {
        let sk = key();
        let mut mp = Mempool::new(100, 3);
        for n in 0..3 {
            mp.add(tx(&sk, [1; 32], 10, n)).unwrap();
        }
        assert_eq!(mp.add(tx(&sk, [1; 32], 10, 3)), Err(MempoolError::TooManyFromSender));
    }

    #[test]
    fn full_pool_evicts_lowest_fee_for_higher_fee() {
        let sk = key();
        let mut mp = Mempool::new(2, 100);
        let low = tx(&sk, [1; 32], 5, 0);
        let low_hash = low.compute_tx_hash();
        // `add_checked` with a funded sender: eviction requires verified balance
        let bal = 1_000;
        mp.add_checked(low, bal).unwrap();
        mp.add_checked(tx(&sk, [1; 32], 10, 1), bal).unwrap();
        // pool full; a higher-fee tx evicts the lowest (fee 5)
        mp.add_checked(tx(&sk, [1; 32], 20, 2), bal).unwrap();
        assert_eq!(mp.len(), 2);
        assert!(!mp.contains(&low_hash), "lowest-fee tx must be evicted");
        // a lower-fee tx is rejected when full
        assert_eq!(mp.add_checked(tx(&sk, [1; 32], 1, 3), bal), Err(MempoolError::Full));
    }

    #[test]
    fn unfunded_add_never_evicts_and_checked_rejects_unfunded() {
        let sk = key();
        let mut mp = Mempool::new(2, 100);
        mp.add(tx(&sk, [1; 32], 5, 0)).unwrap();
        mp.add(tx(&sk, [1; 32], 10, 1)).unwrap();
        // unchecked `add` cannot evict even with a huge declared fee
        assert_eq!(mp.add(tx(&sk, [1; 32], u64::MAX, 2)), Err(MempoolError::Full));
        // add_checked rejects a sender that cannot pay amount + gas_limit
        assert_eq!(
            mp.add_checked(tx(&sk, [1; 32], 10, 1), 0),
            Err(MempoolError::InsufficientBalance)
        );
    }

    #[test]
    fn base_fee_rejects_too_low_fee_on_checked_path() {
        let sk = key();
        let mut mp = Mempool::new(100, 100).with_base_fee(10);
        // D2: the fee floor holds on EVERY admission path now — the unchecked
        // path used to bypass it, letting zero-fee spam occupy pool slots for
        // free while the checked path and the proposer filter refused it.
        assert_eq!(mp.add(tx(&sk, [1; 32], 1, 0)), Err(MempoolError::FeeTooLow));
        // The checked/network path enforces it.
        assert_eq!(mp.add_checked(tx(&sk, [1; 32], 5, 1), 1_000), Err(MempoolError::FeeTooLow));
        assert!(mp.add_checked(tx(&sk, [1; 32], 10, 1), 1_000).is_ok());
    }

    #[test]
    fn select_bounded_respects_total_gas_cap() {
        let sk = key();
        let mut mp = Mempool::new(100, 100);
        mp.add(tx(&sk, [1; 32], 100, 0)).unwrap(); // gas 100 (too big for cap)
        mp.add(tx(&sk, [1; 32], 50, 1)).unwrap();
        mp.add(tx(&sk, [1; 32], 10, 2)).unwrap();
        let picked = mp.select_bounded(10, 60);
        let total: u64 = picked.iter().map(|t| t.gas_limit).sum();
        assert!(total <= 60, "block gas must stay within the cap");
        assert_eq!(picked[0].gas_limit, 50, "highest affordable fee first");
    }

    #[test]
    fn remove_and_prune_confirmed() {
        let sk = key();
        let mut mp = Mempool::new(100, 100);
        let t0 = tx(&sk, [1; 32], 10, 0);
        let t1 = tx(&sk, [1; 32], 10, 1);
        let h0 = mp.add(t0).unwrap();
        let h1 = mp.add(t1).unwrap();
        mp.remove(&h0);
        assert_eq!(mp.len(), 1);
        mp.prune_confirmed(&[h1]);
        assert!(mp.is_empty());
    }

    #[test]
    fn per_sender_count_decremented_on_remove() {
        let sk = key();
        let mut mp = Mempool::new(10, 2);
        let h = mp.add(tx(&sk, [1; 32], 10, 0)).unwrap();
        mp.add(tx(&sk, [1; 32], 10, 1)).unwrap();
        assert_eq!(mp.add(tx(&sk, [1; 32], 10, 2)), Err(MempoolError::TooManyFromSender));
        mp.remove(&h);
        // after freeing a slot the sender can add again
        assert!(mp.add(tx(&sk, [1; 32], 10, 2)).is_ok());
    }

    #[test]
    fn mempool_file_format_is_versioned_with_legacy_fallback() {
        // `mev` (and the registry handle) are `#[serde(skip)]`, so the engine
        // fields never enter the encoding. `inserted_at` DOES (audit: blocks
        // troubles — TTL needs it), so files are versioned with a magic
        // prefix instead: new files start with MP02, legacy bare files still
        // decode via the mirror below.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct LegacyMempool {
            txs: HashMap<TxHash, Transaction>,
            order: BTreeMap<(u64, TxHash), TxHash>,
            per_sender: HashMap<[u8; 32], usize>,
            max_size: usize,
            per_sender_limit: usize,
            base_fee: u64,
        }

        let sk = key();
        let mut mp = Mempool::new(10, 10).with_base_fee(7);
        mp.add(tx(&sk, [1; 32], 10, 0)).unwrap();
        mp.add(tx(&sk, [1; 32], 20, 1)).unwrap();

        let legacy = LegacyMempool {
            txs: mp.txs.clone(),
            order: mp.order.clone(),
            per_sender: mp.per_sender.clone(),
            max_size: mp.max_size,
            per_sender_limit: mp.per_sender_limit,
            base_fee: mp.base_fee,
        };
        let new_bytes = bincode::serialize(&mp).unwrap();
        let legacy_bytes = bincode::serialize(&legacy).unwrap();
        assert_ne!(new_bytes, legacy_bytes, "inserted_at must change the encoding");

        // New bytes (bare, no magic) decode into the new struct directly...
        let back: Mempool = bincode::deserialize(&new_bytes).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.inserted_at.len(), 2, "timestamps travel with the pool");
        // ...and legacy bytes decode into the mirror (the load_into fallback).
        let _: LegacyMempool = bincode::deserialize(&legacy_bytes).unwrap();

        // Old bytes -> new struct: decodes, and the engine starts defaulted
        // (skipped fields), then re-seals on the next admission.
        let mut back: Mempool = bincode::deserialize(&new_bytes).unwrap();
        assert_eq!(back.len(), 2);
        assert!(back.mev.pool_envelopes.is_empty(), "skipped field decodes as default");
        let t = tx(&sk, [1; 32], 30, 2);
        back.add(t.clone()).unwrap();
        assert_eq!(back.mev.verify_pool_tx(&t), crate::mev::SealVerdict::Match);
    }

    #[test]
    fn envelope_lifecycle_follows_the_transaction() {
        let sk = key();
        let mut mp = Mempool::new(10, 10);
        let h = mp.add(tx(&sk, [1; 32], 10, 0)).unwrap();
        assert!(mp.mev.pool_envelopes.contains_key(&h), "admission seals");
        mp.remove(&h);
        assert!(!mp.mev.pool_envelopes.contains_key(&h), "removal drops the envelope");

        let h2 = mp.add(tx(&sk, [1; 32], 10, 5)).unwrap();
        assert!(mp.mev.pool_envelopes.contains_key(&h2));
        mp.prune_confirmed(&[h2]);
        assert!(mp.mev.pool_envelopes.is_empty(), "pruning drops envelopes too");

        let h3 = mp.add(tx(&sk, [1; 32], 10, 6)).unwrap();
        assert!(mp.mev.pool_envelopes.contains_key(&h3));
        mp.evict_unexecutable(|_| Some((u64::MAX, 0))); // stale nonce for everything
        assert!(mp.mev.pool_envelopes.is_empty(), "eviction drops envelopes too");
    }

    #[test]
    fn nonce_gap_rejects_far_future_at_admission() {
        // Audit (blocks troubles): nonce 17 with onchain 0 must fail fast,
        // not sit in the pool forever behind an unreachable head.
        let sk = key();
        let me = sk.verifying_key().to_bytes();
        let mp = Mempool::new(100, 100);
        assert!(mp.check_nonce_gap(&me, 0, 0).is_none());
        assert!(mp.check_nonce_gap(&me, 16, 0).is_none());
        match mp.check_nonce_gap(&me, 17, 0) {
            Some(MempoolError::NonceGap { expected, got }) => {
                assert_eq!((expected, got), (0, 17));
            }
            other => panic!("expected NonceGap, got {other:?}"),
        }
        // With pooled prefix [0,1], the window moves with the head.
        let mut mp2 = Mempool::new(100, 100);
        mp2.add(tx(&sk, [1; 32], 10, 0)).unwrap();
        mp2.add(tx(&sk, [1; 32], 10, 1)).unwrap();
        assert!(mp2.check_nonce_gap(&me, 2, 0).is_none());
        assert!(mp2.check_nonce_gap(&me, 18, 0).is_none());
        assert!(matches!(
            mp2.check_nonce_gap(&me, 19, 0),
            Some(MempoolError::NonceGap { .. })
        ));
    }

    #[test]
    fn sweep_expired_drains_only_stuck_txs() {
        // Gapped suffix [4,5,7] with onchain 4: 7 is past the head (mex=6)
        // and old -> swept; 4,5 stay (executable). Fresh pool: nothing moves.
        // (Inserted-at stamps use the wall clock; the test reads it back.)
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sk = key();
        let mut mp = Mempool::new(100, 100);
        for n in [4u64, 5, 7] {
            mp.add(tx(&sk, [1; 32], 10, n)).unwrap();
        }
        assert_eq!(mp.sweep_expired(now, |_| Some((4, 1_000_000))), 0);
        assert_eq!(mp.len(), 3);
        assert_eq!(
            mp.sweep_expired(now + Mempool::STUCK_TX_TTL_SECS + 1, |_| Some((4, 1_000_000))),
            1
        );
        assert_eq!(mp.len(), 2);
        // Unknown senders are skipped, never assumed broke.
        assert_eq!(
            mp.sweep_expired(now + Mempool::STUCK_TX_TTL_SECS + 1, |_| None),
            0
        );
    }

    #[test]
    fn select_respects_wire_and_proof_caps() {
        use crate::crypto_privacy::{PedersenCommitment, RangeProof};
        use curve25519_dalek::scalar::Scalar;
        // A max-proof Transfer2 (~330KB est, 16 proofs): wire cap 24MB means
        // at most ~70 fit even with infinite gas/count budget.
        let one = {
            let sk = key();
            let r = Scalar::from(1u64);
            let c = PedersenCommitment::commit(100, &r);
            let p = RangeProof::prove(&c, 100, &r, 64);
            let ops = vec![crate::svm::OpCode::SysCallConfidentialTransfer2 {
                recipient: [9u8; 32],
                transfer: Box::new(crate::crypto_privacy::ConfidentialTransfer::new(
                    vec![c; 8],
                    vec![c; 8],
                    0,
                )),
                input_ranges: vec![p.clone(); 8],
                output_ranges: vec![p; 8],
            }];
            Transaction::sign_with_payload(&sk, [1u8; 32], 0, 100_000_000, 0, 1, 1, ops)
        };
        assert!(Mempool::estimate_tx_wire_bytes(&one) > 100_000, "fat tx estimates big");
        assert_eq!(Mempool::count_tx_proof_units(&one), 16);
        let mut mp2 = Mempool::new(1000, 1000);
        for i in 0..150u64 {
            let mut seed = [0xBu8; 32];
            seed[0] = i as u8;
            seed[1] = (i >> 8) as u8;
            let k = SigningKey::from_bytes(&seed);
            let r = Scalar::from(i + 1);
            let c = PedersenCommitment::commit(100, &r);
            let p = RangeProof::prove(&c, 100, &r, 64);
            let ops = vec![crate::svm::OpCode::SysCallConfidentialTransfer2 {
                recipient: [9u8; 32],
                transfer: Box::new(crate::crypto_privacy::ConfidentialTransfer::new(
                    vec![c; 8],
                    vec![c; 8],
                    0,
                )),
                input_ranges: vec![p.clone(); 8],
                output_ranges: vec![p; 8],
            }];
            let t = Transaction::sign_with_payload(&k, [1u8; 32], 0, 100_000_000, i, 1, 1, ops);
            mp2.add(t).unwrap();
        }
        let sel = mp2.select_for_block_multi(10_000, u64::MAX, |_| true);
        // 150 fat txs x ~164KB = ~24.6MB > 24MB cap: not all selected.
        // (Proof cap 150x16=2400 > 2048 would also bind first — wire wins here
        // only if proofs stay under it; either cap stopping is correct.)
        assert!(sel.len() < 150, "a packing cap must stop packing: got {}", sel.len());
        assert!(!sel.is_empty(), "but small packing still works");
    }

    #[test]
    fn blast_200_reused_small_proofs_bind_packing_caps() {
        // Blast check (packing perf): 200 fat txs built from ONE reused 8-bit
        // range proof (fast: a single `prove`, then cheap clones — NOT 200
        // 64-bit proves). Each tx carries 48+48 = 96 proofs, so the unbounded
        // totals blow BOTH caps (wire: 200 x `one_wire` > MAX_BLOCK_WIRE_BYTES;
        // proofs: 200 x 96 = 19_200 > MAX_BLOCK_PROOF_UNITS — both asserted
        // below, so the fixture is meaningful under any width-aware estimate
        // revision). `select_multi` must stop early on at least one of them,
        // and the selected set must respect BOTH.
        use crate::crypto_privacy::{PedersenCommitment, RangeProof};
        use curve25519_dalek::scalar::Scalar;
        let r = Scalar::from(7u64);
        let c = PedersenCommitment::commit(42, &r);
        let p = RangeProof::prove(&c, 42, &r, 8);
        assert_eq!(p.bits, 8, "small-proof fixture must stay 8-bit");
        let fat_ops = || {
            vec![crate::svm::OpCode::SysCallConfidentialTransfer2 {
                recipient: [9u8; 32],
                transfer: Box::new(crate::crypto_privacy::ConfidentialTransfer::new(
                    vec![c; 8],
                    vec![c; 8],
                    0,
                )),
                input_ranges: vec![p.clone(); 48],
                output_ranges: vec![p.clone(); 48],
            }]
        };
        // Unbounded totals exceed both caps (so the test is meaningful).
        let one_wire = {
            let sk = key();
            let t = Transaction::sign_with_payload(&sk, [1u8; 32], 0, 100_000_000, 0, 1, 1, fat_ops());
            Mempool::estimate_tx_wire_bytes(&t)
        };
        let one_proofs = {
            let sk = key();
            let t = Transaction::sign_with_payload(&sk, [1u8; 32], 0, 100_000_000, 0, 1, 1, fat_ops());
            Mempool::count_tx_proof_units(&t)
        };
        assert_eq!(one_proofs, 96, "fixture must carry 96 proof units/tx");
        assert!(
            one_wire.saturating_mul(200) > Mempool::MAX_BLOCK_WIRE_BYTES,
            "200 fat txs must overflow the wire cap unbounded ({} x 200)",
            one_wire,
        );
        assert!(
            one_proofs.saturating_mul(200) > Mempool::MAX_BLOCK_PROOF_UNITS,
            "200 fat txs must overflow the proof cap unbounded"
        );
        let mut mp = Mempool::new(1024, 1024);
        for i in 0..200u64 {
            let mut seed = [0xCBu8; 32];
            seed[..8].copy_from_slice(&i.to_le_bytes());
            let k = SigningKey::from_bytes(&seed);
            let t = Transaction::sign_with_payload(&k, [1u8; 32], 0, 100_000_000, 0, 1, 1, fat_ops());
            mp.add(t).expect("unchecked admission must succeed");
        }
        assert_eq!(mp.len(), 200);
        let sel = mp.select_for_block_multi(10_000, u64::MAX, |_| true);
        assert!(sel.len() < 200, "a packing cap must bind under blast: got {}", sel.len());
        assert!(!sel.is_empty(), "but small packing still works");
        let wire: usize = sel.iter().map(Mempool::estimate_tx_wire_bytes).sum();
        let proofs: usize = sel.iter().map(Mempool::count_tx_proof_units).sum();
        assert!(
            wire <= Mempool::MAX_BLOCK_WIRE_BYTES,
            "selected wire {wire} must respect the cap"
        );
        assert!(
            proofs <= Mempool::MAX_BLOCK_PROOF_UNITS,
            "selected proofs {proofs} must respect the cap"
        );
    }

    #[test]
    fn test_mempool_activation_sequencing() {
        use crate::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};

        let custom_registry = StatefulImplicitKeyRegistry::new();
        let mut mp = Mempool::new(100, 50)
            .with_base_fee(100)
            .with_implicit_registry(custom_registry.clone());

        let seed = 0x51;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);

        // Account is not activated yet: custom_registry does not have `from`.
        assert!(custom_registry.lookup(&from).is_none());

        // Tx2 arrives before Tx1: nonce 1, implicit envelope (pubkey omitted from wire)
        let mut tx2 = Transaction {
            from,
            to: [2u8; 32],
            amount: 50,
            gas_limit: 100,
            nonce: 1,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg2 = tx2.signing_message();
        let sig2 = Transaction::create_falcon512_test_signature(&pk, &msg2, seed);
        tx2.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig2).encode();

        let h2 = mp.add(tx2.clone()).expect("Tx2 must be accepted into activation buffer");
        assert!(mp.is_buffered(&h2), "Tx2 must be buffered pending activation");
        assert!(mp.contains(&h2), "contains() must find buffered Tx2");
        assert_eq!(mp.len(), 0, "No executable transactions in active pool yet");
        assert_eq!(mp.activation_buffer.count_for_account(&from), 1);

        // Proposer packing cannot select Tx2 yet
        let picked = mp.select_for_block(10, u64::MAX, |_| true);
        assert!(picked.is_empty(), "Unactivated transaction cannot be picked for block");

        // Now Tx1 arrives: nonce 0, explicit PQ activation carrying raw public key + surcharge gas
        let mut tx1 = Transaction {
            from,
            to: [3u8; 32],
            amount: 100,
            gas_limit: 100 + PQ_ACTIVATION_SURCHARGE_GAS,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg1 = tx1.signing_message();
        let sig1 = Transaction::create_falcon512_test_signature(&pk, &msg1, seed);
        tx1.signature = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig1).encode();

        let h1 = mp.add(tx1.clone()).expect("Tx1 activation must succeed");
        assert!(!mp.is_buffered(&h2), "Tx2 must no longer be in buffer after activation");
        assert_eq!(mp.activation_buffer.count_for_account(&from), 0);
        assert_eq!(mp.len(), 2, "Both Tx1 and Tx2 must now be in active pool");
        assert!(mp.contains(&h1));
        assert!(mp.contains(&h2));

        // Block packing selects Tx1 (nonce 0) followed by Tx2 (nonce 1)
        let block_txs = mp.select_for_block(10, u64::MAX, |_| true);
        assert_eq!(block_txs.len(), 2);
        assert_eq!(block_txs[0].nonce, 0);
        assert_eq!(block_txs[0].compute_tx_hash(), h1);
        assert_eq!(block_txs[1].nonce, 1);
        assert_eq!(block_txs[1].compute_tx_hash(), h2);
    }

    #[test]
    fn test_surcharge_gas_accounting_for_activation_tx() {
        use crate::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};

        let custom_registry = StatefulImplicitKeyRegistry::new();
        let mut mp = Mempool::new(100, 50)
            .with_base_fee(500)
            .with_implicit_registry(custom_registry);

        let seed = 0x62;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);

        let mut tx_cheap = Transaction {
            from,
            to: [9u8; 32],
            amount: 10,
            gas_limit: 500 + PQ_ACTIVATION_SURCHARGE_GAS - 1, // 1 gas unit short of required surcharge
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg = tx_cheap.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        tx_cheap.signature = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig.clone()).encode();

        // Reject if gas_limit does not cover base_fee + PQ_ACTIVATION_SURCHARGE_GAS
        assert_eq!(
            mp.add(tx_cheap),
            Err(MempoolError::FeeTooLow),
            "Underpaid activation surcharge must fail with FeeTooLow"
        );

        // Sufficient gas_limit passes
        let mut tx_ok = Transaction {
            from,
            to: [9u8; 32],
            amount: 10,
            gas_limit: 500 + PQ_ACTIVATION_SURCHARGE_GAS,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg_ok = tx_ok.signing_message();
        let sig_ok = Transaction::create_falcon512_test_signature(&pk, &msg_ok, seed);
        tx_ok.signature = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk, sig_ok).encode();
        assert!(mp.add(tx_ok).is_ok(), "Fully paid activation surcharge must succeed");
    }

    #[test]
    fn test_activation_buffer_capacity_limit_16() {
        use crate::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};

        let custom_registry = StatefulImplicitKeyRegistry::new();
        let mut mp = Mempool::new(100, 50)
            .with_base_fee(100)
            .with_implicit_registry(custom_registry);

        let seed = 0x83;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);

        // Buffer 16 out-of-order nonces (nonces 1 through 16)
        for nonce in 1..=16 {
            let mut tx = Transaction {
                from,
                to: [1u8; 32],
                amount: 1,
                gas_limit: 100,
                nonce,
                source_shard: 1,
                target_shard: 1,
                signature: Vec::new(),
                payload: Vec::new(),
            };
            let msg = tx.signing_message();
            let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
            tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
            assert!(mp.add(tx).is_ok());
        }

        assert_eq!(mp.activation_buffer.count_for_account(&from), 16);

        // 17th nonce exceeds per-account capacity limit
        let mut tx17 = Transaction {
            from,
            to: [1u8; 32],
            amount: 1,
            gas_limit: 100,
            nonce: 17,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg17 = tx17.signing_message();
        let sig17 = Transaction::create_falcon512_test_signature(&pk, &msg17, seed);
        tx17.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig17).encode();

        assert_eq!(
            mp.add(tx17),
            Err(MempoolError::TooManyFromSender),
            "17th buffered nonce must be refused"
        );

        // Transaction with fee below base_fee is rejected
        let mut tx_low_fee = Transaction {
            from,
            to: [1u8; 32],
            amount: 1,
            gas_limit: 50, // below base_fee of 100
            nonce: 18,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg_low = tx_low_fee.signing_message();
        let sig_low = Transaction::create_falcon512_test_signature(&pk, &msg_low, seed);
        tx_low_fee.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig_low).encode();

        assert_eq!(
            mp.add(tx_low_fee),
            Err(MempoolError::FeeTooLow),
            "Sub-floor buffered transaction must fail with FeeTooLow"
        );
    }

    #[test]
    fn test_activation_insufficient_gas_fails_without_registering_pubkey() {
        use crate::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};

        let custom_registry = StatefulImplicitKeyRegistry::new();
        let mut mp = Mempool::new(100, 50)
            .with_base_fee(100)
            .with_implicit_registry(custom_registry.clone());

        let seed = 0x5a;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);

        // Required gas: base_fee (100) + PQ_ACTIVATION_SURCHARGE_GAS (45_000) = 45_100.
        // We supply 100 gas, which covers base_fee but not the activation surcharge.
        let mut tx_cheap = Transaction {
            from,
            to: [8u8; 32],
            amount: 10,
            gas_limit: 100,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg = tx_cheap.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        tx_cheap.signature = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk, sig).encode();

        assert!(custom_registry.lookup(&from).is_none());

        let res = mp.add(tx_cheap);
        assert_eq!(res, Err(MempoolError::FeeTooLow));

        // Registry must NOT have registered the public key
        assert!(
            custom_registry.lookup(&from).is_none(),
            "Implicit registry must NOT be mutated on low-fee activation tx"
        );
        assert!(mp.implicit_registry().lookup(&from).is_none());
    }

    #[test]
    fn test_pure_pq_rejects_envelope_wrapped_ed25519_with_malformed() {
        use crate::post_quantum::{PqScheme, PqSignatureEnvelope};
        use ed25519_dalek::Signer;

        let sk = key();
        let pk_bytes = sk.verifying_key().to_bytes().to_vec();

        let mut tx = Transaction {
            from: [0x33; 32],
            to: [0x44; 32],
            amount: 50,
            gas_limit: 500,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg = tx.signing_message();
        let sig = sk.sign(&msg).to_bytes().to_vec();

        // Classical Ed25519 wrapped in PQ1 envelope
        let env = PqSignatureEnvelope::new_explicit(PqScheme::Ed25519, pk_bytes, sig);
        tx.signature = env.encode();

        let mut mp = Mempool::new(10, 10).with_pure_pq(true);
        let res = mp.add(tx);

        match res {
            Err(MempoolError::Malformed(reason)) => {
                assert!(
                    reason.contains("Pure PQ mode: scheme must be post-quantum"),
                    "Expected scheme must be post-quantum rejection, got: {reason}"
                );
            }
            other => panic!("Expected Malformed error, got: {:?}", other),
        }
    }

    #[test]
    fn test_pending_activation_buffer_global_cap_2048() {
        let mut buffer = PendingActivationBuffer::new();

        // 128 accounts * 16 nonces = 2048 buffered transactions
        for acct_idx in 0..128u32 {
            let mut from = [0u8; 32];
            from[0..4].copy_from_slice(&acct_idx.to_be_bytes());
            for nonce in 0..16u64 {
                let tx = Transaction {
                    from,
                    to: [1u8; 32],
                    amount: 1,
                    gas_limit: 100,
                    nonce,
                    source_shard: 1,
                    target_shard: 1,
                    signature: Vec::new(),
                    payload: Vec::new(),
                };
                assert!(buffer.buffer_tx(tx, 50).is_ok());
            }
        }

        assert_eq!(buffer.len(), 2048);
        assert_eq!(buffer.len(), PendingActivationBuffer::MAX_GLOBAL_BUFFERED_TXS);

        // 2049th tx exceeds global buffer cap
        let mut from_extra = [0u8; 32];
        from_extra[0..4].copy_from_slice(&128u32.to_be_bytes());
        let tx_overflow = Transaction {
            from: from_extra,
            to: [1u8; 32],
            amount: 1,
            gas_limit: 100,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };

        assert_eq!(
            buffer.buffer_tx(tx_overflow, 50),
            Err(MempoolError::TooManyFromSender),
            "2049th transaction must be rejected by global buffer cap"
        );
        assert_eq!(buffer.len(), 2048);
    }

    #[test]
    fn test_pending_activation_buffer_overwrite_nonce_removes_old_hash() {
        let mut buffer = PendingActivationBuffer::new();
        let from = [7u8; 32];

        let tx1 = Transaction {
            from,
            to: [1u8; 32],
            amount: 10,
            gas_limit: 100,
            nonce: 5,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let h1 = tx1.compute_tx_hash();
        assert_eq!(buffer.buffer_tx(tx1, 50), Ok(h1));
        assert!(buffer.contains_hash(&h1));
        assert!(buffer.by_hash.contains_key(&h1));
        assert_eq!(buffer.len(), 1);

        // Overwrite nonce 5 with a replacement transaction (different amount -> different hash)
        let tx2 = Transaction {
            from,
            to: [1u8; 32],
            amount: 20,
            gas_limit: 100,
            nonce: 5,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let h2 = tx2.compute_tx_hash();
        assert_ne!(h1, h2);

        assert_eq!(buffer.buffer_tx(tx2, 50), Ok(h2));
        assert_eq!(buffer.len(), 1);
        assert!(!buffer.contains_hash(&h1), "Old hash must no longer be in buffer");
        assert!(!buffer.by_hash.contains_key(&h1), "Old hash must be removed from by_hash");
        assert!(buffer.contains_hash(&h2), "New hash must be in buffer");
        assert!(buffer.by_hash.contains_key(&h2), "New hash must be in by_hash");
        assert_eq!(buffer.get(&from, 5).unwrap().amount, 20);
    }

    #[test]
    fn test_sweep_expired_prunes_stale_activation_buffer() {
        use crate::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};

        let custom_registry = StatefulImplicitKeyRegistry::new();
        let mut mp = Mempool::new(100, 50)
            .with_base_fee(100)
            .with_implicit_registry(custom_registry);

        let seed = 0x91;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);

        let mut tx = Transaction {
            from,
            to: [2u8; 32],
            amount: 50,
            gas_limit: 100,
            nonce: 1, // out-of-order, unactivated -> buffered
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
        };
        let msg = tx.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();

        let now = 10_000u64;
        let ctx = AdmissionCtx::new(now);
        let h = mp.insert(tx, u64::MAX, false, ctx).expect("Must buffer in activation buffer");

        assert!(mp.activation_buffer.contains_hash(&h));
        assert_eq!(mp.activation_buffer.len(), 1);

        // At now, not expired yet
        let swept = mp.sweep_expired(now, |_| None);
        assert_eq!(swept, 0);
        assert!(mp.activation_buffer.contains_hash(&h));

        // After TTL, must be pruned
        let swept = mp.sweep_expired(now + Mempool::STUCK_TX_TTL_SECS + 1, |_| None);
        assert_eq!(swept, 1);
        assert!(!mp.activation_buffer.contains_hash(&h));
        assert_eq!(mp.activation_buffer.len(), 0);
    }
}

/// Decoder fuzz regressions (Agent 1): the mempool admission path must never
/// panic on transactions that decoded from peer bytes. Appended without
/// touching existing code.
#[cfg(test)]
mod decoder_fuzz_regressions {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn admission_of_fuzz_shaped_txs_never_panics() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let good = Transaction::sign(&sk, [1u8; 32], 10, 5, 0, 1, 1);
        let enc = bincode::serialize(&good).unwrap();
        let mut corpus = vec![enc.clone()];
        for n in (0..enc.len()).step_by(3) {
            corpus.push(enc[..n].to_vec());
        }
        let mut maxed = enc.clone();
        for b in maxed.iter_mut() {
            *b = 0xFF;
        }
        corpus.push(maxed);
        for input in &corpus {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if let Ok(tx) = bincode::deserialize::<Transaction>(input) {
                    let mut mp = Mempool::new(16, 16);
                    let _ = mp.add(tx.clone());
                    let _ = mp.add_checked(tx, u64::MAX);
                }
            }));
            assert!(r.is_ok(), "mempool admission panicked on len {}", input.len());
        }
    }
}
