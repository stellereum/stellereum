//! Transaction mempool: fee-priority ordering, bounded size with eviction, and
//! per-sender anti-flood limits. Pure and synchronous; the network layer feeds
//! transactions in and the block producer pulls the highest-fee ones out.

use crate::post_quantum::StatefulImplicitKeyRegistry;
use crate::sharding::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

pub type TxHash = [u8; 32];

/// Maximum out-of-order nonces buffered per unactivated account (§2.3).
///
/// ALIGNED WITH THE NONCE WINDOW (audit: activation buffer exhaustion): a
/// buffered nonce for an unactivated account IS a future nonce, so it is
/// bounded by the same window as an activated account's (`NONCE_FUTURE_WINDOW`
/// = 4). The old limit of 16 let a single account park 16 transactions in the
/// GLOBAL buffer, so a handful of accounts could eat the whole 2048-slot
/// ceiling and lock every legitimate unactivated account out.
pub const MAX_ACTIVATION_BUFFER_NONCES_PER_ACCOUNT: usize = 4;

/// State Rent Surcharge (~45,000 gas) for activation transactions carrying
/// raw post-quantum public keys (§2.2).
pub const PQ_ACTIVATION_SURCHARGE_GAS: u64 = 45_000;

/// Buffers out-of-order nonces for unactivated accounts (up to 4 nonces per account
/// (= NONCE_FUTURE_WINDOW) when Tx2 arrives before Tx1 — Stellereum PQ-BFT v5 spec §2.3).
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
    /// Per-account cap on buffered out-of-order nonces (mirrors
    /// [`MAX_ACTIVATION_BUFFER_NONCES_PER_ACCOUNT`]).
    ///
    /// Safety role (admission DoS bound): one account cannot eat the whole
    /// global buffer and lock out legitimate unactivated accounts.
    pub const MAX_NONCES_PER_ACCOUNT: usize = MAX_ACTIVATION_BUFFER_NONCES_PER_ACCOUNT;
    /// Global ceiling on buffered activation transactions.
    ///
    /// Safety role (memory DoS bound): caps total buffered bytes across all
    /// accounts; overflow reports [`MempoolError::Full`] (fail-closed).
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
    /// - Up to [`MAX_ACTIVATION_BUFFER_NONCES_PER_ACCOUNT`] buffered nonces per
    ///   unactivated account.
    /// - Deduplication by transaction hash and stale-hash pruning on overwrite.
    ///
    /// The global ceiling reports [`MempoolError::Full`]: it is a GLOBAL
    /// resource limit, not a per-sender quota, and reporting
    /// `TooManyFromSender` for it told the sender "you have too many
    /// transactions" when the truth was "the shared buffer is full" — a
    /// misleading verdict that hid a global DoS behind a per-sender error
    /// (audit: activation buffer exhaustion).
    pub fn buffer_tx(&mut self, tx: Transaction, min_fee: u64) -> Result<TxHash, MempoolError> {
        self.buffer_tx_with_timestamp(tx, min_fee, crate::zkml::now_secs())
            .map(|(h, _)| h)
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
            return Err(MempoolError::Full);
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
        self.buffered.get(account).is_some_and(|m| !m.is_empty())
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
    pub fn drain_contiguous(
        &mut self,
        account: &[u8; 32],
        mut start_nonce: u64,
    ) -> Vec<Transaction> {
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
        let tx = self
            .buffered
            .get_mut(&sender)
            .and_then(|m| m.remove(&nonce));
        if self.buffered.get(&sender).is_some_and(|m| m.is_empty()) {
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
    /// The shard this pool admits for, when the caller knows it (P2 shard
    /// gate). `insert` refuses transactions whose `source_shard` is not this
    /// shard: without it a spammer fills the pool with foreign-shard
    /// transactions that the proposer must skip, evicting legitimate ones
    /// (mempool pollution with zero inclusion cost). `None` (every legacy
    /// `wall_now()` caller) keeps exactly today's behavior: the proposer
    /// filter remains the enforcement point. Threading it here puts the check
    /// at the single choke point every admission funnels through. Only set by
    /// callers running sharded (`ShardRegistry::is_sharded()`): a single-shard
    /// node must keep admitting historical source=1/target=1 traffic.
    pub shard: Option<crate::sharding::ShardId>,
    /// PAYMASTER (sponsored transactions): the SPONSOR's on-chain balance at
    /// admission time, when the caller already read it.
    ///
    /// `insert` enforces the sponsor coverage check against this head: a
    /// sponsored transaction whose fee the sponsor cannot cover is refused
    /// with `SponsorInsufficientBalance` instead of occupying pool space the
    /// proposer must then skip. `None` (every legacy caller) keeps exactly
    /// today's behavior for legacy transactions — and FAILS CLOSED for
    /// sponsored ones (a sponsored transaction admitted without a known
    /// sponsor balance is refused: coverage cannot be shown). Callers that
    /// admit sponsored transactions (RPC, gossip, runtime, restore) MUST set
    /// this via [`AdmissionCtx::with_sponsor_balance`], reading the sponsor
    /// account exactly like they already read the sender account.
    pub sponsor_balance: Option<u64>,
    /// A14 chain-binding rollout, phase 3: the chain height this transaction
    /// would be admitted/included at, when the caller knows it.
    ///
    /// `insert` enforces [`crate::chain_binding::check_admission`] against
    /// this height and the ambient `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` env:
    /// unbound envelopes are refused with `UnboundRefused` at/after
    /// activation instead of occupying pool space the proposer must then
    /// skip (defense in depth for P2P-received transactions, which never
    /// pass the RPC refusal). `None` (every legacy caller, and every path
    /// that cannot name an inclusion height) keeps exactly today's behavior:
    /// no check runs, so default-off **and** height-less admission stay
    /// byte-identical. Live ingress paths (RPC submit, gossip, overlay)
    /// MUST set this via [`AdmissionCtx::with_chain_height`].
    pub chain_height: Option<u64>,
}

impl AdmissionCtx {
    pub fn new(now: u64) -> Self {
        Self {
            now,
            onchain_nonce: None,
            shard: None,
            sponsor_balance: None,
            chain_height: None,
        }
    }

    /// Admission against the local wall clock. Used by the live admission
    /// paths (RPC, faucet, runtime, gossip, mempool restore) — mempool entry
    /// is node-local policy, exactly like the base fee, and is re-checked at
    /// propose/execute with the block timestamp.
    pub fn wall_now() -> Self {
        Self {
            now: crate::zkml::now_secs(),
            onchain_nonce: None,
            shard: None,
            sponsor_balance: None,
            chain_height: None,
        }
    }

    /// Carry the sender's on-chain nonce so [`Mempool::insert`] enforces the
    /// nonce-gap fail-fast itself (F-02). Pure builder: the clock is untouched.
    pub fn with_onchain_nonce(mut self, onchain_nonce: u64) -> Self {
        self.onchain_nonce = Some(onchain_nonce);
        self
    }

    /// Carry the admitting shard so [`Mempool::insert`] refuses foreign-shard
    /// transactions itself (P2 shard gate). Pure builder: the clock is untouched.
    pub fn with_shard(mut self, shard: crate::sharding::ShardId) -> Self {
        self.shard = Some(shard);
        self
    }

    /// Carry the sponsor's on-chain balance so [`Mempool::insert`] enforces
    /// the paymaster coverage check itself (sponsored transactions). Pure
    /// builder: the clock is untouched. Legacy transactions ignore this head;
    /// a sponsored transaction WITHOUT it is refused fail-closed.
    pub fn with_sponsor_balance(mut self, sponsor_balance: u64) -> Self {
        self.sponsor_balance = Some(sponsor_balance);
        self
    }

    /// Carry the chain height the transaction would be included at so
    /// [`Mempool::insert`] enforces the chain-binding gate itself (A14 phase
    /// 3). Pure builder: every other head is untouched. Callers that cannot
    /// name an inclusion height leave it `None` and keep legacy behaviour.
    pub fn with_chain_height(mut self, chain_height: u64) -> Self {
        self.chain_height = Some(chain_height);
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
    NonceGap {
        expected: u64,
        got: u64,
    },
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
    /// PAYMASTER: the sponsor grant is past `valid_until` at admission time.
    /// The same predicate is re-checked at propose and at apply against the
    /// block timestamp; admission uses the admission clock.
    SponsorExpired,
    /// PAYMASTER: `tx.to` is not in the grant's `allowed_targets` (non-empty
    /// allowlist). The grant does not cover this recipient.
    SponsorOutOfScope,
    /// PAYMASTER: the fee execution will actually charge
    /// (`max(gas_limit, floor) + surcharge`) exceeds the grant's
    /// `max_fee_per_tx`. The grant does not cover a fee this large.
    SponsorCapExceeded,
    /// PAYMASTER: the grant is unusable — the trailing `SP1` suffix is
    /// malformed, the envelope composes with an unsupported inner
    /// (session/PQ/EVM/chain-bound; v1 sponsors plain legacy ed25519 only),
    /// or the grant was not minted for this transaction.
    SponsorBadGrant,
    /// PAYMASTER: the sponsor's signature over
    /// [`crate::sharding::Transaction::sponsor_message`] does not verify.
    /// BOTH signatures (user + sponsor) must verify; one bad sig refuses the
    /// whole transaction fail-closed.
    SponsorBadSignature,
    /// PAYMASTER: the sponsor cannot cover the fee at admission time (their
    /// balance, minus what their pooled transactions already reserved, is
    /// below the fee execution will charge), or the caller admitted a
    /// sponsored transaction without carrying the sponsor's balance at all.
    /// Anti-DoS: a sponsored transaction with no funded sponsor behind it
    /// must never occupy pool space.
    SponsorInsufficientBalance,
    /// A14 chain-binding rollout, phase 3: the envelope binds no chain id
    /// (legacy unbound) and the gate is armed at the carried height. The
    /// inner string is the stable
    /// [`crate::chain_binding::UNBOUND_REFUSED_ERR_PREFIX`] refusal every
    /// admission path returns, so wallets match one string.
    UnboundRefused(String),
    /// Cross-network replay barrier: the envelope binds a FOREIGN chain id.
    /// A foreign-bound tx is cryptographically valid on ITS network, so this
    /// is refused purely on the replay domain (never on signature), mirroring
    /// the state-engine apply gate word-for-word. The inner string carries the
    /// stable [`crate::chain_binding::CHAIN_ID_MISMATCH_ERR_PREFIX`] refusal.
    ChainIdMismatch(String),
    /// Transaction payload or structure is malformed or violates protocol mode.
    Malformed(String),
    /// The transaction alone exceeds the block wire cap (`MAX_BLOCK_WIRE_BYTES`):
    /// no honest packing can ever include it, so admitting it would only let it
    /// occupy pool space (and fee-evict honest transactions) forever. Fail
    /// closed at admission.
    TxTooLarge {
        wire_bytes: usize,
        cap: usize,
    },
    /// The transaction alone exceeds the block proof-unit cap
    /// (`MAX_BLOCK_PROOF_UNITS`): packing skips it at every height, so it could
    /// never execute. Fail closed at admission.
    TxTooManyProofs {
        proof_units: usize,
        cap: usize,
    },
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
            MempoolError::SponsorExpired => "sponsor grant has expired",
            MempoolError::SponsorOutOfScope => {
                "sponsor grant does not cover this recipient (allowlist)"
            }
            MempoolError::SponsorCapExceeded => {
                "sponsor grant per-tx fee cap does not cover this transaction's fee"
            }
            MempoolError::SponsorBadGrant => "invalid sponsor grant",
            MempoolError::SponsorBadSignature => "invalid sponsor signature",
            MempoolError::SponsorInsufficientBalance => "sponsor cannot pay the transaction fee",
            MempoolError::UnboundRefused(reason) => return write!(f, "{reason}"),
            MempoolError::ChainIdMismatch(reason) => return write!(f, "{reason}"),
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
    /// (priority_fee_per_gas, effective_fee, hash) -> hash : ascending, so
    /// `.rev()` yields the highest priority first.
    ///
    /// PRIORITY, NOT THE RESOURCE CAP (audit: priority inversion): the key
    /// used to be `(gas_limit, hash)`, so a transaction that merely declared a
    /// HUGE `gas_limit` — a resource cap, not a price — took the top of the
    /// pool for free and preempted genuinely urgent transactions. The primary
    /// key is now the sender's EXPLICIT priority bid
    /// (`Transaction::priority_fee_per_gas`, signed by the sender and funded
    /// by its fee, see `required_fee_for_tx`); the secondary key is the fee
    /// the transaction actually pays (`gas_limit`), which is what a sender
    /// raises to buy a better position WITHIN its priority tier.
    order: BTreeMap<(u64, u64, TxHash), TxHash>,
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
    /// Pool-level shard pin (P2 shard gate, defense in depth).
    ///
    /// `AdmissionCtx::shard` pins ONE call; this pins the POOL: when set,
    /// `insert` refuses foreign-shard transactions on EVERY admission path —
    /// including paths whose caller never learned the local shard (RPC,
    /// explorer, gossip ingress, mempool restore). The live node sets it at
    /// startup when `ShardRegistry::is_sharded()` (see `main.rs`); unset
    /// (every test, every single-shard node) keeps the legacy shard-blind
    /// behavior. `#[serde(skip)]` like `failed_penalty`: node-local policy,
    /// never encoded, restarts re-pin at startup.
    #[serde(skip)]
    admission_shard: Option<crate::sharding::ShardId>,
    /// Minimum fee (`gas_limit`) accepted on the checked/network path (A11).
    ///
    /// FEE-MARKET HONESTY (audit F-11, verified as-stated): there is NO
    /// dynamic fee market — this is a STATIC gas-unit floor
    /// (`max(FROZEN_MIN_GAS_FLOOR, governed min_gas_limit)`, synced every
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
    /// FULL-PQ: dead — always enforced; kept for call-site compat and
    /// ignored (admission is PQ-only unconditionally; see below).
    /// Use `with_pure_pq` still compiles but is a no-op (warns).
    #[serde(skip)]
    pub pure_pq_enforced: Option<bool>,
    /// SEALED transactions: the ciphertext the network carries for the
    /// epoch-seal path (see [`crate::mev_epoch`]).
    ///
    /// A sealed transaction is stored as its CIPHERTEXT plus the transparent
    /// ordering metadata; the plaintext never enters the pool. The entry is
    /// admitted only after the envelope passes the structural check
    /// ([`crate::mev_epoch::SealedEnvelope::validate`]) and the epoch matches
    /// the pool's current epoch, so a malformed or stale seal is refused at
    /// admission instead of occupying pool space.
    ///
    /// `#[serde(skip)]` like `mev`: the encoded layout is unchanged and a
    /// restart simply starts with an empty sealed pool (a sealed
    /// transaction that was not included in a block is re-gossiped by its
    /// sender).
    #[serde(skip)]
    pub sealed: HashMap<[u8; 32], crate::mev_epoch::SealedEnvelope>,
    /// The MEV epoch the pool currently accepts sealed transactions for.
    /// A sealed envelope for another epoch is refused: the epoch key is
    /// rotated every 128 blocks and a stale ciphertext can never be
    /// unsealed by the current committee.
    #[serde(skip)]
    pub sealed_epoch: u64,
    /// The node-local state of the epoch-seal protocol: the epoch's DKG, the
    /// epoch key material, the order commitments the node has seen and the
    /// decryption partials it released / received.
    ///
    /// It lives in the mempool because the RPC layer shares the pool and
    /// the epoch key must be reachable from the RPC (`stell_epochKey`).
    /// `#[serde(skip)]` like the rest of the MEV state: the encoded pool
    /// layout is unchanged and a restart re-runs the DKG.
    #[serde(skip)]
    pub mev_seal: crate::mev_epoch::EpochSealManager,
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
            admission_shard: None,
            // No base fee by default; governance/config raises it under load.
            base_fee: 0,
            session_registry: None,
            mev: crate::mev::MevPreemptionEngine::new(),
            failed_penalty: HashMap::new(),
            activation_buffer: PendingActivationBuffer::new(),
            implicit_registry: None,
            pure_pq_enforced: None,
            sealed: HashMap::new(),
            sealed_epoch: crate::mev_epoch::epoch_of_height(0),
            mev_seal: crate::mev_epoch::EpochSealManager::new(),
        }
    }

    /// Explicitly configure Pure Post-Quantum mode for this mempool instance.
    /// FULL-PQ: no-op (always enforced). Kept for call-site compat; warns.
    pub fn with_pure_pq(mut self, enabled: bool) -> Self {
        let _ = enabled;
        eprintln!("[WARN] Mempool::with_pure_pq is a no-op (FULL-PQ always-on): value ignored");
        self.pure_pq_enforced = Some(true);
        self
    }

    /// Magic prefix for versioned mempool files (see `save`).
    ///
    /// BUMPED `MP02` -> `MP03` when the pool gained the explicit priority
    /// bid: the encoded transaction gained a trailing field and the order
    /// index changed key shape, so the inner layout is no longer the `MP02`
    /// one. The prefix is what keeps the two apart: a new file is never
    /// mis-read as an old one (an old binary given an `MP03` file fails to
    /// decode it and starts with an empty pool, instead of silently
    /// mis-parsing it), and an old `MP02` file still restores here through
    /// the `MP02` mirror in `load_into`.
    pub const MEMPOOL_FILE_MAGIC: &[u8; 4] = b"MP03";
    /// The previous envelope version (pre-priority-bid layout). Still
    /// accepted on load (see `load_into`), never written.
    pub const LEGACY_MEMPOOL_FILE_MAGIC: &[u8; 4] = b"MP02";
    /// How far ahead of the sender's executable head a nonce may be at
    /// admission (audit: blocks troubles). Rapid sequential submits stay
    /// inside; wild gaps fail fast with `NonceGap` instead of clogging the
    /// pool behind an unreachable head.
    ///
    /// REDUCED 16 -> 4 (audit: nonce-stuffing lockup): a 16-nonce window let a
    /// sender park 16 unexecutable transactions per account, each holding a
    /// pool slot for the whole `STUCK_TX_TTL_SECS`. The window is now the same
    /// 4 the activation buffer allows, so "far future" means four
    /// transactions, not sixteen.
    pub const NONCE_FUTURE_WINDOW: u64 = 4;
    /// Wall-clock seconds after which an UNEXECUTABLE tx is swept (audit:
    /// blocks troubles). Executable txs are never touched no matter their
    /// age — only ones the pool could never include.
    ///
    /// REDUCED 1800 -> 120: a nonce-stuffed transaction used to sit in the
    /// pool for half an hour, occupying a slot and (with
    /// `evict_unexecutable` sparing future nonces) never being reclaimed.
    pub const STUCK_TX_TTL_SECS: u64 = 120;
    /// Wall-clock seconds after which a FUTURE-nonce transaction (one waiting
    /// for a gap ahead of it to be filled) is reclaimed by
    /// [`Mempool::evict_unexecutable`].
    ///
    /// SHORTER THAN `STUCK_TX_TTL_SECS` on purpose: a future nonce is not
    /// dead — it is WAITING — but it occupies a pool slot exactly like a dead
    /// one, and the sender controls the gap it waits behind. Two minutes is
    /// long enough for the gap to fill under normal operation and short
    /// enough that nonce-stuffing cannot pin the pool.
    pub const FUTURE_NONCE_TTL_SECS: u64 = 60;
    /// Wire-size packing cap per block (audit: blocks troubles): gas-valid
    /// blocks can exceed what gossip can carry (32MB proposal cap), so the
    /// proposer stops packing at ~24MB estimated wire and leaves headroom.
    /// Estimate, not exact bincode (see `estimate_tx_wire_bytes`).
    pub const MAX_BLOCK_WIRE_BYTES: usize = 24 * 1024 * 1024;
    /// Verified-proof cap per block (audit: blocks troubles): attestation
    /// verifies and zkML re-executions serialize on the single apply worker
    /// while `apply_in_flight` blocks the next propose. Bounds worst-case lane
    /// stall per height; gas alone does not (cheap gas, costly verify).
    pub const MAX_BLOCK_PROOF_UNITS: usize = 2048;
    /// Denominator of the sealed-transaction share of the pool (audit:
    /// mempool economics — free sealed fill): sealed envelopes may occupy at
    /// most `max_size / MAX_SEALED_SHARE_DENOM` slots (see
    /// [`Mempool::sealed_cap`]).
    ///
    /// WHY (fail-closed containment, not pricing): the sealed path admits
    /// CIPHERTEXT with no funding check — no balance, no fee floor, no
    /// signature over funds — and the transparent `from` it charges the
    /// per-sender quota to is self-declared, so sender-sprawl (free keygen +
    /// fresh `from` per envelope) sails past the per-sender limit. Reachable
    /// via RPC and via P2P gossip, that is a free pool fill: forged envelopes
    /// (valid curve point + random bytes + random hash) could occupy the whole
    /// combined `max_size` cap and squeeze every honest plain transaction out.
    /// The cap bounds the damage to the sealed quota; the plain pool always
    /// keeps its own `max_size` slots (`insert` counts plain txs only).
    pub const MAX_SEALED_SHARE_DENOM: usize = 4;

    /// Global ceiling on SEALED transactions in this pool: at most one
    /// quarter of `max_size` (at least one slot, so tiny test pools still
    /// admit a sealed transaction). Enforced in [`Mempool::add_sealed`] with
    /// [`MempoolError::Full`]: a refused seal is gossipable-no-more pool
    /// pressure, never a silent drop of honest traffic.
    pub fn sealed_cap(&self) -> usize {
        (self.max_size / Self::MAX_SEALED_SHARE_DENOM).max(1)
    }

    /// Set the base fee (minimum accepted fee). Builder-style.
    pub fn with_base_fee(mut self, base_fee: u64) -> Self {
        self.base_fee = base_fee;
        self
    }

    /// Pin this pool to one shard (P2 shard gate, pool level). Builder-style.
    ///
    /// When set, `insert` refuses transactions whose `source_shard` is not
    /// this shard on EVERY admission path — the callers that already thread
    /// `AdmissionCtx::with_shard` stay pinned per call, and the callers that
    /// do not (RPC, explorer, gossip ingress, restore) are covered here, at
    /// the single choke point, instead of at each call site. `None` restores
    /// the legacy shard-blind behavior (single-shard nodes, tests).
    pub fn pin_admission_shard(mut self, shard: Option<crate::sharding::ShardId>) -> Self {
        self.admission_shard = shard;
        self
    }

    /// The pool-level shard pin, if any.
    pub fn admission_shard(&self) -> Option<crate::sharding::ShardId> {
        self.admission_shard
    }

    /// Pin this pool to one shard, in place (node startup path, which holds
    /// the pool behind a lock and cannot use the consuming builder).
    pub fn set_admission_shard(&mut self, shard: Option<crate::sharding::ShardId>) {
        self.admission_shard = shard;
    }

    /// Admission floor for `sender`: `base_fee` plus any failure penalty the
    /// sender is carrying (D2). The proposer filter snapshots this per sender
    /// so pooled retries of a failing sender are skipped until they over-post.
    pub fn effective_floor(&self, sender: &[u8; 32]) -> u64 {
        self.base_fee
            .saturating_add(self.failed_penalty.get(sender).copied().unwrap_or(0))
    }

    /// Full admission cost of one transaction: `amount + gas_limit`, plus the
    /// State Rent Surcharge for activation txs. This is exactly what execution
    /// charges (`state_engine`), so it is both the single-tx balance check and
    /// the per-sender reservation unit (F-03). Single definition so the two
    /// can never drift apart.
    ///
    /// LEGACY PATH ONLY. A sponsored transaction splits into two legs (see
    /// [`Mempool::sponsor_legs`]): the user covers `amount`, the sponsor
    /// covers the fee. `tx_cost` is kept for the legacy path and as the
    /// arithmetic both legs add up from.
    pub fn tx_cost(tx: &Transaction) -> u64 {
        tx.amount
            .saturating_add(tx.gas_limit)
            .saturating_add(if tx.is_pq_activation() {
                PQ_ACTIVATION_SURCHARGE_GAS
            } else {
                0
            })
    }

    /// PAYMASTER: the fee execution will actually charge for `tx` —
    /// `max(declared gas_limit, admission floor) + activation surcharge`.
    ///
    /// The floor is the SAME [`Mempool::required_fee_for_tx`] admission uses
    /// for the `gas_limit` check (base + D2 penalty + bid), so the cap check
    /// prices what execution will debit. The D2 penalty stays keyed on the
    /// USER (whose nonce advances and whose failure history it prices); the
    /// sponsor is protected by their explicit per-tx cap
    /// (`max_fee_per_tx`), not by the penalty.
    ///
    /// Used for the POLICY check only. The RESERVATION legs use the pure
    /// [`Mempool::sponsored_pure_legs`] instead: admission already refuses
    /// `gas_limit < floor`, so for every admitted transaction the max() is
    /// the identity and the two agree — while the pure legs keep claim and
    /// release byte-identical even if the penalty map moves between them
    /// (recomputing a penalty-keyed fee at release would over-release and
    /// free money that was never claimed).
    pub fn sponsor_fee_cost(&self, tx: &Transaction) -> u64 {
        tx.gas_limit
            .max(self.required_fee_for_tx(tx))
            .saturating_add(if tx.is_pq_activation() {
                PQ_ACTIVATION_SURCHARGE_GAS
            } else {
                0
            })
    }

    /// PAYMASTER: the two PURE funding legs of an EFFECTIVE sponsored
    /// transaction (`sponsor != from`): `(user_cost, sponsor_cost)`.
    ///
    /// * the user pays VALUE: `amount` (their balance is never touched for
    ///   the fee — not base, not gas, not failure-fee);
    /// * the sponsor pays FEE: `gas_limit + activation surcharge`.
    ///
    /// Pure function of the transaction: admission claims exactly these legs
    /// and release frees exactly these legs, so the ledger can never drift.
    /// (`gas_limit` already covers the floor — admission refuses below-floor
    /// declarations before any coverage check — so this is also what
    /// execution debits whenever the floor does not move after admission.)
    ///
    /// `None` on the legacy path and the self-sponsored path
    /// (`sponsor == from`, which fee-routes as plain).
    pub fn sponsored_pure_legs(tx: &Transaction) -> Option<(u64, u64)> {
        tx.sponsored_grant().map(|_| {
            (
                tx.amount,
                tx.gas_limit.saturating_add(if tx.is_pq_activation() {
                    PQ_ACTIVATION_SURCHARGE_GAS
                } else {
                    0
                }),
            )
        })
    }

    /// PAYMASTER: the two funding legs of an EFFECTIVE sponsored transaction
    /// (`sponsor != from`): `(user_cost, sponsor_cost)`.
    ///
    /// The user leg is the pure `amount`; the sponsor leg prices the live
    /// floor (see [`Mempool::sponsor_fee_cost`]). Used where the CURRENT fee
    /// matters (coverage checks); the reservation ledger itself claims and
    /// releases the pure legs ([`Mempool::sponsored_pure_legs`]).
    ///
    /// `None` on the legacy path and the self-sponsored path
    /// (`sponsor == from`, which fee-routes as plain).
    pub fn sponsor_legs(&self, tx: &Transaction) -> Option<(u64, u64)> {
        tx.sponsored_grant()
            .map(|_| (tx.amount, self.sponsor_fee_cost(tx)))
    }

    /// Funds already claimed by `sender`'s pooled transactions (F-03). A new
    /// checked admission is refused when `reserved_for(sender) + tx_cost(new)`
    /// exceeds the sender's balance, so one funding cannot back more slots
    /// than it can jointly pay for.
    pub fn reserved_for(&self, sender: &[u8; 32]) -> u64 {
        self.reserved.get(sender).copied().unwrap_or(0)
    }

    /// Release the claim one transaction holds against its funder's balance.
    ///
    /// THE reservation ledger is a strict one-in / one-out: a transaction's
    /// cost is claimed when it enters the pool (or the activation buffer) and
    /// released EXACTLY once when it leaves (eviction, removal, sweep, or a
    /// drain out of the activation buffer). Releasing twice frees money that
    /// was never there (the sender could then over-commit), and never
    /// releasing LEAKS it: the sender's balance stays reserved forever and
    /// every later transaction is refused with `InsufficientBalance` although
    /// the money is free (audit W6.6: activation-buffer reservation leak).
    ///
    /// PAYMASTER: a sponsored transaction holds TWO claims — the user's
    /// `amount` under the user, the fee under the sponsor — and both are
    /// released here. The legs are the pure
    /// [`Mempool::sponsored_pure_legs`] admission claimed, so release can
    /// never drift from claim.
    fn release_reservation(&mut self, tx: &Transaction) {
        if let Some((user_cost, sponsor_cost)) = Self::sponsored_pure_legs(tx) {
            let sponsor = tx.fee_payer();
            if let Some(r) = self.reserved.get_mut(&tx.from) {
                *r = r.saturating_sub(user_cost);
                if *r == 0 {
                    self.reserved.remove(&tx.from);
                }
            }
            if let Some(r) = self.reserved.get_mut(&sponsor) {
                *r = r.saturating_sub(sponsor_cost);
                if *r == 0 {
                    self.reserved.remove(&sponsor);
                }
            }
            return;
        }
        let cost = Self::tx_cost(tx);
        if let Some(r) = self.reserved.get_mut(&tx.from) {
            *r = r.saturating_sub(cost);
            if *r == 0 {
                self.reserved.remove(&tx.from);
            }
        }
    }

    /// Minimum bid that may displace the cheapest pooled transaction
    /// (audit-mempool F-04): a small, GENTLE premium over the lowest price in
    /// the pool.
    ///
    /// Choice rationale (evict-only-at->=a premium, NOT a per-sender-per-minute
    /// eviction cap): the premium is deterministic and stateless — no wall-clock,
    /// no new per-sender timestamps for an attacker to grind against, no
    /// cross-call accounting that honest bursts could trip. Honest traffic is
    /// unaffected: this gate runs ONLY when the pool is already full (a
    /// non-full pool admits every floor-passing tx), and a full pool means
    /// genuine congestion where a premium is the honest price signal anyway.
    ///
    /// GENTLER THAN 2x (audit: exponential eviction lockout): the old rule
    /// demanded `fee >= 2 * low_fee`, so every full-pool sweep DOUBLED the
    /// admission threshold. Under sustained load the threshold walked into
    /// the millions within a few sweeps and no honest transaction could ever
    /// re-enter the pool again — a permanent, self-inflicted lockout. The
    /// premium is now 5% (+1) of the displaced price, so the threshold grows
    /// linearly with the pool's own price instead of exponentially.
    fn eviction_bid_beats(
        new_priority: u64,
        new_fee: u64,
        low_priority: u64,
        low_fee: u64,
    ) -> bool {
        if new_priority > low_priority {
            // A higher EXPLICIT priority outranks the incumbent — but the
            // newcomer must still not pay LESS than the transaction it
            // displaces (priority is a bonus, not a discount).
            new_fee > low_fee
        } else if new_priority == low_priority {
            // Same priority tier: the newcomer must beat the incumbent's
            // price by the gentle premium.
            new_fee >= low_fee.saturating_add(Self::eviction_premium(low_fee))
        } else {
            // A LOWER explicit priority never displaces anything, whatever
            // it pays: the priority bid is the price that decides.
            false
        }
    }

    /// Premium (in price units) a newcomer must add to the cheapest pooled
    /// price to displace it: 5% of that price, rounded up, at least 1 unit.
    ///
    /// `ceil(low_fee / 20)` with a floor of 1 — 100 -> 105, 1_000 -> 1_050,
    /// 1_000_000 -> 1_050_000 (the old 2x rule demanded 2_000_000). The "+1"
    /// in "5%+1" is the minimum-one-unit floor (a 5% premium on a price below
    /// 20 would otherwise round to 0 and displace for free), not an extra
    /// unit on top: the boundary `low_fee + premium` itself is admitted
    /// (`>=` in `eviction_bid_beats`).
    pub fn eviction_premium(low_fee: u64) -> u64 {
        low_fee.div_ceil(20).max(1)
    }

    /// The fee a transaction must declare (`gas_limit`) to be admitted: the
    /// effective floor PLUS its explicit priority bid.
    ///
    /// THE BID MUST BE PAID FOR. Without this the priority tip would be a
    /// free lever: the cheapest possible spam could claim the top of the
    /// pool forever without paying a single extra unit. Because the bid is
    /// covered by the transaction's own fee, priority costs money and the
    /// admission threshold cannot be gamed for free.
    pub fn required_fee_for_tx(&self, tx: &Transaction) -> u64 {
        self.effective_floor_for_tx(tx)
            .saturating_add(tx.priority_fee_per_gas)
    }

    /// The price a transaction pays for its slot: what it is charged
    /// (`gas_limit`, the chain's fee unit) — the SECONDARY ordering key,
    /// used inside a priority tier.
    pub fn effective_fee(tx: &Transaction) -> u64 {
        tx.gas_limit
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
    ///
    /// THE SENDER'S BALANCE IS RESERVED FOR THE BUFFERED TRANSACTION (audit:
    /// activation buffer exhaustion). The activation buffer is a GLOBAL, capped
    /// resource: 2048 slots that every unactivated account shares. Before this
    /// fix a sender could park transactions in it without funding them, so a
    /// spammer could fill the whole buffer with unfunded transactions and lock
    /// every LEGITIMATE unactivated account out of the network (they were told
    /// "too many transactions from this sender", which was a lie: their own
    /// quota was empty). Reserving the balance makes the buffer cost real
    /// money, exactly like a pooled transaction (F-03), so saturating it
    /// requires funding every slot.
    ///
    /// PAYMASTER v1 does not compose with PQ activation (a sponsor rides a
    /// plain legacy ed25519 inner only), so a sponsored transaction is refused
    /// here fail-closed — the checked path refuses it first anyway.
    ///
    /// `sender_balance` is the sender's CURRENT balance; the transaction's
    /// full cost (`amount + gas_limit` + the activation surcharge) is added to
    /// the sender's reservation table and released when the transaction is
    /// drained, removed or swept.
    pub fn buffer_activation_tx(
        &mut self,
        tx: Transaction,
        sender_balance: u64,
    ) -> Result<TxHash, MempoolError> {
        if tx.sponsored_grant().is_some() {
            return Err(MempoolError::SponsorBadGrant);
        }
        // PQ activation surcharge: the drain path re-admits through the full
        // `effective_floor_for_tx` check, so flooring the buffer on the bare
        // sender floor admits under-priced activation txs that squat in the
        // 2048-slot global buffer until drain re-prices them. Mirror admission
        // exactly. Node-local policy only (never consensus state), matching
        // the existing floor check direction: fail-closed on spam, no validity
        // rule changes.
        let floor = self.required_fee_for_tx(&tx);
        let cost = Self::tx_cost(&tx);
        if sender_balance < cost {
            return Err(MempoolError::InsufficientBalance);
        }
        if self.reserved_for(&tx.from).saturating_add(cost) > sender_balance {
            return Err(MempoolError::InsufficientBalance);
        }
        let (hash, old_tx) = self.activation_buffer.buffer_tx_with_timestamp(
            tx.clone(),
            floor,
            crate::zkml::now_secs(),
        )?;
        if let Some(ref old) = old_tx {
            // The replaced transaction leaves the buffer: its claim ends here.
            self.release_reservation(old);
        }
        *self.reserved.entry(tx.from).or_insert(0) =
            self.reserved_for(&tx.from).saturating_add(cost);
        Ok(hash)
    }

    /// Process and drain all pending activation transactions for a sender.
    ///
    /// The drained transactions leave the BUFFER, so the reservation the buffer
    /// held for them is released here and re-taken by the re-admission below
    /// (in the pool, or back in the buffer if the account is still not
    /// activated). Releasing it exactly once is what keeps the sender's pooled
    /// claim equal to the money his transactions actually claim (audit W6.6:
    /// activation-buffer reservation leak).
    pub fn process_activation_buffer(&mut self, sender: &[u8; 32]) -> Vec<TxHash> {
        let pending = self.activation_buffer.drain_account(sender);
        // The buffer's claims end with the buffer.
        for tx in &pending {
            self.release_reservation(tx);
        }
        let mut admitted = Vec::new();
        let ctx = AdmissionCtx::wall_now();
        for tx in pending {
            let hash = tx.compute_tx_hash();
            // The checked path (with the pool's own unbounded balance) is used
            // on purpose: the unchecked path REFUSES to re-buffer an
            // unactivated transaction (the buffer needs a balance to reserve
            // against) and would silently DROP it.
            if self.insert(tx, u64::MAX, true, ctx).is_ok() {
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

    // ------------------------------------------------------------------
    // Sealed (epoch-seal) transactions
    // ------------------------------------------------------------------

    /// Set the MEV epoch the pool accepts sealed transactions for.
    ///
    /// Called when the chain advances into a new epoch. A sealed envelope
    /// for another epoch is refused at admission: the epoch key rotates
    /// every [`crate::mev_epoch::EPOCH_BLOCKS`] blocks and a ciphertext
    /// sealed to a previous epoch's key can never be unsealed by the
    /// current committee.
    pub fn set_sealed_epoch(&mut self, epoch: u64) {
        if self.sealed_epoch != epoch {
            // The old epoch's ciphertexts are dead: their key is gone and
            // nobody can unseal them. Drop them (the senders re-gossip).
            // Audit F2: release the shared per-sender slots the dropped
            // ciphertexts held — otherwise the quota leaks permanently and
            // a heavy sealed sender is eventually refused on an empty pool.
            for envelope in std::mem::take(&mut self.sealed).into_values() {
                self.release_sender_slot(&envelope.meta.from);
            }
            self.sealed_epoch = epoch;
        }
    }

    /// The MEV epoch the pool currently accepts sealed transactions for.
    pub fn sealed_epoch(&self) -> u64 {
        self.sealed_epoch
    }

    /// Admit a SEALED transaction (the epoch-seal path).
    ///
    /// Fail closed: a malformed envelope, an envelope for another epoch, or
    /// an envelope whose transaction hash is already known is REFUSED with a
    /// clear error, so a bad seal can never occupy pool space, never be
    /// gossiped on, and can never stall a proposer. A seal is ALSO refused
    /// once the sealed quota ([`Mempool::sealed_cap`]) is full — the sealed
    /// path carries no funding proof, so an uncapped seal would be a free,
    /// sender-spoofable pool fill (audit: mempool economics).
    pub fn add_sealed(
        &mut self,
        envelope: crate::mev_epoch::SealedEnvelope,
    ) -> Result<[u8; 32], MempoolError> {
        envelope
            .validate()
            .map_err(|e| MempoolError::Malformed(format!("sealed transaction refused: {e}")))?;
        if envelope.epoch != self.sealed_epoch {
            return Err(MempoolError::Malformed(format!(
                "sealed transaction refused: sealed for epoch {} but the pool is at epoch {}",
                envelope.epoch, self.sealed_epoch
            )));
        }
        let hash = envelope.tx_hash;
        if self.sealed.contains_key(&hash) || self.txs.contains_key(&hash) {
            return Err(MempoolError::Duplicate);
        }
        // The per-sender quota applies to the sealed path too: the sender is
        // visible in the transparent metadata, so the same quota bounds the
        // pool's exposure to one sender. The counter is SHARED with the
        // plain path, so a sender cannot get `2 x limit` by splitting its
        // traffic over the two paths.
        let sender = envelope.meta.from;
        let sender_count = self.per_sender.get(&sender).copied().unwrap_or(0);
        if sender_count >= self.per_sender_limit {
            return Err(MempoolError::TooManyFromSender);
        }
        // Sealed-quota containment (audit: mempool economics — free sealed
        // fill): the sealed path proves no funds, so the sealed count — not
        // just the combined pool size — is capped. Without this, forged
        // envelopes (free keygen, spoofed `from` per envelope) fill the whole
        // combined cap and evict honest plain transactions by pressure.
        if self.sealed.len() >= self.sealed_cap() {
            return Err(MempoolError::Full);
        }
        if self.sealed.len() + self.txs.len() >= self.max_size {
            return Err(MempoolError::Full);
        }
        *self.per_sender.entry(sender).or_insert(0) += 1;
        self.sealed.insert(hash, envelope);
        Ok(hash)
    }

    /// The sealed transactions, ordered for block packing.
    ///
    /// The order is by the TRANSPARENT priority bid (then the fee, then the
    /// hash) — the same key the plain path uses, so a proposer that mixes
    /// both paths keeps ONE deterministic ordering rule. The metadata is
    /// re-verified against the plaintext after the unseal, so a lying
    /// metadata field can buy priority only at the cost of being dropped.
    pub fn sealed_candidates(&self) -> Vec<crate::mev_epoch::SealedEnvelope> {
        let mut out: Vec<crate::mev_epoch::SealedEnvelope> =
            self.sealed.values().cloned().collect();
        out.sort_by(|a, b| {
            b.meta
                .priority_fee_per_gas
                .cmp(&a.meta.priority_fee_per_gas)
                .then(b.meta.gas_limit.cmp(&a.meta.gas_limit))
                .then(a.tx_hash.cmp(&b.tx_hash))
        });
        out
    }

    /// The number of sealed transactions in the pool.
    pub fn sealed_count(&self) -> usize {
        self.sealed.len()
    }

    /// The sealed share of the pool (sealed / (sealed + plain)).
    ///
    /// Reported by the explorer and the metrics so the operator can see
    /// whether the private path is actually being used.
    pub fn sealed_share(&self) -> f64 {
        let sealed = self.sealed.len() as f64;
        let total = sealed + self.txs.len() as f64;
        if total == 0.0 {
            0.0
        } else {
            sealed / total
        }
    }

    /// The sealed envelope for a transaction hash (if we have it).
    pub fn sealed_envelope(&self, hash: &[u8; 32]) -> Option<&crate::mev_epoch::SealedEnvelope> {
        self.sealed.get(hash)
    }

    /// Drop a sealed transaction that left the pool (included in a block).
    pub fn remove_sealed(&mut self, hash: &[u8; 32]) {
        if let Some(envelope) = self.sealed.remove(hash) {
            self.release_sender_slot(&envelope.meta.from);
        }
    }

    /// Give back the per-sender slot a sealed transaction held.
    fn release_sender_slot(&mut self, sender: &[u8; 32]) {
        if let Some(count) = self.per_sender.get_mut(sender) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_sender.remove(sender);
            }
        }
    }

    /// Drop a sealed transaction that could NOT be unsealed, and charge its
    /// sender.
    ///
    /// THE TIMEOUT PATH of the epoch-seal scheme: a sealed transaction whose
    /// decryption partials never arrived (a member withheld its share, or the
    /// ciphertext was garbage) is EVICTED from the pool — it must not hold
    /// pool space forever — and its sender is charged the FAILURE BOND, the
    /// very same penalty an execution failure costs (see
    /// [`Mempool::note_apply_feedback`] and `FAILED_SENDER_PENALTY`): the
    /// sender must over-post on its next submission.
    ///
    /// The bond is NODE-LOCAL policy (like `base_fee`), never consensus
    /// state: it is the same mechanism the chain already uses for a failed
    /// transaction, and it keeps the sealed path from being a free way to
    /// fill the pool. A CONSENSUS-level fee transfer for a dropped sealed
    /// transaction is NOT implemented (it would need a new block-level
    /// construct); see `docs/MEV.md`.
    pub fn drop_sealed(&mut self, hash: &[u8; 32], from: &[u8; 32]) {
        if self.sealed.remove(hash).is_some() {
            self.release_sender_slot(from);
        }
        self.penalize_sender(from);
    }

    /// Raise a sender's admission bond by one step (the D2 failure gate).
    pub fn penalize_sender(&mut self, from: &[u8; 32]) {
        let e = self.failed_penalty.entry(*from).or_insert(0);
        *e = (*e)
            .saturating_add(FAILED_SENDER_PENALTY)
            .min(MAX_FAILED_SENDER_PENALTY);
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
    /// FREEZE (protocol freeze 2026-11-03): canonical admission fee floor,
    /// 280_000 gas (= [`crate::svm::GAS_BASIC_TRANSFER`], the cheapest real
    /// transfer). Value = pre-freeze `STELL_MIN_GAS_LIMIT` code default; the
    /// env knob is removed — the floor MUST be identical on all validators
    /// (main.rs `[config]` log) and a per-node env knob for a must-match
    /// value is a divergence risk. Change requires spec update + audit note
    /// (AGENTS.md §7).
    pub const FROZEN_MIN_GAS_FLOOR: u64 = crate::svm::GAS_BASIC_TRANSFER;

    /// The frozen canonical admission floor (see [`Self::FROZEN_MIN_GAS_FLOOR`]).
    ///
    /// CONSENSUS WARNING (audit 2026-10-06): this is enforced ONLY at
    /// admission, never in the proposer filter or apply path. ALL validators
    /// run the identical value by construction now (frozen const, no env);
    /// node startup still logs the effective floor at info so a divergent
    /// binary is visible in the first lines of every journal.
    pub fn frozen_base_fee_floor() -> u64 {
        Self::FROZEN_MIN_GAS_FLOOR
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
    /// struct, so files carry a magic prefix — `b"MP03" + bincode(self)`.
    /// `load_into` reads the prefix and falls back to the older layouts
    /// (`MP02` and the bare pre-TTL bincode), so old files restore (with
    /// fresh timestamps) instead of silently vanishing.
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
        let body: &[u8] = bytes
            .strip_prefix(Self::MEMPOOL_FILE_MAGIC)
            .or_else(|| bytes.strip_prefix(Self::LEGACY_MEMPOOL_FILE_MAGIC))
            .unwrap_or(&bytes);
        // Pre-TTL layout mirror (no `inserted_at`): bincode cannot skip a
        // missing trailing field, so legacy files decode here explicitly and
        // re-enter with fresh timestamps.
        //
        // The mirror also carries the PRE-PRIORITY shapes: the order index was
        // keyed by `(gas_limit, hash)` and the transaction had no priority
        // field. Bincode is positional, so a legacy file cannot be decoded
        // with the current types — the trailing priority field of the last
        // transaction would eat the next element's bytes, and the order index
        // would mis-parse. The mirror keeps the old shapes and the
        // transactions are converted to the current type (priority 0) below.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct LegacyTransaction {
            from: [u8; 32],
            to: [u8; 32],
            amount: u64,
            gas_limit: u64,
            nonce: u64,
            source_shard: crate::sharding::ShardId,
            target_shard: crate::sharding::ShardId,
            signature: Vec<u8>,
            #[serde(default)]
            payload: Vec<crate::svm::OpCode>,
        }

        impl From<LegacyTransaction> for Transaction {
            fn from(t: LegacyTransaction) -> Self {
                Transaction {
                    from: t.from,
                    to: t.to,
                    amount: t.amount,
                    gas_limit: t.gas_limit,
                    nonce: t.nonce,
                    source_shard: t.source_shard,
                    target_shard: t.target_shard,
                    signature: t.signature,
                    payload: t.payload,
                    priority_fee_per_gas: 0,
                }
            }
        }

        #[derive(serde::Serialize, serde::Deserialize)]
        struct LegacyMempool {
            txs: HashMap<TxHash, LegacyTransaction>,
            order: BTreeMap<(u64, TxHash), TxHash>,
            per_sender: HashMap<[u8; 32], usize>,
            max_size: usize,
            per_sender_limit: usize,
            base_fee: u64,
        }

        // The `MP02` layout: the same pre-priority shapes PLUS the `inserted_at`
        // map. Kept as its own mirror because the two legacy layouts differ by
        // exactly that trailing map, and bincode cannot skip it.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Mp02Mempool {
            txs: HashMap<TxHash, LegacyTransaction>,
            order: BTreeMap<(u64, TxHash), TxHash>,
            per_sender: HashMap<[u8; 32], usize>,
            inserted_at: HashMap<TxHash, u64>,
            max_size: usize,
            per_sender_limit: usize,
            base_fee: u64,
        }

        let saved: Mempool = if let Ok(s) = bincode::deserialize::<Mempool>(body) {
            s
        } else if let Ok(old) = bincode::deserialize::<Mp02Mempool>(body) {
            let mut m =
                Mempool::new(old.max_size, old.per_sender_limit).with_base_fee(old.base_fee);
            m.txs = old.txs.into_iter().map(|(h, t)| (h, t.into())).collect();
            m.per_sender = old.per_sender;
            m.inserted_at = old.inserted_at;
            m
        } else if let Ok(legacy) = bincode::deserialize::<LegacyMempool>(body) {
            let mut m = Mempool::new(legacy.max_size, legacy.per_sender_limit)
                .with_base_fee(legacy.base_fee);
            m.txs = legacy.txs.into_iter().map(|(h, t)| (h, t.into())).collect();
            m.per_sender = legacy.per_sender;
            // `order` is rebuilt by the re-admission loop below (with the
            // CURRENT `(priority, fee, hash)` key), so the legacy index is
            // deliberately not carried over.
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
            // PAYMASTER: restore carries the sponsor's head from committed
            // state, like the live paths do — otherwise every sponsored
            // transaction would be dropped at restart (fail-closed without a
            // head) even though its sponsor is still funded.
            let mut rctx = ctx.with_onchain_nonce(onchain);
            if let Some(grant) = tx.sponsored_grant() {
                let sbal = accounts
                    .get_account(&grant.sponsor)
                    .await
                    .map(|a| a.balance)
                    .unwrap_or(0);
                rctx = rctx.with_sponsor_balance(sbal);
            }
            if self.insert(tx, bal, true, rctx).is_ok() {
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
        self.txs
            .get(hash)
            .or_else(|| self.activation_buffer.get_by_hash(hash))
    }

    /// Add a transaction. Validates the signature, rejects duplicates, enforces
    /// the per-sender quota, and — if the pool is full — evicts the
    /// lowest-PRICED transaction when the new one outbids it, else rejects it.
    /// Add a transaction WITHOUT checking the sender's balance.
    ///
    /// This is the legacy entry point kept for tests and trusted in-process
    /// callers. It can never evict an existing transaction (a caller that cannot
    /// prove the sender's balance must not be able to displace others by
    /// declaring a huge `gas_limit` for free). New transactions are only
    /// admitted if there is room, otherwise `MempoolError::Full` is returned.
    /// Session-key policy is evaluated against the local wall clock; the live
    /// admission paths pass an explicit clock via `add_checked`.
    ///
    /// It also refuses to BUFFER an unactivated (PQ implicit) transaction:
    /// the activation buffer is a global capped resource and every slot in it
    /// must be funded, which needs a balance (audit: activation buffer
    /// exhaustion). Use [`Mempool::add_checked`] for those.
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

    /// Drop every pooled UNBOUND transaction once refusal is active (A14 phase
    /// 3: in-flight unbound transactions are dropped at activation, never
    /// grandfathered — a grandfathered unbound tx included post-height would
    /// fork mixed-version nodes). Returns how many were dropped.
    ///
    /// The partition itself runs through
    /// [`crate::chain_binding::partition_at_activation`] (pure, order
    /// preserving) so the drop accounting stays in one place
    /// (`unbound_dropped_at_activation`); each dropped hash is then evicted
    /// through [`Mempool::evict`], which keeps the fee index, the per-sender
    /// quota and the F-03 reservations in step. Pre-activation (or
    /// default-off) this is a no-op returning 0 — the pool is untouched.
    /// Called ONCE when crossing the activation height (see the main-loop
    /// call site); re-running it later is harmless but pointless, because
    /// `insert` already refuses new unbound arrivals while armed.
    pub fn drop_unbound_at_activation(
        &mut self,
        chain_height: u64,
        activation: &crate::chain_binding::ChainBindingActivation,
    ) -> usize {
        if !activation.refusal_active(chain_height) {
            return 0;
        }
        let items: Vec<(TxHash, bool)> = self
            .txs
            .iter()
            .map(|(hash, tx)| (*hash, tx.chain_id().is_some()))
            .collect();
        let (_kept, dropped) =
            crate::chain_binding::partition_at_activation(items, chain_height, activation);
        for hash in &dropped {
            self.evict(hash);
        }
        for _ in 0..dropped.len() {
            crate::metrics::global().inc_unbound_refused();
        }
        dropped.len()
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
    /// simply waiting for the earlier ones — but only until they have aged
    /// past [`Mempool::FUTURE_NONCE_TTL_SECS`] (see
    /// [`Mempool::evict_unexecutable_at`]).
    /// Drop transactions that can never execute: consumed nonce or
    /// unaffordable at the snapshot the caller supplies. A sender the
    /// snapshot does not know (`None`) is SKIPPED, never treated as broke:
    /// the account may simply be missing from a partial/pre-height view, and
    /// the proposer filter already skips such senders without deleting them
    /// (audit 2026-10-06: the old `(0,0)` default irreversibly destroyed
    /// valid funded transactions).
    pub fn evict_unexecutable<F>(&mut self, account: F) -> usize
    where
        F: FnMut(&[u8; 32]) -> Option<(u64, u64)>,
    {
        self.evict_unexecutable_at(crate::zkml::now_secs(), account)
    }

    /// [`Mempool::evict_unexecutable`] with an EXPLICIT clock.
    ///
    /// On top of the dead transactions (consumed nonce, unaffordable), this
    /// reclaims FUTURE-nonce transactions that have waited for their gap to
    /// fill for longer than [`Mempool::FUTURE_NONCE_TTL_SECS`] (audit:
    /// nonce-stuffing lockup). A future nonce is not dead, but it occupies a
    /// pool slot exactly like a dead one and the SENDER controls the gap it
    /// waits behind: without this, a sender could stuff the pool with
    /// unexecutable transactions that `evict_unexecutable` deliberately
    /// spared, holding slots until the (much longer) stuck-TTL sweep.
    ///
    /// The clock is node-local policy (never consensus state), like the
    /// admission clock.
    pub fn evict_unexecutable_at<F>(&mut self, now_secs: u64, mut account: F) -> usize
    where
        F: FnMut(&[u8; 32]) -> Option<(u64, u64)>,
    {
        // Per-sender executable heads (mex of onchain + pooled), computed once:
        // a tx past its head is waiting for a gap that may never be filled.
        let mut heads: HashMap<[u8; 32], u64> = HashMap::new();
        {
            let mut by_sender: HashMap<[u8; 32], Vec<u64>> = HashMap::new();
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
                let (nonce, balance) = account(&tx.from)?;
                let stale_nonce = tx.nonce < nonce;
                // PAYMASTER: the legs split — the user leg (`amount`) is
                // checked against the user's balance, the fee leg against the
                // SPONSOR's (a sponsor that spent down mid-mempool makes the
                // transaction unexecutable, and the sweep reclaims the slot).
                // An unknown sponsor (partial view) never deletes: the
                // proposer filter skips the transaction without removing it.
                let unaffordable = match Self::sponsored_pure_legs(tx) {
                    Some((user_cost, sponsor_cost)) => {
                        let sponsor = tx.fee_payer();
                        let user_short = user_cost > balance;
                        let sponsor_short = account(&sponsor)
                            .map(|(_, sponsor_balance)| sponsor_cost > sponsor_balance)
                            .unwrap_or(false);
                        user_short || sponsor_short
                    }
                    None => tx.amount.saturating_add(tx.gas_limit) > balance,
                };
                // Waiting behind a gap for too long: the sender controls the
                // gap, so an aged future nonce is pool pollution, not a
                // pending payment.
                let head = heads.get(&tx.from).copied().unwrap_or(nonce);
                let aged_future = tx.nonce > head
                    && self.tx_age_secs(now_secs, tx) >= Self::FUTURE_NONCE_TTL_SECS;
                if stale_nonce || unaffordable || aged_future {
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

    /// Age of a pooled transaction in seconds (0 when it has no stamp).
    fn tx_age_secs(&self, now_secs: u64, tx: &Transaction) -> u64 {
        let inserted = self
            .inserted_at
            .get(&tx.compute_tx_hash())
            .copied()
            .unwrap_or(now_secs);
        now_secs.saturating_sub(inserted)
    }

    fn insert(
        &mut self,
        tx: Transaction,
        sender_balance: u64,
        check_balance: bool,
        ctx: AdmissionCtx,
    ) -> Result<TxHash, MempoolError> {
        // A14 phase 3 (chain binding, defense in depth for P2P-received
        // transactions): refuse unbound envelopes at/after the configured
        // activation height instead of pooling them.
        // GATE: `ctx.chain_height` is the height the caller believes this tx
        // would be included at (RPC ingress: finalized-tip+1; gossip/overlay:
        // same), derived from COMMITTED state — never a peer-supplied value.
        // `None` (every legacy caller) skips the check outright, and with the
        // activation env unset `check_admission_from_env` passes everything,
        // so both height-less and default-off admission stay byte-identical.
        // Cheap (pure predicate) and placed before any crypto so refused
        // replays are also cheap to refuse.
        if let Some(chain_height) = ctx.chain_height {
            if let Err(reason) = crate::chain_binding::check_admission_from_env(
                tx.chain_id().is_some(),
                chain_height,
                crate::consensus::consensus_chain_id(),
            ) {
                crate::metrics::global().inc_unbound_refused();
                return Err(MempoolError::UnboundRefused(reason));
            }
        }
        // Cross-network replay barrier (fail-closed, always on — unlike the
        // activation-gated unbound rule above, a foreign chain id is never
        // admissible on any network): a BOUND envelope naming another chain
        // is refused here instead of pooling it for apply to refuse later.
        // Cheap (one u64 compare, no crypto) and placed with the other
        // pre-crypto gates. Unbound envelopes (None) keep the legacy path —
        // presence is what this checks, existence is the gate above.
        if let Some(envelope_chain) = tx.chain_id() {
            let ours = crate::consensus::consensus_chain_id();
            if envelope_chain != ours {
                return Err(MempoolError::ChainIdMismatch(
                    crate::chain_binding::chain_id_mismatch_err(envelope_chain, ours),
                ));
            }
        }
        // FULL-PQ (no compat, nodes wiped): a PQ envelope carrying a
        // post-quantum scheme is mandatory on EVERY admission path. The old
        // flag-gated allowance for classical (bare ed25519 / non-PQ
        // envelopes) is deleted, not gated — there is no mode in which a
        // classical transaction is admissible.
        {
            let Some(env) = tx.pq_envelope() else {
                return Err(MempoolError::Malformed(
                    "Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope".to_string(),
                ));
            };
            if !env.scheme.is_post_quantum() {
                return Err(MempoolError::Malformed(
                    "Pure PQ mode: scheme must be post-quantum (Falcon-512, ML-DSA-44, or Hybrid)"
                        .to_string(),
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
        // P2 shard gate: when the caller names the admitting shard, refuse
        // foreign-shard transactions at admission instead of letting them
        // occupy pool space the proposer must then skip over. Cheap (one
        // compare) and placed before crypto so junk is also cheap to refuse.
        // `None` keeps the legacy shard-blind behavior for callers that do not
        // know their shard (tests, restore, single-shard paths).
        if let Some(local) = ctx.shard {
            if tx.source_shard != local {
                return Err(MempoolError::Malformed(format!(
                    "transaction belongs to shard {} but this pool admits shard {local}",
                    tx.source_shard
                )));
            }
        }
        // Pool-level pin (same gate, every path): a pool pinned at startup
        // refuses foreign-shard transactions even when the CALLER passes no
        // shard in its context (RPC, explorer, gossip ingress, restore). The
        // per-call context above stays authoritative when present; the pin is
        // the backstop that makes an unpinned call site fail closed instead
        // of shard-blind on a sharded node.
        if let Some(pinned) = self.admission_shard {
            if tx.source_shard != pinned {
                return Err(MempoolError::Malformed(format!(
                    "transaction belongs to shard {} but this pool is pinned to shard {pinned}",
                    tx.source_shard
                )));
            }
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
        // legacy behavior (call-site pre-checks, where present, remain the
        // enforcement point). Cheap (one pool scan) and placed BEFORE the
        // signature verify so gapped junk is also cheap to refuse.
        if let Some(onchain) = ctx.onchain_nonce {
            if let Some(gap) = self.check_nonce_gap(&tx.from, tx.nonce, onchain) {
                return Err(gap);
            }
        }
        // PAYMASTER v1 (sponsored transactions): a well-formed envelope on a
        // third-party sponsor splits funding — the user covers `amount`, the
        // sponsor covers the fee — and BOTH signatures must verify. Refused
        // fail-closed with NAMED errors (never a generic `BadSignature` for
        // a sponsor-side problem), before any balance is touched:
        //
        // * malformed suffix or v1-unsupported composition (session / PQ /
        //   EVM / chain-bound inner: v1 sponsors a plain legacy 64-byte
        //   ed25519 inner only) -> `SponsorBadGrant`;
        // * sponsor signature over `sponsor_message` invalid ->
        //   `SponsorBadSignature`;
        // * expired grant / allowlist miss / fee above `max_fee_per_tx` ->
        //   `SponsorExpired` / `SponsorOutOfScope` / `SponsorCapExceeded`;
        // * sponsor cannot cover the fee (or the caller carried no sponsor
        //   balance at all) -> `SponsorInsufficientBalance` (below).
        //
        // The SELF-SPONSORED path (`sponsor == from`) fee-routes as PLAIN:
        // it skips this gate and falls through to the legacy checks (the
        // user pays their own fee). Both signatures are still verified by
        // `verify_signature_with_registry` below.
        //
        // ANTI-DOS (coverage): a sponsored transaction with no funded
        // sponsor behind it must never occupy pool space — the joint
        // reservation below (user leg + sponsor leg) makes one funding back
        // exactly the slots it can jointly pay for (F-03, both legs).
        //
        // CLOCK: the stateless policy runs against the admission clock
        // `ctx.now`. Propose and apply re-run it against the BLOCK
        // timestamp, so a grant that expires — or a sponsor that spends its
        // balance down — mid-mempool is re-refused there (proposer re-check
        // + apply refusal). Inclusion is therefore reproducible from block +
        // state alone; admission never decides it.
        if tx.sponsor_malformed() {
            return Err(MempoolError::SponsorBadGrant);
        }
        let sponsor_fee: Option<u64> = if let Some(auth) = tx.sponsored_grant() {
            if tx.sponsor_inner_sig().len() != 64 {
                return Err(MempoolError::SponsorBadGrant);
            }
            if !tx.verify_sponsor_sig(&auth) {
                return Err(MempoolError::SponsorBadSignature);
            }
            let fee = self.sponsor_fee_cost(&tx);
            if let Err(e) = tx.check_sponsor_policy(ctx.now, fee) {
                return Err(match e {
                    crate::sharding::SponsorPolicyError::Expired => MempoolError::SponsorExpired,
                    crate::sharding::SponsorPolicyError::OutOfScope => {
                        MempoolError::SponsorOutOfScope
                    }
                    crate::sharding::SponsorPolicyError::CapExceeded => {
                        MempoolError::SponsorCapExceeded
                    }
                    crate::sharding::SponsorPolicyError::BadGrant => MempoolError::SponsorBadGrant,
                });
            }
            Some(fee)
        } else {
            None
        };
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
            // The activation buffer is a GLOBAL, capped resource (2048 slots
            // shared by every unactivated account), so a buffered transaction
            // must be FUNDED: the sender's balance is reserved for it exactly
            // like a pooled transaction (audit: activation buffer exhaustion).
            // An unfunded sender therefore cannot park transactions in the
            // buffer, let alone fill it and lock legitimate unactivated
            // accounts out of the network.
            if !check_balance {
                // The unchecked path carries no balance to reserve against;
                // refuse rather than hand out free buffer slots.
                return Err(MempoolError::InsufficientBalance);
            }
            if sender_balance < cost
                || self.reserved_for(&tx.from).saturating_add(cost) > sender_balance
            {
                return Err(MempoolError::InsufficientBalance);
            }
            let floor = self.required_fee_for_tx(&tx);
            let (hash, old_tx) =
                self.activation_buffer
                    .buffer_tx_with_timestamp(tx.clone(), floor, ctx.now)?;
            if let Some(ref old) = old_tx {
                // The replaced transaction leaves the buffer: its claim ends here.
                self.release_reservation(old);
            }
            *self.reserved.entry(tx.from).or_insert(0) =
                self.reserved_for(&tx.from).saturating_add(cost);
            return Ok(hash);
        }

        // Fee floor on EVERY admission path (D2): includes failure-penalized floor
        // plus the State Rent Surcharge (~45k gas) if this is an activation tx.
        // Evaluated BEFORE `verify_signature_with_registry` so low-fee / zero-fee
        // transactions NEVER mutate the implicit key registry.
        //
        // The floor INCLUDES the sender's explicit priority bid
        // (`required_fee_for_tx`): the bid is a price, so it must be PAID FOR
        // out of the transaction's own fee. A bid nobody funds would be a free
        // lever that lets the cheapest spam claim the top of the pool.
        let floor = self.required_fee_for_tx(&tx);
        if tx.gas_limit < floor {
            return Err(MempoolError::FeeTooLow);
        }

        if !tx.verify_signature_with_registry(self.implicit_registry()) {
            return Err(MempoolError::BadSignature);
        }
        // Verify-once attestation (PERF_PROFILE §6.1): admission just
        // verified this exact signature, so attest it for block apply to
        // skip re-verifying when bytes AND chain context still match.
        // PQ-implicit transactions admitted under a CUSTOM (node-local test)
        // registry are NOT attested — apply verifies against the global
        // registry, so a custom-registry verdict must never be replayed there
        // (fail-closed).
        if !tx.is_pq_implicit() || self.implicit_registry.is_none() {
            crate::state_engine::record_verified_signature(
                &tx,
                crate::consensus::consensus_chain_id(),
            );
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
        //
        // PAYMASTER: the legs split — the user covers VALUE (`amount`), the
        // sponsor covers FEE (`sponsor_fee` above, which prices the live
        // floor). BOTH legs must fit their funder's balance minus that
        // funder's pooled claims, or the transaction is refused with a NAMED
        // error: `InsufficientBalance` for a short user,
        // `SponsorInsufficientBalance` for a short (or unknown — the caller
        // carried no `sponsor_balance` head) sponsor. Like the legacy leg,
        // the sponsor leg is a JOINT reservation: one sponsor funding backs
        // exactly the sponsored slots it can jointly pay for.
        if check_balance {
            if let Some(fee) = sponsor_fee {
                let sponsor = tx.fee_payer();
                let Some(sponsor_balance) = ctx.sponsor_balance else {
                    return Err(MempoolError::SponsorInsufficientBalance);
                };
                if sender_balance < tx.amount
                    || self.reserved_for(&tx.from).saturating_add(tx.amount) > sender_balance
                {
                    return Err(MempoolError::InsufficientBalance);
                }
                if sponsor_balance < fee
                    || self.reserved_for(&sponsor).saturating_add(fee) > sponsor_balance
                {
                    return Err(MempoolError::SponsorInsufficientBalance);
                }
            } else {
                let total = Self::tx_cost(&tx);
                if sender_balance < total {
                    return Err(MempoolError::InsufficientBalance);
                }
                if self.reserved_for(&tx.from).saturating_add(total) > sender_balance {
                    return Err(MempoolError::InsufficientBalance);
                }
            }
        }
        let hash = tx.compute_tx_hash();
        if self.txs.contains_key(&hash) || self.activation_buffer.contains_hash(&hash) {
            return Err(MempoolError::Duplicate);
        }
        // Ordering key: the EXPLICIT priority bid first, the fee paid second
        // (audit: priority inversion — `gas_limit` alone used to decide the
        // order, so a huge resource cap bought priority for free).
        let priority = tx.priority_fee_per_gas;
        let fee = Self::effective_fee(&tx);
        let sender = tx.from;

        // NOTE (V-P2): same-(sender, nonce) coexistence is DELIBERATE (audit
        // closure F10: "implicit-RBF pair both pooled; execution picks
        // first"). A replace-by-premium rule was trialed here and reverted:
        // the pool holds at most `per_sender_limit` txs per sender and EVERY
        // pooled transaction reserves its full cost up front, so same-nonce
        // stuffing is economically bounded (each duplicate must be fully
        // funded), while replacement would silently drop a sender's own
        // in-flight variant. Duplicate *hashes* are still refused below.

        let sender_count = self.per_sender.get(&sender).copied().unwrap_or(0);
        if sender_count >= self.per_sender_limit {
            return Err(MempoolError::TooManyFromSender);
        }

        if self.txs.len() >= self.max_size {
            // Evict the lowest-priced tx only when the newcomer outbids it by
            // the gentle premium (F-04; the premium is 5% + 1 instead of the
            // old 2x doubling, see `eviction_bid_beats`).
            // `check_balance` is false for the unchecked `add` path, so an
            // unverifiable sender can never displace honest transactions.
            let lowest = self.order.keys().next().copied();
            match lowest {
                Some((low_priority, low_fee, low_hash))
                    if check_balance
                        && Self::eviction_bid_beats(priority, fee, low_priority, low_fee) =>
                {
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
        self.order.insert((priority, fee, hash), hash);
        *self.per_sender.entry(sender).or_insert(0) += 1;
        // F-03: this tx's full execution cost is now claimed against its
        // funder's balance until it leaves the pool (via `evict` below, which
        // is the single removal path for `remove`/`prune_confirmed`/
        // `evict_unexecutable`/`sweep_expired`/fee-eviction).
        //
        // PAYMASTER: the claim splits into the pure legs — the user's
        // `amount` under the user, `gas_limit + surcharge` under the sponsor
        // (see `sponsored_pure_legs`: pure so claim and release agree even if
        // the penalty map moves between them).
        if let Some((user_cost, sponsor_cost)) = Self::sponsored_pure_legs(&tx) {
            let sponsor = tx.fee_payer();
            *self.reserved.entry(sender).or_insert(0) =
                self.reserved_for(&sender).saturating_add(user_cost);
            *self.reserved.entry(sponsor).or_insert(0) =
                self.reserved_for(&sponsor).saturating_add(sponsor_cost);
        } else {
            *self.reserved.entry(sender).or_insert(0) = self
                .reserved_for(&sender)
                .saturating_add(Self::tx_cost(&tx));
        }
        self.inserted_at.insert(hash, ctx.now);
        self.txs.insert(hash, tx);

        // If this transaction activated the sender, drain any out-of-order nonces
        // that were waiting in the PendingActivationBuffer.
        if self.activation_buffer.has_account(&sender) {
            let pending = self.activation_buffer.drain_account(&sender);
            // The drained transactions leave the BUFFER, so the claims the
            // buffer held for them end here; the re-admission below takes them
            // afresh (in the pool, or back in the buffer when the account is
            // still unactivated). This release is UNCONDITIONAL: gating it on
            // `check_balance` left the claim in place on the unchecked path,
            // where the re-admission then took it a SECOND time - the sender's
            // pooled claim grew by the cost of every drained transaction and
            // never came back down (audit W6.6: activation-buffer reservation
            // leak / double count).
            for p_tx in &pending {
                self.release_reservation(p_tx);
            }
            let mut dropped = 0usize;
            for p_tx in pending {
                // The re-admission runs the CHECKED path: the transaction is
                // already funded (its claim was taken when it was buffered) and
                // the unchecked path would refuse to re-buffer it (the buffer
                // needs a balance to reserve against) and silently DROP it.
                let pass_balance = if check_balance {
                    sender_balance
                } else {
                    u64::MAX
                };
                if self.insert(p_tx, pass_balance, true, ctx).is_err() {
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
            Some(MempoolError::NonceGap {
                expected: want,
                got: nonce,
            })
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
                let age = now_secs.saturating_sub(
                    *self
                        .inserted_at
                        .get(&tx.compute_tx_hash())
                        .unwrap_or(&now_secs),
                );
                if age < Self::STUCK_TX_TTL_SECS {
                    return None;
                }
                let (nonce, balance) = account(&tx.from)?;
                let stale_nonce = tx.nonce < nonce;
                // PAYMASTER: split legs, like the eviction pass above — a
                // sponsor that spent down mid-mempool makes the transaction
                // unexecutable and the sweep reclaims the slot.
                let unaffordable = match Self::sponsored_pure_legs(tx) {
                    Some((user_cost, sponsor_cost)) => {
                        let sponsor = tx.fee_payer();
                        let user_short = user_cost > balance;
                        let sponsor_short = account(&sponsor)
                            .map(|(_, sponsor_balance)| sponsor_cost > sponsor_balance)
                            .unwrap_or(false);
                        user_short || sponsor_short
                    }
                    None => tx.amount.saturating_add(tx.gas_limit) > balance,
                };
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
        let expired_activation = self
            .activation_buffer
            .drain_stale(now_secs, Self::STUCK_TX_TTL_SECS);
        for tx in &expired_activation {
            // A swept buffered transaction leaves the buffer: its claim ends
            // with it (audit W6.6: the sweep must release the reservation).
            self.release_reservation(tx);
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
            self.order
                .remove(&(tx.priority_fee_per_gas, Self::effective_fee(&tx), *hash));
            if let Some(c) = self.per_sender.get_mut(&tx.from) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    self.per_sender.remove(&tx.from);
                }
            }
            // F-03: release this tx's claim (saturating: a directly-decoded
            // pool — never the live path, which rebuilds via `load_into` —
            // starts with an empty table and must not underflow).
            self.release_reservation(&tx);
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
                // A removed buffered transaction leaves the buffer: its claim
                // ends with it.
                self.release_reservation(t);
            }
            act_tx
        }
    }

    /// Remove a batch of confirmed transactions.
    ///
    /// Hashes that name ACTIVATION-BUFFERED transactions are removed from the
    /// buffer too (releasing their reservation): `evict` alone is a no-op for
    /// them, so a confirmed buffered hash passed here would otherwise leak
    /// its balance claim forever.
    pub fn remove_many(&mut self, hashes: &[TxHash]) {
        for h in hashes {
            if self.txs.contains_key(h) {
                self.evict(h);
            } else if let Some(tx) = self.activation_buffer.remove_by_hash(h) {
                self.release_reservation(&tx);
            }
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
    pub fn select_filtered<F: Fn(&Transaction) -> bool>(
        &self,
        max_txs: usize,
        accept: F,
    ) -> Vec<Transaction> {
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
        order: &std::collections::BTreeMap<(u64, u64, TxHash), TxHash>,
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
        // the same descending `(priority, fee, hash)` sequence the map walk
        // would yield, but without re-descending tree nodes or re-probing the
        // transaction map per element per pass. The visit order — and therefore
        // the selected set — is unchanged (`&self` borrows both maps
        // immutably, so the precomputed alignment cannot drift mid-selection).
        let fee_order: Vec<(u64, u64, TxHash)> = order.keys().copied().collect();
        let aligned: Vec<Option<&Transaction>> =
            fee_order.iter().map(|(_, _, h)| txs.get(h)).collect();
        // Hoisted per-tx packing costs (pure functions of the transaction, so
        // the values are identical to recomputing them inline): `gas_limit`
        // is a field copy, the wire estimate walks the payload op shapes and
        // the proof-unit count walks the same payload. The hot loop below
        // re-walks every untaken element on EVERY pass (up to 64 passes x
        // 10k elements with scattered fees/deep nonce chains), so recomputing
        // these per element per pass is pure waste — one batch pass here
        // replaces up to `passes` recomputations per element. The accept
        // predicate still runs inline in the original order (it is stateful:
        // nonce advance, budget debit, census), and the cap checks below read
        // the same values in the same order, so the selected set and order
        // are unchanged. `None` slots are never selected (the loop skips them
        // before reading the costs), so their filler values are irrelevant.
        let gas_of: Vec<u64> = aligned
            .iter()
            .map(|t| t.map(|t| t.gas_limit).unwrap_or(0))
            .collect();
        let wire_of: Vec<usize> = aligned
            .iter()
            .map(|t| t.map(Self::estimate_tx_wire_bytes).unwrap_or(0))
            .collect();
        let proof_of: Vec<usize> = aligned
            .iter()
            .map(|t| t.map(Self::count_tx_proof_units).unwrap_or(0))
            .collect();
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
                let g = gas_of[i];
                if gas.saturating_add(g) > max_gas {
                    // This one does not fit. A cheaper one behind it might, so keep
                    // walking rather than truncating the block here.
                    continue;
                }
                // Wire + proof-unit caps (audit: blocks troubles): gas-valid
                // does not mean gossipable or verifiable-in-time. Skip (do
                // not truncate: a smaller tx behind may still fit).
                let w = wire_of[i];
                if wire.saturating_add(w) > Self::MAX_BLOCK_WIRE_BYTES {
                    continue;
                }
                let p = proof_of[i];
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
                OpCode::SysCallVerifyZkMlReexec { proof, .. } => 500 + proof.wire_len(),
                OpCode::SysCallVerifyZkMlAttestation { proof, .. } => {
                    500 + proof.public_inputs.len() * 2 + proof.wire_len()
                }
                // A PQ equivocation report carries TWO post-quantum signatures
                // (up to ~2.4 KB each for ML-DSA-44), so the flat 200-byte
                // default would under-count it by more than an order of
                // magnitude and let a producer pack a block past the gossip
                // cap.
                OpCode::SysCallReportPqEquivocation { evidence } => 200 + evidence.wire_len(),
                // A proposal equivocation report carries TWO FULL BLOCKS, so
                // the flat default would under-count it by up to four orders
                // of magnitude. Count it honestly for the same reason: the
                // estimator is what keeps packing under the gossip cap.
                OpCode::SysCallReportProposalEquivocation { evidence } => 200 + evidence.wire_len(),
                _ => 200,
            };
        }
        n
    }

    /// Verified-proof units in a transaction for packing (audit: blocks
    /// troubles): counts attestation verifies + zkML re-executions, the work
    /// that serializes on the single apply worker.
    pub fn count_tx_proof_units(tx: &Transaction) -> usize {
        use crate::svm::OpCode;
        tx.payload
            .iter()
            .map(|op| match op {
                OpCode::SysCallVerifyZkMlAttestation { .. } => 64, // ~one 64-bit proof of work
                OpCode::SysCallVerifyZkMlReexec { .. } => 16,      // re-execution, model-bounded
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

    /// PAYMASTER: every account whose balance the proposer filter must
    /// snapshot — each sender PLUS each third-party sponsor backing a
    /// sponsored transaction. The filter debits the fee leg from the sponsor
    /// and advances only the user's nonce, so it needs both balances up
    /// front (a sponsor missing from the snapshot would read as unfunded).
    pub fn fee_payers(&self) -> std::collections::BTreeSet<[u8; 32]> {
        let mut set = self.senders();
        set.extend(self.txs.values().filter_map(|t| t.effective_sponsor()));
        set
    }

    /// Pending transaction hashes.
    pub fn hashes(&self) -> Vec<TxHash> {
        self.txs.keys().copied().collect()
    }

    /// Drop txs already present in a finalized block (by hash).
    pub fn prune_confirmed(&mut self, confirmed: &[TxHash]) {
        let set: HashSet<TxHash> = confirmed.iter().copied().collect();
        let to_remove: Vec<TxHash> = self
            .txs
            .keys()
            .filter(|h| set.contains(*h))
            .copied()
            .collect();
        for h in to_remove {
            self.evict(&h);
        }
        // A confirmed hash that names an activation-buffered transaction
        // leaves the buffer with it (releasing its reservation): buffered
        // transactions are never `txs`, so the loop above cannot see them,
        // and an unreleased claim would price the sender out of the pool
        // forever.
        for h in confirmed {
            if let Some(tx) = self.activation_buffer.remove_by_hash(h) {
                self.release_reservation(&tx);
            }
        }
        // The SEALED envelopes of the included transactions leave the pool
        // with them: a sealed transaction that was unsealed and included
        // must not be proposed AGAIN (it would be a duplicate), and it must
        // not hold pool space either. The removal happens at APPLY time
        // (like the plain path), not at build time: a block that is built
        // but never finalized must not lose its transactions.
        let sealed_gone: Vec<[u8; 32]> = self
            .sealed
            .iter()
            .filter(|(h, _)| set.contains(*h))
            .map(|(_, e)| e.meta.from)
            .collect();
        self.sealed.retain(|h, _| !set.contains(h));
        for sender in sealed_gone {
            self.release_sender_slot(&sender);
        }
    }

    /// Re-validate every queued transaction against POST-COMMIT state
    /// (CometBFT-style mempool recheck). Call after each commit, AFTER
    /// [`Mempool::prune_confirmed`]: the commit advanced on-chain nonces,
    /// drained balances and may have moved the fee floor, so queued txs that
    /// were valid at admission can now be permanently unexecutable (spent
    /// nonce, drained balance, fee below the new floor). Without this they
    /// accumulate: never included (execution refuses them) yet never pruned,
    /// permanently occupying pool slots and the sender's nonce head.
    ///
    /// `account` yields the post-commit `(nonce, balance)` per sender. A
    /// sender the view does not know (`None`) is SKIPPED, never treated as
    /// broke (same fail-open as [`Mempool::evict_unexecutable`]). Returns how
    /// many were dropped. No-attack behavior: every still-valid tx is kept,
    /// so honest pools come back with 0.
    pub fn recheck<F>(&mut self, now_secs: u64, mut account: F) -> usize
    where
        F: FnMut(&[u8; 32]) -> Option<(u64, u64)>,
    {
        // Pass 1: spent nonce / drained balance / aged future-nonce (same
        // predicate the proposer sweep uses, now against post-commit state).
        let mut dropped = self.evict_unexecutable_at(now_secs, &mut account);
        // Pass 2: the fee floor moved under the tx (base fee rose or a D2
        // failure penalty accrued at/after commit): `gas_limit` no longer
        // covers `required_fee_for_tx`, so admission would refuse it today.
        // `evict` keeps the fee index, per-sender quota and F-03 reservations
        // in step (never remove straight from `txs`).
        let stale_floor: Vec<TxHash> = self
            .txs
            .values()
            .filter(|tx| tx.gas_limit < self.required_fee_for_tx(tx))
            .map(|tx| tx.compute_tx_hash())
            .collect();
        for h in &stale_floor {
            self.evict(h);
        }
        dropped += stale_floor.len();
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding::Transaction;
    use std::sync::atomic::{AtomicU8, Ordering};

    /// FULL-PQ test keys: each call mints a fresh Falcon-512 seed, so every
    /// test sender is distinct (mirrors the old fresh-`SigningKey` helper).
    /// Signatures are real FIPS-206 via `create_falcon512_test_signature`.
    static NEXT_PQ_SEED: AtomicU8 = AtomicU8::new(0x10);

    fn key() -> u8 {
        NEXT_PQ_SEED.fetch_add(1, Ordering::Relaxed)
    }

    /// PQ sender address for a seed (explicit-envelope derivation).
    fn addr(seed: &u8) -> [u8; 32] {
        crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &Transaction::sample_falcon512_pubkey(*seed),
            &crate::post_quantum::DEFAULT_SALT,
        )
    }

    /// Explicit Falcon-512 replacement for the old `Transaction::sign` test
    /// helper: same `(to, amount 10, fee, nonce, shard 1)` shape, PQ envelope.
    ///
    /// IMPLICIT envelope with the key pre-registered globally: no activation
    /// surcharge, so fee floors, costs and balances behave EXACTLY like the
    /// old classical fixtures (the surcharge is covered by the dedicated
    /// activation tests below, not by every fee test).
    fn tx(seed: &u8, to: [u8; 32], fee: u64, nonce: u64) -> Transaction {
        txa(seed, to, 10, fee, nonce)
    }

    /// Same as [`tx`] with an explicit amount (for the unaffordable-balance
    /// fixtures, where the amount itself is the point).
    fn txa(seed: &u8, to: [u8; 32], amount: u64, fee: u64, nonce: u64) -> Transaction {
        txpa(seed, to, amount, fee, nonce, 0)
    }

    /// Implicit Falcon-512 replacement for `Transaction::sign_with_priority`
    /// (same no-surcharge rule as [`tx`]).
    fn txp(seed: &u8, to: [u8; 32], fee: u64, nonce: u64, bid: u64) -> Transaction {
        txpa(seed, to, 10, fee, nonce, bid)
    }

    fn txpa(seed: &u8, to: [u8; 32], amount: u64, fee: u64, nonce: u64, bid: u64) -> Transaction {
        use crate::post_quantum::{PqScheme, PqSignatureEnvelope, DEFAULT_SALT};
        let pk = Transaction::sample_falcon512_pubkey(*seed);
        let from = addr(seed);
        // Pre-register globally (idempotent): admission verifies implicit
        // envelopes against this registry, routes around the activation
        // buffer, and charges no activation surcharge.
        Transaction::global_implicit_registry()
            .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
            .expect("PQ test key must register");
        let mut t = Transaction {
            from,
            to,
            amount,
            gas_limit: fee,
            nonce,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: bid,
        };
        let msg = t.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, *seed);
        t.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
        t
    }

    #[test]
    fn multi_pass_select_completes_contiguous_sequences() {
        // Regression: single-pass fee-order selection with a stateful
        // nonce filter starves out-of-hash-order followers (observed: 10
        // contiguous txs draining 1,3,1,2 per height). Multi-pass must take
        // all executable ones regardless of hash order.
        let sk = key();
        let me = addr(&sk);
        let mut mp = Mempool::new(100, 100);
        for i in 0..10u64 {
            mp.add_checked(tx(&sk, [1u8; 32], 1_000, i), 1_000_000)
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
        let sk = key();
        let me = addr(&sk);
        let mut mp = Mempool::new(300, 300);
        for i in 0..50u64 {
            mp.add_checked(tx(&sk, [1u8; 32], 1_000, i), 1_000_000)
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
        let sk = key();
        let me = addr(&sk);
        let mut mp = Mempool::new(100, 10);

        // All three are admitted while the account is still solvent — that is
        // the real situation: a transaction becomes unexecutable AFTER it is
        // accepted (the nonce gets consumed, or the balance drops elsewhere).
        let stale = tx(&sk, [1u8; 32], 1_000, 0);
        let broke = txa(&sk, [1u8; 32], 9_000, 1_000, 1);
        let queued = txa(&sk, [1u8; 32], 100, 1_000, 3);
        let queued_hash = queued.compute_tx_hash();
        for tx in [stale, broke, queued] {
            mp.add_checked(tx, 20_000).unwrap();
        }
        assert_eq!(mp.len(), 3);

        // Now the account is at nonce 1 (so nonce 0 is consumed) and can only
        // afford 5_000 (so the 9_000 one is dead); the nonce-3 one must survive.
        let dropped = mp.evict_unexecutable(|s| if *s == me { Some((1, 5_000)) } else { None });
        assert_eq!(dropped, 2, "stale nonce and unaffordable tx must go");
        assert_eq!(mp.len(), 1);
        assert!(
            mp.contains(&queued_hash),
            "a future, affordable tx must survive"
        );
        // Evicting must not leak the per-sender quota.
        assert_eq!(mp.per_sender.get(&me).copied().unwrap_or(0), 1);
    }

    #[test]
    fn eviction_skips_unknown_senders_instead_of_killing_them() {
        // Regression (audit 2026-10-06): the old `(0, 0)` default treated a
        // sender missing from the snapshot as broke and irreversibly deleted
        // its funded transactions, while the proposer filter only skips them.
        let sk = key();
        let mut mp = Mempool::new(100, 10);
        let mine = txa(&sk, [2u8; 32], 100, 1_000, 0);
        let mine_hash = mine.compute_tx_hash();
        mp.add_checked(mine, 10_000).unwrap();
        // Snapshot knows NOBODY (partial/pre-height view): nothing may die.
        let dropped = mp.evict_unexecutable(|_| None);
        assert_eq!(dropped, 0, "unknown senders are skipped, never evicted");
        assert!(mp.contains(&mine_hash));
    }

    #[test]
    fn eviction_keeps_healthy_mempool_intact() {
        let sk = key();
        let me = addr(&sk);
        let mut mp = Mempool::new(100, 10);
        for n in 0..3u64 {
            mp.add_checked(txa(&sk, [2u8; 32], 100, 1_000, n), 10_000)
                .unwrap();
        }
        assert_eq!(
            mp.evict_unexecutable(|s| if *s == me { Some((0, 10_000)) } else { None }),
            0
        );
        assert_eq!(mp.len(), 3, "nothing valid may be dropped");
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
    fn explicit_priority_beats_a_huge_gas_limit() {
        // Audit (priority inversion): `gas_limit` is a RESOURCE CAP, not a
        // price. The pool used to be ordered by `gas_limit` alone, so a
        // transaction that merely declared a HUGE cap took the top of the
        // mempool and preempted genuinely urgent traffic. The explicit
        // priority bid is now the primary key, so the urgent transaction
        // wins even though the spammer declares a 10_000x larger cap.
        let sk = key();
        let mut mp = Mempool::new(100, 100);
        let bal = 10_000_000;

        // The spammer: a massive resource cap, no priority bid.
        let huge_cap = tx(&sk, [1; 32], 1_000_000, 0);
        // The urgent one: a NORMAL gas limit, but an explicit priority bid.
        let urgent = txp(&sk, [1; 32], 100, 1, 100);

        mp.add_checked(huge_cap.clone(), bal).unwrap();
        mp.add_checked(urgent.clone(), bal).unwrap();

        let picked = mp.select(2);
        assert_eq!(picked.len(), 2);
        assert_eq!(
            picked[0].compute_tx_hash(),
            urgent.compute_tx_hash(),
            "an explicit priority bid must outrank a huge resource cap"
        );
        assert_eq!(picked[1].compute_tx_hash(), huge_cap.compute_tx_hash());
    }

    #[test]
    fn priority_bid_must_be_funded() {
        // The bid is a PRICE, so it must be paid for: an unfunded bid would
        // be a free lever that lets the cheapest spam own the top of the
        // pool forever.
        let sk = key();
        let mut mp = Mempool::new(100, 100).with_base_fee(100);
        let unfunded = txp(&sk, [1; 32], 100, 0, 1_000);
        assert_eq!(
            mp.add_checked(unfunded, 100_000),
            Err(MempoolError::FeeTooLow),
            "a bid the fee does not cover must be refused"
        );
        // Funding it (gas_limit covers floor + bid) works.
        let funded = txp(&sk, [1; 32], 100 + 1_000, 1, 1_000);
        assert!(
            mp.add_checked(funded, 100_000).is_ok(),
            "a funded bid must be admitted"
        );
    }

    #[test]
    fn priority_bid_survives_the_wire_and_is_committed_in_the_hash() {
        // The bid travels inside the signature envelope (the wire form is
        // byte-compatible with the legacy layout) and it is COMMITTED in the
        // transaction hash: two transactions that differ only in their bid are
        // two DIFFERENT transactions, so two nodes can never disagree about
        // what a transaction's priority is (a bid that was not hashed would be
        // a consensus split waiting to happen).
        //
        // WIRE-ONLY (no admission): FULL-PQ implicit envelopes exercise the
        // same envelope/tag math; admission PQ-ness is covered elsewhere.
        let sk = key();
        let bid_tx = txp(&sk, [1; 32], 100, 0, 777);
        let bytes = bincode::serialize(&bid_tx).expect("serialize");
        let back: Transaction = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(
            back.priority_fee_per_gas, 777,
            "the bid must survive the wire"
        );
        assert_eq!(
            back.compute_tx_hash(),
            bid_tx.compute_tx_hash(),
            "the decoded transaction must keep its identity"
        );
        assert!(
            back.verify_signature(),
            "the decoded transaction must verify"
        );

        // Only the bid differs -> a different hash.
        let other = txp(&sk, [1; 32], 100, 0, 778);
        assert_ne!(
            bid_tx.compute_tx_hash(),
            other.compute_tx_hash(),
            "two bids are two different transactions"
        );
        // The no-bid transaction keeps its identity and is a
        // different transaction from the bid-carrying one.
        let legacy = tx(&sk, [1; 32], 100, 0);
        assert_ne!(legacy.compute_tx_hash(), bid_tx.compute_tx_hash());
        let legacy_bytes = bincode::serialize(&legacy).expect("serialize");
        let legacy_back: Transaction = bincode::deserialize(&legacy_bytes).expect("deserialize");
        assert_eq!(legacy_back.priority_fee_per_gas, 0);
        assert_eq!(legacy_back.compute_tx_hash(), legacy.compute_tx_hash());
    }

    #[test]
    fn priority_bid_is_bound_to_the_sender_signature() {
        // The bid is signed with the rest of the transaction, so a third
        // party cannot inflate someone else's priority (and two bids are two
        // different transactions, with different hashes).
        //
        // WIRE-ONLY (no admission): see above.
        let sk = key();
        let bid_tx = txp(&sk, [1; 32], 100, 0, 500);
        assert!(bid_tx.verify_signature(), "a priority tx must verify");
        let mut tampered = bid_tx.clone();
        tampered.priority_fee_per_gas = 5_000;
        assert!(
            !tampered.verify_signature(),
            "inflating the bid must invalidate the signature"
        );
        assert_ne!(
            bid_tx.compute_tx_hash(),
            tampered.compute_tx_hash(),
            "the bid is part of the transaction identity"
        );
        // The no-bid signing message carries NO priority commitment,
        // so no-bid signatures/hashes stay byte-identical.
        let legacy = tx(&sk, [1; 32], 100, 0);
        assert!(
            !legacy
                .signing_message()
                .windows(8)
                .any(|w| w == crate::sharding::PRIORITY_FEE_COMMITMENT_TAG),
            "a legacy transaction must not commit to a priority"
        );
        assert!(
            bid_tx.signing_message()
                .windows(8)
                .any(|w| w == crate::sharding::PRIORITY_FEE_COMMITMENT_TAG),
            "a priority transaction must commit to its bid"
        );
    }

    #[test]
    fn legacy_transaction_bytes_decode_without_a_priority_field() {
        // Bincode backward compatibility: a transaction encoded BEFORE the
        // priority bid existed ends its byte stream right after `payload`.
        // It must still decode (with the bid defaulting to 0) and keep its
        // hash, or every historical transaction would become unreadable.
        //
        // WIRE-ONLY (no admission): no-bid layout decode path, unchanged.
        // FULL-PQ: the fixture is an implicit Falcon-512 envelope (the old
        // classical constructor no longer verifies anywhere).
        let sk = key();
        let tx = tx(&sk, [1; 32], 100, 0);
        #[derive(serde::Serialize, serde::Deserialize)]
        struct LegacyTx {
            from: [u8; 32],
            to: [u8; 32],
            amount: u64,
            gas_limit: u64,
            nonce: u64,
            source_shard: u32,
            target_shard: u32,
            signature: Vec<u8>,
            payload: Vec<crate::svm::OpCode>,
        }
        let legacy = LegacyTx {
            from: tx.from,
            to: tx.to,
            amount: tx.amount,
            gas_limit: tx.gas_limit,
            nonce: tx.nonce,
            source_shard: tx.source_shard,
            target_shard: tx.target_shard,
            signature: tx.signature.clone(),
            payload: tx.payload.clone(),
        };
        let bytes = bincode::serialize(&legacy).unwrap();
        let back: Transaction =
            bincode::deserialize(&bytes).expect("a legacy transaction must still decode");
        assert_eq!(back.priority_fee_per_gas, 0);
        assert_eq!(back.compute_tx_hash(), tx.compute_tx_hash());
        assert!(back.verify_signature());
    }

    #[test]
    fn duplicate_rejected() {
        let sk = key();
        let mut mp = Mempool::new(100, 100);
        let t = tx(&sk, [1; 32], 10, 0);
        mp.add(t.clone()).unwrap();
        assert_eq!(mp.add(t), Err(MempoolError::Duplicate));
    }

    /// Build an IMPLICIT post-quantum transaction for an account that is not
    /// activated yet (so admission routes it into the activation buffer).
    fn implicit_pq_tx(
        pk: &[u8],
        seed: u8,
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
    ) -> Transaction {
        let mut tx = Transaction {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg = tx.signing_message();
        let sig = Transaction::create_falcon512_test_signature(pk, &msg, seed);
        tx.signature = crate::post_quantum::PqSignatureEnvelope::new_implicit(
            crate::post_quantum::PqScheme::Falcon512,
            sig,
        )
        .encode();
        tx
    }

    /// The activation buffer's reservation must be released EXACTLY once
    /// (audit W6.6, item 3): the buffered transaction's cost is claimed when it
    /// enters the buffer and must be released when it LEAVES the buffer
    /// (drain, remove or sweep) - never twice, never never.
    ///
    /// A double count inflates the sender's pooled claim and a missing release
    /// LEAKS it: the sender's balance stays reserved forever and every later
    /// transaction is refused with `InsufficientBalance` although the money is
    /// free.
    #[test]
    fn activation_buffer_reservation_is_released_exactly_once() {
        use crate::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};

        let registry = crate::post_quantum::StatefulImplicitKeyRegistry::new();
        let mut mp = Mempool::new(100, 50)
            .with_base_fee(100)
            .with_implicit_registry(registry.clone());

        let seed = 0x77u8;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);

        const BALANCE: u64 = 10_000_000;
        let tx = implicit_pq_tx(&pk, seed, from, [7u8; 32], 50, 1_000, 0);
        let cost = Mempool::tx_cost(&tx);

        // The account is NOT activated: the transaction is buffered, and its
        // cost is reserved against the sender's balance.
        mp.add_checked(tx.clone(), BALANCE).expect("buffered");
        assert!(mp.is_buffered(&tx.compute_tx_hash()));
        assert_eq!(
            mp.reserved_for(&from),
            cost,
            "a buffered transaction must reserve its full cost"
        );

        // The account is activated: the buffer is drained into the pool.
        let _ = registry.register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT); // GATE: intentional ignore
        let admitted = mp.process_activation_buffer(&from);
        assert_eq!(admitted.len(), 1, "the buffered tx must re-enter the pool");
        assert!(!mp.is_buffered(&tx.compute_tx_hash()));
        assert_eq!(
            mp.reserved_for(&from),
            cost,
            "the buffer's reservation must be carried over, not doubled"
        );

        // The transaction leaves the pool: the reservation must be gone.
        mp.remove(&tx.compute_tx_hash());
        assert_eq!(
            mp.reserved_for(&from),
            0,
            "a leaving transaction must release its reservation exactly once"
        );
    }

    /// The same invariant on the SWEEP path (audit W6.6, item 3): an expired
    /// buffered transaction must give its reservation back.
    #[test]
    fn activation_buffer_sweep_releases_the_reservation() {
        use crate::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};

        let registry = crate::post_quantum::StatefulImplicitKeyRegistry::new();
        let mut mp = Mempool::new(100, 50)
            .with_base_fee(100)
            .with_implicit_registry(registry.clone());

        let seed = 0x78u8;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);

        const BALANCE: u64 = 10_000_000;
        let tx = implicit_pq_tx(&pk, seed, from, [8u8; 32], 50, 1_000, 0);
        let cost = Mempool::tx_cost(&tx);
        mp.add_checked(tx.clone(), BALANCE).expect("buffered");
        assert_eq!(mp.reserved_for(&from), cost);

        let swept = mp.sweep_expired(
            crate::zkml::now_secs() + Mempool::STUCK_TX_TTL_SECS + 1,
            |_| Some((0, BALANCE)),
        );
        assert_eq!(swept, 1, "the stale buffered tx must be swept");
        assert_eq!(
            mp.reserved_for(&from),
            0,
            "a swept buffered transaction must release its reservation"
        );
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
        assert_eq!(
            mp.add(tx(&sk, [1; 32], 10, 3)),
            Err(MempoolError::TooManyFromSender)
        );
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
        assert_eq!(
            mp.add_checked(tx(&sk, [1; 32], 1, 3), bal),
            Err(MempoolError::Full)
        );
    }

    #[test]
    fn full_pool_eviction_uses_a_gentle_premium() {
        // Audit (exponential eviction lockout): the old rule demanded
        // `fee >= 2 * low_fee`, so EVERY full-pool sweep doubled the
        // admission threshold. Under sustained load the threshold walked
        // into the millions within a few sweeps and no honest transaction
        // could re-enter the pool again — a self-inflicted permanent
        // lockout. The premium is now 5% (+1): linear, not exponential.
        assert_eq!(Mempool::eviction_premium(1), 1);
        assert_eq!(Mempool::eviction_premium(100), 5);
        assert_eq!(Mempool::eviction_premium(1_000), 50);
        assert_eq!(Mempool::eviction_premium(1_000_000), 50_000);

        let sk = key();
        let mut mp = Mempool::new(2, 100);
        let bal = 10_000_000;
        let low = tx(&sk, [1; 32], 1_000, 0);
        let low_hash = low.compute_tx_hash();
        mp.add_checked(low, bal).unwrap();
        mp.add_checked(tx(&sk, [1; 32], 2_000, 1), bal).unwrap();

        // 1_050 = 1_000 + 5% premium: enough under the gentle rule (the old
        // 2x rule would have demanded 2_000).
        mp.add_checked(tx(&sk, [1; 32], 1_050, 2), bal)
            .expect("a 5% premium must displace the cheapest pooled tx");
        assert!(!mp.contains(&low_hash), "the cheapest tx must be evicted");
        assert_eq!(mp.len(), 2);

        // Just below the premium is refused.
        let mut mp2 = Mempool::new(2, 100);
        mp2.add_checked(tx(&sk, [1; 32], 1_000, 0), bal).unwrap();
        mp2.add_checked(tx(&sk, [1; 32], 2_000, 1), bal).unwrap();
        assert_eq!(
            mp2.add_checked(tx(&sk, [1; 32], 1_049, 2), bal),
            Err(MempoolError::Full),
            "a bid under the premium must not displace anything"
        );
    }

    #[test]
    fn unfunded_add_never_evicts_and_checked_rejects_unfunded() {
        let sk = key();
        let mut mp = Mempool::new(2, 100);
        mp.add(tx(&sk, [1; 32], 5, 0)).unwrap();
        mp.add(tx(&sk, [1; 32], 10, 1)).unwrap();
        // unchecked `add` cannot evict even with a huge declared fee
        assert_eq!(
            mp.add(tx(&sk, [1; 32], u64::MAX, 2)),
            Err(MempoolError::Full)
        );
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
        assert_eq!(
            mp.add_checked(tx(&sk, [1; 32], 5, 1), 1_000),
            Err(MempoolError::FeeTooLow)
        );
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
        assert_eq!(
            mp.add(tx(&sk, [1; 32], 10, 2)),
            Err(MempoolError::TooManyFromSender)
        );
        mp.remove(&h);
        // after freeing a slot the sender can add again
        assert!(mp.add(tx(&sk, [1; 32], 10, 2)).is_ok());
    }

    #[test]
    fn mempool_file_format_is_versioned_with_legacy_fallback() {
        // `mev` (and the registry handle) are `#[serde(skip)]`, so the engine
        // fields never enter the encoding. `inserted_at` DOES (audit: blocks
        // troubles — TTL needs it), so files are versioned with a magic
        // prefix instead: new files start with MP03, older files (MP02, and
        // the bare pre-TTL layout) still decode via the mirrors below.
        //
        // The mirrors carry the PRE-PRIORITY shapes: the order index was keyed
        // by `(gas_limit, hash)` and the transaction had no priority field.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct LegacyTransaction {
            from: [u8; 32],
            to: [u8; 32],
            amount: u64,
            gas_limit: u64,
            nonce: u64,
            source_shard: crate::sharding::ShardId,
            target_shard: crate::sharding::ShardId,
            signature: Vec<u8>,
            #[serde(default)]
            payload: Vec<crate::svm::OpCode>,
        }

        #[derive(serde::Serialize, serde::Deserialize)]
        struct LegacyMempool {
            txs: HashMap<TxHash, LegacyTransaction>,
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

        // The legacy order map is keyed by `(fee, tx_hash)`; the current one
        // is keyed by `(priority, fee, hash)`, so the mirror drops the
        // priority (a legacy transaction bids no priority).
        let legacy_order: BTreeMap<(u64, TxHash), TxHash> = mp
            .order
            .iter()
            .map(|((_priority, fee, hash), value)| ((*fee, *hash), *value))
            .collect();
        let legacy_txs: HashMap<TxHash, LegacyTransaction> = mp
            .txs
            .iter()
            .map(|(h, t)| {
                (
                    *h,
                    LegacyTransaction {
                        from: t.from,
                        to: t.to,
                        amount: t.amount,
                        gas_limit: t.gas_limit,
                        nonce: t.nonce,
                        source_shard: t.source_shard,
                        target_shard: t.target_shard,
                        signature: t.signature.clone(),
                        payload: t.payload.clone(),
                    },
                )
            })
            .collect();
        let legacy = LegacyMempool {
            txs: legacy_txs,
            order: legacy_order,
            per_sender: mp.per_sender.clone(),
            max_size: mp.max_size,
            per_sender_limit: mp.per_sender_limit,
            base_fee: mp.base_fee,
        };
        let new_bytes = bincode::serialize(&mp).unwrap();
        let legacy_bytes = bincode::serialize(&legacy).unwrap();
        assert_ne!(
            new_bytes, legacy_bytes,
            "inserted_at must change the encoding"
        );

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
        assert!(
            back.mev.pool_envelopes.is_empty(),
            "skipped field decodes as default"
        );
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
        assert!(
            !mp.mev.pool_envelopes.contains_key(&h),
            "removal drops the envelope"
        );

        let h2 = mp.add(tx(&sk, [1; 32], 10, 5)).unwrap();
        assert!(mp.mev.pool_envelopes.contains_key(&h2));
        mp.prune_confirmed(&[h2]);
        assert!(
            mp.mev.pool_envelopes.is_empty(),
            "pruning drops envelopes too"
        );

        let h3 = mp.add(tx(&sk, [1; 32], 10, 6)).unwrap();
        assert!(mp.mev.pool_envelopes.contains_key(&h3));
        mp.evict_unexecutable(|_| Some((u64::MAX, 0))); // stale nonce for everything
        assert!(
            mp.mev.pool_envelopes.is_empty(),
            "eviction drops envelopes too"
        );
    }

    #[test]
    fn nonce_gap_rejects_far_future_at_admission() {
        // Audit (blocks troubles): a nonce past the window must fail fast,
        // not sit in the pool forever behind an unreachable head.
        //
        // WINDOW REDUCED 16 -> 4 (audit: nonce-stuffing lockup): a 16-nonce
        // window let a sender park 16 unexecutable transactions per account,
        // each holding a pool slot for the whole stuck-TTL. The window is now
        // `NONCE_FUTURE_WINDOW` = 4, so nonce 4 (head 0) is the furthest
        // admission and nonce 5 is refused.
        assert_eq!(Mempool::NONCE_FUTURE_WINDOW, 4);
        let sk = key();
        let me = addr(&sk);
        let mp = Mempool::new(100, 100);
        assert!(mp.check_nonce_gap(&me, 0, 0).is_none());
        assert!(mp.check_nonce_gap(&me, 4, 0).is_none());
        match mp.check_nonce_gap(&me, 5, 0) {
            Some(MempoolError::NonceGap { expected, got }) => {
                assert_eq!((expected, got), (0, 5));
            }
            other => panic!("expected NonceGap, got {other:?}"),
        }
        // With pooled prefix [0,1], the window moves with the head.
        let mut mp2 = Mempool::new(100, 100);
        mp2.add(tx(&sk, [1; 32], 10, 0)).unwrap();
        mp2.add(tx(&sk, [1; 32], 10, 1)).unwrap();
        assert!(mp2.check_nonce_gap(&me, 2, 0).is_none());
        assert!(mp2.check_nonce_gap(&me, 6, 0).is_none());
        assert!(matches!(
            mp2.check_nonce_gap(&me, 7, 0),
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
            mp.sweep_expired(now + Mempool::STUCK_TX_TTL_SECS + 1, |_| Some((
                4, 1_000_000
            ))),
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
    fn evict_unexecutable_reclaims_aged_future_nonces() {
        // Audit (nonce-stuffing lockup): a transaction whose nonce is AHEAD
        // of the sender's executable head is not dead — it is waiting — but
        // it occupies a pool slot exactly like a dead one, and the SENDER
        // controls the gap it waits behind. `evict_unexecutable` used to spare
        // every future nonce unconditionally, so a sender could stuff the
        // pool with unexecutable transactions that nothing ever reclaimed
        // (until the much longer stuck-TTL sweep). Now an aged future nonce
        // is reclaimed.
        assert_eq!(Mempool::FUTURE_NONCE_TTL_SECS, 60);
        assert_eq!(Mempool::STUCK_TX_TTL_SECS, 120);

        let sk = key();
        let me = addr(&sk);
        let now = 1_000_000u64;
        let mut mp = Mempool::new(100, 100);
        // Nonce 5 with an on-chain head of 0: a future nonce behind a gap.
        let future = tx(&sk, [1; 32], 5, 1);
        let future_hash = future.compute_tx_hash();
        mp.insert(future, 1_000_000, true, AdmissionCtx::new(now))
            .expect("a within-window future nonce is admitted");

        // Fresh: still waiting, still pooled.
        assert_eq!(
            mp.evict_unexecutable_at(now, |s| {
                if *s == me {
                    Some((0, 1_000_000))
                } else {
                    None
                }
            }),
            0
        );
        assert!(mp.contains(&future_hash));

        // Aged past the future-nonce TTL: reclaimed.
        assert_eq!(
            mp.evict_unexecutable_at(now + Mempool::FUTURE_NONCE_TTL_SECS, |s| {
                if *s == me {
                    Some((0, 1_000_000))
                } else {
                    None
                }
            }),
            1,
            "an aged future nonce must be reclaimed"
        );
        assert!(!mp.contains(&future_hash));
        assert_eq!(mp.len(), 0);
        // The per-sender quota must not leak.
        assert_eq!(mp.per_sender.get(&me).copied().unwrap_or(0), 0);
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
            priority_fee_per_gas: 0,
        };
        let msg2 = tx2.signing_message();
        let sig2 = Transaction::create_falcon512_test_signature(&pk, &msg2, seed);
        tx2.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig2).encode();

        // The activation buffer is a GLOBAL capped resource: a buffered
        // transaction must be FUNDED (its cost is reserved against the
        // sender's balance), so the checked path with a sufficient balance is
        // the only way in (audit: activation buffer exhaustion).
        // tx2 (implicit) + tx1 (activation, with the surcharge) must both be
        // affordable at the same time.
        const BALANCE: u64 = 1_000_000;
        let h2 = mp
            .add_checked(tx2.clone(), BALANCE)
            .expect("Tx2 must be accepted into activation buffer");
        assert!(
            mp.is_buffered(&h2),
            "Tx2 must be buffered pending activation"
        );
        assert!(mp.contains(&h2), "contains() must find buffered Tx2");
        assert_eq!(mp.len(), 0, "No executable transactions in active pool yet");
        assert_eq!(mp.activation_buffer.count_for_account(&from), 1);

        // Proposer packing cannot select Tx2 yet
        let picked = mp.select_for_block(10, u64::MAX, |_| true);
        assert!(
            picked.is_empty(),
            "Unactivated transaction cannot be picked for block"
        );

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
            priority_fee_per_gas: 0,
        };
        let msg1 = tx1.signing_message();
        let sig1 = Transaction::create_falcon512_test_signature(&pk, &msg1, seed);
        tx1.signature =
            PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig1).encode();

        let h1 = mp
            .add_checked(tx1.clone(), BALANCE)
            .expect("Tx1 activation must succeed");
        assert!(
            !mp.is_buffered(&h2),
            "Tx2 must no longer be in buffer after activation"
        );
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
            priority_fee_per_gas: 0,
        };
        let msg = tx_cheap.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        tx_cheap.signature =
            PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig.clone())
                .encode();

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
            priority_fee_per_gas: 0,
        };
        let msg_ok = tx_ok.signing_message();
        let sig_ok = Transaction::create_falcon512_test_signature(&pk, &msg_ok, seed);
        tx_ok.signature =
            PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk, sig_ok).encode();
        assert!(
            mp.add(tx_ok).is_ok(),
            "Fully paid activation surcharge must succeed"
        );
    }

    #[test]
    fn test_activation_buffer_capacity_limit_4() {
        use crate::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};

        let custom_registry = StatefulImplicitKeyRegistry::new();
        let mut mp = Mempool::new(100, 50)
            .with_base_fee(100)
            .with_implicit_registry(custom_registry);

        let seed = 0x83;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);

        // PER-ACCOUNT CAP REDUCED 16 -> 4 (audit: activation buffer
        // exhaustion): a buffered nonce for an unactivated account IS a
        // future nonce, so it is bounded by the same window as an activated
        // account's (`NONCE_FUTURE_WINDOW` = 4). The old limit of 16 let one
        // account park 16 transactions in the GLOBAL buffer.
        assert_eq!(PendingActivationBuffer::MAX_NONCES_PER_ACCOUNT, 4);

        // Buffered transactions must be FUNDED (their cost is reserved
        // against the sender's balance), so the checked path is the only way
        // in.
        const BALANCE: u64 = 1_000_000;

        // Buffer 4 out-of-order nonces (nonces 1 through 4)
        for nonce in 1..=4 {
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
                priority_fee_per_gas: 0,
            };
            let msg = tx.signing_message();
            let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
            tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
            assert!(mp.add_checked(tx, BALANCE).is_ok());
        }

        assert_eq!(mp.activation_buffer.count_for_account(&from), 4);

        // 5th nonce exceeds the per-account capacity limit
        let mut tx5 = Transaction {
            from,
            to: [1u8; 32],
            amount: 1,
            gas_limit: 100,
            nonce: 5,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg5 = tx5.signing_message();
        let sig5 = Transaction::create_falcon512_test_signature(&pk, &msg5, seed);
        tx5.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig5).encode();

        assert_eq!(
            mp.add_checked(tx5, BALANCE),
            Err(MempoolError::TooManyFromSender),
            "5th buffered nonce must be refused"
        );

        // Transaction with fee below base_fee is rejected
        let mut tx_low_fee = Transaction {
            from,
            to: [1u8; 32],
            amount: 1,
            gas_limit: 50, // below base_fee of 100
            nonce: 6,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg_low = tx_low_fee.signing_message();
        let sig_low = Transaction::create_falcon512_test_signature(&pk, &msg_low, seed);
        tx_low_fee.signature =
            PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig_low).encode();

        assert_eq!(
            mp.add_checked(tx_low_fee, BALANCE),
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
            priority_fee_per_gas: 0,
        };
        let msg = tx_cheap.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        tx_cheap.signature =
            PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk, sig).encode();

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

        // Classical key on purpose: this test proves an Ed25519 scheme id in
        // a PQ1 envelope is refused (not admitted, not verified).
        let esk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pk_bytes = esk.verifying_key().to_bytes().to_vec();

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
            priority_fee_per_gas: 0,
        };
        let msg = tx.signing_message();
        let sig = esk.sign(&msg).to_bytes().to_vec();

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

        // 512 accounts * 4 nonces = 2048 buffered transactions. The
        // per-account cap is now 4 (was 16), so saturating the GLOBAL buffer
        // needs 4x as many accounts as before — and every one of them must
        // actually fund its transactions (see
        // `unfunded_spammer_cannot_saturate_the_activation_buffer`).
        let per_account = PendingActivationBuffer::MAX_NONCES_PER_ACCOUNT as u64;
        let accounts = (PendingActivationBuffer::MAX_GLOBAL_BUFFERED_TXS as u64) / per_account;
        assert_eq!(accounts, 512);
        for acct_idx in 0..accounts as u32 {
            let mut from = [0u8; 32];
            from[0..4].copy_from_slice(&acct_idx.to_be_bytes());
            for nonce in 0..per_account {
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
                    priority_fee_per_gas: 0,
                };
                assert!(buffer.buffer_tx(tx, 50).is_ok());
            }
        }

        assert_eq!(buffer.len(), 2048);
        assert_eq!(
            buffer.len(),
            PendingActivationBuffer::MAX_GLOBAL_BUFFERED_TXS
        );

        // 2049th tx exceeds global buffer cap
        let mut from_extra = [0u8; 32];
        from_extra[0..4].copy_from_slice(&(accounts as u32).to_be_bytes());
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
            priority_fee_per_gas: 0,
        };

        // HONEST ERROR: the global buffer is full, so the refusal is `Full`
        // — NOT `TooManyFromSender`, which blames the sender's own quota for
        // a GLOBAL resource limit (audit: activation buffer exhaustion).
        assert_eq!(
            buffer.buffer_tx(tx_overflow, 50),
            Err(MempoolError::Full),
            "2049th transaction must be rejected by global buffer cap"
        );
        assert_eq!(buffer.len(), 2048);
    }

    #[test]
    fn unfunded_spammer_cannot_saturate_the_activation_buffer() {
        // Audit (activation buffer exhaustion): the activation buffer is a
        // GLOBAL capped resource (2048 slots) that every unactivated account
        // shares. Before this fix a sender could park transactions in it
        // WITHOUT funding them, so a spammer could fill the whole buffer and
        // lock every LEGITIMATE unactivated account out of the network — and
        // they were told "too many transactions from this sender", which was
        // a lie (their own quota was empty).
        //
        // Every buffered transaction must now be FUNDED: its cost is reserved
        // against the sender's balance exactly like a pooled transaction.
        use crate::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};

        let custom_registry = StatefulImplicitKeyRegistry::new();
        let mut mp = Mempool::new(100, 50)
            .with_base_fee(100)
            .with_implicit_registry(custom_registry);

        let make_implicit = |seed: u8, nonce: u64| -> Transaction {
            let pk = Transaction::sample_falcon512_pubkey(seed);
            let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
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
                priority_fee_per_gas: 0,
            };
            let msg = tx.signing_message();
            let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
            tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
            tx
        };

        // The spammer has NO money: every attempt is refused, and the shared
        // buffer stays empty.
        for nonce in 1..=64u64 {
            assert_eq!(
                mp.add_checked(make_implicit(0x11, nonce), 0),
                Err(MempoolError::InsufficientBalance),
                "an unfunded sender must not occupy the activation buffer"
            );
        }
        assert_eq!(
            mp.activation_buffer.len(),
            0,
            "an unfunded spammer must not fill the activation buffer"
        );

        // The unchecked path (no balance at all) must not hand out free
        // buffer slots either.
        assert_eq!(
            mp.add(make_implicit(0x11, 65)),
            Err(MempoolError::InsufficientBalance)
        );
        assert_eq!(mp.activation_buffer.len(), 0);

        // A LEGITIMATE, FUNDED unactivated account still gets in.
        assert!(
            mp.add_checked(make_implicit(0x22, 1), 1_000_000).is_ok(),
            "a funded unactivated account must still be admitted"
        );
        assert_eq!(mp.activation_buffer.len(), 1);
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
            priority_fee_per_gas: 0,
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
            priority_fee_per_gas: 0,
        };
        let h2 = tx2.compute_tx_hash();
        assert_ne!(h1, h2);

        assert_eq!(buffer.buffer_tx(tx2, 50), Ok(h2));
        assert_eq!(buffer.len(), 1);
        assert!(
            !buffer.contains_hash(&h1),
            "Old hash must no longer be in buffer"
        );
        assert!(
            !buffer.by_hash.contains_key(&h1),
            "Old hash must be removed from by_hash"
        );
        assert!(buffer.contains_hash(&h2), "New hash must be in buffer");
        assert!(
            buffer.by_hash.contains_key(&h2),
            "New hash must be in by_hash"
        );
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
            priority_fee_per_gas: 0,
        };
        let msg = tx.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();

        let now = 10_000u64;
        let ctx = AdmissionCtx::new(now);
        // The activation buffer only accepts FUNDED transactions (the sender's
        // balance is reserved for them), so the checked path carries a real
        // balance instead of the unchecked `u64::MAX`.
        let h = mp
            .insert(tx, 1_000_000, true, ctx)
            .expect("Must buffer in activation buffer");

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
            assert!(
                r.is_ok(),
                "mempool admission panicked on len {}",
                input.len()
            );
        }
    }
}
