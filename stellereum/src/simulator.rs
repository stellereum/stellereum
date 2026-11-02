//! Deterministic local devnet + chain simulator.
//!
//! The devnet is a **hermetic, in-process** replica of the chain's core
//! accounting rules: a genesis with `N` validator accounts, a stream of signed
//! [`Transaction`]s grouped into blocks, a flat fee model, per-block proposer
//! rewards and a canonical state root.
//!
//! # Determinism contract
//!
//! Everything in this module is a pure function of (seed, transaction
//! sequence):
//!
//! * **No wall clock.** Block timestamps are *logical* — `start_time_ms +
//!   height * block_time_ms` — never read from the OS clock.
//! * **No OS randomness.** Validator keys, account keys and the workload
//!   generator are derived from a caller-supplied seed through
//!   [`DeterministicRng`] / [`derive_keypair`].
//! * **Canonical state root.** The root is a BLAKE3 hash over the state in a
//!   canonical (sorted) order, so it does not depend on insertion order, hash
//!   map iteration order or the order in which blocks were produced.
//!
//! Two runs with the same seed and the same transaction sequence therefore
//! produce byte-identical state roots, which is what makes the log replay in
//! [`SimLog::replay`] a meaningful check.
//!
//! # State snapshot
//!
//! [`ChainSimulator::snapshot`] serialises the whole state into a versioned,
//! self-describing blob ([`StateSnapshot`]). [`ChainSimulator::restore`]
//! rebuilds the state from it and the state root after the restore is
//! bit-identical to the root at snapshot time.
//!
//! # Fee preview
//!
//! [`ChainSimulator::preview_fee`] computes the fee a transaction *would*
//! pay without touching the state; the same function is used by the apply
//! path, so a preview always equals the fee actually charged.

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::post_quantum::FalconKeypair;
use crate::sharding::{ShardId, Transaction};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Version of the transaction-log format written by [`SimLog::to_bytes`].
///
/// Bump this whenever the on-disk layout changes in a way that an older
/// reader could not understand; readers refuse a version they do not know
/// instead of guessing.
pub const SIM_LOG_VERSION: u32 = 1;

/// Domain separator of the simulator state root.
pub const SIM_STATE_DOMAIN: &[u8] = b"STELLEREUM_SIM_STATE_V1";

/// Domain separator of the simulator block hash.
pub const SIM_BLOCK_DOMAIN: &[u8] = b"STELLEREUM_SIM_BLOCK_V1";

/// Domain separator of the deterministic key derivation.
pub const SIM_KEY_DOMAIN: &str = "STELLEREUM_SIM_KEY_V1";

/// Domain separator of the deterministic RNG.
pub const SIM_RNG_DOMAIN: &str = "STELLEREUM_SIM_RNG_V1";

/// Chain id used by the simulator. Deliberately distinct from the production
/// chain id so a devnet transaction can never be replayed on a real network.
pub const SIM_CHAIN_ID: u64 = 0x5354_4C44; // "STLD" (devnet)

/// Default logical block interval, in milliseconds.
pub const DEFAULT_BLOCK_TIME_MS: u64 = 400;

/// Default logical genesis timestamp, in milliseconds since the Unix epoch.
///
/// A fixed constant: the simulator never reads the wall clock.
pub const DEFAULT_START_TIME_MS: u64 = 1_700_000_000_000;

/// Default genesis balance of every devnet account, in nano-STELL.
pub const DEFAULT_GENESIS_BALANCE: u64 = 1_000_000_000_000; // 1_000 STELL

/// Default stake bonded by every devnet validator, in nano-STELL.
pub const DEFAULT_VALIDATOR_STAKE: u64 = 100_000_000_000; // 100 STELL

/// Default block reward minted to the proposer, in nano-STELL.
pub const DEFAULT_BLOCK_REWARD: u64 = 1_000_000_000; // 1 STELL

/// Default intrinsic gas charged for every transaction.
pub const DEFAULT_INTRINSIC_GAS: u64 = 21_000;

/// Default flat base fee per gas unit, in nano-STELL.
pub const DEFAULT_BASE_FEE_PER_GAS: u64 = 1;

/// Default number of transactions the built-in workload puts in each block.
pub const DEFAULT_TXS_PER_BLOCK: u64 = 2;

/// Maximum number of validator accounts a devnet may be created with.
pub const MAX_DEVNET_ACCOUNTS: usize = 256;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can go wrong inside the simulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimError {
    /// The requested configuration is not usable.
    InvalidConfig(String),
    /// The seed could not be interpreted.
    InvalidSeed(String),
    /// The sender account does not exist.
    UnknownAccount([u8; 32]),
    /// The proposer is not a member of the validator set.
    UnknownValidator([u8; 32]),
    /// The sender cannot pay for the transaction.
    InsufficientBalance {
        address: [u8; 32],
        available: u64,
        required: u64,
    },
    /// The nonce does not match the sender's account nonce.
    BadNonce {
        address: [u8; 32],
        expected: u64,
        got: u64,
    },
    /// The transaction signature does not verify.
    InvalidSignature([u8; 32]),
    /// `gas_limit` is below the intrinsic gas of the transaction.
    GasLimitTooLow { declared: u64, required: u64 },
    /// SVM payloads are not executed by the simulator.
    UnsupportedPayload([u8; 32]),
    /// An arithmetic overflow was detected.
    Overflow(&'static str),
    /// A state snapshot could not be decoded.
    SnapshotCorrupt(String),
    /// A transaction log could not be decoded.
    LogCorrupt(String),
    /// The transaction log carries an unsupported format version.
    LogVersion { found: u32, expected: u32 },
    /// The replayed state root differs from the recorded one.
    ReplayMismatch {
        height: u64,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// The block heights in the log are not contiguous.
    HeightMismatch { expected: u64, got: u64 },
}

impl fmt::Display for SimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimError::InvalidConfig(m) => write!(f, "invalid simulator config: {m}"),
            SimError::InvalidSeed(m) => write!(f, "invalid seed: {m}"),
            SimError::UnknownAccount(a) => {
                write!(f, "unknown account {}", hex::encode(a))
            }
            SimError::UnknownValidator(a) => {
                write!(f, "unknown validator {}", hex::encode(a))
            }
            SimError::InsufficientBalance {
                address,
                available,
                required,
            } => write!(
                f,
                "insufficient balance for {}: have {} nano-STELL, need {}",
                hex::encode(address),
                available,
                required
            ),
            SimError::BadNonce {
                address,
                expected,
                got,
            } => write!(
                f,
                "invalid nonce for {}: expected {}, got {}",
                hex::encode(address),
                expected,
                got
            ),
            SimError::InvalidSignature(a) => {
                write!(f, "invalid transaction signature for {}", hex::encode(a))
            }
            SimError::GasLimitTooLow { declared, required } => write!(
                f,
                "gas limit too low: declared {declared}, intrinsic gas is {required}"
            ),
            SimError::UnsupportedPayload(a) => write!(
                f,
                "SVM payloads are not supported by the simulator (sender {})",
                hex::encode(a)
            ),
            SimError::Overflow(what) => write!(f, "arithmetic overflow while computing {what}"),
            SimError::SnapshotCorrupt(m) => write!(f, "corrupt state snapshot: {m}"),
            SimError::LogCorrupt(m) => write!(f, "corrupt transaction log: {m}"),
            SimError::LogVersion { found, expected } => write!(
                f,
                "unsupported transaction log version {found} (this build understands {expected})"
            ),
            SimError::ReplayMismatch {
                height,
                expected,
                actual,
            } => write!(
                f,
                "state root mismatch at height {height}: recorded {}, replayed {}",
                hex::encode(expected),
                hex::encode(actual)
            ),
            SimError::HeightMismatch { expected, got } => write!(
                f,
                "unexpected block height in log: expected {expected}, got {got}"
            ),
        }
    }
}

impl std::error::Error for SimError {}

// ---------------------------------------------------------------------------
// Deterministic randomness and key derivation
// ---------------------------------------------------------------------------

/// A seeded, reproducible byte source.
///
/// The generator is a counter-mode BLAKE3 function: every draw is a pure
/// function of `(key, counter)`, so the stream depends on nothing but the seed
/// — no entropy source, no clock, no address-space layout.
#[derive(Clone, Debug)]
pub struct DeterministicRng {
    key: [u8; 32],
    counter: u64,
}

impl DeterministicRng {
    /// Create a generator from an arbitrary-length seed.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(SIM_RNG_DOMAIN);
        hasher.update(&(seed.len() as u64).to_be_bytes());
        hasher.update(seed);
        let key = *hasher.finalize().as_bytes();
        Self { key, counter: 0 }
    }

    /// Draw the next 64 bits of the stream.
    pub fn next_u64(&mut self) -> u64 {
        let mut hasher = blake3::Hasher::new_derive_key(SIM_RNG_DOMAIN);
        hasher.update(&self.key);
        hasher.update(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        let digest = hasher.finalize();
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&digest.as_bytes()[..8]);
        u64::from_le_bytes(buf)
    }

    /// Draw a value in `0..upper` (rejection sampling: no modulo bias).
    ///
    /// Returns 0 when `upper == 0`.
    pub fn next_u64_below(&mut self, upper: u64) -> u64 {
        if upper == 0 {
            return 0;
        }
        // Reject the incomplete final bucket so every value is equally likely.
        let zone = u64::MAX - (u64::MAX % upper);
        loop {
            let draw = self.next_u64();
            if draw < zone {
                return draw % upper;
            }
        }
    }

    /// Draw `len` pseudo-random bytes.
    pub fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let mut hasher = blake3::Hasher::new_derive_key(SIM_RNG_DOMAIN);
            hasher.update(&self.key);
            hasher.update(&self.counter.to_be_bytes());
            self.counter = self.counter.wrapping_add(1);
            out.extend_from_slice(hasher.finalize().as_bytes());
        }
        out.truncate(len);
        out
    }

    /// The current position of the stream.
    ///
    /// Part of the simulator snapshot: restoring the state without restoring
    /// the stream position would make the *continuation* of the simulation
    /// differ from the original run.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Move the stream back to a previously recorded position.
    pub fn set_counter(&mut self, counter: u64) {
        self.counter = counter;
    }
}

/// Derive a signing key deterministically from a seed and a label.
///
/// `label` separates the different roles (validator keys, faucet keys, ...)
/// so two roles never share a key.
pub fn derive_keypair(seed: &[u8], label: &[u8], index: u32) -> SigningKey {
    let mut hasher = blake3::Hasher::new_derive_key(SIM_KEY_DOMAIN);
    hasher.update(&(seed.len() as u64).to_be_bytes());
    hasher.update(seed);
    hasher.update(&(label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update(&index.to_be_bytes());
    let bytes = *hasher.finalize().as_bytes();
    SigningKey::from_bytes(&bytes)
}

/// Domain separator of the deterministic PQ key derivation.
///
/// Deliberately distinct from [`SIM_KEY_DOMAIN`] so the Falcon-512 seed bytes
/// never equal the Ed25519 secret bytes for the same `(seed, label, index)`,
/// while remaining a pure function of the SAME caller seed.
pub const SIM_PQ_KEY_DOMAIN: &str = "STELLEREUM_SIM_PQ_KEY_V1";

/// Derive the 32-byte Falcon-512 seed for `(seed, label, index)`.
///
/// Same caller seed and same `(label, index)` role separation as
/// [`derive_keypair`]; only the domain separator differs (see
/// [`SIM_PQ_KEY_DOMAIN`).
pub fn derive_pq_seed(seed: &[u8], label: &[u8], index: u32) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SIM_PQ_KEY_DOMAIN);
    hasher.update(&(seed.len() as u64).to_be_bytes());
    hasher.update(seed);
    hasher.update(&(label.len() as u64).to_be_bytes());
    hasher.update(label);
    hasher.update(&index.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Derive a deterministic Falcon-512 keypair from the same seed as
/// [`derive_keypair`].
///
/// PQ-first companion for simulator/devnet keygen: the same `(seed, label,
/// index)` always yields the same keypair (via
/// [`FalconKeypair::generate_from_seed_bytes`]), with no OS randomness and no
/// wall clock. The existing Ed25519 [`derive_keypair`] path is untouched.
pub fn derive_falcon_keypair(seed: &[u8], label: &[u8], index: u32) -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&derive_pq_seed(seed, label, index))
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// A devnet account: balance plus replay-protection nonce.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SimAccount {
    /// Balance in nano-STELL.
    pub balance: u64,
    /// Next expected nonce (anti-replay counter).
    pub nonce: u64,
}

/// The full simulator state.
///
/// Both maps are sorted (`BTreeMap`), so every traversal — and therefore the
/// state root — is canonical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimState {
    chain_id: u64,
    height: u64,
    total_supply: u64,
    accounts: BTreeMap<[u8; 32], SimAccount>,
    validators: BTreeMap<[u8; 32], u64>,
}

impl SimState {
    /// Balance of an account (0 for an unknown account).
    pub fn balance_of(&self, address: &[u8; 32]) -> u64 {
        self.accounts.get(address).map(|a| a.balance).unwrap_or(0)
    }

    /// Nonce of an account.
    pub fn nonce_of(&self, address: &[u8; 32]) -> u64 {
        self.accounts.get(address).map(|a| a.nonce).unwrap_or(0)
    }

    /// Stake bonded by a validator (0 for a non-validator).
    pub fn stake_of(&self, address: &[u8; 32]) -> u64 {
        self.validators.get(address).copied().unwrap_or(0)
    }

    /// Current block height.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Chain id of this devnet.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Total supply in nano-STELL (balances + bonded stake).
    pub fn total_supply(&self) -> u64 {
        self.total_supply
    }

    /// All accounts, in canonical (address-sorted) order.
    pub fn accounts<'a>(&'a self) -> impl Iterator<Item = (&'a [u8; 32], &'a SimAccount)> + 'a {
        self.accounts.iter()
    }

    /// The validator set as `(address, stake)` pairs, in canonical order.
    pub fn validator_set(&self) -> impl Iterator<Item = ([u8; 32], u64)> + '_ {
        self.validators.iter().map(|(a, s)| (*a, *s))
    }

    /// The canonical state root.
    ///
    /// BLAKE3 over the domain separator and every state field in canonical
    /// order. Two states with the same content always produce the same root,
    /// independently of the order in which they were built.
    pub fn state_root(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SIM_STATE_DOMAIN);
        hasher.update(&self.chain_id.to_be_bytes());
        hasher.update(&self.height.to_be_bytes());
        hasher.update(&self.total_supply.to_be_bytes());
        hasher.update(&(self.accounts.len() as u64).to_be_bytes());
        for (address, account) in &self.accounts {
            hasher.update(address);
            hasher.update(&account.balance.to_be_bytes());
            hasher.update(&account.nonce.to_be_bytes());
        }
        hasher.update(&(self.validators.len() as u64).to_be_bytes());
        for (address, stake) in &self.validators {
            hasher.update(address);
            hasher.update(&stake.to_be_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// Serialise the state into the versioned snapshot format.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.total_supply.to_be_bytes());
        out.extend_from_slice(&(self.accounts.len() as u64).to_be_bytes());
        for (address, account) in &self.accounts {
            out.extend_from_slice(address);
            out.extend_from_slice(&account.balance.to_be_bytes());
            out.extend_from_slice(&account.nonce.to_be_bytes());
        }
        out.extend_from_slice(&(self.validators.len() as u64).to_be_bytes());
        for (address, stake) in &self.validators {
            out.extend_from_slice(address);
            out.extend_from_slice(&stake.to_be_bytes());
        }
        out
    }

    /// Parse a state snapshot produced by [`SimState::encode`].
    fn decode(bytes: &[u8]) -> Result<Self, SimError> {
        let mut cursor = 0usize;
        let magic = take(bytes, &mut cursor, SNAPSHOT_MAGIC.len())
            .ok_or_else(|| SimError::SnapshotCorrupt("truncated magic".into()))?;
        if magic != SNAPSHOT_MAGIC {
            return Err(SimError::SnapshotCorrupt("bad magic".into()));
        }
        let chain_id = read_u64(bytes, &mut cursor)?;
        let height = read_u64(bytes, &mut cursor)?;
        let total_supply = read_u64(bytes, &mut cursor)?;
        let account_count = read_u64(bytes, &mut cursor)?;
        let mut accounts = BTreeMap::new();
        for _ in 0..account_count {
            let mut address = [0u8; 32];
            address.copy_from_slice(
                take(bytes, &mut cursor, 32)
                    .ok_or_else(|| SimError::SnapshotCorrupt("truncated account".into()))?,
            );
            let balance = read_u64(bytes, &mut cursor)?;
            let nonce = read_u64(bytes, &mut cursor)?;
            accounts.insert(address, SimAccount { balance, nonce });
        }
        let validator_count = read_u64(bytes, &mut cursor)?;
        let mut validators = BTreeMap::new();
        for _ in 0..validator_count {
            let mut address = [0u8; 32];
            address.copy_from_slice(
                take(bytes, &mut cursor, 32)
                    .ok_or_else(|| SimError::SnapshotCorrupt("truncated validator".into()))?,
            );
            let stake = read_u64(bytes, &mut cursor)?;
            validators.insert(address, stake);
        }
        if cursor != bytes.len() {
            return Err(SimError::SnapshotCorrupt(format!(
                "{} trailing bytes",
                bytes.len() - cursor
            )));
        }
        Ok(Self {
            chain_id,
            height,
            total_supply,
            accounts,
            validators,
        })
    }
}

/// Magic prefix of the state-snapshot format (`STLSNAP` + format byte).
const SNAPSHOT_MAGIC: &[u8; 8] = b"STLSNAP\x01";

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Option<&'a [u8]> {
    if *cursor + len > bytes.len() {
        return None;
    }
    let out = &bytes[*cursor..*cursor + len];
    *cursor += len;
    Some(out)
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, SimError> {
    let slice = take(bytes, cursor, 8)
        .ok_or_else(|| SimError::SnapshotCorrupt("truncated integer".into()))?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(slice);
    Ok(u64::from_be_bytes(buf))
}

/// A serialised simulator state.
///
/// The blob is self-describing and versioned, so it can be written to disk and
/// restored later without any side-band metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSnapshot {
    bytes: Vec<u8>,
}

impl StateSnapshot {
    /// The raw snapshot bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Build a snapshot from raw bytes (the inverse of
    /// [`StateSnapshot::as_bytes`]).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

// ---------------------------------------------------------------------------
// Configuration, fees, blocks
// ---------------------------------------------------------------------------

/// Simulator configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimConfig {
    /// Chain id of the devnet.
    pub chain_id: u64,
    /// Logical block interval in milliseconds.
    pub block_time_ms: u64,
    /// Logical timestamp of the genesis block, in milliseconds.
    pub start_time_ms: u64,
    /// Genesis balance of every account (nano-STELL).
    pub genesis_balance: u64,
    /// Stake bonded by every validator (nano-STELL).
    pub validator_stake: u64,
    /// Block reward minted to the proposer (nano-STELL).
    pub block_reward: u64,
    /// Flat base fee per gas unit (nano-STELL).
    pub base_fee_per_gas: u64,
    /// Intrinsic gas charged per transaction.
    pub intrinsic_gas: u64,
    /// Number of transactions the built-in workload puts in each block.
    pub txs_per_block: u64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            chain_id: SIM_CHAIN_ID,
            block_time_ms: DEFAULT_BLOCK_TIME_MS,
            start_time_ms: DEFAULT_START_TIME_MS,
            genesis_balance: DEFAULT_GENESIS_BALANCE,
            validator_stake: DEFAULT_VALIDATOR_STAKE,
            block_reward: DEFAULT_BLOCK_REWARD,
            base_fee_per_gas: DEFAULT_BASE_FEE_PER_GAS,
            intrinsic_gas: DEFAULT_INTRINSIC_GAS,
            txs_per_block: DEFAULT_TXS_PER_BLOCK,
        }
    }
}

/// A fee quote: exactly what a transaction would pay.
///
/// Produced by [`ChainSimulator::preview_fee`] without touching the state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeQuote {
    /// Gas units consumed by the transaction.
    pub gas_used: u64,
    /// The gas cap declared by the transaction.
    pub gas_limit: u64,
    /// Base price per gas unit (nano-STELL).
    pub base_fee_per_gas: u64,
    /// Explicit priority bid per gas unit (nano-STELL).
    pub priority_fee_per_gas: u64,
    /// Total fee that would be charged: `gas_used * (base + priority)`.
    pub total_fee: u64,
}

/// The result of applying a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutcome {
    /// Transaction hash (`Transaction::compute_tx_hash`).
    pub tx_hash: [u8; 32],
    /// Sender.
    pub from: [u8; 32],
    /// Recipient.
    pub to: [u8; 32],
    /// Transferred value (nano-STELL).
    pub amount: u64,
    /// Gas consumed.
    pub gas_used: u64,
    /// Fee actually charged (nano-STELL).
    pub fee_charged: u64,
}

/// A block produced by the simulator.
#[derive(Clone, Debug)]
pub struct SimBlock {
    /// Block height (1-based; the genesis is height 0).
    pub height: u64,
    /// Logical timestamp in milliseconds.
    pub time_ms: u64,
    /// Proposer (validator that produced the block).
    pub proposer: [u8; 32],
    /// Transactions in the block, in application order.
    pub txs: Vec<Transaction>,
    /// Total gas consumed by the block.
    pub gas_used: u64,
    /// Total fees collected by the block.
    pub fees: u64,
    /// State root *after* the block was applied.
    pub state_root: [u8; 32],
    /// State root *before* the block was applied.
    pub prev_root: [u8; 32],
    /// Canonical block hash.
    pub block_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// The simulator
// ---------------------------------------------------------------------------

/// A validator of the devnet.
#[derive(Clone)]
pub struct SimValidator {
    /// Validator address (the Ed25519 public key).
    pub address: [u8; 32],
    /// Bonded stake (nano-STELL).
    pub stake: u64,
    /// The signing key (never printed).
    key: SigningKey,
}

impl fmt::Debug for SimValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimValidator")
            .field("address", &hex::encode(self.address))
            .field("stake", &self.stake)
            .finish()
    }
}

/// A deterministic, in-process chain simulator.
///
/// ```no_run
/// use stellereum::simulator::{ChainSimulator, SimConfig};
///
/// let mut sim = ChainSimulator::genesis(b"devnet", 4, SimConfig::default()).unwrap();
/// let summary = sim.run_blocks(10).unwrap();
/// assert_eq!(summary.blocks, 10);
/// ```
#[derive(Clone)]
pub struct ChainSimulator {
    seed: Vec<u8>,
    config: SimConfig,
    state: SimState,
    validators: Vec<SimValidator>,
    blocks: Vec<SimBlock>,
    rng: DeterministicRng,
}

impl fmt::Debug for ChainSimulator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainSimulator")
            .field("chain_id", &self.config.chain_id)
            .field("height", &self.state.height)
            .field("validators", &self.validators.len())
            .field("state_root", &hex::encode(self.state.state_root()))
            .finish()
    }
}

impl ChainSimulator {
    /// Build a devnet genesis from a seed.
    ///
    /// `accounts` validator accounts are derived deterministically from
    /// `seed`; each of them is funded with `config.genesis_balance` and bonds
    /// `config.validator_stake`.
    pub fn genesis(seed: &[u8], accounts: usize, config: SimConfig) -> Result<Self, SimError> {
        if accounts == 0 {
            return Err(SimError::InvalidConfig(
                "a devnet needs at least one validator account".into(),
            ));
        }
        if accounts > MAX_DEVNET_ACCOUNTS {
            return Err(SimError::InvalidConfig(format!(
                "at most {MAX_DEVNET_ACCOUNTS} validator accounts are supported"
            )));
        }
        if config.genesis_balance < config.validator_stake {
            return Err(SimError::InvalidConfig(
                "genesis balance must cover the bonded stake".into(),
            ));
        }
        if config.intrinsic_gas == 0 {
            return Err(SimError::InvalidConfig(
                "intrinsic gas must be greater than zero".into(),
            ));
        }

        let mut validators = Vec::with_capacity(accounts);
        let mut state_accounts = BTreeMap::new();
        let mut state_validators = BTreeMap::new();

        for index in 0..accounts {
            let key = derive_keypair(seed, b"validator", index as u32);
            let address = key.verifying_key().to_bytes();
            validators.push(SimValidator {
                address,
                stake: config.validator_stake,
                key,
            });
            state_accounts.insert(
                address,
                SimAccount {
                    balance: config.genesis_balance - config.validator_stake,
                    nonce: 0,
                },
            );
            state_validators.insert(address, config.validator_stake);
        }

        let state = SimState {
            chain_id: config.chain_id,
            height: 0,
            total_supply: config
                .genesis_balance
                .checked_mul(accounts as u64)
                .ok_or(SimError::Overflow("genesis supply"))?,
            accounts: state_accounts,
            validators: state_validators,
        };

        Ok(Self {
            seed: seed.to_vec(),
            config,
            state,
            validators,
            blocks: Vec::new(),
            rng: DeterministicRng::from_seed(seed),
        })
    }

    /// The configuration this simulator was built with.
    pub fn config(&self) -> &SimConfig {
        &self.config
    }

    /// The seed this simulator was built with.
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    /// The current state.
    pub fn state(&self) -> &SimState {
        &self.state
    }

    /// The validator set.
    pub fn validators(&self) -> &[SimValidator] {
        &self.validators
    }

    /// The blocks produced so far.
    pub fn blocks(&self) -> &[SimBlock] {
        &self.blocks
    }

    /// The current state root.
    pub fn state_root(&self) -> [u8; 32] {
        self.state.state_root()
    }

    /// Current block height.
    pub fn height(&self) -> u64 {
        self.state.height
    }

    /// Balance of an account.
    pub fn balance(&self, address: &[u8; 32]) -> u64 {
        self.state.balance_of(address)
    }

    /// Nonce of an account.
    pub fn nonce(&self, address: &[u8; 32]) -> u64 {
        self.state.nonce_of(address)
    }

    /// Index of a validator in the validator set.
    pub fn validator_index(&self, address: &[u8; 32]) -> Option<usize> {
        self.validators.iter().position(|v| &v.address == address)
    }

    /// Take a snapshot of the whole state.
    ///
    /// The snapshot carries the state AND the position of the deterministic
    /// workload generator, so a restored simulator continues exactly like the
    /// original one.
    pub fn snapshot(&self) -> StateSnapshot {
        let mut bytes = self.state.encode();
        bytes.extend_from_slice(&self.rng.counter().to_be_bytes());
        StateSnapshot { bytes }
    }

    /// Restore the state from a snapshot.
    ///
    /// The state root after the restore is bit-identical to the root at
    /// snapshot time.
    pub fn restore(&mut self, snapshot: &StateSnapshot) -> Result<(), SimError> {
        let bytes = snapshot.as_bytes();
        if bytes.len() < 8 {
            return Err(SimError::SnapshotCorrupt("truncated snapshot".into()));
        }
        let (state_bytes, counter_bytes) = bytes.split_at(bytes.len() - 8);
        let state = SimState::decode(state_bytes)?;
        if state.chain_id != self.config.chain_id {
            return Err(SimError::SnapshotCorrupt(format!(
                "chain id mismatch: snapshot is {}, simulator is {}",
                state.chain_id, self.config.chain_id
            )));
        }
        let mut counter = [0u8; 8];
        counter.copy_from_slice(counter_bytes);
        self.state = state;
        self.rng.set_counter(u64::from_be_bytes(counter));
        self.blocks.retain(|b| b.height <= self.state.height);
        Ok(())
    }

    /// Compute the fee a transaction would pay — WITHOUT committing anything.
    ///
    /// The returned quote is exactly what [`ChainSimulator::apply_transaction`]
    /// charges, because both paths call the same function ([`fee_for`]): the
    /// preview can never drift away from the applied fee.
    pub fn preview_fee(&self, tx: &Transaction) -> Result<FeeQuote, SimError> {
        fee_for(tx, &self.config)
    }

    /// Apply a single transaction to the current state.
    ///
    /// The fee is credited to `proposer` (the block producer), mirroring the
    /// chain's priority-fee model. The state is modified in place; use
    /// [`ChainSimulator::produce_block`] for atomic block production.
    pub fn apply_transaction(
        &mut self,
        proposer: &[u8; 32],
        tx: &Transaction,
    ) -> Result<TxOutcome, SimError> {
        let outcome = apply_tx_to_state(&mut self.state, tx, proposer, &self.config)?;
        Ok(outcome)
    }

    /// Apply a batch of transactions as ONE block.
    ///
    /// The batch is atomic: the block is applied to a copy of the state and
    /// only committed when every transaction succeeds. On failure the
    /// simulator state is left exactly as it was.
    pub fn produce_block(
        &mut self,
        proposer_index: usize,
        txs: Vec<Transaction>,
    ) -> Result<SimBlock, SimError> {
        let proposer = self
            .validators
            .get(proposer_index)
            .ok_or(SimError::UnknownValidator([0u8; 32]))?
            .address;

        let mut next = self.state.clone();
        let mut gas_used = 0u64;
        let mut fees = 0u64;
        for tx in &txs {
            let outcome = apply_tx_to_state(&mut next, tx, &proposer, &self.config)?;
            gas_used = gas_used
                .checked_add(outcome.gas_used)
                .ok_or(SimError::Overflow("block gas"))?;
            fees = fees
                .checked_add(outcome.fee_charged)
                .ok_or(SimError::Overflow("block fees"))?;
        }

        // Proposer reward (minted).
        {
            let account = next.accounts.entry(proposer).or_default();
            account.balance = account
                .balance
                .checked_add(self.config.block_reward)
                .ok_or(SimError::Overflow("block reward"))?;
        }
        next.total_supply = next
            .total_supply
            .checked_add(self.config.block_reward)
            .ok_or(SimError::Overflow("total supply"))?;
        next.height = self.state.height + 1;

        let prev_root = self.state.state_root();
        let state_root = next.state_root();
        let time_ms = self
            .config
            .start_time_ms
            .saturating_add(next.height.saturating_mul(self.config.block_time_ms));
        let block_hash = compute_block_hash(
            &proposer,
            next.height,
            time_ms,
            &prev_root,
            &state_root,
            &txs,
        );

        self.state = next;
        let block = SimBlock {
            height: self.state.height,
            time_ms,
            proposer,
            txs,
            gas_used,
            fees,
            state_root,
            prev_root,
            block_hash,
        };
        self.blocks.push(block.clone());
        Ok(block)
    }

    /// Build the deterministic workload of the next block.
    ///
    /// The workload consists of `config.txs_per_block` transfers between
    /// validator accounts, with amounts, priority bids and nonces derived from
    /// the seeded RNG and the current state.
    pub fn generate_workload(&mut self) -> Result<Vec<Transaction>, SimError> {
        let count = self.validators.len();
        if count == 0 {
            return Ok(Vec::new());
        }
        let mut txs = Vec::with_capacity(self.config.txs_per_block as usize);
        let mut pending_nonce: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        let base = self.state.height as usize * self.config.txs_per_block as usize;

        for i in 0..self.config.txs_per_block {
            let sender_index = (base + i as usize) % count;
            let recipient_index = (sender_index + 1) % count;
            let sender_address = self.validators[sender_index].address;
            let recipient_address = self.validators[recipient_index].address;
            let key = self.validators[sender_index].key.clone();

            let nonce = match pending_nonce.get(&sender_address) {
                Some(nonce) => *nonce,
                None => self.state.nonce_of(&sender_address),
            };
            pending_nonce.insert(sender_address, nonce + 1);

            let amount = 1 + self.rng.next_u64_below(1_000_000_000);
            let priority_fee_per_gas = if self.rng.next_u64().is_multiple_of(4) {
                self.rng.next_u64_below(3)
            } else {
                0
            };

            let tx = Transaction::sign_with_priority(
                &key,
                recipient_address,
                amount,
                self.config.intrinsic_gas,
                nonce,
                0 as ShardId,
                0 as ShardId,
                priority_fee_per_gas,
            );
            txs.push(tx);
        }
        Ok(txs)
    }

    /// Produce `blocks` blocks with the built-in deterministic workload.
    pub fn run_blocks(&mut self, blocks: u64) -> Result<DevnetSummary, SimError> {
        let genesis_root = self.state_root();
        let mut transactions = 0u64;
        let mut total_gas = 0u64;
        let mut total_fees = 0u64;

        for _ in 0..blocks {
            let proposer_index = (self.state.height as usize) % self.validators.len();
            let txs = self.generate_workload()?;
            let block = self.produce_block(proposer_index, txs)?;
            transactions += block.txs.len() as u64;
            total_gas += block.gas_used;
            total_fees += block.fees;
        }

        let validators = self
            .validators
            .iter()
            .map(|v| ValidatorSummary {
                address: v.address,
                stake: v.stake,
                balance: self.state.balance_of(&v.address),
            })
            .collect();

        Ok(DevnetSummary {
            accounts: self.validators.len(),
            blocks,
            transactions,
            total_gas,
            total_fees,
            block_time_ms: self.config.block_time_ms,
            chain_time_ms: blocks.saturating_mul(self.config.block_time_ms),
            genesis_root,
            state_root: self.state_root(),
            validators,
            first_block_hash: self.blocks.first().map(|b| b.block_hash),
            last_block_hash: self.blocks.last().map(|b| b.block_hash),
        })
    }

    /// Build a replayable transaction log out of the recorded blocks.
    pub fn log(&self) -> Result<SimLog, SimError> {
        SimLog::from_simulator(self)
    }
}

/// Summary of a devnet run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevnetSummary {
    /// Number of validator accounts.
    pub accounts: usize,
    /// Number of blocks produced.
    pub blocks: u64,
    /// Number of transactions applied.
    pub transactions: u64,
    /// Total gas consumed.
    pub total_gas: u64,
    /// Total fees collected.
    pub total_fees: u64,
    /// Logical block interval (milliseconds).
    pub block_time_ms: u64,
    /// Total logical chain time covered by the run (milliseconds).
    pub chain_time_ms: u64,
    /// State root of the genesis state.
    pub genesis_root: [u8; 32],
    /// State root after the last block.
    pub state_root: [u8; 32],
    /// The final validator set.
    pub validators: Vec<ValidatorSummary>,
    /// Hash of the first produced block.
    pub first_block_hash: Option<[u8; 32]>,
    /// Hash of the last produced block.
    pub last_block_hash: Option<[u8; 32]>,
}

impl DevnetSummary {
    /// Throughput in transactions per second of *logical* chain time.
    pub fn tps(&self) -> f64 {
        if self.chain_time_ms == 0 {
            return 0.0;
        }
        (self.transactions as f64) / (self.chain_time_ms as f64 / 1000.0)
    }
}

/// One entry of the final validator set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatorSummary {
    /// Validator address.
    pub address: [u8; 32],
    /// Bonded stake (nano-STELL).
    pub stake: u64,
    /// Spendable balance (nano-STELL).
    pub balance: u64,
}

/// Compute the fee of a transaction.
///
/// THE single source of truth for the fee model: the preview path and the
/// apply path both call it, so a preview can never disagree with the fee that
/// is actually charged.
fn fee_for(tx: &Transaction, config: &SimConfig) -> Result<FeeQuote, SimError> {
    if !tx.payload.is_empty() {
        // The simulator models the native ledger only; executing an SVM
        // program would need the full VM context (tokens, orderbook, staking,
        // bridge), so it is refused loudly instead of being silently charged
        // for but not executed.
        return Err(SimError::UnsupportedPayload(tx.from));
    }
    let gas_used = config.intrinsic_gas;
    if tx.gas_limit < gas_used {
        return Err(SimError::GasLimitTooLow {
            declared: tx.gas_limit,
            required: gas_used,
        });
    }
    let price = config
        .base_fee_per_gas
        .checked_add(tx.priority_fee_per_gas)
        .ok_or(SimError::Overflow("fee price"))?;
    let total_fee = gas_used
        .checked_mul(price)
        .ok_or(SimError::Overflow("total fee"))?;
    Ok(FeeQuote {
        gas_used,
        gas_limit: tx.gas_limit,
        base_fee_per_gas: config.base_fee_per_gas,
        priority_fee_per_gas: tx.priority_fee_per_gas,
        total_fee,
    })
}

/// Apply one transaction to a state.
///
/// Free function so that a block can be applied to a *copy* of the state
/// (atomicity) with exactly the same rules as a standalone application.
fn apply_tx_to_state(
    state: &mut SimState,
    tx: &Transaction,
    proposer: &[u8; 32],
    config: &SimConfig,
) -> Result<TxOutcome, SimError> {
    // 1. Fee model (identical to `preview_fee`).
    let quote = fee_for(tx, config)?;
    let gas_used = quote.gas_used;
    let fee = quote.total_fee;

    // 2. Signature.
    if !verify_tx_signature(tx) {
        return Err(SimError::InvalidSignature(tx.from));
    }

    // 3. Sender must exist.
    let sender = match state.accounts.get(&tx.from) {
        Some(account) => *account,
        None => return Err(SimError::UnknownAccount(tx.from)),
    };

    // 4. Anti-replay nonce.
    if sender.nonce != tx.nonce {
        return Err(SimError::BadNonce {
            address: tx.from,
            expected: sender.nonce,
            got: tx.nonce,
        });
    }

    // 5. Balance.
    let total_cost = tx
        .amount
        .checked_add(fee)
        .ok_or(SimError::Overflow("transaction cost"))?;
    if sender.balance < total_cost {
        return Err(SimError::InsufficientBalance {
            address: tx.from,
            available: sender.balance,
            required: total_cost,
        });
    }

    // 6. Apply: debit the sender (value + fee), credit the recipient (value)
    //    and the proposer (fee).
    {
        let account = state
            .accounts
            .get_mut(&tx.from)
            .ok_or(SimError::UnknownAccount(tx.from))?;
        account.balance = account
            .balance
            .checked_sub(total_cost)
            .ok_or(SimError::Overflow("sender balance"))?;
        account.nonce = account
            .nonce
            .checked_add(1)
            .ok_or(SimError::Overflow("sender nonce"))?;
    }
    {
        let account = state.accounts.entry(tx.to).or_default();
        account.balance = account
            .balance
            .checked_add(tx.amount)
            .ok_or(SimError::Overflow("recipient balance"))?;
    }
    {
        let account = state.accounts.entry(*proposer).or_default();
        account.balance = account
            .balance
            .checked_add(fee)
            .ok_or(SimError::Overflow("proposer balance"))?;
    }

    Ok(TxOutcome {
        tx_hash: tx.compute_tx_hash(),
        from: tx.from,
        to: tx.to,
        amount: tx.amount,
        gas_used,
        fee_charged: fee,
    })
}

/// Verify the Ed25519 signature of a transaction.
///
/// The simulator verifies the raw signature over the transaction's signing
/// message. It deliberately does **not** call `Transaction::verify_signature`,
/// which also inspects the process-wide post-quantum / EVM registries: a
/// devnet must be hermetic, and the chain's registry lookups depend on global
/// state that is out of scope here.
fn verify_tx_signature(tx: &Transaction) -> bool {
    if tx.signature.len() < 64 {
        return false;
    }
    // A transaction with an explicit priority bid carries a trailing envelope
    // after the 64-byte signature; the envelope is not part of the signature.
    let Ok(signature) = Signature::from_slice(&tx.signature[..64]) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&tx.from) else {
        return false;
    };
    verifying_key
        .verify(&tx.signing_message(), &signature)
        .is_ok()
}

/// Canonical hash of a simulator block.
fn compute_block_hash(
    proposer: &[u8; 32],
    height: u64,
    time_ms: u64,
    prev_root: &[u8; 32],
    state_root: &[u8; 32],
    txs: &[Transaction],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SIM_BLOCK_DOMAIN);
    hasher.update(proposer);
    hasher.update(&height.to_be_bytes());
    hasher.update(&time_ms.to_be_bytes());
    hasher.update(prev_root);
    hasher.update(state_root);
    hasher.update(&(txs.len() as u64).to_be_bytes());
    for tx in txs {
        hasher.update(&tx.compute_tx_hash());
    }
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Transaction log
// ---------------------------------------------------------------------------

/// Configuration stored in the log header.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogConfig {
    /// Logical block interval in milliseconds.
    pub block_time_ms: u64,
    /// Logical genesis timestamp in milliseconds.
    pub start_time_ms: u64,
    /// Genesis balance of every account (nano-STELL).
    pub genesis_balance: u64,
    /// Stake bonded by every validator (nano-STELL).
    pub validator_stake: u64,
    /// Block reward minted to the proposer (nano-STELL).
    pub block_reward: u64,
    /// Flat base fee per gas unit (nano-STELL).
    pub base_fee_per_gas: u64,
    /// Intrinsic gas charged per transaction.
    pub intrinsic_gas: u64,
    /// Transactions per block of the built-in workload.
    pub txs_per_block: u64,
}

impl From<&SimConfig> for LogConfig {
    fn from(config: &SimConfig) -> Self {
        Self {
            block_time_ms: config.block_time_ms,
            start_time_ms: config.start_time_ms,
            genesis_balance: config.genesis_balance,
            validator_stake: config.validator_stake,
            block_reward: config.block_reward,
            base_fee_per_gas: config.base_fee_per_gas,
            intrinsic_gas: config.intrinsic_gas,
            txs_per_block: config.txs_per_block,
        }
    }
}

impl LogConfig {
    /// Rebuild a full simulator configuration.
    pub fn to_sim_config(&self, chain_id: u64) -> SimConfig {
        SimConfig {
            chain_id,
            block_time_ms: self.block_time_ms,
            start_time_ms: self.start_time_ms,
            genesis_balance: self.genesis_balance,
            validator_stake: self.validator_stake,
            block_reward: self.block_reward,
            base_fee_per_gas: self.base_fee_per_gas,
            intrinsic_gas: self.intrinsic_gas,
            txs_per_block: self.txs_per_block,
        }
    }
}

/// One validator entry of the log header.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogValidator {
    /// Validator address (hex).
    pub address: String,
    /// Bonded stake (nano-STELL).
    pub stake: u64,
}

/// The header record of a transaction log.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogHeader {
    /// Format version.
    pub v: u32,
    /// Chain id of the devnet.
    pub chain_id: u64,
    /// The seed the genesis was derived from (hex).
    pub seed: String,
    /// Number of validator accounts.
    pub accounts: u32,
    /// Simulator configuration.
    pub config: LogConfig,
    /// State root of the genesis state (hex).
    pub genesis_root: String,
    /// The genesis validator set.
    pub validators: Vec<LogValidator>,
}

/// One block record of a transaction log.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogBlock {
    /// Format version.
    pub v: u32,
    /// Block height (1-based).
    pub height: u64,
    /// Logical timestamp in milliseconds.
    pub time_ms: u64,
    /// Proposer address (hex).
    pub proposer: String,
    /// State root before the block (hex).
    pub prev_root: String,
    /// State root after the block (hex).
    pub state_root: String,
    /// Block hash (hex).
    pub block_hash: String,
    /// Total gas of the block.
    pub gas_used: u64,
    /// Total fees of the block.
    pub fees: u64,
    /// The block's transactions, each one bincode-encoded and hex-encoded.
    pub txs: Vec<String>,
}

/// A versioned, line-oriented transaction log.
///
/// The format is JSON lines: the first line is the header, every following
/// line is one block. Each block carries the transaction bytes and the state
/// root the block is expected to produce, so a replay can be verified
/// byte-for-byte.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SimLog {
    /// Header record.
    pub header: LogHeader,
    /// Block records, in height order.
    pub blocks: Vec<LogBlock>,
}

/// The result of replaying a transaction log.
#[derive(Clone, Debug)]
pub struct ReplayReport {
    /// Number of blocks replayed.
    pub blocks: u64,
    /// Number of transactions replayed.
    pub transactions: u64,
    /// Total gas replayed.
    pub total_gas: u64,
    /// Total fees replayed.
    pub total_fees: u64,
    /// State root of the genesis state.
    pub genesis_root: [u8; 32],
    /// State root after the last replayed block.
    pub final_root: [u8; 32],
    /// The replayed simulator (kept for further inspection).
    pub simulator: ChainSimulator,
}

impl SimLog {
    /// Build a log out of a simulator's recorded blocks.
    pub fn from_simulator(sim: &ChainSimulator) -> Result<Self, SimError> {
        let header = LogHeader {
            v: SIM_LOG_VERSION,
            chain_id: sim.config.chain_id,
            seed: hex::encode(&sim.seed),
            accounts: sim.validators.len() as u32,
            config: LogConfig::from(&sim.config),
            genesis_root: hex::encode(
                sim.blocks
                    .first()
                    .map(|b| b.prev_root)
                    .unwrap_or_else(|| sim.state_root()),
            ),
            validators: sim
                .validators
                .iter()
                .map(|v| LogValidator {
                    address: hex::encode(v.address),
                    stake: v.stake,
                })
                .collect(),
        };
        let mut blocks = Vec::with_capacity(sim.blocks.len());
        for block in &sim.blocks {
            let mut txs = Vec::with_capacity(block.txs.len());
            for tx in &block.txs {
                let bytes = bincode::serialize(tx)
                    .map_err(|e| SimError::LogCorrupt(format!("tx encode: {e}")))?;
                txs.push(hex::encode(bytes));
            }
            blocks.push(LogBlock {
                v: SIM_LOG_VERSION,
                height: block.height,
                time_ms: block.time_ms,
                proposer: hex::encode(block.proposer),
                prev_root: hex::encode(block.prev_root),
                state_root: hex::encode(block.state_root),
                block_hash: hex::encode(block.block_hash),
                gas_used: block.gas_used,
                fees: block.fees,
                txs,
            });
        }
        Ok(Self { header, blocks })
    }

    /// Serialise the log as JSON lines.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let header = serde_json::json!({
            "kind": "header",
            "v": self.header.v,
            "chain_id": self.header.chain_id,
            "seed": self.header.seed,
            "accounts": self.header.accounts,
            "config": self.header.config,
            "genesis_root": self.header.genesis_root,
            "validators": self.header.validators,
        });
        out.extend_from_slice(header.to_string().as_bytes());
        out.push(b'\n');
        for block in &self.blocks {
            let record = serde_json::json!({
                "kind": "block",
                "v": block.v,
                "height": block.height,
                "time_ms": block.time_ms,
                "proposer": block.proposer,
                "prev_root": block.prev_root,
                "state_root": block.state_root,
                "block_hash": block.block_hash,
                "gas_used": block.gas_used,
                "fees": block.fees,
                "txs": block.txs,
            });
            out.extend_from_slice(record.to_string().as_bytes());
            out.push(b'\n');
        }
        out
    }

    /// Parse a JSON-lines transaction log.
    pub fn parse(bytes: &[u8]) -> Result<Self, SimError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| SimError::LogCorrupt(format!("not valid UTF-8: {e}")))?;

        let mut header: Option<LogHeader> = None;
        let mut blocks: Vec<LogBlock> = Vec::new();

        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let value: serde_json::Value = serde_json::from_str(line)
                .map_err(|e| SimError::LogCorrupt(format!("line {}: {e}", index + 1)))?;
            let kind = value
                .get("kind")
                .and_then(|k| k.as_str())
                .ok_or_else(|| SimError::LogCorrupt(format!("line {}: missing kind", index + 1)))?
                .to_string();
            let version = value.get("v").and_then(|v| v.as_u64()).ok_or_else(|| {
                SimError::LogCorrupt(format!("line {}: missing version", index + 1))
            })? as u32;
            if version != SIM_LOG_VERSION {
                return Err(SimError::LogVersion {
                    found: version,
                    expected: SIM_LOG_VERSION,
                });
            }
            match kind.as_str() {
                "header" => {
                    if header.is_some() {
                        return Err(SimError::LogCorrupt(
                            "more than one header record".to_string(),
                        ));
                    }
                    let parsed: LogHeader = serde_json::from_value(value)
                        .map_err(|e| SimError::LogCorrupt(format!("header: {e}")))?;
                    header = Some(parsed);
                }
                "block" => {
                    let parsed: LogBlock = serde_json::from_value(value)
                        .map_err(|e| SimError::LogCorrupt(format!("line {}: {e}", index + 1)))?;
                    blocks.push(parsed);
                }
                other => {
                    return Err(SimError::LogCorrupt(format!(
                        "line {}: unknown record kind '{other}'",
                        index + 1
                    )))
                }
            }
        }

        let header = header.ok_or_else(|| SimError::LogCorrupt("missing header record".into()))?;
        Ok(Self { header, blocks })
    }

    /// Replay the log and verify every recorded state root.
    ///
    /// The replay rebuilds the genesis from the seed stored in the header,
    /// re-applies every block and compares the resulting state root with the
    /// recorded one. A mismatch is an error — the caller cannot accidentally
    /// treat a diverging chain as valid.
    pub fn replay(&self) -> Result<ReplayReport, SimError> {
        let seed = hex::decode(&self.header.seed)
            .map_err(|e| SimError::LogCorrupt(format!("seed: {e}")))?;
        let config = self.header.config.to_sim_config(self.header.chain_id);
        let mut simulator = ChainSimulator::genesis(&seed, self.header.accounts as usize, config)?;

        let genesis_root = simulator.state_root();
        let expected_genesis = hex::decode(&self.header.genesis_root)
            .map_err(|e| SimError::LogCorrupt(format!("genesis_root: {e}")))?;
        let expected_genesis: [u8; 32] = expected_genesis
            .try_into()
            .map_err(|_| SimError::LogCorrupt("genesis_root: wrong length".to_string()))?;
        if genesis_root != expected_genesis {
            return Err(SimError::ReplayMismatch {
                height: 0,
                expected: expected_genesis,
                actual: genesis_root,
            });
        }

        let mut transactions = 0u64;
        let mut total_gas = 0u64;
        let mut total_fees = 0u64;

        for block in &self.blocks {
            let expected_height = simulator.height() + 1;
            if block.height != expected_height {
                return Err(SimError::HeightMismatch {
                    expected: expected_height,
                    got: block.height,
                });
            }
            let proposer = hex::decode(&block.proposer)
                .map_err(|e| SimError::LogCorrupt(format!("proposer: {e}")))?;
            let proposer: [u8; 32] = proposer
                .try_into()
                .map_err(|_| SimError::LogCorrupt("proposer: wrong length".to_string()))?;
            let proposer_index = simulator
                .validator_index(&proposer)
                .ok_or(SimError::UnknownValidator(proposer))?;

            let mut txs = Vec::with_capacity(block.txs.len());
            for raw in &block.txs {
                let bytes =
                    hex::decode(raw).map_err(|e| SimError::LogCorrupt(format!("tx bytes: {e}")))?;
                let tx: Transaction = bincode::deserialize(&bytes)
                    .map_err(|e| SimError::LogCorrupt(format!("tx decode: {e}")))?;
                txs.push(tx);
            }

            let produced = simulator.produce_block(proposer_index, txs)?;
            transactions += produced.txs.len() as u64;
            total_gas += produced.gas_used;
            total_fees += produced.fees;

            let expected_root = hex::decode(&block.state_root)
                .map_err(|e| SimError::LogCorrupt(format!("state_root: {e}")))?;
            let expected_root: [u8; 32] = expected_root
                .try_into()
                .map_err(|_| SimError::LogCorrupt("state_root: wrong length".to_string()))?;
            if produced.state_root != expected_root {
                return Err(SimError::ReplayMismatch {
                    height: block.height,
                    expected: expected_root,
                    actual: produced.state_root,
                });
            }
            let expected_hash = hex::decode(&block.block_hash)
                .map_err(|e| SimError::LogCorrupt(format!("block_hash: {e}")))?;
            let expected_hash: [u8; 32] = expected_hash
                .try_into()
                .map_err(|_| SimError::LogCorrupt("block_hash: wrong length".to_string()))?;
            if produced.block_hash != expected_hash {
                return Err(SimError::LogCorrupt(format!(
                    "block hash mismatch at height {}",
                    block.height
                )));
            }
        }

        Ok(ReplayReport {
            blocks: self.blocks.len() as u64,
            transactions,
            total_gas,
            total_fees,
            genesis_root,
            final_root: simulator.state_root(),
            simulator,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> Vec<u8> {
        hex::decode("00ff10").unwrap()
    }

    fn simulator() -> ChainSimulator {
        let config = SimConfig {
            txs_per_block: 3,
            ..Default::default()
        };
        ChainSimulator::genesis(&seed(), 4, config).unwrap()
    }

    #[test]
    fn genesis_is_deterministic() {
        let a = ChainSimulator::genesis(&seed(), 4, SimConfig::default()).unwrap();
        let b = ChainSimulator::genesis(&seed(), 4, SimConfig::default()).unwrap();
        assert_eq!(a.state_root(), b.state_root());
        assert_eq!(a.validators().len(), 4);

        let c = ChainSimulator::genesis(b"other-seed", 4, SimConfig::default()).unwrap();
        assert_ne!(a.state_root(), c.state_root());
    }

    #[test]
    fn pq_keygen_is_deterministic_for_the_same_seed() {
        let a = derive_falcon_keypair(&seed(), b"validator", 1);
        let b = derive_falcon_keypair(&seed(), b"validator", 1);
        assert_eq!(a.public_key(), b.public_key());

        let other_seed = derive_falcon_keypair(b"other-seed", b"validator", 1);
        assert_ne!(a.public_key(), other_seed.public_key());

        let other_role = derive_falcon_keypair(&seed(), b"faucet", 1);
        assert_ne!(a.public_key(), other_role.public_key());

        let other_index = derive_falcon_keypair(&seed(), b"validator", 2);
        assert_ne!(a.public_key(), other_index.public_key());
    }

    #[test]
    fn pq_seed_is_domain_separated_from_the_ed25519_key() {
        let ed = derive_keypair(&seed(), b"validator", 1);
        let pq = derive_pq_seed(&seed(), b"validator", 1);
        assert_ne!(ed.to_bytes(), pq);
    }

    #[test]
    fn snapshot_restore_preserves_state_root() {
        let mut sim = simulator();
        sim.run_blocks(5).unwrap();
        let snapshot = sim.snapshot();
        let root_at_snapshot = sim.state_root();

        // Keep going: the state must diverge from the snapshot.
        sim.run_blocks(5).unwrap();
        assert_ne!(sim.state_root(), root_at_snapshot);

        // Restoring must land exactly on the snapshot.
        sim.restore(&snapshot).unwrap();
        assert_eq!(sim.state_root(), root_at_snapshot);

        // ... and the simulation continues identically from there.
        let mut reference = simulator();
        reference.restore(&snapshot).unwrap();
        reference.run_blocks(5).unwrap();
        sim.run_blocks(5).unwrap();
        assert_eq!(sim.state_root(), reference.state_root());
    }

    #[test]
    fn snapshot_roundtrips_through_bytes() {
        let mut sim = simulator();
        sim.run_blocks(3).unwrap();
        let snapshot = sim.snapshot();
        let restored = StateSnapshot::from_bytes(snapshot.as_bytes().to_vec());
        let mut other = simulator();
        other.restore(&restored).unwrap();
        assert_eq!(other.state_root(), sim.state_root());
    }

    #[test]
    fn replay_reproduces_state_root() {
        let mut sim = simulator();
        sim.run_blocks(10).unwrap();
        let root = sim.state_root();

        let log = sim.log().unwrap();
        let bytes = log.to_bytes();
        let parsed = SimLog::parse(&bytes).unwrap();
        let report = parsed.replay().unwrap();
        assert_eq!(report.final_root, root);
        assert_eq!(report.transactions, 30);
        assert_eq!(report.blocks, 10);
        assert_eq!(report.genesis_root, sim.blocks[0].prev_root);
    }

    #[test]
    fn replay_detects_a_tampered_state_root() {
        let mut sim = simulator();
        sim.run_blocks(3).unwrap();
        let mut log = sim.log().unwrap();
        log.blocks[1].state_root = hex::encode([0xabu8; 32]);
        let err = log.replay().unwrap_err();
        assert!(matches!(err, SimError::ReplayMismatch { height: 2, .. }));
    }

    #[test]
    fn replay_detects_a_tampered_transaction() {
        let mut sim = simulator();
        sim.run_blocks(3).unwrap();
        let mut log = sim.log().unwrap();
        // Flip a byte inside the first transaction of the second block.
        let mut raw = hex::decode(&log.blocks[1].txs[0]).unwrap();
        raw[40] ^= 0xff;
        log.blocks[1].txs[0] = hex::encode(raw);
        let err = log.replay().unwrap_err();
        assert!(
            matches!(
                err,
                SimError::LogCorrupt(_)
                    | SimError::InvalidSignature(_)
                    | SimError::ReplayMismatch { .. }
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn fee_preview_matches_the_fee_charged() {
        let mut sim = simulator();
        let proposer = sim.validators()[0].address;
        let sender = sim.validators()[1].address;
        let recipient = sim.validators()[2].address;
        let key = derive_keypair(&seed(), b"validator", 1);

        let tx = Transaction::sign_with_priority(
            &key,
            recipient,
            1_000,
            sim.config().intrinsic_gas,
            sim.nonce(&sender),
            0,
            0,
            2,
        );

        // The preview must not touch the state.
        let root_before = sim.state_root();
        let sender_before = sim.balance(&sender);
        let proposer_before = sim.balance(&proposer);
        let recipient_before = sim.balance(&recipient);
        let quote = sim.preview_fee(&tx).unwrap();
        assert_eq!(sim.state_root(), root_before);
        assert_eq!(sim.balance(&sender), sender_before);
        assert_eq!(sim.balance(&proposer), proposer_before);

        // The charged fee equals the preview, exactly.
        let outcome = sim.apply_transaction(&proposer, &tx).unwrap();
        assert_eq!(outcome.fee_charged, quote.total_fee);
        assert_eq!(outcome.gas_used, quote.gas_used);

        // The sender paid value + fee, the proposer received the fee, the
        // recipient received the value.
        assert_eq!(
            sim.balance(&sender),
            sender_before - tx.amount - quote.total_fee
        );
        assert_eq!(sim.balance(&proposer), proposer_before + quote.total_fee);
        assert_eq!(sim.balance(&recipient), recipient_before + tx.amount);
    }

    #[test]
    fn fee_preview_rejects_a_low_gas_limit() {
        let sim = simulator();
        let key = derive_keypair(&seed(), b"validator", 0);
        let tx = Transaction::sign(&key, sim.validators()[1].address, 1, 1, 0, 0, 0);
        assert!(matches!(
            sim.preview_fee(&tx),
            Err(SimError::GasLimitTooLow { .. })
        ));
    }

    #[test]
    fn a_forged_signature_is_rejected() {
        let mut sim = simulator();
        let proposer = sim.validators()[0].address;
        let mut tx = Transaction::sign(
            &derive_keypair(&seed(), b"validator", 1),
            sim.validators()[2].address,
            1,
            sim.config().intrinsic_gas,
            0,
            0,
            0,
        );
        tx.amount = 999_999;
        assert!(matches!(
            sim.apply_transaction(&proposer, &tx),
            Err(SimError::InvalidSignature(_))
        ));
    }

    #[test]
    fn a_block_is_atomic() {
        let mut sim = simulator();
        let sender = sim.validators()[1].address;
        let recipient = sim.validators()[2].address;
        let key = derive_keypair(&seed(), b"validator", 1);
        let good = Transaction::sign(&key, recipient, 10, sim.config().intrinsic_gas, 0, 0, 0);
        // Second transaction has a stale nonce: the whole block must fail and
        // the state must stay untouched.
        let bad = Transaction::sign(&key, recipient, 10, sim.config().intrinsic_gas, 7, 0, 0);
        let root_before = sim.state_root();
        let err = sim.produce_block(0, vec![good.clone(), bad]).unwrap_err();
        assert!(matches!(err, SimError::BadNonce { .. }));
        assert_eq!(sim.state_root(), root_before);
        assert_eq!(
            sim.balance(&sender),
            sim.config().genesis_balance - sim.config().validator_stake
        );
    }

    #[test]
    fn log_format_is_versioned_and_strict() {
        let mut sim = simulator();
        sim.run_blocks(2).unwrap();
        let log = sim.log().unwrap();
        let text = String::from_utf8(log.to_bytes()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("\"kind\":\"header\""));
        assert!(lines[0].contains("\"v\":1"));
        assert!(lines[1].contains("\"kind\":\"block\""));

        // An unknown version is refused.
        let broken = text.replace("\"v\":1", "\"v\":9");
        assert!(matches!(
            SimLog::parse(broken.as_bytes()),
            Err(SimError::LogVersion {
                found: 9,
                expected: 1
            })
        ));

        // A missing header is refused.
        let headerless = lines[1..].join("\n");
        assert!(matches!(
            SimLog::parse(headerless.as_bytes()),
            Err(SimError::LogCorrupt(_))
        ));
    }

    #[test]
    fn devnet_run_is_reproducible() {
        let mut a = simulator();
        let mut b = simulator();
        let summary_a = a.run_blocks(7).unwrap();
        let summary_b = b.run_blocks(7).unwrap();
        assert_eq!(summary_a.state_root, summary_b.state_root);
        assert_eq!(summary_a.transactions, summary_b.transactions);
        assert_eq!(summary_a.transactions, 21);
    }
}
