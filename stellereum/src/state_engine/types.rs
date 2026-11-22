use super::{AccountState, MAX_SMALL_RECORD_DECODE_BYTES};
use crate::cell::PatriciaTrie;
use crate::token::TokenRegistry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Asynchronous message between actors
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorMessage {
    pub msg_id: [u8; 32],
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub value: u64, // nano-STELL attached to message
    pub body: Vec<u8>,
    pub bounce: bool,  // if recipient fails or does not exist, bounce funds back
    pub bounced: bool, // indicates whether this message is a bounced response
}

impl ActorMessage {
    pub fn new(
        sender: [u8; 32],
        recipient: [u8; 32],
        value: u64,
        body: Vec<u8>,
        bounce: bool,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(sender);
        hasher.update(recipient);
        hasher.update(value.to_be_bytes());
        hasher.update(&body);
        let msg_id: [u8; 32] = hasher.finalize().into();

        Self {
            msg_id,
            sender,
            recipient,
            value,
            body,
            bounce,
            bounced: false,
        }
    }
}

/// The encoded `body` of an actor message: the program a delivered message
/// runs, plus the fuel the sender prepaid for it.
///
/// `ActorMessage::body` is an opaque `Vec<u8>` (the struct is bincode'd into
/// node snapshots, so its layout must not grow), which is why the two fields
/// the mailbox needs are packed into it with bincode here rather than added
/// to `ActorMessage`. Round-trips are exact: the bytes are produced and
/// consumed by this same node, never by a counterparty.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActorSendBody {
    /// Program executed at delivery, with the recipient as the acting account.
    pub program: Vec<crate::svm::OpCode>,
    /// Fuel prepaid by the sender; also the delivery VM's gas limit.
    pub gas_budget: u64,
}

/// The block-clock inputs a delivered actor body's VM run needs: the block
/// timestamp (never local wall time) plus the two governed staking parameter
/// floors a `VmContext` carries (unreachable for a body today - staking is
/// not wired into the delivery context - but non-optional fields).
pub(super) struct DeliveryCtx {
    pub(super) timestamp: u64,
    pub(super) min_validator_bond: u64,
    pub(super) default_commission_bps: u64,
}

/// Pack a send into the bytes `ActorMessage::body` carries.
pub(super) fn encode_actor_body(program: &[crate::svm::OpCode], gas_budget: u64) -> Vec<u8> {
    bincode::serialize(&ActorSendBody {
        program: program.to_vec(),
        gas_budget,
    })
    // Serialization of this struct cannot fail (fixed ints plus a Vec of
    // unit-like enums), exactly like the transaction envelope's own bincode.
    .expect("actor body serializes")
}

/// Bounded `bincode` deserializer matching `bincode::serialize` wire format
/// (`fixint` encoding + trailing bytes allowed) while enforcing `limit` against
/// crafted container length prefixes in untrusted snapshot/sync blobs.
pub(super) fn bincode_deserialize_limited<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    limit: u64,
) -> Result<T, bincode::Error> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(limit)
        .deserialize(bytes)
}

/// Bounded `bincode` deserializer that also requires the input to be consumed
/// EXACTLY (no trailing bytes).
///
/// Snapshots have a declared shape: a blob whose byte length does not match
/// what the declared struct decodes to is corrupt and MUST fail, never be
/// silently truncated to a shorter struct (audit F10). `bincode`'s
/// `DefaultOptions` already rejects trailing bytes; this wrapper states the
/// requirement at the call site and keeps the same `fixint` wire format and
/// decode limit as [`bincode_deserialize_limited`].
pub(super) fn bincode_deserialize_exact<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    limit: u64,
) -> Result<T, bincode::Error> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(limit)
        .deserialize(bytes)
}

/// Unpack the bytes a queued message carries; anything else is a delivery
/// failure for that message (it bounces - it is never half-delivered).
pub(super) fn decode_actor_body(bytes: &[u8]) -> Result<ActorSendBody, String> {
    bincode_deserialize_limited(bytes, MAX_SMALL_RECORD_DECODE_BYTES)
        .map_err(|e| format!("actor body does not decode: {e}"))
}

/// Pre-state of every account one actor-message delivery touched, taken the
/// first time it is touched and replayed in reverse if the delivery fails.
///
/// The design's per-message snapshot (recipient + sender) generalized to a
/// lazy touched-set: a body can also move value to third parties through
/// `Transfer` or a nested send, and THOSE must roll back with the message too
/// - "failed body leaves no partial effect" is only true if the snapshot
///   covers everything the body reached. `None` = the account did not exist
///   before (a delivery may create one by transferring to it; undo removes it).
#[derive(Default)]
pub(super) struct MessageUndo {
    prev: HashMap<[u8; 32], Option<AccountState>>,
}

impl MessageUndo {
    /// Record `addr`'s pre-state, once, BEFORE it is mutated. Repeated calls
    /// are no-ops, so the FIRST pre-state - the state before this message's
    /// delivery began - is what an undo restores, which is exactly
    /// "walk the undo newest-first back to the original".
    pub(super) fn note(&mut self, map: &HashMap<[u8; 32], AccountState>, addr: [u8; 32]) {
        self.prev
            .entry(addr)
            .or_insert_with(|| map.get(&addr).cloned());
    }

    /// Put every touched account back where it was before this message.
    pub(super) fn rollback(&self, map: &mut HashMap<[u8; 32], AccountState>) {
        for (addr, prev) in &self.prev {
            match prev {
                Some(acc) => {
                    map.insert(*addr, acc.clone());
                }
                None => {
                    map.remove(addr);
                }
            }
        }
    }
}

/// Record `addr`'s pre-state once, before it is mutated - the settlement-side
/// twin of [`MessageUndo::note`], kept as a free function so the borrow of
/// `map` ends with the call instead of spanning the mutations that follow.
/// An address absent from the map records nothing (settlement never creates
/// accounts), which is exactly its rollback state.
pub(super) fn note_account_before(
    map: &HashMap<[u8; 32], AccountState>,
    snapshot: &mut Vec<([u8; 32], AccountState)>,
    noted: &mut HashSet<[u8; 32]>,
    addr: [u8; 32],
) {
    if noted.insert(addr) {
        if let Some(acc) = map.get(&addr) {
            snapshot.push((addr, acc.clone()));
        }
    }
}

/// Escrow record locking funds for an active resting limit order in the CLOB.
///
/// Exactly one of the three locked fields is non-zero for a well-formed record,
/// because an order is one side of one pair:
///
/// * a resting SELL locks base STELL (`locked_base_stell`), whichever path
///   placed it;
/// * a resting BUY placed through `place_order_settled` locks its quote in
///   wUSDT (`locked_quote_wusdt`, burned at lock and minted back on release);
/// * a resting BUY placed through the SVM's `SysCallPlaceOrder` locks its
///   quote in native nano-STELL (`locked_quote_native`, debited at lock and
///   credited back on release) - the VM prices its `order_cost` in the
///   sender's native balance, so that is the asset the lock has to be in.
///
/// The settlement releases whichever asset was locked, to the counterparty,
/// so a record can never pay out in an asset nobody deposited.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowRecord {
    pub trader: [u8; 32],
    pub locked_base_stell: u64,
    pub locked_quote_wusdt: u64,
    /// Quote locked in native units for a BUY placed through the SVM path
    /// (`order_cost` = price * amount / 1_000_000, in nano-STELL).
    pub locked_quote_native: u64,
}

/// Which quote convention a CLOB placement settles under.
///
/// The two live entry points price the quote leg differently, and the
/// settlement core honours whichever one is calling it:
///
/// * `Wusdt` - `place_order_settled`: quote is wUSDT micro-units
///   (`price * amount / 1e9`), locked by burning the buyer's wUSDT.
/// * `NativeSvm` - the `SysCallPlaceOrder` syscall: quote is native
///   nano-STELL (`order_cost` = `price * amount / 1e6`), locked by debiting
///   the buyer's account. The VM only knows the sender's native balance, so
///   that is the asset its affordability check prices.
///
/// A maker's OWN escrow overrides the convention: whoever locked wUSDT pays
/// out wUSDT, whoever locked native pays native - a record can only ever
/// release the asset that was deposited into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ClobQuoteMode {
    Wusdt,
    NativeSvm,
}

impl ClobQuoteMode {
    /// The quote value of `base_nano` nano-STELL at `price_micro` under this
    /// convention. The two conventions are NOT convertible into each other
    /// here: each one prices the asset its own caller settles in, and a
    /// settlement only ever debits and credits the SAME convention, so value
    /// is conserved inside a trade.
    pub(super) fn quote(self, price_micro: u64, base_nano: u64) -> u64 {
        match self {
            // wUSDT micro-units: (USD price * STELL) / 1e9.
            ClobQuoteMode::Wusdt => {
                let prod = (price_micro as u128) * (base_nano as u128);
                (prod / 1_000_000_000u128).min(u64::MAX as u128) as u64
            }
            // Native nano-STELL, calculated in u128 before dividing by 1,000,000
            // to prevent u64::MAX saturation on normal token trades.
            ClobQuoteMode::NativeSvm => {
                let prod = (price_micro as u128) * (base_nano as u128);
                (prod / 1_000_000u128).min(u64::MAX as u128) as u64
            }
        }
    }
}

/// One native STELL movement a settlement has decided on.
///
/// Applied under the accounts write lock with an undo log, BEFORE the staged
/// token and escrow state is committed, so a movement that cannot be funded
/// aborts the whole settlement with nothing changed anywhere.
pub(super) enum NativeMove {
    Debit([u8; 32], u64),
    Credit([u8; 32], u64),
}

/// What one block transition did, as reported by
/// [`InMemoryStateEngine::apply_block_transition`].
///
/// The live consensus path and the reorg path record these same numbers into
/// their own bookkeeping (`ValidatorRuntime::applied_txs` /
/// `applied_statuses`, `ChainState::applied_txs` / `applied_statuses`), so the
/// two can be compared block by block - which is exactly what the differential
/// test does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockTransitionOutcome {
    /// Transactions that were applied (admitted AND committed).
    pub applied: usize,
    /// Transactions that were rejected. `applied + failed == status.len()`.
    pub failed: usize,
    /// Fees actually collected from applied transactions and credited to the
    /// proposer in this transition.
    pub fees_collected: u64,
    /// Per-transaction success flags, in block order - the receipts vector.
    pub status: Vec<bool>,
    /// Per-transaction fee actually charged, in block order (parallel to
    /// `status`; the F-01 failure fee — floor or 0 — for failed transactions,
    /// never a fee that was not debited) - the receipts' `fee_charged`.
    pub tx_fees: Vec<u64>,
    /// Nano-STELL burned by slashing in this block's transition: the
    /// downtime slash of this block's certificate plus the equivocation
    /// slash of its block-carried evidence.
    pub slashed: u64,
    /// Per-transaction emitted contract events, in block order.
    pub events: Vec<Vec<crate::contract::ContractEvent>>,
}

/// Outcome of one [`InMemoryStateEngine::apply_gov_ops`] scan: the
/// block-carried governance verdict for a decided block.
///
/// Module scope (not an associated type): Rust forbids item definitions
/// inside `impl` blocks, and the scan returns this by value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GovOpsOutcome {
    /// Proposals opened by this block.
    pub proposed: usize,
    /// Votes recorded by this block (including idempotent same-choice
    /// replays, which the direct path answers `Ok` without moving the
    /// tally — see `vote_same_choice_replay_is_idempotent`).
    pub voted: usize,
    /// Gov ops refused (inactive gate, failed step-1 tx, height-pin
    /// mismatch, duplicate id, closed window, double vote, zero weight).
    pub refused: usize,
}

/// Namespaced trie key for a token balance: sha256("STS_BAL" || token_id || account)
/// This commits token balances into the same state root as native STELL balances,
/// enabling SPV Merkle proofs for token holdings.
pub fn token_balance_key(token_id: &[u8; 32], account: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"STS_BAL");
    hasher.update(token_id);
    hasher.update(account);
    hasher.finalize().into()
}

/// Namespaced trie key for a token's total supply: sha256("STS_SUPPLY" || token_id)
pub fn token_supply_key(token_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"STS_SUPPLY");
    hasher.update(token_id);
    hasher.finalize().into()
}

/// Namespaced trie key committing a contract's code hash: sha256("STELL_CONTRACT_CODE" || addr)
pub fn contract_key(address: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"STELL_CONTRACT_CODE");
    hasher.update(address);
    hasher.finalize().into()
}

/// Namespaced trie key committing a contract's ABI manifest:
/// sha256("STELL_CONTRACT_ABI" || addr). The manifest is stored next to the
/// code hash so a client can discover the typed interface of a contract from
/// the state root alone.
pub fn contract_abi_key(address: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"STELL_CONTRACT_ABI");
    hasher.update(address);
    hasher.finalize().into()
}

/// Namespaced trie key committing a contract's verified-source fingerprint
/// (P2-15): sha256("STELL_CONTRACT_SOURCE" || addr). Present only for
/// contracts whose creator registered a source via the signed
/// `stell_registerContractSource` action; absent = unverified.
pub fn contract_source_key(address: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"STELL_CONTRACT_SOURCE");
    hasher.update(address);
    hasher.finalize().into()
}

/// Namespaced trie key for a deposited HashPool commitment:
/// `sha256("STELL_HP_TRIE_COMMIT_V1" || commitment)`.
///
/// A NEW trie namespace (deliberately NOT `HP_COMMIT_DST`: that domain is
/// the note-commitment preimage inside `hashpool.rs`, while this one keys
/// the state-trie leaf). The leaf value is the 32-byte stealth address the
/// commitment was registered under.
pub fn hashpool_commitment_key(commitment: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"STELL_HP_TRIE_COMMIT_V1");
    hasher.update(commitment);
    hasher.finalize().into()
}

/// Namespaced trie key for a spent HashPool nullifier:
/// `sha256("STELL_HP_TRIE_NULL_V1" || nullifier)`.
///
/// A NEW trie namespace (deliberately NOT `HP_NULL_DST`, for the same reason
/// as above). The leaf is present with value `[1]` iff the nullifier is
/// spent; absent otherwise. Append-only: neither leaf is ever removed, so
/// two nodes that applied the same ops derive the same root.
pub fn hashpool_nullifier_key(nullifier: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"STELL_HP_TRIE_NULL_V1");
    hasher.update(nullifier);
    hasher.finalize().into()
}

/// Fail-closed refusal from a HashPool apply entry point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashPoolOpError {
    /// The gate is off on this instance: nothing was read, nothing was
    /// written. Loud refusal (never a silent skip) so a misrouted op on
    /// the live path fails closed instead of vanishing.
    Disabled,
    /// The gate is on and the pool itself refused the op (double-spend,
    /// unknown commitment, unbalanced batch, bad owner signature, ...).
    Pool(crate::hashpool::HpError),
}

impl std::fmt::Display for HashPoolOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashPoolOpError::Disabled => write!(f, "hashpool gate is off (default)"),
            HashPoolOpError::Pool(e) => write!(f, "hashpool refused: {e}"),
        }
    }
}

impl std::error::Error for HashPoolOpError {}

impl From<crate::hashpool::HpError> for HashPoolOpError {
    fn from(e: crate::hashpool::HpError) -> Self {
        HashPoolOpError::Pool(e)
    }
}

/// One note deposit carried by [`HashPoolBlockOps`]: the caller computed
/// `commitment = note_commit(chain, value, blinding, stealth)` and
/// `nullifier = note_nullifier(serial)` off-chain (same contract as
/// `HashPool::deposit`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashPoolDepositOp {
    /// Note commitment to register.
    pub commitment: [u8; 32],
    /// Stealth address the commitment is registered under (public).
    pub stealth: [u8; 32],
    /// Nullifier bound to the commitment at deposit.
    pub nullifier: [u8; 32],
}

/// One note spend carried by [`HashPoolBlockOps`]: reveals exactly
/// `(serial, value, blinding)` against the claimed `commitment` (same
/// contract as `HashPool::spend`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashPoolSpendOp {
    /// Claimed commitment (must recompute from the stored stealth).
    pub commitment: [u8; 32],
    /// Note serial (preimage of the bound nullifier).
    pub serial: [u8; 32],
    /// Note value.
    pub value: u64,
    /// Note blinding.
    pub blinding: [u8; 32],
}

/// Explicit HashPool sidecar for one block transition.
///
/// The wire is frozen so blocks carry no HashPool bytes; tests pass ops
/// here to [`InMemoryStateEngine::apply_block_transition_with_hashpool`].
/// Application order is deterministic: deposits (in order), then spends (in
/// order), then batches (in order, each verified before it applies). A
/// refused op is counted, never halting: the rest of the sidecar still
/// applies in order.
#[derive(Clone, Debug, Default)]
pub struct HashPoolBlockOps {
    /// Note deposits to register, in application order.
    pub deposits: Vec<HashPoolDepositOp>,
    /// Note spends to consume, in application order.
    pub spends: Vec<HashPoolSpendOp>,
    /// CoinJoin batches to verify (real Falcon-512) and apply, in order.
    pub batches: Vec<crate::hashpool::CoinJoinBatch>,
}

/// What one [`HashPoolBlockOps`] sidecar application did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HashPoolApplyOutcome {
    /// Deposits registered.
    pub deposits_applied: usize,
    /// Deposits refused (duplicate commitment, ...).
    pub deposits_refused: usize,
    /// Spends consumed.
    pub spends_applied: usize,
    /// Spends refused (double-spend, tampered opening, ...).
    pub spends_refused: usize,
    /// Batches verified and applied.
    pub batches_applied: usize,
    /// Batches refused (unbalanced, bad signature, ...).
    pub batches_refused: usize,
    /// True when the gate was off: every op skipped, state untouched.
    pub skipped_gate_off: bool,
}

/// Compute deterministic contract address following TON StateInit / BLAKE3 model:
/// BLAKE3("STELL_CONTRACT" || code_hash || salt)
pub fn compute_contract_address(code_hash: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"STELL_CONTRACT");
    hasher.update(code_hash);
    hasher.update(salt);
    *hasher.finalize().as_bytes()
}

/// Structured outcome of a contract deployment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployOutcome {
    pub contract_address: [u8; 32],
    pub contract_address_stl57: String,
    pub code_hash: [u8; 32],
}

/// Structured outcome of a contract call (Near receipt / TON observable outcome model).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCallOutcome {
    pub status: String,
    pub return_value: Option<i64>,
    pub gas_used: u64,
    pub events: Vec<crate::contract::ContractEvent>,
    pub error: Option<String>,
}

/// Write every deployed contract's code hash into the Patricia trie so contract
/// existence is part of the state root and SPV-provable.
///
/// A contract's ABI manifest is committed next to its code hash. So is the
/// verified-source fingerprint, when one is registered (absent = unverified:
/// the key is removed, never a placeholder).
pub(super) fn write_contract_trie_entries(
    trie: &mut PatriciaTrie,
    contracts: &crate::contract::ContractRegistry,
) {
    for addr in contracts.contracts.keys() {
        write_single_contract_trie_entry(trie, contracts, addr);
    }
}

/// Write only the specified contract addresses' code hash, ABI manifest, and
/// verified-source fingerprint into the Patricia trie.
pub(super) fn write_contract_trie_entries_for_addrs<'a>(
    trie: &mut PatriciaTrie,
    contracts: &crate::contract::ContractRegistry,
    addrs: impl IntoIterator<Item = &'a [u8; 32]>,
) {
    for addr in addrs {
        write_single_contract_trie_entry(trie, contracts, addr);
    }
}

fn write_single_contract_trie_entry(
    trie: &mut PatriciaTrie,
    contracts: &crate::contract::ContractRegistry,
    addr: &[u8; 32],
) {
    let Some(c) = contracts.contracts.get(addr) else {
        return;
    };
    trie.insert(&contract_key(addr), &c.code_hash);
    match &c.abi {
        Some(abi) => {
            trie.insert(&contract_abi_key(addr), abi.to_json().as_bytes());
        }
        None => {
            trie.remove(&contract_abi_key(addr));
        }
    }
    match &c.source_hash {
        Some(sh) => {
            trie.insert(&contract_source_key(addr), sh);
        }
        None => {
            trie.remove(&contract_source_key(addr));
        }
    }
}

/// Write every token balance + total supply into the Patricia trie.
/// Used on restore to keep the trie consistent with the token registry.
pub(super) fn write_token_trie_entries(trie: &mut PatriciaTrie, tokens: &TokenRegistry) {
    for (id, token) in &tokens.tokens {
        for (acct, bal) in &token.balances {
            let key = token_balance_key(id, acct);
            if *bal == 0 {
                trie.remove(&key);
            } else {
                trie.insert(&key, &bal.to_be_bytes());
            }
        }
        trie.insert(
            &token_supply_key(id),
            &token.metadata.total_supply.to_be_bytes(),
        );
    }
}

/// Roll the oracle back after a failed payload, preserving only the breaker
/// latch.
///
/// The VM writes the oracle in place (it is the one domain whose failure mode
/// has to survive its own transaction), so `execute_payload` restores the
/// pre-payload snapshot on every failure path - a revert must not leave a
/// committed price behind. The EXCEPTION is `breaker_tripped`: a gate that
/// fired (depeg, deviation) keeps the alarm even though its transaction rolled
/// back, because a circuit breaker that silences itself when the attack fails
/// is not a circuit breaker. Both directions are deterministic: the same block
/// produces the same restore on every node.
pub(super) fn restore_oracle_after_failure(
    oracle: &mut crate::oracle::OracleState,
    before: Option<crate::oracle::OracleState>,
) {
    let Some(before) = before else {
        return;
    };
    let latched = oracle.breaker_tripped;
    *oracle = before;
    oracle.breaker_tripped |= latched;
}

/// Pre-change native balances for a set of addresses: `(address, (balance,
/// nonce)?)`, where `None` means the account did not exist. Shared by the PMM,
/// CLOB and bridge rollback snapshots so the tuple shape lives in ONE place.
pub(super) type NativeAccountSnapshot = Vec<([u8; 32], Option<(u64, u64)>)>;

/// Rollback record for one applied bridge settlement: the pre-change native
/// balances AND the pre-change committed bridge domain, so a failure after the
/// bridge leg can undo the coins and the policy state together (a leftover
/// replay-set entry or phantom withdrawal would be consensus-visible state
/// belonging to a payload that never applied).
#[allow(clippy::type_complexity)]
// GATE: snapshot mirrors account tuple layout; alias would churn commitment code.
pub(super) struct BridgeSnapshot {
    pub(super) accounts: NativeAccountSnapshot,
    pub(super) domain: crate::bridge::BridgeState,
    /// Global-supply reservation this bridge settlement took for the NEW
    /// issuance it credited (the gross sum of `BridgeEffect::Credit`).
    ///
    /// A deposit is a mint, not a move: [`super::InMemoryStateEngine::settle_bridge_native`]
    /// reserves it against `TOTAL_SUPPLY_CAP` before writing a balance (audit
    /// F1). If a LATER leg of the same payload fails,
    /// [`super::InMemoryStateEngine::restore_bridge_native`] gives exactly this
    /// amount back, so a refused transaction never burns supply headroom.
    pub(super) minted_nano: u64,
}

/// Rollback record for one applied actor-send settlement: the pre-change
/// balance AND inbox of every account the settlement touched.
///
/// The same shape and the same purpose as [`BridgeSnapshot`]: an actor send
/// debits the sender and enqueues the message INSIDE `execute_payload`, so a
/// failure of any later settlement step (the CLOB escrow runs after it) must
/// take the coins AND the queued message back together - a message left in an
/// inbox after its transaction was refused would deliver value nobody paid
/// for, and a debit left behind would charge for a payload that never
/// applied. The trie never sees the debit (only `commit_native` writes the
/// sender's balance, and only for transactions that commit), so restoring the
/// account map is the whole rollback.
pub(super) struct ActorSnapshot {
    pub(super) accounts: Vec<([u8; 32], AccountState)>,
}

/// Pre-execution snapshot of every consensus domain the payload path can
/// mutate (B1 atomicity). On ANY failure after the VM ran — including a
/// `commit_native` refusal in the caller — the caller restores from this,
/// so a rejected transaction leaves literally nothing behind: no free
/// validator bond, no free mint, no half-settled bridge/actor/PMM legs.
/// Domains with their own snapshot/rollback (bridge, actor, PMM-native,
/// oracle, books) keep it; this covers the ones that had none (tokens,
/// contracts, orderbooks, escrow, PMM curve, staking). Session keys
/// and zkML ride as working copies committed on success and
/// are restored from their `*_before` clones the same way.
pub(super) struct PayloadDomainSnapshot {
    pub(super) tokens: Option<crate::token::TokenRegistry>,
    pub(super) contracts: Option<crate::contract::ContractRegistry>,
    pub(super) orderbooks: Option<crate::orderbook::OrderbookManager>,
    pub(super) order_escrow: Option<std::collections::HashMap<(u32, u64), EscrowRecord>>,
    pub(super) pmm: Option<crate::pmm::PrimaryMarketMaker>,
    pub(super) staking: Option<crate::staking::StakingLedger>,
    pub(super) oracle: Option<crate::oracle::OracleState>,
    pub(super) session_keys: Option<crate::zkml::SessionKeyRegistry>,
    pub(super) zkml_models: Option<crate::zkml::ZkMlModelRegistry>,
}

/// Account-level undo records created DURING execution, returned to the
/// caller so a `commit_native` failure can roll back settlement legs
/// (bridge/actor/PMM-native) that wrote the accounts map directly.
#[allow(clippy::type_complexity)]
// GATE: undo records mirror account tuple layout used across execution paths.
pub struct ExecPostActions {
    pub(super) bridge_snapshot: Option<BridgeSnapshot>,
    pub(super) actor_snapshot: Option<ActorSnapshot>,
    pub(super) pmm_native_snapshot: Vec<([u8; 32], Option<(u64, u64)>)>,
    /// Global-supply reservation the PMM buy leg took for this payload
    /// (`0` when no buy ran). A later `commit_native` refusal must give it
    /// back together with the balances, or a refused payload would permanently
    /// consume mint headroom (audit F5).
    pub(super) pmm_minted_nano: u64,
    pub(super) clob_native_snapshot: Vec<([u8; 32], Option<(u64, u64)>)>,
    /// Outbound contract messages emitted by WASM execution on `>= H`, held
    /// until AFTER `commit_native` succeeds so failed CLOB/native commits
    /// never leave dangling messages in `inbox` / `cross_shard_out`.
    pub(super) outbound_messages: Vec<crate::contract::ContractMessage>,
}

/// The versioned state snapshot: the accounts PLUS the D2 consensus penalty
/// map and the global minted-supply counter.
///
/// WHY A NEW SHAPE: the penalty is not cosmetic - it enters the CONSENSUS fee
/// floor (`consensus_floor_parts` -> the fee `commit_native` charges -> the
/// sender's balance -> the state root). A state snapshot that carried only
/// the accounts would leave a restored node with an EMPTY penalty map while a
/// node that applied the blocks has the real one: the two would then charge
/// DIFFERENT fees for the same transaction and end up with DIFFERENT state
/// roots - a consensus split, triggered by nothing more exotic than a node
/// restarting or syncing from a snapshot (audit W6.6).
///
/// The legacy bare-`Vec<AccountState>` snapshot and the intermediate
/// accounts+penalty shape (pre-`total_minted_nano`) are still accepted by
/// `parse_account_snapshot`; see the format note below.
///
/// FORMAT (audit F10): every CURRENT snapshot is magic-prefixed
/// ([`STATE_SNAPSHOT_MAGIC`]) and versioned ([`STATE_SNAPSHOT_FORMAT_VERSION`]),
/// and every field - including the trailing `total_minted_nano` - is
/// MANDATORY. A blob whose byte length does not match the declared struct is
/// refused, never decoded as a shorter legacy shape: truncating the last 8
/// bytes of a current snapshot used to erase the mint counter (restoring with
/// headroom 0 -> a full second cap) while the already-minted balances
/// survived. The magic is a PREFIX, so a truncated current blob still carries
/// it and cannot be mistaken for any legacy shape; legacy blobs (which never
/// carried the magic) are decoded by their own explicit fallbacks.
///
/// PUBLIC because the OFF-TICK persistence path must write the SAME shape:
/// see [`InMemoryStateEngine::capture_state_snapshot`] and
/// `crate::storage::clone_account_snapshot`.
#[derive(Clone, Debug)]
pub struct StateSnapshotV2 {
    /// The accounts, address-sorted.
    pub accounts: Vec<AccountState>,
    /// The D2 consensus penalty map (sender -> penalty).
    pub penalty: HashMap<[u8; 32], u64>,
    /// The engine's GLOBAL minted-supply counter (genesis allocation folded in
    /// at the first post-genesis mint, see
    /// [`InMemoryStateEngine::genesis_allocation_nano`]).
    ///
    /// It is COMMITTED (`commitment::assemble_cached_digest_with_cnvrf_and_minted`
    /// mixes it in when non-zero), so a snapshot MUST carry it: restoring a
    /// snapshot without it would leave a node free to mint a second cap on top
    /// of the supply it just loaded.
    pub total_minted_nano: u64,
}

/// First bytes of every CURRENT state-snapshot blob: the ASCII tag
/// `STELLSNP` as a numeric u64 (`0x5354_454C_4C53_4E50`). bincode's fixint
/// encoding writes it little-endian on the wire; the value is compared after
/// decoding (see `snapshot_has_magic`), so the endianness is internal.
///
/// A legacy bare-`Vec<AccountState>` blob starts with the vector's u64 length
/// (at most the decode limit, ~millions), never with this value, so the magic
/// is an unambiguous format discriminator without changing the legacy path.
pub const STATE_SNAPSHOT_MAGIC: u64 = 0x5354_454C_4C53_4E50;

/// Version of the magic-prefixed state-snapshot envelope. Bump it in the same
/// change that alters the field set, so a blob from a newer node is refused
/// loudly instead of being decoded with the wrong shape.
pub const STATE_SNAPSHOT_FORMAT_VERSION: u32 = 3;

impl Serialize for StateSnapshotV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("StateSnapshotV2", 5)?;
        st.serialize_field("magic", &STATE_SNAPSHOT_MAGIC)?;
        st.serialize_field("format_version", &STATE_SNAPSHOT_FORMAT_VERSION)?;
        st.serialize_field("accounts", &self.accounts)?;
        st.serialize_field("penalty", &self.penalty)?;
        st.serialize_field("total_minted_nano", &self.total_minted_nano)?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for StateSnapshotV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SnapshotVisitor;

        impl<'de> serde::de::Visitor<'de> for SnapshotVisitor {
            type Value = StateSnapshotV2;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a magic-prefixed, versioned state snapshot")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                use serde::de::Error as _;
                let magic: u64 = seq.next_element()?.ok_or_else(|| {
                    A::Error::custom(
                        "state snapshot: missing magic/version header (legacy or truncated blob)",
                    )
                })?;
                if magic != STATE_SNAPSHOT_MAGIC {
                    return Err(A::Error::custom(
                        "state snapshot: bad magic (not a versioned snapshot)",
                    ));
                }
                let version: u32 = seq.next_element()?.ok_or_else(|| {
                    A::Error::custom("state snapshot: truncated before format version")
                })?;
                if version != STATE_SNAPSHOT_FORMAT_VERSION {
                    return Err(A::Error::custom(format!(
                        "state snapshot: unsupported format version {version} \
                         (expected {STATE_SNAPSHOT_FORMAT_VERSION})"
                    )));
                }
                let accounts: Vec<AccountState> = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("state snapshot: truncated before accounts"))?;
                let penalty: HashMap<[u8; 32], u64> = seq.next_element()?.ok_or_else(|| {
                    A::Error::custom("state snapshot: truncated before penalty map")
                })?;
                let total_minted_nano: u64 = seq.next_element()?.ok_or_else(|| {
                    A::Error::custom(
                        "state snapshot: truncated before total_minted_nano \
                         (refusing to default the mint counter to zero)",
                    )
                })?;
                Ok(StateSnapshotV2 {
                    accounts,
                    penalty,
                    total_minted_nano,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "magic",
            "format_version",
            "accounts",
            "penalty",
            "total_minted_nano",
        ];
        deserializer.deserialize_struct("StateSnapshotV2", FIELDS, SnapshotVisitor)
    }
}

/// The pre-`total_minted_nano` V2 envelope (`accounts` + `penalty` only).
///
/// EXPLICIT legacy shape, used only by the snapshot decoder after the
/// magic-prefixed [`StateSnapshotV2`] route has been refused. It has no magic,
/// so a TRUNCATED current blob (which keeps its magic prefix) can never decode
/// as this: the magic would be read as an account-count length prefix and fail
/// the decode limit. That is what makes accepting this legacy shape safe.
#[derive(Deserialize)]
pub(super) struct LegacyStateSnapshotV2 {
    pub(super) accounts: Vec<AccountState>,
    pub(super) penalty: HashMap<[u8; 32], u64>,
}

/// The unversioned V2 envelope that carried `total_minted_nano` but predates
/// the magic+version prefix (the immediately preceding snapshot writer).
///
/// Same rule as [`LegacyStateSnapshotV2`]: no magic, decoded with an exact
/// length, and unreachable for a truncated CURRENT blob (whose magic survives
/// a suffix truncation). Its absence from the legacy fallbacks would refuse
/// every snapshot written by the previous release.
#[derive(Deserialize)]
pub(super) struct LegacyStateSnapshotV2WithCounter {
    pub(super) accounts: Vec<AccountState>,
    pub(super) penalty: HashMap<[u8; 32], u64>,
    pub(super) total_minted_nano: u64,
}

/// Canonical on-chain EVM ↔ PQ address bijection (`Domain::EvmBindings`).
///
/// Enforces a strict 1-to-1 first-writer-wins mapping between 20-byte EVM
/// addresses and 32-byte PQ accounts. Only `by_evm` is serialized; the
/// inverse index `by_pq` is skipped during serde and rebuilt fail-closed via
/// [`Self::rebuild_inverse`] on restore so the two maps can never desync.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmBindingsState {
    pub by_evm: HashMap<[u8; 20], [u8; 32]>,
    #[serde(skip)]
    pub by_pq: HashMap<[u8; 32], [u8; 20]>,
}

/// Persistence snapshot of [`EvmBindingsState`] (`"evm_bindings_state"` tree
/// in `storage.rs` and `SnapV4` `DomainUnitId::EvmBindings`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmBindingsSnapshot {
    pub by_evm: HashMap<[u8; 20], [u8; 32]>,
}

impl From<&EvmBindingsState> for EvmBindingsSnapshot {
    fn from(state: &EvmBindingsState) -> Self {
        Self {
            by_evm: state.by_evm.clone(),
        }
    }
}

impl EvmBindingsState {
    /// Create an empty canonical EVM bindings state.
    pub fn new() -> Self {
        Self::default()
    }

    /// True when no bindings are recorded.
    pub fn is_empty(&self) -> bool {
        self.by_evm.is_empty()
    }

    /// Number of bound `(evm, pq)` pairs.
    pub fn len(&self) -> usize {
        self.by_evm.len()
    }

    /// Look up the PQ address bound to `evm`.
    pub fn get_pq(&self, evm: &[u8; 20]) -> Option<[u8; 32]> {
        self.by_evm.get(evm).copied()
    }

    /// Look up the EVM address bound to `pq`.
    pub fn get_evm(&self, pq: &[u8; 32]) -> Option<[u8; 20]> {
        self.by_pq.get(pq).copied()
    }

    /// Bind `(evm, pq)` under strict 1-to-1 first-writer-wins semantics:
    /// - identical `(evm, pq)` already present -> `Ok(false)` (idempotent);
    /// - conflict on either `evm` or `pq` -> `Err(...)` without overwriting;
    /// - fresh pair -> inserts into both maps and returns `Ok(true)`.
    pub fn bind(&mut self, evm: [u8; 20], pq: [u8; 32]) -> Result<bool, String> {
        if let Some(&existing_pq) = self.by_evm.get(&evm) {
            if existing_pq == pq {
                if let Some(&existing_evm) = self.by_pq.get(&pq) {
                    if existing_evm != evm {
                        return Err(format!(
                            "EVM bindings invariant violated: PQ account {} maps to 0x{}, expected 0x{}",
                            hex::encode(pq),
                            hex::encode(existing_evm),
                            hex::encode(evm)
                        ));
                    }
                } else {
                    self.by_pq.insert(pq, evm);
                }
                return Ok(false);
            }
            return Err(format!(
                "EVM address 0x{} is already bound to PQ account {} (refusing to re-bind to {})",
                hex::encode(evm),
                hex::encode(existing_pq),
                hex::encode(pq)
            ));
        }
        if let Some(&existing_evm) = self.by_pq.get(&pq) {
            return Err(format!(
                "PQ account {} is already bound to EVM address 0x{} (refusing to bind to 0x{})",
                hex::encode(pq),
                hex::encode(existing_evm),
                hex::encode(evm)
            ));
        }
        self.by_evm.insert(evm, pq);
        self.by_pq.insert(pq, evm);
        Ok(true)
    }

    /// Rebuild `by_pq` from `by_evm`, failing closed if any two distinct EVM
    /// addresses map to the same PQ account.
    pub fn rebuild_inverse(&mut self) -> Result<(), String> {
        let mut inverse = HashMap::with_capacity(self.by_evm.len());
        for (&evm, &pq) in &self.by_evm {
            if let Some(prev_evm) = inverse.insert(pq, evm) {
                return Err(format!(
                    "duplicate PQ address {} in EVM bindings (bound to both 0x{} and 0x{})",
                    hex::encode(pq),
                    hex::encode(prev_evm),
                    hex::encode(evm)
                ));
            }
        }
        self.by_pq = inverse;
        Ok(())
    }

    /// Export a persistence snapshot.
    pub fn to_snapshot(&self) -> EvmBindingsSnapshot {
        EvmBindingsSnapshot::from(self)
    }

    /// Construct and validate [`EvmBindingsState`] from a snapshot (fail-closed
    /// on duplicate PQ mappings).
    pub fn from_snapshot(snap: EvmBindingsSnapshot) -> Result<Self, String> {
        let mut state = Self {
            by_evm: snap.by_evm,
            by_pq: HashMap::new(),
        };
        state.rebuild_inverse()?;
        Ok(state)
    }
}
