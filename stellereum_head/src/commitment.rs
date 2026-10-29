//! Canonical commitment to every consensus-visible subsystem that does NOT
//! live in the Patricia trie.
//!
//! # Why this file exists
//!
//! The state root is the Patricia trie's root. The trie commits native
//! balances, STS token balances and supply, and contract code hashes. For years
//! the remaining subsystems were mutated freely without ever touching the trie,
//! so the root could not see them.
//!
//! That is a soundness hole, not a tidiness issue. Block sync compares roots to
//! decide whether two nodes agree, and the validator set is re-derived from the
//! staking ledger at every height boundary. If the staking ledger is invisible
//! to the root, two nodes can disagree about who the validators are while the
//! root says they agree, and no amount of re-syncing detects it.
//!
//! # The invariant this module enforces
//!
//! `commitment_digest` enumerates every field of the consensus state. The root
//! is then a hash over both the trie root and this digest.
//!
//! Two consequences, both deliberate:
//!
//! 1. A subsystem cannot be added to consensus state and silently left
//!    uncommitted. It has to be listed in exactly one place, and omitting it
//!    from that list now fails the completeness test in
//!    `tests/state_root_completeness_tests.rs`.
//! 2. The commitment is computed at root-read time rather than at each
//!    mutation site. Mutation sites are where the original bug lived: fifty
//!    call sites, each of which had to remember. There is now no call site to
//!    forget.
//!
//! The digest is recomputed lazily at root-read time and cached against a
//! mutation-generation counter (`commitment_generation`). That cache is only
//! sound because the subsystem locks in `InMemoryStateEngine` are private and
//! every write accessor bumps the counter before handing out a guard; see
//! `commit_consensus_domains_if_stale`. The cache does not weaken the authority
//! of the trie: the digest is still written into the trie, which a reader can
//! cross-check independently.
//!
//! # Determinism
//!
//! `HashMap` iteration order differs between processes, so walking a map
//! naively would give two nodes with identical state different digests - a
//! consensus split with no attacker involved. Every map here is therefore
//! sorted by key before hashing, and every length is written explicitly so
//! that no two different states can encode to the same bytes.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::cmp::Reverse;
use std::collections::BTreeMap;

use crate::contract::ContractRegistry;
use crate::orderbook::{OrderSide, OrderType, OrderbookManager, Order};
use crate::pmm::PrimaryMarketMaker;
use crate::sharding::CrossShardKey;
use crate::staking::{StakingLedger, UnbondingEntry};
use crate::state_engine::EscrowRecord;

/// Bumped whenever the set of committed fields changes. Two nodes with
/// different versions must not compare roots, so the version is part of the
/// digest and a mismatch shows up as a root difference rather than as a
/// mysterious validation failure.
///
/// v3 -> v4: the oracle (`OracleState`: publishers, committed feeds, breaker
/// latch) joined the digest. A field that can move without moving the root is
/// the exact hole this module exists to close, so the re-root is deliberate:
/// every data directory needs a wipe (and `tests/genesis_root_known_answer_tests.rs`
/// a new pinned root) in the commit that bumps this.
pub const COMMITMENT_VERSION: u32 = 5;

/// The single trie key that carries the commitment digest.
///
/// The digest goes into the trie under one namespaced key rather than becoming
/// part of the state root's own hash. That keeps `state_root == trie_root`,
/// which matters: Merkle proofs and the block-sync comparison are defined
/// against the trie root, and a light client verifying an account proof must
/// not need a second, separately sourced root. One extra key folds the whole
/// non-trie state into the same root everything else already uses.
pub fn commitment_key() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"STELL_CONSENSUS_COMMITMENT_V1");
    h.finalize().into()
}

fn put_bytes(h: &mut Sha256, tag: &[u8], bytes: &[u8]) {
    h.update((tag.len() as u64).to_be_bytes());
    h.update(tag);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

fn put_u64(h: &mut Sha256, tag: &[u8], v: u64) {
    put_bytes(h, tag, &v.to_be_bytes());
}

fn put_u128(h: &mut Sha256, tag: &[u8], v: u128) {
    put_bytes(h, tag, &v.to_be_bytes());
}

fn put_bool(h: &mut Sha256, tag: &[u8], v: bool) {
    put_bytes(h, tag, &[v as u8]);
}

fn put_addr(h: &mut Sha256, tag: &[u8], v: &[u8; 32]) {
    put_bytes(h, tag, v);
}

/// A snapshot of the non-trie consensus state, cloned under the subsystem locks
/// and hashed without them. Hashing while holding every subsystem lock would
/// serialise every block behind the slowest one; cloning first costs a copy per
/// block and keeps the critical section short.
pub struct CommitmentSnapshot {
    pub tokens: crate::token::TokenRegistry,
    pub staking: StakingLedger,
    pub orderbooks: OrderbookManager,
    pub order_escrow: HashMap<(u32, u64), EscrowRecord>,
    pub pmm: PrimaryMarketMaker,
    pub pmm_usdt_token: Option<[u8; 32]>,
    pub pmm_treasury: [u8; 32],
    pub contracts: ContractRegistry,
    /// Governance. It was the one consensus-visible subsystem left out of the digest,
    /// which meant a node and its peer could disagree about a proposal or a passed
    /// parameter change and still compute the same state root -- the disagreement would
    /// only surface later, as a forked validator set or a different block reward.
    pub governance: crate::governance::Governance,
    /// Committed oracle state. Prices decide whether an order is accepted
    /// (`SysCallPlaceOrder` / `place_order_settled` gate on them) and the
    /// breaker latch pauses trading, so two nodes holding different feeds
    /// would apply different blocks to the SAME root - the same class of split
    /// as an uncommitted staking ledger.
    pub oracle: crate::oracle::OracleState,
    /// On-chain session-key registry (phase 2): lazy registration, cumulative
    /// gas spend and terminal revocation, keyed by session pubkey.
    ///
    /// Uncommitted, a node that had revoked a session key would still agree on
    /// the state root with one that had not, and the two would then apply the
    /// same block's session transactions differently - the exact hole this
    /// module exists to close.
    ///
    /// CONDITIONAL: `commitment_digest` hashes this domain only when the
    /// registry is NON-EMPTY (see `session_keys_digest`), so a chain that has
    /// never registered a session key - every genesis KAT, every pre-phase-2
    /// snapshot - hashes byte-for-byte identically to before. The price is
    /// that an emptied registry must contribute nothing at all, not even a
    /// zero length prefix.
    pub session_keys: crate::zkml::SessionKeyRegistry,
    /// Committed bridge domain (`BridgeState`): the source-tx replay set, the
    /// parked withdrawal queue, the hourly rate-limit window and the escrow
    /// mirror behind `OpCode::SysCallBridge`.
    ///
    /// Uncommitted, a node that had credited a deposit would still agree on the
    /// state root with one that had not, and the two would then apply the same
    /// block's bridge transactions differently - the same class of split as an
    /// uncommitted staking ledger (and a replayable deposit is a mint bug).
    ///
    /// CONDITIONAL: `commitment_digest` hashes this domain only when it is
    /// NON-EMPTY (see `bridge_digest`), so a chain that has never bridged -
    /// every genesis KAT - hashes byte-for-byte identically to before and
    /// `COMMITMENT_VERSION` stays put. Like `session_keys`, an empty domain
    /// must contribute nothing at all, not even a zero length prefix.
    pub bridge: crate::bridge::BridgeState,
    /// Cross-shard replay sets (audit F1): the engine credit gate
    /// (`cross_shard_consumed`), the outbound-transfer log (`cross_shard_produced`
    /// as `(tx hash, produce height)` pairs) and the ack/bounce completion set
    /// (`cross_shard_completed` as tx hashes).
    ///
    /// A node that had consumed a message (or produced an outbound, or
    /// completed a lifecycle) must not report the same root as one that had
    /// not: the two would then apply the next block's cross-shard records
    /// differently under one root - a silent split, and a wiped consumed set
    /// is a double mint. Committing the sets turns any divergence into a root
    /// mismatch that snapshot verification and block sync refuse loudly.
    ///
    /// CONDITIONAL, exactly like `session_keys` / `bridge`: all three empty
    /// writes zero bytes, so a chain that never used cross-shard messaging -
    /// every genesis KAT, every single-shard snapshot - digests byte-for-byte
    /// identically to before and `COMMITMENT_VERSION` stays put.
    ///
    /// Callers pass SORTED vecs (the engine sorts its snapshots); the digest
    /// re-sorts defensively so a hand-built snapshot cannot fork by order.
    pub cross_shard_consumed: Vec<CrossShardKey>,
    pub cross_shard_produced: Vec<([u8; 32], u64)>,
    pub cross_shard_completed: Vec<[u8; 32]>,
}

/// Governance digest.
///
/// `Governance.proposals` and `Proposal.voters` are `HashMap`s, so they MUST be
/// normalised before hashing or two nodes with identical governance would compute
/// different roots -- the same trap `I2` in PROTOCOL.md calls out for every other
/// subsystem. Live tallies (`yes`/`no`/`abstain`) are included, not just the final
/// status, because a node that has counted a different set of votes has genuinely
/// different state even before finalization.
fn governance_digest(h: &mut Sha256, g: &crate::governance::Governance) {
    use crate::governance::{ProposalStatus, VoteChoice};

    put_u64(h, b"gov_next_id", g.next_id);
    put_u64(h, b"gov_quorum_bps", g.quorum_bps);

    let proposals: std::collections::BTreeMap<u64, &crate::governance::Proposal> =
        g.proposals.iter().map(|(k, v)| (*k, v)).collect();
    put_u64(h, b"gov_proposals_len", proposals.len() as u64);
    for (id, p) in proposals {
        put_u64(h, b"gov_prop_id", id);
        put_bytes(h, b"gov_prop_proposer", &p.proposer);
        put_bytes(h, b"gov_prop_title", p.title.as_bytes());
        put_u64(h, b"gov_prop_action_tag", gov_action_tag(&p.action));
        put_u64(h, b"gov_prop_action_value", gov_action_value(&p.action));
        // The oracle publisher actions carry a key, not a number. Without this
        // the tag+value pair of "register 0x11.." and "register 0x22.." would be
        // identical bytes, so two nodes could hold different pending
        // registrations under the same root. It is emitted ONLY for the appended
        // variants: every action that existed before keeps exactly the preimage
        // it had, so no already-committed proposal changes its digest.
        if let crate::governance::GovAction::RegisterOraclePublisher(pk)
        | crate::governance::GovAction::UnregisterOraclePublisher(pk) = &p.action
        {
            put_addr(h, b"gov_prop_action_pubkey", pk);
        }
        put_u64(h, b"gov_prop_created_at", p.created_at);
        put_u64(h, b"gov_prop_voting_end", p.voting_end);
        // u128 tallies: split, because put_u64 only carries 64 bits.
        put_u64(h, b"gov_prop_yes_lo", p.yes as u64);
        put_u64(h, b"gov_prop_yes_hi", (p.yes >> 64) as u64);
        put_u64(h, b"gov_prop_no_lo", p.no as u64);
        put_u64(h, b"gov_prop_no_hi", (p.no >> 64) as u64);
        put_u64(h, b"gov_prop_abstain_lo", p.abstain as u64);
        put_u64(h, b"gov_prop_abstain_hi", (p.abstain >> 64) as u64);
        put_u64(
            h,
            b"gov_prop_status",
            match p.status {
                ProposalStatus::Open => 0,
                ProposalStatus::Passed => 1,
                ProposalStatus::Rejected => 2,
                ProposalStatus::Executed => 3,
            },
        );
        let voters: std::collections::BTreeMap<[u8; 32], VoteChoice> =
            p.voters.iter().map(|(k, v)| (*k, *v)).collect();
        put_u64(h, b"gov_prop_voters_len", voters.len() as u64);
        for (voter, choice) in voters {
            put_bytes(h, b"gov_voter", &voter);
            put_u64(
                h,
                b"gov_vote",
                match choice {
                    VoteChoice::Yes => 0,
                    VoteChoice::No => 1,
                    VoteChoice::Abstain => 2,
                },
            );
        }
        // E7: the frozen quorum base and the per-voter locked weights. Both
        // decide every future finalize of this proposal, so both move the
        // root. APPENDED inside the per-proposal block: a chain with no
        // proposals (every genesis KAT) never reaches these bytes, so its
        // digest is byte-identical to before and COMMITMENT_VERSION stays 4.
        put_u64(h, b"gov_prop_electorate_lo", p.electorate as u64);
        put_u64(h, b"gov_prop_electorate_hi", (p.electorate >> 64) as u64);
        let weights: std::collections::BTreeMap<[u8; 32], u128> =
            p.weights.iter().map(|(k, v)| (*k, *v)).collect();
        put_u64(h, b"gov_prop_weights_len", weights.len() as u64);
        for (voter, w) in weights {
            put_bytes(h, b"gov_weight_voter", &voter);
            put_u64(h, b"gov_weight_lo", w as u64);
            put_u64(h, b"gov_weight_hi", (w >> 64) as u64);
        }
    }

    // Applied parameters. Each is an Option, so the discriminant is hashed too --
    // otherwise `None` and `Some(0)` would collide.
    let ap = &g.applied;
    for (tag, v) in [
        (b"gov_applied_min_bond".as_slice(), ap.min_validator_bond),
        (b"gov_applied_equiv_slash".as_slice(), ap.equivocation_slash_bps),
        (b"gov_applied_commission".as_slice(), ap.default_commission_bps),
        (b"gov_applied_block_reward".as_slice(), ap.block_reward),
        (b"gov_applied_pmm_buffer".as_slice(), ap.pmm_redemption_buffer_bps),
    ] {
        match v {
            Some(x) => {
                put_u64(h, tag, 1);
                put_u64(h, tag, x);
            }
            None => put_u64(h, tag, 0),
        }
    }
    // min_gas_limit is SELF-CONDITIONAL (audit follow-up): it joined the
    // digest after genesis, so writing even a None discriminant would move
    // the genesis root (hard fork). Skipped-when-None keeps every pre-floor
    // preimage byte-identical; a set floor visibly enters the digest.
    if let Some(x) = ap.min_gas_limit {
        put_u64(h, b"gov_applied_min_gas_present", 1);
        put_u64(h, b"gov_applied_min_gas", x);
    }
    match &ap.signal {
        Some(s) => {
            put_u64(h, b"gov_applied_signal_present", 1);
            put_bytes(h, b"gov_applied_signal", s.as_bytes());
        }
        None => put_u64(h, b"gov_applied_signal_present", 0),
    }
}

/// Explicit discriminants, so the committed value cannot drift if the enum is
/// reordered.
fn gov_action_tag(a: &crate::governance::GovAction) -> u64 {
    use crate::governance::GovAction::*;
    match a {
        SetMinValidatorBond(_) => 0,
        SetEquivocationSlashBps(_) => 1,
        SetDefaultCommissionBps(_) => 2,
        SetBlockReward(_) => 3,
        SetPmmRedemptionBufferBps(_) => 4,
        SetGovernanceQuorumBps(_) => 5,
        Signal(_) => 6,
        RegisterOraclePublisher(_) => 7,
        UnregisterOraclePublisher(_) => 8,
        ResetOracleBreaker => 9,
        SetMinGasLimit(_) => 10,
    }
}

/// The numeric payload of an action, or 0 for the non-numeric ones.
fn gov_action_value(a: &crate::governance::GovAction) -> u64 {
    use crate::governance::GovAction::*;
    match a {
        SetMinValidatorBond(v)
        | SetEquivocationSlashBps(v)
        | SetDefaultCommissionBps(v)
        | SetBlockReward(v)
        | SetPmmRedemptionBufferBps(v)
        | SetGovernanceQuorumBps(v)
        | SetMinGasLimit(v) => *v,
        // The keyed/non-numeric actions carry no value here; the publisher key
        // is committed separately in `governance_digest`.
        Signal(_)
        | RegisterOraclePublisher(_)
        | UnregisterOraclePublisher(_)
        | ResetOracleBreaker => 0,
    }
}

/// Stable numeric tag for the order enums.
///
/// Written out by hand rather than via `as u64`: these enums are not `Copy`,
/// and an explicit mapping keeps the committed values independent of any future
/// change to how the enums are laid out or ordered.
fn side_tag(s: &OrderSide) -> u64 {
    match s {
        OrderSide::Buy => 0,
        OrderSide::Sell => 1,
    }
}

fn order_type_tag(t: &OrderType) -> u64 {
    match t {
        OrderType::Limit => 0,
        OrderType::Market => 1,
    }
}

fn order_digest(h: &mut Sha256, o: &Order) {
    put_u64(h, b"order_id", o.order_id);
    put_addr(h, b"trader", &o.trader);
    put_u64(h, b"side", side_tag(&o.side));
    put_u64(h, b"order_type", order_type_tag(&o.order_type));
    put_u64(h, b"price", o.price);
    put_u64(h, b"amount", o.amount);
    put_u64(h, b"filled", o.filled);
    put_u64(h, b"timestamp", o.timestamp);
}

fn book_digest(h: &mut Sha256, book: &crate::orderbook::OrderbookActor) {
    put_u64(h, b"pair_id", book.pair_id as u64);
    put_u64(h, b"next_order_id", book.next_order_id);
    put_u64(h, b"max_depth", book.max_depth as u64);

    // BTreeMap, so already ordered; hashed explicitly anyway so a switch to a
    // hash-ordered container cannot silently change the commitment.
    put_u64(h, b"bids_len", book.bids.len() as u64);
    for (Reverse(price), orders) in &book.bids {
        put_u64(h, b"bid_price", *price);
        put_u64(h, b"bid_orders", orders.len() as u64);
        for o in orders {
            order_digest(h, o);
        }
    }
    put_u64(h, b"asks_len", book.asks.len() as u64);
    for (price, orders) in &book.asks {
        put_u64(h, b"ask_price", *price);
        put_u64(h, b"ask_orders", orders.len() as u64);
        for o in orders {
            order_digest(h, o);
        }
    }
}

/// Commit the token registry.
///
/// Balances and total supply are already in the trie under their own key
/// domains, but that is not the whole actor. `allowances` gates
/// `TransferFrom` succeeding, `minter`/`paused`/`max_supply` gate minting and
/// transferring, and `next_nonce` derives the next token id. A node that
/// disagreed on any of those would agree on the state root, which is exactly the
/// class of divergence this module exists to prevent.
fn tokens_digest(h: &mut Sha256, reg: &crate::token::TokenRegistry) {
    put_u64(h, b"tokens_next_nonce", reg.next_nonce);
    let mut sorted: BTreeMap<&[u8; 32], &crate::token::TokenActor> = BTreeMap::new();
    for (k, v) in &reg.tokens {
        sorted.insert(k, v);
    }
    put_u64(h, b"tokens_len", sorted.len() as u64);
    for (id, t) in sorted {
        put_addr(h, b"token_id", id);
        let m = &t.metadata;
        put_bytes(h, b"token_name", m.name.as_bytes());
        put_bytes(h, b"token_symbol", m.symbol.as_bytes());
        put_bytes(h, b"token_description", m.description.as_bytes());
        put_bytes(h, b"token_decimals", &[m.decimals]);
        put_u64(h, b"token_total_supply", m.total_supply);
        match m.max_supply {
            Some(v) => {
                put_bool(h, b"token_has_max_supply", true);
                put_u64(h, b"token_max_supply", v);
            }
            None => put_bool(h, b"token_has_max_supply", false),
        }
        put_addr(h, b"token_minter", &m.minter);
        put_bool(h, b"token_paused", m.paused);

        let mut bals: BTreeMap<&[u8; 32], &u64> = BTreeMap::new();
        for (k, v) in &t.balances {
            bals.insert(k, v);
        }
        put_u64(h, b"token_balances_len", bals.len() as u64);
        for (acct, bal) in bals {
            put_addr(h, b"token_balance_owner", acct);
            put_u64(h, b"token_balance", *bal);
        }

        let mut alls: BTreeMap<&([u8; 32], [u8; 32]), &u64> = BTreeMap::new();
        for (k, v) in &t.allowances {
            alls.insert(k, v);
        }
        put_u64(h, b"token_allowances_len", alls.len() as u64);
        for ((owner, spender), amt) in alls {
            put_addr(h, b"token_allowance_owner", owner);
            put_addr(h, b"token_allowance_spender", spender);
            put_u64(h, b"token_allowance", *amt);
        }
    }
}

fn staking_digest(h: &mut Sha256, l: &StakingLedger) {
    // Sorted by validator id: HashMap order is not reproducible across nodes.
    let mut vals: BTreeMap<&[u8; 32], &crate::staking::ValidatorStake> = BTreeMap::new();
    for (k, v) in &l.validators {
        vals.insert(k, v);
    }
    put_u64(h, b"validators_len", vals.len() as u64);
    for (id, s) in vals {
        put_addr(h, b"validator", id);
        put_u64(h, b"self_bond", s.self_bond);
        put_u64(h, b"delegated", s.delegated);
        put_u64(h, b"commission_bps", s.commission_bps);
        put_u64(h, b"pending_rewards", s.pending_rewards);
        put_u64(h, b"total_slashed", s.total_slashed);
        put_u64(h, b"missed", s.missed as u64);
        put_u64(h, b"last_downtime_penalty", s.last_downtime_penalty);
    }

    let mut dels: BTreeMap<&([u8; 32], [u8; 32]), &u64> = BTreeMap::new();
    for (k, v) in &l.delegations {
        dels.insert(k, v);
    }
    put_u64(h, b"delegations_len", dels.len() as u64);
    for ((val, del), amt) in dels {
        put_addr(h, b"del_val", val);
        put_addr(h, b"del_owner", del);
        put_u64(h, b"del_amount", *amt);
    }

    let mut rews: BTreeMap<&([u8; 32], [u8; 32]), &u64> = BTreeMap::new();
    for (k, v) in &l.delegator_rewards {
        rews.insert(k, v);
    }
    put_u64(h, b"delegator_rewards_len", rews.len() as u64);
    for ((val, del), amt) in rews {
        put_addr(h, b"rew_val", val);
        put_addr(h, b"rew_owner", del);
        put_u64(h, b"rew_amount", *amt);
    }

    // A Vec: order is part of the value, so it is hashed as-is.
    put_u64(h, b"unbonding_len", l.unbonding.len() as u64);
    for e in &l.unbonding {
        unbonding_digest(h, e);
    }

    let mut wths: BTreeMap<&([u8; 32], [u8; 32]), &u64> = BTreeMap::new();
    for (k, v) in &l.withdrawable {
        wths.insert(k, v);
    }
    put_u64(h, b"withdrawable_len", wths.len() as u64);
    for ((val, owner), amt) in wths {
        put_addr(h, b"wth_val", val);
        put_addr(h, b"wth_owner", owner);
        put_u64(h, b"wth_amount", *amt);
    }

    put_u64(h, b"total_burned", l.total_burned);

    // E2 rewards-pool domain, CONDITIONAL like every domain in this module:
    // a ledger that never minted rewards (rewards_pool == 0 AND
    // rewards_minted == 0 — every genesis KAT) writes zero bytes, so the
    // genesis root stays byte-identical and COMMITMENT_VERSION stays at 4.
    // Once any reward is minted the domain is always present (minted is
    // monotonic, so it cannot flap back to absent), and every value that
    // decides future mints/payouts is committed.
    if l.rewards_pool != 0 || l.rewards_minted != 0 {
        put_bytes(h, b"staking_rewards_domain", b"STAKING_REWARDS_V1");
        put_u64(h, b"rewards_pool", l.rewards_pool);
        put_u64(h, b"rewards_minted", l.rewards_minted);
    }

    // E7 governance-lock domain, CONDITIONAL like the rewards domain above:
    // empty whenever no vote is open (every genesis KAT, and every ledger
    // whose proposals all finalized — `unlock_governance` removes the entry
    // at zero), so those chains digest byte-for-byte identically to before
    // and COMMITMENT_VERSION stays at 4. A non-empty lock decides whether
    // the next unbond/undelegate applies, so it must move the root.
    if !l.locked_governance.is_empty() {
        put_bytes(h, b"staking_gov_locks_domain", b"STAKING_GOV_LOCKS_V1");
        let mut locks: BTreeMap<&[u8; 32], &u64> = BTreeMap::new();
        for (k, v) in &l.locked_governance {
            locks.insert(k, v);
        }
        put_u64(h, b"gov_locks_len", locks.len() as u64);
        for (owner, amt) in locks {
            put_addr(h, b"gov_lock_owner", owner);
            put_u64(h, b"gov_lock_amount", *amt);
        }
    }
}

fn unbonding_digest(h: &mut Sha256, e: &UnbondingEntry) {
    put_addr(h, b"unbond_validator", &e.validator);
    match &e.owner {
        Some(o) => {
            put_bool(h, b"unbond_has_owner", true);
            put_addr(h, b"unbond_owner", o);
        }
        None => put_bool(h, b"unbond_has_owner", false),
    }
    put_u64(h, b"unbond_amount", e.amount);
    put_u64(h, b"unbond_release_at", e.release_at);
}

fn pmm_digest(h: &mut Sha256, p: &PrimaryMarketMaker, usdt: &Option<[u8; 32]>, treasury: &[u8; 32]) {
    put_u128(h, b"pmm_minted_nano", p.minted_nano);
    put_u128(h, b"pmm_reserve_micro", p.reserve_micro);
    put_u128(h, b"pmm_redemption_buffer_micro", p.redemption_buffer_micro);
    put_u128(h, b"pmm_depth_cap_nano", p.depth_cap_nano);
    put_u64(h, b"pmm_base_price_micro", p.base_price_micro);
    match usdt {
        Some(t) => {
            put_bool(h, b"pmm_has_usdt", true);
            put_addr(h, b"pmm_usdt", t);
        }
        None => put_bool(h, b"pmm_has_usdt", false),
    }
    put_addr(h, b"pmm_treasury", treasury);
}

fn contracts_digest(h: &mut Sha256, reg: &ContractRegistry) {
    put_u64(h, b"contracts_next_nonce", reg.next_nonce);
    let mut sorted: BTreeMap<&[u8; 32], &crate::contract::Contract> = BTreeMap::new();
    for (k, v) in &reg.contracts {
        sorted.insert(k, v);
    }
    put_u64(h, b"contracts_len", sorted.len() as u64);
    for (addr, c) in sorted {
        put_addr(h, b"contract_addr", addr);
        put_addr(h, b"contract_creator", &c.creator);
        put_addr(h, b"contract_code_hash", &c.code_hash);
        put_u64(h, b"contract_created_at", c.created_at);
        put_bool(h, b"contract_paused", c.paused);

        // Storage is where a contract's balances and counters actually live.
        // Committing only the code hash would let a node prove a contract
        // exists while proving nothing about what it holds.
        let mut slots: BTreeMap<&i64, &i64> = BTreeMap::new();
        for (k, v) in &c.storage {
            slots.insert(k, v);
        }
        put_u64(h, b"contract_storage_len", slots.len() as u64);
        for (k, v) in slots {
            put_u64(h, b"contract_slot", *k as u64);
            put_u64(h, b"contract_value", *v as u64);
        }
    }
}

fn escrow_digest(h: &mut Sha256, escrow: &HashMap<(u32, u64), EscrowRecord>) {
    let mut sorted: BTreeMap<&(u32, u64), &EscrowRecord> = BTreeMap::new();
    for (k, v) in escrow {
        sorted.insert(k, v);
    }
    put_u64(h, b"escrow_len", sorted.len() as u64);
    for ((pair, order), rec) in sorted {
        put_u64(h, b"escrow_pair", *pair as u64);
        put_u64(h, b"escrow_order", *order);
        put_addr(h, b"escrow_trader", &rec.trader);
        put_u64(h, b"escrow_base", rec.locked_base_stell);
        put_u64(h, b"escrow_quote", rec.locked_quote_wusdt);
        // The SVM path locks a BUY's quote in native units instead of wUSDT;
        // leaving this field out of the digest would let two nodes holding
        // different native escrow report the same state root.
        put_u64(h, b"escrow_quote_native", rec.locked_quote_native);
    }
}

/// Oracle digest.
///
/// `OracleState` already stores its collections as `BTreeSet`/`BTreeMap`
/// (order is a function of the contents), so unlike the `HashMap` subsystems
/// there is nothing to re-sort here - but every length is still written
/// explicitly, so a publisher set and a feed map cannot trade bytes and the
/// same framing rules apply as everywhere else in this module.
fn oracle_digest(h: &mut Sha256, o: &crate::oracle::OracleState) {
    // The latch pauses all trading: it is state, not a cache.
    put_bool(h, b"oracle_breaker_tripped", o.breaker_tripped);

    put_u64(h, b"oracle_publishers_len", o.publishers.len() as u64);
    for publisher in &o.publishers {
        put_addr(h, b"oracle_publisher", publisher);
    }

    put_u64(h, b"oracle_feeds_len", o.feeds.len() as u64);
    for (asset, feed) in &o.feeds {
        put_bytes(h, b"oracle_feed_asset", asset.as_bytes());
        put_u64(h, b"oracle_feed_price", feed.price_micro_usd);
        put_u64(h, b"oracle_feed_timestamp", feed.timestamp);
        put_addr(h, b"oracle_feed_publisher", &feed.publisher);
    }
}

/// Session-key registry digest.
///
/// CONDITIONAL DOMAIN: the caller only invokes this when the registry is
/// non-empty. Nothing about the framing is conditional INSIDE - lengths are
/// still explicit and the `BTreeMap` iteration is already sorted by session
/// pubkey - so the moment a key registers the domain appears in full, and the
/// moment the last one is gone the digest is byte-identical to a chain that
/// never had one (which is what keeps `tests/genesis_root_known_answer_tests.rs`
/// pinned without touching its pins).
///
/// Every field of the record is committed: `gas_spent` because two nodes that
/// disagreed on how much budget was left would accept different next
/// transactions under the same root, `revoked` because revocation IS a
/// consensus decision, and the copied ceilings for the same reason the grant's
/// own parameters are checked - they decide what executes next.
fn session_keys_digest(h: &mut Sha256, reg: &crate::zkml::SessionKeyRegistry) {
    put_u64(h, b"session_keys_len", reg.entries.len() as u64);
    for (pk, r) in &reg.entries {
        put_addr(h, b"session_key", pk);
        put_addr(h, b"session_master", &r.master);
        put_u64(h, b"session_valid_until", r.valid_until);
        put_u64(h, b"session_max_gas_spend", r.max_gas_spend);
    put_u64(h, b"session_gas_spent", r.gas_spent);
    put_u64(h, b"session_scope", r.scope);
    put_u64(h, b"session_max_value_per_tx", r.max_value_per_tx);
    put_bool(h, b"session_revoked", r.revoked);
    }
}

/// Bridge domain digest.
///
/// CONDITIONAL DOMAIN: the caller only invokes this when the domain is
/// NON-EMPTY (see `BridgeState::is_empty`), so a chain that has never bridged
/// - every genesis KAT - digests byte-for-byte identically to before and
/// `COMMITMENT_VERSION` stays put. Nothing about the framing is conditional
/// INSIDE: lengths are explicit and the containers are `BTreeSet`/`BTreeMap`
/// (already ordered by their keys, like the oracle domain), so PROTOCOL.md I2
/// holds - two nodes with identical bridge state hash identical bytes.
///
/// Every field of the domain is committed, because every field of it DECIDES
/// THE NEXT BLOCK: the replay set decides whether a deposit credits again (a
/// disagreement is a double mint), the queue and its id counter decide which
/// release applies and whether it is time-locked, the rate window decides
/// whether the next withdrawal is admitted, and the escrow mirror reports how
/// much value the bridge holds. Omitting any of them would let two nodes
/// apply the same block to the same root and then disagree - exactly the hole
/// `tests/state_root_completeness_tests.rs` and I1 exist to close.
fn bridge_digest(h: &mut Sha256, b: &crate::bridge::BridgeState) {
    put_u64(h, b"bridge_next_withdrawal_id", b.next_withdrawal_id);
    put_u64(h, b"bridge_hourly_withdrawn", b.hourly_withdrawn);
    put_u64(h, b"bridge_last_rate_limit_reset", b.last_rate_limit_reset);
    put_u64(h, b"bridge_escrow_balance", b.escrow_balance);
    put_u64(h, b"bridge_hourly_deposited", b.hourly_deposited);
    put_u64(h, b"bridge_last_deposit_reset", b.last_deposit_reset);
    put_u64(h, b"bridge_total_minted", b.total_minted);
    put_u64(h, b"bridge_next_dispute_id", b.next_dispute_id);

    put_u64(h, b"bridge_records_len", b.deposit_records.len() as u64);
    for (hash, r) in &b.deposit_records {
        put_addr(h, b"bridge_rec_hash", hash);
        put_addr(h, b"bridge_recipient", &r.recipient);
        put_u64(h, b"bridge_rec_amount", r.amount);
        put_u64(
            h,
            b"bridge_rec_chain",
            match r.chain {
                crate::bridge::SupportedChain::Ton => 0,
                crate::bridge::SupportedChain::Arbitrum => 1,
                crate::bridge::SupportedChain::Ethereum => 2,
                crate::bridge::SupportedChain::Solana => 3,
            },
        );
        put_bool(h, b"bridge_rec_via_quorum", r.via_quorum);
        put_u64(h, b"bridge_rec_deposited_at", r.deposited_at);
        put_bool(h, b"bridge_rec_disputed", r.disputed);
    }

    put_u64(h, b"bridge_disputes_len", b.disputes.len() as u64);
    for (id, d) in &b.disputes {
        put_u64(h, b"bridge_dispute_id", *id);
        put_addr(h, b"bridge_dispute_hash", &d.source_tx_hash);
        put_addr(h, b"bridge_dispute_challenger", &d.challenger);
        put_addr(h, b"bridge_dispute_recipient", &d.recipient);
        put_u64(h, b"bridge_dispute_amount", d.amount);
        put_u64(h, b"bridge_dispute_bond", d.bond);
        put_u64(h, b"bridge_dispute_deadline", d.deadline);
        put_bool(h, b"bridge_dispute_resolved", d.resolved);
        put_bool(h, b"bridge_dispute_confirmed", d.confirmed);
    }

    put_u64(h, b"bridge_replay_len", b.processed_source_txs.len() as u64);
    for tx in &b.processed_source_txs {
        put_addr(h, b"bridge_source_tx", tx);
    }

    put_u64(h, b"bridge_pending_len", b.pending_withdrawals.len() as u64);
    for (id, w) in &b.pending_withdrawals {
        put_u64(h, b"bridge_req_id", *id);
        put_addr(h, b"bridge_req_sender", &w.sender);
        put_u64(
            h,
            b"bridge_req_target_chain",
            match w.target_chain {
                crate::bridge::SupportedChain::Ton => 0,
                crate::bridge::SupportedChain::Arbitrum => 1,
                crate::bridge::SupportedChain::Ethereum => 2,
                crate::bridge::SupportedChain::Solana => 3,
            },
        );
        put_bytes(h, b"bridge_req_target_address", w.target_address.as_bytes());
        put_u64(h, b"bridge_req_amount", w.amount);
        put_u64(h, b"bridge_req_requested_at", w.requested_at);
        put_u64(h, b"bridge_req_unlock_at", w.unlock_at);
        put_bool(h, b"bridge_req_executed", w.executed);
    }
}

/// §2 zkML model-registry domain digest.
///
/// CONDITIONAL DOMAIN, exactly like the session-key / bridge / confidential
/// domains: the caller only invokes this when the registry is NON-EMPTY (see
/// [`write_zkml_models_domain`)), so a chain that has never registered a model
/// - every genesis KAT - digests byte-for-byte identically to before and
/// [`COMMITMENT_VERSION`] stays at 4. Nothing about the framing is conditional
/// INSIDE: lengths are explicit and the registry is a `BTreeMap` (already
/// ordered by `model_id`, like the oracle domain), so PROTOCOL.md I2 holds -
/// two nodes with identical registries hash identical bytes.
///
/// Every field that decides the next verification is committed: the `model_id`
/// the proof names, the `model_hash` the proof is matched against, and the full
/// weights/biases/dims the re-execution actually runs. Omitting any of them
/// would let two nodes verify the same proof against different weights under
/// one root - exactly the hole `tests/state_root_completeness_tests.rs` and I1
/// exist to close.
fn zkml_models_digest_inner(h: &mut Sha256, reg: &crate::zkml::ZkMlModelRegistry) {
    write_zkml_models_domain(h, reg);
}

/// Fold the §2 zkML model registry into an existing hasher.
///
/// CONDITIONAL: an EMPTY registry writes zero bytes, so appending this
/// unconditionally keeps the genesis root (and every pre-§2 snapshot root)
/// byte-identical. Inside the domain nothing is conditional: `model_id`s are
/// walked in `BTreeMap` order and every collection's length is written, so two
/// different registries cannot encode to the same preimage.
pub fn write_zkml_models_domain(h: &mut Sha256, reg: &crate::zkml::ZkMlModelRegistry) {
    if reg.is_empty() {
        return;
    }
    put_bytes(h, b"zkml_models_domain", b"ZKML_MODELS_V1");
    put_u64(h, b"zkml_models_len", reg.models.len() as u64);
    for (model_id, rec) in &reg.models {
        put_addr(h, b"zkml_model_id", model_id);
        put_bytes(h, b"zkml_model_hash", &rec.model_hash);
        put_u64(h, b"zkml_model_layers_len", rec.model.layers.len() as u64);
        for layer in &rec.model.layers {
            put_u64(h, b"zkml_layer_in_dim", layer.in_dim as u64);
            put_u64(h, b"zkml_layer_out_dim", layer.out_dim as u64);
            put_u64(h, b"zkml_layer_weights_len", layer.weights.len() as u64);
            for w in &layer.weights {
                put_u64(h, b"zkml_weight", *w as u64);
            }
            put_u64(h, b"zkml_layer_biases_len", layer.biases.len() as u64);
            for b in &layer.biases {
                put_u64(h, b"zkml_bias", *b as u64);
            }
        }
    }
}

/// Standalone digest of the §2 model registry (empty registry digests the
/// empty preimage, matching the zero-bytes conditional contract above).
pub fn zkml_models_digest(reg: &crate::zkml::ZkMlModelRegistry) -> [u8; 32] {
    let mut h = Sha256::new();
    write_zkml_models_domain(&mut h, reg);
    h.finalize().into()
}

/// Fold the §2 zkML VERIFYING-KEY set into an existing hasher.
///
/// CONDITIONAL, exactly like every domain in this module: while NO record
/// carries a VK this writes zero bytes, so appending it unconditionally
/// keeps the genesis root (and every pre-SNARK snapshot root) byte-identical
/// and [`COMMITMENT_VERSION`] stays at 4. Inside the domain nothing is
/// conditional: `model_id`s are walked in `BTreeMap` order and every
/// collection's length is written, so two different key sets cannot encode
/// to the same preimage (PROTOCOL.md I2).
///
/// Committed per key: the `model_id` the proof names, the `vk_hash` the
/// verify handler matches on, the full `vk_bytes` (a node that disagreed on
/// the key would verify different proofs under one root), the I/O shape the
/// handler pins, and the setup attestation (which ceremony this key claims).
/// APPENDED after the models domain, so every pre-SNARK preimage keeps
/// exactly the byte sequence it had.
pub fn write_zkml_vks_domain(h: &mut Sha256, reg: &crate::zkml::ZkMlModelRegistry) {
    if !reg.has_any_vk() {
        return;
    }
    put_bytes(h, b"zkml_vks_domain", b"ZKML_VKS_V1");
    let keyed: Vec<([u8; 32], &crate::snark::RegisteredVk)> = reg
        .models
        .iter()
        .filter_map(|(id, rec)| rec.vk.as_ref().map(|vk| (*id, vk)))
        .collect();
    put_u64(h, b"zkml_vks_len", keyed.len() as u64);
    for (model_id, vk) in keyed {
        put_addr(h, b"zkml_vk_model_id", &model_id);
        put_bytes(h, b"zkml_vk_hash", &vk.vk_hash);
        put_u64(h, b"zkml_vk_in_dim", vk.in_dim);
        put_u64(h, b"zkml_vk_out_dim", vk.out_dim);
        put_u64(h, b"zkml_vk_n_public", vk.n_public_inputs);
        put_bytes(h, b"zkml_vk_bytes", &vk.vk_bytes);
        put_bytes(h, b"zkml_vk_attestation", &vk.setup_attestation);
    }
}

/// Standalone digest of the §2 VK set (no key anywhere digests the empty
/// preimage, matching the zero-bytes conditional contract above).
pub fn zkml_vks_digest(reg: &crate::zkml::ZkMlModelRegistry) -> [u8; 32] {
    let mut h = Sha256::new();
    write_zkml_vks_domain(&mut h, reg);
    h.finalize().into()
}

/// Write the commitment preimage into an existing hasher.
///
/// Split out of [`commitment_digest`] so the confidential-aware entry point
/// below can share the EXACT same byte sequence. The split is behaviour
/// preserving by construction: `commitment_digest` still calls this and
/// finalizes, so its output is byte-for-byte unchanged.
/// Cross-shard replay domain digest (audit F1).
///
/// CONDITIONAL DOMAIN: all three sets empty writes zero bytes, so appending
/// this unconditionally keeps the genesis root (and every pre-cross-shard
/// snapshot root) byte-identical with no `COMMITMENT_VERSION` bump - the same
/// contract as the session-key / bridge / confidential / zkML domains. Inside
/// the domain nothing is conditional: every set's length is written and
/// entries are hashed in sorted order, so two different replay states cannot
/// encode to the same preimage (PROTOCOL.md I2).
///
/// Committed per entry: the full consumed replay key (the source shard, the
/// source block identity and the message id - dropping any of them would let
/// two nodes disagree about WHAT was consumed under one root), the produced
/// `(tx hash, produce height)` pair (the height decides the timeout-bounce
/// linkage, so hashes alone would under-commit), and the completed tx hash
/// (decides whether the next ack/bounce for the same lifecycle applies).
pub fn write_cross_shard_domain(
    h: &mut Sha256,
    consumed: &[CrossShardKey],
    produced: &[([u8; 32], u64)],
    completed: &[[u8; 32]],
) {
    if consumed.is_empty() && produced.is_empty() && completed.is_empty() {
        return;
    }
    put_bytes(h, b"xshard_domain", b"XSHARD_REPLAY_V1");
    let mut consumed_sorted: Vec<CrossShardKey> = consumed.to_vec();
    consumed_sorted.sort();
    put_u64(h, b"xshard_consumed_len", consumed_sorted.len() as u64);
    for k in &consumed_sorted {
        put_u64(h, b"xshard_consumed_src", k.source_shard as u64);
        put_addr(h, b"xshard_consumed_blk", &k.finalized_in_block);
        put_addr(h, b"xshard_consumed_msg", &k.msg_id);
    }
    let mut produced_sorted: Vec<([u8; 32], u64)> = produced.to_vec();
    produced_sorted.sort();
    put_u64(h, b"xshard_produced_len", produced_sorted.len() as u64);
    for (tx_hash, height) in &produced_sorted {
        put_addr(h, b"xshard_produced_tx", tx_hash);
        put_u64(h, b"xshard_produced_h", *height);
    }
    let mut completed_sorted: Vec<[u8; 32]> = completed.to_vec();
    completed_sorted.sort();
    put_u64(h, b"xshard_completed_len", completed_sorted.len() as u64);
    for tx_hash in &completed_sorted {
        put_addr(h, b"xshard_completed_tx", tx_hash);
    }
}

fn commitment_digest_into(h: &mut Sha256, s: &CommitmentSnapshot) {
    put_u64(h, b"COMMITMENT_VERSION", COMMITMENT_VERSION as u64);
    tokens_digest(h, &s.tokens);
    staking_digest(h, &s.staking);
    pmm_digest(h, &s.pmm, &s.pmm_usdt_token, &s.pmm_treasury);
    contracts_digest(h, &s.contracts);
    escrow_digest(h, &s.order_escrow);
    governance_digest(h, &s.governance);
    oracle_digest(h, &s.oracle);
    // Conditional: included only when at least one session key is registered,
    // so an empty registry contributes zero bytes and the genesis root (and
    // every pre-session-key snapshot root) stays byte-identical.
    if !s.session_keys.is_empty() {
        session_keys_digest(h, &s.session_keys);
    }

    let mut books: BTreeMap<&u32, &crate::orderbook::OrderbookActor> = BTreeMap::new();
    for (k, v) in &s.orderbooks.books {
        books.insert(k, v);
    }
    put_u64(h, b"books_len", books.len() as u64);
    for (pair, book) in books {
        put_u64(h, b"book_pair", *pair as u64);
        book_digest(h, book);
    }

    // Conditional: included only when the bridge domain is NON-EMPTY (a replay
    // set entry, a parked withdrawal, a started rate window or a non-zero
    // escrow mirror), so a chain that has never bridged contributes ZERO bytes
    // here and the pinned genesis root stays byte-identical. APPENDED last so
    // every pre-bridge preimage keeps exactly the byte sequence it had.
    if !s.bridge.is_empty() {
        bridge_digest(h, &s.bridge);
    }

    // Conditional: included only when at least one cross-shard replay entry
    // exists (consumed credit, produced outbound, or completed lifecycle), so
    // a chain that never used cross-shard messaging contributes ZERO bytes
    // here and the pinned genesis root stays byte-identical. APPENDED after
    // the bridge domain so every pre-F1 preimage keeps exactly the byte
    // sequence it had. A non-empty replay set decides whether the next
    // inbound credits again (double mint if dropped), whether a bounce is
    // linkage-valid, and whether an ack completes - it must move the root.
    write_cross_shard_domain(
        h,
        &s.cross_shard_consumed,
        &s.cross_shard_produced,
        &s.cross_shard_completed,
    );
}

/// Digest of every consensus subsystem that lives outside the trie.
pub fn commitment_digest(s: &CommitmentSnapshot) -> [u8; 32] {
    let mut h = Sha256::new();
    commitment_digest_into(&mut h, s);
    h.finalize().into()
}

/// Confidential-aware commitment digest.
///
/// Appends the shielded-balance domain [`crate::crypto_privacy::ConfidentialState`]
/// after every existing field. The domain is CONDITIONAL and self-gating: an
/// empty state writes zero bytes, so this is byte-identical to
/// [`commitment_digest`] on any chain that has never used a confidential
/// transfer. That is what allows the domain to be folded in WITHOUT bumping
/// [`COMMITMENT_VERSION`] or re-pinning `tests/genesis_root_known_answer_tests.rs`.
///
/// Not yet called by the live path: the coordinator adds the
/// `CommitmentSnapshot` field and the engine lock, then routes
/// `commitment_digest` through this function (or calls
/// `crate::crypto_privacy::write_confidential_domain` directly inside
/// `commitment_digest_into`). Nothing else in this module changes.
pub fn commitment_digest_with_confidential(
    s: &CommitmentSnapshot,
    confidential: &crate::crypto_privacy::ConfidentialState,
) -> [u8; 32] {
    let mut h = Sha256::new();
    commitment_digest_into(&mut h, s);
    crate::crypto_privacy::write_confidential_domain(&mut h, confidential);
    h.finalize().into()
}

/// §2-aware commitment digest: the snapshot preimage, then the shielded
/// domain, then the zkML model-registry domain, then the zkML VK domain.
///
/// All three appended domains are CONDITIONAL and self-gating (empty writes
/// zero bytes), so this is byte-identical to [`commitment_digest`] on a chain
/// that has never used any of them - which is what lets the registry AND the
/// key set join the digest WITHOUT bumping [`COMMITMENT_VERSION`] or
/// re-pinning `tests/genesis_root_known_answer_tests.rs`. The zkML domains
/// are APPENDED last (models, then VKs) so every pre-SNARK preimage keeps
/// exactly the byte sequence it had.
///
/// This is the live-path digest: `InMemoryStateEngine` routes both
/// `commit_consensus_domains*` entry points through it.
pub fn commitment_digest_with_confidential_and_zkml(
    s: &CommitmentSnapshot,
    confidential: &crate::crypto_privacy::ConfidentialState,
    zkml_models: &crate::zkml::ZkMlModelRegistry,
) -> [u8; 32] {
    let mut h = Sha256::new();
    commitment_digest_into(&mut h, s);
    crate::crypto_privacy::write_confidential_domain(&mut h, confidential);
    zkml_models_digest_inner(&mut h, zkml_models);
    write_zkml_vks_domain(&mut h, zkml_models);
    h.finalize().into()
}

/// zkML-only commitment digest (for tests and callers with no shielded
/// state in scope): the snapshot preimage plus the conditional §2 domains.
pub fn commitment_digest_with_zkml(
    s: &CommitmentSnapshot,
    zkml_models: &crate::zkml::ZkMlModelRegistry,
) -> [u8; 32] {
    let mut h = Sha256::new();
    commitment_digest_into(&mut h, s);
    zkml_models_digest_inner(&mut h, zkml_models);
    write_zkml_vks_domain(&mut h, zkml_models);
    h.finalize().into()
}

