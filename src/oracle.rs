//! 3-Tier Price Safety Network & Oracle Module
//! Tier 1: Pull-Oracle (Pyth / RedStone style signed data in calldata)
//! Tier 2: On-Chain DEX TWAP fallback (30-60 min rolling window)
//! Tier 3: Circuit Breaker (>10% deviation / stale > 15 min / USDT depeg < $0.95)

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

pub const STALE_PRICE_MAX_SECS: u64 = 15 * 60; // 15 minutes
pub const MAX_PRICE_DEVIATION_BPS: u64 = 1000; // 10% = 1000 bps
/// Per-publisher consecutive-feed drift cap (audit O1 MEDIUM follow-up): HALF
/// the global 10% — the same key twice in a row may move an asset at most 5%
/// per feed. A single compromised publisher key can therefore walk the
/// baseline at most 5%/feed (three 5% steps ≈ +15.8%, vs +33% under the bare
/// 10% rule), while distinct-key feeds keep the full 10% rule and the breaker
/// latch condition (>10%, any key) is byte-for-byte unchanged.
///
/// Fail-closed without new consensus state: a same-key feed past 5% is
/// REFUSED (nothing committed) with a loud WARN but does NOT latch the
/// breaker — latching there would hand one key a chain-wide halt button for a
/// 3-day governance reset. Past 10% the global rule latches exactly as
/// before, so true moves still trip the alarm no matter who publishes them.
///
/// Explicitly NOT a TWAP-anchored guard (documented out of scope): anchoring
/// the commit to the 60-min TWAP would need committed TWAP history (new
/// consensus state, `COMMITMENT_VERSION` bump, snapshot migration) for a
/// read-path hint that today is advisory-only by design (`DexTwapCalculator`
/// / `OracleSafetyEngine` never commit). Key rotation stays Sybil-priced by
/// the governance publisher set (10k-STELL proposal + quorum + 3-day vote
/// per key), so alternating two keys still costs two admissions.
pub const MAX_SAME_PUBLISHER_DEVIATION_BPS: u64 = MAX_PRICE_DEVIATION_BPS / 2; // 5% = 500 bps
pub const USDT_MIN_PEG_MICRO_USD: u64 = 950_000; // $0.95 (in 6-decimals micro-USD)
pub const TWAP_WINDOW_SECS: u64 = 3600; // 60 minutes window for TWAP
/// Maximum committed asset-symbol size in bytes (E10).
///
/// `feeds` is committed consensus state keyed by the publisher-supplied
/// symbol. Without a shape rule, an authenticated (or governance-admitted)
/// publisher can bloat every node's state with megabyte keys or poison
/// lookups with empty/whitespace symbols. 32 bytes covers every real symbol
/// (`STELL`, `USDT`, `TON`, `BTC`, `STELL/USDT`); anything else is refused
/// before signature verification, commits nothing and latches nothing.
pub const MAX_ASSET_SYMBOL_BYTES: usize = 32;

/// Whether a feed asset symbol is committable (E10): non-empty, short, and
/// restricted to unambiguous characters. Pure and deterministic: byte-level,
/// no locale, no allocation.
pub fn is_valid_asset_symbol(asset: &str) -> bool {
    let b = asset.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_ASSET_SYMBOL_BYTES
        && b.iter().all(|c| {
            c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_' || *c == b'.' || *c == b'/'
        })
}

/// Freshness of a signed feed against the BLOCK timestamp.
///
/// Shared verbatim by commit time (`OracleState::commit_feed`) and read time
/// (`OracleSafetyEngine::resolve_price`): a check that only one of the two
/// performed would be a check an attacker picks the path for. Never a wall
/// clock - `block_time` is `block.timestamp`, the one value every node that
/// applies the block agrees on.
pub fn check_freshness(feed_timestamp: u64, block_time: u64) -> Result<(), String> {
    if feed_timestamp > block_time {
        return Err(format!(
            "price feed timestamp {feed_timestamp} is ahead of the block timestamp {block_time}"
        ));
    }
    let age = block_time - feed_timestamp;
    if age > STALE_PRICE_MAX_SECS {
        return Err(format!(
            "stale price feed: {age}s old exceeds the {STALE_PRICE_MAX_SECS}s limit"
        ));
    }
    Ok(())
}

/// USDT peg guard, shared by commit time and read time. Pure: the CALLER
/// decides whether a violation latches the breaker, because the read-time path
/// (`resolve_price`) has always latched while a caller may only want to ask.
pub fn check_usdt_peg(asset: &str, price_micro_usd: u64) -> Result<(), String> {
    if asset == "USDT" && price_micro_usd < USDT_MIN_PEG_MICRO_USD {
        return Err(format!(
            "USDT depeg detected (< ${:.2}). Circuit breaker engaged!",
            USDT_MIN_PEG_MICRO_USD as f64 / 1_000_000.0
        ));
    }
    Ok(())
}

/// Relative deviation between two prices in basis points, saturating instead of
/// overflowing: the breaker comparison must not wrap around a u64 multiply.
pub fn deviation_bps(price: u64, reference: u64) -> u64 {
    if reference == 0 {
        return if price == 0 { 0 } else { u64::MAX };
    }
    let diff = price.abs_diff(reference);
    ((diff as u128 * 10_000) / reference as u128).min(u64::MAX as u128) as u64
}

/// Base (priced) asset of a trading pair: the asset whose committed oracle
/// price an order's limit price is deviation-checked against.
pub fn pair_base_asset(pair_id: u32) -> Option<&'static str> {
    match pair_id {
        crate::orderbook::PAIR_STELL_USDT => Some("STELL"),
        _ => None,
    }
}

/// Quote asset of a trading pair: the asset whose peg the pair depends on.
pub fn pair_quote_asset(pair_id: u32) -> Option<&'static str> {
    match pair_id {
        crate::orderbook::PAIR_STELL_USDT => Some("USDT"),
        _ => None,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PriceFeedUpdate {
    pub asset: String,
    pub price_micro_usd: u64, // e.g. 1 STELL = $0.25 => 250_000
    pub timestamp: u64,
    pub publisher_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

impl PriceFeedUpdate {
    pub fn sign(
        asset: &str,
        price_micro_usd: u64,
        timestamp: u64,
        publisher_key: &SigningKey,
    ) -> Self {
        let mut msg = Vec::new();
        msg.extend_from_slice(asset.as_bytes());
        msg.extend_from_slice(&price_micro_usd.to_be_bytes());
        msg.extend_from_slice(&timestamp.to_be_bytes());

        let sig = publisher_key.sign(&msg);

        Self {
            asset: asset.to_string(),
            price_micro_usd,
            timestamp,
            publisher_pubkey: publisher_key.verifying_key().to_bytes(),
            signature: sig.to_vec(),
        }
    }

    pub fn verify(&self) -> bool {
        // P2-8 pure-PQ gate (fail-closed): classical ed25519 feed signatures
        // are refused under enforcement. Callers (`commit_feed`, pull-oracle
        // read path) already map `false` to refuse/fallback, so gating here
        // covers both with no behavior change when not enforced.
        if crate::post_quantum::is_pure_pq_enforced() {
            return false;
        }
        let Ok(vk) = VerifyingKey::from_bytes(&self.publisher_pubkey) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&self.signature) else {
            return false;
        };
        let mut msg = Vec::new();
        msg.extend_from_slice(self.asset.as_bytes());
        msg.extend_from_slice(&self.price_micro_usd.to_be_bytes());
        msg.extend_from_slice(&self.timestamp.to_be_bytes());
        vk.verify(&msg, &sig).is_ok()
    }
}

/// One price observation that a block has committed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedFeed {
    /// Price in micro-USD (6 decimals), exactly as the publisher signed it.
    pub price_micro_usd: u64,
    /// The publisher's own timestamp. Monotonicity per asset is defined on
    /// THIS field, so replaying an old feed is rejected even when it is still
    /// within the freshness window.
    pub timestamp: u64,
    /// Which committed publisher produced it (proven by the feed signature).
    pub publisher: [u8; 32],
}

/// The oracle as consensus state: what the state root commits to.
///
/// # Determinism
///
/// `publishers` is a `BTreeSet` and `feeds` a `BTreeMap`, so their iteration
/// order is a function of their contents and nothing else - the same
/// normalisation `commitment.rs` applies to every `HashMap` in the governance
/// and staking digests. A `HashMap` here would give two nodes with identical
/// oracle state different roots, i.e. a consensus split with no attacker.
///
/// # When it may change
///
/// Only when a block carries a signed feed: the sole writer on the live path
/// is `OpCode::SysCallSubmitPriceFeed`, executed during block application with
/// `ctx.timestamp = block.timestamp`. Gossip (`broadcast_price_feed` /
/// `fetch_price_feed`) and RPC never touch this - a node that never saw the
/// gossip applies identical state from the block alone.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleState {
    /// Publishers whose signatures a committed feed may carry. Empty by
    /// default: with no publishers nothing can ever be committed, which is the
    /// fail-closed starting point.
    pub publishers: BTreeSet<[u8; 32]>,
    /// Latest committed feed per asset, keyed by asset symbol.
    pub feeds: BTreeMap<String, CommittedFeed>,
    /// Circuit-breaker latch. Once true it refuses new feeds AND new orders
    /// until something deliberately resets it. Sticky by design: a gate that
    /// fires keeps the alarm even though its own transaction rolls back.
    pub breaker_tripped: bool,
}

impl OracleState {
    /// Commit a signed feed at `block_time`, applying every check the read
    /// path applies (`resolve_price`) through the SAME helper functions, plus
    /// the checks only a commit can do (publisher set, monotonicity).
    ///
    /// Returns the committed price, or `Err` with no price committed. A `Err`
    /// for the peg/deviation cases also latches `breaker_tripped`; the caller
    /// decides whether that latch survives (the VM rolls back price state but
    /// preserves the latch, see `state_engine::execute_payload`).
    pub fn commit_feed(&mut self, feed: &PriceFeedUpdate, block_time: u64) -> Result<u64, String> {
        // 0. Breaker latch: once tripped nothing gets through.
        if self.breaker_tripped {
            return Err("Circuit breaker is currently active. Trades paused.".to_string());
        }
        // 0a. Malformed-input guards (E9/E10): shape and sanity BEFORE
        // cryptography. A zero price or a junk symbol is malformed publisher
        // output, not market evidence, so it is refused WITHOUT latching
        // (latching would turn one fat-finger into a chain-wide halt until a
        // 3-day governance reset) and commits nothing.
        if !is_valid_asset_symbol(&feed.asset) {
            return Err(format!(
                "invalid asset symbol {:?}: must be 1..=32 ASCII alnum/-_./ chars",
                feed.asset
            ));
        }
        if feed.price_micro_usd == 0 {
            return Err(format!(
                "invalid oracle price 0 for {}: price must be > 0",
                feed.asset
            ));
        }
        // 1. Signature: the feed must be the publisher's own words.
        if !feed.verify() {
            return Err("invalid oracle signature".to_string());
        }
        // 2. Publisher set: a correctly signed feed from an unknown key is
        //    still an unknown key.
        if !self.publishers.contains(&feed.publisher_pubkey) {
            return Err("oracle publisher is not in the committed set".to_string());
        }
        // 3. Freshness against the BLOCK timestamp - the same check the
        //    read-time path runs (`check_freshness`).
        check_freshness(feed.timestamp, block_time)?;
        // 4. Monotonic per asset: an older observation can never replace a
        //    newer one, so a delayed/replayed feed cannot rewind the price.
        if let Some(prev) = self.feeds.get(&feed.asset) {
            if feed.timestamp <= prev.timestamp {
                return Err(format!(
                    "non-monotonic price feed for {}: timestamp {} does not exceed {}",
                    feed.asset, feed.timestamp, prev.timestamp
                ));
            }
        }
        // 5. USDT peg - the same check the read path runs, and it latches.
        if let Err(e) = check_usdt_peg(&feed.asset, feed.price_micro_usd) {
            self.breaker_tripped = true;
            return Err(e);
        }
        // 6. Deviation against the previously committed price: the Tier-3
        //    breaker rule with the last committed feed as the baseline (the
        //    on-chain analogue of the read path's TWAP reference).
        //
        //    RESIDUAL, TIGHTENED (audit O1, single-publisher baseline drift):
        //    the baseline is the last committed feed, so one publisher key
        //    walking it feed-by-feed is bounded by the per-publisher cap
        //    below: the SAME key twice in a row may move an asset at most
        //    `MAX_SAME_PUBLISHER_DEVIATION_BPS` (5%, half the global 10%).
        //    A same-key feed past 5% is refused WITHOUT latching (fail-closed,
        //    loud warn — a latch there would hand one key a chain-wide halt);
        //    past 10% the global rule latches exactly as before, regardless
        //    of key, so true moves still trip the alarm. Distinct-key feeds
        //    keep the full 10% rule (rotation stays Sybil-priced by the
        //    governance publisher set: 10k-STELL proposal + quorum + 3-day
        //    vote per key). Manipulation cost ≈ cost to compromise/bribe one
        //    publisher key per 5%-step (or pass one governance vote for a
        //    malicious publisher); a >10% single step latches the breaker
        //    (3-day governance reset).
        //    FULL-FIX PRECONDITION (deferred, explicitly out of scope):
        //    multi-publisher median/quorum or a TWAP-anchored commit guard
        //    (refuse-without-latch when the commit deviates >X% from the
        //    60-min TWAP) — both need committed TWAP history or a
        //    publisher-stake/slash design, i.e. new consensus state
        //    (`COMMITMENT_VERSION` bump + snapshot migration for an
        //    advisory-only read path), not a tightening of this function.
        if let Some(prev) = self.feeds.get(&feed.asset) {
            let bps = deviation_bps(feed.price_micro_usd, prev.price_micro_usd);
            if bps > MAX_PRICE_DEVIATION_BPS {
                self.breaker_tripped = true;
                return Err(format!(
                    "circuit breaker tripped: price deviation {bps} bps exceeds limit {MAX_PRICE_DEVIATION_BPS} bps"
                ));
            }
            if feed.publisher_pubkey == prev.publisher && bps > MAX_SAME_PUBLISHER_DEVIATION_BPS {
                tracing::warn!(
                    "ORACLE-SINGLE-PUBLISHER-DRIFT REFUSED {asset}: same publisher {pubkey} moved the committed baseline {bps} bps (cap {cap} bps, global {global} bps): feed refused, breaker NOT latched",
                    asset = feed.asset,
                    pubkey = hex::encode(feed.publisher_pubkey),
                    bps = bps,
                    cap = MAX_SAME_PUBLISHER_DEVIATION_BPS,
                    global = MAX_PRICE_DEVIATION_BPS,
                );
                return Err(format!(
                    "same-publisher drift refused for {}: deviation {bps} bps exceeds the per-publisher cap {MAX_SAME_PUBLISHER_DEVIATION_BPS} bps (global {MAX_PRICE_DEVIATION_BPS} bps)",
                    feed.asset
                ));
            }
        }

        let price = feed.price_micro_usd;
        self.feeds.insert(
            feed.asset.clone(),
            CommittedFeed {
                price_micro_usd: price,
                timestamp: feed.timestamp,
                publisher: feed.publisher_pubkey,
            },
        );
        Ok(price)
    }

    /// Authorise a publisher key in the committed registry.
    ///
    /// This is the ONLY way a key enters `publishers`, and its only caller is
    /// `Governance::execute_with_oracle` applying a passed
    /// `GovAction::RegisterOraclePublisher`. A committee-ratified action is the
    /// registration proof; there is deliberately no self-service call, because a
    /// publisher set anyone can extend is not a trusted set.
    ///
    /// Idempotent: returns whether the set actually changed, so a repeated
    /// (but valid) registration is observable as a no-op rather than a phantom
    /// state change.
    ///
    /// E6 defense-in-depth: the all-zero key is refused here too (returns
    /// `false`, inserts nothing), so even a caller that bypassed the
    /// governance execute-time backstop cannot commit a key that can never
    /// produce a feed.
    pub fn register_publisher(&mut self, publisher: [u8; 32]) -> bool {
        if publisher == [0u8; 32] {
            return false;
        }
        self.publishers.insert(publisher)
    }

    /// Revoke a publisher key. Feeds it already signed stay in `feeds` - they
    /// are committed history and cannot be un-observed - but no FUTURE feed may
    /// carry the key, so a compromised publisher is retired by one action.
    ///
    /// Idempotent: returns whether the set actually changed.
    pub fn unregister_publisher(&mut self, publisher: [u8; 32]) -> bool {
        self.publishers.remove(&publisher)
    }

    /// Clear the latched circuit breaker.
    ///
    /// Latching is automatic (a peg or deviation violation is evidence, not a
    /// request), but clearing it is a decision: only a passed
    /// `GovAction::ResetOracleBreaker` may call this. Returns whether the
    /// breaker was latched, so "reset an already-clear breaker" is a no-op the
    /// caller (and the committed proposal) can tell apart from a real reset.
    pub fn reset_breaker(&mut self) -> bool {
        std::mem::replace(&mut self.breaker_tripped, false)
    }

    /// Freshness of the COMMITTED feed for `asset` against the BLOCK
    /// timestamp (frozen-feed gate, audit BR-OR-03).
    ///
    /// `commit_feed` checks freshness at commit time, but a publisher that
    /// simply stops publishing leaves the last committed price in `feeds`
    /// indefinitely. A read path that prices orders against that entry without
    /// re-checking its age trades against a frozen oracle. No committed feed
    /// for `asset` admits (there is no price to be stale); a future-dated or
    /// over-age committed feed refuses. Pure: latches nothing, commits
    /// nothing.
    pub fn is_feed_fresh_at(&self, asset: &str, block_time: u64) -> Result<(), String> {
        let feed = self.feeds.get(asset).ok_or_else(|| {
            format!("no committed price feed for asset '{asset}'")
        })?;
        check_freshness(feed.timestamp, block_time).map_err(|e| {
            format!("frozen oracle feed for {asset}: {e}")
        })
    }

    /// Time-aware admission gate: [`OracleState::gate_order`] plus the
    /// frozen-feed refusal above (audit BR-OR-03).
    ///
    /// Additive-only: the legacy `gate_order(pair, price)` keeps its exact
    /// semantics (no clock, so it cannot age-check) for the wired callers in
    /// `svm`/`native_api`/`state_engine`. New integrations that have the
    /// block timestamp MUST prefer this: every committed feed the pair depends
    /// on (base asset, plus USDT when the pair is quoted in it) must be fresh
    /// at `block_time`, otherwise the order is refused without latching.
    /// Assets with no committed feed admit exactly as before.
    pub fn gate_order_at(
        &self,
        pair_id: u32,
        price_micro_usd: u64,
        block_time: u64,
    ) -> Result<(), String> {
        if self.breaker_tripped {
            return Err("Circuit breaker is currently active. Trades paused.".to_string());
        }
        if pair_quote_asset(pair_id).is_some() && self.feeds.contains_key("USDT") {
            self.is_feed_fresh_at("USDT", block_time)?;
        }
        if let Some(asset) = pair_base_asset(pair_id) {
            if self.feeds.contains_key(asset) {
                self.is_feed_fresh_at(asset, block_time)?;
            }
        }
        self.gate_order(pair_id, price_micro_usd)
    }

    /// Priority gate for order admission: breaker latch, USDT peg and price
    /// deviation against the committed price.
    ///
    /// Called VERBATIM by both entry points - `OpCode::SysCallPlaceOrder` in
    /// the VM and `InMemoryStateEngine::place_order_settled` - because a gate
    /// that only one of them runs is a gate an attacker routes around. With no
    /// committed feeds the gate has nothing to check and admits (that is not a
    /// bypass: there is no price to deviate from and no peg to break).
    ///
    /// Pure admission check (E3 fix): a violation REFUSES the order and
    /// latches NOTHING. The old code latched the breaker here, so ANY account
    /// could halt all trading chain-wide for days with one reverting
    /// limit order (the latch survived even its own transaction's revert).
    /// Latching is a publisher-fault response and lives ONLY in
    /// `commit_feed`, where the offender is an authenticated publisher, not
    /// a trader placing a far-away limit.
    pub fn gate_order(&self, pair_id: u32, price_micro_usd: u64) -> Result<(), String> {
        if self.breaker_tripped {
            return Err("Circuit breaker is currently active. Trades paused.".to_string());
        }
        // USDT peg: this pair is quoted in USDT, so a depegged committed USDT
        // price pauses trading rather than pricing orders against it.
        // (Read-only: a trader's order never trips the breaker for this.)
        if pair_quote_asset(pair_id).is_some() {
            if let Some(usdt) = self.feeds.get("USDT") {
                check_usdt_peg("USDT", usdt.price_micro_usd)?;
            }
        }
        // Deviation: the limit price must be within MAX_PRICE_DEVIATION_BPS of
        // the committed price for the pair's base asset. Far-away limit
        // orders are simply refused (they may still be legitimate market
        // views, just not executable against this reference).
        if let Some(asset) = pair_base_asset(pair_id) {
            if let Some(committed) = self.feeds.get(asset) {
                let bps = deviation_bps(price_micro_usd, committed.price_micro_usd);
                if bps > MAX_PRICE_DEVIATION_BPS {
                    return Err(format!(
                        "order price deviates {bps} bps from the committed {asset} price (limit {MAX_PRICE_DEVIATION_BPS} bps)"
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TradeObservation {
    pub price: u64,
    pub timestamp: u64,
    pub volume: u64,
}

/// Rolling On-Chain DEX TWAP Calculator (30-60 min)
#[derive(Clone, Debug, Default)]
pub struct DexTwapCalculator {
    pub observations: HashMap<String, VecDeque<TradeObservation>>,
}

impl DexTwapCalculator {
    pub fn new() -> Self {
        Self {
            observations: HashMap::new(),
        }
    }

    pub fn record_trade(&mut self, asset: &str, price: u64, timestamp: u64, volume: u64) {
        let history = self.observations.entry(asset.to_string()).or_default();
        history.push_back(TradeObservation {
            price,
            timestamp,
            volume: volume.max(1),
        });

        // Prune older observations beyond the 1-hour window
        let cutoff = timestamp.saturating_sub(TWAP_WINDOW_SECS);
        while let Some(front) = history.front() {
            if front.timestamp < cutoff {
                history.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn calculate_twap(&self, asset: &str, current_time: u64) -> Option<u64> {
        let history = self.observations.get(asset)?;
        if history.is_empty() {
            return None;
        }

        let cutoff = current_time.saturating_sub(TWAP_WINDOW_SECS);
        let mut total_vol_price: u128 = 0;
        let mut total_vol: u128 = 0;

        for obs in history.iter().rev() {
            if obs.timestamp < cutoff {
                break;
            }
            total_vol_price += (obs.price as u128) * (obs.volume as u128);
            total_vol += obs.volume as u128;
        }

        if total_vol == 0 {
            return history.back().map(|o| o.price);
        }

        Some((total_vol_price / total_vol) as u64)
    }
}

/// Advisory-only price resolver: its TWAP fallback is a READ-PATH hint, never consensus.
/// NOT consensus: no block commits `dex_twap_prices`; `OracleState::commit_feed` is the sole price writer.
/// Order admission consults committed feeds via `gate_order`, never this engine's TWAP.
pub struct OracleSafetyEngine {
    pub trusted_publishers: Vec<[u8; 32]>,
    pub dex_twap_prices: HashMap<String, u64>,
    pub twap_calculator: DexTwapCalculator,
    pub circuit_breaker_triggered: bool,
}

impl OracleSafetyEngine {
    pub fn new(trusted_publishers: Vec<[u8; 32]>) -> Self {
        Self {
            trusted_publishers,
            dex_twap_prices: HashMap::new(),
            twap_calculator: DexTwapCalculator::new(),
            circuit_breaker_triggered: false,
        }
    }

    pub fn set_dex_twap(&mut self, asset: &str, price_micro_usd: u64) {
        self.dex_twap_prices
            .insert(asset.to_string(), price_micro_usd);
    }

    pub fn record_dex_trade(
        &mut self,
        asset: &str,
        price_micro_usd: u64,
        timestamp: u64,
        volume: u64,
    ) {
        self.twap_calculator
            .record_trade(asset, price_micro_usd, timestamp, volume);
        if let Some(twap) = self.twap_calculator.calculate_twap(asset, timestamp) {
            self.dex_twap_prices.insert(asset.to_string(), twap);
        }
    }

    pub fn reset_circuit_breaker(&mut self) {
        self.circuit_breaker_triggered = false;
    }

    /// Resolve and validate asset price following 3-tier protection.
    ///
    /// The freshness, peg and deviation checks are the SAME helper functions
    /// `OracleState::commit_feed` runs (`check_freshness`, `check_usdt_peg`,
    /// `deviation_bps`), so "commit-time" and "read-time" validation cannot
    /// drift into two different rules for the same price.
    pub fn resolve_price(
        &mut self,
        feed: Option<&PriceFeedUpdate>,
        asset: &str,
        current_time: u64,
    ) -> Result<u64, String> {
        if self.circuit_breaker_triggered {
            return Err("Circuit breaker is currently active. Trades paused.".to_string());
        }

        // Hardcoded check for USDT peg
        if asset == "USDT" {
            let usdt_price = if let Some(update) = feed {
                update.price_micro_usd
            } else {
                1_000_000
            };

            if let Err(e) = check_usdt_peg(asset, usdt_price) {
                self.circuit_breaker_triggered = true;
                return Err(e);
            }
            return Ok(1_000_000); // 1.00 USD
        }

        // Tier 1: Try Pull-Oracle
        //
        // AUDIT BR-OR-01/BR-OR-02: the feed must name THIS asset and carry a
        // positive price. Without the asset check a correctly signed feed for
        // asset B priced asset A (cross-asset confusion: one signed BTC feed
        // could move — or, via the Tier-3 deviation rule, halt — STELL
        // trading). Without the price check a zero-price feed from a trusted
        // publisher was returned verbatim when no TWAP reference existed,
        // while the commit path (`commit_feed`) refuses zero prices outright.
        // A feed failing either check is ignored (TWAP fallback), never
        // chosen: refusing to invent a price is the fail-closed direction.
        let mut chosen_price: Option<u64> = None;
        if let Some(update) = feed {
            if update.asset == asset
                && update.price_micro_usd > 0
                && update.verify()
                && self.trusted_publishers.contains(&update.publisher_pubkey)
                // Check freshness (reject if older than 15 minutes / in the future)
                && check_freshness(update.timestamp, current_time).is_ok()
            {
                chosen_price = Some(update.price_micro_usd);
            }
        }

        // Tier 2: Fallback to on-chain DEX TWAP if Tier 1 failed or stale
        let price = match chosen_price {
            Some(p) => p,
            None => {
                let twap_calc = self.twap_calculator.calculate_twap(asset, current_time);
                match twap_calc {
                    Some(p) => p,
                    None => *self.dex_twap_prices.get(asset).ok_or_else(|| {
                        "No valid price source: Pull oracle failed/stale and no DEX TWAP available".to_string()
                    })?,
                }
            }
        };

        // Tier 3: Circuit Breaker validation against TWAP
        let twap_ref = self
            .twap_calculator
            .calculate_twap(asset, current_time)
            .or_else(|| self.dex_twap_prices.get(asset).copied());

        if let Some(twap) = twap_ref {
            if twap > 0 {
                let deviation_bps = deviation_bps(price, twap);

                if deviation_bps > MAX_PRICE_DEVIATION_BPS {
                    self.circuit_breaker_triggered = true;
                    return Err(format!(
                        "Circuit breaker tripped: price deviation {} bps exceeds limit {} bps",
                        deviation_bps, MAX_PRICE_DEVIATION_BPS
                    ));
                }
            }
        }

        Ok(price)
    }
}

#[cfg(test)]
mod pq_gate_tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    struct PurePqGuard;
    impl PurePqGuard {
        fn enforce() -> Self {
            crate::post_quantum::set_pure_pq_override(Some(true));
            Self
        }
    }
    impl Drop for PurePqGuard {
        fn drop(&mut self) {
            crate::post_quantum::set_pure_pq_override(None);
        }
    }

    fn signed_feed() -> (PriceFeedUpdate, OracleState) {
        let sk = SigningKey::from_bytes(&[0x31u8; 32]);
        let feed = PriceFeedUpdate::sign("STELL", 250_000, 1_000, &sk);
        let mut state = OracleState::default();
        state.publishers.insert(sk.verifying_key().to_bytes());
        (feed, state)
    }

    /// P2-8 pure-PQ gate: a VALID ed25519 feed verifies/commits with
    /// enforcement off but `verify()` is false and `commit_feed` errs with
    /// enforcement on. Guard reset proves mid-suite flag-flip isolation.
    #[test]
    fn pure_pq_refuses_classical_feed() {
        let (feed, mut state) = signed_feed();

        // Baseline (off): valid ed feed verifies and commits.
        assert!(feed.verify(), "valid ed feed must verify when pure-PQ is off");
        assert!(
            state.commit_feed(&feed, 1_001).is_ok(),
            "valid ed feed must commit when pure-PQ is off"
        );

        // Enforced: the SAME valid feed is refused fail-closed.
        {
            let _guard = PurePqGuard::enforce();
            assert!(
                !feed.verify(),
                "valid ed feed must NOT verify under pure-PQ"
            );
            let mut enforced_state = OracleState::default();
            enforced_state
                .publishers
                .insert(feed.publisher_pubkey);
            assert!(
                enforced_state.commit_feed(&feed, 1_001).is_err(),
                "ed feed must not commit under pure-PQ"
            );
        }

        // Boundary: after guard drop we are back off.
        assert!(
            feed.verify(),
            "post-guard behavior must be off again"
        );
    }
}
