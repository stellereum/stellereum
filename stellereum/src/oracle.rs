//! 3-Tier Price Safety Network & Oracle Module
//! Tier 1: Pull-Oracle (Pyth / RedStone style signed data in calldata)
//! Tier 2: On-Chain DEX TWAP fallback (~91 s rolling VWAP window, W* optimum)
//! Tier 3: Circuit Breaker (>10% deviation / stale > 15 min / USDT depeg < $0.95)

use crate::post_quantum::{FalconKeypair, FALCON512_PUBKEY_LEN};
use ed25519_dalek::{Signer, SigningKey};
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
/// the commit to the TWAP window would need committed TWAP history (new
/// consensus state, `COMMITMENT_VERSION` bump, snapshot migration) for a
/// read-path hint that today is advisory-only by design (`DexTwapCalculator`
/// / `OracleSafetyEngine` never commit). Key rotation stays Sybil-priced by
/// the governance publisher set (10k-STELL proposal + quorum + 3-day vote
/// per key), so alternating two keys still costs two admissions.
pub const MAX_SAME_PUBLISHER_DEVIATION_BPS: u64 = MAX_PRICE_DEVIATION_BPS / 2; // 5% = 500 bps
pub const USDT_MIN_PEG_MICRO_USD: u64 = 950_000; // $0.95 (in 6-decimals micro-USD)
/// Rolling VWAP window in seconds: W* ≈ 91 s optimum (report P4 §2, Eq. 2).
///
/// VALUE NOTE (frozen-economics audit 2026-11-05, math ref
/// `stellereum-math/papers/04_oracle.md` + `results/twap.json`): the prior
/// 3600 s window was ≈40× the MSE optimum (σ=5%/day, one-block 10% shift J:
/// W*=(6(JΔt)²/σ²)^(1/3)=90.7 s at 0.6 s blocks; MSE at 3600 s ≈26× worse
/// than at W*). OBSERVATIONAL-ONLY change. Classification proof: the ONLY
/// readers of this constant are the two `DexTwapCalculator` methods below,
/// consumed solely by the advisory-only `OracleSafetyEngine` Tier-2 fallback
/// and Tier-3 read-path check. Consensus commits `OracleState` only — see
/// the `oracle_digest` commitment function and the persisted `oracle` field
/// in storage — and apply-path admission goes through `OracleState`
/// `commit_feed`/`gate_order` in svm, state_engine and native_api, which
/// never touch this constant. Live main.rs uses the engine for demo/CLI
/// display only. No apply, commitment or snapshot path reads it. Pinned by
/// the `twap_window_is_w_star_91s` test below.
///
/// CAVEAT (report §2, FOR-LEAD-DECISION): Eq. 2 models a ONE-BLOCK shift;
/// a shifter that HOLDS J for the whole window is not diluted by it —
/// long-window protection there is attack-cost, not statistics. Both
/// regimes must be fixed in the oracle spec before retuning again.
pub const TWAP_WINDOW_SECS: u64 = 91; // W* ≈ 91 s (was 3600 s)
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

/// PROPOSAL ONLY — optimal VWAP window, cubic-root law (report P4 §2, Eq. 2).
///
/// FOR-LEAD-DECISION: not wired anywhere (`TWAP_WINDOW_SECS` stays the only
/// live window). Pure reference math for the lead's decision, exercised only
/// by the tests in this file. W* = (6·(J·Δt)²/σ²)^(1/3): `shift_times_dt`
/// is the one-block manipulation impulse J·Δt and `sigma` the per-SECOND
/// volatility, in consistent relative-price units. E.g. σ=5%/day
/// (σ≈1.701e-4/s), J=10% on a 0.6 s block → W*≈90.7 s (twap.json row).
/// Returns +∞ for zero volatility (no variance term to balance).
pub fn twap_optimal_window_secs(shift_times_dt: f64, sigma_per_sec: f64) -> f64 {
    if sigma_per_sec <= 0.0 || !sigma_per_sec.is_finite() {
        return f64::INFINITY;
    }
    (6.0 * shift_times_dt * shift_times_dt / (sigma_per_sec * sigma_per_sec)).cbrt()
}

/// Wald SPRT decision boundaries (report P4 §4).
///
/// Wired by the height-gated Tier-3 below ([`tier3_breaker_tripped`]): the
/// live check stays the fixed 10% `MAX_PRICE_DEVIATION_BPS` breaker while
/// the gate is inactive (see [`SPRT_TIER3_ACTIVATION_HEIGHT`]). Pure math,
/// tested below.
/// Returns (A, B) = (ln((1−β)/α), ln(β/(1−α))).
pub fn sprt_wald_bounds(alpha: f64, beta: f64) -> (f64, f64) {
    debug_assert!(alpha > 0.0 && alpha < 1.0 && beta > 0.0 && beta < 1.0);
    let a = ((1.0 - beta) / alpha).ln();
    let b = (beta / (1.0 - alpha)).ln();
    (a, b)
}

/// One CUSUM/SPRT log-likelihood step for N(0,σ²) vs N(J,σ²).
///
/// Wired by the height-gated Tier-3 below ([`sprt_tier3_llr_sum`]).
/// LLR_r step for a relative-price residual x: (J/σ²)·x − J²/(2σ²).
/// Accumulate while the running sum stays within the [`sprt_wald_bounds`]
/// interval; crossing A accepts H1 (shift), crossing B accepts H0.
/// Pure and deterministic.
pub fn cusum_llr_step(residual: f64, shift: f64, sigma: f64) -> f64 {
    (shift / (sigma * sigma)) * residual - shift * shift / (2.0 * sigma * sigma)
}

/// Expected SPRT samples to decide under H1 (report P4 §4, Eq. 5, Wald
/// identity): E[N|H1] = ((1−β)·A + β·B) / (J²/(2σ²)).
/// Wired by the height-gated Tier-3 below ([`sprt_tier3_expected_samples`]).
/// E.g. J=1%, σ=0.5%/block, α=β=1e-3 → ≈3.45 blocks (twap.json `sprt` table).
pub fn sprt_expected_samples(alpha: f64, beta: f64, shift: f64, sigma: f64) -> f64 {
    let (a, b) = sprt_wald_bounds(alpha, beta);
    ((1.0 - beta) * a + beta * b) / (shift * shift / (2.0 * sigma * sigma))
}

/// Tier-3 SPRT activation height (report P4 §4, Eq. 5; twap.json `sprt`).
///
/// GATE SEMANTICS: at block `height < SPRT_TIER3_ACTIVATION_HEIGHT` the Tier-3
/// check is the historical fixed 10% `MAX_PRICE_DEVIATION_BPS` rule,
/// byte-for-byte. At `height >= SPRT_TIER3_ACTIVATION_HEIGHT` the Tier-3
/// check is the Wald SPRT/CUSUM decision over recent relative-price residuals
/// (accumulated via [`cusum_llr_step`], decided against [`sprt_wald_bounds`]
/// at [`SPRT_TIER3_ALPHA`]/[`SPRT_TIER3_BETA`]).
///
/// INACTIVE BY DEFAULT (`u64::MAX`): no live height can reach the gate, so
/// current behavior is unchanged until the lead explicitly flips this constant
/// at rollout. ADVISORY-ONLY: consumed solely by the read-path
/// `OracleSafetyEngine` Tier-3; consensus admission
/// (`OracleState::commit_feed`/`gate_order`) never reads it and is untouched.
pub const SPRT_TIER3_ACTIVATION_HEIGHT: u64 = u64::MAX;
/// Tier-3 SPRT false-alarm rate (report P4 §4; twap.json `sprt` rows pin
/// α=β=1e-3).
pub const SPRT_TIER3_ALPHA: f64 = 1e-3;
/// Tier-3 SPRT miss rate (report P4 §4; twap.json `sprt` rows pin α=β=1e-3).
pub const SPRT_TIER3_BETA: f64 = 1e-3;
/// Default Tier-3 SPRT target shift: 1% sustained relative-price move.
/// The pure decision path takes an explicit shift so every twap.json `sprt`
/// row stays provable; this default only feeds the height-0 delegation of
/// `OracleSafetyEngine::resolve_price`, whose SPRT branch is unreachable
/// while the gate is inactive.
pub const SPRT_TIER3_SHIFT: f64 = 0.01;
/// Default Tier-3 SPRT per-block volatility: 0.5%/block (first twap.json
/// `sprt` row). Same delegation-only role as [`SPRT_TIER3_SHIFT`].
pub const SPRT_TIER3_SIGMA_PER_BLOCK: f64 = 0.005;

/// Height gate predicate: true iff the SPRT Tier-3 is live at `height`.
/// Pure: integer comparison only.
#[allow(clippy::absurd_extreme_comparisons)] // GATE: `>=` is the rollout-correct form — at the INACTIVE default (u64::MAX) it reduces to `== MAX`; once the lead flips the constant down it becomes a real range check. `==` would silently deactivate every height above a flipped gate.
pub fn sprt_tier3_active_at(height: u64) -> bool {
    height >= SPRT_TIER3_ACTIVATION_HEIGHT
}

/// Accumulated Tier-3 SPRT log-likelihood over `residuals` (relative-price
/// deviations, oldest first) for N(0,σ²) vs N(J,σ²), reusing
/// [`cusum_llr_step`]. Pure and deterministic: strict slice-order summation,
/// no wall-clock, no RNG, no map iteration (see determinism note on
/// [`tier3_breaker_tripped`]).
pub fn sprt_tier3_llr_sum(residuals: &[f64], shift: f64, sigma: f64) -> f64 {
    let mut acc = 0.0;
    for r in residuals {
        acc += cusum_llr_step(*r, shift, sigma);
    }
    acc
}

/// Live Tier-3 SPRT verdict at the report error rates
/// ([`SPRT_TIER3_ALPHA`]/[`SPRT_TIER3_BETA`]): true = H1 accepted, the
/// breaker trips. Pure and deterministic.
pub fn sprt_tier3_decision(residuals: &[f64], shift: f64, sigma: f64) -> bool {
    let (a, _b) = sprt_wald_bounds(SPRT_TIER3_ALPHA, SPRT_TIER3_BETA);
    sprt_tier3_llr_sum(residuals, shift, sigma) >= a
}

/// Wired Tier-3 expectation under H1 at the report error rates (Eq. 5):
/// pins [`sprt_expected_samples`] to [`SPRT_TIER3_ALPHA`]/[`SPRT_TIER3_BETA`]
/// so the twap.json `sprt` rows are provable through the wired path, not just
/// the bare helper. Pure and deterministic.
pub fn sprt_tier3_expected_samples(shift: f64, sigma: f64) -> f64 {
    sprt_expected_samples(SPRT_TIER3_ALPHA, SPRT_TIER3_BETA, shift, sigma)
}

/// Height-gated Tier-3 breaker (the WIRED path).
///
/// Below [`SPRT_TIER3_ACTIVATION_HEIGHT`]: the historical fixed rule —
/// `deviation_bps(price, twap) > MAX_PRICE_DEVIATION_BPS` — integer bps,
/// exact, byte-identical to the pre-SPRT behavior. The SPRT history is
/// ignored on this branch.
/// At/above it: the [`sprt_tier3_decision`] verdict over `sprt_residuals`
/// (one relative deviation per block, oldest first); the single
/// price-vs-twap comparison is ignored on this branch.
///
/// DETERMINISM DISCIPLINE: the fixed branch is integer exact arithmetic.
/// The SPRT branch is IEEE-754 binary64 with slice-order accumulation — bit
/// for bit reproducible for identical input sequences on every node (no
/// fused operations across terms, no data-dependent branching, no
/// wall-clock/RNG/locale). Callers must derive each residual from committed
/// integer micro-USD values in block order, e.g.
/// `(price_micro_usd as f64 - twap_micro_usd as f64) / twap_micro_usd as f64`.
/// Where the report allows, prefer the integer-bps fixed branch; the f64
/// path above is documented here rather than hidden.
pub fn tier3_breaker_tripped(
    price_micro_usd: u64,
    twap_micro_usd: u64,
    height: u64,
    sprt_residuals: &[f64],
    sprt_shift: f64,
    sprt_sigma: f64,
) -> bool {
    if sprt_tier3_active_at(height) {
        return sprt_tier3_decision(sprt_residuals, sprt_shift, sprt_sigma);
    }
    deviation_bps(price_micro_usd, twap_micro_usd) > MAX_PRICE_DEVIATION_BPS
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
        // FULL-PQ: classical ed25519 feed verification is REMOVED.
        // No PQ feed path exists in this zone (wire frozen); fail closed.
        // Callers (`commit_feed`, pull-oracle read path) already map `false`
        // to refuse, so this is the PQ-only behavior.
        false
    }
}

/// Falcon-512 price feed: the PQ successor of [`PriceFeedUpdate`].
///
/// WIRE NOTE: [`PriceFeedUpdate`] is byte-frozen consensus wire and its
/// `verify()` fail-closes (always false) now that no classical feed path
/// exists. This is a NEW, ADDITIVE type — old bytes decode exactly as before
/// (the Ed struct is untouched above) and these bytes never alias the Ed
/// layout, so the frozen wire is preserved while a valid feed exists again.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqPriceFeedUpdate {
    pub asset: String,
    pub price_micro_usd: u64, // e.g. 1 STELL = $0.25 => 250_000
    pub timestamp: u64,
    /// Full 897-byte Falcon-512 public key, carried inline (see identity note).
    ///
    /// `Vec` (not `[u8; 897]`) because serde only derives `Deserialize` for
    /// arrays up to 32 elements; length is enforced fail-closed instead —
    /// `verify()` returns false on any non-897-byte key and
    /// `register_pq_publisher` refuses to register one.
    pub publisher_falcon_pubkey: Vec<u8>,
    /// 666-byte Falcon-512 signature over the feed message.
    pub falcon_sig: Vec<u8>,
}

impl PqPriceFeedUpdate {
    pub fn sign(
        asset: &str,
        price_micro_usd: u64,
        timestamp: u64,
        publisher_key: &FalconKeypair,
    ) -> Self {
        // Message layout mirrors `PriceFeedUpdate::sign` byte-for-byte
        // (asset bytes || price_be || timestamp_be); only the signature scheme
        // changes. Keep the two constructions in lockstep.
        let mut msg = Vec::new();
        msg.extend_from_slice(asset.as_bytes());
        msg.extend_from_slice(&price_micro_usd.to_be_bytes());
        msg.extend_from_slice(&timestamp.to_be_bytes());

        let sig = publisher_key.sign(&msg);

        Self {
            asset: asset.to_string(),
            price_micro_usd,
            timestamp,
            publisher_falcon_pubkey: publisher_key.pubkey().to_vec(),
            falcon_sig: sig,
        }
    }

    pub fn verify(&self) -> bool {
        // Same message layout as `PriceFeedUpdate::sign`; verified with the
        // tree's existing Falcon-512 verifier — the same function validator
        // votes verify against (`Vote::verify_uncached` via
        // `crate::consensus::verify_falcon_signature`, i.e. real FIPS 206 in
        // every build). Wrong-length keys/sigs fail closed inside it.
        let mut msg = Vec::new();
        msg.extend_from_slice(self.asset.as_bytes());
        msg.extend_from_slice(&self.price_micro_usd.to_be_bytes());
        msg.extend_from_slice(&self.timestamp.to_be_bytes());

        crate::consensus::verify_falcon_signature(
            &self.publisher_falcon_pubkey,
            &msg,
            &self.falcon_sig,
        )
    }
}

/// 32-byte consensus binding of a Falcon-512 publisher key.
///
/// PUBLISHER IDENTITY (no Ed alias): an 897-byte Falcon-512 key CANNOT fit in
/// the `[u8; 32]` publisher slots (`OracleState.publishers`,
/// `CommittedFeed.publisher`, governance `RegisterOraclePublisher`), so those
/// slots hold THIS binding — never an Ed25519 key, never a truncation. The
/// feed signature is verified against the full inline 897-byte key and
/// admission requires this binding in the committed set, so the identity is
/// Falcon-key-bound end to end.
///
/// Reusing the existing `[u8; 32]` slots (instead of widening consensus state)
/// keeps the commitment digest layout (`commitment.rs` `oracle_digest`) and
/// the governance action wire byte-identical: no `COMMITMENT_VERSION` bump,
/// no snapshot migration. Cross-type confusion would need an Ed25519 public
/// key equal to a BLAKE3 digest of a Falcon key (second preimage) — infeasible.
pub fn pq_publisher_binding(falcon_pubkey: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("STELL_ORACLE_PQ_BIND_V1");
    h.update(falcon_pubkey);
    *h.finalize().as_bytes()
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
    /// Genesis anchor price per asset (micro-USD), set to the committed price
    /// on the FIRST commit per asset and NEVER ratcheted afterwards.
    ///
    /// WHY THE ANCHOR MUST NOT MOVE: the per-step caps above ratchet the
    /// baseline forward — each committed feed becomes the next step's
    /// reference — so a slow walk (+5%/feed, inside every per-step cap)
    /// escapes any step-relative guard while drifting +15.8% over three
    /// steps. The cumulative latch in `commit_feed_pq` measures against THIS
    /// anchor instead, so the walk trips the breaker once the total drift
    /// exceeds `MAX_PRICE_DEVIATION_BPS` no matter how small the steps are.
    /// A moved anchor is a moved goalpost; genesis is the only goalpost that
    /// cannot be walked.
    #[serde(default)]
    pub anchor_price_micro_usd: BTreeMap<String, u64>,
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
        //    TWAP window) — both need committed TWAP history or a
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

    /// Commit a Falcon-signed feed at `block_time`.
    ///
    /// MIRROR of [`Self::commit_feed`]: every check is the same (breaker
    /// latch, symbol/price shape, membership, freshness, monotonicity, USDT
    /// peg, 10% deviation + 5% same-publisher cap, same latch semantics, same
    /// error strings), only the signature scheme changes — Falcon `verify()`
    /// over the full inline key plus membership of the key's
    /// [`pq_publisher_binding`] in the committed set. Keep the two functions
    /// in lockstep: any rule change applies to both.
    ///
    /// Returns the committed price, or `Err` with no price committed. A `Err`
    /// for the peg/deviation cases also latches `breaker_tripped`, exactly
    /// like [`Self::commit_feed`].
    pub fn commit_feed_pq(
        &mut self,
        feed: &PqPriceFeedUpdate,
        block_time: u64,
    ) -> Result<u64, String> {
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
        // 1. Signature: the feed must be the publisher's own words (Falcon).
        if !feed.verify() {
            return Err("invalid oracle signature".to_string());
        }
        // 2. Publisher set: a correctly signed feed from a key outside the
        //    committed set is still an unknown key. The set holds
        //    [`pq_publisher_binding`]s (see its docs for why the raw 897-byte
        //    key cannot live there), so membership is checked on the binding.
        let binding = pq_publisher_binding(&feed.publisher_falcon_pubkey);
        if !self.publishers.contains(&binding) {
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
        //    on-chain analogue of the read path's TWAP reference). Same
        //    per-publisher cap as [`Self::commit_feed`]: the SAME key twice in
        //    a row may move an asset at most `MAX_SAME_PUBLISHER_DEVIATION_BPS`
        //    (5%); past 10% the global rule latches regardless of key. Key
        //    equality here is binding equality — a Falcon key re-signing under
        //    the same key carries the same binding, a rotated key a different
        //    one — so same-key walks and rotations behave exactly as on the Ed
        //    path. See `commit_feed` step 6 for the full residual/deferred-fix
        //    rationale, which applies verbatim.
        if let Some(prev) = self.feeds.get(&feed.asset) {
            let bps = deviation_bps(feed.price_micro_usd, prev.price_micro_usd);
            if bps > MAX_PRICE_DEVIATION_BPS {
                self.breaker_tripped = true;
                return Err(format!(
                    "circuit breaker tripped: price deviation {bps} bps exceeds limit {MAX_PRICE_DEVIATION_BPS} bps"
                ));
            }
            if binding == prev.publisher && bps > MAX_SAME_PUBLISHER_DEVIATION_BPS {
                tracing::warn!(
                    "ORACLE-SINGLE-PUBLISHER-DRIFT REFUSED {asset}: same publisher {pubkey} moved the committed baseline {bps} bps (cap {cap} bps, global {global} bps): feed refused, breaker NOT latched",
                    asset = feed.asset,
                    pubkey = hex::encode(binding),
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
        // 6b. Cumulative-drift latch (B-GOV/O1): deviation of the CANDIDATE
        // price against the GENESIS anchor (`anchor_price_micro_usd`), NOT the
        // last feed. Per-step caps ratchet the baseline forward, so a slow
        // walk stays inside every step while the total escapes; the anchor
        // never moves, so the total cannot escape this. First commit per
        // asset sets the anchor and passes (there is no drift from oneself);
        // a legacy asset with a feed but no anchor yet (pre-latch state,
        // direct-insert fixtures) is treated the same way — anchored at the
        // candidate price, passing this once — so rollout needs no height
        // gate and no migration. Past `MAX_PRICE_DEVIATION_BPS` cumulative
        // (same 10% const, no new threshold) the breaker latches fail-closed
        // with the same latch semantics as every other breaker trip, and the
        // feed commits nothing.
        //
        // Ed `commit_feed` path: INTENTIONALLY untouched — that path is
        // dead/refusing by design (`PriceFeedUpdate::verify` always fails
        // closed under FULL-PQ), so no feed can commit through it and there
        // is no walk to latch there. Keep the two functions' RULES in
        // lockstep if the Ed path ever lives again.
        if let Some(&anchor) = self.anchor_price_micro_usd.get(&feed.asset) {
            let cumulative_bps = deviation_bps(feed.price_micro_usd, anchor);
            if cumulative_bps > MAX_PRICE_DEVIATION_BPS {
                self.breaker_tripped = true;
                return Err(format!(
                    "circuit breaker tripped: cumulative price drift {cumulative_bps} bps from genesis anchor exceeds limit {MAX_PRICE_DEVIATION_BPS} bps"
                ));
            }
        }

        let price = feed.price_micro_usd;
        // Genesis anchor: set once, on the first commit per asset, and never
        // ratcheted afterwards (see the field docs for why it must not move).
        // `or_insert` keeps a legacy anchor (pre-latch state anchored above)
        // instead of overwriting it.
        self.anchor_price_micro_usd
            .entry(feed.asset.clone())
            .or_insert(price);
        self.feeds.insert(
            feed.asset.clone(),
            CommittedFeed {
                price_micro_usd: price,
                timestamp: feed.timestamp,
                publisher: binding,
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

    /// Authorise a Falcon-512 publisher key in the committed registry.
    ///
    /// PQ counterpart of [`Self::register_publisher`]: the committed set holds
    /// [`pq_publisher_binding`]s, so this binds the 897-byte key and inserts
    /// the binding (idempotent, returns whether the set changed). A
    /// wrong-length key is refused (`false`, inserts nothing) — the shape
    /// analogue of the all-zero-key refusal in `register_publisher`: only a
    /// real Falcon-512 key can ever produce a committable feed.
    pub fn register_pq_publisher(&mut self, falcon_pubkey: &[u8]) -> bool {
        if falcon_pubkey.len() != FALCON512_PUBKEY_LEN {
            return false;
        }
        self.register_publisher(pq_publisher_binding(falcon_pubkey))
    }

    /// Revoke a Falcon-512 publisher key. Like [`Self::unregister_publisher`],
    /// already-committed feeds stay (committed history cannot be un-observed)
    /// while no FUTURE feed may carry the key. Idempotent: returns whether the
    /// set actually changed. A wrong-length key removes nothing (`false`).
    pub fn unregister_pq_publisher(&mut self, falcon_pubkey: &[u8]) -> bool {
        if falcon_pubkey.len() != FALCON512_PUBKEY_LEN {
            return false;
        }
        self.unregister_publisher(pq_publisher_binding(falcon_pubkey))
    }

    /// Clear the latched circuit breaker.
    ///
    /// Latching is automatic (a peg or deviation violation is evidence, not a
    /// request), but clearing it is a decision: only a passed
    /// `GovAction::ResetOracleBreaker` may call this. Returns whether the
    /// breaker was latched, so "reset an already-clear breaker" is a no-op the
    /// caller (and the committed proposal) can tell apart from a real reset.
    /// Governance reset: clears the latch AND the cumulative anchors,
    /// returning the oracle to a genesis-like state — the next committed
    /// feed re-anchors. Without anchor reset a legitimate regime change
    /// (>10% from an ancient anchor) would brick the oracle forever; with
    /// it, recovery is an explicit governance act (quorum + timelock), not
    /// a silent ratchet an attacker can ride.
    pub fn reset_breaker(&mut self) -> bool {
        let was = std::mem::replace(&mut self.breaker_tripped, false);
        self.anchor_price_micro_usd.clear();
        was
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
        let feed = self
            .feeds
            .get(asset)
            .ok_or_else(|| format!("no committed price feed for asset '{asset}'"))?;
        check_freshness(feed.timestamp, block_time)
            .map_err(|e| format!("frozen oracle feed for {asset}: {e}"))
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

/// Rolling On-Chain DEX VWAP Calculator (~91 s W* window).
///
/// NOTE: this computes a VOLUME-weighted mean (weight = trade volume), not
/// a time-weighted mean (report P4 §1). For manipulation analysis use the
/// effective averaging time W_eff = Δt·Σv²/(Σv)² (Δt/N for equal weights);
/// the cubic-root optimum laws are otherwise unchanged.
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
        // Pre-SPRT behavior, byte-identical: height 0 never reaches the
        // inactive-by-default gate (`SPRT_TIER3_ACTIVATION_HEIGHT = u64::MAX`),
        // so Tier-3 is the fixed 10% rule exactly as before.
        self.resolve_price_at_height(
            feed,
            asset,
            current_time,
            0,
            &[],
            SPRT_TIER3_SHIFT,
            SPRT_TIER3_SIGMA_PER_BLOCK,
        )
    }

    /// Height-gated resolve: Tiers 1–2 identical to [`Self::resolve_price`];
    /// Tier-3 reads the [`SPRT_TIER3_ACTIVATION_HEIGHT`] gate via
    /// [`tier3_breaker_tripped`] (`sprt_residuals`: one relative deviation per
    /// block, oldest first, at the `sprt_shift`/`sprt_sigma` operating point).
    /// Advisory-only like [`Self::resolve_price`]: never consensus.
    #[allow(clippy::too_many_arguments)] // GATE: extends `resolve_price` (feed/asset/time) with gate height plus one SPRT operating point (residuals/shift/sigma); grouping them would churn the wired-path tests for no behavioral gain.
    pub fn resolve_price_at_height(
        &mut self,
        feed: Option<&PriceFeedUpdate>,
        asset: &str,
        current_time: u64,
        height: u64,
        sprt_residuals: &[f64],
        sprt_shift: f64,
        sprt_sigma: f64,
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

                if tier3_breaker_tripped(
                    price,
                    twap,
                    height,
                    sprt_residuals,
                    sprt_shift,
                    sprt_sigma,
                ) {
                    self.circuit_breaker_triggered = true;
                    if sprt_tier3_active_at(height) {
                        return Err(format!(
                            "SPRT circuit breaker tripped: LLR sum {:.6} reached upper bound {:.6} (shift {}, sigma {})",
                            sprt_tier3_llr_sum(sprt_residuals, sprt_shift, sprt_sigma),
                            sprt_wald_bounds(SPRT_TIER3_ALPHA, SPRT_TIER3_BETA).0,
                            sprt_shift,
                            sprt_sigma,
                        ));
                    }
                    return Err(format!(
                        "Circuit breaker tripped: price deviation {} bps exceeds limit {} bps",
                        deviation_bps, MAX_PRICE_DEVIATION_BPS
                    ));
                }
            }
        }

        Ok(price)
    }

    /// PQ counterpart of [`Self::resolve_price`]: Tier-1 accepts a
    /// Falcon-signed feed whose key binding is trusted; Tiers 2–3 are
    /// identical (same TWAP fallback, same height-gated Tier-3 verdict).
    /// Advisory-only like [`Self::resolve_price`]: never consensus.
    pub fn resolve_price_pq(
        &mut self,
        feed: Option<&PqPriceFeedUpdate>,
        asset: &str,
        current_time: u64,
    ) -> Result<u64, String> {
        // Pre-SPRT behavior, byte-identical delegation to the gated path at
        // height 0, exactly like `resolve_price`.
        self.resolve_price_at_height_pq(
            feed,
            asset,
            current_time,
            0,
            &[],
            SPRT_TIER3_SHIFT,
            SPRT_TIER3_SIGMA_PER_BLOCK,
        )
    }

    /// PQ counterpart of [`Self::resolve_price_at_height`]: Tiers 1–2
    /// identical with a Falcon feed; Tier-3 reads the
    /// [`SPRT_TIER3_ACTIVATION_HEIGHT`] gate via [`tier3_breaker_tripped`]
    /// exactly as the Ed path does. Advisory-only: never consensus.
    #[allow(clippy::too_many_arguments)] // GATE: mirrors `resolve_price_at_height` (feed/asset/time + gate height + one SPRT operating point); grouping them would churn the wired-path tests for no behavioral gain.
    pub fn resolve_price_at_height_pq(
        &mut self,
        feed: Option<&PqPriceFeedUpdate>,
        asset: &str,
        current_time: u64,
        height: u64,
        sprt_residuals: &[f64],
        sprt_shift: f64,
        sprt_sigma: f64,
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

        // Tier 1: Try Pull-Oracle. Same cross-asset/zero-price guards as the Ed
        // path (audit BR-OR-01/BR-02): the feed must name THIS asset and carry
        // a positive price, verify under Falcon, and its key BINDING
        // (`pq_publisher_binding` — the 897-byte key cannot fit the trusted
        // `[u8; 32]` slots) must be trusted; freshness is block-time checked.
        // A feed failing any check is ignored (TWAP fallback), never chosen.
        let mut chosen_price: Option<u64> = None;
        if let Some(update) = feed {
            if update.asset == asset
                && update.price_micro_usd > 0
                && update.verify()
                && self
                    .trusted_publishers
                    .contains(&pq_publisher_binding(&update.publisher_falcon_pubkey))
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

                if tier3_breaker_tripped(
                    price,
                    twap,
                    height,
                    sprt_residuals,
                    sprt_shift,
                    sprt_sigma,
                ) {
                    self.circuit_breaker_triggered = true;
                    if sprt_tier3_active_at(height) {
                        return Err(format!(
                            "SPRT circuit breaker tripped: LLR sum {:.6} reached upper bound {:.6} (shift {}, sigma {})",
                            sprt_tier3_llr_sum(sprt_residuals, sprt_shift, sprt_sigma),
                            sprt_wald_bounds(SPRT_TIER3_ALPHA, SPRT_TIER3_BETA).0,
                            sprt_shift,
                            sprt_sigma,
                        ));
                    }
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
mod oracle_params_truth_tests {
    use super::*;

    #[test]
    fn twap_window_is_w_star_91s() {
        // Pinned observational value (report P4 §2): 3600 s → 91 s.
        // Advisory-only (see const docs for the per-consumer proof); the
        // consensus breaker thresholds below are UNCHANGED.
        assert_eq!(TWAP_WINDOW_SECS, 91);
        assert_eq!(MAX_PRICE_DEVIATION_BPS, 1000, "Tier-3 breaker stays 10%");
        assert_eq!(STALE_PRICE_MAX_SECS, 15 * 60, "freshness stays 15 min");
        assert_eq!(USDT_MIN_PEG_MICRO_USD, 950_000, "USDT peg stays $0.95");
        assert_eq!(
            MAX_SAME_PUBLISHER_DEVIATION_BPS, 500,
            "per-publisher cap stays 5%"
        );
    }

    #[test]
    fn w_star_formula_reproduces_report_headline() {
        // Report P4 §2 calibration: σ=5%/day → per-second
        // 0.05/sqrt(86400); J=10% held one 0.6 s block → W*≈90.7 s.
        let sigma = 0.05 / 86_400f64.sqrt();
        let w_star = twap_optimal_window_secs(0.10 * 0.6, sigma);
        assert!((w_star - 90.7).abs() < 0.5, "W*≈90.7 s, got {w_star}");
        // Scaling law (Corollary 1): doubling σ shrinks W* by 2^(2/3).
        let w_half = twap_optimal_window_secs(0.10 * 0.6, 2.0 * sigma);
        assert!((w_star / w_half - 2f64.powf(2.0 / 3.0)).abs() < 1e-9);
    }

    #[test]
    fn twap_prunes_at_new_window_and_stays_vwap() {
        // Pruning honors the 91 s window (was 3600 s): an observation older
        // than the window drops out of both record and query paths.
        let mut calc = DexTwapCalculator::new();
        calc.record_trade("X", 100, 1_000, 1);
        calc.record_trade("X", 200, 1_000 + TWAP_WINDOW_SECS + 1, 1);
        assert_eq!(
            calc.calculate_twap("X", 1_000 + TWAP_WINDOW_SECS + 1),
            Some(200),
            "stale observation pruned past the 91 s window"
        );
        // Inside the window both legs count, volume-weighted.
        let mut calc2 = DexTwapCalculator::new();
        calc2.record_trade("Y", 1_000_000, 5_000, 100);
        calc2.record_trade("Y", 1_100_000, 5_010, 100);
        assert_eq!(calc2.calculate_twap("Y", 5_010), Some(1_050_000));
    }

    #[test]
    fn sprt_proposal_matches_report_table() {
        // twap.json `sprt` rows (α=β=1e-3): E[N] for (J, σ) pairs.
        let cases = [
            (0.01, 0.005, 3.45),
            (0.01, 0.01, 13.79),
            (0.02, 0.005, 0.86),
            (0.02, 0.01, 3.45),
        ];
        for (j, sigma, expected) in cases {
            let got = sprt_expected_samples(1e-3, 1e-3, j, sigma);
            assert!(
                (got - expected).abs() / expected < 0.01,
                "J={j} σ={sigma}: E[N]≈{expected}, got {got}"
            );
        }
        // Wald bounds: A = ln((1−β)/α) > 0 > B, symmetric at α=β.
        let (a, b) = sprt_wald_bounds(1e-3, 1e-3);
        assert!((a - 6.906_755).abs() < 1e-5);
        assert!((a + b).abs() < 1e-12);
        // CUSUM step: zero residual = pure −J²/(2σ²) drift; a full-J
        // residual scores +J²/(2σ²).
        let drift = cusum_llr_step(0.0, 0.01, 0.005);
        assert!((drift - (-2.0)).abs() < 1e-12);
        assert!((cusum_llr_step(0.01, 0.01, 0.005) - 2.0).abs() < 1e-12);
    }
}

#[cfg(test)]
mod sprt_tier3_gate_tests {
    use super::*;

    /// Pre-activation pin: the gate is INACTIVE by default, so the wired path
    /// is the fixed 10% rule and the SPRT history is ignored on this branch.
    #[test]
    fn pre_activation_fixed_10pct_rule_pinned() {
        assert_eq!(
            SPRT_TIER3_ACTIVATION_HEIGHT,
            u64::MAX,
            "gate inactive by default until the lead flips it at rollout"
        );
        assert!(!sprt_tier3_active_at(0));
        assert!(!sprt_tier3_active_at(u64::MAX - 1));

        // 9% under → pass; exactly 10% → pass (rule is strict `>`); 11% → trip.
        assert!(!tier3_breaker_tripped(
            1_090_000,
            1_000_000,
            0,
            &[],
            0.01,
            0.005
        ));
        assert!(!tier3_breaker_tripped(
            1_100_000,
            1_000_000,
            0,
            &[],
            0.01,
            0.005
        ));
        assert!(tier3_breaker_tripped(
            1_110_000,
            1_000_000,
            0,
            &[],
            0.01,
            0.005
        ));
        // A maximally alarming SPRT history must NOT trip pre-activation:
        // the fixed branch ignores residuals entirely.
        assert!(!tier3_breaker_tripped(
            1_000_000,
            1_000_000,
            0,
            &[0.01; 64],
            0.01,
            0.005
        ));
    }

    /// Boundary pin: MAX−1 stays on the fixed rule, MAX switches to SPRT.
    #[test]
    fn activation_boundary_height() {
        // Just below: an 11% single print trips (fixed rule) even with an
        // empty SPRT history.
        assert!(tier3_breaker_tripped(
            1_110_000,
            1_000_000,
            u64::MAX - 1,
            &[],
            0.01,
            0.005
        ));
        // Just below: on-par price with a trip-worthy SPRT history does NOT
        // trip (SPRT ignored on the fixed branch).
        assert!(!tier3_breaker_tripped(
            1_000_000,
            1_000_000,
            u64::MAX - 1,
            &[0.01; 4],
            0.01,
            0.005
        ));
        // At the gate: the same on-par price now trips on SPRT evidence…
        assert!(sprt_tier3_active_at(u64::MAX));
        assert!(tier3_breaker_tripped(
            1_000_000,
            1_000_000,
            u64::MAX,
            &[0.01; 4],
            0.01,
            0.005
        ));
        // …while an 11% single print with NO SPRT history does not (the SPRT
        // branch reads residuals, not the one-shot deviation).
        assert!(!tier3_breaker_tripped(
            1_110_000,
            1_000_000,
            u64::MAX,
            &[],
            0.01,
            0.005
        ));
    }

    /// All four twap.json `sprt` rows (α=β=1e-3) proved through the WIRED
    /// expectation path: (J, σ, E[N]) = (1%, 0.5%, 3.45), (1%, 1%, 13.79),
    /// (2%, 0.5%, 0.86), (2%, 1%, 3.45).
    #[test]
    fn wired_expected_samples_match_all_four_report_rows() {
        assert_eq!(SPRT_TIER3_ALPHA.to_bits(), 0.001f64.to_bits());
        assert_eq!(SPRT_TIER3_BETA.to_bits(), 0.001f64.to_bits());
        let cases = [
            (0.01, 0.005, 3.45),
            (0.01, 0.01, 13.79),
            (0.02, 0.005, 0.86),
            (0.02, 0.01, 3.45),
        ];
        for (j, sigma, expected) in cases {
            let got = sprt_tier3_expected_samples(j, sigma);
            assert!(
                (got - expected).abs() / expected < 0.01,
                "wired E[N] J={j} σ={sigma}: ≈{expected}, got {got}"
            );
        }
    }

    /// Post-activation trip/no-trip vectors through the WIRED gate
    /// ([`tier3_breaker_tripped`] at `u64::MAX`): sustained full-shift
    /// residuals `x = J` cross the Wald upper bound exactly at
    /// `ceil(E[N])` samples — 4 / 14 / 1 / 4 for the four report rows —
    /// while one fewer sample stays silent, and flat history never trips.
    #[test]
    fn post_activation_sprt_trip_no_trip_vectors() {
        // (shift J, sigma, E[N] from twap.json, samples-to-trip = ceil(E[N])).
        let cases: [(f64, f64, f64, usize); 4] = [
            (0.01, 0.005, 3.45, 4),
            (0.01, 0.01, 13.79, 14),
            (0.02, 0.005, 0.86, 1),
            (0.02, 0.01, 3.45, 4),
        ];
        for (j, sigma, expected, trip_at) in cases {
            // Sanity: the trip count really is ceil(E[N]) of the report row.
            assert_eq!(
                trip_at,
                expected.ceil() as usize,
                "J={j} σ={sigma}: trip count must be ceil({expected})"
            );
            let trip_history = vec![j; trip_at];
            assert!(
                tier3_breaker_tripped(1_000_000, 1_000_000, u64::MAX, &trip_history, j, sigma),
                "J={j} σ={sigma}: {trip_at} full-shift samples must trip"
            );
            assert!(
                sprt_tier3_decision(&trip_history, j, sigma),
                "J={j} σ={sigma}: pure SPRT verdict must agree with the wired gate"
            );
            if trip_at > 1 {
                let quiet_history = vec![j; trip_at - 1];
                assert!(
                    !tier3_breaker_tripped(
                        1_000_000,
                        1_000_000,
                        u64::MAX,
                        &quiet_history,
                        j,
                        sigma
                    ),
                    "J={j} σ={sigma}: {} samples must stay silent",
                    trip_at - 1
                );
            }
            // Flat market: zeros score pure negative drift, never trip —
            // even over a long window.
            assert!(
                !tier3_breaker_tripped(1_000_000, 1_000_000, u64::MAX, &[0.0; 64], j, sigma),
                "J={j} σ={sigma}: flat residuals must never trip"
            );
        }
        // Empty history post-activation: LLR = 0 < A, silent.
        assert!(!tier3_breaker_tripped(
            1_000_000,
            1_000_000,
            u64::MAX,
            &[],
            0.01,
            0.005
        ));
    }

    /// Engine wiring: the same on-par price is admitted pre-activation and
    /// SPRT-tripped post-activation, with the latch set exactly once.
    #[test]
    fn engine_wired_path_switches_at_activation() {
        // Pre-activation: price == TWAP → Ok, latch clear.
        let mut pre = OracleSafetyEngine::new(vec![]);
        pre.set_dex_twap("STELL", 1_000_000);
        assert!(pre
            .resolve_price_at_height(None, "STELL", 1_000, 0, &[0.01; 64], 0.01, 0.005)
            .is_ok());
        assert!(!pre.circuit_breaker_triggered);

        // Post-activation with 4 full-shift residuals (row 1, E[N]=3.45):
        // trips despite a zero one-shot deviation, and latches.
        let mut post = OracleSafetyEngine::new(vec![]);
        post.set_dex_twap("STELL", 1_000_000);
        let err = post
            .resolve_price_at_height(None, "STELL", 1_000, u64::MAX, &[0.01; 4], 0.01, 0.005)
            .expect_err("SPRT evidence must trip post-activation");
        assert!(
            err.contains("SPRT"),
            "post-activation trip must name SPRT, got: {err}"
        );
        assert!(post.circuit_breaker_triggered);

        // Legacy entry point is byte-identical to the gated path at height 0:
        // identical engines give identical outcomes and latch state — even
        // with a maximally alarming SPRT history, which the fixed branch
        // ignores. (An 11%-style fixed-rule trip is untriggerable through
        // the engine while feed verification fail-closes, so the trip
        // itself is pinned at the `tier3_breaker_tripped` level above.)
        let mut legacy = OracleSafetyEngine::new(vec![]);
        legacy.set_dex_twap("STELL", 1_000_000);
        let mut gated = OracleSafetyEngine::new(vec![]);
        gated.set_dex_twap("STELL", 1_000_000);
        let via_legacy = legacy.resolve_price(None, "STELL", 1_000);
        let via_gated =
            gated.resolve_price_at_height(None, "STELL", 1_000, 0, &[0.01; 64], 0.01, 0.005);
        assert_eq!(via_legacy, via_gated);
        assert_eq!(
            legacy.circuit_breaker_triggered,
            gated.circuit_breaker_triggered
        );
    }

    /// Determinism: identical inputs → identical outputs on repeat, on both
    /// branches; documents the integer/fixed-point discipline (fixed branch
    /// is exact integer bps; SPRT branch is slice-order IEEE-754, bit-stable
    /// for identical input order — no wall-clock, no RNG, no map iteration).
    #[test]
    fn wired_gate_is_deterministic() {
        let residuals = [0.01, 0.005, -0.002, 0.012, 0.008];
        let fixed_a = tier3_breaker_tripped(1_050_000, 1_000_000, 0, &residuals, 0.01, 0.005);
        let sprt_a = tier3_breaker_tripped(1_000_000, 1_000_000, u64::MAX, &residuals, 0.01, 0.005);
        for _ in 0..16 {
            assert_eq!(
                tier3_breaker_tripped(1_050_000, 1_000_000, 0, &residuals, 0.01, 0.005),
                fixed_a
            );
            assert_eq!(
                tier3_breaker_tripped(1_000_000, 1_000_000, u64::MAX, &residuals, 0.01, 0.005),
                sprt_a
            );
            assert_eq!(
                sprt_tier3_llr_sum(&residuals, 0.01, 0.005).to_bits(),
                sprt_tier3_llr_sum(&residuals, 0.01, 0.005).to_bits()
            );
            assert_eq!(
                sprt_tier3_expected_samples(0.01, 0.005).to_bits(),
                sprt_tier3_expected_samples(0.01, 0.005).to_bits()
            );
        }
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

    /// FULL-PQ: a VALID ed25519 feed never verifies and never commits
    /// (classical feed verification removed; always fail-closed).
    #[test]
    fn pure_pq_refuses_classical_feed() {
        let (feed, mut state) = signed_feed();

        // FULL-PQ always-on: the valid ed feed is refused.
        assert!(
            !feed.verify(),
            "valid ed feed must NOT verify under FULL-PQ"
        );
        assert!(
            state.commit_feed(&feed, 1_001).is_err(),
            "ed feed must not commit under FULL-PQ"
        );

        // Still refused with the (no-op) override set.
        {
            let _guard = PurePqGuard::enforce();
            assert!(
                !feed.verify(),
                "valid ed feed must NOT verify under FULL-PQ"
            );
            let mut enforced_state = OracleState::default();
            enforced_state.publishers.insert(feed.publisher_pubkey);
            assert!(
                enforced_state.commit_feed(&feed, 1_001).is_err(),
                "ed feed must not commit under FULL-PQ"
            );
        }
    }
}

#[cfg(test)]
mod pq_feed_tests {
    use super::*;
    use crate::post_quantum::FalconKeypair;

    fn test_kp(seed: u8) -> FalconKeypair {
        FalconKeypair::generate_from_seed(seed)
    }

    fn signed(asset: &str, price: u64, ts: u64, kp: &FalconKeypair) -> PqPriceFeedUpdate {
        PqPriceFeedUpdate::sign(asset, price, ts, kp)
    }

    fn state_with(kp: &FalconKeypair) -> OracleState {
        let mut s = OracleState::default();
        assert!(
            s.register_pq_publisher(kp.pubkey()),
            "test key must register"
        );
        s
    }

    #[test]
    fn pq_feed_verify_happy_path() {
        let kp = test_kp(0xA1);
        let feed = signed("STELL", 250_000, 1_000, &kp);
        assert!(feed.verify(), "a fresh Falcon feed must verify");
        // Falcon signing is randomized: two signatures over the same message
        // both verify (and differ), so committed state never depends on sig
        // bytes — only on asset/price/timestamp/binding.
        let again = signed("STELL", 250_000, 1_000, &kp);
        assert!(again.verify(), "second signature must also verify");
        assert_ne!(
            feed.falcon_sig, again.falcon_sig,
            "test bug: Falcon signatures must be randomized per signing"
        );
    }

    #[test]
    fn pq_feed_bad_signature_is_refused() {
        let kp = test_kp(0xA1);
        let mut feed = signed("STELL", 250_000, 1_000, &kp);
        let last = feed.falcon_sig.len() - 1;
        feed.falcon_sig[last] ^= 0x01;
        assert!(!feed.verify(), "a tampered signature must NOT verify");
    }

    #[test]
    fn pq_feed_wrong_key_is_refused() {
        let kp = test_kp(0xA1);
        let other = test_kp(0xB2);
        let mut feed = signed("STELL", 250_000, 1_000, &kp);
        // Swap the embedded key: the signature no longer matches the claimed
        // publisher, so verification must fail.
        feed.publisher_falcon_pubkey = other.pubkey().to_vec();
        assert!(
            !feed.verify(),
            "signature under a different key must NOT verify"
        );
    }

    #[test]
    fn pq_feed_tampered_fields_are_refused() {
        let kp = test_kp(0xA1);
        let mut feed = signed("STELL", 250_000, 1_000, &kp);
        feed.price_micro_usd = 251_000;
        assert!(!feed.verify(), "a re-priced feed must NOT verify");
        let mut feed = signed("STELL", 250_000, 1_000, &kp);
        feed.asset = "BTC".to_string();
        assert!(!feed.verify(), "a re-asseted feed must NOT verify");
        let mut feed = signed("STELL", 250_000, 1_000, &kp);
        feed.timestamp += 1;
        assert!(!feed.verify(), "a re-timestamped feed must NOT verify");
    }

    #[test]
    fn pq_feed_short_signature_is_refused() {
        let kp = test_kp(0xA1);
        let mut feed = signed("STELL", 250_000, 1_000, &kp);
        feed.falcon_sig.clear();
        assert!(!feed.verify(), "an empty signature must NOT verify");
        feed.falcon_sig = vec![0u8; 64];
        assert!(!feed.verify(), "a short signature must NOT verify");
    }

    #[test]
    fn pq_publisher_binding_is_deterministic_and_key_bound() {
        let a = test_kp(0xA1);
        let b = test_kp(0xB2);
        assert_eq!(
            pq_publisher_binding(a.pubkey()),
            pq_publisher_binding(a.pubkey()),
            "binding must be deterministic"
        );
        assert_ne!(
            pq_publisher_binding(a.pubkey()),
            pq_publisher_binding(b.pubkey()),
            "distinct Falcon keys must bind distinctly"
        );
        assert_ne!(
            pq_publisher_binding(a.pubkey()),
            [0u8; 32],
            "a real key must never bind to the refused zero slot"
        );
    }

    #[test]
    fn pq_registry_refuses_malformed_keys() {
        let mut s = OracleState::default();
        assert!(
            !s.register_pq_publisher(&[0u8; 64]),
            "wrong-length key must be refused"
        );
        assert!(
            !s.unregister_pq_publisher(&[0u8; 64]),
            "wrong-length key removes nothing"
        );
        assert!(s.publishers.is_empty());
        // A real key registers idempotently, exactly like the Ed path.
        let kp = test_kp(0xA1);
        assert!(s.register_pq_publisher(kp.pubkey()));
        assert!(!s.register_pq_publisher(kp.pubkey()));
        assert!(s.unregister_pq_publisher(kp.pubkey()));
        assert!(!s.unregister_pq_publisher(kp.pubkey()));
    }

    #[test]
    fn commit_feed_pq_happy_path() {
        let kp = test_kp(0xA1);
        let mut s = state_with(&kp);
        let price = s
            .commit_feed_pq(&signed("STELL", 250_000, 1_000, &kp), 1_001)
            .expect("a fresh Falcon feed from a registered publisher must commit");
        assert_eq!(price, 250_000);
        let committed = &s.feeds["STELL"];
        assert_eq!(committed.price_micro_usd, 250_000);
        assert_eq!(committed.timestamp, 1_000);
        assert_eq!(
            committed.publisher,
            pq_publisher_binding(kp.pubkey()),
            "the committed publisher is the Falcon key binding"
        );
        assert!(!s.breaker_tripped);
    }

    #[test]
    fn commit_feed_pq_refusals() {
        let kp = test_kp(0xA1);
        // Unknown publisher: correctly signed yet unauthorised.
        let mut s = OracleState::default();
        let err = s
            .commit_feed_pq(&signed("STELL", 250_000, 1_000, &kp), 1_001)
            .expect_err("an unregistered PQ publisher must be refused");
        assert!(
            err.contains("publisher"),
            "refusal must name the set: {err}"
        );
        assert!(s.feeds.is_empty());
        assert!(!s.breaker_tripped);

        // Bad signature from a REGISTERED publisher: still refused.
        let mut s = state_with(&kp);
        let mut bad = signed("STELL", 250_000, 1_000, &kp);
        bad.falcon_sig[10] ^= 0xFF;
        let err = s
            .commit_feed_pq(&bad, 1_001)
            .expect_err("a bad Falcon signature must be refused");
        assert!(
            err.contains("invalid oracle signature"),
            "refusal must name the signature: {err}"
        );
        assert!(s.feeds.is_empty());
        assert!(!s.breaker_tripped);
    }
}
