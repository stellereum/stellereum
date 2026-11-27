//! Genesis Vault and Tokenomics module
//! Base parameters:
//! 1 STELL = $0.25 USD
//! Hard Cap = 1,000,000,000 STELL
//! Public Exchange (Genesis Vault): 25% (250,000,000 STELL)
//! Formula: STELL = (incoming_coins * coin_price_usd) / $0.25

use serde::{Deserialize, Serialize};

/// GLOBAL hard cap: 1,000,000,000 STELL, in nano-STELL (9 decimals).
///
/// ENFORCED BY THE STATE ENGINE (not only by the per-subsystem allocations):
/// every engine mint ([`crate::state_engine::InMemoryStateEngine::mint_native`],
/// and therefore `credit_native`, which delegates to it) atomically reserves
/// against a monotone `total_minted_nano` counter and fails closed when the
/// sum would exceed this value. The local caps ([`GENESIS_VAULT_CAP`],
/// `staking::REWARDS_EMISSION_CAP`, `bridge::BRIDGE_MINT_CAP_NANO`) each bound
/// ONE pool; the engine counter bounds their sum. Transfers are never capped.
/// Hard cap on all STELL that can ever exist, in nano-STELL (9 decimals).
///
/// ENFORCED IN THE ENGINE: `InMemoryStateEngine` keeps a minted-supply counter
/// that every value-creating path goes through (`mint_native`, rewards, bridge
/// deposits, PMM buys) and fails closed one nano past this cap. The GENESIS
/// allocation (fixed by [`TokenAllocation`]: validators, staking pool, faucet)
/// is folded into the SAME counter on the first post-genesis reservation, so
/// `genesis + emission ≤ TOTAL_SUPPLY_CAP` is one invariant, checked in one
/// place. Before that first reservation the counter is zero, which keeps
/// `assemble_cached_digest_*` byte-identical on a chain that has not minted
/// anything yet (the pinned genesis root). NOTE: a genesis allocation above
/// this cap therefore refuses every later mint — fail closed by design.
///
/// CHAIN-WIDE (ruleset v5): a per-engine counter alone let N shards each mint
/// a full cap. Each shard engine is now installed with a deterministic static
/// share of this cap ([`SupplyPartition`]); the shares sum to at most the cap,
/// so the SUM over shards cannot exceed it under any interleaving. The
/// masterchain also aggregates the signed shard-head commitments
/// (`sharding::ShardHeaderCommitment::minted_total_nano`) and refuses a head
/// that would take the committed aggregate past this value. See
/// `docs/SUPPLY_CAP.md`.
pub const TOTAL_SUPPLY_CAP: u64 = 1_000_000_000 * 1_000_000_000; // in nano-STELL (9 decimals)
pub const GENESIS_VAULT_CAP: u64 = 250_000_000 * 1_000_000_000;

/// Version of the CHAIN-WIDE supply partition rule (ruleset v5).
///
/// Folded into the protocol fork id so a fleet that disagrees about how the
/// 1 B cap is split across shards refuses consensus instead of diverging.
pub const CHAIN_SUPPLY_PARTITION_VERSION: u64 = 1;

/// The CHAIN-WIDE partition of [`TOTAL_SUPPLY_CAP`] across the configured
/// shards (masterchain included).
///
/// WHY A STATIC PARTITION. A per-engine counter bounds one engine; with N
/// engines the advertised 1 B cap was `N x cap`. Sharing the remaining
/// headroom dynamically ("every shard may use what is left") is NOT safe under
/// asynchronous interleaving: two shards that both observe `headroom = H` may
/// each mint `H` before either commits, so the committed total reaches
/// `2H`. Even a fair `H / N` allowance per shard is unsafe when different
/// shards act on different (stale) views of the aggregate. A static,
/// genesis-committed partition is the only scheme that is safe without a
/// two-phase quota-handoff protocol:
///
/// ```text
/// minted(shard_i) <= quota_i   for every i, and   sum(quota_i) <= TOTAL_SUPPLY_CAP
/// =>  sum(minted_i) <= TOTAL_SUPPLY_CAP  for EVERY interleaving and EVERY lag.
/// ```
///
/// The partition is derived deterministically from the committed shard set
/// ([`Self::uniform`]), so every node computes the same shares without any
/// local or environment input. [`Self::bounded_limit_nano`] expresses the
/// additional MONOTONE tightening a shard can derive from the last
/// masterchain-committed aggregate: it can only make a shard mint less, never
/// let it borrow another shard's unused quota. Production installs the STATIC
/// share on the engine (a view-dependent engine limit would make `apply()`
/// non-deterministic across nodes with different header views); the helper is
/// the safe under-mint rule for callers that have a committed view. The
/// consequence is honest under-mint (stranded headroom) when some shards are
/// idle; see `docs/SUPPLY_CAP.md`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplyPartition {
    quotas: std::collections::BTreeMap<u32, u64>,
}

impl SupplyPartition {
    /// Split the cap EQUALLY across `shards`, deterministically.
    ///
    /// Shards are sorted ascending; the first `TOTAL_SUPPLY_CAP % n` shards get
    /// one extra nano each. No float, no environment, no insertion-order
    /// dependence, so two nodes with the same committed shard set derive
    /// byte-identical quotas. An empty set yields an empty partition (nobody
    /// may mint) — fail closed.
    pub fn uniform<I: IntoIterator<Item = u32>>(shards: I) -> Self {
        let mut ids: Vec<u32> = shards.into_iter().collect();
        ids.sort_unstable();
        ids.dedup();
        let mut quotas = std::collections::BTreeMap::new();
        let n = ids.len() as u64;
        if n == 0 {
            return Self { quotas };
        }
        let base = TOTAL_SUPPLY_CAP / n;
        let mut remainder = TOTAL_SUPPLY_CAP % n;
        for id in ids {
            let extra = u64::from(remainder > 0);
            remainder = remainder.saturating_sub(1);
            quotas.insert(id, base.saturating_add(extra));
        }
        Self { quotas }
    }

    /// Build an EXPLICIT partition (tests, deterministic genesis configs).
    ///
    /// Fails closed if the quotas sum above the cap or an id is duplicated:
    /// such a partition could never be chain-wide safe.
    pub fn from_quotas<I: IntoIterator<Item = (u32, u64)>>(quotas: I) -> Result<Self, String> {
        let mut map = std::collections::BTreeMap::new();
        for (shard, quota) in quotas {
            if map.insert(shard, quota).is_some() {
                return Err(format!("supply partition: duplicate shard {shard}"));
            }
        }
        let partition = Self { quotas: map };
        partition.validate()?;
        Ok(partition)
    }

    /// The shard's cumulative mint limit, or 0 when the shard is not part of
    /// the committed partition (fail closed: an unknown shard may not mint).
    pub fn quota_for(&self, shard: u32) -> u64 {
        self.quotas.get(&shard).copied().unwrap_or(0)
    }

    /// True when the committed partition assigns this shard a share.
    pub fn contains_shard(&self, shard: u32) -> bool {
        self.quotas.contains_key(&shard)
    }

    /// Every `(shard, quota)` pair in ascending shard order.
    pub fn quotas(&self) -> impl Iterator<Item = (u32, u64)> + '_ {
        self.quotas.iter().map(|(shard, quota)| (*shard, *quota))
    }

    /// Sum of all quotas, in nano-STELL. Never above [`TOTAL_SUPPLY_CAP`] for
    /// a constructed partition.
    pub fn total_nano(&self) -> u128 {
        self.quotas.values().map(|q| *q as u128).sum()
    }

    /// True when the partition covers at least one shard.
    pub fn is_empty(&self) -> bool {
        self.quotas.is_empty()
    }

    /// Fail closed unless the partition is a valid static split of the cap.
    pub fn validate(&self) -> Result<(), String> {
        let total = self.total_nano();
        if total > TOTAL_SUPPLY_CAP as u128 {
            return Err(format!(
                "supply partition sums to {total} nano-STELL, above TOTAL_SUPPLY_CAP {}",
                TOTAL_SUPPLY_CAP
            ));
        }
        Ok(())
    }

    /// The shard's mint limit TIGHTENED by the last masterchain-committed
    /// aggregate, never loosened above its static share.
    ///
    /// `committed_aggregate` is the sum of every committed shard's cumulative
    /// minted total (including this shard's own committed total
    /// `committed_own`), or `None` when this node has no committed aggregate
    /// view yet. The result is:
    ///
    /// * static share when no view exists — safe by construction, so an
    ///   isolated/restarted shard UNDER-mints rather than over-mints;
    /// * `min(share, cap - committed_others)` otherwise, where
    ///   `committed_others = aggregate - committed_own`. A lagging view can
    ///   only make `committed_others` smaller and therefore this bound LOOSER,
    ///   but it can never exceed the shard's static share, which is the actual
    ///   invariant. This is the honest lag bound: the aggregate is an
    ///   additional ceiling, not the primary one.
    pub fn bounded_limit_nano(
        &self,
        shard: u32,
        committed_aggregate: Option<u128>,
        committed_own: u64,
    ) -> u64 {
        let share = self.quota_for(shard);
        let Some(aggregate) = committed_aggregate else {
            return share;
        };
        let others = aggregate.saturating_sub(committed_own as u128);
        let global_room = (TOTAL_SUPPLY_CAP as u128).saturating_sub(others);
        share.min(global_room.min(u64::MAX as u128) as u64)
    }
}
pub const BASE_STELL_PRICE_MICRO_USD: u64 = 250_000; // $0.25 USD (6 decimals)

/// Undivided per-block emission, in nano-STELL: the pool this is divided by
/// `active_validators` in [`StakingEmissionSchedule::calculate_block_reward`].
///
/// This is the ONE definition of the 0.317 STELL per-block reward: the runtime
/// default passed to `with_block_reward` in `src/main.rs` must stay identical
/// to what the schedule pays out, or a solo node and a 100-validator network
/// would disagree about the proposer credit of the very same block.
pub const BLOCK_REWARD_NANO: u64 = 317_000_000;

/// Height gate for the cap-exact geometric emission (report §11, Eq. 4).
///
/// INACTIVE by default (`u64::MAX` — lead flips at rollout). While set to
/// `u64::MAX` EVERY height (including `u64::MAX`) takes the flat branch,
/// matching `chain_spec::ActivationStatus::GatedOff`, so live emission is
/// byte-identical to [`StakingEmissionSchedule::calculate_block_reward`]
/// (pinned by `gated_pre_activation_pins_current_values` below and the
/// unmodified external `flat_block_reward_is_live_and_schedule_is_dead`).
// GATE: task-mandated identifier spelling `EMISSIONCapEXACT_ACTIVATION_HEIGHT`
// (the exact rollout knob the lead flips); casing allow is per-item, not blanket.
#[allow(non_upper_case_globals)]
pub const EMISSIONCapEXACT_ACTIVATION_HEIGHT: u64 = u64::MAX;

/// Cap-exact geometric schedule parameters: 7-yr horizon at 0.6 s blocks
/// (`results/emission.json` row: half-life 1.054 yr, R0 4.380869639 STELL).
/// Integer constants only — no float in this file's new code; the float
/// lives solely in the sibling-owned pure helpers, REUSED via delegation
/// (never duplicated here).
///
/// H = 1.054 yr × 52,560,000 blocks/yr (0.6 s) = 55,398,240 blocks.
/// R0 = Eq. 4 `P·(1−2^(−1/H))` at (350M STELL, H), pinned to the
/// `geometric_schedule_r0_nano` helper output and cross-checked against the
/// emission.json row (±1%) in `cap_exact_r0_matches_eq4_and_json_row`.
pub const CAP_EXACT_HALF_LIFE_BLOCKS: u64 = 55_398_240;
pub const CAP_EXACT_R0_NANO: u64 = 4_379_227_780;

// ---------------------------------------------------------------------------
// Economic activation gates (W4 economics contract §2.2.2 / §2.3)
// ---------------------------------------------------------------------------
//
// Three consensus-facing knobs live here as COMPILED constants, all `u64::MAX`
// (`GatedOff`) until the lead flips them at rollout. They never read the
// environment: every node applying the same block must reach the same verdict,
// so an env knob would be a per-node fork window. Tests (and debug builds)
// get a THREAD-LOCAL override, absent from release builds — the exact pattern
// of [`crate::pq_registry::pq_lifecycle_active_at`].

/// Height at which the STRICT sub-nano EVM/SVM bridge rule activates
/// (`wei_to_nano_exact`: a wei amount that is not a multiple of
/// `WEI_PER_NANO` is refused instead of silently truncated, §2.3 п.1).
///
/// INACTIVE by default (`u64::MAX`): every height, including `u64::MAX`,
/// keeps today's lenient conversion so historical carrier txs replay
/// byte-identically. Imported by `evm_adapter` / `svm` behind this gate.
pub const SUB_NANO_STRICT_ACTIVATION_HEIGHT: u64 = 0;

#[cfg(any(test, debug_assertions))]
thread_local! {
    static SUB_NANO_STRICT_ACTIVATION_OVERRIDE: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// Set (or clear with `None`) the TEST/DEBUG-ONLY
/// [`SUB_NANO_STRICT_ACTIVATION_HEIGHT`] override for the calling thread.
/// Absent from release builds.
#[cfg(any(test, debug_assertions))]
pub fn set_sub_nano_strict_activation_override(activation: Option<u64>) {
    SUB_NANO_STRICT_ACTIVATION_OVERRIDE.with(|c| c.set(activation));
}

/// Effective [`SUB_NANO_STRICT_ACTIVATION_HEIGHT`] for the calling thread.
///
/// Release builds always return the compiled constant (there is no override
/// state at all in that configuration).
pub fn effective_sub_nano_strict_activation_height() -> u64 {
    #[cfg(any(test, debug_assertions))]
    if let Some(h) = SUB_NANO_STRICT_ACTIVATION_OVERRIDE.with(|c| c.get()) {
        return h;
    }
    SUB_NANO_STRICT_ACTIVATION_HEIGHT
}

/// True iff the strict sub-nano rule is active at `height`.
///
/// Strictly `false` for EVERY height (including `u64::MAX`) while the
/// effective gate is `u64::MAX` (`GatedOff`) — matching
/// `chain_spec::ActivationStatus::GatedOff`.
pub fn sub_nano_strict_active_at(height: u64) -> bool {
    let gate = effective_sub_nano_strict_activation_height();
    gate != u64::MAX && height >= gate
}

/// Height at which Fee Market v2 activates: exact `priority_fee_per_gas`
/// charging and the Burn / Proposer / Staking-Pool split of block fees in
/// `apply()` (§2.2.2).
///
/// INACTIVE by default (`u64::MAX`): `apply()` is byte-identical to today at
/// every height while gated off. Registered additionally in
/// `chain_spec::current_activation_schedule()` by the rollout owner.
pub const FEE_MARKET_V2_ACTIVATION_HEIGHT: u64 = 0;

#[cfg(any(test, debug_assertions))]
thread_local! {
    static FEE_MARKET_V2_ACTIVATION_OVERRIDE: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// Set (or clear with `None`) the TEST/DEBUG-ONLY
/// [`FEE_MARKET_V2_ACTIVATION_HEIGHT`] override for the calling thread.
/// Absent from release builds.
#[cfg(any(test, debug_assertions))]
pub fn set_fee_market_v2_activation_override(activation: Option<u64>) {
    FEE_MARKET_V2_ACTIVATION_OVERRIDE.with(|c| c.set(activation));
}

/// Effective [`FEE_MARKET_V2_ACTIVATION_HEIGHT`] for the calling thread.
pub fn effective_fee_market_v2_activation_height() -> u64 {
    #[cfg(any(test, debug_assertions))]
    if let Some(h) = FEE_MARKET_V2_ACTIVATION_OVERRIDE.with(|c| c.get()) {
        return h;
    }
    FEE_MARKET_V2_ACTIVATION_HEIGHT
}

/// True iff Fee Market v2 is active at `height` (same `GatedOff` semantics as
/// [`sub_nano_strict_active_at`]).
pub fn fee_market_v2_active_at(height: u64) -> bool {
    let gate = effective_fee_market_v2_activation_height();
    gate != u64::MAX && height >= gate
}

/// Default share of block fees BURNED forever, in basis points (50%).
///
/// Burned value is never re-minted and never decrements `total_minted_nano`:
/// `TOTAL_SUPPLY_CAP` bounds GROSS lifetime emission, so burning only reduces
/// circulating supply (§2.2.2 invariant 2).
pub const DEFAULT_FEE_BURN_BPS: u64 = 5_000;

/// Default share of block fees credited directly to `block.proposer`, in bps
/// (30%). The split is computed on the WHOLE block in `u128`; the proposer
/// leg additionally receives every remainder nano
/// (`proposer = fees - burn - staking`, exact, no dust lost).
pub const DEFAULT_FEE_PROPOSER_BPS: u64 = 3_000;

/// Default share of block fees routed to the staking rewards pool, in bps
/// (20%). Redirected to the proposer when the proposer has no eligible
/// validator/stake entry. Transfer, not emission: it must NOT touch
/// `rewards_minted` / `REWARDS_EMISSION_CAP` (§2.2.2 invariant 4).
pub const DEFAULT_FEE_STAKING_BPS: u64 = 2_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenAllocation {
    pub genesis_vault: u64,      // 25% - 250M
    pub liquidity_pools: u64,    // 15% - 150M
    pub validator_rewards: u64,  // 35% - 350M
    pub ecosystem_treasury: u64, // 15% - 150M
    pub core_team_vesting: u64,  // 10% - 100M
}

impl Default for TokenAllocation {
    fn default() -> Self {
        Self {
            genesis_vault: 250_000_000 * 1_000_000_000,
            liquidity_pools: 150_000_000 * 1_000_000_000,
            validator_rewards: 350_000_000 * 1_000_000_000,
            ecosystem_treasury: 150_000_000 * 1_000_000_000,
            core_team_vesting: 100_000_000 * 1_000_000_000,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GenesisVault {
    pub total_minted_nano: u64,
    pub usdt_deposited_micro: u64,
    pub ton_deposited_nano: u64,
    pub gram_deposited_nano: u64,
}

/// Full 128×128 → 256-bit product, as four LITTLE-ENDIAN `u64` limbs.
///
/// Pure integer schoolbook multiplication on 64-bit limbs (no external crate,
/// no float): `a * b = out[0] + out[1]·2^64 + out[2]·2^128 + out[3]·2^192`.
fn mul_u128_wide(a: u128, b: u128) -> [u64; 4] {
    let a0 = a as u64;
    let a1 = (a >> 64) as u64;
    let b0 = b as u64;
    let b1 = (b >> 64) as u64;

    let p00 = (a0 as u128) * (b0 as u128);
    let p01 = (a0 as u128) * (b1 as u128);
    let p10 = (a1 as u128) * (b0 as u128);
    let p11 = (a1 as u128) * (b1 as u128);

    let mut out = [0u64; 4];
    out[0] = p00 as u64;
    let mut carry = p00 >> 64;

    let col1 = (p01 as u64 as u128) + (p10 as u64 as u128) + carry;
    out[1] = col1 as u64;
    carry = col1 >> 64;

    let col2 = (p01 >> 64) + (p10 >> 64) + (p11 as u64 as u128) + carry;
    out[2] = col2 as u64;
    carry = col2 >> 64;

    out[3] = ((p11 >> 64) + carry) as u64;
    out
}

/// Exact `floor(a · b / denom)` over the full 256-bit intermediate product.
///
/// WHY: a two-step `(a · b) / x / y` (or `(a / x) · (b / y)`) floors twice and
/// silently loses the exact remainder. This helper multiplies into 256 bits
/// (`mul_u128_wide`, so `a · b` never overflows) and performs ONE binary
/// long division of the 256-bit numerator by the 128-bit denominator, bit by
/// bit from the most significant — pure `u128` arithmetic, no float, no
/// external crate, deterministic on every platform.
///
/// The running remainder is kept below `denom`; the doubled remainder can need
/// 129 bits, so the carry-out bit is tracked explicitly and re-injected with
/// `wrapping_sub` (which computes `2^128 + rem − denom` exactly, and the
/// result is `< denom < 2^128`). 256 iterations, constant time.
///
/// ERRORS (fail closed, no saturation):
/// * `denom == 0` → `Err`;
/// * a non-zero quotient bit at position `>= 128` → the true quotient does not
///   fit `u128` → `Err`.
pub fn mul_div_floor_256(a: u128, b: u128, denom: u128) -> Result<u128, &'static str> {
    if denom == 0 {
        return Err("mul_div_floor_256: denominator is zero");
    }
    let product = mul_u128_wide(a, b);
    let mut rem: u128 = 0;
    let mut quotient: u128 = 0;
    for i in (0..256u32).rev() {
        let bit = (product[(i / 64) as usize] >> (i % 64)) & 1;
        let carry_out = rem >> 127;
        rem = (rem << 1) | (bit as u128);
        if carry_out != 0 || rem >= denom {
            rem = rem.wrapping_sub(denom);
            if i >= 128 {
                return Err("mul_div_floor_256: quotient overflows u128");
            }
            quotient |= 1u128 << i;
        }
    }
    Ok(quotient)
}

impl GenesisVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate STELL amount minted: (in_coins * price_usd) / $0.25
    /// asset_amount is in native decimals (micro for USDT, nano for TON/GRAM)
    /// price_micro_usd is in micro USD ($1 = 1_000_000)
    pub fn calculate_mint(asset_amount: u64, asset_decimals: u32, price_micro_usd: u64) -> u64 {
        // Exact single-step rational (§2.3 п.2), no intermediate truncation:
        //   stell_nano = floor((asset_amount · price_micro_usd · 10^9)
        //                      / (10^decimals · P0))
        // evaluated as ONE `mul_div_floor_256` over a 256-bit product, instead
        // of two chained floored divisions (which lose the exact sub-unit
        // remainder). `asset_amount · price_micro_usd` fits u128; `10^decimals`
        // and the denominator fail closed to 0 on absurd decimal counts
        // (`checked_pow` / `checked_mul`). A quotient that does not fit u128 is
        // saturated to `u64::MAX` (the long-standing contract: absurd inputs
        // are refused later by `deposit_and_mint`'s cap check, never wrapped).
        let numer = (asset_amount as u128) * (price_micro_usd as u128);
        let Some(scale) = 10u128.checked_pow(asset_decimals) else {
            return 0;
        };
        let Some(den) = scale.checked_mul(BASE_STELL_PRICE_MICRO_USD as u128) else {
            return 0;
        };
        match mul_div_floor_256(numer, 1_000_000_000u128, den) {
            Ok(stell_nano) => u128::min(stell_nano, u64::MAX as u128) as u64,
            Err(_) => u64::MAX,
        }
    }

    /// Deposit incoming asset and mint STELL from Genesis Vault
    pub fn deposit_and_mint(
        &mut self,
        asset: &str,
        asset_amount: u64,
        asset_price_micro_usd: u64,
    ) -> Result<u64, String> {
        let (decimals, target_deposit) = match asset {
            "USDT" => (6, &mut self.usdt_deposited_micro),
            "TON" => (9, &mut self.ton_deposited_nano),
            "GRAM" => (9, &mut self.gram_deposited_nano),
            _ => {
                return Err(
                    "Unsupported genesis asset. Only USDT, TON, and GRAM accepted".to_string(),
                )
            }
        };

        let mint_nano = Self::calculate_mint(asset_amount, decimals, asset_price_micro_usd);
        if asset_amount > 0 && mint_nano == 0 {
            return Err("Genesis Vault: zero STELL minted for deposit (ZeroMint)".to_string());
        }

        // Fail-closed arithmetic (econ audit 2026-11-01): the bare `+` panicked
        // on overflow in debug (and the `+=`s below too). `checked_add`
        // refuses instead of wrapping, so an absurd mint can never pass the
        // cap check on a wrapped value.
        let new_total = self
            .total_minted_nano
            .checked_add(mint_nano)
            .ok_or_else(|| {
                "Genesis Vault mint overflows u64: refusing instead of wrapping".to_string()
            })?;
        if new_total > GENESIS_VAULT_CAP {
            return Err("Genesis Vault allocation cap reached (250,000,000 STELL)".to_string());
        }

        let new_deposit = target_deposit.checked_add(asset_amount).ok_or_else(|| {
            "Genesis Vault deposit overflows u64: refusing instead of wrapping".to_string()
        })?;

        self.total_minted_nano = new_total;
        *target_deposit = new_deposit;

        Ok(mint_nano)
    }

    /// Strict deposit variant (for post-hardening activation) that also
    /// rejects zero-amount deposits with `ZeroMint`.
    pub fn deposit_and_mint_checked(
        &mut self,
        asset: &str,
        asset_amount: u64,
        asset_price_micro_usd: u64,
    ) -> Result<u64, String> {
        if asset_amount == 0 {
            return Err("Genesis Vault: zero STELL minted for deposit (ZeroMint)".to_string());
        }
        self.deposit_and_mint(asset, asset_amount, asset_price_micro_usd)
    }
}

/// Core Team Vesting Schedule: 12-month cliff, 24-month linear vesting
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeamVestingSchedule {
    pub total_allocation: u64,
    pub start_timestamp: u64,
    pub cliff_duration_secs: u64,
    pub vesting_duration_secs: u64,
    pub claimed_amount: u64,
}

impl Default for TeamVestingSchedule {
    fn default() -> Self {
        Self {
            total_allocation: 100_000_000 * 1_000_000_000, // 100M STELL
            start_timestamp: 0,
            cliff_duration_secs: 12 * 30 * 86400, // 12 months cliff (360 days)
            vesting_duration_secs: 24 * 30 * 86400, // 24 months vesting (720 days)
            claimed_amount: 0,
        }
    }
}

impl TeamVestingSchedule {
    pub fn new(start_timestamp: u64) -> Self {
        Self {
            start_timestamp,
            ..Default::default()
        }
    }

    /// Calculate unlocked tokens at current timestamp
    pub fn unlocked_amount(&self, current_timestamp: u64) -> u64 {
        let cliff_end = self
            .start_timestamp
            .saturating_add(self.cliff_duration_secs);
        if current_timestamp < cliff_end {
            return 0;
        }

        let elapsed = current_timestamp - cliff_end;
        if elapsed >= self.vesting_duration_secs {
            return self.total_allocation;
        }

        ((self.total_allocation as u128 * elapsed as u128) / (self.vesting_duration_secs as u128))
            as u64
    }

    pub fn claimable_amount(&self, current_timestamp: u64) -> u64 {
        self.unlocked_amount(current_timestamp)
            .saturating_sub(self.claimed_amount)
    }

    /// Locked (unspendable) amount at `current_timestamp`: total minus unlocked.
    ///
    /// Pure and deterministic: the complement of [`Self::unlocked_amount`], so
    /// `locked + unlocked == total` always. The spend gate
    /// ([`Self::check_balance_floor`]) is expressed in terms of this floor so
    /// cumulative spends are bounded WITHOUT tracking `claimed_amount` on
    /// every transfer (a per-spend `claimable` check alone would let N spends
    /// of `unlocked` each drain N×`unlocked`).
    pub fn locked_amount(&self, current_timestamp: u64) -> u64 {
        self.total_allocation
            .saturating_sub(self.unlocked_amount(current_timestamp))
    }

    /// Fail-closed single-spend gate against the claimable amount.
    ///
    /// Refuses (Err, no state change) when `spend_amount` exceeds
    /// [`Self::claimable_amount`] at `current_timestamp`. For EXPLICIT claim
    /// flows: pair with [`Self::record_claim`] so the claimed counter
    /// advances and repeated claims cannot re-spend the same unlocked funds.
    /// The on-chain spend path does NOT use this (it uses
    /// [`Self::check_balance_floor`], which bounds cumulative spends without
    /// per-transfer bookkeeping) — this is the API an explicit claim opcode
    /// or off-chain accounting calls.
    pub fn check_spend_allowed(
        &self,
        current_timestamp: u64,
        spend_amount: u64,
    ) -> Result<(), String> {
        let claimable = self.claimable_amount(current_timestamp);
        if spend_amount > claimable {
            return Err(format!(
                "team vesting lock: spend {spend_amount} exceeds claimable {claimable} (unlocked {} of total {}, already claimed {})",
                self.unlocked_amount(current_timestamp),
                self.total_allocation,
                self.claimed_amount,
            ));
        }
        Ok(())
    }

    /// Fail-closed cumulative-spend gate against the locked floor.
    ///
    /// Refuses (Err, no state change) when the account's post-spend balance
    /// would fall below [`Self::locked_amount`] at `current_timestamp` — i.e.
    /// more of the allocation left the account than has unlocked. This is the
    /// gate the spend path enforces: with `balance_after = balance_before -
    /// total_debit`, `balance_after >= locked ⟺ total_spent <= unlocked`
    /// (when the account was funded with exactly the allocation and inbound
    /// transfers only raise the balance, never the spendable locked part).
    pub fn check_balance_floor(
        &self,
        current_timestamp: u64,
        balance_after: u64,
    ) -> Result<(), String> {
        let locked = self.locked_amount(current_timestamp);
        if balance_after < locked {
            return Err(format!(
                "team vesting lock: balance after spend {balance_after} would fall below locked {locked} (unlocked {} of total {})",
                self.unlocked_amount(current_timestamp),
                self.total_allocation,
            ));
        }
        Ok(())
    }

    /// Advance the claimed counter by `amount`, fail-closed.
    ///
    /// Refuses (Err, counter untouched) when `amount` exceeds the claimable
    /// amount, so an explicit claim can never over-claim. Pair with
    /// [`Self::check_spend_allowed`]: check-then-record is atomic here
    /// because both run on the same `&mut self` with no await between them.
    pub fn record_claim(&mut self, current_timestamp: u64, amount: u64) -> Result<(), String> {
        self.check_spend_allowed(current_timestamp, amount)?;
        self.claimed_amount = self.claimed_amount.saturating_add(amount);
        Ok(())
    }
}

/// 5-10 Year Staking and Validator Rewards Schedule (350M STELL total pool)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StakingEmissionSchedule {
    pub total_pool: u64,
    pub emitted: u64,
    pub annual_base_rate_bps: u64, // e.g. 700 = 7% per year
}

impl Default for StakingEmissionSchedule {
    fn default() -> Self {
        Self {
            total_pool: 350_000_000 * 1_000_000_000, // 350M STELL
            emitted: 0,
            annual_base_rate_bps: 700,
        }
    }
}

impl StakingEmissionSchedule {
    /// INTENTIONALLY DEAD — DO NOT WIRE, DO NOT DELETE (audit I1, owner
    /// directive 2026-10-14: deletion is FORBIDDEN).
    ///
    /// The LIVE path is the flat per-proposer reward [`BLOCK_REWARD_NANO`]
    /// (0.317 STELL to the block proposer every block, governed via
    /// `SetBlockReward`, capped by `REWARDS_EMISSION_CAP` in
    /// `StakingLedger::distribute_reward`): `main.rs` passes
    /// `BLOCK_REWARD_NANO` to `with_block_reward`, the engine mints it
    /// 1:1 into `REWARDS_POOL` (ledger + native), and claims drain the pool.
    /// Pinned live by `flat_block_reward_is_live_and_schedule_is_dead`.
    ///
    /// THIS function divides the same base by `active_validators` — a
    /// per-member-every-block semantic. Applied per-proposer (the only live
    /// call shape) it would UNDERPAY N× (at N=3: 0.106 vs 0.317 STELL/block)
    /// and silently starve proposers while the cap math assumes the flat
    /// rate (350 M ÷ 0.317 ≈ 1.10 B blocks ≈ 7.0 yr at 200 ms blocks).
    /// Zero callers, by decree: keep it as the documented reference curve
    /// for a future every-member payout design, never as a live input.
    /// (Block-time comments elsewhere conflict — 200 ms here vs 3 s in
    /// staking vs 250 ms–1 s in docs — audit O3: projections only, the
    /// unbonding clock uses timestamps and the slash cooldown uses heights,
    /// so determinism is unaffected. Reconcile before quoting cap dates.)
    pub fn calculate_block_reward(&self, active_validators: usize) -> u64 {
        if self.emitted >= self.total_pool || active_validators == 0 {
            return 0;
        }
        // ECON TRUTH (frozen-economics audit 2026-11-05, math ref
        // `stellereum-math/papers/03_economics.md` §10 + `results/emission.json`):
        // the "≈7 years" below is true ONLY on the OLD 200 ms block clock
        // (5 blocks/s = 157,680,000 blocks/yr). The README target block time
        // is 0.6 s, on which the SAME pool and reward exhaust far later:
        //
        //   H* = P / R = 350,000,000 / 0.317 = 1,104,100,946 blocks (pinned
        //        by `emission_exhaustion_height_is_pinned` below).
        //   T* = H* · τ  →  0.2 s: 7.00 yr | 0.25 s: 8.75 yr
        //                   0.6 s: 21.01 yr | 1.0 s: 35.01 yr | 3 s: 105.03 yr
        //
        // At 0.6 s the flat 0.317 STELL/block emits ≈16.66M STELL/yr (≈6.67%
        // on 250M circulating at pool-full, 3.92% at half pool). At 200 ms it
        // would be ≈50M STELL/yr (≈20%/yr initially). Cap date, inflation and
        // reward forecasts MUST state which τ they assume.
        //
        // FOR-LEAD-DECISION (report §11 cap-exact geometric schedule, NOT
        // implemented): R_h = R0·2^(−h/H), R0 = P·(1−2^(−1/H)), which emits
        // exactly P over the infinite tail (99% by H·log2(100) blocks). E.g.
        // 7-yr horizon at 0.6 s → H≈1.054 yr, R0≈4.381 STELL/block vs the
        // flat 0.317. Pure reference math lives in
        // `geometric_schedule_r0_nano` / `geometric_reward_at_height` below
        // (PROPOSAL ONLY — no consensus wiring; changing the live flat
        // reward needs a spec update + audit note per frozen-core rule 7).
        // 350M / 7 years ~= 50M STELL/year ~= 0.317 STELL per block [200 ms
        // clock only — see truth table above; 21.01 yr at the 0.6 s target].
        BLOCK_REWARD_NANO / (active_validators as u64)
    }

    /// Height-gated live emission (cap-exact rollout knob).
    ///
    /// Below [`EMISSIONCapEXACT_ACTIVATION_HEIGHT`] → the current schedule
    /// ([`Self::calculate_block_reward`], flat per-proposer semantics).
    /// At/above → the cap-exact geometric leg
    /// `geometric_reward_at_height(CAP_EXACT_R0_NANO, CAP_EXACT_HALF_LIFE_BLOCKS,
    /// height − activation)` (RELATIVE height, so the boundary pays exactly
    /// R0). The geometric leg is per-proposer like the live flat reward —
    /// no division by `active_validators`.
    ///
    /// Integer dispatch only — no float in this body; the geometric math is
    /// sibling-owned ([`geometric_reward_at_height`]), REUSED via delegation,
    /// never duplicated. While the activation is `u64::MAX`, EVERY height
    /// (including `u64::MAX`) takes the flat branch: byte-identical to
    /// [`Self::calculate_block_reward`] and consistent with `chain_spec::ActivationStatus::GatedOff`.
    pub fn calculate_block_reward_at_height(&self, active_validators: usize, height: u64) -> u64 {
        self.calculate_block_reward_with_activation(
            active_validators,
            height,
            EMISSIONCapEXACT_ACTIVATION_HEIGHT,
        )
    }

    fn calculate_block_reward_with_activation(
        &self,
        active_validators: usize,
        height: u64,
        activation_height: u64,
    ) -> u64 {
        if self.emitted >= self.total_pool || active_validators == 0 {
            return 0;
        }
        if activation_height == u64::MAX || height < activation_height {
            self.calculate_block_reward(active_validators)
        } else {
            geometric_reward_at_height(
                CAP_EXACT_R0_NANO,
                CAP_EXACT_HALF_LIFE_BLOCKS,
                height - activation_height,
            )
        }
    }
}

/// GATED cap-exact geometric emission schedule (report §11, Eq. 4).
///
/// The live path stays the flat per-proposer [`BLOCK_REWARD_NANO`]
/// (consensus-feeding — see the truth note on
/// [`StakingEmissionSchedule::calculate_block_reward`]) while
/// [`EMISSIONCapEXACT_ACTIVATION_HEIGHT`] is `u64::MAX` (INACTIVE). These
/// helpers are the pure reference math for the schedule the height gate in
/// [`StakingEmissionSchedule::calculate_block_reward_at_height`] delegates
/// to at/above activation — REUSED there, never duplicated.
/// (Flipping the activation to a reachable height is a consensus change:
/// needs a spec update + audit note per frozen-core rule 7.)
///
/// R_h = R0 · 2^(−h/H), with R0 = P · (1 − 2^(−1/H)); Σ_{h≥0} R_h = P
/// exactly (infinite tail; 99% emitted by H·log2(100) blocks per Thm. 4).
/// All amounts in nano-STELL; heights in blocks.
pub fn geometric_schedule_r0_nano(pool_nano: u64, half_life_blocks: u64) -> u64 {
    if pool_nano == 0 || half_life_blocks == 0 {
        return 0;
    }
    let decay = 0.5f64.powf(1.0 / half_life_blocks as f64);
    ((pool_nano as f64) * (1.0 - decay)) as u64
}

/// Pure deterministic integer fixed-point `floor(r0_nano * 2^(-height / half_life_blocks))`.
///
/// Decomposes `height / half_life_blocks = whole + rem_h / half_life_blocks`:
/// - Whole halvings (`whole`) are an exact right-shift (`>> whole`, returning
///   `0` for `whole >= 64`).
/// - The fractional exponent `rem_h / half_life_blocks in [0, 1)` is evaluated
///   via 64-bit binary decomposition in Q0.64 using repeated `u128::isqrt`
///   (`2^(-2^-i)` starting from `2^-1 = 1 << 63`).
///
/// Zero `f64` / `libm` dependency: bit-identical across all platforms and
/// strictly a floor (`<=` exact real value, so emissions never exceed cap).
fn pow_half_fixed(r0_nano: u64, half_life_blocks: u64, height: u64) -> u64 {
    pow_half_fixed_exact_q64(r0_nano, half_life_blocks, height).0
}

/// Q64.64 factor `2^(-rem_h / half_life_blocks)` for `rem_h in [0, h)`.
///
/// Binary decomposition of the fractional exponent: bit `i` of
/// `rem_h / half_life_blocks` multiplies `acc` by `2^(-2^-i)`, each computed by
/// repeated `u128::isqrt` (`s` starts at `2^(-1) = 1 << 63`). Pure integer, no
/// float. Returns `1.0` in Q64.64 (`1 << 64`) for `rem_h == 0`.
fn pow2_frac_q64(half_life_blocks: u64, rem_h: u64) -> u128 {
    if rem_h == 0 {
        return 1u128 << 64;
    }
    let h = half_life_blocks as u128;
    let mut rem = rem_h as u128;
    let mut s = 1u128 << 63; // 2^(-1) in Q0.64
    let mut acc = 1u128 << 64; // 1.0 in Q64.64
    for _ in 0..64 {
        s = (s << 64).isqrt();
        rem <<= 1;
        if rem >= h {
            rem -= h;
            acc = (acc * s) >> 64;
        }
        if rem == 0 {
            break;
        }
    }
    acc
}

/// Exact fixed-point `floor(r0_nano · 2^(-height / half_life_blocks))` PLUS the
/// sub-nano remainder in Q64.64 (§2.3 п.4).
///
/// Returns `(floor_nano, frac_q64)` where the exact real reward is
/// `floor_nano + frac_q64 / 2^64` nano-STELL. Unlike
/// `pow_half_fixed`'s old `((r0 · acc) >> 64) >> whole`, this keeps the low
/// 64 bits of `r0 · acc` and the bits shifted out by `whole`, so an external
/// [`emit_with_q64_carry`] accumulator can emit them later instead of losing
/// up to 1 nano per block forever.
///
/// * Whole halvings are an exact right shift of the 128-bit Q64.64 product
///   (`whole >= 128` → `(0, 0)`: the value is below `2^-64` nano, i.e. dust
///   that can never round up within `u64` nano accounting).
/// * `half_life_blocks == 0` is defined deterministically as `(0, 0)` — no
///   panic, no division by zero.
/// * The floor equals the legacy `pow_half_fixed` output exactly (shifts
///   compose: `(x >> 64) >> whole == x >> (64 + whole)`), so the LIVE
///   geometric schedule does not change.
pub fn pow_half_fixed_exact_q64(r0_nano: u64, half_life_blocks: u64, height: u64) -> (u64, u64) {
    if r0_nano == 0 || half_life_blocks == 0 {
        return (0, 0);
    }
    let whole = height / half_life_blocks;
    let rem_h = height % half_life_blocks;
    let acc = pow2_frac_q64(half_life_blocks, rem_h);
    // r0 < 2^64 and acc <= 2^64, so the Q64.64 product always fits u128.
    let exact_q64 = (r0_nano as u128) * acc;
    let shifted = if whole >= 128 { 0 } else { exact_q64 >> whole };
    ((shifted >> 64) as u64, shifted as u64)
}

/// One emission step with a Q64.64 carry: exact per-height reward plus the
/// carried sub-nano remainder from previous heights.
///
/// `total_q64 = (reward_q64 + carry_q64)`, `emit_nano = floor(total)`, and the
/// new carry is the low 64 bits of `total_q64` (always `< 2^64`). The caller
/// stores the returned carry across heights; because every emitted nano comes
/// from an exact floor of the cumulative reward, the SUM of emissions over any
/// horizon never exceeds `floor(Σ exact rewards)` — the `P = 350M STELL`
/// (and therefore `TOTAL_SUPPLY_CAP = 1B STELL`) bound still holds. The
/// emission still has to pass `reserve_mint` / `REWARDS_EMISSION_CAP` at the
/// call site (§2.3 п.4 hard invariant).
///
/// `half_life_blocks == 0` returns `(0, carry_q64)` deterministically (no
/// panic, carry preserved). An absurd `r0_nano = u64::MAX` at `height = 0`
/// with `carry_q64 = u64::MAX` would mathematically need `2^64`; the emitted
/// nano saturates at `u64::MAX` instead of wrapping (unreachable at pool
/// magnitudes: real `R0` is a few nano-billions).
pub fn emit_with_q64_carry(
    r0_nano: u64,
    half_life_blocks: u64,
    height: u64,
    carry_q64: u64,
) -> (u64, u64) {
    if r0_nano == 0 || half_life_blocks == 0 {
        return (0, carry_q64);
    }
    let (floor_nano, frac_q64) = pow_half_fixed_exact_q64(r0_nano, half_life_blocks, height);
    let total_q64 = (frac_q64 as u128) + (carry_q64 as u128);
    let emit_nano = (floor_nano as u128) + (total_q64 >> 64);
    (
        u128::min(emit_nano, u64::MAX as u128) as u64,
        total_q64 as u64,
    )
}

/// Geometric per-height reward (report §11, Eq. 4).
/// Pure deterministic integer fixed-point: R_h = floor(R0 · 2^(−h/H)) in
/// whole nano-STELL. Called by the height gate
/// ([`StakingEmissionSchedule::calculate_block_reward_at_height`]) and by
/// tests; wiring any OTHER payout path to it is a consensus change.
pub fn geometric_reward_at_height(r0_nano: u64, half_life_blocks: u64, height: u64) -> u64 {
    pow_half_fixed(r0_nano, half_life_blocks, height)
}

#[cfg(test)]
mod econ_truth_tests {
    use super::*;

    /// Seconds per (365-day) year, matching `results/emission.json`.
    const SECS_PER_YEAR: f64 = 31_536_000.0;

    #[test]
    fn flat_reward_and_pool_are_pinned() {
        assert_eq!(
            BLOCK_REWARD_NANO, 317_000_000,
            "live flat reward: 0.317 STELL"
        );
        let sched = StakingEmissionSchedule::default();
        assert_eq!(sched.total_pool, 350_000_000 * 1_000_000_000);
        assert_eq!(sched.annual_base_rate_bps, 700);
        assert_eq!(TOTAL_SUPPLY_CAP, 1_000_000_000 * 1_000_000_000);
        assert_eq!(GENESIS_VAULT_CAP, 250_000_000 * 1_000_000_000);
    }

    #[test]
    fn emission_exhaustion_height_is_pinned() {
        // H* = P / R (integer division): the cap-exhaustion height the flat
        // live reward implies. Matches emission.json `blocks_to_exhaust`.
        let sched = StakingEmissionSchedule::default();
        let h_star = sched.total_pool / BLOCK_REWARD_NANO;
        assert_eq!(h_star, 1_104_100_946u64);
    }

    #[test]
    fn exhaustion_truth_21y_at_0_6s_not_7y() {
        // T* = H* · τ. The stale "≈7 years" comment was true only at 200 ms;
        // the README 0.6 s target exhausts in ≈21.01 yr (emission.json).
        let h_star = 1_104_100_946.372_239_8f64;
        let years = |tau_s: f64| h_star * tau_s / SECS_PER_YEAR;
        assert!((years(0.2) - 7.002).abs() < 0.01, "0.2s → ≈7.00 yr");
        assert!((years(0.6) - 21.006).abs() < 0.01, "0.6s → ≈21.01 yr");
        assert!((years(1.0) - 35.011).abs() < 0.02, "1.0s → ≈35.01 yr");
        assert!((years(3.0) - 105.032).abs() < 0.05, "3s → ≈105.03 yr");
    }

    #[test]
    fn dead_schedule_semantics_are_pinned() {
        // calculate_block_reward divides by N (per-member-every-block): N×
        // underpay per-proposer, so it must stay dead. Pin the semantics.
        let sched = StakingEmissionSchedule::default();
        assert_eq!(sched.calculate_block_reward(3), BLOCK_REWARD_NANO / 3);
        assert_eq!(sched.calculate_block_reward(0), 0);
        let mut drained = StakingEmissionSchedule::default();
        drained.emitted = drained.total_pool;
        assert_eq!(drained.calculate_block_reward(1), 0);
    }

    #[test]
    fn geometric_proposal_r0_matches_report_row() {
        // emission.json cap-exact row: 7-yr horizon at 0.6 s → half-life
        // 1.054 yr, R0 ≈ 4.380869639 STELL (checksum_total_infinity = 350M).
        let blocks_per_year = (SECS_PER_YEAR / 0.6) as u64; // 52,560,000
        let half_life_blocks = (1.054 * blocks_per_year as f64) as u64;
        let pool = 350_000_000 * 1_000_000_000u64;
        let r0 = geometric_schedule_r0_nano(pool, half_life_blocks);
        let r0_stell = r0 as f64 / 1_000_000_000.0;
        assert!(
            (r0_stell - 4.380_869_639).abs() / 4.380_869_639 < 0.01,
            "R0 ≈ 4.381 STELL/block, got {r0_stell}"
        );
        assert_eq!(geometric_reward_at_height(r0, half_life_blocks, 0), r0);
        // Halving: R_H ≈ R0/2 within float→int flooring (±2 nano).
        let at_h = geometric_reward_at_height(r0, half_life_blocks, half_life_blocks);
        assert!((at_h as i64 - r0 as i64 / 2).abs() <= 2);
    }

    #[test]
    fn geometric_proposal_checksum_covers_pool() {
        // Thm. 4 spot-check: summing R_h over H·log2(100) blocks emits ≈99%
        // of the pool (tail sum, not closed form — flooring costs dust).
        let half_life_blocks = 1_000u64;
        let pool = 350_000_000 * 1_000_000_000u64;
        let r0 = geometric_schedule_r0_nano(pool, half_life_blocks);
        let n = (half_life_blocks as f64 * 6.643_856_19) as u64; // H·log2(100)
        let mut sum: u128 = 0;
        for h in 0..n {
            sum += geometric_reward_at_height(r0, half_life_blocks, h) as u128;
        }
        let frac = sum as f64 / pool as f64;
        assert!(
            (frac - 0.99).abs() < 0.005,
            "99% by H·log2(100), got {frac}"
        );
    }

    #[test]
    fn cap_exact_gate_is_inactive_by_default() {
        assert_eq!(
            EMISSIONCapEXACT_ACTIVATION_HEIGHT,
            u64::MAX,
            "gate INACTIVE until the lead flips it at rollout"
        );
    }

    #[test]
    fn gated_pre_activation_pins_current_values() {
        // While inactive (`u64::MAX`) EVERY height including `u64::MAX` takes
        // the flat branch: byte-identical to the current schedule (values
        // locked, unmodified) and aligned with `chain_spec::ActivationStatus::GatedOff`.
        let sched = StakingEmissionSchedule::default();
        for &h in &[
            0u64,
            1,
            100,
            1_104_100_945,
            1_104_100_946,
            u64::MAX - 1,
            u64::MAX,
        ] {
            assert_eq!(
                sched.calculate_block_reward_at_height(1, h),
                BLOCK_REWARD_NANO,
                "N=1 flat 0.317 @ h={h}"
            );
            assert_eq!(
                sched.calculate_block_reward_at_height(3, h),
                BLOCK_REWARD_NANO / 3,
                "N=3 @ h={h}"
            );
            assert_eq!(
                sched.calculate_block_reward_at_height(0, h),
                0,
                "N=0 @ h={h}"
            );
        }
        let mut drained = StakingEmissionSchedule::default();
        drained.emitted = drained.total_pool;
        assert_eq!(drained.calculate_block_reward_at_height(1, 0), 0);
        assert_eq!(
            drained.calculate_block_reward_at_height(1, u64::MAX),
            0,
            "drained stays 0 even at the boundary height"
        );
    }

    #[test]
    fn cap_exact_r0_matches_eq4_and_json_row() {
        // emission.json 7-yr@0.6s row: half-life 1.054 yr, R0 4.380869639
        // STELL. Integer-only derivation (no float): blocks/yr at 0.6 s =
        // 31,536,000·10/6; H = 1.054 yr = ×1054/1000.
        let blocks_per_year = 31_536_000u64 * 10 / 6;
        assert_eq!(blocks_per_year, 52_560_000);
        assert_eq!(
            CAP_EXACT_HALF_LIFE_BLOCKS,
            blocks_per_year * 1054 / 1000,
            "H = 1.054 yr in blocks"
        );
        assert_eq!(CAP_EXACT_HALF_LIFE_BLOCKS, 55_398_240);
        let pool = StakingEmissionSchedule::default().total_pool;
        // Exact R0 from Eq. 4 via the sibling helper (REUSED, not duplicated).
        assert_eq!(
            CAP_EXACT_R0_NANO,
            geometric_schedule_r0_nano(pool, CAP_EXACT_HALF_LIFE_BLOCKS),
            "R0 pinned to Eq.4 helper output"
        );
        // Cross-check against the emission.json row 4_380_869_639 nano
        // (±1% integer band: helper float floors ≈0.037% under the row).
        let json_r0_nano = 4_380_869_639u64;
        let lo = json_r0_nano * 99 / 100;
        let hi = json_r0_nano * 101 / 100;
        assert!(
            (lo..=hi).contains(&CAP_EXACT_R0_NANO),
            "R0 {} within ±1% of json row {json_r0_nano}",
            CAP_EXACT_R0_NANO,
        );
        // R0 ≈ 4.381 STELL (integer whole-STELL part, no float).
        assert_eq!(CAP_EXACT_R0_NANO / 1_000_000_000, 4);
    }

    #[test]
    fn gated_boundary_is_exact() {
        let sched = StakingEmissionSchedule::default();
        let a = EMISSIONCapEXACT_ACTIVATION_HEIGHT;
        if a == u64::MAX {
            // Gated off sentinel: inactive for all heights including u64::MAX.
            assert_eq!(
                sched.calculate_block_reward_at_height(1, u64::MAX - 1),
                BLOCK_REWARD_NANO,
                "u64::MAX sentinel: u64::MAX - 1 takes flat 0.317"
            );
            assert_eq!(
                sched.calculate_block_reward_at_height(1, u64::MAX),
                BLOCK_REWARD_NANO,
                "u64::MAX sentinel: u64::MAX also stays flat 0.317 (matches chain_spec::GatedOff)"
            );
        } else if a > 0 {
            assert_eq!(
                sched.calculate_block_reward_at_height(1, a - 1),
                BLOCK_REWARD_NANO,
                "just below activation: flat 0.317"
            );
            assert_eq!(
                sched.calculate_block_reward_at_height(1, a),
                CAP_EXACT_R0_NANO,
                "boundary: exactly R0 (relative height 0)"
            );
        }

        // Also exercise an active activation height boundary directly.
        let active_a = 1_000_000u64;
        assert_eq!(
            sched.calculate_block_reward_with_activation(1, active_a - 1, active_a),
            BLOCK_REWARD_NANO,
            "just below active boundary: flat 0.317"
        );
        assert_eq!(
            sched.calculate_block_reward_with_activation(1, active_a, active_a),
            CAP_EXACT_R0_NANO,
            "active boundary: exactly R0 (relative height 0)"
        );
        assert_eq!(
            sched.calculate_block_reward_with_activation(1, active_a, active_a),
            geometric_reward_at_height(CAP_EXACT_R0_NANO, CAP_EXACT_HALF_LIFE_BLOCKS, 0)
        );
        assert_eq!(
            sched.calculate_block_reward_with_activation(
                1,
                active_a + CAP_EXACT_HALF_LIFE_BLOCKS,
                active_a
            ),
            CAP_EXACT_R0_NANO / 2,
            "one half-life past active boundary: exact halving"
        );
    }

    #[test]
    fn cap_exact_integer_discipline_no_overflow() {
        // New gate code is integer nano math only (u64 domain, u128
        // accumulators): prove no overflow at pool magnitudes.
        let pool = StakingEmissionSchedule::default().total_pool as u128;
        let r0 = CAP_EXACT_R0_NANO as u128;
        assert!(pool < u64::MAX as u128, "pool fits u64 with headroom");
        assert!(r0 < pool, "R0 is a small fraction of pool");
        assert!(CAP_EXACT_R0_NANO.checked_mul(2).is_some(), "2×R0 fits u64");
        // 99% horizon H·log2(100) in integer math (6.64385619 → 6643856/1e6).
        let n99 = CAP_EXACT_HALF_LIFE_BLOCKS
            .checked_mul(6_643_856)
            .expect("n99 multiply fits u64")
            / 1_000_000;
        assert!(n99 > CAP_EXACT_HALF_LIFE_BLOCKS);
        // Rewards never exceed R0 and never wrap (sampled relative heights).
        for &rel in &[
            0u64,
            1,
            CAP_EXACT_HALF_LIFE_BLOCKS,
            2 * CAP_EXACT_HALF_LIFE_BLOCKS,
        ] {
            let r = geometric_reward_at_height(CAP_EXACT_R0_NANO, CAP_EXACT_HALF_LIFE_BLOCKS, rel);
            assert!(r <= CAP_EXACT_R0_NANO, "rel={rel}: {r} <= R0");
        }
        // u128 accumulator smoke: first 1000 rewards sum far below pool.
        let mut sum: u128 = 0;
        for rel in 0..1000u64 {
            sum += geometric_reward_at_height(CAP_EXACT_R0_NANO, CAP_EXACT_HALF_LIFE_BLOCKS, rel)
                as u128;
        }
        assert!(sum < pool, "1000-block prefix {sum} < pool {pool}");
    }

    #[test]
    fn cap_exact_checksum_99_by_h_log2_100_integer() {
        // Thm. 4 spot-check on small H (the real-H horizon is 368M blocks —
        // unloopable in a unit test). Integer-only: horizon via integer
        // ratio, percent via u128 math (floor → 98 or 99 both pass).
        let half_life_blocks = 1_000u64;
        let pool = StakingEmissionSchedule::default().total_pool;
        let r0 = geometric_schedule_r0_nano(pool, half_life_blocks);
        let n = half_life_blocks * 6_643_856 / 1_000_000; // H·log2(100)
        assert_eq!(n, 6643);
        let mut sum: u128 = 0;
        for h in 0..n {
            sum += geometric_reward_at_height(r0, half_life_blocks, h) as u128;
        }
        let pct = sum * 100 / pool as u128;
        assert!(
            (98..=99).contains(&pct),
            "99% by H·log2(100), integer pct={pct}"
        );
    }

    /// FIXES §1.10/§4.7 lock: H_b is in BLOCKS —
    /// H_b = T·SEC_PER_YEAR/τ / log2(100) — derived here with INTEGER-ONLY
    /// math (no f64 in this test body).
    ///
    /// 7-yr horizon at τ = 0.6 s: N_T = 7·31,536,000·10/6 = 367,920,000
    /// blocks; log2(100) = 6.64385618977… → 6_643_856/1e6 (floor, same scale
    /// as `cap_exact_checksum_99_by_h_log2_100_integer`).
    /// Exact-formula floor: 367,920,000·1e6/6_643_856 = 55,377,479.
    /// Pinned `CAP_EXACT_HALF_LIFE_BLOCKS` = 55,398,240 (= 1.054 yr in blocks,
    /// the emission.json row's 3-decimal half-life) sits 20,761 blocks
    /// (+0.037%) above the exact floor: 1.054 rounds the true 1.05360498… yr
    /// UP. REPORTED rounding gap (not an economics change): the pinned value
    /// stays frozen; this test locks BOTH numbers and the <0.1% band so any
    /// future H_b change trips loudly.
    #[test]
    fn hb_is_in_blocks_per_spec_section_1_10_integer() {
        let blocks_per_year = 31_536_000u64 * 10 / 6; // τ = 0.6 s, integer
        assert_eq!(blocks_per_year, 52_560_000);
        let n_t = 7u64 * blocks_per_year; // T = 7 yr horizon
        assert_eq!(n_t, 367_920_000);
        let h_exact_floor = n_t * 1_000_000 / 6_643_856; // N_T / log2(100)
        assert_eq!(h_exact_floor, 55_377_479);
        assert_eq!(CAP_EXACT_HALF_LIFE_BLOCKS, 55_398_240);
        let delta = CAP_EXACT_HALF_LIFE_BLOCKS - h_exact_floor;
        assert_eq!(delta, 20_761);
        // Rounded spec value stays within 0.1% of the exact formula.
        assert!(
            delta * 1000 <= h_exact_floor,
            "delta {delta} must be <0.1% of {h_exact_floor}"
        );
    }

    /// FIXES §2.8/§4.7 lock: Σ_{h≥0} R_h = P (infinite-tail checksum).
    ///
    /// The real-H horizon (368M blocks) is unloopable, so this test checks the
    /// SAME helper family at small H exhaustively: sum every nonzero floored
    /// reward until the helper returns 0, then bound the dust. Flooring can
    /// only UNDERpay (each term loses < 1 nano; the sub-nano tail past the
    /// last nonzero term integrates to < H/ln2 + 1 nano), so P − dust ≤ sum ≤
    /// P with dust = terms + 2·H (generous integer bound). Integer-only test
    /// body (u128 accumulators); the helpers' own float is the REPORTED §4.7
    /// gap (tokenomics.rs:402-419), not re-proven here.
    #[test]
    fn infinite_sum_checksum_within_flooring_dust_small_h() {
        let pool = StakingEmissionSchedule::default().total_pool;
        let h = 1_000u64;
        let r0 = geometric_schedule_r0_nano(pool, h);
        assert!(r0 > 0 && r0 < pool);
        let mut sum: u128 = 0;
        let mut terms: u128 = 0;
        let mut height: u64 = 0;
        loop {
            let r = geometric_reward_at_height(r0, h, height) as u128;
            if r == 0 {
                break;
            }
            sum += r;
            terms += 1;
            height += 1;
            assert!(height < 1_000_000, "must reach zero reward (H={h})");
        }
        assert!(terms > 0);
        assert!(
            sum <= pool as u128,
            "floored sum {sum} must never exceed pool {pool}"
        );
        let deficit = pool as u128 - sum;
        // Generous integer dust bound: <1 nano per floored term plus a 2·H
        // nano allowance covering the sub-nano tail (true tail < H/ln2 + 1).
        let dust_bound = terms + 2 * h as u128;
        assert!(
            deficit <= dust_bound,
            "ΣR_h must equal P within flooring dust: deficit={deficit} bound={dust_bound} terms={terms}"
        );
        // Sanity: essentially the whole pool is emitted (far above the 99%
        // spot already pinned elsewhere).
        assert!(
            sum * 100_000 >= pool as u128 * 99_999,
            "sum={sum} pool={pool}"
        );
    }
}

#[cfg(test)]
mod w4_economics_tests {
    use super::*;

    #[test]
    fn activation_gates_are_active_from_genesis_by_default() {
        assert_eq!(
            SUB_NANO_STRICT_ACTIVATION_HEIGHT, 0,
            "strict sub-nano gate ACTIVE from genesis under Ruleset v7"
        );
        assert_eq!(
            FEE_MARKET_V2_ACTIVATION_HEIGHT, 0,
            "fee market v2 gate ACTIVE from genesis under Ruleset v7"
        );
        for &h in &[0u64, 1, 100, u64::MAX - 1, u64::MAX] {
            assert!(
                sub_nano_strict_active_at(h),
                "strict sub-nano must be true @ {h}"
            );
            assert!(
                fee_market_v2_active_at(h),
                "fee market v2 must be true @ {h}"
            );
        }
    }

    #[test]
    fn activation_gate_overrides_take_effect_and_clear() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                set_sub_nano_strict_activation_override(None);
                set_fee_market_v2_activation_override(None);
            }
        }
        let _reset = Reset;

        set_sub_nano_strict_activation_override(Some(1_000));
        assert!(!sub_nano_strict_active_at(999));
        assert!(sub_nano_strict_active_at(1_000));
        assert!(sub_nano_strict_active_at(u64::MAX));
        assert_eq!(effective_sub_nano_strict_activation_height(), 1_000);
        set_sub_nano_strict_activation_override(Some(u64::MAX));
        assert!(!sub_nano_strict_active_at(u64::MAX));
        set_sub_nano_strict_activation_override(None);
        assert_eq!(effective_sub_nano_strict_activation_height(), 0);
        assert!(sub_nano_strict_active_at(0));

        set_fee_market_v2_activation_override(Some(500));
        assert!(!fee_market_v2_active_at(499));
        assert!(fee_market_v2_active_at(500));
        assert!(fee_market_v2_active_at(u64::MAX));
        assert_eq!(effective_fee_market_v2_activation_height(), 500);
        set_fee_market_v2_activation_override(Some(u64::MAX));
        assert!(!fee_market_v2_active_at(u64::MAX));
        set_fee_market_v2_activation_override(None);
        assert_eq!(effective_fee_market_v2_activation_height(), 0);
        assert!(fee_market_v2_active_at(0));
    }

    #[test]
    fn default_fee_split_sums_to_one_hundred_percent() {
        assert_eq!(DEFAULT_FEE_BURN_BPS, 5_000);
        assert_eq!(DEFAULT_FEE_PROPOSER_BPS, 3_000);
        assert_eq!(DEFAULT_FEE_STAKING_BPS, 2_000);
        assert_eq!(
            DEFAULT_FEE_BURN_BPS + DEFAULT_FEE_PROPOSER_BPS + DEFAULT_FEE_STAKING_BPS,
            10_000
        );
    }

    #[test]
    fn mul_div_floor_256_exact_and_fail_closed() {
        // Basic floor semantics.
        assert_eq!(mul_div_floor_256(0, 0, 5), Ok(0));
        assert_eq!(mul_div_floor_256(0, 123, 7), Ok(0));
        assert_eq!(mul_div_floor_256(10, 20, 8), Ok(25));
        assert_eq!(mul_div_floor_256(7, 3, 10), Ok(2)); // 2.1 floor
        assert_eq!(mul_div_floor_256(1, 1, 1), Ok(1));
        assert_eq!(mul_div_floor_256(10, 10, u128::MAX), Ok(0));

        // Boundaries: full-width operands whose quotient still fits u128.
        assert_eq!(
            mul_div_floor_256(u128::MAX, 2, 2),
            Ok(u128::MAX),
            "(2^128-1)*2/2"
        );
        assert_eq!(
            mul_div_floor_256(u128::MAX, u128::MAX, u128::MAX),
            Ok(u128::MAX),
            "(2^128-1)^2/(2^128-1)"
        );
        assert_eq!(
            mul_div_floor_256(1u128 << 127, 2, u128::MAX),
            Ok(1),
            "2^128/(2^128-1) floors to 1"
        );

        // Quotient overflow is refused, never truncated.
        assert_eq!(
            mul_div_floor_256(u128::MAX, 2, 1),
            Err("mul_div_floor_256: quotient overflows u128")
        );
        assert_eq!(
            mul_div_floor_256(u128::MAX, u128::MAX, 1),
            Err("mul_div_floor_256: quotient overflows u128")
        );

        // Zero denominator is refused.
        assert_eq!(
            mul_div_floor_256(5, 5, 0),
            Err("mul_div_floor_256: denominator is zero")
        );

        // Differential check against plain u128 arithmetic where it cannot
        // overflow (an independent expression of the same floor division).
        for &a in &[0u64, 1, 7, 1_000, 123_456_789, u32::MAX as u64] {
            for &b in &[0u64, 1, 3, 999, 1_000_000] {
                for &d in &[1u128, 3, 7, 10_000, 1_000_000_007] {
                    let a = a as u128;
                    let b = b as u128;
                    assert_eq!(
                        mul_div_floor_256(a, b, d),
                        Ok((a * b) / d),
                        "a={a} b={b} d={d}"
                    );
                }
            }
        }
    }

    #[test]
    fn genesis_mint_is_one_step_exact_and_preserves_contract() {
        // $1 of USDT at $1 → 4 STELL = 4e9 nano.
        assert_eq!(
            GenesisVault::calculate_mint(1_000_000, 6, 1_000_000),
            4_000_000_000
        );
        // 1 TON (9 decimals) at $1 → the same 4 STELL.
        assert_eq!(
            GenesisVault::calculate_mint(1_000_000_000, 9, 1_000_000),
            4_000_000_000
        );
        // 0.333333 USDT at $1 → 1.333332 STELL exactly.
        assert_eq!(
            GenesisVault::calculate_mint(333_333, 6, 1_000_000),
            1_333_332_000
        );
        assert_eq!(GenesisVault::calculate_mint(0, 6, 1_000_000), 0);

        // Absurd decimal count fails closed to 0; absurd price saturates.
        assert_eq!(GenesisVault::calculate_mint(1, 100, 1_000_000), 0);
        assert_eq!(
            GenesisVault::calculate_mint(u64::MAX, 0, u64::MAX),
            u64::MAX
        );

        // Differential check against the old two-branch quotient/remainder
        // decomposition for decimals <= 9 (algebraically the same value).
        for &amount in &[0u64, 1, 7, 333_333, 1_000_000, 12_345_678] {
            for &decimals in &[0u32, 2, 6, 9] {
                for &price in &[1u64, 250_000, 1_000_000, 3_000_000] {
                    let p = (amount as u128) * (price as u128);
                    let den = 10u128.pow(decimals) * (BASE_STELL_PRICE_MICRO_USD as u128);
                    let expected =
                        (p / den) * 1_000_000_000u128 + ((p % den) * 1_000_000_000u128) / den;
                    assert_eq!(
                        GenesisVault::calculate_mint(amount, decimals, price),
                        u128::min(expected, u64::MAX as u128) as u64,
                        "amount={amount} decimals={decimals} price={price}"
                    );
                }
            }
        }
    }

    #[test]
    fn exact_q64_floor_matches_legacy_reward() {
        let r0 = 4_379_227_780u64;
        let h = CAP_EXACT_HALF_LIFE_BLOCKS;
        for &height in &[
            0u64,
            1,
            2,
            h - 1,
            h,
            h + 1,
            2 * h,
            7 * h + 123,
            63 * h,
            64 * h,
            100 * h,
        ] {
            let (floor, _frac) = pow_half_fixed_exact_q64(r0, h, height);
            assert_eq!(
                floor,
                geometric_reward_at_height(r0, h, height),
                "floor must stay byte-identical to the live helper @ {height}"
            );
            assert!(floor <= r0, "reward never exceeds R0 @ {height}");
        }
        // At height 0 the fractional part is exactly zero.
        assert_eq!(pow_half_fixed_exact_q64(r0, h, 0), (r0, 0));
        // One half-life: exact halving (r0 is even → no fraction).
        assert_eq!(pow_half_fixed_exact_q64(r0, h, h), (r0 / 2, 0));
        // Degenerate inputs are deterministic, never panics.
        assert_eq!(pow_half_fixed_exact_q64(5, 0, 10), (0, 0));
        assert_eq!(pow_half_fixed_exact_q64(0, 10, 10), (0, 0));
    }

    #[test]
    fn emit_with_q64_carry_is_capped_and_carry_stays_below_two_pow_64() {
        let pool = StakingEmissionSchedule::default().total_pool as u128;

        // CASE A — the whole geometric tail at H = 1 (r0 = pool/2): the exact
        // infinite sum is exactly `2·r0 = pool`, so the carried emission can
        // never exceed the pool (it lands 1 nano under: the sub-2^-128 tail is
        // discarded as dust).
        let r0_h1 = (pool / 2) as u64;
        let mut carry = 0u64;
        let mut sum: u128 = 0;
        let mut accumulated_q64: u128 = 0;
        let mut height = 0u64;
        loop {
            let (floor, frac) = pow_half_fixed_exact_q64(r0_h1, 1, height);
            let (emit, next_carry) = emit_with_q64_carry(r0_h1, 1, height, carry);
            assert!(
                (next_carry as u128) < (1u128 << 64),
                "carry must be < 2^64 @ {height}"
            );
            accumulated_q64 += ((floor as u128) << 64) + (frac as u128);
            sum += emit as u128;
            assert_eq!(
                sum,
                accumulated_q64 >> 64,
                "emitted nanos are the exact floor of the cumulative reward @ {height}"
            );
            assert_eq!(
                next_carry, accumulated_q64 as u64,
                "carry is the fractional remainder of the cumulative reward @ {height}"
            );
            carry = next_carry;
            height += 1;
            if floor == 0 {
                break;
            }
            assert!(height < 1_000, "H=1 tail must terminate");
        }
        assert!(sum <= pool, "Σemit {sum} must not exceed pool {pool}");
        assert!(sum + 1 >= pool, "H=1 tail emits pool-1 at most: {sum}");
        // Post-horizon carry is irreducible sub-nano dust, still a u64 fraction.
        assert!((carry as u128) < (1u128 << 64));

        // CASE B — a LONG horizon (H = 1024, 48k blocks until the reward
        // floors to 0). `r0 = pool / (2H)` guarantees the mathematical
        // ceiling `Σ exact = r0 / (1 - 2^(-1/H)) <= 2H·r0 <= pool`, so the
        // carried emission must stay under the pool.
        let half_life_blocks = 1_024u64;
        let r0 = (pool / (2 * half_life_blocks as u128)) as u64;
        assert!(r0 > 0);
        let mut carry = 0u64;
        let mut sum: u128 = 0;
        let mut accumulated_q64: u128 = 0;
        let mut height = 0u64;
        loop {
            let (floor, frac) = pow_half_fixed_exact_q64(r0, half_life_blocks, height);
            let (emit, next_carry) = emit_with_q64_carry(r0, half_life_blocks, height, carry);
            assert!(
                (next_carry as u128) < (1u128 << 64),
                "carry must be < 2^64 @ {height}"
            );
            let floor_only = geometric_reward_at_height(r0, half_life_blocks, height) as u128;
            assert_eq!(floor as u128, floor_only, "floor matches the live helper");
            assert!(
                (emit as u128) >= floor_only,
                "carry can only add value, never remove @ {height}"
            );
            accumulated_q64 += ((floor as u128) << 64) + (frac as u128);
            sum += emit as u128;
            assert_eq!(sum, accumulated_q64 >> 64);
            assert_eq!(next_carry, accumulated_q64 as u64);
            carry = next_carry;
            height += 1;
            if floor == 0 {
                break;
            }
            assert!(
                height < 1_000_000,
                "geometric tail must reach zero (H={half_life_blocks})"
            );
        }
        assert!(sum <= pool, "Σemit {sum} must not exceed pool {pool}");
        // Post-horizon carry is irreducible sub-nano dust, still a u64 fraction.
        assert!((carry as u128) < (1u128 << 64));

        // Degenerate inputs preserve the carry deterministically.
        assert_eq!(emit_with_q64_carry(5, 0, 10, 7), (0, 7));
        assert_eq!(emit_with_q64_carry(0, 10, 10, 7), (0, 7));
        // At height 0 the whole reward is emitted and nothing is carried.
        assert_eq!(emit_with_q64_carry(r0, half_life_blocks, 0, 0), (r0, 0));
    }

    #[test]
    fn team_vesting_unlocked_amount_saturates_near_u64_max() {
        let saturating = TeamVestingSchedule {
            total_allocation: 1_000_000,
            start_timestamp: u64::MAX - 10,
            cliff_duration_secs: 100,
            vesting_duration_secs: 200,
            claimed_amount: 0,
        };
        assert_eq!(saturating.unlocked_amount(u64::MAX - 1), 0);
        assert_eq!(saturating.unlocked_amount(u64::MAX), 0);

        let linear = TeamVestingSchedule {
            total_allocation: 1_000_000,
            start_timestamp: u64::MAX - 100,
            cliff_duration_secs: 50,
            vesting_duration_secs: 50,
            claimed_amount: 0,
        };
        assert_eq!(linear.unlocked_amount(u64::MAX - 51), 0);
        assert_eq!(linear.unlocked_amount(u64::MAX - 50), 0);
        assert_eq!(linear.unlocked_amount(u64::MAX - 25), 500_000);
        assert_eq!(linear.unlocked_amount(u64::MAX), 1_000_000);
    }
}
