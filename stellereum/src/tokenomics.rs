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
pub const TOTAL_SUPPLY_CAP: u64 = 1_000_000_000 * 1_000_000_000; // in nano-STELL (9 decimals)
pub const GENESIS_VAULT_CAP: u64 = 250_000_000 * 1_000_000_000;
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

impl GenesisVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate STELL amount minted: (in_coins * price_usd) / $0.25
    /// asset_amount is in native decimals (micro for USDT, nano for TON/GRAM)
    /// price_micro_usd is in micro USD ($1 = 1_000_000)
    pub fn calculate_mint(asset_amount: u64, asset_decimals: u32, price_micro_usd: u64) -> u64 {
        // Value in micro USD = (asset_amount * price_micro_usd) / 10^asset_decimals
        let divisor = 10u128.pow(asset_decimals);
        // Saturating (econ audit 2026-11-01): the naive `*` panicked on
        // overflow for absurd inputs (u64::MAX-scale amount AND price: the
        // SECOND multiply overflowed u128 even though each u64×u64 product
        // fits). Saturation fails closed — the resulting over-cap mint is
        // refused by `deposit_and_mint` instead of panicking or wrapping.
        let value_micro_usd = (asset_amount as u128)
            .saturating_mul(price_micro_usd as u128)
            .saturating_div(divisor);

        // STELL tokens = value_micro_usd / 0.25 USD = value_micro_usd / 250_000
        // in nano-STELL (9 decimals):
        let stell_nano = value_micro_usd
            .saturating_mul(1_000_000_000u128)
            .saturating_div(BASE_STELL_PRICE_MICRO_USD as u128);
        // Saturating (econ audit 2026-11-01): a bare `as u64` silently wrapped
        // absurd inputs to dust, which then sailed UNDER the vault cap below.
        // Saturation fails closed — the resulting over-cap mint is refused by
        // `deposit_and_mint` instead of minting a wrapped pittance.
        u128::min(stell_nano, u64::MAX as u128) as u64
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

        self.total_minted_nano = new_total;
        *target_deposit = target_deposit.checked_add(asset_amount).ok_or_else(|| {
            "Genesis Vault deposit overflows u64: refusing instead of wrapping".to_string()
        })?;

        Ok(mint_nano)
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
        if current_timestamp < self.start_timestamp + self.cliff_duration_secs {
            return 0;
        }

        let elapsed = current_timestamp - (self.start_timestamp + self.cliff_duration_secs);
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
    if r0_nano == 0 || half_life_blocks == 0 {
        return 0;
    }
    let whole = height / half_life_blocks;
    if whole >= 64 {
        return 0;
    }
    let rem_h = height % half_life_blocks;
    if rem_h == 0 {
        return r0_nano >> whole;
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
    let scaled = ((r0_nano as u128) * acc) >> 64;
    (scaled >> whole) as u64
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
