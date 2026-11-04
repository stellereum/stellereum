//! Genesis Vault and Tokenomics module
//! Base parameters:
//! 1 STELL = $0.25 USD
//! Hard Cap = 1,000,000,000 STELL
//! Public Exchange (Genesis Vault): 25% (250,000,000 STELL)
//! Formula: STELL = (incoming_coins * coin_price_usd) / $0.25

use serde::{Deserialize, Serialize};

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
        // Base reward scaled per block (~200ms blocks = 5 blocks/sec = 157_680_000 blocks/yr)
        // 350M / 7 years ~= 50M STELL/year ~= 0.317 STELL per block
        BLOCK_REWARD_NANO / (active_validators as u64)
    }
}
