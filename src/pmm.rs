//! Primary Market Maker (PMM) — the native Mint & Redeem exchange.
//!
//! Implements the bonding-curve model from the launch strategy (section 6):
//! fixed prices on an open market are mathematically fatal (arbitrage drains
//! the reserve), so the PMM prices along a curve:
//!
//! ```text
//!     P(S) = P0 * (1 + S / S_cap)
//! ```
//!
//! where `S` is the STELL the exchange has minted, `P0` the base price ($0.25)
//! and `S_cap` the depth parameter. Buying mints STELL into a USDT reserve;
//! selling burns STELL out of the reserve. Because each successive STELL is
//! more expensive, there is no arbitrage that drains the reserve at a fixed
//! price, and selling is strictly bounded by the available USDT.
//!
//! All amounts are in nano-STELL (9 decimals) and micro-USD (6 decimals).
//! Arithmetic is integer-only (u128 internally) with floor semantics so every
//! node computes exactly the same result — consensus determinism.
//!
//! Safety:
//!  - Buy: exact integral of the curve (closed form with an integer sqrt).
//!  - Sell: exact integral; rejected if it would exceed the usable reserve.
//!  - A `redemption_buffer` (a fraction of buy proceeds) is ring-fenced for
//!    redemptions, so sell pressure is always partially funded (hybrid model).

use serde::{Deserialize, Serialize};

/// Base price P0 = $0.25 (micro-USD).
pub const PMM_BASE_PRICE_MICRO_USD: u64 = 250_000;
/// Curve depth S_cap: the minted amount at which the price doubles (~$0.50).
/// 125,000,000 STELL in nano.
pub const PMM_DEPTH_CAP_NANO: u128 = 125_000_000 * 1_000_000_000;
/// Fraction of buy proceeds ring-fenced for redemptions (20%), in bps.
pub const PMM_REDEMPTION_BUFFER_BPS: u64 = 2_000;
const BPS: u128 = 10_000;
const NANO_PER_STELL: u128 = 1_000_000_000;
const MICRO_PER_USD: u128 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PmmError {
    ZeroAmount,
    /// Selling more than the usable USDT reserve would allow.
    InsufficientReserve,
    /// A buy or sell would move zero value due to rounding.
    Dust,
    /// Arithmetic overflow guard.
    Overflow,
}

impl std::fmt::Display for PmmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PmmError::ZeroAmount => "amount must be greater than zero",
            PmmError::InsufficientReserve => "USDT reserve insufficient for this redemption",
            PmmError::Dust => "amount too small (rounds to zero)",
            PmmError::Overflow => "arithmetic overflow",
        };
        write!(f, "{s}")
    }
}

/// What a PMM syscall did to the curve and to wUSDT, handed to the engine for
/// settlement of the NATIVE leg.
///
/// The VM can move tokens (clone-committed like every other domain) and can
/// advance the curve, but it cannot mint or burn native STELL: that has to go
/// through the engine's `credit_native`/`debit_native`, which also write the
/// account trie. `execute_payload` therefore settles these events once, on
/// overall success, after the VM has finished.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PmmEvent {
    /// The buyer's `usdt_micro` wUSDT was burned and the curve advanced;
    /// `stell_minted` native STELL must now be credited to `buyer`.
    Buy {
        buyer: [u8; 32],
        usdt_micro: u64,
        stell_minted: u64,
    },
    /// `stell_nano` native STELL must be debited from `seller`; their
    /// `usdt_paid` wUSDT was already minted to them from the PMM treasury.
    Sell {
        seller: [u8; 32],
        stell_nano: u64,
        usdt_paid: u64,
    },
}

/// The PMM wiring carried inside `VmContext` for `SysCallPmmBuy`/`SysCallPmmSell`.
///
/// `state` is clone-committed by the VM exactly like the staking ledger: a
/// later revert in the same payload discards the curve advance along with the
/// token mutations, so a partially applied swap can never reach the engine.
pub struct PmmVmContext<'a> {
    /// Committed bonding curve the syscalls mutate (through the VM's working
    /// clone).
    pub state: &'a mut PrimaryMarketMaker,
    /// Bridged-USDT token id. `None` = `pmm_init_usdt` never ran, so the
    /// syscalls revert instead of inventing a quote asset.
    pub usdt_token: Option<[u8; 32]>,
    /// wUSDT minter: the only address allowed to mint the redemption payout.
    pub treasury: [u8; 32],
    /// Governed buffer (bps), resolved from `governance.applied` once per
    /// transaction so a passed `SetPmmRedemptionBufferBps` actually prices the
    /// next buy. Same read-once-per-tx rule as the staking parameters.
    pub redemption_buffer_bps: u64,
    /// Native value the engine still has to move for this payload.
    pub events: Vec<PmmEvent>,
}

/// Result of a buy (USDT -> STELL).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuyReceipt {
    pub stell_minted: u64,
    pub usdt_paid: u64,
    pub new_price_micro_usd: u64,
    pub supply_after: u64,
}

/// Result of a sell (STELL -> USDT).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SellReceipt {
    pub stell_burned: u64,
    pub usdt_paid: u64,
    pub new_price_micro_usd: u64,
    pub supply_after: u64,
}

/// State of the primary market maker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimaryMarketMaker {
    /// STELL minted by the PMM (S).
    pub minted_nano: u128,
    /// Total USDT reserve held (micro-USD).
    pub reserve_micro: u128,
    /// Portion of the reserve ring-fenced for redemptions (micro-USD).
    pub redemption_buffer_micro: u128,
    /// Curve depth S_cap used by this instance.
    pub depth_cap_nano: u128,
    /// Base price P0 (micro-USD).
    pub base_price_micro: u64,
}

impl Default for PrimaryMarketMaker {
    fn default() -> Self {
        Self::new()
    }
}

impl PrimaryMarketMaker {
    pub fn new() -> Self {
        Self {
            minted_nano: 0,
            reserve_micro: 0,
            redemption_buffer_micro: 0,
            depth_cap_nano: PMM_DEPTH_CAP_NANO,
            base_price_micro: PMM_BASE_PRICE_MICRO_USD,
        }
    }

    /// Construct with a fixed initial USDT reserve (bootstrap liquidity).
    pub fn with_reserve(reserve_micro: u64) -> Self {
        let mut pmm = Self::new();
        pmm.reserve_micro = reserve_micro as u128;
        pmm
    }

    /// Current spot price P(S) = P0 * (1 + S / S_cap), in micro-USD.
    pub fn price_micro_usd(&self) -> u64 {
        self.price_at(self.minted_nano)
    }

    fn price_at(&self, supply_nano: u128) -> u64 {
        // P = P0 * (1 + S/S_cap) = P0 * (S_cap + S) / S_cap
        let num = (self.base_price_micro as u128) * (self.depth_cap_nano + supply_nano);
        (num / self.depth_cap_nano) as u64
    }

    /// USDT that can actually be paid for redemptions: the buffer is ring-fenced,
    /// the rest of the reserve is usable once it exceeds the buffer.
    pub fn usable_reserve_micro(&self) -> u128 {
        self.reserve_micro
            .saturating_sub(self.redemption_buffer_micro)
    }

    /// Integer square root (Newton). Deterministic, panic-free.
    fn isqrt(n: u128) -> u128 {
        if n == 0 {
            return 0;
        }
        let mut x = n;
        let mut y = x.div_ceil(2);
        while y < x {
            x = y;
            y = (x + n / x) / 2;
        }
        x
    }

    /// Cost in micro-USD to mint exactly `d_nano` STELL starting from supply `s`.
    ///
    /// Integral of P(S) from s to s+d:
    ///   cost = P0 * ( d + ( (s+d)^2 - s^2 ) / (2 * S_cap) )
    fn buy_cost_micro(&self, s: u128, d: u128) -> u128 {
        let p0 = self.base_price_micro as u128;
        let sc = self.depth_cap_nano;
        let s2 = (s + d) * (s + d);
        let s1 = s * s;
        // (s+d)^2 - s^2 = 2*s*d + d^2
        let quad = (s2 - s1) / (2 * sc);
        p0 * (d + quad) / NANO_PER_STELL
    }

    /// STELL minted for a given USDT amount `u` (micro), starting from supply `s`.
    ///
    /// Closed form (inverting the cost integral):
    ///   Let k = u * S_cap / P0, then
    ///   d = sqrt( (s + S_cap)^2 + 2*S_cap*k ) - (s + S_cap)   [in nano]
    ///
    /// We solve in "nano" units: define A = s + S_cap, B = 2*S_cap*k where
    /// k (in nano) = u_micro * NANO_PER_STELL / P0.
    fn mint_for_usdt(&self, s: u128, u_micro: u128) -> u128 {
        let p0 = self.base_price_micro as u128;
        let sc = self.depth_cap_nano;
        // k = value of u in STELL at base price, in nano.
        let k = u_micro.saturating_mul(NANO_PER_STELL) / p0;
        let a = s + sc;
        let disc = a.saturating_mul(a).saturating_add(2 * sc * k);
        Self::isqrt(disc).saturating_sub(a)
    }

    /// USDT paid (micro) for selling exactly `d_nano` STELL from supply `s`.
    ///
    /// Integral: payout = P0 * ( d - ( s^2 - (s-d)^2 ) / (2*S_cap) )
    ///                    = P0 * ( d - (2*s*d - d^2)/(2*S_cap) )
    fn sell_payout_micro(&self, s: u128, d: u128) -> u128 {
        let p0 = self.base_price_micro as u128;
        let sc = self.depth_cap_nano;
        // s^2 - (s-d)^2 = 2*s*d - d^2
        let s2 = s * s;
        let low = (s - d) * (s - d);
        let quad = (s2 - low) / (2 * sc);
        // payout = P0 * (d - quad) / 1e9
        p0.saturating_mul(d.saturating_sub(quad)) / NANO_PER_STELL
    }

    /// Buy with exactly `usdt_micro` USDT; mints STELL along the curve.
    ///
    /// Uses the protocol default buffer. Callers that must honour a passed
    /// `SetPmmRedemptionBufferBps` use [`PrimaryMarketMaker::buy_with_buffer`].
    pub fn buy_with_usdt(&mut self, usdt_micro: u64) -> Result<BuyReceipt, PmmError> {
        self.buy_with_buffer(usdt_micro, PMM_REDEMPTION_BUFFER_BPS)
    }

    /// [`buy_with_usdt`] with an explicit redemption-buffer share (bps).
    ///
    /// The governed value comes from `governance.applied.pmm_redemption_buffer_bps`
    /// (clamped to 100% here as defence in depth - governance already rejects
    /// values above 10_000). Ring-fencing the wrong fraction is a value bug, not
    /// a cosmetic one: the buffer is what keeps sell pressure partially funded.
    pub fn buy_with_buffer(
        &mut self,
        usdt_micro: u64,
        buffer_bps: u64,
    ) -> Result<BuyReceipt, PmmError> {
        if usdt_micro == 0 {
            return Err(PmmError::ZeroAmount);
        }
        let u = usdt_micro as u128;
        let s = self.minted_nano;
        let d = self.mint_for_usdt(s, u);
        if d == 0 {
            return Err(PmmError::Dust);
        }
        // The exact curve cost may be <= u due to floor rounding. The buyer pays
        // the full `u` and any rounding remainder stays in the reserve (no value
        // is lost and the reserve is never under-funded).
        self.minted_nano = s.checked_add(d).ok_or(PmmError::Overflow)?;
        // Add the full USDT in (buyer pays `u`).
        self.reserve_micro = self.reserve_micro.saturating_add(u);
        // Ring-fence a fraction for redemptions.
        let bps = (buffer_bps as u128).min(BPS);
        let buf = u * bps / BPS;
        self.redemption_buffer_micro = self.redemption_buffer_micro.saturating_add(buf);
        Ok(BuyReceipt {
            stell_minted: d as u64,
            usdt_paid: u as u64,
            new_price_micro_usd: self.price_micro_usd(),
            supply_after: self.minted_nano as u64,
        })
    }

    /// Buy an exact amount of STELL; charges the curve cost.
    pub fn buy_exact_stell(&mut self, stell_nano: u64) -> Result<BuyReceipt, PmmError> {
        if stell_nano == 0 {
            return Err(PmmError::ZeroAmount);
        }
        let d = stell_nano as u128;
        let s = self.minted_nano;
        let cost = self.buy_cost_micro(s, d);
        if cost == 0 {
            return Err(PmmError::Dust);
        }
        self.minted_nano = s.checked_add(d).ok_or(PmmError::Overflow)?;
        self.reserve_micro = self.reserve_micro.saturating_add(cost);
        let buf = cost * PMM_REDEMPTION_BUFFER_BPS as u128 / BPS;
        self.redemption_buffer_micro = self.redemption_buffer_micro.saturating_add(buf);
        Ok(BuyReceipt {
            stell_minted: stell_nano,
            usdt_paid: cost as u64,
            new_price_micro_usd: self.price_micro_usd(),
            supply_after: self.minted_nano as u64,
        })
    }

    /// Sell (redeem) exactly `stell_nano`; pays the curve value in USDT, bounded
    /// by the usable reserve.
    pub fn sell_stell(&mut self, stell_nano: u64) -> Result<SellReceipt, PmmError> {
        if stell_nano == 0 {
            return Err(PmmError::ZeroAmount);
        }
        let d = stell_nano as u128;
        let s = self.minted_nano;
        if d > s {
            // Cannot redeem more than the PMM ever minted.
            return Err(PmmError::InsufficientReserve);
        }
        let payout = self.sell_payout_micro(s, d);
        if payout == 0 {
            return Err(PmmError::Dust);
        }
        if payout > self.usable_reserve_micro() {
            return Err(PmmError::InsufficientReserve);
        }
        self.minted_nano = s - d;
        self.reserve_micro = self.reserve_micro.saturating_sub(payout);
        // Buffer shrinks proportionally but never below zero.
        self.redemption_buffer_micro = self.redemption_buffer_micro.min(self.reserve_micro);
        Ok(SellReceipt {
            stell_burned: stell_nano,
            usdt_paid: payout as u64,
            new_price_micro_usd: self.price_micro_usd(),
            supply_after: self.minted_nano as u64,
        })
    }

    /// Maximum STELL redeemable right now at the current curve (bounded by the
    /// usable reserve and the minted supply).
    pub fn max_redeemable_stell(&self) -> u64 {
        // Binary search the largest d whose payout fits the usable reserve.
        let mut lo = 0u128;
        let mut hi = self.minted_nano;
        let usable = self.usable_reserve_micro();
        while lo < hi {
            let mid = (lo + hi).div_ceil(2);
            let payout = self.sell_payout_micro(self.minted_nano, mid);
            if payout <= usable {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        lo as u64
    }

    /// Total value locked in the reserve, in USD (for dashboards).
    pub fn reserve_usd(&self) -> f64 {
        self.reserve_micro as f64 / MICRO_PER_USD as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usdt(n: u64) -> u64 {
        n * 1_000_000 // n USD in micro
    }
    fn stell(n: u64) -> u64 {
        n * 1_000_000_000 // n STELL in nano
    }

    #[test]
    fn base_price_starts_at_025() {
        let pmm = PrimaryMarketMaker::new();
        assert_eq!(pmm.price_micro_usd(), 250_000, "$0.25 at zero supply");
    }

    #[test]
    fn price_rises_as_buyers_mint() {
        let mut pmm = PrimaryMarketMaker::new();
        let before = pmm.price_micro_usd();
        // buy $1M -> supply grows, price rises above base
        pmm.buy_with_usdt(usdt(1_000_000)).unwrap();
        assert!(
            pmm.price_micro_usd() > before,
            "price must rise after buying"
        );
        assert!(pmm.reserve_micro == usdt(1_000_000) as u128);
    }

    #[test]
    fn buy_then_sell_roundtrip_loses_only_spread() {
        let mut pmm = PrimaryMarketMaker::new();
        let r = pmm.buy_with_usdt(usdt(10_000)).unwrap();
        assert!(r.stell_minted > 0);
        // The redemption buffer (20%) is ring-fenced, so a full instant drain is
        // impossible; redeem the maximum allowed and check it never profits.
        let max = pmm.max_redeemable_stell();
        assert!(max > 0, "some redemption must be possible");
        assert!(
            max < r.stell_minted,
            "a full instant drain is blocked by the buffer"
        );
        let sell = pmm.sell_stell(max).unwrap();
        assert!(sell.usdt_paid <= usdt(10_000), "redemption cannot profit");
        assert!(sell.usdt_paid > 0);
    }

    #[test]
    fn sell_requires_reserve() {
        let mut pmm = PrimaryMarketMaker::new();
        // Buy to mint supply but a tiny reserve relative to a big sell.
        pmm.buy_with_usdt(usdt(100)).unwrap();
        // Try to sell far more than the PMM minted -> rejected.
        assert_eq!(
            pmm.sell_stell(stell(1_000_000)),
            Err(PmmError::InsufficientReserve)
        );
    }

    #[test]
    fn redemption_buffer_is_ring_fenced() {
        let mut pmm = PrimaryMarketMaker::new();
        pmm.buy_with_usdt(usdt(10_000)).unwrap();
        // 20% of 10,000 = 2,000 is ring-fenced
        assert_eq!(pmm.redemption_buffer_micro, 2_000 * 1_000_000);
        assert_eq!(pmm.usable_reserve_micro(), 8_000 * 1_000_000);
    }

    #[test]
    fn no_exploit_with_partial_redemption_exceeding_buffer() {
        let mut pmm = PrimaryMarketMaker::new();
        // mint some supply
        pmm.buy_with_usdt(usdt(100_000)).unwrap();
        // max redeemable must not exceed usable reserve
        let max = pmm.max_redeemable_stell();
        let payout = pmm.sell_payout_micro(pmm.minted_nano, max as u128);
        assert!(payout <= pmm.usable_reserve_micro());
        // one unit more exceeds
        if max < pmm.minted_nano as u64 {
            let over = pmm.sell_payout_micro(pmm.minted_nano, (max as u128) + 1);
            assert!(over > pmm.usable_reserve_micro() || over == payout);
        }
    }

    #[test]
    fn deterministic_pricing() {
        let mut a = PrimaryMarketMaker::new();
        let mut b = PrimaryMarketMaker::new();
        let r1 = a.buy_with_usdt(usdt(12_345)).unwrap();
        let r2 = b.buy_with_usdt(usdt(12_345)).unwrap();
        assert_eq!(
            r1, r2,
            "same input must yield identical output (consensus determinism)"
        );
    }

    #[test]
    fn value_conservation_reserve_equals_net_deposits() {
        let mut pmm = PrimaryMarketMaker::new();
        let mut net = 0i128;
        net += usdt(5_000) as i128;
        pmm.buy_with_usdt(usdt(5_000)).unwrap();
        let s = pmm.sell_stell(stell(100)).unwrap();
        net -= s.usdt_paid as i128;
        assert_eq!(pmm.reserve_micro as i128, net, "reserve = in - out");
    }

    #[test]
    fn zero_amounts_rejected() {
        let mut pmm = PrimaryMarketMaker::new();
        assert_eq!(pmm.buy_with_usdt(0), Err(PmmError::ZeroAmount));
        assert_eq!(pmm.sell_stell(0), Err(PmmError::ZeroAmount));
    }

    /// A passed `SetPmmRedemptionBufferBps` must actually price the buy: the
    /// governed share replaces the 20% default, and the default path is
    /// byte-identical to calling the buffered one with the default.
    #[test]
    fn governed_redemption_buffer_is_applied_by_buy_with_buffer() {
        let mut governed = PrimaryMarketMaker::new();
        let mut default = PrimaryMarketMaker::new();

        // 50% governed ring-fence vs the 20% protocol default.
        let r1 = governed.buy_with_buffer(usdt(10_000), 5_000).unwrap();
        let r2 = default.buy_with_usdt(usdt(10_000)).unwrap();
        assert_eq!(r1, r2, "the buffer must not change what is minted");

        assert_eq!(governed.redemption_buffer_micro, 5_000 * 1_000_000);
        assert_eq!(governed.usable_reserve_micro(), 5_000 * 1_000_000);
        assert_eq!(default.redemption_buffer_micro, 2_000 * 1_000_000);
        assert_eq!(default.usable_reserve_micro(), 8_000 * 1_000_000);

        // The governed buffer is the binding constraint on redemptions: a
        // larger ring-fence leaves less immediately redeemable.
        assert!(governed.max_redeemable_stell() < default.max_redeemable_stell());
    }

    /// Governance already rejects > 10_000 bps, but the engine must clamp even
    /// if a caller hands over a wild value: 100%+ must never make the buffer
    /// exceed the reserve (which would freeze every redemption).
    #[test]
    fn buffered_buy_clamps_the_share_to_one_hundred_percent() {
        let mut pmm = PrimaryMarketMaker::new();
        pmm.buy_with_buffer(usdt(1_000), u64::MAX).unwrap();
        assert!(pmm.redemption_buffer_micro <= pmm.reserve_micro);
        assert_eq!(
            pmm.redemption_buffer_micro, pmm.reserve_micro,
            "clamped at 100%"
        );
    }
}
