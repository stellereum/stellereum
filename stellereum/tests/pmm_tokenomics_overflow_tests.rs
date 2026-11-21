use stellereum::pmm::{PmmError, PrimaryMarketMaker, PMM_BASE_PRICE_MICRO_USD, PMM_DEPTH_CAP_NANO};
use stellereum::tokenomics::{GenesisVault, GENESIS_VAULT_CAP, TOTAL_SUPPLY_CAP};

#[test]
fn pmm_buy_with_usdt_u64_max_returns_overflow_without_panic_or_mutation() {
    let mut pmm = PrimaryMarketMaker::new();
    let res = pmm.buy_with_usdt(u64::MAX);
    assert_eq!(res, Err(PmmError::Overflow));
    assert_eq!(pmm, PrimaryMarketMaker::new());
}

#[test]
fn pmm_buy_exact_stell_u64_max_after_prior_buy_returns_overflow_without_panic() {
    let mut pmm = PrimaryMarketMaker::new();
    pmm.buy_with_usdt(1_000_000).unwrap();
    let before = pmm.clone();

    let res = pmm.buy_exact_stell(u64::MAX);
    assert_eq!(res, Err(PmmError::Overflow));
    assert_eq!(pmm, before, "failed buy must not mutate PMM state");
}

#[test]
fn pmm_buy_exact_stell_u64_max_from_empty_returns_bounded_receipt_without_wrap() {
    let mut pmm = PrimaryMarketMaker::new();
    let receipt = pmm.buy_exact_stell(u64::MAX).unwrap();
    assert_eq!(receipt.stell_minted, u64::MAX);
    assert_eq!(receipt.supply_after, u64::MAX);
    assert_eq!(pmm.minted_nano, u64::MAX as u128);
    assert!(receipt.usdt_paid > 0);
    assert!(receipt.new_price_micro_usd > PMM_BASE_PRICE_MICRO_USD);

    // A follow-up buy of even 1 nano-STELL must fail with Overflow, never wrap u64.
    let before = pmm.clone();
    assert_eq!(pmm.buy_exact_stell(1), Err(PmmError::Overflow));
    assert_eq!(pmm, before);
}

#[test]
fn pmm_buy_with_usdt_near_total_supply_cap_matches_curve_and_rejects_u64_max() {
    let mut pmm = PrimaryMarketMaker::new();
    pmm.buy_exact_stell(TOTAL_SUPPLY_CAP).unwrap();
    let before = pmm.clone();

    assert_eq!(pmm.buy_with_usdt(u64::MAX), Err(PmmError::Overflow));
    assert_eq!(pmm, before);
}

#[test]
fn pmm_curve_accuracy_and_equivalence_at_total_supply_cap() {
    // TOTAL_SUPPLY_CAP = 1_000_000_000 STELL = 8 * PMM_DEPTH_CAP_NANO (125M STELL).
    assert_eq!(TOTAL_SUPPLY_CAP as u128, 8 * PMM_DEPTH_CAP_NANO);

    // Single exact buy of TOTAL_SUPPLY_CAP:
    // Integral of P0*(1 + S/S_cap) from 0 to 8*S_cap = 0.25 * (8 + 32) * 125M = $1.25B.
    let expected_cost_micro: u64 = 1_250_000_000_000_000;
    let expected_price_at_cap: u64 = 2_250_000; // $0.25 * (1 + 8) = $2.25

    let mut exact_single = PrimaryMarketMaker::new();
    let r_single = exact_single.buy_exact_stell(TOTAL_SUPPLY_CAP).unwrap();
    assert_eq!(r_single.stell_minted, TOTAL_SUPPLY_CAP);
    assert_eq!(r_single.usdt_paid, expected_cost_micro);
    assert_eq!(r_single.supply_after, TOTAL_SUPPLY_CAP);
    assert_eq!(r_single.new_price_micro_usd, expected_price_at_cap);

    // Split exact buy in two halves must be bit-for-bit identical at TOTAL_SUPPLY_CAP.
    let half = TOTAL_SUPPLY_CAP / 2;
    let mut exact_split = PrimaryMarketMaker::new();
    let r_half1 = exact_split.buy_exact_stell(half).unwrap();
    let r_half2 = exact_split
        .buy_exact_stell(TOTAL_SUPPLY_CAP - half)
        .unwrap();
    assert_eq!(r_half1.usdt_paid + r_half2.usdt_paid, expected_cost_micro);
    assert_eq!(r_half2.supply_after, TOTAL_SUPPLY_CAP);
    assert_eq!(r_half2.new_price_micro_usd, expected_price_at_cap);
    assert_eq!(exact_split, exact_single);

    // Inverse buy_with_buffer(expected_cost_micro, 0) must mint exact TOTAL_SUPPLY_CAP
    // and round-trip cleanly back to zero supply/reserve.
    let mut by_usdt = PrimaryMarketMaker::new();
    let r_usdt = by_usdt.buy_with_buffer(expected_cost_micro, 0).unwrap();
    assert_eq!(r_usdt.stell_minted, TOTAL_SUPPLY_CAP);
    assert_eq!(r_usdt.usdt_paid, expected_cost_micro);
    assert_eq!(r_usdt.supply_after, TOTAL_SUPPLY_CAP);
    assert_eq!(r_usdt.new_price_micro_usd, expected_price_at_cap);

    let sell_back = by_usdt.sell_stell(TOTAL_SUPPLY_CAP).unwrap();
    assert_eq!(sell_back.stell_burned, TOTAL_SUPPLY_CAP);
    assert_eq!(sell_back.usdt_paid, expected_cost_micro);
    assert_eq!(sell_back.supply_after, 0);
    assert_eq!(sell_back.new_price_micro_usd, PMM_BASE_PRICE_MICRO_USD);
    assert_eq!(by_usdt.minted_nano, 0);
    assert_eq!(by_usdt.reserve_micro, 0);
}

#[test]
fn pmm_zero_mint_and_zero_payout_checked_errors() {
    let mut high_price_pmm = PrimaryMarketMaker {
        base_price_micro: 2_000_000_000, // $2,000/STELL -> 1 micro-USD < 1 nano-STELL
        ..PrimaryMarketMaker::new()
    };
    assert_eq!(
        high_price_pmm.buy_with_buffer_checked(1, 2_000),
        Err(PmmError::ZeroMint)
    );
    assert_eq!(high_price_pmm.minted_nano, 0);
    assert_eq!(high_price_pmm.reserve_micro, 0);

    let mut sell_pmm = PrimaryMarketMaker::new();
    sell_pmm.buy_with_buffer(1_000_000, 0).unwrap();
    let before = sell_pmm.clone();
    assert_eq!(sell_pmm.sell_stell_checked(1), Err(PmmError::ZeroPayout));
    assert_eq!(sell_pmm, before);
}

#[test]
fn genesis_vault_deposit_refuses_zero_mint_without_mutating_state() {
    let mut vault = GenesisVault::new();

    // Micro-USDT deposit that rounds to 0 nano-STELL (1 micro-USDT at $0.0001).
    let err_usdt = vault.deposit_and_mint("USDT", 1, 100).unwrap_err();
    assert!(err_usdt.contains("ZeroMint"), "got: {err_usdt}");
    assert_eq!(vault.total_minted_nano, 0);
    assert_eq!(vault.usdt_deposited_micro, 0);
    assert_eq!(vault.ton_deposited_nano, 0);
    assert_eq!(vault.gram_deposited_nano, 0);

    // Micro-TON deposit that rounds to 0 nano-STELL (1 nano-TON at $0.000001).
    let err_ton = vault.deposit_and_mint("TON", 1, 1).unwrap_err();
    assert!(err_ton.contains("ZeroMint"), "got: {err_ton}");
    assert_eq!(vault.total_minted_nano, 0);
    assert_eq!(vault.ton_deposited_nano, 0);

    // Zero-price non-zero deposit must also refuse without taking assets.
    let err_zero_price = vault.deposit_and_mint("GRAM", 1_000_000, 0).unwrap_err();
    assert!(err_zero_price.contains("ZeroMint"), "got: {err_zero_price}");
    assert_eq!(vault.total_minted_nano, 0);
    assert_eq!(vault.gram_deposited_nano, 0);

    // Strict checked variant also rejects 0 asset_amount as ZeroMint.
    let err_zero_amt = vault
        .deposit_and_mint_checked("USDT", 0, 1_000_000)
        .unwrap_err();
    assert!(err_zero_amt.contains("ZeroMint"), "got: {err_zero_amt}");
    assert_eq!(vault.total_minted_nano, 0);
    assert_eq!(vault.usdt_deposited_micro, 0);
}

#[test]
fn genesis_vault_precision_without_intermediate_truncation_and_cap_bounds() {
    // 1 nano-TON at $1.00 = $1e-9 / $0.25 = 4 nano-STELL (previously truncated to 0).
    let mut vault = GenesisVault::new();
    let minted_ton = vault.deposit_and_mint("TON", 1, 1_000_000).unwrap();
    assert_eq!(minted_ton, 4);
    assert_eq!(vault.ton_deposited_nano, 1);
    assert_eq!(vault.total_minted_nano, 4);

    // 1 micro-USDT at $0.25 = $1e-6 * 0.25 / $0.25 = 1_000 nano-STELL.
    let minted_usdt = vault.deposit_and_mint("USDT", 1, 250_000).unwrap();
    assert_eq!(minted_usdt, 1_000);
    assert_eq!(vault.usdt_deposited_micro, 1);
    assert_eq!(vault.total_minted_nano, 1_004);

    // Normal amounts stay exact.
    assert_eq!(
        GenesisVault::calculate_mint(1_000_000, 6, 1_000_000),
        4_000_000_000
    );
    assert_eq!(
        GenesisVault::calculate_mint(1_000_000_000, 9, 2_500_000),
        10_000_000_000
    );

    // Cap boundary check: filling up to GENESIS_VAULT_CAP works, +1 nano fails cleanly.
    let mut cap_vault = GenesisVault::new();
    cap_vault.total_minted_nano = GENESIS_VAULT_CAP - 4;
    assert_eq!(cap_vault.deposit_and_mint("TON", 1, 1_000_000).unwrap(), 4);
    assert_eq!(cap_vault.total_minted_nano, GENESIS_VAULT_CAP);
    assert!(cap_vault.deposit_and_mint("TON", 1, 1_000_000).is_err());
    assert_eq!(cap_vault.ton_deposited_nano, 1);
}
