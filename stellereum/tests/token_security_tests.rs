//! Adversarial Security & Penetration Testing Suite for the Stellereum Token Standard (STS-20)
//! Simulates real attacker behavior against the fungible token contract:
//!  1. Unauthorized minting (attacker forges minter authority)
//!  2. Token inflation via supply-cap bypass
//!  3. Balance underflow / double-spend of the same balance
//!  4. Allowance over-spend and allowance griefing (failed transfer_from must not consume allowance)
//!  5. Atomicity: failed operations must not mutate state
//!  6. Pause bypass attempts
//!  7. Minter takeover / renouncement abuse
//!  8. Zero-amount and self-transfer griefing
//!  9. Cross-token confusion (operations on one token must not touch another)
//! 10. Overflow attacks on total supply and balances

use stellereum::token::{
    compute_token_id, TokenError, TokenMetadata, TokenOp, TokenRegistry, ZERO_ADDRESS,
};

fn addr(n: u8) -> [u8; 32] {
    [n; 32]
}

fn meta(name: &str, symbol: &str) -> TokenMetadata {
    TokenMetadata {
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: ZERO_ADDRESS,
        paused: false,
        description: String::new(),
    }
}

/// ATTACK 1: Attacker tries to mint tokens without being the minter.
#[test]
fn attack_unauthorized_minting_rejected() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let attacker = addr(0xBA);
    let id = reg
        .create_token(minter, meta("Wrapped USDT", "wUSDT"), 0)
        .unwrap();

    let res = reg.execute(
        &id,
        attacker,
        TokenOp::Mint {
            to: attacker,
            amount: 1_000_000_000,
        },
    );
    assert_eq!(
        res,
        Err(TokenError::NotMinter),
        "Attacker MUST NOT mint tokens!"
    );
    assert_eq!(reg.balance_of(&id, &attacker), 0);
    assert_eq!(
        reg.get(&id).unwrap().metadata.total_supply,
        0,
        "Total supply must be untouched"
    );
}

/// ATTACK 2: Attacker attempts to inflate supply beyond the hard cap.
#[test]
fn attack_supply_cap_inflation_rejected() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let mut m = meta("Capped", "CAP");
    m.max_supply = Some(1_000_000);
    let id = reg.create_token(minter, m, 999_999).unwrap();

    // Legit mint of 1 passes
    reg.execute(
        &id,
        minter,
        TokenOp::Mint {
            to: minter,
            amount: 1,
        },
    )
    .unwrap();
    assert_eq!(reg.get(&id).unwrap().metadata.total_supply, 1_000_000);

    // Any further mint must fail
    assert_eq!(
        reg.execute(
            &id,
            minter,
            TokenOp::Mint {
                to: minter,
                amount: 1
            }
        ),
        Err(TokenError::SupplyCapExceeded)
    );
    assert_eq!(reg.get(&id).unwrap().metadata.total_supply, 1_000_000);
}

/// ATTACK 3: Attacker tries to spend the same balance twice (double-spend).
#[test]
fn attack_double_spend_rejected() {
    let mut reg = TokenRegistry::new();
    let alice = addr(1);
    let bob = addr(2);
    let charlie = addr(3);
    let id = reg.create_token(alice, meta("T", "T"), 100).unwrap();

    // First spend of 100 succeeds
    reg.execute(
        &id,
        alice,
        TokenOp::Transfer {
            to: bob,
            amount: 100,
        },
    )
    .unwrap();
    assert_eq!(reg.balance_of(&id, &alice), 0);

    // Second spend of the same 100 must fail
    assert_eq!(
        reg.execute(
            &id,
            alice,
            TokenOp::Transfer {
                to: charlie,
                amount: 100
            }
        ),
        Err(TokenError::InsufficientBalance)
    );
    assert_eq!(reg.balance_of(&id, &charlie), 0);
}

/// ATTACK 4: Spender tries to move more than the approved allowance.
#[test]
fn attack_allowance_overspend_rejected() {
    let mut reg = TokenRegistry::new();
    let owner = addr(1);
    let spender = addr(2);
    let dest = addr(3);
    let id = reg.create_token(owner, meta("T", "T"), 1_000).unwrap();

    reg.execute(
        &id,
        owner,
        TokenOp::Approve {
            spender,
            amount: 100,
        },
    )
    .unwrap();

    assert_eq!(
        reg.execute(
            &id,
            spender,
            TokenOp::TransferFrom {
                from: owner,
                to: dest,
                amount: 101
            }
        ),
        Err(TokenError::InsufficientAllowance)
    );
    assert_eq!(reg.balance_of(&id, &dest), 0);
}

/// ATTACK 5: A FAILED transfer_from must NOT consume the owner's allowance (atomicity).
/// This is the checks-effects-interactions regression test.
#[test]
fn attack_failed_transfer_from_does_not_consume_allowance() {
    let mut reg = TokenRegistry::new();
    let owner = addr(1);
    let spender = addr(2);
    let dest = addr(3);
    let id = reg.create_token(owner, meta("T", "T"), 50).unwrap();

    // Owner approves 1,000,000 but only has 50 tokens
    reg.execute(
        &id,
        owner,
        TokenOp::Approve {
            spender,
            amount: 1_000_000,
        },
    )
    .unwrap();

    // Spender attempts to move 100 (more than the owner's balance) -> must fail
    let res = reg.execute(
        &id,
        spender,
        TokenOp::TransferFrom {
            from: owner,
            to: dest,
            amount: 100,
        },
    );
    assert_eq!(res, Err(TokenError::InsufficientBalance));

    // CRITICAL: allowance must be untouched after the failed attempt
    assert_eq!(
        reg.get(&id).unwrap().allowance(&owner, &spender),
        1_000_000,
        "Failed transfer_from MUST NOT consume allowance!"
    );
    assert_eq!(
        reg.balance_of(&id, &owner),
        50,
        "Owner balance must be untouched"
    );
}

/// ATTACK 6: Failed mint must not mutate total supply (atomicity).
#[test]
fn attack_failed_mint_leaves_supply_intact() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let mut m = meta("Capped", "CAP");
    m.max_supply = Some(100);
    let id = reg.create_token(minter, m, 100).unwrap();

    let before = reg.get(&id).unwrap().metadata.total_supply;
    // Mint beyond cap fails
    assert_eq!(
        reg.execute(
            &id,
            minter,
            TokenOp::Mint {
                to: minter,
                amount: 1
            }
        ),
        Err(TokenError::SupplyCapExceeded)
    );
    let after = reg.get(&id).unwrap().metadata.total_supply;
    assert_eq!(before, after, "Failed mint MUST NOT change total supply!");
}

/// ATTACK 7: Pause bypass attempts by non-minter and via mint/burn.
#[test]
fn attack_pause_bypass_rejected() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let user = addr(2);
    let id = reg.create_token(minter, meta("T", "T"), 1_000).unwrap();

    reg.execute(&id, minter, TokenOp::Pause).unwrap();

    // All value-moving ops blocked
    assert_eq!(
        reg.execute(
            &id,
            minter,
            TokenOp::Transfer {
                to: user,
                amount: 1
            }
        ),
        Err(TokenError::Paused)
    );
    assert_eq!(
        reg.execute(
            &id,
            minter,
            TokenOp::Mint {
                to: user,
                amount: 1
            }
        ),
        Err(TokenError::Paused)
    );
    assert_eq!(
        reg.execute(
            &id,
            minter,
            TokenOp::Burn {
                from: minter,
                amount: 1
            }
        ),
        Err(TokenError::Paused)
    );

    // Non-minter cannot unpause
    assert_eq!(
        reg.execute(&id, user, TokenOp::Unpause),
        Err(TokenError::NotMinter)
    );
    // Still paused
    assert_eq!(
        reg.execute(
            &id,
            minter,
            TokenOp::Transfer {
                to: user,
                amount: 1
            }
        ),
        Err(TokenError::Paused)
    );
}

/// ATTACK 8: Minter takeover attempts.
#[test]
fn attack_minter_takeover_rejected() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let attacker = addr(2);
    let id = reg.create_token(minter, meta("T", "T"), 0).unwrap();

    // Attacker tries to seize minter authority
    assert_eq!(
        reg.execute(
            &id,
            attacker,
            TokenOp::SetMinter {
                new_minter: attacker
            }
        ),
        Err(TokenError::NotMinter)
    );
    // Attacker tries to renounce the real minter (griefing)
    assert_eq!(
        reg.execute(&id, attacker, TokenOp::RenounceMinter),
        Err(TokenError::NotMinter)
    );
    // Authority intact
    assert_eq!(reg.get(&id).unwrap().metadata.minter, minter);
}

/// ATTACK 9: Zero-amount and self-transfer griefing.
#[test]
fn attack_zero_and_self_transfer_griefing_rejected() {
    let mut reg = TokenRegistry::new();
    let alice = addr(1);
    let id = reg.create_token(alice, meta("T", "T"), 100).unwrap();

    assert_eq!(
        reg.execute(
            &id,
            alice,
            TokenOp::Transfer {
                to: addr(2),
                amount: 0
            }
        ),
        Err(TokenError::ZeroAmount)
    );
    assert_eq!(
        reg.execute(
            &id,
            alice,
            TokenOp::Transfer {
                to: alice,
                amount: 10
            }
        ),
        Err(TokenError::SelfTransfer)
    );
    assert_eq!(
        reg.execute(
            &id,
            alice,
            TokenOp::Mint {
                to: alice,
                amount: 0
            }
        ),
        Err(TokenError::ZeroAmount)
    );
    assert_eq!(
        reg.execute(
            &id,
            alice,
            TokenOp::Burn {
                from: alice,
                amount: 0
            }
        ),
        Err(TokenError::ZeroAmount)
    );
    // Approve to self is meaningless and rejected
    assert_eq!(
        reg.execute(
            &id,
            alice,
            TokenOp::Approve {
                spender: alice,
                amount: 5
            }
        ),
        Err(TokenError::SelfTransfer)
    );
}

/// ATTACK 10: Cross-token confusion — operating on token A must not affect token B.
#[test]
fn attack_cross_token_confusion_isolated() {
    let mut reg = TokenRegistry::new();
    let creator = addr(1);
    let holder = addr(2);

    let id_a = reg
        .create_token(creator, meta("Alpha", "ALPHA"), 1_000)
        .unwrap();
    let id_b = reg
        .create_token(creator, meta("Beta", "BETA"), 1_000)
        .unwrap();
    assert_ne!(id_a, id_b);

    // Transfer on token A
    reg.execute(
        &id_a,
        creator,
        TokenOp::Transfer {
            to: holder,
            amount: 500,
        },
    )
    .unwrap();

    assert_eq!(reg.balance_of(&id_a, &holder), 500);
    assert_eq!(
        reg.balance_of(&id_b, &holder),
        0,
        "Token B must be unaffected by token A ops"
    );

    // Mint on token A only
    reg.execute(
        &id_a,
        creator,
        TokenOp::Mint {
            to: holder,
            amount: 100,
        },
    )
    .unwrap();
    assert_eq!(reg.get(&id_a).unwrap().metadata.total_supply, 1_100);
    assert_eq!(
        reg.get(&id_b).unwrap().metadata.total_supply,
        1_000,
        "Token B supply must be unchanged"
    );
}

/// ATTACK 11: Burn more than the balance.
#[test]
fn attack_over_burn_rejected() {
    let mut reg = TokenRegistry::new();
    let alice = addr(1);
    let id = reg.create_token(alice, meta("T", "T"), 100).unwrap();

    assert_eq!(
        reg.execute(
            &id,
            alice,
            TokenOp::Burn {
                from: alice,
                amount: 101
            }
        ),
        Err(TokenError::InsufficientBalance)
    );
    assert_eq!(reg.balance_of(&id, &alice), 100);
    assert_eq!(reg.get(&id).unwrap().metadata.total_supply, 100);
}

/// ATTACK 12: Renouncement abuse — after renounce, no mint/set_minter, but transfers live on.
#[test]
fn attack_renouncement_abuse() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let id = reg.create_token(minter, meta("T", "T"), 1_000).unwrap();
    reg.execute(&id, minter, TokenOp::RenounceMinter).unwrap();

    assert_eq!(reg.get(&id).unwrap().metadata.minter, ZERO_ADDRESS);
    assert_eq!(
        reg.execute(
            &id,
            minter,
            TokenOp::Mint {
                to: minter,
                amount: 1
            }
        ),
        Err(TokenError::MinterRenounced)
    );
    assert_eq!(
        reg.execute(
            &id,
            minter,
            TokenOp::SetMinter {
                new_minter: addr(9)
            }
        ),
        Err(TokenError::MinterRenounced)
    );
    // The zero address must never be treated as a valid minter
    assert!(!reg.get(&id).unwrap().is_minter(&ZERO_ADDRESS));
    // Transfers remain functional
    reg.execute(
        &id,
        minter,
        TokenOp::Transfer {
            to: addr(2),
            amount: 100,
        },
    )
    .unwrap();
    assert_eq!(reg.balance_of(&id, &addr(2)), 100);
}

/// ATTACK 13: Overflow attack — minting near u64::MAX must not wrap.
#[test]
fn attack_overflow_on_mint_rejected() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let id = reg.create_token(minter, meta("T", "T"), u64::MAX).unwrap();

    // Any additional mint would overflow total_supply
    let res = reg.execute(
        &id,
        minter,
        TokenOp::Mint {
            to: minter,
            amount: 1,
        },
    );
    assert_eq!(
        res,
        Err(TokenError::Overflow),
        "Overflow MUST be caught, not wrapped!"
    );
    assert_eq!(reg.get(&id).unwrap().metadata.total_supply, u64::MAX);
}

/// ATTACK 14: Token ID forgery — attacker cannot guess/collide another creator's token ID.
#[test]
fn attack_token_id_forgery() {
    let victim = addr(1);
    let attacker = addr(2);

    // Attacker tries to derive the victim's token id for nonce 1
    let forged = compute_token_id(&attacker, "Wrapped USDT", "wUSDT", 1);
    let genuine = compute_token_id(&victim, "Wrapped USDT", "wUSDT", 1);
    assert_ne!(
        forged, genuine,
        "Token ID must bind the creator address; forgery must fail"
    );

    let mut reg = TokenRegistry::new();
    let victim_id = reg
        .create_token(victim, meta("Wrapped USDT", "wUSDT"), 1_000)
        .unwrap();
    assert_eq!(victim_id, genuine);
    // Attacker's forged id is not present in the registry
    assert!(!reg.exists(&forged));
    assert_eq!(
        reg.execute(
            &forged,
            attacker,
            TokenOp::Mint {
                to: attacker,
                amount: 1
            }
        ),
        Err(TokenError::TokenNotFound)
    );
}

/// ATTACK 15: Metadata spoofing — invalid metadata cannot be deployed.
#[test]
fn attack_metadata_spoofing_rejected() {
    let mut reg = TokenRegistry::new();
    let creator = addr(1);

    // Empty name / symbol
    assert_eq!(
        reg.create_token(creator, meta("", "wUSDT"), 0),
        Err(TokenError::MetadataInvalid)
    );
    assert_eq!(
        reg.create_token(creator, meta("Wrapped USDT", ""), 0),
        Err(TokenError::MetadataInvalid)
    );

    // Overlong fields
    let long_name = "A".repeat(65);
    assert_eq!(
        reg.create_token(creator, meta(&long_name, "wUSDT"), 0),
        Err(TokenError::MetadataInvalid)
    );

    // Excessive decimals
    let mut bad = meta("Wrapped USDT", "wUSDT");
    bad.decimals = 19;
    assert_eq!(
        reg.create_token(creator, bad, 0),
        Err(TokenError::MetadataInvalid)
    );

    // Initial supply above cap
    let mut capped = meta("Capped", "CAP");
    capped.max_supply = Some(100);
    assert_eq!(
        reg.create_token(creator, capped, 101),
        Err(TokenError::SupplyCapExceeded)
    );

    assert_eq!(reg.token_count(), 0, "No invalid token may be deployed");
}

/// ATTACK 16: Allowance griefing — spender cannot drain more after partial spend.
#[test]
fn attack_allowance_partial_spend_exhaustion() {
    let mut reg = TokenRegistry::new();
    let owner = addr(1);
    let spender = addr(2);
    let id = reg.create_token(owner, meta("T", "T"), 1_000).unwrap();

    reg.execute(
        &id,
        owner,
        TokenOp::Approve {
            spender,
            amount: 300,
        },
    )
    .unwrap();

    // Spender drains 300 in three steps
    for _ in 0..3 {
        reg.execute(
            &id,
            spender,
            TokenOp::TransferFrom {
                from: owner,
                to: spender,
                amount: 100,
            },
        )
        .unwrap();
    }
    assert_eq!(reg.get(&id).unwrap().allowance(&owner, &spender), 0);

    // Fourth attempt must fail
    assert_eq!(
        reg.execute(
            &id,
            spender,
            TokenOp::TransferFrom {
                from: owner,
                to: spender,
                amount: 1
            }
        ),
        Err(TokenError::InsufficientAllowance)
    );
}
