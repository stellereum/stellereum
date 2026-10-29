//! Aggressive adversarial & fuzz security suite for the Stellereum Token Standard.
//! This is the "try to break it" layer: random operation fuzzing with invariant
//! checking, zero-address attacks, approve-race exploitation, snapshot tampering,
//! extreme-value and stress attacks.

use stellereum::cell::PatriciaTrie;
use stellereum::state_engine::{token_balance_key, InMemoryStateEngine};
use stellereum::token::{TokenError, TokenMetadata, TokenOp, TokenRegistry, ZERO_ADDRESS};

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

/// FUZZ: run thousands of random operations and assert the core economic invariant
/// `sum(balances) == total_supply` holds after EVERY single operation.
/// This is the strongest test that no operation can create or destroy value silently.
#[test]
fn fuzz_invariant_supply_equals_sum_of_balances() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let mut m = meta("Fuzz", "FZ");
    m.max_supply = Some(1_000_000_000);
    let id = reg.create_token(minter, m, 0).unwrap();

    let accounts: Vec<[u8; 32]> = (1..=10u8).map(addr).collect();

    // Deterministic LCG so failures are reproducible
    let mut seed: u64 = 0xDEADBEEFCAFEBABE;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        seed >> 33
    };

    for step in 0..10_000u64 {
        let op = next() % 7;
        let a = accounts[(next() as usize) % accounts.len()];
        let b = accounts[(next() as usize) % accounts.len()];
        let amount = next() % 1_000;

        let _ = match op {
            0 => reg.execute(&id, minter, TokenOp::Mint { to: a, amount }),
            1 => reg.execute(&id, a, TokenOp::Transfer { to: b, amount }),
            2 => reg.execute(&id, a, TokenOp::Burn { from: a, amount }),
            3 => reg.execute(&id, minter, TokenOp::Burn { from: a, amount }),
            4 => reg.execute(&id, a, TokenOp::Approve { spender: b, amount }),
            5 => reg.execute(
                &id,
                b,
                TokenOp::TransferFrom {
                    from: a,
                    to: b,
                    amount,
                },
            ),
            6 => reg.execute(
                &id,
                a,
                TokenOp::IncreaseAllowance {
                    spender: b,
                    delta: amount,
                },
            ),
            _ => unreachable!(),
        };

        // INVARIANT 1: total supply must equal the sum of all balances
        let token = reg.get(&id).unwrap();
        let sum: u64 = token.balances.values().sum();
        assert_eq!(
            sum, token.metadata.total_supply,
            "INVARIANT VIOLATED at step {step}: sum(balances)={sum} != total_supply={}",
            token.metadata.total_supply
        );

        // INVARIANT 2: no individual balance may exceed total supply
        for bal in token.balances.values() {
            assert!(
                *bal <= token.metadata.total_supply,
                "balance exceeds total supply at step {step}"
            );
        }

        // INVARIANT 3: supply never exceeds the hard cap
        assert!(token.metadata.total_supply <= 1_000_000_000);
    }
}

/// FUZZ across multiple tokens: operations on one token must never corrupt another.
#[test]
fn fuzz_multi_token_isolation() {
    let mut reg = TokenRegistry::new();
    let creator = addr(1);
    let ids: Vec<[u8; 32]> = (0..5u64)
        .map(|i| {
            let mut m = meta(&format!("T{i}"), &format!("T{i}"));
            m.max_supply = Some(1_000_000);
            reg.create_token(creator, m, 1_000_000).unwrap()
        })
        .collect();

    let accounts: Vec<[u8; 32]> = (2..=8u8).map(addr).collect();
    let mut seed: u64 = 42;
    let mut next = move || {
        seed = seed
            .wrapping_mul(2862933555777941757)
            .wrapping_add(3037000493);
        seed >> 33
    };

    for _ in 0..5_000 {
        let id = ids[(next() as usize) % ids.len()];
        let a = accounts[(next() as usize) % accounts.len()];
        let b = accounts[(next() as usize) % accounts.len()];
        let amount = next() % 500;
        let _ = reg.execute(&id, a, TokenOp::Transfer { to: b, amount });
    }

    // Each token must still satisfy its own invariant
    for id in &ids {
        let token = reg.get(id).unwrap();
        let sum: u64 = token.balances.values().sum();
        assert_eq!(
            sum, token.metadata.total_supply,
            "multi-token invariant violated"
        );
        assert_eq!(token.metadata.total_supply, 1_000_000);
    }
}

/// ATTACK: send tokens to the zero address (would lock them without burning supply).
#[test]
fn attack_transfer_to_zero_address_rejected() {
    let mut reg = TokenRegistry::new();
    let alice = addr(1);
    let id = reg.create_token(alice, meta("T", "T"), 1_000).unwrap();

    assert_eq!(
        reg.execute(
            &id,
            alice,
            TokenOp::Transfer {
                to: ZERO_ADDRESS,
                amount: 100
            }
        ),
        Err(TokenError::ZeroAddress)
    );
    assert_eq!(reg.balance_of(&id, &alice), 1_000, "Balance must be intact");
    assert_eq!(
        reg.get(&id).unwrap().metadata.total_supply,
        1_000,
        "Supply must be intact"
    );
}

/// ATTACK: mint tokens to the zero address (permanent loss).
#[test]
fn attack_mint_to_zero_address_rejected() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let id = reg.create_token(minter, meta("T", "T"), 0).unwrap();
    assert_eq!(
        reg.execute(
            &id,
            minter,
            TokenOp::Mint {
                to: ZERO_ADDRESS,
                amount: 1_000
            }
        ),
        Err(TokenError::ZeroAddress)
    );
    assert_eq!(reg.get(&id).unwrap().metadata.total_supply, 0);
}

/// ATTACK: burn from the zero address.
#[test]
fn attack_burn_from_zero_address_rejected() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let id = reg.create_token(minter, meta("T", "T"), 1_000).unwrap();
    assert_eq!(
        reg.execute(
            &id,
            minter,
            TokenOp::Burn {
                from: ZERO_ADDRESS,
                amount: 1
            }
        ),
        Err(TokenError::ZeroAddress)
    );
}

/// ATTACK: classic ERC-20 approve race — plus the safe increase/decrease helpers.
#[test]
fn attack_approve_race_and_safe_allowance_helpers() {
    let mut reg = TokenRegistry::new();
    let owner = addr(1);
    let spender = addr(2);
    let dest = addr(3);
    let id = reg.create_token(owner, meta("T", "T"), 1_000).unwrap();

    // Owner approves 100
    reg.execute(
        &id,
        owner,
        TokenOp::Approve {
            spender,
            amount: 100,
        },
    )
    .unwrap();
    // Spender front-runs the owner's intended reduction and drains the 100
    reg.execute(
        &id,
        spender,
        TokenOp::TransferFrom {
            from: owner,
            to: dest,
            amount: 100,
        },
    )
    .unwrap();
    assert_eq!(reg.balance_of(&id, &dest), 100);
    assert_eq!(reg.get(&id).unwrap().allowance(&owner, &spender), 0);

    // Safe alternative #1: DecreaseAllowance (no race window)
    reg.execute(
        &id,
        owner,
        TokenOp::Approve {
            spender,
            amount: 50,
        },
    )
    .unwrap();
    reg.execute(
        &id,
        owner,
        TokenOp::DecreaseAllowance { spender, delta: 20 },
    )
    .unwrap();
    assert_eq!(reg.get(&id).unwrap().allowance(&owner, &spender), 30);

    // Decrease below zero must fail (no underflow/wrap)
    assert_eq!(
        reg.execute(
            &id,
            owner,
            TokenOp::DecreaseAllowance { spender, delta: 31 }
        ),
        Err(TokenError::AllowanceUnderflow)
    );
    assert_eq!(
        reg.get(&id).unwrap().allowance(&owner, &spender),
        30,
        "Allowance must be unchanged"
    );

    // Safe alternative #2: IncreaseAllowance
    reg.execute(
        &id,
        owner,
        TokenOp::IncreaseAllowance { spender, delta: 70 },
    )
    .unwrap();
    assert_eq!(reg.get(&id).unwrap().allowance(&owner, &spender), 100);
}

/// ATTACK: approve the zero address.
#[test]
fn attack_approve_zero_address_rejected() {
    let mut reg = TokenRegistry::new();
    let owner = addr(1);
    let id = reg.create_token(owner, meta("T", "T"), 1_000).unwrap();
    assert_eq!(
        reg.execute(
            &id,
            owner,
            TokenOp::Approve {
                spender: ZERO_ADDRESS,
                amount: 100
            }
        ),
        Err(TokenError::ZeroAddress)
    );
}

/// ATTACK: set_minter to zero (renounce alias) then try to mint.
#[test]
fn attack_set_minter_to_zero_then_mint() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let id = reg.create_token(minter, meta("T", "T"), 1_000).unwrap();

    // Silent renounce via set_minter is FORBIDDEN (audit 2026-10-06): a typo
    // would burn mint authority with the wrong event. Explicit renounce only.
    assert_eq!(
        reg.execute(
            &id,
            minter,
            TokenOp::SetMinter {
                new_minter: ZERO_ADDRESS
            }
        ),
        Err(TokenError::ZeroAddress)
    );
    // The explicit path still renounces, and minting stays dead after it.
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
}

/// ATTACK: allowances must be isolated per (owner, spender) and per token.
#[test]
fn attack_allowance_isolation() {
    let mut reg = TokenRegistry::new();
    let owner = addr(1);
    let spender_a = addr(2);
    let spender_b = addr(3);

    let id1 = reg.create_token(owner, meta("A", "A"), 1_000).unwrap();
    let id2 = reg.create_token(owner, meta("B", "B"), 1_000).unwrap();

    reg.execute(
        &id1,
        owner,
        TokenOp::Approve {
            spender: spender_a,
            amount: 500,
        },
    )
    .unwrap();

    // spender_b has no allowance
    assert_eq!(reg.get(&id1).unwrap().allowance(&owner, &spender_b), 0);
    // Token 2 has no allowance for spender_a
    assert_eq!(reg.get(&id2).unwrap().allowance(&owner, &spender_a), 0);
    // Correct pair works
    assert_eq!(reg.get(&id1).unwrap().allowance(&owner, &spender_a), 500);
}

/// ATTACK: extreme values near u64::MAX must not overflow or wrap.
#[test]
fn attack_extreme_values_no_overflow() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let mut m = meta("Big", "BIG");
    m.max_supply = Some(u64::MAX);
    let id = reg.create_token(minter, m, u64::MAX - 10).unwrap();

    // Fill up to exactly u64::MAX
    reg.execute(
        &id,
        minter,
        TokenOp::Mint {
            to: minter,
            amount: 10,
        },
    )
    .unwrap();
    assert_eq!(reg.get(&id).unwrap().metadata.total_supply, u64::MAX);

    // One more token would overflow -> must be rejected, supply unchanged
    assert_eq!(
        reg.execute(
            &id,
            minter,
            TokenOp::Mint {
                to: minter,
                amount: 1
            }
        ),
        Err(TokenError::Overflow)
    );
    assert_eq!(reg.get(&id).unwrap().metadata.total_supply, u64::MAX);
}

/// ATTACK: transferring the exact full balance must zero the account and keep supply.
#[test]
fn attack_transfer_exact_full_balance() {
    let mut reg = TokenRegistry::new();
    let alice = addr(1);
    let bob = addr(2);
    let id = reg.create_token(alice, meta("T", "T"), 1_000).unwrap();

    reg.execute(
        &id,
        alice,
        TokenOp::Transfer {
            to: bob,
            amount: 1_000,
        },
    )
    .unwrap();
    assert_eq!(reg.balance_of(&id, &alice), 0);
    assert_eq!(reg.balance_of(&id, &bob), 1_000);
    assert_eq!(
        reg.get(&id).unwrap().metadata.total_supply,
        1_000,
        "Supply must be conserved"
    );
    // Zero balance must be fully pruned from the map
    assert!(!reg.get(&id).unwrap().balances.contains_key(&alice));
}

/// ATTACK: burn the entire supply to zero.
#[test]
fn attack_burn_entire_supply() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let id = reg.create_token(minter, meta("T", "T"), 1_000).unwrap();

    reg.execute(
        &id,
        minter,
        TokenOp::Burn {
            from: minter,
            amount: 1_000,
        },
    )
    .unwrap();
    assert_eq!(reg.get(&id).unwrap().metadata.total_supply, 0);
    assert_eq!(reg.balance_of(&id, &minter), 0);
    // Burning again fails cleanly
    assert_eq!(
        reg.execute(
            &id,
            minter,
            TokenOp::Burn {
                from: minter,
                amount: 1
            }
        ),
        Err(TokenError::InsufficientBalance)
    );
}

/// ATTACK: repeated approve calls must overwrite, not accumulate.
#[test]
fn attack_repeated_approve_overwrites() {
    let mut reg = TokenRegistry::new();
    let owner = addr(1);
    let spender = addr(2);
    let id = reg.create_token(owner, meta("T", "T"), 1_000).unwrap();

    for amt in [100u64, 200, 50, 999] {
        reg.execute(
            &id,
            owner,
            TokenOp::Approve {
                spender,
                amount: amt,
            },
        )
        .unwrap();
        assert_eq!(reg.get(&id).unwrap().allowance(&owner, &spender), amt);
    }
}

/// ATTACK: garbage snapshot bytes must fail safely without corrupting the engine.
#[tokio::test]
async fn attack_garbage_token_snapshot_fails_safely() {
    let engine = InMemoryStateEngine::new();
    let res = engine
        .restore_token_snapshot(&[0xDE, 0xAD, 0xBE, 0xEF])
        .await;
    assert!(res.is_err(), "Garbage snapshot must be rejected");
    assert_eq!(
        engine.all_token_ids().await.len(),
        0,
        "Registry must stay clean"
    );
    // Engine still usable afterwards
    let id = engine.create_token(addr(1), meta("T", "T"), 100).await;
    assert!(id.is_ok());
}

/// REGRESSION: restoring snapshots must preserve token balances AND their SPV proofs.
#[tokio::test]
async fn snapshot_restore_preserves_token_spv_proofs() {
    let engine = InMemoryStateEngine::new();
    let alice = addr(1);
    let bob = addr(2);
    let id = engine
        .create_token(alice, meta("Wrapped USDT", "wUSDT"), 1_000_000)
        .await
        .unwrap();
    engine
        .token_execute(
            &id,
            alice,
            TokenOp::Transfer {
                to: bob,
                amount: 400_000,
            },
        )
        .await
        .unwrap();

    let acc_snap = engine.create_snapshot().await;
    let tok_snap = engine.create_token_snapshot().await;

    // Fresh engine, restore both snapshots
    let engine2 = InMemoryStateEngine::new();
    engine2.restore_token_snapshot(&tok_snap).await.unwrap();
    engine2.restore_snapshot(&acc_snap).await.unwrap();

    assert_eq!(engine2.token_balance(&id, &bob).await, 400_000);
    assert_eq!(engine2.token_total_supply(&id).await, Some(1_000_000));

    // SPV proof must still verify after restore
    let root = engine2.get_state_root().await;
    let key = token_balance_key(&id, &bob);
    let proof = engine2.get_token_balance_proof(&id, &bob).await.unwrap();
    assert!(
        PatriciaTrie::verify_merkle_proof(&root, &key, &400_000u64.to_be_bytes(), &proof),
        "Token SPV proof must survive a snapshot restore"
    );
}

/// STRESS: deploy many tokens and holders, verify isolation and invariants.
#[test]
fn stress_many_tokens_and_holders() {
    let mut reg = TokenRegistry::new();
    let creator = addr(1);
    let mut ids = Vec::new();

    for i in 0..250u64 {
        let mut m = meta(&format!("Token{i}"), &format!("T{i}"));
        m.max_supply = Some(1_000_000);
        ids.push(reg.create_token(creator, m, 1_000_000).unwrap());
    }
    assert_eq!(reg.token_count(), 250);

    for (i, id) in ids.iter().enumerate() {
        let holder = addr((i % 200) as u8 + 2);
        reg.execute(
            id,
            creator,
            TokenOp::Transfer {
                to: holder,
                amount: 123,
            },
        )
        .unwrap();
        assert_eq!(reg.balance_of(id, &holder), 123);
        assert_eq!(reg.get(id).unwrap().metadata.total_supply, 1_000_000);
    }
}
