//! Integration tests: on-chain token state binding + SVM token syscalls.
//! Verifies that token balances are committed into the consensus state root,
//! are SPV-provable, and that VM token mutations are atomic (rolled back on revert).

use stellereum::cell::PatriciaTrie;
use stellereum::state_engine::{token_balance_key, InMemoryStateEngine};
use stellereum::svm::{OpCode, Svm, VmContext, VmExecutionResult};
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

/// Token creation must commit supply + balances into the consensus state root.
#[tokio::test]
async fn token_creation_commits_to_state_root() {
    let engine = InMemoryStateEngine::new();
    let root_before = engine.get_state_root().await;

    let alice = addr(1);
    let id = engine
        .create_token(alice, meta("Wrapped USDT", "wUSDT"), 1_000_000)
        .await
        .unwrap();

    let root_after = engine.get_state_root().await;
    assert_ne!(
        root_before, root_after,
        "State root must change when a token is created"
    );
    assert_eq!(engine.token_balance(&id, &alice).await, 1_000_000);
    assert_eq!(engine.token_total_supply(&id).await, Some(1_000_000));
    assert_eq!(engine.all_token_ids().await.len(), 1);
}

/// Token balances must be SPV-provable against the state root (like native STELL).
#[tokio::test]
async fn token_balance_is_spv_provable() {
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
                amount: 250_000,
            },
        )
        .await
        .unwrap();

    let root = engine.get_state_root().await;

    // Bob's balance proof
    let bob_key = token_balance_key(&id, &bob);
    let bob_proof = engine.get_token_balance_proof(&id, &bob).await.unwrap();
    assert!(
        PatriciaTrie::verify_merkle_proof(&root, &bob_key, &250_000u64.to_be_bytes(), &bob_proof),
        "Bob's token balance must be SPV-verifiable against the state root"
    );

    // Forged balance must NOT verify against the same proof
    assert!(
        !PatriciaTrie::verify_merkle_proof(
            &root,
            &bob_key,
            &999_999_999u64.to_be_bytes(),
            &bob_proof
        ),
        "A forged token balance must fail SPV verification"
    );
}

/// Token transfer through the state engine updates balances and the state root.
#[tokio::test]
async fn token_transfer_updates_state() {
    let engine = InMemoryStateEngine::new();
    let alice = addr(1);
    let bob = addr(2);
    let id = engine
        .create_token(alice, meta("T", "T"), 1_000)
        .await
        .unwrap();

    let root_before = engine.get_state_root().await;
    engine
        .token_execute(
            &id,
            alice,
            TokenOp::Transfer {
                to: bob,
                amount: 400,
            },
        )
        .await
        .unwrap();
    let root_after = engine.get_state_root().await;

    assert_ne!(
        root_before, root_after,
        "State root must change after a token transfer"
    );
    assert_eq!(engine.token_balance(&id, &alice).await, 600);
    assert_eq!(engine.token_balance(&id, &bob).await, 400);
}

/// SVM token transfer syscall succeeds and mutates the registry.
#[test]
fn svm_token_transfer_syscall_succeeds() {
    let alice = addr(1);
    let bob = addr(2);
    let mut registry = TokenRegistry::new();
    let id = registry.create_token(alice, meta("T", "T"), 1_000).unwrap();

    let mut ctx = VmContext {
        sender: alice,
        balance: 10_000,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        pmm: None,
        zkml_proof: None,
        timestamp: 1_000,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: Some(&mut registry),
        token_events: Vec::new(),
        contracts: None,
        staking: None,
        min_validator_bond: stellereum::staking::MIN_VALIDATOR_BOND,
        default_commission_bps: stellereum::staking::DEFAULT_COMMISSION_BPS,
        payouts: Vec::new(),
        oracle: None,
    };

    let ops = vec![
        OpCode::SysCallTokenTransfer {
            token_id: id,
            to: bob,
            amount: 400,
        },
        OpCode::SysCallTokenBalanceOf {
            token_id: id,
            account: bob,
        },
        OpCode::Halt,
    ];

    // 280_000 (the token transfer) + 280_000 (the balance query): both are
    // priced at the native floor since the token table was aligned with it
    // (audit W6.6).
    let res = Svm::execute(&ops, 1_000_000, &mut ctx);
    match res {
        VmExecutionResult::Success {
            return_value,
            token_events,
            ..
        } => {
            assert_eq!(
                return_value,
                Some(400),
                "BalanceOf must push Bob's new balance"
            );
            assert_eq!(token_events.len(), 1);
        }
        other => panic!("Execution failed: {:?}", other),
    }
    assert_eq!(registry.balance_of(&id, &alice), 600);
    assert_eq!(registry.balance_of(&id, &bob), 400);
}

/// ATOMICITY: a revert after a token mutation must discard the token change entirely.
#[test]
fn svm_token_mutations_are_atomic_on_revert() {
    let alice = addr(1);
    let bob = addr(2);
    let mut registry = TokenRegistry::new();
    let id = registry.create_token(alice, meta("T", "T"), 1_000).unwrap();

    let mut ctx = VmContext {
        sender: alice,
        balance: 10, // tiny native balance so the second op reverts
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        pmm: None,
        zkml_proof: None,
        timestamp: 1_000,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: Some(&mut registry),
        token_events: Vec::new(),
        contracts: None,
        staking: None,
        min_validator_bond: stellereum::staking::MIN_VALIDATOR_BOND,
        default_commission_bps: stellereum::staking::DEFAULT_COMMISSION_BPS,
        payouts: Vec::new(),
        oracle: None,
    };

    let ops = vec![
        // This token transfer would succeed on its own...
        OpCode::SysCallTokenTransfer {
            token_id: id,
            to: bob,
            amount: 400,
        },
        // ...but this native transfer exceeds the balance and reverts the whole tx.
        OpCode::Transfer {
            recipient: bob,
            amount: 9_999,
        },
    ];

    // 280_000 (the token transfer) + 280_000 (the native transfer).
    let res = Svm::execute(&ops, 1_000_000, &mut ctx);
    assert!(
        matches!(res, VmExecutionResult::Reverted(_)),
        "VM must revert"
    );

    // CRITICAL: the token transfer must NOT have been committed.
    assert_eq!(
        registry.balance_of(&id, &alice),
        1_000,
        "Reverted tx must not move tokens"
    );
    assert_eq!(
        registry.balance_of(&id, &bob),
        0,
        "Reverted tx must not credit tokens"
    );
}

/// SVM mint syscall enforces minter authority: a non-minter cannot mint.
#[test]
fn svm_unauthorized_token_mint_rejected() {
    let minter = addr(1);
    let attacker = addr(9);
    let mut registry = TokenRegistry::new();
    let id = registry.create_token(minter, meta("T", "T"), 0).unwrap();

    let mut ctx = VmContext {
        sender: attacker, // not the minter
        balance: 10_000,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        pmm: None,
        zkml_proof: None,
        timestamp: 1_000,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: Some(&mut registry),
        token_events: Vec::new(),
        contracts: None,
        staking: None,
        min_validator_bond: stellereum::staking::MIN_VALIDATOR_BOND,
        default_commission_bps: stellereum::staking::DEFAULT_COMMISSION_BPS,
        payouts: Vec::new(),
        oracle: None,
    };

    let ops = vec![OpCode::SysCallTokenMint {
        token_id: id,
        to: attacker,
        amount: 1_000_000,
    }];
    let res = Svm::execute(&ops, 500_000, &mut ctx);
    assert!(
        matches!(res, VmExecutionResult::Reverted(_)),
        "Unauthorized mint must revert"
    );
    assert_eq!(registry.balance_of(&id, &attacker), 0);
    assert_eq!(registry.token_count(), 1);
}

/// Token op without a registry in context must revert, not panic.
#[test]
fn svm_token_op_without_registry_reverts() {
    let alice = addr(1);
    let mut ctx = VmContext {
        sender: alice,
        balance: 10_000,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        pmm: None,
        zkml_proof: None,
        timestamp: 1_000,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: None,
        token_events: Vec::new(),
        contracts: None,
        staking: None,
        min_validator_bond: stellereum::staking::MIN_VALIDATOR_BOND,
        default_commission_bps: stellereum::staking::DEFAULT_COMMISSION_BPS,
        payouts: Vec::new(),
        oracle: None,
    };

    let ops = vec![OpCode::SysCallTokenTransfer {
        token_id: addr(7),
        to: addr(2),
        amount: 1,
    }];
    let res = Svm::execute(&ops, 500_000, &mut ctx);
    assert!(matches!(res, VmExecutionResult::Reverted(_)));
}

/// ON-CHAIN CREATE: `SysCallTokenCreate` mints a permissionless token through
/// the VM — creator becomes minter, funded with the full initial supply.
#[test]
fn svm_token_create_syscall_full_loop() {
    let alice = addr(1);
    let bob = addr(2);
    let mut registry = TokenRegistry::new();

    let mut ctx = VmContext {
        sender: alice,
        balance: 10_000_000,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        pmm: None,
        zkml_proof: None,
        timestamp: 1_000,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: Some(&mut registry),
        token_events: Vec::new(),
        contracts: None,
        staking: None,
        min_validator_bond: stellereum::staking::MIN_VALIDATOR_BOND,
        default_commission_bps: stellereum::staking::DEFAULT_COMMISSION_BPS,
        payouts: Vec::new(),
        oracle: None,
    };

    let ops = vec![
        OpCode::SysCallTokenCreate {
            name: "Test Coin".into(),
            symbol: "TST".into(),
            decimals: 6,
            initial_supply: 1_000_000,
            max_supply: Some(2_000_000),
        },
        OpCode::Halt,
    ];

    let res = Svm::execute(&ops, 1_000_000, &mut ctx);
    let events = match res {
        VmExecutionResult::Success { token_events, .. } => token_events,
        other => panic!("Create failed: {:?}", other),
    };
    assert_eq!(
        events.len(),
        1,
        "creation with supply must emit the mint event"
    );
    drop(ctx);

    let id = registry
        .find_by_creator_name(&alice, "Test Coin", "TST")
        .expect("created token must resolve by (creator, name, symbol)");
    assert_eq!(registry.balance_of(&id, &alice), 1_000_000);
    assert!(registry
        .get(&id)
        .map(|t| t.is_minter(&alice))
        .unwrap_or(false));

    // The fresh token is immediately usable: transfer + balance through the VM.
    let mut ctx = VmContext {
        sender: alice,
        balance: 10_000_000,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        pmm: None,
        zkml_proof: None,
        timestamp: 1_000,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: Some(&mut registry),
        token_events: Vec::new(),
        contracts: None,
        staking: None,
        min_validator_bond: stellereum::staking::MIN_VALIDATOR_BOND,
        default_commission_bps: stellereum::staking::DEFAULT_COMMISSION_BPS,
        payouts: Vec::new(),
        oracle: None,
    };
    let ops2 = vec![
        OpCode::SysCallTokenTransfer {
            token_id: id,
            to: bob,
            amount: 400_000,
        },
        OpCode::SysCallTokenBalanceOf {
            token_id: id,
            account: bob,
        },
        OpCode::Halt,
    ];
    match Svm::execute(&ops2, 1_000_000, &mut ctx) {
        VmExecutionResult::Success { return_value, .. } => {
            assert_eq!(return_value, Some(400_000));
        }
        other => panic!("Transfer of fresh token failed: {:?}", other),
    }
    drop(ctx);
    assert_eq!(registry.balance_of(&id, &bob), 400_000);
}

/// CREATE FAIL-CLOSED: bad metadata reverts, zero supply emits no event.
#[test]
fn svm_token_create_rejects_bad_metadata() {
    fn try_create(
        name: &str,
        symbol: &str,
        decimals: u8,
        supply: u64,
        cap: Option<u64>,
    ) -> VmExecutionResult {
        let mut registry = TokenRegistry::new();
        let mut ctx = VmContext {
            sender: addr(1),
            balance: 10_000_000,
            orderbooks: None,
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            pmm: None,
            zkml_proof: None,
            timestamp: 1_000,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: Some(&mut registry),
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            min_validator_bond: stellereum::staking::MIN_VALIDATOR_BOND,
            default_commission_bps: stellereum::staking::DEFAULT_COMMISSION_BPS,
            payouts: Vec::new(),
            oracle: None,
        };
        let ops = vec![
            OpCode::SysCallTokenCreate {
                name: name.into(),
                symbol: symbol.into(),
                decimals,
                initial_supply: supply,
                max_supply: cap,
            },
            OpCode::Halt,
        ];
        Svm::execute(&ops, 1_000_000, &mut ctx)
    }

    for (name, symbol, dec, supply, cap) in [
        ("", "TST", 6, 100, None),                   // empty name
        ("T", "", 6, 100, None),                     // empty symbol
        ("T", "TOOLONGSYMBOL12345", 6, 100, None),   // symbol > 16
        ("T", "TST", 19, 100, None),                 // decimals > 18
        ("T", "TST", 6, 3_000_000, Some(2_000_000)), // supply above cap
    ] {
        assert!(
            matches!(
                try_create(name, symbol, dec, supply, cap),
                VmExecutionResult::Reverted(_)
            ),
            "must revert: name={:?} symbol={:?}",
            name,
            symbol
        );
    }

    // Zero supply: succeeds, mints nothing, emits no event.
    match try_create("Empty", "MT", 6, 0, None) {
        VmExecutionResult::Success { token_events, .. } => assert!(token_events.is_empty()),
        other => panic!("Zero-supply create must succeed: {:?}", other),
    }
}

/// RESOLVE: engine-level (creator, name, symbol) lookup finds the token.
#[tokio::test]
async fn token_resolve_finds_by_creator_name() {
    let engine = InMemoryStateEngine::new();
    let alice = addr(1);
    let id = engine
        .create_token(alice, meta("Wrapped USDT", "wUSDT"), 1_000_000)
        .await
        .unwrap();
    assert_eq!(
        engine.token_resolve(&alice, "Wrapped USDT", "wUSDT").await,
        Some(id)
    );
    assert_eq!(
        engine
            .token_resolve(&addr(9), "Wrapped USDT", "wUSDT")
            .await,
        None
    );
    assert_eq!(
        engine.token_resolve(&alice, "Wrapped USDT", "OTHER").await,
        None
    );
}

/// PAUSE SEMANTIC (audit 2026-10-06): pause freezes movement, not approvals.
/// Allowances granted while paused arm on unpause — pinned so nobody
/// "fixes" this into a different semantic silently.
#[test]
fn approvals_survive_pause_but_movement_does_not() {
    let alice = addr(1);
    let bob = addr(2);
    let mut registry = TokenRegistry::new();
    let id = registry.create_token(alice, meta("T", "T"), 1_000).unwrap();
    let t = registry.get_mut(&id).unwrap();
    t.metadata.paused = true;
    // Movement frozen...
    assert!(registry
        .execute(
            &id,
            alice,
            TokenOp::Transfer {
                to: bob,
                amount: 10
            }
        )
        .is_err());
    // ...approvals not.
    assert!(registry
        .execute(
            &id,
            alice,
            TokenOp::Approve {
                spender: bob,
                amount: 100
            }
        )
        .is_ok());
    let t = registry.get_mut(&id).unwrap();
    t.metadata.paused = false;
    assert!(registry
        .execute(
            &id,
            bob,
            TokenOp::TransferFrom {
                from: alice,
                to: bob,
                amount: 100
            }
        )
        .is_ok());
    assert_eq!(registry.balance_of(&id, &bob), 100);
}

/// set_minter to zero is rejected (use renounce_minter); same-triple creates
/// yield DISTINCT ids (registry nonce), never an overwrite.
#[test]
fn minter_rotation_fails_closed_and_recreate_never_overwrites() {
    let alice = addr(1);
    let mut registry = TokenRegistry::new();
    let id = registry.create_token(alice, meta("T", "T"), 1_000).unwrap();
    let t = registry.get_mut(&id).unwrap();
    assert_eq!(
        t.set_minter(alice, ZERO_ADDRESS),
        Err(TokenError::ZeroAddress),
        "silent renounce via set_minter is forbidden"
    );
    let id2 = registry.create_token(alice, meta("T", "T"), 500).unwrap();
    assert_ne!(
        id, id2,
        "re-create must mint a distinct token, not overwrite"
    );
    assert_eq!(registry.balance_of(&id, &alice), 1_000);
    assert_eq!(registry.balance_of(&id2, &alice), 500);
    assert_eq!(
        format!("{}", TokenError::DuplicateToken),
        "token id already registered"
    );
}
