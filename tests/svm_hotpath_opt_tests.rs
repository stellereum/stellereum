//! Guard tests for the SVM hot-path optimization (single dispatch + lazy
//! clone-commit). These pin EXACT semantics across the rewrite:
//!
//! * the dispatch loop charges exactly what `opcode_gas` prices, for every
//!   opcode - including ones that revert (via the OutOfGas-vs-outcome
//!   boundary), so the inlined table can never drift from the priced table;
//! * `gas_used` is bit-identical under the deferred `gas_consumed`
//!   derivation, including Halt truncation and mid-program OutOfGas;
//! * lazy clone-commit is unobservable: wiring registries that a payload
//!   never touches changes nothing (gas, stack, balance), and atomicity
//!   (all-or-nothing working copies) is preserved.

use stellereum::staking::{DEFAULT_COMMISSION_BPS, MIN_VALIDATOR_BOND};
use stellereum::svm::{
    contract_deploy_gas, opcode_gas, OpCode, Svm, VmContext, VmExecutionResult, GAS_ADD_SUB,
    GAS_BASIC_TRANSFER, GAS_HALT, GAS_LOAD_BALANCE, GAS_MUL_DIV, GAS_NOP, GAS_POP, GAS_PUSH,
};
use stellereum::token::{TokenMetadata, TokenRegistry, ZERO_ADDRESS};

fn mk_ctx(balance: u64) -> VmContext<'static> {
    VmContext {
        sender: [1u8; 32],
        balance,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        pmm: None,
        zkml_proof: None,
        timestamp: 1,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: None,
        token_events: Vec::new(),
        contracts: None,
        staking: None,
        min_validator_bond: MIN_VALIDATOR_BOND,
        default_commission_bps: DEFAULT_COMMISSION_BPS,
        payouts: Vec::new(),
        oracle: None,
    }
}

fn is_oog(r: &VmExecutionResult) -> bool {
    matches!(r, VmExecutionResult::OutOfGas)
}

/// The dispatch charge for `op` must equal `opcode_gas(op)`.
///
/// With `gas_limit = cost - 1` the run must die in the charge itself
/// (`OutOfGas`); with `gas_limit = cost` it must get PAST the charge (any
/// non-`OutOfGas` outcome: `Success` or the arm's own `Reverted`). A drifted
/// inlined constant fails one side or the other.
fn assert_charge_matches_table(op: OpCode, balance: u64) {
    let cost = opcode_gas(&op);
    assert!(
        cost > 0,
        "use nonzero-cost ops here; Halt is covered separately"
    );
    let prog = vec![op];
    let mut ctx = mk_ctx(balance);
    let r = Svm::execute(&prog, cost - 1, &mut ctx);
    assert!(is_oog(&r), "limit = cost-1 must OutOfGas, got {r:?}");
    let mut ctx = mk_ctx(balance);
    let r = Svm::execute(&prog, cost, &mut ctx);
    assert!(!is_oog(&r), "limit = cost must clear the charge, got {r:?}");
}

#[test]
fn hot_arithmetic_charges_match_the_priced_table() {
    // Pinned VALUES (catches table edits), then boundary-vs-table (catches
    // dispatch drift even if the table moves legitimately).
    assert_eq!(
        (
            GAS_NOP,
            GAS_PUSH,
            GAS_POP,
            GAS_ADD_SUB,
            GAS_MUL_DIV,
            GAS_LOAD_BALANCE
        ),
        (1, 5, 2, 3, 10, 20)
    );
    assert_eq!(GAS_HALT, 0);
    for op in [
        OpCode::Nop,
        OpCode::Push(9),
        OpCode::Pop,
        OpCode::Add,
        OpCode::Sub,
        OpCode::Mul,
        OpCode::Div,
        OpCode::LoadBalance,
    ] {
        assert_charge_matches_table(op, 1_000_000);
    }
}

#[test]
fn syscall_charges_match_the_priced_table() {
    // Every arm, including ones that always revert on a bare context: the
    // boundary still pins the charge, because the charge runs first.
    let ops = vec![
        OpCode::Transfer {
            recipient: [2u8; 32],
            amount: 1,
        },
        OpCode::SysCallPlaceOrder {
            pair_id: 1,
            is_buy: true,
            price: 1,
            amount: 1,
        },
        OpCode::SysCallCancelOrder { order_id: 7 },
        OpCode::SysCallVerifyZkMl,
        OpCode::SysCallPatriciaLookup([0u8; 32]),
        OpCode::SysCallTokenTransfer {
            token_id: [0; 32],
            to: [1; 32],
            amount: 1,
        },
        OpCode::SysCallTokenTransferFrom {
            token_id: [0; 32],
            from: [1; 32],
            to: [2; 32],
            amount: 1,
        },
        OpCode::SysCallTokenMint {
            token_id: [0; 32],
            to: [1; 32],
            amount: 1,
        },
        OpCode::SysCallTokenBurn {
            token_id: [0; 32],
            from: [1; 32],
            amount: 1,
        },
        OpCode::SysCallTokenApprove {
            token_id: [0; 32],
            spender: [1; 32],
            amount: 1,
        },
        OpCode::SysCallTokenBalanceOf {
            token_id: [0; 32],
            account: [1; 32],
        },
        OpCode::SysCallDeployContract {
            code: vec![0u8; 10],
        },
        OpCode::SysCallCallContract {
            contract: [0; 32],
            method: b"m".to_vec(),
            arg: 0,
        },
        OpCode::SysCallStake {
            validator: [1u8; 32],
            amount: 5,
        },
        OpCode::SysCallUnbond {
            validator: [1u8; 32],
            amount: 5,
        },
        OpCode::SysCallDelegate {
            validator: [1u8; 32],
            amount: 5,
        },
        OpCode::SysCallUndelegate {
            validator: [1u8; 32],
        },
        OpCode::SysCallClaimRewards {
            validator: [1u8; 32],
        },
        OpCode::SysCallSubmitPriceFeed(Box::new(price_feed())),
        OpCode::SysCallRevokeSession {
            session_pubkey: [3u8; 32],
        },
        OpCode::SysCallPmmBuy { usdt_micro: 1 },
        OpCode::SysCallPmmSell { stell_nano: 1 },
        OpCode::SysCallPublishSessionGrant(Box::new(session_grant())),
        OpCode::SysCallBridge(Box::new(bridge_intent())),
        // PQ excision: confidential ops (Transfer2/Shield/Unshield) removed
        // with Ristretto — no charge to pin.
        OpCode::SysCallActorSend {
            recipient: [5u8; 32],
            value: 1,
            body: vec![OpCode::Nop],
            bounce: true,
            gas_budget: 100,
        },
    ];
    for op in ops {
        assert_charge_matches_table(op, 1_000_000_000);
    }
    // Variable-cost helpers agree with the table on several sizes.
    for len in [0usize, 1, 10, 1024] {
        let op = OpCode::SysCallDeployContract {
            code: vec![0u8; len],
        };
        assert_eq!(opcode_gas(&op), contract_deploy_gas(len));
        assert_charge_matches_table(op, 1_000_000_000);
    }
    // Halt costs nothing and still stops the program.
    let prog = vec![OpCode::Push(1), OpCode::Halt, OpCode::Push(2)];
    let mut ctx = mk_ctx(100);
    match Svm::execute(&prog, GAS_PUSH, &mut ctx) {
        VmExecutionResult::Success {
            gas_used,
            return_value,
            ..
        } => {
            assert_eq!(gas_used, GAS_PUSH + GAS_HALT);
            assert_eq!(return_value, Some(1), "ops after Halt never run");
        }
        r => panic!("halt program must succeed, got {r:?}"),
    }
}

#[test]
fn gas_used_is_exact_on_a_mixed_payload() {
    // Hand-computed: 5+5+3+20+2 | 560 | 5+10+5+3+2, stack ends [14, 0].
    let prog = vec![
        OpCode::Push(3),
        OpCode::Push(4),
        OpCode::Add,
        OpCode::LoadBalance,
        OpCode::Pop,
        OpCode::Transfer {
            recipient: [9u8; 32],
            amount: 7,
        },
        OpCode::Push(2),
        OpCode::Mul,
        OpCode::Push(14),
        OpCode::Sub,
    ];
    let want = GAS_PUSH
        + GAS_PUSH
        + GAS_ADD_SUB
        + GAS_LOAD_BALANCE
        + GAS_POP
        + GAS_BASIC_TRANSFER
        + GAS_PUSH
        + GAS_MUL_DIV
        + GAS_PUSH
        + GAS_ADD_SUB;
    assert_eq!(opcode_gas(&OpCode::Nop), GAS_NOP); // table sanity
    let mut ctx = mk_ctx(10_000);
    match Svm::execute(&prog, 1_000_000, &mut ctx) {
        VmExecutionResult::Success {
            gas_used,
            return_value,
            new_balance,
            transfers,
            ..
        } => {
            assert_eq!(
                gas_used, want,
                "deferred gas_consumed must equal the old accumulation"
            );
            assert_eq!(return_value, Some(0));
            assert_eq!(new_balance, 10_000 - 7);
            assert_eq!(transfers, vec![([9u8; 32], 7)]);
        }
        r => panic!("mixed program must succeed, got {r:?}"),
    }
    // OutOfGas lands on the exact opcode: a limit covering the first 6 ops
    // (through the transfer) dies on the 7th push with the transfer applied
    // to the mirror... and the whole run reports OutOfGas.
    let upto_transfer =
        GAS_PUSH + GAS_PUSH + GAS_ADD_SUB + GAS_LOAD_BALANCE + GAS_POP + GAS_BASIC_TRANSFER;
    let mut ctx = mk_ctx(10_000);
    let r = Svm::execute(&prog, upto_transfer + GAS_PUSH - 1, &mut ctx);
    assert!(is_oog(&r), "must die charging the 7th op, got {r:?}");
}

#[test]
fn lazy_clone_commit_is_unobservable() {
    // Same arithmetic/transfer program, once with registries wired and once
    // without: identical gas, stack, balance, transfers. (Eager cloning made
    // the wired run pay 5 clones; lazy must not change a single outcome.)
    let prog = vec![
        OpCode::Push(3),
        OpCode::Push(4),
        OpCode::Add,
        OpCode::Transfer {
            recipient: [9u8; 32],
            amount: 7,
        },
    ];
    let run = |wired: bool| {
        let mut reg = TokenRegistry::new();
        let creator = [7u8; 32];
        let id = reg
            .create_token(
                creator,
                TokenMetadata {
                    name: "T".to_string(),
                    symbol: "T".to_string(),
                    decimals: 6,
                    total_supply: 0,
                    max_supply: None,
                    minter: ZERO_ADDRESS,
                    paused: false,
                    description: String::new(),
                },
                100,
            )
            .unwrap();
        let out = {
            let mut ctx = VmContext {
                sender: [1u8; 32],
                balance: 10_000,
                orderbooks: None,
                patricia_trie: None,
                session_auth: None,
                session_keys: None,
                pmm: None,
                zkml_proof: None,
                timestamp: 1,
                trades: Vec::new(),
                transfers: Vec::new(),
                token_registry: wired.then_some(&mut reg),
                token_events: Vec::new(),
                contracts: None,
                staking: None,
                min_validator_bond: MIN_VALIDATOR_BOND,
                default_commission_bps: DEFAULT_COMMISSION_BPS,
                payouts: Vec::new(),
                oracle: None,
            };
            match Svm::execute(&prog, 1_000_000, &mut ctx) {
                VmExecutionResult::Success {
                    gas_used,
                    return_value,
                    new_balance,
                    transfers,
                    ..
                } => (gas_used, return_value, new_balance, transfers),
                r => panic!("must succeed, got {r:?}"),
            }
        };
        // The untouched registry is bit-identical afterwards (lazy never
        // cloned it, let alone wrote it back).
        assert_eq!(reg.balance_of(&id, &creator), 100);
        out
    };
    assert_eq!(run(false), run(true));
}

#[test]
fn token_atomicity_survives_lazy_cloning() {
    // A token transfer that succeeds followed by a reverting op: the registry
    // must be unchanged (working copy discarded), same as eager clone-commit.
    let mut reg = TokenRegistry::new();
    let creator = [7u8; 32];
    let id = reg
        .create_token(
            creator,
            TokenMetadata {
                name: "T".to_string(),
                symbol: "T".to_string(),
                decimals: 6,
                total_supply: 0,
                max_supply: None,
                minter: ZERO_ADDRESS,
                paused: false,
                description: String::new(),
            },
            100,
        )
        .unwrap();
    let prog = vec![
        OpCode::SysCallTokenTransfer {
            token_id: id,
            to: [8u8; 32],
            amount: 10,
        },
        OpCode::Transfer {
            recipient: [9u8; 32],
            amount: u64::MAX,
        }, // reverts: insufficient
    ];
    let mut ctx = VmContext {
        sender: creator,
        balance: 10_000,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        pmm: None,
        zkml_proof: None,
        timestamp: 1,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: Some(&mut reg),
        token_events: Vec::new(),
        contracts: None,
        staking: None,
        min_validator_bond: MIN_VALIDATOR_BOND,
        default_commission_bps: DEFAULT_COMMISSION_BPS,
        payouts: Vec::new(),
        oracle: None,
    };
    let r = Svm::execute(&prog, 1_000_000, &mut ctx);
    assert!(
        matches!(r, VmExecutionResult::Reverted(_)),
        "must revert, got {r:?}"
    );
    assert_eq!(
        reg.balance_of(&id, &creator),
        100,
        "working copy discarded on revert"
    );
    assert_eq!(reg.balance_of(&id, &[8u8; 32]), 0);
}

// --- helpers to build reverting-but-chargeable syscall operands ---
//
// Each operand only needs to EXIST: the dispatch charge runs before the
// handler, and on a bare context every handler below fails closed (no
// registry/oracle/ledger wired) AFTER the charge - which is exactly what the
// OutOfGas-vs-outcome boundary asserts.

fn price_feed() -> stellereum::oracle::PriceFeedUpdate {
    stellereum::oracle::PriceFeedUpdate {
        asset: "STELL/USD".to_string(),
        price_micro_usd: 250_000,
        timestamp: 1_700_000_000,
        publisher_pubkey: [0; 32],
        signature: vec![],
    }
}

fn session_grant() -> stellereum::zkml::SessionKeyAuthorization {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let master = SigningKey::generate(&mut OsRng);
    let session = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    stellereum::zkml::SessionKeyAuthorization::sign_delegation(
        &master,
        session,
        2_000_000_000,
        1_000_000,
        stellereum::zkml::SCOPE_ALL,
        u64::MAX,
        5757,
    )
}

fn bridge_intent() -> stellereum::bridge::BridgeIntent {
    stellereum::bridge::BridgeIntent::Release { req_id: 1 }
}
