//! Historical blockchain attack reproduction suite.
//! Every test reproduces the *class* of a famous real-world exploit against our code
//! and asserts the defense holds. Learning from other chains' mistakes.
//!
//! Covered incidents:
//!   - The DAO (2016)            reentrancy
//!   - Parity Multisig (2017)    uninitialized / takeover
//!   - BEC Token (2018)          integer overflow
//!   - ETC replay (2016)         cross-chain transaction replay
//!   - Ronin Bridge (2022)       sub-quorum / compromised validators
//!   - Wormhole (2022)           signature verification bypass
//!   - Nomad Bridge (2022)       missing / zero proof accepted
//!   - Poly Network (2021)       cross-chain message tampering
//!   - Euler Finance (2023)      donation / accounting manipulation
//!   - ERC-20 approve race       front-running allowance change
//!   - Out-of-gas griefing       state must not change on OOG
//!   - Oracle flash-loan         price manipulation
//!   - Cross-shard replay        duplicate message delivery
//!   - Timestamp manipulation    time-lock bypass

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use stellereum::bridge::{SupportedChain, TeleportBridgeEngine, TeleportDepositEvent};
use stellereum::cell::{MerkleProof, MerkleStep, PatriciaTrie};
use stellereum::oracle::OracleSafetyEngine;
use stellereum::sharding::{CrossShardMessage, SharedLiquidityHub, Transaction};
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

// ============================================================================
// THE DAO (2016, ~$60M) — REENTRANCY
// The token must not expose any callback/external-call surface during a transfer.
// We assert that a transfer mutates ONLY balances (checks-effects-interactions).
// ============================================================================
#[test]
fn the_dao_reentrancy_no_callback_surface() {
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
            amount: 500,
        },
    )
    .unwrap();
    let allowance_before = reg.get(&id).unwrap().allowance(&owner, &spender);

    // A plain transfer must not touch allowances (no re-entrant effect).
    reg.execute(
        &id,
        owner,
        TokenOp::Transfer {
            to: dest,
            amount: 100,
        },
    )
    .unwrap();

    assert_eq!(
        reg.get(&id).unwrap().allowance(&owner, &spender),
        allowance_before,
        "transfer must not mutate allowances (no reentrancy surface)"
    );
    assert_eq!(reg.balance_of(&id, &dest), 100);
}

// ============================================================================
// PARITY MULTISIG (2017, ~$150M) — UNINITIALIZED / TAKEOVER
// A contract must not be re-initializable, and authority cannot be seized.
// ============================================================================
#[test]
fn parity_uninitialized_and_takeover_rejected() {
    let mut reg = TokenRegistry::new();
    let owner = addr(1);
    let attacker = addr(9);

    let id1 = reg.create_token(owner, meta("X", "X"), 0).unwrap();
    // Same creator + metadata cannot collide (nonce prevents re-init).
    let id2 = reg.create_token(owner, meta("X", "X"), 0).unwrap();
    assert_ne!(id1, id2);

    // Attacker cannot seize minter authority.
    assert_eq!(
        reg.execute(
            &id1,
            attacker,
            TokenOp::SetMinter {
                new_minter: attacker
            }
        ),
        Err(TokenError::NotMinter)
    );
    assert_eq!(reg.get(&id1).unwrap().metadata.minter, owner);
}

// ============================================================================
// BEC TOKEN (2018) — INTEGER OVERFLOW
// Overflow in mint / arithmetic must be rejected, never wrapped.
// ============================================================================
#[test]
fn bec_integer_overflow_rejected() {
    let mut reg = TokenRegistry::new();
    let minter = addr(1);
    let mut m = meta("BEC", "BEC");
    m.max_supply = Some(u64::MAX);
    let id = reg.create_token(minter, m, u64::MAX - 5).unwrap();

    reg.execute(
        &id,
        minter,
        TokenOp::Mint {
            to: minter,
            amount: 5,
        },
    )
    .unwrap();
    assert_eq!(reg.get(&id).unwrap().metadata.total_supply, u64::MAX);

    // Next mint overflows -> rejected
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

// ============================================================================
// ETC REPLAY (2016) — CROSS-CHAIN / CROSS-SHARD TRANSACTION REPLAY
// A signature must be bound to its shard so it cannot be replayed elsewhere.
// ============================================================================
#[test]
fn etc_cross_shard_replay_rejected() {
    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, addr(2), 1_000, 560, 0, 1, 1);
    assert!(tx.verify_signature());

    // Replay on another source shard -> signature no longer valid
    let mut replayed = tx.clone();
    replayed.source_shard = 9;
    assert!(!replayed.verify_signature(), "cross-shard replay must fail");

    // Replay on another target shard
    let mut replayed2 = tx.clone();
    replayed2.target_shard = 9;
    assert!(
        !replayed2.verify_signature(),
        "cross-shard replay must fail"
    );

    // Amount tampering
    let mut replayed3 = tx.clone();
    replayed3.amount = 999_999;
    assert!(!replayed3.verify_signature(), "amount tampering must fail");
}

// ============================================================================
// RONIN BRIDGE (2022, ~$624M) — SUB-QUORUM / COMPROMISED VALIDATORS
// A bridge deposit must require a 2/3 validator quorum.
// ============================================================================
#[test]
fn ronin_bridge_subquorum_rejected() {
    let v1 = SigningKey::generate(&mut OsRng);
    let v2 = SigningKey::generate(&mut OsRng);
    let v3 = SigningKey::generate(&mut OsRng);
    let pubs = vec![
        v1.verifying_key().to_bytes(),
        v2.verifying_key().to_bytes(),
        v3.verifying_key().to_bytes(),
    ];
    let mut bridge = TeleportBridgeEngine::new(pubs.clone());

    let source_tx = [7u8; 32];
    let recipient = addr(8);
    let asset = "USDT".to_string();
    let amount = 1_000_000_000u64;

    // Sign via the canonical message (includes the chain tag since C8).
    let proto = TeleportDepositEvent {
        source_chain: SupportedChain::Ton,
        source_tx_hash: source_tx,
        recipient,
        asset: asset.clone(),
        amount,
        validator_signatures: vec![],
        zk_proof: None,
    };
    let msg = TeleportBridgeEngine::deposit_signing_message(&proto);

    // Only ONE validator signs (quorum is 2 of 3) -> must be rejected
    let sig1 = ed25519_dalek::Signer::sign(&v1, &msg);
    let event = TeleportDepositEvent {
        source_chain: SupportedChain::Ton,
        source_tx_hash: source_tx,
        recipient,
        asset: asset.clone(),
        amount,
        validator_signatures: vec![(pubs[0], sig1.to_vec())],
        zk_proof: None,
    };
    assert!(
        bridge.process_deposit(&event).is_err(),
        "sub-quorum deposit must be rejected!"
    );

    // Two validators sign -> accepted
    let sig2 = ed25519_dalek::Signer::sign(&v2, &msg);
    let event2 = TeleportDepositEvent {
        source_chain: SupportedChain::Ton,
        source_tx_hash: source_tx,
        recipient,
        asset,
        amount,
        validator_signatures: vec![(pubs[0], sig1.to_vec()), (pubs[1], sig2.to_vec())],
        zk_proof: None,
    };
    assert!(bridge.process_deposit(&event2).is_ok());
}

// ============================================================================
// WORMHOLE (2022, ~$326M) — SIGNATURE VERIFICATION BYPASS
// Signatures from non-validators must not count toward quorum.
// ============================================================================
#[test]
fn wormhole_signature_bypass_rejected() {
    let v1 = SigningKey::generate(&mut OsRng);
    let v2 = SigningKey::generate(&mut OsRng);
    let attacker = SigningKey::generate(&mut OsRng);
    let mut bridge = TeleportBridgeEngine::new(vec![
        v1.verifying_key().to_bytes(),
        v2.verifying_key().to_bytes(),
    ]);

    let source_tx = [1u8; 32];
    let recipient = addr(2);
    let asset = "TON".to_string();
    let amount = 5_000_000_000u64;

    let proto = TeleportDepositEvent {
        source_chain: SupportedChain::Ton,
        source_tx_hash: source_tx,
        recipient,
        asset: asset.clone(),
        amount,
        validator_signatures: vec![],
        zk_proof: None,
    };
    let msg = TeleportBridgeEngine::deposit_signing_message(&proto);

    // Attacker forges two "signatures" from its own key
    let forged = ed25519_dalek::Signer::sign(&attacker, &msg);
    let event = TeleportDepositEvent {
        source_chain: SupportedChain::Ton,
        source_tx_hash: source_tx,
        recipient,
        asset,
        amount,
        validator_signatures: vec![
            (attacker.verifying_key().to_bytes(), forged.to_vec()),
            (attacker.verifying_key().to_bytes(), forged.to_vec()),
        ],
        zk_proof: None,
    };
    assert!(
        bridge.process_deposit(&event).is_err(),
        "forged signatures must not count toward quorum!"
    );
}

// ============================================================================
// NOMAD BRIDGE (2022, ~$190M) — MISSING / ZERO PROOF ACCEPTED
// A cross-shard message without a valid inclusion proof must be rejected,
// regardless of the `bounce` flag.
// ============================================================================
#[test]
fn nomad_bridge_missing_proof_rejected() {
    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, addr(2), 1_000, 560, 0, 1, 2);
    let root = [0u8; 32];

    // Untrusted message with NO proof
    let msg = CrossShardMessage::new(1, 2, tx.clone(), root, [0u8; 32], None);
    assert!(
        !msg.verify_inclusion(),
        "missing proof from untrusted source must be rejected"
    );

    let mut hub = SharedLiquidityHub::new(vec![1, 2]);
    hub.route_cross_shard_message(msg);
    assert!(
        hub.take_inbound_messages(2).is_empty(),
        "message without proof must NEVER reach the target shard"
    );

    // Same, but bounce=false: must still be dropped, not routed (proof bypass)
    let msg_nb = CrossShardMessage::new(1, 2, tx, root, [0u8; 32], None);
    let mut msg_nb = msg_nb;
    msg_nb.bounce = false;
    let seq = hub.route_cross_shard_message(msg_nb);
    assert_eq!(
        seq, 0,
        "invalid non-bounceable message must not be sequenced"
    );
    assert!(
        hub.take_inbound_messages(2).is_empty(),
        "invalid message must be dropped"
    );
}

// ============================================================================
// NOMAD BRIDGE — ZERO-ROOT PROOF
// A structurally-valid proof against a zero state root must not verify.
// ============================================================================
#[test]
fn nomad_bridge_zero_root_proof_rejected() {
    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, addr(2), 1_000, 560, 0, 1, 2);

    let mut tx_bytes = Vec::new();
    tx_bytes.extend_from_slice(&tx.amount.to_be_bytes());
    tx_bytes.extend_from_slice(&tx.nonce.to_be_bytes());
    let value_hash: [u8; 32] = Sha256::digest(&tx_bytes).into();

    let zero_proof = MerkleProof {
        key: tx.from,
        value_hash,
        leaf_hash: [0u8; 32],
        path: vec![MerkleStep {
            sibling_is_right: false,
            sibling_hash: [0u8; 32],
            branch_prefix: [0u8; 16],
            skip: 0,
            branch_bit: 0,
        }],
    };
    let msg = CrossShardMessage::new(1, 2, tx, [0u8; 32], [0u8; 32], Some(zero_proof));
    assert!(!msg.verify_inclusion(), "zero-root proof must not verify");
}

// ============================================================================
// POLY NETWORK (2021, ~$611M) — CROSS-CHAIN MESSAGE TAMPERING
// Tampering with the tx inside a cross-shard message invalidates the proof.
// ============================================================================
#[test]
fn poly_network_cross_chain_tampering_rejected() {
    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, addr(2), 1_000, 560, 0, 1, 2);
    let source_balance = 5_000u64; // enough to cover tx.amount

    // Build a real source state root containing the sender's account leaf
    // (balance || nonce) — the same encoding the state engine uses.
    let mut trie = PatriciaTrie::new();
    let mut account_bytes = Vec::new();
    account_bytes.extend_from_slice(&source_balance.to_be_bytes());
    account_bytes.extend_from_slice(&tx.nonce.to_be_bytes());
    trie.insert(&tx.from, &account_bytes);
    let root = trie.root_hash();
    let proof = trie.generate_merkle_proof(&tx.from).unwrap();

    let msg = CrossShardMessage::new(1, 2, tx.clone(), root, [0u8; 32], Some(proof.clone()))
        .with_source_balance(source_balance);
    assert!(msg.verify_inclusion(), "genuine message must verify");

    // Attacker inflates the amount beyond the proven balance, keeping the proof.
    let mut tampered_tx = tx.clone();
    tampered_tx.amount = source_balance + 1;
    let tampered = CrossShardMessage::new(1, 2, tampered_tx, root, [0u8; 32], Some(proof))
        .with_source_balance(source_balance);
    assert!(
        !tampered.verify_inclusion(),
        "inflated amount must fail the balance check"
    );
}

// ============================================================================
// EULER FINANCE (2023, ~$197M) — DONATION / ACCOUNTING MANIPULATION
// Transfers must never change total supply (accounting is invariant).
// ============================================================================
#[test]
fn euler_donation_does_not_break_accounting() {
    let mut reg = TokenRegistry::new();
    let a = addr(1);
    let b = addr(2);
    let id = reg.create_token(a, meta("T", "T"), 1_000_000).unwrap();
    let supply = reg.get(&id).unwrap().metadata.total_supply;

    // Many "donation" style transfers in a loop
    for _ in 0..100 {
        let _ = reg.execute(&id, a, TokenOp::Transfer { to: b, amount: 1 });
        let _ = reg.execute(&id, b, TokenOp::Transfer { to: a, amount: 1 });
    }
    assert_eq!(
        reg.get(&id).unwrap().metadata.total_supply,
        supply,
        "transfers must not create or destroy supply (donation attack immune)"
    );
}

// ============================================================================
// ERC-20 APPROVE RACE — FRONT-RUNNING ALLOWANCE CHANGE
// Safe increase/decrease helpers close the race window.
// ============================================================================
#[test]
fn erc20_approve_race_safe_helpers() {
    let mut reg = TokenRegistry::new();
    let owner = addr(1);
    let spender = addr(2);
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
    // Safe decrease instead of raw approve
    reg.execute(
        &id,
        owner,
        TokenOp::DecreaseAllowance { spender, delta: 60 },
    )
    .unwrap();
    assert_eq!(reg.get(&id).unwrap().allowance(&owner, &spender), 40);
    // Underflow protected
    assert_eq!(
        reg.execute(
            &id,
            owner,
            TokenOp::DecreaseAllowance { spender, delta: 41 }
        ),
        Err(TokenError::AllowanceUnderflow)
    );
}

// ============================================================================
// OUT-OF-GAS GRIEFING — STATE MUST NOT CHANGE ON OOG
// ============================================================================
#[test]
fn out_of_gas_does_not_commit_token_changes() {
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
        timestamp: 1,
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

    // Transfer (560 gas) then spam Nops to exhaust the 600 gas budget
    let mut ops = vec![OpCode::SysCallTokenTransfer {
        token_id: id,
        to: bob,
        amount: 400,
    }];
    ops.extend(std::iter::repeat_n(OpCode::Nop, 100));

    let res = Svm::execute(&ops, 600, &mut ctx);
    assert!(matches!(res, VmExecutionResult::OutOfGas));
    assert_eq!(
        registry.balance_of(&id, &alice),
        1_000,
        "OOG must not move tokens"
    );
    assert_eq!(registry.balance_of(&id, &bob), 0);
}

// ============================================================================
// UNBOUNDED OP DoS — must terminate cleanly, never panic
// ============================================================================
#[test]
fn unbounded_ops_dos_no_panic() {
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
        timestamp: 1,
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
    let ops: Vec<OpCode> = std::iter::repeat_n(OpCode::Nop, 1_000_000).collect();
    let res = Svm::execute(&ops, 1_000, &mut ctx);
    assert!(
        matches!(res, VmExecutionResult::OutOfGas),
        "huge op list must OOG cleanly"
    );
}

// ============================================================================
// ORACLE FLASH-LOAN MANIPULATION & NO-SOURCE
// ============================================================================
#[test]
fn oracle_flashloan_and_no_source_rejected() {
    // No trusted publisher and no TWAP -> no price source at all
    let mut oracle = OracleSafetyEngine::new(vec![]);
    assert!(
        oracle.resolve_price(None, "TON", 1_000).is_err(),
        "oracle with no source must not invent a price"
    );

    // With a trusted oracle and a TWAP baseline, a signed 20% manipulated spike
    // must trip the circuit breaker.
    let oracle_sk = SigningKey::generate(&mut OsRng);
    let oracle_pub = oracle_sk.verifying_key().to_bytes();
    let mut oracle2 = OracleSafetyEngine::new(vec![oracle_pub]);
    oracle2.set_dex_twap("TON", 5_000_000);
    let feed = stellereum::oracle::PriceFeedUpdate::sign("TON", 6_000_000, 1_000, &oracle_sk); // +20%
    assert!(
        oracle2.resolve_price(Some(&feed), "TON", 1_000).is_err(),
        "20% deviation must trip the circuit breaker"
    );
    assert!(oracle2.circuit_breaker_triggered);

    // A forged (unsigned) feed is ignored and falls back to TWAP (not an exploit).
    let mut oracle3 = OracleSafetyEngine::new(vec![]);
    oracle3.set_dex_twap("TON", 5_000_000);
    let forged = stellereum::oracle::PriceFeedUpdate {
        asset: "TON".to_string(),
        price_micro_usd: 99_000_000,
        timestamp: 1_000,
        publisher_pubkey: [0u8; 32],
        signature: vec![],
    };
    assert_eq!(
        oracle3.resolve_price(Some(&forged), "TON", 1_000).unwrap(),
        5_000_000,
        "forged feed must be ignored; TWAP is used instead"
    );
}

// ============================================================================
// SIGNATURE CORRUPTION — a single flipped byte must invalidate the signature
// ============================================================================
#[test]
fn corrupted_signature_rejected() {
    let sk = SigningKey::generate(&mut OsRng);
    let mut tx = Transaction::sign(&sk, addr(2), 1_000, 560, 0, 1, 1);
    assert!(tx.verify_signature());
    tx.signature[0] ^= 0x01;
    assert!(
        !tx.verify_signature(),
        "corrupted signature must be rejected"
    );
}

// ============================================================================
// CROSS-SHARD REPLAY — duplicate delivery must be blocked
// ============================================================================
#[test]
fn cross_shard_replay_dedup() {
    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, addr(2), 1_000, 560, 0, 1, 2);
    let msg = CrossShardMessage::new_trusted(1, 2, tx, [0u8; 32], [0u8; 32]);

    let mut hub = SharedLiquidityHub::new(vec![1, 2]);
    let seq1 = hub.route_cross_shard_message(msg.clone());
    let seq2 = hub.route_cross_shard_message(msg.clone()); // replay
    assert!(seq1 > 0);
    assert_eq!(seq2, 0, "replayed cross-shard message must be rejected");
    assert_eq!(
        hub.take_inbound_messages(2).len(),
        1,
        "message must be delivered exactly once"
    );
}

// ============================================================================
// BRIDGE DEPOSIT REPLAY — same source tx cannot be processed twice
// ============================================================================
#[test]
fn bridge_deposit_replay_rejected() {
    let v = SigningKey::generate(&mut OsRng);
    let pubk = v.verifying_key().to_bytes();
    let mut bridge = TeleportBridgeEngine::new(vec![pubk]);

    let source_tx = [3u8; 32];
    let recipient = addr(4);
    let asset = "USDT".to_string();
    let amount = 1_000_000u64;

    let proto = TeleportDepositEvent {
        source_chain: SupportedChain::Ton,
        source_tx_hash: source_tx,
        recipient,
        asset: asset.clone(),
        amount,
        validator_signatures: vec![],
        zk_proof: None,
    };
    let msg = TeleportBridgeEngine::deposit_signing_message(&proto);
    let sig = ed25519_dalek::Signer::sign(&v, &msg);

    let event = TeleportDepositEvent {
        source_chain: SupportedChain::Ton,
        source_tx_hash: source_tx,
        recipient,
        asset,
        amount,
        validator_signatures: vec![(pubk, sig.to_vec())],
        zk_proof: None,
    };

    assert!(bridge.process_deposit(&event).is_ok());
    // Replay of the SAME source tx hash must be rejected
    assert!(
        bridge.process_deposit(&event).is_err(),
        "bridge deposit replay must be rejected"
    );
}

// ============================================================================
// TIMESTAMP MANIPULATION — time-lock boundary is exact
// ============================================================================
#[test]
fn timestamp_manipulation_timelock_boundary() {
    let v = SigningKey::generate(&mut OsRng);
    let mut bridge = TeleportBridgeEngine::new(vec![v.verifying_key().to_bytes()]);
    let now = 1_000u64;
    let large = 60_000 * 1_000_000_000; // > 50k STELL threshold -> 1h lock

    let req_id = bridge
        .request_withdrawal(
            addr(1),
            SupportedChain::Arbitrum,
            "0xabc".to_string(),
            large,
            now,
        )
        .unwrap();

    // One second before unlock -> rejected
    assert!(bridge.finalize_withdrawal(req_id, now + 3_599).is_err());
    // Exactly at unlock -> accepted
    assert!(bridge.finalize_withdrawal(req_id, now + 3_600).is_ok());
}

// ============================================================================
// MALFORMED INPUT — garbage bytes must fail deserialization safely
// ============================================================================
#[test]
fn malformed_input_deserialization_safe() {
    let bad = bincode::deserialize::<Transaction>(&[0xFF, 0x00, 0x01, 0x02]);
    assert!(
        bad.is_err(),
        "garbage must not deserialize into a Transaction"
    );

    let bad2 = bincode::deserialize::<TokenRegistry>(&[0x00]);
    assert!(
        bad2.is_err(),
        "garbage must not deserialize into a TokenRegistry"
    );
}

// ============================================================================
// UNCHECKED RETURN — API must surface failures, never fail silently
// ============================================================================
#[test]
fn unchecked_return_no_silent_failure() {
    let mut reg = TokenRegistry::new();
    let a = addr(1);
    let id = reg.create_token(a, meta("T", "T"), 100).unwrap();
    // Attempting to move more than the balance must return an explicit error
    let res = reg.execute(
        &id,
        a,
        TokenOp::Transfer {
            to: addr(2),
            amount: 1_000,
        },
    );
    assert_eq!(res, Err(TokenError::InsufficientBalance));
}
