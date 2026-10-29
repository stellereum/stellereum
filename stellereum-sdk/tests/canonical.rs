//! Byte-equality proof: every SDK shape produces the exact wire bytes a
//! hand-built node transaction produces (same constructors, same fields).
//!
//! Ed25519 signatures are deterministic, so all five shapes assert full
//! `to_bytes()` equality. Falcon-512/Hybrid signatures are RANDOMIZED (FIPS 206
//! sampler), so those schemes assert sign+verify round trips, chain binding
//! and field wiring instead of byte equality.

use ed25519_dalek::SigningKey;
use stellereum::contract_abi::{AbiMethod, AbiParam, AbiType, AbiValue, ContractAbi};
use stellereum::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};
use stellereum::sharding::Transaction;
use stellereum::svm::{opcode_gas, OpCode, GAS_BASIC_TRANSFER};
use stellereum_sdk::{
    predict_contract_address, FeeEstimate, SdkKey, SignedTx, TxBuilder, SDK_DEFAULT_CHAIN_ID,
};

const CHAIN: u64 = SDK_DEFAULT_CHAIN_ID;
const SEED: [u8; 32] = [0x42u8; 32];
const FALCON_SEED: [u8; 32] = [0x77u8; 32];

fn ed_key() -> SdkKey {
    SdkKey::ed25519(SEED)
}

fn ed_signing_key() -> SigningKey {
    SigningKey::from_bytes(&SEED)
}

fn ed_addr() -> [u8; 32] {
    ed_signing_key().verifying_key().to_bytes()
}

fn hand_ed(to: [u8; 32], amount: u64, gas: u64, nonce: u64, payload: Vec<OpCode>) -> Transaction {
    Transaction::sign_with_payload_and_chain_id(
        &ed_signing_key(),
        to,
        amount,
        gas,
        nonce,
        0,
        0,
        payload,
        CHAIN,
    )
}

fn assert_canonical(sdk_tx: &SignedTx, hand_tx: &Transaction, shape: &str) {
    let a = sdk_tx.to_bytes();
    let b = bincode::serialize(hand_tx).unwrap();
    assert_eq!(a, b, "{shape}: SDK bytes differ from hand-built node bytes");
    assert_eq!(
        sdk_tx.tx_hash(),
        hand_tx.compute_tx_hash(),
        "{shape}: tx hash differs"
    );
    assert!(sdk_tx.verify(), "{shape}: SDK tx does not verify");
    assert!(
        hand_tx.verify_signature(),
        "{shape}: hand-built tx does not verify"
    );
}

// --- shape 1: transfer ------------------------------------------------------

#[test]
fn transfer_is_byte_equal_to_hand_built() {
    let to = [0x99u8; 32];
    let sdk = TxBuilder::transfer(to, 1_000)
        .nonce(5)
        .sign(&ed_key())
        .unwrap();
    let hand = hand_ed(to, 1_000, GAS_BASIC_TRANSFER, 5, vec![]);
    assert_canonical(&sdk, &hand, "transfer");
    assert!(sdk.is_bound() && sdk.chain_id() == Some(CHAIN));
}

// --- shape 2: token ops -----------------------------------------------------

#[test]
fn token_transfer_is_byte_equal_to_hand_built() {
    let token = [0x11u8; 32];
    let to = [0x22u8; 32];
    let op = OpCode::SysCallTokenTransfer {
        token_id: token,
        to,
        amount: 250,
    };
    let sdk = TxBuilder::token_transfer(token, to, 250)
        .nonce(7)
        .sign(&ed_key())
        .unwrap();
    let hand = hand_ed(ed_addr(), 0, opcode_gas(&op), 7, vec![op]);
    assert_canonical(&sdk, &hand, "token_transfer");
}

#[test]
fn token_approve_and_transfer_from_are_byte_equal() {
    let token = [0x11u8; 32];
    let spender = [0x33u8; 32];
    let op = OpCode::SysCallTokenApprove {
        token_id: token,
        spender,
        amount: 500,
    };
    let sdk = TxBuilder::token_approve(token, spender, 500)
        .sign(&ed_key())
        .unwrap();
    let hand = hand_ed(ed_addr(), 0, opcode_gas(&op), 0, vec![op]);
    assert_canonical(&sdk, &hand, "token_approve");

    let from = [0x44u8; 32];
    let to = [0x55u8; 32];
    let op2 = OpCode::SysCallTokenTransferFrom {
        token_id: token,
        from,
        to,
        amount: 100,
    };
    let sdk2 = TxBuilder::token_transfer_from(token, from, to, 100)
        .sign(&ed_key())
        .unwrap();
    let hand2 = hand_ed(ed_addr(), 0, opcode_gas(&op2), 0, vec![op2]);
    assert_canonical(&sdk2, &hand2, "token_transfer_from");
}

// --- shape 3: staking -------------------------------------------------------

#[test]
fn stake_bond_delegate_undelegate_are_byte_equal() {
    let val = [0x66u8; 32];

    let op = OpCode::SysCallStake {
        validator: val,
        amount: 10_000,
    };
    let sdk = TxBuilder::stake_bond(val, 10_000)
        .nonce(1)
        .sign(&ed_key())
        .unwrap();
    assert_canonical(
        &sdk,
        &hand_ed(ed_addr(), 0, opcode_gas(&op), 1, vec![op]),
        "stake_bond",
    );

    let op = OpCode::SysCallDelegate {
        validator: val,
        amount: 5_000,
    };
    let sdk = TxBuilder::delegate(val, 5_000)
        .nonce(2)
        .sign(&ed_key())
        .unwrap();
    assert_canonical(
        &sdk,
        &hand_ed(ed_addr(), 0, opcode_gas(&op), 2, vec![op]),
        "delegate",
    );

    let op = OpCode::SysCallBeginUndelegate {
        validator: val,
        amount: 5_000,
    };
    let sdk = TxBuilder::begin_undelegate(val, 5_000)
        .nonce(3)
        .sign(&ed_key())
        .unwrap();
    assert_canonical(
        &sdk,
        &hand_ed(ed_addr(), 0, opcode_gas(&op), 3, vec![op]),
        "begin_undelegate",
    );

    let op = OpCode::SysCallUndelegate { validator: val };
    let sdk = TxBuilder::undelegate_withdraw(val)
        .nonce(4)
        .sign(&ed_key())
        .unwrap();
    assert_canonical(
        &sdk,
        &hand_ed(ed_addr(), 0, opcode_gas(&op), 4, vec![op]),
        "undelegate_withdraw",
    );
}

// --- shape 4: contract deploy -----------------------------------------------

#[test]
fn contract_deploy_is_byte_equal_and_address_uses_node_function() {
    let code = vec![0x00u8, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let op = OpCode::SysCallDeployContract { code: code.clone() };
    let sdk = TxBuilder::contract_deploy(code.clone())
        .nonce(9)
        .sign(&ed_key())
        .unwrap();
    assert_canonical(
        &sdk,
        &hand_ed(ed_addr(), 0, opcode_gas(&op), 9, vec![op]),
        "contract_deploy",
    );

    // The SDK predicts the deploy address with the node's own function
    // (imported, not reimplemented): sender + sender-nonce.
    let predicted = predict_contract_address(&ed_addr(), 9);
    let direct = stellereum::contract::contract_address(&ed_addr(), 9);
    assert_eq!(
        predicted, direct,
        "deploy address must be the node's function"
    );
    assert_eq!(predicted, direct);
}

// --- shape 5: contract call --------------------------------------------------

fn sample_abi() -> ContractAbi {
    let mut abi = ContractAbi::new();
    abi.add_method(AbiMethod::mutating(
        "transfer",
        vec![
            AbiParam::new("to", AbiType::Address),
            AbiParam::new("amount", AbiType::U64),
            AbiParam::new("memo", AbiType::String),
        ],
        AbiType::Bool,
    ));
    abi
}

#[test]
fn contract_call_is_byte_equal_with_abi_calldata() {
    let abi = sample_abi();
    let contract = [0xABu8; 32];
    let args = vec![
        AbiValue::Address([0x01u8; 32]),
        AbiValue::U64(1234),
        AbiValue::String("memo".to_string()),
    ];
    let sdk = TxBuilder::contract_call(contract, "transfer", &abi, &args, 0)
        .unwrap()
        .nonce(3)
        .sign(&ed_key())
        .unwrap();

    // Hand-built exactly the way `stell_callContract` (src/rpc.rs) builds it:
    // scalars = as_i64, calldata = abi.encode_args.
    let calldata = abi.encode_args("transfer", &args).unwrap();
    let scalars: Vec<i64> = args.iter().map(|v| v.as_i64().unwrap_or(0)).collect();
    let op = OpCode::SysCallCallContractArgs {
        contract,
        method: b"transfer".to_vec(),
        args: scalars,
        calldata: calldata.clone(),
    };
    let hand = Transaction::sign_with_payload_and_chain_id(
        &ed_signing_key(),
        contract,
        0,
        opcode_gas(&op),
        3,
        0,
        0,
        vec![op],
        CHAIN,
    );
    assert_canonical(&sdk, &hand, "contract_call");

    // The calldata on the wire IS the ABI encoding.
    match &sdk.as_node_tx().payload[0] {
        OpCode::SysCallCallContractArgs { calldata: c, .. } => assert_eq!(c, &calldata),
        other => panic!("wrong opcode: {other:?}"),
    }
}

// --- bound by default / unbound escape ---------------------------------------

#[test]
fn bound_by_default_and_unbound_escape_warns() {
    for b in [
        TxBuilder::transfer([1u8; 32], 1),
        TxBuilder::token_transfer([2u8; 32], [3u8; 32], 1),
        TxBuilder::token_approve([2u8; 32], [3u8; 32], 1),
        TxBuilder::stake_bond([4u8; 32], 1),
        TxBuilder::delegate([4u8; 32], 1),
        TxBuilder::contract_deploy(vec![0x00]),
    ] {
        assert!(b.is_bound(), "every builder must be bound by default");
        let signed = b.sign(&ed_key()).unwrap();
        assert_eq!(signed.chain_id(), Some(CHAIN));
        assert!(signed.as_node_tx().is_chain_id_bound());
    }

    // The escape hatch: unbound, still validly signed, but refused when the
    // node eventually requires chain binding (phase 3 of the A14 rollout).
    let legacy = TxBuilder::transfer([1u8; 32], 1)
        .unbound_legacy()
        .sign(&ed_key())
        .unwrap();
    assert!(!legacy.is_bound());
    assert_eq!(legacy.chain_id(), None);
    assert!(!legacy.as_node_tx().is_chain_id_bound());
    assert!(
        legacy.as_node_tx().verify_signature(),
        "legacy sig must still verify"
    );
    assert!(
        !legacy.as_node_tx().verify_signature_for_chain(CHAIN, true),
        "unbound tx must fail the strict chain check"
    );
}

// --- fee-estimate param shape matches node expectation -----------------------

#[test]
fn fee_estimate_params_match_node_expectation() {
    let sdk = TxBuilder::transfer([9u8; 32], 42).sign(&ed_key()).unwrap();
    let params = sdk.fee_estimate_params();
    // Exactly {"tx": "<hex>"}: the raw-transaction arm of handle_estimate_fee
    // (src/rpc.rs) reads params["tx"] as a string, hex-decodes it and
    // bincode-decodes a Transaction. Mirror that decode here.
    assert_eq!(params.as_object().unwrap().len(), 1);
    let hex_tx = params["tx"].as_str().expect("params.tx must be a string");
    let bytes = hex::decode(hex_tx.strip_prefix("0x").unwrap_or(hex_tx)).unwrap();
    let decoded: Transaction = bincode::deserialize(&bytes).unwrap();
    assert_eq!(decoded.compute_tx_hash(), sdk.tx_hash());

    // The node's documented answer shape parses (docs/RPC.md §4 + the
    // test_estimate_fee_* vectors: numbers, not strings, for these fields).
    let sample = serde_json::json!({
        "gas_limit": 280000u64,
        "estimated_fee": 280000u64,
        "base_fee": 280000u64,
        "source_shard": 0u64,
        "target_shard": 0u64,
        "is_cross_shard": false,
        "status": "ok"
    });
    let est = FeeEstimate::from_json(&sample).unwrap();
    assert_eq!(est.gas_limit, 280_000);
    assert_eq!(est.estimated_fee, 280_000);
    assert!(!est.is_cross_shard);

    // Submit body shape: {"tx": hex} is what stell_sendRawTransaction reads
    // (src/rpc.rs dispatch: params["tx"].as_str(), "missing tx" otherwise).
    let submit_params = serde_json::json!({ "tx": sdk.to_hex() });
    assert!(submit_params["tx"].as_str().is_some());
}

// --- sign + verify round trip per scheme -------------------------------------

#[test]
fn sign_verify_round_trip_ed25519() {
    let key = SdkKey::ed25519([0x11u8; 32]);
    for bound in [true, false] {
        let mut b = TxBuilder::transfer([0x22u8; 32], 77);
        if !bound {
            b = b.unbound_legacy();
        }
        let tx = b.sign(&key).unwrap();
        assert_eq!(tx.is_bound(), bound);
        assert!(tx.verify());
        assert!(tx.as_node_tx().verify_signature());
    }
}

#[test]
fn sign_verify_round_trip_falcon512() {
    let key = SdkKey::falcon_from_seed(FALCON_SEED);
    assert_eq!(
        key.address(),
        derive_pq_address(PqScheme::Falcon512, &key.pubkey_bytes(), &DEFAULT_SALT)
    );
    for bound in [true, false] {
        let mut b = TxBuilder::token_transfer([0x31u8; 32], [0x32u8; 32], 10).nonce(1);
        if !bound {
            b = b.unbound_legacy();
        }
        let tx = b.sign(&key).unwrap();
        assert_eq!(tx.is_bound(), bound);
        assert!(tx.verify(), "falcon tx must verify (bound={bound})");
        assert!(tx.as_node_tx().is_pq());
        if bound {
            assert!(tx.as_node_tx().verify_signature_for_chain(CHAIN, true));
            assert!(!tx.as_node_tx().verify_signature_for_chain(CHAIN + 1, true));
        }
    }
}

#[test]
fn sign_verify_round_trip_hybrid() {
    let key = SdkKey::hybrid(SEED, FALCON_SEED);
    assert_eq!(
        key.address(),
        derive_pq_address(PqScheme::Hybrid, &key.pubkey_bytes(), &DEFAULT_SALT)
    );
    let tx = TxBuilder::stake_bond([0x61u8; 32], 1_000)
        .sign(&key)
        .unwrap();
    assert!(tx.verify(), "hybrid tx must verify");
    assert_eq!(tx.chain_id(), Some(CHAIN));

    // Tampering with a single byte of the payload breaks the signature.
    let mut raw = tx.to_bytes();
    raw[40] ^= 0x01;
    let bad: Transaction = bincode::deserialize(&raw).unwrap();
    assert!(!bad.verify_signature(), "tampered tx must not verify");
}

#[test]
fn default_chain_id_is_the_node_chain_id() {
    assert_eq!(SDK_DEFAULT_CHAIN_ID, 5757);
    assert_eq!(SDK_DEFAULT_CHAIN_ID, stellereum::zkml::DEFAULT_CHAIN_ID);
}
