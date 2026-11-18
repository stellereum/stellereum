//! Byte-for-byte parity with the node crate.
//!
//! Run with `cargo test --features node-parity`. The node crate is an
//! optional dependency so the default client build stays thin.
#![cfg(feature = "node-parity")]

use stellereum_sdk::address;
use stellereum_sdk::key::{FalconKeypair, FALCON512_SIG_LEN};
use stellereum_sdk::opcode::{encode_calldata, CallArg};
use stellereum_sdk::session::{SessionGrant, SCOPE_ALL};
use stellereum_sdk::tx::{SignedTx, TxBuilder, DEFAULT_CHAIN_ID, PQ_ACTIVATION_SURCHARGE_GAS};

use stellereum::post_quantum::{derive_pq_address, verify_pq_signature, PqScheme, DEFAULT_SALT};
use stellereum::sharding::Transaction as NodeTransaction;
use stellereum::svm::OpCode as NodeOpCode;

fn node_tx(signed: &SignedTx) -> NodeTransaction {
    bincode::deserialize(&signed.to_bytes()).expect("node must decode the SDK's bytes")
}

#[test]
fn signature_verifies_with_node_verify_pq_signature() {
    let key = FalconKeypair::generate().unwrap();
    let msg = b"parity: node verifier must accept the SDK signature";
    let sig = key.sign(msg).unwrap();
    assert_eq!(sig.len(), FALCON512_SIG_LEN);
    assert!(
        verify_pq_signature(PqScheme::Falcon512, key.public_key(), msg, &sig),
        "node verify_pq_signature refused the SDK's Falcon-512 signature"
    );
}

#[test]
fn address_derives_to_node_derive_pq_address() {
    let key = FalconKeypair::generate().unwrap();
    assert_eq!(
        key.address(),
        derive_pq_address(PqScheme::Falcon512, key.public_key(), &DEFAULT_SALT)
    );
}

#[test]
fn stl57_matches_node_encoder_and_parser() {
    let addr = [0x5Au8; 32];
    let sdk = address::encode_stl57(&addr);
    let node = stellereum::address::encode_stl57_address(&addr);
    assert_eq!(sdk, node);
    assert_eq!(
        address::parse_address(&node).unwrap(),
        stellereum::address::parse_address(&node).unwrap()
    );
}

#[test]
fn transfer_decodes_and_verifies_in_node() {
    let key = FalconKeypair::generate().unwrap();
    let signed = TxBuilder::transfer([0x22u8; 32], 12_345)
        .nonce(9)
        .sign(&key)
        .unwrap();
    let tx = node_tx(&signed);
    assert_eq!(tx.from, key.address());
    assert_eq!(tx.to, [0x22u8; 32]);
    assert_eq!(tx.amount, 12_345);
    assert_eq!(tx.nonce, 9);
    assert_eq!(tx.gas_limit, signed.gas_limit());
    assert_eq!(tx.chain_id(), Some(DEFAULT_CHAIN_ID));
    assert!(tx.is_pq_activation());
    assert!(
        tx.verify_signature(),
        "node verify_signature refused the SDK tx"
    );
    assert_eq!(tx.compute_tx_hash(), signed.tx_hash());
}

#[test]
fn implicit_transfer_verifies_in_node_registry() {
    let key = FalconKeypair::generate().unwrap();
    let signed = TxBuilder::transfer([0x33u8; 32], 7)
        .nonce(1)
        .implicit()
        .sign(&key)
        .unwrap();
    assert!(!signed.is_pq_activation());
    let tx = node_tx(&signed);
    assert!(tx.is_pq_implicit());
    assert_eq!(tx.chain_id(), Some(DEFAULT_CHAIN_ID));

    let registry = stellereum::post_quantum::StatefulImplicitKeyRegistry::new();
    registry
        .register(
            key.address(),
            PqScheme::Falcon512,
            key.public_key(),
            &DEFAULT_SALT,
        )
        .unwrap();
    assert!(
        tx.verify_signature_with_registry(&registry),
        "node refused the implicit envelope even with the key registered"
    );
    assert_eq!(tx.compute_tx_hash(), signed.tx_hash());
}

#[test]
fn unbound_envelope_has_no_chain_id() {
    let key = FalconKeypair::generate().unwrap();
    let signed = TxBuilder::transfer([0x44u8; 32], 1)
        .nonce(2)
        .unbound()
        .sign(&key)
        .unwrap();
    let tx = node_tx(&signed);
    assert_eq!(tx.chain_id(), None);
    assert!(tx.verify_signature());
}

#[test]
fn stake_payload_matches_node_bincode() {
    let key = FalconKeypair::generate().unwrap();
    let validator = [0x66u8; 32];
    let signed = TxBuilder::stake(validator, 5_000_000)
        .nonce(3)
        .sign(&key)
        .unwrap();
    let expected = bincode::serialize(&vec![NodeOpCode::SysCallStake {
        validator,
        amount: 5_000_000,
    }])
    .unwrap();
    assert_eq!(signed.transaction().payload, expected);
    let tx = node_tx(&signed);
    assert!(tx.verify_signature());
    assert_eq!(tx.payload.len(), 1);
    assert_eq!(tx.compute_tx_hash(), signed.tx_hash());
}

#[test]
fn unjail_payload_matches_node_bincode_with_and_without_top_up() {
    let key = FalconKeypair::generate().unwrap();
    let validator = [0x77u8; 32];

    let signed = TxBuilder::unjail(validator, None)
        .nonce(4)
        .sign(&key)
        .unwrap();
    let expected = bincode::serialize(&vec![NodeOpCode::SysCallUnjail { validator }]).unwrap();
    assert_eq!(signed.transaction().payload, expected);

    let signed = TxBuilder::unjail(validator, Some(9_000))
        .nonce(5)
        .sign(&key)
        .unwrap();
    let expected = bincode::serialize(&vec![
        NodeOpCode::SysCallStake {
            validator,
            amount: 9_000,
        },
        NodeOpCode::SysCallUnjail { validator },
    ])
    .unwrap();
    assert_eq!(signed.transaction().payload, expected);
    assert_eq!(node_tx(&signed).compute_tx_hash(), signed.tx_hash());
}

#[test]
fn contract_call_payload_matches_node_bincode_and_abi_encoder() {
    let key = FalconKeypair::generate().unwrap();
    let contract = [0x88u8; 32];
    let args = vec![
        CallArg::U64(7),
        CallArg::Bool(true),
        CallArg::String("hello".into()),
        CallArg::Address([0x01u8; 32]),
    ];
    let signed = TxBuilder::contract_call(contract, "sum3", &args, 42)
        .unwrap()
        .nonce(6)
        .sign(&key)
        .unwrap();

    let manifest = stellereum::contract_abi::ContractAbi::from_json(
        r#"{"methods":[{"name":"sum3","params":[
            {"name":"a","type":"u64"},
            {"name":"b","type":"bool"},
            {"name":"c","type":"string"},
            {"name":"d","type":"address"}],"returns":"u64"}]}"#,
    )
    .unwrap();
    let node_calldata = manifest
        .encode_args(
            "sum3",
            &[
                stellereum::contract_abi::AbiValue::U64(7),
                stellereum::contract_abi::AbiValue::Bool(true),
                stellereum::contract_abi::AbiValue::String("hello".into()),
                stellereum::contract_abi::AbiValue::Address([0x01u8; 32]),
            ],
        )
        .unwrap();
    assert_eq!(encode_calldata(&args).unwrap(), node_calldata);

    let expected = bincode::serialize(&vec![NodeOpCode::SysCallCallContractArgs {
        contract,
        method: b"sum3".to_vec(),
        args: vec![7, 1, 0, 0],
        calldata: node_calldata,
    }])
    .unwrap();
    assert_eq!(signed.transaction().payload, expected);
    let tx = node_tx(&signed);
    assert_eq!(tx.amount, 42);
    assert_eq!(tx.to, contract);
    assert!(tx.verify_signature());
    assert_eq!(tx.compute_tx_hash(), signed.tx_hash());
}

#[test]
fn session_grant_and_sf1_tx_verify_in_node() {
    let master = FalconKeypair::generate().unwrap();
    let session = FalconKeypair::generate().unwrap();
    let grant = SessionGrant::new(
        &master,
        session.public_key(),
        4_000_000_000,
        100_000_000,
        SCOPE_ALL,
        1_000_000,
        DEFAULT_CHAIN_ID,
    )
    .unwrap();

    // Grant bytes decode into the node's own struct and its own verifier.
    let node_grant: stellereum::zkml::SessionKeyAuthorization =
        bincode::deserialize(&grant.encode()).expect("node must decode the grant");
    assert!(node_grant.verify_signature());

    let signed = TxBuilder::transfer([0x99u8; 32], 55)
        .nonce(12)
        .sign_with_session(&session, &grant)
        .unwrap();
    let tx = node_tx(&signed);
    assert_eq!(tx.from, master.address());
    assert_eq!(tx.chain_id(), Some(DEFAULT_CHAIN_ID));
    assert!(tx.is_session_keyed());
    assert!(
        tx.verify_signature(),
        "node verify_signature refused the SDK's SF1 transaction"
    );
    assert_eq!(tx.compute_tx_hash(), signed.tx_hash());
}

#[test]
fn fee_default_is_node_floor_plus_surcharge() {
    let key = FalconKeypair::generate().unwrap();
    let signed = TxBuilder::transfer([0xAAu8; 32], 1)
        .nonce(0)
        .sign(&key)
        .unwrap();
    let floor = stellereum::mempool::Mempool::frozen_base_fee_floor()
        + stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
    assert_eq!(signed.gas_limit(), floor);
    assert_eq!(
        stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS,
        PQ_ACTIVATION_SURCHARGE_GAS
    );

    let implicit = TxBuilder::transfer([0xAAu8; 32], 1)
        .nonce(1)
        .implicit()
        .sign(&key)
        .unwrap();
    assert_eq!(
        implicit.gas_limit(),
        stellereum::mempool::Mempool::frozen_base_fee_floor()
    );
}

#[test]
fn chain_binding_is_enforced_by_node_verifier() {
    let key = FalconKeypair::generate().unwrap();
    let signed = TxBuilder::transfer([0xCCu8; 32], 1)
        .nonce(3)
        .chain_id(5757)
        .sign(&key)
        .unwrap();
    let tx = node_tx(&signed);
    assert_eq!(tx.chain_id(), Some(5757));
    assert!(tx.verify_signature_for_chain(5757, true));
    assert!(
        !tx.verify_signature_for_chain(5758, true),
        "a foreign chain id must be refused even though the signature is valid"
    );
}

#[test]
fn priority_bid_is_signed_and_hashed_like_node() {
    let key = FalconKeypair::generate().unwrap();
    let signed = TxBuilder::transfer([0xBBu8; 32], 1)
        .nonce(2)
        .priority_fee_per_gas(500)
        .sign(&key)
        .unwrap();
    let tx = node_tx(&signed);
    assert_eq!(tx.priority_fee_per_gas, 500);
    assert!(tx.verify_signature());
    assert_eq!(tx.compute_tx_hash(), signed.tx_hash());
}
