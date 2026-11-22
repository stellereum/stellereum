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

// ============================================================================
// Protocol identity, EVM binding/carrier and governance parity (protocol v1)
// ============================================================================

use stellereum::evm_adapter::{
    binding_message as node_binding_message, build_binding_transaction, build_carrier_transaction,
    carrier_intent_digest, carrier_signing_message, decode_raw_transaction,
    eip1559_tx_signing_hash, evm_transfer_facts, evm_transfer_facts_at, verify_binding_claim,
    verify_carrier_intent, verify_evm_payload_against_tx, Eip1559Transaction,
};
use stellereum_sdk::evm::{EvmBindingBuilder, EvmCarrierBuilder};
use stellereum_sdk::governance::{GovAction, VoteChoice};
use stellereum_sdk::protocol::{ProtocolIdentity, FORK_ID, PROTOCOL_MAJOR, PROTOCOL_MINOR};

fn secp_key() -> k256::ecdsa::SigningKey {
    // Hardhat account #0. Public test vector, never holds value.
    let bytes =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    k256::ecdsa::SigningKey::from_slice(&bytes).unwrap()
}

fn evm_address(sk: &k256::ecdsa::SigningKey) -> [u8; 20] {
    let point = sk.verifying_key().to_encoded_point(false);
    let hash = stellereum::evm_adapter::keccak256(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// A real EIP-1559 value transfer for chain 5757, signed with Hardhat #0.
fn eip1559_raw(nonce: u64, value_wei: u128, to: [u8; 20]) -> Vec<u8> {
    let sk = secp_key();
    let chain_id = 5757;
    let gas_limit = 21_000;
    let hash = eip1559_tx_signing_hash(
        chain_id,
        nonce,
        1,
        1,
        gas_limit,
        Some(&to),
        value_wei,
        &[],
        &[],
    );
    let (sig, recid) = sk.sign_prehash_recoverable(&hash).unwrap();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.to_bytes()[..32]);
    s.copy_from_slice(&sig.to_bytes()[32..]);
    Eip1559Transaction {
        chain_id,
        nonce,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 1,
        gas_limit,
        to: Some(to),
        value: value_wei,
        data: Vec::new(),
        access_list: Vec::new(),
        y_parity: recid.to_byte(),
        v: recid.to_byte() as u64,
        r,
        s,
    }
    .encode()
}

fn binding_proof(pq: &[u8; 32], evm: &[u8; 20]) -> Vec<u8> {
    let sk = secp_key();
    let digest = node_binding_message(5757, evm, pq);
    let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
    let mut proof = Vec::with_capacity(65);
    proof.extend_from_slice(&sig.to_bytes()[..32]);
    proof.extend_from_slice(&sig.to_bytes()[32..]);
    proof.push(recid.to_byte());
    proof
}

#[test]
fn protocol_identity_matches_the_node() {
    assert_eq!(PROTOCOL_MAJOR, stellereum::protocol::PROTOCOL_MAJOR);
    assert_eq!(PROTOCOL_MINOR, stellereum::protocol::PROTOCOL_MINOR);
    assert_eq!(FORK_ID, stellereum::protocol::FORK_ID);
    assert_eq!(FORK_ID, 0x3ae0_0ebc);
    assert_eq!(
        stellereum_sdk::protocol::CONSENSUS_RULESET_VERSION,
        stellereum::protocol::CONSENSUS_RULESET_VERSION
    );
    assert_eq!(stellereum_sdk::protocol::CONSENSUS_RULESET_VERSION, 7);
    assert_eq!(
        stellereum_sdk::protocol::DOMAIN_SET_VERSION,
        stellereum::protocol::DOMAIN_SET_VERSION
    );
    assert_eq!(stellereum_sdk::protocol::DOMAIN_SET_VERSION, 4);
    assert_eq!(stellereum_sdk::protocol::FORK_ID_RULES.len(), 32);
    assert_eq!(
        stellereum_sdk::protocol::FORK_ID_RULES,
        stellereum::protocol::FORK_ID_RULES,
        "the SDK's fork-id rule list must mirror the node's"
    );
    assert_eq!(
        stellereum_sdk::protocol::derive_fork_id(
            stellereum_sdk::DEFAULT_CHAIN_ID,
            stellereum_sdk::protocol::CONSENSUS_RULESET_VERSION,
            stellereum_sdk::protocol::FORK_ID_RULES,
        ),
        stellereum::protocol::derive_fork_id(
            stellereum::zkml::DEFAULT_CHAIN_ID,
            stellereum::protocol::CONSENSUS_RULESET_VERSION,
            stellereum::protocol::FORK_ID_RULES,
        ),
        "the SDK's derivation must equal the node's derive_fork_id"
    );
    let local = ProtocolIdentity::local();
    assert_eq!(local.fork_id, stellereum::protocol::FORK_ID);
    assert_eq!(local.chain_id, stellereum::zkml::DEFAULT_CHAIN_ID);
    assert_eq!(
        local.fork_id_hex(),
        format!("0x{:08x}", stellereum::protocol::FORK_ID)
    );
}

#[test]
fn evm_intent_decode_matches_node_transfer_facts() {
    let to = [0x44u8; 20];
    let raw = eip1559_raw(11, 5_000_000_000, to);
    let ours = stellereum_sdk::evm::decode_evm_intent(&raw).unwrap();
    let theirs = evm_transfer_facts(&raw).unwrap();
    assert_eq!(ours.from, theirs.from);
    assert_eq!(ours.to, theirs.to);
    assert_eq!(ours.value_wei, theirs.value_wei);
    assert_eq!(ours.value_nano, theirs.value_nano);
    assert_eq!(ours.nonce, theirs.nonce);
    assert_eq!(ours.gas_limit, theirs.gas_limit);
    assert_eq!(ours.from, evm_address(&secp_key()));
    assert_eq!(
        ours.chain_id,
        decode_raw_transaction(&raw).unwrap().chain_id().unwrap()
    );

    let sub_nano_raw = eip1559_raw(12, 1_500_000_000, to);
    assert!(stellereum_sdk::evm::decode_evm_intent(&sub_nano_raw).is_err());
    assert!(evm_transfer_facts_at(&sub_nano_raw, true).is_err());
}

#[test]
fn evm_binding_unsigned_payload_and_preimage_match_node_builder() {
    let key = FalconKeypair::generate().unwrap();
    let evm = evm_address(&secp_key());
    let proof = binding_proof(&key.address(), &evm);
    let binding_sig = key
        .sign(&node_binding_message(5757, &evm, &key.address()))
        .unwrap();
    let gas = 700_000;

    let ours = EvmBindingBuilder::new(ProtocolIdentity::local(), evm, proof.clone())
        .unwrap()
        .nonce(9)
        .gas_limit(gas)
        .binding_signature(binding_sig.clone())
        .build_unsigned(&key)
        .unwrap();

    // The node's builder takes the ENVELOPE signature as an argument, so
    // sign the SDK's preimage and let the node verify exactly those bytes.
    let envelope_sig = key.sign(&ours.signing_message_for_chain(5757)).unwrap();
    let theirs = build_binding_transaction(
        key.public_key(),
        evm,
        &binding_sig,
        &proof,
        9,
        gas,
        &envelope_sig,
    )
    .unwrap();
    assert!(theirs.verify_signature());

    assert_eq!(
        ours.payload,
        bincode::serialize(&theirs.payload).unwrap(),
        "binding payload bytes differ"
    );
    assert_eq!(ours.from, theirs.from);
    assert_eq!(ours.to, theirs.to);
    assert_eq!(ours.amount, theirs.amount);
    assert_eq!(ours.nonce, theirs.nonce);
    assert_eq!(ours.gas_limit, theirs.gas_limit);
    assert_eq!(
        ours.signing_message_for_chain(5757),
        theirs.signing_message_for_chain(5757),
        "binding signing preimage differs"
    );

    // The node's own pure verifier accepts what the SDK built.
    let signed = EvmBindingBuilder::new(ProtocolIdentity::local(), evm, proof.clone())
        .unwrap()
        .nonce(9)
        .gas_limit(gas)
        .sign(&key)
        .unwrap();
    let node_tx = node_tx(&signed);
    assert!(node_tx.verify_signature());
    verify_binding_claim(
        match &node_tx.payload[0] {
            NodeOpCode::SysCallBindEvmAddress(claim) => claim,
            other => panic!("expected SysCallBindEvmAddress, got {other:?}"),
        },
        &key.address(),
    )
    .unwrap();
    verify_evm_payload_against_tx(&node_tx).unwrap();
}

#[test]
fn evm_carrier_unsigned_payload_and_preimage_match_node_builder() {
    let key = FalconKeypair::generate().unwrap();
    let raw = eip1559_raw(7, 3_000_000_000, [0x55u8; 20]);
    let to_pq = [0x77u8; 32];
    let gas = 900_000;
    let intent_sig = key
        .sign(&stellereum_sdk::evm::evm_intent_digest(&raw))
        .unwrap();

    let ours = EvmCarrierBuilder::new(ProtocolIdentity::local(), raw.clone(), to_pq)
        .unwrap()
        .gas_limit(gas)
        .intent_signature(intent_sig.clone())
        .build_unsigned(&key)
        .unwrap();

    let envelope_sig = key.sign(&ours.signing_message_for_chain(5757)).unwrap();
    let theirs = build_carrier_transaction(
        &raw,
        key.public_key(),
        &intent_sig,
        to_pq,
        gas,
        &envelope_sig,
    )
    .unwrap();
    assert!(theirs.verify_signature());

    assert_eq!(
        ours.payload,
        bincode::serialize(&theirs.payload).unwrap(),
        "carrier payload bytes differ"
    );
    assert_eq!(ours.from, theirs.from);
    assert_eq!(ours.to, theirs.to);
    assert_eq!(ours.amount, theirs.amount);
    assert_eq!(ours.nonce, theirs.nonce);
    assert_eq!(ours.gas_limit, theirs.gas_limit);
    assert_eq!(
        ours.signing_message_for_chain(5757),
        theirs.signing_message_for_chain(5757),
        "carrier signing preimage differs"
    );
    assert_eq!(
        carrier_signing_message(&theirs),
        ours.signing_message_for_chain(5757)
    );

    let signed = EvmCarrierBuilder::new(ProtocolIdentity::local(), raw.clone(), to_pq)
        .unwrap()
        .gas_limit(gas)
        .sign(&key)
        .unwrap();
    let node_tx = node_tx(&signed);
    assert!(node_tx.verify_signature());
    verify_carrier_intent(
        match &node_tx.payload[0] {
            NodeOpCode::SysCallEvmCarrier(carrier) => carrier,
            other => panic!("expected SysCallEvmCarrier, got {other:?}"),
        },
        &key.address(),
    )
    .unwrap();
    verify_evm_payload_against_tx(&node_tx).unwrap();
    assert_eq!(
        carrier_intent_digest(&node_tx).unwrap(),
        stellereum_sdk::evm::evm_intent_digest(&raw)
    );
}

#[test]
fn gov_propose_unsigned_bytes_and_preimage_match_node_builder() {
    let key = FalconKeypair::generate().unwrap();
    let action = GovAction::SetMinGasLimit(300_000);
    let node_action = stellereum::governance::GovAction::SetMinGasLimit(300_000);

    let ours = TxBuilder::gov_propose(4, "raise the floor".into(), action.clone(), 99)
        .unwrap()
        .nonce(6)
        .gas_limit(500_000)
        .unsigned_transaction(key.address());
    let theirs = stellereum::governance::Governance::gov_propose_tx(
        key.address(),
        6,
        500_000,
        0,
        0,
        4,
        "raise the floor".into(),
        node_action,
        99,
    )
    .unwrap();

    assert_eq!(
        ours.payload,
        bincode::serialize(&theirs.payload).unwrap(),
        "gov propose payload bytes differ"
    );
    assert_eq!(ours.from, theirs.from);
    assert_eq!(ours.to, theirs.to);
    assert_eq!(ours.amount, 0);
    assert_eq!(ours.nonce, theirs.nonce);
    assert_eq!(
        ours.signing_message_for_chain(5757),
        theirs.signing_message_for_chain(5757),
        "gov propose signing preimage differs"
    );

    // Signed by the SDK, accepted by the node's verifier and opcode decoder.
    let signed = TxBuilder::gov_propose(4, "raise the floor".into(), action, 99)
        .unwrap()
        .nonce(6)
        .gas_limit(500_000)
        .sign(&key)
        .unwrap();
    let node_tx = node_tx(&signed);
    assert!(node_tx.verify_signature());
    match &node_tx.payload[0] {
        NodeOpCode::SysCallGovPropose {
            proposal_id,
            title,
            action,
            height_observed,
        } => {
            assert_eq!(*proposal_id, 4);
            assert_eq!(title, "raise the floor");
            assert_eq!(
                **action,
                stellereum::governance::GovAction::SetMinGasLimit(300_000)
            );
            assert_eq!(*height_observed, 99);
        }
        other => panic!("expected SysCallGovPropose, got {other:?}"),
    }
}

#[test]
fn gov_vote_unsigned_bytes_and_preimage_match_node_builder() {
    let key = FalconKeypair::generate().unwrap();
    let ours = TxBuilder::gov_vote(8, VoteChoice::Abstain, 123)
        .nonce(2)
        .gas_limit(400_000)
        .unsigned_transaction(key.address());
    let theirs = stellereum::governance::Governance::gov_vote_tx(
        key.address(),
        2,
        400_000,
        0,
        0,
        8,
        stellereum::governance::VoteChoice::Abstain,
        123,
    );

    assert_eq!(
        ours.payload,
        bincode::serialize(&theirs.payload).unwrap(),
        "gov vote payload bytes differ"
    );
    assert_eq!(
        ours.signing_message_for_chain(5757),
        theirs.signing_message_for_chain(5757)
    );

    let signed = TxBuilder::gov_vote(8, VoteChoice::Abstain, 123)
        .nonce(2)
        .gas_limit(400_000)
        .sign(&key)
        .unwrap();
    let node_tx = node_tx(&signed);
    assert!(node_tx.verify_signature());
    match &node_tx.payload[0] {
        NodeOpCode::SysCallGovVote {
            proposal_id,
            choice,
            height_observed,
        } => {
            assert_eq!(*proposal_id, 8);
            assert_eq!(*choice, stellereum::governance::VoteChoice::Abstain);
            assert_eq!(*height_observed, 123);
        }
        other => panic!("expected SysCallGovVote, got {other:?}"),
    }
}

#[test]
fn every_supported_gov_action_serializes_identically() {
    let ours = vec![
        GovAction::SetMinValidatorBond(1_500_000_000_000),
        GovAction::SetEquivocationSlashBps(500),
        GovAction::SetDefaultCommissionBps(1_000),
        GovAction::SetBlockReward(2_000_000_000),
        GovAction::SetPmmRedemptionBufferBps(250),
        GovAction::SetGovernanceQuorumBps(5_000),
        GovAction::Signal("signal text".into()),
        GovAction::RegisterOraclePublisher([3u8; 32]),
        GovAction::UnregisterOraclePublisher([4u8; 32]),
        GovAction::ResetOracleBreaker,
        GovAction::SetMinGasLimit(300_000),
        GovAction::SoftwareUpgrade {
            name: "v6".into(),
            height: 1_000,
            sha256: [9u8; 32],
        },
        GovAction::CancelUpgrade,
        GovAction::SetFeeSplitBps {
            burn_bps: 5_000,
            proposer_bps: 3_000,
            staking_bps: 2_000,
        },
    ];
    let theirs = vec![
        stellereum::governance::GovAction::SetMinValidatorBond(1_500_000_000_000),
        stellereum::governance::GovAction::SetEquivocationSlashBps(500),
        stellereum::governance::GovAction::SetDefaultCommissionBps(1_000),
        stellereum::governance::GovAction::SetBlockReward(2_000_000_000),
        stellereum::governance::GovAction::SetPmmRedemptionBufferBps(250),
        stellereum::governance::GovAction::SetGovernanceQuorumBps(5_000),
        stellereum::governance::GovAction::Signal("signal text".into()),
        stellereum::governance::GovAction::RegisterOraclePublisher([3u8; 32]),
        stellereum::governance::GovAction::UnregisterOraclePublisher([4u8; 32]),
        stellereum::governance::GovAction::ResetOracleBreaker,
        stellereum::governance::GovAction::SetMinGasLimit(300_000),
        stellereum::governance::GovAction::SoftwareUpgrade {
            name: "v6".into(),
            height: 1_000,
            sha256: [9u8; 32],
        },
        stellereum::governance::GovAction::CancelUpgrade,
        stellereum::governance::GovAction::SetFeeSplitBps {
            burn_bps: 5_000,
            proposer_bps: 3_000,
            staking_bps: 2_000,
        },
    ];
    for (ours, theirs) in ours.iter().zip(theirs.iter()) {
        assert_eq!(
            ours.encode(),
            bincode::serialize(theirs).unwrap(),
            "GovAction bytes differ for {ours:?}"
        );
        assert_eq!(
            ours.action_type(),
            theirs.action_type(),
            "GovAction action_type differs for {ours:?}"
        );
    }
}
