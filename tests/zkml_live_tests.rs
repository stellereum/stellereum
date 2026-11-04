//! §2 zkML on the live block path: reachable + sound-checked.
//!
//! The audit gap: `ZkMlProof::verify_inference` is a STRUCTURAL check only
//! ("NOT sound on its own") and is FOOLED by forged proofs, while the live
//! opcode `SysCallVerifyZkMl` called exactly that check - and was unreachable
//! anyway (`VmContext.zkml_proof` is hard-coded `None`: no transport supplies
//! a proof).
//!
//! This file pins the fix end to end:
//!  * the proof rides INSIDE `Transaction.payload` as
//!    `SysCallVerifyZkMlReexec { model_id, proof }` (discriminant 35) - no new
//!    `Transaction`/`Block` fields, payload bytes already hashed into the
//!    signing message and tx hash;
//!  * models live in a committed, append-only `ZkMlModelRegistry`
//!    (`SysCallRegisterZkMlModel`, discriminant 36), folded into the state
//!    root CONDITIONALLY (empty = zero bytes, `COMMITMENT_VERSION` stays 4);
//!  * the verify handler calls `verify_inference_against(&registered_model)`
//!    - RE-EXECUTION, not a SNARK (see the opcode docs) - and reverts the
//!      whole transaction on failure, like every other refusal opcode.

use ed25519_dalek::SigningKey;
use stellereum::commitment::{commitment_digest, commitment_digest_with_zkml, COMMITMENT_VERSION};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{
    opcode_gas, OpCode, GAS_ZKML_PROOF_PER_BYTE, GAS_ZKML_REEXEC_PER_PARAM, GAS_ZKML_REGISTER,
    GAS_ZKML_REGISTER_PER_PARAM, GAS_ZKML_VERIFY_IN,
};
use stellereum::zkml::{QuantizedLayer, QuantizedLinearModel, ZkMlProof};

const BLOCK_TS: u64 = 1_760_000_000;
const GAS: u64 = 500_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn tiny_model() -> QuantizedLinearModel {
    // Same fixture as the `zkml.rs` unit tests: [3,4] -> [11,7].
    QuantizedLinearModel::new(vec![QuantizedLayer::new(
        2,
        2,
        vec![2, -1, 1, 3],
        vec![1, -2],
    )])
}

fn other_model() -> QuantizedLinearModel {
    QuantizedLinearModel::new(vec![QuantizedLayer::new(
        2,
        2,
        vec![1, 1, 1, 1],
        vec![0, 0],
    )])
}

const MODEL_A: [u8; 32] = [0x51; 32];
const MODEL_B: [u8; 32] = [0x52; 32];

async fn funded(nonce_start: u64) -> (InMemoryStateEngine, SigningKey, [u8; 32]) {
    let _ = nonce_start;
    let e = InMemoryStateEngine::new();
    let sk = key(0x71);
    let addr = sk.verifying_key().to_bytes();
    e.update_account(AccountState::new(addr, 1_000_000_000_000))
        .await;
    (e, sk, addr)
}

fn register_tx(
    sk: &SigningKey,
    to: [u8; 32],
    nonce: u64,
    id: [u8; 32],
    m: &QuantizedLinearModel,
) -> Transaction {
    Transaction::sign_with_payload(
        sk,
        to,
        0,
        GAS,
        nonce,
        1,
        1,
        vec![OpCode::SysCallRegisterZkMlModel {
            model_id: id,
            model: Box::new(m.clone()),
        }],
    )
}

fn verify_tx(
    sk: &SigningKey,
    to: [u8; 32],
    nonce: u64,
    id: [u8; 32],
    p: &ZkMlProof,
) -> Transaction {
    Transaction::sign_with_payload(
        sk,
        to,
        0,
        GAS,
        nonce,
        1,
        1,
        vec![OpCode::SysCallVerifyZkMlReexec {
            model_id: id,
            proof: Box::new(p.clone()),
        }],
    )
}

// ---------------------------------------------------------------------------
// 1. Valid proof accepted, forged proof rejected - on the live block path.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_proof_is_accepted_on_the_live_block_path() {
    let (e, sk, addr) = funded(0).await;
    let m = tiny_model();
    let (_out, proof) = ZkMlProof::prove_reexec(&m, &[3, 4]);

    let rtx = register_tx(&sk, addr, 0, MODEL_A, &m);
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&rtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (1, 0), "registration must apply");
    assert_eq!(s, vec![true]);

    let vtx = verify_tx(&sk, addr, 1, MODEL_A, &proof);
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!(
        (a, f),
        (1, 0),
        "honest proof against the registered model must apply"
    );
    assert_eq!(s, vec![true]);
}

#[tokio::test]
async fn forged_proof_is_rejected_on_the_live_block_path() {
    let m = tiny_model();
    // The audit's core claim, pinned at the unit level first: the structural
    // check is fooled, the sound check is not.
    let forged = ZkMlProof::forge_structural_proof(&m, &[3, 4], &[999, 999]);
    assert!(
        forged.verify_inference(),
        "structural check is fooled by the forgery"
    );
    assert!(
        !forged.verify_inference_against(&m),
        "re-execution against the known model must reject it"
    );

    // And the live opcode - which calls the sound check - rejects it too.
    // This closes the gap: the old path called the structural check (and was
    // unreachable anyway).
    let (e, sk, addr) = funded(0).await;
    let rtx = register_tx(&sk, addr, 0, MODEL_A, &m);
    let (a, f, _, _, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&rtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (1, 0));

    let vtx = verify_tx(&sk, addr, 1, MODEL_A, &forged);
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!(
        (a, f),
        (0, 1),
        "forged proof must NOT apply on the live path"
    );
    assert_eq!(s, vec![false]);
    // No gas wasted-state: the failed verify leaves the registry alone.
    assert_eq!(e.zkml_models_read().await.len(), 1);
}

// ---------------------------------------------------------------------------
// 2. Unregistered / mismatched models are rejected.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unregistered_model_is_rejected() {
    let (e, sk, addr) = funded(0).await;
    let m = tiny_model();
    let (_, proof) = ZkMlProof::prove_reexec(&m, &[3, 4]);
    // Never registered: the handler has nothing to check against.
    let vtx = verify_tx(&sk, addr, 0, MODEL_A, &proof);
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1));
    assert_eq!(s, vec![false]);
}

#[tokio::test]
async fn proof_for_another_model_is_rejected_under_a_registered_id() {
    let (e, sk, addr) = funded(0).await;
    let m = tiny_model();
    let other = other_model();
    let (_, other_proof) = ZkMlProof::prove_reexec(&other, &[3, 4]);

    let rtx = register_tx(&sk, addr, 0, MODEL_A, &m);
    assert_eq!(
        e.apply_block_parallel_fees(std::slice::from_ref(&rtx), BLOCK_TS)
            .await
            .0,
        1
    );

    // The proof's `model_hash` names `other`, the registry binds MODEL_A to
    // `m`: hash-match fails before re-execution even runs.
    let vtx = verify_tx(&sk, addr, 1, MODEL_A, &other_proof);
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1));
    assert_eq!(s, vec![false]);
}

// ---------------------------------------------------------------------------
// 3. Registry rules: append-only, validated, bounded + clone-commit.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registry_is_append_only_validated_and_clone_committed() {
    let (e, sk, addr) = funded(0).await;
    let m = tiny_model();

    // First writer wins.
    let r1 = register_tx(&sk, addr, 0, MODEL_A, &m);
    assert_eq!(
        e.apply_block_parallel_fees(std::slice::from_ref(&r1), BLOCK_TS)
            .await
            .0,
        1
    );
    let r2 = register_tx(&sk, addr, 1, MODEL_A, &other_model());
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&r2), BLOCK_TS)
        .await;
    assert_eq!(
        (a, f),
        (0, 1),
        "re-registering an id must revert (append-only)"
    );
    assert_eq!(s, vec![false]);
    assert_eq!(e.zkml_models_read().await.get(&MODEL_A).unwrap().model, m);

    // Malformed models never join the registry (here: chained dims broken).
    let mut bad = m.clone();
    bad.layers.push(QuantizedLayer {
        in_dim: 77,
        out_dim: 1,
        weights: vec![1],
        biases: vec![0],
    });
    assert!(!bad.validate());
    let rb = register_tx(&sk, addr, 2, MODEL_B, &bad);
    let (a, f, _, _, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&rb), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1), "malformed model must be refused");

    // Clone-commit: a registration in a transaction that later reverts leaves
    // nothing behind. Payload = [register MODEL_B, verify FORGED under MODEL_B].
    let forged = ZkMlProof::forge_structural_proof(&m, &[3, 4], &[999, 999]);
    let both = Transaction::sign_with_payload(
        &sk,
        addr,
        0,
        GAS,
        3,
        1,
        1,
        vec![
            OpCode::SysCallRegisterZkMlModel {
                model_id: MODEL_B,
                model: Box::new(m.clone()),
            },
            OpCode::SysCallVerifyZkMlReexec {
                model_id: MODEL_B,
                proof: Box::new(forged),
            },
        ],
    );
    let (a, f, _, s, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&both), BLOCK_TS)
        .await;
    assert_eq!((a, f), (0, 1), "the forged verify reverts the whole tx");
    assert_eq!(s, vec![false]);
    assert!(
        e.zkml_models_read().await.get(&MODEL_B).is_none(),
        "revert discards the registration"
    );
}

// ---------------------------------------------------------------------------
// 4. Roundtrip moves the root via the block; two nodes agree.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_verify_roundtrip_and_two_nodes_agree() {
    let m = tiny_model();
    let (_, proof) = ZkMlProof::prove_reexec(&m, &[3, 4]);

    async fn build() -> (InMemoryStateEngine, SigningKey, [u8; 32]) {
        funded(0).await
    }
    let (a, ska, addra) = build().await;
    let (b, _, _) = build().await;
    // Same funding key/addr on both (deterministic engines): mirror b's
    // account to a's addr so both apply identical txs.
    let skb = SigningKey::from_bytes(&[0x71; 32]);
    let addrb = skb.verifying_key().to_bytes();
    assert_eq!(addra, addrb);

    let root_empty_a = a.get_state_root().await;
    let root_empty_b = b.get_state_root().await;
    assert_eq!(root_empty_a, root_empty_b, "empty registries agree");

    for engine in [&a, &b] {
        let rtx = register_tx(&ska, addra, 0, MODEL_A, &m);
        assert_eq!(
            engine
                .apply_block_parallel_fees(std::slice::from_ref(&rtx), BLOCK_TS)
                .await
                .0,
            1
        );
    }
    assert_eq!(a.zkml_models_read().await.len(), 1);
    assert_eq!(b.zkml_models_read().await.len(), 1);
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "same register payload, same root"
    );
    assert_ne!(
        a.get_state_root().await,
        root_empty_a,
        "registration moves the root"
    );

    // Verify is read-only on the registry: the digest is unchanged by it.
    let before_a = stellereum::commitment::zkml_models_digest(&a.zkml_models_read().await.clone());
    for (engine, nonce) in [(&a, 1u64), (&b, 1u64)] {
        let vtx = verify_tx(&ska, addra, nonce, MODEL_A, &proof);
        assert_eq!(
            engine
                .apply_block_parallel_fees(std::slice::from_ref(&vtx), BLOCK_TS)
                .await
                .0,
            1
        );
    }
    let after_a = stellereum::commitment::zkml_models_digest(&a.zkml_models_read().await.clone());
    assert_eq!(before_a, after_a, "verify does not mutate the registry");
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "same verify payload, same root"
    );
}

// ---------------------------------------------------------------------------
// 5. Direct VM without a registry fails closed; legacy opcode stays refused.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn direct_vm_without_registry_fails_closed_and_legacy_is_refused() {
    use stellereum::svm::{Svm, VmContext};
    let m = tiny_model();
    let (_, proof) = ZkMlProof::prove_reexec(&m, &[3, 4]);

    // `Svm::execute` wires no registry: both new opcodes fail closed there,
    // the same shape as a token syscall with no registry.
    let mut ctx = VmContext {
        sender: [0u8; 32],
        balance: 0,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        zkml_proof: None,
        timestamp: 0,
        trades: vec![],
        transfers: vec![],
        token_registry: None,
        token_events: vec![],
        contracts: None,
        staking: None,
        pmm: None,
        min_validator_bond: 0,
        default_commission_bps: 0,
        payouts: vec![],
        oracle: None,
    };
    let r = Svm::execute(
        &[OpCode::SysCallRegisterZkMlModel {
            model_id: MODEL_A,
            model: Box::new(m.clone()),
        }],
        10_000_000,
        &mut ctx,
    );
    assert!(matches!(r, stellereum::svm::VmExecutionResult::Reverted(_)));

    let mut ctx2 = VmContext {
        sender: [0u8; 32],
        balance: 0,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        zkml_proof: None,
        timestamp: 0,
        trades: vec![],
        transfers: vec![],
        token_registry: None,
        token_events: vec![],
        contracts: None,
        staking: None,
        pmm: None,
        min_validator_bond: 0,
        default_commission_bps: 0,
        payouts: vec![],
        oracle: None,
    };
    let r = Svm::execute(
        &[OpCode::SysCallVerifyZkMlReexec {
            model_id: MODEL_A,
            proof: Box::new(proof),
        }],
        10_000_000,
        &mut ctx2,
    );
    assert!(matches!(r, stellereum::svm::VmExecutionResult::Reverted(_)));

    // The legacy structural-only opcode is hard-refused even on the block
    // path (it can no longer be resurrected by wiring `zkml_proof`).
    let (e, sk, addr) = funded(0).await;
    let legacy =
        Transaction::sign_with_payload(&sk, addr, 0, GAS, 0, 1, 1, vec![OpCode::SysCallVerifyZkMl]);
    let (a, f, _, _, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&legacy), BLOCK_TS)
        .await;
    assert_eq!(
        (a, f),
        (0, 1),
        "legacy SysCallVerifyZkMl must always revert"
    );
}

// ---------------------------------------------------------------------------
// 6. Gas metering: proof bytes + re-execution + registration size.
// ---------------------------------------------------------------------------

#[test]
fn gas_metering_covers_proof_bytes_reexecution_and_model_size() {
    let m = tiny_model();
    let (_, proof) = ZkMlProof::prove_reexec(&m, &[3, 4]);
    let op = OpCode::SysCallVerifyZkMlReexec {
        model_id: MODEL_A,
        proof: Box::new(proof.clone()),
    };
    let want = GAS_ZKML_VERIFY_IN + (proof.wire_len() as u64) * GAS_ZKML_PROOF_PER_BYTE;
    assert_eq!(opcode_gas(&op), want, "verify gas = base + proof bytes");
    assert!(
        opcode_gas(&op) > GAS_ZKML_VERIFY_IN,
        "a proof must cost its bytes"
    );

    // A bigger proof costs more than a small one (block-space pricing).
    let big = ZkMlProof::new(proof.model_hash, vec![1; 64], vec![2; 64], vec![0u8; 512]);
    let big_op = OpCode::SysCallVerifyZkMlReexec {
        model_id: MODEL_A,
        proof: Box::new(big),
    };
    assert!(opcode_gas(&big_op) > opcode_gas(&op));

    // Re-execution is priced per registered parameter, in-handler.
    assert_eq!((m.param_count() as u64) * GAS_ZKML_REEXEC_PER_PARAM, 6);

    // Registration scales with the model written.
    let rsmall = OpCode::SysCallRegisterZkMlModel {
        model_id: MODEL_A,
        model: Box::new(m.clone()),
    };
    let big_model =
        QuantizedLinearModel::new(vec![QuantizedLayer::new(4, 4, vec![1; 16], vec![0; 4])]);
    let rbig = OpCode::SysCallRegisterZkMlModel {
        model_id: MODEL_B,
        model: Box::new(big_model.clone()),
    };
    assert_eq!(
        opcode_gas(&rsmall),
        GAS_ZKML_REGISTER + (m.param_count() as u64) * GAS_ZKML_REGISTER_PER_PARAM
    );
    assert!(
        opcode_gas(&rbig) > opcode_gas(&rsmall),
        "writing more params must cost more"
    );
}

// ---------------------------------------------------------------------------
// 7. Wire compat: discriminants 0..=38 pinned, legacy goldens unchanged,
//    tx hash commits the proof, pre-§2 decoders fail closed.
// ---------------------------------------------------------------------------

fn every_opcode_and_its_discriminant() -> Vec<(OpCode, u32)> {
    use stellereum::bridge::BridgeIntent;
    use stellereum::crypto_privacy::ConfidentialTransfer;
    use stellereum::oracle::PriceFeedUpdate;
    use stellereum::zkml::SessionKeyAuthorization;
    use stellereum::zkml_attestation::AttestationProof;
    let grant = SessionKeyAuthorization::sign_delegation(
        &SigningKey::from_bytes(&[7u8; 32]),
        [9u8; 32],
        1_500_000_000,
        1_000_000,
        u64::MAX,
        u64::MAX,
        5757,
    );
    let m = tiny_model();
    let (_, proof) = ZkMlProof::prove_reexec(&m, &[1, 2]);
    // SNARK-path fixtures: shape only (the discriminant pin does not run
    // the prover - see tests/zkml_snark_tests.rs for live SNARK proofs).
    let snark_vk = stellereum::zkml_attestation::ModelSpec {
        spec_hash: [0x77; 32],
        spec_bytes: vec![9u8; 64],
        setup_attestation: b"pin".to_vec(),
        n_public_inputs: 4,
        in_dim: 2,
        out_dim: 2,
    };
    let snark_proof = AttestationProof {
        model_hash: [0x78; 32],
        spec_hash: [0x77; 32],
        public_inputs: vec![1, 2],
        public_outputs: vec![11, 7],
        proof_bytes: vec![0u8; stellereum::zkml_attestation::ATTEST_PROOF_BYTES],
    };
    vec![
        (OpCode::Nop, 0),
        (OpCode::Push(1), 1),
        (OpCode::Pop, 2),
        (OpCode::Add, 3),
        (OpCode::Sub, 4),
        (OpCode::Mul, 5),
        (OpCode::Div, 6),
        (OpCode::LoadBalance, 7),
        (
            OpCode::Transfer {
                recipient: [0; 32],
                amount: 1,
            },
            8,
        ),
        (
            OpCode::SysCallPlaceOrder {
                pair_id: 1,
                is_buy: true,
                price: 1,
                amount: 1,
            },
            9,
        ),
        (OpCode::SysCallCancelOrder { order_id: 1 }, 10),
        (OpCode::SysCallVerifyZkMl, 11),
        (OpCode::SysCallPatriciaLookup([0u8; 32]), 12),
        (
            OpCode::SysCallTokenTransfer {
                token_id: [0; 32],
                to: [0; 32],
                amount: 1,
            },
            13,
        ),
        (
            OpCode::SysCallTokenTransferFrom {
                token_id: [0; 32],
                from: [0; 32],
                to: [0; 32],
                amount: 1,
            },
            14,
        ),
        (
            OpCode::SysCallTokenMint {
                token_id: [0; 32],
                to: [0; 32],
                amount: 1,
            },
            15,
        ),
        (
            OpCode::SysCallTokenBurn {
                token_id: [0; 32],
                from: [0; 32],
                amount: 1,
            },
            16,
        ),
        (
            OpCode::SysCallTokenApprove {
                token_id: [0; 32],
                spender: [0; 32],
                amount: 1,
            },
            17,
        ),
        (
            OpCode::SysCallTokenBalanceOf {
                token_id: [0; 32],
                account: [0; 32],
            },
            18,
        ),
        (OpCode::SysCallDeployContract { code: vec![] }, 19),
        (
            OpCode::SysCallCallContract {
                contract: [0; 32],
                method: vec![],
                arg: 0,
            },
            20,
        ),
        (
            OpCode::SysCallStake {
                validator: [0; 32],
                amount: 1,
            },
            21,
        ),
        (
            OpCode::SysCallUnbond {
                validator: [0; 32],
                amount: 1,
            },
            22,
        ),
        (
            OpCode::SysCallDelegate {
                validator: [0; 32],
                amount: 1,
            },
            23,
        ),
        (OpCode::SysCallUndelegate { validator: [0; 32] }, 24),
        (OpCode::SysCallClaimRewards { validator: [0; 32] }, 25),
        (OpCode::Halt, 26),
        (
            OpCode::SysCallSubmitPriceFeed(Box::new(PriceFeedUpdate {
                asset: "STELL/USD".to_string(),
                price_micro_usd: 250_000,
                timestamp: 1_700_000_000,
                publisher_pubkey: [0; 32],
                signature: vec![],
            })),
            27,
        ),
        (
            OpCode::SysCallRevokeSession {
                session_pubkey: [0; 32],
            },
            28,
        ),
        (OpCode::SysCallPmmBuy { usdt_micro: 1 }, 29),
        (OpCode::SysCallPmmSell { stell_nano: 1 }, 30),
        (OpCode::SysCallPublishSessionGrant(Box::new(grant)), 31),
        (
            OpCode::SysCallBridge(Box::new(BridgeIntent::Release { req_id: 1 })),
            32,
        ),
        (
            OpCode::SysCallConfidentialTransfer {
                recipient: [0; 32],
                transfer: Box::new(ConfidentialTransfer::new(vec![], vec![], 0)),
            },
            33,
        ),
        (
            OpCode::SysCallActorSend {
                recipient: [0; 32],
                value: 7,
                body: vec![OpCode::Halt],
                bounce: true,
                gas_budget: 900,
            },
            34,
        ),
        // §2, appended after the actor mailbox: verify (35) then register (36).
        (
            OpCode::SysCallVerifyZkMlReexec {
                model_id: [0x51; 32],
                proof: Box::new(proof),
            },
            35,
        ),
        (
            OpCode::SysCallRegisterZkMlModel {
                model_id: [0x51; 32],
                model: Box::new(m),
            },
            36,
        ),
        // §2 succinct halves, appended after the re-execution halves:
        // VK register (37) then SNARK verify (38). See
        // tests/zkml_snark_tests.rs for the live SNARK path.
        (
            OpCode::SysCallRegisterZkMlSpec {
                model_id: [0x51; 32],
                spec: Box::new(snark_vk),
            },
            37,
        ),
        (
            OpCode::SysCallVerifyZkMlAttestation {
                model_id: [0x51; 32],
                proof: Box::new(snark_proof),
            },
            38,
        ),
    ]
}

#[test]
fn appended_discriminants_preserve_every_existing_encoding() {
    let cases = every_opcode_and_its_discriminant();
    assert_eq!(
        cases.len(),
        39,
        "OpCode must have exactly 39 variants (0..=38)"
    );
    for (op, want) in &cases {
        let bytes = bincode::serialize(op).expect("opcode serializes");
        assert!(
            bytes.len() >= 4,
            "bincode discriminant is a leading u32: {op:?}"
        );
        let got = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(
            got, *want,
            "discriminant of {op:?} moved: {got} != {want}. An OpCode was INSERTED above it"
        );
    }
    // The payload-vector framing legacy nodes decode is untouched too:
    // [len:u64][Push disc:u32][Push val:u64][Halt disc:u32].
    let legacy: Vec<OpCode> = vec![OpCode::Push(42), OpCode::Halt];
    let bytes = bincode::serialize(&legacy).unwrap();
    assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()), 2);
    assert_eq!(
        u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        1,
        "Push is still 1"
    );
    assert_eq!(
        u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
        26,
        "Halt is still 26"
    );
}

#[test]
fn zkml_tx_hash_commits_the_proof_and_pre_node_fails_closed() {
    let sk = SigningKey::from_bytes(&[3u8; 32]);
    let recipient = [0xABu8; 32];
    let m = tiny_model();
    let (_, proof) = ZkMlProof::prove_reexec(&m, &[3, 4]);
    let forged = ZkMlProof::forge_structural_proof(&m, &[3, 4], &[999, 999]);

    let mk = |p: &ZkMlProof| {
        Transaction::sign_with_payload(
            &sk,
            recipient,
            0,
            50_000,
            0,
            1,
            1,
            vec![OpCode::SysCallVerifyZkMlReexec {
                model_id: MODEL_A,
                proof: Box::new(p.clone()),
            }],
        )
    };
    let a = mk(&proof);
    let b = mk(&forged);
    let a_again = mk(&proof);
    assert_eq!(a.compute_tx_hash(), a_again.compute_tx_hash());
    assert_ne!(
        a.compute_tx_hash(),
        b.compute_tx_hash(),
        "different proofs, different txs"
    );
    assert_ne!(a.signing_message(), b.signing_message());

    // Tampering after signing invalidates the signature: payload (hence the
    // proof bytes) is inside what the key signed.
    let mut tampered = a.clone();
    tampered.payload = vec![OpCode::SysCallVerifyZkMlReexec {
        model_id: MODEL_A,
        proof: Box::new(forged),
    }];
    assert!(!tampered.verify_signature());

    // Modelled pre-§2 node (knows 0..=34): fails closed on 35/36.
    for payload in [
        vec![OpCode::SysCallVerifyZkMlReexec {
            model_id: MODEL_A,
            proof: Box::new(proof.clone()),
        }],
        vec![OpCode::SysCallRegisterZkMlModel {
            model_id: MODEL_A,
            model: Box::new(m.clone()),
        }],
    ] {
        let bytes = bincode::serialize(&payload).unwrap();
        let first = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        assert!(
            first >= 35,
            "new opcodes must be unknown to a pre-§2 decoder (got {first})"
        );
        let round: Vec<OpCode> = bincode::deserialize(&bytes).expect("decodes today");
        assert_eq!(round.len(), 1);
    }
    // Legacy traffic still decodes on the old node.
    for legacy in [vec![OpCode::Push(42)], vec![OpCode::Halt], vec![]] {
        let bytes = bincode::serialize(&legacy).unwrap();
        if bytes.len() >= 12 {
            let count = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            if count > 0 {
                let first = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
                assert!(first < 35, "legacy payload must decode pre-§2: {legacy:?}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 8. Commitment: conditional domain, version pinned.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn zkml_registry_is_folded_into_the_commitment_conditionally() {
    use std::collections::HashMap;
    use stellereum::bridge::BridgeState;
    use stellereum::contract::ContractRegistry;
    use stellereum::governance::Governance;
    use stellereum::oracle::OracleState;
    use stellereum::orderbook::OrderbookManager;
    use stellereum::pmm::PrimaryMarketMaker;
    use stellereum::staking::StakingLedger;
    use stellereum::token::TokenRegistry;
    use stellereum::zkml::{SessionKeyRegistry, ZkMlModelRegistry};

    assert_eq!(COMMITMENT_VERSION, 5, "Genesis v5 version");
    let snap = stellereum::commitment::CommitmentSnapshot {
        tokens: TokenRegistry::default(),
        staking: StakingLedger::default(),
        orderbooks: OrderbookManager::default(),
        order_escrow: HashMap::new(),
        pmm: PrimaryMarketMaker::new(),
        pmm_usdt_token: None,
        pmm_treasury: [0u8; 32],
        contracts: ContractRegistry::default(),
        governance: Governance::default(),
        oracle: OracleState::default(),
        session_keys: SessionKeyRegistry::default(),
        bridge: BridgeState::default(),
        cross_shard_consumed: Vec::new(),
        cross_shard_produced: Vec::new(),
        cross_shard_completed: Vec::new(),
        cross_shard_xpc: Vec::new(),
    };
    let empty = ZkMlModelRegistry::default();
    assert!(empty.is_empty());
    // Empty registry: the zkML-aware digest is byte-identical to the base.
    assert_eq!(
        commitment_digest_with_zkml(&snap, &empty),
        commitment_digest(&snap)
    );

    let mut one = ZkMlModelRegistry::default();
    one.register(MODEL_A, tiny_model()).unwrap();
    assert_ne!(
        commitment_digest_with_zkml(&snap, &one),
        commitment_digest(&snap),
        "a registered model must move the digest"
    );
    let mut two = one.clone();
    two.register(MODEL_B, other_model()).unwrap();
    assert_ne!(
        commitment_digest_with_zkml(&snap, &two),
        commitment_digest_with_zkml(&snap, &one),
        "a second model must move the digest again"
    );

    // And through the engine: registration moves the live root.
    let (e, sk, addr) = funded(0).await;
    let before = e.get_state_root().await;
    let rtx = register_tx(&sk, addr, 0, MODEL_A, &tiny_model());
    assert_eq!(
        e.apply_block_parallel_fees(std::slice::from_ref(&rtx), BLOCK_TS)
            .await
            .0,
        1
    );
    assert_ne!(
        e.get_state_root().await,
        before,
        "registry is consensus state"
    );
}
