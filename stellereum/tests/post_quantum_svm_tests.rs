//! Tests for SVM OpCode 46 (`SysCallVerifyPqSignature`).
//!
//! Verifies post-quantum, classic, and hybrid signature verification:
//! - Ed25519 (0x01)
//! - Falcon-512 (0x02)
//! - ML-DSA-44 (0x03)
//! - Hybrid dual-signature (0x04)
//! - Unknown scheme IDs fail safely (push 0 to stack)
//! - Gas metering (base 1500 + per-byte charges)
//! - Out-of-gas behavior

use ed25519_dalek::Signer;
use stellereum::post_quantum::{
    PqScheme, ED25519_SIG_LEN, HYBRID_PUBKEY_LEN, HYBRID_SIG_LEN, MLDSA44_PUBKEY_LEN,
    MLDSA44_SIG_LEN,
};
use stellereum::staking::{DEFAULT_COMMISSION_BPS, MIN_VALIDATOR_BOND};
use stellereum::svm::{
    opcode_gas, pq_verify_gas, OpCode, Svm, VmContext, VmExecutionResult, GAS_PQ_VERIFY_BASE,
    GAS_PQ_VERIFY_PER_BYTE, GAS_PUSH,
};

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
        timestamp: 1_700_000_000,
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

fn sample_ed25519(seed: u8, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let pk = sk.verifying_key().to_bytes().to_vec();
    let sig = sk.sign(msg).to_bytes().to_vec();
    (pk, sig)
}

fn sample_falcon512(seed: u8, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Real FIPS 206 signatures. OpCode 46 verifies through
    // `verify_pq_signature` -> `verify_falcon512`, which runs the actual ring
    // math and has NO test fallback (unlike `verify_falcon_signature_or_test`),
    // so a synthetic check-digest signature always pushes 0 and the "valid
    // signature must push 1" assertions below can never hold.
    let fk = stellereum::post_quantum::FalconKeypair::generate_from_seed(seed);
    (fk.public_key().to_vec(), fk.sign(msg))
}

fn sample_mldsa44(seed: u8, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut pk = vec![seed; MLDSA44_PUBKEY_LEN];
    pk[0] = 0x01; // Non-degenerate rho
    let mut sig = vec![seed ^ 0x55; MLDSA44_SIG_LEN];
    sig[0] = 0x01;

    let rho = &pk[..32];
    let t1 = &pk[32..];
    let mut h = blake3::Hasher::new_derive_key("MLDSA44_VERIFY_V4");
    h.update(rho);
    h.update(t1);
    h.update(msg);
    let mu = *h.finalize().as_bytes();

    let c_tilde = &sig[..32];
    let z_without_trailer = &sig[32..MLDSA44_SIG_LEN - 1];
    let mut binding = blake3::Hasher::new_derive_key("MLDSA44_BINDING_V4");
    binding.update(&mu);
    binding.update(c_tilde);
    binding.update(z_without_trailer);
    let expected = binding.finalize();
    sig[MLDSA44_SIG_LEN - 1] = expected.as_bytes()[0];

    (pk, sig)
}

fn sample_hybrid(seed: u8, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (ed_pk, ed_sig) = sample_ed25519(seed, msg);
    let (falcon_pk, falcon_sig) = sample_falcon512(seed, msg);
    let mut pk = Vec::with_capacity(HYBRID_PUBKEY_LEN);
    pk.extend_from_slice(&ed_pk);
    pk.extend_from_slice(&falcon_pk);
    let mut sig = Vec::with_capacity(HYBRID_SIG_LEN);
    sig.extend_from_slice(&ed_sig);
    sig.extend_from_slice(&falcon_sig);
    (pk, sig)
}

#[test]
fn opcode46_ed25519_execution() {
    let msg = b"SVM Ed25519 Signature Verification";
    let (pk, sig) = sample_ed25519(42, msg);

    // Valid signature -> pushes 1
    let op_valid = OpCode::SysCallVerifyPqSignature {
        scheme_id: PqScheme::Ed25519.id(),
        pubkey: pk.clone(),
        message: msg.to_vec(),
        signature: sig.clone(),
    };
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&[op_valid], 100_000, &mut ctx);
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            assert_eq!(return_value, Some(1), "valid Ed25519 signature must push 1");
        }
        other => panic!("expected Success, got {other:?}"),
    }

    // Tampered message -> pushes 0
    let op_bad_msg = OpCode::SysCallVerifyPqSignature {
        scheme_id: PqScheme::Ed25519.id(),
        pubkey: pk.clone(),
        message: b"Forged message".to_vec(),
        signature: sig.clone(),
    };
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&[op_bad_msg], 100_000, &mut ctx);
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            assert_eq!(return_value, Some(0), "tampered message must push 0");
        }
        other => panic!("expected Success, got {other:?}"),
    }

    // Tampered signature -> pushes 0
    let mut bad_sig = sig;
    bad_sig[0] ^= 0xFF;
    let op_bad_sig = OpCode::SysCallVerifyPqSignature {
        scheme_id: PqScheme::Ed25519.id(),
        pubkey: pk,
        message: msg.to_vec(),
        signature: bad_sig,
    };
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&[op_bad_sig], 100_000, &mut ctx);
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            assert_eq!(return_value, Some(0), "tampered signature must push 0");
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[test]
fn opcode46_falcon512_execution() {
    let msg = b"SVM Falcon-512 Signature Verification";
    let (pk, sig) = sample_falcon512(0x55, msg);

    // Valid Falcon-512 -> pushes 1
    let op_valid = OpCode::SysCallVerifyPqSignature {
        scheme_id: PqScheme::Falcon512.id(),
        pubkey: pk.clone(),
        message: msg.to_vec(),
        signature: sig.clone(),
    };
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&[op_valid], 100_000, &mut ctx);
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            assert_eq!(
                return_value,
                Some(1),
                "valid Falcon-512 signature must push 1"
            );
        }
        other => panic!("expected Success, got {other:?}"),
    }

    // Tampered signature trailer -> pushes 0
    let mut bad_sig = sig;
    let last = bad_sig.len() - 1;
    bad_sig[last] ^= 0xFF;
    let op_bad_sig = OpCode::SysCallVerifyPqSignature {
        scheme_id: PqScheme::Falcon512.id(),
        pubkey: pk,
        message: msg.to_vec(),
        signature: bad_sig,
    };
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&[op_bad_sig], 100_000, &mut ctx);
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            assert_eq!(
                return_value,
                Some(0),
                "tampered Falcon-512 signature must push 0"
            );
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[test]
fn opcode46_mldsa44_execution() {
    let msg = b"SVM ML-DSA-44 Signature Verification";
    let (pk, sig) = sample_mldsa44(0x77, msg);

    // ML-DSA-44 DISABLED fail-closed (forgeable verifier, no FIPS-204 math):
    // even a well-formed signature pushes 0. See post_quantum.rs.
    let op_valid = OpCode::SysCallVerifyPqSignature {
        scheme_id: PqScheme::MlDsa44.id(),
        pubkey: pk.clone(),
        message: msg.to_vec(),
        signature: sig.clone(),
    };
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&[op_valid], 100_000, &mut ctx);
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            assert_eq!(return_value, Some(0), "disabled ML-DSA-44 must push 0");
        }
        other => panic!("expected Success, got {other:?}"),
    }

    // Tampered signature trailer -> pushes 0
    let mut bad_sig = sig;
    let last = bad_sig.len() - 1;
    bad_sig[last] ^= 0xFF;
    let op_bad_sig = OpCode::SysCallVerifyPqSignature {
        scheme_id: PqScheme::MlDsa44.id(),
        pubkey: pk,
        message: msg.to_vec(),
        signature: bad_sig,
    };
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&[op_bad_sig], 100_000, &mut ctx);
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            assert_eq!(
                return_value,
                Some(0),
                "tampered ML-DSA-44 signature must push 0"
            );
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[test]
fn opcode46_hybrid_execution() {
    let msg = b"SVM Hybrid Signature Verification";
    let (pk, sig) = sample_hybrid(0x99, msg);

    // Valid Hybrid -> pushes 1
    let op_valid = OpCode::SysCallVerifyPqSignature {
        scheme_id: PqScheme::Hybrid.id(),
        pubkey: pk.clone(),
        message: msg.to_vec(),
        signature: sig.clone(),
    };
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&[op_valid], 100_000, &mut ctx);
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            assert_eq!(return_value, Some(1), "valid Hybrid signature must push 1");
        }
        other => panic!("expected Success, got {other:?}"),
    }

    // Tampering Ed25519 half -> pushes 0
    let mut bad_ed = sig.clone();
    bad_ed[0] ^= 0xFF;
    let op_bad_ed = OpCode::SysCallVerifyPqSignature {
        scheme_id: PqScheme::Hybrid.id(),
        pubkey: pk.clone(),
        message: msg.to_vec(),
        signature: bad_ed,
    };
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&[op_bad_ed], 100_000, &mut ctx);
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            assert_eq!(
                return_value,
                Some(0),
                "tampered Ed25519 portion of hybrid must push 0"
            );
        }
        other => panic!("expected Success, got {other:?}"),
    }

    // Tampering Falcon half -> pushes 0
    let mut bad_falcon = sig;
    bad_falcon[ED25519_SIG_LEN] ^= 0xFF;
    let op_bad_falcon = OpCode::SysCallVerifyPqSignature {
        scheme_id: PqScheme::Hybrid.id(),
        pubkey: pk,
        message: msg.to_vec(),
        signature: bad_falcon,
    };
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&[op_bad_falcon], 100_000, &mut ctx);
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            assert_eq!(
                return_value,
                Some(0),
                "tampered Falcon portion of hybrid must push 0"
            );
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[test]
fn opcode46_unknown_scheme_id_pushes_zero() {
    let op_unknown = OpCode::SysCallVerifyPqSignature {
        scheme_id: 255,
        pubkey: vec![0u8; 32],
        message: b"test".to_vec(),
        signature: vec![0u8; 64],
    };
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&[op_unknown], 100_000, &mut ctx);
    match res {
        VmExecutionResult::Success { return_value, .. } => {
            assert_eq!(return_value, Some(0), "unknown scheme_id must push 0");
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[test]
fn opcode46_gas_metering_and_schedule_shape() {
    let msg_short = b"short";
    let msg_long =
        b"this is a much longer message to verify per-byte gas metering in SVM opcode 46";
    let (pk, sig) = sample_ed25519(1, msg_short);

    let op_short = OpCode::SysCallVerifyPqSignature {
        scheme_id: PqScheme::Ed25519.id(),
        pubkey: pk.clone(),
        message: msg_short.to_vec(),
        signature: sig.clone(),
    };
    let op_long = OpCode::SysCallVerifyPqSignature {
        scheme_id: PqScheme::Ed25519.id(),
        pubkey: pk.clone(),
        message: msg_long.to_vec(),
        signature: sig.clone(),
    };

    let cost_short = opcode_gas(&op_short);
    let cost_long = opcode_gas(&op_long);

    // Must match formula: base (1500) + wire_bytes * 2
    let wire_short = (pk.len() + msg_short.len() + sig.len()) as u64;
    let expected_short = GAS_PQ_VERIFY_BASE + wire_short * GAS_PQ_VERIFY_PER_BYTE;
    assert_eq!(cost_short, expected_short);
    assert_eq!(
        cost_short,
        pq_verify_gas(pk.len(), msg_short.len(), sig.len())
    );

    let wire_long = (pk.len() + msg_long.len() + sig.len()) as u64;
    let expected_long = GAS_PQ_VERIFY_BASE + wire_long * GAS_PQ_VERIFY_PER_BYTE;
    assert_eq!(cost_long, expected_long);

    // Longer message costs more gas
    assert!(cost_long > cost_short);
    assert_eq!(
        cost_long - cost_short,
        ((msg_long.len() - msg_short.len()) as u64) * GAS_PQ_VERIFY_PER_BYTE
    );

    // Exact gas consumed in execution
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&[op_short], 50_000, &mut ctx);
    match res {
        VmExecutionResult::Success { gas_used, .. } => {
            assert_eq!(gas_used, cost_short);
        }
        other => panic!("expected Success, got {other:?}"),
    }
}

#[test]
fn opcode46_out_of_gas_behavior() {
    let msg = b"Testing Out-Of-Gas Behavior for OpCode 46";
    let (pk, sig) = sample_ed25519(1, msg);

    let op = OpCode::SysCallVerifyPqSignature {
        scheme_id: PqScheme::Ed25519.id(),
        pubkey: pk.clone(),
        message: msg.to_vec(),
        signature: sig.clone(),
    };
    let cost = opcode_gas(&op);

    // 1 gas unit short -> OutOfGas
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(std::slice::from_ref(&op), cost - 1, &mut ctx);
    assert!(
        matches!(res, VmExecutionResult::OutOfGas),
        "limit = cost - 1 must return OutOfGas"
    );

    // Exact gas -> Success
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(std::slice::from_ref(&op), cost, &mut ctx);
    match res {
        VmExecutionResult::Success {
            gas_used,
            return_value,
            ..
        } => {
            assert_eq!(gas_used, cost);
            assert_eq!(return_value, Some(1));
        }
        other => panic!("limit = cost must succeed, got {other:?}"),
    }

    // Mid-sequence OutOfGas: Push(42) succeeds, then SysCallVerifyPqSignature starves
    let seq = vec![OpCode::Push(42), op];
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&seq, GAS_PUSH + cost - 1, &mut ctx);
    assert!(
        matches!(res, VmExecutionResult::OutOfGas),
        "insufficient gas for OpCode 46 mid-sequence must return OutOfGas"
    );
}

#[test]
fn opcode46_multi_scheme_sequence() {
    let msg = b"Multi-Scheme Sequence";
    let (ed_pk, ed_sig) = sample_ed25519(1, msg);
    let (fal_pk, fal_sig) = sample_falcon512(2, msg);
    let (ml_pk, ml_sig) = sample_mldsa44(3, msg);

    let prog = vec![
        OpCode::SysCallVerifyPqSignature {
            scheme_id: PqScheme::Ed25519.id(),
            pubkey: ed_pk,
            message: msg.to_vec(),
            signature: ed_sig,
        },
        OpCode::SysCallVerifyPqSignature {
            scheme_id: PqScheme::Falcon512.id(),
            pubkey: fal_pk,
            message: msg.to_vec(),
            signature: fal_sig,
        },
        OpCode::SysCallVerifyPqSignature {
            scheme_id: PqScheme::MlDsa44.id(),
            pubkey: ml_pk,
            message: msg.to_vec(),
            signature: ml_sig,
        },
    ];

    let total_cost: u64 = prog.iter().map(opcode_gas).sum();
    let mut ctx = mk_ctx(10_000);
    let res = Svm::execute(&prog, total_cost, &mut ctx);
    match res {
        VmExecutionResult::Success {
            gas_used,
            return_value,
            ..
        } => {
            assert_eq!(gas_used, total_cost);
            // Last op is ML-DSA-44, disabled fail-closed -> pushes 0.
            assert_eq!(return_value, Some(0));
        }
        other => panic!("expected Success, got {other:?}"),
    }
}
