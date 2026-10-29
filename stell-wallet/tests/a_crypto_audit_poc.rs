//! A-CRYPTO wallet PoC: disabled ML-DSA-44 re-enabled wallet-side.

#[allow(dead_code)]
#[path = "../src/rpc.rs"]
mod rpc;

#[allow(dead_code)]
#[path = "../src/security.rs"]
mod security;

#[allow(dead_code)]
#[path = "../src/client.rs"]
mod client;

#[allow(dead_code)]
#[path = "../src/pq.rs"]
mod pq;

use pq::PqScheme;

// Wallet must refuse 0x03 exactly like the node (stellereum::post_quantum::PqScheme::from_id).
#[test]
fn poc_wallet_refuses_mldsa44_like_node() {
    let node = stellereum::post_quantum::PqScheme::from_id(3);
    assert!(node.is_err(), "precondition: node refuses 0x03");
    let wallet = PqScheme::from_id(3);
    println!("wallet from_id(3)={wallet:?}");
    // Fails on current code: wallet accepts 0x03.
    assert!(wallet.is_err(), "POC-REAL: wallet PqScheme::from_id(3) accepts disabled scheme");
}

// Wallet can generate + sign with the disabled scheme; node never verifies.
#[test]
fn poc_wallet_mldsa44_sign_never_verifies_node_side() {
    let kp = pq::PqKeyPair::from_seed(PqScheme::MlDsa44, &[0xAAu8; 32]);
    let sig = kp.sign(b"wallet mldsa44 probe");
    // FIXED (audit HIGH-2): wallet refuses to mint disabled-scheme sigs.
    assert!(sig.is_empty(), "disabled-scheme sign must fail closed");
    let node_pk = stellereum::post_quantum::PqScheme::MlDsa44;
    let node_ok = stellereum::post_quantum::verify_pq_signature(
        node_pk,
        kp.public_key(),
        b"wallet mldsa44 probe",
        &sig,
    );
    println!("node verify of wallet mldsa44 sig={node_ok}");
    assert!(!node_ok, "node must refuse mldsa44");
    // The wallet-side gap is that it minted it at all.
    assert!(
        PqScheme::from_id(3).is_err(),
        "POC-REAL: wallet must not construct disabled scheme keys"
    );
}
