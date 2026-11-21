//! Offline relayer model: release signatures must bind the operation and payload.

use stellereum::bridge::MultisigRelayer;
use stellereum::consensus::register_validator_pq_key;
use stellereum::post_quantum::{FalconKeypair, PqScheme};

#[test]
fn falcon_release_authorization_binds_op_and_payload_and_rejects_replays() {
    let ids = [[0xa1; 32], [0xa2; 32], [0xa3; 32]];
    let keys: Vec<_> = ids
        .iter()
        .map(FalconKeypair::generate_from_seed_bytes)
        .collect();
    for (id, key) in ids.iter().zip(&keys) {
        register_validator_pq_key(*id, PqScheme::Falcon512, key.public_key.clone());
    }
    let mut relayer = MultisigRelayer::new(ids.to_vec());
    let op = [0x10; 32];
    let other_op = [0x11; 32];
    let payload = b"recipient and amount";

    // Spell out the model protocol independently of its implementation.
    let mut preimage = b"STELLEREUM_MULTISIG_RELAYER_MODEL_RELEASE_V1".to_vec();
    preimage.extend_from_slice(&op);
    preimage.extend_from_slice(payload);
    let signatures = vec![
        (ids[0], keys[0].sign(&preimage)),
        (ids[1], keys[1].sign(&preimage)),
    ];
    let legacy = vec![
        (ids[0], keys[0].sign(payload)),
        (ids[1], keys[1].sign(payload)),
    ];

    // The old implementation accepts this signed message for other_op even
    // though the signed preimage contains op rather than other_op.
    assert!(relayer
        .try_release(other_op, &preimage, &signatures)
        .is_err());
    assert!(relayer.try_release(op, payload, &legacy).is_err());
    assert!(relayer.try_release(other_op, payload, &signatures).is_err());
    assert!(relayer
        .try_release(op, b"changed recipient or amount", &signatures)
        .is_err());
    assert!(relayer
        .try_release(op, payload, &[signatures[0].clone(), signatures[0].clone()])
        .is_err());
    assert!(!relayer.released.contains(&op));
    assert!(!relayer.released.contains(&other_op));
    assert!(relayer.try_release(op, payload, &signatures).is_ok());
    assert!(relayer.try_release(op, payload, &signatures).is_err());
    assert!(relayer.try_release(other_op, payload, &signatures).is_err());
}
