//! Equivalence and boundary tests for:
//! 1. `post_quantum.rs` OPT-1 (`h_ntt` precomputation in `FALCON_PUBKEY_CACHE` and
//!    removal of redundant trailing-zero scan in `unpack_falcon_sig`), covering
//!    both `verify_pq_signature` and batch verification paths.
//! 2. `cn_vrf.rs` VRF-1 (`epoch_start_height` `saturating_mul` and
//!    `freeze_height_of_epoch` extreme-input safety).

use stellereum::cn_vrf::{
    epoch_start_height, freeze_height_of_epoch, EPOCH_LEN, V3_COMMIT_LOOKAHEAD_BLOCKS,
};
use stellereum::post_quantum::{
    verify_pq_signature, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_PUBKEY_LEN,
    FALCON512_SIG_LEN,
};
use stellereum::qc_aggregate::verify_multisig_bitmap;
use stellereum::sharding::Transaction;

/// Minimal bit-level mirror of `comp_decode` in `post_quantum.rs` used strictly
/// in tests to locate:
/// - the exact `(byte_idx, bit_mask)` of the sign bit of the first `0`
///   coefficient (to synthesize an isolated `-0` encoding), and
/// - the number of consumed compressed bytes (to locate the zero-padding tail).
fn inspect_comp_s2(payload: &[u8]) -> Option<(usize, Option<(usize, u8)>)> {
    let mut acc = 0u32;
    let mut acc_len = 0u32;
    let mut v = 0usize;
    let mut first_zero_sign: Option<(usize, u8)> = None;

    for _ in 0..512 {
        if v >= payload.len() {
            return None;
        }
        let (sign_byte_idx, sign_bit_mask) = if acc_len == 0 {
            (v, 1u8 << 7)
        } else {
            (v - 1, 1u8 << (acc_len - 1))
        };
        acc = (acc << 8) | (payload[v] as u32);
        v += 1;
        let b = acc >> acc_len;
        let s = (b & 128) != 0;
        let mut m = b & 127;

        loop {
            if acc_len == 0 {
                if v >= payload.len() {
                    return None;
                }
                acc = (acc << 8) | (payload[v] as u32);
                v += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if ((acc >> acc_len) & 1) != 0 {
                break;
            }
            m += 128;
            if m > 2047 {
                return None;
            }
        }

        if s && m == 0 {
            return None;
        }
        if !s && m == 0 && first_zero_sign.is_none() {
            first_zero_sign = Some((sign_byte_idx, sign_bit_mask));
        }
    }

    Some((v, first_zero_sign))
}

/// Sign messages with `kp` until we get a valid signature that both:
/// 1. has at least one `0` coefficient in `s2` (so we can flip ONLY that sign
///    bit to `-0`), and
/// 2. has at least one trailing zero-padding byte (`consumed < payload.len()`).
fn sign_with_zero_coeff_and_padding(kp: &FalconKeypair) -> (Vec<u8>, Vec<u8>, usize, usize, u8) {
    for attempt in 0u64..128 {
        let msg = format!("pq-opt-equivalence-msg-{attempt}").into_bytes();
        let sig = kp.sign(&msg);
        assert_eq!(sig.len(), FALCON512_SIG_LEN);
        if let Some((consumed, Some((sign_byte_idx, sign_bit_mask)))) = inspect_comp_s2(&sig[41..])
        {
            if consumed < sig[41..].len() {
                return (msg, sig, 41 + consumed, 41 + sign_byte_idx, sign_bit_mask);
            }
        }
    }
    panic!("failed to produce a Falcon-512 signature with a zero coefficient and padding tail");
}

fn build_pq_tx(fk: &FalconKeypair, sig_bytes: Vec<u8>, nonce: u64) -> Transaction {
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        fk.public_key.clone(),
        sig_bytes,
        [0x42u8; 32],
        100,
        50_000,
        nonce,
        1,
        1,
        Vec::new(),
        &DEFAULT_SALT,
    )
}

fn sign_pq_tx(fk: &FalconKeypair, nonce: u64) -> Transaction {
    let probe = build_pq_tx(fk, vec![0u8; FALCON512_SIG_LEN], nonce);
    let sig = fk.sign(&probe.signing_message());
    build_pq_tx(fk, sig, nonce)
}

#[test]
fn verify_pq_signature_equivalence_across_valid_and_adversarial_inputs() {
    // Fresh keypair so the first verify inside `sign` exercises a cold cache,
    // and repeated `verify_pq_signature` calls below exercise hot cache hits.
    let kp = FalconKeypair::generate();
    let wrong_kp = FalconKeypair::generate_from_seed(0x9A);
    let (msg, sig, pad_start_idx, zero_sign_byte_idx, zero_sign_bit_mask) =
        sign_with_zero_coeff_and_padding(&kp);

    // 1. Valid signature with repeated hot-cache checks.
    for _ in 0..8 {
        assert!(verify_pq_signature(
            PqScheme::Falcon512,
            kp.pubkey(),
            &msg,
            &sig
        ));
    }

    // 2. Damaged signatures (wrong header, damaged body, truncated, oversized, wrong message).
    let mut bad_header = sig.clone();
    bad_header[0] = 0x39;
    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        kp.pubkey(),
        &msg,
        &bad_header
    ));

    let mut damaged_body = sig.clone();
    damaged_body[45] ^= 0x5A;
    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        kp.pubkey(),
        &msg,
        &damaged_body
    ));

    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        kp.pubkey(),
        &msg,
        &sig[..FALCON512_SIG_LEN - 1]
    ));
    let mut oversized = sig.clone();
    oversized.push(0x00);
    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        kp.pubkey(),
        &msg,
        &oversized
    ));
    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        kp.pubkey(),
        b"tampered-message",
        &sig
    ));

    // 3. Non-zero padding tail (both at start of padding tail and at final byte).
    let mut nonzero_pad_start = sig.clone();
    nonzero_pad_start[pad_start_idx] ^= 0x01;
    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        kp.pubkey(),
        &msg,
        &nonzero_pad_start
    ));

    let mut nonzero_pad_end = sig.clone();
    nonzero_pad_end[FALCON512_SIG_LEN - 1] ^= 0x80;
    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        kp.pubkey(),
        &msg,
        &nonzero_pad_end
    ));

    // 4. Isolated `-0` coefficient in `s2` must be rejected by `comp_decode`.
    let mut neg_zero_sig = sig.clone();
    neg_zero_sig[zero_sign_byte_idx] ^= zero_sign_bit_mask;
    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        kp.pubkey(),
        &msg,
        &neg_zero_sig
    ));

    // 5. All-zero 40-byte nonce must be rejected.
    let mut zero_nonce_sig = sig.clone();
    zero_nonce_sig[1..41].fill(0);
    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        kp.pubkey(),
        &msg,
        &zero_nonce_sig
    ));

    // 6. Wrong public key & malformed public key (cold-cache refusal).
    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        wrong_kp.pubkey(),
        &msg,
        &sig
    ));
    let mut bad_pk_header = kp.pubkey().to_vec();
    bad_pk_header[0] = 0x19;
    assert_eq!(bad_pk_header.len(), FALCON512_PUBKEY_LEN);
    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        &bad_pk_header,
        &msg,
        &sig
    ));
    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        &kp.pubkey()[..FALCON512_PUBKEY_LEN - 1],
        &msg,
        &sig
    ));

    // 7. Disabled scheme stays fail-closed.
    assert!(!verify_pq_signature(
        PqScheme::MlDsa44,
        kp.pubkey(),
        &msg,
        &sig
    ));
}

#[test]
fn verify_pq_cold_and_hot_cache_multi_key_and_concurrent_consistency() {
    let keys: Vec<FalconKeypair> = (0..12).map(|_| FalconKeypair::generate()).collect();
    let msgs: Vec<Vec<u8>> = (0..12)
        .map(|i| format!("cache-consistency-{i}").into_bytes())
        .collect();
    let sigs: Vec<Vec<u8>> = keys
        .iter()
        .zip(msgs.iter())
        .map(|(kp, msg)| kp.sign(msg))
        .collect();

    // Repeated sequential passes (hot cache hits across multiple keys).
    for _pass in 0..4 {
        for i in 0..keys.len() {
            assert!(verify_pq_signature(
                PqScheme::Falcon512,
                keys[i].pubkey(),
                &msgs[i],
                &sigs[i]
            ));
            let wrong_idx = (i + 1) % keys.len();
            assert!(!verify_pq_signature(
                PqScheme::Falcon512,
                keys[wrong_idx].pubkey(),
                &msgs[i],
                &sigs[i]
            ));
        }
    }

    // Concurrent verification across threads reading/populating `FALCON_PUBKEY_CACHE`.
    std::thread::scope(|scope| {
        for t in 0..4usize {
            let keys_ref = &keys;
            let msgs_ref = &msgs;
            let sigs_ref = &sigs;
            scope.spawn(move || {
                for r in 0..8usize {
                    let i = (t + r) % keys_ref.len();
                    assert!(verify_pq_signature(
                        PqScheme::Falcon512,
                        keys_ref[i].pubkey(),
                        &msgs_ref[i],
                        &sigs_ref[i]
                    ));
                }
            });
        }
    });
}

#[test]
fn batch_verification_matches_scalar_for_all_defect_classes() {
    let k1 = FalconKeypair::generate();
    let k2 = FalconKeypair::generate();
    let k3 = FalconKeypair::generate();

    // 20 valid transactions (> CHUNK = 16 so `verify_signatures_batch_parallel`
    // and `verify_signatures_partitioned` exercise the parallel rayon path).
    let valid_txs: Vec<Transaction> = (0..20u64)
        .map(|n| {
            let kp = match n % 3 {
                0 => &k1,
                1 => &k2,
                _ => &k3,
            };
            sign_pq_tx(kp, n)
        })
        .collect();

    assert!(Transaction::verify_signatures_batch(&valid_txs));
    assert!(Transaction::verify_signatures_batch_parallel(&valid_txs));
    assert_eq!(
        Transaction::verify_signatures_partitioned(&valid_txs),
        vec![true; valid_txs.len()]
    );

    // Build a transaction whose signature has both a `0` coefficient and a padding tail.
    let mut target_idx = None;
    let mut target_sig = Vec::new();
    let mut pad_idx = 0usize;
    let mut neg_zero_byte = 0usize;
    let mut neg_zero_mask = 0u8;
    for attempt in 100u64..228 {
        let probe = build_pq_tx(&k1, vec![0u8; FALCON512_SIG_LEN], attempt);
        let sig = k1.sign(&probe.signing_message());
        if let Some((consumed, Some((z_byte, z_mask)))) = inspect_comp_s2(&sig[41..]) {
            if consumed < sig[41..].len() {
                target_idx = Some(attempt);
                target_sig = sig;
                pad_idx = 41 + consumed;
                neg_zero_byte = 41 + z_byte;
                neg_zero_mask = z_mask;
                break;
            }
        }
    }
    let target_nonce = target_idx.expect("must find tx signature with zero coeff and padding");

    // 1. Non-zero padding tail
    let mut bad_pad_sig = target_sig.clone();
    bad_pad_sig[pad_idx] ^= 0x01;
    // 2. `-0` coefficient
    let mut bad_neg_zero_sig = target_sig.clone();
    bad_neg_zero_sig[neg_zero_byte] ^= neg_zero_mask;
    // 3. Zero nonce
    let mut bad_zero_nonce_sig = target_sig.clone();
    bad_zero_nonce_sig[1..41].fill(0);
    // 4. Damaged body
    let mut bad_body_sig = target_sig.clone();
    bad_body_sig[50] ^= 0x3C;

    let bad_variants = [
        build_pq_tx(&k1, bad_pad_sig, target_nonce),
        build_pq_tx(&k1, bad_neg_zero_sig, target_nonce),
        build_pq_tx(&k1, bad_zero_nonce_sig, target_nonce),
        build_pq_tx(&k1, bad_body_sig, target_nonce),
        // 5. Wrong key: signature produced under k1's message packed with k2's pubkey
        build_pq_tx(&k2, target_sig.clone(), target_nonce),
    ];

    for bad_tx in bad_variants {
        assert!(
            !bad_tx.verify_signature(),
            "defective tx must fail scalar verify_signature"
        );
        let mut mixed = valid_txs.clone();
        mixed[11] = bad_tx;
        let expected: Vec<bool> = mixed.iter().map(Transaction::verify_signature).collect();
        assert!(!expected[11]);
        assert!(!Transaction::verify_signatures_batch(&mixed));
        assert!(!Transaction::verify_signatures_batch_parallel(&mixed));
        assert_eq!(Transaction::verify_signatures_partitioned(&mixed), expected);
    }

    // Also verify `qc_aggregate::verify_multisig_bitmap` rejects each defect class.
    let qc_msg = b"qc-batch-equivalence";
    let (qc_pad_msg, qc_sig_1, qc_pad_idx, qc_z_byte, qc_z_mask) =
        sign_with_zero_coeff_and_padding(&k1);
    let qc_sig_2 = k2.sign(&qc_pad_msg);
    let qc_sig_3 = k3.sign(&qc_pad_msg);
    let pks = [k1.pubkey(), k2.pubkey(), k3.pubkey()];
    let bitmap = [0b0000_0111u8];

    assert!(verify_multisig_bitmap(
        &pks,
        &qc_pad_msg,
        &[
            qc_sig_1.as_slice(),
            qc_sig_2.as_slice(),
            qc_sig_3.as_slice()
        ],
        &bitmap,
        3
    ));
    assert!(!verify_multisig_bitmap(
        &pks,
        qc_msg,
        &[
            qc_sig_1.as_slice(),
            qc_sig_2.as_slice(),
            qc_sig_3.as_slice()
        ],
        &bitmap,
        3
    ));

    let mut qc_bad_pad = qc_sig_1.clone();
    qc_bad_pad[qc_pad_idx] ^= 0x01;
    assert!(!verify_multisig_bitmap(
        &pks,
        &qc_pad_msg,
        &[
            qc_bad_pad.as_slice(),
            qc_sig_2.as_slice(),
            qc_sig_3.as_slice()
        ],
        &bitmap,
        3
    ));

    let mut qc_neg_zero = qc_sig_1.clone();
    qc_neg_zero[qc_z_byte] ^= qc_z_mask;
    assert!(!verify_multisig_bitmap(
        &pks,
        &qc_pad_msg,
        &[
            qc_neg_zero.as_slice(),
            qc_sig_2.as_slice(),
            qc_sig_3.as_slice()
        ],
        &bitmap,
        3
    ));

    let mut qc_zero_nonce = qc_sig_1.clone();
    qc_zero_nonce[1..41].fill(0);
    assert!(!verify_multisig_bitmap(
        &pks,
        &qc_pad_msg,
        &[
            qc_zero_nonce.as_slice(),
            qc_sig_2.as_slice(),
            qc_sig_3.as_slice()
        ],
        &bitmap,
        3
    ));

    // Wrong key in slot 0 (k2's signature under k1's pubkey).
    assert!(!verify_multisig_bitmap(
        &pks,
        &qc_pad_msg,
        &[
            qc_sig_2.as_slice(),
            qc_sig_2.as_slice(),
            qc_sig_3.as_slice()
        ],
        &bitmap,
        3
    ));
}

#[test]
fn cn_vrf_epoch_and_freeze_height_boundaries_never_panic_or_wrap() {
    assert_eq!(epoch_start_height(0), 0);
    assert_eq!(epoch_start_height(1), EPOCH_LEN);

    let max_exact_epoch = u64::MAX / EPOCH_LEN;
    assert_eq!(
        epoch_start_height(max_exact_epoch),
        max_exact_epoch * EPOCH_LEN
    );
    assert_eq!(epoch_start_height(max_exact_epoch + 1), u64::MAX);
    assert_eq!(epoch_start_height(u64::MAX), u64::MAX);

    assert_eq!(freeze_height_of_epoch(0), 0);
    assert_eq!(
        freeze_height_of_epoch(1),
        EPOCH_LEN - V3_COMMIT_LOOKAHEAD_BLOCKS
    );
    assert_eq!(
        freeze_height_of_epoch(u64::MAX),
        u64::MAX - V3_COMMIT_LOOKAHEAD_BLOCKS
    );
    assert!(freeze_height_of_epoch(u64::MAX) > freeze_height_of_epoch(max_exact_epoch));
}
