// W2 pure-Rust GF(2^8) Reed-Solomon `(k, n)` + `data_plane` Merkle tests.

use stellereum::data_plane;
use stellereum::data_plane::{decode_chunk, make_proof, verify_chunk};
use stellereum::data_plane_rs::{
    encode_committed, gf_add, gf_div, gf_exp, gf_mul, invert_matrix_in_place, pad_data,
    reconstruct_committed, unpad_canonical, verify_shard, CommittedCodeword, Error, ReedSolomon8,
    RsParameters, ShardPiece, GENERATING_POLYNOMIAL, GF_ORDER, MAX_CODEWORD_BYTES,
    MAX_RAW_CODEWORD_BYTES, MAX_SHARD_SIZE, MAX_TOTAL_SHARDS, MIN_DATA_SHARDS, W2_MAX_OBJECT_BYTES,
    W2_WIRE_CHUNK_SIZE,
};

fn deterministic_payload(len: usize, seed: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ u64::from(seed);
    for i in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push(((state >> 56) as u8) ^ (i as u8));
    }
    out
}

fn for_each_k_subset(n: usize, k: usize, mut f: impl FnMut(&[usize])) {
    fn rec(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, f: &mut impl FnMut(&[usize])) {
        if cur.len() == k {
            f(cur);
            return;
        }
        let remaining = k - cur.len();
        for i in start..=(n - remaining) {
            cur.push(i);
            rec(i + 1, n, k, cur, f);
            cur.pop();
        }
    }
    let mut cur = Vec::with_capacity(k);
    rec(0, n, k, &mut cur, &mut f);
}

#[test]
fn gf256_field_laws_and_matrix_inversion_kats() {
    assert_eq!(GENERATING_POLYNOMIAL, 0x1D);
    assert_eq!(GF_ORDER, 256);
    assert_eq!(MIN_DATA_SHARDS, 1);
    assert_eq!(MAX_TOTAL_SHARDS, 256);
    assert_eq!(W2_MAX_OBJECT_BYTES, data_plane::MAX_DATA_SIZE);
    assert_eq!(W2_WIRE_CHUNK_SIZE, 256 * 1024);
    assert_eq!(MAX_SHARD_SIZE, data_plane::MAX_CHUNK_SIZE);
    assert_eq!(MAX_CODEWORD_BYTES, data_plane::MAX_DATA_SIZE);
    assert_eq!(MAX_RAW_CODEWORD_BYTES, 2 * W2_MAX_OBJECT_BYTES);

    // Exhaustive multiplicative inverse, zero, and identity laws over GF(2^8).
    assert_eq!(gf_div(0, 1), Ok(0));
    assert_eq!(gf_div(1, 0), Err(Error::SingularMatrix));
    assert_eq!(gf_exp(0, 0), 1);
    assert_eq!(gf_exp(0, 5), 0);
    assert_eq!(gf_exp(2, 8), 0x1D);

    for a in 0u8..=255 {
        assert_eq!(gf_add(a, a), 0);
        assert_eq!(gf_mul(a, 0), 0);
        assert_eq!(gf_mul(a, 1), a);
        if a != 0 {
            let inv = gf_div(1, a).unwrap();
            assert_eq!(gf_mul(a, inv), 1);
            assert_eq!(gf_exp(a, 255), 1);
        }
    }

    // Known-answer matrix inversion vectors matching `reed-solomon-erasure::galois_8` (0x1D).
    let mut m3 = vec![56, 23, 98, 3, 100, 200, 45, 201, 123];
    invert_matrix_in_place(&mut m3, 3).unwrap();
    assert_eq!(m3, vec![175, 133, 33, 130, 13, 245, 112, 35, 126]);

    // Matrix requiring multiple row swaps during Gauss-Jordan elimination.
    let mut m5 = vec![
        1, 0, 0, 0, 0, //
        0, 1, 0, 0, 0, //
        0, 0, 0, 1, 0, //
        0, 0, 0, 0, 1, //
        7, 7, 6, 6, 1, //
    ];
    invert_matrix_in_place(&mut m5, 5).unwrap();
    assert_eq!(
        m5,
        vec![
            1, 0, 0, 0, 0, //
            0, 1, 0, 0, 0, //
            123, 123, 1, 122, 122, //
            0, 0, 1, 0, 0, //
            0, 0, 0, 1, 0, //
        ]
    );

    // Singular matrix and invalid dimensions are rejected.
    let mut singular = vec![4, 2, 12, 6];
    assert_eq!(
        invert_matrix_in_place(&mut singular, 2),
        Err(Error::SingularMatrix)
    );
    assert_eq!(
        invert_matrix_in_place(&mut [], 0),
        Err(Error::InvalidParameters)
    );
    assert_eq!(
        invert_matrix_in_place(&mut [1, 2, 3], 2),
        Err(Error::InvalidParameters)
    );

    // Vandermonde systematic (2, 4) KAT matching 0x1D.
    let rs = ReedSolomon8::new(2, 4).unwrap();
    assert_eq!(rs.data_shards(), 2);
    assert_eq!(rs.parity_shards(), 2);
    assert_eq!(rs.total_shards(), 4);
    assert_eq!(rs.parity_row(0), Some([3, 2].as_slice()));
    assert_eq!(rs.parity_row(1), Some([2, 3].as_slice()));
    assert_eq!(rs.parity_row(2), None);

    let mut shards = vec![vec![0x01], vec![0x02], vec![0x00], vec![0x00]];
    rs.encode_shards(&mut shards).unwrap();
    assert_eq!(shards, vec![vec![0x01], vec![0x02], vec![0x07], vec![0x04]]);
    assert_eq!(rs.verify_shards(&shards), Ok(true));
}

#[test]
fn exhaustive_k_of_n_subsets_for_2_4_3_5_and_4_7() {
    let configs = [(2u16, 4u16), (3u16, 5u16), (4u16, 7u16)];
    let sizes = [0usize, 1, 13, 37, 256 * 1024 + 17];

    for &(k, n) in &configs {
        let rs = ReedSolomon8::new(usize::from(k), usize::from(n)).unwrap();
        for (size_idx, &len) in sizes.iter().enumerate() {
            let payload = deterministic_payload(len, (k as u8) ^ (n as u8) ^ (size_idx as u8));
            let cw: CommittedCodeword = encode_committed(&payload, k, n).unwrap();
            assert_eq!(cw.params.orig_len, len as u64);
            assert_eq!(cw.params.k, k);
            assert_eq!(cw.params.n, n);
            assert_eq!(cw.params.parity_count(), Ok(n - k));

            let mut subset_count = 0usize;
            for_each_k_subset(usize::from(n), usize::from(k), |subset| {
                subset_count += 1;

                // 1. Verify each shard individually via both `verify_shard` and `data_plane::verify_chunk`.
                let mut pieces: Vec<ShardPiece<'_>> = Vec::with_capacity(usize::from(k));
                for &idx in subset {
                    let idx_u32 = idx as u32;
                    assert_eq!(
                        verify_shard(
                            cw.params,
                            idx_u32,
                            &cw.shards[idx],
                            &cw.proofs[idx],
                            &cw.chunk_root,
                        ),
                        Ok(())
                    );
                    let chunk = cw.chunk(idx_u32).unwrap();
                    assert_eq!(verify_chunk(chunk, &cw.proofs[idx], &cw.chunk_root), Ok(()));
                    pieces.push(cw.piece(idx_u32).unwrap());
                }

                // 2. Full committed reconstruction (with canonical unpadding + codeword/root re-encoding).
                let recovered = reconstruct_committed(cw.params, &cw.chunk_root, &pieces).unwrap();
                assert_eq!(recovered, payload);

                // 3. Direct low-level RS reconstruction (`reconstruct_data` and `reconstruct`).
                let mut raw_slots: Vec<Option<Vec<u8>>> = vec![None; usize::from(n)];
                for &idx in subset {
                    raw_slots[idx] = Some(cw.shards[idx].clone());
                }
                let mut data_only_slots = raw_slots.clone();
                rs.reconstruct_data(&mut data_only_slots).unwrap();
                let data_shards: Vec<Vec<u8>> = data_only_slots
                    .into_iter()
                    .take(usize::from(k))
                    .map(Option::unwrap)
                    .collect();
                assert_eq!(unpad_canonical(&data_shards, cw.params).unwrap(), payload);

                rs.reconstruct(&mut raw_slots).unwrap();
                let full: Vec<Vec<u8>> = raw_slots.into_iter().map(Option::unwrap).collect();
                assert_eq!(full, cw.shards);
            });

            // Verify exact binomial counts: C(4,2)=6, C(5,3)=10, C(7,4)=35.
            let expected_subsets = match (k, n) {
                (2, 4) => 6,
                (3, 5) => 10,
                (4, 7) => 35,
                _ => unreachable!(),
            };
            assert_eq!(subset_count, expected_subsets);
        }
    }
}

#[test]
fn boundary_geometries_wire_chunks_and_data_plane_proof_equivalence() {
    // Minimal (1, 2), max-parity (1, 256), W2-typical (64, 96) multi-MiB, and (200, 256).
    let payload_small = deterministic_payload(99, 0x42);
    for (k, n) in [(1u16, 2u16), (1u16, 256u16), (200u16, 256u16)] {
        let cw = encode_committed(&payload_small, k, n).unwrap();
        let flat: Vec<u8> = cw.shards.concat();
        let (dp_root, _) = make_proof(&flat, cw.params.shard_len, 0).unwrap();
        assert_eq!(cw.chunk_root, dp_root);

        for idx in 0..u32::from(n) {
            let wire = cw.encode_wire_chunk(idx).unwrap();
            let decoded = decode_chunk(&wire).unwrap();
            assert_eq!(decoded, cw.chunk(idx).unwrap());
            let (root_i, proof_i) = make_proof(&flat, cw.params.shard_len, idx).unwrap();
            assert_eq!(root_i, cw.chunk_root);
            assert_eq!(proof_i, cw.proofs[idx as usize]);
        }

        // Reconstruct strictly from parity shards (when n >= 2k) or last k shards.
        let start = usize::from(n - k);
        let pieces: Vec<ShardPiece<'_>> = (start..usize::from(n))
            .map(|i| cw.piece(i as u32).unwrap())
            .collect();
        let recovered = reconstruct_committed(cw.params, &cw.chunk_root, &pieces).unwrap();
        assert_eq!(recovered, payload_small);
    }

    // (64, 96) with 8 MiB + 13 B payload (12 MiB total codeword <= MAX_CODEWORD_BYTES).
    let large_payload = deterministic_payload(8 * 1024 * 1024 + 13, 0x77);
    let cw = encode_committed(&large_payload, 64, 96).unwrap();
    let mut pieces = Vec::with_capacity(64);
    for i in 0..32u32 {
        pieces.push(cw.piece(i).unwrap());
    }
    for i in 64..96u32 {
        pieces.push(cw.piece(i).unwrap());
    }
    let recovered = reconstruct_committed(cw.params, &cw.chunk_root, &pieces).unwrap();
    assert_eq!(recovered, large_payload);

    // Default geometry check & raw (255, 256) check.
    let def_empty = RsParameters::default_for_len(0).unwrap();
    assert_eq!(def_empty.k, 4);
    assert_eq!(def_empty.n, 6);
    assert_eq!(def_empty.shard_len, 1);
    assert_eq!(def_empty.padded_data_len(), Ok(4));
    assert_eq!(def_empty.total_codeword_len(), Ok(6));

    let def_8m = RsParameters::default_for_len(8 * 1024 * 1024).unwrap();
    assert_eq!(def_8m.k, 32);
    assert_eq!(def_8m.n, 48);
    assert_eq!(def_8m.shard_len, W2_WIRE_CHUNK_SIZE);

    let rs_max = ReedSolomon8::new(255, 256).unwrap();
    let mut max_shards: Vec<Vec<u8>> = (0..256)
        .map(|i| vec![(i as u8).wrapping_mul(3); 7])
        .collect();
    rs_max.encode_shards(&mut max_shards).unwrap();
    assert_eq!(rs_max.verify_shards(&max_shards), Ok(true));
    let mut slots: Vec<Option<Vec<u8>>> = max_shards.iter().cloned().map(Some).collect();
    slots[17] = None;
    rs_max.reconstruct_data(&mut slots).unwrap();
    assert_eq!(slots[17].as_ref().unwrap(), &max_shards[17]);
}

#[test]
fn rejects_fewer_than_k_shards() {
    let payload = b"stellereum-rs-too-few";
    let cw = encode_committed(payload, 3, 5).unwrap();
    for count in 0..3 {
        let pieces: Vec<ShardPiece<'_>> = (0..count).map(|i| cw.piece(i as u32).unwrap()).collect();
        assert_eq!(
            reconstruct_committed(cw.params, &cw.chunk_root, &pieces),
            Err(Error::TooFewShards)
        );
    }

    let rs = ReedSolomon8::new(3, 5).unwrap();
    let mut slots: Vec<Option<Vec<u8>>> = vec![
        Some(cw.shards[0].clone()),
        None,
        Some(cw.shards[2].clone()),
        None,
        None,
    ];
    assert_eq!(rs.reconstruct_data(&mut slots), Err(Error::TooFewShards));
}

#[test]
fn rejects_duplicate_and_out_of_range_indices() {
    let payload = b"duplicate-and-oob-test";
    let cw = encode_committed(payload, 3, 5).unwrap();

    // Exact k pieces, but two share index 0.
    let dup_k = vec![
        cw.piece(0).unwrap(),
        cw.piece(0).unwrap(),
        cw.piece(1).unwrap(),
    ];
    assert_eq!(
        reconstruct_committed(cw.params, &cw.chunk_root, &dup_k),
        Err(Error::DuplicateIndex)
    );

    // k + 1 pieces, still rejected if any duplicate index exists.
    let dup_extra = vec![
        cw.piece(0).unwrap(),
        cw.piece(1).unwrap(),
        cw.piece(2).unwrap(),
        cw.piece(1).unwrap(),
    ];
    assert_eq!(
        reconstruct_committed(cw.params, &cw.chunk_root, &dup_extra),
        Err(Error::DuplicateIndex)
    );

    // Out-of-range indices.
    for bad_idx in [5u32, 6, 255, 256, u32::MAX] {
        assert_eq!(
            verify_shard(
                cw.params,
                bad_idx,
                &cw.shards[0],
                &cw.proofs[0],
                &cw.chunk_root
            ),
            Err(Error::IndexOutOfBounds)
        );
        let oob_pieces = vec![
            cw.piece(0).unwrap(),
            cw.piece(1).unwrap(),
            ShardPiece {
                index: bad_idx,
                payload: &cw.shards[2],
                proof: &cw.proofs[2],
            },
        ];
        assert_eq!(
            reconstruct_committed(cw.params, &cw.chunk_root, &oob_pieces),
            Err(Error::IndexOutOfBounds)
        );
    }
}

#[test]
fn rejects_wrong_shard_length() {
    let payload = b"wrong-shard-len";
    let cw = encode_committed(payload, 3, 5).unwrap();
    let shard_len = cw.params.shard_len as usize;

    let mut too_short = cw.shards[0].clone();
    too_short.pop();
    let mut too_long = cw.shards[0].clone();
    too_long.push(0);

    for bad_payload in [b"".as_slice(), too_short.as_slice(), too_long.as_slice()] {
        assert_eq!(
            verify_shard(cw.params, 0, bad_payload, &cw.proofs[0], &cw.chunk_root),
            Err(Error::InvalidShardLength)
        );
        let pieces = vec![
            ShardPiece {
                index: 0,
                payload: bad_payload,
                proof: &cw.proofs[0],
            },
            cw.piece(1).unwrap(),
            cw.piece(2).unwrap(),
        ];
        assert_eq!(
            reconstruct_committed(cw.params, &cw.chunk_root, &pieces),
            Err(Error::InvalidShardLength)
        );
    }

    // Mismatched shard length in raw `ReedSolomon8`.
    let rs = ReedSolomon8::new(3, 5).unwrap();
    let mut bad_shards = cw.shards.clone();
    bad_shards[4] = vec![0u8; shard_len + 1];
    assert_eq!(
        rs.encode_shards(&mut bad_shards),
        Err(Error::InvalidShardLength)
    );
    assert_eq!(
        rs.verify_shards(&bad_shards),
        Err(Error::InvalidShardLength)
    );
}

#[test]
fn rejects_corrupted_parity_shard_before_rs_and_recovers_from_valid_subset() {
    let payload = deterministic_payload(101, 0x11);
    let cw = encode_committed(&payload, 3, 5).unwrap();

    let mut bad_parity = cw.shards[3].clone();
    bad_parity[0] ^= 0x01;

    assert_eq!(
        verify_shard(cw.params, 3, &bad_parity, &cw.proofs[3], &cw.chunk_root),
        Err(Error::InvalidProof)
    );

    let pieces_with_bad_parity = vec![
        cw.piece(1).unwrap(),
        cw.piece(2).unwrap(),
        ShardPiece {
            index: 3,
            payload: &bad_parity,
            proof: &cw.proofs[3],
        },
    ];
    assert_eq!(
        reconstruct_committed(cw.params, &cw.chunk_root, &pieces_with_bad_parity),
        Err(Error::InvalidProof)
    );

    // Valid replacement parity shard (index 4) recovers the exact payload.
    let valid_pieces = vec![
        cw.piece(1).unwrap(),
        cw.piece(2).unwrap(),
        cw.piece(4).unwrap(),
    ];
    assert_eq!(
        reconstruct_committed(cw.params, &cw.chunk_root, &valid_pieces).unwrap(),
        payload
    );
}

#[test]
fn rejects_nonzero_canonical_padding() {
    // orig_len = 5, k = 3, n = 5 -> shard_len = 2, padded_data_len = 6; byte index 5 is pad.
    let params = RsParameters::new(5, 3, 5).unwrap();
    let dp_params = params.data_plane_parameters().unwrap();
    let rs = ReedSolomon8::new(3, 5).unwrap();

    // Malicious encoder puts non-zero byte (0xAA) into pad byte 5 and builds valid RS + Merkle.
    let mut malicious_shards = vec![
        vec![1, 2],
        vec![3, 4],
        vec![5, 0xAA],
        vec![0, 0],
        vec![0, 0],
    ];
    rs.encode_shards(&mut malicious_shards).unwrap();
    assert_eq!(rs.verify_shards(&malicious_shards), Ok(true));

    let flat = malicious_shards.concat();
    let (root, _) = make_proof(&flat, params.shard_len, 0).unwrap();
    let proofs: Vec<_> = (0..5)
        .map(|i| make_proof(&flat, params.shard_len, i).unwrap().1)
        .collect();
    let pieces: Vec<_> = [0usize, 3, 4]
        .iter()
        .map(|&i| ShardPiece {
            index: i as u32,
            payload: &malicious_shards[i],
            proof: &proofs[i],
        })
        .collect();

    assert_eq!(
        reconstruct_committed(params, &root, &pieces),
        Err(Error::NonCanonicalPadding)
    );

    // Direct `unpad_canonical` on empty orig_len = 0 with non-zero pad byte must fail.
    let empty_params = RsParameters::new(0, 2, 4).unwrap();
    assert_eq!(
        unpad_canonical(&[vec![0], vec![1]], empty_params),
        Err(Error::NonCanonicalPadding)
    );
    assert_eq!(dp_params.chunk_count(), Ok(5));
}

#[test]
fn rejects_tampered_orig_len() {
    // orig_len = 5, k = 3, n = 5, shard_len = 2.
    let payload = b"ABCDE";
    let cw = encode_committed(payload, 3, 5).unwrap();
    let pieces: Vec<_> = (0..3).map(|i| cw.piece(i).unwrap()).collect();

    // Tamper orig_len down to 4 (same shard_len = 2, byte 'E' sits in pad position -> rejected).
    let tampered_down = RsParameters {
        orig_len: 4,
        ..cw.params
    };
    assert_eq!(
        reconstruct_committed(tampered_down, &cw.chunk_root, &pieces),
        Err(Error::NonCanonicalPadding)
    );

    // Tamper orig_len to 3 (requires shard_len = 1, mismatched with shard_len = 2).
    let tampered_mismatch_low = RsParameters {
        orig_len: 3,
        ..cw.params
    };
    assert_eq!(
        reconstruct_committed(tampered_mismatch_low, &cw.chunk_root, &pieces),
        Err(Error::InvalidParameters)
    );

    // Tamper orig_len up to 7 (exceeds k * shard_len = 6 and mismatches shard_len).
    let tampered_up = RsParameters {
        orig_len: 7,
        ..cw.params
    };
    assert_eq!(
        reconstruct_committed(tampered_up, &cw.chunk_root, &pieces),
        Err(Error::InvalidParameters)
    );

    // `pad_data` also rejects mismatched slice length vs `params.orig_len`.
    assert_eq!(pad_data(b"ABCD", cw.params), Err(Error::InvalidParameters));
}

#[test]
fn rejects_forged_merkle_proof_and_forged_root_passing_k_shards_individually() {
    let payload = deterministic_payload(63, 0x55);
    let cw = encode_committed(&payload, 3, 5).unwrap();

    // 1. Tampered proof fails `verify_shard` and `reconstruct_committed`.
    let mut bad_proof = cw.proofs[0].clone();
    bad_proof[0][0] ^= 0x80;
    assert_eq!(
        verify_shard(cw.params, 0, &cw.shards[0], &bad_proof, &cw.chunk_root),
        Err(Error::InvalidProof)
    );
    let mut bad_root = cw.chunk_root;
    bad_root[0] ^= 0x01;
    assert_eq!(
        verify_shard(cw.params, 0, &cw.shards[0], &cw.proofs[0], &bad_root),
        Err(Error::InvalidProof)
    );

    // 2. Forged root over inconsistent codeword:
    //    k data shards (0..3) are untouched, parity shard 3 is corrupted BEFORE Merkle tree
    //    construction. Thus every shard in 0..3 individually passes `verify_shard` and
    //    `data_plane::verify_chunk` against `forged_root`, yet re-encoding disagrees with
    //    `forged_root` -> `reconstruct_committed` MUST return `Err(Error::InconsistentCodeword)`.
    let mut forged_shards = cw.shards.clone();
    forged_shards[3][0] ^= 0xFF;
    let forged_flat = forged_shards.concat();
    let (forged_root, _) = make_proof(&forged_flat, cw.params.shard_len, 0).unwrap();
    let forged_proofs: Vec<_> = (0..5)
        .map(|i| make_proof(&forged_flat, cw.params.shard_len, i).unwrap().1)
        .collect();

    let forged_k_pieces: Vec<_> = (0..3)
        .map(|i| {
            assert_eq!(
                verify_shard(
                    cw.params,
                    i,
                    &forged_shards[i as usize],
                    &forged_proofs[i as usize],
                    &forged_root,
                ),
                Ok(())
            );
            ShardPiece {
                index: i,
                payload: &forged_shards[i as usize],
                proof: &forged_proofs[i as usize],
            }
        })
        .collect();

    assert_eq!(
        reconstruct_committed(cw.params, &forged_root, &forged_k_pieces),
        Err(Error::InconsistentCodeword)
    );

    // Passing k + 1 pieces (0..=3, including the forged parity shard 3 that also passes
    // `verify_shard` against `forged_root`) is likewise rejected as `InconsistentCodeword`.
    let mut forged_k_plus_1 = forged_k_pieces;
    assert_eq!(
        verify_shard(
            cw.params,
            3,
            &forged_shards[3],
            &forged_proofs[3],
            &forged_root
        ),
        Ok(())
    );
    forged_k_plus_1.push(ShardPiece {
        index: 3,
        payload: &forged_shards[3],
        proof: &forged_proofs[3],
    });
    assert_eq!(
        reconstruct_committed(cw.params, &forged_root, &forged_k_plus_1),
        Err(Error::InconsistentCodeword)
    );
}

#[test]
fn rejects_invalid_k_n_and_integer_overflow_before_allocation() {
    // k = 0, k = n, k > n, n > 256.
    for (k, n) in [
        (0u16, 2u16),
        (0, 0),
        (4, 4),
        (5, 4),
        (256, 256),
        (1, 257),
        (200, 257),
        (1, u16::MAX),
    ] {
        assert_eq!(
            RsParameters::new(16, k, n),
            Err(Error::InvalidParameters),
            "expected InvalidParameters for (k={k}, n={n})"
        );
        assert_eq!(
            ReedSolomon8::new(usize::from(k), usize::from(n)),
            Err(Error::InvalidParameters)
        );
        assert_eq!(
            encode_committed(b"abc", k, n),
            Err(Error::InvalidParameters)
        );
    }

    // Object size & codeword size overflows / bounds rejected pre-allocation.
    assert_eq!(
        RsParameters::new(W2_MAX_OBJECT_BYTES + 1, 4, 6),
        Err(Error::InvalidParameters)
    );
    assert_eq!(
        RsParameters::new(u64::MAX, 4, 6),
        Err(Error::InvalidParameters)
    );
    assert_eq!(
        RsParameters::default_for_len(W2_MAX_OBJECT_BYTES + 1),
        Err(Error::InvalidParameters)
    );
    // k = 1, n = 2 with 16 MiB object -> shard_len = 16 MiB > MAX_SHARD_SIZE (1 MiB).
    assert_eq!(
        RsParameters::new(W2_MAX_OBJECT_BYTES, 1, 2),
        Err(Error::InvalidParameters)
    );
    // k = 16, n = 17 with 16 MiB object -> shard_len = 1 MiB, total_codeword = 17 MiB > MAX_CODEWORD_BYTES.
    assert_eq!(
        RsParameters::new(W2_MAX_OBJECT_BYTES, 16, 17),
        Err(Error::InvalidParameters)
    );

    // Crafted untrusted RsParameters with overflow / zero / oversized shard_len.
    for bad_params in [
        RsParameters {
            orig_len: 10,
            k: 0,
            n: 2,
            shard_len: 5,
        },
        RsParameters {
            orig_len: 10,
            k: 2,
            n: 2,
            shard_len: 5,
        },
        RsParameters {
            orig_len: 10,
            k: 2,
            n: 257,
            shard_len: 5,
        },
        RsParameters {
            orig_len: 10,
            k: 2,
            n: 4,
            shard_len: 0,
        },
        RsParameters {
            orig_len: 10,
            k: 2,
            n: 4,
            shard_len: 6, // non-canonical (expected 5)
        },
        RsParameters {
            orig_len: u64::MAX,
            k: 2,
            n: 4,
            shard_len: u32::MAX,
        },
        RsParameters {
            orig_len: 2 * u64::from(MAX_SHARD_SIZE) + 2,
            k: 2,
            n: 4,
            shard_len: MAX_SHARD_SIZE + 1,
        },
    ] {
        assert!(bad_params.validate().is_err());
        assert!(reconstruct_committed(bad_params, &[0u8; 32], &[]).is_err());
    }

    // Verify Error Display + std::error::Error implementation.
    let err_msg = format!("{}", Error::Overflow);
    assert_eq!(err_msg, "Overflow");
    let _: &dyn std::error::Error = &Error::SingularMatrix;
}
