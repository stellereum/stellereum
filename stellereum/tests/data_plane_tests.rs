// Exercised through the shared library export (`stellereum::data_plane`);
// the module's local resource limits are not a network/DA path.
use stellereum::data_plane::{
    decode_chunk, encode_chunk, make_proof, verify_chunk, Chunk, Error, Parameters, MAX_CHUNKS,
    MAX_CHUNK_SIZE, MAX_DATA_SIZE, MAX_PROOF_DEPTH,
};

#[test]
fn roundtrip_and_membership_for_empty_single_odd_and_even_trees() {
    for (data, size) in [
        (b"".as_slice(), 4),
        (b"x".as_slice(), 4),
        (b"abcdefghij".as_slice(), 4),
        (b"abcdefghijkl".as_slice(), 3),
    ] {
        let parameters = Parameters {
            total_len: data.len() as u64,
            chunk_size: size,
        };
        for index in 0..parameters.chunk_count().unwrap() {
            let start = index as usize * size as usize;
            let end = start + parameters.payload_len(index).unwrap();
            let chunk = Chunk {
                parameters,
                index,
                payload: &data[start..end],
            };
            let encoded = encode_chunk(chunk).unwrap();
            let decoded = decode_chunk(&encoded).unwrap();
            assert_eq!(decoded, chunk);
            let (root, proof) = make_proof(data, size, index).unwrap();
            assert_eq!(verify_chunk(decoded, &proof, &root), Ok(()));
            assert_eq!(root, make_proof(data, size, 0).unwrap().0);
        }
    }
}

#[test]
fn rejects_corruption_wrong_root_and_metadata() {
    let data = b"abcdefghij";
    let parameters = Parameters {
        total_len: 10,
        chunk_size: 4,
    };
    let chunk = Chunk {
        parameters,
        index: 0,
        payload: &data[..4],
    };
    let (root, proof) = make_proof(data, 4, 0).unwrap();
    let mut bad_proof = proof.clone();
    bad_proof[0][0] ^= 1;
    assert_eq!(
        verify_chunk(chunk, &bad_proof, &root),
        Err(Error::InvalidProof)
    );
    let mut bad_root = root;
    bad_root[0] ^= 1;
    assert_eq!(
        verify_chunk(chunk, &proof, &bad_root),
        Err(Error::InvalidProof)
    );
    let corrupt = Chunk {
        payload: b"abce",
        ..chunk
    };
    assert_eq!(
        verify_chunk(corrupt, &proof, &root),
        Err(Error::InvalidProof)
    );
    let different_index = Chunk { index: 1, ..chunk };
    assert_eq!(
        verify_chunk(different_index, &proof, &root),
        Err(Error::InvalidProof)
    );
    let different_params = Chunk {
        parameters: Parameters {
            total_len: 11,
            chunk_size: 4,
        },
        ..chunk
    };
    assert_eq!(
        verify_chunk(different_params, &proof, &root),
        Err(Error::InvalidProof)
    );
}

#[test]
fn rejects_bad_depth_and_noncanonical_odd_sibling() {
    let data = b"abcdefghij";
    let chunk = Chunk {
        parameters: Parameters {
            total_len: 10,
            chunk_size: 4,
        },
        index: 2,
        payload: b"ij",
    };
    let (root, proof) = make_proof(data, 4, 2).unwrap();
    assert_eq!(
        verify_chunk(chunk, &proof[..1], &root),
        Err(Error::InvalidProof)
    );
    let too_deep = vec![[0; 32]; MAX_PROOF_DEPTH + 1];
    assert_eq!(
        verify_chunk(chunk, &too_deep, &root),
        Err(Error::InvalidProof)
    );
    let mut bad = proof;
    bad[0][0] ^= 1;
    assert_eq!(verify_chunk(chunk, &bad, &root), Err(Error::InvalidProof));
}

#[test]
fn rejects_malformed_encodings_before_copying_payload() {
    let chunk = Chunk {
        parameters: Parameters {
            total_len: 3,
            chunk_size: 4,
        },
        index: 0,
        payload: b"abc",
    };
    let encoded = encode_chunk(chunk).unwrap();
    for len in 0..encoded.len() {
        assert!(decode_chunk(&encoded[..len]).is_err());
    }
    let mut bad = encoded.clone();
    bad[0] ^= 1;
    assert_eq!(decode_chunk(&bad), Err(Error::InvalidEncoding));
    bad = encoded.clone();
    bad[4] += 1;
    assert_eq!(decode_chunk(&bad), Err(Error::InvalidEncoding));
    bad = encoded.clone();
    bad[21..25].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_chunk(&bad), Err(Error::InvalidLength));
    bad = encoded.clone();
    bad[17..21].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_chunk(&bad), Err(Error::IndexOutOfBounds));
    bad = encoded.clone();
    bad[5..13].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(decode_chunk(&bad), Err(Error::InvalidParameters));
    bad = encoded;
    bad.push(0);
    assert_eq!(decode_chunk(&bad), Err(Error::InvalidLength));
}

#[test]
fn validates_bounds_and_overflow_inputs() {
    for parameters in [
        Parameters {
            total_len: 0,
            chunk_size: 0,
        },
        Parameters {
            total_len: 1,
            chunk_size: MAX_CHUNK_SIZE + 1,
        },
        Parameters {
            total_len: MAX_DATA_SIZE + 1,
            chunk_size: 1,
        },
        Parameters {
            total_len: u64::MAX,
            chunk_size: u32::MAX,
        },
        Parameters {
            total_len: u64::from(MAX_CHUNKS) + 1,
            chunk_size: 1,
        },
    ] {
        assert_eq!(parameters.chunk_count(), Err(Error::InvalidParameters));
    }
    let max = Parameters {
        total_len: u64::from(MAX_CHUNKS),
        chunk_size: 1,
    };
    assert_eq!(max.chunk_count(), Ok(MAX_CHUNKS));
    assert_eq!(max.payload_len(MAX_CHUNKS), Err(Error::IndexOutOfBounds));
    assert_eq!(max.payload_len(u32::MAX), Err(Error::IndexOutOfBounds));
    assert_eq!(make_proof(b"abc", 0, 0), Err(Error::InvalidParameters));
    assert_eq!(make_proof(b"abc", 2, 2), Err(Error::IndexOutOfBounds));
    let invalid_chunk = Chunk {
        parameters: Parameters {
            total_len: 3,
            chunk_size: 2,
        },
        index: 0,
        payload: b"a",
    };
    assert_eq!(encode_chunk(invalid_chunk), Err(Error::InvalidLength));
    assert_eq!(
        verify_chunk(invalid_chunk, &[], &[0; 32]),
        Err(Error::InvalidLength)
    );
}

// These helpers deliberately do not use the implementation's private hash
// functions, so the tests also check the specified domains and field order.
fn reference_leaf(chunk: Chunk<'_>) -> [u8; 32] {
    let mut bytes = b"stellereum/data-plane/v1/leaf\0".to_vec();
    bytes.push(1);
    bytes.extend_from_slice(&chunk.parameters.total_len.to_le_bytes());
    bytes.extend_from_slice(&chunk.parameters.chunk_size.to_le_bytes());
    bytes.extend_from_slice(&chunk.index.to_le_bytes());
    bytes.extend_from_slice(&(chunk.payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(chunk.payload);
    *blake3::hash(&bytes).as_bytes()
}

fn reference_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut bytes = b"stellereum/data-plane/v1/node\0".to_vec();
    bytes.extend_from_slice(left);
    bytes.extend_from_slice(right);
    *blake3::hash(&bytes).as_bytes()
}

#[test]
fn canonical_encoding_and_domain_separated_hashes() {
    let parameters = Parameters {
        total_len: 3,
        chunk_size: 2,
    };
    let first = Chunk {
        parameters,
        index: 0,
        payload: b"ab",
    };
    let last = Chunk {
        parameters,
        index: 1,
        payload: b"c",
    };
    assert_eq!(
        encode_chunk(first).unwrap(),
        b"SDP1\x01\x03\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\x02\0\0\0ab"
    );
    let first_hash = reference_leaf(first);
    let last_hash = reference_leaf(last);
    let expected_root = reference_node(&first_hash, &last_hash);
    let (root, proof) = make_proof(b"abc", 2, 0).unwrap();
    assert_eq!(root, expected_root);
    assert_eq!(proof, vec![last_hash]);
    assert_ne!(root, reference_node(&last_hash, &first_hash));
    assert_eq!(verify_chunk(first, &[last_hash], &expected_root), Ok(()));
    // A single leaf is not an internal node, even when the inputs are equal.
    let (single_root, _) = make_proof(b"ab", 2, 0).unwrap();
    let single = Chunk {
        parameters: Parameters {
            total_len: 2,
            chunk_size: 2,
        },
        ..first
    };
    assert_eq!(single_root, reference_leaf(single));
    assert_ne!(single_root, reference_node(&single_root, &single_root));
}

#[test]
fn rejects_noncanonical_duplicate_even_if_attacker_supplies_matching_root() {
    // Five leaves duplicate at two different levels along the final path.
    let data = b"abcde";
    let chunk = Chunk {
        parameters: Parameters {
            total_len: 5,
            chunk_size: 1,
        },
        index: 4,
        payload: b"e",
    };
    let (root, proof) = make_proof(data, 1, 4).unwrap();
    assert_eq!(verify_chunk(chunk, &proof, &root), Ok(()));
    let leaf = reference_leaf(chunk);
    let duplicated = reference_node(&leaf, &leaf);
    assert_eq!(proof[0], leaf);
    assert_eq!(proof[1], duplicated);

    let mut forged = proof.clone();
    forged[0][0] ^= 1;
    let forged_first = reference_node(&leaf, &forged[0]);
    // Make the second duplicate canonical for the forged intermediate node.
    forged[1] = forged_first;
    let forged_second = reference_node(&forged_first, &forged_first);
    let forged_root = reference_node(&proof[2], &forged_second);
    assert_eq!(
        verify_chunk(chunk, &forged, &forged_root),
        Err(Error::InvalidProof)
    );

    let mut forged = proof;
    forged[1][0] ^= 1;
    let forged_second = reference_node(&duplicated, &forged[1]);
    let forged_root = reference_node(&forged[2], &forged_second);
    assert_eq!(
        verify_chunk(chunk, &forged, &forged_root),
        Err(Error::InvalidProof)
    );
}

#[test]
fn membership_does_not_authenticate_a_caller_supplied_root() {
    let trusted_data = b"good";
    let attacker_data = b"evil";
    let parameters = Parameters {
        total_len: 4,
        chunk_size: 2,
    };
    let attacker_chunk = Chunk {
        parameters,
        index: 0,
        payload: &attacker_data[..2],
    };
    let (trusted_root, _) = make_proof(trusted_data, 2, 0).unwrap();
    let (attacker_root, attacker_proof) = make_proof(attacker_data, 2, 0).unwrap();
    assert_ne!(trusted_root, attacker_root);
    assert_eq!(
        verify_chunk(attacker_chunk, &attacker_proof, &trusted_root),
        Err(Error::InvalidProof)
    );
    // Success here is membership only; the caller must authenticate the root.
    assert_eq!(
        verify_chunk(attacker_chunk, &attacker_proof, &attacker_root),
        Ok(())
    );
}

#[test]
fn boundary_sizes_indices_and_proof_lengths() {
    let empty = Chunk {
        parameters: Parameters {
            total_len: 0,
            chunk_size: MAX_CHUNK_SIZE,
        },
        index: 0,
        payload: b"",
    };
    let (root, proof) = make_proof(b"", MAX_CHUNK_SIZE, 0).unwrap();
    assert!(proof.is_empty());
    assert_eq!(root, reference_leaf(empty));
    assert_eq!(verify_chunk(empty, &proof, &root), Ok(()));
    assert_eq!(
        verify_chunk(Chunk { index: 1, ..empty }, &proof, &root),
        Err(Error::IndexOutOfBounds)
    );
    assert_eq!(
        verify_chunk(empty, &[[0; 32]], &root),
        Err(Error::InvalidProof)
    );

    let data = vec![0x5a; MAX_DATA_SIZE as usize];
    let parameters = Parameters {
        total_len: MAX_DATA_SIZE,
        chunk_size: MAX_CHUNK_SIZE,
    };
    let index = parameters.chunk_count().unwrap() - 1;
    let start = index as usize * MAX_CHUNK_SIZE as usize;
    let last = Chunk {
        parameters,
        index,
        payload: &data[start..],
    };
    let (root, proof) = make_proof(&data, MAX_CHUNK_SIZE, index).unwrap();
    assert_eq!(decode_chunk(&encode_chunk(last).unwrap()).unwrap(), last);
    assert_eq!(verify_chunk(last, &proof, &root), Ok(()));
    assert_eq!(
        make_proof(&data, MAX_CHUNK_SIZE, u32::MAX),
        Err(Error::IndexOutOfBounds)
    );

    let data = vec![0x7b; MAX_CHUNKS as usize];
    let chunk = Chunk {
        parameters: Parameters {
            total_len: u64::from(MAX_CHUNKS),
            chunk_size: 1,
        },
        index: MAX_CHUNKS - 1,
        payload: &data[data.len() - 1..],
    };
    let (root, proof) = make_proof(&data, 1, chunk.index).unwrap();
    assert_eq!(proof.len(), MAX_PROOF_DEPTH);
    assert_eq!(verify_chunk(chunk, &proof, &root), Ok(()));
    assert_eq!(
        verify_chunk(chunk, &proof[1..], &root),
        Err(Error::InvalidProof)
    );
}
