//! Merkle inclusion proof regression tests.
//! The original Patricia/Merkle implementation committed the LEFT child's key prefix
//! into branch nodes, but verification used the TARGET key prefix at every level.
//! This made valid proofs fail whenever the target key sat in a right subtree.
//! These tests exhaustively exercise every key at every tree size.

use stellereum::cell::PatriciaTrie;

fn key_for(i: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..8].copy_from_slice(&i.to_be_bytes());
    // Scramble so ordering is not sequential
    let h = blake3::hash(&k);
    *h.as_bytes()
}

/// Every key must produce a proof that verifies against the root, for every tree size.
#[test]
fn merkle_proof_roundtrip_all_keys_all_sizes() {
    for n in 1..=40u64 {
        let mut trie = PatriciaTrie::new();
        for i in 0..n {
            let k = key_for(i);
            let v = format!("value-{i}").into_bytes();
            trie.insert(&k, &v);
        }
        let root = trie.root_hash();

        for i in 0..n {
            let k = key_for(i);
            let v = format!("value-{i}").into_bytes();
            let proof = trie
                .generate_merkle_proof(&k)
                .unwrap_or_else(|| panic!("no proof for key {i} in tree of size {n}"));
            assert!(
                PatriciaTrie::verify_merkle_proof(&root, &k, &v, &proof),
                "VALID proof failed for key {i} in tree of size {n}"
            );
        }
    }
}

/// A proof must reject a forged value for the same key.
#[test]
fn merkle_proof_rejects_forged_value() {
    let mut trie = PatriciaTrie::new();
    for i in 0..10u64 {
        trie.insert(&key_for(i), format!("v{i}").as_bytes());
    }
    let root = trie.root_hash();
    let k = key_for(7);
    let proof = trie.generate_merkle_proof(&k).unwrap();

    assert!(PatriciaTrie::verify_merkle_proof(&root, &k, b"v7", &proof));
    assert!(
        !PatriciaTrie::verify_merkle_proof(&root, &k, b"v8", &proof),
        "forged value accepted!"
    );
    assert!(
        !PatriciaTrie::verify_merkle_proof(&root, &k, b"", &proof),
        "empty forged value accepted!"
    );
}

/// A proof for one key must not verify for a different key.
#[test]
fn merkle_proof_rejects_wrong_key() {
    let mut trie = PatriciaTrie::new();
    for i in 0..16u64 {
        trie.insert(&key_for(i), format!("v{i}").as_bytes());
    }
    let root = trie.root_hash();
    let k1 = key_for(3);
    let proof = trie.generate_merkle_proof(&k1).unwrap();

    let k2 = key_for(4);
    assert!(
        !PatriciaTrie::verify_merkle_proof(&root, &k2, b"v3", &proof),
        "wrong key accepted!"
    );
}

/// Proofs must survive trie mutation (remove + insert) as long as the root is current.
#[test]
fn merkle_proof_after_remove_and_reinsert() {
    let mut trie = PatriciaTrie::new();
    for i in 0..20u64 {
        trie.insert(&key_for(i), format!("v{i}").as_bytes());
    }
    trie.remove(&key_for(5));
    trie.insert(&key_for(50), b"v50");

    let root = trie.root_hash();
    for i in 0..20u64 {
        if i == 5 {
            continue;
        }
        let k = key_for(i);
        let proof = trie.generate_merkle_proof(&k).unwrap();
        assert!(
            PatriciaTrie::verify_merkle_proof(&root, &k, format!("v{i}").as_bytes(), &proof),
            "proof failed after mutation for key {i}"
        );
    }
    // Removed key has no proof
    assert!(trie.generate_merkle_proof(&key_for(5)).is_none());
}
