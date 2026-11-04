//! Property tests for compressed Patricia v2 (relative-skip model).
use std::collections::HashMap;
use stellereum::cpat2::{CompressedTrie, Key};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn key(&mut self) -> Key {
        let mut k = [0u8; 32];
        for c in k.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_be_bytes());
        }
        k
    }
}

#[test]
fn single_key() {
    let mut t = CompressedTrie::new();
    let k = [1u8; 32];
    t.insert(&k, b"hi");
    assert_eq!(t.get(&k), Some(b"hi".as_slice()));
    let r = t.root_hash();
    let p = t.proof(&k).unwrap();
    assert!(CompressedTrie::verify(&r, &k, b"hi", &p));
}

#[test]
fn two_keys_first_bit() {
    let mut t = CompressedTrie::new();
    let mut a = [0u8; 32];
    a[0] = 0x00;
    let mut b = [0u8; 32];
    b[0] = 0x80;
    t.insert(&a, b"a");
    t.insert(&b, b"b");
    let r = t.root_hash();
    assert!(CompressedTrie::verify(&r, &a, b"a", &t.proof(&a).unwrap()));
    assert!(CompressedTrie::verify(&r, &b, b"b", &t.proof(&b).unwrap()));
}

#[test]
fn deep_divergence_same_prefix() {
    let mut t = CompressedTrie::new();
    let mut a = [0xAAu8; 32];
    a[31] = 0x00;
    let mut b = [0xAAu8; 32];
    b[31] = 0x01;
    t.insert(&a, b"x");
    t.insert(&b, b"y");
    let r = t.root_hash();
    assert!(CompressedTrie::verify(&r, &a, b"x", &t.proof(&a).unwrap()));
    assert!(CompressedTrie::verify(&r, &b, b"y", &t.proof(&b).unwrap()));
}

#[test]
fn property_random_matches_hashmap() {
    let mut rng = Rng(0x5EED_1111_2222_3333);
    for trial in 0..40 {
        let mut t = CompressedTrie::new();
        let mut refm: HashMap<Key, Vec<u8>> = HashMap::new();
        let n = 1 + (rng.next() % 80) as usize;
        for i in 0..n {
            let k = rng.key();
            let v = format!("v{trial}-{i}").into_bytes();
            t.insert(&k, &v);
            refm.insert(k, v);
        }
        let r = t.root_hash();
        for (k, v) in &refm {
            assert_eq!(t.get(k), Some(v.as_slice()), "get trial {trial}");
            let p = t
                .proof(k)
                .unwrap_or_else(|| panic!("no proof trial {trial} key {:?}", &k[..4]));
            assert!(
                CompressedTrie::verify(&r, k, v, &p),
                "verify trial {trial} key {:?}",
                &k[..4]
            );
        }
        assert_eq!(t.len(), refm.len());
    }
}

#[test]
fn property_insert_remove() {
    let mut rng = Rng(0xABCD_0000_1111_2222);
    let mut t = CompressedTrie::new();
    let mut refm: HashMap<Key, Vec<u8>> = HashMap::new();
    let mut keys = Vec::new();
    for i in 0..60 {
        let k = rng.key();
        keys.push(k);
        let v = format!("v{i}").into_bytes();
        t.insert(&k, &v);
        refm.insert(k, v);
    }
    // overwrite
    for k in keys.iter().take(15).copied().collect::<Vec<_>>() {
        let v = b"OW".to_vec();
        t.insert(&k, &v);
        refm.insert(k, v);
    }
    // remove
    for k in keys.iter().take(25).copied().collect::<Vec<_>>() {
        assert_eq!(t.remove(&k), refm.remove(&k));
    }
    assert_eq!(t.len(), refm.len());
    let r = t.root_hash();
    for (k, v) in &refm {
        assert_eq!(t.get(k), Some(v.as_slice()));
        let p = t.proof(k).unwrap();
        assert!(CompressedTrie::verify(&r, k, v, &p));
    }
    for k in keys.iter().take(25) {
        assert!(t.get(k).is_none());
    }
}

#[test]
fn proof_rejects_forgery() {
    let mut t = CompressedTrie::new();
    let a = [1u8; 32];
    let b = [2u8; 32];
    t.insert(&a, b"a");
    t.insert(&b, b"b");
    let r = t.root_hash();
    let p = t.proof(&a).unwrap();
    assert!(!CompressedTrie::verify(&r, &a, b"z", &p));
    assert!(!CompressedTrie::verify(&r, &b, b"a", &p));
    assert!(!CompressedTrie::verify(&[7u8; 32], &a, b"a", &p));
}

#[test]
fn empty_tree_proof_none() {
    let t = CompressedTrie::new();
    assert!(t.proof(&[0u8; 32]).is_none());
    assert_eq!(t.root_hash(), [0u8; 32]);
}
