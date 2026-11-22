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
fn stress_2000_keys_with_proofs_and_removals() {
    let mut rng = Rng(0xFEED_FACE_1111_2222);
    let mut t = CompressedTrie::new();
    let mut refm: HashMap<Key, Vec<u8>> = HashMap::new();
    let mut keys = Vec::new();
    for i in 0..2000usize {
        let k = rng.key();
        keys.push(k);
        let v = format!("v{i}").into_bytes();
        t.insert(&k, &v);
        refm.insert(k, v);
    }
    // all proofs verify
    let r = t.root_hash();
    for (k, v) in &refm {
        let p = t.proof(k).unwrap();
        assert!(
            CompressedTrie::verify(&r, k, v, &p),
            "proof fail {:?}",
            &k[..4]
        );
    }
    // remove 800
    for k in keys.iter().take(800).copied().collect::<Vec<_>>() {
        assert_eq!(t.remove(&k), refm.remove(&k));
    }
    assert_eq!(t.len(), refm.len());
    let r2 = t.root_hash();
    for (k, v) in &refm {
        let p = t.proof(k).unwrap();
        assert!(CompressedTrie::verify(&r2, k, v, &p));
    }
    // 1200 remaining, removed gone
    for k in keys.iter().take(800) {
        assert!(t.get(k).is_none());
    }
    // reinsert 400 removed
    for k in keys.iter().take(800).take(400).copied().collect::<Vec<_>>() {
        let v = b"back".to_vec();
        t.insert(&k, &v);
        refm.insert(k, v);
    }
    let r3 = t.root_hash();
    for (k, v) in &refm {
        let p = t.proof(k).unwrap();
        assert!(CompressedTrie::verify(&r3, k, v, &p));
    }
}
