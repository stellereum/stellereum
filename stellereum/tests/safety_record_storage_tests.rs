use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use stellereum::storage::{SafetyRecordIdentity, Storage};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("stell-safety-record-{}-{id}", std::process::id()));
        assert!(!path.exists(), "test directory already exists");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if self.0.exists() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

fn identity() -> SafetyRecordIdentity {
    SafetyRecordIdentity {
        validator: [1; 32],
        chain: [2; 32],
        shard: 3,
    }
}

// Sled 0.34 wraps flock failures in ErrorKind::Other, losing the original
// error kind. Use a process boundary rather than guessing from error text or
// assuming that dropping the public handles has stopped every internal task.
fn seed_record(dir: &TestDir, bytes: &[u8]) {
    std::fs::create_dir(&dir.0).unwrap();
    std::fs::write(dir.0.join("fixture"), bytes).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "safety_fixture_child"])
        .env("STELL_SAFETY_FIXTURE_DIR", &dir.0)
        .status()
        .unwrap();
    assert!(status.success(), "fixture subprocess failed: {status}");
}

fn record_bytes(generation: u64, payload: &[u8]) -> Vec<u8> {
    let id = identity();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"STSAFETY");
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&id.validator);
    bytes.extend_from_slice(&id.chain);
    bytes.extend_from_slice(&id.shard.to_be_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(blake3::hash(&bytes).as_bytes());
    bytes
}

#[test]
fn safety_fixture_child() {
    let Some(path) = std::env::var_os("STELL_SAFETY_FIXTURE_DIR") else {
        return;
    };
    let path = PathBuf::from(path);
    let bytes = std::fs::read(path.join("fixture")).unwrap();
    let db = sled::open(path).unwrap();
    db.open_tree("safety_record_v1")
        .unwrap()
        .insert(b"record", bytes)
        .unwrap();
    db.flush().unwrap();
    std::process::exit(0);
}

#[test]
fn durable_restart_and_identity_binding() {
    let dir = TestDir::new();
    {
        let storage = Storage::open(&dir.0).unwrap();
        let store = storage.safety_record_store(identity()).unwrap();
        assert_eq!(store.load().unwrap(), None);
        assert_eq!(
            store.persist(None, b"first".to_vec()).unwrap().generation,
            1
        );
        assert!(store.persist(None, b"overwrite".to_vec()).is_err());
        assert_eq!(
            store
                .persist(Some(1), b"second".to_vec())
                .unwrap()
                .generation,
            2
        );
    }
    let storage = Storage::open(&dir.0).unwrap();
    let store = storage.safety_record_store(identity()).unwrap();
    let record = store.load().unwrap().unwrap();
    assert_eq!(record.generation, 2);
    assert_eq!(record.payload, b"second");
    drop(store);
    drop(storage);
    for wrong in [
        SafetyRecordIdentity {
            validator: [9; 32],
            ..identity()
        },
        SafetyRecordIdentity {
            chain: [9; 32],
            ..identity()
        },
        SafetyRecordIdentity {
            shard: 9,
            ..identity()
        },
    ] {
        for fail_load in [true, false] {
            let storage = Storage::open(&dir.0).unwrap();
            let correct = storage.safety_record_store(identity()).unwrap();
            let other = storage.safety_record_store(wrong.clone()).unwrap();
            let error = if fail_load {
                other.load().unwrap_err()
            } else {
                other.persist(Some(2), vec![]).unwrap_err()
            };
            assert!(error.to_string().contains("identity or generation mismatch"));
            assert!(correct
                .load()
                .unwrap_err()
                .to_string()
                .contains("requires recovery"));
            assert!(correct
                .persist(Some(2), vec![])
                .unwrap_err()
                .to_string()
                .contains("requires recovery"));
        }
    }
}

#[test]
fn simultaneous_writers_cannot_both_advance() {
    let dir = TestDir::new();
    let storage = Storage::open(&dir.0).unwrap();
    let store = storage.safety_record_store(identity()).unwrap();
    store.persist(None, vec![]).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let threads: Vec<_> = (0..2)
        .map(|n| {
            let handle = storage.clone().safety_record_store(identity()).unwrap();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                handle.persist(Some(1), vec![n])
            })
        })
        .collect();
    barrier.wait();
    let successes = threads
        .into_iter()
        .map(|thread| thread.join().unwrap().is_ok())
        .filter(|success| *success)
        .count();
    assert_eq!(successes, 1);
    assert_eq!(store.load().unwrap().unwrap().generation, 2);
}

#[test]
fn damaged_or_unsupported_record_never_becomes_empty_or_overwritten() {
    let original = record_bytes(1, &[7]);
    let mut bad_checksum = original.clone();
    bad_checksum[90] ^= 1;
    let mut unsupported = original.clone();
    unsupported[9] = 2;
    for bad in [bad_checksum, unsupported, original[..20].to_vec(), {
        let mut extended = original.clone();
        extended.push(0);
        extended
    }] {
        let dir = TestDir::new();
        seed_record(&dir, &bad);
        let storage = Storage::open(&dir.0).unwrap();
        let store = storage.safety_record_store(identity()).unwrap();
        assert!(store.load().is_err());
        assert!(store.persist(None, vec![]).is_err());
        assert!(store.persist(Some(1), vec![]).is_err());
    }
}

#[test]
fn oversized_payload_does_not_change_record() {
    let dir = TestDir::new();
    let storage = Storage::open(&dir.0).unwrap();
    let store = storage.safety_record_store(identity()).unwrap();
    let first = store.persist(None, vec![4]).unwrap();
    assert!(store.persist(Some(1), vec![0; 1024 * 1024 + 1]).is_err());
    assert_eq!(store.load().unwrap(), Some(first));
    let max = vec![5; 1024 * 1024];
    assert_eq!(store.persist(Some(1), max.clone()).unwrap().payload, max);
    assert_eq!(store.load().unwrap().unwrap().payload, max);
}

#[test]
fn flush_survives_process_exit_without_dropping_storage() {
    const CHILD_DIR: &str = "STELL_SAFETY_CRASH_TEST_DIR";
    if let Some(path) = std::env::var_os(CHILD_DIR) {
        let storage = Storage::open(&PathBuf::from(path)).unwrap();
        storage
            .safety_record_store(identity())
            .unwrap()
            .persist(None, b"flushed".to_vec())
            .unwrap();
        std::process::exit(0);
    }
    let dir = TestDir::new();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "flush_survives_process_exit_without_dropping_storage",
        ])
        .env(CHILD_DIR, &dir.0)
        .status()
        .unwrap();
    assert!(status.success());
    let storage = Storage::open(&dir.0).unwrap();
    let record = storage
        .safety_record_store(identity())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(record.generation, 1);
    assert_eq!(record.payload, b"flushed");
}

#[test]
fn malformed_lengths_and_generations_are_rejected() {
    let dir = TestDir::new();
    {
        let storage = Storage::open(&dir.0).unwrap();
        storage
            .safety_record_store(identity())
            .unwrap()
            .persist(None, vec![])
            .unwrap();
    }
    let original = {
        let db = sled::open(&dir.0).unwrap();
        db.open_tree("safety_record_v1")
            .unwrap()
            .get(b"record")
            .unwrap()
            .unwrap()
            .to_vec()
    };
    let mut oversized = original.clone();
    oversized[86..90].copy_from_slice(&u32::MAX.to_be_bytes());
    let mut zero_generation = original.clone();
    zero_generation[78..86].copy_from_slice(&0u64.to_be_bytes());
    let digest = blake3::hash(&zero_generation[..90]);
    zero_generation[90..].copy_from_slice(digest.as_bytes());
    let mut exhausted = original;
    exhausted[78..86].copy_from_slice(&u64::MAX.to_be_bytes());
    let digest = blake3::hash(&exhausted[..90]);
    exhausted[90..].copy_from_slice(digest.as_bytes());
    for (bytes, generation) in [
        (oversized, None),
        (zero_generation, None),
        (exhausted, Some(u64::MAX)),
    ] {
        {
            let db = sled::open(&dir.0).unwrap();
            db.open_tree("safety_record_v1")
                .unwrap()
                .insert(b"record", bytes.clone())
                .unwrap();
            db.flush().unwrap();
        }
        {
            let storage = Storage::open(&dir.0).unwrap();
            let store = storage.safety_record_store(identity()).unwrap();
            if let Some(generation) = generation {
                assert_eq!(store.load().unwrap().unwrap().generation, generation);
                assert!(store.persist(Some(generation), vec![]).is_err());
            } else {
                assert!(store.load().is_err());
                assert!(store.persist(None, vec![]).is_err());
            }
        }
        let db = sled::open(&dir.0).unwrap();
        assert_eq!(
            db.open_tree("safety_record_v1")
                .unwrap()
                .get(b"record")
                .unwrap()
                .unwrap()
                .as_ref(),
            bytes
        );
    }
}
