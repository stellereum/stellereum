use anyhow::{anyhow, Result};
use std::sync::{Arc, Mutex};

/// Identity of the single safety-record owner of a storage directory.
/// `chain` must be a stable, collision-resistant chain identifier (for example
/// the genesis hash), not an operator-selected display name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyRecordIdentity {
    pub validator: [u8; 32],
    pub chain: [u8; 32],
    pub shard: u32,
}

/// Opaque application state: this primitive does not validate consensus rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyRecord {
    pub identity: SafetyRecordIdentity,
    pub generation: u64,
    pub payload: Vec<u8>,
}

pub(super) const SAFETY_TREE: &str = "safety_record_v1";
pub(super) const SAFETY_KEY: &[u8] = b"record";
const SAFETY_MAGIC: &[u8; 8] = b"STSAFETY";
const SAFETY_VERSION: u16 = 1;
const SAFETY_MAX_PAYLOAD: usize = 1024 * 1024;
const SAFETY_HEADER: usize = 8 + 2 + 32 + 32 + 4 + 8 + 4;
const SAFETY_HASH: usize = 32;

impl SafetyRecord {
    fn encode(&self) -> Result<Vec<u8>> {
        if self.generation == 0 || self.payload.len() > SAFETY_MAX_PAYLOAD {
            return Err(anyhow!(
                "invalid safety record generation or payload length"
            ));
        }
        let mut bytes = Vec::with_capacity(SAFETY_HEADER + self.payload.len() + SAFETY_HASH);
        bytes.extend_from_slice(SAFETY_MAGIC);
        bytes.extend_from_slice(&SAFETY_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.identity.validator);
        bytes.extend_from_slice(&self.identity.chain);
        bytes.extend_from_slice(&self.identity.shard.to_be_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        let hash = blake3::hash(&bytes);
        bytes.extend_from_slice(hash.as_bytes());
        Ok(bytes)
    }

    fn decode(bytes: &[u8], identity: &SafetyRecordIdentity) -> Result<Self> {
        if bytes.len() < SAFETY_HEADER + SAFETY_HASH
            || &bytes[..8] != SAFETY_MAGIC
            || u16::from_be_bytes(bytes[8..10].try_into()?) != SAFETY_VERSION
        {
            return Err(anyhow!("invalid or unsupported safety record"));
        }
        let payload_len = u32::from_be_bytes(bytes[86..90].try_into()?) as usize;
        if payload_len > SAFETY_MAX_PAYLOAD
            || bytes.len() != SAFETY_HEADER + payload_len + SAFETY_HASH
        {
            return Err(anyhow!("invalid safety record length"));
        }
        let hash_offset = SAFETY_HEADER + payload_len;
        if blake3::hash(&bytes[..hash_offset]).as_bytes() != &bytes[hash_offset..] {
            return Err(anyhow!("safety record checksum mismatch"));
        }
        let stored_identity = SafetyRecordIdentity {
            validator: bytes[10..42].try_into()?,
            chain: bytes[42..74].try_into()?,
            shard: u32::from_be_bytes(bytes[74..78].try_into()?),
        };
        let generation = u64::from_be_bytes(bytes[78..86].try_into()?);
        if &stored_identity != identity || generation == 0 {
            return Err(anyhow!("safety record identity or generation mismatch"));
        }
        Ok(Self {
            identity: stored_identity,
            generation,
            payload: bytes[SAFETY_HEADER..hash_offset].to_vec(),
        })
    }
}

/// Isolated single-record storage primitive, not connected to consensus or a
/// signer. Calls through clones of the same `Storage` serialize read, update,
/// and flush. sled's exclusive database lock is required; raw tree writes or
/// other access bypassing this API invalidate its guarantees.
///
/// A successful update means sled's synchronous flush completed. This relies
/// on sled, the filesystem and hardware honoring their durability contracts;
/// provisioning and syncing the database directory and its ancestors is the
/// operator's responsibility. A failed write/flush is indeterminate: callers
/// must halt, not sign, and recover explicitly. Read, decode, identity, write,
/// flush, and tree-open errors quarantine all handles sharing this `Storage`
/// until it is dropped and explicitly recovered. Reopening alone is not proof
/// of recovery. Neither a checksum nor a local generation counter detects
/// deletion, a restored old directory, a cloned directory, or malicious
/// rewriting. Absence must not be interpreted as permission to initialize a
/// previously used validator. This is not a migration or anti-rollback scheme.
/// Decoding bounds the payload before copying it, but sled materializes the
/// whole stored value in `get` first; this API cannot bound that allocation
/// when the database has been corrupted or modified outside this API.
#[derive(Clone)]
pub struct SafetyRecordStore {
    pub(super) db: sled::Db,
    pub(super) tree: sled::Tree,
    pub(super) identity: SafetyRecordIdentity,
    pub(super) failed: Arc<Mutex<bool>>,
}

/// On-disk schema version of the node store.
///
/// Bump when a key layout or encoding changes in a way that older binaries would
/// MISREAD (a new tree alone does not need a bump: older binaries ignore it).
/// The version is recorded in the `meta` tree on first open and checked on every
/// later open. A store written by a NEWER binary is refused unless the operator
/// explicitly opts in, because the alternative is a silent misinterpretation of
/// newer data by older code.
pub const SCHEMA_VERSION: u32 = 1;

/// What an open should do with the recorded version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaDecision {
    /// Fresh store: record the current version.
    Initialize,
    /// Same or older version: proceed (older versions migrate on the next run).
    Accept,
    /// Store written by a newer binary: refuse unless explicitly allowed.
    DowngradeBlocked,
}

/// Pure policy, test-pinned: no clock, no I/O, no env.
pub fn schema_decision(stored: Option<u32>, current: u32, allow_downgrade: bool) -> SchemaDecision {
    match stored {
        None => SchemaDecision::Initialize,
        Some(v) if v > current && !allow_downgrade => SchemaDecision::DowngradeBlocked,
        Some(_) => SchemaDecision::Accept,
    }
}

impl SafetyRecordStore {
    /// Read and validate the current record. `None` is ambiguous: it may also
    /// mean lost or deleted state, not a safe fresh validator.
    pub fn load(&self) -> Result<Option<SafetyRecord>> {
        self.load_with_read(|| self.tree.get(SAFETY_KEY))
    }

    fn load_with_read(
        &self,
        read: impl FnOnce() -> sled::Result<Option<sled::IVec>>,
    ) -> Result<Option<SafetyRecord>> {
        let mut failed = self
            .failed
            .lock()
            .map_err(|_| anyhow!("safety lock poisoned"))?;
        if *failed {
            return Err(anyhow!("safety store requires recovery"));
        }
        self.read_current(&mut failed, read)
    }

    fn read_current(
        &self,
        failed: &mut bool,
        read: impl FnOnce() -> sled::Result<Option<sled::IVec>>,
    ) -> Result<Option<SafetyRecord>> {
        let result = read().map_err(anyhow::Error::from).and_then(|current| {
            current
                .map(|bytes| SafetyRecord::decode(&bytes, &self.identity))
                .transpose()
        });
        if result.is_err() {
            *failed = true;
        }
        result
    }

    /// Atomically replace exactly the expected generation and flush before
    /// returning success. `None` initializes generation 1; subsequent writes
    /// must supply the observed generation and advance it exactly once.
    /// Never retry an indeterminate I/O error as though no write occurred.
    pub fn persist(&self, expected: Option<u64>, payload: Vec<u8>) -> Result<SafetyRecord> {
        self.persist_with_flush(expected, payload, || self.db.flush().map(|_| ()))
    }

    fn persist_with_flush(
        &self,
        expected: Option<u64>,
        payload: Vec<u8>,
        flush: impl FnOnce() -> sled::Result<()>,
    ) -> Result<SafetyRecord> {
        self.persist_with_read_and_flush(expected, payload, || self.tree.get(SAFETY_KEY), flush)
    }

    fn persist_with_read_and_flush(
        &self,
        expected: Option<u64>,
        payload: Vec<u8>,
        read: impl FnOnce() -> sled::Result<Option<sled::IVec>>,
        flush: impl FnOnce() -> sled::Result<()>,
    ) -> Result<SafetyRecord> {
        let mut failed = self
            .failed
            .lock()
            .map_err(|_| anyhow!("safety lock poisoned"))?;
        if *failed {
            return Err(anyhow!("safety store requires recovery"));
        }
        let actual = self
            .read_current(&mut failed, read)?
            .map(|record| record.generation);
        if actual != expected {
            return Err(anyhow!("stale safety record generation"));
        }
        let generation = match actual {
            Some(n) => n
                .checked_add(1)
                .ok_or_else(|| anyhow!("safety generation exhausted"))?,
            None => 1,
        };
        let record = SafetyRecord {
            identity: self.identity.clone(),
            generation,
            payload,
        };
        let bytes = record.encode()?;
        if let Err(error) = self.tree.insert(SAFETY_KEY, bytes) {
            *failed = true;
            return Err(error.into());
        }
        if let Err(error) = flush() {
            *failed = true;
            return Err(error.into());
        }
        Ok(record)
    }
}

#[cfg(test)]
mod schema_guard_tests {
    use super::super::Storage;
    use super::*;

    #[test]
    fn fresh_store_initializes_and_same_or_older_accepts() {
        assert_eq!(schema_decision(None, 3, false), SchemaDecision::Initialize);
        assert_eq!(schema_decision(Some(3), 3, false), SchemaDecision::Accept);
        assert_eq!(schema_decision(Some(2), 3, false), SchemaDecision::Accept);
    }

    #[test]
    fn newer_store_is_refused_unless_the_operator_opts_in() {
        assert_eq!(
            schema_decision(Some(4), 3, false),
            SchemaDecision::DowngradeBlocked
        );
        assert_eq!(schema_decision(Some(4), 3, true), SchemaDecision::Accept);
    }

    #[test]
    fn open_records_the_version_and_refuses_a_newer_store() {
        let dir = std::env::temp_dir().join(format!("stell-schema-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let st = Storage::open(&dir).unwrap();
            let raw = st.get_meta("schema_version").unwrap().expect("recorded");
            assert_eq!(
                u32::from_be_bytes(raw.as_slice().try_into().unwrap()),
                SCHEMA_VERSION
            );
        }
        // Pretend a newer binary wrote this store.
        {
            let db = sled::open(&dir).unwrap();
            let meta = db.open_tree("meta").unwrap();
            meta.insert("schema_version", &(SCHEMA_VERSION + 1).to_be_bytes())
                .unwrap();
            meta.flush().unwrap();
        }
        let err = Storage::open(&dir)
            .err()
            .expect("must refuse a newer store")
            .to_string();
        assert!(err.contains("NEWER than this binary"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod safety_record_unit_tests {
    use super::super::Storage;
    use super::*;

    #[test]
    fn read_errors_quarantine_all_handles_without_false_success() {
        for fail_load in [true, false] {
            let dir = std::env::temp_dir().join(format!(
                "stell-safety-read-{}-{}-{}",
                std::process::id(),
                fail_load,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            assert!(!dir.exists());
            let storage = Storage::open(&dir).unwrap();
            let identity = SafetyRecordIdentity {
                validator: [1; 32],
                chain: [2; 32],
                shard: 3,
            };
            let first = storage.safety_record_store(identity.clone()).unwrap();
            let second = storage
                .clone()
                .safety_record_store(identity.clone())
                .unwrap();
            first.persist(None, vec![1]).unwrap();
            let read = || Err(sled::Error::Unsupported("injected read error".into()));
            if fail_load {
                assert!(first.load_with_read(read).is_err());
            } else {
                assert!(first
                    .persist_with_read_and_flush(Some(1), vec![2], read, || {
                        panic!("flush must not run after a read error")
                    })
                    .is_err());
            }
            for handle in [&first, &second] {
                assert!(handle
                    .load()
                    .unwrap_err()
                    .to_string()
                    .contains("requires recovery"));
                assert!(handle
                    .persist(Some(1), vec![3])
                    .unwrap_err()
                    .to_string()
                    .contains("requires recovery"));
            }
            assert!(storage
                .safety_record_store(identity)
                .err()
                .expect("poisoned storage must refuse new safety handle")
                .to_string()
                .contains("requires recovery"));
            assert_eq!(
                SafetyRecord::decode(
                    &first.tree.get(SAFETY_KEY).unwrap().unwrap(),
                    &first.identity
                )
                .unwrap()
                .payload,
                vec![1]
            );
            drop(first);
            drop(second);
            drop(storage);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn decode_failure_remains_quarantined_even_if_bytes_are_repaired() {
        let dir = std::env::temp_dir().join(format!(
            "stell-safety-decode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(!dir.exists());
        let storage = Storage::open(&dir).unwrap();
        let identity = SafetyRecordIdentity {
            validator: [1; 32],
            chain: [2; 32],
            shard: 3,
        };
        let first = storage.safety_record_store(identity.clone()).unwrap();
        let second = storage.clone().safety_record_store(identity).unwrap();
        first.persist(None, vec![1]).unwrap();
        let original = first.tree.get(SAFETY_KEY).unwrap().unwrap();
        first.tree.insert(SAFETY_KEY, &[0u8][..]).unwrap();
        assert!(first.persist(Some(1), vec![2]).is_err());
        first.tree.insert(SAFETY_KEY, original).unwrap();
        assert!(second
            .load()
            .unwrap_err()
            .to_string()
            .contains("requires recovery"));
        assert!(second
            .persist(Some(1), vec![2])
            .unwrap_err()
            .to_string()
            .contains("requires recovery"));
        drop(first);
        drop(second);
        drop(storage);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unknown_flush_result_poison_is_shared_by_all_handles() {
        let dir = std::env::temp_dir().join(format!(
            "stell-safety-flush-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(!dir.exists());
        let storage = Storage::open(&dir).unwrap();
        let identity = SafetyRecordIdentity {
            validator: [1; 32],
            chain: [2; 32],
            shard: 3,
        };
        let first = storage.safety_record_store(identity.clone()).unwrap();
        let second = storage
            .clone()
            .safety_record_store(identity.clone())
            .unwrap();
        first.persist(None, vec![1]).unwrap();
        let error = first.persist_with_flush(Some(1), vec![2], || {
            let bytes = first.tree.get(SAFETY_KEY).unwrap().unwrap();
            let record = SafetyRecord::decode(&bytes, &identity).unwrap();
            assert_eq!(record.generation, 2);
            assert_eq!(record.payload, vec![2]);
            Err(sled::Error::Unsupported(
                "injected unknown flush outcome".into(),
            ))
        });
        assert!(error.is_err());
        for handle in [first, second] {
            assert!(handle
                .load()
                .unwrap_err()
                .to_string()
                .contains("requires recovery"));
            assert!(handle
                .persist(Some(2), vec![3])
                .unwrap_err()
                .to_string()
                .contains("requires recovery"));
        }
        assert!(storage
            .safety_record_store(identity)
            .err()
            .expect("poisoned storage must refuse new safety handle")
            .to_string()
            .contains("requires recovery"));
        drop(storage);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn error_after_successful_flush_is_fail_closed_for_all_handles() {
        let dir = std::env::temp_dir().join(format!(
            "stell-safety-post-flush-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(!dir.exists());
        let storage = Storage::open(&dir).unwrap();
        let identity = SafetyRecordIdentity {
            validator: [1; 32],
            chain: [2; 32],
            shard: 3,
        };
        let first = storage.safety_record_store(identity.clone()).unwrap();
        let second = storage
            .clone()
            .safety_record_store(identity.clone())
            .unwrap();
        first.persist(None, vec![1]).unwrap();
        let result = first.persist_with_flush(Some(1), vec![2], || {
            let bytes = first.tree.get(SAFETY_KEY).unwrap().unwrap();
            let record = SafetyRecord::decode(&bytes, &identity).unwrap();
            assert_eq!(record.generation, 2);
            assert_eq!(record.payload, vec![2]);
            first.db.flush()?;
            Err(sled::Error::Unsupported(
                "injected error after successful flush".into(),
            ))
        });
        assert!(result.is_err());
        for handle in [first, second] {
            assert!(handle
                .load()
                .unwrap_err()
                .to_string()
                .contains("requires recovery"));
            assert!(handle
                .persist(Some(2), vec![3])
                .unwrap_err()
                .to_string()
                .contains("requires recovery"));
        }
        assert!(storage
            .safety_record_store(identity)
            .err()
            .expect("poisoned storage must refuse new safety handle")
            .to_string()
            .contains("requires recovery"));
        drop(storage);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
