//! Serialized durable consensus safety authority (`P0-LOCK-WATERMARK`).
//!
//! Owns the validated safety state `(height, finalized_height, finalized_hash,
//! highest_prevote_round, highest_precommit_round, last_non_nil_prevote,
//! prev_other_non_nil_prevote_round, locked, highest_proposed)` behind a
//! mutex, and guarantees for every vote and proposal:
//!   1. rule validation (floors, lock, O(1) cross-kind guard, QC + body checks)
//!   2. durable lock body (`storage.put_block` + `storage.flush`) when lock advances
//!   3. atomic generation-CAS `SafetyRecordStore::persist` (`+ db.flush`)
//!   4. cryptographic signing (`VoteSigner`: Ed25519 + Falcon-512)
//!   5. in-memory commit (with non-rollback on ambiguous signer failure)
//!
//! See `docs/specs/05_LOCK_SAFETY_P0.md` (Resolutions 1–3).

use crate::consensus::{
    attach_vote_falcon_sig, consensus_chain_id, vote_sign_bytes_for_shard, CommitteeSchedule,
    Height, QuorumCertificate, Round, ValidatorId, ValidatorSet, Vote, VoteKind,
};
use crate::sharding::{Block, ShardId};
use crate::storage::{
    BlockHash, ConsensusCheckpoint, SafetyRecord, SafetyRecordIdentity, SafetyRecordStore, Storage,
    VoteWatermark,
};
use anyhow::{anyhow, Result};
use std::sync::{Arc, Mutex};

pub const SAFETY_PAYLOAD_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityMode {
    Active,
    ObserverOnly,
    Quarantined(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SafetyLockRecord {
    pub round: Round,
    pub block_hash: BlockHash,
    pub value_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LastNonNilPrevote {
    pub round: Round,
    pub block_hash: BlockHash,
    pub value_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HighestProposed {
    pub round: Round,
    pub block_hash: BlockHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyRecordPayload {
    pub schema_version: u16,
    pub height: Height,
    pub finalized_height: Height,
    pub finalized_hash: BlockHash,
    pub highest_prevote_round: Option<Round>,
    pub highest_precommit_round: Option<Round>,
    pub last_non_nil_prevote: Option<LastNonNilPrevote>,
    pub prev_other_non_nil_prevote_round: Option<Round>,
    pub locked: Option<SafetyLockRecord>,
    pub highest_proposed: Option<HighestProposed>,
}

impl SafetyRecordPayload {
    pub fn fresh_for_height(
        height: Height,
        finalized_height: Height,
        finalized_hash: BlockHash,
    ) -> Result<Self> {
        if height == 0 || finalized_height >= height {
            return Err(anyhow!(
                "invalid safety payload height/finalized_height: height={height} finalized={finalized_height}"
            ));
        }
        Ok(Self {
            schema_version: SAFETY_PAYLOAD_SCHEMA_VERSION,
            height,
            finalized_height,
            finalized_hash,
            highest_prevote_round: None,
            highest_precommit_round: None,
            last_non_nil_prevote: None,
            prev_other_non_nil_prevote_round: None,
            locked: None,
            highest_proposed: None,
        })
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        if self.schema_version != SAFETY_PAYLOAD_SCHEMA_VERSION {
            return Err(anyhow!(
                "unsupported safety payload schema version {}",
                self.schema_version
            ));
        }
        if self.height == 0 || self.finalized_height >= self.height {
            return Err(anyhow!(
                "invalid safety payload height={} finalized_height={}",
                self.height,
                self.finalized_height
            ));
        }
        let mut out = Vec::with_capacity(240);
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.finalized_height.to_be_bytes());
        out.extend_from_slice(&self.finalized_hash);

        encode_opt_u32(&mut out, self.highest_prevote_round);
        encode_opt_u32(&mut out, self.highest_precommit_round);
        match self.last_non_nil_prevote {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&v.round.to_be_bytes());
                out.extend_from_slice(&v.block_hash);
                out.extend_from_slice(&v.value_id);
            }
        }
        encode_opt_u32(&mut out, self.prev_other_non_nil_prevote_round);
        match self.locked {
            None => out.push(0),
            Some(l) => {
                out.push(1);
                out.extend_from_slice(&l.round.to_be_bytes());
                out.extend_from_slice(&l.block_hash);
                out.extend_from_slice(&l.value_id);
            }
        }
        match self.highest_proposed {
            None => out.push(0),
            Some(p) => {
                out.push(1);
                out.extend_from_slice(&p.round.to_be_bytes());
                out.extend_from_slice(&p.block_hash);
            }
        }
        Ok(out)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let mut cur = 0usize;
        let schema_version = read_u16(bytes, &mut cur)?;
        if schema_version != SAFETY_PAYLOAD_SCHEMA_VERSION {
            return Err(anyhow!(
                "unsupported safety payload schema version {schema_version}"
            ));
        }
        let height = read_u64(bytes, &mut cur)?;
        let finalized_height = read_u64(bytes, &mut cur)?;
        if height == 0 || finalized_height >= height {
            return Err(anyhow!(
                "invalid safety payload height={height} finalized_height={finalized_height}"
            ));
        }
        let finalized_hash = read_32(bytes, &mut cur)?;
        let highest_prevote_round = read_opt_u32(bytes, &mut cur)?;
        let highest_precommit_round = read_opt_u32(bytes, &mut cur)?;
        let last_non_nil_prevote = match read_tag(bytes, &mut cur)? {
            0 => None,
            1 => Some(LastNonNilPrevote {
                round: read_u32(bytes, &mut cur)?,
                block_hash: read_32(bytes, &mut cur)?,
                value_id: read_32(bytes, &mut cur)?,
            }),
            tag => return Err(anyhow!("invalid last_non_nil_prevote tag {tag}")),
        };
        let prev_other_non_nil_prevote_round = read_opt_u32(bytes, &mut cur)?;
        let locked = match read_tag(bytes, &mut cur)? {
            0 => None,
            1 => Some(SafetyLockRecord {
                round: read_u32(bytes, &mut cur)?,
                block_hash: read_32(bytes, &mut cur)?,
                value_id: read_32(bytes, &mut cur)?,
            }),
            tag => return Err(anyhow!("invalid locked tag {tag}")),
        };
        let highest_proposed = match read_tag(bytes, &mut cur)? {
            0 => None,
            1 => Some(HighestProposed {
                round: read_u32(bytes, &mut cur)?,
                block_hash: read_32(bytes, &mut cur)?,
            }),
            tag => return Err(anyhow!("invalid highest_proposed tag {tag}")),
        };
        if cur != bytes.len() {
            return Err(anyhow!(
                "trailing bytes in safety record payload: expected {cur}, got {}",
                bytes.len()
            ));
        }
        if let Some(last) = last_non_nil_prevote {
            if highest_prevote_round.is_none_or(|r| r < last.round) {
                return Err(anyhow!(
                    "corrupt safety payload: highest_prevote_round < last_non_nil_prevote.round"
                ));
            }
            if let Some(other_r) = prev_other_non_nil_prevote_round {
                if other_r >= last.round {
                    return Err(anyhow!(
                        "corrupt safety payload: prev_other_non_nil_prevote_round >= last_non_nil_prevote.round"
                    ));
                }
            }
        } else if prev_other_non_nil_prevote_round.is_some() {
            return Err(anyhow!(
                "corrupt safety payload: prev_other_non_nil_prevote_round set without last_non_nil_prevote"
            ));
        }
        Ok(Self {
            schema_version,
            height,
            finalized_height,
            finalized_hash,
            highest_prevote_round,
            highest_precommit_round,
            last_non_nil_prevote,
            prev_other_non_nil_prevote_round,
            locked,
            highest_proposed,
        })
    }

    /// Exact O(1) cross-kind check (§1.5):
    /// Allowed iff for EVERY prevote signed at any round `r' > polka_round` at
    /// this height, either it was `nil`, or its `value_id == value_id_x`.
    pub fn can_sign_precommit_cross_kind(&self, polka_round: Round, value_id_x: [u8; 32]) -> bool {
        match self.last_non_nil_prevote {
            None => true,
            Some(last) => {
                if polka_round >= last.round {
                    true
                } else if last.value_id == value_id_x {
                    self.prev_other_non_nil_prevote_round
                        .is_none_or(|p| polka_round >= p)
                } else {
                    false
                }
            }
        }
    }

    /// Apply a validated prevote transition at `round` (`round > highest_prevote_round`).
    fn note_prevote(&mut self, round: Round, target: Option<(BlockHash, [u8; 32])>) {
        self.highest_prevote_round = Some(round);
        if let Some((bh, vid)) = target {
            match self.last_non_nil_prevote {
                None => {
                    self.last_non_nil_prevote = Some(LastNonNilPrevote {
                        round,
                        block_hash: bh,
                        value_id: vid,
                    });
                }
                Some(last) if last.value_id == vid => {
                    self.last_non_nil_prevote = Some(LastNonNilPrevote {
                        round,
                        block_hash: bh,
                        value_id: vid,
                    });
                }
                Some(last) => {
                    self.prev_other_non_nil_prevote_round = Some(
                        self.prev_other_non_nil_prevote_round
                            .map_or(last.round, |p| p.max(last.round)),
                    );
                    self.last_non_nil_prevote = Some(LastNonNilPrevote {
                        round,
                        block_hash: bh,
                        value_id: vid,
                    });
                }
            }
        }
    }
}

fn encode_opt_u32(out: &mut Vec<u8>, v: Option<u32>) {
    match v {
        None => out.push(0),
        Some(n) => {
            out.push(1);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

fn read_tag(bytes: &[u8], cur: &mut usize) -> Result<u8> {
    if *cur >= bytes.len() {
        return Err(anyhow!("unexpected EOF reading tag"));
    }
    let b = bytes[*cur];
    *cur += 1;
    Ok(b)
}

fn read_u16(bytes: &[u8], cur: &mut usize) -> Result<u16> {
    let end = cur
        .checked_add(2)
        .ok_or_else(|| anyhow!("offset overflow"))?;
    if end > bytes.len() {
        return Err(anyhow!("unexpected EOF reading u16"));
    }
    let v = u16::from_be_bytes(bytes[*cur..end].try_into()?);
    *cur = end;
    Ok(v)
}

fn read_u32(bytes: &[u8], cur: &mut usize) -> Result<u32> {
    let end = cur
        .checked_add(4)
        .ok_or_else(|| anyhow!("offset overflow"))?;
    if end > bytes.len() {
        return Err(anyhow!("unexpected EOF reading u32"));
    }
    let v = u32::from_be_bytes(bytes[*cur..end].try_into()?);
    *cur = end;
    Ok(v)
}

fn read_u64(bytes: &[u8], cur: &mut usize) -> Result<u64> {
    let end = cur
        .checked_add(8)
        .ok_or_else(|| anyhow!("offset overflow"))?;
    if end > bytes.len() {
        return Err(anyhow!("unexpected EOF reading u64"));
    }
    let v = u64::from_be_bytes(bytes[*cur..end].try_into()?);
    *cur = end;
    Ok(v)
}

fn read_32(bytes: &[u8], cur: &mut usize) -> Result<[u8; 32]> {
    let end = cur
        .checked_add(32)
        .ok_or_else(|| anyhow!("offset overflow"))?;
    if end > bytes.len() {
        return Err(anyhow!("unexpected EOF reading [u8; 32]"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[*cur..end]);
    *cur = end;
    Ok(out)
}

fn read_opt_u32(bytes: &[u8], cur: &mut usize) -> Result<Option<u32>> {
    match read_tag(bytes, cur)? {
        0 => Ok(None),
        1 => Ok(Some(read_u32(bytes, cur)?)),
        tag => Err(anyhow!("invalid Option<u32> tag {tag}")),
    }
}

/// Deterministic 32-byte chain commitment for `SafetyRecordIdentity.chain` (§2.2.1).
pub fn derive_safety_chain_id(chain_id: u64, genesis_state_root: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"STELL_SAFETY_CHAIN_V1");
    h.update(&chain_id.to_be_bytes());
    h.update(genesis_state_root);
    *h.finalize().as_bytes()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SafetyRefusal {
    NotActive(AuthorityMode),
    HeightMismatch {
        expected: Height,
        got: Height,
    },
    RoundAtOrBelowPrevoteFloor {
        round: Round,
        floor: Round,
    },
    RoundAtOrBelowPrecommitFloor {
        round: Round,
        floor: Round,
    },
    RoundAtOrBelowProposedFloor {
        round: Round,
        floor: Round,
    },
    LockedConflict {
        lock: SafetyLockRecord,
        target_value_id: [u8; 32],
    },
    CrossKindConflict(String),
    InvalidPrevoteQc(String),
    BodyMismatch(String),
    PersistenceFailed(String),
    SignerFailed,
    InternalPoisoned,
}

impl std::fmt::Display for SafetyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotActive(mode) => write!(f, "safety authority not active: {mode:?}"),
            Self::HeightMismatch { expected, got } => {
                write!(f, "safety height mismatch: expected {expected}, got {got}")
            }
            Self::RoundAtOrBelowPrevoteFloor { round, floor } => {
                write!(f, "prevote round {round} <= highest_prevote_round {floor}")
            }
            Self::RoundAtOrBelowPrecommitFloor { round, floor } => {
                write!(
                    f,
                    "precommit round {round} <= highest_precommit_round {floor}"
                )
            }
            Self::RoundAtOrBelowProposedFloor { round, floor } => {
                write!(f, "propose round {round} <= highest_proposed.round {floor}")
            }
            Self::LockedConflict { lock, .. } => {
                write!(
                    f,
                    "locked on {} at round {}",
                    hex::encode(&lock.block_hash[..6]),
                    lock.round
                )
            }
            Self::CrossKindConflict(msg) => write!(f, "cross-kind conflict: {msg}"),
            Self::InvalidPrevoteQc(msg) => write!(f, "invalid prevote QC: {msg}"),
            Self::BodyMismatch(msg) => write!(f, "block body mismatch: {msg}"),
            Self::PersistenceFailed(msg) => write!(f, "durable safety persist failed: {msg}"),
            Self::SignerFailed => write!(f, "vote/proposal signer failed"),
            Self::InternalPoisoned => write!(f, "safety authority mutex poisoned"),
        }
    }
}

impl std::error::Error for SafetyRefusal {}

/// Sealed signing interface passed into `SafetyAuthority` after durable persistence.
pub trait VoteSigner {
    fn validator_id(&self) -> ValidatorId;
    fn sign_ed25519(&self, msg: &[u8]) -> Option<Vec<u8>>;
    fn sign_falcon(&self, msg: &[u8]) -> Option<(ValidatorId, Vec<u8>)>;
}

/// In-memory equivalent of `SafetyRecordStore` used ONLY by `SafetyBackend::Ephemeral`
/// in unit/cluster/live-stand tests (runs the exact same canonical codec & CAS).
#[derive(Clone, Debug)]
pub struct InMemorySafetyRecord {
    generation: u64,
    payload: Vec<u8>,
}

impl InMemorySafetyRecord {
    fn new(payload: &SafetyRecordPayload) -> Result<Self> {
        Ok(Self {
            generation: 1,
            payload: payload.encode_canonical()?,
        })
    }

    fn persist(&mut self, expected_gen: u64, next_payload: Vec<u8>) -> Result<u64> {
        if self.generation != expected_gen {
            return Err(anyhow!(
                "ephemeral CAS mismatch: expected {}, got {}",
                expected_gen,
                self.generation
            ));
        }
        let _ = SafetyRecordPayload::decode_canonical(&next_payload)?;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("ephemeral generation exhausted"))?;
        self.payload = next_payload;
        Ok(self.generation)
    }
}

pub enum SafetyBackend {
    Durable {
        store: SafetyRecordStore,
        storage: Arc<Storage>,
    },
    Ephemeral(InMemorySafetyRecord),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SafetyIoStage {
    PutBlock,
    StorageFlush,
    RecordPersist,
}

#[doc(hidden)]
pub type SafetyIoFaultHook = Arc<dyn Fn(SafetyIoStage) -> Result<()> + Send + Sync>;

#[derive(Clone, Debug)]
pub struct SafetyBootContext {
    pub is_validator: bool,
    pub is_observer_env: bool,
    pub new_chain_explicit: bool,
    pub restored_finalized: Option<(Height, BlockHash)>,
    pub restored_state_height: Option<Height>,
    pub restored_finalized_qc_verified: bool,
    pub legacy_checkpoint: Option<ConsensusCheckpoint>,
    pub legacy_watermark: Option<VoteWatermark>,
}

struct SafetyAuthorityState {
    mode: AuthorityMode,
    backend: Option<SafetyBackend>,
    generation: Option<u64>,
    payload: Option<SafetyRecordPayload>,
    fault_hook: Option<SafetyIoFaultHook>,
}

pub struct SafetyAuthority {
    inner: Mutex<SafetyAuthorityState>,
}

pub type ProposalSignatures = (Vec<u8>, Option<(ValidatorId, Vec<u8>)>);

impl SafetyAuthority {
    /// Ephemeral authority for in-process `ValidatorRuntime::new(...)` unit/cluster tests.
    /// Production node code (`node/consensus_driver.rs`) MUST use [`Self::open_from_storage`]
    /// (`SafetyBackend::Durable`).
    pub fn new_ephemeral(start_height: Height) -> Self {
        let h = start_height.max(1);
        let fh = h.saturating_sub(1);
        let payload = SafetyRecordPayload::fresh_for_height(h, fh, [0u8; 32])
            .expect("valid start height for ephemeral safety authority");
        let mem = InMemorySafetyRecord::new(&payload).expect("canonical encode");
        Self {
            inner: Mutex::new(SafetyAuthorityState {
                mode: AuthorityMode::Active,
                backend: Some(SafetyBackend::Ephemeral(mem)),
                generation: Some(1),
                payload: Some(payload),
                fault_hook: None,
            }),
        }
    }

    pub fn new_observer() -> Self {
        Self {
            inner: Mutex::new(SafetyAuthorityState {
                mode: AuthorityMode::ObserverOnly,
                backend: None,
                generation: None,
                payload: None,
                fault_hook: None,
            }),
        }
    }

    pub fn new_quarantined(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        tracing::error!("[safety] QUARANTINED (fail-closed Observer): {reason}");
        eprintln!("[safety] QUARANTINED (fail-closed Observer): {reason}");
        Self {
            inner: Mutex::new(SafetyAuthorityState {
                mode: AuthorityMode::Quarantined(reason),
                backend: None,
                generation: None,
                payload: None,
                fault_hook: None,
            }),
        }
    }

    /// Open durable `SafetyAuthority` from `Storage`, enforcing clean-genesis-only
    /// auto-init and fail-closed legacy/corrupt quarantine (§2.4).
    pub fn open_from_storage(
        storage: Arc<Storage>,
        identity: SafetyRecordIdentity,
        boot_ctx: SafetyBootContext,
    ) -> Self {
        let store = match storage.safety_record_store(identity) {
            Ok(s) => s,
            Err(e) => {
                return Self::new_quarantined(format!("failed to open safety_record_v1: {e}"));
            }
        };

        let loaded = match store.load() {
            Ok(rec) => rec,
            Err(e) => {
                return Self::new_quarantined(format!(
                    "safety_record_v1 read/decode/identity error: {e} (signing disabled)"
                ));
            }
        };

        let is_configured_observer = !boot_ctx.is_validator || boot_ctx.is_observer_env;

        match loaded {
            None => {
                if is_configured_observer {
                    return Self::new_observer();
                }
                // Clean Genesis Founding ONLY (§2.4.2):
                let check = (|| -> Result<()> {
                    if !boot_ctx.new_chain_explicit {
                        return Err(anyhow!(
                            "STELL_NEW_CHAIN=1 is not set (absent safety_record_v1 cannot be auto-initialized)"
                        ));
                    }
                    if boot_ctx.restored_finalized.is_some() || storage.finalized()?.is_some() {
                        return Err(anyhow!("finalized height > 0"));
                    }
                    if boot_ctx.restored_state_height.unwrap_or(0) > 0
                        || storage.latest_state_height()?.unwrap_or(0) > 0
                    {
                        return Err(anyhow!("latest_state_height > 0"));
                    }
                    if boot_ctx.legacy_watermark.is_some() || storage.vote_watermark()?.is_some() {
                        return Err(anyhow!("legacy vote_watermark present"));
                    }
                    if boot_ctx.legacy_checkpoint.is_some() || storage.consensus()?.is_some() {
                        return Err(anyhow!("legacy consensus checkpoint present"));
                    }
                    if storage.has_non_genesis_blocks_or_headers()? {
                        return Err(anyhow!("non-genesis blocks/headers exist at height > 0"));
                    }
                    Ok(())
                })();

                if let Err(reason) = check {
                    return Self::new_quarantined(format!(
                        "legacy/existing store has no safety_record_v1 ({reason}); \
                         running as fail-closed Observer until operator stops/fences all \
                         signers and runs `stellereum safety-init`"
                    ));
                }

                let init_payload = match SafetyRecordPayload::fresh_for_height(1, 0, [0u8; 32]) {
                    Ok(p) => p,
                    Err(e) => return Self::new_quarantined(format!("genesis safety init: {e}")),
                };
                let bytes = match init_payload.encode_canonical() {
                    Ok(b) => b,
                    Err(e) => return Self::new_quarantined(format!("genesis safety encode: {e}")),
                };
                match store.persist(None, bytes) {
                    Ok(rec) => {
                        tracing::info!(
                            "[safety] initialized clean-genesis durable safety_record_v1 at generation {}",
                            rec.generation
                        );
                        Self {
                            inner: Mutex::new(SafetyAuthorityState {
                                mode: AuthorityMode::Active,
                                backend: Some(SafetyBackend::Durable { store, storage }),
                                generation: Some(rec.generation),
                                payload: Some(init_payload),
                                fault_hook: None,
                            }),
                        }
                    }
                    Err(e) => Self::new_quarantined(format!(
                        "clean-genesis safety_record_v1 persist failed: {e}"
                    )),
                }
            }
            Some(record) => {
                let mut payload = match SafetyRecordPayload::decode_canonical(&record.payload) {
                    Ok(p) => p,
                    Err(e) => {
                        return Self::new_quarantined(format!(
                            "safety_record_v1 canonical payload decode error: {e}"
                        ));
                    }
                };
                if is_configured_observer {
                    return Self::new_observer();
                }

                let mut current_gen = record.generation;
                let (restored_fh, restored_fhash) =
                    boot_ctx.restored_finalized.unwrap_or((0, [0u8; 32]));
                let state_h = boot_ctx.restored_state_height.unwrap_or(0);

                if payload.finalized_height > restored_fh || state_h < payload.finalized_height {
                    return Self::new_quarantined(format!(
                        "safety_record_v1 finalized_height ({}) exceeds restored finalized ({restored_fh}) \
                         or state height ({state_h}); refusing to vote with stale state",
                        payload.finalized_height
                    ));
                }

                let mut need_persist = false;
                if restored_fh > payload.finalized_height {
                    if !boot_ctx.restored_finalized_qc_verified {
                        return Self::new_quarantined(format!(
                            "restored finalized height {restored_fh} > safety record finalized {} \
                             without locally verified precommit QC",
                            payload.finalized_height
                        ));
                    }
                    payload = match SafetyRecordPayload::fresh_for_height(
                        restored_fh.saturating_add(1),
                        restored_fh,
                        restored_fhash,
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            return Self::new_quarantined(format!(
                                "reconcile advance payload failed: {e}"
                            ));
                        }
                    };
                    need_persist = true;
                }

                // Cross-check legacy checkpoint/watermark conservatively (§2.4.3).
                if let Some(cp) = &boot_ctx.legacy_checkpoint {
                    if cp.finalized_height > payload.finalized_height
                        && cp.finalized_height > restored_fh
                    {
                        return Self::new_quarantined(format!(
                            "legacy checkpoint finalized_height {} contradicts safety record {}",
                            cp.finalized_height, payload.finalized_height
                        ));
                    }
                    if cp.height > payload.height {
                        return Self::new_quarantined(format!(
                            "legacy checkpoint height {} exceeds safety record height {}",
                            cp.height, payload.height
                        ));
                    }
                }
                if let Some(wm) = &boot_ctx.legacy_watermark {
                    if let Some(pv) = wm.prevote {
                        if pv.height > payload.height {
                            return Self::new_quarantined(format!(
                                "legacy vote_watermark prevote height {} exceeds safety record height {}",
                                pv.height, payload.height
                            ));
                        }
                        if pv.height == payload.height
                            && payload.highest_prevote_round.is_none_or(|r| pv.round > r)
                        {
                            // Conservative: raise prevote floor (if non-nil, resolve value_id if block present).
                            let target = pv.target.map(|bh| {
                                let vid = storage
                                    .get_block(&bh)
                                    .ok()
                                    .flatten()
                                    .filter(|b| b.compute_hash() == bh)
                                    .map(|b| b.value_id())
                                    .unwrap_or(bh);
                                (bh, vid)
                            });
                            payload.note_prevote(pv.round, target);
                            need_persist = true;
                        }
                    }
                    if let Some(pc) = wm.precommit {
                        if pc.height > payload.height {
                            return Self::new_quarantined(format!(
                                "legacy vote_watermark precommit height {} exceeds safety record height {}",
                                pc.height, payload.height
                            ));
                        }
                        if pc.height == payload.height
                            && payload.highest_precommit_round.is_none_or(|r| pc.round > r)
                        {
                            payload.highest_precommit_round = Some(pc.round);
                            need_persist = true;
                        }
                    }
                }

                if need_persist {
                    let bytes = match payload.encode_canonical() {
                        Ok(b) => b,
                        Err(e) => {
                            return Self::new_quarantined(format!("reconcile encode: {e}"));
                        }
                    };
                    match store.persist(Some(current_gen), bytes) {
                        Ok(rec) => current_gen = rec.generation,
                        Err(e) => {
                            return Self::new_quarantined(format!(
                                "reconcile safety_record_v1 persist failed: {e}"
                            ));
                        }
                    }
                }

                Self {
                    inner: Mutex::new(SafetyAuthorityState {
                        mode: AuthorityMode::Active,
                        backend: Some(SafetyBackend::Durable { store, storage }),
                        generation: Some(current_gen),
                        payload: Some(payload),
                        fault_hook: None,
                    }),
                }
            }
        }
    }

    #[doc(hidden)]
    pub fn set_io_fault_hook_for_test(&self, hook: Option<SafetyIoFaultHook>) {
        if let Ok(mut g) = self.inner.lock() {
            g.fault_hook = hook;
        }
    }

    pub fn mode(&self) -> AuthorityMode {
        match self.inner.lock() {
            Ok(g) => g.mode.clone(),
            Err(_) => AuthorityMode::Quarantined("safety mutex poisoned".into()),
        }
    }

    pub fn can_sign(&self) -> bool {
        matches!(self.mode(), AuthorityMode::Active)
    }

    pub fn is_durable(&self) -> bool {
        self.inner
            .lock()
            .map(|g| matches!(g.backend, Some(SafetyBackend::Durable { .. })))
            .unwrap_or(false)
    }

    pub fn quarantine(&self, reason: impl Into<String>) {
        let reason = reason.into();
        tracing::error!("[safety] QUARANTINED (fail-closed Observer): {reason}");
        eprintln!("[safety] QUARANTINED (fail-closed Observer): {reason}");
        if let Ok(mut g) = self.inner.lock() {
            g.mode = AuthorityMode::Quarantined(reason);
        }
    }

    pub fn current_state(&self) -> Option<SafetyRecordPayload> {
        self.inner.lock().ok().and_then(|g| g.payload.clone())
    }

    pub fn generation(&self) -> Option<u64> {
        self.inner.lock().ok().and_then(|g| g.generation)
    }

    pub fn locked(&self) -> Option<SafetyLockRecord> {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.payload.as_ref().and_then(|p| p.locked))
    }

    /// Prevote authorization + durable write-ahead + signing (§2.3).
    pub fn authorize_and_sign_prevote(
        &self,
        height: Height,
        round: Round,
        shard_id: ShardId,
        target: Option<(BlockHash, [u8; 32] /* value_id */)>,
        signer: &dyn VoteSigner,
    ) -> Result<Vote, SafetyRefusal> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| SafetyRefusal::InternalPoisoned)?;
        if g.mode != AuthorityMode::Active {
            return Err(SafetyRefusal::NotActive(g.mode.clone()));
        }
        let state = g
            .payload
            .as_ref()
            .ok_or_else(|| SafetyRefusal::NotActive(g.mode.clone()))?;
        if state.height != height {
            return Err(SafetyRefusal::HeightMismatch {
                expected: state.height,
                got: height,
            });
        }
        if let Some(floor) = state.highest_prevote_round {
            if round <= floor {
                return Err(SafetyRefusal::RoundAtOrBelowPrevoteFloor { round, floor });
            }
        }
        if let Some((_, vid)) = target {
            if let Some(lock) = state.locked {
                if lock.value_id != vid {
                    return Err(SafetyRefusal::LockedConflict {
                        lock,
                        target_value_id: vid,
                    });
                }
            }
        }

        let mut next_state = state.clone();
        next_state.note_prevote(round, target);

        if let Err(e) = persist_state(&mut g, &next_state, None) {
            let msg = e.to_string();
            tracing::error!("[safety] prevote persist failed; quarantining: {msg}");
            eprintln!("[safety] prevote persist failed; quarantining: {msg}");
            g.mode = AuthorityMode::Quarantined(msg.clone());
            return Err(SafetyRefusal::PersistenceFailed(msg));
        }

        let target_hash = target.map(|(bh, _)| bh);
        let msg =
            vote_sign_bytes_for_shard(shard_id, height, round, VoteKind::Prevote, &target_hash);
        let sig = signer
            .sign_ed25519(&msg)
            .ok_or(SafetyRefusal::SignerFailed)?;
        let mut vote = Vote::signed_with_in_shard(
            signer.validator_id(),
            shard_id,
            height,
            round,
            VoteKind::Prevote,
            target_hash,
            sig,
        );
        match signer.sign_falcon(&msg) {
            Some((_, fsig)) => attach_vote_falcon_sig(&fsig, &mut vote.signature),
            // F9 observability: the durable watermark is already advanced
            // (write-ahead), so this round's vote cannot be retried, and an
            // Ed25519-only vote is dropped by every FULL-PQ peer. Nothing can
            // be recovered here, but the operator must be able to see that the
            // PQ half failed instead of finding a silently wasted round.
            None => tracing::error!(
                height,
                round,
                "[safety] prevote signed WITHOUT a Falcon half (PQ signer unavailable): \
                 the round is lost and peers will drop this vote"
            ),
        }
        Ok(vote)
    }

    /// Lock + Precommit authorization + Step A (`put_block + flush`) + Step B
    /// (`SafetyRecordStore::persist`) + Step C (`sign_bytes` + Falcon) (§2.3).
    #[allow(clippy::too_many_arguments)]
    // GATE: spec §2.1 pins the exact 8-parameter authorize_and_sign_precommit interface.
    pub fn authorize_and_sign_precommit(
        &self,
        height: Height,
        polka_round: Round,
        shard_id: ShardId,
        polka_block: &Block,
        prevote_qc: &QuorumCertificate,
        validators: &ValidatorSet,
        committee_schedule: CommitteeSchedule,
        signer: &dyn VoteSigner,
    ) -> Result<(Vote, Option<SafetyLockRecord>), SafetyRefusal> {
        let target = verify_polka_evidence(
            height,
            polka_round,
            shard_id,
            polka_block,
            prevote_qc,
            validators,
            committee_schedule,
        )?;
        let value_id = polka_block.value_id();

        let mut g = self
            .inner
            .lock()
            .map_err(|_| SafetyRefusal::InternalPoisoned)?;
        if g.mode != AuthorityMode::Active {
            return Err(SafetyRefusal::NotActive(g.mode.clone()));
        }
        let state = g
            .payload
            .as_ref()
            .ok_or_else(|| SafetyRefusal::NotActive(g.mode.clone()))?;
        if state.height != height {
            return Err(SafetyRefusal::HeightMismatch {
                expected: state.height,
                got: height,
            });
        }
        if let Some(floor) = state.highest_precommit_round {
            if polka_round <= floor {
                return Err(SafetyRefusal::RoundAtOrBelowPrecommitFloor {
                    round: polka_round,
                    floor,
                });
            }
        }
        if let Some(lock) = state.locked {
            if lock.value_id != value_id && polka_round <= lock.round {
                return Err(SafetyRefusal::LockedConflict {
                    lock,
                    target_value_id: value_id,
                });
            }
        }
        if !state.can_sign_precommit_cross_kind(polka_round, value_id) {
            return Err(SafetyRefusal::CrossKindConflict(format!(
                "conflicting non-nil prevote after polka_round {polka_round} (last={:?}, prev_other={:?})",
                state.last_non_nil_prevote.map(|p| (p.round, hex::encode(&p.value_id[..4]))),
                state.prev_other_non_nil_prevote_round
            )));
        }

        let next_locked = if state.locked.is_none_or(|l| polka_round > l.round) {
            Some(SafetyLockRecord {
                round: polka_round,
                block_hash: target,
                value_id,
            })
        } else {
            state.locked
        };
        let lock_changed = next_locked != state.locked;

        let mut next_state = state.clone();
        next_state.highest_precommit_round = Some(polka_round);
        next_state.locked = next_locked;

        let lock_block = if lock_changed {
            Some(polka_block)
        } else {
            None
        };
        if let Err(e) = persist_state(&mut g, &next_state, lock_block) {
            let msg = e.to_string();
            tracing::error!("[safety] precommit persist failed; quarantining: {msg}");
            eprintln!("[safety] precommit persist failed; quarantining: {msg}");
            g.mode = AuthorityMode::Quarantined(msg.clone());
            return Err(SafetyRefusal::PersistenceFailed(msg));
        }

        let msg = vote_sign_bytes_for_shard(
            shard_id,
            height,
            polka_round,
            VoteKind::Precommit,
            &Some(target),
        );
        let sig = signer
            .sign_ed25519(&msg)
            .ok_or(SafetyRefusal::SignerFailed)?;
        let mut vote = Vote::signed_with_in_shard(
            signer.validator_id(),
            shard_id,
            height,
            polka_round,
            VoteKind::Precommit,
            Some(target),
            sig,
        );
        match signer.sign_falcon(&msg) {
            Some((_, fsig)) => attach_vote_falcon_sig(&fsig, &mut vote.signature),
            None => tracing::error!(
                height,
                polka_round,
                "[safety] precommit signed WITHOUT a Falcon half (PQ signer unavailable): \
                 the round is lost and peers will drop this vote"
            ),
        }
        Ok((vote, next_locked))
    }

    /// Persist a lock transition from a verified polka without signing a precommit
    /// (used for higher-polka unlock and liveness lock adoption when cross-kind
    /// forbids emitting a precommit for an older polka round, §1.6.1 / §2.1).
    pub fn record_polka_lock_transition(
        &self,
        height: Height,
        polka_round: Round,
        polka_block: &Block,
        prevote_qc: &QuorumCertificate,
        validators: &ValidatorSet,
        committee_schedule: CommitteeSchedule,
    ) -> Result<Option<SafetyLockRecord>, SafetyRefusal> {
        let target = verify_polka_evidence(
            height,
            polka_round,
            polka_block.shard_id,
            polka_block,
            prevote_qc,
            validators,
            committee_schedule,
        )?;
        let value_id = polka_block.value_id();

        let mut g = self
            .inner
            .lock()
            .map_err(|_| SafetyRefusal::InternalPoisoned)?;
        if g.mode != AuthorityMode::Active {
            return Err(SafetyRefusal::NotActive(g.mode.clone()));
        }
        let state = g
            .payload
            .as_ref()
            .ok_or_else(|| SafetyRefusal::NotActive(g.mode.clone()))?;
        if state.height != height {
            return Err(SafetyRefusal::HeightMismatch {
                expected: state.height,
                got: height,
            });
        }
        if let Some(lock) = state.locked {
            if polka_round <= lock.round {
                return Ok(state.locked);
            }
        }
        let next_locked = Some(SafetyLockRecord {
            round: polka_round,
            block_hash: target,
            value_id,
        });
        let mut next_state = state.clone();
        next_state.locked = next_locked;

        if let Err(e) = persist_state(&mut g, &next_state, Some(polka_block)) {
            let msg = e.to_string();
            tracing::error!("[safety] polka lock transition persist failed; quarantining: {msg}");
            eprintln!("[safety] polka lock transition persist failed; quarantining: {msg}");
            g.mode = AuthorityMode::Quarantined(msg.clone());
            return Err(SafetyRefusal::PersistenceFailed(msg));
        }
        Ok(next_locked)
    }

    /// Proposal authorization + durable write-ahead + signing (`propose` & `restamp_for_round`).
    pub fn authorize_and_sign_proposal(
        &self,
        height: Height,
        round: Round,
        block_hash: BlockHash,
        signer: &dyn VoteSigner,
    ) -> Result<ProposalSignatures, SafetyRefusal> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| SafetyRefusal::InternalPoisoned)?;
        if g.mode != AuthorityMode::Active {
            return Err(SafetyRefusal::NotActive(g.mode.clone()));
        }
        let state = g
            .payload
            .as_ref()
            .ok_or_else(|| SafetyRefusal::NotActive(g.mode.clone()))?;
        if state.height != height {
            return Err(SafetyRefusal::HeightMismatch {
                expected: state.height,
                got: height,
            });
        }
        if let Some(prev) = state.highest_proposed {
            if round <= prev.round {
                return Err(SafetyRefusal::RoundAtOrBelowProposedFloor {
                    round,
                    floor: prev.round,
                });
            }
        }

        let mut next_state = state.clone();
        next_state.highest_proposed = Some(HighestProposed { round, block_hash });

        if let Err(e) = persist_state(&mut g, &next_state, None) {
            let msg = e.to_string();
            tracing::error!("[safety] proposal persist failed; quarantining: {msg}");
            eprintln!("[safety] proposal persist failed; quarantining: {msg}");
            g.mode = AuthorityMode::Quarantined(msg.clone());
            return Err(SafetyRefusal::PersistenceFailed(msg));
        }

        let ed_sig = signer
            .sign_ed25519(&block_hash)
            .ok_or(SafetyRefusal::SignerFailed)?;
        let falcon_sig = signer.sign_falcon(&block_hash);
        if falcon_sig.is_none() {
            tracing::error!(
                height,
                "[safety] proposal signed WITHOUT a Falcon half (PQ signer unavailable): \
                 peers will refuse the block"
            );
        }
        Ok((ed_sig, falcon_sig))
    }

    /// Advance safety state on height finalization, adoption, or verified snapshot sync.
    pub fn advance_height(
        &self,
        new_height: Height,
        finalized_height: Height,
        finalized_hash: BlockHash,
    ) -> Result<(), SafetyRefusal> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| SafetyRefusal::InternalPoisoned)?;
        match g.mode {
            AuthorityMode::ObserverOnly => return Ok(()),
            AuthorityMode::Quarantined(_) => {
                // Quarantined observer can still advance chain height in memory,
                // never becomes Active or clears quarantine.
                return Ok(());
            }
            AuthorityMode::Active => {}
        }
        let state = g
            .payload
            .as_ref()
            .ok_or_else(|| SafetyRefusal::NotActive(g.mode.clone()))?;
        if finalized_height < state.finalized_height || new_height <= state.height {
            return Err(SafetyRefusal::HeightMismatch {
                expected: state.height.saturating_add(1),
                got: new_height,
            });
        }
        let next_state =
            SafetyRecordPayload::fresh_for_height(new_height, finalized_height, finalized_hash)
                .map_err(|e| SafetyRefusal::PersistenceFailed(e.to_string()))?;

        if let Err(e) = persist_state(&mut g, &next_state, None) {
            let msg = e.to_string();
            tracing::error!("[safety] advance_height persist failed; quarantining: {msg}");
            eprintln!("[safety] advance_height persist failed; quarantining: {msg}");
            g.mode = AuthorityMode::Quarantined(msg.clone());
            return Err(SafetyRefusal::PersistenceFailed(msg));
        }
        Ok(())
    }
}

fn verify_polka_evidence(
    height: Height,
    polka_round: Round,
    shard_id: ShardId,
    polka_block: &Block,
    prevote_qc: &QuorumCertificate,
    validators: &ValidatorSet,
    committee_schedule: CommitteeSchedule,
) -> Result<BlockHash, SafetyRefusal> {
    if polka_block.height != height {
        return Err(SafetyRefusal::BodyMismatch(format!(
            "polka block height {} != {height}",
            polka_block.height
        )));
    }
    if polka_block.shard_id != shard_id {
        return Err(SafetyRefusal::BodyMismatch(format!(
            "polka block shard {} != {shard_id}",
            polka_block.shard_id
        )));
    }
    let target = polka_block.compute_hash();
    if prevote_qc.kind != VoteKind::Prevote
        || prevote_qc.height != height
        || prevote_qc.round != polka_round
        || prevote_qc.shard_id != shard_id
        || prevote_qc.block_hash != Some(target)
    {
        return Err(SafetyRefusal::InvalidPrevoteQc(format!(
            "prevote QC metadata mismatch (qc={:?}/{}/{}/{:?}, want=Prevote/{height}/{polka_round}/{shard_id})",
            prevote_qc.kind, prevote_qc.height, prevote_qc.round, prevote_qc.shard_id
        )));
    }
    if !prevote_qc.verify_with_schedule(validators, committee_schedule) {
        return Err(SafetyRefusal::InvalidPrevoteQc(
            "prevote QC failed validator quorum/signature verification".into(),
        ));
    }
    Ok(target)
}

fn persist_state(
    g: &mut SafetyAuthorityState,
    next_state: &SafetyRecordPayload,
    lock_block: Option<&Block>,
) -> Result<()> {
    let encoded = next_state.encode_canonical()?;
    let hook = g.fault_hook.clone();
    let expected_gen = g
        .generation
        .ok_or_else(|| anyhow!("missing safety record generation"))?;

    match g.backend.as_mut() {
        Some(SafetyBackend::Durable { store, storage }) => {
            if let Some(blk) = lock_block {
                if let Some(h) = &hook {
                    h(SafetyIoStage::PutBlock)?;
                }
                storage.put_block(blk)?;
                if let Some(h) = &hook {
                    h(SafetyIoStage::StorageFlush)?;
                }
                storage.flush()?;
            }
            if let Some(h) = &hook {
                h(SafetyIoStage::RecordPersist)?;
            }
            let rec = store.persist(Some(expected_gen), encoded)?;
            g.generation = Some(rec.generation);
            g.payload = Some(next_state.clone());
            Ok(())
        }
        Some(SafetyBackend::Ephemeral(mem)) => {
            if lock_block.is_some() {
                if let Some(h) = &hook {
                    h(SafetyIoStage::PutBlock)?;
                    h(SafetyIoStage::StorageFlush)?;
                }
            }
            if let Some(h) = &hook {
                h(SafetyIoStage::RecordPersist)?;
            }
            let next_gen = mem.persist(expected_gen, encoded)?;
            g.generation = Some(next_gen);
            g.payload = Some(next_state.clone());
            Ok(())
        }
        None => Err(anyhow!("no safety backend configured")),
    }
}

/// Explicit operator recovery command (`stellereum safety-init`): writes generation 1
/// to `safety_record_v1` for an existing store after the operator confirms all
/// legacy validators and remote signers for this key are stopped/fenced.
pub fn operator_safety_init(
    storage: &Storage,
    validator_pub: [u8; 32],
    shard: u32,
    prevote_round_floor: Option<Round>,
    precommit_round_floor: Option<Round>,
    fenced_confirmed: bool,
) -> Result<SafetyRecord> {
    if !fenced_confirmed {
        return Err(anyhow!(
            "refusing safety-init: pass --i-fenced-all-signers after stopping and fencing all legacy validators and remote signers for this key"
        ));
    }
    let genesis_bytes = storage
        .get_meta("genesis_state_root")?
        .ok_or_else(|| anyhow!("store has no genesis_state_root metadata"))?;
    let genesis_root: [u8; 32] = genesis_bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "genesis_state_root has invalid length {}",
            genesis_bytes.len()
        )
    })?;
    let identity = SafetyRecordIdentity {
        validator: validator_pub,
        chain: derive_safety_chain_id(consensus_chain_id(), &genesis_root),
        shard,
    };
    let store = storage.safety_record_store(identity)?;
    if let Some(existing) = store.load()? {
        return Err(anyhow!(
            "safety_record_v1 already exists at generation {}; refusing to overwrite",
            existing.generation
        ));
    }

    let (fh, fhash) = storage.finalized()?.unwrap_or((0, [0u8; 32]));
    if fh > 0 {
        let blk = storage.get_block(&fhash)?.ok_or_else(|| {
            anyhow!(
                "finalized block #{fh} ({}) missing from store",
                hex::encode(fhash)
            )
        })?;
        if blk.height != fh || blk.compute_hash() != fhash || blk.precommit_qc.is_none() {
            return Err(anyhow!(
                "finalized block #{fh} failed integrity/QC check; refusing safety-init"
            ));
        }
    }
    let next_height = fh
        .checked_add(1)
        .ok_or_else(|| anyhow!("finalized height overflow"))?;

    if let Some(wm) = storage.vote_watermark()? {
        if let Some(pv) = wm.prevote {
            if pv.height > next_height {
                return Err(anyhow!(
                    "legacy vote_watermark prevote height {} > finalized+1 ({next_height})",
                    pv.height
                ));
            }
            if pv.height == next_height && prevote_round_floor.is_none_or(|f| f < pv.round) {
                return Err(anyhow!(
                    "prevote_round_floor ({prevote_round_floor:?}) must be >= legacy vote_watermark prevote round {} at height {next_height}",
                    pv.round
                ));
            }
        }
        if let Some(pc) = wm.precommit {
            if pc.height > next_height {
                return Err(anyhow!(
                    "legacy vote_watermark precommit height {} > finalized+1 ({next_height})",
                    pc.height
                ));
            }
            if pc.height == next_height && precommit_round_floor.is_none_or(|f| f < pc.round) {
                return Err(anyhow!(
                    "precommit_round_floor ({precommit_round_floor:?}) must be >= legacy vote_watermark precommit round {} at height {next_height}",
                    pc.round
                ));
            }
        }
    }

    let mut payload = SafetyRecordPayload::fresh_for_height(next_height, fh, fhash)?;
    payload.highest_prevote_round = prevote_round_floor;
    payload.highest_precommit_round = precommit_round_floor;
    let bytes = payload.encode_canonical()?;
    store.persist(None, bytes)
}
