//! Clean-room canonical wire types and strict v7 bincode decoder.
//!
//! Matches Stellereum's bincode-1.3 (fixint, little-endian) wire layout
//! byte-for-byte with ZERO `LEGACY_BLOCK_TOLERANCE` and strict canonical
//! round-trip validation (`canonical == bytes`).

use bincode::Options;
use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub type ShardId = u32;
pub type CellHash = [u8; 32];
pub type Height = u64;
pub type Round = u32;
pub type BlockHash = [u8; 32];
pub type ValidatorId = [u8; 32];

pub const MASTERCHAIN_SHARD: ShardId = 0;
pub const MAX_BLOCK_BYTES: usize = 32 * 1024 * 1024;
pub const DEFAULT_CHAIN_ID: u64 = 5757;

pub const PRIORITY_FEE_COMMITMENT_TAG: &[u8; 8] = b"PRIORITY";
pub const CHAIN_ID_COMMITMENT_TAG: &[u8; 8] = b"CHAIN_ID";
pub const SPONSOR_COMMITMENT_TAG: &[u8; 8] = b"SPONSOR_";
pub const SESSION_SIG_TAG: &[u8; 3] = b"SK1";
pub const SESSION_FALCON_SIG_TAG: &[u8; 3] = b"SF1";
pub const CHAIN_SIG_TAG: &[u8; 3] = b"CH1";
pub const EVM_SIG_TAG: &[u8; 3] = b"EV1";
pub const SPONSOR_SIG_TAG: &[u8; 3] = b"SP1";
pub const PQ_ENVELOPE_MAGIC: &[u8; 3] = b"PQ1";

pub const SPONSOR_AUTH_MAX_BYTES: usize = 4096;
pub const SPONSOR_MAX_TARGETS: usize = 64;
pub const FALCON512_PUBKEY_LEN: usize = 897;
pub const MLDSA44_PUBKEY_LEN: usize = 1312;
pub const FALCON512_SIG_LEN: usize = 666;
pub const MLDSA44_SIG_LEN: usize = 2420;
pub const ED25519_SIG_LEN: usize = 64;

pub const MAX_COMMIT_CERT_SIGNERS: usize = 4_096;
pub const VOTE_FALCON_MAGIC: &[u8; 16] = b"STELL_VOTEFAL_V1";
pub const VOTE_FALCON_PART_LEN: usize = 16 + ED25519_SIG_LEN + FALCON512_SIG_LEN;
pub const PQ_QC_MARKER_ID: ValidatorId = [0xFE; 32];
pub const PQ_UQC_MARKER_ID: ValidatorId = [0xFD; 32];
pub const QC_UQC_MAGIC: &[u8; 16] = b"STELL_UQC_PQ_V5_";
pub const QC_PQ_MAGIC: &[u8; 16] = b"STELL_QC_PQ_V5__";

pub const SHARD_HEADER_MINTED_TOTAL_TAG: &[u8; 8] = b"SHMINT01";

pub const XPC_LEGACY: u8 = 0;
pub const XPC_PREPARE: u8 = 1;
pub const XPC_PREPARE_ACK: u8 = 2;
pub const XPC_COMMIT: u8 = 3;
pub const XPC_ABORT_REQUEST: u8 = 4;
pub const XPC_ABORT_ACK: u8 = 5;

const V3_LINK_LEN: usize = 48;
const V3_SEGMENTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PqScheme {
    Falcon512 = 2,
    MlDsa44 = 3,
}

impl PqScheme {
    pub const fn id(&self) -> u8 {
        *self as u8
    }

    pub fn from_id(id: u8) -> Result<Self, String> {
        match id {
            2 => Ok(Self::Falcon512),
            1 | 4 => Err(format!(
                "Refused classical post-quantum scheme ID {id}: only Falcon-512 (0x02) is accepted"
            )),
            other => Err(format!(
                "Unknown post-quantum scheme ID: {other} (only Falcon-512 (0x02) is accepted)"
            )),
        }
    }

    pub const fn is_disabled(&self) -> bool {
        matches!(self, Self::MlDsa44)
    }

    pub const fn is_post_quantum(&self) -> bool {
        matches!(self, Self::Falcon512 | Self::MlDsa44)
    }

    pub const fn name(&self) -> &'static str {
        match self {
            Self::Falcon512 => "Falcon-512",
            Self::MlDsa44 => "ML-DSA-44",
        }
    }

    pub const fn pubkey_size(&self) -> usize {
        match self {
            Self::Falcon512 => FALCON512_PUBKEY_LEN,
            Self::MlDsa44 => MLDSA44_PUBKEY_LEN,
        }
    }

    pub const fn signature_size(&self) -> usize {
        match self {
            Self::Falcon512 => FALCON512_SIG_LEN,
            Self::MlDsa44 => MLDSA44_SIG_LEN,
        }
    }
}

impl TryFrom<u8> for PqScheme {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Self::from_id(v)
    }
}

impl core::fmt::Display for PqScheme {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardHeaderCommitment {
    pub shard_id: ShardId,
    pub height: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub timestamp: u64,
    pub minted_total_nano: u64,
}

impl ShardHeaderCommitment {
    pub fn commitment_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 8 + 32 + 32 + 8 + 16);
        out.extend_from_slice(&self.shard_id.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        if self.minted_total_nano != 0 {
            out.extend_from_slice(SHARD_HEADER_MINTED_TOTAL_TAG);
            out.extend_from_slice(&self.minted_total_nano.to_be_bytes());
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub shard_id: ShardId,
    pub height: u64,
    pub round: u32,
    pub prev_hash: [u8; 32],
    pub state_root: CellHash,
    pub body_commitment: [u8; 32],
    pub mmr_epoch_root: [u8; 32],
    pub epoch_key_commitment: [u8; 32],
    pub timestamp: u64,
    pub proposer: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteKind {
    Prevote,
    Precommit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub height: Height,
    pub round: Round,
    pub kind: VoteKind,
    pub block_hash: Option<BlockHash>,
    pub signatures: Vec<(ValidatorId, Vec<u8>)>,
    pub shard_id: ShardId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub height: Height,
    pub round: Round,
    pub kind: VoteKind,
    pub block_hash: Option<BlockHash>,
    pub voter: ValidatorId,
    pub signature: Vec<u8>,
    pub shard_id: ShardId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMicroCertificate {
    pub scheme: PqScheme,
    pub height: Height,
    pub round: Round,
    pub committee_size: u32,
    pub signers_bitmask: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
    #[serde(default)]
    pub sortition_parent: [u8; 32],
}

impl PqMicroCertificate {
    pub fn new(
        scheme: PqScheme,
        height: Height,
        round: Round,
        committee_size: u32,
        signers_bitmask: Vec<u8>,
        signatures: Vec<Vec<u8>>,
        sortition_parent: [u8; 32],
    ) -> Self {
        Self {
            scheme,
            height,
            round,
            committee_size,
            signers_bitmask,
            signatures,
            sortition_parent,
        }
    }

    pub fn is_signer(&self, index: usize) -> bool {
        if index >= self.committee_size as usize {
            return false;
        }
        let byte = index / 8;
        let bit = index % 8;
        if byte >= self.signers_bitmask.len() {
            return false;
        }
        (self.signers_bitmask[byte] & (1 << bit)) != 0
    }

    pub fn set_signer(&mut self, index: usize, signed: bool) {
        if index >= self.committee_size as usize {
            return;
        }
        let byte = index / 8;
        let bit = index % 8;
        if byte >= self.signers_bitmask.len() {
            self.signers_bitmask.resize(byte + 1, 0);
        }
        if signed {
            self.signers_bitmask[byte] |= 1 << bit;
        } else {
            self.signers_bitmask[byte] &= !(1 << bit);
        }
    }

    pub fn signed_count(&self) -> usize {
        let max_bits = self.signers_bitmask.len().saturating_mul(8);
        let limit = (self.committee_size as usize).min(max_bits);
        (0..limit).filter(|&i| self.is_signer(i)).count()
    }

    pub fn encode(&self) -> Vec<u8> {
        encode_pq_micro_envelope(self)
    }

    pub fn decode(payload: &[u8]) -> Option<Self> {
        decode_pq_micro_envelope(payload)
    }
}

pub fn encode_pq_micro_envelope(cert: &PqMicroCertificate) -> Vec<u8> {
    let bitmask_len = cert.signers_bitmask.len();
    let sig_count = cert.signatures.len();
    let total_sig_bytes: usize = cert.signatures.iter().map(|s| 4 + s.len()).sum();
    let mut out =
        Vec::with_capacity(16 + 32 + 1 + 8 + 4 + 4 + 4 + bitmask_len + 4 + total_sig_bytes);

    out.extend_from_slice(QC_UQC_MAGIC);
    out.extend_from_slice(&cert.sortition_parent);
    out.push(cert.scheme.id());
    out.extend_from_slice(&cert.height.to_le_bytes());
    out.extend_from_slice(&cert.round.to_le_bytes());
    out.extend_from_slice(&cert.committee_size.to_le_bytes());
    out.extend_from_slice(&(bitmask_len as u32).to_le_bytes());
    out.extend_from_slice(&cert.signers_bitmask);
    out.extend_from_slice(&(sig_count as u32).to_le_bytes());
    for sig in &cert.signatures {
        out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        out.extend_from_slice(sig);
    }
    out
}

pub fn decode_pq_micro_envelope(payload: &[u8]) -> Option<PqMicroCertificate> {
    const MIN_HEADER: usize = 16 + 32 + 1 + 8 + 4 + 4 + 4 + 4;
    if payload.len() < 16 || &payload[..16] != QC_UQC_MAGIC {
        return None;
    }

    if payload.len() >= MIN_HEADER {
        let mut sortition_parent = [0u8; 32];
        sortition_parent.copy_from_slice(&payload[16..48]);
        if let Ok(scheme) = PqScheme::from_id(payload[48]) {
            let height = u64::from_le_bytes(payload[49..57].try_into().ok()?);
            let round = u32::from_le_bytes(payload[57..61].try_into().ok()?);
            let committee_size = u32::from_le_bytes(payload[61..65].try_into().ok()?);
            let bitmask_len = u32::from_le_bytes(payload[65..69].try_into().ok()?) as usize;

            let mut cursor = 69usize;
            if let Some(after_bitmask) = cursor.checked_add(bitmask_len) {
                if let Some(min_need) = after_bitmask.checked_add(4) {
                    if payload.len() >= min_need {
                        let signers_bitmask = payload[cursor..after_bitmask].to_vec();
                        cursor = after_bitmask;

                        let sig_count =
                            u32::from_le_bytes(payload[cursor..cursor + 4].try_into().ok()?)
                                as usize;
                        cursor += 4;

                        if sig_count <= MAX_COMMIT_CERT_SIGNERS {
                            let mut signatures = Vec::with_capacity(sig_count);
                            let mut valid = true;

                            for _ in 0..sig_count {
                                if cursor + 4 > payload.len() {
                                    valid = false;
                                    break;
                                }
                                let sig_len = u32::from_le_bytes(
                                    payload[cursor..cursor + 4].try_into().ok()?,
                                ) as usize;
                                cursor += 4;
                                match cursor.checked_add(sig_len) {
                                    Some(end) if end <= payload.len() => {
                                        signatures.push(payload[cursor..end].to_vec());
                                        cursor = end;
                                    }
                                    _ => {
                                        valid = false;
                                        break;
                                    }
                                }
                            }

                            if valid && cursor == payload.len() {
                                return Some(PqMicroCertificate {
                                    scheme,
                                    height,
                                    round,
                                    committee_size,
                                    signers_bitmask,
                                    signatures,
                                    sortition_parent,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_BLOCK_BYTES as u64)
        .deserialize::<PqMicroCertificate>(&payload[16..])
        .ok()
}

pub fn encode_pq_epoch_envelope(cert: &PqMicroCertificate) -> Vec<u8> {
    let mut out = encode_pq_micro_envelope(cert);
    out[..16].copy_from_slice(QC_PQ_MAGIC);
    out
}

pub fn decode_pq_epoch_envelope(payload: &[u8]) -> Option<PqMicroCertificate> {
    if payload.len() < 16 || &payload[..16] != QC_PQ_MAGIC {
        return None;
    }
    let mut temp = payload.to_vec();
    temp[..16].copy_from_slice(QC_UQC_MAGIC);
    decode_pq_micro_envelope(&temp)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleStep {
    pub sibling_is_right: bool,
    pub sibling_hash: [u8; 32],
    pub branch_prefix: [u8; 16],
    pub skip: u16,
    pub branch_bit: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub key: [u8; 32],
    pub value_hash: [u8; 32],
    pub leaf_hash: [u8; 32],
    pub path: Vec<MerkleStep>,
}

mod bytes48_serde {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &[u8; 48], s: S) -> Result<S::Ok, S::Error> {
        let mut tup = s.serialize_tuple(48)?;
        for byte in val {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [u8; 48];
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "a 48-byte array")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; 48];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(48, V)
    }
}

mod opt_bytes48_serde {
    use super::bytes48_serde;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    struct Bytes48Ref<'a>(&'a [u8; 48]);
    impl Serialize for Bytes48Ref<'_> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            bytes48_serde::serialize(self.0, s)
        }
    }

    struct Bytes48Owned([u8; 48]);
    impl<'de> Deserialize<'de> for Bytes48Owned {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            bytes48_serde::deserialize(d).map(Bytes48Owned)
        }
    }

    pub fn serialize<S: Serializer>(val: &Option<[u8; 48]>, s: S) -> Result<S::Ok, S::Error> {
        match val {
            Some(arr) => s.serialize_some(&Bytes48Ref(arr)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 48]>, D::Error> {
        Option::<Bytes48Owned>::deserialize(d).map(|opt| opt.map(|w| w.0))
    }
}

mod serde_anchors_16_48 {
    use super::{bytes48_serde, V3_LINK_LEN, V3_SEGMENTS};
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    struct Link48([u8; V3_LINK_LEN]);
    impl Serialize for Link48 {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            bytes48_serde::serialize(&self.0, s)
        }
    }
    impl<'de> Deserialize<'de> for Link48 {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            bytes48_serde::deserialize(d).map(Link48)
        }
    }

    pub fn serialize<S: Serializer>(
        val: &[[u8; V3_LINK_LEN]; V3_SEGMENTS],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut tup = s.serialize_tuple(V3_SEGMENTS)?;
        for anchor in val {
            tup.serialize_element(&Link48(*anchor))?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<[[u8; V3_LINK_LEN]; V3_SEGMENTS], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [[u8; V3_LINK_LEN]; V3_SEGMENTS];
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "an array of {V3_SEGMENTS} 48-byte anchors")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [[0u8; V3_LINK_LEN]; V3_SEGMENTS];
                for (i, slot) in out.iter_mut().enumerate() {
                    let link: Link48 = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                    *slot = link.0;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(V3_SEGMENTS, V)
    }
}

mod serde_falcon_sig {
    use super::FALCON512_SIG_LEN;
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        val: &[u8; FALCON512_SIG_LEN],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut tup = s.serialize_tuple(FALCON512_SIG_LEN)?;
        for byte in val {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<[u8; FALCON512_SIG_LEN], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [u8; FALCON512_SIG_LEN];
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "a {FALCON512_SIG_LEN}-byte Falcon-512 signature")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; FALCON512_SIG_LEN];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(FALCON512_SIG_LEN, V)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinRootProof {
    pub steps: u64,
    pub final_xy: ([u8; 32], [u8; 32]),
    pub checkpoints: Vec<(u64, [u8; 32], [u8; 32])>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochVdfBeacon {
    pub epoch: u64,
    #[serde(with = "bytes48_serde")]
    pub raw_seed: [u8; 48],
    pub proof: MinRootProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitCarrierV3 {
    pub validator_id: [u8; 32],
    pub epoch_n: u64,
    #[serde(with = "serde_anchors_16_48")]
    pub anchors: [[u8; V3_LINK_LEN]; V3_SEGMENTS],
    #[serde(with = "serde_falcon_sig")]
    pub sig: [u8; FALCON512_SIG_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnVrfV3BlockPayload {
    #[serde(with = "opt_bytes48_serde")]
    pub reveal: Option<[u8; 48]>,
    pub commits: Vec<CommitCarrierV3>,
    pub epoch_vdf: Option<EpochVdfBeacon>,
}

impl CnVrfV3BlockPayload {
    pub fn is_empty(&self) -> bool {
        self.reveal.is_none() && self.commits.is_empty() && self.epoch_vdf.is_none()
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match &self.reveal {
            None => out.push(0u8),
            Some(rev) => {
                out.push(1u8);
                out.extend_from_slice(rev);
            }
        }
        let mut commits: Vec<&CommitCarrierV3> = self.commits.iter().collect();
        commits.sort_by(|a, b| {
            a.validator_id
                .cmp(&b.validator_id)
                .then_with(|| a.epoch_n.cmp(&b.epoch_n))
                .then_with(|| a.anchors.cmp(&b.anchors))
                .then_with(|| a.sig.cmp(&b.sig))
        });
        out.extend_from_slice(&(commits.len() as u32).to_be_bytes());
        for c in commits {
            out.extend_from_slice(&c.validator_id);
            out.extend_from_slice(&c.epoch_n.to_be_bytes());
            for anchor in &c.anchors {
                out.extend_from_slice(anchor);
            }
            out.extend_from_slice(&(c.sig.len() as u32).to_be_bytes());
            out.extend_from_slice(&c.sig);
        }
        match &self.epoch_vdf {
            None => out.push(0u8),
            Some(vdf) => {
                out.push(1u8);
                out.extend_from_slice(&vdf.epoch.to_be_bytes());
                out.extend_from_slice(&vdf.raw_seed);
                out.extend_from_slice(&vdf.proof.steps.to_be_bytes());
                out.extend_from_slice(&vdf.proof.final_xy.0);
                out.extend_from_slice(&vdf.proof.final_xy.1);
                out.extend_from_slice(&(vdf.proof.checkpoints.len() as u32).to_be_bytes());
                for &(step_idx, ref x_bytes, ref y_bytes) in &vdf.proof.checkpoints {
                    out.extend_from_slice(&step_idx.to_be_bytes());
                    out.extend_from_slice(x_bytes);
                    out.extend_from_slice(y_bytes);
                }
            }
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservedOpcodeMarker;

impl Serialize for ReservedOpcodeMarker {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for ReservedOpcodeMarker {
    fn deserialize<D: Deserializer<'de>>(_deserializer: D) -> Result<Self, D::Error> {
        Err(serde::de::Error::custom(
            "reserved/excised confidential opcode discriminant refused at decode",
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceFeedUpdate {
    pub asset: String,
    pub price_micro_usd: u64,
    pub timestamp: u64,
    pub publisher_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqPriceFeedUpdate {
    pub asset: String,
    pub price_micro_usd: u64,
    pub timestamp: u64,
    pub publisher_falcon_pubkey: Vec<u8>,
    pub falcon_sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionKeyAuthorization {
    pub master_address: [u8; 32],
    pub session_pubkey: [u8; 32],
    pub valid_until: u64,
    pub max_gas_spend: u64,
    pub gas_spent: u64,
    pub scope: u64,
    pub max_value_per_tx: u64,
    pub chain_id: u64,
    pub master_signature: Vec<u8>,
    pub master_scheme: PqScheme,
    pub session_scheme: PqScheme,
    pub master_pubkey: Option<Vec<u8>>,
    pub session_pubkey_bytes: Option<Vec<u8>>,
}

impl Serialize for SessionKeyAuthorization {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            #[derive(Serialize)]
            struct HumanReadable<'a> {
                master_address: &'a [u8; 32],
                session_pubkey: &'a [u8; 32],
                valid_until: u64,
                max_gas_spend: u64,
                gas_spent: u64,
                scope: u64,
                max_value_per_tx: u64,
                chain_id: u64,
                master_signature: &'a [u8],
                master_scheme: PqScheme,
                session_scheme: PqScheme,
                master_pubkey: &'a Option<Vec<u8>>,
                session_pubkey_bytes: &'a Option<Vec<u8>>,
            }
            let hr = HumanReadable {
                master_address: &self.master_address,
                session_pubkey: &self.session_pubkey,
                valid_until: self.valid_until,
                max_gas_spend: self.max_gas_spend,
                gas_spent: self.gas_spent,
                scope: self.scope,
                max_value_per_tx: self.max_value_per_tx,
                chain_id: self.chain_id,
                master_signature: &self.master_signature,
                master_scheme: self.master_scheme,
                session_scheme: self.session_scheme,
                master_pubkey: &self.master_pubkey,
                session_pubkey_bytes: &self.session_pubkey_bytes,
            };
            hr.serialize(serializer)
        } else {
            let mut state = serializer.serialize_struct("SessionKeyAuthorization", 13)?;
            state.serialize_field("master_address", &self.master_address)?;
            state.serialize_field("session_pubkey", &self.session_pubkey)?;
            state.serialize_field("valid_until", &self.valid_until)?;
            state.serialize_field("max_gas_spend", &self.max_gas_spend)?;
            state.serialize_field("gas_spent", &self.gas_spent)?;
            state.serialize_field("scope", &self.scope)?;
            state.serialize_field("max_value_per_tx", &self.max_value_per_tx)?;
            state.serialize_field("chain_id", &self.chain_id)?;
            state.serialize_field("master_signature", &self.master_signature)?;
            let master_scheme_id = self.master_scheme.id();
            let session_scheme_id = self.session_scheme.id();
            state.serialize_field("master_scheme", &master_scheme_id)?;
            state.serialize_field("session_scheme", &session_scheme_id)?;
            state.serialize_field("master_pubkey", &self.master_pubkey)?;
            state.serialize_field("session_pubkey_bytes", &self.session_pubkey_bytes)?;
            state.end()
        }
    }
}

impl<'de> Deserialize<'de> for SessionKeyAuthorization {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            #[derive(Deserialize)]
            struct HumanReadable {
                master_address: [u8; 32],
                session_pubkey: [u8; 32],
                valid_until: u64,
                max_gas_spend: u64,
                gas_spent: u64,
                scope: u64,
                max_value_per_tx: u64,
                chain_id: u64,
                master_signature: Vec<u8>,
                #[serde(default = "default_scheme")]
                master_scheme: PqScheme,
                #[serde(default = "default_scheme")]
                session_scheme: PqScheme,
                #[serde(default)]
                master_pubkey: Option<Vec<u8>>,
                #[serde(default)]
                session_pubkey_bytes: Option<Vec<u8>>,
            }
            fn default_scheme() -> PqScheme {
                PqScheme::MlDsa44
            }
            let hr = HumanReadable::deserialize(deserializer)?;
            Ok(SessionKeyAuthorization {
                master_address: hr.master_address,
                session_pubkey: hr.session_pubkey,
                valid_until: hr.valid_until,
                max_gas_spend: hr.max_gas_spend,
                gas_spent: hr.gas_spent,
                scope: hr.scope,
                max_value_per_tx: hr.max_value_per_tx,
                chain_id: hr.chain_id,
                master_signature: hr.master_signature,
                master_scheme: hr.master_scheme,
                session_scheme: hr.session_scheme,
                master_pubkey: hr.master_pubkey,
                session_pubkey_bytes: hr.session_pubkey_bytes,
            })
        } else {
            struct BincodeVisitor;
            impl<'de> Visitor<'de> for BincodeVisitor {
                type Value = SessionKeyAuthorization;

                fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    formatter.write_str("a SessionKeyAuthorization struct")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let master_address: [u8; 32] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing master_address"))?;
                    let session_pubkey: [u8; 32] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing session_pubkey"))?;
                    let valid_until: u64 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing valid_until"))?;
                    let max_gas_spend: u64 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing max_gas_spend"))?;
                    let gas_spent: u64 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing gas_spent"))?;
                    let scope: u64 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing scope"))?;
                    let max_value_per_tx: u64 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing max_value_per_tx"))?;
                    let chain_id: u64 = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing chain_id"))?;
                    let master_signature: Vec<u8> = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("missing master_signature"))?;

                    let master_scheme_id: Option<u8> = match seq.next_element::<u8>() {
                        Ok(Some(id)) => Some(id),
                        _ => None,
                    };
                    let (master_scheme, session_scheme, master_pubkey, session_pubkey_bytes) =
                        match master_scheme_id {
                            None => (PqScheme::MlDsa44, PqScheme::MlDsa44, None, None),
                            Some(mid) => {
                                let master_scheme =
                                    PqScheme::from_id(mid).map_err(serde::de::Error::custom)?;
                                let session_scheme_id: u8 =
                                    seq.next_element()?.ok_or_else(|| {
                                        serde::de::Error::custom("missing session_scheme")
                                    })?;
                                let session_scheme = PqScheme::from_id(session_scheme_id)
                                    .map_err(serde::de::Error::custom)?;
                                let master_pubkey: Option<Vec<u8>> =
                                    seq.next_element()?.unwrap_or(None);
                                let session_pubkey_bytes: Option<Vec<u8>> =
                                    seq.next_element()?.unwrap_or(None);
                                (
                                    master_scheme,
                                    session_scheme,
                                    master_pubkey,
                                    session_pubkey_bytes,
                                )
                            }
                        };

                    Ok(SessionKeyAuthorization {
                        master_address,
                        session_pubkey,
                        valid_until,
                        max_gas_spend,
                        gas_spent,
                        scope,
                        max_value_per_tx,
                        chain_id,
                        master_signature,
                        master_scheme,
                        session_scheme,
                        master_pubkey,
                        session_pubkey_bytes,
                    })
                }
            }

            deserializer.deserialize_struct(
                "SessionKeyAuthorization",
                &[
                    "master_address",
                    "session_pubkey",
                    "valid_until",
                    "max_gas_spend",
                    "gas_spent",
                    "scope",
                    "max_value_per_tx",
                    "chain_id",
                    "master_signature",
                    "master_scheme",
                    "session_scheme",
                    "master_pubkey",
                    "session_pubkey_bytes",
                ],
                BincodeVisitor,
            )
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SupportedChain {
    Ton = 0,
    Arbitrum = 1,
    Ethereum = 2,
    Solana = 3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredHeader {
    pub chain: SupportedChain,
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub tx_root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryMerkleSibling {
    pub hash: [u8; 32],
    pub sibling_is_right: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryMerkleProof {
    pub leaf_index: u32,
    pub siblings: Vec<BinaryMerkleSibling>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositEvidence {
    QuorumAttested {
        signatures: Vec<([u8; 32], Vec<u8>)>,
    },
    TonCell {
        header: StoredHeader,
        header_signatures: Vec<([u8; 32], Vec<u8>)>,
        finalized_seqno: u64,
        boc_bytes: Vec<u8>,
    },
    EvmReceipt {
        header: StoredHeader,
        header_signatures: Vec<([u8; 32], Vec<u8>)>,
        finalized_number: u64,
        log_index: u32,
        receipt_value: Vec<u8>,
        mpt_proof: MerkleProof,
    },
    SolanaTx {
        header: StoredHeader,
        header_signatures: Vec<([u8; 32], Vec<u8>)>,
        finalized_slot: u64,
        tx_index: u32,
        proof: BinaryMerkleProof,
    },
    ZkProofPlaceholder {
        note: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseReceiptEvidence {
    pub req_id: u64,
    pub target_chain: SupportedChain,
    pub target_address: String,
    pub amount: u64,
    pub external_tx_hash: [u8; 32],
    pub finalized_head: u64,
    pub attestation_height: u64,
    pub signatures: Vec<([u8; 32], Vec<u8>)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeIntent {
    Deposit {
        chain: SupportedChain,
        source_tx_hash: [u8; 32],
        recipient: [u8; 32],
        amount: u64,
    },
    Withdraw {
        chain: SupportedChain,
        target_address: String,
        amount: u64,
    },
    Attest {
        source_tx_hash: [u8; 32],
        signatures: Vec<([u8; 32], Vec<u8>)>,
    },
    Release {
        req_id: u64,
    },
    DepositProof {
        source_tx_hash: [u8; 32],
        evidence: Box<DepositEvidence>,
    },
    Refund {
        req_id: u64,
    },
    Challenge {
        source_tx_hash: [u8; 32],
    },
    Resolve {
        dispute_id: u64,
    },
    ReleaseProof {
        req_id: u64,
        receipt: Box<ReleaseReceiptEvidence>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkMlProof {
    pub model_hash: [u8; 32],
    pub public_inputs: Vec<u64>,
    pub public_outputs: Vec<u64>,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantizedLayer {
    pub in_dim: usize,
    pub out_dim: usize,
    pub weights: Vec<i64>,
    pub biases: Vec<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantizedLinearModel {
    pub layers: Vec<QuantizedLayer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelSpec {
    pub spec_hash: [u8; 32],
    pub spec_bytes: Vec<u8>,
    pub setup_attestation: Vec<u8>,
    pub n_public_inputs: u64,
    pub in_dim: u64,
    pub out_dim: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationProof {
    pub model_hash: [u8; 32],
    pub spec_hash: [u8; 32],
    pub public_inputs: Vec<u64>,
    pub public_outputs: Vec<u64>,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub voter: ValidatorId,
    pub shard_id: ShardId,
    pub vote_a: Vote,
    pub vote_b: Vote,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactPqEquivocationEvidence {
    pub voter: ValidatorId,
    pub height: u64,
    pub round: u32,
    pub kind: VoteKind,
    pub block_hash_a: Option<[u8; 32]>,
    pub signature_a: Vec<u8>,
    pub block_hash_b: Option<[u8; 32]>,
    pub signature_b: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalEquivocationEvidence {
    pub proposer: ValidatorId,
    pub round: Round,
    pub block_a: Block,
    pub block_b: Block,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovAction {
    SetMinValidatorBond(u64),
    SetEquivocationSlashBps(u64),
    SetDefaultCommissionBps(u64),
    SetBlockReward(u64),
    SetPmmRedemptionBufferBps(u64),
    SetGovernanceQuorumBps(u64),
    Signal(String),
    RegisterOraclePublisher([u8; 32]),
    UnregisterOraclePublisher([u8; 32]),
    ResetOracleBreaker,
    SetMinGasLimit(u64),
    SoftwareUpgrade {
        name: String,
        height: u64,
        sha256: [u8; 32],
    },
    CancelUpgrade,
    SetFeeSplitBps {
        burn_bps: u64,
        proposer_bps: u64,
        staking_bps: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteChoice {
    Yes,
    No,
    Abstain,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmCarrierIntent {
    pub chain_id: u64,
    pub evm_tx: Vec<u8>,
    pub evm_address: [u8; 20],
    pub pq_pubkey: Vec<u8>,
    pub evm_signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmAddressClaim {
    pub chain_id: u64,
    pub evm_address: [u8; 20],
    pub pq_pubkey: Vec<u8>,
    pub binding_signature: Vec<u8>,
    pub evm_signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterValidatorPayload {
    pub amount: u64,
    pub commission_bps: u64,
    pub withdrawal_address: [u8; 32],
    pub voting_scheme: u8,
    pub voting_pubkey: Vec<u8>,
    pub voting_pop: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateVotingKeyPayload {
    pub validator_id: [u8; 32],
    pub rotation_seq: u64,
    pub new_scheme: u8,
    pub new_pubkey: Vec<u8>,
    pub pop_signature: Vec<u8>,
    pub cancel: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeWithdrawalPayload {
    pub validator_id: [u8; 32],
    pub new_withdrawal_address: [u8; 32],
    pub new_withdrawal_scheme: u8,
    pub new_withdrawal_pubkey: Vec<u8>,
    pub new_withdrawal_salt: [u8; 16],
    pub new_withdrawal_pop: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimWithdrawalPayload {
    pub validator_id: [u8; 32],
    pub withdrawal_address: [u8; 32],
    pub voting_sig: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum OpCode {
    Nop = 0,
    Push(u64),
    Pop,
    Add,
    Sub,
    Mul,
    Div,
    LoadBalance,
    Transfer {
        recipient: [u8; 32],
        amount: u64,
    },
    SysCallPlaceOrder {
        pair_id: u32,
        is_buy: bool,
        price: u64,
        amount: u64,
    },
    SysCallCancelOrder {
        order_id: u64,
    },
    SysCallVerifyZkMl,
    SysCallPatriciaLookup(CellHash),
    SysCallTokenTransfer {
        token_id: [u8; 32],
        to: [u8; 32],
        amount: u64,
    },
    SysCallTokenTransferFrom {
        token_id: [u8; 32],
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
    },
    SysCallTokenMint {
        token_id: [u8; 32],
        to: [u8; 32],
        amount: u64,
    },
    SysCallTokenBurn {
        token_id: [u8; 32],
        from: [u8; 32],
        amount: u64,
    },
    SysCallTokenApprove {
        token_id: [u8; 32],
        spender: [u8; 32],
        amount: u64,
    },
    SysCallTokenBalanceOf {
        token_id: [u8; 32],
        account: [u8; 32],
    },
    SysCallDeployContract {
        code: Vec<u8>,
    },
    SysCallCallContract {
        contract: [u8; 32],
        method: Vec<u8>,
        arg: i64,
    },
    SysCallStake {
        validator: [u8; 32],
        amount: u64,
    },
    SysCallUnbond {
        validator: [u8; 32],
        amount: u64,
    },
    SysCallDelegate {
        validator: [u8; 32],
        amount: u64,
    },
    SysCallUndelegate {
        validator: [u8; 32],
    },
    SysCallClaimRewards {
        validator: [u8; 32],
    },
    Halt,
    SysCallSubmitPriceFeed(Box<PriceFeedUpdate>),
    SysCallRevokeSession {
        session_pubkey: [u8; 32],
    },
    SysCallPmmBuy {
        usdt_micro: u64,
    },
    SysCallPmmSell {
        stell_nano: u64,
    },
    SysCallPublishSessionGrant(Box<SessionKeyAuthorization>),
    SysCallBridge(Box<BridgeIntent>),
    Reserved33ConfidentialTransfer(ReservedOpcodeMarker) = 33,
    SysCallActorSend {
        recipient: [u8; 32],
        value: u64,
        body: Vec<OpCode>,
        bounce: bool,
        gas_budget: u64,
    },
    SysCallVerifyZkMlReexec {
        model_id: [u8; 32],
        proof: Box<ZkMlProof>,
    },
    SysCallRegisterZkMlModel {
        model_id: [u8; 32],
        model: Box<QuantizedLinearModel>,
    },
    SysCallRegisterZkMlSpec {
        model_id: [u8; 32],
        spec: Box<ModelSpec>,
    },
    SysCallVerifyZkMlAttestation {
        model_id: [u8; 32],
        proof: Box<AttestationProof>,
    },
    SysCallTokenCreate {
        name: String,
        symbol: String,
        decimals: u8,
        initial_supply: u64,
        max_supply: Option<u64>,
    },
    Reserved40ConfidentialTransfer2(ReservedOpcodeMarker) = 40,
    Reserved41ConfidentialShield(ReservedOpcodeMarker) = 41,
    Reserved42ConfidentialUnshield(ReservedOpcodeMarker) = 42,
    SysCallRotateValidatorKey {
        old_validator: [u8; 32],
        new_validator: [u8; 32],
    },
    SysCallBeginUndelegate {
        validator: [u8; 32],
        amount: u64,
    },
    SysCallClaimDelegatorRewards {
        validator: [u8; 32],
    },
    SysCallVerifyPqSignature {
        scheme_id: u8,
        pubkey: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    },
    SysCallWithdrawSelfBond {
        validator: [u8; 32],
    },
    SysCallReportEquivocation {
        evidence: Box<EquivocationEvidence>,
    },
    SysCallReportPqEquivocation {
        evidence: Box<CompactPqEquivocationEvidence>,
    },
    SysCallCallContractArgs {
        contract: [u8; 32],
        method: Vec<u8>,
        args: Vec<i64>,
        calldata: Vec<u8>,
    },
    SysCallReportProposalEquivocation {
        evidence: Box<ProposalEquivocationEvidence>,
    },
    SysCallStakeWithCommission {
        validator: [u8; 32],
        amount: u64,
        commission_bps: u64,
    },
    SysCallGovPropose {
        proposal_id: u64,
        title: String,
        action: Box<GovAction>,
        height_observed: u64,
    },
    SysCallGovVote {
        proposal_id: u64,
        choice: VoteChoice,
        height_observed: u64,
    },
    SysCallSubmitPqPriceFeed(Box<PqPriceFeedUpdate>),
    SysCallUnjail {
        validator: [u8; 32],
    },
    SysCallEvmCarrier(Box<EvmCarrierIntent>),
    SysCallBindEvmAddress(Box<EvmAddressClaim>),
    SysCallRegisterValidator(Box<RegisterValidatorPayload>),
    SysCallRotateVotingKey(Box<RotateVotingKeyPayload>),
    SysCallChangeWithdrawal(Box<ChangeWithdrawalPayload>),
    SysCallClaimWithdrawal(Box<ClaimWithdrawalPayload>),
    SysCallAnnounceCommission {
        validator: [u8; 32],
        new_bps: u64,
    },
    SysCallApplyCommission {
        validator: [u8; 32],
    },
    SysCallDeployContractWithAbi {
        code: Vec<u8>,
        abi_json: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorAuthorization {
    pub sponsor: [u8; 32],
    pub max_fee_per_tx: u64,
    pub valid_until: u64,
    #[serde(default)]
    pub allowed_targets: Vec<[u8; 32]>,
    pub chain_id: u64,
    pub sponsor_sig: Vec<u8>,
    #[serde(default)]
    pub sponsor_scheme: Option<PqScheme>,
    #[serde(default)]
    pub sponsor_pubkey: Option<Vec<u8>>,
    #[serde(default)]
    pub sponsor_salt: Option<[u8; 16]>,
}

/// Canonical wire form of a transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionWire {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub gas_limit: u64,
    pub nonce: u64,
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    pub signature: Vec<u8>,
    pub payload: Vec<OpCode>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub gas_limit: u64,
    pub nonce: u64,
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    pub signature: Vec<u8>,
    pub payload: Vec<OpCode>,
    pub priority_fee_per_gas: u64,
}

impl Serialize for Transaction {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        TransactionWire {
            from: self.from,
            to: self.to,
            amount: self.amount,
            gas_limit: self.gas_limit,
            nonce: self.nonce,
            source_shard: self.source_shard,
            target_shard: self.target_shard,
            signature: Transaction::encode_priority_envelope(
                &self.signature,
                self.priority_fee_per_gas,
            ),
            payload: self.payload.clone(),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Transaction {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let wire = TransactionWire::deserialize(d)?;
        let (signature, priority_fee_per_gas) =
            Transaction::split_priority_envelope(&wire.signature);
        Ok(Transaction {
            from: wire.from,
            to: wire.to,
            amount: wire.amount,
            gas_limit: wire.gas_limit,
            nonce: wire.nonce,
            source_shard: wire.source_shard,
            target_shard: wire.target_shard,
            signature,
            payload: wire.payload,
            priority_fee_per_gas,
        })
    }
}

impl Transaction {
    const PRIORITY_ENVELOPE_LEN: usize = 16;

    pub fn split_priority_envelope(blob: &[u8]) -> (Vec<u8>, u64) {
        if blob.len() >= Self::PRIORITY_ENVELOPE_LEN {
            let split = blob.len() - Self::PRIORITY_ENVELOPE_LEN;
            if &blob[split..split + 8] == PRIORITY_FEE_COMMITMENT_TAG {
                let mut bid = [0u8; 8];
                bid.copy_from_slice(&blob[split + 8..]);
                return (blob[..split].to_vec(), u64::from_be_bytes(bid));
            }
        }
        (blob.to_vec(), 0)
    }

    pub fn encode_priority_envelope(body: &[u8], priority_fee_per_gas: u64) -> Vec<u8> {
        if priority_fee_per_gas == 0 {
            return body.to_vec();
        }
        let mut out = Vec::with_capacity(body.len() + Self::PRIORITY_ENVELOPE_LEN);
        out.extend_from_slice(body);
        out.extend_from_slice(PRIORITY_FEE_COMMITMENT_TAG);
        out.extend_from_slice(&priority_fee_per_gas.to_be_bytes());
        out
    }

    pub fn split_sponsor_envelope(blob: &[u8]) -> (usize, Option<SponsorAuthorization>, bool) {
        let tag_len = SPONSOR_SIG_TAG.len();
        if blob.len() < tag_len + 4 + 1 || blob[blob.len() - tag_len..] != SPONSOR_SIG_TAG[..] {
            return (blob.len(), None, false);
        }
        let len_off = blob.len() - tag_len - 4;
        let auth_len = u32::from_be_bytes([
            blob[len_off],
            blob[len_off + 1],
            blob[len_off + 2],
            blob[len_off + 3],
        ]) as usize;
        if auth_len == 0 || auth_len > SPONSOR_AUTH_MAX_BYTES || len_off < auth_len {
            return (blob.len(), None, true);
        }
        let inner_len = len_off - auth_len;
        if inner_len < ED25519_SIG_LEN {
            return (blob.len(), None, true);
        }
        let auth_bytes = &blob[inner_len..len_off];
        match bincode::deserialize::<SponsorAuthorization>(auth_bytes) {
            Ok(auth) => {
                let exact_size = bincode::serialized_size(&auth)
                    .ok()
                    .and_then(|n| usize::try_from(n).ok());
                if exact_size != Some(auth_bytes.len())
                    || (auth.sponsor_sig.len() != FALCON512_SIG_LEN
                        && auth.sponsor_sig.len() != ED25519_SIG_LEN)
                    || auth.allowed_targets.len() > SPONSOR_MAX_TARGETS
                {
                    return (blob.len(), None, true);
                }
                (inner_len, Some(auth), false)
            }
            Err(_) => (blob.len(), None, true),
        }
    }

    pub fn delegation_from_inner(sig: &[u8]) -> Option<(SessionKeyAuthorization, &[u8])> {
        for (sig_len, tag) in [
            (FALCON512_SIG_LEN, SESSION_FALCON_SIG_TAG),
            (ED25519_SIG_LEN, SESSION_SIG_TAG),
        ] {
            let tag_len = tag.len();
            if sig.len() <= sig_len + tag_len || sig[sig_len..sig_len + tag_len] != tag[..] {
                continue;
            }
            let grant: SessionKeyAuthorization =
                bincode::deserialize(&sig[sig_len + tag_len..]).ok()?;
            let expected = sig_len + tag_len + bincode::serialized_size(&grant).ok()? as usize;
            if expected != sig.len() {
                return None;
            }
            return Some((grant, &sig[..sig_len]));
        }
        None
    }

    pub fn chain_id_from_inner(inner_sig: &[u8]) -> Option<u64> {
        let tag_len = CHAIN_SIG_TAG.len();
        if inner_sig.len() == 64 + tag_len + 8 && inner_sig[64..64 + tag_len] == CHAIN_SIG_TAG[..] {
            let offset = 64 + tag_len;
            let bytes: [u8; 8] = inner_sig[offset..offset + 8].try_into().ok()?;
            Some(u64::from_be_bytes(bytes))
        } else {
            None
        }
    }

    pub fn is_evm_inner(inner_sig: &[u8]) -> bool {
        inner_sig.len() > EVM_SIG_TAG.len() && inner_sig[..EVM_SIG_TAG.len()] == EVM_SIG_TAG[..]
    }

    pub fn is_pq_inner(inner_sig: &[u8]) -> bool {
        inner_sig.starts_with(PQ_ENVELOPE_MAGIC)
    }

    /// Compute the deterministic transaction hash matching `stellereum::sharding::Transaction::compute_tx_hash`.
    pub fn compute_tx_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let mut payload_buf = Vec::new();
        self.hash_into(&mut hasher, &mut payload_buf);
        hasher.finalize().into()
    }

    /// Feed this transaction's hash preimage into `hasher`, reusing `payload_buf`.
    pub fn hash_into(&self, hasher: &mut Sha256, payload_buf: &mut Vec<u8>) {
        hasher.update(self.from);
        hasher.update(self.to);
        hasher.update(self.amount.to_be_bytes());
        hasher.update(self.gas_limit.to_be_bytes());
        hasher.update(self.nonce.to_be_bytes());
        hasher.update(self.source_shard.to_be_bytes());
        hasher.update(self.target_shard.to_be_bytes());
        hasher.update(b"PAYLOAD");
        payload_buf.clear();
        match bincode::serialize_into(&mut *payload_buf, &self.payload) {
            Ok(()) => {
                hasher.update((payload_buf.len() as u32).to_be_bytes());
                hasher.update(&payload_buf[..]);
            }
            Err(_) => hasher.update(u32::MAX.to_be_bytes()),
        }
        if self.priority_fee_per_gas != 0 {
            hasher.update(PRIORITY_FEE_COMMITMENT_TAG);
            hasher.update(self.priority_fee_per_gas.to_be_bytes());
        }
        let (inner_len, sponsor_auth, _) = Self::split_sponsor_envelope(&self.signature);
        let inner_sig = &self.signature[..inner_len];
        if let Some((d, _)) = Self::delegation_from_inner(inner_sig) {
            hasher.update(b"SESSION");
            payload_buf.clear();
            match bincode::serialize_into(&mut *payload_buf, &d) {
                Ok(()) => {
                    hasher.update((payload_buf.len() as u32).to_be_bytes());
                    hasher.update(&payload_buf[..]);
                }
                Err(_) => hasher.update(u32::MAX.to_be_bytes()),
            }
        }
        if let Some(cid) = Self::chain_id_from_inner(inner_sig) {
            hasher.update(CHAIN_ID_COMMITMENT_TAG);
            hasher.update(cid.to_be_bytes());
        }
        if let Some(ref auth) = sponsor_auth {
            hasher.update(SPONSOR_COMMITMENT_TAG);
            payload_buf.clear();
            match bincode::serialize_into(&mut *payload_buf, auth) {
                Ok(()) => {
                    hasher.update((payload_buf.len() as u32).to_be_bytes());
                    hasher.update(&payload_buf[..]);
                }
                Err(_) => hasher.update(u32::MAX.to_be_bytes()),
            }
        }
        if Self::is_evm_inner(inner_sig) {
            hasher.update(b"EVM_TX");
            hasher.update(&self.signature);
        }
        if Self::is_pq_inner(inner_sig) {
            hasher.update(b"PQ_ENV");
            hasher.update(&self.signature);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossShardMessage {
    pub msg_id: [u8; 32],
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    pub tx: Transaction,
    pub merkle_inclusion_proof: Option<MerkleProof>,
    pub source_state_root: CellHash,
    pub finalized_in_block: [u8; 32],
    pub source_balance: u64,
    pub bounce: bool,
    pub bounced: bool,
    pub trusted: bool,
    pub sender_pubkey_hash: Option<[u8; 32]>,
    pub sender_scheme: Option<u8>,
    pub xpc_phase: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub shard_id: ShardId,
    pub height: u64,
    pub prev_hash: [u8; 32],
    pub state_root: CellHash,
    pub transactions: Vec<Transaction>,
    pub cross_shard_out: Vec<CrossShardMessage>,
    pub timestamp: u64,
    pub proposer: [u8; 32],
    pub validator_signatures: Vec<([u8; 32], Vec<u8>)>,
    pub precommit_qc: Option<QuorumCertificate>,
    pub shard_headers: Vec<ShardHeaderCommitment>,
    pub order_merkle_root: [u8; 32],
    pub epoch_key_commitment: [u8; 32],
    pub last_qc: Option<QuorumCertificate>,
    pub mmr_epoch_root: [u8; 32],
    pub cnvrf_v3: Option<CnVrfV3BlockPayload>,
    pub round: u32,
}

impl Default for Block {
    fn default() -> Self {
        Self {
            shard_id: MASTERCHAIN_SHARD,
            height: 0,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: Vec::new(),
            cross_shard_out: Vec::new(),
            timestamp: 0,
            proposer: [0u8; 32],
            validator_signatures: Vec::new(),
            precommit_qc: None,
            shard_headers: Vec::new(),
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: None,
            round: 0,
        }
    }
}

impl Block {
    /// True when `shard_headers` is strictly ascending by `shard_id`, contains no
    /// duplicates, and does not commit to `MASTERCHAIN_SHARD` (`0`).
    pub fn shard_headers_canonical(&self) -> bool {
        let mut last: Option<ShardId> = None;
        for h in &self.shard_headers {
            if h.shard_id == MASTERCHAIN_SHARD {
                return false;
            }
            if let Some(prev) = last {
                if h.shard_id <= prev {
                    return false;
                }
            }
            last = Some(h.shard_id);
        }
        true
    }
}

/// Encode a `Block` in canonical v7 wire format (bincode fixint, bounded by `MAX_BLOCK_BYTES`).
pub fn encode_block_v7_canonical(block: &Block) -> Result<Vec<u8>, String> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BLOCK_BYTES as u64)
        .serialize(block)
        .map_err(|e| format!("canonical v7 block encode failed: {e}"))
}

/// Strictly decode a v7 `Block` from untrusted wire bytes:
/// - rejects empty or `> MAX_BLOCK_BYTES` (32 MiB) payloads
/// - uses `with_fixint_encoding()` and `reject_trailing_bytes()`
/// - no `LEGACY_BLOCK_TOLERANCE` (all trailing fields must be present)
/// - enforces `canonical == bytes` round-trip equality
/// - enforces `block.shard_headers_canonical()`
pub fn decode_block_v7_strict(bytes: &[u8]) -> Result<Block, String> {
    if bytes.is_empty() {
        return Err("empty block bytes".to_string());
    }
    if bytes.len() > MAX_BLOCK_BYTES {
        return Err(format!(
            "block of {} bytes exceeds MAX_BLOCK_BYTES ({})",
            bytes.len(),
            MAX_BLOCK_BYTES
        ));
    }
    let block: Block = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BLOCK_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| format!("strict v7 block decode failed: {e}"))?;

    let canonical = encode_block_v7_canonical(&block)?;
    if canonical.as_slice() != bytes {
        return Err("non-canonical block encoding (canonical != bytes)".to_string());
    }
    if !block.shard_headers_canonical() {
        return Err("non-canonical shard_headers in block".to_string());
    }
    Ok(block)
}

/// Encode a `Transaction` in canonical v7 wire format (bincode fixint, bounded by `MAX_BLOCK_BYTES`).
pub fn encode_transaction_v7_canonical(tx: &Transaction) -> Result<Vec<u8>, String> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BLOCK_BYTES as u64)
        .serialize(tx)
        .map_err(|e| format!("canonical v7 transaction encode failed: {e}"))
}

/// Strictly decode a v7 `Transaction` from untrusted wire bytes with round-trip validation.
pub fn decode_transaction_v7_strict(bytes: &[u8]) -> Result<Transaction, String> {
    if bytes.is_empty() {
        return Err("empty transaction bytes".to_string());
    }
    if bytes.len() > MAX_BLOCK_BYTES {
        return Err(format!(
            "transaction of {} bytes exceeds MAX_BLOCK_BYTES ({})",
            bytes.len(),
            MAX_BLOCK_BYTES
        ));
    }
    let tx: Transaction = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BLOCK_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| format!("strict v7 transaction decode failed: {e}"))?;

    let canonical = encode_transaction_v7_canonical(&tx)?;
    if canonical.as_slice() != bytes {
        return Err("non-canonical transaction encoding (canonical != bytes)".to_string());
    }
    Ok(tx)
}

/// Strictly decode a v7 `Vote` from untrusted wire bytes.
pub fn decode_vote_v7_strict(bytes: &[u8]) -> Result<Vote, String> {
    if bytes.is_empty() {
        return Err("empty vote bytes".to_string());
    }
    if bytes.len() > MAX_BLOCK_BYTES {
        return Err(format!(
            "vote of {} bytes exceeds MAX_BLOCK_BYTES ({})",
            bytes.len(),
            MAX_BLOCK_BYTES
        ));
    }
    let vote: Vote = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| format!("strict v7 vote decode failed: {e}"))?;
    let canonical = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BLOCK_BYTES as u64)
        .serialize(&vote)
        .map_err(|e| format!("canonical v7 vote encode failed: {e}"))?;
    if canonical.as_slice() != bytes {
        return Err("non-canonical vote encoding (canonical != bytes)".to_string());
    }
    Ok(vote)
}

/// Strictly decode a v7 `QuorumCertificate` from untrusted wire bytes.
pub fn decode_qc_v7_strict(bytes: &[u8]) -> Result<QuorumCertificate, String> {
    if bytes.is_empty() {
        return Err("empty QC bytes".to_string());
    }
    if bytes.len() > MAX_BLOCK_BYTES {
        return Err(format!(
            "QC of {} bytes exceeds MAX_BLOCK_BYTES ({})",
            bytes.len(),
            MAX_BLOCK_BYTES
        ));
    }
    let qc: QuorumCertificate = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| format!("strict v7 QC decode failed: {e}"))?;
    let canonical = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BLOCK_BYTES as u64)
        .serialize(&qc)
        .map_err(|e| format!("canonical v7 QC encode failed: {e}"))?;
    if canonical.as_slice() != bytes {
        return Err("non-canonical QC encoding (canonical != bytes)".to_string());
    }
    Ok(qc)
}
