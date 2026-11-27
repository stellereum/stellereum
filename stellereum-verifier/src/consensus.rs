//! Clean-room consensus verification, quorum accounting, and sortition.
//!
//! Zero dependencies on `stellereum`, `pqcrypto-falcon`, or `ed25519-dalek`:
//! - Exact `u128` power accounting in [`ValidatorSet`]
//! - Pure height-indexed [`PqKeyLookup`] (no global locks)
//! - Falcon-512 [`Vote::verify`] (`STELLEREUM_BFT_VOTE_V3`) and [`verify_proposer_signature`]
//! - [`QuorumCertificate::verify`] (`µQC` + `CEC` + `qc_split_required` + `mixed_quorum_pair_safe`)
//! - [`derive_sortition_committee`] (`STELL_SORTITION_V5`, `CNVRF_V3`, `rejection_sample_u64`)
//! - [`verify_block`] and [`verify_chain`]

use crate::block_hash::{
    compute_block_hash_at, timestamp_within_bounds, verify_cross_shard_msg_ids,
    verify_order_merkle_root, HEADER_COMMIT_ACTIVATION_HEIGHT,
};
use crate::falcon512::{derive_falcon512_address, verify_falcon512, DEFAULT_SALT};
use crate::tx::{verify_tx_at, ImplicitKeyRegistry};
use crate::wire::{
    decode_pq_epoch_envelope, decode_pq_micro_envelope, Block, BlockHash, Height,
    PqMicroCertificate, PqScheme, QuorumCertificate, Round, ShardId, ValidatorId, Vote, VoteKind,
    DEFAULT_CHAIN_ID, FALCON512_SIG_LEN, MASTERCHAIN_SHARD, MAX_COMMIT_CERT_SIGNERS,
    PQ_QC_MARKER_ID, PQ_UQC_MARKER_ID, VOTE_FALCON_MAGIC, VOTE_FALCON_PART_LEN,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const VOTE_SIGN_DOMAIN: &[u8] = b"STELLEREUM_BFT_VOTE_V3";
pub const MAX_PROPOSER_SIG_ENTRIES: usize = 8;
pub const MAX_PROPOSER_SIG_BYTES: usize = 4 * 1024;

pub const MICRO_COMMITTEE_MAX_SIZE: u32 = 128;
pub const QC_SPLIT_ACTIVATION_HEIGHT: u64 = u64::MAX;
pub const QC_SPLIT_BY_SIZE_THRESHOLD: usize = (MICRO_COMMITTEE_MAX_SIZE as usize * 3) / 2;

pub const SORTITION_DRAW_DOMAIN: &str = "STELL_SORTITION_V5";
pub const SORTITION_UNBIASED_MAX_ATTEMPTS: u32 = 64;
pub const SORTITION_UNBIASED_ACTIVATION_HEIGHT: u64 = u64::MAX;

pub const CNVRF_V3_ACTIVATION_HEIGHT: u64 = u64::MAX;
pub const CNVRF_V3_EPOCH_LEN: u64 = 30_000;
pub const CNVRF_V3_DRAW_DOMAIN: &str = "STELL_SORTITION_CNVRF_V3";
pub const CNVRF_V3_PROPOSER_DOMAIN: &str = "STELL_PROPOSER_CNVRF_V3";

pub const PROPOSER_DOMAIN: &str = "STELL_PROPOSER_V1";
pub const PROPOSER_UNBIASED_DOMAIN: &str = "STELL_PROPOSER_UNBIASED_V1";

/// Epoch-bound 48-byte CN-VRF v3 randomness beacon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochBeacon {
    pub epoch: u64,
    pub output: [u8; 48],
}

/// Committee and proposer selection schedule at one height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitteeSchedule {
    ParentHash,
    Beacon(Option<EpochBeacon>),
}

impl CommitteeSchedule {
    pub fn is_beacon(&self) -> bool {
        matches!(self, Self::Beacon(_))
    }

    pub fn beacon(&self) -> Option<&EpochBeacon> {
        match self {
            Self::Beacon(Some(b)) => Some(b),
            Self::ParentHash | Self::Beacon(None) => None,
        }
    }
}

/// Pure, explicit consensus configuration (no global/thread-local mutable state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusConfig {
    pub chain_id: u64,
    pub qc_split_activation_height: Height,
    pub sortition_unbiased_activation_height: Height,
    pub header_commit_activation_height: Height,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID,
            qc_split_activation_height: QC_SPLIT_ACTIVATION_HEIGHT,
            sortition_unbiased_activation_height: SORTITION_UNBIASED_ACTIVATION_HEIGHT,
            header_commit_activation_height: HEADER_COMMIT_ACTIVATION_HEIGHT,
        }
    }
}

/// Pure, deterministic lookup for validator PQ keys at a given height.
pub trait PqKeyLookup {
    fn pq_key_at(&self, validator: &ValidatorId, height: Height) -> Option<(PqScheme, Vec<u8>)>;
}

impl<T: PqKeyLookup + ?Sized> PqKeyLookup for &T {
    fn pq_key_at(&self, validator: &ValidatorId, height: Height) -> Option<(PqScheme, Vec<u8>)> {
        (*self).pq_key_at(validator, height)
    }
}

impl PqKeyLookup for BTreeMap<ValidatorId, (PqScheme, Vec<u8>)> {
    fn pq_key_at(&self, validator: &ValidatorId, _height: Height) -> Option<(PqScheme, Vec<u8>)> {
        self.get(validator).cloned()
    }
}

impl PqKeyLookup for HashMap<ValidatorId, (PqScheme, Vec<u8>)> {
    fn pq_key_at(&self, validator: &ValidatorId, _height: Height) -> Option<(PqScheme, Vec<u8>)> {
        self.get(validator).cloned()
    }
}

/// Height-aware PQ key entry for clean-room historical verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeightedPqKey {
    pub scheme: PqScheme,
    pub pubkey: Vec<u8>,
    pub activated_at: Height,
    pub superseded_at: Option<Height>,
}

/// In-memory height-indexed PQ key store implementing [`PqKeyLookup`].
#[derive(Clone, Debug, Default)]
pub struct StaticPqKeyRegistry {
    pub entries: BTreeMap<ValidatorId, Vec<HeightedPqKey>>,
}

impl StaticPqKeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, validator: ValidatorId, scheme: PqScheme, pubkey: Vec<u8>) {
        self.insert_window(validator, scheme, pubkey, 0, None);
    }

    pub fn insert_window(
        &mut self,
        validator: ValidatorId,
        scheme: PqScheme,
        pubkey: Vec<u8>,
        activated_at: Height,
        superseded_at: Option<Height>,
    ) {
        self.entries
            .entry(validator)
            .or_default()
            .push(HeightedPqKey {
                scheme,
                pubkey,
                activated_at,
                superseded_at,
            });
    }
}

impl PqKeyLookup for StaticPqKeyRegistry {
    fn pq_key_at(&self, validator: &ValidatorId, height: Height) -> Option<(PqScheme, Vec<u8>)> {
        let windows = self.entries.get(validator)?;
        for w in windows.iter().rev() {
            let active = height >= w.activated_at
                && match w.superseded_at {
                    Some(end) => height < end,
                    None => true,
                };
            if active {
                return Some((w.scheme, w.pubkey.clone()));
            }
        }
        None
    }
}

// ============================================================================
// Quorum & Sortition Math
// ============================================================================

/// Consensus-domain quorum floor: `floor(2n/3) + 1`, computed in `u128`.
pub fn consensus_quorum_min(n: u64) -> u64 {
    ((n as u128 * 2) / 3 + 1) as u64
}

pub fn pq_micro_quorum_threshold(committee_size: u32) -> usize {
    if committee_size == 0 {
        return usize::MAX;
    }
    consensus_quorum_min(committee_size as u64) as usize
}

pub fn pq_micro_quorum_power(committee_total_power: u64) -> u64 {
    if committee_total_power == 0 {
        return u64::MAX;
    }
    consensus_quorum_min(committee_total_power)
}

pub fn micro_committee_size(validator_count: usize) -> u32 {
    validator_count.min(MICRO_COMMITTEE_MAX_SIZE as usize) as u32
}

pub fn pq_micro_required_power(committee_total_power: u64, network_total_power: u64) -> u64 {
    if committee_total_power == 0 {
        return u64::MAX;
    }
    let committee_two_thirds = consensus_quorum_min(committee_total_power);
    let network_two_thirds = match network_total_power {
        0 => u64::MAX,
        w => consensus_quorum_min(w),
    };
    committee_two_thirds.max(network_two_thirds)
}

pub fn pq_micro_advisory_power(committee_total_power: u64) -> u64 {
    if committee_total_power == 0 {
        return u64::MAX;
    }
    consensus_quorum_min(committee_total_power)
}

pub fn pq_full_required_power(network_total_power: u64) -> u64 {
    if network_total_power == 0 {
        return u64::MAX;
    }
    consensus_quorum_min(network_total_power)
}

pub fn qc_split_active_at(height: Height, qc_split_activation: Height) -> bool {
    height >= qc_split_activation
}

pub fn qc_split_required_at(
    height: Height,
    validator_count: usize,
    qc_split_activation: Height,
) -> bool {
    qc_split_active_at(height, qc_split_activation) || validator_count >= QC_SPLIT_BY_SIZE_THRESHOLD
}

pub fn qc_split_required(height: Height, validator_count: usize) -> bool {
    qc_split_required_at(height, validator_count, QC_SPLIT_ACTIVATION_HEIGHT)
}

pub fn mixed_quorum_pair_safe(t_micro: u64, t_full: u64, total_power: u64) -> bool {
    if total_power == 0 || t_micro == u64::MAX || t_full == u64::MAX {
        return false;
    }
    let (t_mu, t_f, w) = (t_micro as u128, t_full as u128, total_power as u128);
    t_mu + t_f > w + w / 3
}

pub fn sortition_unbiased_active_at(height: Height, activation: Height) -> bool {
    activation != u64::MAX && height >= activation
}

/// Exact 64-bit rejection sampling over `[0, modulus)` using BLAKE3 key derivation.
pub fn rejection_sample_u64(domain: &str, seed: &[u8; 32], step: Option<u32>, modulus: u64) -> u64 {
    debug_assert!(modulus > 0);
    let modulus_u128 = modulus as u128;
    let two_pow_64 = 1u128 << 64;
    let limit = two_pow_64 - (two_pow_64 % modulus_u128);
    let mut last_rand = 0u64;
    for attempt in 0..SORTITION_UNBIASED_MAX_ATTEMPTS {
        let mut hasher = blake3::Hasher::new_derive_key(domain);
        hasher.update(seed);
        if let Some(s) = step {
            hasher.update(&s.to_le_bytes());
        }
        hasher.update(&attempt.to_le_bytes());
        let hash = hasher.finalize();
        let rand_val = u64::from_le_bytes(
            hash.as_bytes()[0..8]
                .try_into()
                .expect("blake3 digest is 32 bytes"),
        );
        last_rand = rand_val;
        if (rand_val as u128) < limit {
            return ((rand_val as u128) % modulus_u128) as u64;
        }
    }
    ((last_rand as u128) % modulus_u128) as u64
}

struct StableWeightIndex {
    tree: Vec<u128>,
    n: usize,
}

impl StableWeightIndex {
    fn new(weights: &[u64]) -> Self {
        let n = weights.len();
        let mut tree = vec![0u128; n + 1];
        for (i, &w) in weights.iter().enumerate() {
            let mut j = i + 1;
            while j <= n {
                tree[j] += w as u128;
                j += j & j.wrapping_neg();
            }
        }
        Self { tree, n }
    }

    fn remove(&mut self, index: usize, weight: u64) {
        let mut j = index + 1;
        while j <= self.n {
            self.tree[j] -= weight as u128;
            j += j & j.wrapping_neg();
        }
    }

    fn first_prefix_gt(&self, ticket: u128) -> usize {
        let mut pos = 0usize;
        let mut acc: u128 = 0;
        let mut step = 1usize;
        while step <= self.n {
            step <<= 1;
        }
        step >>= 1;
        while step > 0 {
            let next = pos + step;
            if next <= self.n && acc + self.tree[next] <= ticket {
                pos = next;
                acc += self.tree[next];
            }
            step >>= 1;
        }
        pos
    }
}

pub fn select_committee_from_seed(
    validators: &ValidatorSet,
    committee_size: u32,
    domain: &str,
    seed: &[u8; 32],
) -> Vec<ValidatorId> {
    select_committee_from_seed_at(
        validators,
        committee_size,
        domain,
        seed,
        0,
        SORTITION_UNBIASED_ACTIVATION_HEIGHT,
    )
}

pub fn select_committee_from_seed_at(
    validators: &ValidatorSet,
    committee_size: u32,
    domain: &str,
    seed: &[u8; 32],
    height: Height,
    sortition_unbiased_activation: Height,
) -> Vec<ValidatorId> {
    if committee_size == 0 || validators.is_empty() || validators.total_power() == 0 {
        return Vec::new();
    }

    let pool: Vec<(ValidatorId, u64)> = validators
        .validators
        .iter()
        .filter(|(_, &p)| p > 0)
        .map(|(&id, &p)| (id, p))
        .collect();

    let target_k = (committee_size as usize).min(pool.len());
    if target_k == 0 {
        return Vec::new();
    }
    if target_k == pool.len() {
        let mut ids: Vec<ValidatorId> = pool.into_iter().map(|(id, _)| id).collect();
        ids.sort_unstable();
        return ids;
    }

    let unbiased = sortition_unbiased_active_at(height, sortition_unbiased_activation);
    let mut selected = Vec::with_capacity(target_k);
    let mut total_power: u64 = pool.iter().fold(0u64, |acc, (_, p)| acc.saturating_add(*p));

    let ids: Vec<ValidatorId> = pool.iter().map(|(id, _)| *id).collect();
    let mut weights: Vec<u64> = pool.iter().map(|(_, p)| *p).collect();
    let mut index = StableWeightIndex::new(&weights);

    for step in 0..target_k {
        if total_power == 0 {
            break;
        }

        let ticket = if unbiased {
            rejection_sample_u64(domain, seed, Some(step as u32), total_power)
        } else {
            let mut hasher = blake3::Hasher::new_derive_key(domain);
            hasher.update(seed);
            hasher.update(&(step as u32).to_le_bytes());
            let hash = hasher.finalize();
            let rand_val = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap());
            rand_val % total_power
        };

        let idx = index.first_prefix_gt(ticket as u128);
        let chosen_idx = if idx < ids.len() { idx } else { 0 };

        let winner_id = ids[chosen_idx];
        let winner_power = weights[chosen_idx];
        weights[chosen_idx] = 0;
        index.remove(chosen_idx, winner_power);
        total_power = total_power.saturating_sub(winner_power);
        selected.push(winner_id);
    }

    selected.sort_unstable();
    selected
}

pub fn sortition_seed(prev_block_hash: &[u8; 32], height: Height, round: Round) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SORTITION_DRAW_DOMAIN);
    hasher.update(prev_block_hash);
    hasher.update(&height.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    *hasher.finalize().as_bytes()
}

pub fn derive_sortition_committee_at(
    validators: &ValidatorSet,
    height: Height,
    round: Round,
    committee_size: u32,
    prev_block_hash: &[u8; 32],
    sortition_unbiased_activation: Height,
) -> Vec<ValidatorId> {
    if committee_size == 0 || validators.is_empty() || validators.total_power() == 0 {
        return Vec::new();
    }
    let seed = sortition_seed(prev_block_hash, height, round);
    select_committee_from_seed_at(
        validators,
        committee_size,
        SORTITION_DRAW_DOMAIN,
        &seed,
        height,
        sortition_unbiased_activation,
    )
}

pub fn derive_sortition_committee(
    validators: &ValidatorSet,
    height: Height,
    round: Round,
    committee_size: u32,
    prev_block_hash: &[u8; 32],
) -> Vec<ValidatorId> {
    derive_sortition_committee_at(
        validators,
        height,
        round,
        committee_size,
        prev_block_hash,
        SORTITION_UNBIASED_ACTIVATION_HEIGHT,
    )
}

pub fn cnvrf_v3_epoch_of_height(height: Height) -> u64 {
    height / CNVRF_V3_EPOCH_LEN
}

pub fn cnvrf_v3_beacon_seed(
    beacon_output: &[u8; 48],
    beacon_epoch: u64,
    height: Height,
    round: Round,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CNVRF_V3_DRAW_DOMAIN);
    hasher.update(beacon_output);
    hasher.update(&beacon_epoch.to_le_bytes());
    hasher.update(&height.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    *hasher.finalize().as_bytes()
}

pub fn cnvrf_v3_proposer_seed(
    beacon_output: &[u8; 48],
    beacon_epoch: u64,
    height: Height,
    round: Round,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(CNVRF_V3_PROPOSER_DOMAIN);
    hasher.update(beacon_output);
    hasher.update(&beacon_epoch.to_le_bytes());
    hasher.update(&height.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    *hasher.finalize().as_bytes()
}

pub fn cnvrf_v3_beacon_draw_committee_at(
    validators: &ValidatorSet,
    height: Height,
    round: Round,
    committee_size: u32,
    beacon_output: &[u8; 48],
    beacon_epoch: u64,
    sortition_unbiased_activation: Height,
) -> Vec<ValidatorId> {
    if beacon_epoch != cnvrf_v3_epoch_of_height(height) {
        return Vec::new();
    }
    if committee_size == 0 || validators.is_empty() || validators.total_power() == 0 {
        return Vec::new();
    }
    let seed = cnvrf_v3_beacon_seed(beacon_output, beacon_epoch, height, round);
    select_committee_from_seed_at(
        validators,
        committee_size,
        CNVRF_V3_DRAW_DOMAIN,
        &seed,
        height,
        sortition_unbiased_activation,
    )
}

pub fn cnvrf_v3_beacon_draw_committee(
    validators: &ValidatorSet,
    height: Height,
    round: Round,
    committee_size: u32,
    beacon_output: &[u8; 48],
    beacon_epoch: u64,
) -> Vec<ValidatorId> {
    cnvrf_v3_beacon_draw_committee_at(
        validators,
        height,
        round,
        committee_size,
        beacon_output,
        beacon_epoch,
        SORTITION_UNBIASED_ACTIVATION_HEIGHT,
    )
}

pub fn committee_for_height_at(
    validators: &ValidatorSet,
    height: Height,
    round: Round,
    committee_size: u32,
    parent_hash: Option<&[u8; 32]>,
    schedule: CommitteeSchedule,
    sortition_unbiased_activation: Height,
) -> Vec<ValidatorId> {
    match schedule {
        CommitteeSchedule::ParentHash => match parent_hash {
            Some(parent) => derive_sortition_committee_at(
                validators,
                height,
                round,
                committee_size,
                parent,
                sortition_unbiased_activation,
            ),
            None => Vec::new(),
        },
        CommitteeSchedule::Beacon(beacon) => match beacon {
            Some(b) => cnvrf_v3_beacon_draw_committee_at(
                validators,
                height,
                round,
                committee_size,
                &b.output,
                b.epoch,
                sortition_unbiased_activation,
            ),
            None => Vec::new(),
        },
    }
}

pub fn committee_for_height(
    validators: &ValidatorSet,
    height: Height,
    round: Round,
    committee_size: u32,
    parent_hash: Option<&[u8; 32]>,
    schedule: CommitteeSchedule,
) -> Vec<ValidatorId> {
    committee_for_height_at(
        validators,
        height,
        round,
        committee_size,
        parent_hash,
        schedule,
        SORTITION_UNBIASED_ACTIVATION_HEIGHT,
    )
}

// ============================================================================
// Validator Set (exact u128 power accounting)
// ============================================================================

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: BTreeMap<ValidatorId, u64>,
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_list(list: Vec<(ValidatorId, u64)>) -> Self {
        let mut s = Self::new();
        for (id, power) in list {
            s.add(id, power);
        }
        s
    }

    pub fn add(&mut self, id: ValidatorId, power: u64) {
        if power > 0 {
            self.validators.insert(id, power);
        }
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    pub fn contains(&self, id: &ValidatorId) -> bool {
        self.validators.contains_key(id)
    }

    pub fn power_of(&self, id: &ValidatorId) -> u64 {
        self.validators.get(id).copied().unwrap_or(0)
    }

    pub fn total_power_exact(&self) -> u128 {
        self.validators.values().map(|&p| p as u128).sum()
    }

    pub fn power_total_representable(&self) -> bool {
        self.total_power_exact() <= u64::MAX as u128
    }

    pub fn total_power(&self) -> u64 {
        self.validators
            .values()
            .fold(0u64, |acc, &p| acc.saturating_add(p))
    }

    pub fn quorum_power_exact(&self) -> u128 {
        let total = self.total_power_exact();
        if total == 0 {
            return u128::MAX;
        }
        (total * 2) / 3 + 1
    }

    pub fn quorum_power(&self) -> u64 {
        let total = self.total_power_exact();
        if total == 0 || total > u64::MAX as u128 {
            return u64::MAX;
        }
        consensus_quorum_min(total as u64)
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"STELL-CONSENSUS-VOTE-CACHE-SET-V1");
        h.update(&(self.validators.len() as u64).to_le_bytes());
        for (id, power) in &self.validators {
            h.update(id);
            h.update(&power.to_le_bytes());
        }
        *h.finalize().as_bytes()
    }

    pub fn proposer_from_digest(&self, digest: &[u8; 32]) -> Option<ValidatorId> {
        self.proposer_from_digest_at(digest, 0, SORTITION_UNBIASED_ACTIVATION_HEIGHT)
    }

    pub fn proposer_from_digest_at(
        &self,
        digest: &[u8; 32],
        height: Height,
        sortition_unbiased_activation: Height,
    ) -> Option<ValidatorId> {
        let total = self.total_power();
        if total == 0 {
            return None;
        }
        fn gcd(mut a: u64, mut b: u64) -> u64 {
            while b != 0 {
                let t = b;
                b = a % b;
                a = t;
            }
            a
        }
        let g = self.validators.values().fold(0u64, |acc, &p| gcd(acc, p));
        let g = if g == 0 { 1 } else { g };
        let range = total / g;
        if range == 0 {
            return self.validators.keys().next().copied();
        }
        let slot = if sortition_unbiased_active_at(height, sortition_unbiased_activation) {
            rejection_sample_u64(PROPOSER_UNBIASED_DOMAIN, digest, None, range)
        } else {
            u64::from_le_bytes(digest[..8].try_into().expect("32-byte digest")) % range
        };
        let mut ids: Vec<(&ValidatorId, &u64)> = self.validators.iter().collect();
        ids.sort_unstable();
        let mut acc = 0u64;
        for (id, power) in ids {
            acc = acc.saturating_add(*power / g);
            if slot < acc {
                return Some(*id);
            }
        }
        self.validators.keys().next().copied()
    }

    pub fn proposer_for(&self, height: Height, round: Round) -> Option<ValidatorId> {
        self.proposer_for_at(height, round, SORTITION_UNBIASED_ACTIVATION_HEIGHT)
    }

    pub fn proposer_for_at(
        &self,
        height: Height,
        round: Round,
        sortition_unbiased_activation: Height,
    ) -> Option<ValidatorId> {
        if self.total_power() == 0 {
            return None;
        }
        let mut hasher = blake3::Hasher::new_derive_key(PROPOSER_DOMAIN);
        hasher.update(&height.to_le_bytes());
        hasher.update(&round.to_le_bytes());
        let digest = hasher.finalize();
        self.proposer_from_digest_at(digest.as_bytes(), height, sortition_unbiased_activation)
    }

    pub fn proposer_for_with_schedule(
        &self,
        height: Height,
        round: Round,
        schedule: CommitteeSchedule,
    ) -> Option<ValidatorId> {
        self.proposer_for_with_schedule_at(
            height,
            round,
            schedule,
            SORTITION_UNBIASED_ACTIVATION_HEIGHT,
        )
    }

    pub fn proposer_for_with_schedule_at(
        &self,
        height: Height,
        round: Round,
        schedule: CommitteeSchedule,
        sortition_unbiased_activation: Height,
    ) -> Option<ValidatorId> {
        let beacon = match schedule {
            CommitteeSchedule::ParentHash => {
                return self.proposer_for_at(height, round, sortition_unbiased_activation)
            }
            CommitteeSchedule::Beacon(beacon) => beacon?,
        };
        if beacon.epoch != cnvrf_v3_epoch_of_height(height) {
            return None;
        }
        let seed = cnvrf_v3_proposer_seed(&beacon.output, beacon.epoch, height, round);
        self.proposer_from_digest_at(&seed, height, sortition_unbiased_activation)
    }

    pub fn qc_signed_power(
        &self,
        qc: &QuorumCertificate,
        keys: &dyn PqKeyLookup,
        config: ConsensusConfig,
    ) -> u64 {
        self.qc_signed_power_with_schedule(qc, keys, CommitteeSchedule::ParentHash, config)
    }

    pub fn qc_signed_power_with_schedule(
        &self,
        qc: &QuorumCertificate,
        keys: &dyn PqKeyLookup,
        schedule: CommitteeSchedule,
        config: ConsensusConfig,
    ) -> u64 {
        qc.signers_set_with_config(self, keys, schedule, config)
            .iter()
            .map(|v| self.power_of(v))
            .fold(0u64, |a, p| a.saturating_add(p))
    }

    pub fn qc_meets_quorum(
        &self,
        qc: &QuorumCertificate,
        keys: &dyn PqKeyLookup,
        config: ConsensusConfig,
    ) -> bool {
        self.qc_meets_quorum_with_schedule(qc, keys, CommitteeSchedule::ParentHash, config)
    }

    pub fn qc_meets_quorum_with_schedule(
        &self,
        qc: &QuorumCertificate,
        keys: &dyn PqKeyLookup,
        schedule: CommitteeSchedule,
        config: ConsensusConfig,
    ) -> bool {
        self.power_total_representable()
            && self.qc_signed_power_with_schedule(qc, keys, schedule, config) >= self.quorum_power()
    }
}

// ============================================================================
// Votes & Proposer Signatures
// ============================================================================

pub fn vote_sign_bytes_for_shard(
    chain_id: u64,
    shard_id: ShardId,
    height: Height,
    round: Round,
    kind: VoteKind,
    block_hash: &Option<BlockHash>,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(88);
    m.extend_from_slice(VOTE_SIGN_DOMAIN);
    m.extend_from_slice(&chain_id.to_be_bytes());
    m.extend_from_slice(&shard_id.to_be_bytes());
    m.extend_from_slice(&height.to_be_bytes());
    m.extend_from_slice(&round.to_be_bytes());
    m.push(match kind {
        VoteKind::Prevote => 0,
        VoteKind::Precommit => 1,
    });
    match block_hash {
        Some(h) => {
            m.push(1);
            m.extend_from_slice(h);
        }
        None => m.push(0),
    }
    m
}

pub fn vote_sign_bytes(
    chain_id: u64,
    height: Height,
    round: Round,
    kind: VoteKind,
    block_hash: &Option<BlockHash>,
) -> Vec<u8> {
    vote_sign_bytes_for_shard(chain_id, MASTERCHAIN_SHARD, height, round, kind, block_hash)
}

impl Vote {
    pub fn falcon_signature(&self) -> Option<&[u8]> {
        if self.signature.len() == VOTE_FALCON_PART_LEN
            && self.signature.starts_with(VOTE_FALCON_MAGIC)
        {
            Some(&self.signature[80..80 + FALCON512_SIG_LEN])
        } else if self.signature.len() == FALCON512_SIG_LEN {
            Some(&self.signature)
        } else {
            None
        }
    }

    pub fn verify(&self, keys: &dyn PqKeyLookup, chain_id: u64) -> bool {
        if self.signature.len() > VOTE_FALCON_PART_LEN {
            return false;
        }
        let Some(falcon_sig) = self.falcon_signature() else {
            return false;
        };
        let Some((scheme, pk)) = keys.pq_key_at(&self.voter, self.height) else {
            return false;
        };
        if scheme != PqScheme::Falcon512 || scheme.is_disabled() {
            return false;
        }
        let msg = vote_sign_bytes_for_shard(
            chain_id,
            self.shard_id,
            self.height,
            self.round,
            self.kind,
            &self.block_hash,
        );
        verify_falcon512(&pk, &msg, falcon_sig)
    }
}

pub fn proposer_signature_list_within_cap(block: &Block) -> bool {
    if block.validator_signatures.len() > MAX_PROPOSER_SIG_ENTRIES {
        return false;
    }
    let total = block
        .validator_signatures
        .iter()
        .fold(0usize, |acc, (_, sig)| acc.saturating_add(sig.len()));
    total <= MAX_PROPOSER_SIG_BYTES
}

pub fn verify_proposer_signature_with_config(
    block: &Block,
    keys: &dyn PqKeyLookup,
    config: ConsensusConfig,
) -> bool {
    let hash = compute_block_hash_at(
        block,
        config.chain_id,
        config.header_commit_activation_height,
    );
    verify_proposer_signature_with_hash(block, &hash, keys)
}

pub fn verify_proposer_signature(block: &Block, keys: &dyn PqKeyLookup, chain_id: u64) -> bool {
    verify_proposer_signature_with_config(
        block,
        keys,
        ConsensusConfig {
            chain_id,
            ..ConsensusConfig::default()
        },
    )
}

pub fn verify_proposer_signature_with_hash(
    block: &Block,
    hash: &[u8; 32],
    keys: &dyn PqKeyLookup,
) -> bool {
    if !proposer_signature_list_within_cap(block) {
        return false;
    }
    let Some((scheme, pk)) = keys.pq_key_at(&block.proposer, block.height) else {
        return false;
    };
    if scheme != PqScheme::Falcon512 || scheme.is_disabled() {
        return false;
    }
    let expected_addr = derive_falcon512_address(&pk, &DEFAULT_SALT);
    let mut slot_candidates = 0usize;
    for (signer_id, sig_bytes) in &block.validator_signatures {
        if *signer_id != block.proposer && *signer_id != expected_addr {
            continue;
        }
        if sig_bytes.len() != scheme.signature_size() {
            continue;
        }
        slot_candidates += 1;
        if slot_candidates > MAX_PROPOSER_SIG_ENTRIES {
            return false;
        }
        if verify_falcon512(&pk, hash, sig_bytes) {
            return true;
        }
    }
    false
}

// ============================================================================
// Quorum Certificate Verification (µQC + CEC)
// ============================================================================

impl QuorumCertificate {
    pub fn shard(&self) -> ShardId {
        self.shard_id
    }

    pub fn verify(&self, validators: &ValidatorSet, keys: &dyn PqKeyLookup) -> bool {
        self.verify_with_config(
            validators,
            keys,
            CommitteeSchedule::ParentHash,
            ConsensusConfig::default(),
        )
    }

    pub fn verify_with_schedule(
        &self,
        validators: &ValidatorSet,
        keys: &dyn PqKeyLookup,
        schedule: CommitteeSchedule,
    ) -> bool {
        self.verify_with_config(validators, keys, schedule, ConsensusConfig::default())
    }

    pub fn verify_with_config(
        &self,
        validators: &ValidatorSet,
        keys: &dyn PqKeyLookup,
        schedule: CommitteeSchedule,
        config: ConsensusConfig,
    ) -> bool {
        if self.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
            return false;
        }
        if self.resolve_micro_certificate().is_err() {
            return false;
        }
        let msg = vote_sign_bytes_for_shard(
            config.chain_id,
            self.shard_id,
            self.height,
            self.round,
            self.kind,
            &self.block_hash,
        );
        for (voter, payload) in &self.signatures {
            if *voter == PQ_UQC_MARKER_ID {
                if let Some(cert) = decode_pq_micro_envelope(payload) {
                    if cert.scheme != PqScheme::Falcon512 || cert.scheme.is_disabled() {
                        continue;
                    }
                    if self.verify_micro_cert_with_config(
                        &cert, validators, &msg, keys, schedule, config,
                    ) {
                        return true;
                    }
                }
            } else if *voter == PQ_QC_MARKER_ID {
                if let Some(cert) =
                    decode_pq_epoch_envelope(payload).or_else(|| decode_pq_micro_envelope(payload))
                {
                    if cert.scheme != PqScheme::Falcon512 || cert.scheme.is_disabled() {
                        continue;
                    }
                    if self.verify_epoch_cert(&cert, validators, &msg, keys) {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn verify_and_signed_power_with_config(
        &self,
        validators: &ValidatorSet,
        keys: &dyn PqKeyLookup,
        schedule: CommitteeSchedule,
        config: ConsensusConfig,
    ) -> (bool, u64) {
        let (verified, signers) = self.verify_and_signers_inner(validators, keys, schedule, config);
        let multi_marker = self.recognized_marker_count() > 1;
        if !verified && multi_marker {
            return (false, 0);
        }
        let attributed = if verified && multi_marker {
            self.signers_set_with_config(validators, keys, schedule, config)
        } else {
            signers
        };
        let power = attributed
            .iter()
            .map(|v| validators.power_of(v))
            .fold(0u64, |a, p| a.saturating_add(p));
        (verified, power)
    }

    pub fn signers_set(
        &self,
        validators: &ValidatorSet,
        keys: &dyn PqKeyLookup,
    ) -> HashSet<ValidatorId> {
        self.signers_set_with_config(
            validators,
            keys,
            CommitteeSchedule::ParentHash,
            ConsensusConfig::default(),
        )
    }

    pub fn signers_set_with_config(
        &self,
        validators: &ValidatorSet,
        keys: &dyn PqKeyLookup,
        schedule: CommitteeSchedule,
        config: ConsensusConfig,
    ) -> HashSet<ValidatorId> {
        if self.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
            return HashSet::new();
        }
        if self.resolve_micro_certificate().is_err() {
            return HashSet::new();
        }
        let msg = vote_sign_bytes_for_shard(
            config.chain_id,
            self.shard_id,
            self.height,
            self.round,
            self.kind,
            &self.block_hash,
        );
        let multi_marker = self.recognized_marker_count() > 1;
        let mut single_marker_signers: HashSet<ValidatorId> = HashSet::new();
        for (voter, payload) in &self.signatures {
            if *voter == PQ_UQC_MARKER_ID {
                if let Some(cert) = decode_pq_micro_envelope(payload) {
                    if cert.scheme != PqScheme::Falcon512 || cert.scheme.is_disabled() {
                        continue;
                    }
                    if let Some((ids, committee)) = self.micro_cert_valid_signers_and_committee(
                        &cert, validators, &msg, keys, schedule, config,
                    ) {
                        if Self::micro_cert_meets_quorum(&ids, &committee, validators) {
                            return ids.into_iter().collect();
                        }
                        if !multi_marker {
                            single_marker_signers = ids.into_iter().collect();
                        }
                    }
                }
            } else if *voter == PQ_QC_MARKER_ID {
                if let Some(cert) =
                    decode_pq_epoch_envelope(payload).or_else(|| decode_pq_micro_envelope(payload))
                {
                    if cert.scheme != PqScheme::Falcon512 || cert.scheme.is_disabled() {
                        continue;
                    }
                    if let Some(ids) = self.epoch_cert_valid_signers(&cert, validators, &msg, keys)
                    {
                        if Self::epoch_cert_meets_quorum(&ids, validators) {
                            return ids.into_iter().collect();
                        }
                        if !multi_marker {
                            single_marker_signers = ids.into_iter().collect();
                        }
                    }
                }
            }
        }
        if multi_marker {
            HashSet::new()
        } else {
            single_marker_signers
        }
    }

    fn recognized_marker_count(&self) -> usize {
        self.signatures
            .iter()
            .filter(|(voter, _)| *voter == PQ_UQC_MARKER_ID || *voter == PQ_QC_MARKER_ID)
            .count()
    }

    fn verify_and_signers_inner(
        &self,
        validators: &ValidatorSet,
        keys: &dyn PqKeyLookup,
        schedule: CommitteeSchedule,
        config: ConsensusConfig,
    ) -> (bool, HashSet<ValidatorId>) {
        if self.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
            return (false, HashSet::new());
        }
        if self.resolve_micro_certificate().is_err() {
            return (false, HashSet::new());
        }
        let msg = vote_sign_bytes_for_shard(
            config.chain_id,
            self.shard_id,
            self.height,
            self.round,
            self.kind,
            &self.block_hash,
        );
        let mut verified = false;
        let mut signers: HashSet<ValidatorId> = HashSet::new();
        for (voter, payload) in &self.signatures {
            if *voter == PQ_UQC_MARKER_ID {
                if let Some(cert) = decode_pq_micro_envelope(payload) {
                    if cert.scheme != PqScheme::Falcon512 || cert.scheme.is_disabled() {
                        continue;
                    }
                    if let Some((valid, committee)) = self.micro_cert_valid_signers_and_committee(
                        &cert, validators, &msg, keys, schedule, config,
                    ) {
                        if !verified
                            && Self::micro_cert_meets_quorum(&valid, &committee, validators)
                        {
                            verified = true;
                        }
                        signers.extend(valid);
                    }
                }
            } else if *voter == PQ_QC_MARKER_ID {
                if let Some(cert) =
                    decode_pq_epoch_envelope(payload).or_else(|| decode_pq_micro_envelope(payload))
                {
                    if cert.scheme != PqScheme::Falcon512 || cert.scheme.is_disabled() {
                        continue;
                    }
                    if let Some(valid) =
                        self.epoch_cert_valid_signers(&cert, validators, &msg, keys)
                    {
                        if !verified && Self::epoch_cert_meets_quorum(&valid, validators) {
                            verified = true;
                        }
                        signers.extend(valid);
                    }
                }
            }
        }
        (verified, signers)
    }

    fn micro_cert_valid_signers_and_committee(
        &self,
        cert: &PqMicroCertificate,
        validators: &ValidatorSet,
        msg: &[u8],
        keys: &dyn PqKeyLookup,
        schedule: CommitteeSchedule,
        config: ConsensusConfig,
    ) -> Option<(Vec<ValidatorId>, Vec<ValidatorId>)> {
        if qc_split_required_at(
            self.height,
            validators.len(),
            config.qc_split_activation_height,
        ) {
            return None;
        }
        if cert.height != self.height || cert.round != self.round {
            return None;
        }
        let expected_committee_size = micro_committee_size(validators.len());
        if cert.committee_size != expected_committee_size
            || cert.committee_size == 0
            || cert.committee_size as usize > MAX_COMMIT_CERT_SIGNERS
        {
            return None;
        }

        let expected_bitmask_len = (cert.committee_size as usize).div_ceil(8);
        if cert.signers_bitmask.len() != expected_bitmask_len {
            return None;
        }
        for i in (cert.committee_size as usize)..(cert.signers_bitmask.len() * 8) {
            if (cert.signers_bitmask[i / 8] & (1 << (i % 8))) != 0 {
                return None;
            }
        }

        let committee = committee_for_height_at(
            validators,
            cert.height,
            cert.round,
            cert.committee_size,
            Some(&cert.sortition_parent),
            schedule,
            config.sortition_unbiased_activation_height,
        );
        let expected_len = (cert.committee_size as usize).min(validators.len());
        if committee.len() != expected_len || committee.is_empty() {
            return None;
        }

        for i in committee.len()..(cert.committee_size as usize) {
            if cert.is_signer(i) {
                return None;
            }
        }

        let signed_count = cert.signed_count();
        let is_compact = cert.signatures.len() == signed_count;
        let is_full = cert.signatures.len() == cert.committee_size as usize;
        if !is_compact && !is_full {
            return None;
        }

        let mut sig_idx = 0usize;
        let mut valid_signers = Vec::with_capacity(signed_count);
        for (i, val_id) in committee.iter().enumerate() {
            if cert.is_signer(i) {
                let sig = if is_compact {
                    let s = &cert.signatures[sig_idx];
                    sig_idx += 1;
                    s
                } else {
                    &cert.signatures[i]
                };
                let (scheme, pubkey) = keys.pq_key_at(val_id, cert.height)?;
                if scheme != cert.scheme || scheme != PqScheme::Falcon512 || scheme.is_disabled() {
                    return None;
                }
                if !verify_falcon512(&pubkey, msg, sig) {
                    return None;
                }
                valid_signers.push(*val_id);
            }
        }

        Some((valid_signers, committee))
    }

    fn verify_micro_cert_with_config(
        &self,
        cert: &PqMicroCertificate,
        validators: &ValidatorSet,
        msg: &[u8],
        keys: &dyn PqKeyLookup,
        schedule: CommitteeSchedule,
        config: ConsensusConfig,
    ) -> bool {
        if qc_split_required_at(
            self.height,
            validators.len(),
            config.qc_split_activation_height,
        ) {
            return false;
        }
        let Some((valid, committee)) = self
            .micro_cert_valid_signers_and_committee(cert, validators, msg, keys, schedule, config)
        else {
            return false;
        };
        Self::micro_cert_meets_quorum(&valid, &committee, validators)
    }

    fn micro_cert_meets_quorum(
        valid: &[ValidatorId],
        committee: &[ValidatorId],
        validators: &ValidatorSet,
    ) -> bool {
        let committee_total_u128: u128 = committee
            .iter()
            .map(|id| validators.power_of(id) as u128)
            .sum();
        if committee_total_u128 == 0 {
            return false;
        }
        let committee_total: u64 = committee_total_u128.min(u64::MAX as u128) as u64;
        let network_total_u128 = validators.total_power_exact();
        let quorum_power = pq_micro_required_power(committee_total, validators.total_power());
        if !mixed_quorum_pair_safe(
            quorum_power,
            validators.quorum_power(),
            validators.total_power(),
        ) {
            return false;
        }
        let valid_power: u128 = valid.iter().map(|id| validators.power_of(id) as u128).sum();
        let network_required: u128 = (network_total_u128 * 2) / 3 + 1;
        let committee_required: u128 = (committee_total_u128 * 2) / 3 + 1;
        valid_power
            >= (quorum_power as u128)
                .max(network_required)
                .max(committee_required)
    }

    fn epoch_cert_valid_signers(
        &self,
        cert: &PqMicroCertificate,
        validators: &ValidatorSet,
        msg: &[u8],
        keys: &dyn PqKeyLookup,
    ) -> Option<Vec<ValidatorId>> {
        if cert.height != self.height || cert.round != self.round {
            return None;
        }
        let total_validators = validators.len();
        if total_validators == 0 {
            return None;
        }
        if cert.committee_size == 0
            || cert.committee_size as usize > MAX_COMMIT_CERT_SIGNERS
            || cert.committee_size as usize != total_validators
        {
            return None;
        }

        let expected_bitmask_len = total_validators.div_ceil(8);
        if cert.signers_bitmask.len() != expected_bitmask_len {
            return None;
        }
        for i in total_validators..(cert.signers_bitmask.len() * 8) {
            if (cert.signers_bitmask[i / 8] & (1 << (i % 8))) != 0 {
                return None;
            }
        }

        let mut ids: Vec<ValidatorId> = validators.validators.keys().copied().collect();
        ids.sort_unstable();

        let signed_count = cert.signed_count();
        let is_compact = cert.signatures.len() == signed_count;
        let is_full = cert.signatures.len() == ids.len();
        if !is_compact && !is_full {
            return None;
        }

        let mut sig_idx = 0usize;
        let mut valid_signers = Vec::with_capacity(signed_count);
        for (i, val_id) in ids.iter().enumerate() {
            if cert.is_signer(i) {
                let sig = if is_compact {
                    let s = &cert.signatures[sig_idx];
                    sig_idx += 1;
                    s
                } else {
                    &cert.signatures[i]
                };
                let (scheme, pubkey) = keys.pq_key_at(val_id, cert.height)?;
                if scheme != cert.scheme || scheme != PqScheme::Falcon512 || scheme.is_disabled() {
                    return None;
                }
                if !verify_falcon512(&pubkey, msg, sig) {
                    return None;
                }
                valid_signers.push(*val_id);
            }
        }
        Some(valid_signers)
    }

    fn verify_epoch_cert(
        &self,
        cert: &PqMicroCertificate,
        validators: &ValidatorSet,
        msg: &[u8],
        keys: &dyn PqKeyLookup,
    ) -> bool {
        let Some(valid) = self.epoch_cert_valid_signers(cert, validators, msg, keys) else {
            return false;
        };
        Self::epoch_cert_meets_quorum(&valid, validators)
    }

    fn epoch_cert_meets_quorum(valid: &[ValidatorId], validators: &ValidatorSet) -> bool {
        let power: u128 = valid.iter().map(|id| validators.power_of(id) as u128).sum();
        let total = validators.total_power_exact();
        if total == 0 {
            return false;
        }
        let required: u128 = (total * 2) / 3 + 1;
        power >= required
    }

    // GATE: mirrors `stellereum::consensus::types::resolve_micro_certificate`, which
    // returns `Result<_, ()>`; keeping the identical shape makes the differential
    // comparison trivially verifiable, and the unit error is never surfaced.
    #[allow(clippy::result_unit_err)]
    pub fn resolve_micro_certificate(&self) -> Result<Option<PqMicroCertificate>, ()> {
        if self.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
            return Err(());
        }
        let mut found: Option<PqMicroCertificate> = None;
        for (voter, payload) in &self.signatures {
            if *voter != PQ_UQC_MARKER_ID {
                continue;
            }
            let Some(cert) = decode_pq_micro_envelope(payload) else {
                continue;
            };
            match &found {
                None => found = Some(cert),
                Some(first) if first.sortition_parent != cert.sortition_parent => return Err(()),
                Some(_) => {}
            }
        }
        Ok(found)
    }

    pub fn pq_micro_certificate(&self) -> Option<PqMicroCertificate> {
        self.resolve_micro_certificate().ok().flatten()
    }

    pub fn sortition_parent(&self) -> Option<[u8; 32]> {
        self.pq_micro_certificate().map(|c| c.sortition_parent)
    }

    pub fn binds_to_parent(&self, parent_hash: &[u8; 32]) -> bool {
        match self.resolve_micro_certificate() {
            Err(()) => false,
            Ok(Some(cert)) => &cert.sortition_parent == parent_hash,
            Ok(None) => true,
        }
    }
}

// ============================================================================
// Block & Chain Verification
// ============================================================================

pub struct BlockVerifyContext<'a> {
    pub validators: &'a ValidatorSet,
    pub keys: &'a dyn PqKeyLookup,
    pub schedule: CommitteeSchedule,
    pub config: ConsensusConfig,
    pub expected_prev_hash: Option<[u8; 32]>,
    pub parent_timestamp: Option<u64>,
    pub require_qc: bool,
    pub verify_txs: bool,
    pub require_tx_chain_id: bool,
    pub implicit_registry: Option<&'a mut ImplicitKeyRegistry>,
}

/// Verify a single block's header/body commitments, proposer signature, optional QC,
/// and schedule alignment.
pub fn verify_block(
    block: &Block,
    qc: Option<&QuorumCertificate>,
    validators: &ValidatorSet,
    keys: &dyn PqKeyLookup,
    schedule: CommitteeSchedule,
    config: ConsensusConfig,
) -> Result<(), String> {
    let mut ctx = BlockVerifyContext {
        validators,
        keys,
        schedule,
        config,
        expected_prev_hash: None,
        parent_timestamp: None,
        require_qc: false,
        verify_txs: false,
        require_tx_chain_id: false,
        implicit_registry: None,
    };
    verify_block_with_context(block, qc, &mut ctx)
}

/// Full context-aware block verification (parent hash, timestamp drift, QC, and txs).
pub fn verify_block_with_context(
    block: &Block,
    qc: Option<&QuorumCertificate>,
    ctx: &mut BlockVerifyContext<'_>,
) -> Result<(), String> {
    if !block.shard_headers_canonical() {
        return Err(format!(
            "block {} has non-canonical shard_headers",
            block.height
        ));
    }
    if !verify_order_merkle_root(block) {
        return Err(format!("block {} order_merkle_root mismatch", block.height));
    }
    if !verify_cross_shard_msg_ids(block) {
        return Err(format!(
            "block {} contains cross-shard message with invalid msg_id",
            block.height
        ));
    }
    if block.cross_shard_out.iter().any(|msg| msg.trusted) {
        return Err(format!(
            "block {} contains cross-shard message with trusted=true",
            block.height
        ));
    }
    if let Some(expected_prev) = ctx.expected_prev_hash {
        if block.prev_hash != expected_prev {
            return Err(format!(
                "block {} prev_hash mismatch (expected {}, got {})",
                block.height,
                hex::encode(expected_prev),
                hex::encode(block.prev_hash)
            ));
        }
    }
    if let Some(parent_ts) = ctx.parent_timestamp {
        if !timestamp_within_bounds(parent_ts, block.timestamp) {
            return Err(format!(
                "block {} timestamp {} out of bounds relative to parent {}",
                block.height, block.timestamp, parent_ts
            ));
        }
    }
    if let Some(ref lqc) = block.last_qc {
        let Some(parent_h) = block.height.checked_sub(1) else {
            return Err("block 0 cannot carry last_qc".to_string());
        };
        if lqc.signatures.len() > MAX_COMMIT_CERT_SIGNERS
            || lqc.resolve_micro_certificate().is_err()
        {
            return Err(format!(
                "block {} carries malformed or ambiguous last_qc",
                block.height
            ));
        }
        if lqc.height != parent_h {
            return Err(format!(
                "block {} last_qc is for height {} not parent {parent_h}",
                block.height, lqc.height
            ));
        }
        if lqc.block_hash != Some(block.prev_hash) {
            return Err(format!(
                "block {} last_qc names a different parent block",
                block.height
            ));
        }
        if lqc.kind != VoteKind::Precommit {
            return Err(format!(
                "block {} last_qc is not a Precommit QC",
                block.height
            ));
        }
        if lqc.shard_id != block.shard_id {
            return Err(format!(
                "block {} last_qc shard {} mismatch (block shard {})",
                block.height, lqc.shard_id, block.shard_id
            ));
        }
        if !ctx.validators.power_total_representable() {
            return Err(format!(
                "block {} validator set total power exceeds u64::MAX",
                block.height
            ));
        }
        let (lqc_ok, lqc_power) = lqc.verify_and_signed_power_with_config(
            ctx.validators,
            ctx.keys,
            ctx.schedule,
            ctx.config,
        );
        if !lqc_ok || lqc_power < ctx.validators.quorum_power() {
            return Err(format!(
                "block {} last_qc failed QC verification at height {} (signed={}, required={})",
                block.height,
                lqc.height,
                lqc_power,
                ctx.validators.quorum_power()
            ));
        }
    }

    let bh = compute_block_hash_at(
        block,
        ctx.config.chain_id,
        ctx.config.header_commit_activation_height,
    );

    if !verify_proposer_signature_with_hash(block, &bh, ctx.keys) {
        return Err(format!(
            "block {} proposer Falcon-512 signature verification failed",
            block.height
        ));
    }

    let effective_qc = qc.or(block.precommit_qc.as_ref());
    match effective_qc {
        Some(cert) => {
            if cert.kind != VoteKind::Precommit {
                return Err(format!(
                    "block {} certificate is not a Precommit QC",
                    block.height
                ));
            }
            if cert.height != block.height {
                return Err(format!(
                    "block {} certificate height {} mismatch",
                    block.height, cert.height
                ));
            }
            if cert.shard_id != block.shard_id {
                return Err(format!(
                    "block {} certificate shard {} mismatch (block shard {})",
                    block.height, cert.shard_id, block.shard_id
                ));
            }
            if cert.block_hash != Some(bh) {
                return Err(format!(
                    "block {} certificate block_hash mismatch",
                    block.height
                ));
            }
            if block.round > cert.round {
                return Err(format!(
                    "block {} round {} exceeds certificate round {}",
                    block.height, block.round, cert.round
                ));
            }
            if ctx.validators.proposer_for_with_schedule_at(
                block.height,
                cert.round,
                ctx.schedule,
                ctx.config.sortition_unbiased_activation_height,
            ) != Some(block.proposer)
            {
                return Err(format!(
                    "block {} proposer is not scheduled for height {} round {}",
                    block.height, block.height, cert.round
                ));
            }
            if !cert.binds_to_parent(&block.prev_hash) {
                return Err(format!(
                    "block {} certificate sortition_parent does not bind to prev_hash",
                    block.height
                ));
            }
            if !ctx.validators.power_total_representable() {
                return Err(format!(
                    "block {} validator set total power exceeds u64::MAX",
                    block.height
                ));
            }
            let (ok, signed_power) = cert.verify_and_signed_power_with_config(
                ctx.validators,
                ctx.keys,
                ctx.schedule,
                ctx.config,
            );
            if !ok || signed_power < ctx.validators.quorum_power() {
                return Err(format!(
                    "block {} certificate lacks quorum (signed={}, required={})",
                    block.height,
                    signed_power,
                    ctx.validators.quorum_power()
                ));
            }
        }
        None => {
            if ctx.require_qc {
                return Err(format!(
                    "block {} missing required precommit QuorumCertificate",
                    block.height
                ));
            }
            if !ctx.validators.is_empty()
                && ctx.validators.proposer_for_with_schedule_at(
                    block.height,
                    block.round,
                    ctx.schedule,
                    ctx.config.sortition_unbiased_activation_height,
                ) != Some(block.proposer)
            {
                return Err(format!(
                    "block {} proposer is not scheduled for height {} round {}",
                    block.height, block.height, block.round
                ));
            }
        }
    }

    if ctx.verify_txs {
        let mut fallback_registry = ImplicitKeyRegistry::new();
        let reg = match ctx.implicit_registry.as_deref_mut() {
            Some(r) => r,
            None => &mut fallback_registry,
        };
        for (idx, tx) in block.transactions.iter().enumerate() {
            verify_tx_at(
                tx,
                ctx.config.chain_id,
                ctx.require_tx_chain_id,
                block.timestamp,
                reg,
            )
            .map_err(|e| format!("block {} tx[{idx}] failed verification: {e}", block.height))?;
        }
    }

    Ok(())
}

/// Verify a contiguous sequence of blocks (height continuity, parent hash link,
/// timestamp bounds, proposer signatures, QCs, and optional transactions).
#[allow(clippy::too_many_arguments)] // GATE: explicit consensus verification parameters including require_tx_chain_id
pub fn verify_chain(
    blocks: &[Block],
    validators: &ValidatorSet,
    keys: &dyn PqKeyLookup,
    schedule: CommitteeSchedule,
    config: ConsensusConfig,
    require_qc: bool,
    verify_txs: bool,
    require_tx_chain_id: bool,
) -> Result<(), String> {
    if blocks.is_empty() {
        return Err("empty chain".to_string());
    }
    let expected_shard = blocks[0].shard_id;
    let mut registry = ImplicitKeyRegistry::new();
    let mut prev_hash: Option<[u8; 32]> = None;
    let mut prev_height: Option<Height> = None;
    let mut prev_ts: Option<u64> = None;

    for block in blocks {
        if block.shard_id != expected_shard {
            return Err(format!(
                "block {} shard_id mismatch (expected {}, got {})",
                block.height, expected_shard, block.shard_id
            ));
        }
        if let Some(ph) = prev_height {
            if block.height != ph.saturating_add(1) {
                return Err(format!(
                    "height discontinuity: expected {}, got {}",
                    ph.saturating_add(1),
                    block.height
                ));
            }
        }
        let mut ctx = BlockVerifyContext {
            validators,
            keys,
            schedule,
            config,
            expected_prev_hash: prev_hash,
            parent_timestamp: prev_ts,
            require_qc,
            verify_txs,
            require_tx_chain_id,
            implicit_registry: Some(&mut registry),
        };
        verify_block_with_context(block, None, &mut ctx)?;
        prev_hash = Some(compute_block_hash_at(
            block,
            config.chain_id,
            config.header_commit_activation_height,
        ));
        prev_height = Some(block.height);
        prev_ts = Some(block.timestamp);
    }
    Ok(())
}
