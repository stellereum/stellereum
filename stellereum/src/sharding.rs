//! Sharding, Shared-Liquidity Hub & Blockchain Consensus
//! Masterchain + Shardchain paradigm (TON architecture)
//! Dynamic & infinite sharding with auto-split and merge under load.
//! Cross-shard atomic transactions with tight-coupling cryptographic Merkle proofs.
//! Shared Sequencer for unified execution and external L2 ordering.

use crate::cell::{CellHash, MerkleProof, PatriciaTrie};
use crate::post_quantum::{
    derive_pq_address, verify_pq_signature, PqScheme, StatefulImplicitKeyRegistry, DEFAULT_SALT,
    PQ_ENVELOPE_MAGIC,
};
use crate::zkml::SessionKeyAuthorization;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

static GLOBAL_IMPLICIT_KEY_REGISTRY: std::sync::OnceLock<StatefulImplicitKeyRegistry> =
    std::sync::OnceLock::new();

/// Global thread-safe implicit key registry for post-quantum wire verification.
pub fn global_implicit_key_registry() -> &'static StatefulImplicitKeyRegistry {
    GLOBAL_IMPLICIT_KEY_REGISTRY.get_or_init(StatefulImplicitKeyRegistry::new)
}

/// Signature envelope carrying post-quantum or hybrid signature payload.
///
/// Encoded format:
/// `b"PQ1" (3B) || scheme_id (1B) || is_implicit (1B) || [pubkey_len (2B) || pubkey || salt (16B)]? || sig_len (2B) || sig_bytes`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignatureEnvelope {
    pub scheme: PqScheme,
    pub is_implicit: bool,
    pub pubkey: Option<Vec<u8>>,
    pub signature_bytes: Vec<u8>,
    pub salt: [u8; 16],
    #[serde(default)]
    pub chain_id: Option<u64>,
}

impl PqSignatureEnvelope {
    /// Create envelope with explicit public key attached and default salt.
    pub fn new_explicit(scheme: PqScheme, pubkey: Vec<u8>, signature_bytes: Vec<u8>) -> Self {
        Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt: DEFAULT_SALT,
            chain_id: None,
        }
    }

    /// Create envelope with explicit public key and custom salt attached.
    pub fn new_explicit_with_salt(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        salt: [u8; 16],
    ) -> Self {
        Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt,
            chain_id: None,
        }
    }

    /// Create envelope with explicit public key, custom salt, and chain_id bound.
    pub fn new_explicit_with_chain(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        salt: [u8; 16],
        chain_id: u64,
    ) -> Self {
        Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
            salt,
            chain_id: Some(chain_id),
        }
    }

    /// Create envelope relying on implicit registered public key.
    pub fn new_implicit(scheme: PqScheme, signature_bytes: Vec<u8>) -> Self {
        Self {
            scheme,
            is_implicit: true,
            pubkey: None,
            signature_bytes,
            salt: DEFAULT_SALT,
            chain_id: None,
        }
    }

    /// Create envelope relying on implicit registered public key with chain_id bound.
    pub fn new_implicit_with_chain(
        scheme: PqScheme,
        signature_bytes: Vec<u8>,
        chain_id: u64,
    ) -> Self {
        Self {
            scheme,
            is_implicit: true,
            pubkey: None,
            signature_bytes,
            salt: DEFAULT_SALT,
            chain_id: Some(chain_id),
        }
    }

    /// Encodes envelope into canonical bytes prefixed by `b"PQ1"`.
    /// Includes `salt` (16 bytes) in explicit envelopes (`is_implicit = false`).
    /// Appends `chain_id` (8 bytes) if bound (Finding F1).
    pub fn encode(&self) -> Vec<u8> {
        let salt_len = if !self.is_implicit { 16 } else { 0 };
        let pk_len = self.pubkey.as_ref().map_or(0, |k| k.len());
        let chain_len = if self.chain_id.is_some() { 8 } else { 0 };
        let mut out = Vec::with_capacity(
            3 + 1 + 1 + 2 + pk_len + salt_len + 2 + self.signature_bytes.len() + chain_len,
        );
        out.extend_from_slice(PQ_ENVELOPE_MAGIC);
        out.push(self.scheme.id());
        out.push(if self.is_implicit { 1 } else { 0 });

        if let Some(pk) = &self.pubkey {
            let pk_len_u16 = pk.len() as u16;
            out.extend_from_slice(&pk_len_u16.to_le_bytes());
            out.extend_from_slice(pk);
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }

        if !self.is_implicit {
            out.extend_from_slice(&self.salt);
        }

        let sig_len = self.signature_bytes.len() as u16;
        out.extend_from_slice(&sig_len.to_le_bytes());
        out.extend_from_slice(&self.signature_bytes);
        if let Some(cid) = self.chain_id {
            out.extend_from_slice(&cid.to_be_bytes());
        }
        out
    }

    /// Wire byte length for legacy envelopes without salt.
    pub fn legacy_encode_len(&self) -> usize {
        let chain_len = if self.chain_id.is_some() { 8 } else { 0 };
        3 + 1
            + 1
            + 2
            + self.pubkey.as_ref().map_or(0, |k| k.len())
            + 2
            + self.signature_bytes.len()
            + chain_len
    }

    /// Decodes envelope from byte slice.
    ///
    /// STRICT (audit W6.5 — signature malleability): every length in the
    /// framing is now PINNED to the scheme, so a given (scheme, key,
    /// signature) has exactly ONE valid byte form per framing:
    ///
    /// * the flag byte is `0` (explicit) or `1` (implicit). A flag of `2`
    ///   used to be read as "implicit" (`bytes[4] != 0`), so a byte-flipped
    ///   flag produced a second, differently-framed but equally accepted
    ///   envelope for the same signature.
    /// * an IMPLICIT envelope carries NO public key (`pk_len == 0`). The old
    ///   decoder SKIPPED `pk_len` bytes and returned `pubkey: None` anyway:
    ///   the same logical signature then had an unbounded number of valid
    ///   encodings (insert N junk bytes right after the flag byte), and the
    ///   skipped bytes were never validated. That defeats any byte-based
    ///   dedup / replay filter or transaction id derived from the envelope
    ///   bytes — a re-mint of a valid transaction.
    /// * an EXPLICIT envelope carries EXACTLY `scheme.pubkey_size()` key
    ///   bytes (the old decoder accepted ANY length, including zero, which
    ///   decoded to an explicit envelope with NO key at all).
    /// * the signature is EXACTLY `scheme.signature_size()` bytes (the old
    ///   decoder accepted any length).
    /// * no trailing bytes.
    ///
    /// The historical salt placements are still READ (a transaction already
    /// in flight must decode), but they are mutually exclusive: the salt is
    /// 16 bytes, the key length is pinned to the scheme and the signature
    /// length is pinned to the scheme, so exactly one framing can match a
    /// given byte string.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 7 {
            return Err("Envelope bytes too short".to_string());
        }
        if &bytes[0..3] != PQ_ENVELOPE_MAGIC {
            return Err("Missing PQ1 magic header".to_string());
        }

        let scheme = PqScheme::from_id(bytes[3])?;
        if bytes[4] > 1 {
            return Err("Envelope flag byte must be 0 (explicit) or 1 (implicit)".to_string());
        }
        let is_implicit = bytes[4] == 1;

        let pk_len = u16::from_le_bytes([bytes[5], bytes[6]]) as usize;

        if is_implicit {
            if pk_len != 0 {
                return Err("Implicit envelope must not carry a public key".to_string());
            }
            let mut cursor = 7;
            if bytes.len() < cursor + 2 {
                return Err("Truncated signature length in envelope".to_string());
            }
            let sig_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            cursor += 2;
            if sig_len != scheme.signature_size() {
                return Err(format!(
                    "Envelope signature length mismatch for {}: expected {}, got {}",
                    scheme.name(),
                    scheme.signature_size(),
                    sig_len
                ));
            }
            if bytes.len() != cursor + sig_len && bytes.len() != cursor + sig_len + 8 {
                return Err("Truncated signature bytes in envelope".to_string());
            }
            let signature_bytes = bytes[cursor..cursor + sig_len].to_vec();
            cursor += sig_len;
            let chain_id = if bytes.len() == cursor + 8 {
                Some(u64::from_be_bytes(
                    bytes[cursor..cursor + 8].try_into().unwrap(),
                ))
            } else {
                None
            };
            return Ok(Self {
                scheme,
                is_implicit: true,
                pubkey: None,
                signature_bytes,
                salt: DEFAULT_SALT,
                chain_id,
            });
        }

        // EXPLICIT. The key length is fixed by the scheme. It is read either
        // at offset 5 (canonical framing: key first) or at offset 21 (legacy
        // framing: salt first); both are pinned to `scheme.pubkey_size()`.
        let expected_pk_len = scheme.pubkey_size();
        let pk_len_at_21 = if bytes.len() >= 23 {
            u16::from_le_bytes([bytes[21], bytes[22]]) as usize
        } else {
            0
        };

        let _sig_len_error = |got: usize| {
            format!(
                "Envelope signature length mismatch for {}: expected {}, got {}",
                scheme.name(),
                scheme.signature_size(),
                got
            )
        };

        // Canonical framing: key, then (optional) salt, then signature.
        if pk_len == expected_pk_len {
            let mut cursor = 7 + pk_len;
            // With salt (what `encode()` produces for an explicit envelope).
            if bytes.len() >= cursor + 16 + 2 {
                let maybe_sig_len =
                    u16::from_le_bytes([bytes[cursor + 16], bytes[cursor + 17]]) as usize;
                if maybe_sig_len == scheme.signature_size()
                    && (cursor + 16 + 2 + maybe_sig_len == bytes.len()
                        || cursor + 16 + 2 + maybe_sig_len + 8 == bytes.len())
                {
                    let mut salt = [0u8; 16];
                    salt.copy_from_slice(&bytes[cursor..cursor + 16]);
                    cursor += 16;
                    cursor += 2;
                    let signature_bytes = bytes[cursor..cursor + maybe_sig_len].to_vec();
                    cursor += maybe_sig_len;
                    let chain_id = if bytes.len() == cursor + 8 {
                        Some(u64::from_be_bytes(
                            bytes[cursor..cursor + 8].try_into().unwrap(),
                        ))
                    } else {
                        None
                    };
                    return Ok(Self {
                        scheme,
                        is_implicit: false,
                        pubkey: Some(bytes[7..7 + pk_len].to_vec()),
                        signature_bytes,
                        salt,
                        chain_id,
                    });
                }
            }
            // Legacy framing: no salt at all.
            if bytes.len() >= cursor + 2 {
                let sig_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
                cursor += 2;
                if sig_len == scheme.signature_size()
                    && (bytes.len() == cursor + sig_len || bytes.len() == cursor + sig_len + 8)
                {
                    let signature_bytes = bytes[cursor..cursor + sig_len].to_vec();
                    cursor += sig_len;
                    let chain_id = if bytes.len() == cursor + 8 {
                        Some(u64::from_be_bytes(
                            bytes[cursor..cursor + 8].try_into().unwrap(),
                        ))
                    } else {
                        None
                    };
                    return Ok(Self {
                        scheme,
                        is_implicit: false,
                        pubkey: Some(bytes[7..7 + pk_len].to_vec()),
                        signature_bytes,
                        salt: DEFAULT_SALT,
                        chain_id,
                    });
                }
            }
            return Err("Truncated envelope bytes".to_string());
        }

        // Legacy framing: salt BEFORE the key.
        if pk_len_at_21 == expected_pk_len {
            let cursor_sig = 23 + pk_len_at_21;
            if bytes.len() >= cursor_sig + 2 {
                let sig_len =
                    u16::from_le_bytes([bytes[cursor_sig], bytes[cursor_sig + 1]]) as usize;
                if sig_len == scheme.signature_size()
                    && (cursor_sig + 2 + sig_len == bytes.len()
                        || cursor_sig + 2 + sig_len + 8 == bytes.len())
                {
                    let mut salt = [0u8; 16];
                    salt.copy_from_slice(&bytes[5..21]);
                    let signature_bytes = bytes[cursor_sig + 2..cursor_sig + 2 + sig_len].to_vec();
                    let rem = cursor_sig + 2 + sig_len;
                    let chain_id = if bytes.len() == rem + 8 {
                        Some(u64::from_be_bytes(bytes[rem..rem + 8].try_into().unwrap()))
                    } else {
                        None
                    };
                    return Ok(Self {
                        scheme,
                        is_implicit: false,
                        pubkey: Some(bytes[23..23 + pk_len_at_21].to_vec()),
                        signature_bytes,
                        salt,
                        chain_id,
                    });
                }
            }
        }

        Err(format!(
            "Explicit envelope public key length mismatch for {}: expected {}, got {}",
            scheme.name(),
            expected_pk_len,
            pk_len
        ))
    }
}

pub type ShardId = u32;
pub const MASTERCHAIN_SHARD: ShardId = 0;
pub const BASE_WORKCHAIN_SHARD_INITIAL: ShardId = 1;

/// Environment variable listing the shards a single process runs, comma
/// separated (e.g. `STELL_SHARDS=0,1`). Unset/empty keeps the process on the
/// one shard it was started with, which is the pre-sharding behaviour.
pub const SHARD_REGISTRY_ENV: &str = "STELL_SHARDS";

/// Escape hatch that re-allows a non-canonical shard registry for local
/// soak/tests only. One env var, no new config formats. Public launch is
/// single-shard canonical; the hatch is loudly logged at boot (see `main.rs`)
/// and never documented for operators.
pub const EXPERIMENTAL_SHARDS_ENV: &str = "STELL_EXPERIMENTAL_SHARDS";

/// Freeze doc pinned by the boot-guard refusal text below.
pub const WORKCHAIN_FREEZE_DOC: &str = "docs/PUBLIC_TESTNET_CODE_GAPS.md §1";

/// True only when `STELL_EXPERIMENTAL_SHARDS=1` (exact match). Anything else
/// (unset, empty, `0`, `true`, ...) is disabled — fail-closed.
pub fn experimental_shards_hatch_enabled() -> bool {
    matches!(
        std::env::var(EXPERIMENTAL_SHARDS_ENV).as_deref(),
        Ok("1")
    )
}

/// Boot guard: single-shard `{0}` canonical for public launch (protocol
/// freeze, see [`WORKCHAIN_FREEZE_DOC`]).
///
/// * `Ok(())` — registry is exactly `{MASTERCHAIN_SHARD}` (default path,
///   byte-identical), or the experimental hatch is enabled AND the registry
///   is a VALID configured set (see [`ShardRegistry::validate`]: every
///   multi-shard set names the masterchain and stays within the shard cap).
/// * `Err(msg)` — any other registry (`STELL_SHARDS != {0}`, i.e. any
///   multishard request or any non-canonical single shard) without the hatch,
///   or an INVALID registry (missing masterchain, over the cap) even WITH the
///   hatch: the hatch allows the CONFIGURED set, not just any set.
///   The message names the freeze doc, both env vars, and the recovery.
///
/// Pure except for the hatch env read; use
/// [`check_workchain_boot_guard_with_hatch`] for deterministic tests.
pub fn check_workchain_boot_guard(registry: &ShardRegistry) -> Result<(), String> {
    check_workchain_boot_guard_with_hatch(registry, experimental_shards_hatch_enabled())
}

/// Deterministic core of [`check_workchain_boot_guard`]: `hatch` is the
/// already-resolved `STELL_EXPERIMENTAL_SHARDS=1` flag.
///
/// The hatch allows the CONFIGURED set, not just any set: a registry that
/// fails [`ShardRegistry::validate`] (multi-shard without the masterchain,
/// or over the shard cap) is refused even with the hatch set, fail-closed.
pub fn check_workchain_boot_guard_with_hatch(
    registry: &ShardRegistry,
    hatch: bool,
) -> Result<(), String> {
    if *registry == ShardRegistry::single() {
        return Ok(());
    }
    registry.validate()?;
    if hatch {
        return Ok(());
    }
    Err(format!(
        "REFUSING startup: STELL_SHARDS {{{}}} is not single-shard canonical {{0}} \
         (protocol freeze {doc}). Multishard boot is parked until live-soak + flag-day. \
         For local soak/tests only, set {hatch_env}=1 (loudly logged). \
         Requested shards: {{{}}}",
        MASTERCHAIN_SHARD,
        registry
            .ids()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(","),
        doc = WORKCHAIN_FREEZE_DOC,
        hatch_env = EXPERIMENTAL_SHARDS_ENV,
    ))
}

/// The set of shards a single process is responsible for.
///
/// Before sharding, one process ran exactly one chain and every block was a
/// masterchain block. That must stay byte-for-byte identical, so the DEFAULT
/// registry is `{MASTERCHAIN_SHARD}` and `is_sharded()` is false. Every new
/// shard-aware check in the runtime is gated on `is_sharded()`, which means the
/// single-shard path is untouched and all pre-sharding tests keep passing.
///
/// A process that should run several shards over ONE infnode node sets
/// `STELL_SHARDS`, e.g. `STELL_SHARDS=0,1`. The cross-shard KV helpers in
/// `network.rs` are node-local, so the two consensus instances must share one
/// process (and one `Node`) for messages to flow between them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardRegistry {
    shards: std::collections::BTreeSet<ShardId>,
}

impl Default for ShardRegistry {
    fn default() -> Self {
        Self::single()
    }
}

impl ShardRegistry {
    /// The pre-sharding registry: exactly the masterchain.
    pub fn single() -> Self {
        Self::from_ids([MASTERCHAIN_SHARD])
    }

    /// Build a registry from an explicit set of shard ids. An empty set falls
    /// back to the masterchain so a misparsed env var can never produce a
    /// process that runs no chain at all.
    pub fn from_ids<I: IntoIterator<Item = ShardId>>(ids: I) -> Self {
        let mut shards: std::collections::BTreeSet<ShardId> = ids.into_iter().collect();
        if shards.is_empty() {
            shards.insert(MASTERCHAIN_SHARD);
        }
        Self { shards }
    }

    /// Parse the registry from the environment, falling back to `cli_shard`
    /// when `STELL_SHARDS` is unset or empty. With the CLI default of 0 this is
    /// exactly `{MASTERCHAIN_SHARD}`, preserving single-shard behaviour.
    ///
    /// LENIENT (legacy): unparsable entries are skipped and duplicates
    /// collapse, so garbage can silently shrink to the default. New boot code
    /// must use [`ShardRegistry::parse_list`] (fail-closed) for an explicitly
    /// set `STELL_SHARDS`; this stays for the unset/empty default path and for
    /// existing callers.
    pub fn from_env_or(cli_shard: ShardId) -> Self {
        match std::env::var(SHARD_REGISTRY_ENV) {
            Ok(v) if !v.trim().is_empty() => {
                let ids: Vec<ShardId> = v
                    .split(',')
                    .filter_map(|p| p.trim().parse::<ShardId>().ok())
                    .collect();
                Self::from_ids(ids)
            }
            _ => Self::from_ids([cli_shard]),
        }
    }

    /// Parse an explicitly set `STELL_SHARDS` value, fail-closed.
    ///
    /// * empty value / empty entry (`"0,,1"`, whitespace-only) → `Err`;
    /// * an entry that is not a shard id (`"0,abc"`) → `Err` naming it;
    /// * a duplicate id (`"0,1,1"`) → `Err` naming it (the `BTreeSet`
    ///   backing would otherwise collapse it silently);
    /// * more than [`MAX_SHARDS`] ids → `Err` naming the cap;
    /// * a MULTI-shard set without [`MASTERCHAIN_SHARD`] → `Err` (every
    ///   configured process runs the masterchain; a lone non-masterchain
    ///   single shard stays the boot guard's business, not a parse error).
    ///
    /// On success the ids are unique and iterate in ascending order (the
    /// `BTreeSet` backing), so the registry IS the sorted N-shard set.
    pub fn parse_list(raw: &str) -> Result<Self, String> {
        if raw.trim().is_empty() {
            return Err(format!(
                "REFUSING startup: {env} is empty (set {env}=<id>[,<id>...], e.g. {env}=0,1,2, or unset it for the canonical single-shard {{0}})",
                env = SHARD_REGISTRY_ENV,
            ));
        }
        let mut ids: Vec<ShardId> = Vec::new();
        for (i, tok) in raw.split(',').enumerate() {
            let t = tok.trim();
            if t.is_empty() {
                return Err(format!(
                    "REFUSING startup: {env}={raw:?} has an empty entry at position {i} (every entry must be a shard id)",
                    env = SHARD_REGISTRY_ENV,
                ));
            }
            let id: ShardId = t.parse().map_err(|_| {
                format!(
                    "REFUSING startup: {env}={raw:?} has an invalid shard id `{t}` at position {i} (every entry must be a non-negative integer)",
                    env = SHARD_REGISTRY_ENV,
                )
            })?;
            if ids.contains(&id) {
                return Err(format!(
                    "REFUSING startup: {env}={raw:?} lists shard id {id} twice (ids must be unique)",
                    env = SHARD_REGISTRY_ENV,
                ));
            }
            ids.push(id);
        }
        let registry = Self::from_ids(ids);
        registry.validate()?;
        Ok(registry)
    }

    /// Fail-closed config check for a registry, independent of the hatch.
    ///
    /// * more than [`MAX_SHARDS`] shards → `Err` (the topology hard cap:
    ///   the process must never configure more shards than the network can
    ///   hold);
    /// * a MULTI-shard set without [`MASTERCHAIN_SHARD`] → `Err` (every
    ///   configured process runs the masterchain; cross-shard proofs anchor
    ///   to it).
    ///
    /// A single non-masterchain shard (`{1}`) PASSES: it is non-canonical but
    /// not malformed — refusing it is the boot guard's freeze business (which
    /// still refuses it without the hatch), and the pinned guard tests cover
    /// exactly that.
    pub fn validate(&self) -> Result<(), String> {
        if self.shards.len() > MAX_SHARDS {
            return Err(format!(
                "REFUSING startup: {env} configures {} shards {{{}}} — over the shard cap {cap} (reduce to at most {cap} comma-separated ids)",
                self.shards.len(),
                self.ids()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                env = SHARD_REGISTRY_ENV,
                cap = MAX_SHARDS,
            ));
        }
        if self.is_sharded() && !self.shards.contains(&MASTERCHAIN_SHARD) {
            return Err(format!(
                "REFUSING startup: {env} configures {{{}}} without the masterchain shard {master} (every multi-shard process must include {master})",
                self.ids()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                env = SHARD_REGISTRY_ENV,
                master = MASTERCHAIN_SHARD,
            ));
        }
        Ok(())
    }

    /// True when this process runs MORE THAN ONE shard. This is the single gate
    /// for every new shard-aware check; with the default registry it is false.
    pub fn is_sharded(&self) -> bool {
        self.shards.len() > 1
    }

    /// True when `shard_id` is one of the shards this process runs.
    pub fn contains(&self, shard_id: ShardId) -> bool {
        self.shards.contains(&shard_id)
    }

    /// The shards in ascending order (deterministic iteration).
    pub fn ids(&self) -> impl Iterator<Item = ShardId> + '_ {
        self.shards.iter().copied()
    }

    pub fn len(&self) -> usize {
        self.shards.len()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }
}

/// The process-wide MASTERCHAIN staking ledger, shared with every workchain
/// runtime of the same process.
///
/// The masterchain OWNS the staking registry: a bond, an unbond and a slash
/// are masterchain transactions, and only the masterchain's ledger is committed
/// chain state. A workchain deliberately keeps NO registry of its own (its
/// genesis seeds an empty ledger — see `runtime::fund_shard_genesis`), because
/// a second registry would be a second opinion about who the validators are,
/// and the validator set decides who proposes.
///
/// Sharing the master's ledger is therefore the ONLY way a workchain can learn
/// about a rotation: without it the workchain derived its set from its own
/// (empty) ledger, kept the config-defined set forever, and the audit's
/// "validator set gap" was exactly that — a rotation on the masterchain that
/// never reached the workchains.
pub type MasterStakingLedger = std::sync::Arc<tokio::sync::RwLock<crate::staking::StakingLedger>>;

/// Which staking registry defines a shard's consensus validator set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidatorSetSource {
    /// The shard's OWN ledger. Only the masterchain has one: it is the
    /// registry, and it is committed by the masterchain's own blocks.
    Local,
    /// The MASTERCHAIN's ledger, shared process-wide. Every workchain reads
    /// it, so a masterchain rotation is transmitted to the workchain at the
    /// next height boundary instead of being stranded on the masterchain.
    Masterchain,
}

impl ValidatorSetSource {
    /// The registry that defines the set for `shard_id`.
    pub fn for_shard(shard_id: ShardId) -> Self {
        if shard_id == MASTERCHAIN_SHARD {
            Self::Local
        } else {
            Self::Masterchain
        }
    }

    /// True when the shard takes the masterchain's ledger.
    pub fn uses_masterchain(self) -> bool {
        matches!(self, Self::Masterchain)
    }
}

/// True when `shard_id` is a workchain (any shard but the masterchain).
///
/// A workchain has no staking registry of its own: its consensus validator set
/// comes from the masterchain's ledger (see [`ValidatorSetSource`]).
pub fn is_workchain_shard(shard_id: ShardId) -> bool {
    shard_id != MASTERCHAIN_SHARD
}

/// The height at which a freshly derived validator set takes effect.
///
/// The set that signs height H is the set derived from the registry as of H,
/// so a rotation is installed for H+1 — the height boundary. Every node
/// derives the same set from the same registry, so the switch is a pure
/// function of the chain, not of local timing.
pub fn validator_set_adoption_height(current_height: u64) -> u64 {
    current_height.saturating_add(1)
}

/// Which shard a transaction is destined for. In single-shard mode this
/// predicate is never consulted; it exists so a sharded producer and validator
/// agree on which transactions belong to which shard. A transaction targets
/// the block shard named by its `target_shard` field.
pub fn tx_targets_shard(tx: &Transaction, shard_id: ShardId) -> bool {
    tx.target_shard == shard_id
}

/// Which shard OWNS (produces) a transaction.
///
/// M2: the source shard is the one that debits the sender, so a shard's block
/// selects every transaction whose `source_shard` is that shard — both
/// same-shard transfers (`source == target == shard`) and outbound cross-shard
/// transfers (`source == shard`, `target != shard`). The destination shard
/// never re-includes the transaction in `Block.transactions`; it receives the
/// value through a committed [`CrossShardMessage`] consumption record instead.
///
/// In single-shard mode this predicate is never consulted; the pre-sharding
/// path still uses [`tx_targets_shard`].
pub fn tx_belongs_to_shard(tx: &Transaction, shard_id: ShardId) -> bool {
    tx.source_shard == shard_id
}

/// True when `tx` is an outbound cross-shard transfer out of `shard_id`.
pub fn tx_is_outbound_cross_shard(tx: &Transaction, shard_id: ShardId) -> bool {
    tx.source_shard == shard_id && tx.target_shard != shard_id
}

/// The shard a node's blocks belong to, given the DHT/blob NAMESPACE shard it
/// was started with (`--shard N`) and its [`ShardRegistry`].
///
/// These are deliberately NOT the same thing. Before sharding, one process ran
/// one chain and every block was a MASTERCHAIN block, while `--shard N` only
/// selected the DHT/blob namespace. The default registry
/// (`is_sharded() == false`) must preserve exactly that: the block shard stays
/// [`MASTERCHAIN_SHARD`] even when `--shard 1` is passed. Conflating the two
/// made a `--shard 1` node stamp `block.shard_id = 1` while its persisted chain
/// and sync validation expected shard 0, so catch-up rejected every chain and
/// finality stalled at an ever-increasing round.
///
/// Only a genuine multi-shard process (`STELL_SHARDS` selecting more than one
/// shard) scopes blocks to the namespace shard it was started with.
pub fn block_shard_for(namespace_shard: ShardId, registry: &ShardRegistry) -> ShardId {
    if registry.is_sharded() {
        namespace_shard
    } else {
        MASTERCHAIN_SHARD
    }
}

/// Tag that separates a legacy signature from a session-key envelope inside
/// `Transaction::signature`:
///
/// * legacy  : `64B ed25519 sig` (master key == `tx.from`)
/// * envelope: `64B ed25519 sig` (SESSION key) ++ `b"SK1"` ++ `bincode(SessionKeyAuthorization)`
///
/// This is how delegation rides inside the pre-existing `signature: Vec<u8>`
/// field: `Transaction`/`Block` gain NO new field, so bincode 1.3 keeps
/// decoding every persisted block byte-for-byte, and an old node rejects an
/// envelope at `Signature::from_slice` (64-byte expected, envelope is longer)
/// — fail-closed, exactly as required by the bincode verdict.
pub const SESSION_SIG_TAG: &[u8; 3] = b"SK1";

/// Tag that separates a legacy signature from a chain-id bound envelope inside
/// `Transaction::signature` (Finding F1):
///
/// `64B ed25519 sig` ++ `b"CH1"` ++ `chain_id (8B, big-endian)`
pub const CHAIN_SIG_TAG: &[u8; 3] = b"CH1";

/// Tag that separates a legacy signature from a Phase-2 EVM (secp256k1)
/// settlement envelope inside `Transaction::signature`:
///
/// `b"EV1"` ++ `canonical EVM raw transaction bytes`
/// (RLP legacy, or `0x02` EIP-1559 envelope).
///
/// `Transaction`/`Block` gain NO new field (bincode 1.3 compat — the §5 M3
/// rule: a new struct field would change every persisted block's bytes and
/// break the pinned golden vectors in `actor_envelope_compat_tests`). The
/// envelope rides the pre-existing `signature: Vec<u8>` field, exactly like
/// the `SK1`/`CH1`/`SC1` envelopes before it, and an old node rejects it at
/// `Signature::from_slice` (64 bytes expected, an EV1 envelope is never 64)
/// — fail-closed, as required.
pub const EVM_SIG_TAG: &[u8; 3] = b"EV1";

/// Chain id every EVM-settled transaction must carry. Strict equality, no
/// negotiation: this is the EIP-155 replay-protection domain AND the
/// consensus chain id in one value.
pub const EVM_CHAIN_ID: u64 = 5757;

// Compile-time drift guards: the consensus envelope, the EVM adapter and the
// session-grant default must agree on one chain id, or EVM settlement and
// grant binding silently diverge.
const _: () = assert!(EVM_CHAIN_ID == crate::evm_adapter::CHAIN_ID);
const _: () = assert!(EVM_CHAIN_ID == crate::zkml::DEFAULT_CHAIN_ID);

/// Maximum raw EVM bytes accepted inside an EV1 envelope. Mirrors the RPC
/// gate `evm_adapter::MAX_EVM_RAW_TX_BYTES` (generous for calldata); the
/// mempool wire estimator accounts the envelope bytes, so packing still
/// respects the block gossip cap.
pub const MAX_EVM_ENVELOPE_BYTES: usize = 128 * 1024;

/// Commitment tag bound into the signed message for chain-id-bound transactions.
pub const CHAIN_ID_COMMITMENT_TAG: &[u8; 8] = b"CHAIN_ID";

/// PAYMASTER (gasless / sponsored transactions) — v1 envelope.
///
/// DESIGN (see `docs/PAYMASTER.md` for the full contract):
///
/// A funded sponsor account declares `sponsor: <addr>` plus a `sponsor_sig`
/// on the transaction. Nodes verify BOTH signatures: the USER's signature
/// authorizes the action (and binds the sponsor grant, so the grant cannot be
/// swapped after signing), and the SPONSOR's signature authorizes the FEE for
/// THIS exact transaction (it commits to the tx core fields plus the caps, so
/// the grant cannot be grafted onto another transaction).
///
/// * the fee (base + gas + failure-fee on revert) debits ONLY the sponsor;
///   the user's balance is untouched (they still pay `amount` + payload value
///   — the sponsor pays FEE, not value);
/// * the USER's nonce advances on success AND on attributable failure
///   (anti-replay: a sponsored failure is not replayable for free);
/// * the sponsor sets a per-tx fee cap (`max_fee_per_tx`), an expiry
///   (`valid_until`) and an allowlist (`allowed_targets`, empty = any);
///   per-epoch/total spend is enforced by the sponsor's own signing policy
///   plus the mempool's joint reservation, NOT by consensus state (v1);
/// * v1 composes ONLY with a plain legacy ed25519 inner signature. A sponsor
///   envelope on a session-keyed, chain-bound, PQ or EVM transaction is
///   refused fail-closed (`SponsorPolicyError::BadGrant` / `SponsorUnsupported`).
///
/// WIRE: the envelope rides the pre-existing `signature: Vec<u8>` field as a
/// TRAILING suffix — `inner_sig_blob ++ bincode(SponsorAuthorization) ++
/// len_be32 ++ b"SP1"` — exactly like the priority-fee envelope before it, so
/// `Transaction`/`Block` gain NO new bincode field and every pre-sponsor
/// persisted block still decodes byte-for-byte (an old node rejects the longer
/// blob at `Signature::from_slice`, fail-closed).
///
/// HASH: `compute_tx_hash` mixes in `SPONSOR_COMMITMENT_TAG` + the auth ONLY
/// when a sponsor envelope is present, so a legacy (no-sponsor) transaction
/// hashes byte-identically to before (pinned by `sponsor_legacy_hash_unchanged`).
pub const SPONSOR_SIG_TAG: &[u8; 3] = b"SP1";

/// Commitment tag bound into the user's signed message AND the tx hash for
/// sponsored transactions.
pub const SPONSOR_COMMITMENT_TAG: &[u8; 8] = b"SPONSOR_";

/// Domain separator for the sponsor's fee authorization signature.
pub const SPONSOR_FEE_DOMAIN: &[u8; 14] = b"SPONSOR_FEE_V1";

/// Hard cap on the decoded sponsor auth bytes (fail-closed parse bound; a
/// bigger blob is refused, never truncated). 64 targets * 32B + fixed fields
/// fit comfortably.
pub const SPONSOR_AUTH_MAX_BYTES: usize = 4096;

/// Hard cap on allowlisted targets per grant (DoS bound on wire + verify).
pub const SPONSOR_MAX_TARGETS: usize = 64;

/// Why a session-keyed transaction fails the delegation policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPolicyError {
    /// `now > delegation.valid_until`.
    Expired,
    /// The grant's scope mask does not cover this transaction kind, or the
    /// amount exceeds `max_value_per_tx`.
    OutOfScope,
    /// The grant cannot cover this transaction's declared gas: the remaining
    /// budget (`max_gas_spend - gas_spent`) is too small. In phase 1 this is
    /// the stateless form of revocation (a spent-out grant authorizes
    /// nothing); the stateful registry lands in phase 2.
    BudgetExhausted,
    /// The grant itself is unusable: it does not parse, is not minted for this
    /// sender (`master_address != tx.from`) or the master's grant signature is
    /// invalid / tampered with.
    BadGrant,
}

impl std::fmt::Display for SessionPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SessionPolicyError::Expired => "session key delegation has expired",
            SessionPolicyError::OutOfScope => {
                "session key delegation does not cover this transaction (scope/value cap)"
            }
            SessionPolicyError::BudgetExhausted => {
                "session key delegation has no remaining gas budget"
            }
            SessionPolicyError::BadGrant => "invalid session key delegation grant",
        };
        write!(f, "{s}")
    }
}

/// Why a sponsored transaction fails the sponsor policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SponsorPolicyError {
    /// `now > valid_until` at the checking clock.
    Expired,
    /// `tx.to` is not in `allowed_targets` (non-empty allowlist).
    OutOfScope,
    /// The fee execution will actually charge exceeds `max_fee_per_tx`.
    CapExceeded,
    /// The grant is unusable: malformed envelope, self-contradictory, or a
    /// v1-unsupported composition (session/PQ/EVM/chain inner).
    BadGrant,
}

impl std::fmt::Display for SponsorPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SponsorPolicyError::Expired => "sponsor grant has expired",
            SponsorPolicyError::OutOfScope => {
                "sponsor grant does not cover this recipient (allowlist)"
            }
            SponsorPolicyError::CapExceeded => {
                "sponsor grant per-tx fee cap does not cover this transaction's fee"
            }
            SponsorPolicyError::BadGrant => "invalid sponsor grant",
        };
        write!(f, "{s}")
    }
}

/// A sponsor's fee authorization for ONE transaction (the paymaster grant).
///
/// The sponsor signs [`Transaction::sponsor_message`] (domain
/// `SPONSOR_FEE_V1`) with the key `sponsor` (ed25519: the address IS the
/// pubkey). The user signs [`Transaction::signing_message`], which commits to
/// the FULL auth (including `sponsor_sig`), so neither side can be swapped
/// after signing.
///
/// `#[serde(default)]` on the forward-compat fields (`allowed_targets`):
/// older encodings (or JSON wallets that omit the field) decode as "no
/// allowlist". Absence of the whole envelope is the legacy path — a
/// transaction without it behaves byte-identically to before.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorAuthorization {
    /// The funded account that will be debited the fee. Must differ from
    /// `tx.from` to take effect (`sponsor == from` is the plain path: the fee
    /// is debited from the user and the envelope is fee-routing inert, though
    /// its signature is still verified).
    pub sponsor: [u8; 32],
    /// Hard ceiling on the fee execution may charge for this transaction
    /// (`max(gas_limit, floor) + surcharge`). A transaction whose fee exceeds
    /// this is refused at admission, at proposal and at execution.
    pub max_fee_per_tx: u64,
    /// Unix seconds: the grant authorizes nothing after this (checked against
    /// the admission clock at entry and the block timestamp at propose/apply).
    pub valid_until: u64,
    /// Recipient allowlist (contract/method scoping at the recipient
    /// granularity). Empty = any recipient. Capped at
    /// [`SPONSOR_MAX_TARGETS`] (longer lists fail closed at parse).
    #[serde(default)]
    pub allowed_targets: Vec<[u8; 32]>,
    /// Chain this grant was minted for, committed into both signatures.
    pub chain_id: u64,
    /// ed25519 signature by `sponsor` over [`Transaction::sponsor_message`].
    pub sponsor_sig: Vec<u8>,
}

pub const SHARD_SPLIT_LOAD_THRESHOLD: u64 = 500; // txs per block window triggers auto-split
pub const SHARD_MERGE_LOAD_THRESHOLD: u64 = 50; // low load triggers auto-merge

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardDescriptor {
    pub shard_id: ShardId,
    pub workchain_id: i32,
    pub prefix: u64,
    pub prefix_len: u8,
    pub tx_load: u64,
}

impl ShardDescriptor {
    pub fn new(shard_id: ShardId, workchain_id: i32, prefix: u64, prefix_len: u8) -> Self {
        Self {
            shard_id,
            workchain_id,
            prefix,
            prefix_len,
            tx_load: 0,
        }
    }

    /// Check whether an account address falls within this shard's address prefix.
    ///
    /// The routing prefix is the top `prefix_len` bits of the address's
    /// leading 8 bytes — the same definition TON uses for workchain shard
    /// prefixes. The masterchain owns nothing by prefix: it is addressed
    /// EXPLICITLY, in the `-1:<addr>` form (see [`ShardAddress`]).
    pub fn contains_address(&self, address: &[u8; 32]) -> bool {
        if self.shard_id == MASTERCHAIN_SHARD {
            return false;
        }
        if self.prefix_len == 0 {
            return true;
        }
        let len = u64::from(self.prefix_len).min(64);
        let shift = 64 - len;
        let mask = if shift >= 64 { 0 } else { !0u64 << shift };
        let addr_prefix = u64::from_be_bytes(address[..8].try_into().unwrap());
        (addr_prefix & mask) == (self.prefix & mask)
    }
}

/// Dynamic Infinite Sharding Manager
///
/// The DECISION engine of the sharding architecture: it owns the shard set,
/// the routing-prefix arithmetic and the shard-id allocation. The account
/// ownership and the executable split/merge transitions live in
/// [`ShardTopology`], which drives this manager.
#[derive(Clone, Debug, Default)]
pub struct DynamicShardManager {
    /// The active shard set. A `BTreeMap`, so iteration (and therefore the
    /// routing tie-break) is deterministic across nodes.
    pub shards: BTreeMap<ShardId, ShardDescriptor>,
    /// The next shard id to hand out. Ids are never reused.
    pub next_shard_id: ShardId,
}

impl DynamicShardManager {
    pub fn new() -> Self {
        let mut shards = BTreeMap::new();
        shards.insert(
            MASTERCHAIN_SHARD,
            ShardDescriptor::new(MASTERCHAIN_SHARD, -1, 0, 0),
        );
        shards.insert(
            BASE_WORKCHAIN_SHARD_INITIAL,
            ShardDescriptor::new(BASE_WORKCHAIN_SHARD_INITIAL, 0, 0, 0),
        );
        Self {
            shards,
            next_shard_id: BASE_WORKCHAIN_SHARD_INITIAL + 1,
        }
    }

    /// THE ROUTING RULE, over the shard set.
    ///
    /// The MOST SPECIFIC matching shard wins (longest routing prefix),
    /// tie-broken by the smallest shard id — so the rule is a pure function
    /// of the shard set and two nodes with the same topology route an
    /// address to the same shard. The masterchain is never a candidate here:
    /// it is addressed EXPLICITLY (see [`ShardAddress`]).
    pub fn route_address(&self, address: &[u8; 32]) -> ShardId {
        let mut best: Option<&ShardDescriptor> = None;
        for s in self.shards.values() {
            if !s.contains_address(address) {
                continue;
            }
            best = match best {
                None => Some(s),
                Some(b)
                    if s.prefix_len > b.prefix_len
                        || (s.prefix_len == b.prefix_len && s.shard_id < b.shard_id) =>
                {
                    Some(s)
                }
                other => other,
            };
        }
        match best {
            Some(s) => s.shard_id,
            // No workchain shard matches: fall back to the LOWEST workchain
            // shard id (deterministic), or the masterchain if the network
            // has no workchain shard at all.
            None => self
                .shards
                .keys()
                .copied()
                .filter(|id| *id != MASTERCHAIN_SHARD)
                .min()
                .unwrap_or(MASTERCHAIN_SHARD),
        }
    }

    pub fn record_tx_load(&mut self, shard_id: ShardId, tx_count: u64) {
        if let Some(s) = self.shards.get_mut(&shard_id) {
            s.tx_load += tx_count;
        }
    }

    /// Check and trigger automatic shard split if load exceeds threshold
    ///
    /// The manager owns the PREFIX ARITHMETIC and the ID ALLOCATION; the
    /// account re-assignment that makes the split real is performed by
    /// [`ShardTopology::check_and_split`], which drives this function.
    pub fn check_and_split(
        &mut self,
        shard_id: ShardId,
    ) -> Option<(ShardDescriptor, ShardDescriptor)> {
        let s = self.shards.get(&shard_id)?;
        if shard_id == MASTERCHAIN_SHARD
            || s.tx_load < SHARD_SPLIT_LOAD_THRESHOLD
            || s.prefix_len >= MAX_PREFIX_BITS
        {
            return None;
        }
        // The shard cap is a HARD cap: the topology never grows past it.
        if self.shards.len() >= MAX_SHARDS {
            return None;
        }

        let parent = self.shards.remove(&shard_id)?;
        let new_len = parent.prefix_len + 1;
        let shift = 64 - new_len;

        let child0_prefix = if shift + 1 >= 64 {
            0
        } else {
            (parent.prefix >> (shift + 1)) << (shift + 1)
        };
        let child1_prefix = child0_prefix | (1u64 << shift);

        let id0 = self.next_shard_id;
        let id1 = self.next_shard_id + 1;
        self.next_shard_id += 2;

        let child0 = ShardDescriptor::new(id0, parent.workchain_id, child0_prefix, new_len);
        let child1 = ShardDescriptor::new(id1, parent.workchain_id, child1_prefix, new_len);

        self.shards.insert(id0, child0.clone());
        self.shards.insert(id1, child1.clone());

        Some((child0, child1))
    }

    /// Check and trigger automatic shard merge if companion shards load is low
    pub fn check_and_merge(&mut self, id0: ShardId, id1: ShardId) -> Option<ShardDescriptor> {
        let s0 = self.shards.get(&id0)?.clone();
        let s1 = self.shards.get(&id1)?.clone();

        if s0.prefix_len != s1.prefix_len || s0.prefix_len == 0 {
            return None;
        }

        if s0.tx_load + s1.tx_load > SHARD_MERGE_LOAD_THRESHOLD {
            return None;
        }

        let new_len = s0.prefix_len - 1;
        let shift = 64 - new_len;
        let parent_prefix = if shift >= 64 {
            0
        } else {
            (s0.prefix >> shift) << shift
        };

        self.shards.remove(&id0);
        self.shards.remove(&id1);

        // Ids are NEVER reused: a late cross-shard message addressed to a
        // retired shard id can then never be mistaken for the merged shard.
        let parent_id = self.next_shard_id;
        self.next_shard_id += 1;

        let parent = ShardDescriptor::new(parent_id, s0.workchain_id, parent_prefix, new_len);
        self.shards.insert(parent_id, parent.clone());

        Some(parent)
    }
}

// ===========================================================================
// Shard topology: the executable split/merge path and the published
// address→shard rule.
//
// HONESTY NOTE (read before quoting any sharding claim):
//
//   * DEMONSTRATED: the split/merge state machine, the account re-assignment
//     rule, the trie migration procedure and the routing rule are exercised
//     by a deterministic integration test over a synthetic account set
//     (`tests/sharding_topology_tests.rs`) and by `cargo test --lib sharding`.
//   * DESIGNED, NOT DEMONSTRATED: a LIVE-NETWORK split. No split has been
//     performed on the testnet or on mainnet; the split path has never been
//     driven by a live consensus event.
//
// The thresholds below are PUBLISHED constants, not folklore.
// ===========================================================================

/// Minimum number of accounts a shard must own before the topology is
/// willing to SPLIT it.
///
/// A shard below this size does not pay for its own consensus overhead, so
/// the topology keeps it as one shard. It is also the second half of the
/// anti-oscillation rule: the load thresholds (split at >= 500, merge at
/// <= 50) are disjoint, so a shard can never be simultaneously split- and
/// merge-eligible.
pub const MIN_ACCOUNTS_PER_SHARD: u64 = 100;

/// Maximum number of shards the topology will ever hold, masterchain
/// included.
///
/// HONESTY: the prefix-routing scheme admits a theoretical space of
/// [`MAX_WORKCHAIN_SHARD_SPACE`] (2^60) workchain shards. That is the
/// ADVERTISED ceiling, not a shipped capacity. What this network SHIPS is a
/// hard cap of 16 shards, enforced by [`ShardTopology::check_and_split`],
/// which refuses to grow past it. TON draws the same line publicly (it
/// advertises 2^60 shards and ships a cap of 16): the advertised number is
/// the address space, the cap is the capacity.
pub const MAX_SHARDS: usize = 16;

/// The theoretical workchain shard space of the prefix-routing scheme:
/// 2^60 shards. ADVERTISED, NOT SHIPPED — see [`MAX_SHARDS`].
pub const MAX_WORKCHAIN_SHARD_SPACE: u64 = 1u64 << 60;

/// Maximum routing-prefix length, in bits of the address.
///
/// 60 bits is the width of the theoretical shard space (2^60): a longer
/// prefix cannot name a distinct shard, so the topology refuses to split
/// past it.
pub const MAX_PREFIX_BITS: u8 = 60;

/// Identifier of the routing rule, published so a client can assert which
/// rule a node implements.
pub const ROUTING_RULE_ID: &str = "workchain-prefix-v1";

/// The routing rule, in words. This is the SINGLE SOURCE OF TRUTH: the RPC
/// layer (`stell_estimateFee`, `stell_runGetMethod`), the SVM's cross-shard
/// routing and the topology itself all resolve addresses through it.
///
/// * The MASTERCHAIN is addressed EXPLICITLY, in the `-1:<addr>` form (or by
///   naming shard 0). A bare 32-byte address NEVER routes to the masterchain.
/// * A WORKCHAIN address routes to the shard whose routing prefix is the
///   LONGEST prefix of the address's leading bits. Ties are broken by the
///   SMALLEST shard id, so the rule is a pure function of the topology.
/// * A split EXTENDS the prefix by one bit (the address's bit at the new
///   depth decides the child), a merge REMOVES the deepest bit and restores
///   the parent prefix. The routing rule therefore changes only at the
///   transition, never continuously.
pub const ROUTING_RULE: &str = "masterchain only via the -1: address form; \
workchain addresses route to the shard with the LONGEST matching routing \
prefix (ties broken by the smallest shard id); a split adds one routing bit, \
a merge removes the deepest one";

/// The address form that names the masterchain.
pub const MASTERCHAIN_ADDRESS_FORM: &str = "-1:<addr>";

/// The routing bit at index `bit` of an address.
///
/// `bit` is 0-based and counts from the MOST significant bit of byte 0 —
/// the same order as the routing prefix (see [`address_prefix_word`]).
///
/// Only the first 8 bytes are addressable by the routing prefix (the prefix
/// is a `u64`), so a `bit` of 64 or more reads as 0.
pub fn address_prefix_bit(address: &[u8; 32], bit: u8) -> u8 {
    let byte = (bit / 8) as usize;
    if byte >= 8 {
        return 0;
    }
    let shift = 7 - (bit % 8);
    (address[byte] >> shift) & 1
}

/// The top `prefix_len` bits of an address, as a big-endian `u64`.
///
/// The routing prefix of a shard is the top `prefix_len` bits of the
/// address's leading 8 bytes — the same definition TON uses for its
/// workchain shard prefixes.
///
/// The result is LEFT-ALIGNED, exactly like [`ShardDescriptor::prefix`]: the
/// meaningful bits sit at positions `63 ..= 64 - prefix_len` and the rest
/// are zero. Two descriptors with the same prefix word and the same prefix
/// length therefore cover the same address range.
pub fn address_prefix_word(address: &[u8; 32], prefix_len: u8) -> u64 {
    let word = u64::from_be_bytes(address[..8].try_into().unwrap());
    let len = u64::from(prefix_len).min(64);
    if len == 0 {
        return 0;
    }
    let shift = 64 - len;
    let mask = !0u64 << shift;
    word & mask
}

/// The bit at index `bit` (0-based, most-significant first) of a routing
/// prefix word.
fn prefix_word_bit(prefix: u64, bit: u8) -> u8 {
    if bit >= 64 {
        return 0;
    }
    ((prefix >> (63 - bit)) & 1) as u8
}

/// True when two shard descriptors are SIBLINGS: they share every routing
/// bit but the deepest one, so they cover one parent range exactly.
fn are_siblings(a: &ShardDescriptor, b: &ShardDescriptor) -> bool {
    let len = a.prefix_len;
    if a.prefix_len != b.prefix_len || len == 0 {
        return false;
    }
    let deepest = len - 1;
    if prefix_word_bit(a.prefix, deepest) == prefix_word_bit(b.prefix, deepest) {
        return false;
    }
    // The higher bits (0..deepest) must agree.
    let hi_shift = 64u32.saturating_sub(u32::from(deepest));
    if hi_shift >= 64 {
        return true;
    }
    let mask = !0u64 << hi_shift;
    (a.prefix & mask) == (b.prefix & mask)
}

/// An address together with the chain it is addressed ON.
///
/// The distinction is load-bearing: a bare 32-byte address is a WORKCHAIN
/// address (it routes by prefix), while the masterchain form `-1:<addr>`
/// names the masterchain explicitly. A bare address NEVER routes to the
/// masterchain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShardAddress {
    /// The masterchain (shard 0), addressed explicitly.
    Masterchain([u8; 32]),
    /// A workchain address, routed by prefix.
    Workchain([u8; 32]),
}

impl ShardAddress {
    /// The raw address bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        match self {
            Self::Masterchain(a) | Self::Workchain(a) => a,
        }
    }

    /// The shard this address form names explicitly, if it names one.
    pub fn explicit_shard(&self) -> Option<ShardId> {
        match self {
            Self::Masterchain(_) => Some(MASTERCHAIN_SHARD),
            Self::Workchain(_) => None,
        }
    }

    /// Build an address from raw bytes and an optional explicit shard pin.
    ///
    /// `Some(MASTERCHAIN_SHARD)` means the caller wrote the masterchain form
    /// (`-1:<addr>` or `0:<addr>`); any other id is an explicit workchain
    /// pin, which the routing rule does not use but the RPC layer reports
    /// back to the caller.
    pub fn with_hint(address: [u8; 32], hint: Option<ShardId>) -> Self {
        match hint {
            Some(MASTERCHAIN_SHARD) => Self::Masterchain(address),
            _ => Self::Workchain(address),
        }
    }
}

/// Split a TON-style `<chain>:<address>` string into the shard it names and
/// the address text.
///
/// * `-1:` -> the masterchain (shard 0)
/// * `0:`  -> the masterchain as well (shard 0 IS the masterchain id)
/// * `N:`  -> workchain shard N, named explicitly
///
/// The text after the colon is returned unchanged; the caller parses it with
/// its own address decoder.
pub fn split_shard_prefix(s: &str) -> (Option<ShardId>, &str) {
    let trimmed = s.trim();
    match trimmed.split_once(':') {
        Some((prefix, rest)) => {
            let shard = if prefix == "-1" {
                Some(MASTERCHAIN_SHARD)
            } else {
                prefix.trim().parse::<ShardId>().ok()
            };
            (shard, rest.trim())
        }
        None => (None, trimmed),
    }
}

/// One account as the topology owns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardAccount {
    /// The account address (the routing key).
    pub address: [u8; 32],
    /// The account balance.
    pub balance: u64,
}

/// The digest of an account set: SHA-256 over the addresses in ascending
/// order. Two account sets with the same digest hold the same addresses.
pub fn account_set_digest(accounts: &[ShardAccount]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"STELL_SHARD_ACCOUNTS_V1");
    for a in accounts {
        h.update(a.address);
    }
    h.finalize().into()
}

/// Which way a migration runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationDirection {
    /// One shard becomes two.
    Split,
    /// Two shards become one.
    Merge,
}

/// The account-level migration a transition performs.
///
/// The plan is the DETERMINISTIC description of what moves: which accounts,
/// where they go, and the digests that let a verifier prove the move was the
/// one that was planned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Split or merge.
    pub direction: MigrationDirection,
    /// The shard(s) the state comes from.
    pub source_shards: Vec<ShardId>,
    /// The shard(s) the state goes to.
    pub target_shards: Vec<ShardId>,
    /// The routing bit that decides the destination (splits only).
    pub split_bit: u8,
    /// How many accounts move.
    pub account_count: usize,
    /// Digest of the source account set BEFORE the move.
    pub source_digest: [u8; 32],
    /// Digest of each target account set AFTER the move.
    pub target_digests: Vec<[u8; 32]>,
    /// Balance of the source shard(s) BEFORE the move.
    pub source_balance: u128,
    /// Balance of each target shard AFTER the move.
    pub target_balances: Vec<u128>,
}

impl MigrationPlan {
    /// True when the move conserves the total balance.
    pub fn balances_conserve(&self) -> bool {
        let moved: u128 = self.target_balances.iter().sum();
        moved == self.source_balance
    }
}

/// The explicit map from a trie key to the address that owns it.
///
/// The trie stores account leaves under the raw address, but it also stores
/// NAMESPACED derived keys: a contract's code and ABI manifest
/// (`sha256("STELL_CONTRACT_CODE" || addr)`), a token balance
/// (`sha256("STS_BAL" || token_id || holder)`) and a token's supply
/// (`sha256("STS_SUPPLY" || token_id)`). Those keys are hashes, so the owner
/// CANNOT be recovered from the key alone.
///
/// The migration therefore carries an EXPLICIT manifest, built by the shard
/// that owns the state. A trie key the manifest does not classify ABORTS the
/// migration ([`MigrationError::UnclassifiedKey`]): a split fails closed
/// instead of silently dropping state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationManifest {
    /// `(trie key, owning address)`, sorted by trie key.
    pub entries: Vec<([u8; 32], [u8; 32])>,
}

impl MigrationManifest {
    /// An empty manifest.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record that `key` is owned by `owner`. Re-recording a key replaces the
    /// owner (last write wins, deterministically).
    pub fn own(&mut self, key: [u8; 32], owner: [u8; 32]) {
        match self.entries.binary_search_by(|probe| probe.0.cmp(&key)) {
            Ok(i) => self.entries[i].1 = owner,
            Err(i) => self.entries.insert(i, (key, owner)),
        }
    }

    /// The owner of `key`, if the manifest classifies it.
    pub fn owner_of(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.entries
            .binary_search_by(|probe| probe.0.cmp(key))
            .ok()
            .map(|i| self.entries[i].1)
    }

    /// How many keys the manifest classifies.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the manifest classifies nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The digest of the manifest: SHA-256 over the sorted (key, owner)
    /// pairs. Two manifests with the same digest classify the same keys the
    /// same way.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"STELL_MIGRATION_MANIFEST_V1");
        for (k, o) in &self.entries {
            h.update(k);
            h.update(o);
        }
        h.finalize().into()
    }
}

/// Why a migration step could not be carried out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationError {
    /// The split bit is outside the address prefix.
    BadSplitBit(u8),
    /// A trie key the manifest does not classify. The migration ABORTS: a
    /// split never silently drops state.
    UnclassifiedKey([u8; 32]),
    /// The manifest names a key the trie does not hold.
    MissingKey([u8; 32]),
    /// The key landed in both children.
    DuplicateAssignment([u8; 32]),
    /// The key landed in neither child.
    LostKey([u8; 32]),
    /// The value of a migrated key changed.
    ValueChanged([u8; 32]),
    /// A child holds a key the parent never had.
    ForeignKey([u8; 32]),
    /// The balances did not conserve.
    BalanceMismatch {
        /// The balance the plan says must survive.
        expected: u128,
        /// The balance that was actually there.
        actual: u128,
    },
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSplitBit(b) => write!(f, "split bit {b} is outside the address prefix"),
            Self::UnclassifiedKey(k) => {
                write!(
                    f,
                    "trie key {} is not classified by the manifest",
                    hex::encode(k)
                )
            }
            Self::MissingKey(k) => write!(f, "manifest key {} is not in the trie", hex::encode(k)),
            Self::DuplicateAssignment(k) => {
                write!(f, "trie key {} landed in both children", hex::encode(k))
            }
            Self::LostKey(k) => write!(f, "trie key {} landed in neither child", hex::encode(k)),
            Self::ValueChanged(k) => write!(f, "trie key {} changed value", hex::encode(k)),
            Self::ForeignKey(k) => {
                write!(f, "trie key {} is not in the parent trie", hex::encode(k))
            }
            Self::BalanceMismatch { expected, actual } => {
                write!(
                    f,
                    "balance did not conserve: expected {expected}, got {actual}"
                )
            }
        }
    }
}

/// The trie-level migration: the account plan plus the explicit key→owner
/// manifest, and the procedure that executes it against a real trie.
///
/// The procedure is deterministic and fail-closed:
///
/// 1. every key of the source trie is classified by the MANIFEST
///    (trie key → owning address);
/// 2. the owner's address decides the destination child by the split bit;
/// 3. a key the manifest does not classify ABORTS the migration — the split
///    never silently drops state;
/// 4. the CONSENSUS COMMITMENT key is NOT migrated: it is a digest over the
///    whole state, so each child recomputes its own from its own state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrieMigration {
    /// The account-level plan this migration implements.
    pub plan: MigrationPlan,
    /// The explicit key → owner map.
    pub manifest: MigrationManifest,
}

impl TrieMigration {
    /// Pair a plan with the manifest that implements it.
    pub fn new(plan: MigrationPlan, manifest: MigrationManifest) -> Self {
        Self { plan, manifest }
    }

    /// Execute a SPLIT: build the two child tries from the parent trie.
    pub fn execute_split(
        &self,
        parent: &PatriciaTrie,
    ) -> Result<(PatriciaTrie, PatriciaTrie), MigrationError> {
        let split_bit = self.plan.split_bit;
        if split_bit >= 64 {
            return Err(MigrationError::BadSplitBit(split_bit));
        }
        let commitment_key = crate::commitment::commitment_key();
        let mut keys: Vec<[u8; 32]> = parent.compressed().entries.keys().copied().collect();
        keys.sort_unstable();
        let mut child0 = PatriciaTrie::new();
        let mut child1 = PatriciaTrie::new();
        for key in keys {
            if key == commitment_key {
                // Each child recomputes its own commitment digest over its
                // own state; migrating the parent's digest would make the
                // child claim a root it does not have.
                continue;
            }
            let owner = self
                .manifest
                .owner_of(&key)
                .ok_or(MigrationError::UnclassifiedKey(key))?;
            let value = parent
                .compressed()
                .entries
                .get(&key)
                .cloned()
                .ok_or(MigrationError::MissingKey(key))?;
            if address_prefix_bit(&owner, split_bit) == 0 {
                child0.insert(&key, &value);
            } else {
                child1.insert(&key, &value);
            }
        }
        Ok((child0, child1))
    }

    /// Verify a completed SPLIT: every parent key is in exactly one child,
    /// with the same value, and neither child holds a foreign key.
    pub fn verify_split(
        &self,
        parent: &PatriciaTrie,
        child0: &PatriciaTrie,
        child1: &PatriciaTrie,
    ) -> Result<(), MigrationError> {
        let commitment_key = crate::commitment::commitment_key();
        for (key, value) in parent.compressed().entries.iter() {
            if *key == commitment_key {
                continue;
            }
            let owner = self
                .manifest
                .owner_of(key)
                .ok_or(MigrationError::UnclassifiedKey(*key))?;
            let bit = address_prefix_bit(&owner, self.plan.split_bit);
            let (own, other) = if bit == 0 {
                (child0, child1)
            } else {
                (child1, child0)
            };
            match own.get(key) {
                None => return Err(MigrationError::LostKey(*key)),
                Some(got) if got != value.as_slice() => {
                    return Err(MigrationError::ValueChanged(*key))
                }
                Some(_) => {}
            }
            if other.get(key).is_some() {
                return Err(MigrationError::DuplicateAssignment(*key));
            }
        }
        for key in child0.compressed().entries.keys() {
            if !parent.compressed().entries.contains_key(key) {
                return Err(MigrationError::ForeignKey(*key));
            }
        }
        for key in child1.compressed().entries.keys() {
            if !parent.compressed().entries.contains_key(key) {
                return Err(MigrationError::ForeignKey(*key));
            }
        }
        if !self.plan.balances_conserve() {
            return Err(MigrationError::BalanceMismatch {
                expected: self.plan.source_balance,
                actual: self.plan.target_balances.iter().sum(),
            });
        }
        Ok(())
    }

    /// Execute a MERGE: build the parent trie from the two child tries.
    ///
    /// The merge is the INVERSE of the split: every key of both children
    /// lands in the parent, and a key the manifest does not classify aborts
    /// the merge (fail closed, same as the split).
    pub fn execute_merge(
        &self,
        child0: &PatriciaTrie,
        child1: &PatriciaTrie,
    ) -> Result<PatriciaTrie, MigrationError> {
        let commitment_key = crate::commitment::commitment_key();
        let mut keys: Vec<[u8; 32]> = child0
            .compressed()
            .entries
            .keys()
            .chain(child1.compressed().entries.keys())
            .copied()
            .collect();
        keys.sort_unstable();
        keys.dedup();
        let mut parent = PatriciaTrie::new();
        for key in keys {
            if key == commitment_key {
                continue;
            }
            // The manifest must classify EVERY key, even in a merge: an
            // unclassified key aborts the merge (fail closed) rather than
            // letting an unknown piece of state into the parent.
            self.manifest
                .owner_of(&key)
                .ok_or(MigrationError::UnclassifiedKey(key))?;
            let value = child0
                .compressed()
                .entries
                .get(&key)
                .or_else(|| child1.compressed().entries.get(&key))
                .cloned()
                .ok_or(MigrationError::MissingKey(key))?;
            parent.insert(&key, &value);
        }
        Ok(parent)
    }

    /// Verify a completed MERGE: the parent holds every key of both children
    /// with the same value, and holds nothing else.
    pub fn verify_merge(
        &self,
        parent: &PatriciaTrie,
        child0: &PatriciaTrie,
        child1: &PatriciaTrie,
    ) -> Result<(), MigrationError> {
        let commitment_key = crate::commitment::commitment_key();
        for (key, value) in child0.compressed().entries.iter() {
            if *key == commitment_key {
                continue;
            }
            match parent.get(key) {
                None => return Err(MigrationError::LostKey(*key)),
                Some(got) if got != value.as_slice() => {
                    return Err(MigrationError::ValueChanged(*key))
                }
                Some(_) => {}
            }
        }
        for (key, value) in child1.compressed().entries.iter() {
            if *key == commitment_key {
                continue;
            }
            match parent.get(key) {
                None => return Err(MigrationError::LostKey(*key)),
                Some(got) if got != value.as_slice() => {
                    return Err(MigrationError::ValueChanged(*key))
                }
                Some(_) => {}
            }
        }
        for key in parent.compressed().entries.keys() {
            if key == &commitment_key {
                continue;
            }
            if !child0.compressed().entries.contains_key(key)
                && !child1.compressed().entries.contains_key(key)
            {
                return Err(MigrationError::ForeignKey(*key));
            }
        }
        if !self.plan.balances_conserve() {
            return Err(MigrationError::BalanceMismatch {
                expected: self.plan.source_balance,
                actual: self.plan.target_balances.iter().sum(),
            });
        }
        Ok(())
    }
}

/// Why a split did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitRefusal {
    /// No such shard.
    UnknownShard,
    /// The masterchain never splits.
    Masterchain,
    /// The shard's recorded load is below the split threshold.
    LoadTooLow {
        /// The recorded load.
        load: u64,
        /// The threshold that was not reached.
        threshold: u64,
    },
    /// The shard owns too few accounts to be worth splitting.
    TooFewAccounts {
        /// How many accounts the shard owns.
        accounts: u64,
        /// The minimum a shard must own.
        minimum: u64,
    },
    /// The shard cap is reached.
    ShardCapReached {
        /// The current number of shards.
        shards: usize,
        /// The cap.
        cap: usize,
    },
    /// The routing prefix is already as deep as it can go.
    PrefixTooDeep {
        /// The current prefix length.
        prefix_len: u8,
        /// The maximum prefix length.
        max: u8,
    },
}

impl std::fmt::Display for SplitRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownShard => write!(f, "unknown shard"),
            Self::Masterchain => write!(f, "the masterchain never splits"),
            Self::LoadTooLow { load, threshold } => {
                write!(f, "load {load} is below the split threshold {threshold}")
            }
            Self::TooFewAccounts { accounts, minimum } => {
                write!(
                    f,
                    "{accounts} accounts is below the split minimum {minimum}"
                )
            }
            Self::ShardCapReached { shards, cap } => {
                write!(f, "shard cap {cap} reached ({shards} active)")
            }
            Self::PrefixTooDeep { prefix_len, max } => {
                write!(
                    f,
                    "routing prefix {prefix_len} bits is already at the maximum {max}"
                )
            }
        }
    }
}

/// Why a merge did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeRefusal {
    /// No such shard.
    UnknownShard(ShardId),
    /// The masterchain never merges.
    Masterchain,
    /// The two shards are not siblings (they do not share a parent range).
    NotSiblings,
    /// The two shards belong to different workchains.
    DifferentWorkchain,
    /// The combined load is above the merge threshold.
    LoadTooHigh {
        /// The combined recorded load.
        load: u64,
        /// The threshold that was exceeded.
        threshold: u64,
    },
}

impl std::fmt::Display for MergeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownShard(id) => write!(f, "unknown shard {id}"),
            Self::Masterchain => write!(f, "the masterchain never merges"),
            Self::NotSiblings => write!(f, "the two shards are not siblings"),
            Self::DifferentWorkchain => write!(f, "the two shards belong to different workchains"),
            Self::LoadTooHigh { load, threshold } => {
                write!(f, "load {load} is above the merge threshold {threshold}")
            }
        }
    }
}

/// A topology invariant that does not hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopologyError {
    /// The same address is owned by two shards.
    DuplicateOwner([u8; 32]),
    /// An address is owned by a shard the routing rule does not select.
    Misrouted {
        /// The address.
        address: [u8; 32],
        /// The shard that claims it.
        owner: ShardId,
        /// The shard the routing rule selects.
        routed: ShardId,
    },
    /// A shard owns an account outside its routing prefix.
    PrefixViolation {
        /// The shard.
        shard: ShardId,
        /// The address.
        address: [u8; 32],
    },
    /// The total balance changed.
    BalanceMismatch {
        /// The balance the plan says must survive.
        expected: u128,
        /// The balance that is actually there.
        actual: u128,
    },
}

impl std::fmt::Display for TopologyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateOwner(a) => write!(f, "address {} is owned twice", hex::encode(a)),
            Self::Misrouted {
                address,
                owner,
                routed,
            } => write!(
                f,
                "address {} is owned by shard {owner} but routes to shard {routed}",
                hex::encode(address)
            ),
            Self::PrefixViolation { shard, address } => write!(
                f,
                "address {} is outside the routing prefix of shard {shard}",
                hex::encode(address)
            ),
            Self::BalanceMismatch { expected, actual } => {
                write!(
                    f,
                    "balance did not conserve: expected {expected}, got {actual}"
                )
            }
        }
    }
}

/// A split that was executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitTransition {
    /// The shard that was split.
    pub parent: ShardDescriptor,
    /// The two children, in prefix order (child 0 carries the 0 bit).
    pub children: [ShardDescriptor; 2],
    /// The account-level migration that was performed.
    pub plan: MigrationPlan,
}

/// A merge that was executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeTransition {
    /// The two shards that were merged.
    pub children: [ShardDescriptor; 2],
    /// The shard that now holds their state.
    pub parent: ShardDescriptor,
    /// The account-level migration that was performed.
    pub plan: MigrationPlan,
}

/// The shard topology: the active shard set, who owns which account, and the
/// split/merge transitions between them.
///
/// This is the REACHABLE, TESTABLE home of the dynamic sharding logic. The
/// [`DynamicShardManager`] decides *whether* a shard may split or merge (it
/// owns the prefix arithmetic and the shard-id allocation); the topology
/// owns the ACCOUNT OWNERSHIP and performs the deterministic re-assignment
/// that makes a split real.
#[derive(Clone, Debug)]
pub struct ShardTopology {
    /// The shard set and the split/merge decision logic.
    pub manager: DynamicShardManager,
    /// Per-shard account ownership, sorted by address within each shard.
    pub ownership: BTreeMap<ShardId, Vec<ShardAccount>>,
    /// How many split/merge transitions this topology has applied.
    pub transitions: u64,
}

/// The default topology is the STARTING one (masterchain + base workchain
/// shard), never an empty shard set: a topology with no workchain shard
/// would route every bare address to the masterchain.
impl Default for ShardTopology {
    fn default() -> Self {
        Self::new()
    }
}

impl ShardTopology {
    /// The starting topology: the masterchain (shard 0) and the base
    /// workchain shard (shard 1), which holds every workchain address
    /// (its routing prefix is empty).
    pub fn new() -> Self {
        let manager = DynamicShardManager::new();
        let mut ownership: BTreeMap<ShardId, Vec<ShardAccount>> = BTreeMap::new();
        ownership.insert(MASTERCHAIN_SHARD, Vec::new());
        ownership.insert(BASE_WORKCHAIN_SHARD_INITIAL, Vec::new());
        Self {
            manager,
            ownership,
            transitions: 0,
        }
    }

    /// The active shard set, in ascending shard id.
    pub fn shards(&self) -> impl Iterator<Item = (&ShardId, &ShardDescriptor)> {
        self.manager.shards.iter()
    }

    /// The descriptor of one shard.
    pub fn descriptor(&self, shard: ShardId) -> Option<&ShardDescriptor> {
        self.manager.shards.get(&shard)
    }

    /// How many shards are active (the masterchain included).
    pub fn shard_count(&self) -> usize {
        self.manager.shards.len()
    }

    /// The accounts a shard owns, sorted by address.
    pub fn accounts_of(&self, shard: ShardId) -> &[ShardAccount] {
        self.ownership
            .get(&shard)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Every account in the topology, sorted by address.
    pub fn all_accounts(&self) -> Vec<ShardAccount> {
        let mut all: Vec<ShardAccount> = self
            .ownership
            .values()
            .flat_map(|v| v.iter().copied())
            .collect();
        all.sort_by(|a, b| a.address.cmp(&b.address));
        all
    }

    /// Register an account with a balance on the shard the routing rule
    /// selects. Returns the shard it landed on.
    pub fn register_account(&mut self, address: [u8; 32], balance: u64) -> ShardId {
        let shard = self.route_workchain(&address);
        let list = self.ownership.entry(shard).or_default();
        match list.binary_search_by(|probe| probe.address.cmp(&address)) {
            Ok(i) => list[i].balance = balance,
            Err(i) => list.insert(i, ShardAccount { address, balance }),
        }
        shard
    }

    /// Drop an account (it moved to another shard, or it closed).
    pub fn remove_account(&mut self, address: &[u8; 32]) -> Option<u64> {
        for list in self.ownership.values_mut() {
            if let Ok(i) = list.binary_search_by(|probe| probe.address.cmp(address)) {
                return Some(list.remove(i).balance);
            }
        }
        None
    }

    /// Which shard owns an account, if any.
    pub fn owner_of(&self, address: &[u8; 32]) -> Option<ShardId> {
        self.ownership.iter().find_map(|(id, list)| {
            list.binary_search_by(|probe| probe.address.cmp(address))
                .ok()
                .map(|_| *id)
        })
    }

    /// The total balance the topology holds.
    pub fn total_balance(&self) -> u128 {
        self.ownership
            .values()
            .flat_map(|v| v.iter())
            .map(|a| a.balance as u128)
            .sum()
    }

    /// The balance one shard holds.
    pub fn shard_balance(&self, shard: ShardId) -> u128 {
        self.accounts_of(shard)
            .iter()
            .map(|a| a.balance as u128)
            .sum()
    }

    /// THE ROUTING RULE.
    ///
    /// See [`ROUTING_RULE`]: the masterchain is addressed explicitly, a
    /// workchain address goes to the shard with the longest matching routing
    /// prefix (ties broken by the smallest shard id).
    pub fn route(&self, address: &ShardAddress) -> ShardId {
        match address {
            ShardAddress::Masterchain(_) => MASTERCHAIN_SHARD,
            ShardAddress::Workchain(a) => self.route_workchain(a),
        }
    }

    /// Route a WORKCHAIN address (the bare 32-byte form).
    pub fn route_workchain(&self, address: &[u8; 32]) -> ShardId {
        self.manager.route_address(address)
    }

    /// Record transaction load on a shard (the load window counter).
    pub fn record_tx_load(&mut self, shard: ShardId, count: u64) {
        self.manager.record_tx_load(shard, count);
    }

    /// Decay the recorded load of every shard. The load window rolls, so a
    /// quiet shard drains towards zero and becomes merge-eligible.
    pub fn decay_load(&mut self, amount: u64) {
        for s in self.manager.shards.values_mut() {
            s.tx_load = s.tx_load.saturating_sub(amount);
        }
    }

    /// The published split trigger for `shard_id`.
    ///
    /// A split happens when ALL of these hold:
    ///
    /// * the shard is not the masterchain;
    /// * the shard cap ([`MAX_SHARDS`]) is not reached;
    /// * the routing prefix is not already at [`MAX_PREFIX_BITS`];
    /// * the shard owns at least [`MIN_ACCOUNTS_PER_SHARD`] accounts;
    /// * the shard's recorded load is at least [`SHARD_SPLIT_LOAD_THRESHOLD`].
    pub fn split_preconditions(&self, shard_id: ShardId) -> Result<(), SplitRefusal> {
        let Some(desc) = self.manager.shards.get(&shard_id) else {
            return Err(SplitRefusal::UnknownShard);
        };
        if shard_id == MASTERCHAIN_SHARD {
            return Err(SplitRefusal::Masterchain);
        }
        if self.manager.shards.len() >= MAX_SHARDS {
            return Err(SplitRefusal::ShardCapReached {
                shards: self.manager.shards.len(),
                cap: MAX_SHARDS,
            });
        }
        if desc.prefix_len >= MAX_PREFIX_BITS {
            return Err(SplitRefusal::PrefixTooDeep {
                prefix_len: desc.prefix_len,
                max: MAX_PREFIX_BITS,
            });
        }
        let accounts = self.accounts_of(shard_id).len() as u64;
        if accounts < MIN_ACCOUNTS_PER_SHARD {
            return Err(SplitRefusal::TooFewAccounts {
                accounts,
                minimum: MIN_ACCOUNTS_PER_SHARD,
            });
        }
        if desc.tx_load < SHARD_SPLIT_LOAD_THRESHOLD {
            return Err(SplitRefusal::LoadTooLow {
                load: desc.tx_load,
                threshold: SHARD_SPLIT_LOAD_THRESHOLD,
            });
        }
        Ok(())
    }

    /// The published merge trigger for two shards.
    ///
    /// A merge happens when ALL of these hold:
    ///
    /// * both shards exist, are not the masterchain and belong to the same
    ///   workchain;
    /// * they are SIBLINGS — they share every routing bit but the deepest
    ///   one, so together they cover exactly one parent range;
    /// * their combined recorded load is at most
    ///   [`SHARD_MERGE_LOAD_THRESHOLD`].
    pub fn merge_preconditions(&self, a: ShardId, b: ShardId) -> Result<(), MergeRefusal> {
        let Some(d0) = self.manager.shards.get(&a) else {
            return Err(MergeRefusal::UnknownShard(a));
        };
        let Some(d1) = self.manager.shards.get(&b) else {
            return Err(MergeRefusal::UnknownShard(b));
        };
        if a == MASTERCHAIN_SHARD || b == MASTERCHAIN_SHARD {
            return Err(MergeRefusal::Masterchain);
        }
        if d0.prefix_len != d1.prefix_len || d0.prefix_len == 0 {
            return Err(MergeRefusal::NotSiblings);
        }
        if d0.workchain_id != d1.workchain_id {
            return Err(MergeRefusal::DifferentWorkchain);
        }
        if !are_siblings(d0, d1) {
            return Err(MergeRefusal::NotSiblings);
        }
        let load = d0.tx_load.saturating_add(d1.tx_load);
        if load > SHARD_MERGE_LOAD_THRESHOLD {
            return Err(MergeRefusal::LoadTooHigh {
                load,
                threshold: SHARD_MERGE_LOAD_THRESHOLD,
            });
        }
        Ok(())
    }

    /// Split `shard_id` if the published trigger fires.
    ///
    /// The split is EXECUTED, not merely planned:
    ///
    /// * the routing prefix grows by one bit; the address's bit at the new
    ///   depth decides the child (bit 0 → child 0, bit 1 → child 1);
    /// * the parent's accounts are re-assigned by that rule;
    /// * the parent's recorded load is divided between the children (child 0
    ///   gets the floor, child 1 the remainder), so the SUM is preserved.
    ///
    /// The load division is what makes the cycle converge: a split parent
    /// had a load of at least [`SHARD_SPLIT_LOAD_THRESHOLD`] (500) and the
    /// merge threshold is [`SHARD_MERGE_LOAD_THRESHOLD`] (50), so a shard
    /// that has just split is NOT merge-eligible — the topology can never
    /// oscillate between the two.
    pub fn check_and_split(&mut self, shard_id: ShardId) -> Option<SplitTransition> {
        self.split_preconditions(shard_id).ok()?;
        let parent_desc = self.manager.shards.get(&shard_id).cloned()?;
        let parent_load = parent_desc.tx_load;
        let parent_accounts = self.accounts_of(shard_id).to_vec();
        let source_digest = account_set_digest(&parent_accounts);
        let source_balance = parent_accounts
            .iter()
            .map(|a| a.balance as u128)
            .sum::<u128>();

        let (child0, child1) = self.manager.check_and_split(shard_id)?;
        let split_bit = child0.prefix_len - 1;

        let mut accounts0: Vec<ShardAccount> = Vec::new();
        let mut accounts1: Vec<ShardAccount> = Vec::new();
        for acct in parent_accounts {
            if address_prefix_bit(&acct.address, split_bit) == 0 {
                accounts0.push(acct);
            } else {
                accounts1.push(acct);
            }
        }
        self.ownership.remove(&shard_id);
        self.ownership.insert(child0.shard_id, accounts0);
        self.ownership.insert(child1.shard_id, accounts1);

        let share = parent_load / 2;
        if let Some(s) = self.manager.shards.get_mut(&child0.shard_id) {
            s.tx_load = share;
        }
        if let Some(s) = self.manager.shards.get_mut(&child1.shard_id) {
            s.tx_load = parent_load - share;
        }

        let target_balances = vec![
            self.shard_balance(child0.shard_id),
            self.shard_balance(child1.shard_id),
        ];
        let target_digests = vec![
            account_set_digest(self.accounts_of(child0.shard_id)),
            account_set_digest(self.accounts_of(child1.shard_id)),
        ];

        let plan = MigrationPlan {
            direction: MigrationDirection::Split,
            source_shards: vec![shard_id],
            target_shards: vec![child0.shard_id, child1.shard_id],
            split_bit,
            account_count: self.accounts_of(child0.shard_id).len()
                + self.accounts_of(child1.shard_id).len(),
            source_digest,
            target_digests,
            source_balance,
            target_balances,
        };

        self.transitions += 1;
        Some(SplitTransition {
            parent: parent_desc,
            children: [child0, child1],
            plan,
        })
    }

    /// Merge two sibling shards if the published trigger fires.
    ///
    /// The merge is the INVERSE of the split: the children are replaced by
    /// one parent whose routing prefix is the deepest common prefix, and
    /// both children's accounts move to it. The total balance is unchanged.
    ///
    /// The merged shard gets a NEW shard id: ids are never reused, so a late
    /// cross-shard message addressed to a retired id can never be mistaken
    /// for the merged shard.
    pub fn check_and_merge(&mut self, a: ShardId, b: ShardId) -> Option<MergeTransition> {
        self.merge_preconditions(a, b).ok()?;
        let desc_a = self.manager.shards.get(&a).cloned()?;
        let desc_b = self.manager.shards.get(&b).cloned()?;
        let combined_load = desc_a.tx_load.saturating_add(desc_b.tx_load);

        let mut accounts = self.accounts_of(a).to_vec();
        accounts.extend(self.accounts_of(b).iter().copied());
        accounts.sort_by(|x, y| x.address.cmp(&y.address));
        let source_digest = account_set_digest(&accounts);
        let source_balance = accounts.iter().map(|x| x.balance as u128).sum::<u128>();

        let parent = self.manager.check_and_merge(a, b)?;

        self.ownership.remove(&a);
        self.ownership.remove(&b);
        self.ownership.insert(parent.shard_id, accounts);

        if let Some(s) = self.manager.shards.get_mut(&parent.shard_id) {
            s.tx_load = combined_load;
        }

        let plan = MigrationPlan {
            direction: MigrationDirection::Merge,
            source_shards: vec![a, b],
            target_shards: vec![parent.shard_id],
            split_bit: parent.prefix_len,
            account_count: self.accounts_of(parent.shard_id).len(),
            source_digest,
            target_digests: vec![account_set_digest(self.accounts_of(parent.shard_id))],
            source_balance,
            target_balances: vec![self.shard_balance(parent.shard_id)],
        };

        self.transitions += 1;
        Some(MergeTransition {
            children: [desc_a, desc_b],
            parent,
            plan,
        })
    }

    /// Verify the invariants a topology must hold after every transition:
    ///
    /// * every account is owned by EXACTLY one shard;
    /// * the routing rule resolves every account to the shard that owns it
    ///   (so the rule and the ownership never drift apart);
    /// * every owned address falls inside its shard's routing prefix.
    pub fn verify_invariants(&self) -> Result<(), TopologyError> {
        let mut seen: BTreeMap<[u8; 32], ShardId> = BTreeMap::new();
        for (shard, list) in &self.ownership {
            for acct in list {
                if seen.insert(acct.address, *shard).is_some() {
                    return Err(TopologyError::DuplicateOwner(acct.address));
                }
                let routed = self.route_workchain(&acct.address);
                if routed != *shard {
                    return Err(TopologyError::Misrouted {
                        address: acct.address,
                        owner: *shard,
                        routed,
                    });
                }
                if let Some(desc) = self.manager.shards.get(shard) {
                    if !desc.contains_address(&acct.address) {
                        return Err(TopologyError::PrefixViolation {
                            shard: *shard,
                            address: acct.address,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// The published sharding parameters, as the RPC layer reports them.
    pub fn parameters(&self) -> ShardingParameters {
        let prefix_bits = self
            .manager
            .shards
            .values()
            .map(|d| d.prefix_len)
            .max()
            .unwrap_or(0);
        ShardingParameters {
            rule_id: ROUTING_RULE_ID.to_string(),
            rule: ROUTING_RULE.to_string(),
            prefix_bits,
            masterchain_shard: MASTERCHAIN_SHARD,
            base_workchain_shard: BASE_WORKCHAIN_SHARD_INITIAL,
            masterchain_address_form: MASTERCHAIN_ADDRESS_FORM.to_string(),
            min_accounts_per_shard: MIN_ACCOUNTS_PER_SHARD,
            max_shards: MAX_SHARDS,
            split_load_threshold: SHARD_SPLIT_LOAD_THRESHOLD,
            merge_load_threshold: SHARD_MERGE_LOAD_THRESHOLD,
            max_prefix_bits: MAX_PREFIX_BITS,
            max_workchain_shard_space: MAX_WORKCHAIN_SHARD_SPACE,
            active_shards: self.shard_count(),
        }
    }

    /// The full topology report (parameters + every shard).
    pub fn report(&self) -> ShardTopologyReport {
        let mut shards = Vec::new();
        for (id, desc) in &self.manager.shards {
            shards.push(ShardTopologyEntry {
                shard_id: *id,
                shard_type: if *id == MASTERCHAIN_SHARD {
                    "masterchain".to_string()
                } else {
                    "workchain".to_string()
                },
                workchain_id: desc.workchain_id,
                prefix: desc.prefix,
                prefix_len: desc.prefix_len,
                prefix_bits: prefix_bits_string(desc.prefix, desc.prefix_len),
                accounts: self.accounts_of(*id).len(),
                balance: self.shard_balance(*id),
                tx_load: desc.tx_load,
            });
        }
        ShardTopologyReport {
            parameters: self.parameters(),
            shards,
            transitions: self.transitions,
            total_accounts: self.ownership.values().map(|v| v.len()).sum(),
            total_balance: self.total_balance(),
        }
    }
}

/// The routing prefix of a shard as a bit string (most significant first).
pub fn prefix_bits_string(prefix: u64, prefix_len: u8) -> String {
    let len = u64::from(prefix_len).min(64);
    if len == 0 {
        return String::new();
    }
    let shifted = prefix >> (64 - len);
    format!("{:0width$b}", shifted, width = len as usize)
}

/// The published sharding parameters, as `stell_getShards` reports them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardingParameters {
    /// The identifier of the routing rule.
    pub rule_id: String,
    /// The routing rule, in words.
    pub rule: String,
    /// The routing prefix length the topology currently uses.
    pub prefix_bits: u8,
    /// The masterchain shard id.
    pub masterchain_shard: ShardId,
    /// The base workchain shard id.
    pub base_workchain_shard: ShardId,
    /// The address form that names the masterchain.
    pub masterchain_address_form: String,
    /// Minimum accounts a shard must own to be split.
    pub min_accounts_per_shard: u64,
    /// The hard cap on the number of shards.
    pub max_shards: usize,
    /// Load that triggers a split (txs per window).
    pub split_load_threshold: u64,
    /// Load that allows a merge (txs per window).
    pub merge_load_threshold: u64,
    /// The maximum routing prefix length, in bits.
    pub max_prefix_bits: u8,
    /// The ADVERTISED shard space (2^60) — not the shipped capacity.
    pub max_workchain_shard_space: u64,
    /// How many shards are active right now.
    pub active_shards: usize,
}

/// One shard, as the topology report describes it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardTopologyEntry {
    /// The shard id.
    pub shard_id: ShardId,
    /// `"masterchain"` or `"workchain"`.
    pub shard_type: String,
    /// The workchain this shard belongs to (`-1` for the masterchain).
    pub workchain_id: i32,
    /// The routing prefix word.
    pub prefix: u64,
    /// The routing prefix length, in bits.
    pub prefix_len: u8,
    /// The routing prefix as a bit string.
    pub prefix_bits: String,
    /// How many accounts the shard owns.
    pub accounts: usize,
    /// The balance the shard holds.
    pub balance: u128,
    /// The shard's recorded load (txs per window).
    pub tx_load: u64,
}

/// The full topology report.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardTopologyReport {
    /// The published parameters.
    pub parameters: ShardingParameters,
    /// Every active shard.
    pub shards: Vec<ShardTopologyEntry>,
    /// How many transitions the topology has applied.
    pub transitions: u64,
    /// How many accounts the topology holds.
    pub total_accounts: usize,
    /// The total balance the topology holds.
    pub total_balance: u128,
}

/// Resolve an address to its shard under `topology`.
///
/// THIS IS THE SINGLE SOURCE OF TRUTH of the address→shard rule: the RPC
/// layer, the SVM's cross-shard routing and the topology itself all call
/// this (or [`ShardTopology::route`], which is the same rule).
pub fn route_shard(topology: &ShardTopology, address: &ShardAddress) -> ShardId {
    topology.route(address)
}

/// Route an address to its target shard using dynamic shard routing and prefix rules.
///
/// This is the DEFAULT (single-shard) rule: the starting topology, where the
/// base workchain shard holds every workchain address. For the rule as the
/// live topology applies it, use [`route_shard`] with the node's topology —
/// that is the single source of truth.
pub fn route_address(address: &[u8; 32]) -> ShardId {
    DynamicShardManager::new().route_address(address)
}

/// Domain separator for the explicit mempool priority bid inside the signed
/// message and the transaction hash.
///
/// VERSIONING: the commitment is mixed in ONLY when the bid is non-zero, so a
/// legacy transaction (no bid) keeps byte-identical bytes, signatures, hashes
/// and block hashes. The tag keeps the commitment from ever colliding with
/// another part of the preimage.
pub const PRIORITY_FEE_COMMITMENT_TAG: &[u8; 8] = b"PRIORITY";

/// Wire form of a transaction: the EXACT byte layout of the legacy
/// transaction, so a legacy transaction's bytes are unchanged, with the
/// explicit priority bid carried INSIDE the (length-prefixed) signature blob.
///
/// WHY NOT A PLAIN STRUCT FIELD: bincode is POSITIONAL. A new fixed-size
/// field appended to `Transaction` would be read from the bytes that FOLLOW
/// the transaction in its container — a block's next field, the next
/// transaction in the vector — so every container that holds a transaction
/// (every block, every gossip batch, the chain's own persisted history)
/// would mis-parse, and a legacy transaction could no longer be decoded at
/// all. The signature blob is length-prefixed, so a suffix inside it is
/// SELF-DELIMITING: a legacy transaction's bytes are byte-identical, a
/// transaction with a bid simply carries a longer signature blob, and every
/// container still decodes exactly as before.
#[derive(Serialize, Deserialize)]
struct TransactionWire {
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: ShardId,
    target_shard: ShardId,
    signature: Vec<u8>,
    /// Optional SVM program (micro-gas ops) executed against the sender's account
    /// during block application. Empty = a plain value transfer.
    #[serde(default)]
    payload: Vec<crate::svm::OpCode>,
}

#[derive(Clone, Debug)]
pub struct Transaction {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub gas_limit: u64,
    pub nonce: u64,
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    /// The signature blob WITHOUT the trailing priority envelope (the
    /// envelope is split off at decode time and lives in
    /// `priority_fee_per_gas`).
    pub signature: Vec<u8>,
    /// Optional SVM program (micro-gas ops) executed against the sender's account
    /// during block application. Empty = a plain value transfer.
    pub payload: Vec<crate::svm::OpCode>,
    /// EXPLICIT MEMPOOL PRIORITY BID (audit: priority inversion).
    ///
    /// `gas_limit` is a RESOURCE CAP (it bounds the work a transaction may
    /// do) that historically doubled as the price, so a transaction that
    /// simply declared a huge `gas_limit` took the top of the mempool without
    /// paying any extra: a cap was silently acting as a price. This field is
    /// the EXPLICIT price. The mempool orders by it FIRST (see
    /// `crate::mempool::Mempool`), and admission refuses a bid the sender has
    /// not funded — the bid must be covered by `gas_limit`, so priority is
    /// never free (see `Mempool::required_fee_for_tx`).
    ///
    /// DEFAULT 0 = LEGACY BEHAVIOUR: the bid is mixed into the signed message
    /// and the transaction hash ONLY when it is non-zero, so every legacy
    /// transaction keeps byte-identical bytes, signatures, hashes and block
    /// hashes.
    ///
    /// ON THE WIRE it travels as a trailing envelope INSIDE the signature
    /// blob (see [`TransactionWire`]), never as a separate struct field.
    pub priority_fee_per_gas: u64,
}

impl Serialize for Transaction {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
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
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
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
    /// Length of the trailing priority envelope: an 8-byte tag plus the
    /// big-endian bid.
    const PRIORITY_ENVELOPE_LEN: usize = 16;

    /// Split the trailing priority envelope off a signature blob.
    ///
    /// Returns `(body, bid)`. A blob that does not end with the envelope tag
    /// is a legacy signature: it is returned unchanged with a bid of 0. The
    /// tag is 8 bytes, so a legacy blob that coincidentally ends with it is
    /// 2^-64 unlikely — and it fails closed anyway (the shortened body no
    /// longer verifies).
    fn split_priority_envelope(blob: &[u8]) -> (Vec<u8>, u64) {
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

    /// Append the priority envelope to a signature blob (a no-op for a bid of
    /// 0, which keeps a legacy transaction's bytes byte-identical).
    fn encode_priority_envelope(body: &[u8], priority_fee_per_gas: u64) -> Vec<u8> {
        if priority_fee_per_gas == 0 {
            return body.to_vec();
        }
        let mut out = Vec::with_capacity(body.len() + Self::PRIORITY_ENVELOPE_LEN);
        out.extend_from_slice(body);
        out.extend_from_slice(PRIORITY_FEE_COMMITMENT_TAG);
        out.extend_from_slice(&priority_fee_per_gas.to_be_bytes());
        out
    }

    pub fn sign(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
    ) -> Self {
        Self::sign_with_payload(
            from_key,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            Vec::new(),
        )
    }

    /// Sign a transaction that carries an EXPLICIT MEMPOOL PRIORITY BID.
    ///
    /// The bid is the price the mempool orders by FIRST (audit: priority
    /// inversion — `gas_limit` is a resource cap, not a price). It is signed
    /// with the rest of the transaction, so it cannot be inflated by anyone
    /// but the sender, and admission requires the bid to be FUNDED (the
    /// declared `gas_limit` must cover `floor + bid`), so priority is never
    /// free. A bid of 0 is exactly the legacy behaviour (byte-identical
    /// signing bytes and transaction hash).
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_priority(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        priority_fee_per_gas: u64,
    ) -> Self {
        Self::sign_with_payload_and_priority(
            from_key,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            Vec::new(),
            priority_fee_per_gas,
        )
    }

    /// Sign a transaction carrying an SVM payload (contract call / token syscalls /
    /// orderbook ops). The payload is committed into the signature, so a payload
    /// cannot be swapped after signing.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_payload(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
    ) -> Self {
        Self::sign_with_payload_and_priority(
            from_key,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            payload,
            0,
        )
    }

    /// Sign a transaction carrying an SVM payload AND an explicit mempool
    /// priority bid. See [`Transaction::sign_with_priority`] for the bid's
    /// semantics.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_payload_and_priority(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        priority_fee_per_gas: u64,
    ) -> Self {
        let from_pub = from_key.verifying_key().to_bytes();
        let msg = Self::base_signing_message(
            &from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            &payload,
            priority_fee_per_gas,
        );

        let sig = from_key.sign(&msg);

        Self {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: sig.to_vec(),
            payload,
            priority_fee_per_gas,
        }
    }

    /// Sign a transaction bound to a specific chain_id (Finding F1: anti cross-chain replay).
    #[allow(clippy::too_many_arguments)]
    // GATE: signing needs full tx context; struct params would change public API.
    pub fn sign_with_chain_id(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        chain_id: u64,
    ) -> Self {
        Self::sign_with_payload_and_chain_id(
            from_key,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            Vec::new(),
            chain_id,
        )
    }

    /// Sign a transaction carrying an SVM payload and bound to a specific chain_id.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_payload_and_chain_id(
        from_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        chain_id: u64,
    ) -> Self {
        let from_pub = from_key.verifying_key().to_bytes();
        let mut msg = Self::base_signing_message(
            &from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            &payload,
            0,
        );
        Self::append_chain_id_commitment(&mut msg, chain_id);

        let sig = from_key.sign(&msg);
        let mut signature = sig.to_vec();
        signature.extend_from_slice(CHAIN_SIG_TAG);
        signature.extend_from_slice(&chain_id.to_be_bytes());

        Self {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature,
            payload,
            priority_fee_per_gas: 0,
        }
    }

    /// Sign a transaction with a DELEGATED session key instead of the master
    /// key. The master's grant rides inside `signature` as an envelope:
    /// `session_sig(64B) || b"SK1" || bincode(grant)`.
    ///
    /// `tx.from` stays the master address (the master's account is the one
    /// debited), and both the grant and the payload are committed into what
    /// the session key signs, so neither can be swapped after signing: grafting
    /// this envelope onto another sender's transaction, or grafting another
    /// grant onto this one, invalidates the signature.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_session(
        session_key: &SigningKey,
        delegation: SessionKeyAuthorization,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
    ) -> Self {
        // The grant must have been minted FOR this session key: verification
        // selects the verifying key from `delegation.session_pubkey`, so a
        // mismatch could only ever produce a transaction nobody can verify.
        debug_assert_eq!(
            session_key.verifying_key().to_bytes(),
            delegation.session_pubkey,
            "session key must match the delegation it is used with"
        );
        let from_pub = delegation.master_address;
        let mut msg = Self::base_signing_message(
            &from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            &payload,
            0,
        );
        Self::append_delegation_commitment(&mut msg, &delegation);

        let sig = session_key.sign(&msg);
        let mut signature = sig.to_vec();
        signature.extend_from_slice(SESSION_SIG_TAG);
        // Serialization of this struct cannot realistically fail (fixed-size
        // fields plus one Vec). If it somehow did, the envelope would not
        // parse and the transaction fails closed at verification.
        signature.extend_from_slice(&bincode::serialize(&delegation).unwrap_or_default());

        Self {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature,
            payload,
            priority_fee_per_gas: 0,
        }
    }

    /// The signed message WITHOUT the delegation commitment: every legacy
    /// transaction's exact signing bytes, kept byte-identical so old
    /// signatures, old hashes and the python client's layout still hold.
    ///
    /// The explicit priority bid is part of this base preimage, but only when
    /// it is non-zero: a legacy transaction (no bid) signs exactly the bytes
    /// it always signed, while a bid is BOUND to the sender's signature (a
    /// third party cannot inflate someone else's priority bid).
    #[allow(clippy::too_many_arguments)]
    // GATE: signing preimage needs full tx fields; splitting risks hash mismatch.
    fn base_signing_message(
        from: &[u8; 32],
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: &[crate::svm::OpCode],
        priority_fee_per_gas: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(115);
        msg.extend_from_slice(from);
        msg.extend_from_slice(&to);
        msg.extend_from_slice(&amount.to_be_bytes());
        msg.extend_from_slice(&gas_limit.to_be_bytes());
        msg.extend_from_slice(&nonce.to_be_bytes());
        msg.extend_from_slice(&source_shard.to_be_bytes());
        msg.extend_from_slice(&target_shard.to_be_bytes());
        Self::append_payload_commitment(&mut msg, payload);
        Self::append_priority_commitment(&mut msg, priority_fee_per_gas);
        msg
    }

    /// Commitment of the explicit priority bid, bound into BOTH the signed
    /// message and the tx hash. Nothing is appended for a bid of 0, which is
    /// what keeps every pre-bid transaction byte-identical.
    fn append_priority_commitment(msg: &mut Vec<u8>, priority_fee_per_gas: u64) {
        if priority_fee_per_gas == 0 {
            return;
        }
        msg.extend_from_slice(PRIORITY_FEE_COMMITMENT_TAG);
        msg.extend_from_slice(&priority_fee_per_gas.to_be_bytes());
    }

    /// Deterministic commitment of the payload bound into the signed message.
    fn append_payload_commitment(msg: &mut Vec<u8>, payload: &[crate::svm::OpCode]) {
        msg.extend_from_slice(b"PAYLOAD");
        match bincode::serialize(payload) {
            Ok(bytes) => {
                msg.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                msg.extend_from_slice(&bytes);
            }
            Err(_) => {
                // Unserializable payload -> bind an impossible marker so the
                // signature can never validate (fail closed).
                msg.extend_from_slice(&u32::MAX.to_be_bytes());
            }
        }
    }

    /// Parse the master's grant out of the signature envelope, if this
    /// transaction carries one. `None` for a legacy signature — and for any
    /// blob that does not parse as an exact-fit envelope, which then fails
    /// `Signature::from_slice` (wrong length), so malformed input fails closed.
    pub fn delegation(&self) -> Option<SessionKeyAuthorization> {
        let sig = self.sponsor_inner_sig();
        let tag_len = SESSION_SIG_TAG.len();
        if sig.len() <= 64 + tag_len || sig[64..64 + tag_len] != SESSION_SIG_TAG[..] {
            return None;
        }
        let grant: SessionKeyAuthorization = bincode::deserialize(&sig[64 + tag_len..]).ok()?;
        // Exact fit: the envelope is exactly `sig(64) || tag || grant`, with no
        // trailing junk — otherwise one transaction could carry two byte
        // encodings under a single hash.
        let expected = 64 + tag_len + bincode::serialized_size(&grant).ok()? as usize;
        if expected != sig.len() {
            return None;
        }
        Some(grant)
    }

    /// True when this transaction carries a session-key envelope.
    pub fn is_session_keyed(&self) -> bool {
        self.delegation().is_some()
    }

    /// Commitment of the grant, bound into BOTH the signed message and the tx
    /// hash. Empty for legacy transactions (`delegation()` is `None`), which is
    /// what keeps every pre-envelope byte string — tx bytes, tx hashes, block
    /// hashes — unchanged.
    fn delegation_commitment_bytes(delegation: &SessionKeyAuthorization) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"SESSION");
        match bincode::serialize(delegation) {
            Ok(bytes) => {
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&bytes);
            }
            Err(_) => out.extend_from_slice(&u32::MAX.to_be_bytes()),
        }
        out
    }

    fn append_delegation_commitment(msg: &mut Vec<u8>, delegation: &SessionKeyAuthorization) {
        msg.extend_from_slice(&Self::delegation_commitment_bytes(delegation));
    }

    /// Append chain_id commitment to signing message (Finding F1).
    fn append_chain_id_commitment(msg: &mut Vec<u8>, chain_id: u64) {
        msg.extend_from_slice(CHAIN_ID_COMMITMENT_TAG);
        msg.extend_from_slice(&chain_id.to_be_bytes());
    }

    /// True if transaction carries an Ed25519 chain_id envelope (CH1).
    pub fn is_chain_id_bound(&self) -> bool {
        let sig = self.sponsor_inner_sig();
        let tag_len = CHAIN_SIG_TAG.len();
        sig.len() == 64 + tag_len + 8 && sig[64..64 + tag_len] == CHAIN_SIG_TAG[..]
    }

    /// Extract chain_id from CH1 envelope if present.
    pub fn chain_id_from_envelope(&self) -> Option<u64> {
        if !self.is_chain_id_bound() {
            return None;
        }
        let offset = 64 + CHAIN_SIG_TAG.len();
        let bytes: [u8; 8] = self.sponsor_inner_sig()[offset..offset + 8]
            .try_into()
            .ok()?;
        Some(u64::from_be_bytes(bytes))
    }

    /// True when this transaction carries a Phase-2 EVM (secp256k1)
    /// settlement envelope (`b"EV1"` prefix). Never 64 bytes long, so every
    /// pre-EV1 verifier fails it closed at `Signature::from_slice`.
    pub fn is_evm(&self) -> bool {
        let sig = self.sponsor_inner_sig();
        sig.len() > EVM_SIG_TAG.len() && sig[..EVM_SIG_TAG.len()] == EVM_SIG_TAG[..]
    }

    /// Raw canonical EVM bytes carried by the envelope (`None` for non-EVM
    /// transactions).
    pub fn evm_raw(&self) -> Option<&[u8]> {
        if !self.is_evm() {
            return None;
        }
        Some(&self.sponsor_inner_sig()[EVM_SIG_TAG.len()..])
    }

    /// Decode the EVM envelope into its separate-enum view
    /// ([`crate::evm_adapter::DecodedTransaction`], legacy or EIP-1559).
    /// Fail-closed: oversized envelopes and any RLP parse error yield `None`.
    pub fn evm_decoded(&self) -> Option<crate::evm_adapter::DecodedTransaction> {
        let raw = self.evm_raw()?;
        if raw.is_empty() || raw.len() > MAX_EVM_ENVELOPE_BYTES {
            return None;
        }
        crate::evm_adapter::parse_raw_transaction(raw).ok()
    }

    /// Assemble a Phase-2 EVM settlement transaction. `raw_evm_tx` must be
    /// the canonical EVM wire bytes; every consensus check re-derives from
    /// them, so any mismatch with the mapped fields fails closed in
    /// [`Self::verify_evm_signature`]. The SVM payload stays empty: Phase-2
    /// settles value movement, calldata is not executed.
    #[allow(clippy::too_many_arguments)]
    // GATE: EVM constructor mirrors full tx fields; struct params would change public API.
    pub fn new_evm(
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        raw_evm_tx: Vec<u8>,
    ) -> Self {
        let mut signature = Vec::with_capacity(EVM_SIG_TAG.len() + raw_evm_tx.len());
        signature.extend_from_slice(EVM_SIG_TAG);
        signature.extend_from_slice(&raw_evm_tx);
        Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature,
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        }
    }

    /// Phase-2 EVM (secp256k1) envelope verification.
    ///
    /// Re-derives EVERYTHING from the canonical raw bytes in the envelope, so
    /// block data alone decides — no RPC trust, no wall clock, no state:
    ///
    /// * the raw parses as legacy-EIP-155 or EIP-1559 type-2 AND re-encodes
    ///   byte-exact (non-canonical RLP / trailing junk fails closed);
    /// * [`crate::evm_adapter::DecodedTransaction::verify_signature`] passes —
    ///   strict `chain_id == 5757` (EIP-155 replay protection required, never
    ///   `v = 27/28`), EIP-2 low-s, secp256k1 ecrecover;
    /// * contract creation (`to == None`) is rejected — Phase-2 settles value
    ///   transfers and there is no Stell recipient to invent for a deployment;
    /// * `tx.from` equals `evm_to_stell_address(recovered)`: the mapping the
    ///   mempool nonce/balance checks and the engine apply path then use;
    /// * `tx.nonce` / `gas_limit` / `amount` / `to` equal the mapped EVM
    ///   fields (`amount = wei_to_nano(value)`, sub-nano wei truncated
    ///   deterministically; `gas_limit` is carried verbatim as the nano fee
    ///   so consensus verification stays a pure function of the tx bytes).
    pub fn verify_evm_signature(&self) -> bool {
        let Some(raw) = self.evm_raw() else {
            return false;
        };
        if raw.is_empty() || raw.len() > MAX_EVM_ENVELOPE_BYTES {
            return false;
        }
        let Ok(decoded) = crate::evm_adapter::parse_raw_transaction(raw) else {
            return false;
        };
        // Exact-fit: the envelope commits to canonical bytes only.
        if decoded.encode() != raw {
            return false;
        }
        // Strict chain_id == 5757 + low-s + ecrecover (enforced inside for
        // both the legacy and the EIP-1559 variant).
        let Ok(evm_from) = decoded.verify_signature() else {
            return false;
        };
        // No recipient to map for a deployment — fail closed, don't invent one.
        let Some(evm_to) = decoded.to() else {
            return false;
        };
        if crate::evm_adapter::evm_to_stell_address(&evm_from) != self.from {
            return false;
        }
        if crate::evm_adapter::evm_to_stell_address(&evm_to) != self.to {
            return false;
        }
        if decoded.nonce() != self.nonce {
            return false;
        }
        if decoded.gas_limit() != self.gas_limit {
            return false;
        }
        if crate::evm_adapter::wei_to_nano(decoded.value()) != self.amount {
            return false;
        }
        // EVM-settled transactions carry no SVM payload (no mixed execution
        // model under one signature).
        if !self.payload.is_empty() {
            return false;
        }
        true
    }

    /// Returns the chain_id bound to this transaction, if any.
    ///
    /// - For session key transactions: returns `delegation.chain_id`.
    /// - For chain-bound Ed25519 transactions: returns envelope `chain_id`.
    /// - For PQ transactions with chain binding: returns `envelope.chain_id`.
    /// - For EVM (secp256k1) settlement transactions: returns `EVM_CHAIN_ID`.
    /// - For legacy transactions: returns `None`.
    pub fn chain_id(&self) -> Option<u64> {
        // A sponsor grant carries the replay-protection domain for sponsored
        // transactions (the grant is committed into both signatures).
        if let Some(auth) = self.sponsor_auth() {
            return Some(auth.chain_id);
        }
        if let Some(d) = self.delegation() {
            Some(d.chain_id)
        } else if let Some(cid) = self.chain_id_from_envelope() {
            Some(cid)
        } else if let Some(env) = self.pq_envelope() {
            env.chain_id
        } else if self.is_evm() {
            Some(EVM_CHAIN_ID)
        } else {
            None
        }
    }

    pub fn compute_tx_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let mut payload_buf = Vec::new();
        self.hash_into(&mut hasher, &mut payload_buf);
        hasher.finalize().into()
    }

    /// Feed this transaction's hash preimage into `hasher`, reusing
    /// `payload_buf` as scratch for the bincode payload encoding.
    ///
    /// Split out of [`Self::compute_tx_hash`] so a batch can reuse ONE
    /// hasher (via `finalize_reset`) and ONE scratch buffer across every
    /// transaction instead of allocating both per transaction. The update
    /// sequence is identical, so the hashes are byte-identical.
    fn hash_into(&self, hasher: &mut Sha256, payload_buf: &mut Vec<u8>) {
        use sha2::Digest;
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
        // Conditional commitment: the explicit priority bid is mixed in ONLY
        // when it is non-zero, so a legacy transaction (no bid) keeps its
        // byte-identical hash — and every block hash built from it — while a
        // bid is bound into the transaction's identity (two transactions that
        // differ ONLY in their bid are different transactions).
        if self.priority_fee_per_gas != 0 {
            hasher.update(PRIORITY_FEE_COMMITMENT_TAG);
            hasher.update(self.priority_fee_per_gas.to_be_bytes());
        }
        // Conditional commitment: nothing is appended for a legacy signature,
        // so legacy tx hashes (and every block hash built from them) are
        // byte-identical to before session keys existed.
        if let Some(d) = self.delegation() {
            hasher.update(Self::delegation_commitment_bytes(&d));
        }
        if self.is_chain_id_bound() {
            hasher.update(CHAIN_ID_COMMITMENT_TAG);
            if let Some(cid) = self.chain_id_from_envelope() {
                hasher.update(cid.to_be_bytes());
            }
        }
        // Conditional commitment: nothing is appended for a legacy
        // transaction, so legacy tx hashes (and every block hash built from
        // them) are byte-identical to before sponsorship existed.
        if let Some(auth) = self.sponsor_auth() {
            hasher.update(Self::sponsor_commitment_bytes(&auth));
        }
        // EVM settlement commits the full envelope (tag + canonical raw), so
        // an EVM transaction can never share a hash with a legacy transaction
        // over identical mapped fields (legacy hashes ignore `signature`).
        if self.is_evm() {
            hasher.update(b"EVM_TX");
            hasher.update(&self.signature);
        }
        if self.is_pq() {
            hasher.update(b"PQ_ENV");
            hasher.update(&self.signature);
        }
    }

    /// Hash every transaction in one pass, reusing a single hasher (reset per
    /// transaction) and a single pre-sized scratch buffer.
    ///
    /// The output is byte-identical to mapping [`Self::compute_tx_hash`]
    /// over the slice: the per-transaction update sequence is shared code
    /// (`hash_into`), and `finalize_reset` restarts the hasher to the
    /// identical initial state `Sha256::new()` would give. `out` is
    /// pre-sized to `txs.len()` so the batch allocates once.
    pub fn compute_tx_hashes_batched(txs: &[Transaction]) -> Vec<[u8; 32]> {
        let mut batch = TxHashBatch::new();
        let mut out = Vec::with_capacity(txs.len());
        for tx in txs {
            out.push(batch.hash_one(tx));
        }
        out
    }

    /// Reusable batch-hashing state for callers that hash inline (a single
    /// pass that also serializes): one hasher + one scratch buffer instead
    /// of one pair per transaction. Output is byte-identical to
    /// [`Self::compute_tx_hash`].
    pub fn batch_hasher() -> TxHashBatch {
        TxHashBatch::new()
    }

    /// True if the transaction signature begins with the PQ1 framing marker.
    pub fn is_pq(&self) -> bool {
        self.sponsor_inner_sig().starts_with(PQ_ENVELOPE_MAGIC)
    }

    /// Decode the post-quantum signature envelope if present, ensuring exact fit (no trailing bytes).
    pub fn pq_envelope(&self) -> Option<PqSignatureEnvelope> {
        if !self.is_pq() {
            return None;
        }
        let inner = self.sponsor_inner_sig();
        let env = PqSignatureEnvelope::decode(inner).ok()?;
        if env.encode().len() != inner.len() && env.legacy_encode_len() != inner.len() {
            return None;
        }
        Some(env)
    }

    /// True if this transaction carries a raw public key in a PQ envelope (activation tx).
    pub fn is_pq_activation(&self) -> bool {
        self.pq_envelope()
            .map(|e| !e.is_implicit && e.pubkey.is_some())
            .unwrap_or(false)
    }

    /// True if this transaction is an implicit PQ transaction (public key omitted from wire).
    pub fn is_pq_implicit(&self) -> bool {
        self.pq_envelope()
            .map(|e| e.is_implicit || e.pubkey.is_none())
            .unwrap_or(false)
    }

    /// Returns a reference to the global in-memory implicit key registry.
    pub fn global_implicit_registry() -> &'static StatefulImplicitKeyRegistry {
        global_implicit_key_registry()
    }

    /// Create a post-quantum transaction with an explicit public key attached (activation tx).
    #[allow(clippy::too_many_arguments)]
    // GATE: PQ constructor needs full tx plus key material; splitting changes public API.
    pub fn new_pq_explicit(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        salt: &[u8; 16],
    ) -> Self {
        let from = derive_pq_address(scheme, &pubkey, salt);
        let envelope =
            PqSignatureEnvelope::new_explicit_with_salt(scheme, pubkey, signature_bytes, *salt);
        Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: envelope.encode(),
            payload,
            priority_fee_per_gas: 0,
        }
    }

    /// Create a post-quantum transaction with an implicit public key (pubkey omitted from wire).
    #[allow(clippy::too_many_arguments)]
    // GATE: PQ constructor needs full tx plus key material; splitting changes public API.
    pub fn new_pq_implicit(
        from: [u8; 32],
        scheme: PqScheme,
        signature_bytes: Vec<u8>,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
    ) -> Self {
        let envelope = PqSignatureEnvelope::new_implicit(scheme, signature_bytes);
        Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: envelope.encode(),
            payload,
            priority_fee_per_gas: 0,
        }
    }

    /// Create a post-quantum transaction with an explicit public key and chain_id attached.
    #[allow(clippy::too_many_arguments)]
    pub fn new_pq_explicit_with_chain(
        scheme: PqScheme,
        pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        salt: &[u8; 16],
        chain_id: u64,
    ) -> Self {
        let from = derive_pq_address(scheme, &pubkey, salt);
        let envelope = PqSignatureEnvelope::new_explicit_with_chain(
            scheme,
            pubkey,
            signature_bytes,
            *salt,
            chain_id,
        );
        Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: envelope.encode(),
            payload,
            priority_fee_per_gas: 0,
        }
    }

    /// Create a post-quantum transaction with an implicit public key and chain_id attached.
    #[allow(clippy::too_many_arguments)]
    pub fn new_pq_implicit_with_chain(
        from: [u8; 32],
        scheme: PqScheme,
        signature_bytes: Vec<u8>,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        chain_id: u64,
    ) -> Self {
        let envelope =
            PqSignatureEnvelope::new_implicit_with_chain(scheme, signature_bytes, chain_id);
        Self {
            from,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: envelope.encode(),
            payload,
            priority_fee_per_gas: 0,
        }
    }

    /// Create a REAL Falcon-512 signature for a given message and pubkey.
    ///
    /// AUDIT W6.1 (the test backdoor is GONE): this helper used to be able to
    /// fall back to the BLAKE3 "check digest" pseudo-signature that only the
    /// `#[cfg(test)]` branch of `verify_falcon_signature_or_test` accepted —
    /// a 1/256 forge probability that also made the tamper-detection tests
    /// flaky. It now ALWAYS produces an authentic FIPS 206 signature from the
    /// seeded keypair, and it CHECKS that the public key handed in really is
    /// the public key of that keypair (otherwise the signature would not
    /// verify and the test would fail for the wrong reason).
    #[cfg(any(test, debug_assertions))]
    pub fn create_falcon512_test_signature(pubkey: &[u8], message: &[u8], seed: u8) -> Vec<u8> {
        let kp = crate::post_quantum::FalconKeypair::generate_from_seed(seed);
        assert_eq!(
            kp.public_key(),
            pubkey,
            "create_falcon512_test_signature: the public key must be the one of the \
             seeded keypair (sample_falcon512_pubkey(seed))"
        );
        let sig = kp.sign(message);
        assert!(
            crate::post_quantum::verify_pq_signature(
                crate::post_quantum::PqScheme::Falcon512,
                pubkey,
                message,
                &sig,
            ),
            "create_falcon512_test_signature: the produced signature must verify"
        );
        sig
    }

    /// Generate a sample Falcon-512 public key with canonical header byte.
    #[cfg(any(test, debug_assertions))]
    pub fn sample_falcon512_pubkey(seed: u8) -> Vec<u8> {
        crate::post_quantum::FalconKeypair::generate_from_seed(seed)
            .public_key
            .clone()
    }

    /// Envelope-aware signature verification.
    ///
    /// * legacy  : `tx.from` is the verifying key over `signing_message()`.
    /// * envelope: the delegation must be minted FOR this sender
    ///   (`master_address == tx.from` — the graft-attack guard), the master's
    ///   grant must verify, and the SESSION key must sign `signing_message()`
    ///   (which commits to the grant).
    /// * post-quantum (PQ1 envelope):
    ///   - If explicit pubkey in envelope: verify signature using provided pubkey,
    ///     and verify `derive_pq_address(scheme, pubkey, salt) == self.from`.
    ///     The key is registered into the implicit key registry.
    ///   - If implicit (pubkey omitted from wire): verify signature against the
    ///     address's implicit key registry (`StatefulImplicitKeyRegistry`).
    ///
    /// Malformed input (including a bare 64-byte signature followed by junk)
    /// fails closed: a pre-envelope node rejects the envelope at
    /// `Signature::from_slice`, and so does the legacy branch here.
    pub fn verify_signature(&self) -> bool {
        self.verify_signature_with_registry(Self::global_implicit_registry())
    }

    /// Verify signature against a caller-supplied implicit key registry with default salt.
    pub fn verify_signature_with_registry(&self, registry: &StatefulImplicitKeyRegistry) -> bool {
        self.verify_signature_with_registry_and_salt(registry, &DEFAULT_SALT)
    }

    /// Verify signature against a caller-supplied implicit key registry and salt.
    ///
    /// Malformed sponsor suffixes fail closed; a well-formed sponsor envelope
    /// additionally requires the v1 composition (plain legacy ed25519 inner)
    /// AND a valid sponsor signature — BOTH signatures must verify.
    pub fn verify_signature_with_registry_and_salt(
        &self,
        registry: &StatefulImplicitKeyRegistry,
        salt: &[u8; 16],
    ) -> bool {
        if self.sponsor_malformed() {
            return false;
        }
        if !self.verify_inner_with_registry(registry, salt) {
            return false;
        }
        match self.sponsor_auth() {
            None => true,
            Some(auth) => {
                // v1 composition: the sponsor rides ONLY on a plain legacy
                // ed25519 signature, which is exactly 64 bytes. Session,
                // chain-bound, PQ and EVM inners are longer and refuse here.
                if self.sponsor_inner_sig().len() != 64 {
                    return false;
                }
                self.verify_sponsor_sig(&auth)
            }
        }
    }

    /// The pre-sponsor signature check, run on the sponsor-inner blob (the
    /// full signature for legacy transactions). All envelope helpers it uses
    /// are sponsor-strip-aware, so this is byte-identical to the historical
    /// check on legacy inputs.
    fn verify_inner_with_registry(
        &self,
        registry: &StatefulImplicitKeyRegistry,
        _salt: &[u8; 16],
    ) -> bool {
        // Phase-2 EVM settlement: the envelope carries its own secp256k1
        // authentication (re-derived from the canonical raw on every check),
        // independent of ed25519 keys, PQ key registries and delegations.
        if self.is_evm() {
            if crate::post_quantum::is_pure_pq_enforced() {
                return false;
            }
            return self.verify_evm_signature();
        }
        if self.is_pq() {
            let Some(env) = self.pq_envelope() else {
                return false;
            };
            if crate::post_quantum::is_pure_pq_enforced() && !env.scheme.is_post_quantum() {
                return false;
            }
            if env.signature_bytes.len() != env.scheme.signature_size() {
                return false;
            }
            if !env.is_implicit {
                let Some(ref pk) = env.pubkey else {
                    return false;
                };
                if pk.len() != env.scheme.pubkey_size() {
                    return false;
                }
                let derived = derive_pq_address(env.scheme, pk, &env.salt);
                if derived != self.from {
                    return false;
                }
                let valid = if env.scheme == PqScheme::Falcon512 {
                    crate::consensus::verify_falcon_signature(
                        pk,
                        &self.signing_message(),
                        &env.signature_bytes,
                    )
                } else {
                    verify_pq_signature(
                        env.scheme,
                        pk,
                        &self.signing_message(),
                        &env.signature_bytes,
                    )
                };
                if !valid {
                    return false;
                }
                let _ = registry.register(self.from, env.scheme, pk, &env.salt);
                true
            } else {
                if env.pubkey.is_some() {
                    return false;
                }
                let Some((scheme, pk)) = registry.lookup(&self.from) else {
                    return false;
                };
                if scheme != env.scheme {
                    return false;
                }
                if scheme == PqScheme::Falcon512 {
                    crate::consensus::verify_falcon_signature(
                        &pk,
                        &self.signing_message(),
                        &env.signature_bytes,
                    )
                } else {
                    verify_pq_signature(scheme, &pk, &self.signing_message(), &env.signature_bytes)
                }
            }
        } else {
            if crate::post_quantum::is_pure_pq_enforced() {
                return false;
            }
            match self.delegation() {
                None => {
                    // PAYMASTER: verify the sponsor-INNER blob (the full
                    // signature for legacy transactions). Verifying the raw
                    // `signature` field would feed the trailing `SP1` suffix
                    // into `Signature::from_slice` and fail CLOSED on every
                    // sponsored transaction — including valid ones.
                    let inner_sig = self.sponsor_inner_sig();
                    let sig_slice = if self.is_chain_id_bound() && inner_sig.len() >= 64 {
                        &inner_sig[..64]
                    } else {
                        inner_sig
                    };
                    if let (Ok(vk), Ok(sig)) = (
                        VerifyingKey::from_bytes(&self.from),
                        Signature::from_slice(sig_slice),
                    ) {
                        if vk.verify(&self.signing_message(), &sig).is_ok() {
                            return true;
                        }
                    }
                    crate::crypto_privacy::verify_stealth_signature(
                        &self.from,
                        &self.signing_message(),
                        sig_slice,
                    )
                }
                Some(d) => {
                    if d.master_address != self.from {
                        return false;
                    }
                    if !d.verify_signature() {
                        return false;
                    }
                    let Ok(vk) = VerifyingKey::from_bytes(&d.session_pubkey) else {
                        return false;
                    };
                    let Ok(sig) = Signature::from_slice(&self.signature[..64]) else {
                        return false;
                    };
                    vk.verify(&self.signing_message(), &sig).is_ok()
                }
            }
        }
    }

    /// The exact bytes that the sender signs (used for both single and batch
    /// verify). For an envelope transaction this INCLUDES the grant or chain_id
    /// commitment, so the grant / chain_id cannot be swapped after signing.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Self::base_signing_message(
            &self.from,
            self.to,
            self.amount,
            self.gas_limit,
            self.nonce,
            self.source_shard,
            self.target_shard,
            &self.payload,
            self.priority_fee_per_gas,
        );
        // EVM-settled transactions are never verified against this preimage
        // (their envelope IS the secp256k1-signed raw); return the base
        // message deterministically with no grant/chain commitment appended.
        if self.is_evm() {
            return msg;
        }
        if let Some(d) = self.delegation() {
            Self::append_delegation_commitment(&mut msg, &d);
        } else if self.sponsor_auth().is_none() {
            // Sponsored transactions bind their chain through the sponsor
            // commitment below (single commitment, no ambiguity); the
            // chain-id branch stays legacy-only.
            if let Some(cid) = self.chain_id() {
                Self::append_chain_id_commitment(&mut msg, cid);
            }
        }
        // The sponsor grant is bound into the USER's signed message (and the
        // tx hash), so it cannot be swapped after signing. Nothing is
        // appended for legacy transactions.
        if let Some(auth) = self.sponsor_auth() {
            Self::append_sponsor_commitment(&mut msg, &auth);
        }
        msg
    }

    /// Construct signing message for a specific chain_id (before attaching an envelope).
    pub fn signing_message_for_chain(&self, chain_id: u64) -> Vec<u8> {
        let mut msg = Self::base_signing_message(
            &self.from,
            self.to,
            self.amount,
            self.gas_limit,
            self.nonce,
            self.source_shard,
            self.target_shard,
            &self.payload,
            self.priority_fee_per_gas,
        );
        if let Some(d) = self.delegation() {
            Self::append_delegation_commitment(&mut msg, &d);
        } else {
            Self::append_chain_id_commitment(&mut msg, chain_id);
        }
        msg
    }

    /// Verify signature and enforce chain_id binding (Finding F1: anti cross-chain replay).
    /// If `require_chain_id` is true, legacy transactions without chain_id are rejected.
    pub fn verify_signature_for_chain(
        &self,
        expected_chain_id: u64,
        require_chain_id: bool,
    ) -> bool {
        if require_chain_id && self.chain_id().is_none() {
            return false;
        }
        if let Some(cid) = self.chain_id() {
            if cid != expected_chain_id {
                return false;
            }
        }
        self.verify_signature()
    }

    /// The session scope THIS transaction's payload requires of a grant.
    ///
    /// One definition, used by every path that asks the question, so propose,
    /// mempool admission, block admission and the execution-time gate can
    /// never disagree about which capability a transaction needs:
    ///
    ///  * empty payload -> [`crate::zkml::SCOPE_TRANSFER`];
    ///  * a payload carrying an actor-mailbox send ->
    ///    `SCOPE_SVM_PAYLOAD | SCOPE_ACTOR_SEND` - BOTH bits, because the
    ///    actor send is an extra capability layered on top of "may run a
    ///    payload", never a substitute for it (see `SCOPE_ACTOR_SEND`);
    ///  * any other payload -> [`crate::zkml::SCOPE_SVM_PAYLOAD`].
    ///
    /// Deterministic from the payload bytes alone (no clock, no state), which
    /// is what lets it be mirrored at propose time against the block clock.
    pub fn required_scope(&self) -> u64 {
        if self.payload.is_empty() {
            crate::zkml::SCOPE_TRANSFER
        } else if self
            .payload
            .iter()
            .any(|op| matches!(op, crate::svm::OpCode::SysCallActorSend { .. }))
        {
            crate::zkml::SCOPE_SVM_PAYLOAD | crate::zkml::SCOPE_ACTOR_SEND
        } else {
            crate::zkml::SCOPE_SVM_PAYLOAD
        }
    }

    /// Delegation policy check for this transaction at a given time.
    ///
    /// `now` must be a DETERMINISTIC clock — the block timestamp at propose
    /// selection and at execution, the admission context's time at mempool
    /// entry. Never the local wall clock inside consensus execution.
    ///
    /// Legacy transactions pass unconditionally. Session-keyed transactions
    /// need a grant minted for this sender, not expired, in scope for this
    /// transaction kind, within the per-transaction value cap, and with enough
    /// remaining gas budget for the declared `gas_limit`.
    ///
    /// The signature itself is NOT re-checked here (that is
    /// `verify_signature`); this is the grant's POLICY.
    pub fn check_session_policy(&self, now: u64) -> Result<(), SessionPolicyError> {
        let Some(d) = self.delegation() else {
            // Legacy signature. Anything that claims envelope shape but did
            // not parse is rejected by `verify_signature` instead.
            return Ok(());
        };
        if crate::post_quantum::is_pure_pq_enforced()
            && (!d.master_scheme.is_post_quantum() || !d.session_scheme.is_post_quantum())
        {
            return Err(SessionPolicyError::BadGrant);
        }
        if d.master_address != self.from {
            return Err(SessionPolicyError::BadGrant);
        }
        if !d.verify_signature() {
            return Err(SessionPolicyError::BadGrant);
        }
        if now > d.valid_until {
            return Err(SessionPolicyError::Expired);
        }
        let required_scope = self.required_scope();
        if !d.grants_scope(required_scope) {
            return Err(SessionPolicyError::OutOfScope);
        }
        if self.amount > d.max_value_per_tx {
            return Err(SessionPolicyError::OutOfScope);
        }
        if self.gas_limit > d.remaining_gas() {
            return Err(SessionPolicyError::BudgetExhausted);
        }
        Ok(())
    }

    /// PAYMASTER (sponsored transactions): envelope parsing, signing, policy.
    ///
    /// The envelope is a TRAILING suffix on `signature`:
    /// `inner ++ bincode(SponsorAuthorization) ++ len_be32 ++ b"SP1"`.
    /// The tag sits at the very end (like the priority envelope), so parsing
    /// is unambiguous and composes with every inner shape: strip the sponsor
    /// suffix FIRST, then run the legacy parsers on the inner blob.
    ///
    /// INVARIANTS (all fail closed):
    /// * malformed suffix (bad length, undecodable, over-bound auth) makes
    ///   the WHOLE transaction invalid — never silently legacy;
    /// * v1 sponsors ONLY a plain legacy ed25519 inner (`inner.len() == 64`);
    ///   session/PQ/EVM/chain-bound inners with a sponsor envelope refuse;
    /// * the user's message commits to the full auth (incl. `sponsor_sig`);
    ///   the sponsor's message commits to the tx core + caps. Neither side
    ///   can be swapped or grafted.
    ///   Split the trailing sponsor suffix off a signature blob.
    ///
    /// Returns `(inner_len, auth, malformed)`: `inner_len` is the byte length
    /// of the inner signature blob, `auth` is the parsed grant (when the
    /// suffix is present AND well-formed), `malformed` is true when the tag
    /// is present but the suffix does not parse (fail closed upstream).
    /// A blob without the trailing tag returns `(blob.len(), None, false)` —
    /// the legacy path, byte-identical to before.
    pub fn split_sponsor_envelope(blob: &[u8]) -> (usize, Option<SponsorAuthorization>, bool) {
        let tag_len = SPONSOR_SIG_TAG.len();
        // tag + u32 length + at least 1 auth byte.
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
        // A legit inner signature is at least a 64-byte ed25519 signature.
        if inner_len < 64 {
            return (blob.len(), None, true);
        }
        let auth_bytes = &blob[inner_len..len_off];
        match bincode::deserialize::<SponsorAuthorization>(auth_bytes) {
            Ok(auth) => {
                // DoS bounds, enforced at parse (fail closed, never truncate).
                if auth.sponsor_sig.len() != 64 || auth.allowed_targets.len() > SPONSOR_MAX_TARGETS
                {
                    return (blob.len(), None, true);
                }
                (inner_len, Some(auth), false)
            }
            Err(_) => (blob.len(), None, true),
        }
    }

    /// The inner signature blob (the full blob when no well-formed sponsor
    /// suffix is present).
    pub fn sponsor_inner_sig(&self) -> &[u8] {
        let (inner_len, _, _) = Self::split_sponsor_envelope(&self.signature);
        &self.signature[..inner_len]
    }

    /// True when the trailing sponsor tag is present, regardless of whether
    /// the suffix parses (use [`Self::sponsor_malformed`] to distinguish).
    pub fn has_sponsor_envelope(&self) -> bool {
        let b = &self.signature;
        b.len() > SPONSOR_SIG_TAG.len() + 4
            && b[b.len() - SPONSOR_SIG_TAG.len()..] == SPONSOR_SIG_TAG[..]
    }

    /// True when the sponsor suffix is present but does not parse: the
    /// transaction is invalid and must be refused (never silently legacy).
    pub fn sponsor_malformed(&self) -> bool {
        Self::split_sponsor_envelope(&self.signature).2
    }

    /// The parsed sponsor grant, if a well-formed sponsor envelope is present.
    /// `None` on the legacy path — and on a malformed suffix (check
    /// [`Self::sponsor_malformed`] to tell the two apart).
    pub fn sponsor_auth(&self) -> Option<SponsorAuthorization> {
        Self::split_sponsor_envelope(&self.signature).1
    }

    /// True when this transaction carries a well-formed sponsor envelope
    /// (including a self-sponsored one, which fee-routes as plain).
    pub fn is_sponsored(&self) -> bool {
        self.sponsor_auth().is_some()
    }

    /// The EFFECTIVE sponsor grant: a well-formed envelope whose sponsor is a
    /// THIRD PARTY (`sponsor != from`).
    ///
    /// `None` on the legacy path AND on the self-sponsored path
    /// (`sponsor == from`, which fee-routes as plain per the paymaster
    /// contract: the user pays their own fee, the envelope is signature-only
    /// and changes no balance routing). Every fee-routing decision —
    /// admission coverage, execution debit, proposer accounting — branches on
    /// THIS predicate, so `sponsor == from` can never divert a fee.
    pub fn sponsored_grant(&self) -> Option<SponsorAuthorization> {
        let auth = self.sponsor_auth()?;
        if auth.sponsor == self.from {
            None
        } else {
            Some(auth)
        }
    }

    /// The account debited the fee: the sponsor, or the user when there is no
    /// grant or the grant names the user itself (`sponsor == from` is the
    /// plain path per the paymaster contract).
    pub fn effective_sponsor(&self) -> Option<[u8; 32]> {
        self.sponsor_auth().and_then(|a| {
            if a.sponsor == self.from {
                None
            } else {
                Some(a.sponsor)
            }
        })
    }

    /// The account that pays the fee for this transaction (sponsor or user).
    pub fn fee_payer(&self) -> [u8; 32] {
        self.effective_sponsor().unwrap_or(self.from)
    }

    /// Encode one sponsor suffix (`bincode(auth) ++ len_be32 ++ "SP1"`).
    fn encode_sponsor_suffix(auth: &SponsorAuthorization) -> Vec<u8> {
        // Serialization of this struct cannot realistically fail (fixed-size
        // fields plus bounded vecs). If it somehow did, the envelope would
        // not parse and the transaction fails closed at verification.
        let body = bincode::serialize(auth).unwrap_or_default();
        let mut out = Vec::with_capacity(body.len() + 7);
        out.extend_from_slice(&body);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(SPONSOR_SIG_TAG);
        out
    }

    /// Commitment of the sponsor grant, bound into BOTH the user's signed
    /// message and the tx hash. Empty for legacy transactions, which is what
    /// keeps every pre-sponsor byte string unchanged.
    fn sponsor_commitment_bytes(auth: &SponsorAuthorization) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SPONSOR_COMMITMENT_TAG);
        match bincode::serialize(auth) {
            Ok(bytes) => {
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&bytes);
            }
            Err(_) => out.extend_from_slice(&u32::MAX.to_be_bytes()),
        }
        out
    }

    fn append_sponsor_commitment(msg: &mut Vec<u8>, auth: &SponsorAuthorization) {
        msg.extend_from_slice(&Self::sponsor_commitment_bytes(auth));
    }

    /// The exact bytes the SPONSOR signs: domain tag + sponsor + the full tx
    /// core (so the grant is bound to THIS action) + the caps (so the grant
    /// cannot be inflated after signing). The user's message separately
    /// commits to the full auth, so the grant cannot be re-targeted either.
    pub fn sponsor_message(&self, auth: &SponsorAuthorization) -> Vec<u8> {
        let mut msg = Vec::with_capacity(256);
        msg.extend_from_slice(SPONSOR_FEE_DOMAIN);
        msg.extend_from_slice(&auth.sponsor);
        msg.extend_from_slice(&self.from);
        msg.extend_from_slice(&self.to);
        msg.extend_from_slice(&self.amount.to_be_bytes());
        msg.extend_from_slice(&self.gas_limit.to_be_bytes());
        msg.extend_from_slice(&self.nonce.to_be_bytes());
        msg.extend_from_slice(&self.source_shard.to_be_bytes());
        msg.extend_from_slice(&self.target_shard.to_be_bytes());
        Self::append_payload_commitment(&mut msg, &self.payload);
        msg.extend_from_slice(&self.priority_fee_per_gas.to_be_bytes());
        msg.extend_from_slice(&auth.max_fee_per_tx.to_be_bytes());
        msg.extend_from_slice(&auth.valid_until.to_be_bytes());
        msg.extend_from_slice(b"ALLOWLIST");
        msg.extend_from_slice(&(auth.allowed_targets.len() as u32).to_be_bytes());
        for t in &auth.allowed_targets {
            msg.extend_from_slice(t);
        }
        msg.extend_from_slice(&auth.chain_id.to_be_bytes());
        msg
    }

    /// Verify ONLY the sponsor's signature over [`Self::sponsor_message`].
    /// Fail-closed: wrong length, unparsable key, or a bad signature refuse.
    /// (The user's side is verified separately; BOTH must pass.)
    pub fn verify_sponsor_sig(&self, auth: &SponsorAuthorization) -> bool {
        if auth.sponsor_sig.len() != 64 {
            return false;
        }
        let Ok(vk) = VerifyingKey::from_bytes(&auth.sponsor) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&auth.sponsor_sig) else {
            return false;
        };
        vk.verify(&self.sponsor_message(auth), &sig).is_ok()
    }

    /// Stateless sponsor policy for this transaction at time `now`.
    ///
    /// `fee_to_charge` is the fee execution will actually debit
    /// (`max(gas_limit, floor) + surcharge`); the per-tx cap is checked
    /// against THAT number, not the declared limit, so a below-floor
    /// declaration cannot smuggle an over-cap fee past the sponsor.
    ///
    /// `now` must be a DETERMINISTIC clock — the admission context's time at
    /// mempool entry, the block timestamp at propose/apply. Legacy (and
    /// self-sponsored) transactions pass unconditionally.
    pub fn check_sponsor_policy(
        &self,
        now: u64,
        fee_to_charge: u64,
    ) -> Result<(), SponsorPolicyError> {
        let Some(auth) = self.sponsor_auth() else {
            return Ok(());
        };
        // Self-sponsored: fee-routing is plain, the user pays their own fee.
        if auth.sponsor == self.from {
            return Ok(());
        }
        // v1 composition (mirrors the verify gate): a plain legacy ed25519
        // inner is exactly 64 bytes; anything else refuses.
        if self.sponsor_inner_sig().len() != 64 {
            return Err(SponsorPolicyError::BadGrant);
        }
        if now > auth.valid_until {
            return Err(SponsorPolicyError::Expired);
        }
        if !auth.allowed_targets.is_empty() && !auth.allowed_targets.contains(&self.to) {
            return Err(SponsorPolicyError::OutOfScope);
        }
        if fee_to_charge > auth.max_fee_per_tx {
            return Err(SponsorPolicyError::CapExceeded);
        }
        Ok(())
    }

    /// Sign a transaction whose FEE is paid by a sponsor (gasless path).
    ///
    /// * `user_key` signs the action (and binds the sponsor grant: the grant
    ///   cannot be swapped after signing);
    /// * `sponsor_key` signs the fee authorization for THIS exact transaction
    ///   with THESE caps (it cannot be grafted onto another transaction).
    ///
    /// `allowed_targets` longer than [`SPONSOR_MAX_TARGETS`] is truncated
    /// (narrowing = the fail-closed direction) with a debug assertion for
    /// wallet developers.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_sponsor(
        user_key: &SigningKey,
        sponsor_key: &SigningKey,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: ShardId,
        target_shard: ShardId,
        payload: Vec<crate::svm::OpCode>,
        priority_fee_per_gas: u64,
        max_fee_per_tx: u64,
        valid_until: u64,
        allowed_targets: Vec<[u8; 32]>,
        chain_id: u64,
    ) -> Self {
        let from_pub = user_key.verifying_key().to_bytes();
        let sponsor_pub = sponsor_key.verifying_key().to_bytes();
        debug_assert!(
            allowed_targets.len() <= SPONSOR_MAX_TARGETS,
            "sponsor allowlist truncated to SPONSOR_MAX_TARGETS"
        );
        let mut targets = allowed_targets;
        targets.truncate(SPONSOR_MAX_TARGETS);
        let mut auth = SponsorAuthorization {
            sponsor: sponsor_pub,
            max_fee_per_tx,
            valid_until,
            allowed_targets: targets,
            chain_id,
            sponsor_sig: Vec::new(),
        };
        // The sponsor signs FIRST (the user's message commits to the full
        // auth including this signature, fixing the signing order).
        let provisional = Transaction {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: Vec::new(),
            payload: payload.clone(),
            priority_fee_per_gas,
        };
        let sponsor_msg = provisional.sponsor_message(&auth);
        auth.sponsor_sig = sponsor_key.sign(&sponsor_msg).to_vec();
        // The user signs the action + the grant binding.
        let mut msg = Self::base_signing_message(
            &from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            &payload,
            priority_fee_per_gas,
        );
        Self::append_sponsor_commitment(&mut msg, &auth);
        let sig = user_key.sign(&msg);
        // The in-memory `signature` holds the raw 64-byte user signature
        // plus the sponsor suffix ONLY: the priority envelope is appended by
        // the custom `Serialize` impl at wire time (and stripped back into
        // the struct field at parse time), so encoding it here as well would
        // double-envelope the bid and push the inner blob off the v1 64-byte
        // shape. The bid still binds both signatures (it is committed into
        // `base_signing_message` and `sponsor_message`) and into the hash.
        let mut blob = sig.to_vec();
        blob.extend_from_slice(&Self::encode_sponsor_suffix(&auth));
        Self {
            from: from_pub,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            signature: blob,
            payload,
            priority_fee_per_gas,
        }
    }

    /// Batched verification of many transactions at once (Ed25519 batch verify).
    /// This is significantly faster than verifying signatures one-by-one and is
    /// used when validating a whole block. Returns true iff ALL are valid.
    ///
    /// Envelope transactions contribute their SESSION key (not `tx.from`) to
    /// the batch, and their grant is checked (sender binding + master
    /// signature) before batching, so mixed plain + session batches work.
    pub fn verify_signatures_batch(txs: &[Transaction]) -> bool {
        use ed25519_dalek::verify_batch;
        if txs.is_empty() {
            return true;
        }
        // If any tx has a malformed key/signature, fall back to rejecting the batch
        // (batch verify would error anyway).
        let mut msgs: Vec<Vec<u8>> = Vec::with_capacity(txs.len());
        let mut sigs: Vec<Signature> = Vec::with_capacity(txs.len());
        let mut keys: Vec<VerifyingKey> = Vec::with_capacity(txs.len());
        for tx in txs {
            // PAYMASTER v1: a malformed sponsor suffix fails the batch closed,
            // and a well-formed one needs its sponsor signature checked
            // per-transaction (the batch below only covers the USER's
            // ed25519 signature). v1 composition is a plain legacy inner.
            let (sponsor_inner_len, sponsor_auth, sponsor_malformed) =
                Self::split_sponsor_envelope(&tx.signature);
            if sponsor_malformed {
                return false;
            }
            if let Some(ref auth) = sponsor_auth {
                if sponsor_inner_len != 64 || !tx.verify_sponsor_sig(auth) {
                    return false;
                }
            }
            let inner_sig: &[u8] = &tx.signature[..sponsor_inner_len];
            // Phase-2 EVM settlement authenticates via secp256k1 over its own
            // envelope, not via the ed25519 batch below.
            if tx.is_evm() {
                if crate::post_quantum::is_pure_pq_enforced() {
                    return false;
                }
                if !tx.verify_evm_signature() {
                    return false;
                }
                continue;
            }
            if tx.is_pq() {
                if crate::post_quantum::is_pure_pq_enforced() {
                    if let Some(env) = tx.pq_envelope() {
                        if !env.scheme.is_post_quantum() {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                if !tx.verify_signature() {
                    return false;
                }
                continue;
            }
            if crate::post_quantum::is_pure_pq_enforced() {
                return false;
            }
            let delegation = tx.delegation();
            if let Some(d) = &delegation {
                // The grant must belong to the sender and be authentically
                // minted by that sender — the same rules as the single verify.
                if d.master_address != tx.from || !d.verify_signature() {
                    return false;
                }
            }
            let key_bytes: [u8; 32] = delegation.as_ref().map_or(tx.from, |d| d.session_pubkey);
            let Ok(vk) = VerifyingKey::from_bytes(&key_bytes) else {
                return false;
            };
            let sig_bytes: &[u8] =
                if delegation.is_some() || tx.is_chain_id_bound() || sponsor_auth.is_some() {
                    // Envelope: only the leading 64 bytes are the user / session /
                    // Ed25519 signature.
                    match inner_sig.get(..64) {
                        Some(s) => s,
                        None => return false,
                    }
                } else {
                    inner_sig
                };
            let Ok(sig) = Signature::from_slice(sig_bytes) else {
                return false;
            };
            msgs.push(tx.signing_message());
            sigs.push(sig);
            keys.push(vk);
        }
        if msgs.is_empty() {
            return true;
        }
        let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        verify_batch(&msg_refs, &sigs, &keys).is_ok()
    }

    /// Parallel batched verification across CPU cores (rayon).
    /// Splits the block into chunks and batch-verifies each chunk in parallel.
    /// Falls back to the sequential batch for tiny inputs. Returns true iff ALL valid.
    pub fn verify_signatures_batch_parallel(txs: &[Transaction]) -> bool {
        use rayon::prelude::*;
        const CHUNK: usize = 256;
        if txs.len() <= CHUNK {
            return Self::verify_signatures_batch(txs);
        }
        txs.par_chunks(CHUNK).all(Self::verify_signatures_batch)
    }

    /// Per-transaction validity for a batch of transactions (Ed25519 batch verify
    /// with deterministic scalar fallback).
    ///
    /// Fallback semantics (TRANSACTIONS — keep the good ones): a batch MUST fail
    /// closed, but one bad neighbor must NOT sink honest transactions (mempool
    /// admission, proposer filtering and block execution all keep per-tx
    /// outcomes). So: the fast path batch-verifies everything at once; if the
    /// batch rejects, each transaction is re-checked with the scalar
    /// `verify_signature` in INPUT order and only the bad ones are marked
    /// `false`. `verify_signatures_batch(txs)` is exactly
    /// `partitioned(txs).iter().all(|b| *b)` — same verdict, with the offenders
    /// identified.
    ///
    /// Determinism: per-item validity never depends on batch ORDER (each item
    /// verifies against its own message/key); the fallback iterates input order,
    /// so the returned vector is stable for a given input regardless of which
    /// path was taken.
    ///
    /// No behavior change: element `i` of the result equals
    /// `txs[i].verify_signature()` in all cases (the batch path can only be
    /// stricter than the scalar one, never looser, and any batch rejection
    /// falls back to the scalar verdict per item).
    pub fn verify_signatures_partitioned(txs: &[Transaction]) -> Vec<bool> {
        use ed25519_dalek::verify_batch;
        if txs.is_empty() {
            return Vec::new();
        }
        // Stage each item exactly as the scalar `verify_signature` would check
        // it. Items that cannot even be parsed (bad key bytes, bad sig length,
        // broken envelope, grant mismatch) are marked bad WITHOUT failing the
        // whole batch — the good ones still get their batch verdict.
        struct Staged {
            idx: usize,
            msg: Vec<u8>,
            sig: Signature,
            key: VerifyingKey,
        }
        let mut out = vec![false; txs.len()];
        let mut staged: Vec<Staged> = Vec::with_capacity(txs.len());
        for (i, tx) in txs.iter().enumerate() {
            // Phase-2 EVM settlement: scalar secp256k1 verdict per item (the
            // batch below only speaks ed25519).
            if tx.is_evm() {
                if crate::post_quantum::is_pure_pq_enforced() {
                    out[i] = false;
                    continue;
                }
                out[i] = tx.verify_evm_signature();
                continue;
            }
            if tx.is_pq() {
                if crate::post_quantum::is_pure_pq_enforced() {
                    if let Some(env) = tx.pq_envelope() {
                        if !env.scheme.is_post_quantum() {
                            out[i] = false;
                            continue;
                        }
                    } else {
                        out[i] = false;
                        continue;
                    }
                }
                out[i] = tx.verify_signature();
                continue;
            }
            if crate::post_quantum::is_pure_pq_enforced() {
                out[i] = false;
                continue;
            }
            let delegation = tx.delegation();
            if let Some(d) = &delegation {
                if d.master_address != tx.from || !d.verify_signature() {
                    out[i] = false;
                    continue;
                }
            }
            let key_bytes: [u8; 32] = delegation.as_ref().map_or(tx.from, |d| d.session_pubkey);
            let Ok(vk) = VerifyingKey::from_bytes(&key_bytes) else {
                out[i] = false;
                continue;
            };
            let sig_bytes: &[u8] = if delegation.is_some() || tx.is_chain_id_bound() {
                match tx.signature.get(..64) {
                    Some(s) => s,
                    None => {
                        out[i] = false;
                        continue;
                    }
                }
            } else {
                &tx.signature
            };
            let Ok(sig) = Signature::from_slice(sig_bytes) else {
                out[i] = false;
                continue;
            };
            staged.push(Staged {
                idx: i,
                msg: tx.signing_message(),
                sig,
                key: vk,
            });
        }
        if staged.is_empty() {
            return out;
        }
        // Fast path: one batch verification over the well-formed items.
        {
            let msg_refs: Vec<&[u8]> = staged.iter().map(|s| s.msg.as_slice()).collect();
            let sigs: Vec<Signature> = staged.iter().map(|s| s.sig).collect();
            let keys: Vec<VerifyingKey> = staged.iter().map(|s| s.key).collect();
            if verify_batch(&msg_refs, &sigs, &keys).is_ok() {
                for s in &staged {
                    out[s.idx] = true;
                }
                return out;
            }
        }
        // Slow path: batch rejected — at least one staged signature is bad.
        // Fall back to the scalar verdict per item, in input order, so honest
        // transactions survive a bad neighbor (fail closed per item).
        for s in &staged {
            out[s.idx] = txs[s.idx].verify_signature();
        }
        out
    }

    /// The valid subset of `txs`, in input (stable) order.
    ///
    /// Convenience over [`Self::verify_signatures_partitioned`] for proposer
    /// filtering / gossip batching: keeps every transaction whose scalar
    /// `verify_signature` passes, drops only the bad ones.
    pub fn filter_valid_transactions(txs: &[Transaction]) -> Vec<Transaction> {
        let keep = Self::verify_signatures_partitioned(txs);
        txs.iter()
            .zip(keep.iter())
            .filter(|(_, k)| **k)
            .map(|(tx, _)| tx.clone())
            .collect()
    }
}

/// Reusable per-batch transaction-hashing state (see
/// [`Transaction::batch_hasher`]). Not `Send`-critical: it holds no locks and
/// is used thread-locally inside one pass.
pub struct TxHashBatch {
    hasher: Sha256,
    payload_buf: Vec<u8>,
}

impl TxHashBatch {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            payload_buf: Vec::new(),
        }
    }

    /// Hash one transaction, resetting the hasher for the next call.
    pub fn hash_one(&mut self, tx: &Transaction) -> [u8; 32] {
        use sha2::Digest;
        tx.hash_into(&mut self.hasher, &mut self.payload_buf);
        self.hasher.finalize_reset().into()
    }
}

/// Cross-shard atomic transfer message with tight-coupling cryptographic proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossShardMessage {
    pub msg_id: [u8; 32],
    pub source_shard: ShardId,
    pub target_shard: ShardId,
    pub tx: Transaction,
    pub merkle_inclusion_proof: Option<MerkleProof>,
    pub source_state_root: CellHash,
    pub finalized_in_block: [u8; 32],
    /// Sender's balance proven at `source_state_root` (binds the transfer to the
    /// account leaf and lets the target check the sender actually had the funds).
    #[serde(default)]
    pub source_balance: u64,
    pub bounce: bool,
    pub bounced: bool,
    /// Marks a message as already consensus-attested (locally generated only).
    /// SECURITY: MUST NEVER be set from untrusted network input. If true,
    /// `verify_inclusion` is bypassed. This flag exists for in-process routing
    /// (simulator / same-validator pipeline), not for wire messages.
    pub trusted: bool,
    #[serde(default)]
    pub sender_pubkey_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub sender_scheme: Option<u8>,
    /// The §9 TWO-PHASE-COMMIT phase of this record.
    ///
    /// `0` (`XPC_LEGACY`) means "this is a pre-2PC record": its kind is
    /// derived from the direction and the legacy `bounce` / `bounced` flags,
    /// exactly as before. A non-zero value names a 2PC phase (PREPARE,
    /// PREPARE-ACK, COMMIT, ABORT-REQUEST, ABORT-ACK) and the phase ALONE
    /// decides the kind — the direction must match the phase, or the record
    /// is `Unknown` and is refused.
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one of the struct, so a
    /// message persisted before the 2PC existed simply ends its byte stream
    /// one field early. `serde(default)` covers the self-describing formats
    /// and the bincode path is covered by [`de_xpc_phase`], which reads a
    /// missing trailing field as "this message predates the 2PC" (the legacy
    /// phase) instead of failing the whole decode. The legacy path is
    /// byte-identical: a legacy message's phase is 0 and its `msg_id` is
    /// computed exactly as before.
    #[serde(default, deserialize_with = "de_xpc_phase")]
    pub xpc_phase: u8,
}

impl CrossShardMessage {
    /// Construct a wire (untrusted) cross-shard message. Requires a Merkle proof
    /// for value-bearing transfers — a missing proof will be rejected.
    pub fn new(
        source_shard: ShardId,
        target_shard: ShardId,
        tx: Transaction,
        source_state_root: CellHash,
        finalized_in_block: [u8; 32],
        proof: Option<MerkleProof>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(source_shard.to_be_bytes());
        hasher.update(target_shard.to_be_bytes());
        hasher.update(tx.compute_tx_hash());
        hasher.update(finalized_in_block);
        let msg_id = hasher.finalize().into();

        let mut sender_pubkey_hash = None;
        let mut sender_scheme = None;

        if let Some(env) = tx.pq_envelope() {
            if let Some(ref pk) = env.pubkey {
                sender_scheme = Some(env.scheme.id());
                sender_pubkey_hash = Some(*blake3::hash(pk).as_bytes());
            } else if let Some((_, pk)) = global_implicit_key_registry().lookup(&tx.from) {
                sender_scheme = Some(env.scheme.id());
                sender_pubkey_hash = Some(*blake3::hash(&pk).as_bytes());
            }
        } else if let Some((scheme, pk)) = global_implicit_key_registry().lookup(&tx.from) {
            sender_scheme = Some(scheme.id());
            sender_pubkey_hash = Some(*blake3::hash(&pk).as_bytes());
        }

        Self {
            msg_id,
            source_shard,
            target_shard,
            tx,
            merkle_inclusion_proof: proof,
            source_state_root,
            finalized_in_block,
            source_balance: 0,
            bounce: true,
            bounced: false,
            trusted: false,
            sender_pubkey_hash,
            sender_scheme,
            xpc_phase: crate::xshard2pc::XPC_LEGACY,
        }
    }

    /// Attach the source-account balance that the inclusion proof attests to.
    pub fn with_source_balance(mut self, balance: u64) -> Self {
        self.source_balance = balance;
        self
    }

    /// Attach the sender's post-quantum scheme and public key hash (SEC-PQ-03).
    pub fn with_sender_pubkey_hash(mut self, scheme: u8, pubkey_hash: [u8; 32]) -> Self {
        self.sender_scheme = Some(scheme);
        self.sender_pubkey_hash = Some(pubkey_hash);
        self
    }

    /// Construct a locally-trusted message (already attested by this node's own
    /// consensus pipeline). NEVER deserialize a network message into this state.
    pub fn new_trusted(
        source_shard: ShardId,
        target_shard: ShardId,
        tx: Transaction,
        source_state_root: CellHash,
        finalized_in_block: [u8; 32],
    ) -> Self {
        let mut m = Self::new(
            source_shard,
            target_shard,
            tx,
            source_state_root,
            finalized_in_block,
            None,
        );
        m.trusted = true;
        m
    }

    /// Verify cryptographic tight coupling Merkle proof against source state root.
    /// SECURITY (Nomad-style forgery prevention): a missing proof is REJECTED
    /// unless the message is explicitly locally-trusted.
    pub fn verify_inclusion(&self) -> bool {
        if self.trusted {
            return true;
        }
        self.verify_inclusion_untrusted()
    }

    /// The same inclusion check but the local `trusted` shortcut is IGNORED.
    ///
    /// M2: this is the ONLY form a target shard may use when applying a message
    /// that travelled inside a block. `trusted` is set by the local producer of
    /// a message, but the flag is serialized with the block and a Byzantine
    /// proposer could set it on a message with no proof at all; honoring it here
    /// would mint value out of nothing on every node that applied the block.
    /// Requiring the Merkle proof makes the mint prove it corresponds to a
    /// source-shard account leaf.
    pub fn verify_inclusion_strict(&self) -> bool {
        self.verify_inclusion_untrusted()
    }

    /// Anchored inclusion (C1 fix): the Merkle proof PLUS a check that
    /// `source_state_root` is the state root of a source block THIS process
    /// finalized (or adopted with a verified QC) — looked up by the
    /// `finalized_in_block` hash the message commits to. A self-attested
    /// root (attacker trie + valid-for-that-root proof) fails here because
    /// its hash names no committed header. A lagging node fails here too
    /// (miss, not proof-failure): callers must treat that as NOT-READY
    /// (skip embedding / refuse the carrying block and retry after catching
    /// up), never as verified. `None` registry (single-shard contexts,
    /// unit tests) also fails closed.
    pub fn verify_anchored(&self, registry: Option<&FinalizedHeaderRegistry>) -> bool {
        let Some(reg) = registry else {
            return false;
        };
        if !reg.anchor_holds(
            self.source_shard,
            &self.finalized_in_block,
            &self.source_state_root,
        ) {
            return false;
        }
        self.verify_inclusion_untrusted()
    }

    fn verify_inclusion_untrusted(&self) -> bool {
        let Some(proof) = &self.merkle_inclusion_proof else {
            // No proof from an untrusted source -> reject.
            return false;
        };
        // The proven balance must actually cover the transfer, so an attacker
        // cannot inflate `amount` and keep an old proof for a smaller balance.
        if self.source_balance < self.tx.amount {
            return false;
        }
        // Prove the SENDER ACCOUNT LEAF (balance || nonce) at the source state
        // root — the same 16-byte encoding the state trie uses. This binds the
        // message to real state (not an ad-hoc amount||nonce value).
        let mut account_value = Vec::with_capacity(16);
        account_value.extend_from_slice(&self.source_balance.to_be_bytes());
        account_value.extend_from_slice(&self.tx.nonce.to_be_bytes());

        // Support pinned PQ accounts with explicit proof metadata (SEC-PQ-03)
        // If sender_pubkey_hash and sender_scheme are present, construct the exact 49-byte leaf:
        // account_value (16B) || scheme (1B) || pubkey_hash (32B)
        // and verify the Merkle proof against source_state_root!
        // This ensures Shard 2 can verify the proof completely independently without needing local RAM keys!
        if let (Some(pk_hash), Some(scheme)) = (self.sender_pubkey_hash, self.sender_scheme) {
            let mut pq_leaf = Vec::with_capacity(49);
            pq_leaf.extend_from_slice(&account_value);
            pq_leaf.push(scheme);
            pq_leaf.extend_from_slice(&pk_hash);
            return PatriciaTrie::verify_merkle_proof(
                &self.source_state_root,
                &self.tx.from,
                &pq_leaf,
                proof,
            );
        }

        if PatriciaTrie::verify_merkle_proof(
            &self.source_state_root,
            &self.tx.from,
            &account_value,
            proof,
        ) {
            return true;
        }

        // Support pinned PQ accounts (49-byte leaf: balance || nonce || scheme || pk_hash)
        if let Some(env) = self.tx.pq_envelope() {
            let maybe_pk = env.pubkey.as_ref().cloned().or_else(|| {
                global_implicit_key_registry()
                    .lookup(&self.tx.from)
                    .map(|(_, pk)| pk)
            });
            if let Some(ref pk) = maybe_pk {
                let pk_hash = blake3::hash(pk);
                let mut pq_leaf = Vec::with_capacity(49);
                pq_leaf.extend_from_slice(&account_value);
                pq_leaf.push(env.scheme.id());
                pq_leaf.extend_from_slice(pk_hash.as_bytes());
                if PatriciaTrie::verify_merkle_proof(
                    &self.source_state_root,
                    &self.tx.from,
                    &pq_leaf,
                    proof,
                ) {
                    return true;
                }
            }
        }

        // Support pinned accounts registered in implicit key registry (even if tx is not marked PQ)
        if let Some((scheme, pk)) = global_implicit_key_registry().lookup(&self.tx.from) {
            let pk_hash = blake3::hash(&pk);
            let mut pq_leaf = Vec::with_capacity(49);
            pq_leaf.extend_from_slice(&account_value);
            pq_leaf.push(scheme.id());
            pq_leaf.extend_from_slice(pk_hash.as_bytes());
            if PatriciaTrie::verify_merkle_proof(
                &self.source_state_root,
                &self.tx.from,
                &pq_leaf,
                proof,
            ) {
                return true;
            }
        }

        // Support pinned Ed25519 accounts where pubkey_hash = blake3(from)
        let ed_pk_hash = blake3::hash(&self.tx.from);
        let mut ed_pq_leaf = Vec::with_capacity(49);
        ed_pq_leaf.extend_from_slice(&account_value);
        ed_pq_leaf.push(PqScheme::Ed25519.id());
        ed_pq_leaf.extend_from_slice(ed_pk_hash.as_bytes());
        if PatriciaTrie::verify_merkle_proof(
            &self.source_state_root,
            &self.tx.from,
            &ed_pq_leaf,
            proof,
        ) {
            return true;
        }

        // Support pinned Ed25519 accounts where pubkey_hash = from
        let mut direct_pq_leaf = Vec::with_capacity(49);
        direct_pq_leaf.extend_from_slice(&account_value);
        direct_pq_leaf.push(PqScheme::Ed25519.id());
        direct_pq_leaf.extend_from_slice(&self.tx.from);
        if PatriciaTrie::verify_merkle_proof(
            &self.source_state_root,
            &self.tx.from,
            &direct_pq_leaf,
            proof,
        ) {
            return true;
        }

        false
    }

    /// True when this message is an OUTBOUND (produce) record for `shard_id`:
    /// the value leaves this shard when the block that carries it is applied.
    pub fn is_outbound_for(&self, shard_id: ShardId) -> bool {
        self.source_shard == shard_id && self.target_shard != shard_id
    }

    /// True when this message is an INBOUND (consume) record for `shard_id`:
    /// the recipient is credited on this shard when the block is applied.
    pub fn is_inbound_for(&self, shard_id: ShardId) -> bool {
        self.target_shard == shard_id && self.source_shard != shard_id
    }
}

/// Replay-protection key for a consumed cross-shard message.
///
/// `Block`/`Transaction`/`CrossShardMessage` gain NO new fields (bincode 1.3
/// would break every persisted block), so the source height is not carried as a
/// separate integer. The source block identity is [`CrossShardMessage::finalized_in_block`]
/// (the source shard's finalized head that the producing block extends) and the
/// `msg_id` commits to the source shard, the target shard, the full transaction
/// hash and that block identity. `(source_shard, finalized_in_block, msg_id)` is
/// therefore a unique, deterministic key for the source (height, shard, id):
/// two blocks at different source heights cannot share it, and it is identical
/// on every node that saw the same source block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CrossShardKey {
    pub source_shard: ShardId,
    pub finalized_in_block: [u8; 32],
    pub msg_id: [u8; 32],
}
/// Process-local registry of finalized block headers, shared by every shard
/// runtime in the process (C1 anchor). Maps (shard, source block hash) to the
/// state root THIS process committed to — keyed by PAIR because different
/// shards' geneses (and the zero-hash genesis placeholder below) must never
/// collide. Reads never block consensus: lookups are a BTreeMap probe, and
/// a MISS is fail-closed (message not verifiable YET — the proposer skips
/// it, a validator refuses the block carrying it; both retry after catching
/// up). Wrote on finalize AND adopt (adopted blocks carry verified QCs, so
/// they anchor exactly like local finals) plus an explicit genesis note at
/// every chain start (the first messages reference the genesis parent, which
/// no finalize event ever records). NEVER populated from gossip, RPC, or DHT
/// blobs: only block-application paths write here, so an attacker cannot
/// plant a root.
#[derive(Clone, Debug, Default)]
pub struct FinalizedHeaderRegistry {
    headers: std::collections::BTreeMap<(ShardId, [u8; 32]), crate::cell::CellHash>,
    /// The latest finalized header of every shard this process finalized
    /// (TON `shard_hashes` model): what a masterchain block publishes.
    /// Written ONLY by the block-application paths (finalize / adopt), never
    /// from gossip, RPC or DHT blobs, so an attacker cannot plant a head.
    latest: std::collections::BTreeMap<ShardId, ShardHeaderCommitment>,
}

impl FinalizedHeaderRegistry {
    /// Record a finalized block. Idempotent (same hash = same header).
    pub fn note_finalized(
        &mut self,
        shard: ShardId,
        block_hash: [u8; 32],
        state_root: crate::cell::CellHash,
    ) {
        self.headers.insert((shard, block_hash), state_root);
    }

    /// Record the ANCHOR root of a finalized block: the state root the shard
    /// reached AFTER applying that block.
    ///
    /// WHY THIS IS NOT THE BLOCK'S DECLARED ROOT. A block declares the state
    /// root of its PARENT (the root it was built on - the pre-state
    /// convention this codebase uses), so the root a cross-shard message
    /// carries (the state its inclusion proof was made against) is the
    /// POST-APPLY root of the block the message names, not that block's
    /// declared root. Anchoring the message against the DECLARED root made
    /// every cross-shard transfer produced after a state-changing block
    /// un-anchorable: the target could never verify it, so the transfer was
    /// silently never consumed. The anchor map therefore holds the
    /// post-apply root, and the published shard head keeps the declared root
    /// (that is the root the block itself commits to).
    ///
    /// `note_finalized_commitment` writes the DECLARED root into the anchor
    /// map for backward compatibility; this method overwrites it with the
    /// post-apply root, and the runtime calls it right after.
    pub fn note_finalized_anchor(
        &mut self,
        shard: ShardId,
        block_hash: [u8; 32],
        post_apply_root: crate::cell::CellHash,
    ) {
        self.headers.insert((shard, block_hash), post_apply_root);
    }

    /// Look up a source block hash. Returns the state root this process
    /// committed to — `None` means "not finalized here (yet)".
    pub fn lookup(&self, shard: ShardId, block_hash: &[u8; 32]) -> Option<crate::cell::CellHash> {
        self.headers.get(&(shard, *block_hash)).copied()
    }

    /// Mirror of [`CrossShardMessage::verify_anchored`] for callers that only
    /// need the anchor verdict without the proof check.
    pub fn anchor_holds(
        &self,
        source_shard: ShardId,
        block_hash: &[u8; 32],
        claimed_root: &crate::cell::CellHash,
    ) -> bool {
        matches!(self.lookup(source_shard, block_hash), Some(r) if &r == claimed_root)
    }

    /// Record a finalized block WITH its full header, so the masterchain can
    /// publish a shard-head commitment for it (TON `shard_hashes`).
    ///
    /// The newest header wins: a header at a greater height replaces the
    /// recorded one and a header at the SAME height replaces it as well (the
    /// idempotent re-note of the same block), but a header at a LOWER height
    /// NEVER displaces a newer one — replaying an old block after a reorg
    /// must not roll the published head back.
    ///
    /// The anchor map is updated exactly as [`Self::note_finalized`] does, so
    /// recording a full header is a strict superset of the anchor-only note.
    pub fn note_finalized_commitment(&mut self, commitment: ShardHeaderCommitment) {
        self.headers.insert(
            (commitment.shard_id, commitment.block_hash),
            commitment.state_root,
        );
        let replace = match self.latest.get(&commitment.shard_id) {
            Some(prev) => commitment.height >= prev.height,
            None => true,
        };
        if replace {
            self.latest.insert(commitment.shard_id, commitment);
        }
    }

    /// The latest finalized header of a shard, if this process finalized one.
    pub fn latest_header(&self, shard: ShardId) -> Option<&ShardHeaderCommitment> {
        self.latest.get(&shard)
    }

    /// The latest finalized header of every WORKCHAIN shard (id >= 1), in
    /// ascending shard order — the set a masterchain block publishes.
    ///
    /// The masterchain's own head is deliberately excluded: a block never
    /// commits to its own head, and the masterchain block itself IS the
    /// commitment.
    pub fn workchain_headers(&self) -> Vec<ShardHeaderCommitment> {
        self.latest
            .values()
            .filter(|h| h.shard_id != MASTERCHAIN_SHARD)
            .cloned()
            .collect()
    }
}

/// Process-shared finalized-header registry (C1 anchor plumbing). Every
/// shard runtime and state engine in the process holds the SAME `Arc`
/// (constructed once per process/cluster, passed explicitly — never a
/// global: independent test clusters must not mix their geneses).
/// The whole cross-shard replay state in one snapshot blob (audit F-I).
///
/// The engine's consumed set gates the actual credit at apply time; the
/// runtime's three sets gate proposal/validation (consumed filter), ack/bounce
/// linkage + timeout-bounce generation (produced), and completion marking
/// (completed). ALL of them are memory-only today, so a restart wiped them
/// and a replayed message passed every check: the target credited twice, or a
/// bounce refunded twice. Snapshotted height-keyed like every other domain;
/// restored on startup (full replay via `restore_cross_shard_replay`, engine
/// part in the load paths, runtime part where the runtime is constructed).
/// Sorted vecs (deterministic bytes); a missing entry means "empty", which is
/// also what a fresh process holds.
///
/// COMMITTED into `commitment_digest` (audit F1 fix) via
/// `commitment::write_cross_shard_domain`: a CONDITIONAL domain — all three
/// sets empty writes zero bytes, so existing chains (`COMMITMENT_VERSION`
/// unchanged) and every single-shard snapshot root byte-identically to
/// before, while any non-empty replay state moves the root. Two nodes with
/// identical blocks derive identical sets, so no consensus divergence can
/// arise from the sets themselves — and a node that drops them can no longer
/// agree with one that kept them under one root.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CrossShardReplaySnapshot {
    /// Engine credit gate (one entry per consumed inbound message).
    pub engine_consumed: Vec<CrossShardKey>,
    /// Runtime propose/validate filter mirror.
    pub runtime_consumed: Vec<CrossShardKey>,
    /// Outbounds this chain committed: (tx hash, transaction, height).
    pub produced: Vec<([u8; 32], Transaction, u64)>,
    /// Completed lifecycles (acked or bounced tx hashes).
    pub completed: Vec<[u8; 32]>,
    /// §9 CROSS-SHARD 2PC: the committed two-phase-commit records (the
    /// intermediate states of the cross-shard transfer lifecycle).
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one, so a snapshot
    /// persisted before the 2PC existed ends its byte stream one field early.
    /// `serde(default)` covers the self-describing formats and the bincode
    /// path is covered by [`de_xpc_records`], which reads a missing trailing
    /// field as "no 2PC record" instead of failing the whole decode.
    #[serde(default, deserialize_with = "de_xpc_records")]
    pub xpc: Vec<crate::xshard2pc::XpcRecord>,
}

impl CrossShardKey {
    pub fn of(msg: &CrossShardMessage) -> Self {
        Self {
            source_shard: msg.source_shard,
            finalized_in_block: msg.finalized_in_block,
            msg_id: msg.msg_id,
        }
    }
}

/// The shard-head commitment published by a MASTERCHAIN block (the TON
/// `shard_hashes` model).
///
/// A masterchain block commits to the LATEST finalized header of every
/// workchain shard: which shard, at which height, which block hash, which
/// state root and when. The commitment rides INSIDE the block body, so it is
/// covered by [`Block::compute_hash`] and therefore signed by the BFT quorum
/// — a validator can prove "shard 1 was at height 42 with THIS state root"
/// from a single masterchain block, without ever having seen the source
/// shard's chain. That is what makes cross-shard proofs possible: an inbound
/// message's `source_state_root` is checked against the committed shard head
/// instead of against a locally trusted root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardHeaderCommitment {
    /// The shard this head belongs to (never the masterchain itself).
    pub shard_id: ShardId,
    /// The height of the committed shard block.
    pub height: u64,
    /// The hash of the committed shard block.
    pub block_hash: [u8; 32],
    /// The state root AFTER applying the committed shard block.
    pub state_root: [u8; 32],
    /// The timestamp of the committed shard block.
    pub timestamp: u64,
}

impl ShardHeaderCommitment {
    /// The canonical commitment bytes of one shard head.
    ///
    /// Every field is fixed-width and written big-endian, so the field
    /// boundaries are unambiguous and no two different heads can produce the
    /// same preimage. The set is domain-separated by
    /// [`SHARD_HEADERS_COMMITMENT_TAG`] where it enters the block hash.
    pub fn commitment_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 8 + 32 + 32 + 8);
        out.extend_from_slice(&self.shard_id.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out
    }
}

/// Domain separator for the shard-head commitment inside a block hash.
///
/// Versioning the block-commitment scheme is what keeps a block that
/// publishes no shard head hashing EXACTLY as it did before the field
/// existed: the commitment is only mixed in when the set is non-empty.
pub const SHARD_HEADERS_COMMITMENT_TAG: &[u8; 8] = b"SHARDHDR";

/// Domain separator for the TRANSACTION-ORDER commitment inside a block hash.
///
/// The order commitment is the order Merkle root over the block's transaction
/// list, in execution order (see [`crate::mev::compute_order_merkle_root`]). It
/// is mixed into the block hash under this tag, so the BFT quorum that signs
/// the block hash signs the ORDERING too: a proposer cannot reorder the block
/// after the votes, and every validator re-computes the root from the
/// proposed body and refuses a proposal that does not match.
pub const ORDER_MERKLE_COMMITMENT_TAG: &[u8; 8] = b"ORDROOT1";

/// Domain separator for the EPOCH-KEY commitment inside a block hash.
///
/// The epoch-key commitment is the commitment to the MEV epoch key that
/// sealed transactions of this epoch are encrypted to (see
/// [`crate::mev_epoch`]). It is mixed into the block hash under this tag,
/// so the BFT quorum that signs the block hash signs the epoch key too: a
/// wallet (or a light client) can take the epoch key from a full node and
/// check it against the chain.
pub const EPOCH_KEY_COMMITMENT_TAG: &[u8; 8] = b"EPKEYC01";

/// Domain separator for the canonical downtime-evidence QC inside a block hash.
///
/// The `last_qc` certificate (the precommit QC that decided height-1) is
/// mixed into the block hash under this tag, so the BFT quorum that signs
/// the block hash signs the downtime evidence too: a proposer cannot swap
/// the evidence after the votes, and the evidence is byte-identical on every
/// node that applies the block (W10.5 canonical-attribution fix).
pub const LAST_QC_COMMITMENT_TAG: &[u8; 8] = b"LASTQC01";

/// Domain separator for the EPOCH-MMR commitment inside a block hash.
///
/// The epoch-MMR root is the Merkle-Mountain-Range root over the PREVIOUS
/// epoch's 128 finalized block hashes (see [`crate::mmr`]). It is mixed into
/// the block hash under this tag, so the BFT quorum that signs the block
/// hash signs the epoch root too: a bridge (or a light client) can anchor on
/// one 32-byte root per epoch instead of 128 individual checkpoints.
pub const MMR_EPOCH_COMMITMENT_TAG: &[u8; 8] = b"MMRROOT1";

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// The precommit quorum certificate that finalized this block, if any.
    /// Attached at finalization time. Deliberately EXCLUDED from `compute_hash`
    /// (like `validator_signatures`): it is evidence ABOUT the block, decided by
    /// a quorum that only exists after the block hash is fixed. Including it in
    /// the hash would make finalization change the block's identity.
    /// Block sync verifies this QC instead of trusting bare signatures, because
    /// vote signatures are over `vote_sign_bytes`, not over the block hash, and
    /// can never verify as block signatures.
    pub precommit_qc: Option<crate::consensus::QuorumCertificate>,
    /// The shard-head commitments published by this block (TON `shard_hashes`).
    ///
    /// ONLY a masterchain block carries them: one entry per WORKCHAIN shard
    /// (id >= 1), each naming the latest finalized header of that shard
    /// (height, block hash, state root, timestamp). A workchain block commits
    /// to nothing but its own body, and a masterchain block of a single-shard
    /// process has no workchain shard to speak of — so the set is empty there
    /// and the legacy block hash stays byte-identical.
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one, so a block
    /// persisted before it existed simply ends its byte stream one field
    /// early. `serde(default)` covers the self-describing formats, and the
    /// bincode path is covered by [`de_shard_headers`], which reads a missing
    /// trailing field as "this block predates the commitment" instead of
    /// failing the whole decode.
    ///
    /// The field is ALWAYS encoded (never skipped): bincode is positional, so
    /// omitting a field would make every NESTED block (a batch of proposals,
    /// a block inside a message) misread the next element's bytes as the
    /// missing field. The cost is 8 bytes per block (an empty length
    /// prefix) — and the block HASH is untouched, because the commitment is
    /// only mixed in for a non-empty set.
    #[serde(default, deserialize_with = "de_shard_headers")]
    pub shard_headers: Vec<ShardHeaderCommitment>,
    /// The TRANSACTION-ORDER commitment of this block: the order Merkle root
    /// over this block's transaction list, in execution order.
    ///
    /// It is a CONSENSUS commitment, not a local note: the root is mixed into
    /// [`Block::compute_hash`] under [`ORDER_MERKLE_COMMITMENT_TAG`], so the
    /// quorum that signs the block hash signs the ORDERING. A validator
    /// re-computes the root from the proposed body
    /// ([`crate::mev::compute_order_merkle_root`]) and REFUSES the proposal
    /// when it does not match — a proposer therefore cannot reorder a block
    /// after it has been voted on.
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one, so a block
    /// persisted before it existed simply ends its byte stream one field
    /// early. `serde(default)` covers the self-describing formats, and the
    /// bincode path is covered by [`de_order_merkle_root`], which reads a
    /// missing trailing field as "this block predates the commitment"
    /// (the all-zero root) instead of failing the whole decode.
    ///
    /// The all-zero root is ALSO what a block with NO transactions carries:
    /// there is no order to commit, so the commitment is empty by definition
    /// (see [`crate::mev::compute_order_merkle_root`]). The block hash mixes
    /// the root in only when it is non-zero, so a legacy block (no root) and
    /// an empty block keep their pre-existing block hashes byte-for-byte.
    #[serde(default, deserialize_with = "de_order_merkle_root")]
    pub order_merkle_root: [u8; 32],
    /// The EPOCH-KEY commitment of this block: the commitment to the MEV
    /// epoch key that sealed transactions of this epoch are encrypted to
    /// (see [`crate::mev_epoch`]).
    ///
    /// It is `H(domain || epoch || epoch public key || committee hash ||
    /// threshold)` (see [`crate::mev_epoch::epoch_key_commitment`]), so a
    /// light client (or a wallet) can take the epoch key from a full node
    /// and CHECK it against the chain: the announcement must hash to the
    /// committed value. That is what makes the epoch key a CONSENSUS value
    /// instead of "whatever this node believes".
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one, so a block
    /// persisted before it existed simply ends its byte stream one field
    /// early. `serde(default)` covers the self-describing formats, and the
    /// bincode path is covered by [`de_epoch_key_commitment`], which reads a
    /// missing trailing field as "this block predates the commitment" (the
    /// all-zero value) instead of failing the whole decode.
    ///
    /// The all-zero value is ALSO what a block of an epoch whose committee
    /// has no key carries (no DKG completed, so there is nothing to
    /// commit to), and the block hash mixes the commitment in only when it
    /// is non-zero — a legacy block (no commitment) keeps its pre-existing
    /// block hash byte-for-byte.
    #[serde(default, deserialize_with = "de_epoch_key_commitment")]
    pub epoch_key_commitment: [u8; 32],
    /// The PRECOMMIT quorum certificate that decided the PARENT block
    /// (height-1), embedded by the proposer.
    ///
    /// CANONICAL DOWNTIME EVIDENCE (W10.5 activation-race fix, live
    /// 2026-10-23 #292785/#292786): downtime attribution used to read the
    /// LOCALLY-ASSEMBLED `precommit_qc` attached at finalization time, so two
    /// nodes that finalized the same block with different quorate QC subsets
    /// (e.g. {A,C} vs {A,B,C} — both pass the same quorum) bumped different
    /// `missed` counters in the committed staking ledger and forked the state
    /// root permanently. The evidence is now chosen ONCE, by the proposer of
    /// this block, from the QC that decided the parent — every node that
    /// applies this block attributes the SAME evidence and converges.
    /// `precommit_qc` stays as the finality proof (light clients, checkpoints,
    /// sync); it is no longer evidence for slashing.
    ///
    /// CONSENSUS commitment: the certificate is mixed into
    /// [`Block::compute_hash`] under [`LAST_QC_COMMITMENT_TAG`], so the quorum
    /// that signs the block hash signs the evidence too, and validators
    /// re-verify the embedded QC against the validator set in force at
    /// height-1 before prevoting (see
    /// [`crate::runtime::ValidatorRuntime::check_last_qc_evidence`]).
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one, so a block
    /// persisted before it existed ends its byte stream one field early.
    /// `serde(default)` covers the self-describing formats, and the bincode
    /// path is covered by [`de_last_qc`]. A missing trailing field decodes as
    /// `None` ("predates canonical evidence"); the transition then skips
    /// downtime attribution for that height (replay of pre-upgrade history
    /// falls back to the attached `precommit_qc` — see
    /// `replay_historical_block`). The block HASH mixes the certificate in
    /// only when present, so every pre-existing block keeps its hash
    /// byte-for-byte.
    #[serde(default, deserialize_with = "de_last_qc")]
    pub last_qc: Option<crate::consensus::QuorumCertificate>,
    /// The EPOCH-MMR root committed by this block: the MMR root over the
    /// PREVIOUS epoch's 128 finalized block hashes (see [`crate::mmr`]).
    ///
    /// ONLY the first masterchain block of an epoch carries it (height H
    /// with `H > 0` and `H % 128 == 0` commits epoch `H / 128 - 1` — see
    /// [`crate::mmr::commits_epoch_root`]). Committing the *previous* epoch
    /// keeps the commitment non-circular: a block never commits to a root
    /// that includes its own hash. Every other block carries zero.
    ///
    /// It is a CONSENSUS commitment, not a local note: the root is mixed
    /// into [`Block::compute_hash`] under [`MMR_EPOCH_COMMITMENT_TAG`], so
    /// the quorum that signs the block hash signs the epoch root, and a
    /// validator that knows the epoch's 128 bodies re-computes the root and
    /// REFUSES a proposal that commits a different one (a validator that
    /// does not know them yet accepts — the commitment is still checked by
    /// the quorum that signs the block; see
    /// [`crate::runtime::ValidatorRuntime::check_epoch_mmr_commitment`]).
    /// A workchain block that carries a non-zero root is refused (only the
    /// masterchain commits epochs).
    ///
    /// BACKWARD COMPATIBILITY: the field is the LAST one, so a block
    /// persisted before it existed ends its byte stream one field early.
    /// `serde(default)` covers the self-describing formats, and the bincode
    /// path is covered by [`de_mmr_epoch_root`]. A missing trailing field
    /// decodes as the all-zero root ("predates the epoch MMR"). The block
    /// HASH mixes the root in only when it is non-zero, so every
    /// pre-existing block keeps its hash byte-for-byte.
    ///
    /// COMPATIBILITY ARGUMENT (why this does not fork the live chain):
    ///
    /// * Hash stability: with a zero root the preimage — and therefore the
    ///   hash, the proposer signature and every vote/QC over it — is
    ///   byte-identical to the pre-MMR layout. All history, all checkpoints
    ///   and all signatures agreed before the upgrade keep verifying.
    /// * Store readability: a body persisted before the field existed
    ///   decodes tolerantly (inside `with_legacy_block_tolerance`), so an
    ///   upgraded node replays its old chain instead of re-genesising.
    /// * Fail-closed wire: like every trailing field before it, the wire
    ///   path decodes strictly. A node that has not upgraded does NOT
    ///   "verify the parts it understands" of a block carrying a root it
    ///   cannot interpret — it rejects the message, loudly, instead of
    ///   agreeing to a block identity it computed differently. Mixed-version
    ///   gossip therefore fails closed, never silently forks.
    /// * Coordinated activation: non-zero roots begin only after a
    ///   coordinated all-validators upgrade (the same rollout rule as the
    ///   order commitment and the sortition schedule). Until then — and
    ///   whenever a proposer does not know the epoch's 128 bodies (pruned,
    ///   freshly restarted) — the boundary block carries zero and hashes
    ///   exactly like a legacy block. A zero root at a boundary height is
    ///   valid; it means "not committed", and light clients must treat it
    ///   as such.
    #[serde(default, deserialize_with = "de_mmr_epoch_root")]
    pub mmr_epoch_root: [u8; 32],
}

impl Default for Block {
    /// The neutral block: no body, no commitments, masterchain shard.
    ///
    /// `Default` exists so that a struct literal can be written as
    /// `Block { height: 7, ..Default::default() }`: the functional-update
    /// syntax fills EVERY field the literal does not mention, so adding a
    /// field to [`Block`] can no longer break the call sites that did not
    /// know about it yet.
    ///
    /// The two commitment fields are NOT left to a caller to invent:
    /// [`Block::new_for_test`] derives the order commitment from the body, and
    /// [`Block::recompute_order_commitment`] re-derives it on demand. A block
    /// built through the plain `Default` carries the all-zero order root,
    /// which is exactly what an EMPTY block commits to.
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
            last_qc: None,
            shard_headers: Vec::new(),
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32],
        }
    }
}

thread_local! {
    /// Whether a block body may be decoded with the LEGACY shape (the
    /// trailing commitment fields absent).
    ///
    /// The tolerance exists ONLY for bodies PERSISTED before those fields
    /// existed. It must never apply to a body that arrives over the wire: a
    /// truncated message would then decode as a valid block with an empty
    /// shard-head set and an all-zero order root — i.e. a malformed message
    /// silently reinterpreted as a DIFFERENT block. The wire path therefore
    /// decodes STRICTLY (fail closed) and only the local store opts into the
    /// legacy shape.
    static LEGACY_BLOCK_TOLERANCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `f` with the legacy block shape tolerated.
///
/// Thread-scoped on purpose: the flag is process-global state and the store
/// is read from many threads, so it must not leak into a concurrent decode of
/// a WIRE body (which must stay strict). The closure is synchronous, so no
/// await can observe the flag half-set.
pub fn with_legacy_block_tolerance<T>(f: impl FnOnce() -> T) -> T {
    LEGACY_BLOCK_TOLERANCE.with(|c| {
        let prev = c.replace(true);
        let out = f();
        c.set(prev);
        out
    })
}

/// True when the legacy block shape is tolerated on this thread.
fn legacy_block_tolerance() -> bool {
    LEGACY_BLOCK_TOLERANCE.with(|c| c.get())
}

/// Bincode-tolerant reader for the trailing `order_merkle_root` field of a
/// block.
///
/// A block persisted BEFORE the order commitment existed ends its byte stream
/// right after `shard_headers`. Bincode reports the missing trailing field
/// as an I/O end-of-file, which serde would normally propagate as a hard
/// decode error — an old chain would become unreadable and old blocks
/// received over the wire would be rejected. A missing trailing field means
/// exactly one thing ("this block predates the commitment"), so it decodes as
/// the ALL-ZERO root. Every other error is propagated unchanged (fail
/// closed): a corrupt body must never be read as "no order commitment".
fn de_order_merkle_root<'de, D>(d: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    match <[u8; 32]>::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            // The EOF shows up in two shapes depending on the backend: serde's
            // own "end of file" and bincode's wrapped I/O error ("failed to
            // fill whole buffer" — `read_exact` on a short buffer). Both mean
            // the byte stream ended before this trailing field.
            let msg = e.to_string();
            if legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok([0u8; 32])
            } else {
                Err(e)
            }
        }
    }
}

/// Bincode-tolerant reader for the trailing `epoch_key_commitment` field of a
/// block.
///
/// A block persisted BEFORE the epoch-key commitment existed ends its byte
/// stream right after `order_merkle_root`. Bincode reports the missing
/// trailing field as an I/O end-of-file, which serde would normally
/// propagate as a hard decode error — an old chain would become unreadable
/// and old blocks received over the wire would be rejected. A missing
/// trailing field means exactly one thing ("this block predates the
/// commitment"), so it decodes as the ALL-ZERO value. Every other error is
/// propagated unchanged (fail closed): a corrupt body must never be read as
/// "this block commits to no epoch key".
fn de_epoch_key_commitment<'de, D>(d: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    match <[u8; 32]>::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = e.to_string();
            if legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok([0u8; 32])
            } else {
                Err(e)
            }
        }
    }
}

/// Bincode-tolerant reader for the trailing `last_qc` field of a block.
///
/// A block persisted BEFORE canonical downtime evidence existed ends its byte
/// stream right after `epoch_key_commitment`. Bincode reports the missing
/// trailing field as an I/O end-of-file, which serde would normally
/// propagate as a hard decode error — an old chain would become unreadable
/// and old blocks received over the wire would be rejected. A missing
/// trailing field means exactly one thing ("this block predates canonical
/// evidence"), so it decodes as `None`. Every other error is propagated
/// unchanged (fail closed): a corrupt body must never be read as "no
/// evidence".
fn de_last_qc<'de, D>(d: D) -> Result<Option<crate::consensus::QuorumCertificate>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<crate::consensus::QuorumCertificate>::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = e.to_string();
            if legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// Bincode-tolerant reader for the trailing `mmr_epoch_root` field of a block.
///
/// A block persisted BEFORE the epoch MMR existed ends its byte stream right
/// after `last_qc`. Bincode reports the missing trailing field as an I/O
/// end-of-file, which serde would normally propagate as a hard decode error
/// — an old chain would become unreadable. A missing trailing field means
/// exactly one thing ("this block predates the epoch MMR"), so it decodes as
/// the ALL-ZERO root. Every other error is propagated unchanged (fail
/// closed): a corrupt body must never be read as "no epoch commitment".
fn de_mmr_epoch_root<'de, D>(d: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    match <[u8; 32]>::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = e.to_string();
            if legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok([0u8; 32])
            } else {
                Err(e)
            }
        }
    }
}

/// Bincode-tolerant reader for the trailing `shard_headers` field of a block.
///
/// A block persisted BEFORE the shard-head commitment existed ends its byte
/// stream right after `precommit_qc`. Bincode reports the missing trailing
/// field as an I/O end-of-file, which serde would normally propagate as a
/// hard decode error — an old chain would become unreadable and old blocks
/// received over the wire would be rejected. A missing trailing field means
/// exactly one thing ("this block commits to no shard head"), so it decodes
/// as the EMPTY set. Every other error is propagated unchanged (fail closed):
/// a corrupt body must never be read as "no shard heads".
fn de_shard_headers<'de, D>(d: D) -> Result<Vec<ShardHeaderCommitment>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Vec::<ShardHeaderCommitment>::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            // The EOF shows up in two shapes depending on the backend:
            // serde's own "end of file" and bincode's wrapped I/O error
            // ("failed to fill whole buffer" — `read_exact` on a short
            // buffer). Both mean the same thing here: the byte stream ended
            // before this trailing field.
            let msg = e.to_string();
            if legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok(Vec::new())
            } else {
                Err(e)
            }
        }
    }
}

/// Bincode-tolerant reader for the trailing `xpc` field of a cross-shard
/// replay snapshot.
///
/// A snapshot persisted BEFORE the 2PC existed ends its byte stream right
/// after `completed`. A missing trailing field means exactly one thing
/// ("this snapshot predates the 2PC"), so it decodes as the EMPTY record set
/// instead of failing the whole decode - a node must still be able to open
/// the chain it wrote before the upgrade. Every other error is propagated
/// unchanged (fail closed).
fn de_xpc_records<'de, D>(d: D) -> Result<Vec<crate::xshard2pc::XpcRecord>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Vec::<crate::xshard2pc::XpcRecord>::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = e.to_string();
            if legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok(Vec::new())
            } else {
                Err(e)
            }
        }
    }
}

/// Bincode-tolerant reader for the trailing `xpc_phase` field of a
/// cross-shard message.
///
/// A message persisted BEFORE the 2PC existed ends its byte stream right
/// after `sender_scheme`. Bincode reports the missing trailing field as an
/// I/O end-of-file, which serde would normally propagate as a hard decode
/// error — an old chain would become unreadable and old messages received
/// over the wire would be rejected. A missing trailing field means exactly
/// one thing ("this message predates the 2PC"), so it decodes as the LEGACY
/// phase (`0`) instead of failing the whole decode. Every other error is
/// propagated unchanged (fail closed): a corrupt body must never be read as
/// "a legacy record".
fn de_xpc_phase<'de, D>(d: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match u8::deserialize(d) {
        Ok(v) => Ok(v),
        Err(e) => {
            let msg = e.to_string();
            if legacy_block_tolerance()
                && (msg.contains("end of file")
                    || msg.contains("failed to fill whole buffer")
                    || msg.contains("UnexpectedEof"))
            {
                Ok(crate::xshard2pc::XPC_LEGACY)
            } else {
                Err(e)
            }
        }
    }
}

impl Block {
    /// A block with the consensus commitments DERIVED from its body.
    ///
    /// THIS is the constructor every example, bench and test should use. The
    /// block carries two commitments that are DERIVED from the body rather
    /// than chosen by the caller:
    ///
    /// * the transaction-order commitment ([`Block::order_merkle_root`]),
    ///   recomputed here from `transactions` — a block whose order root
    ///   disagrees with its body is REFUSED by the validator
    ///   (`crate::runtime::ConsensusRuntime::check_order_commitment`), so a
    ///   caller must never have to remember to set it;
    /// * the shard-head set ([`Block::shard_headers`]), empty here (a
    ///   workchain block commits to no shard head).
    ///
    /// Because every field that is not part of the identity of the block is
    /// either defaulted or derived, adding a field to [`Block`] no longer
    /// breaks the call sites: they call this constructor instead of spelling
    /// a struct literal.
    /// Test-only constructor: absent from production builds
    /// (`any(test, debug_assertions)` only).
    #[cfg(any(test, debug_assertions))]
    pub fn new_for_test(
        shard_id: ShardId,
        height: u64,
        prev_hash: [u8; 32],
        state_root: CellHash,
        transactions: Vec<Transaction>,
    ) -> Self {
        let mut b = Self {
            shard_id,
            height,
            prev_hash,
            state_root,
            transactions,
            ..Self::default()
        };
        b.recompute_order_commitment();
        b
    }

    /// Recompute the transaction-order commitment from the body.
    ///
    /// The root is a PURE function of the transaction list (see
    /// [`crate::mev::compute_order_merkle_root`]), so every node derives the
    /// same value from the same body. Call it after mutating
    /// [`Block::transactions`].
    pub fn recompute_order_commitment(&mut self) {
        self.order_merkle_root = crate::mev::compute_order_merkle_root(&self.transactions);
    }

    /// Set the transactions and re-derive the order commitment.
    pub fn with_transactions(mut self, transactions: Vec<Transaction>) -> Self {
        self.transactions = transactions;
        self.recompute_order_commitment();
        self
    }

    /// Set the cross-shard outbound messages.
    pub fn with_cross_shard_out(mut self, messages: Vec<CrossShardMessage>) -> Self {
        self.cross_shard_out = messages;
        self
    }

    /// Set the block timestamp (seconds).
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Set the declared proposer (the validator public key that signed it).
    pub fn with_proposer(mut self, proposer: [u8; 32]) -> Self {
        self.proposer = proposer;
        self
    }

    /// Set the published shard-head commitments (a masterchain block only).
    pub fn with_shard_headers(mut self, headers: Vec<ShardHeaderCommitment>) -> Self {
        self.shard_headers = headers;
        self
    }

    /// Set the attached precommit quorum certificate.
    pub fn with_precommit_qc(mut self, qc: Option<crate::consensus::QuorumCertificate>) -> Self {
        self.precommit_qc = qc;
        self
    }

    /// Set the committed epoch-MMR root (a masterchain epoch-boundary block
    /// only; see [`crate::mmr::commits_epoch_root`]).
    pub fn with_epoch_mmr_root(mut self, root: [u8; 32]) -> Self {
        self.mmr_epoch_root = root;
        self
    }

    /// The canonical block hash.
    ///
    /// CHAIN BINDING: the preimage starts with the domain tag, then the CHAIN
    /// ID ([`crate::consensus::consensus_chain_id`]), then the block fields.
    /// A block signed on one deployment therefore has a different hash — and a
    /// different signature — than the same block on another, so a testnet
    /// block (or a block signed by a testnet validator key) can never be
    /// replayed on mainnet. The domain tag was bumped `V2 -> V3` because the
    /// preimage layout changed.
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Domain separator: version the block-commitment scheme.
        hasher.update(b"STELLEREUM_BLOCK_V3");
        // Chain id: binds the block (and every signature over its hash) to
        // THIS deployment. Without it a block is replayable across chains.
        hasher.update(crate::consensus::consensus_chain_id().to_be_bytes());
        hasher.update(self.shard_id.to_be_bytes());
        hasher.update(self.height.to_be_bytes());
        hasher.update(self.prev_hash);
        hasher.update(self.state_root);
        // CRITICAL: commit to EVERY transaction field (nonce, gas_limit, shards
        // and especially the SVM payload) via the full tx hash. Hashing only
        // from/to/amount let a proposer equivocate with two distinct bodies under
        // a single voted block hash, which would diverge node state after
        // finality. Signatures are intentionally excluded (they sign this hash).
        hasher.update((self.transactions.len() as u32).to_be_bytes());
        for tx in &self.transactions {
            hasher.update(tx.compute_tx_hash());
        }
        // TRANSACTION-ORDER COMMITMENT: the order Merkle root over the
        // transaction list, in execution order. Because it is inside the
        // block hash, the BFT quorum signs the ORDERING: a proposer that
        // reorders the body after the votes changes the hash, and a
        // validator re-computes the root from the proposed body and refuses
        // a proposal that does not match (the root is also checked
        // explicitly, so the refusal does not depend on the hash alone).
        //
        // The root is mixed in ONLY when it is non-zero, which is what keeps
        // every pre-existing block hash byte-for-byte: a block persisted
        // before the field existed decodes with the all-zero root, and so
        // does a block with no transactions (there is no order to commit).
        if self.order_merkle_root != [0u8; 32] {
            hasher.update(ORDER_MERKLE_COMMITMENT_TAG);
            hasher.update(self.order_merkle_root);
        }
        // Commit to cross-shard outbound messages as well.
        hasher.update((self.cross_shard_out.len() as u32).to_be_bytes());
        for m in &self.cross_shard_out {
            hasher.update(m.msg_id);
        }
        // SHARD-HEAD COMMITMENTS (TON `shard_hashes`): a masterchain block
        // commits to the latest finalized header of every workchain shard.
        // Because the commitment is mixed in ONLY for a non-empty set, a
        // block that publishes no shard head hashes exactly as it did before
        // the field existed — legacy chains keep their block hashes
        // byte-for-byte. A non-empty set is length-prefixed and
        // domain-separated, so it can never be confused with any other part
        // of the preimage.
        if !self.shard_headers.is_empty() {
            hasher.update(SHARD_HEADERS_COMMITMENT_TAG);
            hasher.update((self.shard_headers.len() as u32).to_be_bytes());
            for h in &self.shard_headers {
                hasher.update(h.commitment_bytes());
            }
        }
        // EPOCH-KEY COMMITMENT: the commitment to the MEV epoch key this
        // block's epoch uses (see [`crate::mev_epoch`]). It is mixed in ONLY
        // when it is non-zero, exactly like the order commitment: a block
        // whose epoch has no key (no DKG completed) and every block that
        // predates the field keep their pre-existing block hash byte-for-byte.
        if self.epoch_key_commitment != [0u8; 32] {
            hasher.update(EPOCH_KEY_COMMITMENT_TAG);
            hasher.update(self.epoch_key_commitment);
        }
        // CANONICAL DOWNTIME EVIDENCE (W10.5): the certificate that decided
        // height-1, embedded by the proposer. Mixed in ONLY when present, so
        // every block that predates canonical evidence keeps its pre-existing
        // block hash byte-for-byte. Signatures are hashed in canonical
        // (validator-id-sorted) order: the assembly order of a QC depends on
        // vote arrival timing and must not move the block hash.
        if let Some(qc) = &self.last_qc {
            hasher.update(LAST_QC_COMMITMENT_TAG);
            hasher.update(qc.height.to_be_bytes());
            hasher.update(qc.round.to_be_bytes());
            hasher.update([match qc.kind {
                crate::consensus::VoteKind::Prevote => 0u8,
                crate::consensus::VoteKind::Precommit => 1u8,
            }]);
            if let Some(bh) = &qc.block_hash {
                hasher.update([1u8]);
                hasher.update(bh);
            } else {
                hasher.update([0u8]);
            }
            let mut sigs = qc.signatures.clone();
            sigs.sort_by(|a, b| a.0.cmp(&b.0));
            hasher.update((sigs.len() as u32).to_be_bytes());
            for (voter, sig) in &sigs {
                hasher.update(voter);
                hasher.update((sig.len() as u32).to_be_bytes());
                hasher.update(sig);
            }
        }
        // EPOCH-MMR COMMITMENT (V5 Tier-2): the MMR root over the previous
        // epoch's finalized block hashes (see [`crate::mmr`]). Mixed in ONLY
        // when non-zero, exactly like the order and epoch-key commitments: a
        // block that predates the MMR and every block that is not an
        // epoch-committing boundary block keep their pre-existing block hash
        // byte-for-byte.
        if self.mmr_epoch_root != [0u8; 32] {
            hasher.update(MMR_EPOCH_COMMITMENT_TAG);
            hasher.update(self.mmr_epoch_root);
        }
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.proposer);
        hasher.finalize().into()
    }

    /// The shard head this block commits to for `shard_id`, if any.
    pub fn shard_head(&self, shard_id: ShardId) -> Option<&ShardHeaderCommitment> {
        self.shard_headers.iter().find(|h| h.shard_id == shard_id)
    }

    /// True when the committed shard heads are in CANONICAL form: strictly
    /// ascending shard ids, no duplicates, and no entry for the masterchain
    /// itself (a block cannot commit to its own head).
    ///
    /// Canonical order matters because the set is hashed as a sequence: two
    /// byte orders of the same set would be two different block hashes, and a
    /// proposer could equivocate with them. Every honest builder sorts by
    /// shard id, and a validator refuses anything else.
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

    /// Sign this block with a validator key.
    ///
    /// CHAIN BINDING: the signature covers the block HASH, and the block hash
    /// preimage carries the chain id (see [`Self::compute_hash`]). A signature
    /// produced on one deployment therefore never verifies on another, even
    /// with the same key.
    pub fn sign_block(&mut self, validator_key: &SigningKey) {
        let block_hash = self.compute_hash();
        let sig = validator_key.sign(&block_hash);
        self.validator_signatures
            .push((validator_key.verifying_key().to_bytes(), sig.to_vec()));
    }

    /// Verify the block carries a valid signature by its DECLARED proposer.
    ///
    /// SECURITY: proposal authenticity. Without this, any peer could broadcast a
    /// `Proposal` for another validator's slot (with valid transactions but no
    /// proposer signature) and have honest nodes prevote it — breaking
    /// attribution and letting an attacker inject proposals on someone's behalf.
    pub fn verify_proposer_signature(&self) -> bool {
        let hash = self.compute_hash();
        for (pubkey, sig_bytes) in &self.validator_signatures {
            if *pubkey != self.proposer {
                continue;
            }
            let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
                continue;
            };
            let Ok(sig) = Signature::from_slice(sig_bytes) else {
                continue;
            };
            if vk.verify(&hash, &sig).is_ok() {
                return true;
            }
        }
        false
    }

    /// Verify the block carries a real validator quorum, by POWER.
    ///
    /// `verify_signatures(count)` counted distinct pubkeys with a valid signature
    /// and never checked whether any of them was a validator at all, so three
    /// throwaway keypairs satisfied it - a forged block history verified. The
    /// caller then made it worse by passing `quorum_power()`, a sum of stake
    /// units, where a head count was expected. Both halves had to change
    /// together: a signature is only evidence if it comes from a validator, and
    /// the threshold is a fraction of stake, not a number of names.
    ///
    /// A set with no power fails closed, because `quorum_power` is then
    /// unreachable.
    pub fn verify_validator_quorum(&self, validators: &crate::consensus::ValidatorSet) -> bool {
        let required = validators.quorum_power();
        if required == u64::MAX {
            return false;
        }
        let block_hash = self.compute_hash();
        // Dedup + membership first (cheap per item, input order preserved for a
        // deterministic fallback). The expensive crypto happens once below.
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut candidates: Vec<(VerifyingKey, Signature, u64)> = Vec::new();
        for (pubkey, sig_bytes) in &self.validator_signatures {
            // Count each validator at most once, or one key could sign N times to
            // fake an N-of-M quorum.
            if !seen.insert(*pubkey) {
                continue;
            }
            // Membership FIRST: an unknown key has no power and must not be
            // counted even if the signature is perfectly valid.
            let vp = validators.power_of(pubkey);
            if vp == 0 {
                continue;
            }
            let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
                continue;
            };
            let Ok(sig) = Signature::from_slice(sig_bytes) else {
                continue;
            };
            candidates.push((vk, sig, vp));
        }
        if candidates.is_empty() {
            return false;
        }
        // Fast path: one batch verification over the shared block hash.
        // Same-message batching; result is order-independent.
        {
            let msgs: Vec<&[u8]> = candidates.iter().map(|_| block_hash.as_slice()).collect();
            let sigs: Vec<Signature> = candidates.iter().map(|(_, s, _)| *s).collect();
            let keys: Vec<VerifyingKey> = candidates.iter().map(|(k, _, _)| *k).collect();
            if ed25519_dalek::verify_batch(&msgs, &sigs, &keys).is_ok() {
                let power: u64 = candidates.iter().map(|(_, _, p)| p).sum();
                return power >= required;
            }
        }
        // Slow path: batch rejected, so at least one signature is bad. Fall back
        // to per-signature checks in input order and count exactly the valid
        // power — one forged neighbor must not sink a good quorum, and a bad
        // quorum must not pass on its good members. Identical verdict to the
        // old scalar loop in all cases.
        let mut power = 0u64;
        for (vk, sig, vp) in &candidates {
            if vk.verify(&block_hash, sig).is_ok() {
                power = power.saturating_add(*vp);
            }
        }
        power >= required
    }

    /// Count distinct valid signers. Retained for tests and for code that has
    /// its own membership check; the consensus path must use
    /// `verify_validator_quorum`, which also weights by stake.
    pub fn verify_signatures(&self, required_quorum: usize) -> bool {
        // A zero quorum is nonsensical for consensus and must never accept a block.
        if required_quorum == 0 {
            return false;
        }
        let block_hash = self.compute_hash();
        // SECURITY: count each DISTINCT validator at most once. Otherwise a single
        // validator key signing the same block N times would fake an N-of-M quorum.
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut candidates: Vec<(VerifyingKey, Signature)> = Vec::new();
        for (pubkey, sig_bytes) in &self.validator_signatures {
            if !seen.insert(*pubkey) {
                continue; // duplicate signer -> ignore
            }
            let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
                continue;
            };
            let Ok(sig) = Signature::from_slice(sig_bytes) else {
                continue;
            };
            candidates.push((vk, sig));
        }
        if candidates.is_empty() {
            return false;
        }
        // Fast path: one batch verification over the shared block hash.
        {
            let msgs: Vec<&[u8]> = candidates.iter().map(|_| block_hash.as_slice()).collect();
            let sigs: Vec<Signature> = candidates.iter().map(|(_, s)| *s).collect();
            let keys: Vec<VerifyingKey> = candidates.iter().map(|(k, _)| *k).collect();
            if ed25519_dalek::verify_batch(&msgs, &sigs, &keys).is_ok() {
                return candidates.len() >= required_quorum;
            }
        }
        // Slow path: deterministic scalar fallback in input order — identical
        // verdict to the old per-signature loop.
        let mut valid = 0usize;
        for (vk, sig) in &candidates {
            if vk.verify(&block_hash, sig).is_ok() {
                valid += 1;
            }
        }
        valid >= required_quorum
    }
}

/// Shared Sequencer for unified cross-shard ordering and external L2 rollup scheduling
#[derive(Clone, Debug, Default)]
pub struct SharedSequencer {
    pub current_sequence: u64,
    pub scheduled_cross_shard: Vec<(u64, CrossShardMessage)>,
    /// §5 M3: per-source sequenced-height watermark (see `assign_from_block`).
    /// Advanced ONLY from finalized block content — never by time/operator.
    pub watermark: std::collections::BTreeMap<ShardId, u64>,
}

impl SharedSequencer {
    pub fn new() -> Self {
        Self {
            current_sequence: 1,
            scheduled_cross_shard: Vec::new(),
            watermark: std::collections::BTreeMap::new(),
        }
    }

    pub fn sequence_message(&mut self, msg: CrossShardMessage) -> u64 {
        let seq = self.current_sequence;
        self.current_sequence += 1;
        self.scheduled_cross_shard.push((seq, msg));
        seq
    }
}

/// Shared Liquidity Hub across all shards providing atomic all-or-nothing execution
pub struct SharedLiquidityHub {
    pub active_shards: Vec<ShardId>,
    pub pending_inbound_cross_shard: HashMap<ShardId, Vec<CrossShardMessage>>,
    pub sequencer: SharedSequencer,
    /// Replay protection: msg_id of every message already routed/delivered.
    pub seen_cross_shard: std::collections::HashSet<[u8; 32]>,
}

impl SharedLiquidityHub {
    pub fn new(active_shards: Vec<ShardId>) -> Self {
        Self {
            active_shards,
            pending_inbound_cross_shard: HashMap::new(),
            sequencer: SharedSequencer::new(),
            seen_cross_shard: std::collections::HashSet::new(),
        }
    }

    /// Route cross-shard messages directly to destination shard with sequencer ordering.
    /// SECURITY:
    ///  - A message that fails inclusion verification is NEVER routed (bounced or dropped).
    ///  - Duplicate msg_id is rejected (cross-shard replay protection).
    pub fn route_cross_shard_message(&mut self, mut msg: CrossShardMessage) -> u64 {
        // Replay protection: reject an already-seen message id.
        if self.seen_cross_shard.contains(&msg.msg_id) {
            return 0;
        }

        // Unknown/inactive target shard: never queue into a phantom shard.
        // NOTE: a rejected message does NOT reserve its id — otherwise an invalid
        // message could block a later VALID one (e.g. a rejected untrusted copy of
        // a legitimate in-process message). Only accepted messages are marked seen.
        if !self.active_shards.contains(&msg.target_shard) {
            if msg.bounce && !msg.bounced {
                msg.bounced = true;
                std::mem::swap(&mut msg.source_shard, &mut msg.target_shard);
                return self.sequencer.sequence_message(msg);
            }
            return 0;
        }

        if !msg.verify_inclusion() {
            if msg.bounce && !msg.bounced {
                msg.bounced = true;
                std::mem::swap(&mut msg.source_shard, &mut msg.target_shard);
                return self.sequencer.sequence_message(msg);
            }
            // Invalid and non-bounceable: drop, never route.
            return 0;
        }

        self.seen_cross_shard.insert(msg.msg_id);
        let target = msg.target_shard;
        let seq = self.sequencer.sequence_message(msg.clone());
        self.pending_inbound_cross_shard
            .entry(target)
            .or_default()
            .push(msg);
        seq
    }

    pub fn take_inbound_messages(&mut self, shard: ShardId) -> Vec<CrossShardMessage> {
        self.pending_inbound_cross_shard
            .remove(&shard)
            .unwrap_or_default()
    }

    /// Route a cross-shard message to its destination shard THROUGH a
    /// transport (the P2P gossip path or the node-local KV) instead of the
    /// in-process mailbox.
    ///
    /// Same admission rules as [`Self::route_cross_shard_message`] — replay
    /// protection, active-shard check, inclusion proof — but the admitted
    /// message is PUBLISHED to the transport instead of being queued in the
    /// process-local mailbox. With a P2P transport that is what carries the
    /// message to a shard running on ANOTHER host: the transport publishes it
    /// to the gossip topic of the target shard (see
    /// [`crate::network::cross_shard_topic`]).
    ///
    /// The message is NOT queued locally as well: the transport delivers it
    /// back to the destination shard, so queueing it here too would credit it
    /// twice.
    ///
    /// Returns the sequencer position of the routed message, or `0` when the
    /// message was rejected (replay, unknown target, failed inclusion). An
    /// `Err` means the transport refused the publish — the message was NOT
    /// marked as seen, so the caller may retry it.
    pub async fn route_cross_shard_message_via(
        &mut self,
        mut msg: CrossShardMessage,
        transport: &Arc<crate::network::CrossShardTransport>,
    ) -> Result<u64, String> {
        // Replay protection: an already-seen message id is never routed again.
        if self.seen_cross_shard.contains(&msg.msg_id) {
            return Ok(0);
        }

        // Unknown/inactive target shard: never route into a phantom shard —
        // bounce the message back to its source instead.
        if !self.active_shards.contains(&msg.target_shard) {
            if msg.bounce && !msg.bounced {
                msg.bounced = true;
                std::mem::swap(&mut msg.source_shard, &mut msg.target_shard);
                transport.broadcast_cross_shard(&msg).await?;
                let seq = self.sequencer.sequence_message(msg);
                return Ok(seq);
            }
            return Ok(0);
        }

        // A message that fails the inclusion verification is NEVER routed.
        if !msg.verify_inclusion() {
            if msg.bounce && !msg.bounced {
                msg.bounced = true;
                std::mem::swap(&mut msg.source_shard, &mut msg.target_shard);
                transport.broadcast_cross_shard(&msg).await?;
                let seq = self.sequencer.sequence_message(msg);
                return Ok(seq);
            }
            // Invalid and non-bounceable: drop, never route.
            return Ok(0);
        }

        transport.broadcast_cross_shard(&msg).await?;
        self.seen_cross_shard.insert(msg.msg_id);
        let seq = self.sequencer.sequence_message(msg);
        Ok(seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constructor DERIVES the transaction-order commitment (audit W7.2).
    ///
    /// A block whose order root disagrees with its body is refused by the
    /// validator, so a caller must never have to remember to set the field —
    /// the constructor computes it from the body it is given.
    #[test]
    fn new_for_test_derives_the_order_commitment() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let tx = Transaction::sign(&sk, [2u8; 32], 10, 21_000, 0, 0, 0);

        // An empty body commits to nothing: the all-zero root.
        let empty = Block::new_for_test(MASTERCHAIN_SHARD, 1, [0u8; 32], [0u8; 32], vec![]);
        assert_eq!(empty.order_merkle_root, [0u8; 32]);

        // A body with transactions commits to their ORDER.
        let one = Block::new_for_test(MASTERCHAIN_SHARD, 2, [0u8; 32], [0u8; 32], vec![tx.clone()]);
        assert_eq!(
            one.order_merkle_root,
            crate::mev::compute_order_merkle_root(std::slice::from_ref(&tx))
        );
        assert_ne!(one.order_merkle_root, [0u8; 32]);

        // Two blocks with the SAME transactions have the SAME root; the root
        // is a pure function of the body.
        let again =
            Block::new_for_test(MASTERCHAIN_SHARD, 3, [1u8; 32], [0u8; 32], vec![tx.clone()]);
        assert_eq!(one.order_merkle_root, again.order_merkle_root);

        // Mutating the body and re-deriving moves the root.
        let mut moved = one.clone();
        moved.recompute_order_commitment();
        assert_eq!(moved.order_merkle_root, one.order_merkle_root);
    }

    /// `Default` + the functional-update syntax is the future-proof literal
    /// form: a field added to `Block` later is filled from `Default` instead
    /// of breaking every call site (audit W7.2).
    #[test]
    fn default_fills_every_field_a_literal_omits() {
        let b = Block {
            height: 7,
            ..Default::default()
        };
        assert_eq!(b.height, 7);
        assert_eq!(b.shard_id, MASTERCHAIN_SHARD);
        assert!(b.transactions.is_empty());
        assert!(b.shard_headers.is_empty());
        assert_eq!(b.order_merkle_root, [0u8; 32]);
        assert!(b.precommit_qc.is_none());
    }

    #[test]
    fn shard_registry_default_is_single_and_not_sharded() {
        let r = ShardRegistry::default();
        assert!(!r.is_sharded(), "the default registry must be single-shard");
        assert_eq!(r.ids().collect::<Vec<_>>(), vec![MASTERCHAIN_SHARD]);
        assert!(r.contains(MASTERCHAIN_SHARD));
        assert!(!r.contains(BASE_WORKCHAIN_SHARD_INITIAL));
    }

    #[test]
    fn shard_registry_from_ids_marks_multi_shard() {
        let r = ShardRegistry::from_ids([MASTERCHAIN_SHARD, BASE_WORKCHAIN_SHARD_INITIAL]);
        assert!(r.is_sharded());
        assert_eq!(
            r.ids().collect::<Vec<_>>(),
            vec![MASTERCHAIN_SHARD, BASE_WORKCHAIN_SHARD_INITIAL]
        );
        // A single non-masterchain shard is still one chain in this process.
        assert!(!ShardRegistry::from_ids([BASE_WORKCHAIN_SHARD_INITIAL]).is_sharded());
        // An empty set can never produce a process with no chain at all.
        assert_eq!(
            ShardRegistry::from_ids([]).ids().collect::<Vec<_>>(),
            vec![MASTERCHAIN_SHARD]
        );
    }

    #[test]
    fn block_shard_ignores_namespace_shard_when_not_sharded() {
        // Regression: a single-shard node started with `--shard 1` uses shard 1
        // only as the DHT/blob namespace. Its BLOCKS must stay masterchain (0),
        // matching its persisted chain, or sync validation rejects every chain
        // and finality stalls. This was the live stand deadlock.
        let single_via_cli = ShardRegistry::from_env_or(BASE_WORKCHAIN_SHARD_INITIAL);
        assert!(!single_via_cli.is_sharded());
        assert_eq!(
            block_shard_for(BASE_WORKCHAIN_SHARD_INITIAL, &single_via_cli),
            MASTERCHAIN_SHARD
        );
        // A genuine multi-shard process does scope blocks to its namespace shard.
        let multi = ShardRegistry::from_ids([MASTERCHAIN_SHARD, BASE_WORKCHAIN_SHARD_INITIAL]);
        assert!(multi.is_sharded());
        assert_eq!(
            block_shard_for(BASE_WORKCHAIN_SHARD_INITIAL, &multi),
            BASE_WORKCHAIN_SHARD_INITIAL
        );
    }

    #[test]
    fn tx_belongs_to_shard_enforces_strict_partition_isolation() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let tx0 = Transaction::sign(&key, [2u8; 32], 100, 1000, 0, 0, 0);
        let tx1 = Transaction::sign(&key, [2u8; 32], 100, 1000, 0, 1, 1);
        let tx_cross = Transaction::sign(&key, [2u8; 32], 100, 1000, 0, 0, 1);

        assert!(tx_belongs_to_shard(&tx0, 0));
        assert!(
            !tx_belongs_to_shard(&tx0, 1),
            "shard 1 must not own shard 0 tx"
        );

        assert!(tx_belongs_to_shard(&tx1, 1));
        assert!(
            !tx_belongs_to_shard(&tx1, 0),
            "shard 0 must not own shard 1 tx"
        );

        assert!(tx_belongs_to_shard(&tx_cross, 0));
        assert!(
            !tx_belongs_to_shard(&tx_cross, 1),
            "outbound cross-shard tx belongs strictly to source shard"
        );
    }

    #[test]
    fn route_address_is_deterministic_and_most_specific() {
        let mut m = DynamicShardManager::new();
        m.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, SHARD_SPLIT_LOAD_THRESHOLD);
        let (c0, c1) = m
            .check_and_split(BASE_WORKCHAIN_SHARD_INITIAL)
            .expect("split");
        assert_eq!((c0.prefix_len, c1.prefix_len), (1, 1));

        let mut a0 = [0u8; 32];
        a0[0] = 0b0000_0000;
        let mut a1 = [0u8; 32];
        a1[0] = 0b1000_0000;

        let r0 = m.route_address(&a0);
        let r1 = m.route_address(&a1);
        // deterministic across repeated calls
        assert_eq!(r0, m.route_address(&a0));
        assert_eq!(r1, m.route_address(&a1));
        // routed to a shard that actually contains the address, and differently
        assert!(m.shards.get(&r0).unwrap().contains_address(&a0));
        assert!(m.shards.get(&r1).unwrap().contains_address(&a1));
        assert_ne!(r0, r1);
    }

    #[test]
    fn test_explicit_pq_transaction_verification() {
        let registry = StatefulImplicitKeyRegistry::new();
        let seed = 0x42;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = DEFAULT_SALT;
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

        // Pre-create transaction with empty signature to obtain exact signing message
        let mut tx = Transaction {
            from,
            to: [2u8; 32],
            amount: 1000,
            gas_limit: 50_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg = tx.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        let envelope = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig);
        tx.signature = envelope.encode();

        assert!(tx.is_pq());
        assert!(tx.is_pq_activation());
        assert!(!tx.is_pq_implicit());

        // Verification against isolated registry succeeds and auto-registers the key
        assert!(tx.verify_signature_with_registry(&registry));
        let registered = registry
            .lookup(&from)
            .expect("Address must be registered after explicit verify");
        assert_eq!(registered.0, PqScheme::Falcon512);
        assert_eq!(registered.1, pk);

        // Global registry verification also succeeds
        assert!(tx.verify_signature());

        // Explicit Ed25519 PQ envelope
        let ed_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ed_pk = ed_sk.verifying_key().to_bytes().to_vec();
        let ed_from = derive_pq_address(PqScheme::Ed25519, &ed_pk, &salt);
        let mut ed_tx = Transaction {
            from: ed_from,
            to: [3u8; 32],
            amount: 500,
            gas_limit: 30_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let ed_msg = ed_tx.signing_message();
        let ed_sig = ed_sk.sign(&ed_msg).to_bytes().to_vec();
        ed_tx.signature =
            PqSignatureEnvelope::new_explicit(PqScheme::Ed25519, ed_pk, ed_sig).encode();
        assert!(ed_tx.verify_signature());
    }

    #[test]
    fn test_implicit_pq_transaction_verification_zero_wire_overhead() {
        let registry = StatefulImplicitKeyRegistry::new();
        let seed = 0x77;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = DEFAULT_SALT;
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

        // Build Tx2 (implicit, nonce 1)
        let mut tx2 = Transaction {
            from,
            to: [5u8; 32],
            amount: 250,
            gas_limit: 50_000,
            nonce: 1,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg = tx2.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        let envelope = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig);
        tx2.signature = envelope.encode();

        assert!(tx2.is_pq());
        assert!(!tx2.is_pq_activation());
        assert!(tx2.is_pq_implicit());

        // Before registration, implicit verification MUST fail (cannot verify without pubkey)
        assert!(!tx2.verify_signature_with_registry(&registry));

        // Now register address in registry (e.g. from Tx1 activation)
        registry
            .register(from, PqScheme::Falcon512, &pk, &salt)
            .expect("Register");

        // After registration, implicit verification MUST succeed!
        assert!(tx2.verify_signature_with_registry(&registry));

        // Verify wire size difference: implicit envelope carries NO public key or salt bytes
        let explicit_env = PqSignatureEnvelope::new_explicit(
            PqScheme::Falcon512,
            pk.clone(),
            envelope.signature_bytes.clone(),
        );
        let explicit_len = explicit_env.encode().len();
        let implicit_len = tx2.signature.len();
        assert_eq!(explicit_len - implicit_len, pk.len() + 16);
        assert!(explicit_len > 1500);
        assert!(implicit_len < 700);
    }

    #[test]
    fn test_tampering_detection_on_pq_signatures() {
        let registry = StatefulImplicitKeyRegistry::new();
        let seed = 0x99;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = DEFAULT_SALT;
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

        let mut tx = Transaction {
            from,
            to: [8u8; 32],
            amount: 100,
            gas_limit: 50_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg = tx.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        let envelope =
            PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig.clone());
        tx.signature = envelope.encode();

        // Baseline: original transaction verifies
        assert!(tx.verify_signature_with_registry(&registry));

        // 1. Tampered amount
        let mut tampered_amt = tx.clone();
        tampered_amt.amount += 1;
        assert!(
            !tampered_amt.verify_signature_with_registry(&registry),
            "Tampered amount must fail"
        );

        // 2. Tampered recipient
        let mut tampered_to = tx.clone();
        tampered_to.to[0] ^= 0x01;
        assert!(
            !tampered_to.verify_signature_with_registry(&registry),
            "Tampered recipient must fail"
        );

        // 3. Tampered sender address (does not match derived address from pk)
        let mut tampered_from = tx.clone();
        tampered_from.from[0] ^= 0x01;
        assert!(
            !tampered_from.verify_signature_with_registry(&registry),
            "Tampered sender must fail"
        );

        // 4. Tampered signature bytes inside envelope
        let mut tampered_sig_bytes = sig.clone();
        tampered_sig_bytes[50] ^= 0xAA;
        let bad_env =
            PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), tampered_sig_bytes);
        let mut tx_bad_sig = tx.clone();
        tx_bad_sig.signature = bad_env.encode();
        assert!(
            !tx_bad_sig.verify_signature_with_registry(&registry),
            "Corrupted signature bytes must fail"
        );

        // 5. Tampered public key bytes inside envelope
        let mut bad_pk = pk.clone();
        bad_pk[10] ^= 0x55;
        let bad_pk_env =
            PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, bad_pk, sig.clone());
        let mut tx_bad_pk = tx.clone();
        tx_bad_pk.signature = bad_pk_env.encode();
        assert!(
            !tx_bad_pk.verify_signature_with_registry(&registry),
            "Corrupted pubkey must fail"
        );

        // 6. Envelope header corruption (magic mismatch)
        let mut corrupted_magic = tx.clone();
        corrupted_magic.signature[0] = b'X';
        assert!(
            !corrupted_magic.verify_signature_with_registry(&registry),
            "Corrupted envelope magic must fail"
        );

        // 7. Trailing junk attached to envelope
        let mut trailing_junk = tx.clone();
        trailing_junk.signature.push(0xDE);
        trailing_junk.signature.push(0xAD);
        assert!(
            !trailing_junk.verify_signature_with_registry(&registry),
            "Trailing bytes must fail exact-fit check"
        );

        // 8. Truncated envelope
        let mut truncated = tx.clone();
        truncated.signature.truncate(tx.signature.len() - 10);
        assert!(
            !truncated.verify_signature_with_registry(&registry),
            "Truncated envelope must fail"
        );
    }

    #[test]
    fn test_cross_shard_transfer_from_49_byte_pinned_account_leaf() {
        let seed = 0x5a;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = DEFAULT_SALT;
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);
        let to = [9u8; 32];
        let amount = 5_000u64;
        let nonce = 2u64;
        let source_balance = 20_000u64;

        // Build PQ transaction with explicit activation envelope
        let mut tx = Transaction {
            from,
            to,
            amount,
            gas_limit: 30_000,
            nonce,
            source_shard: 1,
            target_shard: 2,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg = tx.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        let envelope =
            PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig.clone());
        tx.signature = envelope.encode();

        // Sender has a 49-byte pinned leaf in the source shard trie
        let pk_hash = blake3::hash(&pk);
        let leaf_49 = crate::cpat2::AccountLeaf::new_pinned(
            source_balance,
            nonce,
            PqScheme::Falcon512.id(),
            *pk_hash.as_bytes(),
        )
        .encode();
        assert_eq!(leaf_49.len(), crate::cpat2::ACCOUNT_LEAF_LEN_PQ);

        let mut trie = PatriciaTrie::new();
        trie.insert(&from, &leaf_49);
        let source_state_root = trie.root_hash();
        let proof = trie.generate_merkle_proof(&from).expect("merkle proof");

        let finalized_in_block = [0x77u8; 32];
        let cross_msg = CrossShardMessage::new(
            1,
            2,
            tx.clone(),
            source_state_root,
            finalized_in_block,
            Some(proof.clone()),
        )
        .with_source_balance(source_balance);

        // 1. Inclusion verification succeeds on 49-byte pinned leaf
        assert!(
            cross_msg.verify_inclusion(),
            "49-byte pinned leaf inclusion proof must verify"
        );
        assert!(
            cross_msg.verify_inclusion_strict(),
            "Strict inclusion must verify"
        );

        // 2. Fund loss prevention: underfunded transfer (source_balance < amount) fails closed
        let underfunded_msg = CrossShardMessage::new(
            1,
            2,
            tx.clone(),
            source_state_root,
            finalized_in_block,
            Some(proof.clone()),
        )
        .with_source_balance(amount - 1);
        assert!(
            !underfunded_msg.verify_inclusion(),
            "Underfunded transfer must be rejected"
        );

        // 3. Fund loss prevention: tampered source_balance fails proof verification
        let tampered_balance_msg = CrossShardMessage::new(
            1,
            2,
            tx.clone(),
            source_state_root,
            finalized_in_block,
            Some(proof.clone()),
        )
        .with_source_balance(source_balance + 1_000);
        assert!(
            !tampered_balance_msg.verify_inclusion(),
            "Tampered balance must fail proof verification"
        );

        // 4. Implicit PQ cross-shard transaction verification
        let implicit_envelope = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig);
        let mut implicit_tx = tx.clone();
        implicit_tx.signature = implicit_envelope.encode();

        Transaction::global_implicit_registry()
            .register(from, PqScheme::Falcon512, &pk, &salt)
            .expect("register implicit key");

        let implicit_cross_msg = CrossShardMessage::new(
            1,
            2,
            implicit_tx,
            source_state_root,
            finalized_in_block,
            Some(proof.clone()),
        )
        .with_source_balance(source_balance);
        assert!(
            implicit_cross_msg.verify_inclusion(),
            "Implicit PQ cross-shard message must verify"
        );

        // 5. Also verify legacy 16-byte leaf cross-shard transfer works cleanly
        let legacy_from = [0x88u8; 32];
        let legacy_leaf = crate::cpat2::AccountLeaf::new_unpinned(10_000, 0).encode();
        assert_eq!(legacy_leaf.len(), crate::cpat2::ACCOUNT_LEAF_LEN_LEGACY);
        let mut legacy_trie = PatriciaTrie::new();
        legacy_trie.insert(&legacy_from, &legacy_leaf);
        let legacy_root = legacy_trie.root_hash();
        let legacy_proof = legacy_trie
            .generate_merkle_proof(&legacy_from)
            .expect("proof");

        let legacy_tx = Transaction {
            from: legacy_from,
            to,
            amount: 1_000,
            gas_limit: 21_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 2,
            signature: vec![0u8; 64],
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let legacy_cross_msg = CrossShardMessage::new(
            1,
            2,
            legacy_tx,
            legacy_root,
            finalized_in_block,
            Some(legacy_proof),
        )
        .with_source_balance(10_000);
        assert!(
            legacy_cross_msg.verify_inclusion(),
            "Legacy 16B leaf cross-shard message must verify"
        );
    }

    /// AUDIT W6.5 (signature malleability): the PQ1 wire envelope must have
    /// exactly ONE valid byte form per `(scheme, key, signature)`.
    ///
    /// The decoder used to accept an implicit envelope with a non-zero
    /// `pk_len` (it skipped the bytes and dropped them), an explicit envelope
    /// with ANY key length (including zero) and a signature of ANY length —
    /// so the same logical signature could be re-minted into many different
    /// byte strings. Any byte-based dedup / replay filter, or any
    /// transaction id derived from those bytes, could then be evaded by
    /// re-encoding the very same transaction.
    #[test]
    fn test_pq_envelope_decode_is_strict_and_non_malleable() {
        let pk = Transaction::sample_falcon512_pubkey(0x91);
        let sig = Transaction::create_falcon512_test_signature(&pk, b"envelope malleability", 0x91);

        // Canonical encodings round-trip.
        let explicit =
            PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig.clone());
        let bytes = explicit.encode();
        assert_eq!(PqSignatureEnvelope::decode(&bytes).unwrap(), explicit);
        let implicit = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig.clone());
        let imp_bytes = implicit.encode();
        assert_eq!(PqSignatureEnvelope::decode(&imp_bytes).unwrap(), implicit);

        // (1) An implicit envelope must NOT carry a public key: junk spliced
        //     where the (claimed) key would be must be REFUSED, not silently
        //     skipped — that skip was the malleability hole.
        let mut spliced = Vec::new();
        spliced.extend_from_slice(&imp_bytes[..7]);
        spliced.extend_from_slice(&[0xAAu8; 4]);
        spliced.extend_from_slice(&imp_bytes[7..]);
        assert!(
            PqSignatureEnvelope::decode(&spliced).is_err(),
            "an implicit envelope with a non-zero pk_len must be refused"
        );

        // (2) An explicit envelope must carry EXACTLY the scheme's key length.
        let mut zero_pk_len = bytes.clone();
        zero_pk_len[5..7].copy_from_slice(&0u16.to_le_bytes());
        assert!(PqSignatureEnvelope::decode(&zero_pk_len).is_err());
        let mut short_pk_len = bytes.clone();
        short_pk_len[5..7].copy_from_slice(&((pk.len() - 1) as u16).to_le_bytes());
        assert!(PqSignatureEnvelope::decode(&short_pk_len).is_err());
        let mut long_pk_len = bytes.clone();
        long_pk_len[5..7].copy_from_slice(&((pk.len() + 1) as u16).to_le_bytes());
        assert!(PqSignatureEnvelope::decode(&long_pk_len).is_err());

        // (3) The signature length is pinned to the scheme.
        let sig_len_off = 7 + pk.len() + 16;
        let mut bad_sig_len = bytes.clone();
        bad_sig_len[sig_len_off..sig_len_off + 2].copy_from_slice(&1u16.to_le_bytes());
        assert!(PqSignatureEnvelope::decode(&bad_sig_len).is_err());

        // (4) The flag byte is 0 (explicit) or 1 (implicit) — nothing else.
        let mut bad_flag = imp_bytes.clone();
        bad_flag[4] = 2;
        assert!(PqSignatureEnvelope::decode(&bad_flag).is_err());

        // (5) Trailing bytes are refused.
        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert!(PqSignatureEnvelope::decode(&trailing).is_err());
    }

    #[test]
    fn test_explicit_pq_custom_non_zero_salt_verification() {
        let registry = StatefulImplicitKeyRegistry::new();
        let seed = 0x88;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let custom_salt = [0x5au8; 16];
        assert_ne!(custom_salt, DEFAULT_SALT);

        let from = derive_pq_address(PqScheme::Falcon512, &pk, &custom_salt);
        let default_from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
        assert_ne!(
            from, default_from,
            "Custom salt must derive disjoint address from default salt"
        );

        let tx_probe = Transaction {
            from,
            to: [7u8; 32],
            amount: 1000,
            gas_limit: 50_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg = tx_probe.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);

        let tx = Transaction::new_pq_explicit(
            PqScheme::Falcon512,
            pk.clone(),
            sig,
            [7u8; 32],
            1000,
            50_000,
            0,
            1,
            1,
            Vec::new(),
            &custom_salt,
        );

        assert_eq!(tx.from, from);
        assert!(tx.is_pq());
        assert!(tx.is_pq_activation());

        let env = tx.pq_envelope().expect("PQ envelope must decode");
        assert_eq!(env.salt, custom_salt, "Envelope must carry custom salt");

        // Verification must use env.salt from the envelope and succeed
        assert!(
            tx.verify_signature_with_registry(&registry),
            "Explicit PQ tx carrying custom non-zero salt must verify"
        );
        let registered = registry
            .lookup(&from)
            .expect("Address must be registered with custom salt");
        assert_eq!(registered.0, PqScheme::Falcon512);
        assert_eq!(registered.1, pk);

        // Global registry also succeeds
        assert!(tx.verify_signature());

        // Subsequent implicit transaction from this sender cleanly verifies via registry
        let tx2_probe = Transaction {
            from,
            to: [8u8; 32],
            amount: 500,
            gas_limit: 50_000,
            nonce: 1,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg2 = tx2_probe.signing_message();
        let sig2 = Transaction::create_falcon512_test_signature(&pk, &msg2, seed);
        let tx2 = Transaction::new_pq_implicit(
            from,
            PqScheme::Falcon512,
            sig2,
            [8u8; 32],
            500,
            50_000,
            1,
            1,
            1,
            Vec::new(),
        );
        assert!(tx2.verify_signature_with_registry(&registry));

        // Wrong salt envelope fails closed (e.g. envelope with DEFAULT_SALT does not match `from`)
        let mut bad_salt_tx = tx.clone();
        let bad_env =
            PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk, env.signature_bytes);
        bad_salt_tx.signature = bad_env.encode();
        assert!(
            !bad_salt_tx.verify_signature_with_registry(&registry),
            "Envelope with mismatched salt must fail verification"
        );
    }

    #[test]
    fn test_pq_tx_hash_envelope_binding() {
        let seed = 0x66;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = [0x12u8; 16];
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

        let tx_probe = Transaction {
            from,
            to: [9u8; 32],
            amount: 100,
            gas_limit: 50_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg = tx_probe.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);

        let tx = Transaction::new_pq_explicit(
            PqScheme::Falcon512,
            pk.clone(),
            sig.clone(),
            [9u8; 32],
            100,
            50_000,
            0,
            1,
            1,
            Vec::new(),
            &salt,
        );

        let baseline_hash = tx.compute_tx_hash();

        // 1. Modifying signature bytes changes tx hash
        let mut tx_mutated_sig = tx.clone();
        let last_idx = tx_mutated_sig.signature.len() - 1;
        tx_mutated_sig.signature[last_idx] ^= 0x01;
        assert_ne!(
            baseline_hash,
            tx_mutated_sig.compute_tx_hash(),
            "Mutating signature bytes must change compute_tx_hash"
        );

        // 2. Modifying salt in envelope changes tx hash
        let mut env_tampered_salt = tx.pq_envelope().unwrap();
        env_tampered_salt.salt[0] ^= 0xFF;
        let mut tx_mutated_salt = tx.clone();
        tx_mutated_salt.signature = env_tampered_salt.encode();
        assert_ne!(
            baseline_hash,
            tx_mutated_salt.compute_tx_hash(),
            "Mutating envelope salt must change compute_tx_hash"
        );

        // 3. Modifying public key in envelope changes tx hash
        let mut env_tampered_pk = tx.pq_envelope().unwrap();
        env_tampered_pk.pubkey.as_mut().unwrap()[5] ^= 0xFF;
        let mut tx_mutated_pk = tx.clone();
        tx_mutated_pk.signature = env_tampered_pk.encode();
        assert_ne!(
            baseline_hash,
            tx_mutated_pk.compute_tx_hash(),
            "Mutating envelope public key must change compute_tx_hash"
        );

        // 4. Verify explicit SEC-PQ-07 commitment layout:
        // Hasher includes prefix b"PQ_ENV" followed by &self.signature
        let mut manual_hasher = Sha256::new();
        manual_hasher.update(tx.from);
        manual_hasher.update(tx.to);
        manual_hasher.update(tx.amount.to_be_bytes());
        manual_hasher.update(tx.gas_limit.to_be_bytes());
        manual_hasher.update(tx.nonce.to_be_bytes());
        manual_hasher.update(tx.source_shard.to_be_bytes());
        manual_hasher.update(tx.target_shard.to_be_bytes());
        manual_hasher.update(b"PAYLOAD");
        let payload_bytes = bincode::serialize(&tx.payload).unwrap();
        manual_hasher.update((payload_bytes.len() as u32).to_be_bytes());
        manual_hasher.update(&payload_bytes);
        manual_hasher.update(b"PQ_ENV");
        manual_hasher.update(&tx.signature);
        let expected_hash: [u8; 32] = manual_hasher.finalize().into();
        assert_eq!(
            baseline_hash, expected_hash,
            "compute_tx_hash must bind b\"PQ_ENV\" and &self.signature"
        );
    }

    #[test]
    fn test_legacy_tx_hash_remains_byte_identical() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let to = [4u8; 32];
        let amount = 2500;
        let gas_limit = 21_000;
        let nonce = 7;
        let source_shard = 0;
        let target_shard = 0;

        let tx = Transaction::sign(
            &sk,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
        );
        assert!(!tx.is_pq(), "Legacy transaction must not be marked as PQ");
        assert_eq!(tx.signature.len(), 64);

        let tx_hash = tx.compute_tx_hash();

        // Exact pre-PQ legacy transaction hash algorithm
        let mut legacy_hasher = Sha256::new();
        legacy_hasher.update(tx.from);
        legacy_hasher.update(tx.to);
        legacy_hasher.update(tx.amount.to_be_bytes());
        legacy_hasher.update(tx.gas_limit.to_be_bytes());
        legacy_hasher.update(tx.nonce.to_be_bytes());
        legacy_hasher.update(tx.source_shard.to_be_bytes());
        legacy_hasher.update(tx.target_shard.to_be_bytes());
        legacy_hasher.update(b"PAYLOAD");
        let payload_bytes = bincode::serialize(&tx.payload).unwrap();
        legacy_hasher.update((payload_bytes.len() as u32).to_be_bytes());
        legacy_hasher.update(&payload_bytes);
        // Note: no PQ_ENV commitment added for legacy
        let expected_legacy_hash: [u8; 32] = legacy_hasher.finalize().into();

        assert_eq!(
            tx_hash, expected_legacy_hash,
            "Legacy transaction hash must remain strictly byte-identical"
        );

        // Modifying signature on legacy transaction does NOT change compute_tx_hash (preserving legacy semantics)
        let mut tx_mutated_sig = tx.clone();
        tx_mutated_sig.signature[0] ^= 0xFF;
        assert_eq!(
            tx_mutated_sig.compute_tx_hash(),
            tx_hash,
            "Legacy tx hash does not bind signature, preserving backward compatibility"
        );
    }

    #[test]
    fn test_cross_shard_verification_target_shard_pinned_pq_account() {
        // Audit finding SEC-PQ-03: When a pinned account on Shard 1 sends an implicit
        // cross-shard transfer to Shard 2, Shard 2 doesn't have the public key in local RAM.
        // CrossShardMessage carries `sender_pubkey_hash` and `sender_scheme`, enabling
        // Shard 2 to construct the 49-byte leaf and verify inclusion without local RAM keys!

        let seed = 0x88;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = DEFAULT_SALT;
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);
        let to = [0x55u8; 32];
        let amount = 3_000u64;
        let nonce = 5u64;
        let source_balance = 15_000u64;

        // 1. Build an implicit PQ transaction (omitting public key from wire)
        let mut tx_probe = Transaction {
            from,
            to,
            amount,
            gas_limit: 40_000,
            nonce,
            source_shard: 1,
            target_shard: 2,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg = tx_probe.signing_message();
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
        let implicit_envelope = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig);
        tx_probe.signature = implicit_envelope.encode();

        assert!(tx_probe.is_pq());
        assert!(tx_probe.is_pq_implicit());

        // 2. Set up the 49-byte leaf in Shard 1's state trie:
        //    account_value (16B) || scheme (1B) || pubkey_hash (32B)
        let pk_hash = blake3::hash(&pk);
        let leaf_49 = crate::cpat2::AccountLeaf::new_pinned(
            source_balance,
            nonce,
            PqScheme::Falcon512.id(),
            *pk_hash.as_bytes(),
        )
        .encode();
        assert_eq!(leaf_49.len(), crate::cpat2::ACCOUNT_LEAF_LEN_PQ);

        let mut trie = PatriciaTrie::new();
        trie.insert(&from, &leaf_49);
        let source_state_root = trie.root_hash();
        let proof = trie.generate_merkle_proof(&from).expect("merkle proof");

        // Register the key in Shard 1's local implicit registry before producing the message
        Transaction::global_implicit_registry()
            .register(from, PqScheme::Falcon512, &pk, &salt)
            .expect("register implicit key on source shard");

        let finalized_in_block = [0xAAu8; 32];
        let cross_msg = CrossShardMessage::new(
            1,
            2,
            tx_probe.clone(),
            source_state_root,
            finalized_in_block,
            Some(proof.clone()),
        )
        .with_source_balance(source_balance);

        // Verify that CrossShardMessage::new automatically populated sender_pubkey_hash and sender_scheme
        assert_eq!(cross_msg.sender_scheme, Some(PqScheme::Falcon512.id()));
        assert_eq!(cross_msg.sender_pubkey_hash, Some(*pk_hash.as_bytes()));

        // 3. Simulate wire transmission to Shard 2 via bincode serialization/deserialization
        let wire_bytes = bincode::serialize(&cross_msg).expect("serialize CrossShardMessage");
        let received_msg: CrossShardMessage =
            bincode::deserialize(&wire_bytes).expect("deserialize CrossShardMessage");

        assert_eq!(received_msg.sender_scheme, Some(PqScheme::Falcon512.id()));
        assert_eq!(received_msg.sender_pubkey_hash, Some(*pk_hash.as_bytes()));

        // 4. On Shard 2: verify inclusion strictly without needing local RAM keys!
        assert!(
            received_msg.verify_inclusion(),
            "Target shard must verify 49-byte leaf inclusion proof using sender_pubkey_hash metadata"
        );
        assert!(
            received_msg.verify_inclusion_strict(),
            "Strict untrusted verification must succeed without local keys"
        );

        // 5. Tampering detection:
        // (a) Tampered sender_pubkey_hash must fail proof verification
        let mut tampered_pk_hash_msg = received_msg.clone();
        tampered_pk_hash_msg.sender_pubkey_hash = Some([0xEEu8; 32]);
        assert!(
            !tampered_pk_hash_msg.verify_inclusion(),
            "Tampered sender_pubkey_hash must be rejected"
        );

        // (b) Tampered sender_scheme must fail proof verification
        let mut tampered_scheme_msg = received_msg.clone();
        tampered_scheme_msg.sender_scheme = Some(PqScheme::Ed25519.id());
        assert!(
            !tampered_scheme_msg.verify_inclusion(),
            "Tampered sender_scheme must be rejected"
        );

        // (c) Explicit PQ envelope cross-shard message
        let explicit_env =
            PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), vec![0u8; 666]);
        let mut explicit_tx = tx_probe.clone();
        explicit_tx.signature = explicit_env.encode();
        let explicit_msg = CrossShardMessage::new(
            1,
            2,
            explicit_tx,
            source_state_root,
            finalized_in_block,
            Some(proof.clone()),
        )
        .with_source_balance(source_balance);
        assert_eq!(explicit_msg.sender_scheme, Some(PqScheme::Falcon512.id()));
        assert_eq!(explicit_msg.sender_pubkey_hash, Some(*pk_hash.as_bytes()));
        assert!(explicit_msg.verify_inclusion());
    }

    #[tokio::test]
    async fn test_finding_f1_chain_id_binding_ed25519() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let from = sk.verifying_key().to_bytes();
        let to = [0x42u8; 32];
        let chain_id_main = 5757u64;
        let chain_id_alt = 777u64;

        let tx = Transaction::sign_with_chain_id(&sk, to, 1_000, 50_000, 0, 1, 1, chain_id_main);

        assert!(
            tx.is_chain_id_bound(),
            "Transaction must carry CH1 envelope"
        );
        assert_eq!(tx.chain_id(), Some(chain_id_main));
        assert!(tx.verify_signature(), "Self verification must pass");
        assert!(
            tx.verify_signature_for_chain(chain_id_main, true),
            "Verification for target chain must pass"
        );
        assert!(
            !tx.verify_signature_for_chain(chain_id_alt, true),
            "Cross-chain replay on alt chain must be rejected"
        );

        // Tampering with chain_id in envelope invalidates cryptographic signature
        let mut tampered_envelope = tx.clone();
        let offset = 64 + CHAIN_SIG_TAG.len();
        tampered_envelope.signature[offset..offset + 8]
            .copy_from_slice(&chain_id_alt.to_be_bytes());
        assert_eq!(tampered_envelope.chain_id(), Some(chain_id_alt));
        assert!(
            !tampered_envelope.verify_signature(),
            "Tampered chain_id envelope must fail signature verification"
        );

        // Stripping envelope to simulate legacy tx fails because signing_message committed chain_id
        let mut stripped = tx.clone();
        stripped.signature.truncate(64);
        assert_eq!(stripped.chain_id(), None);
        assert!(
            !stripped.verify_signature(),
            "Stripping CH1 envelope must fail signature verification"
        );

        // State engine cross-chain replay rejection
        let engine_main =
            crate::state_engine::InMemoryStateEngine::new().with_chain_id(chain_id_main);
        engine_main.credit_native(&from, 100_000).await.unwrap();
        assert!(
            engine_main.apply_transaction(&tx, 1_000).await.is_ok(),
            "Transaction must apply on matching chain engine"
        );

        let engine_alt =
            crate::state_engine::InMemoryStateEngine::new().with_chain_id(chain_id_alt);
        engine_alt.credit_native(&from, 100_000).await.unwrap();
        let err = engine_alt
            .apply_transaction(&tx, 1_000)
            .await
            .expect_err("Must reject transaction on different chain");
        assert!(
            err.contains("chain_id mismatch"),
            "Error must specify chain_id mismatch: {err}"
        );
    }

    #[test]
    fn test_finding_f1_chain_id_binding_pq() {
        let seed = 0x51;
        let pk = Transaction::sample_falcon512_pubkey(seed);
        let salt = DEFAULT_SALT;
        let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);
        let to = [0x77u8; 32];
        let chain_id_main = 5757u64;
        let chain_id_alt = 999u64;

        let tx_probe = Transaction {
            from,
            to,
            amount: 500,
            gas_limit: 40_000,
            nonce: 0,
            source_shard: 1,
            target_shard: 1,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        let msg = tx_probe.signing_message_for_chain(chain_id_main);
        let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);

        let tx = Transaction::new_pq_explicit_with_chain(
            PqScheme::Falcon512,
            pk,
            sig,
            to,
            500,
            40_000,
            0,
            1,
            1,
            Vec::new(),
            &salt,
            chain_id_main,
        );

        assert!(tx.is_pq());
        assert_eq!(tx.chain_id(), Some(chain_id_main));
        assert!(tx.verify_signature(), "PQ transaction must verify");
        assert!(tx.verify_signature_for_chain(chain_id_main, true));
        assert!(
            !tx.verify_signature_for_chain(chain_id_alt, true),
            "PQ transaction must reject verification for different chain"
        );
    }

    #[test]
    fn test_finding_f1_legacy_compatibility_unaffected() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let to = [0x33u8; 32];
        let tx = Transaction::sign(&sk, to, 100, 21_000, 0, 1, 1);

        assert_eq!(tx.chain_id(), None);
        assert!(!tx.is_chain_id_bound());
        assert_eq!(tx.signature.len(), 64);
        assert_eq!(tx.signing_message().len(), 115);
        assert!(tx.verify_signature());
        assert!(tx.verify_signature_for_chain(5757, false));
        assert!(!tx.verify_signature_for_chain(5757, true));
    }

    #[test]
    fn test_finding_f1_batch_verification_with_chain_bound_tx() {
        let sk1 = SigningKey::generate(&mut rand::rngs::OsRng);
        let sk2 = SigningKey::generate(&mut rand::rngs::OsRng);
        let tx1 = Transaction::sign(&sk1, [1u8; 32], 100, 21_000, 0, 1, 1);
        let tx2 = Transaction::sign_with_chain_id(&sk2, [2u8; 32], 200, 21_000, 0, 1, 1, 5757);

        let txs = vec![tx1, tx2];
        assert!(Transaction::verify_signatures_batch(&txs));
        let results = Transaction::verify_signatures_partitioned(&txs);
        assert_eq!(results, vec![true, true]);
    }

    /// The cross-machine path: a cross-shard message published by one shard
    /// reaches the shard that owns it through the P2P GOSSIP channel, not
    /// through shared process memory or a node-local KV.
    #[tokio::test]
    async fn cross_shard_transport_p2p_routes_messages_between_shards() {
        let bus = crate::network::InMemoryCrossShardPubSub::shared();
        let shard0 = crate::network::CrossShardTransport::p2p(Arc::new(
            crate::network::P2pCrossShardTransport::new(bus.clone(), "epoch-a"),
        ));
        let shard1 = crate::network::CrossShardTransport::p2p(Arc::new(
            crate::network::P2pCrossShardTransport::new(bus.clone(), "epoch-a"),
        ));
        let other_chain = crate::network::CrossShardTransport::p2p(Arc::new(
            crate::network::P2pCrossShardTransport::new(bus.clone(), "epoch-b"),
        ));

        // Subscribe BEFORE the publish: gossip has no replay.
        assert!(shard1.fetch_cross_shard_inbound(2).await.is_empty());
        assert!(other_chain.fetch_cross_shard_inbound(2).await.is_empty());

        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let tx = Transaction::sign(&sk, [7u8; 32], 10, 0, 0, 1, 2);
        let msg = CrossShardMessage::new_trusted(1, 2, tx, [0u8; 32], [3u8; 32]);

        let mut hub = SharedLiquidityHub::new(vec![1, 2]);
        let seq = hub
            .route_cross_shard_message_via(msg.clone(), &shard0)
            .await
            .expect("route through the P2P transport");
        assert!(seq > 0, "an admitted message gets a sequencer position");

        let inbound = shard1.fetch_cross_shard_inbound(2).await;
        assert_eq!(
            inbound.len(),
            1,
            "the destination shard must receive the message over the gossip channel"
        );
        assert_eq!(inbound[0].msg_id, msg.msg_id);
        assert!(
            !inbound[0].trusted,
            "a gossiped message must never be trusted (inclusion proof enforced)"
        );

        // Another chain epoch never hears it: the topic is epoch-scoped.
        assert!(other_chain.fetch_cross_shard_inbound(2).await.is_empty());

        // Replay protection still holds on the transport path.
        let seq2 = hub
            .route_cross_shard_message_via(msg.clone(), &shard0)
            .await
            .expect("a replay is rejected, not an error");
        assert_eq!(seq2, 0, "a replayed message must not be routed again");
        assert!(shard1.fetch_cross_shard_inbound(2).await.is_empty());
    }
}

// ===========================================================================
// Shard topology: split / merge / routing rule — unit tests.
//
// These are the IN-PROCESS tests behind `cargo test --lib sharding`. The
// reproducible LOAD test over a synthetic account set (and the trie
// migration over a real trie) lives in
// `tests/sharding_topology_tests.rs`.
// ===========================================================================
#[cfg(test)]
mod topology_tests {
    use super::*;

    /// A deterministic synthetic account: the address is derived from the
    /// index through splitmix64, so the same set is produced on every run
    /// AND the addresses are spread over the whole 8-byte prefix window
    /// (so both children of the first split are populated).
    fn synthetic_address(i: u64) -> [u8; 32] {
        let mut z = i.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let mut a = [0u8; 32];
        a[..8].copy_from_slice(&z.to_be_bytes());
        a[8..16].copy_from_slice(&z.rotate_left(17).to_be_bytes());
        a
    }

    fn topology_with(n: u64) -> ShardTopology {
        let mut t = ShardTopology::new();
        for i in 0..n {
            t.register_account(synthetic_address(i), 1_000 + i);
        }
        t
    }

    #[test]
    fn published_thresholds_are_what_the_docs_say() {
        assert_eq!(MIN_ACCOUNTS_PER_SHARD, 100);
        assert_eq!(MAX_SHARDS, 16);
        assert_eq!(MAX_PREFIX_BITS, 60);
        assert_eq!(MAX_WORKCHAIN_SHARD_SPACE, 1u64 << 60);
        assert_eq!(SHARD_SPLIT_LOAD_THRESHOLD, 500);
        assert_eq!(SHARD_MERGE_LOAD_THRESHOLD, 50);
        // The advertised space and the shipped cap are deliberately
        // different numbers: the first is the address space, the second is
        // the capacity.
        assert!(MAX_WORKCHAIN_SHARD_SPACE > MAX_SHARDS as u64);
    }

    #[test]
    fn a_bare_address_never_routes_to_the_masterchain() {
        let t = ShardTopology::new();
        for i in 0..64u64 {
            let a = synthetic_address(i);
            let routed = t.route(&ShardAddress::Workchain(a));
            assert_ne!(routed, MASTERCHAIN_SHARD);
            assert_eq!(routed, BASE_WORKCHAIN_SHARD_INITIAL);
        }
        // The masterchain form DOES route to the masterchain.
        assert_eq!(
            t.route(&ShardAddress::Masterchain(synthetic_address(0))),
            MASTERCHAIN_SHARD
        );
    }

    #[test]
    fn the_masterchain_address_form_is_parsed_in_one_place() {
        // `-1:` is the masterchain; `0:` is the masterchain too (shard 0 IS
        // the masterchain id); `N:` names a workchain shard explicitly.
        assert_eq!(split_shard_prefix("-1:abc").0, Some(MASTERCHAIN_SHARD));
        assert_eq!(split_shard_prefix("0:abc").0, Some(MASTERCHAIN_SHARD));
        assert_eq!(split_shard_prefix("7:abc").0, Some(7));
        assert_eq!(split_shard_prefix("abc").0, None);
        assert_eq!(split_shard_prefix("-1:abc").1, "abc");
    }

    #[test]
    fn a_split_reassigns_accounts_by_the_prefix_bit() {
        let mut t = topology_with(1000);
        t.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, 600);

        let transition = t
            .check_and_split(BASE_WORKCHAIN_SHARD_INITIAL)
            .expect("the trigger fires: 1000 accounts, load 600");
        let [c0, c1] = transition.children;

        // Every account is now owned by exactly one child, and the bit at the
        // split depth decides which one.
        for acct in t.all_accounts() {
            let bit = address_prefix_bit(&acct.address, transition.plan.split_bit);
            let owner = t.owner_of(&acct.address).expect("owned");
            let expected = if bit == 0 { c0.shard_id } else { c1.shard_id };
            assert_eq!(owner, expected, "the prefix bit must decide the child");
        }
        // Both children are populated.
        assert!(!t.accounts_of(c0.shard_id).is_empty());
        assert!(!t.accounts_of(c1.shard_id).is_empty());
        // The invariants hold.
        t.verify_invariants()
            .expect("invariants hold after the split");
        // The total balance is conserved.
        assert_eq!(
            t.total_balance(),
            t.shard_balance(c0.shard_id) + t.shard_balance(c1.shard_id)
        );
    }

    #[test]
    fn a_split_refuses_below_the_published_thresholds() {
        // Enough accounts, but not enough load.
        let t = topology_with(1000);
        assert_eq!(
            t.split_preconditions(BASE_WORKCHAIN_SHARD_INITIAL),
            Err(SplitRefusal::LoadTooLow {
                load: 0,
                threshold: SHARD_SPLIT_LOAD_THRESHOLD
            })
        );

        // Enough load, but too few accounts.
        let mut few = ShardTopology::new();
        for i in 0..MIN_ACCOUNTS_PER_SHARD - 1 {
            few.register_account(synthetic_address(i), 1);
        }
        few.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, 600);
        assert_eq!(
            few.split_preconditions(BASE_WORKCHAIN_SHARD_INITIAL),
            Err(SplitRefusal::TooFewAccounts {
                accounts: MIN_ACCOUNTS_PER_SHARD - 1,
                minimum: MIN_ACCOUNTS_PER_SHARD
            })
        );

        // The masterchain never splits.
        assert_eq!(
            t.split_preconditions(MASTERCHAIN_SHARD),
            Err(SplitRefusal::Masterchain)
        );

        // An unknown shard never splits.
        assert_eq!(t.split_preconditions(9999), Err(SplitRefusal::UnknownShard));
    }

    #[test]
    fn the_shard_cap_is_enforced() {
        let mut t = ShardTopology::new();
        // Fill the topology up to the cap by splitting the base shard
        // repeatedly (each split needs the account minimum and the load).
        for i in 0..2000u64 {
            t.register_account(synthetic_address(i), 1);
        }
        let mut guard = 0;
        loop {
            // Find any shard that is eligible and split it.
            let candidates: Vec<ShardId> = t
                .shards()
                .map(|(id, _)| *id)
                .filter(|id| *id != MASTERCHAIN_SHARD)
                .collect();
            let mut progressed = false;
            for id in candidates {
                t.record_tx_load(id, SHARD_SPLIT_LOAD_THRESHOLD);
                if t.check_and_split(id).is_some() {
                    progressed = true;
                    break;
                }
            }
            if !progressed {
                break;
            }
            guard += 1;
            assert!(guard < 64, "the split loop must terminate");
            assert!(
                t.shard_count() <= MAX_SHARDS,
                "the topology must never exceed the published shard cap"
            );
        }
        assert_eq!(t.shard_count(), MAX_SHARDS);
        // With the cap reached, no further split is possible.
        let any_workchain = t
            .shards()
            .map(|(id, _)| *id)
            .find(|id| *id != MASTERCHAIN_SHARD)
            .unwrap();
        assert_eq!(
            t.split_preconditions(any_workchain),
            Err(SplitRefusal::ShardCapReached {
                shards: MAX_SHARDS,
                cap: MAX_SHARDS
            })
        );
    }

    #[test]
    fn a_merge_is_the_inverse_of_the_split() {
        let mut t = topology_with(1000);
        t.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, 600);
        let total_before = t.total_balance();
        let accounts_before = t.all_accounts();

        let transition = t
            .check_and_split(BASE_WORKCHAIN_SHARD_INITIAL)
            .expect("split");
        let [c0, c1] = transition.children;

        // The load the split produced is above the merge threshold, so the
        // merge is refused right away — this is the anti-oscillation rule.
        assert_eq!(
            t.merge_preconditions(c0.shard_id, c1.shard_id),
            Err(MergeRefusal::LoadTooHigh {
                load: 600,
                threshold: SHARD_MERGE_LOAD_THRESHOLD
            })
        );

        // The load window rolls: the shard drains and becomes merge-eligible.
        t.decay_load(SHARD_SPLIT_LOAD_THRESHOLD);
        let merge = t
            .check_and_merge(c0.shard_id, c1.shard_id)
            .expect("merge after the load decayed");

        // Balances are conserved.
        assert_eq!(t.total_balance(), total_before);
        // Every account is back, with its balance.
        let accounts_after = t.all_accounts();
        assert_eq!(accounts_after.len(), accounts_before.len());
        for acct in &accounts_before {
            let now = t
                .accounts_of(merge.parent.shard_id)
                .iter()
                .find(|a| a.address == acct.address)
                .expect("the account is still there");
            assert_eq!(now.balance, acct.balance);
        }
        // The routing prefix is restored to the parent's depth.
        assert_eq!(merge.parent.prefix_len, 0);
        // The invariants hold.
        t.verify_invariants()
            .expect("invariants hold after the merge");
    }

    #[test]
    fn the_topology_converges_and_never_oscillates() {
        let mut t = topology_with(1000);
        t.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, 600);
        t.check_and_split(BASE_WORKCHAIN_SHARD_INITIAL)
            .expect("split");

        // Without new load, the topology is a FIXED POINT: no split and no
        // merge fires. This is the convergence property.
        let shards_after_split = t.shard_count();
        for _ in 0..8 {
            for id in t.shards().map(|(id, _)| *id).collect::<Vec<_>>() {
                assert!(t.check_and_split(id).is_none(), "no split may fire");
            }
            assert_eq!(t.shard_count(), shards_after_split);
        }
    }

    #[test]
    fn non_sibling_shards_never_merge() {
        let mut t = topology_with(1000);
        t.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, 600);
        let split = t
            .check_and_split(BASE_WORKCHAIN_SHARD_INITIAL)
            .expect("split");
        let [c0, _c1] = split.children;

        // The masterchain is never a merge partner.
        assert_eq!(
            t.merge_preconditions(MASTERCHAIN_SHARD, c0.shard_id),
            Err(MergeRefusal::Masterchain)
        );
        // A shard cannot merge with itself.
        assert_eq!(
            t.merge_preconditions(c0.shard_id, c0.shard_id),
            Err(MergeRefusal::NotSiblings)
        );
    }

    #[test]
    fn the_routing_rule_follows_the_split() {
        let mut t = topology_with(200);
        t.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, 600);
        let split = t
            .check_and_split(BASE_WORKCHAIN_SHARD_INITIAL)
            .expect("split");
        let [c0, c1] = split.children;

        for acct in t.all_accounts() {
            let routed = t.route(&ShardAddress::Workchain(acct.address));
            assert_eq!(routed, t.owner_of(&acct.address).unwrap());
            assert!(routed == c0.shard_id || routed == c1.shard_id);
        }
        // The masterchain is still never a bare-address destination.
        for acct in t.all_accounts() {
            assert_ne!(
                t.route(&ShardAddress::Workchain(acct.address)),
                MASTERCHAIN_SHARD
            );
        }
    }

    #[test]
    fn the_address_prefix_bit_matches_the_prefix_word() {
        for i in 0..256u64 {
            let a = synthetic_address(i);
            // The full word reproduces the address bits exactly.
            let word = address_prefix_word(&a, 64);
            for bit in 0..8u8 {
                assert_eq!(address_prefix_bit(&a, bit), prefix_word_bit(word, bit));
            }
            // A truncated prefix word keeps the leading bits and zeroes the
            // rest — the same convention as a shard descriptor.
            for len in 0..=8u8 {
                let p = address_prefix_word(&a, len);
                if len == 0 {
                    assert_eq!(p, 0);
                } else {
                    // The bits BELOW the prefix are zeroed.
                    assert_eq!(p & !(!0u64 << (64 - len as u64)), 0);
                }
                for bit in 0..len {
                    assert_eq!(prefix_word_bit(p, bit), address_prefix_bit(&a, bit));
                }
            }
        }
    }

    #[test]
    fn the_topology_report_publishes_the_thresholds() {
        let t = topology_with(1000);
        let report = t.report();
        assert_eq!(
            report.parameters.min_accounts_per_shard,
            MIN_ACCOUNTS_PER_SHARD
        );
        assert_eq!(report.parameters.max_shards, MAX_SHARDS);
        assert_eq!(
            report.parameters.split_load_threshold,
            SHARD_SPLIT_LOAD_THRESHOLD
        );
        assert_eq!(
            report.parameters.merge_load_threshold,
            SHARD_MERGE_LOAD_THRESHOLD
        );
        assert_eq!(report.parameters.max_prefix_bits, MAX_PREFIX_BITS);
        assert_eq!(
            report.parameters.max_workchain_shard_space,
            MAX_WORKCHAIN_SHARD_SPACE
        );
        assert_eq!(report.parameters.masterchain_shard, MASTERCHAIN_SHARD);
        assert_eq!(
            report.parameters.base_workchain_shard,
            BASE_WORKCHAIN_SHARD_INITIAL
        );
        assert_eq!(report.parameters.masterchain_address_form, "-1:<addr>");
        assert_eq!(report.total_accounts, 1000);
        assert_eq!(report.shards.len(), 2);
        // The report is JSON-serializable (the RPC layer serves it).
        let json = serde_json::to_value(&report).expect("serializable");
        assert!(json.get("parameters").is_some());
        assert!(json.get("shards").is_some());
    }
}

/// Decoder fuzz regressions (Agent 1): Transaction/Block bincode decode must
/// never panic on peer bytes (length-prefix / opcode-count / sig abuse).
/// Appended without touching existing code.
#[cfg(test)]
mod decoder_fuzz_regressions {
    use super::*;

    #[test]
    fn tx_and_block_max_prefixes_never_panic() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let tx = Transaction::sign(&sk, [1u8; 32], 10, 5, 0, 1, 1);
        let enc = bincode::serialize(&tx).unwrap();
        let transactions = vec![tx];
        let order_merkle_root = crate::mev::compute_order_merkle_root(&transactions);
        let mut block = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions,
            cross_shard_out: vec![],
            timestamp: 0,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root,
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        block.sign_block(&sk);
        let benc = bincode::serialize(&block).unwrap();
        for base in [&enc, &benc] {
            for i in 0..base.len() {
                if i + 8 <= base.len() {
                    let mut m = base.clone();
                    m[i..i + 8].copy_from_slice(&u64::MAX.to_le_bytes());
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _: Result<Transaction, _> = bincode::deserialize(&m);
                        let _: Result<Block, _> = bincode::deserialize(&m);
                    }));
                    assert!(r.is_ok(), "decode panicked on MAX prefix at {i}");
                }
            }
            for n in 0..base.len() {
                let t = base[..n].to_vec();
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _: Result<Transaction, _> = bincode::deserialize(&t);
                    let _: Result<Block, _> = bincode::deserialize(&t);
                }));
                assert!(r.is_ok(), "decode panicked on truncation len {n}");
            }
        }
    }
}

// ==================== §5 M3: shared sequencer + two-phase atomicity + L2 lane ====================
//
// SCOPE (§5 M3 core). Dynamic split/merge is OUT of scope (non-deterministic by
// load; `DynamicShardManager` wiring untouched). `Block` / `Transaction` gain NO
// new fields (bincode 1.3 compat): every new record rides the pre-existing
// `Block.cross_shard_out: Vec<CrossShardMessage>` field, and the ack/bounce
// kinds below reuse the pre-existing `CrossShardMessage` fields
// (`source_shard` / `target_shard` direction + `bounce` / `bounced` flags).
//
// 1. SHARED SEQUENCER (consensus-adjacent, deterministic). The old
//    `SharedSequencer::sequence_message` counter was Sim-only (call order =
//    whatever the simulator did). The consensus-adjacent rule is
//    [`SharedSequencer::assign_from_block`]: sequence numbers are assigned from
//    COMMITTED block content only, in a global order keyed by
//    `(source_height, source_shard, msg_id)`. Any node replaying the same
//    finalized blocks in `(height, shard)` order derives identical
//    `(CrossShardKey -> seq)` assignments. No wall-clock, no operator input,
//    no network read participates in the ordering rule. The watermark
//    (`note_finalized`) advances only from finalized block content.
// 2. TWO-PHASE ATOMICITY (ack/bounce). M2's source-debit is one-way. M3 adds:
//      * ACK: the target shard, having committed the consumption record,
//        publishes an ack (reversed direction, `bounced == false`). The source
//        shard commits the ack record; the transfer is then COMPLETE and no
//        bounce for it may ever be admitted.
//      * BOUNCE: when the target never consumes (failure/timeout), the source
//        shard commits a bounce-back record after a deterministic TIMEOUT
//        measured in HEIGHTS ([`CROSS_SHARD_TIMEOUT_HEIGHTS`]), refunding
//        `tx.amount` to `tx.from`. A bounce is valid iff the matching outbound
//        is committed on this chain, no ack/bounce for the same transaction
//        completed yet, and `at_height >= produce_height + TIMEOUT`.
//    Replay protection covers acks/bounces under the same [`CrossShardKey`]
//    discipline (each has a distinct `msg_id`), PLUS a per-transaction
//    completion guard (same `tx` hash can complete at most once even across
//    differing carrier hashes) enforced by the runtime.
//    KIND ENCODING (no new fields): with `S = tx.source_shard, T = tx.target_shard`
//      * transfer: `source == S && target == T && !bounced` (proof required);
//      * ack:      `source == T && target == S && !bounced && !bounce` (no proof;
//                  linkage to a committed outbound required);
//      * bounce:   `source == T && target == S && bounced && !bounce` (no proof;
//                  linkage + timeout required).
//    Control records (ack/bounce) MUST carry no Merkle proof: the state engine
//    credits any proof-carrying inbound to `tx.to`, so a proof-carrying
//    reversed-direction record would mint on the source shard. The runtime
//    refuses them (fail closed) and the engine skips proof-less records, which
//    is what makes the refund path safe without a state-engine change.
// 3. L2 SEQUENCING INTERFACE ([`L2Sequencer`] / [`L2Batch`]): a minimal,
//    documented append-only ordering service. Admission rules (contiguous
//    indices, payload-hash binding, signature verification) + ordering
//    guarantee (`(l2_id, batch_index)` FIFO). DA/bridging of L2 state is OUT
//    of scope: this is interface + ordering only; batch transactions reach
//    blocks through normal admission (no new `Block` fields).

/// Timeout for a cross-shard transfer, in SOURCE-shard heights.
///
/// A bounce-back refund for a transaction produced at source height `Hp` may
/// be committed in a source block at height `H` iff `H >= Hp + TIMEOUT`. Pure
/// heights, never seconds: every node applying the same source chain agrees
/// on `Hp` (the height that committed the outbound) and on `H` (the block
/// being validated), so the timeout verdict is deterministic. 64 heights is
/// far beyond any healthy consume+ack latency (2 heights in the honest flow)
/// and short enough that a failed transfer refunds promptly.
pub const CROSS_SHARD_TIMEOUT_HEIGHTS: u64 = 64;

/// True when a bounce-back for an outbound produced at `produce_height` may be
/// committed at `at_height`. Pure function of heights (no clock, no state).
pub fn bounce_eligible(produce_height: u64, at_height: u64) -> bool {
    at_height >= produce_height.saturating_add(CROSS_SHARD_TIMEOUT_HEIGHTS)
}

/// The M3 kind of a [`CrossShardMessage`], derived from its pre-existing
/// fields (direction relative to the carried transaction + flags) and, for
/// the §9 two-phase-commit records, from the `xpc_phase` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossShardKind {
    /// Value transfer `S -> T` (proof required).
    Transfer,
    /// Consumption receipt `T -> S` (linkage required, no value movement).
    Ack,
    /// Refund claim `T -> S` (linkage + timeout required, refunds `tx.from`).
    Bounce,
    /// §9 2PC PREPARE `S -> T` (the source escrows and asks the target to
    /// prepare; NO credit on the target).
    Prepare,
    /// §9 2PC PREPARE-ACK `T -> S` (the target's vote: "I am prepared, I will
    /// credit on the COMMIT"; proven against the target's committed state).
    PrepareAck,
    /// §9 2PC COMMIT `S -> T` (the source's decision; the target credits).
    Commit,
    /// §9 2PC ABORT-REQUEST `S -> T` (the source asks the target to abort a
    /// transfer it never prepared).
    AbortRequest,
    /// §9 2PC ABORT-ACK `T -> S` (the target's authorisation for the source's
    /// refund; proven against the target's committed state).
    AbortAck,
    /// Anything else (not committable; fail closed).
    Unknown,
}

impl CrossShardMessage {
    /// Classify this message without touching its bytes.
    pub fn kind(&self) -> CrossShardKind {
        let s = self.tx.source_shard;
        let t = self.tx.target_shard;
        if s == t {
            return CrossShardKind::Unknown;
        }
        // §9 2PC: a non-zero phase decides the kind on its own. The direction
        // must AGREE with the phase (the phase says who speaks to whom), or
        // the record is refused: a PREPARE travelling target -> source is not
        // a PREPARE, it is a forgery attempt.
        if self.xpc_phase != crate::xshard2pc::XPC_LEGACY {
            return match self.xpc_phase {
                crate::xshard2pc::XPC_PREPARE => {
                    if self.source_shard == s && self.target_shard == t {
                        CrossShardKind::Prepare
                    } else {
                        CrossShardKind::Unknown
                    }
                }
                crate::xshard2pc::XPC_PREPARE_ACK => {
                    if self.source_shard == t && self.target_shard == s {
                        CrossShardKind::PrepareAck
                    } else {
                        CrossShardKind::Unknown
                    }
                }
                crate::xshard2pc::XPC_COMMIT => {
                    if self.source_shard == s && self.target_shard == t {
                        CrossShardKind::Commit
                    } else {
                        CrossShardKind::Unknown
                    }
                }
                crate::xshard2pc::XPC_ABORT_REQUEST => {
                    if self.source_shard == s && self.target_shard == t {
                        CrossShardKind::AbortRequest
                    } else {
                        CrossShardKind::Unknown
                    }
                }
                crate::xshard2pc::XPC_ABORT_ACK => {
                    if self.source_shard == t && self.target_shard == s {
                        CrossShardKind::AbortAck
                    } else {
                        CrossShardKind::Unknown
                    }
                }
                _ => CrossShardKind::Unknown,
            };
        }
        match (
            self.source_shard,
            self.target_shard,
            self.bounced,
            self.bounce,
        ) {
            (a, b, false, _) if a == s && b == t => CrossShardKind::Transfer,
            (a, b, false, false) if a == t && b == s => CrossShardKind::Ack,
            (a, b, true, false) if a == t && b == s => CrossShardKind::Bounce,
            _ => CrossShardKind::Unknown,
        }
    }

    /// True for a value transfer `S -> T` (the only M2 kind).
    pub fn is_transfer(&self) -> bool {
        self.kind() == CrossShardKind::Transfer
    }

    /// True for a consumption receipt `T -> S`.
    pub fn is_ack(&self) -> bool {
        self.kind() == CrossShardKind::Ack
    }

    /// True for a refund claim `T -> S`.
    pub fn is_bounce(&self) -> bool {
        self.kind() == CrossShardKind::Bounce
    }

    /// True for a §9 two-phase-commit record of any phase.
    pub fn is_xpc(&self) -> bool {
        self.xpc_phase != crate::xshard2pc::XPC_LEGACY
    }

    /// True for the §9 PREPARE record (`S -> T`).
    pub fn is_prepare(&self) -> bool {
        self.kind() == CrossShardKind::Prepare
    }

    /// True for the §9 PREPARE-ACK record (`T -> S`).
    pub fn is_prepare_ack(&self) -> bool {
        self.kind() == CrossShardKind::PrepareAck
    }

    /// True for the §9 COMMIT record (`S -> T`).
    pub fn is_commit(&self) -> bool {
        self.kind() == CrossShardKind::Commit
    }

    /// True for the §9 ABORT-REQUEST record (`S -> T`).
    pub fn is_abort_request(&self) -> bool {
        self.kind() == CrossShardKind::AbortRequest
    }

    /// True for the §9 ABORT-ACK record (`T -> S`).
    pub fn is_abort_ack(&self) -> bool {
        self.kind() == CrossShardKind::AbortAck
    }

    /// True for a record that NEVER moves value by itself: the legacy ack and
    /// bounce, and every §9 2PC control record.
    ///
    /// The state engine credits an inbound record to `tx.to` whenever it
    /// carries a Merkle proof, so a control record that carried one would MINT
    /// on the wrong shard. The engine therefore skips every control record
    /// and the runtime performs the value movement itself (the bounce refund,
    /// the 2PC commit credit) under the linkage rules.
    pub fn is_control(&self) -> bool {
        matches!(
            self.kind(),
            CrossShardKind::Ack
                | CrossShardKind::Bounce
                | CrossShardKind::PrepareAck
                | CrossShardKind::Commit
                | CrossShardKind::AbortRequest
                | CrossShardKind::AbortAck
        )
    }

    /// Build a §9 TWO-PHASE-COMMIT record.
    ///
    /// The message id commits to the PHASE, so the records of one transfer
    /// never collide in the transport mailbox (which is keyed by `msg_id`) and
    /// a replay of one phase can never be mistaken for another. The legacy
    /// `msg_id` computation is untouched: a legacy record keeps its
    /// byte-identical id (and therefore its byte-identical replay key).
    pub fn new_xpc(
        phase: u8,
        source_shard: ShardId,
        target_shard: ShardId,
        tx: Transaction,
        source_state_root: CellHash,
        finalized_in_block: [u8; 32],
        proof: Option<MerkleProof>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"XPC2");
        hasher.update([phase]);
        hasher.update(source_shard.to_be_bytes());
        hasher.update(target_shard.to_be_bytes());
        hasher.update(tx.compute_tx_hash());
        hasher.update(finalized_in_block);
        let msg_id = hasher.finalize().into();

        let mut m = Self::new(
            source_shard,
            target_shard,
            tx,
            source_state_root,
            finalized_in_block,
            proof,
        );
        m.msg_id = msg_id;
        // The legacy flags are unused by the 2PC records: `bounce` /
        // `bounced` stay at their neutral values so the legacy kind
        // derivation can never classify a 2PC record.
        m.bounce = false;
        m.bounced = false;
        m.source_balance = 0;
        m.xpc_phase = phase;
        m
    }

    /// Verify the §9 2PC STATE PROOF carried by this record.
    ///
    /// The proof is a Merkle inclusion proof of the 2PC state leaf of the
    /// carried transaction in the PEER's state trie, at the peer's committed
    /// state root. The leaf value is `phase || tx_hash`, and both halves are
    /// known to the verifier (the phase from the record's kind, the
    /// transaction hash from the carried transaction), so the proof is
    /// checkable by anyone holding the message.
    ///
    /// `phases` lists the phases that are acceptable for this record: the
    /// COMMIT record accepts PREPARED (the source escrowed) and COMMITTED
    /// (the source already decided), the PREPARE-ACK accepts PREPARED, the
    /// ABORT-ACK accepts ABORTED.
    ///
    /// SECURITY: the local `trusted` shortcut is IGNORED, exactly like
    /// [`Self::verify_inclusion_strict`] does for the legacy transfer. A 2PC
    /// control record moves value (the COMMIT credits the recipient, the
    /// ABORT-ACK refunds the escrow), so its proof must ALWAYS be checked
    /// against the peer's committed state root. The `trusted` flag is a
    /// locally-produced convenience; it is cleared on every wire decode
    /// (`network::parse_cross_shard_incoming`), so a peer can never set it -
    /// but a 2PC record that skipped the proof would be a mint vector, and
    /// the check is cheap.
    pub fn verify_xpc_proof(&self, phases: &[crate::xshard2pc::XpcPhase]) -> bool {
        let Some(proof) = &self.merkle_inclusion_proof else {
            return false;
        };
        let tx_hash = self.tx.compute_tx_hash();
        let key = crate::xshard2pc::xpc_state_key(&tx_hash);
        phases.iter().any(|phase| {
            let value = crate::xshard2pc::xpc_state_value(*phase, &tx_hash);
            PatriciaTrie::verify_merkle_proof(&self.source_state_root, &key, &value, proof)
        })
    }

    /// Anchored verification of a §9 2PC state proof: the proof must check
    /// out against a state root that a LOCALLY FINALIZED header of the
    /// peer's shard committed to.
    ///
    /// This is the C1 anchor applied to the 2PC: the peer's quorum signed the
    /// block that carries that state root, so the peer's vote (PREPARE-ACK /
    /// ABORT-ACK) cannot be forged by a malicious peer.
    pub fn verify_xpc_anchored(
        &self,
        registry: Option<&FinalizedHeaderRegistry>,
        phases: &[crate::xshard2pc::XpcPhase],
    ) -> bool {
        let Some(reg) = registry else {
            return false;
        };
        if !reg.anchor_holds(
            self.source_shard,
            &self.finalized_in_block,
            &self.source_state_root,
        ) {
            return false;
        }
        self.verify_xpc_proof(phases)
    }

    /// Build the ack for a consumed transfer. The ack travels `T -> S`
    /// carrying the SAME transaction (linkage is by `tx` hash), with
    /// `consumed_in` naming the target block that committed the consumption
    /// (part of the deterministic `msg_id`, identical on every node that
    /// applied the same target block). No proof: the engine skips proof-less
    /// inbound records, and the source validates by linkage, not by proof.
    pub fn new_ack(tx: Transaction, consumed_in: [u8; 32]) -> Self {
        let mut m = Self::new(
            tx.target_shard,
            tx.source_shard,
            tx,
            [0u8; 32],
            consumed_in,
            None,
        );
        m.bounce = false;
        m.bounced = false;
        m.source_balance = 0;
        m
    }

    /// Build the bounce-back refund claim for a transfer that never completed.
    /// Same shape as an ack but `bounced == true`; the source shard credits
    /// `tx.amount` back to `tx.from` when it commits this record (after the
    /// timeout rule passes). `refunded_at` should be the source head the
    /// refunding block extends (deterministic per height). No proof, same
    /// reason as [`Self::new_ack`].
    pub fn new_bounce(tx: Transaction, refunded_at: [u8; 32]) -> Self {
        let mut m = Self::new(
            tx.target_shard,
            tx.source_shard,
            tx,
            [0u8; 32],
            refunded_at,
            None,
        );
        m.bounce = false;
        m.bounced = true;
        m.source_balance = 0;
        m
    }
}

impl SharedSequencer {
    /// Deterministically assign global sequence numbers to every cross-shard
    /// record in a FINALIZED block.
    ///
    /// ORDERING RULE (the M3 contract): records sort by
    /// `(block.height, msg.source_shard, msg.msg_id)` — source height first
    /// (causality across shards), then source shard (cross-shard tie-break),
    /// then message id (within-block tie-break). Each unseen
    /// [`CrossShardKey`] takes `next_sequence()` and the counter advances;
    /// already-sequenced keys keep their number (idempotent replay). Feed
    /// blocks in `(height, shard)` order and any two nodes derive identical
    /// assignments from identical chains. Returns the assignments in global
    /// order.
    pub fn assign_from_block(&mut self, block: &Block) -> Vec<(u64, CrossShardKey)> {
        let mut keys: Vec<CrossShardKey> = block
            .cross_shard_out
            .iter()
            .map(CrossShardKey::of)
            .collect();
        // Total order, independent of the carrier vec's order (KV enumeration
        // order must never leak into consensus-adjacent numbering).
        keys.sort_by(|a, b| {
            // `block.height` is common; order by (source_shard, msg_id, carrier).
            (a.source_shard, a.msg_id, a.finalized_in_block).cmp(&(
                b.source_shard,
                b.msg_id,
                b.finalized_in_block,
            ))
        });
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let seq = match self.sequence_of(&key) {
                Some(s) => s,
                None => {
                    let s = self.current_sequence;
                    self.current_sequence += 1;
                    // Keep the legacy schedule vector consistent (Sim reads it).
                    if let Some(msg) = block
                        .cross_shard_out
                        .iter()
                        .find(|m| CrossShardKey::of(m) == key)
                    {
                        self.scheduled_cross_shard.push((s, msg.clone()));
                    }
                    s
                }
            };
            out.push((seq, key));
        }
        // The watermark is finalized-block content only: the highest sequenced
        // source height per shard, advanced monotonically here.
        let wm = self.watermark.entry(block.shard_id).or_insert(0);
        if block.height > *wm {
            *wm = block.height;
        }
        out
    }

    /// The sequence number of an already-sequenced message, if any.
    pub fn sequence_of(&self, key: &CrossShardKey) -> Option<u64> {
        self.scheduled_cross_shard
            .iter()
            .find(|(_, m)| CrossShardKey::of(m) == *key)
            .map(|(s, _)| *s)
    }

    /// The next sequence number to be assigned.
    pub fn next_sequence(&self) -> u64 {
        self.current_sequence
    }

    /// Highest sequenced source height per shard (the sequencer watermark).
    /// Advanced ONLY by [`Self::assign_from_block`] / [`Self::note_finalized`]
    /// on finalized blocks — never by time or by operator action.
    pub fn watermark(&self) -> &std::collections::BTreeMap<ShardId, u64> {
        &self.watermark
    }

    /// Advance the watermark for a finalized `(shard, height)` without
    /// assigning numbers (e.g. a finalized block with no cross-shard records).
    /// Monotonic: a stale height never moves it backwards.
    pub fn note_finalized(&mut self, source_shard: ShardId, height: u64) {
        let wm = self.watermark.entry(source_shard).or_insert(0);
        if height > *wm {
            *wm = height;
        }
    }
}

// ==================== L2 sequencing interface ====================
//
// A minimal append-only ordering service through which an EXTERNAL L2 submits
// ordered batches for inclusion.
//
// * APPEND-ONLY: per L2, `batch_index` must be exactly the next expected
//   index — no gaps, no overwrites, no reordering. A batch that skips an
//   index is rejected until the missing one arrives; a duplicate index is
//   rejected.
// * ADMISSION: every batch binds its transactions by `payload_hash`
//   (recomputed and compared), every transaction signature must verify, and
//   batches are size-capped. Nothing unverifiable is ever queued.
// * ORDERING GUARANTEE: [`L2Sequencer::batches_for_inclusion`] yields pending
//   batches in canonical `(l2_id, batch_index)` order — FIFO per L2,
//   deterministic across L2s. A proposer pulling in that order gives every
//   node the same L2-derived prefix for the same pending set.
// * OUT OF SCOPE (explicit): DA/bridging of L2 state, execution of L2
//   semantics, and any `Block` format change. Batch transactions are ordinary
//   [`Transaction`]s and reach blocks through normal admission; this is
//   interface + ordering guarantees only.

/// Maximum transactions in one L2 batch (anti-DoS bound on a single submit).
pub const L2_MAX_TXS_PER_BATCH: usize = 1024;

/// One externally-submitted L2 batch: an ordered list of transactions with a
/// binding payload hash. Never embedded in `Block` (no format change); the
/// sequencer only orders batches, and inclusion reuses normal tx admission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L2Batch {
    /// Which L2 this batch belongs to (namespaces the index sequence).
    pub l2_id: u32,
    /// Append-only position within `l2_id` (0-based, contiguous).
    pub batch_index: u64,
    /// The transactions, in submission order (inclusion must preserve it).
    pub txs: Vec<Transaction>,
    /// Binding commitment over `txs` (recomputed and checked at admission).
    pub payload_hash: [u8; 32],
}

impl L2Batch {
    /// Build a batch, computing the binding payload hash.
    pub fn new(l2_id: u32, batch_index: u64, txs: Vec<Transaction>) -> Self {
        let payload_hash = Self::payload_hash_of(&txs);
        Self {
            l2_id,
            batch_index,
            txs,
            payload_hash,
        }
    }

    /// The binding commitment: `sha256(count || tx_hash_0 || tx_hash_1 || ..)`.
    /// Order-sensitive, so a reordered batch has a different hash.
    pub fn payload_hash_of(txs: &[Transaction]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"STELLEREUM_L2_BATCH_V1");
        hasher.update((txs.len() as u64).to_be_bytes());
        for t in txs {
            hasher.update(t.compute_tx_hash());
        }
        hasher.finalize().into()
    }

    /// Admission verification: non-empty, size-capped, hash-bound, and every
    /// transaction signature verifies. Fails closed on any violation.
    pub fn verify(&self) -> Result<(), String> {
        if self.txs.is_empty() {
            return Err("L2 batch carries no transactions".to_string());
        }
        if self.txs.len() > L2_MAX_TXS_PER_BATCH {
            return Err(format!(
                "L2 batch of {} txs exceeds the cap of {}",
                self.txs.len(),
                L2_MAX_TXS_PER_BATCH
            ));
        }
        if self.payload_hash != Self::payload_hash_of(&self.txs) {
            return Err("L2 batch payload hash does not bind its transactions".to_string());
        }
        if !Transaction::verify_signatures_batch(&self.txs) {
            return Err("L2 batch contains a bad transaction signature".to_string());
        }
        Ok(())
    }
}

/// Append-only per-L2 batch sequencer. All state is a pure function of the
/// submitted batches (no clock, no network); ordering is the canonical
/// `(l2_id, batch_index)` order.
#[derive(Clone, Debug, Default)]
pub struct L2Sequencer {
    /// Next expected `batch_index` per L2 (starts at 0).
    expected: HashMap<u32, u64>,
    /// Admitted but not yet included, in canonical order.
    pending: std::collections::BTreeMap<(u32, u64), L2Batch>,
    /// Highest included `batch_index` per L2 (pruning watermark).
    included_through: HashMap<u32, u64>,
}

impl L2Sequencer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit one batch. Accepts it iff it verifies AND its index is exactly
    /// the next expected for its L2 (append-only: gaps and duplicates are
    /// rejected, never queued).
    pub fn submit_batch(&mut self, batch: L2Batch) -> Result<(), String> {
        batch.verify()?;
        let next = self.expected.get(&batch.l2_id).copied().unwrap_or(0);
        if batch.batch_index != next {
            return Err(format!(
                "L2 {} batch index {} is not the next expected ({next}): gaps and duplicates are rejected",
                batch.l2_id, batch.batch_index
            ));
        }
        self.pending
            .insert((batch.l2_id, batch.batch_index), batch.clone());
        self.expected.insert(batch.l2_id, next + 1);
        Ok(())
    }

    /// The next expected batch index for an L2 (0 for a never-seen L2).
    pub fn expected_index(&self, l2_id: u32) -> u64 {
        self.expected.get(&l2_id).copied().unwrap_or(0)
    }

    /// Pending batches in canonical inclusion order (`(l2_id, batch_index)`
    /// ascending), up to `limit`. A proposer taking a prefix of this list
    /// preserves the ordering guarantee.
    pub fn batches_for_inclusion(&self, limit: usize) -> Vec<L2Batch> {
        self.pending.values().take(limit).cloned().collect()
    }

    /// Number of admitted-but-unincluded batches.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Mark batches through `through_index` (inclusive) for `l2_id` as
    /// included: drops them from pending and advances the prune watermark.
    /// Only moves forward (a stale mark is a no-op, never a rewind).
    pub fn mark_included(&mut self, l2_id: u32, through_index: u64) {
        let cur = self.included_through.get(&l2_id).copied().unwrap_or(0);
        // `through_index` is inclusive; the watermark counts included batches.
        let want = through_index.saturating_add(1);
        if want <= cur {
            return;
        }
        self.included_through.insert(l2_id, want);
        self.pending
            .retain(|(id, idx), _| !(*id == l2_id && *idx <= through_index));
    }

    /// How many batches of `l2_id` have been marked included (0 if none).
    pub fn included_count(&self, l2_id: u32) -> u64 {
        self.included_through.get(&l2_id).copied().unwrap_or(0)
    }
}

// ==================== TON `shard_hashes`: shard-head commitments ====================

/// Tests for the shard-head commitment published by a masterchain block.
#[cfg(test)]
mod shard_header_commitment_tests {
    use super::*;

    fn head(shard_id: ShardId, height: u64, tag: u8) -> ShardHeaderCommitment {
        ShardHeaderCommitment {
            shard_id,
            height,
            block_hash: [tag; 32],
            state_root: [tag.wrapping_add(1); 32],
            timestamp: 1_700_000_000 + height,
        }
    }

    fn block_with(headers: Vec<ShardHeaderCommitment>) -> Block {
        Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 10,
            prev_hash: [0xAB; 32],
            state_root: [0xCD; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_500,
            proposer: [0xEF; 32],
            validator_signatures: vec![],
            precommit_qc: None,
            last_qc: None,
            shard_headers: headers,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        }
    }

    #[test]
    fn block_hash_commits_the_shard_heads() {
        let a = block_with(vec![head(1, 5, 0x01)]);
        let b = block_with(vec![head(1, 5, 0x01)]);
        assert_eq!(a.compute_hash(), b.compute_hash(), "same head => same hash");

        // Every field of the commitment is bound: a different height, hash,
        // root or timestamp MUST move the block hash.
        let mut other_height = a.clone();
        other_height.shard_headers[0].height += 1;
        assert_ne!(a.compute_hash(), other_height.compute_hash());

        let mut other_hash = a.clone();
        other_hash.shard_headers[0].block_hash = [0x77; 32];
        assert_ne!(a.compute_hash(), other_hash.compute_hash());

        let mut other_root = a.clone();
        other_root.shard_headers[0].state_root = [0x78; 32];
        assert_ne!(a.compute_hash(), other_root.compute_hash());

        let mut other_time = a.clone();
        other_time.shard_headers[0].timestamp += 1;
        assert_ne!(a.compute_hash(), other_time.compute_hash());

        // An extra shard head is bound too (the set is length-prefixed).
        let mut two = a.clone();
        two.shard_headers.push(head(2, 6, 0x02));
        assert_ne!(a.compute_hash(), two.compute_hash());
    }

    #[test]
    fn a_block_without_shard_heads_keeps_its_legacy_hash() {
        // The commitment is mixed in ONLY for a non-empty set, so a block that
        // publishes no shard head hashes exactly as it did before the field
        // existed (legacy chains keep their block hashes byte-for-byte).
        let legacy = block_with(vec![]);
        let mut with_empty = legacy.clone();
        with_empty.shard_headers = vec![];
        assert_eq!(legacy.compute_hash(), with_empty.compute_hash());

        // ...and adding a head MUST change it, otherwise the quorum would
        // sign a block whose shard roots are not covered.
        let mut with_head = legacy.clone();
        with_head.shard_headers.push(head(1, 5, 0x01));
        assert_ne!(legacy.compute_hash(), with_head.compute_hash());
    }

    /// FORK COMPATIBILITY (V5 Tier-2 MMR): the epoch-MMR trailing field does
    /// not move any pre-existing block hash, and a new block that commits to
    /// no epoch (zero root) hashes identically to a legacy block — so old
    /// signatures over the parts old nodes understand keep verifying.
    /// A non-zero root MUST move the hash (otherwise the quorum would sign a
    /// root it is not bound to), and the commitment must survive the bincode
    /// round-trip.
    #[test]
    fn epoch_mmr_root_keeps_legacy_hashes_and_moves_hash_when_set() {
        let legacy = block_with(vec![]);
        assert_eq!(
            legacy.mmr_epoch_root, [0u8; 32],
            "a pre-MMR block commits to no epoch"
        );
        let legacy_hash = legacy.compute_hash();

        // A new block with a ZERO root is hash-identical to the legacy
        // block: an old node verifies its proposer signature against the
        // same preimage it always did.
        let mut zero = legacy.clone();
        zero.mmr_epoch_root = [0u8; 32];
        assert_eq!(zero.compute_hash(), legacy_hash);

        // The signature made over the legacy shape verifies on the zero-root
        // block (same hash, same preimage).
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut signed = legacy.clone();
        signed.proposer = sk.verifying_key().to_bytes();
        signed.sign_block(&sk);
        let mut signed_zero = signed.clone();
        signed_zero.mmr_epoch_root = [0u8; 32];
        assert!(signed_zero.verify_proposer_signature());

        // A NON-ZERO root moves the hash (the quorum signs the root too) and
        // two different roots are two different blocks.
        let mut committed = legacy.clone();
        committed.mmr_epoch_root = [0x42; 32];
        assert_ne!(committed.compute_hash(), legacy_hash);
        let mut other = legacy.clone();
        other.mmr_epoch_root = [0x43; 32];
        assert_ne!(committed.compute_hash(), other.compute_hash());

        // The commitment survives the bincode round-trip (strict wire path:
        // no tolerance needed for a complete body).
        let bytes = bincode::serialize(&committed).expect("must encode");
        let decoded: Block = bincode::deserialize(&bytes).expect("must decode");
        assert_eq!(decoded.mmr_epoch_root, [0x42; 32]);
        assert_eq!(decoded.compute_hash(), committed.compute_hash());

        // A legacy byte stream (field absent) still decodes tolerantly to
        // the zero root — and therefore to the legacy hash.
        let legacy_shaped = Block {
            shard_id: legacy.shard_id,
            height: legacy.height,
            prev_hash: legacy.prev_hash,
            state_root: legacy.state_root,
            transactions: legacy.transactions.clone(),
            cross_shard_out: legacy.cross_shard_out.clone(),
            timestamp: legacy.timestamp,
            proposer: legacy.proposer,
            validator_signatures: legacy.validator_signatures.clone(),
            precommit_qc: legacy.precommit_qc.clone(),
            last_qc: legacy.last_qc.clone(),
            shard_headers: legacy.shard_headers.clone(),
            order_merkle_root: legacy.order_merkle_root,
            epoch_key_commitment: legacy.epoch_key_commitment,
            mmr_epoch_root: [0u8; 32],
        };
        assert_eq!(legacy_shaped.compute_hash(), legacy_hash);
    }

    #[test]
    fn canonical_shard_head_sets_are_ascending_and_never_self_referential() {
        assert!(block_with(vec![head(1, 5, 0x01), head(2, 6, 0x02)]).shard_headers_canonical());
        assert!(block_with(vec![]).shard_headers_canonical());

        // Descending order is NOT canonical (the set is hashed as a sequence,
        // so two orders would be two different block hashes).
        assert!(!block_with(vec![head(2, 6, 0x02), head(1, 5, 0x01)]).shard_headers_canonical());
        // Duplicates are not canonical either.
        assert!(!block_with(vec![head(1, 5, 0x01), head(1, 6, 0x02)]).shard_headers_canonical());
        // A block never commits to its own head.
        assert!(!block_with(vec![head(MASTERCHAIN_SHARD, 5, 0x01)]).shard_headers_canonical());
    }

    #[test]
    fn shard_head_lookup_by_shard_id() {
        let b = block_with(vec![head(1, 5, 0x01), head(2, 6, 0x02)]);
        assert_eq!(b.shard_head(2).map(|h| h.height), Some(6));
        assert!(b.shard_head(3).is_none());
    }

    /// CROSS-CHAIN REPLAY: the block hash — and therefore every signature over
    /// it — is bound to the chain id. A block signed on the testnet does not
    /// verify on the mainnet, with the very same validator key.
    #[test]
    fn block_hash_and_signature_are_bound_to_chain_id() {
        const TESTNET: u64 = 999_001;
        const MAINNET: u64 = 5757;

        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut block = block_with(vec![]);
        block.proposer = key.verifying_key().to_bytes();

        // Sign on the TESTNET.
        crate::consensus::set_consensus_chain_id_for_tests(TESTNET);
        block.sign_block(&key);
        let testnet_hash = block.compute_hash();
        assert!(
            block.verify_proposer_signature(),
            "the signature verifies on its own chain"
        );

        // On the MAINNET the very same body has a different hash...
        crate::consensus::set_consensus_chain_id_for_tests(MAINNET);
        assert_ne!(
            testnet_hash,
            block.compute_hash(),
            "the block hash must commit to the chain id"
        );
        // ... and the testnet signature does not verify there.
        assert!(
            !block.verify_proposer_signature(),
            "a testnet block signature must NOT verify under a different chain id"
        );

        // Restore the frozen default for the rest of this thread.
        crate::consensus::set_consensus_chain_id_for_tests(0);
    }

    /// Backward compatibility: a block persisted BEFORE the shard-head field
    /// existed (its byte stream ends right after `precommit_qc`) must still
    /// decode — as a block with NO shard heads.
    #[test]
    fn legacy_block_bytes_still_decode() {
        #[derive(serde::Serialize)]
        struct LegacyBlock {
            shard_id: ShardId,
            height: u64,
            prev_hash: [u8; 32],
            state_root: CellHash,
            transactions: Vec<Transaction>,
            cross_shard_out: Vec<CrossShardMessage>,
            timestamp: u64,
            proposer: [u8; 32],
            validator_signatures: Vec<([u8; 32], Vec<u8>)>,
            precommit_qc: Option<crate::consensus::QuorumCertificate>,
        }

        let legacy = LegacyBlock {
            shard_id: MASTERCHAIN_SHARD,
            height: 3,
            prev_hash: [0x11; 32],
            state_root: [0x22; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 42,
            proposer: [0x33; 32],
            validator_signatures: vec![],
            precommit_qc: None,
        };
        let bytes = bincode::serialize(&legacy).expect("legacy block must encode");
        let bytes_len_legacy = bytes.len();
        // The LEGACY shape is tolerated on the STORE path only; the wire
        // decodes strictly (audit W6.4b).
        let decoded: Block = with_legacy_block_tolerance(|| bincode::deserialize(&bytes))
            .expect("legacy block must decode");
        assert_eq!(decoded.height, 3);
        assert_eq!(decoded.state_root, [0x22; 32]);
        assert!(
            decoded.shard_headers.is_empty(),
            "a legacy block commits to no shard heads"
        );
        assert_eq!(
            decoded.order_merkle_root, [0u8; 32],
            "a legacy block commits to no transaction order"
        );
        assert!(
            decoded.last_qc.is_none(),
            "a legacy block carries no canonical downtime evidence"
        );
        assert_eq!(
            decoded.mmr_epoch_root, [0u8; 32],
            "a legacy block commits to no epoch MMR root"
        );
        // The block HASH is untouched by the extension: a legacy block still
        // rehashes to the hash it had before the field existed (this is what
        // keeps an existing chain valid).
        let rebuilt = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 3,
            prev_hash: [0x11; 32],
            state_root: [0x22; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 42,
            proposer: [0x33; 32],
            validator_signatures: vec![],
            precommit_qc: None,
            last_qc: None,
            shard_headers: vec![],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        assert_eq!(decoded.compute_hash(), rebuilt.compute_hash());

        // A block WITH the field round-trips through bincode.
        let modern = block_with(vec![head(1, 5, 0x01)]);
        let bytes = bincode::serialize(&modern).expect("modern block must encode");
        let decoded: Block = bincode::deserialize(&bytes).expect("modern block must decode");
        assert_eq!(decoded.shard_headers, modern.shard_headers);
        assert_eq!(decoded.compute_hash(), modern.compute_hash());

        // The legacy bytes are a PREFIX of the new encoding: the only
        // difference is the trailing shard-head set (empty => 8 bytes), the
        // trailing order commitment (32 bytes), the trailing epoch-key
        // commitment (32 bytes), the trailing canonical-evidence QC
        // (`None` => 1-byte option tag) and the trailing epoch-MMR root
        // (32 bytes).
        let empty = block_with(vec![]);
        let empty_bytes = bincode::serialize(&empty).expect("empty encodes");
        assert_eq!(
            empty_bytes.len(),
            bytes_len_legacy + 8 + 32 + 32 + 1 + 32,
            "the shard-head set adds its (empty) length prefix, the order root adds 32 bytes, \
             the epoch-key commitment adds 32 bytes, the absent evidence QC adds its 1-byte tag \
             and the zero epoch-MMR root adds 32 bytes"
        );
    }

    /// The transaction-ORDER commitment is inside the block hash: the quorum
    /// that signs the block hash signs the ORDER, so a proposer cannot change
    /// the order of a block that has already been voted on.
    #[test]
    fn block_hash_commits_the_transaction_order() {
        let base = block_with(vec![]);
        // The all-zero root (no commitment) is the legacy/empty shape: it is
        // NOT mixed into the hash, so legacy blocks keep their hash.
        assert_eq!(base.order_merkle_root, [0u8; 32]);

        let mut committed = base.clone();
        committed.order_merkle_root = [0x42; 32];
        assert_ne!(
            base.compute_hash(),
            committed.compute_hash(),
            "the order commitment must be inside the signed block hash"
        );

        // Two different commitments are two different blocks.
        let mut other = base.clone();
        other.order_merkle_root = [0x43; 32];
        assert_ne!(committed.compute_hash(), other.compute_hash());

        // The commitment survives the bincode round-trip.
        let bytes = bincode::serialize(&committed).expect("must encode");
        let decoded: Block = bincode::deserialize(&bytes).expect("must decode");
        assert_eq!(decoded.order_merkle_root, [0x42; 32]);
        assert_eq!(decoded.compute_hash(), committed.compute_hash());
    }

    /// The registry remembers the newest finalized header per shard and
    /// publishes only the WORKCHAIN ones, in ascending shard order.
    #[test]
    fn registry_publishes_the_latest_workchain_head() {
        let mut reg = FinalizedHeaderRegistry::default();
        reg.note_finalized_commitment(head(1, 5, 0x01));
        reg.note_finalized_commitment(head(2, 3, 0x02));
        // The masterchain's own head is never published (a block cannot
        // commit to its own head).
        reg.note_finalized_commitment(head(MASTERCHAIN_SHARD, 9, 0x03));

        let published = reg.workchain_headers();
        assert_eq!(published.len(), 2);
        assert_eq!(published[0].shard_id, 1);
        assert_eq!(published[1].shard_id, 2, "ascending shard order");

        // A NEWER header replaces the old one...
        reg.note_finalized_commitment(head(1, 6, 0x04));
        assert_eq!(reg.latest_header(1).map(|h| h.height), Some(6));

        // ...and an OLDER one never rolls the published head back.
        reg.note_finalized_commitment(head(1, 2, 0x05));
        assert_eq!(reg.latest_header(1).map(|h| h.height), Some(6));

        // The anchor map is updated as well (cross-shard inclusion anchoring).
        assert!(reg.anchor_holds(1, &[0x04; 32], &[0x05; 32]));
    }

    // -----------------------------------------------------------------------
    // TAIL-1: batched receipt hashing.
    //
    // `compute_tx_hashes_batched` must be byte-identical to mapping
    // `compute_tx_hash` (same per-transaction update sequence, `finalize_reset`
    // restarts the hasher to the same initial state). No wire-format, quorum
    // or state-transition change: the hashes ARE the transaction identities
    // the receipts file, and these tests pin them equal.
    // -----------------------------------------------------------------------

    fn batch_test_txs(n: usize) -> Vec<Transaction> {
        use crate::svm::OpCode;
        let mut txs = Vec::with_capacity(n);
        for i in 0..n {
            let mut seed = [0u8; 32];
            seed[0..8]
                .copy_from_slice(&(i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15).to_be_bytes());
            seed[8] = 0xB7;
            let sk = SigningKey::from_bytes(&seed);
            // Vary the payload shape (empty / small / multi-op) and the bid
            // so every conditional commitment arm is covered.
            let payload = match i % 4 {
                0 => vec![],
                1 => vec![OpCode::Push(i as u64), OpCode::Push(1), OpCode::Add],
                2 => vec![OpCode::Transfer {
                    recipient: [i as u8; 32],
                    amount: i as u64,
                }],
                _ => vec![OpCode::Nop, OpCode::Push(i as u64), OpCode::Pop],
            };
            let bid = if i % 5 == 0 { i as u64 } else { 0 };
            txs.push(Transaction::sign_with_payload_and_priority(
                &sk,
                [(i as u8).wrapping_add(1); 32],
                i as u64 * 3,
                21_000 + (i as u64 % 7),
                i as u64,
                0,
                0,
                payload,
                bid,
            ));
        }
        txs
    }

    #[test]
    fn batched_hashes_equal_single_hashes() {
        let txs = batch_test_txs(512);
        let batched = Transaction::compute_tx_hashes_batched(&txs);
        assert_eq!(batched.len(), txs.len());
        for (i, tx) in txs.iter().enumerate() {
            assert_eq!(
                batched[i],
                tx.compute_tx_hash(),
                "batched hash of tx {i} must equal its single hash"
            );
        }
        // Empty input hashes to an empty output (no panic, no allocation).
        assert!(Transaction::compute_tx_hashes_batched(&[]).is_empty());
    }

    /// Perf: single vs batched hashing over a block-sized batch. Prints
    /// measured ms for the report; the hard assertion is byte equality.
    #[test]
    fn perf_batched_vs_single_hashing() {
        let txs = batch_test_txs(20_000);
        // Warm up, then measure the per-transaction path.
        let t0 = std::time::Instant::now();
        let mut single = Vec::with_capacity(txs.len());
        for tx in &txs {
            single.push(tx.compute_tx_hash());
        }
        let single_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let t0 = std::time::Instant::now();
        let batched = Transaction::compute_tx_hashes_batched(&txs);
        let batched_ms = t0.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(batched, single, "batched output must equal single output");
        eprintln!(
            "[perf] tx hashing 20k txs: single={single_ms:.2}ms batched={batched_ms:.2}ms speedup={:.2}x",
            if batched_ms > 0.0 { single_ms / batched_ms } else { f64::INFINITY },
        );
    }
}
