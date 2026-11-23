use super::*;
use crate::sharding::{ShardId, Transaction};
use bincode::Options;
use serde_json::Value;

/// sequence.
///
/// On top of that it keeps a hard *lifetime* cap per recipient, so the faucet
/// treasury can never be drained by simply repeating the request.
#[allow(clippy::type_complexity)]
// GATE: faucet persist callback type is fixed by durability hook; alias would churn public builder API.
pub struct Faucet {
    /// Drip amount (`STELL_FAUCET_DRIP_STELL`, default 2 STELL).
    pub drip: u64,
    /// Lifetime maximum creditable amount for a single address.
    pub max_per_address: u64,
    /// The shard this faucet SERVES. Every drip it builds is a same-shard
    /// transfer on this shard (`source_shard == target_shard == shard`); the
    /// faucet account that signs must be genesis-funded on THIS shard (the
    /// masterchain genesis and every workchain genesis both fund the same
    /// faucet address — see `fund_shard_genesis` — so each shard's faucet
    /// draws on its own shard's funding). Must equal the shard of the node
    /// endpoint that serves it: a drip built for any other shard would be
    /// dropped by that shard's proposer as shard-filtered.
    shard: ShardId,
    /// SEED LIFETIME (audit: faucet zeroize): the `pq_key` below derived
    /// from the seed MUST live as long as the faucet itself (every drip is
    /// signed with it), so the seed material is process-lifetime by design,
    /// not a leak to fix. What IS wiped: every INTERMEDIATE copy on the load
    /// path (file bytes, parsed hex line, env string — see
    /// `load_faucet_seed_from_file` / `load_faucet_seed`, all `Zeroizing` or
    /// explicitly zeroized) and the `Faucet::new` frame copy (wiped before
    /// return). Callers: `[u8; 32]` is `Copy`, so YOUR stack binding still
    /// holds the seed after `Faucet::new(seed, ..)` returns — zeroize it at
    /// the call site once the faucet owns it. No behavior change: signing
    /// bytes are identical, only dead copies are wiped.
    ///
    /// FULL-PQ (no compat): the classical ed25519 faucet key is deleted; the
    /// Falcon-512 `pq_key` is the sole signing key.
    /// Falcon-512 keypair derived from the seed (sole PQ drip path).
    /// Same process-lifetime rule as above.
    pq_key: crate::post_quantum::FalconKeypair,
    /// Optional chain id for replay-bound PQ1 envelopes (contract D3).
    /// When `Some(cid)` (or supplied per-call by `RpcState`), every drip signs
    /// `Transaction::signing_message_for_chain(cid)` into
    /// `PqSignatureEnvelope::new_explicit_with_chain`.
    chain_id: Option<u64>,
    state: tokio::sync::Mutex<FaucetState>,
    /// Called with the serialized state after every mutation, so the lifetime
    /// caps and the nonce survive a restart. `None` (tests, disabled faucet)
    /// keeps the previous in-memory-only behaviour. The callback MUST report
    /// write/flush failures: a drip whose durable write fails is rolled back
    /// and refused, never granted in RAM only.
    persist: Option<std::sync::Arc<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>>,
    // NOTE: there is deliberately NO process-local rate-limit map here. The
    // per-source hourly budgets live in FaucetState (persisted): the token +
    // per-address lifetime cap do not stop a token holder from draining the
    // treasury by rotating addresses, and a volatile budget would hand back a
    // fresh hourly allowance on every restart. Hourly budget, not a cooldown,
    // so legit bursts (tests, harnesses) pass; rotation-drain stops at the cap.
}

/// Drips per client IP per hour (both faucet paths). Default 20; override
/// with `STELL_FAUCET_IP_MAX_PER_HOUR`. Per-node anti-abuse budget, not
/// consensus — nodes MAY differ; same value recommended so every node's
/// faucet enforces the same budget.
pub const FAUCET_IP_MAX_PER_HOUR: u32 = 20;

/// Effective per-IP hourly budget (`STELL_FAUCET_IP_MAX_PER_HOUR`, default 20).
pub fn faucet_ip_max_per_hour() -> u32 {
    std::env::var("STELL_FAUCET_IP_MAX_PER_HOUR")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(FAUCET_IP_MAX_PER_HOUR)
}

/// Env var carrying the faucet ed25519 seed inline (64-char hex, cleartext in
/// the process environment — prefer [`FAUCET_KEY_FILE_ENV`]).
/// Genesis-funding ONLY: serving the faucet ([`load_faucet_seed`]) requires
/// the key file and ignores this var fail-closed.
pub const FAUCET_KEY_ENV: &str = "STELL_FAUCET_KEY";
/// Env var naming a FILE that carries the faucet ed25519 seed (hex, first
/// line). The file MUST be owner-only (`0600`) or loading fails closed.
pub const FAUCET_KEY_FILE_ENV: &str = "STELL_FAUCET_KEY_FILE";
/// Env var that explicitly authorises running the faucet with the well-known
/// built-in test key. `1` / case-insensitive `true` opts in; anything else
/// (including unset) refuses the test key fail-closed.
pub const DEV_UNSAFE_TESTKEY_ENV: &str = "STELL_DEV_UNSAFE_TESTKEY";
/// The well-known public test seed (`0x11..11`). It appears in tests and docs,
/// so anyone can derive its private key: running money-printing with it on a
/// live network hands every reader a mint key.
pub const TEST_FAUCET_SEED: [u8; 32] = [0x11u8; 32];

/// Parse the dev-unsafe-testkey flag: `1` or case-insensitive `true` only.
pub fn is_dev_unsafe_testkey(v: Option<&str>) -> bool {
    matches!(v, Some(s) if s == "1" || s.eq_ignore_ascii_case("true"))
}

/// [`is_dev_unsafe_testkey`] over the live process environment.
pub fn is_dev_unsafe_testkey_env() -> bool {
    is_dev_unsafe_testkey(std::env::var(DEV_UNSAFE_TESTKEY_ENV).ok().as_deref())
}

// GATE: H-02 fix — the wallet SIGN arms NEVER use the validator key. This is
// the ONLY production constructor for `RpcState::msg_signing_seed`: an
// ephemeral random seed minted in-memory when explicit dev mode is on
// (`STELL_DEV_UNSAFE_TESTKEY=1`, reusing the existing dev-mode flag — no new
// env knob), else `None` (SIGN arms refuse fail-closed). Never persisted,
// never derived from node/validator key material.
pub fn dev_msg_signing_seed_from_env() -> Option<[u8; 32]> {
    if !is_dev_unsafe_testkey_env() {
        return None;
    }
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    Some(seed)
}

/// True when `seed` is the well-known public test key.
pub fn is_test_key_seed(seed: &[u8; 32]) -> bool {
    seed == &TEST_FAUCET_SEED
}

/// Parse one faucet seed from hex text (trims whitespace, accepts an optional
/// `0x` prefix). The input buffer is zeroized before returning.
pub fn parse_faucet_seed_hex(raw: &str) -> Result<[u8; 32], String> {
    let owned = zeroize::Zeroizing::new(raw.trim().to_string());
    let hex_part: &str = owned.strip_prefix("0x").unwrap_or(owned.as_str()).trim();
    let mut bytes = zeroize::Zeroizing::new(
        hex::decode(hex_part).map_err(|e| format!("[faucet] invalid faucet seed hex: {e}"))?,
    );
    if bytes.len() != 32 {
        return Err(format!(
            "[faucet] invalid faucet seed length: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    zeroize::Zeroize::zeroize(&mut *bytes);
    Ok(seed)
}

/// Load a faucet seed from a file: 0600-checked (owner-only, fail-closed),
/// first non-empty line, hex. File bytes are zeroized after parsing.
pub fn load_faucet_seed_from_file(path: &std::path::Path) -> Result<[u8; 32], String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| {
            format!(
                "[faucet] cannot stat faucet key file {}: {e}",
                path.display()
            )
        })?;
        if !meta.is_file() {
            return Err(format!(
                "[faucet] REFUSING: faucet key path {} is not a file",
                path.display()
            ));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "[faucet] REFUSING: faucet key file {} has insecure permissions 0o{:03o} \
                 (group/other must have NO access — chmod 0600 {})",
                path.display(),
                mode,
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        if !path.is_file() {
            return Err(format!(
                "[faucet] REFUSING: faucet key path {} is not a file",
                path.display()
            ));
        }
    }
    let mut raw = zeroize::Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
        format!(
            "[faucet] cannot read faucet key file {}: {e}",
            path.display()
        )
    })?);
    // The parsed line is a SECOND copy of the secret (the file buffer above
    // is wiped on the next line): it must be a `Zeroizing` too, or the key
    // hex survives in a plain `String` after this function returns.
    let line = zeroize::Zeroizing::new(
        raw.lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("")
            .to_string(),
    );
    zeroize::Zeroize::zeroize(&mut *raw);
    if line.is_empty() {
        return Err(format!(
            "[faucet] REFUSING: faucet key file {} is empty",
            path.display()
        ));
    }
    // `line` wipes itself on drop (`Zeroizing`); the returned seed's lifetime
    // is documented on [`Faucet::new`].
    load_faucet_seed_from_file_content(&line, path)
}

/// Helper so the parsed line (not the whole file buffer) is what gets an error
/// context. Separated for tests.
pub(super) fn load_faucet_seed_from_file_content(
    line: &str,
    path: &std::path::Path,
) -> Result<[u8; 32], String> {
    parse_faucet_seed_hex(line).map_err(|e| format!("{} (in {})", e, path.display()))
}

/// Fail-closed test-key gate: running the faucet with the well-known public
/// test key is REFUSED unless `STELL_DEV_UNSAFE_TESTKEY=1` explicitly opts in.
/// The error is loud and names the exact unsafe override (dev only).
pub fn check_faucet_seed_allows_startup(seed: &[u8; 32]) -> Result<(), String> {
    if is_test_key_seed(seed) && !is_dev_unsafe_testkey_env() {
        return Err(format!(
            "[faucet] REFUSING: faucet key is the well-known PUBLIC test key (0x11..11) — \
             anyone can derive its private key, so starting the faucet with it would run \
             money-printing on a guessable key. Set a real {}=/{} (0600 file preferred) \
             with a fresh random seed. Dev-only override (NEVER on a live network): \
             {}=1",
            FAUCET_KEY_ENV, FAUCET_KEY_FILE_ENV, DEV_UNSAFE_TESTKEY_ENV
        ));
    }
    Ok(())
}

/// True when either faucet-key source is configured (inline env or key file).
pub fn faucet_key_present_from_env() -> bool {
    let inline = std::env::var(FAUCET_KEY_ENV)
        .ok()
        .is_some_and(|s| !s.trim().is_empty());
    let file = std::env::var(FAUCET_KEY_FILE_ENV)
        .ok()
        .is_some_and(|s| !s.trim().is_empty());
    inline || file
}

/// Load the faucet seed for SERVING drips: `STELL_FAUCET_KEY_FILE` is
/// REQUIRED (0600-checked, zeroized after load).
///
/// LEAD (no test keys, no defaults in public paths): serving NEVER falls
/// back to inline `STELL_FAUCET_KEY` — an inline seed alone leaves the
/// faucet disabled fail-closed with a loud error pointing at the file.
/// Inline seeds remain valid ONLY for genesis-funding reproducibility via
/// [`load_faucet_seed_for_genesis`] (root determinism for existing chains).
///
/// * `Ok(seed)` — file configured and parsed, test-key gate passed.
/// * `Err(msg)` — fail-closed loud error: missing file (faucet stays
///   DISABLED), bad file (missing / bad perms / bad hex), or the public
///   test key without the dev override. Callers must refuse to serve the
///   faucet on `Err`.
pub fn load_faucet_seed() -> Result<[u8; 32], String> {
    if let Some(path) = std::env::var(FAUCET_KEY_FILE_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        let path_buf = zeroize::Zeroizing::new(path);
        let seed = load_faucet_seed_from_file(std::path::Path::new(path_buf.as_str()))?;
        check_faucet_seed_allows_startup(&seed)?;
        return Ok(seed);
    }
    if faucet_key_present_from_env() {
        return Err(format!(
            "[faucet] REFUSING: serving the faucet from inline {} is disabled — \
             set {} to a 0600 file carrying the seed (inline seeds are genesis-only, \
             see load_faucet_seed_for_genesis); faucet stays DISABLED",
            FAUCET_KEY_ENV, FAUCET_KEY_FILE_ENV
        ));
    }
    Err(format!(
        "[faucet] no faucet key file configured (set {} to a 0600 file); \
         refusing to start the faucet — faucet stays DISABLED",
        FAUCET_KEY_FILE_ENV
    ))
}

/// Optional variant for genesis-funding paths: `Ok(None)` when NEITHER source
/// is configured (no faucet funding, same as before); `Err` on any
/// misconfiguration (fail-closed, loud); `Ok(Some(seed))` on success.
pub fn try_load_faucet_seed_opt() -> Result<Option<[u8; 32]>, String> {
    if !faucet_key_present_from_env() {
        return Ok(None);
    }
    load_faucet_seed().map(Some)
}

/// Genesis-RECOMPUTE variant: byte-identical derivation to the v1 genesis
/// (`c840d1dc...` funds the faucet account from the then-configured seed),
/// which the stored-root guard compares against on every boot of existing
/// data. A test-key seed is therefore LOUDLY WARNED but RETURNED here —
/// recompute moves no money, it only re-derives an address. SERVING drips
/// from it stays hard-refused via `load_faucet_seed()`. Without this split,
/// any existing chain founded with the test key could never boot again.
pub fn load_faucet_seed_for_genesis() -> Result<[u8; 32], String> {
    let seed = load_faucet_seed_for_genesis_inner()?;
    if is_test_key_seed(&seed) && !is_dev_unsafe_testkey_env() {
        let msg = "[genesis] WARN faucet key is the well-known PUBLIC test key (0x11..11): \
            genesis funding reproduced for root determinism ONLY — serving drips from it \
            stays REFUSED. Rotate to a fresh STELL_FAUCET_KEY_FILE.";
        eprintln!("{msg}");
        tracing::warn!("{msg}");
    }
    Ok(seed)
}

pub(super) fn load_faucet_seed_for_genesis_inner() -> Result<[u8; 32], String> {
    if let Some(path) = std::env::var(FAUCET_KEY_FILE_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        let path_buf = zeroize::Zeroizing::new(path);
        return load_faucet_seed_from_file(std::path::Path::new(path_buf.as_str()));
    }
    if let Some(mut hex_str) = std::env::var(FAUCET_KEY_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        let seed = parse_faucet_seed_hex(&hex_str)?;
        use zeroize::Zeroize;
        hex_str.zeroize();
        return Ok(seed);
    }
    Err(format!(
        "[faucet] no faucet key configured (set {} or {}); no genesis faucet funding",
        FAUCET_KEY_ENV, FAUCET_KEY_FILE_ENV
    ))
}

/// Optional genesis variant of the above: `Ok(None)` when unconfigured.
pub fn try_load_faucet_seed_opt_for_genesis() -> Result<Option<[u8; 32]>, String> {
    if !faucet_key_present_from_env() {
        return Ok(None);
    }
    load_faucet_seed_for_genesis().map(Some)
}

/// Meta key under which a node persists its faucet state.
pub const FAUCET_STATE_META_KEY: &str = "faucet_state_v1";
/// Durable marker proving this node has already initialised the faucet. Its
/// presence without a state blob means the state was LOST (never "fresh"):
/// the startup machine quarantines instead of re-opening every lifetime cap.
pub const FAUCET_INITIALIZED_META_KEY: &str = "faucet_initialized_v1";

/// Compact rollback point for one drip mutation. Restored under the same lock
/// when the durable write/flush fails, so RAM and disk never disagree in the
/// direction that would let an address re-draw credit after a restart.
struct UndoDelta {
    prev_next_nonce: u64,
    who: [u8; 32],
    prev_dispensed: Option<u64>,
    ip_key: Option<String>,
    prev_ip: Option<(u64, u32)>,
    public_who: Option<[u8; 32]>,
    prev_public: Option<u64>,
}

impl UndoDelta {
    fn restore(self, st: &mut FaucetState) {
        st.next_nonce = self.prev_next_nonce;
        match self.prev_dispensed {
            Some(v) => {
                st.dispensed.insert(self.who, v);
            }
            None => {
                st.dispensed.remove(&self.who);
            }
        }
        if let Some(key) = self.ip_key {
            match self.prev_ip {
                Some(v) => {
                    st.ip_buckets.insert(key, v);
                }
                None => {
                    st.ip_buckets.remove(&key);
                }
            }
        }
        if let Some(who) = self.public_who {
            match self.prev_public {
                Some(v) => {
                    st.last_public_drip.insert(who, v);
                }
                None => {
                    st.last_public_drip.remove(&who);
                }
            }
        }
    }
}

#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct FaucetState {
    next_nonce: u64,
    dispensed: std::collections::HashMap<[u8; 32], u64>,
    /// Hourly drip budgets per source, `(hour, count)` keyed by source-IP
    /// string (`"unknown"` when the caller could not attribute one). Lives in
    /// the persisted state — NOT in a process-local map — so a restart does
    /// not reset rate limits (hunt D5: lifetime caps and the nonce were
    /// already persisted for exactly this reason; the budget was not).
    #[serde(default)]
    ip_buckets: std::collections::HashMap<String, (u64, u32)>,
    /// Last public (tokenless) drip timestamp per address, in unix seconds.
    /// Enforces the TON-style cooldown: one public drip per address per
    /// `PUBLIC_DRIP_COOLDOWN_SECS`. Persisted, so restarts do not reopen it.
    #[serde(default)]
    last_public_drip: std::collections::HashMap<[u8; 32], u64>,
    /// Non-serialized fail-closed flag. `#[serde(skip)]` keeps the bincode
    /// layout of persisted blobs byte-identical; quarantine is a runtime
    /// decision derived from startup reads, never a durable state.
    #[serde(skip)]
    quarantined_reason: Option<String>,
}

/// Pre-`last_public_drip` layout (nonce + caps + IP buckets). Accepted on load
/// so a node upgrading from that writer keeps its caps and hourly budgets; the
/// public cooldown map starts empty (bounded under-serve, never over-mint).
#[derive(serde::Deserialize)]
pub(super) struct FaucetStateV2 {
    next_nonce: u64,
    dispensed: std::collections::HashMap<[u8; 32], u64>,
    ip_buckets: std::collections::HashMap<String, (u64, u32)>,
}

/// Number of `last_public_drip` entries above which expired cooldowns are
/// swept from memory (and, with the incremental store, from disk). Lifetime
/// `dispensed` totals are NEVER pruned: they are the anti-drain cap.
pub const PUBLIC_DRIP_PRUNE_THRESHOLD: usize = 10_000;
/// Hard ceiling on per-hour IP rate-limit buckets retained in [`FaucetState`].
pub const IP_BUCKETS_MAX_ENTRIES: usize = 100_000;

fn cap_ip_buckets(
    ip_buckets: &mut std::collections::HashMap<String, (u64, u32)>,
    hour: u64,
    incoming_key: &str,
) {
    if ip_buckets.len() < IP_BUCKETS_MAX_ENTRIES || ip_buckets.contains_key(incoming_key) {
        return;
    }
    ip_buckets.retain(|_, (h, _)| hour.saturating_sub(*h) <= 1);
    while ip_buckets.len() >= IP_BUCKETS_MAX_ENTRIES {
        let victim = ip_buckets
            .iter()
            .min_by(|(ka, (ha, na)), (kb, (hb, nb))| {
                (*ha, *na, ka.as_str()).cmp(&(*hb, *nb, kb.as_str()))
            })
            .map(|(k, _)| k.clone());
        let Some(k) = victim else {
            break;
        };
        ip_buckets.remove(&k);
    }
}

fn cap_last_public_drip(
    last_public_drip: &mut std::collections::HashMap<[u8; 32], u64>,
    now_secs: u64,
    cooldown: u64,
    incoming_who: &[u8; 32],
) {
    if last_public_drip.len() < PUBLIC_DRIP_PRUNE_THRESHOLD
        || last_public_drip.contains_key(incoming_who)
    {
        return;
    }
    last_public_drip.retain(|_, last| now_secs.saturating_sub(*last) < cooldown);
    while last_public_drip.len() >= PUBLIC_DRIP_PRUNE_THRESHOLD {
        let victim = last_public_drip
            .iter()
            .min_by(|(ka, ta), (kb, tb)| (*ta, *ka).cmp(&(*tb, *kb)))
            .map(|(k, _)| *k);
        let Some(k) = victim else {
            break;
        };
        last_public_drip.remove(&k);
    }
}
/// Failed durable faucet writes (serialize / write / flush). A repeating
/// failure is visible even when logs rotate; the consequence (a drip that
/// could not be made durable is refused, never silently granted) is named at
/// the failure site.
pub static FAUCET_PERSIST_FAILURES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Distinguishable refusal reasons for a faucet drip. Callers map these to
/// HTTP/JSON-RPC codes; a lifetime cap is NEVER reported as a cooldown and a
/// broken/persist-failed faucet never hands out a grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaucetDripError {
    /// Address exhausted its lifetime allowance (`dispensed >= max_per_address`).
    LifetimeCapExhausted,
    /// Public faucet still cooling down for this address.
    Cooldown { retry_after_secs: u64 },
    /// Per-IP hourly budget exhausted.
    IpRateLimited,
    /// Faucet state is corrupt/unreadable or startup checks failed (fail-closed).
    Quarantined { reason: String },
    /// Durable write or flush failed; in-memory mutation was rolled back.
    PersistFailed { reason: String },
}

impl std::fmt::Display for FaucetDripError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LifetimeCapExhausted => {
                write!(f, "faucet limit reached for this address")
            }
            Self::Cooldown { retry_after_secs } => write!(
                f,
                "public drip cooling down for this address, retry in {retry_after_secs} seconds"
            ),
            Self::IpRateLimited => {
                write!(f, "per-IP faucet budget exhausted for this hour")
            }
            Self::Quarantined { reason } => {
                write!(f, "faucet quarantined (fail-closed): {reason}")
            }
            Self::PersistFailed { reason } => {
                write!(f, "faucet state could not be persisted: {reason}")
            }
        }
    }
}

impl std::error::Error for FaucetDripError {}

/// Parameters for [`Faucet::request_drip`]. All checks and mutations run under
/// ONE state lock, eliminating the old check-then-build TOCTOU window.
#[derive(Clone, Debug)]
pub struct FaucetDripRequest {
    pub who: [u8; 32],
    pub requested: Option<u64>,
    pub reconcile: Option<(u64, Vec<u64>)>,
    /// Public (tokenless) mode: enforce + record the per-address cooldown.
    pub public: bool,
    pub now_secs: u64,
    /// Source address for the hourly budget. `None` shares the "unknown"
    /// fallback bucket (throttled, never exempt).
    pub ip: Option<std::net::IpAddr>,
}

impl FaucetDripRequest {
    pub fn token(
        who: [u8; 32],
        requested: Option<u64>,
        reconcile: Option<(u64, Vec<u64>)>,
        now_secs: u64,
        ip: Option<std::net::IpAddr>,
    ) -> Self {
        Self {
            who,
            requested,
            reconcile,
            public: false,
            now_secs,
            ip,
        }
    }

    pub fn public(
        who: [u8; 32],
        reconcile: Option<(u64, Vec<u64>)>,
        now_secs: u64,
        ip: Option<std::net::IpAddr>,
    ) -> Self {
        Self {
            who,
            requested: Some(public_drip_nano()),
            reconcile,
            public: true,
            now_secs,
            ip,
        }
    }
}

/// A reserved, signed faucet transfer plus everything `rollback_grant` needs
/// to undo the RAM/disk reservation if mempool admission rejects it.
#[derive(Clone, Debug)]
pub struct FaucetGrant {
    pub tx: Transaction,
    pub who: [u8; 32],
    pub amount: u64,
    pub ip_key: String,
    pub charged_hour: u64,
    pub is_public: bool,
}

/// Durable metadata access used by the startup state machine. Implemented by
/// [`crate::storage::Storage`]; tests inject failures through a fake store to
/// prove every read error is fail-closed.
pub trait FaucetMetaStore {
    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
    /// Insert + fsync barrier: the write MUST be durable before `Ok`.
    fn set_meta_durable(&self, key: &str, value: &[u8]) -> Result<(), String>;
}

impl FaucetMetaStore for crate::storage::Storage {
    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        crate::storage::Storage::get_meta(self, key).map_err(|e| e.to_string())
    }

    fn set_meta_durable(&self, key: &str, value: &[u8]) -> Result<(), String> {
        crate::storage::Storage::set_meta_durable(self, key, value).map_err(|e| e.to_string())
    }
}

/// Public testnet drip: 2 STELL per address (TON-style onboarding drip).
/// Default 2 STELL; override with `STELL_PUBLIC_DRIP_NANO`. Faucet policy,
/// not consensus — nodes MAY differ; same value recommended so every node's
/// faucet credits the same amount.
pub const PUBLIC_DRIP_NANO: u64 = 2 * 1_000_000_000;
/// Public drip cooldown: 45 minutes per address. Default 2700 s; override
/// with `STELL_PUBLIC_DRIP_COOLDOWN_SECS`. Faucet policy, not consensus —
/// nodes MAY differ; same value recommended so every node's faucet enforces
/// the same cooldown.
pub const PUBLIC_DRIP_COOLDOWN_SECS: u64 = 45 * 60;

/// Effective public drip amount (`STELL_PUBLIC_DRIP_NANO`, default 2 STELL).
pub fn public_drip_nano() -> u64 {
    std::env::var("STELL_PUBLIC_DRIP_NANO")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(PUBLIC_DRIP_NANO)
}

/// Effective public drip cooldown (`STELL_PUBLIC_DRIP_COOLDOWN_SECS`, default 2700).
pub fn public_drip_cooldown_secs() -> u64 {
    std::env::var("STELL_PUBLIC_DRIP_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(PUBLIC_DRIP_COOLDOWN_SECS)
}

/// Pre-persistence layout (nonce + per-address totals only). A node upgrading
/// with a record written by the old code must keep its caps: decode falls back
/// to this shape and migrates it (fresh, empty rate buckets), instead of
/// failing closed to empty and re-opening every capped address.
#[derive(serde::Deserialize)]
pub(super) struct LegacyFaucetState {
    next_nonce: u64,
    dispensed: std::collections::HashMap<[u8; 32], u64>,
}

/// Build + sign a post-quantum EXPLICIT-envelope transfer (PQ1, Falcon-512)
/// from a raw Falcon-512 keypair.
///
/// This is the single definition of the faucet-shaped PQ transfer: the sender
/// is `derive_pq_address(Falcon512, pubkey, DEFAULT_SALT)` (== `Faucet::account()`
/// under pure-PQ for the faucet's own keypair), the signature covers the
/// UNBOUND `signing_message()` (byte-identical to every drip the faucet has
/// ever built — unbound admission is active while
/// `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` is unset), and the pubkey rides
/// EXPLICITLY so the very first spend from a fresh account verifies with no
/// registry state (always-explicit = no activation tracking needed).
///
/// Callers: `Faucet::build_transfer` (same-shard drips, `source == target ==
/// self.shard`) and the `wallet send-pq` CLI (masterchain source, any target
/// shard). The keypair MUST be derived with
/// `FalconKeypair::generate_from_seed_bytes` on the RAW 32-byte seed — the
/// same derivation `Faucet::new` uses. (The light-wallet KDF derivation
/// produces a DIFFERENT keypair/address from the same seed and cannot spend
/// faucet-genesis funds.)
pub fn sign_pq_explicit_transfer(
    pq_key: &crate::post_quantum::FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: ShardId,
    target_shard: ShardId,
) -> Transaction {
    let from = crate::post_quantum::derive_pq_address(
        crate::post_quantum::PqScheme::Falcon512,
        &pq_key.public_key,
        &crate::post_quantum::DEFAULT_SALT,
    );
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = pq_key.sign(&msg);
    let env = crate::sharding::PqSignatureEnvelope::new_explicit(
        crate::post_quantum::PqScheme::Falcon512,
        pq_key.public_key.clone(),
        sig,
    );
    tx.signature = env.encode();
    tx
}

/// Chain-bound variant of [`sign_pq_explicit_transfer`] (contract D3).
///
/// Signs `Transaction::signing_message_for_chain(chain_id)` and embeds the
/// same `chain_id` in `PqSignatureEnvelope::new_explicit_with_chain`, so the
/// transaction is accepted both before and after
/// `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` and cannot be replayed across chains.
#[allow(clippy::too_many_arguments)]
// GATE: mirrors `sign_pq_explicit_transfer` plus `chain_id`; keeping positional signature for caller parity.
pub fn sign_pq_explicit_transfer_with_chain(
    pq_key: &crate::post_quantum::FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: ShardId,
    target_shard: ShardId,
    chain_id: u64,
) -> Transaction {
    let from = crate::post_quantum::derive_pq_address(
        crate::post_quantum::PqScheme::Falcon512,
        &pq_key.public_key,
        &crate::post_quantum::DEFAULT_SALT,
    );
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message_for_chain(chain_id);
    let sig = pq_key.sign(&msg);
    let env = crate::sharding::PqSignatureEnvelope::new_explicit_with_chain(
        crate::post_quantum::PqScheme::Falcon512,
        pq_key.public_key.clone(),
        sig,
        crate::post_quantum::DEFAULT_SALT,
        chain_id,
    );
    tx.signature = env.encode();
    tx
}

impl Faucet {
    /// Default drip, in nano-STELL: 2 STELL unless `STELL_FAUCET_DRIP_STELL`
    /// carries a whole-STELL override. The single default every node binary
    /// uses, so the drip amount is one definition, not three hardcodings.
    pub fn default_drip_nano() -> u64 {
        let stell: u64 = std::env::var("STELL_FAUCET_DRIP_STELL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2);
        stell.saturating_mul(1_000_000_000)
    }

    /// `key_seed` is the 32-byte seed of the pre-funded faucet account.
    /// See the seed-lifetime note on the struct: the frame copy is wiped
    /// before return; zeroize YOUR stack copy at the call site.
    pub fn new(mut key_seed: [u8; 32], shard: ShardId, drip: u64, max_per_address: u64) -> Self {
        let pq_key = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&key_seed);
        // Wipe the frame copy: the live material now lives in `pq_key`
        // (process-lifetime by design). The caller's `Copy` binding is theirs
        // to wipe.
        zeroize::Zeroize::zeroize(&mut key_seed);
        Self {
            drip,
            max_per_address,
            shard,
            pq_key,
            chain_id: None,
            state: tokio::sync::Mutex::new(FaucetState::default()),
            persist: None,
        }
    }

    /// Bind every drip signed by this faucet to `chain_id` (contract D3).
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Configured chain id for chain-bound drips, if set.
    pub fn chain_id(&self) -> Option<u64> {
        self.chain_id
    }

    /// Attach a durability hook, returning the faucet for builder-style use.
    #[allow(clippy::type_complexity)]
    // GATE: persist callback signature is part of public builder API; boxing/aliasing would break callers.
    pub fn with_persist(mut self, persist: std::sync::Arc<dyn Fn(&[u8]) + Send + Sync>) -> Self {
        // Legacy infallible hook: adapt to the fallible internal form. Callers
        // that can report write/flush failures MUST use `with_fallible_persist`
        // so a failed drip is refused instead of granted in RAM only.
        self.persist = Some(std::sync::Arc::new(move |bytes: &[u8]| {
            persist(bytes);
            Ok(())
        }));
        self
    }

    /// Attach a durability hook that can FAIL. A serialize/write/flush error
    /// rolls back the in-memory mutation and refuses the drip.
    #[allow(clippy::type_complexity)]
    // GATE: same public builder shape as `with_persist`; an alias would churn callers.
    pub fn with_fallible_persist(
        mut self,
        persist: std::sync::Arc<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>,
    ) -> Self {
        self.persist = Some(persist);
        self
    }

    /// Serialize the mutable state (nonce + per-address dispensed totals +
    /// per-source rate buckets). Serialization errors are reported, never
    /// flattened to empty bytes.
    pub async fn try_save_bytes(&self) -> Result<Vec<u8>, String> {
        let st = self.state.lock().await;
        bincode::serialize(&*st).map_err(|e| format!("faucet state serialization failed: {e}"))
    }

    /// Compatibility helper for tests: serializing a `FaucetState` cannot fail
    /// (all fields are plain serde types), so an error here is an invariant
    /// violation and must be loud rather than silently persisted as `[]`.
    pub async fn save_bytes(&self) -> Vec<u8> {
        self.try_save_bytes()
            .await
            .expect("FaucetState is always bincode-serializable")
    }

    /// Mark the faucet fail-closed. No drip, IP budget or nonce may move while
    /// quarantined; callers surface `FaucetDripError::Quarantined`.
    pub async fn quarantine(&self, reason: impl Into<String>) {
        let reason = reason.into();
        self.state.lock().await.quarantined_reason = Some(reason);
    }

    /// True when startup detected corrupt/unreadable state (or a lost state
    /// blob with prior on-chain activity). All grant paths refuse.
    pub async fn is_quarantined(&self) -> bool {
        self.state.lock().await.quarantined_reason.is_some()
    }

    /// Human-readable quarantine cause, if any.
    pub async fn quarantine_reason(&self) -> Option<String> {
        self.state.lock().await.quarantined_reason.clone()
    }

    /// Restore previously saved state (strict). Unknown/empty bytes QUARANTINE
    /// the faucet instead of silently resetting it to empty: a corrupt record
    /// must never re-open lifetime caps. Records written before the rate
    /// buckets / public cooldown map existed migrate deterministically; stale
    /// buckets and expired cooldowns are dropped on load.
    pub async fn load_bytes_strict(&self, bytes: &[u8]) -> Result<(), String> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let now_hour = now_secs / 3600;
        if bytes.is_empty() {
            let reason = "empty faucet state blob".to_string();
            self.state.lock().await.quarantined_reason = Some(reason.clone());
            return Err(reason);
        }
        // `reject_trailing_bytes` is important: plain `bincode::deserialize`
        // allows trailing data, so a 4-field blob would also decode into the
        // 2-field legacy shape and silently drop rate buckets.
        let opts = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes();
        let decoded = if let Ok(mut st) = opts.deserialize::<FaucetState>(bytes) {
            st.ip_buckets
                .retain(|_, (h, _)| now_hour.saturating_sub(*h) <= 1);
            let cooldown = public_drip_cooldown_secs();
            st.last_public_drip
                .retain(|_, last| now_secs.saturating_sub(*last) < cooldown);
            Some(st)
        } else if let Ok(v2) = opts.deserialize::<FaucetStateV2>(bytes) {
            Some(FaucetState {
                next_nonce: v2.next_nonce,
                dispensed: v2.dispensed,
                ip_buckets: v2
                    .ip_buckets
                    .into_iter()
                    .filter(|(_, (h, _))| now_hour.saturating_sub(*h) <= 1)
                    .collect(),
                last_public_drip: std::collections::HashMap::new(),
                quarantined_reason: None,
            })
        } else if let Ok(legacy) = opts.deserialize::<LegacyFaucetState>(bytes) {
            Some(FaucetState {
                next_nonce: legacy.next_nonce,
                dispensed: legacy.dispensed,
                ip_buckets: std::collections::HashMap::new(),
                last_public_drip: std::collections::HashMap::new(),
                quarantined_reason: None,
            })
        } else {
            None
        };
        match decoded {
            Some(st) => {
                *self.state.lock().await = st;
                Ok(())
            }
            None => {
                let reason = "corrupt faucet state blob (no decodable layout)".to_string();
                self.state.lock().await.quarantined_reason = Some(reason.clone());
                Err(reason)
            }
        }
    }

    /// Compatibility wrapper: strict load, with the failure recorded as a
    /// quarantine. Callers that need the error must use
    /// [`Self::load_bytes_strict`].
    pub async fn load_bytes(&self, bytes: &[u8]) {
        if let Err(e) = self.load_bytes_strict(bytes).await {
            tracing::error!(
                "[faucet] QUARANTINED after loading persisted state: {e}; \
                 all drips are refused fail-closed"
            );
        }
    }

    /// Startup state machine: marker + legacy blob + on-chain nonce.
    ///
    /// * state blob readable + decodable -> load it (and write the marker if
    ///   this is a pre-marker node);
    /// * state blob unreadable/corrupt -> QUARANTINE;
    /// * no state blob + marker present -> QUARANTINE (state was lost);
    /// * no state blob + `onchain_nonce > 0` -> QUARANTINE (the chain proves
    ///   this faucet already spent, so an empty reset would re-open caps);
    /// * no state blob + no marker + `onchain_nonce == 0` -> clean start:
    ///   persist the marker AND the pristine blob with `flush()` before Ok.
    ///
    /// Any error quarantines the faucet; it is never left defaulted/open.
    pub async fn restore_or_quarantine(
        &self,
        store: &dyn FaucetMetaStore,
        onchain_nonce: u64,
    ) -> Result<(), String> {
        match self.try_restore(store, onchain_nonce).await {
            Ok(()) => Ok(()),
            Err(reason) => {
                self.quarantine(reason.clone()).await;
                Err(reason)
            }
        }
    }

    async fn try_restore(
        &self,
        store: &dyn FaucetMetaStore,
        onchain_nonce: u64,
    ) -> Result<(), String> {
        let marker = store
            .get_meta(FAUCET_INITIALIZED_META_KEY)
            .map_err(|e| format!("failed to read {FAUCET_INITIALIZED_META_KEY}: {e}"))?;
        match store.get_meta(FAUCET_STATE_META_KEY) {
            Err(e) => Err(format!("failed to read {FAUCET_STATE_META_KEY}: {e}")),
            Ok(Some(bytes)) => {
                self.load_bytes_strict(&bytes).await?;
                if marker.is_none() {
                    store
                        .set_meta_durable(FAUCET_INITIALIZED_META_KEY, b"1")
                        .map_err(|e| {
                            format!("failed to persist {FAUCET_INITIALIZED_META_KEY}: {e}")
                        })?;
                }
                self.clamp_nonce_down(onchain_nonce).await
            }
            Ok(None) => {
                if marker.is_some() {
                    return Err(format!(
                        "{FAUCET_INITIALIZED_META_KEY} present but faucet state missing — \
                         refusing fail-open reset"
                    ));
                }
                if onchain_nonce > 0 {
                    return Err(format!(
                        "onchain_nonce {onchain_nonce} > 0 with missing faucet state — \
                         refusing fail-open reset"
                    ));
                }
                // Clean start: marker first, then the pristine state blob, both
                // with a durable barrier. A crash between them is still safe:
                // marker + missing/empty state quarantines on the next boot
                // rather than silently resetting (and the state write below
                // happens before any drip can be served).
                store
                    .set_meta_durable(FAUCET_INITIALIZED_META_KEY, b"1")
                    .map_err(|e| format!("failed to persist {FAUCET_INITIALIZED_META_KEY}: {e}"))?;
                let bytes = self.try_save_bytes().await?;
                store
                    .set_meta_durable(FAUCET_STATE_META_KEY, &bytes)
                    .map_err(|e| format!("failed to persist {FAUCET_STATE_META_KEY}: {e}"))?;
                Ok(())
            }
        }
    }

    /// Clamp a diverged durable nonce DOWN to the on-chain nonce. See the
    /// startup reconciliation in main.rs for why only downward moves here.
    /// Returns an error (and restores RAM) when the durable write fails.
    pub async fn clamp_nonce_down(&self, onchain_nonce: u64) -> Result<(), String> {
        let mut st = self.state.lock().await;
        if st.next_nonce > onchain_nonce {
            let prev = st.next_nonce;
            st.next_nonce = onchain_nonce;
            if let Err(e) = self.persist_locked(&st) {
                st.next_nonce = prev;
                return Err(format!("failed to persist clamped faucet nonce: {e}"));
            }
        }
        Ok(())
    }

    fn persist_locked(&self, st: &FaucetState) -> Result<(), String> {
        if let Some(persist) = &self.persist {
            let bytes = bincode::serialize(st)
                .map_err(|e| format!("faucet state serialization failed: {e}"))?;
            persist(&bytes)?;
        }
        Ok(())
    }

    /// The (pre-funded) account the faucet transfers from.
    ///
    /// FULL-PQ (no compat): always the Falcon-512 PQ address. The classical
    /// ed25519 allowance branch is deleted.
    pub fn account(&self) -> [u8; 32] {
        crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &self.pq_key.public_key,
            &crate::post_quantum::DEFAULT_SALT,
        )
    }

    /// The shard this faucet serves: every drip it builds executes there
    /// (`source_shard == target_shard == shard`). A recipient that routes to
    /// any other shard is refused at admission (see
    /// [`resolve_faucet_recipient`]), never queued.
    pub fn shard(&self) -> ShardId {
        self.shard
    }

    /// Build a signed transfer for `who`, or `None` when their lifetime cap is
    /// already exhausted, the faucet is quarantined, or the durable write
    /// failed (the RAM reservation is rolled back in that case).
    ///
    /// Compatibility entry point: it does NOT charge the per-IP budget. New
    /// code should use [`Self::request_drip`], which performs cooldown, cap,
    /// IP budget and persist as ONE atomic step.
    pub async fn build_transfer(
        &self,
        who: [u8; 32],
        requested: Option<u64>,
        reconcile: Option<(u64, Vec<u64>)>,
    ) -> Option<(Transaction, u64)> {
        self.build_transfer_for_chain(who, requested, reconcile, None)
            .await
    }

    /// Chain-bound variant of [`Self::build_transfer`]; `chain_id` overrides
    /// `self.chain_id` when supplied.
    pub async fn build_transfer_for_chain(
        &self,
        who: [u8; 32],
        requested: Option<u64>,
        reconcile: Option<(u64, Vec<u64>)>,
        chain_id: Option<u64>,
    ) -> Option<(Transaction, u64)> {
        let (nonce, amount) = {
            let mut st = self.state.lock().await;
            match self.reserve_locked(
                &mut st,
                who,
                requested,
                reconcile,
                false,
                unix_now_secs(),
                None,
            ) {
                Ok(v) => v,
                Err(FaucetDripError::LifetimeCapExhausted) => return None,
                Err(e) => {
                    tracing::error!("[faucet] refusing drip: {e}");
                    return None;
                }
            }
        };
        Some((
            self.sign_transfer_for_chain(who, amount, nonce, chain_id),
            amount,
        ))
    }

    /// Public testnet drip (TON-style, tokenless): fixed 2 STELL per address
    /// per 45 minutes. Cooldown, lifetime cap and persist run under ONE lock.
    ///
    /// Compatibility entry point: its error is the old "seconds to wait"
    /// number, so only `Cooldown` can be reported faithfully. `Err(0)` means
    /// "refused for another reason" (cap exhausted, quarantined, persist
    /// failure) — callers that need the distinction must use
    /// [`Self::request_drip`]. A lifetime cap is NEVER reported as a cooldown.
    pub async fn build_public_transfer(
        &self,
        who: [u8; 32],
        now_secs: u64,
        reconcile: Option<(u64, Vec<u64>)>,
    ) -> Result<(Transaction, u64), u64> {
        let (nonce, amount) = {
            let mut st = self.state.lock().await;
            match self.reserve_locked(
                &mut st,
                who,
                Some(public_drip_nano()),
                reconcile,
                true,
                now_secs,
                None,
            ) {
                Ok(v) => v,
                Err(FaucetDripError::Cooldown { retry_after_secs }) => {
                    return Err(retry_after_secs)
                }
                Err(e) => {
                    tracing::error!("[faucet] public drip refused: {e}");
                    return Err(0);
                }
            }
        };
        Ok((
            self.sign_transfer_for_chain(who, amount, nonce, None),
            amount,
        ))
    }

    /// Single-lock drip request for BOTH ingress paths. Runs strictly:
    /// quarantine -> (public) cooldown -> lifetime cap -> per-IP budget ->
    /// mutate -> ONE persist(+flush). A persist error rolls back every touched
    /// field (nonce, dispensed, ip_buckets, last_public_drip) before releasing
    /// the lock and returns [`FaucetDripError::PersistFailed`]: no grant.
    pub async fn request_drip(
        &self,
        req: FaucetDripRequest,
    ) -> Result<FaucetGrant, FaucetDripError> {
        self.request_drip_for_chain(req, None).await
    }

    /// Chain-bound variant of [`Self::request_drip`]; `chain_id` overrides
    /// `self.chain_id` when supplied so RPC/explorer ingress binds drips to
    /// `st.chain_id` even when `Faucet::new` was constructed without
    /// `.with_chain_id(...)`.
    pub async fn request_drip_for_chain(
        &self,
        req: FaucetDripRequest,
        chain_id: Option<u64>,
    ) -> Result<FaucetGrant, FaucetDripError> {
        let ip_key = req
            .ip
            .map(crate::rpc::budget_bucket_ip)
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let charged_hour = req.now_secs / 3600;
        let (nonce, amount) = {
            let mut st = self.state.lock().await;
            self.reserve_locked(
                &mut st,
                req.who,
                req.requested,
                req.reconcile.clone(),
                req.public,
                req.now_secs,
                Some(ip_key.as_str()),
            )?
        };
        let tx = self.sign_transfer_for_chain(req.who, amount, nonce, chain_id);
        Ok(FaucetGrant {
            tx,
            who: req.who,
            amount,
            ip_key,
            charged_hour,
            is_public: req.public,
        })
    }

    /// Atomic reservation under an already-held state lock. Read-only checks
    /// first, then all mutations, then exactly one durable write. On write
    /// failure every touched field is restored from [`UndoDelta`].
    #[allow(clippy::too_many_arguments)]
    // GATE: reservation inputs mirror the public drip request fields; grouping
    // them into another struct would duplicate `FaucetDripRequest`.
    fn reserve_locked(
        &self,
        st: &mut FaucetState,
        who: [u8; 32],
        requested: Option<u64>,
        reconcile: Option<(u64, Vec<u64>)>,
        public: bool,
        now_secs: u64,
        charge_ip: Option<&str>,
    ) -> Result<(u64, u64), FaucetDripError> {
        if let Some(reason) = &st.quarantined_reason {
            return Err(FaucetDripError::Quarantined {
                reason: reason.clone(),
            });
        }
        let cooldown = public_drip_cooldown_secs();
        if public {
            if let Some(last) = st.last_public_drip.get(&who) {
                let elapsed = now_secs.saturating_sub(*last);
                if elapsed < cooldown {
                    return Err(FaucetDripError::Cooldown {
                        retry_after_secs: cooldown - elapsed,
                    });
                }
            }
        }
        let hour = now_secs / 3600;
        let ip_max = faucet_ip_max_per_hour();
        if let Some(key) = charge_ip {
            // Hour-unit comparison: entries store the UTC hour number, not a
            // timestamp (a seconds-based retain would wipe live buckets).
            if st.ip_buckets.len() > 100_000 {
                st.ip_buckets
                    .retain(|_, (h, _)| hour.saturating_sub(*h) <= 1);
            }
            if let Some((h, n)) = st.ip_buckets.get(key) {
                if *h == hour && *n >= ip_max {
                    return Err(FaucetDripError::IpRateLimited);
                }
            }
        }
        let already = st.dispensed.get(&who).copied().unwrap_or(0);
        let remaining = self.max_per_address.saturating_sub(already);
        if remaining == 0 {
            // On the token-authenticated `stell_faucet` ingress (`!public`),
            // key-rotation probes against capped addresses still consume an
            // hourly IP slot so rotating capped keys cannot bypass the per-IP
            // treasury cap (`pentest_batch_captcha_ws::faucet_key_rotation_...`).
            // On the public explorer endpoint (`public`), `LifetimeCapExhausted`
            // is refused before charging the IP bucket so one capped address
            // does not burn another visitor's NAT/shared IP budget.
            if !public {
                if let Some(key) = charge_ip {
                    let prev_ip = st.ip_buckets.get(key).copied();
                    match st.ip_buckets.get_mut(key) {
                        Some((h, n)) if *h == hour => {
                            *n += 1;
                        }
                        _ => {
                            cap_ip_buckets(&mut st.ip_buckets, hour, key);
                            st.ip_buckets.insert(key.to_string(), (hour, 1));
                        }
                    }
                    if let Err(e) = self.persist_locked(st) {
                        match prev_ip {
                            Some(v) => {
                                st.ip_buckets.insert(key.to_string(), v);
                            }
                            None => {
                                st.ip_buckets.remove(key);
                            }
                        }
                        let n = FAUCET_PERSIST_FAILURES
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            + 1;
                        tracing::error!(
                            "[faucet] persist failed #{n}; IP charge rolled back and refused: {e}"
                        );
                        return Err(FaucetDripError::PersistFailed { reason: e });
                    }
                }
            }
            return Err(FaucetDripError::LifetimeCapExhausted);
        }
        let amount = if public {
            // Public drips are a FIXED policy amount: never let a caller (or a
            // malformed request) raise it above `public_drip_nano()`.
            public_drip_nano().min(remaining)
        } else {
            requested.unwrap_or(self.drip).min(self.drip).min(remaining)
        };
        // Rollback point: captured BEFORE any mutation, restored on persist
        // failure (`dispensed` lifetime totals are never pruned anywhere).
        let undo = UndoDelta {
            prev_next_nonce: st.next_nonce,
            who,
            prev_dispensed: st.dispensed.get(&who).copied(),
            ip_key: charge_ip.map(str::to_string),
            prev_ip: charge_ip.and_then(|k| st.ip_buckets.get(k).copied()),
            public_who: public.then_some(who),
            prev_public: if public {
                st.last_public_drip.get(&who).copied()
            } else {
                None
            },
        };
        st.dispensed.insert(who, already + amount);
        // Reconcile under the same lock (atomic with assignment): reserved
        // nonces lost with a wiped mempool leave a permanent gap (new drips
        // wait behind phantom predecessors forever). `reconcile` carries
        // (on-chain nonce, pending nonces); we take the smallest nonce that is
        // neither executed nor pending (mex) -- filling gaps instead of
        // waiting behind them, never duplicating. None keeps pure increment
        // (tests, explorer, single-shot uses).
        if let Some((onchain, mut pending)) = reconcile {
            pending.sort_unstable();
            let mut want = onchain;
            for n in pending {
                if n < want {
                    continue;
                }
                if n == want {
                    want += 1;
                } else {
                    break;
                }
            }
            // Max, not overwrite (audit follow-up): two concurrent drips with
            // the same stale `pending` snapshot compute the same `want`; the
            // second must not clobber the first's increment (duplicate nonce).
            if want > st.next_nonce {
                st.next_nonce = want;
            }
        }
        let nonce = st.next_nonce;
        st.next_nonce += 1;
        if let Some(key) = charge_ip {
            match st.ip_buckets.get_mut(key) {
                Some((h, n)) if *h == hour => {
                    *n += 1;
                }
                _ => {
                    cap_ip_buckets(&mut st.ip_buckets, hour, key);
                    st.ip_buckets.insert(key.to_string(), (hour, 1));
                }
            }
        }
        if public {
            // Bound the cooldown map: expired entries are dead weight, and
            // within a single window the oldest entries are evicted at cap. The
            // lifetime `dispensed` ledger is NEVER touched by this sweep.
            cap_last_public_drip(&mut st.last_public_drip, now_secs, cooldown, &who);
            st.last_public_drip.insert(who, now_secs);
        }
        // Durable before returning: a crash between here and the transfer must
        // not resurrect spent lifetime credit. A failed write is NOT a grant.
        if let Err(e) = self.persist_locked(st) {
            undo.restore(st);
            let n = FAUCET_PERSIST_FAILURES
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .saturating_add(1);
            tracing::error!(
                "[faucet] CRITICAL: failed to persist drip state ({} failure(s)): {e}; \
                 in-memory reservation rolled back, drip REFUSED",
                n
            );
            return Err(FaucetDripError::PersistFailed { reason: e });
        }
        Ok((nonce, amount))
    }

    fn sign_transfer_for_chain(
        &self,
        who: [u8; 32],
        amount: u64,
        nonce: u64,
        chain_id: Option<u64>,
    ) -> Transaction {
        // Faucet drips go through mempool admission like any other tx, so the
        // declared gas must clear the base fee (raised x500 with the base
        // transfer fee - a hardcoded 21_000 here silently broke every drip).
        // FULL-PQ (no compat): drips are always PQ-explicit transfers.
        let gas = crate::svm::GAS_BASIC_TRANSFER + crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS;
        match chain_id.or(self.chain_id) {
            Some(cid) => sign_pq_explicit_transfer_with_chain(
                &self.pq_key,
                who,
                amount,
                gas,
                nonce,
                self.shard,
                self.shard,
                cid,
            ),
            None => sign_pq_explicit_transfer(
                &self.pq_key,
                who,
                amount,
                gas,
                nonce,
                self.shard,
                self.shard,
            ),
        }
    }

    /// Undo a granted drip that was rejected by mempool admission. Restores
    /// the nonce, the lifetime credit, the public cooldown AND the per-IP
    /// budget under one lock; the durable write happens before `Ok`.
    pub async fn rollback_grant(&self, grant: &FaucetGrant) -> Result<(), FaucetDripError> {
        let mut st = self.state.lock().await;
        let undo = UndoDelta {
            prev_next_nonce: st.next_nonce,
            who: grant.who,
            prev_dispensed: st.dispensed.get(&grant.who).copied(),
            ip_key: Some(grant.ip_key.clone()),
            prev_ip: st.ip_buckets.get(&grant.ip_key).copied(),
            public_who: grant.is_public.then_some(grant.who),
            prev_public: if grant.is_public {
                st.last_public_drip.get(&grant.who).copied()
            } else {
                None
            },
        };
        if grant.tx.nonce < st.next_nonce {
            st.next_nonce = grant.tx.nonce;
        }
        let already = st.dispensed.get(&grant.who).copied().unwrap_or(0);
        st.dispensed
            .insert(grant.who, already.saturating_sub(grant.amount));
        if grant.is_public {
            st.last_public_drip.remove(&grant.who);
        }
        if let Some((h, n)) = st.ip_buckets.get_mut(&grant.ip_key) {
            if *h == grant.charged_hour && *n > 0 {
                *n -= 1;
            }
        }
        if let Err(e) = self.persist_locked(&st) {
            undo.restore(&mut st);
            let n = FAUCET_PERSIST_FAILURES
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .saturating_add(1);
            tracing::error!(
                "[faucet] CRITICAL: failed to persist drip rollback ({} failure(s)): {e}; \
                 in-memory state restored to the charged grant",
                n
            );
            return Err(FaucetDripError::PersistFailed { reason: e });
        }
        Ok(())
    }

    /// Give a nonce back when the transfer could not be admitted.
    ///
    /// Rewinds to the failed nonce (not just the tip): with mex-reconcile at
    /// every build site, a lower `next_nonce` is always safe (the next build
    /// recomputes the mex around still-pending nonces, so nothing duplicates),
    /// while the old tip-only rewind left permanent gaps under interleaved
    /// admissions (audit 2026-10-06).
    ///
    /// Compatibility wrapper for callers of the old API; it does not know the
    /// IP key, so new ingress code should use [`Self::rollback_grant`].
    pub async fn rollback(&self, tx: &Transaction, who: [u8; 32], amount: u64) {
        let mut st = self.state.lock().await;
        let prev_nonce = st.next_nonce;
        let prev_dispensed = st.dispensed.get(&who).copied();
        let prev_public = st.last_public_drip.get(&who).copied();
        if tx.nonce < st.next_nonce {
            st.next_nonce = tx.nonce;
        }
        let already = st.dispensed.get(&who).copied().unwrap_or(0);
        st.dispensed.insert(who, already.saturating_sub(amount));
        st.last_public_drip.remove(&who);
        if let Err(e) = self.persist_locked(&st) {
            // Durable state still carries the charge: keeping RAM charged is
            // the safe direction (under-serve), never a free re-grant.
            st.next_nonce = prev_nonce;
            match prev_dispensed {
                Some(v) => {
                    st.dispensed.insert(who, v);
                }
                None => {
                    st.dispensed.remove(&who);
                }
            }
            match prev_public {
                Some(v) => {
                    st.last_public_drip.insert(who, v);
                }
                None => {
                    st.last_public_drip.remove(&who);
                }
            }
            FAUCET_PERSIST_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(
                "[faucet] CRITICAL: failed to persist drip rollback: {e}; \
                 in-memory state restored to the charged grant"
            );
        }
    }

    /// Lifetime amount already credited to `who`.
    pub async fn dispensed_to(&self, who: [u8; 32]) -> u64 {
        self.state
            .lock()
            .await
            .dispensed
            .get(&who)
            .copied()
            .unwrap_or(0)
    }

    /// Per-source drip throttle: at most FAUCET_IP_MAX_PER_HOUR drips per UTC
    /// hour. Returns true when the drip may proceed (and records it).
    /// Loopback is NOT exempt — a leaked token + rotation script is local too.
    ///
    /// `ip` is `None` when the caller could not attribute a source (direct
    /// dispatch in unit tests): those drips share ONE fallback budget instead
    /// of bypassing the throttle entirely. Buckets live in the persisted
    /// [`FaucetState`] and every granted drip re-persists, so restarts do not
    /// reset budgets (hunt D5). Quarantine or a failed persist refuses the
    /// grant and rolls the bucket back.
    pub async fn check_ip_throttle(&self, ip: Option<std::net::IpAddr>, now_secs: u64) -> bool {
        let key = ip
            .map(crate::rpc::budget_bucket_ip)
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let mut st = self.state.lock().await;
        if st.quarantined_reason.is_some() {
            return false;
        }
        let hour = now_secs / 3600;
        if st.ip_buckets.len() > 100_000 {
            // Hour-unit comparison: entries store the UTC hour number, not a
            // timestamp (the old seconds-based retain wiped live buckets).
            st.ip_buckets
                .retain(|_, (h, _)| hour.saturating_sub(*h) <= 1);
        }
        let ip_max = faucet_ip_max_per_hour();
        let prev = st.ip_buckets.get(&key).copied();
        let allowed = match st.ip_buckets.get_mut(&key) {
            Some((h, n)) if *h == hour => {
                if *n >= ip_max {
                    false
                } else {
                    *n += 1;
                    true
                }
            }
            _ => {
                cap_ip_buckets(&mut st.ip_buckets, hour, &key);
                st.ip_buckets.insert(key.clone(), (hour, 1));
                true
            }
        };
        if allowed {
            if let Err(e) = self.persist_locked(&st) {
                match prev {
                    Some(v) => {
                        st.ip_buckets.insert(key, v);
                    }
                    None => {
                        st.ip_buckets.remove(&key);
                    }
                }
                let n = FAUCET_PERSIST_FAILURES
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    .saturating_add(1);
                tracing::error!(
                    "[faucet] CRITICAL: failed to persist IP budget ({} failure(s)): {e}; \
                     budget charge rolled back, drip REFUSED",
                    n
                );
                return false;
            }
        }
        allowed
    }
}

/// Wall-clock seconds, with the same `0` fallback the faucet has always used
/// for pre-epoch clocks (still fail-safe: `0` only makes cooldowns longer).
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn parse_rpc_address_with_shard_hint(
    s: &str,
) -> Result<([u8; 32], Option<u32>), String> {
    let (shard, rest) = crate::sharding::split_shard_prefix(s);
    let addr = parse_rpc_address(rest)?;
    Ok((addr, shard))
}

/// Resolve an address to its shard under the node's topology, applying the
/// documented address→shard rule (see `crate::sharding::ROUTING_RULE`).
/// (crate-visible: the explorer gateway enforces the same faucet shard rule.)
///
/// `hint` is the EXPLICIT shard the caller named (`-1:` / `0:` / `N:`).
/// * `Some(0)` (the masterchain form) -> shard 0, always;
/// * `Some(n)` (an explicit workchain pin) -> shard n, as named;
/// * `None` -> the routing rule over the node's topology.
pub(crate) async fn resolve_shard_for_address(
    st: &RpcState,
    address: [u8; 32],
    hint: Option<u32>,
) -> u32 {
    match hint {
        Some(shard) => shard,
        None => {
            let topology = st.engine.shard_topology().await;
            crate::sharding::route_shard(
                &topology,
                &crate::sharding::ShardAddress::Workchain(address),
            )
        }
    }
}

/// Parse a faucet recipient and enforce the faucet's shard scope.
///
/// Returns the recipient address and the shard it lives on. The shard is the
/// documented address→shard rule ([`crate::sharding::ROUTING_RULE`]): the
/// masterchain form (`-1:<addr>` / `0:<addr>`) names shard 0, a bare address
/// routes by prefix (never the masterchain), an explicit `N:<addr>` pin names
/// shard N.
///
/// On a sharded node ([`ShardRegistry::is_sharded`]) a recipient that routes
/// to any shard OTHER than the faucet's own is an `Err`: the drip would be a
/// `source_shard != shard` transaction, which that shard's proposer drops as
/// shard-filtered, so it could sit in the mempool but never execute — while
/// holding the faucet nonce it reserved. Refusing BEFORE any nonce is
/// reserved keeps the faucet's nonce sequence (and lifetime caps) intact for
/// the next, servable drip. On a single-shard node the rule is not enforced
/// (the pre-sharding path admits and executes regardless of the tags).
///
/// (crate-visible: the explorer gateway's token and public faucet paths
/// enforce exactly this rule.)
pub(crate) async fn resolve_faucet_recipient(
    st: &RpcState,
    faucet: &Faucet,
    raw: &str,
) -> Result<([u8; 32], ShardId), String> {
    let (addr, hint) =
        parse_rpc_address_with_shard_hint(raw).map_err(|e| format!("invalid address: {e}"))?;
    let shard = resolve_shard_for_address(st, addr, hint).await;
    if st.shard_registry.is_sharded() && shard != faucet.shard() {
        return Err(format!(
            "faucet on shard {} cannot serve an address on shard {shard} \
             (a drip built for another shard would be dropped as shard-filtered \
             and could never execute); fund this address from the faucet serving \
             shard {shard}",
            faucet.shard(),
        ));
    }
    Ok((addr, shard))
}

pub(super) fn parse_addr_from_val(val: Option<&Value>) -> Result<[u8; 32], String> {
    match val {
        Some(v) if v.is_string() => parse_rpc_address(v.as_str().unwrap()),
        Some(v) if v.is_array() => {
            serde_json::from_value::<[u8; 32]>(v.clone()).map_err(|e| e.to_string())
        }
        _ => Err("missing or invalid address in opcode".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faucet_ip_buckets_and_public_drip_stay_bounded_within_window() {
        let mut buckets = std::collections::HashMap::new();
        let hour = 100u64;
        for i in 0..IP_BUCKETS_MAX_ENTRIES {
            let count = if i == 0 { 1 } else { 5 };
            buckets.insert(format!("10.0.{}.{}", i / 256, i % 256), (hour, count));
        }
        assert_eq!(buckets.len(), IP_BUCKETS_MAX_ENTRIES);

        cap_ip_buckets(&mut buckets, hour, "192.168.1.1");
        buckets.insert("192.168.1.1".to_string(), (hour, 1));
        assert_eq!(buckets.len(), IP_BUCKETS_MAX_ENTRIES);
        assert!(
            !buckets.contains_key("10.0.0.0"),
            "lowest-count bucket in current hour must be evicted"
        );
        assert!(buckets.contains_key("192.168.1.1"));

        let mut drips = std::collections::HashMap::new();
        let now = 50_000u64;
        let cooldown = 2_700u64;
        for i in 0..PUBLIC_DRIP_PRUNE_THRESHOLD {
            let mut who = [0u8; 32];
            who[..8].copy_from_slice(&(i as u64).to_be_bytes());
            // Entry 0 is oldest active within window.
            drips.insert(who, now - 100 + if i == 0 { 0 } else { 50 });
        }
        assert_eq!(drips.len(), PUBLIC_DRIP_PRUNE_THRESHOLD);

        let newcomer = [0xFFu8; 32];
        cap_last_public_drip(&mut drips, now, cooldown, &newcomer);
        drips.insert(newcomer, now);
        assert_eq!(drips.len(), PUBLIC_DRIP_PRUNE_THRESHOLD);
        assert!(
            !drips.contains_key(&[0u8; 32]),
            "oldest active cooldown must be evicted at cap"
        );
        assert!(drips.contains_key(&newcomer));
    }
}
