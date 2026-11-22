//! Fresh-observer bootstrap: from an empty data directory to the live tip
//! WITHOUT manual `cp -a` of another node's data directory.
//!
//! The sync engine itself already lives in the `run` path
//! (`try_snapshot_sync` → `fast_sync_state` → `walk_chain` in `src/main.rs`,
//! anchored by [`crate::sync::verify_snapshot_anchor_tail`] and paced by the
//! storm-guard budgets in [`crate::sync`]). What was missing was the GATE in
//! front of it: a fresh node that starts with the wrong preconditions (dirty
//! data dir from another chain, `STELL_OBSERVER` lost, no live peer
//! configured, empty `validators:`) derives its own solo genesis and then
//! "syncs" onto a private chain — silently. That is the failure this module
//! closes.
//!
//! The flow (`stellereum node-bootstrap --config node.yaml`):
//!
//! ```text
//!   Stage 1  preflight: STELL_OBSERVER=1, STELL_FAUCET_KEY set,
//!                       data dir CLEAN (refuse a dirty dir, never wipe it),
//!                       config names a live peer (peers: or STELL_DNS_SEEDS)
//!                       and a non-empty validators: set.
//!   Stage 2  snapshot-sync: newest usable 100-boundary (or the exact
//!                       latest-snapshot pointer), state + EVERY committed
//!                       domain (accounts, domains, session, bridge,
//!                       confidential, zkml, cross_shard — the staking LEDGER
//!                       rides the accounts snapshot, so the validator set
//!                       converges via refresh_validator_set_from_staking).
//!   Stage 3  walk the short remainder by bodies (QC per height).
//!   Stage 4  live: the consensus loop owns the tip from here.
//! ```
//!
//! Every stage logs LOUDLY (`[bootstrap]`) and every network wait is bounded
//! with honest retries (exponential backoff + jitter, same ladder as the
//! fetch path) — a slow link or a stale peer delays bootstrap, never lies to
//! it. A stale domain blob (present but not matching the anchored root) is a
//! REJECTION with a retry on the next boundary, never a commit.
//!
//! This module holds the pure, test-pinned half (preflight predicates, plan,
//! retry schedule, stale classification). The live half is the existing `run`
//! engine, which `node-bootstrap` execs into after the gate passes — one code
//! path, no fork.

use std::path::Path;

/// How many whole-flow bootstrap attempts the CLI makes before giving up.
///
/// One attempt = one preflight + one handoff to the sync engine. The engine
/// itself retries internally (per-chunk, per-blob, per-boundary); this bound
/// is only the outer "peer set completely dead" loop. Loud on every attempt.
pub const BOOTSTRAP_MAX_ATTEMPTS: u32 = 5;

/// Gap at or below which no snapshot is needed: the bodies are walked
/// directly. Mirrors the `> 100` gate in `try_catch_up` (src/main.rs) so the
/// plan and the engine can never disagree about which path owns the gap.
pub const BOOTSTRAP_SNAPSHOT_GAP: u64 = 100;

/// Consecutive stale-domain rejections after which the plan moves to the next
/// older boundary instead of retrying the same one. A boundary whose domains
/// never match its anchored root is poisoned-or-rotated, not slow.
pub const BOOTSTRAP_MAX_STALE_PER_BOUNDARY: u32 = 3;

/// Preflight verdict for one fresh-observer bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapPreflight {
    /// `STELL_OBSERVER` is `1`/`true`: the node follows, never mints genesis.
    pub observer: bool,
    /// `STELL_FAUCET_KEY` is present (genesis input; must match the network).
    pub faucet_key_present: bool,
    /// The data directory holds no previous chain.
    pub data_dir_clean: bool,
    /// The config names someone live (`peers:` non-empty or DNS seeds set).
    pub peer_pointer_present: bool,
    /// `validators:` is non-empty (empty derives a solo genesis = split).
    pub validator_set_present: bool,
}

impl BootstrapPreflight {
    /// True only when every gate passes. Any `false` is a fail-closed
    /// refusal with a named cause, never a guess forward.
    pub fn ready(&self) -> bool {
        self.observer
            && self.faucet_key_present
            && self.data_dir_clean
            && self.peer_pointer_present
            && self.validator_set_present
    }

    /// Every failing gate, in stable order, for the loud refusal line.
    pub fn failures(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.observer {
            out.push("STELL_OBSERVER!=1 (a fresh key without the observer flag mints its own genesis and splits)");
        }
        if !self.faucet_key_present {
            out.push("STELL_FAUCET_KEY unset (genesis input must match the network byte-for-byte)");
        }
        if !self.data_dir_clean {
            out.push("data directory is NOT clean (wipe the whole ./data, never single files — OPERATIONS §8 — or re-run with --allow-dirty for a restart, not a fresh bootstrap)");
        }
        if !self.peer_pointer_present {
            out.push("no live peer pointer (peers: is empty and STELL_DNS_SEEDS is unset — the node would bootstrap against nobody)");
        }
        if !self.validator_set_present {
            out.push("validators: is empty (derives a solo genesis and splits silently — get the CURRENT set from the admin)");
        }
        out
    }
}

/// Env var that explicitly authorises minting a NEW genesis on a fresh data
/// directory even though peers/DNS seeds are configured (i.e. the operator
/// really means "found a new chain", not "join the network").
///
/// `1` or case-insensitive `true` opts in. Anything else — including unset —
/// is NOT authorised. Fail-closed: a typo'd data dir with live peers must
/// never fork itself off the network silently.
pub const NEW_CHAIN_ENV: &str = "STELL_NEW_CHAIN";

/// Parse the new-chain flag exactly the way [`is_observer_env`] parses its
/// flag: `1` or case-insensitive `true`. Anything else is NOT authorised.
pub fn is_new_chain_explicit(v: Option<&str>) -> bool {
    matches!(v, Some(s) if s == "1" || s.eq_ignore_ascii_case("true"))
}

/// [`is_new_chain_explicit`] over the live process environment.
pub fn is_new_chain_explicit_env() -> bool {
    is_new_chain_explicit(std::env::var(NEW_CHAIN_ENV).ok().as_deref())
}

/// The loud refusal text for a fresh data dir that points at live peers.
///
/// Names the exact recovery command so the operator is never left guessing:
/// either wipe the pointer (to found) or export the flag (to confirm founding).
/// Validator keys joining an existing network must come in as OBSERVERS first
/// (STELL_OBSERVER=1: network-matching genesis, no self-add), sync, then
/// promote — a fresh validator-config mint would fork a private genesis.
pub fn fresh_join_refusal_message() -> String {
    format!(
        "[bootstrap] REFUSING: fresh/empty data directory BUT peers/DNS seeds are configured — \
         this node intends to JOIN, not found. Minting a new genesis now would fork it onto a \
         private chain SILENTLY. Refusing fail-closed. Recovery: EITHER point at an empty peer \
         set to found a new chain, OR confirm founding explicitly with \
         {env}=1, e.g.: {env}=1 stellereum node-bootstrap --config node.yaml. \
         Joining an existing network with a validator key? Set STELL_OBSERVER=1 first (sync as \
         observer), then unset it to promote — never mint a fresh validator genesis against peers.",
        env = NEW_CHAIN_ENV
    )
}

/// Fail-closed gate for the empty-data-dir path (task (a)).
///
/// * dirty data dir (`data_dir_clean == false`) → `Ok`: this is a restart,
///   owned by the genesis-fingerprint guard, not by this gate.
/// * clean dir with NO peer pointer → `Ok`: nothing to join, founding is the
///   only interpretation.
/// * clean dir WITH a peer pointer (peers: or `STELL_DNS_SEEDS`) → this node
///   intends to JOIN. Minting a fresh genesis would fork it silently, so
///   refuse with [`fresh_join_refusal_message`] unless `new_chain_explicit`
///   (`STELL_NEW_CHAIN=1`) confirms founding.
///
/// The `Err` string IS the loud log line: callers must print it (and the
/// env-reading wrapper below already does, via both `eprintln!` and
/// `tracing::error!`).
pub fn guard_fresh_data_dir(
    data_dir_clean: bool,
    peer_pointer_present: bool,
    new_chain_explicit: bool,
) -> Result<(), String> {
    if !data_dir_clean {
        return Ok(());
    }
    if !peer_pointer_present {
        return Ok(());
    }
    if new_chain_explicit {
        return Ok(());
    }
    Err(fresh_join_refusal_message())
}

/// Env-reading wrapper over [`guard_fresh_data_dir`]: reads `STELL_NEW_CHAIN`
/// itself and logs the refusal LOUDLY (stderr + tracing) on the join path.
///
/// Returns the same `Result` so callers can `bail!` on it.
pub fn guard_fresh_data_dir_from_env(
    data_dir_clean: bool,
    peer_pointer_present: bool,
) -> Result<(), String> {
    let explicit = is_new_chain_explicit_env();
    match guard_fresh_data_dir(data_dir_clean, peer_pointer_present, explicit) {
        Ok(()) => Ok(()),
        Err(msg) => {
            eprintln!("{msg}");
            tracing::error!("{msg}");
            Err(msg)
        }
    }
}

/// Parse the observer flag exactly the way `build_validator_set` does
/// (src/main.rs): `1` or case-insensitive `true`. Anything else — including
/// unset — is NOT an observer.
pub fn is_observer_env(v: Option<&str>) -> bool {
    matches!(v, Some(s) if s == "1" || s.eq_ignore_ascii_case("true"))
}

/// Pure core of the data-dir gate: clean means NEITHER a block store NOR a
/// DHT blob cache from a previous run is present. Takes booleans (not paths)
/// so tests pin the truth table without touching the filesystem.
pub fn data_dir_is_clean(store_exists: bool, kv_exists: bool) -> bool {
    !store_exists && !kv_exists
}

/// Filesystem wrapper over [`data_dir_is_clean`]: a directory is dirty when
/// `<dir>/store` (block/state store) or `<dir>/kv.json` (DHT blob cache)
/// exists. Missing directory itself counts as clean (fresh machine).
pub fn data_dir_is_clean_fs(dir: &Path) -> bool {
    let store_exists = dir.join("store").exists();
    let kv_exists = dir.join("kv.json").exists();
    data_dir_is_clean(store_exists, kv_exists)
}

/// The snapshot boundary a bootstrap attempt must try FIRST.
///
/// Mirrors `try_snapshot_sync` (src/main.rs) exactly: the newest 100-height
/// boundary at/below the peer tip, overridden by the exact latest-snapshot
/// pointer when it is sane (ahead of us, at or under the peer tip —
/// snapshots complete on worker timing, so %100 probes miss them all).
/// Returns `None` when no snapshot is needed (gap is walk-sized) or no
/// boundary exists above our height.
pub fn select_bootstrap_boundary(
    peer_height: u64,
    our_height: u64,
    latest_pointer: Option<u64>,
) -> Option<u64> {
    if peer_height <= our_height {
        return None;
    }
    if peer_height - our_height <= BOOTSTRAP_SNAPSHOT_GAP {
        return None;
    }
    let mut boundary = (peer_height / 100) * 100;
    if let Some(latest) = latest_pointer {
        if latest > our_height && latest <= peer_height {
            boundary = latest;
        }
    }
    if boundary <= our_height || boundary == 0 {
        return None;
    }
    Some(boundary)
}

/// Outer retry delay for a failed bootstrap attempt (ms): the same jittered
/// exponential ladder as the fetch path
/// ([`crate::sync::fetch_retry_backoff_with_jitter_ms`]), so a dead peer set
/// is re-probed on a schedule that paces the DHT instead of hammering it.
/// `attempt` is 1-based; `jitter` is the caller's uniform draw (clamped
/// inside, like the fetch path).
pub fn bootstrap_retry_delay_ms(attempt: u32, jitter: u64) -> u64 {
    crate::sync::fetch_retry_backoff_with_jitter_ms(attempt, jitter)
}

/// What one snapshot-boundary attempt concluded about its domain bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryOutcome {
    /// State + every domain verified against the anchored root. Done.
    Committed { boundary: u64 },
    /// A domain blob was missing (pruned peer, weak link): retry, same
    /// boundary — absence is transient, not evidence.
    MissingDomain { boundary: u64, kind: String },
    /// A domain blob was PRESENT but the bundle failed the trusted-root
    /// check: stale/poisoned. Retry the same boundary while the per-boundary
    /// budget holds, then step to the next older boundary.
    StaleDomain {
        boundary: u64,
        kind: String,
        consecutive_stale: u32,
    },
}

/// Next step after a stale-domain rejection: retry the same boundary while
/// the per-boundary budget holds, else step one 100-window older (never
/// below `our_height`, never 0 — exhaustion is `None`, a loud refusal, not
/// a wrap).
pub fn next_boundary_after_stale(
    boundary: u64,
    consecutive_stale: u32,
    our_height: u64,
) -> Option<u64> {
    if consecutive_stale < BOOTSTRAP_MAX_STALE_PER_BOUNDARY {
        return Some(boundary);
    }
    let older = boundary.saturating_sub(100);
    if older <= our_height || older == 0 {
        return None;
    }
    Some(older)
}

/// One line of the loud stage log. Stages are 1-based out of 4
/// (preflight → snapshot → walk → live) so `journalctl` readers can tell at a
/// glance how far a fresh node got.
pub fn stage_line(stage: u32, msg: &str) -> String {
    format!("[bootstrap] stage {stage}/4: {msg}")
}

/// Short hex prefix for 3am log lines: first 16 hex chars with a trailing
/// `...` when longer. Keeps the fail-closed genesis-guard lines short while
/// still distinguishing roots.
fn short_root_hex(raw: &[u8]) -> String {
    let full = hex::encode(raw);
    if full.len() > 16 {
        format!("{}...", &full[..16])
    } else {
        full
    }
}

/// Fail-closed genesis-guard message (message text only: no I/O, no env).
///
/// `expected` is the freshly computed root (this config), `found` is the
/// stored root from the data directory. `shard` names the shard store when
/// the guard is per-shard, or `None` for the masterchain data directory.
///
/// The text names both roots (16-hex-char prefixes), the shard when given,
/// and the usual suspects (`STELL_FAUCET_KEY(/_FILE)`,
/// the `validators:` list, `STELL_SHARDS`)
/// plus the wipe-or-restore recovery. Callers must still refuse to start
/// (comparison semantics unchanged — this only formats the refusal).
pub fn genesis_mismatch_msg(shard: Option<u32>, expected: &[u8; 32], found: &[u8]) -> String {
    let expected_hex = short_root_hex(expected);
    let found_hex = short_root_hex(found);
    let scope = match shard {
        Some(s) => format!("for the shard {s} store"),
        None => "for this data directory".to_string(),
    };
    format!(
        "genesis state root mismatch {scope}:\n  expected (config): {expected_hex}\n  found (stored): {found_hex}\n\
          Suspects: STELL_FAUCET_KEY(/_FILE), validators: list, STELL_SHARDS. \
         Wipe ./data to start a new chain, or restore the original config."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observer_flag_parses_exactly_like_the_validator_set_builder() {
        assert!(is_observer_env(Some("1")));
        assert!(is_observer_env(Some("true")));
        assert!(is_observer_env(Some("TRUE")));
        assert!(!is_observer_env(None));
        assert!(!is_observer_env(Some("0")));
        assert!(!is_observer_env(Some("yes")));
        assert!(!is_observer_env(Some("")));
    }

    #[test]
    fn dirty_dir_truth_table() {
        assert!(data_dir_is_clean(false, false));
        assert!(!data_dir_is_clean(true, false));
        assert!(!data_dir_is_clean(false, true));
        assert!(!data_dir_is_clean(true, true));
    }

    #[test]
    fn preflight_is_fail_closed_and_names_every_cause() {
        let bad = BootstrapPreflight {
            observer: false,
            faucet_key_present: false,
            data_dir_clean: false,
            peer_pointer_present: false,
            validator_set_present: false,
        };
        assert!(!bad.ready());
        assert_eq!(bad.failures().len(), 5);
        let good = BootstrapPreflight {
            observer: true,
            faucet_key_present: true,
            data_dir_clean: true,
            peer_pointer_present: true,
            validator_set_present: true,
        };
        assert!(good.ready());
        assert!(good.failures().is_empty());
        // One lost flag is enough to refuse: the observer flag alone gates genesis.
        let lost_flag = BootstrapPreflight {
            observer: false,
            ..good.clone()
        };
        assert!(!lost_flag.ready());
    }

    #[test]
    fn boundary_selection_mirrors_the_sync_engine() {
        // Walk-sized gap: no snapshot.
        assert_eq!(select_bootstrap_boundary(50, 0, None), None);
        assert_eq!(select_bootstrap_boundary(100, 0, None), None);
        // Newest 100-boundary below the tip.
        assert_eq!(select_bootstrap_boundary(72704, 0, None), Some(72700));
        // Exact pointer wins when sane (worker-timed heights like 78519).
        assert_eq!(
            select_bootstrap_boundary(78620, 0, Some(78519)),
            Some(78519)
        );
        // Insane pointers are ignored, never trusted.
        assert_eq!(
            select_bootstrap_boundary(78620, 0, Some(99999)),
            Some(78600)
        );
        assert_eq!(select_bootstrap_boundary(78620, 0, Some(0)), Some(78600));
        // Not ahead of us: nothing to do.
        assert_eq!(select_bootstrap_boundary(100, 100, None), None);
        assert_eq!(select_bootstrap_boundary(90, 100, None), None);
    }

    #[test]
    fn stale_boundary_steps_down_then_refuses_loudly() {
        // Budget holds: retry the same boundary.
        assert_eq!(next_boundary_after_stale(72700, 0, 0), Some(72700));
        assert_eq!(next_boundary_after_stale(72700, 2, 0), Some(72700));
        // Budget spent: step one window older.
        assert_eq!(next_boundary_after_stale(72700, 3, 0), Some(72600));
        // Floor: never step at/below our height, never to 0.
        assert_eq!(next_boundary_after_stale(100, 3, 0), None);
        assert_eq!(next_boundary_after_stale(200, 3, 150), None);
    }

    #[test]
    fn retry_ladder_paces_dead_peers_and_never_hurries() {
        // Floor is always the exponential base: a dead peer set is never
        // re-probed sooner than 100ms (same anti-re-flood contract as fetches).
        assert!(bootstrap_retry_delay_ms(1, 0) >= 100);
        assert!(bootstrap_retry_delay_ms(1, 0) <= 200);
        assert!(bootstrap_retry_delay_ms(5, 0) >= bootstrap_retry_delay_ms(1, 0));
        // Jitter only delays, capped at +100ms.
        assert_eq!(
            bootstrap_retry_delay_ms(1, 10_000),
            bootstrap_retry_delay_ms(1, 0) + 100
        );
    }
}
