//! Chain-binding rollout (A14 structural fix), PHASE 1.
//!
//! # Status: activation plumbing + admission predicate + discovery strings
//!
//! Wallets default to UNBOUND envelopes today (a testnet signature verifies on
//! mainnet); the RPC admits unbound transactions with warn+meter (phase 1
//! shipped: `note_unbound_admission` in `rpc.rs`, counter
//! `stell_unbound_tx_total`). This module is the phase-2/3 scaffolding from
//! `docs/PLAN-BINDING.md`: the activation-height switch, the PURE admission
//! predicate phase 3 will wire into every admission path, the exact RPC
//! refusal string wallets discover the requirement through, and the pure
//! mempool-drain helper for in-flight unbound transactions at activation.
//!
//! NOTHING here used to be wired into admission: every admission path behaved
//! byte-identically with or without this module. Phase 3 wires
//! [`check_admission`] (via [`check_admission_from_env`], which reads the
//! ambient [`CHAIN_BINDING_ACTIVATION_ENV`]) into `rpc.rs`
//! (`stell_sendRawTransaction`, `admit_signed_payload_tx`,
//! `eth_sendRawTransaction`), `mempool.rs::insert` (gated on
//! `AdmissionCtx::chain_height`, so height-less callers keep legacy
//! behaviour), the block-apply gates in `state_engine.rs` (committed block
//! height), and the one-shot activation drain in `main.rs`. With the env
//! unset every one of those paths still admits exactly as before
//! (default-off is byte-identical).

use std::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Activation
// ============================================================================

/// Environment variable naming the chain height at which unbound transactions
/// start being REFUSED. Unset / unparsable / `0` means "never" (phase 1+2
/// behaviour: admit + meter). A scheduled height (governance-agreed, published
/// in `docs/PLAN-BINDING.md`) is the activation mechanism — see the plan doc
/// for why a flag-day height beats a governance vote for a replay-safety
/// rule (votes themselves need replay-safe envelopes to be trustworthy).
pub const CHAIN_BINDING_ACTIVATION_ENV: &str = "STELL_CHAIN_BIND_ACTIVATION_HEIGHT";

/// Sentinel meaning "refusal never activates" (the default).
pub const CHAIN_BINDING_NEVER: u64 = u64::MAX;

/// Activation height for the unbound-transaction refusal (phase 3).
///
/// `height == CHAIN_BINDING_NEVER` (default) keeps phase-1 behaviour on every
/// path. Otherwise, at chain height `>= height`, admitting or including an
/// unbound transaction is a consensus failure. Heights are comparable across
/// mixed-version nodes because the boundary is a plain integer every node
/// derives from the same env/governance value — no clock, no voting round.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChainBindingActivation {
    pub height: u64,
}

impl ChainBindingActivation {
    /// Refusal never activates (phase 1+2 behaviour).
    pub fn never() -> Self {
        Self {
            height: CHAIN_BINDING_NEVER,
        }
    }

    /// Refuse unbound transactions at and after `height`.
    pub fn at_height(height: u64) -> Self {
        Self { height }
    }

    /// Read from the environment. Unset / unparsable / `0` => [`Self::never`].
    pub fn from_env() -> Self {
        let raw = std::env::var(CHAIN_BINDING_ACTIVATION_ENV).unwrap_or_default();
        match raw.trim().parse::<u64>() {
            Ok(h) if h != 0 => Self { height: h },
            _ => Self::never(),
        }
    }

    /// True when unbound transactions must be refused at `chain_height`.
    /// The `never()` sentinel refuses at NO height (even `u64::MAX`).
    pub fn refusal_active(&self, chain_height: u64) -> bool {
        self.height != CHAIN_BINDING_NEVER && chain_height >= self.height
    }
}

// ============================================================================
// Admission predicate (phase-3 wiring target — pure, tested, not yet called)
// ============================================================================

/// Prefix of the RPC refusal string every admission path must return for an
/// unbound transaction once refusal is active. Pinned here (not formatted
/// inline at each call site) so wallets can match ONE stable string across
/// RPC methods and versions.
pub const UNBOUND_REFUSED_ERR_PREFIX: &str = "rejected: unbound transaction refused";

/// The exact RPC refusal string for an unbound transaction at activation.
/// Tells the wallet WHAT happened, SINCE WHEN, and HOW to fix it (re-sign
/// bound to `chain_id`), plus where the rollout is documented.
pub fn unbound_refused_err(activation_height: u64, chain_id: u64) -> String {
    format!(
        "{UNBOUND_REFUSED_ERR_PREFIX}: chain binding enforced at height {activation_height}; \
         re-sign the transaction bound to chain_id {chain_id} \
         (wallet: create_bound_transaction / new_*_with_chain; see docs/PLAN-BINDING.md)"
    )
}

/// Prefix shared by every chain-id mismatch refusal (mempool admission and
/// state-engine apply use the identical sentence so operators grep once).
/// A foreign-bound envelope is cryptographically valid on ITS network — the
/// refusal is about the replay domain, never the signature.
pub const CHAIN_ID_MISMATCH_ERR_PREFIX: &str = "Transaction chain_id mismatch:";

/// Cross-network replay refusal naming BOTH chains, byte-identical to the
/// state-engine apply gate (`state_engine.rs`) so operators grep once.
/// Pure so every surface refuses identically.
pub fn chain_id_mismatch_err(envelope_chain: u64, our_chain: u64) -> String {
    format!(
        "{CHAIN_ID_MISMATCH_ERR_PREFIX} chain id {envelope_chain} does not match this chain ({our_chain})"
    )
}

/// Human-readable requirement line for wallet discovery (RPC help text, CLI
/// `--help`, onboarding docs): which chain id to bind to and what happens
/// without it. Pure so every surface prints the same sentence.
pub fn wallet_requirement_doc(chain_id: u64, activation: &ChainBindingActivation) -> String {
    match activation.height {
        CHAIN_BINDING_NEVER => format!(
            "chain binding: sign transactions bound to chain_id {chain_id}; \
             unbound transactions are currently admitted but metered and will be refused \
             after a scheduled activation height (see docs/PLAN-BINDING.md)"
        ),
        h => format!(
            "chain binding: REQUIRED — sign transactions bound to chain_id {chain_id}; \
             unbound transactions are refused at height >= {h}"
        ),
    }
}

/// Phase-3 admission decision for ONE transaction. `is_bound` is
/// `tx.chain_id().is_some()` (covers CH1, session grants, PQ chain binding
/// and EVM settlement — every envelope with a replay domain); `chain_height`
/// is the height the transaction would be admitted/included at.
///
/// * unbound + refusal inactive => `Ok(())` (phase-1 behaviour: the caller
///   still warns + meters);
/// * unbound + refusal active => `Err(`[`unbound_refused_err`]` careful:
///   returns the owned string, call sites map it to their error type);
/// * bound => `Ok(())` at every height (activation never breaks bound flow).
pub fn check_admission(
    is_bound: bool,
    chain_height: u64,
    activation: &ChainBindingActivation,
    chain_id: u64,
) -> Result<(), String> {
    if is_bound || !activation.refusal_active(chain_height) {
        return Ok(());
    }
    Err(unbound_refused_err(activation.height, chain_id))
}

/// Phase-3 wiring helper: [`check_admission`] against the ambient environment
/// ([`CHAIN_BINDING_ACTIVATION_ENV`], default-off). Every production admission
/// path calls this (never [`check_admission`] with a hand-rolled activation)
/// so there is exactly ONE env name and ONE default-off rule: unset /
/// unparsable / `0` admits everything, byte-identically to the pre-wiring
/// behaviour. The caller supplies the height (committed block height at
/// propose/apply, finalized-tip+1 at RPC ingress — see the `// GATE:`
/// comment at each call site, never a caller-supplied value) and the local
/// chain id (used only for the refusal message).
pub fn check_admission_from_env(
    is_bound: bool,
    chain_height: u64,
    chain_id: u64,
) -> Result<(), String> {
    check_admission(is_bound, chain_height, &ChainBindingActivation::from_env(), chain_id)
}

/// Split one mempool snapshot at activation: bound transactions stay queued,
/// unbound ones are dropped (returned second) so the caller can count and log
/// them. PURE — phase 3 calls it once when crossing the activation height
/// (see `docs/PLAN-BINDING.md` for why in-flight unbound txs are dropped
/// rather than grandfathered: a grandfathered unbound tx included post-height
/// would fork mixed-version nodes).
///
/// Items are `(T, is_bound)` pairs so the helper stays independent of the
/// `Transaction` type; order is preserved in both outputs.
pub fn partition_at_activation<T>(
    items: Vec<(T, bool)>,
    chain_height: u64,
    activation: &ChainBindingActivation,
) -> (Vec<T>, Vec<T>) {
    if !activation.refusal_active(chain_height) {
        let kept = items.into_iter().map(|(t, _)| t).collect();
        return (kept, Vec::new());
    }
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for (t, is_bound) in items {
        if is_bound {
            kept.push(t);
        } else {
            dropped.push(t);
        }
    }
    note_unbound_dropped(dropped.len() as u64);
    (kept, dropped)
}

// ============================================================================
// Phase-3 metering (dropped-at-activation counter; admission metering reuses
// the existing `stell_unbound_tx_total`)
// ============================================================================

static UNBOUND_DROPPED_AT_ACTIVATION: AtomicU64 = AtomicU64::new(0);

fn note_unbound_dropped(n: u64) {
    UNBOUND_DROPPED_AT_ACTIVATION.fetch_add(n, Ordering::Relaxed);
}

/// How many queued unbound transactions this process has dropped at
/// activation (phase 3). Zero until phase 3 wires [`partition_at_activation`].
pub fn unbound_dropped_at_activation() -> u64 {
    UNBOUND_DROPPED_AT_ACTIVATION.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN_ID: u64 = 5757;

    #[test]
    fn default_never_refuses_and_env_parses() {
        let never = ChainBindingActivation::never();
        assert!(!never.refusal_active(0));
        assert!(!never.refusal_active(u64::MAX));
        let at = ChainBindingActivation::at_height(10_000);
        assert!(!at.refusal_active(9_999));
        assert!(at.refusal_active(10_000));
        assert!(at.refusal_active(10_001));
        // Env: unset/garbage/zero => never.
        assert_eq!(
            ChainBindingActivation::from_env(),
            ChainBindingActivation::never()
        );
    }

    #[test]
    fn phase1_behaviour_is_admit_everything() {
        let never = ChainBindingActivation::never();
        assert!(
            check_admission(false, 1, &never, CHAIN_ID).is_ok(),
            "phase 1 admits unbound"
        );
        assert!(check_admission(true, 1, &never, CHAIN_ID).is_ok());
    }

    #[test]
    fn phase3_refuses_only_unbound_at_and_after_height() {
        let act = ChainBindingActivation::at_height(10_000);
        // Bound flows at every height, including post-activation.
        assert!(check_admission(true, 9_999, &act, CHAIN_ID).is_ok());
        assert!(check_admission(true, 10_000, &act, CHAIN_ID).is_ok());
        // Unbound passes before, refuses at and after.
        assert!(check_admission(false, 9_999, &act, CHAIN_ID).is_ok());
        let err = check_admission(false, 10_000, &act, CHAIN_ID).expect_err("must refuse");
        assert!(
            err.starts_with(UNBOUND_REFUSED_ERR_PREFIX),
            "refusal string must start with the pinned prefix: {err}"
        );
        assert!(
            err.contains("10000"),
            "refusal names the activation height: {err}"
        );
        assert!(
            err.contains("5757"),
            "refusal names the chain id to bind to: {err}"
        );
        assert!(check_admission(false, 10_001, &act, CHAIN_ID).is_err());
    }

    #[test]
    fn activation_drain_keeps_bound_and_drops_unbound_only_when_active() {
        let act = ChainBindingActivation::at_height(100);
        // Pre-activation: nothing drops (even unbound).
        let (kept, dropped) = partition_at_activation(vec![("a", false), ("b", true)], 99, &act);
        assert_eq!(kept, vec!["a", "b"]);
        assert!(dropped.is_empty());
        // At activation: bound stays, unbound drops, order preserved.
        let (kept, dropped) =
            partition_at_activation(vec![("a", false), ("b", true), ("c", false)], 100, &act);
        assert_eq!(kept, vec!["b"]);
        assert_eq!(dropped, vec!["a", "c"]);
        // Never-activation: full pass-through.
        let (kept, dropped) = partition_at_activation(
            vec![("a", false)],
            u64::MAX - 1,
            &ChainBindingActivation::never(),
        );
        assert_eq!(kept, vec!["a"]);
        assert!(dropped.is_empty());
    }

    #[test]
    fn wallet_discovery_strings_name_chain_and_state() {
        let pending = wallet_requirement_doc(CHAIN_ID, &ChainBindingActivation::never());
        assert!(pending.contains("5757"));
        assert!(pending.contains("metered"));
        let enforced = wallet_requirement_doc(CHAIN_ID, &ChainBindingActivation::at_height(50_000));
        assert!(enforced.contains("REQUIRED"));
        assert!(enforced.contains("50000"));
    }
}
