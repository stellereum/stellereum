//! BLS is CLASSICAL (quantum-breakable) — LEGACY-ONLY marker and default-off pins.
//!
//! BLS12-381 pairings fall to Shor's algorithm: this module is never a
//! post-quantum primitive. What this pins (additive only; no existing test or
//! BLS logic touched):
//! * `BLS_IS_POST_QUANTUM == false` (the programmatic policy marker);
//! * default startup still refuses to COUNT BLS-QC power (`STELL_BLS_QC=1`
//!   hard-refused; unset/off starts the Ed25519 baseline unchanged).

use stellereum::bls::*;

// Env-touching tests share one process-wide guard so parallel threads never
// observe each other's temporary `set_var`/`remove_var` windows.
static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvRestore {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvRestore {
    fn save(keys: &[&'static str]) -> Self {
        Self {
            saved: keys.iter().map(|k| (*k, std::env::var(k).ok())).collect(),
        }
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

#[test]
fn bls_is_marked_not_post_quantum() {
    // GATE: pins the classical marker at RUNTIME (black_box defeats the
    // const-fold; the test must fail loudly if the marker is flipped).
    assert!(
        !std::hint::black_box(BLS_IS_POST_QUANTUM),
        "BLS12-381 is classical (Shor-breakable): the marker must stay false"
    );
}

#[test]
fn default_startup_still_refuses_bls_qc_counting() {
    let _gate = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let _restore = EnvRestore::save(&[BLS_QC_ENV]);

    // Default (unset): no refusal — the Ed25519 baseline starts as before.
    // GATE (HDAE wire-EMIT cut): the `QcBlsConfig::default().enabled` pin lived
    // here; the shell is deleted (zero live users), and the gate-OK assert
    // above already pins default-OFF.
    std::env::remove_var(BLS_QC_ENV);
    assert!(refuse_bls_qc_if_enabled().is_ok());

    // Enabled still hard-refuses: consensus MUST NOT count BLS aggregate QCs
    // on the default/PQ path.
    for on_spelling in ["1", "true", "TRUE", "on", "ON"] {
        std::env::set_var(BLS_QC_ENV, on_spelling);
        assert!(
            refuse_bls_qc_if_enabled().is_err(),
            "{on_spelling:?} must still be refused at startup"
        );
    }

    // Anything else stays OFF (and therefore unrefused).
    for off_spelling in ["0", "false", "yes", ""] {
        std::env::set_var(BLS_QC_ENV, off_spelling);
        assert!(
            refuse_bls_qc_if_enabled().is_ok(),
            "{off_spelling:?} must mean OFF"
        );
    }
}
