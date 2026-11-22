//! Cloudflare Turnstile captcha gate for the public faucet.
//!
//! The public faucet (`POST /api/faucet-public/:address`) requires a
//! proof-of-humanity check in front of the per-IP hourly budget.
//! OPERATOR CONTRACT (fail-closed):
//! - Set BOTH `STELL_TURNSTILE_SITE_KEY` and `STELL_TURNSTILE_SECRET_KEY` to
//!   enable the captcha (`CaptchaConfig::Enabled`): every public claim is
//!   verified via Cloudflare `siteverify` before any budget is consumed.
//! - When NEITHER key is set (`CaptchaConfig::Disabled`) the gateway refuses
//!   non-loopback public claims with `503 captcha not configured` and moves
//!   no funds; loopback clients (`127.0.0.0/8`, `::1` — local dev/tests) keep
//!   the IP-throttle-only path (see `api_faucet_public`).
//!
//! Configuration (both keys or neither):
//!
//! | variable | visibility | meaning |
//! |---|---|---|
//! | `STELL_TURNSTILE_SITE_KEY` | public (embedded in the explorer HTML) | widget site key |
//! | `STELL_TURNSTILE_SECRET_KEY` | server-only, never logged | siteverify secret |
//!
//! A deployment that sets only one of the two keys is treated as a
//! misconfiguration: the faucet answers `503` instead of silently dispensing
//! without captcha (fail-closed — the operator clearly *meant* to enable it),
//! on loopback and non-loopback alike.
//!
//! Verification happens server-side against Cloudflare's `siteverify` endpoint
//! through the already-vendored blocking HTTP client (`ureq`), executed on the
//! blocking pool so the async runtime is never stalled. Tests inject a mock
//! [`CaptchaVerifier`] and never touch the network.

use std::fmt;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

/// Cloudflare Turnstile **site** key for the public faucet. This value is
/// public by design: it is embedded in the explorer HTML so the browser can
/// render the widget. Default: unset. When BOTH keys are unset the public
/// faucet is `Disabled`: non-loopback claims are refused with `503 captcha
/// not configured` (fail-closed; loopback keeps the IP-throttle-only path).
/// Must be paired with [`TURNSTILE_SECRET_KEY_ENV`]; setting only this key
/// is a misconfiguration and the public faucet answers `503` until both are set.
pub const TURNSTILE_SITE_KEY_ENV: &str = "STELL_TURNSTILE_SITE_KEY";

/// Cloudflare Turnstile **secret** key for the public faucet. Server-side
/// only: it authorizes `siteverify` calls and must never reach a browser, a
/// log line, or an error message. Default: unset. When BOTH keys are unset
/// the public faucet is `Disabled`: non-loopback claims are refused with
/// `503 captcha not configured` (fail-closed; loopback keeps the
/// IP-throttle-only path). Must be paired with
/// [`TURNSTILE_SITE_KEY_ENV`]; setting only this key is a
/// misconfiguration and the public faucet answers `503` until both are set —
/// refusing beats dispensing without captcha while the operator believes the
/// captcha is on.
pub const TURNSTILE_SECRET_KEY_ENV: &str = "STELL_TURNSTILE_SECRET_KEY";

/// Cloudflare `siteverify` endpoint (HTTPS, form-encoded POST).
pub const SITEVERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// Network budget for one `siteverify` round-trip. Also applied as the total
/// deadline of the blocking-pool task, so a wedged DNS resolver cannot hold a
/// faucet request open forever.
pub const SITEVERIFY_TIMEOUT: Duration = Duration::from_secs(8);

/// Cap on the `siteverify` response body we are willing to buffer. Cloudflare
/// responses are a few hundred bytes; anything larger is not something we
/// parse (and not something we should keep in memory per request).
const MAX_SITEVERIFY_BODY_BYTES: u64 = 8 * 1024;

/// Outcome of one captcha verification. Deliberately not `bool`: the faucet
/// must distinguish "Cloudflare said no" (client should retry with a fresh
/// token) from "we could not ask Cloudflare" (fail closed, operator problem).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaptchaVerdict {
    /// `{"success":true}` — the token proved humanity.
    Success,
    /// `{"success":false,...}` — Cloudflare rejected the token. `error_codes`
    /// carries the `error-codes` array (e.g. `invalid-input-response`,
    /// `timeout-or-duplicate`); safe to log and to echo, unlike the token.
    Rejected { error_codes: Vec<String> },
    /// Transport failure, timeout, or an unparseable response: we do not know
    /// whether the token was valid, so the faucet must NOT dispense.
    Unavailable { reason: String },
}

/// Captcha configuration derived from the environment. The secret is never
/// printed by `Debug` (see the manual impl below).
#[derive(Clone, PartialEq, Eq)]
pub enum CaptchaConfig {
    /// Neither key set: non-loopback public claims are refused with `503
    /// captcha not configured` (fail-closed, no funds move); loopback clients
    /// (local dev/tests) keep the per-IP hourly budget path. Configure BOTH
    /// keys to enable the captcha on public claims.
    Disabled,
    /// Both keys set: the captcha is mandatory on the public faucet.
    Enabled {
        site_key: String,
        secret_key: String,
    },
    /// Exactly one of the two keys set — operator error. The public faucet
    /// answers `503` rather than dispensing without captcha.
    Misconfigured,
}

impl fmt::Debug for CaptchaConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => f.write_str("CaptchaConfig::Disabled"),
            Self::Misconfigured => f.write_str("CaptchaConfig::Misconfigured"),
            Self::Enabled { site_key, .. } => f
                .debug_struct("CaptchaConfig::Enabled")
                .field("site_key", site_key)
                .field("secret_key", &"<redacted>")
                .finish(),
        }
    }
}

impl CaptchaConfig {
    /// Read both keys from the environment. A key counts as set only when the
    /// variable is present and non-blank after trimming, so `= ` in a unit file
    /// does not "enable" the captcha.
    pub fn from_env() -> Self {
        let site = non_empty_env(TURNSTILE_SITE_KEY_ENV);
        let secret = non_empty_env(TURNSTILE_SECRET_KEY_ENV);
        match (site, secret) {
            (Some(site_key), Some(secret_key)) => Self::Enabled {
                site_key,
                secret_key,
            },
            (None, None) => Self::Disabled,
            // Partial config (site key only OR secret only) is refused: the
            // operator clearly meant to turn the captcha on, so failing closed
            // with a loud startup warning beats dispensing unprotected.
            _ => Self::Misconfigured,
        }
    }

    /// The public site key to embed in the explorer HTML, when the captcha is
    /// fully configured. `None` for [`CaptchaConfig::Disabled`] and
    /// [`CaptchaConfig::Misconfigured`] (the page must not advertise a widget
    /// the server cannot verify).
    pub fn site_key(&self) -> Option<&str> {
        match self {
            Self::Enabled { site_key, .. } => Some(site_key),
            _ => None,
        }
    }

    /// The secret for `siteverify`, when the captcha is fully configured.
    pub fn secret_key(&self) -> Option<&str> {
        match self {
            Self::Enabled { secret_key, .. } => Some(secret_key),
            _ => None,
        }
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Transport abstraction over the `siteverify` round-trip, so faucet tests can
/// inject canned verdicts without touching the network. Implementations must
/// be blocking-safe: [`CaptchaGate`] runs them on the blocking pool.
pub trait CaptchaVerifier: Send + Sync {
    /// Exchange a turnstile token for a verdict. `secret` comes from the
    /// server-side config and must never be logged; `token` is the client-
    /// supplied `cf-turnstile-response` value and must never be logged either
    /// (it is a single-use credential).
    fn verify(
        &self,
        secret: &str,
        token: &str,
        remote_ip: Option<std::net::IpAddr>,
    ) -> CaptchaVerdict;
}

/// Production verifier: form-encoded POST to Cloudflare `siteverify` via the
/// vendored blocking HTTP client (`ureq`). No redirects, no proxy-from-env
/// (an ambient `HTTP_PROXY` must not be able to steer captcha verdicts), and
/// a hard 8 s budget on the whole round-trip.
#[derive(Debug, Default, Clone, Copy)]
pub struct TurnstileVerifier;

impl CaptchaVerifier for TurnstileVerifier {
    fn verify(
        &self,
        secret: &str,
        token: &str,
        remote_ip: Option<std::net::IpAddr>,
    ) -> CaptchaVerdict {
        let agent = ureq::AgentBuilder::new()
            .timeout(SITEVERIFY_TIMEOUT)
            .redirects(0)
            .try_proxy_from_env(false)
            .build();
        let ip_str = remote_ip.map(|ip| ip.to_string());
        let mut form: Vec<(&str, &str)> = vec![("secret", secret), ("response", token)];
        if let Some(ip) = ip_str.as_deref() {
            form.push(("remoteip", ip));
        }
        let result = agent
            .post(SITEVERIFY_URL)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_form(&form);
        match result {
            Ok(resp) => classify_siteverify_response(resp),
            // `ureq` turns 4xx/5xx into an error, but Cloudflare still ships a
            // JSON body with `success`/`error-codes` on many of them (e.g.
            // `bad-request`); the body is authoritative when parseable.
            Err(ureq::Error::Status(_, resp)) => classify_siteverify_response(resp),
            Err(e) => {
                // Class only: the error's Display can embed the request URL,
                // and we do not want URL fragments near captcha machinery.
                // The token and the secret live in the body and are never
                // logged here.
                tracing::warn!("[turnstile] siteverify unreachable (class={:?})", e.kind());
                CaptchaVerdict::Unavailable {
                    reason: format!("siteverify transport error (class={:?})", e.kind()),
                }
            }
        }
    }
}

/// Parse a `siteverify` response body (any HTTP status — the body decides).
fn classify_siteverify_response(resp: ureq::Response) -> CaptchaVerdict {
    let mut body = String::new();
    if let Err(e) = resp
        .into_reader()
        .take(MAX_SITEVERIFY_BODY_BYTES)
        .read_to_string(&mut body)
    {
        return CaptchaVerdict::Unavailable {
            reason: format!("siteverify body read failed ({e})"),
        };
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
        // A non-JSON body means we cannot know the verdict: fail closed.
        return CaptchaVerdict::Unavailable {
            reason: "siteverify returned a non-JSON body".to_string(),
        };
    };
    let success = v.get("success").and_then(|s| s.as_bool()).unwrap_or(false);
    let error_codes: Vec<String> = v
        .get("error-codes")
        .and_then(|c| c.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if success {
        CaptchaVerdict::Success
    } else {
        // The codes are Cloudflare's vocabulary (`invalid-input-response`,
        // `timeout-or-duplicate`, ...): safe to log and to show the user.
        // Neither the token nor the secret appears here.
        tracing::warn!("[turnstile] siteverify rejected token (error-codes: {error_codes:?})");
        CaptchaVerdict::Rejected { error_codes }
    }
}

/// Startup diagnostics, called once when the gateway is built. A forgotten
/// captcha config on a public node must be visible in the logs, and a partial
/// config must be shouted about.
pub fn log_captcha_startup(config: &CaptchaConfig) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| match config {
        CaptchaConfig::Disabled => tracing::warn!(
            "public faucet has no captcha configured (set STELL_TURNSTILE_SITE_KEY and STELL_TURNSTILE_SECRET_KEY); non-loopback public claims will fail with 503 until both are set"
        ),
        CaptchaConfig::Misconfigured => tracing::warn!(
            "public faucet captcha is misconfigured: exactly one of STELL_TURNSTILE_SITE_KEY / STELL_TURNSTILE_SECRET_KEY is set; public faucet requests will fail with 503 until both are set"
        ),
        CaptchaConfig::Enabled { .. } => {
            tracing::info!("public faucet captcha enabled (Cloudflare Turnstile)")
        }
    });
}

/// The captcha gate carried by the gateway state: the deployment's config
/// plus the verifier used to check tokens. Cheap to construct; holds no
/// per-request state.
pub struct CaptchaGate {
    config: CaptchaConfig,
    verifier: Arc<dyn CaptchaVerifier>,
}

impl CaptchaGate {
    /// Explicit config + verifier (tests inject a mock verifier here).
    pub fn new(config: CaptchaConfig, verifier: Arc<dyn CaptchaVerifier>) -> Self {
        Self { config, verifier }
    }

    /// Config from the environment, production verifier, and a one-shot
    /// startup log line describing the mode.
    pub fn from_env() -> Self {
        let config = CaptchaConfig::from_env();
        log_captcha_startup(&config);
        Self {
            config,
            verifier: Arc::new(TurnstileVerifier),
        }
    }

    /// A gate that never requires a captcha (existing deployments, tests).
    pub fn disabled() -> Self {
        Self::new(CaptchaConfig::Disabled, Arc::new(TurnstileVerifier))
    }

    /// The deployment's configuration.
    pub fn config(&self) -> &CaptchaConfig {
        &self.config
    }

    /// The public site key to embed in the explorer HTML, if any.
    pub fn site_key(&self) -> Option<&str> {
        self.config.site_key()
    }

    /// Check one turnstile token. Only meaningful when the config is
    /// [`CaptchaConfig::Enabled`]; otherwise returns
    /// [`CaptchaVerdict::Unavailable`] as a defensive fail-closed default so a
    /// handler bug can never dispense past a disabled gate silently.
    ///
    /// The verifier runs on the blocking pool (`ureq` is synchronous) under a
    /// hard deadline, so a stalled Cloudflare connection costs the request at
    /// most ~10 s and then fails closed.
    pub async fn verify(&self, token: &str, remote_ip: Option<std::net::IpAddr>) -> CaptchaVerdict {
        let Some(secret) = self.config.secret_key().map(str::to_string) else {
            return CaptchaVerdict::Unavailable {
                reason: "captcha gate has no secret key configured".to_string(),
            };
        };
        let verifier = Arc::clone(&self.verifier);
        let token = token.to_string();
        let deadline = SITEVERIFY_TIMEOUT + Duration::from_secs(2);
        let call = tokio::task::spawn_blocking(move || verifier.verify(&secret, &token, remote_ip));
        match tokio::time::timeout(deadline, call).await {
            Ok(Ok(verdict)) => verdict,
            Ok(Err(join)) => CaptchaVerdict::Unavailable {
                reason: format!("captcha verifier task failed ({join})"),
            },
            Err(_) => CaptchaVerdict::Unavailable {
                reason: "captcha verifier timed out".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env is process-global: these tests serialize on a lock so parallel
    // test threads cannot observe each other's half-applied state.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_keys() {
        std::env::remove_var(TURNSTILE_SITE_KEY_ENV);
        std::env::remove_var(TURNSTILE_SECRET_KEY_ENV);
    }

    #[test]
    fn from_env_absent_keys_disables_captcha() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_keys();
        assert_eq!(CaptchaConfig::from_env(), CaptchaConfig::Disabled);
    }

    #[test]
    fn from_env_both_keys_enables_captcha() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_keys();
        std::env::set_var(TURNSTILE_SITE_KEY_ENV, "site-abc");
        std::env::set_var(TURNSTILE_SECRET_KEY_ENV, "secret-xyz");
        let cfg = CaptchaConfig::from_env();
        assert_eq!(
            cfg,
            CaptchaConfig::Enabled {
                site_key: "site-abc".to_string(),
                secret_key: "secret-xyz".to_string(),
            }
        );
        assert_eq!(cfg.site_key(), Some("site-abc"));
        clear_keys();
    }

    #[test]
    fn from_env_secret_only_is_misconfigured() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_keys();
        std::env::set_var(TURNSTILE_SECRET_KEY_ENV, "secret-xyz");
        assert_eq!(CaptchaConfig::from_env(), CaptchaConfig::Misconfigured);
        clear_keys();
    }

    #[test]
    fn from_env_site_key_only_is_misconfigured() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_keys();
        std::env::set_var(TURNSTILE_SITE_KEY_ENV, "site-abc");
        assert_eq!(CaptchaConfig::from_env(), CaptchaConfig::Misconfigured);
        clear_keys();
    }

    #[test]
    fn from_env_blank_values_count_as_absent() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_keys();
        std::env::set_var(TURNSTILE_SITE_KEY_ENV, "   ");
        std::env::set_var(TURNSTILE_SECRET_KEY_ENV, "");
        assert_eq!(CaptchaConfig::from_env(), CaptchaConfig::Disabled);
        clear_keys();
    }

    #[test]
    fn debug_redacts_the_secret() {
        let cfg = CaptchaConfig::Enabled {
            site_key: "site-abc".to_string(),
            secret_key: "super-secret".to_string(),
        };
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("super-secret"),
            "secret must not leak via Debug: {rendered}"
        );
        assert!(
            rendered.contains("site-abc"),
            "site key is public and may appear: {rendered}"
        );
    }

    #[test]
    fn gate_without_secret_fails_closed() {
        let gate = CaptchaGate::new(CaptchaConfig::Disabled, Arc::new(TurnstileVerifier));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let verdict = rt.block_on(gate.verify("tok", None));
        assert!(
            matches!(verdict, CaptchaVerdict::Unavailable { .. }),
            "verify on a gate without a secret must fail closed: {verdict:?}"
        );
    }
}
