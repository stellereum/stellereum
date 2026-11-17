//! Live-cluster safety gate.
//!
//! The harness is dry-run by default. Sending a transaction requires
//! `--allow-live`, and the known production/validator hosts additionally
//! require `--operator-order`, so a copy-pasted URL can never turn a local
//! smoke test into traffic against the live cluster.
//!
//! This module is pure (no network, no DNS): a hostname is compared literally.
//! That is intentional. Resolving a name here would make the gate's verdict
//! depend on DNS, and `rpc.stellereum.org` is blocked by name for exactly that
//! reason.

use std::net::IpAddr;

/// Hosts that run (or proxy) the live cluster. Sending a transaction to any of
/// them requires an explicit operator order in addition to `--allow-live`.
pub const LIVE_HOSTS: &[&str] = &[
    "212.113.103.105",
    "213.21.246.5",
    "138.124.102.200",
    "178.155.74.242",
    "77.110.96.68",
    "rpc.stellereum.org",
];

/// What the gate found in the configured URLs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndpointAudit {
    pub live_hosts: Vec<String>,
    pub remote_hosts: Vec<String>,
    pub loopback_hosts: Vec<String>,
}

impl EndpointAudit {
    pub fn touches_live_cluster(&self) -> bool {
        !self.live_hosts.is_empty()
    }

    pub fn has_remote(&self) -> bool {
        !self.remote_hosts.is_empty()
    }
}

/// Extract the host from an `http://` / `https://` URL (or a bare
/// `host:port`), lowercased, without userinfo, brackets or port.
///
/// This is deliberately permissive about the scheme: ureq rejects what it
/// cannot speak, while the gate must see the same host the request would hit.
pub fn url_host(url: &str) -> Option<String> {
    let rest = match url.split_once("://") {
        Some((_scheme, rest)) => rest,
        None => url,
    };
    let authority = rest.split(['/', '?', '#']).next()?.trim();
    if authority.is_empty() {
        return None;
    }
    let host_port = authority.rsplit('@').next()?.trim();
    let host = if let Some(inner) = host_port.strip_prefix('[') {
        // IPv6 literal: `[::1]:8545`.
        inner.split(']').next()?
    } else {
        match host_port.rsplit_once(':') {
            // `host:port` only when the tail is numeric; a bare hostname with
            // a colon (or a malformed URL) keeps its whole authority.
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => host_port,
        }
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

pub fn host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

pub fn host_is_live(host: &str) -> bool {
    LIVE_HOSTS.iter().any(|h| host.eq_ignore_ascii_case(h))
}

/// Classify URLs without enforcing anything (used by `--dry-run` output too).
pub fn audit(urls: &[String]) -> EndpointAudit {
    let mut out = EndpointAudit::default();
    for url in urls {
        let Some(host) = url_host(url) else {
            continue;
        };
        if host_is_live(&host) {
            out.live_hosts.push(host);
        } else if host_is_loopback(&host) {
            out.loopback_hosts.push(host);
        } else {
            out.remote_hosts.push(host);
        }
    }
    out.live_hosts.sort();
    out.live_hosts.dedup();
    out.remote_hosts.sort();
    out.remote_hosts.dedup();
    out.loopback_hosts.sort();
    out.loopback_hosts.dedup();
    out
}

/// Gate a LIVE run. Returns the audit plus human-readable warnings when the
/// run is permitted; an error string when it is not.
pub fn gate_live(
    urls: &[String],
    allow_remote: bool,
    operator_order: bool,
) -> Result<(EndpointAudit, Vec<String>), String> {
    if urls.is_empty() {
        return Err("no RPC endpoint configured".to_string());
    }
    let audit = audit(urls);
    if audit.touches_live_cluster() && !operator_order {
        return Err(format!(
            "refusing to send transactions to the LIVE cluster host(s) {:?}: \
             the operator must pass --operator-order together with --allow-live. \
             Use a local test node (http://127.0.0.1:8545) for the default runbook.",
            audit.live_hosts
        ));
    }
    if audit.has_remote() && !allow_remote {
        return Err(format!(
            "refusing a non-loopback endpoint {:?} without --allow-remote \
             (remote test nodes need an explicit second acknowledgement)",
            audit.remote_hosts
        ));
    }

    let mut warnings = Vec::new();
    if audit.touches_live_cluster() {
        warnings.push(format!(
            "LIVE CLUSTER SELECTED: {:?}. This sends real transactions. \
             Confirm the operator order, the funding addresses and the stop conditions \
             in docs/LOADTEST_RUNBOOK.md before continuing.",
            audit.live_hosts
        ));
    }
    if audit.has_remote() {
        warnings.push(format!(
            "non-loopback endpoint(s) {:?}: verify this is a TEST node, not production",
            audit.remote_hosts
        ));
    }
    if audit.loopback_hosts.is_empty() && audit.remote_hosts.is_empty() {
        warnings.push("no recognized host in the endpoint URL(s); proceeding only because no live host matched".to_string());
    }
    Ok((audit, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_string()
    }

    #[test]
    fn parses_hosts_with_ports_paths_and_userinfo() {
        assert_eq!(
            url_host("http://127.0.0.1:8545"),
            Some("127.0.0.1".to_string())
        );
        assert_eq!(
            url_host("https://user:pass@rpc.example.org:443/path?q=1"),
            Some("rpc.example.org".to_string())
        );
        assert_eq!(url_host("http://[::1]:8545/"), Some("::1".to_string()));
        assert_eq!(url_host("localhost:8545"), Some("localhost".to_string()));
        assert_eq!(url_host("not a url"), Some("not a url".to_string()));
    }

    #[test]
    fn loopback_detection_is_strict() {
        assert!(host_is_loopback("127.0.0.1"));
        assert!(host_is_loopback("127.42.0.1"));
        assert!(host_is_loopback("::1"));
        assert!(host_is_loopback("LOCALHOST"));
        assert!(!host_is_loopback("0.0.0.0"));
        assert!(!host_is_loopback("10.0.0.1"));
        assert!(!host_is_loopback("rpc.stellereum.org"));
    }

    #[test]
    fn live_hosts_are_blocked_without_order() {
        let urls = vec![s("http://212.113.103.105:8545")];
        let e = gate_live(&urls, true, false).unwrap_err();
        assert!(e.contains("--operator-order"), "{e}");
    }

    #[test]
    fn live_hosts_need_both_flags() {
        let urls = vec![s("https://rpc.stellereum.org")];
        assert!(gate_live(&urls, true, false).is_err());
        let (audit, warn) = gate_live(&urls, true, true).unwrap();
        assert_eq!(audit.live_hosts, vec!["rpc.stellereum.org".to_string()]);
        assert!(warn.iter().any(|w| w.contains("LIVE CLUSTER")));
    }

    #[test]
    fn remote_hosts_need_allow_remote() {
        let urls = vec![s("http://203.0.113.10:8545")];
        assert!(gate_live(&urls, false, false).is_err());
        assert!(gate_live(&urls, true, false).is_ok());
    }

    #[test]
    fn loopback_is_allowed() {
        let urls = vec![s("http://127.0.0.1:8545")];
        let (audit, _) = gate_live(&urls, false, false).unwrap();
        assert!(!audit.touches_live_cluster());
        assert!(!audit.has_remote());
    }

    #[test]
    fn port_is_not_mistaken_for_a_host_suffix() {
        assert!(!host_is_live("212.113.103.105.example.org"));
        assert!(host_is_live("212.113.103.105"));
    }
}
