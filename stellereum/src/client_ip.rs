//! Real client IP behind a reverse proxy.
//!
//! Problem: when the node binds `127.0.0.1` behind nginx/Cloudflare, the TCP
//! peer (`ConnectInfo`) is always the proxy, so every client shared one
//! rate-limit bucket / faucet IP-bucket and Turnstile saw a useless
//! `remoteip`. This module resolves the real client IP from proxy headers,
//! but ONLY when the TCP peer is a configured trusted proxy.
//!
//! Configuration:
//!
//! | variable | default | meaning |
//! |---|---|---|
//! | `STELL_TRUSTED_PROXY_CIDRS` | `127.0.0.0/8, ::1/128` (loopback only) | comma-separated CIDRs or plain IPs allowed to supply client-IP headers |
//! | `STELL_XFF_MODE` | `rightmost` | `rightmost` (secure default) or `leftmost` (see spoofing notes) |
//!
//! Header precedence (first hit wins, only when the peer is trusted):
//! `X-Forwarded-For` → `Forwarded: for=` (RFC 7239) → `CF-Connecting-IP` →
//! `True-Client-IP` → `X-Real-IP`. Fallback is always the TCP peer.
//!
//! ## Spoofing model — read this before changing `STELL_XFF_MODE`
//!
//! `X-Forwarded-For` is attacker-controlled input. A client may send
//! `X-Forwarded-For: <fake>` and every proxy appends the address it saw, so
//! the header becomes `<fake>, <real-client>, <proxy1>`. The only entry the
//! attacker cannot forge is the one appended by the FIRST trusted proxy.
//!
//! - `rightmost` (default, SAFE): walk the chain right-to-left, skip entries
//!   that are themselves trusted proxies, return the first untrusted entry.
//!   If every entry is a trusted proxy, return the leftmost (the original
//!   client as seen by the outermost proxy). An attacker can only prepend
//!   fakes to the left, which this mode ignores. This is safe as long as
//!   `STELL_TRUSTED_PROXY_CIDRS` covers EVERY proxy that appends to the
//!   header (and the firewall guarantees the peer really is one of them).
//! - `leftmost` (UNSAFE unless the proxy overwrites): return the first entry.
//!   Use ONLY when the front proxy is configured to OVERWRITE the header
//!   (`proxy_set_header X-Forwarded-For $remote_addr`, Cloudflare-style
//!   single-hop) rather than append. With appending proxies an attacker picks
//!   an arbitrary IP by sending `X-Forwarded-For: <victim>` — rate limits,
//!   faucet budgets and Turnstile `remoteip` are then attacker-chosen.
//!
//! Additional notes:
//! - When the TCP peer is NOT trusted, ALL headers are ignored and the peer
//!   is returned. This is the fail-closed default: an Internet client cannot
//!   spoof its way into another bucket.
//! - Default trust is loopback only. That fixes the `127.0.0.1`-behind-nginx
//!   deployment, but any LOCAL user/process can then spoof `X-Forwarded-For`
//!   — restrict local access on multi-user hosts.
//! - `Forwarded`, `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP` are single
//!   values set by the proxy; they are honored only from a trusted peer, for
//!   the same reason. Prefer `X-Forwarded-For`/`Forwarded` chains when the
//!   proxy appends; single-IP headers only when the proxy overwrites them.

use axum::http::HeaderMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Env var with the comma-separated list of trusted proxy CIDRs / IPs.
pub const TRUSTED_PROXY_CIDRS_ENV: &str = "STELL_TRUSTED_PROXY_CIDRS";
/// Env var selecting the `X-Forwarded-For` chain discipline.
pub const XFF_MODE_ENV: &str = "STELL_XFF_MODE";

/// How to pick the client out of an `X-Forwarded-For` / `Forwarded` chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XffMode {
    /// Rightmost untrusted entry (secure default; see module docs).
    Rightmost,
    /// Leftmost entry (only for overwriting single-hop proxies).
    Leftmost,
}

impl XffMode {
    /// Parse from a raw env/config string (case-insensitive, trimmed).
    /// Unknown / empty values fall back to [`XffMode::Rightmost`] (fail-safe).
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "leftmost" | "left" | "first" => XffMode::Leftmost,
            // "rightmost" | "right" | "last" | "" | anything-else
            _ => XffMode::Rightmost,
        }
    }

    /// Effective mode from `STELL_XFF_MODE` (default [`XffMode::Rightmost`]).
    pub fn from_env() -> Self {
        std::env::var(XFF_MODE_ENV)
            .map(|v| Self::parse(&v))
            .unwrap_or(XffMode::Rightmost)
    }
}

/// One trusted network: an address family plus a masked network + prefix len.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedNet {
    V4 { net: u32, prefix: u8 },
    V6 { net: u128, prefix: u8 },
}

impl TrustedNet {
    fn contains(&self, ip: &IpAddr) -> bool {
        match (*self, *ip) {
            (TrustedNet::V4 { net, prefix }, IpAddr::V4(v4)) => {
                let mask = v4_mask(prefix);
                (u32::from(v4) & mask) == net
            }
            (TrustedNet::V6 { net, prefix }, IpAddr::V6(v6)) => {
                let mask = v6_mask(prefix);
                (u128::from(v6) & mask) == net
            }
            // IPv4-mapped IPv6 peer (e.g. ::ffff:127.0.0.1) vs a v4 net.
            (TrustedNet::V4 { net, prefix }, IpAddr::V6(v6)) => {
                if let Some(mapped) = v6.to_ipv4_mapped() {
                    let mask = v4_mask(prefix);
                    (u32::from(mapped) & mask) == net
                } else {
                    false
                }
            }
            // Plain v4 peer vs a v6 net: map it into ::ffff:0:0/96 space.
            (TrustedNet::V6 { net, prefix }, IpAddr::V4(v4)) => {
                let mapped = v4.to_ipv6_mapped();
                let mask = v6_mask(prefix);
                (u128::from(mapped) & mask) == net
            }
        }
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        (!0u32) << (32 - prefix)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        (!0u128) << (128 - prefix)
    }
}

/// Parse one `CIDR` or plain IP token (`"10.0.0.0/8"`, `"::1"`, `"1.2.3.4"`).
/// Invalid tokens return `None` (callers skip them).
pub fn parse_trusted_token(tok: &str) -> Option<TrustedNet> {
    let tok = tok.trim();
    if tok.is_empty() {
        return None;
    }
    if let Some((addr_s, prefix_s)) = tok.split_once('/') {
        let prefix: u8 = prefix_s.trim().parse().ok()?;
        let addr: IpAddr = addr_s.trim().parse().ok()?;
        match addr {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    return None;
                }
                let mask = v4_mask(prefix);
                Some(TrustedNet::V4 {
                    net: u32::from(v4) & mask,
                    prefix,
                })
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    return None;
                }
                let mask = v6_mask(prefix);
                Some(TrustedNet::V6 {
                    net: u128::from(v6) & mask,
                    prefix,
                })
            }
        }
    } else {
        match tok.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => Some(TrustedNet::V4 {
                net: u32::from(v4),
                prefix: 32,
            }),
            Ok(IpAddr::V6(v6)) => Some(TrustedNet::V6 {
                net: u128::from(v6),
                prefix: 128,
            }),
            Err(_) => None,
        }
    }
}

/// Default trust: loopback only (`127.0.0.0/8`, `::1/128`).
pub fn default_trusted_nets() -> Vec<TrustedNet> {
    vec![
        TrustedNet::V4 {
            net: u32::from(Ipv4Addr::new(127, 0, 0, 0)),
            prefix: 8,
        },
        TrustedNet::V6 {
            net: u128::from(Ipv6Addr::LOCALHOST),
            prefix: 128,
        },
    ]
}

/// Parse `STELL_TRUSTED_PROXY_CIDRS`.
///
/// - var absent → loopback-only default;
/// - var present but blank → trust NOTHING (operator explicitly disabled);
/// - otherwise comma-separated CIDRs / plain IPs; invalid entries are skipped.
pub fn trusted_nets_from_env() -> Vec<TrustedNet> {
    match std::env::var(TRUSTED_PROXY_CIDRS_ENV) {
        Err(_) => default_trusted_nets(),
        Ok(raw) => {
            if raw.trim().is_empty() {
                return Vec::new();
            }
            raw.split(',').filter_map(parse_trusted_token).collect()
        }
    }
}

/// Parse the same list from an explicit string (deterministic tests).
pub fn parse_trusted_list(raw: &str) -> Vec<TrustedNet> {
    raw.split(',').filter_map(parse_trusted_token).collect()
}

/// True when `ip` is inside any of `nets`.
pub fn is_trusted_in(ip: &IpAddr, nets: &[TrustedNet]) -> bool {
    nets.iter().any(|n| n.contains(ip))
}

/// True when `ip` is a trusted proxy per the current env config.
pub fn is_trusted_peer(ip: &IpAddr) -> bool {
    is_trusted_in(ip, &trusted_nets_from_env())
}

/// Parse one IP token from a forwarding header.
///
/// Accepts bare IPs, `[v6]` / `[v6]:port`, `v4:port`; rejects `unknown`,
/// obfuscated identifiers (`_hidden`, `_secluded`), empty and garbage.
pub fn parse_ip_token(tok: &str) -> Option<IpAddr> {
    let mut t = tok.trim();
    if t.is_empty() {
        return None;
    }
    // Strip one layer of quotes (Forwarded may quote the value).
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        t = t[1..t.len() - 1].trim();
    }
    if t.is_empty() {
        return None;
    }
    let lower = t.to_ascii_lowercase();
    if lower == "unknown" || lower == "_hidden" || lower == "_secluded" || lower == "hidden" {
        return None;
    }
    // Direct parse first (covers bare v4 + v6).
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Some(ip);
    }
    // Bracketed v6, optionally with a port: [2001:db8::1] or [2001:db8::1]:4711.
    if let Some(rest) = t.strip_prefix('[') {
        if let Some((inner, _after)) = rest.split_once(']') {
            if let Ok(ip) = inner.trim().parse::<IpAddr>() {
                return Some(ip);
            }
            return None;
        }
        return None;
    }
    // Bare v4 with a port (1.2.3.4:5678). v6 without brackets is ambiguous
    // with a port suffix, so only attempt this when the left side is dotted.
    if t.contains('.') && t.contains(':') {
        if let Some((left, right)) = t.rsplit_once(':') {
            if !right.is_empty() && right.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(ip) = left.trim().parse::<IpAddr>() {
                    // Only accept the port-stripped form for v4 (v6 must be
                    // bracketed to disambiguate).
                    if matches!(ip, IpAddr::V4(_)) {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

/// Parse an `X-Forwarded-For` header value into the chain (left → right).
pub fn parse_xff_chain(value: &str) -> Vec<IpAddr> {
    value.split(',').filter_map(parse_ip_token).collect()
}

/// Collect the full `X-Forwarded-For` chain across repeated headers.
pub fn xff_chain_from_headers(headers: &HeaderMap) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for v in headers.get_all("x-forwarded-for") {
        if let Ok(s) = v.to_str() {
            out.extend(parse_xff_chain(s));
        }
    }
    out
}

/// Parse RFC 7239 `Forwarded` header(s) into the `for=` chain (left → right).
/// Example: `for=192.0.2.60;proto=http, for="[2001:db8::1]:4711"`.
pub fn forwarded_chain_from_headers(headers: &HeaderMap) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for v in headers.get_all("forwarded") {
        let Ok(s) = v.to_str() else { continue };
        // Elements split on ','; parameters on ';'; we want for=<value>.
        for elem in s.split(',') {
            for pair in elem.split(';') {
                let pair = pair.trim();
                let Some((k, val)) = pair.split_once('=') else {
                    continue;
                };
                if !k.trim().eq_ignore_ascii_case("for") {
                    continue;
                }
                if let Some(ip) = parse_ip_token(val.trim()) {
                    out.push(ip);
                }
                break; // one for= per element
            }
        }
    }
    out
}

/// First valid IP in a single-IP header (`X-Real-IP`, `CF-Connecting-IP`,
/// `True-Client-IP`). A comma-separated value takes its first valid entry.
fn single_ip_header(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    let v = headers.get(name)?;
    let s = v.to_str().ok()?;
    s.split(',').filter_map(parse_ip_token).next()
}

/// Pick the client out of a forwarding chain.
///
/// - [`XffMode::Leftmost`]: first entry (only for overwriting proxies).
/// - [`XffMode::Rightmost`]: rightmost entry that is NOT itself a trusted
///   proxy; if all entries are trusted, the leftmost (original client).
pub fn select_from_chain(
    chain: &[IpAddr],
    mode: XffMode,
    trusted: &[TrustedNet],
) -> Option<IpAddr> {
    if chain.is_empty() {
        return None;
    }
    match mode {
        XffMode::Leftmost => Some(chain[0]),
        XffMode::Rightmost => {
            for ip in chain.iter().rev() {
                if !is_trusted_in(ip, trusted) {
                    return Some(*ip);
                }
            }
            Some(chain[0])
        }
    }
}

/// Resolve with explicit config (deterministic; tests use this).
pub fn resolve_with(
    headers: &HeaderMap,
    peer: IpAddr,
    trusted: &[TrustedNet],
    mode: XffMode,
) -> IpAddr {
    if !is_trusted_in(&peer, trusted) {
        return peer;
    }
    let xff = xff_chain_from_headers(headers);
    if let Some(ip) = select_from_chain(&xff, mode, trusted) {
        return ip;
    }
    let fwd = forwarded_chain_from_headers(headers);
    if let Some(ip) = select_from_chain(&fwd, mode, trusted) {
        return ip;
    }
    for name in ["cf-connecting-ip", "true-client-ip", "x-real-ip"] {
        if let Some(ip) = single_ip_header(headers, name) {
            return ip;
        }
    }
    peer
}

/// Resolve the real client IP: proxy headers only when the TCP `peer` is a
/// trusted proxy per `STELL_TRUSTED_PROXY_CIDRS`; otherwise the peer itself.
/// `X-Forwarded-For` chain discipline comes from `STELL_XFF_MODE`.
pub fn resolve_client_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    let trusted = trusted_nets_from_env();
    let mode = XffMode::from_env();
    resolve_with(headers, peer, &trusted, mode)
}

/// Convenience: resolve from an optional `ConnectInfo` peer.
/// `None` (no TCP info, e.g. in-process dispatch) falls back to headers-only
/// resolution against a loopback peer — in practice headers alone are NOT
/// trusted without a peer, so this returns `None` unless headers yield an IP
/// under an explicitly trusted view. Prefer [`resolve_client_ip`] when the
/// peer is known.
pub fn resolve_client_ip_opt(headers: &HeaderMap, peer: Option<IpAddr>) -> Option<IpAddr> {
    peer.map(|p| resolve_client_ip(headers, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse::<axum::http::HeaderValue>().unwrap(),
            );
        }
        m
    }

    fn nets(raw: &str) -> Vec<TrustedNet> {
        parse_trusted_list(raw)
    }

    #[test]
    fn default_trust_is_loopback_only() {
        let d = default_trusted_nets();
        assert!(is_trusted_in(&"127.0.0.1".parse::<IpAddr>().unwrap(), &d));
        assert!(is_trusted_in(&"127.9.9.9".parse::<IpAddr>().unwrap(), &d));
        assert!(is_trusted_in(&"::1".parse::<IpAddr>().unwrap(), &d));
        assert!(!is_trusted_in(&"10.0.0.1".parse::<IpAddr>().unwrap(), &d));
        assert!(!is_trusted_in(&"8.8.8.8".parse::<IpAddr>().unwrap(), &d));
        assert!(!is_trusted_in(&"::2".parse::<IpAddr>().unwrap(), &d));
    }

    #[test]
    fn cidr_parsing_and_matching() {
        let n = nets("10.0.0.0/8, 192.168.1.0/24, 2001:db8::/32");
        assert!(is_trusted_in(&"10.1.2.3".parse::<IpAddr>().unwrap(), &n));
        assert!(!is_trusted_in(&"11.0.0.1".parse::<IpAddr>().unwrap(), &n));
        assert!(is_trusted_in(
            &"192.168.1.99".parse::<IpAddr>().unwrap(),
            &n
        ));
        assert!(!is_trusted_in(
            &"192.168.2.1".parse::<IpAddr>().unwrap(),
            &n
        ));
        assert!(is_trusted_in(&"2001:db8::1".parse::<IpAddr>().unwrap(), &n));
        assert!(!is_trusted_in(
            &"2001:db9::1".parse::<IpAddr>().unwrap(),
            &n
        ));
        // Plain IPs are /32 + /128.
        let n = nets("1.2.3.4, 2001:db8::7");
        assert!(is_trusted_in(&"1.2.3.4".parse::<IpAddr>().unwrap(), &n));
        assert!(!is_trusted_in(&"1.2.3.5".parse::<IpAddr>().unwrap(), &n));
        assert!(is_trusted_in(&"2001:db8::7".parse::<IpAddr>().unwrap(), &n));
        // Garbage entries are skipped, valid ones still apply.
        let n = nets("garbage, 10.0.0.0/99, 10.1.0.0/16, /24");
        assert!(is_trusted_in(&"10.1.2.3".parse::<IpAddr>().unwrap(), &n));
        assert!(!is_trusted_in(&"10.2.0.1".parse::<IpAddr>().unwrap(), &n));
    }

    #[test]
    fn untrusted_peer_ignores_spoofed_headers() {
        let trusted = nets("127.0.0.0/8, ::1/128");
        let peer: IpAddr = "8.8.8.8".parse::<IpAddr>().unwrap();
        let headers = h(&[("x-forwarded-for", "1.2.3.4")]);
        assert_eq!(
            resolve_with(&headers, peer, &trusted, XffMode::Rightmost),
            peer
        );
        assert_eq!(
            resolve_with(&headers, peer, &trusted, XffMode::Leftmost),
            peer
        );
    }

    #[test]
    fn rightmost_resists_spoofed_prefix() {
        // Attacker prepends a fake; first trusted proxy appends the real IP.
        let trusted = nets("127.0.0.0/8");
        let peer: IpAddr = "127.0.0.1".parse::<IpAddr>().unwrap();
        let headers = h(&[("x-forwarded-for", "9.9.9.9, 1.2.3.4")]);
        // Rightmost-untrusted picks 1.2.3.4 (the entry the proxy added),
        // NOT the attacker-forged leftmost 9.9.9.9.
        assert_eq!(
            resolve_with(&headers, peer, &trusted, XffMode::Rightmost),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        // Leftmost is spoofable: documents why it must not be the default.
        assert_eq!(
            resolve_with(&headers, peer, &trusted, XffMode::Leftmost),
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn rightmost_skips_trusted_tail() {
        // Chain: client, proxy1 (trusted), proxy2 (trusted, closest to us).
        let trusted = nets("10.0.0.0/8, 127.0.0.0/8");
        let peer: IpAddr = "127.0.0.1".parse::<IpAddr>().unwrap();
        let headers = h(&[("x-forwarded-for", "1.2.3.4, 10.0.0.9, 10.0.0.10")]);
        assert_eq!(
            resolve_with(&headers, peer, &trusted, XffMode::Rightmost),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn xff_parsing_handles_ipv6_ports_and_garbage() {
        assert_eq!(
            parse_ip_token("2001:db8::1"),
            Some("2001:db8::1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            parse_ip_token("[2001:db8::1]:4711"),
            Some("2001:db8::1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            parse_ip_token("1.2.3.4:5678"),
            Some("1.2.3.4".parse::<IpAddr>().unwrap())
        );
        assert_eq!(parse_ip_token("unknown"), None);
        assert_eq!(parse_ip_token("_hidden"), None);
        assert_eq!(parse_ip_token(""), None);
        assert_eq!(parse_ip_token("not-an-ip"), None);
        assert_eq!(parse_ip_token("999.1.1.1"), None);
        let chain = parse_xff_chain("unknown, 1.2.3.4, garbage, 2001:db8::9");
        assert_eq!(
            chain,
            vec![
                "1.2.3.4".parse::<IpAddr>().unwrap(),
                "2001:db8::9".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn forwarded_for_is_parsed() {
        let trusted = nets("127.0.0.0/8");
        let peer: IpAddr = "127.0.0.1".parse::<IpAddr>().unwrap();
        let headers = h(&[(
            "forwarded",
            "for=192.0.2.60;proto=http, for=\"[2001:db8::1]:4711\"",
        )]);
        let chain = forwarded_chain_from_headers(&headers);
        assert_eq!(
            chain,
            vec![
                "192.0.2.60".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap()
            ]
        );
        // Rightmost picks the entry closest to the proxy.
        assert_eq!(
            resolve_with(&headers, peer, &trusted, XffMode::Rightmost),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn fallback_headers_and_peer() {
        let trusted = nets("127.0.0.0/8");
        let peer: IpAddr = "127.0.0.1".parse::<IpAddr>().unwrap();
        for (name, val) in [
            ("x-real-ip", "5.6.7.8"),
            ("cf-connecting-ip", "6.7.8.9"),
            ("true-client-ip", "7.8.9.0"),
        ] {
            let headers = h(&[(name, val)]);
            assert_eq!(
                resolve_with(&headers, peer, &trusted, XffMode::Rightmost),
                val.parse::<IpAddr>().unwrap(),
                "fallback {name} must be honored from a trusted peer"
            );
        }
        // No headers → peer.
        let headers = h(&[]);
        assert_eq!(
            resolve_with(&headers, peer, &trusted, XffMode::Rightmost),
            peer
        );
        // XFF wins over single-IP fallbacks.
        let headers = h(&[("x-forwarded-for", "1.1.1.1"), ("x-real-ip", "2.2.2.2")]);
        assert_eq!(
            resolve_with(&headers, peer, &trusted, XffMode::Rightmost),
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn xff_mode_parsing_defaults_safe() {
        assert_eq!(XffMode::parse("leftmost"), XffMode::Leftmost);
        assert_eq!(XffMode::parse("LEFT"), XffMode::Leftmost);
        assert_eq!(XffMode::parse("rightmost"), XffMode::Rightmost);
        assert_eq!(XffMode::parse(""), XffMode::Rightmost);
        assert_eq!(XffMode::parse("garbage"), XffMode::Rightmost);
    }
}
