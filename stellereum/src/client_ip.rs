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
//!
//! ## Loopback claims are never trusted by default
//!
//! Being a trusted proxy is not enough to forward a **loopback** address: a
//! same-host nginx forwards `CF-Connecting-IP: 127.0.0.1` verbatim when a
//! client sends it, and the public faucet's captcha-disabled path treats
//! loopback as local (no captcha). Such a claim must not open that branch.
//!
//! Enforced rule:
//! * the TCP peer must be in `STELL_TRUSTED_PROXY_CIDRS` (as before), AND
//! * a forwarded address that is loopback is accepted only when the
//!   deployment opts in with `STELL_TRUST_LOOPBACK_FORWARDED=1` (default
//!   **off**). Without the opt-in the header claim is discarded and the
//!   resolution is marked [`ClientIpSource::ForwardedLoopbackRejected`].
//!
//! Provenance is part of the result: [`ClientIp::is_local_client`] is true
//! only for a DIRECT loopback TCP peer, never for a header claim. The
//! legitimate same-host topology keeps working because the forwarded address
//! there is the real (public) client, not loopback.

use axum::http::HeaderMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Env var with the comma-separated list of trusted proxy CIDRs / IPs.
pub const TRUSTED_PROXY_CIDRS_ENV: &str = "STELL_TRUSTED_PROXY_CIDRS";
/// Env var selecting the `X-Forwarded-For` chain discipline.
pub const XFF_MODE_ENV: &str = "STELL_XFF_MODE";
/// Opt-in for accepting a forwarded LOOPBACK client address (default off).
///
/// Only meaningful together with a trusted (configured) proxy peer: a
/// loopback claim from a non-proxy peer is ignored regardless. Turn this on
/// only for a proxy that OVERWRITES the client-IP headers and fronts local
/// callers whose loopback identity genuinely matters; with the default off,
/// a loopback claim is never captcha-exempt.
pub const TRUST_LOOPBACK_FORWARDED_ENV: &str = "STELL_TRUST_LOOPBACK_FORWARDED";

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

/// Canonicalize an address for identity decisions.
///
/// A dual-stack listener reports an IPv4 peer as an IPv4-mapped IPv6 address
/// (`::ffff:a.b.c.d`). Left as-is, `Ipv6Addr::is_loopback` is false for
/// `::ffff:127.0.0.1` (only `::1` matches), and the same client gets two
/// rate-limit buckets / faucet budgets for `a.b.c.d` and `::ffff:a.b.c.d`.
/// Every trust, locality and bucket key therefore runs on the canonical form:
/// `::ffff:a.b.c.d` becomes `a.b.c.d`.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        IpAddr::V4(_) => ip,
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
        // Canonicalize first: a mapped v6 peer is matched as the v4 it is, so
        // `::ffff:127.0.0.1` cannot dodge a `127.0.0.0/8` trust rule.
        match (*self, canonical_ip(*ip)) {
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
                // A CIDR in mapped-v6 space (`::ffff:127.0.0.0/104`) is the
                // v4 network it maps to; incoming peers are canonicalized to
                // v4, so a v6-form rule would otherwise never match.
                if let Some(v4) = v6.to_ipv4_mapped() {
                    if prefix < 96 {
                        return None;
                    }
                    let p = prefix - 96;
                    let mask = v4_mask(p);
                    return Some(TrustedNet::V4 {
                        net: u32::from(v4) & mask,
                        prefix: p,
                    });
                }
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
            Ok(ip) => match canonical_ip(ip) {
                IpAddr::V4(v4) => Some(TrustedNet::V4 {
                    net: u32::from(v4),
                    prefix: 32,
                }),
                IpAddr::V6(v6) => Some(TrustedNet::V6 {
                    net: u128::from(v6),
                    prefix: 128,
                }),
            },
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
/// The result is canonicalized ([`canonical_ip`]), so a header claiming
/// `::ffff:a.b.c.d` yields the same [`IpAddr`] as `a.b.c.d`.
pub fn parse_ip_token(tok: &str) -> Option<IpAddr> {
    parse_ip_token_raw(tok).map(canonical_ip)
}

fn parse_ip_token_raw(tok: &str) -> Option<IpAddr> {
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

/// Where the resolved client address came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientIpSource {
    /// The TCP peer itself; no forwarding header was accepted.
    Peer,
    /// A forwarding header, accepted because the peer is a configured proxy
    /// (and, for a loopback address, the deployment opted in).
    Forwarded,
    /// A forwarding header claimed a loopback address from a configured proxy
    /// but the deployment has NOT opted in. The address falls back to the TCP
    /// peer, and the claim must never be treated as a local client (see
    /// [`ClientIp::is_local_client`]).
    ForwardedLoopbackRejected,
}

/// A resolved client address plus where it came from.
///
/// Rate limits and faucet budgets key on [`ClientIp::addr`]; security
/// decisions that depend on locality must use [`ClientIp::is_local_client`],
/// which is false for every header-derived address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientIp {
    /// The resolved client address (never header-derived loopback unless the
    /// deployment opted in).
    pub addr: IpAddr,
    /// Provenance of [`ClientIp::addr`].
    pub source: ClientIpSource,
}

impl ClientIp {
    /// The address came from the TCP connection itself (canonicalized, so a
    /// mapped v6 peer is stored as its v4 form).
    pub fn from_peer(addr: IpAddr) -> Self {
        Self {
            addr: canonical_ip(addr),
            source: ClientIpSource::Peer,
        }
    }

    /// True when a forwarding header supplied the address.
    pub fn is_forwarded(&self) -> bool {
        matches!(self.source, ClientIpSource::Forwarded)
    }

    /// True only for a DIRECT loopback TCP peer: a header-derived loopback
    /// claim is never local (fail-closed for the captcha-exempt faucet path).
    /// The address is canonicalized, so an IPv4-mapped `::ffff:127.0.0.1`
    /// peer counts as loopback.
    pub fn is_local_client(&self) -> bool {
        self.source == ClientIpSource::Peer && canonical_ip(self.addr).is_loopback()
    }
}

impl PartialEq<IpAddr> for ClientIp {
    fn eq(&self, other: &IpAddr) -> bool {
        self.addr == *other
    }
}

/// Parse an explicit boolean env flag (`1/true/yes/on`, case-insensitive).
fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Whether the deployment opted in to forwarding a LOOPBACK client address
/// (`STELL_TRUST_LOOPBACK_FORWARDED`, default off).
pub fn trust_loopback_forwarded_from_env() -> bool {
    env_flag(TRUST_LOOPBACK_FORWARDED_ENV)
}

/// Resolve with explicit config and an explicit loopback-forwarding policy
/// (deterministic; tests use this).
///
/// A forwarded address is returned only when `peer` is trusted. A forwarded
/// address that is loopback is accepted only with `trust_loopback_forwarded`
/// AND a trusted peer; otherwise the claim is recorded as
/// [`ClientIpSource::ForwardedLoopbackRejected`] and `addr` falls back to the
/// peer.
pub fn resolve_detailed(
    headers: &HeaderMap,
    peer: IpAddr,
    trusted: &[TrustedNet],
    mode: XffMode,
    trust_loopback_forwarded: bool,
) -> ClientIp {
    // Canonicalize the peer BEFORE any trust check: a dual-stack listener
    // reports `::ffff:127.0.0.1`, which must be judged (and bucketed) as
    // `127.0.0.1`.
    let peer = canonical_ip(peer);
    if !is_trusted_in(&peer, trusted) {
        return ClientIp::from_peer(peer);
    }
    let claimed = select_from_chain(&xff_chain_from_headers(headers), mode, trusted)
        .or_else(|| select_from_chain(&forwarded_chain_from_headers(headers), mode, trusted))
        .or_else(|| {
            ["cf-connecting-ip", "true-client-ip", "x-real-ip"]
                .iter()
                .find_map(|name| single_ip_header(headers, name))
        })
        .map(canonical_ip);
    match claimed {
        None => ClientIp::from_peer(peer),
        Some(ip)
            if ip.is_loopback() && !(trust_loopback_forwarded && is_trusted_in(&peer, trusted)) =>
        {
            ClientIp {
                addr: peer,
                source: ClientIpSource::ForwardedLoopbackRejected,
            }
        }
        Some(ip) => ClientIp {
            addr: ip,
            source: ClientIpSource::Forwarded,
        },
    }
}

/// Resolve with explicit config using the SECURE default policy: a forwarded
/// loopback address is rejected unless `STELL_TRUST_LOOPBACK_FORWARDED` is set.
pub fn resolve_with(
    headers: &HeaderMap,
    peer: IpAddr,
    trusted: &[TrustedNet],
    mode: XffMode,
) -> ClientIp {
    resolve_detailed(
        headers,
        peer,
        trusted,
        mode,
        trust_loopback_forwarded_from_env(),
    )
}

/// Resolve the real client IP: proxy headers only when the TCP `peer` is a
/// trusted proxy per `STELL_TRUSTED_PROXY_CIDRS`; otherwise the peer itself.
/// `X-Forwarded-For` chain discipline comes from `STELL_XFF_MODE`; loopback
/// forwarded addresses also require `STELL_TRUST_LOOPBACK_FORWARDED`.
pub fn resolve_client_ip(headers: &HeaderMap, peer: IpAddr) -> ClientIp {
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
pub fn resolve_client_ip_opt(headers: &HeaderMap, peer: Option<IpAddr>) -> Option<ClientIp> {
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

    /// F11: a loopback claim forwarded by a same-host (loopback) proxy is
    /// NOT accepted without the explicit opt-in, and is never local.
    #[test]
    fn loopback_forwarded_claim_rejected_without_opt_in() {
        let trusted = nets("127.0.0.0/8, ::1/128, 10.0.0.0/8");
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        for name in ["cf-connecting-ip", "x-real-ip", "true-client-ip"] {
            let headers = h(&[(name, "127.0.0.1")]);
            let r = resolve_detailed(&headers, peer, &trusted, XffMode::Rightmost, false);
            assert_eq!(r.addr, peer, "{name}: falls back to the TCP peer");
            assert_eq!(
                r.source,
                ClientIpSource::ForwardedLoopbackRejected,
                "{name}: claim must be recorded as rejected"
            );
            assert!(
                !r.is_local_client(),
                "{name}: a header claim must never be a local client"
            );
        }
        // The same rule on the chain headers.
        for (name, value) in [
            ("x-forwarded-for", "127.0.0.1"),
            ("forwarded", "for=127.0.0.1"),
        ] {
            let headers = h(&[(name, value)]);
            let r = resolve_detailed(&headers, peer, &trusted, XffMode::Rightmost, false);
            assert_eq!(r.source, ClientIpSource::ForwardedLoopbackRejected);
            assert!(!r.is_local_client(), "{name}: chain claim is not local");
        }

        // A trusted NON-loopback proxy claiming loopback gets the same refusal.
        let lan_proxy: IpAddr = "10.0.0.7".parse().unwrap();
        let headers = h(&[("cf-connecting-ip", "127.0.0.1")]);
        let r = resolve_detailed(&headers, lan_proxy, &trusted, XffMode::Rightmost, false);
        assert_eq!(r.addr, lan_proxy);
        assert_eq!(r.source, ClientIpSource::ForwardedLoopbackRejected);
        assert!(!r.is_local_client());

        // Opt-in: accepted from a configured proxy...
        let r = resolve_detailed(&headers, lan_proxy, &trusted, XffMode::Rightmost, true);
        assert_eq!(r.addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(r.source, ClientIpSource::Forwarded);
        // ...but never from an unconfigured peer, opt-in or not.
        let untrusted: IpAddr = "8.8.8.8".parse().unwrap();
        let r = resolve_detailed(&headers, untrusted, &trusted, XffMode::Rightmost, true);
        assert_eq!(r.addr, untrusted);
        assert_eq!(r.source, ClientIpSource::Peer);
    }

    /// The legitimate same-host deployment (loopback proxy, real public
    /// client) keeps working: the forwarded address is the client.
    #[test]
    fn legit_same_host_proxy_forwards_public_client() {
        let trusted = nets("127.0.0.0/8, ::1/128");
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let headers = h(&[("x-real-ip", "203.0.113.9")]);
        let r = resolve_detailed(&headers, peer, &trusted, XffMode::Rightmost, false);
        assert_eq!(r.addr, "203.0.113.9".parse::<IpAddr>().unwrap());
        assert_eq!(r.source, ClientIpSource::Forwarded);
        assert!(r.is_forwarded());
        assert!(!r.is_local_client());
    }

    /// Only a DIRECT loopback peer is a local client (captcha-exempt path).
    #[test]
    fn direct_loopback_peer_is_local_client() {
        let trusted = nets("127.0.0.0/8");
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let r = resolve_detailed(&HeaderMap::new(), peer, &trusted, XffMode::Rightmost, false);
        assert_eq!(r.source, ClientIpSource::Peer);
        assert!(r.is_local_client());

        let public: IpAddr = "8.8.8.8".parse().unwrap();
        let r = resolve_detailed(
            &HeaderMap::new(),
            public,
            &trusted,
            XffMode::Rightmost,
            false,
        );
        assert!(!r.is_local_client());
    }

    /// FAIL-BEFORE (T5a): `::ffff:127.0.0.1` must be the SAME client as
    /// `127.0.0.1`: a loopback claim is rejected without the opt-in, the
    /// opt-in path returns the canonical v4, and both spellings share one
    /// limiter bucket (no quota doubling / ban evasion).
    #[test]
    fn ipv4_mapped_loopback_rejected_and_buckets_unified() {
        let trusted = nets("127.0.0.0/8, ::1/128");
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let headers = h(&[("x-forwarded-for", "::ffff:127.0.0.1")]);

        // Default policy (STELL_TRUST_LOOPBACK_FORWARDED off).
        let r = resolve_detailed(&headers, peer, &trusted, XffMode::Rightmost, false);
        assert_eq!(
            r.source,
            ClientIpSource::ForwardedLoopbackRejected,
            "mapped-v6 loopback claim must be rejected like plain v4"
        );
        assert_eq!(r.addr, peer);
        assert!(!r.is_local_client());

        // Opt-in: accepted, but canonicalized to the v4 form.
        let r = resolve_detailed(&headers, peer, &trusted, XffMode::Rightmost, true);
        assert_eq!(r.source, ClientIpSource::Forwarded);
        assert_eq!(r.addr, "127.0.0.1".parse::<IpAddr>().unwrap());

        // A mapped-v6 PEER is loopback too (dual-stack listener).
        let mapped_peer: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let r = resolve_detailed(
            &HeaderMap::new(),
            mapped_peer,
            &trusted,
            XffMode::Rightmost,
            false,
        );
        assert_eq!(r.addr, peer);
        assert_eq!(r.source, ClientIpSource::Peer);
        assert!(r.is_local_client());

        // Both spellings resolve to the same canonical IpAddr...
        assert_eq!(parse_ip_token("::ffff:1.2.3.4"), parse_ip_token("1.2.3.4"));
        assert_eq!(
            parse_ip_token("::ffff:1.2.3.4"),
            Some("1.2.3.4".parse().unwrap())
        );
        // ...and therefore share one rate-limit bucket.
        let limiter = crate::explorer::RateLimiter::new(1);
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        let mapped: IpAddr = "::ffff:1.2.3.4".parse().unwrap();
        assert!(limiter.check_at(canonical_ip(v4), 100));
        assert!(
            !limiter.check_at(canonical_ip(mapped), 100),
            "mapped-v6 must not open a second bucket for the same client"
        );
    }

    /// A trusted-proxy rule written in mapped-v6 space still matches the v4
    /// peer it denotes.
    #[test]
    fn mapped_v6_cidr_matches_v4_peer() {
        let trusted = nets("::ffff:10.0.0.0/104");
        assert!(is_trusted_in(&"10.1.2.3".parse().unwrap(), &trusted));
        assert!(!is_trusted_in(&"11.2.3.4".parse().unwrap(), &trusted));
    }
}
