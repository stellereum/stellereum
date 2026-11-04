//! DNS seed discovery: bootstrap peers from public DNS TXT records.
//!
//! A fresh validator used to need a hand-edited `node.yaml` with every peer's
//! `node-id`/`ed-pub`/`x-pub`/`endpoints`. With this module the same peer set
//! can be discovered from DNS: operators publish one TXT record per node under
//! a seed domain, operators of new nodes set `STELL_DNS_SEEDS` to that domain
//! and nothing else.
//!
//! # Record format (one TXT record per peer, single line)
//!
//! ```text
//! stellereum/v1 node_id=inf1:<hex20> ed=<hex32> host=<name> port=<udp> [x=<hex32>]
//! ```
//!
//! * the first token MUST be the version tag `stellereum/v1`;
//! * `node_id` is the infnode node id (`blake3(ed_pub)[..20]`, hex, the
//!   `inf1:` prefix optional on input and canonical in output) and MUST match
//!   the `ed` key — a record whose id does not hash from its own key is
//!   rejected (anti-spoofing, same rule as `infnode::federation`);
//! * `ed` is the ed25519 public key (32 bytes hex), `x` the optional x25519
//!   public key (32 bytes hex), `host` a DNS name, `port` the UDP/QUIC port
//!   (must be in `1024..=65535`);
//! * tokens are whitespace-separated `key=value` pairs; unknown keys are
//!   ignored (forward compatibility), duplicate or malformed keys reject the
//!   whole record (typo resistance); any missing required field rejects it.
//!
//! # Security model
//!
//! Discovery peers are NOT validators: nothing in this module ever touches
//! `cfg.validators`, so `build_validator_set` (and with it the quorum and the
//! genesis state root) stays a pure function of the config file. Discovery
//! poisoning can at worst point the node at peers it then talks to under the
//! normal pinned-key TLS authentication — it can never mint consensus power.
//!
//! ACL posture (audit-network F10, aligned, not changed): peers added here go
//! through infnode's `ensure_dht_peer` with the hardcoded restricted ACL
//! (`lookup`/`update`/`find_node` — no `store`/`sync`, and no `find_value`),
//! so a seed-domain takeover buys at most 32 DHT-routing entries (capped by
//! [`MAX_DNS_PEERS`]), never KV reads/writes by strangers. The testnet
//! `unknown-allow` TOFU-challenge path is a DIFFERENT path (first-contact
//! peers, not DNS peers) and additionally grants `dht.find_value`: strangers
//! there can READ DHT KV (public chain data — blob manifests, headers — low
//! impact, nothing forgeable, nothing writable). That asymmetry is deliberate
//! and documented here so the code comment at `ensure_dht_peer` ("find_value
//! is withheld") reads as the DNS-path contract, not the TOFU-path contract.
//!
//! QUIC/TLS posture (audit-network F11, testnet-accepted): first contact on
//! the live testnet runs `allow-unknown: true` (TOFU: operator MUST check the
//! SSH-style fingerprint in the log); mainnet MUST set `allow-unknown: false`
//! with fully pinned peers. Inbound node-id spoofing without the ed private
//! key fails challenge-auth; static-file peers without a
//! `node_id == blake3(ed_pub)` binding (audit-network F6) remain an
//! operator-file trust boundary — see the F6 note in the final report.
//!
//! The whole feature is opt-in: with `STELL_DNS_SEEDS` unset or empty the node
//! performs ZERO network calls and behaves exactly as before.

use infnode::config::PeerConfig;
use infnode::node::Node;
use infnode::proto::NODEID_LEN;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Environment variable enabling discovery: comma-separated seed domains,
/// e.g. `STELL_DNS_SEEDS="seeds.stellereum.org,backup.seeds.stellereum.org"`.
///
/// Unset or empty = discovery disabled, no network calls at all. The value is
/// operator-local bootstrap configuration: the SAME value on every node is NOT
/// required — discovery peers are not validators, so nodes may discover
/// different (or no) peers and still share one validator set and one genesis.
pub const DNS_SEEDS_ENV: &str = "STELL_DNS_SEEDS";

/// Hard cap on peers accepted from DNS in total (poisoning bound). A hostile
/// DNS answer can never inject more than this many peers into the peer-set.
pub const MAX_DNS_PEERS: usize = 32;

/// Lowest port a discovered peer may advertise (privileged ports rejected).
pub const MIN_DISCOVERED_PORT: u16 = 1024;

/// Longest accepted TXT record; anything longer is rejected unread.
pub const MAX_TXT_RECORD_LEN: usize = 512;

/// Timeout for the whole resolve of ONE seed domain (query + retries).
pub const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-nameserver UDP wait inside one domain resolve (several servers may be
/// tried before the domain budget above is exhausted).
const PER_SERVER_TIMEOUT: Duration = Duration::from_secs(2);

/// Version tag that must lead every seed TXT record.
const RECORD_VERSION: &str = "stellereum/v1";

/// DNS QTYPE for TXT records.
const QTYPE_TXT: u16 = 16;

/// Cap on parsed answers walked out of one DNS response (response-size bound).
const MAX_ANSWERS_WALKED: u16 = 64;

/// Counter of TXT resolver invocations. Injected into tests through
/// [`reset_txt_query_count`]/[`txt_query_count`] to prove that a disabled
/// (or empty) `STELL_DNS_SEEDS` performs ZERO resolver work.
static TXT_QUERIES: AtomicUsize = AtomicUsize::new(0);

/// One peer discovered from a DNS TXT record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredPeer {
    /// Canonical `inf1:<hex40>` node id.
    pub node_id: String,
    /// ed25519 public key (the TLS pin and the consensus identity of the peer).
    pub ed_pub: [u8; 32],
    /// Optional x25519 public key (encrypted transport).
    pub x_pub: Option<[u8; 32]>,
    /// Advertised DNS name (resolved to addresses via A/AAAA before dialing).
    pub host: String,
    /// Advertised UDP/QUIC port.
    pub port: u16,
}

impl DiscoveredPeer {
    /// Raw 20-byte node id, if the string decodes.
    pub fn node_id_raw(&self) -> Option<[u8; NODEID_LEN]> {
        let s = self.node_id.strip_prefix("inf1:").unwrap_or(&self.node_id);
        let b = hex::decode(s).ok()?;
        b.try_into().ok()
    }
}

/// Outcome of [`merge_seeds`]: the peers that may be added, plus why the rest
/// was dropped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeResult {
    /// Deduplicated, capped peers not present in the configured set.
    pub new_peers: Vec<DiscoveredPeer>,
    /// Records dropped because their node id or ed key was already known
    /// (configured peer or an earlier discovery record).
    pub duplicates: usize,
    /// Records dropped because the [`MAX_DNS_PEERS`] cap was reached.
    pub over_cap: usize,
}

/// Parse one TXT record into a [`DiscoveredPeer`]. See the module doc for the
/// format. Any structural problem — missing required field, bad hex, wrong
/// lengths, port outside `1024..=65535`, id not matching the ed key, oversized
/// or empty record — returns `None`; the record is rejected as a whole.
pub fn parse_txt_record(s: &str) -> Option<DiscoveredPeer> {
    let s = s.trim();
    if s.is_empty() || s.len() > MAX_TXT_RECORD_LEN {
        return None;
    }
    let mut tokens = s.split_whitespace();
    if tokens.next()? != RECORD_VERSION {
        return None;
    }
    let mut node_id: Option<String> = None;
    let mut ed: Option<[u8; 32]> = None;
    let mut x: Option<Option<[u8; 32]>> = None;
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    for tok in tokens {
        let (key, value) = tok.split_once('=')?;
        match key {
            "node_id" => {
                if node_id.is_some() {
                    return None; // duplicate key: reject, never last-wins
                }
                let raw = hex::decode(value.strip_prefix("inf1:").unwrap_or(value)).ok()?;
                let raw: [u8; NODEID_LEN] = raw.try_into().ok()?;
                node_id = Some(format!("inf1:{}", hex::encode(raw)));
            }
            "ed" => {
                if ed.is_some() {
                    return None;
                }
                let b = hex::decode(value).ok()?;
                ed = Some(b.try_into().ok()?);
            }
            "x" => {
                if x.is_some() {
                    return None;
                }
                let b = hex::decode(value).ok()?;
                x = Some(Some(b.try_into().ok()?));
            }
            "host" => {
                if host.is_some() {
                    return None;
                }
                if !valid_host(value) {
                    return None;
                }
                host = Some(value.to_string());
            }
            "port" => {
                if port.is_some() {
                    return None;
                }
                let p: u16 = value.parse().ok()?;
                if p < MIN_DISCOVERED_PORT {
                    return None;
                }
                port = Some(p);
            }
            // Unknown keys are ignored on purpose (forward compatibility).
            _ => {}
        }
    }
    let node_id = node_id?;
    let ed = ed?;
    let host = host?;
    let port = port?;
    // Anti-spoofing: the node id must be blake3(ed_pub)[..20], the infnode
    // convention. A record pairing a victim's id with another key is rejected.
    let expected = blake3::hash(&ed);
    if node_id != format!("inf1:{}", hex::encode(&expected.as_bytes()[..NODEID_LEN])) {
        return None;
    }
    Some(DiscoveredPeer {
        node_id,
        ed_pub: ed,
        x_pub: x.flatten(),
        host,
        port,
    })
}

/// DNS-name sanity for the advertised host: non-empty, bounded length,
/// letters/digits/`-`/`.`/`_` only, no empty labels.
fn valid_host(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    let h = h.trim_end_matches('.');
    if h.is_empty() {
        return false;
    }
    h.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Merge discovered peers with the configured peer set: drop anything whose
/// node id or ed key is already known (configured peer or earlier discovery),
/// and cap the remainder at [`MAX_DNS_PEERS`]. Pure and order-preserving.
pub fn merge_seeds(configured: &[PeerConfig], discovered: Vec<DiscoveredPeer>) -> MergeResult {
    let mut known_ids: Vec<[u8; NODEID_LEN]> = Vec::new();
    let mut known_ed: Vec<[u8; 32]> = Vec::new();
    for p in configured {
        if let Ok(raw) = p.node_id_raw() {
            known_ids.push(raw);
        }
        if let Ok(ed) = p.ed_bytes() {
            known_ed.push(ed);
        }
    }
    let mut out = MergeResult::default();
    for d in discovered {
        if out.new_peers.len() >= MAX_DNS_PEERS {
            out.over_cap += 1;
            continue;
        }
        // Defense in depth: parse already validated the port, re-check here so
        // the cap path can never admit a peer the parser would have rejected.
        if d.port < MIN_DISCOVERED_PORT {
            out.over_cap += 1;
            continue;
        }
        let Some(raw) = d.node_id_raw() else {
            out.over_cap += 1;
            continue;
        };
        if known_ids.contains(&raw) || known_ed.contains(&d.ed_pub) {
            out.duplicates += 1;
            continue;
        }
        known_ids.push(raw);
        known_ed.push(d.ed_pub);
        out.new_peers.push(d);
    }
    out
}

/// Parse the raw `STELL_DNS_SEEDS` value into a list of seed domains. Empty
/// input (or only commas/whitespace) yields an empty list; entries with an
/// invalid character set or absurd length are dropped.
pub fn parse_seed_domains(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| {
            s.len() <= 253
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        })
        .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Seed domains from the environment. Empty (unset or blank) means discovery
/// is disabled and the caller must perform no network calls.
pub fn seed_domains_from_env() -> Vec<String> {
    match std::env::var(DNS_SEEDS_ENV) {
        Ok(raw) => parse_seed_domains(&raw),
        Err(_) => Vec::new(),
    }
}

/// Number of TXT resolver invocations so far (test instrumentation).
pub fn txt_query_count() -> usize {
    TXT_QUERIES.load(Ordering::SeqCst)
}

/// Reset the resolver invocation counter (test instrumentation).
pub fn reset_txt_query_count() {
    TXT_QUERIES.store(0, Ordering::SeqCst);
}

/// Parse `/etc/resolv.conf` content: return the `nameserver` addresses (port
/// 53). Malformed lines, comments (`#`, `;`) and non-IP values are skipped;
/// this function never panics on any input.
pub fn parse_resolv_conf(content: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else { continue };
        if key != "nameserver" {
            continue;
        }
        let Some(val) = parts.next() else { continue };
        // Strip an optional IPv6 zone id ("%eth0") before parsing.
        let ip_str = val.split('%').next().unwrap_or(val);
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            out.push(SocketAddr::new(ip, 53));
        }
    }
    out
}

/// Nameservers from `/etc/resolv.conf`; empty when the file is missing or
/// holds no usable `nameserver` line.
pub fn read_resolver_addrs() -> Vec<SocketAddr> {
    read_resolver_addrs_from(Path::new("/etc/resolv.conf"))
}

/// [`read_resolver_addrs`] with an injectable path (tests).
pub fn read_resolver_addrs_from(path: &Path) -> Vec<SocketAddr> {
    match std::fs::read_to_string(path) {
        Ok(content) => parse_resolv_conf(&content),
        Err(_) => Vec::new(),
    }
}

/// Encode a DNS name (QNAME wire format). Returns `None` on an empty name, a
/// label over 63 bytes or a name over 253 bytes.
fn encode_dns_name(name: &str) -> Option<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Some(out)
}

/// Build a standard recursive TXT query for `domain`.
fn build_txt_query(domain: &str, id: u16) -> Option<Vec<u8>> {
    let qname = encode_dns_name(domain)?;
    let mut q = Vec::with_capacity(12 + qname.len() + 4);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1, standard query
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    q.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    q.extend_from_slice(&qname);
    q.extend_from_slice(&QTYPE_TXT.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    Some(q)
}

/// Position after a DNS name at `off`, following compression-pointer-free
/// skipping: a pointer ends the name (2 bytes consumed), labels advance.
/// Bounds-checked; returns `None` on any malformed input.
fn skip_name(buf: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let len = *buf.get(off)? as usize;
        if len == 0 {
            return Some(off + 1);
        }
        if len & 0xC0 == 0xC0 {
            buf.get(off + 1)?;
            return Some(off + 2);
        }
        if len & 0xC0 != 0 {
            return None; // reserved label type
        }
        off = off.checked_add(1 + len)?;
        if off > buf.len() {
            return None;
        }
    }
}

/// Decode one TXT RDATA (a sequence of character-strings, concatenated).
fn parse_txt_rdata(rdata: &[u8]) -> Option<String> {
    let mut out = String::new();
    let mut i = 0usize;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        i += 1;
        let chunk = rdata.get(i..i.checked_add(len)?)?;
        out.push_str(std::str::from_utf8(chunk).ok()?);
        i += len;
    }
    Some(out)
}

/// Parse a DNS response and extract the TXT strings from its answers.
/// Header id must match the query; rcode != 0 or TC set is an error.
fn parse_dns_response(buf: &[u8], expect_id: u16) -> Result<Vec<String>, String> {
    if buf.len() < 12 {
        return Err("short DNS response".into());
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expect_id {
        return Err("DNS response id mismatch".into());
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(format!("DNS rcode {rcode}"));
    }
    if flags & 0x0200 != 0 {
        return Err("DNS response truncated (TC)".into());
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    let an = u16::from_be_bytes([buf[6], buf[7]]).min(MAX_ANSWERS_WALKED);
    let mut off = 12usize;
    for _ in 0..qd {
        off = skip_name(buf, off).ok_or("malformed question name")?;
        off = off
            .checked_add(4)
            .filter(|o| *o <= buf.len())
            .ok_or("short question section")?;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        off = skip_name(buf, off).ok_or("malformed answer name")?;
        if off + 10 > buf.len() {
            return Err("short answer header".into());
        }
        let rtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let rclass = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
        let rdlen = u16::from_be_bytes([buf[off + 8], buf[off + 9]]) as usize;
        off += 10;
        let rdata = buf.get(off..off + rdlen).ok_or("short rdata")?;
        off += rdlen;
        if rtype == QTYPE_TXT && rclass == 1 {
            if let Some(s) = parse_txt_rdata(rdata) {
                out.push(s);
            }
        }
    }
    Ok(out)
}

/// True when `buf` is a response to `expect_id` with the TC (truncated) bit
/// set (RFC 1035 §4.1.1). Used to trigger the TCP fallback: a truncated UDP
/// answer is not a failure, it is an instruction to retry over TCP.
fn is_truncated_response(buf: &[u8], expect_id: u16) -> bool {
    if buf.len() < 12 {
        return false;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expect_id {
        return false;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    flags & 0x0200 != 0
}

/// One TXT query over TCP (RFC 1035 §4.2.2: two-byte big-endian length prefix
/// before every message), against a single nameserver.
///
/// Uses the same [`PER_SERVER_TIMEOUT`] budget as the UDP path and the same
/// [`parse_dns_response`] validation (id match, rcode == 0, TXT extraction).
/// A TC bit on the TCP answer itself is still an error — TCP answers must not
/// be truncated.
async fn query_txt_via_tcp(
    addr: &SocketAddr,
    query: &[u8],
    expect_id: u16,
) -> Result<Vec<String>, String> {
    if query.is_empty() || query.len() > u16::MAX as usize {
        return Err("bad query length for TCP".into());
    }
    let exchange = async {
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| format!("TCP connect {addr} failed: {e}"))?;
        let prefix = (query.len() as u16).to_be_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut stream, &prefix)
            .await
            .map_err(|e| format!("TCP send to {addr} failed: {e}"))?;
        tokio::io::AsyncWriteExt::write_all(&mut stream, query)
            .await
            .map_err(|e| format!("TCP send to {addr} failed: {e}"))?;
        let mut len_buf = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut len_buf)
            .await
            .map_err(|e| format!("TCP recv length from {addr} failed: {e}"))?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len < 12 {
            return Err("short DNS TCP response".to_string());
        }
        let mut buf = vec![0u8; resp_len];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
            .await
            .map_err(|e| format!("TCP recv body from {addr} failed: {e}"))?;
        parse_dns_response(&buf, expect_id)
    };
    match tokio::time::timeout(PER_SERVER_TIMEOUT, exchange).await {
        Ok(r) => r,
        Err(_) => Err(format!("TCP {addr} timed out")),
    }
}

/// One UDP TXT query against the given nameservers, trying each in turn.
/// This is the ONLY function that touches the network; it bumps the resolver
/// counter so tests can observe exactly how often it would have been called.
///
/// When a UDP answer arrives with the TC (truncated) bit set — what public
/// resolvers like 8.8.8.8/1.1.1.1 return for `seeds.stellereum.org` once the
/// TXT set outgrows a UDP datagram — the same query is retried over TCP
/// (RFC 1035 §4.2.2, two-byte length prefix) against the SAME server before
/// moving on to the next nameserver.
pub async fn query_txt_records(addrs: &[SocketAddr], domain: &str) -> Result<Vec<String>, String> {
    TXT_QUERIES.fetch_add(1, Ordering::SeqCst);
    if addrs.is_empty() {
        return Err("no nameservers available".into());
    }
    let id: u16 = rand::random();
    let query = build_txt_query(domain, id).ok_or_else(|| format!("bad domain {domain}"))?;
    for addr in addrs {
        let bind: SocketAddr = if addr.is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let sock = match tokio::net::UdpSocket::bind(bind).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("[dns-seeds] UDP bind {bind} failed: {e}");
                continue;
            }
        };
        if let Err(e) = sock.send_to(&query, addr).await {
            tracing::warn!("[dns-seeds] send to {addr} failed: {e}");
            continue;
        }
        let mut buf = [0u8; 4096];
        match tokio::time::timeout(PER_SERVER_TIMEOUT, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                if from != *addr {
                    continue;
                }
                match parse_dns_response(&buf[..n], id) {
                    Ok(txts) => return Ok(txts),
                    Err(e) => {
                        if is_truncated_response(&buf[..n], id) {
                            tracing::warn!(
                                "[dns-seeds] truncated (TC) UDP from {addr}, retrying via TCP"
                            );
                            match query_txt_via_tcp(addr, &query, id).await {
                                Ok(txts) => return Ok(txts),
                                Err(te) => {
                                    tracing::warn!(
                                        "[dns-seeds] TCP fallback to {addr} failed: {te}"
                                    );
                                    continue;
                                }
                            }
                        }
                        tracing::warn!("[dns-seeds] bad response from {addr}: {e}");
                        continue;
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::warn!("[dns-seeds] recv from {addr} failed: {e}");
                continue;
            }
            Err(_) => {
                tracing::warn!("[dns-seeds] {addr} timed out");
                continue;
            }
        }
    }
    Err(format!("no TXT answer for {domain}"))
}

/// Resolve the TXT records of one seed domain, bounded by
/// [`DNS_RESOLVE_TIMEOUT`] for the whole domain.
pub async fn resolve_domain(domain: &str) -> Result<Vec<String>, String> {
    let addrs = read_resolver_addrs();
    match tokio::time::timeout(DNS_RESOLVE_TIMEOUT, query_txt_records(&addrs, domain)).await {
        Ok(r) => r,
        Err(_) => Err(format!("timeout after {DNS_RESOLVE_TIMEOUT:?}")),
    }
}

/// Discover peers from the given seed domains. A failing domain logs a warning
/// and is skipped — the node must start and run with zero working seeds.
pub async fn discover_seeds(domains: &[String]) -> Vec<DiscoveredPeer> {
    let mut out = Vec::new();
    for domain in domains {
        match resolve_domain(domain).await {
            Ok(records) => {
                for r in records {
                    match parse_txt_record(&r) {
                        Some(p) => out.push(p),
                        None => {
                            tracing::warn!("[dns-seeds] {domain}: rejected malformed TXT record");
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "[dns-seeds] resolve {domain} failed: {e} (continuing without its seeds)"
                );
            }
        }
    }
    out
}

/// Resolve a discovered peer's host to dialable `ip:port` endpoints via
/// A/AAAA lookup. Empty result = the host currently resolves to nothing.
pub async fn resolve_peer_endpoints(peer: &DiscoveredPeer) -> Vec<String> {
    match tokio::net::lookup_host((peer.host.as_str(), peer.port)).await {
        Ok(addrs) => addrs.map(|a| a.to_string()).collect(),
        Err(e) => {
            tracing::warn!("[dns-seeds] {} host lookup failed: {e}", peer.host);
            Vec::new()
        }
    }
}

/// Add discovered peers to a node's peer-set via infnode's existing dynamic
/// peer API (`Node::ensure_dht_peer`), which is idempotent: peers already in
/// the map are left untouched, so a repeated pass creates no duplicates.
/// Returns the number of peers newly added.
pub async fn add_discovered_peers(node: &Arc<Node>, peers: &[DiscoveredPeer]) -> usize {
    let mut added = 0usize;
    for p in peers {
        let Some(raw) = p.node_id_raw() else { continue };
        if raw == node.id {
            continue; // never dial ourselves
        }
        if node.peers.read().await.contains_key(&raw) {
            continue; // only add peers that are not known yet
        }
        let endpoints = resolve_peer_endpoints(p).await;
        if endpoints.is_empty() {
            tracing::warn!("[dns-seeds] {}: no A/AAAA addresses, skipping", p.node_id);
            continue;
        }
        let info = infnode::dht::NodeInfo {
            id: raw,
            endpoints,
            ed_hex: hex::encode(p.ed_pub),
            x_hex: p.x_pub.map(hex::encode).unwrap_or_default(),
            last_seen: infnode::dht::now_ms(),
        };
        match node.ensure_dht_peer(&info).await {
            Ok(()) => {
                added += 1;
                tracing::info!(
                    "[dns-seeds] added peer {} @ {:?} (discovery only, NOT a validator)",
                    p.node_id,
                    info.endpoints
                );
            }
            Err(e) => {
                tracing::warn!("[dns-seeds] failed to add peer {}: {e}", p.node_id);
            }
        }
    }
    added
}

/// One full discovery pass: env -> TXT resolve -> parse -> merge against the
/// configured peers -> add the new ones to the node. Safe to call repeatedly;
/// doing nothing when `STELL_DNS_SEEDS` is unset or empty.
pub async fn run_dns_seed_pass(node: &Arc<Node>) {
    let domains = seed_domains_from_env();
    if domains.is_empty() {
        return;
    }
    let discovered = discover_seeds(&domains).await;
    if discovered.is_empty() {
        return;
    }
    let merged = merge_seeds(&node.cfg.peers, discovered);
    if merged.new_peers.is_empty() {
        tracing::debug!(
            "[dns-seeds] pass: nothing new ({} duplicate(s), {} over cap)",
            merged.duplicates,
            merged.over_cap
        );
        return;
    }
    let added = add_discovered_peers(node, &merged.new_peers).await;
    tracing::info!(
        "[dns-seeds] pass: {} new peer(s) added, {} duplicate(s), {} over cap",
        added,
        merged.duplicates,
        merged.over_cap
    );
}

/// Spawn the background discovery loop: one pass immediately (before consensus
/// has to find anyone), then every `interval`.
pub fn spawn_dns_seed_discovery(node: Arc<Node>, interval: Duration) {
    tokio::spawn(async move {
        run_dns_seed_pass(&node).await;
        loop {
            tokio::time::sleep(interval).await;
            run_dns_seed_pass(&node).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes the tests that touch `STELL_DNS_SEEDS` (process-global env).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn ed_of(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn id_of(ed: &[u8; 32]) -> String {
        let h = blake3::hash(ed);
        format!("inf1:{}", hex::encode(&h.as_bytes()[..NODEID_LEN]))
    }

    fn valid_record(seed: u8, port: u16) -> String {
        let ed = ed_of(seed);
        format!(
            "stellereum/v1 node_id={} ed={} host=node{}.example port={port}",
            id_of(&ed),
            hex::encode(ed),
            seed % 10
        )
    }

    fn configured_peer(seed: u8) -> PeerConfig {
        let ed = ed_of(seed);
        PeerConfig {
            name: format!("peer-{seed}"),
            node_id: id_of(&ed),
            ed_pub: hex::encode(ed),
            x_pub: hex::encode(ed_of(seed.wrapping_add(1))),
            pq_pub: None, // GATE: classical-only fixture (no PQ identity announced)
            endpoints: vec!["127.0.0.1:9411".into()],
            allow: vec!["*".into()],
            rate_limit_per_sec: 0,
            role: None,
            storage_roles: vec![],
        }
    }

    fn discovered(seed: u8) -> DiscoveredPeer {
        let ed = ed_of(seed);
        DiscoveredPeer {
            node_id: id_of(&ed),
            ed_pub: ed,
            x_pub: Some(ed_of(seed.wrapping_add(1))),
            host: format!("node{}.example", seed % 10),
            port: 9411,
        }
    }

    #[test]
    fn valid_txt_record_parses() {
        let rec = valid_record(0x11, 9411);
        let p = parse_txt_record(&rec).expect("valid record must parse");
        assert_eq!(p.node_id, id_of(&ed_of(0x11)));
        assert_eq!(p.ed_pub, ed_of(0x11));
        assert_eq!(p.x_pub, None, "x is optional and absent here");
        assert_eq!(p.host, "node7.example"); // 0x11 % 10 == 7
        assert_eq!(p.port, 9411);

        // With the optional x key.
        let rec = format!(
            "{} x={}",
            valid_record(0x12, 20000),
            hex::encode(ed_of(0x99))
        );
        let p = parse_txt_record(&rec).expect("record with x must parse");
        assert_eq!(p.x_pub, Some(ed_of(0x99)));
    }

    #[test]
    fn missing_required_fields_are_rejected() {
        let ed = ed_of(0x21);
        let base = format!(
            "node_id={} ed={} host=n.example port=9411",
            id_of(&ed),
            hex::encode(ed)
        );
        assert!(parse_txt_record(&base).is_none(), "missing version tag");
        let full = format!("stellereum/v1 {base}");
        assert!(parse_txt_record(&full).is_some());
        assert!(
            parse_txt_record(&format!(
                "stellereum/v1 ed={} host=n.example port=9411",
                hex::encode(ed)
            ))
            .is_none(),
            "missing node_id"
        );
        assert!(
            parse_txt_record(&format!(
                "stellereum/v1 node_id={} host=n.example port=9411",
                id_of(&ed)
            ))
            .is_none(),
            "missing ed"
        );
        assert!(
            parse_txt_record(&format!(
                "stellereum/v1 node_id={} ed={}",
                id_of(&ed),
                hex::encode(ed)
            ))
            .is_none(),
            "missing host and port"
        );
    }

    #[test]
    fn bad_hex_wrong_lengths_and_bad_ports_are_rejected() {
        let ed = ed_of(0x31);
        let id = id_of(&ed);
        // Bad ed hex.
        assert!(parse_txt_record(&format!(
            "stellereum/v1 node_id={id} ed=zz host=n.example port=9411"
        ))
        .is_none());
        // ed of the wrong length.
        assert!(parse_txt_record(&format!(
            "stellereum/v1 node_id={id} ed={} host=n.example port=9411",
            hex::encode(&ed[..16])
        ))
        .is_none());
        // node_id of the wrong length.
        assert!(parse_txt_record(&format!(
            "stellereum/v1 node_id=inf1:{} ed={} host=n.example port=9411",
            hex::encode(&ed[..8]),
            hex::encode(ed)
        ))
        .is_none());
        // node_id not matching the ed key (spoof attempt).
        let other = id_of(&ed_of(0x32));
        assert!(parse_txt_record(&format!(
            "stellereum/v1 node_id={other} ed={} host=n.example port=9411",
            hex::encode(ed)
        ))
        .is_none());
        // Privileged and unparsable ports.
        for port in ["80", "0", "1023", "abc", "70000"] {
            assert!(
                parse_txt_record(&format!(
                    "stellereum/v1 node_id={id} ed={} host=n.example port={port}",
                    hex::encode(ed)
                ))
                .is_none(),
                "port {port} must be rejected"
            );
        }
        // Duplicate keys reject the record (typo resistance, never last-wins).
        assert!(parse_txt_record(&format!(
            "stellereum/v1 node_id={id} node_id={id} ed={} host=n.example port=9411",
            hex::encode(ed)
        ))
        .is_none());
        // Invalid host characters.
        assert!(parse_txt_record(&format!(
            "stellereum/v1 node_id={id} ed={} host=bad host.example port=9411",
            hex::encode(ed)
        ))
        .is_none());
    }

    #[test]
    fn empty_and_oversized_records_are_rejected() {
        assert!(parse_txt_record("").is_none());
        assert!(parse_txt_record("   \t ").is_none());
        let long = format!("stellereum/v1 junk={}", "a".repeat(MAX_TXT_RECORD_LEN));
        assert!(long.len() > MAX_TXT_RECORD_LEN);
        assert!(parse_txt_record(&long).is_none());
        // A record that fits but carries an absurdly long host is rejected too.
        let long_host = "a".repeat(300);
        assert!(parse_txt_record(&format!(
            "stellereum/v1 node_id={} ed={} host={long_host} port=9411",
            id_of(&ed_of(0x41)),
            hex::encode(ed_of(0x41))
        ))
        .is_none());
    }

    #[test]
    fn merge_dedups_by_node_id_and_ed_pub() {
        let configured = vec![configured_peer(0x51)];
        let d_id_dup = discovered(0x51); // same node id + ed as the configured peer
        let ed_only = discovered(0x52);
        let mut ed_only_dup = discovered(0x52);
        ed_only_dup.node_id = id_of(&ed_of(0x77)); // different id, SAME ed
        let first = discovered(0x53);
        let mut second = first.clone(); // exact duplicate across two seed domains
        second.host = "other.example".into();
        let fresh = discovered(0x54);

        let r = merge_seeds(
            &configured,
            vec![d_id_dup, ed_only, ed_only_dup, first, second, fresh],
        );
        assert_eq!(r.new_peers.len(), 3, "0x52 + 0x53 once + 0x54");
        assert_eq!(r.new_peers[0].node_id, discovered(0x52).node_id);
        assert_eq!(r.new_peers[1].node_id, discovered(0x53).node_id);
        assert_eq!(r.new_peers[2].node_id, discovered(0x54).node_id);
        assert_eq!(r.duplicates, 3, "configured-id, ed-only, repeat");
        assert_eq!(r.over_cap, 0);
    }

    #[test]
    fn merge_caps_at_max_dns_peers() {
        let discovered: Vec<DiscoveredPeer> = (0..50u8).map(discovered).collect();
        let r = merge_seeds(&[], discovered);
        assert_eq!(r.new_peers.len(), MAX_DNS_PEERS);
        assert_eq!(r.new_peers.len(), 32);
        assert_eq!(r.over_cap, 18);
        assert_eq!(r.duplicates, 0);
    }

    #[test]
    fn re_resolve_pass_creates_no_duplicates() {
        // First pass: everything is new against an empty configured set.
        let pass1 = merge_seeds(&[], vec![discovered(0x61), discovered(0x62)]);
        assert_eq!(pass1.new_peers.len(), 2);
        // Simulate the runtime peer-set after the first pass: the discovered
        // peers are now (configured-like) known entries.
        let mut now_configured = vec![configured_peer(0x60)];
        for p in &pass1.new_peers {
            now_configured.push(PeerConfig {
                name: p.node_id.clone(),
                node_id: p.node_id.clone(),
                ed_pub: hex::encode(p.ed_pub),
                x_pub: p.x_pub.map(hex::encode).unwrap_or_default(),
                pq_pub: None, // GATE: discovered peers carry no PQ identity yet
                endpoints: vec![format!("{}:{}", p.host, p.port)],
                allow: vec!["*".into()],
                rate_limit_per_sec: 0,
                role: None,
                storage_roles: vec![],
            });
        }
        // Second pass resolves the same DNS records again.
        let pass2 = merge_seeds(&now_configured, vec![discovered(0x61), discovered(0x62)]);
        assert!(pass2.new_peers.is_empty(), "second pass must add nobody");
        assert_eq!(pass2.duplicates, 2);
        assert_eq!(pass2.over_cap, 0);
    }

    #[test]
    fn resolv_conf_parsing_is_panic_free_and_correct() {
        assert!(parse_resolv_conf("").is_empty());
        assert!(parse_resolv_conf("garbage\nnot a config\n#\n;\n").is_empty());
        assert!(parse_resolv_conf("nameserver\nnameserver not-an-ip\n").is_empty());
        let servers = parse_resolv_conf(
            "# comment\nsearch example.com\nnameserver 1.1.1.1\n; other\nnameserver 2606:4700:4700::1111\nnameserver 8.8.8.8%eth0\noptions timeout:2\n",
        );
        assert_eq!(
            servers,
            vec![
                "1.1.1.1:53".parse().unwrap(),
                "[2606:4700:4700::1111]:53".parse().unwrap(),
                "8.8.8.8:53".parse().unwrap(),
            ]
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: tests serialize process env via ENV_LOCK across awaits; no prod lock held
    async fn query_with_no_nameservers_errors_without_panicking() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_txt_query_count();
        let r = query_txt_records(&[], "seeds.example.org").await;
        assert!(r.is_err(), "no nameservers must be a clean error");
        assert_eq!(txt_query_count(), 1, "the resolver path was entered once");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: tests serialize process env via ENV_LOCK across awaits; no prod lock held
    async fn empty_or_absent_env_makes_zero_resolver_calls() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_txt_query_count();

        std::env::remove_var(DNS_SEEDS_ENV);
        assert!(seed_domains_from_env().is_empty());
        run_dns_seed_pass_disabled_path().await;

        std::env::set_var(DNS_SEEDS_ENV, "");
        assert!(seed_domains_from_env().is_empty());
        run_dns_seed_pass_disabled_path().await;

        std::env::set_var(DNS_SEEDS_ENV, "  ,  ,");
        assert!(seed_domains_from_env().is_empty());
        run_dns_seed_pass_disabled_path().await;

        std::env::set_var(
            DNS_SEEDS_ENV,
            " Seeds.Stellereum.Org , bad host! , backup.seeds.stellereum.org ",
        );
        assert_eq!(
            seed_domains_from_env(),
            vec![
                "seeds.stellereum.org".to_string(),
                "backup.seeds.stellereum.org".to_string(),
            ],
            "invalid entries dropped, valid ones lowercased"
        );

        assert_eq!(
            txt_query_count(),
            0,
            "a disabled/empty STELL_DNS_SEEDS must perform ZERO resolver calls"
        );
        std::env::remove_var(DNS_SEEDS_ENV);
    }

    /// The disabled path with a real (empty) domain list: `discover_seeds`
    /// loops over nothing, so no resolver call can happen.
    async fn run_dns_seed_pass_disabled_path() {
        let domains = seed_domains_from_env();
        let discovered = discover_seeds(&domains).await;
        assert!(discovered.is_empty());
    }

    /// Encode one TXT RDATA body (length-prefixed character-strings).
    fn txt_rdata_for_test(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() + 1);
        for chunk in bytes.chunks(255) {
            out.push(chunk.len() as u8);
            out.extend_from_slice(chunk);
        }
        out
    }

    /// Build a synthetic DNS response for `domain` with the given TXT answers.
    /// `truncated=true` sets the TC bit and carries zero answers (what
    /// 8.8.8.8/1.1.1.1 return for an oversized `seeds.stellereum.org` zone);
    /// `truncated=false` is a complete answer with one RR per TXT string.
    fn build_dns_response_for_test(
        id: u16,
        domain: &str,
        txts: &[String],
        truncated: bool,
    ) -> Vec<u8> {
        let qname = encode_dns_name(domain).expect("test domain must encode");
        let flags: u16 = if truncated { 0x8380 } else { 0x8180 }; // QR+RD+RA [+TC]
        let an = if truncated { 0 } else { txts.len() as u16 };
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&an.to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        out.extend_from_slice(&qname);
        out.extend_from_slice(&QTYPE_TXT.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
        if !truncated {
            for txt in txts {
                out.extend_from_slice(&[0xC0, 0x0C]); // NAME = pointer to QNAME
                out.extend_from_slice(&QTYPE_TXT.to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes()); // CLASS=IN
                out.extend_from_slice(&300u32.to_be_bytes()); // TTL
                let rdata = txt_rdata_for_test(txt);
                out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                out.extend_from_slice(&rdata);
            }
        }
        out
    }

    /// Three peers A/B/C as TXT strings (valid seed records).
    fn three_peer_txts() -> Vec<String> {
        vec![
            valid_record(0xA1, 9411),
            valid_record(0xB2, 9412),
            valid_record(0xC3, 9413),
        ]
    }

    #[test]
    fn truncated_response_is_detected_and_rejected_by_parser() {
        let id = 0x1234;
        let domain = "seeds.stellereum.org";
        let truncated = build_dns_response_for_test(id, domain, &[], true);
        assert!(
            is_truncated_response(&truncated, id),
            "TC bit must be detected"
        );
        let err = parse_dns_response(&truncated, id).expect_err("TC must be an error");
        assert!(err.contains("TC"), "unexpected error: {err}");
        // Wrong id: not ours, so not treated as our truncation.
        assert!(!is_truncated_response(&truncated, id.wrapping_add(1)));

        let txts = three_peer_txts();
        let full = build_dns_response_for_test(id, domain, &txts, false);
        assert!(!is_truncated_response(&full, id));
        let parsed = parse_dns_response(&full, id).expect("full answer must parse");
        assert_eq!(parsed, txts, "all 3 TXT records must survive one response");
        for s in &parsed {
            assert!(
                parse_txt_record(s).is_some(),
                "each of the 3 TXT records must parse as a peer"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: tests serialize process env via ENV_LOCK across awaits; no prod lock held
    async fn udp_path_returns_multiple_txt_records() {
        use tokio::net::UdpSocket;
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let domain = "seeds.stellereum.org";
        let txts = three_peer_txts();
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP");
        let addr = server.local_addr().expect("local addr");
        let srv_txts = txts.clone();
        let domain_owned = domain.to_string();
        let srv = tokio::spawn(async move {
            let mut qbuf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut qbuf).await.expect("recv query");
            assert!(n >= 12, "query must have a header");
            let qid = u16::from_be_bytes([qbuf[0], qbuf[1]]);
            let resp = build_dns_response_for_test(qid, &domain_owned, &srv_txts, false);
            server.send_to(&resp, peer).await.expect("send answer");
        });
        let got = query_txt_records(&[addr], domain)
            .await
            .expect("plain UDP path must return the 3 TXT records");
        assert_eq!(got, txts, "UDP path must preserve all 3 records");
        srv.await.expect("server task");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // GATE: tests serialize process env via ENV_LOCK across awaits; no prod lock held
    async fn synthetic_truncated_udp_falls_back_to_tcp() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, UdpSocket};
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let domain = "seeds.stellereum.org";
        let txts = three_peer_txts();

        // Same port for UDP and TCP (different protocols may share it).
        let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP");
        let port = udp.local_addr().expect("local addr").port();
        let tcp = TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .expect("bind TCP on the same port");
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");

        // UDP side: always answers TC-only (the 8.8.8.8/1.1.1.1 behaviour).
        let domain_udp = domain.to_string();
        let udp_srv = tokio::spawn(async move {
            let mut qbuf = [0u8; 512];
            let (n, peer) = udp.recv_from(&mut qbuf).await.expect("udp recv");
            assert!(n >= 12);
            let qid = u16::from_be_bytes([qbuf[0], qbuf[1]]);
            let resp = build_dns_response_for_test(qid, &domain_udp, &[], true);
            udp.send_to(&resp, peer).await.expect("udp send TC");
        });
        // TCP side: full answer with the 3 TXT records, RFC 1035 framing.
        let domain_tcp = domain.to_string();
        let tcp_txts = txts.clone();
        let tcp_srv = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.expect("tcp accept");
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.expect("tcp read len");
            let qlen = u16::from_be_bytes(len_buf) as usize;
            assert!(qlen >= 12, "TCP query must have a header");
            let mut qbuf = vec![0u8; qlen];
            stream.read_exact(&mut qbuf).await.expect("tcp read query");
            let qid = u16::from_be_bytes([qbuf[0], qbuf[1]]);
            let resp = build_dns_response_for_test(qid, &domain_tcp, &tcp_txts, false);
            stream
                .write_all(&(resp.len() as u16).to_be_bytes())
                .await
                .expect("tcp write len");
            stream.write_all(&resp).await.expect("tcp write body");
        });

        let got = query_txt_records(&[addr], domain)
            .await
            .expect("TC-truncated UDP must fall back to TCP and find the records");
        assert_eq!(got, txts, "TCP fallback must return all 3 TXT records");
        for s in &got {
            assert!(
                parse_txt_record(s).is_some(),
                "each TCP-fallback record must parse as a peer"
            );
        }
        udp_srv.await.expect("udp task");
        tcp_srv.await.expect("tcp task");
    }
}
