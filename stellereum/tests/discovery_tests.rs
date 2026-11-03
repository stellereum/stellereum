//! Eclipse-resistant discovery: identity comes from config, endpoints may come
//! from the network.
//!
//! Background: `P2pNetworkAdapter::discover_peers` (src/network.rs) returns every
//! endpoint the DHT view (`known_peers`: routing table + configured peers)
//! claims, with no check on WHO the endpoint claims to be — and the routing
//! table is fed by unauthenticated peer gossip (`dht.find_node` responses,
//! `dht.update` route merges). An attacker who controls a node's DHT view can
//! therefore inject attacker-chosen identities: the first step of an eclipse.
//!
//! These tests pin the fix, all as pure data-level checks (no live DHT —
//! `P2pNetworkAdapter` holds an `Arc<infnode::node::Node>`, which cannot be
//! constructed in a test):
//!
//! 1. `filter_discovered_to_pinned` NEVER admits an unknown ed-pub — not even a
//!    record with an empty/missing key (legacy gossip carries none).
//! 2. A KNOWN identity (ed-pub pinned in the local `peers:` config) with a NEW
//!    endpoint from the network IS admitted — discovery still learns routes.
//! 3. The `PeerEndpointTable` freshness table is bounded: adversarial endpoint
//!    floods cannot grow memory without limit.
//! 4. A peer that fails N times is deprioritized (sorts last, reports backed
//!    off) but NOT forgotten — a later success restores it immediately.

use stellereum::network::{
    filter_discovered_to_pinned, pinned_identity_set, PeerEndpoint, PeerEndpointTable,
    ENDPOINT_BACKOFF_THRESHOLD, MAX_ENDPOINT_RECORDS,
};

fn ed(hex_char: char) -> String {
    std::iter::repeat_n(hex_char, 64).collect()
}

fn node_info(id_byte: u8, ed_pub: &str, endpoints: &[&str]) -> infnode::dht::NodeInfo {
    infnode::dht::NodeInfo {
        id: [id_byte; 20],
        endpoints: endpoints.iter().map(|s| s.to_string()).collect(),
        ed_hex: ed_pub.to_string(),
        x_hex: ed('c'),
        last_seen: 0,
    }
}

fn peer_config(
    name: &str,
    node_id_byte: u8,
    ed_pub: &str,
    endpoints: &[&str],
) -> infnode::config::PeerConfig {
    infnode::config::PeerConfig {
        name: name.to_string(),
        node_id: format!("inf1:{}", hex::encode([node_id_byte; 20])),
        ed_pub: ed_pub.to_string(),
        x_pub: ed('d'),
        pq_pub: None, // GATE: classical-only test fixture
        endpoints: endpoints.iter().map(|s| s.to_string()).collect(),
        allow: vec!["*".to_string()],
        rate_limit_per_sec: 0,
        role: None,
        storage_roles: vec![],
    }
}

#[test]
fn unknown_identity_is_never_admitted_by_the_filter() {
    // Local config pins exactly one peer identity.
    let pinned_ed = ed('a');
    let peers = vec![peer_config("honest", 0x01, &pinned_ed, &["10.0.0.1:9410"])];
    let pinned = pinned_identity_set(&peers);
    assert_eq!(pinned.len(), 1);

    // The network view claims: the honest peer (moved address), an attacker's
    // fresh key, and a legacy gossip record with no key at all.
    let attacker_ed = ed('b');
    let discovered = vec![
        node_info(0x01, &pinned_ed, &["10.0.0.9:9410"]),
        node_info(0x02, &attacker_ed, &["10.9.9.9:9410"]),
        node_info(0x03, "", &["10.9.9.10:9410"]),
    ];

    let kept = filter_discovered_to_pinned(discovered, &pinned);

    // Only the pinned identity survives, with its new endpoint.
    assert_eq!(kept.len(), 1, "exactly the pinned identity must survive");
    assert_eq!(kept[0].ed_hex, pinned_ed);
    assert!(kept[0].endpoints.contains(&"10.0.0.9:9410".to_string()));
    // The attacker's endpoint must appear NOWHERE in the output.
    let all_eps: Vec<&str> = kept
        .iter()
        .flat_map(|n| n.endpoints.iter().map(String::as_str))
        .collect();
    assert!(
        !all_eps.contains(&"10.9.9.9:9410"),
        "attacker endpoint admitted!"
    );
    assert!(
        !all_eps.contains(&"10.9.9.10:9410"),
        "keyless gossip admitted!"
    );
}

#[test]
fn known_identity_with_a_new_endpoint_is_admitted() {
    // Identity comes from config (one pinned ed-pub, one static endpoint)...
    let pinned_ed = ed('e');
    let peers = vec![peer_config("peer", 0x07, &pinned_ed, &["10.0.0.1:9410"])];
    let pinned = pinned_identity_set(&peers);

    // ...endpoints may come from the network, even in different hex case.
    let discovered = vec![node_info(
        0x07,
        &pinned_ed.to_ascii_uppercase(),
        &["10.0.0.2:9411"],
    )];

    let kept = filter_discovered_to_pinned(discovered, &pinned);
    assert_eq!(
        kept.len(),
        1,
        "new endpoint for a KNOWN identity must be kept"
    );
    assert_eq!(kept[0].endpoints, vec!["10.0.0.2:9411".to_string()]);
}

#[test]
fn failure_backoff_caps_memory() {
    // Adversarial gossip can advertise unbounded distinct endpoints; the table
    // must not grow with it.
    let mut table = PeerEndpointTable::new(8);
    for i in 0..200 {
        table.record_failure(&format!("10.99.0.{i}:9410"));
    }
    assert!(table.len() <= 8, "table grew to {} entries", table.len());

    // Same for the production cap: hammer it with 4x the cap.
    let mut table = PeerEndpointTable::with_default_cap();
    assert_eq!(table.cap(), MAX_ENDPOINT_RECORDS);
    for i in 0..MAX_ENDPOINT_RECORDS * 4 {
        table.record_success(
            &format!("10.100.{}.{}:9410", i / 256, i % 256),
            1_000 + i as u64,
        );
    }
    assert!(
        table.len() <= MAX_ENDPOINT_RECORDS,
        "table grew to {}",
        table.len()
    );
}

#[test]
fn repeatedly_failing_peer_is_deprioritized_but_not_forgotten() {
    let mut table = PeerEndpointTable::with_default_cap();
    let bad = "10.0.0.9:9410";
    let good = "10.0.0.1:9410";

    table.record_success(good, 1_000);
    for _ in 0..ENDPOINT_BACKOFF_THRESHOLD + 3 {
        table.record_failure(bad);
    }

    // Deprioritized: backed off and sorted after the healthy endpoint...
    let rec = table
        .get(bad)
        .expect("failing peer must still be remembered");
    assert!(rec.backed_off(), "N failures must back the endpoint off");
    assert_eq!(rec.consecutive_failures, ENDPOINT_BACKOFF_THRESHOLD + 3);
    let order = table.preferred_order();
    assert_eq!(order.first().unwrap(), good);
    assert_eq!(order.last().unwrap(), bad);

    // ...but not forgotten: one success restores it to full standing.
    table.record_success(bad, 2_000);
    let rec = table.get(bad).unwrap();
    assert!(!rec.backed_off());
    assert_eq!(rec.consecutive_failures, 0);
    assert_eq!(rec.last_seen_ms, 2_000);
    assert!(table.preferred_order().contains(&bad.to_string()));
}

#[test]
fn failure_count_saturates_instead_of_wrapping() {
    // A permanently dead endpoint must not wrap its counter back to 0 (which
    // would silently un-back it off). Drive one record to the ceiling directly.
    let mut rec = PeerEndpoint::new("10.0.0.5:9410", 1_000);
    rec.consecutive_failures = u32::MAX - 1;
    rec.mark_failure();
    assert_eq!(rec.consecutive_failures, u32::MAX);
    rec.mark_failure();
    assert_eq!(rec.consecutive_failures, u32::MAX, "counter wrapped!");
    assert!(rec.backed_off());
    // And it still recovers on success.
    rec.mark_success(2_000);
    assert_eq!(rec.consecutive_failures, 0);
    assert!(!rec.backed_off());
}
