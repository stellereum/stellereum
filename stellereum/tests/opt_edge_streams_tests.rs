use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Barrier};
use stellereum::client_ip::{
    canonical_ip, forwarded_chain_from_headers, parse_ip_token, parse_trusted_list,
    resolve_client_ip, resolve_client_ip_opt, resolve_detailed, resolve_with_config,
    select_from_chain, xff_chain_from_headers, ClientIp, ClientIpConfig, ClientIpSource,
    TrustedNet, XffMode,
};
use stellereum::explorer::RateLimiter;
use stellereum::rpc::{SubscriptionHub, SubscriptionTopic, MAX_SUBSCRIPTIONS_PER_CLIENT};

fn build_headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.append(
            HeaderName::from_bytes(k.as_bytes()).expect("header name"),
            HeaderValue::from_str(v).expect("header value"),
        );
    }
    map
}

fn reference_resolve(
    headers: &HeaderMap,
    peer: IpAddr,
    trusted: &[TrustedNet],
    mode: XffMode,
    trust_loopback_forwarded: bool,
) -> ClientIp {
    let peer = canonical_ip(peer);
    if !stellereum::client_ip::is_trusted_in(&peer, trusted) {
        return ClientIp::from_peer(peer);
    }
    let single = ["cf-connecting-ip", "true-client-ip", "x-real-ip"]
        .iter()
        .find_map(|name| {
            headers
                .get(*name)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').filter_map(parse_ip_token).next())
        });
    let claimed = select_from_chain(&xff_chain_from_headers(headers), mode, trusted)
        .or_else(|| select_from_chain(&forwarded_chain_from_headers(headers), mode, trusted))
        .or(single)
        .map(canonical_ip);
    match claimed {
        None => ClientIp::from_peer(peer),
        Some(ip) if ip.is_loopback() && !trust_loopback_forwarded => ClientIp {
            addr: peer,
            source: ClientIpSource::ForwardedLoopbackRejected,
        },
        Some(ip) => ClientIp {
            addr: ip,
            source: ClientIpSource::Forwarded,
        },
    }
}

#[test]
fn client_ip_config_resolve_matches_resolve_detailed_and_reference() {
    let trusted = parse_trusted_list("127.0.0.0/8, ::1/128, 10.0.0.0/8, 2001:db8:1::/48");
    let peers: Vec<IpAddr> = vec![
        "127.0.0.1".parse().unwrap(),
        "::ffff:127.0.0.1".parse().unwrap(),
        "::1".parse().unwrap(),
        "10.2.3.4".parse().unwrap(),
        "::ffff:10.2.3.4".parse().unwrap(),
        "2001:db8:1::42".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        "::ffff:8.8.8.8".parse().unwrap(),
    ];

    let header_cases: Vec<Vec<(&str, &str)>> = vec![
        vec![],
        vec![("x-forwarded-for", "")],
        vec![(
            "x-forwarded-for",
            " , unknown, _hidden, _secluded, garbage ",
        )],
        vec![("x-forwarded-for", "1.2.3.4")],
        vec![("x-forwarded-for", "9.9.9.9, 1.2.3.4")],
        vec![("x-forwarded-for", "9.9.9.9, 10.1.2.3, 127.0.0.1")],
        vec![(
            "x-forwarded-for",
            "1.2.3.4, 198.51.100.7, 10.0.0.9, 10.0.0.10",
        )],
        vec![("x-forwarded-for", "10.0.0.2, 10.0.0.3, 127.0.0.5")],
        vec![(
            "x-forwarded-for",
            " , 203.0.113.5:8080 , , [2001:db8:2::1]:443 , 10.9.8.7 ",
        )],
        vec![("x-forwarded-for", "::ffff:127.0.0.1")],
        vec![("x-forwarded-for", "::ffff:198.51.100.1, ::ffff:10.0.0.1")],
        vec![
            ("x-forwarded-for", "9.9.9.9, 198.51.100.2"),
            ("x-forwarded-for", "10.0.0.5, 10.0.0.6"),
        ],
        vec![("x-forwarded-for", "unknown"), ("x-forwarded-for", " , ")],
        vec![(
            "forwarded",
            "for=192.0.2.60;proto=http, for=\"[2001:db8::1]:4711\";by=127.0.0.1",
        )],
        vec![(
            "forwarded",
            "proto=https;for=unknown, for=198.51.100.9;for=1.1.1.1, for=10.1.1.1",
        )],
        vec![
            ("forwarded", "for=198.51.100.11"),
            ("forwarded", "for=10.20.30.40"),
        ],
        vec![("forwarded", "for=\"::ffff:127.0.0.1\"")],
        vec![
            ("x-forwarded-for", "unknown"),
            ("forwarded", "for=203.0.113.99"),
        ],
        vec![
            ("cf-connecting-ip", "203.0.113.10"),
            ("x-real-ip", "203.0.113.20"),
        ],
        vec![
            ("true-client-ip", "203.0.113.30"),
            ("x-real-ip", "203.0.113.40"),
        ],
        vec![("x-real-ip", "::ffff:127.0.0.1")],
        vec![("x-real-ip", "::1")],
    ];

    for mode in [XffMode::Rightmost, XffMode::Leftmost] {
        for trust_loopback in [false, true] {
            let cfg = ClientIpConfig {
                trusted: trusted.clone(),
                mode,
                trust_loopback_forwarded: trust_loopback,
            };
            for &peer in &peers {
                for pairs in &header_cases {
                    let headers = build_headers(pairs);
                    let got_cfg = cfg.resolve(&headers, peer);
                    let got_fn = resolve_with_config(&headers, peer, &cfg);
                    let expected = resolve_detailed(&headers, peer, &trusted, mode, trust_loopback);
                    let reference =
                        reference_resolve(&headers, peer, &trusted, mode, trust_loopback);

                    assert_eq!(
                        got_cfg, expected,
                        "cfg.resolve mismatch: mode={mode:?} trust_loopback={trust_loopback} peer={peer} pairs={pairs:?}"
                    );
                    assert_eq!(
                        got_fn, expected,
                        "resolve_with_config mismatch: mode={mode:?} trust_loopback={trust_loopback} peer={peer} pairs={pairs:?}"
                    );
                    assert_eq!(
                        expected, reference,
                        "reference mismatch: mode={mode:?} trust_loopback={trust_loopback} peer={peer} pairs={pairs:?}"
                    );
                }
            }
        }
    }

    assert!(resolve_client_ip_opt(&HeaderMap::new(), None).is_none());
    let peer: IpAddr = "8.8.4.4".parse().unwrap();
    assert_eq!(
        resolve_client_ip_opt(&HeaderMap::new(), Some(peer)),
        Some(resolve_client_ip(&HeaderMap::new(), peer))
    );
}

#[test]
fn rate_limiter_sharded_accuracy_mapped_v6_and_prune() {
    let limiter = RateLimiter::new(3);
    let now = 1_700_000_000u64;

    // Distinct IPs distributed across all 16 shards each get their full `per_sec` budget.
    for last in 0u8..200 {
        let ip = IpAddr::from([192, 0, 2, last]);
        assert!(limiter.check_at(ip, now));
        assert!(limiter.check_at(ip, now));
        assert!(limiter.check_at(ip, now));
        assert!(!limiter.check_at(ip, now));
    }

    // Next second resets every bucket.
    for last in 0u8..200 {
        let ip = IpAddr::from([192, 0, 2, last]);
        assert!(limiter.check_at(ip, now + 1));
    }

    // IPv4 and IPv4-mapped IPv6 share the exact same shard and bucket.
    let v4: IpAddr = "198.51.100.77".parse().unwrap();
    let mapped: IpAddr = "::ffff:198.51.100.77".parse().unwrap();
    assert!(limiter.check_at(v4, now + 10));
    assert!(limiter.check_at(mapped, now + 10));
    assert!(limiter.check_at(v4, now + 10));
    assert!(
        !limiter.check_at(mapped, now + 10),
        "v4 and ::ffff:v4 must share one bucket"
    );

    // Zero clamps to 1/sec.
    let min_limiter = RateLimiter::new(0);
    let ip: IpAddr = "203.0.113.1".parse().unwrap();
    assert!(min_limiter.check_at(ip, now));
    assert!(!min_limiter.check_at(ip, now));

    // Pruning stale windows drops `now` entries at `now + 2` while retaining `now + 1`.
    limiter.prune(now + 12);
    assert!(limiter.check_at(v4, now + 10));
}

#[test]
fn rate_limiter_multithreaded_stress_is_exact() {
    const THREADS: usize = 8;
    const PER_SEC: u32 = 50;
    const ITERS_PER_THREAD: usize = 40;
    let limiter = Arc::new(RateLimiter::new(PER_SEC));
    let barrier = Arc::new(Barrier::new(THREADS));
    let now = 1_700_123_456u64;

    // Shared contended IPs (including mapped-v6 aliases) + thread-local IPs.
    let shared_v4: IpAddr = "198.51.100.10".parse().unwrap();
    let shared_mapped: IpAddr = "::ffff:198.51.100.10".parse().unwrap();

    let handles: Vec<_> = (0..THREADS)
        .map(|tid| {
            let limiter = Arc::clone(&limiter);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let mut shared_allowed = 0u32;
                let mut local_allowed = 0u32;
                let local_ip = IpAddr::from([10, 20, 0, tid as u8 + 1]);
                for i in 0..ITERS_PER_THREAD {
                    let probe = if (i + tid) % 2 == 0 {
                        shared_v4
                    } else {
                        shared_mapped
                    };
                    if limiter.check_at(probe, now) {
                        shared_allowed += 1;
                    }
                    if limiter.check_at(local_ip, now) {
                        local_allowed += 1;
                    }
                }
                (shared_allowed, local_allowed)
            })
        })
        .collect();

    let mut total_shared = 0u32;
    for h in handles {
        let (shared, local) = h.join().expect("worker panicked");
        total_shared += shared;
        assert_eq!(local, ITERS_PER_THREAD as u32);
    }
    assert_eq!(total_shared, PER_SEC);
}

fn ref_topic_key(s: &str) -> String {
    let t = s.trim();
    if let Ok(n) = t.parse::<i64>() {
        return n.to_string();
    }
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        if let Ok(n) = i64::from_str_radix(h, 16) {
            return n.to_string();
        }
    }
    t.to_lowercase()
}

fn ref_topic_matches(filter: &SubscriptionTopic, event: &SubscriptionTopic) -> bool {
    match (filter, event) {
        (SubscriptionTopic::NewHeads, SubscriptionTopic::NewHeads) => true,
        (SubscriptionTopic::NewTxs, SubscriptionTopic::NewTxs) => true,
        (SubscriptionTopic::Invalidations, SubscriptionTopic::Invalidations) => true,
        (
            SubscriptionTopic::Events {
                contract: want_contract,
                topics: want_topics,
            },
            SubscriptionTopic::Events {
                contract: ev_contract,
                topics: ev_topics,
            },
        ) => {
            if let Some(want) = want_contract {
                match ev_contract {
                    Some(have) if have.eq_ignore_ascii_case(want) => {}
                    _ => return false,
                }
            }
            if want_topics.is_empty() {
                return true;
            }
            want_topics.iter().any(|w| {
                let w = w.trim();
                w == "*"
                    || w == "#"
                    || ev_topics
                        .iter()
                        .any(|h| ref_topic_key(h) == ref_topic_key(w))
            })
        }
        _ => false,
    }
}

#[test]
fn subscription_hub_publish_matches_reference_topic_matches() {
    let hub = SubscriptionHub::new();
    let c_a = "aa".repeat(32);
    let c_a_upper = "AA".repeat(32);
    let c_b = "bb".repeat(32);

    let filters = vec![
        SubscriptionTopic::NewHeads,
        SubscriptionTopic::NewTxs,
        SubscriptionTopic::Invalidations,
        SubscriptionTopic::Events {
            contract: None,
            topics: vec![],
        },
        SubscriptionTopic::Events {
            contract: Some(c_a.clone()),
            topics: vec![],
        },
        SubscriptionTopic::Events {
            contract: Some(c_a_upper.clone()),
            topics: vec!["1".into(), "0x0A".into()],
        },
        SubscriptionTopic::Events {
            contract: Some(c_a.clone()),
            topics: vec!["0x7B".into(), "Transfer".into()],
        },
        SubscriptionTopic::Events {
            contract: None,
            topics: vec!["*".into()],
        },
        SubscriptionTopic::Events {
            contract: Some(c_b.clone()),
            topics: vec!["#".into()],
        },
        SubscriptionTopic::Events {
            contract: Some(c_a.clone()),
            topics: vec!["-5".into(), "  ".into()],
        },
        SubscriptionTopic::Events {
            contract: None,
            topics: vec!["0xdeadbeefdeadbeefdeadbeef".into()],
        },
    ];

    let mut subs: Vec<(String, SubscriptionTopic)> = Vec::new();
    for (idx, f) in filters.iter().enumerate() {
        let client = format!("client-{}", idx % 3);
        let id = hub
            .subscribe_for(f.clone(), Some(&client))
            .expect("subscribe");
        subs.push((id, f.clone()));
    }

    let events = vec![
        SubscriptionTopic::NewHeads,
        SubscriptionTopic::NewTxs,
        SubscriptionTopic::Invalidations,
        SubscriptionTopic::Events {
            contract: Some(c_a.clone()),
            topics: vec!["0x1".into()],
        },
        SubscriptionTopic::Events {
            contract: Some(c_a.clone()),
            topics: vec!["10".into(), "99".into()],
        },
        SubscriptionTopic::Events {
            contract: Some(c_a_upper.clone()),
            topics: vec!["123".into()],
        },
        SubscriptionTopic::Events {
            contract: Some(c_a.clone()),
            topics: vec!["TRANSFER".into()],
        },
        SubscriptionTopic::Events {
            contract: Some(c_b.clone()),
            topics: vec![],
        },
        SubscriptionTopic::Events {
            contract: Some(c_a.clone()),
            topics: vec!["0x-5".into()],
        },
        SubscriptionTopic::Events {
            contract: Some(c_a.clone()),
            topics: vec!["".into()],
        },
        SubscriptionTopic::Events {
            contract: None,
            topics: vec!["0xDEADBEEFDEADBEEFDEADBEEF".into()],
        },
    ];

    // 1) Without receivers: addressed count must match reference.
    for ev in &events {
        let expected_count = subs
            .iter()
            .filter(|(_, f)| ref_topic_matches(f, ev))
            .count();
        let got_count = hub.publish(ev, json!({ "ok": true }));
        assert_eq!(got_count, expected_count, "no-rx count mismatch for {ev:?}");
    }

    // 2) With receiver: exact target subscription IDs and payload must match reference.
    let mut rx = hub.notifications();
    for (i, ev) in events.iter().enumerate() {
        let expected_ids: HashSet<String> = subs
            .iter()
            .filter(|(_, f)| ref_topic_matches(f, ev))
            .map(|(id, _)| id.clone())
            .collect();
        let payload = json!({ "seq": i, "kind": "test" });
        let got_count = hub.publish(ev, payload.clone());
        assert_eq!(got_count, expected_ids.len());

        let mut received_ids = HashSet::new();
        for _ in 0..got_count {
            let note = rx.try_recv().expect("notification queued");
            assert_eq!(note.result, payload);
            assert!(received_ids.insert(note.subscription));
        }
        assert!(rx.try_recv().is_err(), "no extra notifications expected");
        assert_eq!(received_ids, expected_ids, "target ids mismatch for {ev:?}");
    }
}

#[test]
fn subscription_hub_per_client_limit_and_direct_registry_sync() {
    let hub = SubscriptionHub::new();
    let mut ids = Vec::new();
    for _ in 0..MAX_SUBSCRIPTIONS_PER_CLIENT {
        ids.push(
            hub.subscribe_for(SubscriptionTopic::NewHeads, Some("10.0.0.1"))
                .expect("within per-client limit"),
        );
    }
    let err = hub
        .subscribe_for(SubscriptionTopic::NewHeads, Some("10.0.0.1"))
        .expect_err("must enforce per-client cap");
    assert!(err.contains("per-client"));

    // Unsubscribing one via `unsubscribe_for` frees a slot for that client.
    assert!(!hub.unsubscribe_for(&ids[0], Some("10.0.0.2")));
    assert!(hub.unsubscribe_for(&ids[0], Some("10.0.0.1")));
    let replacement = hub
        .subscribe_for(SubscriptionTopic::NewTxs, Some("10.0.0.1"))
        .expect("freed slot must be usable");
    ids[0] = replacement;

    // Direct mutation of `pub registry` must keep `publish` consistent.
    {
        let mut reg = hub.registry.write().unwrap();
        let mut copy: HashMap<String, _> = reg.drain().collect();
        // Keep only the NewTxs subscription inserted above.
        copy.retain(|id, _| id == &ids[0]);
        *reg = copy;
    }
    assert_eq!(hub.publish(&SubscriptionTopic::NewHeads, json!({})), 0);
    assert_eq!(hub.publish(&SubscriptionTopic::NewTxs, json!({})), 1);
}
