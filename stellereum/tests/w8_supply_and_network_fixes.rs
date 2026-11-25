//! Wave 8 Agent D regression tests:
//! 1. `Mempool::matching_account` matches `pool.all()` filtered & sorted by
//!    `nonce` descending, caps returned transactions at `limit`, and reports
//!    exact `total_count` without cloning unrelated transactions.
//! 2. `resolve_peer_endpoints_with_timeout` / `resolve_peer_endpoints_with_lookup`
//!    bounds host resolution and returns empty cleanly on timeout or failure.
//! 3. `.github/workflows/*.yml` pins every `uses:` action reference to an exact
//!    40-hex commit SHA (no floating tags such as `@v4`, `@stable`, `@nightly`).

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use stellereum::dns_seeds::{
    resolve_peer_endpoints_with_lookup, resolve_peer_endpoints_with_timeout, DiscoveredPeer,
    DNS_HOST_LOOKUP_TIMEOUT,
};
use stellereum::mempool::Mempool;
use stellereum::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};
use stellereum::sharding::{PqSignatureEnvelope, Transaction};

fn pq_addr(seed: u8) -> [u8; 32] {
    derive_pq_address(
        PqScheme::Falcon512,
        &Transaction::sample_falcon512_pubkey(seed),
        &DEFAULT_SALT,
    )
}

fn signed_transfer(seed: u8, to: [u8; 32], amount: u64, gas_limit: u64, nonce: u64) -> Transaction {
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = pq_addr(seed);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("PQ test key must register");
    let mut t = Transaction {
        from,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = t.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    t.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    t
}

#[test]
fn mempool_matching_account_matches_all_filtered_sorted_and_caps_at_limit() {
    let mut pool = Mempool::new(100, 100);
    let seed_target = 0xE1;
    let seed_other_in = 0xE2;
    let seed_unrelated = 0xE3;

    let target = pq_addr(seed_target);
    let unrelated_recipient = [0x99u8; 32];

    // Outgoing from target (distinct nonces: 0, 2, 5).
    for nonce in [0u64, 2, 5] {
        pool.add(signed_transfer(
            seed_target,
            unrelated_recipient,
            100,
            1_000,
            nonce,
        ))
        .unwrap();
    }
    // Incoming to target from another sender (distinct nonces: 1, 4).
    for nonce in [1u64, 4] {
        pool.add(signed_transfer(seed_other_in, target, 200, 1_000, nonce))
            .unwrap();
    }
    // Unrelated transactions that must neither be counted nor returned.
    for nonce in [10u64, 20, 30] {
        pool.add(signed_transfer(
            seed_unrelated,
            unrelated_recipient,
            300,
            1_000,
            nonce,
        ))
        .unwrap();
    }

    let mut expected: Vec<Transaction> = pool
        .all()
        .into_iter()
        .filter(|t| t.from == target || t.to == target)
        .collect();
    expected.sort_by(|x, y| y.nonce.cmp(&x.nonce));
    assert_eq!(expected.len(), 5);

    // Zero limit still returns exact total count and empty vec.
    let (total_zero, got_zero) = pool.matching_account(&target, 0);
    assert_eq!(total_zero, 5);
    assert!(got_zero.is_empty());

    // Cap below total returns exact total count and top `limit` by nonce desc.
    let (total_capped, got_capped) = pool.matching_account(&target, 3);
    assert_eq!(total_capped, 5);
    assert_eq!(got_capped.len(), 3);
    let got_hashes: Vec<[u8; 32]> = got_capped.iter().map(|t| t.compute_tx_hash()).collect();
    let expected_hashes: Vec<[u8; 32]> = expected
        .iter()
        .take(3)
        .map(|t| t.compute_tx_hash())
        .collect();
    assert_eq!(got_hashes, expected_hashes);
    assert_eq!(
        got_capped.iter().map(|t| t.nonce).collect::<Vec<_>>(),
        vec![5, 4, 2]
    );

    // Cap above total returns all matching transactions in descending nonce order.
    let (total_all, got_all) = pool.matching_account(&target, 20);
    assert_eq!(total_all, 5);
    assert_eq!(
        got_all
            .iter()
            .map(|t| t.compute_tx_hash())
            .collect::<Vec<_>>(),
        expected
            .iter()
            .map(|t| t.compute_tx_hash())
            .collect::<Vec<_>>()
    );

    // Unknown account yields zero count and empty vec.
    let (total_none, got_none) = pool.matching_account(&[0xFEu8; 32], 20);
    assert_eq!(total_none, 0);
    assert!(got_none.is_empty());
}

#[tokio::test]
async fn dns_host_lookup_timeout_returns_empty_without_hanging() {
    assert_eq!(DNS_HOST_LOOKUP_TIMEOUT, Duration::from_secs(5));

    let peer = DiscoveredPeer {
        node_id: format!("inf1:{}", hex::encode([0x11u8; 20])),
        pq_pub: vec![0x22u8; 897],
        kem_ek_hash: None,
        host: "nonexistent.invalid".to_string(),
        port: 9411,
    };

    // Slow / hung lookup future must be aborted at `timeout` and yield empty Vec.
    let start = Instant::now();
    let timed_out = resolve_peer_endpoints_with_lookup(
        &peer,
        Duration::from_millis(30),
        std::future::pending::<std::io::Result<Vec<SocketAddr>>>(),
    )
    .await;
    assert!(timed_out.is_empty(), "timeout must return empty endpoints");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "timeout must return promptly without hanging"
    );

    // Erroring lookup future yields empty Vec.
    let errored = resolve_peer_endpoints_with_lookup(
        &peer,
        Duration::from_millis(50),
        std::future::ready(Err::<Vec<SocketAddr>, _>(std::io::Error::other(
            "simulated lookup failure",
        ))),
    )
    .await;
    assert!(errored.is_empty());

    // Successful lookup future yields formatted ip:port strings.
    let addr: SocketAddr = "127.0.0.1:9411".parse().unwrap();
    let ok = resolve_peer_endpoints_with_lookup(
        &peer,
        Duration::from_millis(50),
        std::future::ready(Ok(vec![addr])),
    )
    .await;
    assert_eq!(ok, vec!["127.0.0.1:9411".to_string()]);

    // Real `resolve_peer_endpoints_with_timeout` on reserved `.invalid` domain
    // returns empty cleanly within the short timeout bound.
    let start_real = Instant::now();
    let real_res = resolve_peer_endpoints_with_timeout(&peer, Duration::from_millis(40)).await;
    assert!(real_res.is_empty());
    assert!(start_real.elapsed() < Duration::from_secs(2));
}

#[test]
fn github_workflows_pin_all_actions_to_40_hex_commit_shas() {
    let workflows_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(".github")
        .join("workflows");
    assert!(
        workflows_dir.is_dir(),
        "workflows directory must exist at {}",
        workflows_dir.display()
    );

    let mut checked_files = Vec::new();
    let mut checked_uses = 0usize;

    for entry in std::fs::read_dir(&workflows_dir).expect("read workflows dir") {
        let path = entry.expect("dir entry").path();
        let ext = path.extension().and_then(|s| s.to_str());
        if ext != Some("yml") && ext != Some("yaml") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let content = std::fs::read_to_string(&path).expect("read workflow file");
        checked_files.push(name.clone());

        for (idx, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.starts_with('#') {
                continue;
            }
            let Some(after_uses) = line
                .strip_prefix("- uses:")
                .or_else(|| line.strip_prefix("uses:"))
            else {
                continue;
            };
            let action_ref = after_uses.split('#').next().unwrap_or("").trim();
            let (action, rev) = action_ref.split_once('@').unwrap_or_else(|| {
                panic!(
                    "{name}:{}: `uses:` reference missing `@`: `{action_ref}`",
                    idx + 1
                )
            });
            assert!(
                rev.len() == 40 && rev.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                "{name}:{}: action `{action}` is not pinned to a 40-hex SHA: `{rev}`",
                idx + 1
            );
            checked_uses += 1;
        }
    }

    checked_files.sort();
    assert_eq!(
        checked_files,
        vec!["ci.yml", "fuzz.yml", "nightly.yml", "release.yml"]
    );
    assert!(checked_uses >= 36, "expected at least 36 uses: entries");
}
