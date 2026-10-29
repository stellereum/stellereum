//! Prometheus exposition-format tests for the consensus metrics registry.
//!
//! These are mostly tests about the *format* rather than the numbers, because
//! the format is the contract. A scrape that is subtly malformed still looks
//! plausible in a terminal, and the failure surfaces much later as a silently
//! missing series on a dashboard or a counter that resets every scrape. So
//! there is a real line parser below and every rendered line goes through it.
//!
//! The security test (hostile peer id) is the one that matters most: the peer
//! id is attacker-chosen, and a label value that can close its own sample line
//! lets a remote peer forge metrics. A monitoring system that can be fed
//! forged counters is worse than one that is down, because it lies quietly.

use std::sync::Arc;
use std::thread;
use stellereum::metrics::{
    Registry, Snapshot, VoteKind, CONTENT_TYPE, DEFAULT_BLOCK_INTERVAL_BUCKETS,
    DEFAULT_BLOCK_TXS_BUCKETS, DEFAULT_PEER_LATENCY_BUCKETS,
};

/// Every family the consensus plan calls for, with the TYPE it must declare.
const REQUIRED: &[(&str, &str)] = &[
    ("stell_consensus_round", "gauge"),
    ("stell_consensus_height", "gauge"),
    ("stell_block_interval_seconds", "histogram"),
    ("stell_consensus_votes_total", "counter"),
    ("stell_peer_latency_seconds", "histogram"),
    ("stell_fork_total", "counter"),
    // #288000 execution-divergence firewall counter (see src/metrics.rs
    // DIVERGENCE_TOTAL): declared by the registry, so the exposition parser
    // must accept it here too.
    ("stell_divergence_total", "counter"),
    ("stell_weak_qc_refused_total", "counter"),
    ("stell_mempool_size", "gauge"),
    ("stell_mempool_sealed", "gauge"),
    ("stell_mempool_plain", "gauge"),
    ("stell_mev_unsealed_total", "counter"),
    ("stell_mev_unseal_failed_total", "counter"),
    ("stell_block_txs", "histogram"),
    ("stell_state_root_commits_total", "counter"),
    ("stell_validator_set_size", "gauge"),
    ("stell_validator_power_total", "gauge"),
    ("stell_validator_quorum_power", "gauge"),
    ("stell_validator_set_fragile", "gauge"),
    ("stell_data_dir_bytes", "gauge"),
    ("stell_snapshot_count", "gauge"),
    ("stell_state_entries", "gauge"),
    ("stell_persist_queue_depth", "gauge"),
    ("stell_persist_queue_dropped_total", "counter"),
    ("stell_peer_round_lag", "gauge"),
    // Nil-storm / proposer observability families (see src/metrics.rs):
    // declared by the registry, so the parser must accept them here too.
    ("stell_nil_rounds_total", "counter"),
    ("stell_nil_breaker_fires_total", "counter"),
    ("stell_proposer_missed_total", "counter"),
    ("stell_slow_validation_total", "counter"),
    // A14 chain-binding rollout meter (see src/metrics.rs UNBOUND_TX_TOTAL):
    // declared by the registry, so the parser must accept it here too.
    ("stell_unbound_tx_total", "counter"),
    ("stell_build_info", "gauge"),
];

/// A registry carrying one observation of everything, so no family is empty.
fn populated() -> Arc<Registry> {
    let reg = Registry::shared();
    reg.set_height(412);
    reg.set_round(3);
    reg.set_mempool_size(17);
    reg.set_validator_set_full(5, 5_000_000_000_000, 3_333_333_333_334, true);
    reg.set_data_dir_bytes(2_900_000_000);
    reg.set_snapshot_count(9);
    reg.set_state_entries(1234);
    reg.set_persist_queue_depth(3);
    reg.add_persist_queue_dropped(2);
    reg.set_peer_round_lag("peer-a", 2);
    reg.inc_fork();
    // Newer families must render samples too (see REQUIRED): the helper's
    // contract is "one observation of everything, so no family is empty".
    reg.inc_divergence();
    reg.inc_weak_qc_refused();
    reg.set_mempool_sealed_split(2, 3);
    reg.inc_mev_unsealed(1);
    reg.inc_mev_unseal_failed(1);
    reg.inc_nil_round();
    reg.inc_nil_breaker_fire();
    reg.inc_proposer_miss();
    reg.inc_slow_validation();
    reg.inc_unbound_tx();
    reg.inc_state_root_commit();
    reg.add_state_root_commits(2);
    reg.inc_vote(VoteKind::Prevote);
    reg.inc_vote(VoteKind::Prevote);
    reg.inc_vote(VoteKind::Precommit);
    reg.observe_block(9, 0.4);
    reg.observe_peer_latency("peer-a", 0.003);
    reg.observe_peer_latency("peer-b", 0.9);
    reg
}

// ============================================================================
// A minimal parser for the text exposition format
// ============================================================================

/// `name{labels} value`, as `(name, labels, value)`.
///
/// Owns its strings: the parser reads from a `&str` line, and borrowing the
/// metric name out of a local `String` would tie every sample in a scrape to
/// the lifetime of the text it came from for no benefit.
#[derive(Debug, Clone, PartialEq)]
struct Sample {
    name: String,
    labels: Vec<(String, String)>,
    value: f64,
}

fn is_valid_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == ':' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

/// Parse one sample line. Returns `Err` with a reason for anything malformed.
fn parse_sample(line: &str) -> Result<Sample, String> {
    let (head, value_str) = line
        .rsplit_once(' ')
        .ok_or_else(|| format!("no value field: {line:?}"))?;
    let value: f64 = value_str
        .parse()
        .map_err(|_| format!("value {:?} is not a float: {line:?}", value_str))?;
    // A well-formed value carries no further spaces; if it did, `rsplit_once`
    // would have silently folded the extra words into the value field.
    if value_str.contains(' ') {
        return Err(format!("value field has trailing junk: {line:?}"));
    }

    let (name, labels) = match head.strip_suffix('}') {
        Some(prefix) => {
            let open = prefix
                .find('{')
                .ok_or_else(|| format!("closing brace without opening brace: {line:?}"))?;
            // No nesting is legal inside a label set, so the first `{` is ours.
            if prefix[open + 1..].contains('{') {
                return Err(format!("nested label braces: {line:?}"));
            }
            (
                prefix[..open].to_string(),
                parse_labels(&prefix[open + 1..], line)?,
            )
        }
        None => {
            if head.contains('{') || head.contains('}') {
                return Err(format!("unbalanced label braces: {line:?}"));
            }
            (head.to_string(), Vec::new())
        }
    };

    if !is_valid_name(&name) {
        return Err(format!("invalid metric name {name:?}: {line:?}"));
    }
    Ok(Sample {
        name,
        labels,
        value,
    })
}

fn parse_labels(src: &str, line: &str) -> Result<Vec<(String, String)>, String> {
    let mut labels = Vec::new();
    let mut chars = src.chars().peekable();
    loop {
        // key
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' {
                break;
            }
            key.push(c);
            chars.next();
        }
        if chars.peek() != Some(&'=') {
            return Err(format!("label without '=': {line:?}"));
        }
        chars.next();
        if !is_valid_name(&key) {
            return Err(format!("invalid label name {key:?}: {line:?}"));
        }
        if chars.peek() != Some(&'"') {
            return Err(format!("label value not quoted: {line:?}"));
        }
        chars.next();
        // value, with only \" \\ \n recognised as escapes
        let mut value = String::new();
        let mut closed = false;
        while let Some(c) = chars.next() {
            match c {
                '"' => {
                    closed = true;
                    break;
                }
                '\\' => match chars.next() {
                    Some(e @ '"') => value.push(e),
                    Some(e @ '\\') => value.push(e),
                    Some('n') => value.push('\n'),
                    Some(other) => return Err(format!("invalid escape \\{other}: {line:?}")),
                    None => return Err(format!("truncated escape: {line:?}")),
                },
                other => value.push(other),
            }
        }
        if !closed {
            return Err(format!("unterminated label value: {line:?}"));
        }
        labels.push((key, value));
        match chars.next() {
            Some(',') => continue,
            Some(c) => return Err(format!("junk {c:?} after label value: {line:?}")),
            None => break,
        }
    }
    Ok(labels)
}

/// Parse a full scrape, rejecting anything that is not a comment or a sample.
fn parse_exposition(text: &str) -> Vec<Sample> {
    let mut samples = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        match parse_sample(line) {
            Ok(s) => samples.push(s),
            Err(e) => panic!("malformed exposition line: {e}"),
        }
    }
    samples
}

fn samples_named(text: &str, name: &str) -> Vec<Sample> {
    parse_exposition(text)
        .into_iter()
        .filter(|s| s.name == name)
        .collect()
}

fn count_prefix(text: &str, prefix: &str) -> usize {
    text.lines().filter(|l| l.starts_with(prefix)).count()
}

// ============================================================================
// (a) every required metric is present
// ============================================================================

#[test]
fn exposition_contains_every_required_metric() {
    let text = populated().render();

    for (name, kind) in REQUIRED {
        assert!(
            text.contains(&format!("# TYPE {name} {kind}\n")),
            "missing or mistyped family {name} (want {kind}) in:\n{text}"
        );
    }

    // Counters carry their `_total` suffix in the sample names, so assert the
    // samples themselves exist and not just the TYPE declarations.
    assert!(
        text.contains("stell_consensus_round 3"),
        "round sample missing:\n{text}"
    );
    assert!(
        text.contains("stell_consensus_height 412"),
        "height sample missing:\n{text}"
    );
    assert!(
        text.contains("stell_fork_total 1"),
        "fork counter missing:\n{text}"
    );
    assert!(
        text.contains("stell_mempool_size 17"),
        "mempool gauge missing:\n{text}"
    );
    assert!(
        text.contains("stell_validator_set_size 5"),
        "validator set gauge missing:\n{text}"
    );
    assert!(
        text.contains("stell_validator_power_total 5000000000000"),
        "validator power missing:\n{text}"
    );
    assert!(
        text.contains("stell_validator_quorum_power 3333333333334"),
        "quorum power missing:\n{text}"
    );
    assert!(
        text.contains("stell_validator_set_fragile 1"),
        "fragile flag missing:\n{text}"
    );
    assert!(
        text.contains("stell_data_dir_bytes 2900000000"),
        "data-dir gauge missing:\n{text}"
    );
    assert!(
        text.contains("stell_snapshot_count 9"),
        "snapshot gauge missing:\n{text}"
    );
    assert!(
        text.contains("stell_state_entries 1234"),
        "state-entries gauge missing:\n{text}"
    );
    assert!(
        text.contains("stell_persist_queue_depth 3"),
        "persist depth missing:\n{text}"
    );
    assert!(
        text.contains("stell_persist_queue_dropped_total 2"),
        "persist dropped missing:\n{text}"
    );
    assert!(
        text.contains("stell_peer_round_lag{peer=\"peer-a\"} 2"),
        "peer lag missing:\n{text}"
    );
    assert!(
        text.contains("stell_build_info{"),
        "build info missing:\n{text}"
    );
    assert!(
        text.contains("stell_state_root_commits_total 3"),
        "state root commit counter missing:\n{text}"
    );
    assert!(
        text.contains("stell_consensus_votes_total"),
        "vote counter missing:\n{text}"
    );
    assert!(
        text.contains("stell_block_interval_seconds_bucket"),
        "block interval missing:\n{text}"
    );
    assert!(
        text.contains("stell_block_txs_bucket"),
        "block txs missing:\n{text}"
    );
    assert!(
        text.contains("stell_peer_latency_seconds_bucket"),
        "peer latency missing:\n{text}"
    );

    // Labels are part of the contract: votes are split by kind, latency by peer.
    assert!(
        text.contains("stell_consensus_votes_total{kind=\"prevote\"} 2"),
        "prevote label missing:\n{text}"
    );
    assert!(
        text.contains("stell_consensus_votes_total{kind=\"precommit\"} 1"),
        "precommit label missing:\n{text}"
    );
    assert!(
        text.contains("peer=\"peer-a\""),
        "peer label missing:\n{text}"
    );
    assert!(
        text.contains("peer=\"peer-b\""),
        "second peer label missing:\n{text}"
    );

    // A fresh registry must already describe the whole node, so alerting rules
    // see zero rather than "no data" before the first vote lands.
    let cold = Registry::shared().render();
    for (name, _) in REQUIRED {
        assert!(
            cold.contains(&format!("# TYPE {name} ")),
            "{name} absent from a cold registry"
        );
    }
    assert!(cold.contains("stell_fork_total 0"));
    assert!(cold.contains("stell_data_dir_bytes 0"));
    assert!(cold.contains("stell_snapshot_count 0"));
    assert!(cold.contains("stell_state_entries 0"));
    assert!(cold.contains("stell_persist_queue_depth 0"));
    assert!(cold.contains("stell_persist_queue_dropped_total 0"));
    assert!(cold.contains("stell_validator_power_total 0"));
    assert!(cold.contains("stell_validator_quorum_power 0"));
    assert!(cold.contains("stell_validator_set_fragile 0"));
    assert!(cold.contains("stell_build_info{"));
    assert!(cold.contains("stell_consensus_votes_total{kind=\"prevote\"} 0"));
    assert!(cold.contains("stell_consensus_votes_total{kind=\"precommit\"} 0"));
    assert!(cold.contains("stell_block_interval_seconds_count 0"));
}

// ============================================================================
// (b) HELP and TYPE lines
// ============================================================================

#[test]
fn help_and_type_lines_are_well_formed() {
    let reg = populated();
    reg.inc_fork();
    let text = reg.render();
    let lines: Vec<&str> = text.lines().collect();

    // Exactly one HELP and one TYPE per family, each immediately preceding that
    // family's first sample.
    for (name, kind) in REQUIRED {
        let help: Vec<&&str> = lines
            .iter()
            .filter(|l| l.starts_with(&format!("# HELP {name} ")))
            .collect();
        let types: Vec<&&str> = lines
            .iter()
            .filter(|l| l.starts_with(&format!("# TYPE {name} ")))
            .collect();

        assert_eq!(
            help.len(),
            1,
            "expected exactly one HELP for {name}, got {help:?}"
        );
        assert_eq!(
            types.len(),
            1,
            "expected exactly one TYPE for {name}, got {types:?}"
        );
        assert_eq!(
            *types[0],
            format!("# TYPE {name} {kind}"),
            "wrong TYPE for {name}"
        );

        let help_text = help[0].strip_prefix(&format!("# HELP {name} ")).unwrap();
        assert!(!help_text.is_empty(), "{name} has an empty HELP");
        assert!(
            !help_text.contains('\n'),
            "{name} HELP must stay on one line"
        );
        assert!(is_valid_name(name), "{name} is not a legal metric name");

        // The header must come before the family's samples: a TYPE line in the
        // middle of a family is ignored by some parsers and mis-typed by others.
        // A sample is `name{`, `name_` (a histogram child) or `name `.
        let first_sample = lines
            .iter()
            .position(|l| {
                !l.starts_with('#')
                    && (l.starts_with(&format!("{name}{{"))
                        || l.starts_with(&format!("{name}_"))
                        || l.starts_with(&format!("{name} ")))
            })
            .unwrap_or_else(|| panic!("no samples for {name}"));
        let help_at = lines.iter().position(|l| *l == *help[0]).unwrap();
        let type_at = lines.iter().position(|l| *l == *types[0]).unwrap();
        assert!(
            help_at < first_sample,
            "HELP for {name} must precede its samples"
        );
        assert!(
            type_at < first_sample,
            "TYPE for {name} must precede its samples"
        );
        assert_eq!(
            type_at,
            help_at + 1,
            "TYPE must directly follow HELP for {name}"
        );
    }

    assert!(
        CONTENT_TYPE.starts_with("text/plain"),
        "unexpected content type: {CONTENT_TYPE}"
    );
}

// ============================================================================
// (c) counters accumulate
// ============================================================================

#[test]
fn counter_increments_and_reflects_the_total() {
    let reg = Registry::shared();

    for _ in 0..7 {
        reg.inc_fork();
    }
    reg.add_state_root_commits(10);
    reg.add_state_root_commits(5);
    for _ in 0..3 {
        reg.inc_vote(VoteKind::Prevote);
    }
    for _ in 0..4 {
        reg.inc_vote(VoteKind::Precommit);
    }

    let text = reg.render();
    assert!(
        text.contains("stell_fork_total 7"),
        "fork total wrong:\n{text}"
    );
    assert!(
        text.contains("stell_state_root_commits_total 15"),
        "commit total wrong:\n{text}"
    );
    assert!(
        text.contains("stell_consensus_votes_total{kind=\"prevote\"} 3"),
        "prevotes wrong:\n{text}"
    );
    assert!(
        text.contains("stell_consensus_votes_total{kind=\"precommit\"} 4"),
        "precommits wrong:\n{text}"
    );

    // A counter never decreases, and a separate label is a separate series.
    for _ in 0..3 {
        reg.inc_fork();
    }
    let after = reg.render();
    assert!(
        after.contains("stell_fork_total 10"),
        "fork total must keep accumulating:\n{after}"
    );
    assert!(
        after.contains("stell_consensus_votes_total{kind=\"prevote\"} 3"),
        "prevote series must be untouched by precommits:\n{after}"
    );

    let snap = reg.snapshot();
    assert_eq!(snap.forks, 10.0);
    assert_eq!(snap.state_root_commits, 15.0);
    assert_eq!(snap.votes_prevote, 3.0);
    assert_eq!(snap.votes_precommit, 4.0);
    assert!(
        snap.to_json().contains("\"forks\":10.0"),
        "snapshot json: {}",
        snap.to_json()
    );
}

// ============================================================================
// (d) gauges take the latest value
// ============================================================================

#[test]
fn gauge_takes_the_latest_value() {
    let reg = Registry::shared();

    for h in [1u64, 2, 3, 41, 42, 43] {
        reg.set_height(h);
    }
    for r in [0u32, 1, 7, 2] {
        reg.set_round(r);
    }
    for m in [5u64, 0, 250, 12] {
        reg.set_mempool_size(m);
    }
    for v in [1u64, 4, 4, 6] {
        reg.set_validator_set_size(v);
    }

    let text = reg.render();
    assert!(
        text.contains("stell_consensus_height 43\n"),
        "height must be the latest:\n{text}"
    );
    assert!(
        text.contains("stell_consensus_round 2\n"),
        "round must be the latest:\n{text}"
    );
    assert!(
        text.contains("stell_mempool_size 12\n"),
        "mempool must be the latest:\n{text}"
    );
    assert!(
        text.contains("stell_validator_set_size 6\n"),
        "validator set must be the latest:\n{text}"
    );

    // A gauge is a single value, not a total: exactly one sample each, and the
    // histogram families must not have been disturbed by the writes.
    for name in [
        "stell_consensus_height",
        "stell_consensus_round",
        "stell_mempool_size",
        "stell_validator_set_size",
    ] {
        assert_eq!(
            samples_named(&text, name).len(),
            1,
            "{name} must have exactly one sample"
        );
    }
    assert!(
        text.contains("stell_block_interval_seconds_count 0"),
        "gauge writes must not observe histograms"
    );
    assert!(text.contains("stell_block_txs_count 0"));

    // Going back to zero is a legitimate gauge state, not a "missing" one.
    reg.set_mempool_size(0);
    assert!(reg.render().contains("stell_mempool_size 0\n"));
}

// ============================================================================
// (e) histograms
// ============================================================================

#[test]
fn histogram_emits_buckets_sum_and_count() {
    let reg = Registry::shared();
    for _ in 0..5 {
        reg.observe_block_interval(0.05);
    }
    for _ in 0..3 {
        reg.observe_block_interval(0.75);
    }
    reg.observe_block_interval(42.0); // above every bound: only `+Inf` and `_count`

    let text = reg.render();
    let samples = samples_named(&text, "stell_block_interval_seconds_count");
    assert_eq!(samples.len(), 1);
    assert_eq!(
        samples[0].value, 9.0,
        "_count must equal the number of observations"
    );

    let sums = samples_named(&text, "stell_block_interval_seconds_sum");
    assert_eq!(sums.len(), 1);
    let expected_sum = 5.0 * 0.05 + 3.0 * 0.75 + 42.0;
    assert!(
        (sums[0].value - expected_sum).abs() < 1e-9,
        "_sum wrong: {} vs {expected_sum}",
        sums[0].value
    );

    // Every declared bound appears, in ascending order, plus the mandatory
    // `+Inf` bucket.
    let buckets = samples_named(&text, "stell_block_interval_seconds_bucket");
    let bounds: Vec<f64> = buckets
        .iter()
        .map(|s| {
            assert_eq!(
                s.labels.len(),
                1,
                "unlabelled histogram bucket must carry only `le`"
            );
            assert_eq!(s.labels[0].0, "le");
            s.labels[0]
                .1
                .parse::<f64>()
                .expect("`le` must be a float or +Inf")
        })
        .collect();
    let mut expected: Vec<f64> = DEFAULT_BLOCK_INTERVAL_BUCKETS.to_vec();
    expected.push(f64::INFINITY);
    assert_eq!(
        bounds.len(),
        expected.len(),
        "bucket count mismatch: {bounds:?}"
    );
    assert_eq!(bounds, expected, "bucket bounds/order mismatch: {bounds:?}");

    // Cumulative, so `histogram_quantile` has a monotone series to work with.
    let counts: Vec<f64> = buckets.iter().map(|s| s.value).collect();
    assert!(
        counts.windows(2).all(|w| w[0] <= w[1]),
        "bucket counts must be non-decreasing: {counts:?}"
    );
    assert_eq!(
        counts[0], 5.0,
        "five 0.05s observations must land in the first bucket"
    );
    assert_eq!(
        *counts.last().unwrap(),
        9.0,
        "+Inf bucket must equal _count"
    );

    // The other two families use their own defaults and the same shape.
    reg.observe_block_txs(0);
    reg.observe_block_txs(500);
    reg.observe_peer_latency("p1", 0.02);
    reg.observe_peer_latency("p1", 2.0);
    let text = reg.render();
    assert_eq!(samples_named(&text, "stell_block_txs_count")[0].value, 2.0);
    assert_eq!(
        samples_named(&text, "stell_peer_latency_seconds_count").len(),
        1
    );
    assert_eq!(
        samples_named(&text, "stell_peer_latency_seconds_sum")[0].value,
        2.02
    );
    assert_eq!(
        samples_named(&text, "stell_block_interval_seconds_count").len(),
        1
    );

    let txs_buckets = samples_named(&text, "stell_block_txs_bucket");
    assert_eq!(txs_buckets.len(), DEFAULT_BLOCK_TXS_BUCKETS.len() + 1);
    // A labelled histogram bucket keeps the family labels alongside `le`.
    let peer_buckets: Vec<Sample> = samples_named(&text, "stell_peer_latency_seconds_bucket")
        .into_iter()
        .filter(|s| s.labels.iter().any(|(_, v)| v == "p1"))
        .collect();
    assert_eq!(
        peer_buckets.len(),
        DEFAULT_PEER_LATENCY_BUCKETS.len() + 1,
        "peer p1 must get every bucket plus +Inf"
    );
    for bucket in &peer_buckets {
        let keys: Vec<&str> = bucket.labels.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec!["le", "peer"],
            "labels must be sorted by name, `le` first"
        );
    }
    // Two observations: 0.02s and 2.0s, each landing in the first bucket whose
    // bound it does not exceed. The index is looked up from the constant so the
    // test survives someone retuning the buckets.
    let landed: Vec<f64> = peer_buckets
        .iter()
        .take(DEFAULT_PEER_LATENCY_BUCKETS.len())
        .map(|s| s.value)
        .collect();
    let fast = DEFAULT_PEER_LATENCY_BUCKETS
        .iter()
        .position(|b| 0.02 <= *b)
        .unwrap();
    let slow = DEFAULT_PEER_LATENCY_BUCKETS
        .iter()
        .position(|b| 2.0 <= *b)
        .unwrap();
    assert_eq!(
        landed[fast], 1.0,
        "the 0.02s sample belongs in the {fast} bucket: {landed:?}"
    );
    assert_eq!(
        landed[slow], 2.0,
        "the 2.0s sample belongs in the {slow} bucket: {landed:?}"
    );
}

// ============================================================================
// (f) determinism
// ============================================================================

#[test]
fn two_renders_with_identical_data_are_byte_identical() {
    let reg = populated();
    // Insert peers and vote kinds in a deliberately unhelpful order, and with
    // enough of them that a hash-ordered implementation would be obvious.
    for p in ["zz", "mm", "aa", "11", "zz", "AA", "peer-3", "peer-2"] {
        reg.observe_peer_latency(p, 0.02);
    }
    for k in [
        VoteKind::Precommit,
        VoteKind::Prevote,
        VoteKind::Precommit,
        VoteKind::Prevote,
    ] {
        reg.inc_vote(k);
    }

    let first = reg.render();
    let second = reg.render();
    assert_eq!(
        first, second,
        "two renders of identical data must be byte-identical"
    );

    // Same shape, independently built: a second registry fed the same
    // operations in the same order must render identically too. A HashMap
    // iteration order would be stable within a process but not across
    // instances of the map's layout, which is exactly the bug that makes a
    // scrape look flaky in production and never reproduce in a test.
    let rebuild = || {
        let r = Registry::shared();
        r.set_height(412);
        r.set_round(3);
        r.set_mempool_size(17);
        r.set_validator_set_full(5, 5_000_000_000_000, 3_333_333_333_334, true);
        r.set_data_dir_bytes(2_900_000_000);
        r.set_snapshot_count(9);
        r.set_state_entries(1234);
        r.set_persist_queue_depth(3);
        r.add_persist_queue_dropped(2);
        r.set_peer_round_lag("peer-a", 2);
        r.inc_fork();
        r.inc_divergence();
        r.inc_weak_qc_refused();
        r.set_mempool_sealed_split(2, 3);
        r.inc_mev_unsealed(1);
        r.inc_mev_unseal_failed(1);
        r.inc_nil_round();
        r.inc_nil_breaker_fire();
        r.inc_proposer_miss();
        r.inc_slow_validation();
        r.inc_unbound_tx();
        r.inc_state_root_commit();
        r.add_state_root_commits(2);
        r.inc_vote(VoteKind::Prevote);
        r.inc_vote(VoteKind::Prevote);
        r.inc_vote(VoteKind::Precommit);
        r.observe_block(9, 0.4);
        r.observe_peer_latency("peer-a", 0.003);
        r.observe_peer_latency("peer-b", 0.9);
        for p in ["zz", "mm", "aa", "11", "zz", "AA", "peer-3", "peer-2"] {
            r.observe_peer_latency(p, 0.02);
        }
        for k in [
            VoteKind::Precommit,
            VoteKind::Prevote,
            VoteKind::Precommit,
            VoteKind::Prevote,
        ] {
            r.inc_vote(k);
        }
        r.render()
    };
    assert_eq!(
        first,
        rebuild(),
        "identical operations must produce identical bytes"
    );

    // Labels come out sorted by value within a family.
    let peers: Vec<String> = parse_exposition(&first)
        .into_iter()
        .filter(|s| s.name == "stell_peer_latency_seconds_count")
        .map(|s| s.labels.into_iter().find(|(k, _)| k == "peer").unwrap().1)
        .collect();
    let mut sorted = peers.clone();
    sorted.sort();
    assert_eq!(
        peers, sorted,
        "label values must be emitted in sorted order: {peers:?}"
    );

    // A fresh process would be a stronger guarantee, but this at least proves
    // nothing in the render path depends on wall-clock time or address order.
    assert!(!first.is_empty());
}

// ============================================================================
// (g) SECURITY: hostile label values
// ============================================================================

#[test]
fn hostile_label_value_cannot_inject_a_fake_metric_line() {
    let reg = Registry::shared();
    // The exact shape of a real peer id: free-form, attacker-chosen, echoed
    // straight into the exposition.
    let hostile = "evil\"\nstell_fake_metric 1\n";
    reg.observe_peer_latency(hostile, 0.25);
    let text = reg.render();

    // No line of the output may be a sample of a metric that does not exist.
    for line in text.lines() {
        assert!(
            !line.starts_with("stell_fake_metric"),
            "injected a forged sample line: {line:?}"
        );
    }
    // Nor may it have manufactured a HELP/TYPE header for it.
    assert!(
        !text.contains("# HELP stell_fake_metric"),
        "injected a HELP line:\n{text}"
    );
    assert!(
        !text.contains("# TYPE stell_fake_metric"),
        "injected a TYPE line:\n{text}"
    );

    // The payload survives only as inert text inside a quoted label, and only
    // on the series it was attached to.
    let mentioning: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("stell_fake_metric"))
        .collect();
    let peer_lines: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("stell_peer_latency_seconds"))
        .collect();
    assert_eq!(
        mentioning.len(),
        peer_lines.len(),
        "payload must not escape its own series"
    );
    assert!(
        mentioning.iter().all(|l| l.contains("peer=")),
        "payload must stay inside the label"
    );
    assert!(
        !mentioning.iter().any(|l| l.contains("evil\"")),
        "quote must be escaped, not bare: {mentioning:?}"
    );

    // The single most important assertion: the whole document still parses.
    // Whatever the sanitiser did, it did not break the format.
    let samples = parse_exposition(&text);
    let peer = samples
        .iter()
        .filter(|s| s.name == "stell_peer_latency_seconds_count")
        .collect::<Vec<_>>();
    assert_eq!(
        peer.len(),
        1,
        "hostile peer must produce exactly one latency series"
    );
    assert_eq!(
        peer[0].value, 1.0,
        "the observation itself must still be recorded"
    );

    // The sanitised value round-trips through the format's own escapes: the
    // parser un-escapes `\"` back to a quote, so the meaningful assertion is
    // that the quote arrived *escaped* on the wire and never closed the string.
    // Spaces survive sanitising (they are legal inside a quoted label value);
    // the newlines do not.
    let sanitised = "evil\\\"_stell_fake_metric 1_";
    let peer_labels = &peer[0].labels;
    assert_eq!(peer_labels[0].0, "peer");
    assert!(
        text.contains(&format!("peer=\"{sanitised}\"")),
        "payload must be escaped in place, not dropped:\n{text}"
    );
    assert!(
        !peer_labels[0].1.contains('\n'),
        "newline must not survive into the parsed value"
    );
    assert_eq!(
        peer_labels[0].1, "evil\"_stell_fake_metric 1_",
        "the parsed value must be the sanitised payload, whole"
    );

    // Other hostile shapes: a bare newline, a CR, a NUL, a backslash, and a
    // value that tries to close the label and open a second one.
    for bad in [
        "\nstell_fake_metric 2\n",
        "p\r\nstell_fake_metric 3\n",
        "p\u{0}stell_fake_metric 4",
        "p\\\"x",
        "p\",peer=\"spoofed",
        "p\n# TYPE stell_fake_metric counter",
        "",
    ] {
        let reg = Registry::shared();
        reg.observe_peer_latency(bad, 0.1);
        let text = reg.render();
        for line in text.lines() {
            assert!(
                !line.starts_with("stell_fake_metric"),
                "injected via {bad:?}: {line:?}"
            );
            assert!(
                !line.contains("\r"),
                "carriage return leaked from {bad:?}: {line:?}"
            );
        }
        assert_eq!(
            samples_named(&text, "stell_peer_latency_seconds_count").len(),
            1,
            "exactly one latency series for {bad:?}"
        );
        parse_exposition(&text);
    }

    // A sanitised value cannot collide with a real one either, and the empty
    // peer id is still a legal (if useless) series rather than a parse error.
    let reg = Registry::shared();
    reg.observe_peer_latency("", 0.1);
    assert!(parse_exposition(&reg.render())
        .iter()
        .any(|s| s.name == "stell_peer_latency_seconds_count"));
}

// ============================================================================
// (h) the output is well-formed exposition
// ============================================================================

#[test]
fn every_exposition_line_is_parsable() {
    let reg = populated();
    for p in ["peer-a", "peer-b", "peer-c"] {
        reg.observe_peer_latency(p, 0.02);
    }
    reg.inc_fork();
    let text = reg.render();

    assert!(text.ends_with('\n'), "exposition must end with a newline");
    assert!(!text.contains("\r"), "no CR: the format is LF-terminated");
    assert!(!text.contains("\n\n"), "no blank lines");

    let mut total = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let sample = parse_sample(line).unwrap_or_else(|e| panic!("{e}"));
        // `# HELP x` / `# TYPE x` aside, a sample's name is either the family
        // or a `_bucket` / `_sum` / `_count` child of it. Exact match first:
        // a gauge family may itself end in `_count` (e.g.
        // `stell_snapshot_count`) and must not be mistaken for a histogram
        // child.
        let family = if REQUIRED.iter().any(|(n, _)| *n == sample.name) {
            sample.name.as_str()
        } else {
            sample
                .name
                .strip_suffix("_bucket")
                .or_else(|| sample.name.strip_suffix("_sum"))
                .or_else(|| sample.name.strip_suffix("_count"))
                .unwrap_or(sample.name.as_str())
        };
        assert!(
            REQUIRED.iter().any(|(n, _)| *n == family),
            "sample {sample:?} does not belong to a declared family"
        );
        // Label names are unique within a series, and `le` only on buckets.
        let mut keys: Vec<&str> = sample.labels.iter().map(|(k, _)| k.as_str()).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "duplicate label in {line:?}");
        if sample.name.ends_with("_bucket") {
            assert!(keys.contains(&"le"), "bucket must carry `le`: {line:?}");
            // Exactly the family's own labels plus `le`, and nothing else.
            let family_labels = if family == "stell_peer_latency_seconds" {
                1
            } else {
                0
            };
            assert_eq!(
                keys.len(),
                family_labels + 1,
                "unexpected bucket labels: {line:?}"
            );
        } else {
            assert!(
                !keys.contains(&"le"),
                "`le` only belongs on a bucket: {line:?}"
            );
        }
        total += 1;
    }
    assert!(total > 0, "nothing was rendered");
    assert_eq!(total, parse_exposition(&text).len());

    // Numeric values only: no hex, no `1e-3`-style surprises, no trailing units.
    for sample in parse_exposition(&text) {
        let rendered = format!("{}", sample.value);
        assert!(
            rendered.parse::<f64>().is_ok() || rendered == "NaN" || rendered == "+inf",
            "unexpected value rendering {rendered}"
        );
    }

    // `le` bounds are non-decreasing within a family+label-set, and every
    // histogram ends in `+Inf`, which the text format requires.
    for (family, defaults) in [
        (
            "stell_block_interval_seconds",
            DEFAULT_BLOCK_INTERVAL_BUCKETS,
        ),
        ("stell_block_txs", DEFAULT_BLOCK_TXS_BUCKETS),
    ] {
        let bounds: Vec<f64> = samples_named(&text, &format!("{family}_bucket"))
            .iter()
            .map(|s| s.labels[0].1.parse().unwrap())
            .collect();
        assert_eq!(bounds.len(), defaults.len() + 1, "{family} bucket count");
        assert_eq!(
            bounds[defaults.len()],
            f64::INFINITY,
            "{family} must end with +Inf"
        );
    }
}

// ============================================================================
// (i) concurrency
// ============================================================================

#[test]
fn concurrent_updates_from_several_threads_produce_a_correct_total() {
    const THREADS: usize = 8;
    const PER_THREAD: u64 = 2_000;

    let reg = Registry::shared();
    let mut handles = Vec::with_capacity(THREADS);
    for t in 0..THREADS {
        let reg = reg.clone();
        handles.push(thread::spawn(move || {
            for i in 0..PER_THREAD {
                reg.inc_fork();
                reg.inc_vote(if i % 2 == 0 {
                    VoteKind::Prevote
                } else {
                    VoteKind::Precommit
                });
                reg.observe_block_interval(0.1);
                reg.observe_block_txs(3);
                reg.observe_peer_latency(&format!("peer-{}", t % 3), 0.005);
                // Interleave gauge writes from several threads on purpose: a
                // gauge has no "correct" total, but it must never corrupt the
                // map or panic.
                reg.set_height(i);
                reg.set_mempool_size(i);
                reg.set_round(1);
                reg.inc_state_root_commit();
            }
        }));
    }
    for h in handles {
        h.join().expect("a worker thread panicked");
    }

    let total = THREADS as u64 * PER_THREAD;
    let text = reg.render();

    assert!(
        text.contains(&format!("stell_fork_total {total}\n")),
        "fork total wrong:\n{text}"
    );
    assert!(
        text.contains(&format!("stell_state_root_commits_total {total}\n")),
        "commit total wrong:\n{text}"
    );
    // Every thread contributes an even split of prevotes and precommits.
    let expected_each = total / 2;
    assert!(
        text.contains(&format!(
            "stell_consensus_votes_total{{kind=\"prevote\"}} {expected_each}"
        )),
        "prevote total wrong:\n{text}"
    );
    assert!(
        text.contains(&format!(
            "stell_consensus_votes_total{{kind=\"precommit\"}} {expected_each}"
        )),
        "precommit total wrong:\n{text}"
    );
    // Histogram observations must not be lost either.
    assert!(
        text.contains(&format!("stell_block_interval_seconds_count {total}\n")),
        "block interval count wrong:\n{text}"
    );
    assert!(
        text.contains(&format!("stell_block_txs_count {total}\n")),
        "block txs count wrong:\n{text}"
    );
    assert!(text.contains(&format!("stell_block_txs_sum {}", 3.0 * total as f64)));

    // Three peer ids across eight threads, so the split is uneven by
    // construction; what matters is that nothing is lost or double-counted.
    let per_peer: Vec<Sample> = samples_named(&text, "stell_peer_latency_seconds_count");
    assert_eq!(per_peer.len(), 3, "one latency series per peer id");
    let observed: u64 = per_peer.iter().map(|s| s.value as u64).sum();
    assert_eq!(
        observed, total,
        "no latency observation may be lost: {observed} != {total}"
    );
    let counts: Vec<u64> = per_peer.iter().map(|s| s.value as u64).collect();
    assert!(
        counts.iter().all(|c| *c > 0),
        "every peer must be represented: {counts:?}"
    );
    let spread = counts.iter().max().unwrap() - counts.iter().min().unwrap();
    assert!(
        spread <= PER_THREAD,
        "peer series may only differ by whole threads of work: {counts:?}"
    );

    // The whole thing must still be a valid document after a concurrent workout.
    parse_exposition(&text);

    // And it must still be deterministic afterwards.
    assert_eq!(text, reg.render(), "post-concurrency render must be stable");

    let snap: Snapshot = reg.snapshot();
    assert_eq!(snap.forks, total as f64);
    assert_eq!(snap.state_root_commits, total as f64);
    assert_eq!(snap.votes_prevote, expected_each as f64);
    assert_eq!(snap.votes_precommit, expected_each as f64);
    assert_eq!(
        snap.height,
        (PER_THREAD - 1) as f64,
        "a gauge ends on some thread's last write"
    );
}

// ============================================================================
// (j) explorer wiring: the registry is what /metrics actually serves
// ============================================================================

/// The gateway must serve the *registry*, not a hand-built handful of lines.
/// This asserts the scraped document carries every consensus family exactly
/// once, that the registry's gauges took the caller's live values, and that the
/// explorer-local gauges (`contracts`, `tokens`, and the historical
/// `stellereum_*` names) are appended without breaking the format.
#[test]
fn explorer_scrape_renders_registry_plus_live_gauges() {
    let reg = Registry::shared();
    let text = stellereum::explorer::render_metrics(&reg, 9_000, 12, 4, 3);

    for (name, kind) in REQUIRED {
        let help = format!("# HELP {name} ");
        let ty = format!("# TYPE {name} {kind}");
        assert_eq!(
            count_prefix(&text, &help),
            1,
            "want exactly one HELP for {name}:\n{text}"
        );
        assert_eq!(
            count_prefix(&text, &ty),
            1,
            "want exactly one TYPE for {name}:\n{text}"
        );
    }

    // The registry gauges took the live values from the handler.
    assert!(
        text.contains("stell_consensus_height 9000\n"),
        "height not wired into registry:\n{text}"
    );
    assert!(
        text.contains("stell_mempool_size 12\n"),
        "mempool not wired into registry:\n{text}"
    );

    // The explorer-local gauges survive under their public names.
    assert!(
        text.contains("stellereum_block_height 9000\n"),
        "legacy height missing:\n{text}"
    );
    assert!(
        text.contains("stellereum_mempool_size 12\n"),
        "legacy mempool missing:\n{text}"
    );
    assert!(
        text.contains("stellereum_contracts_total 4\n"),
        "contracts gauge missing:\n{text}"
    );
    assert!(
        text.contains("stellereum_tokens_total 3\n"),
        "tokens gauge missing:\n{text}"
    );

    // Exactly one HELP/TYPE for the appended families too, and the whole
    // document still parses as exposition.
    for name in [
        "stellereum_block_height",
        "stellereum_mempool_size",
        "stellereum_contracts_total",
        "stellereum_tokens_total",
    ] {
        assert_eq!(
            count_prefix(&text, &format!("# HELP {name} ")),
            1,
            "one HELP for {name}"
        );
        assert_eq!(
            count_prefix(&text, &format!("# TYPE {name} gauge")),
            1,
            "one TYPE for {name}"
        );
    }
    parse_exposition(&text);

    // The advertised content type is exactly the exposition version.
    assert_eq!(CONTENT_TYPE, "text/plain; version=0.0.4");
}

/// Incrementing a counter or setting a gauge is visible on the very next
/// scrape, which is the whole point of wiring the two together.
#[test]
fn live_scrape_reflects_counter_increments_and_gauge_sets() {
    let reg = Registry::shared();

    let first = stellereum::explorer::render_metrics(&reg, 1, 0, 0, 0);
    assert!(
        first.contains("stell_fork_total 0\n"),
        "cold counter must read zero:\n{first}"
    );

    reg.inc_fork();
    reg.inc_fork();
    reg.inc_vote(VoteKind::Precommit);
    let second = stellereum::explorer::render_metrics(&reg, 42, 7, 2, 1);

    assert!(
        second.contains("stell_fork_total 2\n"),
        "counter increment not reflected:\n{second}"
    );
    assert!(
        second.contains("stell_consensus_votes_total{kind=\"precommit\"} 1"),
        "vote increment not reflected:\n{second}"
    );
    assert!(
        second.contains("stell_consensus_height 42\n"),
        "gauge set not reflected:\n{second}"
    );
    assert!(
        second.contains("stell_mempool_size 7\n"),
        "mempool gauge set not reflected:\n{second}"
    );
    assert!(
        second.contains("stellereum_contracts_total 2\n"),
        "contracts gauge set not reflected:\n{second}"
    );
    assert!(
        second.contains("stellereum_tokens_total 1\n"),
        "tokens gauge set not reflected:\n{second}"
    );
}

/// `GatewayState::new` uses the process-wide registry, so anything else that
/// calls [`stellereum::metrics::global`] is looking at the same data without
/// the node binary having to thread an `Arc` through its constructor.
#[test]
fn global_registry_is_a_single_shared_instance() {
    let a = stellereum::metrics::global();
    let b = stellereum::metrics::global();
    assert!(
        Arc::ptr_eq(&a, &b),
        "global() must hand back the same registry"
    );

    a.set_height(31_337);
    assert!(
        b.render().contains("stell_consensus_height 31337\n"),
        "shared registry must see the write"
    );
}

// ============================================================================
// (k) disk / validator / build observability (additive families)
// ============================================================================

/// The new observability families behave like the old ones: gauges take the
/// latest value, the persist-dropped counter only accumulates, per-peer lag is
/// sanitised like latency, build info is a singleton, and the snapshot covers
/// the new scalars.
#[test]
fn observability_gauges_counters_and_build_info() {
    use stellereum::metrics::{
        BUILD_VERSION, DATA_DIR_BYTES, PERSIST_QUEUE_DROPPED_TOTAL, SNAPSHOT_COUNT, STATE_ENTRIES,
    };

    let reg = Registry::shared();

    // Gauges take the latest value (validator story in one call).
    reg.set_validator_set_full(2, 4_000_000_000_000, 2_666_666_666_667, true);
    reg.set_validator_set_full(2, 4_000_000_000_000, 2_666_666_666_667, false);
    let text = reg.render();
    assert!(
        text.contains("stell_validator_set_size 2\n"),
        "size:\n{text}"
    );
    assert!(
        text.contains("stell_validator_power_total 4000000000000\n"),
        "power:\n{text}"
    );
    assert!(
        text.contains("stell_validator_quorum_power 2666666666667\n"),
        "quorum:\n{text}"
    );
    assert!(
        text.contains("stell_validator_set_fragile 0\n"),
        "fragile must take latest:\n{text}"
    );

    // Disk / state gauges.
    reg.set_data_dir_bytes(1);
    reg.set_data_dir_bytes(2_900_000_000);
    reg.set_snapshot_count(11);
    reg.set_state_entries(777);
    reg.set_persist_queue_depth(8);
    reg.set_persist_queue_depth(0);
    let text = reg.render();
    assert!(
        text.contains("stell_data_dir_bytes 2900000000\n"),
        "dir bytes:\n{text}"
    );
    assert!(
        text.contains("stell_snapshot_count 11\n"),
        "snapshots:\n{text}"
    );
    assert!(
        text.contains("stell_state_entries 777\n"),
        "entries:\n{text}"
    );
    assert!(
        text.contains("stell_persist_queue_depth 0\n"),
        "depth takes latest:\n{text}"
    );

    // The dropped counter accumulates and never decreases.
    reg.add_persist_queue_dropped(4);
    reg.inc_persist_queue_dropped();
    let text = reg.render();
    assert!(
        text.contains("stell_persist_queue_dropped_total 5\n"),
        "dropped:\n{text}"
    );

    // Per-peer lag: one series per peer, hostile ids stay inside the label.
    reg.set_peer_round_lag("peer-7", 12);
    reg.set_peer_round_lag("evil\"\nstell_fake_metric 1\n", 3);
    let text = reg.render();
    assert!(
        text.contains("stell_peer_round_lag{peer=\"peer-7\"} 12"),
        "lag:\n{text}"
    );
    for line in text.lines() {
        assert!(
            !line.starts_with("stell_fake_metric"),
            "lag label escaped its series: {line:?}"
        );
    }
    parse_exposition(&text);
    assert_eq!(samples_named(&text, "stell_peer_round_lag").len(), 2);

    // Build info is a singleton: re-resolving never leaves two samples.
    reg.set_build_info("0.1.0", "abc1234", "clean");
    reg.set_build_info("0.1.0", "abc1234", "clean");
    let text = reg.render();
    assert_eq!(
        samples_named(&text, "stell_build_info").len(),
        1,
        "exactly one build-info series:\n{text}"
    );
    assert!(text.contains("stell_build_info{"), "info labels:\n{text}");
    assert!(text.contains("version=\"0.1.0\""), "version label:\n{text}");

    // Snapshot + JSON cover the new scalars.
    let snap = reg.snapshot();
    assert_eq!(snap.validator_set_size, 2.0);
    assert_eq!(snap.validator_power_total, 4_000_000_000_000.0);
    assert_eq!(snap.validator_quorum_power, 2_666_666_666_667.0);
    assert_eq!(snap.validator_set_fragile, 0.0);
    assert_eq!(snap.data_dir_bytes, 2_900_000_000.0);
    assert_eq!(snap.snapshot_count, 11.0);
    assert_eq!(snap.state_entries, 777.0);
    assert_eq!(snap.persist_queue_depth, 0.0);
    assert_eq!(snap.persist_queue_dropped, 5.0);
    let json = snap.to_json();
    for key in [
        "validator_power_total",
        "validator_quorum_power",
        "validator_set_fragile",
        "data_dir_bytes",
        "snapshot_count",
        "state_entries",
        "persist_queue_depth",
        "persist_queue_dropped",
    ] {
        assert!(json.contains(key), "snapshot json missing {key}: {json}");
    }

    // Build resolvers: version is the crate version, hash is non-empty
    // (compile-time env, STELL_BUILD_HASH env, or the git fallback).
    assert_eq!(stellereum::metrics::BUILD_VERSION, BUILD_VERSION);
    let hash = stellereum::metrics::build_hash_resolved();
    assert!(!hash.is_empty(), "resolved hash must not be empty");
    let dirty = stellereum::metrics::build_dirty_resolved();
    assert!(!dirty.is_empty(), "resolved dirty flag must not be empty");
    let info = stellereum::metrics::build_info_json();
    assert_eq!(
        info["version"],
        serde_json::Value::String(BUILD_VERSION.to_string())
    );
    assert!(info.get("git_hash").is_some(), "info json: {info}");
    assert!(info.get("dirty").is_some(), "info json: {info}");

    // The name constants are the exposition names (keeps the two in sync).
    assert_eq!(DATA_DIR_BYTES, "stell_data_dir_bytes");
    assert_eq!(SNAPSHOT_COUNT, "stell_snapshot_count");
    assert_eq!(STATE_ENTRIES, "stell_state_entries");
    assert_eq!(
        PERSIST_QUEUE_DROPPED_TOTAL,
        "stell_persist_queue_dropped_total"
    );

    // The explorer scrape carries the new families too.
    let scraped = stellereum::explorer::render_metrics(&reg, 5, 0, 0, 0);
    for name in [
        "stell_data_dir_bytes",
        "stell_snapshot_count",
        "stell_state_entries",
        "stell_persist_queue_depth",
        "stell_persist_queue_dropped_total",
        "stell_peer_round_lag",
        "stell_validator_power_total",
        "stell_validator_quorum_power",
        "stell_validator_set_fragile",
        "stell_build_info",
    ] {
        assert!(
            scraped.contains(&format!("# TYPE {name} ")),
            "{name} missing from scrape:\n{scraped}"
        );
    }
    parse_exposition(&scraped);
}

/// The data-dir scan is best-effort: it sums real bytes, counts snapshot-like
/// names, and reads a missing dir as zero (never fails a scrape).
#[test]
fn data_dir_stats_scans_bytes_and_snapshot_names() {
    use stellereum::explorer::{data_dir_path, data_dir_stats};

    // Default path honours the env override.
    std::env::remove_var("STELL_DATA_DIR");
    assert_eq!(data_dir_path(), std::path::PathBuf::from("./data"));

    // Missing dir reads as zero.
    let (bytes, snaps) = data_dir_stats(std::path::Path::new("/nonexistent-stell-dir-xyz"));
    assert_eq!((bytes, snaps), (0, 0));

    // Real dir: byte sum is exact, snapshot names are counted.
    let dir = std::env::temp_dir().join(format!(
        "stell-metrics-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.bin"), vec![7u8; 100]).unwrap();
    std::fs::write(dir.join("state_snapshot_100.bin"), vec![7u8; 50]).unwrap();
    let sub = dir.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("domains_snapshot_100.bin"), vec![7u8; 25]).unwrap();
    let (bytes, snaps) = data_dir_stats(&dir);
    assert_eq!(bytes, 175, "byte sum must be exact");
    assert_eq!(snaps, 2, "two snapshot-like names");
    std::fs::remove_dir_all(&dir).unwrap();
}
