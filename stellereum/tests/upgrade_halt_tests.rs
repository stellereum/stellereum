//! Software-upgrade halt: drained exit, durable marker, startup refusal and
//! frame-version negotiation.
//!
//! These tests exercise the REAL logic in `src/node/upgrade_halt.rs` (included
//! by path, the `liveness_alarm.rs`/`hashpool.rs` precedent) and the REAL
//! `infnode::proto` helpers, not copies. They pin the four properties
//! `docs/UPGRADE_AND_RECOVERY.md` §1.2.3/§1.2.4/§1.3 call out:
//!
//! 1. the halt DRAINS the persistence queue before exiting (bounded by a cap);
//! 2. the halt marker is durable and read back exactly;
//! 3. a stale marker + the wrong binary REFUSES consensus (loud), while the
//!    right binary clears it and joins;
//! 4. frame versions negotiate as a range and a mismatch is diagnosable.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use infnode::proto::{
    frame_version_mismatch_line, negotiate_frame_version, report_frame_version_mismatch, Frame,
    FRAME_VERSION, FRAME_VERSION_MAX, FRAME_VERSION_MIN,
};

#[path = "../src/node/upgrade_halt.rs"]
#[allow(dead_code)]
mod upgrade_halt;

use upgrade_halt::{
    clear_marker, drain_for_halt, guard_upgrade_halt, marker_path, marker_satisfied_by,
    normalize_version, preview_halt_decision, read_marker, running_exe_sha256, running_version,
    write_marker, HaltDecision, UpgradeHaltMarker, MARKER_FILE_NAME, MARKER_HEADER,
    MARKER_PATH_ENV, RUNNING_VERSION_ENV,
};

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn temp_marker_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "stell-upgrade-halt-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn sample_marker() -> UpgradeHaltMarker {
    UpgradeHaltMarker {
        height: 1200,
        halted_at_height: 1200,
        plan_name: "v0.2.0".to_string(),
        plan_sha256: [0xab; 32],
        target_version: "v0.2.0".to_string(),
        running_version: "0.1.0".to_string(),
        halted_unix: 1_763_500_000,
    }
}

fn fast_drain_cfg(cap: Duration) -> stellereum::storage::ShutdownDrainConfig {
    stellereum::storage::ShutdownDrainConfig {
        cap,
        poll: Duration::from_millis(5),
        log_every: Duration::from_millis(200),
        settle_grace: Duration::from_millis(10),
    }
}

// ---------------------------------------------------------------------------
// 1. drain-before-exit, with a fake persistence queue
// ---------------------------------------------------------------------------

/// The halt lane must AWAIT the queue: a depth that a fake writer drains to
/// zero has to be observed as drained, with the settle grace included.
#[tokio::test]
async fn halt_drain_waits_for_the_fake_persistence_queue() {
    let depth = Arc::new(AtomicU64::new(3));
    let writer = depth.clone();
    tokio::spawn(async move {
        while writer.load(Ordering::Relaxed) > 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            writer.fetch_sub(1, Ordering::Relaxed);
        }
    });
    let out = drain_for_halt(
        || depth.load(Ordering::Relaxed),
        fast_drain_cfg(Duration::from_secs(5)),
    )
    .await;
    assert!(out.drained, "the fake writer drained; the halt must see it");
    assert_eq!(out.last_pending, 0);
    assert_eq!(depth.load(Ordering::Relaxed), 0);
}

/// A wedged disk must never hang the halt: the cap fires and the caller still
/// exits (the old `exit(42)` did not even have a cap because it did not wait).
#[tokio::test]
async fn halt_drain_is_bounded_on_a_wedged_queue() {
    let started = Instant::now();
    let out = drain_for_halt(|| 7u64, fast_drain_cfg(Duration::from_millis(50))).await;
    assert!(
        !out.drained,
        "a queue that never empties must not report drained"
    );
    assert_eq!(out.last_pending, 7);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the halt drain must return at its cap, not hang"
    );
}

// ---------------------------------------------------------------------------
// 2. the marker: exact format + durable round trip
// ---------------------------------------------------------------------------

#[test]
fn marker_format_is_versioned_and_exact() {
    let marker = sample_marker();
    let expected = format!(
        "stell-upgrade-halt v1\n\
         height=1200\n\
         halted_at_height=1200\n\
         plan_name=v0.2.0\n\
         plan_sha256={}\n\
         target_version=v0.2.0\n\
         running_version=0.1.0\n\
         halted_unix=1763500000\n",
        "ab".repeat(32)
    );
    assert_eq!(marker.render(), expected);
    assert_eq!(
        UpgradeHaltMarker::parse(&expected).expect("parse the rendered marker"),
        marker
    );
    assert_eq!(MARKER_HEADER, "stell-upgrade-halt v1");
}

#[test]
fn marker_write_read_clear_roundtrip() {
    let dir = temp_marker_dir("roundtrip");
    let path = dir.join(MARKER_FILE_NAME);
    let marker = sample_marker();

    write_marker(&path, &marker).expect("write marker");
    assert_eq!(read_marker(&path).expect("read marker"), Some(marker));
    // Atomic write: the temp sibling is renamed, never left behind.
    assert!(!path.with_extension("tmp").exists());
    // The bytes on disk are the documented text format.
    assert_eq!(
        std::fs::read_to_string(&path).expect("read text"),
        sample_marker().render()
    );

    assert!(clear_marker(&path).expect("clear marker"));
    assert_eq!(read_marker(&path).expect("read cleared"), None);
    assert!(!clear_marker(&path).expect("clearing an absent marker is not an error"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn marker_parse_fails_closed() {
    let good = sample_marker().render();

    let bad_header = good.replacen(MARKER_HEADER, "stell-upgrade-halt v2", 1);
    assert!(
        UpgradeHaltMarker::parse(&bad_header).is_err(),
        "a marker from a newer format must be refused, not misread"
    );

    let no_height: String = good
        .lines()
        .filter(|line| !line.starts_with("height="))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(UpgradeHaltMarker::parse(&no_height).is_err());

    let bad_hex = good.replacen(&"ab".repeat(32), "zz", 1);
    assert!(UpgradeHaltMarker::parse(&bad_hex).is_err());

    let short_hex = good.replacen(&"ab".repeat(32), "abab", 1);
    assert!(UpgradeHaltMarker::parse(&short_hex).is_err());
}

// ---------------------------------------------------------------------------
// 3. startup: refuse on stale marker + wrong binary; accept + clear otherwise
// ---------------------------------------------------------------------------

#[test]
fn startup_refuses_stale_marker_with_wrong_version() {
    let dir = temp_marker_dir("refuse");
    let path = dir.join(MARKER_FILE_NAME);
    let marker = sample_marker();
    write_marker(&path, &marker).expect("write marker");

    // finalized == halt height: "at or below the current finalized height"
    // fires the guard (the halt height itself is already past).
    let decision = guard_upgrade_halt(&path, || Ok(Some(marker.height)), "0.1.0", || None);
    let message = match decision {
        HaltDecision::Refuse { message } => message,
        other => panic!("expected Refuse, got {other:?}"),
    };
    assert!(
        message.contains("REFUSING TO START CONSENSUS"),
        "refusal must be loud: {message}"
    );
    assert!(
        message.contains(&path.display().to_string()),
        "refusal must name the marker file: {message}"
    );
    assert!(
        message.contains("expected target version: 'v0.2.0'"),
        "refusal must name the expected version: {message}"
    );
    assert!(
        message.contains("running binary version:  '0.1.0'"),
        "refusal must name what this binary reports: {message}"
    );
    assert!(
        message.contains("STELL_UPGRADE_VERSION=v0.2.0"),
        "refusal must be actionable: {message}"
    );
    // The marker SURVIVES a refusal — the operator fixes the binary.
    assert_eq!(read_marker(&path).expect("read marker"), Some(marker));

    // A node far past the halt height refuses just the same.
    assert!(matches!(
        guard_upgrade_halt(&path, || Ok(Some(50_000)), "0.1.0", || None),
        HaltDecision::Refuse { .. }
    ));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn startup_clears_marker_when_binary_reports_target_version() {
    let dir = temp_marker_dir("clear");
    let path = dir.join(MARKER_FILE_NAME);
    let marker = sample_marker();
    write_marker(&path, &marker).expect("write marker");

    // Version string match (leading `v` is normalized).
    let decision = guard_upgrade_halt(&path, || Ok(Some(marker.height + 40)), "v0.2.0", || None);
    match decision {
        HaltDecision::Cleared { marker: cleared } => assert_eq!(cleared, marker),
        other => panic!("expected Cleared, got {other:?}"),
    }
    assert_eq!(read_marker(&path).expect("read cleared"), None);

    // Executable-digest match: a rebuilt binary may report a different
    // version but proves identity with the plan's sha256.
    let mut rebuilt = sample_marker();
    rebuilt.target_version = "2026-10-20-hotfix".to_string();
    write_marker(&path, &rebuilt).expect("write marker");
    assert!(matches!(
        guard_upgrade_halt(&path, || Ok(Some(9_999)), "0.1.0", || Some([0xab; 32])),
        HaltDecision::Cleared { .. }
    ));
    assert_eq!(read_marker(&path).expect("read cleared"), None);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn marker_below_finalized_is_pending_not_fired() {
    let dir = temp_marker_dir("pending");
    let path = dir.join(MARKER_FILE_NAME);
    let marker = sample_marker();
    write_marker(&path, &marker).expect("write marker");

    let decision = guard_upgrade_halt(&path, || Ok(Some(marker.height - 1)), "0.1.0", || None);
    match decision {
        HaltDecision::Pending { marker: pending } => assert_eq!(pending.height, 1200),
        other => panic!("expected Pending, got {other:?}"),
    }
    // Not yet reached: the marker stays, the halt fires at the height.
    assert_eq!(read_marker(&path).expect("read marker"), Some(marker));
    std::fs::remove_dir_all(&dir).ok();
}

/// The applied state can be AHEAD of the async finalized metadata (the
/// walk/apply lane advances state first; the finalize pointer lands later).
/// The boot guard must classify by the higher of the two, or a node that
/// already crossed the halt height rejoins consensus with the OLD binary.
///
/// Failing before the fix: `latest_state_height()` did not exist, and the
/// production call site read only `finalized()` — which this fixture sets to
/// `H-1`, yielding `Pending` right here.
#[test]
fn guard_uses_applied_state_height_when_state_is_ahead_of_finalized() {
    let dir = temp_marker_dir("stateahead");
    let path = dir.join(MARKER_FILE_NAME);
    let store = stellereum::storage::Storage::open(&dir.join("store")).expect("open store");
    let halt_height = 1200u64;

    // Metadata says below the halt height, applied state says past it.
    store
        .set_finalized(halt_height - 1, &[0x11; 32])
        .expect("set finalized");
    store
        .put_state(halt_height + 5, b"applied-state-ahead")
        .expect("put state");
    assert_eq!(
        store.latest_state_height().expect("read state height"),
        Some(halt_height + 5),
        "key-only state height must see the applied snapshot"
    );

    let marker = sample_marker();
    write_marker(&path, &marker).expect("write marker");

    // Pre-fix predicate (finalized metadata only): Pending, i.e. the old
    // binary would be allowed to rejoin and vote past the halt height.
    let finalized_only = guard_upgrade_halt(&path, || Ok(Some(halt_height - 1)), "0.1.0", || None);
    assert!(
        matches!(finalized_only, HaltDecision::Pending { .. }),
        "the metadata-only comparison is exactly the defect: {finalized_only:?}"
    );

    // Production predicate: max(finalized, latest_state_height).
    let decision = guard_upgrade_halt(
        &path,
        || {
            let finalized = store
                .finalized()
                .map_err(|e| e.to_string())?
                .map(|(h, _)| h);
            let applied = store.latest_state_height().map_err(|e| e.to_string())?;
            Ok(finalized.max(applied))
        },
        "0.1.0",
        || None,
    );
    match decision {
        HaltDecision::Refuse { message } => {
            assert!(
                message.contains("REFUSING TO START CONSENSUS"),
                "must refuse, loudly: {message}"
            );
            assert!(
                message.contains("finalized head 1205"),
                "refusal must report the applied-height evidence: {message}"
            );
        }
        other => panic!("state at H+5 with a halt marker at H must refuse, got {other:?}"),
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn no_marker_proceeds_without_reading_the_store() {
    let dir = temp_marker_dir("nomarker");
    let path = dir.join(MARKER_FILE_NAME);
    let called = std::cell::Cell::new(false);
    let decision = guard_upgrade_halt(
        &path,
        || {
            called.set(true);
            Ok(Some(999))
        },
        "0.1.0",
        || None,
    );
    assert_eq!(decision, HaltDecision::Proceed);
    assert!(
        !called.get(),
        "a node without a marker must not pay a store read on startup"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn guard_refuses_when_finalized_head_cannot_be_read() {
    let dir = temp_marker_dir("unreadablehead");
    let path = dir.join(MARKER_FILE_NAME);
    write_marker(&path, &sample_marker()).expect("write marker");

    let decision = guard_upgrade_halt(&path, || Err("store locked".to_string()), "0.1.0", || None);
    match decision {
        HaltDecision::Refuse { message } => {
            assert!(message.contains("could not be read"), "{message}");
            assert!(message.contains("store locked"), "{message}");
            assert!(message.contains(&path.display().to_string()), "{message}");
        }
        other => panic!("expected Refuse, got {other:?}"),
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn corrupt_marker_refuses_instead_of_being_ignored() {
    let dir = temp_marker_dir("corrupt");
    let path = dir.join(MARKER_FILE_NAME);
    std::fs::write(&path, "not a marker\n").expect("write garbage");

    match guard_upgrade_halt(&path, || Ok(Some(10)), "0.1.0", || None) {
        HaltDecision::Refuse { message } => {
            assert!(message.contains("cannot be read"), "{message}");
            assert!(message.contains(&path.display().to_string()), "{message}");
        }
        other => panic!("expected Refuse, got {other:?}"),
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// The values the guard feeds into the marker: the default path is next to the
/// store, and the binary reports a non-empty version plus (on Linux) a stable
/// executable digest. All three are overridable only by documented env vars.
#[test]
fn binary_identity_and_default_marker_path_are_live() {
    if std::env::var(MARKER_PATH_ENV).is_err() {
        assert_eq!(
            marker_path(),
            PathBuf::from("./data").join(MARKER_FILE_NAME),
            "default marker path must sit next to the store"
        );
    }

    let reported = running_version();
    assert!(!reported.is_empty(), "a binary must report some version");
    match std::env::var(RUNNING_VERSION_ENV) {
        Ok(v) if !v.trim().is_empty() => assert_eq!(reported, v.trim()),
        _ => assert_eq!(reported, env!("CARGO_PKG_VERSION")),
    }

    #[cfg(target_os = "linux")]
    {
        let sha = running_exe_sha256().expect("Linux exposes /proc/self/exe");
        assert_eq!(
            Some(sha),
            running_exe_sha256(),
            "the executable digest must be stable within a process"
        );
        assert_ne!(sha, [0u8; 32]);
    }

    assert_eq!(normalize_version("v1.2.3"), normalize_version(" 1.2.3 "));
    assert_eq!(normalize_version("V1.2.3"), "1.2.3");
    assert_ne!(normalize_version("1.2.3"), normalize_version("1.2.4"));
}

#[test]
fn preview_is_read_only_and_matches_the_startup_refusal() {
    let dir = temp_marker_dir("preview");
    let path = dir.join(MARKER_FILE_NAME);
    let marker = sample_marker();
    write_marker(&path, &marker).expect("write marker");

    // The status preview must produce the SAME decision text the guard emits...
    let preview = preview_halt_decision(&path, marker.height, "0.1.0", None);
    let guard = guard_upgrade_halt(&path, || Ok(Some(marker.height)), "0.1.0", || None);
    assert_eq!(
        preview, guard,
        "the CLI preview must not drift from the guard"
    );
    // ...and must NOT mutate the data directory.
    assert_eq!(
        read_marker(&path).expect("read marker"),
        Some(marker.clone())
    );

    // A satisfied preview reports `Cleared` but leaves the file for the real
    // startup guard to remove.
    assert!(matches!(
        preview_halt_decision(&path, marker.height, "v0.2.0", None),
        HaltDecision::Cleared { .. }
    ));
    assert_eq!(read_marker(&path).expect("read marker"), Some(marker));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn satisfaction_truth_table() {
    let marker = sample_marker();
    // Same version, leading `v` normalized either way.
    assert!(marker_satisfied_by(&marker, "v0.2.0", None));
    assert!(marker_satisfied_by(&marker, "V0.2.0", None));
    // Wrong version, no digest.
    assert!(!marker_satisfied_by(&marker, "0.1.0", None));
    // Wrong version but the plan digest matches: satisfied.
    assert!(marker_satisfied_by(&marker, "0.1.0", Some([0xab; 32])));
    // Wrong version and a different digest: refused.
    assert!(!marker_satisfied_by(&marker, "0.1.0", Some([0xcd; 32])));
}

// ---------------------------------------------------------------------------
// 4. source pins: the halt lane's ORDER must not regress
// ---------------------------------------------------------------------------

/// Regression pin for the two holes this work closes, checked against the real
/// sources (the `heal_fail_closed_tests.rs` `include_str!` precedent):
///
/// * the trigger is the PREDICATE `height >= plan.height`, not the `==` event
///   that a restarted/offline node never fires;
/// * the halt lane drains the persistence queue and writes the durable marker
///   BEFORE `exit(42)` (the old code exited without any wait);
/// * startup consults the marker guard before joining consensus;
/// * the decoder reports a frame-version mismatch through the negotiation
///   helper.
#[test]
fn halt_lane_drains_writes_marker_then_exits() {
    let driver = include_str!("../src/node/consensus_driver.rs");
    let bootstrap = include_str!("../src/node/bootstrap.rs");
    let proto = include_str!("../../infnode/crates/infnode/src/proto.rs");

    assert!(
        driver.contains("if plan.height <= height {"),
        "the halt trigger must be `height >= plan.height` (missed-event safety)"
    );
    assert!(
        !driver.contains("if plan.height == height {"),
        "the `==` event trigger silently skips offline/restarted nodes"
    );

    let halt = driver
        .find("UPGRADE TRIGGERED at height")
        .expect("halt lane present");
    let drain = driver
        .find("drain_for_halt")
        .expect("halt lane must await the persistence drain");
    let marker = driver
        .find("UpgradeHaltMarker {")
        .expect("halt lane must write the durable marker");
    let exit = driver
        .find("std::process::exit(42);")
        .expect("halt must exit 42");
    assert!(
        halt < drain && drain < marker && marker < exit,
        "order must be trigger -> drain -> marker -> exit(42)"
    );

    assert!(
        bootstrap.contains("guard_upgrade_halt("),
        "startup must consult the upgrade-halt marker before joining consensus"
    );
    assert!(
        bootstrap.contains("latest_state_height()"),
        "the boot guard must compare against applied state, not finalized metadata alone \
         (a node whose state crossed the halt height ahead of its finalized pointer must \
         still refuse the old binary)"
    );
    assert!(
        proto.contains("if b[0] != FRAME_VERSION {")
            && proto.contains("report_frame_version_mismatch(b[0]);"),
        "the frame decoder must report a version mismatch through the negotiation helper"
    );
}

// ---------------------------------------------------------------------------
// 5. frame-version negotiation (infnode::proto)
// ---------------------------------------------------------------------------

#[test]
fn frame_version_negotiation_matrix() {
    let ours = u32::from(FRAME_VERSION);
    assert_eq!(
        (FRAME_VERSION_MIN, FRAME_VERSION_MAX),
        (ours, ours),
        "this build speaks exactly one wire version (FULL-PQ flag day)"
    );

    // same
    assert_eq!(negotiate_frame_version(ours, ours), Some(ours));
    // older peer, disjoint from our range (v1 classical trailer)
    assert_eq!(negotiate_frame_version(1, 1), None);
    // older peer whose range spans ours: highest common version wins
    assert_eq!(negotiate_frame_version(1, ours), Some(ours));
    // newer peer, disjoint
    assert_eq!(negotiate_frame_version(ours + 1, ours + 1), None);
    // newer peer whose range starts at ours
    assert_eq!(negotiate_frame_version(ours, ours + 4), Some(ours));
    // disjoint ranges on both sides
    assert_eq!(negotiate_frame_version(7, 9), None);
    // inverted range is failed closed
    assert_eq!(negotiate_frame_version(9, 7), None);
}

#[test]
fn frame_version_mismatch_line_names_both_sides() {
    let line = frame_version_mismatch_line(1);
    assert!(
        line.contains("peer speaks v1, we speak v2"),
        "the operator line must name both sides: {line}"
    );
    assert!(
        line.contains("coordinated upgrade required"),
        "the operator line must state the action: {line}"
    );
    assert!(
        line.contains("common version: none"),
        "v1 is outside the supported range: {line}"
    );
    // The reporter returns the same text (stderr printing happens once).
    assert_eq!(report_frame_version_mismatch(1), line);

    // The decoder still refuses the frame with its stable error string.
    let frame = Frame {
        kind: infnode::proto::kind::REQ,
        seq: 0,
        ts: 0,
        src: [1u8; infnode::proto::NODEID_LEN],
        dst: [2u8; infnode::proto::NODEID_LEN],
        svc: 0,
        payload: b"x".to_vec(),
        nonce: vec![0u8; 4],
        sig: Vec::new(),
    };
    let mut bytes = frame.encode();
    bytes[0] = 1;
    let err = Frame::decode(&bytes)
        .expect_err("a v1 frame must be refused")
        .to_string();
    assert!(
        err.contains("unsupported version"),
        "decode error string is pinned: {err}"
    );
}
