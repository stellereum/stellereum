//! Genesis-guard message tests (fail-closed text only).
//!
//! Pins [`stellereum::bootstrap::genesis_mismatch_msg`]: both roots appear
//! (16-hex-char prefixes), the shard is named when given, and the hint names
//! the usual suspects plus the wipe path. Comparison semantics live in
//! `src/main.rs` and are unchanged — this only pins the refusal text.

use stellereum::bootstrap::genesis_mismatch_msg;

fn prefix16(raw: &[u8]) -> String {
    let full = hex::encode(raw);
    full[..16].to_string()
}

#[test]
fn shard_message_contains_both_roots_names_shard_and_hints() {
    let expected = [0xABu8; 32];
    let found = vec![0xCDu8; 32];
    let msg = genesis_mismatch_msg(Some(1), &expected, &found);
    assert!(
        msg.contains(&prefix16(&expected)),
        "must show expected root: {msg}"
    );
    assert!(
        msg.contains(&prefix16(&found)),
        "must show stored root: {msg}"
    );
    assert!(msg.contains("shard 1"), "must name the shard: {msg}");
    assert!(
        msg.contains("STELL_FAUCET_KEY"),
        "must name the faucet key suspect: {msg}"
    );
    assert!(
        msg.contains("./data"),
        "must name the wipe path: {msg}"
    );
}

#[test]
fn datadir_message_names_suspects_without_shard() {
    let expected = [0x11u8; 32];
    let found = vec![0x22u8; 32];
    let msg = genesis_mismatch_msg(None, &expected, &found);
    assert!(
        msg.contains(&prefix16(&expected)),
        "must show expected root: {msg}"
    );
    assert!(
        msg.contains(&prefix16(&found)),
        "must show stored root: {msg}"
    );
    assert!(
        msg.contains("data directory"),
        "datadir scope must be named: {msg}"
    );
    assert!(
        !msg.contains("shard 0"),
        "datadir message must not name a shard: {msg}"
    );
    // GATE (LEAD a: STELL_LEGACY_GENESIS_ROOT removed): the suspect list no
    // longer names the deleted escape hatch; every remaining suspect is
    // still pinned (no assert weakened, one entry removed).
    for suspect in ["STELL_FAUCET_KEY", "validators:", "STELL_SHARDS"] {
        assert!(msg.contains(suspect), "must name {suspect}: {msg}");
    }
    assert!(msg.contains("./data"), "must name the wipe path: {msg}");
}

#[test]
fn shard_message_names_all_suspects_too() {
    let expected = [0x01u8; 32];
    let found = vec![0x02u8; 32];
    let msg = genesis_mismatch_msg(Some(0), &expected, &found);
    // GATE (LEAD a: STELL_LEGACY_GENESIS_ROOT removed — see above).
    for suspect in ["STELL_FAUCET_KEY", "validators:", "STELL_SHARDS"] {
        assert!(msg.contains(suspect), "must name {suspect}: {msg}");
    }
    assert!(msg.contains("shard 0"), "must name shard 0: {msg}");
    assert!(msg.contains("./data"), "must name the wipe path: {msg}");
}
