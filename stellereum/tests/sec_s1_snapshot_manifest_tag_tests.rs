//! SEC-S1 regression: the local (unanchored) SnapV4 assemble/apply paths must
//! reject an out-of-range `unit_tag` with a typed error instead of indexing the
//! fixed-size `[Vec<&SnapshotUnitDesc>; TOTAL_UNIT_TAGS]` grouping array and
//! panicking (index out of bounds).
//!
//! Attack precondition: a `snap_manifests` value in the local store that was
//! corrupted or rewritten outside this API (crash debris, tampered data dir, a
//! future caller that skips `validate_manifest_pre_fetch`). `assemble_base_state`
//! / `apply_delta_state` deliberately do not require the Falcon anchor (they are
//! the disk-reload path), but they must still fail closed — a panic takes down
//! the restore instead of returning `UnknownUnitTag`.

use std::collections::BTreeMap;
use stellereum::snapshot_v4::{
    apply_delta_state, assemble_base_state, compute_units_merkle_root, SnapStateV4, SnapV4Error,
    SnapshotKind, SnapshotManifestV1, SnapshotUnitDesc, SNAP_MANIFEST_MAGIC, SNAP_MANIFEST_VERSION,
    UNIT_ENC_FULL,
};

fn manifest_with_unit_tag(kind: SnapshotKind, unit_tag: u16) -> SnapshotManifestV1 {
    let units = vec![SnapshotUnitDesc {
        unit_tag,
        sub_index: 0,
        encoding: UNIT_ENC_FULL,
        unit_hash: [0x11; 32],
        chunk_hash: [0x22; 32],
        byte_len: 4,
    }];
    SnapshotManifestV1 {
        magic: SNAP_MANIFEST_MAGIC,
        version: SNAP_MANIFEST_VERSION,
        chain_id: 1,
        shard_id: 0,
        kind,
        target_height: 1,
        target_block_hash: [0u8; 32],
        target_state_root: [0u8; 32],
        validator_set_hash: [0u8; 32],
        total_wire_bytes: 4,
        total_uncompressed_bytes: 4,
        units_merkle_root: compute_units_merkle_root(&units),
        units,
        publisher_id: [0u8; 32],
        publisher_sig: Vec::new(),
    }
}

#[tokio::test]
async fn apply_delta_state_rejects_unknown_unit_tag_without_panicking() {
    // 273 is the first tag past the canonical taxonomy (0..=272).
    let manifest = manifest_with_unit_tag(
        SnapshotKind::Delta {
            base_height: 0,
            base_state_root: [0u8; 32],
        },
        273,
    );
    let chunks: BTreeMap<(u16, u16), Vec<u8>> = BTreeMap::new();
    let base = SnapStateV4::default();
    let err = apply_delta_state(&base, 0, [0u8; 32], &manifest, &chunks)
        .await
        .expect_err("out-of-range unit_tag must be a typed error, not a panic");
    assert_eq!(err, SnapV4Error::UnknownUnitTag(273));
}

#[tokio::test]
async fn assemble_base_state_rejects_unknown_unit_tag_without_panicking() {
    // A hostile u16 well past the array length (TOTAL_UNIT_TAGS == 273).
    let manifest = manifest_with_unit_tag(SnapshotKind::Base, u16::MAX);
    let chunks: BTreeMap<(u16, u16), Vec<u8>> = BTreeMap::new();
    let err = assemble_base_state(&manifest, &chunks)
        .await
        .expect_err("out-of-range unit_tag must be a typed error, not a panic");
    assert_eq!(err, SnapV4Error::UnknownUnitTag(u16::MAX));
}
