//! Block sync: bring a lagging node up to a peer's head by walking the chain
//! backwards via `prev_hash`, then applying the missing blocks ancestor-first.
//!
//! This is the building block for catch-up: a fresh or briefly-offline node
//! asks the network for the head block, follows parent links back to its own
//! last finalized hash, and replays the gap. The walk is guarded against cycles,
//! unbounded length and missing parents (fail-closed).
//!
//! # LIGHT CLIENT ANCHOR (audit W8.3 / production blocker A10)
//!
//! A peer chain used to be accepted on the strength of the peer's own say-so
//! plus a per-block quorum check. The node now ALSO runs every peer-supplied
//! block through its [`crate::light_client::LightClient`], which is anchored
//! at the node's OWN finalized head — the header that carries the precommit
//! quorum certificate that decided it. A peer chain is accepted only if it
//! extends that anchor:
//!
//! * it continues the anchor's chain (height + 1, hash linkage),
//! * every block carries a precommit quorum certificate that verifies under
//!   the node's committed validator set,
//! * it does not roll the state root back to a root an earlier finalized
//!   header already superseded, and
//! * it fits the bounded header window.
//!
//! The trusted root the light client ends up holding is the root a QUORUM
//! committed to — not a root the peer asserted.

use crate::sharding::Block;
use std::collections::HashSet;

/// Verify peer-supplied blocks against the node's TRUSTED anchor, using the
/// light client's machinery.
///
/// The anchor is the light client's checkpoint: the node's own finalized head,
/// carrying the precommit quorum certificate that decided it (or the chain's
/// genesis anchor, when the node has not finalized anything yet). Every block
/// in `blocks` is turned into a [`crate::light_client::LightHeader`] and
/// applied to a CLONE of the client, so the caller's live client is untouched
/// and the check is a pure function of (anchor, blocks).
///
/// Returns the state root the chain commits to at the last block's height —
/// the root a quorum vouched for. The caller compares it with the root the
/// node computes by applying the blocks; a mismatch means the peer and the
/// node disagree about the state, and the chain is refused.
///
/// Fails closed (never skips) on: a gap in the heights, a broken parent link,
/// a missing or non-precommit certificate, a certificate that does not reach a
/// quorum of real validator power, a state-root rollback, and a full header
/// window.
pub fn verify_synced_blocks_against_anchor(
    light: &crate::light_client::LightClient,
    blocks: &[Block],
) -> Result<crate::cell::CellHash, String> {
    // Backward-compatible entry: every header is checked against the client's
    // pinned set. Live callers MUST use
    // `verify_synced_blocks_against_anchor_with_sets` so each header's QC is
    // checked against the set in force at ITS height.
    verify_synced_blocks_against_anchor_with_sets(light, blocks, &|_| None)
}

/// W10.5 activation-boundary anchor check: like
/// [`verify_synced_blocks_against_anchor`], but the probe light client
/// verifies each header's QC against `resolve_set(height)` — the set in force
/// at that header's height — instead of the client's pinned set. A height the
/// resolver cannot name falls back to the pinned set (the pre-change set the
/// anchor was built on, which is the conservative direction for recent
/// windows; ancient windows are snapshot-gated, not walked here).
pub fn verify_synced_blocks_against_anchor_with_sets(
    light: &crate::light_client::LightClient,
    blocks: &[Block],
    resolve_set: &dyn Fn(u64) -> Option<crate::consensus::ValidatorSet>,
) -> Result<crate::cell::CellHash, String> {
    if blocks.is_empty() {
        return Err("block sync: empty chain against the light-client anchor".to_string());
    }
    // The clone is the probe: the live client keeps its own window.
    let mut probe = light.clone();
    for b in blocks {
        // W10.5: verify this header against the set in force at ITS height.
        // The pinned set is the fallback for heights the resolver cannot
        // name (pre-change history older than this process).
        if let Some(set) = resolve_set(b.height) {
            probe.validators = set;
        }
        let header = crate::light_client::LightHeader::of_block(b).ok_or_else(|| {
            format!(
                "block sync: block {} carries no precommit quorum certificate; \
                 there is nothing to anchor on",
                b.height
            )
        })?;
        // Finality-only: walked bodies carry just the proposer's block
        // signature (votes never sign the block hash), so the strict
        // block-signature quorum would refuse every legitimate tail block
        // (live 2026-10-25). The precommit QC — verified under the set in
        // force at this height — is the trust; body validity rides with the
        // body path that calls this probe.
        probe
            .apply_header_without_block_signatures(header)
            .map_err(|e| {
                format!(
                    "block sync: block {} does not extend the trusted anchor: {e}",
                    b.height
                )
            })?;
    }
    Ok(probe.state_root())
}

/// The genesis anchor of this chain, for a light client that has not seen a
/// quorum-certified header yet.
///
/// The height-1 block links to the ZERO prev-hash sentinel (the genesis block
/// is not part of the hash chain — `runtime::ValidatorRuntime::propose` uses
/// the sentinel when nothing is finalized yet), so that sentinel is what the
/// anchor names. The genesis STATE ROOT is the one the node built its own
/// genesis from, so it is trusted by construction.
pub fn genesis_light_anchor(
    genesis_root: crate::cell::CellHash,
) -> crate::light_client::GenesisAnchor {
    crate::light_client::GenesisAnchor {
        height: 0,
        block_hash: [0u8; 32],
        parent_hash: [0u8; 32],
        state_root: genesis_root,
    }
}

/// Walk from `head` back to `last_finalized` (exclusive) and return the missing
/// blocks in ANCESTOR-FIRST order (ready to apply sequentially).
///
/// `fetch` resolves a block hash to a block (e.g. `adapter.fetch_block`).
/// Errors on a cycle, a missing parent, or a chain longer than `max_len`.
pub async fn collect_missing_blocks<F, Fut>(
    head: [u8; 32],
    last_finalized: [u8; 32],
    max_len: usize,
    mut fetch: F,
) -> Result<Vec<Block>, String>
where
    F: FnMut([u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Option<Block>>,
{
    let mut chain: Vec<Block> = Vec::new();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut cur = head;
    loop {
        if cur == last_finalized {
            break;
        }
        if chain.len() >= max_len {
            return Err("block sync: chain longer than max_len".to_string());
        }
        if !seen.insert(cur) {
            return Err("block sync: cycle detected".to_string());
        }
        let mut blk = fetch(cur)
            .await
            .ok_or_else(|| format!("block sync: missing block {}", hex::encode(cur)))?;
        // Yield per height: on a 1-vCPU node a long walk of slow (2.5s-RTT)
        // fetches must not starve consensus traffic queued behind this task.
        // Zero cost when idle; one scheduler pass per height when loaded.
        tokio::task::yield_now().await;
        // F3(a): the body we were handed MUST hash to the hash we asked for. A
        // source (buggy fetch, poisoned DHT entry, malicious peer) that serves a
        // different body under this key would otherwise have its `prev_hash`
        // followed and re-anchor us onto a chain we never requested. Reject at
        // the fetch boundary, before anything is applied.
        if blk.compute_hash() != cur {
            return Err(format!(
                "block sync: fetched body at height {} does not hash to the requested {} \
                 (mismatched block rejected)",
                blk.height,
                hex::encode(cur)
            ));
        }
        // XSHARD INTEGRITY at the adoption boundary (fail-closed): every
        // carried cross-shard message must carry its construction-time id —
        // recomputed here (domain-aware) from (source, target, tx hash,
        // finalizing block) — and no adopted message may arrive `trusted`.
        // A forged `msg_id` rebinds a valid proof to a different body; a set
        // `trusted` bit would bypass the inclusion proof at trusted-honoring
        // call sites. A forged id refuses the whole block; the flag is
        // cleared so no downstream path can observe wire-set trust.
        for m in blk.cross_shard_out.iter_mut() {
            if !m.verify_msg_id() {
                return Err(format!(
                    "block sync: block {} carries a cross-shard message with a forged msg_id \
                     (recomputed id mismatch; refusing the block)",
                    blk.height
                ));
            }
            m.trusted = false;
        }
        let prev = blk.prev_hash;
        chain.push(blk);
        cur = prev;
    }
    chain.reverse();
    Ok(chain)
}

/// One published block HEADER, reduced to the fields the snapshot anchor needs.
///
/// The snapshot path trusts `state_root` from a header a peer published. That is
/// only sound if the header is part of OUR chain, which is proven by hash
/// linkage: each header must name the previous header's hash as its parent. This
/// is the shape `P2pNetworkAdapter::fetch_block_header` returns, mapped to the
/// linkage fields plus the committed root.
///
/// A1: linkage alone is NOT enough (an attacker links a fully forged chain).
/// Each link therefore also carries the height's precommit QC plus the
/// proposer the deterministic schedule names, and the anchor walk verifies
/// all three (linkage + QC validity under OUR committed set + proposer
/// match) via [`verify_finality_for_header`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderLink {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub proposer: [u8; 32],
    pub qc: crate::consensus::QuorumCertificate,
}

/// Upper bound for the proposer-schedule scan in [`proposer_matches_schedule`].
/// QC rounds beyond this are absurd (runaway-round DoS); reject loudly instead
/// of spinning millions of schedule evaluations.
pub const MAX_PROPOSER_SCHEDULE_SCAN_ROUNDS: u32 = 100_000;

/// Check the block proposer against the deterministic schedule for ANY round
/// `0..=qc_round` (not just exactly `qc_round`).
///
/// A locked block is routinely RE-PROPOSED in a later round (lock-hint
/// rescue): the block carries its ORIGINAL author, but the QC forms in the
/// re-proposal round. Comparing only against the QC round rejects such
/// legitimate blocks ("not the scheduled proposer for QC round r").
/// The QC itself (2/3 of OUR set on this exact hash) remains the unforgeable
/// anchor — no key material outside our set can mint one — so widening the
/// proposer check to earlier rounds keeps the anti-reward-theft property
/// (the named proposer must have held SOME slot at this height) without
/// bricking re-proposed blocks.
pub fn proposer_matches_schedule(
    validators: &crate::consensus::ValidatorSet,
    height: u64,
    proposer: &[u8; 32],
    qc_round: u32,
) -> bool {
    // Non-validators have 0 power and never match any round.
    if validators.power_of(proposer) == 0 {
        return false;
    }
    let bound = qc_round.min(MAX_PROPOSER_SCHEDULE_SCAN_ROUNDS);
    if (0..=bound).any(|r| validators.proposer_for(height, r).as_ref() == Some(proposer)) {
        return true;
    }
    // If qc_round > 0 (view change occurred), allow tolerance for nearby view changes
    if qc_round > 0 {
        let nearby = qc_round
            .saturating_add(4)
            .min(MAX_PROPOSER_SCHEDULE_SCAN_ROUNDS);
        return (0..=nearby).any(|r| validators.proposer_for(height, r).as_ref() == Some(proposer));
    }
    false
}

/// One height's finality gate, shared by the header-anchor path and the body
/// path so the two can never drift (A1). Fails closed with a height-named
/// reason on: wrong QC kind, height/hash mismatch, bad proposer schedule,
/// or failed quorum verification under the GIVEN set (which must always be
/// the node's own pre-snapshot committed set — verifying against a set read
/// from the untrusted snapshot would be circular).
pub fn verify_finality_for_header(
    validators: &crate::consensus::ValidatorSet,
    height: u64,
    block_hash: &[u8; 32],
    proposer: &[u8; 32],
    qc: &crate::consensus::QuorumCertificate,
) -> Result<(), String> {
    use crate::consensus::VoteKind;
    if qc.kind != VoteKind::Precommit {
        return Err(format!(
            "finality: height {height}: QC kind is not Precommit"
        ));
    }
    if qc.height != height {
        return Err(format!(
            "finality: QC height {} does not match header height {height}",
            qc.height
        ));
    }
    if qc.block_hash != Some(*block_hash) {
        return Err(format!(
            "finality: QC does not bind header hash at height {height}"
        ));
    }
    if !proposer_matches_schedule(validators, height, proposer, qc.round) {
        return Err(format!(
            "finality: header proposer at height {height} held no schedule slot in rounds 0..={} ",
            qc.round
        ));
    }
    if !qc.verify(validators) {
        return Err(format!(
            "finality: QC fails quorum verification at height {height}"
        ));
    }
    Ok(())
}

/// The outcome of a snapshot-anchor proof.
///
/// Two values, and BOTH must come from the VERIFIED chain:
///
/// * `state_root` — the post-state of the boundary block, committed by the
///   verified successor header. A snapshot must hash to it.
/// * `boundary_hash` — the block hash at the boundary height
///   (`next_height - 1`) ON THE VERIFIED CHAIN. It is the chain's finalized
///   head at that height AND the sortition entropy for the height the node
///   resumes at (see [`crate::consensus::HeightConsensus::set_parent_hash`]).
///
/// The second value is why the anchor returns a struct and not a bare root:
/// a peer publishes the header record and its QC SEPARATELY, and only the
/// block HASH is covered by the quorum certificate. The `prev_hash` field of
/// a peer-supplied header record is therefore ATTACKER-CONTROLLED unless it
/// is checked against the verified chain. Taking the finalized head (and the
/// sortition parent) from such a field lets a peer point this node at a
/// FORK — which would both partition it (every later commit must extend the
/// poisoned head) and steer the sortition committee (audit W6.4b).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotAnchor {
    /// The trusted state root for the snapshot (the post-boundary state).
    pub state_root: [u8; 32],
    /// The verified block hash at the boundary height.
    pub boundary_hash: [u8; 32],
}

/// Prove that the header a peer offers at `next_height` is hash-linked to OUR
/// own finalized chain, AND quorum-finalized under our committed set — and
/// return that header's `state_root` as the trusted root for a state snapshot.
///
/// A snapshot's root is attacker-chosen unless it is pinned to the local chain.
/// This walks every height from our anchor (our finalized `(height, hash)`, or,
/// at genesis, the locally-known genesis root `[0u8; 32]`) up to `next_height`,
/// requiring per height BOTH the linkage (`prev_hash` chains) AND finality
/// ([`verify_finality_for_header`]: Precommit QC binding this height+hash,
/// verified against `validators`, from the scheduled proposer). A forged
/// header with an arbitrary `state_root` fails either the link or the QC —
/// linkage alone never suffices (A1: fully-linked forged chains are cheap).
///
/// `validators` MUST be the node's own pre-snapshot committed set: verifying
/// against a set derived from the untrusted snapshot is circular (attacker
/// mints keys, forges QCs, verifies). Consequence, stated plainly: a validator
/// rotation between our anchor and the boundary makes honest QCs unverifiable
/// and the snapshot is REFUSED (fail closed to the body walk, which replays
/// with the correct set-at-height).
///
/// F5 SET-AT-HEIGHT (validator-set rotation): the single-set entry
/// [`verify_snapshot_anchor`] below is kept for backward compatibility, but
/// live callers MUST use [`verify_snapshot_anchor_with_sets`] so every
/// height's QC is checked against the set in force AT THAT height
/// (`ValidatorRuntime::validator_set_for_height`). A height with no
/// resolvable set is fail-closed (refused), never guessed.
///
/// `fetch_header(height)` resolves the published header (+QC) at a height and
/// returns `None` when nothing is published. Any gap is a refusal, never a
/// skip. `max_span` bounds the walk so a far-ahead peer cannot force an
/// unbounded verify loop.
pub async fn verify_snapshot_anchor_with_sets<F, Fut, R>(
    our_finalized: Option<(u64, [u8; 32])>,
    genesis_root: [u8; 32],
    next_height: u64,
    resolve_set: R,
    max_span: u64,
    mut fetch_header: F,
) -> Result<SnapshotAnchor, String>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Option<HeaderLink>>,
    // Owned (not `&dyn Fn`): the resolver is held across awaits inside
    // `tokio::spawn`ed sync tasks, so the future must stay `Send` — a bare
    // `&dyn Fn` is not `Sync` and would poison every spawner.
    R: Fn(u64) -> Option<crate::consensus::ValidatorSet>,
{
    let (anchor_height, mut parent_hash) = match our_finalized {
        Some((h, hash)) => (h, hash),
        // Genesis: the chain roots at the zero prev-hash sentinel (the first
        // proposed block links to `[0u8; 32]`), so that is the conservative
        // anchor until a finalized head exists.
        None => (0u64, genesis_root),
    };
    if next_height <= anchor_height {
        return Err(format!(
            "snapshot anchor: header height {next_height} is not above our anchor at {anchor_height}"
        ));
    }
    if next_height - anchor_height > max_span {
        return Err(format!(
            "snapshot anchor: span {} exceeds max_span {max_span} (refusing unbounded walk)",
            next_height - anchor_height
        ));
    }

    let mut trusted_root: Option<[u8; 32]> = None;
    // The verified block hash at `next_height - 1`: the boundary block, whose
    // hash the successor header links to. Tracked from the walk itself, so it
    // is a value the QUORUM vouched for — never a peer-supplied `prev_hash`.
    let mut boundary_hash: Option<[u8; 32]> = None;
    for height in (anchor_height + 1)..=next_height {
        let link = fetch_header(height).await.ok_or_else(|| {
            format!(
                "snapshot anchor: no header published at height {height}; \
                 cannot prove linkage, refusing to trust a snapshot root"
            )
        })?;
        if link.height != height {
            return Err(format!(
                "snapshot anchor: header at height {height} reports height {}",
                link.height
            ));
        }
        if link.prev_hash != parent_hash {
            return Err(format!(
                "snapshot anchor: header at height {height} does not link to parent {} \
                 (forged or forked header chain rejected)",
                hex::encode(parent_hash)
            ));
        }
        // F5 set-at-height: each height's QC is verified against the set in
        // force AT THAT height. An unresolvable height is a refusal, never a
        // fallback to a neighbouring set (which would accept quorums the
        // height never had, or refuse ones it genuinely reached).
        let vs = resolve_set(height).ok_or_else(|| {
            format!(
                "snapshot anchor: no validator set resolvable at height {height}; \
                 refusing without a set-at-height (F5 fail-closed)"
            )
        })?;
        verify_finality_for_header(&vs, height, &link.block_hash, &link.proposer, &link.qc)
            .map_err(|e| format!("snapshot anchor: {e}"))?;
        // The block at `next_height - 1` is the boundary: it is the height
        // the snapshot restores to, and its hash is the finalized head the
        // node resumes from.
        if height + 1 == next_height {
            boundary_hash = Some(link.block_hash);
        }
        parent_hash = link.block_hash;
        trusted_root = Some(link.state_root);
        // Yield per verified height (same event-loop hygiene as the body
        // walk above; QC batch-verification is CPU-heavy on weak nodes).
        tokio::task::yield_now().await;
    }

    let state_root = trusted_root
        .ok_or_else(|| "snapshot anchor: empty header walk (no root established)".to_string())?;
    // The boundary hash: the last block of the walk below the tip. When the
    // walk covers only the tip (our anchor IS the boundary), the boundary is
    // our own finalized head.
    let boundary_hash = boundary_hash.unwrap_or(match our_finalized {
        Some((h, hash)) if h + 1 == next_height => hash,
        _ => genesis_root,
    });
    Ok(SnapshotAnchor {
        state_root,
        boundary_hash,
    })
}

/// Backward-compatible single-set entry for [`verify_snapshot_anchor_with_sets`]:
/// every height resolves to the same set. Live callers MUST use
/// `verify_snapshot_anchor_with_sets` so each certificate is checked against
/// the set in force at ITS height; a height it cannot resolve is fail-closed
/// (refused), never guessed.
pub async fn verify_snapshot_anchor<F, Fut>(
    our_finalized: Option<(u64, [u8; 32])>,
    genesis_root: [u8; 32],
    next_height: u64,
    validators: &crate::consensus::ValidatorSet,
    max_span: u64,
    fetch_header: F,
) -> Result<SnapshotAnchor, String>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Option<HeaderLink>>,
{
    let single = validators.clone();
    verify_snapshot_anchor_with_sets(
        our_finalized,
        genesis_root,
        next_height,
        move |_| Some(single.clone()),
        max_span,
        fetch_header,
    )
    .await
}

/// How many trailing heights [`verify_snapshot_anchor_tail`] checks.
///
/// Small on purpose: every height in the window is independently QC-verified
/// against OUR committed set, so the window size buys no quorum strength — it
/// only proves the trailing segment is one linked chain.
///
/// THREE heights, not one (audit W6.4b): with a single height the window
/// holds only the snapshot's SUCCESSOR header, whose `prev_hash` — the
/// boundary block, the finalized head the node resumes from and the sortition
/// entropy for the next height — is never checked against anything. A peer
/// could then serve a successor header whose `prev_hash` names a block of its
/// own choosing, and the node would adopt it as its finalized head: a fork,
/// a permanent partition (every later commit must extend the poisoned head),
/// and a peer-steered sortition committee.
///
/// The window therefore reaches one height BELOW the boundary as well, so
/// the whole segment `[boundary-1, boundary+1]` is one linked chain of
/// QC-verified blocks: the boundary block's own QC proves its hash, the
/// linkage check ties the successor header to it, and the linkage check
/// below ties the boundary header to its own parent — a forged `prev_hash`
/// anywhere in the segment is refused.
pub const SNAPSHOT_ANCHOR_TAIL_WINDOW: u64 = 3;

/// Prove the header at `next_height` for a node anchored at GENESIS, without
/// walking every header since height 1 — and return its `state_root` as the
/// trusted root for a state snapshot.
///
/// WHY THIS EXISTS: pruned peers (`STELL_KEEP_BLOCKS` 4000/8000) delete headers
/// below `tip − KEEP`, so [`verify_snapshot_anchor`] from a genesis anchor can
/// never complete on a long chain: the first missing header refuses the whole
/// snapshot, the body-walk fallback finds no bodies either, and a fresh
/// observer is stranded at height 0 forever. The trailing window only touches
/// headers just above the (near-tip) snapshot boundary, which retention
/// guarantees.
///
/// WHY IT IS SOUND (genesis anchors only): every window height must BOTH link
/// to its parent AND carry a Precommit QC verified against OUR committed set
/// ([`verify_finality_for_header`]). Forging the window therefore needs a 2/3
/// quorum of exactly the keys our full walk would check — the same forgery
/// budget. The full walk additionally proves continuity from a non-genesis
/// finalized head, which a fresh node does not have (every chain roots at the
/// zero prev-hash sentinel, so heights 1..tip prove nothing beyond "some
/// QC-signed chain" anyway). Callers MUST use the full walk whenever
/// `our_finalized` is `Some`.
///
/// RESIDUAL ADMIN TRUST (audit F4 — stated explicitly, not buried): on a
/// FRESH node `validators` is the CONFIG/ADMIN-SUPPLIED set (genesis config,
/// `node-bootstrap` preflight, operator flags). Nothing cryptographic
/// distinguishes the true genesis set from an attacker-crafted one at this
/// point: a wrong `validators:` set verifies an ATTACKER's QCs and syncs onto
/// a fork, and the tail window cannot detect it (the epoch is derived from
/// the synced root itself). The tail anchor is therefore only as trustworthy
/// as the admin-supplied set. Operational mitigation: pin the
/// genesis/first-checkpoint validator-set hash (or a checkpoint block hash)
/// out of band and compare the operator-visible set fingerprint at bootstrap
/// before syncing; a rotation between anchor and boundary instead makes
/// honest QCs unverifiable, so the snapshot is REFUSED (fail-closed to the
/// body walk, which replays with the set-at-height) — downtime, never a
/// fork. Deep fix: height-indexed validator sets threaded through sync/replay
/// (see the F5 note on [`validate_sync_chain`]).
///
/// SYNC TRAP N3 (R3 CODE-TAILS sweep, tail-anchor refusal on stale-set drift):
/// this refusal is CORRECT (fail-closed) but operationally it strands a node
/// whose committed set drifted behind the network's rotation: every boundary
/// refuses, and the fallback body walk only covers 256 heights (see the N6
/// note at `walk_chain` in `src/main.rs`), so a node more than 256 behind the
/// rotation never rejoins on its own. Minimal fix (no wire change): before
/// refusing, pull the CURRENT set with
/// `ValidatorRuntime::refresh_validator_set_from_fresh_snapshot` (the set-only
/// domain-snapshot pull in `src/main.rs`, bounded + fail-closed) and retry
/// this window ONCE against the fresh set; refuse only if that still fails.
/// Until then the operator repair is: fresh domain snapshot in, then re-sync.
///
/// Fail-closed like the full walk: any missing header, broken link, or failed
/// QC is a refusal, never a skip.
///
/// F5 SET-AT-HEIGHT: the single-set entry [`verify_snapshot_anchor_tail`]
/// below is kept for backward compatibility, but live callers MUST use this
/// per-height variant so each window height's QC is checked against the set
/// in force AT THAT height. A height with no resolvable set is fail-closed
/// (refused), never guessed.
pub async fn verify_snapshot_anchor_tail_with_sets<F, Fut, R>(
    next_height: u64,
    resolve_set: R,
    mut fetch_header: F,
) -> Result<SnapshotAnchor, String>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Option<HeaderLink>>,
    // Owned (not `&dyn Fn`): same `Send`-future reason as
    // [`verify_snapshot_anchor_with_sets`].
    R: Fn(u64) -> Option<crate::consensus::ValidatorSet>,
{
    if next_height == 0 {
        return Err("snapshot anchor (tail): no header at height 0 to anchor on".to_string());
    }
    // Window edge: heights start at 1, so a boundary near genesis yields a
    // shorter window rather than wrapping below height 1.
    let lo = next_height
        .saturating_sub(SNAPSHOT_ANCHOR_TAIL_WINDOW - 1)
        .max(1);
    let mut parent_hash: Option<[u8; 32]> = None;
    let mut trusted_root: Option<[u8; 32]> = None;
    // The verified block hash at the BOUNDARY height (`next_height - 1`).
    let mut boundary_hash: Option<[u8; 32]> = None;
    for height in lo..=next_height {
        let link = fetch_header(height).await.ok_or_else(|| {
            format!(
                "snapshot anchor (tail): no header published at height {height}; \
                 cannot prove linkage, refusing to trust a snapshot root"
            )
        })?;
        if link.height != height {
            return Err(format!(
                "snapshot anchor (tail): header at height {height} reports height {}",
                link.height
            ));
        }
        // Within the window every header must name the previous header's hash
        // as its parent — the same linkage rule as the full walk. Only the
        // OLDEST window header has no parent to check against (its parent is
        // pruned history, not our chain): its QC alone vouches for it.
        if let Some(parent) = parent_hash {
            if link.prev_hash != parent {
                return Err(format!(
                    "snapshot anchor (tail): header at height {height} does not link to parent {} \
                     (forged or forked header chain rejected)",
                    hex::encode(parent)
                ));
            }
        }
        // F5 set-at-height: this window height's QC is verified against the
        // set in force AT THIS height. An unresolvable height refuses the
        // whole window (fail-closed), never falls back to a neighbouring set.
        let vs = resolve_set(height).ok_or_else(|| {
            format!(
                "snapshot anchor (tail): no validator set resolvable at height {height}; \
                 refusing without a set-at-height (F5 fail-closed)"
            )
        })?;
        verify_finality_for_header(&vs, height, &link.block_hash, &link.proposer, &link.qc)
            .map_err(|e| format!("snapshot anchor (tail): {e}"))?;
        // The boundary block (the height the snapshot restores to): its hash
        // is QC-verified above, so it is a value the quorum vouched for.
        if height + 1 == next_height {
            boundary_hash = Some(link.block_hash);
        }
        parent_hash = Some(link.block_hash);
        trusted_root = Some(link.state_root);
        // Yield per verified height (see the full walk above).
        tokio::task::yield_now().await;
    }

    let state_root = trusted_root.ok_or_else(|| {
        "snapshot anchor (tail): empty header walk (no root established)".to_string()
    })?;
    // Below height 1 there is no boundary block (the chain roots at the zero
    // prev-hash sentinel), so the genesis parent is the honest answer.
    let boundary_hash = boundary_hash.unwrap_or([0u8; 32]);
    Ok(SnapshotAnchor {
        state_root,
        boundary_hash,
    })
}

/// Backward-compatible single-set entry for
/// [`verify_snapshot_anchor_tail_with_sets`]: every window height resolves to
/// the same set. Live callers MUST use the `_with_sets` variant so each
/// certificate is checked against the set in force at ITS height.
pub async fn verify_snapshot_anchor_tail<F, Fut>(
    next_height: u64,
    validators: &crate::consensus::ValidatorSet,
    fetch_header: F,
) -> Result<SnapshotAnchor, String>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Option<HeaderLink>>,
{
    let single = validators.clone();
    verify_snapshot_anchor_tail_with_sets(next_height, move |_| Some(single.clone()), fetch_header)
        .await
}

/// F3(b): after a body walk, the walked tail must BE the advertised head.
///
/// `walk_chain` re-anchors consensus on the walked chain, never on the peer's
/// claimed height: a peer that advertises a height above the chain it actually
/// served must be refused, not allowed to drag us to a height no block exists
/// for. Returns the next height to resume at (`walked height + 1`).
pub fn walked_head_anchor(
    blocks: &[Block],
    peer_hash: [u8; 32],
    peer_height: u64,
) -> Result<u64, String> {
    let last = blocks
        .last()
        .ok_or_else(|| "block sync: empty walk cannot be anchored".to_string())?;
    let walked = last.compute_hash();
    if walked != peer_hash {
        return Err(format!(
            "block sync: walked head {} does not hash to the advertised head {}",
            hex::encode(walked),
            hex::encode(peer_hash)
        ));
    }
    if last.height != peer_height {
        return Err(format!(
            "block sync: walked head is at height {} but the peer advertised {peer_height}; \
             refusing the advertised-head desync",
            last.height
        ));
    }
    Ok(last.height + 1)
}

/// Validate a synced chain before applying it.
///
/// Three things must hold, or the peer is lying and the chain is refused:
///
/// 1. heights increase by exactly 1 from `expected_first_height`;
/// 2. every block links to its parent, and the first block links to
///    `expected_first_hash` — our own last finalized block, so a peer cannot
///    hand us a history that forks exactly at the join point;
/// 3. every block carries a genuine validator quorum. Checking only the
///    proposer signature would let a single peer feed an entire unfinalized
///    history, which is exactly the attack block sync has to refuse.
///
/// `required_quorum` is the node's own 2/3 quorum size; a zero quorum is refused
/// outright rather than degenerating into "accept anything".
///
/// F5 SET-AT-HEIGHT (validator-set rotation), CLOSED by threading:
/// `StakingLedger::to_validator_set` still only ever reflects current bonded
/// stake (`src/staking.rs`), so a historical block's precommit QC verified
/// against the node's CURRENT set is the conservative direction (signers who
/// have rotated out carry no power; a peer cannot manufacture a quorum from
/// stale keys). The threading that closes the residual — a quorum of current
/// validators pointlessly vouching for old heights — is:
/// * body walks: [`validate_sync_chain_with_sets`], which resolves the set in
///   force at EACH height (`ValidatorRuntime::validator_set_for_height`) and
///   fail-closes on an unresolvable height (the single-set
///   [`validate_sync_chain`] below is the backward-compatible entry);
/// * snapshot anchors: [`verify_snapshot_anchor_with_sets`] and
///   [`verify_snapshot_anchor_tail_with_sets`], same per-height rule;
/// * snapshot trust: [`check_snapshot_set_binding`], which requires the
///   snapshot at the boundary height to strict-decode and commit to the SAME
///   non-empty validator set that verified its anchor — a snapshot without a
///   set commitment cannot serve as a trust anchor (fail-closed).
///
/// The replay path in `runtime::replay_historical_block` derives the
/// set-at-height from the engine at the block's pre-state.
pub fn validate_sync_chain(
    blocks: &[Block],
    expected_first_height: u64,
    expected_first_hash: [u8; 32],
    validators: &crate::consensus::ValidatorSet,
) -> Result<(), String> {
    // Backward-compatible single-set entry: every height resolves to the same
    // set. Live callers MUST use `validate_sync_chain_with_sets` so each
    // certificate is checked against the set in force at ITS height.
    let single = validators.clone();
    validate_sync_chain_with_sets(
        blocks,
        expected_first_height,
        expected_first_hash,
        &move |_| Some(single.clone()),
    )
}

/// W10.5 activation-boundary verification: every block's decision proof is
/// checked against the validator set IN FORCE AT THAT BLOCK'S HEIGHT —
///
/// a set change takes effect at a clean H+1 boundary on every node, so a
/// height-H certificate verified against today's live set accepts quorums H
/// never had (or refuses quorums H genuinely reached). `resolve_set` answers
/// "which set decided height H" (see
/// [`crate::runtime::ValidatorRuntime::validator_set_for_height`]); a height
/// it cannot resolve is fail-closed (refused), never guessed.
pub fn validate_sync_chain_with_sets(
    blocks: &[Block],
    expected_first_height: u64,
    expected_first_hash: [u8; 32],
    resolve_set: &dyn Fn(u64) -> Option<crate::consensus::ValidatorSet>,
) -> Result<(), String> {
    // Bind to the shard the chain itself claims. Callers that know their own
    // shard must use `validate_sync_chain_for_shard_with_sets` so a peer
    // cannot feed a different shard's blocks under our chain anchor.
    let expected_shard = blocks
        .first()
        .map(|b| b.shard_id)
        .unwrap_or(crate::sharding::MASTERCHAIN_SHARD);
    validate_sync_chain_for_shard_with_sets(
        blocks,
        expected_first_height,
        expected_first_hash,
        resolve_set,
        expected_shard,
    )
}

/// Shard-aware variant of [`validate_sync_chain`]: additionally requires every
/// block to be on `expected_shard` (the node's own chain). See the F5 note on
/// `validate_sync_chain` for the validator-rotation limitation.
///
/// Backward-compatible single-set entry (see `validate_sync_chain`): live
/// callers MUST use [`validate_sync_chain_for_shard_with_sets`].
pub fn validate_sync_chain_for_shard(
    blocks: &[Block],
    expected_first_height: u64,
    expected_first_hash: [u8; 32],
    validators: &crate::consensus::ValidatorSet,
    expected_shard: u32,
) -> Result<(), String> {
    let single = validators.clone();
    validate_sync_chain_for_shard_with_sets(
        blocks,
        expected_first_height,
        expected_first_hash,
        &move |_| Some(single.clone()),
        expected_shard,
    )
}

/// Shard-aware W10.5 activation-boundary verification: like
/// [`validate_sync_chain_with_sets`], additionally pinning every block to
/// `expected_shard`.
pub fn validate_sync_chain_for_shard_with_sets(
    blocks: &[Block],
    expected_first_height: u64,
    expected_first_hash: [u8; 32],
    resolve_set: &dyn Fn(u64) -> Option<crate::consensus::ValidatorSet>,
    expected_shard: u32,
) -> Result<(), String> {
    // An empty walk proves nothing: accepting it would let a caller treat "no
    // blocks" as "a valid chain", re-anchoring consensus on heights no block
    // exists for. Every legitimate caller holds at least one block here.
    if blocks.is_empty() {
        return Err("block sync: empty chain cannot be validated".to_string());
    }
    // A resolver that cannot name a set fails closed: without a set there is
    // no quorum to meet, so the first height already refuses. (The live
    // runtime resolver always answers — see `validator_set_for_height`.)
    let first_set = resolve_set(expected_first_height).ok_or_else(|| {
        format!(
            "block sync: no validator set known for height {expected_first_height}; refusing to validate"
        )
    })?;
    // A set with no power can never be satisfied. Check it up front so the reason
    // is "the validator set is empty" rather than a confusing per-block failure.
    if first_set.quorum_power() == u64::MAX {
        return Err("block sync: validator set has no power; refusing to validate".to_string());
    }
    let mut prev: Option<&Block> = None;
    let mut expected = expected_first_height;
    for b in blocks {
        if b.height != expected {
            return Err(format!(
                "block sync: height gap (expected {expected}, got {})",
                b.height
            ));
        }
        // W10.5: the set IN FORCE AT THIS BLOCK'S HEIGHT — never the live
        // set. A rotation mid-window must not re-verify old certificates
        // against the new quorum (or new certificates against the old one).
        let validators = resolve_set(b.height).ok_or_else(|| {
            format!(
                "block sync: no validator set known for height {}; refusing to validate",
                b.height
            )
        })?;
        if b.height != expected {
            return Err(format!(
                "block sync: height gap (expected {expected}, got {})",
                b.height
            ));
        }
        // F8: a synced block must belong to the chain we are syncing. A chain
        // that extends our finalized hash but claims another shard (or mixes
        // shards) must be refused before its QCs are given any weight.
        if b.shard_id != expected_shard {
            return Err(format!(
                "block sync: block {} is on shard {} but this chain is shard {expected_shard}",
                b.height, b.shard_id
            ));
        }
        // The first block must continue OUR chain, not a peer's alternative.
        let parent = prev
            .map(|p| p.compute_hash())
            .unwrap_or(expected_first_hash);
        if b.prev_hash != parent {
            return Err("block sync: broken parent link".to_string());
        }
        // Falcon-aware proposer check (not the Ed-only method): under a PQ
        // proposer the Ed-only check stalls sync fail-closed forever.
        if !crate::consensus::verify_proposer_signature(b) {
            return Err("block sync: invalid proposer signature".to_string());
        }
        // The decision proof travels WITH the block as its precommit QC. This is
        // deliberately not the block's `validator_signatures` list: a block carries
        // only the proposer's signature, and every other validator's agreement exists
        // as a precommit vote -- which is over `vote_sign_bytes`, a different message
        // from the block hash, so those signatures can never verify as block
        // signatures. Checking the attached QC (kind, height, quorum, membership)
        // is the correct verification, and it is also strictly stronger: it proves
        // the network committed, not merely that keys signed.
        let Some(qc) = &b.precommit_qc else {
            return Err(format!(
                "block sync: block {} carries no decision proof",
                b.height
            ));
        };
        if qc.kind != crate::consensus::VoteKind::Precommit {
            return Err(format!(
                "block sync: block {} decision proof is not a precommit quorum",
                b.height
            ));
        }
        if qc.height != b.height {
            return Err(format!(
                "block sync: block {} decision proof is for height {}",
                b.height, qc.height
            ));
        }
        if qc.block_hash != Some(b.compute_hash()) {
            return Err(format!(
                "block sync: block {} decision proof commits to a different block",
                b.height
            ));
        }
        // CHAIN BINDING of the committee: a µQC must have been elected with the
        // parent hash this block commits to, so a peer cannot pick the
        // committee it controls.
        if !qc.binds_to_parent(&b.prev_hash) {
            return Err(format!(
                "block sync: block {} decision proof was elected with a different parent block",
                b.height
            ));
        }
        if !qc.verify(&validators) {
            return Err(format!(
                "block sync: block {} decision proof lacks a validator quorum (carries {} of {} required power, total {})",
                b.height,
                validators.qc_signed_power(qc),
                validators.quorum_power(),
                validators.total_power()
            ));
        }
        // F8: the block's proposer must hold a deterministic-schedule slot at
        // this height (any round 0..=QC round — see `proposer_matches_schedule`
        // for why re-proposed locked blocks legitimately differ from the QC
        // round), exactly as `adopt_committed` enforces. Without this a peer
        // names any key it controls as proposer, and every fee/reward that
        // finalization credits to the proposer is redirected. The proposer
        // signature above only proves the named key signed; it says nothing
        // about whether that key was allowed to propose this slot.
        let round = qc.round;
        if !proposer_matches_schedule(&validators, b.height, &b.proposer, round) {
            return Err(format!(
                "block sync: block {} proposer {} holds no schedule slot in rounds 0..={round}",
                b.height,
                hex::encode(&b.proposer[..8]),
            ));
        }
        prev = Some(b);
        expected += 1;
    }
    Ok(())
}

/// State-Sync (Fast-Sync) for brand-new nodes or nodes lagging far behind.
/// Rather than replaying thousands of blocks, state-sync restores a serialized
/// state snapshot and verifies that its computed `state_root` EXACTLY matches
/// the trusted `expected_root` from the finalized block header.
///
/// If valid, commits the state into `target_engine`.
/// If the root does not match, rejects the snapshot before mutating target state
/// (poisoning / forgery guard).
/// Domain kinds published beside every state snapshot (see
/// `P2pNetworkAdapter::persist_domain_snapshot`). Restored in the same order
/// as `load_full_state_into` so a synced node roots identically.
pub const SYNC_DOMAIN_KINDS: &[&str] = &[
    "domains",
    "session",
    "bridge",
    "zkml",
    "cross_shard",
    "pq_keys",
];

pub async fn fast_sync_state<F, Fut, G, GFut>(
    target_engine: &crate::state_engine::InMemoryStateEngine,
    expected_root: crate::cell::CellHash,
    fetch_snapshot: F,
    fetch_domain: G,
) -> Result<(), String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<Vec<u8>>>,
    G: FnMut(&'static str) -> GFut,
    GFut: std::future::Future<Output = Option<Vec<u8>>>,
{
    fast_sync_fetch_verify_commit(
        target_engine,
        expected_root,
        fetch_snapshot,
        fetch_domain,
        None,
    )
    .await
    .map(|_| ())
}

/// F5 SET-AT-HEIGHT trust gate for snapshots: like [`fast_sync_state`], but
/// the snapshot is additionally required to COMMIT TO the validator set at
/// `snapshot_height`, and to commit to exactly the set that verified its
/// anchor (`anchor_set` — the set the caller proved the boundary QCs under,
/// resolved at the boundary height via
/// `ValidatorRuntime::validator_set_for_height` or the `_with_sets` anchor).
///
/// Fail-closed BEFORE the target is mutated: a snapshot at `snapshot_height`
/// that carries no `domains` blob, whose domains blob is legacy/unknown
/// (strict parse, see
/// [`crate::storage::decode_domain_snapshot_strict`]), that commits to an
/// EMPTY set, or that commits to a DIFFERENT set than `anchor_set`, is
/// refused as a trust anchor — the node must re-fetch (fresh set-only pull +
/// retry, see the N3 note on [`verify_snapshot_anchor_tail_with_sets`]) or
/// fall back to the body walk, never vote on an unbound snapshot.
///
/// Returns the bound validator set (the set the node resumes with at
/// `snapshot_height + 1`, to install via the checked refresh) on success.
/// Wire format unchanged: the commitment already flows inside the `domains`
/// blob; this only enforces that the trust path checks it.
pub async fn fast_sync_state_with_set_binding<F, Fut, G, GFut>(
    target_engine: &crate::state_engine::InMemoryStateEngine,
    expected_root: crate::cell::CellHash,
    fetch_snapshot: F,
    fetch_domain: G,
    snapshot_height: u64,
    anchor_set: &crate::consensus::ValidatorSet,
) -> Result<crate::consensus::ValidatorSet, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<Vec<u8>>>,
    G: FnMut(&'static str) -> GFut,
    GFut: std::future::Future<Output = Option<Vec<u8>>>,
{
    let bound = fast_sync_fetch_verify_commit(
        target_engine,
        expected_root,
        fetch_snapshot,
        fetch_domain,
        Some((snapshot_height, anchor_set)),
    )
    .await?;
    bound.ok_or_else(|| {
        "fast sync: set binding requested but no bound set returned (internal error)".to_string()
    })
}

/// F5 set-at-height binding check over an already-fetched domain bundle.
///
/// The snapshot at `snapshot_height` MUST commit to the validator set in force
/// at that height — i.e. its `domains` blob strict-decodes and derives a
/// NON-EMPTY set — and that set MUST equal `anchor_set`, the set the caller
/// verified the snapshot's anchor QCs under. Any other shape refuses the
/// snapshot AS A TRUST ANCHOR (fail-closed):
/// * no `domains` blob: the snapshot carries no set commitment at all;
/// * legacy/unknown `domains` bytes: strict parse refuses (no downgrade —
///   re-publish from a current binary);
/// * empty derived set: nothing could vouch for `snapshot_height + 1`;
/// * different set: stale or rotated snapshot (or a forked feed) — pull a
///   fresh set and retry, or walk bodies with per-height sets.
///
/// An empty `anchor_set` is itself a refusal: an anchor verified under no
/// quorum proves nothing, so there is no binding to check against. (Unbonded
/// chains, where no quorum exists yet, use the non-binding [`fast_sync_state`]
/// with a config set — this gate is for quorum-secured heights.)
pub fn check_snapshot_set_binding(
    snapshot_height: u64,
    bundle: &[(&'static str, Vec<u8>)],
    anchor_set: &crate::consensus::ValidatorSet,
) -> Result<crate::consensus::ValidatorSet, String> {
    let dbytes = bundle
        .iter()
        .find(|(kind, _)| *kind == "domains")
        .map(|(_, bytes)| bytes)
        .ok_or_else(|| {
            format!(
                "fast sync: snapshot at height {snapshot_height} carries no `domains` blob: \
                 it does not commit to the validator set at that height — \
                 refusing as a trust anchor (fetch the domains snapshot or \
                 re-publish from a current binary)"
            )
        })?;
    let snap = crate::storage::decode_domain_snapshot_strict(dbytes)
        .map_err(|e| format!("fast sync: snapshot at height {snapshot_height}: {e}"))?;
    let set = snap.staking.to_validator_set();
    if set.validators.is_empty() {
        return Err(format!(
            "fast sync: snapshot at height {snapshot_height} commits to an EMPTY validator set — \
             refusing as a trust anchor (an empty set cannot vouch for height {}; \
             unbonded chains must use the non-binding fast-sync path with a config set)",
            snapshot_height + 1
        ));
    }
    if anchor_set.validators.is_empty() {
        return Err(format!(
            "fast sync: anchor set is EMPTY but the snapshot at height {snapshot_height} commits \
             to a non-empty set — refusing as a trust anchor (the anchor was never quorum-verified)"
        ));
    }
    if set.validators != anchor_set.validators {
        return Err(format!(
            "fast sync: snapshot at height {snapshot_height} commits to a validator set that does \
             not match the set that verified its anchor (stale, rotated, or forked snapshot) — \
             refusing as a trust anchor (pull a fresh set via the set-only refresh and retry, \
             or fall back to the body walk with per-height sets)"
        ));
    }
    Ok(set)
}

async fn fast_sync_fetch_verify_commit<F, Fut, G, GFut>(
    target_engine: &crate::state_engine::InMemoryStateEngine,
    expected_root: crate::cell::CellHash,
    mut fetch_snapshot: F,
    mut fetch_domain: G,
    set_binding: Option<(u64, &crate::consensus::ValidatorSet)>,
) -> Result<Option<crate::consensus::ValidatorSet>, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<Vec<u8>>>,
    G: FnMut(&'static str) -> GFut,
    GFut: std::future::Future<Output = Option<Vec<u8>>>,
{
    let bytes = fetch_snapshot()
        .await
        .ok_or_else(|| "fast sync: failed to fetch state snapshot".to_string())?;
    // The snapshot is tens of MB: yield before the heavy restore so queued
    // consensus traffic runs first on a loaded 1-vCPU executor.
    tokio::task::yield_now().await;

    // Fetch every domain blob ONCE (audit follow-up F-J): accounts-only
    // restores fail the root check on any live chain, so a far-behind node
    // could never fast-sync. Absent blobs (pre-domain directory, or a domain
    // never used) mean empty — same rule as local restore — EXCEPT
    // `cross_shard` (audit F1): an absent replay blob is fail-closed by the
    // coverage gate below (refuse unless the target holds no replay state),
    // never silently installed as empty.
    //
    // STRICTLY SEQUENTIAL (never JoinSet/futures-unordered): the bundle is up
    // to 8 large blobs and each fans out to manifest + per-chunk streams, so
    // any parallelism here multiplies straight onto the 256-stream cap. One
    // blob in flight + a yield per domain keeps the footprint at one chunk
    // stream on the weak-node pull shape; parallel callers stay bounded by
    // the process-wide fetch semaphores instead.
    let mut bundle: Vec<(&'static str, Vec<u8>)> = Vec::new();
    for kind in SYNC_DOMAIN_KINDS {
        if let Some(dbytes) = fetch_domain(kind).await {
            bundle.push((kind, dbytes));
        }
        tokio::task::yield_now().await;
    }

    // Restore into an ephemeral engine first to verify the cryptographic root
    // before touching live state. The SAME bundle installs into the target
    // below, so the two can never disagree on bytes. The accounts restore
    // PRESERVES the replay sets (audit F1): `restore_snapshot`'s clear is the
    // reorg-replay semantic and would silently wipe the target's consumed set
    // when the blob is absent; the preserve variant plus the coverage gate
    // below makes a missing or short blob a loud refusal instead.
    let temp_engine = crate::state_engine::InMemoryStateEngine::new();
    temp_engine
        .restore_snapshot_preserve_replay_sets(&bytes)
        .await
        .map_err(|e| format!("fast sync: restore snapshot error: {e}"))?;
    install_bundle(&temp_engine, &bundle).await?;

    let computed_root = temp_engine.get_state_root().await;
    if computed_root != expected_root {
        return Err(format!(
            "fast sync: state root mismatch! expected {}, computed {} (poisoned snapshot rejected)",
            hex::encode(expected_root),
            hex::encode(computed_root)
        ));
    }

    // F5 SET-AT-HEIGHT binding gate: when requested, the snapshot must commit
    // to the validator set at its height (strict parse, non-empty, equal to
    // the anchor set) BEFORE the target is mutated, so a refusal leaves live
    // state untouched exactly like the root and replay gates.
    let bound_set = match set_binding {
        Some((snapshot_height, anchor_set)) => Some(check_snapshot_set_binding(
            snapshot_height,
            &bundle,
            anchor_set,
        )?),
        None => None,
    };

    // FAIL-CLOSED replay gate (audit F1): the root check above pins the
    // snapshot's replay sets, but installing into the TARGET must additionally
    // prove the incoming sets cover what the target already holds. Cases:
    // * blob absent + target replay state non-empty => REFUSE. The snapshot
    //   carries no replay proof for entries the target already committed to;
    //   installing would either wipe them (double mint) or keep them under a
    //   root that no longer commits to them (silent split). Absent blob with
    //   an EMPTY target is the never-cross-sharded chain and proceeds.
    // * blob present but not covering the target => REFUSE (same reasons).
    // Only a covering incoming set fast-forwards the target. This runs BEFORE
    // any mutation of the target, so a refusal leaves live state untouched.
    let incoming = find_cross_shard_snapshot(&bundle)?;
    match &incoming {
        None => {
            let (consumed, produced, completed) = (
                target_engine.cross_shard_consumed_len().await,
                target_engine.cross_shard_produced_len().await,
                target_engine.cross_shard_completed_len().await,
            );
            if consumed != 0 || produced != 0 || completed != 0 {
                return Err(format!(
                    "fast sync: snapshot omits the cross_shard blob while local replay state is \
                     non-empty (consumed={consumed} produced={produced} completed={completed}); \
                     installing would silently drop replay protection (double mint). Refusing: \
                     re-sync from a peer that publishes the cross_shard domain, or wipe and resync"
                ));
            }
        }
        Some(snap) => {
            if !target_engine.cross_shard_replay_covers(snap).await {
                return Err(format!(
                    "fast sync: snapshot cross_shard set does not cover local replay state \
                     (local consumed={} produced={} completed={} vs incoming consumed={} produced={} \
                     completed={}); installing would silently drop replay protection (double mint). \
                     Refusing: the snapshot is older than local commits or from a divergent chain",
                    target_engine.cross_shard_consumed_len().await,
                    target_engine.cross_shard_produced_len().await,
                    target_engine.cross_shard_completed_len().await,
                    snap.engine_consumed.len() + snap.runtime_consumed.len(),
                    snap.produced.len(),
                    snap.completed.len(),
                ));
            }
        }
    }

    // Cryptographic root matches and the replay gate passed: install the SAME
    // bytes into the target.
    target_engine
        .restore_snapshot_preserve_replay_sets(&bytes)
        .await
        .map_err(|e| format!("fast sync: commit snapshot error: {e}"))?;
    install_bundle(target_engine, &bundle).await?;
    Ok(bound_set)
}

/// Extract the cross-shard replay snapshot from a fetched domain bundle, if
/// the peer published one. A corrupt blob is a hard error (fail closed),
/// never an empty set: decoding "whatever bytes arrived" as empty would turn
/// a truncated fetch into a wiped consumed set.
fn find_cross_shard_snapshot(
    bundle: &[(&'static str, Vec<u8>)],
) -> Result<Option<crate::sharding::CrossShardReplaySnapshot>, String> {
    for (kind, dbytes) in bundle {
        if *kind == "cross_shard" {
            let snap: crate::sharding::CrossShardReplaySnapshot = bincode::deserialize(dbytes)
                .map_err(|e| format!("fast sync: restore cross-shard error: {e:?}"))?;
            return Ok(Some(snap));
        }
    }
    Ok(None)
}

/// Install one fetched domain bundle into an engine. Shared by the verify
/// (throwaway) and commit (target) phases.
async fn install_bundle(
    engine: &crate::state_engine::InMemoryStateEngine,
    bundle: &[(&'static str, Vec<u8>)],
) -> Result<(), String> {
    for (kind, dbytes) in bundle {
        match *kind {
            "domains" => {
                // Trust-anchor path: strict parse (current shape only, no
                // warn-and-upgrade downgrade, trailing bytes rejected). A
                // legacy or unknown-version blob is a hard refusal here; the
                // LENIENT `decode_domain_snapshot` stays available only to the
                // local-restore path that must still boot pre-upgrade data
                // directories. See `decode_domain_snapshot_strict`.
                let snap = crate::storage::decode_domain_snapshot_strict(dbytes)
                    .map_err(|e| format!("fast sync: restore domains error: {e}"))?;
                snap.apply(engine).await;
            }
            "session" => {
                engine
                    .restore_session_keys(dbytes)
                    .await
                    .map_err(|e| format!("fast sync: restore session keys error: {e}"))?;
            }
            "bridge" => {
                engine
                    .restore_bridge(dbytes)
                    .await
                    .map_err(|e| format!("fast sync: restore bridge error: {e}"))?;
            }
            // Ristretto deletion wave: confidential/shielded ledger removed with
            // crypto_privacy; fetched blob (if any) falls through to the
            // forward-compat unhandled arm below (logged, not installed).
            "zkml" => {
                engine
                    .restore_zkml_models(dbytes)
                    .await
                    .map_err(|e| format!("fast sync: restore zkml error: {e}"))?;
            }
            "cross_shard" => {
                // Full replay install (audit F1): consumed (both halves) +
                // produced + completed, extend-only. NEVER a clear: a missing
                // blob is handled by the fail-closed gate in `fast_sync_state`
                // (refuse unless the target is replay-empty), never by
                // installing emptiness here.
                let snap: crate::sharding::CrossShardReplaySnapshot = bincode::deserialize(dbytes)
                    .map_err(|e| format!("fast sync: restore cross-shard error: {e:?}"))?;
                engine.restore_cross_shard_replay(&snap).await;
            }
            "pq_keys" => {
                // Audit F7: the fetched `pq_keys` blob is INSTALLED, not
                // logged-and-skipped, so the fetch set (SYNC_DOMAIN_KINDS)
                // equals the install set. Wire format is
                // `Storage::export_pq_keys_blob` (bincode pairs); a corrupt
                // blob is a hard error (fail closed), never an empty import.
                // Absent blob (pre-publisher peer) installs as nothing: the
                // root check already passed without this domain (PQ keys ride
                // the accounts snapshot's pinned `pubkey_hash`), and missing
                // keys only refuse PQ-gated admission until gossip re-pins
                // them — availability, never a fork.
                engine
                    .restore_pq_keys(dbytes)
                    .await
                    .map_err(|e| format!("fast sync: restore pq_keys error: {e}"))?;
            }
            // Forward-compat: kinds the restore path does not install yet.
            // A non-empty blob here is logged loudly so a silently-dropped
            // domain can never hide: the root check above already passed, so
            // this is operational visibility, not a refusal.
            unhandled => {
                if !dbytes.is_empty() {
                    eprintln!(
                        "[sync] fast sync: fetched domain blob {unhandled:?} ({} bytes) \
                         has no restore path and was NOT installed; publishing peers \
                         should not rely on it reaching synced nodes",
                        dbytes.len()
                    );
                }
            }
        }
        // Domain restores deserialize megabytes and rebuild indexes: yield per
        // domain so the two install passes (verify + commit) never hold the
        // executor for their whole duration on a weak node.
        tokio::task::yield_now().await;
    }
    Ok(())
}

// ==================== Adopter body/receipt replication (mechanics only) ====================
//
// Bodies/receipts are ALREADY committed by the proposer: the commit certificate
// (precommit QC over `block.compute_hash()`) fixes the block identity, so
// replication must not alter what is committed, only who holds it. NO consensus
// change lives here: these are pure planning + verification helpers. The live
// wiring (adopt_committed / walk_chain in runtime.rs + main.rs, owned by another
// agent) calls them behind/parallel to finalization -- replication NEVER blocks
// finalization.
//
// Design (what replicates where + verification rule per artifact):
// * BODY (transactions): fetch from proposer/peers by hash, then
//   `verify_replicated_body` requires `block.compute_hash() == expected_hash`.
//   `compute_hash` commits to every tx hash (+ cross-shard ids, header fields),
//   so equality proves byte-identical transactions to what the network
//   committed. Mismatch = discard + log (no peer down-score infra exists;
//   callers log via eprintln). Safe invariant: hash commitment.
// * RECEIPT (per-tx success): NOTHING on the wire commits to it, so it is NEVER
//   fetched-and-trusted. The adopter produces it by the single real application
//   (`apply_block_transition`, the block_apply_parity-tested path) during
//   adopt/walk, and persists that outcome via `storage::put_receipts_for_block`
//   (+ `record_adopted_block` in rpc.rs for the serve path). Re-execution to
//   *derive* a receipt outside the single apply is forbidden (it would execute
//   transfers twice -- see the rpc.rs parity test). Safe invariant: determinism
//   of the single apply, not a hash.

/// Max concurrent per-height fetches in one replication pass. Bounds sockets +
/// memory: a node 1000 heights behind paces `BACKFILL_MAX_PER_PASS`-sized
/// windows of at most this many in flight, never 1000 at once.
pub const ADOPT_REPL_MAX_CONCURRENCY: usize = 8;
/// Per-height fetch timeout (ms). A slow peer fails this height (honest
/// unavailability), never stalls the pass or consensus.
pub const ADOPT_REPL_PER_HEIGHT_TIMEOUT_MS: u64 = 5_000;
/// Bounded retries per height before reporting honest unavailability.
pub const ADOPT_REPL_MAX_RETRIES: u32 = 3;
/// Max heights touched by one backfill pass. Paces catch-up; the caller runs
/// pass after pass while the plan is non-empty.
pub const ADOPT_REPL_BACKFILL_MAX_PER_PASS: usize = 64;
/// Retro/body window reused from the publish path (`RETRO_PUBLISH_DEPTH` in
/// main.rs): replication never asks for bodies older than this below the tip.
/// Older heights come from snapshots + header walks, not body fetch.
pub const ADOPT_REPL_RETRO_DEPTH: u64 = 4096;
/// Retention window reused from the DHT/local horizon (KEEP=8000): a height
/// below `tip - KEEP` may already be pruned on every peer, so it is honestly
/// unavailable via body fetch rather than retried forever.
pub const ADOPT_REPL_KEEP_WINDOW: u64 = 8000;

/// Bound on concurrent DHT fetches from the catch-up path (storm guard).
///
/// Live incident 2026-10-13 (observer C, 1 vCPU/60% quota, ~1800 behind):
/// every outgoing `request_to` sat at 2500-3500ms while B→C answered in
/// 269ms, and the receiver logged `too many concurrent streams on one
/// connection, dropping stream` (limit 256) plus `sending stopped by peer:
/// error 0` batches. `collect_missing_blocks` is strictly sequential, so the
/// walk itself cannot open hundreds of streams — the fan-out came from the
/// surrounding fetch amplification: 128 snapshot probes × (state + 7 domains
/// + header + QC), each `fetch_blob` fanning out to manifest + per-chunk
///   `dht.find_value`/`storage.fetch` lookups, plus background `replicate_blob`
///   pushes to the newcomer and immediate retries on top of timeouts. The
///   dropped streams then timed out, retried, and re-flooded (self-excitation).
///
/// The guard mirrors `ADOPT_REPL_MAX_CONCURRENCY`: at most 8 fetch_blobs in
/// flight process-wide, no matter how many catch-up subtasks (probe, anchor
/// walk, domain bundle, body walk) overlap. The hot path is unaffected — it
/// was already sequential (1 in flight) — this only caps future/parallel
/// callers. Enforced in `network::P2pNetworkAdapter` via a process-wide
/// semaphore; pinned by `network::tests`.
pub const FETCH_MAX_CONCURRENCY: usize = 8;
/// Base backoff between fetch retries (ms). The old 10ms×attempt hammered the
/// DHT inside the timeout window; exponential backoff from 100ms paces
/// retries far below consensus timescales while still converging.
pub const FETCH_RETRY_BASE_BACKOFF_MS: u64 = 100;
/// Cap for the exponential retry backoff (ms).
pub const FETCH_RETRY_MAX_BACKOFF_MS: u64 = 1_000;
/// Cap for the retry jitter added on top of the exponential backoff (ms).
///
/// Without jitter every node that times out on the same slow peer retries on
/// the SAME tick (100/200/400ms ladder), re-opening dozens of streams at once
/// and re-tripping the receiver's 256-stream drop — the synchronized re-flood
/// half of the 2026-10-13 self-excitation. A uniform draw from
/// `0..=FETCH_RETRY_JITTER_MAX_MS` spreads the retries across ~100ms with
/// zero cost to convergence. Pure-function bound; see
/// [`fetch_retry_backoff_with_jitter_ms`].
pub const FETCH_RETRY_JITTER_MAX_MS: u64 = 100;
/// Bound on concurrent LARGE-blob (snapshot/domain) fetches.
///
/// `FETCH_MAX_CONCURRENCY` caps fetch_blob ENTRY, but a snapshot is tens of
/// MB = tens of 1MB chunks, each costing a manifest lookup plus
/// `dht.find_value`/`storage.fetch` round trips that hold their streams for
/// the whole chunk body. Two such blobs already saturate a 1-vCPU event loop;
/// more overlap only lengthens every `resp=` tail past the 2.5s timeout and
/// feeds the retry storm. Large fetches therefore take this second, narrower
/// lane (nested INSIDE the 8-wide fetch permit, in that order, so no lock
/// cycle): at most 2 snapshot-sized blobs assemble at once process-wide, no
/// matter how many catch-up subtasks overlap. Small fetches (headers, bodies,
/// head pointers) skip this lane and keep the full 8.
pub const SNAPSHOT_FETCH_MAX_CONCURRENCY: usize = 2;
/// Per-chunk fetch timeout for LARGE (snapshot/domain) blobs (ms).
///
/// Generous on purpose: a snapshot is tens of MB = tens of 1MB chunks, which
/// is NORMAL, not an anomaly. Small fetches (headers, ~320KB bodies) converge
/// in ~5s windows; a single snapshot chunk on a weak link (RTT 70-300ms idle,
/// 2.5s+ loaded, 1vCPU/60%) routinely needs seconds, so bounding it at the
/// small-fetch budget turns every slow chunk into a whole-blob failure.
/// 20s per chunk attempt keeps slow-but-moving chunks alive while still
/// bounding a dead peer far below the per-blob budget.
pub const SNAPSHOT_CHUNK_TIMEOUT_MS: u64 = 20_000;
/// Bounded retries per CHUNK (not per blob) for large-blob assembly.
///
/// A single dropped chunk must retry just that chunk, never restart the blob:
/// with ~50 chunks per 50MB snapshot even a 5% per-chunk drop rate would fail
/// ~92% of whole-blob attempts without per-chunk resume. 6 retries per chunk
/// (≈7 tries) drives a 20%-drop link to <1e-4 residual per chunk.
pub const SNAPSHOT_CHUNK_RETRIES: u32 = 6;
/// Per-attempt timeout for the snapshot MANIFEST fetch (ms).
///
/// The manifest is one small KV lookup (local, then `dht.find_value`), so it
/// gets its own SMALL budget, separate from chunk bodies: a missing manifest
/// ("nobody published this boundary") must fail fast and move the probe to
/// the next boundary, not burn the chunk budget waiting for megabytes that
/// were never announced.
///
/// Over a WAN link with a 1-vCPU peer, the two-phase Kademlia lookup
/// (`dht.find_node` + `dht.find_value`) takes ~5-7s total. Bounded at 10s so a
/// real response is never preempted by a timeout, while an absent boundary still
/// fails fast (10s × 2 attempts = 20s).
pub const SNAPSHOT_MANIFEST_TIMEOUT_MS: u64 = 10_000;
/// Overall budget for ONE large-blob assembly (ms).
///
/// Serial 50-chunk pull at 2.5s/chunk needs ~125s when moving; 300s (5min)
/// is ~2.4x headroom for jitter/drops/retries without letting a dead boundary
/// wedge the tick forever. The per-chunk timeout bounds each step; this
/// bounds the sum.
pub const SNAPSHOT_BLOB_TIMEOUT_MS: u64 = 300_000;
/// Bounded whole-blob attempts (outer retry around manifest + resume-assembly).
///
/// Covers the MANIFEST level (a missing manifest — "nobody published this
/// boundary yet" — is retried here with backoff, then scored a miss) and, as
/// a rare safety net, a chunk assembly that exhausted per-chunk retries
/// (e.g. manifest re-resolved to new replicas unbsticks a chunk pinned to
/// dead peers). Per-chunk resume already handles drops inside one attempt,
/// so this almost never fires for chunk reasons. Capped at 2 so a truly
/// absent blob converges to a fast miss instead of retrying forever.
pub const SNAPSHOT_BLOB_ATTEMPTS: u32 = 2;

/// Generous per-blob time budget for a snapshot-sized blob with `n_chunks`.
///
/// Linear in chunks (15s per chunk — inside the 20s per-attempt timeout so a
/// moving pull never trips it) plus a 30s manifest/resolve slack, floored at
/// 60s (small blobs still get a sane minimum) and capped at
/// [`SNAPSHOT_BLOB_TIMEOUT_MS`]. Pure so tests pin it without time.
pub fn snapshot_blob_budget_ms(n_chunks: usize) -> u64 {
    const PER_CHUNK_MS: u64 = 15_000;
    const SLACK_MS: u64 = 30_000;
    const FLOOR_MS: u64 = 60_000;
    let want = (n_chunks as u64)
        .saturating_mul(PER_CHUNK_MS)
        .saturating_add(SLACK_MS)
        .max(FLOOR_MS);
    want.min(SNAPSHOT_BLOB_TIMEOUT_MS)
}

/// Loud failure for one large-blob assembly: names WHICH chunk died, after
/// how many tries, out of how many, under which per-chunk timeout — so a
/// `None` upstream is never silent about size/chunk/budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotChunkFailure {
    /// Index of the first chunk still missing when retries ran out.
    pub chunk_index: usize,
    /// Total chunks in the blob (blob size class, e.g. 50 ≈ 50MB).
    pub n_chunks: usize,
    /// Chunk attempts spent on the failed chunk (tries, not retries).
    pub attempts: u32,
    /// Per-chunk timeout each attempt was bounded by (ms).
    pub timeout_ms: u64,
}

impl std::fmt::Display for SnapshotChunkFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "snapshot chunk {}/{} unavailable after {} attempts (per-chunk timeout {}ms); \
             completed chunks are kept, only this chunk needs a retry",
            self.chunk_index, self.n_chunks, self.attempts, self.timeout_ms
        )
    }
}

/// Assemble `n_chunks` chunk bodies with per-chunk resume.
///
/// `fetch_chunk(i)` resolves chunk `i` to its bytes (`None` = this attempt
/// missed: drop, timeout, slow peer — including a per-chunk expected-hash
/// mismatch, which the caller reports as a miss exactly like a drop so a
/// forged chunk is NEVER installed). Chunks are pulled in BOUNDED
/// index-ordered batches of at most [`chunk_batch_for_blob`](`chunk_batch_for_blob`(`n_chunks`))
/// (i.e. at most [`FETCH_BLOB_CHUNK_BATCH`] concurrent fetches, and strictly
/// serial width 1 for blobs above [`LARGE_BLOB_SERIAL_CHUNKS`] — the weak-node
/// pull shape is unchanged for snapshot-sized blobs), and a `yield_now` runs
/// after every batch so the tick never wedges on a 1-vCPU executor.
///
/// FAIRNESS: every batch covers distinct indices in increasing order, each
/// missing index gets exactly one attempt per pass (no prioritization, no
/// starvation of honest peers), and completed slots are assigned back by
/// index — so assembly order is canonical regardless of completion order.
///
/// RESUME: completed slots are kept across passes and NEVER re-fetched — a
/// pass only asks for still-missing indices. Up to `max_retries` extra passes
/// run (i.e. up to `max_retries + 1` tries per chunk); the first still-missing
/// index afterwards is returned as [`SnapshotChunkFailure`] (loud: which
/// chunk / how many / what budget). Empty blob → empty vec (success).
pub async fn assemble_chunks_resumable<F, Fut>(
    n_chunks: usize,
    max_retries: u32,
    mut fetch_chunk: F,
) -> Result<Vec<Vec<u8>>, SnapshotChunkFailure>
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = Option<Vec<u8>>>,
{
    use std::collections::BTreeSet;
    let mut slots: Vec<Option<Vec<u8>>> = (0..n_chunks).map(|_| None).collect();
    let passes = max_retries.saturating_add(1);
    // Bounded fan-out: at most one `chunk_batch_for_blob` width in flight —
    // never unbounded — and width 1 (serial) for snapshot-sized blobs, so the
    // weak-node pull shape is byte-identical to before on large blobs.
    let width = chunk_batch_for_blob(n_chunks)
        .max(1)
        .min(FETCH_BLOB_CHUNK_BATCH.max(1));
    for _pass in 0..passes {
        let mut missing: BTreeSet<usize> = slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| if s.is_none() { Some(i) } else { None })
            .collect();
        if missing.is_empty() {
            break;
        }
        // Snapshot the missing set for this pass: newly-failed indices are
        // retried on the NEXT pass, never by re-walking a mutating set.
        let round: Vec<usize> = missing.iter().copied().collect();
        // Index-ordered batches (round-robin fairness: no index is
        // prioritized, no honest peer starves); assignment back is by index,
        // so completion order never affects assembly order. Futures are built
        // sequentially (one `FnMut` borrow at a time) then polled
        // concurrently via `join_all` on this task — no spawn, no `Send`
        // bound, no extra threads.
        for batch in round.chunks(width) {
            // Build one owned future per missing index (sequential `FnMut`
            // borrows, each ending with its call — the futures hold owned
            // bytes, never the closure borrow), then poll the batch
            // concurrently on this task: at most `width` chunk streams in
            // flight, never unbounded.
            let idxs: Vec<usize> = batch
                .iter()
                .copied()
                .filter(|&i| slots[i].is_none())
                .collect();
            let futs: Vec<Fut> = idxs.iter().map(|&i| fetch_chunk(i)).collect();
            let outs = futures::future::join_all(futs).await;
            for (&i, got) in idxs.iter().zip(outs) {
                if let Some(bytes) = got {
                    slots[i] = Some(bytes);
                    missing.remove(&i);
                }
            }
            // Yield per batch: assembly must not hold the executor across
            // slow fetches on a weak node.
            tokio::task::yield_now().await;
        }
        if missing.is_empty() && slots.iter().all(|s| s.is_some()) {
            break;
        }
    }
    if let Some(idx) = slots.iter().position(|s| s.is_none()) {
        return Err(SnapshotChunkFailure {
            chunk_index: idx,
            n_chunks,
            attempts: passes,
            timeout_ms: SNAPSHOT_CHUNK_TIMEOUT_MS,
        });
    }
    Ok(slots
        .into_iter()
        .map(|s| s.expect("all slots filled"))
        .collect())
}

/// Bound on chunks of ONE blob assembled concurrently.
///
/// A single `fetch_blob` fans out to manifest + per-chunk lookups; bounding
/// the per-blob batch bounds the per-blob stream demand to `batch + 1`
/// regardless of blob size. Enforced by chunk drivers (see
/// [`plan_chunk_batches`]); blobs above [`LARGE_BLOB_SERIAL_CHUNKS`] use
/// batches of 1 (strictly serial) so a tens-of-MB snapshot never holds more
/// than one chunk stream at a time.
pub const FETCH_BLOB_CHUNK_BATCH: usize = 4;
/// Blob size (in chunks) above which assembly is strictly serial.
///
/// Snapshots (tens of MB ≈ tens of chunks) are the weak node's heaviest
/// fetch: serial assembly keeps their stream footprint at exactly 1 and
/// yields the event loop between chunks instead of pipelining tens of
/// megabyte bodies through it at once.
pub const LARGE_BLOB_SERIAL_CHUNKS: usize = 8;
/// Cap for the jitter on the retro-publish push pacing (ms).
///
/// Retro pushes are background replication; every publisher wakes on the same
/// 30s cadence, so identical 5ms pacing re-synchronizes their
/// `replicate_blob` bursts onto the same newcomer. A uniform draw from
/// `0..=RETRO_PUSH_JITTER_MAX_MS` de-phases the bursts. Small (≤5ms): pacing
/// stays ~5ms per body, never a stall.
pub const RETRO_PUSH_JITTER_MAX_MS: u64 = 5;
/// Pacing between snapshot-probe misses (ms per consecutive miss). A tight
/// loop over 128 missing boundaries fired ~384 fetch_blobs back-to-back,
/// saturating the 1-vCPU event loop and starving consensus traffic. Linear
/// pacing yields the loop to the consensus sender.
pub const SNAPSHOT_PROBE_PACE_MS_PER_MISS: u64 = 20;
/// Cap for snapshot-probe pacing (ms).
pub const SNAPSHOT_PROBE_PACE_MAX_MS: u64 = 200;
/// Gap above which a lagging node must NOT push its stale bodies/heads.
///
/// A node ~1800 behind that retro-publishes its own 128-body window every 30s
/// (plus 8 tip-supplement bodies) spawns ~136 background `replicate_blob`
/// tasks per pass, each fanning out to K closest peers — pure flood the tip
/// never needs, competing with the node's own catch-up fetches for the same
/// 256 stream slots. Skipping pushes while far behind prioritizes consensus
/// (fetch) over replication (push) with zero hot-path cost: in-sync nodes
/// (gap ≤ threshold) behave byte-identically.
pub const RETRO_SKIP_BEHIND_GAP: u64 = 100;

/// Exponential backoff for fetch retries: `BASE * 2^(attempt-1)`, capped.
/// `attempt` is 1-based; saturating so absurd inputs cannot overflow. Pure.
pub fn fetch_retry_backoff_ms(attempt: u32) -> u64 {
    if attempt == 0 {
        return FETCH_RETRY_BASE_BACKOFF_MS;
    }
    let shift = (attempt - 1).min(4);
    FETCH_RETRY_BASE_BACKOFF_MS
        .saturating_mul(1u64 << shift)
        .min(FETCH_RETRY_MAX_BACKOFF_MS)
}

/// Pacing delay after consecutive snapshot-probe misses: linear in misses,
/// capped. Pure.
pub fn snapshot_probe_pace_ms(consecutive_misses: u32) -> u64 {
    (consecutive_misses as u64)
        .saturating_mul(SNAPSHOT_PROBE_PACE_MS_PER_MISS)
        .min(SNAPSHOT_PROBE_PACE_MAX_MS)
}

/// Retry backoff WITH jitter: exponential base plus a uniform draw.
///
/// `jitter` is the caller's random draw (any u64; values above
/// [`FETCH_RETRY_JITTER_MAX_MS`] are clamped, so a raw `rand::random::<u64>()`
/// needs no modulo at the call site). The floor is ALWAYS the exponential
/// base — jitter only ever DELAYS, never hurries: a timed-out fetch never
/// retries sooner than 100ms, which is what breaks the "timeout → instant
/// retry → re-flood" shape (`request_to dial=0ms resp=2500-3500ms`). The
/// ceiling is `MAX_BACKOFF + JITTER_MAX`. Pure so tests pin it without time.
pub fn fetch_retry_backoff_with_jitter_ms(attempt: u32, jitter: u64) -> u64 {
    fetch_retry_backoff_ms(attempt).saturating_add(jitter.min(FETCH_RETRY_JITTER_MAX_MS))
}

/// Chunk batch width for assembling one blob with `n_chunks`.
///
/// Small blobs may pipeline up to [`FETCH_BLOB_CHUNK_BATCH`] chunks; large
/// blobs (above [`LARGE_BLOB_SERIAL_CHUNKS`]) assemble strictly serially
/// (width 1) so a snapshot-sized fetch holds exactly one chunk stream and
/// yields between chunks instead of wedging the weak node's event loop.
/// Pure.
pub fn chunk_batch_for_blob(n_chunks: usize) -> usize {
    if n_chunks > LARGE_BLOB_SERIAL_CHUNKS {
        1
    } else {
        FETCH_BLOB_CHUNK_BATCH.max(1)
    }
}

/// Split `n_chunks` into `(start, end)` batches of at most `batch`.
///
/// `batch` saturates to ≥1 (a zero width would loop forever in a driver).
/// Empty blob → no batches. Pure so the fan-out shape is test-pinned without
/// a live DHT; chunk drivers iterate these ranges and MUST `yield_now`
/// between batches (event-loop hygiene on 1-vCPU nodes).
pub fn plan_chunk_batches(n_chunks: usize, batch: usize) -> Vec<(usize, usize)> {
    let batch = batch.max(1);
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < n_chunks {
        let end = (start + batch).min(n_chunks);
        out.push((start, end));
        start = end;
    }
    out
}

/// Retro-push pacing WITH jitter: base 5ms plus a uniform draw.
///
/// Same clamping contract as [`fetch_retry_backoff_with_jitter_ms`]: the
/// floor is always the base pace (pushes never fire faster than today), the
/// draw only de-phases publishers that woke on the same cadence. Pure.
pub fn retro_publish_pace_with_jitter_ms(jitter: u64) -> u64 {
    crate::network::RETRO_PUBLISH_PACE_MS.saturating_add(jitter.min(RETRO_PUSH_JITTER_MAX_MS))
}

/// Whether a node at `our_tip` with a peer at `peer_tip` must skip its
/// retro-publish pushes this pass (stale pushes would flood while catching
/// up). Pure.
pub fn should_skip_retro_while_behind(our_tip: u64, peer_tip: u64) -> bool {
    peer_tip > our_tip && peer_tip - our_tip > RETRO_SKIP_BEHIND_GAP
}

/// Gap within which the LIVE Committed path owns catch-up (observer fast path).
///
/// When the hint gap is this small, the missing bodies are already arriving as
/// `ConsensusMsg::Committed` broadcasts carrying the full block + QC — no DHT
/// fetch is needed. Running the catch-up machine on top (DHT `fetch_head` +
/// body walk) only duplicates the same heights' QC verification while holding
/// the tick for seconds on a weak link. Pure.
pub const LIVE_ADOPT_GAP_THRESHOLD: u64 = 16;

/// Whether this tick should DEFER the catch-up machine so live adopt runs first.
///
/// `hint_gap` is the free peer-hint gap (`peer_hint - our_tip`, 0 when in sync);
/// `live_traffic_pending` is whether the consensus inbox has anything queued.
/// Defer only when live traffic is pending AND the gap is live-sized: a far-behind
/// node still needs the DHT walk even while tip commits stream in (those commits
/// are for heights it cannot adopt yet). Pure.
pub fn should_defer_catchup_for_live(hint_gap: u64, live_traffic_pending: bool) -> bool {
    live_traffic_pending && hint_gap <= LIVE_ADOPT_GAP_THRESHOLD
}

/// Whether this tick should DEFER the catch-up machine given the health of the
/// LIVE adopt flow, not just a point sample of the inbox.
///
/// Remainder of the 2026-10-13 observer incident: `should_defer_catchup_for_live`
/// samples `!rx.is_empty()` once at the tick top. At a 1 block/s chain tempo with
/// 100ms ticks, ~9 ticks in 10 observe an empty inbox while the next Committed is
/// still in pubsub transit — so every catch-up interval (2s) the tick entered
/// `try_catch_up` (`fetch_head` + a 1-height DHT body walk, seconds each on a weak
/// link) for heights the imminent Committed would deliver for free. Live messages
/// queued behind those multi-second stalls; the queueing delay compounded to the
/// observed ~30s/block on empty blocks. `live_adopt_fresh` closes the sampling
/// race: a successful parent-match adopt within the last catch-up interval proves
/// the live flow is delivering, even if this exact tick top sees an empty inbox.
///
/// Defer while the gap is live-sized AND (traffic queued OR live flow fresh). A
/// far-behind node (gap above threshold) still walks even with fresh adopts —
/// tip commits are for heights it cannot adopt yet — and a stalled live flow
/// (no adopt for a full interval) resumes the DHT machine on schedule. Pure.
pub fn should_defer_catchup_for_live_flow(
    hint_gap: u64,
    live_traffic_pending: bool,
    live_adopt_fresh: bool,
) -> bool {
    hint_gap <= LIVE_ADOPT_GAP_THRESHOLD && (live_traffic_pending || live_adopt_fresh)
}

/// Whether a Committed block is live-adoptable without any DHT work: it is for
/// our exact next height and extends our finalized head. Pure over header fields
/// so the tick can decide before paying any verification cost.
pub fn is_live_adoptable(
    our_height: u64,
    our_head: [u8; 32],
    block_height: u64,
    block_prev: [u8; 32],
) -> bool {
    block_height == our_height && block_prev == our_head
}

/// Outcome of one replicated height. Never blocks finalization: `Unavailable`
/// is an honest, retry-later answer, not an error that stalls consensus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplicateOutcome {
    /// Body verified against the committed hash and persisted.
    Stored,
    /// Body failed verification (hash mismatch / undecodable): discarded and
    /// logged by the caller. The peer is NOT trusted.
    RejectedTamper(String),
    /// No body available (pruned, offline peer, timeout after bounded retries):
    /// honest unavailability. Consensus already finalized; retry later.
    Unavailable(String),
}

/// Verify a fetched body against the ALREADY-COMMITTED header hash.
///
/// Never trust, always verify: a body that does not hash to `expected_hash` is
/// discarded (Err names the mismatch for the log). This is the check that makes
/// replication unable to alter what was committed.
pub fn verify_replicated_body(expected_hash: &[u8; 32], block: &Block) -> Result<(), String> {
    let computed = block.compute_hash();
    if computed != *expected_hash {
        return Err(format!(
            "replicated body at height {} rejected: hashes to {} but the committed header is {}",
            block.height,
            hex::encode(computed),
            hex::encode(expected_hash)
        ));
    }
    Ok(())
}

/// Decode fetched bytes and verify against the committed hash in one step (the
/// fetch-and-verify boundary the network path uses).
pub fn verify_replicated_bytes(expected_hash: &[u8; 32], bytes: &[u8]) -> Result<Block, String> {
    let block: Block =
        bincode::deserialize(bytes).map_err(|e| format!("replicated body undecodable: {e:?}"))?;
    verify_replicated_body(expected_hash, &block)?;
    Ok(block)
}

/// Whether `height` may still be body-fetched at `tip`: inside BOTH the retro
/// window (publish horizon) and the retention window (prune horizon). Outside
/// either, the honest answer is "not available via fetch" (snapshot/header
/// paths own those heights), never an unbounded retry storm.
pub fn height_is_replicable(height: u64, tip: u64, keep: u64, retro_depth: u64) -> bool {
    if height > tip {
        return false;
    }
    let age = tip.saturating_sub(height);
    age <= keep && age <= retro_depth
}

/// Bounded, tip-ward backfill plan: the heights in `(local..=tip)` the next
/// pass should fetch, oldest-first within a TIP-MOST window of at most
/// `max_per_pass`.
///
/// A node 1000 heights behind must NOT fetch 1000 bodies at once: with
/// `max_per_pass=64` the first pass covers the 64 heights nearest the tip (so
/// RPCs serve the tip first), and the caller repeats until the gap closes.
/// Heights outside the replicable window are excluded (honest unavailability).
/// Pure over heights so it is unit-testable without a network.
pub fn plan_backfill_tip_ward(
    local_finalized: u64,
    tip: u64,
    max_per_pass: usize,
    keep: u64,
    retro_depth: u64,
) -> Vec<u64> {
    if max_per_pass == 0 || tip <= local_finalized {
        return Vec::new();
    }
    let mut wanted: Vec<u64> = ((local_finalized + 1)..=tip)
        .filter(|h| height_is_replicable(*h, tip, keep, retro_depth))
        .collect();
    if wanted.len() > max_per_pass {
        wanted = wanted[wanted.len() - max_per_pass..].to_vec();
    }
    wanted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{FalconKeypair, Vote, VoteKind};
    use crate::sharding::MASTERCHAIN_SHARD;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    /// FULL-PQ QC (mirrors `consensus::tests::fvote` + `VoteSet::certificate`
    /// idiom): Ed list for membership/power plus Falcon µQC envelope for
    /// crypto — exactly what `QuorumCertificate::verify` requires. `parent`
    /// must be the block's `prev_hash` (chain binding).
    fn pq_cert_for(
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        parent: [u8; 32],
        vs: &crate::consensus::ValidatorSet,
        keys: &[(SigningKey, FalconKeypair)],
    ) -> crate::consensus::QuorumCertificate {
        let mut set = crate::consensus::VoteSet::new();
        for (sk, fk) in keys {
            let v = Vote::sign_with_falcon(sk, fk, height, round, VoteKind::Precommit, Some(block_hash));
            set.add(v, vs, height, round, VoteKind::Precommit)
                .expect("falcon vote must ingest");
        }
        set.certificate_with_parent(Some(block_hash), vs, Some(&parent))
            .expect("quorum must compile a Falcon µQC")
    }

    fn chain(len: u64) -> Vec<Block> {
        let sk = SigningKey::generate(&mut OsRng);
        let fk = FalconKeypair::generate();
        crate::consensus::register_validator_pq_key(
            sk.verifying_key().to_bytes(),
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
        let vs = crate::consensus::ValidatorSet::from_list(vec![(
            sk.verifying_key().to_bytes(),
            1,
        )]);
        let keys = vec![(sk.clone(), fk.clone())];
        let mut out = Vec::new();
        let mut prev = [0u8; 32];
        for h in 0..=len {
            let mut b = Block {
                shard_id: MASTERCHAIN_SHARD,
                height: h,
                prev_hash: prev,
                state_root: [h as u8; 32],
                transactions: vec![],
                cross_shard_out: vec![],
                timestamp: h,
                proposer: sk.verifying_key().to_bytes(),
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                order_merkle_root: [0u8; 32],
                epoch_key_commitment: [0u8; 32],
                mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            };
            b.sign_block(&sk);
            let hash = b.compute_hash();
            // A decision proof travels with the block: without it the chain is
            // exactly what the quorum check must refuse.
            b.precommit_qc = Some(pq_cert_for(h, 0, hash, prev, &vs, &keys));
            prev = hash;
            out.push(b);
        }
        out
    }

    /// A chain where every block is co-signed by `extra` validators, so it
    /// carries a real quorum instead of a lone proposer signature.
    /// Build the validator set a chain claims decided it: exactly the signers named
    /// in its attached precommit QC, equal power. The quorum lives in the QC, not in
    /// the block-signature list (which carries only the proposer), so the set must be
    /// derived from the QC or the threshold is measured against the wrong members.
    /// Marker entries (`PQ_UQC_MARKER_ID` / `PQ_QC_MARKER_ID`) are envelopes,
    /// not members, and are skipped.
    fn set_from(b: &Block) -> crate::consensus::ValidatorSet {
        let mut vs = crate::consensus::ValidatorSet::new();
        if let Some(qc) = &b.precommit_qc {
            for (pk, _) in &qc.signatures {
                if *pk == crate::consensus::PQ_UQC_MARKER_ID
                    || *pk == crate::consensus::PQ_QC_MARKER_ID
                {
                    continue;
                }
                vs.add(*pk, 1);
            }
        }
        vs
    }

    fn quorum_chain(len: u64, signers: usize) -> Vec<Block> {
        // The validators are the signers named in the QC (proposer + `signers`
        // others), and the PROPOSER of each height must be the one the schedule
        // names -- F8 enforces that, so a fixed proposer would be correctly
        // refused.
        let keys: Vec<SigningKey> = (0..signers + 1)
            .map(|_| SigningKey::generate(&mut OsRng))
            .collect();
        let fks: Vec<FalconKeypair> = keys
            .iter()
            .map(|k| {
                let fk = FalconKeypair::generate();
                crate::consensus::register_validator_pq_key(
                    k.verifying_key().to_bytes(),
                    crate::post_quantum::PqScheme::Falcon512,
                    fk.public_key.clone(),
                );
                fk
            })
            .collect();
        let vs = crate::consensus::ValidatorSet::from_list(
            keys.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let all_keys: Vec<(SigningKey, FalconKeypair)> =
            keys.into_iter().zip(fks).collect();
        let mut out = Vec::new();
        let mut prev = [0u8; 32];
        for h in 0..=len {
            let proposer_id = vs.proposer_for(h, 0).expect("non-empty set has a proposer");
            let proposer_idx = all_keys
                .iter()
                .position(|(k, _)| k.verifying_key().to_bytes() == proposer_id)
                .expect("proposer is a member");
            let (proposer_sk, _) = &all_keys[proposer_idx];
            let proposer = proposer_sk.clone();
            let mut b = Block {
                shard_id: MASTERCHAIN_SHARD,
                height: h,
                prev_hash: prev,
                state_root: [h as u8; 32],
                transactions: vec![],
                cross_shard_out: vec![],
                timestamp: h,
                proposer: proposer_id,
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                order_merkle_root: [0u8; 32],
                epoch_key_commitment: [0u8; 32],
                mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            };
            b.sign_block(&proposer);
            let hash = b.compute_hash();
            // The quorum lives in the attached precommit QC, not in extra block-hash
            // signatures: validators agree via votes (over vote_sign_bytes), and only
            // the QC proves they did.
            b.precommit_qc = Some(pq_cert_for(h, 0, hash, prev, &vs, &all_keys));
            prev = hash;
            out.push(b);
        }
        out
    }

    /// HeaderLink with the block's own QC attached (the happy-path link for
    /// A1 anchor tests).
    fn qc_link(b: &Block) -> HeaderLink {
        HeaderLink {
            height: b.height,
            block_hash: b.compute_hash(),
            prev_hash: b.prev_hash,
            state_root: b.state_root,
            proposer: b.proposer,
            qc: b
                .precommit_qc
                .clone()
                .expect("quorum_chain blocks carry QCs"),
        }
    }

    #[tokio::test]
    async fn collects_missing_blocks_ancestor_first() {
        let blocks = chain(3);
        let map: HashMap<[u8; 32], Block> = blocks
            .iter()
            .map(|b| (b.compute_hash(), b.clone()))
            .collect();
        let genesis = blocks[0].compute_hash();
        let head = blocks[3].compute_hash();

        let got = collect_missing_blocks(head, genesis, 100, |h| {
            let b = map.get(&h).cloned();
            async move { b }
        })
        .await
        .unwrap();

        assert_eq!(got.len(), 3, "blocks 1..=3");
        assert_eq!(got[0].height, 1);
        assert_eq!(got[2].height, 3);
        // A proposer-only chain is only acceptable in a single-validator network.
        //
        // The validator set is passed instead of a head count, because the
        // threshold is a fraction of stake and membership is checked. Building
        // the set from the block's own signers is the single-validator case:
        // one member, one signature, quorum met.
        let solo = set_from(&got[0]);
        assert_eq!(solo.validators.len(), 1, "the chain carries one signature");
        assert!(validate_sync_chain(&got, 1, genesis, &solo).is_ok());

        // In a real network the quorum exceeds 1, and then the same chain -
        // which carries nothing but the proposer's own signature - is refused.
        // This is the shape the old head-count check missed: the chain would have
        // been accepted because a count of 1 satisfied "quorum > 0".
        let mut wider = solo.clone();
        for i in 0..3u8 {
            wider.add([0xEEu8.wrapping_add(i); 32], 1);
        }
        assert!(
            wider.quorum_power() > 1,
            "a real network needs more than one"
        );
        assert!(
            validate_sync_chain(&got, 1, genesis, &wider).is_err(),
            "a proposer-only chain must not satisfy a multi-validator quorum"
        );

        // A set with no power refuses outright rather than degenerating.
        assert!(
            validate_sync_chain(&got, 1, genesis, &crate::consensus::ValidatorSet::new()).is_err()
        );

        // Already at head -> nothing to fetch.
        let none = collect_missing_blocks(head, head, 100, |_h| async { None })
            .await
            .unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn sync_requires_validator_quorum_and_our_own_parent() {
        let blocks = quorum_chain(3, 2);
        let genesis = blocks[0].compute_hash();
        let map: HashMap<[u8; 32], Block> = blocks
            .iter()
            .map(|b| (b.compute_hash(), b.clone()))
            .collect();
        let head = blocks[3].compute_hash();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let got = rt
            .block_on(collect_missing_blocks(head, genesis, 100, |h| {
                let b = map.get(&h).cloned();
                async move { b }
            }))
            .unwrap();

        // 3 signers satisfy a quorum. The validator set is passed rather than a
        // count because the threshold is a fraction of stake and membership is
        // checked - a head count is not evidence.
        let vs3 = set_from(&got[0]);
        assert!(validate_sync_chain(&got, 1, genesis, &vs3).is_ok());
        // A set that omits one signer cannot count that signer's power, so the
        // remaining signatures fall short. The old head-count check had no way to
        // express this: it never knew who was supposed to be in the set.
        let mut partial = crate::consensus::ValidatorSet::new();
        for (pk, _) in got[0].validator_signatures.iter().take(2) {
            partial.add(*pk, 1);
        }
        partial.add([0xEEu8; 32], 1); // a member that never signed
        assert!(
            validate_sync_chain(&got, 1, genesis, &partial).is_err(),
            "a signer's power must not count unless it is a member AND it signed"
        );
        // Forking exactly at the join point is refused even with a valid quorum.
        assert!(validate_sync_chain(&got, 1, [0xAAu8; 32], &vs3).is_err());

        // A peer that strips the decision proof cannot feed us anything. The
        // quorum lives in the attached precommit QC, not in the block-signature
        // list, so removing the QC -- not truncating signatures -- is the strip
        // that must fail.
        let mut stripped = got.clone();
        for b in &mut stripped {
            b.precommit_qc = None;
        }
        assert!(validate_sync_chain(&stripped, 1, genesis, &vs3).is_err());

        // A single validator listed many times inside the QC must not fake a quorum:
        // power counts each member once, so ten copies of one signer are still one.
        let mut dup = got.clone();
        for b in &mut dup {
            if let Some(qc) = b.precommit_qc.as_mut() {
                let one = qc.signatures[0].clone();
                qc.signatures = vec![one; 10];
            }
        }
        assert!(validate_sync_chain(&dup, 1, genesis, &vs3).is_err());
    }

    /// Audit F8: sync must enforce the proposer schedule (as `adopt_committed`
    /// does) and refuse blocks from another shard.
    #[test]
    fn sync_checks_proposer_schedule_and_shard() {
        let keys: Vec<SigningKey> = (0..4).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let fks: Vec<FalconKeypair> = keys
            .iter()
            .map(|k| {
                let fk = FalconKeypair::generate();
                crate::consensus::register_validator_pq_key(
                    k.verifying_key().to_bytes(),
                    crate::post_quantum::PqScheme::Falcon512,
                    fk.public_key.clone(),
                );
                fk
            })
            .collect();
        let all_keys: Vec<(SigningKey, FalconKeypair)> =
            keys.clone().into_iter().zip(fks.clone()).collect();
        let vs = crate::consensus::ValidatorSet::from_list(
            keys.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let idx_of = |id: [u8; 32]| {
            keys.iter()
                .position(|k| k.verifying_key().to_bytes() == id)
                .unwrap()
        };
        // Build a genuine block at `h` on `prev`, signed by validator
        // `proposer_idx`, carrying a full precommit QC.
        let mk = |h: u64, prev: [u8; 32], proposer_idx: usize, shard: u32| -> Block {
            let mut b = Block {
                shard_id: shard,
                height: h,
                prev_hash: prev,
                state_root: [0u8; 32],
                transactions: vec![],
                cross_shard_out: vec![],
                timestamp: h,
                proposer: keys[proposer_idx].verifying_key().to_bytes(),
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                order_merkle_root: [0u8; 32],
                epoch_key_commitment: [0u8; 32],
                mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            };
            b.sign_block(&keys[proposer_idx]);
            let hash = b.compute_hash();
            b.precommit_qc = Some(pq_cert_for(h, 0, hash, prev, &vs, &all_keys));
            b
        };
        let sched = |h: u64| vs.proposer_for(h, 0).unwrap();
        let b1 = mk(1, [0u8; 32], idx_of(sched(1)), MASTERCHAIN_SHARD);
        let b2 = mk(2, b1.compute_hash(), idx_of(sched(2)), MASTERCHAIN_SHARD);
        let b3 = mk(3, b2.compute_hash(), idx_of(sched(3)), MASTERCHAIN_SHARD);
        let good = vec![b1.clone(), b2.clone(), b3.clone()];
        let genesis = [0u8; 32];
        assert!(validate_sync_chain(&good, 1, genesis, &vs).is_ok());

        // A block signed by a MEMBER that is not the scheduled proposer for its
        // slot must be refused, even though the QC is a genuine quorum.
        let wrong_idx = (idx_of(sched(1)) + 1) % keys.len();
        let wrong = mk(1, [0u8; 32], wrong_idx, MASTERCHAIN_SHARD);
        let err =
            validate_sync_chain(&[wrong, b2.clone(), b3.clone()], 1, genesis, &vs).unwrap_err();
        assert!(
            err.contains("schedule slot"),
            "non-scheduled proposer must be refused: {err}"
        );

        // Shard binding: these are shard-0 blocks; a shard-1 expectation refuses,
        // and the matching expectation accepts.
        assert!(
            validate_sync_chain_for_shard(&good, 1, genesis, &vs, 1).is_err(),
            "wrong-shard chain must be refused"
        );
        assert!(validate_sync_chain_for_shard(&good, 1, genesis, &vs, 0).is_ok());

        // A chain that mixes shards must also be refused.
        let mut mixed = b2.clone();
        mixed.shard_id = 1;
        let err = validate_sync_chain(&[b1, mixed, b3], 1, genesis, &vs).unwrap_err();
        assert!(
            err.contains("shard"),
            "mixed-shard chain must be refused: {err}"
        );
    }

    #[tokio::test]
    async fn missing_parent_and_overlong_chain_are_errors() {
        let blocks = chain(3);
        let head = blocks[3].compute_hash();
        // Empty source -> missing block error.
        let err = collect_missing_blocks(head, [0u8; 32], 100, |_h| async { None }).await;
        assert!(err.is_err());
        // max_len smaller than the gap -> length error.
        let map: HashMap<[u8; 32], Block> = blocks
            .iter()
            .map(|b| (b.compute_hash(), b.clone()))
            .collect();
        let genesis = blocks[0].compute_hash();
        let err2 = collect_missing_blocks(head, genesis, 1, |h| {
            let b = map.get(&h).cloned();
            async move { b }
        })
        .await;
        assert!(err2.is_err());
    }

    #[tokio::test]
    async fn fast_sync_state_verifies_root_and_applies() {
        use crate::state_engine::{AccountState, InMemoryStateEngine};

        let source = InMemoryStateEngine::new();
        let user = [0x55u8; 32];
        source
            .update_account(AccountState::new(user, 777_000))
            .await;
        let root = source.get_state_root().await;
        let snap = source.create_snapshot().await;

        let target = InMemoryStateEngine::new();
        // Fast-sync into the clean target engine (no domains: empty chain):
        fast_sync_state(
            &target,
            root,
            || async { Some(snap.clone()) },
            |_| async { None },
        )
        .await
        .unwrap();

        assert_eq!(target.get_state_root().await, root);
        assert_eq!(target.get_account(&user).await.unwrap().balance, 777_000);
    }

    #[tokio::test]
    async fn fast_sync_state_rejects_poisoned_snapshot() {
        use crate::state_engine::{AccountState, InMemoryStateEngine};

        let source = InMemoryStateEngine::new();
        let user = [0x55u8; 32];
        source
            .update_account(AccountState::new(user, 777_000))
            .await;
        let genuine_root = source.get_state_root().await;

        // Attacker creates a poisoned snapshot where balance is 999_999_999:
        let attacker_engine = InMemoryStateEngine::new();
        attacker_engine
            .update_account(AccountState::new(user, 999_999_999))
            .await;
        let poisoned_snap = attacker_engine.create_snapshot().await;

        let target = InMemoryStateEngine::new();
        // Providing the poisoned snapshot against genuine_root MUST be rejected!
        let res = fast_sync_state(
            &target,
            genuine_root,
            || async { Some(poisoned_snap.clone()) },
            |_| async { None },
        )
        .await;
        assert!(res.is_err(), "poisoned snapshot must be rejected");
        assert!(
            target.get_account(&user).await.is_none(),
            "target state must remain untouched"
        );
    }

    #[tokio::test]
    async fn fast_sync_state_carries_domains_not_just_accounts() {
        // F-J (audit follow-up): accounts-only restores fail the root check
        // on any chain with domain activity — the bundle must travel.
        use crate::state_engine::{AccountState, InMemoryStateEngine};
        use crate::token::{TokenMetadata, ZERO_ADDRESS};

        let source = InMemoryStateEngine::new();
        let user = [0x66u8; 32];
        source
            .update_account(AccountState::new(user, 1_000_000))
            .await;
        let meta = TokenMetadata {
            name: "Sync".into(),
            symbol: "SYN".into(),
            decimals: 6,
            total_supply: 0,
            max_supply: None,
            minter: ZERO_ADDRESS,
            paused: false,
            description: String::new(),
        };
        let tid = source.create_token(user, meta, 500).await.unwrap();
        let root = source.get_state_root().await;
        let snap = source.create_snapshot().await;
        // Domain blobs exactly as the publish path captures them.
        let staking = source.staking_read().await.clone();
        let gov = source.governance_read().await.clone();
        let dom = crate::storage::DomainSnapshot::capture(&source, &staking, &gov).await;
        let domains: std::collections::HashMap<String, Vec<u8>> =
            [("domains", bincode::serialize(&dom).unwrap())]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect();

        let target = InMemoryStateEngine::new();
        fast_sync_state(
            &target,
            root,
            || async { Some(snap.clone()) },
            |kind: &'static str| {
                let domains = domains.clone();
                async move { domains.get(kind).cloned() }
            },
        )
        .await
        .expect("sync with domains must verify");
        assert_eq!(target.get_state_root().await, root);
        assert_eq!(target.token_balance(&tid, &user).await, 500);

        // And WITHOUT the domains the same snapshot must FAIL the root check
        // (this is the pre-fix behavior that stranded far-behind nodes).
        let bare = InMemoryStateEngine::new();
        let res = fast_sync_state(
            &bare,
            root,
            || async { Some(snap.clone()) },
            |_| async { None },
        )
        .await;
        assert!(
            res.is_err(),
            "accounts-only must not verify on a live chain"
        );
    }

    #[tokio::test]
    async fn sync_domain_kinds_registers_pq_keys() {
        use crate::state_engine::InMemoryStateEngine;

        assert!(
            SYNC_DOMAIN_KINDS.contains(&"pq_keys"),
            "SEC-PQ-08: SYNC_DOMAIN_KINDS must register pq_keys domain"
        );

        let source = InMemoryStateEngine::new();
        let root = source.get_state_root().await;
        let snap = source.create_snapshot().await;

        let target = InMemoryStateEngine::new();
        let requested_domains = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let requested_clone = requested_domains.clone();

        let _ = fast_sync_state(
            &target,
            root,
            || async { Some(snap.clone()) },
            |kind: &'static str| {
                let req = requested_clone.clone();
                async move {
                    req.lock().unwrap().push(kind);
                    None
                }
            },
        )
        .await;

        let reqs = requested_domains.lock().unwrap().clone();
        assert!(
            reqs.contains(&"pq_keys"),
            "fast_sync_state must fetch pq_keys domain"
        );
    }

    // ==================== F3(a): mismatched body rejected ====================

    #[tokio::test]
    async fn collect_missing_blocks_rejects_a_body_that_does_not_hash_to_the_request() {
        let blocks = chain(3);
        let genesis = blocks[0].compute_hash();
        let head = blocks[3].compute_hash();
        // Every request is answered with block #1's body, which does NOT hash to
        // the requested key. The old walk would follow its `prev_hash` and
        // re-anchor onto a chain nobody asked for.
        let impostor = blocks[1].clone();
        let err = collect_missing_blocks(head, genesis, 100, move |_h| {
            let b = impostor.clone();
            async move { Some(b) }
        })
        .await
        .expect_err("a body filed under the wrong hash must be refused");
        assert!(
            err.contains("does not hash"),
            "error names the mismatch: {err}"
        );
    }

    // ==================== XSHARD: forged msg_id refused, trust cleared ====================

    fn xshard_test_message() -> crate::sharding::CrossShardMessage {
        let tx = crate::sharding::Transaction {
            from: [0x11u8; 32],
            to: [0x22u8; 32],
            amount: 1_000,
            gas_limit: 21_000,
            nonce: 7,
            source_shard: 1,
            target_shard: MASTERCHAIN_SHARD,
            signature: vec![0x5Au8; 64],
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        };
        crate::sharding::CrossShardMessage::new(1, MASTERCHAIN_SHARD, tx, [0x33u8; 32], [0x44u8; 32], None)
    }

    #[tokio::test]
    async fn collect_missing_blocks_refuses_a_forged_msg_id_and_clears_wire_trust() {
        let blocks = chain(3);
        let genesis = blocks[0].compute_hash();

        // A block that honestly carries one cross-shard message (served with
        // the wire `trusted` bit SET, as a Byzantine serializer would): the
        // walk adopts it, but the message arrives untrusted.
        let mut carrier = blocks[1].clone();
        let mut honest_msg = xshard_test_message();
        honest_msg.trusted = true;
        carrier.cross_shard_out = vec![honest_msg];
        carrier.prev_hash = genesis;
        let carrier_hash = carrier.compute_hash();
        let mut map: HashMap<[u8; 32], Block> = blocks
            .iter()
            .map(|b| (b.compute_hash(), b.clone()))
            .collect();
        map.insert(carrier_hash, carrier.clone());
        let got = collect_missing_blocks(carrier_hash, genesis, 100, |h| {
            let b = map.get(&h).cloned();
            async move { b }
        })
        .await
        .expect("an honestly-identified carrier must be adopted");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].cross_shard_out.len(), 1);
        assert!(
            got[0].cross_shard_out[0].verify_msg_id(),
            "the adopted message carries its construction id"
        );
        assert!(
            !got[0].cross_shard_out[0].trusted,
            "no adopted message may arrive trusted (wire bit cleared at the boundary)"
        );

        // A carrier whose message id was rebound (bit flip, then re-hashed so
        // the body check passes) is refused at the adoption boundary.
        let mut forged = blocks[2].clone();
        let mut forged_msg = xshard_test_message();
        forged_msg.msg_id[0] ^= 0xFF;
        forged.cross_shard_out = vec![forged_msg];
        forged.prev_hash = genesis;
        let forged_hash = forged.compute_hash();
        let err = collect_missing_blocks(forged_hash, genesis, 100, move |h| {
            let b = (h == forged_hash).then(|| forged.clone());
            async move { b }
        })
        .await
        .expect_err("a carrier with a forged msg_id must be refused");
        assert!(
            err.contains("forged msg_id"),
            "error names the forgery: {err}"
        );
    }

    // ==================== F1: hash-linked snapshot anchor ====================

    #[tokio::test]
    async fn snapshot_anchor_accepts_a_chain_linked_to_our_finalized_head() {
        // Our finalized head is block #2; the snapshot's successor is #5.
        // Every link carries its QC; the set is the chain's own signers.
        let blocks = quorum_chain(5, 2);
        let head_hash = blocks[2].compute_hash();
        let vs = set_from(&blocks[2]);
        let links: HashMap<u64, HeaderLink> =
            blocks.iter().map(|b| (b.height, qc_link(b))).collect();
        let root =
            verify_snapshot_anchor(Some((2, head_hash)), [0u8; 32], 5, &vs, 1_000_000, |h| {
                let l = links.get(&h).cloned();
                async move { l }
            })
            .await
            .expect("a genuine QC-anchored chain from our own finalized head must anchor");
        assert_eq!(root.state_root, blocks[5].state_root);
    }

    #[tokio::test]
    async fn snapshot_anchor_rejects_a_forged_header_with_arbitrary_state_root() {
        // A peer offers a header at #5 with an ARBITRARY state_root and a
        // broken parent link (it is not part of our chain). This is exactly the
        // header a snapshot-forgery needs: a root the peer chose and a snapshot
        // that hashes to it.
        let blocks = quorum_chain(5, 2);
        let head_hash = blocks[2].compute_hash();
        let vs = set_from(&blocks[2]);
        let mut links: HashMap<u64, HeaderLink> =
            blocks.iter().map(|b| (b.height, qc_link(b))).collect();
        links.insert(
            5,
            HeaderLink {
                height: 5,
                block_hash: [0xEE; 32],
                prev_hash: [0xBA; 32],  // not #4's hash: the link is broken
                state_root: [0xEE; 32], // arbitrary forged root
                proposer: [0u8; 32],
                qc: blocks[5].precommit_qc.clone().unwrap(),
            },
        );
        let err = verify_snapshot_anchor(Some((2, head_hash)), [0u8; 32], 5, &vs, 1_000_000, |h| {
            let l = links.get(&h).cloned();
            async move { l }
        })
        .await
        .expect_err("a forged, unlinked header must be refused");
        assert!(
            err.contains("does not link"),
            "error names the broken anchor: {err}"
        );
    }

    #[tokio::test]
    async fn snapshot_anchor_rejects_a_forged_but_fully_linked_chain() {
        // A1 CORE: the attacker builds a FULLY HASH-LINKED chain under our
        // anchor height with an arbitrary state root, signed by ATTACKER keys
        // (valid signatures, non-member QCs, correct attacker-side proposer
        // schedule). Linkage alone accepts it; the QC membership gate must
        // refuse it.
        use ed25519_dalek::SigningKey as Sk;
        let honest = quorum_chain(5, 2);
        let head_hash = honest[2].compute_hash();
        let honest_vs = set_from(&honest[2]);
        // Attacker committee (disjoint keys) + its validator set.
        let evil_keys: Vec<Sk> = (0..3).map(|_| Sk::generate(&mut OsRng)).collect();
        let evil_fks: Vec<FalconKeypair> = evil_keys
            .iter()
            .map(|k| {
                let fk = FalconKeypair::generate();
                crate::consensus::register_validator_pq_key(
                    k.verifying_key().to_bytes(),
                    crate::post_quantum::PqScheme::Falcon512,
                    fk.public_key.clone(),
                );
                fk
            })
            .collect();
        let evil_all: Vec<(Sk, FalconKeypair)> = evil_keys
            .clone()
            .into_iter()
            .zip(evil_fks.clone().into_iter())
            .collect();
        let evil_vs = crate::consensus::ValidatorSet::from_list(
            evil_keys
                .iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let mut links: HashMap<u64, HeaderLink> = honest
            .iter()
            .take(3)
            .map(|b| (b.height, qc_link(b)))
            .collect();
        // Heights 3-5 come from the attacker chain, linked onto our #2, with
        // a forged root throughout.
        let mut prev = head_hash;
        for h in 3..=5u64 {
            let proposer_id = evil_vs.proposer_for(h, 0).expect("non-empty set");
            let proposer = evil_keys
                .iter()
                .find(|k| k.verifying_key().to_bytes() == proposer_id)
                .expect("proposer is a member")
                .clone();
            let mut eb = Block {
                shard_id: MASTERCHAIN_SHARD,
                height: h,
                prev_hash: prev,
                state_root: [0xEE; 32], // the forged root
                transactions: vec![],
                cross_shard_out: vec![],
                timestamp: h,
                proposer: proposer_id,
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                order_merkle_root: [0u8; 32],
                epoch_key_commitment: [0u8; 32],
                mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
            };
            eb.sign_block(&proposer);
            let hash = eb.compute_hash();
            eb.precommit_qc = Some(pq_cert_for(h, 0, hash, prev, &evil_vs, &evil_all));
            let link = qc_link(&eb);
            prev = link.block_hash;
            links.insert(h, link);
        }
        let err = verify_snapshot_anchor(
            Some((2, head_hash)),
            [0u8; 32],
            5,
            &honest_vs,
            1_000_000,
            |h| {
                let l = links.get(&h).cloned();
                async move { l }
            },
        )
        .await
        .expect_err("a linked-but-attacker-signed chain must be refused");
        assert!(
            err.contains("quorum") || err.contains("finality"),
            "error names the QC gate, not linkage: {err}"
        );
    }

    #[tokio::test]
    async fn snapshot_anchor_rejects_a_missing_header_in_the_walk() {
        // Height 3 is absent: an attacker cannot skip a link.
        let blocks = quorum_chain(5, 2);
        let head_hash = blocks[2].compute_hash();
        let vs = set_from(&blocks[2]);
        let links: HashMap<u64, HeaderLink> = blocks
            .iter()
            .filter(|b| b.height != 3)
            .map(|b| (b.height, qc_link(b)))
            .collect();
        let err = verify_snapshot_anchor(Some((2, head_hash)), [0u8; 32], 5, &vs, 1_000_000, |h| {
            let l = links.get(&h).cloned();
            async move { l }
        })
        .await
        .expect_err("a gap in the header walk must be refused");
        assert!(
            err.contains("no header published"),
            "error names the gap: {err}"
        );
    }

    #[tokio::test]
    async fn snapshot_anchor_at_genesis_requires_the_root_sentinel_link() {
        // At genesis there is no finalized head; the chain roots at [0u8; 32].
        // Links carry real single-signer QCs (A1: linkage without quorum is
        // refused, so even the synthetic genesis walk is QC-gated).
        let gk = SigningKey::generate(&mut OsRng);
        let gfk = FalconKeypair::generate();
        crate::consensus::register_validator_pq_key(
            gk.verifying_key().to_bytes(),
            crate::post_quantum::PqScheme::Falcon512,
            gfk.public_key.clone(),
        );
        let gpk = gk.verifying_key().to_bytes();
        let vs = crate::consensus::ValidatorSet::from_list(vec![(gpk, 1)]);
        let gkeys = vec![(gk.clone(), gfk.clone())];
        let mk_link = |h: u64, prev: [u8; 32], root: [u8; 32]| {
            let block_hash = [h as u8; 32];
            let qc = pq_cert_for(h, 0, block_hash, prev, &vs, &gkeys);
            HeaderLink {
                height: h,
                block_hash,
                prev_hash: prev,
                state_root: root,
                proposer: gpk,
                qc,
            }
        };
        let mut links: HashMap<u64, HeaderLink> = HashMap::new();
        let mut prev = [0u8; 32];
        for h in 1..=3u64 {
            links.insert(h, mk_link(h, prev, [h as u8; 32]));
            prev = [h as u8; 32];
        }
        let root = verify_snapshot_anchor(None, [0u8; 32], 3, &vs, 1_000_000, |h| {
            let l = links.get(&h).cloned();
            async move { l }
        })
        .await
        .expect("a chain rooted at genesis must anchor");
        assert_eq!(root.state_root, [3u8; 32]);

        // Break the very first link: nothing may be trusted.
        let mut broken = links.clone();
        broken.insert(1, mk_link(1, [0xCC; 32], [0xCC; 32]));
        assert!(
            verify_snapshot_anchor(None, [0u8; 32], 3, &vs, 1_000_000, |h| {
                let l = broken.get(&h).cloned();
                async move { l }
            })
            .await
            .is_err(),
            "a header not rooted at the genesis sentinel must be refused"
        );
    }

    #[tokio::test]
    async fn snapshot_anchor_enforces_max_span() {
        // A far-ahead boundary with a tiny span budget is refused without
        // fetching the whole range (no unbounded verify loop).
        let blocks = quorum_chain(5, 2);
        let head_hash = blocks[2].compute_hash();
        let vs = set_from(&blocks[2]);
        let links: HashMap<u64, HeaderLink> =
            blocks.iter().map(|b| (b.height, qc_link(b))).collect();
        let err = verify_snapshot_anchor(
            Some((2, head_hash)),
            [0u8; 32],
            5,
            &vs,
            1, // span 3 > 1: refuse before walking
            |h| {
                let l = links.get(&h).cloned();
                async move { l }
            },
        )
        .await
        .expect_err("span over budget must be refused");
        assert!(err.contains("max_span"), "error names the bound: {err}");
    }

    #[tokio::test]
    async fn snapshot_anchor_refuses_rotated_set_fail_closed() {
        // QCs valid under set B do not verify under a disjoint stale set A:
        // rotation + gap refuses (liveness cost, documented) rather than
        // trusting.
        let blocks = quorum_chain(5, 2);
        let head_hash = blocks[2].compute_hash();
        let stale = crate::consensus::ValidatorSet::from_list(vec![([0xF0u8; 32], 1)]);
        let links: HashMap<u64, HeaderLink> =
            blocks.iter().map(|b| (b.height, qc_link(b))).collect();
        let err =
            verify_snapshot_anchor(Some((2, head_hash)), [0u8; 32], 5, &stale, 1_000_000, |h| {
                let l = links.get(&h).cloned();
                async move { l }
            })
            .await
            .expect_err("stale disjoint set must not verify foreign QCs");
        assert!(
            err.contains("quorum") || err.contains("finality"),
            "error names the QC gate: {err}"
        );
    }

    // ==================== F3(b): advertised-head desync ====================

    #[test]
    fn walked_head_anchor_refuses_an_advertised_height_above_the_walked_height() {
        let blocks = chain(5);
        let head_hash = blocks[5].compute_hash();
        // The walk stopped at #5 but the peer advertised #9: refuse the desync.
        let err = walked_head_anchor(&blocks, head_hash, 9)
            .expect_err("an advertised height above the walked head must be refused");
        assert!(err.contains("advertised"), "error names the desync: {err}");

        // A walked tail that does not hash to the advertised head is refused too.
        let err2 = walked_head_anchor(&blocks, [0xAB; 32], 5)
            .expect_err("a walked tail not matching the advertised hash must be refused");
        assert!(
            err2.contains("does not hash"),
            "error names the hash mismatch: {err2}"
        );

        // The honest case re-anchors on the WALKED height + 1.
        assert_eq!(walked_head_anchor(&blocks, head_hash, 5).unwrap(), 6);
    }
}

#[cfg(test)]
mod repl_tests {
    use super::*;

    fn test_block(height: u64) -> Block {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let mut b = Block {
            shard_id: crate::sharding::MASTERCHAIN_SHARD,
            height,
            prev_hash: [0u8; 32],
            state_root: [height as u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: height,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        };
        b.sign_block(&sk);
        b
    }

    #[test]
    fn replicated_body_must_hash_to_the_committed_header() {
        let b = test_block(9);
        let h = b.compute_hash();
        assert!(verify_replicated_body(&h, &b).is_ok());
        // Tampered body (one byte in a committed field) is rejected.
        let mut tampered = b.clone();
        tampered.timestamp ^= 0xFF;
        let err = verify_replicated_body(&h, &tampered).expect_err("tamper must be refused");
        assert!(err.contains("rejected"), "{err}");
        // Filed under the wrong hash is rejected too.
        assert!(verify_replicated_body(&[0xEEu8; 32], &b).is_err());
    }

    #[test]
    fn replicated_bytes_decode_and_verify_in_one_step() {
        let b = test_block(3);
        let h = b.compute_hash();
        let bytes = bincode::serialize(&b).unwrap();
        assert_eq!(
            verify_replicated_bytes(&h, &bytes).unwrap().compute_hash(),
            h
        );
        assert!(verify_replicated_bytes(&[0xAAu8; 32], &bytes).is_err());
        assert!(verify_replicated_bytes(&h, &[0xFF, 0x00]).is_err());
    }

    #[test]
    fn backfill_is_bounded_tip_ward_and_respects_windows() {
        // A node 1000 behind with cap 64 fetches the 64 nearest the tip first.
        let plan =
            plan_backfill_tip_ward(0, 1000, 64, ADOPT_REPL_KEEP_WINDOW, ADOPT_REPL_RETRO_DEPTH);
        assert_eq!(plan.len(), 64);
        assert_eq!(plan[0], 937);
        assert_eq!(plan[63], 1000);
        // Small gaps fetch everything, oldest-first within the window.
        assert_eq!(
            plan_backfill_tip_ward(10, 13, 64, ADOPT_REPL_KEEP_WINDOW, ADOPT_REPL_RETRO_DEPTH),
            vec![11, 12, 13]
        );
        // Caught up / degenerate: nothing to fetch (never a storm).
        assert!(
            plan_backfill_tip_ward(5, 5, 64, ADOPT_REPL_KEEP_WINDOW, ADOPT_REPL_RETRO_DEPTH)
                .is_empty()
        );
        assert!(
            plan_backfill_tip_ward(5, 9, 0, ADOPT_REPL_KEEP_WINDOW, ADOPT_REPL_RETRO_DEPTH)
                .is_empty()
        );
        // Reuses the existing bounds: outside KEEP/retro the honest answer is
        // unavailability, not a fetch.
        assert!(!height_is_replicable(
            1,
            20_000,
            ADOPT_REPL_KEEP_WINDOW,
            ADOPT_REPL_RETRO_DEPTH
        ));
        assert!(height_is_replicable(
            19_900,
            20_000,
            ADOPT_REPL_KEEP_WINDOW,
            ADOPT_REPL_RETRO_DEPTH
        ));
        let old: Vec<u64> = plan_backfill_tip_ward(
            0,
            20_000,
            10_000,
            ADOPT_REPL_KEEP_WINDOW,
            ADOPT_REPL_RETRO_DEPTH,
        );
        assert!(!old.contains(&1), "pruned heights are never planned");
        assert_eq!(*old.last().unwrap(), 20_000);
    }
}

#[cfg(test)]
mod fanout_tests {
    use super::*;

    #[test]
    fn jittered_backoff_never_hurries_and_stays_capped() {
        // Floor is always the exponential base: jitter only delays.
        assert_eq!(
            fetch_retry_backoff_with_jitter_ms(1, 0),
            FETCH_RETRY_BASE_BACKOFF_MS
        );
        assert_eq!(fetch_retry_backoff_with_jitter_ms(1, 37), 137);
        assert_eq!(fetch_retry_backoff_with_jitter_ms(2, 100), 300);
        // Oversized draws clamp instead of blowing the ceiling.
        assert_eq!(
            fetch_retry_backoff_with_jitter_ms(1, u64::MAX),
            FETCH_RETRY_BASE_BACKOFF_MS + FETCH_RETRY_JITTER_MAX_MS
        );
        assert_eq!(
            fetch_retry_backoff_with_jitter_ms(100, u64::MAX),
            FETCH_RETRY_MAX_BACKOFF_MS + FETCH_RETRY_JITTER_MAX_MS
        );
        // Same attempt, different draws → different delays (de-synchronized
        // retries), both inside [base, base+JITTER_MAX].
        let a = fetch_retry_backoff_with_jitter_ms(3, 11);
        let b = fetch_retry_backoff_with_jitter_ms(3, 87);
        assert_ne!(a, b, "jitter must spread same-tick retries");
        for d in [a, b] {
            assert!(d >= fetch_retry_backoff_ms(3));
            assert!(d <= fetch_retry_backoff_ms(3) + FETCH_RETRY_JITTER_MAX_MS);
        }
    }

    #[test]
    fn chunk_batches_cover_exactly_and_serialize_large_blobs() {
        assert_eq!(FETCH_BLOB_CHUNK_BATCH, 4);
        assert_eq!(LARGE_BLOB_SERIAL_CHUNKS, 8);
        // Small blobs pipeline in bounded batches.
        assert_eq!(chunk_batch_for_blob(0), FETCH_BLOB_CHUNK_BATCH);
        assert_eq!(chunk_batch_for_blob(8), FETCH_BLOB_CHUNK_BATCH);
        // Large blobs (snapshot-sized) go strictly serial.
        assert_eq!(chunk_batch_for_blob(9), 1);
        assert_eq!(chunk_batch_for_blob(10_000), 1);
        // Batch ranges tile exactly: no gap, no overlap, no shortfall.
        assert!(plan_chunk_batches(0, 4).is_empty());
        assert_eq!(plan_chunk_batches(1, 4), vec![(0, 1)]);
        assert_eq!(plan_chunk_batches(4, 4), vec![(0, 4)]);
        assert_eq!(plan_chunk_batches(6, 4), vec![(0, 4), (4, 6)]);
        assert_eq!(
            plan_chunk_batches(9, 1),
            vec![
                (0, 1),
                (1, 2),
                (2, 3),
                (3, 4),
                (4, 5),
                (5, 6),
                (6, 7),
                (7, 8),
                (8, 9)
            ]
        );
        // Zero width saturates to serial instead of looping forever.
        assert_eq!(plan_chunk_batches(3, 0), vec![(0, 1), (1, 2), (2, 3)]);
        // Tiling property for a snapshot-sized blob.
        let n = 40usize;
        let batches = plan_chunk_batches(n, chunk_batch_for_blob(n));
        assert_eq!(batches.len(), n, "large blob: one chunk per batch");
        let flat: Vec<usize> = batches.iter().flat_map(|(s, e)| *s..*e).collect();
        assert_eq!(flat, (0..n).collect::<Vec<_>>());
    }

    #[test]
    fn snapshot_lane_is_narrower_than_the_fetch_pool() {
        assert_eq!(SNAPSHOT_FETCH_MAX_CONCURRENCY, 2);
    }

    #[test]
    fn retro_pace_jitter_only_dephases_never_hurries() {
        assert_eq!(
            retro_publish_pace_with_jitter_ms(0),
            crate::network::RETRO_PUBLISH_PACE_MS
        );
        assert_eq!(
            retro_publish_pace_with_jitter_ms(3),
            crate::network::RETRO_PUBLISH_PACE_MS + 3
        );
        assert_eq!(
            retro_publish_pace_with_jitter_ms(u64::MAX),
            crate::network::RETRO_PUBLISH_PACE_MS + RETRO_PUSH_JITTER_MAX_MS
        );
    }
}
