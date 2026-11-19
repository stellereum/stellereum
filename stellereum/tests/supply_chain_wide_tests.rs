//! CHAIN-WIDE `TOTAL_SUPPLY_CAP` (ruleset v5).
//!
//! These tests pin the fix for the last known economics gap: the cap used to
//! be enforced by a counter inside ONE [`InMemoryStateEngine`], so N
//! workchains could each mint a full cap. The model now is:
//!
//! * every shard engine gets a deterministic STATIC share of the cap
//!   ([`stellereum::tokenomics::SupplyPartition`]), installed from the
//!   committed shard set — no env, clock or peer input;
//! * the masterchain's signed shard-head commitments carry each workchain's
//!   CUMULATIVE minted total (including its genesis pre-mine);
//! * the masterchain aggregates those committed totals and REFUSES a header
//!   that would take the sum above the cap;
//! * the aggregate is a pure function of the committed headers, so a restart
//!   replays it identically.
//!
//! The per-engine counter still holds as defence in depth; see
//! `per_engine_guard_still_holds_after_the_partition`.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::ValidatorSet;
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{
    FinalizedHeaderRegistry, ShardHeaderCommitment, ShardRegistry, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::tokenomics::{SupplyPartition, TOTAL_SUPPLY_CAP};

const STELL: u64 = 1_000_000_000;

fn addr(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn head(shard: u32, height: u64, minted_total_nano: u64) -> ShardHeaderCommitment {
    ShardHeaderCommitment {
        shard_id: shard,
        height,
        block_hash: [shard as u8; 32],
        state_root: [shard.wrapping_add(1) as u8; 32],
        timestamp: 1_760_000_000 + height,
        minted_total_nano,
    }
}

fn masterchain_runtime(
    registry: ShardRegistry,
    headers: FinalizedHeaderRegistry,
) -> ValidatorRuntime {
    let key = SigningKey::generate(&mut OsRng);
    let me = key.verifying_key().to_bytes();
    let state = std::sync::Arc::new(InMemoryStateEngine::new());
    let validators = ValidatorSet::from_list(vec![(me, 1)]);
    let hdrs = std::sync::Arc::new(std::sync::RwLock::new(headers));
    ValidatorRuntime::new(key, validators, state, 1)
        .with_shard(MASTERCHAIN_SHARD, registry)
        .with_finalized_headers(hdrs)
}

/// The joint cap, not a per-engine cap: on a two-shard chain each shard gets
/// HALF the cap, and once both have minted their half the aggregate is exactly
/// the cap. A further mint is refused on both sides.
#[tokio::test]
async fn two_shards_cannot_jointly_mint_past_the_chain_cap() {
    let partition = SupplyPartition::uniform([MASTERCHAIN_SHARD, 1]);
    assert_eq!(
        partition.total_nano(),
        TOTAL_SUPPLY_CAP as u128,
        "the partition must allocate the whole cap, never more"
    );
    let share = partition.quota_for(MASTERCHAIN_SHARD);
    assert_eq!(share, TOTAL_SUPPLY_CAP / 2);
    assert_eq!(partition.quota_for(1), TOTAL_SUPPLY_CAP / 2);

    let master = InMemoryStateEngine::new();
    let workchain = InMemoryStateEngine::new();
    master.set_chain_mint_limit_nano(partition.quota_for(MASTERCHAIN_SHARD));
    workchain.set_chain_mint_limit_nano(partition.quota_for(1));

    // A single engine may no longer mint the FULL chain cap: its share is the
    // joint cap divided by the shard count.
    assert!(
        master.mint_native(&addr(0x01), TOTAL_SUPPLY_CAP).await.is_err(),
        "a shard must not be able to mint the whole chain cap"
    );

    // Each shard mints just under its half.
    master
        .mint_native(&addr(0x02), share - 7)
        .await
        .expect("masterchain share is mintable");
    workchain
        .mint_native(&addr(0x03), share - 7)
        .await
        .expect("workchain share is mintable");

    let aggregate = master.committed_minted_nano().await as u128
        + workchain.committed_minted_nano().await as u128;
    assert_eq!(
        aggregate,
        TOTAL_SUPPLY_CAP as u128 - 14,
        "both shards' totals add up to the chain aggregate"
    );

    // Only 7 nanos of local headroom remain on each side. A mint that needs
    // more is refused; the JOINT budget is exhausted even though neither
    // engine ever saw more than its own share.
    assert!(master.mint_native(&addr(0x04), 8).await.is_err());
    assert!(workchain.mint_native(&addr(0x05), 8).await.is_err());
    assert_eq!(
        master.committed_minted_nano().await as u128
            + workchain.committed_minted_nano().await as u128,
        aggregate,
        "refusals must not move the aggregate"
    );

    // Fill both shares exactly: the chain is now at the cap.
    master.mint_native(&addr(0x06), 7).await.unwrap();
    workchain.mint_native(&addr(0x07), 7).await.unwrap();
    assert_eq!(
        master.committed_minted_nano().await as u128
            + workchain.committed_minted_nano().await as u128,
        TOTAL_SUPPLY_CAP as u128
    );
    assert!(master.mint_native(&addr(0x08), 1).await.is_err());
    assert!(workchain.mint_native(&addr(0x09), 1).await.is_err());
}

/// Genesis pre-mine on two workchains is part of the aggregate, not a free
/// allocation outside it. It consumes the shard's share from height 0.
#[tokio::test]
async fn genesis_premine_on_two_workchains_counts_toward_the_aggregate() {
    let genesis_a = 3 * STELL;
    let genesis_b = 5 * STELL;
    // The masterchain is not part of this pair; shards 1 and 2 split the cap.
    let partition =
        SupplyPartition::from_quotas([(1u32, TOTAL_SUPPLY_CAP / 2), (2u32, TOTAL_SUPPLY_CAP / 2)])
            .expect("a two-workchain partition fits the cap");

    let shard_a = InMemoryStateEngine::new();
    let shard_b = InMemoryStateEngine::new();
    shard_a.set_chain_mint_limit_nano(partition.quota_for(1));
    shard_b.set_chain_mint_limit_nano(partition.quota_for(2));

    // Genesis funding uses the UNCAPPED transfer primitive exactly like
    // `fund_shard_genesis`, so only the chain-wide accounting can see it.
    shard_a
        .update_account(AccountState::new(addr(0xA1), genesis_a))
        .await;
    shard_b
        .update_account(AccountState::new(addr(0xB2), genesis_b))
        .await;

    let total_a = shard_a.committed_minted_nano().await;
    let total_b = shard_b.committed_minted_nano().await;
    assert_eq!(total_a, genesis_a, "pre-mine is reported before any mint");
    assert_eq!(total_b, genesis_b);

    let mut registry = FinalizedHeaderRegistry::default();
    registry.note_finalized_commitment(head(1, 0, total_a));
    registry.note_finalized_commitment(head(2, 0, total_b));
    assert_eq!(
        registry.committed_minted_total_nano(),
        genesis_a as u128 + genesis_b as u128,
        "the committed aggregate counts BOTH workchain genesis allocations"
    );

    // Each shard may still mint only up to its share INCLUDING genesis.
    shard_a
        .mint_native(&addr(0xA3), TOTAL_SUPPLY_CAP / 2 - genesis_a)
        .await
        .expect("the rest of shard 1's share is mintable");
    shard_b
        .mint_native(&addr(0xB4), TOTAL_SUPPLY_CAP / 2 - genesis_b)
        .await
        .expect("the rest of shard 2's share is mintable");

    let aggregate = shard_a.committed_minted_nano().await as u128
        + shard_b.committed_minted_nano().await as u128;
    assert_eq!(
        aggregate,
        TOTAL_SUPPLY_CAP as u128,
        "genesis + emission on both workchains is exactly the chain cap"
    );
    assert!(shard_a.mint_native(&addr(0xA5), 1).await.is_err());
    assert!(shard_b.mint_native(&addr(0xB6), 1).await.is_err());

    // A header that reports only post-genesis EMISSION understates the
    // shard's cumulative total by exactly the genesis allocation, and the
    // committed head (which includes genesis) is what the masterchain uses.
    let emission_only = TOTAL_SUPPLY_CAP / 2 - genesis_a;
    let mut committed = FinalizedHeaderRegistry::default();
    committed.note_finalized_commitment(head(1, 1, TOTAL_SUPPLY_CAP / 2));
    assert_eq!(
        committed.committed_minted_for(1).unwrap() - emission_only,
        genesis_a,
        "the difference between the committed total and emission-only IS the genesis pre-mine"
    );
}

/// The masterchain REFUSES a workchain head whose declared minted total would
/// exceed the cap. Before the fix the header carried no minted total at all,
/// so this proposal was indistinguishable from an honest one.
#[test]
fn masterchain_refuses_a_workchain_head_above_the_chain_cap() {
    let registry = ShardRegistry::from_ids([MASTERCHAIN_SHARD, 1]);
    let rt = masterchain_runtime(registry, FinalizedHeaderRegistry::default());

    let mut block = stellereum::sharding::Block {
        height: 1,
        shard_headers: vec![head(1, 1, TOTAL_SUPPLY_CAP + 1)],
        ..Default::default()
    };
    let err = rt
        .check_chain_supply_commitment(&block)
        .expect_err("a declared total above the cap must be refused");
    assert!(
        err.contains("TOTAL_SUPPLY_CAP") || err.contains("chain-wide supply share"),
        "unexpected refusal: {err}"
    );

    // At/under the cap on this shard alone is accepted by the supply check.
    block.shard_headers = vec![head(1, 1, TOTAL_SUPPLY_CAP / 2)];
    rt.check_chain_supply_commitment(&block)
        .expect("a head inside its chain-wide share is accepted");

    // The AGGREGATE path: the masterchain's own committed total plus the
    // proposed heads must not exceed the cap, even when no single term is
    // above the global cap. Shards 2/3 are outside this node's configured
    // partition, so the per-share check cannot fire; the SUM check is what
    // refuses the proposal.
    let mut headers = FinalizedHeaderRegistry::default();
    headers.note_finalized_commitment(head(MASTERCHAIN_SHARD, 1, TOTAL_SUPPLY_CAP / 2));
    let rt = masterchain_runtime(ShardRegistry::from_ids([MASTERCHAIN_SHARD, 1]), headers);
    block.shard_headers = vec![
        head(2, 2, TOTAL_SUPPLY_CAP / 2),
        head(3, 2, TOTAL_SUPPLY_CAP / 2),
    ];
    let err = rt
        .check_chain_supply_commitment(&block)
        .expect_err("the SUM over shards must be refused, not only each term");
    assert!(
        err.contains("chain-wide supply cap exceeded"),
        "unexpected refusal: {err}"
    );
}

/// The aggregate is restored IDENTICALLY from committed headers: same serialized
/// registry, same total; replaying the delta into a fresh registry also lands on
/// the same value.
#[test]
fn committed_aggregate_is_identical_after_restart_and_replay() {
    let mut live = FinalizedHeaderRegistry::default();
    live.note_finalized_commitment(head(MASTERCHAIN_SHARD, 11, 7 * STELL));
    live.note_finalized_commitment(head(1, 5, 3 * STELL));
    live.note_finalized_commitment(head(2, 9, 5 * STELL));
    let expected = live.committed_minted_total_nano();
    assert_eq!(expected, 15 * STELL as u128);

    // Snapshot -> restart.
    let bytes = live.to_bytes().expect("registry snapshot");
    let restored = FinalizedHeaderRegistry::from_bytes(&bytes).expect("registry restore");
    assert_eq!(
        restored.committed_minted_total_nano(),
        expected,
        "a restart must derive the same chain-wide aggregate"
    );

    // Delta replay (the live/adopt path) into a fresh registry.
    let mut replayed = FinalizedHeaderRegistry::default();
    replayed
        .apply_delta(live.to_delta())
        .expect("delta replay must be accepted");
    assert_eq!(replayed.committed_minted_total_nano(), expected);

    // A newer head for one shard replaces that shard's contribution; the sum
    // is still a pure function of the committed heads.
    let mut newer = replayed.clone();
    newer.note_finalized_commitment(head(1, 6, 4 * STELL));
    assert_eq!(
        newer.committed_minted_total_nano(),
        expected + STELL as u128,
        "only the replaced shard's delta moves the aggregate"
    );
}

/// The static partition is deterministic in the shard SET (order-independent)
/// and never allocates more than the cap, for every supported shard count.
#[test]
fn uniform_partition_is_deterministic_and_never_exceeds_the_cap() {
    for n in 1u32..=16 {
        let ascending = SupplyPartition::uniform(0..n);
        let mut descending_ids: Vec<u32> = (0..n).collect();
        descending_ids.reverse();
        let descending = SupplyPartition::uniform(descending_ids);
        assert_eq!(
            ascending, descending,
            "input order must not move any quota (n={n})"
        );
        assert_eq!(
            ascending.total_nano(),
            TOTAL_SUPPLY_CAP as u128,
            "the partition allocates the cap exactly, never more (n={n})"
        );
        let sum: u128 = ascending.quotas().map(|(_, q)| q as u128).sum();
        assert_eq!(sum, TOTAL_SUPPLY_CAP as u128);
    }
}

/// Honest lag bound: the last committed aggregate can only TIGHTEN a shard's
/// static share, never loosen it. A stale view that undercounts the other
/// shards therefore still cannot let this shard mint past its share.
#[test]
fn lagging_aggregate_view_tightens_but_never_loosens_the_static_share() {
    let partition = SupplyPartition::uniform([MASTERCHAIN_SHARD, 1]);
    let share = partition.quota_for(1);
    assert_eq!(
        partition.bounded_limit_nano(1, None, 0),
        share,
        "with no committed view the shard uses its static share (under-mint, never over-mint)"
    );
    assert_eq!(
        partition.bounded_limit_nano(1, Some(0), 0),
        share,
        "a lagging view that says 'nobody minted' cannot widen the static share"
    );
    assert_eq!(
        partition.bounded_limit_nano(1, Some(TOTAL_SUPPLY_CAP as u128), 0),
        0,
        "a fully consumed aggregate leaves this shard no global room"
    );
    assert_eq!(
        partition.bounded_limit_nano(1, Some(share as u128), share),
        share,
        "the shard's own committed total is not charged twice"
    );
    assert_eq!(
        partition.bounded_limit_nano(1, Some(u128::MAX), 0),
        0,
        "an impossible aggregate saturates to zero, never wraps past the cap"
    );
}

/// Defence in depth: the per-engine guard is still enforced. Even a shard
/// whose static share is the full cap refuses one nano past it.
#[tokio::test]
async fn per_engine_guard_still_holds_after_the_partition() {
    let engine = InMemoryStateEngine::new();
    assert_eq!(engine.chain_mint_limit_nano(), TOTAL_SUPPLY_CAP);
    engine
        .mint_native(&addr(0xC1), TOTAL_SUPPLY_CAP)
        .await
        .expect("the full cap is mintable on a single-shard chain");
    let err = engine
        .mint_native(&addr(0xC2), 1)
        .await
        .expect_err("the per-engine guard must still fail closed");
    assert!(err.contains("global supply cap"), "unexpected error: {err}");
    assert_eq!(engine.committed_minted_nano().await, TOTAL_SUPPLY_CAP);
}
