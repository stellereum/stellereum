// ===========================================================================
// Shard topology: split / merge / routing rule — unit tests.
//
// These are the IN-PROCESS tests behind `cargo test --lib sharding`. The
// reproducible LOAD test over a synthetic account set (and the trie
// migration over a real trie) lives in
// `tests/sharding_topology_tests.rs`.
// ===========================================================================

use super::topology::prefix_word_bit;
use super::*;

/// A deterministic synthetic account: the address is derived from the
/// index through splitmix64, so the same set is produced on every run
/// AND the addresses are spread over the whole 8-byte prefix window
/// (so both children of the first split are populated).
fn synthetic_address(i: u64) -> [u8; 32] {
    let mut z = i.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    let mut a = [0u8; 32];
    a[..8].copy_from_slice(&z.to_be_bytes());
    a[8..16].copy_from_slice(&z.rotate_left(17).to_be_bytes());
    a
}

fn topology_with(n: u64) -> ShardTopology {
    let mut t = ShardTopology::new();
    for i in 0..n {
        t.register_account(synthetic_address(i), 1_000 + i);
    }
    t
}

#[test]
fn published_thresholds_are_what_the_docs_say() {
    assert_eq!(MIN_ACCOUNTS_PER_SHARD, 100);
    assert_eq!(MAX_SHARDS, 16);
    assert_eq!(MAX_PREFIX_BITS, 60);
    assert_eq!(MAX_WORKCHAIN_SHARD_SPACE, 1u64 << 60);
    assert_eq!(SHARD_SPLIT_LOAD_THRESHOLD, 500);
    assert_eq!(SHARD_MERGE_LOAD_THRESHOLD, 50);
    // The advertised space and the shipped cap are deliberately
    // different numbers: the first is the address space, the second is
    // the capacity.
    assert!(MAX_WORKCHAIN_SHARD_SPACE > MAX_SHARDS as u64);
}

#[test]
fn a_bare_address_never_routes_to_the_masterchain() {
    let t = ShardTopology::new();
    for i in 0..64u64 {
        let a = synthetic_address(i);
        let routed = t.route(&ShardAddress::Workchain(a));
        assert_ne!(routed, MASTERCHAIN_SHARD);
        assert_eq!(routed, BASE_WORKCHAIN_SHARD_INITIAL);
    }
    // The masterchain form DOES route to the masterchain.
    assert_eq!(
        t.route(&ShardAddress::Masterchain(synthetic_address(0))),
        MASTERCHAIN_SHARD
    );
}

#[test]
fn the_masterchain_address_form_is_parsed_in_one_place() {
    // `-1:` is the masterchain; `0:` is the masterchain too (shard 0 IS
    // the masterchain id); `N:` names a workchain shard explicitly.
    assert_eq!(split_shard_prefix("-1:abc").0, Some(MASTERCHAIN_SHARD));
    assert_eq!(split_shard_prefix("0:abc").0, Some(MASTERCHAIN_SHARD));
    assert_eq!(split_shard_prefix("7:abc").0, Some(7));
    assert_eq!(split_shard_prefix("abc").0, None);
    assert_eq!(split_shard_prefix("-1:abc").1, "abc");
}

#[test]
fn a_split_reassigns_accounts_by_the_prefix_bit() {
    let mut t = topology_with(1000);
    t.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, 600);

    let transition = t
        .check_and_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .expect("the trigger fires: 1000 accounts, load 600");
    let [c0, c1] = transition.children;

    // Every account is now owned by exactly one child, and the bit at the
    // split depth decides which one.
    for acct in t.all_accounts() {
        let bit = address_prefix_bit(&acct.address, transition.plan.split_bit);
        let owner = t.owner_of(&acct.address).expect("owned");
        let expected = if bit == 0 { c0.shard_id } else { c1.shard_id };
        assert_eq!(owner, expected, "the prefix bit must decide the child");
    }
    // Both children are populated.
    assert!(!t.accounts_of(c0.shard_id).is_empty());
    assert!(!t.accounts_of(c1.shard_id).is_empty());
    // The invariants hold.
    t.verify_invariants()
        .expect("invariants hold after the split");
    // The total balance is conserved.
    assert_eq!(
        t.total_balance(),
        t.shard_balance(c0.shard_id) + t.shard_balance(c1.shard_id)
    );
}

#[test]
fn a_split_refuses_below_the_published_thresholds() {
    // Enough accounts, but not enough load.
    let t = topology_with(1000);
    assert_eq!(
        t.split_preconditions(BASE_WORKCHAIN_SHARD_INITIAL),
        Err(SplitRefusal::LoadTooLow {
            load: 0,
            threshold: SHARD_SPLIT_LOAD_THRESHOLD
        })
    );

    // Enough load, but too few accounts.
    let mut few = ShardTopology::new();
    for i in 0..MIN_ACCOUNTS_PER_SHARD - 1 {
        few.register_account(synthetic_address(i), 1);
    }
    few.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, 600);
    assert_eq!(
        few.split_preconditions(BASE_WORKCHAIN_SHARD_INITIAL),
        Err(SplitRefusal::TooFewAccounts {
            accounts: MIN_ACCOUNTS_PER_SHARD - 1,
            minimum: MIN_ACCOUNTS_PER_SHARD
        })
    );

    // The masterchain never splits.
    assert_eq!(
        t.split_preconditions(MASTERCHAIN_SHARD),
        Err(SplitRefusal::Masterchain)
    );

    // An unknown shard never splits.
    assert_eq!(t.split_preconditions(9999), Err(SplitRefusal::UnknownShard));
}

#[test]
fn the_shard_cap_is_enforced() {
    let mut t = ShardTopology::new();
    // Fill the topology up to the cap by splitting the base shard
    // repeatedly (each split needs the account minimum and the load).
    for i in 0..2000u64 {
        t.register_account(synthetic_address(i), 1);
    }
    let mut guard = 0;
    loop {
        // Find any shard that is eligible and split it.
        let candidates: Vec<ShardId> = t
            .shards()
            .map(|(id, _)| *id)
            .filter(|id| *id != MASTERCHAIN_SHARD)
            .collect();
        let mut progressed = false;
        for id in candidates {
            t.record_tx_load(id, SHARD_SPLIT_LOAD_THRESHOLD);
            if t.check_and_split(id).is_some() {
                progressed = true;
                break;
            }
        }
        if !progressed {
            break;
        }
        guard += 1;
        assert!(guard < 64, "the split loop must terminate");
        assert!(
            t.shard_count() <= MAX_SHARDS,
            "the topology must never exceed the published shard cap"
        );
    }
    assert_eq!(t.shard_count(), MAX_SHARDS);
    // With the cap reached, no further split is possible.
    let any_workchain = t
        .shards()
        .map(|(id, _)| *id)
        .find(|id| *id != MASTERCHAIN_SHARD)
        .unwrap();
    assert_eq!(
        t.split_preconditions(any_workchain),
        Err(SplitRefusal::ShardCapReached {
            shards: MAX_SHARDS,
            cap: MAX_SHARDS
        })
    );
}

#[test]
fn a_merge_is_the_inverse_of_the_split() {
    let mut t = topology_with(1000);
    t.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, 600);
    let total_before = t.total_balance();
    let accounts_before = t.all_accounts();

    let transition = t
        .check_and_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .expect("split");
    let [c0, c1] = transition.children;

    // The load the split produced is above the merge threshold, so the
    // merge is refused right away — this is the anti-oscillation rule.
    assert_eq!(
        t.merge_preconditions(c0.shard_id, c1.shard_id),
        Err(MergeRefusal::LoadTooHigh {
            load: 600,
            threshold: SHARD_MERGE_LOAD_THRESHOLD
        })
    );

    // The load window rolls: the shard drains and becomes merge-eligible.
    t.decay_load(SHARD_SPLIT_LOAD_THRESHOLD);
    let merge = t
        .check_and_merge(c0.shard_id, c1.shard_id)
        .expect("merge after the load decayed");

    // Balances are conserved.
    assert_eq!(t.total_balance(), total_before);
    // Every account is back, with its balance.
    let accounts_after = t.all_accounts();
    assert_eq!(accounts_after.len(), accounts_before.len());
    for acct in &accounts_before {
        let now = t
            .accounts_of(merge.parent.shard_id)
            .iter()
            .find(|a| a.address == acct.address)
            .expect("the account is still there");
        assert_eq!(now.balance, acct.balance);
    }
    // The routing prefix is restored to the parent's depth.
    assert_eq!(merge.parent.prefix_len, 0);
    // The invariants hold.
    t.verify_invariants()
        .expect("invariants hold after the merge");
}

#[test]
fn the_topology_converges_and_never_oscillates() {
    let mut t = topology_with(1000);
    t.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, 600);
    t.check_and_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .expect("split");

    // Without new load, the topology is a FIXED POINT: no split and no
    // merge fires. This is the convergence property.
    let shards_after_split = t.shard_count();
    for _ in 0..8 {
        for id in t.shards().map(|(id, _)| *id).collect::<Vec<_>>() {
            assert!(t.check_and_split(id).is_none(), "no split may fire");
        }
        assert_eq!(t.shard_count(), shards_after_split);
    }
}

#[test]
fn non_sibling_shards_never_merge() {
    let mut t = topology_with(1000);
    t.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, 600);
    let split = t
        .check_and_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .expect("split");
    let [c0, _c1] = split.children;

    // The masterchain is never a merge partner.
    assert_eq!(
        t.merge_preconditions(MASTERCHAIN_SHARD, c0.shard_id),
        Err(MergeRefusal::Masterchain)
    );
    // A shard cannot merge with itself.
    assert_eq!(
        t.merge_preconditions(c0.shard_id, c0.shard_id),
        Err(MergeRefusal::NotSiblings)
    );
}

#[test]
fn the_routing_rule_follows_the_split() {
    let mut t = topology_with(200);
    t.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, 600);
    let split = t
        .check_and_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .expect("split");
    let [c0, c1] = split.children;

    for acct in t.all_accounts() {
        let routed = t.route(&ShardAddress::Workchain(acct.address));
        assert_eq!(routed, t.owner_of(&acct.address).unwrap());
        assert!(routed == c0.shard_id || routed == c1.shard_id);
    }
    // The masterchain is still never a bare-address destination.
    for acct in t.all_accounts() {
        assert_ne!(
            t.route(&ShardAddress::Workchain(acct.address)),
            MASTERCHAIN_SHARD
        );
    }
}

#[test]
fn the_address_prefix_bit_matches_the_prefix_word() {
    for i in 0..256u64 {
        let a = synthetic_address(i);
        // The full word reproduces the address bits exactly.
        let word = address_prefix_word(&a, 64);
        for bit in 0..8u8 {
            assert_eq!(address_prefix_bit(&a, bit), prefix_word_bit(word, bit));
        }
        // A truncated prefix word keeps the leading bits and zeroes the
        // rest — the same convention as a shard descriptor.
        for len in 0..=8u8 {
            let p = address_prefix_word(&a, len);
            if len == 0 {
                assert_eq!(p, 0);
            } else {
                // The bits BELOW the prefix are zeroed.
                assert_eq!(p & !(!0u64 << (64 - len as u64)), 0);
            }
            for bit in 0..len {
                assert_eq!(prefix_word_bit(p, bit), address_prefix_bit(&a, bit));
            }
        }
    }
}

#[test]
fn the_topology_report_publishes_the_thresholds() {
    let t = topology_with(1000);
    let report = t.report();
    assert_eq!(
        report.parameters.min_accounts_per_shard,
        MIN_ACCOUNTS_PER_SHARD
    );
    assert_eq!(report.parameters.max_shards, MAX_SHARDS);
    assert_eq!(
        report.parameters.split_load_threshold,
        SHARD_SPLIT_LOAD_THRESHOLD
    );
    assert_eq!(
        report.parameters.merge_load_threshold,
        SHARD_MERGE_LOAD_THRESHOLD
    );
    assert_eq!(report.parameters.max_prefix_bits, MAX_PREFIX_BITS);
    assert_eq!(
        report.parameters.max_workchain_shard_space,
        MAX_WORKCHAIN_SHARD_SPACE
    );
    assert_eq!(report.parameters.masterchain_shard, MASTERCHAIN_SHARD);
    assert_eq!(
        report.parameters.base_workchain_shard,
        BASE_WORKCHAIN_SHARD_INITIAL
    );
    assert_eq!(report.parameters.masterchain_address_form, "-1:<addr>");
    assert_eq!(report.total_accounts, 1000);
    assert_eq!(report.shards.len(), 2);
    // The report is JSON-serializable (the RPC layer serves it).
    let json = serde_json::to_value(&report).expect("serializable");
    assert!(json.get("parameters").is_some());
    assert!(json.get("shards").is_some());
}
