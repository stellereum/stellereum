use super::adopt::encode_committed_loopback;
use super::catchup::effective_catchup_pass_budget;
use super::propose::proposal_parent_is_finalized;
use super::*;
use stellereum::consensus::VoteKind;
use stellereum::consensus_net::parse_incoming_with_peer_key;

mod parked_replay_tests {
    use super::*;

    /// A parked commit is re-injected as an ordinary `Committed` frame, so the
    /// next drain runs the full adopt arm (validation + persistence +
    /// publication/receipts). Pin the exact framing: encode -> parse must
    /// yield the same height/body/certificate, attributed to the local replay
    /// source.
    #[test]
    fn parked_commit_loopback_round_trips_through_the_drain_parser() {
        let block = stellereum::sharding::Block {
            height: 7,
            round: 2,
            ..Default::default()
        };
        let bh = block.compute_hash();
        let certificate = stellereum::consensus::QuorumCertificate {
            height: 7,
            round: 2,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            signatures: vec![],
            shard_id: block.shard_id,
        };
        let raw = encode_committed_loopback(7, &block, &certificate, "local-replay")
            .expect("parked commit must encode");
        let (msg, src) = parse_incoming_with_peer_key(&raw).expect("loopback frame must parse");
        // The parser's second value is the PEER KEY used for attribution, not
        // the informational "src" label the loopback JSON also carries; a
        // frame without a peer key is a local broadcast frame.
        assert_eq!(src, "broadcast");
        match msg {
            ConsensusMsg::Committed {
                height,
                block: b,
                certificate: c,
            } => {
                assert_eq!(height, 7);
                assert_eq!(b.compute_hash(), bh);
                assert_eq!(c.height, 7);
                assert_eq!(c.block_hash, Some(bh));
            }
            _ => panic!("loopback frame must decode as Committed"),
        }
    }
}

mod vote_watermark_tests {
    use super::*;
    use stellereum::storage::{ConsensusCheckpoint, Storage, VoteWatermark, VoteWatermarkEntry};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "stell-vote-watermark-{tag}-{}-{nanos}",
            std::process::id()
        ))
    }

    /// FINDING C: a crash AFTER a prevote at round 300 but BEFORE the next
    /// consensus checkpoint must not lose the vote. The write-ahead watermark
    /// survives the reopen, raises the resumed round above the liveness cap
    /// (64), and forbids every vote at a round <= 300 for that height.
    ///
    /// (Fails before the fix: there was no watermark at all — only the
    /// checkpoint, which still says round 0 — so the node resumed at round 0
    /// and could re-vote 0..=300.)
    #[test]
    fn crash_after_prevote_never_rewinds_or_revotes() {
        let dir = temp_dir("prevote300");
        {
            let st = Storage::open(&dir).expect("open");
            // The checkpoint predates the vote: round 0 at height 7.
            st.set_consensus(&ConsensusCheckpoint {
                height: 7,
                round: 0,
                locked_hash: None,
                locked_round: 0,
                finalized_height: 6,
                finalized_hash: [9u8; 32],
            })
            .expect("checkpoint");
            // The vote was cast at round 300, fsynced BEFORE the broadcast.
            let mut wm = VoteWatermark::default();
            wm.note(VoteWatermarkEntry {
                height: 7,
                round: 300,
                kind: 0, // prevote
                target: Some([1u8; 32]),
                shard_id: 1,
            });
            st.persist_vote_watermark(&wm).expect("watermark durable");
        } // "crash": drop the storage handle

        let st = Storage::open(&dir).expect("reopen after crash");
        let wm = st
            .vote_watermark()
            .expect("read watermark")
            .expect("watermark survived the crash");
        let cp = st
            .consensus()
            .expect("read checkpoint")
            .expect("checkpoint");
        assert_eq!(cp.round, 0, "the checkpoint still predates the vote");
        let entry = wm.prevote_at(7).expect("prevote at height 7");
        assert_eq!(entry.round, 300);
        assert_eq!(entry.shard_id, 1);
        assert_eq!(entry.target, Some([1u8; 32]));

        // The restore rule (the PRODUCTION helper): `min(cap)` is LIVENESS;
        // the vote watermark is a hard FLOOR that the cap must never rewind
        // below.
        let floor = wm.floor_round(7).expect("floor at height 7");
        let restored = restored_round(cp.round, Some(floor));
        assert_eq!(
            restored, 300,
            "the resumed round must not rewind below the cast vote"
        );

        // And no vote at any round <= 300 for this height may be cast.
        for round in 0..=300u32 {
            assert!(
                round_at_or_below_vote_floor(Some((7, floor)), 7, round),
                "round {round} must be refused"
            );
        }
        assert!(!round_at_or_below_vote_floor(Some((7, floor)), 7, 301));
        // A different height is not governed by this height's floor.
        assert!(!round_at_or_below_vote_floor(Some((7, floor)), 8, 0));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// FINDING C: the precommit watermark is independent of the prevote one,
    /// so a crash between the two does not let the node lose (or duplicate)
    /// either statement.
    #[test]
    fn prevote_and_precommit_watermarks_are_independent() {
        let dir = temp_dir("two-kinds");
        {
            let st = Storage::open(&dir).expect("open");
            let mut wm = VoteWatermark::default();
            wm.note(VoteWatermarkEntry {
                height: 4,
                round: 11,
                kind: 0,
                target: Some([2u8; 32]),
                shard_id: 0,
            });
            st.persist_vote_watermark(&wm).expect("prevote");
            wm.note(VoteWatermarkEntry {
                height: 4,
                round: 11,
                kind: 1,
                target: Some([2u8; 32]),
                shard_id: 0,
            });
            st.persist_vote_watermark(&wm).expect("precommit");
        }
        let st = Storage::open(&dir).expect("reopen");
        let wm = st.vote_watermark().unwrap().unwrap();
        assert_eq!(wm.prevote_at(4).unwrap().round, 11);
        assert_eq!(wm.precommit_at(4).unwrap().round, 11);
        assert_eq!(wm.floor_round(4), Some(11));

        // A nil prevote is a real signed statement: `target == None` must
        // round-trip (it is not "no vote").
        let mut wm2 = wm.clone();
        wm2.note(VoteWatermarkEntry {
            height: 5,
            round: 12,
            kind: 0,
            target: None,
            shard_id: 0,
        });
        st.persist_vote_watermark(&wm2).unwrap();
        let wm3 = st.vote_watermark().unwrap().unwrap();
        assert_eq!(wm3.prevote_at(5).unwrap().target, None);
        assert_eq!(wm3.floor_round(5), Some(12));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A LATE POLKA'S PRECOMMIT IS NOT BLOCKED BY THE PREVOTE FLOOR.
    ///
    /// The live shape: a validator raced to round 11 and signed nil prevotes
    /// there, then the quorum-completing prevotes of round 0 arrive. The
    /// polka is precommitted at r0 (its own round). The union `floor_round`
    /// is 11 and would refuse that precommit, parking the height even though
    /// the precommit is a different (height, round, kind) statement and the
    /// node signed no precommit below it. The PRECOMMIT floor is still
    /// enforced: a round this node already precommitted in is refused.
    #[test]
    fn late_polka_precommit_ignores_the_prevote_floor() {
        // Prevoted nil at r11, never precommitted at this height.
        let prevote_floor = Some((7, 11));
        let precommit_floor: Option<(u64, u32)> = None;
        assert!(round_at_or_below_vote_floor(prevote_floor, 7, 0));
        assert!(
            !round_at_or_below_vote_floor(precommit_floor, 7, 0),
            "the r0 precommit of a late polka must not be refused by the r11 prevote floor"
        );
        // ...but a precommit at a round already precommitted is still refused.
        let precommit_floor = Some((7, 11));
        assert!(round_at_or_below_vote_floor(precommit_floor, 7, 0));
        assert!(round_at_or_below_vote_floor(precommit_floor, 7, 11));
        assert!(!round_at_or_below_vote_floor(precommit_floor, 7, 12));
        // A different height is governed by its own floor.
        assert!(!round_at_or_below_vote_floor(precommit_floor, 8, 0));
    }
}

mod restart_height_tests {
    use super::*;

    /// The stored finalize pointer normally wins; the engine state can only be
    /// older (slower) than it, and that gap is healed elsewhere.
    #[test]
    fn a_snapshot_at_or_below_the_finalized_tip_keeps_the_stored_tip() {
        let stored = Some((40u64, [7u8; 32]));
        for state in [0u64, 39, 40] {
            assert_eq!(
                reconciled_finalized_tip(state, stored, |_| panic!("must not resolve")),
                Ok(stored),
                "state {state} must not override a finalized tip at 40"
            );
        }
        assert_eq!(
            reconciled_finalized_tip(0, None, |_| panic!("must not resolve")),
            Ok(None)
        );
    }

    /// HEIGHT-SPLIT: when the state snapshot is AHEAD of the stored pointer,
    /// the state height is final (the loader verified its root against block
    /// S+1) and must become the tip — never leave `hc.height = S+1` paired
    /// with a parent F we did not finalize.
    #[test]
    fn an_engine_ahead_of_the_pointer_repairs_the_tip_from_the_local_header() {
        let hash = [0x5Au8; 32];
        let got = reconciled_finalized_tip(55, Some((50, [0x11; 32])), |s| {
            assert_eq!(s, 55);
            Some(hash)
        });
        assert_eq!(got, Ok(Some((55, hash))));
        // No pointer at all + a restored state: same repair.
        let got = reconciled_finalized_tip(9, None, |_| Some([0x99; 32]));
        assert_eq!(got, Ok(Some((9, [0x99; 32]))));
    }

    /// No local proof of the state height's block hash -> fail closed. Running
    /// with the stale parent would propose above an unfinalized parent and the
    /// catch-up walk would anchor behind the engine, wedging both paths.
    #[test]
    fn an_unprovable_ahead_state_is_refused() {
        let got = reconciled_finalized_tip(55, Some((50, [0x11; 32])), |_| None);
        assert!(got.is_err(), "an unprovable head must never be used");
    }

    /// Proposing is only meaningful at exactly `finalized_tip + 1`; every
    /// other relationship builds a block peers refuse (a height gap or a
    /// reused parent).
    #[test]
    fn proposals_only_at_the_next_finalized_parent() {
        assert!(proposal_parent_is_finalized(0, 1), "genesis child");
        assert!(proposal_parent_is_finalized(5, 6));
        assert!(
            !proposal_parent_is_finalized(5, 5),
            "parent already decided"
        );
        assert!(!proposal_parent_is_finalized(5, 7), "skips a height");
        assert!(!proposal_parent_is_finalized(5, 4));
        assert!(!proposal_parent_is_finalized(u64::MAX, u64::MAX));
    }

    #[test]
    fn periodic_retransmit_dedups_against_signed_round_not_local_round() {
        let b = stellereum::sharding::Block {
            height: 9,
            round: 2,
            ..Default::default()
        };
        let mut outbox = std::collections::VecDeque::new();
        assert!(!outbox_has_proposal(&outbox, b.height, b.round));
        assert!(enqueue_outbox(
            &mut outbox,
            stellereum::consensus_net::proposal_gossip_msg(&b, b.round),
        ));
        // Even when local hc.round is 5 > b.round (2), checking (b.height, b.round)
        // recognizes the already-queued signed-round proposal and avoids duplicate enqueue.
        assert!(!outbox_has_proposal(&outbox, 9, 5));
        assert!(outbox_has_proposal(&outbox, b.height, b.round));
    }

    #[tokio::test]
    async fn write_ahead_finalized_block_persists_block_and_tip_before_safety_flush() {
        let dir = std::env::temp_dir().join(format!(
            "stell_write_ahead_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let st =
            std::sync::Arc::new(stellereum::storage::Storage::open(&dir).expect("open storage"));
        let ap = stellereum::storage::AsyncPersistence::start(st.clone());

        let mut b1 = stellereum::sharding::Block {
            height: 1,
            prev_hash: [0u8; 32],
            ..Default::default()
        };
        let h1 = b1.compute_hash();
        b1.precommit_qc = Some(stellereum::consensus::QuorumCertificate {
            height: 1,
            round: 0,
            kind: stellereum::consensus::VoteKind::Precommit,
            block_hash: Some(h1),
            signatures: vec![],
            shard_id: 0,
        });

        write_ahead_finalized_block(&ap, 1, h1, b1.clone(), true)
            .await
            .expect("write_ahead_finalized_block");
        assert_eq!(st.finalized().unwrap(), Some((1, h1)));
        let stored = st.get_block(&h1).unwrap().expect("stored block 1");
        assert_eq!(stored.compute_hash(), h1);
        assert!(stored.precommit_qc.is_some());

        drop(ap);
        drop(st);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

mod publish_and_catchup_policy_tests {
    use super::*;

    #[test]
    fn small_gap_live_catchup_budget_is_capped_at_120ms() {
        let base = Duration::from_millis(2_000);
        // Live chain (< 1500ms since last finalize/adopt) + blind probe (gap == 0) => 120ms cap.
        assert_eq!(
            effective_catchup_pass_budget(base, 0, Duration::from_millis(250)),
            Duration::from_millis(120)
        );
        assert_eq!(
            effective_catchup_pass_budget(base, 0, Duration::from_millis(1_499)),
            Duration::from_millis(120)
        );
        // Smaller base stays untouched for blind probe.
        assert_eq!(
            effective_catchup_pass_budget(Duration::from_millis(80), 0, Duration::from_millis(200)),
            Duration::from_millis(80)
        );
        // Verified ahead evidence (gap >= 1) ALWAYS keeps full base budget even on a live chain.
        assert_eq!(
            effective_catchup_pass_budget(base, 1, Duration::from_millis(200)),
            base
        );
        assert_eq!(
            effective_catchup_pass_budget(base, 2, Duration::from_millis(1_499)),
            base
        );
        assert_eq!(
            effective_catchup_pass_budget(base, 3, Duration::from_millis(100)),
            base
        );
        // Stalled chain (>= 1500ms) keeps full base budget even for blind probes.
        assert_eq!(
            effective_catchup_pass_budget(base, 0, Duration::from_millis(1_500)),
            base
        );
    }

    #[test]
    fn dht_publish_gates_suppress_redundant_non_proposer_writes() {
        // Small validator sets (<= 2) always publish immediately.
        for v in [1usize, 2] {
            for h in 1..=9u64 {
                assert!(should_publish_body_now(v, false, h));
                assert!(should_publish_header_now(v, false, h));
            }
        }
        // On a 4-validator cluster, the proposer always publishes immediately.
        for h in 1..=9u64 {
            assert!(should_publish_body_now(4, true, h));
            assert!(should_publish_header_now(4, true, h));
        }
        // Non-proposers only reinforce on mod-4 (body) / mod-8 (header).
        assert!(!should_publish_body_now(4, false, 1));
        assert!(!should_publish_body_now(4, false, 3));
        assert!(should_publish_body_now(4, false, 4));
        assert!(should_publish_body_now(4, false, 8));

        assert!(!should_publish_header_now(4, false, 4));
        assert!(should_publish_header_now(4, false, 8));
    }
}

mod r3_driver_pq_tests {
    use super::*;

    struct GateGuard;
    impl GateGuard {
        fn at(h: u64) -> Self {
            stellereum::pq_registry::set_pq_lifecycle_activation_override(Some(h));
            Self
        }
    }
    impl Drop for GateGuard {
        fn drop(&mut self) {
            stellereum::pq_registry::set_pq_lifecycle_activation_override(None);
        }
    }

    #[test]
    fn peer_pq_keys_env_honored_before_w3_and_ignored_at_or_after_w3() {
        // This test deliberately CLEARS and replaces the process-global PQ
        // registry. Hold the ONE shared test lock for the whole body so a
        // parallel test that just registered/signed with its own keys cannot
        // have them wiped between registration and verification.
        let _global = crate::node::policy::test_support::global_lock();
        let _g = GateGuard::at(100);
        let peer_id = [0xD7u8; 32];
        let fk = stellereum::post_quantum::FalconKeypair::generate_from_seed(0xD7);
        let spec = format!("{}:{}", hex::encode(peer_id), hex::encode(&fk.public_key));

        stellereum::consensus::clear_validator_pq_keys_for_tests();
        stellereum::consensus::sync_committed_pq_registry(
            &stellereum::pq_registry::PqRegistry::new(),
            true,
        );

        // Pre-W3 (< 100): STELL_PEER_PQ_KEYS populates PQ_VALIDATOR_KEYS.
        apply_peer_pq_keys_env_at(50, Some(&spec));
        assert_eq!(
            stellereum::consensus::pq_key_at_height(&peer_id, 50),
            Some((
                stellereum::post_quantum::PqScheme::Falcon512,
                fk.public_key.clone()
            ))
        );

        // Reset legacy + committed maps, then test >= 100: STELL_PEER_PQ_KEYS is ignored.
        stellereum::consensus::clear_validator_pq_keys_for_tests();
        stellereum::consensus::sync_committed_pq_registry(
            &stellereum::pq_registry::PqRegistry::new(),
            true,
        );
        apply_peer_pq_keys_env_at(100, Some(&spec));
        assert_eq!(stellereum::consensus::pq_key_at_height(&peer_id, 100), None);
        assert_eq!(
            stellereum::consensus::get_validator_pq_key(&peer_id),
            None,
            "STELL_PEER_PQ_KEYS must not populate PQ_VALIDATOR_KEYS when pq_lifecycle_active_at(init_height) is true"
        );
    }
}

mod validator_self_check_tests {
    use super::*;

    #[test]
    fn self_check_is_silent_for_manageable_validator_and_loud_without_withdrawal() {
        let local = [0xA1u8; 32];
        let cold = [0xC0u8; 32];
        let mut ledger = stellereum::staking::StakingLedger::new();

        // Not bonded yet: explicit (non-eprintln) warning, never a silent skip.
        let missing = local_validator_self_check_message(&local, &ledger)
            .expect("missing record must be reported");
        assert!(!missing.0);
        assert!(missing.1.contains("NO staking record"));

        // Unclaimed pre-W3 record: LOUD and actionable, with the exact command.
        ledger
            .bond(
                local,
                stellereum::staking::required_bond_floor_nano(),
                stellereum::staking::DEFAULT_COMMISSION_BPS,
            )
            .unwrap();
        let unmanageable = local_validator_self_check_message(&local, &ledger)
            .expect("None withdrawal must be reported");
        assert!(unmanageable.0, "must also go to stderr");
        assert!(unmanageable.1.contains("UNMANAGEABLE"));
        assert!(unmanageable.1.contains("claim-withdrawal"));
        assert!(unmanageable.1.contains("SysCallClaimWithdrawal"));

        // Claimed record: healthy, no log at all.
        ledger
            .bond_with_withdrawal(
                [0xA2u8; 32],
                stellereum::staking::required_bond_floor_nano(),
                stellereum::staking::DEFAULT_COMMISSION_BPS,
                cold,
            )
            .unwrap();
        assert!(local_validator_self_check_message(&[0xA2u8; 32], &ledger).is_none());
    }
}
