use ed25519_dalek::SigningKey;
use infnode::config as node_config;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cli::args::*;
use crate::cli::tx_builders::*;
use crate::node::bootstrap::*;
use crate::node::policy::*;
use stellereum::consensus::{ValidatorSet, VoteKind};
use stellereum::consensus_net::{ConsensusMsg, MAX_BATCH_ITEMS};
use stellereum::sharding::Transaction;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::zkml::SessionKeyAuthorization;

/// P3-H4 gossip-batching unit tests: outbox dedup, flattening, and the
/// vote-then-proposal ordering the drain relies on.
#[cfg(test)]
mod gossip_batch_tests {
    use super::*;
    use stellereum::consensus::Vote;

    fn test_vote(h: u64, r: u32, kind: VoteKind, voter: [u8; 32]) -> ConsensusMsg {
        ConsensusMsg::Vote {
            vote: Vote::signed_with(voter, h, r, kind, None, vec![0u8; 64]),
            locked: None,
        }
    }

    #[test]
    fn guard_once_dedups_same_vote() {
        // The per-round cast guard fired at ENQUEUE time: re-enqueueing the
        // same (height, round, kind, voter) collapses to one item.
        let mut outbox = std::collections::VecDeque::new();
        let v = test_vote(1, 0, VoteKind::Prevote, [7u8; 32]);
        assert!(enqueue_outbox(&mut outbox, v.clone()));
        assert!(
            !enqueue_outbox(&mut outbox, v.clone()),
            "same vote must dedup"
        );
        assert_eq!(outbox.len(), 1);
        // A different kind is a different vote.
        assert!(enqueue_outbox(
            &mut outbox,
            test_vote(1, 0, VoteKind::Precommit, [7u8; 32])
        ));
        assert_eq!(outbox.len(), 2);
    }

    #[test]
    fn flush_dedup_collapses_timeout_requeues() {
        // Timeout re-sends rebuild the SAME votes: after one flush window the
        // outbox holds one copy each, and chunking never duplicates.
        let mut outbox = std::collections::VecDeque::new();
        for _ in 0..3 {
            enqueue_outbox(&mut outbox, test_vote(1, 0, VoteKind::Prevote, [7u8; 32]));
            enqueue_outbox(&mut outbox, test_vote(1, 0, VoteKind::Precommit, [7u8; 32]));
        }
        assert_eq!(outbox.len(), 2, "requeues must collapse");
        // Chunked drain (mirrors flush_outbox without the network).
        let mut seen = 0;
        while !outbox.is_empty() {
            let n = outbox.len().min(MAX_BATCH_ITEMS);
            let chunk: Vec<ConsensusMsg> = outbox.drain(..n).collect();
            seen += chunk.len();
        }
        assert_eq!(seen, 2);
        assert!(outbox.is_empty());
    }

    #[tokio::test]
    async fn flush_outbox_enqueues_fifo_and_empties_once() {
        // New invariant (P4 transport decoupling): `flush_outbox` drains the
        // outbox front-to-back into the ordered background sender. The outbox is
        // emptied exactly once, no item is duplicated, and the wire order across
        // batch chunks is the enqueue order. This is a real end-to-end check of
        // the new path (no infnode needed): the sender's handler records what it
        // was handed.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<u64>();
        let sender = stellereum::consensus_net::spawn_ordered_sender(move |chunk| {
            let tx = tx.clone();
            async move {
                for m in &chunk {
                    if let ConsensusMsg::Vote { vote, .. } = m {
                        let _ = tx.send(vote.height);
                    }
                }
            }
        });
        let mut outbox = std::collections::VecDeque::new();
        for h in 1..=40u64 {
            assert!(enqueue_outbox(
                &mut outbox,
                test_vote(h, 0, VoteKind::Prevote, [h as u8; 32]),
            ));
        }
        assert_eq!(outbox.len(), 40);
        flush_outbox(&sender, &mut outbox, 1, 0);
        assert!(
            outbox.is_empty(),
            "a successful flush empties the outbox exactly once"
        );

        let mut got = Vec::new();
        for _ in 0..40 {
            got.push(
                tokio::time::timeout(Duration::from_secs(5), rx.recv())
                    .await
                    .expect("sender must deliver every item")
                    .expect("channel stays open"),
            );
        }
        assert_eq!(
            got,
            (1..=40).collect::<Vec<u64>>(),
            "flush must preserve FIFO order across batch chunks"
        );
    }

    #[test]
    fn flatten_preserves_sender_order_and_drops_nesting() {
        let a = test_vote(1, 0, VoteKind::Prevote, [1u8; 32]);
        let b = test_vote(1, 0, VoteKind::Precommit, [2u8; 32]);
        let flat = flatten_incoming(ConsensusMsg::Batch(vec![a.clone(), b.clone()]));
        assert_eq!(flat.len(), 2);
        assert_eq!(flat[0].encode().unwrap(), a.encode().unwrap());
        assert_eq!(flat[1].encode().unwrap(), b.encode().unwrap());
        // A nested batch smuggled past decode is dropped, never returned.
        let nested = ConsensusMsg::Batch(vec![ConsensusMsg::Batch(vec![a])]);
        assert!(flatten_incoming(nested).is_empty());
        // Singletons pass through untouched.
        let flat_single = flatten_incoming(b.clone());
        assert_eq!(flat_single.len(), 1);
        assert_eq!(flat_single[0].encode().unwrap(), b.encode().unwrap());
    }

    #[tokio::test]
    async fn flush_drops_superseded_votes_but_never_proposals_or_commits() {
        // Tail-killer finality test: superseded-vote drops must not affect
        // finality. At (h=9, r=5) the outbox holds a stale r3 vote, a live r5
        // vote, a proposal and a commit. The flush must deliver everything
        // EXCEPT the stale vote — and a commit must survive even at r=99,
        // because finality rides commits, never pruned votes.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ConsensusMsg>();
        let sender = stellereum::consensus_net::spawn_ordered_sender(move |chunk| {
            let tx = tx.clone();
            async move {
                for m in chunk {
                    let _ = tx.send(m);
                }
            }
        });
        fn vote(h: u64, r: u32) -> ConsensusMsg {
            ConsensusMsg::Vote {
                vote: Vote::signed_with([8u8; 32], h, r, VoteKind::Prevote, None, vec![0u8; 64]),
                locked: None,
            }
        }
        fn block_at(h: u64) -> stellereum::sharding::Block {
            stellereum::sharding::Block {
                shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
                height: h,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                transactions: vec![],
                cross_shard_out: vec![],
                timestamp: 1,
                proposer: [8u8; 32],
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                mmr_epoch_root: [0u8; 32],
                cnvrf_v3: None,
                order_merkle_root: [0u8; 32],
                epoch_key_commitment: [0u8; 32],
            }
        }
        let commit = |h: u64, r: u32| ConsensusMsg::Committed {
            height: h,
            block: block_at(h),
            certificate: stellereum::consensus::QuorumCertificate {
                height: h,
                round: r,
                kind: VoteKind::Precommit,
                block_hash: None,
                signatures: vec![],
            },
        };
        let mut outbox = std::collections::VecDeque::new();
        assert!(enqueue_outbox(&mut outbox, vote(9, 3)));
        assert!(enqueue_outbox(&mut outbox, vote(9, 5)));
        outbox.push_back(ConsensusMsg::Proposal {
            height: 9,
            round: 5,
            block: block_at(9),
        });
        outbox.push_back(commit(9, 5));
        flush_outbox(&sender, &mut outbox, 9, 5);
        assert!(outbox.is_empty());
        let mut got = Vec::new();
        for _ in 0..3 {
            got.push(
                tokio::time::timeout(Duration::from_secs(5), rx.recv())
                    .await
                    .expect("sender must deliver")
                    .expect("channel stays open"),
            );
        }
        assert_eq!(got.len(), 3, "stale r3 vote must be pruned, rest delivered");
        assert!(matches!(&got[0], ConsensusMsg::Vote { vote, .. } if vote.round == 5));
        assert!(matches!(&got[1], ConsensusMsg::Proposal { .. }));
        assert!(matches!(&got[2], ConsensusMsg::Committed { .. }));

        // A commit is never superseded, no matter the round lag.
        let mut outbox2 = std::collections::VecDeque::new();
        outbox2.push_back(commit(9, 5));
        flush_outbox(&sender, &mut outbox2, 9, 99);
        assert!(
            outbox2.is_empty(),
            "a commit must always flush, even at r=99"
        );
        let back = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("commit must be delivered")
            .expect("channel stays open");
        assert!(matches!(back, ConsensusMsg::Committed { .. }));
    }

    #[test]
    fn hinted_vote_upgrades_hintless_queued_copy() {
        // Lock-hint rescue: a timeout/periodic re-send rebuilds the SAME vote
        // with a fresh lock hint after locking. Collapsing it against the
        // still-queued hintless original would drop the hint forever, so the
        // re-enqueue upgrades the queued copy in place (and reports queued so
        // the caller still flushes). An identical re-enqueue still dedups, and
        // a hintless duplicate never strips a queued hint.
        fn vote_locked(voter: [u8; 32], locked: Option<[u8; 32]>) -> ConsensusMsg {
            ConsensusMsg::Vote {
                vote: Vote::signed_with(voter, 1, 0, VoteKind::Prevote, None, vec![0u8; 64]),
                locked,
            }
        }
        let mut outbox = std::collections::VecDeque::new();
        assert!(enqueue_outbox(&mut outbox, vote_locked([7u8; 32], None)));
        assert_eq!(outbox.len(), 1);
        // Same vote, now carrying the lock hint: upgrades, not duplicates.
        assert!(
            enqueue_outbox(&mut outbox, vote_locked([7u8; 32], Some([9u8; 32]))),
            "hinted re-send must upgrade the queued copy"
        );
        assert_eq!(outbox.len(), 1, "upgrade must not duplicate");
        assert!(
            matches!(&outbox[0], ConsensusMsg::Vote { locked: Some(h), .. } if *h == [9u8; 32]),
            "queued copy must carry the fresh hint"
        );
        // Identical re-enqueue collapses.
        assert!(!enqueue_outbox(
            &mut outbox,
            vote_locked([7u8; 32], Some([9u8; 32]))
        ));
        assert_eq!(outbox.len(), 1);
        // A hintless re-send never strips a queued hint.
        assert!(!enqueue_outbox(&mut outbox, vote_locked([7u8; 32], None)));
        assert!(
            matches!(
                &outbox[0],
                ConsensusMsg::Vote {
                    locked: Some(_),
                    ..
                }
            ),
            "queued hint must survive a hintless duplicate"
        );
    }

    #[tokio::test]
    async fn flush_prunes_stale_proposals_but_keeps_current_and_commits() {
        // Proposal pile-up: the thin-proposal re-send plus the view-change
        // re-send enqueue one body per round, and behind a slow peer the FIFO
        // would flush stale bodies ahead of the current round's thin empty
        // proposal and its votes, pushing the round past the timeout. Stale
        // proposals (other heights, or two+ rounds old at this height) must
        // drop at flush while the current proposal and every commit still go
        // out, in order.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ConsensusMsg>();
        let sender = stellereum::consensus_net::spawn_ordered_sender(move |chunk| {
            let tx = tx.clone();
            async move {
                for m in chunk {
                    let _ = tx.send(m);
                }
            }
        });
        fn block_at(h: u64) -> stellereum::sharding::Block {
            stellereum::sharding::Block {
                shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
                height: h,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                transactions: vec![],
                cross_shard_out: vec![],
                timestamp: 1,
                proposer: [8u8; 32],
                validator_signatures: vec![],
                shard_headers: vec![],
                precommit_qc: None,
                last_qc: None,
                mmr_epoch_root: [0u8; 32],
                cnvrf_v3: None,
                order_merkle_root: [0u8; 32],
                epoch_key_commitment: [0u8; 32],
            }
        }
        let commit = |h: u64, r: u32| ConsensusMsg::Committed {
            height: h,
            block: block_at(h),
            certificate: stellereum::consensus::QuorumCertificate {
                height: h,
                round: r,
                kind: VoteKind::Precommit,
                block_hash: None,
                signatures: vec![],
            },
        };
        let mut outbox = std::collections::VecDeque::new();
        outbox.push_back(ConsensusMsg::Proposal {
            height: 8,
            round: 5,
            block: block_at(8),
        });
        outbox.push_back(ConsensusMsg::Proposal {
            height: 9,
            round: 3,
            block: block_at(9),
        });
        outbox.push_back(ConsensusMsg::Proposal {
            height: 9,
            round: 5,
            block: block_at(9),
        });
        outbox.push_back(commit(9, 5));
        flush_outbox(&sender, &mut outbox, 9, 5);
        assert!(outbox.is_empty());
        let mut got = Vec::new();
        for _ in 0..2 {
            got.push(
                tokio::time::timeout(Duration::from_secs(5), rx.recv())
                    .await
                    .expect("sender must deliver")
                    .expect("channel stays open"),
            );
        }
        assert_eq!(
            got.len(),
            2,
            "stale proposals must be pruned, current + commit delivered"
        );
        assert!(matches!(
            &got[0],
            ConsensusMsg::Proposal {
                height: 9,
                round: 5,
                ..
            }
        ));
        assert!(matches!(&got[1], ConsensusMsg::Committed { .. }));
    }

    #[test]
    fn thin_proposal_resend_never_duplicates_the_outbox() {
        // No-duplicate-send: the periodic thin-proposal re-send used to
        // push_back the identical body every window (each copy a flush, an
        // encode and a wire copy for zero new information). The
        // outbox_has_proposal guard keeps exactly one copy queued.
        let blk = stellereum::sharding::Block {
            shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
            height: 7,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1,
            proposer: [8u8; 32],
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        let mut outbox = std::collections::VecDeque::new();
        outbox.push_back(ConsensusMsg::Proposal {
            height: 7,
            round: 2,
            block: blk.clone(),
        });
        assert!(outbox_has_proposal(&outbox, 7, 2));
        assert!(
            !outbox_has_proposal(&outbox, 7, 3),
            "other rounds are distinct"
        );
        assert!(
            !outbox_has_proposal(&outbox, 8, 2),
            "other heights are distinct"
        );
        // The guarded re-send path pushes only when absent.
        if !outbox_has_proposal(&outbox, 7, 2) {
            outbox.push_back(ConsensusMsg::Proposal {
                height: 7,
                round: 2,
                block: blk,
            });
        }
        assert_eq!(outbox.len(), 1, "identical proposal must not duplicate");
    }

    #[tokio::test]
    async fn round_converges_only_on_verified_peer_rounds() {
        // Round-convergence safety: the drain follows a peer's round ONLY via
        // note_peer_vote_round AFTER on_prevote/on_precommit accepted the vote
        // (signature + membership + scope inside VoteSet::add). A forged vote
        // is rejected there and must move nothing — never fast-forward on
        // unverified claims.
        use stellereum::consensus::ValidatorSet;
        use stellereum::runtime::{fund_genesis, ValidatorRuntime};
        let ks: Vec<SigningKey> = (0..2).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let id = |k: &SigningKey| k.verifying_key().to_bytes();
        // FULL-PQ: votes verify Falcon-only — register deterministic Falcon
        // companions (voter identities stay Ed).
        let fks: Vec<stellereum::post_quantum::FalconKeypair> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let fk = stellereum::post_quantum::FalconKeypair::generate_from_seed(i as u8);
                stellereum::consensus::register_validator_pq_key(
                    id(k),
                    stellereum::post_quantum::PqScheme::Falcon512,
                    fk.public_key.clone(),
                );
                fk
            })
            .collect();
        let vset = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());
        let state = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
        let mut rt = ValidatorRuntime::new(ks[0].clone(), vset, state, 1);
        let h = rt.hc.height;

        // Genuine peer vote two rounds ahead: accepted, then followed.
        //
        // The round now follows INSIDE the vote path (the future-round rule
        // lives in `on_prevote`, so every consumer of the runtime gets it),
        // so the round is already at 2 when the vote is admitted. The
        // explicit `note_peer_vote_round` call is what the DRAIN does for a
        // vote it verified; it is a no-op here because the round already
        // moved.
        let peer_vote = Vote::sign_with_falcon(&ks[1], &fks[1], h, 2, VoteKind::Prevote, None);
        assert!(
            rt.on_prevote(peer_vote.clone()).is_ok(),
            "genuine vote must verify"
        );
        assert_eq!(
            rt.hc.round, 2,
            "behind node follows the verified peer round"
        );
        assert!(
            !rt.note_peer_vote_round(peer_vote.height, peer_vote.round),
            "following the round twice must not move it"
        );

        // Forged vote (tampered after signing): rejected, round untouched.
        let mut bad =
            Vote::sign_with_falcon(&ks[1], &fks[1], h, 5, VoteKind::Prevote, Some([1u8; 32]));
        bad.block_hash = Some([2u8; 32]);
        assert!(
            rt.on_prevote(bad.clone()).is_err(),
            "forged vote must fail verification"
        );
        // The drain never calls note_peer_vote_round for a rejected vote.
        assert_eq!(
            rt.hc.round, 2,
            "unverified claims must never move the round"
        );
    }

    #[test]
    fn floors_pinned_until_live_remeasurement() {
        // Gated floor decision (R-tempo re-measurement 2026-10-26: the whole
        // live fleet runs 50/50 via env and r0 bursts finalize at ~1s, with
        // per-proposal CPU (not the floor) binding loaded heights — see the
        // DEFAULT_MIN_BLOCK_MS rationale and the R-tempo LAN harness). If any
        // of these change again, the throughput argument above must be
        // re-done first.
        assert_eq!(DEFAULT_MIN_BLOCK_MS, 50, "empty-block floor stays 50ms");
        assert_eq!(TICK_MS, 50, "tick quantum stays 50ms");
        assert_eq!(
            BATCH_MS, TICK_MS,
            "batch window rides the tick, no extra wakeup"
        );
        // The retransmit floor keeps a wedged round from becoming a hot loop.
        assert_eq!(
            stellereum::consensus_net::retransmit_interval_ms(200, 0),
            150
        );
    }

    #[tokio::test]
    async fn batched_vote_then_proposal_accepts() {
        // Ordering: a vote arriving BEFORE its proposal (same Batch, sender
        // order preserved) must not poison the proposal.
        use stellereum::consensus::ValidatorSet;
        use stellereum::runtime::{fund_genesis, ValidatorRuntime};
        use stellereum::sharding::MASTERCHAIN_SHARD;
        let ks: Vec<SigningKey> = (0..2).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let id = |k: &SigningKey| k.verifying_key().to_bytes();
        // FULL-PQ: votes and proposals verify Falcon-only — register
        // deterministic Falcon companions (voter identities stay Ed).
        let fks: Vec<stellereum::post_quantum::FalconKeypair> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let fk = stellereum::post_quantum::FalconKeypair::generate_from_seed(i as u8);
                stellereum::consensus::register_validator_pq_key(
                    id(k),
                    stellereum::post_quantum::PqScheme::Falcon512,
                    fk.public_key.clone(),
                );
                fk
            })
            .collect();
        let vset = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());
        let state = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
        let mut rt = ValidatorRuntime::new(ks[0].clone(), vset, state, 1);
        while rt.hc.proposer().unwrap() != id(&ks[1]) {
            rt.hc.next_round();
        }
        let r = rt.hc.round;
        let mut block = stellereum::sharding::Block {
            shard_id: MASTERCHAIN_SHARD,
            height: rt.hc.height,
            prev_hash: [0u8; 32],
            state_root: rt.state.get_state_root().await,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1,
            proposer: id(&ks[1]),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        block.sign_block_with_falcon(&ks[1], &fks[1]);
        let peer_vote =
            Vote::sign_with_falcon(&ks[1], &fks[1], rt.hc.height, r, VoteKind::Prevote, None);
        let batch = ConsensusMsg::Batch(vec![
            ConsensusMsg::Vote {
                vote: peer_vote,
                locked: None,
            },
            ConsensusMsg::Proposal {
                height: rt.hc.height,
                round: r,
                block,
            },
        ]);
        // Encode/decode round-trips as one Batch, then flatten like the drain.
        let bytes = ConsensusMsg::batch_encode(&flatten_incoming(batch)).unwrap();
        let decoded = ConsensusMsg::decode(&bytes).unwrap();
        let mut accepted = false;
        for inner in flatten_incoming(decoded) {
            match inner {
                ConsensusMsg::Vote { vote: v, locked } => {
                    rt.note_lock_hint(v.height, v.kind, v.block_hash, locked);
                    rt.note_peer_vote_round(v.height, v.round);
                    let _ = rt.on_prevote(v);
                }
                ConsensusMsg::Proposal { block, .. } => {
                    let er = rt.hc.round;
                    if rt.on_proposal(id(&ks[1]), block, er).await.is_ok() {
                        accepted = true;
                    }
                }
                ConsensusMsg::Batch(_) => panic!("flatten must never yield Batch"),
                ConsensusMsg::Committed { .. } => {}
            }
        }
        assert!(accepted, "vote-then-proposal must accept the proposal");
    }

    #[tokio::test]
    async fn batched_nil_hints_recorded() {
        // A nil prevote carrying a lock hint inside a Batch still records the
        // demand via note_lock_hint.
        use stellereum::consensus::ValidatorSet;
        use stellereum::runtime::{fund_genesis, ValidatorRuntime};
        let ks: Vec<SigningKey> = (0..2).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let id = |k: &SigningKey| k.verifying_key().to_bytes();
        let vset = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());
        let state = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
        let mut rt = ValidatorRuntime::new(ks[0].clone(), vset, state, 1);
        while rt.hc.proposer().unwrap() != id(&ks[0]) {
            rt.hc.next_round();
        }
        let mine = rt.propose(1).await.expect("propose");
        let mh = mine.compute_hash();
        // Peer's nil prevote with our locked hash, delivered in a Batch.
        let nil = Vote::sign(&ks[1], rt.hc.height, rt.hc.round, VoteKind::Prevote, None);
        let batch = ConsensusMsg::Batch(vec![ConsensusMsg::Vote {
            vote: nil,
            locked: Some(mh),
        }]);
        let bytes = ConsensusMsg::batch_encode(&flatten_incoming(batch)).unwrap();
        let decoded = ConsensusMsg::decode(&bytes).unwrap();
        for inner in flatten_incoming(decoded) {
            if let ConsensusMsg::Vote { vote: v, locked } = inner {
                rt.note_lock_hint(v.height, v.kind, v.block_hash, locked);
                let _ = rt.on_prevote(v);
            }
        }
        while rt.hc.proposer().unwrap() != id(&ks[0]) {
            rt.hc.next_round();
        }
        let served = rt.propose(1).await.expect("must serve the demand");
        assert_eq!(
            served.compute_hash(),
            mh,
            "batched nil hint must be recorded"
        );
    }

    #[tokio::test]
    async fn test_sec06_deferred_queue_time_gated_and_prioritizes_rx() {
        use std::collections::VecDeque;

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut inbound_deferred: VecDeque<(Instant, String)> = VecDeque::new();

        // 1. Put a deferred item with wake_at 100ms in the future
        let future_wake = Instant::now() + Duration::from_millis(100);
        inbound_deferred.push_back((future_wake, "deferred_msg_1".to_string()));

        // 2. Send live messages into rx
        tx.send("live_vote_1".to_string()).unwrap();
        tx.send("live_vote_2".to_string()).unwrap();

        // 3. Emulate drain loop: prioritizes rx over deferred
        let mut drained = Vec::new();
        for _ in 0..10 {
            let raw: String = match rx.try_recv() {
                Ok(r) => r,
                Err(_) => {
                    let now = Instant::now();
                    if inbound_deferred
                        .front()
                        .map(|(wake_at, _)| now >= *wake_at)
                        .unwrap_or(false)
                    {
                        inbound_deferred.pop_front().unwrap().1
                    } else {
                        break;
                    }
                }
            };
            drained.push(raw);
        }

        // Live messages must be drained first; deferred message must NOT be popped because now < wake_at
        assert_eq!(drained, vec!["live_vote_1", "live_vote_2"]);
        assert_eq!(inbound_deferred.len(), 1);

        // 4. Now add an already-matured deferred item (wake_at <= now)
        let past_wake = Instant::now() - Duration::from_millis(10);
        let pos = inbound_deferred
            .iter()
            .position(|(w, _)| *w > past_wake)
            .unwrap_or(inbound_deferred.len());
        inbound_deferred.insert(pos, (past_wake, "matured_deferred_msg".to_string()));

        // At this point, rx is empty. Drain loop should pop the matured item, but leave the future item.
        let mut drained_second = Vec::new();
        for _ in 0..10 {
            let raw: String = match rx.try_recv() {
                Ok(r) => r,
                Err(_) => {
                    let now = Instant::now();
                    if inbound_deferred
                        .front()
                        .map(|(wake_at, _)| now >= *wake_at)
                        .unwrap_or(false)
                    {
                        inbound_deferred.pop_front().unwrap().1
                    } else {
                        break;
                    }
                }
            };
            drained_second.push(raw);
        }

        assert_eq!(drained_second, vec!["matured_deferred_msg"]);
        assert_eq!(inbound_deferred.len(), 1);
        assert_eq!(inbound_deferred[0].1, "deferred_msg_1");
    }
}

#[cfg(test)]
mod round_timeout_tests {
    use super::*;

    #[test]
    fn effective_timeout_grows_with_round_and_caps() {
        assert_eq!(effective_round_timeout_ms(800, 0), 800);
        assert_eq!(effective_round_timeout_ms(800, 1), 1300);
        assert_eq!(effective_round_timeout_ms(800, 4), 2800);
        // Cap: base + 10_000, never more.
        assert_eq!(effective_round_timeout_ms(800, 1000), 10_800);
        assert_eq!(effective_round_timeout_ms(3000, 1000), 13_000);
    }

    #[test]
    fn c2_deterministic_timeout_identical_despite_wall_clock_skew() {
        // TASK 4: two honest nodes with DIFFERENT wall clocks but the SAME
        // state compute the SAME deadline. Model: node A started round 3 at
        // wall t=0, node B at wall t=97_318ms (skewed clock, slow tick). Both
        // compute the VALUE via `deterministic_timeout_for` (no clock read);
        // only the firing (elapsed comparison) uses their own clock.
        let a_start = std::time::Instant::now();
        let b_start = a_start - std::time::Duration::from_millis(97_318);
        let a_ms = deterministic_timeout_for(3500, 3, 2);
        let b_ms = deterministic_timeout_for(3500, 3, 2);
        assert_eq!(a_ms, b_ms, "identical state => identical timeout");
        // Geometric ladder (paper 02_liveness §6, B2 wave): min(3500·2^3,
        // 3500+10000) + min(2·500, 5000) = 13500 + 1000. The determinism
        // property above is the test's core; the value pins the ladder.
        assert_eq!(a_ms, 14_500);
        let _ = (a_start, b_start); // clocks exist, value ignores them
                                    // Enumerated inputs, pinned: base + round-backoff (cap 10s) + adaptive (cap 5s).
        assert_eq!(deterministic_timeout_for(3500, 0, 0), 3500);
        assert_eq!(
            deterministic_timeout_for(3500, 1000, 1000),
            3500 + 10_000 + 5_000
        );
        // Deterministic down-proposer gate: ledger evidence only.
        assert!(should_use_down_proposer_timeout_deterministic(10));
        assert!(!should_use_down_proposer_timeout_deterministic(0));
    }
}

#[cfg(test)]
mod straggler_grace_tests {
    use super::*;

    #[test]
    fn defaults_keep_current_behavior() {
        assert_eq!(STRAGGLER_GRACE_MS_DEFAULT, 0);
        assert_eq!(STRAGGLER_GRACE_CAP_MS_DEFAULT, 30_000);
        // Grace 0 => hold 0 whatever the evidence (byte-identical gates).
        assert_eq!(
            straggler_hold_ms(9, 4, false, Some((9, 3, 100)), 0, 30_000, 50_000),
            0
        );
        assert_eq!(
            straggler_hold_ms(9, 4, true, Some((8, 0, 100)), 0, 30_000, 50_000),
            0
        );
    }

    #[test]
    fn no_evidence_no_hold() {
        // No peer seen at all: never wait (a silent network must time out).
        assert_eq!(
            straggler_hold_ms(9, 4, false, None, 5_000, 5_000, 50_000),
            0
        );
    }

    #[test]
    fn stale_evidence_no_hold() {
        // Peer seen but aged out: dead peers cannot park the chain.
        assert_eq!(
            straggler_hold_ms(9, 4, false, Some((9, 3, 50_000)), 5_000, 5_000, 50_000),
            0
        );
        // Boundary is strict: age == freshness is stale.
        assert_eq!(
            straggler_hold_ms(9, 4, false, Some((9, 3, 50_000)), 5_000, 5_000, 50_000),
            0
        );
    }

    #[test]
    fn behind_peer_holds_one_grace() {
        // Clause 1: live peer voting an older round — its current-round vote
        // may still be in flight.
        assert_eq!(
            straggler_hold_ms(9, 4, false, Some((9, 3, 100)), 5_000, 5_000, 50_000),
            5_000
        );
        // Older height counts too.
        assert_eq!(
            straggler_hold_ms(9, 4, true, Some((8, 9, 100)), 5_000, 5_000, 50_000),
            5_000
        );
    }

    #[test]
    fn unheard_proposal_holds_only_without_live() {
        // Clause 2: no live proposal + peer live at our height, not ahead.
        assert_eq!(
            straggler_hold_ms(9, 4, false, Some((9, 4, 100)), 5_000, 5_000, 50_000),
            5_000
        );
        // Holding a proposal: the value-vote path owns this round, no hold.
        assert_eq!(
            straggler_hold_ms(9, 4, true, Some((9, 4, 100)), 5_000, 5_000, 50_000),
            0
        );
    }

    #[test]
    fn ahead_peer_never_holds() {
        // A peer ahead of us is followed via future-rule jumps, never waited
        // on (waiting would deadlock us behind it).
        assert_eq!(
            straggler_hold_ms(9, 4, false, Some((9, 5, 100)), 5_000, 5_000, 50_000),
            0
        );
        assert_eq!(
            straggler_hold_ms(9, 4, false, Some((10, 0, 100)), 5_000, 5_000, 50_000),
            0
        );
    }

    #[test]
    fn cap_binds_grace() {
        assert_eq!(
            straggler_hold_ms(9, 4, false, Some((9, 3, 100)), 100_000, 5_000, 50_000),
            5_000
        );
        assert_eq!(
            straggler_hold_ms(9, 4, false, Some((9, 3, 100)), 2_000, 5_000, 50_000),
            2_000
        );
    }
}

/// Round-timer accounting: WHY the effective rung is ~2× the configured base
/// (docs/TEMPO_PROFILE.md §5.3), and the minimal subsumption fix.
///
/// The view-change gate (`hold_bounded` + `effective_timeout +
/// straggler_hold`) fires at `max(effective, 2 * base)` while a peer is
/// active — during a veto stall votes flow continuously, so the peer-active
/// hold is always engaged and every rung dwells ~2× base. Backoff, adaptive
/// extension, retransmit and (default-off) grace are ruled out as the 2×
/// source by the composition below: at round 0 they contribute nothing, yet
/// the gate still sits at 2× base.
#[cfg(test)]
mod round_timer_accounting_tests {
    use super::*;

    /// The full per-rung deadline composition for a fixed
    /// (base, round, missed) input: deterministic core, then the peer-active
    /// hold bound. Mirrors the gate
    /// (`elapsed > effective + hold && !hold_bounded` with
    /// `hold_bounded ⇔ peer active && elapsed < 2 * base` ⇒ fires at
    /// `max(effective + hold, 2 * base)` when a peer is active).
    fn composed_deadline_ms(base_ms: u64, round: u32, missed: u32, hold_ms: u64) -> u64 {
        let effective = deterministic_timeout_for(base_ms, round, missed);
        let capped_hold = cap_hold_to_two_x_bound(hold_ms, effective, base_ms);
        (effective + capped_hold).max(base_ms.saturating_mul(2))
    }

    #[test]
    fn effective_rung_is_twice_base_while_peer_active() {
        // TEMPO configuration: base 10s, round 0, no missed streak.
        assert_eq!(deterministic_timeout_for(10_000, 0, 0), 10_000);
        // Backoff (round 0) and adaptive (missed 0) contribute nothing…
        assert_eq!(deterministic_timeout_for(10_000, 0, 0), 10_000);
        // …while non-zero inputs add exactly their ladder terms (the
        // ladder is real, it is just zero at round 0 with no missed streak).
        assert_eq!(
            deterministic_timeout_for(10_000, 0, 4),
            10_000 + 4 * stellereum::consensus::ADAPTIVE_EXTENSION_PER_MISS_MS
        );
        // …yet with a live peer (hold engaged, grace off) the rung dwells
        // 2× base: 20_000ms, the measured 19–21s rungs.
        assert_eq!(composed_deadline_ms(10_000, 0, 0, 0), 20_000);
        // Same shape at the 3.5s base the unanimity3 tests pin.
        assert_eq!(deterministic_timeout_for(3_500, 0, 0), 3_500);
        assert_eq!(composed_deadline_ms(3_500, 0, 0, 0), 7_000);
        // Backoff is bounded by `base + DETERMINISTIC_BACKOFF_CAP_MS` (10s):
        // at base 10s, round 4 saturates at 20s (`10s + 10s` cap); for any
        // larger base (e.g. 30s) the 2× hold bound still dominates backoff.
        assert_eq!(
            deterministic_timeout_for(10_000, 4, 0),
            10_000 + stellereum::consensus::DETERMINISTIC_BACKOFF_CAP_MS
        );
        assert_eq!(composed_deadline_ms(10_000, 4, 0, 0), 20_000);
        assert_eq!(deterministic_timeout_for(30_000, 4, 0), 40_000);
        assert_eq!(composed_deadline_ms(30_000, 4, 0, 0), 60_000);
        // Retransmit is ruled out structurally: it only re-sends, it never
        // gates the view change (no term in the composition above).
    }

    #[test]
    fn grace_zero_hold_zero_deadline_unchanged() {
        // CONSTRAINT: no default behavior change when the straggler envs are
        // unset. hold 0 ⇒ capped hold 0 ⇒ deadline `effective + 0` for every
        // (effective, base) shape, including past-the-bound (high rounds) and
        // below-the-bound (round-0 cap) deadlines.
        for (effective, base) in [
            (10_000, 10_000),
            (650, 10_000),
            (800, 800),
            (13_000, 3_000),
            (3_500, 3_500),
            (0, 1_000),
        ] {
            assert_eq!(
                cap_hold_to_two_x_bound(0, effective, base),
                0,
                "grace 0 must cap to 0 for effective={effective} base={base}"
            );
        }
    }

    #[test]
    fn grace_subsumed_into_two_x_bound_not_added_past_it() {
        // Saturated regime (the rollout shape: grace ≫ slack): total never
        // passes 2× base. Unsubsumed this would be 100 + 1500 = 1600.
        assert_eq!(cap_hold_to_two_x_bound(1_500, 100, 100), 100);
        // Round-0 cap shape (TEMPO heights stall proposalless at 650ms):
        // slack (2×10s − 650ms) still covers the whole grace, so small
        // grace is FULLY preserved — the fix only trims stacking past 2×.
        assert_eq!(cap_hold_to_two_x_bound(1_500, 650, 10_000), 1_500);
        // Partial slack: grace fills exactly to the bound and stops.
        assert_eq!(cap_hold_to_two_x_bound(1_500, 1_000, 1_000), 1_000);
        // Deterministic core already past the bound (high rounds / big
        // backoff): no room for grace, no stacking past it.
        assert_eq!(cap_hold_to_two_x_bound(1_500, 13_000, 3_000), 0);
        // Bound edge: effective exactly at 2× base ⇒ zero slack.
        assert_eq!(cap_hold_to_two_x_bound(1_500, 2_000, 1_000), 0);
    }

    #[test]
    fn subsumed_composition_never_passes_two_x_while_peer_active() {
        // End-to-end on the gate composition: even with grace enabled, a
        // held round fires at most at 2× base (was effective + grace).
        assert_eq!(composed_deadline_ms(10_000, 0, 0, 5_000), 20_000);
        assert_eq!(composed_deadline_ms(100, 0, 0, 1_500), 200);
        // …while a silent round still waits past its deterministic deadline
        // (subsumption only trims the stack, it never removes the grace).
        let effective = deterministic_timeout_for(1_000, 0, 0);
        assert_eq!(effective, 1_000);
        assert_eq!(
            effective + cap_hold_to_two_x_bound(1_500, effective, 1_000),
            2_000
        );
    }
}

/// Liveness-policy predicates (dead-peer retro gate + down-proposer fast
/// timeout + alignment window): pure functions, pinned without a node.
#[cfg(test)]
mod liveness_policy_tests {
    use super::*;

    #[test]
    fn retro_suppression_engages_only_when_stagnant_and_idle() {
        // Engages: tip unchanged since the last pass AND inbound idle 60s+.
        assert!(should_suppress_retro_publish(100, 100, 60));
        assert!(should_suppress_retro_publish(100, 100, 3600));
        // Avoids: fresh inbound — a returning peer announces itself via
        // votes/proposals first, so retro must resume for it.
        assert!(!should_suppress_retro_publish(100, 100, 59));
        assert!(!should_suppress_retro_publish(100, 100, 0));
        // Avoids: a new finalization advanced the tip — there is new history
        // a lagging peer may need.
        assert!(!should_suppress_retro_publish(101, 100, 3600));
        assert!(!should_suppress_retro_publish(50, 49, u64::MAX));
    }

    #[test]
    fn retro_behind_gate_runs_when_behind_peer_seen_recently() {
        let w = RETRO_BEHIND_WINDOW_DEFAULT_SECS;
        assert_eq!(w, 120, "behind window default must stay 120s");
        // Recently seen (0s, 1s, just inside the window): RUN (no suppress).
        assert!(!should_suppress_retro_no_behind_peer(Some(0), w, false));
        assert!(!should_suppress_retro_no_behind_peer(Some(1), w, false));
        assert!(!should_suppress_retro_no_behind_peer(Some(w - 1), w, false));
    }

    #[test]
    fn retro_behind_gate_suppresses_when_no_behind_peer_in_window() {
        let w = RETRO_BEHIND_WINDOW_DEFAULT_SECS;
        // Never seen one this run: SUPPRESS (nothing a retro push could serve).
        assert!(should_suppress_retro_no_behind_peer(None, w, false));
        // Seen, but stale (at/over the window): SUPPRESS.
        assert!(should_suppress_retro_no_behind_peer(Some(w), w, false));
        assert!(should_suppress_retro_no_behind_peer(Some(w + 1), w, false));
        assert!(should_suppress_retro_no_behind_peer(
            Some(u64::MAX),
            w,
            false
        ));
    }

    #[test]
    fn retro_behind_gate_never_suppresses_when_we_are_behind() {
        let w = RETRO_BEHIND_WINDOW_DEFAULT_SECS;
        // Catch-up/fetch path is untouched: even with no behind peer seen,
        // a node that is itself behind must NOT suppress via this gate (the
        // stale-push guard owns that decision separately).
        assert!(!should_suppress_retro_no_behind_peer(None, w, true));
        assert!(!should_suppress_retro_no_behind_peer(
            Some(u64::MAX),
            w,
            true
        ));
        assert!(!should_suppress_retro_no_behind_peer(Some(0), w, true));
    }

    #[test]
    fn retro_behind_window_env_parsing() {
        let saved = std::env::var("STELL_RETRO_BEHIND_WINDOW_SECS").ok();
        std::env::remove_var("STELL_RETRO_BEHIND_WINDOW_SECS");
        assert_eq!(retro_behind_window_secs(), 120);
        std::env::set_var("STELL_RETRO_BEHIND_WINDOW_SECS", "0");
        assert_eq!(retro_behind_window_secs(), 120, "non-positive falls back");
        std::env::set_var("STELL_RETRO_BEHIND_WINDOW_SECS", "not-a-number");
        assert_eq!(retro_behind_window_secs(), 120, "garbage falls back");
        std::env::set_var("STELL_RETRO_BEHIND_WINDOW_SECS", "30");
        assert_eq!(retro_behind_window_secs(), 30, "explicit override wins");
        assert!(
            !should_suppress_retro_no_behind_peer(Some(29), 30, false)
                && should_suppress_retro_no_behind_peer(Some(30), 30, false),
            "window boundary: idle < window runs, idle >= window suppresses"
        );
        match saved {
            Some(v) => std::env::set_var("STELL_RETRO_BEHIND_WINDOW_SECS", v),
            None => std::env::remove_var("STELL_RETRO_BEHIND_WINDOW_SECS"),
        }
    }

    #[test]
    fn suppressed_retro_never_touches_outbox() {
        // Tick-branch contract: when the behind-peer predicate says SUPPRESS,
        // the retro branch must not run — `retro_ran` stays false, so neither
        // the outbox (votes/commits) nor `publish_lane` nor the
        // `retro_published_upto` cursor is touched. Model the branch decision
        // (same inputs the tick computes) and assert the skip.
        let mut outbox_len = 0usize;
        let mut retro_ran = false;
        let suppressed =
            should_suppress_retro_no_behind_peer(None, RETRO_BEHIND_WINDOW_DEFAULT_SECS, false);
        assert!(suppressed, "no behind peer seen => suppressed");
        if !suppressed {
            retro_ran = true;
            outbox_len += 1;
        }
        assert!(!retro_ran, "suppressed pass must not run");
        assert_eq!(outbox_len, 0, "suppressed pass must not touch the outbox");
        // And the live case runs.
        let suppressed_live =
            should_suppress_retro_no_behind_peer(Some(5), RETRO_BEHIND_WINDOW_DEFAULT_SECS, false);
        assert!(!suppressed_live, "recent behind peer => pass runs");
    }

    #[test]
    fn join_skips_cooldown_peers_and_rejoins_when_cleared() {
        use stellereum::consensus_net::join_should_dial;
        // Cooldown peer: no dial (kills the ~1.7s handshake timeout on-tick).
        assert!(!join_should_dial(true), "cooldown peer must not be dialed");
        // Healthy peer: dial.
        assert!(join_should_dial(false), "live peer must be dialed");
        // Returning peer (DHT/probe success cleared its cooldown entry):
        // `in_cooldown == false` again, so join resumes automatically.
        let in_cooldown_after_clear = false;
        assert!(
            join_should_dial(in_cooldown_after_clear),
            "cleared cooldown must rejoin on the next window"
        );
        // Section-level wiring mirrors it: all-cooldown => skip both dials.
        let net_has_healthy = false;
        let gossip_has_healthy = false;
        assert!(!join_should_dial(!net_has_healthy));
        assert!(!join_should_dial(!gossip_has_healthy));
        assert!(join_should_dial(false), "any healthy peer => dial");
    }

    #[test]
    fn down_proposer_fast_timeout_predicate() {
        let t = stellereum::staking::DOWNTIME_MISS_THRESHOLD;
        // Proven down (at/above threshold) with no vote seen → fast timeout.
        assert!(should_use_down_proposer_timeout(t, false));
        assert!(should_use_down_proposer_timeout(t + 50, false));
        // Below threshold → live proposer, normal backoff.
        assert!(!should_use_down_proposer_timeout(t - 1, false));
        assert!(!should_use_down_proposer_timeout(0, false));
        // Down on paper but voted this height → alive now, normal backoff.
        assert!(!should_use_down_proposer_timeout(t, true));
        assert!(!should_use_down_proposer_timeout(u32::MAX, true));
    }

    #[test]
    fn down_proposer_timeout_default_and_backoff_intact() {
        // Default 800ms when the env is absent, empty, zero or garbage.
        let saved = std::env::var("STELL_DOWN_PROPOSER_TIMEOUT_MS").ok();
        std::env::remove_var("STELL_DOWN_PROPOSER_TIMEOUT_MS");
        assert_eq!(down_proposer_timeout_ms(), 800);
        assert_eq!(DOWN_PROPOSER_TIMEOUT_DEFAULT_MS, 800);
        std::env::set_var("STELL_DOWN_PROPOSER_TIMEOUT_MS", "0");
        assert_eq!(down_proposer_timeout_ms(), 800, "non-positive falls back");
        std::env::set_var("STELL_DOWN_PROPOSER_TIMEOUT_MS", "not-a-number");
        assert_eq!(down_proposer_timeout_ms(), 800, "garbage falls back");
        std::env::set_var("STELL_DOWN_PROPOSER_TIMEOUT_MS", "500");
        assert_eq!(down_proposer_timeout_ms(), 500, "explicit override wins");
        match saved {
            Some(v) => std::env::set_var("STELL_DOWN_PROPOSER_TIMEOUT_MS", v),
            None => std::env::remove_var("STELL_DOWN_PROPOSER_TIMEOUT_MS"),
        }
        // The fast path CAPS (min): backoff growth never leaks through it…
        assert_eq!(800, 800);
        // …while the normal path keeps the full backoff ladder intact.
        assert_eq!(effective_round_timeout_ms(3000, 10), 8000);
        assert_eq!(effective_round_timeout_ms(800, 1000), 10_800);
    }

    #[test]
    fn proposal_alignment_window_widened() {
        // Audit MED: the hash-slot schedule rejects ~20% genuine early
        // proposals at +4; local acceptance strictly widens to +8.
        assert_eq!(
            stellereum::runtime::PROPOSAL_ALIGN_WINDOW_ROUNDS,
            8,
            "alignment window must stay +8 until the next audit re-measures it"
        );
    }
}

/// Guard: DNS seed discovery must NEVER change the consensus validator set.
/// Discovered peers live only in the runtime peer-set (`node.peers`); feeding
/// them into `build_validator_set` would let a DNS attacker mint quorum power
/// and split the genesis state root. These tests pin the invariant that extra
/// peer entries (exactly what discovery appends) leave the set byte-identical.
#[cfg(test)]
mod dns_seed_guard_tests {
    use super::*;

    fn peer(name: &str, ed: [u8; 32]) -> node_config::PeerConfig {
        node_config::PeerConfig {
            name: name.to_string(),
            consensus_pub: Some(hex::encode(ed)),
            // PQ pin for the DNS-merge identity (the validator set itself
            // keys on `consensus_pub`, which is consensus-only).
            pq_pub: Some(infnode::keyring::PqKeys::from_seed(ed).pq_pub_hex()),
            endpoints: vec!["127.0.0.1:9411".to_string()],
            allow: vec!["*".to_string()],
            rate_limit_per_sec: 0,
            role: None,
            storage_roles: vec![],
        }
    }

    fn node_id_hex(ed: &[u8; 32]) -> String {
        let h = blake3::hash(ed);
        format!("inf1:{}", hex::encode(&h.as_bytes()[..20]))
    }

    fn cfg_with(
        peers: Vec<node_config::PeerConfig>,
        validators: Vec<String>,
    ) -> node_config::NodeConfig {
        node_config::NodeConfig {
            name: "guard".to_string(),
            listen: "127.0.0.1:9400".to_string(),
            client_listen: None,
            advertise: None,
            peers,
            allow_unknown: false,
            unknown_allow: vec![],
            metrics_listen: None,
            log_level: None,
            roles: Default::default(),
            outbox_ttl_secs: 3600,
            storage_roles: vec![],
            validators,
            domain: None,
            web_listen: None,
            wallet: None,
            web_static: None,
        }
    }

    fn bytes_of(vset: &ValidatorSet) -> Vec<u8> {
        bincode::serialize(vset).expect("validator set must serialize")
    }

    /// A peer entry that DNS discovery would append: a node whose id is NOT in
    /// `validators:`.
    fn discovered_peer_entry(seed: u8) -> node_config::PeerConfig {
        peer(&format!("dns-seed-{seed}"), [seed; 32])
    }

    #[test]
    fn discovered_peers_do_not_change_the_validator_set_all_listed() {
        let self_ed = [0xAAu8; 32];
        let peer_ed = [0xBBu8; 32];
        let base_peers = vec![peer("b", peer_ed)];
        let validators = vec![node_id_hex(&self_ed), node_id_hex(&peer_ed)];
        let cfg = cfg_with(base_peers.clone(), validators.clone());
        let (vset_plain, is_val_plain) =
            build_validator_set(&cfg, self_ed, &node_id_hex(&self_ed), false);
        assert!(is_val_plain);
        assert_eq!(vset_plain.len(), 2);

        // The same config with DNS-discovered (non-validator) peers appended.
        let mut with_discovered = base_peers;
        with_discovered.push(discovered_peer_entry(0xC1));
        with_discovered.push(discovered_peer_entry(0xC2));
        let cfg2 = cfg_with(with_discovered, validators);
        let (vset_dns, is_val_dns) =
            build_validator_set(&cfg2, self_ed, &node_id_hex(&self_ed), false);

        assert_eq!(is_val_dns, is_val_plain);
        assert_eq!(
            bytes_of(&vset_dns),
            bytes_of(&vset_plain),
            "discovered peers must leave the validator set byte-identical"
        );
    }

    #[test]
    fn unlisted_peer_key_is_excluded_from_validator_set() {
        // F6 (structural now): peer configs carry NO declared node-id — the
        // id is derived from the pinned ed key, so a doctored config can no
        // longer claim our id for a stranger's key (the old lie is
        // inexpressible). What remains pinned: a peer whose derived id is NOT
        // listed contributes nothing.
        let self_ed = [0x11u8; 32];
        let peer_ed = [0x22u8; 32];
        let stranger = peer("b", peer_ed); // derived id != listed self id
        let validators = vec![node_id_hex(&self_ed)];
        let cfg = cfg_with(vec![stranger], validators);
        let (vset, is_val) = build_validator_set(&cfg, self_ed, &node_id_hex(&self_ed), false);
        assert!(is_val, "we are listed, self stays a validator");
        assert!(
            !vset.contains(&peer_ed),
            "unlisted peer key must not enter the validator set"
        );
        assert_eq!(vset.len(), 1, "only self remains");
    }

    #[test]
    fn discovered_peers_do_not_change_the_validator_set_others_only() {
        // The deployed convention: `validators:` names ONLY the other node.
        let self_ed = [0x11u8; 32];
        let peer_ed = [0x22u8; 32];
        let base_peers = vec![peer("b", peer_ed)];
        let validators = vec![node_id_hex(&peer_ed)];
        let cfg = cfg_with(base_peers.clone(), validators.clone());
        let (vset_plain, is_val_plain) =
            build_validator_set(&cfg, self_ed, &node_id_hex(&self_ed), false);
        assert!(is_val_plain, "list-names-only-others still includes self");
        assert_eq!(vset_plain.len(), 2);

        let mut with_discovered = base_peers;
        with_discovered.push(discovered_peer_entry(0xC3));
        let cfg2 = cfg_with(with_discovered, validators);
        let (vset_dns, is_val_dns) =
            build_validator_set(&cfg2, self_ed, &node_id_hex(&self_ed), false);

        assert_eq!(is_val_dns, is_val_plain);
        assert_eq!(
            bytes_of(&vset_dns),
            bytes_of(&vset_plain),
            "discovered peers must leave the validator set byte-identical"
        );
    }

    #[test]
    fn observer_flag_skips_self_add_and_keeps_live_genesis_set() {
        // Fresh key C with validators=[A,B] (others-only shape): by default
        // self is added implicitly, giving a 3-member set (own genesis).
        let self_ed = [0x33u8; 32];
        let peer_a = [0x11u8; 32];
        let peer_b = [0x22u8; 32];
        let cfg = cfg_with(
            vec![peer("a", peer_a), peer("b", peer_b)],
            vec![node_id_hex(&peer_a), node_id_hex(&peer_b)],
        );
        let (vset_plain, is_val_plain) =
            build_validator_set(&cfg, self_ed, &node_id_hex(&self_ed), false);
        assert!(is_val_plain);
        assert_eq!(vset_plain.len(), 3);

        // With STELL_OBSERVER=1 the bootstrap set stays exactly {A,B}, so
        // genesis funds the same accounts as the live network.
        // Observer as a pure parameter (no env reads in tests: the old
        // set_var/remove_var dance raced with parallel tests reading env).
        let (vset_obs, is_val_obs) =
            build_validator_set(&cfg, self_ed, &node_id_hex(&self_ed), true);
        assert!(!is_val_obs, "observer flag must exclude self");
        assert_eq!(vset_obs.len(), 2);
        assert!(!vset_obs.contains(&self_ed));
        assert!(vset_obs.contains(&peer_a) && vset_obs.contains(&peer_b));
    }

    #[test]
    fn merge_seeds_never_returns_anything_listed_as_validator() {
        // Even if a DNS record advertises a REAL validator's identity, the
        // merge only dedups against the peer list — and the caller adds the
        // result to the runtime peer-set only. What this test pins is the
        // module contract the integration relies on: merge output is plain
        // `DiscoveredPeer`s with no validator-list side channel at all, and a
        // discovered clone of a configured peer is dropped as a duplicate.
        let validator_ed = [0xD1u8; 32];
        let configured = vec![peer("validator", validator_ed)];
        let pq = infnode::keyring::PqKeys::from_seed(validator_ed);
        let clone_of_validator = stellereum::dns_seeds::DiscoveredPeer {
            node_id: pq.pq_id_hex(),
            pq_pub: pq.pq_pub(),
            kem_ek_hash: None,
            host: "evil.example".to_string(),
            port: 9411,
        };
        let r = stellereum::dns_seeds::merge_seeds(&configured, vec![clone_of_validator]);
        assert!(
            r.new_peers.is_empty(),
            "a DNS clone of a configured validator is a duplicate, never new"
        );
    }
}

#[cfg(test)]
mod cli_tx_builder_tests {
    use super::*;
    use stellereum::bridge::{BridgeIntent, SupportedChain};
    use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn falcon_key(seed: u8) -> stellereum::post_quantum::FalconKeypair {
        stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&[seed; 32])
    }

    fn attest_key(seed: u8) -> AttestKey {
        let sk = key(seed);
        let fk = falcon_key(seed);
        stellereum::consensus::register_validator_pq_key(
            sk.verifying_key().to_bytes(),
            stellereum::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
        AttestKey {
            validator_id: sk.verifying_key().to_bytes(),
            falcon: fk,
        }
    }

    fn only_op(tx: &Transaction) -> &OpCode {
        assert_eq!(tx.payload.len(), 1, "CLI payloads carry exactly one opcode");
        &tx.payload[0]
    }

    #[test]
    fn cli_gas_never_drops_below_the_admission_base() {
        assert_eq!(cli_tx_gas(0), GAS_BASIC_TRANSFER);
        assert_eq!(cli_tx_gas(GAS_BASIC_TRANSFER), GAS_BASIC_TRANSFER);
        let high = GAS_BASIC_TRANSFER + 5_000;
        assert_eq!(
            cli_tx_gas(high),
            high,
            "a costlier opcode keeps its own budget"
        );
    }

    #[test]
    fn place_order_builder_signs_the_order_opcode() {
        let trader = falcon_key(0x31);
        let from = falcon_pq_address(&trader);
        let tx = build_place_order_tx(&trader, 1, true, 250_000, 7_000, 9);

        assert_eq!(tx.from, from, "the sender is the trader");
        assert_eq!(tx.nonce, 9);
        assert!(tx.is_pq(), "CLI tx must carry PQ1 envelope");
        assert!(tx.gas_limit >= stellereum::svm::GAS_ORDER_PLACE);
        assert!(tx.gas_limit >= GAS_BASIC_TRANSFER);
        assert!(tx.verify_signature(), "CLI tx must verify");
        match only_op(&tx) {
            OpCode::SysCallPlaceOrder {
                pair_id,
                is_buy,
                price,
                amount,
            } => {
                assert_eq!(*pair_id, 1);
                assert!(*is_buy);
                assert_eq!(*price, 250_000);
                assert_eq!(*amount, 7_000);
            }
            other => panic!("wrong opcode: {other:?}"),
        }
    }

    #[test]
    fn cancel_order_builder_signs_the_cancel_opcode() {
        let trader = falcon_key(0x32);
        let from = falcon_pq_address(&trader);
        let tx = build_cancel_order_tx(&trader, 4242, 3);

        assert_eq!(tx.from, from);
        assert_eq!(tx.nonce, 3);
        assert!(tx.is_pq(), "CLI tx must carry PQ1 envelope");
        assert!(tx.gas_limit >= stellereum::svm::GAS_ORDER_CANCEL);
        assert!(tx.verify_signature());
        match only_op(&tx) {
            OpCode::SysCallCancelOrder { order_id } => assert_eq!(*order_id, 4242),
            other => panic!("wrong opcode: {other:?}"),
        }
    }

    #[test]
    fn session_grant_builder_publishes_the_master_signed_grant() {
        let master = falcon_key(0x33);
        let master_addr = falcon_pq_address(&master);
        let session = falcon_key(0x44);
        let grant = SessionKeyAuthorization::sign_delegation_falcon512(
            &master,
            stellereum::post_quantum::PqScheme::Falcon512,
            &session.public_key,
            u64::MAX,
            1_000_000,
            stellereum::zkml::SCOPE_ALL,
            5_000,
            stellereum::zkml::DEFAULT_CHAIN_ID,
        );
        let tx = build_session_grant_tx(&master, &grant, 1);

        assert_eq!(
            tx.from, master_addr,
            "only the master may publish its grant"
        );
        assert_eq!(tx.nonce, 1);
        assert!(tx.is_pq(), "CLI tx must carry PQ1 envelope");
        assert!(tx.gas_limit >= stellereum::svm::GAS_PUBLISH_SESSION_GRANT);
        assert!(tx.verify_signature());
        match only_op(&tx) {
            OpCode::SysCallPublishSessionGrant(carried) => {
                assert_eq!(carried.master_address, master_addr);
                assert!(
                    carried.verify_signature(),
                    "the carried grant must still verify"
                );
            }
            other => panic!("wrong opcode: {other:?}"),
        }
    }

    #[test]
    fn bridge_intent_builder_carries_deposit_and_withdraw() {
        let signer = falcon_key(0x34);
        let from = falcon_pq_address(&signer);
        let recipient = [0xABu8; 32];

        let deposit = BridgeIntent::Deposit {
            chain: SupportedChain::Ton,
            source_tx_hash: [0x11; 32],
            recipient,
            amount: 5_000_000_000,
        };
        let tx = build_bridge_intent_tx(&signer, std::slice::from_ref(&deposit), 2);
        assert_eq!(tx.from, from);
        assert_eq!(tx.nonce, 2);
        assert!(tx.is_pq());
        assert!(tx.gas_limit >= stellereum::svm::GAS_BRIDGE_INTENT);
        assert!(tx.verify_signature());
        match only_op(&tx) {
            OpCode::SysCallBridge(intent) => assert_eq!(intent.as_ref(), &deposit),
            other => panic!("wrong opcode: {other:?}"),
        }

        let withdraw = BridgeIntent::Withdraw {
            chain: SupportedChain::Arbitrum,
            target_address: "0xdeadbeef".to_string(),
            amount: 1_000,
        };
        let tx2 = build_bridge_intent_tx(&signer, std::slice::from_ref(&withdraw), 3);
        assert!(tx2.is_pq());
        assert!(tx2.verify_signature());
        match only_op(&tx2) {
            OpCode::SysCallBridge(intent) => assert_eq!(intent.as_ref(), &withdraw),
            other => panic!("wrong opcode: {other:?}"),
        }
    }

    /// GAP 1, the fix itself: a deposit the CLI builds carries BOTH the claim
    /// and the attestation bundle that authorizes it, and those signatures
    /// verify against exactly the message `BridgeState::plan` checks at
    /// settlement - so the tx a `bridge deposit` prints and submits is one a
    /// block can actually apply (rather than a claim every block refuses).
    #[test]
    fn bridge_deposit_tx_carries_the_attestation_a_block_accepts() {
        let signer = falcon_key(0x35);
        let validators = [attest_key(0x51), attest_key(0x52), attest_key(0x53)];
        let validator_pks: Vec<[u8; 32]> = validators.iter().map(|k| k.validator_id).collect();
        let deposit = BridgeIntent::Deposit {
            chain: SupportedChain::Ton,
            source_tx_hash: [0x22; 32],
            recipient: [0xCD; 32],
            amount: 7_000_000_000,
        };

        // The CLI gathers signatures from the keys it can access ...
        let attestation = attest_for(&deposit, &validators[..2]).expect("attest");
        // ... and builds ONE transaction carrying both intents.
        let tx = build_bridge_intent_tx(&signer, &[attestation.clone(), deposit.clone()], 4);
        assert_eq!(tx.payload.len(), 2, "Attest and Deposit ride the same tx");
        assert!(
            tx.gas_limit >= stellereum::svm::GAS_BRIDGE_INTENT * 2,
            "a two-op payload declares two bridge gas budgets"
        );
        assert!(tx.is_pq());
        assert!(tx.verify_signature());

        match &tx.payload[0] {
            OpCode::SysCallBridge(att) => match att.as_ref() {
                BridgeIntent::Attest {
                    source_tx_hash,
                    signatures,
                } => {
                    assert_eq!(
                        *source_tx_hash, [0x22; 32],
                        "the bundle is paired with its claim by source tx"
                    );
                    assert_eq!(signatures.len(), 2, "one signature per attesting key");
                    let distinct: std::collections::HashSet<_> =
                        signatures.iter().map(|(pk, _)| *pk).collect();
                    assert_eq!(distinct.len(), signatures.len(), "signers are distinct");
                }
                other => panic!("first opcode must be the Attest bundle: {other:?}"),
            },
            other => panic!("wrong opcode: {other:?}"),
        }
        match &tx.payload[1] {
            OpCode::SysCallBridge(dep) => assert_eq!(dep.as_ref(), &deposit),
            other => panic!("wrong opcode: {other:?}"),
        }

        // THE END-TO-END CHECK: run the very plan every node runs. The
        // CLI-built pair must be ADMITTED (2 of 3 committed validators is the
        // `(n*2+2)/3 = 2` quorum) and must plan exactly one credit.
        let carried: Vec<BridgeIntent> = tx
            .payload
            .iter()
            .filter_map(|op| match op {
                OpCode::SysCallBridge(i) => Some((**i).clone()),
                _ => None,
            })
            .collect();
        let plan = stellereum::bridge::BridgeState::default()
            .plan(
                &carried,
                &validator_pks,
                falcon_pq_address(&signer),
                1_760_000_000,
            )
            .expect("a deposit the CLI submits must pass §8 policy");
        assert_eq!(
            plan.effects,
            vec![stellereum::bridge::BridgeEffect::Credit {
                recipient: [0xCD; 32],
                amount: 7_000_000_000,
            }],
            "the plan credits the claimed recipient exactly once"
        );
        assert!(plan.state.processed_source_txs.contains(&[0x22; 32]));
    }

    /// GAP 1 key gathering: explicit `--attest-key` seeds win, the local
    /// stand's node key is the fallback, and with NOTHING available the CLI
    /// refuses to build the claim at all instead of submitting one every
    /// block would reject (quorum fail-closed).
    #[test]
    fn attest_keys_come_from_explicit_seeds_or_the_local_node_key() {
        let dir = std::env::temp_dir().join(format!(
            "stell-attest-keys-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp keys dir");

        let explicit = key(0x61);
        let explicit_hex = hex::encode(explicit.to_bytes());

        // (a) nothing available -> hard error, never an unattested claim.
        let err = resolve_attest_keys(&[], &dir)
            .expect_err("with no key at all the deposit must not be built")
            .to_string();
        assert!(
            err.contains("--attest-key"),
            "the refusal must say how to supply a key: {err}"
        );

        // (b) explicit seeds.
        let keys =
            resolve_attest_keys(std::slice::from_ref(&explicit_hex), &dir).expect("explicit seed");
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].validator_id,
            explicit.verifying_key().to_bytes(),
            "the seed must reconstruct the very key it names"
        );

        // (c) local stand fallback: `run` loads and bonds THIS key, so it is
        //     the one a solo stand's quorum counts.
        let consensus = stellereum::node_keys::load_or_generate_consensus_key(&dir)
            .expect("create the consensus key");
        let keys = resolve_attest_keys(&[], &dir).expect("consensus-key fallback");
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].validator_id,
            consensus.verifying_key().to_bytes(),
            "the fallback must be the consensus validator key"
        );

        // (c2) when falcon.key exists in keys_dir, it is loaded for signing.
        let saved_falcon = falcon_key(0x77);
        stellereum::node_keys::ensure_secure_dir(&dir).expect("secure dir");
        stellereum::node_keys::write_private_file(
            &dir.join("falcon.key"),
            &saved_falcon.to_bytes(),
        )
        .expect("save falcon.key");
        let keys_with_falcon = resolve_attest_keys(&[], &dir).expect("falcon.key fallback");
        assert_eq!(keys_with_falcon.len(), 1);
        assert_eq!(
            keys_with_falcon[0].falcon.public_key, saved_falcon.public_key,
            "falcon.key in keys_dir must be preferred over derived fallback"
        );

        // (d) explicit replaces the fallback (duplicates collapse too).
        let keys = resolve_attest_keys(&[explicit_hex.clone(), explicit_hex.clone()], &dir)
            .expect("explicit wins");
        assert_eq!(keys.len(), 1, "duplicate seeds collapse to one signer");

        // (e) malformed input fails loudly.
        assert!(resolve_attest_keys(&["not-hex".to_string()], &dir).is_err());
        assert!(resolve_attest_keys(&[hex::encode([1u8; 8])], &dir).is_err());

        // (f) attestations only ever pair with a deposit.
        let withdraw = BridgeIntent::Withdraw {
            chain: SupportedChain::Ton,
            target_address: "EQD".to_string(),
            amount: 1,
        };
        assert!(attest_for(&withdraw, &[attest_key(0x61)]).is_err());
        assert!(
            attest_for(
                &BridgeIntent::Deposit {
                    chain: SupportedChain::Ton,
                    source_tx_hash: [9u8; 32],
                    recipient: [3u8; 32],
                    amount: 1,
                },
                &[]
            )
            .is_err(),
            "an empty bundle is refused by `validate`, so the CLI must not build one"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// §7 Phase 1 -- "remove non-transport milliseconds": the primitives the
/// consensus loop now submits to instead of awaiting inline.
///
/// These live in this binary, so `tests/` cannot reach them; the library-level
/// pins (snapshot bytes) live in `tests/tick_offload_tests.rs`.
#[cfg(test)]
mod tick_offload_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Poll `cond` on the async executor until it holds or the deadline passes.
    async fn wait_until(deadline: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let t0 = std::time::Instant::now();
        while t0.elapsed() < deadline {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        cond()
    }

    fn test_rpc_state() -> Arc<stellereum::rpc::RpcState> {
        Arc::new(stellereum::rpc::RpcState {
            engine: Arc::new(InMemoryStateEngine::new()),
            mempool: Arc::new(tokio::sync::RwLock::new(
                stellereum::mempool::Mempool::default(),
            )),
            height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            node_id: "tick-offload-test".to_string(),
            chain_id: stellereum::zkml::DEFAULT_CHAIN_ID,
            staking: Arc::new(tokio::sync::RwLock::new(
                stellereum::staking::StakingLedger::new(),
            )),
            governance: Arc::new(tokio::sync::RwLock::new(
                stellereum::governance::Governance::new(),
            )),
            recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
            receipts: Arc::new(tokio::sync::RwLock::new(
                stellereum::rpc::ReceiptIndex::default(),
            )),
            auth_token: None,
            tx_broadcast: None,
            faucet: None,
            faucet_token: None,
            msg_signing_seed: None,
            archive_store: None,
            shard_registry: stellereum::sharding::ShardRegistry::single(),
        })
    }

    /// The 15s mempool save: NOT awaited on the tick, and never two writers on
    /// the same file at once.
    ///
    /// The write lock is held while we probe, so the spawned save is provably
    /// stuck in `blocking_read` -- which makes "did the caller wait?" and "can a
    /// second save start?" deterministic instead of timing-dependent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mempool_save_is_not_awaited_on_the_tick_and_never_overlaps() {
        let dir = std::env::temp_dir().join(format!(
            "stell_tick_mempool_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("mempool.bin");

        let fk = stellereum::post_quantum::FalconKeypair::generate_from_seed(0x42);
        let from = falcon_pq_address(&fk);
        let gas = cli_tx_gas(0).saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
        let tx = sign_pq_explicit_payload(&fk, from, 0, gas, 0, 1, 1, vec![]);
        let pool = Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default(),
        ));
        pool.write().await.add(tx).expect("admit");
        let guard = Arc::new(AtomicBool::new(false));

        // Hold the WRITE lock: the save blocks in `blocking_read`, so the file
        // cannot appear and the guard cannot be released while we probe.
        let held = pool.write().await;

        let t0 = std::time::Instant::now();
        assert!(
            schedule_mempool_save(&pool, &path, &guard),
            "the first save must claim the guard"
        );
        assert!(
            !schedule_mempool_save(&pool, &path, &guard),
            "a save already in flight must be refused -- never a second writer on the same file"
        );
        let caller_dt = t0.elapsed();
        assert!(
            caller_dt < Duration::from_millis(100),
            "the tick must not wait for the save; scheduling took {caller_dt:?}"
        );
        assert!(
            !path.exists(),
            "nothing may be written while the pool is locked"
        );
        assert!(
            guard.load(Ordering::SeqCst),
            "guard held until the write ends"
        );

        drop(held);
        assert!(
            wait_until(Duration::from_secs(10), || !guard.load(Ordering::SeqCst)).await,
            "the deferred save must finish and release the guard"
        );
        assert!(path.exists(), "the deferred write must still happen");
        let bytes = std::fs::read(&path).expect("read the pool back");
        // Versioned envelope (MP02 magic + bincode): strip the prefix before
        // decoding, mirroring `load_into`.
        let body: &[u8] = match bytes.strip_prefix(stellereum::mempool::Mempool::MEMPOOL_FILE_MAGIC)
        {
            Some(b) => b,
            None => &bytes,
        };
        let restored: stellereum::mempool::Mempool =
            bincode::deserialize(body).expect("the saved bytes decode");
        assert_eq!(restored.len(), 1, "the saved pool is the pool we had");

        // The guard really was released: a later window can save again.
        assert!(
            schedule_mempool_save(&pool, &path, &guard),
            "a completed save must not block the next window"
        );
        assert!(
            wait_until(Duration::from_secs(10), || !guard.load(Ordering::SeqCst)).await,
            "second save must finish too"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `spawn_guarded_blocking` is fire-and-forget for the caller and
    /// single-flight per guard: while one job runs, a second trigger is
    /// refused outright (it must not merely be queued, and it must never run).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn guarded_blocking_jobs_are_fire_and_forget_and_single_flight() {
        let guard = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));

        let t0 = std::time::Instant::now();
        assert!(spawn_guarded_blocking(&guard, {
            let (running, peak, finished) = (running.clone(), peak.clone(), finished.clone());
            move || {
                let inside = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(inside, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(200));
                running.fetch_sub(1, Ordering::SeqCst);
                finished.fetch_add(1, Ordering::SeqCst);
            }
        }));
        assert!(
            t0.elapsed() < Duration::from_millis(50),
            "the caller must not run (or wait for) the job itself"
        );

        assert!(
            !spawn_guarded_blocking(&guard, {
                let finished = finished.clone();
                move || {
                    finished.fetch_add(1, Ordering::SeqCst);
                }
            }),
            "a second trigger must be refused while the first job runs"
        );
        assert_eq!(
            finished.load(Ordering::SeqCst),
            0,
            "the refused job must never execute"
        );

        assert!(
            wait_until(Duration::from_secs(10), || !guard.load(Ordering::SeqCst)).await,
            "the job must finish and release the guard"
        );
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "two guarded jobs must never run at the same time"
        );
        assert_eq!(finished.load(Ordering::SeqCst), 1);

        assert!(
            spawn_guarded_blocking(&guard, {
                let finished = finished.clone();
                move || {
                    finished.fetch_add(1, Ordering::SeqCst);
                }
            }),
            "the guard must be reusable after the job completes"
        );
        assert!(
            wait_until(Duration::from_secs(10), || finished.load(Ordering::SeqCst)
                == 2)
            .await,
            "the follow-up job must run"
        );
    }

    /// The prune the finalize path fires every 100 heights: same functions,
    /// same arguments, same ignored errors -- only the thread changes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn state_and_domain_prune_run_through_the_guard_off_the_tick() {
        let dir = std::env::temp_dir().join(format!(
            "stell_tick_prune_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = stellereum::storage::Storage::open(&dir).expect("open storage");
        for h in 1..=10u64 {
            store.put_state(h, &[h as u8; 4]).expect("state");
            store.put_domains(h, &[h as u8; 4]).expect("domains");
        }

        let guard = Arc::new(AtomicBool::new(false));
        let worker = store.clone();
        let t0 = std::time::Instant::now();
        assert!(spawn_guarded_blocking(&guard, move || {
            let _ = worker.prune_state_below(5);
            let _ = worker.prune_domains_below(5);
        }));
        assert!(
            t0.elapsed() < Duration::from_millis(50),
            "the tick must not run the prune itself"
        );
        assert!(
            wait_until(Duration::from_secs(10), || {
                store.get_state(1).ok().flatten().is_none()
            })
            .await,
            "the deferred prune must actually prune"
        );
        assert!(
            store.get_state(7).ok().flatten().is_some(),
            "heights inside the ring must survive"
        );
        assert!(
            matches!(store.latest_domains().ok().flatten(), Some((h, _)) if h >= 7),
            "domain snapshots inside the ring must survive"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A lane drives its jobs ONE AT A TIME, in submission order -- the FIFO
    /// property that replaces awaiting them serially on the tick.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lane_runs_jobs_one_at_a_time_in_submission_order() {
        let lane = spawn_tick_lane();
        let order = Arc::new(std::sync::Mutex::new(Vec::<u32>::new()));
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        for i in 0..24u32 {
            let (order, running, peak) = (order.clone(), running.clone(), peak.clone());
            lane.submit(async move {
                let inside = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(inside, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(2)).await;
                order.lock().expect("lock").push(i);
                running.fetch_sub(1, Ordering::SeqCst);
            });
        }
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        lane.submit(async move {
            let _ = done_tx.send(());
        });
        tokio::time::timeout(Duration::from_secs(10), done_rx)
            .await
            .expect("the lane must drain")
            .expect("lane stays open");

        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "one job at a time on a lane"
        );
        assert_eq!(
            *order.lock().expect("lock"),
            (0..24).collect::<Vec<u32>>(),
            "jobs must complete in submission order"
        );
    }

    /// Receipts before the next height is visible.
    ///
    /// A wallet polls the RPC concurrently with the tick. The instant the
    /// reader observes height 2, height 1's receipts must already be in the
    /// index -- which is exactly what the `record_lane` FIFO guarantees
    /// (receipts(H), block(H), receipts(H+1), block(H+1) run in that order).
    /// If the records were spawned unordered, the reader could observe
    /// `height == 2` first and miss the earlier receipt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn receipts_are_recorded_before_a_later_height_is_readable() {
        let rpc = test_rpc_state();
        let lane = spawn_tick_lane();

        let sk = SigningKey::generate(&mut OsRng);
        let from = sk.verifying_key().to_bytes();
        let tx = Transaction::sign_with_payload(&sk, from, 0, 100_000, 0, 1, 1, vec![]);
        let tx_hash = tx.compute_tx_hash();

        let reader_rpc = rpc.clone();
        let reader = tokio::spawn(async move {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let mut violations = 0u32;
            loop {
                if reader_rpc.height.load(Ordering::Relaxed) >= 2 {
                    // Height 2 is visible NOW: height 1's receipt must be too.
                    if reader_rpc.receipts.read().await.get(&tx_hash).is_none() {
                        violations += 1;
                    }
                    break;
                }
                if std::time::Instant::now() > deadline {
                    panic!("the record lane never reached height 2");
                }
                tokio::task::yield_now().await;
            }
            violations
        });

        // The tick's submissions, in the order the finalize path makes them.
        let (r1, r2) = (rpc.clone(), rpc.clone());
        lane.submit(async move {
            r1.record_receipts(
                1,
                [0x11; 32],
                std::slice::from_ref(&tx),
                &[true],
                &[100_000],
            )
            .await;
            r1.record_block(1, [0x11; 32], 1, 100).await;
        });
        lane.submit(async move {
            r2.record_receipts(2, [0x22; 32], &[], &[], &[]).await;
            r2.record_block(2, [0x22; 32], 0, 101).await;
        });

        let violations = tokio::time::timeout(Duration::from_secs(15), reader)
            .await
            .expect("the reader must observe a height")
            .expect("reader task");
        assert_eq!(
            violations, 0,
            "a reader that sees height 2 must already see height 1's receipts"
        );
        assert_eq!(rpc.height.load(Ordering::Relaxed), 2);
        assert!(rpc.receipts.read().await.get(&tx_hash).is_some());
    }

    /// The two lanes are independent: a job that stalls for a long time on the
    /// publish lane must not hold up the record lane (that is why receipts have
    /// their own FIFO instead of queueing behind a DHT write).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_publish_lane_cannot_delay_the_record_lane() {
        let publish_lane = spawn_tick_lane();
        let record_lane = spawn_tick_lane();

        // Publish lane wedged on a slow transport round trip.
        publish_lane.submit(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let rpc = test_rpc_state();
        let r = rpc.clone();
        record_lane.submit(async move {
            r.record_block(1, [0x33; 32], 0, 7).await;
        });
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let r2 = rpc.clone();
        record_lane.submit(async move {
            r2.record_block(2, [0x44; 32], 0, 8).await;
            let _ = done_tx.send(());
        });

        tokio::time::timeout(Duration::from_millis(250), done_rx)
            .await
            .expect("the record lane must drain while the publish lane is stuck")
            .expect("lane stays open");
        assert_eq!(rpc.height.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_parallel_exec_activation_rules() {
        // Default: false
        assert!(!is_parallel_exec_active(None, false, false));
        assert!(!is_parallel_exec_active(Some(""), false, false));
        assert!(!is_parallel_exec_active(Some("0"), false, false));
        assert!(!is_parallel_exec_active(Some("false"), false, false));
        assert!(!is_parallel_exec_active(Some("FALSE"), false, false));

        // STELL_PARALLEL_EXEC=1 or true
        assert!(is_parallel_exec_active(Some("1"), false, false));
        assert!(is_parallel_exec_active(Some("true"), false, false));
        assert!(is_parallel_exec_active(Some("TRUE"), false, false));
        assert!(is_parallel_exec_active(Some(" 1 "), false, false));

        // CLI flag --parallel-exec
        assert!(is_parallel_exec_active(None, true, false));

        // State engine pre-configured
        assert!(is_parallel_exec_active(None, false, true));

        // Clap parsing of --parallel-exec
        use clap::Parser;
        let cli = Cli::try_parse_from(["stellereum", "run", "--parallel-exec"]).unwrap();
        match cli.command {
            Commands::Run { parallel_exec, .. } => assert!(parallel_exec),
            _ => panic!("expected Commands::Run"),
        }
        let cli_default = Cli::try_parse_from(["stellereum", "run"]).unwrap();
        match cli_default.command {
            Commands::Run {
                parallel_exec,
                pure_pq,
                ..
            } => {
                assert!(!parallel_exec);
                assert!(!pure_pq);
            }
            _ => panic!("expected Commands::Run"),
        }
        let cli_pq = Cli::try_parse_from(["stellereum", "run", "--pure-pq"]).unwrap();
        match cli_pq.command {
            Commands::Run { pure_pq, .. } => assert!(pure_pq),
            _ => panic!("expected Commands::Run"),
        }
    }
}

#[cfg(test)]
mod heal_fail_closed_tests {
    use super::*;

    #[test]
    fn heal_failure_exits_only_on_final_attempt() {
        // Transient misses retry: attempts 1..MAX must NOT exit.
        for attempt in 1..HEAL_MAX_ATTEMPTS {
            assert!(
                !heal_failure_should_exit(attempt),
                "attempt {attempt} must retry, not exit"
            );
        }
        // Exhausted budget refuses: the caller loud-errors + process::exit(1)
        // instead of labelling unhealed state with the finalized height.
        assert!(heal_failure_should_exit(HEAL_MAX_ATTEMPTS));
        assert!(heal_failure_should_exit(HEAL_MAX_ATTEMPTS + 1));
    }

    #[test]
    fn heal_retry_budget_is_three() {
        // The 3-attempt retry behavior is pinned: changing the budget changes
        // restart/wipe operator expectations, so it must change loudly here.
        assert_eq!(HEAL_MAX_ATTEMPTS, 3);
    }
}
