//! # BFT lock safety + liveness at the HeightConsensus level.
//!
//! REVIEW DIMENSION 1 (enterprise-testnet consensus review): SAFETY
//! (agreement + validity + integrity) and the convergence side of LIVENESS.
//!
//! These tests drive the REAL `HeightConsensus` state machine (votes,
//! locks, polkas, quorums) with hand-built keys and powers — no mocks,
//! only adversarial vote injection. What they prove:
//!
//! * SAFETY (agreement): two honest nodes locked on DIFFERENT blocks at the
//!   same height can never finalize DIFFERENT blocks. The lock check in
//!   `try_precommit_quorum` (`consensus.rs`), the same-round prevote-QC
//!   gate, and the quorum-intersection arithmetic each refuse the fork
//!   independently (`locked_node_refuses_a_conflicting_precommit_qc`,
//!   `precommit_qc_without_a_same_round_prevote_qc_never_decides`,
//!   `nil_veto_arithmetic_blocks_every_palka`).
//! * LOCK DISCIPLINE (validity of unlocks): a nil quorum at a higher round
//!   NEVER unlocks (`nil_quorum_at_a_higher_round_never_unlocks` — the
//!   audit F-01 rule: nil means "no block was agreed in that round", and
//!   unlocking on it would drop a lock on a block finalized one round
//!   earlier); only a NON-NIL polka at a STRICTLY HIGHER round unlocks
//!   (`higher_non_nil_palka_unlocks`).
//! * CONVERGENCE (liveness): two honest nodes locked on different blocks,
//!   with the rest unlocked, CONVERGE on the author's re-proposal instead
//!   of forking (`split_locks_converge_on_the_authors_reproposal`): the
//!   differently-locked node observes the higher-round polka, unlocks, and
//!   all three decide the same block.
//! * KNOWN LIMITATION (liveness, HIGH): with NO unlocked tiebreaker — the
//!   [2,2] symmetric split — neither value can ever marshal a polka, so no
//!   higher polka ever forms and both locks hold forever
//!   (`symmetric_split_lock_never_converges_without_unlocked_power`).
//!   The deadlock breaker deliberately preserves bodyful locks (safety over
//!   liveness), so automation does not fix this either; the structural fix
//!   is the Tendermint validRound mechanism (the proposal carries the
//!   prevote QC that justifies unlocking, so a locked node can follow a
//!   value it never saw a polka for). This test pins the stall AND the
//!   absence of a fork, so the limitation stays visible until validRound
//!   lands.
//!
//! All powers are explicit and every quorum number is asserted from the
//! set's own rule (`quorum_power`), so the tests pin the REAL arithmetic,
//! including the live veto shape ([2,1,1]: the power-2 holder alone blocks
//! every polka, exactly like the ~34%-stake validators on the live stand).

use ed25519_dalek::SigningKey;
use stellereum::consensus::{HeightConsensus, ValidatorSet, Vote, VoteKind};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// Three validators with SKEWED power [2,1,1] (total 4, quorum 3): the
/// live-stand shape, where the largest holder alone vetoes every polka.
fn skewed_set() -> (SigningKey, SigningKey, SigningKey, ValidatorSet) {
    let (a, b, c) = (key(1), key(2), key(3));
    let vs = ValidatorSet::from_list(vec![(id(&a), 2), (id(&b), 1), (id(&c), 1)]);
    assert_eq!(vs.total_power(), 4);
    assert_eq!(vs.quorum_power(), 3, "floor(2*4/3)+1 = 3");
    (a, b, c, vs)
}

fn prevote(k: &SigningKey, h: u64, r: u32, target: Option<[u8; 32]>) -> Vote {
    Vote::sign(k, h, r, VoteKind::Prevote, target)
}

fn precommit(k: &SigningKey, h: u64, r: u32, target: Option<[u8; 32]>) -> Vote {
    Vote::sign(k, h, r, VoteKind::Precommit, target)
}

const X: [u8; 32] = [0x58; 32];
const Y: [u8; 32] = [0x59; 32];

/// SAFETY: a node locked on X refuses to decide Y even when a full Y
/// precommit QC plus a same-round Y prevote QC are presented (the
/// adversarial injection: two conflicting polkas in one round need >1/3
/// Byzantine power, which is exactly what this simulates).
#[test]
fn locked_node_refuses_a_conflicting_precommit_qc() {
    let (a, b, c, vs) = skewed_set();
    let mut hc = HeightConsensus::new(1, vs);
    hc.locked = Some((X, 0));

    // A full Y quorum at the SAME round as the lock (prevotes + precommits,
    // power 4 >= 3). The unlock scan must NOT release the lock (same round
    // is not a higher round), and finalization must refuse.
    for k in [&a, &b, &c] {
        hc.add_prevote(prevote(k, 1, 0, Some(Y))).unwrap();
        hc.add_precommit(precommit(k, 1, 0, Some(Y))).unwrap();
    }
    assert_eq!(
        hc.locked,
        Some((X, 0)),
        "same-round evidence must not unlock"
    );
    assert_eq!(
        hc.try_precommit_quorum(),
        None,
        "a locked node must never decide against its lock"
    );
    assert_eq!(hc.decided, None);
}

/// SAFETY: a precommit QC alone never decides — the same-round prevote QC
/// gate (`try_precommit_quorum`) refuses, so precommits for a block nobody
/// prevoted cannot finalize it.
#[test]
fn precommit_qc_without_a_same_round_prevote_qc_never_decides() {
    let (a, b, c, vs) = skewed_set();
    let mut hc = HeightConsensus::new(1, vs);
    for k in [&a, &b, &c] {
        hc.add_precommit(precommit(k, 1, 0, Some(X))).unwrap();
    }
    assert_eq!(
        hc.try_precommit_quorum(),
        None,
        "precommits without a same-round prevote QC must not decide"
    );
    assert_eq!(hc.decided, None);
}

/// SAFETY + LIVENESS SHAPE: with the largest holder (power 2 of 4) voting
/// nil, NO polka can form — for Y (power 2 < 3) or for X (power 2 < 3) or
/// nil itself. This is the exact live-stall arithmetic: a ~1/3+ holder's
/// nil single-handedly vetoes every quorum, so the polka that would unlock
/// it never forms and the height parks.
#[test]
fn nil_veto_arithmetic_blocks_every_palka() {
    let (a, b, c, vs) = skewed_set();
    let mut hc = HeightConsensus::new(1, vs);
    hc.add_prevote(prevote(&a, 1, 0, None)).unwrap();
    hc.add_prevote(prevote(&b, 1, 0, Some(Y))).unwrap();
    hc.add_prevote(prevote(&c, 1, 0, Some(Y))).unwrap();

    assert_eq!(hc.prevote_set(0).unwrap().power_for(Some(Y)), 2);
    assert_eq!(hc.prevote_set(0).unwrap().power_for(None), 2);
    assert_eq!(
        hc.try_prevote_quorum_at(),
        None,
        "no target reaches 3: no polka, no unlock, no precommit"
    );
    assert_eq!(hc.observed_polka(), None);
}

/// LOCK DISCIPLINE (audit F-01): a nil quorum at a HIGHER round must NEVER
/// unlock. Otherwise a node that timed out in round 1 would drop its lock
/// on a block finalized in round 0 and finalize a conflicting block later.
#[test]
fn nil_quorum_at_a_higher_round_never_unlocks() {
    let (a, b, c, vs) = skewed_set();
    let mut hc = HeightConsensus::new(1, vs);
    hc.locked = Some((X, 0));
    hc.round = 1; // the node timed out into round 1; the scan covers rounds <= local.

    for k in [&a, &b, &c] {
        hc.add_prevote(prevote(k, 1, 1, None)).unwrap();
    }
    let found = hc.try_prevote_quorum_at();
    assert_eq!(found, Some((1, None)), "the nil quorum is observed");
    assert_eq!(
        hc.locked,
        Some((X, 0)),
        "a nil quorum says nothing about any block: the lock must hold"
    );
}

/// LOCK DISCIPLINE: a NON-NIL polka at a STRICTLY HIGHER round for a
/// different value releases the lock (BFT liveness — the network moved on
/// without us after a lost vote).
#[test]
fn higher_non_nil_palka_unlocks() {
    let (a, b, c, vs) = skewed_set();
    let mut hc = HeightConsensus::new(1, vs);
    hc.locked = Some((X, 0));
    hc.round = 1; // the node timed out into round 1; the scan covers rounds <= local.

    for k in [&a, &b, &c] {
        hc.add_prevote(prevote(k, 1, 1, Some(Y))).unwrap();
    }
    let found = hc.try_prevote_quorum_at();
    assert_eq!(found, Some((1, Some(Y))));
    assert_eq!(
        hc.locked, None,
        "the higher polka for Y must release the X lock"
    );
}

/// CONVERGENCE: A locked on X, B locked on Y, C unlocked. The author
/// re-proposes X at round 1; A and C vote it (B nils — lock mismatch, the
/// correct Tendermint vote); the X polka at round 1 > B's lock round
/// unlocks B; all three precommit X and decide X. No fork, one decision.
#[test]
fn split_locks_converge_on_the_authors_reproposal() {
    let (a, b, c, vs) = skewed_set();
    let mut ha = HeightConsensus::new(1, vs.clone());
    let mut hb = HeightConsensus::new(1, vs.clone());
    let mut hc = HeightConsensus::new(1, vs);
    ha.locked = Some((X, 0));
    hb.locked = Some((Y, 0));

    // Round 1: every node holds the re-proposed X body.
    for h in [&mut ha, &mut hb, &mut hc] {
        h.round = 1;
        let proposer = h.proposer().expect("the schedule must name a proposer");
        h.receive_proposal(proposer, X)
            .expect("round-1 X proposal must be accepted");
    }

    // The prevote rule, pinned at unit level: lock-match votes the value,
    // lock-mismatch votes nil, unlocked votes the proposal.
    assert_eq!(ha.decide_prevote(), Some(X));
    assert_eq!(
        hb.decide_prevote(),
        None,
        "B is locked on Y: it must nil-vote X"
    );
    assert_eq!(hc.decide_prevote(), Some(X));

    // The round's prevotes (A:X, B:nil, C:X) reach every node.
    let votes = vec![
        prevote(&a, 1, 1, Some(X)),
        prevote(&b, 1, 1, None),
        prevote(&c, 1, 1, Some(X)),
    ];
    for h in [&mut ha, &mut hb, &mut hc] {
        for v in &votes {
            h.add_prevote(v.clone()).unwrap();
        }
    }

    // X carries power 3 >= 3: the polka forms on every node despite B's nil.
    for h in [&mut ha, &mut hb, &mut hc] {
        assert_eq!(h.try_prevote_quorum_at(), Some((1, Some(X))));
    }
    // …and it unlocks B (round 1 > lock round 0, different value).
    assert_eq!(hb.locked, None, "the higher X polka must unlock B's Y lock");
    assert_eq!(
        ha.locked,
        Some((X, 0)),
        "A's X lock is confirmed, not dropped"
    );

    // All three precommit X at the polka's round and decide X — one value,
    // no fork.
    for h in [&mut ha, &mut hb, &mut hc] {
        for k in [&a, &b, &c] {
            h.add_precommit(precommit(k, 1, 1, Some(X))).unwrap();
        }
    }
    assert_eq!(ha.try_precommit_quorum(), Some(X));
    assert_eq!(hb.try_precommit_quorum(), Some(X));
    assert_eq!(hc.try_precommit_quorum(), Some(X));
    assert_eq!(
        (ha.decided, hb.decided, hc.decided),
        (Some(X), Some(X), Some(X))
    );
}

/// KNOWN LIMITATION (liveness, HIGH — see the review report): the symmetric
/// [2,2] split. A locked on X and B locked on Y, quorum 3: neither value
/// can marshal a polka (each side's own power 2 < 3, the other side nils),
/// so no higher polka ever forms, neither lock ever releases, and no
/// decision is ever taken — while the round counter climbs. The deadlock
/// breaker deliberately preserves bodyful locks (safety over liveness), so
/// automation does not fix this either.
///
/// This test pins BOTH halves: the stall (no decision after several
/// contested rounds) AND the absence of a fork (no conflicting decision,
/// no precommit QC banked). It must be DELETED — not updated — when the
/// validRound mechanism lands, because validRound makes this shape
/// converge.
#[test]
fn symmetric_split_lock_never_converges_without_unlocked_power() {
    let (a, b, _, _) = skewed_set();
    let vs22 = ValidatorSet::from_list(vec![(id(&a), 2), (id(&b), 2)]);
    assert_eq!(vs22.quorum_power(), 3, "floor(2*4/3)+1 = 3");

    let mut ha = HeightConsensus::new(1, vs22.clone());
    let mut hb = HeightConsensus::new(1, vs22);
    ha.locked = Some((X, 0));
    hb.locked = Some((Y, 0));

    // Four contested rounds, alternating values. Each round the proposing
    // side votes its lock and the other side nils; nothing reaches 3.
    for r in 1..=4u32 {
        let (proposal, a_vote, b_vote) = if r % 2 == 1 {
            (X, Some(X), None)
        } else {
            (Y, None, Some(Y))
        };
        for (h, v) in [(&mut ha, a_vote), (&mut hb, b_vote)] {
            // Advance via the state machine, not `h.round = r`: `next_round`
            // clears the prior round's proposal, which the F1
            // one-proposal-per-round guard (72bcfd8 2026-10-30) otherwise
            // refuses to overwrite -- a stale direct assignment leaves the
            // previous round's body in place and `decide_prevote` votes it.
            // Both nodes start at round 0, so one step per contested round
            // lands exactly on `r`.
            h.next_round();
            assert_eq!(h.round, r, "one state-machine step per contested round");
            let proposer = h.proposer().expect("schedule must name a proposer");
            h.receive_proposal(proposer, proposal).ok();
            assert_eq!(
                h.decide_prevote(),
                v,
                "r{r}: the lock decides the vote (value on match, nil on mismatch)"
            );
        }
        ha.add_prevote(prevote(&a, 1, r, a_vote)).unwrap();
        ha.add_prevote(prevote(&b, 1, r, b_vote)).unwrap();
        hb.add_prevote(prevote(&a, 1, r, a_vote)).unwrap();
        hb.add_prevote(prevote(&b, 1, r, b_vote)).unwrap();
        assert_eq!(
            ha.try_prevote_quorum_at(),
            None,
            "r{r}: no polka for either value"
        );
        assert_eq!(
            hb.try_prevote_quorum_at(),
            None,
            "r{r}: no polka for either value"
        );

        ha.add_precommit(precommit(&a, 1, r, a_vote)).unwrap();
        ha.add_precommit(precommit(&b, 1, r, b_vote)).unwrap();
        hb.add_precommit(precommit(&a, 1, r, a_vote)).unwrap();
        hb.add_precommit(precommit(&b, 1, r, b_vote)).unwrap();
        assert_eq!(ha.try_precommit_quorum(), None, "r{r}: no decision on A");
        assert_eq!(hb.try_precommit_quorum(), None, "r{r}: no decision on B");
    }

    // The stall is total — and fork-free: neither side decided anything.
    assert_eq!((ha.decided, hb.decided), (None, None));
    assert!(ha.precommit_qc.is_none() && hb.precommit_qc.is_none());
    // …while the locks that caused it are still held (the breaker keeps
    // bodyful locks by design, so this is also the post-breaker state).
    assert_eq!(ha.locked, Some((X, 0)));
    assert_eq!(hb.locked, Some((Y, 0)));
}
