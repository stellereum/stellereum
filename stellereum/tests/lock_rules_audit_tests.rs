//! Lock-rule audit tests (Tendermint locking, fail-closed).
//!
//! Scope: LOCK RULES ONLY — the exact state machine around
//! `HeightConsensus::locked`, `decide_prevote`, `try_prevote_quorum_at`
//! (unlock), `try_precommit_quorum` (lock + decide), the polka ledger
//! (`note_polka` / `observed_polka` / `best_polka`), and cross-height lock
//! isolation. Vote-set / QC assembly, round-sync and proposal validation
//! belong to other audits and are not touched here.
//!
//! State machine in words:
//!
//! ```text
//! unlocked ---(prevote QC for B at r, precommit B at r, same-round
//!               prevote QC for B agrees)--> locked=(B,r), decided=B
//! locked=(A,rL) ---(observe NON-NIL polka (rP,B), B!=A, rP>rL)--> unlocked
//! locked=(A,rL) ---(nil QC, any round)--> locked (UNCHANGED: nil is not a polka)
//! locked=(A,rL) ---(non-nil polka (rP,B), B!=A, rP<=rL)--> locked (UNCHANGED:
//!               stale evidence must not release a newer lock)
//! locked=(A,rL) ---(decide path sees conflicting block B)--> REFUSE (no decide,
//!               lock held), even at a higher round (fail-closed: the unlock
//!               must have happened first via a higher polka)
//! locked=(A,rL) ---(decide same value A at older round r<rL)--> decided=A,
//!               lock STAYS (A,rL): the lock round only moves forward
//! any lock ---(new HeightConsensus)--> None (locks never cross heights)
//! ```
//!
//! Every test below drives the REAL `HeightConsensus` (plus two
//! `ValidatorRuntime::make_precommit` tests for the vote-casting guard) with
//! real signed votes — no mocks.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::consensus::{HeightConsensus, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::ValidatorRuntime;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// Four validators, power 1 each: total 4, quorum `floor(2*4/3)+1 = 3`.
fn four() -> (Vec<SigningKey>, ValidatorSet) {
    let ks = vec![key(11), key(22), key(33), key(44)];
    let vs = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());
    assert_eq!(vs.quorum_power(), 3);
    (ks, vs)
}

fn prevote(k: &SigningKey, h: u64, r: u32, target: Option<[u8; 32]>) -> Vote {
    Vote::sign(k, h, r, VoteKind::Prevote, target)
}

fn precommit(k: &SigningKey, h: u64, r: u32, target: Option<[u8; 32]>) -> Vote {
    Vote::sign(k, h, r, VoteKind::Precommit, target)
}

fn quorum_prevotes(hc: &mut HeightConsensus, ks: &[SigningKey], h: u64, r: u32, t: Option<[u8; 32]>) {
    for k in ks {
        hc.add_prevote(prevote(k, h, r, t)).unwrap();
    }
}

fn quorum_precommits(
    hc: &mut HeightConsensus,
    ks: &[SigningKey],
    h: u64,
    r: u32,
    t: Option<[u8; 32]>,
) {
    for k in ks {
        hc.add_precommit(precommit(k, h, r, t)).unwrap();
    }
}

const X: [u8; 32] = [0x58; 32];
const Y: [u8; 32] = [0x59; 32];

// ============================================================================
// decide_prevote: the lock votes the lock, or nil.
// ============================================================================

/// A node locked on X that is offered Y MUST prevote nil (it must not vote
/// against its own lock), while the same lock offered X votes X.
#[test]
fn locked_prevote_must_nil_on_conflicting_proposal() {
    let (_, vs) = four();
    let mut hc = HeightConsensus::new(1, vs);
    hc.locked = Some((X, 0));
    hc.round = 1;

    let proposer = hc.proposer().expect("schedule must name a proposer");
    hc.receive_proposal(proposer, Y)
        .expect("conflicting proposal is still accepted as a proposal");
    assert_eq!(
        hc.decide_prevote(),
        None,
        "locked on X, proposed Y: the only legal prevote is nil"
    );

    // Same lock, matching proposal: vote the locked value.
    let mut hc2 = HeightConsensus::new(1, hc.validators.clone());
    hc2.locked = Some((X, 0));
    hc2.round = 1;
    let proposer2 = hc2.proposer().expect("schedule must name a proposer");
    hc2.receive_proposal(proposer2, X).unwrap();
    assert_eq!(hc2.decide_prevote(), Some(X));
}

/// No live proposal means nil — whether locked or not. A stale proposal from
/// an older round is NOT live and must not be voted either.
#[test]
fn no_live_proposal_means_nil_prevote() {
    let (_, vs) = four();
    let mut hc = HeightConsensus::new(1, vs);
    hc.round = 1;
    assert_eq!(hc.decide_prevote(), None, "no proposal: nil");

    let mut locked = HeightConsensus::new(1, hc.validators.clone());
    locked.locked = Some((X, 0));
    locked.round = 1;
    assert_eq!(locked.decide_prevote(), None, "locked but no proposal: nil");
}

// ============================================================================
// Unlock discipline: only a higher-round NON-NIL polka unlocks.
// ============================================================================

/// Higher-round conflicting polka releases the lock (BFT liveness: the
/// network moved on without us). Both the scan window and the polka ledger
/// must agree on the release.
#[test]
fn higher_round_conflicting_polka_unlocks() {
    let (ks, vs) = four();
    let mut hc = HeightConsensus::new(1, vs);
    hc.locked = Some((X, 0));
    hc.round = 1;

    quorum_prevotes(&mut hc, &ks, 1, 1, Some(Y));
    assert_eq!(hc.try_prevote_quorum_at(), Some((1, Some(Y))));
    assert_eq!(hc.observed_polka(), Some((1, Y)));
    assert_eq!(hc.locked, None, "higher Y polka must release the X lock");
}

/// EQUAL-round conflicting evidence must NOT unlock. Same-round quorums for
/// two values need >1/3 Byzantine power; believing the second one would let a
/// Byzantine quorum bounce an honest node off its lock in the round it took it.
#[test]
fn equal_round_conflicting_polka_must_not_unlock() {
    let (ks, vs) = four();
    let mut hc = HeightConsensus::new(1, vs);
    hc.locked = Some((X, 1));
    hc.round = 1;

    quorum_prevotes(&mut hc, &ks, 1, 1, Some(Y));
    // The ledger records what the network said ...
    assert_eq!(hc.observed_polka(), Some((1, Y)));
    // ... but the lock holds: 1 > 1 is false.
    assert_eq!(
        hc.locked,
        Some((X, 1)),
        "equal-round evidence must never unlock"
    );

    // And the decide path refuses the conflict too.
    quorum_precommits(&mut hc, &ks, 1, 1, Some(Y));
    assert_eq!(hc.try_precommit_quorum(), None);
    assert_eq!(hc.decided, None);
    assert_eq!(hc.locked, Some((X, 1)));
}

/// A LOWER-round (stale) polka must NOT unlock a newer lock:
/// newest-wins, an older quorum is superseded evidence.
#[test]
fn lower_round_conflicting_polka_must_not_unlock() {
    let (ks, vs) = four();
    let mut hc = HeightConsensus::new(1, vs);
    hc.locked = Some((X, 5));
    hc.round = 5;

    quorum_prevotes(&mut hc, &ks, 1, 3, Some(Y));
    hc.try_prevote_quorum_at();
    assert_eq!(
        hc.locked,
        Some((X, 5)),
        "stale round-3 evidence must not release a round-5 lock"
    );
}

/// A nil quorum at a HIGHER round must NEVER unlock (audit F-01): nil means
/// "no block was agreed in that round" — unlocking on it would drop a lock on
/// a block finalized one round earlier and fork.
#[test]
fn nil_quorum_at_higher_round_must_not_unlock() {
    let (ks, vs) = four();
    let mut hc = HeightConsensus::new(1, vs);
    hc.locked = Some((X, 0));
    hc.round = 1;

    quorum_prevotes(&mut hc, &ks, 1, 1, None);
    assert_eq!(hc.try_prevote_quorum_at(), Some((1, None)));
    assert_eq!(hc.observed_polka(), None, "nil is not a polka");
    assert_eq!(
        hc.locked,
        Some((X, 0)),
        "a nil quorum says nothing about any block"
    );
}

/// A nil precommit quorum neither locks nor decides, locked or not.
#[test]
fn nil_qc_never_locks_nor_decides() {
    let (ks, vs) = four();
    let mut hc = HeightConsensus::new(1, vs);
    quorum_prevotes(&mut hc, &ks, 1, 0, None);
    quorum_precommits(&mut hc, &ks, 1, 0, None);
    assert_eq!(hc.try_precommit_quorum(), None);
    assert_eq!(hc.locked, None, "nil must never create a value lock");
    assert_eq!(hc.decided, None);
}

/// The ledger path: a polka whose votes arrive AFTER the node raced ahead of
/// the network (outside the scan window) still unlocks — the ledger is the
/// network's latest word wherever it formed.
#[test]
fn late_polka_outside_scan_window_still_unlocks_via_ledger() {
    let (ks, vs) = four();
    let mut hc = HeightConsensus::new(1, vs);
    hc.locked = Some((X, 0));
    hc.round = 20; // raced far ahead; the scan window covers [12..20].

    quorum_prevotes(&mut hc, &ks, 1, 2, Some(Y)); // lands outside the window
    assert_eq!(hc.observed_polka(), Some((2, Y)), "ledger must record it");
    hc.try_prevote_quorum_at();
    assert_eq!(
        hc.locked, None,
        "the late round-2 polka (2 > 0) must release the lock"
    );
}

/// A stale ledger entry below the lock round does not unlock either.
#[test]
fn stale_ledger_below_lock_does_not_unlock() {
    let (ks, vs) = four();
    let mut hc = HeightConsensus::new(1, vs);
    hc.locked = Some((X, 5));
    hc.round = 5;

    quorum_prevotes(&mut hc, &ks, 1, 3, Some(Y));
    hc.try_prevote_quorum_at();
    assert_eq!(hc.locked, Some((X, 5)));
}

// ============================================================================
// Decide gate: same-round prevote agreement + lock refusal + monotonic lock.
// ============================================================================

/// A conflicting precommit QC — even with a matching same-round prevote QC —
/// must not decide past a held lock (fail-closed refusal).
#[test]
fn locked_decide_refuses_conflicting_qc() {
    let (ks, vs) = four();
    let mut hc = HeightConsensus::new(1, vs);
    hc.locked = Some((X, 0));

    quorum_prevotes(&mut hc, &ks, 1, 0, Some(Y));
    quorum_precommits(&mut hc, &ks, 1, 0, Some(Y));
    // Same round, so no unlock ...
    assert_eq!(hc.locked, Some((X, 0)));
    // ... and no decision against the lock.
    assert_eq!(hc.try_precommit_quorum(), None);
    assert_eq!(hc.decided, None);
}

/// Deciding the SAME value at an older round must not regress the lock round:
/// otherwise stale evidence could unlock past the newer lock (newest-wins
/// violation: a round-7 B polka would release a lock dropped from 9 to 5).
#[test]
fn decide_must_not_regress_lock_round() {
    let (ks, vs) = four();
    let mut hc = HeightConsensus::new(1, vs);
    hc.locked = Some((X, 9));
    hc.round = 9;

    quorum_prevotes(&mut hc, &ks, 1, 5, Some(X));
    quorum_precommits(&mut hc, &ks, 1, 5, Some(X));
    assert_eq!(
        hc.try_precommit_quorum(),
        Some(X),
        "same value still decides"
    );
    assert_eq!(
        hc.locked,
        Some((X, 9)),
        "the lock round must only move forward"
    );
}

/// The happy path still locks forward: deciding X at round 1 locks (X,1).
#[test]
fn decide_advances_lock_forward() {
    let (ks, vs) = four();
    let mut hc = HeightConsensus::new(1, vs);
    hc.round = 1;

    quorum_prevotes(&mut hc, &ks, 1, 1, Some(X));
    quorum_precommits(&mut hc, &ks, 1, 1, Some(X));
    assert_eq!(hc.try_precommit_quorum(), Some(X));
    assert_eq!(hc.locked, Some((X, 1)));
    assert_eq!(hc.decided, Some(X));
}

// ============================================================================
// Cross-height isolation: locks (and their votes) never cross heights.
// ============================================================================

/// A lock taken at height 1 is gone at height 2: the fresh height starts
/// unlocked, follows its own proposal, and rejects height-1 votes.
#[test]
fn lock_does_not_survive_height_advance() {
    let (ks, vs) = four();
    let mut h1 = HeightConsensus::new(1, vs.clone());
    h1.locked = Some((X, 0));
    h1.round = 1;
    quorum_prevotes(&mut h1, &ks, 1, 1, Some(X));
    quorum_precommits(&mut h1, &ks, 1, 1, Some(X));
    assert_eq!(h1.try_precommit_quorum(), Some(X));

    // Height 2 starts with a clean slate (this mirrors the runtime, which
    // installs a fresh `HeightConsensus::new` on every finalize).
    let mut h2 = HeightConsensus::new(2, vs);
    assert_eq!(h2.locked, None);
    assert_eq!(h2.decided, None);
    let proposer = h2.proposer().expect("schedule must name a proposer");
    h2.receive_proposal(proposer, Y).unwrap();
    assert_eq!(h2.decide_prevote(), Some(Y));

    // A stale height-1 vote is out of scope at height 2, not a phantom polka.
    assert!(h2.add_prevote(prevote(&ks[0], 1, 0, Some(X))).is_err());
    assert_eq!(h2.observed_polka(), None);
}

// ============================================================================
// Vote-casting guard (production `ValidatorRuntime::make_precommit`): never
// precommit against the held lock; follow only a strictly higher polka.
// ============================================================================

async fn funded_state(owner: [u8; 32]) -> Arc<InMemoryStateEngine> {
    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(AccountState::new(owner, 10_000_000)).await;
    st
}

async fn runtime4() -> (Vec<SigningKey>, ValidatorRuntime) {
    let ks = vec![key(11), key(22), key(33), key(44)];
    let vs = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());
    let me = id(&ks[0]);
    let st = funded_state(me).await;
    let rt = ValidatorRuntime::new(ks[0].clone(), vs, st, 1);
    (ks, rt)
}

/// Locked on X at round 1, the node must NOT precommit a round-1 Y polka
/// (equal round is stale evidence), but MUST follow a round-2 Y polka and
/// re-lock there.
#[tokio::test]
async fn precommit_casting_refuses_equal_round_conflict_follows_higher() {
    let (ks, mut rt) = runtime4().await;
    let h = rt.hc.height;
    rt.hc.locked = Some((X, 1));
    rt.hc.round = 1;

    // Equal-round Y polka: the network speaks, but not above our lock.
    for k in &ks {
        rt.on_prevote(prevote(k, h, 1, Some(Y))).unwrap();
    }
    assert_eq!(rt.hc.observed_polka(), Some((1, Y)));
    assert_eq!(
        rt.make_precommit(),
        None,
        "equal-round conflict must not be precommitted"
    );
    assert_eq!(rt.hc.locked, Some((X, 1)), "the lock must hold");

    // Strictly higher Y polka: unlock and follow.
    rt.next_round();
    assert_eq!(rt.hc.round, 2);
    for k in &ks {
        rt.on_prevote(prevote(k, h, 2, Some(Y))).unwrap();
    }
    let pc = rt
        .make_precommit()
        .expect("higher polka must be followed");
    assert_eq!(pc.block_hash, Some(Y));
    assert_eq!(pc.round, 2, "stamped with the polka's round");
    assert_eq!(rt.hc.locked, Some((Y, 2)));
}

/// A nil quorum never becomes a precommit while a value lock is held.
#[tokio::test]
async fn precommit_casting_ignores_nil_quorum_under_value_lock() {
    let (ks, mut rt) = runtime4().await;
    let h = rt.hc.height;
    rt.hc.locked = Some((X, 0));
    rt.hc.round = 1;

    for k in &ks {
        rt.on_prevote(prevote(k, h, 1, None)).unwrap();
    }
    assert_eq!(rt.hc.observed_polka(), None);
    assert_eq!(
        rt.make_precommit(),
        None,
        "nil is not a polka: nothing to precommit"
    );
    assert_eq!(rt.hc.locked, Some((X, 0)));
}
