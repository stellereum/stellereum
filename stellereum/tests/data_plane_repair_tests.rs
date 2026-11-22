// Exercised through the shared library exports (`stellereum::data_plane`,
// `stellereum::data_plane_repair`); neither is wired into a network path.
use std::time::{Duration, Instant};

use stellereum::data_plane::{make_proof, Chunk, Parameters};
use stellereum::data_plane_repair::{Acceptance, Context, Error, Limits, Repair, SessionId};

const DATA: &[u8] = b"abcdefghij";
const SESSION: SessionId = SessionId([1; 32]);
const CONTEXT: Context = Context {
    height: 7,
    round: 2,
};

fn params() -> Parameters {
    Parameters {
        total_len: 10,
        chunk_size: 4,
    }
}
fn limits() -> Limits {
    Limits {
        max_chunks: 3,
        max_bytes: 1000,
        max_retries: 1,
        max_in_flight: 3,
    }
}
fn setup(now: Instant, limits: Limits) -> Repair {
    let root = make_proof(DATA, 4, 0).unwrap().0;
    Repair::new(
        CONTEXT,
        SESSION,
        root,
        params(),
        limits,
        now,
        now + Duration::from_secs(10),
    )
    .unwrap()
}
fn chunk(index: u32) -> Chunk<'static> {
    let start = index as usize * 4;
    Chunk {
        parameters: params(),
        index,
        payload: &DATA[start..(start + params().payload_len(index).unwrap())],
    }
}
fn proof(index: u32) -> Vec<[u8; 32]> {
    make_proof(DATA, 4, index).unwrap().1
}

#[test]
fn reordered_duplicate_and_complete_assembly() {
    let now = Instant::now();
    let mut repair = setup(now, limits());
    let a = repair.request(CONTEXT, now, 0).unwrap();
    let b = repair.request(CONTEXT, now, 1).unwrap();
    let c = repair.request(CONTEXT, now, 2).unwrap();
    assert_eq!(
        repair.accept(CONTEXT, now, c, chunk(2), &proof(2)),
        Ok(Acceptance::Stored)
    );
    assert_eq!(
        repair.accept(CONTEXT, now, c, chunk(2), &proof(2)),
        Ok(Acceptance::Duplicate)
    );
    assert_eq!(repair.body(CONTEXT, now), Err(Error::Incomplete));
    assert_eq!(
        repair.accept(CONTEXT, now, a, chunk(0), &proof(0)),
        Ok(Acceptance::Stored)
    );
    assert_eq!(
        repair.accept(CONTEXT, now, b, chunk(1), &proof(1)),
        Ok(Acceptance::Stored)
    );
    assert_eq!(repair.body(CONTEXT, now).unwrap(), DATA);
}

#[test]
fn tamper_wrong_index_and_stale_attempt_never_fill_slot() {
    let now = Instant::now();
    let mut repair = setup(now, limits());
    let first = repair.request(CONTEXT, now, 0).unwrap();
    let corrupt = Chunk {
        payload: b"abce",
        ..chunk(0)
    };
    assert_eq!(
        repair.accept(CONTEXT, now, first, corrupt, &proof(0)),
        Err(Error::InvalidChunk)
    );
    let second = repair.request(CONTEXT, now, 0).unwrap();
    assert_eq!(
        repair.accept(CONTEXT, now, first, chunk(0), &proof(0)),
        Err(Error::UnknownRequest)
    );
    assert_eq!(
        repair.accept(CONTEXT, now, second, chunk(1), &proof(1)),
        Err(Error::WrongChunk)
    );
    assert_eq!(repair.request(CONTEXT, now, 0), Err(Error::RetryLimit));
    assert_eq!(repair.body(CONTEXT, now), Err(Error::Incomplete));
}

#[test]
fn limits_count_attempts_parallelism_chunks_and_rejected_bytes() {
    let now = Instant::now();
    let mut too_few = limits();
    too_few.max_chunks = 2;
    assert!(matches!(
        Repair::new(
            CONTEXT,
            SESSION,
            [0; 32],
            params(),
            too_few,
            now,
            now + Duration::from_secs(1)
        ),
        Err(Error::ChunkLimit)
    ));
    let mut capped = limits();
    capped.max_in_flight = 1;
    capped.max_bytes = 67; // one response needs 4 + 2*32 bytes
    let mut repair = setup(now, capped);
    let first = repair.request(CONTEXT, now, 0).unwrap();
    assert_eq!(
        repair.request(CONTEXT, now, 0),
        Err(Error::AlreadyRequested)
    );
    assert_eq!(
        repair.request(CONTEXT, now, 1),
        Err(Error::ConcurrencyLimit)
    );
    let corrupt = Chunk {
        payload: b"abce",
        ..chunk(0)
    };
    assert_eq!(
        repair.accept(CONTEXT, now, first, corrupt, &proof(0)),
        Err(Error::ByteLimit)
    );
    assert_eq!(repair.body(CONTEXT, now), Err(Error::ByteLimit));
    let mut repair = setup(now, limits());
    let first = repair.request(CONTEXT, now, 0).unwrap();
    repair.fail(CONTEXT, now, first).unwrap();
    let retry = repair.request(CONTEXT, now, 0).unwrap();
    repair.fail(CONTEXT, now, retry).unwrap();
    assert_eq!(repair.request(CONTEXT, now, 0), Err(Error::RetryLimit));
}

#[test]
fn cancellation_deadline_and_context_change_retire_everything() {
    let now = Instant::now();
    let mut repair = setup(now, limits());
    let req = repair.request(CONTEXT, now, 0).unwrap();
    repair.cancel();
    assert_eq!(
        repair.accept(CONTEXT, now, req, chunk(0), &proof(0)),
        Err(Error::Cancelled)
    );
    assert_eq!(repair.body(CONTEXT, now), Err(Error::Cancelled));
    let mut repair = setup(now, limits());
    assert_eq!(
        repair.body(CONTEXT, now + Duration::from_secs(10)),
        Err(Error::Deadline)
    );
    assert_eq!(repair.request(CONTEXT, now, 0), Err(Error::Deadline));
    let mut repair = setup(now, limits());
    let req = repair.request(CONTEXT, now, 0).unwrap();
    let next = Context {
        round: 3,
        ..CONTEXT
    };
    assert_eq!(
        repair.accept(next, now, req, chunk(0), &proof(0)),
        Err(Error::ContextChanged)
    );
    assert_eq!(repair.body(CONTEXT, now), Err(Error::ContextChanged));
    let mut repair = setup(now, limits());
    assert_eq!(
        repair.body(CONTEXT, now - Duration::from_nanos(1)),
        Err(Error::ClockRegression)
    );
}

#[test]
fn wrong_root_and_empty_body() {
    let now = Instant::now();
    let mut repair = Repair::new(
        CONTEXT,
        SESSION,
        [0; 32],
        params(),
        limits(),
        now,
        now + Duration::from_secs(1),
    )
    .unwrap();
    let req = repair.request(CONTEXT, now, 0).unwrap();
    assert_eq!(
        repair.accept(CONTEXT, now, req, chunk(0), &proof(0)),
        Err(Error::InvalidChunk)
    );
    let parameters = Parameters {
        total_len: 0,
        chunk_size: 4,
    };
    let (root, proof) = make_proof(b"", 4, 0).unwrap();
    let mut repair = Repair::new(
        CONTEXT,
        SESSION,
        root,
        parameters,
        limits(),
        now,
        now + Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(repair.body(CONTEXT, now), Err(Error::Incomplete));
    let req = repair.request(CONTEXT, now, 0).unwrap();
    assert_eq!(
        repair.accept(
            CONTEXT,
            now,
            req,
            Chunk {
                parameters,
                index: 0,
                payload: b""
            },
            &proof
        ),
        Ok(Acceptance::Stored)
    );
    assert_eq!(repair.body(CONTEXT, now), Ok(Vec::new()));
}

#[test]
fn tampered_proof_and_duplicate_responses_consume_budget() {
    let now = Instant::now();
    let mut repair = setup(now, limits());
    let req = repair.request(CONTEXT, now, 0).unwrap();
    let mut bad = proof(0);
    bad[0][0] ^= 1;
    assert_eq!(
        repair.accept(CONTEXT, now, req, chunk(0), &bad),
        Err(Error::InvalidChunk)
    );
    assert_eq!(repair.body(CONTEXT, now), Err(Error::Incomplete));

    let mut capped = limits();
    capped.max_bytes = 68;
    let mut repair = setup(now, capped);
    let req = repair.request(CONTEXT, now, 0).unwrap();
    assert_eq!(
        repair.accept(CONTEXT, now, req, chunk(0), &proof(0)),
        Ok(Acceptance::Stored)
    );
    assert_eq!(
        repair.accept(CONTEXT, now, req, chunk(0), &proof(0)),
        Err(Error::ByteLimit)
    );
    assert_eq!(repair.body(CONTEXT, now), Err(Error::ByteLimit));
}

#[test]
fn completed_slot_rejects_unissued_stale_and_invalid_duplicates() {
    let now = Instant::now();
    let mut repair = setup(now, limits());
    let stale = repair.request(CONTEXT, now, 0).unwrap();
    repair.fail(CONTEXT, now, stale).unwrap();
    let accepted = repair.request(CONTEXT, now, 0).unwrap();
    let other = repair.request(CONTEXT, now, 1).unwrap();
    assert_eq!(
        repair.accept(CONTEXT, now, accepted, chunk(0), &proof(0)),
        Ok(Acceptance::Stored)
    );
    assert_eq!(
        repair.accept(CONTEXT, now, stale, chunk(0), &proof(0)),
        Err(Error::UnknownRequest)
    );
    let mut forged = other;
    forged.index = 0;
    assert_eq!(
        repair.accept(CONTEXT, now, forged, chunk(0), &proof(0)),
        Err(Error::UnknownRequest)
    );
    assert_eq!(
        repair.accept(CONTEXT, now, accepted, chunk(1), &proof(1)),
        Err(Error::WrongChunk)
    );
    let mut bad = proof(0);
    bad[0][0] ^= 1;
    assert_eq!(
        repair.accept(CONTEXT, now, accepted, chunk(0), &bad),
        Err(Error::InvalidChunk)
    );
    assert_eq!(
        repair.accept(CONTEXT, now, accepted, chunk(0), &proof(0)),
        Ok(Acceptance::Duplicate)
    );
    assert_eq!(
        repair.accept(CONTEXT, now, other, chunk(1), &proof(1)),
        Ok(Acceptance::Stored)
    );
    assert_eq!(repair.body(CONTEXT, now), Err(Error::Incomplete));
}

#[test]
fn impossible_byte_budget_and_invalid_parameters_rejected_at_creation() {
    let now = Instant::now();
    let deadline = now + Duration::from_secs(1);
    let mut capped = limits();
    capped.max_bytes = 9;
    assert!(matches!(
        Repair::new(CONTEXT, SESSION, [0; 32], params(), capped, now, deadline),
        Err(Error::ByteLimit)
    ));
    let bad = Parameters {
        total_len: u64::MAX,
        chunk_size: 1,
    };
    assert!(matches!(
        Repair::new(CONTEXT, SESSION, [0; 32], bad, limits(), now, deadline),
        Err(Error::InvalidParameters)
    ));
    assert!(matches!(
        Repair::new(CONTEXT, SESSION, [0; 32], params(), limits(), now, now),
        Err(Error::InvalidParameters)
    ));
}

#[test]
fn out_of_bounds_and_late_fail_do_not_release_or_revive_requests() {
    let now = Instant::now();
    let mut capped = limits();
    capped.max_in_flight = 1;
    let mut repair = setup(now, capped);
    assert_eq!(
        repair.request(CONTEXT, now, u32::MAX),
        Err(Error::IndexOutOfBounds)
    );
    let first = repair.request(CONTEXT, now, 0).unwrap();
    repair.fail(CONTEXT, now, first).unwrap();
    let retry = repair.request(CONTEXT, now, 0).unwrap();
    assert_eq!(repair.fail(CONTEXT, now, first), Err(Error::UnknownRequest));
    assert_eq!(
        repair.request(CONTEXT, now, 1),
        Err(Error::ConcurrencyLimit)
    );
    assert_eq!(
        repair.fail(CONTEXT, now + Duration::from_secs(10), retry),
        Err(Error::Deadline)
    );
    assert_eq!(repair.fail(CONTEXT, now, retry), Err(Error::Deadline));
}

#[test]
fn stale_response_from_another_session_cannot_complete_or_retire_request() {
    let now = Instant::now();
    let mut old = setup(now, limits());
    let stale = old.request(CONTEXT, now, 0).unwrap();
    old.cancel();

    let root = make_proof(DATA, 4, 0).unwrap().0;
    let mut new = Repair::new(
        CONTEXT,
        SessionId([2; 32]),
        root,
        params(),
        limits(),
        now,
        now + Duration::from_secs(10),
    )
    .unwrap();
    let current = new.request(CONTEXT, now, 0).unwrap();
    assert_ne!(stale, current);
    assert_eq!(new.fail(CONTEXT, now, stale), Err(Error::UnknownRequest));
    assert_eq!(
        new.accept(CONTEXT, now, stale, chunk(0), &proof(0)),
        Err(Error::UnknownRequest)
    );
    assert_eq!(new.body(CONTEXT, now), Err(Error::Incomplete));
    assert_eq!(
        new.accept(CONTEXT, now, current, chunk(0), &proof(0)),
        Ok(Acceptance::Stored)
    );
    assert_eq!(
        new.accept(CONTEXT, now, stale, chunk(0), &proof(0)),
        Err(Error::UnknownRequest)
    );
    assert_eq!(
        new.accept(CONTEXT, now, current, chunk(0), &proof(0)),
        Ok(Acceptance::Duplicate)
    );
}

#[test]
fn cross_session_rejected_response_still_consumes_budget() {
    let now = Instant::now();
    let mut old = setup(now, limits());
    let stale = old.request(CONTEXT, now, 0).unwrap();
    let mut capped = limits();
    capped.max_bytes = 68;
    let root = make_proof(DATA, 4, 0).unwrap().0;
    let mut new = Repair::new(
        CONTEXT,
        SessionId([2; 32]),
        root,
        params(),
        capped,
        now,
        now + Duration::from_secs(10),
    )
    .unwrap();
    let current = new.request(CONTEXT, now, 0).unwrap();
    assert_eq!(
        new.accept(CONTEXT, now, stale, chunk(0), &proof(0)),
        Err(Error::UnknownRequest)
    );
    assert_eq!(
        new.accept(CONTEXT, now, current, chunk(0), &proof(0)),
        Err(Error::ByteLimit)
    );
}

#[test]
fn reusing_session_identifier_recreates_token_collision() {
    let now = Instant::now();
    let mut old = setup(now, limits());
    let stale = old.request(CONTEXT, now, 0).unwrap();
    old.cancel();
    // This violates the caller's uniqueness obligation, even after cancellation.
    let mut new = setup(now, limits());
    let current = new.request(CONTEXT, now, 0).unwrap();
    assert_eq!(stale, current);
    assert_eq!(
        new.accept(CONTEXT, now, stale, chunk(0), &proof(0)),
        Ok(Acceptance::Stored)
    );
}
