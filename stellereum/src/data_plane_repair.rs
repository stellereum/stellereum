//! Isolated, caller-driven repair. This is not a protocol or a DA guarantee.
//!
//! The caller must independently authenticate `root` for `context` and the
//! parameters, supply a monotonic clock, cancel underlying I/O when requests
//! are retired, and enforce any aggregate (multi-session or wire) limits.
//! The caller must supply a distinct session identifier for every repair whose
//! requests might overlap or arrive late, including across restarts. Reusing an
//! identifier can make an old token valid again. The caller must preserve the
//! original request token with its I/O and must not relabel a reply with a new
//! token. Session identifiers are not generated, registered, or authenticated
//! by this module and are not a wire protocol.
//! Deadlines are enforced when this state machine is called, not by a timer.

use std::time::Instant;

use crate::data_plane::{verify_chunk, Chunk, Hash, Parameters};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    pub height: u64,
    pub round: u64,
}

/// Caller-assigned identifier; uniqueness and lifecycle are the caller's duty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(pub [u8; 32]);

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_chunks: u32,
    /// Maximum sum of response payload and proof bytes, including rejected responses.
    pub max_bytes: u64,
    /// Additional attempts per index after its first request.
    pub max_retries: u32,
    pub max_in_flight: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    pub index: u32,
    session: SessionId,
    id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidParameters,
    ChunkLimit,
    ByteLimit,
    RetryLimit,
    ConcurrencyLimit,
    IndexOutOfBounds,
    AlreadyRequested,
    AlreadyComplete,
    UnknownRequest,
    WrongChunk,
    InvalidChunk,
    Incomplete,
    Cancelled,
    Deadline,
    ContextChanged,
    ClockRegression,
    IdExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Acceptance {
    Stored,
    Duplicate,
}

struct Slot {
    payload: Option<Vec<u8>>,
    active: Option<u64>,
    completed: Option<u64>,
    attempts: u64,
}

pub struct Repair {
    context: Context,
    session: SessionId,
    root: Hash,
    parameters: Parameters,
    limits: Limits,
    deadline: Instant,
    last_now: Instant,
    slots: Vec<Slot>,
    in_flight: u32,
    bytes: u64,
    next_id: u64,
    terminal: Option<Error>,
}

impl Repair {
    /// `root` is trusted only because the caller authenticated it independently.
    /// `session` must not be reused while any old token or reply could reappear.
    pub fn new(
        context: Context,
        session: SessionId,
        root: Hash,
        parameters: Parameters,
        limits: Limits,
        now: Instant,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let count = parameters
            .chunk_count()
            .map_err(|_| Error::InvalidParameters)?;
        if count > limits.max_chunks {
            return Err(Error::ChunkLimit);
        }
        // A complete body necessarily consumes at least its payload bytes.
        if parameters.total_len > limits.max_bytes {
            return Err(Error::ByteLimit);
        }
        usize::try_from(parameters.total_len).map_err(|_| Error::InvalidParameters)?;
        let count = usize::try_from(count).map_err(|_| Error::InvalidParameters)?;
        if limits.max_in_flight == 0 || deadline <= now {
            return Err(Error::InvalidParameters);
        }
        Ok(Self {
            context,
            session,
            root,
            parameters,
            limits,
            deadline,
            last_now: now,
            slots: (0..count)
                .map(|_| Slot {
                    payload: None,
                    active: None,
                    completed: None,
                    attempts: 0,
                })
                .collect(),
            in_flight: 0,
            bytes: 0,
            next_id: 0,
            terminal: None,
        })
    }

    fn stop(&mut self, reason: Error) -> Error {
        self.slots = Vec::new();
        self.in_flight = 0;
        self.terminal = Some(reason);
        reason
    }

    fn check(&mut self, context: Context, now: Instant) -> Result<(), Error> {
        if let Some(reason) = self.terminal {
            return Err(reason);
        }
        if context != self.context {
            return Err(self.stop(Error::ContextChanged));
        }
        if now < self.last_now {
            return Err(self.stop(Error::ClockRegression));
        }
        self.last_now = now;
        if now >= self.deadline {
            return Err(self.stop(Error::Deadline));
        }
        Ok(())
    }

    /// Retires all state permanently. The caller must also abort outstanding I/O.
    pub fn cancel(&mut self) {
        if self.terminal.is_none() {
            self.stop(Error::Cancelled);
        }
    }

    /// Reserve one addressable request. Failed/expired requests must be retired
    /// with `fail` before retrying. Attempts are counted even if no reply arrives.
    pub fn request(
        &mut self,
        context: Context,
        now: Instant,
        index: u32,
    ) -> Result<Request, Error> {
        self.check(context, now)?;
        let index_usize = usize::try_from(index).map_err(|_| Error::IndexOutOfBounds)?;
        let slot = self
            .slots
            .get_mut(index_usize)
            .ok_or(Error::IndexOutOfBounds)?;
        if slot.payload.is_some() {
            return Err(Error::AlreadyComplete);
        }
        if slot.active.is_some() {
            return Err(Error::AlreadyRequested);
        }
        if slot.attempts > u64::from(self.limits.max_retries) {
            return Err(Error::RetryLimit);
        }
        if self.in_flight >= self.limits.max_in_flight {
            return Err(Error::ConcurrencyLimit);
        }
        let id = self.next_id.checked_add(1).ok_or(Error::IdExhausted)?;
        self.next_id = id;
        slot.active = Some(id);
        slot.attempts += 1;
        self.in_flight += 1;
        Ok(Request {
            index,
            session: self.session,
            id,
        })
    }

    /// Retire a failed request; late responses to this token cannot fill a retry.
    pub fn fail(&mut self, context: Context, now: Instant, request: Request) -> Result<(), Error> {
        self.check(context, now)?;
        if request.session != self.session {
            return Err(Error::UnknownRequest);
        }
        let index = usize::try_from(request.index).map_err(|_| Error::UnknownRequest)?;
        let slot = self.slots.get_mut(index).ok_or(Error::UnknownRequest)?;
        if slot.active != Some(request.id) {
            return Err(Error::UnknownRequest);
        }
        slot.active = None;
        self.in_flight -= 1;
        Ok(())
    }

    /// Charge every submitted response, even duplicates, invalid or stale replies.
    /// A malformed active response retires its attempt. Proof and payload are
    /// borrowed, so callers must bound network framing before allocating them.
    pub fn accept(
        &mut self,
        context: Context,
        now: Instant,
        request: Request,
        chunk: Chunk<'_>,
        proof: &[Hash],
    ) -> Result<Acceptance, Error> {
        self.check(context, now)?;
        let size = u64::try_from(chunk.payload.len()).ok().and_then(|n| {
            u64::try_from(proof.len())
                .ok()
                .and_then(|p| p.checked_mul(32))
                .and_then(|p| n.checked_add(p))
        });
        let total = size.and_then(|n| self.bytes.checked_add(n));
        match total {
            Some(n) if n <= self.limits.max_bytes => self.bytes = n,
            _ => return Err(self.stop(Error::ByteLimit)),
        }
        if request.session != self.session {
            return Err(Error::UnknownRequest);
        }
        let index = usize::try_from(request.index).map_err(|_| Error::UnknownRequest)?;
        let slot = self.slots.get_mut(index).ok_or(Error::UnknownRequest)?;
        if let Some(payload) = &slot.payload {
            if slot.completed != Some(request.id) {
                return Err(Error::UnknownRequest);
            }
            if chunk.index != request.index || chunk.parameters != self.parameters {
                return Err(Error::WrongChunk);
            }
            verify_chunk(chunk, proof, &self.root).map_err(|_| Error::InvalidChunk)?;
            if chunk.payload != payload.as_slice() {
                return Err(Error::InvalidChunk);
            }
            return Ok(Acceptance::Duplicate);
        }
        if slot.active != Some(request.id) {
            return Err(Error::UnknownRequest);
        }
        slot.active = None;
        self.in_flight -= 1;
        if chunk.index != request.index || chunk.parameters != self.parameters {
            return Err(Error::WrongChunk);
        }
        verify_chunk(chunk, proof, &self.root).map_err(|_| Error::InvalidChunk)?;
        slot.payload = Some(chunk.payload.to_vec());
        slot.completed = Some(request.id);
        Ok(Acceptance::Stored)
    }

    /// No partial body is exposed. Checking context and time is mandatory here too.
    pub fn body(&mut self, context: Context, now: Instant) -> Result<Vec<u8>, Error> {
        self.check(context, now)?;
        if self.slots.iter().any(|slot| slot.payload.is_none()) {
            return Err(Error::Incomplete);
        }
        let capacity =
            usize::try_from(self.parameters.total_len).map_err(|_| Error::InvalidParameters)?;
        let mut body = Vec::with_capacity(capacity);
        for slot in &self.slots {
            if let Some(payload) = &slot.payload {
                body.extend_from_slice(payload);
            }
        }
        Ok(body)
    }
}
