//! Consensus P2P transport: carries proposals and votes between validators over
//! the infnode pubsub layer — WITHOUT modifying infnode.
//!
//! Design (per the "blockchain stays outside infnode" rule):
//!  - infnode is used only through its public API:
//!      * `register_app_sub(topic)` to receive app-level messages
//!      * `request_to(peer, "pubsub.msg", {topic,data})` to deliver a message
//!        to the peer's app subscription
//!      * `send_to(peer, "pubsub.msg", {topic,data})` for the fire-and-forget
//!        form of the same delivery (votes/proposals): the frame is written and
//!        the peer's `RESP` is NOT awaited, so the remote round trip leaves
//!        the critical path. See [`message_is_fire_and_forget`].
//!  - Messages are an enum serialized with bincode and hex-encoded into `data`.
//!
//! Security: every inbound message is size-checked and bincode-decoded; malformed
//! or oversized payloads are rejected. Vote signatures are verified downstream by
//! the consensus engine, so a forged vote is dropped there.

mod admission;
mod framing;
mod gossip;
mod limiter;

/// Compact-µQC gossip codec (prototype's first wiring). Included by path so
/// no other file changes (the `dandelion.rs` precedent below); the module
/// itself stays `std`-only and standalone-`rustc --test` compatible.
#[path = "../compact_prop.rs"]
pub mod compact_prop;

/// Dandelion stem/fluff relay policy, reused verbatim (see header in `framing.rs`).
///
/// Nested here (rather than top-level `lib.rs`) so this wiring stays a
/// publish-path-only change.
#[path = "../dandelion.rs"]
pub mod dandelion;

pub use admission::*;
pub use framing::*;
pub use gossip::*;
pub use limiter::*;

#[cfg(test)]
mod tests;
