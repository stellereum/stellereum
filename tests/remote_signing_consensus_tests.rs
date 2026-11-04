//! End-to-end proof that a REMOTE signer actually signs consensus messages.
//!
//! `ValidatorRuntime` used to own a plaintext `SigningKey` and sign votes and the
//! proposal in-process. A remote / HSM signer was therefore only a handle nobody
//! called: the node would have kept signing from the key in its own heap while an
//! operator believed the key was in an HSM. These tests pin the two properties that
//! matter once the handle is threaded through:
//!
//!   * a configured remote signer is the thing that signs, and its signature
//!     verifies against the remote key -- so the vote is genuinely produced out of
//!     process;
//!   * when the signer fails there is NO local fallback. The vote is simply absent.
//!     A fallback would be the exact silent failure the module exists to prevent.
//!
//! A third test pins that attaching a signer whose key is not the node's validator
//! identity is refused, because `id` (and every vote's `voter` field) is fixed from
//! the local key at construction.

use ed25519_dalek::{Signer as _, SigningKey};
use rand::rngs::OsRng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use stellereum::consensus::{ValidatorSet, Vote, VoteKind};
use stellereum::remote_signer::{
    LocalSigner, RemoteSigner, Signer, SignerError, SignerTransport, TransportErrorKind,
    SIGNATURE_LEN,
};
use stellereum::runtime::ValidatorRuntime;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

/// A transport that signs with `key` until told to fail.
struct FakeTransport {
    key: SigningKey,
    fail: Arc<AtomicBool>,
    sign_calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl SignerTransport for FakeTransport {
    fn public_key(&self) -> Result<[u8; 32], SignerError> {
        Ok(self.key.verifying_key().to_bytes())
    }

    fn sign(&self, msg: &[u8]) -> Result<[u8; SIGNATURE_LEN], SignerError> {
        self.sign_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(SignerError::Transport(TransportErrorKind::Request));
        }
        Ok(self.key.sign(msg).to_bytes())
    }
}

fn remote_setup(
    key: SigningKey,
) -> (
    ValidatorRuntime,
    Arc<AtomicBool>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let fail = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let transport = FakeTransport {
        key: key.clone(),
        fail: Arc::clone(&fail),
        sign_calls: Arc::clone(&calls),
    };
    let remote = RemoteSigner::new(Arc::new(transport)).expect("remote signer pins the key");

    let vs = ValidatorSet::from_list(vec![(key.verifying_key().to_bytes(), 1)]);
    let state = Arc::new(InMemoryStateEngine::new());
    let rt = ValidatorRuntime::new(key, vs, state, 1)
        .with_remote_signer(Arc::new(remote))
        .expect("remote key matches the validator identity");
    (rt, fail, calls)
}

fn local_state() -> Arc<InMemoryStateEngine> {
    Arc::new(InMemoryStateEngine::new())
}

#[test]
fn a_configured_remote_signer_is_what_signs_the_vote() {
    let key = SigningKey::generate(&mut OsRng);
    let (rt, _fail, calls) = remote_setup(key.clone());

    // Get to a point where a prevote can be produced.
    let mut rt = rt;
    rt.hc.proposal = Some((key.verifying_key().to_bytes(), [0xAB; 32]));
    rt.hc.step = stellereum::consensus::Step::Prevote;

    let before = calls.load(Ordering::SeqCst);
    let vote = rt
        .make_prevote()
        .expect("the remote signer must produce a vote");
    assert!(
        calls.load(Ordering::SeqCst) > before,
        "the vote must have gone through the remote transport, not the local key"
    );

    // The vote must verify, and its voter must be the remote key.
    assert!(
        vote.verify(),
        "a remote-signed vote must carry a valid signature"
    );
    assert_eq!(vote.voter, key.verifying_key().to_bytes());
    assert_eq!(vote.kind, VoteKind::Prevote);
}

#[test]
fn a_remote_signer_failure_produces_no_vote_at_all() {
    let key = SigningKey::generate(&mut OsRng);
    let (rt, fail, _calls) = remote_setup(key.clone());
    let mut rt = rt;

    rt.hc.proposal = Some((key.verifying_key().to_bytes(), [0xCD; 32]));
    rt.hc.step = stellereum::consensus::Step::Prevote;

    // Now break the signer.
    fail.store(true, Ordering::SeqCst);

    // FAIL CLOSED: no vote, and in particular no locally-signed vote.
    assert!(
        rt.make_prevote().is_none(),
        "a failing remote signer must yield no vote rather than fall back to the local key"
    );
}

#[test]
fn attaching_a_signer_for_a_different_key_is_refused() {
    let node_key = SigningKey::generate(&mut OsRng);
    let other_key = SigningKey::generate(&mut OsRng);

    let transport = FakeTransport {
        key: other_key,
        fail: Arc::new(AtomicBool::new(false)),
        sign_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    };
    let remote = RemoteSigner::new(Arc::new(transport)).expect("pins the other key");

    let vs = ValidatorSet::from_list(vec![(node_key.verifying_key().to_bytes(), 1)]);
    let rt = ValidatorRuntime::new(node_key, vs, local_state(), 1);

    let err = match rt.with_remote_signer(Arc::new(remote)) {
        Ok(_) => panic!("a signer for another key must be refused"),
        Err(e) => e,
    };
    assert!(
        err.contains("does not match"),
        "the refusal must name the cause: {err}"
    );
}

#[tokio::test]
async fn the_local_path_is_unchanged_when_no_remote_signer_is_configured() {
    let key = SigningKey::generate(&mut OsRng);
    let vs = ValidatorSet::from_list(vec![(key.verifying_key().to_bytes(), 1)]);
    let state = local_state();
    state
        .update_account(AccountState::new(key.verifying_key().to_bytes(), 1_000_000))
        .await;
    let mut rt = ValidatorRuntime::new(key.clone(), vs, state, 1);

    rt.hc.proposal = Some((key.verifying_key().to_bytes(), [0x11; 32]));
    rt.hc.step = stellereum::consensus::Step::Prevote;

    let vote = rt.make_prevote().expect("the local path still signs");
    assert!(vote.verify());
    assert_eq!(vote.voter, key.verifying_key().to_bytes());

    // And a LocalSigner wrapped as a dyn Signer behaves identically.
    let local = LocalSigner::from_seed(&key.to_bytes());
    assert_eq!(local.public_key(), key.verifying_key().to_bytes());
    let sig = local.sign(b"x").expect("local signer signs");
    assert_eq!(sig.to_bytes().len(), SIGNATURE_LEN);
}

#[test]
fn remote_signed_vote_is_indistinguishable_from_a_local_one() {
    // Same key, same message -> the two paths must produce the same vote bytes,
    // because both sign the same `vote_sign_bytes` preimage. If they diverged, a
    // remote-signed vote would be rejected by peers running the local path.
    let key = SigningKey::generate(&mut OsRng);
    let vs = ValidatorSet::from_list(vec![(key.verifying_key().to_bytes(), 1)]);

    let mut local_rt = ValidatorRuntime::new(key.clone(), vs.clone(), local_state(), 1);
    let (remote_rt, _f, _c) = remote_setup(key.clone());
    let mut remote_rt = remote_rt;

    for rt in [&mut local_rt, &mut remote_rt] {
        rt.hc.proposal = Some((key.verifying_key().to_bytes(), [0x42; 32]));
        rt.hc.step = stellereum::consensus::Step::Prevote;
    }

    let lv: Vote = local_rt.make_prevote().unwrap();
    let rv: Vote = remote_rt.make_prevote().unwrap();
    assert_eq!(lv, rv, "the two signing paths must agree byte for byte");
    assert!(rv.verify());
}
