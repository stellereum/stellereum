//! Signing-path evidence only: this does not run the node driver or network.

use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer as _, SigningKey};
use stellereum::consensus::{vote_sign_bytes, ValidatorSet, VoteKind};
use stellereum::remote_signer::{RemoteSigner, SignerError, SignerTransport, SIGNATURE_LEN};
use stellereum::runtime::ValidatorRuntime;
use stellereum::state_engine::InMemoryStateEngine;

#[path = "support/falcon_votes.rs"]
mod falcon_votes;

struct RecordingTransport {
    key: SigningKey,
    messages: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl SignerTransport for RecordingTransport {
    fn public_key(&self) -> Result<[u8; 32], SignerError> {
        Ok(self.key.verifying_key().to_bytes())
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], SignerError> {
        self.messages.lock().unwrap().push(message.to_vec());
        Ok(self.key.sign(message).to_bytes())
    }
}

#[test]
fn runtime_signer_observes_late_polka_and_refuses_repeated_precommit_sign() {
    const HEIGHT: u64 = 71;
    let (keys, falcons) = falcon_votes::falcon_set(4);
    let messages = Arc::new(Mutex::new(Vec::new()));
    let signer = RemoteSigner::new(Arc::new(RecordingTransport {
        key: keys[0].clone(),
        messages: messages.clone(),
    }))
    .unwrap();
    let validators = ValidatorSet::from_list(
        keys.iter()
            .map(|key| (key.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let mut runtime = ValidatorRuntime::new(
        keys[0].clone(),
        validators,
        Arc::new(InMemoryStateEngine::new()),
        HEIGHT,
    )
    .with_falcon_key(falcons[0].clone())
    .with_remote_signer(Arc::new(signer))
    .unwrap();
    let block = stellereum::sharding::Block {
        height: HEIGHT,
        state_root: [0xa1; 32],
        timestamp: 71,
        proposer: keys[0].verifying_key().to_bytes(),
        round: 4,
        ..Default::default()
    };
    let value = block.compute_hash();
    runtime.blocks.insert(value, block);
    runtime.hc.round = 11;
    let prevote = runtime.make_prevote().expect("round 11 prevote");
    assert!(prevote.verify());
    assert_eq!((prevote.round, prevote.block_hash), (11, None));
    runtime.on_prevote(prevote).unwrap();

    for i in 0..3 {
        let vote = falcon_votes::fvote(
            &keys[i],
            &falcons[i],
            HEIGHT,
            4,
            VoteKind::Prevote,
            Some(value),
        );
        assert!(vote.verify());
        runtime.on_prevote(vote).unwrap();
    }
    let first = runtime.make_precommit().expect("late polka");
    assert!(first.verify());
    assert_eq!((first.round, first.block_hash), (4, Some(value)));
    assert!(
        runtime.make_precommit().is_none(),
        "SafetyAuthority must refuse re-signing round 4 precommit"
    );

    assert_eq!(
        *messages.lock().unwrap(),
        vec![
            vote_sign_bytes(HEIGHT, 11, VoteKind::Prevote, &None),
            vote_sign_bytes(HEIGHT, 4, VoteKind::Precommit, &Some(value)),
        ]
    );
}
