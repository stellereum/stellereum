//! P0 safety invariants at the bridge policy and evidence-verification boundaries.
//!
//! These are offline synthetic fixtures. A local `executed` flag is not proof
//! that any external-chain payout happened. In particular, this suite tests the
//! local loss of a refund path, not theft or an external transfer.

use ed25519_dalek::SigningKey;
use stellereum::bridge::bridge_adapters::{
    binary_proof_for, build_binary_merkle_root, evm_receipt_encoding, evm_receipt_key,
    solana_leaf_encoding, ton_leaf_encoding, verify_evidence, AdapterKindTag, ChainAdapter,
    DepositClaim, DepositEvidence, EvmAdapter, SolanaAdapter, StoredHeader, TonAdapter,
    SOLANA_FINALITY_SLOTS,
};
use stellereum::bridge::{
    set_bridge_v2_activation_override, BridgeEffect, BridgeIntent, BridgeState, SupportedChain,
    ETHEREUM_FINALITY_BLOCKS, MIN_TON_CONFIRMATIONS, REFUND_GRACE_SECS,
};
use stellereum::cell::{Cell, PatriciaTrie};
use stellereum::consensus::register_validator_pq_key;
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::zkml::effective_chain_id;

/// Post-activation policy: `BRIDGE_V2_ACTIVATION_HEIGHT` is compiled off until
/// Ruleset v7, so this suite pins the gate at height 0 for its thread. The
/// guard clears the override on drop (also on panic).
struct BridgeV2Gate;

impl BridgeV2Gate {
    fn active() -> Self {
        set_bridge_v2_activation_override(Some(0));
        Self
    }
}

impl Drop for BridgeV2Gate {
    fn drop(&mut self) {
        set_bridge_v2_activation_override(None);
    }
}

#[test]
fn outsider_release_cannot_destroy_the_senders_refund_path() {
    let _gate = BridgeV2Gate::active();
    let sender = [0x31; 32];
    let outsider = [0x32; 32];
    let now = 1_760_000_000;
    let amount = 1_000_000_000;
    let parked = BridgeState::default()
        .plan(
            &[BridgeIntent::Withdraw {
                chain: SupportedChain::Arbitrum,
                target_address: "0xdeadbeef".to_string(),
                amount,
            }],
            &[],
            sender,
            now,
        )
        .expect("withdrawal must be admitted")
        .state;
    assert!(!parked.pending_withdrawals[&0].executed);

    let refund_at = now + REFUND_GRACE_SECS;
    let refund = [BridgeIntent::Refund { req_id: 0 }];
    let control = parked
        .plan(&refund, &[], sender, refund_at)
        .expect("sender can refund the untouched request after grace");
    assert_eq!(
        control.effects,
        vec![BridgeEffect::Unpark {
            recipient: sender,
            amount,
        }]
    );
    assert!(!control.state.pending_withdrawals.contains_key(&0));

    // Plan receives the payer identity from its caller; this policy-level test
    // does not itself authenticate a transaction. No payout proof is present.
    let attempt = parked.plan(&[BridgeIntent::Release { req_id: 0 }], &[], outsider, now);
    if let Ok(released) = &attempt {
        assert!(
            released.state.plan(&refund, &[], sender, refund_at).is_ok(),
            "an outsider's bare Release must not make the sender's refund impossible"
        );
    }
    assert!(
        attempt.is_err(),
        "a bare outsider Release must not finalize the request"
    );
}

fn validators() -> (Vec<SigningKey>, Vec<[u8; 32]>) {
    let keys: Vec<_> = (0xD0..=0xD2)
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect();
    let ids = keys
        .iter()
        .map(|key| {
            let id = key.verifying_key().to_bytes();
            let falcon = FalconKeypair::generate_from_seed_bytes(&key.to_bytes());
            register_validator_pq_key(id, PqScheme::Falcon512, falcon.public_key.clone());
            id
        })
        .collect();
    (keys, ids)
}

/// Validator quorum over the V2 header preimage, which BINDS the adapter kind
/// and the foreign finalized head (`finalized_seqno` / `finalized_number` /
/// `finalized_slot`). Under V2 a post-signature inflation of that number is
/// therefore a signature mismatch, not an accepted claim.
fn signatures(
    header: &StoredHeader,
    kind: AdapterKindTag,
    finalized_head: u64,
    keys: &[SigningKey],
) -> Vec<([u8; 32], Vec<u8>)> {
    let message = header.signing_message_v2_binding(effective_chain_id(), kind, finalized_head);
    keys[..2]
        .iter()
        .map(|key| {
            let falcon = FalconKeypair::generate_from_seed_bytes(&key.to_bytes());
            (key.verifying_key().to_bytes(), falcon.sign(&message))
        })
        .collect()
}

fn claim(chain: SupportedChain) -> DepositClaim {
    DepositClaim {
        chain,
        source_tx_hash: [0x71; 32],
        recipient: [0xAB; 32],
        amount: 5_000_000_000,
    }
}

fn header(chain: SupportedChain, root: [u8; 32]) -> StoredHeader {
    StoredHeader {
        chain,
        height: 1_000,
        prev_hash: [0x11; 32],
        tx_root: root,
    }
}

#[test]
fn ton_unsigned_finalized_seqno_cannot_promote_a_shallow_proof() {
    let _gate = BridgeV2Gate::active();
    let (keys, ids) = validators();
    let claim = claim(SupportedChain::Ton);
    let (boc, root) = Cell::from_bytes(&ton_leaf_encoding(&claim));
    let header = header(claim.chain, root);
    let shallow = DepositEvidence::TonCell {
        header: header.clone(),
        header_signatures: signatures(&header, AdapterKindTag::Ton, header.height, &keys),
        finalized_seqno: header.height,
        boc_bytes: boc.to_boc_bytes(),
    };
    // With depth deliberately disabled, validate the actual inclusion and quorum.
    TonAdapter::new(0)
        .verify_deposit(&claim, &shallow, &ids)
        .expect("control: valid inclusion and signed header");
    assert!(verify_evidence(&claim, &shallow, &ids).is_err());
    let mut inflated = shallow.clone();
    if let DepositEvidence::TonCell {
        finalized_seqno, ..
    } = &mut inflated
    {
        *finalized_seqno = header.height + MIN_TON_CONFIRMATIONS;
    }
    // The only difference is a number the V2 preimage BINDS, so the inflation
    // no longer verifies against the same signatures.
    assert!(
        verify_evidence(&claim, &inflated, &ids).is_err(),
        "raising an unsigned finalized seqno must not authenticate finality"
    );
}

#[test]
fn evm_unsigned_finalized_number_cannot_promote_a_shallow_proof() {
    let _gate = BridgeV2Gate::active();
    let (keys, ids) = validators();
    let claim = claim(SupportedChain::Ethereum);
    let index = 0;
    let key = evm_receipt_key(&claim.source_tx_hash, index);
    let receipt = evm_receipt_encoding(
        claim.chain,
        &claim.source_tx_hash,
        index,
        &claim.recipient,
        claim.amount,
    );
    let mut trie = PatriciaTrie::new();
    trie.insert(&key, &receipt);
    let header = header(claim.chain, trie.root_hash());
    let shallow = DepositEvidence::EvmReceipt {
        header: header.clone(),
        header_signatures: signatures(&header, AdapterKindTag::Evm, header.height, &keys),
        finalized_number: header.height,
        log_index: index,
        receipt_value: receipt,
        mpt_proof: trie.generate_merkle_proof(&key).expect("receipt proof"),
    };
    EvmAdapter::new(claim.chain, 0)
        .verify_deposit(&claim, &shallow, &ids)
        .expect("control: valid inclusion and signed header");
    assert!(verify_evidence(&claim, &shallow, &ids).is_err());
    let mut inflated = shallow.clone();
    if let DepositEvidence::EvmReceipt {
        finalized_number, ..
    } = &mut inflated
    {
        *finalized_number = header.height + ETHEREUM_FINALITY_BLOCKS;
    }
    assert!(
        verify_evidence(&claim, &inflated, &ids).is_err(),
        "raising an unsigned finalized number must not authenticate finality"
    );
}

#[test]
fn solana_unsigned_finalized_slot_cannot_promote_a_shallow_proof() {
    let _gate = BridgeV2Gate::active();
    let (keys, ids) = validators();
    let claim = claim(SupportedChain::Solana);
    let leaves = vec![
        b"other-0".to_vec(),
        solana_leaf_encoding(&claim),
        b"other-2".to_vec(),
        b"other-3".to_vec(),
    ];
    let root = build_binary_merkle_root(&leaves).expect("fixture root");
    let header = header(claim.chain, root);
    let shallow = DepositEvidence::SolanaTx {
        header: header.clone(),
        header_signatures: signatures(&header, AdapterKindTag::Solana, header.height, &keys),
        finalized_slot: header.height,
        tx_index: 1,
        proof: binary_proof_for(&leaves, 1).expect("fixture proof"),
    };
    SolanaAdapter::new(0)
        .verify_deposit(&claim, &shallow, &ids)
        .expect("control: valid inclusion and signed header");
    assert!(verify_evidence(&claim, &shallow, &ids).is_err());
    let mut inflated = shallow.clone();
    if let DepositEvidence::SolanaTx { finalized_slot, .. } = &mut inflated {
        *finalized_slot = header.height + SOLANA_FINALITY_SLOTS;
    }
    assert!(
        verify_evidence(&claim, &inflated, &ids).is_err(),
        "raising an unsigned finalized slot must not authenticate finality"
    );
}
