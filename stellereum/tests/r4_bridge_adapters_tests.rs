//! R4 (BF-1a) — height-indexed, V2-bound bridge adapter verification.
//!
//! Pins the `H - 1 / H / H + 1` activation matrix around
//! `BRIDGE_V2_ACTIVATION_HEIGHT` on `check_header_at_height`, the V2
//! adapter/chain/`chain_id`/finalized-head bindings, strict EVM pinning, and
//! the fail-closed height-indexed quorum (`verify_quorum_signatures_at_height`).
//!
//! Every fixture is deterministic (Falcon-512 keys from fixed seeds, a
//! committed `PqRegistry` built in-process): no RNG, no clock, no global
//! `PQ_VALIDATOR_KEYS`.

use stellereum::bridge::bridge_adapters::{
    binary_proof_for, build_binary_merkle_root, chain_tag, check_header_at_height,
    evm_receipt_encoding, evm_receipt_key, solana_leaf_encoding, ton_leaf_encoding,
    verify_evidence_at_height, AdapterKindTag, DepositClaim, DepositEvidence, EvmAdapter,
    StoredHeader, BRIDGE_HEADER_SIGN_DOMAIN_V2, SOLANA_FINALITY_SLOTS,
};
use stellereum::bridge::{
    set_bridge_v2_activation_override, verify_quorum_signatures_at_height, PqKeyLookup,
    SupportedChain, ARBITRUM_FINALITY_BLOCKS, ETHEREUM_FINALITY_BLOCKS, MIN_TON_CONFIRMATIONS,
};
use stellereum::cell::{Cell, MerkleProof, PatriciaTrie};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::pq_registry::PqRegistry;

const CHAIN_ID: u64 = 7;

/// Test-only thread-local activation gate. Cleared on drop (also on panic).
struct Gate;

impl Gate {
    fn at(height: u64) -> Self {
        set_bridge_v2_activation_override(Some(height));
        Self
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        set_bridge_v2_activation_override(None);
    }
}

/// Three deterministic Falcon-512 validators committed in an explicit
/// `PqRegistry` (activation height 0), i.e. no process-local map.
struct Fixture {
    keys: Vec<([u8; 32], FalconKeypair)>,
    registry: PqRegistry,
}

impl Fixture {
    fn new(n: u8) -> Self {
        let mut registry = PqRegistry::new();
        let mut keys = Vec::new();
        for i in 0..n {
            let seed = 0xE0 + i;
            let id = [seed; 32];
            let key = FalconKeypair::generate_from_seed_bytes(&[seed; 32]);
            registry
                .register(id, PqScheme::Falcon512, key.public_key.clone(), 0, 0, true)
                .expect("fixture registry accepts a fresh deterministic Falcon key");
            keys.push((id, key));
        }
        Self { keys, registry }
    }

    fn ids(&self) -> Vec<[u8; 32]> {
        self.keys.iter().map(|(id, _)| *id).collect()
    }

    fn sign_v1(&self, header: &StoredHeader, upto: usize) -> Vec<([u8; 32], Vec<u8>)> {
        let msg = header.signing_message();
        self.keys[..upto]
            .iter()
            .map(|(id, key)| (*id, key.sign(&msg)))
            .collect()
    }

    fn sign_v2(
        &self,
        header: &StoredHeader,
        chain_id: u64,
        adapter: AdapterKindTag,
        finalized_head: u64,
        upto: usize,
    ) -> Vec<([u8; 32], Vec<u8>)> {
        let msg = header.signing_message_v2_binding(chain_id, adapter, finalized_head);
        self.keys[..upto]
            .iter()
            .map(|(id, key)| (*id, key.sign(&msg)))
            .collect()
    }
}

fn ton_header(height: u64, root: [u8; 32]) -> StoredHeader {
    StoredHeader {
        chain: SupportedChain::Ton,
        height,
        prev_hash: [0x11; 32],
        tx_root: root,
    }
}

// ===========================================================================
// H - 1 / H / H + 1: V1 rejected at/after activation, replayed before it.
// ===========================================================================

#[test]
fn header_v1_is_rejected_at_and_after_activation() {
    let _gate = Gate::at(1_000);
    let fx = Fixture::new(3);
    let ids = fx.ids();
    let header = ton_header(500, [0x22; 32]);
    let finalized = 500 + MIN_TON_CONFIRMATIONS;

    let v1 = fx.sign_v1(&header, 2);
    let v2 = fx.sign_v2(&header, CHAIN_ID, AdapterKindTag::Ton, finalized, 2);

    // H - 1: the historical V1 preimage still replays.
    assert_eq!(
        check_header_at_height(&header, &v1, &ids, finalized, 999, CHAIN_ID, &fx.registry)
            .expect("V1 header must replay below activation"),
        2
    );

    // H and H + 1: V1 is refused fail-closed (no dual-accept fallback).
    let err = check_header_at_height(&header, &v1, &ids, finalized, 1_000, CHAIN_ID, &fx.registry)
        .expect_err("V1 header must be refused at H");
    assert!(err.contains("V2"), "refusal must name the V2 rule: {err}");
    assert!(
        check_header_at_height(&header, &v1, &ids, finalized, 1_001, CHAIN_ID, &fx.registry)
            .is_err(),
        "V1 header must be refused at H + 1"
    );

    // H and H + 1: the V2 preimage verifies with distinct Falcon signers.
    assert_eq!(
        check_header_at_height(&header, &v2, &ids, finalized, 1_000, CHAIN_ID, &fx.registry)
            .expect("V2 header must verify at H"),
        2
    );
    assert_eq!(
        check_header_at_height(&header, &v2, &ids, finalized, 1_001, CHAIN_ID, &fx.registry)
            .expect("V2 header must verify at H + 1"),
        2
    );

    // The V2 preimage is not a V1 replay: below activation it must not verify.
    assert!(
        check_header_at_height(&header, &v2, &ids, finalized, 999, CHAIN_ID, &fx.registry).is_err(),
        "V2 signature must not double as a pre-activation V1 attestation"
    );
}

#[test]
fn finalized_head_is_bound_inside_the_v2_signature() {
    let _gate = Gate::at(0);
    let fx = Fixture::new(3);
    let ids = fx.ids();
    let header = ton_header(500, [0x22; 32]);
    let signed_finalized = 500 + MIN_TON_CONFIRMATIONS;

    let v2 = fx.sign_v2(&header, CHAIN_ID, AdapterKindTag::Ton, signed_finalized, 2);
    assert!(check_header_at_height(
        &header,
        &v2,
        &ids,
        signed_finalized,
        0,
        CHAIN_ID,
        &fx.registry
    )
    .is_ok());

    // The BR-OR-04 attack: inflate the finalized head after signing. The depth
    // arithmetic would accept it, the V2 quorum must not.
    assert!(
        check_header_at_height(
            &header,
            &v2,
            &ids,
            signed_finalized + MIN_TON_CONFIRMATIONS,
            0,
            CHAIN_ID,
            &fx.registry,
        )
        .is_err(),
        "an unsigned finalized-head inflation must invalidate the quorum"
    );
}

// ===========================================================================
// V2 preimage: chain_id, foreign chain tag and adapter discriminant.
// ===========================================================================

#[test]
fn v2_preimage_domain_and_encoding_are_stable() {
    let header = ton_header(500, [0x22; 32]);
    assert_eq!(BRIDGE_HEADER_SIGN_DOMAIN_V2, &b"STELL_BRIDGE_HEADER_V2"[..]);
    assert_eq!(chain_tag(SupportedChain::Ton), 0x54);
    assert_eq!(chain_tag(SupportedChain::Arbitrum), 0x41);
    assert_eq!(chain_tag(SupportedChain::Ethereum), 0x45);
    assert_eq!(chain_tag(SupportedChain::Solana), 0x53);

    // 22B domain + 8B chain_id + 1B adapter + 1B chain tag + 8 + 32 + 32 + 8.
    let msg = header.signing_message_v2_binding(CHAIN_ID, AdapterKindTag::Ton, 900);
    assert_eq!(msg.len(), 112);
    assert_eq!(&msg[..22], BRIDGE_HEADER_SIGN_DOMAIN_V2);
    assert_eq!(&msg[22..30], CHAIN_ID.to_be_bytes().as_slice());
    assert_eq!(msg[30], AdapterKindTag::Ton as u8);
    assert_eq!(msg[31], 0x54);
    // The zero-finalized form and the bound form differ only in the last 8B.
    let zero = header.signing_message_v2(CHAIN_ID);
    assert_eq!(zero.len(), 112);
    assert_eq!(&zero[..104], &msg[..104]);
    assert_eq!(&zero[104..], 0u64.to_be_bytes().as_slice());

    // Adapter discriminants are the task-pinned values.
    assert_eq!(AdapterKindTag::Ton as u8, 0);
    assert_eq!(AdapterKindTag::Evm as u8, 1);
    assert_eq!(AdapterKindTag::Solana as u8, 2);
    assert_eq!(
        AdapterKindTag::from(SupportedChain::Ethereum),
        AdapterKindTag::Evm
    );
    assert_eq!(
        AdapterKindTag::from(SupportedChain::Arbitrum),
        AdapterKindTag::Evm
    );
}

#[test]
fn cross_chain_id_and_cross_adapter_v2_signatures_are_rejected() {
    let _gate = Gate::at(0);
    let fx = Fixture::new(3);
    let ids = fx.ids();
    let header = ton_header(500, [0x22; 32]);
    let finalized = 500 + MIN_TON_CONFIRMATIONS;

    // Control: the committed chain id verifies.
    let good = fx.sign_v2(&header, CHAIN_ID, AdapterKindTag::Ton, finalized, 2);
    assert!(
        check_header_at_height(&header, &good, &ids, finalized, 0, CHAIN_ID, &fx.registry).is_ok()
    );

    // Cross-network replay: same header, signed for another Stellereum chain.
    let other_chain = fx.sign_v2(&header, CHAIN_ID + 1, AdapterKindTag::Ton, finalized, 2);
    assert!(
        check_header_at_height(
            &header,
            &other_chain,
            &ids,
            finalized,
            0,
            CHAIN_ID,
            &fx.registry
        )
        .is_err(),
        "a signature for chain_id {} must not replay on {CHAIN_ID}",
        CHAIN_ID + 1
    );

    // Cross-adapter: same header/chain tag, but signed under the EVM variant.
    let other_adapter = fx.sign_v2(&header, CHAIN_ID, AdapterKindTag::Evm, finalized, 2);
    assert!(
        check_header_at_height(
            &header,
            &other_adapter,
            &ids,
            finalized,
            0,
            CHAIN_ID,
            &fx.registry
        )
        .is_err(),
        "a signature bound to another adapter discriminant must be refused"
    );

    // Cross-chain transplant inside one adapter kind: an Arbitrum header
    // signature must not verify for an Ethereum header with identical fields.
    let arb = StoredHeader {
        chain: SupportedChain::Arbitrum,
        height: 10_000,
        prev_hash: [0x22; 32],
        tx_root: [0x33; 32],
    };
    let arb_finalized = 10_000 + ARBITRUM_FINALITY_BLOCKS;
    let arb_sigs = fx.sign_v2(&arb, CHAIN_ID, AdapterKindTag::Evm, arb_finalized, 2);
    let eth = StoredHeader {
        chain: SupportedChain::Ethereum,
        ..arb.clone()
    };
    assert!(
        check_header_at_height(
            &eth,
            &arb_sigs,
            &ids,
            arb_finalized,
            0,
            CHAIN_ID,
            &fx.registry
        )
        .is_err(),
        "an Arbitrum chain-tag signature must not transplant onto Ethereum"
    );
}

// ===========================================================================
// Full evidence path at V2.
// ===========================================================================

#[test]
fn v2_ton_evidence_verifies_and_refuses_cross_adapter_header_signatures() {
    let _gate = Gate::at(0);
    let fx = Fixture::new(3);
    let ids = fx.ids();
    let claim = DepositClaim {
        chain: SupportedChain::Ton,
        source_tx_hash: [0x71; 32],
        recipient: [0xAB; 32],
        amount: 5_000_000_000,
    };
    let (boc, root) = Cell::from_bytes(&ton_leaf_encoding(&claim));
    let header = ton_header(1_000, root);
    let finalized = 1_000 + MIN_TON_CONFIRMATIONS;
    let sigs = fx.sign_v2(&header, CHAIN_ID, AdapterKindTag::Ton, finalized, 2);
    let evidence = DepositEvidence::TonCell {
        header: header.clone(),
        header_signatures: sigs,
        finalized_seqno: finalized,
        boc_bytes: boc.to_boc_bytes(),
    };
    verify_evidence_at_height(&claim, &evidence, &ids, 0, CHAIN_ID, &fx.registry)
        .expect("V2 TON evidence must verify with the committed registry");

    // Same evidence, V1-signed header: refused at V2.
    let v1_signed = DepositEvidence::TonCell {
        header: header.clone(),
        header_signatures: fx.sign_v1(&header, 2),
        finalized_seqno: finalized,
        boc_bytes: boc.to_boc_bytes(),
    };
    assert!(
        verify_evidence_at_height(&claim, &v1_signed, &ids, 0, CHAIN_ID, &fx.registry).is_err(),
        "V1-signed TON header must be refused at V2"
    );

    // Same header, signed under the EVM adapter discriminant: refused.
    let evm_tagged = DepositEvidence::TonCell {
        header: header.clone(),
        header_signatures: fx.sign_v2(&header, CHAIN_ID, AdapterKindTag::Evm, finalized, 2),
        finalized_seqno: finalized,
        boc_bytes: boc.to_boc_bytes(),
    };
    let err = verify_evidence_at_height(&claim, &evm_tagged, &ids, 0, CHAIN_ID, &fx.registry)
        .expect_err("cross-adapter TON header signature must be refused");
    assert!(err.contains("V2"), "{err}");

    // Inflating the signed finalized seqno is refused by the same binding.
    let inflated = DepositEvidence::TonCell {
        header,
        header_signatures: fx.sign_v2(
            &ton_header(1_000, root),
            CHAIN_ID,
            AdapterKindTag::Ton,
            finalized,
            2,
        ),
        finalized_seqno: finalized + MIN_TON_CONFIRMATIONS,
        boc_bytes: boc.to_boc_bytes(),
    };
    assert!(
        verify_evidence_at_height(&claim, &inflated, &ids, 0, CHAIN_ID, &fx.registry).is_err(),
        "an unsigned finalized-seqno inflation must not authenticate finality"
    );
}

#[test]
fn v2_evm_and_solana_evidence_verify_against_committed_registry() {
    let _gate = Gate::at(0);
    let fx = Fixture::new(3);
    let ids = fx.ids();

    // --- EVM (Ethereum) ---
    let evm_claim = DepositClaim {
        chain: SupportedChain::Ethereum,
        source_tx_hash: [0x55; 32],
        recipient: [0x99; 32],
        amount: 500_000_000,
    };
    let log_index = 0u32;
    let receipt_key = evm_receipt_key(&evm_claim.source_tx_hash, log_index);
    let receipt = evm_receipt_encoding(
        evm_claim.chain,
        &evm_claim.source_tx_hash,
        log_index,
        &evm_claim.recipient,
        evm_claim.amount,
    );
    let mut trie = PatriciaTrie::new();
    trie.insert(&receipt_key, &receipt);
    let evm_header = StoredHeader {
        chain: SupportedChain::Ethereum,
        height: 10_000,
        prev_hash: [0x22; 32],
        tx_root: trie.root_hash(),
    };
    let evm_finalized = 10_000 + ETHEREUM_FINALITY_BLOCKS;
    let evm_evidence = DepositEvidence::EvmReceipt {
        header: evm_header.clone(),
        header_signatures: fx.sign_v2(&evm_header, CHAIN_ID, AdapterKindTag::Evm, evm_finalized, 2),
        finalized_number: evm_finalized,
        log_index,
        receipt_value: receipt,
        mpt_proof: trie
            .generate_merkle_proof(&receipt_key)
            .expect("fixture trie proves its own key"),
    };
    verify_evidence_at_height(&evm_claim, &evm_evidence, &ids, 0, CHAIN_ID, &fx.registry)
        .expect("V2 EVM evidence must verify with the committed registry");

    // --- Solana ---
    let sol_claim = DepositClaim {
        chain: SupportedChain::Solana,
        source_tx_hash: [0x60; 32],
        recipient: [0xBB; 32],
        amount: 42_000_000,
    };
    let leaves = vec![
        b"other-0".to_vec(),
        solana_leaf_encoding(&sol_claim),
        b"other-2".to_vec(),
        b"other-3".to_vec(),
    ];
    let sol_root = build_binary_merkle_root(&leaves).expect("fixture root");
    let sol_header = StoredHeader {
        chain: SupportedChain::Solana,
        height: 2_000,
        prev_hash: [0x33; 32],
        tx_root: sol_root,
    };
    let sol_finalized = 2_000 + SOLANA_FINALITY_SLOTS;
    let sol_evidence = DepositEvidence::SolanaTx {
        header: sol_header.clone(),
        header_signatures: fx.sign_v2(
            &sol_header,
            CHAIN_ID,
            AdapterKindTag::Solana,
            sol_finalized,
            2,
        ),
        finalized_slot: sol_finalized,
        tx_index: 1,
        proof: binary_proof_for(&leaves, 1).expect("fixture proof"),
    };
    verify_evidence_at_height(&sol_claim, &sol_evidence, &ids, 0, CHAIN_ID, &fx.registry)
        .expect("V2 Solana evidence must verify with the committed registry");
}

// ===========================================================================
// Strict EVM pinning (`docs/specs/06 §1.2.2`).
// ===========================================================================

#[test]
fn evm_adapter_refuses_non_evm_chains_at_v2() {
    let _gate = Gate::at(0);

    assert!(
        EvmAdapter::try_new(SupportedChain::Ton, MIN_TON_CONFIRMATIONS).is_err(),
        "TON is not an EVM chain"
    );
    assert!(
        EvmAdapter::try_new(SupportedChain::Solana, SOLANA_FINALITY_SLOTS).is_err(),
        "Solana is not an EVM chain"
    );
    assert!(EvmAdapter::try_new(SupportedChain::Ethereum, ETHEREUM_FINALITY_BLOCKS).is_ok());
    assert!(EvmAdapter::try_new(SupportedChain::Arbitrum, ARBITRUM_FINALITY_BLOCKS).is_ok());

    // Release builds skip the `debug_assert` in `new`, so verification itself
    // must fail closed for a non-EVM instance.
    let fx = Fixture::new(3);
    let ids = fx.ids();
    let claim = DepositClaim {
        chain: SupportedChain::Ton,
        source_tx_hash: [0x71; 32],
        recipient: [0xAB; 32],
        amount: 5_000_000_000,
    };
    let header = ton_header(1_000, [0x22; 32]);
    let evidence = DepositEvidence::EvmReceipt {
        header,
        header_signatures: vec![([0u8; 32], vec![0u8; 64])],
        finalized_number: 1_000,
        log_index: 0,
        receipt_value: vec![0u8; 8],
        mpt_proof: MerkleProof {
            key: [0u8; 32],
            value_hash: [0u8; 32],
            leaf_hash: [0u8; 32],
            path: Vec::new(),
        },
    };
    let adapter = EvmAdapter {
        chain: SupportedChain::Ton,
        min_confirmations: MIN_TON_CONFIRMATIONS,
        headers: Default::default(),
    };
    let err = adapter
        .verify_deposit_at_height(&claim, &evidence, &ids, 0, CHAIN_ID, &fx.registry)
        .expect_err("a non-EVM EVM adapter must refuse at V2");
    assert!(err.contains("non-EVM"), "{err}");

    // The dispatcher refuses EVM evidence for a non-EVM claim before any
    // receipt encoding/proof work.
    assert!(
        verify_evidence_at_height(&claim, &evidence, &ids, 0, CHAIN_ID, &fx.registry).is_err(),
        "EVM evidence for a TON claim must be refused"
    );

    // Non-EVM chains no longer collapse onto the shared 0x00 receipt tag.
    let ton_receipt = evm_receipt_encoding(SupportedChain::Ton, &[1u8; 32], 0, &[2u8; 32], 5);
    let sol_receipt = evm_receipt_encoding(SupportedChain::Solana, &[1u8; 32], 0, &[2u8; 32], 5);
    let eth_receipt = evm_receipt_encoding(SupportedChain::Ethereum, &[1u8; 32], 0, &[2u8; 32], 5);
    assert_ne!(
        ton_receipt[20], 0x00,
        "TON must not use the legacy 0x00 tag"
    );
    assert_ne!(
        sol_receipt[20], 0x00,
        "Solana must not use the legacy 0x00 tag"
    );
    assert_ne!(ton_receipt[20], eth_receipt[20]);
    assert_eq!(eth_receipt[20], 0x01);
    assert_eq!(
        evm_receipt_encoding(SupportedChain::Arbitrum, &[1u8; 32], 0, &[2u8; 32], 5)[20],
        0x02
    );
}

// ===========================================================================
// Height-indexed quorum: fail closed on empty set / missing key.
// ===========================================================================

#[test]
fn verify_quorum_signatures_at_height_fails_closed() {
    let fx = Fixture::new(3);
    let ids = fx.ids();
    let msg = b"quorum probe";
    let sigs: Vec<([u8; 32], Vec<u8>)> = fx.keys[..2]
        .iter()
        .map(|(id, key)| (*id, key.sign(msg)))
        .collect();

    assert_eq!(
        verify_quorum_signatures_at_height(msg, &sigs, &ids, 0, &fx.registry)
            .expect("2 of 3 distinct Falcon signers must reach quorum"),
        2
    );

    // Empty validator set: the (0 * 2 + 2) / 3 == 0 trap must not pass.
    assert!(
        verify_quorum_signatures_at_height(msg, &sigs, &[], 0, &fx.registry).is_err(),
        "an empty validator set must refuse fail-closed"
    );

    // Signer in the voted set but with NO committed key at the height.
    let mut with_unknown = ids.clone();
    with_unknown.push([0xAAu8; 32]);
    let unknown_key = ([0xAAu8; 32], fx.keys[0].1.sign(msg));
    assert!(
        verify_quorum_signatures_at_height(msg, &[unknown_key], &with_unknown, 0, &fx.registry)
            .is_err(),
        "a signer with no committed PQ key must refuse fail-closed"
    );

    // Signer outside the committed validator set.
    let outsider = ([0xBBu8; 32], fx.keys[0].1.sign(msg));
    assert!(
        verify_quorum_signatures_at_height(msg, &[outsider], &ids, 0, &fx.registry).is_err(),
        "an unknown signer must refuse the whole bundle"
    );

    // Sub-quorum signature count.
    assert!(
        verify_quorum_signatures_at_height(msg, &sigs[..1], &ids, 0, &fx.registry).is_err(),
        "1 of 3 is below the bridge threshold"
    );

    // Empty signature bundle.
    assert!(
        verify_quorum_signatures_at_height(msg, &[], &ids, 0, &fx.registry).is_err(),
        "no signatures, no quorum"
    );

    // The trait object form used by the adapters resolves the same keys.
    let lookup: &dyn PqKeyLookup = &fx.registry;
    assert!(lookup.pq_key_at(&ids[0], 0).is_some());
    assert!(lookup.pq_key_at(&[0xAAu8; 32], 0).is_none());
}
