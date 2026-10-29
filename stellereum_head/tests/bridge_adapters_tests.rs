//! §8 chain-adapter verification framework: unit tests.
//!
//! Every adapter must VERIFY SOMETHING REAL: each test builds
//! synthetic-but-VALID fixtures (genuine ed25519 signatures, genuine Merkle
//! roots over the claimed bytes) and then shows the adapter accepts them and
//! rejects every tampering (wrong root, bad signature, outsider-signed
//! "unknown" header, shallow depth, claim mismatch). The zk placeholder is
//! pinned to fail closed at both layers. All fixtures use FIXED seeds - no
//! RNG, no clock, no network - so these tests are bit-deterministic.

use ed25519_dalek::{Signer, SigningKey};
use stellereum::bridge::bridge_adapters::{
    binary_proof_for, build_binary_merkle_root, evm_receipt_encoding, evm_receipt_key,
    solana_leaf_encoding, ton_leaf_encoding, verify_binary_merkle_proof, verify_evidence,
    BinaryMerkleProof, ChainAdapter, DepositClaim, DepositEvidence, EvidenceKind, EvmAdapter,
    HeaderStore, SolanaAdapter, StoredHeader, TonAdapter, SOLANA_FINALITY_SLOTS,
};
use stellereum::bridge::{
    SupportedChain, ARBITRUM_FINALITY_BLOCKS, ETHEREUM_FINALITY_BLOCKS, MIN_TON_CONFIRMATIONS,
};
use stellereum::cell::{BagOfCells, Cell, PatriciaTrie};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn validators(n: usize, base: u8) -> (Vec<SigningKey>, Vec<[u8; 32]>) {
    let keys: Vec<SigningKey> = (0..n).map(|i| key(base.wrapping_add(i as u8))).collect();
    let pks: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
    (keys, pks)
}

fn sign_all(header: &StoredHeader, keys: &[SigningKey]) -> Vec<([u8; 32], Vec<u8>)> {
    let msg = header.signing_message();
    keys.iter()
        .map(|k| (k.verifying_key().to_bytes(), k.sign(&msg).to_vec()))
        .collect()
}

fn ton_claim() -> DepositClaim {
    DepositClaim {
        chain: SupportedChain::Ton,
        source_tx_hash: [0x71u8; 32],
        recipient: [0xABu8; 32],
        amount: 5_000_000_000,
    }
}

/// A fully valid TON evidence bundle for `claim` (real BoC, real header
/// quorum, real depth). Tampering tests mutate the OUTPUT of this.
fn valid_ton_evidence(
    claim: &DepositClaim,
    keys: &[SigningKey],
    tx_root_override: Option<[u8; 32]>,
    finalized_override: Option<u64>,
) -> (DepositEvidence, StoredHeader) {
    const HEIGHT: u64 = 1_000;
    let leaf = ton_leaf_encoding(claim);
    let (boc, root) = Cell::from_bytes(&leaf);
    let header = StoredHeader {
        chain: SupportedChain::Ton,
        height: HEIGHT,
        prev_hash: [0x11u8; 32],
        tx_root: tx_root_override.unwrap_or(root),
    };
    let finalized = finalized_override.unwrap_or(HEIGHT + MIN_TON_CONFIRMATIONS);
    let ev = DepositEvidence::TonCell {
        header: header.clone(),
        header_signatures: sign_all(&header, &keys[..2]),
        finalized_seqno: finalized,
        boc_bytes: boc.to_boc_bytes(),
    };
    (ev, header)
}

fn evm_claim() -> DepositClaim {
    DepositClaim {
        chain: SupportedChain::Ethereum,
        source_tx_hash: [0x55u8; 32],
        recipient: [0x99u8; 32],
        amount: 500_000_000,
    }
}

/// A fully valid EVM evidence bundle (real compressed-Patricia receipt
/// proof, real header quorum, real depth).
fn valid_evm_evidence(
    claim: &DepositClaim,
    keys: &[SigningKey],
    log_index: u32,
    root_override: Option<[u8; 32]>,
) -> (DepositEvidence, StoredHeader) {
    const HEIGHT: u64 = 10_000;
    let receipt_key = evm_receipt_key(&claim.source_tx_hash, log_index);
    let receipt = evm_receipt_encoding(
        claim.chain,
        &claim.source_tx_hash,
        log_index,
        &claim.recipient,
        claim.amount,
    );
    let mut trie = PatriciaTrie::new();
    trie.insert(&receipt_key, &receipt);
    let root = trie.root_hash();
    let proof = trie
        .generate_merkle_proof(&receipt_key)
        .expect("fixture trie always proves its own key");
    let header = StoredHeader {
        chain: claim.chain,
        height: HEIGHT,
        prev_hash: [0x22u8; 32],
        tx_root: root_override.unwrap_or(root),
    };
    let finalized = HEIGHT
        + match claim.chain {
            SupportedChain::Arbitrum => ARBITRUM_FINALITY_BLOCKS,
            _ => ETHEREUM_FINALITY_BLOCKS,
        };
    let ev = DepositEvidence::EvmReceipt {
        header: header.clone(),
        header_signatures: sign_all(&header, &keys[..2]),
        finalized_number: finalized,
        log_index,
        receipt_value: receipt,
        mpt_proof: proof,
    };
    (ev, header)
}

fn sol_claim() -> DepositClaim {
    DepositClaim {
        chain: SupportedChain::Solana,
        source_tx_hash: [0x60u8; 32],
        recipient: [0xBBu8; 32],
        amount: 42_000_000,
    }
}

/// A fully valid Solana evidence bundle (real binary Merkle tree over four
/// leaves, ours at index 1).
fn valid_sol_evidence(
    claim: &DepositClaim,
    keys: &[SigningKey],
    root_override: Option<[u8; 32]>,
) -> (DepositEvidence, StoredHeader) {
    const SLOT: u64 = 50_000;
    let ours = solana_leaf_encoding(claim);
    let leaves = vec![
        b"solana-noise-leaf-0".to_vec(),
        ours,
        b"solana-noise-leaf-2".to_vec(),
        b"solana-noise-leaf-3".to_vec(),
    ];
    let root = build_binary_merkle_root(&leaves).expect("four leaves always root");
    let proof = binary_proof_for(&leaves, 1).expect("index 1 always proves");
    let header = StoredHeader {
        chain: SupportedChain::Solana,
        height: SLOT,
        prev_hash: [0x33u8; 32],
        tx_root: root_override.unwrap_or(root),
    };
    let ev = DepositEvidence::SolanaTx {
        header: header.clone(),
        header_signatures: sign_all(&header, &keys[..2]),
        finalized_slot: SLOT + SOLANA_FINALITY_SLOTS,
        tx_index: 1,
        proof,
    };
    (ev, header)
}

// ===========================================================================
// HeaderStore: chaining discipline
// ===========================================================================

#[test]
fn header_store_links_chains_and_refuses_conflicts() {
    let mut store = HeaderStore::new();
    assert!(store.is_empty());
    let h0 = StoredHeader {
        chain: SupportedChain::Ton,
        height: 0,
        prev_hash: [0u8; 32],
        tx_root: [0xA0u8; 32],
    };
    store.insert(h0.clone()).expect("genesis header inserts");
    // Idempotent re-insert of the identical header.
    store
        .insert(h0.clone())
        .expect("identical re-insert is a no-op");
    assert_eq!(store.len(), 1);

    let h1 = StoredHeader {
        chain: SupportedChain::Ton,
        height: 1,
        prev_hash: h0.header_hash(),
        tx_root: [0xA1u8; 32],
    };
    store.insert(h1.clone()).expect("linked child inserts");
    // Broken link refused.
    let bad_link = StoredHeader {
        chain: SupportedChain::Ton,
        height: 2,
        prev_hash: [0xFFu8; 32],
        tx_root: [0xA2u8; 32],
    };
    assert!(
        store.insert(bad_link).is_err(),
        "unlinked header must be refused"
    );
    // Conflicting header at a known height refused (no silent rewrites).
    let conflict = StoredHeader {
        chain: SupportedChain::Ton,
        height: 1,
        prev_hash: h0.header_hash(),
        tx_root: [0xDEu8; 32],
    };
    assert!(
        store.insert(conflict).is_err(),
        "conflicting header must be refused"
    );

    assert!(store.contains(SupportedChain::Ton, 1));
    assert!(!store.contains(SupportedChain::Ton, 2));
    assert!(
        !store.contains(SupportedChain::Ethereum, 1),
        "chains are namespaced"
    );
    assert_eq!(store.latest(SupportedChain::Ton), Some(&h1));
    assert_eq!(store.latest(SupportedChain::Solana), None);
}

// ===========================================================================
// Binary Merkle proofs: real verification, real rejections
// ===========================================================================

#[test]
fn binary_merkle_proof_verifies_and_rejects_tampering() {
    let leaves = vec![
        b"leaf-zero".to_vec(),
        b"leaf-one".to_vec(),
        b"leaf-two".to_vec(),
    ];
    let root = build_binary_merkle_root(&leaves).expect("three leaves root");
    let proof = binary_proof_for(&leaves, 1).expect("index 1 proves");
    assert!(verify_binary_merkle_proof(&root, &leaves[1], &proof).is_ok());

    // Wrong leaf bytes.
    assert!(verify_binary_merkle_proof(&root, b"leaf-ONE", &proof).is_err());
    // Wrong root.
    assert!(verify_binary_merkle_proof(&[0xFFu8; 32], &leaves[1], &proof).is_err());
    // Transplanted index (proof for 1, checked as if it were for 2).
    let mut moved = proof.clone();
    moved.leaf_index = 2;
    assert!(verify_binary_merkle_proof(&root, &leaves[1], &moved).is_err());
    // Truncated path.
    let mut cut = proof.clone();
    cut.siblings.pop();
    assert!(verify_binary_merkle_proof(&root, &leaves[1], &cut).is_err());
    // Flipped sibling side.
    let mut flipped = proof.clone();
    flipped.siblings[0].sibling_is_right = !flipped.siblings[0].sibling_is_right;
    assert!(verify_binary_merkle_proof(&root, &leaves[1], &flipped).is_err());
    // Empty tree has no root.
    assert!(build_binary_merkle_root(&[]).is_err());
    assert!(binary_proof_for(&leaves, 9).is_err());
}

// ===========================================================================
// Quorum-attested evidence: the live rule, adapted
// ===========================================================================

#[test]
fn quorum_evidence_adapts_the_live_threshold() {
    let (keys, pks) = validators(3, 0xA0);
    let claim = ton_claim();
    // 2 of 3 is the (3*2+2)/3 quorum: passes.
    let event = stellereum::bridge::TeleportDepositEvent {
        source_chain: claim.chain,
        source_tx_hash: claim.source_tx_hash,
        recipient: claim.recipient,
        asset: stellereum::bridge::LIVE_DEPOSIT_ASSET.to_string(),
        amount: claim.amount,
        validator_signatures: vec![],
        zk_proof: None,
    };
    let msg = stellereum::bridge::TeleportBridgeEngine::deposit_signing_message(&event);
    let sigs: Vec<([u8; 32], Vec<u8>)> = keys[..2]
        .iter()
        .map(|k| (k.verifying_key().to_bytes(), k.sign(&msg).to_vec()))
        .collect();
    let ev = DepositEvidence::QuorumAttested { signatures: sigs };
    let v = verify_evidence(&claim, &ev, &pks).expect("2/3 quorum verifies");
    assert_eq!(v.via, EvidenceKind::Quorum);
    assert_eq!(v.amount, claim.amount);

    // One signature is sub-quorum.
    let one = DepositEvidence::QuorumAttested {
        signatures: {
            let s = &keys[..1];
            s.iter()
                .map(|k| (k.verifying_key().to_bytes(), k.sign(&msg).to_vec()))
                .collect()
        },
    };
    assert!(
        verify_evidence(&claim, &one, &pks).is_err(),
        "1 of 3 must fail"
    );

    // Same signer twice is still one vote.
    let dup_sig = k_sign(&keys[0], &msg);
    let dup = DepositEvidence::QuorumAttested {
        signatures: vec![dup_sig.clone(), dup_sig],
    };
    assert!(
        verify_evidence(&claim, &dup, &pks).is_err(),
        "duplicates count once"
    );

    // Outsider signatures count for nothing.
    let outsider = key(0xEE);
    let foreign = DepositEvidence::QuorumAttested {
        signatures: vec![
            (
                outsider.verifying_key().to_bytes(),
                outsider.sign(&msg).to_vec(),
            ),
            (
                key(0xEF).verifying_key().to_bytes(),
                key(0xEF).sign(&msg).to_vec(),
            ),
        ],
    };
    assert!(verify_evidence(&claim, &foreign, &pks).is_err());

    // Empty validator set fails closed (the (0*2+2)/3 == 0 trap).
    assert!(
        verify_evidence(&claim, &ev, &[]).is_err(),
        "no set, no quorum"
    );

    // Shape layer refuses the empty bundle too.
    assert!(DepositEvidence::QuorumAttested { signatures: vec![] }
        .validate_shape()
        .is_err());
}

fn k_sign(k: &SigningKey, msg: &[u8]) -> ([u8; 32], Vec<u8>) {
    (k.verifying_key().to_bytes(), k.sign(msg).to_vec())
}

// ===========================================================================
// TON adapter: real BoC verification
// ===========================================================================

#[test]
fn ton_adapter_verifies_valid_cell_evidence() {
    let (keys, pks) = validators(3, 0xA0);
    let claim = ton_claim();
    let (ev, _) = valid_ton_evidence(&claim, &keys, None, None);
    ev.validate_shape().expect("valid shape");
    let v = TonAdapter::new(MIN_TON_CONFIRMATIONS)
        .verify_deposit(&claim, &ev, &pks)
        .expect("valid TON evidence verifies");
    assert_eq!(v.via, EvidenceKind::TonCell);
    assert_eq!((v.recipient, v.amount), (claim.recipient, claim.amount));
    // Same through the consensus dispatcher.
    assert!(verify_evidence(&claim, &ev, &pks).is_ok());
}

#[test]
fn ton_adapter_rejects_every_tampering() {
    let (keys, pks) = validators(3, 0xA0);
    let claim = ton_claim();
    let adapter = TonAdapter::new(MIN_TON_CONFIRMATIONS);

    // (a) Tampered BoC bytes (flipped data bit -> cell hash mismatch).
    let (mut ev, _) = valid_ton_evidence(&claim, &keys, None, None);
    if let DepositEvidence::TonCell { boc_bytes, .. } = &mut ev {
        let n = boc_bytes.len();
        boc_bytes[n - 1] ^= 0x01;
    }
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "tampered BoC must fail"
    );

    // (b) Header root does not match the BoC (valid quorum over the WRONG root).
    let (ev, _) = valid_ton_evidence(&claim, &keys, Some([0xFFu8; 32]), None);
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "wrong root must fail"
    );

    // (c) Header signed by outsiders ("unknown" header).
    let (mut ev, _) = valid_ton_evidence(&claim, &keys, None, None);
    if let DepositEvidence::TonCell {
        header,
        header_signatures,
        ..
    } = &mut ev
    {
        let outsider = key(0xEE);
        let msg = header.signing_message();
        *header_signatures = vec![
            (
                outsider.verifying_key().to_bytes(),
                outsider.sign(&msg).to_vec(),
            ),
            (
                key(0xEF).verifying_key().to_bytes(),
                key(0xEF).sign(&msg).to_vec(),
            ),
        ];
    }
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "outsider header must fail"
    );

    // (d) Signatures for a DIFFERENT header (bad signature transplant).
    let (mut ev, header) = valid_ton_evidence(&claim, &keys, None, None);
    let other = StoredHeader {
        chain: SupportedChain::Ton,
        height: 9_999,
        prev_hash: [0u8; 32],
        tx_root: header.tx_root,
    };
    if let DepositEvidence::TonCell {
        header_signatures, ..
    } = &mut ev
    {
        *header_signatures = sign_all(&other, &keys[..2]);
    }
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "transplanted sigs must fail"
    );

    // (e) Shallow depth (finalized == header height: 0 confirmations).
    let (ev, header) = valid_ton_evidence(&claim, &keys, None, Some(1_000));
    let _ = header;
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "unconfirmed deposit must fail"
    );

    // (f) Leaf mismatch: evidence proves a DIFFERENT amount than claimed.
    let mut richer = claim.clone();
    richer.amount += 1;
    let (ev, _) = valid_ton_evidence(&richer, &keys, None, None);
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "evidence for another amount must fail"
    );

    // (g) Wrong chain on either side.
    let sol = DepositClaim {
        chain: SupportedChain::Solana,
        ..claim.clone()
    };
    let (ev, _) = valid_ton_evidence(&claim, &keys, None, None);
    assert!(adapter.verify_deposit(&sol, &ev, &pks).is_err());
    assert!(SolanaAdapter::new(SOLANA_FINALITY_SLOTS)
        .verify_deposit(&sol, &ev, &pks)
        .is_err());

    // (h) Garbage BoC.
    let (mut ev, _) = valid_ton_evidence(&claim, &keys, None, None);
    if let DepositEvidence::TonCell { boc_bytes, .. } = &mut ev {
        *boc_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
    }
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "garbage BoC must fail"
    );
}

// ===========================================================================
// EVM adapter: real receipts-trie verification
// ===========================================================================

#[test]
fn evm_adapter_verifies_valid_receipt_evidence() {
    let (keys, pks) = validators(3, 0xA0);
    let claim = evm_claim();
    let (ev, _) = valid_evm_evidence(&claim, &keys, 0, None);
    ev.validate_shape().expect("valid shape");
    let v = EvmAdapter::new(SupportedChain::Ethereum, ETHEREUM_FINALITY_BLOCKS)
        .verify_deposit(&claim, &ev, &pks)
        .expect("valid EVM evidence verifies");
    assert_eq!(v.via, EvidenceKind::EvmReceipt);
    assert!(verify_evidence(&claim, &ev, &pks).is_ok());
}

#[test]
fn evm_adapter_rejects_every_tampering() {
    let (keys, pks) = validators(3, 0xA0);
    let claim = evm_claim();
    let adapter = EvmAdapter::new(SupportedChain::Ethereum, ETHEREUM_FINALITY_BLOCKS);

    // (a) Receipt bytes swapped for another amount (proof is for the ORIGINAL
    // receipt, so EITHER the binding or the proof check must catch it).
    let (mut ev, _) = valid_evm_evidence(&claim, &keys, 0, None);
    if let DepositEvidence::EvmReceipt { receipt_value, .. } = &mut ev {
        let n = receipt_value.len();
        receipt_value[n - 1] ^= 0x01;
    }
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "tampered receipt must fail"
    );

    // (b) Valid quorum over the WRONG root.
    let (ev, _) = valid_evm_evidence(&claim, &keys, 0, Some([0xEEu8; 32]));
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "wrong root must fail"
    );

    // (c) Outsider-signed header.
    let (mut ev, _) = valid_evm_evidence(&claim, &keys, 0, None);
    if let DepositEvidence::EvmReceipt {
        header,
        header_signatures,
        ..
    } = &mut ev
    {
        let outsider = key(0xEE);
        let msg = header.signing_message();
        *header_signatures = vec![
            (
                outsider.verifying_key().to_bytes(),
                outsider.sign(&msg).to_vec(),
            ),
            (
                key(0xEF).verifying_key().to_bytes(),
                key(0xEF).sign(&msg).to_vec(),
            ),
        ];
    }
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "outsider header must fail"
    );

    // (d) Shallow depth (only 10 of the 64 required confirmations).
    let (mut ev, header) = valid_evm_evidence(&claim, &keys, 0, None);
    if let DepositEvidence::EvmReceipt {
        finalized_number, ..
    } = &mut ev
    {
        *finalized_number = header.height + 10;
    }
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "unfinalized deposit must fail"
    );

    // (e) Chain mismatch: Arbitrum header cited to the Ethereum adapter.
    let arb = DepositClaim {
        chain: SupportedChain::Arbitrum,
        ..claim.clone()
    };
    let (ev, _) = valid_evm_evidence(&arb, &keys, 0, None);
    assert!(
        adapter.verify_deposit(&arb, &ev, &pks).is_err(),
        "cross-chain header must fail"
    );
    // ... while the Arbitrum adapter (32 confirmations) accepts it.
    assert!(verify_evidence(&arb, &ev, &pks).is_ok());
}

// ===========================================================================
// Solana adapter: real transaction-Merkle verification
// ===========================================================================

#[test]
fn solana_adapter_verifies_valid_tx_evidence() {
    let (keys, pks) = validators(3, 0xA0);
    let claim = sol_claim();
    let (ev, _) = valid_sol_evidence(&claim, &keys, None);
    ev.validate_shape().expect("valid shape");
    let v = SolanaAdapter::new(SOLANA_FINALITY_SLOTS)
        .verify_deposit(&claim, &ev, &pks)
        .expect("valid Solana evidence verifies");
    assert_eq!(v.via, EvidenceKind::SolanaTx);
    assert!(verify_evidence(&claim, &ev, &pks).is_ok());
}

#[test]
fn solana_adapter_rejects_every_tampering() {
    let (keys, pks) = validators(3, 0xA0);
    let claim = sol_claim();
    let adapter = SolanaAdapter::new(SOLANA_FINALITY_SLOTS);

    // (a) Wrong root (valid quorum over it).
    let (ev, _) = valid_sol_evidence(&claim, &keys, Some([0xDDu8; 32]));
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "wrong root must fail"
    );

    // (b) Outsider-signed header.
    let (mut ev, _) = valid_sol_evidence(&claim, &keys, None);
    if let DepositEvidence::SolanaTx {
        header,
        header_signatures,
        ..
    } = &mut ev
    {
        let outsider = key(0xEE);
        let msg = header.signing_message();
        *header_signatures = vec![(
            outsider.verifying_key().to_bytes(),
            outsider.sign(&msg).to_vec(),
        )];
    }
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "outsider header must fail"
    );

    // (c) Shallow slot depth.
    let (mut ev, header) = valid_sol_evidence(&claim, &keys, None);
    if let DepositEvidence::SolanaTx { finalized_slot, .. } = &mut ev {
        *finalized_slot = header.height + 1;
    }
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "unconfirmed slot must fail"
    );

    // (d) Proof transplanted from another leaf in the same tree.
    let ours = solana_leaf_encoding(&claim);
    let leaves = vec![
        b"solana-noise-leaf-0".to_vec(),
        ours,
        b"solana-noise-leaf-2".to_vec(),
    ];
    let other_proof = binary_proof_for(&leaves, 0).expect("index 0 proves");
    let (mut ev, _) = valid_sol_evidence(&claim, &keys, None);
    if let DepositEvidence::SolanaTx {
        proof, tx_index, ..
    } = &mut ev
    {
        *proof = BinaryMerkleProof {
            leaf_index: 1,
            siblings: other_proof.siblings.clone(),
        };
        *tx_index = 1;
    }
    assert!(
        adapter.verify_deposit(&claim, &ev, &pks).is_err(),
        "transplanted proof must fail"
    );
}

// ===========================================================================
// zk placeholder: fails closed at BOTH layers, for EVERY chain
// ===========================================================================

#[test]
fn zk_placeholder_evidence_always_fails_closed() {
    let (_, pks) = validators(3, 0xA0);
    let claims = [ton_claim(), evm_claim(), sol_claim()];
    for claim in &claims {
        let ev = DepositEvidence::ZkProofPlaceholder {
            note: "future zk deposit proof for testing".to_string(),
        };
        assert!(
            ev.validate_shape().is_err(),
            "placeholder must be refused by shape validation ({:?})",
            claim.chain
        );
        assert!(
            verify_evidence(claim, &ev, &pks).is_err(),
            "placeholder must be refused by verification ({:?})",
            claim.chain
        );
    }
}

// ===========================================================================
// Dispatcher + determinism
// ===========================================================================

#[test]
fn dispatcher_routes_by_claim_chain_and_rejects_mismatches() {
    let (keys, pks) = validators(3, 0xA0);
    let ton = ton_claim();
    let (ton_ev, _) = valid_ton_evidence(&ton, &keys, None, None);
    // EVM evidence cited for a TON claim: refused, not misrouted.
    let evm = evm_claim();
    let (evm_ev, _) = valid_evm_evidence(&evm, &keys, 0, None);
    assert!(verify_evidence(&ton, &evm_ev, &pks).is_err());
    assert!(verify_evidence(&evm, &ton_ev, &pks).is_err());
    // Each chain's own evidence verifies through the single entry point.
    assert!(verify_evidence(&ton, &ton_ev, &pks).is_ok());
    assert!(verify_evidence(&evm, &evm_ev, &pks).is_ok());
    let sol = sol_claim();
    let (sol_ev, _) = valid_sol_evidence(&sol, &keys, None);
    assert!(verify_evidence(&sol, &sol_ev, &pks).is_ok());
}

#[test]
fn verification_is_deterministic() {
    let (keys, pks) = validators(3, 0xA0);
    let claim = ton_claim();
    let (ev, _) = valid_ton_evidence(&claim, &keys, None, None);
    let first = verify_evidence(&claim, &ev, &pks);
    let second = verify_evidence(&claim, &ev, &pks);
    assert_eq!(first, second, "same bytes must give the same verdict");

    let (bad, _) = valid_ton_evidence(&claim, &keys, Some([0xFFu8; 32]), None);
    let e1 = verify_evidence(&claim, &bad, &pks).unwrap_err();
    let e2 = verify_evidence(&claim, &bad, &pks).unwrap_err();
    assert_eq!(e1, e2, "rejections must be byte-stable too");
}

#[test]
fn evidence_size_caps_fail_closed() {
    let oversized = DepositEvidence::TonCell {
        header: StoredHeader {
            chain: SupportedChain::Ton,
            height: 1,
            prev_hash: [0u8; 32],
            tx_root: [0u8; 32],
        },
        header_signatures: vec![([0u8; 32], vec![0u8; 64])],
        finalized_seqno: 100,
        boc_bytes: vec![0u8; 65 * 1024],
    };
    assert!(oversized.validate_shape().is_err(), "oversized BoC refused");
    // A proof path longer than any 256-bit trie can produce.
    let long = DepositEvidence::EvmReceipt {
        header: StoredHeader {
            chain: SupportedChain::Ethereum,
            height: 1,
            prev_hash: [0u8; 32],
            tx_root: [0u8; 32],
        },
        header_signatures: vec![([0u8; 32], vec![0u8; 64])],
        finalized_number: 100,
        log_index: 0,
        receipt_value: vec![1u8; 32],
        mpt_proof: stellereum::cell::MerkleProof {
            key: [0u8; 32],
            value_hash: [0u8; 32],
            leaf_hash: [0u8; 32],
            path: (0..300)
                .map(|_| stellereum::cell::MerkleStep {
                    sibling_is_right: true,
                    sibling_hash: [0u8; 32],
                    branch_prefix: [0u8; 16],
                    skip: 0,
                    branch_bit: 0,
                })
                .collect(),
        },
    };
    assert!(
        long.validate_shape().is_err(),
        "overlong proof path refused"
    );
}

#[test]
fn ton_boc_fixture_uses_real_cell_hashing() {
    // Guard for the fixture itself: the test BoC root must be a GENUINE cell
    // hash (recomputed here by hand), so the adapter test above proves real
    // hash verification and not fixture theater.
    use sha2::Digest;
    let claim = ton_claim();
    let leaf = ton_leaf_encoding(&claim);
    let (boc, root) = Cell::from_bytes(&leaf);
    let only: Vec<(&[u8; 32], &stellereum::cell::Cell)> = boc.cells.iter().collect();
    assert_eq!(only.len(), 1, "a 92-byte leaf fits one cell");
    let (stored_hash, cell) = only[0];
    let mut h = sha2::Sha256::new();
    h.update([cell.references.len() as u8]);
    h.update((cell.data.len() as u16).to_be_bytes());
    h.update(&cell.data);
    let recomputed: [u8; 32] = h.finalize().into();
    assert_eq!(
        *stored_hash, recomputed,
        "stored hash must be the real cell hash"
    );
    assert_eq!(root, recomputed);
    let bytes = BagOfCells::from_boc_bytes(&boc.to_boc_bytes()).expect("round-trips");
    assert_eq!(bytes.read_bytes(&root), Some(leaf));
}
