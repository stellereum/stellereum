//! Audit W8.3 / production blocker A10: the LIGHT CLIENT, wired in.
//!
//! Three things are pinned here, and they are the three ways the old
//! arrangement failed:
//!
//!  1. **An honest proof from an honest node VERIFIES.** The whole point of
//!     the module: a wallet can check a balance without running consensus.
//!  2. **A tampered leaf or a tampered root is REFUSED.** A proof that does
//!     not authenticate at the trusted root is not a proof, and saying
//!     "balance = 0" because the server declined to answer is not a proof
//!     either.
//!  3. **A LYING server is DETECTED.** The server cannot make the client
//!     believe anything: the root it serves is only believed once the
//!     quorum certificate on the anchoring header has been verified against
//!     the validator set the OPERATOR pinned (never one the server hands
//!     out).
//!
//! Plus the sync-path wiring: a peer chain is accepted only if it extends the
//! node's quorum-certified anchor.

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::sync::Arc;
use stellereum::cell::CellHash;
use stellereum::consensus::{BlockHash, QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::light_client::{Checkpoint, LightClient, LightError, ProofAnswer};
use stellereum::rpc::RpcState;
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};

const N: usize = 4; // 4 validators at power 1 => quorum is 3

fn keys() -> Vec<SigningKey> {
    (0..N)
        .map(|i| SigningKey::from_bytes(&[i as u8 + 1; 32]))
        .collect()
}

fn validators(keys: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

/// A precommit quorum certificate over `hash` at `height`, signed by the
/// first three validators (a genuine power quorum).
fn cert(signers: &[SigningKey], height: u64, hash: BlockHash) -> QuorumCertificate {
    let signatures = signers
        .iter()
        .map(|k| {
            let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(hash));
            (v.voter, v.signature)
        })
        .collect();
    QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures,
    }
}

/// A minimal RPC state with an account that has a balance.
async fn rpc_state_with_account(addr: [u8; 32], balance: u64) -> Arc<RpcState> {
    let engine = Arc::new(stellereum::state_engine::InMemoryStateEngine::new());
    engine
        .update_account(stellereum::state_engine::AccountState::new(addr, balance))
        .await;
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default(),
        )),
        height: Arc::new(std::sync::atomic::AtomicU64::new(42)),
        node_id: "inf1:test".to_string(),
        chain_id: 777,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(Default::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    })
}

/// The anchor a light client trusts: a finalized header with a real quorum
/// certificate over the state root the proofs authenticate against.
fn anchor_over(
    _validators: &ValidatorSet,
    keys: &[SigningKey],
    height: u64,
    block_hash: BlockHash,
    state_root: CellHash,
) -> Checkpoint {
    Checkpoint::new(
        height,
        block_hash,
        [0x11u8; 32],
        state_root,
        cert(&keys[..3], height, block_hash),
    )
}

// ===========================================================================
// 1. An honest proof from an honest node verifies.
// ===========================================================================

#[tokio::test]
async fn an_honest_proof_from_an_honest_node_verifies() {
    let ks = keys();
    let vs = validators(&ks);
    let alice = [0xA1u8; 32];
    let st = rpc_state_with_account(alice, 5_000).await;

    // The node serves the proof against its own state root.
    let raw = st
        .call("stell_getProof", json!({ "address": hex::encode(alice) }))
        .await;
    assert!(
        raw.get("error").is_none(),
        "the proof must be served: {raw}"
    );
    let answer = ProofAnswer::from_json(&raw).expect("the answer parses");
    assert_eq!(answer.balance, 5_000);
    assert_eq!(answer.address, alice);

    // The light client anchors on a QUORUM-CERTIFIED header over that root.
    let cp = anchor_over(&vs, &ks, 43, [0x22u8; 32], answer.state_root);
    let lc = LightClient::new(vs.clone(), cp).expect("the anchor verifies");

    let proven = lc
        .verify_proof_answer(&answer)
        .expect("an honest proof must verify");
    assert_eq!(proven.balance, 5_000);
    assert!(proven.exists);
    assert_eq!(proven.state_root, answer.state_root);
}

// ===========================================================================
// 2. A tampered leaf or a tampered root is refused.
// ===========================================================================

#[tokio::test]
async fn a_tampered_leaf_is_refused() {
    let ks = keys();
    let vs = validators(&ks);
    let alice = [0xA1u8; 32];
    let st = rpc_state_with_account(alice, 5_000).await;
    let raw = st
        .call("stell_getProof", json!({ "address": hex::encode(alice) }))
        .await;
    let mut answer = ProofAnswer::from_json(&raw).expect("the answer parses");
    let cp = anchor_over(&vs, &ks, 43, [0x22u8; 32], answer.state_root);
    let lc = LightClient::new(vs.clone(), cp).expect("the anchor verifies");

    // The server inflates the balance it reports. The proof still commits to
    // the honest leaf, so the claim contradicts the proof: REFUSED.
    answer.balance = 5_000_000;
    assert!(
        matches!(
            lc.verify_proof_answer(&answer),
            Err(LightError::InvalidProof(_))
        ),
        "a balance that contradicts the proven leaf must be refused"
    );

    // The server tampers with the PROOF itself (a flipped leaf byte). The
    // Merkle check fails: the proof no longer authenticates at the root.
    let mut tampered = ProofAnswer::from_json(&raw).expect("the answer parses");
    let mut node = hex::decode(&tampered.account_proof[0]).expect("hex node");
    node[0] ^= 0xff;
    tampered.account_proof[0] = hex::encode(node);
    match lc.verify_proof_answer(&tampered) {
        Err(LightError::NotIncluded { .. }) => {}
        Err(LightError::InvalidProof(m)) => {
            // A tampered node can also fail to PARSE (the wire form is
            // length-prefixed): either way it is refused.
            assert!(!m.is_empty(), "the refusal must say why");
        }
        Err(other) => panic!("unexpected refusal: {other:?}"),
        Ok(p) => panic!("a tampered proof MUST NOT verify: {p:?}"),
    }
}

#[tokio::test]
async fn a_tampered_root_is_refused() {
    let ks = keys();
    let vs = validators(&ks);
    let alice = [0xA1u8; 32];
    let st = rpc_state_with_account(alice, 5_000).await;
    let raw = st
        .call("stell_getProof", json!({ "address": hex::encode(alice) }))
        .await;
    let mut answer = ProofAnswer::from_json(&raw).expect("the answer parses");
    let cp = anchor_over(&vs, &ks, 43, [0x22u8; 32], answer.state_root);
    let lc = LightClient::new(vs.clone(), cp).expect("the anchor verifies");

    // The server names a root of its own: the client has never finalized it.
    answer.state_root = [0x99u8; 32];
    assert!(
        matches!(
            lc.verify_proof_answer(&answer),
            Err(LightError::RootUntrusted { .. })
        ),
        "a root the client never finalized must be refused"
    );
}

// ===========================================================================
// 3. A lying server is detected.
// ===========================================================================

#[tokio::test]
async fn a_lying_server_cannot_make_the_client_believe_a_made_up_root() {
    let ks = keys();
    let vs = validators(&ks);
    let alice = [0xA1u8; 32];
    let st = rpc_state_with_account(alice, 5_000).await;
    let raw = st
        .call("stell_getProof", json!({ "address": hex::encode(alice) }))
        .await;
    let answer = ProofAnswer::from_json(&raw).expect("the answer parses");

    // The server's lie: it serves a header that commits to a root of its own
    // making, with a certificate that is NOT from the validator set.
    let liars = SigningKey::from_bytes(&[0xF0u8; 32]);
    let liars2 = SigningKey::from_bytes(&[0xF1u8; 32]);
    let liars3 = SigningKey::from_bytes(&[0xF2u8; 32]);
    let lying_root = [0x77u8; 32];
    let lying_hash = [0x66u8; 32];
    let lying_cert = cert(&[liars, liars2, liars3], 43, lying_hash);

    // (a) The certificate is checked against the OPERATOR'S set: three
    //     signatures that are not from it carry no power, so the anchor is
    //     REFUSED and the client never gets to believe the root.
    let lying_cp = Checkpoint::new(43, lying_hash, [0x11u8; 32], lying_root, lying_cert.clone());
    assert!(
        LightClient::new(vs.clone(), lying_cp).is_err(),
        "a certificate signed by outsiders must not anchor anything"
    );

    // (b) And even if the server handed over a certificate that DOES verify
    //     (it signed one for a root of its own), the root it commits to is
    //     not the root the proof is against — the client notices the two
    //     stories do not match.
    let honest_cert = cert(&ks[..3], 43, lying_hash);
    let honest_but_wrong_root =
        Checkpoint::new(43, lying_hash, [0x11u8; 32], lying_root, honest_cert);
    let lc = LightClient::new(vs.clone(), honest_but_wrong_root).expect("the anchor verifies");
    assert!(
        matches!(
            lc.verify_proof_answer(&answer),
            Err(LightError::RootUntrusted { .. })
        ),
        "a proof about a root the anchored header does not commit to must be refused"
    );
}

#[tokio::test]
async fn a_lying_server_that_serves_a_foreign_proof_is_detected() {
    // A server that answers about a DIFFERENT chain: the proof authenticates
    // at a root the operator's chain never had. The client's trusted-root
    // check catches it before the Merkle check even runs.
    let ks = keys();
    let vs = validators(&ks);
    let alice = [0xA1u8; 32];
    let foreign = rpc_state_with_account(alice, 999).await;
    let raw = foreign
        .call("stell_getProof", json!({ "address": hex::encode(alice) }))
        .await;
    let foreign_answer = ProofAnswer::from_json(&raw).expect("the answer parses");

    let honest = rpc_state_with_account(alice, 5_000).await;
    let raw = honest
        .call("stell_getProof", json!({ "address": hex::encode(alice) }))
        .await;
    let honest_answer = ProofAnswer::from_json(&raw).expect("the answer parses");
    assert_ne!(
        honest_answer.state_root, foreign_answer.state_root,
        "the two chains must have different roots"
    );

    let cp = anchor_over(&vs, &ks, 43, [0x22u8; 32], honest_answer.state_root);
    let lc = LightClient::new(vs.clone(), cp).expect("the anchor verifies");
    assert!(
        matches!(
            lc.verify_proof_answer(&foreign_answer),
            Err(LightError::RootUntrusted { .. })
        ),
        "a proof from another chain must be refused"
    );
}

// ===========================================================================
// The RPC: the node SERVES the quorum-certified chain.
// ===========================================================================

#[tokio::test]
async fn the_rpc_serves_the_quorum_certified_header_and_the_anchor() {
    let ks = keys();
    let vs = validators(&ks);
    let st = rpc_state_with_account([0xA1u8; 32], 5_000).await;

    // A finalized block with a real precommit QC.
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 43,
        prev_hash: [0x11u8; 32],
        state_root: [0x33u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_000_000,
        proposer: ks[0].verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    let bh = b.compute_hash();
    b.precommit_qc = Some(cert(&ks, 43, bh));
    st.record_finalized_header(&b).await;

    // The header is served, with its certificate.
    let served = st
        .call("stell_getFinalizedHeader", json!({ "height": 43 }))
        .await;
    assert!(
        served.get("error").is_none(),
        "the header must be served: {served}"
    );
    assert_eq!(served["height"], 43);
    assert_eq!(served["block_hash"], hex::encode(bh));
    assert_eq!(served["state_root"], hex::encode([0x33u8; 32]));
    assert_eq!(served["cert"]["kind"], "Precommit");
    // The certificate is served VERBATIM: every signer's signature the node
    // recorded, so a verifier can count the quorum itself.
    assert_eq!(
        served["cert"]["signatures"].as_array().unwrap().len(),
        N,
        "the served certificate must carry every signer's signature"
    );

    // The anchor is served too.
    let anchor = st.call("stell_getFinalizedCheckpoint", json!({})).await;
    assert!(
        anchor.get("error").is_none(),
        "the anchor must be served: {anchor}"
    );
    assert_eq!(anchor["height"], 43);
    assert_eq!(anchor["trusted_root"], hex::encode([0x33u8; 32]));

    // A height the node never finalized is an honest miss, never a
    // fabricated header.
    let miss = st
        .call("stell_getFinalizedHeader", json!({ "height": 999 }))
        .await;
    assert!(
        miss.get("error").is_some(),
        "an unknown height must not be served"
    );

    // And the served header really does anchor a light client.
    let header = stellereum::light_client_cli::parse_served_header(&served).expect("parses");
    let cp = Checkpoint::new(
        header.height,
        header.block_hash,
        header.prev_hash,
        header.state_root,
        header.cert,
    );
    assert!(LightClient::new(vs, cp).is_ok());
}

#[tokio::test]
async fn the_rpc_serves_the_zkml_capability_statement() {
    let st = rpc_state_with_account([0xA1u8; 32], 5_000).await;
    let caps = st.call("stell_zkmlCapabilities", json!({})).await;
    assert!(
        caps.get("error").is_none(),
        "the statement must be served: {caps}"
    );
    assert_eq!(caps["zero_knowledge"], false);
    assert_eq!(caps["succinct"], false);
    assert_eq!(caps["hiding"], false);
    assert_eq!(caps["trusted_setup"], false);
    assert_eq!(caps["sound"], true);
    let opcodes = caps["opcodes"].as_array().expect("opcodes");
    assert!(opcodes
        .iter()
        .any(|o| o["opcode"] == "SysCallVerifyZkMlReexec"));
    assert!(opcodes
        .iter()
        .any(|o| o["opcode"] == "SysCallVerifyZkMlAttestation"));
    for o in opcodes {
        assert_eq!(o["zero_knowledge"], false);
        assert_eq!(o["succinct"], false);
    }
}

// ===========================================================================
// The CLI: the operator's validator set is the trust anchor.
// ===========================================================================

#[test]
fn the_cli_refuses_to_run_without_an_out_of_band_validator_set() {
    // A file the operator pinned: the shape `stell_getValidators` serves, so
    // it can be dumped ONCE and pinned.
    let dir = std::env::temp_dir().join(format!(
        "stell_lc_cli_test_{}_{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("validators.json");
    let ks = keys();
    let list: Vec<Value> = ks
        .iter()
        .map(|k| json!({ "validator": hex::encode(k.verifying_key().to_bytes()), "power": "1" }))
        .collect();
    std::fs::write(&path, json!({ "validators": list }).to_string()).unwrap();

    let set = stellereum::light_client_cli::load_validator_set(&path).expect("the set parses");
    assert_eq!(set.len(), N);
    assert_eq!(set.total_power(), N as u64);

    // An EMPTY set can never reach a quorum: the client must refuse it
    // rather than "verify" against nothing.
    let empty = dir.join("empty.json");
    std::fs::write(&empty, json!({ "validators": [] }).to_string()).unwrap();
    assert!(
        stellereum::light_client_cli::load_validator_set(&empty).is_err(),
        "an empty validator set must be refused"
    );

    // A missing file is refused loudly, never silently ignored.
    assert!(
        stellereum::light_client_cli::load_validator_set(&dir.join("nope.json")).is_err(),
        "a missing validator set file must be refused"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_cli_parses_a_served_header_and_refuses_a_certificate_it_cannot_check() {
    let ks = keys();
    let cert_json = json!({
        "height": 43u64,
        "round": 0u64,
        "kind": "Precommit",
        "block_hash": hex::encode([0x22u8; 32]),
        "signatures": ks[..3].iter().map(|k| {
            let v = Vote::sign(k, 43, 0, VoteKind::Precommit, Some([0x22u8; 32]));
            json!({ "validator": hex::encode(v.voter), "signature": hex::encode(v.signature) })
        }).collect::<Vec<Value>>(),
    });
    let served = json!({
        "height": 43u64,
        "block_hash": hex::encode([0x22u8; 32]),
        "prev_hash": hex::encode([0x11u8; 32]),
        "state_root": hex::encode([0x33u8; 32]),
        "proposer": hex::encode([0x00u8; 32]),
        "timestamp": 1_700_000_000u64,
        "cert": cert_json,
    });
    let header =
        stellereum::light_client_cli::parse_served_header(&served).expect("the header parses");
    assert_eq!(header.height, 43);
    assert_eq!(header.cert.kind, VoteKind::Precommit);
    assert_eq!(header.cert.signatures.len(), 3);

    // The certificate verifies against the operator's set: the anchor holds.
    let vs = validators(&ks);
    let cp = Checkpoint::new(
        header.height,
        header.block_hash,
        header.prev_hash,
        header.state_root,
        header.cert,
    );
    assert!(LightClient::new(vs.clone(), cp).is_ok());

    // A PREVOTE quorum is not finality: the anchor must be refused.
    let prevote = json!({
        "height": 43u64,
        "round": 0u64,
        "kind": "Prevote",
        "block_hash": hex::encode([0x22u8; 32]),
        "signatures": [],
    });
    let bad = json!({
        "height": 43u64,
        "block_hash": hex::encode([0x22u8; 32]),
        "prev_hash": hex::encode([0x11u8; 32]),
        "state_root": hex::encode([0x33u8; 32]),
        "cert": prevote,
    });
    let bad_header =
        stellereum::light_client_cli::parse_served_header(&bad).expect("the header parses");
    assert_eq!(bad_header.cert.kind, VoteKind::Prevote);
    let bad_cp = Checkpoint::new(
        bad_header.height,
        bad_header.block_hash,
        bad_header.prev_hash,
        bad_header.state_root,
        bad_header.cert,
    );
    assert!(
        LightClient::new(vs, bad_cp).is_err(),
        "a prevote quorum must not anchor a light client"
    );
}

// ===========================================================================
// The sync path: a peer chain must extend the node's quorum-certified anchor.
// ===========================================================================

/// A chain of blocks at heights 1..=n, each with a genuine precommit QC.
fn chain(keys: &[SigningKey], n: u64, root: CellHash) -> Vec<Block> {
    let mut out = Vec::new();
    let mut prev = [0u8; 32];
    for h in 1..=n {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + h,
            proposer: keys[0].verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        let bh = b.compute_hash();
        b.precommit_qc = Some(cert(keys, h, bh));
        prev = bh;
        out.push(b);
    }
    out
}

#[test]
fn a_peer_chain_that_extends_the_anchor_is_accepted() {
    let ks = keys();
    let vs = validators(&ks);
    let root = [0x42u8; 32];
    let blocks = chain(&ks, 3, root);

    // The node's anchor: the genesis (height 0, the zero sentinel).
    let light =
        LightClient::with_genesis_anchor(vs.clone(), stellereum::sync::genesis_light_anchor(root))
            .expect("the genesis anchor");

    let anchored = stellereum::sync::verify_synced_blocks_against_anchor(&light, &blocks)
        .expect("an honest chain that extends the anchor must be accepted");
    assert_eq!(anchored, root);
}

#[test]
fn a_peer_chain_that_forks_off_the_anchor_is_refused() {
    let ks = keys();
    let vs = validators(&ks);
    let root = [0x42u8; 32];
    let blocks = chain(&ks, 3, root);
    let light =
        LightClient::with_genesis_anchor(vs.clone(), stellereum::sync::genesis_light_anchor(root))
            .expect("the genesis anchor");

    // A fork: the second block names a different parent.
    let mut forked = blocks.clone();
    forked[1].prev_hash = [0xEEu8; 32];
    let bh = forked[1].compute_hash();
    forked[1].precommit_qc = Some(cert(&ks, 2, bh));
    assert!(
        stellereum::sync::verify_synced_blocks_against_anchor(&light, &forked).is_err(),
        "a chain that forks off the anchor must be refused"
    );

    // A chain with a HEIGHT GAP must be refused too.
    let mut gapped = blocks.clone();
    gapped.remove(1);
    assert!(
        stellereum::sync::verify_synced_blocks_against_anchor(&light, &gapped).is_err(),
        "a chain with a gap must be refused"
    );
}

#[test]
fn a_peer_chain_without_a_quorum_certificate_is_refused() {
    let ks = keys();
    let vs = validators(&ks);
    let root = [0x42u8; 32];
    let mut blocks = chain(&ks, 2, root);
    // The peer drops the decision proof from its second block.
    blocks[1].precommit_qc = None;
    let light =
        LightClient::with_genesis_anchor(vs.clone(), stellereum::sync::genesis_light_anchor(root))
            .expect("the genesis anchor");
    assert!(
        stellereum::sync::verify_synced_blocks_against_anchor(&light, &blocks).is_err(),
        "a block with no decision proof must be refused"
    );
}

#[test]
fn a_peer_chain_signed_by_outsiders_is_refused() {
    let ks = keys();
    let vs = validators(&ks);
    let root = [0x42u8; 32];
    let mut blocks = chain(&ks, 2, root);
    // The peer re-signs the second block with keys that are NOT validators.
    let liars = [
        SigningKey::from_bytes(&[0xF0u8; 32]),
        SigningKey::from_bytes(&[0xF1u8; 32]),
        SigningKey::from_bytes(&[0xF2u8; 32]),
    ];
    blocks[1].precommit_qc = Some(cert(&liars, 2, blocks[1].compute_hash()));
    let light =
        LightClient::with_genesis_anchor(vs.clone(), stellereum::sync::genesis_light_anchor(root))
            .expect("the genesis anchor");
    assert!(
        stellereum::sync::verify_synced_blocks_against_anchor(&light, &blocks).is_err(),
        "a certificate signed by non-validators must be refused"
    );
}

// ===========================================================================
// The COMMAND, end to end: the real binary against a real (fake) RPC server.
// ===========================================================================

/// A minimal JSON-RPC server: it answers the two methods the light client
/// calls, with the answers it is handed, and an honest error for anything
/// else. This is the "server" side of the end-to-end test — the point is
/// that the CLIENT is what decides, not the server.
fn spawn_fake_rpc(proof: Value, header: Value) -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("the fake RPC binds");
    let addr = listener.local_addr().expect("the fake RPC has an address");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf: Vec<u8> = Vec::new();
            let mut tmp = [0u8; 4096];
            // The head, up to and including the blank line.
            let head_len = loop {
                let n = match stream.read(&mut tmp) {
                    Ok(0) => break 0usize,
                    Ok(n) => n,
                    Err(_) => break 0usize,
                };
                buf.extend_from_slice(&tmp[..n]);
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break p + 4;
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_len]).to_string();
            let clen = head
                .lines()
                .find_map(|l| {
                    let mut it = l.splitn(2, ':');
                    let k = it.next()?.trim();
                    let v = it.next()?.trim();
                    if k.eq_ignore_ascii_case("content-length") {
                        v.parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let mut body = buf[head_len.min(buf.len())..].to_vec();
            while body.len() < clen {
                let n = match stream.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                body.extend_from_slice(&tmp[..n]);
            }
            let text = String::from_utf8_lossy(&body).to_string();
            let method = text
                .split("\"method\"")
                .nth(1)
                .and_then(|s| s.split('"').nth(1))
                .unwrap_or("")
                .to_string();
            let payload = match method.as_str() {
                "stell_getProof" => proof.clone(),
                "stell_getFinalizedHeader" => header.clone(),
                _ => Value::Null,
            };
            let resp = json!({ "jsonrpc": "2.0", "id": 1, "result": payload });
            let out = serde_json::to_vec(&resp).expect("the answer serializes");
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    out.len()
                )
                .as_bytes(),
            );
            let _ = stream.write_all(&out);
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

/// The certificate in the wire form the node serves it in.
fn cert_json(signers: &[SigningKey], height: u64, hash: BlockHash) -> Value {
    json!({
        "height": height,
        "round": 0u64,
        "kind": "Precommit",
        "block_hash": hex::encode(hash),
        "signatures": signers
            .iter()
            .map(|k| {
                let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(hash));
                json!({ "validator": hex::encode(v.voter), "signature": hex::encode(v.signature) })
            })
            .collect::<Vec<Value>>(),
    })
}

/// The validator set file the operator pins: the shape `stell_getValidators`
/// serves, so it can be dumped ONCE and pinned.
fn write_validator_set(dir: &std::path::Path, keys: &[SigningKey]) -> std::path::PathBuf {
    let list: Vec<Value> = keys
        .iter()
        .map(|k| json!({ "validator": hex::encode(k.verifying_key().to_bytes()), "power": "1" }))
        .collect();
    let path = dir.join("validators.json");
    std::fs::write(&path, json!({ "validators": list }).to_string()).expect("the set is written");
    path
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "stell_lc_e2e_{tag}_{}_{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp dir");
    dir
}

/// The end-to-end happy path: the REAL binary, a REAL (fake) JSON-RPC server,
/// an honest proof and an honest quorum certificate. The command must report
/// VERIFIED and exit 0.
#[test]
fn the_light_client_command_verifies_an_honest_proof_end_to_end() {
    let rt = tokio::runtime::Runtime::new().expect("a runtime");
    let ks = keys();
    let alice = [0xA1u8; 32];

    let (proof, header) = rt.block_on(async {
        let st = rpc_state_with_account(alice, 5_000).await;
        let raw = st
            .call("stell_getProof", json!({ "address": hex::encode(alice) }))
            .await;
        assert!(
            raw.get("error").is_none(),
            "the proof must be served: {raw}"
        );
        let answer = ProofAnswer::from_json(&raw).expect("the answer parses");
        // The chain's convention: the header at h+1 commits to the state at h.
        let height = answer.height.expect("the answer carries a height") + 1;
        let block_hash = [0x22u8; 32];
        let header = json!({
            "height": height,
            "block_hash": hex::encode(block_hash),
            "prev_hash": hex::encode([0x11u8; 32]),
            "state_root": hex::encode(answer.state_root),
            "proposer": hex::encode(ks[0].verifying_key().to_bytes()),
            "timestamp": 1_700_000_000u64,
            "cert": cert_json(&ks[..3], height, block_hash),
        });
        (raw, header)
    });

    let url = spawn_fake_rpc(proof, header);
    let dir = temp_dir("honest");
    let vs_path = write_validator_set(&dir, &ks);

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "light-client",
            "--from",
            &url,
            "--verify",
            &hex::encode(alice),
            "--validators",
            vs_path.to_str().unwrap(),
            "--wait-seconds",
            "5",
        ])
        .output()
        .expect("the light-client command runs");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "an honest proof must be verified: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("VERIFIED"),
        "the command must report VERIFIED: {stdout}"
    );
    assert!(
        stdout.contains("5000"),
        "the command must report the proven balance: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The end-to-end LIAR: the server serves a header whose certificate is
/// signed by keys that are NOT in the operator's validator set. The command
/// must REFUSE (non-zero exit) — a server cannot certify its own chain.
#[test]
fn the_light_client_command_detects_a_lying_server_end_to_end() {
    let rt = tokio::runtime::Runtime::new().expect("a runtime");
    let ks = keys();
    let alice = [0xA1u8; 32];

    let (proof, header) = rt.block_on(async {
        let st = rpc_state_with_account(alice, 5_000).await;
        let raw = st
            .call("stell_getProof", json!({ "address": hex::encode(alice) }))
            .await;
        let answer = ProofAnswer::from_json(&raw).expect("the answer parses");
        let height = answer.height.expect("the answer carries a height") + 1;
        let block_hash = [0x22u8; 32];
        // The liar's certificate: signed by OUTSIDERS.
        let liars = [
            SigningKey::from_bytes(&[0xF0u8; 32]),
            SigningKey::from_bytes(&[0xF1u8; 32]),
            SigningKey::from_bytes(&[0xF2u8; 32]),
        ];
        let header = json!({
            "height": height,
            "block_hash": hex::encode(block_hash),
            "prev_hash": hex::encode([0x11u8; 32]),
            "state_root": hex::encode(answer.state_root),
            "proposer": hex::encode([0xEEu8; 32]),
            "timestamp": 1_700_000_000u64,
            "cert": cert_json(&liars, height, block_hash),
        });
        (raw, header)
    });

    let url = spawn_fake_rpc(proof, header);
    let dir = temp_dir("liar");
    let vs_path = write_validator_set(&dir, &ks);

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "light-client",
            "--from",
            &url,
            "--verify",
            &hex::encode(alice),
            "--validators",
            vs_path.to_str().unwrap(),
            "--wait-seconds",
            "5",
        ])
        .output()
        .expect("the light-client command runs");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        !out.status.success(),
        "a lying server must NOT be believed: {stdout}\n{stderr}"
    );
    assert!(
        !stdout.contains("VERIFIED"),
        "a lying server must never produce a VERIFIED line: {stdout}"
    );
    assert!(
        stderr.contains("REFUSED") || stdout.contains("REFUSED"),
        "the refusal must be explicit: {stdout}\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
