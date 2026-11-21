//! R2-B: Canonical `Domain::EvmBindings` state commitment, strict 1-to-1
//! first-writer-wins block application (`1a-TER`), `H - 1 / H / H + 1`
//! activation boundary, `DomainCache` assembly parity, `clone_for_simulation`
//! isolation, and `COMMITMENT_VERSION = 5` / genesis KAT preservation.

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use stellereum::commitment::{
    assemble_cached_digest_with_cnvrf_minted_and_evm_bindings, books_preimage, bridge_preimage,
    cnvrf_v3_preimage, commitment_digest_with_zkml_cnvrf_and_evm_bindings,
    contracts_preimage_cached, cross_shard_preimage, escrow_preimage, evm_bindings_preimage,
    governance_preimage, oracle_preimage, pmm_preimage, session_keys_preimage, staking_preimage,
    tokens_preimage, xpc_preimage, zkml_preimage, CommitmentSnapshot, Domain, DomainCache,
    COMMITMENT_VERSION,
};
use stellereum::consensus::ValidatorSet;
use stellereum::evm_adapter::{self, LegacyTransaction};
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{
    effective_evm_bindings_state_activation_height, evm_bindings_state_active_at,
    set_evm_bindings_state_activation_override, AccountState, CnVrfV3EngineSnapshot,
    EvmBindingsSnapshot, EvmBindingsState, InMemoryStateEngine,
    EVM_BINDINGS_STATE_ACTIVATION_HEIGHT,
};

const TS: u64 = 1_760_000_000;
const FUNDS: u64 = 10_000_000_000_000;
const GAS: u64 = 1_000_000;
const TRANSFER_WEI: u128 = 1_000 * 1_000_000_000;

struct EvmBindingsGateGuard;

impl EvmBindingsGateGuard {
    fn at(height: u64) -> Self {
        set_evm_bindings_state_activation_override(Some(height));
        Self
    }
}

impl Drop for EvmBindingsGateGuard {
    fn drop(&mut self) {
        set_evm_bindings_state_activation_override(None);
    }
}

fn falcon(seed: u8) -> FalconKeypair {
    let mut s = [0u8; 32];
    s[0] = seed;
    s[31] = 0xB5;
    FalconKeypair::generate_from_seed_bytes(&s)
}

fn pq_of(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, kp.public_key(), &DEFAULT_SALT)
}

fn secp(seed: u8) -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("secp key")
}

fn evm_of(key: &k256::ecdsa::SigningKey) -> [u8; 20] {
    evm_adapter::pubkey_to_address(key.verifying_key().to_encoded_point(false).as_bytes())
        .expect("evm address")
}

fn proof(key: &k256::ecdsa::SigningKey, chain: u64, evm: &[u8; 20], pq: &[u8; 32]) -> Vec<u8> {
    let msg = evm_adapter::binding_message(chain, evm, pq);
    let (sig, recid) = key.sign_prehash_recoverable(&msg).expect("sig");
    let raw = sig.to_bytes();
    let mut s = [0u8; 32];
    s.copy_from_slice(&raw[32..64]);
    let mut rec = recid.to_byte();
    if !evm_adapter::is_low_s(&s) {
        let n = evm_adapter::SECP256K1_N;
        let mut out = [0u8; 32];
        let mut borrow: i32 = 0;
        for i in (0..32).rev() {
            let v = n[i] as i32 - s[i] as i32 - borrow;
            if v < 0 {
                out[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                out[i] = v as u8;
                borrow = 0;
            }
        }
        s = out;
        rec ^= 1;
    }
    let mut p = Vec::with_capacity(65);
    p.extend_from_slice(&raw[..32]);
    p.extend_from_slice(&s);
    p.push(rec);
    p
}

fn binding_tx(
    kp: &FalconKeypair,
    evm_key: &k256::ecdsa::SigningKey,
    evm: [u8; 20],
    nonce: u64,
) -> Transaction {
    let chain = evm_adapter::effective_chain_id();
    let pk = kp.public_key().to_vec();
    let pq = pq_of(kp);
    let claim_sig = kp.sign(&evm_adapter::binding_message(chain, &evm, &pq));
    let evm_proof = proof(evm_key, chain, &evm, &pq);
    let sign_this =
        evm_adapter::binding_template_message(&pk, evm, &claim_sig, &evm_proof, nonce, GAS)
            .expect("template");
    let tx_sig = kp.sign(&sign_this);
    evm_adapter::build_binding_transaction(&pk, evm, &claim_sig, &evm_proof, nonce, GAS, &tx_sig)
        .expect("binding tx")
}

fn evm_raw(key: &k256::ecdsa::SigningKey, chain: u64, nonce: u64, to: [u8; 20]) -> Vec<u8> {
    let mut tx = LegacyTransaction {
        nonce,
        gas_price: 1,
        gas_limit: 21_000,
        to: Some(to),
        value: TRANSFER_WEI,
        data: vec![],
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
        chain_id: Some(chain),
    };
    let (sig, recid) = key
        .sign_prehash_recoverable(&tx.signing_hash())
        .expect("sig");
    let raw = sig.to_bytes();
    tx.r.copy_from_slice(&raw[..32]);
    tx.s.copy_from_slice(&raw[32..64]);
    let mut rec = recid.to_byte();
    if !evm_adapter::is_low_s(&tx.s) {
        let n = evm_adapter::SECP256K1_N;
        let mut out = [0u8; 32];
        let mut borrow: i32 = 0;
        for i in (0..32).rev() {
            let v = n[i] as i32 - tx.s[i] as i32 - borrow;
            if v < 0 {
                out[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                out[i] = v as u8;
                borrow = 0;
            }
        }
        tx.s = out;
        rec ^= 1;
    }
    tx.v = chain * 2 + 35 + rec as u64;
    tx.encode()
}

fn carrier_tx(kp: &FalconKeypair, raw: &[u8], to_pq: [u8; 32]) -> Transaction {
    let pk = kp.public_key().to_vec();
    let intent = kp.sign(&evm_adapter::evm_intent_digest(raw));
    let msg =
        evm_adapter::carrier_template_message(raw, &pk, &intent, to_pq, GAS).expect("template");
    let tx_sig = kp.sign(&msg);
    evm_adapter::build_carrier_transaction(raw, &pk, &intent, to_pq, GAS, &tx_sig).expect("carrier")
}

fn block(height: u64, txs: Vec<Transaction>) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: TS + height,
        proposer: SigningKey::from_bytes(&[0x5Au8; 32])
            .verifying_key()
            .to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        round: 0,
    }
}

#[tokio::test]
async fn first_writer_wins_same_evm_and_same_pq_with_parallel_parity() {
    let _gate = EvmBindingsGateGuard::at(10);

    let kp_a = falcon(0x11);
    let pq_a = pq_of(&kp_a);
    let kp_b = falcon(0x12);
    let pq_b = pq_of(&kp_b);

    let evm_key_1 = secp(0x21);
    let evm_1 = evm_of(&evm_key_1);
    let evm_key_2 = secp(0x22);
    let evm_2 = evm_of(&evm_key_2);

    // Block containing:
    //  tx0: (evm_1, pq_a) -> succeeds and binds evm_1 <-> pq_a
    //  tx1: (evm_1, pq_b) -> conflict on evm_1; first-writer-wins keeps pq_a
    //  tx2: (evm_2, pq_a) -> conflict on pq_a; first-writer-wins keeps evm_1
    let tx0 = binding_tx(&kp_a, &evm_key_1, evm_1, 0);
    let tx1 = binding_tx(&kp_b, &evm_key_1, evm_1, 0);
    let tx2 = binding_tx(&kp_a, &evm_key_2, evm_2, 1);
    let blk = block(10, vec![tx0, tx1, tx2]);

    let seq = InMemoryStateEngine::new().with_parallel_exec(false);
    let par = InMemoryStateEngine::new().with_parallel_exec(true);
    for e in [&seq, &par] {
        e.update_account(AccountState::new(pq_a, FUNDS)).await;
        e.update_account(AccountState::new(pq_b, FUNDS)).await;
    }

    let out_seq = seq.apply_block_transition(&blk, 0).await;
    let out_par = par.apply_block_transition(&blk, 0).await;
    assert_eq!(out_seq.status, vec![true, true, true]);
    assert_eq!(out_par.status, out_seq.status);
    assert_eq!(out_par.tx_fees, out_seq.tx_fees);

    let root_seq = seq.get_state_root().await;
    let root_par = par.get_state_root().await;
    assert_eq!(
        root_seq, root_par,
        "parallel_exec == sequential state_root must match"
    );

    let state_seq = seq.evm_bindings_read().await.clone();
    let state_par = par.evm_bindings_read().await.clone();
    assert_eq!(
        state_seq, state_par,
        "parallel_exec == sequential EvmBindingsState must match"
    );
    assert_eq!(state_seq.len(), 1);
    assert_eq!(state_seq.get_pq(&evm_1), Some(pq_a));
    assert_eq!(state_seq.get_evm(&pq_a), Some(evm_1));
    assert_eq!(state_seq.get_pq(&evm_2), None);
    assert_eq!(state_seq.get_evm(&pq_b), None);
}

#[tokio::test]
async fn activation_boundary_h_minus_1_h_h_plus_1_and_domain_cache_and_sim_isolation() {
    let h = 100u64;
    let kp1 = falcon(0x31);
    let pq1 = pq_of(&kp1);
    let evm_key1 = secp(0x41);
    let evm1 = evm_of(&evm_key1);

    let kp2 = falcon(0x32);
    let pq2 = pq_of(&kp2);
    let evm_key2 = secp(0x42);
    let evm2 = evm_of(&evm_key2);

    let recipient_kp = falcon(0x33);
    let recipient_pq = pq_of(&recipient_kp);
    let recipient_evm = evm_of(&secp(0x43));

    // Reference engine with default gate (u64::MAX, GatedOff) at H - 1.
    let ref_pre = InMemoryStateEngine::new();
    ref_pre.update_account(AccountState::new(pq1, FUNDS)).await;
    ref_pre.update_account(AccountState::new(pq2, FUNDS)).await;
    ref_pre
        .update_account(AccountState::new(recipient_pq, 0))
        .await;
    let bind_pre = binding_tx(&kp1, &evm_key1, evm1, 0);
    let b_pre_ref = block(h - 1, vec![bind_pre.clone()]);
    let out_ref = ref_pre.apply_block_transition(&b_pre_ref, 0).await;
    assert_eq!(out_ref.status, vec![true]);
    assert!(ref_pre.evm_bindings_read().await.is_empty());
    let root_ref_pre = ref_pre.get_state_root().await;

    // Activate gate at H = 100.
    let _gate = EvmBindingsGateGuard::at(h);
    assert!(!evm_bindings_state_active_at(h - 1));
    assert!(evm_bindings_state_active_at(h));
    assert!(evm_bindings_state_active_at(h + 1));

    let eng = InMemoryStateEngine::new();
    eng.update_account(AccountState::new(pq1, FUNDS)).await;
    eng.update_account(AccountState::new(pq2, FUNDS)).await;
    eng.update_account(AccountState::new(recipient_pq, 0)).await;

    // Height H - 1: canonical EvmBindings stays empty (0B), root matches v6.
    let out_h_minus_1 = eng.apply_block_transition(&b_pre_ref, 0).await;
    assert_eq!(out_h_minus_1.status, vec![true]);
    assert!(eng.evm_bindings_read().await.is_empty());
    assert_eq!(
        eng.get_state_root().await,
        root_ref_pre,
        "at H - 1 state_root must be byte-identical to pre-activation v6"
    );

    // Height H: binding commits to Domain::EvmBindings and moves state_root.
    let bind_h = binding_tx(&kp1, &evm_key1, evm1, 1);
    let b_h = block(h, vec![bind_h]);
    let out_h = eng.apply_block_transition(&b_h, 0).await;
    assert_eq!(out_h.status, vec![true]);
    assert_eq!(eng.evm_bindings_read().await.len(), 1);
    assert_eq!(eng.evm_bindings_read().await.get_pq(&evm1), Some(pq1));
    assert_eq!(eng.evm_bindings_read().await.get_evm(&pq1), Some(evm1));
    assert_eq!(eng.evm_binding_pq(&evm1).await, Some(pq1));
    assert_eq!(eng.evm_binding_for_pq(&pq1).await, Some(evm1));
    let root_h = eng.get_state_root().await;
    assert_ne!(root_h, root_ref_pre);

    // Height H + 1: carrier tx binds (evm2, pq2) and moves state_root further.
    let chain = evm_adapter::effective_chain_id();
    let raw = evm_raw(&evm_key2, chain, 0, recipient_evm);
    let carrier_h1 = carrier_tx(&kp2, &raw, recipient_pq);
    let b_h1 = block(h + 1, vec![carrier_h1]);
    let out_h1 = eng.apply_block_transition(&b_h1, 0).await;
    assert_eq!(out_h1.status, vec![true]);
    assert_eq!(eng.evm_bindings_read().await.len(), 2);
    assert_eq!(eng.evm_bindings_read().await.get_pq(&evm2), Some(pq2));
    let root_h1 = eng.get_state_root().await;
    assert_ne!(root_h1, root_h);

    // Verify commit_consensus_domains (streaming) == get_state_root() (DomainCache).
    let eng_cached_root = eng.get_state_root().await;
    eng.commit_consensus_domains().await;
    let eng_streaming_root = eng.state_trie.read().await.root_hash();
    assert_eq!(
        eng_cached_root, eng_streaming_root,
        "DomainCache assembly and streaming commit_consensus_domains must be byte-identical"
    );

    // Verify commitment_digest == assemble_cached_digest directly via public commitment API.
    let snap: CommitmentSnapshot = eng.commitment_snapshot().await;
    let zkml = eng.zkml_models_read().await.clone();
    let cnvrf = CnVrfV3EngineSnapshot::default();
    let evm_state = eng.evm_bindings_read().await.clone();
    let streaming_digest =
        commitment_digest_with_zkml_cnvrf_and_evm_bindings(&snap, &zkml, &cnvrf, &evm_state);

    let mut cache = DomainCache::default();
    let evm_bytes = evm_bindings_preimage(&evm_state);
    cache.put_evm_bindings_silent(1, evm_bytes.clone());
    assert_eq!(cache.get_evm_bindings_silent(1), Some(evm_bytes.clone()));
    let cached_digest = assemble_cached_digest_with_cnvrf_minted_and_evm_bindings(
        [
            &tokens_preimage(&snap.tokens),
            &staking_preimage(&snap.staking),
            &pmm_preimage(&snap.pmm, &snap.pmm_usdt_token, &snap.pmm_treasury),
            &contracts_preimage_cached(&snap.contracts, &mut cache.abi),
            &escrow_preimage(&snap.order_escrow),
            &governance_preimage(&snap.governance),
            &oracle_preimage(&snap.oracle),
            &session_keys_preimage(&snap.session_keys),
            &books_preimage(&snap.orderbooks),
            &bridge_preimage(&snap.bridge),
            &cross_shard_preimage(
                &snap.cross_shard_consumed,
                &snap.cross_shard_produced,
                &snap.cross_shard_completed,
            ),
            &xpc_preimage(&snap.cross_shard_xpc),
            &zkml_preimage(&zkml),
        ],
        &cnvrf_v3_preimage(&cnvrf),
        0,
        &evm_bytes,
    );
    assert_eq!(streaming_digest, cached_digest);

    // clone_for_simulation must not mutate live engine.evm_bindings.
    let sim = eng.clone_for_simulation().await;
    let kp_sim = falcon(0x34);
    let pq_sim = pq_of(&kp_sim);
    let evm_key_sim = secp(0x44);
    let evm_sim = evm_of(&evm_key_sim);
    sim.update_account(AccountState::new(pq_sim, FUNDS)).await;
    let bind_sim = binding_tx(&kp_sim, &evm_key_sim, evm_sim, 0);
    sim.apply_transaction_at_height(&bind_sim, TS + h + 2, h + 2)
        .await
        .expect("sim tx applies");
    assert_eq!(sim.evm_bindings_read().await.len(), 3);
    assert_eq!(sim.evm_bindings_read().await.get_pq(&evm_sim), Some(pq_sim));
    assert_eq!(
        eng.evm_bindings_read().await.len(),
        2,
        "clone_for_simulation must never mutate live engine.evm_bindings"
    );
    assert_eq!(eng.evm_bindings_read().await.get_pq(&evm_sim), None);
    assert_eq!(eng.get_state_root().await, root_h1);
}

#[tokio::test]
async fn apply_transaction_at_height_matches_block_apply_parity() {
    let h = 50u64;
    let _gate = EvmBindingsGateGuard::at(h);

    let kp = falcon(0x51);
    let pq = pq_of(&kp);
    let evm_key = secp(0x61);
    let evm = evm_of(&evm_key);
    let tx = binding_tx(&kp, &evm_key, evm, 0);

    let single = InMemoryStateEngine::new();
    let blk_eng = InMemoryStateEngine::new();
    for e in [&single, &blk_eng] {
        e.update_account(AccountState::new(pq, FUNDS)).await;
    }

    single
        .apply_transaction_at_height(&tx, TS + h, h)
        .await
        .expect("single apply");
    let b = block(h, vec![tx]);
    let out = blk_eng.apply_block_transition(&b, 0).await;
    assert_eq!(out.status, vec![true]);

    assert_eq!(
        *single.evm_bindings_read().await,
        *blk_eng.evm_bindings_read().await
    );
}

#[test]
fn evm_bindings_state_bijection_and_rebuild_inverse_fail_closed() {
    let mut state = EvmBindingsState::new();
    let evm1 = [0x11u8; 20];
    let evm2 = [0x22u8; 20];
    let pq1 = [0xAAu8; 32];
    let pq2 = [0xBBu8; 32];

    assert!(state.is_empty());
    assert_eq!(state.bind(evm1, pq1), Ok(true));
    assert_eq!(state.bind(evm1, pq1), Ok(false));
    assert!(state.bind(evm1, pq2).is_err());
    assert!(state.bind(evm2, pq1).is_err());
    assert_eq!(state.len(), 1);
    assert_eq!(state.get_pq(&evm1), Some(pq1));
    assert_eq!(state.get_evm(&pq1), Some(evm1));

    // Corrupt snapshot with duplicate pq value must fail closed in rebuild_inverse.
    let mut by_evm = HashMap::new();
    by_evm.insert(evm1, pq1);
    by_evm.insert(evm2, pq1);
    let snap = EvmBindingsSnapshot { by_evm };
    assert!(EvmBindingsState::from_snapshot(snap).is_err());
}

#[tokio::test]
async fn default_u64_max_preserves_commitment_version_5_and_genesis_kat() {
    assert_eq!(COMMITMENT_VERSION, 5);
    assert_eq!(EVM_BINDINGS_STATE_ACTIVATION_HEIGHT, u64::MAX);
    assert_eq!(effective_evm_bindings_state_activation_height(), u64::MAX);
    assert!(!evm_bindings_state_active_at(0));
    assert!(!evm_bindings_state_active_at(u64::MAX));

    const V1: [u8; 32] = [0x11u8; 32];
    const V2: [u8; 32] = [0x22u8; 32];
    const EXPECTED_GENESIS_ROOT: &str =
        "c07880e016dbb60dd84d9d1dd64bd141e4694d99ba919c288b9b08554f9373a5";

    let engine = Arc::new(InMemoryStateEngine::new());
    let vs = ValidatorSet::from_list(vec![(V1, 1), (V2, 1)]);
    stellereum::runtime::fund_genesis(&engine, &vs, 100_000_000_000_000_000).await;

    let faucet =
        stellereum::rpc::Faucet::new([0x11u8; 32], 1, 100 * 1_000_000_000, 1_000 * 1_000_000_000);
    let _ = engine
        .credit_native_transfer(&faucet.account(), 1_000_000_000_000_000)
        .await;

    let root = hex::encode(engine.get_state_root().await);
    assert_eq!(root, EXPECTED_GENESIS_ROOT);

    // Domain::ALL must remain length 13.
    assert_eq!(Domain::ALL.len(), 13);
}
