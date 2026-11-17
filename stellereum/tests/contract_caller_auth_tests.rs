//! CT-P0 (audit KI-38): the wasm host must expose the AUTHENTICATED caller —
//! the address that signed the executing transaction — and the deployed
//! `sts20_token.wat` contract must refuse a forged integer `from`.
//!
//! The attack is the classic replay: the victim's account id (1) is public,
//! so a stranger packs `from = 1` into `transfer`. The integer is not a
//! credential: the contract compares `host.caller` (resolved by the node from
//! the verified transaction signer) against the address bound at `init`.
//! The forged transaction must revert and leave balances untouched.

use std::fs;

use stellereum::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;

const VICTIM_SEED: u8 = 0x61;
const ATTACKER_SEED: u8 = 0x62;

fn pq_pair(seed: u8) -> ([u8; 32], Vec<u8>) {
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("PQ fixture registration must succeed");
    (from, pk)
}

fn pq_tx(seed: u8, nonce: u64, payload: Vec<OpCode>) -> Transaction {
    let (from, pk) = pq_pair(seed);
    let mut tx = Transaction {
        from,
        to: [0u8; 32],
        amount: 0,
        gas_limit: 5_000_000,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    assert!(tx.verify_signature(), "PQ fixture signature must verify");
    tx
}

fn call(seed: u8, nonce: u64, contract: [u8; 32], method: &str, arg: i64) -> Transaction {
    pq_tx(
        seed,
        nonce,
        vec![OpCode::SysCallCallContract {
            contract,
            method: method.as_bytes().to_vec(),
            arg,
        }],
    )
}

fn sts20_wasm() -> Vec<u8> {
    let src = fs::read_to_string("contracts/sts20_token.wat")
        .expect("contracts/sts20_token.wat must exist");
    wat::parse_str(&src).expect("sts20_token.wat must compile")
}

async fn funded_engine() -> (InMemoryStateEngine, [u8; 32], [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let (victim, _) = pq_pair(VICTIM_SEED);
    let (attacker, _) = pq_pair(ATTACKER_SEED);
    engine
        .update_account(AccountState::new(victim, 1_000_000_000_000))
        .await;
    engine
        .update_account(AccountState::new(attacker, 1_000_000_000_000))
        .await;
    (engine, victim, attacker)
}

#[tokio::test]
async fn poc_p0_forged_from_replay_is_refused_onchain() {
    let (engine, victim, _attacker) = funded_engine().await;

    // Victim deploys and initializes the token; `init` binds host.caller.
    let (applied, failed) = engine
        .apply_block_parallel(
            &[pq_tx(
                VICTIM_SEED,
                0,
                vec![OpCode::SysCallDeployContract { code: sts20_wasm() }],
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0), "deploy must be applied");
    let addr = engine.all_contract_addresses().await[0];

    let (applied, failed) = engine
        .apply_block_parallel(&[call(VICTIM_SEED, 1, addr, "init", 1_000_000)], 0)
        .await;
    assert_eq!((applied, failed), (1, 0), "init must be applied");

    // The contract stored the VERIFIED transaction sender (victim), not an
    // integer supplied by the caller. Slots 4..8 hold its 32 bytes as four
    // little-endian i64 words.
    let stored = engine
        .get_contract(&addr)
        .await
        .expect("contract exists")
        .storage;
    for word in 0..4usize {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&victim[word * 8..word * 8 + 8]);
        assert_eq!(
            stored.get(&(4 + word as i64)).copied().unwrap_or(0),
            i64::from_le_bytes(bytes),
            "host.caller word {word} must equal the verified sender"
        );
    }

    // Legitimate owner call: victim transfers from admin id 1 to id 2.
    let owner_transfer = 100_000_000 + 2 * 100_000 + 10_000;
    let (applied, failed) = engine
        .apply_block_parallel(&[call(VICTIM_SEED, 2, addr, "transfer", owner_transfer)], 0)
        .await;
    assert_eq!((applied, failed), (1, 0), "owner transfer must succeed");
    assert_eq!(
        engine
            .call_contract(&addr, "balance_of", 2, 100_000)
            .await
            .unwrap()
            .0,
        9_950
    );

    // ATTACK: attacker replays the public admin id as `from`, but the
    // authenticated caller is a different address. Must revert atomically.
    let before_admin = engine
        .call_contract(&addr, "balance_of", 1, 100_000)
        .await
        .unwrap()
        .0;
    let forged_transfer = 100_000_000 + 7 * 100_000 + 5_000;
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call(ATTACKER_SEED, 0, addr, "transfer", forged_transfer)],
            0,
        )
        .await;
    assert_eq!(
        (applied, failed),
        (0, 1),
        "forged `from` replay must be refused (P0)"
    );
    assert_eq!(
        engine
            .call_contract(&addr, "balance_of", 1, 100_000)
            .await
            .unwrap()
            .0,
        before_admin,
        "admin balance moved by a stranger (P0)"
    );
    assert_eq!(
        engine
            .call_contract(&addr, "balance_of", 7, 100_000)
            .await
            .unwrap()
            .0,
        0,
        "attacker credited by a forged transfer (P0)"
    );

    // A forged admin burn is refused for the same reason (no id is a credential).
    let (applied, failed) = engine
        .apply_block_parallel(&[call(ATTACKER_SEED, 0, addr, "burn", 1_000)], 0)
        .await;
    assert_eq!(
        (applied, failed),
        (0, 1),
        "forged burn must be refused (P0)"
    );

    // The real owner can still burn (legitimate caller succeeds).
    let (applied, failed) = engine
        .apply_block_parallel(&[call(VICTIM_SEED, 3, addr, "burn", 1_000)], 0)
        .await;
    assert_eq!((applied, failed), (1, 0), "owner burn must succeed");
}

#[tokio::test]
async fn poc_p0_forged_owner_nft_transfer_is_refused_onchain() {
    let (engine, _victim, _attacker) = funded_engine().await;

    let src = fs::read_to_string("contracts/stl_domain_registry.wat")
        .expect("contracts/stl_domain_registry.wat must exist");
    let wasm = wat::parse_str(&src).expect("stl_domain_registry.wat must compile");

    let (applied, failed) = engine
        .apply_block_parallel(
            &[pq_tx(
                VICTIM_SEED,
                0,
                vec![OpCode::SysCallDeployContract { code: wasm }],
            )],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0), "deploy must be applied");
    let addr = engine.all_contract_addresses().await[0];

    // Victim initializes (binds host.caller), opens an auction for domain 1
    // (bidder id 10, 4 chars) and finalizes it.
    for (nonce, method, arg) in [
        (1u64, "init", 99i64),
        (2, "start_auction", 10_000_000_000 + 10 * 100_000 + 4),
        (3, "finalize_auction", 1),
    ] {
        let (applied, failed) = engine
            .apply_block_parallel(&[call(VICTIM_SEED, nonce, addr, method, arg)], 0)
            .await;
        assert_eq!((applied, failed), (1, 0), "{method} must be applied");
    }
    assert_eq!(
        engine
            .call_contract(&addr, "resolve", 1, 100_000)
            .await
            .unwrap()
            .0,
        10,
        "domain 1 must resolve to the auction winner id 10"
    );

    // ATTACK: the owner id (10) is public, but the attacker's authenticated
    // address is not the owner bound at init -> the NFT-style transfer and
    // the DNS re-point both revert.
    let forged_target = 10_000_000_000 + 10 * 100_000 + 666;
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call(ATTACKER_SEED, 0, addr, "set_target", forged_target)],
            0,
        )
        .await;
    assert_eq!(
        (applied, failed),
        (0, 1),
        "forged set_target must revert (P0)"
    );

    let forged_transfer = 10_000_000_000 + 10 * 100_000 + 30;
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call(ATTACKER_SEED, 0, addr, "transfer", forged_transfer)],
            0,
        )
        .await;
    assert_eq!((applied, failed), (0, 1), "domain hijack must revert (P0)");
    assert_eq!(
        engine
            .call_contract(&addr, "resolve", 1, 100_000)
            .await
            .unwrap()
            .0,
        10,
        "domain hijacked via caller spoof (P0)"
    );

    // The real owner (same key that initialized) can still re-point it.
    let (applied, failed) = engine
        .apply_block_parallel(
            &[call(VICTIM_SEED, 4, addr, "set_target", forged_target)],
            0,
        )
        .await;
    assert_eq!((applied, failed), (1, 0), "owner set_target must succeed");
    assert_eq!(
        engine
            .call_contract(&addr, "resolve", 1, 100_000)
            .await
            .unwrap()
            .0,
        666
    );
}
