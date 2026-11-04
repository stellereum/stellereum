//! First-class shielded path: `stell_shieldedTransfer` -> `stell_shieldedBalance`
//! -> `stell_unshield` over the state engine.
//!
//! Privacy framing: transparent stays the base layer — this is the PATH (the
//! three RPC arms over the existing shield / Transfer2 / unshield opcodes),
//! not a consensus flip. The tests pin:
//!
//! 1. shield -> balance -> unshield round-trips on the live block path, with
//!    the prepare output being EXACTLY what gets signed and applied;
//! 2. a double-spend of a shielded note is refused by the `spent` nullifier
//!    set (commitment bytes; no separate nullifier field exists — the set IS
//!    the guard, exposed exactly as stored);
//! 3. a wrong viewing key decrypts nothing and sums zero;
//! 4. fee accounting is exact: the 1.75x confidential gas surcharge
//!    (SHIELD 3_500; Transfer2 base 3_500 + 1_750/commitment + 44/bit;
//!    UNSHIELD base 3_500 + 525/input) and the inner confidential fee burned
//!    to `total_fees`, with the escrow left holding exactly that fee.

use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use stellereum::crypto_privacy::{
    BitProof, PedersenCommitment, RangeProof, UnshieldInput, ViewingKey,
};
use stellereum::native_api::dispatch;
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{
    confidential_transfer2_gas, OpCode, GAS_CONFIDENTIAL_SHIELD, GAS_CONFIDENTIAL_T2_PER_BIT,
    GAS_CONFIDENTIAL_T2_PER_COMMITMENT, GAS_CONFIDENTIAL_TRANSFER2, GAS_CONFIDENTIAL_UNSHIELD,
    GAS_CONFIDENTIAL_UNSHIELD_PER_INPUT,
};

const BLOCK_TS: u64 = 1_760_000_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sender_of(seed: u8) -> [u8; 32] {
    key(seed).verifying_key().to_bytes()
}

fn hex32(s: &str) -> [u8; 32] {
    let b = hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("hex");
    <[u8; 32]>::try_from(b.as_slice()).expect("32 bytes")
}

fn block(proposer: [u8; 32], height: u64, txs: Vec<Transaction>) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: BLOCK_TS + height,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    }
}

async fn funded_engine(seed: u8, balance: u64) -> (InMemoryStateEngine, [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let addr = sender_of(seed);
    engine
        .update_account(AccountState::new(addr, balance))
        .await;
    (engine, addr)
}

fn parse_range_proof(v: &Value) -> RangeProof {
    let bits = v["bits"].as_u64().expect("bits") as u8;
    let bit_commitments = v["bit_commitments"]
        .as_array()
        .expect("bit_commitments")
        .iter()
        .map(|h| PedersenCommitment {
            commitment: hex32(h.as_str().expect("hex")),
        })
        .collect();
    let bit_proofs = v["bit_proofs"]
        .as_array()
        .expect("bit_proofs")
        .iter()
        .map(|b| BitProof {
            e0: hex32(b["e0"].as_str().expect("e0")),
            s0: hex32(b["s0"].as_str().expect("s0")),
            e1: hex32(b["e1"].as_str().expect("e1")),
            s1: hex32(b["s1"].as_str().expect("s1")),
        })
        .collect();
    RangeProof {
        bits,
        bit_commitments,
        bit_proofs,
    }
}

/// Rebuild the EXACT executable payload a `stell_shieldedTransfer` prepare
/// described, and sign it. Whatever the prepare promised is what the chain
/// applies — or the test fails.
fn transfer_tx_from_prepare(sk: &SigningKey, prep: &Value, nonce: u64) -> Transaction {
    let args = &prep["transaction"]["args"];
    let shield = &args["shield"];
    let shield_commitment = hex32(shield["commitment"].as_str().expect("commitment"));
    let shield_amount = shield["amount"].as_u64().expect("shield amount");
    let shield_blinding = hex32(shield["blinding"].as_str().expect("blinding"));
    let t = &args["transfer"];
    let transfer = stellereum::crypto_privacy::ConfidentialTransfer::new(
        t["input_commitments"]
            .as_array()
            .expect("ins")
            .iter()
            .map(|h| PedersenCommitment {
                commitment: hex32(h.as_str().expect("hex")),
            })
            .collect(),
        t["output_commitments"]
            .as_array()
            .expect("outs")
            .iter()
            .map(|h| PedersenCommitment {
                commitment: hex32(h.as_str().expect("hex")),
            })
            .collect(),
        t["fee"].as_u64().expect("fee"),
    );
    let input_ranges = t["input_ranges"]
        .as_array()
        .expect("ir")
        .iter()
        .map(parse_range_proof)
        .collect();
    let output_ranges = t["output_ranges"]
        .as_array()
        .expect("or")
        .iter()
        .map(parse_range_proof)
        .collect();
    let gas_limit = prep["gas_limit"].as_u64().expect("gas_limit");
    Transaction::sign_with_payload(
        sk,
        [0xEE; 32],
        0,
        gas_limit,
        nonce,
        1,
        1,
        vec![
            OpCode::SysCallConfidentialShield {
                commitment: shield_commitment,
                amount: shield_amount,
                blinding: shield_blinding,
            },
            OpCode::SysCallConfidentialTransfer2 {
                recipient: hex32(t["recipient"].as_str().expect("recipient")),
                transfer: Box::new(transfer),
                input_ranges,
                output_ranges,
            },
        ],
    )
}

fn unshield_tx_from_prepare(sk: &SigningKey, prep: &Value, nonce: u64) -> Transaction {
    let args = &prep["transaction"]["args"];
    let inputs: Vec<UnshieldInput> = args["inputs"]
        .as_array()
        .expect("inputs")
        .iter()
        .map(|i| UnshieldInput {
            commitment: hex32(i["commitment"].as_str().expect("commitment")),
            amount: i["amount"].as_u64().expect("amount"),
            blinding: hex32(i["blinding"].as_str().expect("blinding")),
        })
        .collect();
    let gas_limit = prep["gas_limit"].as_u64().expect("gas_limit");
    Transaction::sign_with_payload(
        sk,
        [0xEE; 32],
        0,
        gas_limit,
        nonce,
        1,
        1,
        vec![OpCode::SysCallConfidentialUnshield { inputs }],
    )
}

// ===========================================================================
// 1. shield -> balance -> unshield round trip, prepare output executed verbatim.
// ===========================================================================

#[tokio::test]
async fn shield_balance_unshield_round_trip_on_the_state_engine() {
    let (engine, sender) = funded_engine(0x71, 10_000_000).await;
    let (recipient, recipient_addr) = (key(0x72), sender_of(0x72));
    engine
        .update_account(AccountState::new(recipient_addr, 1_000_000))
        .await;

    // --- prepare the shielded transfer (fee shown BEFORE signing) ---
    let prep = dispatch(
        &engine,
        "stell_shieldedTransfer",
        &json!({
            "to": hex::encode(recipient_addr),
            "amount": "50000",
            "fee": "100",
            "sender": hex::encode(sender),
        }),
    )
    .await
    .expect("prepare must succeed");
    assert_eq!(prep["action"], "shielded_transfer");
    assert_eq!(prep["submit_with"], "stell_sendRawTransaction");
    // Exact 1.75x-surcharge gas: 3_500 shield + (3_500 + 2*1_750 + 64*44) transfer2.
    assert_eq!(prep["gas_limit"], 13_316);
    assert_eq!(prep["gas_breakdown"]["shield_gas"], 3_500);
    assert_eq!(prep["gas_breakdown"]["transfer_gas"], 9_816);
    assert_eq!(prep["confidential_fee"], "100");

    // --- apply EXACTLY what the prepare built ---
    let tx = transfer_tx_from_prepare(&key(0x71), &prep, 0);
    let out = engine
        .apply_block_transition(&block(sender, 1, vec![tx]), 0)
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");

    // Sender paid shield_total (50_100); self-proposed so gas came back.
    assert_eq!(
        engine.get_account(&sender).await.unwrap().balance,
        10_000_000 - 50_100,
        "sender loses exactly the shielded total"
    );
    let shielded = engine.confidential_read().await;
    assert_eq!(
        shielded.total_fees, 100,
        "inner fee burned to the shielded total"
    );
    assert_eq!(shielded.spent.len(), 1, "the shield input is now spent");
    drop(shielded);
    let escrow = engine
        .get_account(&stellereum::crypto_privacy::SHIELD_ESCROW)
        .await
        .unwrap();
    assert_eq!(escrow.balance, 50_100, "escrow backs the outstanding coin");

    // --- balance: the auditor flow (payload encrypted to the viewing key) ---
    let output_commitment = hex32(
        prep["transaction"]["args"]["transfer"]["output_commitments"][0]
            .as_str()
            .unwrap(),
    );
    let blinding =
        Scalar::from_bytes_mod_order(hex32(prep["openings"][1]["blinding"].as_str().unwrap()));
    let vk = ViewingKey::derive_from_seed(&[0xABu8; 32]);
    let enc = ViewingKey::encrypt_amount_for_auditor(&vk.view_pub, 50_000, &blinding).unwrap();
    let bal = dispatch(
        &engine,
        "stell_shieldedBalance",
        &json!({
            "viewing_key": hex::encode(vk.view_priv),
            "payloads": [{
                "ephemeral_pub": hex::encode(enc.ephemeral_pub),
                "ciphertext": hex::encode(&enc.ciphertext),
                "nonce": hex::encode(enc.nonce),
            }],
        }),
    )
    .await
    .expect("balance must succeed");
    assert_eq!(bal["spendable_sum"], "50000");
    assert_eq!(bal["coin_count"], 1);
    assert_eq!(bal["undecryptable"], 0);
    assert_eq!(
        bal["coins"][0]["commitment"],
        hex::encode(output_commitment)
    );
    assert_eq!(bal["coins"][0]["spent"], false);
    assert_eq!(bal["coins"][0]["spendable"], true);
    assert_eq!(bal["coins"][0]["owner"], hex::encode(recipient_addr));
    assert_eq!(bal["chain"]["spent_nullifiers"], 1);
    assert_eq!(bal["chain"]["owned_outputs"], 1);
    assert_eq!(bal["chain"]["total_fees"], "100");

    // --- unshield: the recipient exits back to transparent ---
    let unprep = dispatch(
        &engine,
        "stell_unshield",
        &json!({
            "to": hex::encode(recipient_addr),
            "amount": "50000",
            "sender": hex::encode(recipient_addr),
            "inputs": [{
                "commitment": hex::encode(output_commitment),
                "amount": "50000",
                "blinding": hex::encode(blinding.to_bytes()),
            }],
        }),
    )
    .await
    .expect("unshield prepare must succeed");
    assert_eq!(unprep["gas_limit"], 3_500 + 525, "base + one input");
    let exit = unshield_tx_from_prepare(&recipient, &unprep, 0);
    let out = engine
        .apply_block_transition(&block(recipient_addr, 2, vec![exit]), 0)
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");

    // Exact round trip: recipient +50_000 (self-proposed, gas back);
    // escrow keeps exactly the burned inner fee; sender untouched since.
    assert_eq!(
        engine.get_account(&recipient_addr).await.unwrap().balance,
        1_000_000 + 50_000
    );
    assert_eq!(
        engine.get_account(&sender).await.unwrap().balance,
        10_000_000 - 50_100
    );
    let escrow = engine
        .get_account(&stellereum::crypto_privacy::SHIELD_ESCROW)
        .await
        .unwrap();
    assert_eq!(
        escrow.balance, 100,
        "escrow = outstanding (0) + burned fees (100)"
    );
    let shielded = engine.confidential_read().await;
    assert_eq!(shielded.spent.len(), 2, "both coins consumed");
    assert_eq!(shielded.total_fees, 100);
    drop(shielded);

    // The exited coin now scans as spent, not spendable.
    let bal = dispatch(
        &engine,
        "stell_shieldedBalance",
        &json!({
            "viewing_key": hex::encode(vk.view_priv),
            "payloads": [{
                "ephemeral_pub": hex::encode(enc.ephemeral_pub),
                "ciphertext": hex::encode(&enc.ciphertext),
                "nonce": hex::encode(enc.nonce),
            }],
        }),
    )
    .await
    .unwrap();
    assert_eq!(bal["spendable_sum"], "0", "spent coins sum to nothing");
    assert_eq!(bal["coins"][0]["spent"], true);
    assert_eq!(bal["coins"][0]["spendable"], false);
}

// ===========================================================================
// 2. Double-spend of a shielded note is refused (spent nullifier set).
// ===========================================================================

#[tokio::test]
async fn double_spend_of_a_shielded_note_is_refused() {
    let (engine, sender) = funded_engine(0x75, 10_000_000).await;

    let prep = dispatch(
        &engine,
        "stell_shieldedTransfer",
        &json!({
            "to": hex::encode(sender),
            "amount": "50000",
            "fee": "100",
            "sender": hex::encode(sender),
        }),
    )
    .await
    .unwrap();
    let tx = transfer_tx_from_prepare(&key(0x75), &prep, 0);
    let out = engine
        .apply_block_transition(&block(sender, 1, vec![tx]), 0)
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");
    assert_eq!(engine.confidential_read().await.spent.len(), 1);

    // Replay the SAME shield+transfer: the shield input commitment is already
    // in `spent` — the nullifier set refuses it before anything mutates.
    let replay = transfer_tx_from_prepare(&key(0x75), &prep, 1);
    let out = engine
        .apply_block_transition(&block(sender, 2, vec![replay]), 0)
        .await;
    assert_eq!(
        (out.applied, out.failed),
        (0, 1),
        "replay must be refused: {out:?}"
    );
    assert_eq!(
        engine.confidential_read().await.spent.len(),
        1,
        "a refused replay adds no nullifier"
    );

    // The unshield prepare itself refuses a spent coin: same guard, read-only.
    let output_commitment = prep["transaction"]["args"]["transfer"]["output_commitments"][0]
        .as_str()
        .unwrap()
        .to_string();
    let blinding = prep["openings"][1]["blinding"]
        .as_str()
        .unwrap()
        .to_string();
    let exit_prep = dispatch(
        &engine,
        "stell_unshield",
        &json!({
            "to": hex::encode(sender),
            "amount": "50000",
            "sender": hex::encode(sender),
            "inputs": [{
                "commitment": output_commitment,
                "amount": "50000",
                "blinding": blinding,
            }],
        }),
    )
    .await
    .unwrap();
    // The refused replay consumed nonce 1 (F-01: attributable failures burn
    // the nonce), so the exit rides nonce 2.
    let exit = unshield_tx_from_prepare(&key(0x75), &exit_prep, 2);
    let out = engine
        .apply_block_transition(&block(sender, 2, vec![exit]), 0)
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");
    // Exit once more with a fresh nonce: DoubleSpend on chain...
    let exit2 = unshield_tx_from_prepare(&key(0x75), &exit_prep, 3);
    let out = engine
        .apply_block_transition(&block(sender, 3, vec![exit2]), 0)
        .await;
    assert_eq!(
        (out.applied, out.failed),
        (0, 1),
        "double exit refused: {out:?}"
    );
    assert_eq!(engine.confidential_read().await.spent.len(), 2);
    // ...and refused at prepare time too (the read sees the same state the
    // chain enforces: the exited coin left `owned` at exit — `retire_for_unshield`
    // checks ownership before the spent set, pinned by
    // `audit_closure_privacy_tests::unshield_entry_is_fully_gated` — so the
    // prepare reports NotOwner, the same fail-closed refusal as the chain.
    // The nullifier backstop is verified directly below: the coin IS in `spent`.
    let err = dispatch(
        &engine,
        "stell_unshield",
        &json!({
            "to": hex::encode(sender),
            "amount": "50000",
            "sender": hex::encode(sender),
            "inputs": [{
                "commitment": output_commitment,
                "amount": "50000",
                "blinding": blinding,
            }],
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), -32003);
    assert!(
        err.message().contains("not owned"),
        "unexpected: {}",
        err.message()
    );
    assert!(
        engine
            .confidential_read()
            .await
            .is_spent(&hex32(&output_commitment)),
        "the exited coin stays in the `spent` nullifier set"
    );
}

// ===========================================================================
// 3. A wrong viewing key sees nothing.
// ===========================================================================

#[tokio::test]
async fn wrong_viewing_key_sees_nothing() {
    let (engine, sender) = funded_engine(0x71, 10_000_000).await;
    let prep = dispatch(
        &engine,
        "stell_shieldedTransfer",
        &json!({
            "to": hex::encode(sender),
            "amount": "777",
            "fee": "10",
            "sender": hex::encode(sender),
        }),
    )
    .await
    .unwrap();
    let tx = transfer_tx_from_prepare(&key(0x71), &prep, 0);
    let out = engine
        .apply_block_transition(&block(sender, 1, vec![tx]), 0)
        .await;
    assert_eq!((out.applied, out.failed), (1, 0), "{out:?}");

    let blinding =
        Scalar::from_bytes_mod_order(hex32(prep["openings"][1]["blinding"].as_str().unwrap()));
    let right_vk = ViewingKey::derive_from_seed(&[0x01u8; 32]);
    let wrong_vk = ViewingKey::derive_from_seed(&[0x02u8; 32]);
    let enc = ViewingKey::encrypt_amount_for_auditor(&right_vk.view_pub, 777, &blinding).unwrap();
    let payload = json!({
        "ephemeral_pub": hex::encode(enc.ephemeral_pub),
        "ciphertext": hex::encode(&enc.ciphertext),
        "nonce": hex::encode(enc.nonce),
    });

    let wrong = dispatch(
        &engine,
        "stell_shieldedBalance",
        &json!({ "viewing_key": hex::encode(wrong_vk.view_priv), "payloads": [payload] }),
    )
    .await
    .unwrap();
    assert_eq!(wrong["spendable_sum"], "0");
    assert_eq!(wrong["undecryptable"], 1);
    assert_eq!(wrong["coins"][0]["decrypted"], false);
    assert!(
        wrong["coins"][0].get("amount").is_none() && wrong["coins"][0].get("commitment").is_none(),
        "no amount or commitment may leak to the wrong key: {wrong}"
    );

    let right = dispatch(
        &engine,
        "stell_shieldedBalance",
        &json!({ "viewing_key": hex::encode(right_vk.view_priv), "payloads": [payload] }),
    )
    .await
    .unwrap();
    assert_eq!(right["spendable_sum"], "777");
    assert_eq!(right["coins"][0]["decrypted"], true);
}

// ===========================================================================
// 4. Fee accounting is exact; V1 stays refused; prepares mutate nothing.
// ===========================================================================

#[tokio::test]
async fn fee_accounting_is_exact_and_v1_stays_refused() {
    // The 1.75x confidential surcharge, pinned at the source.
    assert_eq!(GAS_CONFIDENTIAL_SHIELD, 3_500);
    assert_eq!(GAS_CONFIDENTIAL_TRANSFER2, 3_500);
    assert_eq!(GAS_CONFIDENTIAL_T2_PER_COMMITMENT, 1_750);
    assert_eq!(GAS_CONFIDENTIAL_T2_PER_BIT, 44);
    assert_eq!(GAS_CONFIDENTIAL_UNSHIELD, 3_500);
    assert_eq!(GAS_CONFIDENTIAL_UNSHIELD_PER_INPUT, 525);

    // 1-in/1-out at 32-bit widths: 3_500 + 2*1_750 + 64*44 = 9_816.
    let r = Scalar::from(0x5EED_u64);
    let c_in = PedersenCommitment::commit(1_100, &r);
    let c_out = PedersenCommitment::commit(1_000, &r);
    let ir = vec![RangeProof::prove_auto(&c_in, 1_100, &r)];
    let or_ = vec![RangeProof::prove_auto(&c_out, 1_000, &r)];
    assert_eq!(ir[0].bits, 32);
    assert_eq!(confidential_transfer2_gas(&ir, &or_), 9_816);

    // 64-bit whale width prices per bit: 3_500 + 2*1_750 + 128*44 = 12_632.
    let big = 1u64 << 40;
    let rb = Scalar::from(0xBEEF_u64);
    let cb_in = PedersenCommitment::commit(big + 10, &rb);
    let cb_out = PedersenCommitment::commit(big, &rb);
    let bir = vec![RangeProof::prove_auto(&cb_in, big + 10, &rb)];
    let bor_ = vec![RangeProof::prove_auto(&cb_out, big, &rb)];
    assert_eq!(bir[0].bits, 64);
    assert_eq!(confidential_transfer2_gas(&bir, &bor_), 12_632);

    // Prepares mutate nothing: no shielded history, no balance moves.
    let (engine, sender) = funded_engine(0x71, 10_000_000).await;
    let before = engine.get_account(&sender).await.unwrap().balance;
    let prep = dispatch(
        &engine,
        "stell_shieldedTransfer",
        &json!({
            "to": hex::encode(sender),
            "amount": "1000",
            "fee": "100",
            "sender": hex::encode(sender),
        }),
    )
    .await
    .unwrap();
    assert_eq!(prep["gas_limit"], 3_500 + 9_816);
    assert!(engine.confidential_read().await.is_empty());
    assert_eq!(engine.get_account(&sender).await.unwrap().balance, before);
    let _ = dispatch(
        &engine,
        "stell_shieldedBalance",
        &json!({ "viewing_key": hex::encode([0x77u8; 32]) }),
    )
    .await
    .unwrap();
    assert!(engine.confidential_read().await.is_empty());

    // V1 (equation-only, no range proofs) stays refused on the block path.
    let v1 = stellereum::crypto_privacy::ConfidentialTransfer::new(vec![c_in], vec![c_out], 100);
    let v1tx = Transaction::sign_with_payload(
        &key(0x71),
        [0xEE; 32],
        0,
        50_000,
        0,
        1,
        1,
        vec![OpCode::SysCallConfidentialTransfer {
            recipient: sender,
            transfer: Box::new(v1),
        }],
    );
    let out = engine
        .apply_block_transition(&block(sender, 1, vec![v1tx]), 0)
        .await;
    assert_eq!(
        (out.applied, out.failed),
        (0, 1),
        "V1 must stay refused: {out:?}"
    );
    assert!(engine.confidential_read().await.is_empty());

    // Fail-closed shapes: missing params, bad recipient, protocol recipient,
    // unshield amount mismatch, unshield pays-the-signer rule.
    let err = dispatch(&engine, "stell_shieldedTransfer", &json!({}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), -32602);
    let err = dispatch(
        &engine,
        "stell_shieldedTransfer",
        &json!({ "to": hex::encode(sender), "amount": "0", "sender": hex::encode(sender) }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), -32003);
    let err = dispatch(
        &engine,
        "stell_shieldedTransfer",
        &json!({
            "to": hex::encode(stellereum::crypto_privacy::SHIELD_ESCROW),
            "amount": "10",
            "sender": hex::encode(sender),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), -32003);
    let err = dispatch(
        &engine,
        "stell_unshield",
        &json!({
            "to": hex::encode(sender),
            "amount": "999",
            "sender": hex::encode(sender_of(0x72)),
            "inputs": [],
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.code(),
        -32602,
        "to != signer is a caller error: {}",
        err.message()
    );
}
