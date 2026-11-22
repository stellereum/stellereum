//! REVIEW REGRESSION (KNOWN GAP, producer-side fix owned elsewhere):
//! a cross-shard message produced by a CONTRACT (`host.send_message`) cannot
//! pass the inbound credit gate.
//!
//! `Svm::route_contract_messages_with_topology` (and, at/after the hardening
//! height, `route_contract_messages_hardened` — both are called by the
//! engine's `process_contract_outbound_messages*`) build a
//! `CrossShardMessage` from a `ContractMessage` as follows:
//!
//!   * `Transaction { signature: vec![], nonce: 0, source_shard: local, .. }`
//!     — an unsigned synthetic transaction that is NOT in `Block.transactions`;
//!   * `source_state_root = [0; 32]`, `finalized_in_block = [0; 32]`, no
//!     Merkle proof;
//!   * the construction-time `msg_id` is then OVERWRITTEN with the contract
//!     message's own id.
//!
//! The inbound legacy gate (`InMemoryStateEngine::apply_cross_shard_consumptions`)
//! requires, in this order: `verify_msg_id()`, `tx.verify_signature()`, and
//! `verify_cross_shard_escrow_anchored()` (an anchored proof of the SOURCE-SIDE
//! escrow leaf). The router output satisfies NONE of the three, and no escrow
//! leaf exists because the synthetic tx never applied in a source block.
//!
//! This test is a TRIPWIRE: it asserts today's (fail-closed) outcome — the
//! target credits nothing. When the producer is fixed (svm.rs / block assembly,
//! outside this agent's file scope) the gate assertions must be inverted to
//! assert a VERIFIED message instead.

use std::collections::HashMap;

use serde_json::json;

use stellereum::contract::ContractMessage;
use stellereum::sharding::{Block, ShardTopology, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::Svm;

const SHARD1: u32 = 1;
const CONTRACT: [u8; 32] = [0x22u8; 32];
const RECIPIENT: [u8; 32] = [0x77u8; 32];
const VALUE: u64 = 350_000;

fn outbound_from_contract() -> ContractMessage {
    ContractMessage {
        msg_id: [0xABu8; 32],
        sender: CONTRACT,
        recipient: RECIPIENT,
        value: VALUE,
        payload: b"PING".to_vec(),
        bounce: true,
    }
}

#[tokio::test]
async fn contract_outbound_cross_shard_message_fails_every_inbound_gate() {
    let mut accounts: HashMap<[u8; 32], AccountState> = HashMap::new();
    accounts.insert(CONTRACT, AccountState::new(CONTRACT, 1_000_000));
    let mut xout = Vec::new();
    let topology = ShardTopology::new();

    Svm::route_contract_messages_with_topology(
        &[outbound_from_contract()],
        &mut accounts,
        &mut xout,
        MASTERCHAIN_SHARD,
        true,
        &topology,
    );

    assert_eq!(xout.len(), 1, "one cross-shard record expected");
    let msg = &xout[0];
    assert_eq!(msg.source_shard, MASTERCHAIN_SHARD);
    assert_eq!(msg.target_shard, SHARD1);
    assert!(msg.is_transfer());
    assert!(msg.is_inbound_for(SHARD1));

    // Gate 1: the id was rebound to the contract message's own id, so the
    // recompute from (source, target, tx_hash, finalized_in_block) mismatches.
    assert_ne!(
        msg.msg_id,
        msg.expected_msg_id(),
        "the router overwrites msg_id; the inbound recompute must reject it"
    );
    assert!(
        !msg.verify_msg_id(),
        "GAP: a contract-originated message does not carry a valid msg_id"
    );

    // Gate 2: the synthetic transaction has no signature at all.
    assert!(
        !msg.tx.verify_signature(),
        "GAP: the synthetic contract transaction carries no PQ signature"
    );

    // Gate 3: no source escrow proof exists (zero root, zero anchor, no proof),
    // and the synthetic transaction never appeared in a source block, so no
    // escrow leaf could have been recorded for it.
    assert!(msg.merkle_inclusion_proof.is_none());
    assert_eq!(msg.source_state_root, [0u8; 32]);
    assert_eq!(msg.finalized_in_block, [0u8; 32]);
    // The construction-time balance attestation is also left at zero, so the
    // runtime's inclusion verifier (`source_balance >= tx.amount`) would
    // refuse the record even if a proof were attached.
    assert_eq!(msg.source_balance, 0);
    assert!(msg.source_balance < msg.tx.amount);

    let target = InMemoryStateEngine::new();
    target.enable_cross_shard();
    target.set_shard_id(SHARD1);
    assert!(
        !target.verify_cross_shard_escrow_anchored(msg),
        "GAP: the source debit / escrow cannot be proven for a synthetic tx"
    );
}

/// `>= H` (`WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT = 0`, i.e. the live
/// path) routes through `route_contract_messages_hardened`. At/after
/// `WASM_XSHARD_CONTRACT_SEND_REFUSAL_HEIGHT` (`0`) it now REFUSES a
/// cross-shard send BEFORE the debit: nothing is enqueued and the sender keeps
/// its value. That is the safety fix — the record it used to build could never
/// pass an inbound gate, so the debit was a burn.
#[tokio::test]
async fn hardened_live_router_refuses_cross_shard_send_before_debit() {
    let mut accounts: HashMap<[u8; 32], AccountState> = HashMap::new();
    accounts.insert(CONTRACT, AccountState::new(CONTRACT, 1_000_000));
    let mut xout = Vec::new();
    let msg = ContractMessage {
        payload: Vec::new(),
        ..outbound_from_contract()
    };
    let debited = Svm::route_contract_messages_hardened(
        &[msg],
        &mut accounts,
        &mut xout,
        MASTERCHAIN_SHARD,
        true,
        &ShardTopology::new(),
        0,
    );

    assert!(
        xout.is_empty(),
        "no undeliverable cross-shard record may be emitted"
    );
    assert!(
        debited.is_empty(),
        "the sender must not be debited for a refused message"
    );
    assert_eq!(
        accounts[&CONTRACT].balance, 1_000_000,
        "the sender keeps the value"
    );
}

#[tokio::test]
async fn contract_outbound_cross_shard_message_credits_nobody_on_target() {
    let mut accounts: HashMap<[u8; 32], AccountState> = HashMap::new();
    accounts.insert(CONTRACT, AccountState::new(CONTRACT, 1_000_000));
    let mut xout = Vec::new();
    Svm::route_contract_messages_with_topology(
        &[outbound_from_contract()],
        &mut accounts,
        &mut xout,
        MASTERCHAIN_SHARD,
        true,
        &ShardTopology::new(),
    );
    let msg = xout.pop().expect("cross-shard record");

    let target = InMemoryStateEngine::new();
    target.enable_cross_shard();
    target.set_shard_id(SHARD1);

    let block = Block::new_for_test(SHARD1, 7, [0u8; 32], [0u8; 32], Vec::new())
        .with_cross_shard_out(vec![msg])
        .with_timestamp(1_760_000_000);

    let credited = target.apply_cross_shard_consumptions(&block).await;
    assert_eq!(
        credited, 0,
        "a contract-originated message must never be credited without a source escrow proof"
    );
    assert_eq!(target.cross_shard_consumed_len().await, 0);
    assert_eq!(
        target.get_account(&RECIPIENT).await.map(|a| a.balance),
        None,
        "the target must not mint the recipient's balance: {}",
        json!({ "recipient": hex::encode(RECIPIENT) })
    );
}
