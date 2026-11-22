//! REGRESSION / FINDING (review execution/atomicity, claim 5): a cross-shard
//! message produced by a CONTRACT (`host.send_message`) is not deliverable.
//!
//! The legacy record built at the source has, by construction:
//!   * an OVERWRITTEN canonical `msg_id` (the contract's own id instead of
//!     `expected_msg_id()`);
//!   * a synthesized `Transaction { signature: Vec::new(), nonce: 0, .. }`
//!     that never appeared in a source block;
//!   * `source_state_root = [0; 32]`, `finalized_in_block = [0; 32]`, no
//!     Merkle proof and `source_balance = 0` — so no escrow leaf exists.
//!
//! The inbound apply path (`apply_cross_shard_consumptions`) requires
//! `verify_msg_id()`, `tx.verify_signature()` and
//! `verify_cross_shard_escrow_anchored(msg)`. Those checks MUST NOT be
//! weakened: they are what stops a Byzantine carrier from minting value.
//!
//! The producing side used to DEBIT the sender for that undeliverable record,
//! so every cross-shard contract send burned the value. The safety fix
//! (`WASM_XSHARD_CONTRACT_SEND_REFUSAL_HEIGHT = 0`) refuses the send before
//! the debit: the hardened router leaves the balance and `cross_shard_out`
//! untouched, and transaction execution reverts the whole payload. This test
//! pins both halves: the refusal, and the fact that the legacy record still
//! fails every inbound gate (so deleting those gates is not an option).

use std::collections::HashMap;

use stellereum::contract::ContractMessage;
use stellereum::sharding::{Block, ShardTopology, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::Svm;

#[tokio::test]
async fn cross_shard_contract_message_is_refused_at_source_and_by_every_inbound_gate() {
    let sender = [0x51u8; 32];
    let recipient = [0x52u8; 32];
    let contract_msg = ContractMessage {
        // A contract-provided id — deliberately not the construction hash.
        msg_id: [0xABu8; 32],
        sender,
        recipient,
        value: 5,
        payload: Vec::new(),
        bounce: true,
    };

    let mut accounts: HashMap<[u8; 32], AccountState> =
        HashMap::from([(sender, AccountState::new(sender, 100))]);
    let mut cross_shard_out = Vec::new();
    // The default topology routes a workchain address to shard 1, so a
    // masterchain contract's send is CROSS-SHARD.
    let topology = ShardTopology::new();

    // 1. The hardened (live) router REFUSES before any mutation.
    let debited = Svm::route_contract_messages_hardened(
        std::slice::from_ref(&contract_msg),
        &mut accounts,
        &mut cross_shard_out,
        MASTERCHAIN_SHARD,
        true,
        &topology,
        0,
    );
    assert!(
        debited.is_empty(),
        "a refused cross-shard send must not debit anybody"
    );
    assert!(
        cross_shard_out.is_empty(),
        "a refused cross-shard send must not enqueue a record"
    );
    assert_eq!(
        accounts[&sender].balance, 100,
        "the sender keeps the value instead of burning it"
    );

    // 2. The legacy (pre-hardening) record is still unverifiable inbound.
    //    Build it with the legacy router so the inbound-gate coverage of this
    //    test survives the producer-side fix.
    let mut legacy_out = Vec::new();
    Svm::route_contract_messages_with_topology(
        std::slice::from_ref(&contract_msg),
        &mut accounts,
        &mut legacy_out,
        MASTERCHAIN_SHARD,
        true,
        &topology,
    );
    assert_eq!(legacy_out.len(), 1, "legacy router still emits the record");
    let msg = &legacy_out[0];

    assert_eq!(
        msg.msg_id, contract_msg.msg_id,
        "the construction id was overwritten with the contract id"
    );
    assert_ne!(
        msg.msg_id,
        msg.expected_msg_id(),
        "the carried id cannot match the canonical construction hash"
    );
    assert!(
        !msg.verify_msg_id(),
        "inbound `verify_msg_id` must refuse the record"
    );
    assert!(
        !msg.tx.verify_signature(),
        "the synthesized tx has an empty signature and must be refused"
    );
    assert!(
        !msg.verify_inclusion_strict(),
        "the untrusted inclusion check must refuse it (id + proof)"
    );

    // And the engine applies it as a no-op on the target shard: no credit,
    // no replay claim.
    let engine = InMemoryStateEngine::new();
    engine.enable_cross_shard();
    engine.set_shard_id(1);
    engine.update_account(AccountState::new(recipient, 0)).await;
    let block = Block::new_for_test(1, 1, [0u8; 32], [0u8; 32], Vec::new())
        .with_cross_shard_out(vec![msg.clone()]);
    let credited = engine.apply_cross_shard_consumptions(&block).await;

    assert_eq!(credited, 0, "the undeliverable message must not credit");
    assert_eq!(
        engine.get_account(&recipient).await.unwrap().balance,
        0,
        "the recipient receives nothing"
    );
    assert_eq!(
        engine.cross_shard_consumed_len().await,
        0,
        "the refused record must not consume the replay key"
    );
}
