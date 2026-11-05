//! Disjoint Wave Scheduler & Resource Conflict Detection (Sealevel-lite)
//!
//! Track #1 Parallel Execution:
//! Partitions transactions within a block into independent waves of mutually disjoint
//! access keys so that within each wave, transactions can execute concurrently across
//! worker threads while preserving deterministic block sequence priority and atomic commit.
//!
//! # GRANULARITY (audit W5.3)
//!
//! The single `Global` barrier that used to swallow EVERY token / orderbook /
//! contract transaction is gone. Those subsystems are keyed by their own id, so
//! two transactions on DIFFERENT tokens (or different pairs, or different
//! contracts) no longer collide and no longer collapse the block into a chain
//! of singleton waves:
//!
//! * [`ResourceKey::Token`] - the fungible token registry is keyed by token id.
//! * [`ResourceKey::OrderBook`] - every trading pair has its own book.
//! * [`ResourceKey::Contract`] - every deployed contract has its own state.
//!
//! [`ResourceKey::Global`] is now RESERVED for the subsystems that really are
//! single-instance and therefore cannot be split per id: the staking ledger,
//! the oracle, the bridge escrow, the session-key registry and the commitment
//! domain - plus the few operations whose target id is not knowable
//! statically (token creation and contract deployment, which both draw from a
//! global registry nonce, and order cancellation, whose pair is not part of
//! the opcode).
//!
//! # THE SCHEDULER IS ADVISORY
//!
//! A wave partition may be conservative; it may never be unsound. The
//! component that decides what may actually run at the same time is the
//! EXECUTOR (`state_engine::apply_block_parallel_fees_with_events`), and it
//! only runs a wave CONCURRENTLY when every transaction in it is a plain
//! value transfer (no payload at all). A payload-bearing transaction mutates
//! consensus domains that the VM clone-commits WHOLESALE, so such a wave is
//! still applied one transaction at a time, in block order. A finer key
//! therefore buys wave granularity, never an unsound overlap.

use crate::sharding::Transaction;
use crate::svm::OpCode;
use std::collections::HashMap;

/// Resource key representing a distinct shared state partition or subsystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceKey {
    /// One account (balance / nonce / mailbox).
    Account([u8; 32]),
    /// ONE fungible token. The token registry is keyed by token id, so two
    /// transactions on different tokens touch disjoint state and do not
    /// conflict.
    Token([u8; 32]),
    /// ONE deployed contract. Every contract owns its own code and storage.
    Contract([u8; 32]),
    /// ONE orderbook (trading pair).
    OrderBook(u32),
    /// The actor-mailbox scope marker: a transaction authorised to enqueue
    /// actor messages touches the mailbox subsystem.
    Actor,
    /// A TRULY GLOBAL subsystem: the staking ledger, the oracle, the bridge
    /// escrow, the session-key registry, the commitment domain, and the
    /// operations whose target id cannot be derived statically (token and
    /// contract creation, order cancellation).
    Global,
}

/// Extracts all resource access keys touched by a transaction.
///
/// - Plain transfer: `Account(tx.from)`, `Account(tx.to)`.
/// - Payload: parses/inspects OpCodes or required_scope; maps the
///   single-instance subsystems (staking, oracle, PMM, bridge, confidential,
///   session keys) to `Global`, and the id-addressable ones to their own
///   key: `Token(token_id)`, `OrderBook(pair_id)`, `Contract(address)`.
///
/// Two transactions conflict iff their key sets intersect. Distinct tokens,
/// distinct pairs and distinct contracts therefore DO NOT conflict, which is
/// what lets them share a wave.
pub fn extract_access_keys(tx: &Transaction) -> Vec<ResourceKey> {
    let mut keys = Vec::with_capacity(4);
    keys.push(ResourceKey::Account(tx.from));
    keys.push(ResourceKey::Account(tx.to));
    // PAYMASTER v1: a sponsored transaction also mutates the sponsor account
    // (the fee leg debits it), so it conflicts with every transaction
    // touching the sponsor. Without this, two sponsored transactions sharing
    // one sponsor could land in the same wave and double-spend the sponsor's
    // fee balance (no-double-spend invariant). Placed before the empty-
    // payload early return: plain sponsored transfers conflict too.
    if let Some(sponsor) = tx.effective_sponsor() {
        keys.push(ResourceKey::Account(sponsor));
    }

    if tx.payload.is_empty() {
        dedup_keys(&mut keys);
        return keys;
    }

    if tx.required_scope() & crate::zkml::SCOPE_ACTOR_SEND != 0 {
        keys.push(ResourceKey::Actor);
    }

    for op in &tx.payload {
        match op {
            OpCode::Nop
            | OpCode::Push(_)
            | OpCode::Pop
            | OpCode::Add
            | OpCode::Sub
            | OpCode::Mul
            | OpCode::Div
            | OpCode::LoadBalance
            | OpCode::Halt
            | OpCode::SysCallVerifyPqSignature { .. } => {}

            OpCode::Transfer { recipient, .. } => {
                keys.push(ResourceKey::Account(*recipient));
            }

            // The staking ledger is a SINGLE ledger: every bond, delegation
            // and reward is one row in one table, so no per-id split exists.
            OpCode::SysCallStake { .. }
            | OpCode::SysCallUnbond { .. }
            | OpCode::SysCallDelegate { .. }
            | OpCode::SysCallUndelegate { .. }
            | OpCode::SysCallClaimRewards { .. }
            | OpCode::SysCallRotateValidatorKey { .. }
            | OpCode::SysCallBeginUndelegate { .. }
            | OpCode::SysCallClaimDelegatorRewards { .. }
            | OpCode::SysCallWithdrawSelfBond { .. }
            | OpCode::SysCallReportPqEquivocation { .. } => {
                keys.push(ResourceKey::Global);
            }

            // FUNGIBLE TOKENS: keyed by token id. Two transfers of DIFFERENT
            // tokens touch different entries of the registry, so they do not
            // conflict. (The registry's snapshot/rollback granularity is
            // whole-domain, which is why the EXECUTOR still keeps a
            // payload-bearing wave sequential - see the module docs.)
            OpCode::SysCallTokenTransfer { token_id, to, .. } => {
                keys.push(ResourceKey::Token(*token_id));
                keys.push(ResourceKey::Account(*to));
            }
            OpCode::SysCallTokenTransferFrom {
                token_id, from, to, ..
            } => {
                keys.push(ResourceKey::Token(*token_id));
                keys.push(ResourceKey::Account(*from));
                keys.push(ResourceKey::Account(*to));
            }
            OpCode::SysCallTokenMint { token_id, to, .. } => {
                keys.push(ResourceKey::Token(*token_id));
                keys.push(ResourceKey::Account(*to));
            }
            OpCode::SysCallTokenBurn { token_id, from, .. } => {
                keys.push(ResourceKey::Token(*token_id));
                keys.push(ResourceKey::Account(*from));
            }
            OpCode::SysCallTokenApprove {
                token_id, spender, ..
            } => {
                keys.push(ResourceKey::Token(*token_id));
                keys.push(ResourceKey::Account(*spender));
            }
            OpCode::SysCallTokenBalanceOf { token_id, account } => {
                keys.push(ResourceKey::Token(*token_id));
                keys.push(ResourceKey::Account(*account));
            }
            OpCode::SysCallTokenCreate { .. } => {
                // The new token id is derived from the registry's GLOBAL
                // creation nonce, so two creations can never be split per id.
                keys.push(ResourceKey::Global);
            }

            // ORDERBOOKS: one book per trading pair. A cancel names an ORDER,
            // not a pair, and the pair it belongs to is not knowable
            // statically, so it stays a global barrier.
            OpCode::SysCallPlaceOrder { pair_id, .. } => {
                keys.push(ResourceKey::OrderBook(*pair_id));
            }
            OpCode::SysCallCancelOrder { .. } => {
                keys.push(ResourceKey::Global);
            }

            // CONTRACTS: one contract owns its own code and storage. (A
            // contract's code may CALL another contract, which is why the
            // executor keeps payload-bearing waves sequential.)
            OpCode::SysCallCallContract { contract, .. } => {
                keys.push(ResourceKey::Contract(*contract));
            }
            OpCode::SysCallDeployContract { .. } => {
                // The new address is derived from the registry's GLOBAL
                // deployment nonce, so two deployments can never be split per
                // id.
                keys.push(ResourceKey::Global);
            }

            // The PMM curve, the bridge escrow, the confidential ledger and
            // the oracle are all single-instance subsystems.
            OpCode::SysCallPmmBuy { .. } | OpCode::SysCallPmmSell { .. } => {
                keys.push(ResourceKey::Global);
            }

            OpCode::SysCallSubmitPriceFeed(_) => {
                keys.push(ResourceKey::Global);
            }

            OpCode::SysCallBridge(_) => {
                keys.push(ResourceKey::Global);
            }

            OpCode::SysCallActorSend { recipient, .. } => {
                keys.push(ResourceKey::Actor);
                keys.push(ResourceKey::Account(*recipient));
            }

            _ => {
                // Anything not recognised may touch anything: fail closed.
                keys.push(ResourceKey::Global);
            }
        }
    }

    dedup_keys(&mut keys);
    keys
}

fn dedup_keys(keys: &mut Vec<ResourceKey>) {
    if keys.len() <= 1 {
        return;
    }
    if keys.len() == 2 {
        if keys[0] == keys[1] {
            keys.pop();
        }
        return;
    }
    let mut i = 0;
    while i < keys.len() {
        let mut j = i + 1;
        while j < keys.len() {
            if keys[i] == keys[j] {
                keys.swap_remove(j);
            } else {
                j += 1;
            }
        }
        i += 1;
    }
}

/// Disjoint wave scheduler. Partitions transactions into waves of mutually disjoint
/// access keys while preserving block sequence priority greedily and deterministically.
pub struct DisjointScheduler;

impl DisjointScheduler {
    /// Partitions `txs` into independent waves `Vec<Vec<usize>>` where within each wave,
    /// all transactions have disjoint access keys.
    /// Deterministic, greedy, preserves block sequence priority.
    pub fn schedule(txs: &[Transaction]) -> Vec<Vec<usize>> {
        if txs.is_empty() {
            return Vec::new();
        }

        let mut waves: Vec<Vec<usize>> = Vec::new();
        let mut last_wave_for_key: HashMap<ResourceKey, usize> = HashMap::new();
        let mut last_global_wave: Option<usize> = None;
        let mut current_max_wave: usize = 0;

        for (i, tx) in txs.iter().enumerate() {
            let keys = extract_access_keys(tx);
            let has_global = keys.contains(&ResourceKey::Global);

            let target_wave = if has_global {
                if i == 0 {
                    0
                } else {
                    current_max_wave + 1
                }
            } else {
                let mut wave_idx = last_global_wave.map(|w| w + 1).unwrap_or(0);
                for key in &keys {
                    if let Some(&w) = last_wave_for_key.get(key) {
                        wave_idx = wave_idx.max(w + 1);
                    }
                }
                wave_idx
            };

            if has_global {
                last_global_wave = Some(target_wave);
            }
            for key in &keys {
                last_wave_for_key.insert(*key, target_wave);
            }
            current_max_wave = current_max_wave.max(target_wave);

            while waves.len() <= target_wave {
                waves.push(Vec::new());
            }
            waves[target_wave].push(i);
        }

        waves
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_transfer(from: &SigningKey, to: [u8; 32], nonce: u64) -> Transaction {
        Transaction::sign(from, to, 100, 10, nonce, 1, 1)
    }

    fn make_payload_tx(
        from: &SigningKey,
        to: [u8; 32],
        nonce: u64,
        payload: Vec<OpCode>,
    ) -> Transaction {
        Transaction::sign_with_payload(from, to, 0, 10, nonce, 1, 1, payload)
    }

    /// The transaction at `idx` of `waves`, or `None`.
    fn wave_of(waves: &[Vec<usize>], idx: usize) -> Option<usize> {
        waves.iter().position(|w| w.contains(&idx))
    }

    #[test]
    fn test_independent_transfers_same_wave() {
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let k3 = SigningKey::generate(&mut OsRng);
        let r1 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let r2 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let r3 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();

        let txs = vec![
            make_transfer(&k1, r1, 0),
            make_transfer(&k2, r2, 0),
            make_transfer(&k3, r3, 0),
        ];

        let waves = DisjointScheduler::schedule(&txs);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0], vec![0, 1, 2]);

        // Granularity: a plain transfer claims exactly its two accounts and
        // nothing else - no global barrier.
        let keys = extract_access_keys(&txs[0]);
        assert!(!keys.contains(&ResourceKey::Global));
        assert!(keys.contains(&ResourceKey::Account(txs[0].from)));
        assert!(keys.contains(&ResourceKey::Account(txs[0].to)));
    }

    #[test]
    fn test_sender_conflict_different_waves() {
        let k1 = SigningKey::generate(&mut OsRng);
        let r1 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let r2 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();

        let txs = vec![make_transfer(&k1, r1, 0), make_transfer(&k1, r2, 1)];

        let waves = DisjointScheduler::schedule(&txs);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1]);

        // The conflict is the ACCOUNT, not a subsystem barrier.
        let keys = extract_access_keys(&txs[0]);
        assert!(!keys.contains(&ResourceKey::Global));
        assert!(keys.contains(&ResourceKey::Account(k1.verifying_key().to_bytes())));
    }

    #[test]
    fn test_recipient_conflict_different_waves() {
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let shared_recipient = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();

        let txs = vec![
            make_transfer(&k1, shared_recipient, 0),
            make_transfer(&k2, shared_recipient, 0),
        ];

        let waves = DisjointScheduler::schedule(&txs);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1]);
    }

    #[test]
    fn test_chain_transfers_different_waves() {
        let k_a = SigningKey::generate(&mut OsRng);
        let k_b = SigningKey::generate(&mut OsRng);
        let addr_b = k_b.verifying_key().to_bytes();
        let addr_c = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();

        // A -> B then B -> C
        let txs = vec![
            make_transfer(&k_a, addr_b, 0),
            make_transfer(&k_b, addr_c, 0),
        ];

        let waves = DisjointScheduler::schedule(&txs);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1]);
    }

    #[test]
    fn test_payload_conflicts() {
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let k3 = SigningKey::generate(&mut OsRng);
        let r0 = [100u8; 32];
        let r1 = [101u8; 32];
        let r2 = [102u8; 32];
        let token_a = [1u8; 32];
        let token_b = [2u8; 32];

        let tx0 = make_payload_tx(
            &k1,
            r0,
            0,
            vec![OpCode::SysCallTokenTransfer {
                token_id: token_a,
                to: [10u8; 32],
                amount: 50,
            }],
        );
        let tx1 = make_payload_tx(
            &k2,
            r1,
            0,
            vec![OpCode::SysCallTokenTransfer {
                token_id: token_a,
                to: [11u8; 32],
                amount: 50,
            }],
        );
        let tx2 = make_payload_tx(
            &k3,
            r2,
            0,
            vec![OpCode::SysCallTokenTransfer {
                token_id: token_b,
                to: [12u8; 32],
                amount: 50,
            }],
        );

        let txs = vec![tx0, tx1, tx2];
        let waves = DisjointScheduler::schedule(&txs);

        // PER-RESOURCE GRANULARITY: the two transactions on token A conflict
        // (same token id) and land in different waves; the transaction on
        // token B touches a DIFFERENT registry entry, so it shares the wave
        // of the first token-A transaction instead of collapsing the block
        // into singleton waves.
        assert_eq!(waves.len(), 2, "distinct tokens must not add a wave");
        assert_eq!(waves[0], vec![0, 2]);
        assert_eq!(waves[1], vec![1]);

        // The conflict is the TOKEN id, not a global barrier.
        let keys = extract_access_keys(&txs[0]);
        assert!(keys.contains(&ResourceKey::Token(token_a)));
        assert!(!keys.contains(&ResourceKey::Token(token_b)));
        assert!(!keys.contains(&ResourceKey::Global));

        // Orderbook conflicts: per PAIR, not per registry.
        let k4 = SigningKey::generate(&mut OsRng);
        let k5 = SigningKey::generate(&mut OsRng);
        let k6 = SigningKey::generate(&mut OsRng);
        let r4 = [104u8; 32];
        let r5 = [105u8; 32];
        let r6 = [106u8; 32];
        let ob0 = make_payload_tx(
            &k4,
            r4,
            0,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: 1,
                is_buy: true,
                price: 100,
                amount: 10,
            }],
        );
        let ob1 = make_payload_tx(
            &k5,
            r5,
            0,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: 1,
                is_buy: false,
                price: 105,
                amount: 10,
            }],
        );
        let ob2 = make_payload_tx(
            &k6,
            r6,
            0,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: 2,
                is_buy: true,
                price: 50,
                amount: 20,
            }],
        );

        let ob_waves = DisjointScheduler::schedule(&[ob0, ob1, ob2]);
        assert_eq!(ob_waves.len(), 2, "distinct pairs must not add a wave");
        assert_eq!(ob_waves[0], vec![0, 2]);
        assert_eq!(ob_waves[1], vec![1]);
    }

    #[test]
    fn test_global_barriers() {
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let k3 = SigningKey::generate(&mut OsRng);
        let r1 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let r3 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();

        let tx0 = make_transfer(&k1, r1, 0);
        let tx1_global = make_payload_tx(
            &k2,
            [0u8; 32],
            0,
            vec![OpCode::SysCallDeployContract {
                code: vec![0x00, 0x61, 0x73, 0x6d],
            }],
        );
        let tx2 = make_transfer(&k3, r3, 0);

        // A contract DEPLOYMENT draws its address from the registry's global
        // nonce: it is a true global barrier - alone in its wave, and every
        // transaction after it is pushed into a later wave.
        let keys = extract_access_keys(&tx1_global);
        assert!(keys.contains(&ResourceKey::Global));

        let waves = DisjointScheduler::schedule(&[tx0, tx1_global, tx2]);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1]);
        assert_eq!(waves[2], vec![2]);
    }

    #[test]
    fn test_distinct_tokens_share_a_wave() {
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let token_a = [11u8; 32];
        let token_b = [22u8; 32];

        let tx0 = make_payload_tx(
            &k1,
            [1u8; 32],
            0,
            vec![OpCode::SysCallTokenTransfer {
                token_id: token_a,
                to: [2u8; 32],
                amount: 10,
            }],
        );
        let tx1 = make_payload_tx(
            &k2,
            [3u8; 32],
            0,
            vec![OpCode::SysCallTokenTransfer {
                token_id: token_b,
                to: [4u8; 32],
                amount: 20,
            }],
        );

        let waves = DisjointScheduler::schedule(&[tx0, tx1]);
        assert_eq!(waves.len(), 1, "two different tokens must share one wave");
        assert_eq!(waves[0], vec![0, 1]);
    }

    #[test]
    fn test_same_token_conflicts_different_waves() {
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let token_a = [11u8; 32];

        let tx0 = make_payload_tx(
            &k1,
            [1u8; 32],
            0,
            vec![OpCode::SysCallTokenTransfer {
                token_id: token_a,
                to: [2u8; 32],
                amount: 10,
            }],
        );
        let tx1 = make_payload_tx(
            &k2,
            [3u8; 32],
            0,
            vec![OpCode::SysCallTokenTransfer {
                token_id: token_a,
                to: [4u8; 32],
                amount: 20,
            }],
        );

        let waves = DisjointScheduler::schedule(&[tx0, tx1]);
        assert_eq!(waves.len(), 2, "the same token must conflict");
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1]);
    }

    #[test]
    fn test_distinct_contracts_share_a_wave() {
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let contract_a = [31u8; 32];
        let contract_b = [32u8; 32];

        let tx0 = make_payload_tx(
            &k1,
            contract_a,
            0,
            vec![OpCode::SysCallCallContract {
                contract: contract_a,
                method: b"ping".to_vec(),
                arg: 1,
            }],
        );
        let tx1 = make_payload_tx(
            &k2,
            contract_b,
            0,
            vec![OpCode::SysCallCallContract {
                contract: contract_b,
                method: b"ping".to_vec(),
                arg: 2,
            }],
        );

        let keys = extract_access_keys(&tx0);
        assert!(keys.contains(&ResourceKey::Contract(contract_a)));
        assert!(!keys.contains(&ResourceKey::Global));

        let waves = DisjointScheduler::schedule(&[tx0, tx1]);
        assert_eq!(
            waves.len(),
            1,
            "two different contracts must share one wave"
        );
        assert_eq!(waves[0], vec![0, 1]);
    }

    #[test]
    fn test_same_contract_conflicts_different_waves() {
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let contract_a = [31u8; 32];

        let tx0 = make_payload_tx(
            &k1,
            contract_a,
            0,
            vec![OpCode::SysCallCallContract {
                contract: contract_a,
                method: b"ping".to_vec(),
                arg: 1,
            }],
        );
        let tx1 = make_payload_tx(
            &k2,
            contract_a,
            0,
            vec![OpCode::SysCallCallContract {
                contract: contract_a,
                method: b"ping".to_vec(),
                arg: 2,
            }],
        );

        let waves = DisjointScheduler::schedule(&[tx0, tx1]);
        assert_eq!(waves.len(), 2, "the same contract must conflict");
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1]);
    }

    #[test]
    fn test_distinct_orderbooks_share_a_wave() {
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);

        let tx0 = make_payload_tx(
            &k1,
            [1u8; 32],
            0,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: 7,
                is_buy: true,
                price: 100,
                amount: 1,
            }],
        );
        let tx1 = make_payload_tx(
            &k2,
            [2u8; 32],
            0,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: 8,
                is_buy: true,
                price: 100,
                amount: 1,
            }],
        );

        let waves = DisjointScheduler::schedule(&[tx0, tx1]);
        assert_eq!(waves.len(), 1, "two different pairs must share one wave");
        assert_eq!(waves[0], vec![0, 1]);
    }

    #[test]
    fn test_id_less_operations_stay_global() {
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);

        // Token creation: the id comes from a global registry nonce.
        let create = make_payload_tx(
            &k1,
            [1u8; 32],
            0,
            vec![OpCode::SysCallTokenCreate {
                name: "X".to_string(),
                symbol: "X".to_string(),
                decimals: 6,
                initial_supply: 1,
                max_supply: None,
            }],
        );
        assert!(extract_access_keys(&create).contains(&ResourceKey::Global));

        // Order cancellation: the opcode names an ORDER, not a pair.
        let cancel = make_payload_tx(
            &k2,
            [2u8; 32],
            0,
            vec![OpCode::SysCallCancelOrder { order_id: 1 }],
        );
        assert!(extract_access_keys(&cancel).contains(&ResourceKey::Global));

        // A global operation is alone in its wave and pushes the following
        // transactions into a later wave.
        let after = make_transfer(&k1, [3u8; 32], 1);
        let waves = DisjointScheduler::schedule(&[create, after]);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1]);
    }

    #[test]
    fn test_per_resource_key_does_not_act_as_a_global_barrier() {
        // A per-resource transaction (a token transfer) must NOT push the
        // transactions after it into a later wave: that is exactly the
        // "everything collapses into sequential waves" behaviour the audit
        // flagged.
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let k3 = SigningKey::generate(&mut OsRng);
        let r2 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let r3 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();

        let tx0 = make_payload_tx(
            &k1,
            [1u8; 32],
            0,
            vec![OpCode::SysCallTokenTransfer {
                token_id: [9u8; 32],
                to: [2u8; 32],
                amount: 1,
            }],
        );
        let tx1 = make_transfer(&k2, r2, 0);
        let tx2 = make_transfer(&k3, r3, 0);

        let waves = DisjointScheduler::schedule(&[tx0, tx1, tx2]);
        assert_eq!(
            waves.len(),
            1,
            "a per-resource key must not split the block"
        );
        assert_eq!(waves[0], vec![0, 1, 2]);
        assert_eq!(wave_of(&waves, 0), Some(0));
    }
}
