//! Disjoint Wave Scheduler & Resource Conflict Detection (Sealevel-lite)
//!
//! Track #1 Parallel Execution:
//! Partitions transactions within a block into independent waves of mutually disjoint
//! access keys so that within each wave, transactions can execute concurrently across
//! worker threads while preserving deterministic block sequence priority and atomic commit.

use crate::sharding::Transaction;
use crate::svm::OpCode;
use std::collections::HashMap;

/// Resource key representing a distinct shared state partition or subsystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceKey {
    Account([u8; 32]),
    Token([u8; 32]),
    Contract([u8; 32]),
    Orderbook(u32),
    Staking,
    Oracle,
    Pmm,
    Bridge,
    Confidential,
    Actor,
    Global,
}

/// Extracts all resource access keys touched by a transaction.
///
/// - Plain transfer: `Account(tx.from)`, `Account(tx.to)`.
/// - Payload: parses/inspects OpCodes or required_scope; maps staking opcodes to `Staking`,
///   pmm to `Pmm`, oracle to `Oracle`, bridge to `Bridge`, confidential to `Confidential`,
///   actor to `Actor`, anything else/unrecognized to `Global`.
/// - Token / orderbook / contract opcodes are GLOBAL subsystem barriers by design
///   (Domain Rollback Clobbering): those domains are snapshotted/restored wholesale,
///   so per-id disjointness cannot isolate a rollback. They emit `Global`.
pub fn extract_access_keys(tx: &Transaction) -> Vec<ResourceKey> {
    let mut keys = Vec::with_capacity(4);
    keys.push(ResourceKey::Account(tx.from));
    keys.push(ResourceKey::Account(tx.to));

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

            OpCode::SysCallStake { .. }
            | OpCode::SysCallUnbond { .. }
            | OpCode::SysCallDelegate { .. }
            | OpCode::SysCallUndelegate { .. }
            | OpCode::SysCallClaimRewards { .. }
            | OpCode::SysCallRotateValidatorKey { .. }
            | OpCode::SysCallBeginUndelegate { .. }
            | OpCode::SysCallClaimDelegatorRewards { .. } => {
                keys.push(ResourceKey::Staking);
            }

            OpCode::SysCallTokenTransfer { token_id: _, to, .. } => {
                // DOMAIN ROLLBACK CLOBBERING: the token registry is snapshotted
                // and restored as ONE whole domain (`snapshot_payload_domains` /
                // `rollback_payload`). Per-token-id disjointness is therefore
                // unsound: a rollback of token A wipes a sibling's token B
                // effects in the same wave. Classify as a global subsystem
                // barrier so such transactions never share a wave.
                keys.push(ResourceKey::Global);
                keys.push(ResourceKey::Account(*to));
            }
            OpCode::SysCallTokenTransferFrom { token_id: _, from, to, .. } => {
                keys.push(ResourceKey::Global);
                keys.push(ResourceKey::Account(*from));
                keys.push(ResourceKey::Account(*to));
            }
            OpCode::SysCallTokenMint { token_id: _, to, .. } => {
                keys.push(ResourceKey::Global);
                keys.push(ResourceKey::Account(*to));
            }
            OpCode::SysCallTokenBurn { token_id: _, from, .. } => {
                keys.push(ResourceKey::Global);
                keys.push(ResourceKey::Account(*from));
            }
            OpCode::SysCallTokenApprove { token_id: _, spender, .. } => {
                keys.push(ResourceKey::Global);
                keys.push(ResourceKey::Account(*spender));
            }
            OpCode::SysCallTokenBalanceOf { token_id: _, account } => {
                keys.push(ResourceKey::Global);
                keys.push(ResourceKey::Account(*account));
            }
            OpCode::SysCallTokenCreate { .. } => {
                keys.push(ResourceKey::Global);
            }

            OpCode::SysCallPlaceOrder { .. } | OpCode::SysCallCancelOrder { .. } => {
                // Same whole-domain argument as tokens: the orderbook manager
                // (+ escrow map) is snapshotted/restored wholesale, and CLOB
                // settlement also mutates the token domain. Per-pair-id
                // disjointness cannot isolate a rollback. Global barrier.
                keys.push(ResourceKey::Global);
            }

            OpCode::SysCallCallContract { .. } | OpCode::SysCallDeployContract { .. } => {
                // Contract execution can reach any domain through the VM
                // (tokens/books via settlement legs), and contract trie entries
                // have no undo. Global barrier.
                keys.push(ResourceKey::Global);
            }

            OpCode::SysCallPmmBuy { .. } | OpCode::SysCallPmmSell { .. } => {
                keys.push(ResourceKey::Pmm);
            }

            OpCode::SysCallSubmitPriceFeed(_) => {
                keys.push(ResourceKey::Oracle);
            }

            OpCode::SysCallBridge(_) => {
                keys.push(ResourceKey::Bridge);
            }

            OpCode::SysCallConfidentialTransfer { .. }
            | OpCode::SysCallConfidentialTransfer2 { .. }
            | OpCode::SysCallConfidentialShield { .. }
            | OpCode::SysCallConfidentialUnshield { .. } => {
                keys.push(ResourceKey::Confidential);
            }

            OpCode::SysCallActorSend { recipient, .. } => {
                keys.push(ResourceKey::Actor);
                keys.push(ResourceKey::Account(*recipient));
            }

            _ => {
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
    }

    #[test]
    fn test_sender_conflict_different_waves() {
        let k1 = SigningKey::generate(&mut OsRng);
        let r1 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let r2 = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();

        let txs = vec![
            make_transfer(&k1, r1, 0),
            make_transfer(&k1, r2, 1),
        ];

        let waves = DisjointScheduler::schedule(&txs);
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1]);
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
        // Domain Rollback Clobbering: token ops are global subsystem barriers,
        // so even disjoint token ids never share a wave (whole-registry
        // snapshot/rollback granularity). Each payload gets its own wave.
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1]);
        assert_eq!(waves[2], vec![2]);

        // Orderbook conflicts
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
        // Same barrier rule for orderbooks: per-pair disjointness is unsound
        // (whole-manager snapshot + token-domain side effects). Singleton waves.
        assert_eq!(ob_waves.len(), 3);
        assert_eq!(ob_waves[0], vec![0]);
        assert_eq!(ob_waves[1], vec![1]);
        assert_eq!(ob_waves[2], vec![2]);
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
            vec![OpCode::SysCallDeployContract { code: vec![0x00, 0x61, 0x73, 0x6d] }],
        );
        let tx2 = make_transfer(&k3, r3, 0);

        let waves = DisjointScheduler::schedule(&[tx0, tx1_global, tx2]);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1]);
        assert_eq!(waves[2], vec![2]);
    }
}
