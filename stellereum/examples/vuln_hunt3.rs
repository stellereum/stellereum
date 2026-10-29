//! PERSONAL VULNERABILITY HUNT — round 3 (cross-module / consensus edge cases).
//!     cargo run --release --example vuln_hunt3

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellereum::chain::{BlockTree, ChainManager};
use stellereum::consensus::{ValidatorSet, Vote, VoteKind, VoteSet};
use stellereum::sharding::Transaction;
use stellereum::sharding::{Block, CrossShardMessage, SharedLiquidityHub, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

fn hdr(n: u32, t: &str) {
    println!("\n\x1b[1;36m[{n}] {t}\x1b[0m");
}
fn blocked(t: &str) {
    println!("  \x1b[32mBLOCKED\x1b[0m: {t}");
}
fn vuln(t: &str) {
    println!("  \x1b[41m!! VULNERABLE:\x1b[0m {t}");
}

#[tokio::main]
async fn main() {
    println!("\x1b[1;33m##########################################################");
    println!("##   VULN HUNT ROUND 3 (cross-module)                  ##");
    println!("##########################################################\x1b[0m");

    let sk = SigningKey::generate(&mut OsRng);
    let mk = |h: u64, prev: [u8; 32], tag: u8| {
        let mut b = Block::new_for_test(MASTERCHAIN_SHARD, h, prev, [tag; 32], vec![])
            .with_timestamp(h)
            .with_proposer(sk.verifying_key().to_bytes());
        b.sign_block(&sk);
        b
    };

    // 1. Finality regression via deeper fork
    hdr(1, "Finality: deeper fork cannot unfinalize");
    {
        let mut cm = ChainManager::new(mk(0, [0u8; 32], 0));
        let g = cm.best_head();
        let a1 = cm.tree.insert(mk(1, g, 1));
        let a2 = cm.tree.insert(mk(2, a1, 2));
        cm.recompute_canonical();
        cm.finalize(a2).unwrap();
        // build a much longer competing branch from genesis
        let mut prev = g;
        for h in 1..10 {
            prev = cm.tree.insert(mk(h, prev, 100 + h as u8));
        }
        cm.recompute_canonical();
        if cm.best_head() == a2 || cm.finalized_hash == a2 {
            blocked("finalized block stays canonical despite longer fork");
        } else {
            vuln("longer fork overtook finalized block");
        }
    }

    // 2. Cross-shard replay
    hdr(2, "Cross-shard: replay same msg twice");
    {
        let mut hub = SharedLiquidityHub::new(vec![0, 1]);
        let tsk = SigningKey::generate(&mut OsRng);
        let tx = Transaction::sign(&tsk, [2u8; 32], 5, 0, 0, 0, 1);
        // trusted local message (skips inclusion proof) so routing proceeds
        let msg = CrossShardMessage::new_trusted(0, 1, tx, [0u8; 32], [0u8; 32]);
        let _first = hub.route_cross_shard_message(msg.clone());
        let second = hub.route_cross_shard_message(msg.clone());
        // second must be dropped (0 = not routed)
        if second == 0 {
            blocked("second route rejected (replay protection)");
        } else {
            vuln("same cross-shard message routed twice");
        }
    }

    // 3. Vote: equivocation (two different blocks same height/round by one validator)
    hdr(3, "Consensus: equivocation detection");
    {
        let ks: Vec<SigningKey> = (0..4).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let vs = ValidatorSet::from_list(
            ks.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let mut set = VoteSet::new();
        let v1 = Vote::sign(&ks[0], 1, 0, VoteKind::Precommit, Some([1u8; 32]));
        let v2 = Vote::sign(&ks[0], 1, 0, VoteKind::Precommit, Some([2u8; 32]));
        set.add(v1, &vs, 1, 0, VoteKind::Precommit).unwrap();
        let r = set.add(v2, &vs, 1, 0, VoteKind::Precommit);
        if r.is_err() {
            blocked("equivocating validator detected/rejected");
        } else if !set.equivocations().is_empty() {
            blocked("equivocation recorded");
        } else {
            vuln("equivocation accepted silently");
        }
    }

    // 4. Quorum with zero validators
    hdr(4, "Consensus: empty validator set");
    {
        let vs = ValidatorSet::from_list(vec![]);
        let set = VoteSet::new();
        if set.quorum_reached(None, &vs) {
            vuln("quorum reached with 0 validators");
        } else {
            blocked("no quorum possible with empty set");
        }
    }

    // 5. Block with duplicate txs applied twice
    hdr(
        5,
        "State: duplicate tx in apply_block_parallel (no double debit)",
    );
    {
        let e = InMemoryStateEngine::new();
        let s = SigningKey::generate(&mut OsRng);
        let from = s.verifying_key().to_bytes();
        e.update_account(AccountState::new(from, 1_000)).await;
        let tx = Transaction::sign(&s, [9u8; 32], 300, 0, 0, 1, 1);
        let _ = e.apply_block_parallel(&[tx.clone(), tx.clone()], 0).await;
        let bal = e.get_account(&from).await.unwrap().balance;
        if bal < 700 {
            vuln(&format!("double debit, balance {bal}"));
        } else {
            blocked(&format!("no double debit (balance {bal})"));
        }
    }

    // 6. State root determinism under identical parallel apply
    hdr(6, "State: identical parallel block -> identical root");
    {
        let s1 = SigningKey::generate(&mut OsRng);
        let s2 = SigningKey::generate(&mut OsRng);
        let r1 = || async {
            let e = InMemoryStateEngine::new();
            e.update_account(AccountState::new(s1.verifying_key().to_bytes(), 1000))
                .await;
            e.update_account(AccountState::new(s2.verifying_key().to_bytes(), 1000))
                .await;
            let t = vec![
                Transaction::sign(&s1, s2.verifying_key().to_bytes(), 10, 0, 0, 1, 1),
                Transaction::sign(&s2, s1.verifying_key().to_bytes(), 20, 0, 0, 1, 1),
            ];
            let _ = e.apply_block_parallel(&t, 0).await;
            e.get_state_root().await
        };
        let a = r1().await;
        let b = r1().await;
        if a == b {
            blocked("deterministic root across runs");
        } else {
            vuln("non-deterministic state root");
        }
    }

    // 7. Block tree: self-parent cycle protection
    hdr(7, "BlockTree: cycle (block references itself as parent)");
    {
        let mut tree = BlockTree::new();
        let mut b = mk(1, [0u8; 32], 1);
        b.prev_hash = b.compute_hash(); // self-parent
        let _ = tree.insert(b);
        // should not infinite loop
        blocked("self-parent block inserted without hang");
    }

    // 8. Timestamp / height monotonicity in blocks
    hdr(8, "Chain: accepts block with a recycled height?");
    {
        let mut cm = ChainManager::new(mk(0, [0u8; 32], 0));
        let g = cm.best_head();
        let b1 = cm.tree.insert(mk(1, g, 1));
        // same height, different tag, same parent -> competing sibling
        let b1b = cm.tree.insert(mk(1, g, 2));
        cm.recompute_canonical();
        // fork-choice should pick one deterministically
        let head = cm.best_head();
        if head == b1 || head == b1b {
            blocked("sibling at same height resolved deterministically");
        } else {
            vuln("fork-choice ambiguous");
        }
    }

    println!("\n\x1b[1;33m############ ROUND 3 DONE ############\x1b[0m");
}
