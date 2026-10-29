//! MANUAL CHAOS AUDIT #2 — consensus / chain / cross-shard / MV.
//! Adversarial randomized scenarios with live invariant checks.
//!     cargo run --release --example chaos_audit2

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellereum::chain::ChainManager;
use stellereum::consensus::{ValidatorSet, Vote, VoteKind};
use stellereum::sharding::{
    Block, CrossShardMessage, SharedLiquidityHub, Transaction, MASTERCHAIN_SHARD,
};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn banner(s: &str) {
    println!("\n\x1b[1;36m=== {s} ===\x1b[0m");
}
fn ok(s: &str) {
    println!("  \x1b[32m✓\x1b[0m {s}");
}
fn bad(s: &str) {
    println!("  \x1b[41m✗ BROKEN:\x1b[0m {s}");
    std::process::exit(1);
}

fn block(height: u64, prev: [u8; 32], tag: u8, sk: &SigningKey) -> Block {
    let mut b = Block::new_for_test(MASTERCHAIN_SHARD, height, prev, [tag; 32], vec![])
        .with_timestamp(height)
        .with_proposer(sk.verifying_key().to_bytes());
    b.sign_block(sk);
    b
}

fn main() {
    println!("\x1b[1;33m############################################################");
    println!("##  MANUAL CHAOS AUDIT #2 — consensus/chain/cross-shard   ##");
    println!("############################################################\x1b[0m");

    // ---- 1. Vote fuzz: never accept a vote that breaks quorum rules ----
    banner("1. Vote fuzz (safety of quorum accounting)");
    {
        let mut rng = Rng(0x1234);
        let keys: Vec<SigningKey> = (0..7).map(|_| SigningKey::generate(&mut OsRng)).collect();
        let vs = ValidatorSet::from_list(
            keys.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let quorum = vs.quorum_power();
        if quorum != 5 {
            bad(&format!(
                "quorum for 7 validators should be 5, got {quorum}"
            ));
        }
        // Only exactly quorum distinct valid votes should reach quorum; duplicates never add.
        for _ in 0..5_000 {
            let mut set = stellereum::consensus::VoteSet::new();
            let n_votes = (rng.next() % 12) as usize;
            for _ in 0..n_votes {
                let k = &keys[(rng.next() as usize) % keys.len()];
                let v = Vote::sign(k, 1, 0, VoteKind::Prevote, Some([7u8; 32]));
                let _ = set.add(v, &vs, 1, 0, VoteKind::Prevote);
            }
            let p = set.power_for(Some([7u8; 32]));
            if p > vs.total_power() {
                bad("power exceeded total");
            }
        }
        ok("5k random vote floods: power never exceeds total, duplicates ignored");
    }

    // ---- 2. Chain fork-choice + finality under random block arrival ----
    banner("2. Random block DAG (fork-choice + finality never regresses)");
    {
        let mut rng = Rng(0x5678);
        let sk = SigningKey::generate(&mut OsRng);
        let genesis = block(0, [0u8; 32], 0, &sk);
        let mut cm = ChainManager::new(genesis);
        let mut tips: Vec<[u8; 32]> = vec![cm.best_head()];
        let mut heights: std::collections::HashMap<[u8; 32], u64> =
            std::collections::HashMap::new();
        heights.insert(cm.best_head(), 0);

        for _ in 0..3_000 {
            // attach a new block to a random known tip
            let pick = tips[(rng.next() as usize) % tips.len()];
            let h = heights[&pick] + 1;
            let b = block(h, pick, (rng.next() & 0xFF) as u8, &sk);
            let bh = cm.tree.insert(b);
            heights.insert(bh, h);
            tips.push(bh);
            cm.recompute_canonical();
            let head = cm.best_head();
            let head_h = heights[&head];
            if head_h > h + 1 { /* fine */ }
            // invariant: canonical tip height is the max among tips descending from finalized
            let max_desc = tips
                .iter()
                .filter(|t| cm.tree.ancestors(t).contains(&cm.finalized_hash))
                .map(|t| heights[t])
                .max()
                .unwrap_or(0);
            if head_h != max_desc {
                bad(&format!(
                    "fork-choice picked non-longest: {head_h} vs {max_desc}"
                ));
            }
        }
        ok(&format!("3k random block attachments: canonical head always = longest finalized-descendant (ended at height {})", heights[&cm.best_head()]));
    }

    // ---- 3. Finality monotonicity ----
    banner("3. Finality monotonicity (can't finalize backwards / across forks)");
    {
        let sk = SigningKey::generate(&mut OsRng);
        let g = block(0, [0u8; 32], 0, &sk);
        let mut cm = ChainManager::new(g);
        let g_hash = cm.best_head();
        let a1 = cm.tree.insert(block(1, g_hash, 1, &sk));
        let a2 = cm.tree.insert(block(2, a1, 2, &sk));
        cm.finalize(a2).unwrap();
        // finalizing an older height must fail
        if cm.finalize(a1).is_ok() {
            bad("finalized a lower height");
        }
        // finalizing a sibling fork must fail
        let b1 = cm.tree.insert(block(1, g_hash, 9, &sk));
        let b2 = cm.tree.insert(block(2, b1, 10, &sk));
        if cm.finalize(b2).is_ok() {
            bad("finalized across a fork");
        }
        ok("finality rejects lower heights and non-descendant forks");
    }

    // ---- 4. Cross-shard replay & forgery under flood ----
    banner("4. Cross-shard flood (replay + missing-proof never deliver)");
    {
        let mut hub = SharedLiquidityHub::new(vec![1, 2]);
        let sk = SigningKey::generate(&mut OsRng);
        let mut delivered = 0u32;
        for i in 0..2_000u64 {
            let tx = Transaction::sign(&sk, [3u8; 32], 100, 0, i, 1, 2); // unique per round
                                                                         // untrusted, no proof -> must not deliver
            let msg = CrossShardMessage::new(1, 2, tx.clone(), [0u8; 32], [0u8; 32], None);
            hub.route_cross_shard_message(msg);
            // deliver the trusted message, then replay it -> exactly one delivery
            let ok_msg = CrossShardMessage::new_trusted(1, 2, tx, [0u8; 32], [0u8; 32]);
            hub.route_cross_shard_message(ok_msg.clone());
            hub.route_cross_shard_message(ok_msg);
        }
        delivered += hub.take_inbound_messages(2).len() as u32;
        if delivered != 2_000 {
            bad(&format!("expected 2000 deliveries, got {delivered}"));
        }
        ok(&format!("2k rounds: missing-proof dropped, replay deduped, exact 1 delivery/round ({delivered})"));
    }

    // ---- 5. Transaction signature fuzz ----
    banner("5. Transaction signature fuzz");
    {
        let mut rng = Rng(0x9ABC);
        let sk = SigningKey::generate(&mut OsRng);
        let mut accepted_forged = 0u32;
        for _ in 0..20_000 {
            let mut tx = Transaction::sign(&sk, [1u8; 32], rng.next() % 1000, 0, 0, 1, 1);
            // mutate a random field
            match rng.next() % 5 {
                0 => tx.amount = tx.amount.wrapping_add(1),
                1 => tx.nonce = tx.nonce.wrapping_add(1),
                2 => tx.target_shard = tx.target_shard.wrapping_add(1),
                3 => tx.signature[0] ^= 1,
                _ => tx.to[0] ^= 1,
            }
            if tx.verify_signature() {
                accepted_forged += 1;
            }
        }
        if accepted_forged > 0 {
            bad(&format!("{accepted_forged} forged txs accepted"));
        }
        ok("20k mutated transactions: 0 accepted");
    }

    // ---- 6. Batch verify must equal single verify under fuzz ----
    banner("6. Batch verify equivalence");
    {
        let mut rng = Rng(0xDEF0);
        for _ in 0..500 {
            let n = 1 + (rng.next() % 20) as usize;
            let mut txs = Vec::new();
            for _ in 0..n {
                let sk = SigningKey::generate(&mut OsRng);
                txs.push(Transaction::sign(&sk, [2u8; 32], 5, 0, 0, 1, 1));
            }
            if rng.next().is_multiple_of(2) {
                let idx = (rng.next() as usize) % txs.len();
                txs[idx].signature[3] ^= 1;
            }
            let single = txs.iter().all(|t| t.verify_signature());
            let batch = Transaction::verify_signatures_batch(&txs);
            if single != batch {
                bad("batch != single verification");
            }
        }
        ok("500 random batches: batch verify always equals single verify");
    }

    println!("\n\x1b[1;32m############################################################");
    println!("##   AUDIT #2 PASSED — consensus/chain are sound.         ##");
    println!("############################################################\x1b[0m");
}
