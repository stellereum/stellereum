//! PERSONAL VULNERABILITY HUNT — round 2 (module-focused).
//!     cargo run --release --example vuln_hunt2

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellereum::bridge::{SupportedChain, TeleportBridgeEngine, TeleportDepositEvent};
use stellereum::crypto_privacy::{ConfidentialTransfer, PedersenCommitment, ViewingKey};
use stellereum::mempool::Mempool;
use stellereum::oracle::{OracleSafetyEngine, PriceFeedUpdate};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::zkml::{QuantizedLayer, QuantizedLinearModel, SessionKeyAuthorization, ZkMlProof};

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
    println!("##   VULN HUNT ROUND 2 (modules)                       ##");
    println!("##########################################################\x1b[0m");

    // 1. Bridge: replay a deposit
    hdr(1, "Bridge: deposit replay");
    {
        let v1 = SigningKey::generate(&mut OsRng);
        let mut bridge = TeleportBridgeEngine::new(vec![v1.verifying_key().to_bytes()]);
        let mut msg = Vec::new();
        msg.extend_from_slice(&[7u8; 32]);
        msg.extend_from_slice(&[8u8; 32]);
        msg.extend_from_slice(b"USDT");
        msg.extend_from_slice(&100u64.to_be_bytes());
        let sig = ed25519_dalek::Signer::sign(&v1, &msg).to_vec();
        let ev = TeleportDepositEvent {
            source_chain: SupportedChain::Ton,
            source_tx_hash: [7u8; 32],
            recipient: [8u8; 32],
            asset: "USDT".into(),
            amount: 100,
            validator_signatures: vec![(v1.verifying_key().to_bytes(), sig)],
            zk_proof: None,
        };
        let r1 = bridge.process_deposit(&ev);
        let r2 = bridge.process_deposit(&ev);
        if r1.is_ok() && r2.is_ok() {
            vuln("same deposit processed twice");
        } else {
            blocked("duplicate deposit rejected (source_tx_hash dedup)");
        }
    }

    // 2. Bridge: withdrawal replay after finalize
    hdr(2, "Bridge: withdrawal replay");
    {
        let mut bridge = TeleportBridgeEngine::new(vec![]);
        let req = bridge
            .request_withdrawal([1u8; 32], SupportedChain::Arbitrum, "0x1".into(), 1_000, 0)
            .unwrap();
        let f1 = bridge.finalize_withdrawal(req, 999_999);
        let f2 = bridge.finalize_withdrawal(req, 999_999);
        if f1.is_ok() && f2.is_ok() {
            vuln("withdrawal executed twice");
        } else {
            blocked("withdrawal cannot be finalized twice");
        }
    }

    // 3. Confidential: negative/inflated transfer via commitment
    hdr(3, "Confidential: balance-conservation bypass");
    {
        let r_in = PedersenCommitment::random_blinding();
        let r_out = PedersenCommitment::random_blinding();
        // inputs 100, outputs 200 (creating 100 from nothing)
        let tx = ConfidentialTransfer::new(
            vec![PedersenCommitment::commit(100, &r_in)],
            vec![PedersenCommitment::commit(200, &r_out)],
            0,
        );
        if tx.verify_balance_conservation() {
            vuln("outputs > inputs accepted");
        } else {
            blocked("inflation rejected by conservation check");
        }
    }

    // 4. Confidential: viewing-key decryption with wrong key
    hdr(4, "Confidential: viewing-key forgery");
    {
        let vk = ViewingKey::generate();
        let other = ViewingKey::generate();
        let r = PedersenCommitment::random_blinding();
        let payload = ViewingKey::encrypt_amount_for_auditor(&vk.view_pub, 12345, &r).unwrap();
        if other.decrypt_amount(&payload).is_ok() {
            vuln("foreign key decrypted payload");
        } else {
            blocked("only the holder of the viewing key can decrypt");
        }
    }

    // 5. Oracle: negative/low price
    hdr(5, "Oracle: zero/absurd price");
    {
        let sk = SigningKey::generate(&mut OsRng);
        let mut o = OracleSafetyEngine::new(vec![sk.verifying_key().to_bytes()]);
        o.set_dex_twap("TON", 5_000_000);
        let zero = PriceFeedUpdate::sign("TON", 0, 1000, &sk);
        if o.resolve_price(Some(&zero), "TON", 1000).is_ok() {
            vuln("zero price accepted");
        } else {
            blocked("zero price rejected");
        }
    }

    // 6. zkML: forged proof (tamper output)
    hdr(6, "zkML: tampered proof");
    {
        let model = QuantizedLinearModel::new(vec![QuantizedLayer::new(
            2,
            2,
            vec![2, -1, 1, 3],
            vec![1, -2],
        )]);
        let mut proof = ZkMlProof::forge_structural_proof(&model, &[3, 4], &[11, 7]);
        proof.public_outputs[0] ^= 0xFF;
        if proof.verify_inference() {
            vuln("tampered output verified");
        } else {
            blocked("tampered proof rejected");
        }
    }

    // 7. zkML: session key over budget
    hdr(7, "zkML: session-key gas cap bypass");
    {
        let master = SigningKey::generate(&mut OsRng);
        let mut auth = SessionKeyAuthorization::sign_delegation(
            &master,
            [8u8; 32],
            4_000_000_000,
            1000,
            stellereum::zkml::SCOPE_ALL,
            u64::MAX,
            0,
        );
        let first = auth.verify_and_spend_gas(500, 1001);
        let over = auth.verify_and_spend_gas(u64::MAX, 1002);
        if first.is_ok() && over.is_ok() {
            vuln("session gas cap bypassed");
        } else {
            blocked("session gas cap enforced");
        }
    }

    // 8. Mempool: flood + per-sender limit
    hdr(8, "Mempool: sender flood");
    {
        let sk = SigningKey::generate(&mut OsRng);
        let mut mp = Mempool::new(1000, 5);
        let mut rejected = 0;
        for n in 0..50 {
            let tx = Transaction::sign(&sk, [1u8; 32], 1, 0, n, 1, 1);
            if mp.add(tx).is_err() {
                rejected += 1;
            }
        }
        if rejected == 0 {
            vuln("per-sender limit not enforced");
        } else {
            blocked(&format!("per-sender cap enforced ({rejected}/50 rejected)"));
        }
    }

    // 9. Mempool: fee-griefing (huge declared gas_limit, never paid)
    hdr(9, "Mempool/fee: gas_limit as fake fee");
    {
        let rich = SigningKey::generate(&mut OsRng);
        let mut mp = Mempool::new(2, 100);
        // two honest txs with low gas_limit
        let h1 = Transaction::sign(&rich, [1u8; 32], 1, 1, 0, 1, 1);
        let h2 = Transaction::sign(&rich, [1u8; 32], 1, 1, 1, 1, 1);
        mp.add(h1).unwrap();
        mp.add(h2).unwrap();
        // attacker declares gas_limit = u64::MAX but balance can't cover it
        let atk = Transaction::sign(&rich, [1u8; 32], 1, u64::MAX, 2, 1, 1);
        let pushed = mp.add(atk).is_ok();
        if pushed {
            println!("  \x1b[33mNOTE\x1b[0m: gas_limit used directly as eviction fee; declared-but-unpayable gas can evict honest txs (fee model gap)");
        } else {
            blocked("unpayable gas_limit could not displace honest txs");
        }
    }

    // 10. State: transfer to non-existent with amount > cost
    hdr(10, "State: large transfer beyond balance");
    {
        let e = InMemoryStateEngine::new();
        let sk = SigningKey::generate(&mut OsRng);
        let from = sk.verifying_key().to_bytes();
        e.update_account(AccountState::new(from, 100)).await;
        let tx = Transaction::sign(&sk, [1u8; 32], 1_000_000, 0, 0, 1, 1);
        if e.apply_transaction(&tx, 0).await.is_ok() {
            let f = e.get_account(&from).await.unwrap();
            if f.balance == 100 {
                blocked("insufficient-balance tx rejected (balance intact)");
            } else {
                vuln(&format!("balance corrupted: {}", f.balance));
            }
        } else {
            blocked("insufficient balance rejected");
        }
    }

    println!("\n\x1b[1;33m############ ROUND 2 DONE ############\x1b[0m");
}
