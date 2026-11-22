//! LIVE ADVERSARIAL ATTACK DEMO
//! Run with: cargo run --example attack_demo
//!
//! This is not a unit test — it is an interactive penetration test that actually
//! executes attacks against the running token system and prints the defense response
//! for every attempt. It pokes: minting, double-spend, zero-address, allowance race,
//! pause, overflow, SPV forgery, snapshot tampering, and SVM atomicity.

use stellereum::cell::PatriciaTrie;
use stellereum::state_engine::{token_balance_key, InMemoryStateEngine};
use stellereum::svm::{OpCode, Svm, VmContext, VmExecutionResult};
use stellereum::token::{TokenMetadata, TokenOp, TokenRegistry, ZERO_ADDRESS};

fn addr(n: u8) -> [u8; 32] {
    [n; 32]
}

fn short(a: &[u8; 32]) -> String {
    hex::encode(&a[..4])
}

fn meta(name: &str, symbol: &str) -> TokenMetadata {
    TokenMetadata {
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: ZERO_ADDRESS,
        paused: false,
        description: String::new(),
    }
}

fn banner(title: &str) {
    println!("\n\x1b[1;36m╔══════════════════════════════════════════════════════════════╗");
    println!("║ {:<60} ║", title);
    println!("╚══════════════════════════════════════════════════════════════╝\x1b[0m");
}

fn attack(label: &str) {
    println!("\n\x1b[1;31m▶ АТАКА:\x1b[0m {}", label);
}

fn defended(msg: &str) {
    println!("  \x1b[1;32m✓ ОТРАЖЕНО:\x1b[0m {}", msg);
}

fn breached(msg: &str) {
    println!("  \x1b[1;41m✗ ПРОБОЙ:\x1b[0m {}", msg);
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    println!("\x1b[1;33m");
    println!("==================================================================");
    println!("   STELLEREUM TOKEN STANDARD — LIVE PENETRATION TEST");
    println!("   Попытка взлома в реальном времени");
    println!("==================================================================");
    println!("\x1b[0m");

    // ==================== SETUP ====================
    banner("ИНИЦИАЛИЗАЦИЯ: разворачиваем токен wUSDT");
    let engine = InMemoryStateEngine::new();
    let us = addr(0x01); // minter / владелец
    let alice = addr(0x02);
    let bob = addr(0x03);
    let attacker = addr(0xEE);

    let mut m = meta("Wrapped USDT", "wUSDT");
    m.max_supply = Some(1_000_000);
    let token_id = engine.create_token(us, m, 1_000_000).await.unwrap();

    println!("  Токен ID:      {}", short(&token_id));
    println!("  Minter (владелец): {}", short(&us));
    println!(
        "  Total supply:  {}",
        engine.token_total_supply(&token_id).await.unwrap()
    );
    println!(
        "  Баланс владельца: {}",
        engine.token_balance(&token_id, &us).await
    );
    println!(
        "  State root:    {}",
        hex::encode(&engine.get_state_root().await[..6])
    );

    // ==================== ATTACK 1 ====================
    attack("Хакер пытается начеканить себе 1 000 000 токенов (не будучи minter)");
    match engine
        .token_execute(
            &token_id,
            attacker,
            TokenOp::Mint {
                to: attacker,
                amount: 1_000_000,
            },
        )
        .await
    {
        Ok(_) => breached("хакер начеканил токены!"),
        Err(e) => {
            defended(&format!("минт отклонён: {e}"));
            let bal = engine.token_balance(&token_id, &attacker).await;
            if bal == 0 {
                println!("  Баланс хакера: {bal} (не изменился)");
            } else {
                breached("баланс хакера изменился!");
            }
        }
    }

    // ==================== ATTACK 2 ====================
    attack("Double-spend: владелец переводит 600 000, затем пытается перевести ещё 600 000");
    engine
        .token_execute(
            &token_id,
            us,
            TokenOp::Transfer {
                to: alice,
                amount: 600_000,
            },
        )
        .await
        .unwrap();
    println!("  Первый перевод 600 000 -> {} ✓", short(&alice));
    match engine
        .token_execute(
            &token_id,
            us,
            TokenOp::Transfer {
                to: bob,
                amount: 600_000,
            },
        )
        .await
    {
        Ok(_) => breached("двойная трата прошла!"),
        Err(e) => {
            defended(&format!("вторая трата отклонена: {e}"));
            println!(
                "  Баланс владельца: {}",
                engine.token_balance(&token_id, &us).await
            );
            println!(
                "  Баланс bob:       {}",
                engine.token_balance(&token_id, &bob).await
            );
        }
    }

    // ==================== ATTACK 3 ====================
    attack("Отправка токенов на ZERO_ADDRESS (сжечь в никуда без уменьшения supply)");
    let supply_before = engine.token_total_supply(&token_id).await.unwrap();
    match engine
        .token_execute(
            &token_id,
            alice,
            TokenOp::Transfer {
                to: ZERO_ADDRESS,
                amount: 100,
            },
        )
        .await
    {
        Ok(_) => breached("токены улетели на zero-address!"),
        Err(e) => {
            defended(&format!("перевод на zero-address отклонён: {e}"));
            let supply_after = engine.token_total_supply(&token_id).await.unwrap();
            if supply_before == supply_after {
                println!("  Supply сохранён: {supply_after}");
            } else {
                breached("supply изменился!");
            }
        }
    }

    // ==================== ATTACK 4 ====================
    attack("Spender пытается потратить больше allowance (approve 5000, тратит 9999)");
    engine
        .token_execute(
            &token_id,
            us,
            TokenOp::Approve {
                spender: attacker,
                amount: 5_000,
            },
        )
        .await
        .unwrap();
    match engine
        .token_execute(
            &token_id,
            attacker,
            TokenOp::TransferFrom {
                from: us,
                to: attacker,
                amount: 9_999,
            },
        )
        .await
    {
        Ok(_) => breached("превышение allowance прошло!"),
        Err(e) => {
            defended(&format!("отклонено: {e}"));
            println!(
                "  Баланс хакера: {}",
                engine.token_balance(&token_id, &attacker).await
            );
        }
    }

    // ==================== ATTACK 5 ====================
    attack("Провальный transferFrom не должен тратить allowance (атомарность)");
    // Владелец имеет ~400 000. Хакер с allowance 5 000 пытается перевести 500 000.
    let allowance_before = {
        let reg = engine.tokens_read().await;
        reg.get(&token_id).unwrap().allowance(&us, &attacker)
    };
    let res = engine
        .token_execute(
            &token_id,
            attacker,
            TokenOp::TransferFrom {
                from: us,
                to: attacker,
                amount: 500_000,
            },
        )
        .await;
    let allowance_after = {
        let reg = engine.tokens_read().await;
        reg.get(&token_id).unwrap().allowance(&us, &attacker)
    };
    if res.is_ok() {
        breached("провальный перевод прошёл!");
    } else if allowance_before == allowance_after {
        defended(&format!(
            "отклонено ({}) и allowance сохранён: {} == {}",
            res.unwrap_err(),
            allowance_before,
            allowance_after
        ));
    } else {
        breached(&format!(
            "allowance испорчен: {allowance_before} -> {allowance_after}"
        ));
    }

    // ==================== ATTACK 6 ====================
    attack("Обход pause: владелец ставит pause, хакер пытается двигать токены");
    engine
        .token_execute(&token_id, us, TokenOp::Pause)
        .await
        .unwrap();
    println!("  Токен поставлен на паузу");
    match engine
        .token_execute(
            &token_id,
            alice,
            TokenOp::Transfer {
                to: bob,
                amount: 10,
            },
        )
        .await
    {
        Ok(_) => breached("перевод прошёл во время паузы!"),
        Err(e) => {
            defended(&format!("перевод заблокирован: {e}"));
            // хакер не может снять паузу
            match engine
                .token_execute(&token_id, attacker, TokenOp::Unpause)
                .await
            {
                Ok(_) => breached("хакер снял паузу!"),
                Err(e2) => defended(&format!("снятие паузы хакером отклонено: {e2}")),
            }
        }
    }
    engine
        .token_execute(&token_id, us, TokenOp::Unpause)
        .await
        .unwrap();

    // ==================== ATTACK 7 ====================
    attack("Overflow: попытка начеканить больше max_supply (1 000 000)");
    // Сейчас supply = 1 000 000 (cap). Любой минт должен упасть.
    match engine
        .token_execute(&token_id, us, TokenOp::Mint { to: us, amount: 1 })
        .await
    {
        Ok(_) => breached("превышение cap прошло!"),
        Err(e) => defended(&format!("минт сверх cap отклонён: {e}")),
    }

    // ==================== ATTACK 8 ====================
    attack("Подделка SPV-пруфа: вредоносная нода заявляет ложный баланс");
    // Дадим bob реальный баланс, чтобы запись существовала в три
    engine
        .token_execute(
            &token_id,
            alice,
            TokenOp::Transfer {
                to: bob,
                amount: 42_000,
            },
        )
        .await
        .unwrap();
    let root = engine.get_state_root().await;
    let bob_key = token_balance_key(&token_id, &bob);
    let proof = engine
        .get_token_balance_proof(&token_id, &bob)
        .await
        .unwrap();
    let real_balance = engine.token_balance(&token_id, &bob).await;
    println!("  Реальный баланс bob: {real_balance}");
    let real_ok =
        PatriciaTrie::verify_merkle_proof(&root, &bob_key, &real_balance.to_be_bytes(), &proof);
    let fake_ok =
        PatriciaTrie::verify_merkle_proof(&root, &bob_key, &999_999_999u64.to_be_bytes(), &proof);
    if real_ok && !fake_ok {
        defended("настоящий баланс подтверждён, поддельный (999 999 999) ОТКЛОНЁН");
    } else {
        breached("SPV-пруф принял подделку!");
    }
    // Известное ограничение: баланс 0 не хранится в три (запись прунится),
    // поэтому non-inclusion proof для пустого аккаунта не поддерживается.
    let empty = addr(0x77);
    if engine
        .get_token_balance_proof(&token_id, &empty)
        .await
        .is_none()
    {
        println!("  \x1b[33mℹ замечание:\x1b[0m для нулевого баланса пруф отсутствует (non-inclusion не реализован)");
    }

    // ==================== ATTACK 9 ====================
    attack("Атомарность SVM: токен-перевод + последующий revert");
    let mut registry = TokenRegistry::new();
    let tid = registry
        .create_token(alice, meta("Atomic", "ATM"), 1_000)
        .unwrap();
    let mut ctx = VmContext {
        sender: alice,
        balance: 10, // мало нативного баланса -> вторая операция ревертит
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        pmm: None,
        zkml_proof: None,
        timestamp: 1,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: Some(&mut registry),
        token_events: Vec::new(),
        contracts: None,
        staking: None,
        min_validator_bond: stellereum::staking::MIN_VALIDATOR_BOND,
        default_commission_bps: stellereum::staking::DEFAULT_COMMISSION_BPS,
        payouts: Vec::new(),
        oracle: None,
    };
    let ops = vec![
        OpCode::SysCallTokenTransfer {
            token_id: tid,
            to: bob,
            amount: 400,
        },
        OpCode::Transfer {
            recipient: bob,
            amount: 9_999,
        }, // revert
    ];
    let res = Svm::execute(&ops, 100_000, &mut ctx);
    if matches!(res, VmExecutionResult::Reverted(_)) {
        let a = registry.balance_of(&tid, &alice);
        let b = registry.balance_of(&tid, &bob);
        if a == 1_000 && b == 0 {
            defended(&format!(
                "VM откатился, токены НЕ двинулись (alice={a}, bob={b})"
            ));
        } else {
            breached(&format!(
                "токены сдвинулись несмотря на revert (alice={a}, bob={b})"
            ));
        }
    } else {
        breached("VM не откатился!");
    }

    // ==================== ATTACK 10 ====================
    attack("Мусорный снапшот: восстановление из битых байт");
    match engine
        .restore_token_snapshot(&[0xDE, 0xAD, 0xBE, 0xEF])
        .await
    {
        Ok(_) => breached("мусорный снапшот принят!"),
        Err(e) => {
            defended(&format!("снапшот отклонён: {e}"));
            println!(
                "  Реестр цел: {} токен(ов)",
                engine.all_token_ids().await.len()
            );
        }
    }

    // ==================== ATTACK 11 ====================
    attack("Fuzz: 10 000 случайных операций, проверка инварианта sum(balances)==supply");
    let mut reg = TokenRegistry::new();
    let mut fm = meta("Fuzz", "FZ");
    fm.max_supply = Some(1_000_000_000);
    let fid = reg.create_token(us, fm, 0).unwrap();
    let accounts: Vec<[u8; 32]> = (1..=8u8).map(addr).collect();
    let mut seed: u64 = 0xDEADBEEF;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        seed >> 33
    };
    let mut violations = 0u64;
    for _ in 0..10_000 {
        let op = next() % 6;
        let a = accounts[(next() as usize) % accounts.len()];
        let b = accounts[(next() as usize) % accounts.len()];
        let amt = next() % 1000;
        let _ = match op {
            0 => reg.execute(&fid, us, TokenOp::Mint { to: a, amount: amt }),
            1 => reg.execute(&fid, a, TokenOp::Transfer { to: b, amount: amt }),
            2 => reg.execute(
                &fid,
                a,
                TokenOp::Burn {
                    from: a,
                    amount: amt,
                },
            ),
            3 => reg.execute(
                &fid,
                a,
                TokenOp::Approve {
                    spender: b,
                    amount: amt,
                },
            ),
            4 => reg.execute(
                &fid,
                b,
                TokenOp::TransferFrom {
                    from: a,
                    to: b,
                    amount: amt,
                },
            ),
            _ => reg.execute(
                &fid,
                us,
                TokenOp::Burn {
                    from: a,
                    amount: amt,
                },
            ),
        };
        let t = reg.get(&fid).unwrap();
        let sum: u64 = t.balances.values().sum();
        if sum != t.metadata.total_supply {
            violations += 1;
        }
    }
    if violations == 0 {
        defended("10 000 операций, инвариант НИ РАЗУ не нарушен");
        let t = reg.get(&fid).unwrap();
        println!(
            "  Итог: supply={}, сумма балансов={}",
            t.metadata.total_supply,
            t.balances.values().sum::<u64>()
        );
    } else {
        breached(&format!("инвариант нарушен {violations} раз!"));
    }

    // ==================== ИТОГ ====================
    println!("\n\x1b[1;32m");
    println!("==================================================================");
    println!("   ✅ ВСЕ 11 ВЕКТОРОВ АТАК ОТРАЖЕНЫ. ПРОБОЕВ НЕ НАЙДЕНО.");
    println!("==================================================================");
    println!("\x1b[0m");
}
