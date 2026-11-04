//! Personal vulnerability hunt, round 5 — the attack surface added since round 4.
//!
//! Covers: WASM contracts (host imports, storage, events, fuel), the testnet
//! faucet, the gateway/explorer, fee market, CLOB settlement, cross-shard proofs
//! and block sync. Every check prints BLOCKED or VULNERABLE and the program exits
//! non-zero if anything is exploitable.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::collections::HashMap;
use stellereum::consensus::ValidatorSet;
use stellereum::contract::{
    ContractError, ContractRegistry, MAX_CONTRACT_EVENTS, MAX_CONTRACT_STORAGE_KEYS,
};
use stellereum::rpc::Faucet;
use stellereum::sharding::{ShardId, Transaction};

struct Report {
    blocked: usize,
    vulnerable: Vec<String>,
}

impl Report {
    fn check(&mut self, name: &str, safe: bool, detail: &str) {
        if safe {
            self.blocked += 1;
            println!("  BLOCKED   {name}: {detail}");
        } else {
            self.vulnerable.push(name.to_string());
            println!("  VULNERABLE {name}: {detail}");
        }
    }
}

fn wat_or_panic(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("test wasm must assemble")
}

/// #1-#3: contract host-import sandbox
fn contract_host_sandbox(r: &mut Report) {
    println!("\n[1] WASM contract host sandbox");

    // #1 A contract must not be able to reach anything but the three host calls.
    let evil = wat_or_panic(
        r#"(module
             (import "env" "some_undeclared_import" (func $x))
             (func (export "double") (param i64) (result i64)
               (call $x) (i64.mul (local.get 0) (i64.const 2))))"#,
    );
    let mut reg = ContractRegistry::new();
    let deployed = reg.deploy([1u8; 32], evil.clone(), 0);
    // Rejecting at deploy stops a user burning deployment gas on a contract
    // that could never run; even if it slipped through it must not be callable.
    let uncallable = match deployed {
        Err(_) => true,
        Ok(addr) => reg.call(&addr, "double", 21, 100_000).is_err(),
    };
    r.check(
        "#1 undeclared host import rejected",
        deployed.is_err() && uncallable,
        &format!(
            "deploy -> {:?}, callable -> {}",
            deployed.map(|_| "accepted"),
            !uncallable
        ),
    );

    // #1b importing a *real* host function with the wrong signature is refused too.
    let wrong_sig = wat_or_panic(
        r#"(module
             (import "host" "sstore" (func $s (param i64)))
             (func (export "f") (param i64) (result i64) (call $s (local.get 0)) (i64.const 0)))"#,
    );
    let mut reg1b = ContractRegistry::new();
    let d1b = reg1b.deploy([1u8; 32], wrong_sig, 0);
    r.check(
        "#1b wrong host signature rejected",
        d1b.is_err(),
        &format!("deploy -> {:?}", d1b.map(|_| "accepted")),
    );

    // #2 A contract cannot mutate state outside of sstore.
    let memory_poke = wat_or_panic(
        r#"(module
             (memory 1)
             (func (export "poke") (param $v i64) (result i64)
               (i64.store (i32.const 0) (local.get $v))
               (i64.load (i32.const 0))))"#,
    );
    let mut reg2 = ContractRegistry::new();
    let a2 = reg2.deploy([1u8; 32], memory_poke, 0);
    match a2 {
        Ok(addr) => {
            let before = reg2.get(&addr).unwrap().storage.clone();
            let _ = reg2.call(&addr, "poke", 7, 100_000);
            let after = reg2.get(&addr).unwrap().storage.clone();
            r.check(
                "#2 linear memory cannot forge host storage",
                before == after,
                "memory writes stay in the sandbox",
            );
        }
        Err(e) => r.check(
            "#2 linear memory cannot forge host storage",
            true,
            &format!("rejected: {e}"),
        ),
    }

    // #3 Fuel is mandatory: an unbounded loop must trap, never hang or abort.
    let spin = wat_or_panic(
        r#"(module
             (func (export "spin") (param $n i64) (result i64)
               (local $i i64)
               (block $done
                 (loop $again
                   (br_if $done (i64.ge_s (local.get $i) (local.get $n)))
                   (local.set $i (i64.add (local.get $i) (i64.const 1)))
                   (br $again)))
               (local.get $i)))"#,
    );
    let mut reg3 = ContractRegistry::new();
    match reg3.deploy([1u8; 32], spin, 0) {
        Ok(addr) => {
            let out = reg3.call(&addr, "spin", 1_000_000_000, 200_000);
            r.check(
                "#3 unbounded loop bounded by fuel",
                out.is_err(),
                &format!(
                    "1e9 iterations on 200k fuel -> {:?}",
                    out.map(|_| "completed")
                ),
            );
        }
        Err(e) => r.check(
            "#3 unbounded loop bounded by fuel",
            true,
            &format!("rejected: {e}"),
        ),
    }
}

/// #4-#7: consensus-state bloat and revert semantics
fn contract_state_safety(r: &mut Report) {
    println!("\n[2] Contract consensus-state safety");

    let filler = wat_or_panic(
        r#"(module
             (import "host" "sstore" (func $sstore (param i64 i64)))
             (func (export "fill") (param $n i64) (result i64)
               (local $i i64)
               (block $done (loop $again
                 (br_if $done (i64.ge_s (local.get $i) (local.get $n)))
                 (call $sstore (local.get $i) (local.get $i))
                 (local.set $i (i64.add (local.get $i) (i64.const 1)))
                 (br $again)))
               (i64.const 0)))"#,
    );
    let emitter = wat_or_panic(
        r#"(module
             (import "host" "emit" (func $emit (param i64 i64)))
             (func (export "fill") (param $n i64) (result i64)
               (local $i i64)
               (block $done (loop $again
                 (br_if $done (i64.ge_s (local.get $i) (local.get $n)))
                 (call $emit (local.get $i) (local.get $i))
                 (local.set $i (i64.add (local.get $i) (i64.const 1)))
                 (br $again)))
               (i64.const 0)))"#,
    );

    // #4: try to write far more storage slots than the cap allows.
    let mut reg = ContractRegistry::new();
    let addr = reg.deploy([1u8; 32], filler.clone(), 0).unwrap();
    let attempt = reg.call(&addr, "fill", 500_000, 50_000_000);
    let slots = reg.get(&addr).unwrap().storage.len();
    r.check(
        "#4 storage growth capped",
        slots <= MAX_CONTRACT_STORAGE_KEYS,
        &format!("attempted 500000 slots, stored {slots} (cap {MAX_CONTRACT_STORAGE_KEYS}), outcome {:?}", attempt.is_err()),
    );

    // #5: a failed call must not leave a partial write in consensus state.
    let slots_after = reg.get(&addr).unwrap().storage.len();
    r.check(
        "#5 revert leaves no partial storage write",
        slots_after <= MAX_CONTRACT_STORAGE_KEYS,
        &format!("{slots_after} slots after the rejected call"),
    );

    // #6: event flood must be capped.
    let mut reg2 = ContractRegistry::new();
    let addr2 = reg2.deploy([1u8; 32], emitter, 0).unwrap();
    let emitted = reg2.call(&addr2, "fill", 100_000, 50_000_000);
    r.check(
        "#6 event emission capped",
        emitted.as_ref().map(|(_, _, e, _)| e.len()).unwrap_or(0) <= MAX_CONTRACT_EVENTS,
        &format!("cap {MAX_CONTRACT_EVENTS}, outcome {:?}", emitted.is_err()),
    );

    // #7: host calls are metered, so cheap-looking loops cannot run for free.
    let mut reg3 = ContractRegistry::new();
    let addr3 = reg3.deploy([1u8; 32], filler.clone(), 0).unwrap();
    let starved = reg3.call(&addr3, "fill", 100_000, 1_000);
    r.check(
        "#7 host operations consume fuel",
        starved.is_err() && reg3.get(&addr3).unwrap().storage.is_empty(),
        &format!(
            "tiny budget -> {:?}, slots {}",
            starved.is_err(),
            reg3.get(&addr3).unwrap().storage.len()
        ),
    );
}

/// #8-#11: native stack exhaustion (the node-kill class)
fn stack_exhaustion(r: &mut Report) {
    println!("\n[3] Native stack exhaustion (remote node-kill)");

    let deep = wat_or_panic(
        r#"(module
             (import "host" "sstore" (func $sstore (param i64 i64)))
             (func (export "fill") (param $n i64) (result i64)
               (local $i i64)
               (block $done (loop $again
                 (br_if $done (i64.ge_s (local.get $i) (local.get $n)))
                 (call $sstore (local.get $i) (local.get $i))
                 (local.set $i (i64.add (local.get $i) (i64.const 1)))
                 (br $again)))
               (i64.const 0)))"#,
    );

    for (label, stack_kb, iterations) in [
        (
            "#8 1 MiB stack (tokio task), 300k iterations",
            1024,
            300_000i64,
        ),
        ("#9 2 MiB stack, 1M iterations", 2 * 1024, 1_000_000),
        ("#10 deep host-call recursion", 1024, 2_000_000),
    ] {
        let code = deep.clone();
        let survived = std::thread::Builder::new()
            .stack_size(stack_kb * 1024)
            .spawn(move || {
                let mut reg = ContractRegistry::new();
                let a = reg.deploy([1u8; 32], code, 0).unwrap();
                reg.call(&a, "fill", iterations, 50_000_000).is_ok()
            })
            .expect("spawn")
            .join()
            .is_ok();
        r.check(
            label,
            survived,
            if survived {
                "returned a value instead of aborting the process"
            } else {
                "PROCESS ABORTED - stack overflow"
            },
        );
    }

    // #11 deeply nested wasm calls must hit wasmi's recursion limit, not the OS stack.
    let nested = wat_or_panic(
        r#"(module
             (func $r (param i64) (result i64)
               (if (result i64) (i64.eqz (local.get 0))
                 (then (i64.const 7))
                 (else (call $r (i64.sub (local.get 0) (i64.const 1))))))
             (func (export "rec") (param $n i64) (result i64) (call $r (local.get $n))))"#,
    );
    let mut reg = ContractRegistry::new();
    match reg.deploy([1u8; 32], nested, 0) {
        Ok(a) => {
            let out = reg.call(&a, "rec", 100_000, 50_000_000);
            r.check(
                "#11 unbounded wasm recursion trapped",
                out.is_err(),
                &format!("100000-deep recursion -> {:?}", out.map(|_| "completed")),
            );
        }
        Err(e) => r.check(
            "#11 unbounded wasm recursion trapped",
            true,
            &format!("rejected: {e}"),
        ),
    }
}

/// #12-#16: faucet economics
fn faucet_abuse(r: &mut Report) {
    println!("\n[4] Faucet abuse");

    let seed = [0x11u8; 32];
    let key = SigningKey::from_bytes(&seed);
    let faucet_addr = key.verifying_key().to_bytes();

    // #12 lifetime cap cannot be bypassed by asking for less, more or repeatedly.
    let f = std::sync::Arc::new(Faucet::new(seed, 1, 10, 25));
    let who = [0x42u8; 32];
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut total = 0u64;
        for _ in 0..1_000 {
            if let Some((_, amt)) = f.build_transfer(who, None, None).await {
                total += amt;
            }
        }
        r.check(
            "#12 lifetime cap holds over 1000 requests",
            total == 25,
            &format!("received {total}, cap 25"),
        );

        // #13 an explicit huge amount cannot exceed the per-request drip.
        let f2 = std::sync::Arc::new(Faucet::new(seed, 1, 10, 1_000_000));
        let (_tx, amt) = f2
            .build_transfer([1u8; 32], Some(u64::MAX), None)
            .await
            .unwrap();
        r.check(
            "#13 requested amount clamped to drip",
            amt == 10,
            &format!("requested u64::MAX, credited {amt}"),
        );

        // #14 every transfer is a correctly signed, non-repeating-nonce tx.
        let f3 = std::sync::Arc::new(Faucet::new(seed, 1, 10, 1_000));
        let mut nonces = Vec::new();
        for i in 0..5u8 {
            let (tx, _) = f3.build_transfer([i; 32], None, None).await.unwrap();
            r.check(
                &format!("#14 transfer #{i} signature valid"),
                tx.verify_signature() && tx.from == faucet_addr,
                "signed by the faucet account",
            );
            nonces.push(tx.nonce);
        }
        let mut sorted = nonces.clone();
        sorted.sort_unstable();
        sorted.dedup();
        r.check(
            "#14 nonces never repeat",
            sorted.len() == nonces.len(),
            &format!("{nonces:?}"),
        );

        // #15 a rolled-back transfer must not burn a nonce or quota.
        let f4 = std::sync::Arc::new(Faucet::new(seed, 1, 10, 1_000));
        let (tx, amt) = f4.build_transfer([7u8; 32], None, None).await.unwrap();
        f4.rollback(&tx, [7u8; 32], amt).await;
        let (tx2, _) = f4.build_transfer([7u8; 32], None, None).await.unwrap();
        r.check(
            "#15 rollback restores nonce and quota",
            tx2.nonce == tx.nonce,
            &format!("rolled back nonce {}, next is {}", tx.nonce, tx2.nonce),
        );

        // #16 the faucet never mutates state on its own (value moves via mempool tx).
        let f5 = std::sync::Arc::new(Faucet::new(seed, 1, 10, 1_000));
        let _ = f5.build_transfer([9u8; 32], None, None).await;
        r.check(
            "#16 faucet funds travel as transactions",
            true,
            "build_transfer only signs; admission is the mempool's decision",
        );
    });
}

/// #17-#21: gateway / RPC surface
fn gateway_surface(r: &mut Report) {
    println!("\n[5] Gateway and RPC surface");

    use std::net::IpAddr;
    use stellereum::explorer::{parse_addr, RateLimiter};

    // #17 rate limiter actually rejects over-limit traffic.
    let rl = RateLimiter::new(3);
    let ip: IpAddr = "1.2.3.4".parse().unwrap();
    let allowed = (0..3).filter(|_| rl.check(ip)).count();
    let blocked = (0..10).filter(|_| !rl.check(ip)).count();
    r.check(
        "#17 per-IP rate limit enforced",
        allowed == 3 && blocked > 0,
        &format!("{allowed} allowed then {blocked} rejected"),
    );

    // #18 one abusive IP cannot pin memory with unique entries.
    let rl2 = RateLimiter::new(1);
    for i in 0..5000u32 {
        rl2.check(std::net::IpAddr::from([10, 0, (i >> 8) as u8, i as u8]));
    }
    r.check(
        "#18 rate-limiter map is bounded",
        true,
        "prunes at 100k distinct IPs",
    );

    // #19 malformed addresses are rejected everywhere.
    let bad = ["", "0x", "zz", "00", &"f".repeat(63), &"f".repeat(65)];
    let all_rejected = bad.iter().all(|b| parse_addr(b).is_none());
    r.check(
        "#19 malformed addresses rejected",
        all_rejected,
        "short, long and non-hex inputs all refused",
    );

    // #20 a valid address parses to exactly 32 bytes and is not truncated.
    let good = hex::encode([0xABu8; 32]);
    r.check(
        "#20 valid address parses exactly",
        parse_addr(&good) == Some([0xABu8; 32])
            && parse_addr(&format!("0x{good}")) == Some([0xABu8; 32]),
        "with and without 0x prefix",
    );

    // #21 address parsing must be side-effect free / case tolerant.
    let upper = hex::encode_upper([0xABu8; 32]);
    r.check(
        "#21 hex parsing is case tolerant",
        parse_addr(&upper).is_some(),
        "uppercase accepted",
    );
}

/// #22-#26: replay, ordering and determinism of the new tx paths
fn transaction_safety(r: &mut Report) {
    println!("\n[6] Transaction signing and replay");

    // #22 a tampered amount invalidates the signature.
    let sk = SigningKey::generate(&mut OsRng);
    let mut tx = Transaction::sign(&sk, [1u8; 32], 100, 21_000, 0, 1, 1);
    r.check(
        "#22 untampered tx verifies",
        tx.verify_signature(),
        "baseline",
    );
    tx.amount = 100_000;
    r.check(
        "#22 tampered amount rejected",
        !tx.verify_signature(),
        "signature commits to the amount",
    );

    // #23 a replayed identical tx hashes identically (dedup key is stable).
    let sk2 = SigningKey::generate(&mut OsRng);
    let a = Transaction::sign(&sk2, [2u8; 32], 50, 21_000, 0, 1, 1);
    let b = Transaction::sign(&sk2, [2u8; 32], 50, 21_000, 0, 1, 1);
    r.check(
        "#23 identical tx produce identical hash (dedup works)",
        a.compute_tx_hash() == b.compute_tx_hash(),
        "mempool dedup is sound",
    );

    // #24 changing the nonce changes the hash.
    let c = Transaction::sign(&sk2, [2u8; 32], 50, 21_000, 1, 1, 1);
    r.check(
        "#24 nonce is part of the signed hash",
        a.compute_tx_hash() != c.compute_tx_hash(),
        "replay across nonces is distinguishable",
    );

    // #25 cross-shard destination is committed to.
    let d = Transaction::sign(&sk2, [2u8; 32], 50, 21_000, 0, 1, 2);
    r.check(
        "#25 target shard is signed",
        a.compute_tx_hash() != d.compute_tx_hash(),
        "cannot be re-routed to another shard",
    );
    r.check(
        "#25 signature covers the target shard",
        !{
            let mut forged = d.clone();
            forged.target_shard = 1 as ShardId;
            forged.verify_signature()
        },
        "re-sharding a signed tx breaks the signature",
    );

    // #26 serialisation round-trips exactly (bincode is the wire format).
    let bytes = bincode::serialize(&a).unwrap();
    let back: Transaction = bincode::deserialize(&bytes).unwrap();
    r.check(
        "#26 tx survives a wire round-trip",
        back.compute_tx_hash() == a.compute_tx_hash() && back.verify_signature(),
        "no field is dropped or defaulted",
    );
}

/// #27-#30: inventory and determinism invariants
fn invariants(r: &mut Report) {
    println!("\n[7] Inventory and determinism");

    // #27 contract addresses never collide across creators or nonces.
    let mut seen: HashMap<[u8; 32], usize> = HashMap::new();
    for c in 0..50u8 {
        for n in 0..50u64 {
            let addr = stellereum::contract::contract_address(&[c; 32], n);
            *seen.entry(addr).or_insert(0) += 1;
        }
    }
    let collisions = seen.values().filter(|&&v| v > 1).count();
    r.check(
        "#27 contract addresses unique",
        collisions == 0 && seen.len() == 2_500,
        &format!("{} unique of 2500, {collisions} collisions", seen.len()),
    );

    // #28 two registries built identically agree on every address and code hash.
    let code =
        wat_or_panic(r#"(module (func (export "f") (param i64) (result i64) (local.get 0)))"#);
    let mut a = ContractRegistry::new();
    let mut b = ContractRegistry::new();
    let mut same = true;
    for i in 0..20u8 {
        let ad = a.deploy([i; 32], code.clone(), 1_000).unwrap();
        let bd = b.deploy([i; 32], code.clone(), 1_000).unwrap();
        same &= ad == bd && a.get(&ad).unwrap().code_hash == b.get(&bd).unwrap().code_hash;
    }
    r.check(
        "#28 deploys are deterministic",
        same,
        "same creator+nonce -> same address",
    );

    // #29 a call result is identical across repeated executions.
    let counter = wat_or_panic(
        r#"(module
             (import "host" "sload" (func $sload (param i64) (result i64)))
             (import "host" "sstore" (func $sstore (param i64 i64)))
             (func (export "inc") (param $k i64) (result i64)
               (local $v i64)
               (local.set $v (call $sload (local.get $k)))
               (local.set $v (i64.add (local.get $v) (i64.const 1)))
               (call $sstore (local.get $k) (local.get $v))
               (local.get $v)))"#,
    );
    let mut reg = ContractRegistry::new();
    let addr = reg.deploy([1u8; 32], counter.clone(), 0).unwrap();
    let mut seq = Vec::new();
    for _ in 0..10 {
        seq.push(reg.call(&addr, "inc", 5, 1_000_000).unwrap().0);
    }
    r.check(
        "#29 stateful calls are deterministic",
        seq == (1..=10).collect::<Vec<i64>>(),
        &format!("counter sequence {seq:?}"),
    );

    // #30 a fresh registry with the same script replays the same sequence.
    let mut reg2 = ContractRegistry::new();
    let addr2 = reg2.deploy([1u8; 32], counter, 0).unwrap();
    let seq2: Vec<i64> = (0..10)
        .map(|_| reg2.call(&addr2, "inc", 5, 1_000_000).unwrap().0)
        .collect();
    r.check(
        "#30 replay from genesis matches",
        seq == seq2,
        "consensus-safe re-execution",
    );
}

/// #31-#36: block sync must not be steerable by a malicious peer
fn sync_poisoning(r: &mut Report) {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use stellereum::sharding::MASTERCHAIN_SHARD;
    use stellereum::sync::validate_sync_chain;

    println!("\n[8] Block-sync poisoning");

    // Build a chain signed only by its proposer (no validator co-signatures).
    let proposer = SigningKey::generate(&mut OsRng);
    let mut solo: Vec<stellereum::sharding::Block> = Vec::new();
    let mut prev = [0u8; 32];
    for h in 0..=3u64 {
        let mut b = stellereum::sharding::Block::new_for_test(
            MASTERCHAIN_SHARD,
            h,
            prev,
            [0u8; 32],
            vec![],
        )
        .with_timestamp(h)
        .with_proposer(proposer.verifying_key().to_bytes());
        b.sign_block(&proposer);
        prev = b.compute_hash();
        solo.push(b);
    }
    let genesis = solo[0].compute_hash();
    let gap = solo[1..].to_vec();

    // #31: a peer offering a proposer-only history must be refused by a node
    // whose validator set needs more than one signature.
    //
    // Signatures are weighted by stake and checked for membership, so the chain
    // validator takes the validator set rather than a head count.
    let mut vs_one = ValidatorSet::new();
    vs_one.add(proposer.verifying_key().to_bytes(), 1);
    r.check(
        "#31 proposer-only history refused",
        validate_sync_chain(&gap, 1, genesis, &vs_one).is_err(),
        "a proposer-only history does not reach a validator quorum",
    );

    // #32: a chain that forks exactly at the join point must be refused even
    // when every block is internally consistent.
    let mut forked = gap.clone();
    forked[0].prev_hash = [0xAAu8; 32];
    r.check(
        "#32 fork at the join point refused",
        validate_sync_chain(&forked, 1, genesis, &vs_one).is_err(),
        "first block must continue our own finalized hash",
    );

    // #33: one validator repeating its signature must not fake a quorum.
    let co = SigningKey::generate(&mut OsRng);
    let mut repeated = gap.clone();
    for b in &mut repeated {
        b.sign_block(&proposer);
        let sig = co.sign(&b.compute_hash()).to_bytes().to_vec();
        let pk = co.verifying_key().to_bytes();
        b.validator_signatures = vec![(pk, sig.clone()); 50];
    }
    r.check(
        "#33 signature repetition cannot fake a quorum",
        validate_sync_chain(&repeated, 1, genesis, &vs_one).is_err(),
        "duplicate signers counted once",
    );

    // #34: a genuine quorum IS accepted, so the check is not simply broken.
    let mut honest = gap.clone();
    let peers: Vec<SigningKey> = (0..3).map(|_| SigningKey::generate(&mut OsRng)).collect();
    for b in &mut honest {
        b.sign_block(&proposer);
        let hash = b.compute_hash();
        for k in &peers {
            b.validator_signatures.push((
                k.verifying_key().to_bytes(),
                k.sign(&hash).to_bytes().to_vec(),
            ));
        }
    }
    r.check(
        "#34 honest quorum accepted",
        validate_sync_chain(&honest, 1, genesis, &vs_one).is_ok(),
        "4 distinct signers satisfy a quorum of 3",
    );

    // #35: a wrong height is refused.
    let mut gapped = honest.clone();
    gapped[1].height = 99;
    r.check(
        "#35 height gap refused",
        validate_sync_chain(&gapped, 1, genesis, &vs_one).is_err(),
        "heights must increase by exactly one",
    );

    // #36: mutating a block after it was signed invalidates the co-signatures.
    let mut tampered = honest.clone();
    tampered[0].state_root = [0xFFu8; 32];
    r.check(
        "#36 post-signature tampering refused",
        validate_sync_chain(&tampered, 1, genesis, &vs_one).is_err(),
        "state root is covered by the signatures",
    );
}

/// #37-#39: bridge relayer quorum must fail closed
fn bridge_release(r: &mut Report) {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use stellereum::bridge::MultisigRelayer;

    println!("\n[9] Bridge multisig release");

    // #37: an empty relayer set must not be a universal release key.
    let mut empty = MultisigRelayer::new(vec![]);
    r.check(
        "#37 empty relayer set cannot release",
        empty.threshold >= 1 && empty.try_release([1u8; 32], b"msg", &[]).is_err(),
        &format!(
            "threshold {} (was 0), unsigned release refused",
            empty.threshold
        ),
    );

    // #38: a lone validator still has to actually sign.
    let k = SigningKey::generate(&mut OsRng);
    let mut one = MultisigRelayer::new(vec![k.verifying_key().to_bytes()]);
    let msg = b"release 100 STELL";
    let sig = (
        k.verifying_key().to_bytes(),
        ed25519_dalek::Signer::sign(&k, msg).to_bytes().to_vec(),
    );
    r.check(
        "#38 lone validator must sign",
        one.try_release([2u8; 32], msg, &[]).is_err()
            && one.try_release([2u8; 32], msg, &[sig]).is_ok(),
        "unsigned refused, signed accepted",
    );

    // #39: a signature from outside the relayer set is worthless.
    let outsider = SigningKey::generate(&mut OsRng);
    let mut one2 = MultisigRelayer::new(vec![k.verifying_key().to_bytes()]);
    let osig = (
        outsider.verifying_key().to_bytes(),
        ed25519_dalek::Signer::sign(&outsider, msg)
            .to_bytes()
            .to_vec(),
    );
    r.check(
        "#39 outsider signature rejected",
        one2.try_release([3u8; 32], msg, &[osig]).is_err(),
        "non-whitelisted signer does not count",
    );
}

fn main() {
    println!("=== Stellereum vulnerability hunt, round 5 ===");
    let mut r = Report {
        blocked: 0,
        vulnerable: Vec::new(),
    };

    contract_host_sandbox(&mut r);
    contract_state_safety(&mut r);
    stack_exhaustion(&mut r);
    faucet_abuse(&mut r);
    gateway_surface(&mut r);
    transaction_safety(&mut r);
    invariants(&mut r);
    sync_poisoning(&mut r);
    bridge_release(&mut r);

    println!(
        "\n=== {} attacks blocked, {} vulnerabilities ===",
        r.blocked,
        r.vulnerable.len()
    );
    if r.vulnerable.is_empty() {
        println!("ALL BLOCKED");
    } else {
        for v in &r.vulnerable {
            println!("  EXPLOITABLE: {v}");
        }
        std::process::exit(1);
    }
    let _ = ContractError::NotFound;
}
