//! SVM hot-path benchmarks (std-only; the repo carries no criterion dep).
//!
//! Run in RELEASE for realistic numbers:
//!     cargo test --release --bench svm_hot_path -- --nocapture
//! (`cargo bench` runs them too.) Each test prints `[bench][svm_hot_path]`
//! lines with M ops/s / ns/op for the dispatch hot path.
//!
//! What is measured, and why it is honest:
//! * `nop_cached` — the `examples/benchmark.rs` SVM section, faithfully:
//!   1,000 `Nop` x 5,000 fresh-`VmContext` executes. Same-machine
//!   before/after is the headline delta for dispatch work.
//! * `mixed_single` — one 1M-op MIXED payload (arithmetic + stack +
//!   balance + transfer) in a single execute: the streaming regime, where
//!   instruction-byte traffic dominates.
//! * `mixed_chunked` — the same mix as 1,000-op x 1,000 executes: the
//!   many-small-payloads regime, where per-call setup dominates.
//! * `empty_call` — pure per-call setup/commit overhead (empty program).
//!
//! These are REPORTS, not gates: there are no timing asserts, only
//! correctness asserts (every run must `Success` with the exact expected
//! stack top / balance / gas) - a slow machine must still be green.

use std::time::Instant;
use stellereum::staking::{DEFAULT_COMMISSION_BPS, MIN_VALIDATOR_BOND};
use stellereum::svm::{OpCode, Svm, VmContext, VmExecutionResult};
use stellereum::token::{TokenMetadata, TokenRegistry, ZERO_ADDRESS};

fn mk_ctx(balance: u64) -> VmContext<'static> {
    VmContext {
        sender: [1u8; 32],
        balance,
        orderbooks: None,
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        pmm: None,
        zkml_proof: None,
        timestamp: 1,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: None,
        token_events: Vec::new(),
        contracts: None,
        staking: None,
        min_validator_bond: MIN_VALIDATOR_BOND,
        default_commission_bps: DEFAULT_COMMISSION_BPS,
        payouts: Vec::new(),
        oracle: None,
    }
}

/// Deterministic "realistic" mix: arithmetic, stack traffic, balance reads and
/// an occasional value transfer. Every op succeeds on a bare context with a
/// funded balance; the pattern is carefully stack-neutral per 10-op window
/// (net 0) so a 1M-op run never grows the stack without bound.
fn mixed_ops(len: usize) -> Vec<OpCode> {
    let window = [
        OpCode::Push(3),
        OpCode::Push(4),
        OpCode::Add, // -> 7
        OpCode::Push(2),
        OpCode::Mul, // -> 14
        OpCode::LoadBalance,
        OpCode::Pop, // drop balance copy
        OpCode::Push(14),
        OpCode::Sub, // -> 0
        OpCode::Pop, // back to empty
    ];
    let mut v = Vec::with_capacity(len + len / 200 + 1);
    for (i, slot) in (0..len).enumerate() {
        let _ = slot;
        v.push(window[i % window.len()].clone());
        // One small transfer every 200 ops so the mix also covers a
        // balance-mutating syscall arm (1 unit from a deep balance).
        if i % 200 == 199 {
            v.push(OpCode::Transfer {
                recipient: [9u8; 32],
                amount: 1,
            });
        }
    }
    v
}

/// Median-of-`repeats` timing of `f`, returning seconds per call.
fn time_secs(repeats: usize, warmup: usize, mut f: impl FnMut()) -> f64 {
    for _ in 0..warmup {
        f();
    }
    let mut samples = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_secs_f64());
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

fn report_ops(name: &str, ops: u64, secs: f64) {
    println!(
        "[bench][svm_hot_path][{name}] {:.2}M ops/s ({:.3} ns/op, {ops} ops in {:.3?})",
        (ops as f64 / secs) / 1e6,
        secs * 1e9 / ops as f64,
        std::time::Duration::from_secs_f64(secs),
    );
}

#[test]
fn nop_cached() {
    let ops: Vec<OpCode> = std::iter::repeat_n(OpCode::Nop, 1_000).collect();
    // Warmup + correctness: exact gas for 1,000 Nops.
    {
        let mut ctx = mk_ctx(1);
        match Svm::execute(&ops, 1_000_000, &mut ctx) {
            VmExecutionResult::Success {
                gas_used,
                return_value,
                ..
            } => {
                assert_eq!(gas_used, 1_000, "1,000 Nops cost 1 gas each");
                assert_eq!(return_value, None, "no pushes, empty stack");
            }
            r => panic!("Nop program must succeed, got {r:?}"),
        }
    }
    let n = 5_000u64;
    let secs = time_secs(5, 1, || {
        for _ in 0..n {
            let mut ctx = mk_ctx(1);
            match Svm::execute(&ops, 1_000_000, &mut ctx) {
                VmExecutionResult::Success { .. } => {}
                r => panic!("Nop program must succeed, got {r:?}"),
            }
        }
    });
    report_ops("nop_cached_1000x5000", 1_000 * n, secs);
}

#[test]
fn mixed_single() {
    let ops = mixed_ops(1_000_000);
    // Correctness: stack-neutral mix ends with an empty stack; count transfers.
    {
        let mut ctx = mk_ctx(1_000_000_000);
        match Svm::execute(&ops, u64::MAX / 2, &mut ctx) {
            VmExecutionResult::Success {
                return_value,
                transfers,
                new_balance,
                ..
            } => {
                assert_eq!(return_value, None, "stack-neutral mix leaves nothing");
                assert_eq!(transfers.len(), 1_000_000 / 200, "one transfer per 200 ops");
                assert_eq!(new_balance, 1_000_000_000 - transfers.len() as u64);
            }
            r => panic!("mixed program must succeed, got {r:?}"),
        }
    }
    let total = ops.len() as u64;
    let secs = time_secs(5, 2, || {
        let mut ctx = mk_ctx(1_000_000_000);
        match Svm::execute(&ops, u64::MAX / 2, &mut ctx) {
            VmExecutionResult::Success { .. } => {}
            r => panic!("mixed program must succeed, got {r:?}"),
        }
    });
    report_ops("mixed_single_1M", total, secs);
}

#[test]
fn mixed_chunked() {
    let ops = mixed_ops(1_000);
    let total = ops.len() as u64 * 1_000;
    {
        let mut ctx = mk_ctx(1_000_000_000);
        match Svm::execute(&ops, 1_000_000, &mut ctx) {
            VmExecutionResult::Success { .. } => {}
            r => panic!("mixed chunk must succeed, got {r:?}"),
        }
    }
    let secs = time_secs(5, 2, || {
        for _ in 0..1_000 {
            let mut ctx = mk_ctx(1_000_000_000);
            match Svm::execute(&ops, 1_000_000, &mut ctx) {
                VmExecutionResult::Success { .. } => {}
                r => panic!("mixed chunk must succeed, got {r:?}"),
            }
        }
    });
    report_ops("mixed_chunked_1000x1000", total, secs);
}

/// A token registry with one funded token, as the block path wires it into
/// every payload's context (clone-commit working copy).
fn funded_registry() -> (TokenRegistry, [u8; 32]) {
    let mut reg = TokenRegistry::new();
    let creator = [7u8; 32];
    let id = reg
        .create_token(
            creator,
            TokenMetadata {
                name: "Bench".to_string(),
                symbol: "BNC".to_string(),
                decimals: 6,
                total_supply: 0,
                max_supply: None,
                minter: ZERO_ADDRESS,
                paused: false,
                description: String::new(),
            },
            1_000_000_000,
        )
        .expect("create_token succeeds");
    (reg, id)
}

#[test]
fn registry_wired_overhead() {
    // A pure-arithmetic program that never touches the registry: any delta
    // vs `empty_call` is the eager clone-commit working copy per execute.
    let ops: Vec<OpCode> = std::iter::repeat_n(OpCode::Nop, 1_000).collect();
    let (reg, _) = funded_registry();
    {
        let mut reg = reg.clone();
        let mut ctx = VmContext {
            sender: [1u8; 32],
            balance: 1,
            orderbooks: None,
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            pmm: None,
            zkml_proof: None,
            timestamp: 1,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: Some(&mut reg),
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            min_validator_bond: MIN_VALIDATOR_BOND,
            default_commission_bps: DEFAULT_COMMISSION_BPS,
            payouts: Vec::new(),
            oracle: None,
        };
        match Svm::execute(&ops, 1_000_000, &mut ctx) {
            VmExecutionResult::Success { gas_used, .. } => assert_eq!(gas_used, 1_000),
            r => panic!("must succeed, got {r:?}"),
        }
    }
    let n = 5_000u64;
    let secs = time_secs(5, 2, || {
        for _ in 0..n {
            let mut reg = reg.clone();
            let mut ctx = VmContext {
                sender: [1u8; 32],
                balance: 1,
                orderbooks: None,
                patricia_trie: None,
                session_auth: None,
                session_keys: None,
                pmm: None,
                zkml_proof: None,
                timestamp: 1,
                trades: Vec::new(),
                transfers: Vec::new(),
                token_registry: Some(&mut reg),
                token_events: Vec::new(),
                contracts: None,
                staking: None,
                min_validator_bond: MIN_VALIDATOR_BOND,
                default_commission_bps: DEFAULT_COMMISSION_BPS,
                payouts: Vec::new(),
                oracle: None,
            };
            match Svm::execute(&ops, 1_000_000, &mut ctx) {
                VmExecutionResult::Success { .. } => {}
                r => panic!("must succeed, got {r:?}"),
            }
        }
    });
    // Note: `reg.clone()` in the loop is the HARNESS cloning to give each
    // call a fresh registry (the engine does the same per tx); the reported
    // number therefore includes one harness clone + the VM's working-copy
    // clone. Compare against `empty_call` + a bare 1,000-Nop run.
    println!(
        "[bench][svm_hot_path][registry_wired_1000nop] {:.1} ns/call ({n} calls, 1-token registry wired)",
        secs * 1e9 / n as f64,
    );
}

#[test]
fn empty_call() {
    let ops: Vec<OpCode> = vec![];
    {
        let mut ctx = mk_ctx(1);
        match Svm::execute(&ops, 1_000_000, &mut ctx) {
            VmExecutionResult::Success { gas_used, .. } => assert_eq!(gas_used, 0),
            r => panic!("empty program must succeed, got {r:?}"),
        }
    }
    let n = 50_000u64;
    let secs = time_secs(5, 2, || {
        for _ in 0..n {
            let mut ctx = mk_ctx(1);
            match Svm::execute(&ops, 1_000_000, &mut ctx) {
                VmExecutionResult::Success { .. } => {}
                r => panic!("empty program must succeed, got {r:?}"),
            }
        }
    });
    println!(
        "[bench][svm_hot_path][empty_call] {:.1} ns/call ({n} calls)",
        secs * 1e9 / n as f64,
    );
}
