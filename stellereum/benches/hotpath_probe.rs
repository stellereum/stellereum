//! Hot-path probe for mempool admission, the proposer payer snapshot, gossip
//! frame build and RPC batch dispatch (std-only; no criterion).
//!
//! Run in RELEASE:
//!     cargo test --release --bench hotpath_probe -- --nocapture
//!
//! REPORTS, not gates: no timing asserts, only correctness asserts, so a slow
//! machine still runs green. Every timed closure is the PRODUCTION function
//! the node calls on that path — no re-implementation lives here.
//!
//! Fixtures are Falcon-512 implicit-envelope transactions (FULL-PQ admission
//! refuses classical ones), deterministically seeded so runs are comparable.

use rayon::prelude::*;
use std::sync::OnceLock;
use std::time::Instant;
use stellereum::mempool::Mempool;
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::sharding::Transaction;
use stellereum::svm::GAS_BASIC_TRANSFER;

const BAL: u64 = 1_000_000_000_000;
const RECIPIENT: [u8; 32] = [9u8; 32];
const SENDERS: usize = 10_128;

fn pq_seed(i: u64) -> [u8; 32] {
    let mut seed = [0x62u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    seed
}

struct PqSender {
    kp: FalconKeypair,
    from: [u8; 32],
}

fn senders() -> &'static [PqSender] {
    static ONCE: OnceLock<Vec<PqSender>> = OnceLock::new();
    ONCE.get_or_init(|| {
        (0..SENDERS as u64)
            .into_par_iter()
            .map(|i| {
                let kp = FalconKeypair::generate_from_seed_bytes(&pq_seed(i));
                let from = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
                let _ = Transaction::global_implicit_registry().register(
                    from,
                    PqScheme::Falcon512,
                    &kp.public_key,
                    &DEFAULT_SALT,
                );
                PqSender { kp, from }
            })
            .collect()
    })
}

fn pq_tx(idx: usize) -> Transaction {
    let s = &senders()[idx];
    let skeleton = Transaction {
        from: s.from,
        to: RECIPIENT,
        amount: 1,
        gas_limit: GAS_BASIC_TRANSFER,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = skeleton.signing_message();
    let sig = s.kp.sign_with_seed(&msg, &pq_seed(9_000_000 + idx as u64));
    Transaction::new_pq_implicit(
        s.from,
        PqScheme::Falcon512,
        sig,
        RECIPIENT,
        1,
        GAS_BASIC_TRANSFER,
        0,
        1,
        1,
        Vec::new(),
    )
}

fn medal(nanos: f64) -> String {
    if nanos >= 1_000_000.0 {
        format!("{:.3} ms/op", nanos / 1_000_000.0)
    } else if nanos >= 1_000.0 {
        format!("{:.3} us/op", nanos / 1_000.0)
    } else {
        format!("{:.1} ns/op", nanos)
    }
}

/// Returns (median, best) in ns. The median is the headline on an idle
/// machine; the best is the robust estimator on a SHARED host (a sample that
/// was descheduled can only be slower, never faster).
fn median_ns(repeats: usize, warmup: usize, mut f: impl FnMut()) -> (f64, f64) {
    for _ in 0..warmup {
        f();
    }
    let mut v = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let t = Instant::now();
        f();
        v.push(t.elapsed().as_nanos() as f64);
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (v[v.len() / 2], v[0])
}

/// Admission throughput: `n` distinct-sender PQ transactions into a FRESH
/// pool per sample (transaction building is outside the timer).
#[test]
fn admission_plain() {
    let n = 1_000usize;
    let txs: Vec<Transaction> = (0..n).into_par_iter().map(pq_tx).collect();
    let (ns, best) = median_ns(5, 1, || {
        let mut pool = Mempool::new(n + 128, 10_000);
        for tx in txs.iter().cloned() {
            pool.add_checked(tx, BAL)
                .expect("funded admission must succeed");
        }
        assert_eq!(pool.len(), n);
    });
    println!(
        "[bench][hotpath][admission_plain] n={n:>5} time={} median, {} best ({:.1} us/tx best)",
        medal(ns),
        medal(best),
        best / n as f64 / 1_000.0,
    );
}

/// Proposer payer snapshot (`fee_payers`) over a full 10k pool — the call
/// `propose` makes once per height before the selection walk.
#[test]
fn fee_payers_snapshot() {
    let txs: Vec<Transaction> = (0..10_000).into_par_iter().map(pq_tx).collect();
    let mut pool = Mempool::new(10_128, 10_000);
    for tx in txs {
        pool.add_checked(tx, BAL)
            .expect("funded admission must succeed");
    }
    assert_eq!(pool.len(), 10_000);
    let mut payers = 0usize;
    let (ns, best) = median_ns(10, 2, || {
        payers = pool.fee_payers().len();
    });
    assert_eq!(payers, 10_000, "one distinct payer per plain tx");
    println!(
        "[bench][hotpath][fee_payers] pool=10000 payers={payers} time={} median, {} best",
        medal(ns),
        medal(best),
    );
}

// ---------------------------------------------------------------------------
// Gossip frame build (stage (a) of broadcast: dedup + encode + hex + JSON)
// ---------------------------------------------------------------------------

fn votes(n: usize) -> Vec<stellereum::consensus_net::ConsensusMsg> {
    use stellereum::consensus::{Vote, VoteKind};
    use stellereum::consensus_net::ConsensusMsg;
    (0..n)
        .map(|i| ConsensusMsg::Vote {
            vote: Vote {
                height: 42,
                round: 1,
                kind: VoteKind::Prevote,
                block_hash: Some([7u8; 32]),
                voter: [i as u8; 32],
                signature: vec![0xAB; 64],
                shard_id: 0,
            },
            locked: None,
        })
        .collect()
}

/// One proposal carrying `txs` transactions (the message whose deep clone on
/// every broadcast the borrow removes).
fn proposal_with(txs: usize) -> Vec<stellereum::consensus_net::ConsensusMsg> {
    use stellereum::consensus_net::ConsensusMsg;
    let block = stellereum::sharding::Block {
        height: 42,
        transactions: (0..txs).into_par_iter().map(pq_tx).collect(),
        ..stellereum::sharding::Block::default()
    };
    vec![ConsensusMsg::Proposal {
        height: 42,
        round: 0,
        block,
    }]
}

/// The send-time vote dedup over a live proposal chunk (production helper).
#[test]
fn gossip_dedup_proposal() {
    use stellereum::consensus_net::{coalesce_live_for_send, VoteSendFilter};
    let msgs = proposal_with(10_000);
    let mut kept = 0usize;
    let (ns, best) = median_ns(9, 1, || {
        let mut filter = VoteSendFilter::new(std::time::Duration::from_millis(200));
        let live = coalesce_live_for_send(&msgs, &mut filter, Instant::now());
        kept = live.len();
    });
    assert_eq!(kept, 1, "a proposal is never deduped away");
    println!(
        "[bench][hotpath][gossip_dedup] items=1 proposal_txs=10000 time={} median, {} best",
        medal(ns),
        medal(best),
    );
}

/// Frame build for a 32-vote chunk (production helper): batch encode + hex +
/// JSON.
#[test]
fn gossip_encode_32_votes() {
    use stellereum::consensus_net::{encode_broadcast_payload, ConsensusMsg};
    let msgs = votes(32);
    let live: Vec<std::borrow::Cow<'_, ConsensusMsg>> =
        msgs.iter().map(std::borrow::Cow::Borrowed).collect();
    let mut bytes = 0usize;
    let (ns, best) = median_ns(9, 2, || {
        let frame = encode_broadcast_payload("stellereum/consensus/v1/epoch-bench", &live)
            .unwrap_or_else(|e| panic!("frame must encode: {}", e.message()));
        bytes = frame.encoded_len;
    });
    assert!(bytes > 0);
    println!(
        "[bench][hotpath][gossip_encode] items=32 inner_bytes={bytes} time={} median, {} best",
        medal(ns),
        medal(best),
    );
}

// ---------------------------------------------------------------------------
// RPC batch dispatch
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn rt_block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime builds")
        .block_on(f)
}

fn rpc_state() -> stellereum::rpc::RpcState {
    use std::sync::Arc;
    let engine = Arc::new(stellereum::state_engine::InMemoryStateEngine::new());
    let mempool = Arc::new(tokio::sync::RwLock::new(Mempool::default()));
    stellereum::rpc::RpcState {
        engine,
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(42)),
        node_id: "inf1:bench".to_string(),
        chain_id: 777,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(
            stellereum::rpc::ReceiptIndex::default(),
        )),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    }
}

/// 64-item batch of the cheapest real method: parse + dispatch + response
/// shape per item.
#[test]
fn rpc_batch_chainid_64() {
    let st = rpc_state();
    let items: Vec<serde_json::Value> = (0..64u64)
        .map(|i| serde_json::json!({"jsonrpc": "2.0", "id": i, "method": "eth_chainId", "params": []}))
        .collect();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime builds");
    let mut answered = 0usize;
    let (ns, best) = median_ns(7, 2, || {
        // A distinct loopback peer per sample keeps the per-IP budget out of
        // the measurement (the limiter is charged per item, exactly as in
        // production).
        use std::net::{IpAddr, Ipv4Addr};
        static SAMPLE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
        let n = SAMPLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 1, (n % 250 + 1) as u8));
        let out = rt.block_on(stellereum::rpc::handle_rpc_batch_call(
            &st,
            &items,
            4096,
            None,
            Some(ip),
        ));
        let out = out.unwrap_or_else(|e| {
            panic!(
                "batch must be accepted: code {}",
                e.error.map(|x| x.code).unwrap_or(0)
            )
        });
        answered = out.iter().filter(|r| r.result.is_some()).count();
    });
    assert_eq!(answered, 64, "every item must answer");
    println!(
        "[bench][hotpath][rpc_batch_chainid] items=64 time={} median, {} best",
        medal(ns),
        medal(best),
    );
}

/// 64-item batch whose items carry a 64 KiB params blob and an unknown
/// method: the only per-item work is parse + dispatch (the params are never
/// touched), so this isolates the batch item-copy cost.
#[test]
fn rpc_batch_bigparams_64() {
    let st = rpc_state();
    let blob = "ab".repeat(32 * 1024);
    let items: Vec<serde_json::Value> = (0..64u64)
        .map(|i| {
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": i,
                "method": "stell_noSuchMethodBench",
                "params": [blob],
            })
        })
        .collect();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench runtime builds");
    let mut errors = 0usize;
    let (ns, best) = median_ns(7, 2, || {
        use std::net::{IpAddr, Ipv4Addr};
        static SAMPLE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
        let n = SAMPLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 2, (n % 250 + 1) as u8));
        let out = rt.block_on(stellereum::rpc::handle_rpc_batch_call(
            &st,
            &items,
            512_000,
            None,
            Some(ip),
        ));
        let out = out.unwrap_or_else(|e| {
            panic!(
                "batch must be accepted: code {}",
                e.error.map(|x| x.code).unwrap_or(0)
            )
        });
        errors = out.iter().filter(|r| r.error.is_some()).count();
    });
    assert_eq!(errors, 64, "unknown method must answer with an error");
    println!(
        "[bench][hotpath][rpc_batch_bigparams] items=64 params=64KiB time={} median, {} best",
        medal(ns),
        medal(best),
    );
}
