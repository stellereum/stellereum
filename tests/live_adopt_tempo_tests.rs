//! Live-adopt tempo regression (observer C, 2026-10-13).
//!
//! ВЕЩДОКИ: observer C (1 vCPU, CPUQuota 60%) принимал живые Committed-блоки по
//! ~30с/штука при пустых блоках и темпе цепи ~1 блок/с — итог ~0.3 блока/с,
//! вечное отставание. Исполнение тривиально, значит 30с — не apply, а ожидания
//! внутри тика: DHT-фетчи с таймаутами, catch-up работа поверх живого adopt'а,
//! inline-публикации (`store_blob` с ожиданием реплики) в обработчике adopt'а,
//! дорогая QC-верификация до дешёвых linkage-проверок.
//!
//! Фикс (рядом, без ломки STELL_OBSERVER / tail-anchor / fetch-семафора):
//! * живой adopt при совпадении parent — сразу: тик откладывает catch-up машину,
//!   пока в инбоксе живой трафик и гэп live-размера (`should_defer_catchup_for_live`);
//! * тяжёлые публикации adopt'а и tip-supplement — в фон (`publish_lane`), не в тике;
//! * hot path adopt'а: дешёвые проверки (proposer schedule, prev_hash, размер/газ,
//!   proposer-сигнатура) ДО дорогой QC-верификации; дубли убраны.
//!
//! Эти тесты пинят контракт, от которого зависит темп:
//! 1. чистые предикаты live-пути (`is_live_adoptable`, `should_defer_catchup_for_live`);
//! 2. порядок проверок: форкнутый коммит умирает на linkage, не на кворуме
//!    (дешёвое до дорогого — иначе каждый stale-коммит жёг Falcon-верификацию);
//! 3. темп: observer догоняет и ДЕРЖИТ цепь пустых блоков — adopt rate >= chain rate
//!    на слабом профиле (N пустых adopt'ов за бюджет, на порядок ниже N секунд цепи).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::Instant;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::Block;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::sync::{
    is_live_adoptable, should_defer_catchup_for_live, should_defer_catchup_for_live_flow,
    LIVE_ADOPT_GAP_THRESHOLD,
};

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}
fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
fn vs_of(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}

async fn observer_runtime(ks: &[SigningKey]) -> ValidatorRuntime {
    let vs = vs_of(ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, 1_000_000_000_000_000).await;
    ValidatorRuntime::new(ks[0].clone(), vs, st, 1)
}

/// Пустой блок высоты `h` для текущего рута observer'а, подписанный плановым
/// proposer'ом раунда 0, с подлинным precommit-QC (кворум 3/4).
async fn live_block_for(
    rt: &ValidatorRuntime,
    ks: &[SigningKey],
    h: u64,
    prev: [u8; 32],
) -> (Block, QuorumCertificate) {
    let vs = rt.validators.clone();
    let round = rt.hc.round;
    let proposer = vs
        .proposer_for(h, round)
        .expect("non-empty set has a proposer");
    let pk = ks.iter().find(|k| id(k) == proposer).unwrap();
    let mut b = Block {
        shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
        height: h,
        prev_hash: prev,
        state_root: rt.state.get_state_root().await,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_000 + h,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    // Canonical downtime evidence (W10.5): a live block above the genesis
    // child carries the QC that decided its parent (production
    // `decided_parent_qc`), and an adopter that knows the parent decision
    // REFUSES a block that omits it. The observer learns each height's QC
    // from the adopt itself (`last_decision`), so the evidence chains
    // forward exactly like the live network.
    if h > 1 {
        if let Some((dh, _, qc)) = rt.last_decision.clone() {
            if dh + 1 == h {
                b.last_qc = Some(qc);
            }
        }
    }
    b.sign_block(pk);
    let bh = b.compute_hash();
    let sigs = ks
        .iter()
        .take(3)
        .map(|k| {
            let v = Vote::sign(k, h, round, VoteKind::Precommit, Some(bh));
            (v.voter, v.signature)
        })
        .collect();
    let qc = QuorumCertificate {
        height: h,
        round,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: sigs,
    };
    assert!(qc.verify(&vs), "fixture QC must verify");
    (b, qc)
}

#[test]
fn live_adoptable_names_exactly_the_parent_match() {
    let ours = 41u64;
    let head = [0xABu8; 32];
    // Точное продолжение — adopt без DHT.
    assert!(is_live_adoptable(ours, head, ours, head));
    // Чужой prev — не live, только catch-up walk.
    assert!(!is_live_adoptable(ours, head, ours, [0xEEu8; 32]));
    // Чужой height — не live (вперёд — forward sync, назад — повтор).
    assert!(!is_live_adoptable(ours, head, ours + 1, head));
    assert!(!is_live_adoptable(ours, head, ours.saturating_sub(1), head));
}

#[allow(clippy::assertions_on_constants)]
// GATE: test pins protocol constants against each other; const-evaluable by design, fails usefully if a constant is ever re-tuned.
#[test]
fn catchup_defers_only_for_live_gaps_with_queued_traffic() {
    // Живой трафик + маленький гэп — drain владеет высотами, DHT молчит.
    assert!(should_defer_catchup_for_live(0, true));
    assert!(should_defer_catchup_for_live(1, true));
    assert!(should_defer_catchup_for_live(
        LIVE_ADOPT_GAP_THRESHOLD,
        true
    ));
    // Далеко позади — tip-коммиты не adopt'ятся (height mismatch), нужен walk.
    assert!(!should_defer_catchup_for_live(
        LIVE_ADOPT_GAP_THRESHOLD + 1,
        true
    ));
    assert!(!should_defer_catchup_for_live(1800, true));
    // Без живого трафика откладывать нечего — catch-up идёт по таймеру.
    assert!(!should_defer_catchup_for_live(0, false));
    assert!(!should_defer_catchup_for_live(1, false));
    // Порог — live-окно, а не окно снапшотов (100): живые догонки — единицы блоков.
    assert!(
        LIVE_ADOPT_GAP_THRESHOLD <= 64,
        "live window must stay tiny next to the snapshot window"
    );
}

/// Дефер по свежести live-adopt'а, а не только по мгновенному снимку инбокса.
///
/// Остаток инцидента 2026-10-13: старый предикат семплировал `!rx.is_empty()` в
/// одной точке тика. При темпе цепи 1 блок/с и тике 100мс ~9 тиков из 10 видят
/// пустой инбокс, пока следующий Committed ещё в транзите, — и каждые 2с тик
/// уходил в DHT-машину (`fetch_head` + walk на 1 высоту, секунды на слабой
/// связи) за высотами, которые imminent-коммит отдаёт бесплатно. Очередь живых
/// сообщений за этими сталлами и давала ~30с/блок на пустых блоках.
/// Свежий parent-match adopt доказывает, что live-поток доставляет, даже если
/// именно эта вершина тика застала пустой инбокс.
#[test]
fn catchup_defers_on_fresh_live_adopt_without_queued_traffic() {
    // Свежий adopt + live-гэп — DHT молчит, даже с пустым инбоксом (гонка закрыта).
    assert!(should_defer_catchup_for_live_flow(0, false, true));
    assert!(should_defer_catchup_for_live_flow(1, false, true));
    assert!(should_defer_catchup_for_live_flow(
        LIVE_ADOPT_GAP_THRESHOLD,
        false,
        true
    ));
    // Очередь в инбоксе деферит сама по себе (старый контракт цел).
    assert!(should_defer_catchup_for_live_flow(1, true, false));
    assert!(should_defer_catchup_for_live_flow(1, true, true));
    // Далеко позади — tip-коммиты не adopt'ятся (height mismatch), нужен walk,
    // даже если свежий adopt только что прошёл.
    assert!(!should_defer_catchup_for_live_flow(
        LIVE_ADOPT_GAP_THRESHOLD + 1,
        true,
        true
    ));
    assert!(!should_defer_catchup_for_live_flow(1800, false, true));
    // Протухший live-поток и пустой инбокс — DHT-машина идёт по расписанию.
    assert!(!should_defer_catchup_for_live_flow(0, false, false));
    assert!(!should_defer_catchup_for_live_flow(1, false, false));
}

/// Записи adopt'а держат контракт вне тика (через упорядоченную полосу).
///
/// Drain раньше `await record_adopted_block` инлайн (два конкурирующих
/// write-лока + сериализация на каждый adopt) и синхронно клал тело в sled,
/// хотя `enqueue_block` персистит те же байты. Теперь записи едут полосой
/// (тот же FIFO, что у finalize-пути). Пин контракта полосы: высоты встают
/// по порядку и видимая высота H+1 подразумевает все ранние receipts уже в
/// индексе — читатель никогда не видит высоту без её receipts.
#[tokio::test]
async fn adopted_records_keep_order_and_completeness_off_tick() {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicU64;
    use stellereum::mempool::Mempool;
    use stellereum::rpc::{ReceiptIndex, RpcState};
    use stellereum::sharding::Transaction;

    const N: u64 = 12;
    let engine = Arc::new(InMemoryStateEngine::new());
    let rpc = Arc::new(RpcState {
        engine: engine.clone(),
        mempool: Arc::new(tokio::sync::RwLock::new(Mempool::default())),
        height: Arc::new(AtomicU64::new(0)),
        node_id: "adopt-lane-test".to_string(),
        chain_id: 1,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    });

    // Полоса той же формы, что tick-полосы в main.rs: один FIFO-потребитель.
    type LaneJob = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
    let (lane_tx, mut lane_rx) = tokio::sync::mpsc::unbounded_channel::<LaneJob>();
    let consumer = tokio::spawn(async move {
        while let Some(job) = lane_rx.recv().await {
            job.await;
        }
    });

    // Чётные высоты несут по одной tx (receipts нетривиальны), нечётные пусты.
    let sk = SigningKey::generate(&mut OsRng);
    let mut expect_receipts = 0usize;
    for h in 1..=N {
        let txs: Vec<Transaction> = if h % 2 == 0 {
            expect_receipts += 1;
            vec![Transaction::sign_with_payload(
                &sk,
                [0xAAu8; 32],
                1_000,
                stellereum::svm::GAS_BASIC_TRANSFER,
                h,
                1,
                1,
                vec![],
            )]
        } else {
            vec![]
        };
        let statuses = vec![true; txs.len()];
        let fees = vec![stellereum::svm::GAS_BASIC_TRANSFER; txs.len()];
        let bh = [h as u8; 32];
        let r = rpc.clone();
        // Первая job нарочно медленная: поздние высоты не должны её обогнать.
        let slow_first = h == 1;
        lane_tx
            .send(Box::pin(async move {
                if slow_first {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                r.record_adopted_block(h, bh, &txs, &statuses, &fees, 1_000 + h)
                    .await;
            }))
            .expect("lane lives while jobs are submitted");
    }
    drop(lane_tx);
    consumer.await.expect("lane consumer runs every job");

    assert_eq!(
        rpc.height.load(std::sync::atomic::Ordering::Relaxed),
        N,
        "every adopted height must be recorded"
    );
    let rb = rpc.recent_blocks.read().await;
    let heights: Vec<u64> = rb.iter().map(|b| b.height).collect();
    assert_eq!(
        heights,
        (1..=N).rev().collect::<Vec<_>>(),
        "record_lane FIFO must preserve height order (newest first)"
    );
    drop(rb);
    let idx = rpc.receipts.read().await;
    assert_eq!(
        idx.len(),
        expect_receipts,
        "no receipt may be lost moving records off the tick"
    );
    for h in (2..=N).step_by(2) {
        assert_eq!(
            idx.for_height(h).len(),
            1,
            "height {h} must carry its receipt once its summary is visible"
        );
    }
}

/// Порядок hot path: форк умирает на linkage до QC-криптографии.
///
/// Блок с чужим prev_hash и мусорным QC при старом порядке падал на
/// "quorum" (полная Falcon/Ed-верификация), при новом — на "does not extend"
/// (два сравнения хешей). Пин */
#[tokio::test]
async fn forked_commit_dies_on_linkage_before_quorum_crypto() {
    let ks = keys(4);
    let mut rt = observer_runtime(&ks).await;
    let (mut b, _) = live_block_for(&rt, &ks, 1, [0u8; 32]).await;
    // Форк: чужой prev при нашей высоте.
    b.prev_hash = [0xEEu8; 32];
    // Мусорный QC той же формы (неверные подписи): отличить порядок можно только
    // по тексту отказа — linkage-первый код до verify не доходит.
    let garbage_qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(b.compute_hash()),
        signatures: vec![([0x11u8; 32], vec![0u8; 64]); 3],
    };
    let err = rt
        .adopt_committed(1, b, garbage_qc)
        .await
        .expect_err("forked commit must be refused");
    assert!(
        err.contains("does not extend"),
        "cheap linkage must fire before quorum crypto, got: {err}"
    );
    assert!(rt.finalized.is_empty(), "refused adopt must not advance");
}

/// Темп: observer ДЕРЖИТ цепь пустых блоков (adopt rate >= chain rate).
///
/// Цепь идёт 1 блок/с (пустые блоки, исполнение тривиально). Слабый профиль —
/// это про тик, а не про apply, поэтому тест меряет сам adopt hot path:
/// N последовательных parent-match adopt'ов должны уложиться в бюджет, на
/// порядок меньший N секунд цепи. 30с/блок регрессии здесь — это >N*30с.
#[tokio::test]
async fn observer_holds_chain_tempo_on_empty_blocks() {
    const N: u64 = 30;
    // Цепь 1 блок/с → N блоков за N секунд. Бюджет adopt'а — 10с (≥3 блока/с),
    // с запасом от флаков CI, но на два порядка строже 30с/блок (900с на N).
    const BUDGET_SECS: u64 = 10;
    let ks = keys(4);
    let mut rt = observer_runtime(&ks).await;
    let t0 = Instant::now();
    for _ in 1..=N {
        let h = rt.hc.height;
        let prev = rt.finalized.last().map(|(_, x)| *x).unwrap_or([0u8; 32]);
        // Предикат live-пути: каждый такой блок adopt'ится без DHT.
        assert!(
            is_live_adoptable(h, prev, h, prev),
            "every tempo block must be live-adoptable (parent match)"
        );
        let (b, qc) = live_block_for(&rt, &ks, h, prev).await;
        let bh = b.compute_hash();
        rt.adopt_committed(h, b, qc)
            .await
            .expect("live chain block must adopt");
        assert_eq!(rt.finalized.last().unwrap().1, bh);
    }
    let dt = t0.elapsed();
    assert_eq!(rt.finalized.len() as u64, N);
    assert!(
        dt.as_secs() < BUDGET_SECS,
        "observer must HOLD chain tempo: {N} empty adopts took {dt:?} (chain needs {N}s, budget {BUDGET_SECS}s)"
    );
    let per_block_ms = dt.as_millis() as f64 / N as f64;
    assert!(
        per_block_ms < 1_000.0,
        "adopt rate ({per_block_ms:.1}ms/block) must beat the 1 block/s chain rate"
    );
}
