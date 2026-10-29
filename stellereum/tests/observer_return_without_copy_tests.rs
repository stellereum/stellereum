//! Возврат вылетевшей observer-ноды БЕЗ ручного копирования дата-директорий.
//!
//! Живой случай: observer C (1vCPU/60%/2G) со stale-данными — state ~77k с
//! леджером БЕЗ собственного бонда 81821 — против живого типа ~93k. Ручной
//! `cp -a data` через ssh запрещён: чужой стор несёт чужой genesis-фингерпринт
//! и раскалывает цепь тихо.
//!
//! Процедура (каждый переход с честной проверкой, см. OPERATIONS §10):
//!
//! ```text
//!   Stage 0  чистая дата: genesis-движок, ничего не скопировано.
//!   Stage 1  snapshot: state + ВСЕ домены С БОНДОМ с границы (latest-pointer
//!            first, затем %100 вниз), tail-anchored (gap>50 → trailing window).
//!   Stage 2  tail-anchor: HeaderLink-окно QC-проверено под НАШ committed set.
//!   Stage 3  walk: тела остатка, QC на каждой высоте, parent-root до apply.
//!   Stage 4  live: консенсус владеет типом (franchise через свежий леджер).
//! ```
//!
//! Этот файл доказывает ТЕСТОМ: слабая нода (дропы/таймауты) от генезиса до
//! типа ТОЛЬКО протоколом — как `node_bootstrap_tests`, но со СТАРЫМ леджером
//! в стартовой точке (аналог C: первый доменный блоб — настоящий, но
//! до-бондовый, декодируется и ОБЯЗАН быть отвергнут, затем свежий чинит сет).
//!
//! Слои, которые реально едут (единственный фейк — транспорт):
//! `fast_sync_state`, `verify_snapshot_anchor(_tail)`, `collect_missing_blocks`,
//! `validate_sync_chain_for_shard`, `bootstrap::{select_bootstrap_boundary,
//! next_boundary_after_stale}`, `ValidatorRuntime::refresh_*` (stale-gate).
//! Счётчики доказывают, что прогон был по-настоящему враждебным.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use stellereum::bootstrap;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::sync::{
    collect_missing_blocks, fast_sync_state, validate_sync_chain_for_shard, verify_snapshot_anchor,
    verify_snapshot_anchor_tail, HeaderLink,
};

// Масштаб уменьшен против живых 77k/93k, но отношения сохранены:
// леджер-лаг stale (400) > кольца свежести 300, gap (650) > tail-порога 50,
// остаток после снапшота (50) внутри KEEP-окна 150.
const TIP: u64 = 650;
const KEEP: u64 = 150;
const BOND_HEIGHT: u64 = 350;
const STALE_LEDGER_HEIGHT: u64 = 200; // до-бондовый доменный снапшот
const BOUNDARY: u64 = 600; // новейшая %100-граница под типом

fn effect_account(h: u64) -> [u8; 32] {
    let mut addr = [0u8; 32];
    addr[0..8].copy_from_slice(&h.to_le_bytes());
    addr[8] = 0x0B;
    addr
}

fn effect_balance(h: u64) -> u64 {
    1_000_000 + h * 7
}

fn observer_keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn observer_vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn attach_quorum(b: &mut Block, ks: &[SigningKey], height: u64, bh: [u8; 32]) {
    let sigs = ks
        .iter()
        .map(|k| {
            let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(bh));
            (v.voter, v.signature)
        })
        .collect();
    b.precommit_qc = Some(QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: sigs,
    });
}

struct LiveChain {
    blocks: Vec<Block>,
    snapshots: HashMap<u64, Vec<u8>>,
    domains: HashMap<u64, Vec<u8>>,
    roots: HashMap<u64, [u8; 32]>,
}

/// Живая цепь с бондом C в середине: кто восстановится без доменного блоба
/// С бондом — восстановит ЧУЖОЙ сет (ловушка ноды C).
async fn build_live_chain(
    ks: &[SigningKey],
    bonded: &SigningKey,
    tip: u64,
    bond_at: u64,
) -> (LiveChain, InMemoryStateEngine) {
    let vs = observer_vset(ks);
    let engine = InMemoryStateEngine::new();
    let mut blocks = Vec::new();
    let mut snapshots = HashMap::new();
    let mut domains = HashMap::new();
    let mut roots = HashMap::new();
    roots.insert(0, engine.get_state_root().await);
    let mut prev = [0u8; 32];
    for h in 1..=tip {
        let root_before = engine.get_state_root().await;
        let proposer_id = vs.proposer_for(h, 0).expect("non-empty set has a proposer");
        let proposer = ks
            .iter()
            .find(|k| k.verifying_key().to_bytes() == proposer_id)
            .expect("proposer is a member")
            .clone();
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: root_before,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_000 + h,
            proposer: proposer.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(&proposer);
        let bh = b.compute_hash();
        attach_quorum(&mut b, ks, h, bh);
        prev = bh;
        blocks.push(b);
        engine
            .update_account(AccountState::new(effect_account(h), effect_balance(h)))
            .await;
        if h == bond_at {
            let id = bonded.verifying_key().to_bytes();
            engine
                .credit_native(&id, 100_000 * 1_000_000_000)
                .await
                .expect("faucet credit must apply");
            engine
                .staking_write()
                .await
                .bond(id, 5 * stellereum::staking::MIN_VALIDATOR_BOND, 0)
                .expect("mid-chain bond must apply");
        }
        roots.insert(h, engine.get_state_root().await);
        if h % 100 == 0 {
            snapshots.insert(h, engine.create_snapshot().await);
            let staking = engine.staking_read().await.clone();
            let gov = engine.governance_read().await.clone();
            let dom = stellereum::storage::DomainSnapshot::capture(&engine, &staking, &gov).await;
            domains.insert(h, bincode::serialize(&dom).unwrap());
        }
    }
    (
        LiveChain {
            blocks,
            snapshots,
            domains,
            roots,
        },
        engine,
    )
}

/// Транспорт-фальшивка: принированная (KEEP), слабая (миссы/таймауты) и
/// один раз НЕЧЕСТНАЯ по-старому (serve настоящего, но ДО-бондового блоба).
/// Каждый враждебный эпизод считается — прогон без единого мисса не доказывает
/// ничего.
struct FlakyPeers<'a> {
    chain: &'a LiveChain,
    tip: u64,
    keep: u64,
    snapshot_misses_left: Arc<AtomicU64>,
    header_misses_left: Arc<AtomicU64>,
    /// Сколько раз отдать СТАРЫЙ (до-бондовый, декодируемый) domains-блоб
    /// вместо свежего: он обязан быть ОТВЕРГНУТ, никогда не закоммичен.
    stale_domains_left: Arc<AtomicU64>,
    flaked_bodies: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
    n_snapshot_miss: Arc<AtomicU64>,
    n_header_miss: Arc<AtomicU64>,
    n_stale_domain: Arc<AtomicU64>,
    n_body_miss: Arc<AtomicU64>,
}

impl<'a> FlakyPeers<'a> {
    fn retained(&self, h: u64) -> bool {
        h > self.tip.saturating_sub(self.keep)
    }

    fn link_at(&self, h: u64) -> Option<HeaderLink> {
        if self
            .header_misses_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            self.n_header_miss.fetch_add(1, Ordering::SeqCst);
            return None; // таймаут слабой связи: ретрай, никогда доверие
        }
        if h == 0 || h > self.tip || !self.retained(h) {
            return None;
        }
        let b = self.chain.blocks.get(h as usize - 1)?;
        if b.height != h {
            return None;
        }
        Some(HeaderLink {
            height: b.height,
            block_hash: b.compute_hash(),
            prev_hash: b.prev_hash,
            state_root: b.state_root,
            proposer: b.proposer,
            qc: b.precommit_qc.clone()?,
        })
    }

    fn snapshot_at(&self, h: u64) -> Option<Vec<u8>> {
        if self
            .snapshot_misses_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            self.n_snapshot_miss.fetch_add(1, Ordering::SeqCst);
            return None; // мисс/таймаут: честный ретрай той же границы
        }
        self.chain.snapshots.get(&h).cloned()
    }

    fn domain_at(&self, h: u64, kind: &str) -> Option<Vec<u8>> {
        if kind != "domains" {
            return None; // эта цепь упражняет только accounts + леджер
        }
        if self
            .stale_domains_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            self.n_stale_domain.fetch_add(1, Ordering::SeqCst);
            // НАСТОЯЩИЙ, но СТАРЫЙ блоб (до бонда): декодируется, но обязан
            // быть отвергнут и корневой проверкой, и свежестным гейтом.
            // Это и есть стартовая точка ноды C.
            return self.chain.domains.get(&STALE_LEDGER_HEIGHT).cloned();
        }
        self.chain.domains.get(&h).cloned()
    }

    fn body_at(&self, hash: &[u8; 32]) -> Option<Block> {
        {
            let mut flaked = self.flaked_bodies.lock().unwrap();
            if !flaked.contains(hash) {
                flaked.insert(*hash);
                self.n_body_miss.fetch_add(1, Ordering::SeqCst);
                return None; // первый спрос каждого тела роняется
            }
        }
        let b = self
            .chain
            .blocks
            .iter()
            .find(|b| b.compute_hash() == *hash)?
            .clone();
        if !self.retained(b.height) {
            return None;
        }
        (b.compute_hash() == *hash).then_some(b)
    }
}

fn flaky_peers<'a>(
    chain: &'a LiveChain,
    snapshot_misses: u64,
    header_misses: u64,
    stale_domains: u64,
) -> FlakyPeers<'a> {
    FlakyPeers {
        chain,
        tip: TIP,
        keep: KEEP,
        snapshot_misses_left: Arc::new(AtomicU64::new(snapshot_misses)),
        header_misses_left: Arc::new(AtomicU64::new(header_misses)),
        stale_domains_left: Arc::new(AtomicU64::new(stale_domains)),
        flaked_bodies: std::sync::Mutex::new(std::collections::HashSet::new()),
        n_snapshot_miss: Arc::new(AtomicU64::new(0)),
        n_header_miss: Arc::new(AtomicU64::new(0)),
        n_stale_domain: Arc::new(AtomicU64::new(0)),
        n_body_miss: Arc::new(AtomicU64::new(0)),
    }
}

/// Сквозной критерий: чистая дата → snapshot С бондом → tail-anchor → walk →
/// live, только протоколом, со stale-леджером в стартовой точке, по слабой
/// связи. Каждый переход с честной проверкой.
#[tokio::test]
async fn stale_observer_returns_via_protocol_only_no_copy() {
    let ks = observer_keys(2);
    let bonded = SigningKey::generate(&mut OsRng);
    let bonded_id = bonded.verifying_key().to_bytes();
    let vs = observer_vset(&ks);
    let (chain, source_engine) = build_live_chain(&ks, &bonded, TIP, BOND_HEIGHT).await;
    let source_tip_root = source_engine.get_state_root().await;
    assert!(
        source_engine
            .staking_read()
            .await
            .to_validator_set()
            .power_of(&bonded_id)
            > 0,
        "источник обязан нести бонд середины цепи, иначе половина про леджер ничего не доказывает"
    );
    // Старый блоб реален и до-бондов: без бонда внутри.
    {
        let stale_bytes = chain
            .domains
            .get(&STALE_LEDGER_HEIGHT)
            .expect("stale boundary snapshot");
        let snap: stellereum::storage::DomainSnapshot =
            bincode::deserialize(stale_bytes).expect("stale blob decodes");
        assert!(
            snap.staking.to_validator_set().power_of(&bonded_id) == 0,
            "стартовая точка обязана быть БЕЗ бонда (как C: леджер старее 81821)"
        );
        let fresh_bytes = chain
            .domains
            .get(&BOUNDARY)
            .expect("fresh boundary snapshot");
        let fresh: stellereum::storage::DomainSnapshot =
            bincode::deserialize(fresh_bytes).expect("fresh blob decodes");
        assert!(
            fresh.staking.to_validator_set().power_of(&bonded_id) > 0,
            "свежий блоб границы обязан нести бонд"
        );
    }

    let peers = flaky_peers(&chain, 2, 3, 1);

    // --- Stage 0: чистая дата. Наблюдатель стартует с генезиса, ни байта не
    // скопировано: единственные входы дальше — fetched-блобы, каждый проверен
    // до коммита. ---
    let observer_engine = InMemoryStateEngine::new();
    assert_eq!(
        observer_engine.get_state_root().await,
        InMemoryStateEngine::new().get_state_root().await,
        "наблюдатель обязан стартовать с генезиса, а не с копии"
    );

    // --- Stage 0.5: stale-стартовая точка на уровне сета. Рантайм с
    // конфиг-сетом {A,B} видит леджер 200 при стейте 600: лаг 400 > кольца
    // 300 → STALE, fail-closed в observer без голосов (как C). ---
    {
        let stale_rt_engine = Arc::new(InMemoryStateEngine::new());
        let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), stale_rt_engine, 1);
        let stale_ledger = {
            let stale_bytes = chain.domains.get(&STALE_LEDGER_HEIGHT).unwrap();
            let snap: stellereum::storage::DomainSnapshot =
                bincode::deserialize(stale_bytes).unwrap();
            snap.staking
        };
        let changed = rt
            .refresh_validator_set_from_ledger(&stale_ledger, BOUNDARY, STALE_LEDGER_HEIGHT)
            .await;
        assert!(!changed, "протухший сет нельзя устанавливать");
        assert!(
            rt.is_validator_set_stale(),
            "лаг 400 при кольце 300 обязан выставить STALE"
        );
        assert!(
            !rt.effective_can_vote(true),
            "stale: даже конфиг-валидатор не голосует — честный observer"
        );
        // А свежий доменный блоб (тем же сетевым путём) чинит сет отдельно
        // от блоков — ремонт без единого replay древнего бонда.
        let fresh_bytes = loop {
            if let Some(b) = peers.domain_at(BOUNDARY, "domains") {
                // Первый fetch отдаёт СТАРЫЙ блоб: отбрасываем его здесь же
                // (свежестный гейт ниже его не примет) и повторяем спрос —
                // честный ретрай, а не пропуск.
                let probe_rt_engine = Arc::new(InMemoryStateEngine::new());
                let mut probe =
                    ValidatorRuntime::new(ks[0].clone(), vs.clone(), probe_rt_engine, 1);
                match probe
                    .refresh_validator_set_from_domain_bytes(&b, BOUNDARY, BOUNDARY)
                    .await
                {
                    Ok(true) => break b, // свежий и меняющий — наш кандидат
                    Ok(false) => {
                        // Либо свежий-без-изменений, либо STALE. Различаем по
                        // флагу: STALE продолжаем ретраить, свежий-равный —
                        // тоже пропускаем (нам нужен меняющий).
                        continue;
                    }
                    Err(_) => continue,
                }
            }
        };
        // Детерминированно: после одного stale — свежий блоб границы.
        // Возвращаем один stale для Stage 3: отклонение протухшего бандла
        // обязано проверяться и на пути set-only, и на пути fast-sync.
        peers.stale_domains_left.store(1, Ordering::SeqCst);
        let installed = rt
            .refresh_validator_set_from_domain_bytes(&fresh_bytes, BOUNDARY, BOUNDARY)
            .await
            .expect("свежие домены обязаны декодироваться");
        // Свежий леджер {A,B}→{A,B} на уровне конфиг-сета может не менять сет
        // (бонд C — вне конфиг-сета: to_validator_set его видит, а рантайм
        // ставит поверх конфига). Главное — stale снят протоколом, без cp.
        let _ = installed;
        assert!(
            !rt.is_validator_set_stale(),
            "свежий доменный снапшот по протоколу обязан снять STALE"
        );
    }

    // --- Stage 1: план. Реальный bootstrap-планер: новейшая граница под
    // типом (gap 650 > 100 → снапшот нужен), stale-бюджет держит ретрай той
    // же границы. ---
    let boundary = bootstrap::select_bootstrap_boundary(TIP, 0, Some(BOUNDARY))
        .expect("цепь с типом 650 обязана предложить границу");
    assert_eq!(boundary, BOUNDARY);
    assert_eq!(
        bootstrap::next_boundary_after_stale(boundary, 1, 0),
        Some(boundary),
        "один stale обязан ретраить ТУ ЖЕ границу, а не бросать её"
    );

    // --- Stage 2: tail-anchor поверх дропающихся заголовков. Полный проход
    // от генезиса ОБЯЗАН упасть (история принирована: gap 650 > KEEP 150) —
    // иначе tail-окно не нужно было бы. Окно 8 высот целиком внутри ретеншна.
    // ---
    let full = verify_snapshot_anchor(None, [0u8; 32], boundary + 1, &vs, 1_000_000, |h| {
        let l = peers.link_at(h);
        async move { l }
    })
    .await;
    assert!(
        full.is_err(),
        "полный проход от генезиса обязан упасть на принированных пирах — иначе инцидент невозможен"
    );
    let mut trusted = None;
    for _ in 0..25 {
        match verify_snapshot_anchor_tail(boundary + 1, &vs, |h| {
            let l = peers.link_at(h);
            async move { l }
        })
        .await
        {
            Ok(a) => {
                trusted = Some(a.state_root);
                break;
            }
            Err(_) => continue, // мисс — ретрай ТОГО ЖЕ окна, никогда пропуск
        }
    }
    let trusted = trusted.expect("хвостовое окно внутри ретеншна обязано заанкориться");
    assert_eq!(
        trusted, chain.roots[&boundary],
        "доверенный корень — пост-состояние границы, которому обязан хешироваться снапшот"
    );

    // --- Stage 3: snapshot (state+domains С бондом). Миссы ретраят ту же
    // границу; СТАРЫЙ domains-блоб обязан УПАСТЬ громко (root mismatch), а не
    // закоммититься; свежий — встать и принести бонд. ---
    let mut consecutive_stale = 0u32;
    let committed = loop {
        let snap = loop {
            if let Some(s) = peers.snapshot_at(boundary) {
                break s;
            }
        };
        let res = fast_sync_state(
            &observer_engine,
            trusted,
            || async { Some(snap.clone()) },
            |kind: &'static str| {
                let d = peers.domain_at(boundary, kind);
                async move { d }
            },
        )
        .await;
        match res {
            Ok(()) => break boundary,
            Err(e) => {
                // Старый domains-блоб обязан падать ГРОМКО с доменной/корневой
                // причиной — ретрай ниже делает его честным.
                assert!(
                    e.contains("domains") || e.contains("root mismatch") || e.contains("restore"),
                    "stale-бандл обязан падать ГРОМКО с доменной/корневой причиной, got: {e}"
                );
                consecutive_stale += 1;
                assert!(
                    consecutive_stale <= bootstrap::BOOTSTRAP_MAX_STALE_PER_BOUNDARY,
                    "один stale-блоб не должен исчерпать бюджет границы"
                );
                match bootstrap::next_boundary_after_stale(boundary, consecutive_stale, 0) {
                    Some(next) => {
                        assert_eq!(
                            next, boundary,
                            "бюджет держит: ретрай ТОЙ ЖЕ границы, а не отказ"
                        );
                        continue;
                    }
                    None => panic!("один stale-блоб никогда не должен бросать на мель"),
                }
            }
        }
    };
    assert_eq!(committed, BOUNDARY);
    assert!(
        consecutive_stale >= 1,
        "fast-sync обязан был встретить и отвергнуть stale-бандл до успеха"
    );
    assert_eq!(
        observer_engine.get_state_root().await,
        chain.roots[&BOUNDARY]
    );
    // ЛЕДЖЕР ПРИЕХАЛ С БЛОБОМ: бонд виден на наблюдателе без единой копии.
    assert!(
        observer_engine
            .staking_read()
            .await
            .to_validator_set()
            .power_of(&bonded_id)
            > 0,
        "наблюдатель обязан унаследовать бонд середины цепи через domains-блоб снапшота"
    );

    // --- Stage 4: walk остатка по роняющимся телам. Каждый дроп роняет одну
    // целую попытку прохода (fail-closed), 50 высот остатка с одним дропом на
    // тело — до 51 попытки: честная форма слабой связи вживую. ---
    let tip_block = &chain.blocks[(TIP - 1) as usize];
    let tip_hash = tip_block.compute_hash();
    let boundary_block = &chain.blocks[(committed - 1) as usize];
    let boundary_hash = boundary_block.compute_hash();
    let mut walked = None;
    for _ in 0..60 {
        if let Ok(w) = collect_missing_blocks(tip_hash, boundary_hash, 1_000_000, |h| {
            let b = peers.body_at(&h);
            async move { b }
        })
        .await
        {
            walked = Some(w);
            break;
        }
    }
    let walked =
        walked.expect("пост-снапшотные тела внутри ретеншн-окна: проход обязан завершиться");
    validate_sync_chain_for_shard(
        &walked,
        committed + 1,
        boundary_hash,
        &vs,
        MASTERCHAIN_SHARD,
    )
    .expect("остаток несёт настоящий кворум на каждой высоте");
    assert_eq!(walked.first().unwrap().height, committed + 1);
    assert_eq!(walked.last().unwrap().height, TIP);
    for b in &walked {
        let ours = observer_engine.get_state_root().await;
        assert_eq!(
            b.state_root, ours,
            "блок {} обязан продолжать наш стейт",
            b.height
        );
        observer_engine
            .update_account(AccountState::new(
                effect_account(b.height),
                effect_balance(b.height),
            ))
            .await;
    }
    // --- Stage 5: live. Хвост прохода — ИМЕННО разрекламированная голова;
    // стейт — ТОЧНО тип источника: ни одного байта мимо протокола. ---
    assert_eq!(walked.last().unwrap().compute_hash(), tip_hash);
    assert_eq!(
        observer_engine.get_state_root().await,
        source_tip_root,
        "наблюдатель сходится на тип источника ТОЧНО — без ручных копий"
    );

    // Доказательство враждебности: миссы, дропы заголовков, один stale-домен
    // и дропы тел — всё сработало и всё пережито ретраями.
    assert!(
        peers.n_snapshot_miss.load(Ordering::SeqCst) >= 2,
        "снапшот-миссы обязаны были сработать"
    );
    assert!(
        peers.n_header_miss.load(Ordering::SeqCst) >= 1,
        "дропы заголовков обязаны были сработать"
    );
    assert_eq!(
        peers.n_stale_domain.load(Ordering::SeqCst),
        2,
        "ровно два stale-домена (set-only и fast-sync), оба отвергнуты"
    );
    assert!(
        peers.n_body_miss.load(Ordering::SeqCst) >= 1,
        "дропы тел обязаны были сработать"
    );
}

/// Процедура возврата как план: границы, бюджет stale и префлайт-гейт —
/// чистые функции, которыми пользуется и тест выше, и живой `run`.
#[test]
fn bootstrap_plan_pins_the_return_procedure() {
    // Gap ≤100 — только walk, снапшот не нужен (зеркало `> 100` в try_catch_up).
    assert_eq!(bootstrap::select_bootstrap_boundary(50, 0, None), None);
    // Живой масштаб: тип 93k с чистой даты — новейшая граница под типом.
    assert_eq!(
        bootstrap::select_bootstrap_boundary(93_000, 0, None),
        Some(93_000)
    );
    // Точный pointer побеждает, когда санитарен (воркерные высоты).
    assert_eq!(
        bootstrap::select_bootstrap_boundary(93_000, 77_000, Some(92_900)),
        Some(92_900)
    );
    // Безумный pointer игнорируется, никогда не доверяется.
    assert_eq!(
        bootstrap::select_bootstrap_boundary(93_000, 77_000, Some(99_999)),
        Some(93_000)
    );
    // Stale-бюджет: ретрай той же границы, затем шаг старше, затем громкий отказ.
    assert_eq!(
        bootstrap::next_boundary_after_stale(93_000, 1, 77_000),
        Some(93_000)
    );
    assert_eq!(
        bootstrap::next_boundary_after_stale(93_000, 3, 77_000),
        Some(92_900)
    );
    // Префлайт fail-closed и называет каждую причину (гейт против cp-костыля).
    let bad = bootstrap::BootstrapPreflight {
        observer: false,
        faucet_key_present: false,
        data_dir_clean: false,
        peer_pointer_present: false,
        validator_set_present: false,
    };
    assert!(!bad.ready());
    assert_eq!(bad.failures().len(), 5);
    let good = bootstrap::BootstrapPreflight {
        observer: true,
        faucet_key_present: true,
        data_dir_clean: true,
        peer_pointer_present: true,
        validator_set_present: true,
    };
    assert!(good.ready());
    assert!(good.failures().is_empty());
}
