//! Regression for the stale-ledger node-C incident.
//!
//! ВЕЩДОК: нода C отресторилась из слепка (state 92072) с леджером БЕЗ
//! собственного бонда (доменный снапшот старее бонда 81821). Дальше walk не
//! может её научить (бонд древний, вне walking-окна, а snapshot-домены тоже
//! старые): C навечно с чужим сетом — не голосует, кворумы считает чужие.
//!
//! Что пинится здесь:
//! * restore/snapshot-refresh сверяет высоту леджера с высотой стейта; леджер,
//!   отставший более чем на K (дефолт — snap-кольцо 300), — это STALE:
//!   громкий WARN (Err содержит `STALE`) + отказ использовать протухший сет
//!   для кворума (fail-closed в observer без голосов);
//! * свежий сет подтягивается отдельно от блоков — из свежих доменных
//!   снапшотов (`refresh_validator_set_from_domain_bytes`).

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::consensus::ValidatorSet;
use stellereum::runtime::ValidatorRuntime;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::storage::{
    check_validator_set_freshness_with_lag, decode_domain_snapshot,
    validator_set_freshness_max_lag, DomainSnapshot, Storage, VALIDATOR_SET_FRESHNESS_DEFAULT_LAG,
};

fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn rt_with_config_set(keys: &[SigningKey]) -> ValidatorRuntime {
    let vs = ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let engine = Arc::new(InMemoryStateEngine::new());
    ValidatorRuntime::new(keys[0].clone(), vs, engine, 1)
}

fn ledger_with(keys: &[SigningKey]) -> stellereum::staking::StakingLedger {
    let mut l = stellereum::staking::StakingLedger::new();
    for k in keys {
        l.bond(
            k.verifying_key().to_bytes(),
            stellereum::staking::MIN_VALIDATOR_BOND + stellereum::staking::STELL_MIN_BOND_BUFFER,
            0,
        )
        .unwrap();
    }
    l
}

#[test]
fn freshness_default_is_the_snapshot_ring() {
    // Дефолт — требовать свежесть в пределах snap-кольца (3×100).
    assert_eq!(VALIDATOR_SET_FRESHNESS_DEFAULT_LAG, 300);
    // Без env — дефолт (env в параллельном тест-ране трогать нельзя).
    if std::env::var("STELL_VALIDATOR_SET_MAX_LAG").is_err()
        && std::env::var("STELL_LEDGER_FRESHNESS_MAX_LAG").is_err()
    {
        assert_eq!(validator_set_freshness_max_lag(), 300);
    }
}

#[test]
fn freshness_pure_gate_flags_stale_and_ahead() {
    // Свежо внутри кольца.
    assert!(check_validator_set_freshness_with_lag(92072, 92072, 300).is_ok());
    assert!(check_validator_set_freshness_with_lag(92072, 91800, 300).is_ok());
    // Граница: lag == max — ещё свежо; lag == max+1 — STALE.
    assert!(check_validator_set_freshness_with_lag(1000, 700, 300).is_ok());
    let err = check_validator_set_freshness_with_lag(92072, 81821 - 1, 300)
        .expect_err("ledger 81820 при state 92072 отстаёт на 10252 — обязан быть STALE");
    assert!(err.contains("STALE"), "громкий WARN-маркер, got: {err}");
    // Леджер ВПЕРЕДИ стейта — тоже отказ (порча меток), никогда не доверять.
    let ahead = check_validator_set_freshness_with_lag(100, 200, 300)
        .expect_err("ledger ahead of state must be refused");
    assert!(ahead.contains("STALE"), "got: {ahead}");
}

#[tokio::test]
async fn restore_with_stale_ledger_warns_and_fails_closed_to_observer() {
    // Конфиг-сет {A,B}; свежий леджер знал бы {A,B,C}, но рестор принёс
    // СТАРЫЙ леджер {A,B} с высоты 81820 при стейте 92072.
    let ka = test_key(0xA1);
    let kb = test_key(0xB2);
    let kc = test_key(0xC3);
    let mut rt = rt_with_config_set(&[ka.clone(), kb.clone()]);
    let self_id = rt.id;
    assert!(
        rt.validators.validators.contains_key(&self_id),
        "предусловие: мы в конфиг-сете"
    );

    let stale_ledger = ledger_with(&[ka.clone(), kb.clone()]);
    let state_h = 92_072u64;
    let ledger_h = 81_820u64; // старее бонда 81821

    let changed = rt
        .refresh_validator_set_from_ledger(&stale_ledger, state_h, ledger_h)
        .await;
    assert!(!changed, "протухший сет нельзя устанавливать");
    assert!(
        rt.is_validator_set_stale(),
        "STALE обязан выставить fail-closed флаг"
    );
    let reason = rt.validator_set_stale_reason().unwrap_or("");
    assert!(
        reason.contains("STALE"),
        "честный лог вместо тихого неверного сета, got: {reason}"
    );
    // Fail-closed в observer БЕЗ голосов — даже конфиг-валидатор не голосует.
    assert!(
        !rt.effective_can_vote(true),
        "stale: конфиг-валидатор обязан стать observer без голосов"
    );
    assert!(
        !rt.effective_can_vote(false),
        "stale: observer тем более не голосует"
    );
    // Протухший сет НЕ подменил текущий (кворумы не считаются по-чужому).
    assert!(
        !rt.validators
            .validators
            .contains_key(&kc.verifying_key().to_bytes()),
        "чужой ключ C не должен проникнуть из свежего будущего; сет не тронут"
    );
}

#[tokio::test]
async fn fresh_ledger_installs_set_and_keeps_franchise() {
    let ka = test_key(0xA1);
    let kb = test_key(0xB2);
    let kc = test_key(0xC3);
    let mut rt = rt_with_config_set(&[ka.clone(), kb.clone()]);

    // Свежий леджер {A,B,C} с высоты внутри кольца.
    let fresh_ledger = ledger_with(&[ka.clone(), kb.clone(), kc.clone()]);
    let changed = rt
        .refresh_validator_set_from_ledger(&fresh_ledger, 92_072, 92_000)
        .await;
    assert!(changed, "свежий сет обязан установиться");
    assert!(
        !rt.is_validator_set_stale(),
        "свежий рефреш снимает stale-флаг"
    );
    // W10.5 ACTIVATION BOUNDARY: derived at ledger-height 92000 ⇒ in force
    // from height 92001, NEVER immediately. The fresh set is STAGED (C is
    // in it, with the agreed activation); the in-force set moves only when
    // this node advances to the activation height. Asserting immediate
    // installation here would re-introduce the mid-flight quorum jump.
    let (activation, staged) = rt
        .pending_validators
        .clone()
        .expect("свежий сет обязан быть застейджен, а не установлен сразу");
    assert_eq!(activation, 92_001, "активация — следующий хайт за леджером");
    assert!(
        staged
            .validators
            .contains_key(&kc.verifying_key().to_bytes()),
        "C обязан появиться в застейдженном сете"
    );
    assert!(
        !rt.validators
            .validators
            .contains_key(&kc.verifying_key().to_bytes()),
        "in-force сет не двигается до границы активации"
    );
    assert!(rt.effective_can_vote(true), "со свежим сетом франшиза жива");
}

#[tokio::test]
async fn set_only_refresh_from_fresh_domains_repairs_stale_node() {
    // Нода уже в STALE (леждер 81820 при стейте 92072)...
    let ka = test_key(0xA1);
    let kb = test_key(0xB2);
    let kc = test_key(0xC3);
    let mut rt = rt_with_config_set(&[ka.clone(), kb.clone()]);
    let stale_ledger = ledger_with(&[ka.clone(), kb.clone()]);
    rt.refresh_validator_set_from_ledger(&stale_ledger, 92_072, 81_820)
        .await;
    assert!(rt.is_validator_set_stale());

    // ...и отдельно от блоков подтягивает СВЕЖИЙ доменный снапшот {A,B,C}
    // (процедура refresh сета из свежих доменных снапшотов, не из apply).
    let engine = InMemoryStateEngine::new();
    let fresh_ledger = ledger_with(&[ka.clone(), kb.clone(), kc.clone()]);
    let gov = stellereum::governance::Governance::new();
    let snap = DomainSnapshot::capture(&engine, &fresh_ledger, &gov).await;
    let bytes = bincode::serialize(&snap).unwrap();
    // Снапшот обязан декодироваться тем же путём, что и сетевой блоб.
    let decoded = decode_domain_snapshot(&bytes).unwrap();
    assert!(decoded
        .staking
        .validators
        .contains_key(&kc.verifying_key().to_bytes()));

    let installed = rt
        .refresh_validator_set_from_domain_bytes(&bytes, 92_072, 92_050)
        .await
        .expect("свежие домены обязаны декодироваться");
    assert!(installed, "свежий доменный снапшот обязан починить сет");
    assert!(
        !rt.is_validator_set_stale(),
        "ремонт обязан снять stale-флаг"
    );
    assert!(
        rt.effective_can_vote(true),
        "после ремонта нода снова голосует"
    );

    // А СТАРЫЙ доменный снапшот чинить не должен (stale остаётся).
    let old_snap = DomainSnapshot::capture(&engine, &stale_ledger, &gov).await;
    let old_bytes = bincode::serialize(&old_snap).unwrap();
    let installed_old = rt
        .refresh_validator_set_from_domain_bytes(&old_bytes, 92_072, 81_820)
        .await
        .expect("старые домены декодируются, но обязаны быть отвергнуты как STALE");
    assert!(!installed_old, "старые домены не устанавливают сет");
    assert!(
        rt.is_validator_set_stale(),
        "после старого снапшота stale обязан вернуться"
    );
    assert!(
        !rt.effective_can_vote(true),
        "со старым сетом — снова честный observer"
    );
}

#[tokio::test]
async fn storage_gap_detector_sees_state_ahead_of_domains() {
    // Диск: стейт новее доменов сильнее кольца → разрыв виден до рефреша.
    let dir = std::env::temp_dir().join(format!(
        "stell-vset-fresh-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let store = Storage::open(&dir).unwrap();
    store.put_state(92_072, b"state-new").unwrap();
    store.put_domains(81_820, b"domains-old").unwrap();
    let gap = store.ledger_state_gap().unwrap().expect("обе стороны есть");
    assert_eq!(gap, (92_072, 81_820));
    let err = stellereum::storage::check_validator_set_freshness(gap.0, gap.1)
        .expect_err("разрыв 10252 при кольце 300 — STALE");
    assert!(err.contains("STALE"), "got: {err}");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn paired_heights_are_fresh() {
    // Свежая пара (state и domains на одной высоте) — не STALE.
    let dir = std::env::temp_dir().join(format!(
        "stell-vset-paired-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let store = Storage::open(&dir).unwrap();
    store.put_state(500, b"s").unwrap();
    store.put_domains(500, b"d").unwrap();
    let gap = store.ledger_state_gap().unwrap().expect("обе стороны есть");
    assert_eq!(gap, (500, 500));
    assert!(stellereum::storage::check_validator_set_freshness(gap.0, gap.1).is_ok());
    std::fs::remove_dir_all(&dir).ok();
}
