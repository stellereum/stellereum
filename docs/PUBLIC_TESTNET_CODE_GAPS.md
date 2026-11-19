# Публичный тестнет: кодовые пробелы и protocol freeze

Статус: рабочий документ лида. Русский язык — для скармливания нейро-аудиторам вместе с кодом.
Обновлено: 2026-11-18 (2026-11-18 changelog: §1 приведён к коду — классика PQ отказывается на КАЖДОЙ высоте, H-окна больше нет; PQ-транспорт безусловен; `{0,1}` грузится без hatch; ECVRF/BLS удалены, CN-VRF импортируется; `STELL_BLS_QC` удалён вместе с BLS). Предыдущее обновление: 2026-11-04. Правило: публике — один зафиксированный протокол, не конструктор из env-флагов.

## 0. Вердикт одной строкой

Код готов к открытию на ~95%. Ниже — всё, что отделяет текущий код от frozen-протокола паблика:
пять решений, два удаления, один нейро-аудит. Ничего из этого не требует новой криптографии.

## 1. Protocol freeze — таблица решений (все приняты лидом, исполняются)

| Флаг/гейт | Состояние в коде | Решение → исполнение |
|---|---|---|
| `STELL_INF_PQ_HANDSHAKE` (infnode handshake) | FULL-PQ, классического режима нет; NodeId не менялся | **FULL-PQ без окна — ИСПОЛНЕНО.** Автогенерация `pq-identity.key` (0600). Классика **отказывается на КАЖДОЙ высоте**: `PQ_CLASSICAL_REFUSE_AFTER_HEIGHT`, смешанное окно и счётчик fallback **удалены** (`infnode/crates/infnode/src/proto.rs:371-378`). `STELL_INF_PQ_HANDSHAKE` парсится-и-игнорируется (`PQ_HANDSHAKE_ENV`, `proto.rs:357-359`); `pq_handshake_active()` всегда `true` (`:361-368`). NodeId не менялся (флаг-дэй отдельно) |
| transport-KEX (ml-kem) | Крейт завезён, KAT зелёные; handshake делает offer/encap/decap + hybrid-ключ на verified-PQ | **Аудит исполнен, gap-таблица в отчёте.** MEV-нога PQ активна **на каждой высоте**: `is_pq_transport_active` всегда `true` (`stellereum/src/mev_epoch.rs:1003-1006`), классическая X25519-нога удалена. `PQ_TRANSPORT_H_ACTIVATION_HEIGHT = 10_000` (`:995`) сохранён только для замороженного расписания (`chain_spec.rs:153-155`) и больше ничего не гейтит; константы `PREFER_PQ_MEV_TRANSPORT` в коде нет (только prose-упоминание в `state_engine/mod.rs:71`). Остатки classical (Ristretto-DH sealed-tx, stealth, snapshot-e2e, P2P TLS, RemoteSigner) — задокументированы как известные, часть уже за pure-PQ гейтами. Полный cut классики — только флаг-днём с interop-доказательством |
| VRF (`STELL_VRF_ACTIVATION_HEIGHT`) | ECVRF удалён; живьём — parent-hash draw; CN-VRF v3 **импортируется**, но гейт выключен | **Parent-hash draw — THE механизм. ИСПОЛНЕНО:** arming удалён (флаг inert + WARN), глобальный реестр сериализован. ECVRF **удалён**: `vrf.rs` — 133 строки чистой математики лотереи, без ключей/env/активации. CN-VRF **не песочница**: импортируется `runtime/mod.rs:621-629`, `commitment.rs:1919+`, `storage.rs:5106`, `sync.rs:2864`; v3-гейт сортировки существует и выключен (`consensus/sortition.rs:552-634`, `u64::MAX`). Включение v3 — только после нейро-аудита |
| Workchain (`STELL_SHARDS`, `XPC_ACTIVATION_HEIGHT`) | unset = один шард `{0}`; фиксированная пара `{0,1}` разрешена; 2PC **active from genesis**; live-soak есть | **ИСПОЛНЕНО:** boot-guard принимает `{0}` и ровно `{0,1}` **без** `STELL_EXPERIMENTAL_SHARDS` (`stellereum/src/sharding/topology.rs:89-124`); прочие наборы (`{1}`, `{2}`, `{0,1,2}`) отказывают без hatch. `{0}` остаётся default, `{0,1}` — задокументированная фиксированная публичная пара. `XPC_ACTIVATION_HEIGHT = 0` (`xshard2pc.rs:146`), `STELL_XPC_ACTIVATION_HEIGHT` deprecated/ignored; живой прогон — `scripts/soak_two_shard.sh` (`docs/TWO_SHARD_DEPLOY.md`). Тесты guard/2PC зелёные |
| `STELL_BLS_QC` | **BLS удалён из дерева** (нет `bls.rs`, нет константы `STELL_BLS_QC`) | **Закрыто удалением.** Классическая BLS-нога вырезана; QC/µQC — только PQ (`consensus/types.rs:1859-1861`). Отдельный флаг не нужен: включать нечего |
| ~~legacy-genesis env knob~~, faucet test-key | Техдолг в коде | **ИСПОЛНЕНО:** legacy-ветки удалены — strict-only (`stellereum/src/post_quantum.rs:1598-1600`), тоггл no-op (`stellereum/tests/a_crypto_audit_poc.rs:147-174`), гарды его не перечисляют (`stellereum/tests/genesis_guard_tests.rs:60-64`); faucet требует key-file (`stellereum/src/rpc.rs:502-508`, без файла — DISABLED), 7 debug-хуков загейчены/удалены (таблица в отчёте), доки OPERATIONS помечены stale (вне зоны) |

Высоты H больше не существует: классика мертва **на каждой высоте**, env-override нет.
Тестовые переопределения гейтов — thread-local и существуют только под
`cfg(any(test, debug_assertions))` (`consensus/sortition.rs:194-220`,
`governance.rs:84-114`); в release их нет.

## 2. Удалить/закрыть до паблика (код)

1. **~~legacy-genesis env knob~~ — ЗАКРЫТО (было: legacy-путь парсинга/ключей).** Ветка удалена, парсер — strict-only (`stellereum/src/post_quantum.rs:1598-1600`; no-op пин `stellereum/tests/a_crypto_audit_poc.rs:147-174`). Иначе легаси навсегда часть «протокола» — устранено.
   Иначе легаси навсегда часть «протокола».
2. **Faucet test-key по умолчанию** (`111...1`-класс). Публичный кран без ключа обязан быть
   ВЫКЛЮЧЕН (fail-closed), а не открыт миру. Исполнение: faucet требует key-file; тестовый ключ
   работает только с явным тестовым флагом, которого нет в прод-доках. Сьюты перевести на файлы.
3. **Debug-эндпоинты и тестовые хуки** — инвентаризация: каждый либо gated за тестовой сборкой,
   либо удалён. Список при исполнении (grep `debug`, `test-only`, `#[cfg(test)]`-нарушители вне тестов).
4. **Тестовые константы в прод-пути** — бюджеты вида `*_FOR_TESTS`, захардкоженные сиды вне `#[cfg(test)]`.
   Либо за `cfg(test)`, либо удалить.

## 3. Нейро-аудит пакет (внешних людей нет — только нейронки, по готовности кода 100%)

Критерий «код 100%»: lib 0 failed + clippy 0/0 оба крейта + матрица 100% green +
audit-repro PASS + ноль UNVERIFIED в `docs/specs/` + настоящий раздел (§1) исполнен.
Состав пакета (склейка, не новая писанина):
- `docs/specs/*_PHASE2` + `docs/PQ_CN_VRF_SPEC.md` + `docs/CLASSICAL_INVENTORY.md`
  + `docs/WORKCHAIN_DECISION.md` (`docs/program/` и `docs/PQ_VRF_FRONTIER_V2.md`
  в дереве отсутствуют — не включать)
- Матрица (`FEATURES.md`, N строк) + последний `audit-repro` лог + `docs/PENTEST_*` сводка
  (все батареи + таблица DEFEATED/FINDING с остатками: 2× Low reputation accepted)
- Явный список «что НЕ аудировать»: BLS/ECVRF (удалены из дерева), workchain (parked),
  CN-VRF wiring (его нет — песочница), transport flag-H (исполнен, но live-эксплуатация впереди)
- Вопросы нейронкам: soundness CN-VRF (§2 спеки), abort-экономика, commit-reveal параметры,
  остатки classical paths (grep-список из inventory), wire-совместимость H-перехода

## 4. Очередь после нейро-аудита (не блокеры записи, блокеры включения)

1. CN-VRF wiring в sortition (запрещено до аудита, `AGENTS.md` §7).
2. Transport flag-H эксплуатация + NodeId re-ceremony для внешних операторов.
3. Workchain unpark (live-soak → отдельный флаг-дэй).
4. ~~BLS/ECVRF вырезание~~ — **ИСПОЛНЕНО** (удалены из дерева).
5. Слэшинг-лайв дрилл, видимый в эксплорере.

## 5. Явно НЕ блокеры паблика (зафиксировано, чтоб не всплывало)

- BLS/ECVRF — **в дереве отсутствуют** (удалены); упоминания только исторические.
- PQ-registry delays (7200 — параметр, не пробел).
- Explorer/RPC мелочи, темп выше 0.6 (запас уже ×50 по CPU).
- Nightly по крону (инфра, не код).
