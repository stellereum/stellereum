# Публичный тестнет: кодовые пробелы и protocol freeze

Статус: рабочий документ лида. Русский язык — для скармливания нейро-аудиторам вместе с кодом.
Обновлено: 2026-11-04 (2026-11-04 changelog: закрыты stale-ссылки на удалённый legacy-genesis knob — strict-only подтверждён цитатами, активная задача снята). Правило: публике — один зафиксированный протокол, не конструктор из env-флагов.

## 0. Вердикт одной строкой

Код готов к открытию на ~95%. Ниже — всё, что отделяет текущий код от frozen-протокола паблика:
пять решений, два удаления, один нейро-аудит. Ничего из этого не требует новой криптографии.

## 1. Protocol freeze — таблица решений (все приняты лидом, исполняются)

| Флаг/гейт | Состояние в коде | Решение → исполнение |
|---|---|---|
| `STELL_INF_PQ_HANDSHAKE` (infnode handshake) | default OFF → классический QUIC; PQ-путь есть, NodeId не менялся | **ON по умолчанию — ИСПОЛНЕНО.** Автогенерация `pq-identity.key` (0600), классика живёт только до **H=300_000** (`PQ_CLASSICAL_REFUSE_AFTER_HEIGHT`, `proto.rs`), дальше отказ. Смешанное окно с WARN+счётчиком. NodeId не менялся (флаг-дэй отдельно) |
| transport-KEX (ml-kem) | Крейт завезён, KAT зелёные; handshake уже делает offer/encap/decap + hybrid-ключ на verified-PQ; зазор — что именно шифруется сессионным ключом vs остатки классики | **Аудит исполнен, gap-таблица в отчёте.** MEV-нога вшита за **H=10_000** (`PQ_TRANSPORT_H_ACTIVATION_HEIGHT`, спит до переворота `PREFER_PQ_MEV_TRANSPORT`). Остатки classical (Ristretto-DH sealed-tx, stealth, snapshot-e2e, P2P TLS, RemoteSigner) — задокументированы как известные, часть уже за pure-PQ гейтами. Полный cut классики — только флаг-днём с interop-доказательством |
| VRF (`STELL_VRF_ACTIVATION_HEIGHT`) | OFF; ECVRF помечен classical; CN-VRF — песочница без импорта в консенсус; живьём — parent-hash draw | **Parent-hash draw — THE механизм. ИСПОЛНЕНО:** arming удалён (флаг inert + WARN), 11 stale-пинов переведены на retired-ожидания, phase3-флейк (глобальный реестр) вылечен сериализацией всех 12 тестов (12/12 ×3). ECVRF — мёртвый код под маркером. CN-VRF — только после нейро-аудита |
| Workchain (`STELL_SHARDS`, `STELL_XPC_ACTIVATION_HEIGHT`) | unset = один шард, 2PC Disabled; локальный soak 4/4 + N=3 доказан, live-soak не было | **Single-shard канон. ИСПОЛНЕНО:** boot-guard — `STELL_SHARDS != {0}` без `STELL_EXPERIMENTAL_SHARDS=1` отказывает старту с указанием на этот док. Тесты guard 5/5 |
| `STELL_BLS_QC` | hard-refused на старте | **Оставить refused как финальное.** BLS — classical legacy, компактные QC не считаются никогда. Пин-тест уже есть |
| ~~legacy-genesis env knob~~, faucet test-key | Техдолг в коде | **ИСПОЛНЕНО:** legacy-ветки удалены — strict-only (`stellereum/src/post_quantum.rs:1598-1600`), тоггл no-op (`stellereum/tests/a_crypto_audit_poc.rs:147-174`), гарды его не перечисляют (`stellereum/tests/genesis_guard_tests.rs:60-64`); faucet требует key-file (`stellereum/src/rpc.rs:502-508`, без файла — DISABLED), 7 debug-хуков загейчены/удалены (таблица в отчёте), доки OPERATIONS помечены stale (вне зоны) |

H (высота смерти классики/эксперимента) выбирается лидом перед пабликом с запасом в недели;
константа в коде + env-override для тестов. До H поведение смешанное с громкими WARN и метрикой.

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
- `docs/program/` (зеркало для GitHub) + `docs/specs/*_PHASE2` + `docs/PQ_CN_VRF_SPEC.md`
  + `docs/CLASSICAL_INVENTORY.md` + `docs/PQ_VRF_FRONTIER_V2.md` + `docs/WORKCHAIN_DECISION.md`
- Матрица (`FEATURES.md`, N строк) + последний `audit-repro` лог + `docs/PENTEST_*` сводка
  (все батареи + таблица DEFEATED/FINDING с остатками: 2× Low reputation accepted)
- Явный список «что НЕ аудировать»: BLS/ECVRF (refused, мёртвый код), workchain (parked),
  CN-VRF wiring (его нет — песочница), transport flag-H (исполнен, но live-эксплуатация впереди)
- Вопросы нейронкам: soundness CN-VRF (§2 спеки), abort-экономика, commit-reveal параметры,
  остатки classical paths (grep-список из inventory), wire-совместимость H-перехода

## 4. Очередь после нейро-аудита (не блокеры записи, блокеры включения)

1. CN-VRF wiring в sortition (запрещено до аудита, `AGENTS.md` §7).
2. Transport flag-H эксплуатация + NodeId re-ceremony для внешних операторов.
3. Workchain unpark (live-soak → отдельный флаг-дэй).
4. BLS/ECVRF вырезание (удаление мёртвого кода; refused-статус делает это косметикой).
5. Слэшинг-лайв дрилл, видимый в эксплорере.

## 5. Явно НЕ блокеры паблика (зафиксировано, чтоб не всплывало)

- BLS/ECVRF в дереве (помечены classical, refused/off — безопасны как комментарии).
- PQ-registry delays (7200 — параметр, не пробел).
- Explorer/RPC мелочи, темп выше 0.6 (запас уже ×50 по CPU).
- Nightly по крону (инфра, не код).
