# Оценка блокчейна Stellereum — полный технический аудит и сводный отчет 7 специализированных агентов

> **Пост-волновой статус (2026-11-19, `24e2a1dca`).** Части отчёта ниже —
> датированные срезы. После них изменились: 2PC (`XPC_ACTIVATION_HEIGHT = 0`,
> active from genesis; A3/W8.5-формулировки «disabled» устарели),
> block-carried governance (`GOV_OPS_ACTIVATION_HEIGHT = 0` + deterministic
> finalize/execute; `SoftwareUpgrade` всё ещё за `UPGRADE_EXEC_ACTIVATION_HEIGHT`
> = `u64::MAX`), compact gossip (proposal path wired, gate `0`; µQC emitter
> deferred) и EVM write path (PQ binding + carrier вместо мёртвого refusal).
> Актуальные детали — `docs/COMPACT_PROPAGATION.md`, `docs/TWO_SHARD_DEPLOY.md`,
> `docs/GOV_BLOCK_CARRIED_DESIGN.md`, `docs/site/02-concepts.md`.

> **Ревизия 2026-10-25 (S7-retry3, сертификация).** Это пятая редакция отчёта. Первая (ниже, ЧАСТЬ I) — исходная
> оценка, **сохранённая дословно** как baseline (проверено diff'ом: блок от заголовка
> «ЧАСТЬ I.» до заголовка «ЧАСТЬ II.» байт-идентичен, sha256 = `f96b0df23d6ddb93a641b57b4ef9798f47538940f7eeb0e80f0ca1c4b3120bb2`). Эта ревизия описывает состояние кода **после волн W1–W10 без изменений протокола** (только тестовые/док-фиксы после 2026-10-23): A9 закрыт кодом (сборка всех таргетов, оба stale-ожидания вылечены), SECURITY.md создан как DRAFT; живая сеть в момент проверки **отказана в статусе STABLE** — активная DIVERGENCE на #305832 (см. новый раздел «STABLE TESTNET CERTIFICATION»). Каждое утверждение перепроверено по исходникам;
> ниже везде указан `file:line` и имя регрессионного теста, который пиннит фикс.
> Числа в ЧАСТИ V — фактический вывод команд, прогнанных **2026-10-25** (агент S7-retry3).
> Правка GUARD 2026-10-28: ЧАСТЬ I не тронута (sha256 до/после сверен, см. конец файла);
> обновлены только причины в ЧАСТИ 0/VI (там, где есть свежие замеры), числа ЧАСТИ V
> (замеры GUARD 2026-10-28) и добавлена датированная запись «STAB + deploy wave» в конце.
>
> Правка REP2 2026-10-28 (REPORT SYNC + OPEN-BRANCH CLOSURE, без логики протокола):
> ЧАСТЬ I не тронута (sha256 до/после сверен, см. конец файла; при несовпадении
> ревизия считается недействительной). Обновлены: причины/скоринг ЧАСТЕЙ 0/VI только
> там, где есть измеренные основания (одна строка на изменение); карта волн + таблица
> возможностей (STAB verify-once + MMR-кэш, TAIL-1, VEL-харнесс, MMR epoch roots +
> `stell_getEpochRoot`, SDK-крейт, B9 Logs-страница, paymaster/privacy/burn/order/bridge);
> ЧАСТЬ IV (B2, B9 закрыты кодом; открыто осталось только genuine-open с владельцами);
> ЧАСТЬ V (все числа — собственные прогоны REP2 2026-10-28: `cargo test --lib` 1034/0,
> TAIL-1 perf, VEL-харнесс, новые сьюты, explorer build). Маркировка: **VERIFIED**
> (проверено в коде/прогоном, указан file:line/тест), **UNVERIFIED** (заявка чужой волны,
> в этом дереве не воспроизводится — не выдумано, помечено честно). Добавлена секция
> «REP2 SYNC» в конце. P1-G2..G4 ACCEPTED-заметка подтверждена в коде grep'ом
> (без правок); shares-alignment: половина `stellereum/docs/MEV.md` §5.6 существует,
> недостающая половина добавлена в V5-спек §4 как docs-текст (консистентно с
> pool-message реализацией).
>
> **Легенда статусов (используется в ЧАСТЬ II и ЧАСТЬ III):**
>
> | Статус | Что означает |
> | :--- | :--- |
> | **FIXED** | Дефект закрыт в коде; указаны `file:line` фикса и тест, который его пиннит. |
> | **MITIGATED** | Риск ослаблен, но не устранён; указано, что именно изменилось и какой остаточный риск. |
> | **ACCEPTED** | Это не дефект: сознательное архитектурное решение (или заведомо ложное срабатывание исходного аудита). Указано, почему. |
> | **OPEN** | Не закрыто. Указано, чего именно не хватает. |

---

## ЧАСТЬ 0. СОСТОЯНИЕ НА СЕГОДНЯ (после волн W1–W10)

### 0.1. Текущая сводная оценка

Таблица ниже — **актуальная** версия итоговых оценок. Оценки из ЧАСТЬ I оставлены
дословно там, где они были, и приводятся здесь рядом для сравнения.

| Критерий | PART I (было) | СЕЙЧАС | Обоснование (одна строка) |
| :--- | :--- | :--- | :--- |
| **Целостность кода** | ★★★★☆ 7.5/10 | **★★★★☆ 8.5/10** | A9 закрыт: все таргеты собираются, stale-инициализаторы починены; но живая DIVERGENCE #305832 показывает, что атомарный undo лечит форму, а не корень расхождения. |
| **Консенсус** | ★★★★☆ 8/10 | **★★★★☆ 8.5/10** | VEL-харнесс собственным прогоном: LAN 100 высот mean 350 мс p99 350 мс 0 вью-чейнджей, WAN 20 высот mean 690 мс extra_rounds 0; живьём 2026-10-28 оба RPC-узла сошлись (идентичные tip_hash/state_root, 0 DIVERGENCE за 3 ч). |
| **Криптография** | ★★★☆☆ 6.5/10 | **★★★★☆ 8.5/10** | P4: 24-атаковая батарея держится, 0x29-канон запиннен (`v34_fpq1`), Debug-утечки закрыты; 0x39 осознанно не принимается (interop-стена, ACCEPTED). |
| **Смарт-контракты** | ★★★☆☆ 5.5/10 | **★★★★★ 9/10** | P5 закрыл 3 CRITICAL auth-гейта (`deploy`/`call`/`wrapped-deploy`) + mint-cap-cycle + staking/token/contract эксплойт-тесты; 8/8 `p5_*` зелёные. |
| **Хранилище/стейт** | ★★★★☆ 7.5/10 | **★★★★★ 9/10** | MMR epoch roots коммитятся в блоках каждые 128 высот + `stell_getEpochRoot` запиннен 3/3 (прогон REP2); DIVERGENCE-аларм молчит 3 ч, оба RPC-узла отдают идентичные tip/state_root. |
| **Шардинг** | ★★★☆☆ 5.5/10 | **★★★☆☆ 7.5/10** | Фауцет роутит дрипы на шард получателя + pool-level `admission_shard`-пин; **живой split и живая 2PC-финализация по-прежнему не проведены**; воркчейн финализирует, мастерчейн встал. |
| **P2P/сети** | ★★★★☆ 7/10 | **★★★★☆ 8.5/10** | P1: 6 fixed + G1/G5 доведены V-P1; G2–G4 остаются filed-гепами; infnode-lib 44/44 (1 флейк при первом прогоне, повтор зелёный). |
| **Тесты** | ★★★★★ 9/10 | **★★★★★ 9/10** | lib: **1034 passed, 0 failed** (2026-10-28, REP2, 20.31 с; было 1025 GUARD); TAIL-1 дифференциальные пины 4/4 + VEL-харнесс 2/2 + MMR/paymaster/shielded/order/каноникал-SDK сьюты зелёные собственным прогоном. |
| **Документация** | ★★★★☆ 8/10 | **★★★★★ 9.5/10** | SECURITY.md — DRAFT с плейсхолдерами (заменить, иначе не shippable); shares-alignment закрыт с обеих сторон: MEV.md §5.6 + V5-спек §4 (REP2 docs-only). |
| **Production-readiness** | ★★☆☆☆ 4.5/10 | **★★★☆☆ 6.5/10** | Узлы сошлись (идентичные tip_hash/state_root на обоих RPC, 4/4 `fragile:false`, 0 DIVERGENCE за 3 ч, ~3.3 с/блок за 196 с), но канон-как-процесс (#305832 → ресинк меньшинства) не предъявлен — REFUSE в силе; блокеры A1–A3, A6–A7, A14–A18 в силе. |

**Общий вердикт (актуальный):**

* **~8.5/10 как прототип / публичный тестнет** — код стал зеленее (1034 lib на 2026-10-28 REP2, все таргеты собираются, TAIL-1 дифференциальные пины и VEL-харнесс прогнаны лично, SECURITY.md-DRAFT), живая сеть 2026-10-28 сошлась (идентичные tip/state_root на обоих RPC, 0 DIVERGENCE за 3 ч, ~3.3 с/блок) — но канон-как-процесс по #305832 не предъявлен, поэтому STABLE по-прежнему не присвоен (см. сертификацию + секцию REP2).
* **~6.5/10 как production L1** — блокеры перечислены честно в ЧАСТЬ IV (a): **внешний
  аудит не проведён**, **живой шардовый split не выполнен**, **2PC не активирован и не
  финализирован вживую**, **живая DKG-церемония эпохи не проведена**,
  **сортиция grindable**, **BLS без PoP не включается**, **SECURITY.md — DRAFT с плейсхолдерами**,
  **канон-как-процесс по #305832 не предъявлен** (обновлённый A18: конвергенция наблюдена, процедура — нет), A17 (A-rebond + D-stake) по-прежнему PENDING.

Сравните с исходной оценкой PART I: **~6.5/10 как прототип, ~4.5/10 как production L1**.
Прирост дали волны W2 (контракты), W3 (стриминг/шардинг/light client), W4 (PQ),
W8 (liveness-корень, MEV-seal, 2PC, light client в sync-пути, ops-готовность,
аудит-пакет), W9 (верификация исходников, стандарт подписи, archive proofs) и
W10 (fork-heal, faucet-fix, пентесты P1–P5, верификации, OS-оценка).

### 0.2. Карта волн (что реально сделано)

| Волна | Содержание | Как проверить в коде |
| :--- | :--- | :--- |
| **W1** | Критические уязвимости ядра: SEC-01 (инверсия замка), SEC-03 (downtime-slashing по µQC/BLS), SEC-04 (нулевой хэш апгрейда), SEC-05 (O(N log N) удаление в trie), SEC-06 (голод inbound-канала), SEC-07 (бесплатный сбой), коллизия шардовой маршрутизации, паритет газа токенов | `src/runtime.rs:4693`, `src/consensus.rs:2537`, `src/governance.rs:279`, `src/cpat2.rs:262`, `src/main.rs:3748`, `src/state_engine.rs:3120`, `src/sharding.rs:538`, `src/token.rs:38` |
| **W2** | Контрактный жизненный цикл P0: 13 host-импортов (было 3), события VM→receipt→storage→RPC, `stell_deployContract`/`stell_callContract`/`stell_runGetMethod`, cap кода 256 KiB→2 MiB, `host.send_message`, `stell_estimateFee` | `src/contract.rs:45`, `src/contract.rs:1107`, `src/storage.rs:159`, `src/rpc.rs:4581` / `:4795` / `:4388` |
| **W3** | Потоковая передача и шардинг P1: shard-header commitment, `stell_getShards`, `stell_getProof` + SPV, синк воркчейн-сета, P2P cross-shard топики, WebSocket + SSE, fork-choice + invalidation | `src/sharding.rs:4180`, `src/rpc.rs:3268` / `:3517`, `src/network.rs:2549`, `src/main.rs:2331` |
| **W4** | PQ-крипто и финализация: Falcon-512 FIPS 206, sortition от хэша родителя + network-anchored µQC quorum, chain-id в голосах и блоках, ленивый F1-аккумулятор, полнота commitment-доменов, priority fee в мемпуле, шифрование ключей `enc2` | `src/post_quantum.rs:1346`, `src/consensus.rs:747` / `:691`, `src/staking.rs:1849`, `src/commitment.rs:593`, `src/node_keys.rs:392` |
| **W5** | Consensus-enforced порядок транзакций, параллельное исполнение по resource-ключам, ABI + JSON-манифест + codegen Rust/TS, devnet + детерминированный симулятор, P2P-латентность, гигиена репозитория (CI, fuzz-путь, мёртвые зависимости) | `src/runtime.rs:2661`, `src/parallel_exec.rs`, `src/contract_abi.rs`, `src/bin/abi_codegen.rs`, `src/simulator.rs`, `.github/workflows/ci.yml` |
| **W6** | **Четыре независимых ре-аудита**: consensus/BFT (W6.4b), crypto/PQ (W6.5), mempool/sharding/execution (W6.6), staking/governance/network/RPC (W6.7) → ~40 фиксов (реестр в ЧАСТЬ III) | комментарии `AUDIT W6.4b` / `W6.5` / `W6.6` / `W6.7` по `src/**` |
| **W7** | Обнаружена при подготовке этой ревизии: **W7.1** — truth-gate моста (единственное настоящее доказательство мошенничества — кворумная ретрактация); **W7.2** — fail-closed словарь governance-действий, честный бюджет `stell_estimateFee`, разделение `stell_bridgeDeposit` (read) и `stell_bridgeDepositPrepare` (write) | `src/bridge.rs:738` / `:1517`, `src/governance.rs`, `src/rpc.rs:4020` / `:4074` |
| **W8** | Liveness-корень + операционная готовность: **W8.1** — цикл `sync_round_to` в `note_peer_vote_round` (forward-only, verified-votes-only, без кворум-гейта); **W8.2** — детерминированный harness `consensus_cluster` + 13 сценариев (+1 ignored); **W8.3** — light client в sync-пути + внешний CLI + `stell_getFinalizedHeader`/`stell_getFinalizedCheckpoint`, честный zkML (`zero_knowledge:false`), `STELL_AUTO_UPGRADE` OFF; **W8.4** — MEV epoch seal (Feldman DKG / 128 блоков, ECDH+XChaCha20, `STX1`, order commitment, `stell_epochKey`); **W8.5** — кросс-шардовый 2PC (`src/xshard2pc.rs`, гейт `STELL_XPC_ACTIVATION_HEIGHT`); **W8.6** — ops-автоматизация + preflight-находки живого кластера; **W8.7** — внешний аудит-пакет + 3 новых fuzz-таргета | `src/runtime.rs:4176-4232`, `src/consensus.rs:3402`, `tests/consensus_liveness_harness.rs`, `tests/consensus_liveness_repro.rs`, `src/sync.rs:50`, `src/mev_epoch.rs:81` / `:1616`, `src/xshard2pc.rs`, `scripts/stell-sync.sh`, `docs/audits/EXTERNAL_AUDIT_BRIEF.md` |
| **W9** | Проверяемость артефактов: **W9.1** — верификация исходников контрактов (`stell_verifyContractSource` / `stell_getContractSource` / `stell_registerContractSource`); **W9.2** — стандарт подписи кошелька (EIP-191-подобный преимаж с chain-id, envelope v1, `stell_signMessage`/`stell_verifyMessage`/`stell_signTypedData`/`stell_verifyTypedData`, `docs/WALLET_SIGNING.md`); **W9.3** — archive proofs (`stell_getArchiveProof` / `stell_getHistoricalRoot`, снимки каждые 1000 высот) | `src/contract_source.rs`, `src/rpc.rs:5790` / `:5890` / `:5930`, `src/wallet_signing.rs:48` / `:53` / `:57` / `:94`, `src/cpat2.rs:899`, `src/rpc.rs:3038` / `:3101` |
| **W10** | Живой форк + пентесты + верификации: **W10.1** — fork-heal #288000 (неатомарный `commit_native` → атомарный undo + pre-mutation отказы + `DIVERGENCE`-лог + `stell_divergence_total` + офлайн `stelops diverge`); **W10.2** — faucet-fix (дрипы на шард получателя, отказ до резерва nonce/cap); **P1** — P2P-пентест (6 fixed + 5 filed G1–G5); **P2** — mempool-пентест (pool-level `admission_shard`-пин, 1 leak-fix, legacy-replay ESCALATED); **P3** — BFT-пентест (R1/R2 fixed, 2 escape-варианта задокументированы); **P4** — крипто-пентест (0x29-канон запиннен, Debug-утечки закрыты, 24-батарея); **P5** — RPC/auth/bridge/staking-пентест (3 CRITICAL fixed + mint-cap + staking/token/contract); **V-P1/V-P2/V-P34** — независимые верификации; **E1** — OS-оценка (scorecard + бэклог 22 шт.) | `src/state_engine.rs:3355` (undo) / `:3405` (pre-mutation) / `:11930` (`fork288000_*`), `src/runtime.rs:3962` (DIVERGENCE), `src/metrics.rs:82`, `scripts/tools/stelops/src/main.rs:594`, `src/rpc.rs:2411` (`resolve_faucet_recipient`), `src/mempool.rs:1508` (pool-pin), `src/consensus_net.rs:2079` (P1-F1) / `:3012` (8/tick), `tests/p2_mempool_pentest.rs`, `tests/p3_byzantine_pentest.rs`, `tests/p4_crypto_pentest.rs`, `tests/vp2_verify.rs`, `tests/v34_verification_pentest.rs`, `tests/pq_fork288000_replay.rs` |

| **W11 (STAB/TAIL-1/VEL/MMR)** | Перф-хлесты без смены протокола: **STAB** — verify-once кэши (order-root/batch-verdict/proposer-sig/QC-power per block-hash, `src/runtime.rs:778-800`, ключи `:4212`/`:4229`) + MMR-кэш эпох (`src/chain.rs:215-231`, `:526`) + slow-validation метр (`SLOW_VALIDATION_THRESHOLD_MS=500`, `:799`, тест `:7817`); **TAIL-1** — per-domain generation кэш commitment (`src/commitment.rs:2213`, `DomainCache`/`DomainGenerations`, `src/state_engine.rs:376-395`) + батчированные receipt-хэши (`src/rpc.rs:12832`); **VEL** — 0.5s-харнесс `tests/block_tempo_lan.rs` (LAN 100 высот + WAN-контраст 20 высот); **MMR** — epoch roots в блоках (`Block::mmr_epoch_root`, `src/sharding.rs:5001`; proposer `:runtime.rs:1263`, проверка `:1295`) + `stell_getEpochRoot` (`src/rpc.rs:4398`) | `src/runtime.rs:778`, `src/chain.rs:526`, `src/commitment.rs:2213`, `src/rpc.rs:12832` / `:4398`, `tests/block_tempo_lan.rs`, `tests/mmr_epoch_root_tests.rs` (3/3), `src/light_client.rs:706-862` (verify) |
| **W11 (SDK/B9/surfaces)** | DX-закрытия: **B2** — крейт `stellereum-sdk` (TxBuilder transfer/token/stake/deploy/call, `predict_contract_address` = функция ноды, byte-equality пины `tests/canonical.rs` 12/12); **B9** — Logs-страница `/events` в explorer (ABI-декодирование индексером, build exit 0); **paymaster** v1 (`Transaction::sign_with_sponsor`, `sponsor_balance_of`, `AdmissionCtx::with_sponsor_balance`, `tests/paymaster_tests.rs` 21/21); **privacy-path** (`stell_shieldedTransfer`/`stell_shieldedBalance`/`stell_unshield`, `tests/shielded_path_tests.rs` 4/4); **token-burn-admin** (`stell_tokenBurn`, self-burn + minter admin-burn, `src/native_api.rs:956`); **order** (`stell_placeOrder`/`stell_cancelOrder` + one-call, `tests/one_call_order_placement_tests.rs` 7/7); **bridge** (`stell_bridgeDepositPrepare`/`stell_bridgeWithdraw`/`stell_bridgeStatus` + truth-gate W7.1) | `stellereum-sdk/src/lib.rs`, `stellereum-sdk/tests/canonical.rs`, `explorer-site/explorer/src/pages/Events.tsx`, `src/sharding.rs:3880`, `src/state_engine.rs:1747`, `src/mempool.rs:300`, `src/native_api.rs:162` / `:316` / `:380` |

### 0.3. Актуальная таблица возможностей (переписанная таблица сравнения PART I, §4)

Таблица PART I §4 оставлена дословно ниже. Здесь — та же сетка строк с **текущим**
статусом, перепроверенным по коду **2026-10-23**. 🟡 означает «код написан и покрыт
тестом, но живое доказательство (split, внешняя церемония, живой прогон) ещё не
предъявлено».

| Возможность | Статус | Доказательство (метод / файл / тест) | Что всё ещё отсутствует |
| :--- | :--- | :--- | :--- |
| **Консенсус** | ✅ | `note_peer_vote_round` доводит раунд до раунда пира в пределах бюджета (`src/runtime.rs:4176-4232`, кап `src/consensus.rs:3402`); W10: precommit-путь загейчен верификацией как prevote (`src/runtime.rs:4710-4721`, `observe_peer_vote` `:4309`), R2 — verify-grade attribution + fail-closed slash-гейт (`src/state_engine.rs:6010-6046`); DIVERGENCE-аларм (`src/runtime.rs:3962-3990`, `stell_divergence_total`); harness 13+1 ignored — `tests/consensus_liveness_harness.rs`; repro 14/15 (1 stale-ожидание под новый бюджет); V-P34 13/13 — `tests/v34_verification_pentest.rs` | `validRound`+Polka-QC нет (мягкий unlock); сортиция grindable; proposal-equivocation evidence type отсутствует (P3-escape) |
| **Шардинг** | 🟡 | P2P-транспорт `src/network.rs:2549`, `stell_getShards`, split/merge-машина `src/sharding.rs:1886`, миграция trie, 2PC `src/xshard2pc.rs`. W10: фауцет роутит дрипы на шард получателя (`resolve_faucet_recipient`, `src/rpc.rs:2411`), pool-level `admission_shard`-пин на всех путях (`src/mempool.rs:1508-1517`, стартовый пин `src/main.rs:401`), V-P2 16/16 — `tests/vp2_verify.rs` | **Живой split не проведён**; перенос repartitions между узлами не реализован; 2PC за гейтом и не финализирован вживую (A2, A3); legacy cross-chain replay жив (P2-escalation) |
| **Deploy RPC** | ✅ | `stell_deployContract` (`src/rpc.rs:4581`+) + W9.1-верификация исходника `stell_verifyContractSource` (`src/rpc.rs:5790`). W10 (P5): contract-arms требуют auth-токен (`src/rpc.rs:8782`), wrapped-deploy проверяет подпись (`:8890`); mint-cap-cycle запиннен (`bridge::p5_revoke_cycle_cannot_reopen_mint_cap_headroom`) | Ничего в коде; остаток — UX (готовые SDK теперь есть, см. ABI) |
| **Call RPC (write)** | ✅ | `stell_callContract` (`src/rpc.rs:4795`+) с наблюдаемым outcome. W10 (P5): `from` обязан совпадать с подписантом (`src/rpc.rs:8837` `p5_call_contract_from_must_equal_signer`) | Ничего в коде |
| **Getter** | ✅ | `stell_runGetMethod` (`src/rpc.rs:4388`+) read-only, пин к block hash | Ничего в коде |
| **ABI** | ✅ | STELL-ABI v1 + codegen Rust/TS (`src/contract_abi.rs`, `src/bin/abi_codegen.rs`, манифест `contracts/sts20_token_abi.json`). **W11: крейт `stellereum-sdk`** — TxBuilder transfer/token/stake/deploy/call, адрес через функцию ноды, byte-equality пины `stellereum-sdk/tests/canonical.rs` 12/12 (прогон REP2) | B2 закрыт кодом (см. ЧАСТЬ IV) |
| **События** | ✅ | VM→receipt→storage→RPC end-to-end; индексер декодирует по ABI (`stellereum-indexer/src/db.rs:201-222`, `tests/indexer_api_tests.rs`). **W11: Logs-страница `/events`** в explorer (`explorer-site/explorer/src/pages/Events.tsx`, маршрут `:36`) с ABI-статусом из `stell_getContractAbi`; build exit 0 (REP2: `index.html` 1.06 kB, `index-*.js` 70.42 kB, `vendor-*.js` 179.53 kB) | B9 закрыт кодом (см. ЧАСТЬ IV) |
| **WS / стрим** | ✅ | WebSocket + SSE с finality-тегами и invalidation-событием (W3) | Ничего известного |
| **Fork-choice** | ✅ | ChainManager подключён, invalidation публикуется (`src/chain.rs:692`, `src/main.rs:2331`, `src/rpc.rs:5718`) | Ничего известного |
| **Light client** | ✅ | Sync-путь проверяет пирские блоки против якоря (`src/sync.rs:50` `verify_synced_blocks_against_anchor`); внешний CLI `stellereum light-client --from --verify`; `stell_getFinalizedHeader`/`stell_getFinalizedCheckpoint` (`src/rpc.rs:4176` / `:4199`). **W11: epoch roots** — `Block::mmr_epoch_root` (`src/sharding.rs:5001`) коммитит предыдущую эпоху на границе (`commits_epoch_root`, `src/mmr.rs:91`; proposer `src/runtime.rs:1263`, проверка `src/runtime.rs:1295-1310`), `stell_getEpochRoot` (`src/rpc.rs:4398`) + клиентская проверка (`src/light_client.rs:706-862`); пины `tests/mmr_epoch_root_tests.rs` 3/3 (прогон REP2) | Нет ротации валидатор-сета, нет собственного fetch заголовков, нет обработки eclipse/partition (зафиксировано в шапке `src/light_client.rs`) |
| **Кросс-шардовые вызовы** | 🟢 (post-wave) | 2PC-машина: PREPARE/PREPARE-ACK/COMMIT/ABORT, монотонные фазы, восстановление из committed, bounce византийского источника отбит; `XPC_ACTIVATION_HEIGHT = 0` (`xshard2pc.rs:146`), двухшардовый soak (`scripts/soak_two_shard.sh`); credit counter + mailbox pruning | Живой двухшардовый прогон есть; live shard-1 остаётся PARKED, перенос состояния между узлами отсутствует |
| **VM** | ✅ | wasmi + 13 host-импортов (`src/contract.rs:1107`), лимиты, события | Ничего известного |
| **PQ-крипто** | 🟡 | Falcon-512 FIPS 206 (`src/post_quantum.rs:1346`), chain-id в голосах/блоках, µQC network-anchored quorum. W10 (P4): 24-атаковая батарея 24/24 — `tests/p4_crypto_pentest.rs`; 0x29-канон запиннен, 0x39 отвергается (`src/post_quantum.rs:2185-2257`, `tests/v34_verification_pentest.rs:553`); Debug-утечки закрыты ручными impl (`src/mev_v4.rs:299,516,686`) | BLS-QC включить нельзя (нет PoP, OPEN); legacy-путь ~2³² жив ради genesis root (MITIGATED); 0x29-vs-0x39 — осознанная interop-стена (ACCEPTED) |
| **MEV** | 🟡 | Epoch seal в коде: Feldman DKG каждые 128 блоков (`src/mev_epoch.rs:81`), ECDH+XChaCha20, AAD, `STX1` (`:1616`), order commitment в хэше блока, `stell_epochKey` (`src/rpc.rs:3899`); 25 тестов `tests/mev_epoch_seal_tests.rs`; V-P34 seal-ledger держится (`v34_p5_seal_leakage_ledger_holds_for_five_txs`); shares идут pool-gossip (`MevFrame::Release`), не в голосах — alignment записан с обеих сторон (`stellereum/docs/MEV.md` §5.6 + V5-спек §4, REP2) | Честные остатки `docs/MEV.md` §4.3: скомпрометированный комитет читает эпоху; liveness DKG; ключ из текущего view сета, не из beacon; дроп sealed-транзакции без on-chain fee |
| **Приватность** | ✅ | Pedersen/stealth/viewing keys аккуратно; опциональный путь. **W11: privacy-path поверхности** — `stell_shieldedTransfer` / `stell_shieldedBalance` (read) / `stell_unshield` (`src/native_api.rs:380-394`, PREPARE/READ-разделение `:2523`); пины `tests/shielded_path_tests.rs` 4/4 (прогон REP2) | Per-key proofs не-trie доменов отсутствуют (P3) |
| **Финализация** | ✅ | Моментальный BFT-финал; light-client-якорь — precommit-QC | Ничего известного |
| **Аудит** | 🟡 | Внешний аудит-пакет готов: `EXTERNAL_AUDIT_BRIEF.md`, `INVARIANTS.md` (80 шт.: 78 PINNED + 2 PARTIAL), `KNOWN_ISSUES.md`, `THREAT_MODEL.md`, `scripts/audit-repro.sh`, 7 fuzz-таргетов | **Сам внешний аудит не проведён** (A1, владелец — организация) |
| **Тесты** | 🟡 | lib **1034 passed, 0 failed** (REP2 2026-10-28, 20.31 с); TAIL-1 дифференциальные пины 4/4 (`cached_assembly…`, `randomized_mutations…`, `abi_json_cache…`, `record_receipts_batched…`) + perf-пробы; VEL-харнесс 2/2 (`block_tempo_lan`: LAN mean 350 мс, WAN mean 690 мс, собственным прогоном); W11-сьюты: paymaster 21, shielded 4, one-call-order 7, mmr-epoch-root 3, SDK-canonical 12; корпус 2184 файла | Полный `--tests --no-fail-fast` REP2 не перегонялся (scope: lib + адресные сьюты); V5 S1–S29 в этом дереве отсутствуют — UNVERIFIED (см. секцию REP2) |

---

## ЧАСТЬ I. ИСХОДНАЯ ОЦЕНКА И АРХИТЕКТУРНЫЙ КОНТЕКСТ

Пересмотренная оценка с учётом позиционирования сети как не-EVM, шардированной архитектуры уровня TON / Near / MultiversX.
Проведён глубокий анализ кодовой базы (~91k строк Rust в src/, + крейт infnode, + отдельный репозиторий stellereum-contracts), включая запуск тестов, проверку живой сети и сравнение с production не-EVM L1. Итог ниже — честный, без прикрас.

### 1. Общая оценка

| Критерий | Оценка | Комментарий |
| :--- | :--- | :--- |
| **Целостность кода** | ★★★★☆ 7.5/10 | Реальный, честный код. 2 TODO, 0 unimplemented!/todo!. Есть мёртвый код и незакоммиченные правки, ломающие 10 тестов |
| **Консенсус** | ★★★★☆ 8/10 | Tendermint-BFT полностью реализован, работает вживую (1319 блоков за 12 мин на shard 0). Но fork-choice не подключён к ноде |
| **Криптография** | ★★★☆☆ 6.5/10 | Ed25519/BLAKE3/X25519 — solid. Falcon-512 — самописный (~2.3k строк). zk-SNARK — не настоящий ZK. BLS — есть, но выключен |
| **Смарт-контракты** | ★★★☆☆ 5.5/10 | Безопасный WASM-песочниц (wasmi), но ABI — (i64)->i64, всего 3 хост-импорта, нет RPC деплоя/вызова/getter, события теряются. Для не-EVM сети — это главный блокер экосистемы |
| **Хранилище/стейт** | ★★★★☆ 7.5/10 | Собственный Patricia-Merkle (blake3), BoC-ячейки, pruning, snapshot-sync через DHT. Но нет SPV-доказательств по слотам, нет per-key archive proofs |
| **Шардинг** | ★★★☆☆ 5.5/10 | Masterchain + 2 shardchain, заявлен infinite dynamic sharding, но shard 1 завис на живой сети, split/merge не продемонстрированы |
| **P2P/сети** | ★★★★☆ 7/10 | QUIC+TLS, Kademlia DHT, TOFU-пиры — реально работает в WAN (4 узла, Россия). Проблемы с латентностью |
| **Тесты** | ★★★★★ 9/10 | ~2025 тестов, fuzzing-корпусы 2049 файлов, adversarial-регрессии. Один из лучших показателей среди подобных проектов |
| **Документация** | ★★★★☆ 8/10 | PROTOCOL.md и README честно указывают на свои пробелы — редкость |
| **Production-readiness** | ★★☆☆☆ 4.5/10 | Сеть живёт, но: нет reorg-пути, нет контрактного RPC, нет light client, нет WS, MEV-защита отложена, ключи открытым текстом |

**Общий балл:** ~6.5/10 как прототип/тестнет, ~4.5/10 как production L1.

Оценка смарт-контрактов и шардинга понижена относительно EVM-бенчмарка: для сети, позиционирующей себя как TON-подобная, отсутствие deploy/getter RPC и доказанного split/merge — не «недостаток относительно Ethereum», а незакрытая базовая функциональность самой архитектуры.

---

### 2. Что реально есть и работает

#### Консенсус — полноценный BFT
- Tendermint-style: propose → prevote → precommit → commit. Round-robin пропорер.
- Lock-механика, equivocation evidence, downtime slashing (сжигание реального стейка) — всё реализовано и покрыто тестами.
- Доказано вживую: 4-нодовая WAN-сеть (Россия: 3 узла + этот), 1319 финализированных блоков за 12 минут на shard 0, ротация пропореров корректна.

#### Криптография — в основном честная
| Примитив | Статус |
| :--- | :--- |
| **Ed25519 (dalek)** | ✅ Работает, batch verify |
| **BLAKE3 / SHA-256** | ✅ Работает |
| **X25519 + ChaCha20-Poly1305** | ✅ Работает (шифрование нод/кошелька) |
| **BLS12-381** | ✅ Реальная, но выключена по умолчанию |
| **Falcon-512 (PQ)** | ⚠️ Работает, но самописная (не аудированная библиотека) |
| **ML-DSA-44** | ❌ Отключена как «куемая» |
| **zk-SNARK** | ❌ Не настоящий ZK — повторный forward-pass, без zero-knowledge и без сжатия |
| **Pedersen/stealth (Ristretto)** | ✅ Реализовано аккуратно |

#### Контракты
- WASM-исполнитель (wasmi 2.0) с жёсткими лимитами: 256 KiB код, 50M fuel, 16 MiB память, 4096 ключей storage. Песочница — всего 3 хост-импорта (sload, sstore, emit). Сами по себе — безопасны.
- 4 реальных контракта на .wat (STS-20 токен, ликвидный пул, DNS-реестр, account-object) — рабочие, проходят e2e-тесты.
- Дополнительно ~45-opcode собственный SVM для транзакций: CLOB-ордербук, стейкинг, bridge, конфиденциальные переводы, оракул, PMM — уникальная для не-EVM сетей глубина системных операций.

#### Хранилище
- Собственный сжатый Patricia-Merkle (blake3), BoC-ячейки в духе TON, state commitment v5, pruning (50k блоков), snapshot-restore с верификацией корня, синхронизация снапшотов через DHT.

#### Тестирование
- ~2025 тестов — включая adversarial-регрессии (20 штук, повторяющих закрытые атаки), fuzzing-корпусы на декодеры (2049 файлов), 4-нодовые adversarial-сценарии. Серьёзный уровень, выше среднего для L1 любой архитектуры.

---

### 3. Чего НЕ хватает по сравнению с не-EVM шардированными сетями (TON / Near / MultiversX / Solana)

#### 🔴 Критические пробелы (блокеры экосистемы)
1. **Нет deploy / call / getter RPC — контракты недоступны внешним разработчикам**
   - Deploy/call возможен только рукопостроенной bincode-транзакцией с OpCode (examples/deploy_live_contracts.rs — единственный референс).
   - Нет read-only getter — ни аналога TON runGetMethod, ни NEAR call_function, ни MultiversX vm-values/query.
   - Нет write-call с наблюдаемым outcome — ни аналога NEAR receipt (success/failure, return value, gas used, events), ни MultiversX ReturnCode.
   - Сравнение: TON (StateInit + sendBoc + runGetMethod), Near (DeployContract + query call_function + NEP-297 outcomes), MultiversX (vm-values/query + JSON ABI + structured logs), Solana (BPF-loader + simulateTransaction). У всех четырёх есть все три примитива. У Stellereum — ни одного. Это главный блокер: без этого ни один внешний разработчик не напишет контракт.
   - Кошельки, индексеры, бриджи — всё зависит от этого слоя.
2. **События контрактов теряются на пути блока**
   - svm.rs:1499 отбрасывает _events при исполнении на пути блока. VmExecutionResult их не содержит. StoredReceipt — log-free.
   - host.emit вызывается контрактами (в т.ч. рабочими .wat), оплачивается — и результат выбрасывается. Ни в receipt, ни в eth_getLogs, ни в фильтры, ни в эксплорер.
   - Сравнение: NEAR (NEP-297 — структурированные логи в outcome), MultiversX (identifier+topics+data + WS subscribeEvents), Solana (meta.logMessages + WS logsSubscribe), TON (хотя бы сырой материал — messages/traces — сохраняется и выводится оффчейн через /v3/actions, /v3/traces). Stellereum — ни одного из двух школ: нет ни on-chain логов, ни сохраняемого сырого материала для оффчейн-производной.
3. **Нет fork-choice / reorg / invalidation-сигнала в живой ноде**
   - chain.rs (ChainManager, choose_head, reorg_plan) — написан и протестирован, но не подключён к main.rs. Живая нода принимает только блоки, продолжающие finalized head. Два конфликтующих QC на одной высоте = постоянный раскол сети, который ПО не умеет чинить.
   - Даже для моментальной BFT-финализации это критично: TON (indexer: pending/confirmed/finalized + trace_invalidated — кандидаты шарда могут быть вытеснены до коммита masterchain), MultiversX (notifier: явные revert_events + finalized_events), Solana (3 уровня commitment), Near (final vs. sync). Split/merge шарда сам по себе может осиротить view клиента — нужен хотя бы invalidation-сигнал, которого нет.
4. **Нет light client**
   - light_client.rs скомпилирован и протестирован, но ничего его не вызывает (закреплено тестом audit_rpc_evm_closeout.rs). SPV-проверка баланса есть, но «узел сам выдаёт корень, в который верит» — не доказательство для внешнего верификатора.
   - Сравнение: Near (полный протокол next_light_client_block + on-chain LC за Rainbow bridge), Sui (checkpoints + authenticated events + sui_light_client), Aptos (proof-complete примитивы + ZK LC), TON (proof-доки полные, key-block bootstrap — в работе), MultiversX (roadmap), Solana (незрелый). Momentary BFT-финализация делает LC для Stellereum проще, чем для TON — нет fork-choice для симуляции, но кода нет.
5. **Нет WebSocket / стриминга**
   - Только HTTP POST JSON-RPC, batch-запросы запрещены. Ни одного механизма подписки.
   - Сравнение: TON Streaming v2 (SSE+WS с finality-тегами), Near (query subscription), MultiversX (WS subscribeEvents/subscribeCustomEvents), Solana (logsSubscribe/slotSubscribe/accountSubscribe — у сети без нативных событий WS-логи есть). Даже Solana, у которой нет нативного примитива события, первой сделала WS-поток логов.
6. **Шардинг не продемонстрирован; shard 1 завис**
   - check_and_split/check_and_merge существуют в коде, но на живой сети shard 1 замёрз (0 блоков, раунды крутятся, 6 транзакций в мемпуле), открытая диагностика «stand blackhole hunt». Ни одного успешного split/merge в проде.
   - Нет RPC get_shards (аналог TON liteServer.getShards, Near shard_layout) — кошельки/индексеры не shard-aware.
   - Shard-head набор + state root не публикуются в каждом masterchain-блоке (TON shard_hashes) — кросс-шардовые доказательства невозможны.
   - Сравнение зрелости шардинга (2026): Near (dynamic resharding в проде с 2.13, авто-split за ~1.5 эпохи) > MultiversX (6 лет в проде, Supernova 2026) > TON (production cap 16 шардов, обычно 4–8 активных, threshold split/merge) > Sui/Aptos (сознательно не шардятся) > Stellereum (дизайн заявлен, не продемонстрирован).

#### 🟡 Существенные пробелы
7. **ABI контрактов — (i64)->i64 один аргумент**
   - Параметры пакируются руками: from*100_000_000 + to*100_000 + amount. Нет multi-arg, нет typed returns, нет memory-sharing, нет calldata blobs, нет JSON/BoC ABI-манифеста.
   - Сравнение: Near (ABI JSON + cargo near abi codegen), MultiversX (JSON ABI → SDK typing + event decoding), TON (Tolk/Blueprint ABI). Все имеют именованные методы + мульти-арг + типизированные возвраты без EVM.
   - Плюс 256 KiB cap кода — Rust→wasm32 с SDK-зависимостями обычно даёт 150–400 KB. Молчаливый убийца сложности контрактов (Near ~4 MB).
8. **Всего 3 хост-импорта (sload/sstore/emit)**
   - Нет: caller/value/block_time/block_hash, нет send_message (кросс-шардовый вызов + reply), нет sha256/blake3, нет ed25519_verify, нет input/return.
   - Нет кросс-шардового вызова контракта — без него каждый dApp вынужден быть single-shard, что обнуляет смысл шардинга. TON (message routing), Near (receipts) — оба делают это асинхронно с callback/reply из коробки.
9. **MEV-защита — заявлена, но отложена**
   - Shamir threshold: раунд-ключ локален для ноды, пропорер всё равно видит транзакции. Полноценная защита требует асимметричного sealing, раунда share-release и sealed gossip — ничего из этого нет на wire. README это честно признаёт.
10. **Приватность — есть, но не наследуемая архитектура**
    - Pedersen commitments, stealth addresses, viewing keys — реализованы и работают аккуратно. Но конфиденциальные транзакции — опциональный путь, а не стандарт сети (в отличие от Zcash, Penumbra).
11. **Приватные ключи нод лежат открытым текстом**
    - keys/identity.key — сырой hex без парольной фразы. Есть отличный зашифрованный формат (enc2: Argon2id + XChaCha20), но по умолчанию не используется. Кошелёк — BIP-39-подобный, но seed = проприетарный SHA-256, несовместим с чем-либо кроме своего CLI.
12. **BLS отключён → при 100+ валидаторах 100+ Ed25519-подписей в сертификате**
    - PROTOCOL.md сам это признаёт. Near, Cosmos, Aptos — используют агрегацию/BLS из коробки.
13. **Нет fee-estimation RPC**
    - Ни аналога TON estimateFee, ни MultiversX /transaction/cost, ни задокументированного правила address→shard. Кошельки не могут предсказать стоимость.

#### 🟢 Мелкие / гигиенические
- 4 мёртвых зависимости: pqcrypto-falcon, pqcrypto-traits, group 0.13, ff 0.13 (0 использований)
- sled — фактически не поддерживается (последний релиз 2022), сжатие парсится, но не включается
- 22 дублирующихся версии крейтов в lockfile (rand 0.8 + 0.10 и т.д.)
- fuzz/Cargo.toml указывает на несуществующий абсолютный путь → fuzzing сломан на чистом клоне
- Git-tracked каталог --help/ (артефакт случайной команды) в корне репо
- CI: только build+test. Нет clippy, rustfmt, cargo audit, fuzz-прогона, coverage
- Дрейф документации: блочный газ 500M в коде, но 120M в доках; README всё ещё говорит «999 passing» — сейчас их ~2025
- Нет SDK / codegen из ABI; нет devnet-симулятора с state snapshot; нет explorer с декодированными событиями; нет стандартных интерфейсов для нативных возможностей SVM (токен/бридж/стейкинг/CLOB), чтобы кошельки интегрировались один раз

---

### 4. Прямое сравнение с не-EVM шардированными сетями

| Возможность | Stellereum | TON |
| :--- | :--- | :--- |
| **Консенсус** | Tendermint-BFT ✅ | PoS + catchain |
| **Шардинг** | Заявлен, 1 завис, split/merge не показан | Threshold split/merge, cap 16, обычно 4–8 |
| **Deploy RPC** | ❌ | ✅ sendBoc + StateInit |
| **Call RPC (write)** | ❌ | ✅ async message |
| **Read-only getter** | ❌ | ✅ runGetMethod |
| **ABI** | ❌ (i64)->i64 | Tolk/Blueprint ABI |
| **События/logs** | ❌ теряются | ⚠️ оффчейн из messages/traces |
| **WebSocket/стрим** | ❌ | ✅ SSE+WS, finality + invalidate |
| **Fork-choice/invalidation** | ❌ | ✅ trace_invalidated |
| **Light client** | ❌ (код есть, не подключён) | ⚠️ proof-доки, bootstrap в работе |
| **Кросс-шардовый вызов контрактов** | ❌ | ✅ message routing |
| **Свой VM** | wasmi (3 хост-импорта) | TVM |
| **Пост-квантовая крипто** | Falcon (самописный) | ❌ |
| **MEV-защита** | Отложена | ❌ |
| **Конфиденциальность** | Pedersen/stealth | ❌ |
| **Моментальная финализация** | ✅ | ~5 с |
| **Аудит внешними** | ❌ | Частично |
| **Тесты** | ~2025 ✅ | Много |

**Вывод по сравнению:** как не-EVM шардированный L1 Stellereum архитектурно корректен (BFT + masterchain/shards + BoC + bounce + собственный VM — настоящая TON-линия, а не имитация), и по криптографии/тестам/честности документации обгоняет MultiversX и приближается к Near. Но по базовой контрактной и шардовой функциональности он сейчас примерно на уровне TON-подобных сетей 2021–2022 года: контракты существуют on-chain, но недоступны внешним разработчикам, события выбрасываются, шардинг не продемонстрирован. Ключевые конкуренты (Near, MultiversX) закрыли эти слои годами ранее — и именно эти слои, а не EVM, являются правильным ориентиром.

---

### 5. Что честно сделано хорошо
1. PROTOCOL.md и README прямо перечисляют свои пробелы — редчайшее качество для L1-проектов. «Нет light client», «MEV отложен», «archive не коммитится per-key» — написано без маркетингового шума.
2. Adversarial-регрессии — 20 тестов буквально повторяют каждую закрытую атаку. Так делают только зрелые проекты.
3. Fail-closed философия — слабый валидатор становится observer, устаревший validator set → отказ, пустой bridge quorum → отказ.
4. Fuzzing с закоммиченными корпусами (2049 файлов) на все декодеры.
5. Тесты гоняются на живой сети — 4 узла в реальном WAN.
6. Глубина нативного SVM (CLOB, оракул, bridge, PMM, confidential, session keys, staking) — уникальна среди не-EVM сетей; Near/MultiversX такого набора системных операций на уровне VM не имеют.
7. Архитектурная линия TON выдержана последовательно: BoC-ячейки, bounce-семантика, masterchain как hub, моментальная BFT-финализация, собственный trie — это не «EVM-сеть без EVM», а осознанная альтернатива.

---

### 6. Приоритеты для Production L1

#### P0 — контрактный жизненный цикл (без этого ничего остального не имеет смысла):
1. `deploy(code, data)` RPC — адрес = hash(code,data), shard по префиксу адреса, bounce при отказе (модель TON StateInit + fixed_prefix_length)
2. `call(contract, method, args, value, fuel)` RPC с наблюдаемым outcome: success/failure, return value, gas used, events (модель NEAR receipt / MultiversX ReturnCode)
3. Read-only getter RPC `run_get_method(addr, method, args)` — без побочных эффектов, без fuel, пин к block hash (модель TON runGetMethod / Near call_function / MultiversX vm-values/query)
4. Сохранение событий `{emitter, topics[], data}` в outcome + в блок + get_events(tx) + исторический индекс (схема NEAR NEP-297 — самый дешёвый вариант)
5. Расширить хост-импорты: caller/value/block_time/block_hash, send_message (кросс-шард + reply), sha256/blake3, ed25519_verify, input/return — минимум для осмысленных контрактов

#### P0 — потоковая передача:
6. WebSocket / SSE с: новыми блоками, новыми событиями (фильтр по контракту/topic), статусом tx. Добавить finality-теги (pending/confirmed/finalized) + invalidation-событие для split/merge шарда (модель TON Streaming v2)

#### P1 — шардинг и доказательства:
7. Починить shard-1 stall и провести воспроизводимые load-тесты check_and_split/check_and_merge на testnet; опубликовать пороги; честно ограничить заявление (TON заявляет 2^60, но шипит cap 16 — это отраслевая норма честности)
8. RPC `get_shards(masterchain_block)` → активные shard id + heads (модель TON liteServer.getShards, Near shard_layout)
9. Публиковать shard-head набор + state root в каждом masterchain-блоке (модель TON shard_hashes) — фундамент для light client и бриджей
10. `estimate_fee` RPC + задокументированное правило address→shard

#### P1 — light client:
11. Определить Merkle inclusion/exclusion proof поверх blake3 Patricia-Merkle trie (BoC-ячейки ложатся естественно — переиспользовать идею pruned-branch/proof-cell из TON); RPC `get_block_header_proof(root_hash)`; BFT-набор подписей для key-blocks masterchain; клиент-библиотека (эквивалент lite-client). Momentary BFT-финализация делает это проще, чем для TON — нет fork-choice для симуляции.

#### P2 — DX-паритет:
12. ABI-манифест (JSON/BoC) с именованными методами, мульти-арг, типизированные возвраты + SDK codegen (Rust/TS)
13. Локальный devnet + chain simulator (state snapshot, deterministic replay, fee preview)
14. Стандартные интерфейсы для нативных возможностей SVM (токен/transfer, bridge, staking, CLOB events) — чтобы кошельки интегрировались один раз (модель NEAR NEP-141/171, TON TEP-74/jetton)
15. Explorer с декодированными событиями + верификацией исходников; faucet; стандарт подписи кошелька
16. Пересмотреть 256 KiB cap кода (Near ~4 MB) — молчаливый убийца сложности

#### Общие:
17. Починить 10 упавших тестов (незакоммиченные правки round-reset ломают deadlock-breaker)
18. Приватные ключи нод — зашифрованные по умолчанию (формат enc2: уже есть)
19. Внешний аудит (критично для любого L1)
20. Выбросить 4 мёртвые зависимости, починить fuzz-путь, добавить clippy/audit в CI
21. Заменить самописный Falcon на аудированную библиотеку (liboqs и т.п.)

---


## ЧАСТЬ II. ДЕТАЛЬНЫЕ РЕЗУЛЬТАТЫ АУДИТА 7 СПЕЦИАЛИЗИРОВАННЫХ АГЕНТОВ

> Текст находок ниже — **исходный, без изменений** (это baseline). Под каждой находкой
> добавлена строка **СТАТУС**, проверенная по коду на 2026-10-21.

### Агент 1: Консенсус и BFT-безопасность (`consensus.rs`, `runtime.rs`)

1. **[CRITICAL] Инвертированная проверка блокировки в `adopt_committed` (`runtime.rs:3985-3988`):**
   ```rust
   if let Some((locked_block, locked_round)) = self.hc.locked {
       if locked_round <= certificate.round && locked_block != bh {
           return Err("refusing to adopt a block that contradicts our lock".to_string());
       }
   }
   ```
   Узел, залоченный на блоке $A$ в раунде 0, при получении канонического сертификата на блок $B$ в раунде 1 отказывается его принять ($0 \le 1 \implies \text{true}$), перманентно раскалывая сеть. Блокировка должна запрещать только принятие противоречащих блоков из **прошлых или равных** раундов ($r < r_{\text{lock}}$), но не канонических коммитов из старших раундов.

   > **СТАТУС: FIXED.** Условие инвертировано на противоположное по смыслу: конфликтный
   > блок отвергается только если сертификат **не старше** раунда замка.
   > `src/runtime.rs:4693-4697` — `if certificate.round <= locked_round && locked_block != bh`.
   > Комментарий в коде прямо называет старый дефект («the old `locked_round <= certificate.round`
   > test refused exactly that and partitioned the node»).
   > **Тесты:** `tests/consensus_reaudit_tests.rs:416` (`a_later_round_certificate_supersedes_the_lock`),
   > `:434` (`a_same_round_certificate_naming_another_block_is_refused`),
   > `:455` (`an_earlier_round_certificate_naming_another_block_is_refused`),
   > плюс `tests/adopt_prevote_tests.rs:134` (`anti_lock_adoption_is_refused`) и `:149`
   > (`adopting_the_locked_block_succeeds`).

2. **[HIGH] Отсутствие механизма `validRound` в предложениях (`consensus.rs:2224, 2286-2296`):**
   В CometBFT/Tendermint пропозер при переходе раунда обязан прикладывать `validRound` и Polka-QC, на основе которого залоченные валидаторы снимают лок и голосуют за новое значение. В Stellereum этого нет: если $>1/3$ залочились в раунде 0, в раунде 1 они будут голосовать nil вечно, вызывая тупик liveness.

   > **СТАТУС: MITIGATED.** Полного CometBFT-механизма (`validRound` + Polka-QC в теле
   > предложения) по-прежнему нет, но линковый тупик закрыт двумя механиками:
   > (а) **validRound-lite** — `lock_hint` на nil-prevote несёт залоченный блок
   > (`src/main.rs:923-929`), так что залоченный валидатор виден сети;
   > (б) **polka-unlock** — кворум prevote за *другое* непустое значение в **строго
   > более позднем** раунде снимает замок (`src/consensus.rs:3055-3079`).
   > **Остаточный риск:** unlock требует именно кворума prevote за непустое значение;
   > полноценный `validRound` с приложенным Polka-QC так и не реализован, поэтому
   > снятие замка по-прежнему зависит от того, что сеть успела сформировать кворум
   > (в терминах CometBFT — «мягкий» unlock, а не доказанный).

3. **[HIGH] Одно-голосный скачкообразный каскад раундов (`runtime.rs:2520-2543`):**
   Прием одного-единственного голоса из старшего раунда сбрасывает текущий шаг узла и переводит его в `Step::Propose` старшего раунда. В WAN при сетевом джиттере узлы обгоняют друг друга по очереди («leapfrog cascade»), не задерживаясь в раунде для сбора кворума.

    > **СТАТУС: MITIGATED (обновлено W8.1).** «Sit-while-armed» **откачен**: держать
    > раунд ради вооружённого соседа роняло сходимость двух armed-узлов на разных
    > раундах и ломало пин `round_nudge_reopens_gate_once_not_per_tick`. Вместо
    > удержания — **конвергенция**: `note_peer_vote_round` доводит локальный раунд
    > **до раунда пира** циклом `sync_round_to` в пределах существующего
    > побюджетного лимита (`MAX_SYNC_JUMPS_PER_ROUND`), строго вперёд, только по
    > проверенным голосам, сознательно без кворум-гейта — отставший узел всегда
    > следует за сетью. Дедуп `last_followed_round` по-прежнему означает «один голос
    > двигает один раз». `src/runtime.rs:4176-4232` (цикл — `:4225-4231`),
    > кап — `src/consensus.rs:3402-3424`.
   > **Тесты:** `tests/consensus_liveness_repro.rs` (14 passed + 1 stale-ожидание
   > под новый R1-бюджет, см. A9 — падает без фикса конвергенции),
   > `tests/consensus_liveness_harness.rs` (13 сценариев + 1 ignored, 0.82 с),
    > `tests/chase_livelock_tests.rs`, `tests/hunt_round_dos.rs`.
   > **Остаточный риск:** каскад «3 гонщика» (≥3 WAN-скошенных равномощных узла)
   > остаётся известной открытой формой; структурное лечение — jumps по кворуму
   > (≥2 различных голосующих), а не одностороннее следование.
   > **W10 (P3+V-P34, R1):** corroboration-дыра закрыта — precommit-путь шёл без
   > верификации (zero-key-подделки покупали +8 за свежий раунд), теперь гейчен
   > `observe_peer_vote` как prevote-путь (`src/runtime.rs:4710-4721`).
   > Одна проверенная ложь капирована одним sync-шагом (+8, `ROUND_LOOKBACK`),
   > реплей подавляется дедупом; два стейкнувших сговорщика тратят бюджет by design;
   > fresh-identity Sybil'ы membership-rejected. Пины: `v34_r1a`–`r1d`
   > (`tests/v34_verification_pentest.rs:90-241`), chase-набор
   > `tests/chase_livelock_tests.rs` (13/13). **Побочка:** старое ожидание
   > `a_vote_for_a_future_round_advances_us` (прыжок сразу на r25) устарело под
   > новый бюджет — см. A9.

4. **[MEDIUM] Иллюзорный сброс раунда в Deadlock Breaker (`consensus.rs:2823-2846`):**
   Лог сообщает о сбросе в раунд 0 (`[consensus] DEADLOCK-BREAKER local reset to round 0`), но код выполняет `self.round = self.round.saturating_add(1)`. Рассинхронизированные узлы не возвращаются к общей фазе.

   > **СТАТУС: FIXED.** Лог и поведение теперь совпадают: сообщение говорит
   > «advancing the round and widening the quorum-scan window», а код делает ровно это —
   > `self.round = self.round.saturating_add(1)` плюс `scan_lookback = REPHASE_SCAN_WINDOW`.
   > `src/consensus.rs:3498-3525` (`apply_deadlock_local_reset`), вызов и лог —
   > `src/main.rs:4981-5018`. Отдельно: раунд **никогда не перематывается назад**
   > (это сам-эквивокация), и debug-ассерт `rt.hc.round > from_round` это пиннит.
   > **Тесты:** `tests/consensus_rephase_tests.rs`, `tests/deadlock_breaker_tests.rs`.

5. **[MEDIUM] Слепая зона спасения залоченного пропозера (`runtime.rs:1449-1507`):**
   Если автор залоченного блока упал, следующие пропозеры отклоняют `lock_hint`, так как у них нет тела блока в памяти (`ours == false`), блокируя завершение высоты.

   > **СТАТУС: MITIGATED.** Гейт `ours` стал **строже**, а не мягче: в rescue-set
   > попадает **только** блок, который этот узел **сам авторировал** и **сам держит**
   > (`b.height == hc.height && b.proposer == self.id`), а не просто любой блок,
   > лежащий в памяти. Это закрыло находку W6.4b №6 («lock-hint rescue мог
   > предложить чужое тело»).
   > `src/runtime.rs:2989-3002` (`note_lock_hint`, комментарий «OUR body means we
   > AUTHORED it, not merely that we happen to hold a copy»).
   > **Но исходная жалоба остаётся в силе как liveness-остаток.** Механизм
   > `demanded` (`src/runtime.rs:1838-1883`) умеет **отдать** тело, которое узел
   > **уже держит**; пути «спросить тело у пира по lock-hint» в коде нет. Поэтому если
   > автор залоченного блока упал и его тела нет ни у нового пропозера, ни у кого
   > ещё, высота по-прежнему не завершается до высвобождения замка (кворум prevote
   > за другое непустое значение в более позднем раунде либо наблюдённый precommit QC).
   > Это **не** дефект безопасности, но это и не «закрыто»: пункт вынесен в
   > ЧАСТЬ IV.c как улучшение C-уровня («запрос тела у пира по lock-hint»).

---

### Агент 2: Криптография и пост-квантовая защита (`post_quantum.rs`, `bls.rs`, `address.rs`)

1. **[CRITICAL] Утечка приватного ключа Falcon-512 через округление Бабаи (`post_quantum.rs:1495-1508`):**
   В `sign_with_seed` вместо дискретного гауссовского сэмплирования по решётке (требуемого стандартом NIST FIPS 206 / FN-DSA) применено детерминированное округление Бабаи:
   $$k_1 = \lfloor -c \cdot F / q \rceil, \quad k_2 = \lfloor c \cdot f / q \rceil, \quad s_2 = k_1 f + k_2 F$$
   Подписи распределены строго внутри параллелепипеда базиса. Классическая атака Нгуена-Регева (Nguyen-Regev, Eurocrypt 2006) полностью восстанавливает секретные векторы $f, F$ по ковариационной матрице ~400–1000 подписей. Вектор $G$ вообще инициализируется нулями.

   > **СТАТУС: FIXED.** Подписант переписан на **FIPS 206 (FN-DSA)**: дискретное
   > гауссово сэмплирование выполняется эталонной C-реализацией Falcon-512
   > (`PQCLEAN_FALCON512_CLEAN_sign_dyn`), а не округлением Бабаи; ключ — полная
   > NTRU-пара `(f, g, F, G)`.
   > `src/post_quantum.rs:1165-1397` (комментарий-обоснование + `falcon512_sign_dyn`
   > на `:1346`), `falcon512_keygen` на `:1291`, проверка NTRU-соотношения
   > `falcon_ntru_relation_holds` на `:1405`. Крейт `pqcrypto-falcon` стал **прямой**
   > зависимостью (`Cargo.toml`), C-архив линкуется явно, при обновлении зависимости
   > сборка падает loudly, а не деградирует молча.
   > **Тесты:** `src/post_quantum.rs:3053` (`test_falcon_signing_is_non_deterministic_and_verifies`
   > — две подписи одного сообщения различаются, все nonce'ы уникальны) и
   > `:3131` (`test_falcon_signature_is_not_the_babai_round_off` — подпись **не**
   > совпадает с воспроизведённым округлением Бабаи).

2. **[HIGH] Полная предсказуемость сортиции комитетов без VRF (`consensus.rs:573-577`):**
   Посев сортиции `BLAKE3("STELL_SORTITION_V4" || height || round || step)` не содержит энтропии, случайности или хэша предыдущего блока. Любой участник может за недели вперед вычислить точный состав любого комитета, спланировать таргетированный DDoS или сговор.

   > **СТАТУС: MITIGATED.** Посев теперь включает **хэш родительского блока**:
   > `BLAKE3("STELL_SORTITION_V5" || prev_block_hash || height || round)`, а сам
   > `sortition_parent` едет вместе с сертификатом, чтобы проверяющий пере-вывел
   > **тот же** комитет.
   > `src/consensus.rs:747-820` (`derive_sortition_committee` + `sortition_seed`),
   > `src/consensus.rs:443` (`PqMicroCertificate::sortition_parent`).
   > Комитет неизвестен **заранее** (форк переизбирает комитет), но **не является
   > нефальсифицируемым**: пропозер родительского блока подбирает его байты, то есть
   > и его хэш, то есть и следующий комитет — «grinding».
   > **Остаточный риск (задокументирован в коде и в PROTOCOL.md §6.2):** security
   > boundary — не parent-hash, а **network-anchored quorum**
   > (`pq_micro_required_power`, см. п. 4 ниже); VRF-based отбор — структурное
   > исправление, которое вне объёма этих волн.

3. **[HIGH] Межсетевой повтор (Replay) в голосах и блоках (`consensus.rs:922-938`, `sharding.rs:2286-2311`):**
   Байты подписи голоса консенсуса (`vote_sign_bytes`) и хэш блока не содержат `chain_id`. Подписи валидаторов с тестовой сети валидны на основной сети с теми же ключами.

   > **СТАТУС: FIXED.** `chain_id` входит и в преимаж подписи голоса, и в хэш блока.
   > `src/consensus.rs:1172-1175` (`vote_sign_bytes` → `consensus_chain_id().to_be_bytes()`),
   > `src/sharding.rs:4446` (`Block::compute_hash` → тот же `consensus_chain_id()`).
   > Идентификатор **фиксируется один раз на процесс** (`FROZEN_CHAIN_ID`, `OnceLock`),
   > чтобы два валидатора с разным окружением не разошлись по консенсусу.
   > **Тесты:** `src/consensus.rs:4469` (`test_vote_signature_is_bound_to_chain_id`),
   > `:4515` (`test_vote_preimage_commits_to_chain_id_and_fields`);
   > на уровне блока — `tests/block_hash_binding_tests.rs`.

4. **[HIGH] Размер микро-комитета $k=16$ уязвим для захвата кворума (`consensus.rs:345`):**
   При $N=100$ и доле злоумышленника в 33%, вероятность получить $\ge 11$ из 16 мест в комитете составляет $0.16\%$. При темпе блоков 250–500 мс это дает **~550 скомпрометированных комитетов в сутки**. Для безопасности BFT сортиция требует $k \ge 500..1000$.

   > **СТАТУС: FIXED (порог изменён сильнее, чем предлагалось).** Вместо $k=16$ —
   > `MICRO_COMMITTEE_MAX_SIZE = 64` (`src/consensus.rs:635`), и, что важнее, порог
   > µQC теперь **привязан к сети**, а не только к комитету:
   > `required = max(⌊2·W_committee/3⌋+1, ⌊W_network/2⌋+1)` —
   > `pq_micro_required_power` (`src/consensus.rs:691-701`).
   > Строгое большинство **всей сети** даёт свойство пересечения кворумов: любые два
   > конфликтующих сертификата делят хотя бы одного подписавшего, чего у 16-местного
   > комитета не было (там 2/3 от ~16% сети ≈ 11% — форг без форка).
   > Комитет, не дотягивающий до сетевого порога, **отвергается**, а не принимается
   > с ослабленным порогом; полный Ed25519-QC-путь остаётся авторитетным.
   > **Тесты:** `src/consensus.rs:4723` / `:4756` (чистая кворумная математика и
   > end-to-end), `tests/pure_pq_enforcement_tests.rs:118`, `tests/pq_uqc_power_quorum_tests.rs`.

5. **[MEDIUM] Уязвимость формата агрегации BLS12-381 (Rogue-Key) (`bls.rs:488-505`):**
   В реестре BLS отсутствует Proof-of-Possession (PoP). Из-за риска атаки подмены ключа путь BLS принудительно заблокирован аварийным выходом (`refuse_bls_qc_if_enabled`), превращая весь модуль BLS в мертвый код.

    > **СТАТУС: OPEN (осознанно и задокументировано; перепроверено 2026-10-22).** Ничего
    > не изменилось и **ничего не должно** меняться, пока нет PoP-реестра:
    > `refuse_bls_qc_if_enabled`
    > (`src/bls.rs:497-514`) при `STELL_BLS_QC=1` **отказывает на старте** с громким
    > сообщением, а не деградирует молча. Реестр (`STELL_BLS_KEYS_FILE` /
    > `STELL_BLS_KEYS`) по-прежнему несёт голые пары `<ed25519> <bls-pubkey>` без
    > доказательств владения.
    > **Честная формулировка:** BLS-агрегация **не может быть включена** — это
    > не «мёртвый код, который мы забыли», а осознанный fail-closed до
    > структурного изменения формата реестра (каждой записи нужна подпись) и
    > пере-регистрации всех операторов.
   > **Остаточный риск:** при масштабировании сети до 100+ валидаторов каждый
   > сертификат несёт 100+ Ed25519-подписей (PROTOCOL.md §7 это фиксирует).
   > **W10 (V-P34, R2):** BLS-ветвь attribution тоже была битой (отвергнутый
   > конверт атрибутировал членов) — теперь только verified-aggregate members
   > (пин `v34_r2e`, `tests/v34_verification_pentest.rs:426`); сам fail-closed
   > отказ BLS-QC без PoP не тронут.

6. **[MEDIUM] Податливость (malleability) неявных конвертов транзакций (`sharding.rs:171-197`):**
   Парсер не проверяет `pk_len == 0` для неявных пост-квантовых подписей, допуская инъекцию мусорных байт без нарушения валидации подписи, искажая хэш транзакции.

   > **СТАТУС: FIXED.** Декодер конверта стал строгим: ровно **одна** валидная
   > байтовая форма на `(scheme, key, signature)`. Неявный конверт обязан иметь
   > `pk_len == 0` (сплайс мусора отвергается, а не пропускается), явный — ровно
   > `key_len` данной схемы, подпись — ровно `sig_len`.
   > `src/post_quantum.rs:429` (`PqSignatureEnvelope::decode`).
   > **Тест:** `src/sharding.rs:5305`
   > (`test_pq_envelope_decode_is_strict_and_non_malleable`).

---

### Агент 3: Движок исполнения, VM и состояние SMT (`state_engine.rs`, `svm.rs`, `cpat2.rs`)

1. **[CRITICAL] Катастрофическая сложность удаления ключа из Trie $O(N \log N)$ (`cpat2.rs:201-210`):**
   При удалении ключа `CompressedTrie::remove` полностью обнуляет дерево (`self.root = None`) и последовательно перевставляет все оставшиеся элементы! В `rollback_payload` это порождает лавинообразные задержки и вектор DoS.

   > **СТАТУС: FIXED.** `remove` больше не перестраивает дерево: удаление —
   > локальная рекурсия по ветвям с схлопыванием родителя (`collapse`).
   > `src/cpat2.rs:262-268` (`CompressedTrie::remove`) и `src/cpat2.rs:202-235`
   > (`Node::remove_node`). Сложность — O(глубина пути), а не O(N log N).
   > **Тесты (дифференциальные, против полной перестройки):**
   > `src/cpat2.rs:1404` (`test_remove_is_differential_against_rebuild`),
   > `:1496` (то же на случайном порядке вставок), `:1547`
   > (`test_remove_random_keys_matches_fresh_trie`), плюс
   > `tests/cpat2_stress.rs`.

2. **[CRITICAL] Псевдо-параллелизм исполнения транзакций (`state_engine.rs:3356-3564`):**
   Транзакции внутри волн не исполняются параллельно на пуле потоков. Захватывается единый глобальный лок `accounts.write().await`, и транзакции применяются строго последовательно в цикле. Для всех транзакций с токенами, ордербуками или контрактами генерируется `ResourceKey::Global`, принудительно схлопывая их в одиночные последовательные волны.

   > **СТАТУС: MITIGATED.** Глобальный ключ действительно убран: `ResourceKey` теперь
   > различает `Token(id)`, `OrderBook(pair)`, `Contract(addr)`, `Account(addr)`, и
   > `Global` остался только для действительно глобальных подсистем (стейкинг, оракул,
   > эскроу моста, реестр сессий, commitment-домен) и для операций, чей id статически
   > неизвестен (создание токена, деплой контракта, отмена ордера).
   > `src/parallel_exec.rs` (перечисление и обоснование в шапке модуля).
   > **Но:** настоящий параллелизм разрешён **только** для волн, где все транзакции —
   > простые переводы без payload (`wave_all_plain`). Транзакция с payload
   > мутирует consensus-домены, которые VM клонирует целиком, поэтому такие волны
   > применяются **строго по порядку, по одной**.
   > `src/state_engine.rs:4180-4188` (комментарий «Concurrency is allowed ONLY for
   > `wave_all_plain` waves above») и сам последовательный путь ниже по функции
   > `apply_block_parallel_fees_with_events` (`src/state_engine.rs:3893`).
   > **Остаточный риск:** блок, набитый токен-транзакциями по **разным** токенам,
   > формально распадается на несколько волн, но исполняется последовательно —
   > выигрыш от гранулярности есть, а настоящего параллелизма на CPU нет.
   > **Тесты:** `src/state_engine.rs` — `test_parallel_wave_execution_is_deterministic`
   > и `parallel_wave_matches_sequential_for_randomized_blocks`;
   > `tests/parallel_exec_tests.rs`, `tests/parallel_execution_tests.rs`,
   > `tests/chaos_parallel_exec_tests.rs`.

3. **[HIGH] Экономический перекос газа в 500 раз (`svm.rs:30-42`):**
   Базовый перевод нативного STELL стоит 280,000 nano-STELL, а перевод кастомного токена STS (с более сложной логикой в памяти и trie) — всего 560 nano-STELL. Спамер может забивать блоки транзакциями токенов в 500 раз дешевле нативных переводов.

   > **СТАТУС: FIXED.** Единое правило: **ни одна токеновая операция не может стоить
   > дешевле базового перевода**. `GAS_BASIC_TRANSFER = 280_000`, и
   > `GAS_TOKEN_TRANSFER / MINT / BURN / APPROVE / ADMIN / CREATE` все равны ему.
   > `src/svm.rs:39-52` (включая `const _: () = assert!(GAS_TOKEN_TRANSFER >= GAS_BASIC_TRANSFER)` —
   > проверка на этапе компиляции), `src/token.rs:32-53` (такой же `assert!` для всех
   > шести констант). Это закрывает «500-кратный дисконт», а не просто поднимает цену.

4. **[HIGH] Отсутствие реального байткод-исполнителя EVM (`evm_adapter.rs:637-652`):**
   EVM — чисто декоративный RPC-фасад. Calldata отбрасывается при конвертации в транзакцию L1; деплой EVM-контрактов запрещен; `eth_getStorageAt` возвращает нули.

   > **СТАТУС: ACCEPTED (по замыслу, для не-EVM сети).** Сеть не является EVM-сетью,
   > и её собственный VM — `wasmi` + 45-операционный SVM. EVM-слой существует для
   > совместимости кошельков (MetaMask, Chainlist, DeFiLlama) и честно ограничен:
   > `evm_raw_to_stell_transaction` (`src/evm_adapter.rs:642-663`) отвергает
   > создание контракта (`to == None`) и **не исполняет** calldata — L1-нога это
   > обычный перевод значения; `eth_getStorageAt` (`src/evm_adapter.rs:429-439`)
   > честно возвращает нули, потому что EVM-стейт-три не существует.
   > Это **не** дефект безопасности и **не** недоделка: для TON-подобной сети
   > отсутствие EVM-интерпретатора — архитектурная позиция, а не пробел.
   > **Остаточный риск:** пользователь, ожидающий `eth_call`/`eth_sendRawTransaction`
   > с исполнением контракта, получит перевод без вызова — это должно быть явно
   > написано в документации для внешних разработчиков.

5. **[MEDIUM] Изоляция подсистем через глобальные мьютексы (`state_engine.rs`):**
   Грубые `Arc<RwLock<...>>` на реестры аккаунтов, токенов и ордербуков создают бутылочное горлышко при параллельных RPC-чтениях.

   > **СТАТУС: MITIGATED.** Гранулярность конфликтов поднята до per-resource
   > (см. п. 2): токен-реестр, ордербук и контракт больше не схлопываются в один
   > `Global`-ключ. Но сами хранилища по-прежнему защищены `Arc<RwLock<...>>`
   > (`accounts`, `tokens`, `orderbooks`), и параллельное применение блока всё ещё
   > сериализовано по `accounts`.
   > **Остаточный риск:** на 1-vCPU стенде это не является узким местом (узкое
   > место — криптография подписи), но на большем железе глобальный `accounts`-лог
   > останется точкой конкуренции. Снятие потребует либо RCU/шардинга по адресам,
   > либо copy-on-write движка — это отдельная волна, а не «ошибка» в текущем коде.

---

### Агент 4: P2P-сеть и транспорт QUIC (`consensus_net.rs`, `network.rs`, `infnode`)

1. **[CRITICAL] Голодание входящего канала консенсуса при отложенных пакетах (`main.rs:3598-3650`):**
   Когда `InboundBulkLimiter` откладывает партию (Defer), она возвращается в хвост очереди `pending`. В следующей итерации она извлекается первой и снова откладывается. Цикл на 512 итераций блокирует вызов `rx.try_recv()`, полностью замораживая прием свежих голосов и предложений из сокета на 1–2 секунды.

   > **СТАТУС: FIXED.** Отложенные партии вынесены из цикла опроса сокета в
   > отдельную **time-gated очередь** `inbound_deferred` с плановым `wake_at`, и
   > цикл опроса в первую очередь читает **живые** сообщения: отложенное
   > поднимается, только если `rx` пуст **и** срок вышел.
   > `src/main.rs:3748-3763` (дренаж), `:3805-3812` / `:3884-3890` / `:3948-3954`
   > (парковка), `src/main.rs:4183` (инвариант «deferred уже в очереди»).
   > **Тест:** `src/main.rs:8112`
   > (`test_sec06_deferred_queue_time_gated_and_prioritizes_rx`) — живые сообщения
   > уходят первыми, незрелое отложенное не поднимается.

2. **[HIGH] Схлопывание лимитера пиров в один глобальный ключ (`main.rs:3632-3635`):**
   `infnode` при отправке `pubsub.msg` не включает поля `"from"` или `"src"`. Код консенсуса сваливается в дефолт `"broadcast"`. Вместо раздельного троттлинга по 1024 пирам весь входящий трафик валидаторов душится одним общим ведром токенов.

   > **СТАТУС: FIXED.** Ключ ведра извлекается из конверта pubsub по полю `src`
   > (предпочтительно) или `from` (legacy), с нормализацией префикса `inf1:`;
   > конверт без отправителя честно попадает в общий fallback-бакет.
   > `src/consensus_net.rs:1767` (`inbound_peer_key_prefers_src_then_from`),
   > вызов на пути консенсуса — `src/main.rs:3794`.
   > **Тесты:** `src/consensus_net.rs:1767` и `:1789`
   > (`inbound_limiter_buckets_are_per_peer`).
   > **W10 (P1+V-P1):** ключ валидируется (непустой ASCII-hex, ≤128 символов,
   > `src/consensus_net.rs:3055-3074`, пин `pentest_inbound_peer_key_validates_sender`
   > `:2179` + `verification_peer_key_holds_against_malicious_senders` `:2397`);
   > singleton-flood изолирован per-peer (пин `verification_singleton_flood_is_per_peer_isolated`
   > `:2319`); только Committed обходит лимитер, с капом 8/tick
   > (`COMMITTED_INNER_BUDGET_PER_TICK`, `src/consensus_net.rs:3012`, пины
   > `pentest_only_committed_bypasses_inbound_limiter` `:2118` и
   > `verification_committed_bypass_is_capped_per_tick` `:2356`).

3. **[HIGH] Накладные расходы двустороннего RPC для широковещания (`consensus_net.rs:931-998`):**
   Широковещание реализовано как вызов `request_to("pubsub.msg")` поверх двусторонних стримов QUIC, ожидающих ответного фрейма `RESP`. В глобальном WAN с задержками 70–120 мс время броадкаста подскакивает до 300–1200 мс. Необходим переход на однонаправленные стримы (`open_uni()`) или QUIC DATAGRAM.

   > **СТАТУС: FIXED (для горячего пути).** Голоса и предложения уходят
   > **fire-and-forget** (`send_to`), не дожидаясь `RESP`; ожидаемый (acknowledged)
   > путь сохранён только для `Committed` — это путь докачивания блока + QC, где
   > ACK является доказательством доставки, и он редкий.
   > `src/consensus_net.rs:346-357` (`message_is_fire_and_forget` /
   > `batch_is_fire_and_forget`), `:1132-1155` (ветвление `send_to` / `request_to`).
   > **Остаточный риск:** «односторонний QUIC-поток» в терминах исходной находки —
   > это `send_to` поверх существующего infnode-канала, а не отдельный `open_uni()`;
   > идемпотентность доставки по-прежнему обеспечивается повторной рассылкой
   > консенсус-цикла, а не ACK'ом.

4. **[MEDIUM] Искусственная задержка тай-брейка в 750 мс (`infnode/src/node.rs:791-801`):**
   При одновременном открытии соединения нода с большим NodeID спит $15 \times 50 = 750\text{ мс}$ в ожидании входящего звонка от соседа. Если сосед перезагружается или загружен, каждый коннект теряет почти секунду.

   > **СТАТУС: FIXED.** Ожидание одновременного открытия сокращено с 750 мс
   > (`15 × 50`) до **100 мс** (`SIMOPEN_WAIT_MS_DEFAULT`), с сохранением исходной
   > цели тай-брейка (не дать QUIC simultaneous-open abort storm) и с
   > переопределением через `INFNODE_SIMOPEN_WAIT_MS`.
   > `infmail-valid-backend/crates/infnode/src/node.rs:132-147` (константа и парсер),
   > `:850-859` (использование).

5. **[MEDIUM] Рассинхронизация темпа заголовков и QC-сайдкаров (`network.rs:737-775`):**
   Заголовки блоков публикуются как `Pointer`, а их сертификаты (QC) — как `Bulk`. При срабатывании лимита полосы заголовки сохраняются, а QC отбрасываются, из-за чего синхронизирующиеся узлы видят заголовок без доказательства и реджектят его.

   > **СТАТУС: FIXED.** Заголовок, его height→hash-указатель и QC-сайдкар теперь
   > едут **по одной полосе** (`Pointer`), поэтому circuit breaker полосы treats их
   > как одну единицу: либо приземлились все три, либо (при падении) не приземлилась
   > ни одна — «заголовок без QC» больше невозможно.
   > `src/network.rs:759-811` (`header_publish_slots` + три вызова
   > `paced_store_blob_in_lane` на одном `lane`). Комментарий прямо описывает
   > исходный дефект («a split pair is worse than a missing pair»).
   > **W10 (P1+V-P1, F4):** hostile index-блобы (чужие имена/ключи, не-hex,
   > регистр/префиксы) отвергаются валидацией хэша — ровно 64 ASCII-hex
   > (`src/network.rs:314`, пины `pentest_header_index_rejects_hostile_hashes`
   > `:3619` и `verification_header_index_case_prefix_and_segments` `:3657`).
   > G5 (oracle): поддельный фид, подложенный в локальный KV через `dht.sync`
   > от недоверенных пиров, больше не выдаётся — fetch перепроверяет подпись,
   > fail-closed читается как «нет фида» (`src/network.rs:1804`,
   > пин `verification_oracle_fetch_reverifies_signature` `:3700`).

---

### Агент 5: Шардинг и межшардовые телепорты (`sharding.rs`, `runtime.rs`)

1. **[CRITICAL] Локальный характер межшардового транспорта (`network.rs:2120-2169`, `sharding.rs:317-320`):**
   Передача кросс-шардовых сообщений работает исключительно через разделяемую память процесса или локальный RocksDB/Sled узел. Не существует P2P-протокола или топиков сплетен для маршрутизации сообщений между шардами, развернутыми на разных физических серверах.

   > **СТАТУС: FIXED.** Есть настоящий P2P-транспорт между шардами:
   > `P2pCrossShardTransport` публикует сообщение в gossip-топик **целевого** шарда
   > (`stell/cross_shard/<epoch>/<shard_id>`), и каждый узел, hosting'щий этот шард,
   > получает его через overlay. Топик **scope'ится эпохой**, поэтому две сети рядом
   > не видят трафик друг друга; копия сообщения дополнительно лежит в теле блока,
   > поэтому потерянная gossip-копия восстанавливается распространением блока.
   > `src/network.rs:2549-2614` (`P2pCrossShardTransport`, `cross_shard_topic`),
   > `src/network.rs:110-127` (схема топика).
   > **Тест:** `src/network.rs:2955` (`p2p_cross_shard_topic_is_epoch_scoped`).

2. **[HIGH] Разрыв валидаторного сета воркчейнов (`main.rs:298-301`, `runtime.rs:3762`):**
   На воркчейнах реестр стейкинга пуст по определению. Ротация валидаторов, слэшинг и добавление стейка происходят на Masterchain, но на воркчейны эти обновления не транслируются. Валидаторы воркчейна навсегда остаются в неизменном составе момента запуска процесса.

   > **СТАТУС: FIXED.** Воркчейн и мастерчейн делят **один и тот же** handle
   > мастерчейнового реестра (`master_staking`), поэтому ротация/слэшинг/бонд
   > мастерчейна видна воркчейну; переключение на новый сет происходит на границе
   > высоты (`validator_set_adoption_height` = текущая+1) — чистая функция цепочки,
   > а не локального тайминга.
   > `src/main.rs:2219-2226` (передача `master_staking` в воркчейн-рантайм),
   > `src/sharding.rs:501-517` (`is_workchain_shard`,
   > `validator_set_adoption_height`).

3. **[HIGH] Коллизия маршрутизации в `tx_belongs_to_shard` (`sharding.rs:408-410`):**
   Условие `|| (tx.source_shard == 0 && shard_id == 1)` разрешает Shard 1 упаковывать транзакции Masterchain. Это нарушает изоляцию шардов и создает потенциал двойного расходования.

   > **СТАТУС: FIXED.** Условие схлопнуто до строгого владения источником:
   > `tx.source_shard == shard_id` (`src/sharding.rs:538-540`). Шард, который
   > является **источником**, производит транзакцию (включая исходящие кросс-шардовые);
   > шард-получатель **никогда** не включает её в `Block.transactions` — значение
   > приходит через запись о потреблении `CrossShardMessage`.
   > **Тест:** `src/sharding.rs:4935`
   > (`tx_belongs_to_shard_enforces_strict_partition_isolation`).
   > **W10 (P2+V-P2):** гейт спущен в мемпул — pool-level пин `admission_shard`
   > в `insert` закрывает gossip/restore-пути, которые были непиннены
   > (`src/mempool.rs:1508-1517`), стартовый пин — `src/main.rs:401,2549,6817`.
   > Пины: `p2_shard_gate_refuses_foreign_tx_when_pinned` и
   > `p2_both_shards_claim_tx_rejected_by_non_owner` (`tests/p2_mempool_pentest.rs:261,282`),
   > V-P2 16/16 (`tests/vp2_verify.rs`, в т.ч. `shard_gate_pinned_pool_refuses_foreign_on_every_path`
   > и `shard_gate_restore_drops_foreign`). **ESCALATED:** legacy cross-chain replay —
   > кошелёк по умолчанию строит replayable-транзакции (`p2_legacy_tx_replays_across_chain_ids`,
   > `legacy_unbound_replay_succeeds_on_both_chains`) — нужен chain-binding rollout (см. ЧАСТЬ IV).

4. **[MEDIUM] Неработоспособность динамического расщепления/слияния (Split/Merge) (`sharding.rs:568-683`):**
   Логика `check_and_split`/`check_and_merge` в `DynamicShardManager` оторвана от `state_engine` и `cpat2`. Механизм физического разбиения Patricia-Merkle Trie и миграции балансов между шардами отсутствует.

   > **СТАТУС: MITIGATED.** Собран полноценный **state machine** разбиения/слияния:
   > триггер по нагрузке, перераспределение аккаунтов по биту префикса, сохранение
   > баланса и дигеста аккаунтов (`MigrationPlan`), а также ** trie-level миграция**:
   > `TrieMigration::execute_split` / `execute_merge` переносят каждый ключ
   > родительского `PatriciaTrie` ровно в одного ребёнка и **fail-closed**
   > на неклассифицированном ключе (миграция никогда не теряет состояние молча).
   > `src/sharding.rs:1886-1946` (split), `:1957-1979` (merge),
   > `src/sharding.rs:1201-1267` (`MigrationError` + `TrieMigration`),
   > `:1276` / `:1373` (`execute_split` / `execute_merge`).
   > Правило address→shard задокументировано в `docs/SHARDING.md` §1 и опубликовано
   > через `stell_getShards` / `stell_getShardTopology`.
   > **Остаточный риск (важно):** миграция **не подключена** к живому `state_engine`
   > — она выполняется над синтетическим набором аккаунтов в процессе, а перенос
   > пере repartition'нутого состояния между **узлами** не реализован. Сам `docs/SHARDING.md` §0
   > честно помечает «A split on the live testnet / mainnet — **DESIGNED — NOT PERFORMED**».
   > **Тесты:** `tests/sharding_topology_tests.rs` (split/merge/миграция/сходимость).

5. **[LOW] Лимит в 1 кросс-шардовый перевод на отправителя за блок (`runtime.rs:1603-1610`):**
   Из-за генерации доказательства включения по состоянию до начала блока один адрес не может отправить более 1 кросс-шардового перевода за 3 секунды.

   > **СТАТУС: FIXED.** Ограничения больше нет: каждый исходящий кросс-шардовый
   > перевод получает **своё** Merkle-доказательство включения по pre-block leaf
   > отправителя и своё pre-block сальдо, а якорь берётся из общего
   > process-shared реестра финализированных заголовков (C1-anchor), а не из
   > состояния «до начала блока» в его прежнем виде.
   > `src/runtime.rs:2237-2270` (построение `cross_shard_out`),
   > `src/runtime.rs:897-905` (`verify_cross_shard_anchored`),
   > `src/runtime.rs:1789-1802` (genesis-anchor).
   > **Остаточный риск:** остаётся **другое** ограничение — «кросс-шардовое
   > обязательство не приземляется на не-anchor'нутом родителе»
   > (`src/runtime.rs:2586-2634`), и это сознательное fail-closed-правило.

---

### Агент 6: Мемпул, MEV и рынок комиссий (`mempool.rs`, `rpc.rs`, `mev.rs`)

1. **[CRITICAL] Вектор DoS через бесплатные сбои (Free-Failure Attack) (`state_engine.rs:2715-2860`, `mempool.rs:401-412`):**
   При сбое исполнения транзакции состояние атомарно откатывается, и списанная комиссия равна нулю (`fee_charged = 0`). Штраф `failed_penalty` привязан к адресу отправителя, генерация которого бесплатна. Атакующий может генерировать тысячи адресов и забивать блоки транзакциями с максимальной вычислительной нагрузкой (до 2048 Proof Units), не тратя ни одного нано-STELL.

   > **СТАТУС: FIXED.** Сбойная транзакция **платит комиссию** (floor + фактически
   > потреблённое газо, с насыщением) и **сжигает nonce**, если отправитель может её
   > оплатить. Правило доступности: если денег не хватает — не меняется **ничего**
   > (ни списания, ни nonce, ни состояния), потому что списать последнюю пыль за
   > транзакцию, которая всё равно не выполнилась, — это поверхность для грифа, а не
   > свойство безопасности.
   > `src/state_engine.rs:3100-3139` (`apply_failure_fee_to_map` — «SEC-07 failure
   > fee, sync core»), async-обёртка `:3145-3152`.
   > **Тесты:** `src/state_engine.rs:10361`
   > (`test_sec07_free_failure_dos_charges_fee_and_increments_nonce`),
   > `tests/apply_floor_tests.rs`, `tests/adversarial_regression_tests.rs:140`.
   > **Остаточный риск:** стоимость спама по-прежнему определяется числом **адресов**,
   > а не числом монет — но теперь каждый адрес обязан заплатить floor, а 1024
   > транзакции на адрес ограничены квотой мемпула.

2. **[HIGH] Искажение приоритетов через манипуляцию `gas_limit` (`mempool.rs:340, 1044`):**
   Индекс очереди мемпула отсортирован по `(tx.gas_limit, hash)`. Транзакция, выставившая огромный `gas_limit`, получает высший приоритет над срочной транзакцией со стандартным лимитом, даже если обе платят одинаковую базовую ставку.

   > **СТАТУС: FIXED.** Первичным ключом индекса стал **явный priority-bid**
   > `priority_fee_per_gas` — поле, подписанное отправителем и оплачиваемое комиссией;
   > `gas_limit` опустился во вторичный ключ (он покупает позицию **внутри** своей
   > price-категории, но не может перебить чужую явную ставку).
   > `src/mempool.rs:354-366` (структура `order` и обоснование), `:669`
   > (`required_fee_for_tx`), `:1371` / `:1578` (использование).
   > **Тесты:** `src/mempool.rs:2084` (bid переживает wire round-trip),
   > `tests/mempool_econ_tests.rs`.

3. **[HIGH] Исчерпание буфера активации неактивированных аккаунтов (`mempool.rs:62-64, 988-1008`):**
   Глобальный лимит буфера неактивированных PQ-аккаунтов составляет всего 2048 слотов. Заспамив 128 адресов по 16 транзакций (затратив менее 0.6 STELL), атакующий полностью блокирует онбординг новых пользователей с ошибкой `TooManyFromSender`.

   > **СТАТУС: MITIGATED.** (а) Лимит на **аккаунт** урезан с 16 до 4 —
   > `MAX_ACTIVATION_BUFFER_NONCES_PER_ACCOUNT` выровнен с nonce-окном
   > активированного аккаунта (`src/mempool.rs:12-20`); 128 адресов больше не съедают
   > весь буфер. (б) Глобальный потолок 2048 слотов теперь честно рапортует
   > `MempoolError::Full`, а **не** `TooManyFromSender`: раньше отправителю врали
   > «слишком много твоих транзакций», тогда как правда была «общий буфер полон» —
   > глобальный DoS прятался за per-sender ошибкой.
   > `src/mempool.rs:39-78` (`PendingActivationBuffer::buffer_tx_with_timestamp`).
   > **Остаточный риск:** глобальный предел в 2048 слота остаётся, и транзакция в
   > буфере **не оплачена** деньгами — комиссия списывается только когда она
   > фактически исполнится. Sybil из множества адресов по-прежнему может
   > заполнить буфер; закрыт только «дешёвый» путь (16 неконсеквентных nonce'ов с
   > одного адреса).

4. **[MEDIUM] Геометрическая блокировка при вытеснении (`mempool.rs:544-546`):**
   Для вытеснения транзакции из забитого пула требуется предложить удвоенную комиссию (`fee >= low_fee * 2`). При всплесках нагрузки порог входа возрастает экспоненциально ($280\text{k} \to 560\text{k} \to 1.12\text{M} \to 2.24\text{M}$), блокируя нормальную работу сети.

   > **СТАТУС: FIXED.** Премия за вытеснение — **5 % (+1)** от цены вытесняемой
   > транзакции вместо ×2. Порог растёт **линейно** по собственной цене пула, а не
   > экспоненциально; правило срабатывает только при заполненном пуле (в пустом
   > пуле проходит любой проходящий floor), так что честный трафик не затронут.
   > `src/mempool.rs:609-640` (`eviction_bid_beats` + обоснование).
   > **Остаточный риск:** правило остаётся **локальной политикой** — разные ноды
   > могут иметь разные пулы и, следовательно, разные пороги; это влияет только на
   > liveness локального пула, не на консенсус.

5. **[MEDIUM] Фиктивная защита от MEV (`mev.rs:415-440`):**
   Шифрование транзакций внутри пула использует локальный симметричный ключ самой ноды (`POOL_ROUND = 0`). Обязательства по порядку блоков хранятся только в локальной памяти пропозера, в блок не включаются и консенсусом не проверяются (при несовпадении выводится предупреждение, но блок финализируется).

    > **СТАТУС: FIXED (вторая половина закрыта кодом W8.4; операционный остаток — в
    > `docs/MEV.md` §4.3).** Первая половина находки — «обязательство по порядку не
    > проверяется консенсусом» — **была закрыта раньше**: корень Меркла порядка
    > транзакций лежит **внутри подписанного хэша блока**
    > (`Block::order_merkle_root`), а валидатор **пересчитывает** его из тела
    > предложения и **отвергает** несовпадение. Значит, кворум BFT голосует и за
    > **порядок**: переставить блок после голосов невозможно.
    > `src/sharding.rs:4460-4475` (корень в хэше) и `src/runtime.rs:2642-2671`
    > (`check_order_commitment` — «COORDINATED ROLLOUT: this is a hard rule»).
    > Вторая половина — «шифрование node-local» — **больше не node-local в коде**:
    > epoch seal (ES1) — Feldman-взвешенный DKG каждые 128 блоков
    > (`src/mev_epoch.rs:81` `EPOCH_BLOCKS`), кошельки запечатывают эфемерным ECDH +
    > XChaCha20 (AAD привязывает эпоху/транзакцию/комитет), в wire идёт
    > `STX1`-фрейм (`src/mev_epoch.rs:1616`), commitment эпохи — в теле блока
    > (`Block::epoch_key_commitment`, `src/sharding.rs:4297`), order commitment
    > разблокирует раздачу долей, threshold-unseal — в `src/runtime.rs:2281`
    > (`sealed_proposer_path`), RPC — `stell_epochKey` (`src/rpc.rs:3899`),
    > `stell_sendSealedTransaction`, `stell_mevStats`.
    > **Тесты:** `tests/mev_epoch_seal_tests.rs` (**25 passed**),
    > `tests/mempool_mev_audit_closure_tests.rs` (**10 passed**).
   > **Остаточный риск (честный, `docs/MEV.md` §4.3):** скомпрометированный комитет
   > читает эпоху; liveness DKG зависит от онлайна контрибьюторов; комитет
   > выводится из текущего view валидатор-сета, а не из beacon; дроп
   > sealed-транзакции не переносит fee on-chain (только admission bond).
   > **W10 (V-P34, P5-ledger):** seal-ledger держится — 5 разнотипных транзакций,
   > видимое `{from, nonce, gas_limit, fee, shards}`, запечатанное `{to, amount,
   > payload, args}` (пин `v34_p5_seal_leakage_ledger_holds_for_five_txs`,
   > `tests/v34_verification_pentest.rs:706`).

---

### Агент 7: Стейкинг, слэшинг и управление (`staking.rs`, `governance.rs`, `commitment.rs`)

1. **[CRITICAL] Массовый ложный слэшинг валидаторов при использовании µQC/BLS (`state_engine.rs:4895-4909`):**
   Модуль слэшинга за простой извлекает список подписантов прямо из `cert.signatures`. Но при агрегации подписей (BLS или Falcon µQC) в поле `signatures` кладется только маркер (`0xFF` или `0xFD`). Проверка `signers.contains(validator)` возвращает `false` для **всех честных валидаторов**, и через 10 блоков сеть сжигает 0.1% стейка у каждого валидатора, повторяя это каждые 100 блоков до полного обнуления депозитов.

   > **СТАТУС: FIXED.** Список подписантов теперь **разворачивается** из
   > агрегатного конверта: `QuorumCertificate::signers_set` распознаёт
   > `PQ_UQC_MARKER_ID` (µQC), `PQ_QC_MARKER_ID` (CEC) и `BLS_QC_MARKER_ID`,
   > пере-выводит комитет по `sortition_parent` и **по битовой маске** отмечает
   > реальных подписавших.
   > `src/consensus.rs:2537-2615` (`signers_set`).
   > **Fail-closed:** если µQC-конверт не декодируется, комитет **неизвестен** — и
   > конверт не даёт **ни одного** подписавшего (угадывать, например, нулевого
   > родителя, значило бы назвать неверных валидаторов, что само по себе является
   > evidence для слэша).
   > Потребитель: `src/state_engine.rs:5551-5576` (`apply_downtime_slash`), плюс
   > правило «только избранный сет» (elected-only), чтобы неактивные ключи не
   > копили `missed`.
   > **Тест:** `src/consensus.rs:5095`
   > (`test_signers_set_extraction_falcon_uqc_bls_and_classical` — три формы:
   > классическая, µQC, BLS).
   > **W10 (P3+V-P34, R2):** decode-only attribution признана битой — отвергнутые QC
   > всё равно атрибутировали подписантов (все три envelope-вида + классический путь).
   > FIXED verify-grade attribution (per-sig classical, verified-aggregate BLS,
   > valid-signer PQ) + fail-closed `verify`-гейт в `apply_downtime_slash`
   > (`src/state_engine.rs:6010-6046`: неверифицируемый сертификат не двигает стейк
   > ни в какую сторону). Пины: `v34_r2a`/`r2b`/`r2c` (red-до-фикса),
   > `v34_r2d`/`r2e` (genuine без регресса) — `tests/v34_verification_pentest.rs:270-471`.

2. **[CRITICAL] Обход верификации бинарника при ончейн-обновлении ПО (`main.rs:4280`):**
   ```rust
   if plan.sha256 == [0u8; 32] || plan.sha256 == hash.as_slice() {
   ```
   Если в предложении по обновлению ПО передан хэш из нулей, проверка целостности полностью отключается, позволяя выполнить произвольный бинарник через `execve`.

   > **СТАТУС: FIXED.** Нулевой хэш **запрещён на трёх уровнях**: при
   > валидации действия в предложении, при ратификации и при самом исполнении.
   > `src/governance.rs:279` (валидация действия `SoftwareUpgrade`:
   > `*sha256 == [0u8; 32]` → `GovError::InvalidAction`),
   > `src/governance.rs:1060` (исполнение),
   > `src/governance.rs:628` (сверка с фактическим digest: нулевой digest **никогда**
   > не совпадает).
   > **Тест:** `src/governance.rs` — кейсы `action_zero_sha` / `action_empty_name` /
   > `action_zero_height` в модульных тестах валидации действия.
   > **Сверх исходной находки (W6.7):** закрыт ещё и весь класс «upgrade как
   > произвольный exec» — см. ЧАСТЬ III, `W6-07`.

3. **[HIGH] $O(N)$ цикл распределения наград за каждый блок (`staking.rs:1635-1647`):**
   При финализации блока награда пропозера немедленно раскидывается по всем его делегаторам в цикле по `self.delegations`. Наличие тысяч микро-делегаторов драматически увеличивает время применения блока. Необходим переход на ленивый $O(1)$ аккумулятор (F1 Fee Distribution).

   > **СТАТУС: FIXED.** Введён ленивый **F1-аккумулятор**: распределение за блок
   > только **поднимает** ставку `reward_per_token` валидатора, а каждая
   > делегаторская доля считается лениво — из аккумулятора и собственного
   > checkpoint'а делегата — в момент, когда делегат задет (claim / изменение
   > стейка / слэш). Стоимость блока перестала зависеть от числа делегатов.
   > `src/staking.rs:1849-1894` (`distribute_reward` — O(1)), аккумулятор и
   > checkpoint'ы — `src/staking.rs:499-520` и `:807-820`, коммит домена —
   > `src/staking.rs:716-720`.
   > **Оговорка про округление (задокументирована в коде):** масштабированная ставка
   > усекается на `< 1/1e18` за распределение, поэтому ленивая доля отличается от
   > точной пропорциональной **не более чем на 1 нано** за распределение и **никогда
   > не превышает** её (пул не перерасходуется). Пыль остаётся в `rewards_pool` и
   > **не** переносится пропозеру: иначе выплата зависела бы от **числа делегатов**
   > (шлифуемый вход).

4. **[MEDIUM] Неподключенный пост-квантовый слэшинг за эквивокацию (`staking.rs:1416-1498`):**
   Функция `slash_pq_equivocation` (сжигающая 100% стейка за двойную подпись в микро-комитете) полностью реализована и протестирована, но для нее нет опкода в SVM и транзакции с доказательством PQ-эквивокации невозможно отправить в блокчейн.

   > **СТАТУС: FIXED.** Добавлен опкод `OpCode::SysCallReportPqEquivocation`
   > (`src/svm.rs:875`), он же проходит mempool-фильтр
   > (`src/mempool.rs:1813`), помечает транзакцию как затрагивающую стейкинг
   > (`src/state_engine.rs:1778`), и на исполнении вызывает
   > `slash_pq_equivocation` (`src/svm.rs:2690-2745`) с fail-closed обработкой
   > плохой подписи / неизвестного голосовавшего.
   > **Тесты:** `tests/equivocation_slash_tests.rs`, `tests/pq_equivocation_report_tests.rs`,
   > `src/svm.rs:3222` (собственный кейс SVM).
   > **W10 (P3):** два варианта эквивокации задокументированы как **ускользающие от слэшинга**:
   > cross-round lock-violation (пары голосов разных раундов — не submittable evidence) и
   > double-propose (конверт покрывает только пары голосов, предложения — не голоса).
   > Пины: `p3_eq_cross_round_lock_violation_escapes_slash_path` (`:151`) и
   > `p3_eq_double_propose_escapes_vote_slash_path` (`:194`) —
   > `tests/p3_byzantine_pentest.rs`. Нужен proposal-equivocation evidence type (см. ЧАСТЬ IV).

5. **[MEDIUM] Неполнота состояния в дайджесте обязательств (`commitment.rs:469-559`):**
   Поля `equivocation_dedup`, `validator_pq_keys` и `vesting_schedules` исключены из расчета `commitment_digest`. Рассинхронизация этих структур между нодами не отражается на корне состояния, создавая риски скрытого форка.

   > **СТАТУС: FIXED.** В дайджест commitment'а вошли **все четыре** домена:
   > `equivocation_dedup`, `pq_equivocation_dedup`, `validator_pq_keys`,
   > `vesting_schedules` — каждый со своим domain-separation тегом и
   > **канонической (отсортированной) сериализацией**, чтобы порядок обхода не
   > влиял на дайджест.
   > `src/commitment.rs:579-650`.
   > **Тесты:** `src/commitment.rs:1276` (`equivocation_dedup_moves_the_digest`),
   > `:1288` (`pq_equivocation_dedup_moves_the_digest`),
   > `:1299` (`validator_pq_keys_move_the_digest`),
   > `:1327` (`vesting_schedules_move_the_digest`), плюс
   > `tests/state_root_completeness_tests.rs` и
   > `tests/domain_persistence_tests.rs`.
   > **Дополнительно (W6.7):** пустой домен обязан писать **ноль байт** — иначе
   > «опустевший» домен мог бы «поглотить» разницу в другом домене
   > (`src/commitment.rs:1469-1520`).

---


## ЧАСТЬ III. СВОДНЫЙ РЕЕСТР ПРОБЛЕМ И ПЛАН ДОРАБОТКИ ПО ВОЛНАМ

### III.1. Реестр критических уязвимостей (P0/Security) — исходные SEC-01…SEC-07

| ID | Категория | Локация (было) | Суть проблемы | **СТАТУС** | Где исправлено | Тест |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Consensus | `runtime.rs:3985` | Инвертированное условие блокировки в `adopt_committed` раскалывает сеть при коммите блока старшего раунда. | **FIXED** | `src/runtime.rs:4693-4697` | `tests/consensus_reaudit_tests.rs:416,434,455`; `tests/adopt_prevote_tests.rs:134,149` |
| **SEC-02** | Crypto | `post_quantum.rs:1495` | Утечка приватного ключа Falcon-512 через детерминированное округление Бабаи вместо гауссовского шума. | **FIXED** | `src/post_quantum.rs:1165-1397` (FIPS 206 / PQClean C-ref) | `src/post_quantum.rs:3053,3131` |
| **SEC-03** | Staking | `state_engine.rs:4895` | Слэшинг за простой не распаковывает битовую маску µQC/BLS и наказывает 100% честных валидаторов. | **FIXED** | `src/consensus.rs:2537-2615` (`signers_set`) | `src/consensus.rs:5095`; `tests/slashing_rotation_tests.rs` |
| **SEC-04** | Governance | `main.rs:4280` | `plan.sha256 == [0u8; 32]` позволяет запустить неподписанный вредоносный бинарник через `execve`. | **FIXED** | `src/governance.rs:279,1060,628` | модульные тесты `src/governance.rs` (`action_zero_sha`) |
| **SEC-05** | State/SMT | `cpat2.rs:201` | `remove` уничтожает всё дерево и перестраивает его за $O(N \log N)$ при каждом удалении. | **FIXED** | `src/cpat2.rs:202-235,262-268` | `src/cpat2.rs:1404,1496,1547`; `tests/cpat2_stress.rs` |
| **SEC-06** | P2P | `main.rs:3598` | Вечный цикл перекладывания отложенных пакетов блокирует прием голосов консенсуса из сокета. | **FIXED** | `src/main.rs:3748-3763,3805-3812` | `src/main.rs:8112` |
| **SEC-07** | Mempool | `state_engine.rs:2715` | Сбойные транзакции не оплачивают газ, открывая бесплатный DoS валидаторов тяжелыми доказательствами. | **FIXED** | `src/state_engine.rs:3100-3139` | `src/state_engine.rs:10361`; `tests/apply_floor_tests.rs` |

Дополнительно в W1 закрыты: **коллизия шардовой маршрутизации**
(`src/sharding.rs:538-540`, тест `src/sharding.rs:4935`) и **500-кратный перекос газа
токенов** (`src/token.rs:32-53` + `const`-assert'ы в `src/svm.rs:40-52`).

### III.2. Новые находки ре-аудитов W6 (четыре независимых аудита) и W7

Четыре ре-аудита W6 были проведены **независимо** по четырём разрезам: consensus/BFT
(W6.4b), crypto/PQ (W6.5), mempool/sharding/execution (W6.6), staking/governance/network/RPC
(W6.7). Каждая находка имеет маркер в коде (`AUDIT W6.4b` / `W6.5` / `W6.6` / `W6.7`),
что делает реестр проверяемым.

| ID | Область | Суть | **СТАТУС** | Где исправлено |
| :--- | :--- | :--- | :--- | :--- |
| **W6-01** | Consensus | Deadlock-breaker целился в `round + MAX_ROUND_AHEAD` (1000) и потому не мог закрыть рассинхронизацию **больше** 1000 раундов (в живьё: A r1550 против B r318). | **FIXED** | `src/consensus.rs:2756` (`MAX_DEADLOCK_JUMP = 65_536`), `:3342-3358` |
| **W6-02** | Consensus | Локальный re-phase двигал раунд на +1 (то есть ни на что) и **не** сходился с сетью. | **FIXED** | `src/consensus.rs:3498-3525` (расширяет `scan_lookback` до `REPHASE_SCAN_WINDOW = 4096`) |
| **W6-03** | Consensus | Обрезка кандидатов fork-choice **записывала** invalidation, но **не публиковала** её — потерянная ветвь исчезала без следа. | **FIXED** | `src/chain.rs:692` (`take_pending_invalidations`), `src/main.rs:2331-2341`, `src/rpc.rs:5718` |
| **W6-04** | Consensus | Snapshot-anchor брал финализированный head и **энтропию сортиции** из присланного пиром заголовка, чей `prev_hash` не покрыт кворум-сертификатом → пир мог указать ноде на форк и направить её комитет сортиции. | **FIXED** | `src/sync.rs:185-312` (`verify_snapshot_anchor` идёт по **своей** цепочке и требует QC на каждой высоте) |
| **W6-05** | Consensus | Неизвестный sortition-parent компилировал µQC против **нулевого** родителя — комитет, который не избирает никто. | **FIXED** | `src/main.rs:2029,2407` (fail closed: неизвестный родитель → комитета нет) |
| **W6-06** | Consensus | Lock-hint rescue мог **перепредложить чужое тело** под своим слотом пропозера. | **FIXED** | `src/runtime.rs:2989-3002` (в rescue-set только `b.proposer == self.id`) |
| **W6-07** | Consensus | Декодер wire-сообщения терпел **обрезанное** тело (без хвостовых commitment-полей), молча переинтерпретируя его как другой блок. | **FIXED** | строгий декодер `ConsensusMsg` (`src/consensus.rs`), тест `tests/consensus_reaudit_tests.rs` |
| **W6-08** | Crypto | Ключ, записанный до-FIPS-206, — **неполный** NTRU-ключ (нет `G`), то есть не FN-DSA-ключ. | **FIXED** (адрес не меняется) | `src/post_quantum.rs:1464-1601` (партнёр реконструируется в памяти), `src/main.rs:5431-5461` (`keys rotate-falcon`) |
| **W6-09** | Crypto | Legacy-деривация Falcon имеет **~2³²** эффективной энтропии (seed выбирает лишь автоморфный образ базового ключа) → приватный ключ восстанавливается брутфорсом из публичного. | **MITIGATED** | `src/post_quantum.rs:1604-1643` (громкий ERROR + stderr), `:1970-2010`; путь живёт только ради исторического genesis root |
| **W6-10** | Crypto | Податливость конверта PQ1 (implicit с `pk_len≠0`, произвольная длина ключа/подписи) → обход байтовых dedup-фильтров. | **FIXED** | `src/post_quantum.rs:429` (`PqSignatureEnvelope::decode`) |
| **W6-11** | Crypto | Shamir: дубликат `validator_id` давал нулевой знаменатель Лагранжа, а `Scalar::invert(0) == 0` — тихо **неверный** ключ вместо ошибки. | **FIXED** | `src/mev.rs:125-142` |
| **W6-12** | Crypto | µQC: лимит комитета `16` был захардкожен в **двух** местах (риск форка) и позволял захват кворума. | **FIXED** | `src/consensus.rs:635` (единая константа 64) + `:691` (network-anchored quorum) |
| **W6-13** | Crypto | BLS-агрегат-верификатор принимал вырожденный/identity-агрегат (у поля — публичные members). | **FIXED** | `src/bls.rs:353,774` |
| **W6-14** | Crypto | MEV order-commitment подписывался **голым** 32-байтным корнем без domain separation и без привязки к раунду → кросс-протокольный replay. | **FIXED** | `src/mev.rs:263,540,760` |
| **W6-15** | Crypto | Некорректный набор Shamir-долей принимался молча. | **FIXED** | `src/mev.rs:117,730` |
| **W6-16** | Crypto | Base58-декодер адреса был **O(n²)** по длине входа (неограниченный DoS), плюс гомоглифы и нулевой префикс. | **FIXED** | `src/address.rs:142,255,277,306`; тесты `tests/stl57_audit_pentest_tests.rs` |
| **W6-17** | Crypto | Stealth-ключ выдавался без проверки соответствия `one_time_pub`; viewing key мог печататься в лог. | **FIXED** | `src/crypto_privacy.rs:188,1856,1871` |
| **W6-18** | Execution | D2-штраф консенсуса **не входил** в снапшот → восстановленная нода считала другие комиссии → **другой state root** (раскол консенсуса от простого рестарта). | **FIXED** | `src/state_engine.rs:11047-11104` (тест `snapshot_carries_the_d2_penalty_so_a_restored_node_agrees`) |
| **W6-19** | Mempool | **Утечка резерва** activation-буфера: стоимость транзакции списывалась при входе, но не возвращалась на всех выходных путях (вечная блокировка средств) или возвращалась дважды. | **FIXED** | `src/mempool.rs:599-607` (строгий one-in/one-out), тест `src/mempool.rs:2238` |
| **W6-20** | Execution | Failure fee (F-01) применялся только на блочном пути, но не на single-tx пути → одна и та же транзакция давала **разные корни** в зависимости от пути. | **FIXED** | `src/state_engine.rs:3145-3164` |
| **W6-21** | Execution | Токеновые операции могли стоить дешевле базового перевода (дисконт для спама). | **FIXED** | `src/token.rs:32-53` (`const`-assert'ы) |
| **W6-22** | Execution | Оптимистичная (CAS) параллельная волна могла разойтись с последовательным путём. | **FIXED** | `src/state_engine.rs:11154-11174` (тест на рандомизированных блоках) |
| **W6-23** | State | `CompressedTrie::remove` перестраивал дерево целиком (тот же SEC-05, переоткрыт как дефект корректности/производительности). | **FIXED** | `src/cpat2.rs:262` + дифференциальные тесты `src/cpat2.rs:1391-1560` |
| **W6-24** | Execution | Семантика комиссии («платишь объявленный `gas_limit`, а не потреблённое») не была зафиксирована как инвариант. | **FIXED** (зафиксировано) | `src/svm.rs:48` |
| **W6-25** | Execution | Параллельный «plain» fast-path обходил team-vesting floors (снапшот не покрывал). | **FIXED** | `src/state_engine.rs:3967-3979` (снапшот floors на блок, проверка inline) |
| **W6-26** | Governance | Имя upgrade-плана могло **выйти за пределы** `data/upgrades/` (path traversal) → governance-предложение указывало на произвольный путь в системе. | **FIXED** | `src/governance.rs:518` (`upgrade_name_is_safe`), проверка при propose/execute/разрешении кандидата |
| **W6-27** | Governance | **TOCTOU** апгрейда: файл читали+хэшировали, а потом исполняли **по пути** → подмена между проверкой и `execve`. | **FIXED** | `src/governance.rs:591` (`stage_verified_upgrade_binary`: проверенные байты → приватный каталог 0700 со случайным именем → исполняется **копия**) |
| **W6-28** | Governance | Кандидат апгрейда мог быть **symlink** → «кандидат в каталоге оператора» превращался в «любой файл на машине», а старый `chmod 0755` менял права **цели** ссылки. | **FIXED** | `src/governance.rs:591+` (`symlink_metadata`, отказ для symlink и не-regular) |
| **W6-29** | RPC/Governance | `stell_executeProposal` применял прошедшее предложение (в т.ч. **бинарный апгрейд**) **без токена** — единственный governance-write без гейта. | **FIXED** | `src/rpc.rs:4020` (тот же constant-time токен-гейт, что у submit/vote) |
| **W6-30** | RPC | `stell_estimateFee` клонирует **всё** состояние движка и гоняет полный SVM на **неаутентифицированном** чтении; общий лимит 300/с/IP был несопоставимо щедрым, а оценка могла поднять газ до полного контрактного потолка (50M). | **FIXED** | `src/rpc.rs:895` (свой бюджет 5/с/IP, `STELL_ESTIMATE_FEE_RATE_LIMIT`), `:2363` (потолок 5 000 000 газа, **не поднимаемый** вызывающим) |
| **W6-31** | RPC | `stell_getEvents` мог ответить **миллионами** событий (50 000 receipts × 256 событий) на неаутентифицированный read. | **FIXED** | `src/rpc.rs:977` (`MAX_EVENTS_RETURNED = 1000`), вызывающий может просить меньше |
| **W6-32** | RPC | Один клиент мог забрать **весь** глобальный реестр подписок (4096) и отрезать всех остальных. | **FIXED** | `src/rpc.rs:5203,5212` (глобальный 4096 + per-client 64) |
| **W6-33** | Network | Fire-and-forget отправка засчитывалась как **успех** в health-ledger → пир, который принимает запись, но не обрабатывает сообщение, никогда не вытеснялся. | **FIXED** | `src/consensus_net.rs:326,1171` (успех в ledger — только подтверждённая отправка) |
| **W6-34** | Node keys | Приватные ключи ноды писались **неатомарно** → падение в момент записи могло обнулить живой ключ. | **FIXED** | `src/node_keys.rs:392-422` (temp в том же каталоге → `fsync` файла → `rename` → `fsync` каталога) |
| **W6-35** | Sync | Snapshot-anchor проверял **одну** высоту → `prev_hash` заголовка-преемника не проверялся ни с чем → пир мог подсунуть форк как финализированный head. | **FIXED** | `src/sync.rs:335` (`SNAPSHOT_ANCHOR_TAIL_WINDOW = 3`, окно `[boundary-1, boundary+1]`) |
| **W6-36** | Consensus | Sortition-parent брался из присланного пиром заголовка → steering комитета. | **FIXED** | см. W6-04 / W6-05 |
| **W6-37** | Consensus | Кламп deadlock-breaker'а делал фикс бессмысленным. | **FIXED** | см. W6-01 |
| **W6-38** | Consensus | **nil-polka снимал замок** → узел, таймаутнувший в раунде 1, ронял замок на блоке, финализированном в раунде 0, и мог финализировать конфликтующий (нарушение safety). | **FIXED** | `src/consensus.rs:3067-3079` (unlock — только по кворуму за **другое непустое** значение в строго более позднем раунде) |
| **W6-39** | Bridge | Спор о мошенничестве принимал **поддельное** доказательство → честный получатель терял депозит, а challenger получал бонд + 10%. | **FIXED** (см. W7-01) | `src/bridge.rs:738,1517` |
| **W6-40** | MEV | «Порог» MEV в одном процессе держал бы все доли — security theater. | **ACCEPTED / отложено** (движок v4 по-прежнему припаркован) | `src/mev_v4.rs:25-50` (движок припаркован, выключен по умолчанию, удаление запрещено) |
| **W7-01** | Bridge | **Truth-gate спора:** отзыв депозита теперь требует **положительного** проверяемого доказательства (кворумная ретрактация ровно этого claim'а). Отсутствие доказательства — не мошенничество: спор **откладывается** (с ограничением) или отвергается громко, без выплат. | **FIXED** | `src/bridge.rs:738` (единственное fraud-proof), `:1517` (truth gate), `:1676-1720` (deferral/refuse) |
| **W7-02** | Governance | Неизвестный `type` в `stell_submitProposal` попадал в catch-all и превращался в `Signal` — опечатка выглядела как принятое предложение. | **FIXED** (fail closed) | `src/governance.rs:357` (`gov_action_from_params`), `:348` (отказ с перечислением словаря) |
| **W7-03** | RPC | Ответ `stell_estimateFee` должен честно отражать **фактически использованный** бюджет, а не завышенную константу. | **FIXED** | `src/rpc.rs:2530,2566` |
| **W7-04** | RPC/Native API | Коллизия имён: чтение acceptance-record'а депозита и транзакция-«prepare» назывались одинаково. | **FIXED** | `stell_bridgeDeposit` (чтение) vs `stell_bridgeDepositPrepare` (подписываемая транзакция) — `src/native_api.rs` |

**Итого по реестру:** SEC-01…SEC-07 — **7/7 FIXED**. Находки ре-аудитов W6 — **40** строк
(W6-01…W6-40) плюс **4** находки W7 (W7-01…W7-04), итого **44** строки:
**42 FIXED**, **1 MITIGATED** (W6-09 — энтропия legacy-ключа Falcon), **1
ACCEPTED/отложено** (W6-40 — движок v4 припаркован; сама потребность закрыта иначе:
настоящий epoch seal построен в W8.4 в `src/mev_epoch.rs`, см. Agent 6 п. 5).
Ни одна строка реестра не осталась в статусе OPEN (OPEN в PART II — только BLS/PoP,
осознанно).

**Итого по реестру W10 (2026-10-23, закрытие P1-G2…G4 — R3 2026-10-26):** **35 строк**: **26 FIXED** (W10-FORK,
W10-FAUCET, P1-F1…F6, P1-G1, P1-G5, P2-SHARD-GATE, P2-RESV-LEAK, P3-R1, P3-R2,
P4-F-DBG-1…4, P5-F1…F3, P5-MINT-CAP + V-фиксации),
**5 HOLDS-VERIFIED** (P3-HALT-LOUD, P3-QC-FORGE, P4-BATT-24, V-P2-гейт, V-P34-ledger),
**2 ACCEPTED** (P4-F-PQ-1 — interop-стена; P1-G2…G4 — filed без контента, закрыты R3),
**1 ESCALATED** (P2-LEGACY-REPLAY —
chain-binding rollout), **2 OPEN** (P3-EQ-ESCAPE ×2 как одна
строка + E1-бэклог как evaluated-открыт). E1 — оценка, а не дефект: 22-пунктный
бэклог с владельцами живёт в ЧАСТИ IV.

> **Важное замечание о честности реестра.** Реестр W6/W7 составлен по маркерам
> `AUDIT W6.*` / `W7.*` **в исходниках** — то есть по фактическому коду, а не по
> отчёту ре-аудита. Каждая строка выше указывает `file:line`, который можно открыть и
> проверить. Это сильнее, чем ссылка на «список агента». То же правило применено
> к реестру W10 ниже: каждая строка пиннится маркером `PENTEST`/`VERIFICATION`
> в коде или именованным тестом, прогнанным 2026-10-23.

### III.2b. Новые находки волны W10 (fork-heal, faucet, пентесты P1–P5, верификации V, OS-оценка E1)

Волна W10 состоит из двух операционных ремонтов (**W10.1** fork-heal, **W10.2**
faucet-fix), пяти пентестов (**P1–P5**), трёх независимых верификаций
(**V-P1/V-P2/V-P34**) и OS-оценки (**E1**). Операционные детали живого кластера
(состав снапшота C, темп 612 блоков/10 мин, бинарь `04e3e44c` на всех 4 узлах)
приведены по отчёту волны — в коде им соответствуют регрессионные пины ниже.

| ID | Область | Суть | **СТАТУС** | Где исправлено / запиннено |
| :--- | :--- | :--- | :--- | :--- |
| **W10-FORK** | Execution | Неатомарный `commit_native` (`src/state_engine.rs`): post-commit PQ-pin падал ПОСЛЕ дебита+инкремента nonce — полуприменённая транзакция (`failed/fee 0`, корень `e783…`) против чистой (`success/fee 395000`, корень `9f1e…`) при том же хэше блока #288000. Канон = C. | **FIXED** | Атомарный undo (полный leaf: баланс/nonce/scheme/pubkey_hash, `src/state_engine.rs:3355-3364`), отказы disabled-схем до мутации (`:3405-3415`), откат через undo-лог (`:3617-3622`); DIVERGENCE-лог + `stell_divergence_total` (`src/runtime.rs:3962-3990`, `src/metrics.rs:82`); офлайн `stelops diverge` (`scripts/tools/stelops/src/main.rs:594-670`); пины `fork288000_*` (`src/state_engine.rs:11930-12106`, 4/4) + `tests/pq_fork288000_replay.rs` (5/5, канон `success/fee 395000`) |
| **W10-FAUCET** | RPC/Sharding | Дрипы строились не на тот шард / кросс-шардовый дрип сжигал nonce и кап до отказа. | **FIXED** | `resolve_faucet_recipient` (`src/rpc.rs:2411-2429`): роут на шард получателя (`-1:`/`N:`-хинты, `route_shard`), отказ ДО резерва nonce/cap; анти-абуз цел; пины `faucet_masterchain_drip_finalizes_on_shard_0` (`:8383`), `faucet_workchain_drip_finalizes_on_its_shard` (`:8424`), `faucet_refuses_shard_mismatched_drip_without_burning_nonce` (`:8465`), `faucet_prefix_matrix_routes_before_nonce_reservation` (`:8514`) — 13/13 `faucet_*` |
| **P1-F1** | P2P | Trailing-bytes decode: `allow_trailing_bytes` пропускал мусор за валидным сообщением. | **FIXED** | `src/consensus_net.rs:438` (`reject_trailing_bytes`); пины `pentest_decode_rejects_trailing_bytes` (`:2085`) + `verification_decode_rejects_trailing_on_every_shape` (`:2251`) |
| **P1-F2** | P2P | Singleton limiter bypass: всё, кроме Batch, обходило лимитер (`!matches!(Batch)`); Committed-обход без бюджета. | **FIXED** | Только Committed обходит (`src/consensus_net.rs:2995`), кап 8/tick (`:3012`); пины `:2118`, `:2356`, `:2319` (per-peer изоляция singleton-flood) |
| **P1-F3** | P2P | Peer-key validation: невалидированный `src` — неограниченные heap-ключи в `HashMap`. | **FIXED** | Валидация (непустой ASCII-hex ≤128, `src/consensus_net.rs:3055-3074`); пины `:2179`, `:2397` |
| **P1-F4** | P2P | Header-index hostile hashes: вражеский index-блоб подсовывал имена/ключи. | **FIXED** | Валидация хэша — ровно 64 ASCII-hex (`src/network.rs:314`); пины `:3619`, `:3657` |
| **P1-F5** | P2P | Dynamic-peer budget: динамические пиры рождались без rate-limit. | **FIXED** | Born rate-limited (`infnode/src/node.rs:2619`, `:64`); пин `pentest_dynamic_peers_are_born_rate_limited` (`:6864`) + `verification_dht_peer_flood_is_bound_per_identity` (`:6957`) |
| **P1-F6** | P2P | Manifest traversal: отравленный манифест удалял файлы / `local_chunk_get` шёл в path-join без гейта. | **FIXED** | Гейт chunk-id на всех путях (`infnode/src/node.rs:3693-3732`); пины `:6897`, `:6930`, `:7015` |
| **P1-G1** | P2P | Filed gap: одиночная поддельная proposal ставила catch-up hint и гоняла DHT-walk каждый тик. | **FIXED (V-P1)** | Хинт только от attributable proposal (подпись + стейк): оба сайта — receiver-loop (`proposal_hint_admissible`, `src/consensus_net.rs:3021-3033`) и `on_proposal` (`src/main.rs:4235` + runtime-hint); пин `:2456` |
| **P1-G2..G4** | P2P | Три filed gap'а волны P1 (не G1/G5) — при закрытии контента не найдено нигде (поиск R3: `git log --all -S`, `rg P1-G`, отчёт волны P1; см. пометку в коде). | **ACCEPTED (без контента, R3)** | Закрыты пометкой `P1-G2..G4 — ACCEPTED` на `proposal_hint_admissible` (`src/consensus_net.rs`, дом G1/G5); пин `report_p1_g2_g4_filed_without_content_is_closed_as_accepted` (пере-утверждает оба bookend-гейта G1/G5). Будущим аудитам G2–G4 как «filed» не числить |
| **P1-G5** | P2P | Filed gap: поддельный oracle-фид через `dht.sync` в локальный KV выдавался как рыночное свидетельство. | **FIXED (V-P1)** | Fetch перепроверяет подпись (`src/network.rs:1804-1812`); пин `:3696` (`:3700`) |
| **P2-SHARD-GATE** | Mempool | Gossip/restore-пути мемпула были непиннены: чужая шард-транзакция admits'илась без шард-скоупа. | **FIXED** | Pool-level `admission_shard`-пин в `insert` (`src/mempool.rs:1508-1517`) + стартовый пиннинг (`src/main.rs:401,2549,6817`); строгий framing/nonce/fee/saturation держатся (16/16 `tests/p2_mempool_pentest.rs`) |
| **P2-RESV-LEAK** | Mempool | Утечка резерва `remove_many`/`prune_confirmed` (класс W6.6). | **FIXED** | Единый путь снятия через `release_reservation` (`src/mempool.rs:1699-1720`); пин `reservation_released_exactly_once_on_every_exit` (`tests/vp2_verify.rs:372`) |
| **P2-LEGACY-REPLAY** | Mempool/Wallet | Кошелёк по умолчанию строит replayable-транзакции (нет chain binding). | **ESCALATED** | Пины-эксплойты `p2_legacy_tx_replays_across_chain_ids` (`tests/p2_mempool_pentest.rs:142`), `legacy_unbound_replay_succeeds_on_both_chains` + `bound_envelope_wrong_chain_fails` (`tests/vp2_verify.rs:725,753`); нужен chain-binding rollout (см. ЧАСТЬ IV) |
| **P3-R1** | Consensus | Round-chase corroboration hole: precommit-путь шёл без верификации. | **FIXED** | Гейт `observe_peer_vote` (`src/runtime.rs:4710-4721`); пины `v34_r1a`–`r1d` (`tests/v34_verification_pentest.rs:90-241`) |
| **P3-R2** | Consensus | `signers_set`-vs-`verify` mismatch: отвергнутые QC атрибутировали подписантов. | **FIXED** | Verify-grade attribution + fail-closed slash-гейт (`src/state_engine.rs:6010-6046`); пины `v34_r2a`–`r2e` (`:270-471`) |
| **P3-HALT-LOUD** | Consensus | Форма #288000 (same hash, different roots) обязана орать, а не молча форкаться. | **HOLDS (verified)** | DIVERGENCE-аларм отличен от тихих отказов: `p3_diverge_same_bytes_divergent_verdict_halts_not_forks` (`tests/p3_byzantine_pentest.rs:596`), `v34_diverge_halt_is_loud_not_silent` (`:503`) |
| **P3-QC-FORGE** | Consensus | Батарея подделок QC обязана отказывать. | **HOLDS (verified)** | 7/7 `p3_qc_forge_*` (`tests/p3_byzantine_pentest.rs:472-594`): дубли/не-члены/чужая высота/смешанный раунд/паддинг/оверсайз-маска/BLs-сплайсинг |
| **P3-EQ-ESCAPE ×2** | Consensus | Два варианта эквивокации ускользают от слэшинга (cross-round, double-propose). | **OPEN (документировано)** | Пины-эксплойты `:151`, `:194`; нужен proposal-equivocation evidence type (см. ЧАСТЬ IV) |
| **P4-F-PQ-1** | Crypto | 0x29-vs-0x39 framing: reference-PQClean эмитит 0x39, цепь — 0x29. | **ACCEPTED (interop-стена)** | Осознанно не меняется (сломало бы данные цепи): ровно одна точка эмиссии 0x29, 0x39 отвергается (`src/post_quantum.rs:2185-2257`); пин `v34_fpq1_chain_emits_0x29_reference_0x39_refused` (`:553`) |
| **P4-F-DBG-1..4** | Crypto | Debug-утечки секретов: blinding (`UnshieldInput`), epoch shares (`EpochKeyMaterial`), DKG (`EpochDkg`), round keys (`mev.rs` shares/engine). | **FIXED** | Ручные redact-impl'ы (`src/mev.rs:63,418`, `src/mev_epoch.rs:442,603`, `src/mev_v4.rs:299,516,686`); пин `p4_secret_material_never_appears_in_debug_output` (`tests/p4_crypto_pentest.rs:713`) + `v34_fdbg_no_secret_material_in_debug` (`:611`) |
| **P4-BATT-24** | Crypto | 24-атаковая батарея обязана держаться/пиниться. | **HOLDS (verified)** | 24/24 `tests/p4_crypto_pentest.rs` (прогон 2026-10-23) |
| **P5-F1** | RPC | Contract arms без auth-гейта: `stell_deployContract`/`stell_callContract`-ветви писали консенсус-состояние без токена. | **FIXED (CRITICAL)** | Auth-гейт на arms (`src/rpc.rs:5401` + комментарий P5 FIX); пин `p5_contract_arms_require_auth_token_when_configured` (`:8782`) |
| **P5-F2** | RPC | From/signer confusion: `from` выбирал чужой дебетуемый аккаунт. | **FIXED (CRITICAL)** | `from` == signer (`src/rpc.rs:5547,5731`); пин `p5_call_contract_from_must_equal_signer` (`:8837`) |
| **P5-F3** | RPC | Wrapped-deploy без проверки подписи: неподписанная транзакция admits'илась напрямую. | **FIXED (CRITICAL)** | Проверка подписи на wrapped-пути (`src/rpc.rs:5433`); пин `p5_wrapped_deploy_rejects_forged_signature` (`:8890`) |
| **P5-MINT-CAP** | Bridge | Revoke-cycle мог переоткрыть mint-cap headroom. | **FIXED** | Пин `p5_revoke_cycle_cannot_reopen_mint_cap_headroom` (`bridge::tests`) + staking/token/contract эксплойт-тесты (`p5_exit_and_claim_sequences_are_conservative`, `p5_allowance_double_spend_and_front_run_race`, `p5_metadata_spoofing_same_symbol_is_a_different_token`, `p5_event_cap_and_oob_host_args_are_fail_closed`) — 8/8 `p5_*` |
| **V-P1** | Verification | Независимая перепроверка P1: F2-bypass, F4-парсер, G1-триггер, G5-oracle. | **FIXED-VERIFIED** | F2 BROKEN→FIXED (кап 8/tick, `:2356`), F4 FIXED (`:3657`), G1 EXPLOITABLE→FIXED оба сайта (`:2456`), G5 FIXED (`:3700`); F1/F3/F5/F6 hold |
| **V-P2** | Verification | Независимая перепроверка P2 усиленными эксплойтами. | **HOLDS-VERIFIED** | Shard-gate BROKEN→HOLDS (pool-пин + стартовый пиннинг, `tests/vp2_verify.rs:38-173`), 1 reservation leak FIXED (`:372`), legacy replay ESCALATED (`:725`) |
| **V-P34** | Verification | Независимая перепроверка P3+P4. | **FIXED-VERIFIED** | R1 BROKEN→FIXED (`v34_r1a`–`r1d`), R2 BROKEN→FIXED (`v34_r2a`–`r2e`), 3 mev_v4 Debug-утечки FIXED (`v34_fdbg`), 13/13 |
| **E1** | OS evaluation | Scorecard зрелости: 9× 🟡, 1× ❌ (нет SECURITY.md) + бэклог 22 шт., из них 7 P0. | **EVALUATED (бэклог открыт)** | ❌ верифицирован кодом: `SECURITY.md` отсутствует в корне; P0: SECURITY.md, канонический tx-builder SDK, правило подтверждений, multisig-or-non-goal, onboarding runbook, rollback story, hardware floor (см. ЧАСТЬ IV, владельцы) |

### III.3. Что было в плане волн (исходный план PART III) и что с ним стало

Исходный документ содержал план «Волна 1 … Волна 4». Фактически выполнено **семь**
волн; ниже — соответствие плана и факта.

| План (исходный) | Факт | Комментарий |
| :--- | :--- | :--- |
| **Волна 1**: SEC-01, SEC-03, SEC-04, SEC-05, SEC-06, SEC-07, shard routing | **Выполнена полностью**, плюс паритет газа токенов | См. III.1 |
| **Волна 2**: WASM host imports, event system, deploy/call/getter RPC, code cap, `send_message` | **Выполнена**, с отличиями: host-импортов стало **13** (а не 8/9 — добавились `calldata` и `return_data`), ABI реализован как **STELL-ABI v1** с JSON-манифестом и codegen | `src/contract.rs:1107`, `src/contract_abi.rs` |
| **Волна 3**: WS/SSE, `get_shards`, shard-header commitment, cross-shard P2P, validator-set sync, `estimate_fee` | **Выполнена полностью** | `src/rpc.rs`, `src/network.rs:2549`, `src/main.rs:2219` |
| **Волна 4**: light client + proofs, Falcon FIPS 206, sortition VRF, F1, `enc2`, ChainManager wiring, чистка репозитория | **Выполнена, кроме VRF**: вместо VRF — parent-hash seed + **network-anchored quorum** (документированный residual: сортиция grindable) | `src/consensus.rs:747,691` |
| (не было в плане) | **Волна 5**: consensus-enforced order commitment, параллельное исполнение, ABI+codegen, devnet+симулятор, P2P-латентность, гигиена | `src/runtime.rs:2642`, `src/simulator.rs`, `.github/workflows/ci.yml` |
| (не было в плане) | **Волна 6**: четыре независимых ре-аудита → ~40 фиксов | См. III.2 |
| (не было в плане) | **Волна 7**: truth-gate моста + fail-closed governance-словарь + честные лимиты RPC | `src/bridge.rs`, `src/governance.rs:357` |
| (не было в плане) | **Волна 8**: liveness-корень консенсуса + детерминированный harness, light client в sync-пути + внешний CLI, честный zkML + `STELL_AUTO_UPGRADE` OFF, MEV epoch seal, кросс-шардовый 2PC, ops-автоматизация + preflight живого кластера, внешний аудит-пакет + 3 fuzz-таргета | `src/runtime.rs:4176`, `tests/consensus_liveness_harness.rs`, `src/sync.rs:50`, `src/mev_epoch.rs`, `src/xshard2pc.rs`, `scripts/stell-sync.sh`, `docs/audits/EXTERNAL_AUDIT_BRIEF.md` |
| (не было в плане) | **Волна 9**: верификация исходников контрактов, стандарт подписи кошелька, per-key archive proofs + исторические корни | `src/contract_source.rs`, `src/wallet_signing.rs`, `src/cpat2.rs:899` |
| (не было в плане) | **Волна 10**: fork-heal #288000 + faucet-fix + пентесты P1–P5 + верификации V-P1/V-P2/V-P34 + OS-оценка E1 (реестр — ЧАСТЬ III, §III.2b) | `src/state_engine.rs:3355` / `:11930`, `src/runtime.rs:3962`, `src/metrics.rs:82`, `scripts/tools/stelops/src/main.rs:594`, `src/rpc.rs:2411`, `src/mempool.rs:1508`, `tests/p2_mempool_pentest.rs`, `tests/p3_byzantine_pentest.rs`, `tests/p4_crypto_pentest.rs`, `tests/vp2_verify.rs`, `tests/v34_verification_pentest.rs`, `tests/pq_fork288000_replay.rs` |

**Отклонения от плана, о которых стоит сказать честно:**

1. **Sortition не стал VRF.** Родительский хэш делает комитет *неизвестным заранее*, но
   не *нефальсифицируемым*. Структурное исправление — VRF — вне объёма; вместо него
   введён сетевой якорь кворума. Это **MITIGATED**, а не FIXED.
2. **Light client не встроен в sync-путь** — сознательно и запрещено до «hardfork-grade»
   изменения (см. `src/light_client.rs:1-60` и пин `tests/audit_rpc_evm_closeout.rs:731`).
3. **Параллельное исполнение реально только для plain-переводов** (см. Agent 3, п. 2).
4. **MEV-sealing остаётся node-local** (см. Agent 6, п. 5).
5. **Живой шардовый split не выполнен** (см. `docs/SHARDING.md` §0).

---

## ЧАСТЬ IV. ЧТО ОСТАЛОСЬ — честный список открытого

Этот раздел — самая важная часть ревизии. Ничего здесь не преуменьшено: пункт, который
закрыт на 70 %, записан как «закрыт на 70 %», а не как «сделан».

### IV.a. Блокеры для production (без них L1 в прод не выпускать)

| # | Блокер | Что именно не сделано | Почему это блокер | Ссылка |
| :--- | :--- | :--- | :--- | :--- |
| **A1** | **Внешний аудит не проведён** | Ни одного независимого аудита сторонней командой; все аудиты — внутренние (7 агентов + 4 ре-аудита + волны W1–W7) | Ре-аудиты находят дефекты в коде, написанном **после** предыдущего аудита; без внешнего аудита у нас нет оценки, насколько хорошо внутренние волны закрыли **системные** (а не точечные) классы | — |
| **A2** | **Живой шардовый split/merge не выполнен** | State machine и миграция trie реализованы и покрыты тестами над **синтетическим** набором аккаунтов, но ни один split не был выполнен по живому консенсус-событию, и **перенос пере-партиционированного состояния между узлами не реализован** | Шардинг — заявленная архитектурная особенность; без живого split'а это обещание, а не свойство | `docs/SHARDING.md` §0 |
| **A3** | ~~**Кросс-шардовый 2PC написан, но не активирован и не финализирован вживую**~~ **ЗАКРЫТ post-wave** | 2PC-машина активна из генезиса: `XPC_ACTIVATION_HEIGHT = 0` (`src/xshard2pc.rs:146`), `STELL_XPC_ACTIVATION_HEIGHT` deprecated/ignored; target-side COMMIT считается одним inbound credit, consumed mailbox records pruned; `scripts/soak_two_shard.sh` прогоняет реальные два шарда. Остаётся только topology: live shard-1 PARKED, state transfer при repartition не реализован | Владелец остатка — ops/code (unpark + state transfer); протокольный гейт больше не блокер | `src/xshard2pc.rs`, `docs/TWO_SHARD_DEPLOY.md`, `scripts/soak_two_shard.sh`, `PROTOCOL.md` §9 |
| ~~**A4**~~ **ЗАКРЫТ КАК КОД (W8.4)** | ~~**MEV-защита остаётся node-local**~~ | **Закрыто кодом, остаток — операционный.** Epoch seal ES1: Feldman DKG каждые 128 блоков (`src/mev_epoch.rs:81`), ECDH+XChaCha20 с AAD, `STX1`-фрейм в wire (`:1616`), commitment эпохи в блоке, order commitment разблокирует доли, threshold-unseal, `stell_epochKey` (`src/rpc.rs:3899`). Пин: `tests/mev_epoch_seal_tests.rs` (25 passed). **Остаток** (владелец — ops/живая сеть): живая DKG-церемония эпохи не проведена; честные пределы — `docs/MEV.md` §4.3 (комитет читает эпоху при компрометации t, liveness DKG, view-зависимый комитет, no on-chain fee за дроп) | Живая DKG-церемония не проведена; остаток зафиксирован честно | `src/mev_epoch.rs`, `docs/MEV.md` §4 |
| ~~**A5**~~ **ЗАКРЫТ (W8.3)** | ~~**zk-SNARK — не является доказательством с нулевым знанием**~~ | **Аудит проведён, код и доки переписаны честно.** Модуль `src/snark.rs` переименован в `src/zkml_attestation.rs`; его шапка теперь прямо говорит, что это **НЕ** SNARK, **НЕ** STARK и **НЕ** zero-knowledge: нет R1CS/AIR, нет polynomial commitment, нет парных проверок, нет FRI. Это **sound re-execution attestation**: верификатель перевыполняет модель, пересчитывает BLAKE3 trace root и Fiat–Shamir challenge. Опкоды переименованы (`SysCallVerifyZkMlIn` → `SysCallVerifyZkMlReexec`, `SysCallVerifyZkMlSnark` → `SysCallVerifyZkMlAttestation`, `SysCallRegisterZkMlVk` → `SysCallRegisterZkMlSpec`); **wire-дискриминанты не изменились** (35/37/38). Зарегистрированный «verifying key» переименован в *model spec* — это не Groth16-ключ, а constrained format + I/O shape + свободная метка «setup» (никакой церемонии за ней нет). Добавлена **машиночитаемая** декларация `zkml_capabilities()`, которую RPC отдаёт как `stell_zkmlCapabilities` (`zero_knowledge: false`, `succinct: false`, `hiding: false`, `trusted_setup: false`, `sound: true`). Попутно исправлен недоплат: «attestation»-путь делал ту же полную ре-экзекцию, что и reexec-путь, но тарифицировался ДЕШЕВЛЕ — теперь оба платят за модель. | Заявленное «zk»-свойство не выполнялось — теперь код и RPC **говорят правду**, и интегратор читает это из данных, а не из маркетингового имени. Остаток (структурное исправление — настоящая ZK-схема) остаётся в C3 | `src/zkml_attestation.rs:1`, `src/zkml.rs:38`, `src/svm.rs:668`, `src/rpc.rs` (`stell_zkmlCapabilities`) |
| **A6** | **Сортиция комитетов grindable** | Пропозер родительского блока подбирает байты → хэш → состав следующего комитета. Порог держится на network-anchored quorum, но сам отбор не unforgeable | При достаточно большой доле в сети атакующий может целенаправленно «выбирать» состав µQC; структурное исправление — VRF | `src/consensus.rs:728-746`, `PROTOCOL.md` §6.2 |
| **A7** | **BLS-агрегация не включается** | Нет Proof-of-Possession в реестре → `STELL_BLS_QC=1` приводит к отказу на старте | При 100+ валидаторах — 100+ Ed25519-подписей в каждом сертификате (рост размера и проверки) | `src/bls.rs:497-514`, `PROTOCOL.md` §7 |
| ~~**A8**~~ **ЗАКРЫТ (W8.3)** | ~~**`STELL_AUTO_UPGRADE` по умолчанию = 1**~~ | **Дефолт изменён на OFF.** Теперь вооружение требует явного `STELL_AUTO_UPGRADE=1`/`true` (регистр не важен, пробелы игнорируются); **любая опечатка падает в безопасную сторону** — узел не exec'ает ничего и завершается с кодом 42 (Cosmovisor-совместимо), супервизор перезапускает его. При вооружении узел печатает **громкий баннер** на stderr и `WARN` в лог на старте. Путь «exit 42» для невооружённого случая сохранён без изменений. Ре-аудит W6-остатков (path traversal / TOCTOU / symlink) подтвердил: имя — безопасный сегмент пути, кандидат — не symlink, исполняются **проверенные байты** (staging в приватный каталог 0700). **Добавлен недостающий тест**: симлинк на **родительском каталоге** кандидата тоже отвергается (был остаток W6.7) | Governance-решение больше не приводит к `execve` без явного, node-local, операторского гейта; решение «заменить бинарник на этой машине» принимает оператор, а не код | `src/governance.rs` (`auto_upgrade_armed_from`), `src/main.rs` (баннер + дефолт), `docs/OPERATIONS.md` §12 |
| ~~**A9**~~ **ЗАКРЫТ 2026-10-25 (S7-retry3)** | ~~**Полный `cargo test --tests` не собирался**~~ | **Закрыто кодом, проверено прогоном.** `cargo build --all-targets` — 0 ошибок; `tests/sharding_topology_tests` — 6 passed; `tests/light_client_wiring_tests` — 15 passed; оба stale-ожидания вылечены: `consensus_liveness_repro` — 15 passed (было 14+1 stale), `audit_rpc_evm_closeout` — 30 passed (было 29+1 stale, allowlist теперь знает `stell_divergence_total`). Полный пересчёт — в ЧАСТИ V (все числа от 2026-10-25) | Зелёный полный прогон восстановлен | ЧАСТЬ V, §V.2; `tests/sharding_topology_tests.rs`, `tests/light_client_wiring_tests.rs`, `tests/consensus_liveness_repro.rs`, `tests/audit_rpc_evm_closeout.rs` |
| ~~**A10**~~ **ЗАКРЫТ (W8.3)** | ~~**Light client не подключён к sync-пути**~~ | **Подключён.** (1) **Sync-путь:** узел держит собственный `LightClient`, якорь — его собственный финализированный head (заголовок с precommit-QC, его решившим); каждый блок, предложенный пиром, проверяется против этого якоря **до** применения (`sync::verify_synced_blocks_against_anchor`): продолжение цепочки (высота+1, hash-связность), precommit-QC, подтверждающий кворум реальной власти валидаторов, отсутствие отката state root. (2) **Внешний верификатор:** добавлена команда `stellereum light-client --from <rpc> --verify <account> --validators <file>` (модель Near `light_client` / Sui `sui_light_client`) — она НЕ запускает консенсус. (3) **Кросс-верифицируемый корень:** клиент **никогда** не доверяет корню, который ему выдал сервер: корень принимается только после проверки precommit-сертификата якорного заголовка против **внешнего** набора валидаторов (`--validators`, не из RPC сервера). Узел теперь отдаёт якорь и заголовки с QC: `stell_getFinalizedCheckpoint`, `stell_getFinalizedHeader`. (4) **Тесты:** честное доказательство — проверяется; подделанный leaf/root — отвергается; сервер, который врёт (чужая цепочка / сертификат от посторонних ключей / корень, которого нет в цепочке) — обнаруживается. Старый «tripwire» `light_client_not_wired_into_sync` **инвертирован**: теперь он падает, если узел перестанет зависеть от light client | Внешний наблюдатель больше не обязан верить корень, выданный полной нодой: корень подтверждён кворумом, который клиент проверяет сам по внешнему набору валидаторов | `src/light_client.rs`, `src/sync.rs` (`verify_synced_blocks_against_anchor`), `src/light_client_cli.rs`, `src/runtime.rs` (`note_light_anchor`), `src/rpc.rs`, `tests/light_client_wiring_tests.rs` |
| ~~**A11**~~ **ЗАКРЫТ КАК КОД + ОПЕРАЦИОННО (W10.1)** | ~~**Живой форк #288000: один хэш — два корня**~~ | **Корень найден и закрыт.** Неатомарный `commit_native`: post-commit PQ-pin падал после дебита+nonce (`failed/fee 0`, `e783…`) против чистого применения (`success/fee 395000`, `9f1e…`). Канон = C (чистый реплей succeeds). Лечение: снапшот C + ресинк A/B/D; все 4 финализируют 30+ мин, пик 612 блоков/10 мин; бинарь `04e3e44c` на всех 4 (по отчёту волны). Харднинг в коде: атомарный undo (полный leaf incl. scheme/pubkey_hash), отказ disabled-схем до мутации, `DIVERGENCE`-лог + `stell_divergence_total`, офлайн `stelops diverge`. Пины: `fork288000_*` (4/4 lib) + `tests/pq_fork288000_replay.rs` (5/5) | Форк той же формы теперь орёт в протокол, а не молча раскалывает сеть; канон #288000 зафиксирован тестом | `src/state_engine.rs:3355` / `:3405` / `:11930`, `src/runtime.rs:3962`, `src/metrics.rs:82`, `scripts/tools/stelops/src/main.rs:594` |
| ~~**A12**~~ **ЗАКРЫТ (W10, P5)** | ~~**Contract auth-гейты: 3 CRITICAL**~~ | **Закрыты кодом.** Руки контрактов требовали auth-токен при конфигурации (`p5_contract_arms_require_auth_token_when_configured`), `from` обязан совпадать с подписантом, wrapped-deploy проверяет подпись; плюс mint-cap-cycle и staking/token/contract эксплойт-тесты. 8/8 `p5_*` зелёные 2026-10-23 | RPC-запись консенсус-состояния без аутентификации/авторства закрыта | `src/rpc.rs:5401` / `:5433` / `:5547` / `:5731` / `:8782` / `:8837` / `:8890` |
| ~~**A13**~~ **ЗАКРЫТ (W10, P4)** | ~~**Debug-утечки секретов**~~ | **Закрыты ручными redact-impl.** Blinding (`UnshieldInput`), epoch shares (`EpochKeyMaterial`), DKG (`EpochDkg`), round keys (`mev.rs`) + 3 `mev_v4`-утечки (V-P34). Пины: `p4_secret_material_never_appears_in_debug_output` + `v34_fdbg_no_secret_material_in_debug` | Секреты больше не печатаются в логи ни одной из проверенных структур | `src/mev.rs:63,418`, `src/mev_epoch.rs:442,603`, `src/mev_v4.rs:299,516,686` |
| **A14** | **Legacy cross-chain replay жив (P2-escalation)** | Кошелёк по умолчанию строит replayable-транзакции без chain binding (`chain_id == None`, verify проходит на любой цепи). Bound-конверт существует и держится (`sign_with_chain_id`), но не является дефолтом сборки | Подписи с тестнета валидны на мейннете при тех же ключах — нужен chain-binding rollout: дефолт-bound сборка + `require_chain_id` на admission; владелец — wallet/code | `tests/p2_mempool_pentest.rs:142`, `tests/vp2_verify.rs:725,753` |
| **A15** | **Нет proposal-equivocation evidence type** | Double-propose и cross-round lock-violation ускользают от слэшинга: конверт покрывает только пары голосов. Детект есть (rival bodies, fork-choice), carrier'а для submission+slash нет | Пропозер может подписать два блока без наказуемого следа; владелец — code (новый evidence type + опкод/путь подачи) | `tests/p3_byzantine_pentest.rs:151,194` |
| **A16** | **E1-бэклог: SECURITY.md — DRAFT + 6 P0 (владелец — docs/org)** | Scorecard E1: 9× 🟡, 1× ❌. Изменение 2026-10-25: `SECURITY.md` **создан в корне репозитория** (проверено: файл есть, ~6 КБ), но статус — **DRAFT с плейсхолдерами**: контакт, PGP-ключ и bounty — `REPLACE-ME`/`security@example.invalid`, которые организация ОБЯЗАНА заменить. Остальной P0-бэклог без изменений (6 шт.): канонический tx-builder SDK; правило подтверждений; multisig-or-non-goal; onboarding runbook; rollback story; hardware floor | Disclosure-процесс описан, но не shippable, пока стоят плейсхолдеры; владелец — docs/org (+ code для SDK) | `SECURITY.md` в корне (2026-10-25), E1 (волна W10) |
| **A17** | **A-rebond + D-stake PENDING (владелец — ops)** | По отчёту волны: переподключение A и стейк D на живом кластере после fork-heal — в ожидании. В коде следов нет (операционная задача) | Незавершённый хвостовой шаг heal'а; владелец — ops | — (W10.1, ops) |
| **A18** | **ОБНОВЛЁН 2026-10-28: DIVERGENCE #305832 — конвергенция наблюдена, канон-как-процесс не предъявлен (владелец — code+ops)** | 2026-10-25: 222 DIVERGENCE за 35 мин (`height=305832 … their_root=01b036… our_root=9c33…`). 2026-10-28 (REP2, read-only): оба RPC-узла (8546 + 18545) отдают **идентичные** `tip_hash`/`state_root` мастерчейна (tip 390668, root `8cd8d83d…` на 21:18Z), валидатор-сет 4/4 `fragile:false`, `journalctl nodeB --since '3h'` — **0 DIVERGENCE**, темп 60 блоков/196 с (~3.3 с/блок, оба tip-источника согласны). Наблюдение: `eth_blockNumber` опережает `stell_getShards` tip на ~960 — зафиксировано как наблюдение, не диагноз. Чего нет: офлайн-канона через `stelops diverge` + ресинка меньшинства + разбора корня расхождения — без этого STABLE не присваивается, REFUSE в силе | Конвергенция ≠ процедура: нужен канон-канон + ресинк + разбор корня, иначе DIVERGENCE вернётся | Логи nodeB 2026-10-25, сэмпл REP2 2026-10-28, `src/runtime.rs:4189-4206`, `src/metrics.rs:82` |

### IV.b. Блокеры для публичного тестнета (для внешних пользователей и разработчиков)

| # | Блокер | Суть | Ссылка |
| :--- | :--- | :--- | :--- |
| **B1** | **EVM-фасад без интерпретатора** | `eth_sendRawTransaction` селлит **только переводы значения**; создание контракта отвергается, calldata **не исполняется**, `eth_getStorageAt` всегда возвращает нули. Для не-EVM сети это по замыслу, но кошелёк, ожидающий `eth_call` с исполнением, получит перевод без вызова | `src/evm_adapter.rs:429-439,642-663` |
| ~~**B2**~~ **ЗАКРЫТ (W11, REP2)** | ~~**Нет SDK / готовых клиентов**~~ | **Закрыто кодом.** Крейт `stellereum-sdk`: `TxBuilder::{transfer, token_transfer, token_approve, token_transfer_from, token_mint, token_burn, token_create, stake_bond, delegate, begin_undelegate, undelegate_withdraw, contract_deploy, contract_call}`; адрес деплоя через функцию ноды `predict_contract_address`; конверты chain-bound по умолчанию (`chain_id` 5757, `unbound_legacy` только офлайн + warn). Пины: `stellereum-sdk/tests/canonical.rs` 12/12 byte-equality (прогон REP2 2026-10-28). Остаток — TS-клиент (только Rust-крейт) | — | `stellereum-sdk/src/lib.rs`, `stellereum-sdk/tests/canonical.rs` |
| ~~**B3**~~ **ЗАКРЫТ (W9.3)** | ~~**Per-key archive proofs отсутствуют**~~ | **Закрыто.** Per-key proofs существуют для каждого trie-резидентного слота (балансы, STS-балансы/supply, код/ABI контрактов, commitment-digest), отдаются из персистентной истории снапшотов и аутентифицируются QC якорного блока: `stell_getArchiveProof` (`src/rpc.rs:3038`), `stell_getHistoricalRoot` (`src/rpc.rs:3085`), формат `ArchiveProof` (`src/cpat2.rs:899`), проверка на клиенте (`src/light_client.rs:1565` / `:1616`), правило retention — `src/storage.rs:227-267` (снимки каждые 1000 высот, `STELL_SNAPSHOT_INTERVAL`). Пин: 16 archive-тестов lib. **Остаток по дизайну:** не-trie домены (стейкинг, ордербук, storage контрактов) — digest-only, см. P3/C8 | — | `PROTOCOL.md` §5.4/§7 |
| **B4** | **Восстановление из снапшота не перестраивает commitment** | Commitment пересчитывается при следующем чтении корня; снапшот, снятый до этого изменения, не несёт commitment-ключ, и первое чтение folds in-memory состояние | — | `PROTOCOL.md` §7 |
| **B5** | **Commitment пересчитывается на каждое чтение корня** | O(состояние) на блок — корректно, но дорого; на больших состояниях это заметная нагрузка | `PROTOCOL.md` §7 |
| **B6** | **Кросс-шардовое обязательство — на весь процесс, а не на шард** | Домен `XSHARD_REPLAY_V1` коммитит replay-наборы **всего процесса**, поэтому два шарда одного процесса делят один корень вместо корня на шард | `PROTOCOL.md` §7 |
| **B7** | **Рынок комиссий — статический** | Динамического fee market нет: floor — статический, node-local (`STELL_MIN_GAS_LIMIT` / governance `min_gas_limit`); `eth_gasPrice` / `eth_feeHistory` отдают **хардкод-константы** для testnet. Расхождение floor между валидаторами влияет только на liveness локального пула, не на консенсус — но кошелёк не может предсказать цену в нагрузке | `src/mempool.rs:385-394`, `src/evm_adapter.rs` |
| ~~**B8**~~ **ЗАКРЫТ (W9.2)** | ~~**Формат кошелька не стандартизован**~~ | **Закрыто кодом.** Стандарт подписи: EIP-191-подобный преимаж с chain-id-привязкой (`src/wallet_signing.rs:94` `message_preimage`, домены `:48` / `:53`), envelope v1 (`WALLET_SIG_VERSION = 1`, `:57`), `stell_signMessage`/`stell_verifyMessage`/`stell_signTypedData`/`stell_verifyTypedData` (`src/rpc.rs:4854-4856`), тест-векторы и оба CLI используют его, док — `docs/WALLET_SIGNING.md`. Пин: 14 lib-тестов `wallet_signing`. Остаток — UX: TS-клиент (Rust-крейт закрыл B2 в W11) | — | `src/wallet_signing.rs` |
| ~~**B9**~~ **ЗАКРЫТ (W11, REP2)** | ~~**Explorer не декодирует события по ABI**~~ | **Закрыто кодом + билдом.** Logs-страница `/events` (`explorer-site/explorer/src/pages/Events.tsx`, маршрут `src/App.tsx:36`): фильтры по контракту/блоку/tx, ABI-статус из `stell_getContractAbi` ноды, `decoded` / `raw`-бейджи. Build-доказательство REP2 2026-10-28: `npm run build` exit 0 (`index.html` 1.06 kB, `index-*.js` 70.42 kB, `vendor-*.js` 179.53 kB) | — | `explorer-site/explorer/src/pages/Events.tsx`, `explorer-site/dist-explorer/` |
| ~~**B10**~~ **ЗАКРЫТ КАК КОД (W10.2; ops-хвост — у ops)** | ~~**Нет публичного фауцета для новых пользователей**~~ | **Код закрыт:** фауцет роутит дрипы на шард получателя (`resolve_faucet_recipient`, `src/rpc.rs:2411`, `-1:`/`N:`-хинты, правило `route_shard`), кросс-шардовый дрип отказывается ДО резерва nonce/cap, анти-абуз (IP-троттлинг, капчи-гейт, кап-лимиты) цел — 13/13 `faucet_*`. **Остаток у ops:** публичная фауцет-точка внешнего тестнета (POST, CAPTCHA-гейт) настраивается операционно, не кодом | `src/rpc.rs:248,700,2411,4136`, `src/turnstile.rs`, `tests/faucet_turnstile_tests.rs` |
| **B11** | **Шард 1 на живой сети не «починен» демонстрацией** | Исходный «stand blackhole hunt» закрыт коммитами (`c3e2742`, `735f2f1`, `30f5314`), но **публичной** сети с двумя живыми шардами и работающим split'ом не существует | git log, `docs/SHARDING.md` §0 |

### IV.c. Улучшения (не блокеры, но делают продукт лучше)

| # | Улучшение | Зачем | Ссылка |
| :--- | :--- | :--- | :--- |
| **C1** | **VRF-based сортиция** | Убирает grinding по parent-hash | `src/consensus.rs:728-746` |
| **C2** | **PoP-реестр для BLS** | Включает агрегацию и снимает 100+ подписей на сертификат | `src/bls.rs:474-514` |
| ~~**C3**~~ **ЗАКРЫТ (W8.3, вторая половина)** | ~~**Настоящий ZK (R1CS/STARK-схема или честное переименование)**~~ | Переименование сделано: `src/snark.rs` → `src/zkml_attestation.rs`, опкоды переименованы без смены wire-дискриминантов, `stell_zkmlCapabilities` отдаёт `zero_knowledge:false`. Настоящая ZK-схема — отдельная структурная работа, не блокер | — | `src/zkml_attestation.rs:1` |
| **C4** | **Глобальный `accounts`-лог → шардинг по адресам / COW** | Снимает точку конкуренции на большом железе | `src/state_engine.rs` |
| **C5** | **Настоящий параллелизм для payload-транзакций** | Сейчас параллельно исполняются только plain-переводы | `src/parallel_exec.rs`, `src/state_engine.rs:4180` |
| **C6** | **`rustfmt` / `clippy -D warnings` в CI как блокирующие** | Сейчас оба шага — advisory (`continue-on-error: true`), и в дереве накопился долг | `.github/workflows/ci.yml` |
| **C7** | **Динамический fee market** | Сейчас floor статический; при перегрузке нет ценового сигнала | `src/mempool.rs:385` |
| **C8** | **Per-key commitment для не-EVM подсистем** | Позволяет доказывать стейкинг/ордербук, а не только баланс | `PROTOCOL.md` §7 |
| **C9** | **Commitment-домен на шард, а не на процесс** | Разделяет корни шардов | `PROTOCOL.md` §7 |
| **C10** | **Snapshot-anchor без genesis-anchor** | Genesis-anchor требует доверия к админу снапшота (задокументировано как residual) | `src/sync.rs:359` |
| ~~**C11**~~ **ЗАКРЫТ (W9.2)** | ~~**`secp256k1`-совместимость кошелька / стандарт подписи**~~ | Стандарт envelope v1 + chain-id-привязка + тест-векторы; оба CLI используют его (`docs/WALLET_SIGNING.md`) | — | `src/wallet_signing.rs` |
| **C12** | **Снапшоты по шардам** | Сейчас снапшот — общий на процесс | `src/storage.rs` |
| ~~**C13**~~ **ЗАКРЫТ КАК КОД (W8.5)** | ~~**Кросс-шардовая атомарность (2PC / shared sequencer)**~~ | 2PC-машина в коде (`src/xshard2pc.rs`), 11 тестов; остаток — активация гейтом и живой прогон (см. A3, владелец — ops) | — | `src/xshard2pc.rs` |
| **C14** | **Coverage в CI** | Coverage не измеряется | `.github/workflows/ci.yml` |
| **C15** | **Дрейф документации** | Счётчики тестов в `PROTOCOL.md` (§ «Test counts») устарели; `README.md` местами отстаёт | `PROTOCOL.md`, `README.md` |
| **C16** | **Запрос тела блока у пира по lock-hint** | Упавший автор залоченного блока по-прежнему не даёт высоту завершить: rescue умеет отдать только то тело, которое узел уже держит | `src/runtime.rs:2989-3002`, `:1838-1883` |
| **C17** | **0x29-vs-0x39 interop-стена (ACCEPTED, W10/P4)** | Цепь эмитит только 0x29; reference-совместимый 0x39 отвергается сознательно (иначе — два валидных фрейминга и форк данных). Внешние PQ-интеграции должны знать канон цепи | `src/post_quantum.rs:2185-2257` |
| ~~**C18**~~ **ЗАКРЫТ (R3 2026-10-26)** | ~~**P1-G2…G4: три filed-гепа довести до FIXED/ACCEPTED**~~ | Контента не найдено нигде (поиски R3 — см. строку P1-G2..G4 и пометку в коде); закрыты как ACCEPTED без контента, будущим аудитам как «filed» не числить | `src/consensus_net.rs` (`P1-G2..G4 — ACCEPTED` + `report_p1_g2_g4_*`) |
| **C19** | **1vCPU-потолок слабых нод (владелец — perf/ops)** | Observer C на 1 vCPU (CPUQuota 60%) принимал Committed-блоки по ~30 с при темпе цепи ~1 блок/с — вечное отставание до live-adopt фиксов (`tests/live_adopt_tempo_tests.rs`). Живой прогон на 1vCPU-железе после фиксов не предъявлен; клейм «Да (1 vCPU справляется)» (V5-спек §6) — незамеренный | `tests/live_adopt_tempo_tests.rs`, V5-спек §6 |
| **C20** | **WAN-RTT-пол живого 0.5s-темпа (владелец — perf/ops)** | VEL-харнесс (REP2): LAN mean 350 мс p99 350 мс 0 вью-чейнджей; WAN-контраст mean 690 мс extra_rounds 0 — остаточный зазор до 0.5 с на живом WAN = RTT-пол + мультираундовая рассинхронизация. Verify-once кэши (STAB) сняли повторный крипто-налог, но сеть, а не CPU, теперь потолок | `tests/block_tempo_lan.rs`, `src/runtime.rs:778-800` |

### IV.d. RESIDUAL-отчёты W6, которые остаются (дословно из кода)

Это не «исправленные, но неидеальные» пункты, а **явно оставленные** остатки. Каждый
зафиксирован комментарием в коде — их можно найти поиском по `RESIDUAL`:

| Где | Остаток |
| :--- | :--- |
| `src/consensus.rs:728-746` | Сортиция **grindable**: parent-hash делает комитет неизвестным заранее, но не unforgeable; бар держит network-anchored quorum |
| `src/consensus.rs:730-746` | VRF-based отбор — структурное исправление, «out of scope here» |
| `src/bls.rs:474-514` | PoP-реестра нет; BLS-QC **нельзя** включить — fail-closed до структурного изменения формата |
| `src/mev.rs:1-45` | Threshold preemption не реализован: нет асимметричного sealing, release-раунда долей, sealed gossip |
| `src/mev_epoch.rs:1-60`, `docs/MEV.md` §4 | **W8.4: epoch seal в коде.** Остатки честно зафиксированы: комитет из t читает эпоху при компрометации; liveness DKG; комитет из текущего view сета; дроп без on-chain fee |
| `src/xshard2pc.rs:146` | **W8.5: 2PC активен из генезиса.** `XPC_ACTIVATION_HEIGHT = 0`; env-переключатель удалён; перевод с недостижимым таргетом остаётся в escrow до ответа — цена атомарности. Legacy-записи до активации (на старой цепи) доигрывают старый lifecycle |
| `src/storage.rs:227-267` | **W9.3: retention-правило.** Снимки каждые 1000 высот (`STELL_SNAPSHOT_INTERVAL`); archive-режим хранит всё, prune-режим режет тела старше `height - STELL_KEEP_BLOCKS`; не-trie домены — digest-only |
| `src/mev_v4.rs:25-50` | Движок MEV v4 припаркован: «wiring is FORBIDDEN until the flag is enabled AND the preconditions hold» |
| `src/light_client.rs` (шапка модуля) | **W8.3: подключён** — sync-путь проверяет пирские блоки против кворум-сертифицированного якоря, внешний CLI-верификатор работает. Остатки: нет обновления валидатор-сета (набор — весь trust anchor), нет собственного fetch'а заголовков (transport — проблема вызывающего), нет обработки eclipse/partition |
| `src/zkml_attestation.rs:1` | **W8.3: переименовано и задокументировано честно** — «This is re-execution, not a zk-SNARK» теперь стоит в шапке модуля; нет схемы, нет trusted setup, нет succinctness, нет hiding. Машиночитаемая декларация: `stell_zkmlCapabilities` |
| `src/sync.rs:359` | «RESIDUAL ADMIN TRUST» — genesis-anchor требует доверия к администратору снапшота |
| `src/post_quantum.rs:1604-1643`, `:1970-2010` | Legacy-ключ Falcon имеет ~2³² эффективной энтропии; путь живёт ради исторического genesis root, оператор обязан ротировать ключ |
| `src/consensus.rs:3034-3079` | Локальный re-phase может **сохранить** блокировку, если наблюдался QC — явный размен «liveness на safety» |
| `src/runtime.rs:4698-4726` | Adopt-путь не может проверить prevote-кворум на проводе (нужен wire-изменение); residual задокументирован в коде |
| `src/runtime.rs:3962-3990`, `src/metrics.rs:82` | **W10.1: DIVERGENCE fail-loud.** Хэш блока коммитит только PRE-state root — кворум может финализировать хэш, не сойдясь в post-state; эта ветвь — единственный внутрипротокольный свидетель сплита, поэтому орёт (лог + `stell_divergence_total`). Ресинк НЕ автоматический: канон выбирает оператор через `stelops diverge`, не машина |
| `src/mempool.rs:1508-1517` | **W10.2/P2: pool-pin — backstop, не замена.** Per-call контекст авторитетен, когда есть; пин заставляет непинненные call sites (RPC, explorer, gossip, restore) failing-closed вместо shard-blind |
| `src/post_quantum.rs:2185-2257` | **W10/P4: 0x29 — канон цепи, не референса.** `sign()` всегда эмитил 0x29, каждый блок на диске — 0x29; принять 0x39 значило бы два валидных фрейминга |
| `src/consensus.rs:3012` (`COMMITTED_INNER_BUDGET_PER_TICK = 8`) | **W10/V-P1: Committed-обход капирован.** Дешёвый живой catch-up не голодает 60с, но и не топит тик безлимитно |
| `tests/p2_mempool_pentest.rs:142`, `tests/vp2_verify.rs:725` | **W10/P2: legacy replay — задокументированный эскалированный остаток.** Необвязанная транзакция верифицируется на любой цепи; лечится только rollout'ом сборки+адмиссии |
| `src/state_engine.rs` (параллельный путь) | Настоящий параллелизм — только для plain-переводов |
| `src/parallel_exec.rs` (шапка) | Планировщик волн **advisory**: он может быть консервативен, но не неверен |
| `src/consensus.rs:630-660` | При `N ≤ 64` комитет = вся сеть, и µQC-порог совпадает с сетевым (двухступенчатость неотличима от одноступенчатой) |
| `src/staking.rs:1872-1892` | Пыль от округления F1 остаётся в `rewards_pool` и сознательно **не** выносится (иначе выплата зависела бы от числа делегатов) |

---


## ЧАСТЬ V. КАК ПРОВЕРИТЬ

Все команды проверены на этом дереве **2026-10-23**. Числа в колонке «ожидается» — это
**фактический вывод**, а не оценка. Честные исключения помечены: полный
`cargo test --tests` **не собирается** из-за двух stale-инициализаторов (см. §V.2, A9),
плюс два адресных набора имеют по одному stale-ожиданию.

### V.0. Быстрый чек-лист (для ревьюера, 5 минут)

```bash
cd /home/imm/stellereum-project/stellereum

# 1. Сборка всего, включая примеры и бенчмарки
cargo build --all-targets

# 2. Библиотека (юнит-тесты) — зелёная
cargo test --lib

# 3. Интеграционные наборы — полный прогон без early-exit
cargo test --tests --no-fail-fast

# 4. Индексер
cd ../stellereum-indexer && cargo test && cd -

# 5. Explorer + faucet (npm)
cd ../explorer-site && npm run build && cd -

# 6. Фаззинг: сборка + короткий прогон по закоммиченному корпусу
cargo +nightly fuzz build
for t in frame_decode consensus_msg_decode transaction_decode block_decode cert_envelope_decode evm_raw_tx_decode peer_msg_decode; do
  cargo +nightly fuzz run "$t" -- -runs=2000 -timeout=10
done

# 7. Health-скрин кластера (нужен живой RPC)
./scripts/cluster_health.sh            # или: ../scripts/stell-sync.sh health
```

### V.1. Сборка

| Команда | Ожидается (2026-10-25, S7-retry3) |
| :--- | :--- |
| `cd stellereum && cargo build --all-targets` | **0 ошибок** (проверено 2026-10-25; раньше 2 таргета не линковались — A9 закрыт; 2026-10-28 не перегонялся отдельно — полный `cargo test --tests` скомпилировал все 216 таргетов) |
| `cd stellereum && cargo build --release` | (не перегонялся 2026-10-25; не перегонялся 2026-10-28) |
| `cd stellereum && cargo build --examples --benches` | **0 ошибок** (проверено 2026-10-28, GUARD, ~60 с; было «не перегонялся 2026-10-25») |

### V.2. Тесты

| Команда | Ожидается (2026-10-25) | Комментарий |
| :--- | :--- | :--- |
| `cd stellereum && cargo test --lib` | **1034 passed; 0 failed** (2026-10-28, REP2, 20.31 с; было 1025 GUARD, +9 новых: TAIL-1/heat-пути commitment-кэша и смежные; было 936 2026-10-25) | зелёная; GUARD-фикс `archive_proof…restart` (retry reopen, `src/storage.rs:3945`) держится |
| `cd stellereum && cargo test --test audit_repro_tests` | **4 passed; 0 failed** (2026-10-28, GUARD, 5/5 прогонов) | было 3+1 FAILED в полном `--tests`: `repro_4` гонялся с окном `set_pure_pq_override(Some(true))` из `repro_3` (process-wide atomic для интеграционных бинарей) — сериализовано статическим Mutex, `tests/audit_repro_tests.rs:18-24` |
| `cd stellereum && cargo build --all-targets` | **0 ошибок** (2026-10-25) | оба stale-инициализатора починены — A9 закрыт |
| `cd stellereum && cargo test --test consensus_liveness_harness` | **13 passed; 0 failed; 1 ignored** | детерминированный liveness-harness W8.2 |
| `cd stellereum && cargo test --test consensus_liveness_repro` | **15 passed; 0 failed** (2026-10-25) | было 14+1 stale — ожидание вылечено под R1-бюджет |
| `cd stellereum && cargo test --test light_client_wiring_tests` | **15 passed; 0 failed** (2026-10-25) | было НЕ СОБИРАЕТСЯ — починено |
| `cd stellereum && cargo test --test sharding_topology_tests` | **6 passed; 0 failed** (2026-10-25) | было НЕ СОБИРАЕТСЯ — починено (набор ужался до 6 после рефактора топологии) |
| `cd stellereum && cargo test --test hunt_consensus_round2` | **9 passed; 0 failed** | старый A9-хвост (W9.1 `source_hash`) починен |
| `cd stellereum && cargo test --test mev_epoch_seal_tests` | **25 passed; 0 failed** | epoch seal W8.4 |
| `cd stellereum && cargo test --test xshard_2pc_tests` | **11 passed; 0 failed** | 2PC W8.5 |
| `cd stellereum && cargo test --test mempool_mev_audit_closure_tests` | **10 passed; 0 failed** | MEV-замыкание |
| `cd stellereum && cargo test --test audit_rpc_evm_closeout` | **30 passed; 0 failed** (2026-10-25) | было 29+1 stale — allowlist теперь знает `stell_divergence_total` |
| `cd stellereum && cargo test --lib wallet_signing` | **14 passed; 0 failed** | стандарт подписи W9.2 |
| `cd stellereum && cargo test --lib contract_source` | **9 passed; 0 failed** | верификация исходников W9.1 |
| `cd stellereum && cargo test --lib archive` | **16 passed; 0 failed** | archive proofs + retention W9.3 |
| `cd stellereum && cargo test --lib cpat2` | **22 passed; 0 failed** | trie + `ArchiveProof` |
| `cd stellereum && cargo test --test p2_mempool_pentest` | **16 passed; 0 failed** | пентест P2 (W10) |
| `cd stellereum && cargo test --test p3_byzantine_pentest` | **23 passed; 0 failed** | пентест P3 (W10) |
| `cd stellereum && cargo test --test p4_crypto_pentest` | **24 passed; 0 failed** | пентест P4, 24-батарея (W10) |
| `cd stellereum && cargo test --test vp2_verify` | **16 passed; 0 failed** | верификация V-P2 (W10) |
| `cd stellereum && cargo test --test v34_verification_pentest` | **13 passed; 0 failed** | верификация V-P34 (W10) |
| `cd stellereum && cargo test --test chase_livelock_tests` | **13 passed; 0 failed** | chase-набор, затронут R1 (W10) |
| `cd stellereum && cargo test --test pq_fork288000_replay` | **5 passed; 0 failed** | офлайн-реплей #288000, канон C (W10.1) |
| `cd stellereum && cargo test --lib fork288000` | **4 passed; 0 failed** | fork-харднинг `commit_native` (W10.1) |
| `cd stellereum && cargo test --lib faucet_` | **13 passed; 0 failed** | фауцет-роутинг (W10.2) |
| `cd stellereum && cargo test --lib p5_` | **8 passed; 0 failed** | пентест P5: auth/bridge/staking/token/contract (W10) |
| `cd stellereum && cargo test --lib pentest_` | **4 passed; 0 failed** | пентест P1, lib-часть (F1–F4) (W10) |
| `cd stellereum && cargo test --lib verification_` | **23 passed; 0 failed** | V-P1-пины + смежные верификации (W10) |
| `cd stellereum && cargo test --test transport_audit_fixes` | **4 passed; 0 failed** | транспортные пины |
| `cd stellereum && cargo test --test hunt_round_dos` | **8 passed; 0 failed** | round-DoS бюджет (смежен R1) |
| `cargo test -p infnode --lib` (крейт infnode) | **44 passed; 0 failed** (2026-10-25; при первом прогоне 43+1 flaky, повтор — 44/44) | в т.ч. P1-F5/F6: 3 pentest + 2 verification (W10) |
| `cd stellereum-indexer && cargo test` | (не перегонялся 2026-10-25; было **21 passed; 0 failed**) | индексатор — см. сертификацию: отдельный процесс не запущен, статусы ниже |

**Про красное состояние — честно (обновлено 2026-10-28, GUARD, финально).** Красная тройка W10 **закрыта**: оба stale-инициализатора починены (wiring 15/15, topology 6/6), оба stale-ожидания вылечены (repro 15/15, closeout 30/30). `cargo build --examples --benches` — 0 ошибок (2026-10-28). Полный `cargo test --tests --no-fail-fast` run #2 2026-10-28: **216 сьютов, 2884 passed / 0 failed**; lib финально **1025/0**. Два GUARD тест-фикса: lib-flake `archive_proof…restart` (sled lock под параллелью → retry-reopen, `src/storage.rs:3945`) и `audit_repro_tests::repro_4` (PQ-override race → Mutex, `tests/audit_repro_tests.rs:18-24`). Старый остаток flake-класса прежний: infnode-lib давал 43+1 при первом прогоне (флейк, не регресс). Зафиксировано вмешательство: во время батареи в дереве шла параллельная правка протокола (commitment domain-cache: `src/commitment.rs`, `src/state_engine.rs` — новые поля `domain_cache`/`domain_gens`, `dom_guard`), дерево дважды временно не собиралось (E0063 → lifetime в `dom_guard`, `src/state_engine.rs:6936`; GUARD scope — FILED, не чинено); финальные числа сняты на зелёном дереве (`cargo check --lib` exit 0, clippy --lib/--test exit 0).
Старые три класса устаревших ожиданий (failure-fee, D2-корень, genesis-bond) —
ниже, для пересчёта после починки инициализаторов.

История трёх классов устаревших ожиданий (для пересчёта после починки):

1. **Класс «failure fee»** (F-01, волна W1). Тесты ждут «отклонённая транзакция не
   платит ничего», а по SEC-07 сбойная транзакция **обязана** заплатить floor и
   сжечь nonce. Примеры: `clob_fill_rolls_back_when_the_native_commit_fails`
   (`left: [100000], right: [0]`), `under_reserved_svm_taker_cannot_touch_the_book_or_the_escrow`,
   `breaker_reset_requires_a_passed_executed_governance_action` (`zero-floor failure pays nothing`).
2. **Класс «корень состояния»** (W6-18). Тесты ждут «отклонённая операция не двигает
   state root», но после W6.6 карта D2-штрафа **едет вместе с состоянием** — значит
   отклонённая транзакция поднимает floor своего отправителя и **корень меняется**.
   Это и было целью фикса (иначе восстановленная нода считала бы другие комиссии и
   получила бы другой корень). Примеры: `stale_feed_rejected_at_block_time`,
   `deviation_feed_rejected_latches_breaker_and_blocks_later_feeds`,
   `invalid_pq_evidence_is_refused_fail_closed`,
   `forged_confidential_transfer_is_rejected_without_moving_state`.
3. **Класс «genesis-bond»** (SEC-ECON-01). `fund_genesis` переносит
   `GENESIS_VALIDATOR_BOND` (= `MIN_VALIDATOR_BOND` = 1 000 STELL) с аккаунта
   валидатора в `STAKING_POOL`, чтобы genesis-стейк был обеспечен. Тест
   `same_validator_set_yields_identical_state_root` всё ещё ждёт `balance == BAL`
   (`left: 99999000000000000, right: 100000000000000000`). **Само свойство
   детерминизма при этом проходит**: корни двух нод с одинаковым валидатор-сетом
   совпадают (assert на строке 31 проходит, падает только проверка баланса на строке 37).

> Отдельно: во время подготовки этой ревизии **был** ещё один красный тест —
> `b2_true_challenge_revoke_pays_bond_plus_reward_and_burns_rest` в
> `tests/audit_closure_bridge_tests.rs`. Он падал потому, что волна W7.1 (truth-gate
> моста) изменила ожидаемое поведение спора, а тест всё ещё требовал отзыва депозита по
> **поддельному** доказательству. Тест переведён на настоящее кворумное доказательство
> (`genuine_failure_proof`) — в текущем дереве он зелёный.

### V.3. Индексер

| Команда | Ожидается | Что покрывает |
| :--- | :--- | :--- |
| `cd stellereum-indexer && cargo test` | **21 passed; 0 failed** | `tests/indexer_api_tests.rs`: схема SQLite и запросы, WAL на файле, Gram-совместимость API и поиск, графики block-time, **контрактные события (`test_contract_events_endpoints`)**, **декодирование событий по ABI (`test_events_are_decoded_with_the_contract_abi`)**, фильтры событий в БД, разбор обеих форм raw-события |
| | | Схема: `contract_events(tx_hash, block_height, contract, event_name, topic, value, …)` + 4 индекса — `stellereum-indexer/src/db.rs:201-222` |

### V.4. Explorer / faucet (фронтенд)

| Команда | Ожидается |
| :--- | :--- |
| `cd explorer-site && npm run build` | **exit 0** (прогон REP2 2026-10-28): `testnet-explorer` (`tsc --noEmit && vite build` → `✓ built in 1.09s`) и `testnet-faucet-backend` (`build-ok`) |

Артефакт: `explorer-site/dist-explorer/` (`index.html` 1.06 kB, `index-*.js` 70.42 kB,
`vendor-*.js` 179.53 kB; было 62.69/178.67 — выросла Logs-страница `/events`).

### V.5. Фаззинг

| Команда | Ожидается |
| :--- | :--- |
| `cd stellereum && cargo +nightly fuzz build` | `Finished release profile ...`, **0 ошибок**; собираются **7** таргетов: `frame_decode`, `consensus_msg_decode`, `transaction_decode`, `block_decode`, `cert_envelope_decode`, `evm_raw_tx_decode`, `peer_msg_decode` (последние 3 — новые в W8.7) |
| `cargo +nightly fuzz run frame_decode -- -runs=2000 -timeout=10` | `Done 2000 runs`, без краша |
| `cargo +nightly fuzz run consensus_msg_decode -- -runs=2000 -timeout=10` | `Done 2000 runs`, без краша |
| `cargo +nightly fuzz run transaction_decode -- -runs=2000 -timeout=10` | `Done 2000 runs`, без краша |
| `cargo +nightly fuzz run block_decode -- -runs=2000 -timeout=10` | `Done 2000 runs`, без краша |

**Корпус: 4427 файлов в рабочем дереве** (`find fuzz/corpus -type f | wc -l` на
2026-10-23; закоммиченное число отличается, т.к. здесь нет git-репозитория для
`git ls-files`, а libFuzzer дописывает входы при прогонах).

Тот же корпус детерминированно прогоняется под stable: `cargo test --test fuzz_decoder_tests`.

> Историческая справка: в исходной оценке (PART I) корпус был «2049 файлов» и путь
> фаззинга вёл на **несуществующий абсолютный путь** (`/home/imm/infmail-valid-backend/...`),
> из-за чего `cargo fuzz` не работал на чистом клоне. Сейчас путь **относительный**
> (`fuzz/Cargo.toml`: `path = "../../infmail-valid-backend/crates/infnode"`), а `cargo +nightly fuzz build`
> проходит. Число файлов корпуса отличается от «2049» потому, что libFuzzer
> **дописывает** новые входы в корпус при каждом прогоне (сейчас в рабочем дереве 2062).

### V.6. Health-скрин кластера

| Команда | Ожидается |
| :--- | :--- |
| `cd stellereum && ./scripts/cluster_health.sh` | Форвардит на `../scripts/stell-sync.sh health`. Печатает: валидатор-сет с power'ом каждого участника и суммарным power'ом, quorum и флаг `fragile`; shard-head'ы (тип, высота tip, хэш tip, локальный/нет); chain tip по каждому шарду; tip индексера; round-trip задержку RPC. **Exit 0** — все проверки прошли; **exit 1** — какая-то не прошла |
| `cd stellereum && ./scripts/cluster_health.sh --rpc URL --indexer URL --timeout SECS` | те же проверки с явными адресами |

**Без живой ноды** скрипт честно печатает `[WARN] could not read the validator set from
http://127.0.0.1:8545` и продолжает — это ожидаемое поведение на машине без запущенного
кластера (проверено локально).

### V.7. Целевые регрессионные наборы по волнам

Каждая волна имеет свой адресный набор тестов — их можно гонять точечно:

| Волна | Команда |
| :--- | :--- |
| W1 (SEC-01) | `cargo test --test consensus_reaudit_tests --test adopt_prevote_tests` |
| W1 (SEC-03) | `cargo test --lib consensus::tests::test_signers_set_extraction_falcon_uqc_bls_and_classical` |
| W1 (SEC-04) | `cargo test --lib governance::tests` |
| W1 (SEC-05) | `cargo test --lib cpat2::tests` + `cargo test --test cpat2_stress` |
| W1 (SEC-06) | `cargo test --bin stellereum test_sec06_deferred_queue_time_gated_and_prioritizes_rx` |
| W1 (SEC-07) | `cargo test --lib state_engine::tests::test_sec07_free_failure_dos_charges_fee_and_increments_nonce` + `cargo test --test apply_floor_tests` |
| W2 (контракты) | `cargo test --test contract_integration_tests --test ecosystem_contracts_tests` + `cargo test --lib contract::tests` |
| W3 (стриминг/шардинг) | `cargo test --test streaming_sse_http_tests --test sharding_topology_tests --test light_client_tests` |
| W4 (PQ/сортиция/F1) | `cargo test --lib post_quantum::tests --test pq_audit_closure_tests --test pq_uqc_power_quorum_tests --test staking_rewards_pool_tests` |
| W5 (order/параллелизм/ABI) | `cargo test --lib state_engine::tests::test_parallel_wave_execution_is_deterministic --test parallel_execution_tests` + `cargo run --bin abi_codegen -- contracts/sts20_token_abi.json --lang both --out-dir target/abi` |
| W6 (ре-аудиты) | `cargo test --test consensus_reaudit_tests --test consensus_rephase_tests --test network_audit_close_tests --test staking_audit_closure_tests --test mempool_mev_audit_closure_tests --test pq_audit_closure_tests --test audit_closure_bridge_tests --test audit_closure_oracle_gov_tests --test audit_closure_privacy_tests` |
| W7 (мост/Governance/RPC) | `cargo test --test audit_closure_bridge_tests --test governance_applied_tests --test audit_rpc_evm_closeout` |
| W8 (liveness/MEV/2PC/LC) | `cargo test --test consensus_liveness_harness --test consensus_liveness_repro --test light_client_wiring_tests --test mev_epoch_seal_tests --test xshard_2pc_tests --test chase_livelock_tests --test hunt_round_dos` |
| W9 (артефакты) | `cargo test --lib wallet_signing --lib contract_source --lib archive --lib cpat2` |
| W10 (fork/faucet/pentest/verify) | `cargo test --test pq_fork288000_replay --test p2_mempool_pentest --test p3_byzantine_pentest --test p4_crypto_pentest --test vp2_verify --test v34_verification_pentest --test chase_livelock_tests` + `cargo test --lib fork288000 faucet_ p5_ pentest_ verification_` + `cargo test -p infnode --lib` |
| Индексер | `cd stellereum-indexer && cargo test` |

Проверено точечно на этом дереве 2026-10-23: `cargo test --lib` → **926 passed +
1 flaky (соло зелёный), 927 всего**;
`consensus_liveness_harness` → **13 passed + 1 ignored**; `consensus_liveness_repro` →
**14 passed + 1 stale-ожидание**; `light_client_wiring_tests` → **НЕ СОБИРАЕТСЯ**
(E0063); `mev_epoch_seal_tests` → **25 passed**; `xshard_2pc_tests` →
**11 passed**; `mempool_mev_audit_closure_tests` → **10 passed**;
`audit_rpc_evm_closeout` → **29 passed + 1 stale-ожидание**;
`cargo test --lib wallet_signing` → **14 passed**; `contract_source` →
**9 passed**; `archive` → **16 passed**; `cpat2` → **22 passed**;
W10: `p2_mempool_pentest` → **16 passed**; `p3_byzantine_pentest` → **23 passed**;
`p4_crypto_pentest` → **24 passed**; `vp2_verify` → **16 passed**;
`v34_verification_pentest` → **13 passed**; `chase_livelock_tests` → **13 passed**;
`pq_fork288000_replay` → **5 passed**; `cargo test --lib fork288000` → **4 passed**;
`faucet_` → **13 passed**; `p5_` → **8 passed**; `pentest_` → **4 passed**;
`verification_` → **23 passed**; `transport_audit_fixes` → **4 passed**;
`hunt_round_dos` → **8 passed**; `hunt_consensus_round2` → **9 passed**;
infnode `--lib` → **44 passed** (в т.ч. 3 pentest + 2 verification).

### V.8. CI (`.github/workflows/ci.yml`)

| Job | Что делает | Статус |
| :--- | :--- | :--- |
| `lint` | `cargo fmt --all -- --check` и `cargo clippy --all-targets --all-features -- -D warnings` | **advisory** (`continue-on-error: true`) — в дереве есть предсуществующий долг форматирования и clippy |
| `build` | `cargo build --all-targets` + `cargo build --release` | блокирующий |
| `test` | `cargo test --lib`, `cargo test --tests`, `cargo run --example passport_audit`, `vuln_hunt{,2,3,4}` | блокирующий (и **красный** на текущем дереве — см. V.2) |
| `audit` | `rustsec/audit-check@v2.0.0` — зависимости против RustSec | блокирующий |
| `fuzz` | `cargo +nightly fuzz build` + 4 таргета по `-runs=2000 -timeout=10` | блокирующий, nightly |

### V.9. Метрики дерева на момент среза (2026-10-28, REP2)

| Метрика | Значение |
| :--- | :--- |
| Файлов в `src/*.rs` | 55 |
| Файлов в `tests/*.rs` | 207 (`ls tests/*.rs | wc -l`) |
| Юнит-тестов в библиотеке | **1034** (`cargo test --lib`: 1034 passed, 0 failed, 2026-10-28 REP2 20.31 с; было 1025 GUARD, 936 на 2026-10-25) |
| Полный `--tests --no-fail-fast` | **216 сьютов: 2884 passed, 0 failed** (2026-10-28 GUARD run #2; в run #1 было 2883/1 — единственный failure `audit_repro_tests::repro_4` test-wrong, закрыт тест-фиксом, повтор 5/5 зелёный) |
| W10-наборы (все зелёные) | p2 16, p3 23, p4 24, vp2 16, v34 13, chase 13, fork-replay 5, fork-lib 4, faucet-lib 13, p5-lib 8, pentest-lib 4, verification-lib 23, infnode-lib 44 (1 флейк при первом прогоне) |
| W11-наборы (все зелёные, прогоны REP2 2026-10-28) | paymaster 21, shielded-path 4, one-call-order 7, mmr-epoch-root 3, SDK-canonical (byte-equality) 12, TAIL-1 perf: commitment hot-cache speedup 11–17× (debug, этот бокс), receipt-batched speedup 1.18× (debug), tx-hash-batched 1.35×, engine-commit 6.8×; VEL `block_tempo_lan` 2/2: LAN mean 350 мс p99 350 мс 0 вью-чейнджей, WAN mean 690 мс extra_rounds 0 |
| Liveness-harness | 13 passed + 1 ignored (детерминирован) |
| Liveness-repro | **15 passed** (было 14+1 stale — вылечено) |
| Closeout | **30 passed** (было 29+1 stale — вылечено) |
| Wiring / topology | 15 passed / 6 passed (были НЕ СОБИРАЮТСЯ — починены) |
| Прямых зависимостей | 35 (`Cargo.toml`, секция `[dependencies]`); `pqcrypto-falcon` — **используется** (C-архив FIPS 206), `group`/`ff` 0.13 — **выброшены** как прямые |
| Примеров/бенчмарков | `cargo build --all-targets` — **0 ошибок** (все таргеты линкуются) |
| Известные поломки сборки тестов | нет (A9 закрыт) |
| Известные stale-ожидания | нет (оба вылечены); остаток — flake-класс infnode-lib (43+1 → 44/44) |

---

## ЧАСТЬ VI. ИТОГ

Десять волн закрыли **все семь критических уязвимостей** первой волны, превратили
контрактный слой из «демо» в рабочий (13 host-импортов, deploy/call/getter, ABI,
события end-to-end, верификация исходников, auth-гейты P5), встроили light client
в sync-путь с внешним верификатором, добавили стриминг WS/SSE, fork-choice с
invalidation-сигналами, кросс-шардовый P2P-транспорт, сортицию с сетевым якорем
кворума, FIPS 206-подпись, стандарт подписи кошелька, per-key archive proofs — и
закрыли ещё **~40** находок четырёх независимых ре-аудитов. Волна W8 нашла и закрыла
настоящий живой корень liveness-шторма мастерчейна (`note_peer_vote_round`) и
упаковала сеть для внешнего аудита; волна W9 сделала артефакты проверяемыми;
волна W10 **вылечила живой форк** (неатомарный commit → атомарный undo +
DIVERGENCE-аларм + офлайн-дифф), починила фауцет-роутинг, прогнала пять пентестов
(P1–P5, 26 фиксов) с тремя независимыми верификациями и зафиксировала OS-бэклог.
Волна W11 (REP2-синк): STAB verify-once кэши + MMR-кэш эпох, TAIL-1 domain-кэш +
батчированные receipt-хэши с дифференциальными пинами, VEL 0.5s-харнесс (LAN/WAN
замерены лично), MMR epoch roots в блоках + `stell_getEpochRoot`, SDK-крейт с
byte-equality, Logs-страница `/events` с build-доказательством, B2/B9 закрыты,
paymaster/privacy/burn/order/bridge поверхности запиннены.

При этом в «доказанное» по-прежнему не превратились четыре вещи: **живой шардовый
split**, **живая 2PC-финализация** (код за гейтом), **живая DKG-церемония эпохи** (код
готов) и **внешний аудит** (пакет готов, аудитора нет). Красная строка W10 **закрыта**
(A9: сборка и stale-ожидания починены 2026-10-25). Живая сеть 2026-10-28 **сошлась**
(идентичные tip/state_root на обоих RPC, 0 DIVERGENCE за 3 ч), но канон-как-процесс
по **#305832** не предъявлен (обновлённый A18) — это главный открытый пункт.
Эскалированы два структурных хвоста: legacy-replay требует chain-binding rollout,
эквивокация предложений — нового evidence type.

**Вердикт: ~8.5/10 как прототип и публичный тестнет, ~6.5/10 как production L1.**
Против исходных ~6.5/10 и ~4.5/10. Хранилище поднято 8.5→9/10 — за измеренное:
MMR epoch roots в блоках + `stell_getEpochRoot` 3/3 (единственная дельта скоринга,
одна строка основания). Остальное без дельт: код зеленее (1034 lib на 2026-10-28
REP2, все таргеты собираются), живая сеть сошлась, но STABLE не присваивается без
канон-процедуры (см. сертификацию + секцию REP2 ниже).
Основной сдвиг волн — не «больше кода», а переход критических слоёв из состояния «нет»
в состояние «есть, покрыто тестом и честно описано, где кончается код и начинается
операционная работа»: живой форк вылечен и запиннен, контракт-auth закрыт,
пентест-поверхность проверена
независимо. Оставшиеся пробелы перечислены в ЧАСТИ IV; каждый из них — реальный,
а не rhetorical.

---

## STABLE TESTNET CERTIFICATION (S7-retry3, 2026-10-25, только read-only RPC)

### C.0. Гейт (заявлен явно, затем проверен)

1. 4/4 валидатора, `fragile == false` на всех сверяемых нодах;
2. 30+ мин непрерывной финализации (рост tip обоих шардов, без пауз);
3. идентичные корни в сэмплах (`state_root`/`tip_hash`/`block_hash` совпадают между нодами);
4. измеренный block time (по `eth_getBlockByNumber.timestamp` и по приросту tip);
5. ноль DIVERGENCE за окно (`journalctl` + `stell_divergence_total`);
6. explorer-сборка актуальна и индексер отслеживает tip.

### C.1. Фактические свидетельства (команды и вывод, 2026-10-25 ~21:50–21:55 UTC)

* `stell_getValidators` на `http://127.0.0.1:8546` (nodeB) и `http://127.0.0.1:18545` (туннель до nodeA): обе — 4 валидатора, `fragile: false`, `quorum` ~4.977e12, `total_power` ~7.465–7.469e12. Мощность D различается на ~4e6 (1996002000000 vs 2000000000000) — мелкое расхождение вью, не fragility, но зафиксировано.
* `stell_getShards` (обе ноды): шард 0 — `tip_height 305831` на обеих; шард 1 — `tip_height 162700→162712`, `tip_hash 72d1f8e9…` и `state_root 54852fd2…` **идентичны** на обеих; чекпоинт `stell_getFinalizedCheckpoint` — `height 162700`, `block_hash 72d1f8e9…`, `state_root 54852fd2…` **идентичен**; `eth_blockNumber` — `0x4aaa7` (305831) на обеих, `eth_getBlockByNumber latest.hash = 0xa8cb9b17…` на обеих.
* НО: поле шарда 0 `state_root` различается (B fallback `9c33…` vs A `01b036…` vs ранее финализированный `b922…`/`a8cb9b17…`), у A `tip_hash: null` (путь 2 `collect_shard_heads`: `recent_blocks` пуст / репликация отстаёт — `stell_getBlock → not in recent window`), у B в поздних сэмплах тоже `tip_hash: null`. Это не «три канона», а симптом одного события ниже.
* Block time по истории: `eth 0x4aa9d→0x4aaa7` (10 блоков) за ~20 с → **~2 с/блок** на мастерчейне до остановки; воркчейн по `FINALIZED`-логам 162560 (21:20) → 162705 (21:49): 145 блоков за ~1785 с → **~12.3 с/блок**; живой сэмпл 75 с 21:52–21:53: мастерчейн **0 блоков (HALTED)**, воркчейн +7 за ~4 мин (~34 с/блок, деградация).
* DIVERGENCE: `journalctl --user -u stell-nodeB --since '35 min ago' | grep -c DIVERGENCE` = **222**; за последние 10 мин — **40**; свежие строки 21:47: `height=305832 block=76312de7… proposer=c2313fbaf5c0… their_root=01b036… our_root=9c33… same finalized hash, different post-state`. Форма — та же, что #288000 (один хэш, два post-state), но высота новая (#305832), канон **не выбран**.
* Explorer/indexer: `explorer-site/dist-explorer` собран 18:42 (index.html 1066 Б); `vite preview --port 5173` запущен, отвечает; порт 8080 отвечает 400 без Host (ожидаемо для шлюза); **отдельный процесс индексер/синкер не запущен** (в `ps` только nodeB + vite), БД индексера не найдена — «indexer tracking» как живой процесс **не предъявлен**, хотя код декодирования ABI покрыт тестами (`indexer_api_tests`).

### C.2. Таблица 30 перепроверенных заявлений (10 PART II + 10 PART III + 10 W10)

Каждая строка: якорь grep (паттерн жив, строка могла уплыть после 2026-10-23) + пин-тест, прогнанный 2026-10-25. Легенда: **VERIFIED** — паттерн и пин на месте; **STALE** — паттерн ушёл/строка уплыла без замены; **FALSE** — заявление неверно. Итог: **30/30 VERIFIED** (с дрейфом строк, все пины зелёные).

**PART II (10):**

| # | Заявление (PART II) | Якорь grep 2026-10-25 | Пин-тест 2026-10-25 | Статус |
| :--- | :--- | :--- | :--- | :--- |
| II-1 | Agent1 #1: инверсия замка исправлена (`certificate.round <= locked_round`) | `src/runtime.rs:6650` `if certificate.round <= locked_round && locked_block != bh` + комментарий про старый дефект | `consensus_reaudit_tests` 11 passed (кейсы `:416,:434,:455` + `adopt_prevote_tests`) | **VERIFIED** (строка уплыла 4693→6650, паттерн цел) |
| II-2 | Agent1 #3: каскад раундов заменён конвергенцией `note_peer_vote_round/sync_round_to` | `src/runtime.rs:4526 note_peer_vote_round`, `src/consensus.rs:3608 sync_round_to`, `MAX_SYNC_JUMPS_PER_ROUND=8` | `consensus_liveness_harness` 13+1 ignored; `consensus_liveness_repro` **15 passed** (stale вылечен); `chase_livelock_tests` 13 passed | **VERIFIED** |
| II-3 | Agent2 #2: сортиция на parent-hash (`STELL_SORTITION_V5`) | `src/consensus.rs:747 derive_sortition_committee`, `:821 STELL_SORTITION_V5`, `sortition_seed(prev_block_hash…)` | `pq_uqc_power_quorum_tests` (в lib-прогоне 936) + `pure_pq_enforcement` | **VERIFIED** |
| II-4 | Agent2 #3: `chain_id` в голосах и хэше блока | `src/consensus.rs:1202 vote_sign_bytes` + `consensus_chain_id().to_be_bytes()`; `src/sharding.rs:4446` | `block_hash_binding_tests` + `consensus::test_vote_signature_is_bound_to_chain_id` (lib 936) | **VERIFIED** |
| II-5 | Agent2 #4: µQC network-anchored quorum (`required = max(2/3 комитета, 1/2 сети)`) | `src/consensus.rs:635 MICRO_COMMITTEE_MAX_SIZE=64`, `:691 pq_micro_required_power` | `pq_uqc_power_quorum_tests` + `consensus::quorum-math` (lib 936) | **VERIFIED** |
| II-6 | Agent3 #3: паритет газа токенов (`GAS_TOKEN_* == GAS_BASIC_TRANSFER`) | `src/token.rs:32-42` + `const assert >=` в `src/svm.rs` | `apply_floor_tests` + `state_engine::test_sec07…` (lib 936) | **VERIFIED** |
| II-7 | Agent4 #1: time-gated `inbound_deferred` с приоритетом `rx` | `src/main.rs:3178 inbound_deferred`, `:4115 deferred…until scheduled`, `test_sec06…` | `test_sec06_deferred_queue_time_gated_and_prioritizes_rx` (lib 936) | **VERIFIED** (строка уплыла 3748→~4115) |
| II-8 | Agent5 #3: `tx_belongs_to_shard` — строгое владение источником | `src/sharding.rs:538-540` `tx.source_shard == shard_id` | `tx_belongs_to_shard_enforces_strict_partition_isolation` + `p2_mempool_pentest` 16 passed | **VERIFIED** |
| II-9 | Agent6 #1: failure fee + сжигание nonce (`apply_failure_fee_to_map`) | `src/state_engine.rs:3140/3160` SEC-07 failure fee | `test_sec07_free_failure_dos…` (lib 936) + `apply_floor_tests` | **VERIFIED** (строка уплыла 3100→3140) |
| II-10 | Agent7 #1: `signers_set` разворачивает µQC/BLS-битовую маску | `src/consensus.rs:2654 signers_set` + `PQ_UQC_MARKER_ID` | `test_signers_set_extraction…` + `v34_r2a–r2e` 13 passed | **VERIFIED** (строка уплыла 2537→2654) |

**PART III (10: SEC + W6/W7):**

| # | Заявление (PART III) | Якорь grep 2026-10-25 | Пин-тест 2026-10-25 | Статус |
| :--- | :--- | :--- | :--- | :--- |
| III-1 | SEC-04: нулевой хэш апгрейда запрещён на 3 уровнях | `src/governance.rs:279` `*sha256 == [0u8;32] → InvalidAction`, `:1060`, `:628` | `governance::tests action_zero_sha` (lib 936) | **VERIFIED** |
| III-2 | SEC-05: `remove` — локальная рекурсия, не перестройка | `src/cpat2.rs:262 remove` + `Node::remove_node` | `test_remove_is_differential_against_rebuild` + `cpat2_stress` + lib cpat2 22 passed | **VERIFIED** |
| III-3 | W6-06: lock-hint rescue только свои тела (`proposer == self.id`) | `src/runtime.rs:2989 note_lock_hint` «OUR body means we AUTHORED it» | `consensus_rephase_tests` + `deadlock_breaker_tests` | **VERIFIED** (строка уплыла, паттерн цел) |
| III-4 | W6-18: D2-штраф едет в снапшоте | `src/state_engine.rs:11047` `snapshot_carries_the_d2_penalty…` | `snapshot_carries_the_d2_penalty_so_a_restored_node_agrees` (lib 936) | **VERIFIED** |
| III-5 | W6-26: `upgrade_name_is_safe` (path traversal) | `src/governance.rs:518 upgrade_name_is_safe` | `governance::tests` (lib 936) | **VERIFIED** |
| III-6 | W6-27: `stage_verified_upgrade_binary` (TOCTOU → копия 0700) | `src/governance.rs:649 stage_verified_upgrade_binary` | `governance` stage-тесты (lib 936) | **VERIFIED** |
| III-7 | W6-29: `stell_executeProposal` за токен-гейтом | `src/rpc.rs:4829 stell_executeProposal` + `12383 require-auth` | `audit_rpc_evm_closeout` **30 passed** (`executeProposal must require auth`) | **VERIFIED** |
| III-8 | W6-34: атомарная запись ключей (`fsync`→`rename`→`fsync`) | `src/node_keys.rs:392 atomic_write_private` + `:386 DURABILITY` | `atomic_write_private_replaces_content_and_keeps_0600` (lib 936) | **VERIFIED** |
| III-9 | W6-38: nil-polka не снимает замок (только кворум за другое непустое) | `src/consensus.rs:3067 unlock — только по кворуму` (область 3034–3079) | `consensus_rephase_tests` + harness 13 passed | **VERIFIED** |
| III-10 | W7-01: truth-gate моста (только кворумная ретракция) | `src/bridge.rs:738 THE ONLY FRAUD PROOF`, `:1517 truth gate` | `audit_closure_bridge_tests` (b2 truth-gate зелёный) | **VERIFIED** |

**W10 (10: fork/faucet/P1–P5/V):**

| # | Заявление (W10) | Якорь grep 2026-10-25 | Пин-тест 2026-10-25 | Статус |
| :--- | :--- | :--- | :--- | :--- |
| W-1 | W10-FORK: атомарный undo + отказ до мутации | `src/state_engine.rs:3355` undo-лог (область 592–831, 1834–2441) + `:3405 pre-mutation` | `fork288000_*` lib **4 passed** + `pq_fork288000_replay` **5 passed** | **VERIFIED** |
| W-2 | W10-FORK: DIVERGENCE-лог + `stell_divergence_total` + `stelops diverge` | `src/runtime.rs:4189-4206 DIVERGENCE`, `src/metrics.rs:82 DIVERGENCE_TOTAL`, `stelops/.../main.rs:594` | `p3_diverge…halts_not_forks` + `v34_diverge_halt_is_loud` (в наборах 23/13) + живое срабатывание 222 раза | **VERIFIED** (аларм доказан жизнью) |
| W-3 | W10-FAUCET: `resolve_faucet_recipient` (роут до резерва) | `src/rpc.rs:2411 resolve_faucet_recipient` | `faucet_*` lib **13 passed** | **VERIFIED** |
| W-4 | P1-F1: `reject_trailing_bytes` | `src/consensus_net.rs:438 reject_trailing_bytes` + `:2081` | `pentest_decode_rejects_trailing_bytes` + lib `pentest_` **4 passed** | **VERIFIED** |
| W-5 | P2-SHARD-GATE: pool-level `admission_shard` в `insert` | `src/mempool.rs:1508 admission_shard` + `src/main.rs:401,2549,6817` стартовый пин | `p2_mempool_pentest` **16 passed** + `vp2_verify` **16 passed** | **VERIFIED** |
| W-6 | P3-R1: precommit-гейт `observe_peer_vote` | `src/runtime.rs` `observe_peer_vote` (область 4585–5044; было :4710) | `v34_r1a–r1d` + `chase_livelock_tests` **13 passed** | **VERIFIED** (строка уплыла, паттерн цел) |
| W-7 | P3-R2: verify-grade attribution + fail-closed slash-гейт | `src/state_engine.rs:6047-6086 apply_downtime_slash` (было :6010) | `v34_r2a–r2e` (`v34_verification_pentest` **13 passed**) | **VERIFIED** (строка уплыла, паттерн цел) |
| W-8 | P4-F-DBG: ручные redact-`Debug` (без секретов) | `src/mev.rs:63`, `src/mev_epoch.rs:442` redact impls | `p4_secret_material_never_appears_in_debug_output` (`p4_crypto_pentest` **24 passed**) + `v34_fdbg` | **VERIFIED** |
| W-9 | P5-F1: contract-arms за auth-гейтом | `src/rpc.rs:5401` P5 FIX комментарий | `p5_contract_arms_require_auth_token_when_configured` (lib `p5_` **8 passed**) | **VERIFIED** |
| W-10 | P5-F2: `from == signer` на `callContract` | `src/rpc.rs:5547,5731` + тест `:8839` | `p5_call_contract_from_must_equal_signer` + `p5_wrapped_deploy_rejects_forged_signature` (lib `p5_` 8 passed) | **VERIFIED** |

### C.3. Вердикт сертификации: **REFUSE — «STABLE TESTNET» НЕ ПРИСВОЕН**

Явно проверяю гейт C.0:

1. 4/4 non-fragile — **PASS** (обе ноды `fragile: false`; расхождение мощности D ~4e6 — наблюдение, не провал).
2. 30+ мин непрерывной финализации — **FAIL**: мастерчейн стоит на #305831 с ~18:15 (DIVERGENCE на #305832 блокирует высоту); живой сэмпл 75 с — 0 блоков мастерчейна; воркчейн идёт, но с деградацией (~12→34 с/блок).
3. Идентичные корни в сэмплах — **FAIL**: три разных post-state на высоте #305831/#305832 (`01b036…` vs `9c33…` vs `b922…`); идентичны только воркчейн-корни и чекпоинт (шард 1), чего для STABLE недостаточно.
4. Измеренный block time — **ЧАСТИЧНО**: история ~2 с/блок (мастерчейн) и ~12 с/блок (воркчейн), но живой темп — HALTED/деградация, измерение подтверждает остановку, а не стабильность.
5. Ноль DIVERGENCE — **FAIL**: 222 за 35 мин, 40 за 10 мин, свежие в 18:47 UTC; событие активно и не разрешено (канон не выбран, ресинк не проведён).
6. Explorer + indexer tracking — **ЧАСТИЧНО**: explorer-билд свеж (18:42) и preview отвечает; живой процесс индексер/синкер **не предъявлен**, БД не найдена — tracking живой цепи индексером не доказан.

**Итог: 1/6 PASS, 1 частично (не в зачёт), 4 FAIL → REFUSE.** DIVERGENCE-аларм W10.1 сработал образцово (громко, со счётчиком, с инструкцией «resync the minority side»), за что код хвалю; но stable-статус требует не умения орать, а отсутствия расхождения плюс 30+ мин роста обоих шардов с идентичными корнями. Блокеры: **A18** (канон #305832 + ресинк + разбор корня исполнения — code+ops), **A17** (A-rebond + D-stake — ops), плюс из старых: A1 (внешний аудит), A2 (живой split), A3 (живая 2PC-финализация), живая DKG-церемония (остаток A4), A6 (grindable), A7 (BLS/PoP), A14 (chain-binding rollout), A15 (proposal-equivocation evidence), A16-остаток (SECURITY.md плейсхолдеры, SDK, confirmations, multisig-решение, runbook, rollback, hardware floor).

### C.4. Открытый список (что должно случиться до STABLE)

1. Выбрать канон #305832 офлайн-реплеем (как делалось для #288000: `stelops diverge` + `pq_fork288000_replay`-методика) и зафиксировать его пином.
2. Ресинкнуть меньшинство с канонического снапшота; убедиться, что `stell_getShards` на всех нодах даёт одинаковые `tip_hash`/`state_root` мастерчейна.
3. Найти корень расхождения исполнения (тот же класс, что неатомарный commit: какой путь мутирует стейт до отказа/пина) и закрыть кодом с регрессионным пином — иначе DIVERGENCE вернётся на следующей высоте.
4. Показать 30+ мин непрерывного роста **обоих** шардов с идентичными корнями в сэмплах, нулевым `increase(stell_divergence_total[5m])` и измеренным block time.
5. Предъявить живой индексер/синкер, отслеживающий tip (процесс + запрос к API), и explorer, показывающий те же высоты/хэши, что RPC.
6. Закрыть A17 (A-rebond + D-stake) и заменить плейсхолдеры SECURITY.md — иначе следующий аудит снова откажет по формальным основаниям.

*Агент: S7-retry3 (только docs + read-only RPC; без транзакций и рестартов). Проверено: `cargo test --lib` 936 passed; `cargo build --all-targets` 0 ошибок; W10-наборы и V-наборы — все зелёные (числа выше); PART I sha256 до/после — `f96b0df23d6ddb93a641b57b4ef9798f47538940f7eeb0e80f0ca1c4b3120bb2` (байт-идентична).*

---

## STAB + DEPLOY WAVE (GUARD, 2026-10-28, только тесты + docs + read-only RPC)

### S.1. Батарея (все числа — фактический вывод, дерево `stellereum/`, UTC 2026-10-28 ~18:05–18:45)

| Команда | Итог |
| :--- | :--- |
| `cargo test --lib` (до фиксов) | 1020 passed, **1 failed** (`storage::archive_proof_tests::archive_proof_served_from_snapshot_verifies_after_restart` — sled lock `WouldBlock` под полной параллелью; соло зелёный → flake, test-wrong) |
| `cargo test --tests --no-fail-fast` run #1 | 216 сьютов: 2883 passed, **1 failed** (`tests/audit_repro_tests.rs::repro_4` — см. вердикт ниже) |
| `cargo test --lib` (финал, текущее дерево) | **1025 passed, 0 failed** (20.28 с; +4 новых теста параллельного commitment-cache рефактора) |
| `cargo test --tests --no-fail-fast` run #2 | 216 сьютов: **2884 passed, 0 failed** (нулевой failing подтверждён; оговорка: `src/commitment.rs` правился параллельно прогону — см. S.4) |
| `cargo test --test audit_repro_tests` (после фикса) | **4 passed, 0 failed**, 5/5 прогонов подряд |
| `cargo test --lib storage::archive_proof_tests` (после фикса) | **7 passed, 0 failed** |
| `cargo build --examples --benches` | **0 ошибок** (~60 с) |
| `cargo clippy --lib` / `cargo clippy --test audit_repro_tests` | exit 0 оба; в файлах GUARD-правок (`src/storage.rs:3940–3999`, `tests/audit_repro_tests.rs`) — **0 новых предупреждений**; остальные предупреждения (doc-индентация, `needless_borrow`, сложные типы и т.п.) — предсуществующие, не мои, не чинены (scope) |
| `cargo check --lib` (финал) | exit 0, 15 предсуществующих предупреждений |

Проверенные пины run #1/run #2 (совпадают с отчётом 2026-10-25): `consensus_liveness_harness` 13+1 ignored; `consensus_liveness_repro` 15/15; `light_client_wiring_tests` 15/15; `sharding_topology_tests` 6/6; `audit_rpc_evm_closeout` 30/30; `hunt_consensus_round2` 9; `mev_epoch_seal_tests` 25; `xshard_2pc_tests` 11; `mempool_mev_audit_closure_tests` 10; `p2_mempool_pentest` 16; `p3_byzantine_pentest` 23; `p4_crypto_pentest` 24; `vp2_verify` 16; `v34_verification_pentest` 13; `chase_livelock_tests` 13; `pq_fork288000_replay` 5; `hunt_round_dos` 8; `transport_audit_fixes` 4.

### S.2. Вердикты по failures (test-wrong → чинено тестом; code-wrong → FILED, код не тронут)

1. **FIXED-by-test-update (test-wrong, policy: flaky timing).** `storage::archive_proof_tests::archive_proof_served_from_snapshot_verifies_after_restart` (`src/storage.rs:3939`): после `drop(fixture)` немедленный `Storage::open` падает с `WouldBlock` под полной параллелью (sled lock-файл не отпущен), соло — зелёный. Исправление только в тесте: retry reopen 20×100 мс с backoff + policy-комментарий (`src/storage.rs:3945–3957`). Протокол не тронут.
2. **FIXED-by-test-update (test-wrong, policy: test-isolation глобального состояния).** `tests/audit_repro_tests.rs::repro_4` (`tests/audit_repro_tests.rs:222`): `LightClient::new` отвергал валидный Ed25519 QC с «certificate signatures did not verify», т.к. параллельно выполнявшийся `repro_3` выставлял process-wide `PURE_PQ_OVERRIDE=Some(true)` (для интеграционных бинарей `cfg(test)` thread-local зеркало из `src/post_quantum.rs:39-41` не действует — тот же класс гонки, что задокументирован в `src/post_quantum.rs:27-37` для lib-тестов). Исправление только в тестах: статический `Mutex` сериализует 4 теста файла (`tests/audit_repro_tests.rs:18-24` + гарды в каждом тесте). Протокол не тронут. Перепроверено 5/5 зелёных.
3. **FILED (code-wrong, НЕ чинено — вне GUARD scope: protocol logic).** Параллельный commitment domain-cache рефактор дважды ломал сборку дерева во время батареи: (a) `E0063: missing fields domain_cache/domain_gens in InMemoryStateEngine` (`src/state_engine.rs:1294`, самопочинено автором правки); (b) `lifetime may not live long enough` в `dom_guard` (`src/state_engine.rs:6936-6946`): возвращаемый `RwLockWriteGuard<'_, T>` привязан элайдингом к `&self`, а гард реально заимствован из параметра `lock: &RwLock<T>` — требуется явное `<'a>` на оба заимствования; repro: `cargo check --lib` на дереве между правками. Файл: `src/state_engine.rs:6936`, затронут `commit_consensus_domains`/`dom_guard` + `src/commitment.rs` (новый `PreimageSink`, `DomainGenerations`). Автору рефактора: дописать лайфтайм и прогнать `cargo test --tests --no-fail-fast` заново.

### S.3. Что STAB починил / что замерил deploy

* STAB: в conversation GUARD никаких чисел/отчётов STAB-агента **нет** — зафиксировать нечего. Стабилизация этой волны = два GUARD тест-фикса выше (S.2.1, S.2.2) с `file:line`.
* Deploy: отчётных чисел DEPLOY-агента в conversation **нет** → **deploy pending/running** (не выдумано, не измерено GUARD).

### S.4. Живая сеть 2026-10-28 (только read-only RPC, без транзакций/рестартов)

* `eth_blockNumber` на `127.0.0.1:8546` (18:16:35Z): `0x5e9be` (387518); на `127.0.0.1:18545` (туннель nodeA, 18:22Z): `0x4f047` (323399). **Узлы расходятся на ~64k блоков** — сеть НЕ в консенсусе (подтверждает REFUSE C.3, новый факт к A18).
* Валидатор-сет (`stell_getValidators`, 8546): 4 валидатора, `fragile: false`, `quorum 4367902113748`, `total_power 6551853170621`; мощности: `021776cd…` 1461483622338, `9c675ebc…` 1901460050785, `c2313fba…` (D) 1220670613863, `eddf8163…` 1968238883635.
* Tip (`stell_getShards`, 8546): masterchain `tip_height 387518`, hash `a0c8a8ef…`, state_root `94d595df…`, `local: true`; workchain `tip_height 0`, `local: false` — воркчейн локально не обслуживается (зафиксировано как наблюдение, не диагноз).
* Block-time sample (метод: дельта tip по wall-clock через read-only `eth_blockNumber`): 387518 (18:16:35Z) → 387616 (18:21:49Z) = 98 блоков за 314 с → **mean ~3.2 с/блок** на мастерчейне nodeB. Один сэмпл, как заказано.
* `127.0.0.1:8545` на момент проверки не отвечал.

### S.5. Сводка правок отчёта GUARD 2026-10-28 (секции + дельты скоринга)

* Тронуто: шапка-ревизия (+4 строки о правке GUARD); ЧАСТЬ 0.1 — 3 строки причин (Консенсус, Тесты, Production-readiness); ЧАСТЬ V — V.1 (3 строки сборки), V.2 (lib-строка + новая строка `audit_repro_tests`), «красное состояние» (переписано), V.9 (+строка полных `--tests`, lib 936→1025); ЧАСТЬ 0-вердикт и ЧАСТЬ VI (936→1025 в двух местах); добавлена эта секция S.1–S.5.
* **Дельты скоринга: нет (все ★-оценки без изменений).** Причины: тест-фиксы — test-only (на скор кода не тянут); живая сеть по-прежнему без канона (на повышение production нет оснований, на понижение — новых классов дефектов не измерено).
* ЧАСТЬ I: байт-идентична, sha256 до/после — `f96b0df23d6ddb93a641b57b4ef9798f47538940f7eeb0e80f0ca1c4b3120bb2`.

*Агент: GUARD (только тесты + docs; read-only live RPC; без транзакций, рестартов, коммитов, правок протокола).*

---

## REP2 SYNC (Agent REP2, 2026-10-28, docs + read-only verification; no protocol logic, no txs/restarts/commits)

### R.1. Батарея (все числа — собственные прогоны REP2, дерево `stellereum/`, UTC 2026-10-28 ~21:00–22:30)

| Команда | Итог |
| :--- | :--- |
| `cargo test --lib` | **1034 passed, 0 failed** (20.31 с; было 1025 GUARD) |
| `cargo test --test mmr_epoch_root_tests` | **3 passed, 0 failed** |
| `cargo test --test paymaster_tests` | **21 passed, 0 failed** |
| `cargo test --test shielded_path_tests` | **4 passed, 0 failed** |
| `cargo test --test one_call_order_placement_tests` | **7 passed, 0 failed** |
| `cd stellereum-sdk && cargo test` | **12 passed, 0 failed** (`tests/canonical.rs`, byte-equality) |
| `cargo test --test block_tempo_lan -- --nocapture` | **2 passed** (см. R.3) |
| `cargo test --lib perf -- --nocapture` | 4 perf-пробы (см. R.2) |
| `cd explorer-site && npm run build` | **exit 0** (`index.html` 1.06 kB, `index-*.js` 70.42 kB, `vendor-*.js` 179.53 kB) |
| `journalctl --user -u stell-nodeB --since '3 hours ago' \| grep -c DIVERGENCE` | **0** |

### R.2. STAB + TAIL-1 (VERIFIED в коде; числа — этот бокс, debug-профиль)

* **STAB validation-tax (VERIFIED, механизма; именованного perf-харнесса нет — UNVERIFIED как «harness numbers»):** verify-once кэши `src/runtime.rs:778-800` (`order_root_cache`, `batch_verify_cache`, `proposer_sig_cache`, `qc_power_cache`), ключи `:4212`/`:4229`, slow-validation метр + тест `c2_slow_validation_meter_and_log_name_slow_stage` (`:7817`), allowlist-пин `stell_slow_validation_total` (`tests/audit_rpc_evm_closeout.rs:649`, `tests/metrics_tests.rs:56`). Отдельного STAB validation-tax perf-теста в дереве нет — заявленные чужой волной harness-числа здесь не воспроизводятся, помечены UNVERIFIED.
* **STAB MMR cache (VERIFIED):** `ChainManager::mmr_cache` (`src/chain.rs:215-231`), `epoch_mmr_root` (`:526`), инвалидация при re-anchor (`:879-890`), юнит-пин `epoch_mmr_root_covers_a_fully_finalized_epoch` (`src/chain.rs:1374`).
* **TAIL-1 commitment (VERIFIED):** per-domain generation кэш (`src/commitment.rs:2213`, `DomainCache`/`DomainGenerations`/`AbiJsonCache`, поля `src/state_engine.rs:376-395`). Дифференциальные пины (все зелёные): `cached_assembly_matches_streaming_on_populated_snapshot`, `randomized_mutations_cached_equals_streaming` (200 шагов), `abi_json_cache_is_byte_identical`, perf-проба `perf_digest_cached_vs_streaming`. Замер REP2 (debug, этот бокс): populated 1500/300/200 — streaming 26–30 мс, hot-cached 1.7–2.4 мс, **speedup 11–17×**. Заявленные 2–3.6× чужой волны на этом боксе не воспроизводятся (вероятно, release-профиль) — помечены UNVERIFIED как число, механизм VERIFIED.
* **TAIL-1 receipt (VERIFIED):** батчированные receipt-хэши (`src/rpc.rs:12832`), дифференциальный пин `record_receipts_batched_is_byte_identical_to_reference` (256 tx + pre-existing merge-ветвь), perf-проба `perf_record_receipts_batched_vs_reference`. Замер REP2 (debug, 20k tx best-of-5): reference 412.58 мс, batched 349.45 мс, **speedup 1.18×** (заявленные 1.75× — UNVERIFIED как число). Попутно: tx-hashing batched 1.35×, engine-commit 6.8× (те же perf-пробы).

### R.3. VEL 0.5s-харнесс (VERIFIED собственным прогоном)

* `cargo test --test block_tempo_lan` 2/2: **LAN** 100 высот — `virtual_total=36850ms virtual_mean=350.0ms p50=350 p99=350 max=350`, `total_extra_rounds=0` (заявленные «400→350 мс»: конечные 350 мс совпали, начальные 400 мс в этом дереве не зафиксированы — UNVERIFIED как «до»); **WAN-контраст** 20 высот — `virtual_mean=690ms p50=700 p99=750 extra_rounds=0` (заявленные «738→688 мс»: измерено 690 мс — совпадение в пределах шума, принято как VERIFIED-approx). «Slow-WAN waste killed»: отдельного slow-WAN теста в дереве нет — механизм (verify-once кэши снимают повторный крипто-налог на ретраях, `src/runtime.rs:778-800`) VERIFIED, ярлык UNVERIFIED.

### R.4. HEAL-A rejoin (частично VERIFIED)

* Плейбук в дереве VERIFIED: `scripts/stell-sync.sh auto-heal` (HTTP-snapshot ресинк лаггарда, `:174`/`:190`), `lockclear` (`:974-1122`, план read-only + `--force` со стоп/проверкой/стартом), доки `stellereum/docs/OPERATIONS.md` §15 (таблица кейсов, lockclear-план `:2208`), `VALIDATOR_ONBOARDING.md:261`, `cluster-watchdog.sh` (stall → lockclear-подсказка).
* Событие «A 64k-behind → tip»: живьём 2026-10-28 оба узла уже сошлись (см. R.6) — сам момент rejoin мною не наблюдён; заявка чужой волны помечена UNVERIFIED как событие, плейбук VERIFIED как код. Gap-0 snapshot: `sync [node] from HTTP snapshot` + `auto-heal` — VERIFIED как путь, «gap-0» как ярлык чужой волны — UNVERIFIED дословно.

### R.5. Остальные поверхности (все VERIFIED в коде + прогоном)

* **MMR epoch roots в блоках + `stell_getEpochRoot`:** `Block::mmr_epoch_root` (`src/sharding.rs:4954-5001`), proposer-коммит границы (`src/runtime.rs:1263-1295`, проверка `:1295-1310`), `commits_epoch_root` (`src/mmr.rs:91`), RPC `stell_getEpochRoot` (`src/rpc.rs:4373-4442`), клиентские `verify_epoch_root_answer`/`verify_mmr_inclusion` (`src/light_client.rs:706-862`), тесты `tests/mmr_epoch_root_tests.rs` 3/3 (R.1).
* **SDK-крейт + byte-equality:** `stellereum-sdk/` (`Cargo.toml`, `src/lib.rs` 627 строк, `predict_contract_address` = функция ноды), `tests/canonical.rs` 12/12 (R.1). Закрывает B2.
* **B9 Logs-страница + build:** `/events` (`explorer-site/explorer/src/pages/Events.tsx`, маршрут `src/App.tsx:36`, ABI-статус из `stell_getContractAbi`), `npm run build` exit 0 (R.1). Закрывает B9.
* **V5 S1–S29 spec fixes: UNVERIFIED.** Поиски `S1…S29` по обоим спекам (`docs/handoff/*`, `stellereum/docs/handoff/*`), коду и тестам — пусто; в этом дереве фиксировать нечего, не выдумано.
* **Paymaster (одна строка):** спонсорские конверты `Transaction::sign_with_sponsor` (`src/sharding.rs:3880`), баланс спонсора `sponsor_balance_of` (`src/state_engine.rs:1747`), admission-гейты `AdmissionCtx::with_sponsor_balance` (`src/mempool.rs:300`), fee платит спонсор, nonce движется у юзера — `tests/paymaster_tests.rs` 21/21 (R.1).
* **Privacy-path (одна строка):** `stell_shieldedTransfer` / `stell_shieldedBalance` / `stell_unshield` (`src/native_api.rs:380-394`, PREPARE/READ-разделение `:2523`) — `tests/shielded_path_tests.rs` 4/4 (R.1).
* **Token-burn-admin (одна строка):** `stell_tokenBurn` (`src/native_api.rs:162`, impl `:956`) — self-burn держателя + minter admin-burn через `signer`, исполнение `TokenOp::Burn` ревертит чужого caller (`:992`).
* **Order/bridge (одна строка):** `stell_placeOrder` / `stell_cancelOrder` + one-call (`src/native_api.rs:316-323`, impl `:2216`/`:2233`, `tests/one_call_order_placement_tests.rs` 7/7); `stell_bridgeDepositPrepare` (write) vs `stell_bridgeDeposit` (read) / `stell_bridgeWithdraw` / `stell_bridgeStatus` (`src/native_api.rs:240-289`, W7.2-разделение + truth-gate `src/bridge.rs:738`).

### R.6. Живая выборка 2026-10-28 (только read-only RPC; explorer tip — not sampled)

* tip: `eth_blockNumber` 8546+18545 оба `0x5f60c` (391628) на 21:18:31Z → 8546 `0x5f648` (391688) на 21:21:47Z = **60 блоков/196 с, mean ~3.3 с/блок**; `stell_getShards` оба узла: мастерчейн tip **390668**, `tip_hash 38ba17f5…`, `state_root 8cd8d83d…` (идентичны), воркчейн tip 164036 `local:false`. Наблюдение: `eth_blockNumber` опережает shards-tip на ~960 — зафиксировано, не диагностировано.
* 4/4 сет: `stell_getValidators` (8546): 4 валидатора, **`fragile: false`**, `quorum 4350805877654`, `total_power 6526208816480` (мощности 1460022138716 / 1901460050785 / 1196487743344 / 1968238883635).
* Один 3-мин block-time mean: ~3.3 с/блок (выше).
* Explorer tip: **not sampled** (vite preview на 5173 не отвечает; отдельный процесс индексер/синкер не проверялся).
* DIVERGENCE: 0 за 3 ч (R.1). Итог: конвергенция наблюдена, канон-процедура — нет (см. A18).

### R.7. Закрытие двух тонких ветвей (текст-only, zero-risk)

* (a) **P1-G2..G4 ACCEPTED: подтверждено grep'ом, правок не потребовалось.** Заметка существует в `src/consensus_net.rs:3080-3095` (`P1-G2..G4 — ACCEPTED …`), пин-тест `report_p1_g2_g4_filed_without_content_is_closed_as_accepted` (`:2516-…`); кросс-ссылки: тест ссылается на заметку, заметка — на тест. Grep-доказательства: `P1-G2..G4` → `src/consensus_net.rs` (note + test); `report_p1_g2_g4_` → тот же файл. Логика не тронута (комментарий + тест-реассёрт bookend'ов G1/G5).
* (b) **Shares-design alignment: подтверждено наполовину, недостающая половина добавлена docs-текстом.** `stellereum/docs/MEV.md` §5.6 существует (pool-messages vs vote-embedded, WHY/EQUIVALENCE/GAPS). V5-спек §4 (item 4 «Precommit Piggyback») содержал только TODO-статус без алайнмента — **добавлен абзац «СТАТУС-АЛАЙНМЕНТ (REP2, 2026-10-28, docs-only)»** в `docs/handoff/STELLEREUM_PQ_BFT_V5_MASTER_SPEC.txt:141`, консистентный с pool-message реализацией (`MevFrame::Release`, `release_partial`/`ingest_release`, vote-preimage аргумент). Логика не тронута (только docs).

### R.8. Сводка правок REP2 (секции + дельты)

* Тронуто: шапка-ревизия (+REP2-абзац); ЧАСТЬ 0.1 — 4 строки причин (Консенсус, Хранилище, Тесты, Production-readiness) + вердикт (2 строки); ЧАСТЬ 0.2 — 2 новые строки W11; ЧАСТЬ 0.3 — 7 строк (Deploy/ABI/События/Light/MEV/Приватность/Тесты); ЧАСТЬ IV — B2/B9 закрыты, B8-хвост обновлён, A18 переписан, C19/C20 добавлены; ЧАСТЬ V — V.2 lib-строка (1034), V.4 build-числа, V.9 заголовок + lib + W11-строка; ЧАСТЬ VI (W11-абзац, вердикт); добавлена секция R.1–R.8; `docs/handoff/STELLEREUM_PQ_BFT_V5_MASTER_SPEC.txt` §4 (+алайнмент-абзац).
* **Дельты скоринга: одна (Хранилище 8.5→★★★★★ 9/10, основание — одна строка: MMR epoch roots в блоках + `stell_getEpochRoot` 3/3 собственным прогоном).** Всё остальное — без дельт (только причины с измеренными числами).
* ЧАСТЬ I: байт-идентична, sha256 до/после — `f96b0df23d6ddb93a641b57b4ef9798f47538940f7eeb0e80f0ca1c4b3120bb2`.

*Агент: REP2 (только docs + read-only verification; без транзакций, рестартов, коммитов, правок протокола и PART I).*
