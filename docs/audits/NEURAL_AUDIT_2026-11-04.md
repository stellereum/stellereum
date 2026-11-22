# Внешний нейро-аудит Stellereum — 2026-11-04 (третья сторона)

- **Репозиторий:** https://github.com/stellereum/stellereum
- **Коммит аудита:** `e58323db31e737776659601d9c1ad1f47600f695` (2026-11-04)
- **Объём на момент аудита:** ~178 000 строк `src/`, ~154 000 строк `tests/`, 67 модулей
- **Характер:** статический разбор + сборка + прогон lib-тестов. Без динамического фаззинга,
  внешнего криптоаудита и пентеста живой сети.
- **Сборка:** `cargo check --lib` — успешно (1 warning).
- **Тесты:** `cargo test --lib` — **1088 passed, 0 failed** (21.62 s).
- **Статус в нашем трекинге:** принят как вход для P0–P3 программы (см. §9 оригинала).
  Триаж по текущему дереву — в `NEURAL_AUDIT_TRIAGE.md`.

## 1. Итоговая оценка аудитора

| Severity | Кол-во |
|---|---|
| Critical | 2 |
| High | 4 |
| Medium | 6 |
| Low / Info | 7 |

**Вывод аудитора.** Инженерно сильный проект с честной документацией и культурой
fail-closed. Но в текущем виде — закрытый однонодовый/testnet-прототип, а не сеть
к публичному мейннету: критичное находится не в криптографии, а в **границе
RPC ↔ консенсус** и в **незамкнутой governance-петле**. До публичного RPC/мейннета
закрыть в первую очередь.

## 2. Critical

### C-01. Governance/staking меняются через RPC вне блока → расхождение state root и остановка сети

**Файлы:** `src/rpc.rs:5686-5819`, `src/governance.rs:832-908`, `:926-990`,
`src/commitment.rs:500`, `:583`, `:1622`, `:941-950`, `src/main.rs:4215-4217`.

**Суть.** RPC-методы governance пишут напрямую в общий объект, входящий в
commitment/state root, но не через блок (нет gossip и opcode для
proposal/vote/execute). Любой вызов меняет локальный root узла → peers, применив
тот же блок, получат другой root → reject/fork/desync. Происходит даже при
корректном токене.

**Рекомендация аудитора.** Governance в block-carried операцию либо запрет
governance-write RPC на валидаторах/multi-node.

### C-02. Governance RPC без аутентификации личности + вечный lock стейка

**Файлы:** `src/rpc.rs:5728-5759`, `src/governance.rs:895`, `:988`, `:1009`,
`src/runtime.rs:2609` (`Runtime::gov_finalize` нигде не используется).

**Суть.** `proposer`/`voter` из параметров без подписи → голосование чужим стейком,
блокировка всего стейка жертвы через proposal от её имени. `finalize` на живом
пути не вызывается → lock перманентный (нельзя unbond). `executeProposal` для
обычного proposal не сработает, но griefing и C-01 остаются.

**Условие:** RPC доступен снаружи (bind loopback по умолчанию, но есть
`docs/integrations/nginx-rpc.conf` + опциональный токен).

**Рекомендация.** Подпись над `(chain_id, proposal_id, choice)`; кап lock;
подключить `finalize`; fail-closed без токена.

## 3. High

### H-01. RPC-write «fail-open» без `STELL_RPC_AUTH_TOKEN`

**Файлы:** `src/rpc.rs:163-170`, `:5687`, `:5740`, `:5797`, `:6470`, `:6740`,
`:3907`; `src/main.rs:8290-8305`.

**Суть.** Документация (KI-19) утверждает fail-closed без токена — неверно для
governance/contract/sign. Только `stell_mempoolDump` реально fail-closed.

**Рекомендация.** Write-методы fail-closed при `auth_token = None` (как faucet),
либо явный `STELL_ALLOW_OPEN_WRITES=1` для dev. Обновить KI-19 и предупреждение
при старте.

### H-02. `stell_signMessage` подписывает ключом валидатора

**Файлы:** `src/main.rs:552`, `:8085`; `src/rpc.rs:3967-4010`, `:4074+`.

**Суть.** Signing-oracle ключом валидатора; домены разные (прямая подделка не
проходит), но сам факт — грубая ошибка эксплуатации. При отсутствии токена —
анонимно.

**Рекомендация.** Никогда не использовать validator key для `signMessage`; dev-режим —
отдельный ключ, только с токеном, только на loopback, с явным флагом. В production — выключено.

### H-03. `stell_callContract` двойное исполнение и двойное списание

**Файлы:** `src/rpc.rs:6879-6942`; `src/state_engine.rs:1300-1320`.

**Суть.** Direct-путь двигает value и исполняет контракт немедленно, затем та же
операция идёт в mempool и при включении двигает/исполняет второй раз. Плюс
мутация state вне блока (см. C-01).

**Рекомендация.** Убрать прямую мутацию: выполнять вызов только «на клоне» для
возврата результата, состояние менять исключительно при применении tx. Либо
удалить direct-параметры и оставить только `tx`-путь.

### H-04. `stell_deployContract` принимает `private_key` и деплоит вне блока

**Файлы:** `src/rpc.rs:6611-6622`, `:6665-6704`, `:6470`.

**Суть.** Приватный ключ по RPC (утечки) + деплой в state до/вне блока (C-01).

**Рекомендация.** Убрать `private_key` из RPC. Оставить только подписанную raw-tx
форму (`tx`), проверять подпись и не мутировать state вне применения блока.

## 4. Medium

### M-01. `STELL_PURE_PQ` opt-in, off by default

**Файлы:** `src/post_quantum.rs:71-89`; testnet/docker-конфиги; README.

Без флага узел принимает классику. README врёт без оговорки. Перф-цифры — для
plain Ed25519, не Falcon.

**Рекомендация.** Включить PQ в дефолтном профиле testnet/mainnet-конфигов, либо
явно писать «PQ opt-in» и не публиковать перф как PQ-перф.

### M-02. EVM chain id 5757 vs `eth_chainId` = `STELL_CHAIN_ID`

**Файлы:** `src/evm_adapter.rs:51`, `:539`, `:577`, `:6680` vs `:57`, `:224`.

На кастомном chain id кошельки подписывают один id, проверка ждёт 5757 → все
EVM-tx отвергаются.

**Рекомендация.** Единый источник chain id (`effective_chain_id`) во всех
EVM-проверках; либо задокументировать EVM только на chain id 5757.

### M-03. `restore_pq_keys` без проверки; нестандартная salt ломает healing

**Файлы:** `src/state_engine.rs:8139-8185`, `:3253-3262`, `:4864-4875`, `:1654-1745`.

Blob от sync-пира ставится verbatim (не root-bound). Healing с `DEFAULT_SALT`
не восстанавливает аккаунты с другой salt → implicit-PQ tx отвергаются.

**Рекомендация.** При restore проверять `blake3(pk)` и `derive()` против адреса;
salt хранить/использовать при healing; тест на non-default salt + рестарт.

### M-04. BoC `with_capacity` до проверки длины (KI-35)

**Файлы:** `src/cell.rs:165`, `:176`. 12-байтный blob → запрос сотен GiB.

**Рекомендация.** Проверять длину против остатка буфера до `with_capacity`,
либо использовать `try_reserve`.

### M-05. Нет root `Cargo.lock`; `infnode` из git-ветки main

Невоспроизводимая сборка бинарника; upstream меняется без изменения репо.

**Рекомендация.** Коммитить `Cargo.lock`, запинить `infnode` на конкретный `rev`,
включить `cargo audit`/Dependabot в CI.

### M-06. PQ-госсип: compact/PQ не вшиты; µQC на N=100 ≈ 42.6 КБ

Design-only механизмы; 1k-TPS рецепт для Ed25519. Маркетинг делить на
measured/projected.

**Рекомендация.** В маркетинге и README разделить «measured: classical, N=4, LAN»
и «projected: PQ/compact». Подключить compact propagation и измерить PQ-путь
end-to-end, прежде чем заявлять TPS.

## 5. Low / Info (полный текст)

### L-01. Возможный DoS через length-prefix при `bincode::deserialize` на недоверенных байтах

**Файлы:** `src/network.rs:1781` (`parse_cross_shard_incoming`), `:2699`
(`decode_cross_shard_payload` — есть cap 4 MiB), `src/rpc.rs` (decode `tx` из hex),
`src/consensus_net.rs:449` (там есть `with_limit`).

**Суть.** Входной размер ограничен (1 MiB RPC / 4 MiB cross-shard / 32 MiB
consensus), но `bincode` 1.3 для строк/некоторых типов читает длину из префикса;
без явного `with_limit`/проверки остатка это потенциальная амплификация памяти.
Нужен PoC; в `consensus_net` защита уже есть, в остальных местах — не везде.

**Рекомендация.** Единый helper для декодирования недоверенных байтов:
`DefaultOptions::new().with_limit(n).reject_trailing_bytes()` + fuzz
с патологическими length-prefix.

### L-02. Игнорируются коды возврата Falcon FFI

**Файл:** `src/post_quantum.rs:1140-1176` (`keygen`), `:1215-1252` (`sign_dyn`)

**Суть.** C-функции в reference Falcon возвращают `int` (0 = успех). Здесь
объявлены как `()`, результат не проверяется. При ошибке keygen/sign можно
принять невалидный ключ/подпись. Вероятность низкая (внутри циклы), но проверка
обязательна для FIPS-подобного кода.

**Рекомендация.** Объявить `-> i32`, проверять `== 0`, fail-closed.

### L-03. `Cell::new` паникует (`assert!`) на превышении лимитов

**Файл:** `src/cell.rs:26-35`

**Суть.** Для публичного API библиотеки лучше `Result`. `from_boc_bytes`
собирает `Cell` напрямую и не паникует, но любой будущий вызов `Cell::new` на
недоверенных данных — abort.

**Рекомендация.** `try_new`/`Result`, либо `debug_assert!` + проверка на границе.

### L-04. Warning `fetch_update` (deprecated) противоречит заявлению «clippy -D warnings clean»

**Файл:** `src/storage.rs:2979`; вывод `cargo check` — 1 warning.

**Суть.** README: «Lints are law». На текущем rustc 1.99 есть deprecated-метод.
CI на более новом toolchain может покраснеть.

**Рекомендация.** `try_update` или pin toolchain.

### L-05. Расхождение документации и кода по RPC-поверхности

**Файлы:** `docs/RPC.md:22`, `docs/integrations/nginx-rpc.conf`,
`docs/audits/KNOWN_ISSUES.md` KI-19.

**Суть.** Заявления о токен-гейтах и методах неточны (sendRawTransaction открыт
by design; contract-методы существуют; gated arms не все fail-closed). Влияет на
решения операторов о публикации RPC.

**Рекомендация.** Привести доки к фактическому поведению.

### L-06. `derive_key` возвращает ключ по значению; временный массив не зануляется

**Файл:** `src/node_keys.rs:100-111`

**Суть.** `Zeroizing` оборачивается уже после возврата из `derive_key`; копия
`[u8;32]` в стеке функции остаётся. Мелочь, но для key material стоит занулять.

**Рекомендация.** Занулять внутри `derive_key` до возврата.

### L-07. `Cell`/`BagOfCells` не проверяет `refs_len <= 4` и `data_len <= 128` при парсинге

**Файл:** `src/cell.rs:176-220`

**Суть.** `from_boc_bytes` принимает произвольные `refs_len`/`data_len`, хотя
`Cell::new` такие значения запрещает. Ограничено размером blob'а, но лучше
валидировать.

**Рекомендация.** Проверять `refs_len <= 4` и `data_len <= 128` при парсинге.

## 6. Что проверено и признано хорошим (полный текст — важно против односторонности)

- **Подпись транзакций**: `signing_message` связывает from/to/amount/gas/nonce/shards/payload/priority/delegation/chain/sponsor; домены разделены (`src/sharding.rs:3210-3275`, `:3689-3745`).
- **Хэш блока**: коммитит все tx-hash'и, order-root, cross-shard msg_id, shard-headers, epoch-key, last-QC (с сортировкой подписей), MMR-root (`src/sharding.rs:5639-5750`).
- **Кворум**: power-weighted, дедуп по подписанту, membership-first, batch + scalar fallback; пустой сет fail-closed (`src/consensus.rs:2968-3085`, `src/sharding.rs:5740+`).
- **Голоса**: домен + chain id + height/round/kind/block_hash; `verify_strict`; кэш verify-once fail-closed (`src/consensus.rs:1484-1660`).
- **Стекинг**: checked/saturating арифметика, self-first slash, unbonding-очередь, governance locks (`src/staking.rs:2104-2290`, `:1839-1935`).
- **Токены STS-20**: CEI, checked_add/sub, supply cap, pause, minter renounce (`src/token.rs`).
- **Range proofs**: Pedersen + bit-OR proofs + реконструкция; sound-путь `verify_balanced_with_ranges` (`src/crypto_privacy.rs:662-760`, `:1044-1095`).
- **Cross-shard apply**: `verify_inclusion_strict` (не доверяет `trusted` из блока), anchored проверки на propose/validate (`src/state_engine.rs:6288-6310`, `src/sharding.rs:4586-4640`).
- **Faucet**: fail-closed токен, Turnstile, per-IP/lifetime caps, запрет публичного test-key (`src/rpc.rs:477-520`, `src/explorer.rs:556-850`).
- **Ключи узла**: Argon2id 64 MiB/t=3/p=4 + XChaCha20-Poly1305, 0600/0700, symlink-запрет, plaintext только по явному opt-in (`src/node_keys.rs`).
- **Client IP**: XFF только от trusted proxy, rightmost-режим по умолчанию, loopback-only trust (`src/client_ip.rs`).
- **Mempool**: signature verify, fee floor, reservations, per-sender caps, nonce window, eviction premiums (`src/mempool.rs`).
- **SVM syscalls**: owner-only для unbond/rotate/withdraw/claim/cancel; value-переводы идут через engine (`src/svm.rs:1619-2400`).

## 7. Совпало с KNOWN_ISSUES (не переоткрываем)

KI-02, KI-05/06, KI-07, KI-11/12, KI-23 (уже закрыт таймлоком 7200h — см. триаж),
KI-26…29, KI-30, KI-31/33, KI-34, KI-35, KI-37 (уже закрыт — F10 allowlist),
KI-38.

## 8. Ограничения аудита (по словам аудитора)

- Прочитана существенная часть `src/` (consensus, sharding, state_engine, rpc, mempool, staking, governance, token, bridge, cell, cpat2, crypto_privacy, node_keys, post_quantum, client_ip, sync, light_client, evm_adapter, native_api, pmm/oracle частично), но **не все 178k строк построчно**.
- Не запускались: `cargo clippy --all-targets`, полный integration suite (`tests/` ~154k строк), `scripts/audit-repro.sh`, fuzz-корпус, нагрузочные сценарии, live-кластер.
- Не выполнялся внешний криптоаудит Falcon/Ed25519/BLS/range proofs и не проверялась корректность `pqcrypto-falcon` C-архива.
- Выводы по «эксплуатируемости» C-01/C-02/H-01/H-02 зависят от того, опубликован ли RPC и задан ли `STELL_RPC_AUTH_TOKEN`; по умолчанию bind loopback.
- Для L-01 (bincode length-prefix) нужен отдельный PoC/OOM-тест; здесь это гипотеза по коду, а не подтверждённый эксплойт.

## 9. Приоритетный план аудитора

1. **P0:** C-01, C-02, H-01 (токен + fail-closed; убрать мутации вне блока; подключить `finalize`).
2. **P0:** H-02 (убрать validator key из signMessage).
3. **P1:** H-03, H-04 (убрать direct-мутации и `private_key`).
4. **P1:** M-01 (PQ-by-default решение + доки/перф).
5. **P2:** M-02…M-06.
6. **P2:** M-06 (compact/PQ + измерение).
7. **P3:** L-01…L-07.

## 10. Быстрые команды для проверки (из аудита)

```bash
# сборка/тесты
cargo check --lib
cargo test --lib                 # 1088 passed на этом коммите
cargo clippy --all-targets -- -D warnings

# найти RPC-write без fail-closed
rg -n "if let Some\(expected\) = &st.auth_token" src/rpc.rs

# проверить, что finalize не подключён на живом пути
rg -n "gov_finalize|\.finalize\(" src/runtime.rs src/main.rs src/rpc.rs

# проверить pure-PQ дефолт
rg -n "STELL_PURE_PQ" src testnet docker docker-compose.yml README.md

# проверить lock/пин зависимостей
git ls-files | rg "Cargo.lock"
rg -n "infnode" Cargo.toml
```
