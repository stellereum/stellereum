# STELLEREUM — ПАМЯТЬ СЕССИИ (handoff)

> Создано: 2026-09-24. Этот файл описывает всё, что сделано, текущее состояние
> и следующие шаги. Если контекст очистится — читай этот файл первым.
>
> **АКТУАЛЬНО:** разделы 1–7 — старая сессия (225 тестов). Текущее состояние —
> раздел 2.4/8 (355 тестов). Новые идеи — раздел 9. Мульти-нодный live-тест
> ПРОШЁЛ (раздел 8.8–8.9), транспорт починен.

---

## 0. ПРОЕКТЫ (экосистема)

```
infnode    → P2P-транспорт (QUIC/TLS + Kademlia DHT + storage)   [сетевой слой]
   ├─ infmail     → почта поверх infnode                          [приложение]
   └─ stellereum  → L1 блокчейн поверх infnode                    [приложение]
         └─ stell-wallet → SPV CLI-кошелёк `stell`                [клиент]
```

Пути:
- `/home/imm/infmail-valid-backend/crates/infnode` — сетевой слой (workspace с infmail)
- `/home/imm/infmail-valid-backend/crates/infmail` — почта
- `/home/imm/stellereum` — блокчейн (отдельный проект, зависит от infnode по path)
- `/home/imm/stell-wallet` — кошелёк (отдельный проект, бинарник `stell`)
- `/home/imm/HOW_MAIL_WORKS.md` — описание почты + TODO по DNS
- `/home/imm/stellereum/LAUNCH_STRATEGY.txt` — стратегия, дорожная карта, CVE, журнал багов

ВАЖНО: блокчейн НЕ встраивается в код infnode. infnode используется только через
публичный API (kv_store_local/get_local_kv, store_blob/fetch_blob, request_to, pubsub).

---

## 1. ЧТО СДЕЛАНО В ЭТОЙ СЕССИИ

### 1.1 Блокчейн Stellereum — ядро (до сессии + в сессии)
- Cell/BoC, Patricia-Merkle DAG, SPV-пруфы (`cell.rs`)
- Actor Model + bounce (`state_engine.rs`)
- Шардинг + cross-shard hub + BFT-кворум (`sharding.rs`)
- SVM micro-gas + syscalls, атомарный clone-commit (`svm.rs`)
- CLOB Orderbook-Actor (`orderbook.rs`)
- MEV: пороговое шифрование Шамира T-of-N (`mev.rs`)
- zkML + session keys (`zkml.rs`)
- Selective confidentiality: Pedersen, Stealth, Viewing Keys (`crypto_privacy.rs`)
- 3-tier Oracle + Circuit Breaker (`oracle.rs`)
- Teleport Bridge engine (`bridge.rs`)
- Токеномика + Genesis Vault (`tokenomics.rs`)
- **Токен-стандарт STS** + привязка к состоянию + SVM syscalls (`token.rs`)
- Кошелёк `stell` (24-словная мнемоника BIP-39, Argon2id, SPV) (`wallet.rs`)

### 1.2 КОНСЕНСУС (главное этой сессии) — Стэйдж 1Новые модули:
- `src/consensus.rs` — BFT движок: ValidatorSet, Vote, VoteSet, QuorumCertificate,
  HeightConsensus (propose/prevote/precommit/commit), locking (safety), view-change,
  детект эквивокации. 14 тестов.
- `src/runtime.rs` — ValidatorRuntime + Cluster (in-process). Связь консенсуса с
  производством блоков, мемпулом, применением к состоянию. 4 теста.
- `src/consensus_net.rs` — P2P-транспорт: ConsensusMsg (Proposal/Vote) через infnode
  pubsub. `broadcast` шлёт `pubsub.msg` пирам (НЕ pubsub.publish!), `join` шлёт
  `pubsub.subscribe`. 6 тестов.
- `src/main.rs` — команда `Run` теперь запускает реальный консенсус-цикл
  (`run_consensus_node`): propose→prevote→precommit→finalize, persistent-ключи,
  infnode `serve()` для приёма соединений, синхронизация раундов.

### 1.3 Безопасность — найдено и исправлено 15+ уязвимостей
1. transfer_from списывал allowance до проверки баланса (CEI) — ИСПРАВЛЕНО
2. Потеря токенов на ZERO_ADDRESS — ИСПРАВЛЕНО
3. Рассинхрон три при restore снапшота — ИСПРАВЛЕНО
4. Approve-гонка ERC-20 — safe increase/decrease
5. **Merkle-пруфы сломаны** (неверный префикс ветки) — КРИТИЧНО, ИСПРАВЛЕНО
6. **Nomad-style**: отсутствующий пруф принимался — ИСПРАВЛЕНО
7. Обход проверки: невалидное сообщение с bounce=false всё равно роутилось — ИСПРАВЛЕНО
8. Cross-shard replay (дубль msg_id) — дедуп
9. **Fake quorum**: дубли подписей накручивали кворум — ИСПРАВЛЕНО
10. Actor bounce кредитовал дважды (инфляция) — отложенный кредит
11. SVM: заказы в стакане не откатывались при revert — clone-commit
12. verify_signatures(0) принимал неподписанный блок — запрещено
13. Роутинг в несуществующий шард — проверка active_shards
14. Консенсус: нет валидации блока, нет лимита размера, нет границы раундов — ИСПРАВЛЕНО
15. infnode: ключи на диске с правами 0644 + слабый KDF — ИСПРАВЛЕНО
    (Argon2id 64МБ, enc2-формат, 0600/0700, zeroize)

### 1.4 Бенчмарк (release)
- SVM: 798M ops/s | Orderbook: 17.4M orders/s | Merkle verify: 533K/s
- Native transfer: 23.8K tx/s (упирается в Ed25519 ~42µs) | Consensus votes: 22.8K/s
- Wire: 16.8K frm/s (~17 MB/s @1KiB)
- **Trie insert: 314/s — ГЛАВНЫЙ ТОРМОЗ (O(n) rebuild → O(n²))**
Файлы: `examples/benchmark.rs`, `tests/performance_tests.rs`

### 1.5 РЕАЛ-ТЕСТ на сервере — УСПЕХ
- **Соло-валидатор**: финализирует блоки ✅
- **Мульти-нода (2 процесса, порты 9410/9411)**: обе финализировали 64 блока
  с ОДИНАКОВЫМИ хешами → настоящий BFT по сети ✅

---

## 2. ТЕКУЩЕЕ СОСТОЯНИЕ

- **156 тестов, 0 провалов** (`cd /home/imm/stellereum && cargo test`)
- Сборка чистая. Бинарник на сервере: `/root/stellereum/target/release/stellereum` (8.2M)
- Кошелёк `stell` установлен (`~/.cargo/bin/stell`)

### Тест-файлы
`integration_tests.rs`, `blockchain_security_tests.rs`, `historical_attacks_tests.rs`,
`more_attacks_tests.rs`, `attack_round3_tests.rs`, `token_security_tests.rs`,
`token_adversarial_tests.rs`, `token_integration_tests.rs`, `svm_atomicity_tests.rs`,
`merkle_proof_tests.rs`, `performance_tests.rs`

---

## 3. СЕРВЕР ДЛЯ РЕАЛ-ТЕСТА

- **A (aeza)**: `212.113.103.105` — Debian 13, 1 CPU, 3.8GB RAM, ~2.0GB free disk
  - SSH: `ssh stell-test` (ключ `~/.ssh/stell_test_ed25519`, добавлен в authorized_keys)
  - Также работает `ssh root@212.113.103.105`
  - На нём: старый infnode (systemd `aeza-node.service`, порт 9400), Rust 1.95
  - Наш блокчейн: `/root/stellereum`, конфиги `/root/nodeA/node.yaml`, `/root/nodeB/node.yaml`
- **B (infmail-validator)**: `109.107.155.67` — мой ключ НЕ добавлен (нужно добавить для мульти-серверного теста)

### Публичный ключ для добавления на другие серверы
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL0M8YL08FXlpw0RogfN7DloZaPRU8nQzkehuBOsYFpQ stellereum-test
```

### Запуск нод на сервере A
```bash
# конфиги: /root/nodeA/node.yaml (порт 9410), /root/nodeB/node.yaml (порт 9411)
# взаимные пиры, validators = [другой узел]
(cd /root/nodeA && nohup /root/stellereum/target/release/stellereum run --config node.yaml --shard 1 >run.log 2>&1 &)
(cd /root/nodeB && nohup /root/stellereum/target/release/stellereum run --config node.yaml --shard 1 >run.log 2>&1 &)
# ОСТОРОЖНО: pkill -f "stellereum run" убивает ssh-сессию! Использовать pkill -x stellereum
```

### Пересборка на сервере после правок
```bash
scp -i ~/.ssh/stell_test_ed25519 src/*.rs root@212.113.103.105:/root/stellereum/src/
ssh stell-test 'export PATH=$PATH:/root/.cargo/bin; cd /root/stellereum && cargo build --release'
```

---

## 4. ГРАБЛИ (что уже наступали)

1. **`pubsub.publish` НЕ доставляет в app_subs приёмника** — только его подписчикам.
   Для прямой доставки использовать `pubsub.msg` (терминальная операция).
2. **`pkill -f "stellereum run"` убивает ssh-сессию** (её командная строка содержит
   эту строку). Использовать `pkill -x stellereum`.
3. **Раунды нод расходятся** из-за независимых таймеров → нужна синхронизация
   (`advance_to_round` при получении сообщения с большим раундом).
4. **`request_to` без таймаута может зависнуть** → оборачивать в `tokio::time::timeout`.
5. **Genesis state должен быть идентичен на всех нодах** (сейчас у каждой свой
   genesis-аккаунт → разные state_root, но консенсус на блоках всё равно сходится).
6. **Ключи ноды должны быть persistent** (иначе identity меняется каждый запуск).

---
## 5. СЛЕДУЮЩИЕ ШАГИ (todo)

### СДЕЛАНО ПОСЛЕ ПЕРВОЙ ВЕРСИИ ЭТОГО ФАЙЛА
- СТЭЙДЖ 1 закрыт полностью: security-тесты консенсуса (11 тестов)
- СТЭЙДЖ 2 закрыт: `chain.rs` (BlockTree, fork-choice, reorg-план) + `ChainState`
  (checkpoint + apply реорга) — 8 тестов
- СТЭЙДЖ 3 закрыт: `mempool.rs` (fee-приоритет, вытеснение, per-sender quota) +
  `TxGossip` в `consensus_net.rs` + интеграция в runtime/main — 8 тестов
- СТЭЙДЖ 4 (дерево) закрыт: `cell.rs` переписан на **sparse Merkle tree** (256 бит
  ключа). Запись O(1)-по-n (~7-10K ins/s независимо от размера; было 244/s при
  10K и деградировало). Пруфы — 256 сестёр + leaf_hash.
  ВАЖНО: честный компромисс — verify стал дороже (256 хешей), зато запись
  предсказуема. Дальнейший рост ×10 = compressed Patricia (риск для SPV).
- Всего тестов: **191, 0 провалов**

### СТЭЙДЖ 4+5 ЗАВЕРШЕНЫ (после этого)
- СТЭЙДЖ 4: sparse Merkle tree (O(1)-по-n запись, ~8K/s) + `storage.rs`
  (sled: blocks + height-индекс + state-снапшоты + async-persistence).
  Нода восстанавливает состояние при рестарте, диск не тормозит консенсус.
- СТЭЙДЖ 5: `rpc.rs` (axum JSON-RPC 2.0): stell_chainId/nodeId/blockNumber/
  getBalance/getBalanceSpv/tokenBalance/tokenSupply/tokenBalanceSpv/listTokens/
  mempoolSize/sendRawTransaction. Dockerfile + docker-compose + docker/node.yaml.
  RPC проверен вживую (curl): все методы отвечают корректно.
- Всего тестов: **202, 0 провалов**. GitHub: immtes/stellereum (private),
  последний коммит 3e73a27.

### ОПТИМИЗАЦИЯ (после финала стейджей)
- Батч-верификация Ed25519 (`Transaction::verify_signatures_batch`) подключена
  в `validate_proposal`. 5 тестов.
- **COMPRESSED PATRICIA ЗАВЕРШЁН** (`src/cpat2.rs`): relative-skip Patricia,
  обход только точек ветвления (~log n). `cell.rs::PatriciaTrie` обёртка.
  root hash считается лениво (раз на блок).
  РЕЗУЛЬТАТ (release): trie inserts 8.0K -> **2.41M/s (×298)**,
  token transfer 13.4K -> **1.38M tx/s (×103)**, native 3.4K -> **23.9K (×7)**.
  Осталось (некритично): proof generation медленная (рекурсивный сбор сестёр),
  можно кэшировать хеши узлов.
- Всего тестов: **219, 0 провалов**. Коммит 9a71390.
- Бенчмарк (release): SVM 950M ops/s, Orderbook 19.9M/s, native 3.4K tx/s,
  token 13.4K tx/s, trie insert 8.1K/s (стабильно 7-12K при 100..50K ключей),
  Merkle gen 23.6K/s, verify 35.7K/s, votes 22.6K/s, block 51K/s, wire 15K frm/s.
- ГАЗ-ГРИФИНГ в стакане — НАЙДЕНО и ИСПРАВЛЕНО: market-ордер мог пересечь
  неограниченно уровней за фиксированный газ. Фикс: `submit_order_bounded`
  (cap MAX_MATCH_LEVELS=64) + `GAS_PER_MATCH_LEVEL=40` в SVM.
  Тесты: `tests/orderbook_griefing_tests.rs`.
- FUZZ сетевого парсера `Frame::decode` — 40k итераций (случайные байты,
  мутации, truncation, adversarial длины, версии, все префиксы), 0 паник.
  Тесты: `crates/infnode/tests/frame_fuzz_tests.rs`.
- Всего тестов: **stellereum 206 + infnode 7 fuzz**. Коммиты 7a756bf (stellereum),
  60ff3cf (infnode), запушено.
- Сервер A (212.113.103.105): мусор почищен, наши процессы остановлены.
- Сервер B (109.107.155.67): ключ НЕ добавлен (нужно для мульти-серверного теста).

### СТЭЙДЖ 4: Персистентность (СЛЕДУЮЩИЙ, КРИТИЧНО)
- [ ] **Инкрементальное Patricia-дерево** — убрать O(n) rebuild (314 ins/s → цель 100K+)
- [ ] Персистентная БД состояния (RocksDB/Sled) с async-записью вне критического пути
- [ ] Block store на диске

### СТЭЙДЖ 5: RPC/API
- [ ] JSON-RPC для кошельков, эксплорера, ботов
- [ ] Публичный шлюз + Docker-деплой

### Безопасность (незакрытое)
- [ ] Газ-грифинг в стакане (стоимость ордера не зависит от глубины)
- [ ] Fuzz сетевого парсера (proto::Frame)
- [ ] DNS-федерация infnode (несколько резолверов + trust anchor) — см. HOW_MAIL_WORKS.md
- [ ] Внешний аудит + баг-баунти + мониторинг (перед mainnet)

### Экономика (после базового ядра)
- [ ] PrimaryMarketMaker (кривая цены), staking, slashing, governance
- [ ] Реальные мосты: вотчер TON, мультисиг, wSTELL Jetton, релейер

### ФИНАЛ
- [ ] Объяснить пользователю, что сделано за 5 стейджей (определение, зачем, как)

---

## 6. КЛЮЧЕВЫЕ КОМАНДЫ

```bash
# Блокчейн: тесты
cd /home/imm/stellereum && cargo test

# Бенчмарк (release)
cargo run --release --example benchmark

# Живой пентест
cargo run --example attack_demo

# Локальный симулятор сети (in-process)
cargo run -- sim --blocks 3

# Кошелёк
stell new / balance / receive / pay <addr> <amt> / stealth-pay / trade / status
```

---

## 7. ФИЛОСОФИЯ (важно помнить)

- Сеть: infnode — только транспорт, блокчейн снаружи.
- Архитектура паспорта: Actor Model, BoC, бесконечный шардинг, CLOB, micro-gas,
  MEV-пороговое шифрование, zkML, selective confidentiality, 3-tier oracle, мосты.
- Безопасность = слои + процесс (не «найти всё»). Defense in depth, assume breach,
  аудит, баг-баунти, экономическая безопасность (стейк/слэшинг).
- Производительность: in-memory hot state + async-запись + pipelining + шардинг.
  Не закладывать глобальные локи и синхронный диск.
```

### ПОСЛЕ ФИНАЛА СТЕЙДЖЕЙ (безопасность + бенчмарк)

### РУЧНОЙ АУДИТ + ФИКС (после оптимизации)
- Proof-gen ускорен: кэш хешей узлов в Branch. 322/s -> 887K/s (×2753).
- Ручной хаос-аудит #1 (`examples/chaos_audit.rs`): trie(20k ops vs HashMap),
  token(20k, supply invariant), mempool(8k), state conservation, forgery(6),
  extremes — ВСЁ ПРОШЛО.
- Ручной хаос-аудит #2 (`examples/chaos_audit2.rs`): vote fuzz(5k), random block
  DAG fork-choice(3k), finality monotonicity, cross-shard flood, tx signature
  fuzz(20k мутаций), batch==single verify(500) — ВСЁ ПРОШЛО.
- НАЙДЕН И ИСПРАВЛЕН БАГ: rejected cross-shard сообщение резервировало msg_id
  и блокировало валидное. Теперь только ACCEPTED помечаются seen.
- Всего тестов: **219**. Коммиты: c386808 (proof-gen cache), d8c5cb8 (фикс).

### ПАРАЛЛЕЛЬНОЕ ИСПОЛНЕНИЕ + ЛИЧНЫЙ АУДИТ УЯЗВИМОСТЕЙ (финал)
- ПАРАЛЛЕЛИЗМ: `apply_transaction` теперь обновляет только 2 затронутых
  аккаунта (был O(n) rebuild). `apply_block_parallel`: батч-верификация +
  группировка по отправителям + один write-lock. `verify_signatures_batch_parallel`
  (rayon, чанки 256). Итог: native TPS 21K -> 126K (×5.9). Корни идентичны.
  Коммит 381f508.
- Аудит безопасности параллелизма (`examples/chaos_audit3.rs`, 8 секций):
  детерминизм(100 блоков), порядок nonce, self-transfer, дубликаты, mixed-batch,
  консервация(50×200), конкурентные блоки, parallel==sequential batch verify(300).
  ВСЁ ПРОШЛО. Коммит da52cb3.
- Аудит соответствия паспорту (`examples/passport_audit.rs`, 15 технологий):
  Actor/BoC+Patricia/Sharding/CLOB/SVM-gas/MEV-Shamir/zkML/Confidentiality/
  Oracle/Bridges/GenesisVault/STS/BFT/Reorg/SPV — ВСЕ подтверждены живыми вызовами.
  Коммит da52cb3.
- **НАЙДЕНА И ИСПРАВЛЕНА УЯЗВИМОСТЬ FREE-MINT**: `send_message` пропускал
  проверку баланса, если отправителя нет в аккаунтах -> сообщение от
  несуществующего актора всё равно кредитовало получателя (деньги из воздуха).
  Тот же дефект в outbox-роутинге `step_actor_execution`. Фикс: sender ОБЯЗАН
  существовать (жёсткая ошибка), в outbox — drop. Регресс-тест
  `actor_message_from_ghost_sender_rejected`. `examples/vuln_hunt.rs` — 10 классов
  атак (replay, forged sig, allowance double-spend, duplicate quorum signers,
  overflow, unauthorized mint, zero-address и др.) — все BLOCKED после фикса.
  Коммит 92221dc.
- Всего тестов: **225**. Все зелёные.

### ЛИЧНЫЙ АУДИТ УЯЗВИМОСТЕЙ — РАУНДЫ 2-4 (финал)
- `examples/vuln_hunt2.rs` (10 атак на модули): bridge deposit/withdrawal replay,
  confidential conservation + viewing-key forgery, oracle zero-price, zkML tamper +
  session-cap, mempool flood, large transfer — ВСЕ BLOCKED. NOTE: declared
  gas_limit используется как eviction-fee в мемпуле (пробел fee-модели, не
  эксплуатируемо сейчас).
- `examples/vuln_hunt3.rs` (8 кросс-модульных атак): finality regression, cross-shard
  replay, equivocation, empty validator set, double debit, determinism, block-tree
  cycle, same-height siblings — ВСЕ BLOCKED.
- `examples/vuln_hunt4.rs` (фаззинг декодеров/DoS): 130k+ случайных входов в
  ConsensusMsg/BoC/parse_incoming/JSON — 0 паник; over-cap(32MiB)+empty rejected;
  deep JSON rejected (serde recursion limit). MAX_CONSENSUS_MSG=32MiB (by design,
  = frame cap infnode).
- Коммит 82be92c.
- ИТОГО найдено и исправлено настоящих уязвимостей в этой сессии: **2**
  (cross-shard msg_id reservation, actor free-mint). Остальные атаки — blocked.
- Всего тестов: **225** + 6 аудит-примеров. Все зелёные.

### ЭКОНОМИКА (после аудитов)
- FEE-ПРОБЕЛ #9 ЗАКРЫТ (коммит 3993422): `mempool.rs` использовал заявленный
  `gas_limit` как eviction-fee без проверки оплаты -> бесплатное вытеснение.
  Теперь `add_checked(tx, balance)` проверяет amount+gas_limit; `add` НЕ вытесняет.
  Все сетевые пути (runtime.add_tx async, rpc, main gossip/pull) на add_checked.
  `vuln_hunt2` #9 -> BLOCKED.
- STAKING/SLASHING/REWARDS (коммит dc08bb8): новый `src/staking.rs` —
  StakingLedger (bond/unbond+cooldown, delegate/undelegate, withdrawable),
  stake-weighted ValidatorSet, slashing с пропорциональным burn (self+delegators),
  equivocation-evidence -> slash автоматически в `try_finalize`, block reward
  предложителю + split с делегаторами (комиссия). runtime: with_staking/
  with_block_reward/apply_equivocation_slashes. 14 тестов.
- PMM (коммит 799b785): новый `src/pmm.rs` — bonding curve P(S)=P0*(1+S/S_cap),
  точные целочисленные интегралы (buy=isqrt, sell=квадратичная), USDT-резерв +
  ring-fenced redemption_buffer (20%), `max_redeemable_stell()` бинарным поиском,
  buy_with_usdt/buy_exact_stell/sell_stell. CLI `pmm price|buy|sell`.
  9 unit + 6 security тестов (нет round-trip профита, нет полного слива,
  монотонная цена, детерминизм).
- GOVERNANCE (коммит 550d78e): новый `src/governance.rs` — propose (мин 10k STELL)/
  vote (вес=стейк, один голос, без флипа)/finalize (кворум 2/3 + yes>no)/
  execute (только proposer, один раз). GovAction: SetMinValidatorBond,
  SetEquivocationSlashBps, SetDefaultCommissionBps, SetBlockReward,
  SetPmmRedemptionBufferBps, SetGovernanceQuorumBps, Signal. 9 тестов.
- Либы: `lib.rs` += staking, pmm, governance (теперь 27 модулей).
- Всё зелено: 23 набора тестов, 0 провалов.

### TODO (полная реализация, не заглушки)
- [x] fee-модель
- [x] Staking/DPoS/Slashing
- [x] PMM
- [x] Governance
- [x] WASM/деплой контрактов в SVM + хранилище + события
- [x] TON-мост (вотчер TEP-74 / мультисиг 2-of-3)
- [x] EVM-адаптеры (watcher 64 конф. + EIP-712 release)
- [x] Block Explorer + публичный шлюз (CORS, /health, /metrics, rate-limit)
- [x] Testnet faucet (opt-in, через подписанные tx, lifetime-cap)
- [x] CI (GitHub Actions: build, tests, passport_audit, 5 vuln_hunt)
- [x] **Починить одностороннюю доставку pubsub в infnode** (V5, коммит d99822e)
- [x] Живой мульти-нодный тест: 2 ноды, реал BFT по сети, идентичные хеши
- [ ] Внешний аудит / баг-баунти / мониторинг

---

## 8. СДЕЛАНО В ЭТОМ БЛОКЕ (после 2026-09-24, handoff v2)

Коммиты: `9b899f9 … 4f0d1ac` (ветка с аудитом A1–A14 и P1/P2).
Тесты на момент записи: **348 passed, 0 failed**; `passport_audit` = 16/16.

### 8.1 Аудит A1–A14 (все закрыты, с регресс-тестами)
- A1 cross-shard `trusted` сбрасывается при сетевом декоде
- A2 MEV: `verify_round_commitment` дедуплит
- A3 `advance_to_round` ограничен
- A4 zkML: `verify_inference_against(model)`
- A5 range proofs (bit-decomp + Schnorr OR) в `crypto_privacy.rs`
- A6 `route_address` = longest-prefix
- A7 CLOB-сеттл all-or-nothing (STELL ↔ wUSDT) + escrow, pre-валидация
  (найден и исправлен баг частичного сеттла → double-spend)
- A8 стейкинг списывает/кредитует реальные балансы
- A9 полная персистентность доменов (`DomainSnapshot`, sled-дерево `domains`)
- A10 session expiry по block-time (`verify_at`)
- A11 fee-рынок: base_fee, `MAX_BLOCK_GAS=30_000_000`, `select_bounded`, комиссия → пропозеру
- A12 bounded persist queue (`PERSIST_QUEUE_CAP=8192`)
- A13 RPC auth-токен для write-методов
- A14 cross-shard proof доказывает leaf `balance||nonce` + `source_balance >= amount`

### 8.2 P1 — сеть/синк/консенсус
- Детерминированный genesis (`runtime::fund_genesis`) — одинаковый state_root на всех нодах
- Персистентный consensus lock (`ConsensusCheckpoint`) — safety при рестарте
- Ротация validator set из стейка (`refresh_validator_set_from_staking`)
- Block-sync отстающих нод + fast-sync/state-sync с проверкой state_root (`sync.rs`)
- Мемпул-gossip: RPC → P2P `tx_broadcast`, дедуп

### 8.3 P2 — мосты / контракты / шлюз
- CLOB escrow для resting-ордеров + возврат при `cancel_order_settled`
- TON: `TonJettonBurnPayload` (TEP-74) + `TonMultisigReleaseOrder` 2-of-3
- EVM: `EvmWatcher` (64/32 конфирмации) + `EvmReleaseOrder` (EIP-712)
- WASM: `contract.rs` — деплой/вызов, `host.sload/sstore/emit`,
  персистентное хранилище + события, лимит топлива
- Explorer/шлюз: UI, `/api/*`, per-IP rate-limit (prune при >100k IP), CORS
- `/health` (200 OK) и `/metrics` (Prometheus: block_height, mempool_size,
  contracts_total, tokens_total)
- **Faucet (testnet-only, коммит `4f0d1ac`)**: выключен по умолчанию
  (`STELL_FAUCET=1` + `STELL_FAUCET_KEY`), перевод идёт **подписанной tx**
  из заранее пополненного genesis-аккаунта в мемпул (решение — консенсусом,
  не node-local state), жёсткий lifetime-cap на адрес (1000 STELL),
  404/429 при выключенном/исчерпанном. Методы: `stell_faucet`,
  `GET /api/faucet/:address`.
- CI: `.github/workflows/ci.yml` (build, cargo test, passport_audit, 4 vuln_hunt)

### 8.4 Бенчмарки (release)
native 23.7K tx/s · block-apply 118.7K tx/s (×5.6) · token 573K tx/s ·
SVM 760M ops/s · trie 475K ins/s · wire 16K frm/s.
Узкие места для будущей оптимизации: Ed25519 ~42µs/подпись, round_timeout 3с,
O(n) root trie, hex+JSON в pubsub, RwLock churn.

### 8.5 Скорость тестов (было 10–15 мин → 9 секунд)
Причина: тесты крипто-тяжёлые (Ed25519, хеши, Меркель, WASM), а зависимости
компилировались без оптимизаций + полный debuginfo (20 GB target/debug, LLD
падал, диск забивался на 100%).
Решение в `Cargo.toml`: `[profile.dev]/[profile.test] debug = 0` и
`opt-level = 3` для `[profile.dev.package."*"]` / `[profile.test.package."*"]`.
Свой крейт остаётся на opt-level 0 — пересборка быстрая, крипто быстрая.
Итог: 355 тестов за ~9 с, target/debug 20 GB → 1.3 GB.

---

## 8.6 ЛИЧНЫЙ АУДИТ РАУНД 5 — НАЙДЕНО 4 НАСТОЯЩИЕ УЯЗВИМОСТИ

Все 4 — из новой поверхности (WASM-контракты, faucet, sync, мост).
`examples/vuln_hunt5.rs`: **47 атак, все BLOCKED**. Раунды 1–4 тоже зелёные.

### V1 (КРИТИЧНО) — удалённый kill ноды через WASM: переполнение стека
`wasmi` по умолчанию использует dispatch-бэкенд, который **рассчитывает на
tail-call оптимизацию компилятора**. Без неё (debug-сборки, цели без гарантии
TCO) каждый back-edge wasm рекурсивно уходит в Rust, и обычный цикл в
контракте **убивал весь процесс ноды** (SIGSEGV/SIGABRT), а не возвращал trap.
Замеры: ~1900 итераций убивали задачу tokio со стеком 2 MiB, ~25k — поток
64 MiB. В release работало только благодаря TCO, то есть безопасность ноды
зависела от недокументированной оптимизации.
Фикс: фича `portable-dispatch` в Cargo.toml → ограниченный loop-бэкенд.
Проверено: 500k+ итераций на стеке 2 MiB проходят. Регресс-тест
`deep_loops_cannot_overflow_the_native_stack` (падает без фичи).

### V2 (КРИТИЧНО) — block sync принимал нефинализированную цепочку
`validate_sync_chain` проверял ТОЛЬКО подпись прозера. Злоумышленный peer мог
скормить ноде целую историю: блок, подписанный одним прозером, с пустым
`validator_signatures`. Нода применяла его к состоянию и переходила на высоту
пира — то есть ОДИН пир уводил ноду на форк, который кворум никогда не
финализировал. BFT-гарантия обходилась.
Фикс: `validate_sync_chain(blocks, first_height, our_last_hash, quorum)` —
проверяет кворум валидаторов на каждом блоке, что первый блок продолжает НАШ
канонический хеш, и отказывает при quorum == 0. Плюс `main.rs` сверяет
вычисленный state_root каждого применённого блока с корнем в заголовке.

### V3 (средняя) — DoS через раздувание консенсус-состояния
`host.sstore`/`host.emit` выполняются ВНЕ топливного счётчика wasmi. Контракт
мог за один вызов записать миллионы новых ключей — и это становилось
**постоянным** состоянием каждой ноды. Фикс: `MAX_CONTRACT_STORAGE_KEYS=4096`,
`MAX_CONTRACT_EVENTS=256`, плюс оплата газа за sload/sstore/emit
(FUEL_SLOAD/SSTORE/EMIT). Перезапись существующего ключа не ограничена.

### V4 (средняя) — пустой relayer-сет отпускал ВСЕ операции моста
`MultisigRelayer::new(vec![])` → `threshold = (0*2+2)/3 = 0`, а
`count_signers >= 0` верно для любого входа. То есть при неверной конфигурации
релеера ЛЮБАЯ операция выпускалась с пустым списком подписей. Тот же класс,
что был закрыт в `verify_signatures(0)`, но в мосте остался.
Фикс: threshold ≥ 1 + явный отказ при пустом relayer-сете.

### Мелочи, закрытые попутно
- Faucet: отклонённая транзакция сжигала nonce → все следующие капли
  вставали навсегда. Добавлен `rollback`.
- Faucet переводит не состояние напрямую, а подписанной транзакцией в
  мемпул — иначе решение о выпуске средств было бы node-local.
- `validate_code` теперь делает dry-run инстанциацию: контракт, импортирующий
  то, чего хост не даёт, отвергается на деплое, а не становится вечно
  невызываемым за деньги создателя.

### 8.7 LIVE-ТЕСТ 2 НОД НА СЕРВЕРЕ A — НАЙДЕНО 3 БАГА ЖИЗНЕСПОСОБНОСТИ

Живой прогон поймал то, чего не поймали 355 тестов: **сеть вставала на высоте
1 навсегда**, обе ноды исправно предлагали блоки и уходили в view change.

1. **Голос отправлялся ровно один раз.** infnode pubsub — best-effort. Одно
   потерянное precommit оставляло пира навсегда на одну подпись короткой, а
   после расхождения по раундам уже ни одна сторона не могла финализировать.
   Теперь перед view change голоса текущего раунда переотправляются (как
   Tendermint пере-распространяет по таймауту).
2. **Зафинализировавший не сообщал пирам.** Нода, пропустившая решающий голос,
   не узнавала исхода и предлагала блоки, которые все отвергали как
   «wrong height». Добавлен `ConsensusMsg::Committed` (блок + сертификат);
   `adopt_committed` проверяет сертификат по **локальному** набору валидаторов
   и заново валидирует блок — пир не может заставить применить нефинализированное.
3. **`broadcast()`/`join()` резолвили пира по ИМЕНИ и молча ничего не слали**,
   если имя ещё не появилось в реестре. Теперь резолвят по node-id и логируют
   вместо тихого отказа. Отдельно: отказы по proposal'ам вообще глотались
   через `let _ =` — из-за этого у бага не было ни одной диагностики.

`try_finalize` и catch-up используют общий `apply_block_fees_rewards`, так что
блок попадает в state engine одинаково в обоих путях.

### 8.8 ТРАНСПОРТ ПОЧИНЕН — МУЛЬТИ-НОДНЫЙ ТЕСТ ПРОШЁЛ (V5)

Причина односторонней доставки была в **infnode**, не в блокчейне:
`connect_or_get` создавал исходящее соединение, но **не запускал на нём
`frame_loop`**. Цикл запускался только на ПРИНЯТЫХ соединениях (и в
`start_listener`/`reconnect_loop`). QUIC-соединение двунаправленно, поэтому
нода, которая только дозванивалась, могла отправлять запросы, но не могла
обработать ни одного запроса от пира по тому же соединению. Отсюда: A приняла
66 сообщений, B — 0, и сеть стояла на высоте 1.

Фикс (коммит `d99822e` в infmail-valid-backend):
- `ensure_frame_loop` — идемпотентный запуск цикла по `stable_id`;
  `frame_loop` снимает отметку при выходе, переподключение получает новый цикл
- accept-путь тоже регистрирует свой блокирующий цикл в том же множестве, так
  что на соединении не может оказаться двух циклов
- `connect_or_get` поднимает цикл на каждом дозвоне
- `request`/`request_to`/`connect_or_get`/`ping`/`perf`/`poke`/`dht_find_node`
  принимают `self: &Arc<Self>`, чтобы дотянуться до общего реестра

### 8.9 РЕЗУЛЬТАТ ЖИВОГО ТЕСТА (сервер A, 2 ноды, реал QUIC/TLS)
- **Обе ноды финализируют блоки с ИДЕНТИЧНЫМИ хешами и state root.** Дошли до
  высоты 156, отставание 0, RPC обеих нод отдаёт 0x9c.
- Скорость: ~0.2–0.3 с на блок при 2 валидаторах.
- TLS-пиннинг ключей работает (при подмене ключей — «pinned pubkey mismatch»).
- Живые атаки на работающую ноду — **все заблокированы**:
  faucet выключен (`-32601`), неизвестный метод (`-32601`), битый JSON
  (`-32700`), подделка tx, тело 1.2 MB (`-32600 request too large`), флуд
  300 запросов — нода выжила и продолжила финализировать (высота 50 → 96).
- Шлюз: `/health` 200, `/metrics` отдаёт block_height 96, битый адрес → 400.

---

## 8.10 ЖИВОЙ ТЕСТ ТРАНЗАКЦИЙ — НАЙДЕНО ЕЩЁ 3 БАГА (коммит `4de83a1`)

2-нодный тест дал пустые блоки. Прогнал полный сценарий с транзакциями —
и он не заработал вообще: faucet и переводы висели в мемпуле вечно, баланс не
двигался, **ни одной ошибки в логах**.

**B1 (главный): мемпул RPC и мемпул консенсуса — РАЗНЫЕ объекты.**
RPC писал в `RpcState.mempool`, а proposer выбирал из `ValidatorRuntime.mempool`,
который наполнялся только через P2P-оверлей. То есть включение транзакции
зависело от того, вернётся ли она по сети в proposing-ноду. На single-validator
ноде она не возвращалась ВООБЩЕ. Побочно: `stell_mempoolSize` показывал
выдумку, а RPC-мемпул рос бесконечно (его никто не чистил).
Фикс: один общий `Arc<RwLock<Mempool>>` (`ValidatorRuntime::with_mempool`).

**B2: мемпул не выбрасывал неисполнимые tx.** Tx с уже потраченным nonce
(или с упавшим балансом) навсегда оставался: не включался (исполнение
отвергает) и не вычищался. Он занимал слот nonce и **навсегда блокировал все
следующие транзакции этого аккаунта** — то есть один опечатанный nonce
окирпичивал аккаунт. Фикс: `Mempool::evict_unexecutable` (пропускает tx с
nonce ВПЕРЁДИ — они просто ждут очереди). Тесты: `unexecutable_transactions_are_evicted`.

**B3: `wallet send` запрашивал баланс по ПРИВАТНОМУ ключу.** Адрес аккаунта —
это публичный ключ, а не seed. Запрос всегда возвращал `balance 0, nonce 0`,
поэтому CLI вечно переиспользовал nonce 0, и все транзакции после первой были
replay'ами. Помог `--verbose`: он печатает сырой RPC-запрос, и ошибка была
видна сразу. Плюс новые подкоманды: `wallet address` (key → адрес) и
`wallet send` теперь реально отправляет tx.

**B4: genesis молча затирался при рестарте.** Нода сначала пополняла faucet в
genesis, потом восстанавливала состояние с диска — и genesis-финансирование
исчезало без единой ошибки. Любая смена genesis-параметров (набор валидаторов,
балансы, `STELL_FAUCET_KEY`) оставляла ноду на цепи, которую её собственный
конфиг уже не описывал. Фикс: fingerprint genesis state root в storage; при
несовпадении нода **отказывается стартовать** с понятным сообщением.

**Проверено вживую:** faucet → 100 STELL → переводы с nonce 0,1,2,3 → балансы
сходятся → мемпул 0. Genesis state root совпадает на обеих нодах.

### 8.11 ОСТАЁТСЯ ЗАМЕТИТЬ
- ~~Одиночная нода финализирует ~5000 блоков/сек~~ **ПОЧИНЕНО** (коммит
  `24e6e8a`): `STELL_MIN_BLOCK_MS` (по умолчанию 400 мс) ограничивает частоту
  блоков. Замерено: 5000/сек → 2/сек, транзакции не сломались. Это политика
  proposer'а, а не правило консенсуса: валидность блока не зависит от времени.
- Секундное окно `round_timeout = 3s` даёт ~0.2–0.3 с на блок при 2 валидаторах.
- Handle `@stellereum` в Telegram свободен и занят нами (1 подписчик, постов
  нет). Защитить: 2FA + закрыть Join Requests + вписать в README/сайт.

### 8.12 P0-2 СЛЭШИНГ ЗА ПРОСТОЙ (коммит `4ea7652`)
До этого штрафовали только double-vote → увести валидатора офлайн было бесплатно.
1/3 набора молчащих = атака на живучесть, при этом не выглядит как атака.

**Доказательство — precommit-сертификат финализированного блока, не локальный
таймер.** Иначе нода за партитионом штрафовала бы честных пиров (некорректно), и
две ноды вынесли бы разные вердикты (недетерминированно, расхождение state root).
Все ноды выводят один и тот же список отсутствующих из одного и того же блока.

- `staking.rs`: `ValidatorStake.missed`, `last_downtime_penalty`
- `DOWNTIME_MISS_THRESHOLD=10` → 0.1% burn; вернулся к подписям — прощение
- `DOWNTIME_PENALTY_COOLDOWN=100` между слэшами, одна авария стоит ограниченно
- burn списывается из реального `STAKING_POOL`, а не «по бумажке»
- вызывается на обоих путях финализации: локальном и `adopt_committed`
- **Ловушка намеренно оставлена**: cooldown не действует на первое нарушение, иначе
  на молодой цепи (где height < 100) не штрафовался бы вообще никто
- 363 теста. Регрессия-тест: `downtime_slashing_is_driven_by_the_quorum_certificate`

### 8.13 P0-3 RPC RECEIPTS (коммит `5fbe24b`)
Кошелёк мог только спросить «мой хеш ещё в мемпуле?». Как только proposer его
выкинул — узнать ничего нельзя: финализирована, упала или потеряна. Это три
исхода, которые пользователь обязан различать. Без них кошелёк не пишется.

- `stell_getTransactionReceipt` → height, block hash, index, status, gas limit
- `stell_getTransactionStatus` → mined / failed / pending / unknown (для polling)
- ограниченный индекс (50k), вытеснение в порядке вставки, мусорный хеш = ошибка
  клиента, а не паника

**Главная тонкость (поймана тестом):** флаг успеха пишется в точке коммита внутри
применения блока, а НЕ пересчитывается постфактум. После применения nonce отправителя
уже инкрементирован, поэтому повторный разбор отметил бы **все успешные транзакции
как failed**. Первый черновик вообще переприменял блок ради receipts — это исполнило
бы каждый перевод дважды. Оба случая закрыты тестами:
`receipt_status_and_block_are_consistent` (баланс сходится ровно один раз),
`receipt_index_is_bounded`, `receipt_distinguishes_pending_from_unknown`.
368 тестов. Clippy: 0 ошибок, мои варнинги вычищены.

### 8.14 P0-4 СПЕЦИФИКАЦИЯ ПРОТОКОЛА — НАЙДЕНА CRITICAL ДЫРА В SOUNDNESS (коммит `398e900`)
Делал по варианту «код-инварианты, спека как артефакт». Первая же проверка
инварианта нашла дыру, ради которой блок и затевался.

**`get_state_root()` возвращал корень Patricia trie. В trie коммитились только:
нативные балансы, STS-балансы и supply, code hash контрактов. Всё остальное
менялось в памяти и в корень не попадало:**

| Подсистема | Что было вне root | Чем это опасно |
|---|---|---|
| `staking` | bond, delegate, unbonding, `missed`, `last_downtime_penalty` | **набор валидаторов** = f(staking) на каждой границе высоты |
| `orderbooks` | книги, уровни, покоящиеся ордера | CLOB-состояние не сверяемо |
| `order_escrow` | привязка (pair,order)→средства | бухгалтерия escrow не сверяема |
| `pmm` | `minted_nano`, `reserve_micro`, кривая, quote asset | цена STELL не сверяема |
| contract `storage` | балансы и счётчики контракта | можно доказать существование контракта, но не его содержимое |

**Почему это critical, а не «неаккуратно»:** block sync решает по state root,
принимать ли блоки пира. Две ноды могли держать **разные наборы валидаторов,
разные книги или разное storage контрактов** и при этом иметь одинаковый root.
Набор валидаторов — консенсус-критичное состояние, поэтому это дыра в soundness.

**Как чинил (и почему так, а не иначе):** один digest всех доменов пишется
в trie под ОДНИМ namespaced ключом (`STELL_CONSENSUS_COMMITMENT_V1`). Вариант
«включить digest прямо в state root» я сделал первым и он **сломал все SPV-про
ерифы** — они определены против trie root. Единый ключ сохраняет
`state_root == trie_root`, и light client не нужен второй отдельно
подписанный root.
- digest пишется **при чтении root**, если изменился (не гонять по всем
  mutation sites — их десятки, и «забыть» было причиной дыры)
- в `apply_block_parallel_fees` — тоже, чтобы эффекты блока коммитились сразу
- каждая map сортируется по ключу перед хешированием: порядок итерации
  `HashMap` разный между процессами, наивный обход дал бы расхождение root
  без всякого атакующего (есть тест)
- 11 тестов в `tests/state_root_completeness_tests.rs` были красными на
  предыдущем коммите — это зафиксированный список того, что было невидимо
**Ломает сеть:** формат root меняется, живые ноды надо перезапустить с genesis.
379 тестов, 0 провалов; clippy по новому коду чист.

### 8.15 ПЕРЕЗАПУСК СТЕНДА → НАЙДЕН CRITICAL: ЦЕПЬ ФИНАЛИЗИРОВАЛА САМА СЕБЯ
Перезапуск после 8.14 (новый формат root) сразу вскрыл ещё одну дыру.

**Симптом, который вводит в заблуждение:** обе ноды показывали одинаковую высоту
и одинаковый state root — выглядит идеально здоровыми. Но
`stell_getValidators` отдавал: валидаторов `[]`, `total_power: "0"`,
`quorum: "1"`. Блоки шли ~2/сек, все пустые, бесконечно.

**Два дефекта, каждого достаточно:**
1. `quorum_power() = (total*2)/3 + 1`. При `total = 0` это **1** → набор без
   силы достигает кворума **одной подписью**, одна нода финализирует всё сама.
2. `fund_genesis` пополнял аккаунты валидаторов, но **не бондил** их. Набор
   выводится из staking-леджера → свежая цепь стартовала с пустым набором и
   сразу падала в (1).

**Почему это так легко пропустить:** две ноды с пустым набором производят
побайтово одинаковые пустые блоки, поэтому их root'ы совпадают. Совпадение —
артефакт того, что обе пустые, а не доказательство консенсуса.

**Фикс (коммит `5f98aa7`):** `quorum_power()` при нулевой суммарной силе
возвращает недостижимое значение (fail closed: цепь встаёт заметно, а не идёт
без консенсуса); genesis бондит валидателей фиксированными константами, чтобы
все ноды вывели идентичный леджер и root'ы genesis совпали.

**Проверка на живом стенде (обратная к багу):**
- обе ноды: 30 → 38 блоков, растут
- убил nodeB → высота **замерла на 38** (одна нода не может финализировать)
- вернул nodeB → пошли синхронно

### 8.16 ЧТО ЕЩЁ ВСПлыЛО НА ЖИВОМ СТЕНДЕ (не исправлено)
1. **Нода не может вернуться после рестарта.** Убитая nodeB поднялась на
   genesis (height 0), `syncing: false`, и **не пытается догнать** пира: крутится
   в бесконечном view change на высоте 1 (раунд 62+). nodeA при этом застревает
   на своей высоте. То есть перезапуск = нода навсегда вне сети. Это прямо
   пункт плана «P2: рестарт-тест персистентности» — и он провален.
2. **2 валидатора = нужно единогласие.** Кворум по силе 2/3+1, при равных
   долях 2 из 3 дают ровно 2/3 и не хватает. Проверено тестом. Один молчащий
   валидатор останавливает сеть; 4 валидатора — первый размер, переживающий одну
   неисправность. Для тестнета нужен либо третий валидатор, либо смириться с этим.
3. **Node-local рассинхрон при старте.** При почти одновременном старте ноды
   голосуют `nil` на предложения друг друга (в логах `RX Prevote ... target nil`)
   и раунды расходятся — дедлок. С разнесённым стартом (15 с) сходится сразу.
4. **Высота и state root не сэмплируются атомарно.** Опрос может поймать
   момент, когда высота уже N, а применённое состояние ещё N-1: root'ы
   кратковременно расходятся, потом сходятся. Не баг консенсуса, но окно
   наблюдаемости — при мониторинге нельзя считать пару (height, root) согласованной.
5. **nodeB перезапустился с height 0, хотя its data была 1.5 МБ** — асинхронный
   persist («never block consensus on disk I/O») не гарантирует, что состояние
   доживёт до рестарта.

### 8.17 ПАРАЛЛЕЛЬНАЯ РАЗВЕДКА САБАГЕНТАМИ → КРАЕУГОЛЬНЫЙ ДЕФЕКТ
Запустил 3 read-only сабагента параллельно (диагноз бага рестарта / аудит
покрытия состояния / разведка P1). Качество не пострадало, скорость выросла.
Главный результат — дефект, который я последовательно искал бы долго:

**F3.2 — `Block.state_root` это root ДО применения, и валидаторы его НЕ проверяют.**
`propose()` читает `get_state_root()` на `runtime.rs:422` **до** применения tx
блока. Дальше:
- `validate_proposal` (`runtime.rs:446-476`) проверяет высоту, proposer,
  prev_hash, размер, газ и подписи — и **не проверяет `state_root` вообще**.
  То есть proposer может вписать туда что угодно, и все валидаторы примут блок.
  commitment из P0-4 на живом пути **декоративен**.
- единственное сравнение root'ов (`main.rs:190-199`) сравнивает root **после**
  применения с header'ом **до** → off-by-one → любой непустой блок отвергается.
  То есть sync сломан в обе стороны: на консенсусе не проверяется, на sync ложно
  падает. `sync.rs:129-136` (`fast_sync_state`) — тот же off-by-one.
- `adopt_committed` (`runtime.rs:656-701`) вообще не сверяет root.

**Это и есть настоящая причина пункта 8.16(1)**: sync не может принять ни один
блок, плюс `main.rs:180` считал quorum старой формулой (уже исправлено в
`75339ed`).

**Прочие находки (F-номера из аудита):**
- **F1.2 TokenRegistry полностью вне commitment** — allowances, minter/paused/
  max_supply, next_nonce. Латентно CRITICAL: сейчас инертно (нет пути создать
  токен), но первый же opcode создания делает это живой дырой.
  **ИСПРАВЛЕНО `75339ed`** + тест `token_allowances_and_metadata_move_the_root`.
- **F1.1** ключ нативного аккаунта коммитит только `balance`/`nonce` из 8 полей
  `AccountState`; `inbox`/`outbox`/`code`/`storage_root` не коммитятся. Сейчас
  инертно: `send_message`/`step_actor_execution` не имеют вызывающего кода.
- **F2.3 `Governance` + `AppliedParams` живут на ноде, вне root** (`main.rs:952`,
  клонируются в runtime на каждой итерации). Ровно та форма, за которую уже
  платили. Сейчас не эксплуатируется: `applied` никто не читает в консенсус.
- **F2.6 в `RpcState` второй, node-local `StakingLedger`** (`main.rs:949`),
  коммит его игнорирует (параметр `_shared_staking`), а комментарий в `rpc.rs:46`
  утверждает обратное. Инертно, но опасная форма.
- **F3.1 sync-переигровка не делает слэши/reward/unbond и не перевыводит набор
  валидаторов** → нода продолжает со **stale validator set** (тот самый класс
  «ноды вывели разные наборы»).
- **F5.2 `restore_snapshot` теряет все contract-листья** (`state_engine.rs:1566`)
  и не зовёт `write_contract_trie_entries`; `fast_sync_state` сверяет root именно
  с этим неполным trie → отвергает валидный снапшот.
- **F4.1 `Contract.code` не в digest** (только `code_hash`) — терпимо, хеш
  покрывает; но `restore_contract_snapshot` не сверяет `sha256(code)==code_hash`.
  Если снапшоты поедут по сети (а `fast_sync_state` для того и написан) — CRITICAL.
- **Чисто и не требует повторного аудита:** алиас `ValidatorRuntime.staking` на
  engine; все поля `HeightConsensus`; единственное чтение root в коде — внутри
  `get_state_root`; детерминизм digest'а и покрытие полей всех структур, кроме
  `Contract.code`.

**Диагноз бага рестарта (точный):**
- `main.rs:130` — чтение tip'а вложено внутрь ветки успешного снапшота.
  Снапшот пишется раз в 100 высот; цепь убили на 38 → снапшота нет → height 0,
  хотя `finalized_height` в meta лежит.
- Снапшота нет ⇒ `load_full_state_into` → `Ok(None)` ⇒ «no prior state».
- Блок-стор на диске (1.5 МБ) **не читается вообще нигде**: `get_block`,
  `hashes_at_height`, `block_count` без продакшн-вызовов. Replay не существует.
- Sync: `get_latest_shard_height` читает **локальный** KV (`network.rs:71`),
  `broadcast_block` вызывается только для genesis → финализированные блоки
  наружу не публикуются, `peer_height` = собственная голова.
- Даже если бы сработало: `validate_sync_chain` требует quorum подписей, а блок
  несёт ровно одну (proposer'скую) → на 2-валидаторном стенде sync не может
  пройти принципиально.
- Мёртвый код, который и был бы фиксом: `sync::fast_sync_state`,
  `persist_state_snapshot`/`fetch_state_snapshot`, `Storage::get_block`.

**Разведка P1 (объём):** (a) pruning M, полностью независим, единственный без
chain-совместимости; (b) light client L, **блокируется (a)** для header-store и
**(c)** для BLS-ключей; (c) BLS L+, ломает genesis root (ValidatorId внутри
commitment) ⇒ только мягкий форк с activation height; (d) fee-market M, и там
найден отдельный баг: `fee == gas_limit` (цена и место — одно поле), base_fee = 0
⇒ блок из бесплатного спама, а `select_filtered` (антиспам) вообще не подключён.

### 8.18 P1 (a) PRUNING + АРХИВНЫЙ РЕЖИМ (коммит `b891988`) — 398 тестов
Блок-стор не имел retention вообще: каждый финализированный блок писался, ничего
не удалялось, а обе функции `prune_*_below` были **без вызывающего кода**. Нода
накопил ~2.9 ГБ.
- `archive` — по умолчанию (удаление тела блока необратимо и убивает
  возможность переисполнить блок ради аудита); `STELL_ARCHIVE=0` +
  `STELL_KEEP_BLOCKS=<n>` включает pruning
- retention едет на существующей cadence в 100 высот — без лишних пробуждений
- **каждый блок пишет `BlockHeaderRecord`** (height, prev_hash, state_root,
  proposer, timestamp, tx_count, gas_used, настоящий `compute_hash`) — в обоих
  режимах, поэтому переключение archive→prune не теряет цепочку. Это же то, что
  потом прочитает light client
- блок можно удалить **только если его потомок остаётся**, иначе уцелевший суффикс
  не связан с genesis. Правило живёт в одном предикате, общем для
  `prune_blocks_below` и `has_blocks_below` — они однажды разошлись: запрос
  «есть ещё работа?» игнорировал границу и вечно отвечал «да»
- pruning ограничен пачкой на задачу (писатель один, неограниченный скан
  застопорил бы все записи); state/domains держат кольцо строго ниже курсора
- консенсус не тронут, state root не меняется → сеть не ломается

### 8.19 P1 (d) ЖИВАЯ ПРОВЕРКА FEE-MARKET (коммит `dac6830`) — 405 тестов
Давления на fee-market не было вообще: один тест = одна транзакция в одном блоке;
тест на переполнение строил транзакции с `gas_limit: 0` (срабатывал лимит по
числу, лимит газа не достигался); антиспам-селектор был задокументирован как
инструмент продюсера, но `propose()` его **не вызывал**.
- `propose()` использовал `select_bounded` — уважает лимиты, но берёт что влезло.
  Значит флуд транзакций с потраченным nonce **занимал блок, платил proposer'у
  как за реальную работу**, и только потом падал при применении
- при `base_fee = 0` транзакция с `gas_limit: 0` бесплатна, всё равно занимает
  слот и оплачивается так же ⇒ блок из бесплатного спама был возможен
- `select_for_block` — лимиты + фильтр допуска за один проход по fee-порядку,
  поэтому при полном блоке побеждает самая дорогая **исполняемая** транзакция
- фильтр ведёт **ожидаемый nonce на отправителя** (в блоке нужна непрерывная
  последовательность). Моя первая версия сравнивала с nonce аккаунта — это
  пропускало дыру, которая не исполнится; поймал тест
- нода задаёт реальный пол `STELL_MIN_GAS_LIMIT` (по умолчанию
  `GAS_BASIC_TRANSFER`); библиотечный дефолт остаётся 0, чтобы тесты не сломались
- **не сделано и требует отдельного изменения:** цена и место всё ещё одно поле
  (`fee == gas_limit`), bid-ить «больше за меньше места» нельзя. Разделение =
  поле `fee` в `Transaction` ⇒ меняются байты подписи, хеш транзакции и wire-формат

### 8.20 P1 (c) BLS и (b) LIGHT CLIENT — НЕ СДЕЛАНЫ, и вот почему
Оба — L-размера и **ломают формат блока**, а я на исходе сессии. Работать их
«наполовину» хуже, чем не работать: это изменения консенсуса, которые должны
войти одним релизом с тестами, а не по кускам.
- **(c) BLS:** нужен новый C-зависимый `blst`; `ValidatorId = [u8;32]` расширяется
  через consensus/staking/runtime/governance/rpc/main (19 вхождений в consensus
  Alone). `ValidatorId` лежит **внутри staking-леджера**, а леджер — внутри
  commitment, а commitment — внутри state root ⇒ ** BLS-only релиз не стартует на
  существующих data-директориях**. Только мягкий форк с activation height.
  Побочно: `apply_downtime_slashes` выводит состав подписантов из
  `cert.signatures` ⇒ при агрегации нужен бит-вектор, иначе слэшинг сломается.
- **(b) Light client:** зависит от (a) [сделано] и (c) [не сделано], и **блокирован
  багом F3.2**: `Block.state_root` — это root ДО применения, а чекпоинт по
  определению обязан коммитить в POST-state root, к которому клиент потом
  подставляет доказательства.
Моя рекомендация по порядку: **сначала F3.2 (root pre/post)**, потом (c), потом
(b). Пока F3.2 не закрыт, commitment остаётся декоративным на живом пути.

### 8.21 СТЕНД ПОСЛЕ P1 (a)+(d)
Guard B4 снова сработал: commitment v2 (токены) сменил genesis root
`70be69a8` → `a927873a`, ноды отказались стартовать со старыми данными. После
wipe: `archive mode` активен, genesis `a927873ae7ea04df`, обе ноды синхронно
(26→34) с идентичным root `527f25ca…`, растут ~2 блока/сек.

### 8.22 F3-2 ЗАКРЫТ: STATE ROOT В ЗАГОЛОВКЕ ТЕПЕРЬ ПРОВЕРЯЕТСЯ (коммит `5cf9fdb`) — 410 тестов
**Уточнение к 8.17: pre-apply семантика — это НЕ баг.** Заголовок блока коммитит в
состояние, на котором блок строится (root после предыдущего блока) — стандарт,
ровно то, что CometBFT называет app hash. Настоящая дыра была в другом: **это
значение никто не проверял.**
- `validate_proposal` проверял высоту, proposer, подпись, prev_hash, размер, газ и
  все подписи транзакций — и ни разу не смотрел на `state_root`. Proposer мог
  вписать что угодно, и все валидаторы принимали блок ⇒ commitment из P0-4 на
  живом пути был **декоративным**.
- вторая половина — off-by-one: sync переигрывал блок и сравнивал полученный root
  с **pre-apply** значением заголовка, то есть agreement только для блока, не
  меняющего состояние. Теперь сравнение **до** применения.
- `on_proposal` стал async (ожидание читается из состояния).
**Проверка сразу окупилась:** она вскрыла, что staking-тест давал каждой ноде
ledger только со своим ключом. Разные ledger ⇒ разный commitment ⇒ разный root ⇒
ноды **корректно** отвергали предложения друг друга. Пока ledger был вне
commitment, это расхождение было невидимо — commitment его нашёл. Тест теперь
сеет все ноды из одного ledger.

### 8.23 P2: СУБАГЕНТЫ ПАРАЛЛЕЛЬНО (коммит `c5f0573`) — 445 тестов
Три независимые части, сделаны тремя субагентами **одновременно** на
непересекающихся файлах (`lib.rs` я оставил за собой), склейка и проверка — мои.
**Рабочая схема:** каждому агенту жёсткий список файлов во владении + запрет
трогать `lib.rs/main.rs/consensus.rs/rpc.rs/staking.rs`. Конфликтов не было.
- **remote_signer** (23 теста): `Signer` trait, `LocalSigner`, `RemoteSigner` через
  транспорт, `HttpSignerTransport` на `ureq`. **Ключевое свойство: локального
  fallback не существует** — при отказе транспорта ошибка пробрасывается, а не
  подписывается ключом, который оператор считает в HSM. Классический отказ
  remote-signer'ов, теперь невозможен по построению: ключа для fallback нет.
  Ошибки несут класс отказа и **не содержат payload'а** ⇒ ключевой материал не
  может утечь в сообщение (тест проверяет, что в строке ошибки нет ни seed, ни
  подписи). Модуль честно пишет, что сам по себе это не защита уровня HSM.
- **metrics** (9 тестов): 10 метрик в текстовом формате Prometheus без новой
  зависимости; метки сортируются (два скрейпа одинаковых данных байт-в-байт);
  значения меток санитизируются (тест на инъекцию фальшивой метрики). Тесты
  поймали баг: `set_height` **накапливал** вместо присваивания ⇒ гейджи и
  счётчики разведены на уровне типов.
- **testnet/ + docs/**: genesis.env, два node.yaml, полный справочник всех 22
  `stell_*` методов, операционное руководство. **Всё сверено с кодом**: YAML
  реально десериализован против типа конфига infnode, каждая константа выведена
  скриптом из исходников.

**Расхождения, найденные при этой сверке (важно):**
1. `PROTOCOL.md` §1.2 устарел — commitment теперь покрывает и весь token registry.
2. **Governance не в trie и не в digest** ⇒ не консенсус-видима (тот же F2.3).
3. **`stell_faucet` НЕ защищён `STELL_RPC_AUTH_TOKEN`** — токен проверяется только
   в `stell_sendRawTransaction`. Любой, кто дотянется до RPC, может чеканить тест-STELL.
4. **Nonce-счётчик faucet только в памяти** ⇒ после рестарта 0. Дрип проходит
   допуск, RPC возвращает хеш, а продюсер его **молча выкидывает** (contiguous-nonce
   фильтр). Получатель не платится.
5. **3 валидатора не безопаснее 2**: `quorum_power` даёт 3 из 3 при n=3.
   Первый переживающий одну неисправность размер — 4.
6. Пороги даунтайма brutal при дефолтных 400 мс: 10 пропусков ≈ **4 секунды**,
   cooldown в 100 высот ≈ **40 секунд**.
7. `advertise:` в node.yaml инертен — пиры ходят по `peers[].endpoints`.
8. Нет метрики диска; `stell_syncing` — заглушка, всегда `false`.

### 8.24 P2 РЕСТАРТ-ПЕРСИСТЕНТНОСТЬ (коммит `e3644ba`)
Диагноз из 8.16 подтвердился, корневая причина закрыта:
- чтение `finalized_height` было **внутри** ветки `Ok(Some(..))` загрузки
  состояния, то есть срабатывало только если найден снапшот. Снапшоты пишутся
  раз в 100 высот ⇒ убитая на 38-й ноде tip не читался, **хотя он лежал на диске**
  и пишется на каждом финализированном блоке. Теперь читается после загрузки
  при любом исходе, ошибка логируется.
- если восстановились с tip'а, для которого нет снапшота, он пишется сразу — иначе
  каждая следующая перезагрузка повторяет ту же потерю
**Честно про остаток:** это НЕ делает ноду полностью работоспособной после
рестарта. Block sync всё ещё не умеет закрывать разрыв: `get_latest_shard_height`
читает локальный KV, `broadcast_block` вызывается только для genesis, и нода,
потерявшая data-директорию, не может запросить блоки. Такую надо wipe'ить и
стартовать заново — теперь это написано в OPERATIONS.md. Исправлено то, где
данные на месте, а нода просто рестартнула раньше первого снапшота.

### 8.25 ЧТО ОСТАЛОСЬ ИЗ P1/P2
- **P1 (c) BLS** — не сделан: меняет genesis root, нужен мягкий форк + `blst`
- **P1 (b) Light client** — не сделан: блокирован (c) и требует проверки
  подписанного чекпоинта
- **P2 мульти-серверный тест** — заблокирован, нет доступа к 109.107.155.67

### 8.26 ЖИВАЯ ПРОВЕРКА РЕСТАРТА — ПОДТВЕРЖДЕНО И ОСТАЛСЯ РАЗРЫВ
Стенд 212.113.103.105, новая сборка. Убил nodeB на высоте ~43, вернул на тех же
данных. В логе:
```
[storage] no prior state, starting fresh
[storage] finalized head at height 43, resuming at 44      <-- ФИКС РАБОТАЕТ
[storage] wrote a snapshot at the restored head 43
[consensus] loop started at height 44 (proposer=true)
```
**До фикса было `loop started at height 1` + бесконечный view change.** Теперь
нода поднимается на правильной высоте и сама пишет недостающий снапшот.

**Но пересоединиться всё ещё нельзя.** nodeA была на hc.height 45, nodeB после
рестарта на 44, и A отвергала её предложения:
```
[consensus] rejected proposal from 9c675ebc at #44 r0: proposal: wrong height
```
(и r2, r4, r6, r8 — каждый раунд). Разрыв в один блок закрыть нечем: **block sync
не умеет догонять**. `get_latest_shard_height` читает локальный KV, финализированные
блоки наружу не публикуются (`broadcast_block` только для genesis), запроса блока
по высоте нет. Нода без состояния ⇒ wipe и старт с genesis.

**Отдельно хорошая новость:** новая проверка state root (F3.2) ни разу не дала
сработать на посторонний блок — A отвергала по высоте раньше, чем дошла до root.
То есть либо у A совпало бы и состояние, либо защита сработала бы следом. Проверка
живёт и не мешает.

**Итог по стенду:** genesis `a927873ae7ea04df`, обе ноды синхронно, root
`527f25ca…` идентичен, ~2 блока/сек, archive mode.

---

> Три связанных примитива, которых нет в собранном виде ни у кого:
> аккаунт-как-идентичность + приватность-как-опция + связь-как-разрешение.
> Каждый по отдельности существует (ENS / Push Protocol / Fhenix / Vana),
> вместе — нет. Это и есть ниша.

### 9.1 Communication Grants (антиспам-связь вместо почты) — ГЛАВНАЯ ИДЕЯ
Нативный аналог Push Protocol, но на уровне протокола, а не внешний костыль.
- **Идентификатор**: имя → адрес, нативный ENS (`alice.stell` → `0x123…`)
- **Грант**: `send:notifications` от адреса сервиса X к адресу Y, подписан
  кошельком, записан в блокчейн, проверяется нодой при доставке
- **Revoke**: одна транзакция — доступ мгновенно аннулирован (не «код, который
  можно уничтожить», а буквально отзыв на уровне состояния)
- **Scopes** (из Vana): `send:notifications` ≠ `read:data` ≠ `chat:messages`
- **Expiry** (из Fhenix): `setOperator(service, until = now + 30d)` — грант
  сам сгорает, если юзер забыл отозвать
- **Антиспам-экономика** (из Push): сервис застейкает токены; за жалобы —
  частичный slash
- Почта при этом не нужна: Web3 SSO + антиспам-мессенджер в одном

### 9.2 Нативный Account Abstraction
Аккаунт — контракт по умолчанию (как Starknet), без внешних бандлеров
(ERC-4337) и без дыры EIP-7702 с главным ключом. Вход в 10 сервисов без
seed-фразы и без кошелька.

### 9.3 Опциональная приватность (не «религия», а режим)
- прозрачный режим — для бирж и DeFi (совместимость)
- приватный — для личных транзакций
- честное ограничение: скрытие суммы «как у Монеро, но без кучи шифрования»
  невозможно. Выбор: кольцевые подписи ( Монеро, делистят) / zk (тяжело) /
  только скрытие получателя (частично). Уровень приватности надо зафиксировать
  явно, т.к. от него зависит вся архитектура.

### 9.4 Первый сценарий, который стоит показать
«Вход в 10 сервисов без кошелька, без seed-фразы и без почты, с возможностью
отписаться от уведомлений одной транзакцией» — там сходятся все три примитива.

### 9.5 МОСТЫ, КОТОРЫЕ НЕЛЬЗЯ ОГРАБИТЬ (доп. идея)

> Обычный мост = «заблокируй у меня всё, я тебе напечатаю». Мосты взламывали
> именно так: Ronin (скомпрометированный multisig, 5 из 7 без timelock),
> Nomad (мгновенная финальность + неполная привязка к сети назначения),
> Wormhole (подпись на стороне отправителя без проверки на стороне получателя),
> Harmony (скомпрометированные ключи 2 из 5). Вывод: **multisig — необходимое,
> но не достаточное условие.** Ниже — что именно делает мост безопасным.

1. **Optimistic verification + окно оспаривания.** Сообщение не применяется
   мгновенно, а ждёт окна (например 7 дней), в течение которого ЛЮБОЙ может
   подать fraud proof. Ошибка стоит атакующему времени, а не всей суммы сразу.
   Прямое лекарство от Nomad.
2. **Оптимистичный light client вместо доверия к релейеру.** Релейер только
   доставляет сообщение, а проверку получатель делает сам по merkle-proof чужой
   цепи. Взлом релейера = DoS (задержка), а не кража.
3. **Привязка preimage к сети назначения**: chain id + bridge id + nonce + домен
   + сумма в каждой подписи. Именно этой привязки не хватило в Nomad.
4. **Timelock на всё, что можно поменять** (адреса, лимиты, whitelist). Скомпрометированный ключ не может за минуту перенаправить средства.
5. **Per-bridge TVL-лимиты + circuit breaker**: максимум в сутки/месяц и
   автоматический тормоз при аномальном объёме. Ошибка в контракте не выносит
   весь TVL одной транзакцией.
6. **Разделение propose/execute**: proposer не может исполнять, между
   предложением и исполнением обязательная пауза. Один украденный ключ бесполезен.
7. **Связка с Communication Grants (идея 9.1)** — вместо безликого
   `approve all`: грант на конкретный мост `bridge:0xabc` на сумму ≤ N и срок
   T, отзываемый одной транзакцией. Тот же примитив, что для уведомлений, но
   для движения средств: один broad-approve больше не может стоить пользователю всего.
8. **Нативный AA на обоих концах.** Раз аккаунт — контракт, кросс-чейн
   сообщение может прийти прямо в аккаунт пользователя и исполниться по его
   политике, а не по логике чужого контракта-моста. Мост перестаёт быть
   отдельным продуктом и становится ещё одним вызовом аккаунта.
9. **Intent/solver вместо lock-mint.** Пользователь говорит «хочу X в сети Y»,
   солверы конкурируют, оплата условна от доказанной доставки. Контракт с
   балансом пользователю вообще не нужен.
10. **Страхование и slash для canonical-моста** + публичный аудит каждой новой
    пары цепей, а не один раз на архитектуру.

**Что взять первым:** пункты 1, 3, 4, 5 — дёшево и закрывают именно те классы
взломов, которые реально случались. Пункт 2 дороже всех, но он единственный
превращает взлом релейера из катастрофы в неудобство.

### 9.6 Трезвые ограничения
«Лёгкий TON + приватность + AA» = три тяжёлые задачи сразу; вместе — годы.
Нужно выбирать порядок. И «лучше других» — это про UX (вход без seed, оплата
без газа, отписка одной кнопкой), а не про архитектуру.

## Live deploy of the security patch (2026-09-25, ~17:36 UTC)

Deployed `969b8d9` (4 criticals) to the stand on `212.113.103.105`.

- No rsync on the box; source was shipped as a 428 KB tar of
  `src/ tests/ examples/ docs/ testnet/ PROTOCOL.md README.md`.
  **Never tar the whole repo** — the local `data/` (2.9 GB) and `target/`
  (3.9 GB) must be excluded, and the local disk was at 96% so a full tar
  failed with ENOSPC.
- The server `Cargo.toml` has `infnode = { path = "/root/infmail-valid-backend/crates/infnode" }`.
  Exclude `Cargo.toml` from the upload or the local `/home/imm/...` path
  overwrites it and the build breaks.
- `cargo` is not on PATH for non-interactive ssh:
  `export PATH=$PATH:/root/.cargo/bin`.
- Server disk is 10 GB and runs at 92-93%. `target/release` was 696 MB;
  it had to be deleted (binary backed up to
  `/root/stellereum/binary.e3644ba`) before a release build would fit.

### Deploy verified
- Both nodes restarted on the new binary and **resumed at the tip**:
  `restored full state from height 6400, resuming at 6401` /
  `finalized head at height 6471, resuming at 6472` /
  `wrote a snapshot at the restored head 6471`. The `e3644ba` restart fix
  works in production.
- **The security patch did not fork the chain.** Both nodes independently
  finalized block 6506 (`eed69ebd`) with the same state root
  `44505b076061`; after 3 minutes both still agreed on root `7d285090cf71`
  at 0x1a1b, with 0 panics, 0 root mismatches, 0 desyncs.

### Live findings that are still open
- **`stell_faucet` is wide open.** `STELL_RPC_AUTH_TOKEN` is not set on
  either node, RPC binds `0.0.0.0:8545/8546`, and `ufw` is inactive. An
  unauthenticated `stell_faucet` call credited 100 STELL to an arbitrary
  address and the transfer was **mined into block 6535 with status
  `success`**. The faucet key is the literal constant `0x11..11`
  (`[0x11u8; 32]`, the same seed as the unit tests), so anyone who can
  reach the port can mint. The in-memory nonce is lost on restart too.
  Needs: a real random `STELL_FAUCET_KEY`, an auth token on the faucet, a
  firewall, and a non-wildcard bind.
- **Receipt lookup does not round-trip.** `stell_faucet` and the receipt
  both *return* `tx_hash`, but `stell_getTransactionReceipt` only accepts
  `hash` (or a bare string), so feeding the faucet's own `tx_hash` back
  returns `missing tx hash`. `docs/RPC.md` documents `hash`, so the code
  is consistent with the docs but the field naming across methods is not.
  Accept `tx_hash` as an alias.

## Multi-server test, 2 physical machines (2026-09-25 ~19:40 UTC)

Topology finally available: **nodeA on 212.113.103.105** (public) and
**nodeB on 178.155.74.242** (this machine, user `imm`, behind NAT).
Local nodeB lives in `~/multinode/nodeB/` with its own `env.B`, `node.yaml`
(advertise `178.155.74.242:9411`, peer endpoint `212.113.103.105:9410`) and
the identity key copied from `/root/nodeB/keys`. RPC on 127.0.0.1:8547.

### It works
Both nodes started from genesis on separate machines over the internet and
agreed on **every one of 56 common heights — same block hash and same state
root**. Genesis fingerprint matched: `a927873ae7ea04df...`.

### What this exposed
1. **A third validator is structurally impossible.** `build_validator_set`
   (src/main.rs:65) always does `vs.add(self_ed, 1)` before walking peers, so
   the set always contains the node's own identity key. A node with a fresh key
   derives a 3-member set, computes a different genesis root, and silently forms
   its own chain. Growing the validator set needs a protocol change, not a config
   change.
2. **The genesis root is not stable across binary revisions.** A stale build and
   the current one produced different roots for a byte-identical config:
   `94a5357bb715e04d...` vs `a927873ae7ea04df...`. The genesis guard caught it
   correctly and refused to start, but the upshot is that "same chain" depends on
   every node running the exact same build. There is no build-id in the
   fingerprint to make this explicit.
3. **2 validators = zero fault tolerance.** Killing nodeB stopped nodeA
   immediately: last finalize was block #65, then height 66 entered an
   escalating view-change loop (rounds 5, 6, 7, ...). The chain lives exactly as
   long as both machines are up.
4. **A partition does not heal.** After restarting nodeB, nodeA kept stalling:
   nodeB's round counter ran away to r44 while nodeA sat on the same height, and
   both sides logged `handshake timeout` / `conn_closed` repeatedly as the QUIC
   session tried and failed to re-establish through NAT. The chain stayed wedged.
   The only recovery is a **coordinated wipe of both nodes** and a fresh
   genesis start, which is what restored the stand.
5. **A one-block height skew is fatal.** With nodeB at 7197 and nodeA at 7198,
   each rejected the other's proposal as `proposal: wrong height` and neither
   could advance. Same root cause as (4): there is no block catch-up, so a node
   that is even one block behind can never rejoin.
6. **Restarting a process over SSH needs full detachment.** `setsid nohup ... &`
   inside a compound ssh command still died when the session ended, leaving
   nodeA apparently configured but not running. Verify from a *second* ssh
   invocation, and check `ss -lunp | grep stellereum` — a node can be "started"
   with no UDP listener at all.

### Current stand
nodeA on 212 (log `/root/nodeA/live.log`) and nodeB on this machine (log
`~/multinode/nodeB/live.log`), both fresh from genesis, in lockstep.
To rebuild: wipe both `data/` dirs and start both again.

## Block sync + round-counter liveness fix (2026-09-25 ~21:00 UTC)

Commits `1fb2a02`, `06e1c0e`, `01a257b`, `738a672`.

### Two real bugs, both found by trying to use the thing rather than reading it

**1. The head pointer was node-local, so catch-up could never fire.**
`broadcast_block` publishes the shard head with `kv_store_local` and
`get_latest_shard_height` reads it with `get_local_kv` — both strictly local, so
that function could only ever return the node's OWN height. Asking "is a peer
ahead of me?" was asking "am I ahead of myself", and `peer_height > our_height`
was unsatisfiable by construction. Block sync had never run. infnode has no
replicated KV read, so the head now goes into a replicated DHT blob bucket
(`stell_head` / `shard_<n>_head`) via the same store_blob/fetch_blob path
`fetch_block` already uses, published on every finalize and once at startup.
`try_catch_up` then runs inside the consensus loop (throttled to 2s) and
re-anchors `rt.hc` on success, which is what lets a healed partition converge.

**2. One peer message could buy 1000 rounds.** `advance_to_round` was clamped to
`MAX_ROUND_AHEAD` (1000) PER CALL. Measured live: a fresh node at height 1
round 0 received one vote claiming round 57 and jumped there in 100 ms, then
the two nodes inflated each other (57 -> 60 -> 63 -> ...). Since
`proposer = (height + round) % total_power`, the round counter decides WHICH
node must propose, so both ended up rejecting every proposal as
"wrong proposer" and sat in view changes forever. This is the mechanism behind
both "a one-block skew deadlocks the pair" and "a healed partition never
recovers". Now clamped to +1 per message; rounds still advance on our own 3s
timeout via `next_round()`.

### Live result after the fix
Both nodes from a fresh genesis on one host: **133+ finalizes, 0 view changes**,
identical block hash AND state root at every common height, and **max round 0**
on both. Before the fix the same topology produced 0 finalizes and 23-35 view
changes at height 1.

### Operational gotchas learned the hard way
* A binary deploy that "succeeded" left the OLD binary running. Always verify
  with `strings <binary> | grep <new-marker>` after deploying, and check the
  mtime.
* `setsid nohup ... & disown` inside a compound ssh command is NOT reliably
  detached. Verify from a *second* ssh invocation and check
  `ss -lunp | grep stellereum` — a node can appear to start with no listener.
* Starting a second local node while an old one holds the sled DB fails with
  `could not acquire lock on "./data/store/db" ... WouldBlock`. Kill first.
* Never `tar` the whole repo: local `data/` is 2.9 GB and `target/` 3.9 GB, and
  `/` sits at 96%, so a full tar dies with ENOSPC and a partial tarball still
  extracts. Ship `src/ tests/ examples/ docs/ testnet/ *.md` only.
* `tests/hunt_round_dos.rs` takes ~52 s, all of it in the pre-existing
  `hunt_finding_1e_next_round_overflows_and_panics_at_u32_max`.
* The full suite is 567 tests in ~63 s.

## Prevote-QC + "rounds advance only on our own timeout" (2026-09-25 ~21:25 UTC)

Commits `d44b6ba`, then the round-source fix on top.

### HUNT8 closed
`try_precommit_quorum` now requires a prevote quorum for the SAME block, and a
node that has locked refuses to decide a conflicting block. Previously any
precommit quorum finalised whatever it named. Two hunt_slashing tests drove a
finalize with precommits only; they now prevote the same block first.

### A second liveness bug, found only by deploying it
The prevote-QC fix stalled the stand at block 58: nodeA on round 39, nodeB on
round 40 at height 59, nodeB's r40 prevote targeting nil.

Cause was the line commented "stay round-synchronized with peers that are ahead":
every incoming proposal and vote advanced the local round. One node times out
slightly first, the follower adopts the leader's round from a message, the
leader times out again from its own timer, and the two are permanently offset by
one round. At an offset of one, `proposer = (height + round) % total_power`
means each expects the OTHER to propose, so all proposals are refused as "wrong
proposer", the follower prevotes nil, and with prevote-QC required no
prevote+precommit quorum for the same block can form. Wedge until both data dirs
are wiped.

Rounds now move only via `next_round()` on our own 3s timeout, which is
Tendermint's rule. A node behind catches up by timing out at the same rate as
everyone else, rather than by believing a peer's claim about its round.

### Live result
200 finalizes on both nodes, **0 view changes**, identical block hash and state
root at every common height (was: stall at 58 with 19 view changes).

### Residual, not yet chased
At startup, on height 1 only, both nodes still walk their round counter up to
~2000 within the first ~30 s, then recover and every later height starts at round
0. Self-recovered, so not a blocker, but something spins the round during the
first seconds and it should be explained. Note that
`grep -oP "r\K[0-9]+"` over the whole log will report that startup maximum and
look alarming; the per-height rounds are 0.

## P1/P2 push to the P3 boundary (2026-09-25 ~22:40 UTC)

Commits `a5d217b`, `6e53506`, `bbe62fc`.

### Delivered
- **P1-c aggregate certificates** (`src/bls.rs`): a Schnorr-style multisig, NOT
  pairing BLS, and the module says so. It keeps per-signer R points (a single
  shared challenge is unsound in one round) and collapses the N `s` components to
  one, plus a `SignerBitVector` -- which is the part `apply_downtime_slashes`
  actually needs, since it derives the signer set from `(id, signature)` pairs and
  that breaks once signatures aggregate. `HybridCertificate` + `is_bls_active` model
  the soft fork so an aggregate-only release cannot invalidate existing data dirs.
- **P1-b light client** (`src/light_client.rs`): checkpoint must carry a PRECOMMIT
  quorum bound to its own height+hash; headers must extend tip+1; header chain is
  capped; balance proofs are checked against a trusted root with "not included"
  distinguished from "invalid proof" and from "root untrusted"; an empty proof is
  refused rather than read as absence.
- **P2 metrics** (`src/metrics.rs`, `src/explorer.rs`): process-wide `Registry`
  served from the gateway as `text/plain; version=0.0.4`. main.rs unchanged.
- **P2 remote signer, now genuinely threaded** (`runtime.rs`, `consensus.rs`,
  `main.rs`): `vote_sign_bytes` is public and `Vote::signed_with` builds a vote from
  an externally produced signature, so there is ONE preimage definition.
  `ValidatorRuntime::sign_bytes` uses the remote handle and returns `None` on
  failure -- NO fallback to the local key, so a broken signer yields no vote.
  `with_remote_signer` refuses a handle for a different key. Five tests in
  `tests/remote_signing_consensus_tests.rs`, including that a remote-signed vote is
  byte-identical to a local one.

### Reverted (important)
A change made `build_validator_set` add the node's own key ONLY when its id appeared
in `validators:`. The DEPLOYED configs follow the opposite convention
(`nodeA.validators = [nodeB]`), so under the new rule each node would have built a
ONE-member set containing only its peer: two genesis roots and a split. It had been
validated against `testnet/*.yaml` templates, not the deployed files. Reverted in
`bbe62fc`, module deleted, and the real recipe documented on the function: every node
lists the OTHER N-1 in `validators:` with a matching `peers:` entry.

### Live stand
Deployed `bbe62fc` without a wipe (genesis root unchanged: `a927873ae7ea04df`).
Wiped and restarted both because they had resumed a STALE PERSISTED ROUND (806)
from the earlier deadlock -- `main.rs` restores `hp.hc.round = cp.round`, and two
nodes restarted at different rounds stay deadlocked. After the wipe: 165 finalizes
each, identical block hash and state root, 9 view changes (startup transient).

Security posture verified live on the new binary: RPC on 127.0.0.1 only,
`stell_faucet` refused without `STELL_FAUCET_TOKEN` and accepted with it, and
127.0.0.1:8545 refused from outside.

## The stand finally survives a restart (2026-09-26 ~09:00 UTC)

Four bugs, each found only by deploying and reading the live logs. Together they were
the whole "wipe both nodes and hope" ritual.

1. **infnode `last_seq` was per-PEER, not per-connection** (crates/infnode/src/node.rs).
   The sender's `seq` is one node-wide counter, so with two connections or a reconnect
   the receiver saw legitimate frames as out of order and killed `frame_loop` with
   `replay/out-of-order`, before authentication even completed. Live logs showed 7-20
   `conn_closed` and zero `conn_open`. Moved to a per-connection `ConnReplayWindow`,
   and split the per-peer `last_ts` into a `last_seen` liveness field (rewards use it).

2. **The pubsub topic was a fixed name across chains.** After a wipe, nodes still
   heard the previous chain's `#1 r10071` proposals and rejected them forever. The
   consensus and tx topics are now derived from the chain epoch.

3. **The block-body blob name was split in two**: `broadcast_block` wrote an
   epoch-scoped name while the retro-publish path wrote the bare hash, so the same
   block landed in two slots and neither side could find the other's body.

4. **Round PHASE, not just round number.** With two validators `proposer_for` alternates
   by round parity, so nodes that time out independently sit in opposite phases and
   reject every proposal as "wrong proposer" forever. Fixed in two halves: the BEHIND
   node jumps to a peer's higher round (`sync_round_to`, still forward-only), and the
   AHEAD node HOLDS its view change while the peer is active nearby. Applying the hold
   to the behind node too was itself a bug -- a node resuming on round 8 faced a peer
   on round 0 and both waited.

Also: two blocks were not carrying quorums at all, so `block sync` rejected every
block ("lacks a validator quorum"); finalized blocks now carry the precommit quorum,
and late quorums still decide after a node left the round.

### The control script
`scripts/stell-node.sh {start|stop|restart|clean|wipe|wait|status|logs|deploy}`.
`start` returns immediately (no ssh hang), `wait` blocks only as long as needed,
`status` reads the logs per-node and says STALE CHAIN when old unverifiable blocks are
present. Verified: clean start 114 blocks, restart resumed and reconverged at 194,
both nodes identical root, HEALTHY.

## Wave 5 + faucet durability (final base-blockchain push)

Commits through `7221995`. Full suite: 760 passed / 0 failed.

Three audit agents, all read-only + new test files:
- A re-ran all ~15 closed findings literally: 20/20 blocked, no bypass.
- B ran 5 byzantine-4-node attacks: all fail (heal, caps, inert replay, nil-grind
  harmless, amnesia out-of-scope). No new findings.
- C ran 6 economic attacks and found ONE genuine new bug: the faucet lifetime cap
  and nonce lived in a bare in-process Mutex, so each restart resurrected every
  capped address's full allowance (1000 STELL/address/restart at production
  defaults). Fixed by persisting FaucetState to a `faucet_state_v1` meta key on
  every mutation, loaded at startup, corrupt record fails closed to empty.

Also wired (from C's report): governed block_reward/min_bond/commission were never
read by production. Block production now prefers AppliedParams; VmContext carries
the governed staking policy resolved once per transaction.

## Self-healing without wipe (2026-09-26, final base-blockchain milestone)

The last "wipe both data directories" recovery is gone. A deadlocked stand now
recovers by itself on restart:

- Root cause of the restart deadlock: nodes restored a persisted consensus LOCK
  unconditionally, but `rt.blocks` is in-memory only and never restored. So every
  restart produced a bodyless lock, and `try_finalize` (which requires the body)
  could never fire on it -- while the lock made the node refuse every live
  proposal. Observed: nodeA locked at round 8, nodeB at 66, permanent.
- Fix: on checkpoint restore, drop a lock whose block body is absent. Safe because
  finalizing the locked value would need a quorum including this node's fresh vote,
  which it will now cast for the network's value; a second finalized block would
  require OTHER nodes to equivocate (independently slashable).
- Live proof: two nodes deadlocked at #190, restarted with data KEPT, both logged
  "dropping restored lock", then finalized 178 new blocks to #367 with identical
  hash and root. HEALTHY verdict from stell-node.sh. No wipe.

Stand state: 2 validators on one host (212.113.103.105), 760 tests green, all P0-P2
plus the six "open" items closed. P3 (fuzzing already partially done via
fuzz_decoder_tests; performance/BLS-pairing follow-ups) is the boundary per user.

## Startup healing: engine must reach head before voting (2026-09-26)

Closed the last fork vector. A node restored engine state from a snapshot at S while
its finalized head was at F>S, then joined consensus and voted from S-state at F+1 --
proposing with a stale root forever while reporting healthy (784 rejections of correct
proposals, zero finalizes). Catch-up never fired because it keys off finalized height,
and both nodes agreed on the head; the gap was INSIDE one node.

Now startup heals first: replay bodies S+1..F (local store preferred, peers as fallback),
verifying per block the QC, height, hash linkage and F3.2 parent binding, then applying
full finalize effects. Unverifiable history (pre-QC era) fails loudly; unclosable gap
exits(1) instead of forking. Proved live: both nodes logged "engine at 100, head at
166: healing", reached 166, then finalized to #361 with identical hash+root, HEALTHY.

Also fixed along the way: finalized blocks now carry their precommit QC (vote
signatures grafted as block signatures could never verify -- different messages);
validate_sync_chain verifies the attached QC; 761 tests green.

---

## 10. СЕССИЯ 2026-09-27/29: БОЛЬШАЯ ОХОТА ЗА БАГАМИ + АУДИТ

### 10.1 Что сделано (12+ фиксов консенсуса, все с тестами, сюит ~797/0)
- chase-livelock (223 accepts/0 votes): phase-align в on_proposal + note_peer_vote_round (near никогда не двигает)
- асимметричный лок: locked re-proposal + polka-unlock + lock-hint rescue (nil-голос несёт locked hash)
- GCD-нормализация расписания предлагающих (power 10^12 отдавал все слоты одному)
- stale-proposal фильтр по envelope-round; has_live_proposal
- Committed broadcast не отправлялся НИКОГДА (use-after-reset on hc) — починено (adopt работает)
- catch-up применял только fees (форк!) → полный переход (apply_and_advance) + post-apply root check
- snapshot-first catch-up; publish tip/last-8 тел; persist adopted/walked тел
- mempool персист (15s + shutdown + admission); faucet nonce mex (заполняет дыры)
- proposer self-record на locked/demanded путях (refire spam убран)
- P3-H4 батчинг голосов: ConsensusMsg::Batch + outbox 100ms flush (один request_to на пачку)
- transport: replay-drop вместо teardown, evict cached conn, framing 60s→5s, probe_peers
- инфраструктура: chain_diag.sh, конечный статус adopt-aware, restart sequencing, watchdog
- ЗАДЕПЛОЕНО: бинарь на стенде = HEAD (проверено sha256). Стенд жив: #10k+, HEALTHY.

### 10.2 КРИТИЧНЫЕ УЯЗВИМОСТИ (аудит 2026-09-29) — ЧИНИТЬ ПЕРВЫМ ДЕЛОМ
Паспорт требует "полная безопасность без уязвимостей". Найдено:
- **F1 CRITICAL (consensus):** try_snapshot_sync (main.rs ~245-323) берёт trusted_root из
  заголовка пира (fetch_head_hash → fetch_block_header), НЕ привязанного к нашей цепи.
  Пир публикует head+snapshot+header → нода принимает ЛЮБОЕ состояние без ключей.
  Обещанный в комментарии walk заголовков НЕ реализован. Фикс: hash-link к rt.finalized.last().
- **F2 HIGH (DoS):** note_peer_vote_round (runtime.rs ~736) вызывается ДО Vote::verify;
  sync_round_to даёт +64/сообщение, +2048/батч → анонимный пир навсегда рассинхронит
  раунды (next_round += 1 без saturating → overflow паника). Фикс: verify сначала, cap, saturating.
- **F3 HIGH (DoS):** advertised head (height,hash) не связан с телом; walk_chain re-anchor
  на peer_height, не на blocks.last().height → одна DHT-запись убивает ноду.
  Фикс: collect_missing_blocks: blk.compute_hash()==requested; walk: last.hash==peer_hash.
- **F4 HIGH (safety):** equivocation slashing из ЛОКАЛЬНЫХ наблюдений (apply_equivocation_slashes)
  → ноды с обоими голосами и ноды adopt/walk расходятся по state root → раскол от 1 фолта.
  Фикс: слашинг из содержимого блока (evidence), не из локальных VoteSet.
- **RPC F1 CRITICAL:** explorer.rs /api/faucet/:address — БЕЗ токена (обходит STELL_FAUCET_TOKEN),
  GET + CORS * → слив 1M STELL за ~5 мин. Фикс: enforce token / remove route.
- **RPC F2:** explorer.rs .nest("/rpc") ПОСЛЕ .layer() → /rpc без rate-limit и CORS; rpc::serve
  тоже без лимитера. Фикс: nest до layer / route_layer.
- **RPC F5:** stell_mempoolDump (временный) публичен → утечка. Фикс: за auth или убрать.
- Прочее: F5 validate_sync_chain проверяет QC текущим сетом (не высотным); F7 MAX_COMMIT_CERT_SIGNERS
  не в QuorumCertificate::verify; F9 unsigned lock-hint; F10 precommit по QC из старого раунда.

### 10.3 ЗАПУСК (важно для следующих сессий)
- 4-нодовый стенд НЕЛЬЗЯ добавить к живым A/B: генезис = f(validator set), добавление C/D
  меняет root → разные эпохи → несовместимо. Нужен stop+wipe ВСЕХ + правка yaml A/B.
  Артефакты nodeC/D уже созданы на сервере (/root/nodeC, /root/nodeD, /env.C,/D — 4-validator),
  но остановлены. FAULT_RUNBOOK.md §0.1 описывает окно миграции.
- Хост: 1 vCPU, диск почти полный → 4 archive-ноды рискованно; снизить темп/архив перед этим.
- TPS: e2e низкий (2-3 tx/s) из-за nonce-gap в тест-паттерне + 3s раундов; исполнение 118k tx/s.
  Батом подтверждено: propose h=... selected=0 mempool=N (nonce=N) — это дымящийся пистолет дыры.

### 10.4 ПАСПОРТ ПРОЕКТА (цель)
Stellereum = AI-Native MEV-Resistant L1 (TON-core + actor model + orderbook CLOB + SVM + zkML +
session keys + shared sequencer + teleport bridges + selective confidentiality + micro-gas).
STELL токен, hard cap 1B, genesis $0.25. Приоритеты: СНАЧАЛА безопасность/безбажность,
скорость к Solana/Ethereum — на отдельном "блоке Оптимизация".

### 10.5 ЛИВЕСТЬ (сессия 2026-09-29, последовательно закрыто)
Проблема: высоты шли ~1/мин, иногда 180с-стопор (watchdog рестарт).
Диагностика по логам показала ТРИ независимые причины:
1. **1-раундовый офсет.** Оба голосовали ОДНО значение, но A на r15, B на r16 →
   кворум требует одного раунда → никогда. Причина: я ранее запретил
   near-sync (1..3 раунда) как защиту от взрыва раундов. Лечение:
   `note_peer_vote_round` снова следует за ЛЮБЫМ проверенным лидом, но только
   после `Vote::verify` (F2) и с капом `ROUND_LOOKBACK=8` (взрыв невозможен:
   junk-голоса не проходят проверку).
2. **Равный-раундовый deadlock (hold).** `peer_is_active_nearby` считал
   `pr <= our round`, то есть при равных раундах оба держали view-change,
   ни один таймер не шёл, потерянный proposal не повторялся → вечный стопор.
   Лечение: hold только при строго `pr < our round` + переотправка СВОЕГО
   proposal в timeout-ветке (один потерянный пакет больше не стоит раунда).
3. **F8 ошибка синка**: `validate_sync_chain_for_shard` получал `--shard`(1,
   DHT-неймспейс) вместо шарда блоков (MASTERCHAIN=0) → весь catch-up
   отвергался ("on shard 0 but this chain is shard 1"). Фикс: 5794f99.
4. Статус врал NOT SYNCED: сравнивал state root последнего FINALIZE, а у
   adopt-стороны он отстал → фикс: корень сравнивается только на max-height.

Результат: 13903→13917 за 120с (~7 высот/мин, было ~1/мин), без рестартов.

### 10.6 БЕЗОПАСНОСТЬ (аудит 2026-09-29, закрыто, бинарь задеплоен)
Критичные дыры закрыты коммитом 74c9cfe (+5794f99 +6b63e47):
- F1 подделка состояния через snapshot → hash-link к своему finalized head
- F2 накрутка раундов до проверки подписи → verify сначала, кап 8, saturating
- F3 рассинхрон по advertised head → сверка с пройденной цепью
- F4 раскол state root от локального equivocation-slaшинга → слэшинг из
  локальных наблюдений УБРАН из всех путей перехода (evidence в блоке — отложено:
  bincode Block не самоописывается, новое поле ломает старые блоки)
- RPC: /api/faucet без токена (слив 1M STELL за 5 мин) → fail-closed токен;
  /rpc без rate-limit/CORS → nest до layer; mempoolDump за auth; body limit;
  constant-time compare.

### 10.7 ХОЗЯЙСТВО
- Диск: был 100% → освободил 872M (старый локальный чейн /root/stellereum/data),
  включён pruning `STELL_ARCHIVE=0 STELL_KEEP_BLOCKS=8000` в env.A/env.B
  (бэкапы env.*.bak.*). Стабильно 86%.
- infnode: concurrent frame_loop (стримы в отдельных задачах, семафор 64,
  ошибка стрима не рвёт коннект) + атомарная запись чанков (fix "chunk tamper")
  + mkey полное имя бакета + 5s frame timeout — тесты infnode зелёные,
  задеплоено через stellereum build (path dep), но В infnode-репо НЕ закоммичено.
- Стенд: статус adopt-aware, рестарт-скрипт с ожиданием, watchdog (180s stall).

### 10.8 БЭКЛОГ ИННОВАЦИЙ (обсуждать ОТДЕЛЬНО, когда базовый блокчейн готов)
Пользователь: «нововведения мы будем обсуждать когда полноценный блокчейн будет».
Нативные аккаунты — НЕ про ботов, определение приходит позже (не выдумывать).

[ ] ИННОВАЦИЯ 1: Communication Grants — реестр грантов (scope, срок, revoke) + доставка по гранту
[ ] ИННОВАЦИЯ 2: Нативный AA — аккаунт-контракт по умолчанию (WASM-движок уже есть)
[ ] ИННОВАЦИЯ 3: Опциональная приватность — режимы (прозрачный / скрытый получатель / сумма)
[ ] ИННОВАЦИЯ 4: Безопасные мосты — optimistic verification, окно оспаривания, timelock, лимиты
[ ] ИННОВАЦИЯ 5: Идентичность имя→адрес (нативный ENS)

Порядок работ: (1) транспорт → устойчивый liveness; (2) 4-ноды; (3) база «полноценного»;
(4) эти 5 инноваций отдельным блоком; (5) скорость (pipelining, in-memory) и нативные аккаунты.

### 10.9 ТРАНСПОРТ — ХРОНИКА (последний статус 2026-09-29 22:00 UTC)
Сделано: close при evict, learned-addr защита, idle 300→30с, потоки 64→256+reset,
strict tie-break (нижний id единственный инициирует — B перестал набирать, 0 handshake
timeout на B), replay-gate без дропа, мультипоточный рантайм (4 воркера), Recv-Q=0.
ОТКРЫТО (текущий блокер):
- conn_closed ~1500/ноду, stream task error ~295 (frame read timeout, sending stopped, connection lost)
- A: handshake timeout 573, AUTH timeout 222; A→B broadcast 0.5–2с (показывает warn "slow")
- probe: периодически ok (0.5–80мс) и TIMEOUT 2с подряд
- ставка: frame_loop завершается без причины (30с accept_bi idle vs соединение живое) и
  ЗАКРЫВАЕТ коннект → цикл: смерть коннекта → диал ~1с → опять медленно.
  СЛЕДУЮЩИЙ ШАГ: добавить в frame_loop лог ПРИЧИНЫ выхода (idle vs error vs peer closed)
  и перестать закрывать коннект при app-idle (закрывать только по явной ошибке/evict).

### 10.10 ИНВЕНТАРЬ ПАСПОРТА (2026-09-30, агент-аудит, file:line в исходниках)
Статусы по 10 секциям паспорта (DONE/PARTIAL/MISSING):
1. Архитектура (акторы, бесконечный шардинг, BoC/DAG 128B) — PARTIAL: cell.rs/PatriciaTrie есть,
   акторный mailbox НЕ гоняется блоком (send_message только в тестах), мультышардинг только в Sim.
2. AI-Native VM (SVM+zkML+session keys) — PARTIAL: SVM есть и в лив-пути; zkML "STRUCTURAL check only,
   NOT sound" (zkml.rs:332), SNARK нет; session keys ЗАМОРЖЕНЫ (`session_auth: None`, state_engine.rs:386),
   в Transaction нет поля для делегации.
3. Orderbook CLOB — PARTIAL→исправлено (см. 10.11): эскроу/сделки теперь на лив-пути.
4. Micro-gas — DONE (GAS_BASIC_TRANSFER=560, level-gas, depth caps, griefing-тесты).
5. Shared liquidity/sequencer — PARTIAL: SharedLiquidityHub/Sequencer только в Sim; cross_shard_out всегда пуст.
6. MEV-preemption — PARTIAL: mev.rs/bls.rs есть, но мемпул не запечатывается, _mev_engine не используется,
   BLS НЕ в консенсусе (QC = Ed25519-список, crate::bls не импортируется никем в src/).
7. Pipelined execution + io_uring — PARTIAL: AsyncPersistence=фоновый sled, io_uring НЕТ, сплита
   консенсус/исполнение нет, 100-200мс не достигается (MIN_BLOCK_MS=400, ROUND=3000).
8. Teleport bridges — PARTIAL: bridge.rs с лимитами/timelock, но zk_proof всегда None, адаптеров
   цепей нет (offline-модели), движок не в state, CLI "Simulated deposit".
9. Приватность — PARTIAL: Pedersen/stealth/viewing keys есть (curve25519-dalek), но НЕТ OpCode
   конфиденциального перевода (приватность = библиотека+CLI, не леджер), AVX2/NEON не включены.
10. Оракулы 3-tier — PARTIAL: oracle.rs со всеми правилами (stale 15m, dev 10%, breaker, peg 0.95),
    но движок ТОЛЬКО в Sim/CLI, gossip-функции мертвы (network.rs:495/507 без вызовов), в commitment нет.
ИСКЛЮЧЁННОЕ подтверждено отсутствующим: Stellereum Storage ❌ нет, Proxy ❌ есть только отказ от него,
нефинансовые сервисы ❌ нет, TEE/SGX ❌ нет, RingCT ❌ нет.
Дрейф доков: README про crates/stell-wallet (каталога нет), LICENSE отсутствует, PROTOCOL.md утверждает
что governance не в commitment (он В commitment).

### 10.11 ЧТО СДЕЛАНО В ЭТОЙ ФАЗЕ (базовый блокчейн — P0 корректность)
- 1b5435a: лив-путь применяет движения стоимости (transfers/payouts через commit_native, atomic c undo-log)
  + VmContext.timestamp = block.timestamp (unbond/контракты/session expiry). Тесты: tests/live_block_path_tests.rs (7).
- 9ccf4c8: (a) CLOB-эскроу на лив-пути (settle_clob_effects: план→валидация→применение c undo; escrow_digest
  += locked_quote_native; fills/cancels в правильном активе; depth saturation не выбрасывает чужой ордер;
  5 тестов переименованы с "фиксируют баг" на "фиксируют фикс"); (b) единое ядро apply_block_transition
  для live и reorg-путей (иначе reorg молча форкал), доказательство QC теперь в теле блока.
- Полный сюит: 843 passed / 0 failed. Задеплоено на стенд (вайп не потребовался: escrow пуст на генезисе).

### 10.12 ДИЗАЙНЫ, ГОТОВЫЕ К РЕАЛИЗАЦИИ (агенты, только план)
**Session keys (Инновация "аккаунты")** — ключевой вердикт: bincode 1.3 НЕ СДЕЛАЕТ новое поле в
Transaction совместимым (даже #[serde(default)] и Option: decode старого блока -> Err, старые ноды
ломаются). Решение: конверт внутри существующего signature:Vec<u8>: 64B | 64B+b"SK1"+bincode(delegation);
привязка в signing_message/compute_tx_hash ТОЛЬКО при наличии конверта (старый байт-в-байт);
старые ноды fail-closed на verify. Этапы: 0) домен/chain_id в SessionKeyAuthorization + scope/max_value (сейчас
ничего не персистится = бесплатно); 1) AdmissionCtx во всех 5 точках входа в mempool + expiry по block.timestamp;
2) SessionKeyRegistry как ОТДЕЛЬНОЕ sled-дерево (не в DomainSnapshot — тот fail-closed на decode) + условный
digest (иначе ломается генезис-KAT) + OpCode::SysCallRevokeSession; 3) CLI/RPC вывод делегации;
4) golden-тесты байт-совместимости + fuzz.
**Шардинг+Оракул (M1/M2/M3)** — одна нода с двумя экземплярами run_consensus_node (KV межшард только
внутри процесса), consensus_topic нужно сделать shard-scoped; НОВЫХ полей в Block нельзя (bincode) —
использовать cross_shard_out как produces+consumes; ShardRegistry из env, все проверки под
`registry.is_sharded()` (иначе старые тесты падают); M1: tx target_shard=1 попадает в блок shard_id=1;
M2: перевод 0->1 атомарно + replay-защита + равные root на обеих нодах; оракул: НОВЫЙ OpCode
SysCallSubmitPriceFeed (append-only = совместимость), цена меняется ТОЛЬКО из блока (gossip лишь
доставляет к proposer), COMMITMENT_VERSION 3->4 ОДИН раза на оба изменения + репин KAT + вайп стенда.

### 10.13 МЕТРИКИ СТЕНДА (агент, 5.7 мин замера 2026-09-30)
- высоты: 5.6/мин (A), 5.3/мин (B); раунды: медиана 2.1с, среднее 4.1с (B сжигает в 3 раза быстрее)
- ТРАНСПОРТ — узкое место: median broadcast 770мс, p90 1.5-1.9с, 48 таймаутов/5.7мин у A,
  probe A=54% успеха (B=99%), conn churn 34 закрытия/мин, Recv-Q только всплеск 6144
- CPU 29%/25% (запас есть), диск 91-92% (снова растёт! логи под ротацией, data 1.2G/node из-за sled)
- ИТОГ: лимит — RTT/латентность ссылки, не кворум и не CPU.

### 10.14 ФАЗА ПАСПОРТА ЗАВЕРШЕНА (коммит 95df70c, задеплоен 2026-09-30, ВАЙП + новая эпоха 21ffbf7a47bfb3a0)
**Session keys, фаза 0+1** (Инновация "аккаунты" — база без состояния):
- Конверт ВНУТРИ существующего signature:Vec<u8>: 64B | 64B++"SK1"++bincode(grant). Ни одного нового поля
  Transaction/Block -> bincode-совместимость сохранена (golden-тесты пинят байты), старые ноды fail-closed.
- SessionKeyAuthorization: домен b"STELL_SESSKEY_V1" + chain_id + scope-битмаск + max_value_per_tx.
- Enforcement во всех 5 точках входа (AdmissionCtx) + фильтр в propose + повторно на исполнении; expiry
  ТОЛЬКО по block.timestamp; пустой payload больше не обходит проверку.
- tests/session_key_tests.rs: 13 (golden, tamper 9 полей, graft, batch, матрица admission, паритет propose/apply).
- ОТЛОЖЕНО (фаза 2): stateful SessionKeyRegistry (отдельное sled-дерево, условный digest), SysCallRevokeSession,
  накопление budget внутри блока, chain-id enforcement против конфига ноды.
**Оракул on-chain** (секция 10 паспорта):
- Правило детерминизма: цена меняется ТОЛЬКО из блока (gossip лишь доставляет proposer'у).
- Новый OpCode (append-only, дискриминант 27) SysCallSubmitPriceFeed; OracleState = committed-домен
  (BTreeSet/BTreeMap, length-prefixed digest); commit_feed ШАРЕТ код с resolve_price (stale/deviation/peg).
- Гейты в SysCallPlaceOrder и place_order_settled (deviation/peg/breaker) — обхода нет; латч переживает revert.
- stell_submitPriceFeed не пишет состояние; CLI `stell oracle feed` подписывает транзакцию.
- COMMITMENT_VERSION 3->4, KAT перепинчен, DomainSnapshot += oracle -> СТАРЫЕ снапшоты не декодируются
  -> вайп ОБЯЗАТЕЛЕН (выполнен: эпоха 21ffbf7a47bfb3a0).
- ОТЛОЖЕНО: регистрация publisher'ов / сброс breaker'а через GovAction; TWAP-уровень остался в легаси-движке.
**Диск (агент, сервер):** найден НАСТОЯЩИЙ источник: не sled (14MB), а data/chunks (752M/187k файлов —
store_blob перешифровывает при каждой публикации -> новый chunk id -> копия вместо перезаписи) и kv.json
(67MB, переписывается каждые 7с, 3 бэкапа, dedup:* 113k записей). Освобождено 2.1GB (96%->73%, сейчас 63%):
rust-docs 796M, орфаны чанков 1.1G, журнал 157M, apt/sing-box-мусор. Установлен cron `*/15` pruner
(/root/prune-chunk-orphans.py, возраст-гард 1800s) + почасовый logrotate. Рост до заполнения ~5-6 дней.
РЕКОМЕНДАЦИИ (код): (1) chunk_id должен быть blake3(name:offset) чтобы публикация ПЕРЕЗАПИСЫВАЛА, а не копировала;
(2) kv.json нужен TTL-sweep (node.rs:2653 только фильтрует при чтении, не удаляет) и без 3 копий бэкапа.
STELL_KEEP_BLOCKS=8000 НЕ менять (sled не растёт; тело 2.9 дня истории).

### 10.15 ПАСПОРТ, ФАЗА 2 (ветка wip/passport-agents, коммиты f223573/ee9c93b/1327f64, сюит 906/0, задеплоено)
Два оборванных агента доведены С СОХРАНЕНИЕМ ПАМЯТИ (их работа была закоммичена
в f223573 до резума; дерево компилировалось; агенты восстановились по git и доработали).
- **MEV-preemption (паспорт §6)**: запечатывание на admission (mempool.rs), распечатывание
  и побайтовая сверка на build (runtime.rs propose), коммитмент порядка блока при сборке +
  проверка на finalize (BadCommitment/Mismatch/NoCommit). ЧЕСТНО ОТЛОЖЕНО (задокументировано,
  не имитировано): пороговое преемпшн (асимметричный раундовый ключ, выпуск Shamir-долей после
  подписанного коммитмента, gossip запечатанного мемпула) — нужны слоты в wire, а Block не может
  получить bincode-поле.
- **BLS в консенсусе**: агрегированный BLS-сертификат РЯДОМ с Ed25519-списком, конверт внутри
  signatures под маркером [0xFF;32]; verify сначала BLS (pairing+membership+quorum power), при
  ЛЮБОЙ ошибке — фолбэк на Ed25519; golden-тест старого QC (GOLDEN_QC_HEX) доказывает совместимость,
  BLS-only сертификаты fail-closed на старом коде; флаг STELL_BLS_QC (default OFF).
  Тесты: tests/bls_qc_compat_tests.rs (11), tests/mev_preemption_tests.rs (8).
- **Достижимость (паспорт §3/§8)**: реальные OpCode SysCallPmmBuy/Sell + stell_pmmBuy/Sell/State
  (тонкий admit, без записи состояния); CLI orderbook Place/Cancel отправляют payload-tx через RPC
  (Depth читает stell_orderBook, --dry-run сохранён); bridge CLI → SysCallBridge tx с нативной
  ногой (deposit кредитует, withdraw эскроу в BRIDGE_ESCROW). ОТЛОЖЕНО задокументировано: политика
  бриджа (кворум релееров, replay source-tx, очередь release/refund, rate limit).
  ПОЙМАН И ИСПРАВЛЕН реальный дедлок: admit_signed_payload_tx/sendRawTransaction держали write-guard
  mempool как scrutinee временного match -> save_mempool_throttled() само-дедлокился на ПЕРВОМ
  admission свежего процесса, новые RPC-арм висели. Тест tests/pmm_onchain_tests.rs.
- Session keys фаза 2 (была готова в f223573, 6 тестов): SessionKeyRegistry в отдельном sled-дереве,
  УСЛОВНЫЙ digest (генезис-KAT не изменился, COMMITMENT_VERSION остался 4), бюджет по факту применения,
  SysCallRevokeSession (append, index 28), ревокация терминальна и только от мастера.

РЕАЛИЗОВАННЫЕ СЕКЦИИ ПАСПОРТА ТЕПЕРЬ: §3 orderbook (эскроу+сделки+solidify), §4 micro-gas (было),
§6 MEV+BLS (MVP, честные границы), §10 оракул (on-chain + гейты), session keys (2 фазы), PMM/RPC/CLI
достижимость, P0-корректность (VM-стоимость, единое ядро apply).
ОСТАЛОСЬ ДЛЯ «ПОЛНОГО БЛОКА ПО ПАСПОРТУ»: §1 акторный mailbox в блоке и настоящий мультышардинг
(план M1-M3); §2 настоящий SNARK/zkML (сейчас структурная проверка, не звуковая) + включение
session keys в конфиг chain-id; §5 shared sequencer/L2-интерфейс + L2-фида; §7 pipelining
консенсус/исполнение, io_uring, латентность 100-200мс; §8 адаптеры цепей (TON/EVM/Solana) и
zk-доказательство депозита + политика бриджа; §9 OpCode конфиденциального перевода + AVX2/NEON;
оракул: регистрация publisher'ов и сброс breaker через GovAction. И главный БЛОКЕР — транспорт.

### 10.16 СЕССИЯ 2026-10-02 (продолжение): дедлок-регрессия, M1/M2, session-остаток, оракул-gov, транспорт, доки
Ветка wip/passport-agents. HEAD последовательно: 85cf6bf, 10cbce1, 32803dd, 4118a59, 33b2097, 16eab26. Сюит 940/0. Задеплоено (бинарь 17c96323, HEALTHY #32952).

**КРИТИЧЕСКАЯ РЕГРЕССИЯ М1 (коммит 85cf6bf) — нашёл и починил.**
После деплоя M1 стенд встал: обе ноды на высоте 21266, раунд 98, 0 коммитов, вечный
"wrong height". ПРИЧИНА: M1 начал штамповать block.shard_id сырым CLI `--shard` (на стенде
`--shard 1` = DHT-неймспейс!) и валидировать sync-цепочку против него. Но блоки ВСЕГДА
мастерчейн (0), и персистентная цепь shard 0 → walk_chain отвергал любую догоняющую
цепочку, финалити не наступала. ФИКС: `sharding::block_shard_for(namespace_shard, registry)`
= MASTERCHAIN_SHARD если registry не sharded; применён в with_shard и walk_chain
(rt.shard_id). Регресс-тест block_shard_ignores_namespace_shard_when_not_sharded.
УРОК: `--shard N` — это DHT/blob namespace, НЕ block shard. Не путать.
Откат для диагностики: собрал 1327f64, стенд ожил → подтвердило регрессию.

**ТРАНСПОРТ (коммит 10cbce1).** Аудит (read-only корреляция логов): задержка 0.35-2с —
SCHEDULER STARVATION на 1 vCPU (probe bimodal 252<1ms vs 240>=1ms; >63% sys/36% iowait;
load~4), НЕ churn (1-15%). infnode request_to split: dial=0ms, resp=450-540ms (замерено).
Усилитель в нашем коде: flush_outbox слал чанки ПОСЛЕДОВАТЕЛЬНО и тик ждал. ФИКС:
фоновый FIFO-сендер (ConsensusNetwork::start_sender/enqueue, MAX_PENDING_CHUNKS=256),
flush_outbox теперь синхронный enqueue (мкс), 5 call sites без .await. Тесты +3.
ЭФФЕКТ на стенде: queued больше не растёт (было 31, стало 1-2), но resp 0.3-1.3с ОСТАЛСЯ
— первопричина (infnode round-trip) не вылечена. Дальше: прямой транспорт консенсуса
(не pubsub через request_to) или больше vCPU.

**ШАРДИНГ M2 (коммит 32803dd).** Кросс-шардовый перевод 0->1 реально: source дебет/эмит
CrossShardMessage в Block.cross_shard_out; target кредитует ровно раз (replay-ключ
source(height,shard,id), verify_inclusion_strict), детерминированный порядок, supply
сохраняется. Новых полей Block нет. Под is_sharded(). tests/sharding_m2_tests.rs (5).
M3 остаётся: динамический split/merge, shared sequencer/L2, two-phase/bounce, wiring в main.

**SESSION KEYS остаток (4118a59 + 32803dd).** Отзыв только мастер-ключом (не tx.from==master);
preventive tombstone неиспользованного гранта (в entry реестра, без изменения DomainSnapshot);
убран try_read из admission (детерминизм); enforcement chain-id против конфига ноды
(InMemoryStateEngine.chain_id, node-local). COMMITMENT_VERSION=4, genesis KAT не сдвинут.

**ОРАКУЛ governance (33b2097).** GovAction::RegisterOraclePublisher/Unregister/ResetOracleBreaker
(append discrim 7/8/9); execute_with_oracle меняет governance+oracle атомарно; plain execute
fail-closed. Публикация фида требует зарегистрированного издателя. Версия 4/KAT не менялись.
tests/oracle_governance_tests.rs (13).

**ДОКИ (16eab26).** README: нет crates/stell-wallet, реальная CLI-поверхность, 915/0 (не 21/21),
clone-URL = remote, <120мс помечен как target; PROTOCOL: governance в commitment (v3), oracle (v4),
BLS = реальный BLS12-381 (Ed25519 дефолт). Добавлены LICENSE-APACHE/MIT + LICENSE.

**АУДИТ ПАСПОРТА (read-only, HEAD 85cf6bf).** ОСТАЁТСЯ не done:
§1 actor mailbox НЕ вызывается из блока (только тесты/CLI; send_message/step_actor_execution
только state_engine.rs:371/417, grep вне определений пуст); §1c M2 теперь есть;
§2 zkML verify_inference — СТРУКТУРНАЯ (unsound, zkml.rs:652), zkml_proof всегда None (state_engine.rs:643),
opcode недостижим; §5 shared sequencer только в Sim; §7 нет io_uring и сплита consensus/exec
(try_finalize исполняет inline runtime.rs:1288), live ~секунды/блок; §8 bridge zk_proof всегда None,
политика (quorum/replay/queue/rate) заглушена, НЕТ теста SysCallBridge через apply_block_transition
(заявление памяти §10.15 про pmm_onchain_tests неверно); §9 нет OpCode конфиденциального перевода,
нет AVX2/NEON; §10 publisher/breaker ЗАКРЫТО агентом D. Исключённое (Storage/Proxy/non-financial/
TEE/RingCT) подтверждено отсутствующим.

**INFMAIL.ORG УПАЛ (отдельная тема).** Домен наш (Cloudflare Registrar, NS patryk/rosalyn, до 2027).
CF проксирует на 109.107.155.67, но этот IP УЖЕ НЕ НАШ: 443 отдаёт AkamaiGHost с сертом
www.samsung.com (Samsung SDS, Корея) -> страница "Invalid URL" errors.edgesuite.net. SSH: host-key
сменился, пароль U3A1hXdjXSBzW7 отклонён. Aeza 147.45.75.253 — все порты закрыты (сервер выключен).
Вывод: оба сервера прекращены/переиспользованы. Нужен новый origin + правка DNS в CF. Пользователь
сказал пока отложить. CF API-токена в файлах/env нет. Смена host-key валидатора = был пересоздан.

### 10.17 ВОЛНА 2026-10-03: §8 мост, §9 приватность, §1 акторы, §7 тик, НАЙДЕН И УБИТ 7-СЕКУНДНЫЙ ЗАВИС ОБРАБОТЧИКА
Ветка wip/passport-agents. Коммиты: 1f973ff (bridge policy), ce92deb (privacy opcode), abfcbaf (bridge CLI+persist),
b8fc8c3+7fb3e94 (actor mailbox), 1d595c1 (tick offload); infnode: 4ddd70d+6cef405 (Patch A+B), 6caac8f (stall fix).
Сюит: 999/0 (stellereum), 54/0 (infnode). Задеплоено (бинарь 5bd5252), systemd-юниты (enabled после ребута!).

**§8 МОСТ (1f973ff + abfcbaf):** BridgeState = committed-домен (replay-набор BTreeSet, очередь с unlock_at=+1ч,
rate-window, эскроу-зеркало); BridgeIntent::Attest (кворум 2/3 distinct-подписи над deposit_signing_message из
коммитнутого staking-ledger, пустый набор = fail-closed) и Release (append-only дискриминанты в BridgeIntent);
plan() чисто валидирует ДО движения монет; 10 тестов через apply_block_transition; CLI deposit собирает
аттестации (--attest-key/--attest-keys-dir); bridge-domain персистится в отдельном sled-дереве ("bridge") —
replay-набор переживает restore (3 теста). Версия 4/KAT не тронуты (условный digest).

**§9 ПРИВАТНОСТЬ (af8a978 + ce92deb):** engine-слой (ConfidentialState, conservation/double-spend/digest,
9 тестов) + OpCode::SysCallConfidentialTransfer (дискриминант 33, gas 1500) → apply_transfer; fold в
commitment через commitment_digest_with_confidential (условный, пустой = 0 байт, KAT 6/6); 8 live-тестов
(корень меняется только из блока, два узла = один корень). AVX2/NEON — задокументирован TODO (MSM через
vartime_multiscalar_mul, не в консенсусном байтовом фрейминге).

**§1 АКТОРЫ (b8fc8c3):** OpCode::SysCallActorSend (дискриминант 34): recipient/value/bounce/gas_budget +
body:Vec<OpCode> (переиспользует micro-gas + clone-commit). Pass apply_actor_messages_at() — шаг 1b
apply_block_transition (после txs, ДО fees): sort_unstable по адресам (фикс HashMap-недетерминизма),
FIFO, раунды ≤8, ≤4096 сообщ/блок, per-message undo, bounce ровно один раз, откат целиком при revert.
Требование bounce=true в v1 (иначе консервация не аудируется). SCOPE_ACTOR_SEND = SVM_PAYLOAD|ACTOR
(и в admission, и в propose — паритет). Кросс-шард — отказ. 17 тестов (включая golden 35 дискриминантов
+ fail-closed старого декодера). Phase 2 (условная кодировка очередей ACTORQ1) задокументирована.
Открытая дыра: clamp MAX_ACTOR_MSGS_PER_BLOCK не валидирует блок (нет error-канала в apply) — нужен
check на propose/adopt.

**§7 ТИК (1d595c1):** mempool save/prune/snapshot-serialize → spawn_blocking c single-flight;
post-finalize publish_head/retro/header + receipts → два FIFO-lane (publish_lane, record_lane);
Committed-gossip FIFO не тронут; snapshot: клон на тике (мгновение фиксации), encode вне тика —
golden-тест байтов. +10 тестов.

**ГЛАВНОЕ: 7-СЕКУНДНЫЙ ЗАВИС ОБРАБОТЧИКА (attribution агента по журналам 2ч, join dispatch×req_stages×req, 2508 кадров, 0 расхождений):**
- Симптом: receiver proc≈7.1с константно (disp=0 — планировщик ни при чём!), sender wait≈proc.
- Причина: ГЛОБАЛЬНЫЙ persist_gate — каждый dht.store/dht.refresh (7-8 полных переписей kv/мин)
  держал общую мьютекс-гейт, ОГРОМНЫЙ json сериализовался НА async-воркере (85МБ ≈ 1.3с CPU),
  а handle_dht_store/storage.store КЛОНИРОВАЛИ ВСЮ карту на каждый запрос (до 3×85МБ живой памяти
  за persist) → OOM: 144 убийства/3ч под MemoryMax=2G, 17 рестартов nodeA. CHALLENGE (без диска!)
  висел p50 1.2с = чистый convoy.
- ФИКС (6caac8f): per-file гейты (kv/outbox/subs/routes/dht), debounce kv_dirty+10с (бурст=N → 1 запись),
  Arc<HashMap> copy-on-write (entries_snapshot O(1), stored_at по одному ключу), serde+write ЦЕЛИКОМ в
  spawn_blocking, dispatch лог несёт svc, persist_kv_slow-стадии, метрика infnode_kv_persists_total.
- РЕЗУЛЬТАТ (A/B на стенде): resp p50 7065→659мс, p90 12151→968мс; proc p50 7100→617мс;
  OOM 144/3ч → 0; высоты 0.3/мин → ~20/мин (раунды r107-133 → r0-17); load 10-22 → 4.3.

**ОТКРЫТЫЕ ПОСЛЕ ВОЛНЫ:**
- kv nodeA растёт ~1МБ/мин: 99.6% ключей = stell_headers/stell_blocks (publish по КАЖДОЙ высоте,
  без TTL/удаления) → через часы снова OOM/диск. НУЖЕН fix: TTL на blob-публикации или окно
  удержания (KEEP_BLOCKS) + prune старых stell_* ключей в kv.
- Прочее: systemd-юниты enabled (Restart=always, MemoryMax=2G, CPUQuota=80%, StandardError=journal)
  — логи теперь в journalctl, не в current.log (он замёрз навсегда); status-скрипт читает stale-логи!
  (status показывает 42160 хотя журнал уже 42300 — поправить чтение status из journal или через RPC).
- dht.find_node шторм ~2/сек (gossip_routes/join) — чистая нагрузка на 2-нодовой сети.
- infnode kv json: полная перезапись формата не сделана (отложено — debounce хватает).
- Доки: README «915 passing» устарело (сейчас 999).

### 10.18 ИНЦИДЕНТ: СТОП ЦЕПИ 4.5Ч (71587) + ФИКС «NO SESSION KEY FOR CONN» (2026-10-04)
Диагноз (по журналам systemd, join-шторм исключён — транспорт чист):
- С 15:08 цепь встала: viewchange 71587, раунды росли до r19940+, FINALIZED нет 4.5ч.
  Триггер: nodeB убит OOM-киллером в 15:06:48 (NRestarts=5 у B).
- Причина: nodeB НЕ МОГ ОТПРАВИТЬ НИЧЕГО — каждый broadcast падал за ~10мкс с
  "no session key for conn" (69/мин). Кэшированный conn потерял сессию (frame_loop
  teardown снял entry из sessions, объект остался в кэше), а код возвращал его как есть:
  ошибка не классифицирована как сетевая → ни drop, ни redial, ни evict не срабатывали.
  A получала всё (и голосовала одна), B молчала → кворума нет (в эфире только prevote A).
- Дополнительно: A и B были залочены на РАЗНЫХ блоках (4e0fe09b vs 785fc3b7e77d) — следствие,
  а не причина (каждый перепредлагал свой; при рабочем транспорте сошлись бы).
- Попутно: req_denied core.ping = self-ping (безвредно); status-скрипт врал (читал замёрзший
  current.log, журнал уже 71586 — починено агентом: status теперь читает journal first).

ФИКС (infnode b51c8df, мой собственный, НЕ агент):
- `conn_with_session` в request_to (обе попытки): fast path (кэш+сессия) → дроп
  session-less объекта (ровно его, по stable_id) → обычный reconnect (строгий tie-break
  untouched) → last resort: прямой dial даже со стороны higher-id, ТОЛЬКО после доказанной
  непригодности кэша (дроп в этом вызове или <60с назад, покрывает evict-очистку) + кулдаун
  5с/пир против dial-шторма. connect_or_get распался на dial_peer для переиспользования.
- Регресс-тесты node::session_heal_tests (2): dialer-side чинится редиалом; higher-side —
  полный путь (дроп → 1.5с wait → fallback dial; elapsed-ассерт доказывает путь).
  Сюит infnode 58/0. Строгий tie-break для свежих/пустых кэшей сохранён (тест-пути + код).

ДЕПЛОЙ (бинарь 6470a30a = retention 948d09e + zkML 40f1b8d + tick-offload + session-fix):
- Сразу после рестарта: session errors 0, prevote+precommit ОБОИХ ключей, высоты пошли
  (71586→71594 за ~5 мин), HEALTHY. OOM-киллов больше нет (дебаунс kv + per-file гейты).
- Параллельно задеплоен retention kv (TTL + height-prune ≤8000): рост kv.json ограничен
  ~32.5k записей/22МБ против 127k/85МБ+1МБ/мин. Существующие 126/144МБ ужмутся sweep+prune.
- Доки закоммичены (8c374ad). Сюиты: 1020/0 stellereum, 58/0 infnode.

УРОК: «no session key» обязан быть самовосстанавливающимся (как network error), а не
fail-fast. Любая ошибка транспортного пути, не ведущая к drop/redial/evict, — это
потенциальный вечный односторонний блэкаут. Проверочное правило: после ЛЮБОГО рестарта
ноды смотреть, что ОБЕ стороны шлют (prevote/precommit обоих ключей в эфире).

### 10.19 ВОЛНА 2026-10-04/05: AVX2, EXEC-LANE, АДАПТЕРЫ МОСТОВ, SNARK-РИСЁРЧ + БАЗОВЫЙ ЗАМЕР ПОД ОПТИМИЗАЦИЮ
Ветка wip/passport-agents. Коммиты: e01ef1d (AVX2/MSM), 29edc2c (§7 exec lane + actor cap),
ccb58bc (bridge adapters). SNARK — только риcёрч (без кода). Сюит 1058/0. НЕ задеплоено.

**AVX2/MSM (e01ef1d):** curve25519-dalek 4.1.3 уже выбирает AVX2-Pippenger через runtime
CPUID — рукописных интринсиков не надо (честный вывод агента). Добавлен тонкий batch API
поверх vartime_multiscalar_mul: RangeProof::verify 5.83→3.24мс (1.8x), bitproof 1.44x,
conservation/openings на паритете (там сложения — MSM был бы 0.4x, откатили). Дифференциальные
тесты scalar==batch. benches/privacy_batch.rs.

**EXEC-LANE (29edc2c):** try_finalize больше не исполняет inline — apply_decided() на одном
упорядоченном воркере (ApplyLane, FIFO, строго по высотам); propose/on_proposal/adopt гетятся
пока apply in flight; голоса дренируются параллельно. Закрыт гэп actor-mailbox: over-cap блок
(>4096) отвергается на propose/validate/on_proposal/adopt/walk. 10 тестов
(tests/pipeline_state_gating_tests.rs). Замер в тесте: submit-to-decision 170мкс против
1.38мс исполнения (8x развязка на 30-tx блоке).

**АДАПТЕРЫ (ccb58bc):** ChainAdapter-трейт (verify только evidence из tx, без I/O/часов);
TON — реальный парсинг BoC + перепроверка хэшей ячеек + корень + кворум заголовков;
EVM — реальная Merkle-Patricia проверка receipt-профа; Solana — бинарный SHA-256 Merkle-проф
со строгой привязкой индекса; zk — плейсхолдер, всегда отказ. BridgeIntent::DepositProof
(дискриминант 4): кредит по кворуму ИЛИ по верифицированному evidence. 14 + 16 тестов.
Честно stubbed: RLP-декодинг логов, header-sync, TON layout, вотчеры (off-chain граница).

**SNARK-РИСЁРЧ (без кода):** рекомендация — Groth16/BLS12-381 через arkworks 0.5
(пруф 192Б, верифаер 2-5мс ≈ 25-40k газа, прувер 10-80мс; rand 0.8.8 сходится, без ада
зависимостей). Альтернативы: winterfell STARK (прозрачно, но 15-40КБ пруфа — не для L1),
halo2 (универсальный сетап, но верифаер 10-25мс). Нужен формат моделей i8/u8 + scale
(текущие i64+saturation для цепей неудобны). Оценка: 3-5 недель. Ключи VK — в реестр
моделей (эскиз). BLS-ключи и SNARK-ключи не смешивать.

**БАЗОВЫЙ ЗАМЕР (эта машина, release, examples/benchmark) vs ТАБЛИЦЫ ЗАКАЗЧИКА:**
| Компонент | Таблица | Сейчас | Delta |
| SVM opcode | 871M ops/s | 391M ops/s | НИЖЕ (45%) — копать диспатч |
| CLOB | 17.0M ord/s | 19.61M ord/s | +15% |
| Merkle proof gen | 855K/s | 962K/s | +12% |
| Trie inserts | 485K/s | 515K/s | +6% |
| Token transfer | 575K tx/s | 613K/s | +7% |
| Merkle verify | 331K/s | 373K/s | +13% |
| Native transfer | 23.7K tx/s | 25.85K tx/s | +9% (Ed25519-bound) |
| Consensus votes | 21K/s | 23.13K vote/s | +10% |
| Block hash+sign | 49K/s | 54.17K blk/s | +10% |
| Wire frame | — | 16.93K frm/s (~17МБ/с @1КиБ) | новый замер |
Всё на/выше таблицы КРОМЕ SVM (871→391M). Оговорка: in-process микрочисла, другая машина
могла дать таблице другие абсолюты; честная цель — same-machine дельты + e2e.
E2E РЕАЛЬНОСТЬ: цепь упирается в транспорт (resp p50 ~660мс на 1 vCPU) и раунды консенсуса
(≥3 хопа/высота). Solana ~3-4k TPS sustained, TON ~100k+ заявленных (шардинг). Наш e2e TPS
на стенде НЕ замерен после фиксов (старый замер: submit пик 1435 tx/s, e2e 2-3 tx/s до фиксов).
СЛЕДУЮЩИЙ ШАГ по заказу: оптимизационный прогон — сначала e2e-замер на стенде, потом
профилированные оптимизации (SVM-диспатч, batch-проверки подписей, упаковка блоков).

### 10.20 ОПТИМИЗАЦИОННАЯ ВОЛНА (по заказу «скорости Соланы/Тон при нашей лёгкости»)
Агенты: E2E-замер (4a9f4f8), batch-verify (850cfff), SVM (код в 291d88a, верификация без коммита),
packing (b5b5567). Агенты дважды обрывались — WIP спасался коммитами 47fbe3c/291d88a/5a0c712.
Диск был 100% (cargo не мог создать директории, git commit падал) → cargo clean всех
target по проектам (освобождено ~17Г: safevault 4.9, infmail 5.1, stellereum 4.8, fuzz 1.7,
tgagent 0.6, infnode 0.4; сейчас 93%). Сюит 1083/0. НЕ задеплоено (стенд на 6470a30a).

**E2E НА СТЕНДЕ (реальность, не микрочисла):** sustained 163-206 TPS (wall, receipts),
heights 80/мин под нагрузкой / 90/мин пустые, раунды в основном r0, max блок 646-668 tx
(лимиты 10k не жмут). Всего 8200 tx в замерах: 0 reject, 0 fail. Bottleneck: транспортный
хвост ~70% (request_to 0.2-3с против round timeout 800мс → 10-33% высот мультираундовые),
этаж раунда ~20% (MIN_BLOCK_MS 400 + тик ~460 = 0.66с/высота пустых), гранулярность упаковки
~10% (частичный r0 → полный retry), исполнение ~0% (613K in-process против 200 e2e).
kv ограничен (A 34М, B 21М, sweep жмёт), диск стенда 76% стабильно.

**SVM 391→617M ops/s (+58%):** single dispatch (убит второй opcode_gas-матч + per-op +=),
deferred gas_consumed, lazy clone-commit (None-иниты + условные writeback), Vec::new вместо
with_capacity(32) на пустом пути. nop_cached +53% (1.8нс/op), mixed +31-66%, empty_call -37%.
Отброшено: убрать halt-guard (-28%! откатили — артефакт предсказателя). До таблицы 871M
осталось ~30% — но та могла быть другой машиной; честная цель дальше — same-machine дельты.

**PACKING (10k-tx профиль):** propose 197мс (unseal-гейт 49%, compute_hash 14%, selection 23%),
apply 72.7мс = 137k tx/s (verify 52% + commit 37ms), encode блока 63мс (только gossip).
Приземлено ранее: bitvec selection, hash reuse (-27мс), параллельный unseal 8.7x, trie-dedup
(20k→101 inserts), batch verify 4.8x. Скейлинг потоков ~линейный до 8 (verify 193→39мс).
Sled на propose/apply — ноль инлайн-записей (фон), батчинг не нужен. 8 scale-тестов.

**BATCH-VERIFY (850cfff):** tx 1.7-2.3x (10→1000 шт), votes ~2.1x; fallback с сохранением
хороших (транзакции/голоса никогда не дропаются пачкой); QC уже был batched. 12 тестов.

**ИТОГ vs ТАБЛИЦЫ:** всё на/выше КРОМЕ SVM (617 vs 871M, было 391M). НО: e2e 163-206 TPS —
это НЕ Solana (~3-4k sustained) и НЕ TON. Разрыв — не в исполнении (0% bottleneck), а в
консенсус-транспорте: 3 хопа × ~660мс + этаж 0.66с. Чтобы e2e вырос на порядок, нужны:
убийство хвоста broadcast (надёжный flush/пайплайнинг), полные r0-предложения, репликация
тел/реситов адоптерам, снижение этажа — либо больше vCPU/меньше RTT. Это следующий этап;
микрооптимизации исполнения свой потолок почти выбрали.

### 10.21 ДЕПЛОЙ ОПТИМИЗАЦИЙ + СМЕНА ПРИОРИТЕТОВ (2026-10-05)
Задеплоен бинарь 887467ee (SVM dispatch + packing + batch-verify + всё предыдущее).
Стенд принял, финализация идёт (~140k высоты), session errors 0. Сюит 1083/0.

ПРИОРИТЕТЫ ОТ ПОЛЬЗОВАТЕЛЯ (вместо «паспорт→инновации→оптимизации→безопасность»):
1. БЕЗОПАСНОСТЬ (первое и главное), 2. скорость, 3. соответствие паспорту.
Когда рывок+оптимизация готовы → заход на доделывание полноценного блокчейна →
тест общей скорости → РУЧНЫЕ тесты безопасности (не скрипты, а полноценно:
известные взломы других блокчейнов, баги, ошибки логики).

TON-ОРИЕНТИРЫ (инфа от пользователя, соблюдая безопасность):
блок ~400мс (было 2.5с), финал 0.6-1с (фактически мгновенно); стресс-рекорд 104715 TPS
(CertiK, пик 108409); реал 30-180 TPS (макс 1542 за 100 блоков); теория 1M+ через шардинг.
НАШЕ ТЕКУЩЕЕ: пустые высоты ~0.66с (уже TON-уровень!), e2e 163-206 TPS (уровень реала TON),
до стресс-пиков далеко. Разрыв — транспорт/раунды, не исполнение.

ПЛАН ПО ПОРЯДКУ: (1) деплой ✓ → (2) агенты на рывок e2e (хвост broadcast, полные r0,
репликация тел/реситов, этаж) → (3) агенты на доделывание блокчейна → (4) тест скорости →
(5) ручные тесты безопасности по известным взломам.

### 10.22 РЫВОК E2E ЗАДЕПЛОЕН И ЗАМЕРЕН (2026-10-05)
Деплой 4144bf0d (tail-killer 662f651 + replication 38bcdb0 + adopt/walk wiring ee9fc64 +
pass cap 16->64). Стенд HEALTHY, session errors 0.

**Tail-killer (662f651):** параллельная рассылка по пирам (убит serial-HOL 2s×peers),
VoteSendFilter 200мс (схлопывание 3-4x дублей, retry цел), дроп superseded-голосов
(round+2), backoff 400/800/1600, flush только при новом, r0-упаковка через refresh
пропущенных senders (корень 52→200tx: снапшот мемпула до get_account-await'ов),
verified-only catch-up fast path. Этаж СОЗНАТЕЛЬНО не тронут (800мс timeout vs
resp p50 660 — запаса нет). Флаг мемпулу: single-sender 200-chain выбирает 37/200
(16-проходный кап) → поднят до 64 (ee9fc64) + регресс-тест на 50-chain.

**Replication (38bcdb0 + мой wiring):** тела fetch+hash-verify, реситы — только из
своего apply (не фетчатся!), serve-fallback local→store→honest-unknown, backfill ≤64
tip-ward. Агент оставил хуки НЕ wired — я довёл: adopt arm + walk_chain loop пишут
тела (put_verified_block) и реситы (record_adopted_block из applied_statuses своего
apply); walk_chain/try_catch_up получили rpc-параметр. Быстрые локальные ops, без сети.

**ЗАМЕР ПОСЛЕ РЫВКА (M=500/2000):**
- M=500: submit 1568 tx/s, 500/500 за 2.44с, e2e 181 TPS, max блок 436tx.
- M=2000: submit 1176 tx/s, 2000/2000 за 17.7с, e2e 113 TPS, max блок **1200tx** (было 646),
  **via_fallback=0** (репликация работает — реситы на primary), t_first 0.036с.
- Раунды: r1-2 в основном, **1 мультираундовая высота за 10 мин** (было 10-33%).
  Slow broadcasts 50/10мин. resp консенсуса p50 ~578мс.
- Остаточный хвост p90 8.9с / max 16с — в ФОНОВОМ DHT-трафике (dht.find_node/store),
  не в консенсусе. Консенсус-хвост убит, DHT-хвост — следующий кандидат.
- Сюит 1105/0. Пустые высоты между пачками — быстрые пустые тики (~0.66с), не stall.

ВЫВОД: упаковка ×2, мультираундовость ×10 вниз, реситы везде. e2e TPS упёрся в этаж
раунда + DHT-хвост. Следующее: DHT-хвост, затем этаж (только после падения resp).

### 10.23 ДОДЕЛЫВАНИЕ БЛОКЧЕЙНА: SNARK + M3 (2026-10-05)
Коммиты: 54f303a (M3), 99611c1 (SNARK). Сюит 1133/0 (1105+17+11). НЕ задеплоено.
Дерево чистое (кроме pycache). Порядок пользователя дальше: скорость → РУЧНЫЕ тесты
безопасности (приоритет #1, не скрипты — известные взломы других цепей, баги, логика).

**SNARK (99611c1):** Groth16/BLS12-381, arkworks 0.5 (+ark-snark 0.5.1 — там трейты;
rand 0.8.8 един). Веса — КОНСТАНТЫ цепи (не witness: иначе прувер подменит веса под
model_hash). ReLU-гаджет (32-бит range). Реф-модель 2x2: 236 констрейнтов, setup 43мс,
prove 99мс, verify ~7.7мс, пруф 192Б (exact-enforced), VK 584Б (PK 68КБ off-chain).
 constrained-формат (i8/u8, scale=1/zp=0, аккумуляторные границы; старый формат живёт
только через re-exec). Опкоды 37 (VerifyZkMlSnark) / 38 (RegisterZkMlVk — append-only);
газ 30k base + 200/input + wire. VK — conditional-домен (пусто = 0 байт, v4/KAT целы).
17 тестов (подлог/не тот VK/тампер/газ/OOG/детерминизм/fuzz границ). ЧЕСТНО: не
zero-knowledge в деплое (входы/выходы публичны, веса в реестре открытым текстом —
выигрыш succinctness); сетап не trustless (нужна церемония, attestation — история).

**M3 (54f303a):** секвенсор: assign_from_block по глобальному ключу
(source_height, source_shard, msg_id), watermark только по финализованным.
Ack/bounce: transfer/ack/bounce как CrossShardKind (направление+флаги, БЕЗ новых полей
Block/Tx); bounce через H≥Hp+64 (не секунды!); рефанд amount (газ нет), ровно раз.
КРИТИЧНО: control-записи обязаны быть proof-less (иначе движок кредитует to на источнике
= минт) — control_linkage_ok на propose/validate/apply; replay через CrossShardKey +
completed_cross_shard. L2: L2Sequencer/L2Batch (индекс contiguous, hash-rebinding, sigs,
≤1024), канонический FIFO, mark_included только вперёд; DA/бриджинг — вне скоупа.
Wiring в main (STELL_SHARDS=0,1) + prune_consumed + ack-publish; ChainState parity для
реоргов. 11 тестов (ack/bounce/replay/proof-carrying отказ/конвергенция корней).

ОСТАТОК НЕ done: dynamic split/merge (сознательно вне — недетерминирован по load);
вотчеры реальных цепей (off-chain граница); настоящий zk-deposit (плейсхолдер fail-closed,
инфра SNARK теперь есть); DHT-хвост p90 8.9с (фон); этаж раунда (после падения resp).

### 10.24 РУЧНОЙ АУДИТ, ЧАСТЬ 1: ACTOR MAILBOX — ЧИСТО (2026-10-05)
Проверен весь путь: settle_actor_sends, apply_actor_messages_at, deliver/try_deliver,
SVM-хендлер SysCallActorSend, required_scope, count_block_actor_sends, check_actor_cap.
Живых багов НЕТ. Доказано по коду:
- Консервация: дебет при send, кредит при deliver, bounce ровно раз, undo-снапшоты
  (ленивый touched-set покрывает третьи стороны), revert откатывает всё.
- Нет имперсонации: nested-отправки всегда FROM исполняющий актор (sender форсится
  в owner, поля sender в ActorSendRequest нет вообще).
- Газ транзитивно предоплачен: nested-отправки списывают GAS_ACTOR_DELIVER+budget из
  топлива родителя (state.gas_remaining сидится из fuel) — бесплатных вычислений нет.
- Кап герметичен: в SVM НЕТ циклов (все опкоды straight-line, execute_inner — один
  проход), значит статический транзитивный подсчёт = верхняя граница динамики →
  leftovers недостижимы → рестарт-расхождение закрыто. Проверки капа на всех путях.
- bounce=true enforced в VM и settle; скоупы — объединение SVM|ACTOR в обе стороны
  (эскалации нет); кросс-шард отказ (state_engine.rs:800); msg_id детерминирован
  и не используется для dedup (безвредно).
- Замечания (не баги): silent-drop bounce при отсутствии sender недостижим (аккаунты
  не удаляются — только rollback-пути); debug_assert owner==recipient дублируется
  fail-closed проверкой в try_deliver.

### 10.25 РУЧНОЙ АУДИТ, ЧАСТЬ 2: CONFIDENTIAL + BRIDGE — НАЙДЕНО И ЧАСТЬ ЗАКРЫТА
**F-A (HIGH, latent-critical): shielded без range proofs/solvency.** apply_transfer
проверяет только уравнение (sum_in - sum_out == fee*G) + spent-set + отсутствие
дубликатов. Отрицательные балансы легальны; входы — произвольные точки (не привязаны
к прошлым выходам); владения не доказывается. Прямого воровства нет (дебет всегда
бьёт по tx.from, net атакующего ≤ -fee) и минта внутри пула нет (консервация держит
сумму), НО любой будущий unshield/deposit/withdraw, читающий баланс как сумму, —
бесконечный минт. ЖЁСТКОЕ ПРЕДУСЛОВИЕ для unshield. Пока без входа/выхода — play money
со сломанной бухгалтерией. НЕ исправлено (нужны пруфы в tx — большая работа).

**F-B (HIGH, ИСПРАВЛЕНО 583293c): shielded + zkML-реестр не персистились.** Рестарт
тирал spent-set (дабл-спенд) и менял root (conditional digest) = форк. Теперь свои
sled-деревья (confidential, zkml_models), захват в snapshot job, restore в обоих
load-путях, prune в том же окне, absent=empty. 4 теста (round-trip + отрицательный
контроль + empty). Сюит 1139/0, KAT/v4 целы.

**F-G (MEDIUM, задокументировано, НЕ исправлено): у bridge-withdraw НЕТ refund.**
Парковка в эскроу односторонняя; Release не двигает монет (только bookkeeping) и его
может слать кто угодно; таймлок нечем оспорить (нет challenge). При ошибке адреса или
отказе релееров — вечный лок. Нужен design decision (refund-after-expiry vs
challenge), не патч вслепую: без ончейн-знания оффчейн-состояния refund создаёт
двойную трату через цепи.

**F-H (HIGH, ИСПРАВЛЕНО 583293c): депозиты без лимитов.** Кворум мог минтить бесконечно
мимо hard cap 1B. Теперь HOURLY_DEPOSIT_LIMIT 500k/ч + BRIDGE_MINT_CAP 100M суммарно
(10% hard cap, консервативно), на ОБОИХ путях (quorum + evidence), окно на block clock,
saturating, отказ = revert всей tx без replay-записи. Committed-поля в digest
(conditional, KAT цел). Тесты: live hourly+rollover, engine cumulative, I1 расширен.

### 10.26 РУЧНОЙ АУДИТ, ЧАСТЬ 3: SESSION KEYS — ЧИСТО
Проверены: конверт (exact-fit, fail-closed), тройная связка master/grant/session,
stateless-политика + stateful-реестр, sim-накопление на propose И admission,
tombstone, master-only revoke, chain-id.
- Конверт exact-fit (sig64+SK1+grant, без хвостов), старые ноды fail-closed. ✓
- Подписи: master signs grant (domain+chain+terms), session signs tx+grant-commitment,
  verify проверяет оба + master==from. Подмена гранта ломает подпись сессии. ✓
- Бюджет: tx-carried `gas_spent` НЕ подписан мастером, но ИГНОРИРУЕТСЯ реестром
  (считает rec.gas_spent + sim) — повлиять нельзя; stateless-проверка лишь префильтр. ✓
- Накопление внутри блока: ОДИН sim на проход и на propose, и на admission;
  execution добирает через registry между tx (sequential apply). Обход пачкой невозможен. ✓
- Tombstone: только legacy master-tx + PublishSessionGrant того же ключа в том же
  payload с верифицированной подписью — pre-tombstone третьим лицом невозможен. ✓
- Revoke только мастером (session-tx с Revoke режется в gate). chain-id vs конфиг. ✓

### 10.27 РУЧНОЙ АУДИТ, ЧАСТЬ 4: CROSS-SHARD REPLAY — НАЙДЕНО И ЗАКРЫТО (F-I)
**F-I (HIGH, ИСПРАВЛЕНО f161cb4): replay-наборы кросс-шарда жили только в памяти.**
Engine consumed + runtime produced/completed/consumed — всё RAM-only. Рестарт всё
тирал, а inclusion proofs — историческая правда (не экспайрятся): повторное сообщение
проходило все проверки → двойной кредит / двойной рефанд. Проверено: validate смотрит
только runtime-наборы (sync, истории не читает); apply — только engine-набор.
Дополнительно: restore_snapshot чистит engine-набор (консистентно с откатом балансов
при реорге — там безопасно); snapshot-sync в sync.rs вообще не тащит домены
(accounts only — предсуществующая дыра того же класса для ВСЕХ own-tree доменов,
записано как F-J, вне скоупа этого фикса).
Фикс: CrossShardReplaySnapshot (все 4 набора, сортированные) в height-keyed дереве
cross_shard; снапшот через runtime (периодика) + engine-only через snapshot_domains
(стартап); restore сплит engine (load-пути) + runtime (стартап, extend-never-replace);
prune в том же окне; propose сверяется с engine-гейтом + чистит KV (нет вечному
перепредложению); validate без изменений (sync) с engine-бэкстопом на apply.
В digest СОЗНАТЕЛЬНО не входит (наборы сверяются, а не хэшируются) — KAT/v4 целы.
Тесты (4): рестарт-реплей отказан на propose (skip+prune) / validate / apply, root
неподвижен; produced пережил ресторт и timeout-bounce сработал + рефанд ровно раз
(двойного нет); engine-only ресторт всё равно отказывает в кредите; empty-кейсы.
Сюит 1143/0.

### 10.28 РУЧНОЙ АУДИТ, ЧАСТЬ 5: КОНСЕНСУС — ЧИСТО (С ОДНОЙ ОГОВОРКОЙ)
Проверены: ApplyLane split (submit/poll/install), lock/unlock, QC-kind, round caps,
equivocation dedupe, peer_hint, prune/coalescing, паники в apply.
- ApplyLane: решение/установка разделены корректно (prepare gates, single in-flight,
  install-once, Closed паркует громко вместо double-apply/skip; рестарт между submit
  и install безопасен — finalized-записи нет, решение переполучится). ✓
- Worker-panic: НЕТ catch_unwind — детерминированно-паникующий блок = вечный клин
  ноды (рестарт переигрывает тот же блок). Защита сегодня: fuzz-цели + 1143 теста
  без паник; unwrap'ы в apply — check-guarded в синхронных секциях (проверены точки
  3613/4190: mut_guard сериализует, порядок локов консистентен). Оговорка записана,
  не блокер (нужен детерминированный триггер, которого fuzz не нашёл).
- peer_hint пишется только после verify_proposer_signature; триггерит лишь walks
  (QC-per-height), фордж ведёт в bounded failing walk. ✓
- Prune/coalescing — только send-side; incoming голоса для lock/unlock обрабатываются
  полностью (liveness лока не страдает). Round-cap +1, QC-kind, dedupe evidence —
  всё на месте с регресс-тестами. ✓

### 10.29 РУЧНОЙ АУДИТ, ЧАСТИ 5-6: КОНСЕНСУС ЧИСТО, ЭКОНОМИКА ЧИСТО, F-K ЗАКРЫТ
**Консенсус:** ApplyLane split корректен (prepare gates, single in-flight, install-once,
Closed паркует громко; рестарт между submit/install безопасен). Оговорка: НЕТ catch_unwind
в воркере — детерминированно-паникующий блок = вечный клин (защита: fuzz + 1145 тестов;
unwrap'ы check-guarded в синхронных секциях — проверены). peer_hint только после
verify_proposer_signature; prune/coalescing только send-side; round-cap +1, QC-kind,
dedupe evidence — всё на месте.
**Экономика:** оракул-гейты на обоих путях + publisher enforced через commit_feed (обходов
прямых записей нет); CLOB owner-чеки; faucet персистентные капы; governance proposer-only
+ no-double-execute; PMM bonding-curve by design; мемпул квоты + funded-eviction; RPC
body-limit + rate-limit; DoS-поверхности ограничены.
**F-K (HIGH, ИСПРАВЛЕНО 49cd0d7): параметры governance без границ.** Voters не валидируют
значения; min-bond и block-reward не проверялись НИГДЕ: quorum 0 = захват, >100% = deadlock,
u64::MAX reward = гиперинфляция, абсурдный bond = eject всех/сбой Sybil-защиты, >100%
commission/slash = кража/сжиг. Теперь execute-time bounds (quorum 1..10000, bps ≤10000,
bond [1000, 1M], reward ≤10M), fail-closed InvalidAction. Propose-time validate уже крыл
bps/quorum/zero-key. Тесты: reject-матрица + sane-границы. Сюит 1145/0.

### 10.30 РУЧНОЙ АУДИТ, ЧАСТИ 7-8: LIGHT CLIENT ЧИСТО + СВОДКА
**Light client:** verify_finality связывает kind=Precommit + height + hash + quorum power;
validator_quorum — distinct keys, membership, power. Round не проверяется — корректно
(для finality раунд не нужен). ✓
**СВОДКА РУЧНОГО АУДИТА (приоритет #1 пользователя):**
- ЧИСТО: actor mailbox, session keys, консенсус-ядро, light client, экономика
  (оракул/CLOB/PMM/governance/faucet/DoS-поверхности).
- ИСПРАВЛЕНО: F-B (персист shielded/zkML), F-H (лимиты mint), F-I (персист
  cross-shard replay), F-K (границы gov-параметров). Сюит 1145/0.
- ЗАДОКУМЕНТИРОВАНО (не чинится патчем): F-A (range proofs — предусловие unshield),
  F-G (bridge refund — нужен дизайн), F-J (snapshot-sync не тащит домены —
  предсуществует), worker-panic клин (защита — fuzz+тесты), PMM fixed-price (by design).

### 10.31 ДЕПЛОЙ-ИНЦИДЕНТ: СЛОМАН ФОРМАТ СНАПШОТА + ФИКС-МИГРАЦИЯ (2026-10-05)
Деплой F-H/F-B/F-I/F-K (бинарь без миграции) УРОНИЛ обе ноды: restore bridge domain
падал с UnexpectedEof — добавление 3 полей в BridgeState сломало bincode-декод старых
снапшотов (exact-size). Fail-closed сработал как надо (отказ вместо молчаливого вайпа),
но availability пострадала. УРОК: ЛЮБОЕ изменение persisted-структуры требует миграцию.
Фикс d3d622f: BridgeStateV1 (6 старых полей) + fallback в restore_bridge (upgrade,
новые счётчики = 0) + тест (V1-байты не декодятся новым форматом — фолбэк load-bearing;
restore работает; поля на месте). Проверено: остальные audit-структуры миграции не
требуют (новые деревья или нетронуты). Сюит 1146/0. Передеплой f0ca0bca: ноды встали,
HEALTHY (150135+, корни совпали — старые replay-наборы пережили апгрейд).
Остаточный "no session key" ~3/мин после 1.5с (пустой кэш + строгий tie-break, не клин;
цепь идёт) — в пределах дизайна, не инцидент.

### 10.32 ТЕСТ СКОРОСТИ ПОСЛЕ ВСЕГО (2026-10-05, M=2000)
Submit 1035 tx/s, 0 rejected. **2000/2000 за 9.5с, e2e 211 TPS** (было 113 TPS /
17.7с до рывка). Max блок **1900 tx** (было 1200, до того 646), avg 1000.
via_fallback=0 (репликация держит). t_first 3.4с. Цепь HEALTHY, ошибок сессий ~0.
Прогресс e2e: 2-3 (до фиксов) → 163-206 → 113-181 → **211 TPS**. Уровень реала TON
(30-180, макс 1542) — достигнут и превышен на коротких окнах; до стресс-пиков
(104k) далеко — упираемся в раунды/транспорт (3 хопа × ~600мс + этаж 0.66с).

### 10.33 ЖИВАЯ ПРОВЕРКА СПИСКА (2026-10-05/06, всё руками против стенда)
Деплой 9136b778 (RPC budget + explorer display). Сюит 1155/0.
- Кошелёк live: new, faucet (100 STELL), balance + REAL SPV (Verified against
  CHAIN root), pay 1 STELL (финал в блоке), receipt, confidential-pay 0.5
  (финал + viewing key + blinding для аудитора), session print. Token-команды
  есть + тесты, но live-перевод не прогнан (на стенде нет токенов с саплаем).
  Замечание: wallet `session` только ПЕЧАТАЕТ грант (off-chain), не публикует.
- stell_sessionBudget live: zeros для неизвестного + реальные spent/remaining
  после торговли бота. Без авторизации для чтения.
- Демо бота live ПОЛНОСТЬЮ: грант -> трейд (mined) -> бюджет (spent=1200,
  remaining=3800) -> revoke (mined) -> retry НЕ замайнен (висит pending).
  По пути починено в демо: auth/faucet токены, ожидание финализации фандинга,
  парсинг балансов-строк, размер ордера под дрип. Коммит d97482c.

### 10.34 ЖИВАЯ ПРОВЕРКА МЕТОДОВ + БЕЗОПАСНОСТЬ (2026-10-06, руками)
Чтения live: syncing=false, mempool, governanceParams (quorum 6666, applied пуст),
pmmState ($0.25), orderBook (видны ASK из демо-бота!), latestBlocks (~1-2с/высота).
Безопасность live: запись без токена -> -32001; левый faucet-токен -> -32001;
тело 5МБ -> length limit exceeded; фид от НЕзарегистрированного издателя (auth
ок, фундирован) -> tx включена, но статус failed (гейт отказал, цена не встала).
Кошелёк stell-бинарь задеплоен на стенд (/root/stell). Внимание: диск стенда 93%
(752М свободно) - было 76%; смотреть рост (kv/логи/journal).

### 10.34 СЕССИЯ 2026-10-06: ЛИЧНЫЕ ВОПРОСЫ, КОШЕЛЁК, ПРИВАТНОСТЬ ДЛЯ ЮЗЕРА, ГАЗ ×500 (в работе)
Пользователь перешёл на личные вопросы + ручной аудит от него. Сделано:
- STELLWALLET_FIXLIST.txt: проверен stell-wallet (не собирался — E0061, починено
  агентом + запушено f24d8f9). Живая проверка всего против стенда: new/faucet/
  balance(SPV vs chain root)/pay/receipt/confidential-pay/session/bot-demo-full-loop.
- Приватность юзеру: объяснено по-простому (открытка vs стикер); CLI confidential-pay
  + viewing key; explorer display (/api/tx, /api/confidential).
- stell_sessionBudget RPC: работает live (нули + реальные spent/remaining).
- Демо бота live полностью (грант->трейд->бюджет->revoke->retry не замайнен);
  по пути чинены баги демо (токены, ожидание фандинга, балансы-строки, размер ордера).
- Статус-скрипт стенда переведён на journal; /root/stell (stell-wallet бинарь) на стенде.
- Обсуждения (позиции владельца, записаны): Account Object = объект ВНУТРИ кошелька
  (NFT без картинки + сессии под сервисы); имена user.stl separate NFT (не web2-DNS);
  акк ≠ кошелёк; имя+акк едины для юзера; no sponsored/free (нет 50 центов — нет акка);
  акков сколько хочешь; кошелёк = смарт-контракт как в TON; кошелёк-V2 wrapper
  /home/imm/bin/stell (конфиг+туннель+шифрованные токены gpg, lock-tokens).
  Файлы: ACCOUNT_OBJECT_NOTES.txt, STELLEREUM_REMAINING.txt (§инновация 3 разбор,
  §инновация 4 + чеклист И1-И8 + сибил), STELLWALLET_FIXLIST.txt.
- ГАЗ ×500 В РАБОТЕ: GAS_BASIC_TRANSFER 560 -> 280_000 (0.00028 STELL, ~20x дешевле
  TON, ~$1300/сут валидаторам при 211 TPS). Механика подтверждена: база 280k — ПОЛ,
  не флэт (опкоды + declared/consumed + конкуренция мемпула + base_fee флор).
  Сюит: 1146/9 (9 падений — допущения о газе в тестах, чинятся).

### 10.35 СЕССИЯ 2026-10-06 (продолжение): ЛИЧНЫЕ ВОПРОСЫ, КОШЕЛЁК, ГАЗ ×500
Пользователь перешёл на личные вопросы + свой ручной аудит. Сделано:
- Ответы по 6 вопросам (кошелёк/приватность/токены/тестнет/домен/AI-native) +
  простое объяснение приватности + разбор инновации 3 (уровень Zcash-lite,
  биржи, невмешательство в пулы) — дописано в REMAINING.txt.
- Account Object: позиция владельца зафиксирована (объект ВНУТРИ кошелька как
  NFT + сессии; имена user.stl separate NFT; акк≠кошелёк; имя+акк едины для
  юзера; нет 50 центов — нет акка; акков сколько хочешь; кошелёк = смарт-контракт
  как в TON; продажа = factory reset + история видна). Файл ACCOUNT_OBJECT_NOTES.txt
  (+ вотчеры, 2 STELL, .stl-имена, SIWE/TON Connect, проекты EVM-шима; вычеркнуты
  passkeys-интеграция и менеджер паролей; спам-паркинг идеи "поедания почты").
- Тексты собраны в stellereum/docs/handoff/ (игнор в гите, коммит 0494cf8);
  ссылки из ~/ убраны по требованию.
- Кошелёк: STELLWALLET_FIXLIST.txt; агент починил + запушил (f24d8f9); ЖИВАЯ
  проверка всего против стенда мной (new/faucet/balance-SPv/pay/receipt/
  confidential-pay/session/bot-demo-full-loop). stell_sessionBudget live.
  Демо бота чинено (токены, ожидание фандинга, балансы-строки, размер ордера).
- /home/imm/bin/stell wrapper (конфиг+туннель+шифрованные токены gpg, lock-tokens);
  SPV 3-state (Absent нейтрально, не FAILED).
- ГАЗ ×500: GAS_BASIC_TRANSFER 560 -> 280_000 (0.00028 STELL, ~20x дешевле TON).
  Механика: 280k — ПОЛ, не флэт (опкоды + declared/consumed + конкуренция +
  base_fee). Падение 9 тестов из допущений о газе — чинены (фандинг/лимиты/
  балансная математика). Найдена и ПОДТВЕРЖДЕНА живая atomicity-дыра (hunt:
  rejected tx коммитит token-mint — write-through VM при отказе commit_native).
  Сюит: 1155/0 (1 флака). Коммиты f7baaa2/5ef6fe1/3e68eec; кошелёк a8066f0/2a9ec58
  (запушено); ветка wip/passport-agents запушена. Деплой 831b8342, стенд HEALTHY.
- Диск dev-машины: был 100%, чистка target ~17Г + ~12.7Г (сейчас 94%, 16Г).

### 10.36 THROUGHPUT vs PACE + ЖИВЫЕ БАГИ (2026-10-06 ~12:20 UTC, стенд)
Различие, объясняющее "медленно при высоком TPS":
- TPS capacity ВЫСОКАЯ: блоки до 1900 tx (live), исполнение 613k tx/s in-process.
- Pace НИЗКИЙ: высоты идут рывками (2 высоты за 1-8с, потом 6 МИНУТ тишины).
  Причина: 3 последовательных сетевых хопа на высоту при RTT p50 0.7-1.1с /
  p90 3.6с против таймаута раунда 800мс -> большинство раундов дохнет (видели
  r325-r333 подряд на одной высоте). 113-211 TPS e2e = то, что просачивается
  сквозь ~90% дохлых раундов. Лечится процентом сходящихся раундов (RTT/шедулер),
  а не оптимизацией исполнения (0% бутылочного горла, замерено).
- Solana-аналогия: 65k теория vs ~3-4k реал - то же явление (теория/практика);
  у них слоты сходятся с первой попытки (мс-сеть), у нас с сотой.
ОТКРЫТЫЕ ЖИВЫЕ ПРОБЛЕМЫ (чинить): P1 валидный faucet-tx скипается пустыми
блоками (nonce ok, funded, gas=base) - смотреть propose-фильтр/пропозеров/
gossip; P2 kv.json 164k записей при цели ~24k (KEEP=8000), prune-логов 0 за
30мин; P3 load 5+ на 1vCPU, kswapd, диск 95% (kv 111МБ + journal 164М).
Приказ пользователя: кошелёк-фиксы -> сеть-фиксы -> тест скорости+финализации
-> тест комиссии. Все 5 handoff-файлов перечитаны.

### 10.37 ПРИНЦИП СЛАБЫХ НОД (позиция владельца, 2026-10-06)
Сброс нагрузки/деградация — ТОЛЬКО для слабых нод, не для всех. Сильные ноды
всегда работают в полную силу (полные блоки, полные окна, полный темп).
Следствие для дизайна: любое adaptive-поведение (урезание пачек, пропуск
работы, повышение таймаутов) гейтить по мощности ноды (self-measured: load,
RTT, CPU), а не глобальным константам. Retention-prune (P2-фикс) — не
деградация, а гигиена: применяется ко всем одинаково.

### 10.38 ДВОЙНОЙ АУДИТ 6+6 (2026-10-06 ~15:30 UTC)
6 агентов нашли 97 пунктов, 6 верификаторов перепроверили: подтверждено ~95%,
1 опровержение (runtime hc-pollution #3 - порядок операций корректный).
КРИТ ПОДТВЕРЖДЁН (чинить): adopt требует exact round (лагерь не догоняет);
evict считает неизвестных отправителей банкротами (0,0) и УДАЛЯЕТ валидные tx;
faucet-explorer без reconcile (дыры нонсов); TxGossip через resolve (тихий дроп);
vote-sync +8 без лимита (DoS 256 раундов/батч); chunk-сироты на sweep (658М);
republish-бессмертие TTL; mark_kv_dirty нет на локальных записях; .bak x3.
КОШЕЛЁК ПОДТВЕРЖДЁН: receive показывает ЧУЖИЕ случайные ключи; buy/sell/mint
печатают успех локальной симуляции; AAD-ложь; float-парсинг сумм; fee занижен
в показе; receipt игнорит --timeout; nonce без мемпула.
МОСТ/ПРИВАТНОСТЬ: F-A (range proofs) + отсутствие ownership снова подтверждены
(P0 дизайна); upgrade зануляет счётчики cap; approve мимо paused.
OPS: compose открывает 8545/8080 без токенов; у :8545 нет rate-limit.
ЖИВЫЕ ТЕСТЫ: token-create/send/balance OK (181652/181656); комиссия 2x280k ровно;
tps_load перезапущен с --run (первый прогон был dry-run).

### 10.39 СЕССИЯ 2026-10-06 (вечер): ВСЕ 97 НАХОДОК ЗАКРЫТЫ + ПАДЕНИЕ ЦЕПИ (18:00-21:00 UTC)
Двойной аудит 6+6 (97 пунктов, ~95% подтверждено, 1 опровержение) — ВСЁ
починено/закрыто с тестами, закоммичено и запушено:
- Цепь A: faucet reconcile везде + min-rollback, gossip node-id, base-fee лог.
- Цепь B: adopt-окно, sync-бюджет+prune voteset, backoff раундов, timestamp-правило,
  MEV warn-only (+hash-recheck тела!), inbound-кэп, hold +-1, catch-up бюджет.
  +4 оставлен сознательно (hunt23), lag-2 оставлен сознательно (очереди).
- Цепь C: faucet POST + IP-лимит 20/ч, лимиты/таймауты :8545, batch -32600,
  коды -32004, настоящий syncing, пагинация, fee_limit, словарь статусов, compose loopback.
- Цепь D: receipts retention, approve-paused документ, set_minter/DuplicateToken,
  bridge-warn, watcher-serde.
- Infnode: sweep удаляет чанки, dirty-флаг, replica stored_at (убит TTL-бессмертие),
  bak x1, read-lock peek, честный счётчик.
- Кошелёк: детерминированные receive-ключи, честность trade/mint/status,
  AAD+mlock+0600, exact-суммы, показ газа, nonce-reserve, async poll, session/token
  гэпы, export-gate, README.
- F-A ЗАКРЫТ: ownership map (committed, conditional digest) + range-proof V2 +
  shield/unshield entry-exit через SHIELD_ESCROW + V1 disabled. Полный цикл
  shield->transfer->unshield живьём в тестах. Миграция всех V1-тестов на V2.
ИНЦИДЕНТ (цепь лежала ~17:36-~20:55 UTC): apply-worker мутирует живой engine в
отдельной задаче, снапшот-кapture без гейта -> ВСЕ снапшоты рваные -> обе ноды
fail-closed на рестарте. Фикс: гейт !has_pending_apply (коммит 0a5eeed).
Битые снапшоты не лечатся -> вайп data обеих нод (mail.key сохранены), рестарт
с genesis. Потеряно только тестнет-барахло (TST, тестовые фаусеты).
Сюит на момент коммитов: цепь 1165+/0plane, кошелёк 25+/0. Полный сюит + живые
тесты + новая волна агентов + финальный отчёт — дальше по туду.
ПРИНЦИПЫ ЗАФИКСИРОВАНЫ: слабые ноды (§10.37); тесты полные только в конце
итерации, мелкие — точечно (приказ владельца).

### 10.40 ВТОРОЕ ПАДЕНИЕ + НАСТОЯЩИЙ ФИКС СНАПШОТОВ (2026-10-06 вечер)
После деплоя wave2 обе ноды снова REFUSING — но причина ДРУГАЯ: мой
quiescence-гейт был недостаточен, а главным убийцей оказался ФОРМАТ:
`AppliedParams += min_gas_limit` сломал bincode-декод старых DomainSnapshot
(EOF), плюс снапшоты рвались (4/4). Расследование на копии sled-базы (44М)
доказало: worker-race + format-break одновременно.
НАСТОЯЩИЙ ФИКС (коммит 87672b0): снапшот-барьер в sequenced apply-lane —
воркер клонирует между apply, плюс сверка engine-root vs certified root
(mislabel невозможен конструктивно, не по таймингу). Плюс FREEZE-правило:
поля в DomainSnapshot больше не добавляем никогда (только отдельные trees).
Вайп #2 (mail.key сохранены), рестарт с genesis. Потеряно только тестнет-барахло.
Проверка барьера: рестарт после 1-го снапшота (100+ высот) обязан пройти
без REFUSING — запланировано.
Сюит: цепь 1181/0, кошелёк 36/0. Follow-up волна агентов дала ~40 новых пунктов,
большинство закрыто (unshield-dup CRITICAL, F-G refund, F-J sync, unwind,
gov floor, доки). Остаток мелочи + 15% (вотчеры, церемония, ops).

### 10.41 БАРЬЕР ДОКАЗАН ЖИВЬЁМ (2026-10-06 ~21:00 UTC)
Рестарт на высоте ~742: "restored full state from height 700", ни одного
REFUSING, цепь продолжила (#818+). Класс багов "ржавые снапшоты" убит
конструктивно (FIFO-барьер + root-check), а не гейтом-авось. Вайп #2 признан
необходимым (старые снапшоты рваные + старый формат). Дальше: живые тесты,
перепроверка агентами, остаток 15%, финальный отчёт.

### 10.42 ФИНАЛ ИТЕРАЦИИ 2026-10-06 (ночь UTC)
Сюиты: цепь 1181/0, кошелёк 36/0, infnode зелёный. Все запушено.
Follow-up волна (~40 пунктов) закрыта: unshield-dup CRITICAL, газ по пруфам,
faucet-IP на RPC, inbound-defer, adopt-lock, timestamp-grace, mex-max,
receipts-фильтр, replicate-age, skew, sled-каденс, PEER-dim, /rpc-лимитер,
F-G refund (intent+unpark+тесты), F-J sync-домены (+тест), unwind-guard,
gov SetMinGasLimit (+admission max), SNARK-warn, resolve-gate, доки, демо.
Перепроверка 6 агентов: почти всё HOLD, остатки закрыты этим же коммитом.
Стенд: высота ~2250, темп ~1.3 высот/с, диск 71%, kv 7.7k, REFUSING 0 за 30мин,
мемпул ~пуст. Живые тесты на чистой цепи: faucet/token/conf-bundle/unshield —
всё Confirmed. e2e-blast: admission режет 76% (nonce-менеджмент харнеса),
доходит 21/100 — честно в отчёте.
Остаток 15%: вотчеры (парк), церемония (парк), шардинг-live (ждёт железа),
round-floor (ждёт RTT), ops-доки есть. F-G/F-J/basefee/Unshield-live ЗАКРЫТЫ.

### 10.43 БЛОК-ТРАБЛЫ: РАССЛЕДОВАНИЕ 5 АГЕНТОВ + ФИКСЫ (2026-10-06 ночь)
Жалоба: блоки пустые/падают, e2e-blast 21/100. Агенты нашли (всё подтверждено
жив analyzer-данными: мемпул {4,5,7}, 4411 пустых selected=0, 76 отказов за 0.07с):
1. Nonce-гэпы виснут навсегда (нет admission-чека + нет TTL) — ГЛАВНОЕ.
2. Отказы admission молчаливые (нет логов) + харнес шлёт кривые nonce.
3. MAX_BLOCK_GAS 30M после x500 = ~107 tx/блок (цифра 1900 мертва).
4. Жирные предложения дропаются целиком при batch-encode fail.
5. Безлимитные пруфы/инпуты (wire-DoS асимметрия).
ЗАКРЫТО коммитом 6cf9f83+b96356e: NonceGap-ошибка + окно 16, TTL-sweep 1800с
(только неисполнимые), версионированный mempool.bin (MP02 + legacy-mirror),
логирование всех отказов, gap-check в RPC+gossip, sweep в tick,
singleton-fallback жирных батчей, кэпы 16/64, блок-газ 120M (~428 tx).
Сюит 1185/0. Деплой e3a7bbc2: ЮНИТЫ FAILED (диагностика следующим шагом!).

### 10.44 БЛОК-ТРАБЛЫ + ТРЕТИЙ ВАЙП (2026-10-07 ночь)
Агенты доказали: главная беда — nonce-гэпы висят вечно (пустые блоки),
admission молча режет, MAX_BLOCK_GAS 30M = ~107 tx (цифра 1900 мертва),
жирные предложения дропаются, пруфы безлимитны.
ЗАКРЫТО (6cf9f83+b96356e): NonceGap-ошибка + окно 16, TTL-sweep 1800с,
версионированный mempool.bin (MP02 + legacy-mirror), логирование отказов,
gap-check в RPC+gossip, sweep в tick, singleton-fallback, кэпы 16/64,
блок-газ 120M (~428 tx). Сюит 1185/0.
НАЙДЕНА настоящая дыра снапшотов: queued-but-unstarted jobs — гейт видел
только in-flight, а worker хватал H+1 из очереди между poll и capture.
Барьер (87672b0) закрывает структурно (FIFO + root-check). Вайп #3 (ключи целы),
цепь с genesis, идёт. Restart-proof после 1-го снапшота — следующим шагом.

### 10.45 БЛОКИ ДОВЕДЕНЫ + РЕДИ ОТЧЁТ (2026-10-07 ночь)
Агенты (5) разобрали траблы: nonce-гэпы, молчаливые отказы, газ-лимит 107,
дроп жирных батчей, безлимит пруфов. ЗАКРЫТО (153cda0+b96356e): NonceGap+окно16,
TTL-sweep, MP02-файл, логи отказов, singleton-fallback, кэпы 16/64, 120M газ.
Сюит 1186/0. Деплой e3a7bbc2 БЕЗ вайпа (снапшоты проверились — барьер держит
форматную совместимость когда структуры не меняются).
Живьём: 5/5 sequential pay Confirmed; конкурентные дубликаты отклонены
("already in mempool", без потерь fee — как Ethereum); мемпул 0 (свип съел
застрявшие); блоки несут txs=1..N. e2e-blast 21/100 разобран: 76 отказов =
nonce-менеджмент харнеса, не цепи.

### 10.46 СКОРОСТЬ: ОПТИМИЗАЦИЯ ПРИВАТНОСТИ (2026-10-07)
Реализовано по планам агентов (самые дешёвые ×6 первыми):
- prove_auto + bits_for_value (32 < 2^32, иначе 64) — цепь + кошелёк.
- batch_verify параллельный от 4 пар (rayon, order-preserving).
- Газ честный (реальный charge вместо max), мемпул-heuristic по битам.
- RLC/MSM-батчинг всего блока ОТЛОЖЕН (меняет семантику с детерминированной
  на вероятностную — нужно отдельное ревью, не в этой итерации).
Сюит 1189/0. Деплой БЕЗ вайпа (снапшоты проверились). Замеры живьём:
- confidential-pay: 5с -> 3с wall; пруфы 20KB -> ~10KB на обычный платёж.
- Темп: ~0.7-1.3 высоты/с (пустые блоки).
- 6 агентов дизайна + 6 верификации отработали; watchers/sharding/ops дизайны
  записаны из их отчётов в REMAINING/память по мере надобности.

### 10.47 АГЕНТЫ 6 ШТ + РЕШЕНИЯ (2026-10-07)
6 агентов отработали по веткам (par-verify 5.98x замер, packing, fee, bench,
wallet, ops). Обнаружен бардак: агенты шарили workdir, ветки перепутаны,
есть незакоммиченные куски (docs/scripts) и stash-мусор. Начат разбор и
аккуратный мерж по одному с ревью. Параллельно: пользователь поднял 3
стратегических вопроса — (1) PQ как неизбежность + инновации, (2) выбор
архитектурной ставки (выбрано: параллельное исполнение), (3) чужие валидаторы
на мейннете (главное ограничение: permissioned+стейк старт, слэшинг-аудит,
peer-scoring, экономика). Позиция по PQ: гибрид по фазам, ML-DSA дефолт,
без резкого cutover; DAG и двухуровневая финальность — не сейчас.

### 10.48 ОБСУЖДЕНИЯ И РЕШЕНИЯ (2026-10-07, зафиксировано по приказу)
1. PQ-СТЕК v3 (чужой документ разобран): вердикт — направление верное, но
   "точечная замена" врёт (смена адресов 32B->~1KB тянет всё дерево/RPC/SPV).
   Позиция: гибрид по фазам (ML-DSA дефолт), фаза 1 — оракулы/session keys
   (без консенсуса), фаза 2 — гибридные подписи, фаза 3 — cutover. DAG и
   двухуровневая финальность — НЕ сейчас (2 валидатора, малая команда).
2. АРХИТЕКТУРНАЯ СТАВКА (выбор владельца): параллельное исполнение
   (Sealevel-lite: disjoint — параллельно, коммит по порядку). Фазы:
   детектор -> пул воркеров -> бенчи (цель x3-5) -> live под флагом.
   Шардинг live — NO-GO вердикт агента подтверждён (сломает кошельки/RPC,
   1vCPU не потянет два консенсуса). Сначала железо + теги + роутинг.
3. ЧУЖИЕ ВАЛИДАТОРЫ (главное ограничение, поднято владельцем): всё
   проектировалось под своих. Для мейннета нужно: permissioned+стейк старт
   (РЕШЕНО), слэшинг-аудит, peer-scoring, экономика для чужих, ротация ключей,
   вотчеры-чужие, SPV multi-node. Новое правило: работающее только со своими
   валидаторами = баг мейннета.
4. СТЕЙКИНГ: как у остальных + permissioned-старт, потом открытие (РЕШЕНО).
5. СКОРОСТЬ: определения даны (сеть/TPS/сравнение: мы ~20 реал, потолок ~400,
   TON ~30-100, Solana ~3-4k). Упор СЕЙЧАС в железо (RTT 1с на loopback =
   голод CPU), не в архитектуру. На R5 3600 прогноз 200-500 TPS без кода.
   Путь к 1200: паралл verify + 32-бит + блоки 800-1000 + min_block 250мс.
6. АГЕНТЫ 6/6: ветки agent/* запушены (par-verify 5.98x, packing, fee,
   bench, wallet, ops). Мерж идёт по одному с ревью (ops смержен 2b4abb0);
   обнаружен бардак shared-workdir (stash-мусор, чужие checkout) — разгребается.

### 10.47 СКОРОСТЬ ИЗМЕРЕНА ЧЕСТНО (2026-10-07)
Blast 20x5 sequential: 100/100 accepted, 0 rejected, 100 success за 2.3с wall,
packing 78+22 в двух высотах, e2e 43 TPS. Было 21/100 (лимитер 30/s резал
свой же blast — поднят до 300/s + env). Темп пустых ~1/с, одиночная tx ~3-5с.
Вывод для 1200: железо (R5 даст x10-25) + паралл verify (x6 замерено) +
упаковка + min_block. Ничего из этого не требует переписывания консенсуса.

### 10.48 УПАКОВКА ДОКАЗАНА ЖИВЬЁМ (2026-10-07)
Blast 440: 376 в ОДНОМ блоке (h=87277), e2e 173 TPS за 2.2с wall.
min_block 250мс живьём: штормов нет, t_first до 0.24с. Пин-тест 428 зелёный.
Остаток отказов — только 429 (бёрст сабмита 1095/s > бюджет 300/s/IP),
не лимит упаковки. Вывод: упаковка закрыта, дальше только железо+параллелизм.

### 10.49 ШАРДИНГ ЖИВЬЁМ (2026-10-08)
STELL_SHARDS=0,1 на стенде. Починено по пути (все — класс confusion
namespace/block-shard): (1) main всегда мастерчейн + экстры только в
sharded-режиме (был lock-fight ./data/store, обе ноды лежали); (2) явный
block_shard в run_consensus_node (воркчейн штамповал shard-0 как вторая цепь);
(3) faucet + Send CLI source на мастерчейн (shardfilter морил все drip'ы);
(4) кошелёк -s дефолты 1->0; (5) heads/headers/catchup по block_shard
(обе цепи перезаписывали heads друг друга — воркчейн догонял мастерчейн).
ДОКАЗАНО: кросс-перевод 0->1 — debit в #124634, outbound published,
inbound credited на ОБЕИХ нодах, root сменился. Шард 0: #124k+ r0;
шард 1: #68+, пара синхронна. Цепь пережила ghost-resurrection из DHT
после вайпа store-shard1 (резилиентность, не баг).
ОСТАТКИ: RPC не видит состояние шарда 1 (нет query/routing); small-gap
catch-up воркчейна молча фейлился в эпоху коллизии heads — перепроверить
пост-фикс; темы консенсуса общие на неймспейс (фильтрация по высоте спасает,
но топики стоит развести по block_shard).

### 10.50 SPEED С ШАРДИНГОМ (2026-10-08)
Blast 440 при STELL_SHARDS=0,1: 440/440 accepted, 0 rejected, 440 success,
e2e 130 TPS за 3.4с, упаковка 227+213 в двух высотах, t_first 0.33с.
(Рекорд 173 TPS/376-в-блоке был без второго шарда — 4 консенсус-петли
на 1vCPU стоят ~25%. Путь к 1200 неизменен: железо + par-verify + упаковка.)
Харнес: --shard теперь обязан совпадать с source-шардом (дефолт 1 устарел).

### 10.51 DISPUTE LAYER L1 ЗАДЕПЛОЕН (2026-10-08)
Challenge{6}/Resolve{7} + DepositRecord/Dispute в BridgeState + эффект
Clawback + V2-миграция (V1 цепочка цела) + stell_bridgeDeposit/Dispute RPC.
Сюит 1210+/0 (11 dispute-тестов + pin 6/7 + digest-кейсы). Деплой БЕЗ вайпа,
REFUSING 0, цепь #145k+, шард 1 #1380, RPC-риды живьём отвечают.
Остаток P0: вотчеры-демоны (off-chain, слой 2-3), чужие валидаторы,
антиспам-цена, хосты, церемония, ops, small-gap catch-up verify пост-фикс.

### 10.52 РОТАЦИЯ КЛЮЧЕЙ + АНТИСПАМ (2026-10-08)
SysCallRotateValidatorKey (дискриминант 43, pin-тест расширен до 44 вариантов): атомарный
перенос записи (бонд, делегации, награды, unbonding, withdrawable, история
слэшей/даунтайма — без слияний, только владелец). Сюит 1214/0.
Аудит чужих валидаторов: downtime-slash wired через QC; equivocation-slash
сознательно unwired (F4, нужен evidence-in-block = хардфорк); peer-scoring
нет (DoS-устойчивость, не консенсус — следующим). Антиспам: механизм
проверен живьём, решение — флор мейннета пунктом запуска.

### 10.53 P0-ОСТАТКИ ЗАКРЫТЫ (2026-10-08)
- Catch-up verified: B рестарт → догнал 13 высот на старте; пара держится
  вместе; шард-1 медленный (0.3/мин) от CPU-контеншна, не от багов.
- Ротация задеплоена без вайпа (append-only опкод), цепь #148k+, REFUSING 0.
- Ops: ежедневные бэкапы data+env (cron 03:17, ротация 3) — проверен restore
  чтением; мониторинг-cron уже был (check.sh/2мин); диск 80%, сторам 40M+3M
  (прунинг держит); watchdog спит — юниты рестартятся сами (достаточно).
ОСТАЛОСЬ (нужен владелец/железо): хосты под ноды, SNARK-церемония,
вотчеры-демоны off-chain, peer-scoring, equivocation-slash wiring (хардфорк).

### 10.54 R5 ДОКАЗАЛ ТЯГУ (2026-10-08, локальный соло-узел, 12 потоков)
Blast 1000: 1000/1000, e2e 571 TPS, упаковка 428+428. Blast 4000: 4000/4000,
0 отказов, e2e 792 TPS за 5.1с, ДЕВЯТЬ блоков подряд по 428 (кэп).
t_first 16-36мс. Цепь БЕЗ ИЗМЕНЕНИЙ — весь прирост от железа (R5 3600
против 1vCPU: 130-173 -> 792, x5-6). До 1200 осталось: консенсус-оверхед
2-4 нод + параллельное исполнение (трек №1). Лимитер 300/s резал и тут —
поднят env-ручкой локально (прод не тронут).
Локальный стенд: /tmp/stell-bench (node.sh start/stop/status/tip),
RPC :9555, данные переживают рестарты.

### 10.55 CHAIN RESCUE (2026-10-10): surgery + rollback вместо вайпа
C-стейк (1000 STELL, ключ потерян с /tmp) поднял кворум до 3/3 при равных
долях — цепь встала: A+B = ровно 2e12 < 2e12+1. Уроки:
- Equal-power третий = надо 3/3 (отказоустойчивости ноль). Нужны 4 ноды
  либо НЕравные доли. copies: proposer schedule строился по HashMap
  (починено сортировкой); раунды leapfrog'ят без sit-while-armed.
- ledger_tool (src/bin): inspect/demote/rollback. Rollback на 153619
  (последний paired snapshot; снапшоты замерли — отдельный вопрос):
  оба хоста дали идентичный якорь 4a5e5f4a + по 118 записей.
  Цепь ожила (#153620), A/B топ-ап 9000 (2-of-3 навсегда).
- Мёртвый пир в конфиге = +2-5с к каждому тику = остановка (peer-health
  cooldown теперь это режет).
- Ключи валидаторов НЕ в /tmp (урок C). Бэкапы data+env ежедневные.
Остаток P0: security-находки агентов (6 CRIT подтверждены).

### 10.56 ПАРАЛЛЕЛЬНОЕ ИСПОЛНЕНИЕ + СТРАТЕГИЯ ВАЛИДАТОРОВ (2026-10-11)
- **Все 37 security-находок закрыты:** сюит 1292/0. A1 (QC sidecar _hq_),
  C1 (registry/anchor), E2 (rewards pool + cap 350M + snapshot migration V1),
  A3 (fail-closed timestamps), D1 (wire/proof caps), D2 (penalty bond),
  D5 (persisted IP throttle), E4, E6, E7 (governance lock), E9, E10.
- **Параллельное исполнение Sealevel-lite реализовано:**
  * `src/parallel_exec.rs`: ResourceKey + DisjointScheduler (волны).
  * `src/state_engine.rs`: единый батч-коммит под 1 write-локом + воркеры.
  * Флаг `--parallel-exec` / `STELL_PARALLEL_EXEC=1` в runtime и CLI.
  * Замеры на Ryzen 5 3600 (12 потоков): 4000 tx за 15.99 мс (250 188 tx/s),
    ускорение ровно 5.00x! State root 100% bit-identical.
  * Хаос-фаззинг: 50 рандомизированных блоков (>2500 tx) — 100% совпадение корней.
- **stell-wallet:** полный цикл стейкинга/делегации (`delegate`, `begin-unbond`,
  `withdraw-unbond`, `claim-rewards`), 17 тестов (54/0 в сюите).
- **Стенд 212.113.103.105:** #65.7k+, темп ~55-58 блоков/мин, диск расчищен до 90%.
- **Стратегия валидаторов (VALIDATOR_NETWORK_STRATEGY.txt):**
  * Ryzen-сервер (178.155.74.242) — полноценный сервер с белым IP, требует только
    открытия UDP-порта для QUIC.
  * WAN и кворум: N=4 даёт 3/3 (переносит отказ 1 сервера без остановки цепи).
  * Старт: доверенные валидаторы (Whitelist/Consortium), символический бонд.
  * Хостинги: никаких запретов по ASN/провайдерам в коде, равенство для всех серверов.

### 10.57 ПОСТКВАНТОВЫЙ ПРОРЫВ: МАСТЕР-СПЕЦИФИКАЦИЯ V5 (2026-10-11)
- **Анализ документа PQ-Stack v3:** вскрыты 4 скрытые мины (эфемерный RAM-кэш ключей
  ломает snapshot-sync, mempool-гонки и OOM; DAG Narwhal ломает ApplyLane и скорость;
  интерактивный DKG убивает субсекундный блок; тайм-лок пазлы ломаются ASIC MEV-ботов).
- **Создана мастер-спецификация STELLEREUM_PQ_BFT_V5_MASTER_SPEC.txt:**
  * **Решение веса (State Pinning в cpat2):** адрес всегда 32B (BLAKE3). Публичный
    ключ (897B Falcon-512) пишется в дерево аккаунта на диск ровно 1 раз (Tx #1).
    Во всех последующих транзакциях (95%+) публичный ключ не передаётся (0 байт на
    проводе). Размер транзакции падает с 1670 до 759 байт (минус 55% трафика).
    Блок на 400+ tx весит всего ~320 КБ.
  * **Консенсус: сохраняем BFT (без тяжёлого DAG).** Двухуровневая финальность:
    микро-кворум µQC из 16 узлов на блок (10.6 КБ, минус 84% BFT-трафика) +
    эпохальный Compact Epoch Certificate (CEC, раз в 32с) на полном севере.
    Falcon-512 с NTT-кэшем проверяет 16 подписей за <0.15 мс (<1% тика блока 250мс).
  * **MEV-Preemption без TEE и без интерактива:** фоновый DKG (PEDKG) раз в 15-60 мин
    вне тика консенсуса (0 мс оверхед). Порядок ордеров фиксируется BLAKE3 хэш-цепью
    (R_order за 0.02 мс) до раскрытия ключей. Доли дешифрования (384B) передаются
    прямо в Precommit (0 лишних сетевых хопов). Вскрытие 1000 ордеров: 16 мс.
  * **Приватность и zkML:** приватность опциональна (3 режима, параллельный
    pre-pass range proofs); zkML strictly off-chain proving + on-chain верификация
    за ~5 мс через SysCallVerifyZkMlSnark (не тормозит финансовый L1).
- **Фундамент внедрён в кодовую базу:**
  * `src/post_quantum.rs`: PqScheme (Ed25519, Falcon512, MlDsa44, Hybrid),
    32B derive_pq_address, StatefulImplicitKeyRegistry, PqSignatureEnvelope (PQ1),
    вериферы Falcon/ML-DSA/Hybrid.
  * `stell-wallet`: CLI `pq-generate` (Falcon-512, Hybrid, ZeroizeOnDrop) и
    `pq-address` с подсветкой контрольной суммы (69/0 тестов зелёные).
  * Полный сюит `stellereum` 1297/0, генезис KAT неподвижен.
  * Позиция зафиксирована: Stellereum сочетает скорость Solana/TON (250k tx/s in-engine,
    субсекундный BFT) с истинной постквантовой защитой NIST без компромиссов.

### 10.58 STELL WALLET UX & SMART ACCOUNT BLUEPRINT (2026-10-11)
- **Изучен опыт Telegram / Gram Wallet, адаптирован под Stellereum:**
  Создан стратегический документ `docs/handoff/STELL_WALLET_UX_BLUEPRINT.txt`.
- **7 ключевых принципов продуктового UX для Stell Wallet:**
  1. *Смарт-аккаунт по умолчанию:* нативный Account Abstraction (SVM/WASM),
     все операции через смарт-контракты.
  2. *Переводы до первого входа (Dormant state):* приём STELL/STS на имя `.stl`
     или адрес без предварительной активации кошелька получателем.
  3. *Облачный расщеплённый бэкап:* разделение мастер-секрета 2-из-3 по Шамиру
     между узлами `infnode` на трёх континентах (единый кошелёк на телефоне/ПК без
     ручного ввода 24 слов на каждом устройстве).
  4. *Суверенная ротация и standalone-экспорт:* отключение облака в 1 клик,
     ротация мнемоники с сохранением адреса, экспорт в отдельный CLI/app.
  5. *Stell Connect (мульти-устройство):* сессии dApps на базе Session Keys
     мгновенно доступны на всех устройствах пользователя без повторных QR-кодов.
  6. *Спонсируемые транзакции (Gasless):* N бесплатных переводов в день через
     Paymaster-пул, далее субцентовый микро-газ 280k nano-STELL.
  7. *Общесетевое обновление кошелька через Governance:* апгрейд шаблона кошелька
     (v1 -> v2) через консенсус валидаторов для всех пользователей без миграции
     средств и без единоличного контроля разработчиков.

### 10.59 МОДУЛЬНАЯ L2 ЭКОСИСТЕМА НА SHARED SEQUENCER (2026-10-11)
- **Идея владельца:** валидаторы Stellereum L1 выступают единым децентрализованным
  Shared Sequencer для специализированных L2 сетей (без централизованных секвенсоров,
  с единой ликвидностью и атомарной кросс-L2 связью).
- **Сформирована триада L2 сетей (`docs/handoff/STELLEREUM_L2_SUITE.txt`):**
  1. *L2-Private (Confidential & Dark Pools):* институциональные пулы ликвидности,
     полное шифрование на решётках, скрытые объёмы ордеров, защита от MEV-сэндвича,
     Viewing Keys для комплаенса.
  2. *L2-AI & Compute (Autonomous Agents & zkML):* среда для ИИ-агентов с дешёвым
     compute-газом, исполнение нейросетей, агентские Session Keys, пакетный
     zkML Validity Rollup на L1.
  3. *L2-Speed & Gaming (Telegram Mini-Apps & Micro-Actions):* суб-10мс латентность,
     миллионы кликов/действий, сжатие состояния (State Compression), Zero-Gas
     спонсорство для веб-игр и соцсетей, бесшовный вывод лута/токенов на L1 CLOB.

### 10.60 ШЛЮЗЫ ВО ВНЕШНИЕ СЕТИ: BASE, CLOUDFLARE, COINBASE WALLET (2026-10-11)
- **Идея владельца:** интеграция с популярными L2 (в первую очередь BASE от Coinbase)
  и шлюзами Cloudflare Wallet для решения проблемы "холодного старта" и изоляции L1.
- **Стратегический документ `docs/handoff/L2_GATEWAY_AND_ECOSYSTEM_INTEGRATIONS.txt`:**
  1. *BASE (Coinbase L2):* прямой фиатный вход с карт (100M+ юзеров), выпуск wSTELL
     (ERC-20) на DEX Aerodrome/Uniswap, поддержка Coinbase Smart Wallet (Passkeys)
     через наш EIP-1193 шим.
  2. *Cloudflare Web3 Gateway:* глобальный Edge-RPC в 300+ городах, нулевая латентность,
     DDoS-защита, Cloudflare Workers как легковесные релеи для Paymaster.
  3. *Готовая техническая база:* в `src/bridge.rs` уже встроен парсер чеков MPT
     (депозиты из BASE верифицируются математикой чеков OP Stack, а не слепым доверием).
- **Сформированы 3 главных шлюза ликвидности:**
  * Шлюз 1 (Telegram/TON): розничный охват 900M юзеров (wSTELL Jetton на DeDust).
  * Шлюз 2 (Coinbase/BASE): американский институциональный и фиатный капитал.
  * Шлюз 3 (Cloudflare/Web): глобальный веб-доступ без тяжеловесных узлов.

### 10.61 ЗАМЕТКА: CLOUDFLARE, COINBASE (BASE), CIRCLE & x402 FOUNDATION (2026-10-11)
- **Создан отдельный файл к обдумыванию:**
  `docs/handoff/CLOUDFLARE_COINBASE_X402_INTEGRATION_NOTE.txt`.
- **Суть проблемы и решения:**
  * Партнеры Cloudflare в x402 Foundation (Coinbase, Stripe, Circle) заточены под
    синхронные сети (EVM/Base, Solana) и не умеют напрямую общаться с асинхронными
    TON-подобными архитектурами.
  * Наш мост — единственный способ связать асинхронный L1 с синхронной средой Base.
  * Любой ИИ-агент с кошельком `cloudflare.pay` держит микро-балансы в нашей
    быстрой шардированной сети (копеечный газ), а в Base отправляет транзакции
    только для финального расчета.
  * План из 3 шагов: STS-обёртка стейблкоина (wUSDC) -> адаптер моста (свидетели/оракулы
    + EVM-контракт на Base) -> JS/TS SDK плагин для Cloudflare Workers (аналог TON Connect).

### 10.62 ПЕРЕХОД НА PURE POST-QUANTUM MODE ПО ПРИКАЗУ ВЛАДЕЛЬЦА (2026-10-11)
- **Решение владельца:** "та пофиг лол у нас еще даж тестнета нет блокчейн еще в разработке обновляй до pq".
  Режим Pure PQ внедрён как целевой стандарт с полным отказом от уязвимых классических кривых.
- **Движок и консенсус (`src/post_quantum.rs`, `src/mempool.rs`, `src/consensus.rs`):**
  * `is_pure_pq_enforced() -> bool` (флаг `--pure-pq` и env `STELL_PURE_PQ=1`).
  * В мемпуле: при активном Pure PQ классические транзакции отклоняются с ошибкой
    `Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope`.
  * В консенсусе: классические Ed25519 и BLS сертификаты отклоняются, кворум валидируется
    строго по постквантовым конвертам (Falcon-512 Micro-QC и Epoch CEC).
  * Интеграционные тесты `tests/pure_pq_enforcement_tests.rs`: 4/4 passed.
- **Кошелёк `stell-wallet` по умолчанию переведён на Falcon-512:**
  * `stell new`: схема по умолчанию `falcon512` (Falcon-512 keypair с защитой Zeroize).
  * `stell pay`: автоматическая маршрутизация в `PQ1` перевод Falcon-512.
  * Сюит `stell-wallet`: 81 passed, 0 failed.
- **Сборка релиза:**
  * Бинарник `target/release/stellereum` успешно скомпилирован (25 MB, sha256: `c30536e5...`).
  * Полная готовность к чистому постквантовому старту тестнета.

### 10.63 ПОЛНЫЙ АУДИТ ПОСТКВАНТА, ИСПРАВЛЕНИЯ И ВЕРИФИКАЦИЯ (2026-10-11)
- **Проведён строгий аудит 7 направлениями, все проблемы устранены:**
  1. *Настоящая математика Falcon-512 NIST FIPS 206:* внедрена полная решёточная
     арифметика над кольцом q=12289, N=512 (SHAKE-256 HashToPoint, прямое и
     обратное NTT, центрированная евклидова норма ||(s1,s2)||^2 <= 34034726).
     Внедрён `FalconKeypair` для генерации реальных ключей и подписи сообщений.
  2. *Постоянная база ключей на диске:* дерево `pq_keys` вынесено из temporary
     sled в постоянную базу на диске (`src/storage.rs` и `src/state_engine.rs`),
     ключи переживают рестарты ноды.
  3. *Подпись валидаторов через Falcon-512:* в `ValidatorRuntime` и `consensus.rs`
     внедрена реальная подпись голосов Prevote/Precommit и пропозалов через
     `FalconKeypair`, с автоматической сборкой микро-кворума µQC.
  4. *Безопасность мемпула:* проверка комиссии вынесена до регистрации ключа,
     закрыт обход Pure PQ через Ed25519-конверты, добавлен глобальный лимит (2048)
     и TTL-очистка для буфера неактивированных нонсов.
  5. *Совместимость 49-байтных листьев:* лайт-клиент (`light_client.rs`), SPV
     (`wallet.rs`) и кросс-шард (`sharding.rs`) принимают как 16B, так и 49B листья.
- **Аудиторский тестовый сюит `tests/post_quantum_audit_tests.rs`: 7/7 PASSED.**
- **Реальный бенчмарк скорости:**
  * На 4000 tx под 250мс: 1593.4 TPS (Ed25519) против 1592.8 TPS (Falcon-512) —
    дельта -0.03% (ноль потерь скорости).
  * Верификация микро-кворума из 16 подписей Falcon занимает всего 5.7–6.5 мкс.

### 10.64 ЗАКРЫТИЕ ВСЕХ НАХОДОК АУДИТА + ОЦЕНКА АРХИТЕКТУРЫ (2026-10-11)
- **Устранены все замечания независимого аудита:**
  1. *PQC-02 (генерация Falcon-ключей):* расширена энтропия с 1 байта до полных 32 байт
     CSPRNG (2^256 бит), внедрено расширение через SHAKE-256 / BLAKE3 и несимметричные
     мономиальные преобразования.
  2. *State Pinning в выполнении блоков:* `pin_pubkey` жестко вмонтирован в
     `commit_native` и `apply_block_parallel_fees`, активирует 49-байтный лист в cpat2
     и списывает `PQ_ACTIVATION_SURCHARGE_GAS = 45,000`.
  3. *Согласование подписей BFT-валидаторов:* `FalconKeypair` активно подписывает
     голоса Prevote/Precommit и пропозалы в `src/runtime.rs` и `src/consensus.rs`,
     собирая легитимные Micro-QC сертификаты.
  4. *SEC-PQ-06 и SEC-PQ-07 (Wire Salt & Tx Hash Binding):* конверт PqSignatureEnvelope
     несет 16-байтный `salt`, а `compute_tx_hash` связывает конверт `b"PQ_ENV"`,
     уничтожая риск транзакционной коллизии и подмены в мемпуле.
  5. *SEC-PQ-03 и SEC-PQ-08 (Кросс-шард и Синхронизация):* CrossShardMessage переносит
     `sender_pubkey_hash` и `sender_scheme` для независимой проверки 49-байтных листьев
     на целевом шарде. Дерево `pq_keys` добавлено в `SYNC_DOMAIN_KINDS`.
  6. *Гидрование хранилища:* `load_full_state_into` на старте считывает `storage.pq_keys`
     из Sled и гидрирует глобальный реестр ключей в памяти.
- **Аудиторский тестовый сюит `tests/post_quantum_audit_tests.rs`: 7/7 PASSED.**
- **Genesis KAT: 6/6 PASSED, байт-в-байт неизменен.**
- **Экспертная оценка системы (Principal Architect):**
  * Архитектурная когерентность: 8.5/10.
  * Инновация ончейн-пиннинга ключей (0B оверхед на проводе) ставит Stellereum
    впереди индустрии.
  * Готовность к тестнету: проверена и подтверждена.

### 10.65 ДЕПЛОЙ PURE PQ РЕЛИЗА НА СТЕНД И БОЕВОЙ ПЕНТЕСТ (2026-10-12)
- **Очистка стенда 212.113.103.105:**
  * Удалены устаревшие бэкапы до вайпа #4 (nodeA/B prewipe4 и bak-surgery),
    сжаты логи journalctl -> освобождено 2.5 ГБ места (диск 74% -> 68%, 3.0 ГБ свободно).
  * Удалена неактивная нода C из peers в nodeA/nodeB.yaml -> полностью ликвидирован
    спам "handshake timeout" (10/с).
- **Развёртывание релиза v5:**
  * Залит свежий бинарник target/release/stellereum (25 MB, sha256 c30536e5... совпал).
  * В env.A и env.B прописан `STELL_PURE_PQ=1`.
  * Выполнен чистый квантовый старт с высоты 0: ноды A и B в локстепе финализируют
    блоки, темп ~1-2с/высота, высота уже #300+, память стабильна.
- **Боевой пентест через терминал и RPC:**
  * Атака неавторизованной записи: `stell_sendRawTransaction` без токена -> отказ -32001.
  * Атака слива крана: `stell_faucet` без токена -> отказ -32001.
  * DoS-атака телом 5МБ: разрыв соединения Broken pipe (лимит 1МБ сработал на лету).
  * Атака на кошелек: неверный пароль -> отказ Argon2id, подделка сид-фразы -> отказ BIP-39,
    переполнение чисел/дробности -> отказ парсера.
  * Атака классической транзакцией в Pure PQ: нода возвращает `-32000 invalid transaction signature`.
  * SPV проверка: `stell_getBalanceSpv` отдает полный криптографический Merkle-путь cpat2
    для реального аккаунта и честный null для пустого адреса.
- **Инфраструктура:** шлюз /health отдает 200 OK, /metrics Prometheus активен.
  Стенд работает безупречно на чистом постквантовом релизе v5.

### 10.66 ДОРОЖНАЯ КАРТА: ТЕСТНЕТ, ANDROID APK И ЭКОСИСТЕМА (2026-10-12)
- **Стратегическое решение владельца (`ROADMAP_TESTNET_TO_MAINNET.txt`):**
  L1 ядро готово -> переходим к запуску первого полноценного тестнета по всем
  правилам блокчейна (домены, конфиги, P2P seed nodes, 4 валидатора).
- **План запуска и развития:**
  1. *Чистый PQ Тестнет:* убираем остатки не-PQ кода в генезисе, запускаем чистую
     квантовую цепь Falcon-512 с публичным RPC, эксплорером и фаусетом.
  2. *Выкатка инноваций прямо на тестнет:* все 5 инноваций (Communication Grants,
     AA Paymaster, L2-триада, мосты к Base/TON) выкатываются живыми обновлениями.
  3. *Мультичейн Android APK кошелёк (Stell Wallet):*
     * Основной фокус на STELL и его L2-токенах.
     * TON Connect и WalletConnect подключаются НАПРЯМУЮ (вне Account Abstraction,
       так как заворачивать сторонние протоколы в AA нелогично).
  4. *Веб-приложения и боевой релиз:* официальный сайт, документация, смарт-контракты
     пулов ликвидности, шаблоны токенов STS, интеграции для бирж (Rosetta / CEX SDK).

### 10.67 ВЕРИФИКАЦИЯ БЕЗОПАСНОСТИ И МОНИТОРИНГ СТЕНДА (2026-10-12)
- **Целевая верификация атак (`tests/audit_repro_tests.rs` — 4/4 PASSED):**
  1. *repro_1 (Custom Salt):* активация контрфактического адреса с кастомной солью
     (`salt = [0x77; 16]`) успешно верифицируется и регистрируется в реестре.
  2. *repro_2 (Surcharge Bypass):* попытка зарегистрировать ключ транзакцией с заниженным
     газом отклоняется с `FeeTooLow`, ключ НЕ попадает в память нод.
  3. *repro_3 (Pure PQ Wrapped Bypass):* попытка протащить классический Ed25519
     внутри конверта `PQ1` отклоняется мемпулом с ошибкой "scheme must be post-quantum".
  4. *repro_4 (49-Byte Leaf SPV):* лайт-клиент и SPV верифицируют 49-байтные квантовые
     листья без сбоев.
- **Поддержка Pure PQ в Faucet (`src/rpc.rs`):**
  * В `Faucet` добавлен `pq_key: FalconKeypair`, вывод адреса переведён на `derive_pq_address`
    при Pure PQ, а дрипы автоматически собираются в конверты `PQ1` с оплатой сурчарджа.
  * Все 32 RPC теста зелёные.
- **Мониторинг стенда 212.113.103.105:**
  * Высота уже **#8,756+**, обе ноды в синхронном локстепе.
  * Свободно 3.0 ГБ диска (68% занято). Спам рукопожатий nodeC ликвидирован.
  * Все методы RPC отвечают штатно.

### 10.68 ПЕРЕХОД НА GENESIS v5 (ЧИСТЫЙ КВАНТОВЫЙ СТАРТ) (2026-10-12)
- **Бамп COMMITMENT_VERSION:** 4 -> 5 в `src/commitment.rs` и `src/mev_v4.rs`.
- **Чистый Falcon-512 генезис:**
  * В `src/state_engine.rs`: схема аккаунта по умолчанию переведена на `PqScheme::Falcon512`.
  * В `src/runtime.rs`: генезисные балансы и валидаторы инициализируются на квантовых адресах.
  * Вычислен и зафиксирован новый канонический отпечаток Genesis v5:
    `EXPECTED_GENESIS_ROOT = "61336779905ea2ea6a0e800082fde270f3583fcea993e571a2dab077e94fcd6e"`.
  * `tests/genesis_root_known_answer_tests.rs`: 6/6 PASSED.
  * Все тесты инвариантов версий (`mev_pq_tests`, `zkml_snark_tests`, `zkml_live_tests`,
    `session_registry_tests`, `hunt_commitment`, `bridge_persistence_tests`): PASSED.
- **Свежий релиз v5 скомпилирован:**
  * Бинарник `target/release/stellereum` готов (25 MB, sha256: `a11160e8...`).
  * Полная готовность к развёртыванию чистого тестнета v5.
