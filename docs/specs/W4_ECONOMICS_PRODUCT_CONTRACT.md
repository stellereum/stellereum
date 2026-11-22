# W4 — Economics & Product Contract (HDAE, code truth)

Статус: **архитектурный контракт интеграции W4 («Economics & Product»)** для кодовых агентов.
Зафиксировано по фактическому чтению дерева `stellereum` + `stellereum-indexer` на 2026-11-21 (`CONSENSUS_RULESET_VERSION = 6`, `FORK_ID = 0x0f584a46`, `TOTAL_SUPPLY_CAP = 1_000_000_000 * 10^9` nano-STELL).

> **Правило замороженного ядра (`AGENTS.md` §7).** Изменения `apply()`, `fee_for_gas`, `failure_fee_for`, `staking` math, `evm_transfer_facts` (в SVM) и форматов хранения состояния меняют консенсусный переход и `state_root` — они **обязаны** вводиться за явным activation gate (`u64::MAX` по умолчанию в `chain_spec.rs`), со спецификацией + audit note + полным гейтом (`FORK_ID` / `CONSENSUS_RULESET_VERSION` при активации). Политики мемпула (внутри уже допустимых правил), secondary-индексы `storage.rs`, новые read-only RPC-методы, стриминг `rpc/streams.rs` (без плагинного ABI) и `stellereum-indexer` **не** затрагивают `apply()` / `Block::compute_hash()` / `FORK_ID`.
>
> **Вне скоупа W4 (BY DESIGN).** Локальные per-account fee-рынки (Solana-style write-lock hotspots) — **BY DESIGN post-mainnet**; в W4 сохраняется единый per-shard домен газового/wire/proof-лимита блока (`MAX_BLOCK_GAS`, `MAX_BLOCK_WIRE_BYTES`, `MAX_BLOCK_PROOF_UNITS`). Поток событий (Geyser-лайт) строится исключительно поверх SSE/WS (`rpc/streams.rs` + `stellereum-indexer`) **без** динамического плагинного ABI (`.so` / FFI).

---

## 1. Инвентаризация по коду (`stellereum/src/**`, `stellereum-indexer/src/**`)

### 1.1 Priority fee (`priority_fee_per_gas`, ordering, списание и распределение комиссий)

**Что уже есть:**
- **Wire-совместимое подписанное поле**: `Transaction::priority_fee_per_gas: u64` (`stellereum/src/sharding/transaction.rs:91`). При сериализации `TransactionWire` (`sharding/transaction.rs:41-55, 94-112`) ненулевой bid кодируется как 16-байтовый суффикс `b"PRIORITY" || priority_fee_per_gas.to_be_bytes()` внутри length-prefixed `signature` (`PRIORITY_FEE_COMMITMENT_TAG`, `PRIORITY_ENVELOPE_LEN = 16`, `sharding/transaction.rs:25, 137-169`). При `priority_fee_per_gas == 0` байты и хеши полностью идентичны legacy. При ненулевом bid значение входит в `signing_message()` (`sharding/transaction.rs:541, 548-555`) и `hash_into()` (`sharding/transaction.rs:850-852`).
- **Admission и mempool-индекс**:
  - `Mempool::order: BTreeMap<(u64, u64, TxHash), TxHash>` (`stellereum/src/mempool.rs:560, 2325-2326, 2368, 2746`) упорядочивает по `(tx.priority_fee_per_gas, tx.gas_limit, hash)` (`.rev()` в `select*`, `mempool.rs:2805-3046`).
  - `Mempool::required_fee_for_tx` (`mempool.rs:1111-1114`) требует `tx.gas_limit >= effective_floor_for_tx(tx) + tx.priority_fee_per_gas`; проверяется в `insert()` (`mempool.rs:2252-2255`).
  - `Mempool::eviction_bid_beats` (`mempool.rs:1068-1101, 2349-2358`): более высокий `priority_fee_per_gas` вытесняет при `new_fee > low_fee`; равный — при `new_fee >= low_fee + low_fee.div_ceil(20).max(1)`; меньший — никогда.
  - `Mempool::sealed_candidates` (`mempool.rs:1341-1352`) сортирует по `(priority_fee_per_gas, gas_limit, tx_hash)`.
- **Proposer и validator proposal gate**:
  - `ValidatorRuntime::pack_filter_accept` (`stellereum/src/runtime/mev_sync.rs:103-111`) и sealed-путь (`mev_sync.rs:1332-1340, 1385-1396`) проверяют `t.gas_limit >= base_fee + penalty + pq_surch + t.priority_fee_per_gas`; `sealed_meta_matches` (`mev_sync.rs:21-28`) сверяет `priority_fee_per_gas`.
  - `validate_proposal_unaligned` (`stellereum/src/runtime/consensus_step.rs:754-789`) проверяет `tx.gas_limit >= pool.required_fee_for_tx(tx).max(consensus_floor)`.
- **1B Supply Cap (инвариант)**:
  - `TOTAL_SUPPLY_CAP = 1_000_000_000 * 1_000_000_000` (`stellereum/src/tokenomics.rs:40`), статический раздел по шардам `SupplyPartition` (`tokenomics.rs:79-195`) и CAS-резервация `reserve_mint_nano` (`stellereum/src/state_engine/accounts.rs:1927-1971`).
  - В `apply_block_transition` (`stellereum/src/state_engine/apply.rs:2812-2819`) собранные `fees` зачисляются через **некэпируемый перенос** `credit_native_transfer(&block.proposer, fees)` (`accounts.rs:2054-2059`), а блок-награда — через `reserve_mint(block_reward)` (`apply.rs:2837`).

**Чего не хватает (критические пробелы):**
1. **`priority_fee_per_gas` НЕ списывается в `apply()`!** В `consensus_floor_parts` / `floor_parts_for` / `billed_gas` / `fee_for_gas` / `failure_fee_for` (`state_engine/apply.rs:1573-1595, 1637-1649, 1693-1766, 2089-2090`) и `plan_plain_tx` (`state_engine/parallel.rs:151-156`) `tx.priority_fee_per_gas` **отсутствует полностью**. Простой перевод с `gas_limit = 280_000 + 500_000` и `priority_fee_per_gas = 500_000` проходит admission и proposal check, но на `apply()` платит только `TX_INTRINSIC_GAS = 280_000` — priority bid фактически **возвращается отправителю как неиспользованный газ**, т.е. приоритет в консенсусе ничего не стоит.
2. **Нет fee-density ordering (сортировки по удельной цене за единицу ресурса блока).** `Mempool::order` (`mempool.rs:560, 2368`) и `sealed_candidates` (`mempool.rs:1344-1350`) сортируют по сырому `(priority_fee_per_gas, gas_limit)`. Транзакция на `10_000_000` газа (или тяжёлая zkML/EVM-carrier tx до `MAX_BLOCK_WIRE_BYTES`/`MAX_BLOCK_PROOF_UNITS`) с `priority = 101` вытесняет 35 обычных переводов по `280_000` газа с `priority = 100` каждый (`35 * 100 = 3_500` суммарного priority доходa против `101`).
3. **Нет burn / reward split.** В `apply_block_transition` (`state_engine/apply.rs:2817-2819`) `100%` собранных `fees` уходят `block.proposer`. Отсутствуют сжигание базовой доли (`fee_burn_bps`), распределение в стейкинг-пул/валидаторам (`staking_fee_bps`) и governance-параметры / activation gate для изменения этих правил.
4. **Нет EVM/RPC динамики fee-рынка.** `eth_gasPrice` / `eth_feeHistory` (`evm_adapter/types.rs:89-97`, `evm_adapter/adapter.rs:2190-2273`) отдают статические константы (`DEFAULT_BASE_FEE`, `DEFAULT_MAX_PRIORITY_FEE`), не связанные с текущим `mempool.base_fee` и очередью `priority_fee_per_gas`.

---

### 1.2 Sub-nano truncation (P2 из `docs/OPEN_DEFECTS.md:98`)

**Что уже есть:**
- Native STELL хранится в `u64` nano-STELL (`1 STELL = 10^9` nano-STELL, `AccountState::balance: u64` в `state_engine/mod.rs:107`, trie-лист `16` или `49` байт в `state_engine/mod.rs:144-158`).
- EVM-адаптер (`stellereum/src/evm_adapter/types.rs:1307-1324, 1343-1369`) задаёт `WEI_PER_NANO = 1_000_000_000` и `wei_to_nano(wei) = wei / WEI_PER_NANO`.
- `evm_transfer_facts` (`stellereum/src/evm_adapter/binding.rs:187-193`) уже отклоняет `value_wei < WEI_PER_NANO` (где `value_nano == 0`).
- `ValidatorRewardState::accrue` (`stellereum/src/staking.rs:971-1013`) уже переносит `remainder: u128` по знаменателю `remainder_den: u64` внутри `REWARD_PER_TOKEN_SCALE = 10^18` при неизменном `delegated`.
- `distribute_reward` (`staking.rs:4090-4093`) обеспечивает точную сумму `validator_reward + delegator_pool == reward` за счёт `validator_reward = reward - delegated_share + commission`.

**Где возникает округление / потеря остатка (чего не хватает):**
1. **Тихое усечение sub-nano wei в EVM carrier (`evm_adapter/binding.rs:187-198`, `evm_adapter/types.rs:1318-1324`)**: при `value_wei = 1_500_000_000` (1.5 nano-STELL) `wei_to_nano(value_wei)` молча возвращает `1` nano (`0.5` nano отбрасывается без ошибки и без возврата/учёта; `nano_to_wei(value_nano) != value_wei`). Аналогично в `evm_raw_to_stell_transaction` (`evm_adapter/tx.rs:311`) и `verify_evm_signature` (`sharding/transaction.rs:776`).
2. **Сброс остатка в `ValidatorRewardState::accrue` (`staking.rs:998-1004`)**: при любом изменении `delegated` (`self.remainder_den != delegated`) код выполняет `self.remainder = 0; self.remainder_den = delegated;`, безвозвратно выбрасывая накопленный числитель `remainder`.
3. **Промежуточное двойное усечение в `GenesisVault::calculate_mint` (`tokenomics.rs:278-291`)**: `value_micro_usd = (asset_amount * price_micro_usd) / 10^decimals` усекается до целого микро-USD **до** умножения на `10^9` и деления на `250_000`, что теряет до `250_000 / 10^decimals` микро-USD на каждую операцию (в т.ч. превращает мелкие депозиты `< 1` микро-USD в `0`).
4. **Потеря sub-nano хвоста в `pow_half_fixed` (`tokenomics.rs:617-656`)**: при активации `EMISSIONCapEXACT_ACTIVATION_HEIGHT` каждый блок теряет `< 1` nano из-за целочисленного `>> 64` без переноса дробного остатка `Q0.64` (в `tokenomics.rs:980-1017` заложен запас `terms + 2*H` именно под эту потерю).
5. **Округление `f64` в non-consensus RPC**: `eth_feeHistory` (`evm_adapter/adapter.rs:2258`) использует `(max_priority_fee as f64 * (p / 100.0)).round() as u128`, что теряет точность выше 53 бит мантиссы.

---

### 1.3 History API & bounded `getProgramAccounts`-аналог

**Что уже есть:**
- **Durable store (`stellereum/src/storage.rs`)**:
  - Sled-деревья (`storage.rs:852-865`): `blocks`, `by_height` (`height(8BE) || block_hash(32)`), `headers` (`BlockHeaderRecord`, `storage.rs:553-562`), `receipts_v1` (`tx_hash -> StoredReceipt`, `storage.rs:596-606, 1190-1269`), `state`, `domains`, `pq_keys`.
  - Конфигурация хранения `RetentionConfig { archive: bool, keep_blocks: u64 }` (`storage.rs:666-700`, default `archive = true`, `keep_blocks = 50_000`) и bounded-прунинг `prune_receipts_below` / `prune_blocks_below` (`storage.rs:1276-1367`).
- **Node RPC (`stellereum/src/rpc/`)**:
  - Ограниченное окно в памяти: `MAX_RECEIPTS = 50_000` (`rpc/state.rs:350`), `MAX_RECENT_BLOCKS = 100` (`rpc/state.rs:299`), `MAX_FINALIZED_HEADERS = 512` (`rpc/state.rs:347`).
  - Точечные и оконные методы в `rpc/reads.rs`: `stell_getBlock` (`:1282`), `stell_getBlockTransactions` (`:1378`), `stell_latestBlocks` (`:1183`), `stell_getTransactionReceipt` (`:1967`), `stell_getTransactionByHash` (`:2068`), `stell_getEvents` (`:2142-2254`, сканирует весь in-memory `ReceiptIndex` до `MAX_EVENTS_RETURNED = 1_000` в `rpc/cache.rs:361`), `stell_listTokens` (`:1938-1961`, `skip(offset).take(limit)` до 1000), `stell_getArchiveProof` (`:885`), `stell_getHistoricalRoot` (`:960`).
- **State registries**: `TokenRegistry` (`token.rs:624-627`, `tokens: HashMap<[u8; 32], TokenActor>`, `TokenActor::balances: HashMap<[u8; 32], u64>` в `token.rs:217`) и `ContractRegistry` (`contract.rs:414-419`, `contracts: HashMap<[u8; 32], Contract>`, `Contract::storage: HashMap<i64, i64>` в `contract.rs:224`).
- **Indexer (`stellereum-indexer/src/`)**:
  - SQLite WAL (`db.rs:301-409`): таблицы `blocks`, `transactions`, `accounts`, `contract_events`, `verified_contract_sources` с `shard_id` и индексами `idx_tx_from`, `idx_tx_to`, `idx_tx_block`, `idx_tx_shard_block`, `idx_events_*`.
  - REST API (`server.rs:128-189`) с лимитами `MAX_EVENT_PAGE = 200`, `MAX_OFFSET = 1_000_000` (`server.rs:105-116`).

**Чего не хватает:**
1. **Нет вторичных индексов в `storage.rs`**: `receipts_v1` индексирован только по `tx_hash` (`storage.rs:1191`); `StoredReceipt` не хранит `from`, `to`, `amount`, `shard_id` (`storage.rs:596-606`), `BlockHeaderRecord` не хранит `shard_id` (`storage.rs:553-562`). На ноде нет истории транзакций адреса за пределами in-memory `ReceiptIndex`, а `stell_getEvents` не читает из `sled`.
2. **Нет курсорной пагинации на ноде и в индексере**:
   - `stell_listTokens` (`rpc/reads.rs:1950-1956`) использует `skip(offset).take(limit)` поверх `HashMap::keys()` — порядок итерации `HashMap` недетерминирован, страницы «плывут» и могут дублировать/пропускать токены.
   - `stellereum-indexer/src/db.rs` (`get_blocks_by_shard`, `get_account_txs`, `get_events`, `list_contracts`) использует `LIMIT/OFFSET` до `MAX_OFFSET = 1_000_000`, что даёт $O(\text{offset})$ скан и сдвиг страниц при поступлении новых блоков.
3. **Нет bounded `getProgramAccounts`-аналога**: нет ни `stell_getProgramAccounts`, ни `stell_getTokenAccountsByOwner` в `rpc/reads.rs`, ни индекса `(owner -> tokens)` / `(contract -> storage keys)` / `(creator -> contracts)` с жёсткими лимитами на число элементов, число просмотренных ключей и размер ответа в байтах. В `stellereum-indexer` отсутствуют таблицы `token_balances`, `token_transfers`, `contracts` (`list_contracts` в `db.rs:736-767` видит только контракты с >= 1 событием, а `/api/v2/tokens` в `server.rs:678-733` проксирует лишь первые 100 записей `stell_listTokens`).

---

### 1.4 Поток финализированных событий (SSE/WS — Geyser-лайт)

**Что уже есть:**
- **RPC Streaming Hub (`stellereum/src/rpc/streams.rs`)**:
  - Топики `SubscriptionTopic` (`streams.rs:48-70`): `NewHeads`, `NewTxs`, `Invalidations`, `Events { contract, topics }`.
  - `SubscriptionHub` (`streams.rs:117-370`): синхронный `std::sync::RwLock`, `broadcast::Sender<Notification>` с `STREAM_BROADCAST_CAPACITY = 1024` (`:37`), окно инвалидаций `MAX_INVALIDATION_WINDOW = 64` (`chain.rs:17`).
  - Защитные лимиты (`streams.rs:21, 30, 43, 674, 827, 1030, 1076, 1087, 1098, 1142`): `MAX_SUBSCRIPTIONS = 4096`, `MAX_SUBSCRIPTIONS_PER_CLIENT = 64`, `WS_MAX_SUBS_PER_CONNECTION = 16`, `WS_MAX_MESSAGE_BYTES = 1 MiB`, `MAX_SUBSCRIPTION_TOPICS = 32`, `SSE_IDLE_TIMEOUT_SECS = 300`, `WS_IDLE_TIMEOUT_SECS = 300`, `WS_GENERAL_RATE_LIMIT_DEFAULT = 300/s`, `WS_EXPENSIVE_READ_RATE_LIMIT_DEFAULT = 5/s`.
  - Транспорты: `POST /` (`stell_subscribe`, `stell_unsubscribe`, `stell_getSubscriptions`), `GET /ws` (`streams.rs:1406-1695`), `GET /events` SSE (`streams.rs:883-984`).
- **Consensus hooks (`node/consensus_driver.rs:349, 3925-3946` и `rpc/state.rs:443-681`)**:
  - `record_lane` последовательно вызывает `record_finalized_header`, `record_receipts_with_events` (публикует `publish_new_tx` и `publish_contract_event` после сброса lock `receipts` — `rpc/state.rs:611-627`) и `record_block` (публикует `publish_new_head`, `rpc/state.rs:465-471`); `publish_invalidation` подключён через `invalidation_sink` (`consensus_driver.rs:349`, `runtime/anchors.rs:2245-2268`).

**Чего не хватает:**
1. **Нет последовательности `seq`, replay-окна и сигнала о лаге (`Lagged`)**: `Notification` (`streams.rs:100-105`) не содержит `seq` / `shard_id` / `height`; при переполнении канала `broadcast::error::RecvError::Lagged(skipped)` (`streams.rs:965, 1532`) лишь пишет `tracing::warn!` и молча теряет события — клиент не получает уведомления о пропуске и не может догнать `after_seq`.
2. **Ошибки и бедность текущих payload**:
   - `RpcState::record_block` (`rpc/state.rs:468`) жёстко передаёт `MASTERCHAIN_SHARD` в `publish_new_head` вместо `self.engine.shard_id()` — на workchain-ноде стрим `newHeads` сообщает неверный `shard_id = 0`!
   - `publish_new_head` не передаёт `prev_hash`, `state_root`, `proposer`; `publish_new_tx` не передаёт `shard_id`, `height`, `tx_index`, `fee_charged` и не поддерживает фильтр по `account`; `publish_contract_event` не передаёт `shard_id`, `tx_index`, `log_index`, `topic0`.
3. **Нет Geyser-лайт дельт аккаунтов/токенов**: отсутствуют топики `AccountUpdates` (финализированные изменения баланса/nonce/стейкинга/контракт-слотов по ограниченному списку аккаунтов) и `TokenTransfers` (финализированные STS-20 события из блока).
4. **Индексер работает только поллингом**: `stellereum-indexer/src/syncer.rs:95-116` опрашивает ноду каждые `400 ms` по HTTP, не подписывается на SSE/WS ноды (`/events` или `/ws`), не реагирует push-ом на `invalidations`, а `stellereum-indexer/src/server.rs:128-189` не отдаёт SSE/WS поток потребителям.

---

## 2. Точные контракты, лимиты, совместимость и инварианты

### 2.1 Матрица совместимости: Consensus/Apply vs Pure Policy/RPC/Indexer

| Компонент W4 | Меняет `apply()` / `state_root` / `Block`? | Требует Activation Gate + Audit Note (`AGENTS.md` §7)? | Меняет `FORK_ID` до активации? |
|---|---|---|---|
| Mempool fee-density ordering (`mempool.rs` `order`, `eviction_bid_beats`, `sealed_candidates`) | Нет (node-local admission/packing policy) | Нет (сохраняет `required_fee_for_tx` и parity с `consensus_step.rs:774`) | **Нет** (`0x0f584a46`) |
| Включение `priority_fee_per_gas` в списание `apply()` (`fee_for_gas`, `failure_fee_for`, `plan_plain_tx`) | **Да** (`tx_fees`, балансы отправителя/пропозера, `state_root`) | **Да** (`FEE_MARKET_V2_ACTIVATION_HEIGHT = u64::MAX` + audit note; при активации — bump `CONSENSUS_RULESET_VERSION` / `FORK_ID_RULES`) | **Нет, пока `u64::MAX`** (byte-identical pre-activation) |
| Fee Burn / Reward Split (burn + proposer + staking pool в `apply_block_transition`) | **Да** (баланс `block.proposer`, `REWARDS_POOL`, сжигание долей, `state_root`) | **Да** (тот же `FEE_MARKET_V2_ACTIVATION_HEIGHT = u64::MAX` + audit note) | **Нет, пока `u64::MAX`** |
| Sub-nano strict EVM carrier в `svm.rs` (`wei_to_nano_exact`), `ValidatorRewardState::accrue` rescale, `GenesisVault` / `pow_half_fixed` carry | **Да** (`evm_transfer_facts` в SVM, `staking` accumulator, `emission` награды) | **Да** (`SUB_NANO_STRICT_ACTIVATION_HEIGHT = u64::MAX` + audit note; для `pow_half_fixed` — в паре с `EMISSIONCapEXACT_ACTIVATION_HEIGHT`) | **Нет, пока `u64::MAX`** |
| Sub-nano отказ на RPC/EVM-ingress (`eth_sendRawTransaction` / carrier builder) и integer `eth_feeHistory` | Нет (policy / RPC view) | Нет | **Нет** |
| Secondary indexes в `storage.rs`, History API (`stell_getAddressHistory`), `stell_getProgramAccounts`, `stell_getTokenAccountsByOwner`, детерминированная сортировка `stell_listTokens` | Нет (read-only RPC + локальные sled-индексы) | Нет | **Нет** |
| Geyser-лайт SSE/WS (`rpc/streams.rs`, `rpc/state.rs`, `consensus_driver.rs` `record_lane`) и весь `stellereum-indexer` | Нет (асинхронная публикация после финализации; SQLite + HTTP/SSE/WS) | Нет | **Нет** |

---

### 2.2 Контракт 1: Priority Fee, Fee-Density Ordering и Burn/Reward Split

#### 2.2.1 Локальная сортировка по fee-density (node-local policy, без смены `FORK_ID`)
- **Проблема ресурса блока**: блок ограничен тремя осями (`MAX_BLOCK_GAS`, `Mempool::MAX_BLOCK_WIRE_BYTES = 24 MiB`, `Mempool::MAX_BLOCK_PROOF_UNITS = 2048`, `mempool.rs:807, 816`).
- **Определение эффективной стоимости единицы блока (`effective_resource_units(tx)`)**:
  ```text
  wire_equiv  = estimate_tx_wire_bytes(tx) * GAS_PER_WIRE_BYTE      // GAS_PER_WIRE_BYTE = 100
  proof_equiv = count_tx_proof_units(tx)   * GAS_PER_PROOF_UNIT     // GAS_PER_PROOF_UNIT = 10_000
  units(tx)   = max(tx.gas_limit, wire_equiv, proof_equiv).max(1)   // >= 1 (zero-div impossible)
  ```
  *(При базовой 256-байтовой tx `280_000` gas, `wire_equiv = 45_600`, `proof_equiv = 0` → `units = 280_000`; тяжёлая tx с `1 MiB` подписью/evidence даёт `wire_equiv = 104_857_600`, а с 32 zkML proof units — `proof_equiv = 320_000`, так что спам тяжёлыми байтами/пруфами не получает искусственно высокую плотность.)*
- **Ключ приоритета (чистая integer `u128` арифметика, без `f64`)**:
  - `FEE_DENSITY_SCALE: u128 = 1_000_000_000` (`10^9`).
  - `priority_density(tx) = ((tx.priority_fee_per_gas as u128) * FEE_DENSITY_SCALE) / (units(tx) as u128)` (насыщается в `u64::MAX` или хранится как `u128` в `BTreeMap<(u128, u64, u64, TxHash), TxHash>`):
    1. `priority_density` (убывание, `.rev()`) — явный приоритетный бид на единицу потребляемого ресурса;
    2. `tx.priority_fee_per_gas` (убывание) — tie-breaker при одинаковой плотности;
    3. `tx.gas_limit` (убывание) — общий размер комиссии;
    4. `hash` — детерминированный tie-breaker.
  - **Правило вытеснения при полном пуле (`eviction_bid_beats`)**:
    - Если `new_density > low_density`: допускается при `new_fee > low_fee` (порог не даёт дешевой пустой tx с крошечным `gas_limit` вытеснить крупную без покрытия её floor).
    - Если `new_density == low_density`: требуется `new_fee >= low_fee + eviction_premium(low_fee)` (`ceil(low_fee / 20).max(1)`, как в `mempool.rs:1100`).
    - Если `new_density < low_density`: отказ (`false`).
  - **`Mempool::load_into` (`mempool.rs:1562-1652`)**: при изменении типа ключа `Mempool::order` добавить `MP04` magic-префикс с fallback-декодером `MP03` / `MP02` / legacy (перестроение `order` циклом `insert`), чтобы не сломать существующие `data/mempool.bin` при рестарте.
  - **Инвариант**: `Mempool::required_fee_for_tx(tx) = effective_floor_for_tx(tx).saturating_add(tx.priority_fee_per_gas)` (`mempool.rs:1111-1114`) и `consensus_step.rs:774` **остаются строгими**; `priority_fee_per_gas` по-прежнему полностью покрывается `tx.gas_limit`.

#### 2.2.2 Начисление `priority_fee_per_gas` и Burn/Reward Split в `apply()` (за гейтом)
- **Activation Gate**: `pub const FEE_MARKET_V2_ACTIVATION_HEIGHT: u64 = u64::MAX;` в `stellereum/src/state_engine/apply.rs` (или `tokenomics.rs`) + регистрация в `chain_spec::current_activation_schedule()` (`chain_spec.rs:255-311`), плюс `#[cfg(any(test, debug_assertions))]` thread-local override (по шаблону `UPGRADE_EXEC_ACTIVATION_HEIGHT` / `QC_SPLIT_ACTIVATION_HEIGHT`). Пока значение `u64::MAX`, поведение `apply()` на всех высотах **побайтово идентично текущему**.
- **Списание `priority_fee_per_gas` при `fee_market_v2_active_at(height)`**:
  - Начисленный газ + приоритет:
    ```text
    base_charged = billed_gas(tx, gas_used).max(floor_base)
    priority_charged = tx.priority_fee_per_gas
    // Cap at declared tx.gas_limit? Нет: если tx была допущена consensus_step.rs:774,
    // tx.gas_limit >= floor + priority_fee_per_gas; на прямом/ручном block apply
    // cap `.min(tx.gas_limit)` защищает от списания сверх подписанного tx.gas_limit,
    // причём минимальный обязательный пол = floor_base.min(tx.gas_limit) или max(floor_base):
    fee_core = billed_gas(tx, gas_used)
        .saturating_add(tx.priority_fee_per_gas)
        .min(tx.gas_limit.max(floor_base))
        .max(floor_base)
    fee_with_surcharge = fee_core.saturating_add(surcharge)
    ```
    Для `failure_fee_for` (attributable failure):
    ```text
    fail_core = Self::TX_INTRINSIC_GAS
        .saturating_add(tx.priority_fee_per_gas)
        .min(tx.gas_limit.max(floor_base))
        .max(floor_base)
    fail_fee = fail_core.saturating_add(surcharge)
    ```
    *Гарантия*: (а) при `priority_fee_per_gas == 0` формула **совпадает** с текущей `fee_for_gas` / `failure_fee_for`; (б) подписавший не платит больше `tx.gas_limit + surcharge` (если только `floor_base` выше `gas_limit`); (в) валидная в мемпуле транзакция (`gas_limit >= floor + priority`) **всегда** платит свой `priority_fee_per_gas` целиком, даже если `gas_used < gas_limit`.
  - В `apply_block_parallel_fees_with_events_at_height` и `plan_plain_tx` (`state_engine/parallel.rs:151-156`) передаётся `fee_market_v2_active: bool` (вычисленное из `block.height`), чтобы parallel plain wave и sequential apply давали **побайтово идентичный** `state_root` и `tx_fees`.
- **Разделение комиссий (Burn / Proposer / Staking Pool) при `fee_market_v2_active_at(height)`**:
  - Параметры разделения (по умолчанию, в bps от `BPS_DENOMINATOR = 10_000`, сумма `== 10_000`):
    - `DEFAULT_FEE_BURN_BPS: u64 = 5_000` (50% сжигается навсегда);
    - `DEFAULT_FEE_PROPOSER_BPS: u64 = 3_000` (30% уходит напрямую `block.proposer`);
    - `DEFAULT_FEE_STAKING_BPS: u64 = 2_000` (20% уходит в пул наград стейкинга, если `block.proposer` в наборе валидаторов и имеет делегаторов/активный стейк; иначе — в `proposer_share`).
  - Разделение считается в **`u128` по всему блоку целиком** (не по-транзакционно, чтобы не множить остатки на `N_tx` и не зависеть от разбиения волн) на уровне `apply_block_transition` (`state_engine/apply.rs:2812-2819`):
    ```text
    burn_nano    = ((fees as u128) * (burn_bps as u128) / 10_000) as u64
    staking_nano = ((fees as u128) * (staking_bps as u128) / 10_000) as u64
    proposer_nano = fees - burn_nano - staking_nano   // точный остаток, без потери ни 1 nano!
    ```
  - **Инвариант сохранения стоимости и `1B` supply cap**:
    1. **Никакого `mint_native` / `reserve_mint`**: все `fees` уже дебетованы с отправителей на шаге 1 `apply_block_transition`.
    2. `burn_nano` **не зачисляется никуда** (уменьшает циркулирующее предложение на балансах и **НЕ** декрементирует `total_minted_nano` — `TOTAL_SUPPLY_CAP` остаётся строгой верхней границей **валовой эмиссии за всё время**, `docs/SUPPLY_CAP.md:13-16`).
    3. `proposer_nano` зачисляется через `credit_native_transfer(&block.proposer, proposer_nano)`.
    4. `staking_nano` (если > 0 и `staking.distribute_fee_reward(block.proposer, staking_nano)` разрешён — i.e. валидатор не jailed и существует; при отказе перенаправляется в `proposer_nano`):
       - **критично**: используется отдельный метод `StakingLedger::distribute_fee_reward` (не `distribute_reward`!), который **НЕ увеличивает `staking.rewards_minted`** и **НЕ проверяет `REWARDS_EMISSION_CAP`** (так как это перенос существующих комиссий, а не эмиссия новых монет!), но увеличивает `staking.rewards_pool` и начисляет доли через `ValidatorRewardState::accrue` + `credit_native_transfer(&REWARDS_POOL, staking_nano)` — сохраняя 1:1 покрытие `REWARDS_POOL` без нарушения `350M` emission cap и `1B` supply cap!
    5. Сумма инвариантна: `burn_nano + proposer_nano + staking_nano == fees` (с точностью до 0 nano).
- **Governance-расширение (опционально, строго append-only)**: при добавлении `GovAction::SetFeeSplitBps { burn_bps, proposer_bps, staking_bps }` добавлять строго **в конец** `enum GovAction` (`governance.rs:345`) с проверкой `burn_bps + proposer_bps + staking_bps == 10_000` и привязкой тега в `commitment.rs` (conditional, как `min_gas_limit` в `commitment.rs:751`).

---

### 2.3 Контракт 2: Sub-Nano Exactness & Carry (закрытие P2)

1. **Граница EVM Wei ↔ Nano-STELL (`evm_adapter/types.rs`, `evm_adapter/binding.rs`, `svm.rs`)**:
   - Ввести `pub fn wei_to_nano_exact(wei: u128) -> Result<u64, String>`:
     - Если `wei % WEI_PER_NANO != 0` → `Err("sub-nano wei remainder ...: value must be a multiple of 1_000_000_000 wei")` (никакого молчаливого усечения).
     - Если `wei / WEI_PER_NANO > u64::MAX as u128` → `Err("wei amount overflows u64 nano-STELL")` (никакого `saturating` усечения до `u64::MAX`).
   - **Совместимость**:
     - На RPC/admission (`eth_sendRawTransaction` / `build_carrier_tx` / `Mempool::check_evm_payload`) `wei_to_nano_exact` можно включить немедленно (fail-closed для новых пользовательских транзакций).
     - В консенсусе (`evm_transfer_facts` в `evm_adapter/binding.rs:187`, вызываемом из `svm.rs` через `verify_carrier_intent`) строгая проверка включается за гейтом `SUB_NANO_STRICT_ACTIVATION_HEIGHT: u64 = u64::MAX` (`chain_spec.rs`), чтобы исторические блоки (если бы содержали carrier с не-кратным wei) ре-применялись детерминированно.
     - Утилита `wei_to_nano` в `evm_adapter/types.rs:1318` сохраняется для обратной совместимости legacy-тестов и read-only `EV1` симуляции, с явным `#[deprecated]` / doc-контрактом.
2. **Точная рациональная арифметика без промежуточного усечения (`tokenomics.rs`)**:
   - `GenesisVault::calculate_mint(asset_amount, asset_decimals, price_micro_usd)` (`tokenomics.rs:270-292`): заменить двухступенчатое деление `(asset * price / 10^d) * 10^9 / 250_000` на одноступенчатый 256-битный `mul_div_floor_256(asset_amount as u128 * price_micro_usd as u128, 1_000_000_000u128, 10u128.pow(asset_decimals) * BASE_STELL_PRICE_MICRO_USD as u128)` (чистый целочисленный helper в `tokenomics.rs`, без внешних крейтов, без `f64`). Устраняет двойное округление вниз и сохраняет точный остаток при делении.
   - `GenesisVault::calculate_mint_with_carry(&mut self, ...)` (или `remainder_den` в `GenesisVault` при необходимости): опциональный перенос суб-нано остатка по одному знаменателю — только за тем же гейтом, если `GenesisVault` используется on-chain.
3. **Carry в `ValidatorRewardState::accrue` (`staking.rs:971-1013`)**:
   - При изменении `delegated` (`self.remainder_den != delegated`) вместо обнуления `self.remainder = 0`:
     ```text
     if self.remainder_den > 0 && self.remainder > 0 {
         // Перемасштабируем остаток из старого знаменателя в новый (без деления на 0),
         // сохраняя точный смысл fraction = remainder / old_den:
         // new_rem = floor(old_rem * new_den / old_den)
         self.remainder = mul_div_floor(self.remainder, delegated as u128, self.remainder_den as u128);
     } else {
         self.remainder = 0;
     }
     self.remainder_den = delegated;
     ```
     Это сохраняет до `old_den - 1` долей `1 / REWARD_PER_TOKEN_SCALE` при ротации/изменении делегаций, гарантированно удовлетворяет `self.remainder < delegated` (`0 <= new_rem < new_den`, т.к. `old_rem < old_den`) и никогда не перерасходует `rewards_pool` (floor при ремасштабировании не может раздуть остаток).
   - **Гейт**: изменение логики `accrue` меняет `ValidatorRewardState` в `commitment.rs`, поэтому активируется строго при `height >= SUB_NANO_STRICT_ACTIVATION_HEIGHT` (передаётся в `distribute_reward_at_height` / `distribute_fee_reward`).
4. **Carry в геометрической эмиссии (`tokenomics.rs:562-656`)**:
   - Ввести детерминированный `pow_half_fixed_exact_q64(r0_nano, half_life_blocks, height) -> (u64 /* floor */, u64 /* frac_q64 */)` (текущий `pow_half_fixed` уже вычисляет `scaled = (r0_nano * acc) >> 64` и теряет нижние 64 бита `(r0_nano * acc) & ((1 << 64) - 1)` и сдвинутые `whole` биты).
   - С внешним состоянием `emission_carry_q64: u64` (хранимым в `StakingLedger` / отдельном conditional-поле):
     `total_q64 = (exact_scaled_q64) + (carry_q64 as u128)`; `emit_nano = (total_q64 >> 64) as u64`; `new_carry_q64 = total_q64 as u64`.
   - **Жёсткий инвариант `1B` cap**: даже с carry каждый выпуск проходит через `reserve_mint(emit_nano)` и `rewards_minted + emit_nano <= REWARDS_EMISSION_CAP` (`apply.rs:2837`, `staking.rs:4080-4086`); в конце горизонта carry не может вытолкнуть сумму за пределы `P = 350M STELL` или `TOTAL_SUPPLY_CAP = 1B STELL`.
5. **Отказ от `f64` в `eth_feeHistory` (`evm_adapter/adapter.rs:2258`)**: заменить `((max_priority_fee as f64) * (p / 100.0)).round() as u128` на целочисленное деление с округлением к ближайшему в миллионных долях bps (`p_micro = (p * 10_000.0) as u128`, `(max_priority_fee * p_micro + 500_000) / 1_000_000`).

---

### 2.4 Контракт 3: History API & Bounded `getProgramAccounts`-аналог

#### 2.4.1 Secondary indexes в `stellereum/src/storage.rs` (без изменения `Block` / `state_root`)
Новые **аддитивные** sled-деревья (старые `data/` открываются без миграции; при `archive == false` очищаются синхронно с `prune_receipts_below`):
1. `tx_by_addr`:
   - Ключ (44 байта, fixed-width): `addr[32] || (!height).to_be_bytes()[8] || (!tx_index).to_be_bytes()[4]` (обратный порядок для быстрого tip-first range scan!).
   - Значение: `tx_hash[32]`.
   - Записывается для `tx.from` и (если `tx.to != tx.from`) `tx.to`, а также для `sponsor` (если `tx.effective_sponsor()`).
2. `events_by_contract`:
   - Ключ (48 байт): `contract[32] || (!height).to_be_bytes()[8] || (!tx_index).to_be_bytes()[4] || (!log_index).to_be_bytes()[4]`.
   - Значение: `bincode(StoredContractEvent { tx_hash, topic, value })` (ограничен `MAX_SMALL_RECORD_DECODE_BYTES`).
3. Расширение `StoredReceipt` (`storage.rs:596-606`):
   - Либо отдельное дерево `receipt_meta_v2` (`tx_hash[32] -> bincode(StoredReceiptMetaV2 { from, to, amount, shard_id, timestamp })`), чтобы `decode_receipt` (`storage.rs:635-662`) для `receipts_v1` оставался **100% совместимым** и не ломал существующие тесты/снимки!
4. Константные лимиты сканирования в `storage.rs`:
   - `STORAGE_HISTORY_MAX_LIMIT: usize = 200` (на один запрос).
   - `STORAGE_SCAN_HARD_CAP: usize = 10_000` (максимум прочитанных ключей за один вызов, включая отфильтрованные по `role` / `from_height` / `to_height`).

#### 2.4.2 Новые и обновлённые RPC-методы ноды (`stellereum/src/rpc/reads.rs`, `rpc/cache.rs`)
Единый формат курсорной пагинации (заменяет ненадёжный `offset` на всех новых методах и фиксит `HashMap`-недетерминизм в `stell_listTokens`):
- **Параметры**: `{ cursor?: String, limit?: u64 }`
  - `DEFAULT_PAGE_LIMIT = 50`, `MAX_PAGE_LIMIT = 200` (жёсткий cap). Для `stell_listTokens` — обратная совместимость при передаче `offset` (но итерация сначала сортирует ключи или использует `BTreeMap`-снимок с hard cap `MAX_TOKENS_SORT_CAP = 50_000`, при `cursor` — строго keyset `token_id > cursor`).
- **Лимиты для `getProgramAccounts`-аналога**:
  - `MAX_PROGRAM_ACCOUNTS_LIMIT: usize = 100` (жёстко `<= 200`).
  - `MAX_PROGRAM_ACCOUNTS_SCAN: usize = 10_000` (максимум инспектируемых записей за один RPC-вызов; при достижении лимита возвращается `next_cursor` и `"scan_truncated": true`, гарантируя bounded CPU и отсутствие блокировки RwLock).
  - `MAX_PROGRAM_ACCOUNTS_RESPONSE_BYTES: usize = 2 * 1024 * 1024` (2 MiB).
  - `MAX_PROGRAM_ACCOUNTS_PROOFS: usize = 16` (если `with_proof: true`, возврат CPAT2-доказательств ограничен 16 аккаунтами на страницу и метод тарифицируется как `expensive-ws`).

Спецификация методов:
1. **`stell_getAddressHistory`**:
   - Params: `{ address: String, from_height?: u64, to_height?: u64, role?: "all" | "sender" | "recipient", cursor?: String, limit?: u64 }` (`cursor` = hex-кодированные `(height: u64, tx_index: u32)` = 12 байт).
   - Источник: `ReceiptIndex` (свежие в памяти) + `ArchiveStore::address_history(...)` (`tx_by_addr`), дедупликация по `tx_hash`, без блокировки consensus-потоков.
   - Ответ: `{ address, items: [...], next_cursor: Option<String>, has_more: bool }`.
2. **`stell_getProgramAccounts`** (bounded аналог Solana `getProgramAccounts`):
   - Params:
     ```json
     {
       "program": "token" | "contract" | "system",
       "token": "<hex|Stl57, optional>",
       "contract": "<hex|Stl57, optional>",
       "owner": "<hex|Stl57, optional>",
       "creator": "<hex|Stl57, optional>",
       "min_balance": "<u64 str, optional>",
       "slot_from": "<i64, optional>",
       "slot_to": "<i64, optional>",
       "with_proof": false,
       "cursor": "<hex, optional>",
       "limit": 50
     }
     ```
   - Защита от полного дампа: для `program == "system"` **обязателен** хотя бы один фильтр (`owner` или префикс / `min_balance > 0` при явном курсоре) и `with_proof` ограничивает `limit <= 16`. Для `program == "token"` обязателен `token` или `owner`. Для `program == "contract"` обязателен `contract` (возвращает storage-слоты отсортированные по `i64` ключу) или `creator` (возвращает контракты создателя без raw `code` байткода по умолчанию, если не запрошен `include_code: false` cap).
   - **Детерминизм порядка**: ключи внутри одного вызова перебираются в детерминированном лексикографическом/числовом порядке (через отсортированный индекс ключей, чтобы `next_cursor` был строго монотонным и не зависел от рандома `HashMap`).
   - Ответ: `{ program, items: [...], next_cursor: Option<String>, has_more: bool, scanned: usize, scan_truncated: bool }`.
3. **`stell_getTokenAccountsByOwner`**:
   - Params: `{ owner: String, token?: String, include_zero?: bool, cursor?: String, limit?: u64 }`.
   - Возвращает токены и балансы `owner` в детерминированном порядке `token_id`, с `next_cursor` и `limit <= 200`.
4. **Обновление `stell_getEvents`**:
   - Добавляется `cursor?: String` (`height(8BE) || tx_index(4BE) || log_index(4BE)`) и опциональный `topic?: i64`; если диапазон `from_block..to_block` выходит за пределы in-memory `ReceiptIndex`, читает `events_by_contract` из `archive_store` (`storage.rs`), сохраняя обратную совместимость старого array-ответа без `cursor` и возвращая `{ events, next_cursor, has_more }` при явном `paginated: true` или передаче `cursor`.
5. **Rate-limit регистрация**: `stell_getProgramAccounts`, `stell_getAddressHistory`, `stell_getTokenAccountsByOwner` регистрируются в `rpc_rate_buckets` (`rpc/streams.rs:1278`) с `["transport", "expensive-ws"]` и в `is_ws_expensive_method` (`streams.rs:1048`).

#### 2.4.3 Контракт индексатора (`stellereum-indexer/src/{db.rs, server.rs}`)
- **Keyset Cursor Pagination** (дополнение к `offset`, для новых/v2 маршрутов без ломки старых):
  - Курсор для tx: `cursor = "<block_height>:<tx_index>"`, SQL: `WHERE (block_height < ?h) OR (block_height = ?h AND tx_index < ?idx) ORDER BY block_height DESC, tx_index DESC LIMIT ?limit`.
  - Курсор для events: `cursor = "<block_height>:<id>"`.
  - Курсор для blocks: `cursor = "<height>"`.
  - `MAX_EVENT_PAGE = 200`, `MAX_HISTORY_PAGE = 200`.
- **Новые таблицы SQLite (`db.rs`)**:
  - `token_balances (shard_id INTEGER NOT NULL DEFAULT 0, token_id TEXT NOT NULL, owner TEXT NOT NULL, balance TEXT NOT NULL, updated_height INTEGER NOT NULL, PRIMARY KEY (shard_id, token_id, owner))` + `CREATE INDEX idx_tb_owner ON token_balances(owner, token_id)`.
  - `contracts (shard_id INTEGER NOT NULL DEFAULT 0, address TEXT PRIMARY KEY, creator TEXT, code_hash TEXT, deploy_height INTEGER NOT NULL, has_abi INTEGER NOT NULL DEFAULT 0)` + `CREATE INDEX idx_contracts_creator ON contracts(creator, deploy_height)`.
- **Новые REST endpoints (`server.rs`)**:
  - `GET /api/v2/account/:address/tokens?cursor=&limit=`
  - `GET /api/v2/token/:token/holders?cursor=&limit=`
  - `GET /api/v2/program/:program/accounts?...&cursor=&limit=` (проксирует/агрегирует `contracts` / `token_balances` или `stell_getProgramAccounts` с `limit <= 100`).
  - Добавление `cursor` query param в `/api/v2/account/:address/txs`, `/api/v2/events`, `/api/v2/blocks`, `/api/v2/contracts`.

---

### 2.5 Контракт 4: Geyser-лайт (поток финализированных событий SSE/WS, без плагинного ABI)

1. **Архитектурный принцип (Zero Consensus Blocking, No Plugin ABI)**:
   - Все публикации идут **только** для финализированных (или явно ретрактированных через `Invalidations`) данных из `record_lane` (`node/consensus_driver.rs:3925-3946`) и `invalidation_sink` (`consensus_driver.rs:347-351`), **вне** блокировок `state.accounts` / `receipts` (`rpc/state.rs:611`).
   - Медленные или отключённые потребители **никогда** не блокируют `apply()`, `record_lane` или `SubscriptionHub::publish`.
   - Никакого FFI / `.so` / dynamic loading плагинов: транспорт — исключительно JSON-RPC over WebSocket (`GET /ws`) и SSE (`GET /events`) на ноде + SSE (`GET /api/v2/stream`) на индексере.
2. **Фикс `shard_id` на ноде (`rpc/state.rs:465-471`)**:
   - `RpcState::record_block` обязан передавать `self.engine.shard_id()`, а не захардкоженный `crate::sharding::MASTERCHAIN_SHARD` (`rpc/state.rs:468`).
3. **Расширение `SubscriptionTopic` и конверта `Notification` (`rpc/streams.rs`)**:
   - Новые варианты `SubscriptionTopic` (`streams.rs:48-70`):
     - `AccountUpdates { accounts: Vec<String> }` (`1 <= accounts.len() <= MAX_SUBSCRIPTION_ACCOUNTS = 32` — подписка на «все аккаунты мира» запрещена на публичном сокете).
     - `TokenTransfers { token: Option<String>, owner: Option<String> }` (фильтрация по `token_id` и/или `owner`).
   - Расширение `Notification` (обратно-совместимые опциональные поля с `#[serde(default, skip_serializing_if = "Option::is_none")]`):
     - `seq: Option<u64>` — строго монотонный глобальный счётчик событий `SubscriptionHub` (удобен для `after_seq` / детекции пропусков);
     - `shard_id: Option<u32>`, `height: Option<u64>`.
   - **Replay ring-buffer и сигнал о лаге**:
     - В `SubscriptionHub` добавляется ограниченный буфер `GEYSER_REPLAY_WINDOW: usize = 512` последних опубликованных `(seq, SubscriptionTopic, NotificationPayload)` (защищённый sync `Mutex`, никогда не держится через `.await`).
     - При подписке с `after_seq` (`params.after_seq`): если `after_seq` ещё в окне `[oldest_seq..=latest_seq]`, подходящие события отдаются клиенту **до** перехода в live-поток (с капом `MAX_REPLAY_BURST = 256` за один attach); если `after_seq < oldest_seq` — явный отказ `-32005` (`"replay cursor expired; backfill via RPC/indexer"`), никогда молчаливая дыра.
     - При `RecvError::Lagged(skipped)` в `sse_handler` (`streams.rs:965`) и `handle_ws_with_timeout` (`streams.rs:1532`): транспорт отправляет клиенту структурированное уведомление `{"subscription": "*", "lagged": skipped, "oldest_available_seq": ..., "action": "backfill_required"}` (в SSE — `event: lagged\ndata: ...\n\n`), вместо молчаливого пропуска.
4. **Границы и DoS-лимиты Geyser-лайт (не ослаблять существующие)**:
   - `MAX_SUBSCRIPTIONS = 4096` (`streams.rs:21`)
   - `MAX_SUBSCRIPTIONS_PER_CLIENT = 64` (`streams.rs:30`)
   - `WS_MAX_SUBS_PER_CONNECTION = 16` (`streams.rs:1087`)
   - `WS_MAX_MESSAGE_BYTES = 1 MiB` (`streams.rs:1076`)
   - `MAX_SUBSCRIPTION_TOPICS = 32` (`streams.rs:674`)
   - `MAX_SUBSCRIPTION_ACCOUNTS = 32` (новый константный лимит)
   - `GEYSER_REPLAY_WINDOW = 512` (новый константный лимит)
   - `STREAM_BROADCAST_CAPACITY = 1024` (или `2048`)
   - `SSE_IDLE_TIMEOUT_SECS = 300`, `WS_IDLE_TIMEOUT_SECS = 300`
5. **Интеграция в `stellereum-indexer`**:
   - **Push-подписка (`syncer.rs`)**: `Syncer` подключается к ноде через SSE (`GET /events?topics=newHeads,newTxs,events,invalidations` поверх уже существующего `reqwest::Client::get(...).send().await` + `resp.chunk().await`, **без новых внешних зависимостей**) или WS, триггеря немедленный `sync_step()` при новом `newHeads` и немедленный откат/перепроверку при `invalidations`, сохраняя `400ms` HTTP polling fallback при обрыве потока или отставании `db_tip < node_tip`.
   - **Публичный SSE-стрим индексера (`server.rs`)**: `GET /api/v2/stream?topics=newHeads,newTxs,events&contract=&address=&shard_id=&after_seq=` поверх внутреннего `tokio::sync::broadcast` (емкость `1024`), с лимитом `MAX_INDEXER_SSE_CLIENTS = 256` и `SSE_IDLE_TIMEOUT_SECS = 300`.

---

## 3. Матрица непересекающегося владения файлами, порядок эшелонов и обязательные тесты W4

### 3.1 Матрица владения файлами (`AGENTS.md` §2, §8)

Каждый эшелон имеет **строго непересекающийся** набор файлов; ни один файл не редактируется двумя эшелонами одновременно:

| Эшелон | Область и ответственность | Разрешённые файлы (строго не пересекаются) | Запрещено трогать |
|---|---|---|---|
| **E1: Fee Market & Priority Ordering** | Fee-density ordering в `Mempool` (`MP04` + fallback), гейтированное списание `priority_fee_per_gas` и burn/proposer/staking split в `apply`, регистрация W4-гейтов в `chain_spec.rs` | `stellereum/src/mempool.rs`, `stellereum/src/runtime/mev_sync.rs`, `stellereum/src/runtime/consensus_step.rs`, `stellereum/src/state_engine/apply.rs`, `stellereum/src/state_engine/parallel.rs`, `stellereum/src/state_engine/types.rs`, `stellereum/src/chain_spec.rs`, `stellereum/tests/w4_priority_fee_tests.rs` (new) | `staking.rs`, `tokenomics.rs`, `evm_adapter/**`, `storage.rs`, `rpc/**`, `stellereum-indexer/**`, `protocol.rs` (до решения об активации) |
| **E2: Sub-Nano Exactness & Carry** | `wei_to_nano_exact` на EVM carrier-границе, 256-bit exact rational в `GenesisVault`, rescale carry в `ValidatorRewardState::accrue`, Q0.64 carry в `pow_half_fixed`, integer `eth_feeHistory`, `distribute_fee_reward` в `staking.rs` (вызываемый из E1 или E2 wiring — см. порядок ниже) | `stellereum/src/evm_adapter/types.rs`, `stellereum/src/evm_adapter/binding.rs`, `stellereum/src/evm_adapter/tx.rs`, `stellereum/src/evm_adapter/adapter.rs`, `stellereum/src/svm.rs`, `stellereum/src/tokenomics.rs`, `stellereum/src/staking.rs`, `stellereum/tests/w4_sub_nano_tests.rs` (new) | `mempool.rs`, `state_engine/apply.rs`, `state_engine/parallel.rs`, `chain_spec.rs` (E2 читает/экспортирует свою константу, регистрация в `chain_spec.rs` уже добавлена в E1), `storage.rs`, `rpc/**`, `stellereum-indexer/**` |
| **E3: Storage Indexes & Node History / `getProgramAccounts`** | Вторичные sled-индексы (`tx_by_addr`, `events_by_contract`, `receipt_meta_v2`) + bounded prune, детерминированные итераторы в `token.rs`/`contract.rs`, курсорные RPC `stell_getAddressHistory`, `stell_getProgramAccounts`, `stell_getTokenAccountsByOwner`, обновление `stell_getEvents` и `stell_listTokens` | `stellereum/src/storage.rs`, `stellereum/src/token.rs`, `stellereum/src/contract.rs`, `stellereum/src/rpc/reads.rs`, `stellereum/src/rpc/cache.rs`, `stellereum/tests/w4_history_program_accounts_tests.rs` (new) | `rpc/streams.rs`, `rpc/state.rs`, `node/**`, `state_engine/**`, `mempool.rs`, `stellereum-indexer/**` |
| **E4: Geyser-Lite Streaming (Node)** | Фикс `shard_id` в `record_block`, `seq` + `GEYSER_REPLAY_WINDOW` + `after_seq` + `Lagged` frame, топики `AccountUpdates` и `TokenTransfers`, регистрация новых методов E3 в `rpc_rate_buckets` / `is_ws_expensive_method`, публикация дельт из `record_lane` | `stellereum/src/rpc/streams.rs`, `stellereum/src/rpc/state.rs`, `stellereum/src/node/consensus_driver.rs`, `stellereum/tests/w4_geyser_stream_tests.rs` (new) | `rpc/reads.rs`, `rpc/cache.rs`, `storage.rs`, `state_engine/**`, `mempool.rs`, `stellereum-indexer/**` |
| **E5: Indexer Upgrade** | Keyset cursor pagination, таблицы `token_balances`/`contracts`, SSE/WS push-синхронизация в `syncer.rs`, обработка `invalidations`, публичный SSE `GET /api/v2/stream` и новые v2 endpoints | `stellereum-indexer/src/db.rs`, `stellereum-indexer/src/syncer.rs`, `stellereum-indexer/src/server.rs`, `stellereum-indexer/src/events.rs`, `stellereum-indexer/tests/w4_indexer_tests.rs` (new) | Весь `stellereum/**` |

> **Примечание по связке `E1 <-> E2` (`distribute_fee_reward` и `SUB_NANO_STRICT_ACTIVATION_HEIGHT`)**: чтобы E1 и E2 не пересекались по файлам:
> - **Вариант А (последовательно E2 -> E1)**: сначала E2 добавляет `SUB_NANO_STRICT_ACTIVATION_HEIGHT` и `StakingLedger::distribute_fee_reward` в `staking.rs` / `tokenomics.rs`; затем E1 подключает `distribute_fee_reward` в `state_engine/apply.rs` и регистрирует оба гейта (`FEE_MARKET_V2_ACTIVATION_HEIGHT`, `SUB_NANO_STRICT_ACTIVATION_HEIGHT`) в `chain_spec.rs`.
> - **Параллелизм**: `E2`, `E3`, `E4` и `E5` могут выполняться **одновременно** в 4 независимых worktree (`E1` стартует сразу после `E2` по `staking.rs` либо без `staking_bps` до его приёмки); внутри `stellereum/src/rpc/` `E3` (`reads.rs`, `cache.rs`) и `E4` (`streams.rs`, `state.rs`) не пересекаются ни по одному файлу (`E4` лишь вносит имена методов E3 в `rpc_rate_buckets` и `is_ws_expensive_method`).

### 3.2 Обязательный список тестов W4

Каждый кодовый агент W4 обязан сдать тесты с проверкой «падало до / прошло после» (`docs/OPEN_DEFECTS.md:149`) и пройти полный гейт (`cargo clippy --all-targets -- -D warnings`, `cargo test --no-fail-fast`, для E1/E2 — `consensus_liveness_harness`):

1. **Priority Fee & Fee Market (`E1` — `w4_priority_fee_tests.rs`)**:
   - `mempool_fee_density_orders_small_high_density_ahead_of_bloated_low_density`: две допустимые транзакции — малая `280k` gas с `priority = 50_000` (плотность `~0.178`) опережает крупную `10M` gas с `priority = 100_000` (плотность `0.01`) в `select_for_block_multi`; `MP04` ↔ `MP03` обратная совместимость загрузки.
   - `fee_market_v2_pre_activation_byte_identical`: при `FEE_MARKET_V2_ACTIVATION_HEIGHT == u64::MAX` `apply_block_transition` даёт побайтово тот же `state_root` и `tx_fees`, что до патча.
   - `fee_market_v2_charges_priority_fee_at_apply_and_parallel_parity`: при `height >= activation` `priority_fee_per_gas` реально списывается как на sequential, так и на parallel plain wave путях (`parallel_root == sequential_root`, `applied_fees == debited`).
   - `fee_split_burn_proposer_staking_exact_conservation_and_1b_cap`: сумма `burn + proposer + staking == fees` без потери ни 1 nano; при достижении `TOTAL_SUPPLY_CAP` и `REWARDS_EMISSION_CAP` перенос комиссий (`credit_native_transfer` / `distribute_fee_reward`) **работает** и **не** разблокирует сгоревший headroom в `total_minted_nano` (следующий `mint_native` по-прежнему отклонён fail-closed).

2. **Sub-Nano Exactness & Carry (`E2` — `w4_sub_nano_tests.rs`)**:
   - `evm_carrier_rejects_sub_nano_wei_when_strict`: `1_500_000_000` wei (1.5 nano) отклоняется с явной ошибкой; `2_000_000_000` wei (2.0 nano) принимается и удовлетворяет `nano_to_wei(value_nano) == value_wei`.
   - `genesis_vault_single_step_rational_avoids_double_truncation`: дробные депозиты (например USDT 6 decimals при некруглой цене) не теряют промежуточные микро-USD до умножения на `10^9`.
   - `staking_accumulator_rescales_remainder_on_delegation_change`: изменение `delegated` в `ValidatorRewardState::accrue` сохраняет перемасштабированный остаток (`0 <= remainder < new_den`), не обнуляя накопленную дробную часть и никогда не перерасходуя `rewards_pool`.
   - `geometric_emission_with_q64_carry_never_exceeds_emission_cap_or_1b_cap`: на малых `H` сумма с Q0.64-carry сходится точнее к `P` (меньше dust-дефицита) и строго `<= REWARDS_EMISSION_CAP <= TOTAL_SUPPLY_CAP`.

3. **History API & Bounded `getProgramAccounts` (`E3` — `w4_history_program_accounts_tests.rs`)**:
   - `storage_address_history_survives_restart_and_pruning`: `tx_by_addr` и `events_by_contract` индексируют финализированные блоки, переживают reopen `Storage`, поддерживают курсор `stell_getAddressHistory` без дублей/пропусков и синхронно удаляются в `prune_receipts_below`.
   - `stell_list_tokens_deterministic_under_cursor`: при >100 токенах курсорная пагинация проходит все токены ровно один раз без смещения из-за `HashMap`.
   - `stell_get_program_accounts_enforces_bounds_and_filters`: проверка `MAX_PROGRAM_ACCOUNTS_LIMIT = 100`, `MAX_PROGRAM_ACCOUNTS_SCAN = 10_000` (`scan_truncated: true` + `next_cursor`), `MAX_PROGRAM_ACCOUNTS_PROOFS = 16`, отказ на незафильтрованный `program: "system"` dump и корректный возврат `token` / `contract` / `stell_getTokenAccountsByOwner`.

4. **Geyser-Lite Streaming (`E4` — `w4_geyser_stream_tests.rs`)**:
   - `stream_new_heads_reports_real_workchain_shard_id`: на workchain-ноде (`shard_id = 1`) `newHeads` публикует `shard_id: 1`, а не `0`.
   - `stream_seq_replay_and_lagged_notice`: монотонный `seq`, успешный `after_seq` replay внутри `GEYSER_REPLAY_WINDOW`, отказ `-32005` за пределами окна, и доставка explicit `lagged`-фрейма на WS/SSE при переполнении `broadcast`.
   - `stream_account_updates_and_token_transfers_caps_and_nonblocking`: соблюдение `MAX_SUBSCRIPTION_ACCOUNTS = 32`, публикация дельт при финализации, и доказательство, что зависший/отключённый SSE/WS-клиент не задерживает `record_block`.
   - `rate_bucket_table_covers_every_public_method`: существующий тест инварианта в `rpc/tests.rs` зелёный для всех новых методов из E3 и E4.

5. **Indexer Upgrade (`E5` — `w4_indexer_tests.rs`)**:
   - `indexer_keyset_cursor_stable_under_concurrent_inserts`: вставка новых блоков/транзакций/событий между запросами страниц не сдвигает и не дублирует элементы при курсорной пагинации.
   - `indexer_token_balances_and_contracts_tables_and_reorg_cleanup`: индексация токенов/контрактов и откат при смене хэша `(shard_id, height)` / `invalidations`.
   - `indexer_sse_push_sync_and_stream_endpoint`: `Syncer` реагирует на mock SSE `newHeads`/`invalidations`, а `/api/v2/stream` отдаёт отфильтрованные SSE-события и корректно завершается по `MAX_INDEXER_SSE_CLIENTS` / idle timeout.
