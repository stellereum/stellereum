# Faucet, Receipt Hydration & Explorer Hardening Contract (HDAE, code truth)

Статус: **архитектурный и интеграционный контракт** (закрывает подтверждённые по `VERIFY-FAUCET-RECEIPTS` дефекты 1–5).
Зафиксировано по фактическому чтению дерева `stellereum/src/**` и `stellereum/tests/**` на 2026-11-21 (`CONSENSUS_RULESET_VERSION = 6`, `FORK_ID = 0x0f584a46`, `COMMITMENT_VERSION = 5`).

> **Правило замороженного ядра (`AGENTS.md` §7).**
> 1. Все исправления в данном контракте относятся к локальной долговечности (`storage.rs`, `"faucet_v2"`, `"receipts_by_height"`), политике/доступу крана (`rpc/faucet.rs`, `rpc/writes.rs`, `explorer.rs`), RPC/HTTP-шлюзу (`explorer.rs`, `rpc/reads.rs`, `rpc/state.rs`), read-only хелперам пула (`mempool.rs`) и клиентскому подписанию CLI (`cli/*`).
> 2. Ни одно изменение не затрагивает `apply()`, `Block::compute_hash()`, `QuorumCertificate`, `state_root`, `COMMITMENT_VERSION = 5` или `FORK_ID = 0x0f584a46`.
> 3. **Защита bincode-форматов (`storage.rs:545-552`):** `BlockHeaderRecord`, `StoredReceipt` и `DomainSnapshot` (`DomainSnapshotV1..V3`) сохраняют 100% обратную совместимость с существующими директориями данных; новые персистентные индексы добавляются исключительно через аддитивные деревья `sled` (`"receipts_by_height"`, `"faucet_v2"`) и мета-ключи (`"faucet_initialized_v1"`, `"receipts_by_height_v1"`).

---

## 1. Инвентаризация подтверждённых дефектов (`VERIFY-FAUCET-RECEIPTS`, code truth)

| ID | Компонент | Факт в коде (`file:line`) | Последствие |
|---|---|---|---|
| **D1** | Потеря новых receipts и EVM-индексов при `> 50_000` записях | `stellereum/src/storage.rs:1355-1364` (`all_receipts_capped`), `:1231-1234` (`put_receipt`), `:1317-1346` (`prune_receipts_below`), `:870` (`receipts_v1`); `stellereum/src/rpc/state.rs:350` (`MAX_RECEIPTS = 50_000`), `:719-774` (`hydrate_rpc_from_store`) | `receipts_v1` ключуется по `tx_hash` (случайный порядок SHA-256). `all_receipts_capped(50_000)` берёт первые 50 000 записей по `tx_hash` **до** сортировки по `(height, index)` в `hydrate_rpc_from_store:727`, теряя новейшие receipts и `successful` EVM-транзакции (`:744-748`) после превышения 50 000 записей. |
| **D2** | Fail-open `FaucetState` и отсутствие `flush()` в `set_meta` | `stellereum/src/rpc/faucet.rs:340-358`, `:489-539` (`with_persist`, `load_bytes`, `persist_locked`); `stellereum/src/node/bootstrap.rs:1440-1501` (`saver`, `get_meta`, `clamp_nonce_down`); `stellereum/src/storage.rs:1058-1061` (`set_meta`); `stellereum/src/rpc/tests.rs:1415-1418` | Ошибка чтения `get_meta`, битый блоб в `load_bytes` или пропажа `faucet_state_v1` при `onchain_nonce > 0` молча сбрасывают кран в пустое состояние (обнуление всех lifetime caps). `saver` имеет тип `Fn(&[u8])` без возврата ошибки и не откатывает RAM при сбое записи. `Storage::set_meta` не вызывает `flush()`. |
| **D3** | Unbound-транзакции крана и CLI после `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` | `stellereum/src/rpc/faucet.rs:399-453` (`sign_pq_explicit_transfer`), `:614-622` (`build_transfer`); `stellereum/src/rpc/writes.rs:363-367` (`stell_faucet`); `stellereum/src/explorer.rs:1292-1296` (`api_faucet`), `:1534-1538` (`api_faucet_public`); `stellereum/src/cli/tx_builders.rs:35-226`; `stellereum/src/cli/handlers.rs:514, 631, 736, 814, 1047, 1082, 1190, 1300, 1345` | `sign_pq_explicit_transfer` и `sign_pq_explicit_payload` формируют конверты без `chain_id` (`None`), а все ingress-пути крана (`stell_faucet`, `api_faucet`, `api_faucet_public`) вызывают `AdmissionCtx::wall_now()` без `.with_chain_height(next_height)`, в отличие от `stell_sendRawTransaction` (`rpc/writes.rs:753`). После активации `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` кран и CLI перестают работать. |
| **D4** | Недетерминированная пагинация `HashMap` + 3× `O(N)` сериализация `FaucetState` + утечка `last_public_drip` | `stellereum/src/rpc/reads.rs:1938-1960` (`stell_listTokens`); `stellereum/src/token.rs:624-626` (`TokenRegistry::tokens`); `stellereum/src/explorer.rs:1593-1621` (`api_contracts`); `stellereum/src/contract.rs:414-415` (`ContractRegistry::contracts`); `stellereum/src/rpc/faucet.rs:357, 511-522, 535-539, 608, 647, 729` | `skip(offset).take(limit)` поверх `HashMap::keys()` возвращает случайный порядок, пропуская/дублируя токены и контракты. Один public drip трижды вызывает полную `bincode::serialize(&FaucetState)` под `tokio::sync::Mutex` (`check_ip_throttle`, `last_public_drip.insert`, `build_transfer`) — `3 × O(N)`. Карта `last_public_drip` никогда не очищается от истёкших cooldown-записей. |
| **D5** | Дыры шлюза `/rpc`, uncached `/metrics`, TOCTOU/путаница ошибок в `build_public_transfer` и `pool.all()` | `stellereum/src/explorer.rs:3384-3447` (`router`), `:3333-3340` (`prometheus_metrics`), `:877, 2572-2632` (`health_data_dir_cache`), `:1247, 1488` (`check_ip_throttle`), `:1265-1274, 1504-1513, 1828-1834` (`pool.all()`); `stellereum/src/rpc/writes.rs:326, 342-350`; `stellereum/src/rpc/faucet.rs:631-678` (`build_public_transfer`) | `.nest("/rpc", rpc_router)` на `:3447` стоит **после** `TimeoutLayer(30s)` и `ConcurrencyLimitLayer(512)` (`:3434-3443`). `GET /metrics` при каждом запросе сканирует до 100k файлов в `spawn_blocking` мимо `health_data_dir_cache`. `build_public_transfer` отпускает `state.lock()` между `:648` и `:650` (TOCTOU) и при исчерпанном lifetime cap (`:658`) возвращает `2700s` cooldown. Все 3 пути крана сжигают `ip_buckets` **до** проверок cap/cooldown/mempool. `/api/account` и все 3 пути крана вызывают `mempool.all()`, клонируя весь мемпул. |

---

## 2. Детальные контракты исправлений

### 2.1 D1: Tip-ordered `all_receipts_capped` и прогрев без потери новых receipts (`storage.rs`, `rpc/state.rs`)

1. **Аддитивное дерево индекса `"receipts_by_height"` (`stellereum/src/storage.rs:477-543, 855-896`):**
   - В `Storage::open` открывается дерево `receipts_by_height = db.open_tree("receipts_by_height")?`.
   - Ключ (фиксированной ширины **44 байта**): `height.to_be_bytes()[8] || index.to_be_bytes()[4] || tx_hash[32]`, значение: `&[]` (пустой срез).
   - `StoredReceipt` (`storage.rs:601-612`) и дерево `receipts_v1` (`:870`) **не изменяются** — 100% совместимость с существующими байтами и `decode_receipt` (`:641-668`).
   - `Storage::put_receipt(&self, r: &StoredReceipt)` (`:1231`) и `put_receipts_for_block_with_events` (`:1266`) записывают и в `self.receipts`, и в `self.receipts_by_height`.
   - `Storage::prune_receipts_below(&self, keep_from: u64)` (`:1317-1346`) удаляет устаревшие ключи из `receipts_by_height` и соответствующие `tx_hash` из `receipts_v1` (для старых БД без индекса — сохраняет fallback-скан `receipts_v1`).
2. **Быстрый путь `O(limit)` и безопасный fallback для старых БД (`storage.rs:1355-1364`):**
   - Вводится маркер заполненности индекса `meta["receipts_by_height_v1"] = b"1"`.
   - `Storage::all_receipts_capped(&self, limit: usize)` (и/или парный alias `recent_receipts_capped`):
     - При `limit == 0` возвращает `Ok(Vec::new())`.
     - Если `meta["receipts_by_height_v1"]` установлен: читает `self.receipts_by_height.iter().rev()` (новейшие `(height, index)` первыми!) до `limit` записей и достаёт тела по `self.receipts.get(&tx_hash)?` (**`O(limit)`** I/O и RAM; пропускает висячие ключи, если запись уже запрунена).
     - Если маркер отсутствует (первый запуск на существующем store с `> 50_000` чеков): выполняет однократный потоковый проход по `self.receipts.iter()` с **min-heap ограниченного размера `limit`** (`std::collections::BinaryHeap<Reverse<(u64, u32, [u8; 32])>>`) **И/ИЛИ** бэтчированный backfill `receipts_by_height` (с последующей установкой `meta["receipts_by_height_v1"] = b"1"`). В RAM никогда не хранится более `limit` записей; гарантированно возвращаются `limit` **новейших** по `(height, index)` квитанций, а порядок возврата приводится к `(height, index)` (или `hydrate_rpc_from_store` сохраняет существующую сортировку).
3. **Интеграция с `hydrate_rpc_from_store` (`rpc/state.rs:725-774`):**
   - `store.all_receipts_capped(MAX_RECEIPTS)` теперь возвращает новейшие 50 000 квитанций, поэтому `ReceiptIndex` и пути на её основе больше не теряют хвост цепи.
   - **Синергия с `LIGHT-CLIENT-EVM-SPEC` §4.2:** в `hydrate_rpc_from_store` (`rpc/state.rs:744-772`) проверка успеха EVM-транзакций при прогреве переводится на точечный `store.get_receipt(&tx.compute_tx_hash())?` (`storage.rs:1305`) вместо `HashSet` по `all_receipts_capped`, что полностью отвязывает EVM-индексы от окна `50_000` квитанций.

---

### 2.2 D2 + D4 (часть 2) + D5 (часть 3): Миграция `FaucetState`, карантин, инкрементальное сохранение в `sled`, разделение ошибок и транзакционность `ip_buckets`

#### 2.2.1 Схема миграции существующего `FaucetState` и fail-closed карантин

Вводятся:
- Мета-ключ инициализации: `pub const FAUCET_INITIALIZED_META_KEY: &str = "faucet_initialized_v1";` (`rpc/faucet.rs`).
- Инкрементальное дерево `sled`: `faucet_v2` (`storage.rs`, см. §2.2.2).
- Несериализуемый флаг карантина в `FaucetState` (`#[serde(skip)] quarantined_reason: Option<String>`), сохраняющий **побайтовую совместимость `bincode`** для legacy-блоба `faucet_state_v1`.

**Детерминированная машина состояний при старте (`node/bootstrap.rs:1476-1501`):**

```text
onchain_nonce = state_engine.get_account(&f.account()).await.map(|a| a.nonce).unwrap_or(0)
```

1. **Проверить новое дерево `"faucet_v2"` (если в нём есть `b"m:init"`):**
   - `Err(e)` чтения → **`QUARANTINE`** (`"faucet_v2 read failed: {e}"`).
   - `Ok(Some(_))` → загрузить инкрементально из `"faucet_v2"`, очистить просроченные `ip_buckets` (`now_hour - h > 1`) и `last_public_drip` (`now_secs - last >= cooldown`); при ошибке декодирования любой записи → **`QUARANTINE`** (никогда не сбрасывать `dispensed`!).
2. **Иначе прочитать legacy `get_meta(FAUCET_STATE_META_KEY)` (`"faucet_state_v1"`):**
   - **`Err(e)`** → **`QUARANTINE`** (`"failed to read faucet_state_v1: {e}"`).
   - **`Ok(Some(bytes))`**:
     - Вызвать `f.load_bytes_strict(&bytes).await` (`FaucetState` → fallback `LegacyFaucetState` → иначе `Err`).
     - Если `Err(e)` (повреждённый/недекодируемый блоб) → **`QUARANTINE`** (`"corrupt faucet_state_v1: {e}"`).
     - При успехе: мигрировать состояние в `"faucet_v2"` одним `sled::Batch` (`m:init = 1`, `m:nonce`, `d:*`, актуальные `i:*`, актуальные `p:*`), установить `meta[FAUCET_INITIALIZED_META_KEY] = b"1"` и выполнить **`flush()`**. При ошибке записи/`flush()` → **`QUARANTINE`**.
   - **`Ok(None)`** (нет ни `faucet_v2`, ни `faucet_state_v1`):
     - Проверить `get_meta(FAUCET_INITIALIZED_META_KEY)`:
       - **`Err(e)`** → **`QUARANTINE`** (`"failed to read faucet_initialized_v1: {e}"`).
       - **`Ok(Some(_))`** → кран уже был инициализирован ранее, но состояние исчезло! **`QUARANTINE`** (`"faucet_initialized_v1 present but faucet state missing"`).
       - **`Ok(None)`** → проверить `onchain_nonce`:
         - **`onchain_nonce > 0`** → существующая цепь уже выдавала средства с адреса крана, но `faucet_state_v1` отсутствует (потеря meta на pre-marker ноде или удаление ключа)! **`QUARANTINE`** (`"onchain_nonce > 0 with missing faucet state — refusing fail-open reset"`).
         - **`onchain_nonce == 0`** → чистый старт нового крана: записать `meta[FAUCET_INITIALIZED_META_KEY] = b"1"` + `faucet_v2[b"m:init"] = b"\x01"`, `b"m:nonce" = 0u64` + **`flush()`**. При ошибке записи/`flush()` → **`QUARANTINE`**.
3. **После успешной загрузки (только если `!f.is_quarantined()`):**
   - Выполнить `f.clamp_nonce_down(onchain_nonce).await`, который обязан вернуть `Result<(), String>` и откатить `next_nonce` в RAM при сбое записи/flush (при сбое — также логировать и переводить в карантин / отказываться стартовать).
4. **Поведение в карантине:**
   - При `f.is_quarantined() == true` **каждый** вызов `build_transfer`, `build_public_transfer`, `try_build_transfer_with_throttle`, `try_build_public_transfer_with_throttle` и `check_ip_throttle` отказывает fail-closed (`Quarantined(reason)` / `None` / `false`), HTTP-ручки возвращают `503 Service Unavailable`, JSON-RPC возвращает `-32000`.
   - Замечание по существующему тесту `rpc/tests.rs:1415-1418`: `broken.load_bytes(b"not-a-faucet-state").await; assert_eq!(broken.dispensed_to(who).await, 0);` остаётся совместимым по `dispensed_to == 0`, если `load_bytes` переводит `broken` в `quarantined` (и для нового контракта `build_transfer` на `broken` возвращает `None`, `broken.is_quarantined() == true`).

#### 2.2.2 Инкрементальное сохранение в `sled` (устранение 3× `O(N)` сериализации) + `flush()` + rollback

1. **Проблема текущего кода:** `persist_locked` (`rpc/faucet.rs:535-539`) вызывает `bincode::serialize(&FaucetState)` целиком на каждый шаг (`check_ip_throttle`, `last_public_drip.insert`, `build_transfer`) — до **3 полных `O(N)` сериализаций** под `tokio::sync::Mutex`, а `Storage::set_meta` (`storage.rs:1058-1061`) не вызывает `flush()`.
2. **Долговечный `set_meta_durable` в `storage.rs`:**
   - Добавить `Storage::set_meta_durable(&self, key: &str, value: &[u8]) -> Result<()>` (вставляет ключ в `self.meta` и вызывает `self.meta.flush()?`).
3. **Инкрементальное дерево `"faucet_v2"` в `Storage` (`storage.rs` + `rpc/faucet.rs`):**
   - Схема ключей в дереве `"faucet_v2"`:
     - `b"m:init"` → `[1u8]`
     - `b"m:nonce"` → `u64::to_be_bytes()` (8 байт)
     - `b"d:" || addr[32]` → `u64::to_be_bytes()` (8 байт — lifetime `dispensed[addr]`)
     - `b"i:" || ip_key_utf8` → `hour(8BE) || count(4BE)` (12 байт — `ip_buckets[ip_key]`)
     - `b"p:" || addr[32]` → `last_secs(8BE)` (8 байт — `last_public_drip[addr]`)
   - Трейт/бэкенд `FaucetDeltaStore` (или `enum FaucetPersistBackend` в `rpc/faucet.rs`):
     - `Incremental(Arc<dyn FaucetDeltaStore>)`: на один drip применяет **один** `sled::Batch` из 2–4 затронутых ключей (`m:nonce`, `d:<who>`, `i:<ip>`, опционально `p:<who>` + удаление до `MAX_SWEEP_PER_DRIP = 64` истёкших `p:`/`i:` ключей) + `tree.flush()` (**`O(1)`**, ~100 байт вместо `3 × O(N)`).
     - `Snapshot(Arc<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>)`: для in-memory/test callback-ов (`with_fallible_persist`, а legacy `with_persist` оборачивается в `Ok(())`). Благодаря объединению операций в один вызов (§2.2.3) число сериализаций снижается с **3 до 1**.
4. **Атомарный in-memory rollback при ошибке записи/`flush()`:**
   - Перед изменением `FaucetState` под `self.state.lock().await` сохраняется компактный `UndoDelta { prev_nonce, prev_dispensed: Option<u64>, prev_ip: (String, Option<(u64, u32)>), prev_public: Option<u64> }`.
   - После вызова `persist_delta(...)` (включающего `flush()`): если вернулся `Err(e)`, немедленно восстанавливаются `next_nonce`, `dispensed[who]`, `ip_buckets[ip_key]` и `last_public_drip[who]` из `UndoDelta` (до освобождения mutex!), инкрементируется `FAUCET_PERSIST_FAILURES` и возвращается `Err(PersistFailed(e))`.
5. **Периодическая очистка `last_public_drip` (`rpc/faucet.rs:357, 511-522, 639-678`):**
   - В отличие от `dispensed` (который является lifetime-лимитом и **никогда** не прунится), запись `last_public_drip[who]` теряет смысл при `now_secs.saturating_sub(last) >= cooldown`.
   - Очистка выполняется:
     1. при загрузке (`load_bytes_strict` / чтении `"faucet_v2"`): `retain(|_, last| now_secs.saturating_sub(*last) < cooldown)` (и удаление просроченных `b"p:"` ключей);
     2. при каждой записи в `last_public_drip`: если `last_public_drip.len() > PUBLIC_DRIP_PRUNE_THRESHOLD` (например, `10_000`) или bounded-порциями (до 64 ключей за drip с курсором/итерацией), просроченные записи удаляются из карты в памяти и из `"faucet_v2"` в том же `sled::Batch`.

#### 2.2.3 Разделение ошибок `LifetimeCapExhausted` vs `Cooldown` и транзакционное списание `ip_buckets`

1. **Явные типы ошибок в `rpc/faucet.rs` (вместо `Result<_, u64>` и `Option`):**
   ```rust
   #[derive(Clone, Debug, PartialEq, Eq)]
   pub enum FaucetDripError {
       /// Адрес исчерпал пожизненный лимит (`dispensed >= max_per_address`).
       LifetimeCapExhausted,
       /// Публичный кран на паузе для данного адреса (повтор через `retry_after_secs`).
       Cooldown { retry_after_secs: u64 },
       /// Превышен почасовой лимит на IP (`FAUCET_IP_MAX_PER_HOUR`).
       IpRateLimited,
       /// Состояние крана повреждено / не удалось проверить при старте (fail-closed).
       Quarantined { reason: String },
       /// Ошибка записи/flush долговечного хранилища (состояние в RAM откачено).
       PersistFailed { reason: String },
   }
   ```
   - `build_public_transfer` (`rpc/faucet.rs:631-661`) больше **НИКОГДА** не возвращает `Err(public_drip_cooldown_secs())` (`2700s`) при исчерпании lifetime cap: возвращается `FaucetDripError::LifetimeCapExhausted`.
   - HTTP/JSON-RPC маппинг:
     - `Cooldown { retry_after_secs }` → `429 Too Many Requests` (`"public drip cooling down for this address, retry in {retry_after_secs} seconds"`)
     - `LifetimeCapExhausted` → `429 Too Many Requests` / `-32000` (`"faucet lifetime limit reached for this address"`)
     - `IpRateLimited` → `429 Too Many Requests` / `-32000` (`"per-IP faucet budget exhausted for this hour"`)
     - `Quarantined` / `PersistFailed` → `503 Service Unavailable` / `-32000`
2. **Устранение TOCTOU и транзакционное списание `ip_buckets`:**
   - Удалить разрыв `drop(st)` между проверкой `last_public_drip` (`rpc/faucet.rs:638-648`) и `build_transfer` (`:650`).
   - Вводится единый метод `Faucet::request_drip(&self, params: FaucetDripRequest) -> Result<FaucetGrant, FaucetDripError>` (для обоих режимов: `public: bool`), который **под одним захватом `self.state.lock().await`** выполняет строго последовательно:
     1. Проверка `!quarantined`.
     2. *(Read-only)* Проверка cooldown (`if public`: `last_public_drip.get(&who)`).
     3. *(Read-only)* Проверка lifetime cap (`remaining = max_per_address.saturating_sub(already) > 0`).
     4. *(Read-only)* Проверка `ip_buckets` для канонического `ip_key` (`canonical_ip(ip)`, час `hour = now_secs / 3600`, `count < faucet_ip_max_per_hour()`).
     5. Вычисление `amount`, `mex`-reconcile `nonce`, запись в `UndoDelta`, обновление `dispensed`, `next_nonce`, `ip_buckets`, *(если `public`)* `last_public_drip`.
     6. **ОДИН** вызов `persist_delta` + `flush()`. При `Err` — откат по `UndoDelta` и возврат `Err(PersistFailed)`.
     7. Построение и подпись `Transaction` (`sign_pq_explicit_transfer_with_chain` при наличии `chain_id`).
   - `FaucetGrant` хранит `{ tx, who, amount, ip_key, charged_hour, is_public }`.
   - Если последующий `mempool.write().await.add_checked_ctx(...)` возвращает `Err(e)` (`rpc/writes.rs:369`, `explorer.rs:1298, 1540`):
     - Вызывается `faucet.rollback_grant(&grant).await`: под одним `state.lock().await` откатывает `next_nonce` (если `grant.tx.nonce < st.next_nonce`), уменьшает `dispensed[who]`, удаляет `last_public_drip[who]` (если `is_public`), **декрементирует `ip_buckets[ip_key]` (если `(h, n)` совпадает с `grant.charged_hour` и `n > 0`)** и сохраняет delta одним `sled::Batch` + `flush()`!
   - Таким образом, ни ошибка cap, ни cooldown, ни ошибка `mempool` (например `Full`, `InsufficientBalance`, `DuplicateNonce`) не сжигают `ip_buckets` пользователя.

---

### 2.3 D3: Chain-bound транзакции для крана и CLI + `.with_chain_height(...)` на всех путях крана

1. **Кран (`rpc/faucet.rs`, `node/bootstrap.rs`):**
   - Добавить `pub fn sign_pq_explicit_transfer_with_chain(..., chain_id: u64) -> Transaction` (`rpc/faucet.rs`), которая:
     - вычисляет `msg = tx.signing_message_for_chain(chain_id)` (`sharding/transaction.rs:1357`);
     - подписывает `sig = pq_key.sign(&msg)`;
     - кодирует `PqSignatureEnvelope::new_explicit_with_chain(PqScheme::Falcon512, pq_key.public_key.clone(), sig, DEFAULT_SALT, chain_id)` (`sharding/envelope.rs:58`).
   - Добавить в `struct Faucet` поле `chain_id: Option<u64>` и builder `pub fn with_chain_id(mut self, chain_id: u64) -> Self` (сохраняя сигнатуру `Faucet::new` для обратной совместимости тестов, а `Faucet::with_chain_id(chain_id)` в `node/bootstrap.rs:1431` и в `RpcState`-конструкторах выставляется **обязательно**; дополнительно в `build_transfer` / `request_drip` можно передавать `chain_id` из `st.chain_id`!).
   - При наличии `chain_id` кран всегда строит **bound** PQ1-транзакцию (валидна как до `STELL_CHAIN_BIND_ACTIVATION_HEIGHT`, так и после него — `chain_binding.rs:198`).
2. **Ingress-пути крана (`rpc/writes.rs:363-367`, `explorer.rs:1292-1296, 1534-1538`):**
   - Во всех трёх точках (`stell_faucet`, `api_faucet`, `api_faucet_public`) вычислять:
     ```rust
     let next_height = st.height.load(std::sync::atomic::Ordering::Relaxed).saturating_add(1);
     let actx = AdmissionCtx::wall_now()
         .with_chain_height(next_height)
         .with_onchain_nonce(onchain)
         .with_shard(faucet.shard());
     ```
     (Примечание: `.with_shard(faucet.shard())` выставлять при `st.shard_registry.is_sharded()`, зеркально `rpc/writes.rs` / `resolve_faucet_recipient`.)
   - Это выравнивает кран с `stell_sendRawTransaction` (`rpc/writes.rs:738-756`) и `eth_sendRawTransaction` (`rpc/eth.rs:1968`): после `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` ни одна unbound-транзакция не попадёт в мемпул в обход `chain_binding::check_admission`.
3. **CLI (`cli/tx_builders.rs`, `cli/args.rs`, `cli/handlers.rs`):**
   - В `cli/tx_builders.rs`:
     - Добавить `pub(crate) fn sign_pq_explicit_payload_with_chain(..., chain_id: u64) -> Transaction` (использует `tx.signing_message_for_chain(chain_id)` и `PqSignatureEnvelope::new_explicit_with_chain`).
     - Добавить `chain_id: u64` в конструкторы (или парные `*_with_chain` с переключением всех вызовов в `cli/handlers.rs`):
       - `build_place_order_tx` (`cli/tx_builders.rs:73`, вызов `cli/handlers.rs:1047`)
       - `build_cancel_order_tx` (`cli/tx_builders.rs:106`, вызов `cli/handlers.rs:1082`)
       - `build_session_grant_tx` (`cli/tx_builders.rs:132`, вызов `cli/handlers.rs:814`)
       - `build_bridge_intent_tx` (`cli/tx_builders.rs:166`, вызовы `cli/handlers.rs:1300, 1345`)
       - `build_unjail_tx` (`cli/tx_builders.rs:205`, вызов `cli/handlers.rs:736`)
       - прямой вызов `sign_pq_explicit_payload` в `OracleCommands::SubmitPriceFeed` (`cli/handlers.rs:1190`)
       - `WalletCommands::Send` (`cli/handlers.rs:514`) и `WalletCommands::SendPq` (`cli/handlers.rs:631`) → `sign_pq_explicit_transfer_with_chain`.
   - В `cli/args.rs` и `cli/handlers.rs`:
     - Добавить опциональный `--chain-id <u64>` ко всем перечисленным командам (кроме `DelegateSession`, где `chain_id` уже есть — переиспользовать его для внешнего `build_session_grant_tx`).
     - Реализовать единый helper `resolve_chain_id(rpc: &str, explicit: Option<u64>) -> anyhow::Result<u64>`:
       - если `Some(cid)` — вернуть `Ok(cid)`;
       - иначе — запросить `stell_chainId` по `rpc` (`rpc/reads.rs:1157`), и при ошибке/недоступности `--rpc` (вкл. `--dry-run` без `--chain-id`) **отказать fail-closed**, не откатываясь к unbound-подписи!

---

### 2.4 D4 (часть 1): Детерминизм `TokenRegistry::tokens` / `ContractRegistry::contracts` без поломки bincode `DomainSnapshot`

**Анализ совместимости с `DomainSnapshot` (`storage.rs:2717-2735, 2794-2881, 3190-3207`):**

1. **Что ЛОМАЕТ bincode `DomainSnapshot` (ЗАПРЕЩЕНО):**
   - `bincode` 1.x кодирует структуры позиционно, без имён полей и без поддержки `#[serde(default)]` при пропуске поля.
   - Добавление любого нового сериализуемого поля (без `#[serde(skip)]`) в `TokenRegistry` (`token.rs:624-627`) или `ContractRegistry` (`contract.rs:414-419`) сделает невозможной десериализацию существующих `DomainSnapshot` / `DomainSnapshotV1..V3` (см. `FREEZE RULE` в `storage.rs:545-552`).
2. **Что 100% СОВМЕСТИМО с bincode `DomainSnapshot`:**
   - **Замена типа `HashMap<[u8; 32], V>` → `BTreeMap<[u8; 32], V>`** в:
     - `TokenRegistry::tokens: BTreeMap<[u8; 32], TokenActor>` (`token.rs:625`),
     - `ContractRegistry::contracts: BTreeMap<[u8; 32], Contract>` (`contract.rs:415`).
   - **Доказательство wire-совместимости:**
     - В `serde` + `bincode` оба типа `HashMap` и `BTreeMap` вызывают `Serializer::serialize_map(Some(len))` → записывают `u64` длину, затем `len` пар `(key, value)`.
     - При десериализации `BTreeMap::deserialize` читает `u64` длину и последовательно вставляет все `(key, value)` независимо от порядка ключей во входном потоке. Старые `DomainSnapshot` / `DomainSnapshotV1..V3`, сериализованные из `HashMap`, декодируются в `BTreeMap` без единой ошибки и с тем же набором элементов; `ContractRegistryLegacy::upgrade` (`storage.rs:3196-3205`) уже использует `.into_iter().map(...).collect()`, что работает для `BTreeMap` без изменений.
   - **Дополнительный выигрыш:**
     - `tokens_digest` (`commitment.rs:931`) и `contracts_digest` (`commitment.rs:1323`) уже сортируют `reg.tokens.iter()` / `reg.contracts.iter()` в `Vec` перед хешированием, поэтому `state_root` и `COMMITMENT_VERSION = 5` остаются **побайтово неизменными**, а сортировка в `commitment.rs` становится избыточной.
     - Обеспечивается нативная `O(log N + limit)` курсорная пагинация через `BTreeMap::range((Bound::Excluded(cursor), Bound::Unbounded)).take(limit)`!
   - *(Альтернатива без смены публичного типа полей `HashMap`, если требуется строго `O(1)` lookup или заморозка типа поля:)* `#[serde(skip)]` индекс `BTreeSet<[u8; 32]>` требует кастомного `Deserialize` impl на `TokenRegistry` / `ContractRegistry` для заполнения при восстановлении `DomainSnapshot`, поэтому `BTreeMap` проще, надёжнее и исключает рассинхронизацию индекса с основной картой.
3. **Контракт пагинации `stell_listTokens` (`rpc/reads.rs:1938-1960`) и `api_contracts` (`explorer.rs:1593-1621`):**
   - Добавить параметры `cursor?: "<64-hex>"` (keyset pagination: строго `id > cursor` в лексикографическом порядке `[u8; 32]`, в ответе возвращается `next_cursor: Option<String>` и `has_more: bool`).
   - Для обратной совместимости при отсутствии `cursor` сохраняется поддержка `offset` (также поверх детерминированного `BTreeMap` порядка, с cap `limit <= 1000` и без материализации всего реестра; при этом новые клиенты используют `cursor` за `O(log N + limit)` без сдвига страниц между вставками!).
   - *Координация с `W4-CONTRACT` E3:* `token.rs`, `contract.rs` и `rpc/reads.rs` уже входят в область `E3` (`W4_ECONOMICS_PRODUCT_CONTRACT.md:247, 348`). Поставка `BTreeMap` в `token.rs`/`contract.rs` должна выполняться единым согласованным шагом с `E3` (см. матрицу владения в §3).

---

### 2.5 D5: `explorer::router` слои DoS-защиты, кэш `/metrics` и отказ от `mempool.all()`

1. **`explorer::router` (`explorer.rs:3384-3447`):**
   - Сейчас `.nest("/rpc", rpc_router)` стоит в строке `:3447`, **вне** `TimeoutLayer(30s)` и `ConcurrencyLimitLayer(512)` (`:3434-3443`).
   - **Требуемое исправление:** собрать `explorer_routes` с `.layer(rate_limit)` и `.with_state(gateway)`, прикрепить `.nest("/rpc", rpc_router)` (который уже несёт собственный `nested_rpc_rate_limit`, исключая двойной учёт лимита!), и **поверх объединённого `Router`** навесить:
     - `cors_middleware` (одним слоем на всё или сохранив на обоих без дублирования),
     - `tower::ServiceBuilder` с `HandleErrorLayer` → `408 REQUEST_TIMEOUT`, `TimeoutLayer(30s)` и `ConcurrencyLimitLayer(512)`.
   - Таким образом `/rpc` (и `/rpc/ws`, `/rpc/events`) на гейтвее получает ту же защиту от slow-loris / исчерпания сокетов, что и standalone RPC (`rpc/streams.rs:1867-1877`), не нарушая аудит-инвариант недвойного rate-limiting (`explorer.rs:3380-3383`).
2. **`GET /metrics` (`explorer.rs:3333-3340`):**
   - Удалить прямой `spawn_blocking(move || data_dir_stats(&dir))` в `prometheus_metrics`.
   - Использовать `data_dir_health(&st, now_ms()).await` (`explorer.rs:2572-2632`), который:
     - уважает `st.health_options.data_dir` (`None` = без скана в тестах),
     - читает `st.health_data_dir_cache` с TTL `HEALTH_DATA_DIR_CACHE_TTL_MS = 30_000` ms (`explorer.rs:274`),
     - сериализует холодный скан через `st.health_data_dir_scan_gate` (single-flight, N одновременных `/metrics` скрейпов не запускают N обходов ФС).
3. **Замена `pool.all()` в `api_account`, `stell_faucet`, `api_faucet`, `api_faucet_public`:**
   - В `Mempool` (`mempool.rs`) добавить два лёгких read-only метода без клонирования всего пула:
     1. `pub fn pending_nonces_for(&self, account: &[u8; 32]) -> Vec<u64>`: читает `self.sender_nonces.get(account)` (`mempool.rs:572`) за `O(K_sender)` с **0 клонирований `Transaction`**.
     2. `pub fn pending_for_account(&self, account: &[u8; 32], max_items: usize) -> (usize, Vec<Transaction>)`: итерирует `&self.txs` по ссылке (`t.from == *account || t.to == *account`), считает `total`, и клонирует не более `max_items` транзакций с наибольшими `nonce` (например, min-heap / отсортированный буфер размера `max_items` или сортировка только совпадений, но **не** `self.txs.values().cloned()` всего пула!).
   - Подключение:
     - `rpc/writes.rs:342-350` (`stell_faucet`), `explorer.rs:1265-1274` (`api_faucet`), `explorer.rs:1504-1513` (`api_faucet_public`) → `pool.pending_nonces_for(&faucet_addr)`.
     - `explorer.rs:1828-1842` (`api_account`) → `pool.pending_for_account(&a, MAX_ACCOUNT_TXS)`.

---

## 3. Матрица владения файлами (без пересечений с `LIGHT-CLIENT-EVM-SPEC`, `W4-CONTRACT`, `SEC-FIX-CONTRACT`)

### 3.1 Пересечения с действующими контрактами и барьеры последовательности

Чтобы **ни один файл** не редактировался параллельно двумя агентами (ни внутри этого контракта, ни между `LIGHT-CLIENT-EVM-SPEC`, `W4-CONTRACT`, `SEC-FIX-CONTRACT`), работы делятся на **Волну A (полностью не пересекается ни с одним из 3 контрактов)** и **Волну B (строго последовательный follow-up после слияния владельцев в 3 предыдущих контрактах)**:

| Файл | Владельцы в 3 текущих контрактах | Барьер / решение по изоляции |
|---|---|---|
| `stellereum/src/rpc/faucet.rs` | **Никто** | **Волна A (`FH-1`)** — немедленный старт, 0 пересечений. |
| `stellereum/src/cli/tx_builders.rs`, `stellereum/src/bin_tests.rs` | **Никто** | **Волна A (`FH-5a`)** — немедленный старт, 0 пересечений. |
| `stellereum/src/storage.rs` | `LIGHT-CLIENT-EVM-SPEC` (Stream D), `W4-CONTRACT` (E3) | **Волна B (`FH-2`)** — только после мержа `Stream D` + `E3`. |
| `stellereum/src/rpc/state.rs` | `LIGHT-CLIENT-EVM-SPEC` (Stream E), `W4-CONTRACT` (E4), `SEC-FIX-CONTRACT` (Agent-5) | **Волна B (`FH-2` / `FH-4`)** — только после мержа `Stream E` + `E4` + `Agent-5`. *(EVM-часть `:744-772` уже закрывается `Stream E`.)* |
| `stellereum/src/token.rs`, `stellereum/src/contract.rs`, `stellereum/src/rpc/reads.rs` | `W4-CONTRACT` (E3), `LIGHT-CLIENT-EVM-SPEC` (Stream E: `reads.rs`), `SEC-FIX-CONTRACT` (Agent-5: `reads.rs`) | **Волна B (`FH-3b`)** — `HashMap -> BTreeMap` + `stell_listTokens` cursor выполняется в `E3` либо сразу после `E3` + `Stream E` + `Agent-5`. |
| `stellereum/src/mempool.rs` | `W4-CONTRACT` (E1), `SEC-FIX-CONTRACT` (Agent-3) | **Волна B (`FH-4`)** — только после мержа `E1` + `Agent-3`. |
| `stellereum/src/rpc/writes.rs`, `stellereum/src/rpc/tests.rs` | `SEC-FIX-CONTRACT` (Agent-5) | **Волна B (`FH-4`)** — только после мержа `Agent-5`. |
| `stellereum/src/explorer.rs` | `SEC-FIX-CONTRACT` (Agent-4) | **Волна B (`FH-3a`)** — только после мержа `Agent-4`. |
| `stellereum/src/node/bootstrap.rs` | `LIGHT-CLIENT-EVM-SPEC` (Stream E) | **Волна B (`FH-4`)** — только после мержа `Stream E`. |
| `stellereum/src/cli/args.rs`, `stellereum/src/cli/handlers.rs` | `LIGHT-CLIENT-EVM-SPEC` (Stream B) | **Волна B (`FH-5b`)** — только после мержа `Stream B`. |

### 3.2 Внутренняя непересекающаяся матрица потоков этого контракта (`AGENTS.md` §2, §8)

Внутри каждой волны все потоки **строго дизъюнктны** (ни один `.rs` файл не повторяется в двух строках):

| Поток | Волна | Исключительное владение файлами (strict scope lock) | Ответственность |
|---|---|---|---|
| **`FH-1` (`Faucet-Core`)** | **Волна A** *(сразу)* | `stellereum/src/rpc/faucet.rs`<br>`stellereum/tests/faucet_hardening_tests.rs` *(new)* | `FaucetDripError`, карантин, `load_bytes_strict`, `FaucetDeltaStore` / `UndoDelta` с откатом RAM, очистка `last_public_drip`, транзакционное `request_drip` + `rollback_grant` (`ip_buckets` после cap/cooldown), `sign_pq_explicit_transfer_with_chain` + `with_chain_id`. |
| **`FH-5a` (`CLI-Builders`)** | **Волна A** *(сразу)* | `stellereum/src/cli/tx_builders.rs`<br>`stellereum/src/bin_tests.rs`<br>`stellereum/tests/faucet_cli_chain_bind_tests.rs` *(new)* | `sign_pq_explicit_payload_with_chain`, `*_with_chain` конструкторы (сохранение/обновление `bin_tests.rs` и юнит-тестов). |
| **`FH-2` (`Storage-Hydrate`)** | **Волна B** *(после `Stream D+E`, `E3+E4`, `Agent-5`)* | `stellereum/src/storage.rs`<br>`stellereum/src/rpc/state.rs`<br>`stellereum/tests/receipt_hydration_and_pagination_tests.rs` *(new)* | Дерево `"receipts_by_height"` + `O(limit)` tip-ordered `all_receipts_capped` (с min-heap fallback для старых БД), `set_meta_durable`, дерево `"faucet_v2"` (`FaucetDeltaStore`), проверка `hydrate_rpc_from_store` на `> 50_000` чеках. |
| **`FH-3a` (`Explorer-Gateway`)** | **Волна B** *(после `Agent-4`, `FH-1`, `FH-4`/`FH-3b`)* | `stellereum/src/explorer.rs`<br>`stellereum/tests/explorer_hardening_tests.rs` *(new)* | `.nest("/rpc", rpc_router)` под `TimeoutLayer(30s)` + `ConcurrencyLimitLayer(512)` без двойного rate-limit, `GET /metrics` через `data_dir_health` (`health_data_dir_cache`), `api_faucet*` на `request_drip`/`rollback_grant` + `.with_chain_height`, `api_account` через `pending_for_account`, `api_contracts` cursor pagination. |
| **`FH-3b` (`Registry-Pagination`)** | **Волна B** *(в/после `E3`, `Stream E`, `Agent-5`)* | `stellereum/src/token.rs`<br>`stellereum/src/contract.rs`<br>`stellereum/src/rpc/reads.rs` | `TokenRegistry::tokens` и `ContractRegistry::contracts` (`HashMap` → `BTreeMap` с сохранением bincode `DomainSnapshot`), детерминированная курсорная пагинация `stell_listTokens` (и сохранение обратной совместимости `offset`). |
| **`FH-4` (`RPC-Bootstrap-Mempool`)** | **Волна B** *(после `FH-1`, `FH-2`, `Stream E`, `E1`, `Agent-3+5`)* | `stellereum/src/mempool.rs`<br>`stellereum/src/rpc/writes.rs`<br>`stellereum/src/rpc/tests.rs`<br>`stellereum/src/node/bootstrap.rs` | `Mempool::{pending_nonces_for, pending_for_account}`, подключение `FaucetDeltaStore` + startup-миграции (`faucet_initialized_v1` + `onchain_nonce > 0` quarantine) + `.with_chain_id(chain_id)` в `bootstrap.rs`, `stell_faucet` на `request_drip` + `rollback_grant` + `.with_chain_height(next_height)`, обновление `rpc/tests.rs:1415, 1488`. |
| **`FH-5b` (`CLI-Handlers`)** | **Волна B** *(после `FH-1`, `FH-5a`, `Stream B`)* | `stellereum/src/cli/args.rs`<br>`stellereum/src/cli/handlers.rs` | `--chain-id` + `resolve_chain_id` (`stell_chainId`, fail-closed) во всех tx-командах (`Send`, `SendPq`, `Unjail`, `Orderbook::{Place, Cancel}`, `Oracle::SubmitPriceFeed`, `Bridge::{Deposit, Withdraw}`, `DelegateSession`). |

---

## 4. Обязательный список тестов «падало до» (`fail-before → pass-after`)

Все тесты обязаны воспроизводить дефект на исходном коде (**падают до фикса**) и проходить после фикса с чистым полным гейтом (`cargo clippy --all-targets -- -D warnings` и `cargo test --no-fail-fast`):

1. **Потеря новейших receipts после `> 50_000` записей (`receipts_capped_returns_newest_over_50k_and_legacy_fallback`)** `[FH-2]`:
   - *Падало до:* в `Storage` записывается `55_000` квитанций по `1` tx на блок (`height = 1..=55_000`); после `hydrate_rpc_from_store` квитанции на высотах `54_900..=55_000`, чей `tx_hash` начинается с `0xFF..`, отсутствуют в `ReceiptIndex` (`stell_getTransactionReceipt` возвращает `null`), а `all_receipts_capped(50_000)` теряет новейшие высоты.
   - *После:* `all_receipts_capped(50_000)` и `hydrate_rpc_from_store` гарантированно загружают `height = 5_001..=55_000` (и на legacy-директории без `"receipts_by_height"`, и с индексом в `O(limit)`).
2. **Fail-open карантин `FaucetState` при ошибке чтения/декодирования и при `onchain_nonce > 0` + `Ok(None)` (`faucet_startup_quarantines_on_corrupt_read_err_or_missing_state_with_nonzero_nonce`)** `[FH-1, FH-4]`:
   - *Падало до:* (a) при повреждённом `faucet_state_v1`, (b) при пропаже `faucet_state_v1` при установленном `faucet_initialized_v1` или при `onchain_nonce > 0` без маркера — `Faucet` стартовал с `dispensed = {}` и заново выдавал полный lifetime cap.
   - *После:* во всех трёх сценариях `faucet.is_quarantined() == true`, любая выдача (`request_drip` / `stell_faucet` / `/api/faucet*`) отвергается fail-closed; при `Ok(None)` и `onchain_nonce == 0` кран чисто инициализируется, записывает `faucet_initialized_v1` + `flush()`, а существующий валидный `faucet_state_v1` бесшовно мигрирует в `"faucet_v2"`.
3. **Откат RAM при сбое записи/flush + персистентность через `flush()` + 1× `O(1)` запись и очистка `last_public_drip` (`faucet_persist_failure_rolls_back_ram_and_cleans_expired_cooldowns`)** `[FH-1, FH-2]`:
   - *Падало до:* ошибка `saver` оставляла сдвинутые `next_nonce`/`dispensed`/`ip_buckets` в RAM, `set_meta` не вызывал `flush()`, 1 public drip вызывал 3 полных `bincode::serialize(&FaucetState)`, а `last_public_drip` рос без границ.
   - *После:* инжектированная ошибка persist/flush полностью откатывает `next_nonce`, `dispensed`, `ip_buckets` и `last_public_drip` в RAM; успешный drip делает ровно 1 атомарную batch+flush запись в `"faucet_v2"`; просроченные записи `last_public_drip` (`>= cooldown`) удаляются при загрузке и при достижении порога очистки (lifetime `dispensed` при этом не трогается).
4. **Разделение `LifetimeCapExhausted` vs `Cooldown` + не-сжигание `ip_buckets` + TOCTOU под конкуренцией (`faucet_public_distinguishes_cap_from_cooldown_and_preserves_ip_budget_on_failure`)** `[FH-1, FH-3a, FH-4]`:
   - *Падало до:* после исчерпания lifetime cap `build_public_transfer` возвращал ошибку `"retry in 2700 seconds"`, `ip_buckets` сжигался при cooldown/cap/ошибке `mempool.add_checked_ctx`, а параллельные вызовы `build_public_transfer` допускали TOCTOU.
   - *После:* (a) исчерпанный lifetime cap возвращает `LifetimeCapExhausted` (не `2700s`); (b) повтор на cooldown, ошибка `LifetimeCapExhausted` и отказ mempool (например `InsufficientBalance` или `Full`) **не уменьшают** остаток `ip_buckets` (последующие легитимные запросы на свежий адрес с того же IP проходят все `FAUCET_IP_MAX_PER_HOUR` раз); (c) при 32 конкурентных `request_drip` на один адрес с остатком под 1 drip проходит строго 1 запрос.
5. **Chain-binding для крана, ingress-путей и CLI при активном `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` (`faucet_and_cli_sign_chain_bound_and_ingress_enforces_activation`)** `[FH-1, FH-3a, FH-4, FH-5a, FH-5b]`:
   - *Падало до:* при `STELL_CHAIN_BIND_ACTIVATION_HEIGHT = 10` и `st.height >= 9`: (a) `stell_faucet` / `api_faucet` / `api_faucet_public` подписывали unbound tx (`chain_id() == None`) и передавали `AdmissionCtx::wall_now()` без `.with_chain_height(...)`; (b) `cli` (`send`, `send-pq`, `unjail`, `orderbook`, `oracle`, `bridge`, `delegate-session`) подписывал unbound tx, отвергаемые `stell_sendRawTransaction` / блоком.
   - *После:* (a) кран (с `with_chain_id`) и все CLI-строители производят `chain_id == Some(expected)` с валидной подписью `verify_signature_for_chain(expected, true)`; (b) даже если на `stell_faucet` / `api_faucet*` подаётся/конструируется unbound-транзакция при `next_height >= activation`, `.with_chain_height(next_height)` отвергает её в `mempool::add_checked_ctx` и откатывает грант крана.
6. **Детерминированная пагинация `stell_listTokens` и `api_contracts` + совместимость `DomainSnapshot` (`registry_pagination_is_deterministic_and_decodes_legacy_hashmap_snapshot`)** `[FH-3a, FH-3b]`:
   - *Падало до:* `stell_listTokens` и `GET /api/contracts` на `HashMap` возвращали разные пересекающиеся страницы между двумя процессами/рестартами и пропускали элементы при пагинации.
   - *После:* (a) два независимых экземпляра `TokenRegistry`/`ContractRegistry` со вставкой в разном порядке выдают идентичные отсортированные страницы по `cursor` и `offset` без пропусков и дублей; (b) байты legacy-`DomainSnapshot`, сериализованного старым `HashMap`-макетом, успешно десериализуются в новый `BTreeMap`-макет с сохранением всех токенов, контрактов и побайтово тем же `state_root`.
7. **Защита `/rpc` на гейтвее, кэшируемый `/metrics` и отсутствие `mempool.all()` (`explorer_router_enforces_rpc_timeout_concurrency_cached_metrics_and_no_full_mempool_clone`)** `[FH-3a, FH-4]`:
   - *Падало до:* (a) `/rpc` на `explorer::router` находился вне `TimeoutLayer(30s)` / `ConcurrencyLimitLayer(512)` (при `> 512` удержанных соединений `/rpc` принимал сверх лимита и не таймаутил медленные хендлеры); (b) два подряд `GET /metrics` вызывали повторный скан директории вместо чтения `health_data_dir_cache`; (c) `pending_nonces_for` / `pending_for_account` не существовали, а `/api/account` и кран клонировали весь пул.
   - *После:* (a) `/rpc` на `explorer::router` делит `ConcurrencyLimitLayer(512)` и `TimeoutLayer(30s)` с остальными маршрутами без двойного списания `RateLimiter`; (b) `GET /metrics` при тёплом `health_data_dir_cache` не запускает повторный `data_dir_stats` (проверяется подменой/удалением тестового файла внутри TTL `30s`, пока значение в метриках стабильно из кэша); (c) `Mempool::pending_nonces_for` и `pending_for_account` возвращают точные данные `api_account` и `Mex`-reconcile за `O(K_sender)` / без клонирования посторонних транзакций.
