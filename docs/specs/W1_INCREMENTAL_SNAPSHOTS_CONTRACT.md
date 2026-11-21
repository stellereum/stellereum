# W1 (S4) — Incremental & Chunked Snapshots Contract (HDAE, code truth)

Статус: **архитектурный контракт интеграции W1 / S4** («Инкрементальные снапшоты + скачивание у пиров»).
Зафиксировано по фактическому чтению дерева `stellereum` + `infnode` на 2026-11-21 (`CONSENSUS_RULESET_VERSION = 6`, `FORK_ID = 0x0f584a46`, `COMMITMENT_VERSION = 5`).

> **Правило замороженного ядра (`AGENTS.md` §7).** Изменение формата блоков (`Block::compute_hash()`), правил `apply()`, `COMMITMENT_VERSION`, `vote_sign_bytes`, `FORK_ID` или `SafetyRecordStore` в W1/S4 **запрещено**. Контракт инкрементальных и чанкованных снапшотов работает целиком поверх уже зафиксированного `state_root` (`PatriciaTrie` + `commitment_digest`) и уже существующих `precommit_qc` заголовков, с обратной совместимостью по чтению локальных/сетевых полных снапшотов (`StateSnapshotV2` / `DomainSnapshot`).
>
> **Абсолютный инвариант `SafetyRecordStore`.** Изолированное дерево `safety_record_v1` (`stellereum/src/storage.rs:68, 151, 895-913`), равно как и `ConsensusCheckpoint` (`storage.rs:2596-2604`) и `VoteWatermark` (`storage.rs:2633-2670`), **никогда** не включается в экспорт снапшота, не передаётся по сети, не перезаписывается и не сбрасывается при локальном восстановлении или `try_snapshot_sync`.

---

## 1. Инвентаризация по коду (текущее состояние и пробелы)

### 1.1 Как сейчас снимается и сохраняется снапшот

1. **Каденция и триггер**:
   - Интервал задаётся `snapshot_interval()` (`stellereum/src/node/policy.rs:582-588`, env `STELL_SNAPSHOT_INTERVAL`, default `1000`, минимум `50`).
   - Решение принимается в `stellereum/src/snapshot_cadence.rs:35-68` (`snapshot_candidate` / `should_submit_snapshot`): высоты, кратные `snap_int`, плюс сетка `CATCHUP_GRID = 100` (`snapshot_cadence.rs:29`), если разрыв превысил `snap_int`. При `certified_post_height_root == previous_height_root` idle-снапшот пропускается до `floor_due` (`height - last_snapshot_height > snap_int`), давая худший разрыв `snap_int + 100` (`snapshot_cadence.rs:49-81`).
2. **Захват состояния (`node/consensus_driver.rs` + `runtime/lanes.rs` + `runtime/apply.rs`)**:
   - На консенсусном тике (`stellereum/src/node/consensus_driver.rs:4211-4280`) сначала синхронно сериализуется `rt.cross_shard_replay_snapshot().await` (`:4242-4260`); при ошибке или пустом результате захват пропускается.
   - Далее `rt.submit_snapshot(height, root)` (`stellereum/src/runtime/apply.rs:894-913`) ставит в FIFO-очередь `ApplyLane` задачу `LaneJob::Snapshot(SnapshotJob { height, expected_root, done })` (`stellereum/src/runtime/lanes.rs:252-263`).
   - Воркер `ApplyLane` (`runtime/lanes.rs:318-362`) проверяет `state.get_state_root().await != job.expected_root` (если следующий `apply` уже прошёл — отменяет захват без смешивания высот) и клонирует в памяти:
     - `accounts: StateSnapshotV2` (`storage::clone_account_snapshot` → `InMemoryStateEngine::capture_state_snapshot`, `stellereum/src/state_engine/accounts.rs:2311-2324`: отсортированный по `address` вектор `AccountState`, карта штрафов `consensus_penalty`, счётчик `total_minted_nano`);
     - `domains: DomainSnapshot` (`storage.rs:2698-2715`);
     - `session_keys`, `bridge`, `zkml_models`, `cnvrf_v3` (`runtime/lanes.rs:348-352`).
   - На одном из следующих тиков `rt.poll_snapshot()` (`apply.rs:919-935`, `consensus_driver.rs:4301`) забирает `SnapBundle` (`lanes.rs:230-245`) и запускает `tokio::spawn` (`consensus_driver.rs:4340-4505`), который через `serialize_off_tick` (`storage.rs:4527-4531`) целиком сериализует `accounts` и `domains` в `bincode` на `spawn_blocking`.
3. **Локальное хранение (`stellereum/src/storage.rs`)**:
   - Хранилище `sled` (`Storage::open`, `storage.rs:849-891`) раскладывает полный снимок по отдельным height-keyed (`u64::to_be_bytes`) деревьям (`storage.rs:11-24, 477-537`):
     - `state` ← полный монолитный `StateSnapshotV2` (`put_state`, `:1436`),
     - `domains` ← полный монолитный `DomainSnapshot` (`put_domains`, `:1514`),
     - `session_keys`, `bridge`, `zkml_models`, `cross_shard`, `cnvrf_v3` (`PersistJob::Domains` пишет `cross_shard` первым, `:3943-3956`).
   - В `Archive`-режиме (`RetentionConfig::from_env`, `storage.rs:690-702`, `STELL_ARCHIVE=1` по умолчанию) старые снимки не удаляются вообще; в `Prune`-режиме (`consensus_driver.rs:4514-4535`) хранятся последние `snap_int * 3` высот (`prune_state_below` `:1482-1510`, `prune_domains_below` `:1574-1607`, причём `max_h` и `aux_retained_heights` защищены от удаления, `:1650-1690`).

### 1.2 Какие именно домены включаются (и что проверяется корнем)

1. **Trie (`PatriciaTrie`, `state_engine/accounts.rs:2385-2394, 2443-2457`, `storage.rs:2047-2060`)**:
   - листья аккаунтов (`address -> balance || nonce [|| scheme || pubkey_hash]`, 16 или 49 B),
   - STS балансы и total supply (`STS_BAL`, `STS_SUPPLY`),
   - код и ABI-манифесты контрактов (`STELL_CONTRACT_CODE`, `STELL_CONTRACT_ABI`),
   - 2PC записи (`xshard2pc::xpc_state_key`),
   - единый лист дайджеста консенсусных доменов `commitment::commitment_key()` (`stellereum/src/commitment.rs:110-114`).
2. **Дайджест доменов (`commitment.rs:123-157, 542-628, 1729-1781, 1937-2080`, `COMMITMENT_VERSION = 5`)**:
   - `DomainSnapshot` (`storage.rs:2677-2694`, публикуется как `"domains"`): `tokens`, `contracts`, `orderbooks`, `pmm`, `pmm_usdt_token`, `pmm_treasury`, `order_escrow`, `staking`, `governance`, `oracle`.
   - Отдельные деревья/блобы: `"session"` (`session_keys`, условный), `"bridge"` (`bridge`, условный), `"zkml"` (`zkml_models`), `"cross_shard"` (`cross_shard_consumed`, `produced`, `completed`, `xpc` в `CrossShardReplaySnapshot`, `sharding/xshard.rs:1185-1204`, условные), `"cnvrf_v3"` (`cnvrf_v3`, условный).
   - Скаляр `total_minted_nano` (`StateSnapshotV2`, `state_engine/types.rs:707`) — смешивается в `assemble_cached_digest_with_cnvrf_and_minted` (`commitment.rs:2066`).
   - `consensus_penalty` (`StateSnapshotV2`, `state_engine/types.rs:698`) — не входит в `commitment_digest`, но критичен для `fee_floor` (`accounts.rs:2299-2306`).
3. **Расхождение публикации и загрузки (`pq_keys`)**:
   - `sync::SYNC_DOMAIN_KINDS` (`stellereum/src/sync.rs:1275-1283`) включает **7** видов: `["domains", "session", "bridge", "zkml", "cross_shard", "cnvrf_v3", "pq_keys"]`.
   - `network::SNAPSHOT_PUBLISH_DOMAIN_KINDS` (`stellereum/src/network.rs:1142-1149`) включает только **6** видов — `"pq_keys"` **не публикуется** (хотя `Storage::export_pq_keys_blob` в `storage.rs:2563-2565` и `restore_pq_keys` в `accounts.rs:1368-1409` уже написаны).
4. **Локальные деревья, которые НЕ входят и НЕ должны входить в снапшот**:
   - `safety_record_v1` (`storage.rs:68, 151, 895-913`),
   - `meta` (`consensus`: `ConsensusCheckpoint`, `vote_watermark`: `VoteWatermark`, `finalized`),
   - `receipts_v1`, `blocks`, `by_height`, `headers`, `xshard_headers` (`storage.rs:11-24, 520-535`).

### 1.3 Как снапшот публикуется, скачивается и проверяется

1. **Публикация в P2P/DHT (`network.rs` + `consensus_driver.rs`)**:
   - Доменные блобы (`6` штук) и монолитный `state` отправляются в `publish_lane` (`consensus_driver.rs:4426-4495`, пауза 40 мс между доменами).
   - `persist_state_snapshot` (`network.rs:1982-2059`) пишет под именем `{epoch}_snap_{shard}_{height}` (`network.rs:87-89`) с `ReplStoreKind::Bulk` и TTL `STELL_DHT_FOREVER_TTL_MS` (100 лет, `:200`), и только при `stored > 0` сдвигает указатель `{epoch}_snap_latest_{shard}` (`store_pointer_overwrite`, `:2040-2050`).
   - `persist_domain_snapshot` (`network.rs:2404-2444`) пишет под именем `{epoch}_snap_{shard}_{height}_dom_{kind}` тем же `ReplStoreKind::Bulk` и FOREVER TTL.
   - Внутри `infnode` каждый `store_blob_impl` (`infnode/crates/infnode/src/node.rs:7250-7369`) шифрует payload детерминированным ключом, режет на чанки `BLOB_CHUNK_BYTES = 1 MiB` (`node.rs:9356`), раскладывает чанки по DHT и сохраняет JSON-манифест в `kv.json` (на который указывает `network.rs:140-146`).
2. **Скачивание у пиров (`node/sync.rs` + `network.rs` + `sync.rs`)**:
   - В `try_catch_up` (`stellereum/src/node/sync.rs:564-739`) при разрыве `peer_height - our_height > 100` вызывается `try_snapshot_sync` (`node/sync.rs:83-455`).
   - `try_snapshot_sync` читает указатель `fetch_latest_snapshot` (`:143`, `network.rs:2064-2087`), иначе шагает по сетке `snapshot_probe_step` / `snapshot_probe_steps` (`sync.rs:2103-2123`).
   - **Скачивание**: `fetch_state_snapshot` (`network.rs:2102-2116`) и `fetch_domain_snapshot` (`network.rs:2452-2475`) держат семафоры `fetch_sem()` (cap `8`, `:1168`, `sync.rs:1814`) → `snapshot_fetch_sem()` (cap `2`, `:1180`, `sync.rs:1843`) и используют `fetch_large_blob_resumable` (`network.rs:2256-2393`) + `assemble_chunks_resumable` (`sync.rs:1957-2032`, серийно при `> 8` чанков, `:2049, 2145-2150`, таймаут чанка `20s`, 6 ретраев, бюджет блоба `min(300s, max(60s, 15s*N + 30s))`).
   - **Проверка (`sync.rs` + `node/sync.rs`)**:
     - В `node/sync.rs:180-313` проверяется заголовок `boundary + 1` (`next_hdr.height`, `next_hdr.block_hash`, `next_hdr.prev_hash == boundary_hash`) и QC-цепочка: при `genesis_anchored || gap > 50` через `verify_snapshot_anchor_tail_with_sets_and_schedule` (`sync.rs:796-887`), иначе через полный проход `verify_snapshot_anchor_with_schedule` (`sync.rs:512-620`) с `rt.committee_schedule_at` (`runtime/anchors.rs:246-252`).
     - Затем `fast_sync_state_with_set_binding_prefetched` (`sync.rs:1369-1395` → `fast_sync_verify_commit` `:1494-1617`) последовательно скачивает `SYNC_DOMAIN_KINDS`, восстанавливает всё в throwaway `InMemoryStateEngine`, проверяет:
       1. `computed_root == anchor.state_root` (`:1541-1548`),
       2. F5 `check_snapshot_set_binding` (`:1415-1458`, `decode_domain_snapshot_strict` `:3381-3395` + совпадение `ValidatorSet` с `anchor_set`),
       3. F1 `cross_shard_replay_covers` (`:1574-1607`),
       и только после этого применяет в `rt.state`.
     - Далее `node/sync.rs:382-431` обновляет `rt.finalized`, сбрасывает `rt.hc`, проверяет свежесть набора валидаторов (`refresh_validator_set_from_staking_checked`) и переякоряет лёгкий клиент (`rt.reanchor_light_client_at_snapshot`, `runtime/anchors.rs:1324-1409`).

### 1.4 Где полная пересылка вместо дельт/чанков и выявленные DoS / integrity риски

| # | Область | Факт в коде (`file:line`) | Риск (DoS / Bandwidth / Integrity) |
|---|---|---|---|
| G1 | **Полная пересылка монолитов** | `consensus_driver.rs:4354-4487`, `network.rs:1982-2013, 2404-2444`, `storage.rs:1436, 1514, 2677` | На каждом интервале сериализуются, пишутся в `sled` и рассылаются в DHT **все** аккаунты (`StateSnapshotV2`) и **все** домены (`DomainSnapshot`, `session`, `bridge`, `zkml`, `cross_shard`, `cnvrf_v3`). Код `create_snapshot_chunked` (`state_engine/memory_bounds.rs:522-547`) написан, но не подключён к live-пути. С ростом состояния `kv.json` и `chunks/` раздуваются, а `startup_budget = 20s` (`consensus_driver.rs:1181`) гарантированно срывается на слабом канале. |
| G2 | **Обход валидации манифеста (OOM + нехешированные чанки)** | `network.rs:2182-2231, 2352-2355`, `sync.rs:1967` vs `infnode/crates/infnode/src/node.rs:7676-7728` | В `infnode::fetch_blob` проверки границ есть (`MAX_BLOB_CHUNKS = 4096`, `MAX_BLOB_BYTES = 32 MiB`, `off`/`len`, обязательный `hash`), но `network::fetch_snapshot_manifest` (`network.rs:2127-2232`) их **не вызывает**! Манифест может объявить `n_chunks = 10_000_000` (мгновенная OOM-аллокация `slots` в `assemble_chunks_resumable` на `sync.rs:1967`), опустить `c["hash"]` (`SnapshotChunkMeta.hash: Option<String>` на `network.rs:1201` → `fetch_chunk_net` на `infnode/node.rs:6624-6632` при `None` **не проверяет хеш чанка**!), или склеить `ct` свыше 512 MiB без проверки суммарного размера (`network.rs:2352-2355`). |
| G3 | **Download-before-Verify в `try_snapshot_sync`** | `node/sync.rs:143-175` до `:180-313` | `try_snapshot_sync` сначала читает неподписанный `fetch_latest_snapshot` (shared last-writer-wins в DHT) и **скачивает весь многомегабайтный `fetch_state_snapshot`** (`:166`), и лишь затем проверяет заголовок `boundary + 1` и `precommit_qc` (`:180-313`). Атакующий может подсунуть фальшивый `snap_latest` или манифест и заставить узел качать десятки мегабайт до любой криптографической проверки. |
| G4 | **Отравление DHT-имени без `state_root` и подписи** | `network.rs:87-99, 2040-2050, 2411-2414` | Имя `{epoch}_snap_{shard}_{height}` (и `_dom_{kind}`, `_snap_latest_{shard}`) не содержит ни `state_root`, ни хеша манифеста, ни подписи валидатора. С учётом `FOREVER` TTL (`network.rs:200`) отравленный манифест на высоте `H` в DHT блокирует честный снапшот на той же высоте (и вызывает до `300s` простоя на попытку). |
| G5 | **Двойная-тройная пиковая память при проверке** | `sync.rs:1534-1616`, `storage.rs:3562-3675` | `fast_sync_verify_commit` держит в RAM сырой `Vec<u8>` + `bundle` + `temp_engine` (с полной копией trie) + `target_engine`. Для больших стейтов это 2×–3× RAM. |
| G6 | **Пробел `pq_keys` + tip-исключение локально** | `network.rs:1142-1149` vs `sync.rs:1282`; `storage.rs:1978-1987` | `"pq_keys"` не публикуется в `SNAPSHOT_PUBLISH_DOMAIN_KINDS`; локально `verify_restored_root` при `snapshot_height == tip` пропускает проверку корня (`storage.rs:1987`, зафиксировано и в `REVIEW_INTEGRATION.md:203`). |
| G7 | **Непоследовательность бюджета времени** | `node/policy.rs:671-680` (`180s`) vs `sync.rs:1880` (`300s` × 8) vs `consensus_driver.rs:1181` (`20s`) | Таймаут одного блоба (`300s`) больше бюджета `try_catch_up` (`180s`) и кратно больше стартового бюджета (`20s`), а в `try_snapshot_sync` последовательный `for`-цикл по доменам может оборваться по `tokio::time::timeout`, не оставив сохранённого прогресса чанков между перезапусками catch-up. |

---

## 2. Целевой контракт инкрементальных и чанкованных снапшотов (S4)

### 2.1 Модель данных: Base Checkpoint + Bucket/Domain Chunks + Delta Chain

Вместо двух монолитных блобов (`StateSnapshotV2` + `DomainSnapshot`) + 6 отдельных доменных блобов вводится унифицированный формат **State Checkpoint v4 (`SnapV4`)** с двумя режимами на одном и том же каноническом состоянии:

1. **Режим `Base` (базовый, контентно-адресуемый по префиксам и доменам)**:
   - Аккаунты разбиваются детерминированно по **фиксированному разбиению адресного пространства** на `N_BUCKETS = 256` бакетов по первому байту адреса `addr[0] ∈ 0x00..=0xFF` (внутри каждого бакета записи отсортированы по `address: [u8; 32]`).
     - Если бакет содержит > `MAX_ACCOUNTS_PER_CHUNK` (`16_384`), он суб-разбивается на детерминированные поддиапазоны по 2-му байту (или фиксированным слайсам в отсортированном порядке) так, чтобы каждый несжатый чанк укладывался в `MAX_SNAP_CHUNK_BYTES = 1 MiB` (после добавления заголовка чанка — совместимо с `BLOB_CHUNK_BYTES = 1 MiB`, `infnode/node.rs:9356`).
     - Пустые бакеты не порождают сетевых чанков (в манифесте кодируются как `empty_hash = BLAKE3("STELL_SNAP_BUCKET_EMPTY_V1")` и не передаются).
   - Неаккаунтные домены и скаляры разделяются на независимые адресуемые единицы (`DomainUnitId`):
     - `Scalars` (`penalty`, `total_minted_nano`),
     - `Tokens`, `Contracts` (при превышении `MAX_SNAP_CHUNK_BYTES` режутся по отсортированным ключам `Contract` / `Token` на суб-чанки), `Orderbooks`, `Pmm` (`pmm`, `pmm_usdt_token`, `pmm_treasury`), `OrderEscrow`, `Staking`, `Governance`, `Oracle`,
     - `SessionKeys`, `Bridge`, `ZkMl`, `CrossShard` (включая `xpc`), `CnVrfV3`, `PqKeys`.
   - Каждый бакет/домен-чанк получает `content_hash = BLAKE3("STELL_SNAP_UNIT_V1\0" || unit_id || raw_bytes)`. **Неизменившиеся бакеты и домены между двумя `Base`-чекпоинтами имеют одинаковый `content_hash`** — принимающая сторона и локальный `sled` переиспользуют их без повторной пересылки и дублирования на диске.

2. **Режим `Delta` (инкрементальный state-diff `B_base → B_target`)**:
   - Строится от ближайшего завершённого `Base` (или цепочки `Base → Δ₁ → ... → Δ_k`, где `k <= MAX_DELTA_CHAIN_LEN = 8`, иначе публикуется новый `Base`).
   - Для каждого бакета аккаунтов (`0..256`), у которого `unit_hash(B_target) != unit_hash(B_base)`:
     - передаётся `AccountBucketDelta { bucket: u8, expected_base_hash: [u8; 32], upserts: Vec<AccountState>, deletes: Vec<[u8; 32]> }` (строго отсортированы по `address`, без дубликатов).
     - если размер `AccountBucketDelta` ≥ 70% размера полного бакета — публикуется полный бакет `FullUnit` (чтобы не тратить лишний CPU/байты).
   - Для `Scalars`: всегда передаётся `(penalty_upserts, penalty_deletes, total_minted_nano)`.
   - Для каждого домена из `DomainUnitId`:
     - если `unit_hash(B_target) == unit_hash(B_base)`: в манифесте/дельте указывается `Unchanged { content_hash }` (0 байт payload);
     - если изменился: для map-ориентированных доменов (`Contracts`, `Tokens`, `Orderbooks`, `OrderEscrow`, `CrossShard`, `PqKeys`) допускается `MapDiff { base_hash, upserts, deletes }`, либо (если домен компактный, например `Pmm`, `Governance`, `Oracle`, `Staking`, `SessionKeys`, `Bridge`, `ZkMl`, `CnVrfV3`, или diff > 70% полного размера) — `ReplaceDomain { bytes }`.
   - **`PqKeys` в дельте и базе**: включается как отдельный **не-root-критический** `DomainUnitId::PqKeys` (хешируется в `chunk_merkle_root` манифеста, но не в `state_root`), с той же поштучной верификацией `blake3(pk) == account.pubkey_hash && derive_pq_address(scheme, pk, salt) == addr` (`state_engine/accounts.rs:1342-1347`). Отсутствие опционального `PqKeys` не ломает `state_root`, но при наличии `PqKeys` убирает текущий пробел между `SYNC_DOMAIN_KINDS` и `SNAPSHOT_PUBLISH_DOMAIN_KINDS`.

### 2.2 Аутентифицированный манифест и криптографическая привязка (до скачивания данных!)

```rust
pub enum SnapshotKind {
    Base,
    Delta { base_height: u64, base_state_root: [u8; 32] },
}

pub struct SnapshotUnitDesc {
    pub unit_tag: u16,            // AccountBucket(0..256) | DomainUnitId | DeltaChunk
    pub sub_index: u16,           // для нарезки крупных контрактов/бакетов
    pub encoding: u8,             // 0 = FullUnit, 1 = BucketDelta, 2 = UnchangedRef
    pub unit_hash: [u8; 32],      // BLAKE3 контента единицы на target_height
    pub chunk_hash: [u8; 32],     // BLAKE3 передаваемого wire-чанка (или [0;32] при UnchangedRef)
    pub byte_len: u32,            // 0 при UnchangedRef; иначе 1..=MAX_SNAP_CHUNK_BYTES
}

pub struct SnapshotManifestV1 {
    pub magic: [u8; 8],           // b"STLSNPM1"
    pub version: u16,             // 1
    pub chain_id: u64,            // consensus_chain_id()
    pub shard_id: u32,
    pub kind: SnapshotKind,
    pub target_height: u64,
    pub target_block_hash: [u8; 32],
    pub target_state_root: [u8; 32],
    pub validator_set_hash: [u8; 32], // BLAKE3 канонического validator_set_for_height(target_height)
    pub total_wire_bytes: u64,
    pub total_uncompressed_bytes: u64,
    pub units_merkle_root: [u8; 32],  // BLAKE3-Merkle над всеми SnapshotUnitDesc
    pub units: Vec<SnapshotUnitDesc>,
    pub publisher_id: [u8; 32],
    pub publisher_sig: Vec<u8>,       // Falcon-512 подпись над доменом "STELL_SNAP_MANIFEST_V1\0"
}
```

**Протокол привязки к finalized `state_root` + `precommit_qc` (строгий порядок, fail-closed):**

1. **Якорение заголовков (ДО загрузки чанков данных!)**:
   - Для кандидата `target_height = H` узел сначала проверяет цепь заголовков и кворумные сертификаты до `H + 1`:
     - через `verify_snapshot_anchor_tail_with_sets_and_schedule(H + 1, ...)` (`stellereum/src/sync.rs:796-887`) или `verify_snapshot_anchor_with_schedule(..., H + 1, ...)` (`sync.rs:512-620`).
   - Получаем проверенные консенсусом `trusted_state_root = anchor.state_root` (это `header(H + 1).state_root`) и `trusted_boundary_hash = anchor.boundary_hash` (это `block_hash(H)`, дополнительно подтверждённый `next_hdr.prev_hash == trusted_boundary_hash` и `precommit_qc(H)`).
2. **Получение и Pre-Fetch верификация `SnapshotManifestV1`**:
   - Манифест адресуется по контентному ключу `(shard_id, target_height, trusted_state_root)` (имя в DHT `{epoch}_snapm_{shard}_{H}_{hex8(trusted_state_root)}`), а не только по голой высоте — **подмена/отравление другого состояния на той же высоте под тем же именем невозможна**.
   - Указатель `snap_latest_v2_{shard}` (если читается) обязан содержать `(height, state_root, publisher_id, publisher_sig)`; перед пробингом его `height` и `state_root` немедленно проверяются через `header(H + 1)` + `precommit_qc(H + 1)` (если `snap_latest_v2` не сходится с QC — он отбрасывается за миллисекунды без скачивания снапшота!).
   - **Обязательные проверки манифеста до аллокации и скачивания чанков**:
     1. `manifest.magic == *b"STLSNPM1"` и `manifest.version == 1`; `manifest.chain_id == consensus_chain_id()`; `manifest.shard_id == shard`.
     2. `manifest.target_height == H`, `manifest.target_block_hash == trusted_boundary_hash`, `manifest.target_state_root == trusted_state_root`.
     3. `manifest.validator_set_hash == canonical_vset_hash(&rt.validator_set_for_height(H))` (если пустой `ValidatorSet` — отказ, как в `check_snapshot_set_binding` на `sync.rs:1443`).
     4. Валидация подписи публикатора: `vset_at_H.power_of(&manifest.publisher_id) > 0` и `verify_pq_signature` ключом `pq_key_at_height(&manifest.publisher_id, H)` над `BLAKE3("STELL_SNAP_MANIFEST_V1\0" || canonical_manifest_body_bytes)`.
     5. Проверка лимитов (см. §2.4): `units.len() <= MAX_SNAP_UNITS`, `total_wire_bytes <= MAX_SNAP_WIRE_BYTES`, `total_uncompressed_bytes <= MAX_SNAPSHOT_DECODE_BYTES`, для каждого элемента `byte_len <= MAX_SNAP_CHUNK_BYTES`, сумма `byte_len == total_wire_bytes`, `units_merkle_root` сходится.
     6. Для `SnapshotKind::Delta { base_height, base_state_root }`: `base_height < H`, причём либо узел уже держит локальный verified snapshot на `base_height` с точным `state_root == base_state_root`, либо рекурсивно разрешает цепочку `Base -> Δ_1 -> ... -> Δ_k` глубиной `<= MAX_DELTA_CHAIN_LEN`, где **каждый** промежуточный `base_state_root` и `target_state_root` подтверждён QC-заголовком `header(h + 1)`.
3. **Загрузка чанков у пиров и поштучная проверка**:
   - Первичный путь: **прямой peer-to-peer chunk pull** (`SnapshotNetMsg::GetUnit { shard_id, unit_hash, chunk_hash }` через `request_to` по живым/здоровым пирам с round-robin + fallback в DHT `fetch_chunk_net(..., Some(&expected_hex))`).
   - **Обязательная проверка каждого чанка сразу по получении**: `blake3::hash(&bytes) == desc.chunk_hash` и `bytes.len() == desc.byte_len as usize`. При любом несовпадении: чанк отвергается до помещения в буфер сборки, пир-отправитель помечается страйком (`misbehavior` / временный backoff) и чанк добирается у другого пира без сброса уже скачанных валидных чанков.
   - При этом `fetch_snapshot_manifest` и `fetch_large_blob_resumable` в `stellereum/src/network.rs:2127-2393` (и для legacy-пути) обязаны получить те же жёсткие лимиты `MAX_BLOB_CHUNKS`, `MAX_BLOB_BYTES` / `MAX_SNAPSHOT_DECODE_BYTES`, обязательность `hash`, проверку `off`/`len` и суммы размеров.

### 2.3 Проверка до коммита (Throwaway Verification & Atomic Staging)

Запрещено изменять живой `rt.state` или перезаписывать активные деревья `sled` до завершения полной криптографической верификации:

1. **Изолированная сборка (Staging / Throwaway)**:
   - В `sync.rs`: для `Base` создаётся чистый throwaway `InMemoryStateEngine::new()`, для `Delta` — клонируется / материализуется проверенное состояние `B_base` в изолированный throwaway-движок (или `OverlayStateEngine` без мутации `rt.state`).
   - **Проверка базового снапшота перед наложением дельты**: `base_engine.get_state_root().await == delta.base_state_root`. Несовпадение = немедленный отказ (`Err("delta base_state_root mismatch")`) и fallback на скачивание полного `Base` на высоте `H` (живой движок не затронут!).
   - Декодирование каждой единицы и дельты выполняется строго через `bincode::DefaultOptions::new().with_fixint_encoding().with_limit(...).reject_trailing_bytes()` (правило `decode_domain_snapshot_strict` в `storage.rs:3381-3395`).
   - После применения всех единиц и дельт в throwaway-движок:
     - Пересобирается `PatriciaTrie` (`sync_aux_trie` + аккаунты + 2PC + commitment leaf).
     - Проверяется **F5 set-at-height binding**: `staking.to_validator_set().validators == anchor_set.validators` и не пуст (`sync.rs:1415-1458`).
     - Проверяется **F1 cross-shard replay coverage**: `target_engine.cross_shard_replay_covers(&incoming)` (`sync.rs:1574-1607`).
     - Вычисляется `computed_root = throwaway.get_state_root().await` и сравнивается с `trusted_state_root` (`header(H + 1).state_root` из `precommit_qc`). Несовпадение = hard fail, **никаких записей в `rt.state` или `sled`**.
2. **Атомарный коммит (память + диск)**:
   - Сначала в `sled`: собранные/материализованные единицы на высоту `H` (через контентно-адресуемое хранилище `snap_units` + мета-индекс `snap_manifests[H]`) записываются и `flush`-атся в состоянии `staged`, и только последним атомарным `insert` проставляется указатель/запись `snap_committed[H]` (data-before-index по образцу `put_block`, `storage.rs:956-984`). При падении питания до записи `snap_committed[H]` недописанный снапшот на старте игнорируется/подметается и никогда не считается валидным.
   - Затем обновляется `rt.state`, `rt.finalized`, `rt.hc`, `rt.refresh_validator_set_from_staking_checked(H, H)`, `rt.reanchor_light_client_at_snapshot(H, &boundary_block)`.

### 2.4 Жёсткие лимиты размера, таймаутов и памяти (Anti-DoS)

| Параметр | Значение | Где применяется | Назначение |
|---|---|---|---|
| `MAX_SNAP_UNITS` | `4_096` | `manifest` pre-fetch (`sync.rs`, `network.rs`) | Не допускает OOM при `Vec::with_capacity` / `slots` от поддельного манифеста (выровнено с `MAX_BLOB_CHUNKS = 4096` в `infnode/node.rs:9353`). |
| `MAX_SNAP_CHUNK_BYTES` | `1 MiB` (`1_048_576` B) | pre-fetch & per-chunk recv (`network.rs`, `sync.rs`) | Соответствует `BLOB_CHUNK_BYTES` (`infnode/node.rs:9356`) и помещается в один chunk-буфер. |
| `MAX_SNAP_WIRE_BYTES` | `256 MiB` (для Delta рекомендуется мягкий бюджет `<= 64 MiB`) | `manifest` pre-fetch & aggregator (`network.rs`, `sync.rs`) | Ограничивает суммарный трафик одного снапшота до начала скачивания. |
| `MAX_SNAPSHOT_DECODE_BYTES` | `512 MiB` | `decode_*_strict` (`storage.rs:3363`, `state_engine/mod.rs:63`) | Верхняя граница распакованного bincode-объёма. |
| `MAX_DELTA_CHAIN_LEN` | `8` | `sync.rs`, `node/sync.rs` | Не более 8 последовательных дельт поверх одного `Base`; глубже — автоматический switch на `Base` snapshot. |
| `SNAPSHOT_FETCH_MAX_CONCURRENCY` | `2` (внутри `FETCH_MAX_CONCURRENCY = 8`) | `network.rs:1168-1185`, `sync.rs:1814, 1843` | Сохраняет глобальный порядок блокировок `fetch_sem -> snapshot_fetch_sem`. |
| `SNAP_CHUNK_CONCURRENCY_PER_BLOB` | `1` для >8 чанков, до `4` для мелких дельт | `sync.rs:1972, 2042-2049, 2145-2150` | Защита 1-vCPU нод и 256-stream QUIC cap от самовозбуждения. |
| `SNAP_MANIFEST_TIMEOUT_MS` | `10_000` мс (`SNAPSHOT_MANIFEST_TIMEOUT_MS`) | `network.rs:2134`, `sync.rs:1873` | Быстрый отказ на отсутствующей/непубликовавшейся границе. |
| `SNAP_CHUNK_TIMEOUT_MS` | `20_000` мс (`SNAPSHOT_CHUNK_TIMEOUT_MS`), до `6` ретраев | `network.rs:2307`, `sync.rs:1853, 1860` | Повтор только потерянного чанка (с ротацией пира). |
| `SNAP_DELTA_BUDGET_MS` / `SNAP_BLOB_TIMEOUT_MS` | `60_000` мс (дельта) / `300_000` мс (base) | `sync.rs:1880, 1898-1907`, `node/policy.rs:671-680` | **Важно для `try_catch_up`**: многошаговое скачивание `Base`/`Delta` должно сохранять прогресс верифицированных чанков в локальном кэше `snap_staging` между прерываниями `catchup_budget`, чтобы повторный проход докачивал только недостающие чанки! |
| Пиковая память сборки | Потоковая: в RAM только 1 декодируемый чанк + staging-индекс (`<= MAX_SNAP_CHUNK_BYTES` на активный стрим) + throwaway engine | `sync.rs`, `state_engine/memory_bounds.rs` | Устраняет одновременное удержание сырых 50 МБ байт всех доменов рядом с `temp_engine` и `target_engine`: каждый проверенный чанк освобождается сразу после вставки в throwaway-движок (или пишется в контентно-адресуемое дерево `sled`). |

### 2.5 Совместимость со старыми полными снапшотами

1. **Локальная загрузка при старте (`storage::load_full_state_into`, `storage.rs:3506-3683`)**:
   - Если в `sled` присутствует актуальный `snap_committed[H]` (формат `SnapV4`: base или base+delta), используется новый путь;
   - Если `snap_committed` отсутствует или ниже высоты `latest_paired_snapshot()`, загрузчик **бесшовно** читает существующие деревья `state` (`StateSnapshotV2` + legacy fallback `accounts.rs:2508-2581`) + `domains` (`decode_domain_snapshot` V1..V8, `storage.rs:3280-3357`) + `session_keys`, `bridge`, `zkml_models`, `cross_shard`, `cnvrf_v3` без требования wipe data-dir.
2. **Сетевой fallback в `try_snapshot_sync` (`node/sync.rs` + `network.rs`)**:
   - При наличии пиров со старыми публикациями `{epoch}_snap_{shard}_{height}` (нет `{epoch}_snapm_...` `SnapshotManifestV1`), узел может переключиться на legacy `fetch_state_snapshot` + `fetch_domain_snapshot` (`fast_sync_state_with_set_binding_prefetched`), **но только при соблюдении новых лимитов манифеста** (`MAX_BLOB_CHUNKS`, `MAX_SNAPSHOT_DECODE_BYTES`, обязательный `hash` чанка в `fetch_snapshot_manifest` — тем самым закрывается G2 даже на legacy-пути) и с проверкой `header(H+1)` + `precommit_qc` **до** скачивания тела снапшота (закрывается G3).
   - Публикация (`consensus_driver.rs`): в переходный период (пока все валидаторы не обновились) публикатор может либо дублировать `Base` в старом формате на `base_snapshot_interval` (за флагом `STELL_PUBLISH_LEGACY_FULL_SNAPSHOT=1`, default `0` после перехода), либо публиковать `SnapV4` как основной путь.

### 2.6 Взаимодействие с `SafetyRecordStore` (жёсткий барьер изоляции)

`SafetyRecordStore` (`stellereum/src/storage.rs:50-255, 895-913`) защищает валидатора от двойной подписи (equivocation) при сбоях, откатах и рестартах:
- **Изоляция дерева и API**: `SafetyRecordStore` открывает исключительно дерево `SAFETY_TREE = "safety_record_v1"` (`storage.rs:68, 900`) и при любой ошибке чтения/декода/идентичности/записи/флаша переводит все хендлы в перманентный карантин `safety_failed: Arc<Mutex<bool>>` (`storage.rs:155, 173-191, 223-251`).
- **Контрактные запреты для S4**:
  1. **Никогда не экспортируется**: ни `SnapBundle`, ни `SnapshotManifestV1`, ни `DeltaSnapV1`, ни `Base` не имеют права читать `safety_record_v1`, `meta["consensus"]` (`ConsensusCheckpoint`) или `meta["vote_watermark"]` (`VoteWatermark`).
  2. **Никогда не импортируется / не затирается**: ни `fast_sync_incremental`, ни `restore_snapshot*`, ни `apply_delta`, ни `commit_staged_snapshot` в `storage.rs` не касаются `safety_record_v1`, `meta["consensus"]` или `meta["vote_watermark"]`.
  3. **Никогда не сбрасывается и не разблокируется**: если `safety_failed == true` (карантин) или в `safety_record_v1` уже записана `generation >= 1`, успешный `try_snapshot_sync` (даже если он перепрыгнул вперёд на сотни/тысячи высот!) **не очищает** `safety_record_v1`, **не снижает** `generation` и **не сбрасывает** `safety_failed`.
  4. **Монотонность safety-пола при прыжке по снапшоту**: при обновлении `rt.hc = HeightConsensus::new(boundary + 1, ...)` (`node/sync.rs:386`) консенсусный цикл (`consensus_driver.rs:1198-1230, 1889-1917`) **обязан** проверять, что для новой высоты `boundary + 1` (и тем более если `boundary + 1 == старая высота`) локальные `VoteWatermark` / `SafetyRecordStore` не были перепрыгнуты назад; при `boundary + 1 <= max_signed_height_from_safety_store` узел переходит в режим observer/не голосует на уже подписанной `(height, round, kind)`!
  5. **Удаление/прунинг**: `prune_state_below`, `prune_domains_below`, `prune_deltas_below` и очистка `snap_staging` не итерируют и не удаляют `safety_record_v1`.

---

## 3. Непересекающаяся матрица владения файлами (для кодовых агентов W1)

Согласно `AGENTS.md` §2 и §8, каждый кодовый агент работает строго в своём непересекающемся наборе файлов (ни один файл не изменяется двумя агентами). Существующие `stellereum/src/runtime/anchors.rs` и `stellereum/src/commitment.rs` в W1/S4 **не изменяются** (read-only зависимости).

| Агент / Поток | Разрешённые файлы (строго disjoint) | Ответственность |
|---|---|---|
| **W1-S4-A (Codec & Delta Engine)** | `stellereum/src/snapshot_delta.rs` *(new)*, `stellereum/src/lib.rs` *(только `pub mod snapshot_delta;`)*, `stellereum/src/state_engine/memory_bounds.rs`, `stellereum/src/state_engine/accounts.rs`, `stellereum/src/state_engine/types.rs`, `stellereum/tests/snapshot_delta_codec_tests.rs` *(new)* | Типы `SnapshotManifestV1`, `SnapshotKind`, `SnapshotUnitDesc`, `AccountBucketDelta`, `DomainDelta`; разбиение на 256 префикс-бакетов и доменные единицы; вычисление diff `Base → Target`, применение diff в throwaway engine; строгий fixint-декод (`reject_trailing_bytes`) и интеграция с `create_snapshot_chunked` / `restore_snapshot_chunked_preserve_replay_sets`. |
| **W1-S4-B (Storage & Safety Guard)** | `stellereum/src/storage.rs`, `stellereum/tests/snapshot_storage_safety_tests.rs` *(new)* | Деревья `snap_units` (контентно-адресуемое дедуплицированное хранение бакетов/доменов), `snap_manifests`, `snap_committed`, `snap_staging`; data-before-commit запись и crash-sweep незавершённых `snap_staging`; расширение `load_full_state_into` (приоритет `snap_committed`, fallback на legacy `state`/`domains` V1..V8); `prune_deltas_below`; гарантия неприкосновенности `safety_record_v1` (`SafetyRecordStore`), `ConsensusCheckpoint` и `VoteWatermark`. |
| **W1-S4-C (Sync & Verification)** | `stellereum/src/sync.rs`, `stellereum/src/bootstrap.rs`, `stellereum/src/snapshot_cadence.rs`, `stellereum/tests/snapshot_incremental_verify_tests.rs` *(new)* | Pre-fetch валидация `SnapshotManifestV1` (`chain_id`, лимиты, `units_merkle_root`, Falcon-512 `publisher_sig`, сверка с QC-якорем `header(H+1).state_root` + `precommit_qc(H+1)` + `precommit_qc(H)`); цепочка `Base → Δ_1..Δ_k` (`<= MAX_DELTA_CHAIN_LEN`); `fast_sync_incremental` (проверка `base_state_root`, throwaway сборка, F5 set-binding, F1 replay coverage, `computed_root == trusted_state_root` до коммита, fallback на `Base` / legacy). |
| **W1-S4-D (P2P / DHT Transport)** | `stellereum/src/network.rs`, `stellereum/tests/snapshot_network_dos_tests.rs` *(new)* | Контентные имена `{epoch}_snapm_...`, `{epoch}_snapu_...` и подписанный `{epoch}_snap_latest_v2_{shard}`; прямой peer-pull юнитов/манифестов с ротацией пиров + fallback в DHT; закрытие пробела `fetch_snapshot_manifest` / `fetch_large_blob_resumable` (лимиты `MAX_BLOB_CHUNKS`, `MAX_SNAPSHOT_DECODE_BYTES`, обязательный `hash`, `off`/`len`); добавление `"pq_keys"` в `SNAPSHOT_PUBLISH_DOMAIN_KINDS`; сохранение семафорного порядка `fetch_sem -> snapshot_fetch_sem`. |
| **W1-S4-E (Node Driver Wiring)** | `stellereum/src/node/sync.rs`, `stellereum/src/node/consensus_driver.rs`, `stellereum/src/node/policy.rs`, `stellereum/tests/snapshot_e2e_sync_tests.rs` *(new)* | Перевод `try_snapshot_sync` на схему «сначала манифест + QC-якорь, потом чанки/дельты с persistent staging»; управление `base_snapshot_interval` vs `delta_snapshot_interval` на публикации; проверка safety-пола (`VoteWatermark` / `SafetyRecordStore`) при прыжке `rt.hc` вверх; интеграция с `catchup_pass_budget_ms` и `startup_budget`. |

*Порядок мержа/зависимостей*: `A` (чистые типы и diff) и `B` (storage) не зависят друг от друга (`B` использует байты/хеши, или `B` читает уже вмерженный `A`); `C` и `D` опираются на контракт типов `A`; `E` собирает `B + C + D`. Запрещено изменять `infnode` (взаимодействие только через публичный API `Node`), `commitment.rs`, `runtime/anchors.rs` и `sharding/block.rs`.

---

## 4. Обязательный список тестов для кодовых агентов W1

Каждый пункт из таблицы ниже должен быть оформлен автоматизированным тестом (unit + fault-injection + E2E без мока криптографических проверок) в тестах соответствующего агента и пройти гейт `cargo clippy --all-targets -- -D warnings` и `cargo test --no-fail-fast`:

1. **Повреждённая / усечённая дельта (`corrupted_delta_rejected`)** `[Агенты A, C]`:
   - Битый бит в одном из `AccountBucketDelta` или `MapDiff`, обрезанный хвост, лишние trailing bytes, неверный `chunk_hash` или поддельный `units_merkle_root`.
   - Ожидание: отвергается на проверке чанка / строгом bincode-декоде до модификации `target_engine` и без записи в `snap_committed`; при поштучном отказе от пира качается резервный чанк у честного пира без потери уже скачанных валидных чанков.
2. **Несовпадение `state_root` (`state_root_mismatch_fail_closed`)** `[Агенты C, E]`:
   - Валидно подписанный `SnapshotManifestV1` или дельта, у которой итоговое состояние после наложения на `Base` даёт `computed_root != trusted_state_root` (из `header(H+1).state_root` с валидным `precommit_qc`).
   - Ожидание: throwaway-проверка возвращает `Err`, `target_engine` (его балансы, trie, replay sets, staking, governance) остаётся побайтово идентичен состоянию до `try_snapshot_sync`; в `sled` ничего не коммитится.
3. **Подмена базового снапшота (`base_snapshot_substitution_rejected`)** `[Агенты A, C, E]`:
   - Случай (а): локальный узел на высоте `B_base` имеет **другой** `state_root` (форк или локальная дивергенция), чем `delta.base_state_root`.
   - Случай (б): злоумышленник подсунул дельту с верным `target_height`, но с чужим/поддельным `base_state_root` (не совпадающим с QC-якорем `B_base + 1`) или с перестановкой чанков между двумя разными `Base`.
   - Ожидание: отклоняется **до** наложения дельты (случай б — на pre-fetch этапе до скачивания чанков); узел уходит в fallback-скачивание чистого `Base` снапшота на `target_height`, не трогая `rt.state`.
4. **Обрыв сети / таймаут / резюмирование (`network_drop_and_resume`)** `[Агенты D, E]`:
   - Потеря соединения посреди передачи дельты/базы (dropped chunks, timeout на части чанков, превышение `catchup_budget` в середине передачи, смена пира, crash-прерывание на стадии `snap_staging`).
   - Ожидание: уже скачанные и проверенные по `chunk_hash` чанки сохраняются в `snap_staging`, повторный проход докачивает только недостающие; при обрыве до `snap_committed` рестарт `Storage::open` + `load_full_state_into` не видит полуприменённого снапшота и чисто восстанавливается с предыдущего проверенного чекпоинта.
5. **DoS-границы манифеста и до-загрузочный отказ (`manifest_dos_and_prefetch_auth`)** `[Агенты C, D]`:
   - Поддельный манифест с `units.len() > MAX_SNAP_UNITS`, `total_wire_bytes > MAX_SNAP_WIRE_BYTES`, пропущенным `hash` чанка, неверным `publisher_sig` (подпись не из `validator_set_for_height(H)`), или отравленным `snap_latest_v2`.
   - Ожидание: отказ до аллокации `slots`/`Vec` и до первого `fetch_chunk` запроса; для legacy `fetch_snapshot_manifest` тоже подтверждается отказ без OOM.
6. **Сохранность `SafetyRecordStore` (`safety_record_v1_untouched`)** `[Агенты B, E]`:
   - В `Storage` инициализирован `SafetyRecordStore` (`safety_record_v1`, `generation = 7`, payload `P`) плюс `ConsensusCheckpoint` и `VoteWatermark`.
   - Прогоняются: (а) экспорт `Base` и `Delta` снапшотов (проверка, что `safety_record_v1` отсутствует в байтах); (б) полный и инкрементальный `try_snapshot_sync` вперёд; (в) неудавшийся (отклонённый) `try_snapshot_sync`; (г) `prune_state_below` / `prune_domains_below` / `prune_deltas_below`; (д) состояние карантина `safety_failed = true`.
   - Ожидание: во всех сценариях `safety_record_v1` (`generation == 7`, `payload == P`, `identity`), `ConsensusCheckpoint`, `VoteWatermark` и флаг карантина `safety_failed` остаются абсолютно неизменными; при прыжке на высоту `<=` локально подписанного раунда узел не допускает повторного подписания.
7. **Обратная совместимость и F1/F5-инварианты (`legacy_full_compat_and_f1_f5`)** `[Агенты B, C]`:
   - Восстановление `load_full_state_into` из старых `StateSnapshotV2` + `DomainSnapshot` (`V1..V8`) и сетевой fallback на legacy-пира при отсутствии `SnapshotManifestV1`; проверка отказа при несовпадении `ValidatorSet` (F5) и при неполном покрытии `cross_shard` replay sets (F1), а также побайтовое совпадение `state_root` между полным `Base` и цепочкой `Base + Δ_1 + Δ_2 + Δ_3` (включая `pq_keys`, `staking`, `contracts`, `bridge`, `zkml`, `cnvrf_v3`).
