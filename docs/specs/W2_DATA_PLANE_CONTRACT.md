# W2 — Data Plane & Bounded Repair Contract (HDAE, code truth)

Статус: **архитектурный контракт интеграции W2** (снимает 3 блокера перед запуском эшелонов реализации).
Зафиксировано по состоянию дерева `stellereum` + `infnode` на 2026-11-21 (`FORK_ID = 0x0f584a46`, ruleset v6).

> **Инвариант безопасности (не-DA).** W2 Data Plane является **только** транспортом доставки и ограниченного восстановления байтов блока (`data_plane.rs:1-5`, `data_plane_repair.rs:1-5`). Ни `chunk_root`, ни `SDP1`-Merkle proof, ни паритетные шарды Reed-Solomon `(k, n)` **не являются доказательством доступности данных (Data Availability / DAS)**. Безопасность консенсуса по-прежнему требует полной сборки, проверки `compute_hash()` и всех BFT-проверок до `prevote` / `finalize` / `adopt`.

---

## 0. Исходная база и зафиксированные ограничения

- Изолированные примитивы уже реализованы (пока не экспортированы в `stellereum/src/lib.rs:1-125`, подключены только через `#[path = ...]` в `stellereum/tests/data_plane_tests.rs:3-4` и `stellereum/tests/data_plane_repair_tests.rs:2-5`):
  - `stellereum/src/data_plane.rs:20-28`: формат чанка `SDP1` (`VERSION = 1`, `HEADER = 25` B), лимиты `MAX_DATA_SIZE = 16 MiB` (`:21`), `MAX_CHUNK_SIZE = 1 MiB` (`:22`), `MAX_CHUNKS = 65_536` (`:23`), `MAX_PROOF_DEPTH = 16` (`:24`), домены BLAKE3 `stellereum/data-plane/v1/leaf\0` (`:27`) и `stellereum/data-plane/v1/node\0` (`:28`).
  - `stellereum/src/data_plane_repair.rs:18-92`: конечный автомат `Repair` с `Context { height, round }`, `SessionId([u8; 32])`, `Limits { max_chunks, max_bytes, max_retries, max_in_flight }`, токеном `Request`, учётом `max_bytes` даже на отклонённых ответах (`:241-251`) и терминальными отказами при смене контекста / дедлайне / регрессе часов (`:151-166`).
- **Несоответствие потолков размера блока (`16 MiB` vs `32 MiB`)**:
  - `MAX_CONSENSUS_MSG = 32 MiB` (`stellereum/src/consensus_net.rs:76`) и `MAX_WIRE_BLOCK_BYTES = 32 MiB` (`stellereum/src/network.rs:3212`), тогда как `data_plane::MAX_DATA_SIZE = 16 MiB` (`stellereum/src/data_plane.rs:21`).
  - **Правило контракта**: для W2 RS-разбиения потолок исходного канонического тела — `W2_MAX_OBJECT_BYTES = 16 MiB` (`data_plane::MAX_DATA_SIZE`, либо осознанное повышение `MAX_DATA_SIZE` до `32 MiB` в Эшелоне 1 с обновлением `data_plane_tests.rs`); любой блок в диапазоне `(MAX_DATA_SIZE ..= MAX_WIRE_BLOCK_BYTES]` **не** кодируется в W2 и идёт строго по fallback-пути (`Proposal` / `fetch_block`).
- **Транспортный лимит `infnode`**:
  - `MAX_PUBSUB_DATA_LEN = 1 MiB` (`infnode/crates/infnode/src/proto.rs:19`) проверяет длину **hex-строки** `data` на `pubsub.publish`/`pubsub.relay` (`infnode/crates/infnode/src/node.rs:3579,3633,6274`), т.е. потолок бинарного payload при прохождении через overlay — **512 KiB**.
  - Поэтому W2 ограничивает размер одного передаваемого чанка/шарда потолком `W2_WIRE_CHUNK_SIZE = 256 KiB` (`262_144` B, жёсткий предел для оверлея `<= 500 KiB` с запасом под `SDP1` 25 B + proof `<= 16 * 32 = 512 B` + bincode-обёртку).

---

## 1. Формат payload, привязка `chunk_root` и совместимость с `FORK_ID`

### 1.1 Почему `chunk_root` НЕ входит в `Block::compute_hash()`

- `Block::compute_hash()` (`stellereum/src/sharding/block.rs:930-932` → `compute_hash_committing_round` `:959-1107`) намеренно исключает `validator_signatures` (`:321`) и `precommit_qc` (`:330`), но включает все консенсусные поля заголовка и тела (`shard_id`, `height`, `round`, `prev_hash`, `state_root`, `transactions`, `order_merkle_root`, `cross_shard_out`, `shard_headers`, `epoch_key_commitment`, `last_qc`, `mmr_epoch_root`, `cnvrf_v3`, `timestamp`, `proposer`).
- Попытка включить `chunk_root` в `Block::compute_hash()` создаёт:
  1. **циклическую зависимость**, если чанкируется сериализованный `Block`, содержащий хеш блока или `chunk_root`;
  2. **хард-форк (`FORK_ID` / wire layout)**: изменение структуры `Block` и преимиджа `compute_hash` ломает замороженное ядро (`AGENTS.md` §7), `FORK_ID = 0x0f584a46` (`stellereum/src/protocol.rs:101,226-230`) и паритетные тесты SDK (`stellereum-sdk/src/protocol.rs:300`, `sdk-js/test/builders.test.ts:92`).

### 1.2 Канонический chunked payload (`W2CanonicalBlockBytes`)

Чтобы один и тот же `block_hash` давал **побайтово идентичный** объект для чанков и на стадии proposal, и после финализации (где у разных честных нод `precommit_qc` содержит разные кворумные подмножества `{A,C}` vs `{A,B,C}`, см. `stellereum/src/sharding/block.rs:410-418`), из чанкуемого объекта исключается только пост-фактум свидетельство финализации:

```text
canonical_block := Block { precommit_qc: None, ..proposed_or_finalized_block }
canonical_bytes := bincode::DefaultOptions::new()
                     .with_fixint_encoding()
                     .serialize(&canonical_block)
```

Свойства:
1. `canonical_block.validator_signatures` **сохраняется** (в live-потоке это ровно подпись пропозера, добавленная один раз в `propose()` / `restamp_for_round` — `stellereum/src/runtime/mev_sync.rs:907-915`, `stellereum/src/sharding/block.rs:1170-1182`). Ни финализация (`stellereum/src/runtime/apply.rs:674-675`), ни `adopt_committed` (`stellereum/src/runtime/consensus_step.rs:2819-2820`) её не мутируют.
2. `canonical_block.compute_hash() == block.compute_hash()` по построению (`sharding/block.rs:323-330`).
3. При декодировании после `Repair::body()` получатель **обязан** (fail-closed):
   - декодировать строго через `bincode::DefaultOptions::new().with_limit(MAX_WIRE_BLOCK_BYTES).with_fixint_encoding().reject_trailing_bytes()` (зеркалит `ConsensusMsg::decode` в `consensus_net.rs:685-689`),
   - проверить `canonical_block.precommit_qc.is_none()` (отвергать подмешанный `Some(qc)` внутри тела),
   - проверить `canonical_block.compute_hash() == expected_block_hash`,
   - проверить `crate::consensus::verify_proposer_signature(&canonical_block)` (`consensus/types.rs:297-333`; обязательно и в `on_proposal` `:1287`, и в `adopt_committed` `:2612`).

### 1.3 Привязка и аутентификация `chunk_root` (до скачивания чанков!)

`data_plane_repair.rs:3-4,95` требует независимой аутентификации `(root, parameters)` **до** вызова `Repair::new(...)`, иначе злоумышленник подменит `chunk_root` и сожжёт `max_bytes` / `max_retries`.

#### (а) Proposal path (и совместимость с `CompactProposal` / `COMPACT_GOSSIP`)

- Когда используется W2 Proposal:
  - Основной быстрый путь для транзакций из мемпула остаётся `CompactProposal` (`stellereum/src/compact_prop.rs:607-624`, `COMPACT_GOSSIP_BIT = 1 << 0` в `infnode/crates/infnode/src/proto.rs:255`).
  - W2 Proposal (`ConsensusMsg::DataPlaneProposal`, новый вариант, **дописанный в конец** `ConsensusMsg` после `Body` — `consensus_net.rs:318-343`) используется, когда:
    1. блок не сжимается в `CompactProposal` (превышен `COMPACT_MAX_FULL_SLOTS = 1_024` в `compact_prop.rs:312`, крупные SVM/мемпул-отсутствующие tx, крупные `cross_shard_out`), **или**
    2. `CompactReceiver` исчерпал попытки / порог пропусков (`CompactInbound::FetchFull` в `consensus_net.rs:3053-3058` / `consensus_driver.rs:1629-1674`) и запрашивает тело у пропозера с поддержкой W2.
- Формат объявления `DataPlaneProposal`:
  ```rust
  pub struct DataPlaneHeaderMeta {
      pub shard_id: u32,
      pub height: u64,
      pub round: u32,
      pub prev_hash: [u8; 32],
      pub proposer: [u8; 32],
      pub block_hash: [u8; 32],
      pub orig_len: u64,       // точная длина canonical_bytes до RS-паддинга
      pub k: u16,              // число data-шардов (1 <= k < n <= 256)
      pub n: u16,              // общее число шардов (k + parity)
      pub shard_len: u32,      // длина каждого RS-шарда (= chunk_size в data_plane)
      pub chunk_root: [u8; 32],// Merkle root над всеми n (data + parity) шардами
  }
  pub struct DataPlaneProposal {
      pub meta: DataPlaneHeaderMeta,
      /// Подпись Falcon-512 пропозера (ключа из pq_key_at_height(proposer, height))
      /// над domain-separated дайджестом meta.
      pub proposer_chunk_sig: Vec<u8>,
  }
  ```
- **Доменная подпись пропозера (`proposer_chunk_sig`)**:
  - Преимидж (фиксированной ширины, LE, привязан к `consensus_chain_id()`):
    ```text
    BLAKE3(
      "STELL_W2_PROP_ROOT_V1\0"
      || chain_id.to_le_bytes()     // 8 B, crate::consensus::consensus_chain_id()
      || shard_id.to_le_bytes()     // 4 B
      || height.to_le_bytes()       // 8 B
      || round.to_le_bytes()        // 4 B
      || prev_hash                  // 32 B
      || proposer                   // 32 B
      || block_hash                 // 32 B
      || orig_len.to_le_bytes()     // 8 B
      || k.to_le_bytes()            // 2 B
      || n.to_le_bytes()            // 2 B
      || shard_len.to_le_bytes()    // 4 B
      || chunk_root                 // 32 B
    )
    ```
  - Подписывается Falcon-512 ключом пропозера (`ValidatorRuntime::falcon_signing_key()`), проверяется **до** создания `Repair` через `pq_key_at_height(&meta.proposer, meta.height)` + `verify_pq_signature` (`consensus/types.rs:303-331`) + `validators.power_of(&meta.proposer) != 0` + `compact_proposal_height_is_relevant` + `compact_parent_is_plausible` (`node/policy.rs:302-320`).
  - Невалидная подпись, чужой `proposer`, `k == 0`, `n <= k`, `n > 256`, `orig_len > W2_MAX_OBJECT_BYTES` или `shard_len != ceil_div(orig_len, k)` отвергаются **до** выделения памяти под слоты `Repair`.
  - Вторичная проверка после `Repair::body()` + RS-реконструкции: `canonical_block.compute_hash() == meta.block_hash` и `verify_proposer_signature(&canonical_block)`. После этого `canonical_block` передаётся в `encode_full_proposal_loopback` (`consensus_driver.rs:26-43`) — единый путь в `on_proposal`.

#### (b) Finalized Block path (`precommit_qc`, catch-up, DHT/unicast)

- **Первичный якорь доверия**: верифицированный `precommit_qc` (`certificate.kind == VoteKind::Precommit`, `certificate.height == height`, `certificate.block_hash == Some(block_hash)`, проверенный через `certificate.verify_with_schedule(&validator_set_for_height(height), committee_schedule_at(height))` в `consensus/types.rs:1795` / `consensus_driver.rs:3493-3500` / `node/sync.rs:241-267`).
- Поскольку `precommit_qc` не может содержать `chunk_root` без изменения `vote_sign_bytes` / `FORK_ID`, привязка `chunk_root` для финализированного блока работает в двух совместимых режимах:
  1. **Unicast / `Committed` / compact-µQC catch-up manifest (`DataPlaneFinalizedRef`)**:
     - Вместе с `QuorumCertificate` (например, из `parse_compact_qc_incoming` в `consensus_net.rs:2720-2729` или отдельного manifest-ответа в catch-up) пир передаёт `(DataPlaneHeaderMeta { round: qc.round, .. }, attester_id: [u8; 32], attester_sig: Vec<u8>)`, где `attester_sig` — Falcon-512 подпись валидатора из `validator_set_for_height(height)` (`power_of(&attester_id) > 0`, `pq_key_at_height(&attester_id, height)`) над доменом `STELL_W2_FINAL_ROOT_V1\0` с теми же полями `(chain_id, shard_id, height, block_hash, orig_len, k, n, shard_len, chunk_root)`.
     - Приёмник сначала проверяет `precommit_qc`, затем проверяет `attester_sig` (или оригинальную `proposer_chunk_sig`, если она сохранена и приложена) **до** запуска `Repair::new(...)`.
  2. **DHT sidecar / chunked blob (`network.rs`)**:
     - Дополнительно к существующим `header_name`, `header_index_name`, `header_qc_name` (`stellereum/src/network.rs:60-74`) может публиковаться побочный манифест `w2_manifest_name(epoch, shard_id, height)` с тем же `DataPlaneFinalizedRef` (подписью публикатора-валидатора + привязкой к `block_hash`, уже подтверждённому через `fetch_block_qc` + `fetch_block_header`).
     - После `Repair::body()` + RS-реконструкции получатель **всегда** проверяет `rebuilt.compute_hash() == block_hash` и `verify_proposer_signature(&rebuilt)`, а затем прикрепляет проверенный `rebuilt.precommit_qc = Some(qc)` перед передачей в `adopt_committed` (`consensus_step.rs:2416`) или `walk_chain` (`node/sync.rs:1185-1202`). Тем самым даже скомпрометированный одиночный `attester_id` не может подменить блок: максимум — заставить приёмник отвергнуть тело на `compute_hash()` и уйти в fallback `adapter.fetch_block(&block_hash)`.

### 1.4 `FORK_ID` / ruleset vs capability-negotiated транспорт

- **Изменения `FORK_ID` и `CONSENSUS_RULESET_VERSION` НЕТ.**
  - `CONSENSUS_RULESET_VERSION = 6`, `DOMAIN_SET_VERSION = 3`, `FORK_ID = 0x0f584a46` (`stellereum/src/protocol.rs:100-106,226-230`) остаются **неизменными**. Правила валидации блока, кворумы, хеш блока `Block::compute_hash()`, vote preimage и тайм-ауты не меняются.
- **Механизм ввода — capability-negotiated транспорт** (по модели `COMPACT_GOSSIP` и `MESH_DIRECT` в `stellereum/src/protocol.rs:233,281-345` и `infnode/crates/infnode/src/proto.rs:247-287,510-536`):
  - Добавляем бит способности `DATA_PLANE_REPAIR_BIT = 1 << 2` (`Capabilities::from_bits(1 << 2)`).
  - В `stellereum/src/protocol.rs`:
    - `pub const DATA_PLANE_REPAIR: Capabilities = Capabilities::from_bits(1 << 2);`
    - `pub const CAPABILITIES: Capabilities = Capabilities::ALL.union(DATA_PLANE_REPAIR);`
    - `pub const fn peer_supports_data_plane(caps: Capabilities) -> bool { caps.contains(DATA_PLANE_REPAIR) }`
    - `unnegotiated_capabilities()` (`protocol.rs:298-300`) остаётся `Capabilities::ALL` (**без** `DATA_PLANE_REPAIR`!), чтобы легаси-ноды, не приславшие `Hello`, никогда не получали W2-фреймы (fail-closed для нового транспорта, полная обратная совместимость).
  - `PROTOCOL_MINOR` может остаться `0` (или `1` в пределах `minor_distance <= 1`, `infnode/proto.rs:526-536`): `negotiate` берёт `local.capabilities.intersection(peer.capabilities)`.
  - Dual-emit на стороне отправителя (`consensus_net.rs:1865-1918`): пирам без бита `DATA_PLANE_REPAIR` в согласованной сессии по-прежнему уходит `CompactProposal` (если есть `COMPACT_GOSSIP`) или полный `ConsensusMsg::Proposal` / `Committed`.

---

## 2. Интеграционная архитектура (`network.rs` + `consensus_net.rs` + `consensus_driver.rs`)

### 2.1 Выделенный неблокирующий `RepairLane` и изоляция топика

Консенсусный тик в `stellereum/src/node/consensus_driver.rs:1555+` не должен ждать ни I/O чанков, ни RS-реконструкции, ни делить свой входящий `rx`-канал с потоком чанков (иначе трафик чанков съест `MAX_INBOUND_PER_TICK` / `INNER_BUDGET_PER_TICK` в `consensus_driver.rs:2664,2669`).

1. **Отдельный app-sub топик данных** (без изменений в `infnode`):
   - `data_plane_topic(epoch)` / `data_plane_topic_for_shard(epoch, shard_id)`:
     `stellereum/data-plane/v1/{epoch}` и `stellereum/data-plane/v1/{epoch}/shard/{shard_id}` (по образцу `consensus_topic_for_shard` в `consensus_net.rs:66-68`, длина < `MAX_TOPIC_LEN = 256` в `infnode/proto.rs:22`).
   - Транспорт: только адресная доставка `adapter.deliver_consensus_to_peer(peer, &dp_topic, &hex_payload)` (`network.rs:1363-1382` → `deliver_unicast` `:1222-1240` через `ValidatorMesh` или `node.send_to(..., "pubsub.msg", ...)`). **Никакого all-peer broadcast для `ChunkReq`/`ChunkResp`!**
   - Примечание: `deliver_unicast` и `pubsub.msg` уже поддерживают любые валидные `topic` (проверка `topic_ok` в `infnode/node.rs:3571`) и имеют приоритетное планирование в `infnode/node.rs:2886-2888`.
2. **Асинхронная задача `RepairLane` (по образцу `ApplyLane` / `VdfLane` в `runtime/lanes.rs:265-368,542-629` и `publish_lane` в `consensus_driver.rs:1501`)**:
   - `RepairLane` владеет:
     - приёмником `dp_rx: mpsc::UnboundedReceiver<String>` (подписка `register_app_sub(&dp_topic)`),
     - таблицей активных сессий `HashMap<SessionId, ActiveRepair>`,
     - локальным сервером шардов `DataPlaneServer` (bounded cache),
     - семафором/счётчиками агрегированных лимитов,
     - очередями исходящих `RepairCmd` (`bounded mpsc`, `try_send` с консенсусного тика) и завершённых результатов `RepairEvent` (`bounded mpsc`, `try_recv` в начале тика).
   - **Обработка в консенсусном тике (`consensus_driver.rs`)**:
     - Вверху тика: `while let Ok(ev) = repair_events_rx.try_recv()` — неблокирующий дренаж:
       - `RepairEvent::ProposalReady { round, block, src }` → `encode_full_proposal_loopback(&block, round, &src)` (`consensus_driver.rs:26-43`) в `loopback_queue` (`LOOPBACK_QUEUE_CAP = 64`, `node/policy.rs:109`). Единый путь в `on_proposal`, второго консенсус-пути нет.
       - `RepairEvent::FinalizedReady { height, block_hash, block, certificate }` → прямая передача в `adopt_committed` (если `height == rt.hc.height`) или кэш `repaired_finalized` для `walk_chain`.
       - `RepairEvent::FallbackFull { context, block_hash, is_proposal, reason }` → для proposal: отправка `BodyPull::full_request(context.height, round, block_hash)` (`compact_prop.rs:499`); для finalized: пометка на загрузку через `adapter.fetch_block(&block_hash)` (`network.rs:1432`).
     - При продвижении `rt.hc.height` или смене `rt.hc.round` (для активных proposal-сессий), а также при `adopt_committed` / `try_finalize_submit`: тик отправляет `repair_cmd_tx.try_send(RepairCmd::RetireContext(Context { height, round }))`.
     - Внутри `RepairLane`: `Repair::cancel()` немедленно вызывает `abort()` на всех `JoinHandle` / таймерах I/O этой сессии (исполняет контракт `data_plane_repair.rs:4-5`: *"cancel underlying I/O when requests are retired"*).
   - **Монотонность `Instant` в `RepairLane`**:
     - `RepairLane` ведёт собственный `last_clock: Instant` и на каждом шаге вычисляет `now = std::time::Instant::now().max(self.last_clock); self.last_clock = now;`, исключая ложный `Error::ClockRegression` (`data_plane_repair.rs:158-160`).

### 2.2 Гарантия уникальности `SessionId` и корреляция приватного `Request`

1. **Уникальность `SessionId([u8; 32])` между рестартами (`data_plane_repair.rs:6-11,25-26`)**:
   - На старте процесса (`consensus_driver::run_consensus_node`):
     - `boot_nonce: [u8; 32]` генерируется через `OsRng.fill_bytes(...)` (криптографически случайные 256 бит на каждый запуск процесса, защита от клонирования/вайпа диска или `persistence == None`).
     - Если доступна `persistence` (`sled`), читается и атомарно инкрементируется+флашится монотонный счётчик `w2_boot_epoch: u64` в `meta`-дереве (`boot_epoch = prev + 1`).
   - Внутри `RepairLane` ведётся строго монотонный `session_seq: u64` (при переполнении `checked_add(1)` → fail-closed отказ новой сессии).
   - Формула:
     ```text
     SessionId = BLAKE3(
       "STELL_W2_SESSION_V1\0"
       || boot_nonce           // 32 B CSPRNG
       || boot_epoch.to_le()   // 8 B persisted monotonic (0 if in-memory)
       || shard_id.to_le()     // 4 B
       || height.to_le()       // 8 B
       || round.to_le()        // 4 B
       || session_seq.to_le()  // 8 B
     )
     ```
   - За счёт `boot_nonce` + `boot_epoch` + `session_seq` ни два рестарта, ни две сессии в рамках одного запуска не могут породить одинаковый `SessionId`.
2. **Корреляция приватных полей `data_plane_repair::Request`**:
   - В текущем `stellereum/src/data_plane_repair.rs:39-43` поля `Request::session` и `Request::id` приватны (`pub index: u32`), и `Request` не реализует `Serialize`.
   - **Решение без нарушения инварианта «не перемаркировывать ответ новым токеном» (`data_plane_repair.rs:8-10`)**:
     - Внутри `ActiveRepair` хранится таблица `in_flight_tokens: HashMap<u64, data_plane_repair::Request>`, индексируемая локальным монотонным `wire_req_id: u64`.
     - В сеть в `ChunkReq` уходит пара `(session_id: [u8; 32], wire_req_id: u64, index: u32, block_hash: [u8; 32])`; ответ `ChunkResp` возвращает `(session_id, wire_req_id, index, encoded_chunk, proof)`.
     - При приёме ответа `RepairLane` ищет `session_id` → достаёт **оригинальный** `req = active.in_flight_tokens.remove(&wire_req_id)` (при несовпадении `req.index != resp.index` отклоняет до вызова или через `accept`), и передаёт именно этот исходный `req` в `repair.accept(ctx, now, req, chunk, &proof)`. При тайм-ауте запроса `RepairLane` вызывает `repair.fail(ctx, now, req)` с тем же исходным `req` и удаляет `wire_req_id`.
     - Это работает либо при нулевых правках `data_plane_repair.rs`, либо с добавлением read-only геттеров `Request::session(&self)` / `Request::id(&self)`.

### 2.3 Агрегированные лимиты, framing до аллокации и защита от DoS

| Ресурс | Порог (константа W2) | Механизм принуждения | Аналог в текущем коде |
|---|---|---|---|
| Активные repair-сессии на узел/шард | `W2_MAX_ACTIVE_SESSIONS = 4` | Evict самой старой некритичной (или отказ новой при live proposal) | `COMPACT_MAX_PARKED = 4` (`consensus_net.rs:3023`) |
| Суммарный бюджет памяти всех сессий | `W2_MAX_TOTAL_BYTES = 64 MiB` | Учёт `max_bytes` резерва каждой сессии + накопленных payload; превышение → отказ/эвикция + fallback | `COMPACT_PARKED_BYTES = 64 MiB` (`consensus_net.rs:3028`) |
| Суммарный in-flight по всем сессиям | `W2_MAX_TOTAL_IN_FLIGHT = 16` | Глобальный счётчик + per-session `max_in_flight = 8` | `FETCH_MAX_CONCURRENCY = 8` (`network.rs:1170`), ниже лимита 256 потоков (`network.rs:1157`) |
| Лимит одной сессии (`Limits`) | `max_chunks = n <= 256`, `max_bytes = 2 * orig_len + n * 1024` (потолок `32 MiB`), `max_retries = 2`, `max_in_flight = 8` | Передаётся в `Repair::new`; `accept` списывает и отклонённые ответы (`data_plane_repair.rs:241-251`) | `data_plane_repair::Limits` (`:29-36`) |
| Дедлайн сессии | Proposal: `round_timeout / 2` (1.5 s при `FROZEN_ROUND_TIMEOUT_BASE_MS = 3_000`); Finalized: `5_000 ms` | `Repair::check` + `tokio::time::timeout` на каждый I/O | `FROZEN_ROUND_TIMEOUT_BASE_MS` (`consensus_driver.rs:1312`) |
| Framing ответа ДО аллокации | `raw_json <= 1 MiB` (`MAX_PUBSUB_DATA_LEN`), `chunk_payload <= 256 KiB` (`<= MAX_CHUNK_SIZE`), `proof.len() <= 8` (для `n <= 256`, жёстко `<= MAX_PROOF_DEPTH = 16`) | Проверка длин на срезе `&[u8]` и `bincode::DefaultOptions::with_limit(...)` до `.to_vec()` | `data_plane::decode_chunk` без аллокаций (`:128-166`), `data_plane_repair.rs:230-231` |
| Inbound per-peer rate limit | `InboundBulkLimiter` + `InboundShed` (`INBOUND_SHED_BYTES_PER_SEC`) | `dp_rx` применяет `net.admit_inbound(&peer_key, ...)` для `ChunkReq`/`ChunkResp` | `consensus_net.rs:6954,7332` |
| Серверный кэш (`DataPlaneServer`) | `W2_SERVED_BLOCKS = 4`, `W2_SERVED_BYTES = 64 MiB`, `W2_CHUNK_RATE_PER_PEER_SEC = 64` | LRU/FIFO кэш недавних блоков; per-requester дедуп/кулдаун на `(requester, block_hash, index)` | `CompactBodyServer` (`consensus_net.rs:3327-3520`) |

### 2.4 Fallback на полное тело

- **Proposal**:
  - Пир не имеет `DATA_PLANE_REPAIR` → dual-emit `CompactProposal` / `Proposal`.
  - Сессия W2 вернула `Deadline` / `ByteLimit` / `RetryLimit` / `Error` / невалидный `Block::compute_hash()` → `RepairEvent::FallbackFull` отправляет `BodyPull::full_request(height, round, block_hash)` пропозеру (или ожидает полного `Proposal` / `Committed`).
  - Блок > `W2_MAX_OBJECT_BYTES` (`16 MiB`) → сразу отправляется через `Proposal` (до `MAX_CONSENSUS_MSG = 32 MiB`).
- **Finalized Block**:
  - Отсутствует `DataPlaneFinalizedRef`, провал `Repair`, таймаут или недоступно `k` уникальных шардов → `adapter.fetch_block(&block_hash)` (`network.rs:1432-1444`, существующий DHT blob `BUCKET_STELLEREUM_BLOCKS`).

---

## 3. RS-erasure без уязвимого `lru 0.7.8` (`RUSTSEC-2026-0253`)

### 3.1 Результаты проверки локального `Cargo.lock` и cargo cache

Проверено чтением (без запуска `cargo`/`rustc`):
1. В `/home/imm/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/reed-solomon-erasure-6.0.0/Cargo.toml:44-45,69-75`:
   - Зависимость `lru = "0.7.8"` объявлена **безусловно** (`[dependencies.lru] version = "0.7.8"`, `optional` отсутствует).
   - Доступные features: только `default = ["std"]`, `simd-accel = ["cc", "libc"]`, `std = ["parking_lot"]`.
   - **Вывод**: отключить `lru` через `default-features = false` или комбинацию features **невозможно** (и `infnode/crates/infnode/Cargo.toml:33`, и `infnode/tools/ec-mail-recovery/Cargo.toml:16` уже используют `default-features = false`, но всё равно компилируют `lru 0.7.8`).
2. В `reed-solomon-erasure-6.0.0/src/core.rs:14,24,349,465,703-706,727-728`:
   - `LruCache<Vec<usize>, Arc<Matrix<F>>>` используется **только** для кеширования инвертированной decode-матрицы (`DATA_DECODE_MATRIX_CACHE_CAPACITY = 254`) в методе `get_data_decode_matrix`.
3. В `stellereum/Cargo.lock:1426-1432,2019-2028` и `infnode/Cargo.lock:1449-1455,2092-2101`:
   - `stellereum` сам не использует `reed-solomon-erasure`, но тянет его транзитивно через `infnode = { path = "../infnode/crates/infnode" }` (`stellereum/Cargo.toml:7`).
   - В `infnode` крейт вызывается в `infnode/crates/infnode/src/node.rs:18,6493,6526,11082` и `infnode/tools/ec-mail-recovery/src/main.rs:6,272,376`.
   - Уязвимость `RUSTSEC-2026-0253` (`lru 0.7.8` UAF/double-free при панике в `Drop` внутри `pop()`) уже зафиксирована в `stellereum/LAUNCH_STRATEGY.txt:518-541`.

### 3.2 Решение для W2 в `stellereum`: собственный pure-Rust GF(256) RS(k, n) codec

Вместо подключения `reed-solomon-erasure 6.0.0` (и вместо патча/вендоринга `lru 0.7.8`) реализуем собственный компактный pure-Rust модуль `stellereum/src/data_plane_rs.rs` (~250–350 строк, **0 внешних зависимостей, 0 `unsafe`, 0 `lru`, 0 `Mutex`**):

1. **Математика GF(2^8), совместимая с `infnode` / `reed-solomon-erasure`**:
   - Примитивный полином: `GENERATING_POLYNOMIAL = 0x1D` ($x^8 + x^4 + x^3 + x^2 + 1$, точно как в `reed-solomon-erasure-6.0.0/build.rs:11`).
   - Таблицы `LOG_TABLE: [u8; 256]`, `EXP_TABLE: [u8; 510]`, и nibble-таблицы `MUL_LOW: [[u8; 16]; 256]`, `MUL_HIGH: [[u8; 16]; 256]` (всего 8.75 KiB в `.rodata`, вычисляются `const fn` на этапе компиляции — никакого `build.rs`!).
   - Систематическая кодирующая матрица: верхние `k` строк — единичная матрица $I_k$, нижние `m = n - k` строк — из Vandermonde-матрицы `V(n, k) * V(0..k, 0..k)^{-1}` в $GF(2^8)$ (либо Cauchy-матрица — но Vandermonde с полиномом `0x1D` даёт **100% побайтовое совпадение** с `reed-solomon-erasure::galois_8`, что позволяет переиспользовать ту же реализацию при очистке `infnode` и пройти тест паритета с `ec_reads_legacy_writer_fixture_without_network` в `infnode/node.rs:11068`).
2. **Без кеша decode-матриц (или без `LruCache`)**:
   - На этапе `reconstruct_data` строится подматрица $k \times k$ из первых `k` присутствующих строк (если отсутствуют только parity-шарды, инверсия вообще не нужна — все `k` data-шардов уже на месте, $O(1)$!).
   - Если утерян хотя бы один из `k` data-шардов, выполняется инверсия $k \times k$ методом Гаусса-Жордана в $GF(2^8)$ напрямую по месту в плоском буфере `Vec<u8>` (для `k <= 64` это $\le 4\text{ KiB}$ и микросекунды, для `k = 255` — $65\text{ KiB}$).
   - Никакого `LruCache`, никакого `Mutex`, никакой паники внутри `Drop` (элементы матрицы — `u8`).
3. **Точные пределы `k`, `n` и геометрии шарда**:
   - `GF(2^8)` содержит 256 элементов (`ORDER = 256`), поэтому **жёсткие пределы кодека**:
     - `1 <= k < n <= 256` (т.е. `k <= 255`, `parity = n - k >= 1`, `n <= 256`; режим без избыточности `k == n` тривиально обходит RS).
     - `orig_len <= W2_MAX_OBJECT_BYTES` (`16 MiB`, совпадает с `data_plane::MAX_DATA_SIZE`).
     - `shard_len = if orig_len == 0 { 1 } else { orig_len.div_ceil(k) }` (дополняется нулями до `k * shard_len`), где `1 <= shard_len <= W2_WIRE_CHUNK_SIZE` (`256 KiB` для сетевого переноса; жёсткий предел `data_plane::MAX_CHUNK_SIZE = 1 MiB`).
     - Выбор `(k, n)` по умолчанию для блока размером `L` байт:
       - `k = (L.max(1)).div_ceil(W2_WIRE_CHUNK_SIZE).clamp(4, 128)` (при `L = 16 MiB` и `256 KiB` шарде: `k = 64`),
       - `m = k.div_ceil(2).max(2)` (избыточность 1.5x; напр. `(k=64, n=96)` выдерживает потерю любых 32 шардов, глубина Merkle-дерева $\lceil \log_2 96 \rceil = 7 \le 16$), при условии `k + m <= 256` (иначе `m = 256 - k`).
     - Защита от OOM на приёмнике: размер буфера `n * shard_len` проверяется **до** аллокации (`checked_mul`, потолок `<= 2 * W2_MAX_OBJECT_BYTES = 32 MiB`).

### 3.3 Commitment-связка: Merkle root над data + parity шардами

1. При кодировании `canonical_bytes` (длины `orig_len`):
   - Строятся все `n = k + m` шардов `shards[0..n]` равной длины `shard_len`:
     - `0..k`: данные из `canonical_bytes`, последний блок дополнен нулями до `shard_len`.
     - `k..n`: parity-шарды, вычисленные матрицей `data_plane_rs`.
2. **Общий Merkle-параметр для `data_plane.rs`**:
   - `dp_params = data_plane::Parameters { total_len: (n as u64) * (shard_len as u64), chunk_size: shard_len as u32 }`.
   - `dp_params.chunk_count()` ровно равно `n` (`<= 256 <= MAX_CHUNKS = 65_536`), и `dp_params.payload_len(i) == shard_len` для каждого `i in 0..n`!
   - `chunk_root` и Merkle-доказательства `proof[i]` строятся `data_plane::make_proof(&concatenated_n_shards, shard_len, i)` (или эквивалентно над `shards[0..n]` тем же `leaf_hash` / `node_hash` доменом `stellereum/data-plane/v1/leaf\0` и `.../node\0`).
3. **Почему Merkle-дерево обязано покрывать И data, И parity шарды**:
   - Каждый полученный шард `i in 0..n` (включая parity `i >= k`) верифицируется через `data_plane::verify_chunk` **до** передачи в RS-декодер. Подделанный parity-шард немедленно отвергается с `Error::InvalidChunk`, списывается в `max_bytes` и никогда не участвует в гауссовой реконструкции.
4. **Аутентификация `orig_len` и геометрии `(k, n, shard_len)`**:
   - Все четыре параметра `(orig_len, k, n, shard_len)` вместе с `chunk_root` и `block_hash` подписаны в `proposer_chunk_sig` / `attester_sig`.
   - После получения любых `k` верифицированных шардов `Repair` (адаптер над `Repair` принимает любой из `0..n` индексов и останавливается, как только заполнено `k` уникальных слотов), `rs_reconstruct_data` восстанавливает `shards[0..k]`, склеивает и обрезает до `orig_len`, после чего строгое bincode-декодирование + `compute_hash() == block_hash` проверяют целостность целиком.
   - *Примечание по `Repair::body()` (`data_plane_repair.rs:285-299`)*: текущий `Repair::body()` требует заполнения **всех** `slots` (0..n). При RS-режиме `(k < n)` W2 обёртка либо:
     (а) запрашивает `k` индексов `0..k` с фоновым добором parity `k..n` при отказах/таймаутах и читает присутствующие слоты (или добавляет к `Repair` метод `into_present_slots` / `completed_count()` в Эшелоне 1), либо
     (б) после реконструкции всех `n` шардов заполняет оставшиеся слоты для `body()` (излишне — лучше минимальное расширение `Repair::completed_count(&self) -> u32` / `take_slots` в Эшелоне 1 с сохранением всех проверок `check(context, now)`!).

### 3.4 План полного удаления `lru 0.7.8` из `infnode` и `stellereum`

1. **Шаг 1 (W2 в `stellereum`)**: `stellereum/src/data_plane_rs.rs` реализует чистый GF(256) Vandermonde RS `(k, n)` без `reed-solomon-erasure` и без `lru`. `stellereum` не добавляет зависимость от `reed-solomon-erasure` в `stellereum/Cargo.toml`.
2. **Шаг 2 (отдельный PR в `infnode`, соблюдение изоляции крейтов `AGENTS.md` §2)**:
   - Добавить идентичный pure-Rust GF(256) Vandermonde модуль `infnode/crates/infnode/src/erasure.rs` (полином `0x1D`, без `lru` и без `Mutex`).
   - Переключить `infnode/crates/infnode/src/node.rs:18,6493,6526,11082` и `infnode/tools/ec-mail-recovery/src/main.rs:6,272,376` с `reed_solomon_erasure::galois_8::ReedSolomon` на `infnode::erasure::ReedSolomon8`.
   - Зафиксировать дифференциальным тестом побайтовый паритет новых parity-шардов со старой фикстурой `ec_reads_legacy_writer_fixture_without_network` (`infnode/crates/infnode/src/node.rs:11068-11109`).
   - Удалить `reed-solomon-erasure` из `infnode/crates/infnode/Cargo.toml:33` и `infnode/tools/ec-mail-recovery/Cargo.toml:16` → обновить `infnode/Cargo.lock` и `stellereum/Cargo.lock` (проверить, что `lru 0.7.8` полностью исчез из обоих lock-файлов и `cargo audit` чист по `RUSTSEC-2026-0253`).

---

## 4. Матрица владения файлами, порядок эшелонов W2 и интеграционные тесты

### 4.1 Непересекающаяся матрица владения файлами (по `AGENTS.md` §2, §8)

Каждый эшелон выполняется изолированно (отдельный worktree / непересекающийся набор файлов), без конфликтов слияния:

| Эшелон | Ответственность | Разрешённые файлы (строго не пересекаются) | Запрещено трогать |
|---|---|---|---|
| **E1: RS Codec & Repair Primitives** | Pure-Rust GF(256) RS(k, n), RS+Merkle обвязка, read-only экспорт модулей и минимальный slot-accessor в `Repair` для `k-of-n` | `stellereum/src/data_plane_rs.rs` (new), `stellereum/src/data_plane.rs` (не менять без нужды), `stellereum/src/data_plane_repair.rs` (только `Request` getters / `take_completed_slots`), `stellereum/src/lib.rs` (экспорт `pub mod data_plane*`), `stellereum/tests/data_plane_rs_tests.rs` (new) | `protocol.rs`, `consensus_net.rs`, `network.rs`, `node/**`, `infnode/**`, `sharding/**` |
| **E2: Capability & Wire Codec** | Capability bit `DATA_PLANE_REPAIR`, новые варианты `ConsensusMsg` (строго в конец enum), `DataPlaneProposal`, `DataPlaneFinalizedRef`, `ChunkReq`, `ChunkResp`, Falcon-подписи и строгий bincode-декод | `stellereum/src/protocol.rs`, `stellereum/src/consensus_net.rs` (только wire-типы, топики, `DataPlaneServer`, capability-split, без `node/**`), `stellereum/tests/data_plane_wire_tests.rs` (new) | `data_plane*.rs`, `network.rs`, `node/**`, `runtime/**`, `sharding/block.rs` |
| **E3: Network Unicast & Repair Lane** | Unicast-маршрутизация на `dp_topic`, `SessionId` генератор (CSPRNG + persisted `boot_epoch` в `storage.rs`), неблокирующий `RepairLane` с глобальными лимитами, отменой I/O и fallback | `stellereum/src/network.rs` (helpers `w2_manifest` / `deliver_data_plane_to_peer`), `stellereum/src/storage.rs` (только `w2_boot_epoch` в `meta`), `stellereum/src/node/data_plane_lane.rs` (new), `stellereum/src/node/mod.rs`, `stellereum/tests/data_plane_lane_tests.rs` (new) | `consensus_net.rs` wire-типы, `node/consensus_driver.rs`, `node/sync.rs`, `runtime/**` |
| **E4: Driver & Catch-Up Wiring** | Подключение `RepairLane` в `consensus_driver.rs` (`propose` → `DataPlaneProposal` при необходимости, tick-top drain в `loopback_queue`, `RetireContext` при смене `height`/`round`, catch-up fallback в `node/sync.rs`, политики в `node/policy.rs`) | `stellereum/src/node/consensus_driver.rs`, `stellereum/src/node/sync.rs`, `stellereum/src/node/policy.rs`, `stellereum/tests/data_plane_e2e_tests.rs` (new) | `data_plane*.rs`, `protocol.rs`, `consensus_net.rs`, `network.rs`, `infnode/**` |
| **E5 (отдельный PR): `infnode` LRU Removal** | Удаление `reed-solomon-erasure 6.0.0` и `lru 0.7.8` (`RUSTSEC-2026-0253`) из `infnode` и перегенерация lock-файлов | `infnode/crates/infnode/src/erasure.rs` (new), `infnode/crates/infnode/src/lib.rs`, `infnode/crates/infnode/src/node.rs`, `infnode/crates/infnode/Cargo.toml`, `infnode/tools/ec-mail-recovery/src/main.rs`, `infnode/tools/ec-mail-recovery/Cargo.toml`, `infnode/Cargo.lock`, `stellereum/Cargo.lock` | Весь `stellereum/src/**` |

### 4.2 Порядок эшелонов W2 и критерии перехода

1. **E1** → Гейт: `cargo clippy --all-targets -- -D warnings` (0/0), `data_plane_tests`, `data_plane_repair_tests`, `data_plane_rs_tests` (включая KAT с `0x1D` Vandermonde и property/erasure-тесты `k-of-n` до `n = 256`).
2. **E2** (зависит от E1) → Гейт: `protocol_negotiation_tests`, `protocol_mixed_cluster_tests`, `compact_gossip_tests`, `data_plane_wire_tests` (проверка неизменности `FORK_ID = 0x0f584a46` и тегов `ConsensusMsg` 0..=6!).
3. **E3** (зависит от E1, E2) → Гейт: `data_plane_lane_tests` (неблокирующее выполнение, уникальность `SessionId` после рестарта, отмена I/O, агрегированные лимиты памяти/сессий).
4. **E4** (зависит от E3) → Гейт: `data_plane_e2e_tests`, `consensus_liveness_harness` (`AGENTS.md` §4), `./scripts/verify_testnet_ideal.sh`.
5. **E5** (независимый параллельный PR в `infnode`, обязателен перед релизным `cargo audit` закрытием `RUSTSEC-2026-0253`).

### 4.3 Обязательный список интеграционных тестов W2

1. **Crypto/Codec & Parity (E1 + E2)**:
   - `rs_erasure_reconstructs_from_any_k_of_n_shards`: случайные и граничные `(k, n)` (вкл. `(1, 2)`, `(4, 6)`, `(64, 96)`, `(200, 256)`, пустой объект `0 B`, `1 B`, невыровненный размер), реконструкция из чисто паритетных + смешанных шардов; отказ при `k - 1` шардах, `n > 256`, `k == 0`, `k >= n`.
   - `merkle_root_covers_parity_and_rejects_tampered_parity_before_rs`: порча 1 байта parity-шарда (`index >= k`) отклоняется на `verify_chunk` до вызова `rs_reconstruct_data` и не портит восстановление из оставшихся `k` валидных шардов.
   - `fork_id_and_legacy_consensus_msg_tags_unchanged`: `FORK_ID == 0x0f584a46`, теги `Proposal..Body` (0..=6) побайтово неизменны; пир без `DATA_PLANE_REPAIR` не получает W2-фреймов (`unnegotiated_capabilities()` не содержит `DATA_PLANE_REPAIR`).
   - `proposal_and_finalized_chunk_root_auth_fail_closed`: подмена `chunk_root`, `orig_len`, `k`/`n`, `round`, `chain_id`, или чужая/отсутствующая Falcon-подпись отвергаются **до** создания `Repair`.
2. **Repair Lane, Session & Resource Bounds (E3)**:
   - `session_id_unique_across_restarts_and_late_reply_rejected`: рестарт с тем же `sled` каталогом (и без него) генерирует новый `SessionId`; запоздалый `ChunkResp` от до-рестартной сессии отбрасывается.
   - `context_advance_cancels_repair_and_aborts_in_flight_io`: смена `(height, round)` переводит `Repair` в `ContextChanged` и немедленно завершает/отменяет фоновые I/O задачи.
   - `aggregate_session_memory_and_inflight_caps_enforced`: всплеск одновременных объявлений ограничен `W2_MAX_ACTIVE_SESSIONS = 4`, `W2_MAX_TOTAL_BYTES = 64 MiB`, `W2_MAX_TOTAL_IN_FLIGHT = 16`, а кадры > `W2_WIRE_CHUNK_SIZE` / `proof.len() > MAX_PROOF_DEPTH` отклоняются до аллокации буфера.
   - `unicast_only_no_broadcast_amplification`: 10 запрашивающих пиров порождают ровно 10 unicast `ChunkResp`, 0 all-peer broadcast.
3. **End-to-End Consensus, Mixed Fleet & Fallback (E4)**:
   - `e2e_large_proposal_via_data_plane_finalizes_and_matches_full_hash`: 3+1 нода, блок с не-мемпул транзакциями (> `COMPACT_MAX_FULL_SLOTS`), потеря части data-шардов, восстановление через parity-шарды, проход в `loopback_queue` → `on_proposal` → финализация с тем же `state_root`.
   - `e2e_mixed_capability_fleet_finalizes`: 3 ноды с `DATA_PLANE_REPAIR` + 1 нода без `DATA_PLANE_REPAIR` (dual-emit `CompactProposal`/`Proposal`) достигают одинаковой финализированной высоты.
   - `e2e_repair_failure_falls_back_to_full_proposal_and_dht_fetch_block`: < `k` доступных шардов или подменённый `attester_sig` / несовпадение `compute_hash()` после сборки приводят к безопасному fallback (`BodyPull::full_request` / `adapter.fetch_block`), без зависания раунда и без ложного `prevote`.
   - `e2e_consensus_tick_not_blocked_by_slow_chunk_peer`: искусственная задержка/blackhole одного пира на `dp_topic` не сдвигает таймеры раунда и не блокирует приём голосов на `consensus_topic`.
4. **`infnode` Parity & Audit (E5)**:
   - `ec_parity_matches_legacy_reed_solomon_erasure_6_0_0` (на существующей фикстуре `infnode/crates/infnode/src/node.rs:11068`) + проверка отсутствия `lru 0.7.8` в `infnode/Cargo.lock` и `stellereum/Cargo.lock`.
