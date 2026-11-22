# Light Client Header Commitment & Canonical EVM Bindings Contract (HDAE, code truth)

Статус: **архитектурный контракт интеграции** (закрывает P0 и оба P1 по результатам `VERIFY-REVIEW-CLAIMS`).
Зафиксировано по фактическому чтению дерева `stellereum/src/**` и `stellereum/tests/**` на 2026-11-21 (`CONSENSUS_RULESET_VERSION = 6`, `FORK_ID = 0x0f584a46`, `COMMITMENT_VERSION = 5`).

> **Правило замороженного ядра (`AGENTS.md` §7).**
> 1. Любое изменение преимиджа `Block::compute_hash()`, формата `BlockHeader`, правил `apply_block_transition()` (`SysCallBindEvmAddress` / `Domain::EvmBindings`), `CONSENSUS_RULESET_VERSION` или `FORK_ID` вводится строго **за константными активационными высотами** (`HEADER_COMMIT_ACTIVATION_HEIGHT`, `EVM_BINDINGS_STATE_ACTIVATION_HEIGHT`, по умолчанию `u64::MAX` до согласованного релиза + обновления `protocol.rs` + аудиторской заметки + полного гейта). На высотах `< activation_height` хеширование `Block::compute_hash()`, `state_root`, `COMMITMENT_VERSION = 5` и `genesis_root_known_answer_tests` остаются **побайтово неизменными**.
> 2. **Локальные / не-консенсусные исправления** (`light_client_cli.rs`, удаление `superseded_root` в `light_client.rs`, стриминговый прогрев `hydrate_rpc_from_store`, персистентный индекс `"evm_bindings"`) не меняют `FORK_ID` и применяются немедленно в своих изолированных потоках.
> 3. `BlockHeaderRecord` (`stellereum/src/storage.rs:539-562`) и `DomainSnapshot` (`stellereum/src/storage.rs:539-546, 2677-2694`) защищены правилом заморозки bincode-структур: новые поля добавляются только через аддитивные деревья `sled` (`"headers_v2"`, `"evm_bindings_state"`, `"evm_bindings"`) и версионированные wire-обёртки/аддитивные JSON-поля.

---

## 1. Инвентаризация подтверждённых дефектов (code truth)

| ID | Приоритет | Дефект | Факт в коде (`file:line`) | Последствие |
|---|---|---|---|---|
| **D1** | **P0** | Отсутствие криптографической связи `state_root` и `prev_hash` с подписанным `block_hash` в header-only путях | `sharding/block.rs:959-1107` (`Block::compute_hash` мешает `transactions`, `cross_shard_out`, `shard_headers`, `last_qc`, `cnvrf_v3` инлайн); `light_client.rs:454-474` (`Checkpoint::verify*`), `:530-604` (`verify_finality_with_schedule`), `:643-664` (`LightHeader::verify*`), `:2240-2279` (`verify_archive_proof`); `sync.rs:373-415, 512-620, 796-888` (`verify_snapshot_anchor*`); `consensus/types.rs:2577-2583` (`binds_to_parent` возвращает `true` при `Ok(None)` для не-µQC и никогда не связывает `state_root`); `network.rs:1889-1928` (`fetch_block_header` проверяет только `rec.height` и `rec.block_hash`) | Враждебный RPC/пир может прикрепить **подлинный** `precommit_qc` к `(height, real_block_hash)` и подложить **произвольные** `state_root` и `prev_hash` в `Checkpoint`, `LightHeader`, `HeaderLink`, `stell_getFinalizedHeader`, `stell_getFinalizedCheckpoint`, `stell_getHistoricalRoot`, `stell_getArchiveProof` и snapshot-anchor sync. |
| **D2a** | **P1** | `light_client_cli` не сверяет адрес и высоту ответа RPC | `light_client_cli.rs:348-415`: `stell_getProof` парсится в `answer` (`:366`), но `answer.address` нигде не сравнивается с `opts.verify`; `fetch_anchoring_header` (`:310-345`) и `run()` (`:380`) не проверяют `header.height == height + 1` (плюс возможно переполнение `height + 1` и отсутствует `--min-height`) | Сервер возвращает валидный proof для **чужого** богатого аккаунта или заголовок от **другой** высоты (включая старый подписанный заголовок), и CLI печатает `light client: VERIFIED`. |
| **D2b** | **P1** | Ложный запрет возврата `state_root` (`A -> B -> A`) через `superseded_root` | `light_client.rs:1720-1752` (`check_no_rollback` / `superseded_root`), вызывается из `apply_header` (`:1644`), `apply_header_without_block_signatures` (`:1677`) и `rotate_validator_set` (`:1901`); также `sync.rs:106` (`verify_synced_blocks_against_anchor_with_sets`); тест-опора `tests/light_client_tests.rs:1064-1099` | Легитимная последовательность блоков с валидным `prev_hash` и 2/3+ Precommit QC, возвращающая `state_root` к прежнему значению `A -> B -> A`, отвергается как «rollback», что ломает light client и sync (`sync.rs:106`). |
| **D3** | **P1** | Потеря EVM→PQ привязок старше 50k блоков + OOM на старте | `svm.rs:2582-2602` (`SysCallBindEvmAddress` не пишет в каноническое состояние); `evm_adapter/binding.rs:914-1031` (`EvmBindingRegistry` только process-global `OnceLock`); `rpc/state.rs:725-774` (`hydrate_rpc_from_store`: `all_receipts_capped(MAX_RECEIPTS = 50_000)` `:350,726`, загрузка до `EVM_INDEX_REPLAY_WINDOW = 50_000` полных `Block` в `blocks: Vec<Block>` в RAM `:743-759`, затем `rebuild_evm_indexes_from_blocks` → `clear_evm_bindings()` в `settlement.rs:2107`) | (1) Загрузка до 50 000 полных `Block` в RAM вызывает OOM на старте; (2) привязки, созданные раньше окна 50 000 блоков/чеков или после прунинга, навсегда теряются после рестарта; (3) `SysCallBindEvmAddress` не входит в `state_root` и не передаётся в state-снапшотах. |

---

## 2. Задача 1 (P0): Двухуровневый `BlockHeader` + `body_commitment` за `HEADER_COMMIT_ACTIVATION_HEIGHT`

### 2.1 Активационная граница `H - 1 / H / H + 1` и сохранение legacy-хешей

1. В `stellereum/src/sharding/block.rs` вводится константа по стандартному шаблону (`GOV_OPS_ACTIVATION_HEIGHT` в `governance.rs:144`, `ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT` в `zkml_attestation.rs:149`):
   - `pub const HEADER_COMMIT_ACTIVATION_HEIGHT: u64 = u64::MAX;` (и `pub fn effective_header_commit_activation_height() -> u64`, с test/debug override `#[cfg(any(test, debug_assertions))]`, **без** env-переменной в релизе).
   - При активации на высоте `H` (`HEADER_COMMIT_ACTIVATION_HEIGHT != u64::MAX`, в `protocol.rs:101, 151` повышаются `CONSENSUS_RULESET_VERSION` и список `FORK_ID_RULES` по `AGENTS.md` §7).
2. **Семантика на границе `H - 1 / H / H + 1`:**
   - **Высоты `< H` (вкл. `H - 1`)**: `Block::compute_hash_committing_round(round)` (`sharding/block.rs:959-1107`) выполняет **строго прежний преимидж `"STELLEREUM_BLOCK_V3"`** без единого изменённого байта. Все исторические блоки, подписи пропозера, `precommit_qc` и генезис/KAT-тесты сохраняют побайтовую совместимость.
   - **Высота `H`**:
     - `block_H.prev_hash` указывает на v3-хеш блока `H - 1` (`block_{H-1}.compute_hash()`).
     - `block_H.state_root` есть post-state высоты `H - 1`.
     - `block_H.height == H >= HEADER_COMMIT_ACTIVATION_HEIGHT`, поэтому `block_H.compute_hash()` и `block_H.value_id()` вычисляются по новой схеме `"STELLEREUM_BLOCK_V4"` (`BlockHeader::compute_hash()`).
     - **Следствие для якорения `H - 1`**: пост-состояние `H - 1` доказывается заголовком `H` (`H >= HEADER_COMMIT_ACTIVATION_HEIGHT`), поэтому `state_root(H - 1)` и `prev_hash = hash_{H-1}` уже криптографически доказаны заголовком `H`!
   - **Высота `H + 1` и далее**:
     - `block_{H+1}.prev_hash == block_H.compute_hash()` (v4-хеш), `block_{H+1}.last_qc` указывает на `block_H`, `block_{H+1}.state_root == post_state(H)`, `block_{H+1}.compute_hash()` использует v4.
   - **Правило для header-only верификаторов (`Checkpoint`, `LightHeader`, `HeaderLink`)**:
     - Если `header.height >= effective_header_commit_activation_height()` — проверка `header.to_block_header()?.compute_hash() == header.block_hash` **обязательна (fail-closed)**; несоответствие или отсутствие header-полей (`shard_id`, `round`, `body_commitment`, `epoch_key_commitment`, `mmr_epoch_root`, `timestamp`, `proposer`) ведёт к безусловному отказу до проверки QC или принятия root.
     - Если `header.height < effective_header_commit_activation_height()` — сохраняется прежняя v3-проверка QC над непрозрачным `block_hash` (так как v3-хеш невозможно пересчитать без `transactions`).

### 2.2 Точное разбиение полей `Block` на `BlockHeader` и `body_commitment` (без циклов и пропусков)

Проверены **все 17 полей** `pub struct Block` (`stellereum/src/sharding/block.rs:312-524`):

| Поле `Block` | Ссылка `block.rs` | Куда входит на `height >= H` | Обоснование (почему не пропущено и нет цикла) |
|---|---|---|---|
| `shard_id: ShardId` | `:313` | `BlockHeader` | Определяет шард; обязателен для light/cross-shard верификации. |
| `height: u64` | `:314` | `BlockHeader` | Определяет высоту и активационный порог `>= H`. |
| `round: u32` | `:523` | `BlockHeader` | В `compute_hash_committing_round(round)` для `compute_hash()`; в `value_id()` принудительно `round = 0`. Отдельно от `cert.round` (при lock-rescue `block.round <= cert.round`, `consensus_step.rs:822-846`)! |
| `prev_hash: [u8; 32]` | `:315` | `BlockHeader` | Прямая цель P0: связывает цепочку заголовков и `Checkpoint.parent_hash`. |
| `state_root: CellHash` | `:316` | `BlockHeader` | Прямая цель P0: доказывает `state_root` (post-state `height - 1`) одним заголовком. |
| `mmr_epoch_root: [u8; 32]` | `:491` | `BlockHeader` | Позволяет light-клиенту проверять `stell_getEpochRoot` (`rpc/reads.rs:1681`) напрямую по `LightHeader` (поле уже в `FinalizedHeaderRecord`, `rpc/state.rs:155`). |
| `epoch_key_commitment: [u8; 32]` | `:404` | `BlockHeader` | Позволяет light-клиенту проверять `stell_epochKey` по заголовку (`light_client.rs:807-811`). |
| `timestamp: u64` | `:319` | `BlockHeader` | Внешние верификаторы/оракулы и `BlockHeaderRecord` читают время из заголовка. |
| `proposer: [u8; 32]` | `:320` | `BlockHeader` | Проверяется в `HeaderLink` через `proposer_matches_schedule_with` (`sync.rs:400`) и передаётся в `LightHeader`. |
| `transactions: Vec<Transaction>` | `:317` | `body_commitment` | Полные хеши транзакций `Transaction::batch_hasher().hash_one(tx)` (`block.rs:986-992`). |
| `order_merkle_root: [u8; 32]` | `:379` | `body_commitment` | Корень порядка транзакций (`mev::compute_order_merkle_root`). |
| `cross_shard_out: Vec<CrossShardMessage>` | `:318` | `body_commitment` | Оба элемента: `m.msg_id` и `m.message_commitment()` (зеркально `block.rs:1010-1033`). |
| `shard_headers: Vec<ShardHeaderCommitment>` | `:354` | `body_commitment` | Последовательность `h.commitment_bytes()` (`block.rs:1042-1048`, включая `minted_total_nano`). |
| `last_qc: Option<QuorumCertificate>` | `:438` | `body_commitment` | Каноническая evidence-кворумная запись для `H - 1` (`height, round, kind, shard_id, block_hash, sorted (voter, sig)`). |
| `cnvrf_v3: Option<CnVrfV3BlockPayload>` | `:501` | `body_commitment` | `payload.canonical_bytes()` (`block.rs:263-308`). |
| `validator_signatures: Vec<([u8; 32], Vec<u8>)>` | `:321` | **Исключено** | Подписывают **итог** `Block::compute_hash()` — включение создало бы цикл. |
| `precommit_qc: Option<QuorumCertificate>` | `:330` | **Исключено** | Прикрепляется **после** финализации и подписывает `block_hash` в `vote_sign_bytes` — включение создало бы цикл. |

**Определение `body_commitment` и `BlockHeader` (без циклов, фиксированная ширина / length-prefixed):**

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub shard_id: ShardId,
    pub height: u64,
    pub round: u32,
    pub prev_hash: [u8; 32],
    pub state_root: CellHash,
    pub body_commitment: [u8; 32],
    pub mmr_epoch_root: [u8; 32],
    pub epoch_key_commitment: [u8; 32],
    pub timestamp: u64,
    pub proposer: [u8; 32],
}
```

1. **`Block::body_commitment(&self) -> [u8; 32]`** (домен `b"STELLEREUM_BODY_V4\0"`):
   - SHA-256 над:
     - `b"STELLEREUM_BODY_V4\0"`
     - `(self.transactions.len() as u32).to_be_bytes()` + для каждого `tx`: `tx_batch.hash_one(tx)` (32 B)
     - `self.order_merkle_root` (32 B, безусловно)
     - `(self.cross_shard_out.len() as u32).to_be_bytes()` + для каждого `m`: `m.msg_id` (32 B) + `m.message_commitment()` (фиксировано / как в `sharding/xshard.rs`)
     - `(self.shard_headers.len() as u32).to_be_bytes()` + для каждого `sh`: `(sh_bytes.len() as u32).to_be_bytes() || sh_bytes` (где `sh_bytes = sh.commitment_bytes()`, length-prefixed чтобы исключить склейку с optional `SHMINT01`)
     - `match &self.last_qc { None => 0u8, Some(qc) => 1u8 || qc.shard_id.to_be() || qc.height.to_be() || qc.round.to_be() || kind_u8 || block_hash_tag_and_opt_32 || sorted_sigs_len_and_items }`
     - `match &self.cnvrf_v3 { None => 0u8, Some(p) => 1u8 || (cb.len() as u32).to_be() || cb }`
   - Ни `block_hash`, ни `round`, ни `validator_signatures`, ни `precommit_qc` в `body_commitment` не входят → `body_commitment` не зависит от раунда (сохраняет `Block::value_id()`), и не создаёт циклических хешей.
2. **`BlockHeader::compute_hash(&self) -> [u8; 32]`** (домен `b"STELLEREUM_HDR_V4\0"`):
   - SHA-256 над:
     - `b"STELLEREUM_HDR_V4\0"`
     - `crate::consensus::consensus_chain_id().to_be_bytes()` (8 B — сохраняет chain-binding из `block.rs:965`)
     - `self.shard_id.to_be_bytes()` (4 B)
     - `self.height.to_be_bytes()` (8 B)
     - `self.round.to_be_bytes()` (4 B, безусловно в v4!)
     - `self.prev_hash` (32 B)
     - `self.state_root` (32 B)
     - `self.body_commitment` (32 B)
     - `self.mmr_epoch_root` (32 B)
     - `self.epoch_key_commitment` (32 B)
     - `self.timestamp.to_be_bytes()` (8 B)
     - `self.proposer` (32 B)
3. **`Block::header(&self) -> BlockHeader`** и **`Block::compute_hash_committing_round(&self, round: u32)`**:
   - При `self.height < effective_header_commit_activation_height()`: работает текущий v3-код (`block.rs:960-1107`).
   - При `self.height >= effective_header_commit_activation_height()`: возвращает `BlockHeader { round, ..self.header() }.compute_hash()`.
   - Таким образом, `Block::compute_hash(&self) == self.header().compute_hash()` и `Block::value_id(&self) == BlockHeader { round: 0, ..self.header() }.compute_hash()` **по определению**!

### 2.3 Обновление типов заголовков, хранилища, RPC и `sync.rs`

1. **`BlockHeaderRecord` и аддитивный `BlockHeaderRecordV2` (`stellereum/src/storage.rs`):**
   - `BlockHeaderRecord` (`storage.rs:553-562`) **не модифицируется** (соблюдение `FREEZE RULE`, `storage.rs:539-546`).
   - Вводится `BlockHeaderRecordV2`:
     ```rust
     pub struct BlockHeaderRecordV2 {
         pub header: BlockHeader,
         pub tx_count: u32,
         pub gas_used: u64,
         pub block_hash: BlockHash, // == header.compute_hash() при height >= H
     }
     ```
   - В `Storage` (`storage.rs:477-537, 849-891`) добавляется дерево `"headers_v2"` (ключ `height.to_be_bytes()` → `bincode(BlockHeaderRecordV2)`).
   - `Storage::put_block` (`:973-985`) и `Storage::put_header_v2` пишут legacy `headers` (для обратной совместимости чтения) **плюс** `headers_v2`.
   - `Storage::header_v2_at(height)` / `Storage::latest_header_v2()`:
     - На `height >= H`: требует запись из `"headers_v2"` (или реконструкцию из `get_block` если body не запрунен) и проверяет `rec.header.compute_hash() == rec.block_hash` (fail-closed!).
   - **`HistoricalRoot` (`storage.rs:769-785`) и `Storage::historical_root` (`:2313-2389`)**:
     - К `HistoricalRoot` добавляются (с `#[serde(default)]` для совместимости): `anchor_shard_id: u32`, `anchor_round: u32`, `anchor_body_commitment: [u8; 32]`, `anchor_mmr_epoch_root: [u8; 32]`, `anchor_epoch_key_commitment: [u8; 32]`, `anchor_timestamp: u64`, `anchor_proposer: [u8; 32]`.
     - В `Storage::historical_root` (`:2313-2389`): если `anchor_height >= H`, поля берутся из `headers_v2` (или из `block` при наличии тела), проверяется `anchor_header.compute_hash() == anchor_hash`; если `headers_v2` и тело отсутствуют на `anchor_height >= H` — **отказ** (fail-closed).
2. **`Checkpoint`, `LightHeader`, `HeaderLink`:**
   - **`Checkpoint` (`light_client.rs:239-255`)** получает `#[serde(default)]` поля для v4-реконструкции заголовка: `shard_id: u32`, `round: u32`, `body_commitment: Option<[u8; 32]>`, `mmr_epoch_root: [u8; 32]`, `epoch_key_commitment: [u8; 32]`, `timestamp: u64`, `proposer: [u8; 32]` (плюс `header_v4: Option<BlockHeader>` или конструктор `Checkpoint::from_block_header(header, cert)`).
   - **`LightHeader` (`light_client.rs:616-639`)** получает `#[serde(default)]`: `shard_id: u32`, `round: u32`, `body_commitment: Option<[u8; 32]>`, `mmr_epoch_root: [u8; 32]`, `epoch_key_commitment: [u8; 32]`. `LightHeader::of_block(block)` (`:767-779`) заполняет все поля (при `block.height >= H` — `body_commitment = Some(block.body_commitment())`, при `< H` — `None`).
   - **Единая проверка `verify_header_hash_binding`**:
     - В `Checkpoint::verify_with_schedule` (`:461-474`), `LightHeader::verify_with_schedule` (`:650-664`), `LightClient::apply_header_without_block_signatures` (`:1663-1680`) и `Checkpoint::from_historical_root_json` (`:335-441`):
     - Если `height >= effective_header_commit_activation_height()`:
       1. Требуется `body_commitment == Some(bc)` (при `None` — немедленный отказ!).
       2. Собирается `BlockHeader { shard_id, height, round, prev_hash, state_root, body_commitment: bc, mmr_epoch_root, epoch_key_commitment, timestamp, proposer }`.
       3. Проверяется `hdr.compute_hash() == claimed_block_hash`. Любое несовпадение (`state_root`, `prev_hash`, `height`, `round`, `shard_id`, `body_commitment`, `mmr_epoch_root`, `epoch_key_commitment`, `timestamp`, `proposer`) **отклоняется до или вместе с проверкой QC**!
   - **MMR и `stell_getArchiveProof`**:
     - `verify_archive_proof` (`light_client.rs:2240-2279`) проверяет `proof.state_root` против `self.trusted_height_of_root(&proof.state_root)` (а корни в `LightClient` на `height >= H` могут попасть **только** после `verify_header_hash_binding` + QC). Для `stell_getEpochRoot`: `mmr_epoch_root` входит в `BlockHeader` и покрывается `BlockHeader::compute_hash()`, поэтому `LightHeader` криптографически аутентифицирует `committed_root` для `verify_mmr_inclusion` (`light_client.rs:1001`).
   - **`HeaderLink` (`sync.rs:224-231`) и `sync::verify_snapshot_anchor*` (`sync.rs:512-620, 796-888`)**:
     - `HeaderLink` расширяется полями `shard_id: u32`, `round: u32`, `body_commitment: Option<[u8; 32]>`, `mmr_epoch_root: [u8; 32]`, `epoch_key_commitment: [u8; 32]`, `timestamp: u64`.
     - В `verify_finality_for_header_with_schedule` (`sync.rs:373-415`):
       - При `height >= effective_header_commit_activation_height()`: обязательна проверка `link.body_commitment == Some(bc)` и `BlockHeader::compute_hash() == link.block_hash` (fail-closed!).
       - Это гарантирует, что в обоих `verify_snapshot_anchor_with_sets_and_schedule` (`:584`) и `verify_snapshot_anchor_tail_with_sets_and_schedule` (`:857`) ни `link.state_root`, ни `link.prev_hash` (`boundary_hash`) не могут быть подменены пиром даже при не-µQC сертификате (`binds_to_parent == true` при `Ok(None)` в `consensus/types.rs:2581`).
   - **Сетевой обмен заголовками (`network.rs:1657-1718, 1889-1928`) и `node/sync.rs:180-252`**:
     - `persist_block_header` (`network.rs:1657`) публикует `BlockHeaderRecord` (для `< H` и совместимости) и `BlockHeaderRecordV2` (под именем `header_v2_name(&self.epoch(), shard_id, block.height)` в той же Pointer-lane группе).
     - `fetch_block_header_v2` / обновлённый `fetch_block_header`: при `height >= H` требует `BlockHeaderRecordV2`, проверяет `rec.header.height == height && rec.block_hash == expected_hash && rec.header.compute_hash() == expected_hash`. В `node/sync.rs:190, 240` `anchor_fetch` передаёт полные поля `BlockHeaderRecordV2` в `HeaderLink`.
3. **RPC (`rpc/state.rs`, `rpc/reads.rs`):**
   - `FinalizedHeaderRecord` (`rpc/state.rs:139-190`) получает `#[serde(default)]`: `shard_id: u32`, `round: u32`, `body_commitment: Option<[u8; 32]>`, `epoch_key_commitment: [u8; 32]` (`mmr_epoch_root` уже присутствует `:155`); `record_finalized_header` (`:486-513`) заполняет их из `block`.
   - `stell_getFinalizedHeader` (`rpc/reads.rs:1588-1630`) через `FinalizedHeaderRecord::to_json()` (`rpc/state.rs:162-189`) отдаёт `"shard_id"`, `"round"`, `"body_commitment"`, `"epoch_key_commitment"`, `"mmr_epoch_root"`, `"timestamp"`, `"proposer"`.
   - `stell_getFinalizedCheckpoint` (`rpc/reads.rs:1635-1662`) отдаёт те же поля (`"shard_id"`, `"round"`, `"body_commitment"`, `"epoch_key_commitment"`, `"mmr_epoch_root"`), чтобы JSON напрямую парсился в `Checkpoint` (`light_client_cli::load_checkpoint_file`, `light_client_cli.rs:482`).
   - `stell_getHistoricalRoot` (`rpc/reads.rs:960-1016`) включает `"shard_id"`, `"round"`, `"body_commitment"`, `"mmr_epoch_root"`, `"epoch_key_commitment"`, `"timestamp"`, `"proposer"` из `HistoricalRoot`, и `Checkpoint::from_historical_root_json` (`light_client.rs:335-441`) парсит их и проверяет `compute_hash()` при `anchor_height >= H`.

---

## 3. Задача 2 (P1): Локальный клиентский фикс (`light_client_cli.rs` + `light_client.rs`)

Эти изменения не меняют `FORK_ID` и применяются на стороне верификатора/клиента:

1. **Проверка адреса (`light_client_cli.rs:348-376, 424`):**
   - В `run(opts: &LightClientOptions)` до/сразу после получения `stell_getProof` декодируется эталонный адрес из `opts.verify`:
     `let expected_address = crate::address::parse_address(&opts.verify)?;` (принимает 32-байтовый hex, с или без `0x`, fail-closed при ошибке).
   - Проверяется `if answer.address != expected_address { anyhow::bail!("proof address {} does not match requested --verify {}", hex::encode(answer.address), hex::encode(expected_address)); }`.
   - Дополнительно проверяется `proven.address == expected_address` после `client.verify_proof_answer(&answer)` (`:424`).
2. **Проверка высоты и защита от переполнения (`light_client_cli.rs:310-345, 368-400`):**
   - В `fetch_anchoring_header(url, expected_height, ...)` (`:310-345`): если `parse_served_header` вернул `h` с `h.height != expected_height`, ответ **отвергается** (`last_err = format!("header height {} != expected {expected_height}", h.height)`), никогда не принимается за якорный.
   - В `run()`:
     - `let anchor_height = height.checked_add(1).ok_or_else(|| anyhow::anyhow!("proof height {height} overflows"))?;`
     - После `fetch_anchoring_header(..., anchor_height, ...)`: явная проверка `if header.height != anchor_height { bail!(...); }`.
     - Проверка `header.cert.shard_id == header.shard_id` и при `header.height >= effective_header_commit_activation_height()` — пересчёт `BlockHeader::compute_hash() == header.block_hash` (через `LightHeader` + `LightClient::new` / `Checkpoint::verify_with_schedule`).
3. **Флаг `--min-height` (`cli/args.rs:169-187`, `cli/handlers.rs:1700-1715`, `light_client_cli.rs:58-69`):**
   - В `LightClientOptions` добавляется `pub min_height: Option<u64>`, в `Commands::LightClient` добавляется `#[arg(long)] min_height: Option<u64>`.
   - В `run()`: если `Some(min_h) = opts.min_height`:
     - проверяется `if height < min_h { anyhow::bail!("proof height {height} is below --min-height {min_h}"); }` (и `header.height >= min_h.saturating_add(1)`).
   - Это защищает CLI от rollback-подмены на старый легитимно подписанный чекпоинт (rollback to old height).
4. **Удаление `superseded_root` (`A -> B -> A` fix) в `light_client.rs`:**
   - В `stellereum/src/light_client.rs:1644, 1677, 1720-1752, 1901`: удаляются `check_no_rollback` и `superseded_root` (и их вызовы в `apply_header`, `apply_header_without_block_signatures`, `rotate_validator_set`).
   - Обоснование: легитимная последовательность блоков со сменой состояния и возвратом к прежнему корню `A -> B -> A` (например, пополнение и полный вывод, или откат временной записи в том же домене) при монотонном росте высоты `tip + 1`, валидном `prev_hash == tip_hash()` и 2/3+ Precommit QC абсолютно законна. Запрет `superseded_root` ломал не только `LightClient`, но и `sync::verify_synced_blocks_against_anchor_with_sets` (`sync.rs:106`).
   - Истинная защита от отката обеспечивается: (a) строгим ростом высоты `header.height == tip_height() + 1` (`check_header_shape`, `light_client.rs:1684-1701`), (b) сцеплением `header.prev_hash == tip_hash()` (`:1702-1710`), (c) 2/3+ Precommit QC, (d) `BlockHeader::compute_hash()` на `>= HEADER_COMMIT_ACTIVATION_HEIGHT` и (e) `cp.height >= tip` в `advance_to_checkpoint` (`:1800-1806`).
   - **Проверка существующих тестов:**
     - `stellereum/tests/light_client_tests.rs:1064-1099` (`a_header_may_not_roll_the_state_back_to_a_superseded_root`): тест **намеренно** проверяет ошибочное поведение `superseded_root` на валидной цепи `0xAA -> 0xBB -> 0xAA` с корректным `prev_hash` и QC. Он должен быть **переписан** (с обновлением спеки + аудиторской заметкой по `AGENTS.md` §7) в позитивный тест `a_valid_quorum_certified_chain_may_revisit_an_earlier_state_root` (`apply_header` принимает `A -> B -> A`), а откат по высоте/форку (`height <= tip`, `prev_hash != tip_hash`, подмена `state_root` при `>= H`) проверяется отдельными негативными тестами.
     - `stellereum/tests/light_e2e_tests.rs:548-575`: проверяет `advance_to_checkpoint(rollback)` на высоте `3 < tip (6)` и ожидает `err.contains("older than")` (`light_client.rs:1801`). Этот чек от `superseded_root` **не зависит** и остаётся зелёным без изменений!
     - `stellereum/tests/pentest_light_shard2.rs:495-525`: аналогично проверяет `advance_to_checkpoint` на меньшей высоте; остаётся зелёным без изменений.

---

## 4. Задача 3 (P1): Канонический `Domain::EvmBindings` + стриминговый прогрев без OOM

### 4.1 `Domain::EvmBindings` в `commitment.rs`, `state_engine/`, `apply.rs` и `storage.rs`

1. **Активация и инвариант `COMMITMENT_VERSION = 5`:**
   - Вводится `pub const EVM_BINDINGS_STATE_ACTIVATION_HEIGHT: u64 = u64::MAX;` в `state_engine/mod.rs` (с test-only override `#[cfg(any(test, debug_assertions))]`, без env-переменных в релизе).
   - **Условное включение в `commitment.rs`** (по точному паттерну `write_cnvrf_v3_domain`, `commitment.rs:1931-2013` и `total_minted_nano`, `:2066-2081`):
     - Когда `EvmBindingsState::is_empty()`, домен эмитит **0 байт**.
     - Поэтому `COMMITMENT_VERSION = 5` и `genesis_root_known_answer_tests.rs` остаются **неизменными**!
2. **Структура состояния `EvmBindingsState` (`state_engine/types.rs`):**
   ```rust
   #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
   pub struct EvmBindingsState {
       pub by_evm: HashMap<[u8; 20], [u8; 32]>,
       #[serde(skip)] // деривируется при восстановлении, чтобы не допускать рассинхрона by_evm <-> by_pq
       pub by_pq: HashMap<[u8; 32], [u8; 20]>,
   }
   ```
   - Инвариант биекции 1-к-1: при вставке `(evm, pq)` проверяется И `by_evm.get(&evm)`, И `by_pq.get(&pq)` (**first-writer-wins**).
   - `EvmBindingsState::bind(&mut self, evm: [u8; 20], pq: [u8; 32]) -> Result<bool, String>`:
     - `by_evm.get(&evm) == Some(&pq)` и `by_pq.get(&pq) == Some(&evm)` → `Ok(false)` (идемпотентно).
     - Иной `pq` для `evm` или иной `evm` для `pq` → `Err(...)` (не перезаписывает!).
     - При отсутствии обоих → вставка в `by_evm` и `by_pq`, `Ok(true)`.
   - `EvmBindingsState::rebuild_inverse(&mut self)` при десериализации/восстановлении проверяет инъективность `by_evm` (ошибка при дублировании `pq`, fail-closed).
3. **Кодирование преимиджа в `stellereum/src/commitment.rs`:**
   - В `enum Domain` (`:123-138`) добавляется `EvmBindings`.
   - В `DomainGenerations` (`:196-277`) добавляется `pub evm_bindings: AtomicU64` (`copy_values_into` и `bump_all` включают `Domain::EvmBindings`).
   - В `DomainCache` (`:390-495`): добавляется `evm_bindings_slot: Option<DomainSlot>` (аналогично `cnvrf_slot:392`, чтобы `Domain::ALL: [Domain; 13]` и `[u64; 13]`-контракт тестов `commitment_assembly_differential_tests.rs` сохранялись без поломки, плюс `get_evm_bindings_silent` / `put_evm_bindings_silent`).
   - `write_evm_bindings_domain<S: PreimageSink>(h: &mut S, s: &EvmBindingsState)`:
     - Если `s.by_evm.is_empty()` → `return;`.
     - `put_bytes(h, b"evm_bindings_domain", b"EVM_BINDINGS_V1")`
     - Сортированный вектор `entries: Vec<(&[u8; 20], &[u8; 32])>` по ключу `evm` (байтовый лексикографический порядок — никаких `HashMap`-порядков!).
     - `put_u64(h, b"evm_bindings_len", entries.len() as u64)`
     - Для каждой `(evm, pq)`: `put_bytes(h, b"evm_addr", evm); put_addr(h, b"pq_addr", pq);`.
   - Подключается в `commitment_digest_with_zkml_cnvrf_and_evm_bindings` и `assemble_cached_digest_with_cnvrf_minted_and_evm_bindings` сразу после `cnvrf` / `total_minted_nano` (и вызывается в `InMemoryStateEngine::commit_consensus_domains_cached` `:620-928` и `commit_consensus_domains` `:1587-1611`).
4. **Интеграция в `InMemoryStateEngine` (`state_engine/mod.rs`, `accounts.rs`):**
   - Приватное поле `evm_bindings: Arc<RwLock<EvmBindingsState>>` в `InMemoryStateEngine` (`state_engine/mod.rs:165+`).
   - Доступ: `evm_bindings_read()` и `evm_bindings_write()` (через `dom_guard`, который атомарно инкрементирует `Domain::EvmBindings` + `commitment_generation`).
   - `clone_for_simulation` (`accounts.rs:100-214`): глубокое клонирование `evm_bindings` + пустой `DomainCache`.
   - `restore_snapshot` (`accounts.rs:2338`) vs `restore_snapshot_preserve_replay_sets` (`:2409`): аналогично `session_keys` / `bridge` / `zkml_models` / `cnvrf_v3`, домен хранится в собственном дереве `"evm_bindings_state"`, а не в `StateSnapshotV2` или `DomainSnapshot`.
5. **Детерминированный `apply()` (`state_engine/apply.rs`, `parallel.rs`) — First-Writer-Wins:**
   - **Никакого чтения локальной БД или глобального `OnceLock` внутри `apply()`!** Иначе archive-узел и snapshot-synced узел разойдутся в `state_root`.
   - На `block.height >= effective_evm_bindings_state_activation_height()`:
     - В `apply_block_transition` (`apply.rs:2725-2733`, шаг 1a-TER) для каждой транзакции `i` по порядку `0..block.transactions.len()` с `status[i] == true`:
       - Извлекается проверенное утверждение `(evm, pq)`:
         - для `OpCode::SysCallBindEvmAddress(claim)`: `verify_binding_claim(claim, &tx.from)` (`evm_adapter/binding.rs:337`);
         - для `OpCode::SysCallEvmCarrier(carrier)`: `verify_carrier_intent(carrier, &tx.from)` (`evm_adapter/binding.rs:1010`).
       - Вызывается `self.evm_bindings_write().await.bind(evm, tx.from)` — строго **first-writer-wins** в детерминированном порядке `(height, tx_index)`. Повторное/конфликтное утверждение на уже занятый `evm` или `pq` (включая вторую транзакцию в том же блоке) не перезаписывает привязку (`Err` игнорируется на уровне карты — первая запись сохраняется).
       - Дополнительно в `execute_payload_with_preverify` (`apply.rs:420+`) перед VM можно отклонять (`Err`) повторную попытку `SysCallBindEvmAddress` на уже занятый на начало блока `evm`/`pq`, чтобы несостоятельный повтор тратил failed-fee и давал `status[i] = false` (при этом даже если два конфликтующих `SysCallBindEvmAddress` попали в один блок при параллельном исполнении, шаг 1a-TER всё равно гарантирует детерминизм first-writer-wins!).
     - Тот же коммит выполняется в конце single-tx пути `apply_transaction` (`apply.rs:1540+`, при наличии `height` >= activation).
   - На `block.height < effective_evm_bindings_state_activation_height()`:
     - `self.evm_bindings` не модифицируется (состояние корня идентично до-активационной сети); обновление идёт только в не-консенсусный индекс (`"evm_bindings"` + локальный кэш).
6. **Снапшоты домена в `storage.rs`, `runtime/lanes.rs`, `network.rs`, `sync.rs`:**
   - В `Storage` (`storage.rs:477-537, 849-891`) добавляется height-keyed дерево `"evm_bindings_state"` (`height.to_be_bytes()` → `bincode(EvmBindingsSnapshot { by_evm })`) + `put_evm_bindings_state`, `evm_bindings_state_at`, `prune_evm_bindings_state_below`.
   - В `SnapBundle` (`runtime/lanes.rs:230-245`) и `PersistJob::Domains` (`storage.rs:3943-3955`) добавляется `evm_bindings: Vec<u8>` (с пустым вектором при `is_empty()`).
   - В `Storage::load_full_state_into` (`storage.rs:3506-3683`) и `Storage::rebuild_historical_trie` (`:2275+`): если `evm_bindings_state_at(height)` есть и непусто — восстанавливается в `tmp` и `engine` **до** `verify_restored_root` (`:3634`). Отсутствующая запись на старых директориях означает пустой `EvmBindingsState` (0 байт в хеше — обратная совместимость).
   - В `SYNC_DOMAIN_KINDS` (`sync.rs:1275-1283`) и `SNAPSHOT_PUBLISH_DOMAIN_KINDS` (`network.rs:1142-1149`) добавляется `"evm_bindings"` (и в `install_bundle` в `sync.rs` — отсутствие блоба допустимо только если домен пуст; если непуст, без него `computed_root != expected_root` сработает fail-closed!).

### 4.2 Не-консенсусный персистентный sled-индекс `"evm_bindings"` + стриминговый прогрев без OOM

1. **Персистентное дерево `"evm_bindings"` (`storage.rs`):**
   - Аддитивное дерево `evm_bindings: sled::Tree` в `Storage::open` (`storage.rs:849-891`):
     - `b"e:" || evm(20)` → `pq(32)`
     - `b"p:" || pq(32)` → `evm(20)`
     - `b"meta:cursor"` → `u64::to_be_bytes()` (последняя полностью проиндексированная высота)
   - Запись `Storage::put_evm_binding_if_absent(evm, pq)` использует строгую проверку **first-writer-wins** внутри `sled`: если `b"e:" || evm` или `b"p:" || pq` уже существует с другим адресом — отказ без перезаписи!
   - **Порядок записи (crash-safe data-before-cursor)**: сначала вставляются `b"e:"` и `b"p:"` за блок `h`, затем обновляется `b"meta:cursor"` на `h`. При обрыве питания на старте индексируется с `cursor + 1` (идемпотентно).
   - Важно: `prune_blocks_below` / `prune_receipts_below` **никогда не удаляют** записи из `"evm_bindings"` — поэтому привязки, созданные на высотах `1..N`, переживают любой прунинг и рестарт за пределами `50 000` блоков!
2. **Обновление индекса в live-потоке и единый lookup (`rpc/eth.rs`, `mempool.rs`, `state_engine/accounts.rs`):**
   - При финализации/adopt блока `block` на `publish_lane`/`PersistJob` (в `consensus_driver.rs` / `storage.rs`) новые успешные привязки пишутся в `"evm_bindings"` (и в `EvmBindingRegistry`).
   - `InMemoryStateEngine::evm_binding_pq(&self, evm)` (`state_engine/accounts.rs:2688`) и lookup для `pq -> evm`:
     1. Сначала читает канонический `self.evm_bindings.read().await` (источник истины для `>= EVM_BINDINGS_STATE_ACTIVATION_HEIGHT`).
     2. Если не найдено — читает процессный/персистентный индекс pre-activation (`evm_binding_index()` / `storage.evm_bindings` lookup по ключу `b"e:" || evm` без полного скана!).
3. **Стриминговый инкрементальный прогрев при старте (`rpc/state.rs:725-774`):**
   - **Запрещено** в `hydrate_rpc_from_store`:
     - аллоцировать `Vec<Block>` на `50_000` тел (`:752-759` полностью удаляется!);
     - вызывать `clear_evm_bindings()` (`settlement.rs:2107`) на старте!
     - ограничивать источник `successful` квитанциями из `all_receipts_capped(MAX_RECEIPTS)` (`:726, 744-748`), которые отсекают старую историю!
   - **Новый алгоритм `hydrate_rpc_from_store(st, store)`:**
     1. **Квитанции RPC (`recent_receipts`)**: как и прежде, загружает последние `MAX_RECEIPTS` (`50_000`) только для RPC-ответов `stell_getTransactionReceipt`.
     2. **Прогрев `EvmBindingRegistry` из персистентного `"evm_bindings"` (O(|bindings|), 0 тел блоков!)**:
        - Итерирует префикс `b"e:"` в `store.evm_bindings` потоково (без загрузки блоков) и заполняет `EvmBindingRegistry` (или `Storage` читает `b"e:"` напрямую по требованию, если `len > EVM_BINDING_INDEX_CAP`).
        - Также синхронизирует записи из канонического `st.engine.evm_bindings_read().await`.
     3. **Инкрементальный догон хвоста `(cursor + 1)..=tip` по ОДНОМУ блоку (`O(1)` RAM)**:
        - Читает `cursor = store.evm_bindings_cursor()?`.
        - Если `cursor == Some(c)` — `start_h = c.saturating_add(1)`.
        - Если `cursor == None` (первая миграция существующей data-dir): `start_h = 0` для scan header/block **или** `tip.saturating_sub(EVM_INDEX_REPLAY_WINDOW - 1)` с потоковым чтением по 1 блоку (при наличии архивных блоков — возможно фоновой задачей или bounded batch `1_000` блоков за шаг с `yield_now()`).
        - Для каждой высоты `h` в `start_h..=tip`:
          - Читает `header_at(h)` → `get_block(&rec.block_hash)` в **локальную переменную цикла**, которая освобождается в конце итерации (**максимум 1 `Block` в RAM**!).
          - Быстрая проверка: если ни одна транзакция блока не содержит `classify_evm_payload(tx)` и `is_secp_settlement_tx(tx)` — переходит к следующей высоте без чтения `receipts_v1`.
          - Для EVM-транзакций проверяет успех по `store.get_receipt(&tx.compute_tx_hash())?` (`storage.rs:1305`) — O(1) point-lookup, не держа `50_000` чеков в `HashSet`.
          - Пишет новые `(evm, pq)` first-writer-wins в `"evm_bindings"` + `EvmBindingRegistry`, settlement-ссылки в `evm_settlements`, и обновляет `b"meta:cursor"` батчами (например, каждые 256 высот и в конце цикла).
        - На воркчейн-шарде (`st.engine.shard_id() != MASTERCHAIN_SHARD`): не очищает и не перезаписывает masterchain-записи.
     4. **Сводки блоков (`recent_blocks`)**: без изменений — по `header_at(h)` без загрузки тел (`rpc/state.rs:777-800`).

---

## 5. Непересекающаяся матрица владения файлами (`AGENTS.md` §2, §8)

Ни один файл не редактируется двумя потоками одновременно:

| Поток | Разрешённые файлы (строго disjoint) | Ответственность |
|---|---|---|
| **Stream A: Header Commitment Core** | `stellereum/src/sharding/block.rs`, `stellereum/src/sharding/mod.rs`, `stellereum/src/protocol.rs` *(только при переключении активационной высоты / `FORK_ID`)*, `stellereum/tests/header_commitment_tests.rs` *(new)* | `BlockHeader`, `Block::body_commitment()`, `HEADER_COMMIT_ACTIVATION_HEIGHT`, двухуровневый v4 `compute_hash()` / `value_id()`, сохранение побайтового v3 на `< H`. |
| **Stream B: Light Client & CLI** | `stellereum/src/light_client.rs`, `stellereum/src/light_client_cli.rs`, `stellereum/src/cli/args.rs`, `stellereum/src/cli/handlers.rs`, `stellereum/tests/light_client_tests.rs`, `stellereum/tests/light_cli_tests.rs` | Верификация `BlockHeader::compute_hash()` в `Checkpoint` / `LightHeader` / `from_historical_root_json`; удаление `superseded_root` (`A -> B -> A`); фиксы `light_client_cli` (адрес `opts.verify`, высота `height + 1`, `--min-height`); обновление `light_client_tests.rs:1064`. |
| **Stream C: Canonical `Domain::EvmBindings`** | `stellereum/src/commitment.rs`, `stellereum/src/state_engine/mod.rs`, `stellereum/src/state_engine/types.rs`, `stellereum/src/state_engine/accounts.rs`, `stellereum/src/state_engine/apply.rs`, `stellereum/src/state_engine/settlement.rs`, `stellereum/src/state_engine/parallel.rs`, `stellereum/src/evm_adapter/binding.rs`, `stellereum/tests/evm_bindings_domain_tests.rs` *(new)* | `Domain::EvmBindings` (условный преимидж, `DomainGenerations`, `DomainCache`), `EvmBindingsState`, `EVM_BINDINGS_STATE_ACTIVATION_HEIGHT`, first-writer-wins в `apply_block_transition`, изоляция в `clone_for_simulation`, `evm_binding_pq` + `lookup_bound_evm` поверх canonical + fallback. |
| **Stream D: Storage, Snapshots & Sync Anchor** | `stellereum/src/storage.rs`, `stellereum/src/sync.rs`, `stellereum/src/network.rs`, `stellereum/tests/snapshot_anchor_header_binding_tests.rs` *(new)*, `stellereum/tests/evm_bindings_storage_tests.rs` *(new)* | Аддитивные деревья `"headers_v2"`, `"evm_bindings_state"`, `"evm_bindings"`; `BlockHeaderRecordV2`, `HistoricalRoot` v4-поля; `HeaderLink` + `verify_finality_for_header_with_schedule` hash-binding в `sync.rs`; `fetch_block_header` v2 и `"evm_bindings"` в `SYNC_DOMAIN_KINDS` / `SNAPSHOT_PUBLISH_DOMAIN_KINDS`; стриминговые helpers без `Vec<Block>`. |
| **Stream E: Runtime, RPC & Node Wiring** | `stellereum/src/runtime/lanes.rs`, `stellereum/src/runtime/apply.rs`, `stellereum/src/runtime/anchors.rs`, `stellereum/src/runtime/consensus_step.rs`, `stellereum/src/node/consensus_driver.rs`, `stellereum/src/node/sync.rs`, `stellereum/src/node/bootstrap.rs`, `stellereum/src/rpc/state.rs`, `stellereum/src/rpc/reads.rs`, `stellereum/src/rpc/eth.rs`, `stellereum/tests/evm_startup_oom_and_restart_tests.rs` *(new)*, `stellereum/tests/rpc_header_binding_tests.rs` *(new)* | Потоковый прогрев `hydrate_rpc_from_store` (без `Vec<Block>` и без `clear_evm_bindings()`); проброс `evm_bindings` в `SnapBundle` / `PersistJob`; новые поля в `FinalizedHeaderRecord`, `stell_getFinalizedHeader`, `stell_getFinalizedCheckpoint`, `stell_getHistoricalRoot`; `anchor_fetch` в `node/sync.rs` → `HeaderLink` v2. |

*Порядок мержа*: **A** и **C** независимы; **B** зависит от **A**; **D** зависит от **A** и **C**; **E** интегрирует **A + C + D**. `infnode/**` и `BlockHeaderRecord` / `DomainSnapshot` bincode-схемы не изменяются.

---

## 6. Обязательный список тестов «падало до» (`fail-before → pass-after`)

Все тесты должны воспроизводить реальную атаку/сбой без мока криптографических проверок и пройти `cargo clippy --all-targets -- -D warnings` + `cargo test --no-fail-fast`:

1. **Подменённый `state_root` при валидном QC (`forged_state_root_with_valid_qc_rejected`)** `[A, B, D, E]`:
   - *Падало до*: на высоте `>= HEADER_COMMIT_ACTIVATION_HEIGHT` берётся подлинный `precommit_qc` от реального `block_hash`, но в `Checkpoint`, `LightHeader`, `stell_getFinalizedHeader`, `stell_getFinalizedCheckpoint`, `stell_getHistoricalRoot` (для `stell_getArchiveProof`) и `HeaderLink` (`sync::verify_snapshot_anchor*`) подставляется чужой `state_root` → до фикса `verify*` возвращал `Ok(())`.
   - *После*: немедленный отказ до принятия корня (`header hash mismatch`), состояние `LightClient` / `SnapshotAnchor` не изменяется.
2. **Подменённый `prev_hash` в `sync.rs` / `Checkpoint` / `LightHeader` (`forged_prev_hash_with_valid_qc_rejected`)** `[A, B, D]`:
   - *Падало до*: при не-µQC (или Beacon-расписании, где `QuorumCertificate::binds_to_parent` возвращает `true`) `verify_snapshot_anchor_with_sets_and_schedule` (`sync.rs:512-620`) и `verify_snapshot_anchor_tail_with_sets_and_schedule` (`sync.rs:796-888`) и `Checkpoint`/`LightHeader` принимали подменённый `prev_hash` (`boundary_hash`), уводящий ноду на форк.
   - *После*: `BlockHeader::compute_hash() != block_hash` отвергает заголовок на первом же шаге.
3. **Покрытие всех полей блока + не-цикличность + граница `H - 1 / H / H + 1` (`header_body_commitment_completeness_and_activation_boundary`)** `[A]`:
   - *Падало до*: заголовок не мог пересчитать `block_hash`.
   - *После*: (a) на `H - 1` `compute_hash()` побайтово совпадает с v3; (b) на `H` и `H + 1` изменение любого из 15 консенсусных полей `Block` меняет `compute_hash()`, а изменение `validator_signatures` или `precommit_qc` не меняет `compute_hash()` и `body_commitment()`; (c) `value_id()` совпадает с `BlockHeader { round: 0, .. }.compute_hash()`.
4. **Чужой адрес в `light_client_cli` (`cli_rejects_proof_for_different_address`)** `[B]`:
   - *Падало до*: мок-RPC на запрос `stell_getProof` для `Alice` возвращает валидный proof и заголовок для `Bob`; `light_client_cli::run` печатал `VERIFIED` с балансом `Bob`.
   - *После*: `run` отказывает с явной ошибкой несовпадения `answer.address` и `opts.verify`.
5. **Неверная высота заголовка и `--min-height` в `light_client_cli` (`cli_rejects_wrong_header_height_and_stale_min_height`)** `[B]`:
   - *Падало до*: `fetch_anchoring_header` не проверял `header.height == proof_height + 1`, а CLI не имел `--min-height`, допуская откат на старый подписанный чекпоинт.
   - *После*: заголовок с `height != proof_height + 1` и proof с `height < --min-height` отвергаются fail-closed.
6. **Возврат состояния `A -> B -> A` (`a_valid_quorum_certified_chain_may_revisit_an_earlier_state_root` + регрессия по высоте)** `[B]`:
   - *Падало до*: `LightClient::apply_header` и `sync::verify_synced_blocks_against_anchor_with_sets` (`sync.rs:106`) отвергали честную QC-подписанную цепочку `A -> B -> A` (`superseded_root`, `tests/light_client_tests.rs:1064`).
   - *После*: `A -> B -> A` принимается при валидном `prev_hash` и QC; старый чекпоинт с `cp.height < tip` (`tests/light_e2e_tests.rs:548`) и подмена высоты/родителя по-прежнему отвергаются.
7. **Канонический `Domain::EvmBindings` и first-writer-wins (`evm_bindings_state_root_and_first_writer_wins`)** `[C, D]`:
   - *Падало до*: `SysCallBindEvmAddress` не менял `state_root` и не попадал в снапшоты; `clone_for_simulation` читал глобальный `OnceLock`.
   - *После*: (a) до `EVM_BINDINGS_STATE_ACTIVATION_HEIGHT` и при пустом `EvmBindingsState` `COMMITMENT_VERSION = 5` и genesis root не меняются; (b) на `>= activation` валидный `SysCallBindEvmAddress` меняет `state_root` одинаково на всех нодах; (c) повторная привязка занятого `evm` или `pq` (в одном или разных блоках) не перезаписывает первого владельца; (d) `evm_bindings_state` снапшот восстанавливается и проходит `verify_restored_root` / `fast_sync_verify_commit`.
8. **Рестарт после `> 50 000` блоков без OOM и без потери привязок (`evm_bindings_survive_50k_blocks_prune_and_restart_without_oom`)** `[D, E]`:
   - *Падало до*: `hydrate_rpc_from_store` (`rpc/state.rs:725-774`) чистил `EvmBindingRegistry`, загружал `Vec<Block>` на `50 000` тел в RAM и терял привязки старше `50 000` блоков/чеков или после прунинга.
   - *После*: на хранилище с привязкой на высоте `1`, `55 000` пустых/обычных блоков сверху и выполненным `prune_blocks_below(50_000)` + `prune_receipts_below(50_000)`: (a) рестарт `Storage::open` + `hydrate_rpc_from_store` завершается при инварианте «в RAM не более 1 `Block` за итерацию» (`Vec<Block>` отсутствует, используется инкрементальный курсор `"evm_bindings"` + домен `"evm_bindings_state"`); (b) `eth_getBalance` / `stell_evmBindingLookup` / `evm_binding_pq` находят привязку с высоты `1` в обоих режимах (до и после активации); (c) память/время повторного рестарта `O(delta)` вместо `50 000` блоков.
