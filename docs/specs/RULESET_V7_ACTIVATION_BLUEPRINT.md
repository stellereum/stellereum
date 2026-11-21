# RULESET v7 ACTIVATION BLUEPRINT — Единая схема интеграции консенсусных волн (R1 → R5)

**Статус:** мастер-план интеграции и распределения консенсусных пространств имён для Ruleset v7 (`AGENTS.md` §2, §4, §7, §8).
**Базовая точка дерева (проверено по коду 2026-11-21):** `CONSENSUS_RULESET_VERSION = 6`, `DOMAIN_SET_VERSION = 3`, `FORK_ID = 0x0f584a46` (`stellereum/src/protocol.rs:101, 106, 226`), `COMMITMENT_VERSION = 5` (`stellereum/src/commitment.rs:100`), `EXPECTED_GENESIS_ROOT = "c07880e016dbb60dd84d9d1dd64bd141e4694d99ba919c288b9b08554f9373a5"` (`stellereum/tests/genesis_root_known_answer_tests.rs:62-63`).

> **Правило замороженного ядра (`AGENTS.md` §7).**
> Пока все эшелоны **R1 → R4** находятся в разработке, каждый консенсусный/gated-механизм вводится строго за compile-time константой `= u64::MAX` (`GatedOff`) с `#[cfg(any(test, debug_assertions))]` `thread_local!` override. Пока константы равны `u64::MAX`, `CONSENSUS_RULESET_VERSION == 6`, `DOMAIN_SET_VERSION == 3`, `FORK_ID == 0x0f584a46`, `COMMITMENT_VERSION == 5` и `genesis_root_known_answer_tests` остаются **побайтово неизменными**. Финальное включение Ruleset v7 выполняется **одним общим коммитом/эшелоном R5**.

---

## 0. Базовая линия W0 (уже в дереве на `W0-CONSOLIDATE-GATE`)

Чтобы волны **R1–R4** не дублировали уже принятые non-fork исправления, зафиксирован фактический срез текущего дерева:
- `stellereum/src/state_engine/parallel.rs:230-255`: фикс `auth.sponsor == tx.to` в `plan_plain_tx` **уже в дереве**.
- `stellereum/src/client_ip.rs:124, 463, 478, 524`: `canonical_ip` и `::ffff:127.0.0.1` **уже в дереве**.
- `stellereum/src/rpc/writes.rs:180, 244`: `"stell_mevStats"` **уже в дереве**.
- `stellereum/src/light_client.rs` + `stellereum/tests/light_client_tests.rs:1068`: `a_valid_quorum_certified_chain_may_revisit_an_earlier_state_root` (`A -> B -> A`) **уже в дереве**.
- `stellereum/src/contract.rs:1104-1164`: `CONTRACT_ENGINE` (`OnceLock`) + `CONTRACT_MODULE_CACHE` (`OPT-3`) **уже в дереве**.
- `stellereum/src/pmm.rs:54-67, 326-475` и `stellereum/src/tokenomics.rs:317, 345-353`: `PmmError::ZeroMint`/`ZeroPayout`, `*_checked`, `GenesisVault` `ZeroMint` **уже в дереве** (остаётся их консенсусное подключение в `svm.rs` за гейтом).
- `stellereum/src/snapshot_v4.rs:1-599`: кодек и валидатор `SnapV4` (`SnapshotManifestV1`, `DomainUnitId` `256..=270`) **уже в дереве** (требуется подключение в `storage.rs`, `sync.rs`, `network.rs`, `node/*`, расширение `DomainUnitId` для `PqRegistry` и `EvmBindings`).
- `stellereum/src/safety.rs`: `SafetyRecordPayload::decode_canonical` **уже в дереве** (подключение к `remote_signer.rs` v2 и `node/*` идёт в R3).

---

## 1. Единая таблица распределения дискриминантов, доменов, хранилища и гейтов

### 1.1 `OpCode` (`stellereum/src/svm.rs:500-1229`), `BridgeIntent` (`stellereum/src/bridge.rs:233-377`), `GovAction` (`stellereum/src/governance.rs:298-345`)

Все перечисленные enum сериализуются через `bincode` с `fixint` без имён полей и входят в подписываемые преимиджи (`svm.rs:610-613`, `bridge.rs:255-258, 2684-2739`, `governance.rs:314-317`). Новые варианты добавляются **строго в конец**.

#### А. `enum OpCode` (`stellereum/src/svm.rs:502-1229`)

| Дискриминант | Текущий / Новый вариант | Владелец (спека / эшелон) | Примечание (`file:line`) |
|---|---|---|---|
| `0..=32` | `Nop` (0) .. `SysCallBridge(Box<BridgeIntent>)` (32) | Существующие | `Halt = 26` (`svm.rs:609`), `SysCallBridge = 32` (`svm.rs:674`) |
| `33` | `Reserved33ConfidentialTransfer(ReservedOpcodeMarker) = 33` | Зарезервирован | `svm.rs:677` (отказ при декоде) |
| `34..=39` | `SysCallActorSend` (34) .. `SysCallTokenCreate` (39) | Существующие | `svm.rs:694-890` |
| `40..=42` | `Reserved40..42Confidential* = 40..=42` | Зарезервированы | `svm.rs:893-895` |
| `43..=58` | `SysCallRotateValidatorKey` (43) .. `SysCallBindEvmAddress` (58) | Существующие | `SysCallVerifyPqSignature = 46` (`:939`), `SysCallCallContractArgs = 50` (`:1055`), `SysCallSubmitPqPriceFeed = 55` (`:1158`), `SysCallEvmCarrier = 57` (`:1217`), `SysCallBindEvmAddress = 58` (`:1228`) |
| **`59`** | **`SysCallRegisterValidator(Box<RegisterValidatorPayload>)`** | **Спека #2 (W3) / R3** | Регистрация нового PQ-валидатора + выводного адреса (`07_PQ_VALIDATOR_LIFECYCLE_DRAFT.md §1.3`) |
| **`60`** | **`SysCallRotateVotingKey(Box<RotateVotingKeyPayload>)`** | **Спека #2 (W3) / R3** | PoP-подтверждённая ротация/отмена горячего Falcon-512 ключа (`§1.3, §2.1`) |
| **`61`** | **`SysCallChangeWithdrawal(Box<ChangeWithdrawalPayload>)`** | **Спека #2 (W3) / R3** | Смена `withdrawal_address` с PoP нового холодного адреса (`§1.3`) |
| **`62`** | **`SysCallClaimWithdrawal(Box<ClaimWithdrawalPayload>)`** | **Спека #2 (W3) / R3** | Одноразовая миграция pre-W3 валидаторов с `withdrawal_address == None` (`§4.2`) |
| **`63`** | **`SysCallAnnounceCommission { validator: [u8; 32], new_bps: u64 }`** | **Спека #2 (W3) / R3** | Объявление смены комиссии от `withdrawal_address` (`§1.3`) |
| **`64`** | **`SysCallApplyCommission { validator: [u8; 32] }`** | **Спека #2 (W3) / R3** | Применение созревшей смены комиссии при `block.height >= effective_height` (`§1.3`) |

> **Итого по `OpCode`:** спеки #1, #3, #4, #5, #6 не добавляют ни одного нового варианта `OpCode` (`0` пересечений). При `height >= PQ_LIFECYCLE_ACTIVATION_HEIGHT` старый `SysCallRotateValidatorKey` (`43`) ревертится в `svm.rs` (`07_PQ_VALIDATOR_LIFECYCLE_DRAFT.md §1.2`).

#### Б. `enum BridgeIntent` (`stellereum/src/bridge.rs:233-377`)

| Дискриминант | Вариант | Владелец (спека / эшелон) | Примечание (`file:line`) |
|---|---|---|---|
| `0..=7` | `Deposit` (0), `Withdraw` (1), `Attest` (2), `Release` (3), `DepositProof` (4), `Refund` (5), `Challenge` (6), `Resolve` (7) | Существующие | Зафиксировано тестом `deposit_proof_variant_keeps_legacy_discriminants_stable` (`bridge.rs:2684-2739`) |
| **`8`** | **`ReleaseProof { req_id: u64, receipt: Box<ReleaseReceiptEvidence> }`** | **Спека #1 (Bridge V2) / R4** | Единственный новый вариант `BridgeIntent`; `Release` (`3`) остаётся на месте и требует пары `ReleaseProof` (`8`) при `height >= BRIDGE_V2_ACTIVATION_HEIGHT` (`06_BRIDGE_RELEASE_AUTHORIZATION_DRAFT.md §2.1`) |

#### В. `enum GovAction` (`stellereum/src/governance.rs:298-345`) и `gov_action_tag` (`stellereum/src/commitment.rs:814-831`)

| Дискриминант / Tag | Вариант | Владелец (спека / эшелон) | Примечание (`file:line`) |
|---|---|---|---|
| `0..=12` | `SetMinValidatorBond` (0) .. `CancelUpgrade` (12) | Существующие | `governance.rs:299-344`, `commitment.rs:817-829` |
| **`13`** | **`SetFeeSplitBps { burn_bps: u64, proposer_bps: u64, staking_bps: u64 }`** *(опц. W4)* | **Спека #6 (W4-E1) / R4** | `burn_bps + proposer_bps + staking_bps == 10_000`; условное хеширование в `governance_digest` (`0B` пока `None`, как `min_gas_limit` на `commitment.rs:755-758`) |

---

### 1.2 `Domain` и условные преимиджи в `stellereum/src/commitment.rs`

Контракт `commitment_assembly_differential_tests.rs:227-290` фиксирует `Domain::ALL: [Domain; 13]` (`0..=12`) и массивы `[u64; 13]` / `[&[u8]; 13]`. Поэтому все новые домены подключаются по образцу `Domain::CnVrf` (`commitment.rs:137, 392, 439-450, 1937, 2066`):
1. `Domain::ALL: [Domain; 13]` **не расширяется** (остаётся `[Tokens..=Zkml]`).
2. Каждый новый домен получает выделенный `Option<DomainSlot>` в `DomainCache` (`commitment.rs:390-399`) + `AtomicU64` в `DomainGenerations` (`commitment.rs:196-211`) + `get_*_silent` / `put_*_silent` без поломки 13-элементного счётчика `hits`/`misses`.
3. **Абсолютное правило 0 байт (Conditional 0-byte invariant):** при пустом состоянии домен/поддомен пишет **0 байт** (даже без префикса длины), поэтому до активации (и на пустом генезисе) `COMMITMENT_VERSION = 5` и `EXPECTED_GENESIS_ROOT = "c07880e0..."` не сдвигаются ни на бит.

| Индекс / Слот | `Domain` / Подсекция | Владелец | Условие 0 байт (Empty → 0B) | Не-пустой преимидж & порядок |
|---|---|---|---|---|
| `0..=12` | `Tokens ..= Zkml` (`Domain::ALL`) | База | `SessionKeys`/`Bridge`/`CrossShard`/`Xpc`/`Zkml` -> 0B когда пусты | `commitment_digest_into` (`:1729-1781`) + `write_zkml_*` (`:1595-1664`) |
| *(внутри `Bridge`)* | `BRIDGE_V2_RELEASE_V1` (`release_receipts`, `processed_payout_txs`, `refunded_withdrawals`) | **Спека #1 / R4** | **0B** пока все 3 `BTree*`-поля пусты (сохраняет преимидж даже для не-пустого pre-V2 `BridgeState`!) | В конце `bridge_digest` (`commitment.rs:1564`): условный блок с тегом `b"BRIDGE_V2_RELEASE_V1"` и отсортированными циклами (`06 §2.2`) |
| *(внутри `Staking`)* | `STAKING_WITHDRAWAL_V1` | **Спека #2 / R3** | **0B** когда у всех `ValidatorStake` `withdrawal_address == None` | В конце `staking_digest` (`commitment.rs:1270`): `b"STAKING_WITHDRAWAL_V1"` + отсортированные `(validator_id, addr)` (`07 §2.3`) |
| *(внутри `Staking`)* | `STAKING_EMISSION_CARRY_V1` | **Спека #6 / R4** | **0B** когда `emission_carry_q64 == 0` | В конце `staking_digest`: `b"STAKING_EMISSION_CARRY_V1"` + `emission_carry_q64` (`W4 §2.3.4`) |
| *(внутри `Governance`)* | `gov_applied_fee_split` (и `GovAction` tag `13`) | **Спека #6 / R4** | **0B** когда `applied.fee_split_bps == None` (и нет tag `13` предложений) | После `upgrade_plan` (`commitment.rs:789`): `gov_applied_fee_split_present` + `(burn, proposer, staking)` (`W4 §2.2.2`) |
| `13` (`cnvrf_slot`) | `Domain::CnVrf` | Существующий | `CnVrfV3EngineSnapshot::is_empty()` (`state_engine/mod.rs:616`) -> **0B** | `write_cnvrf_v3_domain` (`commitment.rs:1937-2013`) |
| *(скаляр)* | `total_minted_nano` | Существующий | `total_minted_nano == 0` -> **0B** | `put_u64(h, b"total_minted_nano", total_minted_nano)` (`commitment.rs:2077-2079`) |
| **`14`** (`pq_registry_slot`) | **`Domain::PqRegistry`** | **Спека #2 / R3** | **`PqRegistry::is_empty()` -> 0B** | `write_pq_registry_domain`: `b"PQ_REGISTRY_V1"` + `BTreeMap<ValidatorId, PqKeyRecord>` (`scheme, pubkey, activated_at, next_seq, pending, history`) (`07 §2.3`) |
| **`15`** (`evm_bindings_slot`) | **`Domain::EvmBindings`** | **Спека #3 / R2** | **`EvmBindingsState::by_evm.is_empty()` -> 0B** | `write_evm_bindings_domain`: `b"EVM_BINDINGS_V1"` + отсортированные по `[u8; 20]` пары `(evm_addr, pq_addr)` (`LIGHT_CLIENT §4.1`) |

> **Единый порядок хвоста дайджеста** (идентичен в streaming `commitment_digest_*` и в cached `assemble_cached_digest_*` / `commit_consensus_domains_cached` в `state_engine/accounts.rs:620-928`):
> `Domain::ALL[0..=12]` → `Domain::CnVrf[13]` → `total_minted_nano (!= 0)` → `Domain::PqRegistry[14]` → `Domain::EvmBindings[15]`.

---

### 1.3 `DomainSnapshot`, `sled`-деревья в `storage.rs` и `SnapV4` (`snapshot_v4.rs`) — без коллизии версий

#### А. Деревья `sled` (`stellereum/src/storage.rs:11-25, 485-553, 891-910`)

Существующие 15 деревьев (`blocks`, `by_height`, `meta`, `state`, `domains`, `headers`, `session_keys`, `bridge`, `zkml_models`, `cross_shard`, `cnvrf_v3`, `xshard_headers`, `receipts_v1`, `receipts_by_height`, `pq_keys`) + изолированное `safety_record_v1` (`storage.rs:70`) **не переименовываются и не меняют формат записей**. Новые деревья строго аддитивны:

| Имя `sled::Tree` | Ключ → Значение | Тип / Прунинг | Владелец (спека / эшелон) |
|---|---|---|---|
| `"snap_units"` | `unit_hash(32B)` → raw `SnapV4` unit/chunk bytes | Контентно-адресуемое хранилище W1; `prune_deltas_below` | W1 `SnapV4` / **R2** |
| `"snap_manifests"` | `height(8B BE)` → `bincode(SnapshotManifestV1)` | W1 манифесты; `prune_deltas_below` | W1 `SnapV4` / **R2** |
| `"snap_committed"` | `height(8B BE)` → `bincode(SnapCommitMarker)` | W1 атомарный маркер коммита (`data-before-index`) | W1 `SnapV4` / **R2** |
| `"snap_staging"` | `(height(8B BE) \|\| unit_tag(2B) \|\| sub_index(2B))` → chunk | W1 резюмирование; чистится после коммита/краша | W1 `SnapV4` / **R2** |
| `"headers_v2"` | `height(8B BE)` → `bincode(BlockHeaderRecordV2)` | Консенсус-заголовок v4 (`BlockHeader`); `"headers"` не трогается | **Спека #3 / R2** |
| `"evm_bindings_state"` | `height(8B BE)` → `bincode(EvmBindingsSnapshot { by_evm })` | Root-committed домен; прунится в `prune_domains_below` с `aux_retained_heights()` | **Спека #3 / R2** |
| `"evm_bindings"` | `b"e:"\|\|evm(20) -> pq(32)`, `b"p:"\|\|pq(32) -> evm(20)`, `b"meta:cursor" -> u64 BE` | Не-консенсусный индекс; **никогда не прунится** `prune_blocks_below`/`prune_receipts_below` | **Спека #3 / R2** |
| `"pq_registry"` | `height(8B BE)` → `bincode(PqRegistry)` | Root-committed домен (отдельно от `"pq_keys"`); прунится в `prune_domains_below` с `aux_retained_heights()` | **Спека #2 / R3** |
| `"tx_by_addr"` | `addr(32) \|\| (!height)(8B BE) \|\| (!tx_index)(4B BE) -> tx_hash(32)` | Вторичный индекс истории; синхронно прунится в `prune_receipts_below` | **Спека #6 (W4-E3) / R4** |
| `"events_by_contract"` | `contract(32) \|\| (!height)(8B BE) \|\| (!tx_index)(4B BE) \|\| (!log_index)(4B BE) -> bincode(StoredContractEvent)` | Вторичный индекс событий; синхронно прунится в `prune_receipts_below` | **Спека #6 (W4-E3) / R4** |
| `"receipt_meta_v2"` | `tx_hash(32)` → `bincode(StoredReceiptMetaV2)` | Метаданные `from, to, amount, shard_id, timestamp`; `"receipts_v1"` (`StoredReceipt`) не трогается | **Спека #6 (W4-E3) / R4** |

> **Инвариант безопасности (`W1` §2.6):** `safety_record_v1`, `meta["consensus"]` (`ConsensusCheckpoint`) и `meta["vote_watermark"]` (`VoteWatermark`) **никогда** не экспортируются, не импортируются, не очищаются и не сбрасываются при `SnapV4`, `load_full_state_into` или `try_snapshot_sync`.

#### Б. Цепочка версий `DomainSnapshot`, `StakingLedger`, `BridgeState` и `SnapV4::DomainUnitId`

Чтобы три спеки (W1 `SnapV4`, W3 `ValidatorStake`, W4 `emission_carry_q64`) + Bridge V2 (`BridgeState`) не столкнулись в номерах структур:

1. **`BridgeState` (`stellereum/src/bridge.rs:1038-1204`, `state_engine/accounts.rs:2209-2246`):**
   - `BridgeStateV1` (pre-F-H), `BridgeStateV2` (pre-dispute) — уже есть.
   - **R4 (Спека #1):** вводит `BridgeStateV3` (точная копия текущего `BridgeState` до добавления `release_receipts`, `processed_payout_txs`, `refunded_withdrawals`). Порядок декода в `restore_bridge`: `BridgeState -> BridgeStateV3 -> BridgeStateV2 -> BridgeStateV1`.
2. **`StakingLedger` и `DomainSnapshot` (`stellereum/src/staking.rs:4341-4517`, `stellereum/src/storage.rs:2943-3661`):**
   - Текущие `DomainSnapshotV1..V8` и `StakingLedgerV1..V5` (`V1..V3` в `staking.rs`, `V4..V5` в `storage.rs`) используют текущий 7-польный `ValidatorStake`.
   - **R3 (Спека #2, W3):** добавляет `pub withdrawal_address: Option<[u8; 32]>` в `ValidatorStake` (`staking.rs:878-900`). Вводит `ValidatorStakeV1` (7 старых полей), переводит `StakingLedgerV1..V5` на `ValidatorStakeV1`, добавляет `StakingLedgerV6` (с `ValidatorStakeV1` и `recent_full_exits`) + `DomainSnapshotV9`.
   - **R4 (Спека #6, W4-E2):** добавляет `pub emission_carry_q64: u64` в `StakingLedger` (`staking.rs:1210-1399`). Вводит `StakingLedgerV7` (с новым `ValidatorStake` включая `withdrawal_address`, но без `emission_carry_q64`) + `DomainSnapshotV10`.
   - Порядок декода в `decode_domain_snapshot` (`storage.rs:3546-3623`):
     `DomainSnapshot -> DomainSnapshotV10 -> DomainSnapshotV9 -> DomainSnapshotV8 -> DomainSnapshotV4 -> DomainSnapshotV5 -> DomainSnapshotV6 -> DomainSnapshotV7 -> DomainSnapshotV3 -> DomainSnapshotV2 -> DomainSnapshotV1`.
   - `decode_domain_snapshot_strict` (`storage.rs:3647`) продолжает принимать **только** текущий `DomainSnapshot` (`reject_trailing_bytes`).
3. **`SnapV4::DomainUnitId` (`stellereum/src/snapshot_v4.rs:480-561`) и сетевой sync (`sync.rs:1275`, `network.rs:1142`, `lanes.rs:230`, `storage.rs:3985`):**
   - Текущие `256..=270` (`Scalars..=PqKeys`, `N_DOMAIN_UNITS = 15`) сохраняются.
   - **R2 (Спека #3 + W1):** добавляет `DomainUnitId::EvmBindings = 271` (либо резервирует `271 = PqRegistry`, `272 = EvmBindings` сразу в R2? **Решение без переделок:** в **R2** добавляется `EvmBindings = 271`, `N_DOMAIN_UNITS = 16`; в **R3** добавляется `PqRegistry = 272`, `N_DOMAIN_UNITS = 17` — пока живые снапшоты SnapV4 не зафиксированы до R5, либо `271 = EvmBindings`, `272 = PqRegistry` фиксируются в таблице один раз. Ниже в таблице зафиксированы **единые канонические теги**: `271 = EvmBindings` в R2, `272 = PqRegistry` в R3).
   - Соответственно обновляются: `SYNC_DOMAIN_KINDS` (`sync.rs:1275`), `SNAPSHOT_PUBLISH_DOMAIN_KINDS` (`network.rs:1142`), `SnapBundle` (`runtime/lanes.rs:230`), `PersistJob::Domains` (`storage.rs:3985`), `load_full_state_into` (`storage.rs:3772-3949` — установка `"evm_bindings_state"` и `"pq_registry"` строго **до** `verify_restored_root` на `:3900`).

---

### 1.4 Активационные гейты (`chain_spec.rs`) и единый `FORK_ID_RULES` (`protocol.rs`)

#### А. Таблица всех активационных гейтов в `stellereum/src/chain_spec.rs:255-311`

Существующие 8 зарегистрированных гейтов (`chain_spec.rs:261-309`):
`QC_SPLIT_ACTIVATION_HEIGHT`, `BEACON_DRAW_ACTIVATION_HEIGHT`, `CNVRF_V3_ACTIVATION_HEIGHT`, `COMPACT_GOSSIP_ACTIVATION_HEIGHT`, `EMISSIONCapEXACT_ACTIVATION_HEIGHT`, `PQ_TRANSPORT_H_ACTIVATION_HEIGHT`, `XPC_ACTIVATION_HEIGHT`, `UPGRADE_EXEC_ACTIVATION_HEIGHT` (+ `ZKML_CONTEXT_BINDING_ACTIVATION_HEIGHT` в `zkml_attestation.rs:149`).

Новые консенсусные гейты Ruleset v7 (в **R1–R4** каждый из них компилируется с `u64::MAX` = `GatedOff` и test/debug `thread_local!` override; в **R5** переводится на `0` при свежем генезисе v7 или целевую высоту `H` при обновлении цепи):

| Гейт-константа | Модуль-владелец | Назначение (спека) | Эшелон внедрения | Значение в R1–R4 | Значение в R5 (v7 genesis) |
|---|---|---|---|---|---|
| `EXEC_HARDENING_V1_ACTIVATION_HEIGHT` | `state_engine::apply` (re-export `chain_spec`) | `Halt`-барьер в пост-сканах, `CallContractArgs`/`SubmitPqPriceFeed` rollback, `TX_INTRINSIC_GAS`, CLOB `PlaceOrder`/`CancelOrder` газ (Спека #4 §1.3) | **R1** | `u64::MAX` | `0` (или `H`) |
| `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT` | `chain_spec` / `contract` / `svm` | `SubCallSnapshot`, `caller()` vs `origin()`, `outbound_messages` + `sync_contract_balance`, `deploy_with_nonce`, `validate_code`/`send_message` fuel, `PMM`/`GenesisVault` `ZeroMint`/`ZeroPayout`, `cross_shard_completed` guard, `PQ1` `decode_canonical` (Спека #5 §3) | **R1** | `u64::MAX` | `0` (или `H`) |
| `HEADER_COMMIT_ACTIVATION_HEIGHT` | `sharding::block` | Двухуровневый `BlockHeader` + `body_commitment` (`"STELLEREUM_BLOCK_V4"`), обязательный hash-check в `Checkpoint`/`LightHeader`/`HeaderLink`/`HistoricalRoot` (Спека #3 §2) | **R2** | `u64::MAX` | `0` (или `H`) |
| `EVM_BINDINGS_STATE_ACTIVATION_HEIGHT` | `state_engine` | Канонический домен `Domain::EvmBindings` + first-writer-wins в `apply()` (Спека #3 §4.1) | **R2** | `u64::MAX` | `0` (или `H`) |
| `PQ_LIFECYCLE_ACTIVATION_HEIGHT` | `chain_spec` / `pq_registry` | 3-key separation (`withdrawal_address`), `OpCode` `59..=64`, отказ `SysCallRotateValidatorKey` (`43`), height-indexed `PqRegistry` + PoP, игнор `STELL_PEER_PQ_KEYS` (Спека #2 §4.1) | **R3** | `u64::MAX` | `0` (или `H`) |
| `BRIDGE_V2_ACTIVATION_HEIGHT` | `bridge` | `StoredHeader::signing_message_v2` (отказ V1), запрет голого `Release` (только с `ReleaseProof`), `Challenge` на `DepositProof`, `RETRACTION` precedence в `Resolve`, обязательный `PqKeyLookup` (Спека #1 §1.3) | **R4** | `u64::MAX` | `0` (или `H`) |
| `FEE_MARKET_V2_ACTIVATION_HEIGHT` | `state_engine::apply` | Списание `priority_fee_per_gas` в `fee_for_gas`/`failure_fee_for`/`plan_plain_tx` + burn/proposer/staking split (Спека #6 §2.2.2) | **R4** | `u64::MAX` | `0` (или `H`) |
| `SUB_NANO_STRICT_ACTIVATION_HEIGHT` | `evm_adapter` / `staking` | `wei_to_nano_exact` в `svm.rs`/`evm_transfer_facts`, rescale carry в `ValidatorRewardState::accrue`, Q0.64 emission carry (Спека #6 §2.3) | **R4** | `u64::MAX` | `0` (или `H`) |

> **Замечание по тестам `chain_spec.rs`:** `current_activation_schedule_matches_module_constants` (`chain_spec.rs:402-456`) проверяет точный массив `expected` и `schedule.gates.len()`. Поэтому регистрацию каждого нового гейта в `current_activation_schedule()` и в `tests::current_activation_schedule_matches_module_constants` выполняет тот эшелон, который добавляет константу (один владелец `chain_spec.rs` за эшелон!), пока в R5 не будет зафиксирован итоговый набор v7.

#### Б. Единый `FORK_ID_RULES` и `derive_fork_id` в `stellereum/src/protocol.rs:101-230` (только в эшелоне R5)

В **R1–R4** `protocol.rs` **НЕ изменяется** (`CONSENSUS_RULESET_VERSION = 6`, `DOMAIN_SET_VERSION = 3`, `FORK_ID = 0x0f584a46`, 23 правила в `FORK_ID_RULES`).
В **R5** одним атомарным коммитом:
1. Повысить `CONSENSUS_RULESET_VERSION: u32 = 7` (`protocol.rs:101`) и `DOMAIN_SET_VERSION: u32 = 4` (`protocol.rs:106`).
2. Сохранить первые 23 элемента `FORK_ID_RULES` (`protocol.rs:152-174`) в прежнем порядке и **дописать в конец** (`[23..]`):
   - `crate::pq_registry::PQ_EVIDENCE_RETENTION_HEIGHTS` (`720_000`)
   - `crate::state_engine::EXEC_HARDENING_V1_ACTIVATION_HEIGHT`
   - `crate::chain_spec::WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT`
   - `crate::sharding::HEADER_COMMIT_ACTIVATION_HEIGHT`
   - `crate::state_engine::EVM_BINDINGS_STATE_ACTIVATION_HEIGHT`
   - `crate::chain_spec::PQ_LIFECYCLE_ACTIVATION_HEIGHT`
   - `crate::bridge::BRIDGE_V2_ACTIVATION_HEIGHT`
   - `crate::state_engine::FEE_MARKET_V2_ACTIVATION_HEIGHT`
   - `crate::chain_spec::SUB_NANO_STRICT_ACTIVATION_HEIGHT`
3. В `derive_fork_id` (`protocol.rs:199-219`) вмешать новые консенсусные строки разделения доменов:
   - `b"STELLEREUM_BODY_V4\0"` и `b"STELLEREUM_HDR_V4\0"` (`sharding/block.rs`)
   - `crate::pq_registry::PQ_KEY_POP_DST` (`b"STELL_PQ_KEY_POP_V1"`), `b"STELL_WITHDRAWAL_POP_V1"`, `b"STELL_CLAIM_WITHDRAWAL_V1"`, `b"STELL_VAL_ID_V1"`
   - `crate::bridge::bridge_adapters::BRIDGE_HEADER_SIGN_DOMAIN_V2` (`b"STELL_BRIDGE_HEADER_V2"`), `crate::bridge::BRIDGE_RELEASE_RECEIPT_DOMAIN_V2` (`b"STELL_BRIDGE_RELEASE_RECEIPT_V2"`)
4. Пересчитать и зафиксировать новый `FORK_ID` в `docs/RULESET_V7.md`, `stellereum/tests/protocol_negotiation_tests.rs` и `stellereum-sdk`.

---

## 2. Последовательный план кодовых волн (Эшелоны R1 → R5)

На каждом эшелоне **ровно одна** тяжёлая Rust-волна модифицирует горячие общие файлы (`apply.rs`, `svm.rs`, `parallel.rs`, `storage.rs`, `commitment.rs`, `chain_spec.rs`, `protocol.rs`). Ни один файл не редактируется двумя параллельными воркерами внутри эшелона.

### Эшелон R1 — Execution Atomicity, Halt-Prefix, Gas & WASM/XShard/PMM/Envelope Hardening
*(Объединяет Спеки #4 и #5, так как обе модифицируют `apply.rs`, `svm.rs`, `contract.rs`.)*

| Воркер | Исключительное владение файлами | Точный объём изменений (`file:line`) |
|---|---|---|
| **R1-A (`WASM-Core`)** | `contract.rs`, `rpc/contracts.rs`, `state_engine/contracts.rs` | `SubCallSnapshot` и per-subcall откат storage/balance/events/outbound (`contract.rs:768-807, 1098-1180`); `ContractCallContext { origin, caller }` (`:136-142`) + `host.origin` (за гейтом); `validate_code` `store.set_fuel` (`:476-481`); `host.calldata` charge-before-clone (`:1285-1288`); `host.send_message` per-byte fuel (`:1421`); `deploy_with_nonce(tx.nonce)` при `>= H` (`:541-576`) и консистентность `rpc/contracts.rs:768, 864`; откат `value` при провале в `call_contract_structured_with_value` (`state_engine/contracts.rs:377-443`). |
| **R1-B (`XShard-PQ-Opt`)** | `state_engine/xshard.rs`, `xshard2pc.rs`, `cn_vrf.rs`, `sharding/envelope.rs`, `sharding/transaction.rs`, `post_quantum.rs` | `cross_shard_completed` guard в `Prepare`/`AbortRequest` (`xshard.rs:1070-1084, 1194-1213`, за гейтом); `return true` в `PrepareAck` refresh (`:1121`); `compute_tx_hashes_batched` `O(M+N)` (`:844, 916`, `transaction.rs:893`); `epoch_start_height` `saturating_mul` (`cn_vrf.rs:607, 1774`); `PqSignatureEnvelope::decode_canonical` (`envelope.rs:263-355`) + однократный `split_sponsor_envelope` (`transaction.rs:794-1354`); `h_ntt` в `FALCON_PUBKEY_CACHE` + удаление дубля padding check (`post_quantum.rs:2117-2233`). |
| **R1-C (`Mempool-RPC-Parallel`)** | `mempool.rs`, `state_engine/parallel.rs`, `state_engine/accounts.rs`, `rpc/{mod,auth,reads,streams,cache}.rs` | `PendingActivationBuffer` изоляция `activation_reserved` + TTL/nonce-gap, рекурсивный `estimate_tx_wire_bytes`, `tx_cost` с `surcharges_for_tx` в `evict_unexecutable_at`/`sweep_expired` + `meta` кэш (`mempool.rs`); `PlainTxPlan` inline `[;3]` + `clone_for_simulation_for_payload` (`parallel.rs`, `accounts.rs`); оставшиеся non-fork оптимизации из Спеки #4 §2 (`ReceiptIndex`, `SubscriptionHub`, `FinalizedReadCache`, `simulate_and_estimate_fee`). *(Только если какая-то из этих локальных оптимизаций ещё не вошла в W0.)* |
| **R1-D (`Frozen-Apply-SVM` — после A/B)** | `svm.rs`, `orderbook.rs`, `state_engine/apply.rs`, `state_engine/types.rs`, `chain_spec.rs` | Единый владелец `apply.rs` + `svm.rs`: `OpCode::Halt` барьер в `bridge_intents` (`apply.rs:763-770`), `rotation_aliases` (`:2920-2937`), `apply_cnvrf_v3` (`:3026-3040`), `apply_staking_unjail_ops` (`:3903`), `apply_equivocation_slash` (`:4193`); `SysCallCallContractArgs` + `SysCallSubmitPqPriceFeed` в `snapshot_payload_domains` (`:186-220`) и `oracle_before` (`:550-556`); `billed_gas` `>= TX_INTRINSIC_GAS` (`:1704`) за гейтом; `MAX_MATCH_FILLS_PER_ORDER` + реальный fill-газ и read-only owner check в `PlaceOrder`/`CancelOrder` (`svm.rs:1635-1770`, `orderbook.rs:248-275`); перенос `process_contract_outbound_messages` после `commit_native` + `sync_contract_balance` + bounce-guard (`apply.rs:1010-1015, 3691`, `svm.rs:3441`); проброс `caller`/`origin` + `tx.nonce` в `svm.rs:2030-2175`; PMM CEI + `ZeroMint`/`ZeroPayout` в `svm.rs:2700-2818`; `decode_canonical` при `>= H`; регистрация `EXEC_HARDENING_V1_ACTIVATION_HEIGHT` и `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT` (`u64::MAX`) в `chain_spec.rs`. |

*Обязательные parity-тесты R1:*
- `parallel_exec == sequential` (`apply_block_parallel_fees_with_events_at_height` с `true`/`false` и `apply_transaction == block_apply`).
- Граница `H - 1 / H / H + 1` (через `thread_local!` override): post-`Halt` `SysCallBridge`/`Rotate`, `CallContractArgs`/`SubmitPqPriceFeed` rollback, `[Nop]` = `280_000`, `PlaceOrder` >64 makers, `CancelOrder` без преждевременного clone, `SubCallSnapshot`, `caller != origin`, `outbound_messages` rollback при failed CLOB/commit, bounce не печатает монеты, `deploy_with_nonce`, `decode_canonical` отказ на `salt||key`, `ZeroMint`/`ZeroPayout`.
- При гейтах `= u64::MAX`: `COMMITMENT_VERSION == 5`, `EXPECTED_GENESIS_ROOT == "c07880e0..."`, `FORK_ID == 0x0f584a46`, и `bonding_moves_real_funds_and_grants_validator_power` (`gas_limit = 10_000`) без изменений.

---

### Эшелон R2 — Light Client Header Commitment (`BlockHeader` v4), `Domain::EvmBindings` и `SnapV4` Storage/Sync
*(Объединяет Спеку #3 и интеграцию W1 `SnapV4` в `storage.rs`/`sync.rs`/`network.rs`; `StakingLedger` и `OpCode` ещё не трогаются.)*

| Воркер | Исключительное владение файлами | Точный объём изменений (`file:line`) |
|---|---|---|
| **R2-A (`Header-Core`)** | `sharding/block.rs`, `sharding/mod.rs` | `BlockHeader`, `Block::body_commitment()` (`b"STELLEREUM_BODY_V4\0"`), `BlockHeader::compute_hash()` (`b"STELLEREUM_HDR_V4\0"`), `HEADER_COMMIT_ACTIVATION_HEIGHT = u64::MAX` + `thread_local!` override; побайтовый v3 `"STELLEREUM_BLOCK_V3"` на `< H` (`sharding/block.rs:953-1107`). |
| **R2-B (`EvmBindings-Core`)** | `commitment.rs`, `state_engine/{mod,types,accounts,apply,settlement}.rs`, `evm_adapter/binding.rs`, `chain_spec.rs` | `Domain::EvmBindings` (`slot 15`, 0B при пустом, `Domain::ALL` остаётся `[Domain; 13]`), `EvmBindingsState` (`by_evm` + `#[serde(skip)] by_pq`), `EVM_BINDINGS_STATE_ACTIVATION_HEIGHT = u64::MAX`; first-writer-wins в `apply_block_transition` step `1a-TER` (`apply.rs:2725-2733`) + `apply_transaction`; изоляция в `clone_for_simulation`; регистрация `HEADER_COMMIT_ACTIVATION_HEIGHT` и `EVM_BINDINGS_STATE_ACTIVATION_HEIGHT` в `chain_spec.rs`. |
| **R2-C (`LightClient-CLI` — после R2-A)** | `light_client.rs`, `light_client_cli.rs`, `cli/{args,handlers}.rs` | Верификация `BlockHeader::compute_hash() == claimed_block_hash` в `Checkpoint`, `LightHeader`, `from_historical_root_json` при `>= H`; проверка `answer.address == opts.verify`, `header.height == proof_height + 1` (`checked_add`), `--min-height` в `light_client_cli.rs`. |
| **R2-D (`Storage-SnapV4-Sync` — после R2-A и R2-B)** | `storage.rs`, `snapshot_v4.rs`, `sync.rs`, `network.rs`, `snapshot_cadence.rs`, `bootstrap.rs` | Единый владелец `storage.rs` + `sync.rs`: (1) деревья `"headers_v2"` (`BlockHeaderRecordV2`), `"evm_bindings_state"`, `"evm_bindings"` (не-консенсусный crash-safe индекс, не прунится), плюс `"snap_units"`, `"snap_manifests"`, `"snap_committed"`, `"snap_staging"` (`W1`); (2) `HistoricalRoot` v4 поля + fail-closed `Storage::historical_root` на `>= H`; (3) `DomainUnitId::EvmBindings = 271` (`N_DOMAIN_UNITS = 16`) в `snapshot_v4.rs`; (4) `HeaderLink` + `verify_finality_for_header_with_schedule` hash-binding в `sync.rs`, `"evm_bindings"` + `"pq_keys"` в `SYNC_DOMAIN_KINDS` (`:1275`) и `SNAPSHOT_PUBLISH_DOMAIN_KINDS` (`network.rs:1142`), интеграция `SnapV4` (`fast_sync_incremental`, лимиты `fetch_snapshot_manifest` / `fetch_large_blob_resumable`, барьер неприкосновенности `safety_record_v1` / `ConsensusCheckpoint` / `VoteWatermark`). |
| **R2-E (`Runtime-RPC-Node` — после R2-D)** | `runtime/{lanes,apply,anchors,consensus_step}.rs`, `node/{sync,consensus_driver,bootstrap}.rs`, `rpc/{state,reads,eth}.rs` | Потоковый `hydrate_rpc_from_store` (`O(1)` RAM, без `Vec<Block>` на 50k и без `clear_evm_bindings()`); `evm_bindings` в `SnapBundle`/`PersistJob`; v4-поля заголовка в `FinalizedHeaderRecord`, `stell_getFinalizedHeader`, `stell_getFinalizedCheckpoint`, `stell_getHistoricalRoot`, `anchor_fetch`; `try_snapshot_sync` переход на `SnapV4` + проверка safety-пола `VoteWatermark`/`SafetyRecordStore`. |

*Обязательные parity-тесты R2:*
- `parallel == sequential` с `SysCallBindEvmAddress` + `SysCallEvmCarrier` в одном блоке (first-writer-wins детерминирован).
- `H - 1 / H / H + 1`: `compute_hash()` на `H - 1` равен v3; на `H`/`H + 1` изменение любого из 15 полей меняет `compute_hash()`, изменение `validator_signatures`/`precommit_qc` не меняет; `Checkpoint`/`LightHeader`/`HeaderLink`/`stell_getHistoricalRoot` с подменённым `state_root` или `prev_hash` при валидном QC отклоняются на `>= H`.
- `COMMITMENT_VERSION == 5` и `genesis_root_known_answer_tests` не сдвинуты (при пустом `EvmBindingsState` и при `u64::MAX`).
- `commitment_assembly_differential_tests` (`Domain::ALL` `[u64; 13]`) + `evm_bindings_survive_50k_blocks_prune_and_restart_without_oom` + W1 `safety_record_v1_untouched` / `corrupted_delta_rejected`.

---

### Эшелон R3 — PQ Validator Lifecycle, Key Separation и Remote Signer v2 (`07_PQ_VALIDATOR_LIFECYCLE_DRAFT.md`, W3)
*(Готовит обязательный `BF-0` фундамент `PqRegistry` на `InMemoryStateEngine` для R4 Bridge V2 и вводит `OpCode` `59..=64`.)*

| Воркер | Исключительное владение файлами | Точный объём изменений (`file:line`) |
|---|---|---|
| **R3-A (`Registry-Signer`)** | `pq_registry.rs`, `remote_signer.rs`, `chain_spec.rs` | `PQ_KEY_POP_DST`, `PQ_EVIDENCE_RETENTION_HEIGHTS = 720_000`, `PQ_KEY_HISTORY_MAX_COUNT = 32`, `PqKeyRecord::next_seq`, `checked_add` вместо `saturating_add`, явный `cancel_rotation` до `effective_height`, отказ дубликатов/своих ключей, удаление Ed25519 stub (`pq_registry.rs:587-623`); перевод `remote_signer.rs` на Falcon-512 (`897B`/`666B`), `/v2/public_key`, `/v2/sign`, `ConsensusSignRequest` anti-oracle проверка, без Ed25519 и без локального fallback; регистрация `PQ_LIFECYCLE_ACTIVATION_HEIGHT` (`u64::MAX`) в `chain_spec.rs`. |
| **R3-B (`Staking-Commit` — после R3-A)** | `staking.rs`, `commitment.rs` | `ValidatorStake::withdrawal_address: Option<[u8; 32]>` (`staking.rs:878-900`); `pq_apply_due_rotations`, `slash_pq_equivocation_at_height` с `pq_active_key(&pq_registry, &voter, height)`; `Domain::PqRegistry` (`slot 14`, 0B при пустом) + `STAKING_WITHDRAWAL_V1` в `staking_digest` (`commitment.rs`). |
| **R3-C (`Storage-SnapV4` — после R3-B)** | `storage.rs`, `snapshot_v4.rs` | Аддитивное дерево `"pq_registry"` (`height -> bincode(PqRegistry)`) + `prune_pq_registry_below` в `prune_domains_below`; `ValidatorStakeV1` + `StakingLedgerV1..V5` перевод на `ValidatorStakeV1` + `StakingLedgerV6` + `DomainSnapshotV9` в `decode_domain_snapshot`; загрузка `"pq_registry"` в `load_full_state_into` до `verify_restored_root`; `DomainUnitId::PqRegistry = 272` (`N_DOMAIN_UNITS = 17`) в `snapshot_v4.rs`. |
| **R3-D (`VM-Engine-Apply` — после R3-C)** | `svm.rs`, `mempool.rs`, `state_engine/{mod,apply,accounts,types}.rs` | `OpCode` `59..=64` (`SysCallRegisterValidator`..`SysCallApplyCommission`), авторизация `withdrawal_address` для 7 ops, запрет `SysCallRotateValidatorKey` (`43`) на `>= H`; `InMemoryStateEngine::pq_registry` + `pq_registry_read/write`; в `apply_block_transition`: Step 0 `apply_due_pq_rotations(block.height)`, Step 5f `apply_pq_registry_ops(block, &status)` (остановка на `OpCode::Halt`), одноразовый adoption pass при переходе на `H`, `consensus::sync_committed_pq_registry`; `apply.rs:3061` переход на `pq_key_at_height` перед `validator_pq_keys`; `"pq_registry"` в `PersistJob::Domains`. |
| **R3-E (`Consensus-Readers` — после R3-C, параллельно с R3-D)** | `consensus/rotation.rs`, `light_client.rs`, `sync.rs`, `network.rs` | `sync_committed_pq_registry` (очистка `PQ_VALIDATOR_KEYS` post-W3 + `clear_verified_vote_cache`); `light_client.rs:701` перевод на height-aware `pq_key_at_height`; `"pq_registry"` в `SYNC_DOMAIN_KINDS` и `SNAPSHOT_PUBLISH_DOMAIN_KINDS`. |
| **R3-F (`Runtime-Node-RPC-CLI` — после R3-D/E)** | `runtime/{anchors,consensus_step,mev_sync,lanes}.rs`, `node/{bootstrap,consensus_driver,sync}.rs`, `rpc/{state,reads}.rs`, `cli/{args,tx_builders}.rs` | Единый `Arc<dyn PqSigner>` + `SafetyRecordStore` check-persist-then-sign (удаление `falcon_key` split и запрет локального фоллбека при `STELL_REMOTE_SIGNER_URL`); `pq_registry` в `SnapBundle`; игнор `STELL_PEER_PQ_KEYS` с `WARN` при `>= H`; удаление `pq_registry_handle()` из `rpc/state.rs` → чтение из `st.engine.pq_registry_read()`; CLI-билдеры для `59..=64`. |

*Обязательные parity-тесты R3:*
- `parallel == sequential` на смешанных блоках со staking/lifecycle опкодами `59..=64`.
- `H - 1 / H / H + 1` для `PQ_LIFECYCLE_ACTIVATION_HEIGHT` и границы ротации `E - 1 / E / E + 1`: старый ключ принимается на `E - 1` и отвергается на `E`; новый ключ отвергается на `E - 1` и принимается на `E`; 5 ротаций внутри `720_000` блоков позволяют `slash_pq_equivocation_at_height` на 1-й ключ; > `720_000` блоков отвергаются fail-closed.
- `DomainSnapshotV8` декодируется через `DomainSnapshotV9` с `withdrawal_address == None`, `decode_domain_snapshot_strict` отказывает legacy; потеря `"pq_registry"` при непустом домене проваливает `verify_restored_root`.
- `COMMITMENT_VERSION == 5` и `genesis_root_known_answer_tests` неизменны при пустом `PqRegistry` / `withdrawal_address == None`.

---

### Эшелон R4 — Bridge V2 Release Authorization + W4 Economics & Product (`06_BRIDGE_RELEASE_AUTHORIZATION_DRAFT.md` + `W4_ECONOMICS_PRODUCT_CONTRACT.md`)
*(Выполняется в две последовательные фазы внутри R4: **R4.1** непересекающиеся домены/индексы → **R4.2** единая интеграция `commitment.rs` + `apply.rs`/`parallel.rs`/`svm.rs`, чтобы в каждом горячем файле был ровно один владелец.)*

#### Фаза R4.1 — Непересекающиеся ядра Bridge V2 и W4
| Воркер | Исключительное владение файлами | Точный объём изменений (`file:line`) |
|---|---|---|
| **R4.1-Bridge** | `bridge.rs`, `bridge_adapters.rs`, `native_api.rs`, `examples/vuln_hunt5.rs` | `BRIDGE_V2_ACTIVATION_HEIGHT = u64::MAX` + override; `PqKeyLookup` (удаление `get_validator_pq_key` из `bridge.rs:618`); `BridgeIntent::ReleaseProof` (`8`), `ReleaseReceiptEvidence`, `BRIDGE_RELEASE_RECEIPT_DOMAIN_V2`, `PAYOUT_SAFETY_MARGIN_SECS`; `BridgeState` + `BridgeStateV3`, `plan_at_height` (отказ голого `Release`, `Challenge` на `DepositProof`, `RETRACTION` precedence в `Resolve`, cap `<= 1024` на `Attest`); `StoredHeader::signing_message_v2`, `AdapterKindTag`, `check_header_at_height` (отказ V1 на `>= H`), strict EVM pinning (`bridge_adapters.rs:162`); фикс `examples/vuln_hunt5.rs:690-702` на Falcon-512 + `MultisigRelayer::release_signing_message`. |
| **R4.1-W4-E2** | `evm_adapter/{types,binding,tx,adapter}.rs`, `tokenomics.rs`, `staking.rs`, `governance.rs` | `wei_to_nano_exact` + integer `eth_feeHistory` (`evm_adapter/*`); 256-bit `mul_div_floor_256` в `GenesisVault::calculate_mint` + `pow_half_fixed_exact_q64` (`tokenomics.rs`); `ValidatorRewardState::accrue` rescale carry при смене `delegated`, `distribute_reward_at_height`, `distribute_fee_reward` (без роста `rewards_minted`), `emission_carry_q64` (`staking.rs`); опц. `GovAction::SetFeeSplitBps` (`13`) (`governance.rs`). |
| **R4.1-W4-History** | `storage.rs`, `token.rs`, `contract.rs`, `rpc/{reads,cache}.rs`, `stellereum-indexer/src/{db,syncer,server,events}.rs` | Деревья `"tx_by_addr"`, `"events_by_contract"`, `"receipt_meta_v2"` + прунинг с `prune_receipts_below`; `StakingLedgerV7` + `DomainSnapshotV10` (если `emission_carry_q64` на `StakingLedger`); детерминированная курсорная пагинация `stell_listTokens`, `stell_getAddressHistory`, `stell_getProgramAccounts`, `stell_getTokenAccountsByOwner`, `stell_getEvents`; апгрейд SQLite/SSE/REST в `stellereum-indexer` (включая `token_balances`, `contracts`). |
| **R4.1-W4-Geyser** | `rpc/{streams,state}.rs`, `node/consensus_driver.rs` | Фикс `self.engine.shard_id()` в `record_block` (`rpc/state.rs:468`); `seq` + `GEYSER_REPLAY_WINDOW = 512` + `after_seq` + `lagged`-фреймы + топики `AccountUpdates` / `TokenTransfers` (`rpc/streams.rs`); регистрация новых RPC-методов R4.1 в `rpc_rate_buckets` и `is_ws_expensive_method`. |

#### Фаза R4.2 — Единая интеграция горячих файлов (строго после R4.1)
| Воркер | Исключительное владение файлами | Точный объём изменений (`file:line`) |
|---|---|---|
| **R4.2-Commit** | `commitment.rs`, `chain_spec.rs` | В `commitment.rs`: `BRIDGE_V2_RELEASE_V1` в `bridge_digest`, `STAKING_EMISSION_CARRY_V1` в `staking_digest`, опц. `SetFeeSplitBps` (`13`) в `governance_digest` (все условно: `0B` при пустых/нулевых значениях). В `chain_spec.rs`: регистрация `BRIDGE_V2_ACTIVATION_HEIGHT`, `FEE_MARKET_V2_ACTIVATION_HEIGHT`, `SUB_NANO_STRICT_ACTIVATION_HEIGHT` (`u64::MAX`). |
| **R4.2-Engine** | `state_engine/{apply,parallel,settlement,accounts,types}.rs`, `svm.rs`, `mempool.rs`, `runtime/{mev_sync,consensus_step}.rs`, `cli/{args,tx_builders}.rs` | Единая проходка по `apply.rs`/`parallel.rs`/`svm.rs`: (1) Bridge V2: проброс `(block.height, self.chain_id, (&*staking, &*pq_registry))` из `apply_block_parallel_fees_with_events_at_height` -> `execute_payload_with_preverify_at_height` -> `settle_bridge_native` -> `BridgeState::plan_at_height`; `BridgeStateV3` в `accounts.rs::restore_bridge`; `ReleaseProof` CLI-билдер; (2) W4 Fee Market v2: `FEE_MARKET_V2_ACTIVATION_HEIGHT` в `fee_for_gas`/`failure_fee_for`/`plan_plain_tx` (`priority_fee_per_gas` списание с parity `parallel == sequential`) + burn/proposer/staking split в `apply_block_transition` через `credit_native_transfer` и `distribute_fee_reward` (сохранение 1B supply cap); `MP04` fee-density ordering в `mempool.rs` + `mev_sync.rs`/`consensus_step.rs`; (3) W4 Sub-Nano: `SUB_NANO_STRICT_ACTIVATION_HEIGHT` для `wei_to_nano_exact` в `svm.rs` и `distribute_reward_at_height` в `apply_block_transition`. |

*Обязательные parity-тесты R4:*
- `parallel == sequential` на `FEE_MARKET_V2` (`priority_fee_per_gas > 0`, burn+proposer+staking == `fees` до 1 nano, сгоревшие комиссии не возвращают headroom в `total_minted_nano`).
- `H - 1 / H / H + 1` для `BRIDGE_V2_ACTIVATION_HEIGHT`, `FEE_MARKET_V2_ACTIVATION_HEIGHT`, `SUB_NANO_STRICT_ACTIVATION_HEIGHT`:
  - `bridge_authorization_p0_regression.rs` зелёный без изменений; на `>= H` голый `Release` отвергается, V1 заголовок отвергается, cross-adapter/cross-chain подписи отвергаются, `Challenge` на `DepositProof` работает (`bridge_dispute_tests.rs:709` разделён на `H - 1` и `H`), `RETRACTION` побеждает повтор `DepositProof`;
  - `1_500_000_000` wei (1.5 nano) отклоняется на `>= H` и принимается на `H - 1`.
- При гейтах `= u64::MAX`: `COMMITMENT_VERSION == 5`, `EXPECTED_GENESIS_ROOT == "c07880e0..."`, `FORK_ID == 0x0f584a46` неизменны.

---

### Эшелон R5 — Финальная активация Ruleset v7 и Frozen-Core Gate (`AGENTS.md` §4, §7)

| Воркер | Исключительное владение файлами | Точный объём изменений |
|---|---|---|
| **R5-Fork-Release** | `stellereum/src/protocol.rs`, `stellereum/src/chain_spec.rs`, `stellereum/src/state_engine/apply.rs` *(только константа если вынесена туда)*, `stellereum/src/sharding/block.rs` *(константа)*, `stellereum/src/bridge.rs` *(константа)*, `docs/RULESET_V7.md` *(new)*, `stellereum/tests/protocol_negotiation_tests.rs`, `stellereum-sdk/**` | (1) Переключение всех выбранных гейтов Ruleset v7 с `u64::MAX` на `0` (свежий генезис v7) либо целевую высоту хардфорка `H`; (2) `CONSENSUS_RULESET_VERSION = 7`, `DOMAIN_SET_VERSION = 4`, добавление правил и доменных строк в `FORK_ID_RULES` / `derive_fork_id` (`protocol.rs`); (3) фиксация нового `FORK_ID` в `docs/RULESET_V7.md`, `protocol_negotiation_tests.rs` и SDK; (4) прогон полного гейта. |

*Обязательные parity-тесты и гейт приёмки R5 (`AGENTS.md` §4, §7):*
1. Смешанный handshake v6 (`0x0f584a46`) vs v7 (`FORK_ID_v7`) громко отказывает в `protocol::negotiate`.
2. Обновление test-пинов `H - 1 / H / H + 1` (для всех тестов, ожидавших legacy-поведение на высоте 0 при `u64::MAX`, — явные регресс-тесты используют `thread_local!` override на `H > 0`, либо обновлены под Ruleset v7 с audit note).
3. Полный прогон:
   - `cargo clippy --all-targets -- -D warnings` (включая `--examples` и `vuln_hunt5.rs`) → 0 warnings, 0 errors;
   - `cargo test --no-fail-fast` по всему workspace → green;
   - `consensus_liveness_harness` → green;
   - `./scripts/verify_testnet_ideal.sh` → green.

---

## 3. Сводная матрица владения горячими файлами по эшелонам

| Общий файл | R1 | R2 | R3 | R4 | R5 |
|---|---|---|---|---|---|
| `state_engine/apply.rs` | **R1-D** | **R2-B** *(только `1a-TER`)* | **R3-D** *(Step 0/5f)* | **R4.2-Engine** | — *(только const при необходимости)* |
| `svm.rs` | **R1-D** | — | **R3-D** *(`59..=64`)* | **R4.2-Engine** *(Bridge/W4)* | — |
| `state_engine/parallel.rs` | **R1-C** | — | — | **R4.2-Engine** | — |
| `commitment.rs` | — | **R2-B** *(`EvmBindings`)* | **R3-B** *(`PqRegistry`)* | **R4.2-Commit** *(`BridgeV2`/W4)* | — |
| `storage.rs` | — | **R2-D** *(`SnapV4`, `headers_v2`, `evm_bindings*`)* | **R3-C** *(`pq_registry`, `SnapV9`)* | **R4.1-W4-History** *(`tx_by_addr`, `events_by_contract`, `receipt_meta_v2`, `SnapV10`)* | — |
| `chain_spec.rs` | **R1-D** | **R2-B** | **R3-A** | **R4.2-Commit** | **R5-Fork-Release** |
| `protocol.rs` | **frozen** | **frozen** | **frozen** | **frozen** | **R5-Fork-Release** |
