# WASM-PMM-XSHARD Hardening Contract (`AUDIT-REMAINING-SUBSYSTEMS`, code truth)

Статус: **архитектурный контракт интеграции (WASM / SVM / PMM / Tokenomics / Cross-Shard 2PC / CN-VRF / PQ Envelope / Hot-Path Opts)** для кодовых агентов.
Зафиксировано по фактическому чтению дерева `stellereum/` (2026-11-21, `CONSENSUS_RULESET_VERSION = 6`, `FORK_ID = 0x0f584a46`, `TOTAL_SUPPLY_CAP = 1_000_000_000 * 10^9` nano-STELL).

> **Правило замороженного ядра (`AGENTS.md` §7).** Изменения `apply()`, газовых/fuel-формул, семантики `caller()`/`origin()`, отката sub-call и outbound-сообщений, формулы адреса деплоя, `pmm.rs`/`tokenomics.rs`, декодера `PqSignatureEnvelope::decode` (влияющего на `tx_hash` и допуск транзакций) и правил состояния `cross_shard_xpc` меняют консенсусный переход и/или `state_root` — они **обязаны** вводиться за явным compile-time activation gate (`u64::MAX` по умолчанию в `stellereum/src/chain_spec.rs`), со спецификацией + audit note + полным гейтом (`CONSENSUS_RULESET_VERSION` / `FORK_ID` при активации). Чистые оптимизации без смены наблюдаемых значений и состояний не требуют activation gate и не меняют `FORK_ID`.

---

## 1. Проверка гипотез по коду (точные вердикты и `file:line`)

### 1.1 Гипотеза 1: `xshard2pc.rs:480-560` + `state_engine/xshard.rs:210-290` — может ли pruned/reclaimed `Commit` пройти повторно?

- **Фактическая карта кода:**
  - `stellereum/src/xshard2pc.rs:473-482`: `target_on_commit(existing: Option<&XpcRecord>)`:
    - `None` → `XpcTransition::Refused("commit without a prepared record")` (`:475`);
    - `Some(Prepared)` → `XpcTransition::Advanced(XpcPhase::Committed)` (`:477`);
    - `Some(Committed)` → `XpcTransition::Noop` (`:478`);
    - `Some(Aborted)` → `XpcTransition::Refused("transfer already aborted")` (`:479`).
  - *(Уточнение координат: `xshard2pc.rs:480-560` охватывает конец `target_on_commit` `:480-482`, `target_on_abort_request` `:494-503`, `SourceAction` `:507-516` и `should_reprepare` `:544-561`; ретеншн `XPC_TERMINAL_RETENTION_HEIGHTS = 360_000` задан на `:699`, а предикат `is_retired` — на `:775-785`. В `state_engine/xshard.rs:219-295` находятся `restore_xpc_records` `:219-264` и `write_xpc_record` `:275-295`; сам прунинг `prune_terminal_xpc_records` находится на `:318-346` и вызывается в каждом блоке на `:551`.)*
  - `stellereum/src/state_engine/xshard.rs:315-346`: `prune_terminal_xpc_records` удаляет запись только из `self.cross_shard_xpc` (`:335`) и лист `xpc_state_key(&tx_hash)` из `self.state_trie` (`:341`), **не удаляя** `tx_hash` из `self.cross_shard_completed` (`:315-317`).
  - `stellereum/src/state_engine/xshard.rs:1140-1189` (`CrossShardKind::Commit`):
    - проверяет `target_on_commit(existing.as_ref()) == Advanced(Committed)` (`:1151-1154`);
    - до зачисления средств делает атомарный claim `if !self.cross_shard_completed.write().await.insert(tx_hash) { return false; }` (`:1167-1169`).
  - Исключение на реорг-пути: `restore_snapshot_chunked` (`stellereum/src/state_engine/memory_bounds.rs:582`) и `restore_snapshot` (`stellereum/src/state_engine/accounts.rs:2375`) намеренно очищают `cross_shard_completed` при откате снапшота для переприменения блоков; sync-путь `restore_snapshot_chunked_preserve_replay_sets` (`memory_bounds.rs:623-655`) + `cross_shard_replay_covers` (`xshard.rs:459-503`) сохраняют `cross_shard_completed`.
- **Вердикт по повторному зачислению `Commit` после прунинга:** **ОПРОВЕРГНУТО.**
  - Прямой повторный `Commit` после `prune_terminal_xpc_records` не проходит: `existing == None` немедленно отклоняется в `target_on_commit(None)` (`xshard2pc.rs:475`), а даже при наличии `Prepared`-записи в `cross_shard_xpc` повторная выплата блокируется на `:1167` перманентным маркером `tx_hash ∈ cross_shard_completed`.
- **Вердикт по сопутствующей уязвимости state-pollution (`Prepare`/`AbortRequest` после прунинга) и багу `PrepareAck`:** **ПОДТВЕРЖДЕНО / НУЖЕН ТЕСТ.**
  1. `state_engine/xshard.rs:1070-1084` (`CrossShardKind::Prepare`) и `:1194-1213` (`CrossShardKind::AbortRequest`) **не проверяют** `self.cross_shard_completed.read().await.contains(&tx_hash)`. После прунинга `Committed`-записи (`existing == None`) при наличии валидного anchor в `FinalizedHeaderRegistry` (`REGISTRY_ANCHOR_WINDOW = 512` в `sharding/xshard.rs:493` или height-0 anchor без истечения `:619-628, 656`):
     - `target_prepare(None)` (`xshard2pc.rs:456`) возвращает `Created`, создавая **вечную зомби-запись `XpcPhase::Prepared`** в `cross_shard_xpc` и `state_trie`, которая никогда не перейдёт в `Committed` (из-за `:1167`), никогда не будет удалена `is_retired` (`xshard2pc.rs:777`) и заставит target бесконечно переиздавать `PrepareAck`;
     - `target_on_abort_request(None)` (`xshard2pc.rs:496`) запишет `XpcPhase::Aborted` поверх уже завершённого трансфера.
  2. `state_engine/xshard.rs:1103-1123` (`CrossShardKind::PrepareAck` на уже `Committed` source-записи): обновляет `rec.decided_height = height` и вызывает `self.write_xpc_record(&rec).await` (`:1110`, мутируя `cross_shard_xpc`, `state_trie` и `Domain::Xpc` на `:293`), но возвращает **`false`** на `:1121`, нарушая собственный контракт `:968` (*«Returns true when the committed state changed»*) и оставляя `mutated = false` в `apply_cross_shard_consumptions` (`:614-615`).

---

### 1.2 Гипотеза 2: `cn_vrf.rs` vs `vrf.rs` + `chain_spec.rs` + `protocol.rs` — высота активации `CN-VRF v3`, `curve25519` в `vrf.rs` и `u128` overflow в sortition при весах `~TOTAL_SUPPLY_CAP`

- **Фактическая карта кода:**
  - **Высота активации `CN-VRF v3`:**
    - `stellereum/src/consensus/sortition.rs:664`: `pub const CNVRF_V3_ACTIVATION_HEIGHT: u64 = u64::MAX;` (`GatedOff`, **НЕ `0`**).
    - `stellereum/src/consensus/sortition.rs:681-689`: `cnvrf_v3_active_at(height)` проверяет `height >= CNVRF_V3_ACTIVATION_HEIGHT` (`false` на всех достижимых высотах при `u64::MAX`).
    - `stellereum/src/chain_spec.rs:274-278`: `CNVRF_V3_ACTIVATION_HEIGHT` зарегистрирован в `current_activation_schedule()` со статусом `ActivationStatus::GatedOff` (`chain_spec.rs:176-180, 338-349`).
    - `stellereum/src/protocol.rs:163-165`: в `FORK_ID_RULES` входят `cn_vrf::{EPOCH_LEN, V3_SEGMENT_LEN, V3_COMMIT_LOOKAHEAD_BLOCKS}`, но **не** `CNVRF_V3_ACTIVATION_HEIGHT`; текущая версия `CONSENSUS_RULESET_VERSION = 6` (`:101`), `FORK_ID = 0x0f584a46` (`:100`).
    - `stellereum/src/state_engine/apply.rs:2972-2976`: шаг 5d `apply_cnvrf_v3` выполняется только при `self.cnvrf_v3_is_active_at(block.height)`.
  - **Использование `vrf.rs` и `curve25519`:**
    - `stellereum/src/vrf.rs:1-133`: ECVRF, ключи, `curve25519`/`edwards25519` и env-активация полностью удалены (`vrf.rs:17-23`). Модуль содержит **только** 3 чистые функции оценки (`lottery_threshold` `:33-57`, `expected_draws_to_include_member` `:66-71`, `expected_draws_to_capture_seats` `:76-88`). Живая сортировка в `consensus/sortition.rs` (`derive_sortition_committee` `:493`, `cnvrf_v3_beacon_draw_committee` `:732`) вообще не вызывает `vrf.rs`.
    - `curve25519_dalek` в `stellereum/src/` остался только для полевой арифметики `Scalar` в Shamir Secret Sharing (`stellereum/src/mev.rs:49-50, 60`) и в тестовых модулях (`light_client.rs:2822`, `wallet.rs:1514`).
  - **Проверка `u128` overflow в sortition при весах порядка `TOTAL_SUPPLY_CAP` (`10^18` nano-STELL) и проверка `cn_vrf.rs`:**
    - В самом `stellereum/src/cn_vrf.rs` (строки `1-1995`) нет ни `u128` арифметики, ни sortition.
    - В `stellereum/src/consensus/sortition.rs:426-490` (`select_committee_from_seed`): `total_power` (`:458`) и `acc` (`:476`) имеют тип `u64` с `saturating_add`. Поскольку `TOTAL_SUPPLY_CAP = 10^18 < u64::MAX (≈ 1.844 * 10^19)` (`tokenomics.rs:40`), суммарный стейк `<= TOTAL_SUPPLY_CAP` не переполняет и даже не насыщает `u64`.
    - В `stellereum/src/consensus/sortition.rs:24-29` (`consensus_quorum_min`): `((n as u128 * 2) / 3 + 1) as u64` — для всех `n: u64` произведение `< 2^65 << 2^128`, переполнение `u128` невозможно.
    - В `stellereum/src/vrf.rs:33-57` (`lottery_threshold`): `num = (stake as u128) * (expected_seats as u128)` (`< 2^128`); при `frac_num >= 1` функция выходит на `:41-44` (`return u128::MAX`), поэтому далее гарантировано `r = frac_rem < t <= u64::MAX < 2^64`, и `(r * HI)` с `HI = 1u128 << 64` (`:50, 53-55`) строго `< 2^128`. Переполнение `u128` невозможно даже при `stake = TOTAL_SUPPLY_CAP` или `u64::MAX`.
    - **Найден реальный `u64` overflow в `stellereum/src/cn_vrf.rs:607-609, 1774-1776`:**
      `epoch_start_height(epoch_n: u64) -> u64 { epoch_n * EPOCH_LEN }` (`:607-609`) использует unchecked `*` (паника в debug / wrap-around в release при `epoch_n > u64::MAX / 30_000`) и вызывается из `freeze_height_of_epoch` (`:1774-1776`), тогда как `admit_commit` (`:1601-1604`) корректно использует `saturating_mul`.
- **Вердикт по Гипотезе 2:**
  - `CNVRF_V3_ACTIVATION_HEIGHT == u64::MAX` (`GatedOff`), **НЕ `0`**: **ПОДТВЕРЖДЕНО** (`consensus/sortition.rs:664`, `chain_spec.rs:274`).
  - Использование `vrf.rs` на `curve25519`: **ОПРОВЕРГНУТО** (`vrf.rs` не содержит `curve25519` и не вызывается консенсусом).
  - `u128` overflow в sortition при весах `~TOTAL_SUPPLY_CAP`: **ОПРОВЕРГНУТО** (переполнения `u128` нет ни в `cn_vrf.rs`, ни в `sortition.rs`, ни в `vrf.rs`), **НО ПОДТВЕРЖДЁН unchecked `u64` overflow в `cn_vrf.rs:607-609, 1774-1776` (`epoch_start_height`)** — требуется замена на `saturating_mul` и регресс-тест.

---

## 2. Подтверждённый реестр дефектов и оптимизаций (`AUDIT-REMAINING-SUBSYSTEMS`)

| ID | Подсистема | Точный `file:line` | Суть дефекта / оптимизации | Тип изменения |
|---|---|---|---|---|
| **WASM-1** | `svm.rs`, `contract.rs` | `svm.rs:2067-2088, 2143-2165`; `contract.rs:136-141, 768-807, 1098-1112, 1191-1493` *(прим.: `contract.rs:2081-2135` в текущем дереве — юнит-тесты `send_message`)* | Нет per-sub-call snapshot/rollback для `storage`/`balance`/`events`/`outbound_messages` при вложенном или обработанном sub-call; в `ContractCallContext.caller` передаётся `ctx.sender` (`tx.from` origin) без разделения `caller()` vs `origin()`. | Консенсусное (за gate `H`) |
| **WASM-2** | `state_engine/apply.rs`, `svm.rs`, `contract.rs` | `apply.rs:1010-1015, 3691-3692`; `svm.rs:3441-3469`; `contract.rs:1466` | `process_contract_outbound_messages` вызывается ДО CLOB-расчётов (`:1035-1135`) и ДО `commit_native` (`:1467`) и не откатывается в `ExecPostActions`/`rollback_payload` (`:332-409, 1177-1183`); нет `sync_contract_balance`/дебета `accounts[contract_addr]` в `execute_payload_with_preverify`; `route_contract_messages_with_topology` кладёт сырой `msg.payload` (`svm.rs:3446`), который падает на `decode_actor_body` (`apply.rs:3692`) и на баунсе (`apply.rs:3614-3633`) **кредитует `accounts[contract_addr]` из воздуха**. | Консенсусное (за gate `H` в части поведения уже применённых блоков; `ExecPostActions` rollback — fail-closed) |
| **WASM-3** | `state_engine/apply.rs` | `apply.rs:186-188` | `snapshot_payload_domains` матчит `SysCallDeployContract \| SysCallCallContract`, **пропуская `SysCallCallContractArgs`** — при провале транзакции после VM (например, в `commit_native`) `contracts` не откатываются. | Консенсусное (за gate `H` либо немедленный B1-фикс при отсутствии исторических провалившихся `SysCallCallContractArgs` tx) |
| **WASM-4** | `rpc/contracts.rs` vs `contract.rs` | `rpc/contracts.rs:768, 864` vs `contract.rs:553` | RPC предсказывает адрес как `contract_address(&tx.from, tx.nonce)`, а `ContractRegistry::deploy_inner` (`contract.rs:553`) вычисляет `contract_address(&creator, self.next_nonce)` по глобальному счётчику реестра. | Консенсусное для `deploy_inner` (за gate `H`); RPC должен отображать формулу консистентно |
| **WASM-5** | `contract.rs` | `contract.rs:475-481, 1285-1288, 1421` | `validate_code` запускает `start`-секцию без `store.set_fuel(...)` (бесконечный цикл DoS); `host.calldata` (`:1285`) клонирует до 64 KiB ДО `HostState::charge` (`:1288`); `host.send_message` (`:1421`) списывает плоские `FUEL_SEND_MESSAGE = 100` вне зависимости от длины `payload` (до 64 KiB) + SHA-256 (`:1471-1477`). | Консенсусное (за gate `H`, т.к. меняет fuel/ошибки исполнения и деплоя) |
| **PMM-1** | `pmm.rs`, `svm.rs` | `pmm.rs:218-222, 239, 251-255, 297-354`; `svm.rs:2711-2733, 2783-2809` | Unchecked `u128` overflow/panic в `2 * sc * k` (`:239`), `(s+d)*(s+d)` (`:218`), `s*s` (`:219, 251`), `p0*(d+quad)` (`:222`) и unchecked `as u64` в квитанциях (`:297-300, 321-323, 352-354`); в `svm.rs:2711-2729` `buy_with_buffer` вызывается ДО проверки баланса `wUSDT`; явные ошибки `ZeroPayout`/`ZeroMint`. | Консенсусное (за gate `H`, except pure panic-avoidance on overflow) |
| **TOK-1** | `tokenomics.rs` | `tokenomics.rs:270-334` (`:278-291, 312-333`) | `GenesisVault::calculate_mint` возвращает `0` для малых сумм (в т.ч. из-за промежуточного усечения до micro-USD на `:278-280`), а `deposit_and_mint` (`:312-333`) принимает `mint_nano == 0`, увеличивает `*target_deposit += asset_amount` (`:329`) и возвращает `Ok(0)` — принимает актив в обмен на `0` STELL (`ZeroMint`). | Консенсусное (за gate `H`) / отказ `ZeroMint` |
| **XPC-1** | `state_engine/xshard.rs` | `xshard.rs:1070-1084, 1103-1123, 1194-1213` | `Prepare` (`:1070-1084`) и `AbortRequest` (`:1194-1213`) не проверяют `cross_shard_completed` после прунинга (`:335`); `PrepareAck` refresh (`:1103-1123`) мутирует `cross_shard_xpc`/`state_trie`/`Domain::Xpc` на `:1110`, но возвращает `false` на `:1121`. | Консенсусное (`Prepare`/`AbortRequest` guard за gate `H` или безопасный replay check); `return true` в `:1121` |
| **VRF-1** | `cn_vrf.rs` | `cn_vrf.rs:607-609, 1774-1776` | `epoch_start_height(epoch_n)` делает unchecked `epoch_n * EPOCH_LEN` (panic/wrap при `epoch_n > u64::MAX / 30_000`), проникает в `freeze_height_of_epoch`. | Замена на `saturating_mul` (безопасно на всех достижимых высотах) |
| **ENV-1** | `sharding/envelope.rs`, `sharding/transaction.rs` | `envelope.rs:263-355`; `transaction.rs:879-882, 1259` | Explicit `PqSignatureEnvelope::decode` принимает оба фрейминга `key\|\|salt` (`:263-294`) и `salt\|\|key` (`:326-354`), а также без-salt (`:297-321`), тогда как `hash_into` (`transaction.rs:879-882`) хеширует сырые байты `self.signature` → `tx_hash` malleability одной и той же валидной подписи. | Консенсусное (за gate `H`) |
| **OPT-1** | `post_quantum.rs` | `post_quantum.rs:2117-2152, 2193-2199, 2233` (vs `:899-905`) | Кешировать `h_ntt` (в NTT-домене) в `FALCON_PUBKEY_CACHE` вместо повторного `ntt(&mut b_ntt)` внутри `poly_mul_ntt` на каждую подпись; удалить дублирующую проверку trailing zero в `unpack_falcon_sig:2193-2199` (уже проверено в `comp_decode:899-905`). | **Чистая оптимизация** (0 изменений поведения/root) |
| **OPT-2** | `state_engine/xshard.rs`, `sharding/transaction.rs` | `xshard.rs:844-856, 916-945`; `transaction.rs:797, 869, 912, 920, 1157, 1339, 1350, 1535-1596` | Предвычислить `Transaction::compute_tx_hashes_batched(&block.transactions)` (`HashMap<[u8; 32], usize>`) вместо $O(M \cdot N)$ пересчёта в `record_legacy_escrow_receipts` / `apply_xpc_source_prepares`; однократный разбор `split_sponsor_envelope` в `hash_into` / `signing_message` / `chain_id` / `verify_signature_*` (и в блочных батчах). | **Чистая оптимизация** (0 изменений поведения/root) |
| **OPT-3** | `contract.rs` | `contract.rs:447-448, 956-957, 1086-1096, 1657-1658` | `OnceLock<wasmi::Engine>` + потокобезопасный ограниченный кэш `wasmi::Module` по `code_hash` (`Sha256(code)`), единый для `validate_code`, `run_contract` и `run_get_method_inner`. | **Чистая оптимизация** (0 изменений поведения/root) |

---

## 3. Точные контракты фиксов и политика активации (`H - 1 / H / H + 1`)

### 3.1 Модель activation gate (`chain_spec.rs` + `protocol.rs`)

Вводится единый compile-time гейт для данной волны консенсусного харденинга (default `GatedOff`):
```rust
// stellereum/src/chain_spec.rs (и/или re-export из модуля-владельца)
pub const WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT: u64 = u64::MAX;
```
- Регистрируется в `chain_spec::current_activation_schedule()` (`chain_spec.rs:255-311`) с проверкой `ActivationGate::new(...)` (`Status::GatedOff` при `u64::MAX`).
- По шаблону `QC_SPLIT_ACTIVATION_HEIGHT` (`consensus/sortition.rs:256-295`) предоставляется `#[cfg(any(test, debug_assertions))]` thread-local override `set_hardening_activation_override(Option<u64>)` (в release не существует).
- **Инвариант `FORK_ID` (`protocol.rs:101, 151-175, 226`):** пока константа равна `u64::MAX`, `FORK_ID` (`0x0f584a46`) и `CONSENSUS_RULESET_VERSION` (`6`) **не меняются**. При координации хард-форка/нового генезиса (переключение `u64::MAX -> H`) обязательно: bump `CONSENSUS_RULESET_VERSION`, включение константы в `FORK_ID_RULES`, audit note + полный гейт (`AGENTS.md` §7).

#### Граница `H - 1 / H / H + 1`:
| Высота | Поведение цепи |
|---|---|
| **`height <= H - 1`** (включая все блоки при `H == u64::MAX`) | **Побайтовая обратная совместимость** со всеми существующими контрактами, блоками и тестами: `ContractRegistry::deploy_inner` использует `next_nonce`, `host.caller` получает переданный `ctx.caller`, `FUEL_SEND_MESSAGE = 100` flat, `host.calldata` поведение без изменений, `PqSignatureEnvelope::decode` принимает legacy explicit-фрейминги, `pmm.rs`/`tokenomics.rs` используют прежнюю классификацию ошибок, `xshard` применяет прежние правила без изменения реплейных веток. *(При этом чистые оптимизации OPT-1/OPT-2/OPT-3 активны всегда с высоты 0, т.к. они детерминированно побайтово эквивалентны.)* |
| **`height == H`** (граница активации) | Все транзакции блока `H` (и одиночные вызовы, привязанные к `height >= H`) выполняются по новым правилам: задействуются `SubCallSnapshot`, `caller()` vs `origin()`, перибайтовый `send_message` fuel + fuel для `start`-секции + `charge`-до-`clone` в `calldata`, атомарный `outbound_messages` откат и `sync_contract_balance`/`ActorSendBody` защита, `SysCallCallContractArgs` snapshot, `tx.nonce`-детерминированный адрес деплоя (если выбран переход формулы — см. §3.2.4), `ZeroPayout`/`ZeroMint` отказы в `pmm.rs`/`tokenomics.rs`, запрет legacy explicit `PqSignatureEnvelope` в `envelope.rs`, `cross_shard_completed` guard в `Prepare`/`AbortRequest`. |
| **`height >= H + 1`** | Все новые правила продолжают действовать; контракты, задеплоенные до `H`, **остаются вызываемыми** по своим уже записанным адресам (`contracts` map/trie не мигрирует адреса задним числом), а для внутренних вызовов видят корректные `caller()` / `origin()` и изоляцию отката. |

---

### 3.2 Контракт фикса для `contract.rs` / `svm.rs` / `state_engine/apply.rs` / `rpc/contracts.rs`

#### 3.2.1 Snapshot/Rollback на каждый sub-call и `SysCallCallContractArgs`
1. **Обязательный snapshot в `snapshot_payload_domains` (`state_engine/apply.rs:186-188`):**
   - Расширить паттерн:
     ```rust
     SysCallDeployContract { .. }
     | SysCallCallContract { .. }
     | SysCallCallContractArgs { .. } => touches_contracts = true,
     ```
2. **Per-sub-call изоляция внутри `ContractRegistry` / `Svm` (`contract.rs:768-807, 1098-1112, 1629-1710` и `svm.rs:2036-2175`):**
   - Ввести явный тип кадра отката:
     ```rust
     pub struct SubCallSnapshot {
         contracts: HashMap<[u8; 32], Contract>, // или affected contract entry + balance/storage
         events_len: usize,
         outbound_len: usize,
         last_return_data: Vec<u8>,
     }
     ```
   - При каждом вложенном вызове (и при вызове `SysCallCallContract` / `SysCallCallContractArgs` / будущем `host.call_contract` со статусом возврата в вызывающий контракт без trap всей транзакции):
     - до входа в целевой контракт берётся snapshot состояния целевого (и вызывающего) контракта (`storage`, `balance`), а также длины `events_len = events.len()`, `outbound_len = outbound_messages.len()`, `last_return_data`;
     - **любая ошибка** sub-call (`Trapped`, `OutOfFuel`, `NoSuchMethod`, `Paused`, `NotFound`, `Overflow`, превышение глубины `call_depth > MAX_CALL_DEPTH = 8`) **немедленно откатывает**:
       - `contract.storage` и `contract.balance` к snapshot до sub-call;
       - `events.truncate(snap.events_len)`;
       - `outbound_messages.truncate(snap.outbound_len)` (и все связанные `outbound_transfers`);
       - `last_return_data` к `snap.last_return_data`;
     - списывается только реально потреблённый `fuel_used` из бюджета вызывающего кадра (при `OutOfFuel` остаток бюджета равен 0 и трап пробрасывается вверх).
   - В `state_engine/contracts.rs:377-443` (`call_contract_structured_with_value`): при `height >= H`, если `call_contract_structured` вернул `status == "failed"`, переданный `value` (если он был переведён до вызова) откатывается с контракта обратно на `caller` через `debit_native` + `credit_native_transfer` (либо переводится только при `status == "success"` в едином `accounts` lock).

#### 3.2.2 Явная политика `caller()` vs `origin()`
- Расширить `ContractCallContext` (`contract.rs:136-141`) и `HostState` (`contract.rs:1098-1112`):
  - `pub origin: [u8; 32]` — **неизменяемый инициатор внешней транзакции (`tx.from`)** на всех уровнях вложенности (`depth = 0..MAX_CALL_DEPTH`).
  - `pub caller: [u8; 32]` — **непосредственный вызывающий**:
    - при вызове из SVM (depth 0: `SysCallCallContract`, `SysCallCallContractArgs`) = `ctx.sender` (`tx.from`);
    - при вложенном вызове из контракта `A` в контракт `B` (depth ≥ 1, при включении `host.call_contract` или цепочке внутренних вызовов) = `A.address` (`calling_contract`), **никогда** не `tx.from`!
    - если SVM-транзакция содержит последовательные `SysCallCallContract` на depth 0, каждый top-level вызов имеет `caller = tx.from`, `origin = tx.from`; любая композиция через контракт-посредник `A -> B` передаёт `B` именно `caller = A`, `origin = tx.from`.
  - В `host_linker` (`contract.rs:1241-1250`):
    - `host.caller(dest_ptr)` продолжает возвращать `caller.data().caller` (обратная совместимость ABI для depth 0 сохранена 100%);
    - при добавлении `host.origin(dest_ptr)` (за gate `H`, с `FUEL_CALLER`) возвращается `caller.data().origin`;
    - в `validate_code` (для модулей до `H`) неизвестные новые хост-импорты не требуются существующим контрактам, поэтому контракты до `H` продолжают работать без перекомпиляции.

#### 3.2.3 Атомарность `process_contract_outbound_messages`, `sync_contract_balance` и запрет печати на баунсе
- В `state_engine/apply.rs`:
  1. Убрать преждевременный вызов `process_contract_outbound_messages` с `:1010-1015` (до CLOB-settlement `:1035-1135` и до `commit_native` `:1467`) **либо** выполнять его строго **после** успешного `commit_native` (вместе с `write_contract_trie_entries` `:1531-1533`), так чтобы ни ошибка CLOB, ни отказ `commit_native` не оставляли сообщения в `accounts.inbox` / `cross_shard_out`.
  2. Перед `Svm::execute_*` (`apply.rs:673-748`, при наличии `SysCallCallContract` / `SysCallCallContractArgs` и `height >= H`) синхронизировать `Contract::balance` из `accounts[addr].balance` для вызываемых контрактов, а после успеха перенести дебет `accounts[contract_addr].balance` в размере отправленного `outbound_messages.iter().map(|m| m.value).sum()` (или синхронизировать обратно в `accounts` атомарно под write-lock `accounts`), гарантируя инвариант сохранения баланса: `bounce` может вернуть только сумму, реально списанную с `accounts[contract_addr]`.
  3. В `svm.rs:3441-3469` (`route_contract_messages_with_topology`): при `height >= H` различать сырой контрактный payload и `ActorSendBody` (либо кодировать контрактный вызов/перевод без обязательного `decode_actor_body` fail-bounce, либо для pure-value `ContractMessage` с пустым `payload` / контрактов доставлять value без фальшивого `ActorSendBody` декода, а failed delivery без предварительного списания с `accounts[contract_addr]` невозможен).

#### 3.2.4 Согласование формулы адреса деплоя (`rpc/contracts.rs` vs `contract.rs:553`)
- Проблема: `rpc/contracts.rs:768, 864` использует `contract_address(&tx.from, tx.nonce)`, тогда как `ContractRegistry::deploy_inner` (`contract.rs:553`) использует `contract_address(&creator, self.next_nonce)`.
- Контракт фикса за gate `H`:
  - **До `H` (`height < H`):** `deploy_inner` сохраняет `contract_address(&creator, self.next_nonce)` (обратная совместимость исторических адресов); `rpc/contracts.rs` для legacy-превью указывает реальную формулу или `contracts.next_nonce` (read-only фикс RPC можно выпустить сразу, не меняя консенсус).
  - **На `height >= H`:** добавить `deploy_with_nonce(creator, code, now, sender_nonce)` (и передавать `tx.nonce` из `svm.rs` / `apply.rs` при `SysCallDeployContract`), вычисляя `contract_address(&creator, tx.nonce)` — тогда предсказание в `rpc/contracts.rs:768, 864` совпадает с реальным адресом 1:1 и не зависит от деплоев других пользователей.

#### 3.2.5 Fuel-гарденинг `contract.rs:475-481, 1285-1288, 1421` (за gate `H`)
1. `validate_code` (`contract.rs:475-481`): при `height >= H` (и сразу для новых RPC-валидаций) устанавливать `store.set_fuel(MAX_CONTRACT_FUEL)` (или `GET_METHOD_SAFETY_FUEL_LIMIT`) **до** `linker.instantiate_and_start(&mut store, &module)` (`:480`), ограничивая работу WASM `start`-функции.
2. `host.calldata` (`contract.rs:1285-1288`): вычислять `len = caller.data().calldata.len()` **без клонирования**, сначала вызывать `HostState::charge(&mut caller, fuel)?`, и только после успешного списания fuel читать/копировать `calldata` в WASM-память (`write_wasm_memory`).
3. `host.send_message` (`contract.rs:1421`): до чтения памяти и SHA-256 проверять базовые границы `payload_len <= 64 * 1024`, `recipient_len == 32` и списывать пропорциональный fuel `FUEL_SEND_MESSAGE + (payload_len as u64) * FUEL_SEND_MESSAGE_PER_BYTE` (где `FUEL_SEND_MESSAGE_PER_BYTE = 1` или `2`, аналогично `FUEL_SHA256_PER_BYTE = 1` + `FUEL_RETURN_DATA_PER_BYTE = 1`), закрывая 64 KiB + SHA-256 амплификацию за 100 fuel.

---

### 3.3 Контракт фикса для `pmm.rs` + `tokenomics.rs` (`ZeroPayout` / `ZeroMint` + `u128` safety)

1. **`pmm.rs:215-256, 282-356`:**
   - **Новые явные варианты `PmmError` (`pmm.rs:45-53`):** добавить `ZeroMint` (при `d == 0` / `stell_minted == 0` в buy-пути) и `ZeroPayout` (при `payout == 0` / `usdt_paid == 0` в sell-пути), либо возвращать `ZeroMint`/`ZeroPayout` за gate `H` (до `H` сохраняется `PmmError::Dust` ради совместимости существующих тестов `pmm.rs`).
   - **Защита от `u128` panic/overflow в кривой:**
     - `mint_for_usdt` (`:233-241`): заменить `2 * sc * k` (`:239`) на `2u128.checked_mul(sc).and_then(|v| v.checked_mul(k))` (вернуть `Result<u128, PmmError>`, при переполнении → `Err(PmmError::Overflow)` вместо `saturating_add` с паникой на `2 * sc * k`!).
     - `buy_cost_micro` (`:215-223`): заменить `(s + d) * (s + d)`, `s * s`, `2 * sc`, `p0 * (d + quad)` на `checked_add` / `checked_mul` → `Result<u128, PmmError>` (`Err(PmmError::Overflow)`), либо использовать алгебраическое тождество `2*s*d + d^2` с `checked_mul` без лишнего возведения в квадрат.
     - `sell_payout_micro` (`:247-256`): использовать `checked_mul` / `checked_sub` (`s >= d` проверять явно) → `Result<u128, PmmError>` (`Err(PmmError::Overflow)`).
     - Квитанции (`:297-300, 321-323, 352-354`): заменить все `as u64` на `u64::try_from(...).map_err(|_| PmmError::Overflow)?`.
2. **`svm.rs:2711-2733, 2783-2809` (`SysCallPmmBuy` / `SysCallPmmSell`):**
   - В `SysCallPmmBuy`: проверять наличие `token_registry` и `reg.balance_of(&usdt_id, &ctx.sender) >= *usdt_micro` **ДО** клонирования/мутации `working_pmm` и вызова `working.buy_with_buffer(...)` (строгий CEI!). Дополнительно fail-closed проверка `if receipt.stell_minted == 0 { return VmExecutionResult::Reverted("PMM buy: zero mint".into()); }`.
   - В `SysCallPmmSell`: fail-closed проверка `if receipt.usdt_paid == 0 || receipt.stell_burned == 0 { return VmExecutionResult::Reverted("PMM sell: zero payout".into()); }`.
3. **`tokenomics.rs:270-334` (`GenesisVault`):**
   - За gate `H` (или новым методом `calculate_mint_checked` / `deposit_and_mint_checked`):
     - `calculate_mint` (`:270-292`): вычислять без промежуточного усечения: `((asset_amount as u128) * (price_micro_usd as u128) * 1_000_000_000u128) / (divisor * BASE_STELL_PRICE_MICRO_USD as u128)` (используя `checked_mul` или split-mul без потери точности при отсутствии переполнения `u128`, fallback на safe `u256`/division order).
     - `deposit_and_mint` (`:295-334`): если `asset_amount == 0` или `mint_nano == 0`, **немедленно возвращать `Err("Genesis Vault: zero STELL minted for deposit (ZeroMint)")`** ДО обновления `total_minted_nano` и `*target_deposit` (`:328-331`). Активы не принимаются и не сжигаются при `mint_nano == 0`.

---

### 3.4 Контракт фикса для `xshard`, `cn_vrf` и `PqSignatureEnvelope`

1. **`state_engine/xshard.rs:1070-1084, 1103-1123, 1194-1213`:**
   - В `CrossShardKind::Prepare` (`:1070-1084`) и `CrossShardKind::AbortRequest` (`:1194-1213`): при `height >= H` (и безопасно в новой логике) добавить первой проверкой:
     ```rust
     if self.cross_shard_completed.read().await.contains(&tx_hash) {
         return false;
     }
     ```
     что навсегда блокирует воскрешение pruned-записей в зомби-`Prepared` или перезапись `Aborted` поверх `Committed`.
   - В `CrossShardKind::PrepareAck` (`:1103-1123`): при успешном обновлении `rec.decided_height = height` (`write_xpc_record(&rec).await == true`) возвращать `true` (`:1121`), чтобы `apply_cross_shard_consumptions` (`:614-615`) выставлял `mutated = true` (и при этом `credited` по-прежнему увеличивается только для `CrossShardKind::Commit` на `:631-635`).
2. **`cn_vrf.rs:607-609, 1774-1776`:**
   - Заменить `epoch_n * EPOCH_LEN` в `epoch_start_height` (`:607-609`) на `epoch_n.saturating_mul(EPOCH_LEN)`, защитив и `freeze_height_of_epoch` (`:1774-1776`) от debug-panic и release-wrap.
3. **`sharding/envelope.rs:263-355`:**
   - Ввести `PqSignatureEnvelope::decode_canonical(bytes: &[u8]) -> Result<Self, String>`, принимающий **только** канонический формат (`key || salt || sig || [chain_id]`, `:263-294`, и implicit `:203-241`) и отклоняющий legacy `salt || key` (`:326-354`) и no-salt (`:297-321`) с точным соответствием `env.encode()` / `env.encoded_len()`.
   - На mempool/RPC ingress (`mempool.rs` / `rpc`) и в консенсусе на `height >= H` (`apply.rs` / `verify_inner_with_registry`) использовать `decode_canonical` + проверку `env.encoded_len() == inner_sig.len()`, оставляя `PqSignatureEnvelope::decode` для исторических блоков `< H`.

---

### 3.5 Контракт чистых оптимизаций (0 изменений правил, `FORK_ID` неизменен)

1. **`post_quantum.rs` (`OPT-1`):**
   - Изменить тип кэша `FALCON_PUBKEY_CACHE` (`post_quantum.rs:2117`) на storing `(h, h_ntt)` или сразу `h_ntt: [u16; 512]` (где `let mut h_ntt = h; ntt(&mut h_ntt);` вычисляется один раз при вставке в `unpack_falcon_pubkey`). В `verify_falcon512` (`:2233`) использовать `poly_mul_precomputed_ntt(&s2_modq, &h_ntt)` (`ntt(&mut a); point_mul(&a, &h_ntt); intt(...)`), экономя 1 полный 512-точечный `ntt()` на каждую верификацию при побайтово идентичном результате.
   - В `unpack_falcon_sig` (`post_quantum.rs:2193-2199`) удалить дублирующий цикл по `&payload[consumed..]`, т.к. `comp_decode` (`:899-905`) уже проверил нулевой паддинг от `v` до конца буфера `input`.
2. **`state_engine/xshard.rs` + `sharding/transaction.rs` (`OPT-2`):**
   - В `record_legacy_escrow_receipts` (`xshard.rs:844-856`) и `apply_xpc_source_prepares` (`xshard.rs:916-945`) заменить `block.transactions.iter().position(|t| t.compute_tx_hash() == tx_hash)` на одноразовое построение `let hashes = Transaction::compute_tx_hashes_batched(&block.transactions);` (`sharding/transaction.rs:893-900`) и `HashMap<[u8; 32], usize>` (при наличии дубликатов `entry(h).or_insert(idx)` сохраняет первый индекс как `position()`!). Сложность падает с $O(M \cdot N)$ до $O(M + N)$.
   - В `sharding/transaction.rs` добавить внутренний helper `parsed_sponsor_view(&self)` / `hash_into_with_sponsor` / `signing_message_with_sponsor`:
     - В `hash_into` (`:827-883`), `signing_message` (`:1319-1354`), `chain_id` (`:794-811`), `verify_signature_with_registry_and_salt` (`:1152-1180`) вызывать `Self::split_sponsor_envelope(&self.signature)` **один раз** (вместо 3–5 вызовов `sponsor_auth()` + `sponsor_inner_sig()` с повторным `bincode::deserialize::<SponsorAuthorization>` на каждый вызов).
     - Заодно для `verify_once.rs:138, 181` и `Transaction::compute_tx_hash()` при желании можно использовать `OnceLock` / предвычисленный `TxHash` в `apply_block_parallel_fees` / `TransactionWithHash` wrapper-адаптере без изменения `Serialize`/`Deserialize` формата `Transaction` (`TransactionWire`, `sharding/transaction.rs:41-55`).
3. **`contract.rs` (`OPT-3`):**
   - Заменить `fn contract_engine() -> Engine` (`contract.rs:1086-1096`) на `static CONTRACT_ENGINE: std::sync::OnceLock<Engine>` (конфиг с `consume_fuel(true)`, `wasm_multi_memory(false)`, `wasm_mutable_global(true)`).
   - Ввести bounded cache скомпилированных модулей:
     ```rust
     const MODULE_CACHE_CAP: usize = 1024;
     static MODULE_CACHE: LazyLock<RwLock<HashMap<[u8; 32], Module>>> = ...;
     ```
     ключуемый по `code_hash: [u8; 32]` (`Sha256::digest(code)`); при превышении `MODULE_CACHE_CAP` — детерминированная очистка (по образцу `FALCON_PUBKEY_CACHE` в `post_quantum.rs:2146-2148`).
   - Функции `validate_code` (`:448`), `run_get_method_inner` (`:957`) и `run_contract` (`:1658`) берут общий `Engine` и `Module` из `cached_module(code_hash, code)`, создавая свежий `Store::new(engine, host)` и `Linker` на каждый вызов (полная изоляция состояния и лимитов памяти/fuel между вызовами!).

---

## 4. Непересекающаяся матрица владения файлами (без пересечений с `SEC-FIX-CONTRACT`)

> **Разделение с `SEC-FIX-CONTRACT` (`docs/specs/05_LOCK_SAFETY_P0.md`, `06_BRIDGE_RELEASE_AUTHORIZATION_DRAFT.md`, `07_PQ_VALIDATOR_LIFECYCLE_DRAFT.md`):**
> `SEC-FIX-CONTRACT` владеет `safety.rs`, `bridge.rs`, `bridge_adapters.rs`, `pq_registry.rs`, `staking.rs`, `remote_signer.rs`, `consensus/*`, `runtime/*`, `node/*`, `storage.rs`, `commitment.rs`, `light_client.rs`, `rpc/reads.rs`, `rpc/state.rs`.
> Ни одна из ячеек ниже **не редактирует** эти файлы. Если в `state_engine/apply.rs` ведутся параллельные работы, **Ячейка B** ограничена исключительно участками `:164-410, 673-1189, 1464-1535` (domain snapshot, `execute_payload_with_preverify`, `ExecPostActions`, `rollback_payload`) и не трогает шаги 0, 5a–5f (`apply_cnvrf_v3`, `apply_pq_registry_ops`, `apply_gov_ops`).

| Агент / Ячейка | Разрешённые файлы (строгий lock) | Запрещённые файлы | Ответственность |
|---|---|---|---|
| **Agent A (`WASM-Core`)** | `stellereum/src/contract.rs`, `stellereum/src/rpc/contracts.rs`, `stellereum/tests/wasm_subcall_hardening_tests.rs` *(new)*, `stellereum/benches/wasm_module_cache.rs` *(new)* | `svm.rs`, `state_engine/**`, `pmm.rs`, `post_quantum.rs`, `rpc/{reads,state}.rs` | `SubCallSnapshot` / rollback, `ContractCallContext { origin, caller }`, `validate_code` `start` fuel, `calldata` charge-before-clone, per-byte `send_message` fuel, `OnceLock<Engine>` + `Module` cache по `code_hash`, deploy-nonce/RPC-прогноз. |
| **Agent B (`SVM-Apply`)** | `stellereum/src/svm.rs`, `stellereum/src/state_engine/apply.rs` *(строго `:164-410, 673-1189, 1464-1535`)*, `stellereum/src/state_engine/contracts.rs`, `stellereum/src/state_engine/types.rs`, `stellereum/tests/svm_outbound_atomicity_tests.rs` *(new)* | `contract.rs`, `state_engine/xshard.rs`, `pmm.rs`, `runtime/**`, `consensus/**`, `bridge.rs` | `SysCallCallContractArgs` в `snapshot_payload_domains`, атомарный `process_contract_outbound_messages` (откат/перенос после `commit_native`), `sync_contract_balance` + дебет `accounts[contract_addr]`, фикс bounce-печати из воздуха, `caller` vs `origin` проброс, PMM CEI в `svm.rs`, value-rollback в `call_contract_structured_with_value`. |
| **Agent C (`PMM-Tokenomics`)** | `stellereum/src/pmm.rs`, `stellereum/src/tokenomics.rs`, `stellereum/tests/pmm_tokenomics_zero_value_tests.rs` *(new)* | `svm.rs`, `contract.rs`, `state_engine/**`, `staking.rs` | Checked `u128` в `pmm.rs` (`2*sc*k`, квадраты, `u64::try_from`), `ZeroMint` / `ZeroPayout`, `GenesisVault::calculate_mint` / `deposit_and_mint` отказ при `mint_nano == 0` без усечения и приёма активов. |
| **Agent D (`XShard-VRF`)** | `stellereum/src/state_engine/xshard.rs`, `stellereum/src/xshard2pc.rs`, `stellereum/src/cn_vrf.rs`, `stellereum/tests/xpc_pruned_reopen_regression_tests.rs` *(new)* | `state_engine/apply.rs`, `consensus/**`, `sharding/**`, `storage.rs` | `cross_shard_completed` guard в `Prepare`/`AbortRequest`, `return true` в `PrepareAck` refresh (`:1121`), `compute_tx_hashes_batched` O(M+N), `cn_vrf::epoch_start_height` `saturating_mul`. |
| **Agent E (`PQ-Envelope-Opt`)** | `stellereum/src/sharding/envelope.rs`, `stellereum/src/sharding/transaction.rs`, `stellereum/src/post_quantum.rs`, `stellereum/tests/pq_envelope_malleability_and_cache_tests.rs` *(new)*, `stellereum/benches/hardening_perf_probe.rs` *(new)* | `contract.rs`, `state_engine/**`, `consensus/**`, `pq_registry.rs`, `remote_signer.rs` | `PqSignatureEnvelope::decode_canonical` (запрет `salt\|\|key` / no-salt за gate `H`), однократный `split_sponsor_envelope`, `h_ntt` в `FALCON_PUBKEY_CACHE`, удаление дубля trailing zero в `unpack_falcon_sig`. |
| **Lead (`Gate-Merge`)** | `stellereum/src/chain_spec.rs`, `stellereum/src/protocol.rs` *(только при реальной активации)* | Все рабочие области A–E до слияния | Регистрация `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT = u64::MAX`, проверка parity на границах `H-1 / H / H+1`, прогон `./scripts/verify_testnet_ideal.sh`. |

---

## 5. Обязательный список тестов «падало до» и бенчмарков до/после

### 5.1 Тесты «падало до» (каждый обязан падать на текущем `main` до фикса и проходить после)

1. **WASM sub-call rollback & `caller()` vs `origin()` (`wasm_subcall_hardening_tests.rs`):**
   - `nested_subcall_failure_rolls_back_storage_events_and_outbound_messages`: контракт `A` мутирует `storage`, вызывает контракт `B`, который делает `sstore`, `emit`, `send_message` и трапает / `OutOfFuel`. *Падало до:* частичные `storage`/`events`/`outbound_messages` переживали провал или не существовало границы sub-call отката. *После (на `>= H`):* `B` полностью откачен, `A` продолжает работу или откатывается целиком, `H - 1` сохраняет legacy поведение.
   - `nested_subcall_sees_calling_contract_as_caller_and_tx_from_as_origin`: при `tx.from -> A -> B` контракт `B` читает `host.caller == A.address`, а `host.origin == tx.from`. *Падало до:* везде передавался `tx.from` (`svm.rs:2068, 2144`).
2. **Outbound atomicity, `SysCallCallContractArgs` snapshot & bounce mint (`svm_outbound_atomicity_tests.rs`):**
   - `failed_clob_or_commit_native_rolls_back_contract_outbound_messages`: транзакция с `SysCallCallContract` (испускает `send_message`) + провальный `SysCallPlaceOrder` / недостаток газа на `commit_native`. *Падало до:* `process_contract_outbound_messages` (`apply.rs:1012`) уже помещал сообщение в `accounts.inbox` / `cross_shard_out` до падения CLOB/`commit_native`.
   - `contract_send_message_bounce_never_mints_free_stell`: контракт с нулевым `accounts[contract_addr].balance` (или с `msg.value > 0` и raw `payload`) отправляет сообщение через `send_message` на несуществующего получателя (или с не-`ActorSendBody` payload). *Падало до:* `decode_actor_body` (`apply.rs:3692`) падал → bounce (`apply.rs:3642`) → `apply_actor_messages_at` (`:3626`) зачислял `msg.value` на `accounts[contract_addr]` из воздуха.
   - `syscall_call_contract_args_failure_rolls_back_contract_storage`: транзакция с `SysCallCallContractArgs` меняет `contract.storage`, затем падает на `commit_native`. *Падало до:* `snapshot_payload_domains` (`apply.rs:186`) пропускал `SysCallCallContractArgs`, оставляя мутацию в `self.contracts`.
3. **Deploy address parity & WASM fuel (`wasm_subcall_hardening_tests.rs`):**
   - `deploy_address_matches_rpc_prediction_at_and_after_h`: два разных отправителя деплоят подряд при `height >= H` — `rpc/contracts.rs` предсказание `contract_address(tx.from, tx.nonce)` совпадает с фактическим адресом в `ContractRegistry`; при `height < H` сохраняется legacy `next_nonce`.
   - `validate_code_infinite_start_section_is_bounded_by_fuel`: WASM-модуль с бесконечным циклом в `(start $loop)` передаётся в `ContractRegistry::validate_code`. *Падало до:* `validate_code` (`contract.rs:480`) зависал навсегда без `set_fuel`.
   - `host_calldata_and_send_message_charge_fuel_before_alloc_and_per_byte`: вызов `host.calldata` с 64 KiB и недостаточным fuel не клонирует буфер до отказа; `host.send_message` с 64 KiB payload потребляет `> FUEL_SEND_MESSAGE` (`100`) пропорционально длине (`>= H`).
4. **PMM & Tokenomics `ZeroPayout` / `ZeroMint` / overflow (`pmm_tokenomics_zero_value_tests.rs`):**
   - `pmm_mint_for_usdt_huge_amount_returns_overflow_not_panic`: `buy_with_usdt(u64::MAX)` (где `2 * sc * k > u128::MAX` на `pmm.rs:239`). *Падало до:* panic в debug / wrap-around в release на `2 * sc * k`.
   - `pmm_buy_checks_wusdt_balance_before_curve_mutation`: `SysCallPmmBuy` с пустым балансом `wUSDT` не мутирует `working_pmm` и ревертится до расчёта кривой (`svm.rs:2711-2729`).
   - `genesis_vault_deposit_refuses_zero_mint_without_taking_assets`: `GenesisVault::deposit_and_mint("TON", 1, 1_000_000)` и `"USDT", 0, ...`. *Падало до:* `deposit_and_mint` (`tokenomics.rs:312-333`) принимал актив (`ton_deposited_nano += 1`) и возвращал `Ok(0)` (`0` STELL).
5. **Cross-Shard 2PC pruning reopen & `PrepareAck` return + `cn_vrf` overflow (`xpc_pruned_reopen_regression_tests.rs`):**
   - `pruned_committed_xpc_cannot_be_reopened_by_prepare_or_abort_request`: после `prune_terminal_xpc_records(decided + 360_000)` повторные `Prepare` и `AbortRequest` (при сохранённом anchor) отклоняются, не создавая зомби-`Prepared` или `Aborted` (`xshard.rs:1070, 1194`). *Падало до:* `target_prepare(None)` создавал `Prepared` в `cross_shard_xpc`.
   - `xpc_prepare_ack_refresh_returns_true_and_marks_mutated`: `apply_xpc_record` на `PrepareAck` при уже `Committed` записи возвращает `true` и обновляет `decided_height`. *Падало до:* возвращал `false` (`xshard.rs:1121`).
   - `cnvrf_epoch_start_and_freeze_height_saturate_on_u64_max_epoch`: `epoch_start_height(u64::MAX)` и `freeze_height_of_epoch(u64::MAX)` не паникуют (`cn_vrf.rs:607, 1774`). *Падало до:* panic `attempt to multiply with overflow`.
6. **PQ Envelope Malleability & Boundary Parity `H-1 / H / H+1` (`pq_envelope_malleability_and_cache_tests.rs`):**
   - `explicit_pq_envelope_salt_first_malleability_rejected_at_h`: перестановка одного валидного `PqSignatureEnvelope` из `key||salt||sig` в `salt||key||sig` (разные `tx_hash`) на `height < H` (`H - 1`) ещё принимается для legacy-совместимости, а на `height >= H` (`H` и `H + 1`) отвергается (`envelope.rs:263-355`).
   - `hardening_gate_boundaries_h_minus_1_h_h_plus_1`: сквозной тест прохождения блоков `H - 1`, `H`, `H + 1` с проверкой детерминизма `state_root` и инварианта `FORK_ID == 0x0f584a46` при `u64::MAX`.

---

### 5.2 Бенчмарки до/после (только чистые оптимизации OPT-1/2/3)

Запуск в release-режиме (по образцу `stellereum/benches/apply_hotpath.rs` — отчёты `median-of-5`, без временных assert-гейтов, но с обязательными **differential correctness asserts** на побайтовое равенство результатов):

| Бенчмарк (`--release --bench hardening_perf_probe` / `wasm_module_cache`) | Что измеряет | Ожидаемый выигрыш и инвариант корректности |
|---|---|---|
| `bench_falcon_verify_ntt_cache_1000` | `verify_pq_signature(Falcon512, ...)` на 1000 подписей при тёплом `FALCON_PUBKEY_CACHE` (сравнение baseline `poly_mul_ntt` vs cached `h_ntt` + без дубля trailing-zero) | Снятие 1× 512-point `ntt()` + 1× 625-byte scan на каждую верификацию; assert: `cached_ok == baseline_ok` для валидных, битых и с ненулевым паддингом подписей. |
| `bench_wasmi_module_cache_by_code_hash` | 500 вызовов `ContractRegistry::call_with_context` и `run_get_method` на нетривиальном `.wasm` (10–100 KiB) с холодным и тёплым кэшем `Engine`+`Module` по `code_hash` | Устранение per-call парсинга/валидации WASM и пересоздания `Engine`; assert: `outcome`, `fuel_used`, `storage`, `events` побайтово совпадают с non-cached `Module::new`. |
| `bench_xshard_escrow_and_xpc_prepare_batch` | `record_legacy_escrow_receipts` + `apply_xpc_source_prepares` на блоке из $N = 1000$ транзакций и $M = 16..256$ `cross_shard_out` (legacy $O(M \cdot N)$ vs `compute_tx_hashes_batched` $O(M + N)$) | Переход от $O(M \cdot N)$ к $O(M + N)$ при росте размера блока; assert: идентичные `state_trie` корни и `xpc_snapshot()`. |
| `bench_tx_hash_and_signing_msg_sponsored_1000` | `compute_tx_hash` + `signing_message` + `verify_signature` на 1000 sponsored PQ-транзакциях (до vs после однократного `split_sponsor_envelope`) | Устранение 3–4× повторных `bincode::deserialize::<SponsorAuthorization>`; assert: побайтово идентичные `tx_hash`, `signing_message()` и `chain_id()`. |
| `bench_apply_hotpath_regression_guard` | Контрольный прогон существующего `stellereum/benches/apply_hotpath.rs` (`apply_mixed_1000`, `verifyonce_1000`) | Подтверждение отсутствия регрессии на plain/mixed hot path. |
