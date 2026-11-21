# SECURITY & PERFORMANCE HARDENING FIXES CONTRACT (`HUNT-SEC-PERF-1`)

Статус: **архитектурный и интеграционный контракт** для следующей волны кодовых агентов.
Зафиксировано по фактическому чтению дерева `stellereum/src/**` на 2026-11-21 (`CONSENSUS_RULESET_VERSION = 6`, `FORK_ID = 0x0f584a46`, `AGENTS.md` §7).

> **Закон замороженного ядра (`AGENTS.md` §7).** Изменения `apply()`, газовой тарификации (`billed_gas`, `fee_for_gas`, `failure_fee_for`, `svm.rs` / `orderbook.rs`), валидности блоков и `state_root` меняют консенсусный переход и **обязаны** вводиться только со spec update + audit note + полным gate, а для активной сети/старых тестов — через явный `activation_height` (`u64::MAX` по умолчанию в `stellereum/src/chain_spec.rs` до согласованного релиза `CONSENSUS_RULESET_VERSION = 7` / нового `FORK_ID` в `stellereum/src/protocol.rs`). Локальные фиксы `parallel.rs` (приведение к каноническому `apply.rs`), `client_ip`, `rpc/*` и локальной политики `mempool.rs` (в пределах допустимых консенсусом блоков) не меняют `FORK_ID` и `state_root` канонического последовательного исполнения.

---

## 1. Классификация 7 подтверждённых багов и уязвимостей

### 1.1 Сводная матрица (Local/Non-Consensus vs Frozen Core §7)

| # | Место (`file:line`) | Суть бага / уязвимости | Класс (`AGENTS.md` §7) | Нужен `activation_height` / `FORK_ID`? | Ссылка на детальный контракт |
|---|---|---|---|---|---|
| **1** | `state_engine/parallel.rs:228-235, 354-366` vs `state_engine/apply.rs:2289-2341` | `auth.sponsor == tx.to`: `plan_plain_tx` берёт pre-tx `recipient` из `snapshot` (`sbal`) и в `commit_plain_plan` перезаписывает списание `fail_fee` со спонсора на `sbal + tx.amount` → инфляция `fail_fee` и расхождение с последовательным `apply.rs` | **Немедленный локальный фикс** (приведение опционального `--parallel-exec` к каноническому `apply.rs`) | **Нет** (канонический `apply.rs` не меняется; перед выкатом проверить, не попадали ли на живой сети plain-tx с `sponsor == to` под `--parallel-exec`) | [§1.2.1](#121-баг-1-parallelrs-authsponsor--txto) |
| **2** | `state_engine/apply.rs:763-770, 2920-2937, 3026-3040` | `bridge_intents`, `rotation_aliases` и `apply_cnvrf_v3` сканируют весь `tx.payload` без остановки на `OpCode::Halt` → бесплатный settle моста и подделка/кража ротации/CN-VRF/downtime-атрибуции чужого валидатора | **Frozen Core §7** (меняет `apply()` и `state_root`) | **Да** (`activation_height` + audit note; при активации — `CONSENSUS_RULESET_VERSION = 7` и `FORK_ID`) | [§1.3.1](#131-баг-2-applyrs-не-останавливается-на-opcodehalt) |
| **3** | `state_engine/apply.rs:186-188, 220, 550-556` | `snapshot_payload_domains` и `oracle_before` пропускают `SysCallCallContractArgs` и `SysCallSubmitPqPriceFeed` → проваленные/ревертнутые tx оставляют мутации контрактов и оракула в состоянии | **Frozen Core §7** (меняет `apply()` и `state_root` при откате) | **Да** (`activation_height` + audit note; при активации — `CONSENSUS_RULESET_VERSION = 7` и `FORK_ID`) | [§1.3.2](#132-баг-3-applyrs-пропускает-syscallcallcontractargs-и-syscallsubmitpqpricefeed-в-откатах) |
| **4** | `state_engine/apply.rs:1704`, `svm.rs:1690-1691, 1720, 1734-1735`, `orderbook.rs:248-275` | `[OpCode::Nop]` списывает `1` nano-STELL вместо `280_000`; `SysCallPlaceOrder` ограничивает level-газ по `.min(64)` при неограниченном числе maker-ордеров на уровне; `SysCallCancelOrder` делает `ensure_working` (клон всех книг) + двойной `O(N)` скан за `100` газа | **Frozen Core §7** (меняет `apply()`, газ, `OutOfGas` и валидность/стоимость блоков) | **Да** (`activation_height` + `CONSENSUS_RULESET_VERSION = 7` / `FORK_ID` + audit note; без гейта ломает старые блоки и тесты) | [§1.3.3](#133-баг-4-тарификация-nop-placeorder-cancelorder) |
| **5** | `client_ip.rs:435-437, 491-498`, `rpc/streams.rs:1413-1415, 1727`, `rpc/auth.rs:59-72` | `::ffff:127.0.0.1` не распознаётся как loopback (`Ipv6Addr::is_loopback` = false) → обход запрета forwarded loopback + расщепление бакетов `v4`/`::ffff:v4`; `rpc_handler`/`ws_handler` отбрасывают `ClientIpSource` (в т.ч. `ForwardedLoopbackRejected` на прокси `127.0.0.1`!) → обход `require_wallet_sign_loopback` | **Немедленный локальный фикс** (edge/transport/RPC) | **Нет** | [§1.2.2](#122-баг-5-client_iprs--rpcstreamsrs--rpcauthrs) |
| **6** | `rpc/writes.rs:177-196` | `stell_mevStats` реализован в `dispatch_writes_inner` (`:243-262`), но отсутствует в `matches!(method, ...)` в `dispatch_writes` (`:177-195`) → всегда `-32601 method not found` | **Немедленный локальный фикс** (RPC dispatch) | **Нет** | [§1.2.3](#123-баг-6-stell_mevstats-в-rpcwritesrs) |
| **7** | `mempool.rs:2208-2241`, `mempool.rs:3054-3082`, `mempool.rs:1868, 2708` | (a) `PendingActivationBuffer` принимает `is_pq_implicit` без проверки подписи и блокирует `self.reserved[tx.from]` жертвы + 2048 глобальных слотов; (b) `estimate_tx_wire_bytes` = `200` для `SysCallActorSend` и др. крупных опкодов; (c) `evict_unexecutable_at` / `sweep_expired` не учитывают `surcharges_for_tx` | **Немедленный локальный фикс** (node-local mempool admission; по §7 требует **audit note + full gate**, но не меняет `apply()`/`FORK_ID`) | **Нет** | [§1.2.4](#124-баг-7-mempoolrs) |

---

### 1.2 Немедленные локальные фиксы (без смены консенсусных правил и `FORK_ID`)

#### 1.2.1 Баг 1: `parallel.rs` (`auth.sponsor == tx.to`)
- **Факт по коду**:
  - В последовательном пути `commit_native_with_floor` (`stellereum/src/state_engine/apply.rs:2289-2341`) сначала выполняется `sp.balance = sbal.saturating_sub(fee_with_surcharge)` (`:2295`), и только затем `recipient.balance = recipient.balance.checked_add(tx.amount)` (`:2333-2337`). При `auth.sponsor == tx.to` (третий сторонний спонсор == получатель; `sponsored_grant()` в `sharding/transaction.rs:1583-1590` исключает только `sponsor == from`) итоговый баланс `tx.to` равен `(sbal - fee_with_surcharge) + tx.amount`.
  - В `plan_plain_tx` (`stellereum/src/state_engine/parallel.rs:228-252`) при `!cross_shard` ветка `match recipient` (`:232-251`) читает исходный `snapshot`-баланс `rbalance` (`== sbal`), вычисляет `new_balance = rbalance + tx.amount` и добавляет `(tx.to, new_balance, rnonce)` **после** `(auth.sponsor, sbal - fail_fee, snonce)`.
  - `commit_plain_plan` (`parallel.rs:354-366`) последовательно перезаписывает `acc.balance = *balance`, затирая списание `fail_fee` и оставляя на счету спонсора `sbal + tx.amount`, при этом `fees_collected` получает `fail_fee` (`parallel.rs:220, 374`) и `apply_block_transition` (`apply.rs:2817-2819`) начисляет `fail_fee` пропозеру → **чистая эмиссия `fail_fee` из воздуха** и расхождение `state_root` с последовательным `apply()`.
  - Кроме того, `checked_add(tx.amount)` на `parallel.rs:233` проверяет переполнение от `sbal` вместо `sbal - fail_fee`.
- **Требуемое исправление**:
  1. В `plan_plain_tx` (`parallel.rs:228-252`): если `auth.sponsor == tx.to`, использовать базу `sbal - fail_fee` (и `snonce`) и проверять `checked_add(tx.amount)` от `sbal - fail_fee`; в `plan.writes` формировать **одну** итоговую запись для `auth.sponsor` (`(tx.to, (sbal - fail_fee) + tx.amount, snonce)`) — это исключает дубликат в `plan.writes` и в `trie_dirty`.
  2. Проверить в `parallel.rs:221-226`: при `tx.from == tx.to` с `auth.sponsor != tx.from` (`sponsored_grant()` гарантирует `sponsor != from`, следовательно `sponsor != tx.to`) существующая ветка уже корректна.
  3. **Совместимость с замороженным ядром**: канонический последовательный `apply.rs` не меняется; фикс лишь восстанавливает инвариант `parallel_exec == sequential` (`parallel.rs:19-21, 118-121`). *(Операционная проверка: перед выкатом убедиться, что в финализированных блоках активной сети до высоты выката не было plain-транзакций с `auth.sponsor == tx.to`.)*

#### 1.2.2 Баг 5: `client_ip.rs` + `rpc/streams.rs` + `rpc/auth.rs`
- **Факт по коду**:
  1. `IpAddr::is_loopback()` для `IpAddr::V6(::ffff:127.0.0.1)` возвращает `false` (Rust `Ipv6Addr::is_loopback` проверяет только `::1`). При этом `TrustedNet::contains` (`client_ip.rs:135-149`) вызывает `v6.to_ipv4_mapped()`, поэтому локальный прокси `::ffff:127.0.0.1` считается доверенным, а заголовок `X-Forwarded-For: ::ffff:127.0.0.1` обходит фильтр `ip.is_loopback()` на `client_ip.rs:492` даже при выключенном `STELL_TRUST_LOOPBACK_FORWARDED`.
  2. Использование `::ffff:a.b.c.d` vs `a.b.c.d` создаёт два раздельных ключа `IpAddr` в `HashMap<IpAddr, ...>` лимитера (`explorer.rs:44`), в `FaucetState` и в строковом `client` (`rpc/streams.rs:899, 2830`) — **bucket split** (удвоение квот и обход банов).
  3. `rpc/streams.rs:1413-1415` (`ws_handler`), `:1727` (`rpc_handler`), `:895-897` (`sse_handler`), `:1832` (`standalone_rate_limit`) вызывают `resolve_client_ip(...).addr`, теряя `ClientIpSource`. Критический сценарий: если локальный прокси (`127.0.0.1`, в дефолтном `STELL_TRUSTED_PROXY_CIDRS`) переслал от удалённого атакующего `X-Forwarded-For: 127.0.0.1`, `resolve_detailed` возвращает `ClientIp { addr: 127.0.0.1, source: ClientIpSource::ForwardedLoopbackRejected }` (`client_ip.rs:494-497`). После `.addr` `rpc_handler` передаёт `Some(127.0.0.1)` в `dispatch`, и `require_wallet_sign_loopback` (`rpc/auth.rs:59-72`) пропускает удалённый запрос к `stell_signMessage` / `stell_signTypedData`!
- **Требуемое исправление**:
  1. В `client_ip.rs`: добавить канонизацию `canonical_ip(ip: IpAddr) -> IpAddr` (`IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip)`) и применять её к `peer` и ко всем извлечённым из заголовков IP в `parse_ip_token` / `resolve_detailed` (`:472-504`), а также в `ClientIp::is_local_client()` (`:435-437`).
  2. В `rpc/streams.rs`, `rpc/mod.rs`, `rpc/writes.rs`, `rpc/reads.rs`, `rpc/state.rs`, `rpc/auth.rs`: передавать `Option<ClientIp>` вместо `Option<IpAddr>` по внутреннему тракту `rpc_handler` / `ws_handler` -> `dispatch` -> `dispatch_writes` -> `handle_sign_message` / `handle_sign_typed_data` -> `require_wallet_sign_loopback`.
  3. В `require_wallet_sign_loopback` (`rpc/auth.rs:59-72`): проверять `Some(client) if client.is_local_client() => None`, иначе отказ `-32001` (тем самым `Forwarded` и `ForwardedLoopbackRejected` всегда отклоняются!).
  4. Для обратной совместимости внешних тестов (`tests/pentest_gov_loop.rs`, `benches/hotpath_probe.rs`) сохранить публичную сигнатуру `handle_rpc_batch_call(..., peer_ip: Option<IpAddr>)` как обёртку над внутренним `handle_rpc_batch_call_client(..., peer_ip: Option<ClientIp>)` (конвертирующую `IpAddr` через `ClientIp::from_peer(canonical_ip(ip))`), а `rpc_handler` должен вызывать `handle_rpc_batch_call_client`.

#### 1.2.3 Баг 6: `stell_mevStats` в `rpc/writes.rs`
- **Факт по коду**: `dispatch_writes_inner` содержит реализацию `"stell_mevStats"` (`rpc/writes.rs:243-262`), `rpc_rate_buckets` перечисляет его (`rpc/streams.rs:1349`), но ранний фильтр `dispatch_writes` (`rpc/writes.rs:177-195`) не включает `"stell_mevStats"`, из-за чего вызов проваливается в `dispatch_reads` и возвращает `-32601 method not found`.
- **Требуемое исправление**: добавить `| "stell_mevStats"` в `matches!(method, ...)` в `rpc/writes.rs:177-195` (без изменения семантики ответа и без auth-гейта, как read-only телеметрия пула в `rpc/tests.rs:8804`).

#### 1.2.4 Баг 7: `mempool.rs` (`PendingActivationBuffer`, `estimate_tx_wire_bytes`, `surcharges_for_tx`)
- **Audit note (`AGENTS.md` §7)**: `mempool admission` относится к критическим правилам ноды, однако все три исправления являются **node-local admission/packing/eviction политикой**: не меняют wire-формат `Transaction`/`Block`, не меняют `apply()`, `state_root` или `FORK_ID`, поэтому `activation_height` не требуется, но обязательны audit note + полный test gate.
- **Требуемые исправления**:
  1. **`PendingActivationBuffer` DoS без подписи (`mempool.rs:2208-2241`)**:
     - **Изоляция резервирования баланса**: разделить `reserved` (подтверждённые пулом транзакции) и `activation_reserved` (непроверенные `is_pq_implicit` в буфере). Метод `reserved_for(&addr)` возвращает их сумму (сохраняя инвариант существующих тестов `mempool.rs:3724, 3768`), НО при поступлении **верифицированной** (`verify_signature_with_registry == true` на `:2257`) `tx.is_pq_activation()` баланс на `:2313` проверяется **только** против `reserved` (без `activation_reserved`), после чего в `:2403-2431` буфер дренируется, `activation_reserved` освобождается, и все поддельные буферизованные транзакции отбрасываются проверкой подписи! Атакующий больше не может заблокировать активацию жертвы.
     - **Структурная валидация и nonce-окно**: до помещения в `PendingActivationBuffer` проверять непустоту и точный размер подписи схемы в `PqSignatureEnvelope` (для `Falcon512`: `0 < env.signature.len() <= MAX_FALCON512_SIG_BYTES`, отклонять пустые/мусорные конверты), `check_nonce_gap` при `ctx.onchain_nonce.is_some()` (чтобы не парковать мусор с `nonce = 1_000_000_000`), и **запретить** ретрансляцию непроверенных `PendingActivationBuffer`-транзакций в P2P gossip/overlay.
     - **Защита глобального буфера (2048 слотов)**: сохранить `MempoolError::Full` на прямом `PendingActivationBuffer::buffer_tx_with_timestamp` при 2048 неистёкших слотах (контракт теста `mempool.rs:4540`), но в `Mempool::insert` перед возвратом `Full` принудительно выполнять `drain_stale(ctx.now, Self::ACTIVATION_BUFFER_TTL_SECS)` (короткий TTL для неподтверждённых записей на пути `insert`, например `30s`, оставляя `sweep_expired` с `STUCK_TX_TTL_SECS = 120s` совместимым с тестом `:4733`) и ввести per-peer throttling в P2P ingress.
  2. **`estimate_tx_wire_bytes` (`mempool.rs:3054-3082`)**:
     - Заменить catch-all `_ => 200` на точный структурный подсчёт для всех переменных/крупных опкодов (`estimate_op_wire_bytes(op, depth)` с ограничением глубины рекурсии, например `MAX_ACTOR_DEPTH = 16`, при превышении — возвращать `MAX_BLOCK_WIRE_BYTES + 1` fail-closed):
       - `OpCode::SysCallActorSend { body, .. }`: `200 + body.iter().map(|child| estimate_op_wire_bytes(child, depth + 1)).sum()` (рекурсивно!);
       - `OpCode::SysCallDeployContract { code }`: `128 + code.len()`;
       - `OpCode::SysCallCallContract { method, .. }`: `128 + method.len()`;
       - `OpCode::SysCallCallContractArgs { method, args, calldata, .. }`: `128 + method.len() + args.len() * 8 + calldata.len()`;
       - `OpCode::SysCallRegisterZkMlModel { model, .. }`: `256 + model.param_count().saturating_mul(8)` (или `bincode::serialized_size` / точный размер полей);
       - `OpCode::SysCallRegisterZkMlSpec { spec, .. }`: `256 + spec.spec_bytes.len() + spec.setup_attestation.len()`;
       - `OpCode::SysCallVerifyPqSignature { pubkey, message, signature, .. }`: `128 + pubkey.len() + message.len() + signature.len()`;
       - `OpCode::SysCallReportEquivocation { evidence }`: `256 + bincode::serialized_size(evidence).unwrap_or(0) as usize`;
       - `OpCode::SysCallEvmCarrier(c)`: `128 + c.evm_tx.len() + c.pq_pubkey.len() + c.evm_signature.len()`;
       - `OpCode::SysCallBindEvmAddress(c)`: `128 + c.pq_pubkey.len() + c.binding_signature.len() + c.evm_signature.len()`;
       - `OpCode::SysCallGovPropose { title, action, .. }`: `256 + title.len() + bincode::serialized_size(action).unwrap_or(0) as usize`;
       - `OpCode::SysCallBridge(intent)`: `256 + bincode::serialized_size(intent).unwrap_or(0) as usize`;
       - `OpCode::SysCallTokenCreate { name, symbol, .. }`: `128 + name.len() + symbol.len()`;
       - Прочие фиксированные опкоды: `64..200`.
     - Так как `insert()` (`mempool.rs:2038`) и `select_multi()` (`:2928, 2982`) используют одну функцию `estimate_tx_wire_bytes`, гарантируется инвариант `admitted => packable` и невозможность собрать блок сверх P2P gossip-лимита.
  3. **Пропуск `surcharges_for_tx` в эвикшене (`mempool.rs:1868, 2708`)**:
     - В `evict_unexecutable_at` (`mempool.rs:1868`) и `sweep_expired` (`mempool.rs:2708`) заменить `None => tx.amount.saturating_add(tx.gas_limit) > balance` на `None => Self::tx_cost(tx) > balance` (где `tx_cost` включает `Self::surcharges_for_tx(tx)` — `45_000` для `is_pq_activation` и `30_000` для `is_evm_carrier_tx`).

---

### 1.3 Баги замороженного ядра (`Frozen Core`, `AGENTS.md` §7) — Gate, Audit Note и совместимость `H-1 / H / H+1`

Все три пункта ниже (Баги 2, 3, 4) меняют результат `apply()`, биллинг газа, откаты доменов состояния или валидность транзакций внутри блока. Они **ЗАПРЕЩЕНЫ** к включению безусловно на работающей сети: без height-gate они ломают пересинхронизацию/реорг исторических блоков (`replay_historical_block`, `ChainState::reorg`) и вызывают раскол при несинхронном обновлении нод.

#### Единый механизм активации и совместимость `H-1 / H / H+1`

1. **Протокольная константа в `stellereum/src/chain_spec.rs`**:
   - Ввести явный height gate (или пару гейтов, если газовый хардфорк выносится отдельно от atomicity-фикса):
     - `EXEC_HARDENING_V1_ACTIVATION_HEIGHT: u64 = u64::MAX` (покрывает Баги 2, 3, 4 — или раздельно `APPLY_HALT_ROLLBACK_ACTIVATION_HEIGHT` и `GAS_HARDENING_V1_ACTIVATION_HEIGHT`, оба **`u64::MAX`** в PR внедрения кода, что означает *inert at all reachable heights*, **байт-идентичность `FORK_ID = 0x0f584a46` и `CONSENSUS_RULESET_VERSION = 6` до момента активации**).
     - Обязательный test-only thread-local override (по шаблону `set_zkml_context_binding_activation_height_for_tests` в `zkml_attestation.rs:190` / `set_genesis_chain_spec_override` в `chain_spec.rs:121`) для детерминированного тестирования границ `H-1 / H / H+1` без поломки существующих тестов!
2. **Активация на живой сети / Ruleset v7**:
   - При переходе к активации (`activation_height != u64::MAX`, например `H` на существующей цепи или `0` на новом genesis):
     - Добавить `EXEC_HARDENING_V1_ACTIVATION_HEIGHT` в `FORK_ID_RULES` (`stellereum/src/protocol.rs:151-175`);
     - Повысить `CONSENSUS_RULESET_VERSION: u32 = 7` (`protocol.rs:101`);
     - Перевычислить `FORK_ID` (`protocol.rs:226`) — старые узлы с `FORK_ID = 0x0f584a46` будут громко отклоняться на handshake (`infnode::proto::negotiate` / `upgrade_halt`), не допуская тихого форка;
     - Обновить `docs/RULESET_V7.md` + `chain_spec::current_activation_schedule()`.
3. **Поведение на границе `H-1 / H / H+1`**:
   - **`height < H` (включая `H-1` и все старые блоки до форка)**: исполняются строго по правилам v6 (все существующие блоки и старые юнит-тесты проходят с тем же `state_root`, что и до патча).
   - **`height == H` (первый блок активации)**: включаются правила v7 (`Halt`-барьер во всех сканерах, полный `snapshot_payload_domains` / `oracle_before`, новый расчёт `billed_gas` и `PlaceOrder`/`CancelOrder`). Переход является **чистой функцией `(block.height, pre-state, block bytes)`**, одинаковой при live finalize, adopt, sync walk, replay и reorg.
   - **`height > H` (включая `H+1` и далее)**: все ноды с новым `FORK_ID` применяют правила v7 детерминированно; ни одна нода старого `FORK_ID` не участвует в консенсусе после рукопожатия.
   - *(Особое внимание: `apply_transaction` — single-tx путь без `block.height` — должен принимать явный `chain_height` либо использовать активный гейт так же, как `apply_block_parallel_fees_at_height`, чтобы не нарушить инвариант `apply_transaction == block_apply`!)*

---

#### 1.3.1 Баг 2: `apply.rs` не останавливается на `OpCode::Halt`
- **Точки в коде**:
  - `stellereum/src/state_engine/apply.rs:763-770` (`bridge_intents` в `execute_payload_with_preverify`);
  - `stellereum/src/state_engine/apply.rs:2920-2937` (`rotation_aliases` в `apply_block_transition`);
  - `stellereum/src/state_engine/apply.rs:3026-3040` (`apply_cnvrf_v3` миграция `v3_state` и `abort_state`).
  - *(Дополнительные сопутствующие сканы для защиты в глубину в том же гейте: `apply_staking_unjail_ops` на `apply.rs:3903` и `apply_equivocation_slash` на `apply.rs:4193` — также не прерываются на `OpCode::Halt`.)*
- **Требуемое исправление (при `height >= H`)**:
  - Заменить `.iter().filter_map(...)` / `for op in &tx.payload` на `.take_while(|op| !matches!(op, crate::svm::OpCode::Halt))` (или `if matches!(op, crate::svm::OpCode::Halt) { break; }` по образцу `apply_gov_ops` в `apply.rs:4468-4470`).
  - В `execute_payload_with_preverify` передать `height: u64` (или `halt_prefix_only: bool`) из `apply_block_parallel_fees_with_events_at_height` (через `execute_payload_at_height`), чтобы `height < H` оставался байт-идентичным, а `height >= H` отсекал post-Halt `SysCallBridge`.
- **Audit Note**: *«HUNT-SEC-PERF-1 / EXEC-HALT-01: В `Svm::execute_inner` (`svm.rs:1579, 2551`) `OpCode::Halt` завершает исполнение и учёт газа; все пост-исполнительные сканеры блока (`bridge_intents`, `rotation_aliases`, `apply_cnvrf_v3`, а также `apply_staking_unjail_ops` и `apply_equivocation_slash`) обязаны рассматривать только executed prefix до первого `OpCode::Halt`, как уже делает `apply_gov_ops` (`apply.rs:4468`). Без этого любой отправитель мог активировать post-Halt `SysCallBridge` без газа или подменить ротацию валидатора в CN-VRF/downtime-атрибуции чужого ключа. Изменение защищено height-gate для сохранения идентичного replay на высоте `< H`».*

#### 1.3.2 Баг 3: `apply.rs` пропускает `SysCallCallContractArgs` и `SysCallSubmitPqPriceFeed` в откатах
- **Точки в коде**:
  - `stellereum/src/state_engine/apply.rs:186-188` (`snapshot_payload_domains`: нет `SysCallCallContractArgs { .. }`);
  - `stellereum/src/state_engine/apply.rs:220` (`snapshot_payload_domains`: нет `SysCallSubmitPqPriceFeed(_)`);
  - `stellereum/src/state_engine/apply.rs:550-556` (`oracle_before`: нет `SysCallSubmitPqPriceFeed(_)`).
- **Требуемое исправление (при `height >= H`)**:
  - Добавить `| SysCallCallContractArgs { .. }` в ветку `touches_contracts = true` (`apply.rs:186-188`);
  - Добавить `| SysCallSubmitPqPriceFeed(_)` в ветку `touches_oracle = true` (`apply.rs:220`);
  - Добавить `| crate::svm::OpCode::SysCallSubmitPqPriceFeed(_)` в условие `oracle_before` (`apply.rs:550-556`).
  - *(При `height >= H` проверять только executed prefix до `OpCode::Halt` для обоих списков.)*
- **Audit Note**: *«HUNT-SEC-PERF-1 / EXEC-ROLLBACK-01: `SysCallCallContractArgs` мутирует `ContractRegistry`, а `SysCallSubmitPqPriceFeed` мутирует `OracleState`, но отсутствовали в `snapshot_payload_domains` и `oracle_before`. При revert после этих опкодов или отказе settlement/`commit_native` мутации не откатывались. Включается с `EXEC_HARDENING_V1_ACTIVATION_HEIGHT`, сохраняя pre-H поведение для исторического replay».*

#### 1.3.3 Баг 4: Тарификация `[Nop]`, `PlaceOrder`, `CancelOrder`
- **Точки в коде**:
  - `stellereum/src/state_engine/apply.rs:1704` (`billed_gas`: `if tx.payload.is_empty() || gas_used == 0 { Self::TX_INTRINSIC_GAS } else { 0 }`);
  - `stellereum/src/svm.rs:205, 1584-1586` (`GAS_NOP = 1`), `:40-41, 113-115, 1690-1691` (`GAS_ORDER_PLACE = 1_200`, `level_gas = (trade_events.len() as u64).min(MAX_MATCH_LEVELS as u64) * GAS_PER_MATCH_LEVEL`), `:1720, 1734-1745` (`GAS_ORDER_CANCEL = 100` + `ensure_working` + скан всех пар/уровней/ордеров);
  - `stellereum/src/orderbook.rs:248-275` (`submit_order_bounded`: `levels_crossed` ограничен `MAX_MATCH_LEVELS = 64`, но `for maker in orders.iter_mut()` на одном уровне не ограничен и не учитывается по числу maker-итераций при `min(MAX_MATCH_LEVELS)` в `svm.rs:1690`).
- **Требуемое исправление (строго за `activation_height`, при `height >= H`)**:
  1. **Минимальный биллинг транзакции (`apply.rs:1704`)**:
     - Ни одна успешная транзакция при `height >= H` не может стоить дешевле `Self::TX_INTRINSIC_GAS` (`280_000`): заменить логику `billed_gas` на `gas_used.max(Self::TX_INTRINSIC_GAS).min(tx.gas_limit)` (эквивалентно полу-базовой стоимости конверта для всех транзакций; `tx.payload.is_empty()` и `[Nop]` оба платят `280_000`, при этом `gas_used > 280_000` не увеличивается на лишние `280_000`, т.е. дорогие контракты не платят двойную цену!).
     - *Защита старых тестов*: комментарий `apply.rs:1683-1686` указывает, что старый тест `bonding_moves_real_funds_and_grants_validator_power` ожидает списания `2_000` газа при `gas_limit = 10_000` для `SysCallStake` (при default `activation_height = u64::MAX`). Гейт `height >= H` (default `u64::MAX`) **гарантирует 100% сохранность** всех старых тестов и исторических блоков, пока гейт не активирован, а в тестах с включённым гейтом проверяется `280_000` за `[Nop]`.
  2. **`SysCallPlaceOrder` (`svm.rs:1690-1691`, `orderbook.rs:248-275`)**:
     - В `orderbook.rs:248-275`: ввести жёсткий лимит на число матчей/итераций за один вызов (`MAX_MATCH_FILLS_PER_ORDER`, например `256` или учёт каждого обработанного maker-ордера в счётчике работы, чтобы 1000 ордеров на 1 уровне нельзя было прогнать за цену 64 уровней) и возвращать число просмотренных уровней/ордеров (или не резать `.min(MAX_MATCH_LEVELS)` при расчёте газа за фактические `trade_events.len()`!).
     - В `svm.rs:41, 1690-1691`: поднять `GAS_ORDER_PLACE` (или учитывать клонирование книги + базовый порог) и тарифицировать **каждый** пройденный ценовой уровень и каждый fill без `.min(MAX_MATCH_LEVELS)` списания в 0 для 65..N-го fill'а (`GAS_PER_MATCH_FILL` / `OutOfGas` до мутации, либо на `working_books` — а т.к. при `OutOfGas` `working_books` отбрасывается целиком, `state_engine` полностью защищён).
  3. **`SysCallCancelOrder` (`svm.rs:40, 1720, 1734-1745`)**:
     - Не клонировать `working_books` (`ensure_working`), пока не найдено совпадение в `ctx.orderbooks` (read-only поиск владельца по `ctx.orderbooks` **до** `ensure_working`!).
     - Поднять `GAS_ORDER_CANCEL` пропорционально реальной стоимости поиска/клонирования книги (например, не ниже базовой стоимости `GAS_ORDER_PLACE` / плюс по числу просмотренных ордеров/уровней `GAS_PER_CANCEL_SCAN`), либо ввести в `OrderbookActor` индекс `order_index: HashMap<u64, (OrderSide, u64)>` для `O(1)` поиска/отмены (под гейтом, если меняет порядок/лимит газа; сама `O(1)` структура данных `order_index` внутри `OrderbookActor` с фиксированной ценой `GAS_ORDER_CANCEL_V2` устраняет `O(N)` DoS полностью).
- **Audit Note**: *«HUNT-SEC-PERF-1 / EXEC-GAS-01: `[OpCode::Nop]` стоил 1 nano-STELL вместо `TX_INTRINSIC_GAS = 280_000` из-за условия `gas_used == 0` в `billed_gas`, а `PlaceOrder`/`CancelOrder` допускали клонирование и скан/матчинг `OrderbookManager` за 100–3_760 газа. Исправление меняет списание газа и границы `OutOfGas` — вводится строго за `activation_height` (default `u64::MAX`, при активации — ruleset v7 + новый `FORK_ID`)».*

---

## 2. Спецификация 5 оптимизаций: критерии эквивалентности и бенчмарков до/после

### 2.1 `ReceiptIndex` (`rpc/state.rs:380-420`, `rpc/reads.rs:1348, 1418, 2226-2249`)
- **Текущее узкое место**: `for_height(h)` (`rpc/state.rs:407-411`) и `stell_getEvents` (`rpc/reads.rs:2226-2249`) сканируют все `MAX_RECEIPTS = 50_000` записей `ReceiptIndex.map` и сортируют выборку на каждый вызов.
- **Целевая оптимизация**:
  - Добавить в `ReceiptIndex`:
    - `by_height: BTreeMap<u64, Vec<(u32, [u8; 32])>>` (инвариант: сортирован или поддерживается в порядке `index`);
    - `by_contract_events: HashMap<[u8; 32], BTreeMap<(u64, u32), [u8; 32]>>` (ключ `(height, index)` → `tx_hash`, без дубликатов при нескольких событиях одного контракта в одной tx).
  - При `insert(r)`: обновлять `by_height` и `by_contract_events` (включая замену уже существующего `tx_hash` и удаление вытесненного `old` при `order.len() > MAX_RECEIPTS`).
- **Критерии эквивалентности**:
  1. Для любой последовательности `insert()` (включая перезапись существующего `tx_hash` с обновлением `events` и вытеснение > `50_000` записей) `for_height(h)` возвращает ту же последовательность `&TxReceipt` в точном порядке `r.index`.
  2. `stell_getEvents` с параметрами `(contract, from_block, to_block, limit)` возвращает идентичный JSON-массив событий в порядке `(r.height, r.index)` и порядке `r.events`.
  3. Сумма записей по всем `by_height` равна `map.len() <= MAX_RECEIPTS`; в `by_contract_events` не остаётся висячих хешей после вытеснения.
- **Критерии бенчмарка до/после**:
  - Фикстура: `ReceiptIndex` заполнен `50_000` чеков (500 блоков × 100 tx/блок, 5% tx с событиями 10 контрактов).
  - Измерять: `for_height` (median/p99 µs/call), `stell_getEvents(contract, 0..500, limit=100)` (median/p99 µs/call), `insert` при полном кэше (с вытеснением, µs/op).
  - Порог приёмки: `for_height` ускорение **>= 50x**, `stell_getEvents` ускорение **>= 50x**, `insert` не медленнее `1.2x` от baseline.

### 2.2 `stell_estimateFee` (`rpc/reads.rs:507-610`, `state_engine/accounts.rs:100-237`)
- **Текущее узкое место**: `simulate_and_estimate_fee` (`rpc/reads.rs:514`) всегда вызывает `st.engine.clone_for_simulation().await`, глубоко клонируя ~24 подсистемы (все аккаунты, `state_trie`, все контракты, все ордербуки, стейкинг, оракул, zkML, `pq_db` и т.д.), даже когда `sim_tx.payload.is_empty()` (`:555`) или payload касается только 1 домена.
- **Целевая оптимизация**:
  1. **Wave 1 (в `rpc/reads.rs`)**: при `sim_tx.payload.is_empty()` пропустить `clone_for_simulation()` целиком; прочитать только `consensus_floor_parts(&sim_tx)` + `mempool.read().await.base_fee` и вычислить `estimated_fee = GAS_BASIC_TRANSFER.max(base_fee).saturating_add(surcharge)`.
  2. **Wave 1 (`accounts.rs`) + Wave 2 (`rpc/reads.rs`)**: добавить `InMemoryStateEngine::clone_for_simulation_for_payload(&self, payload: &[OpCode]) -> Self`, клонирующий только те домены, которые могут быть прочитаны/изменены данным `payload` (плюс `accounts`, `governance.applied`, `consensus_penalty`, `session_keys` при наличии делегации) и оставляющий остальные домены пустыми (не клонируя `state_trie`, `pq_db`, `pq_tree`, `contracts`, `orderbooks`, `zkml_models`, `staking`, `bridge`, если они не затронуты `payload`).
- **Критерии эквивалентности**:
  1. Дифференциальный тест: на наборе из plain transfer, `SysCallTokenTransfer`, `SysCallCallContract`, `SysCallCallContractArgs`, `SysCallPlaceOrder`, `SysCallPmmBuy`, `SysCallStake`, `SysCallVerifyZkMlReexec`, cross-shard, revert и `OutOfGas` ответы `simulate_and_estimate_fee` (JSON `gas_limit`, `estimated_fee`, `base_fee`, `gas_budget`, `gas_ceiling`, коды ошибок) **байт-идентичны** полному `clone_for_simulation()`.
  2. Живой `st.engine` (все домены и счётчики) остаётся неизменным.
- **Критерии бенчмарка до/после**:
  - Фикстура: `InMemoryStateEngine` с 10_000 аккаунтов, заполненным `state_trie`, 50 контрактами, 3 ордербуками.
  - Измерять: latency (median µs/call) для (a) plain `stell_estimateFee`, (b) `SysCallTokenTransfer` `stell_estimateFee`.
  - Порог приёмки: plain transfer ускорение **>= 20x** (0 байт клонирования состояния); token transfer ускорение **>= 3x**.

### 2.3 `Mempool` (`mempool.rs`, `benches/hotpath_probe.rs`)
- **Текущее узкое место**: повторные вычисления `tx.compute_tx_hash()` в `insert` / `evict` / `evict_unexecutable_at` / `sweep_expired` / `tx_age_secs`; линейный до-64-проходный скан в `select_multi` (`:2894-3046`) без кэширования `wire_bytes`/`proof_units`; двойной обход `self.txs` в `fee_payers()` (`:3138-3142`).
- **Целевая оптимизация**:
  1. Предвычисленные поля в хранимой записи пула (или вспомогательной карте `meta: HashMap<TxHash, TxPoolMeta>` с `wire_bytes`, `proof_units`, `tx_cost`, `sponsor`), вычисляемые 1 раз при `insert`.
  2. Оптимизация `select_multi` (при `passes > 1`): кэширование `wire`/`proofs` из `meta` + индекс отложенных nonce по отправителю (когда tx отклонена из-за nonce, продолжать/повторять только для отправителей, чья цепочка продвинулась в текущем проходе, избегая 64-кратного пересканирования уже отвергнутых tx).
  3. Инкрементальное поддержание или однопроходный `fee_payers()`.
- **Критерии эквивалентности**:
  1. На 1_000+ случайных пулах (разные `priority_fee_per_gas`, `gas_limit`, длинные цепочки nonce 1..200 одного отправителя, спонсоры, лимиты `MAX_BLOCK_WIRE_BYTES`/`MAX_BLOCK_PROOF_UNITS`) `select_for_block` и `select_for_block_multi` возвращают **тот же упорядоченный вектор транзакций**.
  2. `fee_payers()`, `senders()`, `reserved_for()`, `next_pending_nonce()`, `evict_unexecutable_at()`, `sweep_expired()` возвращают идентичные результаты.
- **Критерии бенчмарка до/после**:
  - Прогон `stellereum/benches/hotpath_probe.rs` (`admission_plain`, `fee_payers_snapshot`) + новый бенч `select_for_block_multi_10k` (10_000 tx, из них 200-tx цепочка на одного отправителя).
  - Порог приёмки: `select_for_block_multi_10k` ускорение **>= 3x**, `fee_payers_snapshot` без регрессии (или быстрее), `admission_plain` без регрессии (при корректном учёте `estimate_tx_wire_bytes` для Бага 7b).

### 2.4 `client_ip` + `RateLimiter` (`client_ip.rs`, `explorer.rs:42-86`, `rpc/streams.rs`)
- **Текущее узкое место**: `resolve_client_ip` (`client_ip.rs:527-531`) на **каждый** HTTP/WS/SSE запрос (дважды на один HTTP RPC — в `standalone_rate_limit` и `rpc_handler`) вызывает `env::var` 3 раза и парсит/аллоцирует `Vec<TrustedNet>` + `Vec<IpAddr>` цепочки заголовков; `RateLimiter` (`explorer.rs:42-86`) использует единственный `Mutex`.
- **Целевая оптимизация**:
  1. В `client_ip.rs`: кэшировать распарсенный env-конфиг (`ClientIpConfig` через `OnceLock` с явным `resolve_with_config`, сохраняя чистые `resolve_detailed`/`resolve_with` для тестов и позволяя сбрасывать/инжектировать конфиг в тестах); добавить zero-alloc fast-path при `!is_trusted_in(&peer, trusted)` (не читать `headers`) и zero-alloc проход по XFF/Forwarded без создания `Vec<IpAddr>`.
  2. В `rpc/streams.rs`: передавать resolved `ClientIp` из middleware (`standalone_rate_limit`) в `rpc_handler` через `req.extensions()` (fallback на `resolve_client_ip`, если роутер смонтирован без middleware), убирая двойной вызов на запрос.
  3. В `explorer.rs`: шардированный `RateLimiter` (например, `16` шардов `Mutex<HashMap<IpAddr, (u64, u32)>>` по хешу `IpAddr`) для снижения lock contention.
- **Критерии эквивалентности**:
  1. `resolve_detailed` и `resolve_with` выдают идентичный `(canonical_ip(addr), source)` на всём матричном наборе тестов `client_ip::tests` + новых тестах `::ffff:127.0.0.1` и многоходовых XFF-цепочек.
  2. `RateLimiter::check_at(ip, now)` допускает строго `per_sec` запросов для каждой секунды `now` на каждый канонический IP.
- **Критерии бенчмарка до/после**:
  - Микробенч: 100_000 вызовов `resolve_client_ip` (direct peer + XFF 3-hop) и 8-поточный `RateLimiter::check_at`.
  - Порог приёмки: `resolve_client_ip` ускорение **>= 10x** (0 heap-аллокаций на direct-peer и simple XFF), многопоточный `RateLimiter` ускорение **>= 4x**.

### 2.5 `SubscriptionHub` / `FinalizedReadCache` / `state_engine/parallel.rs`

1. **`SubscriptionHub` (`rpc/streams.rs:117-370`)**:
   - **Проблема**: `publish` (`:351-369`) держит `registry.read()`, на каждое событие `Events` вызывает `topic_key()` с аллокацией `String` в цикле по `N` подпискам и клонирует `Value` для каждого `Notification`; глобальный `broadcast` будит все WS/SSE задачи на чужие события.
   - **Оптимизация**: нормализовать `topics` один раз при `subscribe_for` (`NormalizedEventsFilter`); оборачивать общий JSON payload в `Arc<Value>` (или pre-serialized `Arc<str>`) вместо `N` глубоких `result.clone()`; поддерживать per-client счётчик `HashMap<String, usize>` для `O(1)` проверки `MAX_SUBSCRIPTIONS_PER_CLIENT` (без `.values().filter().count()`).
   - **Эквивалентность**: идентичные JSON-уведомления WS/SSE, та же семантика `topic_matches`, те же лимиты `MAX_SUBSCRIPTIONS`, `MAX_SUBSCRIPTIONS_PER_CLIENT`, `WS_MAX_SUBS_PER_CONNECTION`.
   - **Бенчмарк до/после**: `publish(Events)` при `2_000` активных подписках (100 целевых, по 8 топиков) — latency µs/publish и число аллокаций; ожидаемое ускорение **>= 5x**.

2. **`FinalizedReadCache` (`rpc/cache.rs:59-206`)**:
   - **Проблема**: `FinalizedReadKey` аллоцирует `method: String` и `serde_json::to_vec(params)` на каждый `get`/`put`, клонирует `Value` на каждый hit, и при eviction сканирует все 512 записей под одним `Mutex`.
   - **Оптимизация**: enum `CacheMethod` (`Copy`, без `String`), потоковое хеширование `serde_json::to_writer(&mut hasher, params)` без `Vec<u8>`, хранение `Arc<Value>`, LRU-очередь / индекс порядка вставки для `O(1)` вытеснения.
   - **Эквивалентность**: побайтово идентичные JSON-ответы и идентичная логика инвалидации (`filled_tip != tip`, TTL 60s, `evict_height`, `evict_epoch_roots`).
   - **Бенчмарк до/после**: `finalized_read_cache_get` (hit и miss) + `put` при заполненном кэше (512 ключей) — latency ns/op; ожидаемое ускорение **>= 3x** и устранение промежуточных аллокаций на hit.

3. **`state_engine/parallel.rs` (`apply_plain_wave` и `apply_block_parallel_fees_with_events_at_height`)**:
   - **Проблема**: `PlainTxPlan::writes: Vec<...>` аллоцирует вектор на каждую tx в волне (`parallel.rs:72`); `consensus_penalty.read().await.clone()` и `vesting_schedules` клонируются целиком на каждый блок (`:779-792`); `par_chunks` собирает промежуточные `Vec` на каждый chunk (`:505`).
   - **Оптимизация**:
     - Заменить `PlainTxPlan::writes: Vec<([u8; 32], u64, u64)>` на inline-массив `writes: [([u8; 32], u64, u64); 3]` + `write_len: u8`;
     - Заменить полный `.clone()` `consensus_penalty` и полный обход `vesting_schedules` на fast-path `if map.is_empty()` / чтение только адресов текущего блока (`tx.from`);
     - Предвыделенный плоский буфер планов / `par_iter` без вложенных `collect::<Vec<_>>` на chunk.
   - **Эквивалентность**: **байт-идентичный `state_root`**, `applied`, `failed`, `fees_collected`, `status`, `tx_fees`, `events` относительно `parallel_exec = false` (дифференциальный прогон `parallel_wave_matches_sequential_for_randomized_blocks` + новый тест `sponsor == to`).
   - **Бенчмарк до/после**: блок из `2_000` plain PQ-транзакций (disjoint waves) в `--release` — ms/block и tx/s; ожидаемое ускорение этапа планирования/слияния **>= 1.5x** при 0 heap-аллокаций в `plan_plain_tx`.

---

## 3. Матрица владения файлами и список тестов «падало до» для следующей волны

### 3.1 Непересекающаяся матрица владения файлами (`AGENTS.md` §8)

#### Волна 1 (5 параллельных агентов, 0 общих `.rs` файлов)

| Агент | Исключительное владение файлами (scope lock) | Задачи | Зависимости на другие волны |
|---|---|---|---|
| **Agent-1 (`Parallel-Sim`)** | `stellereum/src/state_engine/parallel.rs`<br>`stellereum/src/state_engine/accounts.rs`<br>`stellereum/src/state_engine/tests/parallel_waves.rs` | Баг 1 (`auth.sponsor == tx.to`), Опт. 5c (`PlainTxPlan` inline, selective penalty/vesting read), Опт. 2 backend (`clone_for_simulation_for_payload`) | Нет |
| **Agent-2 (`Frozen-Core`)** | `stellereum/src/state_engine/apply.rs`<br>`stellereum/src/svm.rs`<br>`stellereum/src/orderbook.rs`<br>`stellereum/src/chain_spec.rs`<br>`stellereum/src/protocol.rs` *(только при активации)*<br>`stellereum/tests/security_hardening_frozen_core_tests.rs` *(новый файл)* | Баги 2, 3, 4 строго за `activation_height` (`u64::MAX` по умолчанию) + audit notes + test-only override | Нет |
| **Agent-3 (`Mempool`)** | `stellereum/src/mempool.rs`<br>`stellereum/benches/hotpath_probe.rs` | Баг 7a (`PendingActivationBuffer` изоляция `activation_reserved` + structural/nonce/TTL защита), Баг 7b (`estimate_tx_wire_bytes` рекурсия и крупные опкоды), Баг 7c (`tx_cost` с `surcharges_for_tx` в `evict_unexecutable_at`/`sweep_expired`), Опт. 3 (`meta` + `select_multi` + бенч) | Нет |
| **Agent-4 (`Edge-IP`)** | `stellereum/src/client_ip.rs`<br>`stellereum/src/explorer.rs` | Баг 5a (канонизация `::ffff:127.0.0.1` и `v4`-mapped в `client_ip.rs`), Опт. 4 (`ClientIpConfig` cache, zero-alloc fast-path, шардированный `RateLimiter` в `explorer.rs`) | Нет |
| **Agent-5 (`RPC`)** | `stellereum/src/rpc/mod.rs`<br>`stellereum/src/rpc/auth.rs`<br>`stellereum/src/rpc/writes.rs`<br>`stellereum/src/rpc/reads.rs`<br>`stellereum/src/rpc/state.rs`<br>`stellereum/src/rpc/streams.rs`<br>`stellereum/src/rpc/cache.rs`<br>`stellereum/src/rpc/tests.rs` | Баг 5b (`Option<ClientIp>` + `is_local_client()` в `require_wallet_sign_loopback`, сохранив legacy-обёртку `handle_rpc_batch_call`), Баг 6 (`stell_mevStats` в `dispatch_writes`), Опт. 1 (`ReceiptIndex`), Опт. 2 fast-path для empty payload в `stell_estimateFee`, Опт. 5a (`SubscriptionHub`), Опт. 5b (`FinalizedReadCache`) | Потребует 3-строчного подключения `clone_for_simulation_for_payload` в Волна 2 |

#### Волна 2 (после слияния Волны 1)
- **Agent-5 (`RPC` follow-up, только `stellereum/src/rpc/reads.rs` + `stellereum/src/rpc/tests.rs`)**: переключить непустой путь `simulate_and_estimate_fee` с `clone_for_simulation()` на `clone_for_simulation_for_payload(&sim_tx.payload)` от Agent-1 + дифференциальный тест и бенч.
- **Release/Fork Coordinator (отдельный коммит при выкате хардфорка)**: переключение `EXEC_HARDENING_V1_ACTIVATION_HEIGHT` с `u64::MAX` на целевую высоту `H`, bump `CONSENSUS_RULESET_VERSION = 7` + добавление в `FORK_ID_RULES` (`protocol.rs`) + `docs/RULESET_V7.md`.

---

### 3.2 Обязательные тесты «падало до» (`FAIL-BEFORE` Regression Matrix)

Каждый агент обязан сначала воспроизвести/написать тест, который **падает на текущем коде (до фикса)**, и доказать его прохождение после фикса:

| ID | Агент | Имя теста (рекомендованное) и целевой файл | Что воспроизводит («падало до» на текущем коде) | Что проверяет после фикса |
|---|---|---|---|---|
| **T1** | Agent-1 | `parallel_sponsored_tx_sponsor_equals_recipient_matches_sequential` (`state_engine/tests/parallel_waves.rs`) | Блок с plain sponsored tx, где `auth.sponsor == tx.to` и `--parallel-exec`: баланс `tx.to` становится `sbal + amount` (инфляция `fail_fee`), расходится `state_root` с `parallel_exec = false` | Одинаковый `state_root` и баланс `(sbal - fee) + amount`, `sum(balances) + fees_collected == const` |
| **T2a** | Agent-2 | `post_halt_bridge_intent_is_ignored_after_activation` (`tests/security_hardening_frozen_core_tests.rs`) | Tx `[OpCode::Halt, OpCode::SysCallBridge(deposit)]` при `height >= H`: до фикса мост зачисляет депозит без оплаты `GAS_BRIDGE_INTENT` | При `height >= H` мост не исполняется; при `height < H` сохраняется совместимость с legacy |
| **T2b** | Agent-2 | `post_halt_rotate_validator_does_not_forge_alias_or_cnvrf_migration` (`tests/security_hardening_frozen_core_tests.rs`) | Посторонняя успешная tx `[OpCode::Halt, OpCode::SysCallRotateValidatorKey { old_validator: victim, new_validator: attacker }]`: до фикса `rotation_aliases` и `apply_cnvrf_v3` мигрируют чужого валидатора | При `height >= H` alias, `cnvrf_v3` и `cnvrf_abort` для `victim` остаются нетронутыми |
| **T3a** | Agent-2 | `call_contract_args_rolls_back_on_commit_failure` (`tests/security_hardening_frozen_core_tests.rs`) | Tx с `SysCallCallContractArgs` (мутирует storage) + последующий отказ `commit_native` / settlement: до фикса мутация `contracts` остаётся в состоянии | При `height >= H` состояние `contracts` и `state_root` полностью откатываются к pre-tx |
| **T3b** | Agent-2 | `submit_pq_price_feed_rolls_back_on_revert_and_commit_failure` (`tests/security_hardening_frozen_core_tests.rs`) | Tx `[SysCallSubmitPqPriceFeed(valid), OpCode::Transfer { amount: u64::MAX }]` (revert) или отказ commit: до фикса оракул сохраняет цену | При `height >= H` цена в `oracle` не появляется после revert/отказа (при сохранении sticky breaker latch, если сработал) |
| **T4a** | Agent-2 | `nop_payload_pays_tx_intrinsic_gas_after_activation` (`tests/security_hardening_frozen_core_tests.rs`) | Tx `[OpCode::Nop]` с `governed_base = 0`: до фикса `fee_for_gas` списывает `1` nano-STELL вместо `280_000` | При `height >= H` списывается `TX_INTRINSIC_GAS = 280_000`; при `height < H` старые тесты (`gas_limit = 10_000`, `SysCallStake`) не сломаны |
| **T4b** | Agent-2 | `place_order_many_makers_single_level_and_cancel_order_gas_enforced` (`tests/security_hardening_frozen_core_tests.rs`) | (1) `PlaceOrder` против >64 maker-ордеров на одном ценовом уровне с малым `gas_limit`: до фикса `.min(64)` позволял матчить сотни ордеров бесплатно; (2) `CancelOrder` с большим ордербуком за `100` газа | При `height >= H` перерасход работы корректно бьётся в `OutOfGas` / адекватную цену |
| **T5a** | Agent-4 | `ipv4_mapped_loopback_rejected_and_buckets_unified` (`client_ip.rs` unit tests) | `resolve_detailed` с `X-Forwarded-For: ::ffff:127.0.0.1` при `trust_loopback_forwarded = false`: до фикса возвращал `Forwarded(::ffff:127.0.0.1)`; разные бакеты для `1.2.3.4` и `::ffff:1.2.3.4` | Возвращает `ForwardedLoopbackRejected` и peer; `1.2.3.4` и `::ffff:1.2.3.4` дают один канонический `IpAddr::V4(1.2.3.4)` |
| **T5b** | Agent-5 | `wallet_sign_rejects_forwarded_loopback_and_rejected_claim_via_http_and_ws` (`rpc/tests.rs`) | Запрос `stell_signMessage` с прокси `127.0.0.1` и `X-Forwarded-For: 127.0.0.1` (или `STELL_TRUST_LOOPBACK_FORWARDED=1`): до фикса `rpc_handler`/`ws_handler` теряли `ClientIpSource` и пускали в `require_wallet_sign_loopback` | Отказ `-32001` для `Forwarded` и `ForwardedLoopbackRejected` на HTTP и WS |
| **T6** | Agent-5 | `stell_mev_stats_is_reachable_via_rpc_dispatch` (`rpc/tests.rs`) | Вызов `stell_mevStats` через `dispatch` / `rpc_handler`: до фикса возвращает `-32601 method not found` | Возвращает `Ok` со статистикой `epoch`, `sealed`, `plain`, `sealed_share` |
| **T7a** | Agent-3 | `unverified_activation_buffer_cannot_block_real_pq_activation` (`mempool.rs` unit tests) | Злоумышленник вставляет поддельную `is_pq_implicit` с `amount = balance - fee` без валидной подписи, затем владелец шлёт реальную подписанную `is_pq_activation`: до фикса владелец получал `InsufficientBalance` | Владелец успешно активируется, буфер дренируется, поддельная `is_pq_implicit` отклоняется с освобождением резерва |
| **T7b** | Agent-3 | `estimate_tx_wire_bytes_counts_nested_actor_send_and_large_ops` (`mempool.rs` unit tests) | Tx с `SysCallActorSend` содержащей большой `body` (например, `SysCallDeployContract { code: vec![0; 512_000] }` или вложенные `SysCallActorSend`): до фикса `estimate_tx_wire_bytes` давал `~456` байт вместо `>500 KiB` и пускал гига-tx сверх `MAX_BLOCK_WIRE_BYTES` | Оценка честно превышает порог и отклоняет oversize-tx (`TxTooLarge`) |
| **T7c** | Agent-3 | `evict_unexecutable_and_sweep_include_activation_and_carrier_surcharges` (`mempool.rs` unit tests) | `is_pq_activation` (или `SysCallEvmCarrier`) tx при балансе `amount + gas_limit <= balance < amount + gas_limit + 45_000`: до фикса `evict_unexecutable_at` и `sweep_expired` не удаляли неисполняемую tx | Обе процедуры удаляют транзакцию и освобождают её резервацию |
| **T-Opt1..5** | Agents 1,3,4,5 | Дифференциальные и benchmark-тесты по §2.1–§2.5 | Проверка байт-идентичности ответов/корней и фиксация замеров `до` и `после` | Подтверждение эквивалентности и целевых порогов ускорения |

---

## 4. Чеклист приёмки следующей волны (Gate по `AGENTS.md` §4)

1. Ни один агент не выходит за границы своего scope lock в §3.1.
2. Запрещены `todo!()`, `unimplemented!()`, `FIXME`, ослабление существующих тестов.
3. Все баги замороженного ядра (2, 3, 4) снабжены height-gate (default `u64::MAX` до координации ruleset v7), audit note в коде и тестами границы `H-1 / H / H+1`.
4. Для каждого фикса приведены:
   - подтверждённый прогон теста «падало до -> прошло после»;
   - для оптимизаций — дифференциальный тест эквивалентности и честно измеренные числа `до/после` в `--release` (`AGENTS.md` §5);
   - зелёный `./scripts/verify_testnet_ideal.sh` (или `cargo clippy --all-targets -- -D warnings` + `cargo test --no-fail-fast` по scope + `consensus_liveness_harness` для consensus-adjacent изменений).
