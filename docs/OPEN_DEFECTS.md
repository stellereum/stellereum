# OPEN_DEFECTS — реестр найденных дефектов и статус закрытия

Snapshot: после пентеста-2 и кросс-кат свипа. Рабочие логи ревью/пентеста
удалены из публичного дерева (см. `docs/audits/INTERNAL_REVIEW_ARCHIVE.md`);
этот реестр сохраняет результаты и тесты-пины, по которым они закрыты.
Статус: Ruleset v7; `UP-5` (`stellereum-upgrader`) закрыт в дереве.
Обновлено на HEAD `c58375443` (+ HEIGHT-SPLIT wave; закрыты `--owner-key` и `store_mail`).
Дополнено 2026-11-26 по Волнам 9–15; снимок рабочего дерева — HEAD `ab0adbf08`
плюс незакоммиченные изменения (см. `docs/audits/AUDIT_HANDOFF_2026-11-26.md`).
Этот раздел ниже — единственное место, где статусы Волн 9–15 подтверждены
чтением кода; прогоны `cargo`/`node --test`/скриптов не выполнялись.
Дополнено 2026-11-21 по контрактам `docs/specs/05_LOCK_SAFETY_P0.md`,
`06_BRIDGE_RELEASE_AUTHORIZATION_DRAFT.md`, `07_PQ_VALIDATOR_LIFECYCLE_DRAFT.md`,
`LIGHT_CLIENT_AND_EVM_INDEX_CONTRACT.md`, `SECURITY_HARDENING_FIXES_CONTRACT.md`,
`FAUCET_AND_EXPLORER_HARDENING_CONTRACT.md`, `WASM_XSHARD_PMM_HARDENING_CONTRACT.md`,
`W1_INCREMENTAL_SNAPSHOTS_CONTRACT.md`, `W4_ECONOMICS_PRODUCT_CONTRACT.md`,
`W2_DATA_PLANE_CONTRACT.md` и `RULESET_V7_ACTIVATION_BLUEPRINT.md` (после `W0-CONSOLIDATE-GATE`).

Статусы: **FIXED** — код исправлен и есть тест «падало до»; **DEPLOYED** — то же,
плюс бинарь на A/B/D; **FIXED (локально, не задеплоено)** — правка есть в рабочем
дереве, но миграция/выкат не выполнены; **ASSIGNED** — в работе у агента;
**OPEN** — только контракт и/или fail-before тест, кода фикса нет; **ACCEPTED** —
осознанно принятый риск с обоснованием; **BY DESIGN** — ограничение по замыслу;
**SEPARATE SYSTEM** — вынесено в отдельную систему (см. конец документа).

## P0 — блокеры безопасности/живучести

P0-DOWNTIME-EVIDENCE-HALT (FIXED + выкачено, 2026-11-24, halt ~8 часов).
Живой случай: на высоте 253 120 набор выродился в 4 членов с мощностью **1**
каждый, затем активировался `{A,D}`. Блок 253 120 финализирован и лежит в сторе,
но его встроенный precommit-QC под набором, который резолвится для этой высоты,
даёт «0 из 3 требуемой мощности». Поэтому
`restore_last_decision_from_finalized_block` падал на **всех** членах, взводил
`parent_evidence_missing`, и `propose()` отказывался занимать слот «до
восстановления проверенным решением пира». Отказывались все → решение не могло
появиться никогда: самоподдерживающийся halt. Плюс `release_height` B/C были
выше замороженного tip, поэтому и вернуть их было нельзя (замкнутый круг).
Фикс: при непроверяемом доказательстве **собственного** финала нода переходит в
уже определённое протоколом состояние «решение родителя неизвестно»
(`last_decision = None`; пустой `last_qc` каноничен, апплаер детерминированно
пропускает атрибуцию). Доказательство не фабрикуется, проверки не ослабляются;
цена — одна высота без учёта downtime, со следующего блока доказательства
нормальные. Проверено живьём: A и D начали финализировать за секунды
(114/118 блоков за 35 с), выкачено на все 4 ноды. **Отдельный вопрос** —
почему набор был «4 члена по мощности 1» — разобран ниже (RCA 2026-11-25:
это конфиг-набор бутстрапа, а не вывод `to_validator_set()`).

RCA (2026-11-25, диагноз закрыт; код стейкинга/консенсуса НЕ менялся):

* **`to_validator_set()` тут ни при чём.** `StakingLedger::to_validator_set`
  (`stellereum/src/staking.rs:2682-2697`) возвращает `self_bond + delegated`
  как есть: ни деления на сумму/НОД, ни `max(1, …)`, ни повторного/пропущенного
  множителя `1e9`. При замороженном `MIN_VALIDATOR_BOND = 1000 * 1e9`
  (`staking.rs:62`) каждый избранный валидатор несёт `>= 1e12` мощности — это
  подтверждает живой журнал: `[48fd69d1:2000000000000, 5762c331:1895140009773,
  9865d36e:1694725316015, df3d10f3:1985720492676]`. Набор «4 × мощность 1» —
  это **конфиг-набор бутстрапа**: `node/bootstrap.rs:660-665`
  (`build_validator_set`) добавляет ровно по единице мощности на каждого
  валидатора из `validators:`; журнал при каждом старте печатает
  `Consensus: 4 validator(s), quorum power 3`.
* **Цепочка отказа.** Рантайм стартует с конфиг-набором; на restore
  ledger-набор ставится со сдвигом `ledger_height + 1`
  (`sharding/topology.rs:376-378`), а первая запись истории —
  `(0, config_set)` (`runtime/consensus_step.rs:2577-2581`). Поэтому
  `validator_set_for_height(H)` для высоты финализированного тип `H`
  выбирает запись `(0, config_set)` (`consensus_step.rs:2683-2710`): 4 члена
  по 1, `quorum = floor(2*4/3)+1 = 3`. Встроенный precommit-QC типа собран
  µQC-сертификатом под реальным ledger-набором (у которого число членов уже
  отличалось после джейлов); атрибуция под конфиг-набором fail-closed
  отвергает сертификат по несовпадению `committee_size`
  (`consensus/types.rs:2560-2566`, `3041-3132`) → 0 подписантов →
  «0 из 3 требуемой мощности» → `parent_evidence_missing` → самоподдерживающийся
  halt. Наблюдённый 0 сам доказывает, что `n_real != 4`: при `n_real == 4`
  комитет µQC — это все 4 id в сортированном порядке (выбор при `k == n` не
  зависит от мощностей, `sortition.rs:505-509`), поэтому под конфиг-набором
  подписи атрибутировались бы и дали `>= 3`. «Затем активировался `{A,D}`» —
  это уже ledger-набор, просевший до 2 членов (журнал: `4 -> 3 -> 2`), он и
  был поставлен в историю с активацией `H+1`.
* **Предусловия воспроизведения:** (1) рестарт/restore в точке, где высота
  финализированного типа равна высоте последнего локального
  domain/ledger-снапшота (типичный at-tip рестарт), либо любая ситуация, когда
  высота типа меньше первой активации ledger-набора в истории процесса;
  (2) встроенный QC типа собран под набором, отличающимся от конфиг-набора
  числом членов (любая цепь с джейлами/ротациями); (3) непустой `validators:`
  в конфиге (4 записи → 4 × 1). Safety-правила не нарушены: резолв в конфиг-
  набор — это консервативный fail-closed (древний QC отвергается, чужой
  кворум не принимается); дефект — liveness/самовосстановление.
* **Тест-пин:** `stellereum/tests/rca_degenerate_validator_set.rs` — (1)
  инвариант «4 бонда дают мощность, пропорциональную стейку, total > 4,
  quorum > 1» (исключает гипотезу нормализации); (2) детерминированное
  воспроизведение «0 из 3» (µQC под набором из 3 членов, атрибуция под
  конфиг-набором из 4 × 1); (3) fail-before `#[ignore]`
  `restart_at_the_finalized_tip_must_attribute_the_tip_qc` — рестарт на тип
  должен уметь проверить его собственный QC.
* **Что осталось (не в этой волне):** персистентная/восстанавливаемая история
  наборов (или вывод набора на высоту `H` из снапшота `H-1`), чтобы
  `validator_set_for_height(tip)` не падал в конфиг-набор. Точное число членов
  реального набора именно на 253 120 по сохранившимся журналам не
  восстановимо (journald ротирован, store на B без заголовков той высоты);
  механизм от числа членов не зависит — достаточно `n != 4`.

P0-READINESS-DEAD (DEPLOYED на A/B/C/D в 7bc1bf56, 2026-11-25).
`GatewayState::set_ready_peers` / `note_ready_finalized` не имели ни одного вызова,
поэтому `/readyz` и `stell_ready` всегда отдавали 0 — любой health-check снял бы
живую ноду из ротации. Исправлено: readiness-хэндл публикуется процесс-глобально
(`explorer::register_readiness` из `serve()`), драйвер сообщает число пиров каждые
20 тиков и финализированную высоту в точке установки блока
(`note_readiness_finalized`). Сеттеры — no-op, если explorer не поднят. Алерты
больше не зависят от гейджа (`FalconSignRate` переведён на
`changes(stell_consensus_height[5m])`), но теперь он честный.

P0-JAIL-BUDGET-16S (MITIGATED автоматическим unjail, 2026-11-24, availability:
one hiccup = 20+ minutes below 4/4). При `STELL_MIN_BLOCK_MS=400` бюджет джейла =
42 мисса = **16.8 с**. Живой случай: `nodeB` делит машину со сборками и дважды
упал в джейл; `nodeC` падал в тех же окнах — набор проседал до **2/4 (кворум
2/2)**. Частично закрыто: `scripts/auto-unjail.sh` (systemd user service
`stell-auto-unjail`, опрос 60 с) возвращает узел сразу после `release_height`,
как только его высота в пределах `AUTO_UNJAIL_MAX_GAP` от тип — только
`validator unjail`, холодные ключи остаются на своих нодах, есть cooldown и
`--dry-run`. Остаётся: (а) 2 vCPU и вынос сборок с валидаторных хостов;
(б) поднять бюджет (42 → 200+ миссов) через высоту активации, поскольку порог
консенсусно-видим: разные пороги у нод дадут разные наборы. Правило «никаких
тяжёлых сборок при наборе < 4/4» остаётся в силе; сборки идут `taskset -c 8-11
nice -n 19`.

→ ЧАСТИЧНО ЗАКРЫТО (Волна 10, 2026-11-26): механизм `JAIL_BUDGET_V2` /
`DOWNTIME_MISS_THRESHOLD_V2 = 200` (80 s при 400 ms) реализован и покрыт
тестами, но гейт `JAIL_BUDGET_V2_ACTIVATION_HEIGHT` остаётся `INERT
(u64::MAX)`; оперативная митигация `auto-unjail` по-прежнему обязательна.
См. «Волна 9–15».

P0-PEER-SNAPSHOT-ANCHOR (FIXED в дереве, ожидает выката `cf054343`, 2026-11-25).
Исправлено в Волне 2 (`e7246c5c2`) и Волне 7 (`ae493a270`):
1. `verify_snapshot_anchor_with_sets_and_schedule` + строгий `validator_set_for_height_strict`
   (без тихого фоллбека в конфиг-набор 4×1); `validator_set_history_v1` сохраняется и
   восстанавливается через `Storage`, а at-tip restore сеет bonded-набор на высоте `ledger_height`.
2. `retro_publish_blocks` публикует неизменяемые заголовки (`_h_`, `_h2_`, `_hi_`) в полосе
   `Pointer` до `_hq_` без сдвига `shard_head`, глубина расширена до snapshot span.
3. `try_snapshot_sync_with_persistence` сохраняет граничный блок, снапшоты и `finalized` до
   `advance_to_verified_snapshot`.
Тесты: `tests/w2_snapshot_anchor_tests.rs` (12/12), `tests/rca_degenerate_validator_set.rs` (3/3,
ранее `#[ignore]` разблокирован), `tests/w7_storage_recovery_fixes.rs::w6_a2_3`.

P0-SAFETY-BOOT-ONE-BLOCK (FIXED в дереве, ожидает выката `cf054343`, 2026-11-25).
Закрыто полностью (graceful + hard-`SIGKILL`):
- `TimeoutStopSec=300` (`20-stop-timeout.conf`) для graceful drain (до 240 с);
- Write-ahead `put_block` + `set_finalized` **до** `safety.advance_height` на всех путях
  финализации, adoption (`adopt_committed_with_write_ahead`) и `walk_chain_once_with_lanes`;
- Proof-carrying `reconcile_boot_sigkill_gap` (`src/safety.rs`) при старте: если `safety_record_v1`
  опережает `storage.finalized()`, проверяет локальные блоки, связку `prev_hash` и встроенные
  `precommit_qc`, допроигрывает состояние вперёд без ослабления safety (при отсутствии или
  подделке блока/QC по-прежнему уходит в карантин).
Тесты: `tests/w2_safety_boot_reconcile_tests.rs` (3/3), `adopt::w7_adopt_tests` (2/2).

## P1 — высокий риск

| ID | Дефект | Статус | Где |
|---|---|---|---|
| H1-net | `BodyPull` широковещательный и повторяемый | DEPLOYED (served-once + 8/с) | consensus_net.rs |
| H4/F-9 | парковщик compact без аутентификации/ре-арма | DEPLOYED | consensus_net.rs |
| F-3/R8 | at-tip по тишине отключал catch-up навсегда | DEPLOYED (BlindProbe 10 мин) | policy.rs |
| S5-7/RX-SILENCE | at-tip валидатор, потерявший только ВХОДЯЩИЙ consensus-трафик (votes/proposals/commits), продолжал ждать `AT_TIP_PROBE_INTERVAL_MS = 120 s`, тогда как downtime-бюджет `42 × 800 ms = 33.6 s` — jail задолго до probe. Тишина — единственный симптом односторонней потери push, «at tip» по отсутствию ahead-доказательств её не видит. | **FIXED (локально, не задеплоено)**: `RX_SILENCE_PROBE_MS = 10_000` + чистый `at_tip_silence_due(now, last_rx, last_probe)`; при at-tip, тишине ≥ 10 s и НЕ наступившем 120 s backstop — ровно один bounded head/QC probe (`RX_SILENCE_PROBE_BUDGET_MS = 500`), не чаще одного на окно, `last_catchup` не сдвигается (120 s backstop сохраняет расписание), при живом трафике не запускается, acceptance не меняется. Тесты: `tests/h9_rx_silence_probe.rs` (5, fake clock: one-per-window, steady traffic, miss не лупит, границы/бюджет, сброс окна кадром). | node/policy.rs, node/consensus_driver.rs |
| F-4 | высота proposal из неподписанного конверта | DEPLOYED | driver / policy |
| F-5 | далёкий `Committed` проверял QC до дешёвого reject | DEPLOYED | driver |
| R4 | compact-only proposals ломают mixed-version | **FIXED** (UP-1) | compact/consensus_net |
| mesh-delivered | один overlay-успех маскировал N провалов | DEPLOYED | network.rs |
| Committed-skip | mesh-shortcut глотал `Committed` для suspected | DEPLOYED | consensus_net.rs |
| dead-peer path | ретрай мёртвого пира на каждом кадре; write считался liveness | DEPLOYED | network.rs |
| DHT fanout | lookup фан-аутил на всех пиров (`degree^ttl`) | DEPLOYED | infnode/dht.rs |
| endpoint poisoning | третья сторона переписывала endpoint закреплённого пира | DEPLOYED | infnode/node.rs |
| 2PC window | COMMIT перестаёт re-emit за ~46 с до ретайра → target не получит кредит | **FIXED** (HUNT-4) | xshard2pc.rs |
| block caps | sealed+plain union обходит `MAX_BLOCK_TXS/GAS` | **FIXED** (HUNT-2) | mev_sync.rs |
| QC power | split-гейт — count, не power: N=191 требует всех 128 | **FIXED** (HUNT-1) | sortition/types |
| proof caps | валидатор не проверяет wire/proof-бюджеты продюсера | **FIXED** (HUNT-4) | consensus_step/mempool |
| recovery | walk ≤256 при снапшотах до 1100 → на halted цепи нет самовосстановления | **FIXED** (UP-3) | node/sync.rs |
| upgrade gate | `UPGRADE_EXEC_ACTIVATION_HEIGHT = u64::MAX`, гейт в константе | **FIXED** (UP-2) | governance/chain_spec |
| BRIDGE-EVIDENCE-CHALLENGE | `DepositProof`-депозиты записываются с `via_quorum: false` даже для `QuorumAttested`, а `Challenge` их отвергает → скомпрометированный 2/3 кворум обходит optimistic challenge, прислав `DepositProof` вместо `Attest`. | **FIXED (локально, не активировано)**: на `>= H` обход `!record.via_quorum` убран (DepositProof challengeable в `CHALLENGE_MAX_AGE_SECS`); в `Resolve` кворумная `RETRACTION` проверяется ДО confirm. `bridge_dispute_tests` 12/12, `bridge_challenge_tests` 5/5. | `docs/specs/06_BRIDGE_RELEASE_AUTHORIZATION_DRAFT.md` §0.3, §2.4; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md`; `stellereum/tests/bridge_dispute_tests.rs` |
| BRIDGE-PQ-HEIGHT-KEY | `distinct_falcon_signers` читает process-local `PQ_VALIDATOR_KEYS` вместо committed height-indexed `PqRegistry`; модельная подпись в `vuln_hunt5` уже исправлена, консенсусный bridge-путь — нет. | **FIXED (локально, не активировано)**: `PqKeyLookup` + `verify_quorum_signatures_at_height`/`distinct_falcon_signers_at_height`; `get_validator_pq_key` удалён. Ниже `H` — `PreV2ConsensusLookup` (replay байт-в-байт), на `>= H` — только committed ключи; `plan_at_height` использует `verify_evidence_at_height`/`verify_quorum_retraction_at_height`. | `docs/specs/06_BRIDGE_RELEASE_AUTHORIZATION_DRAFT.md` §0.4, §3; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md` |
| PQ-REMOTE-SIGNER | `remote_signer.rs` типизирован под Ed25519 (32B ключ, 64B подпись); Falcon-512 подписывается локально после `self.sign_bytes`, поэтому HSM/remote-путь не покрывает консенсусные подписи. | **FIXED (локально, не активировано)**: `PqSigner`/`LocalPqSigner`/`RemotePqSigner` v2 (`/v2/public_key`, `/v2/sign`, Falcon-512 `897B`/`666B`), `ConsensusSignRequest` anti-oracle, запрет локального фоллбека при `STELL_REMOTE_SIGNER_URL`, `SafetyRecordStore` check-persist-then-sign сохранён. `r3_pq_registry_signer_tests`, `r3_runtime_node_rpc_cli_tests` 6/6. | `docs/specs/07_PQ_VALIDATOR_LIFECYCLE_DRAFT.md` §0.3, §3, §4.3 п.5; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md` |
| SEC-PARALLEL-SPONSOR | При `auth.sponsor == tx.to` `plan_plain_tx` / `commit_plain_plan` затирали списание `fail_fee` и эмитили его из воздуха; `state_root` расходился с последовательным `apply.rs`. | **FIXED (локально, не задеплоено)**: одна итоговая запись `(sbal - fail_fee) + tx.amount` и overflow-ветка в `state_engine/parallel.rs` (прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён). | `docs/specs/SECURITY_HARDENING_FIXES_CONTRACT.md` §1.2.1; `stellereum/src/state_engine/tests/parallel_waves.rs` (`parallel_sponsored_tx_sponsor_equals_recipient_matches_sequential`) |
| SEC-GAS-BASE-CLOB | `[OpCode::Nop]` стоит 1 nano вместо `TX_INTRINSIC_GAS = 280_000`; `PlaceOrder` ограничивает газ по `.min(64)` при неограниченном числе maker-ордеров на уровне; `CancelOrder` клонирует все книги и дважды сканирует за 100 газа. | **FIXED (локально, за гейтом R1 до активации в R5)**: `billed_gas_at` (`gas_used.max(TX_INTRINSIC_GAS).min(tx.gas_limit)`), `MAX_MATCH_FILLS_PER_ORDER = 256` в `orderbook.rs`, снятие `.min(MAX_MATCH_LEVELS)` в `SysCallPlaceOrder` и read-only owner check до `ensure_working` + `GAS_ORDER_CANCEL_HARDENED` в `svm.rs` за `EXEC_HARDENING_V1_ACTIVATION_HEIGHT` (`r1_frozen_apply_svm_tests`, `parallel == sequential`). | `docs/specs/SECURITY_HARDENING_FIXES_CONTRACT.md` §1.3.3; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md`; `stellereum/tests/r1_frozen_apply_svm_tests.rs` |
| SEC-MEMPOOL-BUFFER | `PendingActivationBuffer` резервировал баланс по неподписанной `is_pq_implicit` (2048 глобальных слотов), `estimate_tx_wire_bytes` давал 200 B для крупных опкодов, а `evict_unexecutable_at` / `sweep_expired` игнорировали surcharge. | **FIXED (локально, не задеплоено)**: `activation_reserved` изолирован, рекурсивный `estimate_op_wire_bytes`, `tx_cost` с surcharge в `mempool.rs` (прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён). | `docs/specs/SECURITY_HARDENING_FIXES_CONTRACT.md` §1.2.4; `stellereum/src/mempool.rs` (`unverified_activation_buffer_cannot_block_real_pq_activation`, `estimate_tx_wire_bytes_counts_nested_actor_send_and_large_ops`, `evict_unexecutable_and_sweep_include_activation_and_carrier_surcharges`, `unfunded_spammer_cannot_saturate_the_activation_buffer`, `test_surcharge_gas_accounting_for_activation_tx`, `activation_buffer_reservation_is_released_exactly_once`) |
| WASM-SUBCALL-ISOLATION | Нет per-sub-call snapshot/rollback для `storage` / `balance` / `events` / `outbound_messages`; `caller()` на всех глубинах равен `tx.from`; `SysCallCallContractArgs` не входит в snapshot доменов. | **FIXED (локально, за гейтом R1 до активации в R5)**: `SubCallSnapshot`, `ContractCallOptions { origin, caller }`, `host.origin`, откат `value` в `state_engine/contracts.rs`, `SysCallCallContractArgs` в `snapshot_payload_domains_at` за `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT` / `EXEC_HARDENING_V1_ACTIVATION_HEIGHT` (`r1_wasm_hardening_tests`, `r1_frozen_apply_svm_tests`). | `docs/specs/WASM_XSHARD_PMM_HARDENING_CONTRACT.md` §2, §3.2.1–3.2.2; §5.1 п.1–2; `stellereum/tests/r1_wasm_hardening_tests.rs`, `stellereum/tests/r1_frozen_apply_svm_tests.rs` |
| WASM-OUTBOUND-ATOMICITY | `process_contract_outbound_messages` вызывается до CLOB и `commit_native` и не откатывается; сырой `msg.payload` падает в `decode_actor_body`, а bounce кредитует `accounts[contract_addr]` из воздуха. | **FIXED (локально, за гейтом R1 до активации в R5)**: перенос маршрутизации `outbound_messages` в `ExecPostActions` строго после `commit_native`, `sync_contract_balance` и `Svm::route_contract_messages_hardened` (дебет до постановки/боунса, отказ невалидных непустых payload) за `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT` (`r1_frozen_apply_svm_tests`). | `docs/specs/WASM_XSHARD_PMM_HARDENING_CONTRACT.md` §2 WASM-2, §3.2.3; §5.1 п.2; `stellereum/tests/r1_frozen_apply_svm_tests.rs` |
| WASM-FUEL | `validate_code` запускает `start`-секцию без `set_fuel`; `host.calldata` клонирует до 64 KiB до `charge`; `send_message` берёт плоские 100 fuel за payload до 64 KiB. | **FIXED (локально, за гейтом R1 до активации в R5)**: `host.calldata` fuel-before-clone активен; `validate_code_hardened` (`VALIDATE_CODE_START_FUEL_LIMIT`) и побайтовый `host.send_message` (`FUEL_SEND_MESSAGE + len * FUEL_SEND_MESSAGE_PER_BYTE`) за `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT` (`r1_wasm_hardening_tests`). | `docs/specs/WASM_XSHARD_PMM_HARDENING_CONTRACT.md` §2 WASM-5, §3.2.5; §5.1 п.3; `stellereum/tests/r1_wasm_hardening_tests.rs`, `stellereum/tests/wasm_cache_equivalence_tests.rs` |
| PMM-U128-WUSDT | Unchecked `u128` в `2 * sc * k`, `(s + d) * (s + d)`, `s * s`, `p0 * (d + quad)` и `as u64` в квитанциях; `SysCallPmmBuy` мутирует кривую до проверки баланса `wUSDT`; `ZeroMint` / `ZeroPayout` не отдаются. | **FIXED (локально, за гейтом R1 до активации в R5)**: `PMM-OVERFLOW` (`pmm.rs`), `TOKENOMICS-ZEROMINT` (`tokenomics.rs`) и CEI-проверка `wUSDT` до мутации кривой + `*_checked` / `ZeroMint` / `ZeroPayout` в `svm.rs` за `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT` (`pmm_tokenomics_overflow_tests`, `r1_frozen_apply_svm_tests`). | `docs/specs/WASM_XSHARD_PMM_HARDENING_CONTRACT.md` §2 PMM-1/TOK-1, §3.3; §5.1 п.4; `stellereum/tests/pmm_tokenomics_overflow_tests.rs`, `stellereum/tests/r1_frozen_apply_svm_tests.rs` |
| PQ1-MALLEABILITY | `PqSignatureEnvelope::decode` принимает `key + salt`, `salt + key` и no-salt, а `hash_into` хеширует сырые байты → `tx_hash` malleability одной и той же валидной подписи. | **FIXED (локально, за гейтом R1 до активации в R5)**: `PqSignatureEnvelope::decode_canonical` + `decode_at_height` в `sharding/envelope.rs` подключены через `sharding/transaction.rs`, `state_engine/verify_once.rs`, `apply.rs`, `parallel.rs` за `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT` (`r1_envelope_canonical_tests`, `r1_frozen_apply_svm_tests`). | `docs/specs/WASM_XSHARD_PMM_HARDENING_CONTRACT.md` §2 ENV-1, §3.4.3; §5.1 п.6; `stellereum/tests/r1_envelope_canonical_tests.rs`, `stellereum/tests/r1_frozen_apply_svm_tests.rs` |
| XPC-PRUNED-REOPEN | `Prepare` / `AbortRequest` не проверяют `cross_shard_completed` после прунинга (зомби-`Prepared`), а `PrepareAck` refresh мутирует запись, но возвращает `false`. | **FIXED (локально, не задеплоено)**: `XPC-PRUNE` — в `state_engine/xshard.rs` добавлен guard `cross_shard_completed` в `Prepare`/`AbortRequest` и `return true` при refresh `PrepareAck` (прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён). | `docs/specs/WASM_XSHARD_PMM_HARDENING_CONTRACT.md` §2 XPC-1, §3.4.1; §5.1 п.5; `stellereum/tests/xshard_prune_and_batch_tests.rs` (`pruned_committed_xpc_cannot_be_reopened_by_prepare_or_abort_request`, `xpc_prepare_ack_refresh_updates_decided_height_and_state_root`) |
| LC-EVM-BINDINGS | `Domain::EvmBindings` отсутствует: `SysCallBindEvmAddress` не входит в `state_root` / снапшоты, `EvmBindingRegistry` process-global, `hydrate_rpc_from_store` грузит до 50k полных `Block` (OOM) и теряет привязки старше окна или после prune. | **FIXED (локально: индекс/O(1)-прогрев сразу, канонический домен за гейтом R2 до R5)**: `Domain::EvmBindings` + `EvmBindingsState` + first-writer-wins в `apply.rs` за `EVM_BINDINGS_STATE_ACTIVATION_HEIGHT = u64::MAX`, деревья `"evm_bindings_state"` + непрунящийся `"evm_bindings"`, `SnapBundle`/`PersistJob::EvmBindingsState`, и стриминговый `O(1)` `hydrate_rpc_from_store` без `Vec<Block>` и `clear_evm_bindings()` (`r2_evm_bindings_state_tests`, `r2_storage_snapv4_sync_tests`, `r2_runtime_rpc_e2e_tests`). | `docs/specs/LIGHT_CLIENT_AND_EVM_INDEX_CONTRACT.md` §1 D3, §4; `stellereum/tests/r2_evm_bindings_state_tests.rs`, `stellereum/tests/r2_storage_snapv4_sync_tests.rs`, `stellereum/tests/r2_runtime_rpc_e2e_tests.rs` |
| LC-CLI-PROOF-BIND | `light_client_cli` не сверял `answer.address` и ключ proof с `--verify`, высоту заголовка с `height + 1`, не имел `--min-height` → возможен `VERIFIED` для чужого аккаунта или старой высоты. | **FIXED (локально, не задеплоено)**: `check_answer_matches_request`, `check_anchoring_header`, `--min-height`, overflow-safe `height + 1` в `light_client_cli.rs` (прошло `W0-CONSOLIDATE-GATE`; живой кластер/бинарь CLI ещё не обновлён). | `docs/specs/LIGHT_CLIENT_AND_EVM_INDEX_CONTRACT.md` §3; `stellereum/src/light_client_cli.rs`; `stellereum/tests/light_client_tests.rs` (`a_cli_answer_for_another_account_is_refused`, `a_cli_answer_whose_proof_is_for_another_key_is_refused`, `a_cli_answer_below_the_pinned_min_height_is_refused`, `a_cli_anchoring_header_at_another_height_is_refused`) |
| LC-ROOT-REVISIT | `superseded_root` / `check_no_rollback` отвергал легитимную QC-подписанную цепь `A -> B -> A` и ломал `sync::verify_synced_blocks_against_anchor_with_sets`. | **FIXED (локально, не задеплоено)**: `LC-A-TO-B-TO-A` — gate удалён в `light_client.rs`; защита остаётся на строгом росте высоты, `prev_hash` и 2/3+ QC (прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён). | `docs/specs/LIGHT_CLIENT_AND_EVM_INDEX_CONTRACT.md` §3.4; `stellereum/src/light_client.rs`; `stellereum/tests/light_client_tests.rs` (`a_valid_quorum_certified_chain_may_revisit_an_earlier_state_root`) |
| FAUCET-RECEIPTS-TIP | `all_receipts_capped(50_000)` берёт первые 50k в tx-hash порядке, а не новейшие по `(height, index)` → после 50k теряются свежие receipts и EVM-индексы. | **FIXED (локально, не задеплоено)**: `FAUCET-RECEIPTS-ORDER` — аддитивное дерево `receipts_by_height`, `latest_receipts_capped(50_000)`, backfill pre-upgrade сторов и синхронный прунинг в `storage.rs` + `hydrate_rpc_from_store` в `rpc/state.rs` (прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён). | `docs/specs/FAUCET_AND_EXPLORER_HARDENING_CONTRACT.md` §1 D1, §2.1; §4 п.1; `stellereum/tests/receipt_restart_order_tests.rs` (`restart_hydrates_newest_receipts_not_a_hash_prefix`, `prune_removes_receipts_from_the_tip_index`, `open_backfills_tip_index_for_a_pre_upgrade_store`) |
| FAUCET-FAIL-OPEN | `FaucetState` fail-open: ошибка чтения, битый блоб или пропажа состояния при `onchain_nonce > 0` молча обнуляли lifetime caps; `saver` не возвращал ошибку, `set_meta` не делал `flush()`. | **FIXED (локально, не задеплоено)**: fail-closed quarantine, fallible/durable persist, откат RAM в `rpc/faucet.rs` (прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён). | `docs/specs/FAUCET_AND_EXPLORER_HARDENING_CONTRACT.md` §2.2; `stellereum/src/rpc/tests.rs` (`faucet_startup_quarantines_on_storage_read_error`, `faucet_startup_quarantines_corrupt_or_missing_state`, `faucet_startup_quarantines_when_marker_flush_fails`, `faucet_persist_failure_rolls_back_ram_and_refuses_grant`) |
| FAUCET-CHAIN-BIND | `sign_pq_explicit_transfer` / `payload`, ingress-пути крана (`stell_faucet`, `api_faucet*`) и CLI-строители подписывают unbound tx без `chain_id` и `.with_chain_height`, поэтому после `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` кран и CLI перестают работать. | **FIXED (локально, не задеплоено)**: `FAUCET-CHAIN-BIND` / `CLI-CHAIN-BIND` — добавлены `sign_pq_explicit_transfer_with_chain`, `Faucet::with_chain_id` / `request_drip_for_chain`, проброс `chain_id` и `.with_chain_height` в `rpc/faucet.rs`, `rpc/writes.rs`, `explorer.rs`, а также `build_*_with_chain` и fail-closed `resolve_chain_id` в `cli/{tx_builders,handlers}.rs` (прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён). | `docs/specs/FAUCET_AND_EXPLORER_HARDENING_CONTRACT.md` §1 D3, §2.3; §4 п.5; `stellereum/src/rpc/tests.rs` (`faucet_signs_chain_bound_tx_and_survives_chain_binding_activation_at_height_1`), `stellereum/tests/cli_chain_binding_tests.rs` (`every_chain_aware_cli_builder_binds_the_envelope`, `no_chain_id_and_unreachable_rpc_fails_closed_when_binding_is_scheduled`, `explicit_chain_id_wins_without_any_rpc`, `pre_activation_offline_fallback_keeps_the_unbound_shape`) |
| FAUCET-EXPLORER-GATEWAY | На `explorer::router` `/rpc` смонтирован после `TimeoutLayer` / `ConcurrencyLimitLayer`; `/metrics` сканирует до 100k файлов без кэша; `build_public_transfer` имеет TOCTOU и сжигает `ip_buckets` до проверок; `/api/account` и кран клонируют весь пул через `mempool.all()`. | **FIXED (локально, не задеплоено)**: `EXPLORER-RPC-LIMITS` и `EXPLORER-METRICS-CACHE` в `explorer.rs` (`/rpc` внутри `TimeoutLayer(30s)` + `ConcurrencyLimitLayer(512)` с отдельным `nested_rpc_rate_limit`, `/metrics` переиспользует `health_data_dir_cache`, `api_faucet_public`/`api_faucet` переведены на единую блокировку `request_drip_for_chain` + `rollback_grant` без потери IP-бюджета; остаточная деталь: `api_account` и `api_faucet` всё ещё фильтруют `pool.all()`). Прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён. | `docs/specs/FAUCET_AND_EXPLORER_HARDENING_CONTRACT.md` §1 D5, §2.5; §4 п.7; `stellereum/tests/explorer_gateway_hardening_tests.rs` (`explorer_router_rpc_enforces_timeout_layer`, `explorer_router_rpc_enforces_concurrency_limit_without_double_rate_limit`, `prometheus_metrics_reuses_health_data_dir_cache`, `api_faucet_public_distinguishes_lifetime_cap_from_cooldown_and_rolls_back`) |
| SNAP-MANIFEST-DOS | `fetch_snapshot_manifest` не применяет границы `MAX_BLOB_CHUNKS` / `MAX_BLOB_BYTES`; манифест может объявить миллионы чанков, опустить `hash` чанка или склеить >512 MiB. | **FIXED (локально, не задеплоено)**: `parse_and_validate_snapshot_manifest` в `network.rs` применяет жёсткие лимиты `MAX_BLOB_CHUNKS`, `MAX_BLOB_BYTES`, обязательный 32B `hash` каждого чанка и непрерывность `off/len`, а также `DomainUnitId::EvmBindings = 271` в `snapshot_v4.rs` (`r2_storage_snapv4_sync_tests`, `snapshot_v4_tests`). | `docs/specs/W1_INCREMENTAL_SNAPSHOTS_CONTRACT.md` §1.4 G2, §2.2; `stellereum/tests/r2_storage_snapv4_sync_tests.rs`, `stellereum/tests/snapshot_v4_tests.rs` |
| SNAP-DOWNLOAD-BEFORE-VERIFY | `try_snapshot_sync` сначала скачивает многомегабайтный snapshot/manifest из DHT и только потом проверяет `boundary + 1` и `precommit_qc`. | **FIXED (локально, не задеплоено)**: `node/sync.rs` проверяет `next_hdr` + QC-якорь и `verify_snapv4_manifest_pre_fetch` строго до скачивания чанков данных (`snapshot_v4_tests`, `r2_storage_snapv4_sync_tests`). | `docs/specs/W1_INCREMENTAL_SNAPSHOTS_CONTRACT.md` §1.4 G3, §2.3; `stellereum/tests/snapshot_v4_tests.rs`, `stellereum/tests/r2_storage_snapv4_sync_tests.rs` |
| SNAP-PQKEYS | `"pq_keys"` не публикуется в `SNAPSHOT_PUBLISH_DOMAIN_KINDS`; после snapshot-sync исторические PQ-ключи теряются. | **FIXED (локально, не задеплоено)**: `"pq_keys"` и `"evm_bindings"` включены в `SNAPSHOT_PUBLISH_DOMAIN_KINDS` (`network.rs`) и `SYNC_DOMAIN_KINDS` (`sync.rs`) и публикуются в `consensus_driver.rs` (`r2_storage_snapv4_sync_tests`, `observer_and_recovery_tests`). | `docs/specs/W1_INCREMENTAL_SNAPSHOTS_CONTRACT.md` §1.4 G6, §2.1; `stellereum/tests/r2_storage_snapv4_sync_tests.rs`, `stellereum/tests/observer_and_recovery_tests.rs` |
| SNAP-DHT-NAME | DHT-имя `{epoch}_snap_{shard}_{height}` не содержит `state_root`, хеш манифеста или подпись; отравленный манифест с `FOREVER` TTL блокирует честный снапшот на той же высоте. | **FIXED (локально, не задеплоено)**: контент-адресованное именование `snapv4_manifest_name(epoch, shard, height, state_root)` и `snapv4_unit_name` с проверкой `blake3(bytes) == expected_hash` в `network.rs` (`r2_storage_snapv4_sync_tests`). | `docs/specs/W1_INCREMENTAL_SNAPSHOTS_CONTRACT.md` §1.4 G4, §2.2; `stellereum/tests/r2_storage_snapv4_sync_tests.rs` |
| SNAP-TIP-SKIP | `verify_restored_root` при `snapshot_height == tip` пропускает проверку корня. | **FIXED (локально, не задеплоено)**: `put_finalized_post_root` / `finalized_post_root_at` в `storage.rs` + запись из `consensus_driver.rs`, проверка корня против сохранённого `finalized_post_root_at(tip)` даже при отсутствии `tip + 1` (`r2_storage_snapv4_sync_tests`). | `docs/specs/W1_INCREMENTAL_SNAPSHOTS_CONTRACT.md` §1.4 G6; `stellereum/src/storage.rs`, `stellereum/tests/r2_storage_snapv4_sync_tests.rs` |
| FEE-PRIORITY-APPLY | `priority_fee_per_gas` проходит admission и proposal-check, но не списывается в `apply()` / `parallel`: priority bid фактически возвращается отправителю как неиспользованный газ. | **FIXED (локально, не активировано; `FEE_MARKET_V2_ACTIVATION_HEIGHT = u64::MAX`)**: `fee_for_gas_at_v2`/`failure_fee_for_v2` списывают `priority_fee_per_gas` внутри core (cap `gas_limit`, floor + surcharge); при выключенном гейте формула побайтово прежняя; `fee_market_v2` считается один раз на блок (sequential/parallel/`fail_with_floor!` parity). `w4_priority_fee_tests`. Активация — **R5**. → FIXED (R5, 2026-11-26: константа уже `0` в `stellereum/src/tokenomics.rs:296`, `docs/RULESET_V7.md` §7 это подтверждает; строка реестра была устаревшей). | `docs/specs/W4_ECONOMICS_PRODUCT_CONTRACT.md` §1.1, §2.2; §3.2 п.1; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md` |

## P2 — средний риск

| ID | Дефект | Статус | Где |
|---|---|---|---|
| S5 | мёртвые сеттеры (`SetEquivocationSlashBps`, `SetMinValidatorBond`) | DEPLOYED | — |
| S6 | один EVM intent мог сеттлиться дважды | DEPLOYED (nullifier в trie) | — |
| S7 | обход upgrade-гейта на direct/halt путях | DEPLOYED | — |
| R6 | carrier-наценка не бралась при исполнении | DEPLOYED | — |
| R7 | nonce/value равенство только на admission | DEPLOYED | — |
| S10 | никогда-не-принимаемые mailbox-записи росли без bound | DEPLOYED | — |
| M1 | `stell_getEvmBinding` называл mempool-claim «committed» | DEPLOYED | — |
| M2 | per-account ключ Files из seed ноды | DEPLOYED | — |
| M3 | `put ok` до репликации, zero-replica = успех | DEPLOYED | — |
| M4 | неограниченные `chunks[]` в манифесте | DEPLOYED | — |
| M5 | `stell_unsubscribe` без аутентификации | DEPLOYED | — |
| receipt params | `[hash]` не принимался | DEPLOYED | — |
| stale docs | ~30 доков противоречили коду | DEPLOYED (V2) | — |
| stell_getBlock | всегда «not in recent window», даже `latest` | **FIXED** (HUNT-5) | — |
| getTransactionByHash | `stell_*` метода нет | **FIXED** (HUNT-5) | — |
| SEC-MEVSTATS | `stell_mevStats` реализован в `dispatch_writes_inner`, но отсутствовал в `matches!` фильтре `dispatch_writes` → всегда `-32601`. | **FIXED (локально, не задеплоено)**: метод добавлен в фильтр `rpc/writes.rs` (прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён). | `docs/specs/SECURITY_HARDENING_FIXES_CONTRACT.md` §1.2.3; `stellereum/src/rpc/tests.rs` (`rpc::tests::stell_mev_stats_is_reachable_via_rpc_dispatch`) |
| WASM-DEPLOY-ADDR | RPC предсказывает `contract_address(tx.from, tx.nonce)`, а `ContractRegistry::deploy_inner` использует глобальный `self.next_nonce` → адрес деплоя расходится с консенсусом. | **FIXED (локально, за гейтом R1 до активации в R5)**: `deploy_with_nonce(tx.nonce)` в `contract.rs`/`svm.rs` за `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT`, плюс `legacy_contract_address`/`legacy_next_nonce` в `rpc/contracts.rs` на `< H` (`r1_wasm_hardening_tests`). | `docs/specs/WASM_XSHARD_PMM_HARDENING_CONTRACT.md` §2 WASM-4, §3.2.4; §5.1 п.3; `stellereum/tests/r1_wasm_hardening_tests.rs` |
| CNVRF-EPOCH-OVERFLOW | `epoch_start_height` делает unchecked `epoch_n * EPOCH_LEN` (panic в debug / wrap в release) и проникает в `freeze_height_of_epoch`. | **FIXED (локально, не задеплоено)**: `CNVRF-OVERFLOW` — `epoch_n.saturating_mul(EPOCH_LEN)` в `cn_vrf.rs` (прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён). | `docs/specs/WASM_XSHARD_PMM_HARDENING_CONTRACT.md` §2 VRF-1, §3.4.2; §5.1 п.5; `stellereum/tests/pq_opt_equivalence_tests.rs` (`cn_vrf_epoch_and_freeze_height_boundaries_never_panic_or_wrap`) |
| FAUCET-PAGINATION | `skip(offset).take(limit)` поверх `HashMap::keys()` в `stell_listTokens` / `api_contracts` даёт случайный порядок, пропуски и дубли; `last_public_drip` не чистился от истёкших записей (часть D4). | **FIXED (локально, не задеплоено)**: `TOKEN-LIST-PAGINATION` + `CONTRACT-LIST-PAGINATION` — `TokenRegistry::tokens` (`token.rs`) и `ContractRegistry::contracts` (`contract.rs`) переведены на `BTreeMap` с обратной совместимостью legacy `HashMap`-снапшотов, детерминированная курсорная пагинация в `stell_listTokens` (`rpc/reads.rs`) и `GET /api/contracts` (`explorer.rs`), очистка cooldown в `rpc/faucet.rs` (прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён). | `docs/specs/FAUCET_AND_EXPLORER_HARDENING_CONTRACT.md` §1 D4, §2.4; §4 п.6; `stellereum/tests/token_pagination_and_fee_opt_tests.rs` (`token_registry_and_list_tokens_are_deterministic_across_insertion_orders`, `list_tokens_cursor_pagination_survives_mid_scan_insertions_without_skips_or_dups`, `token_registry_bincode_roundtrip_and_legacy_hashmap_snapshot_compat`), `stellereum/tests/explorer_gateway_hardening_tests.rs` (`api_contracts_pagination_is_deterministic_and_supports_after_cursor`, `api_faucet_public_distinguishes_lifetime_cap_from_cooldown_and_rolls_back`), `stellereum/tests/wasm_cache_equivalence_tests.rs` (`contract_registry_btreemap_order_and_bincode_roundtrip_legacy_compat`) |
| FEE-BURN-SPLIT | 100% собранных fees уходят `block.proposer`; нет burn/staking split и governance-параметров. | **FIXED (локально, не активировано)**: сплит в u128 на весь блок — `burn = fees*burn_bps/10_000`, `staking = fees*staking_bps/10_000`, `proposer = fees - burn - staking` (0 nano потерь); burn никуда не зачисляется, staking — `StakingLedger::distribute_fee_reward` (без `rewards_minted`/emission cap) + 1:1 `REWARDS_POOL`; jailed/неизвестный прпозер → доля прпозеру. `w4_priority_fee_tests`. | `docs/specs/W4_ECONOMICS_PRODUCT_CONTRACT.md` §1.1, §2.2; §3.2 п.1; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md` |
| FEE-SUBNANO-EXACT | Тихое усечение sub-nano wei в EVM carrier, сброс `remainder` в `ValidatorRewardState::accrue`, двойное усечение `GenesisVault::calculate_mint`, потеря Q0.64 в `pow_half_fixed`, `f64` в `eth_feeHistory`. | **FIXED (локально, не активировано; `SUB_NANO_STRICT_ACTIVATION_HEIGHT = u64::MAX`) → ИСПРАВЛЕНО (R5, 2026-11-26: константа уже `0` в `stellereum/src/tokenomics.rs:251`, `docs/RULESET_V7.md` §8 это подтверждает; строка реестра была устаревшей)**: `wei_to_nano_exact` на EVM carrier-границе (RPC/admission strict, консенсус по гейту), целочисленный `eth_feeHistory` без `f64`, одношаговый 256-битный `GenesisVault::calculate_mint`, `ValidatorRewardState::accrue_with_rescale` при смене `delegated` (проводка в `distribute_reward_at_height`/`distribute_fee_reward_at_height` в `apply.rs` Step 2/3), `pow_half_fixed_exact_q64`/`emit_with_q64_carry` + committed `StakingLedger::emission_carry_q64` (`STAKING_EMISSION_CARRY_V1` conditional + `StakingLedgerV7`/`DomainSnapshotV10`). Тесты: `w4_sub_nano_tests` **4/4** (`397+`/полный гейт). | `docs/specs/W4_ECONOMICS_PRODUCT_CONTRACT.md` §1.2, §2.3; §3.2 п.2; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md` |
| FEE-DENSITY-ORDER | `Mempool::order` / `sealed_candidates` сортируют по сырому `(priority_fee_per_gas, gas_limit)`, а не по плотности `priority / max(gas, wire, proof)`; тяжёлая tx вытесняет пачку обычных. | **FIXED (локально)**: `Mempool::fee_density` = `priority / max(gas, wire, proof_units*10k)` (целочисленно, детерминированный total order) применяется в `select_for_block`, `select_for_block_multi` и `sealed_candidates`. `propose_select_differential_tests` 3/3. | `docs/specs/W4_ECONOMICS_PRODUCT_CONTRACT.md` §1.1, §2.2.1; §3.2 п.1; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md` |
| STREAM-SHARD-ID | `RpcState::record_block` жёстко передаёт `MASTERCHAIN_SHARD` в `publish_new_head`; на workchain-ноде `newHeads` сообщает `shard_id = 0`. | **FIXED (локально, не задеплоено)**: `RpcState::record_block` публикует `self.engine.shard_id()` и quorum-certified header (`prev_hash`/`state_root`/`proposer`; `null` при отсутствии сертификата). `w4_geyser_stream_tests`. | `docs/specs/W4_ECONOMICS_PRODUCT_CONTRACT.md` §1.4, §2.5; §3.2 п.4; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md` |
| STREAM-GEYSER-LITE | Нет `seq` / replay-окна / explicit `Lagged`, нет топиков `AccountUpdates` / `TokenTransfers`, payload не содержит `prev_hash` / `state_root` / `proposer` / `tx_index`. | **FIXED (локально, не задеплоено)**: `seq` + `GEYSER_REPLAY_WINDOW = 512` + `after_seq` (+ `-32005`), явные `Lagged`-фреймы в SSE/WS, топики `AccountUpdates`/`TokenTransfers` (`MAX_SUBSCRIPTION_ACCOUNTS = 32`), публикация дельт вне блокировок `record_block`. Индексерная часть — **FIXED** ранее. Тесты: `w4_geyser_stream_tests` 4/4 (`stellereum-indexer/tests/w4_indexer_tests.rs` 4/4). | `docs/specs/W4_ECONOMICS_PRODUCT_CONTRACT.md` §1.4, §2.5; §3.2 п.4; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md`; `stellereum-indexer/tests/w4_indexer_tests.rs` |
| HISTORY-API | Нет вторичных sled-индексов (`tx_by_addr`, `events_by_contract`), курсорной пагинации и bounded `stell_getProgramAccounts` / `stell_getTokenAccountsByOwner`; indexer использует `LIMIT/OFFSET`. | **FIXED (локально, не задеплоено)**: деревья `tx_by_addr` (tip-first, 44Б), `events_by_contract` (48Б), `receipt_meta_v2` (без изменения `receipts_v1`) + синхронный prune; keyset-курсоры; `stell_getAddressHistory`, `stell_getProgramAccounts` (cap 100/10k/2 MiB/16 proofs, `scan_truncated`, отказ на нефильтрованный `system`), `stell_getTokenAccountsByOwner`, `cursor` в `stell_getEvents`/`stell_listTokens`. `w4_history_program_accounts_tests` 3/3; индексерная часть — **FIXED** ранее. | `docs/specs/W4_ECONOMICS_PRODUCT_CONTRACT.md` §1.3, §2.4; §3.2 п.3; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md`; `stellereum-indexer/tests/w4_indexer_tests.rs` (`indexer_keyset_cursor_stable_under_concurrent_inserts`, `indexer_token_balances_and_contracts_tables_and_reorg_cleanup`, `indexer_sse_parser_and_push_sync_with_backfill_fallback`, `indexer_stream_endpoint_filtering_replay_and_limits`) |
| SNAP-BUDGET | Бюджеты снапшотов несогласованы: `startup_budget = 20s`, `try_catch_up = 180s`, таймаут блоба `300s`; прогресс чанков не сохраняется между перезапусками catch-up. | **FIXED (локально, частично для SnapV4)**: `try_snapshot_sync` переведён на по-чанковый `SnapV4` (`fetch_verified_snapv4_chunks` + `snap_staging`/`snap_units` в `storage.rs`) и `fetch_large_blob_resumable` для legacy; таймауты `startup_budget`/`try_catch_up` оставлены консервативными в `node/policy.rs` до live soak-замера. | `docs/specs/W1_INCREMENTAL_SNAPSHOTS_CONTRACT.md` §1.4 G7, §2.4; `stellereum/src/node/sync.rs`, `stellereum/src/storage.rs` |

## P3 — низкий риск / принято

| ID | Дефект | Статус | Где |
|---|---|---|---|
| F-10 | restored round: `last_prevoted` сеется сырым раундом | ASSIGNED (HUNT-1) | — |
| F-11 | подписи tx вне `compute_hash` | ASSIGNED (HUNT-1) | — |
| F-12 | nil-breaker ре-бродкастит тело старого раунда | ASSIGNED (HUNT-1) | — |
| S8 | timestamp блока выбирает продюсер | ASSIGNED (HUNT-1/4) | — |
| S9 | вес голоса можно вывести перед голосом | ASSIGNED (HUNT-4) | — |
| unicast Body | нет `send_to_peer`, ответы broadcast (bounded) | **FIXED** (`send_to_peer`, 10→10 unicast) | — |
| `--owner-key` | seed в argv | **FIXED** (HEAD `9832e97a9`: `--owner-key-file` 0600/stdin, `$INFNODE_OWNER_KEY`; argv deprecated with a loud warning; `cli_seal_tests`) | — |
| store_mail | fail-open на неоткрываемом ключе | **FIXED** (HEAD `9832e97a9`: `StoreMailError`, key boxed before any chunk/manifest; `store_mail_with_unboxable_owner_key_fails_closed`) | — |
| sub-nano | усечение при переводе в nano | **FIXED (локально, не активировано)** — см. `FEE-SUBNANO-EXACT`: закрыты все 5 пунктов (§2.3 п.1–п.5: `wei_to_nano_exact`, 256-bit `GenesisVault`, `accrue_with_rescale`, `emission_carry_q64`, integer `eth_feeHistory`). `w4_sub_nano_tests` **4/4**. → FIXED (R5, 2026-11-26: `SUB_NANO_STRICT_ACTIVATION_HEIGHT = 0`). | `docs/specs/W4_ECONOMICS_PRODUCT_CONTRACT.md` §1.2, §2.3, §3.2 п.2; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md`; см. `FEE-SUBNANO-EXACT` |
| pre-auth sealed | старые sealed-блобы отклоняются | ACCEPTED (требуют переопубликации) | — |
| zkML | re-execution, не ZK | **SEPARATE SYSTEM** | см. «Отложено осознанно» |
| EVM | только переводы, без контрактов | **SEPARATE SYSTEM** | см. «Отложено осознанно» |
| >2 шардов | фиксированная пара `{0,1}` | ACCEPTED (канон; динамический split/merge — отдельная система) | — |
| OPT-HNTT | `verify_falcon512` заново делает 512-точечный `ntt()` для `h` на каждую подпись и дублирует trailing-zero скан в `unpack_falcon_sig`. | **FIXED (локально, не задеплоено)**: `unpack_falcon_pubkey_ntt` кэширует `h_ntt = ntt(h)` в `FALCON_PUBKEY_CACHE`, `verify_pq_signature` использует `poly_mul_precomputed_ntt_in_place` (`post_quantum.rs`; прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён). | `docs/specs/WASM_XSHARD_PMM_HARDENING_CONTRACT.md` §2 OPT-1, §3.5.1; `stellereum/tests/pq_opt_equivalence_tests.rs` (`verify_pq_signature_equivalence_across_valid_and_adversarial_inputs`, `verify_pq_cold_and_hot_cache_multi_key_and_concurrent_consistency`, `batch_verification_matches_scalar_for_all_defect_classes`) |
| OPT-TXHASH-BATCH | `record_legacy_escrow_receipts` / `apply_xpc_source_prepares` пересчитывают `compute_tx_hash()` на каждую пару (O(M·N)); `split_sponsor_envelope` разбирается 3–5 раз. | **FIXED (локально, не задеплоено)**: `Transaction::compute_tx_hashes_batched` / `batch_hasher` в `sharding/transaction.rs` и `state_engine/xshard.rs` (прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён). | `docs/specs/WASM_XSHARD_PMM_HARDENING_CONTRACT.md` §2 OPT-2, §3.5.2; `stellereum/tests/xshard_prune_and_batch_tests.rs` (`compute_tx_hash_and_metadata_match_reference_across_all_tx_variants`, `record_legacy_escrow_and_xpc_source_prepares_preserve_first_match_and_order`) |
| OPT-WASMI-CACHE | `contract_engine()` создаёт `Engine` на каждый вызов; скомпилированный `wasmi::Module` не кэшируется по `code_hash`. | **FIXED (активировано в R5, локально не задеплоено)**: `CONTRACT_ENGINE` (`Eager`) + `CONTRACT_MODULE_CACHE` (`blake3`) активны с генезиса (`WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT = 0`; `wasm_cache_equivalence_tests` 6/6, `contract_integration_tests` 4/4, `r1_wasm_hardening_tests` 7/7). | `docs/specs/WASM_XSHARD_PMM_HARDENING_CONTRACT.md` §2 OPT-3, §3.5.3; `stellereum/tests/wasm_cache_equivalence_tests.rs`, `stellereum/tests/contract_integration_tests.rs`, `stellereum/tests/r1_wasm_hardening_tests.rs` |
| OPT-RECEIPT-INDEX | `ReceiptIndex::for_height` и `stell_getEvents` сканируют до 50k записей и сортируют на каждый вызов. | **FIXED (локально, не задеплоено)**: `ReceiptIndex::by_height` (`BTreeMap<u64, Vec<[u8; 32]>>`) + `ReceiptIndex::by_contract_events` (`HashMap<[u8; 32], BTreeSet<(u64, u32, [u8; 32])>>`, `O(log N + K)` без коллизий в `stell_getEvents`) в `rpc/state.rs`/`rpc/reads.rs` (`receipt_index_for_height_equivalence_60k_eviction_and_updates`, `receipt_index_by_contract_events_matches_full_scan_under_overwrites_and_eviction`). | `docs/specs/SECURITY_HARDENING_FIXES_CONTRACT.md` §2.1; `stellereum/tests/rpc_opt_equivalence_tests.rs`, `stellereum/src/rpc/tests.rs` |
| OPT-ESTIMATE-FEE | `simulate_and_estimate_fee` всегда глубоко клонирует все домены, даже для пустого payload. | **FIXED (локально, не задеплоено)**: `is_plain_fast_path` для plain-transfer + селективный `clone_for_simulation_for_tx`/`_for_payload` в `state_engine/accounts.rs` + `rpc/reads.rs` (пропускает `state_trie`, `pq_db`, `cross_shard_*`, `hashpool`, `cnvrf_*` и незадействованные домены; `estimate_fee_fast_path_is_differential_equivalent_to_clone_for_simulation`, `clone_for_simulation_for_tx_matches_full_clone_across_domains`). | `docs/specs/SECURITY_HARDENING_FIXES_CONTRACT.md` §2.2; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md`; `stellereum/tests/token_pagination_and_fee_opt_tests.rs`, `stellereum/src/rpc/tests.rs` |
| OPT-SUBSCRIPTION-HUB | `SubscriptionHub::publish` аллоцирует `String`/клонирует `Value` на каждую подписку под `registry.read()`. | **FIXED (локально, не задеплоено)**: преднормализованный `SubscriptionIndex` с `O(1)` `client_counts`, безаллокационной нормализацией `publish` и fast-exit при пустом `hub` в `rpc/streams.rs` (`opt_edge_streams_tests`). | `docs/specs/SECURITY_HARDENING_FIXES_CONTRACT.md` §2.5.1; `stellereum/tests/opt_edge_streams_tests.rs` |
| OPT-FINALIZED-CACHE | `FinalizedReadCache` аллоцирует `String`/`Vec<u8>` на каждый get/put и сканирует 512 записей при eviction. | **FIXED (локально, не задеплоено)**: `FinalizedReadKey` (`method: &'static str`, `Copy`) + streaming `Blake3IoWriter` в `finalized_read_cache_params_hash` (`rpc/cache.rs`; прошло `W0-CONSOLIDATE-GATE`; живой кластер ещё не обновлён). | `docs/specs/SECURITY_HARDENING_FIXES_CONTRACT.md` §2.5.2; `stellereum/tests/rpc_opt_equivalence_tests.rs` (`finalized_read_cache_params_hash_matches_reference_to_vec`, `finalized_read_cache_no_collisions_across_methods_and_params`) |
| OPT-CLIENT-IP-CONFIG | `resolve_client_ip` на каждый запрос читает env и парсит CIDR; `RateLimiter` — один `Mutex`. | **FIXED (локально, не задеплоено)**: `ClientIpConfig` (`OnceLock` в release + env-перечитка в debug/test), zero-alloc проход `XFF`/`Forwarded`, extension-передача в `rpc/streams.rs`/`explorer.rs`, 16-шардовый `RateLimiter` по `canonical_ip` (`opt_edge_streams_tests`, `client_ip_proxy_tests`). | `docs/specs/SECURITY_HARDENING_FIXES_CONTRACT.md` §2.4; `stellereum/tests/opt_edge_streams_tests.rs`, `stellereum/tests/client_ip_proxy_tests.rs` |
| OPT-PARALLEL-WAVE | `PlainTxPlan::writes: Vec`, полный клон `consensus_penalty` / `vesting_schedules`, промежуточные `Vec` в `par_chunks`. | **FIXED (локально, не задеплоено)**: `PlainTxPlan::writes` переведён на inline `[([u8; 32], u64, u64); 3]` + `write_len: u8` (0 heap-аллокаций/tx), выборочное чтение `consensus_penalty`/`vesting_schedules` по адресам блока (`empty()` fast-path), плоский `wave.par_iter().with_min_len(chunk)` без промежуточных `Vec` на чанк. Без смены `FORK_ID`; `state_engine::tests::parallel_waves` **3/3**, `w4_priority_fee_tests` **4/4**. | `docs/specs/SECURITY_HARDENING_FIXES_CONTRACT.md` §2.5.3; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md`; T-Opt5c |
| HQ-QC-RETRO-BACKOFF | `retro_publish_blocks` перепубликует только тела `_blk_*`, не восстанавливая пропавший `_hq_{shard}_{height}` QC; при промахе `fetch_block_qc` / `blind-QC-probe` долбит пиров `dht.find_value` каждые ~1.38 с (воспроизведено вживую на `#6805`/`nodeB`). | **DEPLOYED** (`3a2c2ef3e` на A/B/C/D): `plan_block_qc_publish` / `publish_block_qc_companion` в `retro_publish_blocks` и `retro_publish_block` (`ReplStoreKind::Companion`, `Pointer` lane, без изменения `shard_head` и локального KV) + `QcMissBackoff` (`2s → 4s → 8s → 16s → 30s`, cap 128) и 1-попыточный `fetch_block_qc_probe` в `network.rs` и `node/sync.rs`. Тесты: `qc_miss_backoff_scales_resets_and_stays_bounded`, `retro_publish_blocks_republishes_hq_qc_without_moving_head_and_backs_off_misses`, `retro_publish_tests` 7/7. | `stellereum/src/network.rs`, `stellereum/src/node/sync.rs` |
| R5-RULESET-V7 | Активация Ruleset v7 (`FORK_ID = 0x3ae00ebc`, 8 гейтов R1–R4 на `0`, `CONSENSUS_RULESET_VERSION = 7`, `DOMAIN_SET_VERSION = 4`) + детерминированный посев `PqRegistry` на чистом v7 генезисе (`seed_genesis_pq_registry`). | **DEPLOYED** (`3a2c2ef3e` на A/B/C/D, 4/4 валидатора по `2000 STELL`, `fragile: false`): все 8 гейтов активны с `0`, `docs/RULESET_V7.md`, `stellereum-sdk` (45/45 + 20/20 `node-parity`), `sdk-js` (23/23 + `tsc` 0/0), `seed_genesis_pq_registry` в `node/bootstrap.rs`, полный гейт `stellereum` **399/399** зелёный (`clippy 0/0` по всем крейтам). | `docs/RULESET_V7.md`, `stellereum/src/protocol.rs`, `stellereum/src/node/bootstrap.rs` |

## Новые P0 из волны HUNT (false-slash примитивы)

| ID | Дефект | Статус |
|---|---|---|
| SLASH-A | `Vote` не содержит `shard_id` и не подписывает его → честный мультишард-валидатор слэшится за нормальную работу | **FIXED** (V3-preimage + QC/evidence/offense key) |
| SLASH-B | `Block` не содержит `round` → честный пропозер после view change слэшится как double-propose | **FIXED** (ruleset 4: `round` в подписанной identity, slashing включён) |
| RE-PROP-ROUND | ruleset 4/5: lock-rescue/demanded rescue честно пере-отправляет ТО ЖЕ подписанное тело (его hash — значение, на котором держат lock), но admission требовал `block.round == hc.round` → тело старого раунда отвергалось, высота зависала; adopt тем же требованием блокировал catch-up | **FIXED** (admission принимает более ранний signed round только для тела, которое уже держим — повтор известного значения; новое stale-тело по-прежнему fail-closed; adopt принимает `block.round <= certificate.round`, QC подписывает точный hash; тесты `locked_proposer_reproposes_locked_value`, `lock_hint_rescue_converges`, `demanded_reproposal_records_live_proposal_and_broadcasts_once`) |
| SIGNED-ROUND-LIVENESS | ruleset 4/5: re-served locked body хранит СТАРЫЙ signed round, а prevote штамповался ЛОКАЛЬНЫМ раундом → все три валидатора prevote'или один и тот же hash в r505/r507/r515, ни один раунд не собирал кворум → height 1 не финализировался навсегда. Дополнительно forward-sync стирал уже принятое предложение, и узел приходил в раунд головы «пустым». | **FIXED** (промежуточный шаг: prevote несёт signed round ТЕЛА; forward-sync сохраняет живым proposal, совпадающий с lock/голосом за то же тело; corroboration-chase допускает двух peer'ов в окне `ROUND_LOOKBACK` ниже цели. **Окончательно закрыт ruleset v6** (`docs/RULESET_V6.md`): тело на rescue re-stamp'ится на `hc.round`, поэтому signed round голоса = текущий раунд и всегда выше fsynced watermark; lock-сравнения идут по `value_id`. Инварианты: без rewind, без голоса ниже watermark, без будущего signed round. Тесты `signed_round_liveness_tests`, `live_stall_repro_tests`, `value_id_lock_tests`, `round_sync_audit_tests`) |
| SLASH-C | рестарт откатывает раунд до ≤64, голоса не персистятся → self-equivocation и потеря голоса | **FIXED** (fsync watermark до голосования + round floor) |
| DOWNTIME | `DOWNTIME_MISS_THRESHOLD = 10` при 240 мс = 2.4 с → слэш за WAN-блип | **FIXED** (ruleset v2: 42 = 10.08 s) |
| CNVRF-WINDOW | `V3_COMMIT_LOOKAHEAD = 360` = 86 с; VDF обязан успеть, иначе boundary без beacon | **FIXED** (682 = 163.7 s, замер VDF 20.5 s × 8) |
| CNVRF-HOOKS | live/sequenced finalize не вызывал epoch hooks (тихо до активации v3) | FIXED (HUNT-2) |
| BLOCK-CAPS | sealed+plain union обходил `MAX_BLOCK_TXS/GAS`; валидатор не проверял wire/proof-капы | FIXED (HUNT-2) |
| CATCHUP-BUDGET | 250 мс при блоке 240 мс → отстающая нода не могла закрыть разрыв | FIXED (HUNT-2) |
| QUORUM-SCAN | поиск кворума не видел более старый доказуемый раунд | FIXED (HUNT-1) |
| QC-POWER | µQC собирался по count, а не по power (N=191 требовал всех 128) | FIXED (HUNT-1) |
| DEADLOCK-CORR | corroboration = 2 ID (<1/3 на 7 нодах) | FIXED (HUNT-1) |
| VOTE-BUCKETS | отказанные голоса создавали пустые бакеты и вытесняли настоящие | FIXED (HUNT-1) |
| RETAIN-CAP | cap обходился, если polka-раунд самый старый | FIXED (HUNT-1) |
| XSHARD-EVID | cross-shard пары принимались как double-propose | FIXED (HUNT-1) |
| RPC-BLOCK | `stell_getBlock` не принимал ни один селектор | FIXED (HUNT-5) |
| RPC-TX | `stell_getTransactionByHash` отсутствовал | FIXED (HUNT-5) |
| EVM-HIST | исторические EVM-теги отдавали текущее состояние | FIXED (HUNT-5) |
| EVM-ZEROTX | после рестарта квитанции фабриковали нулевого отправителя | FIXED (HUNT-5) |
| MESH-DELIVERED | один overlay-успех маскировал N провалов | FIXED (HUNT-3) |
| MESH-COMMITTED | `Committed` глотался mesh-shortcut'ом для suspected | FIXED (HUNT-3) |
| DHT-FANOUT | lookup фан-аутил на всех пиров (`degree^ttl`) | FIXED (HUNT-3) |
| DHT-POISON | третья сторона переписывала endpoint закреплённого пира | FIXED (HUNT-3) |
| ROUTING-LRU | вытеснение по вставке, а не по последнему наблюдению (eclipse) | FIXED (HUNT-3) |
| SUSPICION | sticky без ре-арма → hot loop; восстановление не пробовалось | FIXED (HUNT-3) |
| HALT-GUARD | guard сравнивал маркер только с finalized-метаданными, состояние могло быть впереди | **FIXED** (UP-3) |
| RECOVERY | walk ≤256 при снапшотах до 1100 → на halted цепи нет самовосстановления | **FIXED** (UP-3) |

## Апгрейд-система (новая волна)

| ID | Работа | Статус |
|---|---|---|
| UP-1 | `PROTOCOL_VERSION` + `FORK_ID` + handshake + capabilities + dual-emit | **FIXED** (ruleset v3, fork `0xb13baff4`) |
| UP-2 | gate в chain-spec на генезисе + включение on-chain исполнения + fork-id в digest | **FIXED** (env-высота на генезисе, в digest; retroactive отказан) |
| UP-3 | deadlock восстановления: walk vs snapshot cadence + recovery-режим | **FIXED** (multi-hop recovery 400/1100) |
| UP-4 | `scripts/upgrade_drill.sh` (manual + onchain) + runbook + замер RTO | **FIXED** (manual PASS, RTO 10.8 s; onchain fail-closed) |
| UP-5 | `cosmovisor`-аналог (демон, следящий за committed-планом) | **FIXED (локально, не задеплоено)**: `stellereum-upgrader` — `--supervise` (перехват exit 42), `--staged-dir`, `--print-systemd`, точный v1-маркер, `[u8;32]` digest из RPC, fallback на маркер при уже упавшем RPC, atomic swap; 19/19 тестов (`cargo test -p stellereum-upgrader`). Живой кластер ещё не обновлён. |

## Изолированные модули W1/W2/W4 (прошли `W0-CONSOLIDATE-GATE`, локально)

| ID | Модуль / область | Статус | Где / тесты |
|---|---|---|---|
| W1-SNAPV4-CODEC | Кодек и валидатор инкрементальных снапшотов `SnapV4` (`SnapshotManifestV1`, `DomainUnitId`, Merkle-proof, pre-fetch верификация) | **FIXED (локально, не задеплоено)**: интеграция в `storage.rs`/`sync.rs`/`network.rs`/`consensus_driver.rs` идёт в **R2** (`docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md`); живой кластер ещё не обновлён. | `stellereum/src/snapshot_v4.rs`; `stellereum/tests/snapshot_v4_tests.rs` (10/10) |
| W2-DATA-PLANE-RS | Чисто-Rust GF(256) Reed-Solomon + BLAKE3 Merkle (`data_plane_rs`) и bounded repair (`data_plane`, `data_plane_repair`) | **FIXED (локально, не задеплоено)**: интеграция в `sync.rs`/`network.rs`/`consensus_driver.rs` идёт в **R2** (`docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md`); живой кластер ещё не обновлён. | `stellereum/src/data_plane_rs.rs`; `stellereum/tests/data_plane_rs_tests.rs` (11/11), `stellereum/tests/data_plane_tests.rs`, `stellereum/tests/data_plane_repair_tests.rs` |
| W2-LEDGER-TOOL | Автономный верификатор блоков и цепочек `stellereum-ledger-tool` (`inspect-block`, `verify-block`, `verify-chain`) | **FIXED (локально, не задеплоено)**: интеграция в сетевой/нодовый контур не требуется (отдельная CLI-утилита; живой кластер/релизные бинари ещё не обновлены). | `stellereum-ledger-tool/src/main.rs` (9 unit-тестов), `stellereum-ledger-tool/tests/cli.rs` (2 integration-теста; итого 11/11) |
| W2-INFNODE-EC | Erasure coding в `infnode` (`ec_encode`/`ec_decode`, bounded read, key_box/hash checks) | **FIXED (локально, не задеплоено)**: живой кластер `infnode` ещё не обновлён; сетевая интеграция с `stellereum` идёт в **R2**. | `infnode/crates/infnode/src/node.rs` (`mod ec_tests`, 15 тестов: `ec_roundtrip_no_loss` .. `ec_invalid_key_box_bounds_are_refused`) + `infnode/crates/infnode/tests/storage_seal_tests.rs` (`store_mail_with_unboxable_owner_key_fails_closed` и др.) |
| W2-EC-MAIL-RECOVERY | Автономная утилита восстановления EC-почты `ec-mail-recovery` | **FIXED (локально, не задеплоено)**: живой кластер/релизные бинари ещё не обновлены. | `infnode/tools/ec-mail-recovery/src/main.rs` (9/9: `legacy_writer_with_missing_data_shard` .. `ml_kem_box_and_legacy_x25519_refusal`) |
| W4-INDEXER-GEYSER | Апгрейд `stellereum-indexer`: keyset-курсоры, таблицы `token_balances`/`contracts`, reorg cleanup, SSE `GET /api/v2/stream` | **FIXED (локально, не задеплоено)**: и индексерная, и нодовая стороны (`tx_by_addr`/`events_by_contract`/`stell_getProgramAccounts` и Geyser `rpc/streams.rs`) полностью реализованы и прошли гейты; живой индексер/кластер ещё не обновлены. | `stellereum-indexer/src/{db,syncer,server,events}.rs`; `stellereum-indexer/tests/w4_indexer_tests.rs` (4/4: `indexer_keyset_cursor_stable_under_concurrent_inserts`, `indexer_token_balances_and_contracts_tables_and_reorg_cleanup`, `indexer_sse_parser_and_push_sync_with_backfill_fallback`, `indexer_stream_endpoint_filtering_replay_and_limits`) |

## Аудит исполнения и шардинга (внешнее ревью, 2026-11-23)

| ID | Находка | Статус |
|---|---|---|
| EXEC-PMM-SHARDGATE-ATOMICITY | `PmmBuy`/`PmmSell` → `settle_pmm_native` → отказ C7 shard-gate оставлял native-кредит/списание и резерв эмиссии: отклонённый buy давал бесплатные STELL, sell сжигал деньги. | **FIXED (локально, не задеплоено)**: на отказе выполняются `release_mint_nano` + `restore_pmm_native` + восстановление книг/oracle; вердикт отказа не менялся (rollback-only). Тесты: `tests/review_exec_pmm_bridge_atomicity.rs` (2, fail-before). |
| RPC-GETMETHOD-PAST-HEIGHT | `stell_runGetMethod` с `height < tip` исполнял геттер на ЖИВОМ registry и отдавал текущий результат как исторический. | **FIXED (локально)**: прошлая высота теперь fail-closed `historical state is not available on this node` (как `stell_getProof`); движковый helper тоже. Тесты: `tests/review_xshard_rpc_height_pinning.rs` (2) + обновлён `rpc::tests`. |
| XSHARD-CONTRACT-SEND-BURN | Контрактный `send_message` на другой шард дебетовал отправителя и клал в `cross_shard_out` запись, которую inbound принять не может (битый `msg_id`, пустая подпись, нет escrow-листа, нет потребителя очереди) → сжигание value без доставки и bounce. | **FIXED (локально)**: `WASM_XSHARD_CONTRACT_SEND_REFUSAL_HEIGHT = 0` — источник отказывает весь payload ДО любых мутаций; same-shard доставка не изменилась; inbound-проверки не тронуты. Тесты: `tests/review_final_cross_shard_contract_send.rs` (3). Реальный протокол — `stellereum/docs/specs/CONTRACT_XSHARD_SEND_REFUSAL.md`. |
| CONTRACT-BLOCK-HASH-ZERO | `host.block_hash` всегда отдавал 32 нуля (оба opcode-варианта и preview). | **FIXED, gated (локально)**: `CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT = u64::MAX` (выключено). При активации контракт видит **хеш родителя** (детерминирован, известен до исполнения). Тесты: `tests/review_final_contract_block_hash.rs` (3, оба состояния). **ACTIVATION-REQUIRED** для включения; RPC-preview и одиночный `apply_transaction*` пока передают ноль. |
| XSHARD-CONFIG-DIVERGENCE | `cross_shard_enabled` — node-local (`STELL_SHARDS`). Валидаторы на одном consensus-топике разойтись не могут, но одиночный **observer** на шардированной цепи применяет shard-0 блоки с флагом off и получает другой post-state. | **ACCEPTED (митигация)**: расхождение ловится громким `DIVERGENCE` и не форкает молча; observer шардированной цепи обязан `STELL_SHARDS=0,1`. Долгосрочный фикс (genesis-committed набор шардов / вывод burn-credit только из полей tx) — отдельный активационный пункт. |
| SYNC-BLIND-ANCHOR | «Тихий» узел (DHT-голова читает собственное эхо, proposals не приходят) в `blind-QC-probe` цеплялся за `tip+1` и принимал **по одному блоку за проход**. При темпе 2.5 бл/с узел, отставший на ~1000 блоков, физически не мог закрыть разрыв (CPU 38%, тики 0–17 мс) и оставался вне кворума. | **FIXED (локально, не задеплоено)**: blind-probe проверяет лестницу `+64/+256/+1024` (восходяще, до первого промаха) и якорит walk на **самой дальней решённой** высоте, включая батчевый/snapshot-путь. Liveness-only: каждый блок/QC/родитель/root по-прежнему проверяется. Тесты: `recovery_walk_closes_400_and_1100_without_a_new_snapshot`, `walk_ignores_uncertified_proposal_in_rt_blocks_and_fetches_decided_body`. |

Проверено и **не подтверждено** на текущем дереве (ревью опиралось на код до hardening-гейтов; добавлены тесты-пины, чтобы не «починили» обратно): PQ-oracle rollback (`review_exec_pq_oracle_revert.rs`), `SysCallCallContractArgs` в снапшоте, публикация сообщений контракта до `commit_native`, bridge-opcode после `Halt` (`r1_frozen_apply_svm_tests`).

## Аудит безопасности и оптимизаций (2026-11-23)

| ID | Находка | Статус |
|---|---|---|
| SEC-VOTE-CACHE-DOS | **HIGH.** Ключ verified-vote кэша содержал полную подпись из сети; лимит был по числу записей, не по байтам. Публичные id + подпись до 32 MiB → десятки «голосов» раздували память ноды без ключа. | **FIXED (локально, не задеплоено)**: каноническая длина проверяется до построения ключа; вердикт не изменился, такой голос просто не кэшируется. Тест `sec_s3_vote_cache_dos_tests.rs`. |
| SEC-SLASH-EVIDENCE-SCOPE | **MED.** Примитивы слэша не сверяли `shard_id`/`round` evidence с самим нарушением, хотя dedup-ключ их включал → повторный 5% burn за то же нарушение и false-slash на cross-round паре. | **FIXED (локально)**: проверки приведены к `verify_*_evidence`; в block-path и раньше отсекалось каноникализацией. Тесты `sec_s3_slash_envelope_scope_tests.rs`. |
| SEC-INFNODE-HANDSHAKE-MAP | **HIGH.** `handshake_buckets` ограничивался `rate × 5 мин`; IPv6 /64 без аутентификации → неограниченный рост → OOM. | **FIXED (локально)**: кап 4096 + reaper + LRU. |
| SEC-INFNODE-PEER-PROTOCOL-MAP | **MED.** Вердикты `peer_protocol` не чистились; ротация дешёвых Falcon-id росла вечно. | **FIXED**: кап 4096, `(state, Instant)`, вытеснение старейшего. |
| SEC-INFNODE-AUTH-BANS | **MED.** «Живые» баны не вытеснялись; истёкшие без повторного IP оставались. | **FIXED**: кап 8192, вытеснение ближайшего к истечению. |
| SEC-DHT-FIND-NODE-UNCAPPED | **MED.** Ответ `dht.find_node` обходился без лимита до валидации → десятки МБ `NodeInfo` с одного пира. | **FIXED**: `parse_dht_node_list` режет до `MAX_ROUTES_PER_UPDATE` до аллокаций. |
| SEC-DHT-STORE-KV-BYPASS | **MED.** `dht.store` без `stored_at` шёл в локальный writer и обходил `MAX_KV_ENTRIES/BYTES`. | **FIXED**: `store_replica` с capacity-check, отказ `ok:false`. |
| SEC-REP-SHARD-CAP | **MED.** Репутационный шард вставлял запись даже на «hard cap». | **FIXED**: вытеснение при капе. |
| SEC-MIME-DEPTH | **MED.** MIME-парсер рекурсировал по `multipart/*` без глубины → stack overflow от одного письма. | **FIXED**: `MAX_MIME_DEPTH=16`. |
| SEC-SNAP-UNIT-TAG-PANIC | **MED.** `group_units_by_tag` индексировал массив невалидным `unit_tag` из персистентного манифеста → panic при restore. | **FIXED**: `Result` + `UnknownUnitTag` до индексации. |
| SEC-SNAP-MERKLE-DUP-LAST | **LOW, ACTIVATION.** Duplicate-last правило позволяет переlabelить proof в дерево большего размера; production verifier не вызывается. | **ACTIVATION-REQUIRED** (меняет digest манифеста / v4 checkpoint). |
| SEC-PQ-EVIDENCE-SHARD | **MED, ACTIVATION.** PQ-evidence всегда использует masterchain-preimage; double-sign в другом шарде непроверяем → непунishable. | **ACTIVATION-REQUIRED** (wire: `shard_id` в evidence + новая dedup-домен). |
| SEC-GOV-OPEN-PROPOSALS | **LOW, ACTIVATION.** Нет кэпа открытых proposal'ов → O(#proposals) на блок и рост состояния. | **ACTIVATION-REQUIRED** (admission policy). |
| SEC-GOV-LEGACY-FINALIZE | **LOW.** Height-less `Governance::finalize` может дать `Passed` без timelock-записи. Живого вызова нет. | Report-only (убрать в следующем форке). |
| SEC-SNAP-TIP-SKIP | **LOW.** При отсутствии `finalized_post_root_v1` снапшот принимается без внешнего anchor (spec-pinned compat). | Report-only; окно только при локальной записи/порче. |
| SEC-DNS-BAILIWICK | **LOW.** Парсер принимает TXT с чужим owner-name; id всё равно должен выводиться из Falcon-ключа (≤32 пиров). | Report-only (fail-closed по ключу). |
| SEC-DNS-LOOKUP-TIMEOUT | **LOW.** `resolve_peer_endpoints` без таймаута на хост; враждебная seed-зона может затянуть фоновый проход. | Report-only. |
| PERF-S4-HOTPATH | 5 безопасных оптимизаций: один governance-снапшот, CLOB без клона `TokenRegistry` на консенсусных путях, без deep-clone `ClobEvent`, read-only mailbox fast path, `Linker` через `OnceLock`. | **FIXED (локально)**: counting-тесты `perf_s4_*`; wall-clock не измерялся. |

## Вторая волна аудита (2026-11-23, bridge/EVM/oracle/xshard)

| ID | Находка | Статус |
|---|---|---|
| BRIDGE-REFUND-WINDOW | **HIGH.** Refund заявки, запаркованной в ПРОШЛОМ часовом окне, безусловно вычитал сумму из `hourly_withdrawn` текущего окна → серией таких refund'ов можно было обнулить текущий лимит и вывести >2× `HOURLY_RATE_LIMIT_NANO`. | **FIXED (локально, не задеплоено)**: вычитание только если `requested_at >= last_rate_limit_reset`; инвариант восстановлен. Тесты `tests/x6_bridge_accounting_tests.rs` (fail-before). Меняет committed-счётчик для pre-window refund → нужен согласованный апгрейд. |
| XSHARD-BOUNCE-MINT | **CRITICAL (multi-shard only).** Timeout-bounce возвращал `tx.amount` по outbound-записи, которая доказывает только связность, а не списание на источнике: (a) валидно подписанная tx с `nonce=u64::MAX` падает на apply (дебета нет), запись создаётся, через 64 высоты bounce минтит value; (b) 2PC-escrow + legacy-запись + bounce → target кредитует COMMIT, source возвращает refund (двойная трата). | **ACTIVATION-REQUIRED**: фикс в `runtime/**` (produced только при `status[i]==true`, inclusion/escrow proof для outbound, escrow-leaf перед bounce, отказ при наличии 2PC-записи; зеркала движка синхронно). В `{0}` недостижимо; обязателен до включения `{0,1}`. → Гейт `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` и тесты добавлены (Волна 9, 2026-11-26), но гейт остаётся `INERT (u64::MAX)`; поведение на живой `{0}` не менялось. |
| XPC-PREPARED-UNBOUNDED | **HIGH (multi-shard).** `Prepare` принимает affordability-proof и пишет `PREPARED`; `is_retired` не ретирит `PREPARED`, а один funded-ключ создаёт неограниченно разных tx-hash на одном nonce → target забивается ~16 записями/блок навсегда. | **ACTIVATION-REQUIRED, РЕАЛИЗОВАНО за инертным гейтом (Волна 9, 2026-11-26)**: bounded per-source admission — `target_prepare_slot_available` (один активный `Prepared` на `(source_shard, from, nonce)` и `MAX_ACTIVE_PREPARED_PER_SENDER = 4`) + `XPC_PREPARE_TTL_HEIGHTS = 4_096` в `is_retired_at`; всё за `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT = u64::MAX`, на живой `{0}` не включено. Тесты: `xshard2pc` unit + `w9_core_polish_tests::xpc_prepared_unbounded_guard_blocks_same_nonce_spam_when_gated_and_preserves_pre_activation`. |
| BRIDGE-TARGET-ADDRESS-UNBOUNDED | **HIGH.** `TeleportWithdrawalRequest.target_address: String` не ограничен по длине и коммитится в `pending_withdrawals`; лимит только по сумме, количество бесплатно → state под контролем атакующего. | **FIXED (локально, за гейтом `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT = u64::MAX`)**: `MAX_BRIDGE_TARGET_ADDRESS_BYTES = 128`; проверка в `BridgeIntent::validate_at_height` (а `validate()` = высота 0, поэтому гейт-с-генезиса тоже ловится) и в `BridgeState::plan_at_height` — единственном пути, который паркует заявку, ДО rate-window/очереди. Ниже гейта вердикт байт-в-байт прежний (1 MiB проходит), на/выше — отказ с именем лимита. Тесты: `tests/h9_bridge_target_address_cap.rs` (5: ниже гейта 1 MiB, ниже гейта при назначенной активации, на/выше отказ, height-indexed validate + граница 128/129, обычный адрес). Включение — отдельное активационное решение. | `stellereum/src/bridge.rs`, `stellereum/src/chain_spec.rs` |
| XSHARD-REEMIT-ROTATION | **LOW.** `height % plan.len()` при периоде 64 и `plan.len() % 64 == 0` даёт постоянный offset — часть набора ждёт дольше. Самоисправляется, value не теряется. | Documented (proposer-policy). |
| XPC-DECIDED-ZERO | **LATENT.** `decided_height == 0` трактуется как «не решено»: COMMIT/ABORT-ACK применяется, но decision-leaf не пишется, а ошибка записи игнорируется. Недостижимо (target не может быть PREPARED до высоты 0). | Report-only (смена state-format sentinel). |

## Liveness и производительность (вторая волна, 2026-11-23)

| ID | Находка | Статус |
|---|---|---|
| LIVE-ROUND-TIMER | **HIGH.** Принятый peer-vote делает future-round chase внутри `on_prevote/on_precommit`; follow-up chase возвращал «already there» и **не перезапускал** `round_started` → следующий тик делал view-change мимо только что выровненного раунда. | **FIXED (локально)**: таймер перезапускается при любом наблюдённом движении раунда (vote и proposal alignment). |
| LIVE-BLIND-LADDER | **HIGH.** В лестнице якоря не было ступеней ниже 64: разрыв 2–63 блока принимался по одному блоку за проход и не закрывался за бюджет даунтайма. | **FIXED**: `2/4/8/16/32/64/256/1024`; дальнейший quorum-verified якорь садится в `peer_hint`, следующий проход получает gap-scaled budget и latch re-arm. |
| LIVE-SNAPSHOT-PROGRESS | **MED.** Snapshot-catch-up двигал finalized/hc/safety, но не штамповал progress → deadlock breaker на следующем тике делал ложный local re-phase. | **FIXED**: `advance_to_verified_snapshot()` + `record_progress`. |
| LIVE-COMMIT-PARK | **MED.** Park-guard был инвертирован (`height == hc.height` вместо `H+1`): единственный adoptable commit отбрасывался, а избыточный занимал слот. | **FIXED**: паркуется только `H+1`; parked commit переигрывается через обычный drain (persistence/receipts/QC-sidecar/publication). |
| LIVE-PARK-SLOT | **MED.** Слот парковки принимал любую высоту — одна junk-запись вытесняла реальный `H+1`. | **FIXED**: принимаются только replayable высоты. |
| LIVE-QC-EVIDENCE | **MED.** Blind-QC sidecar влиял на бюджет/latch после простого decode+height. | **FIXED**: persistent evidence требует реальный Precommit-кворум под набором на этой высоте; непроверенный sidecar лишь ограничивает walk. |
| PERF-S7-TRANSPORT | 12 безопасных оптимизаций: BLAKE3 один проход на chunk, dedup под read-lock, zero-copy fan-out/mail/blob, base64 прямо в буфер, precomputed XOR-сортировка, prealloc `closest`, Merkle leaf без Vec. | **FIXED (локально)**: counting/differential тесты `perf_s7_*`; byte-identity зафиксирована. |

## Правило закрытия

Дефект считается закрытым только если: (1) есть тест, падающий на коде до фикса;
(2) полный параллельный гейт зелёный; (3) бинарь задеплоен на A/B/D и цепь
финализирует. «Код исправлен, но не выкачен» — это DEPLOYED-1, отдельный статус.

## Отложено осознанно (`SEPARATE SYSTEM`)

Это не «забытые» дефекты: каждое направление требует отдельного контракта,
бюджета и аудита и не блокирует текущий релиз.

| ID | Тема | Почему отложено |
|---|---|---|
| SYS-ZKML | zkML без ZK | Сейчас это re-execution, а не zero-knowledge; ZK-верификатор — отдельная криптосистема с собственным trusted setup и аудитом. |
| SYS-EVM-CONTRACTS | EVM-контракты | Поддержаны только переводы; EVM-исполнение и совместимость — отдельный слой адаптера, а не расширение текущего моста. |
| SYS-SPLIT-MERGE | Динамический split/merge шардов | Текущий канон — фиксированная пара `{0,1}`; динамика меняет validator-set, state routing и cross-shard 2PC одновременно. |
| SYS-SECOND-CLIENT | Второй клиент | Нужен независимый консенсус-клиент и его спека для differential-тестов; вне текущего скоупа. |
| SYS-WALLET-CONNECT | wallet/connect | Внешний кошелёк и connector-протокол — продуктовый слой; на консенсус и state root не влияет. |

## Сплошной аудит Волны 6 и фиксы Волны 7 (2026-11-25)

Волна 6 (8 read-only агентов) + Волна 7 (6 фикс-агентов + независимый аудит диффов):

* **Закрыто в коде (с регрессионными тестами, `clippy --workspace -D warnings` 0/0, `cargo-audit` 0 уязвимостей):**
  * **Консенсус / Safety / PQ:** `W6-A1-1` (Critical: UTF-8 срез в `adopt.rs`), `W6-A1-2` (`finalize_restore_qc_verified`), `W6-A2-4` (write-ahead до `adopt_committed`), `W6-A1-3/5` (`RemoteSigner` v2 `/v2/set_lock` + cross-kind + `https_only`), `W6-A1-6`, `W6-A7-5/6/8` (`LightHeader` PQ без отката в Ed25519, `explicit_pinned` в `FALCON_PUBKEY_CACHE`, FIPS-203 проверка ML-KEM-768) → `tests/w7_consensus_crypto_fixes.rs`.
  * **Storage / State / Recovery:** `W6-A2-1` (Critical: персистентность `STELL_EVM_SETTLED_V1` в `evm_settled_state`), `W6-A2-2` (`SnapStateV4` `restore_pq_registry`), `W6-A2-3`, `W6-A2-5/6/7` (`prune_state_below` по paired-высотам, `bump_commitment_generation` на mint/release, индекс-первое удаление чеков) → `tests/w7_storage_recovery_fixes.rs`.
  * **P2P / `infnode`:** `W6-A3-1..10` (`MAX_PUBSUB_DATA_LEN = 16 MiB`, пост-auth `CHALLENGE`, `MAX_UNSEALED_BLOB_BYTES = 64 MiB`, проверка подписи в `CompactReceiver`, защита `dht.lookup` от циклов, LRU маршрутов и чанкование gossip, ACL `m:`/`f:` + fail-closed TOFU, подписанные `infmail` `acct:`, `reorder` по `(src, origin)` + `(topic, msg_id)`) → `tests/w7_p2p_hardening_fixes.rs`.
  * **SVM / Контракты:** `W6-A4-3/4` (немедленный table-cap и `FUEL_FALCON512_VERIFY_V2` в `stell_runGetMethod`), `W6-A4-5` (фиксы в `sts20-token`, `liquidity-pool`, `account-object`, `stl-dns`, `e2e-tests` 7/7 + `wasm32`) → `tests/w7_svm_and_contracts_fixes.rs`.
  * **RPC / SSE / Индексатор / Ключи / SDK / Ops:** `W6-A5-1..8`, `W6-A6-3/4/6/9/12`, `W6-A8-1/2/4..15` → `tests/w7_rpc_indexer_keys_fixes.rs`, `stellereum-indexer/tests/w7_indexer_hardening.rs`, `sdk-js` 33/33, `ops/status` 8/8.
* **За высотными гейтами (`u64::MAX`, `INERT`, ждут активационной волны):**
  * `W6-A4-1/2`: `ACTOR_MAILBOX_HARDENING_HEIGHT` (запрет несанкционированных `Transfer`/дебитов в чужом `inbox` и биллинг `host.send_message` `gas_budget`).
  * `W6-A7-1` / `W6-A1-4`: персистентность `cnvrf_freeze_inputs` и догонка `epoch_vdf` при `CNVRF_V3_ACTIVATION_HEIGHT`.
  * `W6-A7-2/3/4`: паркованный `mev_epoch.rs` (`OrderCommitment`/`ShareRelease`/`EpochKeyAnnouncement`).
  * `W6-A7-7`: modulo-bias в `sortition`. → РЕАЛИЗОВАНО (Волна 10, 2026-11-26) за `SORTITION_UNBIASED_ACTIVATION_HEIGHT` (INERT `u64::MAX`); см. «Волна 9–15».
* **Вне кодового скоупа на момент Волны 7 (зафиксировано, тогда не правлено; `W6-A6-*` закрыто в Волне 9 — см. ниже):**
  * `W6-A6-1,2,5,7,8,10,11` в `stell-wallet/` (отложенные пользовательские правки — SPV leaf-decode, `pq-transfer` chain-binding, stealth plaintext fallback, `faucet_token` HTTP check, zeroization, fake `aa` commands, local sim overflow/permissions). → FIXED (Волна 9, 2026-11-26): см. раздел «Волна 9–15» (шесть из семи подтверждены новыми тестами; `W6-A6-8` — код без отдельного fail-before теста).

## Волна 8 — Дозакрытие остаточных уязвимостей и блокера разджейливания (2026-11-25)

* **Закрыто в коде с регрессионными тестами (`cargo fmt --all --check`, `cargo clippy --workspace --locked --all-targets -- -D warnings` 0/0, `stellereum --lib` 1527/1527, `stellereum --bins` 113/113, `consensus_liveness_harness` 13/13, все 4 W8-сьюта и `stellereum-upgrader` 27/27 зелёные):**
  * **Supply chain и сеть:** `W6-A8-3` — все 36 `uses:` в `.github/workflows/{ci,fuzz,nightly,release}.yml` запинованы к точным 40-hex commit SHA; `SEC-DNS-LOOKUP-TIMEOUT` — `resolve_peer_endpoints` ограничен `DNS_HOST_LOOKUP_TIMEOUT = 5s`; `FAUCET-EXPLORER-GATEWAY` остаток — убраны все вызовы `pool.all()` из `explorer.rs` (добавлен `Mempool::matching_account`) → `tests/w8_supply_and_network_fixes.rs` (3/3).
  * **CN-VRF v3 и паркованный `mev_epoch` (`W6-A7-1..4`, `W6-A1-4`, `retention.rs`):** персистентность `cnvrf_freeze_inputs` в отдельном дереве sled и запрет тихого пропуска seed после `H_freeze`; извлечение/проверка `epoch_vdf` в `adopt_committed` и `walk_chain_once_with_lanes` до `committee_schedule_at`; PQ-подписи, членство комитета, анти-эквивокация и DLEQ/Feldman-проверка в `mev_epoch.rs` / `runtime/mev_sync.rs`; `saturating_add(1)` в `storage/retention.rs` → `tests/w8_cnvrf_and_mev_hardening_tests.rs` (15/15).
  * **Safety, Sync, WS, ABI:** сохранение `last_non_nil_prevote` при апгрейде `LegacyConsensusSafetyStateV1` (`remote_signer.rs`); проверка `shard_id` в `cheap`-ветке `adopt.rs`; учёт `latest_snap_committed()` при проверке свежести набора (`consensus_driver/mod.rs`); разбор объектного и строкового `stell_unsubscribe` в WS (`rpc/streams.rs`); фикс bare length-prefixed fallback в `ContractAbi::decode_return` → `tests/w8_polish_hardening_tests.rs` (3/3).
  * **CLI, `unjail` под D2-штрафом, `stellereum-upgrader`, systemd:** `--gas-limit` + автоэскалация газа (`2x..16x`, cap `5_000_000`) при `"below the base fee"` в `validator unjail` / `wallet unjail` (проверено вживую: разджейлены `C` и `D` и возвращён кворум `4/4`); `W6-A8-12` — `--falcon-seed-file` + `STELL_FALCON_SEED` с `Zeroizing` и перевод `scripts/soak_two_shard.sh` на `0600` key-file; запрет 3xx-редиректов/proxy-env в `UpgradePlan::read_rpc`, передача `rpc_plan` в `run_supervise`, проверка прав/симлинков в `Progress::record`; харденинг `scripts/systemd/stellereum-indexer.service`; синхронизация `ACTIVATION_BATCH_1.md` A7 → `tests/w8_cli_unjail_and_upgrader_tests.rs` (30/30), `stellereum-upgrader` (27/27).

## Волна 9–16 — закрытие шероховатостей, инертных гейтов и пост-аудитных находок (2026-11-26)

Снимок: рабочее дерево поверх HEAD `ab0adbf08` после прохождения Волн 9–16 и
пост-аудитного ревью/фиксов (см. `docs/audits/AUDIT_HANDOFF_2026-11-26.md`).

**Статус проверок:** подтверждено локальными прогонами в рабочем дереве:
`cargo fmt --all -- --check` (PASS), `cargo clippy --workspace --locked --offline --all-targets -- -D warnings`
(0 предупреждений / 0 ошибок), `stellereum --lib` (`1530/1530`), `stellereum --bins`
(`113/113`), все сьюты `w8..w16` и 27 оставшихся интеграционных наборов из `ci_local.sh`
(включая `consensus_liveness_harness` `13/13`), `stellereum-indexer` (включая `w14_multishard_backfill_tests` `6/6`
и `indexer_api_tests` `12/12`), `stell-wallet` (все таргеты green), `stellereum-wasm` (`unit` + `wasm32-unknown-unknown` build),
`stellereum-contracts` (`--workspace` + пересборка 4 `wasm32` контрактов), `sdk-js` (`typecheck` + `45/45`),
`explorer-site/backend` (`7/7`). Живой кластер не перезапускался (`DEPLOYED` для этих правок не ставится).

### CLI и кошелёк

| Область | Что сделано | Статус | Тест / файл |
|---|---|---|---|
| `stellereum wallet generate` / `address` | Ключ и адрес теперь **Falcon-512** (897 B pk, 666 B sig, `STL_ADDR_V4`), а не Ed25519. `generate` печатает 32-байтный seed в `Zeroizing`, `address` выводит spendable PQ-адрес. | FIXED (в дереве, не задеплоено) | `w9_cli_wallet_and_config_tests.rs::wallet_generate_and_address_derive_spendable_falcon_pq_address`; `stellereum/src/cli/handlers.rs:422-476` |
| `wallet balance` | Идёт через RPC (`stell_getBalance` + shard/address), а не по локальному файлу; при недоступном RPC — явная ошибка, не выдуманный ноль. | FIXED (в дереве; сетевой путь не прогонялся) | `stellereum/src/cli/handlers.rs:440-460`; отдельного сетевого теста нет |
| `--falcon-seed-file` | Seed читается из файла `0600`/stdin/`STELL_FALCON_SEED` с `Zeroizing`, argv-seed остаётся deprecated. | FIXED (в дереве) | `cli_parses_wallet_consistency_and_falcon_seed_file_flags` (тот же файл) |
| `remote-signer serve` | Добавлена подкоманда `remote-signer serve` (v2 `/v2/public_key`, `/v2/sign`, `/v2/set_lock`), `--genesis-hash`/`--shard`, ограничение 32 одновременных соединений, общий дедлайн `DeadlineReader`, корректный выход по Ctrl-C/SIGTERM и unit `scripts/systemd/stell-remote-signer.service`; без URL/токена и вне loopback путь fail-closed, локального фоллбека нет. | FIXED (в дереве; сервис не установлен) | `w9_cli_wallet_and_config_tests.rs` (23/23); `scripts/systemd/stell-remote-signer.service` |
| `contract deploy` / `contract call` | CLI строит и подписывает Falcon-512 `SysCallDeployContract` / `SysCallCallContract` (JSON-аргументы, `--calldata`, `contract_address` по `tx.nonce`), а не только WAT-пример. | FIXED (в дереве) | `w9_cli_wallet_and_config_tests.rs` (23/23); `stellereum/src/cli/args.rs` |

Итого по файлу `w9_cli_wallet_and_config_tests.rs` — **23** теста (включая `node_config_round_timeout_warning_and_toml_example_valid`, `acquire_node_dir_lock_rejects_concurrent_lock_and_releases_on_drop`, `--calldata`, `remote-signer serve`, `--node-toml` и `verify_signature_for_chain` self-checks).

### `stell-wallet/` — семь дефектов W6-A6

| ID | Было | Исправлено | Тест | Статус |
|---|---|---|---|---|
| `W6-A6-1` | SPV-баланс не проверял, что `leaf_data` действительно кодирует `balance || nonce`; подделанный лист проходил. | Декодирование листа (включая 49-байтный PQ-лист) и сверка с заявленными `balance/nonce`; подделка отвергается. | `w9_wallet_hardening_tests.rs::w6_a6_1_spv_rejects_forged_balance_with_real_16_byte_leaf_data`, `::w6_a6_1_spv_supports_49_byte_pq_leaf_and_rejects_forged_balance` | FIXED (в дереве) |
| `W6-A6-2` | `pq-transfer`/`pq-payload` подписывали unbound конверт, который после chain-binding активации не проходил бы. | `build_pq_transfer_tx_bound` / `build_pq_payload_tx_bound` + `resolve_sign_chain_id`; legacy-строители оставлены как явный unbound escape hatch. | `wallet_chain_binding_tests.rs` (4: `bound_pq_transfer_verifies_only_on_its_chain`, `bound_pq_payload_carries_stake_and_binds`, `legacy_pq_builders_stay_unbound_but_verifying`, `transaction_chain_parity_between_paths`) | FIXED (в дереве) |
| `W6-A6-5` | Stealth-выходы читались из незааутентифицированного plaintext JSON (вектор подмены). | `load_stealth_outputs_with_password` требует пароль и отказывает plaintext-fallback. | `w6_a6_5_plaintext_stealth_outputs_rejected_with_password`; `stell-wallet/src/notes.rs:1164` | FIXED (в дереве) |
| `W6-A6-7` | `faucet_drip` мог отправить `STELL_FAUCET_TOKEN` по cleartext/не-loopback URL. | Проверка политики URL/токена **до** сети; не-loopback `http://` отвергается. | `w6_a6_7_faucet_drip_refuses_non_loopback_http` | FIXED (в дереве) |
| `W6-A6-8` | Passphrase/seed/hex жили в обычных `String`/`Vec`. | `Zeroizing` для seed, passphrase, hex-seed (`pq.rs`/`security.rs`/`client.rs`); `SecureSecret`/`HardenedKeystore` не логируют секрет; notes-ключ зануляется. | `wallet_pq_tests::test_secure_memory_scrubbing_and_no_leak` (проверка Debug-редакции); код проверен, `stell-wallet` tests green | FIXED (в дереве) |
| `W6-A6-10` | `stell aa` печатал «успех» без on-chain вызова. | Все `AaCommands` fail-closed с явным сообщением «no transaction was sent»; `revoke_session` не притворяется успешным. | `ux_pay_accepts_stl57_address_and_aa_fails_closed`, `wallet_aa_revoke_tests::revoke_session_fails_closed_even_with_a_valid_wallet`, `wallet_privacy_integration_tests::test_cli_excised_privacy_commands_fail_closed` | FIXED (в дереве) |
| `W6-A6-11` | Локальная симуляция переполнялась, приватные файлы писались с широкими правами. | Overflow-checked атомарный локальный broadcast (без частичных списаний, включая rollback `to`), приватные файлы `0600`. | `w6_a6_11_local_broadcast_rejects_overflow_atomically`, `w6_a6_11_private_files_written_with_0600_mode` | FIXED (в дереве) |

`stell-wallet` исключён из корневого workspace (`Cargo.toml` → `exclude`),
поэтому проверяется отдельным прогоном (`cargo test --manifest-path stell-wallet/Cargo.toml`: все таргеты прошли, 0 падений).

### SDK / ABI

| Область | Что сделано | Статус | Тест |
|---|---|---|---|
| `stellereum-sdk` | Добавлены `Op::DeployContract`, `Op::DeployContractWithAbi` и `TxIntent::ContractDeploy`; wire-дискриминант **65**, gas-оценка и `Transaction::deploy_contract*` совпадают с узлом. | FIXED (в дереве) | `stellereum-sdk/src/{opcode,tx,signer}.rs`; `w10_deploy_contract_abi_tests::opcode_discriminant_is_65_and_wire_and_gas_match_sdk_layout` |
| `CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT` | `SysCallDeployContractWithAbi` валидирует ABI (≤ `MAX_CONTRACT_ABI_BYTES`), деплоит и сохраняет `ContractAbi` в `ContractRegistry`/`state_root`; ниже гейта — fail-closed revert. | **INERT (`u64::MAX`)** — реализовано, не включено | `w10_deploy_contract_abi_tests` (4/4: inert+registered, discriminant 65, on-chain persist, rejected/oversized ABI) |
| `sdk-js` | Добавлен `contractCallRaw`/`contract_call_raw`, `contractDeploy` берёт `baseFee()`, валидация `evm_carrier` non-zero, зануление `sk`, bounds checks; `npm run typecheck && npm test` **45/45** зелёные. | FIXED (в дереве) | `sdk-js/test/*.test.ts` (45/45); `sdk-js/package.json` |
| `stellereum-wasm` + `WasmFalconSigner` | Отдельный `wasm32-unknown-unknown` cdylib с C ABI (`alloc`, `falcon_keygen`, `falcon_sign_with_entropy`, `falcon_verify`, `falcon_derive_address`), фикс длины `"STL_ADDR_V4"` (11 B) и `__getrandom_v03_custom` zero-output guard; `sdk-js/src/wasm_signer.ts` грузит его и зануляет линейную память. | FIXED (в дереве) | `stellereum-wasm/src/lib.rs` (4/4 + `wasm32` release build); `sdk-js/test/wasm_signer.test.ts` |

### Контракты

| Область | Что сделано | Статус | Тест |
|---|---|---|---|
| `*_pq` entrypoints + `SLOT_PQ_MODE` | В `sts20-token`, `account-object`, `liquidity-pool`, `stl-dns` работают PQ-точки входа (`init_pq`, `transfer_pq`, `transfer_from_pq`, `approve_pq`, `mint_pq`, `burn_pq`, `create_session_pq`, `deposit_pq`, `withdraw_pq`, `resolve_pq`, …) под 32-байтный `host.caller`; добавлен `SLOT_PQ_MODE` для блокировки неаутентифицированных legacy entrypoints после `init_pq`, фиксы `checked_add`/zero-reserve/`i64::try_from`, пересобраны 4 `wasm32` контракта. | FIXED (в дереве; контракты вне root workspace) | `stellereum-contracts` `--workspace` (green, включая `w9_pq_contract_auth_tests.rs`) |
| Старые packed-`i64` entrypoints | `init`, `transfer`, `approve`, `deposit`, … при отсутствии `init_pq` остаются **DEMO-GRADE** shim'ами с integer id (`caller_is`), без внешнего аудита. | BY DESIGN / DEMO-GRADE | `stellereum-contracts/README.md`; заголовки `contracts/*/src/lib.rs` |

### Консенсус-гейты (все — `INERT u64::MAX`)

| Гейт | Значение | Что реализовано | Тест |
|---|---|---|---|
| `SORTITION_UNBIASED_ACTIVATION_HEIGHT` | `u64::MAX` (INERT) | `rejection_sample_u64` + `select_committee_from_seed_at` / `proposer_from_digest_at`; ниже гейта — побайтово прежний modulo-путь. | `w10_sortition_and_jail_gates_tests.rs` (6/6) |
| `JAIL_BUDGET_V2_ACTIVATION_HEIGHT` | `u64::MAX` (INERT) | `DOWNTIME_MISS_THRESHOLD_V2 = 200` (80 s при 400 ms) и `downtime_miss_threshold_at(height)`; ниже гейта — 42. | тот же файл (`jail_budget_v2_*`) |
| `EXECUTION_PIPELINE_V1_ACTIVATION_HEIGHT` | `u64::MAX` (INERT) | `committed_state_height_at` (lag 2), `anchor_height_for_post_state_at` (S+2), `VecDeque` `apply_in_flight`, `ApplyLane` penalty snapshot, `PendingExecView`, proposer/adopt/catchup lag-2 gating, `post_state_roots` seed при старте/снапшоте. | `w12_pipeline_gate_tests.rs` (7/7), `w12_pipeline_runtime_state_tests.rs` (11/11) |
| `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` | `u64::MAX` (INERT) | Bounded per-source PREPARE (`MAX_ACTIVE_PREPARED_PER_SENDER = 4`) + TTL `4_096`, всё за гейтом; см. `XPC-PREPARED-UNBOUNDED`. | `x8_bounce_escrow_gate.rs`, `activation_gate_xshard_bounce_escrow_tests.rs`, `w9_core_polish_tests::xpc_prepared_*` (10/10) |
| `CNVRF_V3_ACTIVATION_HEIGHT` (schedule-only) | `u64::MAX` (INERT) | Готовность CN-VRF v3: многоэпоховый переход Producer/Adopter, churn набора в середине эпохи, отказ `Beacon(None)` и подделанного `epoch_vdf`; активация по-прежнему выключена. | `w11_cnvrf_epoch_churn_tests.rs` (3/3) |

**Важно:** четыре гейта — `SORTITION_UNBIASED`, `JAIL_BUDGET_V2`,
`CONTRACT_ABI_ONCHAIN` (см. раздел SDK/ABI) и `EXECUTION_PIPELINE_V1` —
**не входят в `FORK_ID_RULES`** (`docs/audits/AUDIT_HANDOFF_2026-11-26.md`
§1.2). Их включение координируется общей высотой активации и одним бинарём,
а не сменой `FORK_ID`; «тот же `FORK_ID`» не доказывает одинаковое поведение
разных бинарей на этих гейтах. `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` тоже
не входит в `FORK_ID_RULES`; `CNVRF_V3_ACTIVATION_HEIGHT` — schedule-only.

### Storage и инструменты

| Инструмент | Что сделано | Статус | Тест |
|---|---|---|---|
| `stelops compact` | Offline-перестройка store: отказ без `--force`, отказ при живом lock, копия `.pre-compact.*`, повторное открытие каждого дерева и сверка счётчиков/хешей перед атомарным переносом. | FIXED (в дереве) | `scripts/tools/stelops/src/main.rs` (`compact_refuses_without_force_and_missing_store` и др.) |
| `stellereum-ledger-tool verify-store` | Проверяет связность блоков и высоты в store, отвергает битый/не-store вход; остаётся автономным офлайн-инструментом. | FIXED (в дереве) | `stellereum-ledger-tool/tests/cli.rs::verify_store_checks_linked_blocks_and_rejects_broken_or_non_store` |

### Ops

| Область | Что сделано | Статус | Где |
|---|---|---|---|
| `join-testnet.sh` | `STELL_MIN_BLOCK_MS=400`, bootstrap через `stellereum store bootstrap` (snapshot + safety-init), `--skip-snapshot`/`--refresh-store`, честные проверки store. | FIXED (в дереве; не прогонялся) | `scripts/join-testnet.sh` |
| `run-observer.sh` | Тот же `store bootstrap --observer` + `safety-reset` для чужого `safety_record_v1`; observer больше не стартует с пустым store. | FIXED (в дереве) | `scripts/run-observer.sh` |
| prune | `PRUNE_GRACE`/`PRUNE_MAX_KV_AGE = 7200` (2 h) и `flock` на весь проход — cron-тик не может идти параллельно с ручным. | FIXED (в дереве) | `scripts/node-prune-cron.sh` |
| graceful stop | `TimeoutStopSec=300` в `stell-nodeA/B.service` (C/D в этом дереве его не несут — проверять деплой). | FIXED (в дереве; только A/B) | `stellereum/scripts/systemd/stell-node{A,B}.service` |
| `status_server.py` | Явные порты кластера (`127.0.0.1:8095`, targets 9080/8546/18081/9081/18552/9082), поле `jailed` per-node, `unknown` вместо выдуманных значений. | FIXED (в дереве; сервис не перезапускался) | `ops/status/status_server.py` |
| `node_exporter` | Идемпотентный `setup-validator-monitoring.sh`: remote `:9100` только на loopback + SSH-туннели A/C/D. | FIXED (в дереве; на хостах не применялся) | `scripts/setup-validator-monitoring.sh` |
| cosign | `verify-cosign-artifact.sh` (`--require`/`--if-present`, OIDC identity, `.sha256`), подключён в `rolling-deploy.sh` и `auto-bootstrap-store.sh` (`--require-cosign`). | FIXED (в дереве; артефакты не проверялись) | `scripts/verify-cosign-artifact.sh`, `scripts/rolling-deploy.sh`, `scripts/auto-bootstrap-store.sh` |

### Индексатор

| Область | Что сделано | Статус | Тест |
|---|---|---|---|
| Мультишард-бэкфилл и роутинг | `syncer.rs` читает `stell_getShards`, бэкфиллит все активные шарды, отклоняет trailing bytes в `raw_tx`, корректно пересчитывает `accounts.tx_count` при реорге, а `get_shards`/фильтры используют longest-prefix маршрутизацию и shard-0 `mc_seqno`/`lag`. | FIXED (в дереве; индексер не перезапускался) | `stellereum-indexer/tests/w14_multishard_backfill_tests.rs` (6/6) |
| Честные метрики | `/api/overview` и `db::get_stats` больше не зажимают значения в `[0.48, 0.50]` / `.max(1.0)`: `tps`, `avg_block_time`, `yesterday` считаются из реальных данных; chain id конфигурируется. | FIXED (в дереве) | `w9_indexer_honest_stats_tests.rs` (2/2), `indexer_api_tests.rs` (12/12) |
| Deploy-ABI без RPC | ABI из `SysCallDeployContractWithAbi` берётся из метаданных tx, а не дозапрашивается по RPC; revert не персистит ABI и не ставит `has_abi`. | FIXED (в дереве) | `w10_indexer_abi_deploy_tests.rs` (2/2) |

### RPC

| Область | Что сделано | Статус | Тест |
|---|---|---|---|
| `ShardRpcRouter` | Общий `Arc<RwLock<BTreeMap<u32, Arc<RpcState>>>>`; bootstrap регистрирует каждый hosted shard, поэтому HTTP/WS шарда 1 наконец доступны с любой ноды, а не только с локального движка. | FIXED (в дереве; живой кластер не обновлялся) | `stellereum/tests/w14_shard_rpc_router_tests.rs` (5/5); `stellereum/src/rpc/state.rs`, `node/bootstrap.rs` |

### MEV

| Область | Что сделано | Статус | Тест |
|---|---|---|---|
| `MevKemRegistry` + peer gossip + DLEQ | `bootstrap` выводит 64-байтный ML-KEM seed (`derive_mev_kem_seed`), `MevFrame::KemKey` (`chain_id`-привязанный `KemKeyAnnouncement` с проверкой `activation_height <= now_height` и `merge_non_conflicting`) распространяет ключи пиров по P2P, а `MevFrame::PqRelease` проходит обязательную Chaum-Pedersen DLEQ-проверку (`ingest_release_authenticated_with_ephemeral`). | FIXED (в дереве; не выкачено на живой кластер) | `w11_mev_kem_registry_wiring_tests.rs` (8/8) |

### Документация

| Документ | Что обновлено | Статус |
|---|---|---|
| `docs/site/00-index.md`, `01-quickstart.md`, `03-contracts.md`, `04-validators.md`, `05-operators.md` | Актуальные CLI (`wallet generate/address/balance`, `--falcon-seed-file`, `contract deploy/call`), 14 host-импортов, `*_pq`-контракты, `STELL_SHARDS=0`, faucet-лимиты, join/observer/prune. | FIXED (в дереве) |
| `stellereum/docs/RPC.md` | Таблица auth-политики (`stell_deployContract`/`stell_callContract` — TOKEN-ALWAYS), `stell_getShards`, shard-aware методы, deploy/call. | FIXED (в дереве) |
| `stellereum/docs/WALLET_SIGNING.md` | Falcon-512 как единственная живая схема, удаление Ed25519/Hybrid, точные размеры конверта, `sign`/`verify`/typed-data, anti-oracle. | FIXED (в дереве) |
| `docs/TESTNET_UX_COMPARISON.md` | Живой testnet `rpc.stellereum.org`, faucet 2 STELL / 45 min / 50 STELL cap, границы доверия. | FIXED (в дереве) |
| `docs/audits/AUDIT_HANDOFF_2026-11-26.md` | Пакет для внешнего аудитора: заморозка `FORK_ID`, 14 гейтов, 18 незмеренных ячеек, честные ограничения. | FIXED (в дереве; актуализирован) |

### Независимый верификатор (`stellereum-verifier`)

Что **есть** (включён в корневой `Cargo.toml` workspace, проверено прогоном):

* 7 модулей (`wire`, `falcon512`, `block_hash`, `consensus`, `tx`, `commitment`, `lib`);
  чистый Rust без зависимости от `stellereum` в `[dependencies]` (`stellereum` только
  в `dev-dependencies` для differential-тестов).
* CLI `src/main.rs`: `verify-tx`, `verify-block`, `verify-chain`, `verify-proof`,
  `verify-snapshot`, `--chain-id`, `--validators`, `--require-qc`, `--require-chain-id`,
  `--verify-txs`, `--absent`, строгая валидация конфликтующих флагов; exit codes 0/1/2.
* `VerifierCommitmentSnapshot` хеширует все 17 доменов (включая `zkml`, `cnvrf`,
  `total_minted_nano`, `evm_bindings`, `pq_registry`); `verify_block` проверяет `last_qc`
  криптографически; `verify_tx` проверяет `SF1`/`SP1` политики и канонический
  `split_sponsor_envelope`.
* Differential-тесты `diff_block_qc`, `diff_commitment_root`, `diff_quorum_sortition`,
  `diff_tx_envelopes`, `fuzz_corpus_parity` + unit/CLI-тесты.

### Закрыто в Волнах 9–16 + пост-аудитных фиксах и оставшиеся пробелы (2026-11-26)

1. **MEV peer KEM gossip + DLEQ — FIXED (в дереве).** Реализованы `MevFrame::KemKey`,
   `chain_id`-привязка и проверка `activation_height <= now_height` в `KemKeyAnnouncement`,
   устойчивый `merge_non_conflicting` и DLEQ-проверка на `MevFrame::PqRelease`
   (`w11_mev_kem_registry_wiring_tests.rs` 8/8).
2. **`stellereum-verifier` — FIXED (в дереве).** Добавлены подкоманды
   `verify-proof`/`verify-snapshot`, 17-доменный `VerifierCommitmentSnapshot`,
   крипто-проверка `last_qc` и `SF1`/`SP1` политик, включён в корневой `Cargo.toml`.
3. **Волна 12, фаза 2b (`EXECUTION_PIPELINE_V1`) — FIXED (в дереве, гейт `INERT u64::MAX`).**
   Реализованы `VecDeque` `apply_in_flight`, `ApplyLane` с захватом штрафов, `PendingExecView`
   с фильтрацией `is_in_flight` в `propose()`, сидинг `post_state_roots` при старте и снапшоте,
   `write_ahead_finalized_block` до `safety.advance_height` и lag-2 драйвер
   (`w12_pipeline_runtime_state_tests.rs` 11/11). Гейт остаётся `u64::MAX` до координированной
   активации.
4. **Волна 13 (`PARALLEL_EXEC_V2` + STM) — FIXED (в дереве, opt-in `parallel_exec`).**
   Исправлены кросс-доменные волны `Contract <-> Market/Staking` и `sync_aux_trie()` при отказе
   `commit_native` в ветке `Token` (`w13_parallel_native_and_stm_parity_tests.rs` 9/9,
   `w13_scheduler_access_tests.rs` 9/9, `w13_contract_stm_trace_tests.rs` 4/4,
   `w13_domain_overlays_tests.rs` 5/5). `stellereum.toml.example` сохраняет `parallel_exec = false`;
   живой замер на кластере остаётся `NOT MEASURED`.
5. **Волна 14b (динамический sharding split/merge) — FIXED (в дереве).**
   Реализована fail-closed миграция `sharding_migration.rs` (проверка непустых неподдерживаемых
   доменов, перенос `pq_registry`/`pq_keys_fallback`/`consensus_penalty`, split/merge
   `chain_mint_limit_nano` и `total_minted_nano`, проверка `tx_load`, SPV-листьев и токенов) —
   `w14_dynamic_sharding_tests.rs` 8/8, подключено в `scripts/ci_local.sh` и `.github/workflows/ci.yml`.
6. **`docs/feature_gates.yaml` — FIXED.** Перегенерирован командой `stellereum gates --yaml`
   (14 гейтов); `feature_gates::tests::committed_manifest_matches_the_table` зелёный.
7. **Остаётся `NOT MEASURED` / заблокировано на живом кластере:**
   * **`perf-matrix`:** все 18 ячеек `NOT MEASURED` (требуется живой `4/4` кластер и отдельный замер
     после восстановления `nodeB`/`nodeC`).
   * **Живой деплой / rolling-deploy / индексер / мониторинг:** заблокированы до восстановления `4/4`
     (после перезагрузки хоста `nodeA`/`nodeD` на `#727828`, `nodeB` застрял на `#658159` с отказом
     `snapshot-sync` на `#720000`, `nodeC` под высокой нагрузкой не отвечает по RPC).

## Волны 17–24 — многораундовый self-improving аудит и закрытие находок (2026-11-27)

Три цикла сквозного аудита (`C1–C3`, по 3–4 read-only агента) и 8 последовательно
проверенных волн фиксов (**Waves 17–24**) без изменения замороженного ядра
(`FORK_ID = 0x3ae00ebc`, Ruleset v7, Chain ID `5757`, все консенсусные гейты `INERT u64::MAX`):

* **Ядро `stellereum/src/` (Волны 17, 21, 23, 24):**
  * Детерминизм и инварианты: учёт `SysCallDeployContractWithAbi` в `pre_deploy_addrs` (`parallel.rs`), сортировка `pair_id` в `SysCallCancelOrder` (`svm.rs`), детерминированный порядок `qc.signatures` (`consensus/engine.rs`), fail-closed при падении apply-воркера в `adopt_committed` (`consensus_step.rs`).
  * Lock safety и async I/O: снятие локов до `.await` в `stell_getProgramAccounts` (`rpc/reads.rs`) и `admit_tx_from_ingress` (`propose.rs`, порядок `accounts` -> `mempool`), перенос фонового sled/`fsync` писателя на выделенный OS-поток `"stell-persist"` (`storage/persistence.rs`), батчевая гидрация `hydrate_rpc_from_store` и sled/WAT I/O в `spawn_blocking` (`rpc/{eth,contracts,state}.rs`, `storage/archive.rs`, `mempool::load_into`).
  * Защита от DoS / OOM и оптимизации: клонирование только целевого контракта в `preview_contract_call`, `OrderbookManager::clone_pair`, снятие двойной валидации деплоя до `falcon_host_fuel_v2` и `PqRegistry` RO-проверка (`svm.rs`), `BinaryHeap`-фронтир `select_multi` + кэш `TxMeta` + `O(|confirmed|)` `prune_confirmed` + `by_account` + удаление `mempool.all()` из `adopt.rs`, отказ от 0-байтных снапшотов + `PersistJob::DomainsBundle` + `prune_receipts_below` по `receipts_by_height`, ограничение `ValidatorRuntime::{blocks,finalized}` / `EvmAdapter` / `FalconPubkeyCache` / `VerifiedVoteCache` / `SharedSequencer` / `L2Sequencer`, фиксы `mev_epoch` (`roll_partials_to` + `valid_signature_count`) и `mev_kem_registry`, `evm_adapter` (`eth_feeHistory` `u64::MAX`, ASCII `get_balance`, `y_parity <= 1`, строгий `blockHash`), `light_client*` (таймаут/капы/lag-2), `remote_signer` `@`-userinfo bypass, `store_bootstrap` `tar -tvf` до `tar -xf`.
  * Liveness/P2P: `BodyPull::full_request` юникаст (`W6-A3-7`), `Body` index cap, `heal_engine_to_head` прогресс/таймаут/кэш, RAII `AtomicFlagResetGuard`, `PREFIX_SHARD_MEMPOOL` 512 cap, атомарный `publish_head`, 10с таймаут `publish_overlay`, 15с таймаут в `network/retention.rs`, pre-download QC verify и fail-closed drain timeout в `sync.rs`, параллельный shutdown в `bootstrap.rs`.
* **Индексатор, верификатор, fuzz, инструменты, SDK и контракты (Волны 18, 19, 22, 24):**
  * `stellereum-indexer`: `into_make_service_with_connect_info`, фикс `get_validators` post-sort `falcon_pubkey`, `PRAGMA busy_timeout`, композитный PK `contracts(shard_id, address)` с миграцией, журнал `token_balance_history` для отката при реорге, `spawn_blocking` хэндлеры, `fetch_abi` без кэширования временных ошибок.
  * `stellereum-verifier` и `stellereum-ledger-tool`: глубина JSON `64`, `0x`/`0X`, exit codes `1`/`2`, `--block` в `verify-snapshot`, `shard_id` continuity, `README.md`; не-мутирующий `verify-store` во временной копии с проверкой `.node.lock`, симлинков и обрезанного префикса заголовков; `stellereum-upgrader` `O_NOFOLLOW` + `(dev, ino)` + HTTPS/64KiB; `stelops` без `.expect()`-паник.
  * `stellereum/fuzz` и CI: 24 сида во всех 5 ранее пустых корпусах, `TEST_THREADS=1` для `--lib`, включение `stellereum-verifier`, `stellereum-wasm` (`working-directory: stellereum-wasm`) и `sdk-js` в `ci_local.sh` и `.github/workflows/ci.yml`.
  * `stellereum-contracts`, `stellereum-sdk`, `sdk-js`, `stellereum-wasm`, `stell-wallet`, `explorer-site/backend`, `ops`/`scripts`: полные `SLOT_PQ_MODE` и `*_pq` parity + `calldata_exact` + 256-bit `mul_div_u128` (`wasm32` пересобраны), `SP1` `SponsorAuthorization` + `SF1` `SessionGrant` + пустой `payload` в Rust/JS SDK, чистый браузерный SHA-256 и тесты на реальном `stellereum_wasm.wasm` (`56/56`), канонический солёный `PQ1` и `Zeroizing` + тест `W6-A6-8` в `stell-wallet`, BLAKE3 `Stl57` + единый bucket + IPv6 `/64` в `explorer-site/backend` (`17/17`), `status_server.py` (`14/14`), PromQL алерты (`NodeOutOfSync`/`PeersLost`/`FalconSignRate`), унификация `systemd` A/B/C/D и `scripts/*.sh`.

**Подтверждённый итоговый прогон (2026-11-27):**
* `./scripts/ci_local.sh --sdk`: **`CI_LOCAL_RESULT=PASS`** (`passed=6 failed=0`: `fmt`, `clippy --workspace --all-targets -- -D warnings`, `test-lib` `1602/1602`, 7 PR-сьютов `stellereum`, `sibling-suites` (`stellereum-verifier`, `stellereum-indexer`, `stellereum-ledger-tool`, `stellereum-upgrader`, `infnode`, `infmail`, `stellereum-sdk --features node-parity`), `stellereum-wasm` unit + `wasm32`, `sdk-js` `56/56` + `check:rpc-types` + `build`).
* Отдельно подтверждены после правок: `vuln_bundle_tests` + `pentest_state_wave`, `light_client_tests` (`22/22`), `stellereum-contracts` (`--workspace` + 4 `wasm32` билда), `stell-wallet` (все таргеты, `clippy 0/0`), `explorer-site/backend` (`17/17`), `stelops` (`5/5`), `ops/status` (`14/14`).
* Прим. по полному `--full` (`452/459`): 5 старых до-v7/до-W8 тестов (`activation_gates_inert`, `w4_engine_hardening_tests::wasm_table_elements_cap_gate_row_is_inert`, `downtime_restore_tests`, `network_audit_close_tests::tempo_c_slot_and_alignment_stay_put`, `hunt_consensus_round3::hunt23_adopt_committed_accepts_a_non_proposer_block`) содержат устаревшие ожидания, не затронутые Волнами 17–24.


