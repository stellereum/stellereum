# OPEN_DEFECTS — реестр найденных дефектов и статус закрытия

Snapshot: после пентеста-2 и кросс-кат свипа. Рабочие логи ревью/пентеста
удалены из публичного дерева (см. `docs/audits/INTERNAL_REVIEW_ARCHIVE.md`);
этот реестр сохраняет результаты и тесты-пины, по которым они закрыты.
Статус: Ruleset v7; `UP-5` (`stellereum-upgrader`) закрыт в дереве.
Обновлено на HEAD `c58375443` (+ HEIGHT-SPLIT wave; закрыты `--owner-key` и `store_mail`).
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

P0-READINESS-DEAD (FIXED в дереве, выкат — ближайшим rolling deploy, 2026-11-24).
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

P0-PEER-SNAPSHOT-ANCHOR (OPEN, 2026-11-23, liveness: catch-up blocked).
Отставший узел не может догнать цепь через снапшот, полученный от пира. Живые
наблюдения (`nodeB` на 155 243, `nodeC` на 171 697) дают два независимых отказа
проверки `snapshot anchor (tail)` в `src/sync.rs`:

1. `no header published at height <boundary-1>; cannot prove linkage` — заголовок
   на границе обязан быть в DHT, но публикация заголовков ограничена по глубине,
   поэтому «прогулка» от нашего anchor до границы снапшота недоказуема;
2. `finality: header proposer at height <h> held no schedule slot in rounds 0..=r`
   — исторический набор валидаторов, которым проверяется расписание пропозера,
   не совпадает с набором, действовавшим на той высоте (набор менялся на каждом
   джейле/разджейле `nodeC` в тот период).

Оба отказа — fail-closed и это правильно; дефект в том, что штатного пути
восстановления нет и узел висит до ручного вмешательства. Обход, применённый
дважды: восстановление из ПУБЛИЧНОГО HTTP-снапшота
(`https://rpc.stellereum.org/snapshot/latest.tar.zst` → `data/`) + `safety-reset`
+ `safety-init` (см. `ops/safety_recovery_runbook.md`). Требуется: (а) глубина
публикации заголовков ≥ максимального span снапшота, либо снапшот, несущий
собственный проверяемый префикс заголовков; (б) разрешение набора строго через
`validator_set_history` с отказом при отсутствии записи (сейчас возможен
«соседний» набор). Fail-before тесты: снапшот на границе, у которой заголовок
не опубликован; и снапшот, чей anchor-пропозер не входит в исторический набор.

P0-SAFETY-BOOT-ONE-BLOCK (MITIGATED — root cause found, 2026-11-23, availability:
restart -> Observer). После рестарта `safety_record_v1.finalized_height` может
превышать сохранённый finalized/state ровно на 1 блок, и узел уходит в
fail-closed Observer. **Корень не в консенсусе**: указатель finalized пишется
через очередь `PersistJob::Finalized`, а graceful shutdown дренирует её с
верхним пределом 240 с (`src/node/bootstrap.rs`). Дефолтный systemd
`TimeoutStopSec=90s` убивал процесс SIGKILL посреди этого дренажа — отсюда
запись на блок впереди стора. Исправлено drop-in'ом `20-stop-timeout.conf`
(`TimeoutStopSec=300`) на A/B/C/D; проверено: `systemctl show … -p
TimeoutStopUSec` = 5min на всех. Остаётся (не блокер): автоматический reconcile
на boot для случая принудительного SIGKILL — сейчас лечится
`safety-reset` + `safety-init` по `ops/safety_recovery_runbook.md`.

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
| FEE-PRIORITY-APPLY | `priority_fee_per_gas` проходит admission и proposal-check, но не списывается в `apply()` / `parallel`: priority bid фактически возвращается отправителю как неиспользованный газ. | **FIXED (локально, не активировано; `FEE_MARKET_V2_ACTIVATION_HEIGHT = u64::MAX`)**: `fee_for_gas_at_v2`/`failure_fee_for_v2` списывают `priority_fee_per_gas` внутри core (cap `gas_limit`, floor + surcharge); при выключенном гейте формула побайтово прежняя; `fee_market_v2` считается один раз на блок (sequential/parallel/`fail_with_floor!` parity). `w4_priority_fee_tests`. Активация — **R5**. | `docs/specs/W4_ECONOMICS_PRODUCT_CONTRACT.md` §1.1, §2.2; §3.2 п.1; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md` |

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
| FEE-SUBNANO-EXACT | Тихое усечение sub-nano wei в EVM carrier, сброс `remainder` в `ValidatorRewardState::accrue`, двойное усечение `GenesisVault::calculate_mint`, потеря Q0.64 в `pow_half_fixed`, `f64` в `eth_feeHistory`. | **FIXED (локально, не активировано; `SUB_NANO_STRICT_ACTIVATION_HEIGHT = u64::MAX`)**: `wei_to_nano_exact` на EVM carrier-границе (RPC/admission strict, консенсус по гейту), целочисленный `eth_feeHistory` без `f64`, одношаговый 256-битный `GenesisVault::calculate_mint`, `ValidatorRewardState::accrue_with_rescale` при смене `delegated` (проводка в `distribute_reward_at_height`/`distribute_fee_reward_at_height` в `apply.rs` Step 2/3), `pow_half_fixed_exact_q64`/`emit_with_q64_carry` + committed `StakingLedger::emission_carry_q64` (`STAKING_EMISSION_CARRY_V1` conditional + `StakingLedgerV7`/`DomainSnapshotV10`). Тесты: `w4_sub_nano_tests` **4/4** (`397+`/полный гейт). | `docs/specs/W4_ECONOMICS_PRODUCT_CONTRACT.md` §1.2, §2.3; §3.2 п.2; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md` |
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
| sub-nano | усечение при переводе в nano | **FIXED (локально, не активировано)** — см. `FEE-SUBNANO-EXACT`: закрыты все 5 пунктов (§2.3 п.1–п.5: `wei_to_nano_exact`, 256-bit `GenesisVault`, `accrue_with_rescale`, `emission_carry_q64`, integer `eth_feeHistory`). `w4_sub_nano_tests` **4/4**. | `docs/specs/W4_ECONOMICS_PRODUCT_CONTRACT.md` §1.2, §2.3, §3.2 п.2; `docs/specs/RULESET_V7_ACTIVATION_BLUEPRINT.md`; см. `FEE-SUBNANO-EXACT` |
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
| XSHARD-BOUNCE-MINT | **CRITICAL (multi-shard only).** Timeout-bounce возвращал `tx.amount` по outbound-записи, которая доказывает только связность, а не списание на источнике: (a) валидно подписанная tx с `nonce=u64::MAX` падает на apply (дебета нет), запись создаётся, через 64 высоты bounce минтит value; (b) 2PC-escrow + legacy-запись + bounce → target кредитует COMMIT, source возвращает refund (двойная трата). | **ACTIVATION-REQUIRED**: фикс в `runtime/**` (produced только при `status[i]==true`, inclusion/escrow proof для outbound, escrow-leaf перед bounce, отказ при наличии 2PC-записи; зеркала движка синхронно). В `{0}` недостижимо; обязателен до включения `{0,1}`. |
| XPC-PREPARED-UNBOUNDED | **HIGH (multi-shard).** `Prepare` принимает affordability-proof и пишет `PREPARED`; `is_retired` не ретирит `PREPARED`, а один funded-ключ создаёт неограниченно разных tx-hash на одном nonce → target забивается ~16 записями/блок навсегда. | **ACTIVATION-REQUIRED**: escrow-backed PREPARE или bounded per-source admission. |
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
