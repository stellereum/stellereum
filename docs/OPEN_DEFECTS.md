# OPEN_DEFECTS — реестр найденных дефектов и статус закрытия

Snapshot: после пентеста-2 и кросс-кат свипа. Источники: `docs/PENTEST2_*.md`,
`docs/REVIEW_WAVE_REGRESSIONS.md`, `docs/LOGIC_BUG_SWEEP.md`.
Обновлено на HEAD `9832e97a9` (закрыты `--owner-key` и `store_mail`).

Статусы: **FIXED** — код исправлен и есть тест «падало до»; **DEPLOYED** — то же,
плюс бинарь на A/B/D; **FIXED** — в работе у агента; **OPEN** — не начато;
**ACCEPTED** — осознанно принятый риск с обоснованием.

## P0 — блокеры безопасности/живучести

| ID | Дефект | Статус | Где |
|---|---|---|---|
| R1/DET-01 | минт награды из тик-копии governance → расхождение root | DEPLOYED | apply.rs / runtime |
| S4 | `Halt` не останавливал gov-op после себя (1 tx = 8 предложений) | DEPLOYED | apply.rs |
| C1/S1 | EVM-binding без доказательства владения EVM-ключом | DEPLOYED | binding.rs / svm.rs / mempool |
| H1 | EVM-индексы жили в памяти и не перестраивались | DEPLOYED | settlement.rs / rpc/state.rs |
| C1-net/R2 | `FetchFull` сажал hint из непроверенного фрейма → вечный обход catch-up | DEPLOYED | consensus_driver.rs |
| C2/F-8 | клон мемпула на каждый compact-фрейм | DEPLOYED | consensus_net.rs |
| F-1/R3/H5 | loopback без cap, ломал сортировку очереди | DEPLOYED | consensus_driver.rs |
| F-6/H3 | не было рабочего fallback на полный proposal (>64 промахов = стол) | DEPLOYED | compact_prop.rs / driver |
| S2 | 17 prepares → невалидный блок → клин цепи | DEPLOYED | mev_sync.rs / anchors.rs |
| S3 | COMMIT'ы не ретайрились, записи не чистились | DEPLOYED | xshard2pc.rs / xshard.rs |
| mesh-complete | «полная доставка» сравнивалась с сырым числом пиров → двойная отправка | DEPLOYED | consensus_net.rs |
| H2 | sealed-манифест не аутентифицирован (downgrade пиром) | DEPLOYED | infnode/node.rs |
| LIVE-STALL | после ruleset v5 три ноды голосуют один блок на разных раундах → нет кворума, высота не финализируется | **IN PROGRESS** (F1; аудит: `docs/LIVENESS_ROUND_SYNC_AUDIT.md`, репро: `tests/live_stall_repro_tests.rs`) | consensus/driver |
| CHAIN-SUPPLY | 1B cap считался на движок, а не на цепь | **FIXED** (ruleset 5: статический раздел + masterchain aggregate) | tokenomics / sharding |

## P1 — высокий риск

| ID | Дефект | Статус | Где |
|---|---|---|---|
| H1-net | `BodyPull` широковещательный и повторяемый | DEPLOYED (served-once + 8/с) | consensus_net.rs |
| H4/F-9 | парковщик compact без аутентификации/ре-арма | DEPLOYED | consensus_net.rs |
| F-3/R8 | at-tip по тишине отключал catch-up навсегда | DEPLOYED (BlindProbe 10 мин) | policy.rs |
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

## P2 — средний риск

| ID | Дефект | Статус |
|---|---|---|
| S5 | мёртвые сеттеры (`SetEquivocationSlashBps`, `SetMinValidatorBond`) | DEPLOYED |
| S6 | один EVM intent мог сеттлиться дважды | DEPLOYED (nullifier в trie) |
| S7 | обход upgrade-гейта на direct/halt путях | DEPLOYED |
| R6 | carrier-наценка не бралась при исполнении | DEPLOYED |
| R7 | nonce/value равенство только на admission | DEPLOYED |
| S10 | никогда-не-принимаемые mailbox-записи росли без bound | DEPLOYED |
| M1 | `stell_getEvmBinding` называл mempool-claim «committed» | DEPLOYED |
| M2 | per-account ключ Files из seed ноды | DEPLOYED |
| M3 | `put ok` до репликации, zero-replica = успех | DEPLOYED |
| M4 | неограниченные `chunks[]` в манифесте | DEPLOYED |
| M5 | `stell_unsubscribe` без аутентификации | DEPLOYED |
| receipt params | `[hash]` не принимался | DEPLOYED |
| stale docs | ~30 доков противоречили коду | DEPLOYED (V2) |
| stell_getBlock | всегда «not in recent window», даже `latest` | **FIXED** (HUNT-5) |
| getTransactionByHash | `stell_*` метода нет | **FIXED** (HUNT-5) |

## P3 — низкий риск / принято

| ID | Дефект | Статус |
|---|---|---|
| F-10 | restored round: `last_prevoted` сеется сырым раундом | ASSIGNED (HUNT-1) |
| F-11 | подписи tx вне `compute_hash` | ASSIGNED (HUNT-1) |
| F-12 | nil-breaker ре-бродкастит тело старого раунда | ASSIGNED (HUNT-1) |
| S8 | timestamp блока выбирает продюсер | ASSIGNED (HUNT-1/4) |
| S9 | вес голоса можно вывести перед голосом | ASSIGNED (HUNT-4) |
| unicast Body | нет `send_to_peer`, ответы broadcast (bounded) | **FIXED** (`send_to_peer`, 10→10 unicast) |
| `--owner-key` | seed в argv | **FIXED** (HEAD `9832e97a9`: `--owner-key-file` 0600/stdin, `$INFNODE_OWNER_KEY`; argv deprecated with a loud warning; `cli_seal_tests`) |
| store_mail | fail-open на неоткрываемом ключе | **FIXED** (HEAD `9832e97a9`: `StoreMailError`, key boxed before any chunk/manifest; `store_mail_with_unboxable_owner_key_fails_closed`) |
| sub-nano | усечение при переводе в nano | ACCEPTED (документировано) |
| pre-auth sealed | старые sealed-блобы отклоняются | ACCEPTED (требуют переопубликации) |
| zkML | re-execution, не ZK | ACCEPTED (отдельная система позже) |
| EVM | только переводы, без контрактов | ACCEPTED (скоуп) |
| >2 шардов | фиксированная пара `{0,1}` | ACCEPTED (канон) |

## Новые P0 из волны HUNT (false-slash примитивы)

| ID | Дефект | Статус |
|---|---|---|
| SLASH-A | `Vote` не содержит `shard_id` и не подписывает его → честный мультишард-валидатор слэшится за нормальную работу | **FIXED** (V3-preimage + QC/evidence/offense key) |
| SLASH-B | `Block` не содержит `round` → честный пропозер после view change слэшится как double-propose | **FIXED** (ruleset 4: `round` в подписанной identity, slashing включён) |
| RE-PROP-ROUND | ruleset 4/5: lock-rescue/demanded rescue честно пере-отправляет ТО ЖЕ подписанное тело (его hash — значение, на котором держат lock), но admission требовал `block.round == hc.round` → тело старого раунда отвергалось, высота зависала; adopt тем же требованием блокировал catch-up | **FIXED** (admission принимает более ранний signed round только для тела, которое уже держим — повтор известного значения; новое stale-тело по-прежнему fail-closed; adopt принимает `block.round <= certificate.round`, QC подписывает точный hash; тесты `locked_proposer_reproposes_locked_value`, `lock_hint_rescue_converges`, `demanded_reproposal_records_live_proposal_and_broadcasts_once`) |
| SIGNED-ROUND-LIVENESS | ruleset 4/5: re-served locked body хранит СТАРЫЙ signed round, а prevote штамповался ЛОКАЛЬНЫМ раундом → все три валидатора prevote'или один и тот же hash в r505/r507/r515, ни один раунд не собирал кворум → height 1 не финализировался навсегда. Дополнительно forward-sync стирал уже принятое предложение, и узел приходил в раунд головы «пустым». | **FIXED** (prevote несёт signed round ТЕЛА — он одинаков у всех держателей; fsync-watermark проверяется по ЭТОМУ раунду, голос ниже floor не отправляется; forward-sync сохраняет живым proposal, совпадающий с lock/голосом за то же тело; corroboration-chase допускает двух peer'ов в окне `ROUND_LOOKBACK` ниже цели. Инварианты: без rewind, без голоса ниже watermark, без будущего signed round. Тесты `signed_round_liveness_tests`, `live_stall_repro_tests`, `round_sync_audit_tests`) |
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
| UP-5 | `cosmovisor`-аналог (демон, следящий за committed-планом) | OPEN (после деплоя) |

## Правило закрытия

Дефект считается закрытым только если: (1) есть тест, падающий на коде до фикса;
(2) полный параллельный гейт зелёный; (3) бинарь задеплоен на A/B/D и цепь
финализирует. «Код исправлен, но не выкачен» — это DEPLOYED-1, отдельный статус.
