# Stellereum: исправления для блокчейна и рабочие формулы

> Снимок кода: `stellereum/stellereum`, commit `7f204d1` (2026-11-05).
> Номера строк могут сдвигаться — ищите по именам функций.
> Это **инженерный документ**: что сломано, как правильно, какие формулы
> рабочие и какие тесты приёмки. Математические доказательства — в
> `papers/P1–P26`, аудит — `CORRECTIONS.md`, `HIGH_TRIAGE_SUMMARY.md`.

**Статусы:** `FIXED` — уже в main; `OPEN` — воспроизводится; `DESIGN` —
решение, не баг; `RESEARCH` — открытая математика.

**Главное правило:** не выдавать 256-битные хеши и µQC за границу
безопасности. 256-бит даёт ≈85 бит collision; µQC — ускоритель, не
финальность.

---

## 0. Что делать в первую очередь

| # | Приоритет | Проблема | Файл | Действие |
|---|---|---|---|---|
| 1 | **P0** | Мост не работает в FULL-PQ: `verify_quorum_signatures` всегда `Err`, `count_signers=0` | `src/bridge.rs:563-572`, `:1873-1876` | Проверять Falcon-ключи, считать DISTINCT, порог `ceil(2n/3)` |
| 2 | **P1** | Ротация PQ-ключа не влияет на консенсус | `src/consensus.rs:1002-1032`, `pq_registry.rs:43-63` | Протянуть `height` в verify, читать `pq_active_key(v,height)` |
| 3 | **P1** | 256-битные корни | `src/mmr.rs`, state/order roots | 384 бита для 128-bit collision; 512 при `M=2^20` целях |
| 4 | **P1** | Модуль `xmss_vrf.rs` готов, но интеграция **gated-OFF** | `xmss_vrf.rs`, `consensus.rs:893-911` | Активация — через rollout §8; пока — сетевой `2/3` |
| 5 | **P1** | Block-signature quorum — Ed25519 | `src/sharding.rs:5857-5915`, `consensus.rs:277-317` | Falcon/PQ или удалить, если не нужен для финальности |
| 6 | **P1** | MEV threshold на Ristretto/X25519 | `src/mev_epoch.rs:135` | PQ KEM / threshold LWE |
| 7 | **P0/P1** | µQC `max(2W_c/3,2W_n/3)` недостижим при `W_c<⌊2W_n/3⌋+1` | `src/consensus.rs:703-716` | C1: advisory `q(W_c)` + full QC `q(W_n)`; full CEC |
| 8 | **FIXED** | buffer = withheld (variant B) | `pmm.rs:24-29`, `:673-704` | Задокументировано; не откатывать |
| 9 | **FIXED (inactive)** | Эмиссия cap-exact wired за гейтом | `tokenomics.rs:35`, `:429-636` | `EMISSIONCapEXACT_ACTIVATION_HEIGHT=u64::MAX`; активация §8 |
| 10 | P2 | sampling-QC без залога не sound | light client | `P_det=s/k`; нужен залог/ATS |
| 11 | **FIXED** | timeout ladder `+500` | `src/consensus.rs:3423` | Уже geometric `×2`; проверить, что legacy не вызывается |

---

## 0.1. Полный реестр 23 пунктов (чтобы ничего не потерялось)

| # | Статус | Недочёт | Куда в этом файле |
|---:|---|---|---|
| 1 | **FIXED** | PMM sign: `d−quad` → `d+quad` (`pmm.rs:255`) | §1.0 |
| 2 | **FIXED (safety)** | µQC floor `2/3`; liveness остаётся | §1.0, §1.7 |
| 3 | **FIXED** | 2PC apply anchor `source_state_root` | §1.0 |
| 4 | **FIXED** | `TWAP_WINDOW_SECS=91` | §1.0 |
| 5 | **OPEN P0** | Bridge PQ quorum всегда `Err` | §1.1 |
| 6 | **OPEN P1** | PQ rotation не влияет на verify | §1.2 |
| 7 | **OPEN P1** | block-signature quorum Ed25519 | §1.5 |
| 8 | **DESIGN (gated)** | модуль XMSS-VRF готов, интеграция OFF | §1.4 |
| 9 | **OPEN P1** | 256-битные корни | §1.3 |
| 10 | **OPEN P1** | MEV threshold на Ristretto/X25519 | §1.6 |
| 11 | **FIXED** | buffer = withheld (variant B) | §1.9 |
| 12 | **OPEN P1/P2** | QC = k отдельных Falcon; нет агрегации | §2.6, §1.12 |
| 13 | **DESIGN P2** | threshold ML-DSA для полного набора 100+ | §6 |
| 14 | **DESIGN P2** | sampling-QC без залога не sound | §1.11 |
| 15 | **RESEARCH P2** | refinement BFS-моделью, не Coq/Lean | §6 |
| 16 | **FIXED (inactive)** | cap-exact wired, гейт `u64::MAX` | §1.10 |
| 17 | **FIXED** | timeout ladder: geometric ×2 | §1.0, §1.8 |
| 18 | **OPEN P1** | Merkle: код всё ещё 256; модель исправлена | §1.3 |
| 19 | **OPEN P1** | QROM: 256 недостаточно для 128-bit | §1.3, §2.5 |
| 20 | **DESIGN P1** | TSS скрывает состав; bitmap не binding | §1.12 |
| 21 | **RESEARCH P2** | WOTS+/XMSS уникальность вычислительная | §6 |
| 22 | **OPEN P0/P1** | µQC `max(...)` недостижим — liveness | §1.7 |
| 23 | **OPEN P2** | калибровка: нет mainnet-данных | §2.12, §6 |

---

## 1.0. Уже исправлено (регрессионные тесты — не ломать)

* **#1 PMM sign.** В main `pmm.rs:255` — `saturating_add(quad)`; тест
  `pmm.rs:648` пиннит поведение. Не откатывать к `d−quad`: потеря
  92.5%/100% при 100M/250M USD.
* **#2 µQC floor (safety).** `pq_micro_required_power` больше не
  `W/2+1`; `mixed_quorum_pair_safe` — tripwire. Liveness-дефект
  остаётся — см. §1.7.
* **#3 2PC apply anchor.** `state_engine.rs:6466-6500` читает
  `FinalizedHeaderRegistry` и проверяет `anchor_holds` до phase-proof.
* **#4 TWAP window.** `oracle.rs:55` — `TWAP_WINDOW_SECS=91` (было
  3600; окно ~40× от оптимума).
* **#17 timeout.** `consensus.rs:3423` — geometric `×2`, cap 10s;
  legacy `+500` (`main.rs:1042`) не вызывается. Проверить, что не
  вернули аддитивную лестницу.

---

## 1. Детальные исправления

### 1.1. Мост: PQ-кворум (P0)

**Симптом.** `verify_quorum_signatures` возвращает
`Err("FULL-PQ: classical bridge quorum removed")`;
`MultisigRelayer::count_signers` возвращает `0`. Любой deposit/release с
кворумом отклоняется — мост fail-closed без PQ-пути.

**Что делать.** Проверять **зарегистрированные** Falcon-512 ключи
валидаторов из `consensus::get_validator_pq_key(id)` или
height-indexed `pq_registry`; считать `DISTINCT` подписантов; сравнивать
с `bridge_threshold(n) = ⌈2n/3⌉`. Ed25519-id — идентичность, не ключ
подписи; Ed25519-подпись не считать.

**Приёмка.**
* 3 из 4 зарегистрированных Falcon-ключей → `Ok(3)`; 2 из 4 → `Err`.
* Дубликат подписанта считается один раз.
* Незарегистрированный/чужой ключ не считается.
* Тесты `pure_pq_refuses_classical_quorum`,
  `multisig_release_requires_distinct_threshold_and_is_once` — зелёные.

**Математика.** `bridge_threshold(n)=⌈2n/3⌉` — минимальный безопасный при
`B<n/3` (P1). Для атомарных весов точный минимум — `M(w,β)+1` (P22).

---

### 1.2. Ротация PQ-ключей (P1)

**Симптом.** `pq_registry::get_active_key(validator, height)` есть, но
`Vote::verify_uncached` (`consensus.rs:1363-1369`) читает
`get_validator_pq_key(voter)` — process-global map без высоты. On-chain
rotation не влияет на verifying key.

**Что делать.** Протянуть `height` в verify-путь (голос уже несёт
`height`) и резолвить ключ через `pq_active_key(validator, height)` из
committed registry; **fail-closed**, если ключ на высоту не найден. Кэш
вердиктов ключуется по байтам ключа — учесть.

**Приёмка.** Голос старым ключом после `effective_height` отклоняется;
новым — принимается; на высоте до `effective_height` — наоборот.

---

### 1.3. Хеши и Merkle (P1)

**Симптом.** 256-битные корни. BHT: collision ≈ **85.3** бита. При
`2^20` целях shared-query — **78.6** бита. Block-hash collision — отказ
безопасности BFT (P17 Th.3).

**Правильная модель (исправлено).**
* Collision resistance корня **не зависит** от глубины:
  `λ_col = n_h/3` (85.3 для 256).
* Second-preimage: `λ_2pre = n_h/2 − h/2` (quantum), `n_h − h`
  (classical). Для 256: 118 (h=20) / 96 (h=64).
* `n/3 − h`, 65.3, 53.3, 21.3 — **ошибки** (старая модель).
* Для 128-bit collision нужен **384-битный** хеш; для 128-bit
  second-preimage при h=64 — 384, при h=256 — 512.

**Что делать.** 384-битные корни (block/state/order/MMR); при цели
128-bit second-preimage на глубине 256 — 512. Миграция — отдельный
проект (wire/state).

**Таблица (биты):**

| хеш | collision | 2pre h=20 | h=64 |
|---:|---:|---:|---:|
| 256 | 85.3 | 118.0 | 96.0 |
| 384 | 128.0 | 182.0 | 160.0 |
| 512 | 170.7 | 246.0 | 224.0 |
| 768 | 256.0 | 374.0 | 352.0 |

---

### 1.4. VRF / beacon (DESIGN, gated OFF)

**Статус (refresh 2026-11-06): модуль готов, интеграция gated-OFF.**
`stellereum/src/xmss_vrf.rs` — 1236 строк, WOTS+ len=67, тесты;
`beacon_draw_committee`; гейт `BEACON_DRAW_ACTIVATION_HEIGHT=u64::MAX`
в `consensus.rs:893-911`. **Было:** «VRF не подключён». **Стало:**
модуль есть, активация выключена до rollout §8. Пока гейт OFF,
parent-hash grinding остаётся риском.

**Симптом (история).** `derive_sortition_committee` сеет parent hash;
модуль `xmss_vrf.rs` есть, но гейт OFF — сортировка всё ещё от parent
hash. Grinding комитета: `1/P_capture`; при `n=100,k=64,α=1/3`
≈`3.05·10^7` хешей (0.03 с), Grover ≈`5.5·10^3` (5.5 мкс в модели).

**Что делать.** VRF/beacon (XMSS-эпоха — P15; пороговый beacon — P6) или
сетевой `2/3` как **единственная** граница безопасности. Если VRF не
готов — документировать, что комитет не является границей безопасности.

**Формулы.** `E[draws]=1/P_capture` для **любого** большинства;
`C(n,s)/C(k,s)` — только для заданного `s`-подмножества. Структурный
захват: `P=0` при `n_A<q` (distinct-модель), `P=1` при `n_B≤k−q`.
Минимум честных: `n_B ≥ ⌈k/3⌉` (для `k=64` — 22).

---

### 1.5. Block-signature quorum (P1)

**Симптом.** `Block::verify_validator_quorum` (`sharding.rs:5857-5915`)
проверяет Ed25519; `verify_proposer_signature` имеет Ed25519-фолбэк
(`consensus.rs:277-317`). PQ-финальность — vote QC, но block-signature
quorum остаётся классическим.

**Что делать.** Либо удалить block-signature quorum (если он не нужен
для финальности), либо заменить на Falcon/PQ с батч-проверкой. Решение
за лидом; математически это остаточная классическая поверхность.

---

### 1.6. MEV threshold (P1)

**Симптом.** `threshold_for(n)` и threshold-расшифровка на
Ristretto255/X25519/Ed25519 — классика.

**Что делать.** ML-KEM / threshold LWE или Shamir/GF(256) + PQ-
аутентификация. Это не «поменять константу», а замена протокола
(P11/P18).

---

### 1.7. µQC: C1 (P0/P1, liveness)

**Симптом.** `pq_micro_required_power` возвращает
`max(⌊2W_c/3⌋+1, ⌊2W_n/3⌋+1)`. При `W_c < ⌊2W_n/3⌋+1` второй член
недостижим — µQC не собирается. Это **liveness/availability**, не
safety. Production epoch CEC не эмитится; `PROTOCOL.md:723,778,789`
всё ещё говорит `W/2+1` (I20 stale — см. §7);
`MICRO_COMMITTEE_MAX_SIZE=128` (`consensus.rs:637`).

**Решение C1.**
* µQC — **advisory**: `q(W_c)=⌊2W_c/3⌋+1`.
* Финальность — **только full QC**: `q(W_n)=⌊2W_n/3⌋+1`.
* Full CEC эмитится каждый epoch.
* `mixed_quorum_pair_safe` — tripwire, не замена full QC.

**Формулы.** Полный порог: `q(W)=⌊2W/3⌋+1`; bridge:
`⌈2W/3⌉` (при `B<W/3`). Смешанная пара: `T_µ+T_f−W>B` — только
**достаточное** условие для атомарных весов; точный критерий — P22.

---

### 1.8. Timeout ladder (FIXED, проверить)

**Статус.** В main `consensus.rs:3423` — geometric `×2`, cap 10s.
**Проверено (refresh):** живых коллеров `effective_round_timeout_ms`
нет; legacy `+500` (`main.rs:1042`) только тест-пины
`main.rs:10592-10597,10990`. Не откатывать к аддитивной лестнице.

**Формула.** При i.i.d. латентностях `T*` минимизирует
`V(T)=[I(T)+(T+c)q(T)]/(1−q(T))`; для `γ=2,c=0`
`T*=x₀(2+√3)≈3.732x₀`, `V*=T*/2`. Персистентное замедление —
**не** даёт устойчивого `ρ≈2` (selection bias); `ρ*` не идентифицируется.

---

### 1.9. PMM buffer (FIXED, variant B)

**Статус (refresh 2026-11-06): FIXED — variant B.** В main
`pmm.rs:24-29` — binding `usable = reserve − buffer`; пин
`pmm.rs:673-704`. Решение: buffer = **withheld** и задокументирован;
PMM и redemption его не видят. **Было:** OPEN, выбор A/B. **Стало:**
FIXED (withheld + documented). Историю A/B ниже оставить.

**Симптом (история).** `usable = reserve − buffer` (`pmm.rs:192-195`)
противоречит «ring-fenced for redemptions»: буфер одновременно
удерживается и тратится на PMM — скрытый налог на выход.

**Решение (принято): variant B — withheld.** `usable=reserve−buffer`
корректно; buffer недоступен и для PMM, и для redemption; описание
«ring-fenced» убрано. Variant A (ring-fenced) — история, не выбирать.

**Формула максимального выкупа при буфере `b`:**

```
f_max(x,b) = [(1+x) − sqrt((1+x)² − x(1−b)(2+x))] / x,   x=S/S_c.
```

---

### 1.10. Эмиссия cap-exact (FIXED, code-complete; inactive)

**Статус (refresh 2026-11-06): code-complete, inactive.** В main
`tokenomics.rs:35` — `EMISSIONCapEXACT_ACTIVATION_HEIGHT=u64::MAX`
(inactive default); хелперы и пины `tokenomics.rs:429-636`.
**Было:** «не внедрена». **Стало:** wired за гейтом; активация —
только через rollout §8.

**Симптом (история).** `H = T/log2(100)` смешивает годы и блоки; таблица верна
только потому, что код умножает на `SEC_PER_YEAR/τ`.

**Правильно.**
```
N_T = T · SEC_PER_YEAR / τ              (блоков за T лет)
H_b = N_T / log2(100)                   (блоков на халвинг)
H_y = T / log2(100)                     (лет на халвинг)
R0  = P · (1 − 2^(−1/H_b))
R_h = R0 · 2^(−h/H_b)                   (h — номер блока)
Σ_{h≥0} R_h = P                           (точно, бесконечная сумма)
```
99% пула — за `H_b·log2(100)=N_T` блоков. Для 0.6 с и 7/10/20 лет
`H_y = 1.054/1.505/3.010` лет.

---

### 1.11. Sampling-QC (P2)

**Симптом.** Light client проверяет `s` подписей из `k`; при одной
плохой `P_det=s/k`. Это не sound без залога/ATS.

**Что делать.** Залог/слэшинг за неверную подпись или accountable
multisig; fraud-proof: `B > V(1−P_det)/P_det` (risk-neutral).

---

### 1.12. Accountability (P2)

**Симптом.** Threshold-подпись скрывает состав; bitmap к TSS не
binding (frameability).

**Что делать.** Для slashing — multisig + bitmap, не TSS. Цена
атрибуции `≥ log2 C(n,t)`: 114 бит при `n=128,t=85`; 936 при
`n=1024,t=682`. Для 128 мест `k×Falcon + bitmap` = **85 КБ** —
меньше Lemur (~150 КБ) и Chipmunk (~237 КБ).

---

## 2. Рабочие формулы (copy-paste)

### 2.1. Кворум

```
consensus(n) = floor(2n/3) + 1
bridge(n)    = ceil(2n/3)          (B < n/3)
t*(n)        = ceil(2n/3)          (unit weights)
2t − W > B                          (достаточно; не iff для атомарных весов)
```

### 2.2. Weighted quorum (точная теория, P22)

```
P(U)  = max{ w(A) : A ⊆ U, 2·w(A) ≤ w(U) }
M(w,β)= max_{I: w(I) ≤ β} [ w(I) + P(V\I) ]
Safe(w,β,t) ⟺ t > M(w,β)
t*(w,β) = M(w,β) + 1
```

`P(U)` — лучшая сбалансированная часть; DP `O(nβW)`; NP-hard
(PARTITION). `2t−W>β` — только достаточно; `w_max`-поправка ложна.

### 2.3. µQC (C1)

```
q(W_c) = floor(2W_c/3) + 1      (advisory)
q(W_n) = floor(2W_n/3) + 1      (full QC, финальность)
W_c < floor(2W_n/3) + 1         (порог max недостижим — liveness)
```

### 2.4. Размер комитета

```
D(p‖q) = p·ln(p/q) + (1−p)·ln((1−p)/(1−q))
k_suff(ε,α) = ceil( ln(1/ε) / D(2/3‖α) )
α=1/3: D = (1/3)ln2 ≈ 0.2310
```

Точные минимальные `k` (биномиальный хвост; **немонотонен**):
`105` для `2^−40`, `177` для `2^−64`, `225` для `2^−80`.
Достаточные по Чернову: `120/192/240`.

**Текущий cap (refresh 2026-11-06):** `MICRO_COMMITTEE_MAX_SIZE=128`
(`stellereum/src/consensus.rs:637`).
**Было → стало:** `64` → `2^−24.86` (история) → `128` → `≈2^−47.36`.
Точный хвост немонотонен: `105` — минимум для `2^−40`, `106` хуже;
`128` даёт `≈2^−47.36 ≤ 2^−40`. Cap 128 **не** покрывает `2^−64`
(нужно 177) и `2^−80` (нужно 225).

### 2.5. Хеши / Merkle / QROM

```
collision:        λ = n_h/3
second-preimage:  λ = n_h/2 − h/2   (quantum)
                  λ = n_h − h       (classical)
shared multi-target collision: λ = n_h/3 − (1/3)log2 M
union bound:                   λ = n_h/3 − log2 M
```

QROM (cited/heuristic): FS loss `Θ(q²)`, не `q`/`√q`. При `q=2^64`:
challenge 384 (λ=128) / 512 (λ=256); collision 512 (λ=128, `M=2^32`) /
1024 (λ=256); preimage 384/768.

### 2.6. QC / checkpoint / accountability

```
|QC|         = 666k + ceil(k/8)                 (Falcon-512 + bitmap)
|checkpoint| = |TS_sig| + h·32 + ceil(n/8)
k*           = (S + 32)/666                     (безубыточность vs succinct)
accountability ≥ log2 C(n,t)
```

`k=128`: QC = **85 264 B**; checkpoint = 3309 + 640 + 16 = **3 965 B**
(h=20, TS_sig=3309). `k=1024`: QC ≈ **682 КБ**.

### 2.7. Threshold PQ

```
additive:  Σ z_i = y + c·s1
norm:      ||y|| ≈ sqrt(t)·σ
rejection: (1−ρ)^t                     (только локальная модель!)
smudging:  σ_y ≥ Q·2^(λ−1)·||c·s1_i||
budget:    Q_max ≈ (σ/B)²
Shamir:    max|λ_i| = C(T, floor(T/2)) ≈ 2^T / sqrt(πT/2)
```

Core-SVP loss (δ-модель, **эвристика**):

| t | F-512 | F-1024 | ML-DSA D-44/65/87 (conservative) |
|---:|---:|---:|---:|
| 2 | 13.9 | 27.2 | 15–49 |
| 4 | 25.5 | 50.2 | 15–55 |
| 16 | 43.6 | 87.1 | 17–70 |
| 64 | 57.1 | 115.1 | 20–82 |
| 256 | 67.5 | 137.1 | 23–90 |
| 1024 | 75.7 | 154.7 | 25–94 |

`β_eff = max(sqrt(t)·β_sig, sqrt(t)·β_smudge)`; smudging часто binds.
`T∈[9,32]` — открытый gap FIPS-204-exact.

### 2.8. PMM / экономика

```
R(s,d)   = P0·(d + (2sd − d²)/(2Sc))
Sell(s+d,d) = Buy(s,d)                 (с floor — точно)
R ≥ V(S)                                (integer-код платёжеспособен)
f_max(x,b) = [(1+x) − sqrt((1+x)² − x(1−b)(2+x))]/x
S_c*     = D·sqrt(κ)/σ
H*       = P/R;   T* = H*·τ
R_h      = P·(1 − 2^(−1/H_b))·2^(−h/H_b)
```

### 2.9. Liveness

```
q(T) = (x0/T)^γ
I(T) = γ·x0^γ·(T^(1−γ) − x0^(1−γ))/(1−γ)
V(T) = [I(T) + (T+c)·q(T)] / (1 − q(T))
γ=2,c=0: T* = x0·(2+√3),  V* = T*/2
```

Backoff: geometric `×2`, cap 30s (в коде 10s). Персистентность:
`ρ≈2` не идентифицируется; мультипликативная лестница — эвристика.

### 2.10. Оракул

```
W* = ( 6·(J·Δt)² / σ² )^(1/3)
θ  = σ·Φ⁻¹(1 − α/2)                  (одноблочный спот)
VWAP: sd = σ·sqrt(W/3)               (равные веса)
```

### 2.11. MMR

```
#peaks(n) = popcount(n)
|π| ≤ floor(log2 n) + popcount(n) − 1
max_i |π_i| = floor(log2 n) + popcount(n) − 1
```

Multiproof: формула верна только если все `q` листьев в одном
совершенном поддереве; для разных пиков `|multiproof| = q·|π|`.

### 2.12. Калибровка (framework, данных нет)

```
λ̂ ≤ 3/N (rule of three)
q = 1 − p̂ − λ̂
Var(q̂) = Var(p̂) + Var(λ̂) + 2Cov(p̂,λ̂)
c = mean(interval | VC) − T − E[X]
Var(ĉ) ≈ Var(interval|VC)/m + Var(Ê[X])
```

Mainnet-данных нет; `stell_block_interval_seconds`,
`stell_peer_latency_seconds`, `stell_consensus_votes_total` — мёртвые
series; нет trade tape/oracle history.

---

## 3. Таблицы констант

### 3.1. Пороги по `n`

| n | consensus | bridge | минимум честных `⌈k/3⌉` (k=n) |
|---:|---:|---:|---:|
| 3 | 3 | 2 | 1 |
| 4 | 3 | 3 | 2 |
| 7 | 5 | 5 | 3 |
| 64 | 43 | 43 | 22 |
| 100 | 67 | 67 | 34 |
| 128 | 86 | 86 | 43 |
| 1024 | 683 | 683 | 342 |

### 3.2. Комитет `k` (α=1/3)

| цель | точный min `k` | достаточный `k` |
|---|---:|---:|
| 2^−40 | 105 | 120 |
| 2^−64 | 177 | 192 |
| 2^−80 | 225 | 240 |

### 3.3. Хеши

| цель | collision | 2pre h=20 | 2pre h=64 |
|---|---:|---:|---:|
| 85 бит | 256 | 256 | 256 |
| 128 бит | 384 | 384 | 384 (h≤64), 512 (h=256) |
| 170 бит | 512 | 512 | 512 |

### 3.4. QC/checkpoint

| n | QC `666n+⌈n/8⌉` | checkpoint (`h=20`) |
|---:|---:|---:|
| 64 | 42 632 B | ~3.3 КБ |
| 128 | 85 264 B | 3 965 B |
| 1024 | 682 112 B | ~3.9 КБ |

### 3.5. Liveness (`x0=466.7 мс`, γ=2)

| c, мс | T*, мс | V*, мс |
|---:|---:|---:|
| 0 | 1741.7 | 870.9 |
| 500 | 2788.9 | 894.3 |
| 1000 | 3809.1 | 904.8 |

---

## 4. Rust-эскизы (не применены; для код-роли)

### 4.1. µQC C1

```rust
// advisory; НЕ финальность
pub fn pq_micro_advisory_power(committee_total: u64) -> u64 {
    if committee_total == 0 { u64::MAX } else { consensus_quorum_min(committee_total) }
}
// финальность; всегда сетевой 2/3
pub fn pq_full_required_power(network_total: u64) -> u64 {
    if network_total == 0 { u64::MAX } else { consensus_quorum_min(network_total) }
}
```

Не возвращать `max(committee, network)` как финальный порог.

### 4.2. Мост: DISTINCT Falcon

```rust
pub fn verify_bridge_quorum(
    signers: &[(ValidatorId, FalconSig)],
    n: usize,
    key_of: impl Fn(ValidatorId) -> Option<FalconPk>,
) -> Result<usize, BridgeError> {
    let mut seen = BTreeSet::new();
    for (id, sig) in signers {
        let pk = key_of(*id).ok_or(BridgeError::UnknownKey)?;
        if !falcon_verify(pk, &bridge_msg(), sig) { continue; }
        seen.insert(*id);
    }
    let need = bridge_threshold(n); // ceil(2n/3)
    if seen.len() >= need { Ok(seen.len()) } else { Err(BridgeError::Quorum) }
}
```

### 4.3. Ротация

```rust
fn verify_vote(v: &Vote, reg: &PqRegistry) -> bool {
    let pk = match reg.get_active_key(v.voter, v.height) {
        Some(pk) => pk,
        None => return false, // fail-closed
    };
    falcon_verify(pk, &v.signing_root(), &v.sig)
}
```

### 4.4. Хеши

```rust
pub const HASH_LEN: usize = 48; // 384 бита; 64 при 2^20 целях
```

### 4.5. Timeout

```rust
let t = base.saturating_mul(1u64 << round.min(5)).min(30_000);
```

### 4.6. Буфер

```rust
// current main = variant B (withheld + documented): pmm.rs:24-29; pins :673-704
let usable = reserve.saturating_sub(buffer);
// variant A (ring-fenced) — НЕ выбирать: противоречит текущему решению.
```

### 4.7. Эмиссия

```rust
// INTEGER-ONLY: f64/log2/powf запрещены (clippy/test reject).
// SCALE = 10^12; LOG2_100_SCALED — log2(100) в fixed-point.
let n_t: u128 = (t_years as u128) * (SEC_PER_YEAR as u128) / (tau as u128);
let h_b: u128 = n_t * SCALE / LOG2_100_SCALED;      // блоков на халвинг
let r0: u128 = p - mul_div(p, exp2_neg(SCALE, h_b), SCALE);
let r_h = |h: u128| mul_div(r0, exp2_neg(SCALE, h / h_b), SCALE);
// ΣR_h = P: геометрическая сумма в fixed-point, допуск 1 ulp; без float.
```

**Важно:** `100f64.log2()`/`powf` не пройдут гейты. Использовать
integer-хелперы `tokenomics.rs:429-636` (nano-discipline
`tokenomics.rs:371-383`). Формулы те же, арифметика — целочисленная.

---

## 5. Приёмка и тесты

```bash
cargo test --lib bridge
cargo test --lib pmm
cargo test --lib consensus::tests::quorum
cargo test --lib
```

Обязательные новые тесты:
* bridge: 3/4 Falcon → Ok, 2/4 → Err, duplicate → 1, unknown key → Err.
* rotation: old key after `effective_height` → reject; new → accept.
* hashes: `HASH_LEN=48`; domain separation; old 32-byte roots rejected.
* µQC: `pq_full_required_power` used for finality; advisory ≠ finality.
* buffer: buy/sell respect the chosen semantics; redemption ≤ redeemable.
* emission: 99% at `N_T` blocks; `ΣR_h=P`.

Математические проверки:
```bash
cd ~/Documents/stellereum-math && ./run_all.sh   # 115/115
```

---

## 6. Что НЕ исправлено / допущения

* **Mainnet-калибровка:** данных нет; оценки `σ,D,J,γ,c` — framework,
  не числа. Нужны dead-series + trade tape + oracle history.
* **Threshold ML-DSA для 100+:** SOTA не production; `T∈[9,32]` gap.
  Для checkpoint — `T≤6–8`; для slashing — multisig+bitmap.
* **BHT `2^{n/3}`:** query/qRAM-модель; serial `2^{2n/3}`, CNS `2^{2n/5}`,
  classical rho `2^{n/4}`. Не выдавать за время.
* **QROM-размеры:** часть — эвристика; DFM даёт только
  `κ ≥ λ + 2log2(2q+1)`.
* **Merkle depth:** collision не падает; second-preimage `h/2`;
  `n/3−h` — ошибка.
* **Weighted quorum:** точная теорема (P22); DP pseudo-polynomial,
  NP-hard; для больших `W` — ILP/эвристика.
* **Threshold loss:** core-SVP/δ-модель — эвристика, не теорема.
* **P05 9 vs 8:** 9 состояний верны (`xpc_refinement_full.py`, P15);
  `xshard.py`/`xshard.json` устарели (8).
* **#15 refinement:** BFS-модель, не Coq/Lean; O7 (guard'ы Python =
  guard'ы Rust) и O8 (полнота переходов `xshard2pc.rs`) открыты.
* **#21 WOTS+/XMSS уникальность:** вычислительная (collision), не
  информационная; malicious keygen при коллизии хеша. Нужен
  XMSS-эпоха/слэшинг, не Falcon+hash.
* **#13 threshold ML-DSA 100+:** SOTA не production; для checkpoint
  `T≤6–8`; для slashing — multisig+bitmap.
* **#16 cap-exact emission:** реализовать `H_b` (блоки), а не `H` в
  годах; решение по горизонту (7/21 год) — за лидом.

---

## 7. file:line и отозванные утверждения

**file:line (refresh 2026-11-06):** для пунктов refresh — текущий main;
для #6/#7/#12/#3 (нет refresh-фактуры) — снимок `7f204d1`, сверить перед
применением. `7f204d1` — исторический снимок, не единственный источник.
* #17 timeout: **FIXED**, geometric `×2`, `consensus.rs:3423`; живых
  коллеров `effective_round_timeout_ms` нет, только тест-пины
  `main.rs:10592-10597,10990`.
* #11 buffer: **FIXED** variant B — `pmm.rs:24-29` (binding
  `usable=reserve−buffer`) + пины `pmm.rs:673-704`.
* #16 emission: **code-complete, inactive** — `tokenomics.rs:35`
  (`EMISSIONCapEXACT_ACTIVATION_HEIGHT=u64::MAX`); хелперы/пины
  `tokenomics.rs:429-636`; integer discipline `tokenomics.rs:371-383`.
* #8 VRF: `xmss_vrf.rs` (1236 строк, WOTS+ len=67, тесты) +
  `beacon_draw_committee`; гейт `consensus.rs:893-911`
  (`BEACON_DRAW_ACTIVATION_HEIGHT=u64::MAX`).
* #2 cap: `MICRO_COMMITTEE_MAX_SIZE=128` (`consensus.rs:637`).
* #6 rotation: `pq_registry.rs:43-63` docs; `get_active_key:492`; суть open.
* #7: vote path Falcon-only; block-sig/proposer fallback Ed25519.
* #12: QC = Ed25519-список + k Falcon.
* #3: anchor `:6468-6502`.

**PROTOCOL.md (stale; чужой файл — только предложение текста):**
* `PROTOCOL.md:723,778,789`, инвариант I20 и таблица `:1007` говорят
  `W/2+1`. Код уже `2/3`: `consensus.rs:703-713`. Спека **врёт**.
* Предлагаемый replacement для I20 (вставить в FIXES, не в PROTOCOL):
  > I20: Full QC threshold = `floor(2W/3)+1`; µQC — advisory
  > `floor(2W_c/3)+1`, не финальность; см. `consensus.rs:703-713`.

**Отозвано (не использовать):**
* `y=H(seed‖pk)` как VUF/VRF — Falcon не-уникален (P07/P09).
* `25–76` как следствие (13) — таблица `½log2 k` (P11 E.1).
* `n/3−(1/3)log2T` из union bound — только `n/3−log2T` (P17 T5).
* `σ_y ≥ 2^λ‖c·s1‖` без `Q` — правильно `Q·2^{λ−1}` (P18 T4).
* `‖c·h‖ ≤ ‖c‖‖h‖` — нужен `√n`/`‖c‖₁` (P16 T4).
* «grinding самодетектируем» — только при раскрытии обеих подписей
  (P15 B4).
* BHT «требует `2^{n/3}`» — верхняя оценка, нижняя неизвестна (P10 D2).

## 8. ROLLOUT (обязательно; иначе форк)

**Правило.** Любой height-dependent фикс — PMM sign, µQC threshold,
rotation, hash migration, cap-exact emission, beacon — активируется
только так:

1. **Один бинарник.** Все ноды обновлены на одну и ту же сборку **до**
   высоты `H`.
2. **Одна активация.** Один коммит на `H = tip + 7200` (≈72 мин при
   0.6 с; запас на пропагацию и рестарты).
3. **Совместимость.** До `H` старые бинарники работают по старому
   правилу; после `H` — не голосуют/отклоняются.
4. **Мониторинг.** `H−7200…H`: все ноды на новой версии; `H…H+100`:
   нет fork/panic; откат — только через новый `H`, не вручную.
5. **Запрещено** активировать несколько пунктов в одном блоке и менять
   порог/знак без `H`.

**Текущее состояние цепи (refresh 2026-11-06):**
* `h = 753` стоит; кворум `3/3`; валидатор `B` **down с 4 ноября**.
* Любые height-dependent пункты **бессмысленны до ремонта B**: нет
  кворума для активации. Сначала восстановить B/кворум, потом rollout.

**Порядок активаций (один бинарник, затем H):**

| Шаг | Что | Гейт | Риск |
|---:|---|---|---|
| 1 | PMM sign (уже FIXED) | нет | низкий |
| 2 | µQC C1 (advisory + full QC) | height | средний |
| 3 | Rotation height | height | средний |
| 4 | Hash 384 (fork) | height/fork | высокий |
| 5 | Beacon/XMSS | `BEACON_DRAW_ACTIVATION_HEIGHT` | высокий |
| 6 | cap-exact emission | `EMISSIONCapEXACT_ACTIVATION_HEIGHT` | средний |

**Pre-flight:** хеш бинарника совпадает у всех; снапшот состояния;
метрики `H−7200…H+100`; план отката — новый `H`, не ручной откат.

---

## 9. DO-NOT-IMPLEMENT (до отдельного решения)

Не начинать кусками. Разрешённый максимум для этих пунктов — **доки и
тесты**, не production-пути:

* **STARK-прувер** — нет бэкенда; в статьях только crossover-математика.
* **Wiring/активация XMSS** — только через rollout §8.
* **Bridge PQ-кворум** — §4.2 — эскиз; нужен отдельный дизайн/тесты.
* **Миграция 384-битных хешей** — отдельный проект/форк (wire/state).
* **Флип cap-exact / SPRT / CUSUM / sampling / beacon** — только через §8.
* **Threshold ML-DSA** — SOTA не production; для checkpoint `T≤6–8`.
* **Coq/Lean-доказательства** — research (см. `FORMALIZATION.md`).
* **Mainnet-калибровка** — данных нет (P26).

Если исполнитель начинает с этих пунктов «по кускам» — это нарушение
rollout и риск форка.

---

**Источники:** `DEFECTS.md`, `CORRECTIONS.md`, `HIGH_TRIAGE_SUMMARY.md`,
`papers/P1–P26`, `code/`, `results/`. Это не заменяет код-аудит: перед
применением сверить `file:line` с текущим main.
