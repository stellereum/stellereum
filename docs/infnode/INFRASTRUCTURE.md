# InfMail — Как будет работать федеративная сеть (v2)

## Оглавление
1. [Что есть сейчас](#1-что-есть-сейчас)
2. [Три роли в сети](#2-три-роли-в-сети)
3. [Архитектура сети](#3-архитектура-сети)
4. [Voting — за ноды, не за валидаторов](#4-voting--за-ноды-не-за-валидаторов)
5. [Earnings — как зарабатывают ноды и валидаторы](#5-earnings--как-зарабатывают-ноды-и-валидаторы)
6. [Распределение регистраций между нодами](#6-распределение-регистраций-между-нодами)
7. [Путь письма — как backend нод и валидаторов работает вместе](#7-путь-письма--как-backend-нод-и-валидаторов-работает-вместе)
8. [Кодовые изменения](#8-новые-файлы-в-проекте)
9. [Что делать первым](#9-что-делать-первым)

---

## 1. Что есть сейчас

### Backend (`infmail-backend/src/`)
- `main.rs` — поднимает Axum-сервер на 1 порту
- `api.rs` — все HTTP-эндпоинты (register, login, send_mail, get_inbox, 2fa, settings, …)
- `stalwart.rs` + `ports.rs` — общение с **одним** локальным Stalwart через JMAP
- `security.rs` — argon2-хэширование, JWT-claims, AES-шифрование TOTP-секретов
- `web3.rs` + `blockchain.rs` — интеграция с TON-Registry (только email→wallet mapping)
- `database.rs` — SQLite с миграциями
- `indexer.rs` — слушает TON-блокчейн, обновляет записи

### Frontend (`infmail-frontend/src/`)
- `app/page.tsx` — landing `infmail.org`
- `app/login/page.tsx`, `app/register/page.tsx`, `app/dashboard/page.tsx`
- `app/recovery/page.tsx`, `app/add-account/page.tsx`
- `store/useAppStore.ts` — Zustand: accounts, jwtToken, mails, settings

### Contracts (`infmail-contracts/src/`)
- `registry.tolk` — `RegisterZK { emailHash, walletRef }` за 0.1 TON
- `storage.tolk` — `TopupStorage { targetEmailHash }` — общий фонд
- `collection.tolk` — NFT (заготовка)

### Что работает
- ✅ Юзернейм `nickname@infmail.org`
- ✅ Регистрация через email+password **или** TON-кошелёк
- ✅ JWT-cookie auth, 2FA, E2EE ключи
- ✅ Inbox/Sent/Drafts/Spam/Trash через JMAP
- ✅ Recovery по trusted-email или 2FA

### Чего НЕ работает
- ❌ **Нет реальной отправки писем наружу** — JMAP-Stalwart только внутри
- ❌ Нет DKIM/SPF/DMARC
- ❌ Нет федерации — один сервер = одна точка отказа
- ❌ Нет way для юзера поднять свой узел
- ❌ Нет consensus для распределения регистраций

---

## 2. Три роли в сети

В сети InfMail три **разных** участника. Они не конкурируют — у каждого своя функция.

### 2.1 Валидаторы (Validators) — наши серверы

**Кто владеет:** Компания InfMail (то есть мы).
**Количество:** 3-5 фиксированных серверов с чистыми IP.
**Можно ли удалить голосованием:** **Нет.** Валидаторы — это критическая инфраструктура. Если валидатор плохо работает — мы его чиним или заменяем сами.

**Что делают:**
- Принимают SMTP (порт 25) от внешнего мира (Gmail, Outlook)
- Подписывают исходящие письма **своим DKIM ed25519-ключом**
- Добавляют ARC-цепочку (кто, когда, какие подписи)
- Передают входящие на домашнюю ноду получателя
- Передают исходящие от нод в Gmail/Outlook через **свой чистый IP**

**Зарабатывают:**
- Плата за relay (когда нода шлёт письмо через валидатор)
- Премиум-тарифы (для корпоративных клиентов, которые хотят SLA)
- B2B (другие почтовые сервисы платят за relay через нас)

**Ключевой инвариант:** Валидатор **никогда** не хранит почту юзеров. Только подписывает и пересылает. Stateless по дизайну.

### 2.2 Ноды (Nodes) — где живёт почта

**Кто владеет:** Кто угодно. Юзер поднимает домашнюю ноду, или сторонний оператор поднимает "облачную" ноду.
**Количество:** Сколько угодно, динамически растёт.
**Можно ли удалить голосованием:** **Да.** Если нода спамит, теряет данные, обманывает юзеров — валидаторы голосуют за её отключение.

**Что делают:**
- Хранят почту юзеров в локальном Stalwart (JMAP)
- Принимают API-запросы от панели `infmail.org` по mTLS
- Принимают входящие от валидаторов
- Отдают исходящие валидаторам для relay

**Два подтипа:**
- **Home Node** — юзер поднял на своём сервере, контролирует сам
- **Cloud Node** — сторонний оператор (например, немецкий провайдер запустил ноду для своих клиентов)

**Зарабатывают:**
- **0.05 TON за каждую регистрацию**, которая назначена на эту ноду
- **Месячная подписка** юзера за хостинг (например, $1/мес за 1GB mailbox)
- **Плата за дополнительное место** (storage overage)
- **Опционально** — доп. сервисы (custom domain, более крупные вложения, и т.д.)

### 2.3 Frontend — единая панель infmail.org

**Кто владеет:** Компания InfMail.
**Stateless:** Не хранит почту. Это **только UI + routing**.

**Что делает:**
- Регистрация / login (формы, OAuth, TON Connect)
- Находит ноду юзера через `/.well-known/infmail-node` или DNS TXT
- Проксирует запросы к его ноде через mTLS
- Показывает статус сети (какие ноды онлайн, сколько валидаторов)
- Маркетинговая страница (landing)
- Админ-панель (только для нас)

---

## 3. Архитектура сети

```
┌──────────────────────────────────────────────────────────────────┐
│  ВНЕШНИЙ МИР: Gmail, Outlook, ProtonMail, любой SMTP            │
└──────────────────────────┬───────────────────────────────────────┘
                           │ outbound SMTP (port 25)
                           │ ←── DKIM/SPF/DMARC passes
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   ╔══════════╗       ╔══════════╗       ╔══════════╗
   ║VALID-1   ║       ║VALID-2   ║       ║VALID-3   ║   ← НАШИ
   ║ IP A     ║◄─────►║ IP B     ║◄─────►║ IP C     ║     фиксированные
   ║ DKIM ed  ║       ║ DKIM ed  ║       ║ DKIM ed  ║
   ║ ARC seal ║       ║ ARC seal ║       ║ ARC seal ║
   ╚════┬═════╝       ╚════┬═════╝       ╚════┬═════╝
        │                  │                  │
        │  (mutual TLS, no relay)            │
        │                  │                  │
        └──────────┬───────┴──────────┬───────┘
                   │                  │
                   ▼                  ▼
        ┌──────────────────────────────┐
        │       TON BLOCKCHAIN         │
        │  ┌────────────────────────┐  │
        │  │ Registry:              │  │
        │  │  email → node_id       │  │  ← ГДЕ юзер
        │  │  emailHash → walletRef │  │  ← Web3 proof
        │  │  node → reputation     │  │  ← рейтинг ноды
        │  │  node → stake          │  │  ← стейк ноды
        │  │  votes[]               │  │  ← голоса на remove
        │  └────────────────────────┘  │
        └──────────────────────────────┘
                   ▲
                   │ events (indexer)
                   │
        ┌──────────┴─────────────────────┐
        │  DNS WATCHER (наш сервис)      │
        │  infmail.org zone             │
        │  + _node.<email>.infmail.org   │  ← какой ноде жить
        └────────────────────────────────┘

   ═════ ВНУТРЕННЯЯ СЕТЬ (mutual TLS) ═════

   ┌────────────┐   ┌────────────┐   ┌────────────┐
   │ NODE-1     │   │ NODE-2     │   │ NODE-3     │   ← СТОРОННИЕ
   │ Europe/DE  │   │ USA/West   │   │ Asia/SG    │     операторы
   │ 5000 users │   │ 3000 users │   │ 1000 users │     зарабатывают
   │ ┌────────┐ │   │ ┌────────┐ │   │ ┌────────┐ │     на подписках
   │ │Stalwart│ │   │ │Stalwart│ │   │ │Stalwart│ │
   │ │  (JMAP)│ │   │ │  (JMAP)│ │   │ │  (JMAP)│ │
   │ └────────┘ │   │ └────────┘ │   │ └────────┘ │
   │ ┌────────┐ │   │ ┌────────┐ │   │ ┌────────┐ │
   │ │InfMail │ │   │ │InfMail │ │   │ │InfMail │ │
   │ │  API   │ │   │ │  API   │ │   │ │  API   │ │
   │ └────────┘ │   │ └────────┘ │   │ └────────┘ │
   │  satoshi@.. │   │  alice@..  │   │ bob@..     │
   └────────────┘   └────────────┘   └────────────┘
```

---

## 4. Voting — за ноды, не за валидаторов

**Принцип:** Валидаторы — наши. Голосовать за их удаление бессмысленно (мы их и так контролируем). Голосовать нужно за ноды — это публичная инфраструктура с произвольными операторами.

**Ключевое уточнение:** Spamhaus / Google blocklists банят **IP валидаторов** (потому что они отправляют почту в Gmail), а **не нод**. Нода вообще не может отправить письмо в Gmail напрямую — она релеит через валидатор, который прогоняет через антиспам и подписывает DKIM от своего имени. Если Spamhaus забанит IP ноды — ничего не произойдёт, потому что SMTP-трафик с этого IP не идёт в Gmail. Поэтому Spamhaus trigger для нод — бессмысленный. Используем другие сигналы.

### 4.1 Триггеры для голосования

Валидаторы автоматически отслеживают поведение нод:

| Что случилось | Кто заметил | Действие |
|----------------|-------------|----------|
| Нода не отвечает 30+ минут (down) | Все 3 валидатора (пингуют) | +1 vote от каждого |
| Нода шлёт слишком много relay-запросов (DoS) | Validator (rate-limit) | +1 vote + temporary freeze |
| Нода пытается релеить спам, который отклонён антиспамом 100+ раз/час | Validator (Rspamd score) | +1 vote |
| Взлом ноды (аномальные паттерны: юзеры жалуются на чужие письма, доступ с новых IP-стран) | Validator (ML-детект + anomaly detection) | +1 vote + immediate freeze |
| Юзер пожаловался (через support) на свою ноду | Validator (вручную) | +1 vote |
| Оператор ноды нарушил ToS (продажа данных, майнинг на чужом CPU, etc) | Validator (вручную, после расследования) | +1 vote |
| Нода хранит запрещённый контент (CP, etc) — по жалобе юзеров или authorities | Validator (вручную) | +1 vote + immediate freeze |

### 4.2 Контракт

```tolk
struct Node {
    operator: address         // кошелёк оператора ноды
    endpoint: string          // "node-eu-1.infmail.org:443"
    pubkey: uint256           // mTLS сертификат
    stake: coins              // ≥10k TON (меньше чем валидатор)
    reputation: int           // 0..100, начинается с 50
    active: bool
    registeredAt: uint32
    userCount: uint32
    storageUsedGB: uint32
    removalVotes: uint8
}

struct Storage {
    nodes: map<uint256, Node>          // nodeHash → Node
    node_by_domain: map<string, uint256>  // "node-eu-1.infmail.org" → nodeHash
    email_to_node: map<uint256, uint256>  // emailHash → nodeHash (где юзер)
    total_nodes: uint32
    active_nodes: uint32
    min_node_stake: coins = 10_000_000_000  // 10k TON
    removal_threshold: uint8 = 2            // нужно 2 голоса из валидаторов
}

// Сообщения
struct (0x4e4f4445) RegisterNode {
    endpoint: string
    pubkey: uint256
    stake: coins
}

struct (0x4e4f564d) VoteRemoveNode {
    nodeHash: uint256
    reason: int  // 1=spam, 2=down, 3=compromise, 4=other
}

// Events
emit("NodeRegistered", nodeHash, endpoint);
emit("NodeRemoved", nodeHash, reason);
emit("UserAssigned", emailHash, nodeHash);
```

**Кто может голосовать:** только активные валидаторы (3-5 адресов).
**Кто НЕ может голосовать:** операторы нод, юзеры.
**Сколько нужно голосов:** `removal_threshold` (по умолчанию 2 из 3-5 валидаторов).

### 4.3 Что происходит после remove

```tolk
VoteRemoveNode => {
    require(is_validator(msg.senderAddress), 401);
    require(!storage.removal_votes.exists(hashOf(msg.senderAddress)), 402);
    
    val node = storage.nodes.get(target_hash).loadValue();
    require(node.active, 403);
    require(node.removalVotes < storage.removal_threshold - 1, 404);
    
    node.removalVotes += 1;
    storage.nodes.set(target_hash, node);
    
    if (node.removalVotes >= storage.removal_threshold) {
        node.active = false;
        node.stake = 0;  // ← slash
        storage.nodes.set(target_hash, node);
        
        // Эвакуация юзеров
        emit("NodeRemoved", target_hash, msg.reason);
        // DNS-Watcher перестаёт указывать на этот endpoint
        // Validator при следующей попытке relay — fallback на другую ноду
    }
}
```

**Эвакуация юзеров:**
1. Validator эмитит "NodeRemoved" event
2. DNS-Watcher удаляет `_node.<email>.infmail.org` для всех юзеров этой ноды
3. При следующем запросе от юзера — load balancer переназначает на новую ноду
4. Если возможно — данные мигрируют (operator заранее синхронизирует с резервной нодой)

---

## 5. Earnings — как зарабатывают ноды и валидаторы

### 5.1 Источники дохода

```
                    ┌─────────────┐
                    │   Юзер      │
                    │  платит $1  │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │ 0.05 TON │ │ $0.95    │ │  $0.05   │
        │  setup   │ │  /мес    │ │  relay   │
        │ fee      │ │ node     │ │  to      │
        │          │ │ operator │ │ valid.   │
        └────┬─────┘ └────┬─────┘ └────┬─────┘
             │            │            │
             ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  Node    │ │   Node   │ │Validator │
        │ operator │ │ operator │ │ (us)     │
        │ (once)   │ │ (recurr) │ │          │
        └──────────┘ └──────────┘ └──────────┘
```

### 5.2 Конкретные потоки

#### Юзер регистрируется

```
0.1 TON (RegisterZK в TON) → расщепляется:
├─ 0.05 TON → Node operator     (за assignment)
├─ 0.03 TON → Storage контракт (фонд сети)
├─ 0.01 TON → Validator-1        (relay fee pool)
└─ 0.01 TON → резерв InfMail
```

**Как это работает:** Когда юзер шлёт `RegisterZK` транзакцию в TON, его `walletRef` уже зарегистрирован. Отдельная транзакция `AssignNode { emailHash, nodeHash }` платит `0.05 TON` напрямую оператору ноды. **Это off-chain в нашем backend, но on-chain settled через TON-транзакцию.**

#### Юзер платит monthly subscription

```
Stripe / Crypto → Backend → split:
├─ 85% ($0.85 of $1) → Node operator (за хостинг)
├─ 10% ($0.10)        → Validator-1 (за relay в прошлом месяце)
└─ 5%  ($0.05)        → InfMail (инфраструктура)
```

**Как делятся между валидаторами:** пропорционально количеству relayed писем в этом месяце. Validator-1 записал в лог: "relay satoshi → 50 писем, alice → 30 писем, всего 80". Validator-2: "relay 60 писем". Validator-3: "relay 100 писем". Всего 240. Validator-3 получает 100/240 = 42% от relay-pool.

#### Storage overage

Если юзер использует 10 GB вместо бесплатных 1 GB:

```
$0.10/GB/мес дополнительно → 100% Node operator
```

**Почему:** Валидатор не хранит данные. Только нода. Значит storage fee — её доход.

### 5.3 Что получает валидатор (InfMail)

| Источник | Размер | За что |
|----------|--------|--------|
| Relay fee | ~0.01 TON / 100 писем | Подпись и relay каждого outbound |
| Premium relay | $0.005 / письмо | Для корпоративных клиентов с SLA |
| Enterprise contracts | $500-5000 / мес | Кастомные домены, retention, etc |
| B2B relay | $0.001 / письмо | Другие почтовые сервисы платят за relay через нас |
| Stake rewards | 5-10% APY | За стейк 100k TON в валидатор-пуле |

**Validator 1 с 10k активных юзеров через него:**
- 10k юзеров * ~50 писем/мес * 0.005 = **$2,500/мес** от relay fees
- 5-10% APY на 100k TON стейка = **~$5-10k/год**
- Premium/Enterprise = **variable, target $5-20k/мес**

### 5.4 Что получает нода (оператор)

| Источник | Размер | За что |
|----------|--------|--------|
| Setup fee | 0.05 TON / юзер | Начальная регистрация |
| Monthly subscription | $0.85 / юзер / мес | Хостинг mailbox |
| Storage overage | $0.10 / GB | Дополнительное место |
| Domain fee | $0.50 / домен / мес | Custom domain hosting |
| Premium tier | +50% | Расширенный backup, priority support |

**Node с 3000 юзеров (типичный средний оператор):**
- Setup: 100 новых / мес * 0.05 TON = **5 TON/мес** (~$10-20)
- Subscriptions: 3000 * $0.85 = **$2,550/мес** ← главный доход
- Storage: 100 юзеров * 2GB extra * $0.10 = **$20/мес**
- **Итого: ~$2,580/мес** с одной ноды на 3000 юзеров

### 5.5 ROI ноды

**Стоимость содержания хорошей ноды:**
- VPS: $50-200/мес (зависит от размера)
- Storage: $0.02/GB/мес на S3-совместимом
- Трафик: $0.01-0.05/GB
- Bandwidth relay: $10-50/мес

**Break-even:** ~250 платных юзеров ($0.85/мес = $212) — отбивает VPS $200. **Всё что сверху — прибыль.**

---

## 6. Распределение регистраций между нодами

### 6.1 Алгоритм выбора ноды

Когда новый юзер регистрируется, нужно выбрать ноду для его mailbox. Алгоритм:

```rust
// src/federation/load_balancer.rs
async fn pick_node(user_ip: IpAddr, country: &str) -> Node {
    let nodes = registry.get_active_nodes().await;  // все ноды с reputation > 30
    
    // 1. Фильтруем по capacity
    let capable: Vec<Node> = nodes
        .into_iter()
        .filter(|n| n.storage_free_gb() > MIN_FREE_GB)  // хотя бы 1GB свободно
        .filter(|n| n.userCount < MAX_USERS_PER_NODE)    // не перегружена
        .collect();
    
    // 2. Скорим каждую
    let scored: Vec<(Node, f64)> = capable
        .into_iter()
        .map(|n| {
            let geo_score = geo_distance_score(user_ip, n.geo);    // 0-100
            let rep_score = n.reputation as f64;                  // 0-100
            let cap_score = capacity_score(n);                     // 0-100
            let load_score = (1.0 - n.userCount as f64 / MAX_USERS_PER_NODE as f64) * 100.0;
            
            let total = geo_score * 0.4 + rep_score * 0.3 + cap_score * 0.1 + load_score * 0.2;
            (n, total)
        })
        .collect();
    
    // 3. Сортируем и берём лучшую
    scored.into_iter().max_by(|a, b| a.1.partial_cmp(&b.1).unwrap()).unwrap().0
}
```

**Метрики:**
- **geo_score** (40%): пинг от user_ip до ноды, меньше = лучше. Макс 100 за <50ms.
- **rep_score** (30%): reputation ноды 0-100.
- **cap_score** (10%): свободное место, больше = лучше.
- **load_score** (20%): насколько нода недогружена (1 - userCount/max).

### 6.2 Сценарии выбора

**Сценарий A: Юзер из Германии**
- Node-DE (geo=10ms, rep=85, free=5TB, users=2000/5000): score = 95*0.4 + 85*0.3 + 80*0.1 + 60*0.2 = **87**
- Node-US (geo=150ms, rep=90, free=2TB, users=3000/5000): score = 50*0.4 + 90*0.3 + 60*0.1 + 40*0.2 = **63**
- **→ Node-DE wins**

**Сценарий B: Все ноды перегружены**
- Все ноды возвращают `storage_free_gb < MIN_FREE_GB`
- Алгоритм возвращает 503 "No capacity, try later" или автоматически создаёт новую ноду в облаке (наш fallback)

**Сценарий C: Юзер хочет конкретную ноду**
- В форме регистрации есть dropdown "Choose region/node"
- Прямой выбор минует алгоритм (но всё равно проверяется capacity)

### 6.3 Юзер хочет сменить ноду

```
User → Settings → "Move mailbox to different node"
   ↓
1. UI показывает список доступных нод (geo + reputation)
2. Юзер выбирает целевую ноду
3. Backend координирует миграцию:
   a) New node создаёт пустой mailbox
   b) Old node экспортирует mbox
   c) Transfer через encrypted channel между нодами (operator-to-operator)
   d) DNS обновляется: _node.satoshi.infmail.org → new endpoint
   e) Old node удаляет данные через 7 дней (grace period)
4. Юзер автоматически перенаправлен на новую ноду
```

**Оплата:** бесплатно первые 2 раза в год, потом $1 (для покрытия bandwidth).

### 6.4 Что если выбранная нода упала

```
1. Validator обнаруживает ноду down (пинг не проходит)
2. Validator эмитит "NodeDegraded" event (НЕ remove — может временно)
3. DNS-Watcher устанавливает TTL=60s для записей этой ноды
4. Юзер при следующем запросе → load balancer переназначает на другую
5. Старая нода когда восстановится → юзер может вручную вернуться
```

---

## 7. Путь письма — как backend нод и валидаторов работает вместе

### 7.1 Новый юзер регистрируется

```
Шаг 1: Юзер → infmail.org/register
   POST { email: "alice", password: "...", pow: ... }
   ↓
Шаг 2: Frontend → Frontend Backend (только infmail.org)
   POST /api/v1/auth/register
   { email, password, solution }
   ↓
Шаг 3: Frontend Backend (аутентификация + routing)
   a) Проверяет PoW
   b) Валидирует password
   c) Спрашивает у Validator pool: pick_node(alice_ip, country)
   d) Validator pool возвращает: node_hash + node_endpoint
   e) Frontend Backend создаёт account на ЭТОЙ ноде:
      POST https://node-eu-1.infmail.org:443/api/v1/internal/create-user
      { email, password_hash, jwt_secret }
   ↓
Шаг 4: Node (получил create-user)
   a) Создаёт mailbox в своём Stalwart
   b) Создаёт запись в TON: AssignNode { emailHash, nodeHash }
   c) Создаёт запись _node.alice.infmail.org в DNS
   d) Возвращает { user_jwt, session_cookie }
   ↓
Шаг 5: Frontend Backend отдаёт JWT юзеру
   ↓
Шаг 6: Юзер заходит на dashboard
   Frontend знает: "юзер alice на node-eu-1.infmail.org"
   Все API-запросы → mTLS к этой ноде
```

### 7.2 Юзер шлёт письмо в Gmail

**Ключевой момент:** Нода **никогда** не отправляет SMTP напрямую в Gmail/Outlook. Даже если нода попытается — это будет заблокировано на уровне сети (нода не имеет открытого port 25 наружу, и даже если бы имела — IP домашний/облачный, в blacklist у Gmail). Вся исходящая идёт **только через валидаторы** по mutual TLS.

```
Шаг 1: Юзер в dashboard → Compose → Send
   Frontend → POST https://node-eu-1.infmail.org/api/v1/mail/send
   Headers: { mTLS cert, Authorization: Bearer JWT }
   Body: { to: "bob@gmail.com", subject: "Hi", body: "..." }
   ↓
Шаг 2: Node (его mailbox)
   a) Проверяет claims
   b) Сохраняет в свой Stalwart (письмо в Sent)
   c) Спрашивает у Validator-1: "куда relay'ить?"
      → Validator-1 выбирает outbound-валидатор (например, VALID-2, меньше всего нагружен)
      → Validator-1 НЕ принимает решение о relay сам, а координирует
   ↓
Шаг 3: Node → outbound-валидатор (mutual TLS, через WireGuard)
   Protocol: внутренний JSON-RPC или SMTP-over-TLS
   
   {"action": "relay_outbound",
    "envelope": {"from": "alice@infmail.org", "to": "bob@gmail.com"},
    "raw_mime": "...<base64>..."}
   ↓
Шаг 4: Validator-2 (принимает relay от ноды)
   a) Проверяет mTLS-сертификат ноды (это node-eu-1 из реестра?)
   b) Rate limit: не шлёт ли нода 1000 запросов/сек (DoS)?
   c) Прогоняет raw MIME через Rspamd → score 0.2 (низкий, ok)
      Если score > 5.0 — ОТКЛОНЯЕТ (письмо не релеится, возвращает 429 ноде)
      Если score 0.5-5.0 — отправляет с пометкой [BULK]
   d) Подписывает DKIM от СВОЕГО имени:
      DKIM-Signature: v=1; a=ed25519-sha256; d=infmail.org; s=v2; ...
      Использует свой приватный ed25519 ключ
   e) ARC-подписывает (т.к. нода уже возможно подписала локально):
      ARC-Seal: i=1; a=ed25519-sha256; ...
      ARC-Message-Signature: i=1; a=ed25519-sha256; ...
   f) Отправляет в Gmail через свой SMTP:
      SMTP на gmail-smtp-in.l.google.com:25
      с envelope MAIL FROM:<alice@infmail.org>
   ↓
Шаг 5: Gmail проверяет
   SPF: pass (validator-2.infmail.org в _spf.infmail.org)
   DKIM: pass (публичный ключ v2._domainkey.infmail.org совпал)
   DMARC: pass (всё сходится)
   ARC: pass (цепочка валидна)
   → Входящие ✓
```

**Почему валидатор не может быть забанен через спам от ноды:** Каждый relay через валидатор проходит через Rspamd с порогом score=5.0. Если нода попытается релеить 1000 спам-писем — все 1000 будут отклонены на уровне валидатора, в Gmail не уйдёт ничего. Валидатор залогирует это и автоматически отдаст vote на remove этой ноды. То есть нода **физически не может** отправить спам в Gmail — её единственный путь наружу через валидатор, который фильтрует.

### 7.3 Gmail отвечает Бобу

```
Шаг 1: Gmail → MX lookup infmail.org
   DNS: MX 10 validator-1.infmail.org (round-robin)
   ↓
Шаг 2: Validator-1 принимает SMTP от Gmail
   RCPT TO:<alice@infmail.org>
   ↓
Шаг 3: Validator-1 проверяет
   - SPF: gmail.com в _spf.infmail.org (pass)
   - DKIM: google.com в _domainkey.infmail.org (pass)
   - DMARC: pass
   ↓
Шаг 4: Validator-1 узнаёт, где mailbox alice
   - DNS TXT: _node.alice.infmail.org → node-eu-1.infmail.org
   - Или спрашивает у Validator-2/3 (consensus)
   ↓
Шаг 5: Validator-1 → Node (mutual TLS)
   {"action": "relay_inbound",
    "envelope": {"from": "bob@gmail.com", "to": "alice@infmail.org"},
    "raw_mime": "...<base64>..."}
   ↓
Шаг 6: Node сохраняет
   - Stalwart: mail received in Inbox
   - WebSocket push в активную сессию юзера
   ↓
Шаг 7: Юзер видит новое письмо (real-time!)
```

### 7.4 Юзер пишет юзеру InfMail (alice → bob, оба в сети)

```
alice@infmail.org (на node-eu-1) → bob@infmail.org (на node-us-1)

Шаг 1: alice send → node-eu-1
Шаг 2: node-eu-1 проверяет: bob в системе?
   - Спрашивает у Validator-1 (или локальный кэш): "где bob?"
   - Validator-1: "bob на node-us-1"
Шаг 3: Оптимизация: можно ли relay напрямую node → node?
   ВАРИАНТ A (быстрый): node-eu-1 → node-us-1 (mutual TLS, прямой)
   ВАРИАНТ B (безопасный): node-eu-1 → validator-1 → node-us-1
   → Используем ВАРИАНТ B (через валидатор) — единая политика ARC, единый audit log
Шаг 4: Validator-1 принимает от node-eu-1
   - ARC-проверка source (уже подписан node?)
   - Передаёт в node-us-1
Шаг 5: node-us-1 сохраняет в свой Stalwart
Шаг 6: WebSocket push к bob'у
```

### 7.5 Что если нода упала во время отправки

```
1. Юзер нажимает Send → POST к node-eu-1
2. Node-eu-1 начинает relay к validator-2
3. В этот момент node-eu-1 крашится
4. Validator-2 видит: relay_inbound повис
5. Validator-2 эмитит "NodeDegraded" event
6. DNS TTL для _node.alice.infmail.org → 60s
7. Alice в следующий раз получает:
   "Ваш узел недоступен. Перейдите на резервную ноду?"
   → В один клик: данные мигрируют, alice на новой ноде
```

### 7.6 Чтение почты (юзер открывает dashboard)

```
1. Frontend загружается на infmail.org
2. Frontend проверяет: где alice?
   - Пробует GET https://alice.node-eu-1.infmail.org/.well-known/infmail-node
   - Если ответ 200 → использует этот URL
   - Если 404/timeout → fallback на infmail.org (облачная нода)
3. Frontend направляет ВСЕ API-запросы на этот URL
4. Каждый запрос:
   - mTLS (если своя нода) или cookie auth (если облачная)
   - JWT в Authorization header
5. Нода отвечает данными из своего Stalwart
```

### 7.7 Исходящее от нескольких юзеров (batch relay)

Если 100 юзеров одновременно шлют письма, валидатор обрабатывает их параллельно:

```
Validator-1 pool:
├─ Tokio workers (32 потока)
├─ Rate limit: 1000 relay/сек (настраивается)
├─ Queue: 10k pending
└─ Если перегрузка → 429 Retry-After, нода переключается на другой валидатор
```

---

## 8. Новые файлы в проекте

### Backend

```
infmail-backend/src/
├── smtp/                     # NEW: SMTP-сервер + DKIM + ARC
│   ├── mod.rs
│   ├── dkim.rs                # ed25519-подписи
│   ├── arc.rs                 # ARC-Seal/Message-Signature
│   ├── antispam.rs            # SpamAssassin / Rspamd
│   ├── outbound.rs            # SMTP-клиент в Gmail/Outlook
│   └── incoming.rs            # SMTP-сервер от внешнего мира
├── wireguard/                 # NEW: VPN-туннели
│   ├── mod.rs
│   └── peer.rs
├── federation/                # NEW: координация нод и валидаторов
│   ├── mod.rs
│   ├── transport.rs           # mTLS между нодами
│   ├── load_balancer.rs       # pick_node()
│   ├── relay.rs               # relay_inbound, relay_outbound
│   ├── discovery.rs           # найти ноду юзера
│   └── migration.rs           # миграция mailbox между нодами
├── billing/                    # NEW: подписки и распределение денег
│   ├── mod.rs
│   ├── subscriptions.rs        # Stripe, Crypto payments
│   ├── split.rs                # распределение 85/10/5
│   └── payout.rs               # выплаты операторам
├── dns/                        # NEW: DNS-Watcher
│   ├── mod.rs
│   └── updater.rs
├── ports.rs                    # + SmtpPort, FederationPort, BillingPort, DnsPort
├── api.rs                      # расширить
├── web3.rs                     # расширить: register_node, vote_remove_node
├── main.rs                     # mode: validator | node | cloud
└── config.rs                   # NEW: config.toml
```

### Frontend

```
infmail-frontend/src/
├── lib/
│   ├── nodeDiscovery.ts        # найти ноду юзера
│   └── proxyClient.ts          # mTLS-запросы
├── store/
│   └── useAppStore.ts          # + nodeUrl, + nodeStatus
├── app/
│   ├── api/
│   │   ├── nodes/lookup/route.ts
│   │   ├── nodes/list/route.ts
│   │   └── network/status/route.ts
│   └── settings/
│       └── my-node/page.tsx     # NEW
└── components/
    ├── NetworkStatus.tsx
    ├── NodeConnectPrompt.tsx
    └── NodeSelector.tsx
```

### Contracts

```
infmail-contracts/src/
├── registry.tolk               # РАСШИРИТЬ: +Node, +AssignNode, +VoteRemoveNode
├── storage.tolk                # РАСШИРИТЬ: validator/node rewards
└── network.tolk                # NEW: registry нод
```

---

## 9. Что делать первым

### Фаза 1: Реальный SMTP (2-3 недели)
**Цель:** письма доходят до Gmail.

1. Зарегистрировать `infmail.org` (если не)
2. Поднять 1 VPS с чистым IP (Hetzner/OVH)
3. Настроить DNS: MX, SPF, DKIM, DMARC
4. Написать `smtp/mod.rs` (SMTP-сервер + клиент)
5. Написать `smtp/dkim.rs` (ed25519-подписи)
6. Написать `smtp/outbound.rs` (отправка в Gmail)
7. Интегрировать в `api.rs::send_mail`
8. Тест: `test@infmail.org` → `my-personal@gmail.com` приходит

### Фаза 2: WireGuard и нода (3-4 недели)
**Цель:** одна нода + один валидатор работают вместе.

1. Поднять 2-ую VPS как валидатор
2. Настроить WireGuard между текущим backend (node) и validator
3. Написать `wireguard/mod.rs`
4. Написать `federation/relay.rs` (relay_inbound, relay_outbound)
5. ARC-подписи при relay
6. Тест: юзер на node-eu-1 шлёт через validator-us-1 в Gmail

### Фаза 3: TON контракты нод (2-3 недели)
**Цель:** децентрализованный реестр нод.

1. Расширить Registry: `Node`, `RegisterNode`, `VoteRemoveNode`
2. Написать indexer для нод (по аналогии с email indexer)
3. Написать `dns/updater.rs` — слушает events, обновляет DNS
4. `federation/load_balancer.rs` — алгоритм pick_node

### Фаза 4: Billing (2-3 недели)
**Цель:** деньги текут.

1. `billing/subscriptions.rs` — Stripe / Crypto
2. `billing/split.rs` — 85% нода, 10% валидатор, 5% InfMail
3. `billing/payout.rs` — ежемесячные выплаты операторам
4. Dashboard для оператора ноды (видит доходы, запросить payout)

### Фаза 5: Home Node (3-4 недели)
**Цель:** юзер может поднять свой узел.

1. `config.toml` парсинг (тот же бинарь, разные режимы)
2. CLI: `infmail node init alice@infmail.org`
3. Авто-генерация WireGuard-ключей
4. Авторегистрация в TON-Registry (RegisterNode)
5. mTLS между панелью и домашним узлом
6. UI: "Set up home node" онбординг

### Фаза 6: UI сети (1-2 недели)
**Цель:** юзер видит состояние.

1. `NetworkStatus` компонент
2. `My Node` страница
3. `NodeSelector` при регистрации
4. Админ-панель для нас (операторы нод, жалобы, статистика)

**Итого: 14-19 недель до MVP с монетизацией.**

---

## Резюме в одном абзаце

**Сейчас:** Один сервер с JMAP-Stalwart, юзернеймы `nickname@infmail.org`, TON-Registry для ownership. Письма внутри системы работают, наружу — нет.

**Будет:** Тот же бинарь в 3 режимах (validator / node / cloud). **Валидаторы** — наши фиксированные серверы с чистыми IP, подписывают DKIM/ARC, **никогда не удаляются голосованием**. **Ноды** — публичная инфраструктура от сторонних операторов, хранят почту юзеров, **удаляются голосованием валидаторов** если спамят или падают. **Frontend** — stateless-маршрутизатор находит ноду юзера через discovery и проксирует к ней. Новые регистрации распределяются между нодами по load-balancing алгоритму (geo + reputation + capacity). Ноды зарабатывают на monthly subscriptions + setup fees + storage overage. Валидаторы зарабатывают на relay fees + premium + enterprise. DNS автоматически обновляется через TON events. Юзеру ничего не меняется визуально — та же панель, но физически его почта там, где он (или оператор его ноды) хочет.
