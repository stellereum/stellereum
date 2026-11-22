# InfMail — Хранение и финансы (v5)

## 1. Модель дохода

**Два потока:**

| Поток | Сумма | Когда | Тип |
|-------|-------|-------|-----|
| Регистрация | 0.1 TON | Один раз | Setup |
| Подписка | 2 TON/мес | Каждый месяц | Recurring |

**Включено в подписку 2 TON:**
- Mailbox 5-10 GB (на assigned ноде)
- AI-функции через Cocoon (Telegram) — умный inbox, смарт-ответы, антиспам, перевод
- E2EE шифрование
- Бэкап в TON Storage

---

## 2. Распределение денег

### 2.1 Регистрация (0.1 TON)

```
0.1 TON расщепляется:
├─ 0.06 TON (60%) → нода-оператор
├─ 0.025 TON (25%) → InfMail (валидаторы)
├─ 0.01 TON (10%) → TON fee
└─ 0.005 TON (5%) → резерв
```

### 2.2 Подписка (2 TON/мес)

```
2 TON расщепляется:
├─ 1.2 TON (60%) → нода-оператор (за storage 5-10 GB + serving)
├─ 0.6 TON (30%) → InfMail (валидаторы + AI inference через Cocoon)
└─ 0.2 TON (10%) → резерв (AI fees, TON Storage DR, edge cases)
```

### 2.3 Почему такой split

**Нода получает 60% подписки** (1.2 TON) потому что:
- Платит за storage 5-10 GB на юзера (SSD: $0.10/GB/мес × 10 GB = $1/мес ≈ 0.03 TON)
- Платит за сервер (CPU, RAM, network)
- Платит за бэкап в TON Storage (дополнительные $0.01-0.05/мес за юзера)
- Несёт риск downtime (если юзер уйдёт — нода теряет recurring revenue)

**InfMail получает 30% подписки** (0.6 TON) потому что:
- Оплачивает валидаторы с чистыми IP ($200/мес × 3 = $600/мес)
- Оплачивает AI inference через Cocoon (~$0.10-0.50/мес за юзера)
- DNS-инфраструктура
- TON Storage fees для cold tier
- Поддержка юзеров
- Развитие платформы

**Резерв 10%** потому что:
- AI inference может стоить больше при активном использовании
- TON Storage fees могут расти
- Спорные транзакции, refunds
- Расширение нод (больше storage → больше расходы)

---

## 3. AI через Cocoon (Telegram)

### 3.1 Что такое Cocoon

Cocoon — децентрализованная AI-сеть от Telegram:
- Запросы идут к ближайшему inference-узлу
- Юзер платит за compute (TON micropayments)
- Модели: open-source LLM (Llama, Mistral, etc)
- Приватно — данные не уходят в OpenAI/Anthropic

### 3.2 Что делает AI в InfMail

**Smart Inbox (бесплатно, базовая):**
- Категоризация писем (work, personal, newsletters, spam)
- Извлечение action items ("ответить до пятницы", "оплатить счёт")
- Саммари длинных тредов

**Smart Reply (в подписке):**
- Генерация черновика ответа по контексту
- 3-5 вариантов в разных тонах (формальный, дружеский, короткий)
- На выбранном языке юзера

**Search (в подписке):**
- Семантический поиск по истории писем
- "Найди письмо от Иванова про квартальный отчёт"
- Работает локально если возможно (если нода имеет модель)

**Translation (в подписке):**
- Автоперевод входящих писем
- 50+ языков
- С сохранением форматирования

### 3.3 Как платится AI

```
Юзер жмёт "Smart Reply"
   ↓
Нода проверяет: есть ли inference локально?
   ↓
Если да → бесплатно для InfMail, юзер уже заплатил подписку
   ↓
Если нет → запрос к Cocoon network:
   POST https://cocoon.tg/inference
   { model: "llama-3-8b", prompt: "...", max_tokens: 200 }
   ↓
Cocoon отвечает + bill в TON micropayment
   ↓
InfMail оплачивает из 30% подписки
```

**Стоимость AI per юзер:**
- Лёгкий юзер: ~$0.10/мес (10-20 inference запросов)
- Активный юзер: ~$0.50/мес (100+ запросов)
- Из 0.6 TON/мес (30% подписки) → $1.73/мес — хватает с запасом

**Можно ли развернуть LLM на ноде?**
- Маленькие модели (1-3B параметров): да, на современном CPU
- Средние (7-13B): нужен GPU ($50-200/мес)
- Большие (70B+): только на валидаторах или в Cocoon

**Стратегия:**
- Нода имеет fallback: локальная модель (если есть) → Cocoon (если нет)
- Если юзер хочет без AI — opt-out в настройках → нода возвращает 0.7 TON/мес
- Premium tier (будущее): больше inference, приоритет, custom модели

---

## 4. Хранение данных

### 4.1 Где что лежит

```
ASSIGNED НОДА (SSD):
├─ Вся почта (мгновенный доступ)
├─ Mailbox 5-10 GB на юзера
├─ Все письма hot — никаких "tiers"
└─ Юзер не думает про storage

TON STORAGE (бэкап, E2EE):
├─ Каждое письмо дублируется зашифрованно
├─ X25519 + ChaCha20-Poly1305 (публичный ключ юзера)
├─ Только юзер может прочитать
└─ Для disaster recovery
```

### 4.2 Стоимость storage

**На ноде (10 GB на юзера):**
- 1000 юзеров × 10 GB = 10 TB
- SSD: $0.10/GB/мес = $1,000/мес
- НО! 60% подписки = $1.2 * 1000 = $1,200/мес дохода
- **Margin: 17%** — тесновато, нужно оптимизировать

**Оптимизация:**
- Компрессия (zstd): экономит 30-50% → 10 GB → 5-7 GB
- Tier внутри ноды: hot SSD (последние 90 дней) + cold HDD (старше)
- Дедупликация (одинаковые attachments)
- Attachment offload (большие файлы → TON Storage сразу)

**Реалистично на ноде:**
- 1000 юзеров × 7 GB сжатых = 7 TB
- Стоимость: $700/мес (SSD) или $140/мес (HDD + горячий кэш)
- **Margin: 40-80%** — нормально

**В TON Storage (бэкап):**
- 7 TB зашифрованных chunks
- $0.001/GB/мес = $7/мес
- **100x дешевле SSD** — это основная экономия

### 4.3 Архитектура хранения на ноде

```
/var/lib/infmail-node/
├── stalwart/                  # JMAP mailbox (active)
│   ├── inbox/                 # последние 90 дней на SSD
│   ├── sent/
│   ├── drafts/
│   ├── archive/               # >90 дней на HDD
│   └── tombstones/            # soft-deleted (30 дней до hard delete)
│
├── compressed/                # zstd-сжатые старые письма
│   └── 2024/                  # по году
│
├── ton-storage-cache/         # локальный кэш TON Storage
│   └── bag_id_xyz/
│
├── accounts/                  # кэш account state (реплицируется)
│   ├── alice@infmail.org.json
│   └── ...
│
├── keys/                      # E2EE private keys (per user)
│   └── alice@infmail.org.key
│
├── cocoon-cache/              # AI inference results (TTL 24h)
│   └── smart-reply/msg_123.json
│
└── logs/                      # operation logs
    └── relay.log
```

---

## 5. Что при падении ноды

### 5.1 Сценарий

```
1. Validator-1, -2, -3 пингуют ноду → timeout
2. Консенсус: "NodeOffline"
3. Эмитят в TON
4. DNS TTL → 60s
5. Load balancer → новая нода
6. Новая нода скачивает из TON Storage
7. Юзер логинится → видит свою почту
```

### 5.2 Восстановление с нуля

```
Новая нода получает emailHash alice:

1. Скачивает chunks из TON Storage:
   - Зашифрованные письма (E2EE, нода не может прочитать)
   - Зашифрованный mailbox state
   - Зашифрованные attachments
   - Зашифрованный список контактов

2. Распаковывает chunks в локальный кэш
   /var/lib/infmail-node/recovery/alice@infmail.org/

3. Ждёт юзера (он залогинится когда захочет)

4. Юзер заходит:
   POST /api/v1/auth/login
   { email, password, ... }
   ↓
5. Node отправляет challenge (для 2FA если есть)
   ↓
6. Юзер вводит password + TOTP
   ↓
7. Node получает private key юзера (decrypted with password)
   ↓
8. Node использует private key чтобы расшифровать mailbox
   ↓
9. Юзер видит свою почту

10. Бэкап в TON Storage обновляется на новой ноде
```

### 5.3 Скорость восстановления

| Размер mailbox | Время скачивания | Время расшифровки | Итого |
|----------------|------------------|-------------------|-------|
| 100 MB | 1-2 мин | 5 сек | ~2 мин |
| 1 GB | 5-10 мин | 30 сек | ~10 мин |
| 10 GB | 30-60 мин | 5 мин | ~65 мин |

**Прогресс-бар для юзера:**
```
Восстановление почты alice@infmail.org...
██████████░░░░░░░░░░ 47% (3.2 GB из 6.8 GB)
Осталось: ~4 минуты
```

### 5.4 Что если и TON Storage недоступен

TON Storage работает пока работает TON. TON — топ-10 блокчейн, uptime 99.99%. Если TON упадёт — теоретически вся система встанет (но это маловероятно).

**Дополнительная защита:** некоторые ноды могут держать encrypted backups других нод (peer-to-peer replication). Это опционально для нод с большим количеством юзеров.

---

## 6. Account records

```
TON BLOCKCHAIN (immutable):
├─ emailHash → walletRef         (ownership)
├─ emailHash → assignedNodeHash  (где mailbox)
├─ nodeHash → reputation, stake
├─ nodeHash → endpoint, pubkey
└─ Events log

ASSIGNED НОДА (current state):
├─ Mailbox (вся почта)
├─ Encrypted backup в TON Storage
├─ Account profile
├─ Settings, filters, labels
├─ TOTP secret, backup codes
├─ WebAuthn credentials
└─ AI preferences

ВСЕ НОДЫ (read-only cache):
├─ Минимальный профиль юзера
└─ Public key (E2EE)
```

### Регистрация

```
1. User → infmail.org/register { email, password, pow }
2. Validator pool: pick_node() → node_id
3. Validator → Node: create_user({ email, passwordHash, publicKey })
4. Node: создаёт Stalwart mailbox
5. Node: TON RegisterZK { emailHash, walletRef } (value 0.1 TON)
   0.1 TON расщепляется (60/25/10/5)
6. Node: TON AssignNode { emailHash, nodeHash }
7. Node: первичный бэкап в TON Storage
8. DNS: _node.alice.infmail.org → endpoint
9. User: получает JWT
```

### Подписка

```
1. User → infmail.org/subscribe { payment: 2 TON }
2. Frontend backend → TON Smart Contract:
   Subscribe {
     emailHash,
     value: 2 TON,
     duration: 30 days
   }
3. TON Contract расщепляет 2 TON (60/30/10)
4. TON Contract продлевает subscription на 30 дней
5. User → Node: теперь имеет active subscription
6. Node: AI features enabled, 10 GB quota available
```

### Отправка письма

```
1. User → Node: POST /mail/send
2. Node: сохраняет в Stalwart (Sent)
3. Node: дублирует в TON Storage (encrypted)
4. Node: relay в Validator
5. Validator: Rspamd + Cocoon AI smart-spam
6. Validator: DKIM signature
7. Validator: relay в Gmail
8. User: видит в Sent
```

### Получение письма

```
1. Gmail → Validator: SMTP port 25
2. Validator: SPF/DKIM/DMARC check
3. Validator: getAssignedNode(emailHash) из TON
4. Validator: Cocoon AI smart-categorize
5. Validator → Node: relay_inbound
6. Node: сохраняет в Stalwart
7. Node: дублирует в TON Storage
8. WebSocket push → User
9. User: видит новое письмо
```

---

## 7. Сводная экономика

### Сценарий A: Нода на 1000 юзеров

**Доходы в месяц:**
- Setup fees (50 новых/мес): 50 × 0.06 = **3 TON/мес** (~$6)
- Subscriptions (1000 юзеров): 1000 × 1.2 = **1,200 TON/мес** (~$2,400)
- **Итого: 1,203 TON/мес** (~$2,406)

**Расходы в месяц:**
- VPS + Storage: ~$300 (~150 TON)
- Bandwidth: ~$50 (~25 TON)
- TON Storage backup: ~$7 (~3.5 TON)
- **Итого: ~178 TON/мес** (~$356)

**Прибыль: ~1,025 TON/мес** (~$2,050)

### Сценарий B: Моя доля (InfMail) с 10k юзеров в сети

**Доходы:**
- Setup fees: 10k × 0.025 = **250 TON** (разово, при наборе базы)
- Subscriptions: 10k × 0.6 = **6,000 TON/мес**
- 1000 новых/мес × 0.025 = **25 TON/мес** (recurring)
- **Итого: 6,025 TON/мес recurring** после набора базы

**Расходы:**
- 3 валидатора × $200 = $600 (~300 TON)
- AI inference (Cocoon): ~$0.30/юзер × 10k = $3,000 (~1,500 TON)
- DNS + инфра: ~$100 (~50 TON)
- Команда (1-2 человека): $5,000 (~2,500 TON)
- **Итого: ~4,350 TON/мес**

**Прибыль: ~1,675 TON/мес** (~$3,350)

**При 100k юзеров:** ~16,750 TON/мес прибыли (~$33,500/мес)

---

## 8. Ключевые отличия от v4

| Параметр | v4 | v5 |
|----------|-----|-----|
| Подписка | $1/мес | 2 TON/мес (~$4) |
| Storage в подписке | 1 GB | 5-10 GB |
| AI | Не было | Cocoon (Telegram) |
| AI inference cost | - | Из 30% подписки |
| Split подписки | 70/20/10 | 60/30/10 |
| Recurring income | $1/мес | 2 TON/мес (в 4x больше) |

**Главное:** Подписка 2 TON/мес — это основной recurring revenue. С 10k юзеров это 6,000 TON/мес. С AI через Cocoon — premium feature который отличает от Gmail.
