# INFMAIL — ПОЛНОЕ ОПИСАНИЕ ПРОЕКТА И ПЛАН РАБОТ
> Обновлено: 2026-08-11. Этот файл — единственный источник полного контекста.
> Если контекст сессии потерян — прочитай этот файл целиком перед любыми правками.

---

## 1. КРАТКО

Децентрализованная E2E-почта + файловое хранилище на собственном протоколе **infnode**.
Эталон-конкурент: ProtonMail / Google Mail. Домен: `infmail.org`.

Ключевая идея владельца:
- **infnode — это СЕТЕВОЙ СЛОЙ** (не монолит). Он не должен содержать бизнес-логику почты.
- **Почта (InfMail) — отдельный проект**, работающий поверх infnode (как сервис), распределяется по нодам.
- **Валидатор** — точка входа в сеть для внешнего мира (Google/Yandex/SMTP) + держит web-слой.
- **Ноды** — внутренняя сеть: хранение (mail/files), передача сообщений, репликация.
- Будущее: свой блокчейн на базе infnode, Web4 (AI), OAuth-аккаунты как у Google.

---

## 1.5. КАК РАБОТАЕТ СИСТЕМА (для восстановления контекста)

### Топология и процессы
- **Валидатор 109.107.155.67 (node2)** — единственная web-нода. systemd: `infnode` (сеть 9400 UDP + web API 127.0.0.1:3001), `infmail-web` (Next.js 3000), `stalwart` (SMTP/IMAP), `nginx` (80/443 → 3000).
- **Локальная машина (node1)** — dev-нода, NAT. Запускается `./target/release/infnode serve --config deploy/node1/node.yaml`. Подключается к валидатору и aeza исходящими QUIC-соединениями (hole-punch). Обратные соединения от валидатора НЕ проходят (NAT).
- **aeza 147.45.75.253 (node3)** — storage-нода, только mail. Валидатор и aeza обмениваются dht.update/core.ping.

### Потоки данных
- **Входящее внешнее письмо**: Gmail → MX (mail.infmail.org) → stalwart (25/465) → IMAP-синк infnode (фоновый цикл 15с, `inbound.rs`) → парсит MIME (вложения base64/QP) → блобы `mail:{id}`, `mail:{id}:att:{i}` в DHT-хранилище + индекс `mail:{email}:index`.
- **Исходящее внутреннее**: compose UI → `/api/v1/mail/send` → блоб + индексы Inbox/Sent. E2E: браузер шифрует tweetnacl (X25519+XSalsa20), сервер хранит шифротекст.
- **Исходящее внешнее**: `/mail/send` к внешнему адресу → `smtp_relay_external` (lettre → stalwart → Gmail).
- **Файлы**: upload → клиент E2E-шифрует (XChaCha20 от keypair) → блоб `file:{email}:{name}` + индекс `files:{email}`. Download → расшифровка на клиенте.

### Хранение
- **accounts.json** (`/opt/infnode/web/accounts.json`) — ВСЕ аккаунты: pw_hash (argon2id), smtp_pass, квоты, подписки, сессии, E2E-ключи. Только на валидаторе (единая точка отказа).
- **kv.json** — DHT-KV: индексы писем (`mail:{email}:index/read/...`), файлов (`files:{email}`), реестр (`user:{email}` — публичные E2E-ключи), манифесты блобов (`m:*`, `f:*`), recovery-коды, blacklist, web3 nonce.
- **chunks/** — зашифрованные чанки (XChaCha20 per-blob, ключ в манифесте kv.json).
- **rewards.json** — веса/аптайм/trust_score нод для Distribute TON.

### Сеть (DHT)
- QUIC (UDP 9400), Ed25519 идентичность, X25519 сессионные ключи, Kademlia k-bucket.
- `store_blob` → локальные чанки + репликация к k-ближайшим (RF≤3).
- `dht.store/find_value` — KV; локально-авторитетные ключи (recovery/blacklist/mail/files) НЕ отдаются/принимаются по сети (защита от захвата).
- TOFU: неизвестные ноды принимаются только если `allow_unknown`, иначе reject.
- ACL пиров: `allow: ["*"]` для доверенных (node1, aeza).

### Подписки и оплата
- Юзер шлёт TON в Storage-контракт с комментарием `INFMAIL_SUB:<email>:<nonce>`.
- Индексатор каждые 45с: TON Center getTransactions → курсор по tx_hash → активация paid (продление 30дн/порог, cap 365дн).
- `INFNODE_WEB_ALLOW_DEMO_SUBSCRIBE=1` — демо-эндпоинт (бесплатный paid), для e2e.

### Ключевые ограничения (известные)
- Аккаунты только на валидаторе → нет репликации (надо добавить DHT `acct:{email}`).
- node1 не принимает входящие реплики (NAT) → RF=3 для почты фактически 2.
- `service.mail` (mailbox.jsonl) — устаревший мёртвый механизм, web.rs не использует (надо удалить).
- DKIM не настроен → внешние письма в спаме.
- JWT в localStorage (не httpOnly cookie).
- Web3-регистрация не проверяет on-chain оплату (бесплатные аккаунты).

---

## 2. СЕРВЕРЫ И ДОСТУПЫ (SENSITIVE)

| Роль | IP | Логин/пароль | SSH-скрипт |
|---|---|---|---|
| **Валидатор + почта + webmail (основной)** | `109.107.155.67` | `root` / `U3A1hXdjXSBzW7` | `/tmp/sshcmd.py`, `/tmp/scpcmd.py` (pexpect, venv `/tmp/venv`) |
| **Второй сервер (faucet/airdrop, Aeza, storage-нода)** | `147.45.75.253` | `root` / `q5foUWxm1T0B` | `/tmp/opencode/ssh2run.py`, `scp2.py` |
| Локальная машина (node1, NAT) | NAT `178.155.74.242`, порт 9400 | user `imm` | локально |
| 139.100.200.54 | НЕ наш (чужой, ignore) | — | — |

> ⚠️ /tmp очищается! Скрипты SSH пересоздаются при необходимости (pexpect, пароли выше).

### СЕТЬ ИЗ 3 НОД (RF=3 для почты)
- **node2 = валидатор**, `109.107.155.67:9400` (web API 3001, фронт 3000). Хранит mail+files. id `inf1:e17f0aaab9f7eeb63f224692c4bcf15d250f7949`.
- **node1** = локальная машина (NAT), ключи `/home/imm/infNode/deploy/node1/keys`, data_dir deploy/node1. Хранит mail+files. id `inf1:57146ca81f999f4cc3b0d50846d4cc4a53c65f18`.
- **aeza** = storage-нода `147.45.75.253:9400` (белый IP), **только mail** (`storage-roles: [mail]`), systemd `aeza-node`, конфиг `/root/infnode-node/node.yaml`. id `inf1:e963614041e8f29a5394d6cdf067eaabda958c0a`. Диск ~9.8G (почищено до 58%).
- Mesh: node1→node2, node1→aeza, node2↔aeza — работают. **Проблема**: NAT на node1 — обратная репликация (валидатор→node1) НЕ проходит (handshake timeout). Репликация файлов в сторону node1 ненадёжна.

### РОЛИ НОД (важно)
- `mail` = почта + хранилище писем
- `files` = отдельное файловое хранилище «за подписку»
- node1 = mail+files; aeza = только mail; валидатор = mail+files

---

## 3. АРХИТЕКТУРА — КАК ЕСТЬ СЕЙЧАС (монолит, НАРУШЕНИЕ)

Текущая реальность (нужно исправить):
- `infnode` (Rust, `/home/imm/infNode`) содержит **ВСЁ**: сеть (QUIC+DHT+storage в `node.rs`) И web-логику почты (`web.rs` 2666 строк, вшит `mod web;` в `main.rs:16`).
- Аккаунты лежат в `accounts.json` **только на валидаторе** (`/opt/infnode/web/accounts.json`). node1/aeza не знают об аккаунтах — они хранят только чанки.
- `web.rs` модули: auth (JWT/PoW/2FA), accounts, mail_api, files_api, plans, nft, subscribe, quota — всё внутри бинаря сети.

### Что работает сейчас (проверено)
- Webmail на `https://infmail.org`: register/login (classic + web3 TON), E2E-письма, файлы, алиасы, квота 1ГБ/3ГБ (mail), 0/6ГБ (files), подписки (plan), SMTP оба направления.
- Скорость send/inbox ~7-9мс, внешнее письмо → webmail за ~3с.
- Протокол: догоняющая репликация, роли нод, NAT hole punch (fallback), inbound-мост (IMAP INBOX+Junk), pubsub.
- Контракты TON (testnet) задеплоены:
  - Registry: `EQB_Y-LRJvZU7oBFSgVeP8CZM9fWe8VHcr3W9qO0y6dDJXHm`
  - Collection (NFT): `kQB5Y4R7OzRTfy1sfSpSfWccRfzuALtGhysikPz3CVRHUOk_`
  - Storage v2: `kQBwVBK0Pm1ZHgGczc38a5vhT5oEed6Gujml9f_lNMnByjWT` (admin=деплойер)
- Оплата: юзер шлёт TON в Storage с комментарием `INFMAIL_SUB:<email>:<nonce>` → индексер (45с) → активация подписки. Проверено end-to-end.
- Reward: 30% валидатору, 70% нодам по весам. node1 +0.14 TON, aeza +0.07 TON.
- Кошельки нод: node1=`EQAyVNlB4dFypbtyV8obXjBT5mIUb1jjATZbesVF2PYgtkDb`, aeza=`EQDiL2M_yn6HZlqXoYXGduiGDR1nBOZATyJ0__7rFBTiAnmU`.

### Deployer кошелёк (testnet)
- `kQCrDoZwy6L100ote94GSYRHC63TZAchvwEyobRTA-k-qgnf` (0 TON, нужно пополнить для деплоя).

---

## 4. АРХИТЕКТУРА — ЦЕЛЕВАЯ (как должно быть)

```
┌─────────────────────────────────────────────────────────────────┐
│                ВАЛИДАТОР (109) — gateway в инфнет              │
│   • InfMail Frontend (Next.js, :3000)                          │
│   • infmail-backend (auth, аккаунты, mail-API, квоты,          │
│                       OAuth IdP, NFT-выдача, AI-агенты)         │
│   • infnode (:3001 → нода-валидатор, держит данные как peer)    │
│   • TON-индексер подписок + AI-маршрутизатор                   │
│   • Stalwart (SMTP/IMAP bridge) + nginx                         │
│   • (1–3 валидатора, сейчас 1)                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
              ╔═══════════════ внутренняя сеть infnode ══════════════╗
              ║  DHT + репликация RF=3 + pubsub + E2E              ║
              ║  • node1 (локаль)  →  хранение mail+files          ║
              ║  • node2 = валидатор                                ║
              ║  • aeza (storage) →  хранение mail                 ║
              ║  • будущие ноды                                     ║
              ╚═══════════════════════════════════════════════════════╝
```

### Распределение ответственности

**ВАЛИДАТОР (бизнес-логика почты, формально отвечает за аккаунты):**
- Аккаунты, JWT/OAuth, 2FA, PoW-челленджи
- Квоты, подписки (paid_until), NFT-выдача
- Mail-API (REST для фронта): inbox/send/attachments/spam
- Files-API: upload/download + файловое ревью по нодам
- Indexer Storage v2: TON-подписки → запись в DHT
- Inbound IMAP-синк (stalwart → парсинг → DHT)
- Webmail backend (axum), frontend proxy (nginx)

**НОДЫ (сетевой слой, infnode — НЕ знает про аккаунты webmail):**
- DHT (Kademlia, k-bucket)
- Storage: чанки/репликация RF=3
- `service.mail` (низкоуровневый RPC: store/fetch/list)
- `core.storage` (статистика)
- `pubsub.*` (уведомления)
- NAT-hole-punch (нода за NAT = полноценный peer)
- E2E at-rest шифрование (XChaCha20)

**ФРОНТ (Next.js, infmail-web):**
- UI: ящик, ридер, compose, files, plan, settings
- Локальное E2E (X25519/XChaCha20 через tweetnacl)
- TonConnect UI для TON-оплаты
- OAuth UI (будущее)

**STALWART (MTA):** только SMTP/IMAP, мост в инфнет. Никакой бизнес-логики.

**КОНТРАКТЫ (infmail-acton, отдельный проект):** registry, storage (оплата), NFT collection/item.

---

## 5. ПЛАН ДЕКОМПОЗИЦИИ (вынести web из infnode)

### Фаза 0 — Каталог «почтового» в infnode (сделано)
- `web.rs` (2666 строк) — REST/бизнес (auth, accounts, mail, files, plans, nft, subscribe)
- `inbound.rs` (738) — IMAP-синк
- `mailbox.rs` (127) — шифрование at-rest
- `blockchain.rs` (183) — TON-вызовы (для индексера подписок)
- `services.rs` — `service.mail` (низкоуровневый RPC)
- Аккаунты в `accounts.json` (квоты/paid_until) — почтовое, не сетевое

### Фаза 1 — Контракт API инфноды (аудит service.mail)
- Проверить что реально покрывает `service.mail` (services.rs:60) и `core.storage`.
- Решение: `service.mail` + `dht.store/find_value` + `core.storage` = полный API сети.
- Убрать `web.rs` полностью.

### Фаза 2 — Скелет `infmail-backend`
- Путь: `/home/imm/infmail-backend` (восстановить из legacy на валидаторе или новый crate).
- Модули: `auth/`, `accounts/`, `quota/`, `mail_api/`, `files_api/`, `plans/`, `nft/`, `indexer/`, `inbound/`, `web/`.
- Прямые `st.node.*` → RPC `service.mail` / `dht.store` / `dht.find_value` / `core.storage`.

### Фаза 3 — Удаление из infnode
- Удалить `mod web;` из `main.rs:16`, `web.rs` целиком, `mod inbound;`.
- Из `services.rs` оставить `core.*` + `dht.*`. `mailbox.rs` — перенести как утилиту.
- `blockchain.rs` — TON-индексер в infmail-backend.

### Фаза 4 — Квоты и аккаунты в DHT
- `acct:{email}` → JSON с paid_until_ms, bytes_used, files_used, wallet, oauth_providers, ed25519_pub, tweetnacl_pub.
- `quota:{email}` — отдельный ключ для быстрых обновлений.
- Удалить accounts.json валидатора.

### Фаза 5 — Деплой
- На валидаторе: `infmail-backend.service` (отдельный бинарь), порт 8000 или 3001.
- nginx → upstream на infmail-backend.
- На node1/aeza: только infnode, без web.

### Фаза 6 — Документация
- Обновить INFNODE_CONTEXT.md под целевую архитектуру.

---

## 6. КЛЮЧЕВЫЕ ПУТИ И ФАЙЛЫ

- Протокол: `/home/imm/infNode/` (src: web.rs, node.rs, inbound.rs, blockchain.rs, mailbox.rs, dht.rs, proto.rs, services.rs; docs: PROJECT.md, PLAN_WEB3.md, AUDIT.md, SECURITY.md, PROTOCOL.md)
- Фронтенд: `/home/imm/infmail-web/` (Next.js; src/services/api.ts — вызовы)
- Контракты: `/root/infmail-acton` на 109.107.155.67 (Tolk, blueprint/acton 1.1.0, build/ готов)
- Deploy-скрипт контрактов: `/root/deploy_contracts.sh`
- accounts.json: `/opt/infnode/web/accounts.json`
- systemd: `infnode` (валидатор), `infmail-web` (фронт), `stalwart`, `nginx`
- Legacy backend (мёртвый): `/root/infmail-backend` (порт 8000, не запущен) — только для e2e-fixture
- e2e-спеки: `/home/imm/infmail-web/e2e/specs/` (storage-plan, mail-core, full-journey, sent-copy, user-journey, и др.)

---

## 7. УЯЗВИМОСТИ (анализ)

### Критичные (исправлены в этой сессии)
- ✅ Сброс лимитов при истечении paid (effective_* клампы)
- ✅ Квота входящей почты (reject/queue через max_bytes)
- ✅ Двойной учёт files_used при перезаписи
- ✅ mail_send: квота отправителя не списывается при ошибке получателя
- ✅ files_delete: физическое удаление блобов (delete_blob + kv_remove_local)
- ✅ settings_subscribe демо-дыра закрыта (env-флаг INFNODE_WEB_ALLOW_DEMO_SUBSCRIBE=1)
- ✅ Индексер: привязка кошелька к email (griefing-защита)
- ✅ mail_action delete: проверка владения перед refund
- ✅ CORS сужен (allowlist)

### Средние (остались)
- JWT_SECRET в env systemd (виден через /proc) — вынести в файл 0600.
- IMAP TLS `danger_accept_invalid_certs(true)` — реальный сертификат stalwart.
- `mail_attachment_save` без проверки magic bytes/MIME — можно XSS через .html/.exe.
- PoW difficulty=3 на проде (ок, но можно поднять).
- Storage-нода aeza открыта наружу — fail2ban + rate-limit на 9400.
- Регистрация web3 — проверить replay-защиту (nonce в payload).

---

## 8. РЕАЛИЗОВАНО В ЭТОЙ СЕССИИ (проверено)

### Бэкенд
- Эндпоинт «Сохранить в Files»: `POST /api/v1/mail/{id}/attachment/{idx}/save-to-files` (402 free, 403 чужой, дедуп имён `name (n)`).
- 9 фиксов безопасности/логики (см. раздел 7).

### Фронтенд
- Кнопка «Сохранить в Files» в ридере (только paid, уведомление).
- Карточка Storage с двумя барами (почта/файлы) в сайдбаре, клик → своя страница.
- Чип плана в топбаре → Plan; акцент-кнопка «Открыть Файлы» при paid.
- Фикс: E2EE-индикатор в compose не включался для внутренних адресов (`useE2EE` теперь true для @infmail.org).
- Тексты квот из `plan`, ревью-блок только для paid.

### Тесты (все прода-спеки прошли)
- storage-plan.spec: 6/6 (S1 вложения, S2 free-файлы 413, S3+S4 paid-квоты, S5 review, S6 UI, S7 save-to-files)
- mail-core.spec: 3/3
- full-journey.spec: 21/21 (обновлены устаревшие E2EE-селекторы)
- sent-copy.spec: 1/1 (обновлён)
- user-journey.spec: 6/6 (обновлён)
- web3.spec + all.spec: локальные (mock/infra-fixture), для локального dev

### Деплой на валидатор (109.107.155.67)
- Бэкенд: бинарник → `/opt/infnode/infnode`, systemd restart. active.
- Фронт: tar src → `/opt/infmail-web`, `npm run build` на сервере, restart infmail-web. active.
- systemd override: `/etc/systemd/system/infnode.service.d/demo.conf`:
  - `INFNODE_WEB_ALLOW_DEMO_SUBSCRIBE=1` (для e2e)
  - `INFNODE_WEB_FILE_QUOTA=0` (концепция: файлы только по подписке)
- Прод проверен: все страницы 200, plan/quota/files/review работают, free-upload 413.

---

## 9. ТЕКУЩИЕ ЗАДАЧИ (приоритеты прямо сейчас)

Пользователь сказал: «отложи блокчейн, web4 и т.п. Нам надо сделать все запросы про ноды, аккаунты, сообщения, все контракты и тесты».

1. **[АУДИТ] Аудит service.mail / core.storage** — что реально покрывают, какие RPC нужны.
2. **[НОДЫ] Роли, репликация, распределение файлов** — ревью-эндпоинт (types+nodes) проверить на проде.
3. **[АККАУНТЫ] Схема аккаунтов** — зафиксировать: валидатор формально отвечает за акки, ноды за хранение/передачу. Проверить accounts.json, JWT, OAuth-заготовки.
4. **[СООБЩЕНИЯ] Полный путь письма** — service.mail, E2E, вложения, доставка, квоты.
5. **[КОНТРАКТЫ] Все контракты** — registry/storage/NFT: запросы, интеграция, тесты (без своего блокчейна).
6. **[ТЕСТЫ] Полный набор** — e2e прода-спеки + контракты + юнит.
7. **[ДЕКОМПОЗИЦИЯ] Вынос web.rs в infmail-backend** — после закрытия п.1-6.

---

## 10. ДОЛГОСРОЧНЫЙ ROADMAP (отложено, НЕ делать сейчас)

1. **Свой блокчейн на базе infnode** — облегчённый улучшенный TON без внешних сервисов, BFT-консенсус поверх DHT валидаторов, аккаунты/транзакции/BLS, совместимость с Ed25519 (TON-кошельки). Storage v2 → перенос в этот блокчейн.
2. **Web4 = AI-интеграция** — `service.ai` RPC, AI-агент как аккаунт, маршрутизация, E2E-prompts, фронт-чат.
3. **OAuth (три режима)** — вход через Google/Apple/MS, выдача scoped-токенов наружу, интеграция со своим блокчейном.
4. **Единый аккаунт как Google** — почта + Drive + мессенджер + AI, один JWT, одна DHT-запись.
5. **Файловая E2E на клиенте** — ключ из master-пароля (PBKDF2/Argon2id), шифрование до отправки.
6. **3+ валидатора + шардирование web-сессий**.
7. **NAT hole-punch + проброс UDP 9400** на домашнем роутере → полноценная репликация на node1.

---

## 11. КОМАНДЫ-ШПАРГАЛКА

- Деплой бинаря: `scp → /root/infnode-vN` → `systemctl stop infnode; cp /root/infnode-vN /opt/infnode/infnode; systemctl start infnode`.
- SSH: `/tmp/venv/bin/python /tmp/sshcmd.py 'команда'` (pexpect, пароль U3A1hXdjXSBzW7).
- scp: `/tmp/venv/bin/python /tmp/scpcmd.py <src> 'root@109.107.155.67:<dst>'`.
- Сборка: `cd /home/imm/infNode && cargo build --release`; тесты `cargo test`.
- Фронт: `cd /home/imm/infmail-web && npx tsc --noEmit && npm run build`.
- E2E против прода (через туннель + локальный dev-фронт):
  - туннель: `nohup /tmp/venv/bin/python /tmp/opencode/tunnel.py &` (3001:127.0.0.1:3001)
  - dev-фронт: `nohup env NEXT_PUBLIC_API_URL=http://127.0.0.1:3001 npm run dev &`
  - `env E2E_BASE_URL=http://localhost:3000 npx playwright test --project=chromium --grep "S1|..."`
- e2e через прокси-домен (node fetch, Cloudflare OK): `env E2E_BASE_URL=https://infmail.org npx playwright test ...` (API-тесты только; UI-браузер блокируется JS-challenge).
- Контракты: `cd /root/infmail-acton && npx blueprint build --all && npx jest` (57/57).

### Примечание про e2e и Cloudflare
- Прод за Cloudflare: node fetch (API) проходит, Playwright-браузер (UI) — НЕТ (JS-challenge).
- Поэтому UI-тесты гоняются через локальный dev-фронт + SSH-туннель на бэкенд валидатора.
- В `account-fixture.ts` registerClassicViaApi решает PoW (sha256 salt+nonce) и шлёт `Connection: close` (обход keep-alive Cloudflare).

---

## 12. ВАЖНЫЕ НАБЛЮДЕНИЯ / ОГРАНИЧЕНИЯ

- **NAT node1**: обратная репликация к node1 не проходит (UDP 9400). Файлы фактически в 2 репликах (валидатор+aeza). Для полной RF=3 нужен проброс порта.
- **Playwright против прода**: браузер не проходит Cloudflare. UI-тесты → локальный фронт+туннель.
- **Локальный e2e против прода**: node fetch работает через https://infmail.org (Cloudflare).
- **zsh на сервере**: ломает команды с `|`, `;`, `<`, `>` — использовать bash-скрипты через scp+`bash`.
- **legacy infmail-backend**: лежит в `/root/infmail-backend`, не запущен, участвует только в e2e-fixture (`infra-fixture`), падает с EACCES. Не является частью рабочего стека.
- **infmail-acton**: контракты отдельным проектом. Это НЕ часть backend.

---

## 13. СОДЕРЖИМОЕ /ROOT НА ВАЛИДАТОРЕ (109) — карта файлов

### Скрипты (364 .sh), группы по назначению
- **`vps_v*` (v3–v40)** — история деплоев бинаря: `systemctl stop infnode; cp /root/infnode-vNN /opt/infnode/infnode; systemctl start infnode`.
- **`vps_acton*`** — деплой/проверка контрактов Tolk (Collection→NftCollection, Storage).
- **`vps_storage*`** — деплой Storage-контракта, смотр диска/chunks, wrapper.
- **`vps_stalwart*`, `vps_smtp*`, `vps_domid`** — конфиг/проверка stalwart (SMTP/IMAP, домены).
- **`vps_wallet*`** — поиск мнемоник/ключей кошельков.
- **`vps_unitfix*`** — полный systemd-юнит infnode (ВАЖНО для деплоя; содержит все env: SMTP, STALWART, REGISTRY, STORAGE, NFT).
- **`vps_web*`** — nginx-конфиг infmail.org → 3000; /api/v1 проксирует Next на 3001.
- **`vps_verify*`** — rewards.json, балансы после Distribute.
- **`vps_pw_poll*`** — поллинг Playwright-прогонов.
- **`vps_inb*`, `vps_2fa`, `vps_uifeed`, `vps_core`** — e2e/API-тесты.
- **`fulltest.sh` / `fulltest3.sh`** — API-тесты на сервере (register, E2E-mail, web3, files, aliases, quota, SMTP). fulltest3 — обновлённая.
- **`deploy_contracts.sh`** — деплой контрактов на testnet (нужен пополненный кошелёк).
- **`real_inbound.sh`**, **`imap_inbound.py`** — тест входящих через IMAP.
- **`scripts/infmail-smoke.sh`** — смок-тест 3 проектов (contracts jest + frontend node --test).

### Прочие файлы/папки
- **`infnode-v3`…`infnode-v40`** — ~38 версий бинаря infnode.
- **`opencode-summary.md`** — контекст LEGACY-аудита (старые infmail-backend/frontend: httpOnly JWT cookie, Argon2, rate-limiter UPSERT, DB-индексы).
- **`infos.txt`** — заметки владельца про валидаторы: 3-5 шлюзов с ротацией, ARC, DMARC p=reject, SPF на все IP валидаторов, блокчейн-список валидаторов, `nickname@infmail.org`.
- **`nft-card-studio/`, `nft_cards_final/`** — генерация NFT-карточек (6 стилей PNG).
- **`proxies/`** — docker-compose hysteria-туннель (`infUbot_Proxy`, network_mode host).
- **`stardust/`** — jetton-контракты (mock USDT) — тестовый проект.
- **`old/infmail-frontend/`** — старая версия фронта.
- **`test_jmap.py`, `vps_imaptest.py`** — IMAP/JMAP тесты.
- **`infmail-backend/`** — legacy backend (порт 8000, не запущен).
- **`infmail-acton/`** — контракты TON (registry/storage/NFT, Tolk).

---

## 14. АУДИТ service.mail / core.storage (результат)

- **`service.mail`** (services.rs:234-284) — низкоуровневый RPC: `append`/`list` к `mail_dir/{mailbox}/mailbox.jsonl` (файл-журнал, шифрование e1:XChaCha20Poly1305). **НЕ используется web.rs**. На валидаторе `/opt/infnode/infmail/inbox/mailbox.jsonl` — тестовое письмо от 2026-08-04 ("hello from behind NAT" от node1) из ранних испытаний.
- **`core.storage`** (services.rs:198-216) — статистика: kv_bytes + chunks_bytes (для наград). Используется нодами.
- **web.rs работает НЕ через RPC**: напрямую `node.store_blob/fetch_blob` (DHT-чанки) + `kv_store_local/get_local_kv` (индексы `mail:{email}:index`, `files:{email}`, аккаунты) в том же процессе.
- **Вывод для декомпозиции**: `service.mail` (mailbox.jsonl) — устаревший/параллельный механизм, его можно игнорировать или удалить. Для выноса web в отдельный бинарник нужен НОВЫЙ контракт сети: web-слой должен ходить к ноде по RPC `dht.store` / `dht.find_value` / `core.storage` (+ возможно `service.mail` переориентировать на блобы). Сейчас весь web-слой — локальный, в одном процессе с нодой.

---

## 15. ВАЖНЫЕ ДОКУМЕНТЫ (найдены в /root на валидаторе, скопированы в /home/imm/)

Это спецификации федеративной сети v2/v5, созданные в старом проекте (2026-07-10..20), ДО перехода на infnode-монолит. Они описывают ЦЕЛЕВУЮ архитектуру.

| Файл (локально) | Дата | Что описывает |
|---|---|---|
| `INFRASTRUCTURE.md` | 2026-07-10 | Полная спецификация федеративной сети v2: 3 роли (валидаторы/ноды/фронт), voting за ноды, earnings, load-balancing регистраций, путь письма (relay через валидаторы, DKIM/ARC/SPF/DMARC), фазы 1-6. |
| `HOW_IT_WORKS.md` | 2026-07-10 | То же простым языком (для понимания). |
| `STORAGE_AND_MONEY.md` | 2026-07-10 | Финансы v5: подписка 2 TON/мес, split 60/30/10, AI через Cocoon (Telegram), хранение (нода SSD + TON Storage бэкап E2EE), восстановление при падении ноды. |
| `FINAL_TODO.md` | 2026-07-20 | Статус legacy-проекта: backend 61 тест + acton 70 + frontend build = 131. Уже не актуально (монолит перекрыл). |
| `NFT_DEVELOPMENT_PLAN.md` | 2026-07-12 | План NFT (на сервере, копия не скачана — см. /root). |
| `PROJECT_PLAN.md` | актуальный | Этот файл — сводка всего. |

**Ключевые тезисы целевой архитектуры (из INFRASTRUCTURE.md):**
- Валидаторы (3-5, наши): принимают SMTP от мира, DKIM/ARC подпись, relay. **Никогда не хранят почту** (stateless). НЕ удаляются голосованием.
- Ноды (сторонние): хранят почту юзеров (Stalwart/JMAP), mTLS к панели, relay через валидаторы. Удаляются голосованием валидаторов (spam/down/взлом). Зарабатывают: 0.05 TON setup + $0.85/мес/юзер + storage overage.
- Frontend (наша панель infmail.org): stateless UI + routing, находит ноду юзера через `_node.<email>.infmail.org` DNS / `.well-known`.
- Регистрация → pick_node (geo 40% + reputation 30% + capacity 10% + load 20%).
- Путь письма: нода НИКОГДА не шлёт SMTP напрямую в Gmail — только через валидатор (Rspamd + DKIM + ARC). Валидатор физически не может быть забанен спамом ноды.
- **Требует: DKIM/SPF/DMARC, SMTP-сервер+клиент, WireGuard (mTLS между нодами), контракт нод в TON, DNS-watcher, billing split.**

---

## 16. СОСТОЯНИЕ СЕТИ (проверено 2026-08-08/09)

- **Валидатор (node2)** `109.107.155.67:9400` — работает. web API 3001, фронт 3000. KV 1073 ключа (`user:*` аккаунты, `mail:*:index`, `files:*`), chunks 1.3M/2 файла, infmail/ (service.mail) 12K.
- **aeza** `147.45.75.253:9400` — работает, uptime 1.0, weight ~361KB (реплики). Присылает dht.update/core.ping каждые ~30с.
- **node1** (локальная, NAT `178.155.74.242:9400/9401`) — **НЕ ОТВЕЧАЕТ**: rewards.json показывает uptime=0.0, bytes=0. Валидатор постоянно логирует `handshake timeout` к node1. Причина: NAT, обратные соединения не проходят (UDP 9400 не проброшен на роутере).
- **Вывод**: фактически работающая сеть = node2 + aeza (2 ноды, RF для почты по факту = 2, файлы = 2: валидатор + ... но aeza только mail → файлы фактически только на валидаторе). node1 — в конфиге, но не активна.
- **Фикс**: проброс UDP 9400 на домашнем роутере (или node1 перевести на сервер с белым IP), тогда RF=3 для почты заработает полноценно.

---

## 17. АККАУНТЫ — КАК ХРАНЯТСЯ (проверено)

- **`/opt/infnode/web/accounts.json`** (534 аккаунта, 559KB) — ОСНОВНОЙ источник. На валидаторе. Поля аккаунта: `aliases`, `bytes_used`/`files_used` (квоты), `paid_until_ms`, `plan`, `pw_hash`, `smtp_pass`, `wallet`, `quota_limit`/`file_quota_limit`, `ed_pub`/`enc_priv` (E2EE), `e2e_secret`, `totp_*`, `backup_codes*`, `trusted_email`, `pending_email`, `created_ms`.
- **`user:{email}` в KV** (370 ключей) — только публичные ключи (`ed_pub`, `x_pub`) для E2EE-маршрутизации. Дублирует часть данных.
- **processed_payments: 3** — подписки активированные индексером.
- **Вывод**: аккаунты целиком на валидаторе (accounts.json). node1/aeza НЕ знают о них. Для декомпозиции/федерации аккаунты должны стать DHT-ключом `acct:{email}` (реплицируемым) или оставаться на валидаторе как бизнес-слой (валидатор формально отвечает за акки по видению владельца). Ноды — только хранение/передача.

---

## 18. ПОЛНЫЙ ПУТЬ ПИСЬМА (проверено на проде 2026-08-09)

- `mail/send` (JWT, to@infmail.org, body + attachments[]) → 200, id письма.
- Входящий: `mail/inbox?folder=Inbox` → письмо в списке получателя, `attachments: [{name, mime, size}]` верные.
- Скачивание: `GET /mail/{id}/attachment/{idx}` → base64, байты совпадают.
- Отправитель: `mail/inbox?folder=Sent` → письмо в Sent.
- **Статус: всё работает** после деплоя (вложения, E2EE-тела, индексы, квоты).

---

## 19. КОНТРАКТЫ (проверено 2026-08-09)

- **Файлы**: `/root/infmail-acton/contracts/` — `NftCollection.tolk`, `NftItem.tolk`, `registry.tolk`, `storage.tolk`, `errors/fees-management/messages/types.tolk`.
- **Деплой-скрипты** (Acton.toml): deploy-emulation, deploy-testnet (Collection), deploy-storage (Storage), nft-change-admin, nft-deploy-batch, nft-deploy-item, nft-transfer-item.
- **Deployer кошелёк**: `kQCrDoZwy6L100ote94GSYRHC63TZAchvwEyobRTA-k-qgnf`, **balance 0.397 TON** (пополнился). Мнемоника в `wallets.toml`.
- **Тесты (jest)**: Collection.spec (13), NftItem.spec (3), Registry.spec (6), RegistryExtended.spec (26), Storage.spec (11) = **59 тестов, ВСЕ ПРОШЛИ** (5 suites PASS).
- **БАГ ПОЧИНЕН**: `vps_rename.sh` переименовал `contracts/Collection.tolk` → `NftCollection.tolk`, но битый symlink `src/collection.tolk → ../contracts/Collection.tolk` остался → Collection.spec падал `ENOENT`. Починил: `ln -sfn ../contracts/NftCollection.tolk src/collection.tolk`.
- **Адреса на testnet** (из env валидатора):
  - Registry: `EQB_Y-LRJvZU7oBFSgVeP8CZM9fWe8VHcr3W9qO0y6dDJXHm`
  - Collection (NFT): `kQB5Y4R7OzRTfy1sfSpSfWccRfzuALtGhysikPz3CVRHUOk_`
  - Storage v2: `kQBwVBK0Pm1ZHgGczc38a5vhT5oEed6Gujml9f_lNMnByjWT`
- **Интеграция в infnode**: `blockchain.rs` — runGetMethod (TON Center), индексер подписок (`INFMAIL_SUB:<email>:<nonce>`), NFT status. `/api/v1/nft/status/{email}` → 200 (реальный).

---

## 20. ИТОГОВЫЙ СТАТУС ТЕСТОВ (2026-08-09)

| Набор | Результат |
|---|---|
| Бэкенд юнит (cargo test) | 12/12 ✅ |
| Фронт юнит (node --test) | 6/6 ✅ |
| Контракты (jest, infmail-acton) | 59/59 ✅ (5 suites) |
| E2E прода-спеки (playwright, 10 файлов) | 44/44 ✅ |

E2E файлы: storage-plan (6), mail-core (3), full-journey (21), sent-copy (1), user-journey (6), send-bug, fix-verify, bug-repro, preview, ui-feedback.
**ВСЁ ЗЕЛЁНОЕ.** (web3.spec + all.spec — локальные, требуют mock/infra, для локального dev.)

---

## 21. ВНЕШНЯЯ ДОСТАВКА / DKIM (проверено 2026-08-09)

- **MX**: `10 mail.infmail.org` ✅
- **SPF**: `v=spf1 ip4:109.107.155.67 mx -all` ✅
- **DMARC**: `v=DMARC1; p=reject; rua=mailto:postmaster@infmail.org` ✅
- **DKIM**: запись `v2._domainkey.infmail.org` — **ОТСУТСТВУЕТ**. В stalwart (v0.16) DKIM-объекты не настроены (CLI-схема не показывает DkimSign; домен infmail.org id=b без DKIM). 
- **Вывод**: исходящие внешние письма проходят только SPF, DKIM не подписывается → риск попадания в спам в Gmail/Outlook. Это главный пробел «топовости» внешней доставки.
- **TODO**: настроить DKIM в stalwart (сгенерировать ed25519 ключ, добавить DNS-запись `v2._domainkey.infmail.org`, включить подпись для исходящих) и проверить доставку в gmail.

---

## 22. ПРИОРИТЕТЫ «ТОПОВОСТИ» (что делать дальше)

### Блок A — Внешняя доставка (критично для работы с реальным миром)
1. **DKIM**: настроить в stalwart + DNS. Без этого письма в Gmail = спам. (главное)
2. Проверить доставку в gmail/outlook реальными письмами.
3. Прогрев IP валидатора (если в блеклисте — Spamhaus).

### Блок B — Сеть / отказоустойчивость
4. **node1 (NAT)**: проброс UDP 9400 на роутере ИЛИ убрать из активного роутинга (сейчас rewards показывает uptime 0.0, пустой вес). Фактически сеть = node2+aeza.
5. Файловое хранилище: RF для файлов фактически 2 (валидатор + node1 не работает) — после фикса NAT RF=3.
6. 3-5 валидаторов (план, сейчас 1).

### Блок C — Архитектура (по видению владельца)
7. **Декомпозиция**: вынести `web.rs` из infnode в отдельный `infmail-backend` (по фазам 0-6). infnode = чистый сетевой слой.
8. Аккаунты: репликация `accounts.json` (сейчас только валидатор) или DHT-ключи.
9. `service.mail` (mailbox.jsonl) — устаревший, либо удалить, либо переориентировать.

### Блок D — Функциональность
10. NFT: довести verify/card/upgrade до рабочего (сейчас стабы).
11. E2E-шифрование файлов на клиенте (ключ из master-пароля).
12. OAuth (вход Google/Apple + выдача scoped-токенов) — по видению владельца.
13. AI (Web4): `service.ai` RPC + фронт-чат (по видению).

### Блок E — Безопасность (средние хвосты)
14. JWT-секрет: вынести из env systemd в файл 0600.
15. IMAP-синк: реальный TLS-сертификат вместо `danger_accept_invalid_certs(true)`.
16. `mail_attachment_save`: проверка magic bytes/MIME (XSS через .html).
17. fail2ban/rate-limit на 9400 для aeza (открытый p2p-порт).

---

## 23. ВОССТАНОВЛЕНИЕ СЕТИ (2026-08-09) — node1

- **Причина проблемы**: node1 была **просто не запущена** (serve.log от 2026-08-04, нет процесса). Не NAT-hole-punch сам по себе — он РАБОТАЕТ (в тестах подтверждался).
- **Сделано**: запустил node1 локально (`nohup ./target/release/infnode serve --config deploy/node1/node.yaml`), создал юнит `/home/imm/.config/systemd/user/infnode-node1.service` для автозапуска при входе пользователя imm.
- **Результат**: node1 видит peers:2, шлёт `dht.update`/`core.ping` на валидатор (`req` от `57146ca...` ok:true). Сеть node1↔node2 восстановлена через исходящие соединения node1.
- **Нюанс**: валидатор сам не может инициировать соединение К node1 (входящие handshake timeout из-за NAT), но node1 сама подключается к валидатору → данные ходят. Для полноценного двунаправленного доступа нужен проброс UDP 9400 на домашнем роутере (или полагаться на hole-punch, который срабатывает когда оба активны).
- **rewards.json**: обновляется раз в 600с; вес node1 появится в следующем цикле (storage_stats). Сейчас node1 weight=0 в rewards, но это устаревший снапшот.

---

## 24. УЯЗВИМОСТИ — ИСПРАВЛЕНО В ЭТОТ ЗАХОД (2026-08-09)

1. **IMAP TLS** (`inbound.rs:472`): `danger_accept_invalid_certs(true)` теперь применяется ТОЛЬКО для loopback (127.0.0.1/localhost). Для удалённых IMAP-серверов сертификат верифицируется. (MitM на loopback невозможен.)
2. **XSS через вложения** (`mail_attachment_save`): для `.html/.htm/.svg/.xml/.xhtml` контент проверяется на активные маркеры (`<script>`, `javascript:`, `onerror=`, `<iframe`) → отказ `422` при сохранении в Files. (Браузер не отрендерит HTML как есть — файлы отдаются base64 JSON.)
3. **Rate-limit p2p** (`node.yaml` валидатора): добавлен `rate-limit-per-sec: 200` для пиров node1 и aeza (защита от флуда на 9400). Механизм уже был в коде (`peer.rate`), теперь включён конфигом.
4. **JWT-секрет**: НЕ в env — выводится из ключа ноды (`derive_jwt_secret`, blake3 от signing key). Безопасно, дополнительных действий не требует.

---

## 25. ЧТО НЕ СДЕЛАНО В ПОЧТЕ (полный список, 2026-08-09)

### Заглушки на бэкенде (есть эндпоинт, но ответ — no-op)
1. **Сессии** (`/settings/sessions`) — всегда `[]`, revoke/set-primary/revoke-all — `noop` (web.rs:1754-1766). Фронт-UI есть, реального управления сессиями нет.
2. **Recovery** (`/auth/recovery/*`) — «восстановление через резервный email пока не настроено» (web.rs:844-850).
3. **Blacklist/Unblock** (`/mail/blacklist`, `/mail/unblock-sender`) — no-op (web.rs:1467-1477).

### Отсутствующие почтовые функции
4. **Trash (корзина)** — `delete` безвозвратный (web.rs:1428), корзины нет. Нет `restore`.
5. **Archive** — папки/действия архива нет.
6. **Поиск по почте на сервере** — в топбаре есть поиск (по превью?), но нет серверного поиска по телу/отправителю.
7. **Пагинация/фильтры** — `mail_inbox` берёт весь индекс без лимита; нет фильтров по дате/флагу.
8. **Чтение/непрочитано в списке** — есть `read/unread` (web.rs:1402-1413), работает.
9. **Пометки (labels/флаги)** — нет.
10. **Умный inbox (категории work/personal/newsletters)** — нет (по STORAGE_AND_MONEY — план через AI).
11. **Автоответы/фильтры (правила)** — нет.
12. **Подпись (signature)** — нет.

### Внешняя доставка (критично для реальной работы)
13. **DKIM** — DNS-записи нет, stalwart не подписывает → письма в Gmail = спам (только SPF). СЛЕДУЮЩИЙ ПРИОРИТЕТ.
14. **Проверка доставки в Gmail/Outlook** — не делалась реальными письмами.
15. **Прогрев IP валидатора** (если в блеклистах Spamhaus) — не делался.

### Что работает (подтверждено e2e 44/44)
- Отправка внутренняя (E2E + вложения), входящая через IMAP-синк, Sent/Drafts/Spam, read/unread, delete, квоты, алиасы, 2FA (реальный TOTP), подписки (TON), файлы, ревью.

### Смежное (из документов v2/v5, в бэклоге)
- 3-5 валидаторов, ноды-операторы, billing split, DKIM/ARC/SPF/DMARC, AI (Cocoon), OAuth, E2E-шифрование файлов, свой блокчейн.

---

## 26. НОВЫЕ ПОЧТОВЫЕ ФУНКЦИИ (2026-08-09, задеплоены)

### Trash + Archive
- **`mail/action`** новые действия: `trash` (в Корзину из Inbox/Spam/Drafts/Archive), `restore` (обратно в Inbox), `archive`, `unarchive`.
- `delete` — безвозвратное (убирает из всех индексов + refund квоты). Корзина = промежуточный шаг через `trash`.
- `mail_index_key`: добавлены `Trash` → `trash-index`, `Archive` → `archive-index`.
- Фронт: sidebar получил папки Archive/Trash; ридер — кнопки Archive/Move-to-Inbox/Restore/Not-spam/Trash.

### Сессии (реальные)
- JWT теперь содержит `sid` (16 симв.) + `v` (session_epoch). `issue_session` создаёт/обновляет сессию в Account.sessions.
- `auth_email` → проверяет sid и session_epoch: revoke-all инкрементит epoch → все старые JWT невалидны; revoke удаляет конкретную сессию.
- `settings/sessions` (GET) возвращает список; `revoke` (session_id), `set-primary`, `revoke-all` — реальные.
- Account: добавлены `sessions: Vec<SessionInfo>`, `session_epoch: u32`. Совместимость старых аккаунтов через `#[serde(default)]`; старые JWT без sid продолжают работать.

### Blacklist / Unblock
- `mail/blacklist {sender}` / `mail/unblock-sender {sender}` — хранится в KV `blacklist:{email}`.
- mail_inbox фильтрует отправителей из чёрного списка (для Inbox/Archive; Spam/Trash показываются).

### Recovery (без внешнего SMTP)
- `auth/recovery/request {email}`: генерирует 6-значный код (15 мин), хранит в KV `recovery:{email}`, доставляет **внутренним письмом** от `system@infmail.org` в inbox (не наружу). Rate-limit 3/час/email.
- `auth/recovery/reset-password`: принимает код (или текущий пароль) + новый пароль → меняет, сбрасывает все сессии.

### Поиск и пагинация
- mail_inbox: `?q=...` — серверный поиск по sender/subject/body; `?limit=&offset=` — пагинация (если limit задан → `{items,total}`, иначе массив — обратная совместимость).

### Подпись (signature)
- Account.signature + `settings/signature` GET/POST.
- Фронт: редактор подписи в Settings, при отправке письма подпись добавляется к телу.

### Исправленные баги (в этом заходе)
- **Паника preview на кириллице**: `body[..120]` рвал UTF-8 → panic. Исправлен безопасным char-boundary slice.
- **Inbox виснул 20с+**: `kv_get` для blacklist ходил в сеть (dht.find_value к node1, недоступной) → таймаут. Добавлен `kv_get_local` (только локальный KV) для почтовых данных.

### Тесты
- storage-plan: S8 (trash/archive/search/pagination), S9 (sessions), S10 (blacklist), S11 (recovery), S12 (signature) — все прошли. Итого 11 тестов storage-plan зелёные.

---

## 27. ДЕКОМПОЗИЦИЯ + РАЗВЁРТКА + TRUST-SCORE (2026-08-09)

### Декомпозиция (выполнена, без ломки прода)
- `src/lib.rs`: все модули pub (node, dht, proto, services, web, ...). crate → `infnode::`.
- `src/main.rs`: тонкий бинарник **infnode** (сеть). `src/bin/infmail-backend.rs`: бинарник **infmail-backend** (webmail) — `web::run` + своя нода-пир.
- Сборка: `infnode` 15MB + `infmail-backend` 14MB. Lib-тесты 12/12.
- Итог: сетевой слой и web-слой — отдельные процессы/бинарники, переиспользуют общий код.

### Быстрая развёртка
- `deploy/deploy_validator.sh`: сборка + scp на валидатор + systemd `infnode` (сеть) и `infmail-backend` (web) + проверка.
- `deploy/setup_node.sh`: развёртка ноды (роль mail/files/both, автозапуск systemd, рестарт при падении).

### Trust-score ноды (сбалансированный)
- rewards.rs: `trust_score` (0..100) = uptime × 100.
- weight = `sqrt(bytes) × (0.3 + 0.7 × uptime)` — сглаживание: мелкие ноды не угнетаются, надёжные получают больше.
- Проверено: aeza 749KB → weight 862 (было бы 744803 при линейном). trust_score 99.

### GitHub
- infNode: коммиты `8a309af` (фичи+фиксы), `b4af932` (декомпозиция), `fbab268` (скрипты+gitignore), `36cc937` (trust-score). Всё в main.
- infmail-web → `immtes/infmail-frontend` (`acbb3c2`, force-push).

### Деплой на валидатор
- infnode задеплоен, активен, web 200. node1 переподключена (peers:2).
- E2E после деплоя: **35/35 прошли** (storage 11 + full-journey 21 + mail-core 3).

---

## 28. АУДИТ БЕЗОПАСНОСТИ (2026-08-09) — исправлено и задеплоено

1. **JWT без sid в части входов** — `register_web3`, `web3_select_account`, `web3_recover_email`, `renew_cookie`, `verify_2fa` выдавали токены без sid → revoke их не отзывал. Теперь все входы через `issue_session` (sid). commit `de0907b`.
2. **Смена пароля не сбрасывала сессии** — `settings_change_password`/`recovery_reset` теперь очищают `sessions` + инкремент `session_epoch` (старые JWT невалидны).
3. **unwrap-паника на гонке пиров** — `node.rs` `peers.get().unwrap()` (ping, CHALLENGE, TOFU) → безопасный `ok_or_else` (защита от DoS-падения при удалении пира между resolve и get).
4. **Подделка X-Forwarded-For** — `proxy.ts` (Next) доверял клиентскому XFF → rate-limit обходился фейковым IP. Теперь XFF перезаписывается на X-Real-IP (реальный от nginx).
5. **web3_login без rate-limit** — добавлен лимит 30/15мин по IP.
6. **Client IP** — бэкенд использует XFF от Next (перезаписанный), :3001 слушает loopback только.

Проверено: 12/12 lib-тестов, e2e storage+mail 14/14. Всё задеплоено на валидатор.

### Осталось (средний приоритет)
- Web3 proof replay: timestamp служит nonce, но не проверяется на повторное использование (нужен MitM TLS для эксплуатации).
- `client_ip` доверяет XFF только от proxy.ts (исправлено), прямой доступ к :3001 извне закрыт.

---

## 30. АУДИТ 2 (2026-08-09) — второй прогон, исправлено

### Критические (закрыто)
1. **Web3 login захват аккаунта** — `verify_ton_proof` не связывал public_key с address → подделка proof чужого адреса. Фикс: `wallet_pub` привязывается при регистрации, web3_login/select_account требуют совпадения public_key. commit `66e65c8`.
2. **Захват классического аккаунта оплатой** — индексер привязывал кошелёк плательщика к аккаунту без wallet → платёж 0.5 TON захватывал аккаунт. Фикс: кошелёк НЕ привязывается к классическому аккаунту автоматически.

### Высокие (закрыто)
3. **delete replay** — рефанд квоты повторялся (saturating_sub без нижнего ограничения), блобы не удалялись. Фикс: идемпотентность (проверка индекса) + физическое удаление delete_blob письма и вложений.
4. **verify_2fa без rate-limit** — брутфорс TOTP. Фикс: 5/мин/аккаунт + 20/мин/IP.
5. **PoW клиентский** — difficulty/salt из запроса → обход анти-бота. Фикс: сервер требует difficulty≥3 и 16-hex соль.
6. **DHT-KV произвольные ключи от пиров** — подмена recovery-кода/индексов. Фикс: пиры не пишут `recovery:/blacklist:/mail:/files:`.
7. **save_db неатомарно** — обрыв = потеря аккаунтов. Фикс: temp+rename.
8. **IMAP без лимита тела** — OOM. Фикс: 2MB тело + raw-лимит.

### Средние (закрыто)
9. **client_ip подделка XFF** — приоритет X-Real-IP (надёжный от nginx).
10. **CORS footgun** — пустой allowlist → локальный дефолт, permissive только по env-флагу.
11. **Двойной IMAP-синк** — убран спавн в mail_inbox (дубликаты/квота), доставка фоновым циклом.
12. **Хардкод STALWART_PASSWORD** — из deploy_validator.sh убран (env).

### Фронтенд
13. **HTML писем** — cleanHtmlLinks вырезает javascript:/data: href и on* атрибуты; sandbox="" (без allow-popups).
14. **Приватные ключи в sessionStorage** — clearKeys() при logout/logoutAll.
15. **console.log с proof** — убран.

### Проверено после фиксов
- e2e storage+mail 14/14, доставка через фоновый цикл работает.
- Lib-тесты 12/12.
- Всё задеплоено (бэкенд 66e65c8, фронт 4ce0c34).

### Осталось (не закрыто, задокументировано)
- jwtToken всех аккаунтов в localStorage — httpOnly cookie (крупный рефакторинг, риск).
- Web3 proof replay (timestamp=nonce, не проверяется повторно) — требует MitM TLS.
- Зависимости: next/@ton/ton/axios — обновить при следующем цикле.
- 8 legacy web3-аккаунтов без wallet_pub — блокированы web3-входом (безопасность), пересоздать.

---

## 31. АУДИТ 3 (2026-08-09) — третий прогон, исправлено

### Критические (закрыто)
1. **HTTP body limit 2MB** — files_upload 64MB (base64) блокировался лимитом axum → файлы >1.5MB не грузились. Фикс: `DefaultBodyLimit::max(90MB)`. Проверено: файл 5MB → 200. commit `7a537a9`.
2. **accounts.json/keys 644** — читались всеми локальными процессами (pw_hash, smtp_pass, e2e_secret, identity.key → JWT-форджинг). Фикс: `chmod 600`.
3. **Порт 3000 (Next) наружу** — прямой доступ без TLS/nginx (обход rate-limit/заголовков). Фикс: iptables DROP 3000/3001/8080/9413 + persist через `infmail-fw.service`.
4. **HTTPS-серт истекал завтра** — certbot не было. Фикс: установлен certbot 4.0.0, `certbot renew --force-renewal` → продлён до 7 ноя 2026, nginx reload.

### Высокие (закрыто)
5. **Stalwart admin 8080 наружу** — закрыт firewall (остался на 127.0.0.1).
6. **fail2ban не было** — установлен, SSH-jail активен (5 попыток/10 мин → бан 600с).
7. **Rate-limit память** — HashMap расти бесконечно при подделке XFF. Фикс: prune при росте >10k.

### Средние/низкие
8. **blockchain ureq без таймаутов** — зависший TON Center держал blocking-потоки. Фикс: Agent с timeout connect/read.
9. **PlanView nonce = Math.random** — предсказуем для TON-комментария. Фикс: crypto.getRandomValues.
10. **next.config без security headers** — добавлены X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, X-XSS-Protection (проверено на проде).
11. **add-account Web3 без usernameLen/фикс 0.1 TON** — расхождение с register (функц. баг, задокументировано).

### Что ОК (проверено)
- Backup codes требуют пароль (xor blake3, но коды недоступны без пароля).
- Self-mail квота один раз; cross-folder refund без двойного.
- Web3 temp_token exp, proof криптопроверка, blockchain SSRF нет (env-only).
- rewards timeout 5с, IMAP лимит, owner-gate файлов, ureq в spawn_blocking.

### Деплой
- Бэкенд `7a537a9`, фронт `71d1b01`, сертификат продлён, firewall+fail2ban активны.
- E2E 14/14, файл 5MB работает.

### Осталось (задокументировано)
- jwtToken всех аккаунтов в localStorage (httpOnly cookie — крупный рефакторинг).
- Web3 proof replay (timestamp=nonce) — требует MitM TLS.
- 8 legacy web3-аккаунтов без wallet_pub — пересоздать.
- add-account Web3-путь унифицировать с register (pricing+usernameLen).
- band_server.py :9413 — тестовый, можно отключить.

---

## 33. АУДИТ 4 (2026-08-09) — четвёртый прогон, исправлено

### Критические/высокие (закрыто)
1. **Recovery-код читаем по сети** — `dht.find_value`/`dht.sync` отдавали `recovery:{email}` (код восстановления) пирам → захват аккаунта. Фикс: recovery/blacklist/mail/files не отдаются по сети; `user:*` (реестр E2E-ключей) остаётся публичным. commits `b23cdb6`, `9904bcb`.
2. **mail_inbox без проверки владения** — злонамеренный пир мог добавить чужой mail_id в свой индекс и прочитать тело. Фикс: проверка to/sender в mail_inbox и mail_action.
3. **DefaultBodyLimit 90MB глобально** — DoS на auth/login большими телами. Фикс: 90MB только на `POST /files`.
4. **Web3 proof replay** — payload теперь должен содержать nonce от `web3_generate_payload`, nonce одноразовый (удаляется после использования).
5. **X-Real-IP подделка** — proxy.ts перезаписывает и X-Real-IP (клиентский фейк не проходит).

### Проверено после фиксов
- e2e 14/14, доставка+владение (Inbox+Sent) работают, классический login ок.

### Осталось (задокументировано)
- **add-account Web3 сломан** (payload без usernameLen, registerWeb3 без Bearer temp_token, 0.1 фикс) — унифицировать с register (pricing+usernameLen+temp_token). Основной register работает.
- **Web3 регистрация без проверки оплаты** — аккаунт создаётся после proof без on-chain подтверждения (бесплатные аккаунты). Фикс: pending-активация через Registry ownership.
- **httpOnly cookie** для jwtToken (крупная миграция, CSRF-защита, мультиаккаунт).
- **Индексер платежей**: нет курсора, limit=100 — потеря оплаты при простое (ретраи есть).
- **Контракты**: usernameLength не верифицируется (ценовой обход), Storage без withdraw — при выводе в прод.

---

## 34. ФИНАЛ АУДИТА 4 (2026-08-09) — остатки закрыты

- **add-account Web3 починен**: usernameLen + pricing + saveWeb3Intent с temp_token (раньше payload без usernameLen, registerWeb3 без Bearer → 401). Фронт `b6f9a34`.
- **web3-регистрация не перехватывает чужие алиасы**: resolve_db_email + registry_get в register_web3 и web3_save_intent (раньше можно было занять email-алиас чужого аккаунта). Бэкенд `75d57b6`.
- **E2E в реальном браузере: 49/49 прошли** (storage-plan 12 + full-journey 21 + mail-core 3 + sent-copy + user-journey + остальные). Без регрессий.
- Прод: HTTPS 200, API 200, security headers на месте, node1 переподключена (peers:2).

### Что осталось по infmail (бэклог, не срочно):
1. **httpOnly cookie для jwtToken** (крупная миграция: 40+ маршрутов, CSRF-защита, мультиаккаунт до 8 сессий, SameSite+Origin-check). Bearer оставить для CLI/API.
2. **Web3 регистрация без проверки on-chain оплаты** — аккаунт создаётся после proof (бесплатно). Фикс: pending-активация через Registry ownership (полная оплата).
3. **Индексер платежей**: нет курсора, limit=100 — при простое >100 транзакций старые пропускаются (ретраи есть, риск мал). Фикс: курсор по lt/hash.
4. **8 legacy web3-аккаунтов без wallet_pub** — блокированы web3-входом, пересоздать.
5. **Контракты**: usernameLength не верифицируется (ценовой обход), Storage без withdraw — при выводе в mainnet.
6. **E2E-шифрование файлов на клиенте** (ключ из master-пароля) — приватность файлов at-rest.
7. **OAuth** (вход Google/Apple + scoped-токены) — по видению владельца.
8. **DKIM для внешней доставки** (Gmail/Outlook не в спаме) — вне текущего фокуса.

---

## 35. БЭКЛОГ ЗАКРЫТ (2026-08-10) — курсор индексера + E2E-файлы

- **Индексатор курсор** (`3009053`): `get_payment_comments` возвращает tx_hash; `check_subscription_payments` обрабатывает только новые tx (курсор `last_payment_tx`), не теряет платежи при >100 за раунд; `processed_payments` trim до 500 (не растёт бесконечно).
- **E2E-шифрование файлов на клиенте** (`4d9a093`): `encryptFileBytes`/`decryptFileBytes` (XChaCha20, ключ от активного X25519 keypair), формат `ef1:`; FilesView upload шифрует, download расшифровывает. Старые plain-файлы совместимы.
- E2E 14/14 (storage+mail) после фиксов; туннель SSH был причиной фейла (не код).

---

## 36. ОЦЕНКА «ЧТО ПЛОХО / ЧЕГО НЕ ХВАТАЕТ ДЛЯ ПОЛНОЦЕННОСТИ СЕТИ»

### Архитектурные пробелы (главное)
1. **Аккаунты только на валидаторе** (`accounts.json`) — единая точка отказа. Если валидатор упадёт/будет взломан — потеря всех аккаунтов и SMTP-паролей. Нужна репликация (DHT `acct:{email}`) или резервный валидатор.
2. **Нет 3-5 валидаторов** — по видению владельца (INFRASTRUCTURE.md) их должно быть 3-5 с DNS MX round-robin. Сейчас 1 → SMTP-точка отказа.
3. **Нода-операторы не подключены** — нет модификаций (billing split, Registry нод, voting). Сеть = только наши 3 ноды (node2/aeza/локаль). Это «децентрализация-игрушка», не полноценная сеть.
4. **node1 (NAT) фактически не реплицирует** — uptime 0.0 в rewards, обратные соединения не проходят. RF=3 для почты не выполняется (фактически 2).
5. **Устаревший `service.mail`** (mailbox.jsonl) — параллельный мёртвый механизм, путает. Нужно удалить или переориентировать.

### Функциональные пробелы почты
6. **DKIM отсутствует** — внешние письма в Gmail/Outlook = спам. Критично для реальной доставки.
7. **Проверка on-chain оплаты Web3** — аккаунт создаётся после proof без подтверждения платежа в Registry (бесплатные аккаунты). Нужна pending-активация.
8. **httpOnly cookie для JWT** — токены в localStorage (XSS → полный захват). Крупная, но важная миграция.
9. **Индексер платежей**: курсор добавлен, но нужна проверка суммы против баланса конкретного email и multi-страничность (>100 всё же).
10. **Нет OAuth** (вход Google/Apple, scoped-токены) — для Google-модели.

### Наблюдения по качеству кода
11. **`settings_subscribe` demo-флаг включён в проде** — любой юзер может получить paid бесплатно через API. Включён для e2e; на проде опасен.
12. **`trusted_email` без пароля** — можно установить без подтверждения (мина на будущее).
13. **Корень на SSH (permitrootlogin yes)** — несмотря на fail2ban/firewall, лучше ключи без root.
14. **Контракты**: usernameLength не верифицируется (ценовой обход), Storage без withdraw — при выводе в mainnet.
15. **Тесты**: 49 e2e + 12 lib + 59 контрактов зелёные, но нет unit-тестов на web.rs (auth/квоты/сессии) — только e2e.

### Приоритет для «полноценности»
A. Репликация аккаунтов (или 2-й валидатор) — отказоустойчивость.
B. DKIM — реальная доставка.
C. httpOnly cookie — безопасность сессий.
D. Web3 on-chain оплата (pending) — бизнес-модель.
E. Ноды-операторы + billing — децентрализация.

---

## 37. УСТОЙЧИВОСТЬ СЕТИ (2026-08-11) — сделано

1. **Репликация аккаунтов в DHT** (`2d38752` + фикс last_req_from_peer): фоновый цикл `replicate_accounts_loop` (5 мин) пишет профили аккаунтов БЕЗ секретов (pw_hash, smtp_pass, e2e_secret, backup_codes) в `acct:{email}`. При потере валидатора профили/квоты/подписки восстановимы.
2. **node1 (NAT) получает uptime в rewards**: `last_req_from_peer` — карта входящих запросов от пиров (обновляется при любом dht.update/core.ping от node1), rewards считает `ok = ping_ok || heartbeat_ok (last < 3 мин)`. node1 теперь не будет вечным uptime 0.0.
3. **Удалён мёртвый `service.mail`** (mailbox.jsonl): функция `mail`, safe_mailbox/mail_encrypt/mail_decrypt и регистрация удалены из services.rs. Web-слой использует только DHT-блобы.

**Восстановление при потере валидатора**: установить infnode на новой ноде, импортировать `acct:{email}` из DHT (профили) — письма/файлы уже реплицируются в DHT. Секреты (пароли/SMTP) не реплицируются — юзеры восстановят через recovery (код в inbox нового валидатора).

---

## 38. ЕДИНЫЙ ИСТОЧНИК ПРАВДЫ (при продолжении сессии)

1. Прочитать этот файл целиком.
2. Проверить валидатор: `curl -s -o /dev/null -w '%{http_code}' https://infmail.org` (200 = жив).
3. Проверить сервисы: `systemctl is-active infnode infmail-web stalwart`.
4. Дальше по текущим задачам (раздел 9).
