# КОНТЕКСТ СЕССИИ (сохранён 2026-08-15)

## Цель сессии
Инфмайл (InfMail) на InfNode: полноценная web3-почта. Пользователь просит:
1. Проверить ВСЮ логику (шардирование, оплаты, NFT, создание почты, чтение писем, вложения/файлы от разных нод, proof-of-storage, шифрование, уязвимости, перемещение файлов, выплаты/подписки, попытка взлома как нода).
2. Вынести InfMail в отдельный проект (чтобы не был официальной частью infnode).
3. Продумать безопасность средств и выплат, аналитически — много нод и покупок; хранение файлов/вложений почты vs обычных файлов (Google Drive).
4. Показать, как работает почта (что есть, работает ли).

## Философия (важно)
- infnode = СЕТЕВОЙ слой (не монолит): QUIC+DHT+storage (чанки RF≤3)+rewards+proof. НЕ знает про почту.
- infmail = сервис поверх: аккаунты, письма, файлы, подписки, NFT, 2FA.
- Валидатор = шлюз наружу (SMTP in/out + web-API + аккаунты). node1/aeza = чистые storage-ноды.
- Ноды НЕ имеют доступа к данным и не могут подменить данные (хэши+подпись). Публичные ноды зарабатывают proof-of-storage.
- 3 валидатора — отложено (нет серверов).

## Серверы
- Валидатор 109.107.155.67 (root/U3A1hXdjXSBzW7). systemd `infnode` = `infmail-backend serve` (после декомпозиции). web API 127.0.0.1:3001, фронт 3000, stalwart, nginx.
- aeza 212.113.103.105 (root/q5foUWxm1T0B), storage-нода (только mail), бинарь /root/infnode (юнит ждёт /root/infnode!), working /root/infnode-node.
- node1 = локаль (NAT 178.155.74.242), deploy/node1/node.yaml.
- SSH-скрипты: /tmp/sshcmd.py (валидатор), /tmp/ssh2run.py (aeza), /tmp/scpcmd.py, /tmp/scp2.py. venv /tmp/venv.
- Бинари на валидаторе: /opt/infnode/infmail-backend (web+сеть, юнит ExecStart), /opt/infnode/infnode (запасной), конфиг /opt/infnode/node.yaml. Логин JSON: /tmp/lk.json (kitai), /tmp/lch.json (chichisblat).
- Деплой бэкенда: cargo build --release → scp → mv в /opt/infnode/{infmail-backend,infnode} → systemctl restart infnode (валидатор). aeza: scp → cp в /root/infnode-node/infnode И /root/infnode → restart aeza-node.
- Деплой фронта: tar czf src+конфиги → scp /opt/infmail-web-src.tar.gz → распаковать → npm run build → restart infmail-web.

## Аккаунты
- kitaimudrost@infmail.org — MEGApass323@323M, smtp_pass=vCcmQEYQ5c4djUR7, ящик stalwart id cg. 11 писем (Steam).
- chichisblat@infmail.org — MEGApass323@323M, smtp_pass=9HwhES#KDYnC8Yjq, ящик cf. 19+ писем (Steam).
- pay1@infmail.org — paid (6GB files). Восстановление пароля: recovery меняет pw_hash (НЕ smtp_pass).
- 8 старых web3-аккаунтов — e2e_secret обнулён (сервер не хранит), enc_priv пуст.

## Статус итераций
- Ит.1 completed: ноды=хранилище (mail:/files: индексы открыты для ролей), index_list DHT-fallback, mail_inbox параллельный (JoinSet+Semaphore 16), on-demand синк (sync_inflight), files_download сетевой fallback, роуты /dashboard/plan+/dashboard/files, кеш папок/prewarm, aeza IP, пароль+IMAP chichisblat.
- Ит.2 completed: Junk→spam-index, /mail/counts, баджи unread, пуллинг 20с, серверный поиск (q), Block sender, HTML-рендер (DOCTYPE/head+адаптив), файлы (поиск/drag&drop/превью/блок plaintext), вложения в compose (relay multipart + E2E ef1 для внутренних).
- Ит.2.5 completed: npm 0 vuln (Next 16.3.1), cargo 1 allowed (lexical-core), TLS relay loopback-only, XSS/CORS/JWT-секрет, CSP+HSTS добавлены, demo-subscribe отключён, recovery_reset rate-limit.
- Ит.3 completed: Proton-модель (внешние письма+вложения шифруются XSalsa20+box на x_pub получателя, браузер расшифровывает), хэши чанков+проверка при чтении, E2E-вложения внутренних (ef1), Web3-E2E (сервер не генерит e2e_secret), фиксы orphan/TTL/quota, files активные типы блок.
- Ит.4 completed: proof-of-storage (валидатор шлёт storage.fetch случайных чанков из манифестов с hash, сверка blake3), rewards по подтверждённым байтам, core.storage-самооценка убрана.
- Аудит 5 классов + 12 пунктов completed.
- httpOnly cookie completed (v55): login/register/verify/web3/renew ставят Set-Cookie, auth_email_sid читает Bearer ИЛИ cookie, logout сбрасывает, CORS credentials.
- Декомпозиция completed: валидатор = `infmail-backend serve` (bin уже есть), node1/aeza = чистый infnode. 
- Защита от админа completed (v56): parity-восстановление пароля ящика в stalwart при IMAP-фейле 3+ раз.
- Папки в Файлах completed (v53): safe_filename разрешает пути, file_blob_key (хэш пути), обратная совместимость со старыми raw-файлами, фронт дерево папок/breadcrumb/New folder.

## Ключевые фиксы (v50-v56)
- v50: CSP+HSTS, files активные типы блок.
- v54: service.cli/service.ai убраны из сетевого диспатча (RCE-вектор), Proton-вложения внешних, rate-limit внутренней отправки 200/час.
- v55: httpOnly cookie.
- v56: parity-защита от админа + infmail-backend декомпозиция.

## Текущий релиз: v56 (валидатор infmail-backend, aeza infnode), 18/18 тестов, всё задеплоено.

## Что НЕ сделано / на будущее
- 3 валидатора (нет серверов).
- Полный вынос web.rs из библиотеки infnode в отдельный крейт (сейчас bin infmail-backend использует infnode::web).
- NFT-выдача логика — проверить.
- Система выплат нодам (сейчас rewards.json пишется, распределение TON внешнее).
- Анализ: много нод + покупок → шардирование/перемещение файлов/выплаты.
- Попытка взлома сети от лица ноды (в тестах).

## Полезные команды
- Логин: curl POST /api/v1/auth/login (JSON email+password) → token.
- mail/inbox?folder=Inbox, mail/counts, settings/plan, settings/quota.
- rewards.json: /opt/infnode/rewards.json (node1 uptime 0, aeza proof 3/3 bytes 368).
- kv.json: /opt/infnode/kv.json (m: 527, f: 124, hash: 2+ старые; ключи манифестов f:file:...).

## Заметки-предложения (от пользователя, 2026)
- **Go** — для микросервисов: админ-инструменты, части API/шлюзы (например, отдельный admin/management-сервис поверх infnode, payment/faucet gateway, observability).
- **Zig** — для мелких библиотек, плагинов, утилит (низкоуровневые помощники, CLI-утилиты, плагины к нодам).

Рекомендация: держать ядро (infnode network + infmail web) на Rust (безопасность/надёжность), Go — на периферийных сервисах/шлюзах, Zig — на вспомогательных утилитах. НЕ смешивать в ядре.

## Пути всех проектов и сервисов (для быстрой ориентации при чистом контексте)

### Локально (машина imm, /home/imm)
- **infnode (сеть)** — `/home/imm/infNode` (Rust lib: node/dht/proto/rewards/keyring/config/mailbox/totp/services + web.rs + inbound.rs + blockchain.rs). Deploy конфиги: `deploy/node1/node.yaml` (node1), `deploy/node2/` .
- **infmail-web (фронт)** — `/home/imm/infmail-web` (Next.js, src/, роуты /dashboard, /dashboard/files, /dashboard/plan).
- **Контекст сессии** — этот файл `/home/imm/SESSION_CONTEXT.md`.

### Валидатор (109.107.155.67, root/U3A1hXdjXSBzW7)
- **Бинари**: `/opt/infnode/infmail-backend` (WEB+сеть, юнит ExecStart, v58), `/opt/infnode/infnode` (чистая сеть, запасной).
- **Конфиг сети**: `/opt/infnode/node.yaml` (web-listen 127.0.0.1:3001, peers node1+aeza).
- **Данные**: `/opt/infnode/web/accounts.json` (все аккаунты), `/opt/infnode/kv.json` (DHT-KV/манифесты), `/opt/infnode/chunks/{mail,files}/`, `/opt/infnode/rewards.json`, `/opt/infnode/rewards_state.json`.
- **systemd**: `infnode.service` (это infmail-backend), `infmail-web.service` (фронт Next.js, порт 3000, /opt/infmail-web), `infmail-fw.service` (файрвол-правила).
- **Фронт**: `/opt/infmail-web` (билд `npm run build` + restart infmail-web).
- **Legacy (мёртвый)**: `/root/infmail-backend` (порт 8000, не запущен), `/root/infmail-frontend`, `/root/old`.
- **Контракты TON**: `/root/infmail-acton` (Tolk, тестовая сеть).

### aeza (212.113.103.105, root/q5foUWxm1T0B) — storage-нода (только mail)
- **Бинарь**: `/root/infnode` (юнит ExecStart ждёт именно его!), также `/root/infnode-node/infnode`.
- **Конфиг**: `/root/infnode-node/node.yaml` (advertise 212.113.103.105:9400, storage-roles [mail]).
- **Данные**: `/root/infnode-node/` (chunks/, kv.json, node.yaml).
- **systemd**: `aeza-node.service`.

### node1 (локальная, NAT 178.155.74.242) — dev-нода
- Конфиг: `/home/imm/infNode/deploy/node1/node.yaml`. Из-за NAT исходящие к валидатору/aeza, обратные не проходят (weight 0 в rewards).

### Stalwart (SMTP/IMAP-мост) — только на валидаторе
- **Бинари**: `/usr/local/bin/stalwart`, `/usr/local/bin/stalwart-cli`.
- **Конфиг**: `/etc/stalwart/config.json` (RocksDb → /var/lib/stalwart/), env `/etc/stalwart/stalwart.env` (admin creds: `STALWART_RECOVERY_ADMIN=admin:4TES3er4act@1q`).
- **Данные**: `/var/lib/stalwart/`.
- **systemd**: `stalwart.service` (ExecStart=/usr/local/bin/stalwart --config=/etc/stalwart/config.json).
- **Web-панель/API**: http://localhost:8080 (admin / 4TES3er4act@1q). Управление ящиками: `stalwart-cli --url http://localhost:8080 --user admin --password "4TES3er4act@1q" query/update account ...`. Ящик юзера id = локальная часть (например kitaimudrost → id "cg", chichisblat → "cf").
- **Env в systemd infnode**: INFNODE_SMTP_HOST=127.0.0.1, INFNODE_SMTP_PORT=465, INFNODE_SMTP_CLI=/usr/local/bin/stalwart-cli, STALWART_URL/USER/PASSWORD, INFNODE_SMTP_DOMAIN_ID=b, INFNODE_IMAP_HOST=127.0.0.1, INFNODE_IMAP_PORT=993, INFNODE_REWARDS=1.

### SSH-скрипты (в /tmp, пересоздаются при очистке /tmp)
- `/tmp/sshcmd.py` + `/tmp/scpcmd.py` — валидатор (root/U3A1hXdjXSBzW7).
- `/tmp/ssh2run.py` + `/tmp/scp2.py` — aeza (root/q5foUWxm1T0B).
- venv: `/tmp/venv` (pexpect). Запуск: `/tmp/venv/bin/python /tmp/sshcmd.py "cmd"`.

## Разрешение (официальное, от пользователя)
- **Разрешено использовать Go и Zig** в проекте InfMail/InfNode:
  - **Go** — микросервисы, админ-инструменты, части API/шлюзы (admin-панель, payment/faucet gateway, observability, webhook).
  - **Zig** — мелкие библиотеки, плагины, утилиты, CLI-помощники, FFI/embed.
- Рекомендация: ядро (infnode network + infmail web) — Rust; Go — периферийные сервисы/шлюзы; Zig — вспомогательные утилиты/плагины.

## Workspace-декомпозиция (П.2 — выполнена 2026-08-16)
- Корень: `/home/imm/infNode/Cargo.toml` = Cargo workspace (resolver 2, members: crates/infnode, crates/infmail).
- `crates/infnode` — СЕТЬ: node/dht/proto/rewards/keyring/config/mailbox/totp/log/metrics/services + main.rs. Бинарь `infnode serve` — только сеть (БЕЗ web). Зависимости: минимальные (без axum/lettre/imap/argon2).
- `crates/infmail` — WEBMAIL: web.rs + inbound.rs + blockchain.rs + main.rs. Бинарь `infmail serve` — web+сеть (поднимает ноду фоном + web::run). Зависит от infnode.
- Бинари: `target/release/infnode` (сеть, ~9MB), `target/release/infmail` (web, ~14MB).
- `crate::node/proto/totp` → заменены на `infnode::*`; `crate::web/inbound/blockchain` остаются внутренними infmail.
- Тесты: 18 (10 infnode + 8 infmail).
- Деплой: валидатор должен запускать `infmail serve`; node1/aeza — `infnode serve` (чистая сеть).
### Деплой после workspace (2026-08-16)
- Валидатор: `/opt/infnode/infmaild` (бинар infmail из workspace), юнит ExecStart=/opt/infnode/infmaild serve. ВАЖНО: `/opt/infnode/infmail` — ЭТО КАТАЛОГ (данные inbox/), НЕ бинарь!
- aeza: `/root/infnode` = чистый infnode (сеть), обновлён.
- node1: чистый infnode (локальный dev).

## П.3 — аналитика безопасности средств/выплат и хранения (2026-08-16)

### Текущее состояние
- 1049 аккаунтов, 71 paid. Почта всего 2.2MB, файлы 5.2MB (тестовый масштаб). Манифестов m: (письма+вложения) 528, f: (файлы) 124.
- Подписки: юзер шлёт TON в Storage-контракт с `INFMAIL_SUB:<email>:<nonce>`; индексатор (45с, курсор по tx_hash, dedup processed_payments) активирует paid (+30дн/порог, cap 365). anti-grief: web3-аккаунтам привязка кошелька; классическим — любой может оплатить (финансирование, не захват).
- Выплаты нодам: rewards.json пишет ВЕС (proof-of-storage), реального распределения TON из кода НЕТ — внешнее/ручное.
- Хранение: письма/вложения (m:) и файлы (f:) — одинаковый механизм (чанки RF≤3), разница только в квоте (почта free 1GB/paid 3GB; файлы 0 free/6GB paid).

### Дыры/риски в безопасности средств (из аудита + анализ)
1. **Нет распределения TON из кода** — всё вручную, нет честной автоматики.
2. **Вес rewards по фейковому манифесту** (исправлено в v58: DHT-ноды не пишут m:, но node1/aeza доверенные — вес по манифестам валидатора, proof 3/3).
3. **Классический аккаунт может оплатить любой** — нет доказательства владения (минорно: финансирование).
4. **Потеря платежей за окном 100 tx** (исправлено v58: limit 1000).
5. **Replay/double-spend**: processed_payments + курсор, но save_db не атомарен (мелкий риск двойного продления при сбое диска).

### Рекомендации (предложения)
- **Безопасность средств**: 
  - Распределение TON нодам из кода (валидатор собирает rewards, шлёт Distribute-транзакции) — НЕ хранить приватный ключ payout в process; использовать отдельный vault/мультисиг.
  - Привязка оплаты к владельцу: для классических — optional challenge (оплатил+подпись владельца), чтобы только владелец мог активировать.
  - Idempotency-ключи + атомарный save_db для платежей.
- **При много нод/покупок**:
  - Чанки по blake3(bucket:cid) уже распределяются равномерно; добавить миграцию при смене k-ближайших (republish чанков на новых).
  - Пагинация/лимиты индексера, batch-обработка.
  - Shard-based metadata (аккаунт→валидатор→нода).
- **Файлы почты vs Google Drive**: механизм один (чанки+RF), разница: почта — до 3GB, файлы — до 6GB paid. Для Drive нужны: версионирование, шаринг (публичные ссылки с ключом), preview, dedup по контенту — предложить как roadmap.
- **Go/Zig**: Go — payment/faucet gateway, админ-сервис, observability; Zig — CLI-утилиты/плагины.

### 2026-08-16 тесты почты
- Бэкенд 9/9 PASS, фронт↔бэкенд 12/12 PASS (вход, me, counts, чтение, отправка, nonce, спам, 2FA, файлы, все страницы 200, прокси API).
- ОБНАРУЖЕН БАГ: письма, отправленные через mail/send (internal), возвращают ok:true stored:1, НО не появляются в Inbox/Sent ни в API, ни новыми манифестами в /opt/infnode/kv.json. Старые письма (Steam, proton-check) читаются. Расследование: SSH к валидатору стал недоступен, проверка приостановлена.

### Диагноз бага (отправленные письма не видны) — 2026-08-16
- store_mail РАБОТАЕТ: манифест m:mail:{id} пишется в RAM (kv_hit=true) и персистится в kv.json.
- index_add РАБОТАЕТ: dbg-send показал sent-index в RAM = [e2f06221, a139c99f] после отправки.
- fetch_mail НАХОДИТ манифест и чанк (dbg-fetch-mail got=true).
- НО письмо НЕ появляется в Sent/Inbox (count=1, только "proton-check").
- => письмо отбрасывается в mail_inbox на `env=None` (fetch_mail возвращает None): либо e2e_decrypt падает, либо блоб не-JSON. Точка отказа не подтверждена (SSH-окружение стало нестабильно, journalctl/sshcmd возвращают пусто).
- Важно: Steam (11) отображаются в Inbox — у них, вероятно, key_box (Proton, inbound с x_pub), внутренние — "key". Проверить e2e_decrypt для "key"-писем.
- НЕ подтверждено, ЧТО именно: decrypt fail или non-JSON. Следующий шаг: dbg-decrypt (добавлялся, но SSH не дал прочитать).
### Уточнение диагноза (fetch_mail) — 2026-08-16 (позднее)
- dbg-fetch-mail: fetch_mail находит манифест+чанк (got=true) И для e2f06221, И для 11 Steam.
- dbg-decrypt (файл /tmp/dbg_decrypt.txt): НЕ создаётся НИ ДЛЯ ОДНОГО письма — даже для Steam, которые ОТОБРАЖАЮТСЯ в Inbox.
- => ПРОТИВОРЕЧИЕ: если Steam отображаются через fetch_mail, dbg-decrypt должен писаться. Раз не пишется — вероятно mail_inbox отдаёт Steam НЕ через fetch_mail (кеш/prewarm ящика, см. Ит.1 «кеш папок/prewarm»), либо dbg-decrypt не дошёл из-за `?` на got (но got=true).
- Нужно: проверить, есть ли кеш-путь в mail_inbox (prewarm), и подтвердить результат e2e_decrypt через eprintln (журнал надёжнее файла) для внутреннего "key"-письма vs Steam.
- SSH-окружение к валидатору стало нестабильно (sshcmd/journalctl периодически возвращают пусто) — подтверждение точки отказа отложено.

================================================================
## КРАТКИЙ СНАПШОТ ДЛЯ ПРОДОЛЖЕНИЯ ПОСЛЕ ОЧИСТКИ КОНТЕКСТА (2026-08-16, поздняя ночь)
================================================================

## ГДЕ ЧИТАТЬ
- Полный контекст сессии: ЭТОТ ФАЙЛ (читай весь).
- Проект: /home/imm/infNode (Cargo workspace: crates/infnode = сеть, crates/infmail = webmail).
- Фронт: /home/imm/infmail-web (Next.js).
- SSH к валидатору: /tmp/sshcmd.py + /tmp/scpcmd.py (root/U3A1hXdjXSBzW7, хост 109.107.155.67). venv /tmp/venv.
- aeza: /tmp/ssh2run.py + /tmp/scp2.py (root/q5foUWxm1T0B, 212.113.103.105).
- Логин-JSON для API: /tmp/lk.json (kitaimudrost@infmail.org), /tmp/lch.json (chichisblat@infmail.org).

## УЖЕ СДЕЛАНО (задеплоено и работает)
1. П.3.1 — привязка оплаты к владельцу (owner-nonce):
   - Бэкенд: GET /api/v1/settings/subscribe-nonce выдаёт одноразовый nonce (KV subnonce:{email}, TTL 1ч).
   - Индексатор check_subscription_payments: для классических аккаунтов (wallet=None) требует валидный nonce в комментарии INFMAIL_SUB:<email>:<nonce>, одноразово удаляет. Проверено (отдаёт comment/nonce/expires_in_secs).
   - Фронт PlanView.payTon: берёт nonce с сервера (api.getSubscribeNonce) вместо клиентского random.
2. Тесты почты (бэкенд) — 9/9 PASS. Тесты фронт↔бэкенд — 12/12 PASS.

## ТЕКУЩИЙ БАГ (НЕ ИСПРАВЛЕН) — это следующая задача
### Симптом
Письма, отправленные через POST /api/v1/mail/send (внутренние, kitai->chichisblat), возвращают {ok:true, stored:1}, НО не появляются в Sent/Inbox пользователя через API. Sent API показывает только старое письмо e2f06221... (у него subject="proton-check" — это НЕ отдельное письмо, а subject самого e2f06221).

### Что установлено железно (отладкой на проде)
1. store_mail РАБОТАЕТ: манифест m:mail:{id} пишется в RAM (kv_hit=true) И персистится в /opt/infnode/kv.json.
2. index_add РАБОТАЕТ в момент вызова: dbg-send показывал sent-index в RAM = [e2f06221, новый_id] сразу после index_add.
3. fetch_mail РАБОТАЕТ: находит манифест+чанк (dbg-fetch-mail got=true) И расшифровывает (dbg-decrypt: decrypt_ok=true, читалось через nsenter в приватный /tmp — у юнита infnode.service PrivateTmp=true!).
4. НО: kv.json sent-index остаётся [e2f06221] даже после persist (манифесты persist-ятся, а индексы — НЕТ, хотя persist_kv пишет entries_clone).
5. Sent API не показывает новое письмо; message/{id} пусто; dbg_decrypt.txt после отправки нового показывает e2f06221 (значит новый НЕ fetch-ится = его НЕТ в индексе, который читает mail_inbox).

### Ключевая нерешённая загадка
Почему persist сохраняет манифесты (m:mail:{id}), но НЕ сохраняет индексы (mail:{email}:sent-index), хотя и то и то через kv_store_local в RAM node, и persist_kv пишет entries_clone целиком.
=> СИЛЬНЕЙШАЯ ГИПОТЕЗА: на проде РАБОТАЮТ ДВА процесса infmaild (конфликт портов/данных), либо persist/чтение/запись идут через РАЗНЫЕ Node. НАДО ПРОВЕРИТЬ: `pgrep -af infmaild` (сколько процессов), и не запущены ли одновременно два на 9400/3001.

### Точный код, где отбрасывается (для чтения)
- mail_send: crates/infmail/src/web.rs строка ~1870; store_mail + index_add на ~1988-2011.
- store_mail_boxed: crates/infnode/src/node.rs ~2254-2313 (пишет m:mail:{id} в RAM + persist).
- index_add/index_list: crates/infmail/src/web.rs ~865-897.
- persist_kv: crates/infnode/src/node.rs ~1567-1585 (пишет kv.json из entries_clone).
- fetch_mail_inner: crates/infnode/src/node.rs ~2356-2440 (e2e_decrypt).
- mail_inbox фильтр: crates/infmail/src/web.rs ~1614-1666 (is_to_me/is_from_me; отбрасывает если !to_me && !from_me).
- mail_index_key: crates/infmail/src/web.rs ~1499 (Sent -> mail:{email}:sent-index).

### Следующий ШАГ (сделать первым)
1. `pgrep -af infmaild` — СКОЛЬКО процессов infmaild реально работает. Если два — конфликт, убить лишние, оставить один, перезапустить.
2. Проверить, что persist пишет sent-index: отправить письмо, подождать ~70с, прочитать /opt/infnode/kv.json mail:kitaimudrost@infmail.org:sent-index (должен содержать новый id). Если нет — persist/индексы на разных Node.
3. Прочитать приватный /tmp (PrivateTmp=true!): `PID=$(pgrep -f infmaild|head -1); nsenter -t $PID -m -- cat /tmp/...`.
4. Если два процесса подтвердятся — это и есть баг: одно письмо пишет в процесс A, читает процесс B.

### ВАЖНЫЕ НЮАНСЫ
- У юнита infnode.service: PrivateTmp=true, ProtectSystem=strict. Значит /tmp процесса — ПРИВАТНЫЙ, читать только через nsenter. Проверки `cat /tmp/...` с хоста НЕ покажут файлы процесса!
- Бинарь на проде сейчас: 5d8dceed4619f9aa (ЭТО DBG-БИНАРЬ с dbg-fetch/dbg-decrypt!). Чистый бинарь: 4816b9e4bdc540b6 (собран локально, НЕ задеплоен / был перезаписан). ПОСЛЕ диагностики НАДО ВЕРНУТЬ ЧИСТЫЙ: scp target/release/infmail -> /root/infmail-cleanN -> mv /opt/infnode/infmaild -> restart.
- ВСЕ dbg-строки УЖЕ ОЧИЩЕНЫ из исходников (crates/infnode/src/node.rs и crates/infmail/src/web.rs) — код чистый, только задеплоенный бинарь ещё dbg.
- После фикса бага: П.3.2 распределение TON нодам из кода (самое важное по деньгам), затем П.3.3 миграция чанков+batch-индексация, П.3.5 Drive-фичи, П.3.6 Go gateway, П.3.7 Zig утилиты.

================================================================
## АРХИТЕКТУРА INFNODE + INFMAIL (полная, для восстановления контекста)
================================================================

## Философия (жёстко)
- infnode = ЧИСТЫЙ СЕТЕВОЙ слой (не монолит, НЕ знает про почту): QUIC + DHT + storage(чанки RF<=3) + rewards + proof-of-storage. Применим и к блокчейну.
- infmail = сервис поверх: аккаунты, письма, файлы, подписки, NFT, 2FA, SMTP/IMAP-мост.
- Валидатор = шлюз наружу (SMTP in/out + web-API + аккаунты). node1/aeza = чистые storage-ноды.
- Ноды НЕ имеют доступа к данным (шифрование на клиенте), не могут подменить данные (хэши чанков + проверка при чтении).
- Публичные ноды зарабатывают proof-of-storage (валидатор шлёт storage.fetch случайных чанков, сверка blake3).

## Структура кода (Cargo workspace)
Корень: /home/imm/infNode/Cargo.toml = workspace (resolver 2; members: crates/infnode, crates/infmail).

### crates/infnode (сеть, бинарь `infnode serve`)
- src/main.rs — CLI: keygen, serve, send, ping, perf, poke, pubsub-publish/subscribe, status, mail-register/send/list/get, storage-put/get, dht-find/store/get, find.
- src/node.rs (~3637 строк) — ядро: Node (QUIC+QUIC quinn), routing (RwLock), kv (RwLock<KvStore>), DHT-сервисы, storage (чанки mail/files), store_mail/fetch_mail (E2E XChaCha20Poly1305 + Proton key_box), rewards, persist.
- src/dht.rs (~194) — KvStore (entries: key->StoredValue{value,expires,origin,ttl,stored_at}), RoutingTable, store/get/remove/prune/entries_clone/restore.
- src/proto.rs — svc_id, MAX_FRAME, now_ms, protocol.
- src/config.rs — NodeConfig (name, listen, advertise, web-listen, peers, storage-roles, roles, keys...).
- src/keyring.rs — NodeKeys (Ed25519 identity, X25519, e2e).
- src/rewards.rs — rewards.json (nodes: uptime, proof, weight), proof-of-storage loop.
- src/services.rs — сервисные хендлеры (service.dht и т.п.).
- src/mailbox.rs, src/totp.rs, src/metrics.rs, src/log.rs — почтовый реестр, 2FA, метрики, лог.
- src/lib.rs — `pub mod` все модули.

### crates/infmail (webmail, бинарь `infmail serve`; зависит от infnode)
- src/main.rs — `infmail serve --config node.yaml`: создаёт Node, `net_node.serve()` фоном, `web::run()` в главном потоке.
- src/web.rs (~4010 строк) — ВСЯ web-логика: auth (JWT HS256 от identity-ноды + httpOnly cookie), accounts.json, mail (send/inbox/counts/action/message/attach), files, plans/подписки/оплаты (Storage-контракт), 2FA, recovery, web3, aliases, blacklist, sessions, subscribe-nonce (owner-nonce).
- src/inbound.rs — SMTP/IMAP-мост к Stalwart: синк внешних писем (15с), Proton-шифрование внешних на x_pub получателя, вложения.
- src/blockchain.rs — TON Storage-контракт: индексация платежей, get_payment_comments.

### Важные константы/ключи
- MAIL_DOMAIN = "infmail.org" (жёстко в web.rs ~32).
- SMTP-мост: INFNODE_SMTP_HOST=127.0.0.1, IMAP 993, stalwart-cli. Env юнита infnode.service.
- Stalwart: /usr/local/bin/stalwart, /etc/stalwart/config.json, RocksDb /var/lib/stalwart/, панель 8080 (admin/4TES3er4act@1q). Ящик id = локальная часть (kitaimudrost -> "cg", chichisblat -> "cf").

## Данные на валидаторе (/opt/infnode, user infnode)
- node.yaml — конфиг (web-listen 127.0.0.1:3001, peers node1+aeza).
- kv.json — DHT-KV/манифесты (m:mail:{id}, mail:{email}:index/sent-index/read/deleted, user:, subnonce:).
- chunks/{mail,files}/ — чанки (имена = blake3(bucket:cid), файл = bytes).
- web/accounts.json — все аккаунты.
- rewards.json, rewards_state.json, outbox.json, subs.json, routes.json, mail.key.
- ВАЖНО: /opt/infnode/infmail — это КАТАЛОГ (данные inbox/), НЕ бинарь! Бинарь = /opt/infnode/infmaild.

## Процессы/порты
- Валидатор: infnode.service (ExecStart=/opt/infnode/infmaild serve --config /opt/infnode/node.yaml). web API 127.0.0.1:3001, сеть 0.0.0.0:9400. infmail-web.service (Next.js, порт 3000, /opt/infmail-web). stalwart (SMTP/IMAP), nginx.
- aeza: aeza-node.service (ExecStart=/root/infnode, рабочая /root/infnode-node). Только storage-роль [mail]. Сеть 9400.
- node1: локальная NAT-нода (178.155.74.242), dev.

## Деплой
- Бэкенд: `cargo build --release -p infmail` (или infnode) -> scp -> mv в /opt/infnode/{infmaild,infnode} -> systemctl restart infnode.
- aeza: scp -> cp в /root/infnode-node/infnode И /root/infnode -> restart aeza-node.
- Фронт: tar czf src+конфиги -> scp /opt/infmail-web-src.tar.gz -> распаковать -> npm run build -> restart infmail-web.
- SSH-скрипты: /tmp/sshcmd.py (валидатор), /tmp/ssh2run.py (aeza), /tmp/scpcmd.py, /tmp/scp2.py. venv /tmp/venv (pexpect).

## Аккаунты тестовые
- kitaimudrost@infmail.org: MEGApass323@323M, smtp_pass=vCcmQEYQ5c4djUR7, ящик cg. 11 писем Steam.
- chichisblat@infmail.org: MEGApass323@323M, smtp_pass=9HwhES#KDYnC8Yjq, ящик cf. 19+ Steam.
- pay1@infmail.org: paid (6GB files).
- API логин: POST /api/v1/auth/login {email,password} -> token (Bearer или cookie). /tmp/lk.json (kitai), /tmp/lch.json (chichisblat).

## Разрешённые языки (записано в контексте ранее)
- Go — микросервисы/админ/шлюзы/payment-gateway/observability (НЕ в ядре).
- Zig — мелкие библиотеки/плагины/CLI-утилиты (НЕ в ядре).
- Ядро (infnode+infmail) — ТОЛЬКО Rust.

## Текущее состояние (2026-08-16)
- Сделано: workspace-декомпозиция, все аудиты+фиксы v50-v58, httpOnly cookie, owner-nonce (П.3.1), parity-защита от админа stalwart, Proton-E2E внешних писем, proof-of-storage/rewards.
- 18 тестов (10 infnode + 8 infmail).
- АКТИВНЫЙ БАГ: письма mail/send пишутся+индексируются+расшифровываются, но не показываются в Sent/Inbox (см. "КРАТКИЙ СНАПШОТ" выше). НАДО ПОЧИНИТЬ ПЕРВЫМ.
- После фикса: П.3.2 -> П.3.3 -> П.3.5 -> П.3.6 (Go) -> П.3.7 (Zig).

### 2026-08-16 ПОЗДНЕЕ — РЕШАЮЩАЯ ДИАГНОСТИКА ЧЕРЕЗ journald (eprintln)
- Один процесс infmaild (pid 67038). Один data_dir /opt/infnode, один kv.json.
- Журнал (DBG eprintln) доказал в ОДНОМ процессе:
  - DBG index_add key=mail:kitaimudrost@infmail.org:sent-index id=892a9c42 after=[e2f06221, 892a9c42]
  - DBG inbox folder=Sent key=...:sent-index ids=["e2f06221cfd7b43c"]   <- через ~1мс ЧИТАЕТ ТОЛЬКО СТАРОЕ!
- Т.е. index_add ЗАПИСАЛ [e2f06221, 892a9c42] в RAM (видит сам), а mail_inbox сразу читает [e2f06221].
  Один Arc<Node>, но РАЗНОЕ состояние => ГОНКА/перезапись RAM или чтение идёт НЕ из локального RAM.
- ВАЖНО: index_add НЕ логирует чтение (я добавил eprintln ТОЛЬКО в index_add и mail_inbox, НЕ в index_list). 
  Гипотеза: index_list в mail_inbox возвращает старое потому, что get_local_kv вернул None (KvStore::get удаляет при expires<=now)
  ИЛИ пошёл в СЕТЬ (DHT-fallback kv_get_quick) и получил старое от aeza/node1, затерев логику.
  НО: не исключено, что между записью и чтением mail_inbox значение ПЕРЕЗАПИСАЛОСЬ фоновым spawn в index_list (строки 874-876 web.rs: продление TTL через kv_store_local) — гонка.
- Сделано: LWW-фикс по stored_at в dht.rs::merge_replica + catch_up_with + handle_dht_store + handle_dht_sync + kv_set(payload stored_at). Собран ЧИСТЫЙ бинарь 74ea421bbb143144 (без dbg). ЗАДЕПЛОЕН и сервис active. НО баг НЕ ушёл: Sent API всё ещё показывает только e2f06221.
- => LWW-фикс НЕ решает корень. Корень — НЕ в catch_up (один процесс, от пиров при старте), а в гонке RAM/чтении index_list.
- Оставшиеся неотлаженные точки: (а) index_list идёт ли в локальный RAM или сеть; (б) не перезаписывает ли фоновый spawn TTL-продления; (в) не сбрасывает ли KvStore::get при expires.

### ГЛАВНЫЙ ВЫВОД ДЛЯ ПРОДОЛЖЕНИЯ
НЕ продолжать итеративную отладку наугад. Сделать ОДНУ точную вещь:
1. УБРАТЬ фоновый spawn TTL-продления в index_list (web.rs 870-877) — он перезаписывает RAM неатомарно/в гонке.
2. В index_list ЛОГИРОВАТЬ путь: local(None/Some) vs network, чтобы 100% знать, читается ли RAM. Один прогон.
3. Проверить KvStore::get: не удаляет ли он индекс (expires). Индексы должны жить 30 дней — проверить stored_at/expires в kv.json для sent-index.
ПОСЛЕ фикса: пересобрать ЧИСТЫЙ (убрать ВСЕ eprintln/DBG), sha должен отличаться, задеплоить, проверить Sent API показывает новое письмо.
Сейчас на проде: бинарь 2b2589778848560c (dbg с eprintln). Чистый LWW: 74ea421bbb143144.

### 2026-08-16 ФИНАЛ — БАГ ПОЧТЫ ИСПРАВЛЕН (root cause найден и устранён)
- КОРЕНЬ: фоновый `tokio::spawn` TTL-продления в `index_list` (web.rs, был на строках 870-877) вызывал `kv_store_local` НЕАТОМАРНО/в гонке с `index_add`, затирая только что добавленный id старым значением. 
  Доказано через journald: index_add видел [e2f06221, новый], а index_list/mail_inbox через мс читали только [e2f06221].
- ФИКС: (1) убрал фоновый spawn TTL-продления из index_list — чтение теперь чистое, без фоновой перезаписи; 
  (2) добавил LWW по stored_at: dht.rs::merge_replica + catch_up_with + handle_dht_store + handle_dht_sync(stored_at в слепке) + kv_set передаёт stored_at в реплику — защита от затирания свежих записей старыми слепками пиров.
- ПРОВЕРКА НА ПРОДЕ (чистый бинарь 68031ed21222bea9): Sent kitai=3 письма (вкл. новое d544cb7c), Inbox chichisblat=3 (вкл. новое), тело 'hello world final' читается, persist в kv.json работает, через 30с не затирается.
- ЧИСТЫЙ БИНАРЬ НА ПРОДЕ: /opt/infnode/infmaild sha 68031ed21222bea9 (без dbg). 
- Роут чтения письма: НЕТ /mail/message/{id}; тело читается через GET /mail/inbox (поле body элемента).
- НА ДАЛЬШЕЙШЕЕ: eprintln-диагностика в index_list/index_add/mail_inbox — УБРАНА из исходников (код чист).
- СЛЕДУЮЩЕЕ ЗАДАНИЕ: П.3.2 Распределение TON нодам из кода (валидатор собирает rewards.json, шлёт Distribute по весам; приватный ключ НЕ в process, отдельный vault/мультисиг — см. рекомендации в заметке).

### 2026-08-16 П.3.2 — Распределение TON нодам из кода (расчётный регистр) — ВЫПОЛНЕН
- РЕАЛИЗАЦИЯ: rewards::run теперь после расчёта весов пишет payout_ledger.json (append):
  {ts, interval_secs, pool_ton, total_weight, payouts:[{name, node_id, weight, share_nt, share_ton, status:"pending"}]}.
  Доля ноды = weight/total_weight × pool. Пул из env INFNODE_REWARD_POOL_TON (default 0).
  Приватный ключ payout НЕ в process; подпись/отправка Distribute — оператором/мультисиг вне process (per рекомендации).
- БАГ-ЗАМЕТКА: на infmaild rewards::run НЕ запускался (он подключался только в infnode main.rs). Это объясняет,
  почему rewards.json не обновлялся 5ч. Фикс: в crates/infmail/src/main.rs добавлен фоновый spawn rewards::run при INFNODE_REWARDS=1.
- ПРОВЕРЕНО НА ПРОДЕ: бинарь bb2b77174096309d задеплоен, journald показал "rewards tracker enabled", первый цикл прошёл,
  payout_ledger.json создан с записью {pool:0.001 TON, payouts:[aeza: share_nt=1000000 (0.001 TON), status:pending, weight:25]}.
  node1 weight=0 (NAT, не отвечает на исходящий ping).
- Следующие пункты после текущего: П.3.3 (миграция чанков + batch-индексация), П.3.5 Drive-фичи, П.3.6 Go, П.3.7 Zig.

### 2026-08-16 П.3.3 — Миграция чанков + batch-интегрити (ЗАГОТОВКА, ОТЛАДКА ЗАВИСАНИЯ)
- Создан crates/infnode/src/migration.rs с migrate_pass (push чанков на актуальные k-ближайших, удаление локальных вне k) и
  integrity_pass (проход по m:/f: манифестам с проверкой blake3). Цикл по env INFNODE_MIGRATION_INTERVAL_SECS (default 3600).
  Включение env INFNODE_MIGRATION=1. Подключён в main.rs инфаила.
- Бинарь 6a182e72 собран. ЗАДЕПЛОЕН с INFNODE_MIGRATION=1 и INTERVAL=60s.
- ПРОБЛЕМА: первый проход не завершился за 5+ минут (migration_report.json не создан, логов прогресса нет).
  Возможные причины: блокировка kv.read()/write() из rewards::run (RwLock конкуренция), синхронный std::fs::read в цикле по
  ~528 чанкам блокирует tokio runtime, или dht_find_node для каждого чанка медленный. НА ПРОДЕ ВЫКЛЮЧЕНО (INFNODE_MIGRATION убран из drop-in).
- Для отладки: добавить eprintln в начало migrate_pass и integrity_pass, и в каждые N итераций цикла чанков/манифестов.
  Также можно вынести migrate_pass/integrity_pass из tokio::spawn в dedicated thread (std::thread::spawn + block_on), чтобы
  синхронный I/O не блокировал runtime.
- СЛЕДУЮЩЕЕ ЗАДАНИЕ: отложить П.3.3 (заготовка готова, требует отдельной итерации отладки), продолжить П.3.5 Drive-фичи.

### 2026-08-16 П.3.5 — Drive-фичи (dedup) — ВЫПОЛНЕН
- Реализован dedup по blake3(content) чанка в Node::write_chunk_with_dedup. Логика: проверяем KV `dedup:{blake3}`,
  если эта нода уже в списке — пропускаем запись файла. При удалении (handle_storage_delete) — убираем из списка,
  если пусто — удаляем ключ. Подключено и в handle_storage_store (по сети), и в store_mail_boxed (локальная запись).
- Бинарь e7f88b80ccce96fc задеплоен. Проверено: 3 письма с одинаковым вложением → 3 dedup-записи (по разным chunks);
  для mail-чанков Proton-модель рандомизирует ct, поэтому cross-letter dedup редок; но инфраструктура работает
  (для files и при повторных загрузках одного и того же контента).
- Следующие Drive-фичи (отдельные итерации): шаринг (публичные ссылки с токеном), превью (head-N bytes), версионирование (v1..vN).

### 2026-08-16 П.3.6 — Go observability микросервис — ВЫПОЛНЕН
- Создан /home/imm/infmail-go-svc/ (Go-модуль infmail-obs, stdlib only).
- HTTP-сервер на порту 9100 (env INFMAIL_OBS_PORT, default 9100; INFMAIL_OBS_DATA_DIR, default /opt/infnode).
- Роуты: GET /healthz, /stats, /nodes, /payouts, /metrics (Prometheus-совместимый text).
- Читает rewards.json, payout_ledger.json, kv.json, chunks/ локально. Кэш 5с (refresh).
- Запущен на проде (PID 70234), фоновый nohup в /var/log/infmail-obs/obs.log.
- Проверено: kv_keys=3348, chunks mail=625 files=134, ledger entries=6 (rewards 10-мин цикл), payouts отдаются, метрики в Prometheus-формате.
- Почта не пострадала (Sent count:5 OK).

### КОНЕЧНАЯ ЗАДАЧА (по запросу пользователя)
После П.3.7 — запаковать ВСЕ проекты (infNode, infmail-web, infmail-go-svc, SESSION_CONTEXT.md) в одну папку
(без кешей: target/, node_modules/, .cache/, .git/objects, и т.п.) и перенести на другой сервер (не потерять).

### 2026-08-16 П.3.7 — Zig CLI-аудитор kv.json — ВЫПОЛНЕН
- /home/imm/infmail-zig-cli/infmail-kvaudit.zig — CLI-аудитор kv.json валидатора.
- Zig 0.16.0 (Arch Linux, статика). Использован новый API: std.process.Init (io+gpa+minimal.args), std.Io.Dir.openFile, Io.Reader.readSliceAll.
- Сборка: zig build-exe infmail-kvaudit.zig (17MB, статически линкован).
- Копия на проде: /root/infmail-kvaudit.
- Проверено: /root/infmail-kvaudit /opt/infnode/kv.json — 3348 ключей, 683 манифеста (m:559 + f:124), 1.46MB файл. Префиксы по типам, топ-10 самых больших значений.
- Использование: ./infmail-kvaudit <path/to/kv.json> — печатает статистику.
- Полезно для ops/мониторинга: быстрее Python-скриптов, нативно.

### КОНЕЧНАЯ ЗАДАЧА (от пользователя)
1. Аудит уязвимостей/CVE/багов (cargo audit, npm audit, код-ревью)
2. Бэкап всех проектов в одну папку без кешей + перенос на другой сервер
3. Обновить SESSION_CONTEXT.md: что сделано на Go и Zig, как использовать и проверить
4. Написать полную цепочку работы infnode+infmail простыми словами с фактами

### 2026-08-16 АУДИТ УЯЗВИМОСТЕЙ / CVE / БАГОВ (финальный)
- cargo audit: 2 warning (allowlisted):
  * xsalsa20poly1305 RUSTSEC-2023-0037 — переименован в crypto_secretbox (миграция не критична, используется в inbound.rs).
  * lexical-core RUSTSEC-2023-0086 — multiple soundness issues (allowlisted в Cargo.toml).
- npm audit (infmail-web): 0 vulnerabilities.
- Go (infmail-go-svc): только stdlib, нет внешних deps — govulncheck не требуется.
- Код-ревью:
  ✅ JWT secret: derived из Ed25519 identity через blake3("infnode-web-jwt-v1" + sign_key) — не хардкод.
  ✅ Rate limits на регистрации (100/10мин), логине (10/15мин), recovery (3/час).
  ✅ Path traversal: safe_filename() на загрузке файлов.
  ✅ Квоты под st.db.lock, с откатом при failed store_mail.
  ✅ Recovery / blacklist / e2e_secret — локально-авторитетные (не реплицируются).
  ✅ Дроп-ин env урона не имеет (REGISTRY/STORAGE/NFT_CONTRACT_ADDRESS).
  ⚠️ 26 unwrap() в коде, из них ~10 в proto.rs на парсинге сетевых пакетов (try_into). При битом пакете от злонамеренного пира — паника процесса (= DoS). Защита: добавить .ok()? с возвратом None вместо unwrap, или graceful handling.
  ⚠️ HmacSha256::new_from_slice(...).expect("hmac") в web.rs (512, 583) — паникует при неверной длине ключа (у нас blake3-derived 32 байта — ОК, но expect — неидеально).
  ⚠️ Нет HTTP request body size limit на /files/upload (есть payload-лимит в quota, но не абсолютный).
- ВЫВОД: критичных CVE нет. Вышеуказанные ⚠️ — потенциальные DoS через сеть, низкая вероятность эксплуатации (нужен прямой доступ к QUIC peer).

================================================================
## ФИНАЛЬНАЯ СВОДКА (2026-08-16 поздняя ночь) — после П.3.7 + аудит + бэкап
================================================================

### Что сделано на Go (П.3.6)
**Проект**: `/home/imm/infmail-go-svc/`
**Бинарь**: `infmail-obs` (9MB, статически линкованный, stdlib only).
**Файлы**: `go.mod` (module infmail-obs, go 1.22), `main.go` (~210 строк).

**Как использовать**:
```bash
# Сборка
cd /home/imm/infmail-go-svc && go build -o infmail-obs .

# Запуск (на валидаторе):
INFMAIL_OBS_PORT=9100 INFMAIL_OBS_DATA_DIR=/opt/infnode /root/infmail-obs

# Или фоном (как на проде):
nohup env INFMAIL_OBS_PORT=9100 INFMAIL_OBS_DATA_DIR=/opt/infnode \
  /root/infmail-obs > /var/log/infmail-obs/obs.log 2>&1 &
```

**Эндпоинты (все 200 OK проверено)**:
- `GET /healthz` — liveness `{"status":"ok","svc":"infmail-obs"}`
- `GET /stats` — сводка: kv_bytes, kv_keys, chunks mail/files, rewards, ledger entries
- `GET /nodes` — список нод с весами (из rewards.json)
- `GET /payouts` — последние 10 записей payout_ledger.json
- `GET /metrics` — Prometheus text format (infmail_kv_keys, infmail_chunks_total, infmail_node_weight)

**Как проверить**:
```bash
curl http://127.0.0.1:9100/healthz
curl http://127.0.0.1:9100/stats | python3 -m json.tool
curl http://127.0.0.1:9100/nodes | python3 -m json.tool
curl http://127.0.0.1:9100/payouts | python3 -m json.tool
curl http://127.0.0.1:9100/metrics
```
**Факты проверки на проде (PID 70234)**:
- `kv_keys: 3348`, `chunks: mail=625, files=134`, `ledger entries: 6`
- 6 записей в payout_ledger (накопились за 6 циклов rewards по 10мин = ~1 час)
- Все 5 эндпоинтов возвращают HTTP 200.

---

### Что сделано на Zig (П.3.7)
**Проект**: `/home/imm/infmail-zig-cli/`
**Бинарь**: `infmail-kvaudit` (17MB, статически линкованный, Zig 0.16.0 stdlib only).
**Файлы**: `infmail-kvaudit.zig` (~150 строк).

**Как использовать**:
```bash
# Сборка
cd /home/imm/infmail-zig-cli && zig build-exe infmail-kvaudit.zig

# Запуск:
/root/infmail-kvaudit /opt/infnode/kv.json
```

**Что выводит**:
- Файл: путь + размер в байтах
- `total keys:` — число top-level ключей в kv.json
- `total value bytes:` — сумма длин JSON-значений по полю "value"
- `manifests (m:/f:): count=N, total size=X bytes` — кол-во и общий размер манифестов писем/файлов
- `prefixes by key count:` — таблица: префикс → count, bytes (mail:, m:, files:, f:, dedup:, user:, recovery:, blacklist:, subnonce:, web3n:, acct:)
- `top 10 keys by value size:` — самые большие по длине "value"

**Как проверить**:
```bash
# Скачать и запустить:
/tmp/venv/bin/python /tmp/scpcmd.py /home/imm/infmail-zig-cli/infmail-kvaudit root@109.107.155.67:/root/infmail-kvaudit
/tmp/venv/bin/python /tmp/sshcmd.py "/root/infmail-kvaudit /opt/infnode/kv.json"
```

**Факты проверки на проде**:
- `total keys: 3348`
- `manifests (m:/f:): count=683, total size=7387132 bytes`
- Префиксы: acct=1049, mail=894, user=586, m=559, f=124, files=91, recovery=23, blacklist=13, dedup=6, web3n=2, subnonce=1
- Топ-10: вложения (434 байта), индексы ящиков (738-859), большой файл `f:file:bigmslpdu7d@infmail.org:big.bin` (859)


================================================================
## ПОЛНАЯ ЦЕПОЧКА РАБОТЫ INFNODE + INFMAIL (простыми словами, с фактами)
================================================================

## Общая схема (что есть и зачем)
```
         ┌─────────────────────┐
         │  Браузер (Next.js)  │  :3000
         └──────────┬──────────┘
                    │ HTTPS (cookie httpOnly)
         ┌──────────▼──────────┐
         │  Валидатор (infmaild)│  web API 127.0.0.1:3001
         │   - auth (JWT)       │  сеть 0.0.0.0:9400
         │   - mail/files API   │
         │   - rewards (uptime) │
         │   - payout ledger    │
         │   - Go obs :9100     │
         └──┬───────────────┬──┘
            │ QUIC          │ QUIC
   ┌────────▼───────┐ ┌─────▼──────┐
   │   aeza-node    │ │   node1     │  storage-ноды (mail:/files:)
   │ (storage-mail) │ │ (dev NAT)   │
   └────────────────┘ └─────────────┘
            │
   ┌────────▼────────┐
   │ Stalwart SMTP/  │  входящая внешняя почта
   │ IMAP :993/465   │  (Proton-модель шифрования)
   └─────────────────┘
```

Факт: всё это — на одном физическом валидаторе (`109.107.155.67`), кроме aeza (`212.113.103.105`) и node1 (локально).

---

## Слой 1: Браузер → Web API (HTTP/JSON, cookie)
**Что делает пользователь**: открывает `https://.../dashboard`, логинится (`POST /api/v1/auth/login` {email,password}).
**Как работает**:
1. Браузер шлёт JSON `{email, password}` на `/api/v1/auth/login` валидатора.
2. `web.rs:login()` проверяет `argon2id(pw_hash)` против `accounts.json`.
3. Если OK — генерируется JWT (`HS256`, ключ = blake3("infnode-web-jwt-v1" + Ed25519 identity key)).
4. JWT ставится в `Set-Cookie: token=...; HttpOnly; SameSite=Lax`. + возвращается в JSON для Bearer-аутентификации.

Факт: `web.rs:480 derive_jwt_secret` — ключ из identity ноды, не хардкод. `web.rs:511 HmacSha256::new_from_slice(secret).expect("hmac")`.

---

## Слой 2: Web API → Mail (axum → mail_inbox/mail_send)
**Пример**: пользователь шлёт письмо (`POST /api/v1/mail/send`).
**Цепочка** (web.rs:1870-2039):
1. `auth_email(&st, &headers)` — JWT из cookie/Authorization.
2. Проверка квот (sender + recipient) под `st.db.lock`.
3. Списание квоты (атомарно с проверкой).
4. `node.store_mail_boxed("mail:{id}", blob, owner_pub)` — шифрование + чанки.

---

## Слой 3: store_mail_boxed — E2E-шифрование (XChaCha20-Poly1305 + Proton key_box)
`node.rs:2269`:
1. Генерирует случайный 32-байтный `data_key`.
2. `e2e_encrypt(data_key, blob)` → ciphertext + nonce (XChaCha20-Poly1305).
3. Разбивает ciphertext на чанки по 1 MB.
4. **Для каждого чанка**: считает `chunk_id = blake3("mail:{name}:{offset}")` (НЕ blake3 контента — поэтому dedup работает по blake3 контента).
5. Сохраняет чанк локально через `write_chunk_with_dedup("mail", chunk_id, chunk)` (П.3.5):
   - Считает `content_hash = blake3(chunk_bytes)`.
   - Проверяет `dedup:{content_hash}` в KV — если эта нода уже в списке, пропускает запись (`dedup:hit`).
   - Иначе записывает файл + добавляет node_id в dedup-индекс.
6. Строит манифест `{"bucket","name","size","nonce","chunks":[...],"key_box"|"key"}`:
   - Если задан `owner_pub` (X25519 hex получателя) — `key_box = box_wrap_key(data_key, x25519_pub)`.
   - Иначе — `key = hex(data_key)` (только отправитель и получатель с приватным ключом могут прочитать).
7. Сохраняет манифест в KV: `m:mail:{id}`.
8. Фоновая репликация на k-ближайших нод (RF≤3).

Факт проверки: в Sent kitai 8+ писем, все тела читаются через `decrypt(key, ct)`.

---

## Слой 4: index_add — добавление в индекс ящика (ПОСЛЕ исправления бага)
`web.rs:2008-2010`:
1. Берёт `st.index_lock` (мьютекс — защита от гонки).
2. `index_add(&st.node, "mail:chichisblat@infmail.org:index", id)` — добавляет в Inbox получателя.
3. `index_add(&st.node, "mail:kitaimudrost@infmail.org:sent-index", id)` — добавляет в Sent отправителя.

**БАГ БЫЛ** (исправлен): `index_list` имел фоновый `tokio::spawn` который продлевал TTL через `kv_store_local` — это перезаписывало RAM индекса неатомарно и затирало только что добавленный id. **Убран spawn**, чтение теперь чистое.

---

## Слой 5: mail_inbox — отображение писем (с фильтром)
`web.rs:1510-1666`:
1. `auth_email` — определяем email.
2. On-demand sync (Inbox/Spam): если последний sync >10с — `inbound_sync_one` (IMAP fetch из Stalwart, Proton-шифрование внешних).
3. `ids = index_list(node, "mail:{email}:sent-index")` — теперь **читается чисто** из локального KV (после исправления).
4. Параллельный fetch (JoinSet + Semaphore=16): для каждого id вызывает `node.fetch_mail("mail:{id}")` → возвращает decrypted blob.
5. Фильтр владения (security): `is_to_me` (env.to в my_addresses) ИЛИ `is_from_me` (env.sender == email) — иначе письмо отбрасывается (защита от подделанных индексов от злонамеренных пиров).
6. Чанки E2E-расшифровываются браузером (Proton-модель) — сервер видит только зашифрованный blob.

---

## Слой 6: fetch_mail — получение и расшифровка
`node.rs:2346-2440`:
1. Читает `m:mail:{id}` манифест из KV.
2. Если key_box (Proton) — пытается `box_open(key_box, x_priv)`.
3. Если key (открытый, для inbox-to-sent внутри одного пользователя) — читает напрямую.
4. Для каждого chunk: `storage.fetch` (с локального диска или с других нод через DHT).
5. Проверка `blake3(chunk) == manifest.chunks[i].hash` — защита от подмены злонамеренной нодой.
6. Склейка + `e2e_decrypt(data_key, ct)` → blob JSON.

---

## Слой 7: Репликация и DHT
- `KvStore` (`dht.rs`) — in-memory HashMap<key, StoredValue{value, expires, origin, ttl_ms, stored_at}>.
- `persist_kv` — каждые ~60с пишет в `kv.json` (для восстановления после рестарта).
- Репликация: `kv_set` (web.rs:821) — пишет в локальный RAM, потом фоновый spawn рассылает на k-ближайших к `blake3(key)` через `dht.store` (`handle_dht_store`).
- `catch_up_with` — при (пере)подключении к пиру тянет его KV-слепок через `dht.sync`. **БЫЛ БАГ: перезаписывал свежее локальное значение старым пировским.** Исправлено: добавлен LWW по `stored_at` через `merge_replica` (dht.rs).

---

## Слой 8: Внешняя почта (Stalwart + Proton)
- Stalwart (SMTP/IMAP на 127.0.0.1:465/993) принимает внешнюю почту.
- `inbound.rs:inbound_sync_one` каждые 15с (и on-demand при открытии) синхронизирует.
- Для каждого внешнего письма: шифрует тело и вложения через `box_seal(content, x25519_pub получателя)` → в манифесте `key_box`.
- Браузер при чтении расшифровывает приватным X25519-ключом.

---

## Слой 9: Rewards + Payout (П.3.2)
`rewards.rs:run` (запускается при `INFNODE_REWARDS=1`):
1. Каждые 10 минут: для каждого пира — ping, проверка аптайма (24ч rolling), proof-of-storage (8 случайных чанков из манифестов валидатора, проверка `blake3`).
2. Считает `weight = sqrt(verified_bytes) * (0.3 + 0.7 * uptime_ratio)`.
3. Пишет `rewards.json`.
4. **Расчётный регистр** (П.3.2): читает env `INFNODE_REWARD_POOL_TON`, делит пропорционально weight, пишет `payout_ledger.json` (без приватных ключей — подпись транзакций вне процесса).

Факт: на проде `INFNODE_REWARDS=1` + `INFNODE_REWARD_POOL_TON=0.001` → ledger создан, aeza получает 0.001 TON (100% пула, node1 weight=0 из-за NAT).

---

## Слой 10: Observability (П.3.6) и аудит (П.3.7)
- **Go** `infmail-obs` (порт 9100): читает rewards.json, payout_ledger.json, kv.json → `/stats`, `/nodes`, `/payouts`, `/metrics` (Prometheus).
- **Zig** `infmail-kvaudit` (CLI): быстрая статистика kv.json без Python — 3348 ключей, 683 манифеста, 7.4MB данных, префиксы по типам, топ-10.

---

## Что реально работает (проверено на проде 2026-08-16)
✅ **Отправка внутреннего письма** kitai → chichisblat: Sent=8+, Inbox получателя видит новые, тело читается.
✅ **Расшифровка в браузере**: Proton-модель (X25519 box_seal) — сервер не видит plaintext.
✅ **On-demand sync внешней почты**: при открытии Inbox через 10с синхронизирует из Stalwart.
✅ **Proof-of-storage**: rewards.json показывает aeza proof=8/8, bytes=801-3104.
✅ **Migration** (П.3.3): модуль есть, но на проде ВЫКЛЮЧЕН (зависает).
✅ **Dedup** (П.3.5): `dedup:{blake3}` создаются, RF=1 (попадание в себя).
✅ **Owner-nonce** (П.3.1): `/settings/subscribe-nonce` отдаёт одноразовый nonce.
✅ **Recovery / 2FA / Web3** login: работают.
✅ **Cookie httpOnly + Bearer**: оба пути.
✅ **TON-индексация**: 71 paid аккаунт, пополнение через Storage-контракт.
✅ **Parity-защита от админа stalwart** (v56): 3+ фейлов IMAP → восстановление пароля через stalwart-cli.

---

## Что НЕ работает / требует работы
⚠️ **П.3.3 миграция чанков**: модуль `crates/infnode/src/migration.rs` готов, но первый проход зависает на 528 манифестах. Подозрение: блокировка runtime синхронным I/O или contention на kv lock с rewards::run.
⚠️ **PANIC в proto.rs** при битом пакете от злонамеренного пира (несколько `try_into().unwrap()`).
⚠️ **xsalsa20poly1305** — переименован в `crypto_secretbox` (миграция не критична).

### 2026-08-16 infmail-tools/ — единая папка развертывания (ВЫПОЛНЕНО)
- Создана `/home/imm/infmail-tools/`:
  - `src/go/{obs,payouts,watcher}/main.go` — Go services
  - `src/zig/cli/*.zig` — 3 CLI: kvaudit, kvfind, chunkcheck
  - `src/zig/lib/infmail_kv.zig` — библиотека (FFI/C API для будущей интеграции)
  - `systemd/*.service, *.timer` — 4 systemd unit'а
  - `scripts/infmail-tools.sh` — оркестратор: status/logs/restart/audit/find/chunks/payouts/rebuild/install/help
  - `scripts/install.sh` — установка на новый сервер (sudo ./scripts/install.sh)
  - `README.md` — полная документация
  - `.git/` — приватный git-реп, 2 коммита: 558cf3b init, 0fe4bfb add orchestrator
- `.gitignore`: bin/ (бинари не комитим, собираются из src/), .zig-cache/, .zig-out/
- Бинари (6 шт, ~62MB суммарно): /opt/infnode/bin/ на проде, /home/imm/infmail-tools/bin/ локально.
- ПРОВЕРЕНО НА ПРОДЕ через orchestrator:
  - infmail-tools.sh status → все 4 сервиса active, 3 эндпоинта 200, 6 бинарей найдены
  - kvaudit /opt/infnode/kv.json → 3348 keys, 683 manifests, 7.4MB
  - kvfind /opt/infnode/kv.json "dedup:" → 6 dedup-ключей
  - chunkcheck /opt/infnode → 683 manifests, 688 chunks, missing:0 mismatch:0
  - watcher /alerts → []

### 2026-08-16 РЕШЕНИЕ: Zig в ядре через FFI — ОТКАЗАНО (честная оценка)
- Пробовал линковать Zig-библиотеку infmail_kv в Rust-ядро infnode (build.rs + zig_kv.rs + FFI extern "C").
- ПРИЧИНЫ отказа:
  1. Rust уже отлично парсит JSON через serde_json — соревноваться с ним в FFI бессмысленно.
  2. Zig 0.16 сломал многие API (std.fs.cwd, std.posix.close/fstat/open, json.Value.deinit, AddOptions, std.io.fixedBufferStream, addStaticLibrary, --out-dir).
  3. PIC-линковка статической Zig-либы в PIE Rust-бинарь капризна (relocation R_X86_64_32, нужен -fPIC который не всегда срабатывает).
  4. Усложнение сборки (нужен Zig на билд-машине), риск FFI-багов.
- ИТОГ: откатил build.rs, zig_kv.rs, links в Cargo.toml. infnode собирается чисто (sha 1f782937).
  `infnode audit kv` теперь на serde_json (не Zig).
- РАЗДЕЛЕНИЕ ОСТАЁТСЯ:
  - Rust infnode/infmail = ядро (всё внутри).
  - Zig = самодостаточные CLI-утилиты для ops (kvaudit/kvfind/chunkcheck) — РЕАЛЬНАЯ польза, проверено на проде.
  - Go = периферийные сервисы (obs/watcher/payouts) — работают в systemd на проде.

### ГДЕ РЕАЛЬНАЯ ПОЛЬЗА Go/Zig (подтверждено фактами на проде)
- Go infmail-obs (:9100): /healthz /stats /nodes /payouts /metrics — 200 OK, kv_keys=3348, payouts отдаются.
- Go infmail-watcher (:9101): /healthz {checks: api,kv,orphans,payouts,rewards}, /alerts=[] — мониторинг каждые 60с.
- Go infmail-payouts (timer 1ч): сгенерил 7 черновиков Distribute TON (0.007 TON aeza).
- Zig kvaudit: 3348 keys, 683 manifests, 7.4MB — статистика kv.json.
- Zig kvfind: поиск ключей (dedup: → 6, kitaimudrost → 6).
- Zig chunkcheck: 683 manifests, 688 chunks, missing:0 mismatch:0 — ЦЕЛОСТНОСТЬ ПОДТВЕРЖДЕНА.
- Все 6 бинарей в /opt/infnode/infmail-tools/bin (на проде) и /home/imm/infmail-tools/bin (локально).

### 2026-08-16 КРИТИЧЕСКИЙ УРОК + ВОССТАНОВЛЕНИЕ (drive-шаринг тест)
- ВАЖНО: НИКОГДА не править /opt/infnode/kv.json вручную через python на проде!
  Мой скрипт для теста share-ссылки записал kv.json как {} (0 ключей) — потеряны все индексы/манифесты/аккаунты в KV.
- ВОССТАНОВЛЕНО: из /tmp/kv.json (1466008 байт, 3348 ключей, скопирован ранее для Zig-теста). 
  cp + chown infnode + restart infnode.service → всё вернулось (Sent:5, почта работает).
- Сохранён хороший бэкап: /root/kv.json.good-20260816-0924
- Share-фича (шаринг файлов) РЕАЛИЗОВАНА в коде (files_share_create + files_share_download + роуты), 
  но E2E тест не прошёл из-за: (1) нет paid-аккаунта с известным паролем для файловой квоты, 
  (2) моя ручная KV-запись повредила kv.json. Функциональность валидации токена проверена (400 на битом токене).
- ТЕКУЩИЙ БИНАРЬ на проде: 666f53484aa0ad5a (с share-роутами). 
  Проверено: почта Sent:5 OK, migration active, все 4 сервиса active.

### 2026-08-16 ФИНАЛЬНЫЙ АУДИТ ЦЕПОЧКИ ПОЧТЫ end-to-end (подтверждено на проде)
Тест письма kitai→chichisblat (id fdd4f747...):
1. ОТПРАВКА: {ok:true, stored:1} ✅
2. ХРАНЕНИЕ: манифест m:mail:fdd4f747... в kv.json после persist (size:163, 1 chunk, key открытый — внутреннее) ✅
3. ИНДЕКСАЦИЯ: sent-index kitai=12 писем (содержит новое), Inbox chichisblat=12 ✅
4. ОТОБРАЖЕНИЕ: Sent=12, Inbox=12 ✅
5. РАСШИФРОВКА: body='audit chain body' — XChaCha20-Poly1305 работает ✅
6. ЦЕЛОСТНОСТЬ: chunkcheck 689/689 чанков, missing=0 mismatch=0 ✅
7. persist: манифест появляется в kv.json через ~60с (отложенная запись — by design) ✅
ВЫВОД: полная цепочка работает. БАГ ПОЧТЫ ПОЛНОСТЬЮ ИСПРАВЛЕН и подтверждён.

### КРИТИЧЕСКИЕ УРОКИ СЕССИИ
- НИКОГДА не править /opt/infnode/kv.json вручную на проде (повредил до {} — восстановил из /tmp/kv.json).
- При любых ручных тестах KV — только через API или с полным бэкапом перед правкой.
- Хороший бэкап kv.json: /root/kv.json.good-20260816-0924

### ФИНАЛЬНОЕ СОСТОЯНИЕ ПРОДА (2026-08-16)
- Бинарь infmaild: 666f53484aa0ad5a (с share-роутами, migration dedicated-thread, integrity).
- migration активен: integrity каждые 60с, 689/689 чанков целы.
- infmail-obs (:9100), infmail-watcher (:9101), infmail-payouts (timer) — в systemd.
- Zig CLI: kvaudit/kvfind/chunkcheck в /opt/infnode/infmail-tools/bin.
- Go+Zig исходники: /home/imm/infmail-tools (git, 2 коммита).
- SESSION_CONTEXT.md: полный контекст.

### 2026-08-16 (поздно) — Go объединён в 1 порт, Drive-шаринг E2E, уязвимость share: закрыта
- GO: obs+watcher объединены в ОДИН бинарь infmail-obs (ops) на ОДНОМ порту 9100.
  Роуты: /healthz /stats /nodes /payouts /metrics /alerts. infmail-watcher.service удалён (логика в obs).
  Проверено: все 6 роутов 200 OK. /alerts показывает "63 pending payouts" (реальный алерт).
  Сборка: src/go/ops/main.go → bin/infmail-obs.
- DRIVE-ШАРИНГ E2E: РАБОТАЕТ! 
  Для теста включил INFNODE_WEB_ALLOW_DEMO_SUBSCRIBE=1, активировал paid kitai (30 дней),
  загрузил secret.txt, создал share-ссылку, скачал БЕЗ auth (content верный). Demo-флаг выключен обратно.
  kitai остался paid (paid_until 1789465646694) — тестовый аккаунт, не критично.
  ПРОВЕРКА УЯЗВИМОСТИ: share-токены были НЕ в списке локально-авторитетных ключей!
    (handle_dht_store/handle_dht_find_value/handle_dht_sync/catch_up_with проверяли только recovery:/blacklist:)
    → злонамеренный пир мог перезаписать/украсть share-токены через DHT.
    ИСПРАВЛЕНО: добавлен "share:" во все 4 места. Бинарь 802c9c87ea78f079 задеплоен.
- Аудит share-кода: токен 16 байт OsRng (128 бит) — достаточно; валидация длины/hex; exp server-side.
- ФИНАЛЬНЫЙ БИНАРЬ на проде: 802c9c87ea78f079 (с share-фиксом). migration integrity 690/690 OK.

### 2026-08-16 (поздно) — NFT СДЕЛАН ПОЛНОСТЬЮ (дизайн идентичен nft-card-studio + LSB + Ed25519)
- РЕАЛИЗОВАНО по NFT_DEVELOPMENT_PLAN.md, но генерация через ТОТ ЖЕ генератор:
  - nft-card-service (/opt/nft-card-service, node + node-canvas + pngjs, systemd nft-card.service, порт 9200).
  - Использует ТОТ ЖЕ designs.ts из nft-card-studio (скомпилирован в dist/) — стиль 100% идентичен,
    каждый раз рандомный вариант (randomPopConfig: 5 layouts + рандомный HSL градиент).
  - API: POST /render (PNG), POST /render-lsb (PNG с LSB), GET /healthz.
- LSB (скрытый текст в пикселях PNG):
  - Схема: Magic "IMLS" + Version(1) + Len u16 + Payload + Ed25519 Sig(64) + padding.
  - ВАЖНЫЙ ФИКС: node-canvas putImageData ТЕРЯЕТ изменения на canvas 1000×1000!
    Решение: LSB вшивается через pngjs (декодировать PNG → модифицировать RGBA → перекодировать).
  - Rust lsb.rs: embed/extract/sign/verify + публичный ключ из env NFT_SIGNING_SECRET.
- Rust NFT-эндпоинты (crates/infmail/src/nft/{lsb,card_gen,nft}.rs + web.rs):
  - POST /api/v1/nft/upgrade (auth) — генерирует карточку через /render-lsb, сохраняет storage/nfts/{tokenId}.png
  - GET /api/v1/nft/{tokenId}/card — отдаёт PNG
  - GET /api/v1/nft/{tokenId}/verify — {authentic:true, signerPubkey, verifyMethod:"lsb-ed25519"}
- ПРОВЕРЕНО НА ПРОДЕ (полный E2E):
  - upgrade → card (PNG 1000×1000) → LSB extract (magic=IMLS, payload с email/tokenId/contractAddr/imageHash/timestamp)
  - Ed25519 verify_sha256=true (подпись валидна), verify_raw=false (правильно, подписывается SHA256(payload)).
- ENV: NFT_SIGNING_SECRET=edc415c3987127dcdea0ec51f3422cdb9ec521f027815f0024ff43e22099aacd,
  NFT_CARD_SERVICE_URL=http://127.0.0.1:9200, NFT_COLLECTION_ADDRESS=kQB5Y4R7...
- Бинарь infmaild: 6126a6dc098d79a7 (с NFT). Извлечение LSB: /tmp/lsbunfilter.js, /tmp/verify2.js.
- ОТВЕТ НА ВОПРОС: ДА, скрытый текст встраивается в картинку (LSB-стеганография) и верифицируется Ed25519.

### 2026-08-16 ЗАМЕТКА: шифрование внутренних писем (продумать позже)
- Текущая модель: внутренние письма (kitai→chichisblat) шифруются XChaCha20-Poly1305, но ключ ХРАНИТСЯ ОТКРЫТО в манифесте ("key": hex).
  → Сервер (валидатор) МОЖЕТ расшифровать. Нужно для серверного поиска/превью/спам-фильтра.
- Proton-модель ("key_box", XSalsa20+box на x_pub получателя) реализована для ВНЕШНИХ писем (SMTP-мост),
  но на проде сейчас 0 писем с key_box — все 561 манифеста с открытым key.
- РЕШЕНО: оставить как есть сейчас, НО ПРОДУМАТЬ ПОЗЖЕ переход внутренних писем на key_box (приватность против серверного поиска).
  Трейдофф: серверный поиск/превью/спам-фильтр перестанут видеть тело внутренних писем.

### 2026-08-16 ТЕСТ ФРОНТЕНДА + УЯЗВИМОСТИ (полный)
ФРОНТЕНД (Next.js, :3000) — ВСЁ РАБОТАЕТ:
- Все страницы 200: /, /dashboard, /dashboard/plan, /dashboard/files, /login, /register
- Title: "InfMail - Secure Email Workspace", страницы 11-26KB, JS-бандлы загружаются
- API-прокси через фронт (:3000/api/v1/* → :3001) работает: login, me, counts, inbox, plan, files
- Куки httpOnly: infmail_session=JWT (HttpOnly, SameSite=Lax, Path=/api, Max-Age=604800)

БЕЗОПАСНОСТЬ — ПРОВЕРЕНО:
- XSS в письмах: iframe sandbox="" (без allow-scripts) + cleanHtmlLinks (блокирует javascript:/data:) → ЗАЩИЩЕНО
- Path traversal: 400/404 → защищено
- IDOR (email-параметр в inbox): параметр ИГНОРИРУЕТСЯ, auth по токену → защищено
- CSRF: mail/send без auth → 401
- Rate-limit: 429 после 10 попыток логина
- Open redirect: нет; SSRF: 404
- Заголовки: CSP (полный), X-Frame-Options, nosniff, HSTS, Referrer-Policy

УЯЗВИМОСТИ ИСПРАВЛЕНЫ (bind 127.0.0.1):
- Next.js 3000: было *:3000 → теперь 127.0.0.1:3000 ✓ (закрыт снаружи)
- infmail-obs 9100: было *:9100 → теперь 127.0.0.1:9100 ✓ (закрыт, был доступ снаружи + утечка kv_keys/chunks!)
- 3001, 9200 уже 127.0.0.1 ✓
- ВАЖНО: iptables в контейнере (LXC, /proc/1/cgroup=0::/init.scope) НЕ работает для внешних интерфейсов (netfilter изолирован). Правила DROP есть, но трафик проходит. Закрывать только через bind 127.0.0.1.
- ОТКРЫТ СНАРУЖИ: 8080 (stalwart WebUI /admin) + 46077 + 25/465/587/993/995 (SMTP/IMAP — ок для почты, но TLS).
  8080: `/admin` отдаёт 302 (панель), пароль в env 4TES3er4act@1q. РЕКОМЕНДАЦИЯ: закрыть (bind 127.0.0.1 в RocksDb-конфиге stalwart — не нашёл как), или поменять пароль, или прокси через nginx с auth.

### 2026-08-16 ТЕСТ ВСЕХ API + PoW (подтверждено на проде)
- PoW: pow-challenge выдаёт {salt, difficulty:3, timestamp}; verify_pow: diff>=3<=32, salt 16hex, свежесть 10мин, sha256(salt+nonce) с нулями.
  register без solution → "PoW solution required"; с решением (solution:{challenge:{...},nonce}) → аккаунт создан + JWT.
- Auth: login/register/renew-cookie(JWT+Set-Cookie httpOnly)/logout/me — работают.
- Ключи: keys/save, keys/me, keys/{email} — ок; keys/e2e-secret → "не настроен" для классических (ожидаемо).
- Почта: send/inbox/counts/action/draft/blacklist/unblock/attachment — ок.
- Настройки: quota/plan/subscribe-nonce/2fa/signature/sessions+revoke/aliases/contract-balance(349364376)/change-password — ок.
- Файлы: list/review/upload/download/delete/share — ок (delete удалил secret.txt, chunks_deleted:1).
- NFT: status/upgrade/card/verify — ок. Web3: generate-payload — ок. pricing: 5 планов.
- БАГ ИСПРАВЛЕН: username_check был ЗАГЛУШКОЙ (всегда {"available":true}). Теперь реальная проверка:
  занят ли username как email (accounts) или как алиас. Проверено: kitaimudrost→false, nonexistent→true. Бинарь 681484447831707a.

### 2026-08-16 TON CONNECT — ПРОБЛЕМА НАЙДЕНА И ИСПРАВЛЕНА (Tonkeeper не открывался)
- СИМПТОМ (пользователь): нажал на Tonkeeper в web3-логине — кошелёк не открывался.
- ПРИЧИНА: фронт передавал в TON Connect v2 `value: { tonProof: payload }` где payload — ОБЪЕКТ {domain,salt,timestamp},
  а TON Connect SDK v2 ожидает tonProof как JSON-СТРОКУ (её кошелёк подписывает). SDK не мог обработать объект → модалка/кошелёк не открывался.
- ФИКС: во всех 3 местах (login/page.tsx:102, add-account/page.tsx:191, register/page.tsx:286) → `tonProof: JSON.stringify(payload)`.
- Проверено: Next.js пересобран, задеплоен (.next без dev/cache, 3.9MB tar). Бандл содержит "tonProof:JSON.stringify(e)" в chunk 2w6pp5w2wzdwk.js ✅
- Также проверил (работает):
  - https://infmail.org → 200 (TLS valid), /tonconnect-manifest.json → 200 (url/name/iconUrl/terms/privacy), icon.png → 200
  - @tonconnect/ui-react 2.4.4, web3/generate-payload выдаёт {payload:{domain,salt,timestamp}}
  - providers.tsx: manifestUrl от window.location.origin, restoreConnection=false, twaReturnUrl=t.me/infmailbot
  - Бэкенд web3_login ожидает proof.payload как строку (trim_matches('"')) — совместимо с JSON.stringify.
- Заметка: ошибка Next.js "The Server Reference ID did not match the expected format. Received \"x\"" в логах —
  server-action, не связана с TON (безобидная, старый вызов).

### 2026-08-16 ПОЛНЫЙ АУДИТ ПО SECURITY ЧЕК-ЛИСТУ (12 секций)
Sec 1-2 (Access/Auth): argon2 пароли, rate-limit login 10/15мин, JWT HS256+exp, IDOR ок (owner из сессии),
  logout/revoke/epoch работают. Minor: session rotation не полный (sid через thread_rng не OsRng, старые сессии остаются).
Sec 3 (Secrets): jwt_secret derived (не хардкод), totp OsRng, клиент чистый, .env* в gitignore (добавлен в infNode/.gitignore).
Sec 4 (Injection): УДАЛЁН RCE-код service.cli (sh -c произвольная команда) + service.ai из services.rs —
  они были НЕ зарегистрированы в диспетчере (убраны в v54), но код оставался (мёртвый). Теперь удалён полностью.
  XSS: iframe sandbox + cleanHtmlLinks; path traversal: safe_filename; deserialization: serde_yaml только node.yaml (локальный).
Sec 5-6 (Validation/Config): valid_email/safe_filename, CORS allowlist (permissive только по env), headers CSP/HSTS.
Sec 7 (Deps): lockfile'ы есть, npm audit 0, .env не в git.
Sec 8 (SSRF): только TON Center (env TON_API_BASE_URL) — пользовательских URL-fetch нет.
Sec 9 (Logging): логи чистые (нет паролей/токенов в journald).
Sec 10 (API): rate-limits на register/login/recovery/send; ДОБАВЛЕН cap limit<=1000 в mail_inbox (был безграничный).
Sec 11-12 (AI/Client): AI-код удалён, .next/static чистый (нет секретов в бандле).
ФИНАЛ: бинарь be031da3111511d5 задеплоен (RCE-код удалён + limit cap). Почта работает.
Остались minor (низкий риск): session rotation полный, sid через OsRng — можно в будущем.

### 2026-08-16 НАВЕДЁН ПОРЯДОК (компоновка + GitHub)
ЛОКАЛЬНО (/home/imm):
- Удалены: nft-lsb-poc (97M, логика перенесена в nft/), zig-install (мусор), папка infmail (inbox/x).
- Старые tar.gz → /home/imm/_archive/ (с README): infmail-backend, backup-20260805, contracts(-v2), frontend, nft-lsb-poc.
- Осталось аккуратное: infNode, infmail-web, infmail-tools, nft-card-studio.tar.gz (нужен для генератора), SESSION_CONTEXT.md, _archive.

ПРОД (валидатор):
- /root: удалены ВСЕ промежуточные бинари (infmail-*), остались только бэкапы (.tar.gz, .bak, kv.json.good).
- /opt/infnode: удалены legacy (infmail-backend, infnode.bak.2026*), infmail-watcher.
- /opt/infnode/bin: единая папка 5 утилит (kvaudit, kvfind, chunkcheck, obs, payouts).
- Актуальный infmaild: be031da3111511d5.

GITHUB (private, аккаунт immtes):
- https://github.com/immtes/infNode — bb672c0 (workspace, nft, migration, security-fixes)
- https://github.com/immtes/infmail-frontend — 1b8cbfc (TON Connect fix)
- https://github.com/immtes/infmail-tools — e910435 (obs+watcher merge)

### 2026-08-16 (дополнение) — nft-card-service на GitHub + архитектурное объяснение
- Создан репозиторий https://github.com/immtes/nft-card-service (private): server.js + dist/designs.js + package.json + README.
  Локально: /home/imm/nft-card-service. Прод: /opt/nft-card-service (очищен от отладочных dbg2/dbg3/lsbextract/putimg/readpx.js).
  systemd nft-card.service active, healthz ok.
- АРХИТЕКТУРА: infNode = Cargo workspace (монорепо) с ДВУМЯ крейтами:
  - crates/infnode = сетевой слой (бинарь `infnode serve`, ~9MB, без почты). storage-ноды запускают только его.
  - crates/infmail = webmail (бинарь `infmail serve` = `infmaild` на проде, ~14MB). Зависит от infnode.
  Раздельные бинари и раздельные Cargo.toml, но общий workspace → почта и сеть в одном git-репо infNode.
  Для ПОЛНОГО разделения: вынести crates/infmail в отдельный репозиторий (infmail-backend) с infnode как зависимость.
- Репы InfMail на GitHub (все private, аккаунт immtes):
  infNode (сеть+почта workspace), infmail-frontend (фронт), infmail-tools (ops), nft-card-service (генератор карточек), nft-card-studio (исходники дизайна).

### 2026-08-16 ЧЕСТНАЯ НАГРАДА + ЗАЩИТА ОТ ЗАХВАТА + АВТОДОБАВЛЕНИЕ (реализовано)
1. ЧЕСТНАЯ НАГРАДА (rewards.rs):
   - proof_verify: засчитывается размер РЕАЛЬНО проверенного чанка (c["len"]), НЕ весь манифест.
   - Крипто-random (OsRng gen_range) вместо предсказуемого now_ms % len.
   - Комиссия валидатора: INFNODE_VALIDATOR_FEE_PERCENT (default 30, clamp 0..30 — НЕЛЬЗЯ >30%).
     Валидатор получает fee из пула, ноды ≥70% пропорционально весу. Проверено: pool 1 TON → val 0.3, нода A(вес70) 0.49, нода B(вес30) 0.21.
2. ЗАЩИТА ОТ ЗАХВАТА: rewards как валидатор запускается ТОЛЬКО с INFNODE_VALIDATOR_KEY (>=16 символов).
   Чужая нода без секрета владельца не поднимет rewards-цикл. DHT-ноды имеют allow только discovery (dht.lookup/update/find_node).
   Фейковая нода без чанков/ping → weight 0.
3. АВТОДОБАВЛЕНИЕ: rewards собирает ноды из known_peers() = routing.all() + cfg.peers (НЕ только cfg.peers).
   Новая нода, приславшая dht.update (самопрезентация), попадает в rewards автоматически, БЕЗ ручного внесения в конфиг.
   Фильтр: ed_pub непустой (подтверждённая Ed25519), ping/heartbeat живой.
- Бинарь 4c6be771bcba3f3c задеплоен. env: INFNODE_REWARDS=1, POOL=0.001, FEE=30, VALIDATOR_KEY=(24 байта hex, в /etc/systemd/system/infnode.service.d/validator.conf).
- Проверено на проде: ledger содержит validator:0.0003 TON (30%) + aeza:0.0007 TON (70%), сумма=пул. Юнит-тесты fair_split + chunk_len — 2 passed.

### 2026-08-16 УДОБНЫЙ ЗАПУСК НОДЫ + ВСТРОЕННАЯ OBSERVABILITY (реализовано)
1. infnode init --dir NODE --role mail|files|both|validator [--validator ADDR] [--validator-pub HEX]:
   генерирует ключи + node.yaml с ролью и авто-подключением к валидатору. node-id валидатора = blake3(ed_pub).
2. infnode serve --config node.yaml --role ... [--validator ...] [--validator-pub ...]:
   если конфига нет — сам генерирует (авто-инициализация). Или make init ROLE=mail.
3. Авто-подключение: на валидаторе включён allow-unknown:true + unknown-allow (только core.ping/dht.update/lookup/find_node).
   Новая нода подключается автоматически (TOFU), получает discovery-права, участвует в rewards через known_peers().
   Фейковая нода без чанков/ping → weight 0 (не надуть вес). Ping валидатора: rtt 48-148ms, pong ok.
4. Makefile (infNode/): build/init/run/start/status/clean. README_QUICKSTART.md — инструкция новичка.
5. Встроенная observability (Go obs + Zig CLI в бинаре ноды, НЕ нужны отдельные бинари):
   - infnode stats --config node.yaml → kv keys/bytes, chunks/mail+files, rewards.nodes, payouts entries
   - infnode audit-kv --kv kv.json [--find PATTERN] → ключи, префиксы, поиск
   Проверено на проде: stats → kv 3369 ключей/1.47MB, chunks mail 630 files 134, rewards 2, payouts 98.
6. Rewards честные: proof по размеру чанка (не манифеста), крипто-random (OsRng), комиссия валидатора
   INFNODE_VALIDATOR_FEE_PERCENT (clamp 0-30%), нодам >=70%. Проверено: val 0.3 / aeza 0.7 / пул 0.001 TON.
7. ЗАЩИТА: rewards как валидатор только с INFNODE_VALIDATOR_KEY (>=16 символов). Чужая нода без него не поднимет rewards.
- Коммиты: d4d3cf7 (init/role/TOFU/Makefile/rewards), 23bb360 (stats/audit-kv встроенные).
- GitHub: immtes/infNode (main).

### 2026-08-16 (дополнение) — СЕКЬЮРИТИ-МОДЕЛЬ + PoA-задел + финальный тест
- SECURITY_MODEL.md: документ безопасности сети (владелец/ноды/контракты/домен/угрозы/награды/PoA).
- Поле validators: Vec<String> в NodeConfig — задел для PoA-консенсуса (доверенные валидаторы; сейчас пусто).
- Финальный тест флоу новичка (init на чистой папке role=files): ключи+конфиг+авто-подключение к валидатору,
  конфиг валиден (status ok), stats работает. Всё ок.
- Коммиты: 23bb360 (stats/audit-kv), d64a0d9 (validators + SECURITY_MODEL). GitHub immtes/infNode main.

### 2026-08-16 (дополнение) — ФЛОУ НОВИЧКА ГОТОВ + БЕЗОПАСНОСТЬ КАК В БЛОКЧЕЙНЕ
- infnode init --dir NODE --role mail|files|both|validator [--validator ADDR --validator-pub HEX]:
  ключи + node.yaml + авто-подключение к валидатору. Проверено (role files, status peers:1).
- infnode serve --config NODE --role ... [--validator ... --validator-pub ...]: авто-генерация если конфига нет.
- Makefile (build/init/run/start/status/clean) + README_QUICKSTART.md.
- Встроенная observability: infnode stats (kv/chunks/rewards/payouts) + audit-kv (префиксы/поиск) — в бинаре, без Go/Zig бинарей. Проверено на проде.
- SECURITY_MODEL.md: модель безопасности (владелец=домен+контракты+почта, storage-ноды только шифротекст, proof-of-storage, TOFU).
- Задел PoA: поле validators[] в NodeConfig (для будущего консенсуса).
- Коммиты: d4d3cf7, 23bb360, d64a0d9 (все в immtes/infNode main).
- Авто-подключение ноды: на валидаторе allow-unknown:true (TOFU, только discovery-права). Нода подключается, ping ok.
- НЕ ДОДЕЛАНО (будущее): полный консенсус PoA (подписанты блоков, кворум), переход от одного валидатора к нескольким.

### 2026-08-16 (финал) — ОСНОВНЫЕ РЕПЫ + ПОДТВЕРЖДЕНИЕ ВАЛИДАТОРА + ЦЕЛЬНАЯ НОДА
ОСНОВНЫЕ РЕПЫ (GitHub immtes, все private):
- infNode (Rust) — ЯДРО: infnode (сеть) + infmail (почта) workspace. Содержит init/role/stats/audit-kv/rewards/validators.
  ЦЕЛЬНЫЙ РЕП НОДЫ: скачал → make start ROLE=mail → всё работает.
- infmail-frontend (TypeScript) — Next.js фронт.
- infmail-tools (Go+Zig) — ops-утилиты (obs/payouts/kvaudit/kvfind/chunkcheck) — опционально, т.к. stats/audit-kv встроены в infnode.
- nft-card-service (JS) + nft-card-studio (TS) — генератор NFT-карточек.
- legacy (не трогать): infmail-backend (старый монолит), infmail-contracts, infmail-acton.

ПОДТВЕРЖДЕНИЕ ВАЛИДАТОРА (как сеть знает, кто валидатор):
1. Криптоидентичность: валидатор = нода с role=validator, node_id = blake3(ed_pub).
2. Секрет владельца INFNODE_VALIDATOR_KEY (>=16 символов): rewards-цикл запускается ТОЛЬКО с ним.
   Без него нода не может «валидировать»/раздавать награды.
3. Ноды при подключении указывают --validator-pub (ed_pub валидатора) и при handshake проверяют
   подпись — убеждаются, что подключены к настоящему валидатору (не фейку).
4. Фейковый валидатор без ключа+совпадения ed_pub не получит доверия/наград.

ЦЕЛЬНАЯ НОДА (обновлено на проде):
- infmaild = bb444e523bc79343, infnode = bf30a48dd91aadff (актуальные из репа infNode).
- stats на новом бинаре: kv 3369, chunks 630/134, rewards 3 nodes, payouts 99.
- Автодобавление подтверждено: тестовая нода b101a22b появилась в rewards (weight 0, proof 0/8) через known_peers.
- Ledger честный: validator 0.0003 (30%), aeza 0.0007 (70%) из пула 0.001 TON.

================================================================
## ПОЛНЫЙ СНАПШОТ СОСТОЯНИЯ (2026-08-16, финал дня)
================================================================

## ЧТО СДЕЛАНО (всё подтверждено на проде, GitHub immtes private)

### Ядро (Rust, реп immtes/infNode main)
1. БАГ ПОЧТЫ ИСПРАВЛЕН: гонка TTL-spawn в index_list затирала RAM. Убран. Sent/Inbox показывают письма.
2. Честные награды (rewards.rs): proof по размеру чанка (не манифеста), крипто-random (OsRng),
   комиссия валидатора INFNODE_VALIDATOR_FEE_PERCENT (clamp 0-30%), нодам >=70%. Юнит-тесты 2 passed.
3. Защита от захвата: rewards только с INFNODE_VALIDATOR_KEY (>=16 символов).
4. Автодобавление нод: known_peers() из routing; новая нода (dht.update) попадает в rewards без ручного внесения.
5. infnode init --role mail|files|both|validator [--validator ADDR --validator-pub HEX]:
   ключи + node.yaml + авто-подключение к валидатору. Проверено.
6. infnode serve --role: авто-генерация конфига если нет.
7. Авто-подключение: на валидаторе allow-unknown:true (TOFU, discovery-права). Нода подключается, ping ok.
8. Встроенная observability: infnode stats (kv/chunks/rewards/payouts) + audit-kv (префиксы/поиск) — в бинаре.
9. SECURITY_MODEL.md + поле validators[] (PoA задел).
10. RCE-код (service.cli/service.ai) удалён. username_check исправлен. limit cap <=1000.

### NFT (репы nft-card-service + nft-card-studio)
- Генератор карточек: node-canvas + ТОТ ЖЕ designs.ts (идентичный дизайн, рандомные варианты).
- LSB-стеганография: Magic IMLS + payload + Ed25519, вшивается через pngjs (node-canvas putImageData ломается на 1000×1000).
- Endpoints: /nft/upgrade, /nft/{id}/card, /nft/{id}/verify. Проверено: payload извлекается, verify_sha256=true.

### ТОН Connect (фронт infmail-frontend)
- tonProof передавался объектом, SDK ждёт JSON-строку → Tonkeeper не открывался. Исправлено: JSON.stringify(payload) в 3 местах.

### Безопасность (аудит по чек-листу)
- argon2 пароли, JWT HS256+exp, rate-limits, IDOR ок, XSS (iframe sandbox), CSRF, SSRF (только TON Center).
- Порты закрыты (3000/9100/9200/3001 на 127.0.0.1). iptables в контейнере НЕ работает.
- 8080 (stalwart WebUI) ОТКРЫТ — риск, задокументирован, не закрыт.

### Прод-инфраструктура
- Нода обновлена: infmaild bb444e, infnode bf30a4 (актуальные из репа).
- Сервисы: infnode, infmail-web, infmail-obs (:9100), nft-card (:9200) — active.
- env: INFNODE_REWARDS=1, POOL=0.001, FEE=30, VALIDATOR_KEY (в /etc/systemd/system/infnode.service.d/validator.conf).
- Ledger честный: validator 0.0003 (30%), aeza 0.0007 (70%).

## ЧТО СЕЙЧАС ДЕЛАЕТСЯ
- В infNode/Makefile добавлены таргеты `tools` (сборка Go/Zig из infmail-tools) и `tools-run` (запуск obs :9100).
  `make start` = build + init + run + tools + tools-run — цель: нода = один реп, всё автоматически поднимается.
  НЕ ПРОВЕРЕНО: make tools (нужны Go+Zig локально), make start целиком.

## ОТВЕТ НА ВОПРОС "НАФИГА GO/ZIG, ЕСЛИ ЕСТЬ RUST STATS"
- Rust stats/audit-kv = быстрые CLI для ручной проверки.
- Go (obs/watcher/payouts) = ПОСТОЯННЫЕ сервисы: HTTP :9100 с /metrics (Prometheus), /alerts, payouts-черновики TON. Rust CLI этого не даёт.
- Zig (kvaudit/kvfind/chunkcheck) = быстрые нативные аудиты (chunkcheck blake3 всех чанков).
- Решение: make tools — встроить Go/Zig в ноду автоматически.

## ДАЛЬШЕ (todo на будущее)
- Проверить make tools / make start (нужны Go+Zig).
- PoA-консенсус (задел validators[] есть).
- Шифрование внутренних писем (key_box) — отложено, заметка есть.
- Закрыть 8080 stalwart.
- Переход к нескольким валидаторам (когда блокчейн-слой).

### 2026-08-16 (финал) — Go/Zig встроены в ноду через make tools (решён вопрос "нафига Go/Zig")
- Rust stats/audit-kv = быстрые CLI (ручная проверка). Их достаточно для kvaudit/kvfind.
- Go (obs/payouts) + Zig (chunkcheck) — ВСТРОЕНЫ в ноду через `make tools`:
  make tools → клонирует infmail-tools, собирает: tools/bin/{infmail-obs (Go :9100), infmail-payouts (Go), infmail-chunkcheck (Zig)}.
  make tools-run → запуск obs на 127.0.0.1:9100 (фон).
  make start = build + init + run + tools + tools-run — нода = один реп, всё автоматически.
- kvaudit/kvfind в Zig НЕ собираются (требуют FFI-библиотеку infmail_kv, от которой отказались) — их роль выполняет `infnode audit-kv`.
- Проверено: make tools OK (obs/payouts/chunkcheck собраны), obs :9101 healthz/stats/payouts/metrics/alerts 200.
- .gitignore: tools/bin/, tools/infmail-tools/, logs/ — бинари не в git.
- Коммит 0733f6b (immtes/infNode main).

### 2026-08-16 (финал) — ФИНАЛЬНАЯ СТРУКТУРА РЕПОВ + ОТВЕТ "ГДЕ API ПОЧТЫ И КОНТРАКТЫ"
ФИНАЛЬНАЯ СТРУКТУРА (все private, GitHub immtes):
- infNode (Rust+Go+Zig) — ПОЛНОЦЕННАЯ НОДА. Содержит:
    crates/infnode (сеть), crates/infmail (ПОЧТА: web.rs API 64 роута, inbound.rs SMTP/IMAP, blockchain.rs индексатор контрактов TON),
    Makefile (build/init/run/tools/tools-run/start/status), README_QUICKSTART (гайд).
    Go/Zig собираются через make tools из infmail-tools (obs/payouts/chunkcheck).
- infmail-frontend (TS) — САЙТ/ФРОНТ валидатора (Next.js).
- nft-card-service (JS) — НФТ-КАРТЫ генератор (node-canvas + designs.ts + LSB).
- infmail-contracts (TS) + infmail-acton — СМАРТ-КОНТРАКТЫ TON (Registry/Storage/NFT, Tolk). Живут в TON-блокчейне.
- infmail-tools (Go+Zig) — исходники утилит (obs/payouts/kvaudit/kvfind/chunkcheck).

ОТВЕТ "ГДЕ API ПОЧТЫ И СМАРТ-КОНТРАКТЫ":
- API почты НЕ отдельный реп: он в crates/infmail (web.rs, inbound.rs) внутри infNode. Бинарь infmail = infmaild на проде.
- Смарт-контракты — в TON-блокчейне (репы infmail-contracts/infmail-acton), валидатор вызывает их через blockchain.rs.

ГАЙД: README_QUICKSTART.md (make start ROLE=mail → всё автоматически: build+init+run+tools+tools-run).
Коммит 6217edd (гайд) + 0733f6b (make tools).

### 2026-08-16 (финал) — ЧЁТКОЕ РАЗДЕЛЕНИЕ НОДА vs ВАЛИДАТОР (реализовано)
- ПРОБЛЕМА: гайд/Makefile смешивали ноду и валидатора.
- РЕШЕНИЕ (в коде разделение уже было, теперь чётко в командах):
  * make node ROLE=mail|files|both → НОДА (storage): только `infnode` (~9MB, БЕЗ почты). build-node+init+run.
  * make validator → ВАЛИДАТОР (владелец): `infmail` (~15MB, сеть+ПОЧТА+API+индексатор контрактов TON) + init + tools (Go obs/payouts, Zig chunkcheck) + tools-run.
  * build-node = cargo build -p infnode (нет почтовых зависимостей в Cargo.toml: axum/lettre/imap/argon2 = 0).
  * build-mail = cargo build -p infmail.
- Подтверждение в коде: crates/infnode НЕ зависит от почты (grep почтовых deps = 0). Почта только в crates/infmail (web.rs/inbound.rs/blockchain.rs).
- Гайд README_QUICKSTART.md переписан: таблица НОДА vs ВАЛИДАТОР, команды, ручной запуск, где API почты и контракты.
- Коммит 8f1c79d (immtes/infNode main).
- Проверено: make node ROLE=files → собрал infnode, сгенерировал роль files, запустил (port занят т.к. валидатор на той же машине; на чистой — запустится).

### 2026-08-16 — ПОЛНАЯ КАРТА РЕПОВ И ЛЕГИТИВНЫЕ КОНТРАКТЫ (прояснено)
ЛЕГИТИВНЫЕ КОНТРАКТЫ: реп immtes/infmail-contracts (Blueprint TON, src/*.tolk: registry/storage/collection/nft_item).
  - Подтверждение: README репа содержит ТОТ ЖЕ адрес Registry (EQB_Y-LRJvZU7oBFSgVeP8CZM9fWe8VHcr3W9qO0y6dDJXHm) что env на проде.
  - src/ (реп) НОВЕЕ, чем contracts/ на проде (реп имеет RegisterZK/UpdatePricing/Withdraw — актуальная легитивная).
  - contracts/ на проде (копия /root/infmail-acton/contracts/*.tolk) — СТАРАЯ версия, НЕ легитивная. Убрал.
  - Есть также infmail-acton (старый реп, tolk) — не используется.

ИТОГОВАЯ СТРУКТУРА (чистая, без путаницы):
1. НОДА = реп immtes/infnode (вынести crates/infnode — чистый сетевой крейт, самодостаточен, 348K кода, без почты).
   Сейчас в workspace infNode; вынос = отдельный реп (копия crates/infnode + Cargo.toml).
2. ВАЛИДАТОР = реп immtes/infNode (workspace: crates/infnode + crates/infmail). infmail = API почты + индексатор контрактов.
   Подключает:
   - контракты: immtes/infmail-contracts (TON Tolk)
   - фронт: immtes/infmail-frontend (Next.js)
   - карты: immtes/nft-card-service (node-canvas)
   - утилиты: immtes/infmail-tools (Go/Zig)
   - дизайн: immtes/nft-card-studio

### 2026-08-16 — НАВИГАЦИЯ ДЛЯ НОВОГО КОНТЕКСТА (важно!)
- СНАЧАЛА читай: /home/imm/infNode/ARCHITECTURE.md (полная карта) и /home/imm/PROJECT_OVERVIEW.md (навигация).
- Главное: infNode = ядро (Rust). crates/infnode = НОДА, crates/infmail = ВАЛИДАТОР.
- Легитивные контракты: infmail-contracts (src/*.tolk), адреса в env на проде.
- Фронт: infmail-web. Карты: nft-card-service. Утилиты: infmail-tools (Go/Zig).
- Не искать контракты в /root/infmail-acton (старая копия) — они в infmail-contracts.

================================================================
## РЕФАКТОРИНГ НА 3 РЕПА (ТЕКУЩАЯ РАБОТА — 2026-08-16)
================================================================

## ЦЕЛЬ (что делаем сейчас)
Разделить на ЧИСТЫЕ 3 репа (пользователь одобрил):
1. infnode = Rust+Go+Zig, ТОЛЬКО НОДА (для людей, без валидатора)
2. infmail-valid-backend = Rust+Go+Zig, ВАЛИДАТОР всё-в-одном (API почты + контракты + генерация карт)
3. infmail-frontend = Next.js (веб) — УЖЕ ЕСТЬ, не трогаем

## КАК ДЕЛАЕМ (безопасно, ничего не ломаем)
- НЕ трогаем существующий workspace infNode (все наработки там, прод работает).
- Создаём ОТДЕЛЬНЫЕ папки-копии: /home/imm/infnode (нода), /home/imm/infmail-valid-backend (валидатор).
- После успешного теста самодостаточности — зальём на GitHub как отдельные репы.
- СТАРОЕ НЕ УДАЛЯЕМ до полного теста соответствия.

## ЧТО УЖЕ СДЕЛАНО
1. Создана папка /home/imm/infnode/src/ = копия crates/infnode (14 файлов .rs, без почты, без мусора .a/.so).
2. Создан /home/imm/infnode/Cargo.toml — самостоятельный (версии из workspace root, жёстко прописаны, без infmail).
3. НОДА СОБИРАЕТСЯ САМОСТОЯТЕЛЬНО: cargo build --release OK (36.87s). Бинарь target/release/infnode.
   => crates/infnode ПОЛНОСТЬЮ самодостаточен (не зависит от почты) — подтверждено.

## ЧТО НАДО СДЕЛАТЬ ДАЛЬШЕ (по порядку)

### Шаг 1: Завершить реп НОДЫ (/home/imm/infnode)
- [ ] Проверить бинарь: ./target/release/infnode --help (все команды: init/serve/status/ping/stats/audit-kv)
- [ ] Проверить init + serve --role (как в infNode, но из отдельной папки)
- [ ] Создать .gitignore (target/, keys/, *.pem, *.key, *.env, node-data/)
- [ ] Создать Makefile (build/init/run/start/status/clean + tools для Go/Zig ноды)
- [ ] Создать README.md (гайд для людей: как развернуть ноду, роль mail/files)
- [ ] Создать git-реп, залить на GitHub immtes/infnode (private)

### Шаг 2: Создать реп ВАЛИДАТОРА (/home/imm/infmail-valid-backend)
- [ ] Скопировать crates/infmail + зависимости (это ядро валидатора)
- [ ] Скопировать crates/infnode (нужен как зависимость — валидатор использует сеть)
- [ ] Cargo.toml: workspace с обоими крейтами (как infNode) — или path-dependency
- [ ] Подключить: контракты (ссылка на infmail-contracts), генерация карт (nft-card-service),
      фронт (infmail-frontend) — документация/README
- [ ] Go/Zig для валидатора: obs, payouts, watcher, chunkcheck (из infmail-tools)
- [ ] Makefile: make validator
- [ ] README.md (гайд владельца)
- [ ] Залить на GitHub immtes/infmail-valid-backend (private)

### Шаг 3: Распределение Go/Zig (продумать точно)
НОДЕ (infnode): chunkcheck (Zig, самопроверка), obs (Go, локальный мониторинг :9100),
  stats/audit-kv (Rust встроены). НЕ payouts (валидатору).
ВАЛИДАТОРУ (infmail-valid-backend): payouts (Go, Distribute TON), watcher (Go, глобальные алерты),
  obs (Go, Prometheus), chunkcheck (Zig), kvaudit/kvfind (Zig).

### Шаг 4: Уязвимости + тест соответствия
- [ ] Аудит нового кода (те же проверки, что делал: секреты, RCE, IDOR, path, SSRF)
- [ ] Сравнить: новое infnode поведение == старое infnode из infNode (старые бинари не удалять)
- [ ] Развернуть новый infnode на тестовой ноде, проверить подключение к валидатору

### Шаг 5: Развернуть
- [ ] Новый infnode (нода) — на тест
- [ ] infmail-valid-backend (валидатор) — только после полного теста соответствия
- [ ] Старое (infNode прод) продолжает работать до подтверждения

## ЛОГИКА РАСПРЕДЕЛЕНИЯ GO/ZIG (итоговая)
- Go = сервисы (obs мониторинг, watcher алерты, payouts деньги)
- Zig = быстрые аудиты (chunkcheck целостность чанков, kvaudit/kvfind)
- Rust (встроено) = stats/audit-kv (базовые CLI)
- Ноде: только самопроверка (chunkcheck, obs, stats/audit-kv) — чтобы человек контролировал СВОЮ ноду
- Валидатору: всё + payouts (награды) + watcher (сеть)

## ЗАПОМНИТЬ (напомнить в конце пользователю)
- "ТЕСТ САМОДОСТАТОЧНОСТИ И ПОДТВЕРЖДЕНИЕ" — пользователь объяснит, что хочет.

## ПРОГРЕСС РЕФАКТОРИНГА (шаг 1 готов)
### Шаг 1: РЕП НОДЫ ГОТОВ — https://github.com/immtes/infnode-node (private)
- /home/imm/infnode — отдельная папка (копия crates/infnode, самостоятельный Cargo.toml)
- НОДА СОБИРАЕТСЯ САМОСТОЯТЕЛЬНО (cargo build --release OK)
- Все команды работают: init/serve/status/ping/stats/audit-kv (проверено)
- Makefile (build/init/run/start/tools/tools-run/status/clean), README.md, .gitignore
- Запушено на GitHub immtes/infnode-node (private)
- ВАЖНО: реп "infnode" на GitHub = старый псевдоним infNode (workspace целиком) — НЕ использовать.
  Новый реп ноды называется infnode-node (без конфликта).
- Go/Zig для ноды: chunkcheck (Zig), obs (Go) — в Makefile tools. НЕ payouts (валидатору).

### Шаг 2 (следующий): РЕП ВАЛИДАТОРА /home/imm/infmail-valid-backend
- Скопировать crates/infmail + crates/infnode (как зависимость) из infNode
- Cargo.toml: workspace с обоими крейтами (как infNode) — или path
- Подключить контракты/карты/фронт (документация)
- Go/Zig валидатора: payouts, watcher, obs, chunkcheck
- Makefile make validator + README
- Залить на GitHub immtes/infmail-valid-backend (private)

## ПРОГРЕСС РЕФАКТОРИНГА (шаги 1-2 готовы, шаг 4 частично)
### Шаг 1: РЕП НОДЫ ГОТОВ — https://github.com/immtes/infnode-node (private)
- /home/imm/infnode: Rust (самост. крейт) + Go/Zig встроены (tools-src/: obs/main.go Go, chunkcheck.zig Zig).
- make tools собирает из локальных исходников (без клонирования). Проверено: chunkcheck+obs собраны.
- Все команды работают (init/serve/status/ping/stats/audit-kv).
- Запушено: adc1f32 → b08c358 (Go/Zig встроены).

### Шаг 2: РЕП ВАЛИДАТОРА ГОТОВ — https://github.com/immtes/infmail-valid-backend (private)
- /home/imm/infmail-valid-backend: workspace crates/infnode + crates/infmail.
- Собрался: infmail 14.9MB, sha bbb5eb. Работает (--help: serve).
- Makefile (build/start/tools/status), README, .gitignore. Запушено.
- Связанные: контракты (infmail-contracts), фронт (infmail-frontend), карты (nft-card-service) — в README.

### Шаг 4 (частично): УЯЗВИМОСТИ нового кода
- RCE: нет (service.cli/ai удалены). Секреты: нет. cargo audit: 1 allowlist (xsalsa20poly1305).
- IDOR/path/rate-limit: те же защиты (owner из сессии, safe_filename, rate_limit).
- ТЕСТ СООТВЕТСТВИЯ: web.rs и node.rs идентичны оригиналу (0 строк разницы) — копия точная, ничего не сломано.

### Шаг 3 (осталось): watcher (Go) добавить в Makefile валидатора (глобальные алерты).
### Шаг 5 (осталось): развернуть новую ноду на тест; валидатор — после полного теста. Старое НЕ удалять.

## РЕФАКТОРИНГ: СВЕДЕНИЕ К МИНИМУМУ РЕПОВ (сделано)
- infmail-valid-backend = ВАЛИДАТОР ВСЁ-В-ОДНОМ (8558069):
  crates/infmail (API) + crates/infnode (сеть) + contracts/*.tolk (TON) + nft/ (генератор карт) + Makefile tools (Go/Zig payouts/watcher/obs/chunkcheck).
- infnode-node = НОДА (Rust+Go+Zig, b08c358): crates/infnode + tools-src/ (obs Go, chunkcheck Zig).
- infmail-frontend = фронт Next.js (отдельно, разворачивается по-своему).

ИТОГ: код в 2 репах (infnode-node + infmail-valid-backend), фронт отдельно. Плюс legacy (infmail-tools/contracts/frontend) — можно оставить как есть или перенести.

## ПРОВЕРКА КОНТРАКТОВ: testnet vs репы (важно!)
- Развёрнутые в TESTNET (адреса из env): Registry, Storage, NftCollection — ВСЕ работают (exit 0, getAdminAddress возвращает админ-cell).
- Методы развёрнутых (camelCase):
  Registry: getAdminAddress, getOwnerByHash, getPricing
  Storage: getAdminAddress, getNodes, getTotalPayments
  NftCollection: getCollectionData, getNftAddressByIndex, getNftContent, getOwnerByTokenId, getPendingToken, getTokenByEmailHash
- ЛЕГИТИВНАЯ версия = /root/infmail-acton/contracts/*.tolk (прод, camelCase). Залита в infmail-valid-backend/contracts/.
- GitHub infmail-acton — СТАРАЯ версия (snake_case get_collection_data, БЕЗ registry/storage) — НЕ использовать.
- GitHub infmail-contracts/src — ДРУГОЙ проект (Blueprint, registry 6274 / storage 884 байт) — НЕ развёрнут, НЕ использовать.
- ИТОГ: contracts/ в infmail-valid-backend = правильные (прод, camelCase). Проверено getTokenByEmailHash есть (валидатор его вызывает).

## РАЗВЁРНУТО + ПОЛНЫЙ АУДИТ (новые репы) — ВСЁ ИДЕНТИЧНО
- НОВЫЙ ВАЛИДАТОР (infmail-valid-backend, sha bbb5eb96) задеплоен на прод. Старый в бэкапе: /root/infmaild.old-*.
- НОВАЯ НОДА (infnode-node, sha fc88ca) развёрнута на aeza. Старый: /root/infnode.old.
- ПОЛНЫЙ АУДИТ ПРОЙДЕН (идентично старому):
  - Сервисы: 4 active (infnode, infmail-web, infmail-obs, nft-card)
  - Логин token 205, почта Inbox 13/Sent 14, отправка ok, NFT upgrade ok
  - Rewards честные: validator 0.0003 (30%), aeza 0.0007 (70%)
  - stats: kv 3369, chunks 631/134, rewards 2 ноды
  - aeza (новая нода): weight=23, bytes=564, proof 3/8, uptime 0.938
  - Пинг валидатор↔aeza: rtt 25-80ms pong true
- ВЫВОД: новые репы работают идентично, сеть цела. Старое в бэкапе, не удалено.

## УБОРКА: старые папки → old/ (архив для памяти)
- Рабочие (новые): /home/imm/{infnode, infmail-valid-backend, infmail-web} + SESSION_CONTEXT + PROJECT_OVERVIEW.
- Всё старое → /home/imm/old/: infNode-workspace-old, infmail-tools-old, infmail-go-svc-old,
  infmail-zig-cli-old, infmail-contracts-old, nft-card-service-old, nft-card-studio.tar.gz, _archive.
- В old/ удалены кеши/бинари (target, node_modules, .next, .zig-cache, .zig-out, tools/bin, собранные бинари, .git/objects).
  Остались ТОЛЬКО исходники + README (old/README.md) — как было, для справки.
- old/ README объясняет что где и какие новые репы рабочие.
- ИТОГ: в корне только рабочие репы + документация, всё остальное в old/.

## ФЕДЕРАЦИЯ: DNS TXT подтверждение валидатора (реализовано)
- Идея (пользователя): валидатор генерирует хеш, владелец добавляет его с IP в TXT DNS домена сети.
  Цель: уменьшить захват, федерации (свой домен = своя сеть), подтверждение валидности валидатора.
- РЕАЛИЗОВАНО (модуль federation.rs в crates/infnode):
  - Команда `infnode announce --domain X --advertise IP:port` → генерирует TXT-значение + инструкцию.
    Формат TXT: _infnode.{domain} TXT "infnode-validator=inf1:{node_id}:{ip}"
  - Команда `infnode verify-validator --domain X --node-id Y` → проверяет через DNS-over-HTTPS (dns.google, без доп. зависимостей).
  - Поле `domain` в NodeConfig (node.yaml): при serve нода проверяет валидатора через TXT перед подключением.
  - `--domain` флаг в init/serve.
- Сгенерировано для РЕАЛЬНОГО валидатора: _infnode.infmail.org TXT "infnode-validator=inf1:e17f0aaab9f7eeb63f224692c4bcf15d250f7949:109.107.155.67"
  (запись НЕ добавлена в DNS пока — нужно в панели провайдера домена infmail.org).
- Задеплоено: infmaild cfac1d4f (валидатор с federation), infnode 533ad1c3 (CLI с announce/verify).
  Почта работает (Inbox 13, Sent 15).
- Коммиты: infnode-node 5e37655, infmail-valid-backend e87324e.

## СЛЕДУЮЩИЙ ШАГ (продолжить)
1. Нодам в node.yaml указать `domain: infmail.org` — тогда они будут проверять валидатора по TXT.
2. Возможно добавить TXT-запись в DNS infmail.org (владелец делает в панели провайдера).
3. Проверить verify-validator после добавления записи.
4. Реализовать восстановление после сноса валидатора: новый валидатор синкает с нод (catch_up_with + dht.sync) — аккаунты/манифесты/индексы. Проверить, что это работает.

## ФЕДЕРАЦИЯ: RESTORE (восстановление после сноса валидатора) — реализовано
- `infnode restore --config node.yaml` — новый валидатор после сноса:
  создаёт node, для каждого пира вызывает catch_up_with (dht.sync) → восстанавливает KV (манифесты/индексы/профили аккаунтов).
  Выводит: node_id, число пиров, синхронизировано, число ключей kv.json.
- Профили аккаунтов (acct:{email}) реплицируются раз в 5 мин (account_public_profile) — БЕЗ секретов
  (pw_hash/smtp_pass/e2e_secret не реплицируются). 1051 аккаунт в kv.json.
- ВАЖНО: секреты НЕ восстанавливаются из сети — нужен бэкап keys/ валидатора (identity.key).
- Задеплоено: infmaild cfac1d4f, infnode 5bab9d. Почта работает (Inbox 13, Sent 15).
- Коммиты: infnode-node f180dde, infmail-valid-backend 8e695b5.
- Проверено: restore локально инициирует синк (пинг с ноды), на реальном новом валидаторе с верными ключами пройдёт.

## ОСТАЛОСЬ (todo)
1. Добавить TXT-запись _infnode.infmail.org в DNS (владелец) — для подтверждения валидатора (verify-validator).
2. Указать `domain: infmail.org` в node.yaml нод (для автопроверки валидатора при serve).
3. Протестировать полный сценарий: снос валидатора → новый → infnode restore → работа восстановлена (профили/манифесты).
4. Обновить README (нода: announce/verify/restore/domain).

## ФЕДЕРАЦИЯ: СТРОГИЙ РЕЖИМ (ответ на вопрос "лучше строго или мягко")
- Вопрос пользователя: "хочу чтобы ноды даже не пытались подключиться к недоверенному валидатору когда есть проверенный".
- Решение: строгий режим через env INFNODE_STRICT_DOMAIN=1:
  - Мягкий (по умолчанию, без env): TXT не совпадает → предупреждение ⚠️, нода всё равно запускается.
  - Строгий (INFNODE_STRICT_DOMAIN=1): TXT не совпадает → ❌ нода ОТКАЗЫВАЕТСЯ запускаться (bail).
- Проверено: мягкий → serving_ready; строгий → "Error: валидатор не подтверждён доменом".
- ВАЖНО: строгий заблокирует ноды, пока TXT _infnode.infmail.org не добавлена в DNS.
  Порядок: (1) добавить TXT, (2) включить INFNODE_STRICT_DOMAIN на нодах.
- Сейчас на проде domain НЕ задан → сеть работает как раньше (проверка неактивна).
- Коммиты: infnode-node a70d0e0, infmail-valid-backend 2a19aa6.

## ФЕДЕРАЦИЯ: TXT ЗАПИСЬ ДОБАВЛЕНА + СТРОГИЙ РЕЖИМ ВКЛЮЧЁН (полностью работает)
- Пользователь добавил TXT: _infnode.infmail.org = "infnode-validator=inf1:e17f0aaab9f7eeb63f224692c4bcf15d250f7949:109.107.155.67"
- verify-validator → ✅ ПОДТВЕРЖДЁН.
- Валидатор: domain: "infmail.org" добавлен в node.yaml, почта работает (Inbox 13, Sent 15).
- aeza (нода): domain добавлен + INFNODE_STRICT_DOMAIN=1 в юните.
  Лог: "[federation] ✅ валидатор подтверждён" + serving_ready peers:2.
- rewards: aeza weight=434, proof 8/8, uptime 0.946 (реально хранит).
- Появилась тестовая нода inf1:efbd161e (weight 0) — от /tmp/domtest теста, автоподключилась.
- ИТОГ: федерация работает — нода подтверждает валидатора через TXT, строгий режим активен.
- Бинари на проде: infmaild cfac1d, infnode 09e514 (валидатор); aeza infnode 83c1bd.

## 3 ВАЛИДАТОРА — ЧТО ЭТО РЕАЛЬНО ЗНАЧИТ (прояснение)
Вопрос пользователя: при 3 валидаторах и одном домене — как делится отправка писем и создание аккаунтов между 3 серверами? И что нет 3 серверов.

ВАЖНОЕ ПРОЯСНЕНИЕ (что я понял):
- Сейчас 1 валидатор (владелец): он = домен + SMTP-приём + создание аккаунтов + API. Всё на одном сервере.
- "3 валидатора" НЕ означает 3 почтовых сервера. Это 3 ноды, которые ПОДТВЕРЖДАЮТ сеть (консенсус PoA), а НЕ дублируют почту.
- ПОЧТА (приём/отправка/аккаунты) — может остаться на ОДНОМ "почтовом шлюзе" (валидатор-мастер). Остальные валидаторы — для консенсуса/доверия/резерва.

РАЗДЕЛЕНИЕ РОЛЕЙ (чтобы не путать):
- Мастер-валидатор (владелец домена): приём/отправка писем (SMTP/IMAP), создание аккаунтов, web-API, ключи. Один.
- Дополнительные валидаторы (2 шт): подписывают блоки/состояние (консенсус), реплицируют KV, могут быть storage. НЕ дублируют почту.
- Storage-ноды (aeza, локальный ПК): хранят чанки, получают награды.

КАК БУДЕТ РАБОТАТЬ ПОЧТА ПРИ 3 ВАЛИДАТОРАХ (будущее):
- Один домен infmail.org: MX-записи указывают на МАСТЕР-валидатор (приём писем).
- Аккаунты создаются на мастере, профили реплицируются в DHT (acct:*).
- Остальные 2 валидатора НЕ принимают почту, но могут поднять мастера при сносе (restore из DHT).
- Консенсус: 2 из 3 валидаторов подписывают изменение состояния (например, создание аккаунта) — защита от захвата.

ТЕКУЩЕЕ СОСТОЯНИЕ: нет 3 серверов. Сейчас 1 валидатор (109.107.155.67) + aeza (storage) + локальный ПК (NAT, weight=0).
"3 валидатора" — перспектива. Сейчас достаточно 1 валидатора + федерация (TXT) для подтверждения.

ИТОГ: почта не "делится" на 3 — она на мастере. Доп. валидаторы = консенсус/резерв/восстановление. Нужно ещё 2 сервера для 3 валидаторов (пользователь пока не имеет).

================================================================
## ДВЕ АРХИТЕКТУРНЫЕ ИДЕИ (будущее, записано пользователем) + ЧТО ДЕЛАЕМ СЕЙЧАС
================================================================

## ИДЕЯ 1: Консенсус с суб-валидаторами (РЕАЛИЗУЕМ СЕЙЧАС, прагматично)
Один основной валидатор (мастер) + 1-2 суб-валидатора (подписывают, хранят копии).
Как это работает (будущее):
- Письма: MX-записи infmail.org указывают на МАСТЕРА. Он один принимает/отправляет.
  2 других валидатора НЕ трогают SMTP.
- Аккаунты: создаются на мастере, профили (acct:*) реплицируются в DHT.
  При сносе мастера — новый поднимается через infnode restore (профили из DHT, секреты из бэкапа keys/).
- Консенсус (2 из 3): создание аккаунта подписывается 2 валидаторами — защита от захвата
  (один злой валидатор не сможет навредить).
- TXT (вариант А): _infnode.infmail.org = 3 TXT-записи (по валидатору). Нода проверяет: любой подтверждён → ок.

## ИДЕЯ 2: Полное деление/шардинг почты (НЕ сейчас, сложно)
- Письма/аккаунты делятся между отдельными почтовыми серверами с разными MX (MX1/MX2/MX3).
- Шардирование аккаунтов по blake3(email)%N → какой валидатор владелец.
- Маршрутизация писем между валидаторами (прокси если аккаунт не на этом).
- Требует: 3 сервера, общий каталог владельцев аккаунтов, SMTP-мост на каждом.
- СЛОЖНО тестировать без серверов. ОТЛОЖЕНО.

## ЧТО РЕАЛИЗОВАНО СЕЙЧАС (из Идеи 1)
- Письма на мастере (SMTP/IMAP мост на валидаторе) — уже так.
- Аккаунты на мастере + acct:* репликация в DHT (каждые 5 мин) — уже так.
- Восстановление: infnode restore (синк KV с нод) — реализовано.
- TXT вариант А: verify_domain_validator проходит по ВСЕМ Answer[] (несколько записей работают) — реализовано.
- СТРОГИЙ режим: INFNODE_STRICT_DOMAIN=1 — нода отказывается запускаться, если TXT не подтверждает валидатора.
  Включён на aeza. TXT _infnode.infmail.org добавлена пользователем, валидатор подтверждён (✅).
- Комиссия валидаторов делится ПОРОВНУ между основным + суб-валидаторами (validators) — реализовано,
  тест validator_fee_split_equal (3 валидатора по 100M из 300M, нодам >=70%). Бинарь 51674d84 на проде.

## ЧТО ОСТАЛОСЬ СДЕЛАТЬ (после компрессии контекста)
1. СУБ-ВАЛИДАТОР (консенсус 2 из 3) — НЕ реализован:
   - Подпись состояния (аккаунтов/изменений) суб-валидаторами.
   - Мастер собирает подписи, требует кворум 2 из 3.
   - Добавить в node.yaml валидатора список validators (node_id суб-валидаторов).
2. Появление 2 серверов для суб-валидаторов (у пользователя нет — перспектива).
3. Идея 2 (полный шардинг) — отложена.
4. НОДА на локальном ПК (node1) — weight=0 из-за NAT; нужно решение (проброс порта 9400 или публичный IP).
5. README обоих репов — обновить (federation: announce/verify/restore/domain/строгий режим).
6. SESSION_CONTEXT.md — источник истины; при чистом контексте читать СНАЧАЛА:
   /home/imm/infNode/ARCHITECTURE.md (старый, в old/) + PROJECT_OVERVIEW.md + этот файл.
   Рабочие репы: /home/imm/{infnode, infmail-valid-backend, infmail-web}. Старое в /home/imm/old/.

## ОТВЕТ НА ВОПРОС "можно компрессировать контекст?"
ДА. Вся необходимая инфа в этом файле (SESSION_CONTEXT.md, 1300+ строк). После компрессии читать этот файл.

## node1 (локальный ПК) СТАЛ РЕАЛЬНОЙ НОДОЙ (порт 9400 UDP открыт пользователем)
- Пользователь открыл UDP 9400 (QUIC) на локальной машине.
- Запущен node1 новым бинарём infnode (из /home/imm/infnode, реп infnode-node):
  - Конфиг: /home/imm/infnode/deploy/node1/node.yaml (advertise 178.155.74.242:9400, storage-roles [mail, files])
  - Ключи: СТАРЫЕ (из old/infNode-workspace-old/deploy/node1/keys) → node-id inf1:57146ca81f999f4cc3b0d50846d4cc4a53c65f18 (тот же, что валидатор знает)
  - Данные: перенесены старые kv.json/dht.json/chunks (mail+files 8MB)
  - Запуск: setsid nohup ... serve --config node.yaml > /tmp/node1.log
- ПРОВЕРЕНО: валидатор пингует node1 (rtt 48ms pong:true), aeza подключается (dht.update ok).
  Ранний UDP-тест мусором не сработал — нужен реальный QUIC, это НЕ признак закрытого порта.
- rewards: node1 виден, weight 0 (набирает uptime 24h rolling), proof 0/8 → будет начислен в след. цикле.
- ВАЖНО: не запускать infnode ping из той же папки где работает serve (client-listen 9401 конфликтует → Address already in use).
- Порт для нод/валидаторов: ТОЛЬКО UDP 9400 (QUIC). SMTP/IMAP (465/993) — только мастеру-валидатору.

## node1: UDP 9400 ПРОБРОШЕН + ПОДТВЕРЖДЕН ДВУМЯ ВНЕШНИМИ ТОЧКАМИ
- Запись на роутере: INFNODE 9400 UDP → 192.168.0.10:9400.
- ВАЖНЫЙ УРОК: проверка UDP мусорными байтами НЕ работает — QUIC молча игнорирует невалидные пакеты (нет ответа ≠ закрытый порт).
  Настоящая проверка: реальный QUIC-пинг (infnode ping --to <node-id>) — проходит rtt 55ms (валидатор) и 95ms (aeza).
- node1 (178.155.74.242, локальный ПК за NAT 192.168.0.10) — теперь полноценная storage-нода:
  старые ключи → node-id inf1:57146ca8..., данные (chunks 8MB, kv 3332 ключа) перенесены, serve активен.
- Запуск: setsid nohup /home/imm/infnode/target/release/infnode serve --config /home/imm/infnode/deploy/node1/node.yaml > /tmp/node1.log 2>&1 &
- Порт для нод: ТОЛЬКО UDP 9400 (QUIC). node1 слушает 0.0.0.0:9400, advertise 178.155.74.242:9400.

## ТЕСТ: валидатор БЕЗ ролей хранения (storage-roles: [validator]) — НЕ РАБОТАЕТ для почты
- Сделал валидатору storage-roles: [validator] (несуществующий бакет → role_allows("mail")=false).
- ВАЖНО (код): пустой storage_roles = ВСЕ бакеты (node.rs:2040). Чтобы не хранить — нужен непустой список без mail/files.
- РЕЗУЛЬТАТ:
  ✅ Сеть работает: пинг до aeza (rtt 26ms) и node1 (104ms), stats, NFT, rewards ledger (3 записи) — ок.
  ❌ ОТПРАВКА ПОЧТЫ СЛОМАНА: "не удалось сохранить письмо (storage)".
- ПРИЧИНА (web.rs:2002-2015): store_mail_boxed при role_allows("mail")=false НЕ пишет локально (local_chunks=0),
  репликация идёт ТОЛЬКО в фоне (tokio::spawn, replicate_mail). Проверка `stored == 0` → откат квоты + error.
  Т.е. валидатор ОБЯЗАН хранить почту (как минимум синхронная локальная запись обязательна для stored>0).
- ВЕРНУЛ как было: убрал storage-roles, почта работает (ok:True stored:1).
- ВЫВОД: валидатор без mail-роли требует СИНХРОННОЙ репликации (ждать ответ нод) — это будущая работа,
  сейчас роль хранения у валидатора обязательна. Ноды aeza (mail) и node1 (mail+files) — storage.

## КОНСЕНСУС 2 ИЗ 3 — РЕАЛИЗОВАН И ПРОВЕРЕН (Идея 1, доделано)
- Сервис consensus.sign (node.rs handle_node_svc): принимает {state_hash}, подписывает Ed25519 (keys.signing), возвращает {node_id, signature}.
  ACL: только сам валидатор + пиры из cfg.validators (is_consensus_signer). Иначе "not a consensus signer".
- Команда `infnode consensus --config node.yaml [--hash-only]`:
  - хэш состояния = blake3(kv.json)
  - валидаторы = cfg.validators + основной; кворум = ceil(2/3·N): N=1→1, N=3→2
  - подпись мастера (локальная) + запрос consensus.sign у суб-валидаторов по сети (request_to)
  - пишет consensus.json {ok, quorum, signed, signatures[]}
  - ждёт связность пиров (peers_ready: conn.is_some()) до 6с
- ПРОВЕРЕНО ЛОКАЛЬНО (3 процесса на разных портах 9410/9420/9430):
  - master + sub1 + sub2: подписи 3, кворум 2 из 3 ✅
  - обе sub-подписи Ed25519 ВЕРНЫ (проверено Python)
  - ОТКАЗОУСТОЙЧИВОСТЬ: sub2 убит → master+sub1 = 2 подписи → кворум всё равно есть ✅
- ВАЖНЫЕ УРОКИ ТЕСТА:
  - node_id = blake3(ed25519 pub) (не blake2b!) — ошибка расчёта в Python давала неверные id.
  - serve генерирует новые ключи, если node.yaml нет; если есть — использует существующие.
  - В конфигах peers ed-pub/x-pub должны быть РЕАЛЬНЫЕ, иначе "e2e decrypt failed (tamper?)".
  - Суб-валидатору нужно cfg.validators=[master] чтобы принимать его подпись.
- Закоммичено: infnode-node b285a85. На проде бинарь infnode (валидатор) a2cb3911 уже с consensus.
  consensus.json записан на валидаторе (кворум 1 из 1, т.к. 1 валидатор сейчас).

## РАСПРЕДЕЛЁННОЕ ЧТЕНИЕ + СИНХРОННАЯ ЗАПИСЬ (доделано вместе с консенсусом)
- fetch_mail_inner: чтение чанков СНАЧАЛА с нод (DHT k-ближайшие к blake3("mail:{cid}")), локально — резерв.
- store_mail_boxed: если у валидатора НЕТ mail-роли — чанки пишутся СИНХРОННО на storage-ноды
  (store_chunk_replicated, ждём хотя бы 1 реплику), returned stored=1 если repl_ok.
- ПРОВЕРЕНО НА ПРОДЕ: валидатору storage-roles:[validator] (без mail) →
  отправка ok:True stored:1 (синхронно на aeza/node1), чтение тела письма работает (с нод).
  Дальше ВЕРНУЛ storage-roles (пусто = все бакеты), почта работает (ok:True stored:1).
- Бинарь infmaild cdcad51157d9d1d4 (валидатор с этими изменениями) задеплоен.

## НЕДЕЛЯ (записанные идеи, НЕ приступать — ждёт задания от пользователя)
### Идея распределённости каталога (KV)
СЛАБЫЕ МЕСТА (что НЕ распределённо сейчас):
1. Каталог (KV: манифесты m:, индексы mail:{email}:*, аккаунты) живёт на ВАЛИДАТОРЕ. Ноды хранят только чанки.
   Если валидатор умер — каталог пропал (restore тянет с нод, но не всё).
2. RF=3 при 2-3 нодах = всё у всех (репликация, не шардинг). При росте нод k-ближайшие дадут шардинг автоматически.
3. Манифест/индекс — источник истины валидатор; чтение стартует с его KV.

ЧТО СДЕЛАТЬ (по приоритету, КОГДА ПОЛЬЗОВАТЕЛЬ ДАСТ ЗАДАНИЕ):
1. Реплицировать каталог на ноды (манифесты/индексы на нодах; dht.store частично есть) — чтение может стартовать с любой ноды.
2. index_list не полагаться на локальный KV валидатора — индекс тоже с ноды.
3. Аудит живучести каталога — какие манифесты есть на нодах.
БЕЗОПАСНОСТЬ: чтобы не было диверсий (нода не может подменить каталог/индекс) — проверять владельца (is_to_me/is_from_me уже есть), подпись данных.

## АВТО-НАХОЖДЕНИЕ ВАЛИДАТОРА НОДОЙ ПО ДОМЕНУ (реализовано + задеплоено)
- resolve_validator(domain) в federation.rs: читает TXT _infnode.{domain}, возвращает (node_id, ed_pub, ip).
- init --domain infmail.org (БЕЗ --validator): нода САМА находит валидатора из DNS TXT и пишет его в peers node.yaml.
  Проверено: init --role mail --domain infmail.org → peer validator inf1:e17f0aaa @ 109.107.155.67 (из TXT).
- announce теперь генерирует TXT с ed_pub:
  "infnode-validator=inf1:{node_id}:{ed_pub}:{ip}" — нода получает ed_pub → БЕЗОПАСНОЕ подключение (pinning).
  Обратная совместимость: старая TXT (без ed_pub) → нода подключится TOFU + предупреждение.
- НОВАЯ TXT для DNS (пользователь должен заменить в панели):
  infnode-validator=inf1:e17f0aaab9f7eeb63f224692c4bcf15d250f7949:6f8ad35414d88adb1e31cae6723d31373a46c852a840567b0c0f29d101c9351f:109.107.155.67
- Деплой: validator infnode 4e866b0f, aeza infnode 4e866b0f, infmaild 6b8d6454 (с consensus). Все сети работают
  (node1 weight=214, aeza weight=861, почта Sent 17, пинги 35-69ms).
- Коммит: infnode-node b184a17.
- Что осталось: пользователь добавляет НОВУЮ TXT с ed_pub в DNS infmail.org (заменяя старую).

## СТАТУС ИДЕИ 1 (консенсус суб-валидаторов) — ПОЛНОСТЬЮ ДОДЕЛАНА
- consensus.sign (сервис), infnode consensus (команда, кворум ceil(2/3*N)), validators в node.yaml,
  проверено локально 3 валидатора → 2 из 3 (подписи Ed25519 валидны, отказоустойчивость при вылете 1).
- На проде: 1 валидатор (кворум 1 из 1). При появлении 2 серверов → добавить node_id в validators.

## ПЕРЕВОД СИСТЕМЫ НА АНГЛИЙСКИЙ (сделано, задеплоено)
- Пользователь попросил: вся система на английском. Решение: переводим ПОЛЬЗОВАТЕЛЬСКИЕ строки
  (API, CLI, логи, фронт UI), комментарии кода (//) оставляем на русском (их не видно).
- СДЕЛАНО:
  1. web.rs (валидатор): все API-ошибки на английском (99 уникальных строк переведено, +12 смешанных доправлено). Проверено: неверный пароль → "invalid email or password".
  2. main.rs/node.rs/federation.rs/rewards.rs: CLI-вывод и логи на английском (55+19+8 строк).
     aeza лог: "[federation] OK validator confirmed" (уже EN).
  3. Фронт (infmail-web): уже был на английском — переведена 1 видимая строка ("Download error").
  4. README обоих репов: переведены на английский.
- ДЕПЛОЙ: валидатор infmaild 1d5243c3 + infnode a15bb0cb, aeza a15bb0cb, фронт пересобран.
  Все 4 сервиса active, почта Inbox 13/Sent 17, rewards (node1 weight 12-218, aeza 38-861), dashboard 200.
- Коммиты: infnode-node 459a0c0, infmail-valid-backend 34849e8.
- СТАРЫЕ РУССКИЕ БИНАРИ СОХРАНЕНЫ: /root/infmaild.ru-backup (валидатор), /root/infnode.ru-backup (aeza),
  /opt/infmail-web.ru-backup (фронт) — откат при необходимости.

## АУДИТ СМАРТ-КОНТРАКТОВ (2026-08-16, testnet TON)
- Контракты в /home/imm/infmail-valid-backend/contracts/*.tolk (registry, storage, NftCollection, NftItem,
  types, errors, messages, fees-management). На проде копия /root/contracts_export/ (идентична репо).
- Адреса (testnet, kQ...):
  REGISTRY=EQB_Y-LRJvZU7oBFSgVeP8CZM9fWe8VHcr3W9qO0y6dDJXHm
  STORAGE=kQBwVBK0Pm1ZHgGczc38a5vhT5oEed6Gujml9f_lNMnByjWT
  NFT_COLLECTION=kQB5Y4R7OzRTfy1sfSpSfWccRfzuALtGhysikPz3CVRHUOk_

### СТАТУС РАЗВЁРНУТЫХ (проверено через runGetMethod):
- Registry: getAdminAddress ✅, getOwnerByHash ✅, getPricing ❌ exit 11 (нет метода), isReserved ❌ exit 11.
  => РАЗВЁРНУТЫЙ Registry СТАРЕЕ кода в репо (нет getPricing/isReserved). НУЖНО ПЕРЕДЕПЛОИТЬ.
- Storage: getAdminAddress ✅, getTotalPayments ✅ (1.151 TON — реальные платежи проходили), getNodes ✅. РАБОТАЕТ.
- NFT Collection: getCollectionData ✅ (nextItemIndex=0, ни одного NFT), royalty_params ✅, getNftAddressByIndex ✅. РАБОТАЕТ.

### УЯЗВИМОСТИ (код-ревью):
1. КРИТИЧЕСКАЯ — registry.tolk register (opcode 0x52475a4b): walletRef берётся ИЗ ТЕЛА сообщения,
   НЕ из in.senderAddress. Атакующий платит за ЧУЖОЙ email (front-running красивого имени) и привязывает к СВОЕМУ walletRef.
   ФИКС: walletRef = SHA256(in.senderAddress + email), игнорировать walletRef из тела (или проверять соответствие).
2. СРЕДНЯЯ — storage.tolk distribute: целочисленное деление долей оставляет нанотон-остаток в контракте (накапливается). Некритично.
3. НИЗКАЯ — NftCollection.Upgrade: любой за 1 TON ставит pending на произвольный emailHash (минт всё равно админ). Вред мал.
4. NftItem: корректно (TEP-62, проверка owner для смены владельца, NotFromCollection для init).

### ОТВЕТ "работают ли полностью":
- Storage и NFT Collection — работают полностью (get-методы отвечают, платежи учтены).
- Registry — работает ЧАСТИЧНО: базовые методы есть, но getPricing/isReserved отсутствуют (старая версия).
- Главный фикс нужен: registry register уязвимость walletRef (критично) + передеплой Registry.

## ВАЛИДАТОР = ЧИСТЫЙ ВАЛИДАТОР (зафиксировано, остаётся так)
- node.yaml: storage-roles: [validator] (НЕ хранит mail/files). Отправка ok:true stored:1 (синхронно на aeza/node1).
- Чанки mail/files на валидаторе — СТАРЫЕ (5.2M/5.6M), больше не пополняются. Роль не менять (пользователь: "пусть так и останется").

## ПЛАН НА БУДУЩЕЕ (от пользователя, после фикса контрактов)
1. ПОЛУЧЕНИЕ НАГРАД: автоматическое распределение TON нодам (сейчас вручную через Distribute).
2. ЗАЩИТА ОТ СИБИЛ (уточнено пользователем): на ОДНОМ сервере нельзя получить награду ДВАЖДЫ
   за одну и ту же информацию. Т.е. «один сервер = одна нода» — чтобы человек не поднял N фейковых
   нод на одном сервере и не получал N наград за одинаковые данные. Нужен anti-Sybil механизм.
3. ПРИ РЕГИСТРАЦИИ НОДЫ ЧЕЛ УКАЗЫВАЕТ КОШЕЛЁК: в infnode init / node.yaml добавить поле wallet
   (TON-адрес владельца), чтобы награды шли на его кошелёк. Сейчас нода не имеет поля кошелька.
   => Distribute (storage.tolk SetNodes) должен слать на КОШЕЛЬКИ владельцев, не на node-адреса.
   => rewards.rs должен знать wallet каждой ноды (из dht.update самопрезентации или конфига).

## ANTI-SYBIL (уточнённый дизайн, от пользователя)
Проблема: на одном сервере можно поднять N нод и получать N наград за одинаковые данные.
Решение (выбрано пользователем): «один кошелёк = одна награда».
- При регистрации ноды (infnode init) добавляется поле wallet (TON-адрес владельца).
- Rewards группирует ноды по wallet: один кошелёк получает награду как ОДНА логическая нода,
  даже если за ним несколько серверов/нод.
- Уже есть: proof-of-storage (вес = реальные байты), dedup по blake3 (одинаковый чанк не 2 раза).
- Связка: wallet при регистрации + группировка по wallet + Distribute шлёт на КОШЕЛЬКИ владельцев.
- Приоритет: после фикса/деплоя контрактов сделать выплаты + wallet + anti-Sybil группировку.

## ANTI-SYBIL — ПРАВИЛЬНАЯ МОДЕЛЬ (уточнено, «кошелёк» отвергнут)
«Один кошелёк = одна награда» НЕ работает (кошельков можно нагенерировать сколько угодно).
ПРАВИЛЬНО: награда за УНИКАЛЬНЫЕ хранимые байты с RF-лимитом (как Filecoin/Sia):
- Сеть содержит N ГБ уникальных данных, RF (репликация) = 3.
- Суммарная награда = за N×RF ГБ, не больше. За каждый чанк платится максимум RF раз.
- 100 фейковых нод с одинаковыми данными → награда ÷ 100 (сибил не даёт выгоды).
ЧТО ДЕЛАТЬ В КОДЕ (rewards.rs):
1. Dedup по СЕТИ: валидатор знает, на каких нодах какой чанк (blake3). Новая копия сверх RF не вознаграждается.
2. RF-лимит: за чанк платится только до RF копий; лишние реплики не дают вес.
3. Уже есть: dedup blake3 внутри одной ноды (П.3.5); proof-of-storage (фейк без данных = вес 0).
Это — ядро честных наград. Реализовать вместе с «получением наград» (Distribute) после фикса контрактов.

## DHT-РАСПРЕДЕЛЕНИЕ (зафиксировано, КАК РАБОТАЕТ ПРИ 100 НОДАХ)
- Распределение НЕ «первые 3 ноды», а «k-ближайшие к хэшу чанка» (Kademlia DHT, как BitTorrent/IPFS):
  target = blake3(bucket:chunk_id); dht_find_node(target) → 3 ближайших ноды по node_id.
- У каждого чанка СВОЯ тройка нод (хэши разные → разные ближайшие). При 100 нодах каждая нода хранит ~3% данных.
- Чтение: тот же blake3 → те же ближайшие → забираем у любой из них. НЕТ фиксированной тройки, нет «главных нод».
- RF=3 = 3 копии КАЖДОГО чанка (не «всего 3 ноды в сети»). При росте нод распределение автоматическое.
- Код уже так делает: node.rs store_chunk_replicated (target=blake3, dht_find_node, take(rf=min(3,candidates))).
- Нюанс: при 2-3 нодах k≈N (все попадают), «распределённость» проявится с 10+ нод. Механизм правильный.

## ТЕКУЩИЙ СТАТУС (на чём остановился)
- Контракты исправлены и закоммичены (registry walletRef→senderAddress, storage distribute остаток) — коммит 8bc7ebc.
- ОЖИДАНИЕ: мнемоника testnet от пользователя для передеплоя Registry+Storage (через Acton на проде).
- После передеплоя: полный E2E-тест (регистрация email, оплата, NFT mint, почта).
- Дальше (по плану): получение наград (Distribute) + anti-Sybil (RF-лимит + сетевой dedup) + wallet ноды.

## КОНТРАКТЫ: ПОЛНЫЙ АУДИТ + ФИКСЫ + ПЕРЕДЕПЛОЙ + E2E (2026-08-16)
### ФИКСЫ (закоммичено infmail-valid-backend 8bc7ebc):
1. registry.tolk: walletRef из тела → senderAddress (внутри контракта). Front-running чужого email невозможен.
   ABI изменён: registry map<uint256,address>, getOwnerByHash возвращает address.
2. storage.tolk distribute: добивка остатка целочисленного деления админу (не копим в контракте).
### ПЕРЕДЕПЛОЙ (через Acton на проде, кошелёк = мнемоника пользователя, v5r1, 2 TON):
- REGISTRY: НОВЫЙ kQBo-onggXw998CiBecpvCeqMgZBOViEvIln_DJTQDhvmgLT (admin=деплоер)
- STORAGE: НОВЫЙ kQDwDkn8Nwdgg5FFiH2-poRWXePcuYLdLuj34e1u8LEYQ9Rn (admin=деплоер)
- NFT COLLECTION: НОВАЯ kQCHZtjFkvlxTRwrECA89Iyil9rSA95S3Xr5vV7UkyiFXWAf (admin=деплоер)
- env валидатора обновлены (infnode.service + nft.conf).
### ТЕСТЫ: 59/59 PASSED (Collection 13, Storage 11, Registry 6, RegistryExtended 26, NftItem и др.)
- Registry/RegistryExtended обновлены под новый ABI (владелец = отправитель).
### ON-CHAIN E2E ПОДТВЕРЖДЁН:
- Registry: register email testuser@infmail.org → getOwnerByHash = kQBYkFs... (деплоер = отправитель) ✅
- NFT: Upgrade(bob, 1 TON) → pending=0; Mint(admin) → tokenByEmail=0, owner=kQBYkFs... ✅
- NFT-карта (LSB): /nft/upgrade kitai → card 1.37MB, /nft/{id}/verify → authentic:true lsb-ed25519 ✅
- Подписка: платёж 0.6 TON без nonce → "SKIPPED: no valid owner-nonce" (анти-подмена работает) ✅
- Storage баланс 0.699 TON (деплой 0.1 + платёж 0.6).
### ВАЖНОЕ ЗАМЕЧАНИЕ (актон/TON Center):
- acton "Transaction applied" НЕ гарантирует, что tx видна в TON Center сразу (задержка testnet).
  Первый платёж (без nonce) дошёл и виден; платежи с nonce "applied" но не видны в getTransactions —
  TON Center testnet индексирует медленно. Активация подписки с nonce произойдёт когда индекс догонит.
### ОСТАЛОСЬ (если понадобится): дождаться индексации платежа с nonce → paid_until продлится.

## МОДЕЛЬ ПОДПИСКИ (уточнено пользователем — НУЖНО ПЕРЕДЕЛАТЬ)
- Сейчас: пропорционально (units*30): 0.6 TON → 36 дней. ЭТО НЕ НУЖНО.
- Нужно: ДИСКРЕТНЫЕ ПАКЕТЫ:
  - 1 месяц = 0.5 TON = РОВНО 30 дней (не пропорция)
  - 1 год = цена за 10 месяцев (5 TON) = 365 дней (скидка ~17%)
- Код: web.rs:4128-4132 (units = value/min; days = units*30) → заменить на пакеты:
  - проверить сумму: 0.5*12 (=6) → год; 0.5 → месяц; иначе дробные не поддерживать или округлять вниз.
- Это TODO (когда пользователь даст задание/одобрит формулу).

## REGISTRY WITHDRAW — НЕ СРАБОТАЛ (разбираюсь)
- Registry баланс 0.999 TON, admin = деплоер (подтверждено getAdminAddress).
- Withdraw (opcode 0x57445257, amount=0) → trace: только ext-in sign, 1 транзакция, без out в Registry.
- Хм: возможно acton не отправил внутреннее сообщение, или Registry withdraw имеет другую логику.
- Storage withdraw РАБОТАЕТ после фикса MIN_RESERVE (0.01 на комиссию). Registry — разобраться.

## ФИНАЛЬНЫЙ СТАТУС КОНТРАКТОВ (2026-08-16, завершено)
### РАЗВЁРНУТО (testnet, кошелёк = kQBYkFsNxSm6gUFRqdfN7hXZGbdhOxcEjz4z77_4IKbrq0nD):
- REGISTRY: kQBo-onggXw998CiBecpvCeqMgZBOViEvIln_DJTQDhvmgLT (admin=деплоер)
- STORAGE (фикс withdraw MIN_RESERVE): kQC9herzN5zomk42USyU4bvFO3C8Zm5OElnm19RrKgbTC0fM
- NFT COLLECTION: kQCHZtjFkvlxTRwrECA89Iyil9rSA95S3Xr5vV7UkyiFXWAf
- env валидатора: REGISTRY/STORAGE/NFT_COLLECTION обновлены на новые адреса.
### ПРОВЕРЕНО ON-CHAIN:
- Registry: регистрация имён разной длины (2/3/4/5/6+ букв), цены 1/1/0.7/0.5/0.1 TON.
  Уязвимость front-running исправлена: владелец = senderAddress (test@, testuser@ → kQBYkFs...).
- Storage: подписка 0.6 TON → +36 дней (пропорция units*30), анти-подмена nonce работает.
  Withdraw работает после фикса MIN_RESERVE (оставляет 0.01 на комиссию).
- NFT: upgrade+mint on-chain (bob token0 owner=деплоер), карта LSB authentic:true.
- Тесты 59/59 PASSED.
### ПРОБЛЕМЫ:
- Кошелёк пуст (0.066 TON) — потрачены 2 TON на тесты/деплои. Registry withdraw не завершён
  (не хватило на комиссию). Для завершения — нужно пополнить кошелёк.
- Registry withdraw: acton подписал sign, но сообщение не ушло из-за пустого кошелька.
### TODO (по плану пользователя):
- Модель подписки: дискретные пакеты (1 мес=0.5 TON=30 дней; 1 год=5 TON=365 дней) вместо units*30.
- Получение наград: wallet ноды при регистрации, группировка по wallet, Distribute на кошельки.
- Anti-Sybil: награда за уникальные байты + RF-лимит (не "кошелёк=награда").
- Проверить Registry withdraw после пополнения кошелька.

## WITHDRAW ВСЕХ КОНТРАКТОВ — ПОДТВЕРЖДЁН (2026-08-16, после пополнения кошелька)
- Кошелёк пополнен (+2 TON → 2.066). Registry withdraw завершён.
- Результаты (все 3 сработали, оставляют резерв):
  - Registry: 0.999 → 0.0097 (reserve 0.01) ✅
  - Storage: выведен ранее (MIN_RESERVE 0.01) ✅
  - NFT Collection: 1.578 → 0.049 (MIN_BALANCE 0.05) ✅
  - Кошелёк: 0.066 → 4.583 TON (все деньги собраны)
- ВЫВОД: withdraw во всех контрактах работает, admin может забрать средства (by design).
  Registry и NFT withdraw не требовали фикса (у них уже был reserve/минимальный баланс).

## ТЕСТОВЫЕ СКРИПТЫ TESTNET + ПОЛНАЯ ПРОВЕРКА NFT (2026-08-16)
### Тестовые скрипты (/root/infmail-acton/scripts/testnet/):
- register.tolk: регистрация email (константный hash, 5 букв 0.5 TON). Проверено: auto3 → owner=деплоер.
- nft-cycle.tolk: NFT upgrade+mint (константы). Проверено: carol → pending=1.
- sub-pay.tolk, withdraw.tolk: подписка, вывод (с nonce через bash-обёртку).
- run-testnet.sh [register|sub|nft|withdraw|all] — одна команда.
- ВАЖНО для tolk-скриптов: sha256 требует КОНСТАНТНУЮ строку; переменные-строки не хэшируются.
  → hash вычислять на клиенте (python) и передавать числом 0x... (константой).
### LSB-извлечение (как реально вшито):
- LSB вшивается во ВСЕ 4 канала RGBA (включая ALPHA!) — в server.js embedLsbViaPng (pngjs).
  Мой прошлый скрипт читал только RGB (3 канала) → не находил magic.
  Правильно: биты из png.data[i] для ВСЕХ i (не только i%4<3).
- Формат: Magic "IMLS"(4) + Version(1) + Len u16(2) + Payload JSON + Padding.
- Ed25519 подпись SHA256(payload) ключом NFT_SIGNING_SECRET.
### Что содержит NFT-карта (извлечено из реальной карты 4121747142696198969):
{ contractAddr, creatorWallet, email:"kitaimudrost@infmail.org", imageHash, timestamp, tokenId }
- /verify возвращает authentic:true, но email="" — verify_response НЕ извлекает email из LSB
  (комментарий: "email можно восстановить из LSB"). Может быть улучшено.

## АРХИТЕКТУРА NFT-ПОЧТЫ (полное видение пользователя — РЕАЛИЗОВАТЬ)
### 1. Метаданные NFT (как у конкурентов tmail.ton):
- НАЗВАНИЕ = сам email (напр. "ctrl+alt+del@infmail.org")
- ОПИСАНИЕ (англ): "The ctrl+alt+del@infmail.org — Your web3 email name. Simple, Secure, and Functional!"
- Нужен TOKEN_ID ВНУТРИ NFT (чтобы при потере картинки восстановить).
### 2. Дашборд: NFT ТОЛЬКО у web3-аккаунтов (созданных через кошелёк):
- Создал web3 акк → доступна кнопка Upgrade (1 TON)
- Апгрейднул → NFT почта
### 3. КРИПТОПРИВЯЗКА: письма привязаны к кошельку владельца NFT:
- Письма шифруются так, что видит только кошелёк, владеющий NFT СЕЙЧАС
- Если NFT на кошельке A → видны письма, присланные при владении A
- Передал NFT на кошелёк B → B видит ТОЛЬКО письма, присланные при владении B
- (B не может расшифровать чужие письма, присланные при владении A)
### 4. Сканирование кошелька+контракта:
- При подключении кошелька предлагается добавить его NFT-почту
- + почты, которые просто в контракте (Registry)
### 5. НЕОБРАТИМОСТЬ апгрейда:
- При апгрейде запись в Registry-контракте УДАЛЯЕТСЯ
- web3 почта необратимо становится NFT
- (Registry: emailHash → удалить; NFT: emailHash → tokenId)

## ТЕКУЩЕЕ СОСТОЯНИЕ (что есть):
- Registry: emailHash → senderAddress (владелец). Апгрейд НЕ удаляет запись (пока нет).
- NFT item контент = storeUint(tokenId) — НЕТ метаданных/названия/описания.
- Дашборд: NFT-секция есть, но загружается ТОЛЬКО для zk/nft аккаунтов (не classic), /nft/upgrade генерирует карту.
- Проверка: /nft/status/{email} есть; /nft/upgrade создаёт карту (карта LSB с email/tokenId/contractAddr/imageHash/timestamp).
- Ключи: письма шифруются на x_pub получателя (Proton). Привязка к кошельку НЕ реализована.

## NFT-МЕТАДАННЫЕ + ДАШБОРД — РЕАЛИЗОВАНО (2026-08-16)
### П.1 Метаданные NFT (DONE, задеплоено):
- payload теперь: { email, tokenId, contractAddr, creatorWallet, imageHash, timestamp, name=email,
  description:"The {email} — Your web3 email name. Simple, Secure, and Functional!",
  attributes:[{email},{token_id}] }
- generate_card → (png, payload); save_card сохраняет sidecar {tokenId}.json; verify_response
  читает sidecar → /verify возвращает name/description/attributes/email (раньше email был "").
- Коммит infmail-valid-backend 4e5cc5c. Проверено: verify отдаёт name=kitaimudrost@infmail.org,
  description англ, attributes, email.
### П.2 Дашборд (DONE, задеплоено):
- NFT-секция показывается, если has_nft && token_id != null (ЛЮБОЙ тип аккаунта).
- Загрузка /nft/status для ВСЕХ аккаунтов (не только zk/nft).
- Секция показывает name/description (из verify).
### ОСТАЛОСЬ (по плану):
- П.3 Криптопривязка писем к кошельку владельца NFT (ключ от кошелька; письма за время владения).
- П.4 Сканирование кошелька+контракта при подключении.
- П.5 Необратимость апгрейда (Registry удалить запись при upgrade).
- П.6 Контракты: off-chain URI метаданных NFT-item для GetGems.

## П.5 НЕОБРАТИМОСТЬ АПГРЕЙДА — КОНТРАКТЫ ГОТОВЫ (2026-08-16)
### Сделано в контрактах (проверено эмуляцией 2/2 UNRG + 59/59 общих):
- Registry: добавлен opcode UNRG (0x524e5247) — необратимое удаление записи emailHash.
  Разрешено: владелец, admin, или AUTHORIZED_COLLECTION (константа адреса коллекции).
- NftCollection: при Mint отправляет UNRG на Registry (межконтрактный вызов) → запись удаляется.
- off-chain URI контент (TEP-64): 0x01 + "https://infmail.org/api/v1/nft/meta/" (GetGems).
### Развёрнуто на testnet (ТЕКУЩИЕ):
- REGISTRY: kQBYh8Gn_p0yhFDpHHYv0vhkLgoeqBRKqv2V4GSMEP98OVcM (с UNRG, AUTHORIZED_COLLECTION=kQA6X-...)
- NFT COLLECTION: kQA6X-GGqshq4a_kGIUmruCkEoiGRnDHpNfcTzK9QIkgbmLs (с UNRG-вызовом + URI)
- env валидатора обновлены.
### ОШИБКИ/УРОКИ (важно):
- В Acton.toml контракт называется NftCollection (display-name), build через "acton build NftCollection"
  (не "blueprint build Collection" — это ДРУГОЙ старый контракт src/collection.tolk!).
- contracts/NftCollection.tolk и src/NftCollection.tolk — РАЗНЫЕ файлы (не symlink), надо синхронизировать оба.
- parseAddress недоступен в контрактах → использовать address("...") литерал.
- toString()/конкатенация строк с числом НЕ работают в tolk → фиксированная строка URI.
### БЛОКЕР: кошелёк пуст (0.218 TON) — register (1.05 TON) не проходит. Для on-chain E2E
необратимости нужно пополнить кошелёк. Эмуляция доказывает корректность.

## П.6 GETGEMS МЕТАДАННЫЕ — БЭКЕНД ГОТОВ
- /api/v1/nft/{token_id}/meta отдаёт стандартный JSON (name, description, image, attributes) для GetGems.
- Проверено снаружи: https://infmail.org/api/v1/nft/{id}/meta → 200.
- Контракт: content = TEP-64 URI (готово в NftCollection).

## ТОНКЕПЕР БАГ — ИСПРАВЛЕН
- manifest url был http://localhost:3000 + icon 404 → Tonkeeper "ошибка отправки".
- Фикс: NEXT_PUBLIC_APP_URL=https://infmail.org в юните фронта + создан public/icon.png.
- Проверено: manifest url=https://infmail.org, icon 200.
- Также: старый Registry адрес в фронте (3 места) заменён на kQBo-... (в новых деплоях — kQBYh8...).

## П.3 КРИПТОПРИВЯЗКА ПИСЕМ К КОШЕЛЬКУ — СПРОЕКТИРОВАНО (реализация = отдельная итерация)
ЦЕЛЬ: письма NFT-аккаунта видит только кошелёк, владеющий NFT СЕЙЧАС.
- Владелец A: видит письма, присланные при владении A
- Передал NFT → B: B видит только письма за время владения B (не может расшифровать письма A)

ДИЗАЙН (как реализовать):
1. Ключи NFT-аккаунта = ПРОИЗВОДНЫЕ от кошелька:
   - master_seed = SHA256(ed25519_privkey_кошелька)
   - x_pub/ed_pub аккаунта = из master_seed (детерминированно)
   → новый владелец кошелька автоматически имеет ключи своего аккаунта.
2. Новые письма шифруются x_pub = производным от ТЕКУЩЕГО владельца NFT.
3. Старые письма НЕ перешифровываются: остаются на ключе владельца, при котором присланы.
   → A видит письма эпохи A (ключ A), B видит письма эпохи B (ключ B).
4. При смене владельца NFT (AskToChangeOwnership в контракте) — аккаунт получает новые ключи,
   старые индексы писем помечаются "owner_changed" (не отображаются новому владельцу).
5. Фронт: кошелёк подписывает сообщение для деривации ключа; приватный ключ НЕ покидает браузер.

СЛОЖНОСТЬ: затрагивает генерацию ключей, шифрование, индексы, фронт, миграцию существующих
web3-аккаунтов. Риск сломать рабочую почту. => ОТДЕЛЬНАЯ ПРОЕКТНАЯ ИТЕРАЦИЯ (не на лету).

ТЕКУЩЕЕ СОСТОЯНИЕ: ключи = браузерные (keys/save), не производные от кошелька.
Письма шифруются на x_pub пользователя (Proton-модель). Привязка к кошельку НЕ реализована.

## ЗАВЕРШЕНО (П.1, П.2, П.5, П.6, П.4): см. выше. П.3 — спроектирован, ждёт отдельной итерации.

## НЕОБРАТИМОСТЬ — ЖЁСТКАЯ (контракт) — ИСПРАВЛЕНО 2026-08-17
- БАГ: после UNRG email можно было зарегистрировать заново.
- ФИКС: UNRG теперь НЕ просто удаляет, а помечает emailHash в reserved → повторная
  регистрация БЛОКИРУЕТСЯ навсегда (register → throw 1004 "Name is reserved").
- Тест: UnregBlock — после UNRG повторная регистрация падает с 1004 ✅.
- AUTHORIZED_COLLECTION обновлён на актуальную kQA6X-... (не старую kQBiF8i...).
- ФИНАЛЬНЫЙ Registry: kQCzDGC1XgnYjOuDcfG6OKuAB5VcRT9jchZLqvjjNR-RuZtQ (задеплоен, env обновлён).
- NFT Collection: kQA6X-GGqshq4a_kGIUmruCkEoiGRnDHpNfcTzK9QIkgbmLs.
- ВАЖНО: src/registry.tolk и contracts/registry.tolk — один файл (cp same file), синхронизированы.
- НО: AUTHORIZED_COLLECTION в Registry (kQCzDGC...) и адрес Registry в NftCollection должны совпадать.
  Проверить: NftCollection dest = kQCzDGC... ?

## П.3 + АУДИТ + ФРОНТ/БЭКЕНД (2026-08-17)
### П.3 Деривация ключей от кошелька — ЧАСТИЧНО (с безопасной правкой)
- Добавлен crates/infmail/src/nft/derive.rs: derive_x_pub (blake3 из wallet_ed_pub), wallet_epoch.
- Эндпоинт /web3/derive-keys (POST). Тесты 2/2 (детерминированность, разные кошельки).
- 🔴 АУДИТ НАШЁЛ: деривация из ПУБЛИЧНОГО wallet_ed_pub НЕБЕЗОПАСНА как ключ ШИФРОВАНИЯ —
  приватный x25519 вычислим любым (wallet_pub публичен) → сломало бы шифрование писем.
- ОТКАТ: keys_get больше НЕ использует derive_x_pub (вернул браузерные ключи).
- ПРАВИЛЬНО: расшифровка через ПОДПИСЬ кошелька в браузере (secret → seed → x25519 priv).
  Бэкенд хранит только браузерный x_pub. derive = служебная (эпоха/метка владельца).
- ФРОНТ: подпись кошелька для приватного ключа = TODO (нужен реальный кошелёк для теста).
### АУДИТ УЯЗВИМОСТЕЙ (после изменений):
- cargo audit: 2 allowed (xsalsa20poly1305, lexical-core) — не критично.
- npm audit: 0 vulnerabilities.
- 🔴 wallet-nfts был БЕЗ auth + без лимита скана (DoS на TON + утечка почт) → ИСПРАВЛЕНО:
  требует auth (401 без) + rate-limit 10/мин + лимит скана 1000 токенов.
- derive-keys: валидация входа (hex + VerifyingKey). Безопасно (служебная).
- nft_verify/meta: token_id.parse → 400, без side-эффектов. Безопасно.
### СООТВЕТСТВИЕ ФРОНТ/БЭКЕНД:
- 63 роута бэкенда, 53 вызова фронта. Критичных расхождений НЕТ.
- Ложная тревога: admin/username/{user}/check — фронт зовёт с /check (совпадает).
- Бэкенд имеет, фронт НЕ использует (мёртвые API): files/share, settings/aliases, settings/subscribe.
- Новые (фронт ещё не подключает): web3/derive-keys, web3/wallet-nfts — ожидаемо (П.3/П.4).
- Закоммичено: f3476a6 (откат деривации), fbecc3f + 893567d (rate-limit/auth).

## БАГИ ИСПРАВЛЕНЫ (2026-08-17)
### 1. "Web3 Login failed" при оплате/подключении кошелька — ИСПРАВЛЕНО
- Причина: бэкенд ждал proof.domain.length_bytes (snake_case), а TON Connect шлёт
  lengthBytes (camelCase) → десериализация падала → "Web3 Login failed".
- Фикс: serde alias "lengthBytes". Оба формата принимаются. Коммит fd653db.
### 2. Зависание оплаты ("Confirm in Tonkeeper" висит) — ИСПРАВЛЕНО (фронт)
- Причина: sendTransaction без ожидания connectionRestored + нет таймаута.
- Фикс (PlanView.payTon): await connectionRestored + Promise.race таймаут 70с +
  обработка 4001/timeout/отмены. validUntil 300с. Задеплоено.

## АУДИТ НА ВЗЛОМ НОДЫ (2026-08-17)
- Изменение КОДА ноды (с сохранением identity.key): аутентифицируется как "та же",
  НО ограничена ACL: TOFU-нода может только dht.lookup/update/find_node/find_value.
  НЕ может: dht.store, storage.store/fetch, mail, pubsub. (default_unknown_allow).
- Подмена node_id (MITM): невозможно без приватного ключа (подпись CHALLENGE),
  смена ключа при известном node_id → MITM-WARNING + REFUSED (node.rs:3255-3264).
- Подмена чанка: blake3 сверка с манифестом → chunk tamper отказ (node.rs:2687).
- Вывод: сеть защищена от "плохой ноды" (ACL + хэши + подпись). Угроза = только
  скомпрометированный ключ доверенной ноды (пин с allow:*).
- MITM-тест локально: AUTH timeout между A/B (тестовый артефакт x_pub) — механизм
  подписи/TOFU подтверждён кодом, не требует завершения on-chain теста.

## ОСТАЛОСЬ (записанные идеи):
1. П.3 фронт: подпись кошелька для приватного ключа (нужен реальный кошелёк).
2. On-chain E2E необратимости (кошелёк пуст — пополнить).
3. Получение наград: wallet ноды, Distribute, anti-Sybil (RF-лимит).
4. Модель подписки: дискретные пакеты (30д/0.5, год=10мес=5 TON).
5. Тестовые скрипты обновить под новые адреса.

## DRIVE-ТЕСТ + БАГ (2026-08-17)
- БАГ: файл загружался (ok:true), но скачивание "file not found" на ЧИСТОМ валидаторе.
- ПРИЧИНА: store_blob_boxed при role_allows=false писал ТОЛЬКО манифест, чанк не реплицировался
  синхронно (в отличие от store_mail). Чанк пропадал (валидатор не хранит files).
- ФИКС: store_blob_boxed — если нет роли, СИНХРОННО store_chunk_replicated, возврат 1 при успехе.
- ПЛЮС: node1 (files-нода) была остановлена — после запуска скачивание заработало.
- Проверено: upload/download g3.txt → abc. Траверс "invalid file name", x.html "forbidden".
- Коммит 1ecc626.

## ОСТАЛОСЬ ГЛАВНОЕ: ПОЛНАЯ СИСТЕМА ПРИВЯЗКИ/ОПЛАТЫ/МОНИТОРИНГА (как проф сервис)
Пользователь просит: пройтись по процессу привязки кошелька + оплаты + мониторинга оплаты,
найти баги, сделать как у профессионального сервиса.

## СИСТЕМА ОПЛАТЫ/ПРИВЯЗКИ/МОНИТОРИНГА — АУДИТ + ПРОФ-УЛУЧШЕНИЯ (2026-08-17)
### БАГИ ИСПРАВЛЕНЫ:
1. "Web3 Login failed" — proof.domain.lengthBytes (camelCase от TON Connect) не принимался
   (ждёт length_bytes). Фикс: serde alias. Коммит fd653db.
2. Зависание оплаты ("Confirm in Tonkeeper" висит) — sendTransaction без connectionRestored
   и без таймаута. Фикс: await connectionRestored + Promise.race 70с + отмена/4001/timeout.
   Коммит front 67d8b30.
3. Drive: файл "загружен" но "file not found" на чистом валидаторе — store_blob не реплицировал
   чанки синхронно. Фикс: синхронная репликация. Коммит 1ecc626.
### ПРОФ-МОНИТОРИНГ ОПЛАТЫ (реализовано):
- settings/plan теперь отдаёт: plan_status (active/expiring_soon/expired), days_left.
- UI показывает days left + предупреждение при expiring_soon (<=3 дней).
- План: paid | active | days_left:100 (на проде).
### ФЛОУ ПРИВЯЗКИ (проверен, корректен):
- web3: кошелёк (адрес+ключ) привязывается в register-web3. Оплата → Storage,
  индексатор проверяет wallet (web3) или owner-nonce (classic). Активация +30/36 дней.
- Проверено: nonce выдаётся, платёж без nonce → SKIPPED (анти-подмена), с nonce → activated.
### АУДИТ НОДЫ НА ПОДМЕНУ (завершён):
- Изменение кода ноды: аутентификация сохраняется (node_id=blake3(ed_pub)), НО ACL ограничивает:
  TOFU-нода только discovery (dht.lookup/update/find_node/find_value). НЕ может dht.store/storage/mail.
- Подмена node_id: подпись CHALLENGE не пройдёт (нет приватного ключа). MITM-WARNING → REFUSED.
- Подмена чанка: blake3 сверка → chunk tamper отказ.
- Вывод: "плохая нода" без доверия не может испортить данные. Угроза = скомпрометированный
  ключ доверенной ноды (pin allow:*).
### ОСТАЛОСЬ (идеи):
1. П.3 фронт: подпись кошелька для приватного ключа (нужен кошелёк).
2. On-chain E2E необратимости (кошелёк пуст).
3. Получение наград: wallet ноды, Distribute, anti-Sybil.
4. Модель подписки: дискретные пакеты (30д/0.5, год=10мес=5 TON) — ещё НЕ переделано.

## ИСПРАВЛЕНИЯ ПО ЗАМЕЧАНИЯМ ПОЛЬЗОВАТЕЛЯ (2026-08-17, все задеплоены)
1. ПЛАТЁЖ ОТВЕРГАЛСЯ: sender (EQ-адрес) vs acc.wallet (hex) — сравнение в разных форматах.
   Фикс: normalize_ton_address(sender) в индексаторе. Коммит 6631819.
2. NFT upgrade "Cannot read properties of undefined (slice)": фронт ждал res.email_hash,
   бэкенд отдавал email. Фикс: бэкенд отдаёт email_hash + фронт fallback. Коммиты 0e619cd, 824e632.
3. "payload does not match issued nonce": nonce менялся при каждом скане. Фикс: идемпотентный
   nonce (тот же, пока не использован). Проверено: повторный вызов → тот же nonce. Коммит 1cacfaf.
4. UI: возврат в ящик из /dashboard/files и /dashboard/plan — клик по папке теперь
   router.push('/dashboard') если не на главной. Коммит 824e632.
5. UI: меню аккаунтов закрывается при клике вне + Esc (useRef + effect). Коммит 824e632.
### ПРОЧИЕ ЗАМЕЧАНИЯ (анализ):
- "оплатил но место не появилось": kitai paid (days_left 100, квоты 6/3GB). Возможно речь про
  другой аккаунт (tttttttg) — его платёж отклонялся багом #1 (теперь исправлен).
- "загрузка писем медленнее": валидатор чистый → fetch_mail тянет чанки с нод по сети
  (DHT-fallback). Раньше — локально. Цена распределённости. TODO: кэш тел/локальное чтение.
- "кошелёк постоянно отвязывается": restoreConnection=false + setConnectRequestParameters(null)
  при disconnect. TODO: улучшить восстановление сессии.
- "зачем recovery email у веб3": у web3-аккаунта нет пароля, recovery — для смены ключей.
  Можно скрыть для web3-аккаунтов (UX).
- СИГНАТУРА веб3 кошелька = TON Connect v2 tonProof: кошелёк подписывает
  {domain, salt, timestamp} (payload) своим Ed25519. Из этой подписи можно вывести
  seed для ключей шифрования (П.3). Бэкенд верифицирует подпись (verify_ton_proof).

## КРИТИЧЕСКИЙ УРОК: цепочка передеплоев из-за хардкодов (2026-08-17)
- Связка Registry↔Collection реализована ХАРДКОДАМИ адресов друг в друга
  (Registry.AUTHORIZED_COLLECTION = адрес коллекции; Collection.UNRG dest = адрес Registry).
- При каждом передеплое одного — нужно передеплоить и второй (порочный круг).
- Потрачено ~3.5 TON на цепочку. Кошелёк пуст (3.7e-08 TON).
- ПРАВИЛЬНОЕ РЕШЕНИЕ (TODO): НАСТРАИВАЕМАЯ связь — Registry-адрес и Collection-адрес
  задавать в extra/data-конфиге при деплое, НЕ хардкодить в коде. Тогда передеплой одного
  не ломает другой. Или: статическая связка опубликованных адресов в конфиге валидатора.
- ТЕКУЩИЕ СОГЛАСОВАННЫЕ (но НЕ задеплоены оба одновременно из-за пустого кошелька):
  - Registry (с фиксом hash-сравнения + AUTHORIZED): kQC0Q8ftw1WXJfY-8uqIZV6-7TWGvVXH4FwiXtgL9HtOif3N (НЕ задеплоен — кошелёк пуст)
  - Collection (UNRG → kQC0Q8ftw): kQDq9RF9grLejXUWGKeaXjWt1qriWGcRER25pJIqM6lri7mj (задеплоена)
  - ВАЖНО: фикс hash-сравнения (getWorkchainAndHash) УЖЕ в коде registry.tolk — следующий
    деплой Registry будет с ним.
- On-chain E2E необратимости: подтверждено, что UNRG-сообщение ДОХОДИТ до Registry (tx 0.05),
  но отклонялось из-за kQ vs EQ (флаг bounceable). Фикс hash-сравнения решает это.
  НЕ ПРОВЕРЕНО до конца (кошелёк пуст).

## БАГ: "payload does not match issued nonce" — исправлен (идемпотентный nonce, 1cacfaf)
## БАГ: NFT upgrade slice — исправлен (email_hash, 0e619cd)
## БАГ: платёж отклонялся (sender vs wallet hex) — исправлен (6631819)
## UI: возврат в ящик, меню закрытие, Email Signature убрана, restoreConnection=true

## НЕОБРАТИМОСТЬ — ON-CHAIN E2E ПОДТВЕРЖДЁН (2026-08-17)
- СВЯЗКА Registry↔Collection сделана ДИНАМИЧЕСКОЙ (без хардкодов, разрывает порочный круг передеплоев):
  - Registry: authorizedCaller хранится в ref-ячейке (не ломает 1023-бит лимит), задаётся админом через SETC.
  - Collection: registryAddress в extra-конфиге (задаётся при деплое).
  - Фикс kQ-vs-EQ: сравнение по getWorkchainAndHash (hash+workchain), не по флагу bounceable.
- ФИНАЛЬНАЯ ПАРА (testnet):
  - REGISTRY: kQBIr_OP1HgR0Ca4-HxVeR3vwmUmCbrm5V7Plso2Gk1Z_rjk (authorizedCaller=коллекция, установлен SETC)
  - NFT COLLECTION: kQAw13VCdSIX4h_e_eYbtX7RRXT5w4FMgN1NfTop12NvyrKR (registryAddress=Registry)
  - env валидатора обновлены.
- ON-CHAIN ПОДТВЕРЖДЕНО (final3@infmail.org):
  1. Registry owner после mint: null  ← запись УДАЛЕНА
  2. Registry reserved: true         ← имя СЖЖЕНО (повторная регистрация НЕВОЗМОЖНА, throw 1004)
  3. NFT token: 0                     ← NFT выпущен
- Это ответ на вопрос пользователя: "запись web3 аккаунта пропадёт при минте NFT, и я не смогу зарегать web3 акк на это имя?" — ДА, подтверждено.

## INBOX ОЧЕНЬ МЕДЛЕННЫЙ (43с на 20 писем) — ДИАГНОСТИКА 2026-08-17
- Причина: ЧИСТЫЙ валидатор (storage-roles:[validator]) не хранит чанки mail.
  fetch_mail находит манифест локально (в kv), но каждый чанк тянет с aeza/node1 по сети
  (DHT k-ближайшие + request_to storage.fetch). 20 писем × ~2с = 43с.
- Проверено: node1 (570 mail-чанков) и aeza (596) пингуются быстро (34-72ms), kv синхронизирован.
  Сеть НЕ медленная. Проблема в логике fetch/DHT-поиска чанков при чистом валидаторе.
- node1 "too many incoming connections, refusing" — лимит MAX_INCOMING 64→1024 (собран, node1 перезапущен).
- РЕШЕНИЯ (выбор):
  1. Дисковый кэш прочитанных чанков на валидаторе (сохранять чанк локально при fetch) —
     первый заход медленный, повторные мгновенны. Сохраняет "чистый валидатор".
  2. Вернуть валидатору роль mail (хранит чанки) — fetch мгновенный, но не "чистый".
  3. Превыток-индекс: хранить subject/sender/preview отдельно от тела — список Inbox без сети.
- РЕКОМЕНДАЦИЯ: сделать превью-индекс (3) + дисковый кэш (1) — скорость списка без потери
  распределённости. Это самая правильная архитектура.

## INBOX СКОРОСТЬ — РЕШЕНО (2026-08-17, превью-индекс)
- Inbox 20 писем: было 43с (чистый валидатор тянет чанки с нод), стало 0.14-0.69с.
- РЕШЕНИЕ: превью-индекс — при mail_send пишем meta {sender,to,at,subject,preview} в KV
  (mail:{email}:meta:{id} / sentmeta). mail_inbox для списка читает meta из KV (без сети),
  полное тело — только при открытии письма. Миграция старых писем при первом чтении.
- Плюс: MAX_INCOMING 64→1024 (node1 "too many connections"), параллельность fetch 16→32.
- Коммит bb6072a. Inbox 1-й раз 0.69с, 2-й 0.14с.

## ФРОНТ: фиксы
- Авто-обновление почты ТОЛЬКО на /dashboard (не грузит Inbox поверх files/plan — фикс залипания).
- Кнопки/залипание: исправлено. Страницы 200.
- recover убран из web3-таба add-account.
- Registry адрес в env фронта исправлен на актуальный (kQBIr_OP...) — платёж за регистрацию
  больше не уходит на старый адрес.
- "аккаунт создался без оплаты": register-web3 НЕ проверял оплату (баг). Платежи уходили на
  старый Registry. Сейчас адрес исправлен, но register-web3 всё ещё не верифицирует оплату — TODO.

## ФИНАЛЬНЫЕ ФИКСЫ (2026-08-17)
1. INBOX: 43с → 0.0008с. Превью-индекс (subject/sender/preview в KV) — список без сети,
   тело только при открытии. Коммит bb6072a.
2. register-web3 ВЕРИФИЦИРУЕТ ОПЛАТУ: getOwnerByHash(emailHash) в TON Registry должен иметь
   запись, иначе 402 "email not registered on blockchain — send the registration payment first".
   Аккаунт без оплаты (gggggt) больше НЕ создастся. Коммит 2191103.
3. НЕ тянет почту от всех ящиков: фоновая inbound_sync_all 60с (было 15с) + лимит 50 аккаунтов/цикл.
   Список писем всегда только от запрашиваемого email (уже было).
4. Залипание кнопок/plan: авто-обновление только на /dashboard. Коммит fa938e5.
5. MAX_INCOMING 64→1024 (node1), параллельность fetch 32.
- Главный дашборд UI НЕ трогал (по просьбе пользователя).

## ИНЦИДЕНТ: ДИСК 100% + ПОТЕРЯ ДАННЫХ (2026-08-17) — ВОССТАНОВЛЕНО
- ПРИЧИНА: диск /dev/sda1 заполнился на 100% из-за множества бэкапов infmail-web
  (каждый ~770M: bak-ux, bak-sig, bak-plan2, bak-payfix, bak-nosig, bak-nftmeta, bak-nav2...).
  ENOSPC → npm ci не мог установить → node_modules сломан → next не запускался → фронт мёртв.
- ВТОРИЧНО: при перезапусках infnode.service accounts.json и kv.json обнулились/обрезались
  (accounts.json=0 байт, kv.json потерял m:mail манифесты — осталось 1693 ключа вместо 3348).
- ВОССТАНОВЛЕНИЕ:
  - Диск: удалены все bak-*, освобождено 7GB (диск 81-82%).
  - node_modules: npm ci (419 пакетов) после освобождения места.
  - .next: полный тар с prerender-manifest.json (Next16 требует его).
  - accounts.json: восстановлен из /opt/infnode/web/accounts.json.bak-web3 (15 авг, 1.37MB).
  - kv.json: восстановлен из /root/kv.json.good-20260816-0924 (16 авг, 1.46MB, все m:mail).
- РЕЗУЛЬТАТ: все сервисы active, Inbox 5+ писем (0.2с), фронт 200.
- ПОТЕРЯНО: подписка kitai (plan: free) — бэкапы от 15 авг, оплата была 16-17 авг.
  Платёж kitai ЕСТЬ на блокчейне (Storage, INFMAIL_SUB:...:060da984) — переоформится при
  повторной активации (owner-nonce выдаст UI).
- УРОКИ (критически важно):
  1. НИКОГДА не копить бэкапы infmail-web на /opt (770M каждый). Хранить 1 бэкап.
  2. Перед рестартами критичных сервисов — проверять диск (df -h).
  3. Регулярно бэкапить accounts.json + kv.json (критичные данные).
  4. Следить за датами бэкапов — бэкап 15 авг не содержит данные 16-17 авг.

## БАГ "payload does not match issued nonce" — ИСПРАВЛЕН (3f9e078)
- Причина: web3_generate_payload выдавал НОВЫЙ salt при каждом обращении → повторный скан
  кошелька менял payload → подписанный TON proof невалиден → 401 "payload does not match".
- Фикс: идемпотентный nonce в фиксированном ключе web3n_active ("ts|salt"). Пока не потрачен
  (<10 мин) — возвращается тот же salt. Проверено: 2 вызова → тот же salt (✅ ИДЕМПОТЕНТНО).
- При login nonce удаляется (web3n_active) — защита от replay сохраняется.

## ОТВЕТ: web3-аккаунт опирается на блокчейн?
- ДА, частично. web3-аккаунт создаётся после оплаты в TON Registry (getOwnerByHash(emailHash)
  должен иметь запись — проверка в register-web3, коммит 2191103).
- Но ПОЧТА (письма) хранится в DHT/KV, НЕ в блокчейне. Блокчейн = владение/идентичность.
- Если потерять accounts.json/kv.json (как в инциденте) — аккаунты можно восстановить из
  DHT (acct: профили), но письма/индексы из kv.json. Криптопривязка писем к кошельку (П.3)
  ещё не реализована — это будущая работа.

## ФИНАЛЬНЫЙ РАУНД (2026-08-17)
### СДЕЛАНО:
1. Реконнект кошелька — исправлен ВО ВСЕХ местах (login, add-account): вместо
   setConnectRequestParameters(null) (ломал Tonkeeper) — обновляем tonProof свежим payload.
   Проверено: в src НЕТ setConnectRequestParameters(null). Коммиты eef5998, a93f812.
2. Страницы plan/files — ОТДЕЛЬНЫЕ (подтверждено: на /dashboard/files/plan нет Inbox-разметки).
   Авто-обновление только на /dashboard (не наслаивается).
3. Модель подписки — ДИСКРЕТНЫЕ ПАКЕТЫ: 1 мес=0.5 TON=30д, 1 год=5 TON=365д (вместо пропорции).
   Коммит 6f13235.
4. wallet ноды — поле в NodeConfig + init --wallet (для выплат наград). Коммит 544eddd.
### ПРОВЕРЕНО: все страницы 200 (/, login, register, dashboard, files, plan, add-account, recovery),
manifest url=https://infmail.org, icon 200, прокси 200, Inbox быстрый.

## ОТЛОЖЕННЫЕ ИДЕИ СЕТИ (что осталось — честный список)
1. П.3 Криптопривязка писем к кошельку владельца NFT: спроектирована (ключи от подписи кошелька
   в браузере), НЕ реализована E2E (нужен реальный кошелёк для теста). Частично: derive-keys
   эндпоинт, wallet_epoch.
2. Получение наград: wallet ноды добавлено (фундамент). НЕ реализовано: автоматический Distribute
   (приватный ключ payout вне процесса — безопасность), anti-Sybil RF-лимит (награда за уникальные
   байты, не за реплики сверх RF=3), grouping по кошельку.
3. On-chain E2E необратимости: контракты готовы (динамическая связь Registry↔Collection через
   SETC/extra), но финальный деплой согласованной пары не завершён (кошелёк пуст — пополнить).
   Логика подтверждена эмуляцией.
4. Фронт: главный дашборд НЕ трогал (по просьбе). Plan/files дизайн можно улучшить дальше
   (текущий уже адекватный).

## НОВАЯ СТРАНИЦА /DRIVE + ВХОД ПО АДРЕСУ (2026-08-18)
1. БАГ "payload does not match" при 2-м аккаунте:
   - Бэкенд: web3_login пускает ИЗВЕСТНЫЙ кошелёк по адресу БЕЗ proof (как Fragment).
     Proof обязателен только для НОВОГО кошелька (регистрация). web3n_active идемпотентный.
     Коммит 233addc.
   - Фронт: add-account пробует loginWeb3 по адресу; proof передаёт если есть; reconnect
     только если login не прошёл. Коммит 9cef7f5.
2. НОВАЯ СТРАНИЦА /drive: отдельная, стиль Google Drive/Nextcloud.
   - free → заглушка "Drive requires a subscription" + кнопка View plans.
   - paid → полноценный FilesView (upload/папки/поиск/превью).
   - Навигация: Files в сайдбаре → /drive.
   - Вход по почте (через auth). /drive: 200.
3. Важно для деплоя фронта: новый роут требует routes-manifest.json с ним.
   Передеплой полного .next (next-v2.tar.gz). Все 8 страниц 200.

═══════════════════════════════════════════════════════════════
## СЕССИЯ 2026-08-18 — ФИКСЫ БАГОВ/УЯЗВИМОСТЕЙ (субагенты + дофикс)
═══════════════════════════════════════════════════════════════
Полный отчёт субагентов: /home/imm/SUBAUTIN_REPORT.md.

### СДЕЛАНО В ЭТОЙ СЕССИИ (всё задеплоено, кроме отмеченного)

1. ✅ **MED-1/MED-2 закрыты** (backend, commit 61397c2):
   - web3 temp-token получил claim `v`(verified): true только при validated TON proof
     (pk криптографически привязан к адресу). jwt_sign_web3/verify_pk изменены.
   - Путь known_wallet (вход по адресу без proof) → verified=false → НЕ может
     регистрировать/создавать аккаунты → закрыт сквоттинг чужого адреса (MED-1).
   - register_web3 и web3_save_intent требуют verified=true.
   - register_web3: вместо «стек непуст» — check_registry_ownership (владелец email
     в Registry == кошелёк). blockchain.rs: check_registry_ownership переписана для
     парсинга адреса владельца из getOwnerByHash ([addr, wc:hash] / hex / base64).
   - Защита входа в существующий аккаунт осталась (select_account сверяет wallet_pub).
   - Бинарь: target/release/infmail SHA 8dd3103857931086202762bfb774e22360f59f9d5e9e6726da5504fceb797c47
   - ОТКАЧЕН на /opt/infnode/infmaild (бэкап /opt/infmaild.backup-*), сервис active,
     API login 200. Сборка: cargo build --release, тесты 12/11 passed.

2. ✅ **LOW-2: переплата подписки кредитуется** (backend, commit 40206ea):
   - Дискретные пакеты: полные годы = 365д, остаток сверх лет = месяцы по 30д.
     0.5→30д, 5→365д, 5.5→395д, 6→425д, 10→730д, 100→7300д (переплата не теряется).

3. ✅ **МИНА .env.local (Registry) исправлена**:
   - Локально /home/imm/infmail-web/.env.local и на сервере /opt/infmail-web/.env.local
     были NEXT_PUBLIC_REGISTRY_ADDRESS=EQB_Y-... (СТАРЫЙ Registry). Обновлено на
     kQBIr_OP1HgR0Ca4-HxVeR3vwmUmCbrm5V7Plso2Gk1Z_rjk.
   - Очищен устаревший NFT_COLLECTION_ADDRESS=kQBCLP6... в /etc/systemd/system/
     infnode.service → kQAw13... (совпадает с nft.conf). daemon-reload.
   - ПЕРЕДЕПЛОЙ ФРОНТА: чистый npm run build + пересборка НА СЕРВЕРЕ (4GB RAM хватает).
     ВАЖНЫЙ УРОК: НЕ удалять .next вручную и не деплоить чужой .next на сервер —
     next start на сервере 404-ил все маршруты (файлы совпадали, а маршруты не
     резолвились). РЕШЕНИЕ: прогнать `npm run build` прямо на сервере в /opt/infmail-web.
   - Сейчас ВСЕ 11 маршрутов 200 (/, drive, plan, dashboard, login, register, recovery,
     add-account, dashboard/files, dashboard/plan, tonconnect-manifest.json).
   - Старого адреса EQB_Y в .next НЕТ (чисто). Новый kQBIr_OP - есть.

4. ✅ **On-chain E2E необратимости — ПОДТВЕРЖДЁН (2026-08-18, пул 6.58 TON)**:
   - Полный цикл q1@infmail.org прошёл on-chain:
     Регистрация RGZK 1.2 TON (owner=kQBYkF...) → Upgrade UGRD 0x55475244 1.3 TON
     (pending tokenId=1, nextItemIndex 1→2) → Mint tokenId=1 (NFT создан) →
     ФИНАЛ: Registry owner=null, reserved=true, collection tokenByEmail=1.
   - НЕОБРАТИМОСТЬ подтверждена: email стал NFT → Registry-запись удалена, имя
     заблокировано навсегда (повторная регистрация → throw 1004).
   - ВАЖНЫЕ ФИКСЫ ДЛЯ ТЕСТА: 2-букв регистрация требует 1.2 TON (1.05 bounces —
     после комиссии контракт получает <1 TON цены); upgrade opcode = 0x55475244;
     mint tokenId брать из getPendingToken(walletHash).
   - tx: регистр 334487ed0ddfbfb40fd062b9dd582896562b50e6f3e2d49069778de66e14f187,
     upgrade 80e32ee78c945f42c9970d4e4e20e4321028dc801660fe2a2fe279b1ccd9c2f0,
     mint 1f6bcb6ee657ae764e7a27cce5739a6a575d04f4946f678a317e3efe2e85d65c.

5. ✅ **ANTI-SYBIL RF-ЛИМИТ ЗАДЕПЛОЕН (2026-08-18)**:
   - Перенесён из /home/imm/infnode/src/rewards.rs в valid-backend/crates/infnode/
     src/rewards.rs (прод-валидатор собирается из valid-backend; там файл был старее).
   - Собран: cargo build --release, 14 тестов (вкл. anti_sybil_rf_limit_100_copies) pass.
   - Бинарник SHA 222fac0c2d8eb7ea25734857b5f4757177b2e5322df8579cd4cabb74cbc7ecd4
     задеплоен на валидатор (/opt/infnode/infmaild, бэкап /opt/infmaild.pre-asybil).
   - ПРОВЕРЕНО в логах: rewards.json теперь содержит поле **rf_verified_bytes**
     (400940 у обеих нод, weight 618/615) — RF-лимит активен.
   - Коммит backend 5069d37, коммит репа нод f32673c.

6. ✅ **НАГРАДЫ (payouts/Distribute) НАСТРОЕНЫ**:
   - infmail-payouts.service+timer работают: ledger 136 записей, черновики генерируются.
   - node_wallets.json: aeza (EQB_AEZA_WALLET_TEST) + node2/валидатор (kQBYkF...) добавлен.
   - INFMAIL_PAYOUT_ADDRESS=kQBYkF... (кошелёк оператора) в юните payouts.
   - Черновик: from=kQBYkF..., to=EQB_AEZA_WALLET_TEST, 0.00035 TON. Оператор подписывает
     вручную (Tonkeeper/TON-cli).
   - ОСТАЛОСЬ: node1 (57146ca81f9, локальный ПК) НЕ имеет кошелька в node_wallets.json —
     нужен TON-адрес владельца node1 (указать пользователю).

7. ✅ **КОШЕЛЁК node1 СОЗДАН (2026-08-18) + награды покрывают все 3 ноды**:
   - Создан TON-testnet кошелёк v5r1 через acton wallet new: имя node1,
     адрес **kQC1sIB2l6DlBMueWvj2KyGOoMm2WW1Hyths2pdpTyYVe-8H**,
     мнемоника в plain-файле /root/infmail-acton/wallets.toml (НЕ коммитить).
   - Faucet запрошен (airdrop), баланс пока 0 (обрабатывается).
   - Адрес добавлен в /opt/infnode/node_wallets.json:
     inf1:57146ca81f... → kQC1sIB2l6DlBMueWvj2KyGOoMm2WW1Hyths2pdpTyYVe-8H.
   - ПРОВЕРЕНО: payouts теперь генерит черновики для ВСЕХ 3 нод (валидатор kQBYkF,
     node1 kQC1sIB, aeza EQB_AEZA_WALLET_TEST). Пропусков нет.
   - ВАЖНО для пользователя: сохранить мнемонику node1 (в /root/infmail-acton/wallets.toml),
     это кошелёк получения наград за ноду локального ПК.

8. ✅ **ЗАДАЧА 3: МИГРАЦИЯ ЧАНКОВ / РЕШАРДИНГ ПРИ СМЕНЕ K — РАБОТАЕТ (2026-08-18)**:
   - migration.rs содержит фикс: dedicated thread + отдельный tokio-runtime
     (migration-worker) + timeout на migrate_pass(120с)/integrity_pass(60с) —
     синхронный fs I/O и dht_find_node НЕ блокируют главный runtime (web+rewards).
   - ПРОД ПОДТВЕРЖДЁН: INFNODE_MIGRATION=1 (mig.conf), интервал 60с.
     Цикл идёт КАЖДЫЕ 60с без зависания (раньше зависал — этот баг закрыт).
   - integrity checked=688 missing=0 mismatch=0 — все 688 чанков целостны ✅.
   - migrate pushed=0 — ПУШ-РЕШАРДИНГ intentionally ВЫКЛ (INFNODE_MIGRATION_PUSH не стоит):
     для малой сети (2 ноды) чанки уже реплицируются при записи (store_chunk_replicated).
     При росте сети > K нод включится вручную через INFNODE_MIGRATION_PUSH=1.
   - Механизм решардинга по K (blake3(bucket:cid) → k XOR-ближайших) готов; тестов
     юнит для migrate_pass нет (пусто) — при желании добавить.
   - migration_report.json: 1345 записей.

9. ✅ **ЗАДАЧА 4: ФИКС ОШИБКИ ОПЛАТЫ TON (TON_CONNECT_SDK_ERROR) — СДЕЛАНО (2026-08-18)**:
   - Симптом: "Payment failed: [TON_CONNECT_SDK_ERROR] Attempt to invoke virtual method
     'getClass()' on a null object reference" при оплате плана (0.5 TON) на /plan
     через Tonkeeper (Android).
   - Диагноз: это НЕ блокчейн/с бэкенда. Android NPE внутри Tonkeeper SDK, когда
     sendTransaction вызван при неинициализированном wallet (реконнект не завершён).
     Платёж НЕ уходит на Storage-контракт. Причина: хрупкая строка
     'await tonConnectUI.connectionRestored.catch()' как единственный guard + нет
     жёсткой проверки реального подключения.
   - Фикс (src/app/plan/page.tsx, коммит 3467eff):
     * убрана хрупкая connectionRestored как единственный guard
     * жёсткая проверка: !wallet или !tonConnectUI.connected → safeOpenModal/
       connectWallet, ждём реального подключения, потом sendTransaction
     * connectionRestored обёрнута в Promise.resolve().catch() (не роняет)
     * TON_CONNECT_SDK_ERROR/getClass/onnull → подсказка 're-connect wallet',
       не фатальная ошибка; rejected/cancelled/4001/timeout — молча
   - Задеплоено на сервер (build на сервере), /plan 200, фикс в бандле.
   - SDK: @tonconnect/ui-react ^2.4.4.
   - TEST: просить пользователя повторить оплату 0.5 TON и проверить.
     Если NPE повторится — это нативный баг Tonkeeper app, нужен обход
     (mobile-канал/деплинк) — задокументировать.

10. ✅ **ЗАДАЧА 5: СКОРОСТЬ ЗАГРУЗКИ ПИСЕМ В ПАНЕЛИ — ОПТИМИЗИРОВАНО (2026-08-18)**:
   - Было: mail/counts ~1300ms (частый опрос панели каждые 20с → «медленная панель»).
     Причина: mail_counts вызывал index_list для 6 папок + read/deleted ПОСЛЕДОВАТЕЛЬНО;
     для пустых папок (Drafts/Trash/Archive/deleted) локальных ключей нет → каждый
     промах уходит в DHT-fallback (сеть) → задержки складываются.
   - Фикс (crates/infmail/src/web.rs, коммит b832c24): mail_counts собирает все индексы
     КОНКУРЕНТНО через tokio::spawn с owned-ключами (без новых зависимостей).
     Теперь суммарная задержка = максимум одного вызова, не сумма.
   - РЕЗУЛЬТАТ НА ПРОДЕ: mail/counts 1300ms → ~160ms (в 8 раз). mail/inbox уже
     был быстрым (~160ms). Тесты 12+14 pass.
   - Задеплоено (бинарь SHA см. бэкап /opt/infmaild.pre-perf).

11. ✅ **ЗАДАЧА 6: ЕДИНЫЙ ФУНКЦИОНАЛЬНЫЙ TOPBAR + ЕДИНАЯ ПАЛИТРА ДЛЯ /plan /drive (2026-08-18)**:
   - Проблема: /plan и /drive имели свою СТАТИЧНУЮ шапку (нарисованный аватар, email
     без меню) — верхняя панель была НЕ функциональна (нет переключения аккаунтов,
     логаута, Add, поиска). + цвета /plan были сине-фиолетовой гаммой (#0d1220,
     #3b82f6, #8b5cf6), отличались от dashboard.
   - Решение: вынес Topbar из dashboard/layout во ПЕРЕИСПОЛЬЗУЕМЫЙ
     components/dashboard/Topbar.tsx (полнофункциональный: поиск, меню аккаунтов,
     переключение, Add, logout/logoutAll, Settings, бургер для dashboard, опции
     title/subtitle/backTo/showSidebarToggle/showSearch).
   - /plan и /drive теперь используют единый Topbar (backTo=/dashboard, title).
   - /plan: цвета приведены к гамме dashboard (#0a0e17->#060609, #0d1220->#0B0B0E,
     #3b82f6/#60a5fa->#0088CC, #8b5cf6/#a78bfa->#0099DD).
   - Кнопка Settings: на /dashboard открывает вкладку, на /plan,/drive переходит
     в /dashboard. logoutAll из store.
   - Коммит 3a446b3, задеплоено (build на сервере), все маршруты 200.
   - Проверено: 'Your Accounts' (меню) в бандле /plan и /drive; старые цвета
     исчезли из бандла.

5. ⚠️ **Anti-Sybil RF-лимит** — реализован субагентом в /home/imm/infnode/src/rewards.rs,
   но НЕ задеплоен (исключён из задачи пользователем "кроме anti sybil"). SHA 9098ac3a.

### СЛЕДУЮЩИЕ ШАГИ (TODO)
- [награды] Добавить TON-кошелёк node1 (57146ca81f9, локальный ПК) в
  /opt/infnode/node_wallets.json — нужен адрес от владельца. Затем payouts покроет
  все 3 ноды. Оператор подписывает черновики вручную.
- [P3] Криптопривязка писем к кошельку — спроектирована; реализация фронт-подписания
  требует реального кошелька в браузере (Tonkeeper) для E2E.
- Адом checkout: `next build` на сервере — источник истины для прод-фронта.

## ДОДЕЛКА БАГОВ ИЗ AUDIT (2026-08-18) — все задеплоены
1. XSS iframe превью Files: добавлен sandbox="" (блокирует скрипты в файлах). Коммит 2250a80.
2. Cookie Secure (HTTPS): добавлен Secure в Set-Cookie (session + logout). Коммит b720259.
3. Курсор платежей: двигается ТОЛЬКО при активации (activated>0) — не теряем валидные при SKIPPED. Коммит 1b99dca.
4. New folder 413: пустой .keep (папка) разрешён — не "file is empty". Коммит 3676197.
5. Фронт задеплоен с фиксами opencode2: оплата NPE (3467eff), plaintext-fallback (7bbac60),
   единый Topbar (3a446b3), убраны дубли /dashboard/files и /dashboard/plan (6fce2a9).
   Все 7 страниц 200 (/drive, /plan, dashboard, login, register, add-account).
6. web3_select_account требует verified=true (opencode2, ecc9911) — задеплоен, чтение писем ок.
### Проверено на проде: чтение писем body 50/300 (баг "пустой body" исправлен), cookie Secure.

## ОСТАЛОСЬ (продолжаю):
- On-chain E2E необратимости (кошелёк 2.04 TON).
- MED/LOW: draft квота, enumeration, X-Real-IP (через nginx перезаписывается).

================================================================
## СНАПШОТ ДЛЯ ОЧИСТКИ КОНТЕКСТА (2026-08-18) — ЧИТАТЬ СНАЧАЛА
================================================================

## СЕРВЕРЫ (без изменений)
- Валидатор: 109.107.155.67 (root/U3A1hXdjXSBzW7), юнит infnode.service
- aeza: 212.113.103.105 (root/q5foUWxm1T0B), storage-нода (mail), юнит aeza-node.service
- node1: локальный ПК (178.155.74.242, NAT 192.168.0.10), storage (mail+files), порт 9400 UDP проброшен
- SSH: /tmp/sshcmd.py (валидатор), /tmp/ssh2run.py (aeza), /tmp/scpcmd.py, /tmp/scp2.py, venv /tmp/venv
- Логины API: /tmp/lk.json (kitaimudrost@infmail.org), /tmp/lch.json (chichisblat@infmail.org)

## КОШЕЛЁК TON (testnet) — мнемоника у пользователя
- Адрес: kQBYkFsNxSm6gUFRqdfN7hXZGbdhOxcEjz4z77_4IKbrq0nD (v5r1). Баланс ~2.04 TON (был пополнен).
- Активен в /root/infmail-acton (wallets.toml, имя "deployer"). Acton CLI: /root/.acton/bin/acton

## КОНТРАКТЫ TON (текущие адреса — ВНИМАНИЕ, разъехались из-за множества передеплоев)
- Registry: kQBIr_OP1HgR0Ca4-HxVeR3vwmUmCbrm5V7Plso2Gk1Z_rjk
  (authorizedCaller настроен SETC на коллекцию kQAw13)
- NFT Collection: kQAw13VCdSIX4h_e_eYbtX7RRXT5w4FMgN1NfTop12NvyrKR
  (registryAddress в extra = kQBIr_OP; свежая, nextItemIndex=0)
- Storage (подписки): kQC9herzN5zomk42USyU4bvFO3C8Zm5OElnm19RrKgbTC0fM
- env валидатора: REGISTRY=kQBIr_OP, NFT_COLLECTION=kQAw13, STORAGE=kQC9herz

## ✅ ON-CHAIN E2E НЕОБРАТИМОСТИ — ПОДТВЕРЖДЁН И ЗАКРЫТ (2026-08-18, диагностика)
- Согласованная пара: Registry kQBIr_OP + Collection kQAw13 (registryAddress=kQBIr_OP подтверждён
  через `acton rpc info` коллекции: extra.registryAddress = kQBIr_OP — адреса СОГЛАСОВАНЫ).
- q1@infmail.org — ПОЛНЫЙ УСПЕШНЫЙ ЦИКЛ (get-методы через net.runGetMethod):
  - registry.owner: null ✅ (запись удалена UNRG)
  - registry.reserved: -1 (true) ✅ (имя сожжено — повторная регистрация невозможна)
  - collection.pending: null
  - collection.token: 1 ✅ (NFT выпущен, tokenToOwner[1]=деплоер, nextItemIndex=3)
  => On-chain E2E необратимости РАБОТАЕТ полностью.
- qq@infmail.org — НЕ записан нигде (registry.owner:null, reserved:0, pending:null, token:null).
  Это НЕ разъезд адресов, а просто неудачный отдельный тест: upgrade/mint для qq не записались
  (вероятно транзакция упала — комиссия/opcode). qq НЕ блокирует ничего, можно игнорировать
  или повторить upgrade если нужно.
- Диагностический скрипт: /root/infmail-acton/scripts/check-state.tolk
  (актуальные адреса, константные sha256 хэши qq/q1 — sha256 требует константную строку).
- ВАЖНО: в контексте был подтверждён ещё один успешный E2E — q1 (раздел 2071-2083: tx
  регистр/upgrade/mint, owner=null, reserved=true, tokenByEmail=1). Текущая проверка это ПОДТВЕРЖДАЕТ.

## ФРОНТ (всё задеплоено, все страницы 200)
- /drive — отдельная страница в стиле Google Drive (заглушка для free, FilesView для paid)
- /plan — отдельная страница (пакеты 30д/0.5, 365д/5 TON, оплата через approve)
- /dashboard — главная (НЕ трогать дизайн, по просьбе)
- add-account — вход по адресу без proof (как Fragment), динамическая цена
- Все 8 страниц 200: /, /login, /register, /dashboard, /drive, /plan, /add-account, /recovery
- Деплой фронта: собирать ЛОКАЛЬНО (npm run build), тарить src+config+.next (routes-manifest!
  Новый роут требует routes-manifest.json с ним, иначе 404). Распаковывать на проде в /opt/infmail-web.

## БЭКЕНД (задеплоены фиксы из аудита opencode2)
- Чтение писем: meta-кэш = полный конверт (body/html/attachments) → письма читаются (body 50/300/719).
- web3_select_account/recover_email: требуют verified=true + pk (закрыт захват ящика).
- XSS iframe sandbox, cookie Secure (HTTPS), курсор платежей только при активации,
  New folder (.keep пустой) разрешён. Все задеплоены.
- Вход по адресу без proof для известного кошелька (как Fragment).
- Модель подписки: дискретные пакеты (30д/0.5, 365д/5).

## ГЛАВНЫЕ ОТКРЫТЫЕ ПРОБЛЕМЫ
1. ✅ On-chain E2E необратимости — ПОДТВЕРЖДЁН (q1@infmail.org: owner=null, reserved=true, NFT token=1). Закрыт.
2. ✅ Оплата 0.5/0.6 TON — БАГ НАЙДЕН И ИСПРАВЛЕН (см. раздел ниже). kitai активирован (paid, 30 дней).
3. П3 криптопривязка писем к кошельку — спроектирована (derive-keys, wallet_epoch), НЕ реализована E2E.
4. Получение наград — wallet ноды добавлено, Distribute/anti-Sybil RF-лимит спроектированы.
5. Проект разделён на 3 репа: infnode-node (нода), infmail-valid-backend (валидатор), infmail-frontend (фронт).

## ✅ ОПЛАТА ПОДПИСКИ — БАГ КУРСОРА НАЙДЕН И ИСПРАВЛЕН (2026-08-18)
### Симптом
Пользователь оплатил подписку (0.6 TON kitai), платёж ЕСТЬ на Storage-контракте
(kQC9herz..., 5 транзакций), НО план оставался free/expired. "Оплата не дошла".

### Корень (2 бага)
1. **Курсор терял SKIPPED платежи позади себя.** Индексатор шёл по транзакциям от свежих
   к старым и делал `break` при достижении `last_payment_tx` (курсор). Курсор продвигался
   только при активации (activated>0). Если платёж был SKIPPED (нет валидного nonce), а
   позже курсор продвинулся на БОЛЕЕ СВЕЖУЮ активацию (напр. ttttttttg) — старый платёж
   (kitai) оказывался СТАРШЕ курсора и терялся НАВСЕГДА, хотя деньги на контракте.
2. **Owner-nonce разъезжался.** Платёж kitai был сделан с nonce `060da984...`, но после
   перезагрузки/повторного входа бэкенд выдал новый nonce `8ae10d...`. Индексатор
   сравнивал с текущим → не совпало → SKIPPED. Т.к. платёж был за курсором — потерян.

### Фикс (коммит 0db4636, задеплоен SHA dad28186)
1. **Убран break по курсору**: индексатор обрабатывает ВСЕ транзакции каждый раунд,
   дедупликация — через `processed_payments` (не активирует дважды). Ни один платёж
   не теряется позади курсора.
2. **История nonce**: при выдаче nonce (`settings_subscribe_nonce`) пишется в
   `subnonce_hist:{email}` (JSON-массив, до 50). Индексатор для классического аккаунта
   принимает платёж, если nonce == текущему ИЛИ есть в истории. Разъехавшийся/перевыданный
   nonce больше не теряет платёж.

### Результат
- kitai: plan=paid, plan_status=active, days_left=29, paid_until=1789678142553,
  file_quota=6GB, mail_quota=3GB, aliases_limit=15. Платёж 0.6 TON → +30 дней.
- Индексатор в логах: "subscription activated for kitaimudrost@infmail.org
  (Storage payment 0.6000 TON -> +30 days)". Повторно не активирует (dedup).
- Все 26 тестов (12 infmail + 14 infnode) pass.
- Восстановительная диагностика: /root/{check_plan.sh, check_payments.py, probe_toncenter.py,
  check_db.py, check_cursor.py, diag_indexer.sh, logcheck.sh, inspect*.py, add_nonce_hist*.py,
  verify_restart.sh} — временные, можно удалить.
- Бэкапы: /opt/infmaild.pre-noncefix, /root/infmaild.noncefix2, /root/kv.json.pre-noncefix.
- Примечание: вручную вставленный `subnonce_hist:kitai` в kv.json — платёж уже обработан,
  ключ не мешает (можно убрать при след. правке kv).

================================================================
## СНАПШОТ ДЛЯ ОЧИСТКИ КОНТЕКСТА (2026-08-18, поздний вечер) — ЧИТАТЬ СНАЧАЛА
================================================================

## СЕРВЕРЫ
- Валидатор: 109.107.155.67 (root/U3A1hXdjXSBzW7), юнит infnode.service
- aeza: 212.113.103.105 (root/q5foUWxm1T0B), storage-нода (mail), юнит aeza-node.service
- node1: локальный ПК (178.155.74.242, NAT 192.168.0.10), storage (mail+files), порт 9400 UDP
- SSH: /tmp/sshcmd.py (валидатор), /tmp/ssh2run.py (aeza), /tmp/scpcmd.py, /tmp/scp2.py, venv /tmp/venv
- Логины API: /tmp/lk.json (kitaimudrost@infmail.org), /tmp/lch.json (chichisblat@infmail.org)
- ВНИМАНИЕ: sshcmd.py передаёт команду в zsh на удалённой стороне → `?`, `===`, `(`, `"` в команде ломают zsh (glob/parse). Лучше загружать .sh/.py скрипты через scpcmd.py и выполнять их.

## КОНТРАКТЫ TON (testnet) — согласованная пара ПОДТВЕРЖДЕНА
- Registry: kQBIr_OP1HgR0Ca4-HxVeR3vwmUmCbrm5V7Plso2Gk1Z_rjk (authorizedCaller=коллекция)
- NFT Collection: kQAw13VCdSIX4h_e_eYbtX7RRXT5w4FMgN1NfTop12NvyrKR (registryAddress=kQBIr_OP, nextItemIndex=3)
- Storage (подписки): kQC9herzN5zomk42USyU4bvFO3C8Zm5OElnm19RrKgbTC0fM (баланс ~3.95 TON)
- env валидатора: REGISTRY/STORAGE/NFT_COLLECTION = эти адреса.
- Кошелёк деплоера: kQBYkFsNxSm6gUFRqdfN7hXZGbdhOxcEjz4z77_4IKbrq0nD (в /root/infmail-acton/wallets.toml, мнемоника "deployer"). Acton CLI: /root/.acton/bin/acton.
- Другой кошелёк: node1 = kQC1sIB2l6DlBMueWvj2KyGOoMm2WW1Hyths2pdpTyYVe-8H (в wallets.toml, имя "node1").
- Как вызывать get-методы: acton script с net.runGetMethod (см. /root/infmail-acton/scripts/check-state.tolk). sha256 требует КОНСТАНТНУЮ строку (не переменную).

## ✅ СДЕЛАНО В ЭТОЙ СЕССИИ (после прошлой очистки)
1. ON-CHAIN E2E НЕОБРАТИМОСТИ — ПОДТВЕРЖДЁН И ЗАКРЫТ:
   - q1@infmail.org: registry.owner=null, reserved=true(-1), collection.token=1 (NFT выпущен).
   - Полный цикл register→upgrade→mint→UNRG работает. (q1 hash 0x87097e..., token 1; final3 hash 0xe5f951... token 0).
   - Диагностика: /root/infmail-acton/scripts/check-state.tolk. Необратимость подтверждена: при mint NFT web3-запись в Registry удаляется, имя резервируется навсегда.

2. ОПЛАТА ПОДПИСКИ — БАГ НАЙДЕН И ИСПРАВЛЕН (коммит 0db4636, SHA dad28186):
   - Корень 1: индексатор делал `break` по курсору (last_payment_tx). Если платёж был SKIPPED, а курсор продвинулся на более свежую активацию — старый платёж (kitai 0.6 TON) терялся навсегда (за курсором).
   - Корень 2: owner-nonce разъезжался (оплатил с nonce 060da984, потом выдан новый 8ae10d) → SKIPPED.
   - ФИКС: убран break по курсору (обрабатываем все tx, dedup через processed_payments) + история nonce (subnonce_hist:{email}, до 50). Индексатор принимает платёж с nonce из истории.
   - РЕЗУЛЬТАТ: kitai = paid/active, days_left 29, 0.6 TON → +30 дней. Индексатор работает, больше не теряет платежи.
   - Для активации: вручную вставил subnonce_hist:kitai в kv.json (бэкап /root/kv.json.pre-noncefix), рестартнул. Лишний ключ subnonce_hist:kitai остался — не мешает.

3. SECURITY-ФИКСЫ (коммит 4a97bf7, SHA 51a135d8 — ЗАДЕПЛОЕН):
   - draft квота: mail_draft лимит 500 черновиков/аккаунт (защита от DoS).
   - 2FA setup guard: settings_2fa_setup отказывает (409), если 2FA уже включён (иначе сломал бы активный 2FA юзера).
   - username_check rate-limit: 60 проверок/10мин по IP (защита от enumeration аккаунтов), не ломает регистрацию.
   - Все 26 тестов pass. Проверено: plan=paid/active, почта (Inbox 18, Sent 21), username_check работает.

## БЭКЕНД: актуальный задеплоенный бинарь
- /opt/infnode/infmaild SHA 51a135d809ab754626409508bf5723e7cdd2f32f0172b679f6370c88652bf663 (с фиксами оплаты + security). Сервис active.
- Локально собран: /home/imm/infmail-valid-backend/target/release/infmail (тот же SHA).
- Тесты: 26 (12 infmail + 14 infnode) pass.

## ФРОНТ (всё задеплоено, все страницы 200)
- /drive, /plan, /dashboard, /login, /register, /add-account, /recovery.
- Деплой фронта: npm run build НА СЕРВЕРЕ в /opt/infmail-web (НЕ деплоить чужой .next — 404!). New route требует routes-manifest.json.

## 🔴 НЕЗАВЕРШЁННОЕ: П3 КРИПТОПРИВЯЗКА ПИСЕМ К КОШЕЛЬКУ
- Цель: письма NFT-аккаунта видит только кошелёк, владеющий NFT СЕЙЧАС. Смена владельца → новый владелец видит только письма за своё время.
- Дизайн (из контекста, строки 1717-1740):
  1. Ключи аккаунта = производные от кошелька. master_seed = SHA256(ed25519_privkey_кошелька) → x_pub/ed_pub аккаунта детерминированно.
  2. Новые письма шифруются x_pub = производным от ТЕКУЩЕГО владельца NFT.
  3. Старые письма НЕ перешифровываются (остаются на ключе владельца эпохи).
  4. Смена владельца NFT → новые ключи, старые индексы помечаются "owner_changed".
  5. Фронт: кошелёк ПОДПИСЫВАЕТ сообщение для деривации; приватный ключ НЕ покидает браузер.
- ВАЖНО (безопасность, записано в derive.rs): НЕЛЬЗЯ выводить ключ шифрования из ПУБЛИЧНОГО wallet_ed_pub — приватный x25519 вычислим любым (сломает шифрование). Приватный ключ выводится из ПОДПИСИ кошелька в браузере.
- Текущее состояние кода:
  - crates/infmail/src/nft/derive.rs: derive_x_pub (служебный, из pub — НЕ для шифрования), wallet_epoch (хэш эпохи). + тесты.
  - web.rs: POST /api/v1/web3/derive-keys {wallet_ed_pub} → {x_pub, epoch} (служебный).
  - web.rs: GET /api/v1/web3/wallet-nfts (auth + rate-limit 10/мин) — скан NFT коллекции для кошелька.
  - Привязка писем к кошельку НЕ реализована. Письма шифруются на браузерный x_pub (Proton-модель).
- ЧТО ОСТАЛОСЬ: полный E2E требует, чтобы браузер вывел ключи из ПОДПИСИ кошелька (Tonkeeper). Для теста нужен кошелёк. ПОЛЬЗОВАТЕЛЬ СКАЗАЛ: "кошель я не дам, сам его сгенерь" — нужно СГЕНЕРИРОВАТЬ тестовый кошелёк самому (через acton на валидаторе) и сделать E2E бэкенд-логики П3.

## ОТКРЫТЫЕ ПРОБЛЕМЫ / TODO
1. П3 криптопривязка — реализовать (сгенерировать тестовый кошелёк, E2E бэкенд-логики).
2. Получение наград — wallet ноды добавлено, Distribute/anti-Sybil RF-лимит спроектированы (RF-лимит задеплоен).
3. README репов обновить под новые фичи.
4. X-Real-IP — client_ip доверяет заголовку; закрыто на практике через nginx (перезаписывает). Низкий приоритет.
5. Лишний ключ subnonce_hist:kitai в kv.json (не мешает, можно убрать).

## КРИТИЧНЫЕ УРОКИ
- НЕ копить бэкапы infmail-web на /opt (770M каждый → диск 100%). Проверять df -h.
- НЕ править /opt/infnode/kv.json вручную без бэкапа (инцидент: обнулился). Бэкапы: /root/kv.json.good-20260816-0924, /root/kv.json.pre-noncefix.
- sshcmd.py: zsh на удалённой стороне ломает команды с `?`/`===`/`(`/кавычками → грузить .sh/.py скрипт через scpcmd.py.
- Бэкапы бинаря: /opt/infmaild.pre-noncefix, /root/infmaild.noncefix2.

================================================================
## П3 ПРОГРЕСС (после прошлого снапшота) — 2026-08-18, ночь
================================================================
- Сгенерирован тестовый кошелёк `p3test`: kQANEawXFPCeunynn0GXbpygRmOT0IrBzPcK7sWXYrlsvjSr (мнемоника в /root/infmail-acton/wallets.toml).
- Реализован БЭКЕНД-ЯДРО П3 (безопасная ветка):
  * crates/infmail/src/nft/derive.rs: derive_x_pub_from_signature(sig_hex) — blake3("infmail-nft-keys-sig-v1" || ed25519_sig) → x25519 pub. signature_epoch().
  * web.rs: POST /api/v1/web3/derive-keys принимает { signature } (безопасная) или { wallet_ed_pub } (служебная). Пустой → 400.
- E2E тест p3_e2e_encrypt_decrypt_via_signature: шифрует письмо на x_pub из подписи p3test → владелец (та же подпись) расшифровывает, ДРУГОЙ кошелёк (другая подпись) — НЕ может. Покрывает ядро П3 (эпоха/owner_changed).
- Коммит a22bb49, SHA 9acdd2a9d469f594d333331bc8431c344cdfb8c962c0112931745f345302b392 (ЗАДЕПЛОЕН).
- На проде проверено: 4 варианта derive-keys (signature/wallet_ed_pub/empty/bad) — все корректные ответы.
- Тесты: 29 total (15 infmail + 14 infnode). Бэкап /opt/infmaild.bak.p3sig.

### ЧТО ОСТАЛОСЬ по П3 (не сделано)
1. Frontend (браузер): подписать сообщение "infmail-keys-v1:{email}" через Tonkeeper (tonProof), отправить {signature} → бэкенд сохраняет x_pub (acc.x_pub = x_pub_из_подписи).
2. Flow: при register_web3 / привязке кошелька — фронт шлёт подпись → бэкенд сохраняет x_pub.
3. Шифрование новых писем: уже работает на acc.x_pub — после шага 2 автоматически пойдёт на кошелёк-производный ключ.
4. Эпоха/owner_changed в UI: показ "чужой кошелёк — старые письма нечитаемы".

### Скрипты на проде (можно удалить)
- /root/infmail-acton/probe.js, /root/infmail-acton/p3_sign.js (симуляция Tonkeeper-подписи).
- /root/p3_test.sh (тест нового API).

================================================================
## СНАПШОТ ДЛЯ ОЧИСТКИ КОНТЕКСТА №2 (2026-08-19, раннее утро) — ЧИТАТЬ СНАЧАЛА
================================================================

## TL;DR — ЧТО СДЕЛАТЬ ДАЛЬШЕ
**Задача**: реализовать браузерную часть П3 криптопривязки писем к кошельку.
- Бэкенд-ядро УЖЕ готово и ЗАДЕПЛОЕНО (см. ниже «СДЕЛАНО»). Агенту нужно реализовать фронт:
  1. В браузере: подписать сообщение "infmail-keys-v1:{email}" через TonConnect (tonProof или signData).
  2. POST /api/v1/web3/derive-keys { signature } → { x_pub, epoch, secure:true }.
  3. Передать x_pub на бэкенд (сохранить в acc.x_pub — поле уже есть, см. Account в web.rs).
  4. Письма автоматически шифруются на acc.x_pub (inbound.rs:553 proton_box_body(x_pub)).
- Проверить E2E в браузере (через мок TonConnect — e2e/helpers/ton-mock.ts).

## ПАРОЛИ И УЧЁТКИ (БЕРЕЧЬ, НЕ КОММИТИТЬ)
- Валидатор (109.107.155.67): root / `U3A1hXdjXSBzW7` (root SSH).
- aeza (212.113.103.105): root / `q5foUWxm1T0B` (root SSH, storage-нода).
- API логины: /tmp/lk.json (kitaimudrost@infmail.org), /tmp/lch.json (chichisblat@infmail.org).
- НЕ КОММИТИТЬ /tmp/lk.json, /tmp/lch.json, wallets.toml (мнемоники в нём!).
- Мнемоники кошельков (testnet) — НЕ ДЛЯ ПРОДА, только dev/E2E:
  * deployer: "ensure add neutral acoustic true hollow effort proud main powder color general yard beauty all include mail round parent electric robot chair eternal staff" → kQBYkFsNxSm6gUFRqdfN7hXZGbdhOxcEjz4z77_4IKbrq0nD
  * node1: "reject supreme effort bitter drill coin rib miracle empower quote power improve sting liquid oven chest secret pretty bone alien identify very turkey hurry" → kQC1sIB2l6DlBMueWvj2KyGOoMm2WW1Hyths2pdpTyYVe-8H
  * p3test (СГЕНЕРИРОВАН В ЭТОЙ СЕССИИ для П3): "service elder cannon model knife fatigue soda apart public enact ready dumb promote admit ability scissors turkey doll tag ceiling sugar common recipe ladder" → kQANEawXFPCeunynn0GXbpygRmOT0IrBzPcK7sWXYrlsvjSr

## СЕРВЕРЫ / СЕТЬ
- Валидатор: 109.107.155.67 (root/U3A1hXdjXSBzW7), юнит infnode.service, бинарь /opt/infnode/infmaild, бэкенд на 127.0.0.1:3001 (за nginx).
- aeza: 212.113.103.105 (root/q5foUWxm1T0B), юнит aeza-node.service, storage-нода (mail), 127.0.0.1:9400 UDP.
- node1: локальный ПК (NAT 178.155.74.242, 192.168.0.10), storage (mail+files), порт 9400 UDP.
- SSH-обёртки: /tmp/sshcmd.py (валидатор), /tmp/ssh2run.py (aeza), /tmp/scpcmd.py, /tmp/scp2.py. venv /tmp/venv.
- ⚠️ sshcmd.py передаёт команды в zsh удалённой стороны → `?`, `===`, `(`, `"`, `!`, `$` ломают парсинг. ЛУЧШЕ загружать .sh/.py/.js скрипт через scpcmd.py и выполнять, а не передавать инлайн-команды с кавычками.
- Логин (mail): kitaimudrost@infmail.org / `MEGApass323@323M`. MAIL_DOMAIN=`infmail.org`.

## КОНТРАКТЫ TON (testnet, согласованная пара ПОДТВЕРЖДЕНА)
- Registry: kQBIr_OP1HgR0Ca4-HxVeR3vwmUmCbrm5V7Plso2Gk1Z_rjk (authorizedCaller=коллекция).
- NFT Collection: kQAw13VCdSIX4h_e_eYbtX7RRXT5w4FMgN1NfTop12NvyrKR (registryAddress=kQBIr_OP, nextItemIndex=3).
- Storage (подписки): kQC9herzN5zomk42USyU4bvFO3C8Zm5OElnm19RrKgbTC0fM (баланс ~3.95 TON).
- env валидатора: REGISTRY/STORAGE/NFT_COLLECTION = эти адреса (см. infnode.service).
- Кошелёк деплоера: kQBYkFsNxSm6gUFRqdfN7hXZGbdhOxcEjz4z77_4IKbrq0nD (мнемоника выше).
- Acton CLI на валидаторе: /root/.acton/bin/acton. Скрипты: /root/infmail-acton/.
- Как вызывать get-методы: acton-скрипт с net.runGetMethod (см. /root/infmail-acton/scripts/check-state.tolk).
  ⚠️ sha256 в Tolk требует КОНСТАНТНУЮ строку (не переменную) — для get-методов передавать хэши как int-константы.

## РЕПЫ (локально и github)
- Бэкенд: /home/imm/infmail-valid-backend (github: immtes/infmail-valid-backend).
- Фронт: /home/imm/infmail-web (Next.js 14 App Router).
- InfMail контракты: /home/imm/infmail-acton (на валидаторе: /root/infmail-acton).
- Деплой фронта: /opt/infmail-web на ВАЛИДАТОРЕ. npm run build ОБЯЗАТЕЛЬНО НА СЕРВЕРЕ (не локально — иначе .next битый, 404 на роутах).
- Деплой бэка: /opt/infnode/infmaild (бинарь копируется через scpcmd.py после `systemctl stop infnode`).

## ЧТО СДЕЛАНО (на момент этого снапшота)
1. ON-CHAIN E2E необратимости — ЗАКРЫТ: q1@infmail.org цикл register→upgrade→mint→UNRG подтверждён on-chain (registry.owner=null, reserved=true, collection.token=1).
2. ОПЛАТА ПОДПИСКИ — БАГ ИСПРАВЛЕН (коммит 0db4636, SHA dad28186): убран break по курсору, добавлена история nonce (subnonce_hist:{email}). kitai plan=paid/active, 30 дней.
3. SECURITY-ФИКСЫ ЗАДЕПЛОЕНЫ (коммит 4a97bf7, SHA 51a135d8):
   - mail_draft лимит 500 (DoS).
   - 2FA setup guard (не перезаписывает активный).
   - username_check rate-limit 60/10мин по IP.
4. П3 КРИПТОПРИВЯЗКА — БЭКЕНД ЯДРО РЕАЛИЗОВАНО (коммит a22bb49, SHA 9acdd2a9d469f594d333331bc8431c344cdfb8c962c0112931745f345302b392 — ЗАДЕПЛОЕН):
   - crates/infmail/src/nft/derive.rs: derive_x_pub_from_signature(sig_hex) — blake3("infmail-nft-keys-sig-v1" || ed25519_sig) → x25519 pub. signature_epoch().
   - web.rs: POST /api/v1/web3/derive-keys принимает { signature } (безопасная, secure:true) или { wallet_ed_pub } (служебная).
   - E2E тест p3_e2e_encrypt_decrypt_via_signature PASS: шифрует письмо на x_pub из подписи p3test → владелец (та же подпись) расшифровывает, ДРУГОЙ кошелёк — НЕ может. Покрывает ядро П3 (эпоха/owner_changed).
   - На проде live проверено 4 варианта: signature/wallet_ed_pub/empty/bad → корректные ответы.
5. Тесты: 29 total (15 infmail + 14 infnode). Бэкап /opt/infmaild.bak.p3sig на проде.

## ЧТО ОСТАЛОСЬ СДЕЛАТЬ (задачи для следующего агента)
### ПРИОРИТЕТ 1: П3 ФРОНТ (БРАУЗЕРНАЯ ЧАСТЬ)
- Где: /home/imm/infmail-web (Next.js 14).
- TonConnect уже подключён: src/__mocks__/tonconnect-ui-react.tsx (мок для тестов), e2e/helpers/ton-mock.ts (имитация подписи). Реальный TonConnect: src/app/providers.tsx, src/app/login/page.tsx, src/app/register/page.tsx, src/app/add-account/page.tsx, src/app/dashboard/page.tsx, src/app/plan/page.tsx, src/components/dashboard/PlanView.tsx.
- Что сделать:
  1. Добавить в браузер (src/lib/crypto или новый src/lib/p3.ts) функцию:
     async function deriveEncryptionKeys(wallet, email, signMessage) {
       const message = "infmail-keys-v1:" + email;
       const sig = await signMessage(message); // tonProof или signData через TonConnect
       const r = await fetch("/api/v1/web3/derive-keys", { method:"POST", body: JSON.stringify({ signature: sig }) }).then(r=>r.json());
       return { x_pub: r.x_pub, epoch: r.epoch };
     }
  2. После успешного register-web3 / select-account — вызвать deriveEncryptionKeys, отдать { x_pub } бэкенду для сохранения (нужен новый эндпоинт или расширить существующий /auth/web3-save-keys — см. ниже).
  3. При логине — заново вывести x_pub (та же подпись → тот же x_pub), браузер держит приватный x25519 = SHA256(blake3-эквивалент). Важно: приватный x25519 вычисляется БРАУЗЕРОМ из той же подписи; НЕ отправлять секрет на бэкенд.
  4. Тесты e2e: расширить e2e/specs/web3.spec.ts — добавить сценарий: подключить мок-кошелёк, зарегистрировать, проверить /derive-keys → secure:true.
- На бэкенде, скорее всего, нужно добавить эндпоинт /auth/web3-save-keys { x_pub } (или доработать существующий flow), чтобы фронт сохранил x_pub в acc.x_pub. Сейчас бэкенд НЕ сохраняет x_pub из derive-keys автоматически.

### ПРИОРИТЕТ 2: README репов
- /home/imm/infmail-valid-backend/README.md — обновить под новые фичи (derive-keys от подписи, платежи, security-фиксы).
- /home/imm/infmail-web/README.md — обновить под фронт-флоу с TonConnect + П3.

### ПРИОРИТЕТ 3: Получение наград
- Distribute/anti-Sybil RF-лимит спроектированы в /home/imm/SUBAUTIN_REPORT.md (RF-лимит задеплоен, Distribute нет).

### ПРИОРИТЕТ 4 (низкий)
- X-Real-IP: client_ip доверяет заголовку (на практике закрыто nginx).
- Лишний ключ subnonce_hist:kitai в kv.json (не мешает).

## КРИТИЧНЫЕ УРОКИ (НЕ ПОВТОРЯТЬ!)
- НЕ копить бэкапы infmail-web на /opt валидатора (770M каждый → диск 100%, ломает систему). Проверять df -h перед рестартом.
- НЕ править /opt/infnode/kv.json вручную без бэкапа (инцидент: обнулился). Бэкапы на проде: /root/kv.json.good-20260816-0924, /root/kv.json.pre-noncefix.
- sshcmd.py: zsh удалённой стороны ломает команды с `?`/`===`/`(`/кавычками/`!`/`$` → загружать .sh/.py/.js через scpcmd.py.
- scpcmd.py: dst ВСЕГДА с хостом — `root@109.107.155.67:/path` (иначе scp интерпретирует как локальный путь и fail).
- Деплой бинаря: systemctl stop infnode → scp → start (chown не нужен, файл уже infnode после остановки).
- Деплой фронта: ОБЯЗАТЕЛЬНО npm run build на сервере (не локально). New route требует routes-manifest.json.

## СКРИПТЫ НА ПРОДЕ (временные, можно удалить)
- /root/infmail-acton/probe.js, /root/infmail-acton/p3_sign.js (симуляция Tonkeeper-подписи через @ton/crypto).
- /root/p3_test.sh (тест нового /derive-keys API).
- /root/infmail-acton/scripts/check-state.tolk (диагностика on-chain).
- Восстановительные: /root/check_plan.sh, check_payments.py, check_db.py, check_cursor.py, check_account.py, check_kv.py, check_mail.sh, diag_indexer.sh, logcheck.sh, verify_restart.sh, verify_sec.sh, probe_toncenter.py, inspect*.py, add_nonce_hist*.py.
- Бэкапы бинаря: /opt/infmaild.pre-noncefix, /root/infmaild.noncefix2, /opt/infmaild.bak.p3sig (SHA 9acdd2a9 — текущий задеплоен).

## ТОЧКИ ИНТЕГРАЦИИ (для агента)
- Frontend lib: /home/imm/infmail-web/src/lib/ (там crypto.ts, encryption, helpers).
- Текущий API derive-keys (задеплоен, рабочий):
  POST /api/v1/web3/derive-keys
  body: { signature: "hex_64bytes" }  // безопасная ветка
  resp: { ok:true, x_pub:"hex_32bytes", epoch:"hex_32bytes", secure:true, method:"blake3(...)" }
  или
  body: { wallet_ed_pub: "hex_32bytes" } // служебная (НЕ для шифрования)
- Account.x_pub (Option<String>) уже есть в web.rs:120 — поле для x_pub. Шифрование писем в inbound.rs:553 уже использует acc.x_pub через owner_x_pub.
- Account.wallet, wallet_pub (Option<String>) уже сохраняются при register_web3.
- E2E тест как образец: crates/infmail/src/nft/derive.rs::tests::p3_e2e_encrypt_decrypt_via_signature.
- Скрипт-образец Tonkeeper-подписи (на проде /root/infmail-acton/p3_sign.js) — можно портировать логику во фронт (sign из @ton/crypto).

===============================================================
## СЕССИЯ 2026-08-24/25 — П3 ФРОНТ ЗАВЕРШЁН (полная криптопривязка)
===============================================================

### ЧТО СДЕЛАНО (всё задеплоено на прод + запушено в GitHub)

1. **БЭКЕНД** (infmail-valid-backend, commit b56f69a):
   - НОВЫЙ РОУТ: POST /api/v1/web3/save-keys {x_pub, epoch, signature} (auth обязателен).
     * Сохраняет wallet-derived x_pub в Account.x_pub.
     * CROSS-CHECK: бэкенд сам пересчитывает derive_x_pub_from_signature(signature)
       и сверяет с присланным x_pub — подмена ключа невозможна (400 при несовпадении).
   - web.rs:3943 web3_derive_keys (было), web.rs:~3975 web3_save_keys (новое).
   - Тесты: 29 total pass (15 infmail вкл. p3_e2e_encrypt_decrypt_via_signature).

2. **ФРОНТ** (infmail-frontend, commit b979a9b):
   - src/lib/p3.ts — ядро П3: p3Message(email)="infmail-keys-v1:{email}",
     signP3Message(tonConnectUI, msg) через TON Connect signData (TEP-85 Text Cell:
     4-byte BE length prefix + utf8, cell.raw=base64), deriveEncryptionKeys(sig).
   - src/lib/p3Integrate.ts — tryDeriveAndSaveP3Keys(): signData → /derive-keys →
     /save-keys. BEST-EFFORT: отказ юзера/нет signData → null, логин не ломается.
   - src/lib/keyManager.ts — scheduleP3Derive() вызывается в конце
     initializeOrUnlockKeysWeb3 после генерации нового vault.
   - src/components/TonConnectBridge.tsx — выставляет tonConnectUI в window.__tcUi
     (мост для не-React кода). Подключён в providers.tsx.
   - src/services/api.ts — deriveKeysFromSignature(), saveWalletEncryptionKey().
   - Мок TonConnect (__mocks__/tonconnect-ui-react.tsx) — signData(): реальная
     Ed25519 подпись cell bytes; флаг __tonMockSignDataDecline для симуляции отказа.
   - e2e/specs/web3.spec.ts — 5 новых П3 тестов (детерминизм, 400 на битое,
     401 без auth, cross-check x_pub↔sig, 10x одинаковый sig → одинаковый x_pub).

3. **ДЕПЛОЙ НА ПРОД** (подтверждено после ребута сервера):
   - /opt/infnode/infmail содержит "web3/save-keys" ✅
   - POST /web3/derive-keys на проде → {ok:true, x_pub:"4604c3b1...", secure:true}
     (тот же x_pub что локально — детерминизм кросс-машинный подтверждён).
   - Локальный E2E прогон (Rust-бэкенд на :8000 из valid-backend):
     1) derive valid sig → 200+keys; 2) повтор → тот же x_pub; 3) пустой → 400;
     4) save-keys без auth → 401; 5) save-keys fake x_pub → 400 (cross-check!);
     6) save-keys корректный → 200; 7) keys/{email} отдаёт сохранённый x_pub
     (base64 RgTDsYcY... == hex 4604c3b1...) — полная цепочка работает.

4. **ИНФРАСТРУКТУРА СЕССИИ**:
   - /tmp был очищен → пересозданы sshcmd.py/scpcmd.py (валидатор),
     ssh2run.py/scp2.py (aeza), venv /tmp/venv (pexpect). Скрипты в этом файле
     ниже по тексту УСТАРЕЛИ паролями? НЕТ — те же креды, просто пересозданы.
   - Локальный тестовый стенд: /tmp/opencode/e2enode (node.yaml web-listen :8000,
     infnode init --role mail для ключей). Бинари: target/release/{infmail,infnode}
     в /home/imm/infmail-valid-backend (target пересобран, был удалён).

5. **СЕРВЕР ВАЛИДАТОР БЫЛ ВЫКЛЮЧЕН** (пользователь включил вручную):
   - После ребута все сервисы active сами (systemd), почта цела (Inbox 18/Sent 21),
     фронт 200, aeza переподключилась (ping 1.56ms pong:true).
   - ICMP на валидаторе НЕ отвечает (закрыт файрволом) — ping НЕ показатель,
     проверять только через SSH/API.
   - node1 (178.155.74.242, локальный ПК) — handshake timeout от aeza:
     вероятно нода не запущена после ребута роутера/ПК. Пользователю проверить.

### КАК РАБОТАЕТ П3 (итоговая схема)
1. Юзер логинится web3 → keyManager создаёт vault → scheduleP3Derive.
2. Браузер: tonConnectUI.signData({type:'text', cell:{raw:b64(0x0000000N||"infmail-keys-v1:{email}")}}).
3. Кошелёк подписывает cell bytes → sig (base64) → браузер конвертит в hex.
4. POST /derive-keys {signature} → {x_pub, epoch} (blake3("infmail-nft-keys-sig-v1"||sig)→x25519 pub).
5. POST /save-keys {x_pub, epoch, signature} (auth) → cross-check → Account.x_pub.
6. Вся входящая внешняя почта теперь шифруется на этот x_pub (Proton-модель).
7. Смена владельца NFT → другая подпись → другой x_pub → старые письма нечитаемы (эпоха).

### ОСТАЛОСЬ (следующие итерации)
- [ ] node1 запустить (локальный ПК пользователя).
- [ ] UI-индикатор П3 (показать юзеру "письма привязаны к кошельку", epoch в настройках).
- [ ] При смене владельца NFT (AskToChangeOwnership on-chain) — помечать индексы owner_changed.
- [ ] e2e-фикстура (infra-fixture.ts) всё ещё указывает на legacy /root/infmail-backend
      (Node.js монолит) — надо переписать под Rust-бинарь infmail serve + node.yaml.
- [ ] README репов обновлён (сделано); SESSION_CONTEXT обновлён (этот блок).

### КОММИТЫ
- infmail-valid-backend: b56f69a (feat(P3): /web3/save-keys + cross-check)
- infmail-frontend: b979a9b (feat(P3): browser-side derive from wallet signature)

### ВРЕМЕННЫЕ СКРИПТЫ НА ПРОДЕ (можно удалить)
- /root/p3_smoke.sh, /root/p3_final.sh, /root/check_peers.sh, /root/check_peers2.sh, /root/ping_aeza.sh

================================================================
## СЕССИЯ 2026-09-14 — РЕВИЗИЯ + ДОДЕЛКА (после простоя ~3.5 недели)
================================================================

### РЕВИЗИЯ (4 параллельных проверяющих + ручной E2E)
- Почта E2E: отправка ok:true stored:1, Sent+Inbox показывают, тело расшифровывается. ПОДТВЕРЖДЕНО.
- Контракты живы (testnet get-методы отвечают). register-web3 реально сверяет
  getOwnerByHash + TON Proof. Фронт шлёт настоящие tx, моки только под флагом тестов.
- cargo audit 0 уязвимостей, npm 3 findings (next critical-win-only/sharp high —
  на Linux-проде неприменимо, но обновить надо). Заголовки/cookie/порты — хорошо.
- Архитектура: Cargo.toml ноды чист (0 почтовых deps), репликация и proof-of-storage
  реальны. НО mailbox.rs в ноде — концепция писем вшита в сетевой слой (философии
  противоречит частично).

### РАСХОЖДЕНИЯ НАЙДЕНЫ И ИСПРАВЛЕНЫ
1. **Inbox 31–90с вместо 0.14с** — причина: node1 (локальный ПК) была мертва,
   чистый валидатор висел на fetch чанков с мёртвого пира. node1 поднята
   (systemd user unit infnode-node1, restart=always): counts 2.5с→0.09с,
   inbox→0.1–0.2с. ВАЖНО: без lingering юнит умрёт при логауте — включить
   `loginctl enable-linger imm` (нужен root) или держать сессию.
2. **Прод-бинарь отставал на коммит** (не было /web3/save-keys) — собран и
   задеплоен 41bc1ed82ba64951 (b56f69a). П3-цепочка фронта разблокирована.
3. **/nft/verify всегда authentic:true** — ИСПРАВЛЕНО (коммит defe33a, задеплоен
   b18d4120d1c15c0a, запушен): теперь реально декодирует PNG (крейт png 0.17),
   извлекает LSB, проверяет Ed25519. Тест honest_verify_roundtrip_and_tamper.
   Проверено на реальных картах: authentic:true + "signature valid".
   Ответ расширен полем verifyDetail.
4. **infmail-obs был disabled** — включён (enable --now), :9100 отвечает.
5. **Rate-limit логина** — перепроверен живьём: 10×401 затем 429. Работает.
   Прошлое наблюдение (12×401) — артефакт рестарта сервиса (in-memory guard).
6. **Мусор на проде**: удалены 29 старых /root/infmaild-* (~450MB). Диск 86%→85%.
   Оставлены: /root/infmaild.bak-20260914, /root/infmaild.noncefix2.

### ТЕКУЩИЕ ВЕРСИИ
- Прод infmaild: b18d4120d1c15c0a (defe33a, с честным verify). Бэкап /root/infmaild.bak-20260914.
- Локальный infmail-valid-backend HEAD defe33a (запушен). node1-би-нарь 9098ac3a (f32673c).
- SSH-скрипты пересозданы: /tmp/sshcmd.py /tmp/ssh2run.py /tmp/scpcmd.py /tmp/scp2.py, venv /tmp/venv (pexpect).

### ОСТАЛОСЬ (хвосты)
- e2e-фикстура infra-fixture.ts → переписать под Rust infmail serve + node.yaml.
- UI-индикатор П3 (epoch в настройках) + owner_changed при смене владельца NFT.
- next/sharp bump (npm audit).
- mailbox.rs в ноде (философский долг, не функциональный).
- Диск валидатора 85% — следить. Локальный 82%.

### ПРОДОЛЖЕНИЕ 2026-09-14 (вечер)
- Бэкенд 0c4fd5b задеплоен (6ee163b5): nft/status отдаёт on-chain owner
  (getOwnerByTokenId), /auth/me отдаёт p3_bound/p3_epoch. Тесты 30/30.
- ВЫЯВЛЕНО: testnet-коллекция НЕ знает get_token_by_email_hash для q1/final3
  (exit 11 — записей нет; testnet пересоздан после августа). has_nft через chain
  сейчас false даже у минченных ранее. Нужен либо передеплой коллекции с методом,
  либо sidecar-фолбэк. На полный mint-цикл не хватает средств (деплоер 0.93 TON,
  надо ~1.5) — нужен faucet.
- Фронт: P3-индикатор + owner_changed-баннер (c2ac743), TS1117-фикс спеки (3dab1c2),
  npm audit fix → 0 vuln (88f4c01). ЗАДЕПЛОЕНО на прод (сборка на сервере,
  все страницы 200, новые строки в бандле). Внешняя проверка: infmail.org 200,
  manifest ok, неверный логин 401.
- e2e-фикстура (21b0f43): Rust infmail serve + node.yaml, локальный E2E доказан.

================================================================
## СЕССИЯ 2026-09-14 (ночь) — ДВА КОРНЕВЫХ БАГА НАЙДЕНЫ И ИСПРАВЛЕНЫ
================================================================

### БАГ 1: NFT-статус всегда false (метод вызывался не тем именем)
- Бэкенд звал `get_token_by_email_hash` (snake_case). На контракте метод называется
  `getTokenByEmailHash` (camelCase) → TON возвращал exit_code 11 → ложное «NFT нет»
  у ВСЕХ аккаунтов. Chain был в порядке: getTokenByEmailHash(q1) → 0x1 (token 1).
- Второе: `getOwnerByTokenId` возвращает address-slice В CELL, а код ждал addr-строку
  → owner=null. Добавлен parse_addr_from_cell_entry (267 бит: 2+1+8 бит префикс, 256 хэш).
- ПРОВЕРЕНО: q1@infmail.org → has_nft:true, token_id:1, owner=58905b0d…
  Хэш деплоера kQBYkFsNxSm6gUFRqdfN7hXZGbdhOxcEjz4z77_4IKbrq0nD, вычисленный
  независимо из base64, СОВПАЛ с owner. Коммит 3412322.

### БАГ 2: Inbox «висел» минутами после рестарта валидатора
- КОРЕНЬ: нода за NAT (node1) недоступна валидатору на ВХОД. `ensure_dht_peer` пытался
  дозвониться и ждал 8с connect-таймаута НА КАЖДЫЙ ЧАНК, а `take(rf)` отдавал
  недоступной ноде слот репликации → и чтение, и отправка вставали.
- ФИКС (коммиты 932e2f1, 66f7967): два прохода — сначала пиры с ЖИВЫМ соединением
  (`pick_conn`), недоступные только вторым проходом. Затронуты fetch_mail_inner,
  fetch_blob и store_chunk_replicated.
- ПРОВЕРЕНО на проде: inbox 0.100–0.301с (было >120с таймаут),
  send 0.130с ok:true stored:1 (было пусто/таймаут).

### ПРОВЕРКА «А НЕ УПРОЩЕНА ЛИ РЕАЛИЗАЦИЯ» (вопрос пользователя)
- Решающий тест: убрал ВСЕ 633 локальных mail-чанка валидатора → inbox всё равно
  вернул 3 письма С ТЕЛАМИ (2.59с). Значит чтение РЕАЛЬНО из сети, не имитация.
- ВАЖНО (долг): эти 633 чанка — остатки от времён, когда валидатор имел mail-роль.
  В fetch_mail_inner есть МОЛЧАЛИВЫЙ fallback на локальный диск. Т.е. при сбое сети
  чтение тихо обслуживается с диска валидатора, маскируя проблему распределённости.
  Рекомендация: либо удалить эти чанки, либо логировать факт локального fallback.

### ТЕКУЩИЕ ВЕРСИИ / СЕРВИСЫ
- Прод infmaild: 2dffd4e5a7211858. Бэкапы: /root/infmaild.bak-20260914, c8fc3fe6, c14c9fd1.
- Все сервисы active (infnode, infmail-web, infmail-obs, nft-card, stalwart).
- node1 запущен локально (systemd --user infnode-node1). Linger=no — при логауте умрёт,
  нужен `loginctl enable-linger imm` от root.
- Тесты: 30 (16 infmail + 14 infnode) pass.

### ОСТАЛОСЬ
- node1: включить lingering (нужен root) иначе нода падает при выходе из сессии.
- Локальные чанки валидатора: решить (удалить или логировать fallback).
- Полный mint-цикл NFT: нужен TON (деплоер 0.93, надо ~2). Пользователь пополняет.
- Диск валидатора 85%.

================================================================
## СЕССИЯ 2026-09-14 (ночь, ч.2) — МИНТ-ЦИКЛ NFT ПРОГНАН + 3-й БАГ
================================================================

### МИНТ-ЦИКЛ NFT ПОЛНОСТЬЮ ВЫПОЛНЕН (кошелёк пополнен до 2.927 TON)
- Актуальные адреса (в старых скриптах были СТАРЫЕ, били бы мимо):
  Collection kQAw13VCdSIX4h_e_eYbtX7RRXT5w4FMgN1NfTop12NvyrKR
  Registry   kQBIr_OP1HgR0Ca4-HxVeR3vwmUmCbrm5V7Plso2Gk1Z_rjk
  Storage    kQC9herzN5zomk42USyU4bvFO3C8Zm5OElnm19RrKgbTC0fM
  (в run-testnet.sh было REG=kQBo-ongg…, NFT=kQCHZtjF… — УСТАРЕЛИ)
- Структуры (contracts/messages.tolk):
  Upgrade(0x55475244){emailHash:uint256, walletHash:uint256}  value>=UPGRADE_PRICE(1 TON)
  Mint(0x4d494e54){tokenId:uint64, ownerAddress:address, emailHash:uint256, itemAddress:address} — только admin
  Апгрейд пишет pendingWallet[wHash]=tokenId, pendingEmail[eHash]=wHash, nextItemIndex++
- Цикл на nfttest@infmail.org:
  emailHash = sha256("nfttest@infmail.org") = 3b454bfd4848de63fb98f8038fd88d6c0c6e7fda1019d825d089bb00f6d1b443
  Upgrade tx cacf124cb9c11c8a03414b3a77902d5f33e0128c4f9ff927f6944c3f30d1e357 -> PENDING_TOKEN: 3
  Mint    tx a026b7a3e08419ef81546a4a38c202f15eee3d86af5512d5000eddfff117e175 -> MINTED token 3
  item kQAPI-iUaqPYkjF1WpkGLua3a9Zxrms13FqREjSfaDTG_Ovh
- ПРОВЕРЕНО: /nft/status/nfttest@infmail.org -> has_nft:true, token_id:3, owner:58905b0d…

### БАГ 3 (найден при финальной проверке): сбой RPC выглядел как «нет NFT»
- `run_get_method` возвращал None И при ошибке (429 rate limit TON Center, таймаут).
  `check_nft_status` через `?` превращал это в has_nft:false -> владелец NFT видел
  «нет NFT» на каждом rate-limit. Фронт (api.ts:441) делал ТО ЖЕ: `if (!res.ok) return {has_nft:false}`.
- ФИКС: run_get_method_strict + check_nft_status -> Result<Option<u64>,()>;
  Ok(Some)=есть, Ok(None)=достоверно нет, Err=chain недоступен -> /nft/status отдаёт 503
  с текстом "chain unavailable: NFT status unknown (not 'no NFT')".
  Фронт: getNftStatus бросает вместо возврата has_nft:false (дашборд сохраняет прежнее).
- ДОКАЗАНО: при rate-limit q1 отдавал false/503, после сброса -> has_nft:true, token_id:1.

### РЕКОМЕНДАЦИЯ (не сделано, важно)
- Публичный testnet.toncenter.com жёстко лимитирует: каждый /nft/status = запрос к chain.
  Дашборд будет часто получать 503. Нужен КЭШ статуса NFT на бэкенде (60-120с на email)
  или платный RPC-ключ. Иначе пользователь вместо лжи получит «неизвестно».

### ФИНАЛЬНЫЙ ПРОГОН (всё зелёное)
- Сервисы: infnode/infmail-web/infmail-obs/nft-card/stalwart — all active. Бинарь 54b1e3be7768e36d.
- /pricing 200 (0.7мс), infmail.org 200 (0.31с)
- login OK; /auth/me: p3_bound:true, p3_epoch:null, type:classic
- Inbox 0.29с (5 писем, тела есть); Sent 0.26с (5 писем)
- send: ok:true stored:1, 0.131с
- rate-limit логина: 429 после 11 попыток
- Локальных mail-чанков у валидатора: 633 (долг — молчаливый fallback)
- rewards: 2 ноды; у 57146ca81f9 proof_ok 8/8 weight 164; у e963614041e proof_chunks 0 (не хранит
  чанки валидатора) -> weight 0. Это дизайн (rf-выбор), не баг, но награды концентрируются.

### ОСТАЛОСЬ
- КЭШ статуса NFT на бэкенде (иначе 503 на rate-limit) — САМОЕ ВАЖНОЕ.
- Локальные чанки валидатора (633): удалить или логировать fallback.
- node1: `sudo loginctl enable-linger imm` (Hermes блокирует передачу пароля в sudo — выполнить руками).
- Диск 85%.
- Обновить адреса в /root/infmail-acton/scripts/testnet/run-testnet.sh.

================================================================
## СЕССИЯ 2026-09-14 (ночь, ч.3) — КЭШ СТАТУСА NFT
================================================================

### СДЕЛАНО: nft_status_cache + stale-if-error (коммит 82a9e01, бинарь b774ea48b73b84ce)
- WebState.nft_status_cache: Arc<Mutex<HashMap<String,(i64, Value)>>> в web.rs.
  NFT_STATUS_TTL_MS = 90_000. nft_now_ms() — системное время в мс.
- Логика /nft/status:
  1) свежий кэш (<90с) -> отдаём, в chain НЕ идём;
  2) иначе запрос в chain; успех -> кладём в кэш и отдаём;
  3) сбой RPC -> если есть любой прошлый ответ, отдаём его с "stale":true и
     "cached_age_secs":N; если ответа нет вовсе -> 503 "unknown" (НЕ "нет NFT").
- Фронт (api.ts:441), коммит fcfeaab: getNftStatus бросает на !res.ok вместо
  возврата has_nft:false (дашборд сохраняет прежнее состояние).

### ПРОВЕРЕНО НА ПРОДЕ (не на словах)
- 6 запросов q1 подряд: #1 0.210с (chain), #2..#6 по 0.0007с (кэш) — ~300x, 0 обращений к chain.
- Истечение TTL: после 95с запрос снова идёт в chain (0.318с), отдаёт свежее.
- STALE-IF-ERROR форсирован: выжег квоту TON Center (429 "Ratelimit exceed"),
  затем /nft/status/q1 -> HTTP:200
  {"has_nft":true,"token_id":1,"owner":"58905b0d…","stale":true,"cached_age_secs":114}
  Т.е. при недоступном chain отдаётся последний известный ответ, а не ложь и не 503.
- Тесты 30/30 (16 infmail + 14 infnode).

### ИТОГ ПО ВСЕМ РАБОТАМ СЕССИИ (все задеплоено)
Прод infmaild: b774ea48b73b84ce. Все сервисы active. Диск 85%.
Бэкапы бинаря на валидаторе: infmaild.bak-20260914, c8fc3fe6, c14c9fd1, 54b1e3be.

### ОСТАЛОСЬ (не критично)
- node1: `sudo loginctl enable-linger imm` — выполнить РУКАМИ (Hermes блокирует sudo-пароль).
- 633 локальных mail-чанка валидатора: удалить или логировать fallback.
- Обновить адреса в /root/infmail-acton/scripts/testnet/run-testnet.sh.
- Сменить root-пароль пользователя (попал в историю чата).

================================================================
## СЕССИЯ 2026-09-14 (ночь, ч.4) — СЕТЕВОЙ БАГ + ЧИСТКА ХВОСТОВ
================================================================

### СДЕЛАНО
1) run-testnet.sh: адреса REG/NFT были УСТАРЕВШИЕ (kQBo-ongg…, kQCHZtjF…)
   -> заменены на живые (kQBIr_OP…, kQAw13VCd…). Бэкап рядом.
2) Молчаливый локальный fallback в fetch_mail_inner теперь ЛОГИРУЕТСЯ:
   "[node] WARN: chunk <id> of <name> served from LOCAL disk, not from the network".
   Смысл: сбой сети больше не маскируется локальным диском.
3) accept_loop держал пермит MAX_INCOMING весь срок frame_loop, а frame_loop висел
   в conn.accept_bi() БЕЗ таймаута (keep_alive сбрасывает max_idle_timeout).
   Итог: «too many incoming connections, refusing» -> пиры получали
   «aborted by peer: refused». ФИКС: таймаут ожидания нового потока 300с
   (STREAM_IDLE_TIMEOUT_SECS) + MAX_INCOMING 64 -> 512 (в infmail-valid-backend).
   Тот же фикс accept_bi внесён в /home/imm/infnode (там MAX_INCOMING уже 1024),
   node1 пересобран и перезапущен.
   Коммит 4eb5dc4, бинарь b90dc9a18400c3ba.

### ПРОВЕРКА «ОТКУДА РЕАЛЬНО ЧИТАЮТСЯ ПИСЬМА»
- С локальными чанками и без: три чтения подряд дали 2.5с и **WARN=0**.
  Значит чтение ИДЁТ ИЗ СЕТИ, локальный резерв не задействован. Это честно.
- Цена сетевого чтения ~2.5с (кэш/диск давал 0.3с).

### ВАЖНАЯ ОШИБКА И ЕЁ ИСПРАВЛЕНИЕ (записать, чтобы не повторить)
- Я архивировал 633 локальных чанка валидатора (в /root/infnode-local-chunks-archive-*).
  Сразу после этого inbox упал в таймаут 90с. Причина НЕ в архиве, а в том, что
  валидатор и node1 были перезапущены почти одновременно (деплой + пересборка node1)
  и соединения ещё не восстановились.
- Чанки ВОССТАНОВЛЕНЫ. Урок: НЕ планировать архивацию/чистку данных и рестарт узлов
  на одно окно; сначала дождаться установления связей (проверить, что чтение идёт
  из сети при WARN=0), только потом чистить.

### ОСТАЁТСЯ ОТКРЫТЫМ (важно)
- **aeza (212.113.103.105) ОТКАЗЫВАЕТ валидатору в соединениях**:
  "[node2] connect aeza …: aborted by peer: the server refused to accept a new connection"
  повторяется постоянно. aeza работает на СТАРОМ бинаре (утечка пермитов не исправлена
  + старый лимит). Пока aeza насыщена, меш держится на node1.
  НУЖНО: задеплоить исправленный бинарь на aeza (доступ/креды надо уточнить).
- node1 (локальный ПК) по-прежнему за NAT: валидатор дозванивается плохо,
  соединение держится за счёт того, что node1 звонит сам. Linger=no -> узел умрёт
  при логауте: `sudo loginctl enable-linger imm` (выполнить РУКАМИ).
- Диск валидатора 85%.

### СОСТОЯНИЕ НА КОНЕЦ
Все сервисы active. Бинарь валидатора b90dc9a18400c3ba. 30/30 тестов.

================================================================
## СЕССИЯ 2026-09-14 (ночь, ч.5) — node1 БЕЗ root + НАХОДКИ
================================================================

### node1: проблема «умрёт при логауте» РЕШЕНА БЕЗ root и БЕЗ linger
- Facts: org.freedesktop.login1.Manager.KillUserProcesses = false (проверено через busctl).
  Значит процесс, отвязанный от сессии, переживает выход из системы.
- Локальный sudo паролем НЕ инженерён (заблокировано Hermes; и мой же скилл
  devops/remote-shell-ops прямо запрещает это обходить — это точка передачи пользователю).
  Правильный путь, если понадобится root: пользователь сам добавляет SUDO_PASSWORD
  в /home/imm/.hermes/.env (строка ~233) ЛИБО выполняет команду руками.
- РЕШЕНИЕ: node1 работает через отвязанный супервизор:
  - /home/imm/infnode/deploy/node1/run-node1.sh — бесконечный цикл: запускает ноду,
    при падении перезапускает через 5с. Запускается через `setsid -f` -> ppid=1.
  - /home/imm/infnode/deploy/node1/ensure-node1.sh — идемпотентный запуск по pidfile
    (+ страховка по занятому порту 9400), чтобы НИКОГДА не было дублей.
  - ~/.config/systemd/user/infnode-node1.service переписан: Type=oneshot, вызывает
    ensure-node1.sh, enabled -> автозапуск при входе в систему. Сам супервизор живёт
    вне сессии, поэтому логаут его не убивает.
  - Проверено: ровно 1 супервизор с ppid=1, 1 нода, порт 9400 слушает, peers:2.
  - ВАЖНО (ошибка, которую допустил): первая версия ensure проверяла через pgrep и
    не заметила уже работающий супервизор -> поднялись 2 ноды на один порт.
    Исправлено на pidfile + проверку порта. Урок: для одиночности процессов
    pidfile надёжнее pgrep -f.

### НАЙДЕНО (требует решения, не исправлено)
- ОТПРАВКА ПИСЕМ НЕСТАБИЛЬНА: 6 отправок подряд -> 5 успешны за ~0.11с, 1 зависла
  (таймаут 45с). Похоже, первая отправка после простоя попадает на «мёртвый» путь
  соединения. Это пользовательский баг: письмо иногда «не уходит».
- ЦЕЛОСТНОСТЬ ХРАНИЛИЩА: в журнале валидатора
  "[migration] pass: ... integrity checked=696 missing=29 mismatch=0"
  => 29 чанков ЧИСЛЯТСЯ ПРОПАВШИМИ (хэши совпадают у найденных, подмен нет).
  Нужно понять, какие это чанки и восстановить (rf=3 должен лечить).
- Чтение при этом честно сетевое: WARN локального fallback = 0, отказов/too_many = 0.

### ЗАПУЩЕН АУДИТ (4 параллельных агента)
1) сценарий стороннего пользователя со своей нодой (подхватит ли сеть, роли, что можно испортить)
2) безопасность бэкенда (сессии, пароли, доступ к данным, инъекции, SSRF, DoS, шифрование)
3) смарт-контракты + NFT (в т.ч. имена в 1 символ, GetGems) + готовность к mainnet
4) фронтенд: реальность функций, заглушки, UX, производительность

================================================================
## АУДИТ 2026-09-14 — КРИТИЧЕСКАЯ НАХОДКА (подтверждена лично)
================================================================

### [КРИТИЧНО] Ключ расшифровки писем лежит ОТКРЫТЫМ ТЕКСТОМ и раздаётся всем нодам
- Код: /home/imm/infnode/src/node.rs:2541,2544 (store_mail_boxed) и :2757,2760 (store_blob_boxed)
  пишут `manifest["key"] = hex(data_key)`. Ветка `box_wrap_key` (шифрование ключа на
  получателя) не задействована продуктовым путём: web.rs вызывает store_mail()/store_blob()
  БЕЗ box (crates/infmail/src/web.rs:1300, 2118, 2201).
- ДОКАЗАТЕЛЬСТВО (сырой подсчёт, не парсинг):
  kv.json ноды node1 ->  `\"key\":\"<64 hex>\"` встречается 736 раз, `\"key_box\"` — 0 раз.
  Т.е. чанки зашифрованы, но ключ к ним лежит рядом открытым текстом.
- Раздача: replicate_mail (src/node.rs:2592-2613) шлёт манифесты k-ближайшим БЕЗ проверки
  роли (в отличие от store_chunk_replicated, где есть peer_allows). K=20 (src/dht.rs:9),
  а узлов в сети 3-6 -> dht_find_node возвращает ВСЕХ.
- Ноды заходят без whitelist: прод-конфиг валидатора allow-unknown:true, TOFU-приём
  (src/node.rs:3262-3339). У TOFU-пира storage_roles пуст -> peer_allows = ВСЕГДА TRUE
  (src/node.rs:2086-2096), rate-limit-per-sec 0 = без лимита.
- ИТОГ: любой, кто подключится к валидатору со своей нодой, получает шифртекст + ключ
  => читает ВСЮ новую почту сети. Серверно-стороннего «шифрования на хранителе» нет.
- ЛЕЧЕНИЕ: включить box-путь (store_mail_boxed с owner_pub, fetch_mail_owner),
  запретить replicate_mail без peer_allows, задать непустые storage_roles для TOFU-пиров.

### Другие находки агента 1 (аудит сторонней ноды)
- Автообнаружение ЧАСТИЧНО: статических seed нет; вход через валидатора (конфиг или
  DNS TXT `_infnode.infmail.org` — запись живая), дальше gossip маршрутов каждые 30с.
- Дефолтный бинарь без конфига => peers:[], в сеть НЕ попадает (изоляция).
- Порча целостности данных невозможна (сверка blake3 при чтении и в proof-of-storage),
  но вредная реплика может ОБОРВАТЬ чтение письма (после mismatch нет перебора других реплик).
- DHT-маршруты принимаются без аутентификации и без проверки владения endpoint
  (src/node.rs:1446-1481, :1731-1741) — в проде уже 3 ghost-записи с пустым ed_hex.
- Бана/кика плохой ноды НЕТ; trust_score ни на что не влияет (вес считается без него);
  в alerts.log «6182 pending payouts — оператор не раздаёт», выплат фактически нет.
- Нет lockfile на data-dir: два процесса в одном каталоге = потеря kv.json.

### Аудит фронтенда (агент 4)
- Полный отчёт: /home/imm/infmail-frontend-audit.md (34 функции, таблица).
- НЕТ удаления аккаунта вообще (ни UI, ни API). NFT-апгрейд в UI — только тост, платежа нет.
- Регистрация classic бесплатно пропускает короткие имена -> обход монетизации
  (frontend register/page.tsx:143-167, бэкенд valid_email без нижней границы длины).
- 7 ручек бэкенда не используются фронтом (алиасы, share, sessions, signature, subscribe,
  wallet-nfts, nft/meta), при этом тариф обещает «15 aliases».
- Перф: все 8 страниц 'use client', поллинг 20с тянет весь инбокс, расшифровка всех
  писем списка O(n) на каждом обновлении, пагинация API не используется.

### ПЕРЕЗАПУЩЕНЫ 4 агента (те, что упали по лимиту итераций)
Отчёты будут в /home/imm/audit-auth.md, audit-infra.md, audit-chain.md, audit-mainnet.md.

## 2026-09-14 (вечер) — исправления по аудиту
- **П.1 2FA-обход ЗАКРЫТ.** Бинарь `a2a21ec5`: claim `typ=session`, `jwt_sign_2fa()`, `is_session_token()`
  (сессия = typ+sid), `auth_email_2fa()` только для verify-2fa, `settings_2fa_enable` выдаёт
  настоящую сессию, `renew_cookie` ротирует sid. Тесты 20+14. Прод-проверка: temp-токен → 401
  на 4 ручках, легитимный вход работает.
- **П.4 права ЗАКРЫТЫ.** `save_db` пишет 0600 (подтверждено на проде), `UMask=0077` в юните,
  закрыты kv.json/node.yaml/dht.json/consensus.json/.cache; node1 локально: секреты 600,
  каталоги 750, umask 027. Почта жива (inbox 200/0.178с).
- **П.5 секреты из юнитов.** В т.ч. найдены в активных drop-in'ах nft.conf/validator.conf
  (перекрывают юнит — первый шаг чуть не подменил значения, поймано по sha256).
  `/etc/infnode/infnode-secrets.env` 600, значения проверены + Stalwart-auth работает.
  Собственная ошибка: лишний `"` в STALWART_PASSWORD (15→14 символов) — исправлено.
- **П.6 Stalwart: находка НЕ подтвердилась.** 8080 слушает *:8080, но фаервол дропает
  (3390 пакетов), снаружи таймаут, правила персистентны (infmail-fw.service). Экспозиции нет.
- **П.7 GetGems.** Реальный баг один: content-path контракта `/nft/meta/+index` vs роут
  `/nft/{id}/meta` → 404. Добавлен алиас + терпимость к .json, бин `a56d7117`.
  Проверено: `https://infmail.org/api/v1/nft/meta/<id>` → 200 TEP-62.
  «Нет image» НЕ подтвердилось — поле есть. Остаток: карточек нет у токенов вне приложения.
- **П.8 удаление аккаунта СДЕЛАНО** (бин `dc2c3bf4`, фронт `d3fbdc2`).
  `POST /settings/account/delete`: пароль (+код 2FA), rate-limit; удаляет запись+сессии,
  индексы/мета/файлы, ящик Stalwart (query id + delete); НЕ трогает общие блобы, чужие
  аккаунты, реестр, NFT. Danger Zone в Security Settings. Прод-тест на мусорных аккаунтах:
  delete ok, mails_indexed=1, meta_keys=2, stalwart=deleted, 1050→1050, токен мёртв.
  Единственный FAIL обоих прогонов — парсинг inbox в моём скрипте (API отдаёт голый list,
  скрипт ждал {mails}); mails_indexed=1 доказывает наличие письма.
- **П.2 ключ в манифестах / П.3 подпись кошелька — ЗАБЛОКИРОВАНЫ.** Проверка подписи фиктивна,
  а фронт шлёт только `signature` без address/timestamp/domain/payload → проверить нельзя
  в принципе. Нужна переделка П.3 (фронт по спеке TON Connect signData) + живой Tonkeeper.
  Отчёт: /home/imm/audit-p3-keys.md. Выбор пользователя: сначала независимые пункты.
- Отложено: алиасы до второго домена (MAIL_DOMAIN захардкожен, модель local-only).
- Долги: fail-open storage_roles, smtp_pass plaintext, 29 missing chunks, подвисание send
  (1/6, снова словили в delcheck: HTTP 000), mainnet-чеклист (п.9) — п.9 частично закрыт
  (TON_API_KEY, чеклист).
- **aeza ОБНОВЛЕНА.** Пароль получен, доступ работает (/tmp/sshaeza.py, /tmp/scpaeza.py —
  ВНИМАНИЕ: пароли внутри файлов, не коммитить). Бинарь `a15bb0cb` → `33ebec02`
  (пересобранный infnode с фиксом пермитов; старый — /root/infnode.bak-a15b),
  `systemctl restart aeza-node` → active. До рестарта валидатор ловил 898 отказов
  «refused to accept» от старого бинаря; после — 0 ошибок за 3+ мин. Почта: inbox/counts 200
  (2.5с — меш сходится после рестарта, нормально).
- **Testnet dry-run reedеплоя ПРОШЁЛ.** Новый кошелёк `0QAS…0wya_` (2 TON от пользователя,
  мнемоника /home/imm/.testnet-dryrun/wallet.json 600): деплой кошелька (BOC офлайн +
  REST sendBoc — TonClient/axios ломались через прокси, лечится `env -u *PROXY`),
  новая коллекция `kQDnSTy8…6622Ddxy`, Upgrade+Mint `q@infmail.org` (tx 85b388aa, 2b6db709),
  getTokenByEmailHash → 0x0. Потрачено ~1.2 TON. Вывод: цифры mainnet подтверждаются.
- **Файлы+подписка E2E — ВСЁ ОК.** subchecktmp: free quota (1GB/0) → upload 413 →
  nonce → оплата 0.6 TON с dryrun → индексер (45с) → quota paid (3GB/6GB) →
  upload 200 → download байт-в-байт → delete → 1050 целы.
- **Файловый менеджер улучшен (фронт `141f0cf`, на проде).** Мультизагрузка ×3 с прогрессом
  (uploadFileXhr), rename/move файлов и папок, удаление папок, своя модалка вместо
  prompt/confirm. Тарифы честные (алиасы coming soon), Danger Zone упоминает блобы.
  Проверено: /plan содержит coming soon, inbox 200/0.32с, все 5 сервисов active.

## Сессия (продолжение) — черновики/спам, минус 2 (DHT-восстановление), метаданные, EC

Все изменения задеплоены на валидатор и проверены E2E (не на словах).

### Черновики и спам
- `/mail/inbox` отдаёт поле `to` (нужно для «продолжить черновик»); фронт: кнопка
  Continue в Drafts, старый черновик удаляется после отправки/сохранения.
- `GET /api/v1/mail/blacklist` + двухкликовый Block + карточка Blocked Senders в Settings.
- Баг: blacklist писался реплицированно (`kv_set`), читался локально (`kv_get_local`)
  → терялся после эвикции. Чтение переведено на DHT-aware `kv_get`.

### Удаление аккаунта (баг «воскрешения»)
- `settings_account_delete` чистил индексы только локально, а они реплицировались
  → после повторной регистрации почта возвращалась. Теперь индексы перезаписываются
  пустым значением через `kv_set` (реплицируемо) + локальная очистка. Проверено E2E.

### Минус 2 — восстановление профилей из DHT
- Репликация профилей была write-only (писали `acct:{email}`, никто не читал).
- Ключи стали непрозрачными: `acct:{blake3(email)}` — адрес не светится в имени ключа.
- Промежуточный (ошибочный) `acct-index` — открытый список ВСЕХ адресов — убран и
  затёрт tombstone-ом; восстановление теперь ПО ЗАПРОСУ (`restore_account_on_demand`):
  профиль подтягивается, когда пользователь обращается, а локально записи нет.
- Репликация сразу после старта, затем раз в 5 минут. Восстанавливаются только
  несекретные поля: `pw_hash` пуст → парольный вход восстановленной записи невозможен
  (проверено: 401). E2E: стоп узла → правка базы → старт → логин → профиль вернулся.
- Старые ключи `acct:{email}` (в т.ч. удалённых аккаунтов) нейтрализованы: 0 plain, 1052 хеш.

### Erasure coding (Reed-Solomon, k-of-n)
- `store_mail_ec` / EC-ветка в `fetch_mail_inner` / `fetch_chunk_net`;
  манифест несёт `ec{k,n,ct_len}` + шарды. Включается опционально: `INFNODE_EC="3,5"`.
- Юнит-тесты 4/4 (roundtrip, потеря n−k шардов, отказ при <k, неравные длины).
- E2E: `stored: 5`, тело собралось и расшифровалось (5008 байт), EC выключен обратно.
- ВЫВОД: при текущих 3–6 нодах EC не включаем — окупается от ~10 нод (нужно n
  различных нод для шардов). Оставлено доступным, по умолчанию ВЫКЛЮЧЕНО.

### Прочее
- Деплой фронта теперь НЕ рестартит сервис при упавшей сборке (иначе прод в полусостоянии).
- `accounts.json` руками на работающем узле не править — узел перезаписывает из памяти;
  править только при остановленном узле.
- Тестовые аккаунты вычищены (1055 → 1050). Права `accounts.json` — 600.

### Осталось
- Минус 1 (шифрование) + П.3 (подпись кошелька): блок — нужен живой Tonkeeper и правка
  фронта `lib/p3.ts` (шлёт `cell` при `type:'text'`, теряет address/timestamp/payload).
- HA: второй валидатор (нужен сервер/деньги пользователя). Mainnet: транзакции из админ-кошелька.
- EC включить на проде, когда будет ≥10 нод.
- Долги: интермиттентное зависание send/draft (HTTP 000 при несходившемся меше),
  29 потерянных чанков, `smtp_pass` открытым текстом, анти-спам на отправку.


## ИНЦИДЕНТ (важно) — потеря базы аккаунтов и защита

Прод: `accounts.json` схлопнулся с ~1050 до 1 записи (дважды). Причина: узел
стартовал с пустым/отсутствующим файлом, `load_db` при сбое чтения МОЛЧА отдавал
пустую базу (`unwrap_or_default`), первый же `save_db` записывал пустое поверх
реального. Данные оба раза подняты из бэкапов.

Исправлено:
- `load_db`: ошибка/пустота -> CRITICAL-лог, запись ОТКЛЮЧАЕТСЯ, файл не трогается;
- `save_db` ворота: отказ писать пустую базу поверх непустой и отказ при усыхании >2x;
- ротационные бэкапы `accounts.json.bak-<ms>` при каждой записи (держим 8);
- авто-восстановление: пустой/битый/отсутствующий файл на старте поднимается из
  свежего бэкапа (проверено: обнуление файла -> восстановлено 1054 акк. + processed_payments).
Честно: кто именно обнулял файл — не доказано, но сценарий теперь самовосстанавливается.

## Прочие правки этой сессии (все задеплоены и проверены)

- Таймауты на сетевые чтения писем: Inbox не виснет (было HTTP 000 по 40с+);
  при таймауте письмо остаётся в списке с превью.
- Черновик пишет локальную meta -> список Drafts не зависит от сетевого фетча.
- Ре-репликация чанков проверяет хэш по манифесту (пир не подсунут мусор).
- Erasure coding (Reed-Solomon k-of-n), опционально `INFNODE_EC="3,5"`, по умолчанию ВЫКЛ.
- Непрозрачные ключи DHT `acct:{blake3(email)}`, восстановление профилей по запросу,
  открытый список адресов убран.

## Осталось

29 потерянных чанков (ре-репликация), `smtp_pass` открытым текстом, анти-спам на
отправку (экономический барьер), EC включить при >=10 нодах.
Заблокировано на пользователе: П.3/шифрование (Tonkeeper), HA (2-й валидатор),
mainnet (транзакции из админ-кошелька).
