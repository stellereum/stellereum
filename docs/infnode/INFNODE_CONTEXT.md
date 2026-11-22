# INFNODE / INFMAIL — ПОЛНЫЙ КОНТЕКСТ ПРОЕКТА
> Сохранён по просьбе владельца (2026-08). Обновляй при изменениях.

## КРАТКО О СИСТЕМЕ
Децентрализованная E2E-почта + файловое хранилище + мессенджер на собственном протоколе **infnode**.
- **infnode** — оверлейный протокол: QUIC (UDP) + Ed25519 (идентичность/подпись) + X25519/XChaCha20 (E2E, PFS X3DH) + Kademlia DHT + pubsub + storage (чанки/репликация). Язык: Rust. Репозиторий: `/home/imm/infNode`.
- **InfMail** — webmail поверх infnode. Эталон-конкурент: ProtonMail. Домен: `infmail.org`.

## СЕРВЕРЫ И ДОСТУПЫ (ВАЖНО, SENSITIVE)

| Роль | IP | Логин/пароль | SSH-скрипт |
|---|---|---|---|
| **Валидатор + почта + webmail (основной)** | `109.107.155.67` | `root` / `U3A1hXdjXSBzW7` | `/tmp/sshcmd.py`, `/tmp/scpcmd.py` (pexpect, env `/tmp/sshpy`) |
| **Второй сервер (faucet/airdrop, Aeza)** | `147.45.75.253` | `root` / `q5foUWxm1T0B` | `/tmp/opencode/ssh2run.py`, `scp2.py` |
| 139.100.200.54 | НЕ наш (чужой, ignore) | — | — |

### СЕТЬ ИЗ 3 НОД (работает, RF=3)
- **node2** = валидатор, `109.107.155.67:9400` (web API 3001, фронт 3000). Хранит и почту, и файлы.
- **node1** = локальная машина (NAT), deploy/node1, ключи в /home/imm/infNode/deploy/node1/keys, data_dir deploy/node1 (chunks там). **Хранит и почту, И файлы** (нет storage-roles = оба бакета).
- **aeza** = нода-хранилище `147.45.75.253:9400` (белый IP), **только почта** (`storage-roles: [mail]`), systemd `aeza-node`, конфиг `/root/infnode-node/node.yaml`, ключи `/root/infnode-node/keys`. id `inf1:e963614041e8f29a5394d6cdf067eaabda958c0a`. Диск 9.8G (было 98%, почищено до 58%).
- **Роли (важно)**: почта+хранилище писем = mail; отдельное файловое хранилище «за подписку» = files. node1 = mail+files; aeza = только mail; валидатор = mail+files.
- Mesh: node1→node2, node1→aeza, node2↔aeza — все работают. Mail RF=3 (валидатор+node1+aeza), files — только node1+валидатор.
| Локальная машина (нода-хранилище #1) | NAT `178.155.74.242`, порт 9400 | user `imm` | локально |

> ⚠️ /tmp очищается! Скрипты SSH пересоздаются при необходимости: pexpect, пароли выше.
> Пароль и мнемоника кошелька — секретные. Не публиковать.

## АРХИТЕКТУРА (как работает)
- **Валидатор** (109.107.155.67): infnode `serve` (web API на 127.0.0.1:3001) + frontend Next.js (порт 3000, systemd `infmail-web`) + nginx (infmail.org → 3000) + stalwart (MX/SMTP 25/465, IMAP 993, admin 8080).
- **Нода-хранилище**: локальная машина (node1, deploy/node1), держит зашифрованные чанки, репликация RF.
- **Три слоя**: Валидатор (шлюз в SMTP-мир + веб-API) ↔ Ноды (хранение) ↔ Контракты TON (подписки/NFT, этап Web3).
- Внутренние письма: E2E (браузер шифрует tweetnacl), сервер хранит только шифротекст.
- Внешние письма: исходящие → SMTP-мост (stalwart, DKIM); входящие → MX → stalwart → IMAP-синк → webmail.

## ЧТО СДЕЛАНО (статус)
- Webmail живёт на `https://infmail.org`: register/login (classic + web3 TON), E2E-письма, файлы, алиасы, квота 1ГБ, подписки (plan), SMTP оба направления, скорость send/inbox ~7-9мс, внешнее письмо → webmail за ~3с.
- **Протокол**: догоняющая репликация, роли нод (mail/files/both), NAT hole punch (fallback), inbound-мост (IMAP INBOX+Junk), pubsub.
- **Адаптация фронта (п.2)**: все вызовы api.ts резолвятся; web3-флоу end-to-end; graceful-заглушки nft/verify/card, verify-2fa.
- **Аудит**: исправлены — утечка квоты при удалении, открытый SMTP-relay (лимит 200/сут, 2МБ), rate-limit login/register, гонка индексов, replay mail.list (±5мин). Полный тест 15/15 PASS.
- **Контракты (п.3)**: написаны + 57/57 тестов; **ЗАДЕПЛОЕНЫ на testnet** (кошелёк-деплойер пополнен 2 TON через faucet с телефона):
  - Registry: `EQB_Y-LRJvZU7oBFSgVeP8CZM9fWe8VHcr3W9qO0y6dDJXHm` (0.349 TON)
  - Collection (NFT): `kQB5Y4R7OzRTfy1sfSpSfWccRfzuALtGhysikPz3CVRHUOk_`
  - Storage (подписки): `kQAfWl7fEyui6S4omTCol-Dm11sSYVxcPQHDmQaapRyMct2n`
  - NftItem: минтнется при Upgrade
  - Индексер TON Center в ядре (баланс/владение/NFT-проверка по exit_code), `/settings/plan` + `/settings/subscribe` (paid → 3ГБ+6ГБ/15 алиасов), nft-status реальный.
  - **E2E В РЕАЛЬНОМ БРАУЗЕРЕ: 27/27 PASS** (full-journey 21 + user-journey 6) против живого бэкенда (chromium).
  - **НАЙДЕНЫ РЕАЛЬНЫЕ ОСОБЕННОСТИ**: (1) корзины Trash НЕТ — delete безвозвратный; (2) письма внутренним адресам АВТО-E2EE, тема скрыта за "🔒 Encrypted message"; (3) 2FA/recovery/сессии на реальном бэкенде — ЗАГЛУШКИ (verify_2fa всегда ошибка, sessions=[], trusted_email={ok:true}, recovery "не настроено") — фронт-UI есть, бэкенда нет; (4) web3/generate-payload отдаёт payload-ОБЪЕКТ (не строку, как фейк-бэкенд); (5) manifest name="InfMail"; (6) PoW difficulty=3.
  - **REWARD-СИСТЕМА РАБОТАЕТ (testnet)**: Storage v2 принимает комментарии (деньги КОПЯТСЯ, бунс пофикшен — было throw 0xFFFF на комментарий). SetNodes+Distribute: **30% валидатору, 70% нодам по весам работы**. Проверено: node1 +0.1404 TON (66.5%), aeza +0.0706 (33.5%), admin 30%. Кошельки нод инициализированы.
  - Storage v2: `kQBwVBK0Pm1ZHgGczc38a5vhT5oEed6Gujml9f_lNMnByjWT` (admin=деплойер). env валидатора обновлён. Кошельки нод: node1=`EQAyVNlB4dFypbtyV8obXjBT5mIUb1jjATZbesVF2PYgtkDb` (мнемоника: embark boat pyramid...parade foster), aeza=`EQDiL2M_yn6HZlqXoYXGduiGDR1nBOZATyJ0__7rFBTiAnmU` (мнемоника: tobacco chalk mention...coral secret describe). Веса: node1=178767 (kv+chunks байт), aeza=90000.
  - **ОПЛАТА РАБОТАЕТ**: юзер шлёт TON в Storage с комментарием `INFMAIL_SUB:<email>:<nonce>` → индексер (45с) декодит base64-комментарий → активирует подписку. Проверено end-to-end.
  - Deploy-скрипты адаптированы под текущую версию (common.tolk: Storage с extra/maps, удалены старые deployNftItem/Batch, printNftCollectionInfo на кортежах).
- **Deployer кошелёк (testnet)**: адрес `kQCrDoZwy6L100ote94GSYRHC63TZAchvwEyobRTA-k-qgnf`, мнемоника: `clump vicious subway attack video grace purity enroll clutch room awkward memory moon document mind adult know crew despair satoshi grape fetch license wealth`. Кошелёк пуст (0 TON) — faucet лимит по IP (2/24ч) на осн. сервере. Нужно пополнить (faucet с телефона/другого IP, или перевод) → потом деплой контрактов.

## КЛЮЧЕВЫЕ ПУТИ И ФАЙЛЫ
- Репозиторий протокола: `/home/imm/infNode/` (src: web.rs, node.rs, inbound.rs, blockchain.rs, mailbox.rs, dht.rs, proto.rs, services.rs; docs: PROJECT.md, PLAN_WEB3.md, AUDIT.md, SECURITY.md, PROTOCOL.md).
- Фронтенд: `/home/imm/infmail-web/` (Next.js; api.ts — вызовы; майл на /home/imm/infmail-web).
- Контракты: `/root/infmail-acton` на 109.107.155.67 (Tolk, blueprint/acton 1.1.0, build/ готов, wallets.toml).
- Deploy-скрипт контрактов: `/root/deploy_contracts.sh` (на 109.107.155.67).
- accounts.json юзеров валидатора: `/opt/infnode/web/accounts.json`.
- systemd: `infnode` (валидатор), `infmail-web` (фронт), `stalwart`, `nginx`.
- Тестовый меш (локально): `/tmp/opencode/n1|n2web|n3/node.yaml` (порты 9401-9403), web на n2web 3001.
- Proof TON (для теста web3): генерится `node /tmp/opencode/mkproof.js > proof.json` (нужен node_modules @ton/crypto из infmail-web).

## КОМАНДЫ-ШПАРГАЛКА
- Деплой бинаря на валидатор: `scp → /root/infnode-vN` → `systemctl stop infnode; cp /root/infnode-vN /opt/infnode/infnode; systemctl start infnode`.
- SSH: `/tmp/sshpy/bin/python /tmp/sshcmd.py 'команда'`; scp: `/tmp/sshpy/bin/python /tmp/scpcmd.py <src> 'root@109.107.155.67:<dst>'`.
- Второй сервер: `/tmp/sshpy/bin/python /tmp/opencode/ssh2run.py 'команда'` (пароль q5foUWxm1T0B).
- Сборка: `cd /home/imm/infNode && cargo build --release`.
- Полный тест: `/root/fulltest3.sh` (на 109.107.155.67) — 15/15.
- Контракты build/test: `cd /root/infmail-acton && npx blueprint build --all && npx jest` (57/57).

## ОТКРЫТЫЕ ХВОСТЫ / ПЛАН (PLAN_WEB3.md)
1. **Контракты**: пополнить деплойер (см. выше) → `sh /root/deploy_contracts.sh` → Collection/NftItem/Storage на testnet → записать адреса в env → связать оплату (Topup→индексер→paid_until→plan paid) + NFT-апгрейд.
2. Входящая почта: IMAP-синк уже есть (INBOX+Junk), доставка ~3с.
3. AI (Cocoon) — отложено.
4. NAT: для полной связности нужен проброс UDP 9400 на домашнем роутере (пробой не прошёл на этом роутере).
5. Три валидатора (mx1/mx2/mx3) — план, пока 1.

## ЛИЧНОЕ (для контекста)
Владелец: 17 лет, после 9 класса, колледж (2 курс скоро). Изучает Go, Git (продвинутый), Linux 3 года, Docker, API, ESP32. Рассматривает оплачиваемую стажировку Go-бэкенд (финтех). Написал infnode на Rust (сильный кейс).

## ОБРАЗ ДЕЙСТВИЙ ПРИ ПРОДОЛЖЕНИИ СЕССИИ
1. Прочитать этот файл.
2. Проверить: жив ли валидатор (`curl -s -o /dev/null -w '%{http_code}' https://infmail.org` через nginx, или web API 3001).
3. Если есть TON на деплойере — запустить деплой контрактов и подключить оплату.
4. Дальше по плану (контракты → тест NFT/ZK → остальное).
