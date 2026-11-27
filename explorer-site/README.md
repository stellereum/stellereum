# Stellereum Testnet — Explorer + Faucet Backend

Монорепо эксплорера тестнета и backend-прокси крана:

- `explorer/` — тестнет-эксплорер (Vite + React + TS). Данные: `https://rpc.stellereum.org` (нативный Stellereum `stell_*` JSON-RPC, chainId 5757) + индексер `https://explorer.stellereum.org/api/v2` (проксируется через `/api/v2`, см. `docs/INDEXER_PROXY.md`).
- `backend/` — минимальный backend крана (Node + TS + express): локальный rate-limit + прокси к `UPSTREAM_FAUCET_URL`.
- `docs/` — разбор референсов, RPC-заметки, DNS-разделение testnet/mainnet.

## Быстрый старт

```bash
cd explorer-site
npm install
npm run dev:explorer  # :5173
npm run dev:backend   # :8787
```

Сборка:

```bash
npm run build
```

## Дизайн-баланс (что взято у референсов)

- **gram.org**: простота главной (блоки + транзакции рядом, realtime-индикатор Live/Pause), красивые карточки кошельков.
- **tonviewer.com**: строгость таблиц (Date/Hash/Account/Fee/Value), поиск сверху, хлебные крошки, копирование хешей.
- **eth.blockscout.com**: информативность (высота, fee в nano-STELL, block time, validators) без перегруза — только одна строка статов + детали блока/транзакции.

Подробно: `docs/DESIGN_REFERENCES.md`.

## Testnet-разделение

Эксплорер и кран — **только тестнет**. Везде amber-бейдж `TESTNET`, отдельный домен (см. `docs/DNS_SEPARATION.md`).
Никаких mainnet-ссылок в UI нет. RPC захардкожен только на testnet, выбор сети отключён.

## Статусы транзакций и подтверждения (контракт с нодой)

Словарь статусов един для ноды, RPC и эксплорера: `success` / `failed` /
`pending` / `unknown` (`stell_getTransactionReceipt`,
`stell_getTransactionStatus`).

Что означает подтверждение: у цепи **по-блочная BFT-финализация**
(прекоммит-QC кворума `floor(2·total/3)+1` в каждом финализированном блоке)
— **одно подтверждение уже финально**, финализированные блоки никогда не
откатываются. «N подтверждений» = N финализированных блоков поверх блока
включения; это защита от stale-вида, а не от реорга. Полная таблица по
тирам сумм — `stellereum/docs/RPC.md` §4 «Confirmations» (единственный
источник правила; UI только отображает число).

Реорги кандидатных веток (не применённых блоков): `stell_getInvalidations`
(окно 64 записи, `MAX_INVALIDATION_WINDOW`) и топик `invalidations` в
`stell_subscribe` (WS `/ws`, SSE `/events`). Сигнал называет нижнюю
высоту рассинхрона — потребитель обязан пересинкаться с неё.
