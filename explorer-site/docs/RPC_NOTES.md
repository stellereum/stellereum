# RPC заметки — rpc.stellereum.org, нативный `stell_*` (проверено вживую)

## Индексер API (основной источник данных)

Базовый URL: `https://explorer.stellereum.org/api/v2` (CORS: `access-control-allow-origin: *`).
Даёт то, чего нет у ноды: списки транзакций, историю кошелька, поиск, пагинацию.

- `GET /stats` → `{tip_height, total_blocks, total_transactions, total_accounts, current_tps, avg_block_time}`
- `GET /blocks?limit&offset` → `{blocks:[{hash, height, timestamp, tx_count, proposer, state_root}], limit, offset}` (limit 1..200)
- `GET /block/:height_or_hash` → `{block, transactions:[...]}`
- `GET /tx/:hash` → карточка транзакции (from, to, amount, fee, status, block, timestamp)
- `GET /account/:address/txs?limit&offset` → `{address, transactions:[...]}`
- `GET /search?q=` → `{type: block|transaction|account, result}`; нет совпадений → 404 `{error}`
- `GET /events?from_block&to_block&contract&limit&offset` → `{events:[…], count, total, limit, offset}` — лог событий контрактов
- `GET /contract/:address/events?limit&offset` → `{contract, events:[…], count, total, limit, offset}`
- `GET /tx/:hash/events` → `{tx_hash, events:[…], count}`
- `GET /contracts?limit&offset` → `{contracts:[{contract, contract_stl57, event_count, tx_count, first_block, last_block}], count, total, limit, offset}` — список контрактов, выведенный из лога событий
- `GET /shards` → **живая** топология шардов: прокси `stell_getShards` с ноды; при недоступной ноде → 503 `{error, shards: [], total_shards: 0}`

Форма одного события (индексер, декодирован по ABI):

```json
{
  "tx_hash": "0x…", "block_height": 1234, "log_index": 0,
  "contract": "0x…", "contract_stl57": "EQ…",
  "topic0": "0x…", "topics": [], "data": null,
  "event_name": "Transfer", "decoded": true,
  "args": { "topics": { "from": "0x…" }, "data": { "amount": "1000" } }
}
```

Клиент: `explorer/src/lib/indexer.ts` (TTL-кэш, дедуп, ретраи). RPC `stell_*` используется только там, где индексер не покрывает: баланс/nonce аккаунта (`stell_getBalance`), валидаторы, мемпул, syncing.

## Нативный RPC — rpc.stellereum.org (`stell_*`)

- Endpoint: `https://rpc.stellereum.org` (только POST JSON-RPC; GET → 405).
- `stell_chainId` → `5757` (числом, не hex).
- `stell_blockNumber` → hex-высота (на момент проверки ~113k, ~1 блок/сек).
- `stell_latestBlocks` → `[{height, hash, timestamp, txs}]`, свежие первые.
- `stell_getBlock {height}` → `{height, hash, timestamp, txs}` (списка транзакций нет, только счётчик).
- `stell_getBalance {address}` → `{balance (nano-STELL строкой), nonce}`.
- `stell_getTransactionStatus {hash}` → `{status: success|failed|pending|unknown, height}`.
- `stell_getTransactionReceipt {hash}` → `{status, ...}`.
- `stell_getValidators` → `{validators: [{validator, power}], total_power, quorum, fragile}`.
- `stell_mempoolSize`, `stell_syncing` — числа/флаги.
- Официальный кран: `POST testnet.stellereum.org/api/faucet-public/<64hex>` — 5 STELL / адрес / 45 мин.
- Частый polling без пауз → `403 Forbidden` (rate-limit). Поэтому в эксплорере: интервал live ≥4000ms (1 запрос `stell_latestBlocks` на тик), бэкофф при 403/429, сканы батчами по 4 с паузой 300-350ms.

### Методы remediation-волны, которые теперь использует эксплорер

- `stell_getValidators` — **живой** набор валидаторов (мощность каждого, суммарная
  мощность, кворум и флаг `fragile`: кворум требует 100 % набора, т.е. один
  валидатор в оффлайне останавливает сеть). Индексерный `/api/v2/validators` —
  статический снапшот, поэтому он используется только как fallback, и страница
  явно подписывает источник (`LIVE · stell_getValidators` / `INDEXER SNAPSHOT`).
- `stell_getShards` — топология шаров и закоммиченные головы каждого шарда
  (`{shards:[{shard_id, type, tip_height, tip_hash, state_root, local}], total_shards,
  routing_prefix_bits, sharding}`). Проксируется индексером в `/api/v2/shards`.
- `stell_getTransactionReceipt` — **исход** транзакции: `return_value`,
  `gas_used`, `fee_charged`, `contract_address`, `events`.
- `stell_getContractAbi {contract}` — манифест ABI контракта (он закоммичен в
  state trie рядом с code hash, поэтому у всех нод он одинаковый).

Полный справочник методов — `stellereum/docs/RPC.md`.

## Как эксплорер получает данные

Фронтенд ходит **напрямую** в RPC через `fetch` POST:
- `stell_latestBlocks` → свежие блоки каждый тик
- `stell_getBlock {height}` → страница блока / пагинация (окно ~100 блоков)
- `stell_getTransactionStatus` + `stell_getTransactionReceipt` → страница транзакции
- `stell_getBalance` → страница адреса (баланс в nano, nonce)
- `stell_getValidators`, `stell_mempoolSize`, `stell_syncing`, `stell_chainId` → статистика

Если RPC недоступен — показываем кэшированные mock-данные с плашкой `Demo data` (файл `mock.ts`), чтобы вёрстку можно было смотреть без сети.

## Что НЕ используем

- `eth_*` / `web3_*` (EVM-адаптер) — не шлём, цепь нативная.
- TON `getMasterchainInfo` / toncenter `getAddressInformation` — метод `not found`. Не шлём.
- Никаких mainnet endpoints. Только testnet RPC выше.
