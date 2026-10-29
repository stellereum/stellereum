# EVM Chainlist PR — Stellereum Testnet (chainId 5757)

Зона: Chainlist + деплой-доки. Без кода консенсуса, без коммитов.
Источники истины в репо: `docs/RPC.md` (методы `stell_*`, chainId 5757,
`127.0.0.1:8545`, лимит тела 1 MiB, gateway-лимитер 30 req/s/IP),
`docs/OPERATIONS.md` (§6 exposure checklist, §2 метрики),
`docs/handoff/DEFILLAMA_AND_CHAINLIST_INTEGRATION_PLAN.txt` (фазы 1–3),
`site/index.html` (канонические домены).

Файл содержит три готовых к копипасту артефакта:

1. `eip155-5757.json` — тело файла для `ethereum-lists/chains`.
2. Nginx-сниппет `evm.stellereum.org → 127.0.0.1:8545` (rate-limit + Cloudflare Full Strict).
3. Скелет DeFiLlama-адаптера `projects/stellereum/index.js` (TVL через `stell_getValidators`).

---

## 1. Готовый chain-JSON: `_data/chains/eip155-5757.json`

Скопировать **как есть** в форке `ethereum-lists/chains` под именем
`_data/chains/eip155-5757.json` (имя файла — часть контракта: `eip155-<chainId>.json`).

```json
{
  "name": "Stellereum Testnet",
  "chain": "STELL",
  "rpc": [
    "https://rpc.stellereum.org",
    "https://evm.stellereum.org"
  ],
  "faucets": [],
  "nativeCurrency": {
    "name": "STELL",
    "symbol": "STELL",
    "decimals": 18
  },
  "infoURL": "https://stellereum.org",
  "shortName": "stell-t",
  "chainId": 5757,
  "networkId": 5757,
  "explorers": [
    {
      "name": "Stellereum Explorer",
      "url": "https://explorer.stellereum.org",
      "standard": "EIP3091"
    }
  ]
}
```

### Почему поля именно такие

| Поле | Значение / решение |
| --- | --- |
| `name` | `Stellereum Testnet` — по ТЗ. Не `Stellereum Mainnet`: сеть тестовая, mainnet-имя сейчас было бы ложью. |
| `chain` | `STELL` — короткий идентификатор L1. |
| `chainId` / `networkId` | `5757` (`0x167D`). ChainId захардкожен (`zkml::DEFAULT_CHAIN_ID`, см. `docs/RPC.md` §2 `stell_chainId`), `networkId` обязан совпадать. Перед PR проверить отсутствие коллизии (см. §2 шаг 1). |
| `rpc` | Ровно два URL из ТЗ: `https://rpc.stellereum.org` (существующий L1-RPC, см. `site/index.html`) + `https://evm.stellereum.org` (планируемый EVM-прокси, вариант 1 из `DEFILLAMA_AND_CHAINLIST_INTEGRATION_PLAN.txt`). Оба `https`, без trailing slash, без портов — так требует валидатор чейнов. Порядок значимый: первый — primary. |
| `nativeCurrency` | `symbol: STELL`, `decimals: 18` — по ТЗ (требование MetaMask/Chainlist). **Честная оговорка:** нативный леджер считает в nano-STELL (9 decimals, `1 STELL = 1_000_000_000 nano`, см. `src/pmm.rs`, `src/staking.rs: MIN_VALIDATOR_BOND = 1000 * 1e9`). `decimals: 18` — это EVM-представление для кошельков; EVM-шлюз (§3) обязан конвертировать 9 ↔ 18, а не леджер. Не менять леджер ради Chainlist. |
| `faucets` | `[]`. Кран существует (`stell_faucet`, `POST /api/faucet/:address`), но он с токеном и не является публичным passwordless-краном в смысле схемы Chainlist. Пустой массив валиден; ссылку-пустышку не добавлять. |
| `infoURL` | `https://stellereum.org` (canonical из `site/index.html`). |
| `shortName` | `stell-t` — без пробелов, уникален, с суффиксом тестнета. Перед PR проверить уникальность (см. §2 шаг 1). Не `stell`: оставить короткое имя под будущий mainnet. |
| `explorers[0].url` | `https://explorer.stellereum.org` из ТЗ, `standard: EIP3091`. |
| `icon` | Намеренно опущен: иконка требует отдельного файла в `chainIcons/` + поля `icon`. Добавлять только вторым PR, иначе валидация упадёт. |

### redFlags

`redFlags` в схеме `ethereum-lists/chains` — массив известных проблем,
на практике единственное легальное значение — `"reusedChainId"`
(chainId уже занят другой сетью).

- ChainId `5757` уникален (проверяется на шаге 1 порядка подачи).
- Следовательно файл **не содержит** `redFlags` вообще. Отсутствие поля =
  «флагов нет». Пустой `"redFlags": []` тоже принимается валидатором,
  но канон репозитория — опускать поле, что и сделано выше.
- Если проверка коллизии покажет, что `5757` кем-то занят: НЕ подавать PR
  с `"redFlags": ["reusedChainId"]` молча — сначала сменить chainId
  (это изменение консенсуса, вне зоны этого документа) либо явно
  согласовать reuse в описании PR. Подача дубликата без флага = red flag
  ревью и отказ.

### Локальная проверка JSON (обязательно до PR)

```sh
# 1. Валидный JSON + канон-формат:
python3 -m json.tool _data/chains/eip155-5757.json > /dev/null && echo JSON_OK

# 2. Ключевые инварианты схемы:
python3 - <<'EOF'
import json
d = json.load(open("_data/chains/eip155-5757.json"))
assert d["chainId"] == 5757 and d["networkId"] == 5757
assert d["name"] == "Stellereum Testnet"
assert d["rpc"] == ["https://rpc.stellereum.org", "https://evm.stellereum.org"]
assert d["nativeCurrency"] == {"name": "STELL", "symbol": "STELL", "decimals": 18}
assert d["explorers"][0]["url"] == "https://explorer.stellereum.org"
assert all(u.startswith("https://") for u in d["rpc"])
assert " " not in d["shortName"]
assert "redFlags" not in d  # флагов нет, поле опущено (см. выше)
print("SCHEMA_OK")
EOF
```

---

## 2. Порядок подачи PR в `ethereum-lists/chains`

Предусловие (блокер, честно): Chainlist — каталог **строго EVM-сетей**.
Валидация репозитория и chainlist.org дергают `eth_chainId` (`0x167D`),
`eth_blockNumber`, `eth_getBalance`. Сегодня нода отвечает только на
`stell_*` (`POST /`, `docs/RPC.md` §1: `GET /` → 404, батчи запрещены).
Поэтому PR подавать **после** подъёма EVM-шима на `evm.stellereum.org`
(вариант 1 из интеграционного плана: `eth_chainId → 5757`,
`eth_blockNumber → stell_blockNumber`, `eth_getBalance → stell_getBalance`,
`eth_sendRawTransaction → stell_sendRawTransaction`). Прямой прокси
`evm.* → :8545` без шима валидацию не пройдёт — это учтено в §3.

Шаги:

1. **Проверить уникальность.** В свежем клоне `ethereum-lists/chains`:
   `grep -rn '"chainId": 5757' _data/chains/ ; grep -rn '"shortName": "stell-t"' _data/chains/`
   Оба grep обязаны быть пустыми. Если нет — стоп, см. redFlags выше.
2. **Проверить EVM-готовность обоих RPC.** С публичной сети:
   `curl -s -X POST https://evm.stellereum.org -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'`
   должен вернуть `{"result":"0x167d"}`. То же для `rpc.stellereum.org`, если он тоже за EVM-шимом; если первый RPC остаётся чистым `stell_*` — убрать его из массива `rpc` в PR и оставить только `evm`-URL (иначе Chainlist пометит эндпоинт нерабочим).
3. **Форкнуть и ветвить.** Fork `ethereum-lists/chains` → ветка `add-stellereum-testnet-5757` от актуального `master`.
4. **Положить файл.** Путь строго `_data/chains/eip155-5757.json` с содержимым из §1. Имя файла в нижнем регистре, без BOM, LF, финальный newline.
5. **Прогнать локальные чеки репо.** По README апстрима (на момент написания: `yarn install && yarn test`, валидатор проверяет схему, уникальность `chainId`/`shortName`, https-URL, отсутствие trailing slash). Зелёный прогон обязателен до пуша — CI всё равно это проверит.
6. **Открыть PR.** Один chain = один PR. Название `Add Stellereum Testnet (5757)`. В описании: testnet, ссылка на `https://stellereum.org`, на эксплорер, подтверждение что `5757` свободен, какие RPC отвечают на `eth_*`, что иконки нет осознанно.
7. **Пройти ревью.** Типовые замечания: нерабочий RPC (см. шаг 2), неуникальный `shortName`, лишний `redFlags`, неверный `standard` эксплорера. Править только JSON-файлом в своей ветке.
8. **Пост-мерж проверка.** После мержа апстрима Chainlist подтягивает данные автоматически (обычно часы–дни): открыть `https://chainlist.org/?search=5757` / `https://chainlist.org/chain/5757`, нажать Add to MetaMask, проверить `eth_chainId` в кошельке. Если кнопки нет — подождать кэш CDN, не дублировать PR.

---

## 3. Nginx-сниппет: `evm.stellereum.org → 127.0.0.1:8545`

Назначение: терминировать TLS от Cloudflare, резать абуз rate-limit'ом
(порог сверен с нодой: gateway-лимитер `30 req/s/IP`, см. `docs/RPC.md` §9
и `docs/OPERATIONS.md`; сырой RPC-порт своего лимитера **не имеет** —
`OPERATIONS.md` §6, поэтому лимит здесь обязателен) и проксировать
на локальный RPC `127.0.0.1:8545`.

Ограничения, которые надо знать:

- Сырая нода принимает **только `POST /`**, тело ≤ 1 MiB, батч-массивы
  отвергает (`docs/RPC.md` §1). Сниппет это отражает (`limit_except`,
  `client_max_body_size 1m`). `GET /` от ноды вернёт 404 — это норма.
- До готовности EVM-шима этот прокси отдаёт `stell_*`, а не `eth_*`.
  Финальный upstream для Chainlist — порт EVM-шима; как только шим
  слушает свой порт, заменить `proxy_pass http://127.0.0.1:8545;`
  на порт шима (одна строка).
- `STELL_RPC_LISTEN` и эксплорер-порт держать на `127.0.0.1`. Публикация
  идёт только через этот Nginx. `stell_sendRawTransaction` закрыть
  `STELL_RPC_AUTH_TOKEN` (см. `OPERATIONS.md` §6).

```nginx
# /etc/nginx/snippets/stell-ratelimit.conf
# Зона под EVM-хост. 30 r/s = дефолт gateway-лимитера ноды.
limit_req_zone $binary_remote_addr zone=evm:10m rate=30r/s;
limit_conn_zone $binary_remote_addr zone=evm_conn:10m;

# Апстрим — локальная нода (или порт EVM-шима, когда он готов: см. §3 выше).
upstream stell_evm {
  server 127.0.0.1:8545 max_fails=3 fail_timeout=10s;
  keepalive 32;
}

# HTTP: только редирект на HTTPS (Cloudflare Full Strict + Always Use HTTPS).
server {
  listen 80;
  listen [::]:80;
  server_name evm.stellereum.org;
  return 301 https://$host$request_uri;
}

# HTTPS: Cloudflare -> origin. Full Strict требует валидный origin-сертификат.
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  server_name evm.stellereum.org;

  # Origin Certificate из Cloudflare dashboard (или свой ACME-сертификат).
  ssl_certificate     /etc/ssl/cf/evm.stellereum.org.pem;
  ssl_certificate_key /etc/ssl/cf/evm.stellereum.org.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers on;
  # add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

  # Реальный IP клиента за Cloudflare.
  # Диапазоны: https://www.cloudflare.com/ips (держать актуальными).
  # set_real_ip_from 173.245.48.0/20;
  # ... (полный список Cloudflare IPv4/IPv6) ...
  # real_ip_header CF-Connecting-IP;
  # real_ip_recursive on;

  # Лимиты тела и таймауты сверены с нодой (MAX_RPC_BODY = 1 MiB).
  client_max_body_size 1m;
  client_body_timeout 10s;
  client_header_timeout 10s;
  keepalive_timeout 65s;
  proxy_connect_timeout 5s;
  proxy_send_timeout 15s;
  proxy_read_timeout 15s;

  location / {
    # Нода понимает только POST / — остальное отсекаем на edge.
    limit_except POST { deny all; }

    # 30 r/s, burst 60 без задержки + жёсткий отлуп 429 сверх.
    # nodelay держит p99 низким; перелив уходит в 429, а не в очередь.
    limit_req  zone=evm burst=60 nodelay;
    limit_req_status 429;
    limit_conn evm_conn 20;

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header Content-Type $content_type;
    proxy_pass http://stell_evm;
    proxy_request_buffering on;
  }

  # Лёгкий healthcheck для мониторинга (не нода: у ноды /healthz на :8080).
  location = /nginx-health {
    allow 127.0.0.1;
    deny all;
    access_log off;
    return 200 'ok';
  }
}
```

Cloudflare-сторона (dashboard, зона `stellereum.org`, хост `evm`):

- DNS: `evm` → origin IP, proxied (оранжевое облако).
- SSL/TLS → Encryption mode: **Full (strict)**. `Always Use HTTPS: On`.
  Origin-сертификат — Cloudflare Origin Certificate (срок 15 лет) положить
  по путям из сниппета; `nginx -t && systemctl reload nginx`.
- Speed → Polish/Brotli по вкусу (на JSON-RPC не влияет).
- Security → WAF: managed rules on; Rate limiting rule как второй эшелон
  (например 300 req/min/IP на `evm.stellereum.org`), Bot Fight Mode оценить
  отдельно — скрипты SDK не должны отлетать по JS-challenge.
- Caching: для `evm.*` — Bypass (RPC нельзя кэшировать).

Проверка после включения:

```sh
nginx -t && systemctl reload nginx
# eth_* — после готовности шима; до шима тот же запрос со stell_blockNumber:
curl -s -X POST https://evm.stellereum.org \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
# ожидаемо (с шимом): {"jsonrpc":"2.0","id":1,"result":"0x167d"}
# rate-limit:
for i in $(seq 1 100); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST https://evm.stellereum.org \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
done | sort | uniq -c
# при злоупотреблении часть ответов — 429, легитимный одиночный — 200.
```

---

## 4. DeFiLlama-адаптер: `projects/stellereum/index.js`

Файл для **чужого** репозитория `DefiLlama/DefiLlama-Adapters`
(в этот репозиторий НЕ класть — зона запрещает; путь ниже — путь
в их репо). Источник TVL — стейкинг-леджер через `stell_getValidators`
+ `stell_stakeOf` (см. `docs/RPC.md` §5). Суммы в ответах — **decimal
строки в nano-STELL** (`1 STELL = 1_000_000_000 nano`,
`MIN_VALIDATOR_BOND = 1000 STELL`, `src/staking.rs:25`).

Важные честности, зашитые в скелет комментариями:

- `stell_getValidators.power` — это **total bonded в nano** (см.
  `src/staking.rs: to_validator_set` → `v.total()`), а не «голоса».
  Поэтому скелет пересчитывает TVL через `stell_stakeOf.total`
  по каждому валидатору, а `power`-сумму использует только как fallback.
  (Пример в `docs/RPC.md` с `power: "1"` — иллюстративный, не боевой.)
- Это TVL **стейкинга L1**, не DEX-пулов: методология так и называется.
  Бридж-эскроу / PMM / ордербуки (`stell_bridgeState`, `stell_pmmState`
  из интеграционного плана) добавляются отдельными слагаемыми, когда
  их RPC-риды стабилизируются, — в скелете помечены TODO.
- Цена STELL/USD: до листинга на CoinGecko множитель заглушен (`1`),
  итог возвращается как `tether`-эквивалент с явным TODO заменить
  на прайсфид. Завышать TVL выдуманной ценой запрещено.

```js
// projects/stellereum/index.js  (репозиторий DefiLlama/DefiLlama-Adapters)
// TVL Stellereum Testnet = суммарный bonded stake валидаторов.
// Источники: POST ${RPC}  stell_getValidators  -> список валидаторов
//                          stell_stakeOf         -> { total } в nano-STELL (decimal string)
// 1 STELL = 1_000_000_000 nano. Node >= 18 (global fetch), без новых зависимостей.

const RPC = "https://rpc.stellereum.org";
const NANO_PER_STELL = 1_000_000_000n;

// TODO(price): заменить на CoinGecko/DEX-фид после листинга STELL.
// Сейчас 1 STELL = 1 tether-заглушка, чтобы TVL был в нативных единицах и не врал.
const STELL_USD = 1;

async function rpc(method, params = {}) {
  const res = await fetch(RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`rpc http ${res.status} on ${method}`);
  const j = await res.json();
  if (j.error) throw new Error(`rpc ${method}: ${JSON.stringify(j.error)}`);
  return j.result;
}

async function stakingTvlNano() {
  const set = await rpc("stell_getValidators");
  const validators = (set.validators || []).map((v) => v.validator);
  if (validators.length === 0) return 0n;
  // Авторитетно — per-validator totals; power-сумма только fallback.
  try {
    let sum = 0n;
    for (const validator of validators) {
      const s = await rpc("stell_stakeOf", { validator });
      sum += BigInt(s.total);
    }
    return sum;
  } catch (e) {
    let sum = 0n;
    for (const v of set.validators || []) sum += BigInt(v.power);
    return sum;
  }
}

async function tvl() {
  const nano = await stakingTvlNano();
  // BigInt -> float только в самом конце (u64 nano не влезает в Number безопасно до деления).
  const stell = Number(nano) / Number(NANO_PER_STELL);
  // TODO(bridge/pmm): + escrow (stell_bridgeState) + PMM/ордербуки (stell_pmmState),
  // когда их RPC-риды стабилизируются. Сейчас только стейкинг.
  return { tether: stell * STELL_USD };
}

module.exports = {
  timetravel: false,
  misrepresentedTokens: false,
  start: 1758800000, // TODO(start): заменить на unix-время генезиса тестнета.
  hallmarks: [
    // [1758800000, "Stellereum testnet launch"],
  ],
  methodology:
    "TVL = sum(stell_stakeOf.total) over stell_getValidators set, " +
    "nano-STELL / 1e9. Staking-secured L1 TVL; bridge escrow and " +
    "orderbook liquidity to be added once their RPC reads are stable.",
  stellereum: { tvl },
};
```

Проверка скелета (в клоне `DefiLlama-Adapters`, Node ≥ 18):

```sh
node --check projects/stellereum/index.js && echo ADAPTER_SYNTAX_OK
# живой прогон против тестнета (нужен доступный https://rpc.stellereum.org):
node -e "require('./projects/stellereum/index.js').stellereum.tvl().then(console.log)"
# ожидаемо: { tether: <сумма бондов в STELL> }, при генезисе 2 x 1000 STELL -> { tether: ~2000 }
```

PR в DeFiLlama (фаза 1 плана): fork `DefiLlama/DefiLlama-Adapters` →
ветка `add-stellereum` → положить файл по пути выше → `node test.js projects/stellereum`
(их раннер) → PR с методологией и ссылкой на `https://stellereum.org`.
Двойной учёт с CEX-листингами не заявлять.

---

## Статус и следующие шаги

- [x] JSON `eip155-5757.json` готов (§1), инварианты проверяются скриптом.
- [x] Nginx-сниппет готов (§3), пороги сверены с `docs/RPC.md` / `docs/OPERATIONS.md`.
- [x] DeFiLlama-скелет готов (§4), единицы сверены с `src/staking.rs` / `src/rpc.rs`.
- [ ] Блокер Chainlist-PR: EVM-шим `eth_*` на `evm.stellereum.org` (вне зоны этого документа).
- [ ] После шима: шаги 1–8 из §2, затем фаза DeFiLlama-PR (тест раннером).
- [ ] Вторым PR (не этим): иконка сети в `ethereum-lists/chains`, цена STELL для адаптера.
