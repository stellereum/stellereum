# InfMail / InfNode — НАВИГАЦИЯ ПРОЕКТА (прочитай первым)

## Куда смотреть (одна строка на реп)

| Папка/реп | Что | С чего начать |
|-----------|-----|---------------|
| `infNode/` | **ЯДРО** (Rust): нода + валидатор, все наработки | `infNode/ARCHITECTURE.md` |
| `infmail-web/` | Фронт Next.js (сайт) | `infmail-web/README.md` |
| `infmail-contracts/` | Смарт-контракты TON (легитивные) | `infmail-contracts/README.md` |
| `nft-card-service/` | Генератор NFT-карт | `nft-card-service/README.md` |
| `infmail-tools/` | Go/Zig утилиты (obs/payouts/chunkcheck) | `infmail-tools/README.md` |
| `SESSION_CONTEXT.md` | Вся история сессии, статус, решения | читай после ARCHITECTURE.md |

## Главное (чтобы не запутаться)

1. **`infNode` = всё ядро** (Rust). Нода и валидатор — это два бинаря из него:
   - `crates/infnode` → бинарь `infnode` (НОДА, без почты)
   - `crates/infmail` → бинарь `infmail` (ВАЛИДАТОР, почта+API+контракты)
2. **Контракты** легитивные в `infmail-contracts` (src/*.tolk), развёрнуты в TON.
3. **Фронт** в `infmail-web`, **NFT-карты** в `nft-card-service`.
4. **Go/Zig** — вспомогательные утилиты (`infmail-tools`), частично встроены в `infnode` CLI (stats/audit-kv).

## Быстрый старт (для новичка)

```bash
cd infNode
make start ROLE=mail    # НОДА (storage)
make validator          # ВАЛИДАТОР (нужен INFNODE_VALIDATOR_KEY)
```

## На проде (валидатор 109.107.155.67)

- Бинарь валидатора: `/opt/infnode/infmaild`
- Конфиг: `/opt/infnode/node.yaml`
- Контракты (TON): адреса в env сервиса (см. `infNode/ARCHITECTURE.md`)
