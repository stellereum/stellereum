# InfMail — Финальный статус

## Статус: 2026-07-14 — **ВСЁ ИСПРАВЛЕНО**

## Репозитории

| Репозиторий | Назначение | Тесты |
|-------------|-----------|-------|
| `infmail-acton` | Tolk контракты + TypeScript (Blueprint) тесты + Acton Tolk тесты | **54 + 16 = 70** |
| `infmail-backend` | Rust бекенд (Axum) + NFT pipeline | **61** |
| `infmail-frontend` | Next.js фронтенд | build ✅ |
| `infmail-dashboard` | Статическая HTML-панель | — |

## Что было сделано

### Critical (6/6)
1. **token_id = 1** — динамический (TON Center API + атомарный счётчик БД)
2. **Path traversal** — `validate_token_id()` reject не-digits  
3. **Verify без image_hash** — SHA-256 PNG сверяется с LSB + tokenId cross-check
4. **Mint без деплоя NftItem** — `AutoDeployAddress` deploy в Mint handler
5. **NEXT_PUBLIC_ADMIN_TOKEN** — не использовался
6. **Нет ErrorBoundary** — создан + обёрнут `<Providers>`

### High (13/13)
- **Storage withdraw** — admin-only opcode + тесты
- **nft_item customPayload** — `loadMaybeRef()` по TEP-62
- **Mint pending cleanup** — `pendingWallet.delete` + `pendingEmail.delete`
- **expect("jwt")** — все 8 заменены на error response
- **spawn_blocking** — Node.js subprocess обёрнут в `tokio::task::spawn_blocking`
- **Пустые catch {}** — ~20 заменены на `console.error`
- **RwLock poison** — `.unwrap_or_else(|e| e.into_inner())`
- **proxy.ts localhost** — `NEXT_PUBLIC_API_URL`
- **fetch_next_token_id stack index** — `stack[0]` вместо `stack[1]`

### Medium (10/10)
- **NftItem deploy** — deploy через `createMessage` + `AutoDeployAddress`
- **Registry тесты** — reserve, pricing, tiers (8 новых)
- **NftItem тесты** — transfer, getNftData (3 новых)
- **storage.tolk targetEmailHash** — убран
- **Indexer log** — `tracing::warn!` при пустом адресе
- **Meta viewport** — `user-scalable=no`
- **Сonsolidation** — `infmail-contracts` → `infmail-acton` (единый репозиторий)

### Low (6/6)
- **SESSION_TTL** — env var (default 259200)
- **Recovery code** — 6→8 цифр
- **Font path** — cross-platform поиск
- **email_templates** — `APP_URL` env var
- **nft_viewer** — verify через backend API
- **Concurrent NFT mint race** — атомарный `allocate_nft_token_id`

## Итого
| Проект | Тестов | Статус |
|--------|--------|--------|
| infmail-backend | 61 | ✅ |
| infmail-acton (Blueprint) | 54 | ✅ |
| infmail-acton (Acton) | 16 | ✅ |
| infmail-frontend | build | ✅ |
| **Всего** | **131** | ✅ |
