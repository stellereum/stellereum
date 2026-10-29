# Indexer proxy (`/api/v2`)

The public indexer (`https://explorer.stellereum.org/api/v2`) sends a **duplicated**
`Access-Control-Allow-Origin` header (`*, *`). Browsers reject duplicate ACAO, so
cross-origin `fetch` fails with `TypeError: Load failed` (Safari/WebKit) — while
`curl`/Node ignore CORS and work fine.

**Do not call it cross-origin.** The explorer requests the same-origin path
`/api/v2/...` and a proxy forwards it upstream.

## Dev / preview

Already handled by `explorer/vite.config.ts`:

```ts
server: { proxy: { '/api/v2': { target: 'https://explorer.stellereum.org', changeOrigin: true } } }
```

## Production

Add the same rewrite on whatever serves the built `dist/`:

**Nginx**
```nginx
location /api/v2/ {
  proxy_pass https://explorer.stellereum.org/api/v2/;
  proxy_set_header Host explorer.stellereum.org;
}
```

**Netlify** (`public/_redirects`)
```
/api/v2/*  https://explorer.stellereum.org/api/v2/:splat  200
```

**Vercel** (`vercel.json`)
```json
{ "rewrites": [{ "source": "/api/v2/:path*", "destination": "https://explorer.stellereum.org/api/v2/:path*" }] }
```

Alternatively, set `VITE_INDEXER_BASE=https://explorer.stellereum.org/api/v2` before
building — the client also has that as a best-effort fallback if the same-origin
proxy is missing, but it will hit the broken CORS in some browsers.
