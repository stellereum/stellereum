<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover" />
    <meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)" />
    <meta name="theme-color" content="#212121" media="(prefers-color-scheme: dark)" />
    <meta name="description" content="GRAM Explorer, the fastest blockchain explorer for GRAMs: blocks, transactions and accounts in real time." />
    <!-- The link preview (Telegram, X and others): the same card for every page. -->
    <meta property="og:type" content="website" />
    <meta property="og:site_name" content="Gram" />
    <meta property="og:title" content="Gram" />
    <meta property="og:description" content="The native currency of TON" />
    <meta property="og:image" content="https://gram.org/og-image.jpg" />
    <meta property="og:image:type" content="image/jpeg" />
    <meta property="og:image:width" content="1280" />
    <meta property="og:image:height" content="630" />
    <meta property="og:image:alt" content="Gram — the native currency of TON" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="Gram" />
    <meta name="twitter:description" content="The native currency of TON" />
    <meta name="twitter:image" content="https://gram.org/og-image.jpg" />
    <link rel="icon" href="/icons/favicon-32.png" sizes="32x32" type="image/png" />
    <link rel="icon" href="/icons/favicon-64.png" sizes="64x64" type="image/png" />
    <link rel="preload" as="image" href="/assets/gem-white.v1.webp" type="image/webp" />
    <link rel="manifest" href="/manifest.json" />
    <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png" />
    <meta name="apple-mobile-web-app-title" content="GRAM Explorer" />
    <title>GRAM Explorer</title>
    <script>
      try {
        var h = location.hash.match(/^#s=(.+)$/)
        var c = document.cookie.match(/(?:^|; )tx_settings=([^;]*)/)
        var s = JSON.parse(h ? decodeURIComponent(h[1]) : c ? decodeURIComponent(c[1]) : localStorage.getItem('settings') || '{}')
        var t = s.theme
        if (t !== 'light' && t !== 'dark') t = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
        document.documentElement.dataset.theme = t
      } catch (e) {}
      ;(function () {
        var p = location.pathname,
          q = location.search,
          m,
          u = []
        if (p === '/') u = ['/api/price', '/api/stats', '/api/blocks/latest?limit=12', '/api/transactions/latest?limit=40', '/api/tokens', '/api/telegram-wallets']
        else if ((m = p.match(/^\/address\/([^/]+)$/))) {
          // Everything a wallet's page asks for, the sections below the history included, so none waits for the page's code.
          var a = '/api/accounts/' + m[1]
          u = [a, a + '/activity', a + '/contract', a + '/tokens', '/api/prices', a + '/actions', '/api/price', a + '/balance?days=30', a + '/staking', a + '/multisigs', a + '/vestings']
        }
        else if ((m = p.match(/^\/tx\/([^/]+)$/))) u = ['/api/transactions/' + m[1] + (q ? q + '&' : '?') + 'v=10', '/api/transactions/' + m[1] + '/trace?v=10'] // TX_V in src/lib/api.ts
        else if ((m = p.match(/^\/mc\/(\d+)$/))) u = ['/api/blocks/masterchain/' + m[1] + '?v=10']
        else if ((m = p.match(/^\/block\/(-?\d+)\/([0-9a-fA-F]+)\/(\d+)$/))) u = ['/api/blocks/' + m[1] + '/' + m[2] + '/' + m[3] + '?v=10']
        else if (p === '/blocks') u = ['/api/stats', '/api/blocks/latest?limit=12', '/api/transactions/latest?limit=40', '/api/overview']
        else if (p === '/config') u = ['/api/config']
        else if ((m = p.match(/^\/nft\/([^/]+)$/))) u = ['/api/nft/' + m[1], '/api/accounts/' + m[1] + '/actions']
        else if ((m = p.match(/^\/collection\/([^/]+)$/))) u = ['/api/nft-collections/' + m[1], '/api/nft-collections/' + m[1] + '/activity']
        else if ((m = p.match(/^\/jetton\/([^/]+)$/))) u = ['/api/jettons/' + m[1], '/api/jettons/' + m[1] + '/market?days=7']
        else if (p === '/validators') u = ['/api/validators']
        else if (p === '/whales') u = ['/api/whales', '/api/price']
        else if (p === '/stats') u = ['/api/overview', '/api/price', '/api/validators', '/api/market/' + ((window.s && window.s.currency) || 'usd') + '/30', '/api/rounds?limit=30']
        else if (p === '/tools/staking') u = ['/api/staking', '/api/price']
        else if (p === '/tools/unit') u = ['/api/price']
        var P = (window.__PRELOAD__ = {})
        u.forEach(function (x) {
          P[x] = fetch(x, { headers: { accept: 'application/json' } }).then(function (r) {
            return r.json().catch(function () { return null }).then(function (b) {
              return { ok: r.ok, status: r.status, body: b }
            })
          })
          P[x].catch(function () {})
        })
      })()
    </script>
    <script type="module" crossorigin src="/assets/index-B7GmamCL.js"></script>
    <link rel="stylesheet" crossorigin href="/assets/index-YiKdeC2i.css">
  </head>
  <body>
    <div id="app"></div>
  </body>
</html>
