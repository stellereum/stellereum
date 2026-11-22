import { defineConfig } from 'vitepress'

const X_ICON =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M18.9 2H22l-6.8 7.8L23.2 22h-6.3l-4.9-6.4L6.4 22H3.3l7.3-8.3L1.2 2h6.4l4.4 5.9L18.9 2Zm-1.1 18h1.7L7.1 3.9H5.3L17.8 20Z"/></svg>'

const TELEGRAM_ICON =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M21.9 4.3 18.6 20c-.2 1.1-.9 1.4-1.8.9l-5-3.7-2.4 2.3c-.3.3-.5.5-1 .5l.4-5.1 9.3-8.4c.4-.4-.1-.6-.6-.2L6.1 12.8l-4.9-1.5c-1.1-.3-1.1-1 .2-1.5l19.1-7.4c.9-.3 1.7.2 1.4 1.9Z"/></svg>'

const sidebarDescription = (text: string, description: string) =>
  `${text}<span class="st-group-desc">${description}</span>`

export default defineConfig({
  title: 'Stellereum Docs',
  description:
    'Developer documentation for Stellereum (STELL): a pure post-quantum, sharded, non-EVM Layer 1 written in Rust. Testnet only; no external audit.',
  lang: 'en',
  cleanUrls: true,
  lastUpdated: false,

  markdown: {
    languageAlias: {
      wat: 'wasm'
    },
    config(md) {
      // Copy each table header into a data-label on its cells. The mobile
      // stylesheet turns wide tables into stacked label/value cards.
      md.core.ruler.after('inline', 'stellereum-table-labels', (state: any) => {
        const tokens = state.tokens
        const cellText = (token: any) =>
          (token.children ?? [])
            .filter((child: any) => child.type === 'text' || child.type === 'code_inline')
            .map((child: any) => child.content)
            .join('')
            .trim()

        for (let i = 0; i < tokens.length; i++) {
          if (tokens[i].type !== 'table_open') continue

          const headers: string[] = []
          let inHead = false
          for (let j = i + 1; j < tokens.length && tokens[j].type !== 'table_close'; j++) {
            if (tokens[j].type === 'thead_open') inHead = true
            else if (tokens[j].type === 'thead_close') inHead = false
            else if (inHead && tokens[j].type === 'inline') headers.push(cellText(tokens[j]))
          }

          let inBody = false
          let cell = 0
          for (let j = i + 1; j < tokens.length && tokens[j].type !== 'table_close'; j++) {
            const token = tokens[j]
            if (token.type === 'tbody_open') inBody = true
            else if (token.type === 'tbody_close') inBody = false
            else if (inBody && token.type === 'tr_open') cell = 0
            else if (inBody && token.type === 'td_open') token.attrSet('data-label', headers[cell++] ?? '')
          }
        }
      })
    }
  },

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
    ['meta', { name: 'theme-color', content: '#060811' }],
    ['meta', { name: 'color-scheme', content: 'dark' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'Stellereum Docs' }],
    ['meta', { property: 'og:locale', content: 'en_US' }],
    ['meta', { property: 'og:url', content: 'https://docs.stellereum.org/' }],
    [
      'meta',
      { property: 'og:title', content: 'Stellereum Docs — pure post-quantum Layer 1' }
    ],
    [
      'meta',
      {
        property: 'og:description',
        content:
          'Falcon-512 signatures, single-block BFT finality, WASM contracts and a native market. Chain ID 5757, Ruleset v7. Public testnet; no external audit.'
      }
    ],
    ['meta', { property: 'og:image', content: 'https://docs.stellereum.org/og-image.png' }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:site', content: '@stellereum' }],
    [
      'meta',
      { name: 'twitter:title', content: 'Stellereum Docs — pure post-quantum Layer 1' }
    ],
    [
      'meta',
      {
        name: 'twitter:description',
        content:
          'Falcon-512 signatures, single-block BFT finality, WASM contracts and a native market. Chain ID 5757, Ruleset v7. Public testnet; no external audit.'
      }
    ],
    ['meta', { name: 'twitter:image', content: 'https://docs.stellereum.org/og-image.png' }]
  ],

  themeConfig: {
    logo: '/favicon.svg',
    siteTitle: 'Stellereum',

    nav: [
      { text: 'Build', link: '/get-started/quickstart', activeMatch: '/get-started/' },
      { text: 'Contracts', link: '/contracts/overview', activeMatch: '/contracts/' },
      { text: 'API', link: '/api/json-rpc', activeMatch: '/api/' },
      { text: 'Nodes', link: '/nodes/observer', activeMatch: '/nodes/' },
      { text: 'Security', link: '/security/status', activeMatch: '/security/' }
    ],

    socialLinks: [
      { icon: { svg: X_ICON }, link: 'https://x.com/stellereum', ariaLabel: 'X' },
      {
        icon: { svg: TELEGRAM_ICON },
        link: 'https://t.me/stellereum',
        ariaLabel: 'Telegram'
      }
    ],

    search: {
      provider: 'local',
      options: {
        detailedView: true
      }
    },

    sidebar: [
      {
        text: sidebarDescription('Introduction', 'What this is, and a first transfer'),
        items: [
          { text: 'Overview', link: '/get-started/overview' },
          { text: 'Get started', link: '/get-started/quickstart' },
          { text: 'Architecture', link: '/get-started/architecture' },
          { text: 'Networks & endpoints', link: '/get-started/networks' },
          { text: 'Addresses', link: '/get-started/addresses' }
        ]
      },
      {
        text: sidebarDescription('Core concepts', 'The protocol primitives, stated plainly'),
        items: [
          { text: 'Post-quantum', link: '/core-concepts/post-quantum' },
          { text: 'Accounts & fees', link: '/core-concepts/accounts-and-fees' },
          { text: 'Consensus & finality', link: '/core-concepts/consensus-finality' },
          { text: 'Sharding', link: '/core-concepts/sharding' },
          { text: 'Native market', link: '/core-concepts/native-market' }
        ]
      },
      {
        text: sidebarDescription('Smart contracts', 'WASM modules, host API, deploy and migrate'),
        items: [
          { text: 'Overview', link: '/contracts/overview' },
          { text: 'Execution model', link: '/contracts/execution-model' },
          { text: 'Rust contracts', link: '/contracts/rust' },
          { text: 'WAT contracts', link: '/contracts/wat' },
          { text: 'Host functions', link: '/contracts/host-functions' },
          { text: 'ABI manifest', link: '/contracts/abi' },
          { text: 'Deploy & call', link: '/contracts/deploy-and-call' },
          { text: 'Reference standards', link: '/contracts/standards' },
          { text: 'Verification & upgrade', link: '/contracts/verification-and-upgrade' }
        ]
      },
      {
        text: sidebarDescription('SDKs & wallets', 'Sign, submit and delegate from client code'),
        items: [
          { text: 'Rust SDK', link: '/sdk/rust' },
          { text: 'TypeScript SDK', link: '/sdk/typescript' },
          { text: 'Wallet signing', link: '/sdk/wallets-and-signing' },
          { text: 'Session keys', link: '/sdk/session-keys' },
          { text: 'Paymaster', link: '/sdk/paymaster' }
        ]
      },
      {
        text: sidebarDescription('API reference', 'RPC, push streams and the indexer cache'),
        items: [
          { text: 'JSON-RPC', link: '/api/json-rpc' },
          { text: 'WebSocket & SSE', link: '/api/websocket-sse' },
          { text: 'Indexer REST', link: '/api/indexer-rest' },
          { text: 'Errors', link: '/api/errors' }
        ]
      },
      {
        text: sidebarDescription('Nodes & validators', 'Run, upgrade and operate the network'),
        items: [
          { text: 'Observer', link: '/nodes/observer' },
          { text: 'Validator', link: '/nodes/validator' },
          { text: 'Software upgrades', link: '/nodes/upgrades' },
          { text: 'Operations', link: '/nodes/operations' },
          { text: 'Monitoring', link: '/nodes/monitoring' }
        ]
      },
      {
        text: sidebarDescription('Security', 'Audit status, threats and disclosure'),
        items: [
          { text: 'Status', link: '/security/status' },
          { text: 'Threat model', link: '/security/threat-model' },
          { text: 'Reporting', link: '/security/reporting' }
        ]
      },
      {
        text: sidebarDescription('Examples', 'Reference contracts and WAT modules'),
        items: [
          { text: 'Reference contracts', link: '/contracts/standards' },
          { text: 'Bundled WAT modules', link: '/contracts/wat#bundled-wat-examples' }
        ]
      }
    ],

    footer: {
      message:
        'Stellereum is a public testnet. No independent external audit has been completed — do not use real funds.',
      copyright:
        '© 2026 Stellereum Core Contributors · <a href="https://x.com/stellereum" target="_blank" rel="noreferrer">X</a> · <a href="https://github.com/stellereum/stellereum" target="_blank" rel="noreferrer">GitHub</a> · <a href="https://t.me/stellereum" target="_blank" rel="noreferrer">Telegram</a>'
    },

    outline: {
      level: 'deep',
      label: 'On this page'
    },

    skipToContentLabel: 'Skip to content',

    editLink: false
  }
})
