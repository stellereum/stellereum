<script setup lang="ts">
import { withBase } from 'vitepress'

type Feature = {
  title: string
  detail: string
  more: string
  href: string
  icon: string
}

const features: Feature[] = [
  {
    title: 'Post-quantum by default',
    detail:
      'Falcon-512 signs every validator vote and every value-moving transaction. Transactions use a PQ1 envelope; votes use the consensus vote domain. ML-KEM-768 protects node transport. There is no classical signature lane for value.',
    more: 'Read the crypto model',
    href: '/core-concepts/post-quantum',
    icon:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H21M18 12v3M15 12v2"/></svg>',
  },
  {
    title: 'Final in one block',
    detail:
      'Propose, prevote, precommit, commit. A precommit quorum of floor(2·power/3)+1 makes a block final, so the four-validator testnet keeps finalizing with one node offline.',
    more: 'How finality works',
    href: '/core-concepts/consensus-finality',
    icon:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 12.5l5 5L20 6.5"/><path d="M4 6.5h6"/></svg>',
  },
  {
    title: 'Integer-only WASM',
    detail:
      'Contracts run on wasmi with an (i64) -> i64 ABI, 14 host functions, fuel charged before every effect, a 2 MiB code cap and a 4,096-key storage cap.',
    more: 'Build a contract',
    href: '/contracts/overview',
    icon:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z"/><path d="M4 7.5l8 4.5 8-4.5M12 12v9"/></svg>',
  },
  {
    title: 'Shard 0 is the masterchain',
    detail:
      'Accounts, staking, governance and the CLOB live on shard 0. The fixed {0,1} pair is supported in one process with two-phase commit; shard 1 is parked on the public network.',
    more: 'Shard topology and 2PC',
    href: '/core-concepts/sharding',
    icon:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 12l9 5 9-5M3 16l9 5 9-5"/></svg>',
  },
  {
    title: 'A market in the base layer',
    detail:
      'The native CLOB quotes STELL/USDT, STELL/TON and STELL/GRAM. The PMM mints and redeems against a USDT reserve, and scoped session keys delegate trading authority.',
    more: 'Explore the market',
    href: '/core-concepts/native-market',
    icon:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 19V5M4 19h16"/><path d="M7 15l3-4 3 2 4-6"/><path d="M17 7h3v3"/></svg>',
  },
  {
    title: 'Direct RPC and typed SDKs',
    detail:
      'The stell_* namespace is the chain API. A read-only EVM adapter serves chain id and balances. The Rust SDK signs locally; the TypeScript client delegates to a local Rust signer. Both refuse a foreign fork id before signing.',
    more: 'Open the RPC reference',
    href: '/api/json-rpc',
    icon:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/></svg>',
  },
]

const paths = [
  {
    title: 'Build an application',
    detail: 'Keys, faucet, first PQ1 transfer, then WASM contracts.',
    href: '/get-started/quickstart',
  },
  {
    title: 'Run a validator',
    detail: 'Observer first, cold and hot keys, 1,100 STELL bond.',
    href: '/nodes/validator',
  },
  {
    title: 'Integrate a wallet',
    detail: 'Addresses, fees, signing standards and the RPC surface.',
    href: '/get-started/networks',
  },
  {
    title: 'Review the security',
    detail: 'Audit status, threat model and known limitations.',
    href: '/security/status',
  },
]

const glance = [
  { label: 'Chain ID', value: '5757' },
  { label: 'Ruleset', value: 'v7' },
  { label: 'Signatures', value: 'Falcon-512' },
  { label: 'Finality', value: '1 block' },
  { label: 'Block tempo', value: '800 ms' },
  { label: 'Execution', value: 'WASM' },
]

const endpoints = [
  {
    service: 'JSON-RPC',
    url: 'https://rpc.stellereum.org',
    note: 'POST-only. stell_* methods plus the read-only EVM adapter.',
  },
  {
    service: 'Explorer',
    url: 'https://explorer.stellereum.org',
    note: 'Blocks, accounts, transactions and contract activity.',
  },
  {
    service: 'Indexer REST',
    url: 'https://explorer.stellereum.org/api/v2',
    note: 'Indexed history and aggregate queries. Can lag the RPC tip.',
  },
  {
    service: 'Faucet',
    url: 'https://faucet-testnet.stellereum.org',
    note: '2 STELL per drip, 45-minute cooldown, 50 STELL lifetime cap.',
  },
  {
    service: 'Testnet app',
    url: 'https://testnet.stellereum.org',
    note: 'Onboarding and faucet entry point.',
  },
]

const steps = [
  ['Build the node', 'cargo build --release --bin stellereum'],
  ['Create a Falcon wallet', 'stellereum keys init --keys-dir ./keys'],
  ['Fund it from the faucet', '2 STELL per drip on chain 5757'],
  ['Submit and read a PQ1 transfer', 'wallet send-pq → stell_getTransactionReceipt'],
]
</script>

<template>
  <div class="st-home">
    <section class="st-hero" aria-labelledby="st-home-title">
      <div class="st-hero-main">
        <p class="st-eyebrow">
          <span class="st-dot" aria-hidden="true"></span>
          Public testnet
          <span class="st-sep" aria-hidden="true">/</span>
          no external audit
        </p>

        <div class="st-title-row">
          <h1 id="st-home-title">Stellereum</h1>
          <span class="st-title-tag">Docs</span>
        </div>

        <p class="st-lede">
          A pure post-quantum Layer 1 written in Rust. Falcon-512 signatures,
          single-block BFT finality, integer-only WASM contracts and a native
          market in one node.
        </p>

        <div class="st-chips" aria-label="Network identity">
          <span class="st-chip">Chain ID <strong>5757</strong></span>
          <span class="st-chip">Ruleset <strong>v7</strong></span>
          <span class="st-chip">Fork ID <code>0x3ae00ebc</code></span>
        </div>

        <div class="st-actions">
          <a class="st-btn st-btn-primary" :href="withBase('/get-started/quickstart')">
            Quickstart
            <svg viewBox="0 0 16 16" aria-hidden="true">
              <path d="M3 8h9M8.5 3.5L13 8l-4.5 4.5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
          </a>
          <a class="st-btn" :href="withBase('/api/json-rpc')">JSON-RPC reference</a>
        </div>

        <p class="st-fineprint">
          Testnet STELL has no value. State may be reset. Do not reuse keys that
          protect real assets.
        </p>
      </div>

      <aside class="st-terminal" aria-label="Verify the JSON-RPC endpoint">
        <div class="st-terminal-head">
          <span>JSON-RPC</span>
          <span class="st-terminal-method">POST /</span>
        </div>
        <pre><code>curl -sS https://rpc.stellereum.org \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,
       "method":"stell_chainId",
       "params":[]}'</code></pre>
        <div class="st-terminal-result">
          <span>result</span>
          <code>5757</code>
        </div>
        <p>
          A different chain id means a different network.
          <a :href="withBase('/get-started/networks')">Check every endpoint</a>
          before you sign.
        </p>
      </aside>
    </section>

    <section class="st-glance" aria-labelledby="st-glance-title">
      <p id="st-glance-title" class="st-glance-kicker">At a glance</p>
      <dl>
        <div v-for="item in glance" :key="item.label">
          <dt>{{ item.label }}</dt>
          <dd>{{ item.value }}</dd>
        </div>
      </dl>
    </section>

    <section class="st-section" aria-labelledby="st-features-title">
      <div class="st-section-head">
        <p class="st-kicker">Protocol surface</p>
        <h2 id="st-features-title">What the chain gives you</h2>
        <p>
          Concrete primitives, not a roadmap. Every claim below is enforced in
          the node and documented against the source.
        </p>
      </div>

      <div class="st-feature-grid">
        <a
          v-for="feature in features"
          :key="feature.title"
          class="st-feature"
          :href="withBase(feature.href)"
        >
          <span class="st-feature-icon" v-html="feature.icon" aria-hidden="true"></span>
          <h3>{{ feature.title }}</h3>
          <p>{{ feature.detail }}</p>
          <span class="st-feature-more">
            {{ feature.more }}
            <svg viewBox="0 0 16 16" aria-hidden="true">
              <path d="M3 8h9M8.5 3.5L13 8l-4.5 4.5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
          </span>
        </a>
      </div>
    </section>

    <section class="st-split" aria-label="Start here">
      <div class="st-paths">
        <div class="st-section-head st-section-head-tight">
          <p class="st-kicker">Choose a path</p>
          <h2>Start where you are</h2>
        </div>
        <a v-for="path in paths" :key="path.title" class="st-path" :href="withBase(path.href)">
          <span class="st-path-text">
            <strong>{{ path.title }}</strong>
            <span>{{ path.detail }}</span>
          </span>
          <span class="st-path-arrow" aria-hidden="true">→</span>
        </a>
      </div>

      <div class="st-steps">
        <div class="st-section-head st-section-head-tight">
          <p class="st-kicker">First transfer</p>
          <h2>Four steps to finality</h2>
        </div>
        <ol>
          <li v-for="(step, index) in steps" :key="step[0]">
            <span class="st-step-num">{{ String(index + 1).padStart(2, '0') }}</span>
            <span class="st-step-body">
              <strong>{{ step[0] }}</strong>
              <code>{{ step[1] }}</code>
            </span>
          </li>
        </ol>
        <a class="st-text-link" :href="withBase('/get-started/quickstart')">
          Open the full quickstart
          <span aria-hidden="true">→</span>
        </a>
      </div>
    </section>

    <section class="st-section st-endpoints" aria-labelledby="st-endpoints-title">
      <div class="st-section-head">
        <p class="st-kicker">Live network</p>
        <h2 id="st-endpoints-title">Endpoints</h2>
        <p>
          The RPC is authoritative for balances and receipts. The indexer is a
          cache for history and aggregates.
        </p>
      </div>

      <div class="st-table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Service</th>
              <th scope="col">Endpoint</th>
              <th scope="col">Use it for</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="endpoint in endpoints" :key="endpoint.service">
              <td>{{ endpoint.service }}</td>
              <td>
                <a :href="endpoint.url" target="_blank" rel="noreferrer">
                  {{ endpoint.url.replace('https://', '') }}
                </a>
              </td>
              <td>{{ endpoint.note }}</td>
            </tr>
            <tr>
              <td>Documentation</td>
              <td><a href="https://docs.stellereum.org" target="_blank" rel="noreferrer">docs.stellereum.org</a></td>
              <td>This site.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <aside class="st-note">
      <strong>Testnet only.</strong>
      There is no mainnet and no independent external audit. Shard 1 is parked,
      the EVM adapter does not execute bytecode, and zkML is verifiable
      re-execution rather than a zero-knowledge proof.
      <a :href="withBase('/security/status')">Read the security status</a>.
    </aside>
  </div>
</template>

<style scoped>
.st-home {
  box-sizing: border-box;
  width: 100%;
  max-width: 1160px;
  margin: 0 auto;
  padding: 56px 24px 96px;
  overflow-x: clip;
}

:where(.st-home, .st-home *) {
  box-sizing: border-box;
}

.st-hero {
  display: grid;
  grid-template-columns: minmax(0, 1.08fr) minmax(340px, 0.92fr);
  gap: 56px;
  align-items: center;
  padding: 24px 0 48px;
}

.st-hero-main {
  min-width: 0;
}

.st-eyebrow {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 0 0 20px;
  font-family: var(--st-font-mono);
  font-size: 11.5px;
  letter-spacing: 0.02em;
  color: var(--st-text-2);
  text-transform: uppercase;
}

.st-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #63d6a0;
  box-shadow: 0 0 0 3px rgba(99, 214, 160, 0.12);
}

.st-sep {
  color: var(--st-text-3);
}

.st-title-row {
  display: flex;
  align-items: baseline;
  gap: 14px;
}

.st-title-row h1 {
  margin: 0;
  font-family: var(--st-font-sans);
  font-size: clamp(3.4rem, 7.5vw, 5.4rem);
  font-weight: 650;
  line-height: 0.98;
  letter-spacing: -0.055em;
  background: var(--st-grad-text);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}

.st-title-tag {
  font-family: var(--st-font-mono);
  font-size: 12px;
  color: var(--st-text-3);
  letter-spacing: 0.02em;
}

.st-lede {
  max-width: 38rem;
  margin: 24px 0 0;
  font-size: clamp(1.05rem, 1.5vw, 1.2rem);
  line-height: 1.65;
  color: var(--st-text-2);
}

.st-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 24px;
}

.st-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 10px;
  border: 1px solid var(--st-line);
  border-radius: 5px;
  background: var(--st-surface);
  font-family: var(--st-font-mono);
  font-size: 11.5px;
  color: var(--st-text-3);
}

.st-chip strong {
  font-weight: 600;
  color: var(--st-text-1);
}

.st-chip code {
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--st-text-1);
  font-size: inherit;
}

.st-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 32px;
}

.st-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-height: 40px;
  padding: 0 18px;
  border: 1px solid var(--st-line);
  border-radius: 6px;
  background: var(--st-surface);
  color: var(--st-text-1);
  font-size: 13.5px;
  font-weight: 550;
  text-decoration: none;
  transition: border-color 0.16s ease, background 0.16s ease, color 0.16s ease;
}

.st-btn:hover {
  border-color: var(--st-line-strong);
  background: var(--st-surface-2);
}

.st-btn svg {
  width: 14px;
  height: 14px;
}

.st-btn-primary {
  border-color: transparent;
  background: var(--st-indigo);
  color: #060811;
}

.st-btn-primary:hover {
  border-color: transparent;
  background: #93a2ff;
  color: #060811;
}

.st-fineprint {
  max-width: 34rem;
  margin: 20px 0 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--st-text-3);
}

.st-terminal {
  align-self: center;
  display: flex;
  flex-direction: column;
  min-width: 0;
  border: 1px solid var(--st-line);
  border-radius: 8px;
  background: var(--st-surface);
  overflow: hidden;
}

.st-terminal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 16px;
  border-bottom: 1px solid var(--st-line-soft);
  font-family: var(--st-font-mono);
  font-size: 10.5px;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--st-text-3);
}

.st-terminal-method {
  color: var(--st-text-2);
}

.st-terminal pre {
  max-width: 100%;
  margin: 0;
  padding: 18px 16px;
  overflow-x: auto;
  background: transparent;
  font-family: var(--st-font-mono);
  font-size: 12px;
  line-height: 1.65;
  color: #c6d5f2;
}

.st-terminal pre code {
  padding: 0;
  border: 0;
  background: transparent;
  color: inherit;
  font-size: inherit;
}

.st-terminal-result {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin: 0 16px;
  padding: 10px 0;
  border-top: 1px solid var(--st-line-soft);
  font-family: var(--st-font-mono);
  font-size: 11px;
  color: var(--st-text-3);
}

.st-terminal-result code {
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--st-blue);
  font-size: 14px;
  font-weight: 600;
}

.st-terminal p {
  margin: 0;
  padding: 0 16px 16px;
  font-size: 12px;
  line-height: 1.6;
  color: var(--st-text-3);
}

.st-terminal p a {
  color: var(--st-text-2);
  text-decoration: underline;
  text-decoration-color: var(--st-line-strong);
  text-underline-offset: 3px;
}

.st-glance {
  border-top: 1px solid var(--st-line);
  border-bottom: 1px solid var(--st-line);
}

.st-glance-kicker {
  margin: 0;
  padding-top: 12px;
  font-family: var(--st-font-mono);
  font-size: 10.5px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--st-text-3);
}

.st-glance dl {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  margin: 0;
}

.st-glance dl > div {
  padding: 18px 16px;
  border-left: 1px solid var(--st-line-soft);
}

.st-glance dl > div:first-child {
  border-left: 0;
  padding-left: 0;
}

.st-glance dt {
  margin: 0 0 4px;
  font-family: var(--st-font-mono);
  font-size: 10.5px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--st-text-3);
}

.st-glance dd {
  margin: 0;
  font-size: 14px;
  font-weight: 550;
  color: var(--st-text-1);
}

.st-section {
  padding-top: 72px;
}

.st-section-head {
  max-width: 44rem;
  margin-bottom: 28px;
}

.st-section-head-tight {
  margin-bottom: 16px;
}

.st-kicker {
  margin: 0 0 8px;
  font-family: var(--st-font-mono);
  font-size: 11px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--st-blue);
}

.st-section-head h2,
.st-split h2 {
  margin: 0;
  font-size: clamp(1.55rem, 2.4vw, 1.9rem);
  font-weight: 600;
  letter-spacing: -0.03em;
  color: var(--st-text-1);
}

.st-section-head > p:last-child {
  margin: 10px 0 0;
  font-size: 14.5px;
  line-height: 1.65;
  color: var(--st-text-2);
}

.st-feature-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.st-feature {
  display: flex;
  flex-direction: column;
  min-width: 0;
  min-height: 210px;
  padding: 22px;
  border: 1px solid var(--st-line-soft);
  border-radius: 7px;
  background: var(--st-surface);
  color: inherit;
  text-decoration: none;
  transition: border-color 0.18s ease, background 0.18s ease, transform 0.18s ease;
}

.st-feature:hover {
  border-color: var(--st-line-strong);
  background: var(--st-surface-2);
  transform: translateY(-1px);
}

.st-feature-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 34px;
  margin-bottom: 20px;
  border: 1px solid var(--st-line);
  border-radius: 6px;
  background: rgba(94, 184, 255, 0.06);
  color: var(--st-blue);
}

.st-feature-icon :deep(svg) {
  width: 18px;
  height: 18px;
}

.st-feature h3 {
  margin: 0;
  font-size: 15.5px;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--st-text-1);
}

.st-feature p {
  margin: 10px 0 0;
  font-size: 13.5px;
  line-height: 1.68;
  color: var(--st-text-2);
}

.st-feature-more {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin-top: auto;
  padding-top: 20px;
  font-family: var(--st-font-mono);
  font-size: 11.5px;
  color: var(--st-blue);
}

.st-feature-more svg {
  width: 12px;
  height: 12px;
}

.st-split {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 56px;
  margin-top: 72px;
  padding-top: 48px;
  border-top: 1px solid var(--st-line);
}

.st-path {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 14px 0;
  border-bottom: 1px solid var(--st-line-soft);
  color: inherit;
  text-decoration: none;
}

.st-path:first-of-type {
  border-top: 1px solid var(--st-line-soft);
}

.st-path-text {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.st-path-text strong {
  font-size: 14.5px;
  font-weight: 550;
  color: var(--st-text-1);
}

.st-path-text span {
  font-size: 12.5px;
  line-height: 1.55;
  color: var(--st-text-3);
}

.st-path-arrow {
  color: var(--st-text-3);
  transition: color 0.16s ease, transform 0.16s ease;
}

.st-path:hover .st-path-arrow {
  color: var(--st-blue);
  transform: translateX(2px);
}

.st-steps ol {
  margin: 0;
  padding: 0;
  list-style: none;
  border-top: 1px solid var(--st-line-soft);
}

.st-steps li {
  display: flex;
  gap: 14px;
  padding: 14px 0;
  border-bottom: 1px solid var(--st-line-soft);
}

.st-step-num {
  padding-top: 2px;
  font-family: var(--st-font-mono);
  font-size: 11px;
  color: var(--st-text-3);
}

.st-step-body {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
}

.st-step-body strong {
  font-size: 14px;
  font-weight: 550;
  color: var(--st-text-1);
}

.st-step-body code {
  padding: 0;
  border: 0;
  background: transparent;
  font-size: 11.5px;
  color: var(--st-text-3);
  overflow-wrap: anywhere;
}

.st-text-link {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin-top: 18px;
  font-size: 13px;
  font-weight: 550;
  color: var(--st-blue);
  text-decoration: none;
}

.st-text-link:hover {
  color: #93d2ff;
}

.st-endpoints {
  padding-bottom: 8px;
}

.st-table-wrap {
  overflow-x: auto;
  border-top: 1px solid var(--st-line);
}

.st-table-wrap table {
  width: 100%;
  margin: 0;
  border-collapse: collapse;
  font-size: 13px;
}

.st-table-wrap th,
.st-table-wrap td {
  padding: 12px 14px;
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid var(--st-line-soft);
}

.st-table-wrap th {
  font-family: var(--st-font-mono);
  font-size: 10.5px;
  font-weight: 500;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--st-text-3);
  white-space: nowrap;
}

.st-table-wrap td {
  color: var(--st-text-2);
}

.st-table-wrap td:first-child {
  color: var(--st-text-1);
  font-weight: 550;
  white-space: nowrap;
}

.st-table-wrap td:nth-child(2) {
  font-family: var(--st-font-mono);
  font-size: 12px;
}

.st-table-wrap a {
  color: var(--st-text-2);
  text-decoration: none;
  border-bottom: 1px solid var(--st-line);
}

.st-table-wrap a:hover {
  color: var(--st-blue);
  border-bottom-color: var(--st-blue);
}

.st-note {
  margin-top: 64px;
  padding: 18px 20px;
  border-left: 2px solid var(--st-warning);
  background: rgba(255, 196, 107, 0.05);
  font-size: 13px;
  line-height: 1.7;
  color: var(--st-text-2);
}

.st-note strong {
  color: #ffd79a;
}

.st-note a {
  color: #ffd79a;
  text-decoration: underline;
  text-underline-offset: 3px;
}

@media (max-width: 960px) {
  .st-hero {
    grid-template-columns: 1fr;
    gap: 36px;
    padding-top: 8px;
  }

  .st-terminal {
    max-width: 620px;
  }

  .st-glance dl {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  .st-glance dl > div:nth-child(4) {
    border-left: 0;
    padding-left: 0;
  }

  .st-glance dl > div:nth-child(n + 4) {
    border-top: 1px solid var(--st-line-soft);
  }

  .st-feature-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .st-split {
    grid-template-columns: 1fr;
    gap: 40px;
  }
}

@media (max-width: 640px) {
  .st-home {
    padding: 32px 18px 64px;
  }

  .st-title-row {
    gap: 10px;
  }

  .st-title-tag {
    font-size: 11px;
  }

  .st-glance dl {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .st-glance dl > div,
  .st-glance dl > div:nth-child(4) {
    padding: 14px 12px;
    border-left: 1px solid var(--st-line-soft);
  }

  .st-glance dl > div:nth-child(odd) {
    border-left: 0;
    padding-left: 0;
  }

  .st-glance dl > div:nth-child(n + 3) {
    border-top: 1px solid var(--st-line-soft);
  }

  .st-feature-grid {
    grid-template-columns: 1fr;
  }

  .st-section {
    padding-top: 56px;
  }

  .st-split {
    margin-top: 56px;
    padding-top: 40px;
  }

  .st-table-wrap th:nth-child(3),
  .st-table-wrap td:nth-child(3) {
    display: none;
  }
}
</style>
