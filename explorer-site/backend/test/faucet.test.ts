import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import test from 'node:test';
import {
  buildUpstreamRequestInit,
  createFaucetApp,
  decodeStl57,
  encodeStl57,
  extractTurnstileToken,
  isValidAddress,
  norm,
  normalizeIp,
  parseTrustProxy,
  parseUpstreamTxHash,
} from '../src/index.js';

const VALID_HEX_ADDR = 'a'.repeat(64);
const VALID_HEX_ADDR_2 = 'b'.repeat(64);
const VALID_HEX_ADDR_3 = 'c'.repeat(64);

async function withServer(
  app: ReturnType<typeof createFaucetApp>,
  fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const server = await new Promise<ReturnType<typeof app.listen>>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  try {
    const addr = server.address() as AddressInfo;
    await fn(`http://127.0.0.1:${addr.port}`);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
}

test('extractTurnstileToken reads body and header variants', () => {
  assert.equal(extractTurnstileToken({ cfTurnstileToken: '  tok-camel  ' }, {}), 'tok-camel');
  assert.equal(extractTurnstileToken({ cf_turnstile_response: 'tok-snake' }, {}), 'tok-snake');
  assert.equal(
    extractTurnstileToken({}, { 'cf-turnstile-response': 'tok-header' }),
    'tok-header',
  );
  assert.equal(
    extractTurnstileToken({ cfTurnstileToken: '   ' }, { 'CF-Turnstile-Response': 'tok-fallback' }),
    'tok-fallback',
  );
  assert.equal(extractTurnstileToken({}, {}), undefined);
});

test('buildUpstreamRequestInit forwards Turnstile token only when present and sets redirect error', () => {
  const signal = AbortSignal.timeout(1000);
  const withToken = buildUpstreamRequestInit({
    turnstileToken: 'cf-tok-123',
    upstreamToken: 'secret-bearer',
    signal,
  });
  assert.equal(withToken.method, 'POST');
  assert.equal(withToken.redirect, 'error');
  assert.deepEqual(withToken.headers, {
    authorization: 'Bearer secret-bearer',
    'CF-Turnstile-Response': 'cf-tok-123',
    'Content-Type': 'application/json',
  });
  assert.equal(withToken.body, JSON.stringify({ cf_turnstile_response: 'cf-tok-123' }));

  const withoutToken = buildUpstreamRequestInit({ signal });
  assert.equal(withoutToken.method, 'POST');
  assert.equal(withoutToken.redirect, 'error');
  assert.deepEqual(withoutToken.headers, {});
  assert.equal(withoutToken.body, undefined);
});

test('parseUpstreamTxHash accepts tx_hash, txHash, and hash', () => {
  assert.equal(
    parseUpstreamTxHash(JSON.stringify({ status: 'pending', tx_hash: 'deadbeef' }), 'application/json'),
    'deadbeef',
  );
  assert.equal(
    parseUpstreamTxHash(JSON.stringify({ txHash: 'cafebabe' }), 'application/json; charset=utf-8'),
    'cafebabe',
  );
  assert.equal(parseUpstreamTxHash(JSON.stringify({ hash: '01234567' }), 'application/json'), '01234567');
  assert.equal(parseUpstreamTxHash('not json', 'text/plain'), undefined);
});

test('Stl57 BLAKE3 checksum roundtrip, canonicalization, and rejection', () => {
  const stl = encodeStl57(VALID_HEX_ADDR);
  assert.ok(stl.startsWith('Stl57'));
  assert.equal(decodeStl57(stl), VALID_HEX_ADDR);
  assert.equal(isValidAddress(stl), true);
  assert.equal(norm(stl), VALID_HEX_ADDR);
  assert.equal(norm(`0x${VALID_HEX_ADDR.toUpperCase()}`), VALID_HEX_ADDR);

  // Leading-zero burn address roundtrips with Base58 '1' preservation
  const zeroHex = '0'.repeat(64);
  const zeroStl = encodeStl57(zeroHex);
  assert.equal(decodeStl57(zeroStl), zeroHex);
  assert.equal(norm(zeroStl), zeroHex);

  // Corrupting a single character breaks the 4-byte BLAKE3 checksum
  const lastChar = stl[stl.length - 1]!;
  const badStl = `${stl.slice(0, -1)}${lastChar === '9' ? '8' : '9'}`;
  assert.equal(decodeStl57(badStl), null);
  assert.equal(isValidAddress(badStl), false);
});

test('parseTrustProxy handles 0, false, 1, true, numbers, and CIDR/lists', () => {
  assert.equal(parseTrustProxy(undefined), false);
  assert.equal(parseTrustProxy(''), false);
  assert.equal(parseTrustProxy('0'), false);
  assert.equal(parseTrustProxy('false'), false);
  assert.equal(parseTrustProxy('FALSE'), false);
  assert.equal(parseTrustProxy('1'), 1);
  assert.equal(parseTrustProxy('2'), 2);
  assert.equal(parseTrustProxy('true'), true);
  assert.equal(parseTrustProxy('TRUE'), true);
  assert.equal(parseTrustProxy('-1'), false);
  assert.equal(parseTrustProxy('loopback'), 'loopback');
  assert.equal(parseTrustProxy('127.0.0.1, 10.0.0.0/8'), '127.0.0.1, 10.0.0.0/8');
});

test('normalizeIp unwraps IPv4-mapped IPv6 and aggregates IPv6 to /64', () => {
  assert.equal(normalizeIp('192.0.2.1'), '192.0.2.1');
  assert.equal(normalizeIp('::ffff:192.0.2.1'), '192.0.2.1');
  assert.equal(normalizeIp('0:0:0:0:0:ffff:192.0.2.1'), '192.0.2.1');
  assert.equal(normalizeIp('::ffff:c000:0201'), '192.0.2.1');
  assert.equal(
    normalizeIp('2001:0db8:85a3:0042:0000:8a2e:0370:7334'),
    '2001:db8:85a3:42::/64',
  );
  assert.equal(normalizeIp('2001:db8:85a3:42::1'), '2001:db8:85a3:42::/64');
  assert.equal(normalizeIp('fe80::1%eth0'), 'fe80:0:0:0::/64');
  assert.equal(normalizeIp(''), 'unknown');
});

test('createFaucetApp validates timing config and upstream URL scheme', () => {
  assert.throws(() => createFaucetApp({ upstream: '', windowAddrMs: Number.NaN }));
  assert.throws(() => createFaucetApp({ upstream: '', windowAddrMs: 0 }));
  assert.throws(() => createFaucetApp({ upstream: '', windowIpMs: -100 }));
  assert.throws(() => createFaucetApp({ upstream: '', upstreamTimeoutMs: 0 }));
  assert.throws(() => createFaucetApp({ upstream: 'ftp://evil.example/faucet' }));
  assert.throws(() => createFaucetApp({ upstream: 'not-a-valid-url' }));
});

test('GET /status uses 2 STELL default label and supports configurable labels', async () => {
  const defaultApp = createFaucetApp({ upstream: '' });
  await withServer(defaultApp, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/status`);
    assert.equal(res.status, 200);
    const json = (await res.json()) as { ok: boolean; mock: boolean; drip: string };
    assert.deepEqual(json, {
      ok: true,
      mock: true,
      drip: '2 STELL / address / 45 min',
    });
  });

  const customApp = createFaucetApp({
    upstream: '',
    dripAmountLabel: '3 STELL',
    dripLabel: '3 STELL / address / 30 min',
  });
  await withServer(customApp, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/status`);
    assert.equal(res.status, 200);
    const json = (await res.json()) as { drip: string };
    assert.equal(json.drip, '3 STELL / address / 30 min');
  });
});

test('GET /healthz handles mock mode, upstream health/outage, and 5s caching', async () => {
  const mockApp = createFaucetApp({ upstream: '' });
  await withServer(mockApp, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/healthz`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true, mock: true });
  });

  let probeCount = 0;
  let probeStatus = 204;
  let shouldThrow = false;
  const app = createFaucetApp({
    upstream: 'https://testnet.stellereum.org/api/faucet-public',
    fetchFn: async (_input, init) => {
      probeCount += 1;
      assert.equal(init?.redirect, 'error');
      if (shouldThrow) throw new Error('ECONNREFUSED');
      return new Response(null, { status: probeStatus });
    },
  });

  await withServer(app, async (baseUrl) => {
    const res1 = await fetch(`${baseUrl}/healthz`);
    assert.equal(res1.status, 200);
    assert.deepEqual(await res1.json(), { ok: true, upstream: 204 });
    assert.equal(probeCount, 1);

    // Second immediate request is served from the 5s cache.
    const res2 = await fetch(`${baseUrl}/healthz`);
    assert.equal(res2.status, 200);
    assert.deepEqual(await res2.json(), { ok: true, upstream: 204 });
    assert.equal(probeCount, 1);
  });

  probeStatus = 502;
  const unhealthyApp = createFaucetApp({
    upstream: 'https://testnet.stellereum.org/api/faucet-public',
    fetchFn: async () => new Response(null, { status: 502 }),
  });
  await withServer(unhealthyApp, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/healthz`);
    assert.equal(res.status, 503);
    assert.deepEqual(await res.json(), { ok: false, upstream: 502 });
  });

  shouldThrow = true;
  const unreachableApp = createFaucetApp({
    upstream: 'https://testnet.stellereum.org/api/faucet-public',
    fetchFn: async () => {
      throw new Error('network down');
    },
  });
  await withServer(unreachableApp, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/healthz`);
    assert.equal(res.status, 503);
    assert.deepEqual(await res.json(), { ok: false, upstream: 'unreachable' });
  });
});

test('POST /drip mock mode returns demo payout', async () => {
  const app = createFaucetApp({ upstream: '' });
  await withServer(app, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address: encodeStl57(VALID_HEX_ADDR) }),
    });
    assert.equal(res.status, 200);
    const json = (await res.json()) as {
      ok: boolean;
      mock: boolean;
      txHash: string;
      message: string;
    };
    assert.equal(json.ok, true);
    assert.equal(json.mock, true);
    assert.match(json.txHash, /^[0-9a-f]{64}$/);
    assert.equal(json.message, 'Demo payout (no real funds sent).');
  });
});

test('POST /drip shares rate-limit bucket between Stl57 and hex forms', async () => {
  let upstreamCalls = 0;
  const app = createFaucetApp({
    upstream: 'https://testnet.stellereum.org/api/faucet-public',
    trustProxy: true,
    windowAddrMs: 120_000,
    windowIpMs: 60_000,
    fetchFn: async (input) => {
      upstreamCalls += 1;
      assert.equal(
        String(input),
        `https://testnet.stellereum.org/api/faucet-public/${VALID_HEX_ADDR}`,
      );
      return new Response(JSON.stringify({ tx_hash: 'd'.repeat(64) }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });

  await withServer(app, async (baseUrl) => {
    const stl = encodeStl57(VALID_HEX_ADDR);
    const res1 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.1' },
      body: JSON.stringify({ address: stl }),
    });
    assert.equal(res1.status, 200);

    // Same address in 0x-hex from a DIFFERENT IP must still hit the byAddr 429 bucket.
    const res2 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.2' },
      body: JSON.stringify({ address: `0x${VALID_HEX_ADDR.toUpperCase()}` }),
    });
    assert.equal(res2.status, 429);
    const json2 = (await res2.json()) as { ok: boolean; message: string };
    assert.equal(json2.ok, false);
    assert.match(json2.message, /2 minutes/);
    assert.equal(upstreamCalls, 1);
  });
});

test('POST /drip enforces byIp 429 with dynamic minutes, trustProxy, and IPv6 /64 aggregation', async () => {
  // With trustProxy: false (like TRUST_PROXY="0"), X-Forwarded-For is ignored.
  const noProxyApp = createFaucetApp({
    upstream: '',
    trustProxy: parseTrustProxy('0'),
    windowIpMs: 180_000,
  });
  await withServer(noProxyApp, async (baseUrl) => {
    const r1 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.10' },
      body: JSON.stringify({ address: VALID_HEX_ADDR }),
    });
    assert.equal(r1.status, 200);

    const r2 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.11' },
      body: JSON.stringify({ address: VALID_HEX_ADDR_2 }),
    });
    assert.equal(r2.status, 429);
    const json = (await r2.json()) as { message: string };
    assert.match(json.message, /3 minutes/);
  });

  // With trustProxy: true (like TRUST_PROXY="true"), IPv6 /64 and ::ffff:v4 normalize properly.
  const proxyApp = createFaucetApp({
    upstream: '',
    trustProxy: parseTrustProxy('true'),
    windowIpMs: 180_000,
  });
  await withServer(proxyApp, async (baseUrl) => {
    const r1 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '2001:db8:1:2::1' },
      body: JSON.stringify({ address: VALID_HEX_ADDR }),
    });
    assert.equal(r1.status, 200);

    // Different host in the same /64 shares the IP rate limit.
    const r2 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-forwarded-for': '2001:0db8:0001:0002:abcd::99',
      },
      body: JSON.stringify({ address: VALID_HEX_ADDR_2 }),
    });
    assert.equal(r2.status, 429);

    // Different /64 is allowed.
    const r3 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '2001:db8:1:3::1' },
      body: JSON.stringify({ address: VALID_HEX_ADDR_2 }),
    });
    assert.equal(r3.status, 200);

    // ::ffff:a.b.c.d shares bucket with a.b.c.d.
    const r4 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '::ffff:198.51.100.55' },
      body: JSON.stringify({ address: VALID_HEX_ADDR_3 }),
    });
    assert.equal(r4.status, 200);

    const r5 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.55' },
      body: JSON.stringify({ address: 'd'.repeat(64) }),
    });
    assert.equal(r5.status, 429);
  });
});

test('POST /drip returns 503 when active rate-limiter maps are saturated instead of evicting', async () => {
  const app = createFaucetApp({
    upstream: '',
    trustProxy: true,
    maxEntries: 2,
    windowAddrMs: 60_000,
    windowIpMs: 60_000,
  });

  await withServer(app, async (baseUrl) => {
    const r1 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.1' },
      body: JSON.stringify({ address: VALID_HEX_ADDR }),
    });
    assert.equal(r1.status, 200);

    const r2 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.2' },
      body: JSON.stringify({ address: VALID_HEX_ADDR_2 }),
    });
    assert.equal(r2.status, 200);

    // New uncached address & IP when saturated -> 503.
    const r3 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.3' },
      body: JSON.stringify({ address: VALID_HEX_ADDR_3 }),
    });
    assert.equal(r3.status, 503);

    // Already-limited address is NOT evicted and still gets 429.
    const r4 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.4' },
      body: JSON.stringify({ address: VALID_HEX_ADDR }),
    });
    assert.equal(r4.status, 429);
  });
});

test('POST /drip forwards Turnstile token, parses tx_hash, and returns 2 STELL message', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const fakeFetch: typeof fetch = async (input, init) => {
    calls.push({ url: String(input), init });
    return new Response(
      JSON.stringify({
        status: 'pending',
        credited_nano: '2000000000',
        recipient: VALID_HEX_ADDR,
        tx_hash: 'f'.repeat(64),
      }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    );
  };

  const app = createFaucetApp({
    upstream: 'https://testnet.stellereum.org/api/faucet-public',
    fetchFn: fakeFetch,
  });

  await withServer(app, async (baseUrl) => {
    const res = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        address: `0x${VALID_HEX_ADDR.toUpperCase()}`,
        cfTurnstileToken: 'turnstile-abc',
      }),
    });
    assert.equal(res.status, 200);
    const json = (await res.json()) as { ok: boolean; txHash: string; message: string };
    assert.deepEqual(json, {
      ok: true,
      txHash: 'f'.repeat(64),
      message: 'Sent 2 STELL (testnet funds only).',
    });

    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, `https://testnet.stellereum.org/api/faucet-public/${VALID_HEX_ADDR}`);
    assert.equal(calls[0]!.init?.redirect, 'error');
    assert.deepEqual(calls[0]!.init?.headers, {
      'CF-Turnstile-Response': 'turnstile-abc',
      'Content-Type': 'application/json',
    });
    assert.equal(calls[0]!.init?.body, JSON.stringify({ cf_turnstile_response: 'turnstile-abc' }));
  });
});

test('POST /drip accepts CF-Turnstile-Response header and does not hang when token is absent', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const fakeFetch: typeof fetch = async (input, init) => {
    calls.push({ url: String(input), init });
    const headers = init?.headers as Record<string, string> | undefined;
    if (!headers?.['CF-Turnstile-Response']) {
      return new Response('captcha token required', {
        status: 400,
        headers: { 'content-type': 'text/plain' },
      });
    }
    return new Response(JSON.stringify({ tx_hash: 'e'.repeat(64) }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  const app = createFaucetApp({
    upstream: 'https://testnet.stellereum.org/api/faucet-public',
    fetchFn: fakeFetch,
  });

  await withServer(app, async (baseUrl) => {
    // Missing token: responds promptly with 502 and releases rate-limit slots.
    const missingRes = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address: VALID_HEX_ADDR }),
    });
    assert.equal(missingRes.status, 502);
    assert.equal(calls[0]!.init?.body, undefined);

    // Retry immediately with header token: succeeds because failed attempt released slots.
    const headerRes = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'CF-Turnstile-Response': 'header-tok-xyz',
      },
      body: JSON.stringify({ address: VALID_HEX_ADDR }),
    });
    assert.equal(headerRes.status, 200);
    const json = (await headerRes.json()) as { ok: boolean; txHash: string; message: string };
    assert.deepEqual(json, {
      ok: true,
      txHash: 'e'.repeat(64),
      message: 'Sent 2 STELL (testnet funds only).',
    });
    assert.equal(calls[1]!.init?.body, JSON.stringify({ cf_turnstile_response: 'header-tok-xyz' }));
  });
});

test('POST /drip rejects invalid Stl57 checksums, malformed lengths, bad JSON, and >8kb bodies', async () => {
  let called = 0;
  const app = createFaucetApp({
    upstream: 'https://testnet.stellereum.org/api/faucet-public',
    fetchFn: async () => {
      called += 1;
      return new Response(JSON.stringify({ tx_hash: 'a'.repeat(64) }), { status: 200 });
    },
  });

  await withServer(app, async (baseUrl) => {
    // 51 chars after Stl57 matches old regex [38,60] but decodes > 36 bytes
    const bogusStl57 = `Stl57${'2'.repeat(51)}`;
    const res1 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address: bogusStl57 }),
    });
    assert.equal(res1.status, 400);

    // Valid length & base58, wrong 4-byte BLAKE3 checksum
    const validStl = encodeStl57(VALID_HEX_ADDR);
    const badChecksumStl = `${validStl.slice(0, -1)}${validStl.endsWith('9') ? '8' : '9'}`;
    const res2 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address: badChecksumStl }),
    });
    assert.equal(res2.status, 400);

    // Malformed JSON
    const res3 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{not-valid-json',
    });
    assert.equal(res3.status, 400);

    // Oversized body (>8kb)
    const res4 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address: VALID_HEX_ADDR, pad: 'x'.repeat(9000) }),
    });
    assert.equal(res4.status, 413);

    assert.equal(called, 0);
  });
});

test('POST /drip returns 502 and releases slots on upstream error, network throw, or oversized body', async () => {
  let mode: 'throw' | 'oversized' | 'ok' = 'throw';
  const app = createFaucetApp({
    upstream: 'https://testnet.stellereum.org/api/faucet-public',
    fetchFn: async () => {
      if (mode === 'throw') {
        throw new Error('upstream reset');
      }
      if (mode === 'oversized') {
        return new Response('x'.repeat(70 * 1024), {
          status: 200,
          headers: { 'content-type': 'text/plain' },
        });
      }
      return new Response(JSON.stringify({ tx_hash: 'c'.repeat(64) }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });

  await withServer(app, async (baseUrl) => {
    const r1 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address: VALID_HEX_ADDR }),
    });
    assert.equal(r1.status, 502);

    mode = 'oversized';
    const r2 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address: VALID_HEX_ADDR }),
    });
    assert.equal(r2.status, 502);

    mode = 'ok';
    const r3 = await fetch(`${baseUrl}/drip`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address: VALID_HEX_ADDR }),
    });
    assert.equal(r3.status, 200);
  });
});
