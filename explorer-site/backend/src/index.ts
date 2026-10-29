import cors from 'cors';
import express, { type NextFunction, type Request, type Response } from 'express';

const PORT = Number(process.env.PORT || 8787);
const CORS_ORIGIN = (process.env.CORS_ORIGIN || 'http://localhost:5174')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const RAW_UPSTREAM = process.env.UPSTREAM_FAUCET_URL;
// undefined -> default upstream; empty string or "mock" -> mock mode (no real payout).
const UPSTREAM = RAW_UPSTREAM === undefined ? 'https://testnet.stellereum.org/api/faucet-public' : RAW_UPSTREAM.trim();
const UPSTREAM_TOKEN = process.env.UPSTREAM_FAUCET_TOKEN || '';
const WINDOW_ADDR_MS = Number(process.env.ADDR_WINDOW_MS || 45 * 60 * 1000);
const WINDOW_IP_MS = Number(process.env.IP_WINDOW_MS || 10 * 60 * 1000);
const UPSTREAM_TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS || 8000);

const app = express();
// Behind a proxy/load balancer set TRUST_PROXY (e.g. 1 or "loopback"). Default off
// so X-Forwarded-For cannot be spoofed when exposed directly.
app.set('trust proxy', process.env.TRUST_PROXY ? Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY : false);
app.disable('x-powered-by');
app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json({ limit: '8kb' }));

// Local guard rails (upstream enforces 5 STELL / address / 45 min as well).
// Entries are timestamped and pruned, so the maps stay bounded.
const byAddr = new Map<string, number>();
const byIp = new Map<string, number>();
const MAX_ENTRIES = 10_000;

function prune(map: Map<string, number>, windowMs: number) {
  if (map.size <= MAX_ENTRIES) return;
  const cutoff = Date.now() - windowMs;
  for (const [k, t] of map) if (t < cutoff) map.delete(k);
}

function isLimited(map: Map<string, number>, key: string, windowMs: number): boolean {
  const last = map.get(key) || 0;
  return Date.now() - last < windowMs;
}

function isHex64(s: string): boolean {
  const v = s.trim().toLowerCase().startsWith('0x') ? s.trim().slice(2) : s.trim();
  return /^[0-9a-fA-F]{64}$/.test(v);
}

function norm(s: string): string {
  const v = s.trim().toLowerCase();
  return v.startsWith('0x') ? v.slice(2) : v;
}

app.get('/status', (_req, res) => {
  res.json({ ok: true, mock: !UPSTREAM, drip: '5 STELL / address / 45 min' });
});

// Deeper check: pings upstream so the frontend can tell a real outage.
app.get('/healthz', async (_req, res) => {
  if (!UPSTREAM) return res.json({ ok: true, mock: true });
  try {
    const ctrl = AbortSignal.timeout(4000);
    const up = await fetch(UPSTREAM, { method: 'OPTIONS', signal: ctrl });
    // Any non-5xx answer means the upstream host is reachable (405/404 for OPTIONS).
    const healthy = up.status < 500;
    res.status(healthy ? 200 : 503).json({ ok: healthy, upstream: up.status });
  } catch {
    res.status(503).json({ ok: false, upstream: 'unreachable' });
  }
});

app.post('/drip', async (req, res) => {
  const address = String(req.body?.address || '').trim();
  if (!isHex64(address)) {
    res.status(400).json({ ok: false, message: 'Invalid address. Enter 64 hexadecimal characters (0-9, a-f).' });
    return;
  }
  const ip = String(req.ip || req.socket.remoteAddress || 'unknown');
  const addrKey = norm(address);

  prune(byAddr, WINDOW_ADDR_MS);
  prune(byIp, WINDOW_IP_MS);

  // Evaluate both limits WITHOUT mutating, so a rejected request never burns the other window.
  if (isLimited(byAddr, addrKey, WINDOW_ADDR_MS)) {
    res.status(429).json({ ok: false, message: 'Funds already sent to this address. Try again after 45 minutes.' });
    return;
  }
  if (isLimited(byIp, ip, WINDOW_IP_MS)) {
    res.status(429).json({ ok: false, message: 'Too many requests from this network. Try again in 10 minutes.' });
    return;
  }

  // Reserve the slots up-front so concurrent requests for the same address/IP
  // cannot slip past the window (TOCTOU). Released again on failure.
  byAddr.set(addrKey, Date.now());
  byIp.set(ip, Date.now());

  if (!UPSTREAM) {
    const fake = `${Date.now().toString(16)}${'ab'.repeat(32)}`.slice(0, 64);
    res.json({ ok: true, mock: true, txHash: fake, message: 'Demo payout (no real funds sent).' });
    return;
  }

  const release = () => {
    byAddr.delete(addrKey);
    byIp.delete(ip);
  };

  try {
    const headers: Record<string, string> = {};
    if (UPSTREAM_TOKEN) headers.authorization = `Bearer ${UPSTREAM_TOKEN}`;
    const ctrl = AbortSignal.timeout(UPSTREAM_TIMEOUT_MS);
    const up = await fetch(`${UPSTREAM.replace(/\/$/, '')}/${norm(address)}`, { method: 'POST', headers, signal: ctrl });
    const ct = up.headers.get('content-type') || '';
    const text = await up.text();
    let body: { txHash?: string; hash?: string; message?: string } = {};
    if (ct.includes('application/json')) {
      try {
        body = JSON.parse(text) as typeof body;
      } catch {
        body = {};
      }
    }
    const txHash = body.txHash || body.hash;
    if (!up.ok || !txHash) {
      console.error('faucet upstream failed', up.status, text.slice(0, 200));
      release();
      res.status(502).json({ ok: false, message: 'Faucet temporarily unavailable. Try again later.' });
      return;
    }
    // Slots already reserved above — keep them on success.
    res.json({ ok: true, txHash, message: 'Sent 5 STELL (testnet funds only).' });
  } catch (e) {
    console.error('faucet upstream unreachable', e instanceof Error ? e.message : e);
    release();
    res.status(502).json({ ok: false, message: 'Faucet temporarily unavailable. Try again later.' });
  }
});

// Terminal error handler — never leak stack traces to clients.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const status = typeof (err as { status?: number })?.status === 'number' ? (err as { status: number }).status : 500;
  console.error('unhandled error', status, err instanceof Error ? err.stack : err);
  res.status(status).json({ ok: false, message: status === 413 ? 'Payload too large.' : status === 400 ? 'Bad request.' : 'Server error.' });
});

const server = app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`faucet backend on :${PORT} (upstream=${UPSTREAM || 'mock'})`);
});

for (const sig of ['SIGTERM', 'SIGINT'] as const) {
  process.on(sig, () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  });
}
