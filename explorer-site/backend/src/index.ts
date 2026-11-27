import cors from 'cors';
import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_UPSTREAM_URL = 'https://testnet.stellereum.org/api/faucet-public';
const DEFAULT_WINDOW_ADDR_MS = 45 * 60 * 1000;
const DEFAULT_WINDOW_IP_MS = 10 * 60 * 1000;
const DEFAULT_UPSTREAM_TIMEOUT_MS = 8000;
const HEALTHZ_CACHE_TTL_MS = 5000;
const MAX_UPSTREAM_BODY_BYTES = 64 * 1024;
const MAX_ENTRIES = 10_000;

function resolveDefaultUpstream(raw: string | undefined): string {
  if (raw === undefined) return DEFAULT_UPSTREAM_URL;
  const trimmed = raw.trim();
  return trimmed === 'mock' ? '' : trimmed;
}

function parsePositiveMs(raw: string | number | undefined, fallback: number, name: string): number {
  if (raw === undefined) return fallback;
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (trimmed === '') return fallback;
    const n = Number(trimmed);
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error(`${name} must be a positive finite number of milliseconds`);
    }
    return n;
  }
  if (!Number.isFinite(raw) || raw <= 0) {
    throw new Error(`${name} must be a positive finite number of milliseconds`);
  }
  return raw;
}

function parsePositiveInt(raw: number | undefined, fallback: number, name: string): number {
  if (raw === undefined) return fallback;
  if (!Number.isSafeInteger(raw) || raw <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return raw;
}

function validateUpstreamUrl(upstream: string): string {
  const trimmed = upstream.trim();
  if (!trimmed) return '';
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`Invalid UPSTREAM_FAUCET_URL: ${trimmed}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(
      `Invalid UPSTREAM_FAUCET_URL scheme "${parsed.protocol}": must be http: or https:`,
    );
  }
  return trimmed;
}

export function parseTrustProxy(raw: string | undefined): boolean | number | string {
  if (raw === undefined) return false;
  const trimmed = raw.trim();
  if (!trimmed) return false;
  const lower = trimmed.toLowerCase();
  if (lower === 'false' || trimmed === '0') return false;
  if (lower === 'true') return true;
  if (/^-?\d+$/.test(trimmed)) {
    const n = Number(trimmed);
    return Number.isSafeInteger(n) && n > 0 ? n : false;
  }
  return trimmed;
}

function parseIpv4Parts(s: string): [number, number, number, number] | null {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  const nums: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    nums.push(n);
  }
  return [nums[0]!, nums[1]!, nums[2]!, nums[3]!];
}

function parseIpv6Groups(s: string): number[] | null {
  const doubleColonParts = s.split('::');
  if (doubleColonParts.length > 2) return null;

  const parseSide = (side: string, allowIpv4Tail: boolean): number[] | null => {
    if (!side) return [];
    const tokens = side.split(':');
    const out: number[] = [];
    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i]!;
      if (tok.includes('.')) {
        if (!allowIpv4Tail || i !== tokens.length - 1) return null;
        const ipv4 = parseIpv4Parts(tok);
        if (!ipv4) return null;
        out.push((ipv4[0] << 8) | ipv4[1], (ipv4[2] << 8) | ipv4[3]);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(tok)) return null;
        out.push(Number.parseInt(tok, 16));
      }
    }
    return out;
  };

  if (doubleColonParts.length === 1) {
    const groups = parseSide(doubleColonParts[0]!, true);
    if (!groups || groups.length !== 8) return null;
    return groups;
  }

  const left = parseSide(doubleColonParts[0]!, false);
  const right = parseSide(doubleColonParts[1]!, true);
  if (!left || !right) return null;
  const missing = 8 - (left.length + right.length);
  if (missing < 1) return null;
  return [...left, ...new Array<number>(missing).fill(0), ...right];
}

export function normalizeIp(rawIp: string): string {
  const trimmed = rawIp.trim();
  if (!trimmed) return 'unknown';
  const zoneIdx = trimmed.indexOf('%');
  const clean = zoneIdx >= 0 ? trimmed.slice(0, zoneIdx) : trimmed;

  const ipv4 = parseIpv4Parts(clean);
  if (ipv4) {
    return `${ipv4[0]}.${ipv4[1]}.${ipv4[2]}.${ipv4[3]}`;
  }

  if (clean.includes(':')) {
    const groups = parseIpv6Groups(clean);
    if (groups) {
      if (
        groups[0] === 0 &&
        groups[1] === 0 &&
        groups[2] === 0 &&
        groups[3] === 0 &&
        groups[4] === 0 &&
        groups[5] === 0xffff
      ) {
        const hi = groups[6]!;
        const lo = groups[7]!;
        return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
      }
      return `${groups[0]!.toString(16)}:${groups[1]!.toString(16)}:${groups[2]!.toString(16)}:${groups[3]!.toString(16)}::/64`;
    }
  }

  return clean.toLowerCase();
}

function pruneExpired(map: Map<string, number>, windowMs: number, now: number): void {
  const cutoff = now - windowMs;
  for (const [k, t] of map) {
    if (t <= cutoff) {
      map.delete(k);
    }
  }
}

function touchEntry(map: Map<string, number>, key: string, now: number): void {
  map.delete(key);
  map.set(key, now);
}

function isLimited(map: Map<string, number>, key: string, windowMs: number, now: number): boolean {
  const last = map.get(key);
  return last !== undefined && now - last < windowMs;
}

function formatWindowMinutes(windowMs: number): string {
  const mins = Math.max(1, Math.ceil(windowMs / 60_000));
  return `${mins} ${mins === 1 ? 'minute' : 'minutes'}`;
}

function isHex64(s: string): boolean {
  const trimmed = s.trim();
  const v = trimmed.toLowerCase().startsWith('0x') ? trimmed.slice(2) : trimmed;
  return /^[0-9a-fA-F]{64}$/.test(v);
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const STL57_CHECKSUM_DOMAIN = 'STELLEREUM_ADDRESS_CHECKSUM_V1';

const BLAKE3_IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const BLAKE3_MSG_SCHEDULE: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
  [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
  [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
  [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
  [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
  [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

const CHUNK_START = 1;
const CHUNK_END = 2;
const ROOT = 8;
const DERIVE_KEY_CONTEXT = 32;
const DERIVE_KEY_MATERIAL = 64;

function rotr32(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function blake3G(
  state: Uint32Array,
  a: number,
  b: number,
  c: number,
  d: number,
  mx: number,
  my: number,
): void {
  state[a] = (state[a]! + state[b]! + mx) >>> 0;
  state[d] = rotr32(state[d]! ^ state[a]!, 16);
  state[c] = (state[c]! + state[d]!) >>> 0;
  state[b] = rotr32(state[b]! ^ state[c]!, 12);
  state[a] = (state[a]! + state[b]! + my) >>> 0;
  state[d] = rotr32(state[d]! ^ state[a]!, 8);
  state[c] = (state[c]! + state[d]!) >>> 0;
  state[b] = rotr32(state[b]! ^ state[c]!, 7);
}

function blake3Compress(
  cv: Uint32Array,
  blockWords: Uint32Array,
  counter: bigint,
  blockLen: number,
  flags: number,
): Uint32Array {
  const state = new Uint32Array([
    cv[0]!, cv[1]!, cv[2]!, cv[3]!,
    cv[4]!, cv[5]!, cv[6]!, cv[7]!,
    BLAKE3_IV[0]!, BLAKE3_IV[1]!, BLAKE3_IV[2]!, BLAKE3_IV[3]!,
    Number(counter & 0xffff_ffffn),
    Number((counter >> 32n) & 0xffff_ffffn),
    blockLen >>> 0,
    flags >>> 0,
  ]);

  for (let round = 0; round < 7; round++) {
    const s = BLAKE3_MSG_SCHEDULE[round]!;
    blake3G(state, 0, 4, 8, 12, blockWords[s[0]!]!, blockWords[s[1]!]!);
    blake3G(state, 1, 5, 9, 13, blockWords[s[2]!]!, blockWords[s[3]!]!);
    blake3G(state, 2, 6, 10, 14, blockWords[s[4]!]!, blockWords[s[5]!]!);
    blake3G(state, 3, 7, 11, 15, blockWords[s[6]!]!, blockWords[s[7]!]!);
    blake3G(state, 0, 5, 10, 15, blockWords[s[8]!]!, blockWords[s[9]!]!);
    blake3G(state, 1, 6, 11, 12, blockWords[s[10]!]!, blockWords[s[11]!]!);
    blake3G(state, 2, 7, 8, 13, blockWords[s[12]!]!, blockWords[s[13]!]!);
    blake3G(state, 3, 4, 9, 14, blockWords[s[14]!]!, blockWords[s[15]!]!);
  }

  for (let i = 0; i < 8; i++) {
    state[i] = (state[i]! ^ state[i + 8]!) >>> 0;
    state[i + 8] = (state[i + 8]! ^ cv[i]!) >>> 0;
  }
  return state;
}

function bytesToWords16(block: Uint8Array): Uint32Array {
  const padded = new Uint8Array(64);
  padded.set(block.subarray(0, Math.min(64, block.length)));
  const view = new DataView(padded.buffer);
  const words = new Uint32Array(16);
  for (let i = 0; i < 16; i++) {
    words[i] = view.getUint32(i * 4, true);
  }
  return words;
}

function blake3DeriveKeySingleBlock(context: string, input: Uint8Array): Uint8Array {
  const ctxBytes = new TextEncoder().encode(context);
  if (ctxBytes.length > 64 || input.length > 64) {
    throw new RangeError('blake3DeriveKeySingleBlock supports <= 64 byte context and input');
  }
  const ctxOut = blake3Compress(
    BLAKE3_IV,
    bytesToWords16(ctxBytes),
    0n,
    ctxBytes.length,
    CHUNK_START | CHUNK_END | ROOT | DERIVE_KEY_CONTEXT,
  );
  const contextKey = ctxOut.subarray(0, 8);
  const matOut = blake3Compress(
    contextKey,
    bytesToWords16(input),
    0n,
    input.length,
    CHUNK_START | CHUNK_END | ROOT | DERIVE_KEY_MATERIAL,
  );
  const out = new Uint8Array(32);
  const view = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) {
    view.setUint32(i * 4, matOut[i]!, true);
  }
  return out;
}

function base58DecodeBytes(input: string): Uint8Array | null {
  if (input.length === 0) return new Uint8Array();
  let leadingZeros = 0;
  while (leadingZeros < input.length && input[leadingZeros] === '1') {
    leadingZeros += 1;
  }
  const bytes: number[] = [];
  for (let i = leadingZeros; i < input.length; i++) {
    const val = BASE58_ALPHABET.indexOf(input[i]!);
    if (val < 0) return null;
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const out = new Uint8Array(leadingZeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[leadingZeros + i] = bytes[bytes.length - 1 - i]!;
  }
  return out;
}

function base58EncodeBytes(input: Uint8Array): string {
  let leadingZeros = 0;
  while (leadingZeros < input.length && input[leadingZeros] === 0) {
    leadingZeros += 1;
  }
  const digits: number[] = [];
  for (let idx = leadingZeros; idx < input.length; idx++) {
    let carry = input[idx]!;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let out = '1'.repeat(leadingZeros);
  for (let i = digits.length - 1; i >= 0; i--) {
    out += BASE58_ALPHABET[digits[i]!]!;
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function encodeStl57(hexAddr: string): string {
  const clean = hexAddr.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error('encodeStl57 requires a 64-character hex address');
  }
  const addr = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    addr[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  const checksum = blake3DeriveKeySingleBlock(STL57_CHECKSUM_DOMAIN, addr).subarray(0, 4);
  const payload = new Uint8Array(36);
  payload.set(addr, 0);
  payload.set(checksum, 32);
  return `Stl57${base58EncodeBytes(payload)}`;
}

export function decodeStl57(addr: string): string | null {
  const v = addr.trim();
  if (v.slice(0, 5).toLowerCase() !== 'stl57') return null;
  const body = v.slice(5);
  if (!/^[1-9A-HJ-NP-Za-km-z]{35,51}$/.test(body)) return null;
  const decoded = base58DecodeBytes(body);
  if (!decoded || decoded.length !== 36) return null;
  const rawAddr = decoded.subarray(0, 32);
  const gotCheck = decoded.subarray(32, 36);
  const expectedCheck = blake3DeriveKeySingleBlock(STL57_CHECKSUM_DOMAIN, rawAddr).subarray(0, 4);
  let diff = 0;
  for (let i = 0; i < 4; i++) {
    diff |= gotCheck[i]! ^ expectedCheck[i]!;
  }
  if (diff !== 0) return null;
  return bytesToHex(rawAddr);
}

function isStl57(s: string): boolean {
  return decodeStl57(s) !== null;
}

export function isValidAddress(s: string): boolean {
  return isHex64(s) || isStl57(s);
}

export function norm(s: string): string {
  const decoded = decodeStl57(s);
  if (decoded !== null) return decoded;
  const lower = s.trim().toLowerCase();
  return lower.startsWith('0x') ? lower.slice(2) : lower;
}

export function extractTurnstileToken(
  body: unknown,
  headers: Record<string, string | string[] | undefined>,
): string | undefined {
  const b = body && typeof body === 'object' ? (body as Record<string, unknown>) : undefined;
  const bodyCandidates = [
    b?.cfTurnstileToken,
    b?.cf_turnstile_response,
    b?.['cf-turnstile-response'],
    b?.turnstile_token,
  ];
  for (const candidate of bodyCandidates) {
    if (typeof candidate === 'string') {
      const trimmed = candidate.trim();
      if (trimmed) return trimmed;
    }
  }

  const headerVal = headers['cf-turnstile-response'] ?? headers['CF-Turnstile-Response'];
  if (typeof headerVal === 'string') {
    const trimmed = headerVal.trim();
    if (trimmed) return trimmed;
  } else if (Array.isArray(headerVal)) {
    for (const item of headerVal) {
      if (typeof item === 'string') {
        const trimmed = item.trim();
        if (trimmed) return trimmed;
      }
    }
  }
  return undefined;
}

export function buildUpstreamRequestInit(opts: {
  turnstileToken?: string;
  upstreamToken?: string;
  signal: AbortSignal;
}): RequestInit {
  const headers: Record<string, string> = {};
  if (opts.upstreamToken) {
    headers.authorization = `Bearer ${opts.upstreamToken}`;
  }
  const init: RequestInit = {
    method: 'POST',
    headers,
    signal: opts.signal,
    redirect: 'error',
  };
  if (opts.turnstileToken) {
    headers['CF-Turnstile-Response'] = opts.turnstileToken;
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify({ cf_turnstile_response: opts.turnstileToken });
  }
  return init;
}

async function readResponseTextBounded(res: globalThis.Response, maxBytes: number): Promise<string> {
  const clHeader = res.headers.get('content-length');
  if (clHeader !== null) {
    const cl = Number(clHeader);
    if (Number.isFinite(cl) && cl > maxBytes) {
      await res.body?.cancel();
      throw new Error(`upstream response too large (${cl} > ${maxBytes} bytes)`);
    }
  }
  if (!res.body) {
    const text = await res.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) {
      throw new Error(`upstream response too large (> ${maxBytes} bytes)`);
    }
    return text;
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel();
          throw new Error(`upstream response too large (> ${maxBytes} bytes)`);
        }
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

export function parseUpstreamTxHash(text: string, contentType: string): string | undefined {
  let body: { tx_hash?: unknown; txHash?: unknown; hash?: unknown; message?: unknown } = {};
  if (contentType.includes('application/json') || text.trimStart().startsWith('{')) {
    try {
      const parsed: unknown = JSON.parse(text);
      if (parsed && typeof parsed === 'object') {
        body = parsed as typeof body;
      }
    } catch {
      body = {};
    }
  }
  const candidate = body.tx_hash || body.txHash || body.hash;
  return typeof candidate === 'string' && candidate.trim() ? candidate.trim() : undefined;
}

export interface FaucetAppConfig {
  corsOrigin?: string[];
  upstream?: string;
  upstreamToken?: string;
  windowAddrMs?: number;
  windowIpMs?: number;
  upstreamTimeoutMs?: number;
  maxEntries?: number;
  trustProxy?: boolean | number | string;
  dripAmountLabel?: string;
  dripLabel?: string;
  fetchFn?: typeof fetch;
}

export function createFaucetApp(config: FaucetAppConfig = {}): Express {
  const corsOrigin =
    config.corsOrigin ??
    (process.env.CORS_ORIGIN || 'http://localhost:5174')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  const upstream = validateUpstreamUrl(
    config.upstream !== undefined ? config.upstream : resolveDefaultUpstream(process.env.UPSTREAM_FAUCET_URL),
  );
  const upstreamToken = config.upstreamToken ?? (process.env.UPSTREAM_FAUCET_TOKEN || '');
  const windowAddrMs = parsePositiveMs(
    config.windowAddrMs !== undefined ? config.windowAddrMs : process.env.ADDR_WINDOW_MS,
    DEFAULT_WINDOW_ADDR_MS,
    'ADDR_WINDOW_MS',
  );
  const windowIpMs = parsePositiveMs(
    config.windowIpMs !== undefined ? config.windowIpMs : process.env.IP_WINDOW_MS,
    DEFAULT_WINDOW_IP_MS,
    'IP_WINDOW_MS',
  );
  const upstreamTimeoutMs = parsePositiveMs(
    config.upstreamTimeoutMs !== undefined
      ? config.upstreamTimeoutMs
      : process.env.UPSTREAM_TIMEOUT_MS,
    DEFAULT_UPSTREAM_TIMEOUT_MS,
    'UPSTREAM_TIMEOUT_MS',
  );
  const maxEntries = parsePositiveInt(config.maxEntries, MAX_ENTRIES, 'maxEntries');
  const trustProxy =
    config.trustProxy !== undefined
      ? config.trustProxy
      : parseTrustProxy(process.env.TRUST_PROXY);
  const dripAmountLabel =
    (config.dripAmountLabel ?? process.env.DRIP_AMOUNT_LABEL ?? '2 STELL').trim() || '2 STELL';
  const addrMinutesNum = Math.max(1, Math.ceil(windowAddrMs / 60_000));
  const defaultDripLabel = `${dripAmountLabel} / address / ${addrMinutesNum} min`;
  const dripLabel =
    (config.dripLabel ?? process.env.DRIP_LABEL ?? defaultDripLabel).trim() || defaultDripLabel;
  const fetchFn = config.fetchFn ?? fetch;

  const app = express();
  // Behind a proxy/load balancer set TRUST_PROXY (e.g. 1, "true", or "loopback"). Default off
  // so X-Forwarded-For cannot be spoofed when exposed directly.
  app.set('trust proxy', trustProxy);
  app.disable('x-powered-by');
  app.use(cors({ origin: corsOrigin }));
  app.use(express.json({ limit: '8kb' }));

  // Local guard rails (upstream enforces address window as well).
  // Entries are timestamped in LRU order; expired entries are purged, and active
  // saturation rejects uncached entries with 503 instead of evicting rate limits.
  const byAddr = new Map<string, number>();
  const byIp = new Map<string, number>();

  let healthzCache: { expiresAt: number; status: number; body: Record<string, unknown> } | null =
    null;
  let healthzInflight: Promise<{ status: number; body: Record<string, unknown> }> | null = null;

  app.get('/status', (_req, res) => {
    res.json({ ok: true, mock: !upstream, drip: dripLabel });
  });

  // Deeper check: pings upstream (cached for 5s) so the frontend can tell a real outage.
  app.get('/healthz', async (_req, res) => {
    if (!upstream) {
      res.json({ ok: true, mock: true });
      return;
    }
    const now = Date.now();
    if (healthzCache && now < healthzCache.expiresAt) {
      res.status(healthzCache.status).json(healthzCache.body);
      return;
    }
    if (!healthzInflight) {
      healthzInflight = (async () => {
        try {
          const ctrl = AbortSignal.timeout(Math.min(4000, upstreamTimeoutMs));
          const up = await fetchFn(upstream, {
            method: 'OPTIONS',
            signal: ctrl,
            redirect: 'error',
          });
          await up.body?.cancel();
          // Any non-5xx answer means the upstream host is reachable (405/404 for OPTIONS).
          const healthy = up.status < 500;
          return {
            status: healthy ? 200 : 503,
            body: { ok: healthy, upstream: up.status },
          };
        } catch {
          return {
            status: 503,
            body: { ok: false, upstream: 'unreachable' },
          };
        }
      })().finally(() => {
        healthzInflight = null;
      });
    }
    const result = await healthzInflight;
    healthzCache = {
      expiresAt: Date.now() + HEALTHZ_CACHE_TTL_MS,
      status: result.status,
      body: result.body,
    };
    res.status(result.status).json(result.body);
  });

  app.post('/drip', async (req, res) => {
    const rawAddr =
      req.body &&
      typeof req.body === 'object' &&
      !Array.isArray(req.body) &&
      typeof (req.body as Record<string, unknown>).address === 'string'
        ? (req.body as Record<string, string>).address.trim()
        : '';
    if (!isValidAddress(rawAddr)) {
      res
        .status(400)
        .json({ ok: false, message: 'Invalid address. Enter 64 hex chars or an Stl57... address.' });
      return;
    }
    const ip = normalizeIp(String(req.ip || req.socket.remoteAddress || 'unknown'));
    const addrKey = norm(rawAddr);
    const now = Date.now();

    if (byAddr.size >= maxEntries) pruneExpired(byAddr, windowAddrMs, now);
    if (byIp.size >= maxEntries) pruneExpired(byIp, windowIpMs, now);

    // Evaluate both limits WITHOUT mutating, so a rejected request never burns the other window.
    if (isLimited(byAddr, addrKey, windowAddrMs, now)) {
      res.status(429).json({
        ok: false,
        message: `Funds already sent to this address. Try again after ${formatWindowMinutes(windowAddrMs)}.`,
      });
      return;
    }
    if (isLimited(byIp, ip, windowIpMs, now)) {
      res.status(429).json({
        ok: false,
        message: `Too many requests from this network. Try again in ${formatWindowMinutes(windowIpMs)}.`,
      });
      return;
    }

    if ((!byAddr.has(addrKey) && byAddr.size >= maxEntries) || (!byIp.has(ip) && byIp.size >= maxEntries)) {
      res.status(503).json({
        ok: false,
        message: 'Rate limiter capacity reached, try later.',
      });
      return;
    }

    // Reserve the slots up-front (true LRU via delete-before-set) so concurrent requests
    // for the same address/IP cannot slip past the window (TOCTOU). Released on failure.
    touchEntry(byAddr, addrKey, now);
    touchEntry(byIp, ip, now);

    if (!upstream) {
      const fake = `${now.toString(16)}${'ab'.repeat(32)}`.slice(0, 64);
      res.json({ ok: true, mock: true, txHash: fake, message: 'Demo payout (no real funds sent).' });
      return;
    }

    const release = () => {
      byAddr.delete(addrKey);
      byIp.delete(ip);
    };

    try {
      const turnstileToken = extractTurnstileToken(req.body, req.headers);
      const ctrl = AbortSignal.timeout(upstreamTimeoutMs);
      const init = buildUpstreamRequestInit({
        turnstileToken,
        upstreamToken,
        signal: ctrl,
      });
      const up = await fetchFn(`${upstream.replace(/\/$/, '')}/${addrKey}`, init);
      const ct = up.headers.get('content-type') || '';
      const text = await readResponseTextBounded(up, MAX_UPSTREAM_BODY_BYTES);
      const txHash = parseUpstreamTxHash(text, ct);
      if (!up.ok || !txHash) {
        console.error('faucet upstream failed', up.status, text.slice(0, 200));
        release();
        res
          .status(502)
          .json({ ok: false, message: 'Faucet temporarily unavailable. Try again later.' });
        return;
      }
      // Slots already reserved above — keep them on success.
      res.json({ ok: true, txHash, message: `Sent ${dripAmountLabel} (testnet funds only).` });
    } catch (e) {
      console.error('faucet upstream unreachable', e instanceof Error ? e.message : e);
      release();
      res
        .status(502)
        .json({ ok: false, message: 'Faucet temporarily unavailable. Try again later.' });
    }
  });

  // Terminal error handler — never leak stack traces to clients.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const status =
      typeof (err as { status?: number })?.status === 'number'
        ? (err as { status: number }).status
        : 500;
    console.error('unhandled error', status, err instanceof Error ? err.stack : err);
    res.status(status).json({
      ok: false,
      message:
        status === 413
          ? 'Payload too large.'
          : status === 400
            ? 'Bad request.'
            : 'Server error.',
    });
  });

  return app;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const port = Number(process.env.PORT || 8787);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid PORT: ${process.env.PORT}`);
  }
  const app = createFaucetApp();
  const server = app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(
      `faucet backend on :${port} (upstream=${resolveDefaultUpstream(process.env.UPSTREAM_FAUCET_URL) || 'mock'})`,
    );
  });

  for (const sig of ['SIGTERM', 'SIGINT'] as const) {
    process.on(sig, () => {
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 5000).unref();
    });
  }
}
