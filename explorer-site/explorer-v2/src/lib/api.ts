import {
  Block,
  Transaction,
  Validator,
  NetworkStats,
  AccountInfo,
  ContractEvent,
  ContractSummary,
  ShardTopology,
  LiveValidatorSet,
  TxOutcome,
} from '../types';

const API_BASE = window.location.origin.includes('stellereum.org')
  ? 'https://explorer.stellereum.org/api/v2'
  : '/api/v2';

// The node's JSON-RPC endpoint. The explorer prefers the INDEXER for
// chain-shaped reads (it has the history) and the NODE for the chain-shaped
// reads the indexer cannot answer honestly (the LIVE validator set, the shard
// topology).
const RPC_BASE =
  (import.meta as unknown as { env?: Record<string, string> }).env?.VITE_STELL_RPC ||
  (window.location.origin.includes('stellereum.org')
    ? 'https://rpc.stellereum.org'
    : '/rpc');

/**
 * A non-2xx answer from the indexer or the RPC.
 *
 * The pages need the STATUS to tell "not indexed yet" (404) from "the service
 * is down" (5xx), so the status travels with the error instead of only a
 * stringified message.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly url: string;

  constructor(status: number, url: string, message?: string) {
    super(message ?? `HTTP ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.url = url;
  }
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: { 'Accept': 'application/json' } });
  if (!res.ok) {
    throw new ApiError(res.status, url, `API error ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

/** The indexer answers with decimal or `0x`-hex integer quantities. */
function hexToNumber(v: unknown): number {
  if (typeof v === 'number') return Number.isFinite(v) ? v : 0;
  if (typeof v === 'string') {
    const s = v.trim();
    if (!s) return 0;
    const n = s.startsWith('0x') || s.startsWith('0X') ? Number.parseInt(s, 16) : Number(s);
    return Number.isFinite(n) ? n : 0;
  }
  return 0;
}

const MAX_SAFE_BI = BigInt(Number.MAX_SAFE_INTEGER);
const MIN_SAFE_BI = BigInt(Number.MIN_SAFE_INTEGER);

/**
 * Parse a nano-STELL quantity (decimal integer string, `0x` hex fallback, or
 * number) without losing precision when the integer exceeds MAX_SAFE_INTEGER.
 */
function toNanoAmount(v: unknown): number | string {
  if (typeof v === 'number') return Number.isFinite(v) ? v : 0;
  if (typeof v === 'string') {
    const s = v.trim();
    if (!s) return 0;
    if (/^-?0x[0-9a-fA-F]+$/i.test(s) || /^-?\d+$/.test(s)) {
      try {
        const bi = s.startsWith('-0x') || s.startsWith('-0X') ? -BigInt(s.slice(1)) : BigInt(s);
        if (bi >= MIN_SAFE_BI && bi <= MAX_SAFE_BI) {
          return Number(bi);
        }
        return bi.toString();
      } catch {
        return 0;
      }
    }
    const n = Number(s);
    return Number.isFinite(n) ? n : 0;
  }
  return 0;
}

function asArray<T>(v: unknown): T[] {
  return Array.isArray(v) ? (v as T[]) : [];
}

/**
 * One block, normalized.
 *
 * The indexer serves `{hash, height, ...}` (and `proposer: null` while the
 * chain is stalled); the UI reads `block_hash` and always renders the
 * proposer through a null-tolerant formatter — so normalize here, once.
 */
function toBlock(raw: any): Block {
  const b = raw && typeof raw === 'object' ? raw : {};
  return {
    height: hexToNumber(b.height ?? 0),
    block_hash: b.block_hash || b.hash || '',
    tx_count: hexToNumber(b.tx_count ?? 0),
    timestamp: hexToNumber(b.timestamp ?? 0),
    shard_id: hexToNumber(b.shard_id ?? b.shardId ?? 0),
    proposer: b.proposer || b.proposer_stl57 || '',
    proposer_stl57: b.proposer_stl57 || undefined,
    state_root: b.state_root ?? undefined,
    prev_hash: b.prev_hash ?? b.prevHash ?? undefined,
    size: b.size ?? undefined,
  };
}

/**
 * One transaction, normalized.
 *
 * The indexer serves `{tx_hash, amount: "1000000000" | "0x..", fee_charged,
 * gas_limit, ...}`; the UI reads `hash`, `amount`/`fee` (preserving full
 * precision on large nano-STELL strings) and always renders addresses through
 * null-tolerant formatters.
 */
function toTransaction(raw: any): Transaction {
  const t = raw && typeof raw === 'object' ? raw : {};
  return {
    hash: t.hash || t.tx_hash || '',
    block_height: hexToNumber(t.block_height ?? 0),
    from_addr: t.from_addr || t.from || '',
    from_stl57: t.from_stl57 || undefined,
    to_addr: t.to_addr || t.to || '',
    to_stl57: t.to_stl57 || undefined,
    amount: toNanoAmount(t.amount ?? 0),
    gas_limit: hexToNumber(t.gas_limit ?? 0),
    gas_used: hexToNumber(t.gas_used ?? t.gas ?? 0),
    fee: toNanoAmount(t.fee ?? t.fee_charged ?? 0),
    nonce: hexToNumber(t.nonce ?? 0),
    status: t.status === 'failed' || t.status === 'pending' ? t.status : 'success',
    timestamp: hexToNumber(t.timestamp ?? 0),
    source_shard: hexToNumber(t.source_shard ?? t.sourceShard ?? 0),
    target_shard: hexToNumber(t.target_shard ?? t.targetShard ?? 0),
    payload_opcodes: Array.isArray(t.payload_opcodes) ? t.payload_opcodes : undefined,
    signature_scheme: t.signature_scheme ?? undefined,
  };
}

/** One JSON-RPC call against the node. */
export async function rpcCall<T = unknown>(method: string, params: unknown = {}): Promise<T> {
  const res = await fetch(RPC_BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (!res.ok) {
    throw new ApiError(res.status, RPC_BASE, `RPC error ${res.status}: ${res.statusText}`);
  }
  const body = await res.json();
  if (body && body.error) {
    throw new Error(body.error.message || 'RPC error');
  }
  return body.result as T;
}

export async function getStats(): Promise<NetworkStats> {
  return fetchJson<NetworkStats>(`${API_BASE}/stats`);
}

export async function getLatestBlocks(limit = 12): Promise<Block[]> {
  const raw = await fetchJson<any>(`${API_BASE}/blocks?limit=${limit}`);
  // The indexer wraps the list: `{blocks: [...], limit, offset}`.
  const list = Array.isArray(raw) ? raw : raw?.blocks;
  return asArray<any>(list).map(toBlock);
}

export async function getBlock(hashOrHeight: string | number): Promise<Block> {
  const raw = await fetchJson<any>(`${API_BASE}/block/${encodeURIComponent(String(hashOrHeight))}`);
  // The indexer wraps the block: `{block: {...}, transactions: [...]}`.
  const b = raw?.block ?? raw;
  const block = toBlock(b);
  const txs = raw?.transactions;
  if (Array.isArray(txs)) {
    (block as any).transactions = txs.map(toTransaction);
  }
  return block;
}

export async function getLatestTransactions(limit = 12): Promise<Transaction[]> {
  const raw = await fetchJson<any>(`${API_BASE}/txs?limit=${limit}`);
  // The indexer wraps the list: `{transactions: [...], limit, offset}`.
  const list = Array.isArray(raw) ? raw : raw?.transactions;
  return asArray<any>(list).map(toTransaction);
}

export async function getTransaction(hash: string): Promise<Transaction> {
  const raw = await fetchJson<any>(`${API_BASE}/tx/${encodeURIComponent(hash)}`);
  // Accept `{transaction: {...}}` (indexer v2), `{tx: {...}}`, `{result: {...}}`, or bare shape.
  return toTransaction(raw?.transaction ?? raw?.tx ?? raw?.result ?? raw);
}

export async function getValidators(): Promise<{ validators: Validator[]; limits: any; round: any }> {
  const raw = await fetchJson<any>(`${API_BASE}/validators`);
  // The indexer answers `{validators, limits, round}` — but never trust the
  // list to actually be a list (a stalled chain may answer `null`).
  return {
    validators: asArray<Validator>(raw?.validators),
    limits: raw?.limits ?? null,
    round: raw?.round ?? null,
  };
}

/**
 * The LIVE validator set, read from the node's `stell_getValidators`.
 *
 * The indexer's `/api/v2/validators` is a static snapshot, so it is only used
 * as a FALLBACK — and the page labels which source it is showing.
 */
export async function getLiveValidators(): Promise<LiveValidatorSet> {
  return rpcCall<LiveValidatorSet>('stell_getValidators', {});
}

/** The bonded stake of one validator (`stell_stakeOf`). */
export async function getLiveStakeOf(validator: string): Promise<{
  total: string;
  self_bond: string;
  delegated: string;
}> {
  return rpcCall('stell_stakeOf', { validator });
}

export async function getAccount(address: string): Promise<AccountInfo> {
  const raw = await fetchJson<any>(`${API_BASE}/account/${encodeURIComponent(address)}`);
  // The indexer answers `{address, status, stl57, tx_count}` — no balance or
  // nonce. Map what exists; the page renders `0` for the rest, never blank.
  return {
    address: raw?.address || raw?.stl57 || address,
    address_stl57: raw?.address_stl57 || raw?.stl57 || (address.startsWith('Stl57') ? address : ''),
    balance: toNanoAmount(raw?.balance ?? 0),
    nonce: hexToNumber(raw?.nonce ?? 0),
    tx_count: hexToNumber(raw?.tx_count ?? 0),
    is_contract: Boolean(raw?.is_contract ?? false),
    staked_amount: raw?.staked_amount !== undefined ? toNanoAmount(raw.staked_amount) : undefined,
    reward_balance: raw?.reward_balance !== undefined ? toNanoAmount(raw.reward_balance) : undefined,
  };
}

export async function getAccountTransactions(address: string, limit = 25): Promise<Transaction[]> {
  const raw = await fetchJson<any>(`${API_BASE}/account/${encodeURIComponent(address)}/txs?limit=${limit}`);
  // The indexer wraps the list: `{actions: [...], address, limit, offset}`.
  const list = Array.isArray(raw) ? raw : raw?.actions ?? raw?.transactions;
  return asArray<any>(list).map(toTransaction);
}

export async function search(q: string): Promise<{ type: 'block' | 'tx' | 'address' | 'unknown'; value: any }> {
  const raw = await fetchJson<any>(`${API_BASE}/search?q=${encodeURIComponent(q.trim())}`);
  // The indexer answers `{result, type: 'block'}` for blocks,
  // `{result, type: 'tx' | 'transaction'}` for txs, and
  // `{address, stl57, type: 'account'}` for accounts — unify all.
  const type = raw?.type === 'block' ? 'block'
    : raw?.type === 'tx' || raw?.type === 'transaction' ? 'tx'
    : raw?.type === 'address' || raw?.type === 'account' ? 'address'
    : 'unknown';
  return { type, value: raw?.value ?? raw?.result ?? raw };
}

// ---------------------------------------------------------------------------
// Contract events
// ---------------------------------------------------------------------------

export interface EventsQuery {
  contract?: string;
  txHash?: string;
  fromBlock?: number;
  toBlock?: number;
  limit?: number;
  offset?: number;
}

export interface EventsPage {
  events: ContractEvent[];
  count: number;
  total?: number;
  limit?: number;
  offset?: number;
}

/** The events of one transaction (`GET /api/v2/tx/:hash/events`). */
export async function getTxEvents(hash: string): Promise<EventsPage> {
  const page = await fetchJson<any>(`${API_BASE}/tx/${encodeURIComponent(hash)}/events`);
  return { ...page, events: asArray<ContractEvent>(page?.events) };
}

/** The events of one contract (`GET /api/v2/contract/:address/events`). */
export async function getContractEvents(address: string, limit = 50, offset = 0): Promise<EventsPage> {
  const page = await fetchJson<any>(`${API_BASE}/contract/${encodeURIComponent(address)}/events?limit=${limit}&offset=${offset}`);
  return { ...page, events: asArray<ContractEvent>(page?.events) };
}

/** The filtered event feed (`GET /api/v2/events`). */
export async function getEvents(q: EventsQuery = {}): Promise<EventsPage> {
  const p = new URLSearchParams();
  if (q.contract) p.set('contract', q.contract);
  if (q.fromBlock !== undefined) p.set('from_block', String(q.fromBlock));
  if (q.toBlock !== undefined) p.set('to_block', String(q.toBlock));
  p.set('limit', String(q.limit ?? 50));
  p.set('offset', String(q.offset ?? 0));
  const page = await fetchJson<any>(`${API_BASE}/events?${p.toString()}`);
  return { ...page, events: asArray<ContractEvent>(page?.events) };
}

/** The contracts that emitted at least one indexed event. */
export async function getContracts(limit = 50, offset = 0): Promise<{
  contracts: ContractSummary[];
  count: number;
  total: number;
  limit: number;
  offset: number;
}> {
  const page = await fetchJson<any>(`${API_BASE}/contracts?limit=${limit}&offset=${offset}`);
  return { ...page, contracts: asArray<ContractSummary>(page?.contracts) };
}

/**
 * The ABI manifest of a contract, from the node's `stell_getContractAbi`.
 *
 * The manifest is committed to the state trie next to the code hash, so every
 * node serves the SAME one — the explorer and the contract agree by
 * construction.
 */
export async function getContractAbi(contract: string): Promise<{
  contract: string;
  contract_stl57?: string;
  abi: any;
  abi_json?: string;
} | null> {
  return rpcCall('stell_getContractAbi', { contract });
}

// ---------------------------------------------------------------------------
// Shards
// ---------------------------------------------------------------------------

/**
 * The shard topology.
 *
 * The indexer proxies the node's `stell_getShards` (`GET /api/v2/shards`), so
 * the explorer never has to guess the layout; when the proxy is unavailable
 * the RPC is asked directly.
 */
function normalizeShardTopology(topo: ShardTopology): ShardTopology {
  return {
    ...topo,
    total_shards: hexToNumber(topo.total_shards ?? topo.shards.length),
    routing_prefix_bits: hexToNumber(topo.routing_prefix_bits ?? 0),
    shards: topo.shards.map((s: any) => {
      const shardId = hexToNumber(s?.shard_id ?? s?.shardId ?? 0);
      return {
        ...s,
        shard_id: shardId,
        tip_height: hexToNumber(s?.tip_height ?? s?.tipHeight ?? 0),
        type: s?.type || (shardId === 0 ? 'masterchain' : 'workchain'),
      };
    }),
  };
}

export async function getShards(): Promise<ShardTopology> {
  try {
    const topo = await fetchJson<ShardTopology>(`${API_BASE}/shards`);
    if (topo && Array.isArray(topo.shards)) {
      return normalizeShardTopology(topo);
    }
    throw new Error('indexer answered without a shards list');
  } catch (err) {
    // fall through to the node — but only when the indexer failed, so a
    // malformed indexer answer never silently becomes an empty page
    try {
      const topo = await rpcCall<ShardTopology>('stell_getShards', {});
      if (topo && Array.isArray((topo as any).shards)) {
        return normalizeShardTopology(topo);
      }
      throw new Error('node answered without a shards list');
    } catch {
      throw err;
    }
  }
}

// ---------------------------------------------------------------------------
// Transaction outcome
// ---------------------------------------------------------------------------

/**
 * The OUTCOME of a transaction: the contract call's return value, the gas it
 * consumed and the events it emitted.
 *
 * The indexer serves the events; the node's `stell_getTransactionReceipt`
 * serves the return value and the gas used. Both are optional: a transaction
 * that is not a contract call simply has neither.
 */
export async function getTxOutcome(hash: string): Promise<TxOutcome> {
  const outcome: TxOutcome = { events: [], source: [] };

  // The node's receipt carries the return value, the gas used and the events.
  try {
    const receipt = await rpcCall<any>('stell_getTransactionReceipt', { hash });
    if (receipt && receipt.status && receipt.status !== 'unknown') {
      outcome.return_value = receipt.return_value ?? null;
      outcome.gas_used = receipt.gas_used ?? null;
      outcome.fee_charged = receipt.fee_charged ?? null;
      outcome.status = receipt.status;
      outcome.contract_address = receipt.contract_address ?? null;
      if (Array.isArray(receipt.events) && receipt.events.length > 0) {
        outcome.events = receipt.events.map((e: any) => ({
          contract: e.contract,
          contract_stl57: e.contract_stl57,
          topic: e.topic,
          value: e.value,
        }));
        outcome.source.push('rpc');
      }
    }
  } catch {
    // the node may be unreachable; the indexer still has the events
  }

  // The indexer has the DECODED events (ABI-resolved names and fields).
  try {
    const page = await getTxEvents(hash);
    if (page && Array.isArray(page.events) && page.events.length > 0) {
      outcome.events = page.events;
      outcome.source = ['indexer'];
      outcome.total_events = page.total;
    }
  } catch {
    // no indexed events for this transaction
  }

  return outcome;
}
