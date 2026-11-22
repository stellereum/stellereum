/**
 * EVM intent decoding and the canonical EVM↔PQ binding digest.
 *
 * ## What this file does NOT do
 *
 * It does not recover a secp256k1 sender and it does not verify the EVM
 * signature. JavaScript has no audited recoverable-secp256k1 primitive in
 * this repository, and adding one would be a second, unaudited crypto
 * implementation. The fields a builder must bind EXACTLY (chain id, nonce,
 * recipient, value, calldata shape) are decoded here; the node re-verifies
 * the secp256k1 signature over the same bytes and the Rust signer/parity
 * suite cover the recovery path.
 */

import { bytesToHex, hexToBytes } from "./wire.ts";

export const EVM_BINDING_PROOF_LEN = 65;
export const EVM_BINDING_DOMAIN = new TextEncoder().encode("STELL_EVM_BIND_V1");
export const WEI_PER_NANO = 1_000_000_000n;
export const MAX_EVM_RAW_TX_BYTES = 128 * 1024;
export const EVM_CARRIER_MIN_GAS = 700_000;
export const EVM_BINDING_MIN_GAS = 600_000;

export const EVM_CONTRACT_EXECUTION_REFUSAL =
  "EVM contract calls and contract creation are not settled by this chain: it has no EVM " +
  "interpreter and no EVM state trie, so executing bytecode here would be a lie. Only " +
  "value transfers (empty calldata, an existing recipient) are carried; deploy and call " +
  "contracts with the native SVM (stell_deployContract / stell_callContract).";

// ============================================================================
// Keccak-256 (the EVM hash; NOT SHA3-256)
// ============================================================================

const KECCAK_ROUND_CONSTANTS: readonly bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

/** Rotation offset for lane (x, y), indexed x + 5y. */
const KECCAK_ROTATIONS: readonly number[] = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];

const MASK64 = (1n << 64n) - 1n;

function rotl64(value: bigint, shift: number): bigint {
  const s = BigInt(shift % 64);
  if (s === 0n) return value & MASK64;
  return ((value << s) | (value >> (64n - s))) & MASK64;
}

function keccakF1600(state: bigint[]): void {
  for (let round = 0; round < 24; round++) {
    const c: bigint[] = new Array(5);
    for (let x = 0; x < 5; x++) {
      c[x] = state[x]! ^ state[x + 5]! ^ state[x + 10]! ^ state[x + 15]! ^ state[x + 20]!;
    }
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5]! ^ rotl64(c[(x + 1) % 5]!, 1);
      for (let y = 0; y < 25; y += 5) state[x + y] = state[x + y]! ^ d;
    }
    const b: bigint[] = new Array(25).fill(0n);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const idx = x + 5 * y;
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[idx]!, KECCAK_ROTATIONS[idx]!);
      }
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const i = x + 5 * y;
        state[i] = (b[i]! ^ ((~b[(x + 1) % 5 + 5 * y]! & b[(x + 2) % 5 + 5 * y]!) & MASK64)) & MASK64;
      }
    }
    state[0] = state[0]! ^ KECCAK_ROUND_CONSTANTS[round]!;
  }
}

/** keccak256(data) — the EVM hash, domain-separate from SHA3-256. */
export function keccak256(data: Uint8Array): Uint8Array {
  const rate = 136;
  const padded = new Uint8Array(Math.ceil((data.length + 1) / rate) * rate);
  padded.set(data);
  padded[data.length] = padded[data.length]! ^ 0x01;
  padded[padded.length - 1] = padded[padded.length - 1]! ^ 0x80;

  const state: bigint[] = new Array(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) {
        lane = (lane << 8n) | BigInt(padded[offset + i * 8 + j]!);
      }
      state[i] = state[i]! ^ lane;
    }
    keccakF1600(state);
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = state[i]!;
    for (let j = 0; j < 8; j++) {
      out[i * 8 + j] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}

/** `keccak256("STELL_EVM_BIND_V1" || chain_id_be || evm || pq)` (32 bytes). */
export function bindingMessage(chainId: number, evm: Uint8Array, pq: Uint8Array): Uint8Array {
  if (evm.length !== 20) throw new Error(`evm address must be 20 bytes, got ${evm.length}`);
  if (pq.length !== 32) throw new Error(`pq address must be 32 bytes, got ${pq.length}`);
  const buf = new Uint8Array(EVM_BINDING_DOMAIN.length + 8 + 20 + 32);
  let offset = 0;
  buf.set(EVM_BINDING_DOMAIN, offset);
  offset += EVM_BINDING_DOMAIN.length;
  new DataView(buf.buffer).setBigUint64(offset, BigInt(chainId), false);
  offset += 8;
  buf.set(evm, offset);
  offset += 20;
  buf.set(pq, offset);
  return keccak256(buf);
}

// ============================================================================
// RLP (the strict subset an EVM transaction needs)
// ============================================================================

type RlpItem = { kind: "bytes"; value: Uint8Array } | { kind: "list"; value: RlpItem[] };

function rlpDecode(input: Uint8Array): RlpItem {
  const [item, rest] = rlpDecodeWithRest(input, 0);
  if (rest.length !== 0) throw new Error("rlp: trailing bytes");
  return item;
}

function rlpDecodeWithRest(input: Uint8Array, depth: number): [RlpItem, Uint8Array] {
  if (depth > 64) throw new Error("rlp: nesting depth exceeded");
  if (input.length === 0) throw new Error("rlp: unexpected end of input");
  const first = input[0]!;
  if (first < 0x80) return [{ kind: "bytes", value: input.slice(0, 1) }, input.slice(1)];
  if (first <= 0xb7) {
    const len = first - 0x80;
    const payload = take(input, 1, len);
    if (len === 1 && payload[0]! < 0x80) throw new Error("rlp: non-canonical single byte");
    return [{ kind: "bytes", value: payload }, input.slice(1 + len)];
  }
  if (first <= 0xbf) {
    const lenOfLen = first - 0xb7;
    const len = readLength(input, 1, lenOfLen);
    if (len < 56) throw new Error("rlp: non-canonical long string length");
    return [{ kind: "bytes", value: take(input, 1 + lenOfLen, len) }, input.slice(1 + lenOfLen + len)];
  }
  if (first <= 0xf7) {
    const len = first - 0xc0;
    return [{ kind: "list", value: rlpDecodeList(take(input, 1, len), depth + 1) }, input.slice(1 + len)];
  }
  const lenOfLen = first - 0xf7;
  const len = readLength(input, 1, lenOfLen);
  if (len < 56) throw new Error("rlp: non-canonical long list length");
  return [
    { kind: "list", value: rlpDecodeList(take(input, 1 + lenOfLen, len), depth + 1) },
    input.slice(1 + lenOfLen + len),
  ];
}

function rlpDecodeList(payload: Uint8Array, depth: number): RlpItem[] {
  const items: RlpItem[] = [];
  let rest = payload;
  while (rest.length > 0) {
    const [item, next] = rlpDecodeWithRest(rest, depth);
    items.push(item);
    rest = next;
  }
  return items;
}

function take(input: Uint8Array, offset: number, len: number): Uint8Array {
  const end = offset + len;
  if (end > input.length) throw new Error("rlp: unexpected end of input");
  return input.slice(offset, end);
}

function readLength(input: Uint8Array, offset: number, lenOfLen: number): number {
  if (lenOfLen === 0 || lenOfLen > 8) throw new Error("rlp: invalid length-of-length");
  const bytes = take(input, offset, lenOfLen);
  if (bytes[0] === 0) throw new Error("rlp: leading zero in length");
  let len = 0;
  for (const b of bytes) len = len * 256 + b;
  if (!Number.isSafeInteger(len)) throw new Error("rlp: length overflow");
  return len;
}

function asBytes(item: RlpItem, field: string): Uint8Array {
  if (item.kind !== "bytes") throw new Error(`rlp: ${field} must be a byte string`);
  return item.value;
}

function asNumber(item: RlpItem, field: string): number {
  const bytes = asBytes(item, field);
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`rlp: ${field} exceeds 2^53`);
  return Number(value);
}

function asBigInt(item: RlpItem, field: string): bigint {
  const bytes = asBytes(item, field);
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  return value;
}

/** The value-transfer facts a carrier binds. Sender recovery is node-side. */
export interface EvmIntentFacts {
  chainId: number;
  nonce: number;
  gasLimit: number;
  to: string;
  valueWei: bigint;
  valueNano: number;
  dataHex: string;
}

/** Decode an EIP-155 / EIP-1559 value-transfer intent. */
export function decodeEvmIntent(raw: Uint8Array): EvmIntentFacts {
  if (raw.length === 0 || raw.length > MAX_EVM_RAW_TX_BYTES) {
    throw new Error("invalid EVM intent: empty or oversized transaction");
  }
  if (raw[0] === 0x02) {
    const item = rlpDecode(raw.slice(1));
    if (item.kind !== "list" || item.value.length !== 12) {
      throw new Error("invalid EVM intent: EIP-1559 payload must be a 12-field list");
    }
    const items = item.value;
    const chainId = asNumber(items[0]!, "chainId");
    const nonce = asNumber(items[1]!, "nonce");
    const gasLimit = asNumber(items[4]!, "gasLimit");
    const toBytes = asBytes(items[5]!, "to");
    if (toBytes.length !== 20) {
      throw new Error(`invalid EVM intent: ${EVM_CONTRACT_EXECUTION_REFUSAL} (contract creation: to == null)`);
    }
    const valueWei = asBigInt(items[6]!, "value");
    const data = asBytes(items[7]!, "data");
    return finishFacts({ chainId, nonce, gasLimit, toBytes, valueWei, data });
  }

  const item = rlpDecode(raw);
  if (item.kind !== "list" || item.value.length !== 9) {
    throw new Error("invalid EVM intent: legacy payload must be a 9-field list");
  }
  const items = item.value;
  const nonce = asNumber(items[0]!, "nonce");
  const gasLimit = asNumber(items[2]!, "gasLimit");
  const toBytes = asBytes(items[3]!, "to");
  if (toBytes.length !== 20) {
    throw new Error(`invalid EVM intent: ${EVM_CONTRACT_EXECUTION_REFUSAL} (contract creation: to == null)`);
  }
  const valueWei = asBigInt(items[4]!, "value");
  const data = asBytes(items[5]!, "data");
  const v = asNumber(items[6]!, "v");
  if (v < 35) throw new Error("invalid EVM intent: legacy pre-EIP-155 signature carries no chain id");
  const chainId = Math.floor((v - 35) / 2);
  return finishFacts({ chainId, nonce, gasLimit, toBytes, valueWei, data });
}

function finishFacts(input: {
  chainId: number;
  nonce: number;
  gasLimit: number;
  toBytes: Uint8Array;
  valueWei: bigint;
  data: Uint8Array;
}): EvmIntentFacts {
  if (input.data.length !== 0) {
    throw new Error(
      `invalid EVM intent: ${EVM_CONTRACT_EXECUTION_REFUSAL} (intent carries ${input.data.length} bytes of calldata)`,
    );
  }
  if (input.valueWei === 0n) {
    throw new Error("invalid EVM intent: an EVM carrier settles value transfers only (no value)");
  }
  const rem = input.valueWei % WEI_PER_NANO;
  if (rem !== 0n) {
    throw new Error(
      `invalid EVM intent: sub-nano wei remainder (${rem} wei): value must be a multiple of 1_000_000_000 wei`,
    );
  }
  const nano = input.valueWei / WEI_PER_NANO;
  if (nano === 0n) {
    throw new Error("invalid EVM intent: EVM value is below one nano-STELL and cannot be settled");
  }
  if (nano > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("invalid EVM intent: nano-STELL value exceeds 2^53");
  }
  return {
    chainId: input.chainId,
    nonce: input.nonce,
    gasLimit: input.gasLimit,
    to: `0x${bytesToHex(input.toBytes)}`,
    valueWei: input.valueWei,
    valueNano: Number(nano),
    dataHex: bytesToHex(input.data),
  };
}

/** `keccak256(raw)` — the digest the carrier's Falcon authorisation covers. */
export function evmIntentDigest(raw: Uint8Array): Uint8Array {
  return keccak256(raw);
}

/** Strict length/shape check for the 65-byte proof of possession. */
export function requireBindingProof(proof: Uint8Array | string): Uint8Array {
  const bytes = typeof proof === "string" ? hexToBytes(proof, "evmProof") : proof;
  if (bytes.length !== EVM_BINDING_PROOF_LEN) {
    throw new Error(
      `EVM binding requires a ${EVM_BINDING_PROOF_LEN}-byte secp256k1 proof of possession ` +
        `(r || s || recovery_id), got ${bytes.length} bytes`,
    );
  }
  return bytes;
}
