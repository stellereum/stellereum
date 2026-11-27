/**
 * Bincode encoding for the transaction shapes the TypeScript SDK builds.
 *
 * ## Why this file exists (and its honest limit)
 *
 * The pre-existing TS SDK delegated ALL wire encoding to the Rust signer. The
 * EVM and governance builders are different: their payload contains a Falcon
 * signature (binding / carrier intent) that must exist BEFORE the envelope
 * preimage is computed, so the caller needs the unsigned bytes in JS.
 *
 * This module therefore encodes:
 *
 * - a `bincode(Transaction)` with an EMPTY signature (the sidecar attaches the
 *   `PQ1` envelope and signs it; PQ cryptography is never reimplemented here);
 * - the four payload opcodes (`SysCallGovPropose`, `SysCallGovVote`,
 *   `SysCallEvmCarrier`, `SysCallBindEvmAddress`), their `GovAction`
 *   parameters and the transaction signing preimage.
 *
 * The bytes are pinned against the node's own builders by fixed vectors in
 * `test/builders.test.ts` and by the Rust SDK parity suite.
 */

import { SignerError } from "./errors.ts";

export const PQ_ACTIVATION_SURCHARGE_GAS = 45_000;
export const FROZEN_MIN_GAS_FLOOR = 280_000;
export const MASTERCHAIN_SHARD = 0;

export const OP_GOV_PROPOSE = 53;
export const OP_GOV_VOTE = 54;
export const OP_EVM_CARRIER = 57;
export const OP_BIND_EVM_ADDRESS = 58;

export const GAS_GOV_PROPOSE = 2_000;
export const GAS_GOV_VOTE = 600;
export const GAS_EVM_CARRIER_BASE = 2_000;
export const GAS_PQ_VERIFY_BASE = 1_500;
export const GAS_PQ_VERIFY_PER_BYTE = 2;

export const MAX_PROPOSAL_TITLE_BYTES = 256;
export const MAX_SIGNAL_BYTES = 1_024;
export const MAX_UPGRADE_NAME_BYTES = 64;
export const MIN_VALIDATOR_BOND = 1_000n * 1_000_000_000n;
export const MAX_VALIDATOR_BOND = 1_000_000n * 1_000_000_000n;
export const MAX_BLOCK_REWARD_NANO = 10_000_000n * 1_000_000_000n;
export const GOVERNANCE_QUORUM_FLOOR_BPS = 3_333;
export const MAX_MIN_GAS_LIMIT = 10 * FROZEN_MIN_GAS_FLOOR;

export const PAYLOAD_COMMITMENT_TAG = new TextEncoder().encode("PAYLOAD");
export const CHAIN_ID_COMMITMENT_TAG = new TextEncoder().encode("CHAIN_ID");
export const PRIORITY_FEE_COMMITMENT_TAG = new TextEncoder().encode("PRIORITY");
export const PQ_ENVELOPE_HASH_TAG = new TextEncoder().encode("PQ_ENV");

export const SPONSOR_SIG_TAG = new TextEncoder().encode("SP1");
export const SPONSOR_COMMITMENT_TAG = new TextEncoder().encode("SPONSOR_");
export const SPONSOR_FEE_DOMAIN = new TextEncoder().encode("SPONSOR_FEE_V1");
export const SPONSOR_ALLOWLIST_TAG = new TextEncoder().encode("ALLOWLIST");
export const SPONSOR_AUTH_MAX_BYTES = 4096;
export const SPONSOR_MAX_TARGETS = 64;

export const SESSION_FALCON_SIG_TAG = new TextEncoder().encode("SF1");
export const SESSION_COMMITMENT_TAG = new TextEncoder().encode("SESSION");
export const SESSION_KEY_DOMAIN = new TextEncoder().encode("STELL_SESSKEY_V1");

export const SCOPE_TRANSFER = 1n << 0n;
export const SCOPE_SVM_PAYLOAD = 1n << 1n;
export const SCOPE_ACTOR_SEND = 1n << 2n;
export const SCOPE_ALL = (1n << 64n) - 1n;

export type VoteChoice = "yes" | "no" | "abstain";

export type GovAction =
  | { type: "set_min_validator_bond"; value: number | bigint }
  | { type: "set_equivocation_slash_bps"; value: number }
  | { type: "set_default_commission_bps"; value: number }
  | { type: "set_block_reward"; value: number | bigint }
  | { type: "set_pmm_redemption_buffer_bps"; value: number }
  | { type: "set_governance_quorum_bps"; value: number }
  | { type: "signal"; text: string }
  | { type: "register_oracle_publisher"; publisher: string }
  | { type: "unregister_oracle_publisher"; publisher: string }
  | { type: "reset_oracle_breaker" }
  | { type: "set_min_gas_limit"; value: number }
  | { type: "software_upgrade"; name: string; height: number; sha256: string }
  | { type: "cancel_upgrade" }
  | { type: "set_fee_split_bps"; burn_bps: number; proposer_bps: number; staking_bps: number };

/** An unsigned, fully encoded transaction plus the exact bytes to sign. */
export interface UnsignedTransaction {
  /** Hex of `bincode(Transaction)` with an empty signature blob. */
  txHex: string;
  /** Hex of the bincode payload (`Vec<OpCode>`), for inspection/parity. */
  payloadHex: string;
  /** Hex of the exact preimage the PQ envelope signs (`CHAIN_ID` included unless unbound). */
  signingMessageHex: string;
  /** SHA-256 of the unsigned transaction (NOT the final signed hash). */
  unsignedTxHash: string;
  from: string;
  to: string;
  amount: number;
  nonce: number;
  gasLimit: number;
  chainId: number | null;
  priorityFeePerGas: number;
}

export interface TransactionFields {
  from: Uint8Array;
  to: Uint8Array;
  amount: number;
  gasLimit: number;
  nonce: number;
  sourceShard: number;
  targetShard: number;
  payload: Uint8Array;
  priorityFeePerGas: number;
}

const U32_MAX = 0xffff_ffff;
const U64_MAX = (1n << 64n) - 1n;
const EMPTY_VEC_BINCODE = new Uint8Array(8);
const WIRE_FALCON512_SIG_LEN = 666;
const WIRE_ED25519_SIG_LEN = 64;

function toValidU32(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > U32_MAX) {
    throw new RangeError(`u32 out of range [0, 2^32-1]: ${String(value)}`);
  }
  return value;
}

function toValidU64(value: number | bigint): bigint {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new RangeError(`u64 out of range or not a safe non-negative integer: ${String(value)}`);
    }
    return BigInt(value);
  }
  if (typeof value === "bigint") {
    if (value < 0n || value > U64_MAX) {
      throw new RangeError(`u64 bigint out of range [0, 2^64-1]: ${value.toString()}`);
    }
    return value;
  }
  throw new RangeError("u64 must be a number or bigint");
}

class Writer {
  private readonly parts: Uint8Array[] = [];

  u8(value: number): void {
    this.parts.push(Uint8Array.of(value & 0xff));
  }

  u32le(value: number): void {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, toValidU32(value), true);
    this.parts.push(out);
  }

  u32be(value: number): void {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, toValidU32(value), false);
    this.parts.push(out);
  }

  u64le(value: number | bigint): void {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, toValidU64(value), true);
    this.parts.push(out);
  }

  u64be(value: number | bigint): void {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, toValidU64(value), false);
    this.parts.push(out);
  }

  bytes(value: Uint8Array): void {
    this.parts.push(value);
  }

  /** `Vec<u8>`/`String` bincode frame: u64 LE length then bytes. */
  vec(value: Uint8Array): void {
    this.u64le(value.length);
    this.parts.push(value);
  }

  finish(): Uint8Array {
    let len = 0;
    for (const p of this.parts) len += p.length;
    const out = new Uint8Array(len);
    let offset = 0;
    for (const p of this.parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }
}

export function hexToBytes(hex: string, field = "hex"): Uint8Array {
  const clean = hex.trim().replace(/^0x/, "");
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new Error(`${field}: invalid hex`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

const PQ_ADDRESS_LEN = 32;
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const STL57_PREFIX = "Stl57";
const STL57_CHECKSUM_DOMAIN = "STELLEREUM_ADDRESS_CHECKSUM_V1";

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
    throw new RangeError("blake3DeriveKeySingleBlock supports <= 64 byte context and input");
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

function base58Encode(input: Uint8Array): string {
  let leadingZeros = 0;
  while (leadingZeros < input.length && input[leadingZeros] === 0) {
    leadingZeros++;
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
  let out = "1".repeat(leadingZeros);
  for (let i = digits.length - 1; i >= 0; i--) {
    out += BASE58_ALPHABET[digits[i]!]!;
  }
  return out;
}

function base58Decode(input: string): Uint8Array {
  if (input.length === 0) return new Uint8Array();
  let leadingZeros = 0;
  while (leadingZeros < input.length && input[leadingZeros] === "1") {
    leadingZeros++;
  }
  const bytes: number[] = [];
  for (let i = leadingZeros; i < input.length; i++) {
    const ch = input[i]!;
    const val = BASE58_ALPHABET.indexOf(ch);
    if (val < 0) {
      throw new SignerError("invalid_address", `invalid base58 character: ${ch}`);
    }
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

function stl57Checksum(addr32: Uint8Array): Uint8Array {
  return blake3DeriveKeySingleBlock(STL57_CHECKSUM_DOMAIN, addr32).subarray(0, 4);
}

/** Encode a 32-byte Stellereum address as branded `Stl57...` with 4-byte BLAKE3 checksum. */
export function encodeStl57Address(addr: Uint8Array): string {
  if (addr.length !== PQ_ADDRESS_LEN) {
    throw new SignerError("invalid_address", `expected 32-byte address, got ${addr.length}`);
  }
  const payload = new Uint8Array(36);
  payload.set(addr, 0);
  payload.set(stl57Checksum(addr), 32);
  return `${STL57_PREFIX}${base58Encode(payload)}`;
}

/** Parse a `Stl57...` address or 64-character hex (optional `0x`) into 32 bytes. */
export function parseStellereumAddress(input: string, field = "address"): Uint8Array {
  const s = input.trim();
  if (s.length === 0) {
    throw new SignerError("invalid_address", `${field}: address is empty`);
  }
  if (s.slice(0, 5).toLowerCase() === "stl57") {
    const body = s.slice(5);
    if (body.length < 35 || body.length > 51) {
      throw new SignerError("invalid_address", `${field}: invalid Stl57 length`);
    }
    const decoded = base58Decode(body);
    if (decoded.length !== 36) {
      throw new SignerError("invalid_address", `${field}: invalid Stl57 payload length`);
    }
    const addr = decoded.subarray(0, 32);
    const gotCheck = decoded.subarray(32, 36);
    const expectedCheck = stl57Checksum(addr);
    for (let i = 0; i < 4; i++) {
      if (gotCheck[i] !== expectedCheck[i]) {
        throw new SignerError("invalid_address", `${field}: address checksum mismatch`);
      }
    }
    return new Uint8Array(addr);
  }
  const bytes = hexToBytes(s, field);
  if (bytes.length !== PQ_ADDRESS_LEN) {
    throw new SignerError("invalid_address", `${field}: expected 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

export function address32(value: string, field = "address"): Uint8Array {
  return parseStellereumAddress(value, field);
}

export function address20(value: string, field: string): Uint8Array {
  const bytes = hexToBytes(value, field);
  if (bytes.length !== 20) throw new Error(`${field}: expected 20 bytes, got ${bytes.length}`);
  return bytes;
}

const SHA256_H = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** Pure-TypeScript synchronous FIPS 180-4 SHA-256 digest (browser & Node compatible). */
export function sha256(bytes: Uint8Array): Uint8Array {
  const len = bytes.length;
  const paddedLen = Math.ceil((len + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(bytes);
  padded[len] = 0x80;
  const view = new DataView(padded.buffer);
  view.setBigUint64(paddedLen - 8, BigInt(len) * 8n, false);

  let h0 = SHA256_H[0]!;
  let h1 = SHA256_H[1]!;
  let h2 = SHA256_H[2]!;
  let h3 = SHA256_H[3]!;
  let h4 = SHA256_H[4]!;
  let h5 = SHA256_H[5]!;
  let h6 = SHA256_H[6]!;
  let h7 = SHA256_H[7]!;

  const w = new Uint32Array(64);
  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const w15 = w[i - 15]!;
      const w2 = w[i - 2]!;
      const s0 = (rotr32(w15, 7) ^ rotr32(w15, 18) ^ (w15 >>> 3)) >>> 0;
      const s1 = (rotr32(w2, 17) ^ rotr32(w2, 19) ^ (w2 >>> 10)) >>> 0;
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const s1 = (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + s1 + ch + SHA256_K[i]! + w[i]!) >>> 0;
      const s0 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (s0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0, false);
  outView.setUint32(4, h1, false);
  outView.setUint32(8, h2, false);
  outView.setUint32(12, h3, false);
  outView.setUint32(16, h4, false);
  outView.setUint32(20, h5, false);
  outView.setUint32(24, h6, false);
  outView.setUint32(28, h7, false);
  return out;
}

export function encodeGovAction(action: GovAction): Uint8Array {
  const w = new Writer();
  const u64 = (value: number | bigint): void => w.u64le(value);
  switch (action.type) {
    case "set_min_validator_bond": {
      const v = toValidU64(action.value);
      if (v < MIN_VALIDATOR_BOND || v > MAX_VALIDATOR_BOND) {
        throw new Error("set_min_validator_bond out of bounds");
      }
      w.u32le(0);
      u64(v);
      break;
    }
    case "set_equivocation_slash_bps": {
      const b = toValidU64(action.value);
      if (b > 10_000n) {
        throw new Error("basis points above 10_000");
      }
      w.u32le(1);
      u64(b);
      break;
    }
    case "set_default_commission_bps": {
      const b = toValidU64(action.value);
      if (b > 10_000n) {
        throw new Error("basis points above 10_000");
      }
      w.u32le(2);
      u64(b);
      break;
    }
    case "set_block_reward": {
      const v = toValidU64(action.value);
      if (v > MAX_BLOCK_REWARD_NANO) {
        throw new Error("set_block_reward out of bounds");
      }
      w.u32le(3);
      u64(v);
      break;
    }
    case "set_pmm_redemption_buffer_bps": {
      const b = toValidU64(action.value);
      if (b > 10_000n) {
        throw new Error("basis points above 10_000");
      }
      w.u32le(4);
      u64(b);
      break;
    }
    case "set_governance_quorum_bps": {
      const b = toValidU64(action.value);
      if (b < BigInt(GOVERNANCE_QUORUM_FLOOR_BPS) || b > 10_000n) {
        throw new Error("set_governance_quorum_bps out of bounds");
      }
      w.u32le(5);
      u64(b);
      break;
    }
    case "signal": {
      const textBytes = new TextEncoder().encode(action.text);
      if (textBytes.length > MAX_SIGNAL_BYTES) {
        throw new Error("signal text is too long");
      }
      w.u32le(6);
      w.vec(textBytes);
      break;
    }
    case "register_oracle_publisher": {
      const pk = address32(action.publisher, "publisher");
      if (pk.every((b) => b === 0)) {
        throw new Error("oracle publisher key must be non-zero");
      }
      w.u32le(7);
      w.bytes(pk);
      break;
    }
    case "unregister_oracle_publisher": {
      const pk = address32(action.publisher, "publisher");
      if (pk.every((b) => b === 0)) {
        throw new Error("oracle publisher key must be non-zero");
      }
      w.u32le(8);
      w.bytes(pk);
      break;
    }
    case "reset_oracle_breaker":
      w.u32le(9);
      break;
    case "set_min_gas_limit": {
      const v = toValidU64(action.value);
      if (v === 0n || v > BigInt(MAX_MIN_GAS_LIMIT)) {
        throw new Error("set_min_gas_limit out of bounds");
      }
      w.u32le(10);
      u64(v);
      break;
    }
    case "software_upgrade": {
      const nameBytes = new TextEncoder().encode(action.name);
      const height = toValidU64(action.height);
      const digest = hexToBytes(action.sha256, "sha256");
      if (
        nameBytes.length === 0 ||
        nameBytes.length > MAX_UPGRADE_NAME_BYTES ||
        height === 0n ||
        digest.length !== 32 ||
        digest.every((b) => b === 0)
      ) {
        throw new Error("software upgrade name/height/sha256 is invalid");
      }
      for (const b of nameBytes) {
        const ok =
          (b >= 0x30 && b <= 0x39) ||
          (b >= 0x41 && b <= 0x5a) ||
          (b >= 0x61 && b <= 0x7a) ||
          b === 0x2d ||
          b === 0x5f ||
          b === 0x2e;
        if (!ok) {
          throw new Error("software upgrade name has unsafe characters");
        }
      }
      w.u32le(11);
      w.vec(nameBytes);
      u64(height);
      w.bytes(digest);
      break;
    }
    case "cancel_upgrade":
      w.u32le(12);
      break;
    case "set_fee_split_bps": {
      if (
        !Number.isInteger(action.burn_bps) ||
        action.burn_bps < 0 ||
        !Number.isInteger(action.proposer_bps) ||
        action.proposer_bps < 0 ||
        !Number.isInteger(action.staking_bps) ||
        action.staking_bps < 0
      ) {
        throw new Error("set_fee_split_bps: burn_bps, proposer_bps, staking_bps must be non-negative integers");
      }
      if (action.burn_bps + action.proposer_bps + action.staking_bps !== 10_000) {
        throw new Error(
          `set_fee_split_bps: burn_bps + proposer_bps + staking_bps must equal 10000, got ${
            action.burn_bps + action.proposer_bps + action.staking_bps
          }`,
        );
      }
      w.u32le(13);
      u64(action.burn_bps);
      u64(action.proposer_bps);
      u64(action.staking_bps);
      break;
    }
    default: {
      const never: never = action;
      throw new Error(`unknown governance action ${JSON.stringify(never)}`);
    }
  }
  return w.finish();
}

function voteChoiceOrdinal(choice: VoteChoice): number {
  switch (choice) {
    case "yes":
      return 0;
    case "no":
      return 1;
    case "abstain":
      return 2;
    default: {
      const never: never = choice;
      throw new Error(`unknown vote choice ${JSON.stringify(never)}`);
    }
  }
}

export interface EvmCarrierPayload {
  chainId: number;
  evmTx: Uint8Array;
  evmAddress: Uint8Array;
  pqPubkey: Uint8Array;
  evmSignature: Uint8Array;
}

export interface EvmBindingPayload {
  chainId: number;
  evmAddress: Uint8Array;
  pqPubkey: Uint8Array;
  bindingSignature: Uint8Array;
  evmSignature: Uint8Array;
}

/** Encode one `OpCode` value (discriminant + fields). */
export function encodeOp(
  op:
    | { kind: "gov_propose"; proposalId: number; title: string; action: GovAction; heightObserved: number }
    | { kind: "gov_vote"; proposalId: number; choice: VoteChoice; heightObserved: number }
    | ({ kind: "evm_carrier" } & EvmCarrierPayload)
    | ({ kind: "evm_binding" } & EvmBindingPayload),
): Uint8Array {
  const w = new Writer();
  switch (op.kind) {
    case "gov_propose":
      w.u32le(OP_GOV_PROPOSE);
      w.u64le(op.proposalId);
      w.vec(new TextEncoder().encode(op.title));
      w.bytes(encodeGovAction(op.action));
      w.u64le(op.heightObserved);
      break;
    case "gov_vote":
      w.u32le(OP_GOV_VOTE);
      w.u64le(op.proposalId);
      w.u32le(voteChoiceOrdinal(op.choice));
      w.u64le(op.heightObserved);
      break;
    case "evm_carrier":
      w.u32le(OP_EVM_CARRIER);
      w.u64le(op.chainId);
      w.vec(op.evmTx);
      w.bytes(op.evmAddress);
      w.vec(op.pqPubkey);
      w.vec(op.evmSignature);
      break;
    case "evm_binding":
      w.u32le(OP_BIND_EVM_ADDRESS);
      w.u64le(op.chainId);
      w.bytes(op.evmAddress);
      w.vec(op.pqPubkey);
      w.vec(op.bindingSignature);
      w.vec(op.evmSignature);
      break;
    default: {
      const never: never = op;
      throw new Error(`unknown opcode ${JSON.stringify(never)}`);
    }
  }
  return w.finish();
}

/** `bincode(Vec<OpCode>)`: u64 LE count then each opcode. */
export function encodePayload(
  ops: Parameters<typeof encodeOp>[0][],
): Uint8Array {
  const w = new Writer();
  w.u64le(ops.length);
  for (const op of ops) w.bytes(encodeOp(op));
  return w.finish();
}

/** Normalize empty payload `Uint8Array(0)` to canonical 8-byte bincode empty `Vec`. */
export function normalizePayloadBytes(payload: Uint8Array): Uint8Array {
  return payload.length === 0 ? EMPTY_VEC_BINCODE : payload;
}

/** `bincode(Transaction)` with an empty signature blob (plus trailing PRIORITY suffix if non-zero). */
export function encodeUnsignedTransaction(tx: TransactionFields): Uint8Array {
  if (tx.from.length !== 32 || tx.to.length !== 32) throw new Error("transaction addresses must be 32 bytes");
  const w = new Writer();
  w.bytes(tx.from);
  w.bytes(tx.to);
  w.u64le(tx.amount);
  w.u64le(tx.gasLimit);
  w.u64le(tx.nonce);
  w.u32le(tx.sourceShard);
  w.u32le(tx.targetShard);
  if (tx.priorityFeePerGas !== 0) {
    w.u64le(PRIORITY_FEE_COMMITMENT_TAG.length + 8);
    w.bytes(PRIORITY_FEE_COMMITMENT_TAG);
    w.u64be(tx.priorityFeePerGas);
  } else {
    w.u64le(0); // empty signature blob
  }
  w.bytes(normalizePayloadBytes(tx.payload));
  return w.finish();
}

/** The exact preimage without `CHAIN_ID` (used when `unbound: true` / `chainId: null`). */
export function baseSigningMessage(tx: TransactionFields): Uint8Array {
  const payloadBytes = normalizePayloadBytes(tx.payload);
  const w = new Writer();
  w.bytes(tx.from);
  w.bytes(tx.to);
  w.u64be(tx.amount);
  w.u64be(tx.gasLimit);
  w.u64be(tx.nonce);
  w.u32be(tx.sourceShard);
  w.u32be(tx.targetShard);
  w.bytes(PAYLOAD_COMMITMENT_TAG);
  w.u32be(payloadBytes.length);
  w.bytes(payloadBytes);
  if (tx.priorityFeePerGas !== 0) {
    w.bytes(PRIORITY_FEE_COMMITMENT_TAG);
    w.u64be(tx.priorityFeePerGas);
  }
  return w.finish();
}

/** The exact preimage the PQ1 envelope signs (`signing_message_for_chain`). */
export function signingMessage(tx: TransactionFields, chainId: number): Uint8Array {
  const w = new Writer();
  w.bytes(baseSigningMessage(tx));
  w.bytes(CHAIN_ID_COMMITMENT_TAG);
  w.u64be(chainId);
  return w.finish();
}

/** The node's `compute_tx_hash` preimage for an unsigned (no envelope) tx. */
export function unsignedTxHash(tx: TransactionFields): Uint8Array {
  return sha256(baseSigningMessage(tx));
}

/** Assemble an `UnsignedTransaction` from its fields and chain id (`null` when unbound). */
export function finishUnsigned(tx: TransactionFields, chainId: number | null): UnsignedTransaction {
  const encoded = encodeUnsignedTransaction(tx);
  const msg = chainId !== null ? signingMessage(tx, chainId) : baseSigningMessage(tx);
  return {
    txHex: bytesToHex(encoded),
    payloadHex: bytesToHex(tx.payload),
    signingMessageHex: bytesToHex(msg),
    unsignedTxHash: bytesToHex(unsignedTxHash(tx)),
    from: bytesToHex(tx.from),
    to: bytesToHex(tx.to),
    amount: tx.amount,
    nonce: tx.nonce,
    gasLimit: tx.gasLimit,
    chainId,
    priorityFeePerGas: tx.priorityFeePerGas,
  };
}

// ============================================================================
// SP1 (SponsorAuthorization) & SF1 (SessionGrant) wire parity
// ============================================================================

export type PqSchemeWire = "falcon512" | "mldsa44" | 2 | 3;

export interface SponsorAuthorization {
  sponsor: Uint8Array;
  maxFeePerTx: number | bigint;
  validUntil: number | bigint;
  allowedTargets?: Uint8Array[];
  chainId: number | bigint;
  sponsorSig: Uint8Array;
  sponsorScheme?: PqSchemeWire | null;
  sponsorPubkey?: Uint8Array | null;
  sponsorSalt?: Uint8Array | null;
}

export interface SplitSponsorEnvelopeResult {
  innerLen: number;
  innerSig: Uint8Array;
  auth: SponsorAuthorization | null;
  malformed: boolean;
}

export interface SessionGrant {
  masterAddress: Uint8Array;
  sessionPubkey: Uint8Array;
  validUntil: number | bigint;
  maxGasSpend: number | bigint;
  gasSpent?: number | bigint;
  scope: number | bigint;
  maxValuePerTx: number | bigint;
  chainId: number | bigint;
  masterSignature: Uint8Array;
  masterScheme?: PqSchemeWire;
  sessionScheme?: PqSchemeWire;
  masterPubkey?: Uint8Array | null;
  sessionPubkeyBytes?: Uint8Array | null;
}

export interface SplitSessionEnvelopeResult {
  sessionSig: Uint8Array;
  grant: SessionGrant;
  grantBytes: Uint8Array;
}

class Reader {
  private readonly buf: Uint8Array;
  private cursor = 0;

  constructor(buf: Uint8Array) {
    this.buf = buf;
  }

  remaining(): number {
    return this.buf.length - this.cursor;
  }

  u8(): number {
    if (this.cursor >= this.buf.length) {
      throw new SignerError("decode_error", "unexpected EOF reading u8");
    }
    const v = this.buf[this.cursor]!;
    this.cursor += 1;
    return v;
  }

  u32le(): number {
    if (this.cursor + 4 > this.buf.length) {
      throw new SignerError("decode_error", "unexpected EOF reading u32le");
    }
    const v = new DataView(this.buf.buffer, this.buf.byteOffset + this.cursor, 4).getUint32(0, true);
    this.cursor += 4;
    return v;
  }

  u64le(): bigint {
    if (this.cursor + 8 > this.buf.length) {
      throw new SignerError("decode_error", "unexpected EOF reading u64le");
    }
    const v = new DataView(this.buf.buffer, this.buf.byteOffset + this.cursor, 8).getBigUint64(0, true);
    this.cursor += 8;
    return v;
  }

  bytes(n: number): Uint8Array {
    if (n < 0 || this.cursor + n > this.buf.length) {
      throw new SignerError("decode_error", "unexpected EOF reading bytes");
    }
    const slice = new Uint8Array(this.buf.subarray(this.cursor, this.cursor + n));
    this.cursor += n;
    return slice;
  }

  vec(maxLen: number): Uint8Array {
    const len = this.u64le();
    if (len > BigInt(maxLen) || len > BigInt(this.remaining())) {
      throw new SignerError("decode_error", "bincode vector length exceeds bounds");
    }
    return this.bytes(Number(len));
  }
}

function pqSchemeVariantIndex(scheme: PqSchemeWire): number {
  if (scheme === "falcon512" || scheme === 2) return 0;
  if (scheme === "mldsa44" || scheme === 3) return 1;
  throw new SignerError("invalid_argument", `unknown PQ scheme: ${String(scheme)}`);
}

function pqSchemeFromVariantIndex(idx: number): 2 | 3 {
  if (idx === 0) return 2;
  if (idx === 1) return 3;
  throw new SignerError("decode_error", `unknown PqScheme variant index: ${idx}`);
}

function pqSchemeToId(scheme: PqSchemeWire | undefined): number {
  if (scheme === undefined || scheme === "falcon512" || scheme === 2) return 2;
  if (scheme === "mldsa44" || scheme === 3) return 3;
  throw new SignerError("invalid_argument", `unknown PQ scheme: ${String(scheme)}`);
}

/** Exact bincode 1.3 encoding of `SponsorAuthorization`. */
export function encodeSponsorAuth(auth: SponsorAuthorization): Uint8Array {
  if (auth.sponsor.length !== PQ_ADDRESS_LEN) {
    throw new SignerError("invalid_argument", `sponsor address must be ${PQ_ADDRESS_LEN} bytes`);
  }
  const targets = auth.allowedTargets ?? [];
  if (targets.length > SPONSOR_MAX_TARGETS) {
    throw new SignerError(
      "invalid_argument",
      `allowedTargets exceeds SPONSOR_MAX_TARGETS (${SPONSOR_MAX_TARGETS})`,
    );
  }
  const w = new Writer();
  w.bytes(auth.sponsor);
  w.u64le(auth.maxFeePerTx);
  w.u64le(auth.validUntil);
  w.u64le(targets.length);
  for (const target of targets) {
    if (target.length !== PQ_ADDRESS_LEN) {
      throw new SignerError("invalid_argument", `allowedTarget must be ${PQ_ADDRESS_LEN} bytes`);
    }
    w.bytes(target);
  }
  w.u64le(auth.chainId);
  w.vec(auth.sponsorSig);
  if (auth.sponsorScheme === undefined || auth.sponsorScheme === null) {
    w.u8(0);
  } else {
    w.u8(1);
    w.u32le(pqSchemeVariantIndex(auth.sponsorScheme));
  }
  if (auth.sponsorPubkey === undefined || auth.sponsorPubkey === null) {
    w.u8(0);
  } else {
    w.u8(1);
    w.vec(auth.sponsorPubkey);
  }
  if (auth.sponsorSalt === undefined || auth.sponsorSalt === null) {
    w.u8(0);
  } else {
    if (auth.sponsorSalt.length !== 16) {
      throw new SignerError("invalid_argument", "sponsorSalt must be 16 bytes");
    }
    w.u8(1);
    w.bytes(auth.sponsorSalt);
  }
  return w.finish();
}

/** Decode exact-fit bincode 1.3 `SponsorAuthorization`. */
export function decodeSponsorAuth(bytes: Uint8Array): SponsorAuthorization {
  const r = new Reader(bytes);
  const sponsor = r.bytes(PQ_ADDRESS_LEN);
  const maxFeePerTx = r.u64le();
  const validUntil = r.u64le();
  const targetCountBig = r.u64le();
  if (targetCountBig > BigInt(SPONSOR_MAX_TARGETS) || targetCountBig * 32n > BigInt(r.remaining())) {
    throw new SignerError("decode_error", "sponsor allowedTargets count out of bounds");
  }
  const targetCount = Number(targetCountBig);
  const allowedTargets: Uint8Array[] = [];
  for (let i = 0; i < targetCount; i++) {
    allowedTargets.push(r.bytes(PQ_ADDRESS_LEN));
  }
  const chainId = r.u64le();
  const sponsorSig = r.vec(SPONSOR_AUTH_MAX_BYTES);
  if (sponsorSig.length !== WIRE_FALCON512_SIG_LEN && sponsorSig.length !== WIRE_ED25519_SIG_LEN) {
    throw new SignerError("decode_error", `invalid sponsor_sig length: ${sponsorSig.length}`);
  }
  const schemeTag = r.u8();
  let sponsorScheme: 2 | 3 | null;
  if (schemeTag === 0) {
    sponsorScheme = null;
  } else if (schemeTag === 1) {
    sponsorScheme = pqSchemeFromVariantIndex(r.u32le());
  } else {
    throw new SignerError("decode_error", `invalid Option<PqScheme> tag: ${schemeTag}`);
  }
  const pkTag = r.u8();
  let sponsorPubkey: Uint8Array | null;
  if (pkTag === 0) {
    sponsorPubkey = null;
  } else if (pkTag === 1) {
    sponsorPubkey = r.vec(SPONSOR_AUTH_MAX_BYTES);
  } else {
    throw new SignerError("decode_error", `invalid Option<Vec<u8>> tag: ${pkTag}`);
  }
  const saltTag = r.u8();
  let sponsorSalt: Uint8Array | null;
  if (saltTag === 0) {
    sponsorSalt = null;
  } else if (saltTag === 1) {
    sponsorSalt = r.bytes(16);
  } else {
    throw new SignerError("decode_error", `invalid Option<[u8; 16]> tag: ${saltTag}`);
  }
  if (r.remaining() !== 0) {
    throw new SignerError("decode_error", "trailing bytes in SponsorAuthorization");
  }
  return {
    sponsor,
    maxFeePerTx,
    validUntil,
    allowedTargets,
    chainId,
    sponsorSig,
    sponsorScheme,
    sponsorPubkey,
    sponsorSalt,
  };
}

/** Encode the trailing `SP1` suffix: `bincode(SponsorAuthorization) || u32be(len) || "SP1"`. */
export function encodeSponsorSuffix(auth: SponsorAuthorization): Uint8Array {
  if (
    auth.sponsorSig.length !== WIRE_FALCON512_SIG_LEN &&
    auth.sponsorSig.length !== WIRE_ED25519_SIG_LEN
  ) {
    throw new SignerError(
      "invalid_argument",
      `sponsorSig must be ${WIRE_FALCON512_SIG_LEN} (Falcon-512) or ${WIRE_ED25519_SIG_LEN} bytes`,
    );
  }
  const body = encodeSponsorAuth(auth);
  if (body.length === 0 || body.length > SPONSOR_AUTH_MAX_BYTES) {
    throw new SignerError(
      "invalid_argument",
      `encoded SponsorAuthorization length ${body.length} exceeds ${SPONSOR_AUTH_MAX_BYTES}`,
    );
  }
  const w = new Writer();
  w.bytes(body);
  w.u32be(body.length);
  w.bytes(SPONSOR_SIG_TAG);
  return w.finish();
}

/** Split the trailing `SP1` sponsor suffix off a signature blob (matches `Transaction::split_sponsor_envelope`). */
export function splitSponsorEnvelope(blob: Uint8Array): SplitSponsorEnvelopeResult {
  const tagLen = SPONSOR_SIG_TAG.length;
  if (
    blob.length < tagLen + 4 + 1 ||
    blob[blob.length - 3] !== SPONSOR_SIG_TAG[0] ||
    blob[blob.length - 2] !== SPONSOR_SIG_TAG[1] ||
    blob[blob.length - 1] !== SPONSOR_SIG_TAG[2]
  ) {
    return { innerLen: blob.length, innerSig: blob, auth: null, malformed: false };
  }
  const lenOff = blob.length - tagLen - 4;
  const authLen = new DataView(blob.buffer, blob.byteOffset + lenOff, 4).getUint32(0, false);
  if (authLen === 0 || authLen > SPONSOR_AUTH_MAX_BYTES || lenOff < authLen) {
    return { innerLen: blob.length, innerSig: blob, auth: null, malformed: true };
  }
  const innerLen = lenOff - authLen;
  if (innerLen < WIRE_ED25519_SIG_LEN) {
    return { innerLen: blob.length, innerSig: blob, auth: null, malformed: true };
  }
  const authBytes = blob.subarray(innerLen, lenOff);
  try {
    const auth = decodeSponsorAuth(authBytes);
    return {
      innerLen,
      innerSig: blob.subarray(0, innerLen),
      auth,
      malformed: false,
    };
  } catch {
    return { innerLen: blob.length, innerSig: blob, auth: null, malformed: true };
  }
}

/** `SPONSOR_COMMITMENT_TAG || u32be(bincode(auth).length) || bincode(auth)` (matches `Transaction::sponsor_commitment_bytes`). */
export function sponsorCommitment(auth: SponsorAuthorization): Uint8Array {
  const encoded = encodeSponsorAuth(auth);
  const w = new Writer();
  w.bytes(SPONSOR_COMMITMENT_TAG);
  w.u32be(encoded.length);
  w.bytes(encoded);
  return w.finish();
}

/** The exact bytes the sponsor signs (`SPONSOR_FEE_V1 || ...`, matches `Transaction::sponsor_message`). */
export function sponsorMessage(
  tx: TransactionFields,
  auth: {
    sponsor: Uint8Array;
    maxFeePerTx: number | bigint;
    validUntil: number | bigint;
    allowedTargets?: Uint8Array[];
    chainId: number | bigint;
  },
): Uint8Array {
  if (tx.from.length !== PQ_ADDRESS_LEN || tx.to.length !== PQ_ADDRESS_LEN) {
    throw new SignerError("invalid_argument", "transaction addresses must be 32 bytes");
  }
  if (auth.sponsor.length !== PQ_ADDRESS_LEN) {
    throw new SignerError("invalid_argument", "sponsor address must be 32 bytes");
  }
  const targets = auth.allowedTargets ?? [];
  if (targets.length > SPONSOR_MAX_TARGETS) {
    throw new SignerError(
      "invalid_argument",
      `allowedTargets exceeds SPONSOR_MAX_TARGETS (${SPONSOR_MAX_TARGETS})`,
    );
  }
  const payloadBytes = normalizePayloadBytes(tx.payload);
  const w = new Writer();
  w.bytes(SPONSOR_FEE_DOMAIN);
  w.bytes(auth.sponsor);
  w.bytes(tx.from);
  w.bytes(tx.to);
  w.u64be(tx.amount);
  w.u64be(tx.gasLimit);
  w.u64be(tx.nonce);
  w.u32be(tx.sourceShard);
  w.u32be(tx.targetShard);
  w.bytes(PAYLOAD_COMMITMENT_TAG);
  w.u32be(payloadBytes.length);
  w.bytes(payloadBytes);
  w.u64be(tx.priorityFeePerGas);
  w.u64be(auth.maxFeePerTx);
  w.u64be(auth.validUntil);
  w.bytes(SPONSOR_ALLOWLIST_TAG);
  w.u32be(targets.length);
  for (const target of targets) {
    if (target.length !== PQ_ADDRESS_LEN) {
      throw new SignerError("invalid_argument", "allowedTarget must be 32 bytes");
    }
    w.bytes(target);
  }
  w.u64be(auth.chainId);
  return w.finish();
}

/** User signing preimage for a sponsored `PQ1` transaction (`baseSigningMessage(tx) || sponsorCommitment(auth)`). */
export function sponsoredSigningMessage(
  tx: TransactionFields,
  auth: SponsorAuthorization,
): Uint8Array {
  const w = new Writer();
  w.bytes(baseSigningMessage(tx));
  w.bytes(sponsorCommitment(auth));
  return w.finish();
}

/** The exact bytes the master signs for a `SessionKeyAuthorization` (`STELL_SESSKEY_V1 || ...`). */
export function sessionGrantMessage(grant: {
  masterAddress: Uint8Array;
  sessionPubkey: Uint8Array;
  validUntil: number | bigint;
  maxGasSpend: number | bigint;
  scope: number | bigint;
  maxValuePerTx: number | bigint;
  chainId: number | bigint;
}): Uint8Array {
  if (grant.masterAddress.length !== PQ_ADDRESS_LEN || grant.sessionPubkey.length !== PQ_ADDRESS_LEN) {
    throw new SignerError("invalid_argument", "session grant addresses must be 32 bytes");
  }
  const w = new Writer();
  w.bytes(SESSION_KEY_DOMAIN);
  w.u64be(grant.chainId);
  w.bytes(grant.masterAddress);
  w.bytes(grant.sessionPubkey);
  w.u64be(grant.validUntil);
  w.u64be(grant.maxGasSpend);
  w.u64be(grant.scope);
  w.u64be(grant.maxValuePerTx);
  return w.finish();
}

/** Exact bincode 1.3 encoding of `SessionKeyAuthorization` (`zkml.rs`). */
export function encodeSessionGrant(grant: SessionGrant): Uint8Array {
  if (grant.masterAddress.length !== PQ_ADDRESS_LEN || grant.sessionPubkey.length !== PQ_ADDRESS_LEN) {
    throw new SignerError("invalid_argument", "session grant addresses must be 32 bytes");
  }
  const w = new Writer();
  w.bytes(grant.masterAddress);
  w.bytes(grant.sessionPubkey);
  w.u64le(grant.validUntil);
  w.u64le(grant.maxGasSpend);
  w.u64le(grant.gasSpent ?? 0);
  w.u64le(grant.scope);
  w.u64le(grant.maxValuePerTx);
  w.u64le(grant.chainId);
  w.vec(grant.masterSignature);
  w.u8(pqSchemeToId(grant.masterScheme));
  w.u8(pqSchemeToId(grant.sessionScheme));
  if (grant.masterPubkey === undefined || grant.masterPubkey === null) {
    w.u8(0);
  } else {
    w.u8(1);
    w.vec(grant.masterPubkey);
  }
  if (grant.sessionPubkeyBytes === undefined || grant.sessionPubkeyBytes === null) {
    w.u8(0);
  } else {
    w.u8(1);
    w.vec(grant.sessionPubkeyBytes);
  }
  return w.finish();
}

/** Decode exact-fit bincode 1.3 `SessionKeyAuthorization` (only Falcon-512 `0x02` schemes accepted). */
export function decodeSessionGrant(bytes: Uint8Array): SessionGrant {
  const r = new Reader(bytes);
  const masterAddress = r.bytes(PQ_ADDRESS_LEN);
  const sessionPubkey = r.bytes(PQ_ADDRESS_LEN);
  const validUntil = r.u64le();
  const maxGasSpend = r.u64le();
  const gasSpent = r.u64le();
  const scope = r.u64le();
  const maxValuePerTx = r.u64le();
  const chainId = r.u64le();
  const masterSignature = r.vec(SPONSOR_AUTH_MAX_BYTES);
  const masterSchemeId = r.u8();
  const sessionSchemeId = r.u8();
  if (masterSchemeId !== 2 || sessionSchemeId !== 2) {
    throw new SignerError(
      "decode_error",
      `refused non-Falcon-512 session grant schemes (${masterSchemeId}, ${sessionSchemeId})`,
    );
  }
  const masterPkTag = r.u8();
  let masterPubkey: Uint8Array | null;
  if (masterPkTag === 0) {
    masterPubkey = null;
  } else if (masterPkTag === 1) {
    masterPubkey = r.vec(SPONSOR_AUTH_MAX_BYTES);
  } else {
    throw new SignerError("decode_error", `invalid Option<Vec<u8>> tag: ${masterPkTag}`);
  }
  const sessionPkTag = r.u8();
  let sessionPubkeyBytes: Uint8Array | null;
  if (sessionPkTag === 0) {
    sessionPubkeyBytes = null;
  } else if (sessionPkTag === 1) {
    sessionPubkeyBytes = r.vec(SPONSOR_AUTH_MAX_BYTES);
  } else {
    throw new SignerError("decode_error", `invalid Option<Vec<u8>> tag: ${sessionPkTag}`);
  }
  if (r.remaining() !== 0) {
    throw new SignerError("decode_error", "trailing bytes in SessionKeyAuthorization");
  }
  return {
    masterAddress,
    sessionPubkey,
    validUntil,
    maxGasSpend,
    gasSpent,
    scope,
    maxValuePerTx,
    chainId,
    masterSignature,
    masterScheme: 2,
    sessionScheme: 2,
    masterPubkey,
    sessionPubkeyBytes,
  };
}

/** `b"SESSION" || u32be(bincode(grant).length) || bincode(grant)` (matches `Transaction::delegation_commitment_bytes`). */
export function sessionCommitment(grant: SessionGrant): Uint8Array {
  const encoded = encodeSessionGrant(grant);
  const w = new Writer();
  w.bytes(SESSION_COMMITMENT_TAG);
  w.u32be(encoded.length);
  w.bytes(encoded);
  return w.finish();
}

/** Session key signing preimage (`baseSigningMessage(tx) || sessionCommitment(grant)`). */
export function sessionSigningMessage(tx: TransactionFields, grant: SessionGrant): Uint8Array {
  const w = new Writer();
  w.bytes(baseSigningMessage(tx));
  w.bytes(sessionCommitment(grant));
  return w.finish();
}

/** Encode an `SF1` session signature envelope: `666B sessionSig || "SF1" || bincode(grant)`. */
export function encodeSessionEnvelope(sessionSig: Uint8Array, grant: SessionGrant): Uint8Array {
  if (sessionSig.length !== WIRE_FALCON512_SIG_LEN) {
    throw new SignerError(
      "invalid_argument",
      `SF1 sessionSig must be ${WIRE_FALCON512_SIG_LEN} bytes, got ${sessionSig.length}`,
    );
  }
  const w = new Writer();
  w.bytes(sessionSig);
  w.bytes(SESSION_FALCON_SIG_TAG);
  w.bytes(encodeSessionGrant(grant));
  return w.finish();
}

/** Split an `SF1` session envelope (`666B sig || "SF1" || bincode(grant)`), returning `null` if not `SF1` or malformed. */
export function splitSessionEnvelope(blob: Uint8Array): SplitSessionEnvelopeResult | null {
  const tagLen = SESSION_FALCON_SIG_TAG.length;
  if (blob.length <= WIRE_FALCON512_SIG_LEN + tagLen) return null;
  if (
    blob[WIRE_FALCON512_SIG_LEN] !== SESSION_FALCON_SIG_TAG[0] ||
    blob[WIRE_FALCON512_SIG_LEN + 1] !== SESSION_FALCON_SIG_TAG[1] ||
    blob[WIRE_FALCON512_SIG_LEN + 2] !== SESSION_FALCON_SIG_TAG[2]
  ) {
    return null;
  }
  const grantBytes = blob.subarray(WIRE_FALCON512_SIG_LEN + tagLen);
  try {
    const grant = decodeSessionGrant(grantBytes);
    return {
      sessionSig: blob.subarray(0, WIRE_FALCON512_SIG_LEN),
      grant,
      grantBytes,
    };
  } catch {
    return null;
  }
}

/**
 * Exact `Transaction::compute_tx_hash` preimage for `PQ1`, `PQ1 + SP1`, and `SF1` envelopes
 * (where `signature` is the signature blob without the trailing `PRIORITY` envelope).
 */
export function computeTxHashPreimage(tx: TransactionFields, signature: Uint8Array): Uint8Array {
  const w = new Writer();
  w.bytes(baseSigningMessage(tx));

  const split = splitSponsorEnvelope(signature);
  if (split.malformed) {
    throw new SignerError("decode_error", "malformed SP1 sponsor envelope");
  }
  const innerSig = split.innerSig;

  const sf1 = splitSessionEnvelope(innerSig);
  if (sf1 !== null) {
    w.bytes(SESSION_COMMITMENT_TAG);
    w.u32be(sf1.grantBytes.length);
    w.bytes(sf1.grantBytes);
  }

  if (split.auth !== null) {
    w.bytes(sponsorCommitment(split.auth));
  }

  if (innerSig.length >= 3 && innerSig[0] === 0x50 && innerSig[1] === 0x51 && innerSig[2] === 0x31) {
    w.bytes(PQ_ENVELOPE_HASH_TAG);
    w.bytes(signature);
  }

  return w.finish();
}

/** Exact `Transaction::compute_tx_hash` (`sha256(computeTxHashPreimage(tx, signature))`). */
export function computeTxHash(tx: TransactionFields, signature: Uint8Array): Uint8Array {
  return sha256(computeTxHashPreimage(tx, signature));
}
