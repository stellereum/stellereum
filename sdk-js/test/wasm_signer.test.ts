import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  CHAIN_SIG_HEADER,
  FALCON512_PUBKEY_LEN,
  FALCON512_SECKEY_LEN,
  FALCON512_SIG_LEN,
  FALCON_PUBKEY_HEADER,
  FALCON_SECKEY_HEADER,
  PQ_ADDRESS_LEN,
  WasmFalconSigner,
  createWasmImports,
  encodeStl57Address,
  instantiateStellereumWasm,
  parseStellereumAddress,
  type StellereumWasmExports,
} from "../src/wasm_signer.ts";
import { StellereumClient } from "../src/client.ts";
import { SignerError } from "../src/errors.ts";
import { buildGovPropose } from "../src/builders.ts";
import {
  MAX_BLOCK_REWARD_NANO,
  MAX_MIN_GAS_LIMIT,
  MAX_PROPOSAL_TITLE_BYTES,
  MAX_VALIDATOR_BOND,
  MIN_VALIDATOR_BOND,
  PQ_ENVELOPE_HASH_TAG,
  SCOPE_ALL,
  SCOPE_TRANSFER,
  SESSION_COMMITMENT_TAG,
  SESSION_FALCON_SIG_TAG,
  SESSION_KEY_DOMAIN,
  SPONSOR_COMMITMENT_TAG,
  SPONSOR_FEE_DOMAIN,
  SPONSOR_SIG_TAG,
  baseSigningMessage,
  bytesToHex,
  computeTxHash,
  computeTxHashPreimage,
  decodeSessionGrant,
  decodeSponsorAuth,
  encodeGovAction,
  encodeSessionGrant,
  encodeSponsorAuth,
  encodeSponsorSuffix,
  finishUnsigned,
  hexToBytes,
  sessionCommitment,
  sessionGrantMessage,
  sessionSigningMessage,
  sha256,
  signingMessage,
  sponsorCommitment,
  sponsorMessage,
  sponsoredSigningMessage,
  splitSessionEnvelope,
  splitSponsorEnvelope,
  unsignedTxHash,
  type SponsorAuthorization,
  type TransactionFields,
} from "../src/wire.ts";
import type { FetchLike } from "../src/rpc.ts";

// ============================================================================
// Minimal valid WebAssembly binary builder (exercises real WebAssembly.instantiate)
// ============================================================================

function lebU32(value: number): number[] {
  const out: number[] = [];
  let v = value >>> 0;
  do {
    let byte = v & 0x7f;
    v >>>= 7;
    if (v !== 0) byte |= 0x80;
    out.push(byte);
  } while (v !== 0);
  return out;
}

/** Encode a non-negative `i32` as signed LEB128 for `i32.const`. */
function slebI32(value: number): number[] {
  const out: number[] = [];
  let v = value | 0;
  for (;;) {
    let byte = v & 0x7f;
    v >>= 7;
    const signBit = (byte & 0x40) !== 0;
    const done = (v === 0 && !signBit) || (v === -1 && signBit);
    if (!done) byte |= 0x80;
    out.push(byte);
    if (done) break;
  }
  return out;
}

function wasmStr(s: string): number[] {
  const b = [...new TextEncoder().encode(s)];
  return [...lebU32(b.length), ...b];
}

function wasmSection(id: number, payload: number[]): number[] {
  return [id, ...lebU32(payload.length), ...payload];
}

/**
 * Builds a minimal valid `wasm32` module implementing the `stellereum-wasm` ABI:
 * - Imports `env.stellereum_getrandom(i32, i32) -> i32`
 * - Exports `memory`, `alloc`, `dealloc`, `falcon_keygen`,
 *   `falcon_sign_with_entropy`, `falcon_verify`, `falcon_derive_address`.
 */
function buildRealTestWasmModule(): Uint8Array {
  // Type section (id = 1)
  const types = [
    [0x60, 1, 0x7f, 1, 0x7f], // 0: (i32) -> i32
    [0x60, 2, 0x7f, 0x7f, 0], // 1: (i32, i32) -> ()
    [0x60, 2, 0x7f, 0x7f, 1, 0x7f], // 2: (i32, i32) -> i32
    [0x60, 6, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f], // 3: 6xi32 -> i32
    [0x60, 8, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f], // 4: 8xi32 -> i32
  ];
  const typeSec = wasmSection(1, [...lebU32(types.length), ...types.flat()]);

  // Import section (id = 2): func 0 = env.stellereum_getrandom : type 2
  const importSec = wasmSection(2, [
    ...lebU32(1),
    ...wasmStr("env"),
    ...wasmStr("stellereum_getrandom"),
    0x00,
    ...lebU32(2),
  ]);

  // Function section (id = 3): funcs 1..=6
  const funcTypeIndices = [0, 1, 3, 4, 3, 3];
  const funcSec = wasmSection(3, [...lebU32(funcTypeIndices.length), ...funcTypeIndices]);

  // Memory section (id = 5): 1 page (64 KiB)
  const memSec = wasmSection(5, [...lebU32(1), 0x00, ...lebU32(2)]);

  // Global section (id = 6): global 0 mutable i32 bump = 1024
  const globalSec = wasmSection(6, [
    ...lebU32(1),
    0x7f,
    0x01,
    0x41,
    ...lebU32(1024),
    0x0b,
  ]);

  // Export section (id = 7)
  const exportsList: Array<[string, number, number]> = [
    ["memory", 0x02, 0],
    ["alloc", 0x00, 1],
    ["dealloc", 0x00, 2],
    ["falcon_keygen", 0x00, 3],
    ["falcon_sign_with_entropy", 0x00, 4],
    ["falcon_verify", 0x00, 5],
    ["falcon_derive_address", 0x00, 6],
  ];
  const exportSec = wasmSection(7, [
    ...lebU32(exportsList.length),
    ...exportsList.flatMap(([name, kind, idx]) => [...wasmStr(name), kind, ...lebU32(idx)]),
  ]);

  // Code section (id = 10)
  // func 1: alloc(len) -> old_bump; bump += len
  const bodyAlloc = [
    0x01, 0x01, 0x7f, // 1 local i32 (local 1)
    0x23, 0x00, // global.get 0
    0x22, 0x01, // local.tee 1
    0x20, 0x00, // local.get 0
    0x6a, // i32.add
    0x24, 0x00, // global.set 0
    0x20, 0x01, // local.get 1
    0x0b, // end
  ];
  // func 2: dealloc(ptr, len)
  const bodyDealloc = [0x00, 0x0b];
  // func 3: falcon_keygen(seedPtr, seedLen, pkPtr, pkLen, skPtr, skLen)
  const bodyKeygen = [
    0x00,
    0x20, 0x02, 0x41, ...slebI32(FALCON_PUBKEY_HEADER), 0x3a, 0x00, 0x00, // pk[0] = 0x09
    0x20, 0x04, 0x41, ...slebI32(FALCON_SECKEY_HEADER), 0x3a, 0x00, 0x00, // sk[0] = 0x59
    0x41, ...slebI32(0), // return 0
    0x0b,
  ];
  // func 4: falcon_sign_with_entropy(..., sigOutPtr (6), sigOutLen (7))
  // Calls stellereum_getrandom(sigOutPtr, 41) then writes 0x29 to sigOutPtr[0].
  const bodySign = [
    0x00,
    0x20, 0x06, // sigOutPtr
    0x41, ...slebI32(41), // 41 bytes (header + 40-byte nonce)
    0x10, 0x00, // call stellereum_getrandom
    0x1a, // drop return code
    0x20, 0x06, 0x41, ...slebI32(CHAIN_SIG_HEADER), 0x3a, 0x00, 0x00, // sig[0] = 0x29
    0x41, ...slebI32(0), // return 0
    0x0b,
  ];
  // func 5: falcon_verify(...) -> 1
  const bodyVerify = [0x00, 0x41, ...slebI32(1), 0x0b];
  // func 6: falcon_derive_address(pkPtr, pkLen, saltPtr, saltLen, addrOutPtr (4), addrOutLen (5))
  const bodyDerive = [
    0x00,
    0x20, 0x04, 0x41, ...slebI32(0x42), 0x3a, 0x00, 0x00, // addr[0] = 0x42
    0x20, 0x04, 0x41, ...slebI32(0x7f), 0x3a, 0x00, 31, // addr[31] = 0x7f
    0x41, ...slebI32(0), // return 0
    0x0b,
  ];

  const bodies = [bodyAlloc, bodyDealloc, bodyKeygen, bodySign, bodyVerify, bodyDerive];
  const codeSec = wasmSection(10, [
    ...lebU32(bodies.length),
    ...bodies.flatMap((b) => [...lebU32(b.length), ...b]),
  ]);

  return Uint8Array.from([
    0x00, 0x61, 0x73, 0x6d, // magic \0asm
    0x01, 0x00, 0x00, 0x00, // version 1
    ...typeSec,
    ...importSec,
    ...funcSec,
    ...memSec,
    ...globalSec,
    ...exportSec,
    ...codeSec,
  ]);
}

// ============================================================================
// Independent single-chunk BLAKE3 reference (input <= 1024 bytes)
// ============================================================================

const B3_IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const B3_MSG_SCHEDULE: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
  [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
  [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
  [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
  [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
  [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

const B3_CHUNK_START = 1;
const B3_CHUNK_END = 2;
const B3_ROOT = 8;

function b3Rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function b3G(s: Uint32Array, a: number, b: number, c: number, d: number, mx: number, my: number): void {
  s[a] = (s[a]! + s[b]! + mx) >>> 0;
  s[d] = b3Rotr((s[d]! ^ s[a]!) >>> 0, 16);
  s[c] = (s[c]! + s[d]!) >>> 0;
  s[b] = b3Rotr((s[b]! ^ s[c]!) >>> 0, 12);
  s[a] = (s[a]! + s[b]! + my) >>> 0;
  s[d] = b3Rotr((s[d]! ^ s[a]!) >>> 0, 8);
  s[c] = (s[c]! + s[d]!) >>> 0;
  s[b] = b3Rotr((s[b]! ^ s[c]!) >>> 0, 7);
}

function b3Compress(
  cv: Uint32Array,
  block: Uint32Array,
  counter: bigint,
  blockLen: number,
  flags: number,
): Uint32Array {
  const s = new Uint32Array([
    cv[0]!, cv[1]!, cv[2]!, cv[3]!,
    cv[4]!, cv[5]!, cv[6]!, cv[7]!,
    B3_IV[0]!, B3_IV[1]!, B3_IV[2]!, B3_IV[3]!,
    Number(counter & 0xffff_ffffn),
    Number((counter >> 32n) & 0xffff_ffffn),
    blockLen >>> 0,
    flags >>> 0,
  ]);
  for (let round = 0; round < 7; round++) {
    const m = B3_MSG_SCHEDULE[round]!;
    b3G(s, 0, 4, 8, 12, block[m[0]!]!, block[m[1]!]!);
    b3G(s, 1, 5, 9, 13, block[m[2]!]!, block[m[3]!]!);
    b3G(s, 2, 6, 10, 14, block[m[4]!]!, block[m[5]!]!);
    b3G(s, 3, 7, 11, 15, block[m[6]!]!, block[m[7]!]!);
    b3G(s, 0, 5, 10, 15, block[m[8]!]!, block[m[9]!]!);
    b3G(s, 1, 6, 11, 12, block[m[10]!]!, block[m[11]!]!);
    b3G(s, 2, 7, 8, 13, block[m[12]!]!, block[m[13]!]!);
    b3G(s, 3, 4, 9, 14, block[m[14]!]!, block[m[15]!]!);
  }
  for (let i = 0; i < 8; i++) {
    s[i] = (s[i]! ^ s[i + 8]!) >>> 0;
    s[i + 8] = (s[i + 8]! ^ cv[i]!) >>> 0;
  }
  return s;
}

function b3BlockWords(block: Uint8Array): Uint32Array {
  const padded = new Uint8Array(64);
  padded.set(block);
  const view = new DataView(padded.buffer);
  const words = new Uint32Array(16);
  for (let i = 0; i < 16; i++) words[i] = view.getUint32(i * 4, true);
  return words;
}

/** BLAKE3 for inputs `<= 1024` bytes (single chunk), enough for the 924-byte address preimage. */
function blake3SingleChunk(input: Uint8Array): Uint8Array {
  if (input.length > 1024) throw new RangeError("blake3SingleChunk supports <= 1024 bytes");
  const nBlocks = input.length === 0 ? 1 : Math.ceil(input.length / 64);
  let cv = B3_IV.slice();
  let out = new Uint32Array(16);
  for (let i = 0; i < nBlocks; i++) {
    const start = i * 64;
    const block = input.subarray(start, Math.min(start + 64, input.length));
    let flags = 0;
    if (i === 0) flags |= B3_CHUNK_START;
    if (i === nBlocks - 1) flags |= B3_CHUNK_END | B3_ROOT;
    out = b3Compress(cv, b3BlockWords(block), 0n, block.length, flags);
    if (i !== nBlocks - 1) cv = out.subarray(0, 8);
  }
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  for (let i = 0; i < 8; i++) view.setUint32(i * 4, out[i]!, true);
  return bytes;
}

const B3_OFFICIAL_EMPTY = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
const B3_OFFICIAL_ABC = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";
// 1024-byte input `i % 251`, 16 blocks in a single chunk (official vector).
const B3_OFFICIAL_1024 = "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7";

/** `BLAKE3("STL_ADDR_V4" || 0x02 || pubkey || salt)`. */
function referenceDeriveAddress(pubkey: Uint8Array, salt: Uint8Array): Uint8Array {
  const domain = new TextEncoder().encode("STL_ADDR_V4");
  const preimage = new Uint8Array(domain.length + 1 + pubkey.length + salt.length);
  preimage.set(domain, 0);
  preimage[domain.length] = 0x02;
  preimage.set(pubkey, domain.length + 1);
  preimage.set(salt, domain.length + 1 + pubkey.length);
  return blake3SingleChunk(preimage);
}

// ============================================================================
// Instrumented JS-backed WASM harness to assert zeroization & full signing flow
// ============================================================================

interface TrackedAllocation {
  ptr: number;
  len: number;
  zeroedBeforeDealloc: boolean;
}

function createInstrumentedWasm(options: {
  verifyResult?: number;
  overrideSigHeader?: number;
} = {}): {
  exports: StellereumWasmExports;
  allocations: TrackedAllocation[];
  entropyCalls: number[];
  lastSignedMsg?: Uint8Array;
} {
  const memory = new WebAssembly.Memory({ initial: 4 });
  let bump = 1024;
  const allocations: TrackedAllocation[] = [];
  const entropyCalls: number[] = [];
  const state: {
    exports: StellereumWasmExports;
    allocations: TrackedAllocation[];
    entropyCalls: number[];
    lastSignedMsg?: Uint8Array;
  } = {
    exports: null as unknown as StellereumWasmExports,
    allocations,
    entropyCalls,
  };

  const imports = createWasmImports(
    () => memory,
    (buf) => {
      entropyCalls.push(buf.length);
      return globalThis.crypto.getRandomValues(buf);
    },
  );
  const envImport = imports.env as { stellereum_getrandom: (ptr: number, len: number) => number };

  const exports: StellereumWasmExports = {
    memory,
    alloc(len: number): number {
      if (len <= 0) return 0;
      const ptr = bump;
      bump += len;
      new Uint8Array(memory.buffer, ptr, len).fill(0);
      allocations.push({ ptr, len, zeroedBeforeDealloc: false });
      return ptr;
    },
    dealloc(ptr: number, len: number): void {
      const view = new Uint8Array(memory.buffer, ptr, len);
      const isZeroed = view.every((b) => b === 0);
      const entry = allocations.find((a) => a.ptr === ptr && a.len === len);
      if (entry) entry.zeroedBeforeDealloc = isZeroed;
    },
    falcon_keygen(seedPtr, seedLen, pkOutPtr, pkOutLen, skOutPtr, skOutLen): number {
      if (pkOutLen < FALCON512_PUBKEY_LEN || skOutLen < FALCON512_SECKEY_LEN) return -2;
      const seed = seedLen > 0 ? new Uint8Array(memory.buffer, seedPtr, seedLen) : new Uint8Array(32);
      const pk = new Uint8Array(memory.buffer, pkOutPtr, FALCON512_PUBKEY_LEN);
      const sk = new Uint8Array(memory.buffer, skOutPtr, FALCON512_SECKEY_LEN);
      pk.fill(0x12);
      pk[0] = FALCON_PUBKEY_HEADER;
      pk[1] = seed[0] ?? 1;
      sk.fill(0x34);
      sk[0] = FALCON_SECKEY_HEADER;
      sk[1] = seed[0] ?? 1;
      return 0;
    },
    falcon_sign_with_entropy(
      _skPtr,
      skLen,
      msgPtr,
      msgLen,
      entPtr,
      entLen,
      sigOutPtr,
      sigOutLen,
    ): number {
      if (skLen !== FALCON512_SECKEY_LEN || sigOutLen < FALCON512_SIG_LEN) return -2;
      const msg = new Uint8Array(memory.buffer, msgPtr, msgLen);
      state.lastSignedMsg = new Uint8Array(msg);
      const ent = new Uint8Array(memory.buffer, entPtr, entLen);
      // Simulate getrandom call into JS crypto.getRandomValues
      const noncePtr = exports.alloc(40);
      const rc = envImport.stellereum_getrandom(noncePtr, 40);
      if (rc !== 0) return -7;
      const nonce = new Uint8Array(new Uint8Array(memory.buffer, noncePtr, 40));
      new Uint8Array(memory.buffer, noncePtr, 40).fill(0);
      exports.dealloc(noncePtr, 40);

      const digest = createHash("sha256").update(msg).update(ent).digest();
      const sig = new Uint8Array(memory.buffer, sigOutPtr, FALCON512_SIG_LEN);
      sig.fill(0);
      sig[0] = options.overrideSigHeader ?? CHAIN_SIG_HEADER;
      sig.set(nonce, 1);
      sig.set(digest, 41);
      return 0;
    },
    falcon_verify(_pkPtr, pkLen, _msgPtr, _msgLen, sigPtr, sigLen): number {
      if (options.verifyResult !== undefined) return options.verifyResult;
      if (pkLen !== FALCON512_PUBKEY_LEN || sigLen !== FALCON512_SIG_LEN) return 0;
      const sig = new Uint8Array(memory.buffer, sigPtr, sigLen);
      return sig[0] === CHAIN_SIG_HEADER ? 1 : 0;
    },
    falcon_derive_address(pkPtr, pkLen, saltPtr, saltLen, addrOutPtr, addrOutLen): number {
      if (pkLen !== FALCON512_PUBKEY_LEN || addrOutLen < PQ_ADDRESS_LEN) return -2;
      const pk = new Uint8Array(memory.buffer, pkPtr, pkLen);
      const salt = saltLen === 16 ? new Uint8Array(memory.buffer, saltPtr, 16) : new Uint8Array(16);
      const h = referenceDeriveAddress(pk, salt);
      new Uint8Array(memory.buffer, addrOutPtr, PQ_ADDRESS_LEN).set(h);
      return 0;
    },
  };
  state.exports = exports;
  return state;
}

// ============================================================================
// Tests
// ============================================================================

test("WebAssembly.instantiate loads WASM binary, supplies crypto.getRandomValues, and zeroizes memory", async () => {
  const wasmBytes = buildRealTestWasmModule();
  const entropyCalls: number[] = [];
  const { instance, exports } = await instantiateStellereumWasm(wasmBytes, {
    getRandomValues: (target) => {
      entropyCalls.push(target.length);
      return globalThis.crypto.getRandomValues(target);
    },
  });

  const kp = WasmFalconSigner.generateKeypair(instance, new Uint8Array(32).fill(7));
  assert.equal(kp.publicKey.length, FALCON512_PUBKEY_LEN);
  assert.equal(kp.publicKey[0], FALCON_PUBKEY_HEADER);
  assert.equal(kp.secretKey.length, FALCON512_SECKEY_LEN);
  assert.equal(kp.secretKey[0], FALCON_SECKEY_HEADER);
  assert.match(kp.addressStl57, /^Stl57/);

  const signer = new WasmFalconSigner(instance, {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
    getRandomValues: (target) => {
      entropyCalls.push(target.length);
      return globalThis.crypto.getRandomValues(target);
    },
  });

  const resp = await signer.sign({
    tx: {
      kind: "transfer",
      to: "22".repeat(32),
      amount: 500,
      nonce: 3,
      chain_id: 5757,
    },
  });

  assert.equal(resp.ok, true);
  assert.equal(resp.from, kp.address);
  assert.equal(resp.from_stl57, kp.addressStl57);
  assert.equal(resp.to, "22".repeat(32));
  assert.equal(resp.nonce, 3);
  assert.equal(resp.chain_id, 5757);
  assert.equal(resp.activation, true);
  assert.equal(resp.envelope, "pq1-explicit");

  // Both JS signMessage (32B) and WASM stellereum_getrandom (41B) drew entropy!
  assert.ok(entropyCalls.includes(32), "expected JS entropy draw");
  assert.ok(entropyCalls.includes(41), "expected WASM env.stellereum_getrandom call");

  // Verify the allocated WASM heap region [1024..8192) was zeroized on dealloc.
  const heapSlice = new Uint8Array(exports.memory.buffer, 1024, 4096);
  assert.ok(
    heapSlice.every((b) => b === 0),
    "temporary WASM memory must be zeroized before dealloc",
  );
});

test("WasmFalconSigner signs transfers, produces valid PQ1 envelope + tx_hash, and zeroizes every alloc", async () => {
  const instrumented = createInstrumentedWasm();
  const pk = new Uint8Array(FALCON512_PUBKEY_LEN).fill(0x01);
  pk[0] = FALCON_PUBKEY_HEADER;
  const sk = new Uint8Array(FALCON512_SECKEY_LEN).fill(0x02);
  sk[0] = FALCON_SECKEY_HEADER;

  const signer = new WasmFalconSigner(instrumented.exports, {
    publicKey: pk,
    secretKey: sk,
  });

  const toHex = "ab".repeat(32);
  const resp = await signer.sign({
    tx: {
      kind: "transfer",
      to: toHex,
      amount: 123_456,
      nonce: 9,
      chain_id: 5757,
      priority_fee_per_gas: 42,
    },
  });

  assert.equal(resp.ok, true);
  assert.equal(resp.nonce, 9);
  assert.equal(resp.chain_id, 5757);
  assert.equal(resp.gas_limit, 280_000 + 45_000 + 42);
  assert.equal(resp.activation, true);
  assert.equal(resp.envelope, "pq1-explicit");
  assert.equal(resp.tx_hash.length, 64);

  // Verify the exact signing message passed into WASM matches sdk-js wire.signingMessage.
  const expectedMsg = signingMessage(
    {
      from: hexToBytes(signer.address),
      to: hexToBytes(toHex),
      amount: 123_456,
      gasLimit: 280_000 + 45_000 + 42,
      nonce: 9,
      sourceShard: 0,
      targetShard: 0,
      payload: new Uint8Array(8),
      priorityFeePerGas: 42,
    },
    5757,
  );
  assert.deepEqual(instrumented.lastSignedMsg, expectedMsg);

  // Verify PQ1 magic inside wire bytes and 0x29 signature header.
  const wire = hexToBytes(resp.tx_hex);
  const pq1Offset = 32 + 32 + 8 + 8 + 8 + 4 + 4 + 8;
  assert.equal(new TextDecoder().decode(wire.subarray(pq1Offset, pq1Offset + 3)), "PQ1");
  assert.equal(wire[pq1Offset + 3], 2); // Falcon-512
  assert.equal(wire[pq1Offset + 4], 0); // explicit
  const sigOffset = pq1Offset + 3 + 1 + 1 + 2 + 897 + 16 + 2;
  assert.equal(wire[sigOffset], CHAIN_SIG_HEADER);

  // Every single allocation was zeroized before dealloc.
  assert.ok(instrumented.allocations.length > 0);
  for (const alloc of instrumented.allocations) {
    assert.equal(
      alloc.zeroedBeforeDealloc,
      true,
      `allocation ptr=${alloc.ptr} len=${alloc.len} was not zeroized before dealloc`,
    );
  }
  assert.ok(instrumented.entropyCalls.includes(40));
});

test("WasmFalconSigner supports implicit PQ1 envelopes, prepared txs, signDigest, and StellereumClient", async () => {
  const instrumented = createInstrumentedWasm();
  const kp = WasmFalconSigner.generateKeypair(instrumented.exports, new Uint8Array(32).fill(5));
  const signer = new WasmFalconSigner(instrumented.exports, {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
  });

  // 1. Implicit transfer omits public key and activation surcharge
  const implicitResp = await signer.sign({
    tx: {
      kind: "transfer",
      to: signer.addressStl57,
      amount: 10,
      nonce: 1,
      implicit: true,
    },
  });
  assert.equal(implicitResp.activation, false);
  assert.equal(implicitResp.envelope, "pq1-implicit");
  assert.equal(implicitResp.gas_limit, 280_000);
  assert.equal(implicitResp.to, signer.address);

  // 2. Prepared tx assembled by builders.ts
  const unsignedGov = buildGovPropose({
    from: signer.address,
    proposalId: 1,
    title: "wasm governance proposal",
    action: { type: "signal", text: "hello" },
    heightObserved: 100,
    nonce: 2,
  });
  const preparedResp = await signer.sign({
    tx: {
      kind: "prepared",
      tx_hex: unsignedGov.txHex,
      chain_id: unsignedGov.chainId,
    },
  });
  assert.equal(preparedResp.nonce, 2);
  assert.equal(preparedResp.chain_id, 5757);

  // Refuses prepared tx with mismatched sender
  const wrongFrom = buildGovPropose({
    from: "ff".repeat(32),
    proposalId: 1,
    title: "wrong sender",
    action: { type: "signal", text: "nope" },
    heightObserved: 100,
    nonce: 2,
  });
  await assert.rejects(
    signer.sign({ tx: { kind: "prepared", tx_hex: wrongFrom.txHex } }),
    (err: unknown) => err instanceof SignerError && err.code === "invalid_argument",
  );

  // 3. signDigest
  const digestSigHex = await signer.signDigest("aa".repeat(32));
  const digestSig = hexToBytes(digestSigHex);
  assert.equal(digestSig.length, FALCON512_SIG_LEN);
  assert.equal(digestSig[0], CHAIN_SIG_HEADER);
  assert.equal(signer.verify(hexToBytes("aa".repeat(32)), digestSig), true);

  // 4. StellereumClient integration
  const fetchMock: FetchLike = async (_url, init) => {
    const req = JSON.parse(String(init?.body ?? "{}")) as { id: number; method: string };
    let result: unknown = null;
    if (req.method === "stell_chainId") result = 5757;
    else if (req.method === "stell_getBalance") result = { balance: "5000000", nonce: 11 };
    else if (req.method === "stell_baseFee") result = { base_fee: "280000" };
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ jsonrpc: "2.0", id: req.id, result }),
      json: async () => ({ jsonrpc: "2.0", id: req.id, result }),
    };
  };
  const client = new StellereumClient({
    url: "http://node.test",
    fetch: fetchMock,
    signer,
  });
  const signed = await client.transfer("22".repeat(32), 777);
  assert.equal(signed.from, signer.address);
  assert.equal(signed.fromStl57, signer.addressStl57);
  assert.equal(signed.nonce, 11);
  assert.equal(signed.envelope, "pq1-explicit");
});

test("WasmFalconSigner fails closed on non-0x29 header, self-verify failure, and destroy()", async () => {
  const badHeaderWasm = createInstrumentedWasm({ overrideSigHeader: 0x59 });
  const kp = WasmFalconSigner.generateKeypair(badHeaderWasm.exports, new Uint8Array(32).fill(9));
  const badHeaderSigner = new WasmFalconSigner(badHeaderWasm.exports, {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
  });
  await assert.rejects(
    badHeaderSigner.sign({ tx: { kind: "transfer", to: "22".repeat(32), amount: 1 } }),
    (err: unknown) => err instanceof SignerError && err.code === "signing_failed",
  );

  const badVerifyWasm = createInstrumentedWasm({ verifyResult: 0 });
  const badVerifySigner = new WasmFalconSigner(badVerifyWasm.exports, {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
  });
  await assert.rejects(
    badVerifySigner.sign({ tx: { kind: "transfer", to: "22".repeat(32), amount: 1 } }),
    (err: unknown) => err instanceof SignerError && err.code === "verification_failed",
  );

  // destroy() wipes JS secretKey and refuses subsequent signing
  const goodWasm = createInstrumentedWasm();
  const signer = new WasmFalconSigner(goodWasm.exports, {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
  });
  signer.destroy();
  await assert.rejects(
    signer.sign({ tx: { kind: "transfer", to: "22".repeat(32), amount: 1 } }),
    (err: unknown) => err instanceof SignerError && err.code === "destroyed",
  );
  await assert.rejects(
    signer.signDigest("11".repeat(32)),
    (err: unknown) => err instanceof SignerError && err.code === "destroyed",
  );
});

test("WasmFalconSigner fails closed when the WASM module or a required export is missing", async () => {
  // A syntactically valid module with no exports at all.
  const emptyModule = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  await assert.rejects(
    instantiateStellereumWasm(emptyModule),
    (err: unknown) => err instanceof SignerError && err.code === "invalid_wasm",
  );

  // Missing `falcon_sign_with_entropy` export must be rejected at construction.
  const incomplete = createInstrumentedWasm().exports as unknown as Record<string, unknown>;
  const withoutSign = { ...incomplete };
  delete withoutSign["falcon_sign_with_entropy"];
  const pk = new Uint8Array(FALCON512_PUBKEY_LEN);
  pk[0] = FALCON_PUBKEY_HEADER;
  const sk = new Uint8Array(FALCON512_SECKEY_LEN);
  sk[0] = FALCON_SECKEY_HEADER;
  assert.throws(
    () =>
      new WasmFalconSigner(withoutSign as unknown as StellereumWasmExports, {
        publicKey: pk,
        secretKey: sk,
      }),
    (err: unknown) => err instanceof SignerError && err.code === "invalid_wasm",
  );

  // A throwing entropy source also fails closed (never silently signs with zero entropy).
  const wasm = createInstrumentedWasm();
  const signer = new WasmFalconSigner(wasm.exports, {
    publicKey: pk,
    secretKey: sk,
    getRandomValues: () => {
      throw new Error("no entropy");
    },
  });
  await assert.rejects(signer.sign({ tx: { kind: "transfer", to: "22".repeat(32), amount: 1 } }));
});

test("Stl57 address encode/parse roundtrip and checksum rejection", () => {
  const addr = new Uint8Array(32).fill(0xab);
  const stl57 = encodeStl57Address(addr);
  assert.ok(stl57.startsWith("Stl57"));
  assert.deepEqual(parseStellereumAddress(stl57), addr);
  assert.deepEqual(parseStellereumAddress(`stl57${stl57.slice(5)}`), addr);
  assert.deepEqual(parseStellereumAddress(`0x${bytesToHex(addr)}`), addr);

  // Flip last character -> checksum mismatch
  const last = stl57.at(-1)!;
  const tampered = `${stl57.slice(0, -1)}${last === "9" ? "8" : "9"}`;
  assert.throws(
    () => parseStellereumAddress(tampered),
    (err: unknown) => err instanceof SignerError && err.code === "invalid_address",
  );
});

test("address derivation matches the STL_ADDR_V4 known vector (independent BLAKE3 parity)", () => {
  // The in-test reference implementation must match official BLAKE3 vectors first.
  assert.equal(bytesToHex(blake3SingleChunk(new Uint8Array())), B3_OFFICIAL_EMPTY);
  assert.equal(bytesToHex(blake3SingleChunk(new TextEncoder().encode("abc"))), B3_OFFICIAL_ABC);
  const multiBlockInput = new Uint8Array(1024);
  for (let i = 0; i < multiBlockInput.length; i++) multiBlockInput[i] = i % 251;
  assert.equal(bytesToHex(blake3SingleChunk(multiBlockInput)), B3_OFFICIAL_1024);

  const wasm = createInstrumentedWasm();
  const pk = new Uint8Array(FALCON512_PUBKEY_LEN); // 0x09 header + 896 zero coefficients
  pk[0] = FALCON_PUBKEY_HEADER;
  const sk = new Uint8Array(FALCON512_SECKEY_LEN).fill(0x02);
  sk[0] = FALCON_SECKEY_HEADER;

  const signer = new WasmFalconSigner(wasm.exports, { publicKey: pk, secretKey: sk });
  // Known vector: BLAKE3("STL_ADDR_V4" || 0x02 || 0x09||0^896 || 0^16)
  assert.equal(
    signer.address,
    "c523252273b8ab4dd04c3b9ace49e258767e16572697cf0bfc2a9c47f3d76b68",
  );
  assert.equal(signer.addressStl57, encodeStl57Address(hexToBytes(signer.address)));
  assert.deepEqual(
    WasmFalconSigner.deriveAddress(wasm.exports, pk),
    hexToBytes(signer.address),
  );

  // Non-zero 16-byte salt changes the address deterministically (known vector).
  const saltedSigner = new WasmFalconSigner(wasm.exports, {
    publicKey: pk,
    secretKey: sk,
    salt: new Uint8Array(16).fill(0x99),
  });
  assert.equal(
    saltedSigner.address,
    "cc1f0e87cfe98f89a870256336b4f749f2f2451da565c02005f345209594bc5f",
  );
  assert.notEqual(saltedSigner.address, signer.address);
});

test("createWasmImports chunks >64KiB entropy reads and validates pointers", () => {
  const memory = new WebAssembly.Memory({ initial: 3 });
  const chunks: number[] = [];
  const imports = createWasmImports(
    () => memory,
    (buf) => {
      chunks.push(buf.length);
      buf.fill(0x5a);
      return buf;
    },
  );
  const fn = (imports.env as { stellereum_getrandom: (p: number, l: number) => number })
    .stellereum_getrandom;

  assert.equal(fn(1024, 70_000), 0);
  assert.deepEqual(chunks, [65_536, 4_464]);
  assert.equal(new Uint8Array(memory.buffer, 1024, 70_000).every((b) => b === 0x5a), true);

  // Invalid pointer or negative length returns -1
  assert.equal(fn(0, 32), -1);
  assert.equal(fn(1024, -1), -1);
  assert.equal(fn(1024, 0), 0);
});

test("WasmFalconSigner signs contract_call_raw for *_pq raw calldata entrypoints", async () => {
  const wasm = createInstrumentedWasm();
  const kp = WasmFalconSigner.generateKeypair(wasm.exports);
  const signer = new WasmFalconSigner(wasm.exports, kp);
  const contract = "99".repeat(32);
  const calldataHex = "2a00000000000000" + "ab".repeat(32);

  const resp = await signer.sign({
    tx: {
      kind: "contract_call_raw",
      contract,
      method: "set_target_pq",
      args: [42],
      calldata_hex: calldataHex,
      value: 7,
      nonce: 3,
      chain_id: 5757,
    },
  });

  assert.equal(resp.ok, true);
  assert.equal(resp.to, contract);
  assert.equal(resp.nonce, 3);
  assert.equal(resp.chain_id, 5757);
  const txBytes = hexToBytes(resp.tx_hex);
  const cdNeedle = hexToBytes(calldataHex);
  // Confirm the raw calldata bytes appear verbatim in the signed payload without ABI header
  let found = false;
  for (let i = 0; i <= txBytes.length - cdNeedle.length; i++) {
    if (cdNeedle.every((b, j) => txBytes[i + j] === b)) {
      found = true;
      break;
    }
  }
  assert.equal(found, true);
});

// ============================================================================
// Pure-TS SHA-256 parity, GovAction bounds, generate().destroy(), & real WASM
// ============================================================================

function rlpBytesTest(value: Uint8Array): Uint8Array {
  if (value.length === 1 && value[0]! < 0x80) return value;
  const len = value.length;
  if (len < 56) return Uint8Array.of(0x80 + len, ...value);
  const lenBytes = bigIntBytesTest(BigInt(len));
  return Uint8Array.of(0x80 + 55 + lenBytes.length, ...lenBytes, ...value);
}

function rlpListTest(items: Uint8Array[]): Uint8Array {
  const payload = items.flatMap((item) => [...item]);
  if (payload.length < 56) return Uint8Array.of(0xc0 + payload.length, ...payload);
  const lenBytes = bigIntBytesTest(BigInt(payload.length));
  return Uint8Array.of(0xf7 + lenBytes.length, ...lenBytes, ...payload);
}

function bigIntBytesTest(value: bigint): Uint8Array {
  if (value === 0n) return new Uint8Array();
  const out: number[] = [];
  let v = value;
  while (v > 0n) {
    out.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  return Uint8Array.from(out);
}

function legacyEvmTxHex(nonce: number, valueWei: bigint, chainId: number): string {
  const to = Uint8Array.from({ length: 20 }, (_, i) => i + 1);
  const v = BigInt(chainId) * 2n + 35n;
  const raw = rlpListTest([
    rlpBytesTest(bigIntBytesTest(BigInt(nonce))),
    rlpBytesTest(bigIntBytesTest(20_000_000_000n)),
    rlpBytesTest(bigIntBytesTest(21_000n)),
    rlpBytesTest(to),
    rlpBytesTest(bigIntBytesTest(valueWei)),
    rlpBytesTest(new Uint8Array()),
    rlpBytesTest(bigIntBytesTest(v)),
    rlpBytesTest(new Uint8Array(32).fill(1)),
    rlpBytesTest(new Uint8Array(32).fill(1)),
  ]);
  return bytesToHex(raw);
}

test("pure-TS sha256 matches FIPS 180-4 vectors and node:crypto across block boundaries", () => {
  assert.equal(
    bytesToHex(sha256(new Uint8Array())),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  );
  assert.equal(
    bytesToHex(sha256(new TextEncoder().encode("abc"))),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
  assert.equal(
    bytesToHex(sha256(new TextEncoder().encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  );

  for (const len of [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 129, 1024, 4096]) {
    const input = Uint8Array.from({ length: len }, (_, i) => (i * 131 + 17) & 0xff);
    const got = sha256(input);
    const expected = new Uint8Array(createHash("sha256").update(input).digest());
    assert.deepEqual(got, expected, `sha256 mismatch at length ${len}`);
  }
});

test("encodeGovAction enforces parameter bounds matching stellereum-sdk/src/governance.rs", () => {
  assert.throws(
    () => encodeGovAction({ type: "set_min_validator_bond", value: MIN_VALIDATOR_BOND - 1n }),
    /out of bounds/,
  );
  assert.throws(
    () => encodeGovAction({ type: "set_min_validator_bond", value: MAX_VALIDATOR_BOND + 1n }),
    /out of bounds/,
  );
  assert.doesNotThrow(() =>
    encodeGovAction({ type: "set_min_validator_bond", value: MIN_VALIDATOR_BOND }),
  );

  assert.throws(
    () => encodeGovAction({ type: "set_block_reward", value: MAX_BLOCK_REWARD_NANO + 1n }),
    /out of bounds/,
  );
  assert.doesNotThrow(() =>
    encodeGovAction({ type: "set_block_reward", value: MAX_BLOCK_REWARD_NANO }),
  );

  assert.throws(
    () => encodeGovAction({ type: "set_min_gas_limit", value: 0 }),
    /out of bounds/,
  );
  assert.throws(
    () => encodeGovAction({ type: "set_min_gas_limit", value: MAX_MIN_GAS_LIMIT + 1 }),
    /out of bounds/,
  );
  assert.doesNotThrow(() =>
    encodeGovAction({ type: "set_min_gas_limit", value: MAX_MIN_GAS_LIMIT }),
  );

  assert.throws(
    () =>
      encodeGovAction({
        type: "software_upgrade",
        name: "../escape",
        height: 1,
        sha256: "11".repeat(32),
      }),
    /unsafe characters/,
  );
  assert.throws(
    () =>
      encodeGovAction({
        type: "software_upgrade",
        name: "a".repeat(65),
        height: 1,
        sha256: "11".repeat(32),
      }),
    /invalid/,
  );
  assert.throws(
    () =>
      encodeGovAction({
        type: "software_upgrade",
        name: "v6.1",
        height: 0,
        sha256: "11".repeat(32),
      }),
    /invalid/,
  );
  assert.throws(
    () =>
      encodeGovAction({
        type: "software_upgrade",
        name: "v6.1",
        height: 10,
        sha256: "00".repeat(32),
      }),
    /invalid/,
  );
  assert.doesNotThrow(() =>
    encodeGovAction({
      type: "software_upgrade",
      name: "v6.1-rc_2",
      height: 10,
      sha256: "ab".repeat(32),
    }),
  );
});

test("WasmFalconSigner.generate .destroy() contract and gov_propose/evm_carrier guards", async () => {
  const wasmBytes = buildRealTestWasmModule();
  const { signer: s1, keypair: kp1 } = await WasmFalconSigner.generate(wasmBytes, {
    seed: new Uint8Array(32).fill(0x21),
  });
  assert.ok(kp1.secretKey.some((b) => b !== 0));
  // Destroying keypair wipes kp1.secretKey without breaking signer
  kp1.destroy();
  assert.ok(kp1.secretKey.every((b) => b === 0));
  const okResp = await s1.sign({ tx: { kind: "transfer", to: s1.addressStl57, amount: 1 } });
  assert.equal(okResp.ok, true);
  s1.destroy();

  // Destroying signer also wipes the generated keypair's secretKey
  const { signer: s2, keypair: kp2 } = await WasmFalconSigner.generate(wasmBytes, {
    seed: new Uint8Array(32).fill(0x22),
  });
  assert.ok(kp2.secretKey.some((b) => b !== 0));
  s2.destroy();
  assert.ok(kp2.secretKey.every((b) => b === 0));

  // Re-instantiate for validation checks
  const { signer } = await WasmFalconSigner.generate(wasmBytes, {
    seed: new Uint8Array(32).fill(0x23),
  });

  // gov_propose rejects > 256 UTF-8 byte title
  await assert.rejects(
    signer.sign({
      tx: {
        kind: "gov_propose",
        proposal_id: 1,
        title: "a".repeat(MAX_PROPOSAL_TITLE_BYTES + 1),
        action: { type: "signal", text: "ok" },
        height_observed: 10,
      },
    }),
    (err: unknown) => err instanceof SignerError && err.code === "invalid_argument",
  );
  await assert.rejects(
    signer.sign({
      tx: {
        kind: "gov_propose",
        proposal_id: 1,
        title: "é".repeat(129), // 258 UTF-8 bytes
        action: { type: "signal", text: "ok" },
        height_observed: 10,
      },
    }),
    (err: unknown) => err instanceof SignerError && err.code === "invalid_argument",
  );

  // evm_carrier and evm_binding refuse unbound: true instead of silently binding defaultChainId
  await assert.rejects(
    signer.sign({
      tx: {
        kind: "evm_carrier",
        evm_tx: legacyEvmTxHex(7, 3_000_000_000n, 5757),
        to_pq: signer.addressStl57,
        evm_address: "22".repeat(20),
        unbound: true,
      },
    }),
    (err: unknown) => err instanceof SignerError && err.code === "invalid_argument",
  );
  await assert.rejects(
    signer.sign({
      tx: {
        kind: "evm_binding",
        evm_address: "22".repeat(20),
        evm_proof: "66".repeat(65),
        unbound: true,
      },
    }),
    (err: unknown) => err instanceof SignerError && err.code === "invalid_argument",
  );
  signer.destroy();
});

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REAL_WASM_PATH = path.resolve(
  TEST_DIR,
  "../../stellereum-wasm/target/wasm32-unknown-unknown/release/stellereum_wasm.wasm",
);

function verifyRealSignedWire(signer: WasmFalconSigner, txHex: string, txHashHex: string): void {
  const wire = hexToBytes(txHex);
  const view = new DataView(wire.buffer, wire.byteOffset, wire.byteLength);
  const from = wire.subarray(0, 32);
  const to = wire.subarray(32, 64);
  const amount = Number(view.getBigUint64(64, true));
  const gasLimit = Number(view.getBigUint64(72, true));
  const nonce = Number(view.getBigUint64(80, true));
  const sourceShard = view.getUint32(88, true);
  const targetShard = view.getUint32(92, true);
  const envLen = Number(view.getBigUint64(96, true));
  const envelope = wire.subarray(104, 104 + envLen);
  const payload = wire.subarray(104 + envLen);

  // Explicit PQ1 envelope: "PQ1"(3) + scheme(1) + implicit(1) + pkLen(2) + pk(897) + salt(16) + sigLen(2) + sig(666) + chainId(8)
  assert.equal(new TextDecoder().decode(envelope.subarray(0, 3)), "PQ1");
  assert.equal(envelope[3], 2);
  assert.equal(envelope[4], 0);
  const sig = envelope.subarray(3 + 1 + 1 + 2 + FALCON512_PUBKEY_LEN + 16 + 2, 3 + 1 + 1 + 2 + FALCON512_PUBKEY_LEN + 16 + 2 + FALCON512_SIG_LEN);
  assert.equal(sig.length, FALCON512_SIG_LEN);
  assert.equal(sig[0], CHAIN_SIG_HEADER);

  const txFields = {
    from,
    to,
    amount,
    gasLimit,
    nonce,
    sourceShard,
    targetShard,
    payload,
    priorityFeePerGas: 0,
  };
  const msg = signingMessage(txFields, 5757);
  assert.equal(signer.verify(msg, sig), true, "real Falcon-512 signature must verify in WASM");

  const envTag = new TextEncoder().encode("PQ_ENV");
  const base = baseSigningMessage(txFields);
  const preimage = new Uint8Array(base.length + envTag.length + envelope.length);
  preimage.set(base, 0);
  preimage.set(envTag, base.length);
  preimage.set(envelope, base.length + envTag.length);
  assert.equal(txHashHex, bytesToHex(sha256(preimage)));
}

test(
  "real compiled stellereum_wasm.wasm performs Falcon-512 keygen, sign, and verify across all intent kinds",
  { skip: !fs.existsSync(REAL_WASM_PATH) },
  async () => {
    const wasmBytes = fs.readFileSync(REAL_WASM_PATH);
    const { signer, keypair } = await WasmFalconSigner.generate(wasmBytes, {
      seed: new Uint8Array(32).fill(0x42),
    });
    assert.equal(keypair.publicKey.length, FALCON512_PUBKEY_LEN);
    assert.equal(keypair.publicKey[0], FALCON_PUBKEY_HEADER);
    assert.equal(keypair.secretKey.length, FALCON512_SECKEY_LEN);
    assert.equal(keypair.secretKey[0], FALCON_SECKEY_HEADER);
    assert.match(keypair.addressStl57, /^Stl57/);

    const rawMsg = new TextEncoder().encode("real wasm falcon512 check");
    const rawSig = signer.signMessage(rawMsg);
    assert.equal(rawSig[0], CHAIN_SIG_HEADER);
    assert.equal(signer.verify(rawMsg, rawSig), true);
    assert.equal(signer.verify(new TextEncoder().encode("tampered"), rawSig), false);

    const wasmCode = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    const intents = [
      { kind: "contractDeploy" as const, code: wasmCode, nonce: 1 },
      { kind: "contract_deploy" as const, code: wasmCode, nonce: 2 },
      {
        kind: "contract_call" as const,
        contract: "99".repeat(32),
        method: "increment",
        args: [
          { type: "u64" as const, value: 42 },
          { type: "address" as const, value: signer.addressStl57 },
        ],
        value: 10,
        nonce: 3,
      },
      { kind: "stake" as const, validator: signer.addressStl57, amount: 1_000_000, nonce: 4 },
      { kind: "unjail" as const, validator: signer.address, top_up: 500, nonce: 5 },
      {
        kind: "gov_propose" as const,
        proposal_id: 7,
        title: "raise floor",
        action: { type: "set_min_gas_limit", value: 300_000 },
        height_observed: 120,
        nonce: 6,
      },
      {
        kind: "gov_vote" as const,
        proposal_id: 7,
        choice: "yes" as const,
        height_observed: 121,
        nonce: 7,
      },
      {
        kind: "evm_binding" as const,
        evm_address: "22".repeat(20),
        evm_proof: "66".repeat(65),
        nonce: 8,
      },
      {
        kind: "evm_carrier" as const,
        evm_tx: legacyEvmTxHex(9, 3_000_000_000n, 5757),
        to_pq: signer.addressStl57,
        evm_address: "22".repeat(20),
      },
    ];

    for (const intent of intents) {
      const resp = await signer.sign({ tx: intent });
      assert.equal(resp.ok, true, `sign failed for ${intent.kind}`);
      assert.equal(resp.from, signer.address);
      assert.equal(resp.from_stl57, signer.addressStl57);
      assert.equal(resp.envelope, "pq1-explicit");
      assert.equal(resp.chain_id, 5757);
      verifyRealSignedWire(signer, resp.tx_hex, resp.tx_hash);
    }

    // Real compiled WASM SP1 (cosignWithSponsor) + SF1 (signWithSession) end-to-end verification
    const { signer: sponsorSigner } = await WasmFalconSigner.generate(wasmBytes, {
      seed: new Uint8Array(32).fill(0x43),
    });
    const spResp = await signer.cosignWithSponsor({
      tx: {
        kind: "transfer",
        to: "22".repeat(32),
        amount: 2500,
        nonce: 10,
        priority_fee_per_gas: 7,
      },
      sponsor: {
        signer: sponsorSigner,
        maxFeePerTx: 500_000,
        validUntil: 1_900_000_000,
        allowedTargets: ["22".repeat(32)],
      },
    });
    assert.equal(spResp.envelope, "pq1-explicit+sp1");
    assert.equal(spResp.chain_id, 5757);

    const spWire = hexToBytes(spResp.tx_hex);
    const spView = new DataView(spWire.buffer, spWire.byteOffset, spWire.byteLength);
    const spSigLen = Number(spView.getBigUint64(96, true));
    const spWireSig = spWire.subarray(104, 104 + spSigLen);
    // Strip trailing PRIORITY suffix (16 bytes) to get Transaction.signature
    assert.equal(
      new TextDecoder().decode(spWireSig.subarray(spWireSig.length - 16, spWireSig.length - 8)),
      "PRIORITY",
    );
    const spSigNoPrio = spWireSig.subarray(0, spWireSig.length - 16);
    const spSplit = splitSponsorEnvelope(spSigNoPrio);
    assert.equal(spSplit.malformed, false);
    assert.ok(spSplit.auth !== null);
    assert.deepEqual(spSplit.auth.sponsor, hexToBytes(sponsorSigner.address));

    const spTxFields: TransactionFields = {
      from: spWire.subarray(0, 32),
      to: spWire.subarray(32, 64),
      amount: Number(spView.getBigUint64(64, true)),
      gasLimit: Number(spView.getBigUint64(72, true)),
      nonce: Number(spView.getBigUint64(80, true)),
      sourceShard: spView.getUint32(88, true),
      targetShard: spView.getUint32(92, true),
      payload: spWire.subarray(104 + spSigLen),
      priorityFeePerGas: 7,
    };
    assert.equal(
      sponsorSigner.verify(sponsorMessage(spTxFields, spSplit.auth), spSplit.auth.sponsorSig),
      true,
      "real WASM sponsor Falcon-512 signature must verify",
    );
    const spUserSig = spSplit.innerSig.subarray(
      3 + 1 + 1 + 2 + FALCON512_PUBKEY_LEN + 16 + 2,
      3 + 1 + 1 + 2 + FALCON512_PUBKEY_LEN + 16 + 2 + FALCON512_SIG_LEN,
    );
    assert.equal(
      signer.verify(sponsoredSigningMessage(spTxFields, spSplit.auth), spUserSig),
      true,
      "real WASM user Falcon-512 signature must verify over sponsoredSigningMessage",
    );
    assert.equal(spResp.tx_hash, bytesToHex(computeTxHash(spTxFields, spSigNoPrio)));

    // Real compiled WASM SF1 session grant + signWithSession
    const { signer: sessionSigner } = await WasmFalconSigner.generate(wasmBytes, {
      seed: new Uint8Array(32).fill(0x44),
    });
    const grant = signer.createSessionGrant({
      sessionPublicKey: sessionSigner.publicKey,
      validUntil: 1_900_000_000,
      maxGasSpend: 2_000_000,
      scope: SCOPE_TRANSFER,
      maxValuePerTx: 50_000,
      chainId: 5757,
    });
    const sf1Resp = await sessionSigner.signWithSession({
      tx: {
        kind: "transfer",
        to: "33".repeat(32),
        amount: 1234,
        nonce: 11,
      },
      grant,
    });
    assert.equal(sf1Resp.envelope, "sf1");
    assert.equal(sf1Resp.from, signer.address);
    const sf1Wire = hexToBytes(sf1Resp.tx_hex);
    const sf1View = new DataView(sf1Wire.buffer, sf1Wire.byteOffset, sf1Wire.byteLength);
    const sf1SigLen = Number(sf1View.getBigUint64(96, true));
    const sf1Sig = sf1Wire.subarray(104, 104 + sf1SigLen);
    const sf1Parsed = splitSessionEnvelope(sf1Sig);
    assert.ok(sf1Parsed !== null);
    assert.equal(
      signer.verify(sessionGrantMessage(sf1Parsed.grant), sf1Parsed.grant.masterSignature),
      true,
      "real WASM master grant signature must verify",
    );
    const sf1TxFields: TransactionFields = {
      from: sf1Wire.subarray(0, 32),
      to: sf1Wire.subarray(32, 64),
      amount: Number(sf1View.getBigUint64(64, true)),
      gasLimit: Number(sf1View.getBigUint64(72, true)),
      nonce: Number(sf1View.getBigUint64(80, true)),
      sourceShard: sf1View.getUint32(88, true),
      targetShard: sf1View.getUint32(92, true),
      payload: sf1Wire.subarray(104 + sf1SigLen),
      priorityFeePerGas: 0,
    };
    assert.equal(
      sessionSigner.verify(sessionSigningMessage(sf1TxFields, sf1Parsed.grant), sf1Parsed.sessionSig),
      true,
      "real WASM session signature must verify over sessionSigningMessage",
    );
    assert.equal(sf1Resp.tx_hash, bytesToHex(computeTxHash(sf1TxFields, sf1Sig)));

    sponsorSigner.destroy();
    sessionSigner.destroy();

    signer.destroy();
    assert.ok(keypair.secretKey.every((b) => b === 0));
    await assert.rejects(
      signer.sign({ tx: { kind: "transfer", to: signer.address, amount: 1 } }),
      (err: unknown) => err instanceof SignerError && err.code === "destroyed",
    );
  },
);

test("empty payload normalization parity in baseSigningMessage, finishUnsigned, and computeTxHashPreimage", () => {
  const from = new Uint8Array(32).fill(0x11);
  const to = new Uint8Array(32).fill(0x22);
  const emptyTx: TransactionFields = {
    from,
    to,
    amount: 42_000,
    gasLimit: 280_000,
    nonce: 3,
    sourceShard: 0,
    targetShard: 0,
    payload: new Uint8Array(0),
    priorityFeePerGas: 5,
  };
  const canonicalTx: TransactionFields = {
    ...emptyTx,
    payload: new Uint8Array(8),
  };

  assert.deepEqual(baseSigningMessage(emptyTx), baseSigningMessage(canonicalTx));
  assert.deepEqual(signingMessage(emptyTx, 5757), signingMessage(canonicalTx, 5757));
  assert.deepEqual(unsignedTxHash(emptyTx), unsignedTxHash(canonicalTx));

  const fakePq1 = Uint8Array.from([0x50, 0x51, 0x31, 0x02, 0x01, 0x00, 0x00]);
  assert.deepEqual(computeTxHashPreimage(emptyTx, fakePq1), computeTxHashPreimage(canonicalTx, fakePq1));

  // Confirm PAYLOAD || u32be(8) || 0^8 appears at offset 32+32+8+8+8+4+4 = 96
  const base = baseSigningMessage(emptyTx);
  assert.equal(new TextDecoder().decode(base.subarray(96, 103)), "PAYLOAD");
  assert.deepEqual(base.subarray(103, 107), Uint8Array.from([0, 0, 0, 8]));
  assert.deepEqual(base.subarray(107, 115), new Uint8Array(8));

  const uEmpty = finishUnsigned(emptyTx, 5757);
  const uCanonical = finishUnsigned(canonicalTx, 5757);
  assert.equal(uEmpty.signingMessageHex, uCanonical.signingMessageHex);
  assert.equal(uEmpty.unsignedTxHash, uCanonical.unsignedTxHash);
  assert.equal(uEmpty.txHex, uCanonical.txHex);
});

test("SP1 SponsorAuthorization wire layout, splitSponsorEnvelope fail-closed bounds, and cosignWithSponsor", async () => {
  const instrumented = createInstrumentedWasm();
  const userKp = WasmFalconSigner.generateKeypair(instrumented.exports, new Uint8Array(32).fill(0x31));
  const sponsorKp = WasmFalconSigner.generateKeypair(instrumented.exports, new Uint8Array(32).fill(0x32));
  const userSigner = new WasmFalconSigner(instrumented.exports, userKp);
  const sponsorSigner = new WasmFalconSigner(instrumented.exports, sponsorKp);

  const target = new Uint8Array(32).fill(0xaa);
  const sampleAuth: SponsorAuthorization = {
    sponsor: hexToBytes(sponsorSigner.address),
    maxFeePerTx: 1_000_000n,
    validUntil: 1_800_000_000n,
    allowedTargets: [target],
    chainId: 5757n,
    sponsorSig: new Uint8Array(FALCON512_SIG_LEN).fill(0x29),
    sponsorScheme: 2,
    sponsorPubkey: sponsorKp.publicKey,
    sponsorSalt: new Uint8Array(16).fill(0x07),
  };
  const encodedAuth = encodeSponsorAuth(sampleAuth);
  const decodedAuth = decodeSponsorAuth(encodedAuth);
  assert.deepEqual(decodedAuth, sampleAuth);

  // Verify Option<PqScheme>::Some(Falcon512) encodes as 0x01 || u32le(0) (serde variant index, NOT 2).
  const schemeOffset = 32 + 8 + 8 + (8 + 32) + 8 + (8 + FALCON512_SIG_LEN);
  assert.deepEqual(
    encodedAuth.subarray(schemeOffset, schemeOffset + 5),
    Uint8Array.from([0x01, 0x00, 0x00, 0x00, 0x00]),
  );

  // Verify splitSponsorEnvelope on valid and malformed SP1 blobs.
  const fakeInner = new Uint8Array(100).fill(0x55);
  fakeInner.set([0x50, 0x51, 0x31], 0);
  const suffix = encodeSponsorSuffix(sampleAuth);
  assert.equal(new TextDecoder().decode(suffix.subarray(suffix.length - 3)), "SP1");
  const fullBlob = Uint8Array.from([...fakeInner, ...suffix]);
  const splitOk = splitSponsorEnvelope(fullBlob);
  assert.equal(splitOk.malformed, false);
  assert.equal(splitOk.innerLen, fakeInner.length);
  assert.deepEqual(splitOk.innerSig, fakeInner);
  assert.deepEqual(splitOk.auth, sampleAuth);

  // Plain signature without SP1 tag -> not sponsored, not malformed.
  const plainSplit = splitSponsorEnvelope(fakeInner);
  assert.equal(plainSplit.malformed, false);
  assert.equal(plainSplit.auth, null);
  assert.equal(plainSplit.innerLen, fakeInner.length);

  // Malformed SP1 blobs fail closed (malformed = true).
  const shortInnerBlob = Uint8Array.from([...new Uint8Array(63).fill(1), ...suffix]);
  assert.equal(splitSponsorEnvelope(shortInnerBlob).malformed, true);
  const zeroLenSp1 = Uint8Array.from([...fakeInner, 0, 0, 0, 0, ...SPONSOR_SIG_TAG]);
  assert.equal(splitSponsorEnvelope(zeroLenSp1).malformed, true);
  const corruptBody = Uint8Array.from(fullBlob);
  corruptBody[fakeInner.length + schemeOffset + 1] = 0x99; // invalid PqScheme variant index
  assert.equal(splitSponsorEnvelope(corruptBody).malformed, true);

  // Verify sponsorMessage exact layout (priority_fee_per_gas always 8B BE, even when 0).
  const tx0: TransactionFields = {
    from: hexToBytes(userSigner.address),
    to: target,
    amount: 500,
    gasLimit: 325_000,
    nonce: 2,
    sourceShard: 0,
    targetShard: 0,
    payload: new Uint8Array(0),
    priorityFeePerGas: 0,
  };
  const spMsg = sponsorMessage(tx0, sampleAuth);
  assert.deepEqual(spMsg.subarray(0, SPONSOR_FEE_DOMAIN.length), SPONSOR_FEE_DOMAIN);
  assert.equal(new TextDecoder().decode(spMsg.subarray(0, 14)), "SPONSOR_FEE_V1");

  // Cosign via 1-step (sponsor signer passed directly) and 2-step (pre-signed SponsorAuthorization).
  const resp1 = await userSigner.cosignWithSponsor({
    tx: { kind: "transfer", to: bytesToHex(target), amount: 500, nonce: 2, priority_fee_per_gas: 11 },
    sponsor: {
      signer: sponsorSigner,
      maxFeePerTx: 400_000,
      validUntil: 1_900_000_000,
      allowedTargets: [target],
    },
  });
  assert.equal(resp1.ok, true);
  assert.equal(resp1.envelope, "pq1-explicit+sp1");
  assert.equal(resp1.chain_id, 5757);

  const wire1 = hexToBytes(resp1.tx_hex);
  const view1 = new DataView(wire1.buffer, wire1.byteOffset, wire1.byteLength);
  const sigLen1 = Number(view1.getBigUint64(96, true));
  const wireSig1 = wire1.subarray(104, 104 + sigLen1);
  // Trailing PRIORITY suffix stripped from wire signature before hashing / splitting SP1.
  const sigNoPrio1 = wireSig1.subarray(0, wireSig1.length - 16);
  const split1 = splitSponsorEnvelope(sigNoPrio1);
  assert.equal(split1.malformed, false);
  assert.ok(split1.auth !== null);
  const txFields1: TransactionFields = {
    from: wire1.subarray(0, 32),
    to: wire1.subarray(32, 64),
    amount: Number(view1.getBigUint64(64, true)),
    gasLimit: Number(view1.getBigUint64(72, true)),
    nonce: Number(view1.getBigUint64(80, true)),
    sourceShard: view1.getUint32(88, true),
    targetShard: view1.getUint32(92, true),
    payload: wire1.subarray(104 + sigLen1),
    priorityFeePerGas: 11,
  };
  // Verify user's signed message includes SPONSOR_ commitment and omits CHAIN_ID.
  const expectedUserMsg = sponsoredSigningMessage(txFields1, split1.auth);
  assert.deepEqual(instrumented.lastSignedMsg, expectedUserMsg);
  assert.equal(bytesToHex(expectedUserMsg).includes(bytesToHex(new TextEncoder().encode("CHAIN_ID"))), false);

  // Verify hash preimage parity: baseSigningMessage || SPONSOR_ || PQ_ENV || fullSignatureWithoutPriority.
  const expectedHashPreimage = Uint8Array.from([
    ...baseSigningMessage(txFields1),
    ...SPONSOR_COMMITMENT_TAG,
    ...(() => {
      const b = encodeSponsorAuth(split1.auth);
      const l = new Uint8Array(4);
      new DataView(l.buffer).setUint32(0, b.length, false);
      return [...l, ...b];
    })(),
    ...PQ_ENVELOPE_HASH_TAG,
    ...sigNoPrio1,
  ]);
  assert.deepEqual(computeTxHashPreimage(txFields1, sigNoPrio1), expectedHashPreimage);
  assert.equal(resp1.tx_hash, bytesToHex(sha256(expectedHashPreimage)));

  // 2-step pre-signed SponsorAuthorization flow + negative chain_id / unbound checks.
  const preSignedAuth = sponsorSigner.signSponsorAuthorization(txFields1, {
    maxFeePerTx: 400_000,
    validUntil: 1_900_000_000,
    allowedTargets: [encodeStl57Address(target)],
    chainId: 5757,
  });
  const resp2 = await userSigner.cosignWithSponsor({
    tx: {
      kind: "transfer",
      to: bytesToHex(target),
      amount: 500,
      nonce: 2,
      gas_limit: txFields1.gasLimit,
      priority_fee_per_gas: 11,
    },
    sponsor: preSignedAuth,
  });
  assert.equal(resp2.ok, true);
  assert.equal(resp2.envelope, "pq1-explicit+sp1");

  await assert.rejects(
    userSigner.cosignWithSponsor({
      tx: { kind: "transfer", to: bytesToHex(target), amount: 500, nonce: 2, unbound: true },
      sponsor: { signer: sponsorSigner, maxFeePerTx: 400_000, validUntil: 1_900_000_000 },
    }),
    (err: unknown) => err instanceof SignerError && err.code === "invalid_argument",
  );
  await assert.rejects(
    userSigner.cosignWithSponsor({
      tx: { kind: "transfer", to: bytesToHex(target), amount: 500, nonce: 2, chain_id: 9999 },
      sponsor: preSignedAuth,
    }),
    (err: unknown) => err instanceof SignerError && err.code === "invalid_argument",
  );
});

test("SF1 SessionGrant framing, encodeSessionGrant bincode parity, and signWithSession", async () => {
  const instrumented = createInstrumentedWasm();
  const masterKp = WasmFalconSigner.generateKeypair(instrumented.exports, new Uint8Array(32).fill(0x41));
  const sessionKp = WasmFalconSigner.generateKeypair(instrumented.exports, new Uint8Array(32).fill(0x42));
  const masterSigner = new WasmFalconSigner(instrumented.exports, masterKp);
  const sessionSigner = new WasmFalconSigner(instrumented.exports, sessionKp);

  const grant = masterSigner.createSessionGrant({
    sessionPublicKey: sessionKp.publicKey,
    validUntil: 1_900_000_000n,
    maxGasSpend: 5_000_000n,
    scope: SCOPE_ALL,
    maxValuePerTx: 100_000n,
    chainId: 5757,
  });

  // Verify SessionKeyAuthorization bincode layout (schemes are u8 0x02, 0x02).
  const encodedGrant = encodeSessionGrant(grant);
  const decodedGrant = decodeSessionGrant(encodedGrant);
  const expectedDecodedGrant = {
    ...grant,
    gasSpent: BigInt(grant.gasSpent ?? 0),
    chainId: BigInt(grant.chainId),
  };
  assert.deepEqual(decodedGrant, expectedDecodedGrant);
  const schemeOffset = 32 + 32 + 8 * 6 + 8 + FALCON512_SIG_LEN;
  assert.deepEqual(encodedGrant.subarray(schemeOffset, schemeOffset + 2), Uint8Array.from([2, 2]));

  // Verify sessionGrantMessage starts with STELL_SESSKEY_V1 || u64be(chainId).
  const gMsg = sessionGrantMessage(grant);
  assert.deepEqual(gMsg.subarray(0, SESSION_KEY_DOMAIN.length), SESSION_KEY_DOMAIN);
  assert.equal(new TextDecoder().decode(gMsg.subarray(0, 16)), "STELL_SESSKEY_V1");

  // Sign a transfer with the session key.
  const toHex = "55".repeat(32);
  const resp = await sessionSigner.signWithSession({
    tx: {
      kind: "transfer",
      to: toHex,
      amount: 777,
      nonce: 5,
    },
    grant,
  });
  assert.equal(resp.ok, true);
  assert.equal(resp.envelope, "sf1");
  assert.equal(resp.activation, false);
  assert.equal(resp.from, masterSigner.address);
  assert.equal(resp.from_stl57, masterSigner.addressStl57);
  assert.equal(resp.to, toHex);
  assert.equal(resp.chain_id, 5757);

  const wire = hexToBytes(resp.tx_hex);
  const view = new DataView(wire.buffer, wire.byteOffset, wire.byteLength);
  const sigLen = Number(view.getBigUint64(96, true));
  const sf1Sig = wire.subarray(104, 104 + sigLen);
  assert.deepEqual(
    sf1Sig.subarray(FALCON512_SIG_LEN, FALCON512_SIG_LEN + 3),
    SESSION_FALCON_SIG_TAG,
  );
  const parsedSf1 = splitSessionEnvelope(sf1Sig);
  assert.ok(parsedSf1 !== null);
  assert.deepEqual(parsedSf1.grant, expectedDecodedGrant);

  const txFields: TransactionFields = {
    from: wire.subarray(0, 32),
    to: wire.subarray(32, 64),
    amount: Number(view.getBigUint64(64, true)),
    gasLimit: Number(view.getBigUint64(72, true)),
    nonce: Number(view.getBigUint64(80, true)),
    sourceShard: view.getUint32(88, true),
    targetShard: view.getUint32(92, true),
    payload: wire.subarray(104 + sigLen),
    priorityFeePerGas: 0,
  };
  assert.deepEqual(instrumented.lastSignedMsg, sessionSigningMessage(txFields, grant));

  // Verify SF1 compute_tx_hash preimage: baseSigningMessage || SESSION || u32be(len) || bincode(grant) (no PQ_ENV).
  const expectedSf1Preimage = Uint8Array.from([
    ...baseSigningMessage(txFields),
    ...sessionCommitment(grant),
  ]);
  assert.deepEqual(computeTxHashPreimage(txFields, sf1Sig), expectedSf1Preimage);
  assert.equal(
    new TextDecoder().decode(expectedSf1Preimage.subarray(baseSigningMessage(txFields).length, baseSigningMessage(txFields).length + 7)),
    new TextDecoder().decode(SESSION_COMMITMENT_TAG),
  );
  assert.equal(resp.tx_hash, bytesToHex(sha256(expectedSf1Preimage)));

  // Negative checks: unbound, chain mismatch, or wrong session key must fail closed.
  await assert.rejects(
    sessionSigner.signWithSession({
      tx: { kind: "transfer", to: toHex, amount: 1, unbound: true },
      grant,
    }),
    (err: unknown) => err instanceof SignerError && err.code === "invalid_argument",
  );
  await assert.rejects(
    sessionSigner.signWithSession({
      tx: { kind: "transfer", to: toHex, amount: 1, chain_id: 1234 },
      grant,
    }),
    (err: unknown) => err instanceof SignerError && err.code === "invalid_argument",
  );
  await assert.rejects(
    masterSigner.signWithSession({
      tx: { kind: "transfer", to: toHex, amount: 1 },
      grant,
    }),
    (err: unknown) => err instanceof SignerError && err.code === "invalid_key",
  );
});
