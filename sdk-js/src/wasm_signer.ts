/**
 * Browser & Node.js WebAssembly Falcon-512 signer (`WasmFalconSigner`).
 *
 * Uses the standalone `stellereum-wasm` `cdylib` (`wasm32-unknown-unknown`)
 * over a raw C ABI (`alloc`, `dealloc`, `falcon_keygen`,
 * `falcon_sign_with_entropy`, `falcon_verify`, `falcon_derive_address`) with
 * zero `wasm-bindgen`, supplying `crypto.getRandomValues` to the WASM entropy
 * import and zeroizing temporary WASM linear memory after every operation.
 */

import { SignerError } from "./errors.ts";
import { EVM_BINDING_MIN_GAS, EVM_CARRIER_MIN_GAS, bindingMessage, decodeEvmIntent, evmIntentDigest, requireBindingProof } from "./evm.ts";
import { DEFAULT_CHAIN_ID } from "./protocol.ts";
import type {
  FalconSigner,
  JsonCallArg,
  SignRequest,
  SignResponse,
  TxCommon,
  TxIntent,
} from "./signer.ts";
import {
  CHAIN_ID_COMMITMENT_TAG,
  FROZEN_MIN_GAS_FLOOR,
  GAS_EVM_CARRIER_BASE,
  GAS_GOV_PROPOSE,
  GAS_GOV_VOTE,
  GAS_PQ_VERIFY_BASE,
  GAS_PQ_VERIFY_PER_BYTE,
  MASTERCHAIN_SHARD,
  MAX_PROPOSAL_TITLE_BYTES,
  PQ_ACTIVATION_SURCHARGE_GAS,
  PRIORITY_FEE_COMMITMENT_TAG,
  SPONSOR_MAX_TARGETS,
  baseSigningMessage,
  bytesToHex,
  computeTxHashPreimage,
  encodeGovAction,
  encodeOp,
  encodePayload,
  encodeSessionEnvelope,
  encodeSponsorSuffix,
  encodeStl57Address,
  hexToBytes,
  normalizePayloadBytes,
  parseStellereumAddress,
  sessionGrantMessage,
  sessionSigningMessage,
  sha256,
  signingMessage,
  sponsorMessage,
  sponsoredSigningMessage,
  type GovAction,
  type SessionGrant,
  type SponsorAuthorization,
  type TransactionFields,
  type VoteChoice,
} from "./wire.ts";

export { encodeStl57Address, parseStellereumAddress };

export const FALCON512_PUBKEY_LEN = 897;
export const FALCON512_SECKEY_LEN = 1281;
export const FALCON512_SIG_LEN = 666;
export const PQ_SCHEME_FALCON512 = 2;
export const PQ_ADDRESS_LEN = 32;
export const PQ_SALT_LEN = 16;
export const CHAIN_SIG_HEADER = 0x29;
export const FALCON_PUBKEY_HEADER = 0x09;
export const FALCON_SECKEY_HEADER = 0x59;

const PQ_ENVELOPE_MAGIC = new Uint8Array([0x50, 0x51, 0x31]); // "PQ1"

const OP_DEPLOY_CONTRACT_CODE = 19;
const OP_DEPLOY_CONTRACT_WITH_ABI_CODE = 65;
const OP_STAKE = 21;
const OP_CALL_CONTRACT_ARGS = 50;
const OP_UNJAIL = 56;
const GAS_STAKE_BOND = 2_000;
const GAS_STAKE_UNBOND = 800;
const GAS_CONTRACT_CALL = 1_000;
const GAS_CONTRACT_CALL_PER_ARG = 10;
const GAS_CONTRACT_CALL_PER_BYTE = 2;
const GAS_CONTRACT_DEPLOY_BASE = 2_000;
const GAS_CONTRACT_DEPLOY_PER_BYTE = 2;
const MAX_CONTRACT_ABI_BYTES = 64 * 1024;
const MAX_ABI_ARGS = 8;
const MAX_GETRANDOM_CHUNK = 65_536;

/** Function signature matching Web Crypto `crypto.getRandomValues`. */
export type WasmEntropySource = (target: Uint8Array) => Uint8Array;

/** Raw C-ABI exports exposed by `stellereum-wasm` (`wasm32-unknown-unknown`). */
export interface StellereumWasmExports {
  memory: WebAssembly.Memory;
  alloc(len: number): number;
  dealloc(ptr: number, len: number): void;
  falcon_keygen(
    seedPtr: number,
    seedLen: number,
    pkOutPtr: number,
    pkOutLen: number,
    skOutPtr: number,
    skOutLen: number,
  ): number;
  falcon_sign_with_entropy(
    skPtr: number,
    skLen: number,
    msgPtr: number,
    msgLen: number,
    entropyPtr: number,
    entropyLen: number,
    sigOutPtr: number,
    sigOutLen: number,
  ): number;
  falcon_verify(
    pkPtr: number,
    pkLen: number,
    msgPtr: number,
    msgLen: number,
    sigPtr: number,
    sigLen: number,
  ): number;
  falcon_derive_address(
    pkPtr: number,
    pkLen: number,
    saltPtr: number,
    saltLen: number,
    addrOutPtr: number,
    addrOutLen: number,
  ): number;
}

export interface WasmFalconKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  address: string;
  addressStl57: string;
  /** Zeroize the keypair's secretKey buffer in place. */
  destroy(): void;
}

export interface WasmFalconSignerOptions {
  /** 1281-byte `falcon-rust` secret key (Uint8Array or hex). */
  secretKey: Uint8Array | string;
  /** 897-byte FIPS 206 public key (Uint8Array or hex). */
  publicKey: Uint8Array | string;
  /** Optional 16-byte sub-account salt (defaults to 16 zero bytes). */
  salt?: Uint8Array | string;
  /** Default chain ID when the request omits `chain_id` (default 5757). */
  defaultChainId?: number;
  /** Optional entropy provider override; defaults to `globalThis.crypto.getRandomValues`. */
  getRandomValues?: WasmEntropySource;
}

export interface SponsorSignerConfig {
  signer: WasmFalconSigner;
  maxFeePerTx: number | bigint;
  validUntil: number | bigint;
  allowedTargets?: Array<string | Uint8Array>;
}

export interface CosignWithSponsorRequest {
  tx: TxIntent;
  sponsor: SponsorSignerConfig | SponsorAuthorization;
}

export interface CreateSessionGrantOptions {
  sessionPublicKey: Uint8Array | string;
  validUntil: number | bigint;
  maxGasSpend: number | bigint;
  gasSpent?: number | bigint;
  scope: number | bigint;
  maxValuePerTx: number | bigint;
  chainId?: number;
}

export interface SignWithSessionRequest {
  tx: TxIntent;
  grant: SessionGrant;
}

function defaultGetRandomValues(target: Uint8Array): Uint8Array {
  if (
    typeof globalThis.crypto === "undefined" ||
    typeof globalThis.crypto.getRandomValues !== "function"
  ) {
    throw new SignerError("no_entropy", "globalThis.crypto.getRandomValues is unavailable");
  }
  return globalThis.crypto.getRandomValues(target);
}

/**
 * Build the `WebAssembly.Imports` object supplying `crypto.getRandomValues` to
 * `stellereum-wasm`'s `env.stellereum_getrandom(dest_ptr, len) -> i32` import.
 */
export function createWasmImports(
  getMemory: () => WebAssembly.Memory,
  getRandomValues: WasmEntropySource = defaultGetRandomValues,
): WebAssembly.Imports {
  return {
    env: {
      stellereum_getrandom(destPtr: number, len: number): number {
        if (!Number.isInteger(len) || len < 0) return -1;
        if (len === 0) return 0;
        if (!Number.isInteger(destPtr) || destPtr <= 0) return -1;
        try {
          const memory = getMemory();
          let offset = 0;
          while (offset < len) {
            const chunkLen = Math.min(MAX_GETRANDOM_CHUNK, len - offset);
            const view = new Uint8Array(memory.buffer, destPtr + offset, chunkLen);
            getRandomValues(view);
            offset += chunkLen;
          }
          return 0;
        } catch {
          return -1;
        }
      },
    },
  };
}

function assertWasmExports(raw: WebAssembly.Exports | StellereumWasmExports): StellereumWasmExports {
  const rec = raw as Record<string, unknown>;
  if (!(rec.memory instanceof WebAssembly.Memory)) {
    throw new SignerError("invalid_wasm", "WASM module is missing exported WebAssembly.Memory");
  }
  const required = [
    "alloc",
    "dealloc",
    "falcon_keygen",
    "falcon_sign_with_entropy",
    "falcon_verify",
    "falcon_derive_address",
  ] as const;
  for (const name of required) {
    if (typeof rec[name] !== "function") {
      throw new SignerError("invalid_wasm", `WASM module is missing required export "${name}"`);
    }
  }
  return raw as unknown as StellereumWasmExports;
}

/**
 * Instantiate raw `stellereum-wasm` bytes with `crypto.getRandomValues` wired
 * to the `env.stellereum_getrandom` import.
 */
export async function instantiateStellereumWasm(
  wasmBytes: BufferSource,
  options: {
    getRandomValues?: WasmEntropySource;
    extraImports?: WebAssembly.Imports;
  } = {},
): Promise<{ instance: WebAssembly.Instance; exports: StellereumWasmExports }> {
  let memoryRef: WebAssembly.Memory | undefined;
  const baseImports = createWasmImports(() => {
    if (!memoryRef) {
      throw new SignerError("wasm_uninitialized", "WASM memory accessed before instantiation");
    }
    return memoryRef;
  }, options.getRandomValues);

  const imports: WebAssembly.Imports = {
    ...options.extraImports,
    env: {
      ...(options.extraImports?.env as Record<string, WebAssembly.ImportValue> | undefined),
      ...(baseImports.env as Record<string, WebAssembly.ImportValue>),
    },
  };

  const result = await WebAssembly.instantiate(wasmBytes, imports);
  const instance = "instance" in result ? result.instance : result;
  const exports = assertWasmExports(instance.exports);
  memoryRef = exports.memory;
  return { instance, exports };
}

// ============================================================================
// Bincode + PQ1 envelope helpers (browser & Node compatible)
// ============================================================================

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function u16le(v: number): Uint8Array {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, v, true);
  return out;
}

function u32le(v: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, v >>> 0, true);
  return out;
}

function u64le(v: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(v), true);
  return out;
}

function u64be(v: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(v), false);
  return out;
}

function i64le(v: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigInt64(0, BigInt(v), true);
  return out;
}

function i64be(v: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigInt64(0, BigInt(v), false);
  return out;
}

function i32be(v: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setInt32(0, v | 0, false);
  return out;
}

function normalizeBytesInput(input: Uint8Array | string, field: string): Uint8Array {
  return typeof input === "string" ? hexToBytes(input, field) : new Uint8Array(input);
}

function encodeCallArg(arg: JsonCallArg): { tag: number; asI64: bigint; payload: Uint8Array } {
  switch (arg.type) {
    case "i64":
      return { tag: 0x01, asI64: BigInt(arg.value), payload: i64be(arg.value) };
    case "u64":
      return { tag: 0x02, asI64: BigInt.asIntN(64, BigInt(arg.value)), payload: u64be(arg.value) };
    case "i32":
      return { tag: 0x03, asI64: BigInt(arg.value), payload: i32be(arg.value) };
    case "bool":
      return { tag: 0x04, asI64: arg.value ? 1n : 0n, payload: Uint8Array.of(arg.value ? 1 : 0) };
    case "bytes": {
      const b = hexToBytes(arg.value, "args.bytes");
      return { tag: 0x05, asI64: 0n, payload: concatBytes([u32le(b.length), b]) };
    }
    case "address": {
      const a = parseStellereumAddress(arg.value, "args.address");
      return { tag: 0x06, asI64: 0n, payload: a };
    }
    case "string": {
      const s = new TextEncoder().encode(arg.value);
      return { tag: 0x07, asI64: 0n, payload: concatBytes([u32le(s.length), s]) };
    }
  }
}

function encodeCallContractRawOp(
  contract: Uint8Array,
  method: string,
  scalarArgs: number[],
  rawCalldata: Uint8Array | string,
): { opBytes: Uint8Array; execGas: number } {
  const methodBytes = new TextEncoder().encode(method);
  if (methodBytes.length === 0 || methodBytes.length > 256) {
    throw new SignerError("invalid_argument", "contract method must be 1..=256 bytes");
  }
  if (scalarArgs.length > MAX_ABI_ARGS) {
    throw new SignerError("invalid_argument", `${scalarArgs.length} scalar args, max ${MAX_ABI_ARGS}`);
  }
  const calldata =
    typeof rawCalldata === "string"
      ? rawCalldata.length === 0
        ? new Uint8Array(0)
        : hexToBytes(rawCalldata, "calldata_hex")
      : rawCalldata;
  if (calldata.length > MAX_CONTRACT_ABI_BYTES) {
    throw new SignerError("invalid_argument", `calldata exceeds ${MAX_CONTRACT_ABI_BYTES} bytes`);
  }
  const scalarParts = scalarArgs.map((v) => i64le(v));
  const opBytes = concatBytes([
    u32le(OP_CALL_CONTRACT_ARGS),
    contract,
    u64le(methodBytes.length),
    methodBytes,
    u64le(scalarArgs.length),
    ...scalarParts,
    u64le(calldata.length),
    calldata,
  ]);
  const execGas =
    GAS_CONTRACT_CALL +
    scalarArgs.length * GAS_CONTRACT_CALL_PER_ARG +
    (methodBytes.length + calldata.length) * GAS_CONTRACT_CALL_PER_BYTE;
  return { opBytes, execGas };
}

function encodeCallContractArgsOp(
  contract: Uint8Array,
  method: string,
  args: JsonCallArg[],
): { opBytes: Uint8Array; execGas: number } {
  if (args.length > MAX_ABI_ARGS) {
    throw new SignerError("invalid_argument", `${args.length} ABI arguments, max ${MAX_ABI_ARGS}`);
  }
  const methodBytes = new TextEncoder().encode(method);
  if (methodBytes.length === 0 || methodBytes.length > 256) {
    throw new SignerError("invalid_argument", "contract method must be 1..=256 bytes");
  }
  const encodedArgs = args.map(encodeCallArg);
  const calldataParts: Uint8Array[] = [u32le(encodedArgs.length)];
  const scalarParts: Uint8Array[] = [];
  for (const a of encodedArgs) {
    calldataParts.push(Uint8Array.of(a.tag), a.payload);
    scalarParts.push(i64le(a.asI64));
  }
  const calldata = concatBytes(calldataParts);
  if (calldata.length > MAX_CONTRACT_ABI_BYTES) {
    throw new SignerError("invalid_argument", `calldata exceeds ${MAX_CONTRACT_ABI_BYTES} bytes`);
  }
  const opBytes = concatBytes([
    u32le(OP_CALL_CONTRACT_ARGS),
    contract,
    u64le(methodBytes.length),
    methodBytes,
    u64le(encodedArgs.length),
    ...scalarParts,
    u64le(calldata.length),
    calldata,
  ]);
  const execGas =
    GAS_CONTRACT_CALL +
    encodedArgs.length * GAS_CONTRACT_CALL_PER_ARG +
    (methodBytes.length + calldata.length) * GAS_CONTRACT_CALL_PER_BYTE;
  return { opBytes, execGas };
}

function encodeStakeOp(validator: Uint8Array, amount: number): Uint8Array {
  return concatBytes([u32le(OP_STAKE), validator, u64le(amount)]);
}

function encodeUnjailOp(validator: Uint8Array): Uint8Array {
  return concatBytes([u32le(OP_UNJAIL), validator]);
}

function encodeDeployContractPayload(
  codeInput: Uint8Array | string,
  abiInput?: string | Record<string, unknown>,
): { payload: Uint8Array; execGas: number } {
  const code = typeof codeInput === "string" ? hexToBytes(codeInput, "code") : codeInput;
  if (code.length === 0) {
    throw new SignerError("invalid_argument", "contract bytecode must not be empty");
  }
  if (abiInput === undefined) {
    const op = concatBytes([u32le(OP_DEPLOY_CONTRACT_CODE), u64le(code.length), code]);
    return {
      payload: concatBytes([u64le(1), op]),
      execGas: GAS_CONTRACT_DEPLOY_BASE + code.length * GAS_CONTRACT_DEPLOY_PER_BYTE,
    };
  }
  const json = typeof abiInput === "string" ? abiInput : JSON.stringify(abiInput);
  const abi = new TextEncoder().encode(json);
  if (abi.length === 0 || abi.length > MAX_CONTRACT_ABI_BYTES) {
    throw new SignerError("invalid_argument", "contract ABI manifest length is invalid");
  }
  const op = concatBytes([
    u32le(OP_DEPLOY_CONTRACT_WITH_ABI_CODE),
    u64le(code.length),
    code,
    u64le(abi.length),
    abi,
  ]);
  return {
    payload: concatBytes([u64le(1), op]),
    execGas: GAS_CONTRACT_DEPLOY_BASE + (code.length + abi.length) * GAS_CONTRACT_DEPLOY_PER_BYTE,
  };
}

function decodeUnsignedWireTx(bytes: Uint8Array): {
  tx: TransactionFields;
} {
  let cursor = 0;
  const take = (n: number): Uint8Array => {
    if (cursor + n > bytes.length) {
      throw new SignerError("decode_error", "truncated unsigned transaction");
    }
    const slice = bytes.subarray(cursor, cursor + n);
    cursor += n;
    return slice;
  };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u32 = (): number => {
    if (cursor + 4 > bytes.length) throw new SignerError("decode_error", "truncated u32");
    const v = view.getUint32(cursor, true);
    cursor += 4;
    return v;
  };
  const u64 = (): number => {
    if (cursor + 8 > bytes.length) throw new SignerError("decode_error", "truncated u64");
    const v = view.getBigUint64(cursor, true);
    cursor += 8;
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new SignerError("decode_error", "u64 field exceeds JS safe integer");
    }
    return Number(v);
  };

  const from = new Uint8Array(take(32));
  const to = new Uint8Array(take(32));
  const amount = u64();
  const gasLimit = u64();
  const nonce = u64();
  const sourceShard = u32();
  const targetShard = u32();
  const sigLen = u64();
  const sigBlob = take(sigLen);
  const payload = new Uint8Array(bytes.subarray(cursor));

  let priorityFeePerGas = 0;
  let innerSig = sigBlob;
  const prioSuffixLen = PRIORITY_FEE_COMMITMENT_TAG.length + 8;
  if (sigBlob.length >= prioSuffixLen) {
    const split = sigBlob.length - prioSuffixLen;
    const tagMatch = PRIORITY_FEE_COMMITMENT_TAG.every((b, i) => sigBlob[split + i] === b);
    if (tagMatch) {
      const pView = new DataView(sigBlob.buffer, sigBlob.byteOffset + split + 8, 8);
      const prioBig = pView.getBigUint64(0, false);
      if (prioBig > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new SignerError("decode_error", "priorityFeePerGas exceeds JS safe integer");
      }
      priorityFeePerGas = Number(prioBig);
      innerSig = sigBlob.subarray(0, split);
    }
  }
  if (innerSig.length !== 0) {
    throw new SignerError(
      "invalid_argument",
      "prepared tx must be unsigned (empty inner signature)",
    );
  }
  return {
    tx: {
      from,
      to,
      amount,
      gasLimit,
      nonce,
      sourceShard,
      targetShard,
      payload,
      priorityFeePerGas,
    },
  };
}

function encodePq1Envelope(params: {
  implicit: boolean;
  pubkey?: Uint8Array;
  salt: Uint8Array;
  signature: Uint8Array;
  chainId: number | null;
}): Uint8Array {
  const parts: Uint8Array[] = [
    PQ_ENVELOPE_MAGIC,
    Uint8Array.of(PQ_SCHEME_FALCON512),
    Uint8Array.of(params.implicit ? 1 : 0),
  ];
  if (params.implicit) {
    parts.push(u16le(0));
  } else {
    if (!params.pubkey || params.pubkey.length !== FALCON512_PUBKEY_LEN) {
      throw new SignerError("invalid_key", "explicit PQ1 envelope requires 897-byte public key");
    }
    parts.push(u16le(params.pubkey.length), params.pubkey, params.salt);
  }
  parts.push(u16le(params.signature.length), params.signature);
  if (params.chainId !== null) {
    parts.push(u64be(params.chainId));
  }
  return concatBytes(parts);
}

function encodeSignedWireTransaction(tx: TransactionFields, envelope: Uint8Array): Uint8Array {
  const wireSignature =
    tx.priorityFeePerGas === 0
      ? envelope
      : concatBytes([envelope, PRIORITY_FEE_COMMITMENT_TAG, u64be(tx.priorityFeePerGas)]);
  const payloadBytes = normalizePayloadBytes(tx.payload);
  return concatBytes([
    tx.from,
    tx.to,
    u64le(tx.amount),
    u64le(tx.gasLimit),
    u64le(tx.nonce),
    u32le(tx.sourceShard),
    u32le(tx.targetShard),
    u64le(wireSignature.length),
    wireSignature,
    payloadBytes,
  ]);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ============================================================================
// WasmFalconSigner
// ============================================================================

/**
 * Browser & Node.js `FalconSigner` backed by `stellereum-wasm`.
 *
 * All key material stays inside this process (no CLI subprocess or HTTP helper),
 * entropy is supplied via `crypto.getRandomValues`, and temporary WASM linear
 * memory allocations are zeroized before being freed.
 */
export class WasmFalconSigner implements FalconSigner {
  readonly address: string;
  readonly addressStl57: string;
  readonly publicKey: Uint8Array;

  private readonly wasm: StellereumWasmExports;
  private readonly secretKey: Uint8Array;
  private readonly salt: Uint8Array;
  private readonly defaultChainId: number;
  private readonly getRandomValues: WasmEntropySource;
  private readonly addressBytes: Uint8Array;
  private readonly cleanups: Array<() => void> = [];
  private destroyed = false;

  constructor(
    instanceOrExports: WebAssembly.Instance | StellereumWasmExports,
    options: WasmFalconSignerOptions,
  ) {
    const rawExports =
      "exports" in instanceOrExports ? instanceOrExports.exports : instanceOrExports;
    this.wasm = assertWasmExports(rawExports);
    this.getRandomValues = options.getRandomValues ?? defaultGetRandomValues;
    this.defaultChainId = options.defaultChainId ?? DEFAULT_CHAIN_ID;

    const pk = normalizeBytesInput(options.publicKey, "publicKey");
    const sk = normalizeBytesInput(options.secretKey, "secretKey");
    if (pk.length !== FALCON512_PUBKEY_LEN || pk[0] !== FALCON_PUBKEY_HEADER) {
      sk.fill(0);
      throw new SignerError(
        "invalid_key",
        `publicKey must be ${FALCON512_PUBKEY_LEN} bytes with 0x09 header`,
      );
    }
    if (sk.length !== FALCON512_SECKEY_LEN || sk[0] !== FALCON_SECKEY_HEADER) {
      sk.fill(0);
      throw new SignerError(
        "invalid_key",
        `secretKey must be ${FALCON512_SECKEY_LEN} bytes with 0x59 header`,
      );
    }

    const salt =
      options.salt === undefined
        ? new Uint8Array(PQ_SALT_LEN)
        : normalizeBytesInput(options.salt, "salt");
    if (salt.length !== PQ_SALT_LEN) {
      sk.fill(0);
      throw new SignerError("invalid_argument", `salt must be ${PQ_SALT_LEN} bytes`);
    }

    this.publicKey = pk;
    this.secretKey = sk;
    this.salt = salt;
    try {
      this.addressBytes = WasmFalconSigner.deriveAddress(this.wasm, this.publicKey, this.salt);
    } catch (err) {
      sk.fill(0);
      throw err;
    }
    this.address = bytesToHex(this.addressBytes);
    this.addressStl57 = encodeStl57Address(this.addressBytes);
  }

  /** Instantiate `stellereum-wasm` bytes and return a ready `WasmFalconSigner`. */
  static async fromWasmBytes(
    wasmBytes: BufferSource,
    options: WasmFalconSignerOptions,
  ): Promise<WasmFalconSigner> {
    const { exports } = await instantiateStellereumWasm(wasmBytes, {
      getRandomValues: options.getRandomValues,
    });
    return new WasmFalconSigner(exports, options);
  }

  /** Instantiate `stellereum-wasm` bytes, generate a fresh Falcon-512 keypair, and wrap it. */
  static async generate(
    wasmBytes: BufferSource,
    options: {
      seed?: Uint8Array;
      salt?: Uint8Array | string;
      defaultChainId?: number;
      getRandomValues?: WasmEntropySource;
    } = {},
  ): Promise<{ signer: WasmFalconSigner; keypair: WasmFalconKeypair }> {
    const { exports } = await instantiateStellereumWasm(wasmBytes, {
      getRandomValues: options.getRandomValues,
    });
    const kp = WasmFalconSigner.generateKeypair(exports, options.seed, options.salt);
    try {
      const signer = new WasmFalconSigner(exports, {
        publicKey: kp.publicKey,
        secretKey: kp.secretKey,
        salt: options.salt,
        defaultChainId: options.defaultChainId,
        getRandomValues: options.getRandomValues,
      });
      signer.cleanups.push(() => kp.destroy());
      return { signer, keypair: kp };
    } catch (error) {
      kp.destroy();
      throw error;
    }
  }

  /** Generate a Falcon-512 keypair using an already-instantiated WASM module. */
  static generateKeypair(
    instanceOrExports: WebAssembly.Instance | StellereumWasmExports,
    seed?: Uint8Array,
    saltInput?: Uint8Array | string,
  ): WasmFalconKeypair {
    const wasm = assertWasmExports(
      "exports" in instanceOrExports ? instanceOrExports.exports : instanceOrExports,
    );
    if (seed !== undefined && seed.length !== 32) {
      throw new SignerError("invalid_argument", `keygen seed must be 32 bytes, got ${seed.length}`);
    }
    const allocations: Array<{ ptr: number; len: number }> = [];
    const allocTracked = (len: number): number => {
      const ptr = wasm.alloc(len);
      if (ptr === 0) {
        throw new SignerError("wasm_oom", `WASM alloc(${len}) returned null`);
      }
      allocations.push({ ptr, len });
      return ptr;
    };

    try {
      const seedPtr = seed ? allocTracked(seed.length) : 0;
      if (seed) {
        new Uint8Array(wasm.memory.buffer, seedPtr, seed.length).set(seed);
      }
      const pkPtr = allocTracked(FALCON512_PUBKEY_LEN);
      const skPtr = allocTracked(FALCON512_SECKEY_LEN);
      const rc = wasm.falcon_keygen(
        seedPtr,
        seed ? seed.length : 0,
        pkPtr,
        FALCON512_PUBKEY_LEN,
        skPtr,
        FALCON512_SECKEY_LEN,
      );
      if (rc !== 0) {
        throw new SignerError("keygen_failed", `WASM falcon_keygen failed with code ${rc}`);
      }
      const publicKey = new Uint8Array(
        new Uint8Array(wasm.memory.buffer, pkPtr, FALCON512_PUBKEY_LEN),
      );
      const secretKey = new Uint8Array(
        new Uint8Array(wasm.memory.buffer, skPtr, FALCON512_SECKEY_LEN),
      );
      const salt =
        saltInput === undefined
          ? new Uint8Array(PQ_SALT_LEN)
          : normalizeBytesInput(saltInput, "salt");
      const addrBytes = WasmFalconSigner.deriveAddress(wasm, publicKey, salt);
      return {
        publicKey,
        secretKey,
        address: bytesToHex(addrBytes),
        addressStl57: encodeStl57Address(addrBytes),
        destroy(): void {
          secretKey.fill(0);
        },
      };
    } finally {
      WasmFalconSigner.zeroizeAndFreeAll(wasm, allocations);
    }
  }

  /** Derive a 32-byte `STL_ADDR_V4` address via the WASM `falcon_derive_address` export. */
  static deriveAddress(
    instanceOrExports: WebAssembly.Instance | StellereumWasmExports,
    publicKey: Uint8Array,
    salt: Uint8Array = new Uint8Array(PQ_SALT_LEN),
  ): Uint8Array {
    const wasm = assertWasmExports(
      "exports" in instanceOrExports ? instanceOrExports.exports : instanceOrExports,
    );
    if (publicKey.length !== FALCON512_PUBKEY_LEN) {
      throw new SignerError(
        "invalid_key",
        `publicKey must be ${FALCON512_PUBKEY_LEN} bytes, got ${publicKey.length}`,
      );
    }
    if (salt.length !== PQ_SALT_LEN) {
      throw new SignerError("invalid_argument", `salt must be ${PQ_SALT_LEN} bytes`);
    }
    const allocations: Array<{ ptr: number; len: number }> = [];
    const allocTracked = (len: number): number => {
      const ptr = wasm.alloc(len);
      if (ptr === 0) {
        throw new SignerError("wasm_oom", `WASM alloc(${len}) returned null`);
      }
      allocations.push({ ptr, len });
      return ptr;
    };

    try {
      const pkPtr = allocTracked(publicKey.length);
      new Uint8Array(wasm.memory.buffer, pkPtr, publicKey.length).set(publicKey);
      const saltPtr = allocTracked(salt.length);
      new Uint8Array(wasm.memory.buffer, saltPtr, salt.length).set(salt);
      const addrPtr = allocTracked(PQ_ADDRESS_LEN);

      const rc = wasm.falcon_derive_address(
        pkPtr,
        publicKey.length,
        saltPtr,
        salt.length,
        addrPtr,
        PQ_ADDRESS_LEN,
      );
      if (rc !== 0) {
        throw new SignerError("derive_address_failed", `falcon_derive_address failed (${rc})`);
      }
      return new Uint8Array(new Uint8Array(wasm.memory.buffer, addrPtr, PQ_ADDRESS_LEN));
    } finally {
      WasmFalconSigner.zeroizeAndFreeAll(wasm, allocations);
    }
  }

  private static zeroizeAndFreeAll(
    wasm: StellereumWasmExports,
    allocations: Array<{ ptr: number; len: number }>,
  ): void {
    for (let i = allocations.length - 1; i >= 0; i--) {
      const { ptr, len } = allocations[i]!;
      try {
        // Re-read `wasm.memory.buffer` each iteration in case memory grew earlier.
        new Uint8Array(wasm.memory.buffer, ptr, len).fill(0);
      } finally {
        wasm.dealloc(ptr, len);
      }
    }
  }

  private assertActive(): void {
    if (this.destroyed) {
      throw new SignerError("destroyed", "WasmFalconSigner has been destroyed");
    }
  }

  /** Zeroize the JS-held secret key copy (and generated keypair if owned). Further signing calls will throw. */
  destroy(): void {
    this.secretKey.fill(0);
    for (const fn of this.cleanups) fn();
    this.cleanups.length = 0;
    this.destroyed = true;
  }

  /** Sign raw message bytes and return the 666-byte `0x29` chain-canonical signature. */
  signMessage(message: Uint8Array): Uint8Array {
    this.assertActive();
    const entropy = new Uint8Array(32);
    const allocations: Array<{ ptr: number; len: number }> = [];
    const allocTracked = (len: number): number => {
      const ptr = this.wasm.alloc(len);
      if (ptr === 0) {
        throw new SignerError("wasm_oom", `WASM alloc(${len}) returned null`);
      }
      allocations.push({ ptr, len });
      return ptr;
    };

    try {
      this.getRandomValues(entropy);
      const skPtr = allocTracked(this.secretKey.length);
      const msgAllocLen = Math.max(1, message.length);
      const msgPtr = allocTracked(msgAllocLen);
      const entropyPtr = allocTracked(entropy.length);
      const sigPtr = allocTracked(FALCON512_SIG_LEN);

      new Uint8Array(this.wasm.memory.buffer, skPtr, this.secretKey.length).set(this.secretKey);
      if (message.length > 0) {
        new Uint8Array(this.wasm.memory.buffer, msgPtr, message.length).set(message);
      }
      new Uint8Array(this.wasm.memory.buffer, entropyPtr, entropy.length).set(entropy);

      const rc = this.wasm.falcon_sign_with_entropy(
        skPtr,
        this.secretKey.length,
        msgPtr,
        message.length,
        entropyPtr,
        entropy.length,
        sigPtr,
        FALCON512_SIG_LEN,
      );
      if (rc !== 0) {
        throw new SignerError("signing_failed", `WASM falcon_sign_with_entropy failed (${rc})`);
      }

      const sig = new Uint8Array(
        new Uint8Array(this.wasm.memory.buffer, sigPtr, FALCON512_SIG_LEN),
      );
      if (sig.length !== FALCON512_SIG_LEN || sig[0] !== CHAIN_SIG_HEADER) {
        throw new SignerError(
          "signing_failed",
          `WASM returned non-canonical signature header 0x${(sig[0] ?? 0).toString(16)}`,
        );
      }
      return sig;
    } finally {
      entropy.fill(0);
      WasmFalconSigner.zeroizeAndFreeAll(this.wasm, allocations);
    }
  }

  /** Verify a 666-byte `0x29` signature over `message` against an arbitrary 897-byte public key in WASM. */
  static verifySignature(
    instanceOrExports: WebAssembly.Instance | StellereumWasmExports,
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
  ): boolean {
    const wasm = assertWasmExports(
      "exports" in instanceOrExports ? instanceOrExports.exports : instanceOrExports,
    );
    if (publicKey.length !== FALCON512_PUBKEY_LEN || publicKey[0] !== FALCON_PUBKEY_HEADER) {
      return false;
    }
    if (signature.length !== FALCON512_SIG_LEN || signature[0] !== CHAIN_SIG_HEADER) {
      return false;
    }
    const allocations: Array<{ ptr: number; len: number }> = [];
    const allocTracked = (len: number): number => {
      const ptr = wasm.alloc(len);
      if (ptr === 0) {
        throw new SignerError("wasm_oom", `WASM alloc(${len}) returned null`);
      }
      allocations.push({ ptr, len });
      return ptr;
    };

    try {
      const pkPtr = allocTracked(publicKey.length);
      const msgPtr = allocTracked(Math.max(1, message.length));
      const sigPtr = allocTracked(signature.length);

      new Uint8Array(wasm.memory.buffer, pkPtr, publicKey.length).set(publicKey);
      if (message.length > 0) {
        new Uint8Array(wasm.memory.buffer, msgPtr, message.length).set(message);
      }
      new Uint8Array(wasm.memory.buffer, sigPtr, signature.length).set(signature);

      return (
        wasm.falcon_verify(
          pkPtr,
          publicKey.length,
          msgPtr,
          message.length,
          sigPtr,
          signature.length,
        ) === 1
      );
    } finally {
      WasmFalconSigner.zeroizeAndFreeAll(wasm, allocations);
    }
  }

  /** Verify a 666-byte `0x29` signature over `message` against this signer's public key. */
  verify(message: Uint8Array, signature: Uint8Array): boolean {
    return WasmFalconSigner.verifySignature(this.wasm, this.publicKey, message, signature);
  }

  /** Sign a 32-byte digest (hex in, hex out) for EVM binding / carrier payloads. */
  async signDigest(digestHex: string): Promise<string> {
    this.assertActive();
    let digest: Uint8Array;
    try {
      digest = hexToBytes(digestHex, "digest");
    } catch (error) {
      throw new SignerError(
        "invalid_argument",
        error instanceof Error ? error.message : String(error),
      );
    }
    if (digest.length !== 32) {
      throw new SignerError("invalid_argument", `digest must be 32 bytes, got ${digest.length}`);
    }
    const sig = this.signMessage(digest);
    if (!this.verify(digest, sig)) {
      throw new SignerError("verification_failed", "Falcon-512 signature failed WASM self-check");
    }
    return bytesToHex(sig);
  }

  /** Build the canonical unsigned transaction, Falcon-sign in WASM, and emit a `PQ1` `SignResponse`. */
  async sign(request: SignRequest): Promise<SignResponse> {
    this.assertActive();
    const { tx, chainId, implicit } = this.buildTransactionFields(request.tx);
    const msg = chainId !== null ? signingMessage(tx, chainId) : baseSigningMessage(tx);
    const signature = this.signMessage(msg);
    if (!this.verify(msg, signature)) {
      throw new SignerError("verification_failed", "Falcon-512 signature failed WASM self-check");
    }

    const envelope = encodePq1Envelope({
      implicit,
      pubkey: implicit ? undefined : this.publicKey,
      salt: this.salt,
      signature,
      chainId,
    });
    const wireBytes = encodeSignedWireTransaction(tx, envelope);
    const txHash = sha256(computeTxHashPreimage(tx, envelope));

    return {
      ok: true,
      tx_hex: bytesToHex(wireBytes),
      tx_hash: bytesToHex(txHash),
      from: this.address,
      from_stl57: this.addressStl57,
      to: bytesToHex(tx.to),
      nonce: tx.nonce,
      chain_id: chainId,
      gas_limit: tx.gasLimit,
      activation: !implicit,
      envelope: implicit ? "pq1-implicit" : "pq1-explicit",
    };
  }

  /** Sign a `SponsorAuthorization` grant as the fee-paying sponsor over `sponsorMessage(tx, auth)`. */
  signSponsorAuthorization(
    tx: TransactionFields,
    options: {
      maxFeePerTx: number | bigint;
      validUntil: number | bigint;
      allowedTargets?: Array<string | Uint8Array>;
      chainId?: number;
    },
  ): SponsorAuthorization {
    this.assertActive();
    const chainId = options.chainId ?? this.defaultChainId;
    const rawTargets = options.allowedTargets ?? [];
    if (rawTargets.length > SPONSOR_MAX_TARGETS) {
      throw new SignerError(
        "invalid_argument",
        `allowedTargets exceeds SPONSOR_MAX_TARGETS (${SPONSOR_MAX_TARGETS})`,
      );
    }
    const allowedTargets = rawTargets.map((t, i) => {
      if (typeof t === "string") {
        return parseStellereumAddress(t, `allowedTargets[${i}]`);
      }
      if (t.length !== PQ_ADDRESS_LEN) {
        throw new SignerError("invalid_argument", `allowedTargets[${i}] must be ${PQ_ADDRESS_LEN} bytes`);
      }
      return new Uint8Array(t);
    });
    const baseAuth = {
      sponsor: new Uint8Array(this.addressBytes),
      maxFeePerTx: options.maxFeePerTx,
      validUntil: options.validUntil,
      allowedTargets,
      chainId,
    };
    const spMsg = sponsorMessage(tx, baseAuth);
    const sponsorSig = this.signMessage(spMsg);
    if (!this.verify(spMsg, sponsorSig)) {
      throw new SignerError("verification_failed", "Falcon-512 sponsor signature failed WASM self-check");
    }
    return {
      ...baseAuth,
      sponsorSig,
      sponsorScheme: PQ_SCHEME_FALCON512,
      sponsorPubkey: new Uint8Array(this.publicKey),
      sponsorSalt: new Uint8Array(this.salt),
    };
  }

  /**
   * Build and co-sign a FULL-PQ Paymaster v2 (`PQ1` + `SP1`) sponsored transaction.
   *
   * Signing order matches the node (`Transaction::sign_with_sponsor_falcon512`):
   * sponsor signs `sponsorMessage(tx, auth)` FIRST, then the user (`this`)
   * signs `sponsoredSigningMessage(tx, auth)` committing to the full grant.
   */
  async cosignWithSponsor(request: CosignWithSponsorRequest): Promise<SignResponse> {
    this.assertActive();
    const { tx, chainId, implicit } = this.buildTransactionFields(request.tx);
    if (chainId === null) {
      throw new SignerError(
        "invalid_argument",
        "sponsored transactions cannot be unbound: a concrete chain_id is required",
      );
    }

    let auth: SponsorAuthorization;
    if ("signer" in request.sponsor) {
      auth = request.sponsor.signer.signSponsorAuthorization(tx, {
        maxFeePerTx: request.sponsor.maxFeePerTx,
        validUntil: request.sponsor.validUntil,
        allowedTargets: request.sponsor.allowedTargets,
        chainId,
      });
    } else {
      auth = request.sponsor;
      if (BigInt(auth.chainId) !== BigInt(chainId)) {
        throw new SignerError(
          "invalid_argument",
          `sponsor grant chain_id ${auth.chainId} != transaction chain_id ${chainId}`,
        );
      }
      if (auth.sponsor.length !== PQ_ADDRESS_LEN) {
        throw new SignerError("invalid_argument", `sponsor must be ${PQ_ADDRESS_LEN} bytes`);
      }
      if (auth.sponsorSig.length !== FALCON512_SIG_LEN) {
        throw new SignerError(
          "invalid_argument",
          `sponsorSig must be ${FALCON512_SIG_LEN} bytes, got ${auth.sponsorSig.length}`,
        );
      }
      if (auth.sponsorScheme !== PQ_SCHEME_FALCON512 && auth.sponsorScheme !== "falcon512") {
        throw new SignerError("invalid_argument", "FULL-PQ Paymaster v2 requires Falcon-512 sponsorScheme");
      }
      if (!auth.sponsorPubkey || auth.sponsorPubkey.length !== FALCON512_PUBKEY_LEN) {
        throw new SignerError(
          "invalid_key",
          `sponsorPubkey must be ${FALCON512_PUBKEY_LEN} bytes`,
        );
      }
      const spSalt = auth.sponsorSalt ?? new Uint8Array(PQ_SALT_LEN);
      if (spSalt.length !== PQ_SALT_LEN) {
        throw new SignerError("invalid_argument", `sponsorSalt must be ${PQ_SALT_LEN} bytes`);
      }
      const derivedSponsor = WasmFalconSigner.deriveAddress(this.wasm, auth.sponsorPubkey, spSalt);
      if (!bytesEqual(derivedSponsor, auth.sponsor)) {
        throw new SignerError("invalid_key", "sponsorPubkey + sponsorSalt does not derive sponsor address");
      }
      const spMsg = sponsorMessage(tx, auth);
      if (!WasmFalconSigner.verifySignature(this.wasm, auth.sponsorPubkey, spMsg, auth.sponsorSig)) {
        throw new SignerError(
          "verification_failed",
          "Falcon-512 sponsor signature failed WASM verification",
        );
      }
    }

    const userMsg = sponsoredSigningMessage(tx, auth);
    const userSig = this.signMessage(userMsg);
    if (!this.verify(userMsg, userSig)) {
      throw new SignerError("verification_failed", "Falcon-512 user signature failed WASM self-check");
    }

    // Sponsored PQ1 inner envelope leaves chainId null because chain_id is committed via SPONSOR_.
    const innerEnvelope = encodePq1Envelope({
      implicit,
      pubkey: implicit ? undefined : this.publicKey,
      salt: this.salt,
      signature: userSig,
      chainId: null,
    });
    const fullSignature = concatBytes([innerEnvelope, encodeSponsorSuffix(auth)]);
    const wireBytes = encodeSignedWireTransaction(tx, fullSignature);
    const txHash = sha256(computeTxHashPreimage(tx, fullSignature));

    return {
      ok: true,
      tx_hex: bytesToHex(wireBytes),
      tx_hash: bytesToHex(txHash),
      from: this.address,
      from_stl57: this.addressStl57,
      to: bytesToHex(tx.to),
      nonce: tx.nonce,
      chain_id: chainId,
      gas_limit: tx.gasLimit,
      activation: !implicit,
      envelope: implicit ? "pq1-implicit+sp1" : "pq1-explicit+sp1",
    };
  }

  /** Mint and Falcon-512 sign a `SessionGrant` (`SessionKeyAuthorization`) as the master key. */
  createSessionGrant(options: CreateSessionGrantOptions): SessionGrant {
    this.assertActive();
    if (!this.salt.every((b) => b === 0)) {
      throw new SignerError("invalid_argument", "session master key must use default 16-byte zero salt");
    }
    const chainId = options.chainId ?? this.defaultChainId;
    const sessionPk = normalizeBytesInput(options.sessionPublicKey, "sessionPublicKey");
    if (sessionPk.length !== FALCON512_PUBKEY_LEN || sessionPk[0] !== FALCON_PUBKEY_HEADER) {
      throw new SignerError(
        "invalid_key",
        `sessionPublicKey must be ${FALCON512_PUBKEY_LEN} bytes with 0x09 header`,
      );
    }
    const sessionPubkey = WasmFalconSigner.deriveAddress(
      this.wasm,
      sessionPk,
      new Uint8Array(PQ_SALT_LEN),
    );
    const msg = sessionGrantMessage({
      masterAddress: this.addressBytes,
      sessionPubkey,
      validUntil: options.validUntil,
      maxGasSpend: options.maxGasSpend,
      scope: options.scope,
      maxValuePerTx: options.maxValuePerTx,
      chainId,
    });
    const masterSignature = this.signMessage(msg);
    if (!this.verify(msg, masterSignature)) {
      throw new SignerError(
        "verification_failed",
        "Falcon-512 session grant signature failed WASM self-check",
      );
    }
    return {
      masterAddress: new Uint8Array(this.addressBytes),
      sessionPubkey,
      validUntil: options.validUntil,
      maxGasSpend: options.maxGasSpend,
      gasSpent: options.gasSpent ?? 0,
      scope: options.scope,
      maxValuePerTx: options.maxValuePerTx,
      chainId,
      masterSignature,
      masterScheme: PQ_SCHEME_FALCON512,
      sessionScheme: PQ_SCHEME_FALCON512,
      masterPubkey: new Uint8Array(this.publicKey),
      sessionPubkeyBytes: sessionPk,
    };
  }

  /** Sign a transaction using this signer as the delegated Falcon-512 session key (`SF1` envelope). */
  async signWithSession(request: SignWithSessionRequest): Promise<SignResponse> {
    this.assertActive();
    const { grant } = request;
    if (!this.salt.every((b) => b === 0)) {
      throw new SignerError("invalid_argument", "session key must use default 16-byte zero salt");
    }
    if (grant.masterAddress.length !== PQ_ADDRESS_LEN || grant.sessionPubkey.length !== PQ_ADDRESS_LEN) {
      throw new SignerError("invalid_argument", `session grant addresses must be ${PQ_ADDRESS_LEN} bytes`);
    }
    if (
      grant.masterScheme !== undefined &&
      grant.masterScheme !== PQ_SCHEME_FALCON512 &&
      grant.masterScheme !== "falcon512"
    ) {
      throw new SignerError("invalid_argument", "SF1 requires Falcon-512 masterScheme");
    }
    if (
      grant.sessionScheme !== undefined &&
      grant.sessionScheme !== PQ_SCHEME_FALCON512 &&
      grant.sessionScheme !== "falcon512"
    ) {
      throw new SignerError("invalid_argument", "SF1 requires Falcon-512 sessionScheme");
    }
    if (!grant.sessionPubkeyBytes || !bytesEqual(grant.sessionPubkeyBytes, this.publicKey)) {
      throw new SignerError("invalid_key", "session grant sessionPubkeyBytes does not match this signer");
    }
    if (!bytesEqual(grant.sessionPubkey, this.addressBytes)) {
      throw new SignerError("invalid_key", "session grant sessionPubkey does not match this signer address");
    }
    if (!grant.masterPubkey || grant.masterPubkey.length !== FALCON512_PUBKEY_LEN) {
      throw new SignerError(
        "invalid_key",
        `session grant requires ${FALCON512_PUBKEY_LEN}-byte masterPubkey`,
      );
    }
    const derivedMaster = WasmFalconSigner.deriveAddress(
      this.wasm,
      grant.masterPubkey,
      new Uint8Array(PQ_SALT_LEN),
    );
    if (!bytesEqual(derivedMaster, grant.masterAddress)) {
      throw new SignerError("invalid_key", "session grant masterPubkey does not derive masterAddress");
    }
    const grantMsg = sessionGrantMessage(grant);
    if (!WasmFalconSigner.verifySignature(this.wasm, grant.masterPubkey, grantMsg, grant.masterSignature)) {
      throw new SignerError(
        "verification_failed",
        "Falcon-512 session grant masterSignature failed WASM verification",
      );
    }

    if (request.tx.unbound === true || request.tx.chain_id === null) {
      throw new SignerError("invalid_argument", "session-keyed transactions cannot be unbound");
    }
    const { tx, chainId } = this.buildTransactionFields(
      request.tx,
      grant.masterAddress,
      Number(grant.chainId),
    );
    if (chainId === null || BigInt(chainId) !== BigInt(grant.chainId)) {
      throw new SignerError(
        "invalid_argument",
        `session transaction chain_id ${String(chainId)} != grant chain_id ${grant.chainId}`,
      );
    }

    const msg = sessionSigningMessage(tx, grant);
    const sessionSig = this.signMessage(msg);
    if (!this.verify(msg, sessionSig)) {
      throw new SignerError("verification_failed", "Falcon-512 session signature failed WASM self-check");
    }

    const sf1Envelope = encodeSessionEnvelope(sessionSig, grant);
    const wireBytes = encodeSignedWireTransaction(tx, sf1Envelope);
    const txHash = sha256(computeTxHashPreimage(tx, sf1Envelope));

    return {
      ok: true,
      tx_hex: bytesToHex(wireBytes),
      tx_hash: bytesToHex(txHash),
      from: bytesToHex(grant.masterAddress),
      from_stl57: encodeStl57Address(grant.masterAddress),
      to: bytesToHex(tx.to),
      nonce: tx.nonce,
      chain_id: Number(grant.chainId),
      gas_limit: tx.gasLimit,
      activation: false,
      envelope: "sf1",
    };
  }

  private resolveCommon(
    common: TxCommon,
    explicitChainId?: number | null,
    defaultChainIdOverride?: number,
  ): {
    chainId: number | null;
    implicit: boolean;
    baseFee: number;
    priorityFeePerGas: number;
    nonce: number;
    sourceShard: number;
    targetShard: number;
  } {
    const implicit = common.implicit === true;
    const unbound = common.unbound === true;
    if (!unbound && (explicitChainId === null || common.chain_id === null)) {
      throw new SignerError("invalid_argument", "chain_id: null is only valid when unbound: true");
    }
    const chainId = unbound
      ? null
      : (explicitChainId ?? common.chain_id ?? defaultChainIdOverride ?? this.defaultChainId);
    const baseFee = common.base_fee ?? FROZEN_MIN_GAS_FLOOR;
    const priorityFeePerGas = common.priority_fee_per_gas ?? 0;
    const nonce = common.nonce ?? 0;
    const sourceShard = common.source_shard ?? MASTERCHAIN_SHARD;
    const targetShard = common.target_shard ?? MASTERCHAIN_SHARD;
    return {
      chainId,
      implicit,
      baseFee,
      priorityFeePerGas,
      nonce,
      sourceShard,
      targetShard,
    };
  }

  private computeGasLimit(
    execGas: number,
    explicitGas: number | undefined,
    baseFee: number,
    implicit: boolean,
    priorityFeePerGas: number,
    floor = FROZEN_MIN_GAS_FLOOR,
  ): number {
    if (explicitGas !== undefined) return explicitGas;
    const surcharge = implicit ? 0 : PQ_ACTIVATION_SURCHARGE_GAS;
    return Math.max(execGas, baseFee, floor) + surcharge + priorityFeePerGas;
  }

  private buildTransactionFields(
    intent: TxIntent,
    fromOverride?: Uint8Array,
    defaultChainIdOverride?: number,
  ): {
    tx: TransactionFields;
    chainId: number | null;
    implicit: boolean;
  } {
    const common = this.resolveCommon(
      intent,
      intent.kind === "contractDeploy" || intent.kind === "contract_deploy"
        ? intent.chainId
        : undefined,
      defaultChainIdOverride,
    );
    const from = fromOverride ? new Uint8Array(fromOverride) : new Uint8Array(this.addressBytes);

    switch (intent.kind) {
      case "prepared": {
        const raw = hexToBytes(intent.tx_hex, "tx_hex");
        const { tx } = decodeUnsignedWireTx(raw);
        if (!bytesEqual(tx.from, from)) {
          throw new SignerError(
            "invalid_argument",
            `unsigned transaction from 0x${bytesToHex(tx.from)} does not match signer 0x${this.address}`,
          );
        }
        if (common.priorityFeePerGas !== 0) {
          if (tx.priorityFeePerGas === 0) {
            tx.priorityFeePerGas = common.priorityFeePerGas;
          } else if (tx.priorityFeePerGas !== common.priorityFeePerGas) {
            throw new SignerError(
              "invalid_argument",
              `prepared tx priority_fee_per_gas (${tx.priorityFeePerGas}) != request priority_fee_per_gas (${common.priorityFeePerGas})`,
            );
          }
        }
        return { tx, chainId: common.chainId, implicit: common.implicit };
      }

      case "transfer": {
        const to = parseStellereumAddress(intent.to, "to");
        const gasLimit = this.computeGasLimit(
          FROZEN_MIN_GAS_FLOOR,
          intent.gas_limit,
          common.baseFee,
          common.implicit,
          common.priorityFeePerGas,
        );
        return {
          tx: {
            from,
            to,
            amount: intent.amount,
            gasLimit,
            nonce: common.nonce,
            sourceShard: common.sourceShard,
            targetShard: common.targetShard,
            payload: encodePayload([]),
            priorityFeePerGas: common.priorityFeePerGas,
          },
          chainId: common.chainId,
          implicit: common.implicit,
        };
      }

      case "contractDeploy":
      case "contract_deploy": {
        if (intent.from !== undefined) {
          const explicitFrom = parseStellereumAddress(intent.from, "from");
          if (!bytesEqual(explicitFrom, from)) {
            throw new SignerError(
              "invalid_argument",
              `contractDeploy from 0x${bytesToHex(explicitFrom)} does not match signer 0x${this.address}`,
            );
          }
        }
        const code = intent.code ?? intent.code_hex;
        if (code === undefined) {
          throw new SignerError("invalid_argument", "contractDeploy requires code or code_hex");
        }
        const { payload, execGas } = encodeDeployContractPayload(code, intent.abi ?? intent.abi_json);
        const gasLimit = this.computeGasLimit(
          execGas,
          intent.gas ?? intent.gas_limit,
          common.baseFee,
          common.implicit,
          common.priorityFeePerGas,
        );
        return {
          tx: {
            from,
            to: new Uint8Array(from),
            amount: 0,
            gasLimit,
            nonce: common.nonce,
            sourceShard: common.sourceShard,
            targetShard: common.targetShard,
            payload,
            priorityFeePerGas: common.priorityFeePerGas,
          },
          chainId: common.chainId,
          implicit: common.implicit,
        };
      }

      case "contract_call": {
        const contract = parseStellereumAddress(intent.contract, "contract");
        const { opBytes, execGas } = encodeCallContractArgsOp(
          contract,
          intent.method,
          intent.args ?? [],
        );
        const payload = concatBytes([u64le(1), opBytes]);
        const gasLimit = this.computeGasLimit(
          execGas,
          intent.gas_limit,
          common.baseFee,
          common.implicit,
          common.priorityFeePerGas,
        );
        return {
          tx: {
            from,
            to: contract,
            amount: intent.value ?? 0,
            gasLimit,
            nonce: common.nonce,
            sourceShard: common.sourceShard,
            targetShard: common.targetShard,
            payload,
            priorityFeePerGas: common.priorityFeePerGas,
          },
          chainId: common.chainId,
          implicit: common.implicit,
        };
      }

      case "contract_call_raw": {
        const contract = parseStellereumAddress(intent.contract, "contract");
        const rawInput = intent.rawCalldata ?? intent.calldata_hex ?? new Uint8Array(0);
        const { opBytes, execGas } = encodeCallContractRawOp(
          contract,
          intent.method,
          intent.args ?? [],
          rawInput,
        );
        const payload = concatBytes([u64le(1), opBytes]);
        const gasLimit = this.computeGasLimit(
          execGas,
          intent.gas_limit,
          common.baseFee,
          common.implicit,
          common.priorityFeePerGas,
        );
        return {
          tx: {
            from,
            to: contract,
            amount: intent.value ?? 0,
            gasLimit,
            nonce: common.nonce,
            sourceShard: common.sourceShard,
            targetShard: common.targetShard,
            payload,
            priorityFeePerGas: common.priorityFeePerGas,
          },
          chainId: common.chainId,
          implicit: common.implicit,
        };
      }

      case "stake": {
        const validator = parseStellereumAddress(intent.validator, "validator");
        const payload = concatBytes([u64le(1), encodeStakeOp(validator, intent.amount)]);
        const gasLimit = this.computeGasLimit(
          GAS_STAKE_BOND,
          intent.gas_limit,
          common.baseFee,
          common.implicit,
          common.priorityFeePerGas,
        );
        return {
          tx: {
            from,
            to: new Uint8Array(from),
            amount: intent.amount,
            gasLimit,
            nonce: common.nonce,
            sourceShard: common.sourceShard,
            targetShard: common.targetShard,
            payload,
            priorityFeePerGas: common.priorityFeePerGas,
          },
          chainId: common.chainId,
          implicit: common.implicit,
        };
      }

      case "unjail": {
        const validator = parseStellereumAddress(intent.validator, "validator");
        const topUp = intent.top_up ?? 0;
        const ops: Uint8Array[] = [];
        let execGas = GAS_STAKE_UNBOND;
        if (topUp > 0) {
          ops.push(encodeStakeOp(validator, topUp));
          execGas += GAS_STAKE_BOND;
        }
        ops.push(encodeUnjailOp(validator));
        const payload = concatBytes([u64le(ops.length), ...ops]);
        const gasLimit = this.computeGasLimit(
          execGas,
          intent.gas_limit,
          common.baseFee,
          common.implicit,
          common.priorityFeePerGas,
        );
        return {
          tx: {
            from,
            to: new Uint8Array(from),
            amount: topUp,
            gasLimit,
            nonce: common.nonce,
            sourceShard: common.sourceShard,
            targetShard: common.targetShard,
            payload,
            priorityFeePerGas: common.priorityFeePerGas,
          },
          chainId: common.chainId,
          implicit: common.implicit,
        };
      }

      case "gov_propose": {
        if (new TextEncoder().encode(intent.title).length > MAX_PROPOSAL_TITLE_BYTES) {
          throw new SignerError(
            "invalid_argument",
            `proposal title exceeds ${MAX_PROPOSAL_TITLE_BYTES} bytes`,
          );
        }
        const action = intent.action as unknown as GovAction;
        // Validate encoding via wire.ts
        try {
          encodeGovAction(action);
        } catch (error) {
          throw new SignerError(
            "invalid_argument",
            error instanceof Error ? error.message : String(error),
          );
        }
        const payload = encodePayload([
          {
            kind: "gov_propose",
            proposalId: intent.proposal_id,
            title: intent.title,
            action,
            heightObserved: intent.height_observed,
          },
        ]);
        const gasLimit = this.computeGasLimit(
          GAS_GOV_PROPOSE,
          intent.gas_limit,
          common.baseFee,
          common.implicit,
          common.priorityFeePerGas,
        );
        return {
          tx: {
            from,
            to: new Uint8Array(from),
            amount: 0,
            gasLimit,
            nonce: common.nonce,
            sourceShard: common.sourceShard,
            targetShard: common.targetShard,
            payload,
            priorityFeePerGas: common.priorityFeePerGas,
          },
          chainId: common.chainId,
          implicit: common.implicit,
        };
      }

      case "gov_vote": {
        const choice: VoteChoice = intent.choice;
        const payload = encodePayload([
          {
            kind: "gov_vote",
            proposalId: intent.proposal_id,
            choice,
            heightObserved: intent.height_observed,
          },
        ]);
        const gasLimit = this.computeGasLimit(
          GAS_GOV_VOTE,
          intent.gas_limit,
          common.baseFee,
          common.implicit,
          common.priorityFeePerGas,
        );
        return {
          tx: {
            from,
            to: new Uint8Array(from),
            amount: 0,
            gasLimit,
            nonce: common.nonce,
            sourceShard: common.sourceShard,
            targetShard: common.targetShard,
            payload,
            priorityFeePerGas: common.priorityFeePerGas,
          },
          chainId: common.chainId,
          implicit: common.implicit,
        };
      }

      case "evm_binding": {
        if (common.chainId === null) {
          throw new SignerError(
            "invalid_argument",
            "evm_binding cannot be unbound: a concrete chain_id is required",
          );
        }
        const boundChain = common.chainId;
        const evm = hexToBytes(intent.evm_address, "evm_address");
        if (evm.length !== 20) {
          throw new SignerError("invalid_address", `evm_address must be 20 bytes, got ${evm.length}`);
        }
        const proof = requireBindingProof(intent.evm_proof);
        const digest = bindingMessage(boundChain, evm, from);
        const bindingSignature = this.signMessage(digest);
        const payload = encodePayload([
          {
            kind: "evm_binding",
            chainId: boundChain,
            evmAddress: evm,
            pqPubkey: this.publicKey,
            bindingSignature,
            evmSignature: proof,
          },
        ]);
        const execGas =
          GAS_EVM_CARRIER_BASE +
          GAS_PQ_VERIFY_BASE +
          (this.publicKey.length + 32 + bindingSignature.length) * GAS_PQ_VERIFY_PER_BYTE;
        const gasLimit = this.computeGasLimit(
          execGas,
          intent.gas_limit,
          common.baseFee,
          common.implicit,
          common.priorityFeePerGas,
          EVM_BINDING_MIN_GAS,
        );
        return {
          tx: {
            from,
            to: new Uint8Array(from),
            amount: 0,
            gasLimit,
            nonce: common.nonce,
            sourceShard: common.sourceShard,
            targetShard: common.targetShard,
            payload,
            priorityFeePerGas: common.priorityFeePerGas,
          },
          chainId: common.chainId,
          implicit: common.implicit,
        };
      }

      case "evm_carrier": {
        if (common.chainId === null) {
          throw new SignerError(
            "invalid_argument",
            "evm_carrier cannot be unbound: a concrete chain_id is required",
          );
        }
        const boundChain = common.chainId;
        const rawEvmTx = hexToBytes(intent.evm_tx, "evm_tx");
        const facts = decodeEvmIntent(rawEvmTx);
        if (facts.chainId !== boundChain) {
          throw new SignerError(
            "invalid_argument",
            `EVM intent chain id ${facts.chainId} != ${boundChain}`,
          );
        }
        if (intent.nonce !== undefined && intent.nonce !== facts.nonce) {
          throw new SignerError(
            "carrier_nonce_mismatch",
            `carrier nonce mismatch: EVM intent says ${facts.nonce}, request says ${intent.nonce}`,
          );
        }
        if (intent.amount_nano !== undefined && intent.amount_nano !== facts.valueNano) {
          throw new SignerError(
            "carrier_value_mismatch",
            `carrier value mismatch: EVM intent is ${facts.valueNano}, request says ${intent.amount_nano}`,
          );
        }
        const toPq = parseStellereumAddress(intent.to_pq, "to_pq");
        if (!intent.evm_address) {
          throw new SignerError(
            "invalid_argument",
            "evm_carrier requires evm_address (20-byte secp256k1 sender address matching evm_tx)",
          );
        }
        const evmAddress = hexToBytes(intent.evm_address, "evm_address");
        if (evmAddress.length !== 20 || evmAddress.every((b) => b === 0)) {
          throw new SignerError("invalid_argument", "evm_carrier evm_address must be 20 non-zero bytes");
        }
        const intentSignature = this.signMessage(evmIntentDigest(rawEvmTx));
        const payload = encodePayload([
          {
            kind: "evm_carrier",
            chainId: boundChain,
            evmTx: rawEvmTx,
            evmAddress,
            pqPubkey: this.publicKey,
            evmSignature: intentSignature,
          },
        ]);
        const execGas =
          GAS_EVM_CARRIER_BASE +
          GAS_PQ_VERIFY_BASE +
          (this.publicKey.length + 32 + intentSignature.length + rawEvmTx.length) *
            GAS_PQ_VERIFY_PER_BYTE;
        const gasLimit = this.computeGasLimit(
          execGas,
          intent.gas_limit,
          common.baseFee,
          common.implicit,
          common.priorityFeePerGas,
          EVM_CARRIER_MIN_GAS,
        );
        return {
          tx: {
            from,
            to: toPq,
            amount: facts.valueNano,
            gasLimit,
            nonce: facts.nonce,
            sourceShard: common.sourceShard,
            targetShard: common.targetShard,
            payload,
            priorityFeePerGas: common.priorityFeePerGas,
          },
          chainId: common.chainId,
          implicit: common.implicit,
        };
      }
    }
  }
}

export { CHAIN_ID_COMMITMENT_TAG };
