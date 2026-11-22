/**
 * Unsigned builders for the node's EVM and governance transaction shapes.
 *
 * ## Signing is delegated, never faked
 *
 * The result is an `UnsignedTransaction`: `bincode(Transaction)` with an empty
 * signature plus the exact preimage the PQ1 envelope must sign. Attach the
 * Falcon signature with the Rust sidecar
 * (`stellereum-sdk-cli sign` / `sign_prepared`, or `client.signPrepared`).
 *
 * Two EVM shapes also carry an INNER Falcon signature (the binding statement
 * and the carrier's EVM-intent authorisation). JavaScript cannot produce it;
 * the callers pass it in (the documented sidecar hook), and the SDK refuses a
 * missing or wrong-length one instead of pretending.
 */

import {
  EVM_BINDING_MIN_GAS,
  EVM_CARRIER_MIN_GAS,
  bindingMessage,
  decodeEvmIntent,
  requireBindingProof,
} from "./evm.ts";
import {
  assertChainId,
  assertIdentity,
  localIdentity,
  type ProtocolIdentity,
} from "./protocol.ts";
import {
  FROZEN_MIN_GAS_FLOOR,
  GAS_GOV_PROPOSE,
  GAS_GOV_VOTE,
  MASTERCHAIN_SHARD,
  PQ_ACTIVATION_SURCHARGE_GAS,
  address20,
  address32,
  bytesToHex,
  encodeOp,
  encodePayload,
  finishUnsigned,
  hexToBytes,
  type GovAction,
  type UnsignedTransaction,
  type VoteChoice,
} from "./wire.ts";

import { evmIntentDigest } from "./evm.ts";

import { FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN } from "./constants.ts";

export { FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN };

export type BuilderErrorCode =
  | "invalid_argument"
  | "missing_evm_proof"
  | "missing_inner_signature"
  | "carrier_nonce_mismatch"
  | "carrier_value_mismatch"
  | "invalid_evm_intent";

export class BuilderError extends Error {
  readonly code: BuilderErrorCode;

  constructor(code: BuilderErrorCode, message: string) {
    super(message);
    this.name = "BuilderError";
    this.code = code;
  }
}

export interface BaseTxOptions {
  /** Sender's PQ address, 32-byte hex (with or without 0x). */
  from: string;
  identity?: ProtocolIdentity;
  /** Must equal the identity's chain id when supplied. */
  chainId?: number;
  /** Sender nonce (`stell_getBalance`); for carriers this is the EVM nonce. */
  nonce?: number;
  gasLimit?: number;
  baseFee?: number;
  priorityFeePerGas?: number;
  sourceShard?: number;
  targetShard?: number;
  /** Provider's PQ public key (897 bytes, hex). Required by EVM payloads. */
  pqPublicKey?: string;
}

function resolve(identity: ProtocolIdentity | undefined, chainId: number | undefined): number {
  const id = identity ?? localIdentity();
  assertIdentity(id);
  const chain = chainId ?? id.chainId;
  assertChainId(id, chain);
  return chain;
}

function feeGas(opGas: number, options: BaseTxOptions, floor = FROZEN_MIN_GAS_FLOOR): number {
  if (options.gasLimit !== undefined) return options.gasLimit;
  const base = Math.max(opGas, options.baseFee ?? floor, floor);
  return base + PQ_ACTIVATION_SURCHARGE_GAS + (options.priorityFeePerGas ?? 0);
}

function pubkey(value: string | undefined): Uint8Array {
  if (value === undefined) {
    throw new BuilderError("invalid_argument", "pqPublicKey is required");
  }
  const bytes = hexToBytes(value, "pqPublicKey");
  if (bytes.length !== FALCON512_PUBKEY_LEN) {
    throw new BuilderError(
      "invalid_argument",
      `pqPublicKey must be a ${FALCON512_PUBKEY_LEN}-byte Falcon-512 key, got ${bytes.length}`,
    );
  }
  return bytes;
}

function innerSignature(value: string, field: string): Uint8Array {
  if (value.length === 0) {
    throw new BuilderError("missing_inner_signature", `${field} is required (Falcon-512 sidecar hook)`);
  }
  const bytes = hexToBytes(value, field);
  if (bytes.length !== FALCON512_SIG_LEN) {
    throw new BuilderError(
      "invalid_argument",
      `${field} must be a ${FALCON512_SIG_LEN}-byte Falcon-512 signature, got ${bytes.length}`,
    );
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// EVM binding
// ---------------------------------------------------------------------------

export interface EvmBindingOptions extends BaseTxOptions {
  /** 20-byte EVM address being bound. */
  evmAddress: string;
  /** 65-byte secp256k1 proof of possession, hex. */
  evmProof: string;
  /** 666-byte Falcon signature over `bindingMessage(...)`, hex. */
  bindingSignature: string;
}

/**
 * Build the unsigned `SysCallBindEvmAddress` claim transaction.
 *
 * Refuses a missing/malformed proof of possession (the node would refuse the
 * claim too: an EVM address may not be first-claimed by a PQ key that does not
 * control it).
 */
export function buildEvmBinding(options: EvmBindingOptions): UnsignedTransaction {
  const chainId = resolve(options.identity, options.chainId);
  let proof: Uint8Array;
  try {
    proof = requireBindingProof(options.evmProof);
  } catch (error) {
    throw new BuilderError(
      "missing_evm_proof",
      error instanceof Error ? error.message : String(error),
    );
  }
  const bindingSignature = innerSignature(options.bindingSignature, "bindingSignature");
  const from = address32(options.from, "from");
  const evm = address20(options.evmAddress, "evmAddress");
  const payload = encodePayload([
    {
      kind: "evm_binding",
      chainId,
      evmAddress: evm,
      pqPubkey: pubkey(options.pqPublicKey),
      bindingSignature,
      evmSignature: proof,
    },
  ]);
  const tx = {
    from,
    to: from,
    amount: 0,
    gasLimit: feeGas(0, options, EVM_BINDING_MIN_GAS),
    nonce: options.nonce ?? 0,
    sourceShard: options.sourceShard ?? MASTERCHAIN_SHARD,
    targetShard: options.targetShard ?? MASTERCHAIN_SHARD,
    payload,
    priorityFeePerGas: options.priorityFeePerGas ?? 0,
  };
  return finishUnsigned(tx, chainId);
}

/** The digest an EVM key signs for a binding proof (`bindingMessage`). */
export function evmBindingDigest(
  chainId: number,
  evmAddress: string,
  pqAddress: string,
): string {
  return bytesToHex(bindingMessage(chainId, address20(evmAddress, "evmAddress"), address32(pqAddress, "pqAddress")));
}

// ---------------------------------------------------------------------------
// EVM carrier
// ---------------------------------------------------------------------------

export interface EvmCarrierOptions extends Omit<BaseTxOptions, "nonce"> {
  /** Raw EIP-155 / EIP-1559 transaction bytes, hex. */
  evmTx: string;
  /** EVM sender address carried in the payload (20-byte hex). */
  evmAddress: string;
  /** Recipient's bound PQ account (32-byte hex). */
  toPq: string;
  /** 666-byte Falcon signature over `keccak256(evmTx)`, hex. */
  intentSignature: string;
  /** Optional nonce pin; must equal the EVM intent's nonce. */
  nonce?: number;
  /** Optional amount pin (nano-STELL); must equal the EVM value. */
  amountNano?: number;
}

export interface EvmCarrierPlan extends UnsignedTransaction {
  evmNonce: number;
  evmValueNano: number;
  evmChainId: number;
}

/**
 * Build the unsigned `SysCallEvmCarrier` transaction.
 *
 * The carrier's nonce and amount are taken from the EVM intent, never from a
 * caller default; passing `nonce`/`amountNano` pins them and a mismatch is
 * refused with a specific `BuilderError`.
 */
export function buildEvmCarrier(options: EvmCarrierOptions): EvmCarrierPlan {
  const chainId = resolve(options.identity, options.chainId);
  let raw: Uint8Array;
  let facts;
  try {
    raw = hexToBytes(options.evmTx, "evmTx");
    facts = decodeEvmIntent(raw);
  } catch (error) {
    throw new BuilderError(
      "invalid_evm_intent",
      error instanceof Error ? error.message : String(error),
    );
  }
  if (facts.chainId !== chainId) {
    throw new BuilderError(
      "invalid_evm_intent",
      `EVM intent chain id ${facts.chainId} does not match the carrier chain id ${chainId}`,
    );
  }
  if (options.nonce !== undefined && options.nonce !== facts.nonce) {
    throw new BuilderError(
      "carrier_nonce_mismatch",
      `carrier nonce mismatch: EVM intent says ${facts.nonce}, transaction says ${options.nonce}`,
    );
  }
  if (options.amountNano !== undefined && options.amountNano !== facts.valueNano) {
    throw new BuilderError(
      "carrier_value_mismatch",
      `carrier value mismatch: EVM intent is worth ${facts.valueNano} nano-STELL, transaction moves ${options.amountNano}`,
    );
  }
  const intentSignature = innerSignature(options.intentSignature, "intentSignature");
  const from = address32(options.from, "from");
  const to = address32(options.toPq, "toPq");
  if (to.every((b) => b === 0)) {
    throw new BuilderError("invalid_argument", "carrier recipient must be a real PQ account");
  }
  const payload = encodePayload([
    {
      kind: "evm_carrier",
      chainId,
      evmTx: raw,
      evmAddress: address20(options.evmAddress, "evmAddress"),
      pqPubkey: pubkey(options.pqPublicKey),
      evmSignature: intentSignature,
    },
  ]);
  const tx = {
    from,
    to,
    amount: facts.valueNano,
    gasLimit: feeGas(0, options, EVM_CARRIER_MIN_GAS),
    nonce: facts.nonce,
    sourceShard: options.sourceShard ?? MASTERCHAIN_SHARD,
    targetShard: options.targetShard ?? MASTERCHAIN_SHARD,
    payload,
    priorityFeePerGas: options.priorityFeePerGas ?? 0,
  };
  return {
    ...finishUnsigned(tx, chainId),
    evmNonce: facts.nonce,
    evmValueNano: facts.valueNano,
    evmChainId: facts.chainId,
  };
}

/** `keccak256(raw)` as hex — the digest the carrier intent signature covers. */
export function evmCarrierDigest(evmTx: string): string {
  return bytesToHex(evmIntentDigest(hexToBytes(evmTx, "evmTx")));
}

// ---------------------------------------------------------------------------
// Governance
// ---------------------------------------------------------------------------

export interface GovProposeOptions extends BaseTxOptions {
  proposalId: number;
  title: string;
  action: GovAction;
  /** The block height the transaction applies at (must match exactly). */
  heightObserved: number;
}

/** Build the unsigned block-carried `SysCallGovPropose` transaction. */
export function buildGovPropose(options: GovProposeOptions): UnsignedTransaction {
  const chainId = resolve(options.identity, options.chainId);
  if (new TextEncoder().encode(options.title).length > 256) {
    throw new BuilderError("invalid_argument", "proposal title exceeds 256 bytes");
  }
  const from = address32(options.from, "from");
  const payload = encodePayload([
    {
      kind: "gov_propose",
      proposalId: options.proposalId,
      title: options.title,
      action: options.action,
      heightObserved: options.heightObserved,
    },
  ]);
  const tx = {
    from,
    to: from,
    amount: 0,
    gasLimit: feeGas(GAS_GOV_PROPOSE, options),
    nonce: options.nonce ?? 0,
    sourceShard: options.sourceShard ?? MASTERCHAIN_SHARD,
    targetShard: options.targetShard ?? MASTERCHAIN_SHARD,
    payload,
    priorityFeePerGas: options.priorityFeePerGas ?? 0,
  };
  return finishUnsigned(tx, chainId);
}

export interface GovVoteOptions extends BaseTxOptions {
  proposalId: number;
  choice: VoteChoice;
  heightObserved: number;
}

/** Build the unsigned block-carried `SysCallGovVote` transaction. */
export function buildGovVote(options: GovVoteOptions): UnsignedTransaction {
  const chainId = resolve(options.identity, options.chainId);
  const from = address32(options.from, "from");
  const payload = encodePayload([
    {
      kind: "gov_vote",
      proposalId: options.proposalId,
      choice: options.choice,
      heightObserved: options.heightObserved,
    },
  ]);
  const tx = {
    from,
    to: from,
    amount: 0,
    gasLimit: feeGas(GAS_GOV_VOTE, options),
    nonce: options.nonce ?? 0,
    sourceShard: options.sourceShard ?? MASTERCHAIN_SHARD,
    targetShard: options.targetShard ?? MASTERCHAIN_SHARD,
    payload,
    priorityFeePerGas: options.priorityFeePerGas ?? 0,
  };
  return finishUnsigned(tx, chainId);
}
