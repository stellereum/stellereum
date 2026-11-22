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

import { createHash } from "node:crypto";

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

export const PAYLOAD_COMMITMENT_TAG = new TextEncoder().encode("PAYLOAD");
export const CHAIN_ID_COMMITMENT_TAG = new TextEncoder().encode("CHAIN_ID");
export const PRIORITY_FEE_COMMITMENT_TAG = new TextEncoder().encode("PRIORITY");

export type VoteChoice = "yes" | "no" | "abstain";

export type GovAction =
  | { type: "set_min_validator_bond"; value: number }
  | { type: "set_equivocation_slash_bps"; value: number }
  | { type: "set_default_commission_bps"; value: number }
  | { type: "set_block_reward"; value: number }
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
  /** Hex of the exact preimage the PQ envelope signs (includes CHAIN_ID). */
  signingMessageHex: string;
  /** SHA-256 of the unsigned transaction (NOT the final signed hash). */
  unsignedTxHash: string;
  from: string;
  to: string;
  amount: number;
  nonce: number;
  gasLimit: number;
  chainId: number;
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

class Writer {
  private readonly parts: Uint8Array[] = [];

  u8(value: number): void {
    this.parts.push(Uint8Array.of(value & 0xff));
  }

  u32le(value: number): void {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value >>> 0, true);
    this.parts.push(out);
  }

  u32be(value: number): void {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value >>> 0, false);
    this.parts.push(out);
  }

  u64le(value: number | bigint): void {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, BigInt(value), true);
    this.parts.push(out);
  }

  u64be(value: number | bigint): void {
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
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

export function address32(value: string, field: string): Uint8Array {
  const bytes = hexToBytes(value, field);
  if (bytes.length !== 32) throw new Error(`${field}: expected 32 bytes, got ${bytes.length}`);
  return bytes;
}

export function address20(value: string, field: string): Uint8Array {
  const bytes = hexToBytes(value, field);
  if (bytes.length !== 20) throw new Error(`${field}: expected 20 bytes, got ${bytes.length}`);
  return bytes;
}

export function sha256(bytes: Uint8Array): Uint8Array {
  return createHash("sha256").update(bytes).digest();
}

export function encodeGovAction(action: GovAction): Uint8Array {
  const w = new Writer();
  const u64 = (value: number): void => w.u64le(value);
  switch (action.type) {
    case "set_min_validator_bond":
      w.u32le(0);
      u64(action.value);
      break;
    case "set_equivocation_slash_bps":
      w.u32le(1);
      u64(action.value);
      break;
    case "set_default_commission_bps":
      w.u32le(2);
      u64(action.value);
      break;
    case "set_block_reward":
      w.u32le(3);
      u64(action.value);
      break;
    case "set_pmm_redemption_buffer_bps":
      w.u32le(4);
      u64(action.value);
      break;
    case "set_governance_quorum_bps":
      w.u32le(5);
      u64(action.value);
      break;
    case "signal":
      w.u32le(6);
      w.vec(new TextEncoder().encode(action.text));
      break;
    case "register_oracle_publisher":
      w.u32le(7);
      w.bytes(address32(action.publisher, "publisher"));
      break;
    case "unregister_oracle_publisher":
      w.u32le(8);
      w.bytes(address32(action.publisher, "publisher"));
      break;
    case "reset_oracle_breaker":
      w.u32le(9);
      break;
    case "set_min_gas_limit":
      w.u32le(10);
      u64(action.value);
      break;
    case "software_upgrade": {
      w.u32le(11);
      w.vec(new TextEncoder().encode(action.name));
      u64(action.height);
      const digest = hexToBytes(action.sha256, "sha256");
      if (digest.length !== 32) throw new Error("sha256: expected 32 bytes");
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

/** `bincode(Transaction)` with an empty signature blob. */
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
  w.u64le(0); // empty signature blob
  w.bytes(tx.payload.length === 0 ? new Uint8Array(8) : tx.payload);
  return w.finish();
}

/** The exact preimage the PQ1 envelope signs (`signing_message_for_chain`). */
export function signingMessage(tx: TransactionFields, chainId: number): Uint8Array {
  const w = new Writer();
  w.bytes(tx.from);
  w.bytes(tx.to);
  w.u64be(tx.amount);
  w.u64be(tx.gasLimit);
  w.u64be(tx.nonce);
  w.u32be(tx.sourceShard);
  w.u32be(tx.targetShard);
  w.bytes(PAYLOAD_COMMITMENT_TAG);
  w.u32be(tx.payload.length);
  w.bytes(tx.payload);
  if (tx.priorityFeePerGas !== 0) {
    w.bytes(PRIORITY_FEE_COMMITMENT_TAG);
    w.u64be(tx.priorityFeePerGas);
  }
  w.bytes(CHAIN_ID_COMMITMENT_TAG);
  w.u64be(chainId);
  return w.finish();
}

/** The node's `compute_tx_hash` preimage for an unsigned (no envelope) tx. */
export function unsignedTxHash(tx: TransactionFields): Uint8Array {
  const w = new Writer();
  w.bytes(tx.from);
  w.bytes(tx.to);
  w.u64be(tx.amount);
  w.u64be(tx.gasLimit);
  w.u64be(tx.nonce);
  w.u32be(tx.sourceShard);
  w.u32be(tx.targetShard);
  w.bytes(PAYLOAD_COMMITMENT_TAG);
  w.u32be(tx.payload.length);
  w.bytes(tx.payload);
  if (tx.priorityFeePerGas !== 0) {
    w.bytes(PRIORITY_FEE_COMMITMENT_TAG);
    w.u64be(tx.priorityFeePerGas);
  }
  return sha256(w.finish());
}

/** Assemble an `UnsignedTransaction` from its fields and chain id. */
export function finishUnsigned(tx: TransactionFields, chainId: number): UnsignedTransaction {
  const encoded = encodeUnsignedTransaction(tx);
  return {
    txHex: bytesToHex(encoded),
    payloadHex: bytesToHex(tx.payload),
    signingMessageHex: bytesToHex(signingMessage(tx, chainId)),
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
