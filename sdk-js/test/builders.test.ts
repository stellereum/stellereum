import { test } from "node:test";
import assert from "node:assert/strict";

import {
  BuilderError,
  buildEvmBinding,
  buildEvmCarrier,
  buildGovPropose,
  buildGovVote,
} from "../src/builders.ts";
import { keccak256 } from "../src/evm.ts";
import {
  FORK_ID,
  FORK_ID_HEX,
  ProtocolError,
  assertChainId,
  assertIdentity,
  deriveForkId,
  FORK_ID_RULES,
  localIdentity,
} from "../src/protocol.ts";

const FROM = "11".repeat(32);
const EVM = "22".repeat(20);
const TO_PQ = "33".repeat(32);
const PQ_PUBKEY = "44".repeat(897);
const FALCON_SIG = "55".repeat(666);
const PROOF = "66".repeat(65);

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

// --- a minimal EIP-155 RLP encoder, independent of the SDK's decoder ------

function rlpBytes(value: Uint8Array): Uint8Array {
  if (value.length === 1 && value[0]! < 0x80) return value;
  const len = value.length;
  if (len < 56) return Uint8Array.of(0x80 + len, ...value);
  const lenBytes = bigIntBytes(BigInt(len));
  return Uint8Array.of(0x80 + 55 + lenBytes.length, ...lenBytes, ...value);
}

function rlpList(items: Uint8Array[]): Uint8Array {
  const payload = items.flatMap((item) => [...item]);
  if (payload.length < 56) return Uint8Array.of(0xc0 + payload.length, ...payload);
  const lenBytes = bigIntBytes(BigInt(payload.length));
  return Uint8Array.of(0xf7 + lenBytes.length, ...lenBytes, ...payload);
}

function bigIntBytes(value: bigint): Uint8Array {
  if (value === 0n) return new Uint8Array();
  const out: number[] = [];
  let v = value;
  while (v > 0n) {
    out.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  return Uint8Array.from(out);
}

function legacyRaw(nonce: number, valueWei: bigint, chainId: number): Uint8Array {
  const to = Uint8Array.from({ length: 20 }, (_, i) => i + 1);
  const v = BigInt(chainId) * 2n + 35n;
  return rlpList([
    rlpBytes(bigIntBytes(BigInt(nonce))),
    rlpBytes(bigIntBytes(20_000_000_000n)),
    rlpBytes(bigIntBytes(21_000n)),
    rlpBytes(to),
    rlpBytes(bigIntBytes(valueWei)),
    rlpBytes(new Uint8Array()),
    rlpBytes(bigIntBytes(v)),
    rlpBytes(new Uint8Array(32).fill(1)),
    rlpBytes(new Uint8Array(32).fill(1)),
  ]);
}

// ============================================================================

test("keccak256 matches the EVM vectors (not SHA3-256)", () => {
  assert.equal(
    hex(keccak256(new Uint8Array())),
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
  );
  assert.equal(
    hex(keccak256(new TextEncoder().encode("abc"))),
    "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
  );
});

test("fork id mirrors the node's ruleset-v6 derivation", () => {
  assert.equal(FORK_ID_HEX, "0x0f584a46");
  assert.equal(FORK_ID_RULES.length, 23);
  assert.equal(
    deriveForkId(5757n, 6, FORK_ID_RULES),
    FORK_ID,
  );
});

test("chain/fork guard refuses a mismatched identity with a specific error", () => {
  const local = localIdentity();
  assert.doesNotThrow(() => assertIdentity(local));
  assert.throws(
    () => assertIdentity({ ...local, forkId: local.forkId ^ 1 }),
    (error: unknown) => {
      assert.ok(error instanceof ProtocolError);
      assert.equal(error.code, "fork_id_mismatch");
      return true;
    },
  );
  assert.throws(
    () => assertIdentity({ ...local, protocolMinor: local.protocolMinor + 1 }),
    (error: unknown) => {
      assert.ok(error instanceof ProtocolError);
      assert.equal(error.code, "protocol_version_mismatch");
      return true;
    },
  );
  assert.throws(
    () => assertChainId(local, 1),
    (error: unknown) => {
      assert.ok(error instanceof ProtocolError);
      assert.equal(error.code, "chain_id_mismatch");
      return true;
    },
  );
});

test("(a) an EVM binding claim without the 65-byte proof is refused", () => {
  assert.throws(
    () =>
      buildEvmBinding({
        from: FROM,
        pqPublicKey: PQ_PUBKEY,
        evmAddress: EVM,
        evmProof: "00".repeat(64),
        bindingSignature: FALCON_SIG,
        nonce: 1,
      }),
    (error: unknown) => {
      assert.ok(error instanceof BuilderError);
      assert.equal(error.code, "missing_evm_proof");
      assert.match(error.message, /65-byte secp256k1 proof of possession/);
      return true;
    },
  );

  // A complete proof builds the claim: to == from, amount 0.
  const unsigned = buildEvmBinding({
    from: FROM,
    pqPublicKey: PQ_PUBKEY,
    evmAddress: EVM,
    evmProof: PROOF,
    bindingSignature: FALCON_SIG,
    nonce: 1,
  });
  assert.equal(unsigned.from, FROM);
  assert.equal(unsigned.to, FROM);
  assert.equal(unsigned.amount, 0);
  assert.equal(unsigned.chainId, 5757);
});

test("(b) a carrier with a mismatched nonce or value is refused", () => {
  const raw = hex(legacyRaw(7, 3_000_000_000n, 5757));
  const common = {
    from: FROM,
    pqPublicKey: PQ_PUBKEY,
    evmTx: raw,
    evmAddress: EVM,
    toPq: TO_PQ,
    intentSignature: FALCON_SIG,
  };

  assert.throws(
    () => buildEvmCarrier({ ...common, nonce: 8 }),
    (error: unknown) => {
      assert.ok(error instanceof BuilderError);
      assert.equal(error.code, "carrier_nonce_mismatch");
      assert.match(error.message, /EVM intent says 7, transaction says 8/);
      return true;
    },
  );
  assert.throws(
    () => buildEvmCarrier({ ...common, amountNano: 4 }),
    (error: unknown) => {
      assert.ok(error instanceof BuilderError);
      assert.equal(error.code, "carrier_value_mismatch");
      assert.match(error.message, /worth 3 nano-STELL, transaction moves 4/);
      return true;
    },
  );

  const plan = buildEvmCarrier(common);
  assert.equal(plan.evmNonce, 7);
  assert.equal(plan.evmValueNano, 3);
  assert.equal(plan.nonce, 7);
  assert.equal(plan.amount, 3);
  assert.equal(plan.to, TO_PQ);
});

test("(c) gov propose/vote bytes match the node builder's fixed vectors", () => {
  const propose = buildGovPropose({
    from: FROM,
    nonce: 6,
    gasLimit: 500_000,
    proposalId: 4,
    title: "raise the floor",
    action: { type: "set_min_gas_limit", value: 300_000 },
    heightObserved: 99,
  });
  assert.equal(
    propose.txHex,
    "1111111111111111111111111111111111111111111111111111111111111111" +
      "1111111111111111111111111111111111111111111111111111111111111111" +
      "000000000000000020a107000000000006000000000000000000000000000000" +
      "000000000000000001000000000000003500000004000000000000000f000000" +
      "0000000072616973652074686520666c6f6f720a000000e09304000000000063" +
      "00000000000000",
    "gov propose transaction bytes differ from the node builder",
  );
  assert.equal(
    propose.signingMessageHex,
    "1111111111111111111111111111111111111111111111111111111111111111" +
      "1111111111111111111111111111111111111111111111111111111111111111" +
      "0000000000000000000000000007a12000000000000000060000000000000000" +
      "5041594c4f41440000003f01000000000000003500000004000000000000000f" +
      "0000000000000072616973652074686520666c6f6f720a000000e09304000000" +
      "00006300000000000000434841494e5f4944000000000000167d",
    "gov propose signing preimage differs from the node builder",
  );

  const vote = buildGovVote({
    from: FROM,
    nonce: 2,
    gasLimit: 400_000,
    proposalId: 8,
    choice: "abstain",
    heightObserved: 123,
  });
  assert.equal(
    vote.txHex,
    "1111111111111111111111111111111111111111111111111111111111111111" +
      "1111111111111111111111111111111111111111111111111111111111111111" +
      "0000000000000000801a06000000000002000000000000000000000000000000" +
      "0000000000000000010000000000000036000000080000000000000002000000" +
      "7b00000000000000",
    "gov vote transaction bytes differ from the node builder",
  );
  assert.equal(
    vote.signingMessageHex,
    "1111111111111111111111111111111111111111111111111111111111111111" +
      "1111111111111111111111111111111111111111111111111111111111111111" +
      "00000000000000000000000000061a8000000000000000020000000000000000" +
      "5041594c4f414400000020010000000000000036000000080000000000000002" +
      "0000007b00000000000000434841494e5f4944000000000000167d",
    "gov vote signing preimage differs from the node builder",
  );
});
