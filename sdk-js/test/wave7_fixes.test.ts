import { test } from "node:test";
import assert from "node:assert/strict";

import { buildGovVote } from "../src/builders.ts";
import { RpcError, SignerError } from "../src/errors.ts";
import { bindingMessage } from "../src/evm.ts";
import { JsonRpcClient, type FetchLike } from "../src/rpc.ts";
import { HttpFalconSigner } from "../src/signer.ts";
import {
  PRIORITY_FEE_COMMITMENT_TAG,
  bytesToHex,
  encodeUnsignedTransaction,
  hexToBytes,
} from "../src/wire.ts";

const FROM = "11".repeat(32);

test("W6-A6-9: wire encoding rejects negative and non-safe integer u64/u32 inputs", () => {
  assert.throws(
    () =>
      encodeUnsignedTransaction({
        from: hexToBytes(FROM),
        to: hexToBytes(FROM),
        amount: -1,
        gasLimit: 300_000,
        nonce: 0,
        sourceShard: 0,
        targetShard: 0,
        payload: new Uint8Array(),
        priorityFeePerGas: 0,
      }),
    RangeError,
  );

  assert.throws(
    () =>
      encodeUnsignedTransaction({
        from: hexToBytes(FROM),
        to: hexToBytes(FROM),
        amount: 0,
        gasLimit: 300_000,
        nonce: Number.MAX_SAFE_INTEGER + 1,
        sourceShard: 0,
        targetShard: 0,
        payload: new Uint8Array(),
        priorityFeePerGas: 0,
      }),
    RangeError,
  );

  assert.throws(
    () =>
      encodeUnsignedTransaction({
        from: hexToBytes(FROM),
        to: hexToBytes(FROM),
        amount: 0,
        gasLimit: 300_000,
        nonce: 0,
        sourceShard: -1,
        targetShard: 0,
        payload: new Uint8Array(),
        priorityFeePerGas: 0,
      }),
    RangeError,
  );

  assert.throws(
    () =>
      buildGovVote({
        from: FROM,
        nonce: 1,
        proposalId: 2,
        choice: "yes",
        heightObserved: 10,
        priorityFeePerGas: -5,
      }),
    RangeError,
  );
});

test("W6-A6-9: bindingMessage rejects negative and non-safe integer chainId", () => {
  const evm = new Uint8Array(20).fill(0x22);
  const pq = new Uint8Array(32).fill(0x33);

  for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => bindingMessage(bad, evm, pq), RangeError);
  }
  assert.equal(bindingMessage(5757, evm, pq).length, 32);
});

test("W6-A6-12: encodeUnsignedTransaction preserves non-zero priorityFeePerGas via PRIORITY suffix", () => {
  const unsigned = buildGovVote({
    from: FROM,
    nonce: 2,
    gasLimit: 400_000,
    proposalId: 8,
    choice: "yes",
    heightObserved: 123,
    priorityFeePerGas: 77,
  });
  const tagHex = bytesToHex(PRIORITY_FEE_COMMITMENT_TAG);
  // signature length = 16 (0x1000000000000000), followed by "PRIORITY" and 77u64 BE (0x...004d)
  const expectedSigHex = "1000000000000000" + tagHex + "000000000000004d";
  assert.ok(
    unsigned.txHex.includes(expectedSigHex),
    `expected priority suffix ${expectedSigHex} in ${unsigned.txHex}`,
  );
  assert.equal(unsigned.priorityFeePerGas, 77);
});

test("W6-A6-12: JsonRpcClient rejects mismatched response id", async () => {
  const fetchImpl: FetchLike = async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ jsonrpc: "2.0", id: 999, result: "0x1" }),
    json: async () => ({ jsonrpc: "2.0", id: 999, result: "0x1" }),
  });
  const client = new JsonRpcClient({ url: "http://node.test", fetch: fetchImpl });
  await assert.rejects(client.request("stell_blockNumber"), (err: unknown) => {
    assert.ok(err instanceof RpcError);
    assert.match(err.message, /response id mismatch/);
    return true;
  });
});

test("W6-A6-12: HttpFalconSigner rejects non-loopback http:// unless allowInsecureHttp is true", () => {
  assert.throws(
    () => new HttpFalconSigner({ url: "http://signer.example.com:8787" }),
    (err: unknown) => {
      assert.ok(err instanceof SignerError);
      assert.equal(err.code, "insecure_transport");
      return true;
    },
  );

  assert.doesNotThrow(
    () => new HttpFalconSigner({ url: "http://signer.example.com:8787", allowInsecureHttp: true }),
  );
  assert.doesNotThrow(() => new HttpFalconSigner({ url: "https://signer.example.com:8787" }));
  assert.doesNotThrow(() => new HttpFalconSigner({ url: "http://127.0.0.1:8787" }));
  assert.doesNotThrow(() => new HttpFalconSigner({ url: "http://localhost:8787" }));
  assert.doesNotThrow(() => new HttpFalconSigner({ url: "http://[::1]:8787" }));
});
