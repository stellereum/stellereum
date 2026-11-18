import { test } from "node:test";
import assert from "node:assert/strict";

import { StellereumClient } from "../src/client.ts";
import type { FalconSigner, SignRequest, SignResponse } from "../src/signer.ts";
import type { FetchLike } from "../src/rpc.ts";

const FROM = "11".repeat(32);
const TO = "22".repeat(32);

interface Call {
  url: string;
  body: { jsonrpc: string; id: number; method: string; params: unknown };
}

interface Reply {
  status?: number;
  body: string;
}

function mockFetch(handler: (call: Call, index: number) => Reply): {
  fetch: FetchLike;
  calls: Call[];
} {
  const calls: Call[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    const body = JSON.parse(String(init?.body ?? "{}")) as Call["body"];
    const call = { url, body };
    calls.push(call);
    const r = handler(call, calls.length - 1);
    const status = r.status ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => r.body,
      json: async () => JSON.parse(r.body),
    };
  };
  return { fetch: fetchImpl, calls };
}

function ok(id: number, result: unknown): Reply {
  return { body: JSON.stringify({ jsonrpc: "2.0", id, result }) };
}

class FakeSigner implements FalconSigner {
  readonly address = FROM;
  requests: SignRequest[] = [];

  async sign(request: SignRequest): Promise<SignResponse> {
    this.requests.push(request);
    return {
      ok: true,
      tx_hex: "beefcafe",
      tx_hash: "deadbeef",
      from: FROM,
      from_stl57: "Stl57mock",
      to: TO,
      nonce: request.tx.nonce ?? 0,
      chain_id: request.tx.chain_id ?? null,
      gas_limit: request.tx.gas_limit ?? 325_000,
      activation: true,
      envelope: "pq1-explicit",
    };
  }
}

test("buildAndSign fills nonce, chain id and base fee before signing", async () => {
  const mock = mockFetch((call) => {
    switch (call.body.method) {
      case "stell_chainId":
        return ok(call.body.id, 5757);
      case "stell_getBalance":
        return ok(call.body.id, { balance: "1000000000", nonce: 7 });
      case "stell_baseFee":
        return ok(call.body.id, { base_fee: "280000" });
      default:
        return ok(call.body.id, null);
    }
  });
  const signer = new FakeSigner();
  const client = new StellereumClient({
    url: "http://node.test",
    fetch: mock.fetch,
    signer,
  });

  const signed = await client.buildAndSign({ kind: "transfer", to: TO, amount: 123 });

  assert.equal(signed.rawTransaction, "beefcafe");
  assert.equal(signed.nonce, 7);
  assert.equal(signed.chainId, 5757);
  assert.equal(signer.requests.length, 1);
  const tx = signer.requests[0]!.tx;
  assert.equal(tx.kind, "transfer");
  assert.equal(tx.nonce, 7);
  assert.equal(tx.chain_id, 5757);
  assert.equal(tx.base_fee, 280000);
  assert.equal(tx.to, TO);
  assert.equal(tx.amount, 123);
  assert.deepEqual(
    mock.calls.map((c) => c.body.method),
    ["stell_chainId", "stell_getBalance", "stell_baseFee"],
  );
});

test("sendSigned retries with identical raw bytes and never calls the signer", async () => {
  let sendAttempts = 0;
  const mock = mockFetch((call) => {
    if (call.body.method === "stell_sendRawTransaction") {
      sendAttempts += 1;
      if (sendAttempts < 3) return { status: 500, body: "temporary" };
      return ok(call.body.id, "aabbcc");
    }
    return ok(call.body.id, null);
  });
  const signer = new FakeSigner();
  const client = new StellereumClient({
    url: "http://node.test",
    fetch: mock.fetch,
    signer,
  });

  const signed = {
    rawTransaction: "00112233",
    hash: "hash123",
    from: FROM,
    fromStl57: "Stl57mock",
    to: TO,
    nonce: 4,
    chainId: 5757,
    gasLimit: 325_000,
    activation: true,
    envelope: "pq1-explicit",
  };
  const result = await client.sendSigned(signed, {
    attempts: 5,
    baseDelayMs: 1,
    maxDelayMs: 2,
  });
  assert.deepEqual(result, { hash: "aabbcc", attempts: 3, alreadyInMempool: false });
  assert.equal(signer.requests.length, 0, "submission must never sign");
  const sends = mock.calls.filter((c) => c.body.method === "stell_sendRawTransaction");
  assert.equal(sends.length, 3);
  for (const call of sends) {
    assert.deepEqual(call.body.params, { tx: "00112233" });
  }
});

test("duplicate mempool answer is success", async () => {
  const mock = mockFetch((call) => {
    if (call.body.method === "stell_sendRawTransaction") {
      return {
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: call.body.id,
          error: {
            code: -32000,
            message: "rejected: transaction already in mempool",
          },
        }),
      };
    }
    return ok(call.body.id, null);
  });
  const client = new StellereumClient({
    url: "http://node.test",
    fetch: mock.fetch,
    signer: new FakeSigner(),
  });
  const signed = {
    rawTransaction: "0011",
    hash: "known-hash",
    from: FROM,
    fromStl57: "Stl57mock",
    to: TO,
    nonce: 0,
    chainId: 5757,
    gasLimit: 325_000,
    activation: true,
    envelope: "pq1-explicit",
  };
  const result = await client.sendSigned(signed);
  assert.equal(result.alreadyInMempool, true);
  assert.equal(result.hash, "known-hash");
  assert.equal(result.attempts, 1);
});

test("waitForReceipt polls pending then returns the committed receipt", async () => {
  let receipts = 0;
  const mock = mockFetch((call) => {
    if (call.body.method === "stell_getTransactionReceipt") {
      receipts += 1;
      if (receipts < 3) return ok(call.body.id, { status: "pending" });
      return ok(call.body.id, {
        tx_hash: "h",
        height: 9,
        block_hash: "b",
        index: 0,
        status: "success",
        gas_limit: "325000",
        fee_charged: "325000",
        confirmations: 1,
      });
    }
    return ok(call.body.id, null);
  });
  const client = new StellereumClient({
    url: "http://node.test",
    fetch: mock.fetch,
    signer: new FakeSigner(),
  });
  const receipt = await client.waitForReceipt("h", { timeoutMs: 1_000, pollMs: 1 });
  assert.equal(receipt.status, "success");
  assert.equal(receipt.height, 9);
  assert.equal(receipts, 3);
});

test("a non-retryable node refusal is returned after one attempt", async () => {
  const mock = mockFetch((call) => {
    if (call.body.method === "stell_sendRawTransaction") {
      return {
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: call.body.id,
          error: { code: -32000, message: "rejected: invalid transaction signature" },
        }),
      };
    }
    return ok(call.body.id, null);
  });
  const client = new StellereumClient({
    url: "http://node.test",
    fetch: mock.fetch,
    signer: new FakeSigner(),
  });
  const signed = {
    rawTransaction: "0011",
    hash: "h",
    from: FROM,
    fromStl57: "Stl57mock",
    to: TO,
    nonce: 0,
    chainId: 5757,
    gasLimit: 325_000,
    activation: true,
    envelope: "pq1-explicit",
  };
  await assert.rejects(client.sendSigned(signed, { attempts: 5, baseDelayMs: 1 }), /invalid transaction signature/);
  const sends = mock.calls.filter((c) => c.body.method === "stell_sendRawTransaction");
  assert.equal(sends.length, 1);
});
