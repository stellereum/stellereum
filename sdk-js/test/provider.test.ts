import { test } from "node:test";
import assert from "node:assert/strict";

import { StellereumProvider } from "../src/provider.ts";
import { ProviderRpcError, UnsupportedMethodError } from "../src/errors.ts";
import type { FetchLike } from "../src/rpc.ts";

interface Call {
  url: string;
  body: {
    jsonrpc: string;
    id: number;
    method: string;
    params: unknown;
  };
}

interface Reply {
  status?: number;
  body: string;
}

function mockFetch(reply: (call: Call) => Reply): { fetch: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    const body = JSON.parse(String(init?.body ?? "{}")) as Call["body"];
    const call = { url, body };
    calls.push(call);
    const r = reply(call);
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

function okResult(id: number, result: unknown): Reply {
  return { body: JSON.stringify({ jsonrpc: "2.0", id, result }) };
}

test("provider frames eth_chainId exactly once with params []", async () => {
  const mock = mockFetch((call) => okResult(call.body.id, "0x167d"));
  const provider = new StellereumProvider({
    url: "http://node.test/rpc",
    fetch: mock.fetch,
  });

  assert.equal(await provider.request({ method: "eth_chainId" }), "0x167d");
  assert.equal(mock.calls.length, 1);
  assert.equal(mock.calls[0]!.url, "http://node.test/rpc");
  assert.deepEqual(mock.calls[0]!.body, {
    jsonrpc: "2.0",
    id: 1,
    method: "eth_chainId",
    params: [],
  });
});

test("provider forwards params unchanged and increments ids", async () => {
  const addr = "0x" + "11".repeat(20);
  const mock = mockFetch((call) => okResult(call.body.id, "0x0"));
  const provider = new StellereumProvider({ url: "http://node.test", fetch: mock.fetch });

  await provider.request({ method: "eth_getBalance", params: [addr, "latest"] });
  await provider.request({ method: "eth_getCode", params: { address: addr } });

  assert.deepEqual(mock.calls[0]!.body, {
    jsonrpc: "2.0",
    id: 1,
    method: "eth_getBalance",
    params: [addr, "latest"],
  });
  assert.deepEqual(mock.calls[1]!.body, {
    jsonrpc: "2.0",
    id: 2,
    method: "eth_getCode",
    params: { address: addr },
  });
});

test("read-only accounts never hit the network", async () => {
  const mock = mockFetch((call) => okResult(call.body.id, "should not be used"));
  const provider = new StellereumProvider({ url: "http://node.test", fetch: mock.fetch });

  assert.deepEqual(await provider.request({ method: "eth_accounts" }), []);
  assert.deepEqual(await provider.request({ method: "eth_requestAccounts" }), []);
  assert.equal(await provider.request({ method: "eth_coinbase" }), null);
  assert.equal(mock.calls.length, 0);
});

test("EVM write methods are refused locally with 4200", async () => {
  const mock = mockFetch((call) => okResult(call.body.id, "0x0"));
  const provider = new StellereumProvider({ url: "http://node.test", fetch: mock.fetch });

  for (const method of ["eth_sendTransaction", "eth_sign", "personal_sign", "eth_sendRawTransaction"]) {
    await assert.rejects(
      provider.request({ method }),
      (error: unknown) => {
        assert.ok(error instanceof UnsupportedMethodError);
        assert.equal((error as ProviderRpcError).code, 4200);
        return true;
      },
    );
  }
  assert.equal(mock.calls.length, 0);
});

test("node JSON-RPC errors become ProviderRpcError with code/data", async () => {
  const mock = mockFetch((call) => ({
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: call.body.id,
      error: { code: -32000, message: "simulation reverted: nope", data: { reason: "nope" } },
    }),
  }));
  const provider = new StellereumProvider({ url: "http://node.test", fetch: mock.fetch });

  await assert.rejects(provider.request({ method: "eth_call", params: [{}] }), (error: unknown) => {
    assert.ok(error instanceof ProviderRpcError);
    assert.equal((error as ProviderRpcError).code, -32000);
    assert.match((error as Error).message, /simulation reverted/);
    assert.deepEqual((error as ProviderRpcError).data, { reason: "nope" });
    return true;
  });
});

test("stell_* methods pass through", async () => {
  const mock = mockFetch((call) => {
    if (call.body.method === "stell_getBalance") {
      return okResult(call.body.id, { balance: "42", nonce: 3 });
    }
    return okResult(call.body.id, null);
  });
  const provider = new StellereumProvider({ url: "http://node.test", fetch: mock.fetch });

  assert.deepEqual(await provider.stellAccount("Stl57abc"), { balance: "42", nonce: 3 });
  assert.equal(await provider.stellNonce("Stl57abc"), 3);
  assert.equal(mock.calls[0]!.body.params instanceof Array, true);
});
