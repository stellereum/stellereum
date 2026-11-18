import { test } from "node:test";
import assert from "node:assert/strict";

import { HttpFalconSigner } from "../src/signer.ts";
import { SignerError } from "../src/errors.ts";

function mockFetch(body: string, status = 200): {
  fetch: typeof fetch;
  calls: Array<{ url: string; init?: RequestInit }>;
} {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const impl = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => body,
    } as Response;
  }) as typeof fetch;
  return { fetch: impl, calls };
}

test("HttpFalconSigner POSTs the request to /sign with a bearer token", async () => {
  const response = {
    ok: true,
    tx_hex: "aabb",
    tx_hash: "ccdd",
    from: "ee",
    from_stl57: "Stl57x",
    to: "ff",
    nonce: 9,
    chain_id: 5757,
    gas_limit: 325000,
    activation: true,
    envelope: "pq1-explicit",
  };
  const mock = mockFetch(JSON.stringify(response));
  const signer = new HttpFalconSigner({
    url: "http://127.0.0.1:8787/",
    token: "secret",
    fetch: mock.fetch,
  });
  const result = await signer.sign({
    tx: { kind: "transfer", to: "22", amount: 1, nonce: 9 },
  });
  assert.equal(result.tx_hex, "aabb");
  assert.equal(mock.calls.length, 1);
  assert.equal(mock.calls[0]!.url, "http://127.0.0.1:8787/sign");
  assert.equal(mock.calls[0]!.init?.method, "POST");
  assert.equal(
    (mock.calls[0]!.init?.headers as Record<string, string>).authorization,
    "Bearer secret",
  );
  assert.deepEqual(JSON.parse(String(mock.calls[0]!.init?.body)), {
    tx: { kind: "transfer", to: "22", amount: 1, nonce: 9 },
  });
});

test("HttpFalconSigner surfaces signer errors", async () => {
  const mock = mockFetch(
    JSON.stringify({
      ok: false,
      error: { code: "invalid_argument", message: "bad amount", retryable: false },
    }),
    400,
  );
  const signer = new HttpFalconSigner({
    url: "http://127.0.0.1:8787",
    fetch: mock.fetch,
  });
  await assert.rejects(
    signer.sign({ tx: { kind: "transfer", to: "22", amount: 1 } }),
    (error: unknown) => {
      assert.ok(error instanceof SignerError);
      assert.equal((error as SignerError).code, "invalid_argument");
      assert.match((error as Error).message, /bad amount/);
      return true;
    },
  );
});
