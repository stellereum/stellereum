import { test } from "node:test";
import assert from "node:assert/strict";

import { JsonRpcClient, type FetchLike } from "../src/rpc.ts";
import { HttpFalconSigner } from "../src/signer.ts";
import { SignerError, TransportError } from "../src/errors.ts";

/**
 * A transport that answers the request (headers) immediately but never
 * finishes the body unless the caller aborts. This is the shape of a
 * black-holed/slow-loris node: a timeout that stops at the headers never
 * fires.
 */
function hangingBodyFetch(): FetchLike {
  return (_input, init) =>
    Promise.resolve({
      ok: true,
      status: 200,
      json: async () => ({}),
      text: () =>
        new Promise<string>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        }),
    });
}

/** Resolves `"done"` when `promise` settles, `"timeout"` if it hangs. */
function within(promise: Promise<unknown>, ms: number): Promise<"done" | "timeout"> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve("timeout"), ms);
    promise.then(
      () => {
        clearTimeout(timer);
        resolve("done");
      },
      () => {
        clearTimeout(timer);
        resolve("done");
      },
    );
  });
}

test("r2x JSON-RPC timeout also covers the response body", async () => {
  const client = new JsonRpcClient({
    url: "http://node.test",
    fetch: hangingBodyFetch(),
    timeoutMs: 25,
  });

  let failure: unknown = null;
  const outcome = client.request("stell_chainId").then(
    () => "resolved",
    (error: unknown) => {
      failure = error;
      return "rejected";
    },
  );

  assert.equal(
    await within(outcome, 1_000),
    "done",
    "request must not hang after its headers arrive",
  );
  assert.ok(
    failure instanceof TransportError,
    `expected a TransportError after the body timeout, got ${String(failure)}`,
  );
});

test("r2x HTTP signer timeout also covers the response body", async () => {
  const signer = new HttpFalconSigner({
    url: "http://127.0.0.1:1",
    fetch: hangingBodyFetch() as unknown as typeof fetch,
    timeoutMs: 25,
  });

  let failure: unknown = null;
  const outcome = signer.sign({ tx: { kind: "transfer", to: "22", amount: 1 } }).then(
    () => "resolved",
    (error: unknown) => {
      failure = error;
      return "rejected";
    },
  );

  assert.equal(
    await within(outcome, 1_000),
    "done",
    "signer must not hang after its headers arrive",
  );
  assert.ok(
    failure instanceof SignerError,
    `expected a SignerError after the body timeout, got ${String(failure)}`,
  );
});
