import { test } from "node:test";
import assert from "node:assert/strict";

import { StellereumClient } from "../src/client.ts";
import { ProtocolError } from "../src/protocol.ts";
import type { FalconSigner, SignRequest, SignResponse } from "../src/signer.ts";
import type { FetchLike } from "../src/rpc.ts";

const FROM = "11".repeat(32);

interface Call {
  url: string;
  body: { jsonrpc: string; id: number; method: string; params: unknown };
}

function mockFetch(chainId: number): { fetch: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    const body = JSON.parse(String(init?.body ?? "{}")) as Call["body"];
    calls.push({ url, body });
    let result: unknown = null;
    if (body.method === "stell_chainId") result = chainId;
    if (body.method === "stell_getBalance") result = { balance: "1000000000", nonce: 7 };
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ jsonrpc: "2.0", id: body.id, result }),
      json: async () => ({ jsonrpc: "2.0", id: body.id, result }),
    };
  };
  return { fetch: fetchImpl, calls };
}

class PreparedSigner implements FalconSigner {
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
      to: FROM,
      nonce: 7,
      chain_id: 5757,
      gas_limit: 325_000,
      activation: true,
      envelope: "pq1-explicit",
    };
  }
}

test("govPropose builds unsigned bytes locally and asks the sidecar for the envelope", async () => {
  const mock = mockFetch(5757);
  const signer = new PreparedSigner();
  const client = new StellereumClient({ url: "http://node.test", fetch: mock.fetch, signer });

  const signed = await client.govPropose({
    nonce: 6,
    gasLimit: 500_000,
    proposalId: 4,
    title: "raise the floor",
    action: { type: "set_min_gas_limit", value: 300_000 },
    heightObserved: 99,
  });

  assert.equal(signed.rawTransaction, "beefcafe");
  assert.equal(signer.requests.length, 1);
  const tx = signer.requests[0]!.tx;
  assert.equal(tx.kind, "prepared");
  assert.equal(tx.chain_id, 5757);
  assert.equal(typeof (tx as { tx_hex?: string }).tx_hex, "string");
  assert.ok((tx as { tx_hex?: string }).tx_hex!.startsWith("11111111"));
});

test("the client refuses to build when the node chain id differs from the configured identity", async () => {
  const mock = mockFetch(5758);
  const signer = new PreparedSigner();
  const client = new StellereumClient({ url: "http://node.test", fetch: mock.fetch, signer });

  await assert.rejects(
    client.govVote({
      nonce: 1,
      gasLimit: 400_000,
      proposalId: 8,
      choice: "yes",
      heightObserved: 123,
    }),
    (error: unknown) => {
      assert.ok(error instanceof ProtocolError);
      assert.equal(error.code, "chain_id_mismatch");
      return true;
    },
  );
  assert.equal(signer.requests.length, 0);
});
