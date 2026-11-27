import { test } from "node:test";
import assert from "node:assert/strict";

import { StellereumClient } from "../src/client.ts";
import {
  MAX_CONTRACT_ABI_BYTES,
  OP_DEPLOY_CONTRACT,
  OP_DEPLOY_CONTRACT_WITH_ABI,
  buildContractDeployTransaction,
  contractDeployGas,
  encodeContractDeployOp,
  encodeContractDeployPayload,
  type ContractDeployIntent,
  type FalconSigner,
  type SignRequest,
  type SignResponse,
} from "../src/signer.ts";
import {
  CHAIN_ID_COMMITMENT_TAG,
  FROZEN_MIN_GAS_FLOOR,
  PQ_ACTIVATION_SURCHARGE_GAS,
  address32,
  bytesToHex,
  encodeGovAction,
  encodeStl57Address,
  hexToBytes,
} from "../src/wire.ts";
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

test("ContractDeployIntent encodes exact SysCallDeployContract bincode layout", () => {
  const wasm = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  const opFromBytes = encodeContractDeployOp(wasm);
  const opFromHex = encodeContractDeployOp("0x0061736d01000000");
  assert.deepEqual(opFromBytes, opFromHex);

  // Discriminant 19 (u32 LE) || len 8 (u64 LE) || wasm bytes
  assert.equal(OP_DEPLOY_CONTRACT, 19);
  assert.equal(
    bytesToHex(opFromBytes),
    "13000000" + "0800000000000000" + "0061736d01000000",
  );

  const payload = encodeContractDeployPayload(wasm);
  assert.equal(
    bytesToHex(payload),
    "0100000000000000" + "13000000" + "0800000000000000" + "0061736d01000000",
  );

  assert.throws(() => encodeContractDeployOp(new Uint8Array()), /must not be empty/);

  const intent: ContractDeployIntent & { from: string } = {
    kind: "contractDeploy",
    code: wasm,
    from: FROM,
    nonce: 3,
    chainId: 5757,
  };
  const unsigned = buildContractDeployTransaction(intent);
  assert.equal(unsigned.from, FROM);
  assert.equal(unsigned.to, FROM);
  assert.equal(unsigned.amount, 0);
  assert.equal(unsigned.nonce, 3);
  assert.equal(unsigned.chainId, 5757);
  assert.equal(unsigned.payloadHex, bytesToHex(payload));
  assert.equal(unsigned.gasLimit, FROZEN_MIN_GAS_FLOOR + PQ_ACTIVATION_SURCHARGE_GAS);

  const largeWasm = new Uint8Array(200_000).fill(0x01);
  const largeUnsigned = buildContractDeployTransaction({
    kind: "contractDeploy",
    code: largeWasm,
    from: FROM,
    nonce: 4,
    chainId: 5757,
  });
  assert.equal(
    largeUnsigned.gasLimit,
    contractDeployGas(200_000) + PQ_ACTIVATION_SURCHARGE_GAS,
  );
});

test("StellereumClient.contractDeploy and buildAndSign build SysCallDeployContract prepared tx", async () => {
  const mock = mockFetch((call) => {
    switch (call.body.method) {
      case "stell_chainId":
        return ok(call.body.id, 5757);
      case "stell_getBalance":
        return ok(call.body.id, { balance: "1000000000", nonce: 12 });
      case "stell_baseFee":
        return ok(call.body.id, { base_fee: "300000" });
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

  const wasm = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  const expectedPayloadHex = bytesToHex(encodeContractDeployPayload(wasm));

  const signed1 = await client.contractDeploy(wasm);
  assert.equal(signed1.rawTransaction, "beefcafe");
  assert.equal(signer.requests.length, 1);
  const req1 = signer.requests[0]!.tx;
  assert.equal(req1.kind, "prepared");
  assert.equal(req1.chain_id, 5757);
  assert.ok((req1 as { tx_hex: string }).tx_hex.endsWith(expectedPayloadHex));

  const signed2 = await client.buildAndSign({
    kind: "contractDeploy",
    code: "0x0061736d01000000",
    nonce: 99,
    gas: 400_000,
    chainId: 5757,
  });
  assert.equal(signed2.rawTransaction, "beefcafe");
  assert.equal(signer.requests.length, 2);
  const req2 = signer.requests[1]!.tx;
  assert.equal(req2.kind, "prepared");
  assert.ok((req2 as { tx_hex: string }).tx_hex.endsWith(expectedPayloadHex));
});

test("ContractDeployIntent with abi encodes exact SysCallDeployContractWithAbi (discriminant 65)", async () => {
  const wasm = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  const abiObj = { methods: [{ name: "ping", params: [], returns: "i64" }], events: [] };
  const abiStr = JSON.stringify(abiObj);
  const abiBytes = new TextEncoder().encode(abiStr);
  const abiHex = bytesToHex(abiBytes);

  assert.equal(OP_DEPLOY_CONTRACT_WITH_ABI, 65);
  const opFromObj = encodeContractDeployOp(wasm, abiObj);
  const opFromStr = encodeContractDeployOp(wasm, abiStr);
  assert.deepEqual(opFromObj, opFromStr);

  // Discriminant 65 (u32 LE = 0x41000000) || code len 8 (u64 LE) || wasm || abi len (u64 LE) || abi bytes
  const expectedAbiLenHex = (() => {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(abiBytes.length), true);
    return bytesToHex(b);
  })();
  assert.equal(
    bytesToHex(opFromObj),
    "41000000" + "0800000000000000" + "0061736d01000000" + expectedAbiLenHex + abiHex,
  );

  const payload = encodeContractDeployPayload(wasm, abiObj);
  assert.equal(
    bytesToHex(payload),
    "0100000000000000" + bytesToHex(opFromObj),
  );

  assert.throws(() => encodeContractDeployOp(wasm, ""), /must not be empty/);
  assert.throws(
    () => encodeContractDeployOp(wasm, "x".repeat(MAX_CONTRACT_ABI_BYTES + 1)),
    /exceeds/,
  );

  const largeWasm = new Uint8Array(200_000).fill(0x01);
  const largeAbi = JSON.stringify({ methods: [{ name: "m", params: [] }], pad: "a".repeat(20_000) });
  const largeAbiLen = new TextEncoder().encode(largeAbi).length;
  const unsigned = buildContractDeployTransaction({
    kind: "contractDeploy",
    code: largeWasm,
    abi: largeAbi,
    from: FROM,
    nonce: 5,
    chainId: 5757,
  });
  assert.equal(
    unsigned.gasLimit,
    contractDeployGas(200_000, largeAbiLen) + PQ_ACTIVATION_SURCHARGE_GAS,
  );

  const mock = mockFetch((call) => {
    switch (call.body.method) {
      case "stell_chainId":
        return ok(call.body.id, 5757);
      case "stell_getBalance":
        return ok(call.body.id, { balance: "1000000000", nonce: 15 });
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

  await client.contractDeployWithAbi(wasm, abiObj);
  await client.buildAndSign({
    kind: "contractDeploy",
    code: wasm,
    abi: abiStr,
    nonce: 16,
    chainId: 5757,
  });
  assert.equal(signer.requests.length, 2);
  const expectedPayloadHex = bytesToHex(payload);
  assert.ok((signer.requests[0]!.tx as { tx_hex: string }).tx_hex.endsWith(expectedPayloadHex));
  assert.ok((signer.requests[1]!.tx as { tx_hex: string }).tx_hex.endsWith(expectedPayloadHex));
});

function rlpBytesClient(value: Uint8Array): Uint8Array {
  if (value.length === 1 && value[0]! < 0x80) return value;
  const len = value.length;
  if (len < 56) return Uint8Array.of(0x80 + len, ...value);
  const lenBytes = bigIntBytesClient(BigInt(len));
  return Uint8Array.of(0x80 + 55 + lenBytes.length, ...lenBytes, ...value);
}

function rlpListClient(items: Uint8Array[]): Uint8Array {
  const payload = items.flatMap((item) => [...item]);
  if (payload.length < 56) return Uint8Array.of(0xc0 + payload.length, ...payload);
  const lenBytes = bigIntBytesClient(BigInt(payload.length));
  return Uint8Array.of(0xf7 + lenBytes.length, ...lenBytes, ...payload);
}

function bigIntBytesClient(value: bigint): Uint8Array {
  if (value === 0n) return new Uint8Array();
  const out: number[] = [];
  let v = value;
  while (v > 0n) {
    out.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  return Uint8Array.from(out);
}

function legacyEvmTxClient(nonce: number, valueWei: bigint, chainId: number): string {
  const to = Uint8Array.from({ length: 20 }, (_, i) => i + 1);
  const v = BigInt(chainId) * 2n + 35n;
  const raw = rlpListClient([
    rlpBytesClient(bigIntBytesClient(BigInt(nonce))),
    rlpBytesClient(bigIntBytesClient(20_000_000_000n)),
    rlpBytesClient(bigIntBytesClient(21_000n)),
    rlpBytesClient(to),
    rlpBytesClient(bigIntBytesClient(valueWei)),
    rlpBytesClient(new Uint8Array()),
    rlpBytesClient(bigIntBytesClient(v)),
    rlpBytesClient(new Uint8Array(32).fill(1)),
    rlpBytesClient(new Uint8Array(32).fill(1)),
  ]);
  return bytesToHex(raw);
}

class DigestFakeSigner extends FakeSigner {
  digestRequests: string[] = [];

  override async sign(request: SignRequest): Promise<SignResponse> {
    const resp = await super.sign(request);
    return {
      ...resp,
      chain_id: request.tx.unbound ? null : (request.tx.chain_id ?? null),
      activation: request.tx.implicit !== true,
      envelope: request.tx.implicit ? "pq1-implicit" : "pq1-explicit",
    };
  }

  async signDigest(digestHex: string): Promise<string> {
    this.digestRequests.push(digestHex);
    return "29" + "55".repeat(665);
  }
}

test("StellereumClient convenience methods: stake, unjail, contractCall, contractCallRaw", async () => {
  const mock = mockFetch((call) => {
    switch (call.body.method) {
      case "stell_chainId":
        return ok(call.body.id, 5757);
      case "stell_getBalance":
        return ok(call.body.id, { balance: "5000000", nonce: 3 });
      case "stell_baseFee":
        return ok(call.body.id, { base_fee: "280000" });
      default:
        return ok(call.body.id, null);
    }
  });
  const signer = new FakeSigner();
  const client = new StellereumClient({ url: "http://node.test", fetch: mock.fetch, signer });

  await client.stake(TO, 1_000_000);
  await client.unjail(TO);
  await client.unjail(TO, 500, { priorityFeePerGas: 11 });
  await client.contractCall(TO, "transfer", [{ type: "u64", value: 42 }], 99);
  await client.contractCallRaw(TO, "set_pq", Uint8Array.from([0xaa, 0xbb, 0xcc]), 7, [1, 2]);

  assert.equal(signer.requests.length, 5);
  assert.deepEqual(signer.requests[0]!.tx, {
    kind: "stake",
    validator: TO,
    amount: 1_000_000,
    nonce: 3,
    chain_id: 5757,
    base_fee: 280_000,
    priority_fee_per_gas: 0,
  });
  assert.deepEqual(signer.requests[1]!.tx, {
    kind: "unjail",
    validator: TO,
    top_up: null,
    nonce: 3,
    chain_id: 5757,
    base_fee: 280_000,
    priority_fee_per_gas: 0,
  });
  assert.deepEqual(signer.requests[2]!.tx, {
    kind: "unjail",
    validator: TO,
    top_up: 500,
    nonce: 3,
    chain_id: 5757,
    base_fee: 280_000,
    priority_fee_per_gas: 11,
  });
  assert.deepEqual(signer.requests[3]!.tx, {
    kind: "contract_call",
    contract: TO,
    method: "transfer",
    args: [{ type: "u64", value: 42 }],
    value: 99,
    nonce: 3,
    chain_id: 5757,
    base_fee: 280_000,
    priority_fee_per_gas: 0,
  });
  assert.deepEqual(signer.requests[4]!.tx, {
    kind: "contract_call_raw",
    contract: TO,
    method: "set_pq",
    args: [1, 2],
    calldata_hex: "aabbcc",
    value: 7,
    nonce: 3,
    chain_id: 5757,
    base_fee: 280_000,
    priority_fee_per_gas: 0,
  });
});

test("StellereumClient.contractDeploy forwards unbound: true, allows chainId: null, and accepts contract_deploy alias", async () => {
  const mock = mockFetch((call) => {
    switch (call.body.method) {
      case "stell_chainId":
        return ok(call.body.id, 5757);
      case "stell_getBalance":
        return ok(call.body.id, { balance: "5000000", nonce: 8 });
      case "stell_baseFee":
        return ok(call.body.id, { base_fee: "280000" });
      default:
        return ok(call.body.id, null);
    }
  });
  const signer = new DigestFakeSigner();
  const client = new StellereumClient({ url: "http://node.test", fetch: mock.fetch, signer });
  const wasm = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

  const unboundUnsigned = buildContractDeployTransaction({
    kind: "contract_deploy",
    code: wasm,
    from: FROM,
    nonce: 8,
    unbound: true,
    chainId: null,
  });
  assert.equal(unboundUnsigned.chainId, null);
  assert.equal(unboundUnsigned.signingMessageHex.includes(bytesToHex(CHAIN_ID_COMMITMENT_TAG)), false);

  assert.throws(
    () =>
      buildContractDeployTransaction({
        kind: "contractDeploy",
        code: wasm,
        from: FROM,
        chainId: null,
      }),
    /unbound: true/,
  );

  const signedUnbound = await client.contractDeploy(wasm, {
    unbound: true,
    implicit: true,
    priorityFeePerGas: 15,
  });
  assert.equal(signedUnbound.chainId, null);
  assert.equal(signedUnbound.activation, false);
  assert.equal(signedUnbound.envelope, "pq1-implicit");
  assert.equal(signer.requests.length, 1);
  assert.deepEqual(
    mock.calls.map((c) => c.body.method),
    ["stell_getBalance", "stell_baseFee"],
  );
  const req = signer.requests[0]!.tx;
  assert.equal(req.kind, "prepared");
  assert.equal(req.chain_id, null);
  assert.equal(req.unbound, true);
  assert.equal(req.implicit, true);
  assert.equal(req.priority_fee_per_gas, 15);

  const signedAlias = await client.buildAndSign({
    kind: "contract_deploy",
    code: wasm,
    nonce: 9,
    chainId: 5757,
  });
  assert.equal(signedAlias.chainId, 5757);
  assert.equal(signer.requests.length, 2);
});

test("StellereumClient evmBinding, evmCarrier, govPropose, govVote expose baseFee/gasLimit/priorityFeePerGas/implicit/unbound", async () => {
  const mock = mockFetch((call) => {
    switch (call.body.method) {
      case "stell_chainId":
        return ok(call.body.id, 5757);
      case "stell_getBalance":
        return ok(call.body.id, { balance: "5000000", nonce: 4 });
      default:
        return ok(call.body.id, null);
    }
  });
  const signer = new DigestFakeSigner();
  const client = new StellereumClient({ url: "http://node.test", fetch: mock.fetch, signer });
  const pqPublicKey = "44".repeat(897);
  const evmAddress = "22".repeat(20);
  const evmProof = "66".repeat(65);

  const bindingSigned = await client.evmBinding({
    evmAddress,
    evmProof,
    pqPublicKey,
    baseFee: 650_000,
    priorityFeePerGas: 25,
    implicit: true,
    unbound: true,
  });
  assert.equal(bindingSigned.chainId, null);
  assert.equal(bindingSigned.activation, false);
  assert.equal(signer.digestRequests.length, 1);
  const bindingReq = signer.requests[0]!.tx;
  assert.equal(bindingReq.kind, "prepared");
  assert.equal(bindingReq.unbound, true);
  assert.equal(bindingReq.implicit, true);
  assert.equal(bindingReq.chain_id, null);
  assert.equal(bindingReq.priority_fee_per_gas, 25);

  const evmTx = legacyEvmTxClient(7, 3_000_000_000n, 5757);
  const { signed: carrierSigned, plan } = await client.evmCarrier({
    evmTx,
    evmAddress,
    toPq: TO,
    pqPublicKey,
    gasLimit: 750_000,
    priorityFeePerGas: 10,
    implicit: true,
    unbound: true,
  });
  assert.equal(plan.evmNonce, 7);
  assert.equal(plan.evmValueNano, 3);
  assert.equal(plan.gasLimit, 750_000);
  assert.equal(plan.priorityFeePerGas, 10);
  assert.equal(carrierSigned.chainId, null);
  assert.equal(carrierSigned.activation, false);
  assert.equal(signer.digestRequests.length, 2);
  const carrierReq = signer.requests[1]!.tx;
  assert.equal(carrierReq.unbound, true);
  assert.equal(carrierReq.implicit, true);
  assert.equal(carrierReq.chain_id, null);
  assert.equal(carrierReq.priority_fee_per_gas, 10);

  const proposeSigned = await client.govPropose({
    proposalId: 10,
    title: "gov options",
    action: { type: "signal", text: "ok" },
    heightObserved: 55,
    baseFee: 320_000,
    priorityFeePerGas: 12,
    implicit: true,
    unbound: true,
  });
  assert.equal(proposeSigned.chainId, null);
  assert.equal(proposeSigned.activation, false);
  const proposeReq = signer.requests[2]!.tx;
  assert.equal(proposeReq.unbound, true);
  assert.equal(proposeReq.implicit, true);
  assert.equal(proposeReq.chain_id, null);
  assert.equal(proposeReq.priority_fee_per_gas, 12);

  const voteSigned = await client.govVote({
    proposalId: 10,
    choice: "yes",
    heightObserved: 56,
    gasLimit: 400_000,
    priorityFeePerGas: 8,
    implicit: true,
    unbound: true,
  });
  assert.equal(voteSigned.chainId, null);
  assert.equal(voteSigned.activation, false);
  const voteReq = signer.requests[3]!.tx;
  assert.equal(voteReq.unbound, true);
  assert.equal(voteReq.implicit, true);
  assert.equal(voteReq.chain_id, null);
  assert.equal(voteReq.priority_fee_per_gas, 8);
});

test("address32 accepts Stl57... addresses identically to 64-char hex", () => {
  const rawBytes = hexToBytes(FROM);
  const stl57 = encodeStl57Address(rawBytes);
  assert.match(stl57, /^Stl57/);
  assert.deepEqual(address32(stl57, "from"), rawBytes);
  assert.deepEqual(address32(`stl57${stl57.slice(5)}`, "from"), rawBytes);
  assert.deepEqual(address32(FROM, "from"), rawBytes);
  assert.deepEqual(address32(`0x${FROM}`, "from"), rawBytes);

  const last = stl57.at(-1)!;
  const tampered = `${stl57.slice(0, -1)}${last === "9" ? "8" : "9"}`;
  assert.throws(() => address32(tampered, "from"), /checksum mismatch/);

  const wasm = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  const fromHexDeploy = buildContractDeployTransaction({
    kind: "contractDeploy",
    code: wasm,
    from: FROM,
    nonce: 1,
    chainId: 5757,
  });
  const fromStl57Deploy = buildContractDeployTransaction({
    kind: "contractDeploy",
    code: wasm,
    from: stl57,
    nonce: 1,
    chainId: 5757,
  });
  assert.equal(fromStl57Deploy.txHex, fromHexDeploy.txHex);
  assert.equal(fromStl57Deploy.signingMessageHex, fromHexDeploy.signingMessageHex);

  assert.deepEqual(
    encodeGovAction({ type: "register_oracle_publisher", publisher: stl57 }),
    encodeGovAction({ type: "register_oracle_publisher", publisher: FROM }),
  );
});
