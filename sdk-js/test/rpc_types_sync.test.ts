import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import path from "node:path";

import {
  ETH_RPC_METHODS,
  NET_RPC_METHODS,
  NODE_RPC_METHODS,
  STELL_RPC_METHODS,
  WEB3_RPC_METHODS,
  type EthRpcMethod,
  type NodeRpcMethod,
  type StellRpcMethod,
} from "../src/index.ts";

const SDK_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

test("generated RPC method lists contain no duplicates and are sorted", () => {
  for (const [label, list] of [
    ["STELL_RPC_METHODS", STELL_RPC_METHODS],
    ["ETH_RPC_METHODS", ETH_RPC_METHODS],
    ["NET_RPC_METHODS", NET_RPC_METHODS],
    ["WEB3_RPC_METHODS", WEB3_RPC_METHODS],
    ["NODE_RPC_METHODS", NODE_RPC_METHODS],
  ] as const) {
    const unique = new Set(list);
    assert.equal(unique.size, list.length, `${label} must not contain duplicates`);
    const sorted = [...list].sort();
    assert.deepEqual([...list], sorted, `${label} must be sorted`);
  }

  const combined = [
    ...STELL_RPC_METHODS,
    ...ETH_RPC_METHODS,
    ...NET_RPC_METHODS,
    ...WEB3_RPC_METHODS,
  ].sort();
  assert.deepEqual([...NODE_RPC_METHODS], combined);
});

test("core expected stell_*, eth_*, net_*, web3_* methods are in NODE_RPC_METHODS", () => {
  const nodeSet = new Set<string>(NODE_RPC_METHODS);

  const expectedCore: readonly NodeRpcMethod[] = [
    "stell_blockNumber",
    "stell_chainId",
    "stell_getBalance",
    "stell_getValidators",
    "stell_getValidatorStatus",
    "stell_getTransactionReceipt",
    "stell_sendRawTransaction",
    "stell_estimateFee",
    "stell_getProof",
    "stell_getArchiveProof",
    "stell_getHistoricalRoot",
    "stell_subscribe",
    "stell_deployContract",
    "stell_callContract",
    "stell_runGetMethod",
    "stell_submitProposal",
    "stell_vote",
    "stell_getEvmBinding",
    "stell_evmBindingSubmit",
    "stell_evmCarrierSubmit",
    "stell_tokenTransfer",
    "stell_nativeApi",
    "eth_blockNumber",
    "eth_getBlockByNumber",
    "eth_chainId",
    "eth_getBalance",
    "eth_getTransactionReceipt",
    "eth_sendRawTransaction",
    "eth_call",
    "eth_getLogs",
    "eth_getProof",
    "net_version",
    "net_listening",
    "net_peerCount",
    "web3_clientVersion",
  ];

  for (const method of expectedCore) {
    assert.ok(nodeSet.has(method), `Expected ${method} in NODE_RPC_METHODS`);
  }

  const sampleStell: StellRpcMethod = "stell_getValidatorStatus";
  const sampleEth: EthRpcMethod = "eth_getBlockByNumber";
  assert.ok(STELL_RPC_METHODS.includes(sampleStell));
  assert.ok(ETH_RPC_METHODS.includes(sampleEth));
});

test("generate-rpc-types.mjs --check passes against Rust RPC dispatch", () => {
  const scriptPath = path.join(SDK_DIR, "scripts", "generate-rpc-types.mjs");
  const stdout = execFileSync(process.execPath, [scriptPath, "--check"], {
    cwd: SDK_DIR,
    encoding: "utf8",
  });
  assert.match(stdout, /rpc-types: in sync/);
});
