/**
 * EIP-1193-style provider for Stellereum.
 *
 * It is intentionally READ-ONLY for EVM accounts:
 * - `eth_accounts` / `eth_requestAccounts` return `[]` (this SDK never holds a
 *   secp256k1 account);
 * - signing and EVM write methods throw `UnsupportedMethodError` (4200);
 * - every read-shaped `eth_*`, `net_*`, `web3_*` and all `stell_*` methods are
 *   forwarded verbatim to the node.
 *
 * PQ writes do not go through EIP-1193: use `StellereumClient.buildAndSign`
 * and `sendSigned`, which submit `stell_sendRawTransaction`.
 */

import { ProviderRpcError, RpcError, UnsupportedMethodError } from "./errors.ts";
import { JsonRpcClient, type JsonRpcClientOptions } from "./rpc.ts";

export interface RequestArguments {
  readonly method: string;
  readonly params?: readonly unknown[] | Record<string, unknown>;
}

export type ProviderListener = (...args: unknown[]) => void;

export interface StellereumProviderOptions {
  url?: string;
  client?: JsonRpcClient;
  fetch?: JsonRpcClientOptions["fetch"];
  headers?: Record<string, string>;
  timeoutMs?: number;
  /** Chain id served for `eth_chainId` if the node is unreachable? Never used to lie. */
}

const UNSUPPORTED_EVM_WRITES = new Set([
  "eth_sendTransaction",
  "eth_sendRawTransaction",
  "eth_sign",
  "eth_signTransaction",
  "eth_signTypedData",
  "eth_signTypedData_v3",
  "eth_signTypedData_v4",
  "personal_sign",
  "personal_ecRecover",
  "wallet_addEthereumChain",
  "wallet_switchEthereumChain",
  "wallet_watchAsset",
  "wallet_sendCalls",
  "wallet_getCapabilities",
]);

export class StellereumProvider {
  readonly isStellereum = true;
  readonly client: JsonRpcClient;
  private readonly listeners = new Map<string, Set<ProviderListener>>();

  constructor(options: StellereumProviderOptions) {
    this.client =
      options.client ??
      new JsonRpcClient({
        url: options.url ?? "http://127.0.0.1:8545",
        fetch: options.fetch,
        headers: options.headers,
        timeoutMs: options.timeoutMs,
      });
  }

  /** EIP-1193 `request`. */
  async request<T = unknown>(args: RequestArguments): Promise<T> {
    if (!args || typeof args.method !== "string") {
      throw new ProviderRpcError(-32602, "invalid request: method is required");
    }
    const method = args.method;
    const params = args.params ?? [];

    if (method === "eth_accounts" || method === "eth_requestAccounts") {
      // Read-only provider: no EVM account is ever exposed.
      return [] as unknown as T;
    }
    if (method === "eth_coinbase") {
      return null as unknown as T;
    }
    if (UNSUPPORTED_EVM_WRITES.has(method) || method.startsWith("personal_")) {
      throw new UnsupportedMethodError(method);
    }
    if (
      !method.startsWith("eth_") &&
      !method.startsWith("stell_") &&
      !method.startsWith("net_") &&
      !method.startsWith("web3_")
    ) {
      throw new UnsupportedMethodError(method);
    }
    try {
      return await this.client.request<T>(method, params);
    } catch (error) {
      if (error instanceof RpcError) {
        throw new ProviderRpcError(error.code, error.message, error.data);
      }
      throw error;
    }
  }

  // ---------------------------------------------------------------------
  // EIP-1193 events (minimal; the node has no eth_subscription transport)
  // ---------------------------------------------------------------------

  on(event: string, listener: ProviderListener): this {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(listener);
    return this;
  }

  removeListener(event: string, listener: ProviderListener): this {
    this.listeners.get(event)?.delete(listener);
    return this;
  }

  once(event: string, listener: ProviderListener): this {
    const wrapped: ProviderListener = (...args) => {
      this.removeListener(event, wrapped);
      listener(...args);
    };
    return this.on(event, wrapped);
  }

  /** Emit a local event. No polling is performed by the provider. */
  emit(event: string, ...args: unknown[]): boolean {
    const set = this.listeners.get(event);
    if (!set || set.size === 0) return false;
    for (const listener of [...set]) listener(...args);
    return true;
  }

  // ---------------------------------------------------------------------
  // Read helpers (thin wrappers over `request`)
  // ---------------------------------------------------------------------

  /** `eth_chainId` as a hex string (`0x167d`). */
  chainIdHex(): Promise<string> {
    return this.request<string>({ method: "eth_chainId" });
  }

  /** `eth_chainId` as a number. */
  async chainId(): Promise<number> {
    return Number.parseInt(await this.chainIdHex(), 16);
  }

  /** `eth_blockNumber` as a number. */
  async blockNumber(): Promise<number> {
    const hex = await this.request<string>({ method: "eth_blockNumber" });
    return Number.parseInt(hex, 16);
  }

  getBalance(address: string, block = "latest"): Promise<string> {
    return this.request<string>({ method: "eth_getBalance", params: [address, block] });
  }

  async getNonce(address: string, block = "latest"): Promise<number> {
    const hex = await this.request<string>({
      method: "eth_getTransactionCount",
      params: [address, block],
    });
    return Number.parseInt(hex, 16);
  }

  getCode(address: string, block = "latest"): Promise<string> {
    return this.request<string>({ method: "eth_getCode", params: [address, block] });
  }

  call(tx: Record<string, unknown>, block = "latest"): Promise<string> {
    return this.request<string>({ method: "eth_call", params: [tx, block] });
  }

  getReceipt(hash: string): Promise<unknown> {
    return this.request({ method: "eth_getTransactionReceipt", params: [hash] });
  }

  /** `stell_chainId` (numeric in the node's answer). */
  stellChainId(): Promise<number> {
    return this.request<number>({ method: "stell_chainId", params: [] });
  }

  /** `stell_getBalance` -> `{ balance, nonce }` with decimal strings. */
  stellAccount(address: string): Promise<{ balance: string; nonce: number }> {
    return this.request({ method: "stell_getBalance", params: [address] });
  }

  async stellNonce(address: string): Promise<number> {
    return (await this.stellAccount(address)).nonce;
  }

  stellReceipt(hash: string): Promise<unknown> {
    return this.request({ method: "stell_getTransactionReceipt", params: { hash } });
  }

  stellValidators(): Promise<unknown> {
    return this.request({ method: "stell_getValidators", params: [] });
  }

  stellBlock(height: number): Promise<unknown> {
    return this.request({ method: "stell_getBlock", params: { height } });
  }

  async stellBaseFee(): Promise<number> {
    const r = await this.request<{ base_fee: string | number }>({
      method: "stell_baseFee",
      params: [],
    });
    return typeof r.base_fee === "number" ? r.base_fee : Number(r.base_fee);
  }
}
