/**
 * Minimal JSON-RPC 2.0 client.
 *
 * `fetch` is injectable so tests can capture the exact frame. The default is
 * the platform fetch. No retries live here: the client builds requests and
 * maps errors; submission retries live in `StellereumClient.sendSigned` and
 * resend the same raw transaction.
 */

import { RpcError, TransportError } from "./errors.ts";

export interface FetchResponseLike {
  ok: boolean;
  status: number;
  text(): Promise<string>;
  json(): Promise<unknown>;
}

export type FetchLike = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  },
) => Promise<FetchResponseLike>;

export interface JsonRpcClientOptions {
  url: string;
  fetch?: FetchLike;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

interface JsonRpcErrorBody {
  code: number;
  message: string;
  data?: unknown;
}

function isErrorBody(value: unknown): value is { error: JsonRpcErrorBody } {
  return (
    typeof value === "object" &&
    value !== null &&
    "error" in value &&
    typeof (value as { error?: unknown }).error === "object" &&
    (value as { error?: unknown }).error !== null
  );
}

export class JsonRpcClient {
  readonly url: string;
  private readonly fetchImpl: FetchLike;
  private readonly headers: Record<string, string>;
  private readonly timeoutMs: number;
  private nextId = 1;

  constructor(options: JsonRpcClientOptions) {
    this.url = options.url;
    this.fetchImpl = options.fetch ?? (globalThis.fetch as unknown as FetchLike);
    if (!this.fetchImpl) {
      throw new Error("no fetch implementation available; pass options.fetch");
    }
    this.headers = {
      "content-type": "application/json",
      ...(options.headers ?? {}),
    };
    this.timeoutMs = options.timeoutMs ?? 15_000;
  }

  /** One JSON-RPC call; resolves to `result` or throws a typed error. */
  async request<T>(method: string, params: unknown = []): Promise<T> {
    const id = this.nextId++;
    const body = JSON.stringify({ jsonrpc: "2.0", id, method, params });
    const controller =
      typeof AbortController === "undefined" ? undefined : new AbortController();
    const timer =
      controller === undefined
        ? undefined
        : setTimeout(() => controller.abort(), this.timeoutMs);

    let response: FetchResponseLike;
    try {
      response = await this.fetchImpl(this.url, {
        method: "POST",
        headers: this.headers,
        body,
        signal: controller?.signal,
      });
    } catch (error) {
      if (timer !== undefined) clearTimeout(timer);
      throw new TransportError(
        method,
        error instanceof Error ? error.message : String(error),
        true,
      );
    }

    // R2-X: the timeout must cover the BODY too. Clearing it as soon as the
    // headers arrive let a slow/black-holed response hang the client forever
    // (and `sendSigned`/`waitForReceipt` with it). Abort stays armed until
    // the body has been read.
    let raw: string;
    try {
      raw = await response.text();
    } catch (error) {
      throw new TransportError(
        method,
        error instanceof Error ? error.message : String(error),
        true,
      );
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }

    let parsed: unknown;
    try {
      parsed = raw.length === 0 ? {} : JSON.parse(raw);
    } catch {
      if (!response.ok) {
        throw new TransportError(
          method,
          `HTTP ${response.status}: ${raw.slice(0, 200)}`,
          response.status === 408 || response.status === 429 || response.status >= 500,
        );
      }
      throw new RpcError(method, -32700, "response is not JSON", raw.slice(0, 200));
    }

    if (isErrorBody(parsed)) {
      const e = parsed.error;
      throw new RpcError(method, e.code, e.message, e.data);
    }
    if (!response.ok) {
      throw new TransportError(
        method,
        `HTTP ${response.status}`,
        response.status === 408 || response.status === 429 || response.status >= 500,
      );
    }
    if (typeof parsed !== "object" || parsed === null || !("result" in parsed)) {
      throw new RpcError(method, -32603, "response has no result", parsed);
    }
    if ((parsed as { id?: unknown }).id !== id) {
      throw new RpcError(
        method,
        -32603,
        `response id mismatch: expected ${id}, got ${String((parsed as { id?: unknown }).id)}`,
        parsed,
      );
    }
    return (parsed as { result: T }).result;
  }
}
