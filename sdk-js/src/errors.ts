/**
 * Typed errors for the JS package.
 *
 * The JSON-RPC error codes mirror EIP-1193 where one exists. Node refusals
 * keep the node's `code`/`message`/`data` unchanged so callers can match the
 * stable strings documented in `docs/SDK.md`.
 */

/** EIP-1193 provider error. */
export class ProviderRpcError extends Error {
  readonly code: number;
  readonly data?: unknown;

  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = "ProviderRpcError";
    this.code = code;
    if (data !== undefined) this.data = data;
  }
}

/** EIP-1193 `4200`: the provider does not support the requested method. */
export class UnsupportedMethodError extends ProviderRpcError {
  constructor(method: string, message?: string) {
    super(
      4200,
      message ??
        `StellereumProvider is read-only for EVM accounts: ${method} is not supported. ` +
          `Use stellereum-sdk's buildAndSign + sendSigned for PQ transactions.`,
    );
    this.name = "UnsupportedMethodError";
  }
}

/** A JSON-RPC error object returned by the node. */
export class RpcError extends Error {
  readonly method: string;
  readonly code: number;
  readonly data?: unknown;
  readonly retryable: boolean;

  constructor(method: string, code: number, message: string, data?: unknown, retryable = false) {
    super(`rpc ${method} failed (${code}): ${message}`);
    this.name = "RpcError";
    this.method = method;
    this.code = code;
    if (data !== undefined) this.data = data;
    this.retryable = retryable;
  }
}

/** A transport failure. `retryable` means the request may have landed. */
export class TransportError extends Error {
  readonly method: string;
  readonly retryable: boolean;

  constructor(method: string, message: string, retryable = true) {
    super(`transport error during ${method}: ${message}`);
    this.name = "TransportError";
    this.method = method;
    this.retryable = retryable;
  }
}

/** A signer (subprocess or HTTP helper) failure. */
export class SignerError extends Error {
  readonly code: string;
  readonly retryable: boolean;

  constructor(code: string, message: string, retryable = false) {
    super(`signer ${code}: ${message}`);
    this.name = "SignerError";
    this.code = code;
    this.retryable = retryable;
  }
}

/** The same duplicate phrasing the Rust SDK treats as success. */
export function isDuplicateMessage(message: string): boolean {
  const m = message.toLowerCase();
  return (
    m.includes("already in mempool") ||
    m.includes("already known") ||
    m.includes("duplicate transaction")
  );
}

/** `true` when retrying the exact same request is safe. */
export function isRetryableError(error: unknown): boolean {
  if (error instanceof TransportError) return error.retryable;
  if (error instanceof RpcError) return error.retryable || isDuplicateMessage(error.message);
  return false;
}
