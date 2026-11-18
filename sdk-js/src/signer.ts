/**
 * Falcon-512 signing helpers for JS.
 *
 * ## Honest statement: JavaScript cannot sign Falcon-512 here
 *
 * This repository has no WASM Falcon binding, and Falcon-512 signing needs a
 * discrete-Gaussian sampler over the private NTRU basis (FIPS 206). The only
 * audited implementation in the tree is the Rust node's, wrapped by the Rust
 * SDK. Therefore this package does NOT pretend to sign in JS:
 *
 * - `SubprocessFalconSigner` runs `stellereum-sdk-cli sign --key ...` and
 *   pipes the JSON request to stdin (default);
 * - `HttpFalconSigner` POSTs the same JSON to a local
 *   `stellereum-sdk-cli serve` helper.
 *
 * Both produce a real `PQ1` (or `SQ1`/`SF1` for sessions) envelope inside the
 * returned `tx_hex`. The signer is trusted with the key; keep it local.
 */

import { spawn } from "node:child_process";
import { SignerError } from "./errors.ts";

export type JsonCallArg =
  | { type: "i64"; value: number }
  | { type: "u64"; value: number }
  | { type: "i32"; value: number }
  | { type: "bool"; value: boolean }
  | { type: "bytes"; value: string }
  | { type: "address"; value: string }
  | { type: "string"; value: string };

export interface TxCommon {
  nonce?: number;
  chain_id?: number;
  gas_limit?: number;
  base_fee?: number;
  priority_fee_per_gas?: number;
  source_shard?: number;
  target_shard?: number;
  implicit?: boolean;
  unbound?: boolean;
}

export type TxIntent =
  | ({ kind: "transfer"; to: string; amount: number } & TxCommon)
  | ({
      kind: "contract_call";
      contract: string;
      method: string;
      args?: JsonCallArg[];
      value?: number;
    } & TxCommon)
  | ({ kind: "stake"; validator: string; amount: number } & TxCommon)
  | ({ kind: "unjail"; validator: string; top_up?: number | null } & TxCommon);

export interface SignRequest {
  tx: TxIntent;
}

export interface SignResponse {
  ok: true;
  tx_hex: string;
  tx_hash: string;
  from: string;
  from_stl57: string;
  to: string;
  nonce: number;
  chain_id: number | null;
  gas_limit: number;
  activation: boolean;
  envelope: string;
}

interface SignErrorBody {
  code: string;
  message: string;
  retryable: boolean;
}

function parseSignerResponse(raw: string): SignResponse {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new SignerError("bad_response", `signer returned non-JSON: ${raw.slice(0, 300)}`);
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new SignerError("bad_response", "signer returned a non-object");
  }
  const obj = parsed as {
    ok?: boolean;
    error?: SignErrorBody;
  } & Partial<SignResponse>;
  if (obj.ok !== true) {
    const e = obj.error;
    throw new SignerError(
      e?.code ?? "unknown",
      e?.message ?? "signer refused the request",
      e?.retryable ?? false,
    );
  }
  if (
    typeof obj.tx_hex !== "string" ||
    typeof obj.tx_hash !== "string" ||
    typeof obj.from !== "string" ||
    typeof obj.nonce !== "number"
  ) {
    throw new SignerError("bad_response", "signer response is missing required fields");
  }
  return obj as SignResponse;
}

/** A signer that turns a transaction intent into a real PQ envelope. */
export interface FalconSigner {
  readonly address?: string;
  sign(request: SignRequest): Promise<SignResponse>;
}

export interface SubprocessSignerOptions {
  /** Binary path; default `stellereum-sdk-cli` from PATH. */
  command?: string;
  /** Extra args; default `["sign", "--key", keyPath]`. */
  args?: string[];
  /** Required unless `args` is supplied. */
  keyPath?: string;
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  /** Sender address, if you already know it (avoids a nonce lookup). */
  address?: string;
}

/**
 * Run the Rust CLI for each signature.
 *
 * The key never enters JS; only the intent and the signed bytes cross the
 * process boundary.
 */
export class SubprocessFalconSigner implements FalconSigner {
  readonly address?: string;
  private readonly command: string;
  private readonly args: string[];
  private readonly cwd?: string;
  private readonly env?: Record<string, string>;
  private readonly timeoutMs: number;

  constructor(options: SubprocessSignerOptions = {}) {
    this.command = options.command ?? "stellereum-sdk-cli";
    if (options.args) {
      this.args = [...options.args];
    } else {
      if (!options.keyPath) {
        throw new Error("SubprocessFalconSigner: pass keyPath or explicit args");
      }
      this.args = ["sign", "--key", options.keyPath];
    }
    this.cwd = options.cwd;
    this.env = options.env;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.address = options.address;
  }

  sign(request: SignRequest): Promise<SignResponse> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.command, this.args, {
        cwd: this.cwd,
        env: { ...process.env, ...(this.env ?? {}) },
        stdio: ["pipe", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new SignerError("timeout", `signer did not answer in ${this.timeoutMs}ms`, true));
      }, this.timeoutMs);
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk: string) => {
        stderr += chunk;
      });
      child.on("error", (error) => {
        clearTimeout(timer);
        reject(new SignerError("spawn", error.message, true));
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        // The CLI writes one JSON object; tolerate warnings on stderr and
        // take the last parseable stdout line.
        const line = stdout
          .split("\n")
          .map((l) => l.trim())
          .filter((l) => l.startsWith("{"))
          .at(-1);
        if (!line) {
          reject(
            new SignerError(
              "no_output",
              `signer exited ${code ?? "null"} without JSON (stderr: ${stderr.slice(0, 300)})`,
            ),
          );
          return;
        }
        try {
          resolve(parseSignerResponse(line));
        } catch (error) {
          reject(error);
        }
      });
      child.stdin.setDefaultEncoding("utf8");
      child.stdin.write(JSON.stringify(request));
      child.stdin.end();
    });
  }
}

export interface HttpSignerOptions {
  url: string;
  token?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  address?: string;
}

/** POST the same JSON to a local `stellereum-sdk-cli serve` helper. */
export class HttpFalconSigner implements FalconSigner {
  readonly address?: string;
  private readonly url: string;
  private readonly token?: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(options: HttpSignerOptions) {
    this.url = options.url.replace(/\/+$/, "");
    this.token = options.token;
    this.fetchImpl = options.fetch ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.address = options.address;
  }

  async sign(request: SignRequest): Promise<SignResponse> {
    const controller =
      typeof AbortController === "undefined" ? undefined : new AbortController();
    const timer =
      controller === undefined ? undefined : setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (this.token) headers.authorization = `Bearer ${this.token}`;
      response = await this.fetchImpl(`${this.url}/sign`, {
        method: "POST",
        headers,
        body: JSON.stringify(request),
        signal: controller?.signal,
      });
    } catch (error) {
      throw new SignerError(
        "transport",
        error instanceof Error ? error.message : String(error),
        true,
      );
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
    const text = await response.text();
    try {
      return parseSignerResponse(text);
    } catch (error) {
      if (!response.ok && error instanceof SignerError) {
        throw new SignerError(error.code, `${error.message} (HTTP ${response.status})`, false);
      }
      throw error;
    }
  }
}
