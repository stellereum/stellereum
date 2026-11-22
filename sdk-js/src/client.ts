/**
 * High-level client: read helpers, `buildAndSign`, submission with retries
 * that resend the same raw bytes, and receipt waiting.
 *
 * `buildAndSign` delegates the Falcon-512 signature to a `FalconSigner`
 * (subprocess or local HTTP helper). JavaScript never signs Falcon here; see
 * `signer.ts` for the plain statement.
 */

import { isDuplicateMessage, isRetryableError, RpcError, SignerError } from "./errors.ts";
import { StellereumProvider, type StellereumProviderOptions } from "./provider.ts";
import type { FalconSigner, SignRequest, SignResponse, TxIntent } from "./signer.ts";
import {
  BuilderError,
  buildEvmBinding,
  buildEvmCarrier,
  buildGovPropose,
  buildGovVote,
  evmBindingDigest,
  evmCarrierDigest,
  type EvmBindingOptions,
  type EvmCarrierOptions,
  type EvmCarrierPlan,
  type GovProposeOptions,
  type GovVoteOptions,
} from "./builders.ts";
import {
  ProtocolError,
  assertIdentityForChain,
  localIdentity,
  type ProtocolIdentity,
} from "./protocol.ts";
import type { UnsignedTransaction } from "./wire.ts";

/** A signed transaction as returned by the Rust signer. */
export interface SignedTransaction {
  /** Hex bincode(Transaction) including the PQ1/SF1 envelope. */
  rawTransaction: string;
  /** Canonical transaction hash (node's SHA-256 preimage, computed by Rust). */
  hash: string;
  from: string;
  fromStl57: string;
  to: string;
  nonce: number;
  chainId: number | null;
  gasLimit: number;
  activation: boolean;
  envelope: string;
}

export interface BuildAndSignOptions {
  nonce?: number;
  chainId?: number;
  baseFee?: number;
  gasLimit?: number;
  priorityFeePerGas?: number;
  implicit?: boolean;
  unbound?: boolean;
}

export interface SubmitResult {
  hash: string;
  attempts: number;
  alreadyInMempool: boolean;
}

export interface RetryOptions {
  attempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
}

export interface Receipt {
  tx_hash: string;
  height: number;
  block_hash: string;
  index: number;
  status: string;
  gas_limit: string;
  fee_charged: string;
  confirmations: number;
  contract_address?: string;
  return_value?: unknown;
  gas_used?: number;
  events?: unknown[];
}

export interface FeeEstimate {
  gas_limit: string;
  estimated_fee: string;
  base_fee: string;
  source_shard: number;
  target_shard: number;
  is_cross_shard: boolean;
  gas_budget?: number;
  gas_ceiling?: number;
}

export interface Account {
  balance: string;
  nonce: number;
}

export interface StellereumClientOptions extends StellereumProviderOptions {
  /** The signer used by `buildAndSign`. */
  signer: FalconSigner;
  /** Sender address for nonce lookup when the signer does not expose one. */
  address?: string;
  /**
   * The node's protocol identity. Defaults to this build's local identity.
   * The new-shape builders refuse a different chain/fork before signing.
   */
  identity?: ProtocolIdentity;
}

const DEFAULT_FEE_FLOOR = 280_000;
const DEFAULT_ACTIVATION_SURCHARGE = 45_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function asNumber(value: string | number): number {
  return typeof value === "number" ? value : Number(value);
}

function toSignedTransaction(resp: SignResponse): SignedTransaction {
  return {
    rawTransaction: resp.tx_hex,
    hash: resp.tx_hash,
    from: resp.from,
    fromStl57: resp.from_stl57,
    to: resp.to,
    nonce: resp.nonce,
    chainId: resp.chain_id,
    gasLimit: resp.gas_limit,
    activation: resp.activation,
    envelope: resp.envelope,
  };
}

export class StellereumClient {
  readonly provider: StellereumProvider;
  readonly signer: FalconSigner;
  private readonly configuredAddress?: string;
  private readonly configuredIdentity: ProtocolIdentity;

  constructor(options: StellereumClientOptions) {
    this.provider = new StellereumProvider(options);
    this.signer = options.signer;
    this.configuredAddress = options.address ?? options.signer.address;
    this.configuredIdentity = options.identity ?? localIdentity();
  }

  /** The configured protocol identity (local unless `options.identity` was set). */
  identity(): ProtocolIdentity {
    return this.configuredIdentity;
  }

  /** The configured sender address, if the signer or options supplied one. */
  address(): string {
    if (!this.configuredAddress) {
      throw new Error(
        "StellereumClient: no sender address. Pass options.address or set signer.address; " +
          "the nonce cannot be read otherwise.",
      );
    }
    return this.configuredAddress;
  }

  // ------------------------------------------------------------------
  // Reads
  // ------------------------------------------------------------------

  /** `stell_chainId`. */
  async chainId(): Promise<number> {
    const v = await this.provider.client.request<number | string>("stell_chainId", []);
    return asNumber(v);
  }

  /** `stell_getBalance` with the sender address. */
  account(address = this.address()): Promise<Account> {
    return this.provider.client.request<Account>("stell_getBalance", [address]);
  }

  /** Account nonce (the value the next transaction must use). */
  async nonce(address = this.address()): Promise<number> {
    return (await this.account(address)).nonce;
  }

  /** Current admission base floor (`stell_baseFee`). */
  async baseFee(): Promise<number> {
    const v = await this.provider.client.request<{ base_fee: string | number }>(
      "stell_baseFee",
      [],
    );
    return asNumber(v.base_fee);
  }

  /** Latest block height (`stell_blockNumber`). */
  async blockNumber(): Promise<number> {
    const v = await this.provider.client.request<number | string>("stell_blockNumber", []);
    return asNumber(v);
  }

  /** Block summary. */
  block(height: number): Promise<{ height: number; hash: string; txs: number; timestamp: number }> {
    return this.provider.client.request("stell_getBlock", { height });
  }

  /** Validator set. */
  validators(): Promise<{
    validators: Array<{ validator: string; power: string }>;
    total_power: string;
    quorum: string;
    fragile: boolean;
  }> {
    return this.provider.client.request("stell_getValidators", []);
  }

  /** Committed receipt, or `null` while the node reports pending/unknown. */
  async receipt(hash: string): Promise<Receipt | null> {
    const v = await this.provider.client.request<Receipt & { status: string }>(
      "stell_getTransactionReceipt",
      { hash },
    );
    if (v.status === "pending" || v.status === "unknown") return null;
    return v;
  }

  /** Fee estimate for a signed transaction (`{ "tx": hex }`). */
  estimateFee(rawTransaction: string): Promise<FeeEstimate> {
    return this.provider.client.request<FeeEstimate>("stell_estimateFee", {
      tx: rawTransaction,
    });
  }

  // ------------------------------------------------------------------
  // Build + sign
  // ------------------------------------------------------------------

  /**
   * Fill nonce/chain id/base fee, hand the intent to the signer, and return
   * the signed PQ envelope.
   *
   * The signer (Rust) computes the final `gas_limit` unless `gasLimit` is
   * supplied: `max(opcode_gas, base_fee) + 45_000 (explicit PQ1) + priority`.
   */
  async buildAndSign(intent: TxIntent, options: BuildAndSignOptions = {}): Promise<SignedTransaction> {
    const chainId =
      options.chainId ?? intent.chain_id ?? (await this.chainId());
    const nonce =
      options.nonce ?? intent.nonce ?? (await this.nonce(this.address()));
    const baseFee = options.baseFee ?? intent.base_fee ?? (await this.baseFee());

    const tx: TxIntent = {
      ...intent,
      nonce,
      chain_id: chainId,
      base_fee: baseFee,
      priority_fee_per_gas:
        options.priorityFeePerGas ?? intent.priority_fee_per_gas ?? 0,
      ...(options.gasLimit !== undefined || intent.gas_limit !== undefined
        ? { gas_limit: options.gasLimit ?? intent.gas_limit }
        : {}),
      ...(options.implicit === true ? { implicit: true } : {}),
      ...(options.unbound === true ? { unbound: true } : {}),
    };

    const resp = await this.signer.sign({ tx });
    return toSignedTransaction(resp);
  }

  /** Convenience: native transfer. */
  transfer(to: string, amount: number, options: BuildAndSignOptions = {}): Promise<SignedTransaction> {
    return this.buildAndSign({ kind: "transfer", to, amount }, options);
  }

  /** Convenience: WASM contract call. */
  contractCall(
    contract: string,
    method: string,
    args: import("./signer.ts").JsonCallArg[] = [],
    value = 0,
    options: BuildAndSignOptions = {},
  ): Promise<SignedTransaction> {
    return this.buildAndSign(
      { kind: "contract_call", contract, method, args, value },
      options,
    );
  }

  /** Convenience: bond/top-up a validator. */
  stake(validator: string, amount: number, options: BuildAndSignOptions = {}): Promise<SignedTransaction> {
    return this.buildAndSign({ kind: "stake", validator, amount }, options);
  }

  /** Convenience: unjail, optionally with a top-up. */
  unjail(
    validator: string,
    topUp: number | null = null,
    options: BuildAndSignOptions = {},
  ): Promise<SignedTransaction> {
    return this.buildAndSign({ kind: "unjail", validator, top_up: topUp }, options);
  }

  // ------------------------------------------------------------------
  // EVM binding / carrier and governance (protocol v1 shapes)
  // ------------------------------------------------------------------

  /**
   * Attach the PQ1 envelope to an UNSIGNED transaction built by this package.
   *
   * The Rust signer owns the Falcon key and refuses an unsigned transaction
   * whose `from` is not its address.
   */
  async signPrepared(unsigned: UnsignedTransaction): Promise<SignedTransaction> {
    const resp = await this.signer.sign({
      tx: {
        kind: "prepared",
        tx_hex: unsigned.txHex,
        chain_id: unsigned.chainId,
        priority_fee_per_gas: unsigned.priorityFeePerGas,
      },
    });
    return toSignedTransaction(resp);
  }

  private async guardedChainId(options: { chainId?: number }): Promise<number> {
    const identity = this.configuredIdentity;
    const nodeChain = await this.chainId();
    const chain = options.chainId ?? identity.chainId;
    assertIdentityForChain(identity, chain);
    if (nodeChain !== chain) {
      throw new ProtocolError(
        "chain_id_mismatch",
        `chain id mismatch: node reports ${nodeChain}, configured identity is ${chain}`,
      );
    }
    return chain;
  }

  private async innerSignature(
    explicit: string | undefined,
    digestHex: string,
    field: string,
  ): Promise<string> {
    if (explicit) return explicit;
    if (this.signer.signDigest) return this.signer.signDigest(digestHex);
    throw new BuilderError(
      "missing_inner_signature",
      `${field} is required: this signer does not expose signDigest`,
    );
  }

  /**
   * Register the EVM address bound to the signing PQ account.
   *
   * `bindingSignature` is the Falcon signature over
   * `evmBindingDigest(chainId, evmAddress, from)`. Supply it, or let the
   * signer's `signDigest` hook produce it.
   */
  async evmBinding(
    options: Omit<EvmBindingOptions, "from" | "nonce" | "chainId" | "bindingSignature"> & {
      bindingSignature?: string;
      nonce?: number;
      chainId?: number;
    },
  ): Promise<SignedTransaction> {
    const from = this.address();
    const chainId = await this.guardedChainId(options);
    const nonce = options.nonce ?? (await this.nonce(from));
    const digest = evmBindingDigest(chainId, options.evmAddress, from);
    const bindingSignature = await this.innerSignature(
      options.bindingSignature,
      digest,
      "bindingSignature",
    );
    const unsigned = buildEvmBinding({
      ...options,
      from,
      chainId,
      nonce,
      bindingSignature,
    });
    return this.signPrepared(unsigned);
  }

  /**
   * Settle an EVM value-transfer intent under the signing PQ account.
   *
   * `intentSignature` is the Falcon signature over `keccak256(evmTx)`.
   * Nonce and amount are taken from the EVM intent; pass `nonce`/`amountNano`
   * to pin them (a mismatch throws `BuilderError`).
   */
  async evmCarrier(
    options: Omit<EvmCarrierOptions, "from" | "chainId" | "intentSignature"> & {
      intentSignature?: string;
      chainId?: number;
    },
  ): Promise<{ signed: SignedTransaction; plan: EvmCarrierPlan }> {
    const from = this.address();
    const chainId = await this.guardedChainId(options);
    const intentSignature = await this.innerSignature(
      options.intentSignature,
      evmCarrierDigest(options.evmTx),
      "intentSignature",
    );
    const plan = buildEvmCarrier({ ...options, from, chainId, intentSignature });
    const signed = await this.signPrepared(plan);
    return { signed, plan };
  }

  /** Build, sign and return a block-carried governance proposal. */
  async govPropose(
    options: Omit<GovProposeOptions, "from" | "nonce" | "chainId"> & { nonce?: number; chainId?: number },
  ): Promise<SignedTransaction> {
    const from = this.address();
    const chainId = await this.guardedChainId(options);
    const nonce = options.nonce ?? (await this.nonce(from));
    const unsigned = buildGovPropose({ ...options, from, chainId, nonce });
    return this.signPrepared(unsigned);
  }

  /** Build, sign and return a block-carried governance vote. */
  async govVote(
    options: Omit<GovVoteOptions, "from" | "nonce" | "chainId"> & { nonce?: number; chainId?: number },
  ): Promise<SignedTransaction> {
    const from = this.address();
    const chainId = await this.guardedChainId(options);
    const nonce = options.nonce ?? (await this.nonce(from));
    const unsigned = buildGovVote({ ...options, from, chainId, nonce });
    return this.signPrepared(unsigned);
  }

  // ------------------------------------------------------------------
  // Submission
  // ------------------------------------------------------------------

  /**
   * Submit a signed transaction. Retries resend the SAME `rawTransaction`.
   *
   * - transport failures and retryable RPC errors are retried with
   *   exponential backoff;
   * - `rejected: transaction already in mempool` is success;
   * - every other refusal is returned immediately.
   */
  async sendSigned(
    signed: SignedTransaction,
    options: RetryOptions = {},
  ): Promise<SubmitResult> {
    const attempts = Math.max(1, options.attempts ?? 4);
    const baseDelay = options.baseDelayMs ?? 200;
    const maxDelay = options.maxDelayMs ?? 2_000;
    let delay = baseDelay;

    for (let attempt = 1; attempt <= attempts; attempt++) {
      try {
        const hash = await this.provider.client.request<string>(
          "stell_sendRawTransaction",
          { tx: signed.rawTransaction },
        );
        return { hash, attempts: attempt, alreadyInMempool: false };
      } catch (error) {
        if (
          (error instanceof RpcError || error instanceof Error) &&
          isDuplicateMessage(error.message)
        ) {
          return {
            hash: signed.hash,
            attempts: attempt,
            alreadyInMempool: true,
          };
        }
        if (isRetryableError(error) && attempt < attempts) {
          await sleep(delay);
          delay = Math.min(delay * 2, maxDelay);
          continue;
        }
        if (error instanceof RpcError) throw error;
        if (error instanceof SignerError) throw error;
        throw error;
      }
    }
    // Unreachable for attempts >= 1; kept to satisfy the type checker.
    throw new RpcError("stell_sendRawTransaction", -1, "retry loop exhausted");
  }

  /** Submit and wait for the committed receipt. */
  async sendAndWait(
    signed: SignedTransaction,
    options: RetryOptions & { timeoutMs?: number; pollMs?: number } = {},
  ): Promise<{ submit: SubmitResult; receipt: Receipt }> {
    const submit = await this.sendSigned(signed, options);
    const receipt = await this.waitForReceipt(submit.hash, {
      timeoutMs: options.timeoutMs,
      pollMs: options.pollMs,
    });
    return { submit, receipt };
  }

  /** Poll `stell_getTransactionReceipt` until committed or timed out. */
  async waitForReceipt(
    hash: string,
    options: { timeoutMs?: number; pollMs?: number } = {},
  ): Promise<Receipt> {
    const timeoutMs = options.timeoutMs ?? 60_000;
    const pollMs = options.pollMs ?? 1_000;
    const started = Date.now();
    for (;;) {
      const r = await this.receipt(hash);
      if (r) return r;
      if (Date.now() - started >= timeoutMs) {
        throw new RpcError("stell_getTransactionReceipt", -32004, `receipt not found: ${hash}`);
      }
      await sleep(Math.min(pollMs, Math.max(0, timeoutMs - (Date.now() - started))));
    }
  }

  /** The activation surcharge the Rust builder applies to explicit envelopes. */
  static activationSurcharge(): number {
    return DEFAULT_ACTIVATION_SURCHARGE;
  }

  /** The frozen admission floor. */
  static feeFloor(): number {
    return DEFAULT_FEE_FLOOR;
  }

  /** Exposed for tests and advanced callers. */
  async signResponse(intent: TxIntent, options: BuildAndSignOptions = {}): Promise<SignResponse> {
    const signed = await this.buildAndSign(intent, options);
    return {
      ok: true,
      tx_hex: signed.rawTransaction,
      tx_hash: signed.hash,
      from: signed.from,
      from_stl57: signed.fromStl57,
      to: signed.to,
      nonce: signed.nonce,
      chain_id: signed.chainId,
      gas_limit: signed.gasLimit,
      activation: signed.activation,
      envelope: signed.envelope,
    };
  }
}
