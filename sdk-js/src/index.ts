/**
 * `@stellereum/sdk` — Stellereum dApp client.
 *
 * - `StellereumProvider`: EIP-1193 read-only provider + `eth_*` read
 *   passthrough + all `stell_*` methods.
 * - `StellereumClient`: typed reads, `buildAndSign` (delegated to the Rust
 *   Falcon signer), submission retries, receipt waiting.
 * - `SubprocessFalconSigner` / `HttpFalconSigner`: the two supported ways to
 *   obtain a real PQ1/Falcon signature; JS does not sign Falcon natively.
 */

export {
  HttpFalconSigner,
  SubprocessFalconSigner,
  type FalconSigner,
  type JsonCallArg,
  type SignRequest,
  type SignResponse,
  type SubprocessSignerOptions,
  type TxCommon,
  type TxIntent,
} from "./signer.ts";

export {
  StellereumClient,
  type Account,
  type BuildAndSignOptions,
  type FeeEstimate,
  type Receipt,
  type RetryOptions,
  type SignedTransaction,
  type StellereumClientOptions,
  type SubmitResult,
} from "./client.ts";

export { StellereumProvider, type RequestArguments, type StellereumProviderOptions } from "./provider.ts";

export { JsonRpcClient, type FetchLike, type JsonRpcClientOptions } from "./rpc.ts";

export {
  ProviderRpcError,
  RpcError,
  SignerError,
  TransportError,
  UnsupportedMethodError,
  isDuplicateMessage,
  isRetryableError,
} from "./errors.ts";
