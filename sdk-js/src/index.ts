/**
 * `@stellereum/sdk` — Stellereum dApp client.
 *
 * - `StellereumProvider`: EIP-1193 read-only provider + `eth_*` read
 *   passthrough + all `stell_*` methods.
 * - `StellereumClient`: typed reads, `buildAndSign` (delegated to the Rust
 *   Falcon signer), the protocol-v1 EVM/governance builders, submission
 *   retries and receipt waiting.
 * - `SubprocessFalconSigner` / `HttpFalconSigner`: the two supported ways to
 *   obtain a real PQ1/Falcon signature; JS does not sign Falcon natively.
 * - Unsigned builders (`buildEvmBinding`, `buildEvmCarrier`,
 *   `buildGovPropose`, `buildGovVote`) for callers that want the bytes before
 *   asking the sidecar for an envelope.
 */

export {
  HttpFalconSigner,
  SubprocessFalconSigner,
  type FalconSigner,
  type JsonCallArg,
  type SignDigestRequest,
  type SignDigestResponse,
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
  BuilderError,
  buildEvmBinding,
  buildEvmCarrier,
  buildGovPropose,
  buildGovVote,
  evmBindingDigest,
  evmCarrierDigest,
  type BaseTxOptions,
  type BuilderErrorCode,
  type EvmBindingOptions,
  type EvmCarrierOptions,
  type EvmCarrierPlan,
  type GovProposeOptions,
  type GovVoteOptions,
} from "./builders.ts";

export {
  EVM_BINDING_MIN_GAS,
  EVM_BINDING_PROOF_LEN,
  EVM_CARRIER_MIN_GAS,
  EVM_CONTRACT_EXECUTION_REFUSAL,
  WEI_PER_NANO,
  bindingMessage,
  decodeEvmIntent,
  evmIntentDigest,
  keccak256,
  requireBindingProof,
  type EvmIntentFacts,
} from "./evm.ts";

export {
  CAPABILITIES,
  CONSENSUS_RULESET_VERSION,
  DEFAULT_CHAIN_ID as PROTOCOL_DEFAULT_CHAIN_ID,
  FORK_ID,
  FORK_ID_HEX,
  FORK_ID_RULES,
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
  ProtocolError,
  assertChainId,
  assertIdentity,
  assertIdentityForChain,
  deriveForkId,
  localIdentity,
  localVersionInfo,
  type ProtocolIdentity,
} from "./protocol.ts";

export {
  CHAIN_ID_COMMITMENT_TAG,
  FROZEN_MIN_GAS_FLOOR,
  PQ_ACTIVATION_SURCHARGE_GAS,
  bytesToHex,
  encodeGovAction,
  encodeOp,
  encodePayload,
  encodeUnsignedTransaction,
  hexToBytes,
  signingMessage,
  unsignedTxHash,
  type GovAction,
  type UnsignedTransaction,
  type VoteChoice,
} from "./wire.ts";

export {
  ProviderRpcError,
  RpcError,
  SignerError,
  TransportError,
  UnsupportedMethodError,
  isDuplicateMessage,
  isRetryableError,
} from "./errors.ts";
