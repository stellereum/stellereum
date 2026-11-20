/**
 * Protocol identity, fork id and the pre-sign guard.
 *
 * The node refuses consensus participation to a peer with a different fork id
 * or protocol major, and refuses transactions bound to a foreign chain id.
 * The TypeScript SDK runs the SAME guard before it asks the signer for a
 * signature: a stale dApp fails locally with a specific error instead of
 * producing bytes the node will reject.
 *
 * `FORK_ID` is a compile-time FNV-1a-32 fold over the consensus ruleset
 * inputs (`stellereum/src/protocol.rs`). It is duplicated here (a dApp must
 * not link the node) and pinned by the Rust parity suite and by this package's
 * tests.
 */

/** Price of a mismatched chain/fork/version. */
export class ProtocolError extends Error {
  readonly code:
    | "chain_id_mismatch"
    | "fork_id_mismatch"
    | "protocol_version_mismatch"
    | "invalid_identity";

  constructor(code: ProtocolError["code"], message: string) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
  }
}

export const PROTOCOL_MAJOR = 1;
export const PROTOCOL_MINOR = 0;
export const CONSENSUS_RULESET_VERSION = 6;
export const DOMAIN_SET_VERSION = 3;
export const DEFAULT_CHAIN_ID = 5757;
export const CAP_COMPACT_GOSSIP = 1n << 0n;
export const CAP_MESH_DIRECT = 1n << 1n;
export const CAPABILITIES = CAP_COMPACT_GOSSIP | CAP_MESH_DIRECT;

/** Consensus constants folded into `FORK_ID`, in the node's order. */
export const FORK_ID_RULES: readonly bigint[] = [
  4_096n, // MAX_COMMIT_CERT_SIGNERS
  1_000n, // MAX_ROUND_AHEAD
  1n, // MAX_ROUND_ADVANCE_PER_MESSAGE
  8n, // MAX_SYNC_JUMPS_PER_ROUND
  3_000n, // FROZEN_ROUND_TIMEOUT_BASE_MS
  128n, // MICRO_COMMITTEE_MAX_SIZE
  42n, // DOWNTIME_MISS_THRESHOLD
  500n, // DOWNTIME_PENALTY_COOLDOWN
  4_000n, // JAIL_RELEASE_DELAY_HEIGHTS
  30_000n, // COMMISSION_EFFECT_DELAY_HEIGHTS
  30_000n, // COMMISSION_CHANGE_COOLDOWN_HEIGHTS
  30_000n, // CNVRF EPOCH_LEN
  1_875n, // CNVRF V3_SEGMENT_LEN
  682n, // CNVRF V3_COMMIT_LOOKAHEAD_BLOCKS
  30_000n, // PQ_ROTATION_DELAY_HEIGHTS
  30_000n, // MEV_KEM_ROTATION_DELAY_HEIGHTS
  500n, // MEV_EPOCH_BLOCKS
  500n, // MMR_EPOCH_BLOCKS
  3_000_000n, // DEFAULT_VDF_STEPS_PER_EPOCH
  0n, // PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT (0 = active from genesis, ruleset v4)
  3_600_000n, // MAX_BLOCK_TIMESTAMP_DRIFT_MS (1 hour; ruleset v4)
  1n, // CHAIN_SUPPLY_PARTITION_VERSION (ruleset v5)
  1_000_000_000_000_000_000n, // TOTAL_SUPPLY_CAP (ruleset v5)
];

const FORK_DOMAINS: readonly Uint8Array[] = [
  new TextEncoder().encode("STELL_SORTITION_V5"),
  new TextEncoder().encode("STELLEREUM_EQUIVOCATION_OFFENSE_V2"),
  new TextEncoder().encode("STELLEREUM_PROPOSAL_EQUIVOCATION_OFFENSE_V2"),
  new TextEncoder().encode("STELLEREUM_BFT_VOTE_V3"),
  new TextEncoder().encode("STELL_VOTEFAL_V1"),
  new TextEncoder().encode("STELL_UQC_PQ_V5_"),
  new TextEncoder().encode("STELL_QC_PQ_V5__"),
];

const FNV_OFFSET = 0x811c9dc5;
const FNV_PRIME = 0x01000193;

function fnv1a32(seed: number, bytes: Uint8Array): number {
  let h = seed >>> 0;
  for (const b of bytes) {
    h ^= b;
    h = Math.imul(h, FNV_PRIME) >>> 0;
  }
  return h >>> 0;
}

function u32le(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}

function u64le(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

function foldU64(h: number, value: bigint): number {
  return fnv1a32(h, u64le(value));
}

/** Pure derivation of the node's fork id. */
export function deriveForkId(
  chainId: bigint,
  rulesetVersion: number,
  rules: readonly bigint[],
): number {
  let h = fnv1a32(FNV_OFFSET, new TextEncoder().encode("STELL_FORK_ID_V1"));
  h = fnv1a32(h, u32le(DOMAIN_SET_VERSION));
  h = foldU64(h, chainId);
  h = fnv1a32(h, u32le(rulesetVersion));
  for (const domain of FORK_DOMAINS) h = fnv1a32(h, domain);
  for (const rule of rules) h = foldU64(h, rule);
  return h >>> 0;
}

/** The fork id this package was built for (ruleset v6). */
export const FORK_ID = deriveForkId(
  BigInt(DEFAULT_CHAIN_ID),
  CONSENSUS_RULESET_VERSION,
  FORK_ID_RULES,
);

export const FORK_ID_HEX = `0x${FORK_ID.toString(16).padStart(8, "0")}`;

/** The identity of the node a builder targets. */
export interface ProtocolIdentity {
  chainId: number;
  protocolMajor: number;
  protocolMinor: number;
  forkId: number;
  capabilities?: bigint;
}

/** The identity of the chain this package was compiled for. */
export function localIdentity(): ProtocolIdentity {
  return {
    chainId: DEFAULT_CHAIN_ID,
    protocolMajor: PROTOCOL_MAJOR,
    protocolMinor: PROTOCOL_MINOR,
    forkId: FORK_ID,
    capabilities: CAPABILITIES,
  };
}

/**
 * Refuse a protocol version or fork id that is not this build's.
 *
 * Called by every new-shape builder (`buildEvmBinding`, `buildEvmCarrier`,
 * `buildGovPropose`, `buildGovVote`) before any bytes are produced.
 */
export function assertIdentity(identity: ProtocolIdentity): void {
  if (identity.protocolMajor !== PROTOCOL_MAJOR || identity.protocolMinor !== PROTOCOL_MINOR) {
    throw new ProtocolError(
      "protocol_version_mismatch",
      `protocol version mismatch: configured node speaks ${identity.protocolMajor}.${identity.protocolMinor}, ` +
        `this SDK build speaks ${PROTOCOL_MAJOR}.${PROTOCOL_MINOR}`,
    );
  }
  if (identity.forkId !== FORK_ID) {
    throw new ProtocolError(
      "fork_id_mismatch",
      `fork id mismatch: configured node reports 0x${identity.forkId.toString(16).padStart(8, "0")}, ` +
        `this SDK build speaks ${FORK_ID_HEX}`,
    );
  }
}

/** Refuse a transaction chain id that is not the configured identity's. */
export function assertChainId(identity: ProtocolIdentity, chainId: number): void {
  if (chainId !== identity.chainId) {
    throw new ProtocolError(
      "chain_id_mismatch",
      `chain id mismatch: builder would bind ${chainId}, configured node identity is ${identity.chainId}`,
    );
  }
}

/** Verify identity AND chain id in one call. */
export function assertIdentityForChain(identity: ProtocolIdentity, chainId: number): void {
  assertIdentity(identity);
  assertChainId(identity, chainId);
}

/** The machine-readable identity this build speaks (node `version_info` shape). */
export function localVersionInfo(): Record<string, unknown> {
  return {
    protocol_version: `${PROTOCOL_MAJOR}.${PROTOCOL_MINOR}`,
    protocol_major: PROTOCOL_MAJOR,
    protocol_minor: PROTOCOL_MINOR,
    fork_id: FORK_ID,
    fork_id_hex: FORK_ID_HEX,
    capabilities: Number(CAPABILITIES),
    capabilities_names: ["COMPACT_GOSSIP", "MESH_DIRECT"],
    consensus_ruleset_version: CONSENSUS_RULESET_VERSION,
    domain_set_version: DOMAIN_SET_VERSION,
    chain_id: DEFAULT_CHAIN_ID,
  };
}
