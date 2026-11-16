export interface Block {
  height: number;
  block_hash: string;
  tx_count: number;
  timestamp: number;
  shard_id: number;
  proposer: string;
  proposer_stl57?: string;
  state_root?: string;
  prev_hash?: string;
  size?: number;
}

export interface Transaction {
  hash: string;
  block_height: number;
  from_addr: string;
  from_stl57?: string;
  to_addr: string;
  to_stl57?: string;
  amount: number | string; // nano-STELL
  gas_limit: number;
  gas_used: number;
  fee: number | string; // nano-STELL
  nonce: number;
  status: 'success' | 'failed' | 'pending';
  timestamp: number;
  source_shard: number;
  target_shard: number;
  payload_opcodes?: string[];
  signature_scheme?: string;
}

export interface Validator {
  rank: number;
  address: string;
  address_stl57: string;
  name: string;
  stake: string; // nano-STELL
  self_bond: string;
  delegated: string;
  weight: number;
  main: boolean;
  status: string;
  uptime: number;
  commission_bps: number;
  falcon_pubkey: string;
  blocks_proposed: number;
}

export interface NetworkStats {
  tip_height: number;
  total_blocks: number;
  total_transactions: number;
  total_accounts: number;
  current_tps: number;
  tps: number;
  avg_block_time: number;
  block_time: number;
  chain_id: number;
  shards: number;
  validators_count?: number;
}

export interface AccountInfo {
  address: string;
  address_stl57: string;
  balance: number | string; // nano-STELL
  nonce: number;
  tx_count: number;
  is_contract: boolean;
  staked_amount?: number | string;
  reward_balance?: number | string;
}

// ---------------------------------------------------------------------------
// The remediation wave: contracts, events, shards, the live validator set
// and the transaction OUTCOME.
// ---------------------------------------------------------------------------

/** One contract event, as the indexer serves it (ABI-decoded when known). */
export interface ContractEvent {
  tx_hash: string;
  block_height: number;
  log_index: number;
  contract: string;
  contract_stl57?: string;
  topic0?: string;
  topics?: any[];
  data?: any;
  event_name?: string | null;
  decoded?: boolean;
  args?: { topics?: Record<string, unknown>; data?: Record<string, unknown> };
}

/** One contract of the contract list. */
export interface ContractSummary {
  contract: string;
  contract_stl57?: string | null;
  event_count: number;
  tx_count: number;
  first_block: number;
  last_block: number;
  last_event_name?: string | null;
  events_url?: string;
}

/** One shard head, as `stell_getShards` reports it. */
export interface ShardHead {
  shard_id: number;
  type: 'masterchain' | 'workchain';
  tip_height: number;
  tip_hash?: string | null;
  state_root?: string | null;
  local: boolean;
}

/** The published sharding parameters (the address->shard rule). */
export interface ShardingParameters {
  rule_id?: string;
  rule?: string;
  prefix_bits?: number;
  masterchain_shard?: number;
  base_workchain_shard?: number;
  masterchain_address_form?: string;
  min_accounts_per_shard?: number;
  max_shards?: number;
  split_load_threshold?: number;
  merge_load_threshold?: number;
  max_prefix_bits?: number;
  max_workchain_shard_space?: number;
  active_shards?: number;
}

/** The full shard topology. */
export interface ShardTopology {
  shards: ShardHead[];
  total_shards: number;
  routing_prefix_bits: number;
  sharding?: ShardingParameters;
  source?: string;
  rpc_url?: string;
}

/** One member of the LIVE validator set (`stell_getValidators`). */
export interface LiveValidator {
  validator: string;
  power: string;
}

/** The LIVE validator set (`stell_getValidators`). */
export interface LiveValidatorSet {
  validators: LiveValidator[];
  total_power: string;
  quorum: string;
  /** True when the quorum needs 100% of the set: one halt stops the chain. */
  fragile?: boolean;
  fragile_reason?: string | null;
}

/** The OUTCOME of a transaction. */
export interface TxOutcome {
  status?: string;
  return_value?: number | null;
  gas_used?: number | null;
  fee_charged?: string | null;
  contract_address?: string | null;
  events: ContractEvent[];
  total_events?: number;
  /** Which source the events came from (`rpc`, `indexer`). */
  source: string[];
}
