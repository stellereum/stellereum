use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "stellereum")]
#[command(author = "Stellereum Core Contributors")]
#[command(version = "0.1.0")]
#[command(
    about = "Stellereum: Lightweight, AI-Native, MEV-Resistant & Orderbook-Optimized L1 Blockchain"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Start Stellereum validator node with infnode P2P networking
    Run {
        /// Path to infnode YAML configuration file
        #[arg(short, long, default_value = "config.yaml")]
        config: PathBuf,
        /// Shard ID to run (0 = Masterchain, 1 = Base Workchain)
        #[arg(short, long, default_value_t = 0)]
        shard: u32,
        /// Enable disjoint wave parallel block execution
        #[arg(long)]
        parallel_exec: bool,
        /// Enforce Pure Post-Quantum Mode (FULL-PQ: no-op, always enforced;
        /// kept for operator-config compat, ignored with WARN).
        #[arg(long)]
        pure_pq: bool,
        /// Do not start consensus until a supermajority of the committed
        /// validator set at this height is verified to be on this fork id and
        /// protocol version AND reachable. On timeout the node stays up as an
        /// OBSERVER (RPC/sync serve; no propose/vote). Env fallback:
        /// STELL_WAIT_SUPERMAJORITY.
        #[arg(long)]
        wait_for_supermajority: Option<u64>,
        /// Path to Stellereum TOML node configuration file (env: STELL_NODE_TOML,
        /// or auto-discovers ./stellereum.toml if present). Distinct from -c/--config
        /// which is infnode's YAML configuration file.
        #[arg(long)]
        node_toml: Option<PathBuf>,
        /// Disable non-essential telemetry/status-banner exposure (sets
        /// STELL_NO_TELEMETRY=1; disables `/status` HTML dashboard while keeping
        /// `/health`, `/healthz`, `/readyz`, and `/metrics` operational).
        #[arg(short = 't', long, default_value_t = false)]
        no_telemetry: bool,
    },
    /// Bootstrap a FRESH observer from zero: preflight gate, then the live
    /// sync engine (snapshot-sync incl. ledger + all domains, body walk, live).
    ///
    /// Demands a CLEAN data directory + `STELL_OBSERVER=1` + a configured live
    /// peer, and refuses loudly otherwise — a fresh key started wrong derives
    /// its own solo genesis and splits silently. After the gate passes this
    /// execs into the SAME `run` path (one code path, no fork): the
    /// snapshot-sync + walk + live stages run inside the consensus loop with
    /// their usual loud logs and honest retries. Replaces manual `cp -a`
    /// of another node's data directory.
    NodeBootstrap {
        /// Path to infnode YAML configuration file
        #[arg(short, long, default_value = "config.yaml")]
        config: PathBuf,
        /// Shard ID to run (0 = Masterchain, 1 = Base Workchain)
        #[arg(short, long, default_value_t = 0)]
        shard: u32,
        /// Data directory that must be CLEAN (no store/kv.json from a previous run)
        #[arg(long, default_value = "./data")]
        data_dir: PathBuf,
        /// Allow a NON-clean data directory (restart, NOT a fresh bootstrap).
        /// Fresh joins must wipe the whole ./data instead (OPERATIONS §8).
        #[arg(long, default_value_t = false)]
        allow_dirty: bool,
        /// Only check the preflight gate and print the plan; do not start the node.
        #[arg(long, default_value_t = false)]
        no_exec: bool,
    },
    /// Run local testnet simulator (in-process multi-shard & multi-validator cluster)
    Sim {
        /// Number of simulated blocks to produce
        #[arg(short, long, default_value_t = 5)]
        blocks: u64,
    },
    /// Run a local DETERMINISTIC devnet (seeded genesis, blocks, state snapshots)
    ///
    /// The devnet never reads the wall clock and never uses OS randomness:
    /// block timestamps are logical and every key is derived from `--seed`,
    /// so the same seed always produces the same chain and the same state root.
    Devnet {
        /// Number of validator accounts in the devnet genesis
        #[arg(long, default_value_t = 4)]
        accounts: usize,
        /// Number of blocks to simulate
        #[arg(long, default_value_t = 100)]
        blocks: u64,
        /// Deterministic seed (hex). The same seed always yields the same chain.
        #[arg(long, default_value = "00")]
        seed: String,
        /// Transactions per block produced by the built-in workload
        #[arg(long, default_value_t = 2)]
        txs_per_block: u64,
        /// Logical block time in milliseconds (the simulator never reads a clock)
        #[arg(long, default_value_t = 400)]
        block_time_ms: u64,
        /// Write the transaction log (JSON lines) to this path
        #[arg(long)]
        log: Option<PathBuf>,
        /// Write the final state snapshot to this path
        #[arg(long)]
        snapshot: Option<PathBuf>,
    },
    /// Replay a recorded simulator transaction log and verify the state root
    ///
    /// Rebuilds the genesis from the seed stored in the log, re-applies every
    /// block and fails when the resulting state root differs from the
    /// recorded one.
    SimReplay {
        /// Path to the transaction log (JSON lines)
        #[arg(long)]
        log: PathBuf,
    },
    /// Wallet management and transaction dispatch
    Wallet {
        #[command(subcommand)]
        sub: WalletCommands,
    },
    /// Native Orderbook-Actor CLOB operations
    Orderbook {
        #[command(subcommand)]
        sub: OrderbookCommands,
    },
    /// 3-Tier Price Oracle & Circuit Breaker inspection
    Oracle {
        #[command(subcommand)]
        sub: OracleCommands,
    },
    /// Native Teleport Bridges (TON, Arbitrum, Ethereum, Solana)
    Bridge {
        #[command(subcommand)]
        sub: BridgeCommands,
    },
    /// Genesis Vault parameters & token exchange simulation
    Genesis {
        /// Action: "info" or "mint"
        #[arg(default_value = "info")]
        action: String,
        /// Asset to deposit (USDT, TON, GRAM)
        #[arg(long, default_value = "USDT")]
        asset: String,
        /// Amount in native units (e.g. 100 for 100 USDT)
        #[arg(long, default_value_t = 100)]
        amount: u64,
        /// Asset price in USD (e.g. 1.0 for USDT, 5.0 for TON)
        #[arg(long, default_value_t = 1.0)]
        price_usd: f64,
    },
    /// Primary Market Maker (bonding-curve Mint & Redeem exchange)
    Pmm {
        /// Action: "price", "buy", or "sell"
        #[arg(default_value = "price")]
        action: String,
        /// For buy/sell: amount in USD (buy) or STELL (sell)
        #[arg(long, default_value_t = 100)]
        amount: u64,
        /// Initial USDT reserve in USD for the simulation
        #[arg(long, default_value_t = 1_000_000)]
        reserve_usd: u64,
    },
    /// EXTERNAL LIGHT CLIENT: verify a state proof against a quorum-certified
    /// header, WITHOUT running consensus (Near `light_client` / Sui
    /// `sui_light_client` model).
    ///
    /// Fetches a proof from a node's RPC and checks it against a root a
    /// QUORUM committed to: the anchoring header's precommit certificate is
    /// verified against the OUT-OF-BAND validator set you pin with
    /// `--validators` (never against a set the server hands out), and only
    /// then is the Merkle proof checked.
    LightClient {
        /// The node's JSON-RPC endpoint.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        from: String,
        /// The 32-byte account address (hex) whose balance to verify.
        #[arg(long)]
        verify: String,
        /// OUT-OF-BAND validator set (JSON). REQUIRED — without it there is
        /// no trust anchor and the server could certify its own chain.
        #[arg(long)]
        validators: PathBuf,
        /// How long to wait for the node to finalize the header that commits
        /// to the served proof's root.
        #[arg(long, default_value_t = 30)]
        wait_seconds: u64,
        /// Reject proofs and anchoring headers below this height. Guards
        /// against a node replaying an older, genuinely signed checkpoint.
        /// The flag requires a value: `--min-height` on its own is refused.
        #[arg(long)]
        min_height: Option<u64>,
        /// Print the RPC traffic.
        #[arg(long, default_value_t = false)]
        verbose: bool,
    },
    /// Show the light-client anchor (set hash, height) from OFFLINE files.
    ///
    /// Loads the out-of-band validator set and the checkpoint and re-verifies
    /// the checkpoint's precommit quorum under the set. Fail-closed: a bad
    /// anchor is refused instead of printed.
    LightAnchor {
        /// OUT-OF-BAND validator set (JSON). REQUIRED — the trust anchor.
        #[arg(long)]
        validators: PathBuf,
        /// Quorum-certified checkpoint (JSON, as served by
        /// `stell_getFinalizedCheckpoint`).
        #[arg(long)]
        checkpoint: PathBuf,
    },
    /// Verify a header/checkpoint file against the OFFLINE anchor.
    ///
    /// The header file may hold a LightHeader (checked as the tip's successor)
    /// or a Checkpoint (adopted as a newer anchor). Both paths enforce the
    /// precommit-quorum rule under the set in force. Fail-closed on bad proof,
    /// wrong tip or stale set.
    LightVerify {
        /// OUT-OF-BAND validator set (JSON). REQUIRED — the trust anchor.
        #[arg(long)]
        validators: PathBuf,
        /// Quorum-certified checkpoint (JSON) the client is anchored on.
        #[arg(long)]
        checkpoint: PathBuf,
        /// Header or checkpoint file (JSON) to verify against the anchor.
        #[arg(long)]
        header: PathBuf,
    },
    /// Rotate the OFFLINE anchor with a rotation proof file.
    ///
    /// The proof file holds a ValidatorSetRotation (`rotation` header plus
    /// `next_set`). The supermajority-of-old-set rule is enforced by
    /// `LightClient::rotate_validator_set` — the CLI only parses, never judges.
    LightRotate {
        /// OUT-OF-BAND validator set (JSON). REQUIRED — the current anchor set.
        #[arg(long)]
        validators: PathBuf,
        /// Quorum-certified checkpoint (JSON) the client is anchored on.
        #[arg(long)]
        checkpoint: PathBuf,
        /// Rotation proof file (JSON): the successor header plus the next set.
        #[arg(long)]
        rotation: PathBuf,
    },
    /// Network discovery and connectivity guide
    Network,
    /// Inspect the software-upgrade halt marker (read-only).
    ///
    /// Prints the exact marker file, the plan's halt height and target
    /// version, the version this binary reports, and whether the running
    /// binary satisfies the plan. The node's own startup guard makes the same
    /// comparison against the local finalized head before it joins consensus
    /// (`docs/UPGRADE_AND_RECOVERY.md` §1.2.3/§1.2.4). This command NEVER
    /// edits or clears the marker.
    UpgradeStatus {
        /// Marker file to inspect (default: $STELL_UPGRADE_HALT_MARKER, else
        /// ./data/upgrade-halt.marker)
        #[arg(long)]
        marker: Option<PathBuf>,
    },
    /// Node identity keys for validator/observer onboarding (one-command join).
    ///
    /// Uses the SAME `load_or_generate` mechanism as `run`, so keys created
    /// here are byte-identical in format and permissions (0700 dir, 0600
    /// files) to keys created on first start. Used by
    /// `scripts/join-network.sh`.
    Keys {
        #[command(subcommand)]
        sub: KeysCommands,
    },
    /// Initialize durable consensus safety record (generation 1) after
    /// stopping and fencing all legacy validators and remote signers for this key.
    SafetyInit {
        /// Store directory containing the sled DB (default: ./data/store)
        #[arg(long, default_value = "./data/store")]
        store_dir: PathBuf,
        /// Keys directory containing validator.key (default: ./keys)
        #[arg(long, default_value = "./keys")]
        keys_dir: PathBuf,
        /// Optional validator Ed25519 public key (32-byte hex) when key is held by a remote signer
        #[arg(long)]
        validator_pub: Option<String>,
        /// Shard ID to initialize (0 = Masterchain, 1 = Base Workchain)
        #[arg(long, default_value_t = 0)]
        shard: u32,
        /// Conservative initial highest prevote round floor at finalized_height + 1
        #[arg(long)]
        prevote_round_floor: Option<u32>,
        /// Conservative initial highest precommit round floor at finalized_height + 1
        #[arg(long)]
        precommit_round_floor: Option<u32>,
        /// Confirm all legacy validators and remote signers using this key are fenced/stopped
        #[arg(long, default_value_t = false)]
        i_fenced_all_signers: bool,
    },
    /// One-screen operator status: height, validator set, quorum, jails,
    /// efficiency and a verdict with the next action.
    ///
    /// Talks only to the node's own JSON-RPC (no keys, no writes), so it is
    /// safe to run from cron or by a second operator during an incident.
    Status {
        /// Node JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Machine-readable JSON instead of the human summary
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Expected number of validators. When given, a smaller in-set count is
        /// reported as DEGRADED: jailed members do not appear in the set list,
        /// so without this the summary would call a 3-of-4 cluster healthy.
        #[arg(long)]
        expect: Option<usize>,
    },
    /// Print the activation-gate table (id, status, height, proving test).
    ///
    /// `--yaml` renders the committed manifest `docs/feature_gates.yaml`; the
    /// library test `feature_gates::tests::committed_manifest_matches_the_table`
    /// pins the file to the same output, so the document cannot drift.
    Gates {
        /// Render the machine-readable manifest instead of the human table
        #[arg(long, default_value_t = false)]
        yaml: bool,
    },
    /// Delete a durable consensus safety record that can no longer be decoded
    /// (store corruption, an unsupported concurrent open, a lost record), so
    /// that `safety-init` can write generation 1 again.
    ///
    /// This is the §2.3/§2.4 operator recovery path: it DESTROYS the durable
    /// vote watermarks, so it must only run with the node, every legacy
    /// process and every remote signer for this key stopped and fenced.
    SafetyReset {
        /// Store directory containing the sled DB (default: ./data/store)
        #[arg(long, default_value = "./data/store")]
        store_dir: PathBuf,
        /// Confirm the node, its legacy processes and every remote signer for
        /// this key are stopped and fenced
        #[arg(long, default_value_t = false)]
        i_fenced_all_signers: bool,
    },
    /// W3 PQ validator lifecycle and staking transactions
    Validator {
        #[command(subcommand)]
        sub: ValidatorCommands,
    },
    /// On-chain governance proposals, votes, and parameters
    Gov {
        #[command(subcommand)]
        sub: GovCommands,
    },
    /// Inspect and validate Stellereum TOML + environment configuration
    Config {
        #[command(subcommand)]
        sub: ConfigCommands,
    },
    /// Store snapshot bootstrap and recovery operations
    Store {
        #[command(subcommand)]
        sub: StoreCommands,
    },
}

#[derive(Subcommand)]
pub(crate) enum StoreCommands {
    /// Initialize or refresh the local store from a snapshot URL or local `.tar.zst`
    /// archive, verify SHA-256, strip stale `snap*` temp files, and run
    /// `safety-reset` (+ `safety-init` unless `--observer`).
    Bootstrap {
        /// Target data directory containing `store`
        #[arg(long, default_value = "./data")]
        data_dir: PathBuf,
        /// Validator keys directory containing `validator.key`
        #[arg(long, default_value = "./keys")]
        keys_dir: PathBuf,
        /// Shard ID passed to `safety-init` (0 = Masterchain, 1 = Base Workchain)
        #[arg(long, default_value_t = 0)]
        shard: u32,
        /// Snapshot archive URL (ignored when `--archive` is provided)
        #[arg(
            long,
            default_value = "https://rpc.stellereum.org/snapshot/latest.tar.zst"
        )]
        snapshot_url: String,
        /// SHA-256 manifest URL (defaults to `<snapshot-url>.sha256` in HTTP mode)
        #[arg(long)]
        sha256_url: Option<String>,
        /// Fail closed if SHA-256 manifest is missing (e.g. HTTP 404) or unavailable
        #[arg(long, default_value_t = false)]
        require_sha256: bool,
        /// Local `.tar.zst` snapshot archive path for offline/airgapped bootstrap
        #[arg(long)]
        archive: Option<PathBuf>,
        /// Expected 64-hex SHA-256 digest pin for offline or explicit verification
        #[arg(long)]
        expected_sha256: Option<String>,
        /// Backup and replace an existing `<data-dir>/store`
        #[arg(long, default_value_t = false)]
        refresh_if_stale: bool,
        /// Allow replacing an existing `<data-dir>/store` (same as `--refresh-if-stale`)
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Delete existing `<data-dir>/store` instead of renaming to `store.bak-bootstrap-<ts>`
        #[arg(long, default_value_t = false)]
        no_backup: bool,
        /// Confirm all legacy validators and remote signers for this key are stopped and fenced
        #[arg(long, default_value_t = false)]
        i_fenced_all_signers: bool,
        /// Bootstrap as observer: clear foreign `safety_record_v1` via `safety-reset`
        /// without requiring local validator keys or running `safety-init`
        #[arg(long, default_value_t = false)]
        observer: bool,
        /// Validate paths and flags and print the bootstrap plan without mutating disk
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Emit machine-readable JSON summary instead of human-readable output
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ConfigCommands {
    /// Load optional TOML config, merge STELL_* env overrides, and validate invariants
    Check {
        /// Path to TOML config file (error if missing; default: $STELL_NODE_TOML or ./stellereum.toml if present)
        #[arg(long)]
        file: Option<PathBuf>,
        /// Emit machine-readable JSON instead of the human-readable summary
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum GovCommands {
    /// List governance proposals from the node
    List {
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Show full details of a governance proposal
    Show {
        /// Proposal ID
        #[arg(long)]
        id: u64,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Show current governance parameters (quorum, next_id, applied overrides)
    Params {
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Submit a block-carried governance proposal (SysCallGovPropose)
    Propose {
        /// Falcon-512 key file of the proposer
        #[arg(long)]
        falcon_key_file: Option<PathBuf>,
        /// Falcon-512 seed in hex (32 bytes) of the proposer
        #[arg(long)]
        falcon_seed: Option<String>,
        /// Proposal title
        #[arg(long)]
        title: String,
        /// Canonical governance action type (e.g. signal, set_min_gas_limit, software_upgrade)
        #[arg(long)]
        action: String,
        /// JSON object of action parameters (e.g. '{"value": 500000}' or '{"text": "..."}')
        #[arg(long, default_value = "{}")]
        params: String,
        /// Expected proposal id (defaults to `stell_governanceParams.next_id`)
        #[arg(long)]
        proposal_id: Option<u64>,
        /// Observed block height (defaults to `stell_blockNumber` + 1)
        #[arg(long)]
        height: Option<u64>,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into the PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// Cast a block-carried vote on a governance proposal (SysCallGovVote)
    Vote {
        /// Falcon-512 key file of the voter
        #[arg(long)]
        falcon_key_file: Option<PathBuf>,
        /// Falcon-512 seed in hex (32 bytes) of the voter
        #[arg(long)]
        falcon_seed: Option<String>,
        /// Proposal ID to vote on
        #[arg(long)]
        id: u64,
        /// Vote choice: yes, no, or abstain (case-insensitive)
        #[arg(long)]
        choice: String,
        /// Observed block height (defaults to `stell_blockNumber` + 1)
        #[arg(long)]
        height: Option<u64>,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into the PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum ValidatorCommands {
    /// Register a new post-W3 PQ validator (OpCode 59: SysCallRegisterValidator)
    RegisterValidator {
        /// Cold withdrawal Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        withdrawal_seed: Option<String>,
        /// Cold withdrawal Falcon-512 key file
        #[arg(long)]
        withdrawal_key_file: Option<PathBuf>,
        /// Hot voting Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        voting_seed: Option<String>,
        /// Hot voting Falcon-512 key file
        #[arg(long)]
        voting_key_file: Option<PathBuf>,
        /// Initial self-bond amount in nano-STELL
        #[arg(long)]
        amount: u64,
        /// Initial commission in basis points (0..=10000)
        #[arg(long, default_value_t = stellereum::staking::DEFAULT_COMMISSION_BPS)]
        commission_bps: u64,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into both the voting PoP and PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// Announce or cancel a Falcon-512 voting-key rotation (OpCode 60: SysCallRotateVotingKey)
    RotateVotingKey {
        /// Cold withdrawal Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        withdrawal_seed: Option<String>,
        /// Cold withdrawal Falcon-512 key file
        #[arg(long)]
        withdrawal_key_file: Option<PathBuf>,
        /// Immutable 32-byte validator_id in hex
        #[arg(long)]
        validator_id: String,
        /// Expected PqKeyRecord::next_seq value
        #[arg(long)]
        rotation_seq: u64,
        /// New hot voting Falcon-512 seed in hex (omit when --cancel)
        #[arg(long)]
        new_voting_seed: Option<String>,
        /// New hot voting Falcon-512 key file (omit when --cancel)
        #[arg(long)]
        new_voting_key_file: Option<PathBuf>,
        /// Cancel an unmatured pending rotation instead of announcing one
        #[arg(long, default_value_t = false)]
        cancel: bool,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into both the voting PoP and PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// Change a validator's cold withdrawal_address with new-key PoP (OpCode 61: SysCallChangeWithdrawal)
    ChangeWithdrawal {
        /// Current cold withdrawal Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        withdrawal_seed: Option<String>,
        /// Current cold withdrawal Falcon-512 key file
        #[arg(long)]
        withdrawal_key_file: Option<PathBuf>,
        /// Immutable 32-byte validator_id in hex
        #[arg(long)]
        validator_id: String,
        /// New cold withdrawal Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        new_withdrawal_seed: Option<String>,
        /// New cold withdrawal Falcon-512 key file
        #[arg(long)]
        new_withdrawal_key_file: Option<PathBuf>,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into both the withdrawal PoP and PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// One-time migration to claim a cold withdrawal_address for a pre-W3 validator (OpCode 62).
    ///
    /// Warns (before and after signing) when the NEW withdrawal address has a
    /// zero balance: the claim cannot be included until that address is funded,
    /// because it cannot pay gas. `--dry-run` is always allowed.
    ClaimWithdrawal {
        /// New cold withdrawal Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        withdrawal_seed: Option<String>,
        /// New cold withdrawal Falcon-512 key file
        #[arg(long)]
        withdrawal_key_file: Option<PathBuf>,
        /// Pre-W3 validator_id in hex (32 bytes)
        #[arg(long)]
        validator_id: String,
        /// Active hot voting Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        voting_seed: Option<String>,
        /// Active hot voting Falcon-512 key file
        #[arg(long)]
        voting_key_file: Option<PathBuf>,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into both the claim signature and PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// Announce a validator commission change (OpCode 63: SysCallAnnounceCommission)
    AnnounceCommission {
        /// Cold withdrawal Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        withdrawal_seed: Option<String>,
        /// Cold withdrawal Falcon-512 key file
        #[arg(long)]
        withdrawal_key_file: Option<PathBuf>,
        /// Immutable 32-byte validator_id in hex
        #[arg(long)]
        validator_id: String,
        /// New commission rate in basis points (0..=10000)
        #[arg(long)]
        new_bps: u64,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into the PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// Apply a matured validator commission change (OpCode 64: SysCallApplyCommission)
    ApplyCommission {
        /// Cold withdrawal Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        withdrawal_seed: Option<String>,
        /// Cold withdrawal Falcon-512 key file
        #[arg(long)]
        withdrawal_key_file: Option<PathBuf>,
        /// Immutable 32-byte validator_id in hex
        #[arg(long)]
        validator_id: String,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into the PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// Inspect on-chain validator status, stake, jail, and withdrawal balance.
    ///
    /// Prints a prominent MANAGEABILITY line (`OK (withdrawal <addr>)` or
    /// `UNMANAGEABLE: no withdrawal_address`) and, when jailed, `released:
    /// yes/no` with the release height and the current height.
    Status {
        /// Validator ID / address in hex (32 bytes)
        #[arg(long)]
        validator: String,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Add self-bond to a validator (SysCallStake, signed by cold withdrawal key)
    Stake {
        /// Cold withdrawal Falcon-512 key file
        #[arg(long)]
        withdrawal_key_file: Option<PathBuf>,
        /// Cold withdrawal Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        withdrawal_seed: Option<String>,
        /// Immutable 32-byte validator_id in hex
        #[arg(long)]
        validator_id: String,
        /// Amount to stake in nano-STELL
        #[arg(long)]
        amount: u64,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into the PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// Begin unbonding validator self-bond (SysCallUnbond, signed by cold withdrawal key)
    Unbond {
        /// Cold withdrawal Falcon-512 key file
        #[arg(long)]
        withdrawal_key_file: Option<PathBuf>,
        /// Cold withdrawal Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        withdrawal_seed: Option<String>,
        /// Immutable 32-byte validator_id in hex
        #[arg(long)]
        validator_id: String,
        /// Amount to unbond in nano-STELL
        #[arg(long)]
        amount: u64,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into the PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// Withdraw matured validator self-bond (SysCallWithdrawSelfBond, signed by cold withdrawal key)
    Withdraw {
        /// Cold withdrawal Falcon-512 key file
        #[arg(long)]
        withdrawal_key_file: Option<PathBuf>,
        /// Cold withdrawal Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        withdrawal_seed: Option<String>,
        /// Immutable 32-byte validator_id in hex
        #[arg(long)]
        validator_id: String,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into the PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// Delegate stake to a validator (SysCallDelegate)
    Delegate {
        /// Delegator Falcon-512 key file
        #[arg(long)]
        falcon_key_file: Option<PathBuf>,
        /// Delegator Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        falcon_seed: Option<String>,
        /// Target 32-byte validator_id in hex
        #[arg(long)]
        validator_id: String,
        /// Amount to delegate in nano-STELL
        #[arg(long)]
        amount: u64,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into the PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// Begin unbonding a delegation (SysCallBeginUndelegate)
    BeginUndelegate {
        /// Delegator Falcon-512 key file
        #[arg(long)]
        falcon_key_file: Option<PathBuf>,
        /// Delegator Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        falcon_seed: Option<String>,
        /// Target 32-byte validator_id in hex
        #[arg(long)]
        validator_id: String,
        /// Amount to undelegate in nano-STELL
        #[arg(long)]
        amount: u64,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into the PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// Withdraw matured delegation unbonding (SysCallUndelegate)
    WithdrawDelegation {
        /// Delegator Falcon-512 key file
        #[arg(long)]
        falcon_key_file: Option<PathBuf>,
        /// Delegator Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        falcon_seed: Option<String>,
        /// Target 32-byte validator_id in hex
        #[arg(long)]
        validator_id: String,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into the PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// Claim validator rewards (SysCallClaimRewards) or delegator rewards (--delegator, SysCallClaimDelegatorRewards)
    ClaimRewards {
        /// Signer Falcon-512 key file (cold withdrawal key for validator, or delegator key with --delegator)
        #[arg(long)]
        withdrawal_key_file: Option<PathBuf>,
        /// Signer Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        withdrawal_seed: Option<String>,
        /// Target 32-byte validator_id in hex
        #[arg(long)]
        validator_id: String,
        /// Claim delegator rewards instead of validator rewards
        #[arg(long, default_value_t = false)]
        delegator: bool,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into the PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
    /// Re-admit a downtime-jailed validator (SysCallUnjail, Ruleset v7 cold withdrawal key).
    ///
    /// Local preflight refuses a provably dead transaction before signing:
    /// `release_height` in the future (names the exact height/ETA), a record
    /// with no cold withdrawal_address (run claim-withdrawal first), or a zero
    /// withdrawal-address balance (fund it first — it cannot pay gas).
    /// `--dry-run` prints the same diagnosis but is never blocked.
    Unjail {
        /// Cold withdrawal Falcon-512 key file
        #[arg(long)]
        withdrawal_key_file: Option<PathBuf>,
        /// Cold withdrawal Falcon-512 seed in hex (32 bytes)
        #[arg(long)]
        withdrawal_seed: Option<String>,
        /// Immutable 32-byte validator_id in hex
        #[arg(long)]
        validator_id: String,
        /// Optional self-bond top-up in nano-STELL emitted before unjail
        #[arg(long)]
        top_up: Option<u64>,
        /// Optional gas limit override in nano-STELL (must cover base fee / D2 penalty floor)
        #[arg(long)]
        gas_limit: Option<u64>,
        /// JSON-RPC endpoint
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id bound into the PQ1 envelope
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when configured on the node
        #[arg(long)]
        token: Option<String>,
    },
}
#[derive(Subcommand)]
pub(crate) enum WalletCommands {
    /// Generate a fresh Stellereum keypair, viewing key, and stealth address
    Generate,
    /// Inspect account balance and nonce
    Balance {
        /// 32-byte account address in hex format
        #[arg(short, long)]
        address: String,
    },
    /// Print the account address (public key) for a private key.
    ///
    /// The account address is the public key, not the private key, so deriving
    /// it by hand is a reliable way to fund the wrong account and then wonder
    /// why every transaction is rejected for insufficient balance.
    Address {
        /// 32-byte Ed25519 private key (seed) in hex
        #[arg(long)]
        from_key: String,
    },
    /// Send standard STELL transfer
    Send {
        /// Sender Ed25519 private key in hex
        #[arg(long)]
        from_key: String,
        /// Recipient 32-byte address in hex
        #[arg(long)]
        to: String,
        /// Transfer amount in nano-STELL (1 STELL = 1_000_000_000 nano-STELL)
        #[arg(long)]
        amount: u64,
        /// Target shard ID (0 = Masterchain, 1 = Base Workchain).
        /// Defaults to same-shard: cross-shard needs an explicit flag.
        #[arg(long, default_value_t = 0)]
        target_shard: u32,
        /// JSON-RPC endpoint to submit to
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit nonce; by default the account's current nonce is queried
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id to bind the transaction signature to. Omitted: query
        /// `stell_chainId`; while chain binding is not scheduled an
        /// unreachable RPC keeps the legacy unbound signature, once scheduled
        /// an explicit id is required (fail-closed).
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting it
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Print the raw JSON-RPC responses
        #[arg(long, default_value_t = false)]
        verbose: bool,
    },
    /// Send a post-quantum STELL transfer (Falcon-512, PQ1 explicit envelope).
    ///
    /// The ONLY transfer command that verifies when `STELL_PURE_PQ=1` (live +
    /// local-cluster): plain `wallet send` builds legacy ed25519 txs, which
    /// pure-PQ nodes refuse with `invalid transaction signature`.
    /// The Falcon-512 keypair is derived from `--falcon-seed-file`,
    /// `STELL_FALCON_SEED`, or `--falcon-seed` with the SAME raw derivation
    /// `Faucet::new` uses (`generate_from_seed_bytes`, no wallet KDF), so
    /// passing the shared faucet seed spends the genesis-funded faucet PQ
    /// account. The tx shape is byte-identical to a faucet drip
    /// (`sign_pq_explicit_transfer`: unbound, always-explicit, base fee +
    /// activation surcharge) — it fits the existing verifier, no consensus
    /// change. Fail-closed: a bad seed is refused here, never silently
    /// downgraded to an ed25519 (or unsigned) transaction.
    /// Key-derivation caveat: the derivation is strict-only (LEAD: no
    /// legacy branch) — the funded account is always the address this
    /// derivation produces; a mismatched seed means the node refuses for
    /// insufficient balance.
    SendPq {
        /// Falcon-512 seed in hex (32 bytes, dev/test only; prefer --falcon-seed-file or STELL_FALCON_SEED).
        #[arg(long)]
        falcon_seed: Option<String>,
        /// Path to a file containing the 32-byte Falcon-512 hex seed (preferred over --falcon-seed).
        #[arg(long)]
        falcon_seed_file: Option<PathBuf>,
        /// Recipient 32-byte address in hex
        #[arg(long)]
        to: String,
        /// Transfer amount in nano-STELL (1 STELL = 1_000_000_000 nano-STELL)
        #[arg(long)]
        amount: u64,
        /// Target shard ID (0 = Masterchain, 1 = Base Workchain).
        /// Defaults to same-shard: cross-shard needs an explicit flag.
        #[arg(long, default_value_t = 0)]
        target_shard: u32,
        /// JSON-RPC endpoint to submit to
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit nonce; by default the account's current nonce is queried
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id to bind the transaction signature to. Omitted: query
        /// `stell_chainId`; while chain binding is not scheduled an
        /// unreachable RPC keeps the legacy unbound signature, once scheduled
        /// an explicit id is required (fail-closed).
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting it
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Print the raw JSON-RPC responses
        #[arg(long, default_value_t = false)]
        verbose: bool,
    },
    /// Re-admit a downtime-jailed validator (SysCallUnjail, pentest F7 / Ruleset v7)
    ///
    /// Signs ONE PQ transaction carrying an optional `SysCallStake` top-up
    /// followed by `SysCallUnjail`, and submits it to a node. Under Ruleset v7
    /// the validator's cold `withdrawal_address` signs to unjail `validator_id`.
    ///
    /// Same local release-height / withdrawal-balance preflight as
    /// `validator unjail`: a provably dead transaction is refused before
    /// signing (diagnosed but allowed under `--dry-run`). A missing cold
    /// withdrawal_address is diagnosed but still allowed here, because this
    /// legacy command is also the pre-W3 path where the validator id signs.
    Unjail {
        /// Falcon-512 seed in hex (32 bytes) of the signing key (cold withdrawal or pre-W3 validator key)
        #[arg(long)]
        falcon_seed: Option<String>,
        /// Falcon-512 key file of the signing key
        #[arg(long)]
        falcon_key_file: Option<PathBuf>,
        /// Validator address/id in hex. Defaults to the signer's own address.
        #[arg(long)]
        validator: Option<String>,
        /// Optional self-bond top-up in nano-STELL (1 STELL = 1e9 nano).
        /// Emitted BEFORE the unjail in the same payload; it must satisfy the
        /// same governed minimum as any `SysCallStake`.
        #[arg(long)]
        top_up: Option<u64>,
        /// Optional gas limit override in nano-STELL (must cover base fee / D2 penalty floor)
        #[arg(long)]
        gas_limit: Option<u64>,
        /// JSON-RPC endpoint to submit to
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit nonce; by default the account's current nonce is queried
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id to bind the transaction signature to (see `wallet send`).
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting it
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Print the raw JSON-RPC responses
        #[arg(long, default_value_t = false)]
        verbose: bool,
        /// Write-API token, when the node has one configured
        #[arg(long)]
        token: Option<String>,
    },
    /// Delegate Session Key for autonomous AI trading bots
    DelegateSession {
        /// Master Ed25519 private key in hex
        #[arg(long)]
        master_key: String,
        /// Bot session public key in hex
        #[arg(long)]
        session_pub: String,
        /// Maximum gas budget in nano-STELL
        #[arg(long, default_value_t = 50_000)]
        max_gas: u64,
        /// Duration of delegation in seconds
        #[arg(long, default_value_t = 3600)]
        duration_secs: u64,
        /// Scope bitmask (bit 0 = plain transfers, bit 1 = SVM payloads;
        /// default = everything)
        #[arg(long, default_value_t = u64::MAX)]
        scope: u64,
        /// Maximum native amount (nano-STELL) per transaction under this grant
        #[arg(long, default_value_t = u64::MAX)]
        max_value: u64,
        /// Chain id the grant is minted for (bound into the master's signature)
        #[arg(long, default_value_t = stellereum::zkml::DEFAULT_CHAIN_ID)]
        chain_id: u64,
        /// JSON-RPC endpoint to submit to
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce; by default the account's nonce is queried
        #[arg(long)]
        nonce: Option<u64>,
        /// Only print the signed transaction instead of submitting it
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when the node has one configured
        #[arg(long)]
        token: Option<String>,
    },
    /// Sign an arbitrary message with the WALLET SIGNATURE STANDARD
    /// (docs/WALLET_SIGNING.md): EIP-191-style preimage with the chain id
    /// bound in. Produces the standard envelope (version + scheme + pubkey +
    /// signature, hex). The wallet signs LOCALLY — the key never leaves this
    /// machine. Never confused with a transaction signature.
    Sign {
        /// Classical Ed25519 seed in hex. REMOVED: this flag is refused with
        /// a migration error (use `--falcon-key-file`/`--falcon-seed`).
        #[arg(long)]
        from_key: Option<String>,
        /// Signature scheme: `falcon` (the only accepted value; `ed25519`
        /// and `hybrid` are REMOVED and refused by name).
        #[arg(long, default_value = "falcon")]
        scheme: String,
        /// Falcon-512 key file (as written by `keys init`). Required unless
        /// `--falcon-seed` is given.
        #[arg(long)]
        falcon_key_file: Option<PathBuf>,
        /// Falcon-512 seed in hex (32 bytes, deterministic — for dev/test
        /// reproducibility; a stored key file is preferred for real wallets).
        #[arg(long)]
        falcon_seed: Option<String>,
        /// Message to sign (UTF-8). Exactly one of `--message` / `--message-hex`.
        #[arg(long)]
        message: Option<String>,
        /// Message to sign (hex bytes). Exactly one of `--message` / `--message-hex`.
        #[arg(long)]
        message_hex: Option<String>,
        /// Chain id the signature is bound to (default: this deployment's).
        #[arg(long, default_value_t = stellereum::zkml::DEFAULT_CHAIN_ID)]
        chain_id: u64,
    },
    /// Verify a WALLET SIGNATURE STANDARD envelope against an address, a
    /// message and a chain id. Prints VALID or INVALID (exit non-zero when
    /// invalid, so scripts can gate on it). No key needed, no network needed.
    Verify {
        /// Claimed signer address (32-byte hex).
        #[arg(long)]
        address: String,
        /// Message that was signed (UTF-8). Exactly one of `--message` / `--message-hex`.
        #[arg(long)]
        message: Option<String>,
        /// Message that was signed (hex bytes).
        #[arg(long)]
        message_hex: Option<String>,
        /// Standard envelope (hex) as produced by `wallet sign`.
        #[arg(long)]
        signature: String,
        /// Chain id the signature is checked against (default: this deployment's).
        #[arg(long, default_value_t = stellereum::zkml::DEFAULT_CHAIN_ID)]
        chain_id: u64,
    },
    /// Sign STRUCTURED contract-call data (EIP-712-style readable signing):
    /// the canonical JSON of `{contract, method, args, value, nonce, chain_id}`
    /// is displayed AND signed, so the user sees exactly what they authorize.
    SignTypedData {
        /// Classical Ed25519 seed in hex. REMOVED: this flag is refused with
        /// a migration error (use `--falcon-key-file`/`--falcon-seed`).
        #[arg(long)]
        from_key: Option<String>,
        /// Signature scheme: `falcon` (the only accepted value; `ed25519`
        /// and `hybrid` are REMOVED and refused by name).
        #[arg(long, default_value = "falcon")]
        scheme: String,
        /// Falcon-512 key file. Required unless `--falcon-seed` is given.
        #[arg(long)]
        falcon_key_file: Option<PathBuf>,
        /// Falcon-512 seed in hex (32 bytes, deterministic).
        #[arg(long)]
        falcon_seed: Option<String>,
        /// Contract address (32-byte hex).
        #[arg(long)]
        contract: String,
        /// Contract method name.
        #[arg(long)]
        method: String,
        /// Method arguments as a JSON value (default: null).
        #[arg(long)]
        args: Option<String>,
        /// Native value attached, in nano-STELL (default: 0).
        #[arg(long, default_value_t = 0)]
        value: u64,
        /// Sender nonce (default: 0).
        #[arg(long, default_value_t = 0)]
        nonce: u64,
        /// Chain id the call is authorized for (default: this deployment's).
        #[arg(long, default_value_t = stellereum::zkml::DEFAULT_CHAIN_ID)]
        chain_id: u64,
    },
    /// Verify a typed-data signature. Prints VALID or INVALID (exit non-zero
    /// when invalid). The caller passes the STRUCTURED fields (what the user
    /// was shown); the canonical JSON is re-encoded locally before checking.
    VerifyTypedData {
        /// Claimed signer address (32-byte hex).
        #[arg(long)]
        address: String,
        /// Contract address (32-byte hex).
        #[arg(long)]
        contract: String,
        /// Contract method name.
        #[arg(long)]
        method: String,
        /// Method arguments as a JSON value (default: null).
        #[arg(long)]
        args: Option<String>,
        /// Native value attached, in nano-STELL (default: 0).
        #[arg(long, default_value_t = 0)]
        value: u64,
        /// Sender nonce (default: 0).
        #[arg(long, default_value_t = 0)]
        nonce: u64,
        /// Chain id the call was authorized for (default: this deployment's).
        #[arg(long, default_value_t = stellereum::zkml::DEFAULT_CHAIN_ID)]
        chain_id: u64,
        /// Standard envelope (hex) as produced by `wallet sign-typed-data`.
        #[arg(long)]
        signature: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum KeysCommands {
    /// Generate node keys if missing (identity/e2e via
    /// `load_or_generate_node_keys`, Falcon-512 via
    /// `load_or_generate_falcon_key`) and print the NODE IDENTITY line.
    ///
    /// Idempotent: existing keys are loaded, never overwritten.
    Init {
        /// Directory holding identity.key / e2e.key (created 0700 if missing)
        #[arg(long, default_value = "./keys")]
        keys_dir: PathBuf,
        /// Falcon key file. Defaults to `$STELL_FALCON_KEY_FILE`, else
        /// `<keys-dir>/falcon.key` (the same default `run` uses).
        #[arg(long)]
        falcon_file: Option<PathBuf>,
    },
    /// Print the peer-stanza (node-id / ed-pub / x-pub / falcon-pub) for the
    /// new node, ready for the network admin to feed to
    /// `scripts/add-peer.sh`. Keys must already exist (see `keys init`).
    PeerStanza {
        /// Directory holding identity.key / e2e.key
        #[arg(long, default_value = "./keys")]
        keys_dir: PathBuf,
        /// Falcon key file (same default rule as `keys init`)
        #[arg(long)]
        falcon_file: Option<PathBuf>,
        /// Peer name the admin will see in their node.yaml
        #[arg(long, default_value = "new-node")]
        name: String,
        /// Public endpoint other nodes dial (IP:port, UDP/QUIC)
        #[arg(long, default_value = "REPLACE_WITH_PUBLIC_IP:9410")]
        endpoint: String,
    },
    /// Rotate the Falcon-512 validator key to a COMPLETE FIPS 206 (FN-DSA)
    /// NTRU key and print the NEW validator address.
    ///
    /// AUDIT W6.1 (live-cluster key migration): every key written by the
    /// pre-FIPS-206 code is an INCOMPLETE NTRU key (it carries no `G`, the
    /// NTRU partner of `(f, g, F)`). Such keys still load and still sign —
    /// the partner is reconstructed in memory exactly as the reference
    /// implementation's key expansion does — so the upgrade does NOT force
    /// an address change and the live nodes keep their validator address.
    ///
    /// This command is the OPERATOR-side migration to a complete key: it
    /// generates a fresh `(f, g, F, G)` key with the authentic reference
    /// implementation and prints the new validator address. Re-staking under
    /// the new address is a SEPARATE, on-chain operation.
    ///
    /// The old key file is backed up next to it (`<file>.bak-<unix-ts>`) and
    /// `--force` is required when a key already exists, because rotation
    /// CHANGES the validator address.
    RotateFalcon {
        /// Directory holding the node keys (created 0700 if missing)
        #[arg(long, default_value = "./keys")]
        keys_dir: PathBuf,
        /// Falcon key file. Defaults to `$STELL_FALCON_KEY_FILE`, else
        /// `<keys-dir>/falcon.key` (the same default `run` uses).
        #[arg(long)]
        falcon_file: Option<PathBuf>,
        /// Required when a Falcon key already exists (rotation changes the
        /// validator address).
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

/// Resolve the Falcon key path the same way `run` does: explicit flag wins,
/// then `$STELL_FALCON_KEY_FILE`, then `<keys-dir>/falcon.key`.
pub(crate) fn resolve_falcon_path(keys_dir: &std::path::Path, flag: Option<PathBuf>) -> PathBuf {
    if let Some(p) = flag {
        return p;
    }
    if let Ok(env) = std::env::var("STELL_FALCON_KEY_FILE") {
        if !env.is_empty() {
            return PathBuf::from(env);
        }
    }
    keys_dir.join("falcon.key")
}

#[derive(Subcommand)]
pub(crate) enum OrderbookCommands {
    /// Read orderbook depth and best bid/ask FROM A NODE
    ///
    /// Queries the committed book over RPC. A fresh local book would print a
    /// market that exists on no node at all.
    Depth {
        /// Trading pair ID (1 = STELL/USDT, 2 = STELL/TON, 3 = STELL/GRAM)
        #[arg(short, long, default_value_t = 1)]
        pair: u32,
        /// JSON-RPC endpoint to query
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Submit a limit or market order
    ///
    /// Signs a wrapping transaction carrying `SysCallPlaceOrder` and submits
    /// it to a node's mempool. The order exists only when a proposer includes
    /// the transaction in a block - this command never touches a local book.
    Place {
        /// Trader Ed25519 private key in hex
        #[arg(long)]
        trader_key: String,
        /// Trading pair ID (1 = STELL/USDT, 2 = STELL/TON)
        #[arg(long, default_value_t = 1)]
        pair: u32,
        /// Side: "buy" or "sell"
        #[arg(long)]
        side: String,
        /// Order type: "limit" or "market"
        ///
        /// The SVM opcode has no market variant: a market order is expressed
        /// as a limit order at `--price` that crosses on arrival.
        #[arg(long, default_value = "limit")]
        order_type: String,
        /// Limit price in micro-USD (e.g. 250_000 = $0.25)
        #[arg(long, default_value_t = 250_000)]
        price: u64,
        /// Token amount in nano-STELL
        #[arg(long)]
        amount: u64,
        /// JSON-RPC endpoint to submit to
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce; by default the account's nonce is queried
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id to bind the transaction signature to (see `wallet send`).
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting it
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when the node has one configured
        #[arg(long)]
        token: Option<String>,
    },
    /// Cancel an active order (the opcode itself costs 100 nano-STELL of gas)
    Cancel {
        /// Trader Ed25519 private key in hex (only the owner may cancel)
        #[arg(long)]
        trader_key: String,
        /// Order ID to cancel
        #[arg(long)]
        order_id: u64,
        /// JSON-RPC endpoint to submit to
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce; by default the account's nonce is queried
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id to bind the transaction signature to (see `wallet send`).
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting it
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when the node has one configured
        #[arg(long)]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum OracleCommands {
    /// Publish a cryptographic price feed update
    ///
    /// Signs the feed AND the transaction that wraps it
    /// (`OpCode::SysCallSubmitPriceFeed`), then submits that transaction to a
    /// node. The price only becomes state when a proposer includes the
    /// transaction in a block - this command never writes state itself.
    Feed {
        /// Publisher Ed25519 private key in hex (signs the feed itself)
        #[arg(long)]
        key: String,
        /// Asset symbol (e.g. TON, GRAM, USDT)
        #[arg(long)]
        asset: String,
        /// Price in micro-USD (e.g. 5_000_000 = $5.00)
        #[arg(long)]
        price_micro: u64,
        /// Account that signs (and pays for) the wrapping transaction.
        /// Defaults to the publisher key, which then needs a funded account.
        #[arg(long)]
        from_key: Option<String>,
        /// JSON-RPC endpoint to submit to
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce; by default the account's nonce is queried
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id to bind the transaction signature to (see `wallet send`).
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting it
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when the node has one configured
        #[arg(long)]
        token: Option<String>,
    },
    /// Check oracle resolution status and circuit breaker
    Status {
        /// Asset symbol
        #[arg(long, default_value = "TON")]
        asset: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum BridgeCommands {
    /// Claim an incoming teleport deposit
    ///
    /// Signs ONE wrapping transaction carrying `SysCallBridge(Attest)` +
    /// `SysCallBridge(Deposit)` and submits it to a node. When a block
    /// includes it, `BridgeState::plan` checks the 2/3 relayer/validator
    /// quorum over `deposit_signing_message` and the committed source-tx
    /// replay set, and only then does `execute_payload` credit `amount` to
    /// the recipient through ordinary account/trie writes.
    Deposit {
        /// Source chain: ton, arbitrum, ethereum, solana
        #[arg(long, default_value = "ton")]
        chain: String,
        /// Recipient Stellereum address in hex
        #[arg(long)]
        recipient: String,
        /// Amount in nano-STELL
        #[arg(long, default_value_t = 10_000_000_000_000)]
        amount: u64,
        /// Source-chain transaction hash being claimed (32-byte hex).
        ///
        /// The replay key settlement dedups on: one credit per hash, network
        /// wide, forever. Defaults to a deterministic hash of the intent, which
        /// is unique per claim but is NOT a real source-chain hash - supply
        /// the real one for a claim the watcher saw.
        #[arg(long)]
        source_tx_hash: Option<String>,
        /// Account that signs (and pays for) the wrapping transaction
        #[arg(long)]
        from_key: String,
        /// Validator/relayer seed (32-byte hex) that attests this claim.
        ///
        /// Repeat once per bonded validator you hold. When omitted, the local
        /// stand's node key in `--attest-keys-dir` is used. The quorum is
        /// `(n*2+2)/3` DISTINCT signers of the committed staking set, so
        /// anything short of it is refused by every block.
        #[arg(long = "attest-key")]
        attest_key: Vec<String>,
        /// Directory holding the local stand's node keys (identity.key),
        /// used when no `--attest-key` was given
        #[arg(long, default_value = "./keys")]
        attest_keys_dir: String,
        /// JSON-RPC endpoint to submit to
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce; by default the account's nonce is queried
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id to bind the transaction signature to (see `wallet send`).
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting it
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when the node has one configured
        #[arg(long)]
        token: Option<String>,
    },
    /// Request a bridge withdrawal
    ///
    /// The intent is signed, carried and admitted; at settlement the §8
    /// policy debits the sender into `BRIDGE_ESCROW`, queues the request
    /// (a one-hour time-lock at/above the large-withdrawal threshold) and
    /// counts it against the hourly rate window on the BLOCK clock.
    Withdraw {
        /// Target chain: ton, arbitrum, ethereum, solana
        #[arg(long, default_value = "arbitrum")]
        chain: String,
        /// External destination address
        #[arg(long)]
        target_address: String,
        /// Amount in nano-STELL
        #[arg(long, default_value_t = 1_000_000_000_000)]
        amount: u64,
        /// Account that signs (and pays for) the wrapping transaction
        #[arg(long)]
        from_key: String,
        /// JSON-RPC endpoint to submit to
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Explicit sender nonce; by default the account's nonce is queried
        #[arg(long)]
        nonce: Option<u64>,
        /// Chain id to bind the transaction signature to (see `wallet send`).
        #[arg(long)]
        chain_id: Option<u64>,
        /// Only print the signed transaction instead of submitting it
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when the node has one configured
        #[arg(long)]
        token: Option<String>,
    },
}

#[cfg(test)]
mod cli_safety_init_tests {
    use super::*;

    #[test]
    fn cli_parses_status_and_gates_subcommands() {
        let cli = Cli::try_parse_from(["stellereum", "status", "--json"]).expect("parse status");
        match cli.command {
            Commands::Status { rpc, json, expect } => {
                assert_eq!(rpc, "http://127.0.0.1:8545");
                assert!(json);
                assert_eq!(expect, None);
            }
            _ => panic!("unexpected command"),
        }
        let cli = Cli::try_parse_from(["stellereum", "gates", "--yaml"]).expect("parse gates");
        match cli.command {
            Commands::Gates { yaml } => assert!(yaml),
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn cli_parses_safety_reset_subcommand() {
        let cli = Cli::try_parse_from([
            "stellereum",
            "safety-reset",
            "--store-dir",
            "/tmp/store",
            "--i-fenced-all-signers",
        ])
        .expect("parse safety-reset");
        match cli.command {
            Commands::SafetyReset {
                store_dir,
                i_fenced_all_signers,
            } => {
                assert_eq!(store_dir, PathBuf::from("/tmp/store"));
                assert!(i_fenced_all_signers);
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn cli_parses_safety_init_subcommand() {
        let cli = Cli::try_parse_from([
            "stellereum",
            "safety-init",
            "--store-dir",
            "/tmp/store",
            "--keys-dir",
            "/tmp/keys",
            "--shard",
            "0",
            "--prevote-round-floor",
            "12",
            "--precommit-round-floor",
            "4",
            "--i-fenced-all-signers",
        ])
        .expect("parse safety-init");
        match cli.command {
            Commands::SafetyInit {
                store_dir,
                keys_dir,
                validator_pub,
                shard,
                prevote_round_floor,
                precommit_round_floor,
                i_fenced_all_signers,
            } => {
                assert_eq!(store_dir, PathBuf::from("/tmp/store"));
                assert_eq!(keys_dir, PathBuf::from("/tmp/keys"));
                assert_eq!(validator_pub, None);
                assert_eq!(shard, 0);
                assert_eq!(prevote_round_floor, Some(12));
                assert_eq!(precommit_round_floor, Some(4));
                assert!(i_fenced_all_signers);
            }
            _ => panic!("expected SafetyInit command"),
        }
    }

    #[test]
    fn cli_parses_gov_and_validator_subcommands() {
        let gov_cli = Cli::try_parse_from([
            "stellereum",
            "gov",
            "propose",
            "--falcon-seed",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "--title",
            "Test Proposal",
            "--action",
            "signal",
            "--params",
            "{\"text\":\"hello\"}",
            "--dry-run",
        ])
        .expect("parse gov propose");
        assert!(matches!(
            gov_cli.command,
            Commands::Gov {
                sub: GovCommands::Propose { dry_run: true, .. }
            }
        ));

        let vote_cli = Cli::try_parse_from([
            "stellereum",
            "gov",
            "vote",
            "--falcon-key-file",
            "/tmp/falcon.key",
            "--id",
            "3",
            "--choice",
            "Yes",
        ])
        .expect("parse gov vote");
        assert!(matches!(
            vote_cli.command,
            Commands::Gov {
                sub: GovCommands::Vote { id: 3, .. }
            }
        ));

        let val_cli = Cli::try_parse_from([
            "stellereum",
            "validator",
            "claim-rewards",
            "--withdrawal-key-file",
            "/tmp/del.key",
            "--validator-id",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--delegator",
        ])
        .expect("parse validator claim-rewards");
        assert!(matches!(
            val_cli.command,
            Commands::Validator {
                sub: ValidatorCommands::ClaimRewards {
                    delegator: true,
                    ..
                }
            }
        ));

        let unjail_cli = Cli::try_parse_from([
            "stellereum",
            "wallet",
            "unjail",
            "--falcon-key-file",
            "/tmp/cold.key",
            "--validator",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--gas-limit",
            "650000",
        ])
        .expect("parse wallet unjail");
        assert!(matches!(
            unjail_cli.command,
            Commands::Wallet {
                sub: WalletCommands::Unjail {
                    falcon_key_file: Some(_),
                    falcon_seed: None,
                    gas_limit: Some(650_000),
                    ..
                }
            }
        ));

        let val_unjail_cli = Cli::try_parse_from([
            "stellereum",
            "validator",
            "unjail",
            "--withdrawal-key-file",
            "/tmp/cold.key",
            "--validator-id",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--gas-limit",
            "1300000",
        ])
        .expect("parse validator unjail");
        assert!(matches!(
            val_unjail_cli.command,
            Commands::Validator {
                sub: ValidatorCommands::Unjail {
                    gas_limit: Some(1_300_000),
                    ..
                }
            }
        ));

        let send_pq_cli = Cli::try_parse_from([
            "stellereum",
            "wallet",
            "send-pq",
            "--falcon-seed-file",
            "/tmp/faucet.seed",
            "--to",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--amount",
            "1000",
        ])
        .expect("parse wallet send-pq with --falcon-seed-file");
        assert!(matches!(
            send_pq_cli.command,
            Commands::Wallet {
                sub: WalletCommands::SendPq {
                    falcon_seed: None,
                    falcon_seed_file: Some(_),
                    amount: 1000,
                    ..
                }
            }
        ));
    }

    #[test]
    fn cli_parses_run_node_toml_no_telemetry_and_config_check() {
        let run_cli = Cli::try_parse_from([
            "stellereum",
            "run",
            "-c",
            "infnode.yaml",
            "--node-toml",
            "/tmp/stellereum.toml",
            "-t",
        ])
        .expect("parse run with --node-toml and -t");
        match run_cli.command {
            Commands::Run {
                config,
                node_toml,
                no_telemetry,
                ..
            } => {
                assert_eq!(config, PathBuf::from("infnode.yaml"));
                assert_eq!(node_toml, Some(PathBuf::from("/tmp/stellereum.toml")));
                assert!(no_telemetry);
            }
            _ => panic!("expected Commands::Run"),
        }

        let run_long = Cli::try_parse_from(["stellereum", "run", "--no-telemetry"])
            .expect("parse run --no-telemetry");
        match run_long.command {
            Commands::Run {
                config,
                node_toml,
                no_telemetry,
                ..
            } => {
                assert_eq!(config, PathBuf::from("config.yaml"));
                assert_eq!(node_toml, None);
                assert!(no_telemetry);
            }
            _ => panic!("expected Commands::Run"),
        }

        let cfg_default =
            Cli::try_parse_from(["stellereum", "config", "check"]).expect("parse config check");
        assert!(matches!(
            cfg_default.command,
            Commands::Config {
                sub: ConfigCommands::Check {
                    file: None,
                    json: false,
                }
            }
        ));

        let cfg_flags = Cli::try_parse_from([
            "stellereum",
            "config",
            "check",
            "--file",
            "/etc/stellereum/node.toml",
            "--json",
        ])
        .expect("parse config check --file --json");
        match cfg_flags.command {
            Commands::Config {
                sub: ConfigCommands::Check { file, json },
            } => {
                assert_eq!(file, Some(PathBuf::from("/etc/stellereum/node.toml")));
                assert!(json);
            }
            _ => panic!("expected Commands::Config"),
        }
    }

    #[test]
    fn cli_parses_store_bootstrap_defaults_and_flags() {
        let default_cli = Cli::try_parse_from(["stellereum", "store", "bootstrap"])
            .expect("parse store bootstrap defaults");
        match default_cli.command {
            Commands::Store {
                sub:
                    StoreCommands::Bootstrap {
                        data_dir,
                        keys_dir,
                        shard,
                        snapshot_url,
                        sha256_url,
                        require_sha256,
                        archive,
                        expected_sha256,
                        refresh_if_stale,
                        force,
                        no_backup,
                        i_fenced_all_signers,
                        observer,
                        dry_run,
                        json,
                    },
            } => {
                assert_eq!(data_dir, PathBuf::from("./data"));
                assert_eq!(keys_dir, PathBuf::from("./keys"));
                assert_eq!(shard, 0);
                assert_eq!(
                    snapshot_url,
                    "https://rpc.stellereum.org/snapshot/latest.tar.zst"
                );
                assert_eq!(sha256_url, None);
                assert!(!require_sha256);
                assert_eq!(archive, None);
                assert_eq!(expected_sha256, None);
                assert!(!refresh_if_stale);
                assert!(!force);
                assert!(!no_backup);
                assert!(!i_fenced_all_signers);
                assert!(!observer);
                assert!(!dry_run);
                assert!(!json);
            }
            _ => panic!("expected Commands::Store"),
        }

        let full_cli = Cli::try_parse_from([
            "stellereum",
            "store",
            "bootstrap",
            "--data-dir",
            "/var/lib/stell/data",
            "--keys-dir",
            "/var/lib/stell/keys",
            "--shard",
            "1",
            "--snapshot-url",
            "https://example.org/snap.tar.zst",
            "--sha256-url",
            "https://example.org/snap.tar.zst.sha256",
            "--require-sha256",
            "--archive",
            "/tmp/snap.tar.zst",
            "--expected-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--refresh-if-stale",
            "--force",
            "--no-backup",
            "--i-fenced-all-signers",
            "--observer",
            "--dry-run",
            "--json",
        ])
        .expect("parse store bootstrap with all flags");
        match full_cli.command {
            Commands::Store {
                sub:
                    StoreCommands::Bootstrap {
                        data_dir,
                        keys_dir,
                        shard,
                        snapshot_url,
                        sha256_url,
                        require_sha256,
                        archive,
                        expected_sha256,
                        refresh_if_stale,
                        force,
                        no_backup,
                        i_fenced_all_signers,
                        observer,
                        dry_run,
                        json,
                    },
            } => {
                assert_eq!(data_dir, PathBuf::from("/var/lib/stell/data"));
                assert_eq!(keys_dir, PathBuf::from("/var/lib/stell/keys"));
                assert_eq!(shard, 1);
                assert_eq!(snapshot_url, "https://example.org/snap.tar.zst");
                assert_eq!(
                    sha256_url.as_deref(),
                    Some("https://example.org/snap.tar.zst.sha256")
                );
                assert!(require_sha256);
                assert_eq!(archive, Some(PathBuf::from("/tmp/snap.tar.zst")));
                assert_eq!(
                    expected_sha256.as_deref(),
                    Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                );
                assert!(refresh_if_stale);
                assert!(force);
                assert!(no_backup);
                assert!(i_fenced_all_signers);
                assert!(observer);
                assert!(dry_run);
                assert!(json);
            }
            _ => panic!("expected Commands::Store"),
        }
    }
}
