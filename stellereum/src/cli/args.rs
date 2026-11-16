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
    /// The Falcon-512 keypair is derived from `--falcon-seed` with the SAME
    /// raw derivation `Faucet::new` uses (`generate_from_seed_bytes`, no
    /// wallet KDF), so passing the shared faucet seed spends the
    /// genesis-funded faucet PQ account. The tx shape is byte-identical to a
    /// faucet drip (`sign_pq_explicit_transfer`: unbound, always-explicit,
    /// base fee + activation surcharge) — it fits the existing verifier, no
    /// consensus change. Fail-closed: a bad seed is refused here, never
    /// silently downgraded to an ed25519 (or unsigned) transaction.
    /// Key-derivation caveat: the derivation is strict-only (LEAD: no
    /// legacy branch) — the funded account is always the address this
    /// derivation produces; a mismatched seed means the node refuses for
    /// insufficient balance.
    SendPq {
        /// Falcon-512 seed in hex (32 bytes). For the genesis-funded faucet
        /// account this is the shared `STELL_FAUCET_KEY` seed (dev only).
        #[arg(long)]
        falcon_seed: String,
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
        /// Only print the signed transaction instead of submitting it
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Print the raw JSON-RPC responses
        #[arg(long, default_value_t = false)]
        verbose: bool,
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
        /// Ed25519 seed in hex (32 bytes). Required for `ed25519`/`hybrid`.
        #[arg(long)]
        from_key: Option<String>,
        /// Signature scheme: `ed25519` (default), `falcon` or `hybrid`.
        #[arg(long, default_value = "ed25519")]
        scheme: String,
        /// Falcon-512 key file (as written by `keys init`). Required for
        /// `falcon`/`hybrid` unless `--falcon-seed` is given.
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
        /// Ed25519 seed in hex (32 bytes). Required for `ed25519`/`hybrid`.
        #[arg(long)]
        from_key: Option<String>,
        /// Signature scheme: `ed25519` (default), `falcon` or `hybrid`.
        #[arg(long, default_value = "ed25519")]
        scheme: String,
        /// Falcon-512 key file. Required for `falcon`/`hybrid` unless
        /// `--falcon-seed` is given.
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
        /// Only print the signed transaction instead of submitting it
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write-API token, when the node has one configured
        #[arg(long)]
        token: Option<String>,
    },
}
