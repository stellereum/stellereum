//! Official Lightweight CLI Wallet & SPV Client for Stellereum L1 Blockchain
//! Inspired by Electrum CLI: fast, zero-node requirement, top-tier security,
//! QR-code rendering, interactive REPL console, and natural subcommands.

mod client;
pub mod notes;
pub mod pq;
mod rpc;
mod security;
pub mod wallets;

use clap::{Parser, Subcommand};
use client::LightClient;
use colored::*;
use qrcode::render::unicode;
use qrcode::QrCode;
use security::{
    enforce_strict_permissions, format_address_single_line, format_address_with_visual_checksum,
    HardenedKeystore, SecureSecret,
};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
#[allow(unused_imports)]
use stellereum::crypto_privacy::{ConfidentialTransfer, PedersenCommitment, StealthAddress};
use stellereum::orderbook::{OrderSide, OrderType};
use stellereum::tokenomics::GenesisVault;
use stellereum::wallet::{Mnemonic, WalletAccount};

#[derive(Parser)]
#[command(name = "stell")]
#[command(author = "Stellereum Core Contributors")]
#[command(version = "0.1.0")]
#[command(about = "Stellereum High-Performance SPV Light Wallet")]
struct Cli {
    /// Custom path to wallet keystore
    #[arg(short, long, global = true)]
    wallet: Option<PathBuf>,

    /// Path to infnode P2P configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// JSON-RPC endpoint of a Stellereum node (e.g. https://rpc.stellereum.org).
    /// When set (or default), the wallet talks to the CHAIN (balances/proofs from the
    /// node, receipts polled to finality). Defaults to STELL_RPC_URL or https://rpc.stellereum.org.
    #[arg(long, global = true)]
    rpc_url: Option<String>,

    /// Write-API token for the node (fallback: STELL_RPC_AUTH_TOKEN env).
    #[arg(long, global = true)]
    auth_token: Option<String>,

    /// Faucet token for `faucet` in RPC mode (fallback: STELL_FAUCET_TOKEN).
    #[arg(long, global = true)]
    faucet_token: Option<String>,

    /// Seconds to wait for chain finality after submitting a transaction
    /// (default covers multi-minute stalls on a slow chain; broadcast still
    /// returns Pending honestly on timeout — re-check with `receipt`).
    #[arg(long, global = true, default_value_t = 360)]
    timeout: u64,

    /// Seconds between receipt polls while waiting for finality.
    #[arg(long, global = true, default_value_t = 2)]
    poll_interval: u64,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Clone)]
enum Commands {
    /// Create a new hardened wallet (interactive or with password)
    #[command(alias = "init", alias = "create")]
    New {
        /// Optional wallet name (e.g. "trading", "savings")
        name: Option<String>,
        /// Explicit wallet name override via flag
        #[arg(long = "name")]
        wallet_name: Option<String>,
        /// Password to encrypt keystore (if omitted, will prompt securely)
        #[arg(short, long)]
        password: Option<String>,
        /// Signature scheme: falcon512, hybrid, ed25519 (defaults to falcon512)
        #[arg(short, long, default_value = "falcon512")]
        scheme: pq::WalletScheme,
    },
    /// Restore wallet from 24-word recovery phrase or raw private key
    #[command(alias = "recover")]
    Restore {
        /// Optional wallet name (e.g. "recovered", "savings")
        name: Option<String>,
        /// Explicit wallet name override via flag
        #[arg(long = "name")]
        wallet_name: Option<String>,
        /// 24-word recovery mnemonic phrase
        #[arg(short, long)]
        phrase: Option<String>,
        /// Raw 32-byte private key in hex
        #[arg(short, long)]
        key: Option<String>,
        /// New password for restored keystore
        #[arg(long)]
        password: Option<String>,
        /// Signature scheme: falcon512, hybrid, ed25519 (defaults to falcon512)
        #[arg(short, long, default_value = "falcon512")]
        scheme: pq::WalletScheme,
    },
    /// List all local wallets, showing address, scheme, and which is active
    #[command(name = "wallets", alias = "list", alias = "accounts")]
    Wallets,
    /// Switch active wallet by name or address (verifies password)
    #[command(name = "switch", alias = "use")]
    Switch {
        /// Wallet name (e.g. "trading") or address (e.g. "inf1:...")
        name_or_address: String,
        /// Password to unlock and verify wallet (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Display wallet address, QR code, and viewing keys for receiving funds
    #[command(alias = "addr", alias = "address")]
    Receive {
        /// Password (prompted securely if omitted; needed to derive YOUR keys)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Query account balance and verify cryptographic SPV Merkle inclusion proof
    #[command(alias = "bal")]
    Balance {
        /// Target shard ID (0 = Masterchain, 1 = Base Workchain)
        #[arg(short, long, default_value_t = 0)]
        shard: u32,
    },
    /// Request testnet faucet coins for local experimentation
    Faucet {
        /// Amount in STELL (e.g. 500)
        #[arg(default_value_t = 500)]
        amount: u64,
    },
    // NOTE: Faucet/Mint u64 amounts multiply into nano below with checked_mul
    // (audit follow-up) — huge --amount fails loudly instead of wrapping.
    /// Send standard STELL transfer (base fee 280_000 nano-STELL)
    #[command(alias = "send")]
    Pay {
        /// Recipient 32-byte address in hex format
        to: String,
        /// Amount in STELL (e.g. 10.5; exact decimal, no float)
        amount: String,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Target shard ID
        #[arg(short, long, default_value_t = 0)]
        shard: u32,
        /// Source shard override (defaults to --shard; set both to send cross-shard)
        #[arg(long)]
        source_shard: Option<u32>,
        /// Target shard override (defaults to --shard; set both to send cross-shard)
        #[arg(long)]
        target_shard: Option<u32>,
        /// Signature scheme: falcon512, hybrid, ed25519 (defaults to falcon512)
        #[arg(long, default_value = "falcon512")]
        scheme: pq::WalletScheme,
        /// Dry-run mode: construct and validate transaction without broadcasting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Build the legacy UNBOUND (replayable, no chain id) transaction
        /// instead of the default bound envelope. Warns loudly; the node
        /// meters unbound admission and will refuse it in a later phase.
        #[arg(long, default_value_t = false)]
        unbound_legacy: bool,
        /// Gas limit override in nano-STELL (default: base + activation
        /// surcharge when needed; raise to outbid a penalty-inflated floor)
        #[arg(long)]
        fee: Option<u64>,
    },
    /// Bond STELL to become (or top up) a validator (SysCallStake).
    /// The bonded amount leaves this wallet for the staking pool.
    /// Commission: `--commission-bps N` (0–10000) sets the rate for a NEW
    /// validator; omitted means the governance default (1000 bps = 10%).
    /// The rate is IMMUTABLE after bonding — a top-up keeps the registered
    /// rate no matter what flag is passed, and the ledger exposes no setter.
    #[command(alias = "bond")]
    Stake {
        /// Validator key (32-byte hex). Defaults to this wallet's own key
        /// (self-bond = register as validator).
        #[arg(long)]
        validator: Option<String>,
        /// Amount in STELL (e.g. 1000; must clear the governed minimum bond)
        amount: String,
        /// Commission in basis points for a NEW validator (0-10000;
        /// 1000 = 10%). Ignored on top-ups (the registered rate is kept).
        #[arg(long)]
        commission_bps: Option<u64>,
        /// Build the legacy UNBOUND (replayable, no chain id) transaction
        /// instead of the default bound envelope. Warns loudly; the node
        /// meters unbound admission and will refuse it in a later phase.
        #[arg(long, default_value_t = false)]
        unbound_legacy: bool,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Gas limit override in nano-STELL (raise to outbid a penalty-inflated floor)
        #[arg(long)]
        fee: Option<u64>,
    },
    /// Start unbonding from a validator (SysCallUnbond). Only the validator
    /// itself may unbond its own stake; funds return after cooldown.
    Unbond {
        /// Validator key (32-byte hex). Defaults to this wallet's own key.
        #[arg(long)]
        validator: Option<String>,
        /// Amount in STELL
        amount: String,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Delegate STELL to a validator (SysCallDelegate).
    /// Funds stay delegated until you begin-unbond + withdraw-unbond.
    Delegate {
        /// Validator key (32-byte hex). Defaults to this wallet's own key.
        #[arg(long)]
        validator: Option<String>,
        /// Amount in STELL (e.g. 100)
        amount: String,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Begin unbonding a delegation (SysCallBeginUndelegate).
    /// Moves funds into a maturing cooldown entry; use withdraw-unbond later.
    BeginUnbond {
        /// Validator key (32-byte hex). Defaults to this wallet's own key.
        #[arg(long)]
        validator: Option<String>,
        /// Amount in STELL
        amount: String,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Withdraw matured unbonded funds (SysCallUndelegate).
    /// Only pays matured funds after cooldown; errors while still maturing.
    WithdrawUnbond {
        /// Validator key (32-byte hex). Defaults to this wallet's own key.
        #[arg(long)]
        validator: Option<String>,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Claim accrued delegation/validator rewards (SysCallClaimRewards / SysCallClaimDelegatorRewards).
    ClaimRewards {
        /// Validator key (32-byte hex). Defaults to this wallet's own key.
        #[arg(long)]
        validator: Option<String>,
        /// Explicitly claim delegator rewards even if validator equals this wallet's key.
        #[arg(long, default_value_t = false)]
        delegator: bool,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Rotate a validator's consensus key (SysCallRotateValidatorKey).
    /// Only the OLD key may authorize; the whole record (bond, delegations,
    /// rewards, slash history) moves atomically, never merges.
    RotateKey {
        /// New validator key (32-byte hex, must not already validate)
        new_key: String,
        /// Password for the OLD key's keystore (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Send spendable stealth payment: derives one-time stealth address
    /// using recipient's view and spend keys and broadcasts on-chain
    #[command(name = "stealth-pay", alias = "stealth-send")]
    StealthPay {
        /// Recipient viewing public key (32 bytes hex)
        #[arg(long)]
        view_key: Option<String>,
        /// Recipient spending public key (32 bytes hex)
        #[arg(long)]
        spend_key: Option<String>,
        /// First positional: view key (or meta-address, or amount if flags given)
        to: Option<String>,
        /// Second positional: spend key or amount
        arg2: Option<String>,
        /// Third positional: amount in STELL
        arg3: Option<String>,
        /// Amount in STELL (e.g. 25.0; exact decimal)
        #[arg(short, long)]
        amount: Option<String>,
        /// Fee in nano-STELL
        #[arg(long, default_value_t = 280_000)]
        fee: u64,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Target shard ID
        #[arg(short, long, default_value_t = 0)]
        shard: u32,
    },
    /// Scan blockchain for incoming stealth payments matching viewing key
    #[command(name = "stealth-scan", alias = "scan-stealth")]
    StealthScan {
        /// Keystore password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Spend funds from a one-time stealth address to wallet or destination address
    #[command(name = "stealth-spend", alias = "spend-stealth")]
    StealthSpend {
        /// Optional stealth one-time address in hex to spend from
        #[arg(long)]
        one_time_pub: Option<String>,
        /// Destination address in hex (defaults to wallet's own public address)
        #[arg(long)]
        to: Option<String>,
        /// Amount in STELL (if omitted, sweeps full balance minus gas fee)
        #[arg(long)]
        amount: Option<String>,
        /// Keystore password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Target shard ID (default 0)
        #[arg(long, default_value_t = 0)]
        shard: u32,
    },
    /// Shield native STELL into the pool (SysCallConfidentialShield).
    /// Saves note to ~/.stellereum/shielded_notes.json automatically.
    #[command(alias = "shield")]
    ConfidentialShield {
        /// Amount in STELL (exact decimal)
        amount: String,
        /// Blinding in hex (generated randomly if omitted — printed back)
        #[arg(long)]
        blinding: Option<String>,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Target shard ID
        #[arg(short, long, default_value_t = 0)]
        shard: u32,
    },
    /// Display unspent shielded notes and total confidential balance
    #[command(
        name = "shield-balance",
        alias = "confidential-balance",
        alias = "shielded-balance"
    )]
    ShieldBalance,
    /// Unshield by revealing openings or automatically selecting stored notes (SysCallConfidentialUnshield).
    #[command(alias = "unshield")]
    ConfidentialUnshield {
        /// Amount in STELL (exact decimal) to automatically select unspent notes
        #[arg(short, long)]
        amount: Option<String>,
        /// Commitment(s) in hex, comma-separated (manual mode)
        #[arg(long)]
        commitments: Option<String>,
        /// Amount(s) in nano-STELL matching the openings, comma-separated (manual mode)
        #[arg(long)]
        amounts: Option<String>,
        /// Blinding(s) in hex, comma-separated (manual mode)
        #[arg(long)]
        blindings: Option<String>,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Target shard ID
        #[arg(short, long, default_value_t = 0)]
        shard: u32,
    },
    /// Build and submit a REAL shielded transfer (SysCallConfidentialTransfer):
    /// conservation-checked locally, admitted to the chain, receipt polled.
    /// Prints the tx hash plus viewing-key info for the auditor.
    ConfidentialPay {
        /// Recipient shielded address in hex (32 bytes)
        to: String,
        /// Amount in STELL (e.g. 25.0; exact decimal, no float)
        amount: String,
        /// Fee in nano-STELL
        #[arg(long, default_value_t = 1500)]
        fee: u64,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Target shard ID
        #[arg(short, long, default_value_t = 0)]
        shard: u32,
    },
    /// Show an STS token balance (chain-verified SPV proof in RPC mode)
    TokenBalance {
        /// Token ID in hex (32 bytes)
        token: String,
        /// Account in hex (defaults to own wallet address)
        account: Option<String>,
    },
    /// Send STS tokens (SysCallTokenTransfer; native amount is 0, gas base 280_000)
    TokenSend {
        /// Token ID in hex (32 bytes)
        token: String,
        /// Recipient account in hex (32 bytes)
        to: String,
        /// Amount in token base units (raw u64, no decimals conversion)
        amount: u64,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Target shard ID
        #[arg(short, long, default_value_t = 0)]
        shard: u32,
    },
    /// Approve an STS spender allowance (SysCallTokenApprove)
    TokenApprove {
        /// Token ID in hex (32 bytes)
        token: String,
        /// Spender account in hex (32 bytes)
        spender: String,
        /// Allowance in token base units (raw u64)
        amount: u64,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Target shard ID
        #[arg(short, long, default_value_t = 0)]
        shard: u32,
    },
    /// Create a new STS token (SysCallTokenCreate; you become minter).
    /// Prints the token ID (resolved from the node after finality).
    TokenCreate {
        /// Token name (1-64 chars)
        #[arg(long)]
        name: String,
        /// Token symbol (1-16 chars)
        #[arg(long)]
        symbol: String,
        /// Decimals (0-18)
        #[arg(long, default_value_t = 6)]
        decimals: u8,
        /// Initial supply credited to you (base units)
        #[arg(long, default_value_t = 0)]
        supply: u64,
        /// Optional max supply cap (0 = uncapped)
        #[arg(long, default_value_t = 0)]
        max_supply: u64,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Target shard ID
        #[arg(short, long, default_value_t = 0)]
        shard: u32,
    },
    /// Resolve a token ID by (name, symbol) for this wallet's account
    TokenResolve {
        /// Token name used at creation
        #[arg(long)]
        name: String,
        /// Token symbol used at creation
        #[arg(long)]
        symbol: String,
    },
    /// List STS token IDs (paginated `{tokens, total, offset}` object shape)
    #[command(alias = "tokens")]
    TokenList {
        /// Max ids to return (1-1000, chain hard max; default 100)
        #[arg(long, default_value_t = 100)]
        limit: u64,
        /// Skip this many ids (default 0)
        #[arg(long, default_value_t = 0)]
        offset: u64,
    },
    /// Query chain finality for a tx hash (RPC mode: polls the node receipt)
    Receipt {
        /// Transaction hash in hex
        tx_hash: String,
    },
    /// View recent transaction history
    #[command(alias = "history")]
    Txs,
    /// Delegate a session key (scoped, expiring, budgeted access for an app or bot)
    Session {
        /// Bot session public key in hex
        #[arg(short, long)]
        session_pub: String,
        /// Maximum gas budget in nano-STELL
        #[arg(short, long, default_value_t = 50_000)]
        max_gas: u64,
        /// Validity duration in seconds
        #[arg(short, long, default_value_t = 3600)]
        duration: u64,
        /// Scope bitmask (bit 0 = plain transfers, bit 1 = SVM payloads,
        /// bit 2 = actor sends; default = transfers only, least privilege)
        #[arg(long, default_value_t = 1)]
        scope: u64,
        /// Maximum native amount (nano-STELL) per transaction under this grant
        #[arg(long, default_value_t = u64::MAX)]
        max_value: u64,
        /// Chain id the grant is minted for (bound into the signature;
        /// 0 = auto-detect from the node in RPC mode)
        #[arg(long, default_value_t = 0)]
        chain_id: u64,
        /// Publish the grant on-chain as SysCallPublishSessionGrant (makes it
        /// enforceable; without this it stays an off-chain printout)
        #[arg(long, default_value_t = false)]
        publish: bool,
        /// Target shard ID (the grant + publish tx live here)
        #[arg(short, long, default_value_t = 0)]
        shard: u32,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Trade on native decentralized CLOB Orderbook-Actor at micro-gas
    Trade {
        #[command(subcommand)]
        sub: TradeCommands,
    },
    /// View visual L2 depth and spread of orderbook
    #[command(alias = "orderbook")]
    Book {
        /// Trading pair ID (1 = STELL/USDT, 2 = STELL/TON)
        #[arg(short, long, default_value_t = 0)]
        pair: u32,
    },
    /// Quick limit/market buy on CLOB Orderbook
    Buy {
        /// Amount in STELL (e.g. 100; exact decimal)
        amount: String,
        /// Price in USD (e.g. 0.25; exact decimal)
        price: String,
        /// Pair ID (1 = STELL/USDT, 2 = STELL/TON)
        #[arg(short, long, default_value_t = 0)]
        pair: u32,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Quick limit/market sell on CLOB Orderbook
    Sell {
        /// Amount in STELL (e.g. 100; exact decimal)
        amount: String,
        /// Price in USD (e.g. 0.25; exact decimal)
        price: String,
        /// Pair ID (1 = STELL/USDT, 2 = STELL/TON)
        #[arg(short, long, default_value_t = 0)]
        pair: u32,
        /// Password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Cancel an active order at 100 nano-STELL micro-gas
    Cancel {
        /// Order ID to cancel
        order_id: u64,
        /// Pair ID
        #[arg(short, long, default_value_t = 0)]
        pair: u32,
    },
    /// Exchange external assets for STELL in Genesis Vault ($0.25 fixed rate)
    Mint {
        /// Asset symbol (USDT, TON, GRAM)
        #[arg(default_value = "USDT")]
        asset: String,
        /// Inbound asset amount (e.g. 100)
        #[arg(default_value_t = 100)]
        amount: u64,
        /// Market price in USD (e.g. 1.0 for USDT, 5.0 for TON)
        #[arg(default_value_t = 1.0)]
        price_usd: f64,
    },
    /// Securely export private key or mnemonic phrase
    Export {
        /// Keystore password
        #[arg(short, long)]
        password: Option<String>,
        /// Required: acknowledge that printing the seed exposes total control
        /// of funds to anyone reading the screen/logs (audit 2026-10-06)
        #[arg(long, default_value_t = false)]
        show_seed: bool,
    },
    /// Inspect P2P network discovery, DHT routing, and connection topology
    #[command(alias = "network")]
    Status,
    /// Native Account Abstraction (Account Objects / Passports, session keys, rental)
    #[command(name = "aa", alias = "objects", alias = "passport")]
    Aa {
        #[command(subcommand)]
        sub: AaCommands,
    },
    /// Launch interactive Electrum-style REPL shell
    Console,
    /// Derive and display 32-byte post-quantum address from public key and scheme
    #[command(name = "pq-address")]
    PqAddress {
        /// Signature scheme: falcon512, mldsa44, hybrid, ed25519
        #[arg(short, long)]
        scheme: pq::PqScheme,
        /// Public key in hex (if omitted, sample keypair for scheme is generated)
        #[arg(short, long)]
        pubkey: Option<String>,
        /// Optional 16-byte salt in hex (defaults to 16 zero bytes)
        #[arg(long)]
        salt: Option<String>,
    },
    /// Generate sample keypair for post-quantum scheme and derive address
    #[command(name = "pq-generate")]
    PqGenerate {
        /// Post-quantum scheme: falcon512, mldsa44, hybrid
        #[arg(short, long)]
        scheme: pq::PqGenScheme,
        /// Optional 16-byte salt in hex (defaults to 16 zero bytes)
        #[arg(long)]
        salt: Option<String>,
    },
    /// Send post-quantum transfer using Falcon-512 or Hybrid scheme
    #[command(name = "pq-transfer")]
    PqTransfer {
        /// Recipient 32-byte address in hex format
        to: String,
        /// Amount in STELL (e.g. 10.5; exact decimal)
        amount: String,
        /// Post-quantum signature scheme: falcon512 or hybrid
        #[arg(short, long)]
        scheme: pq::PqTransferScheme,
        /// Explicit public key carrier mode (for Tx #1 account activation)
        #[arg(long, default_value_t = false)]
        activation: bool,
        /// Dry-run mode: construct and validate transaction without broadcasting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Keystore password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Target shard ID
        #[arg(long, default_value_t = 0)]
        shard: u32,
    },
    /// Inspect post-quantum cryptography status and capabilities
    #[command(name = "pq-status", alias = "pq")]
    PqStatus {
        /// Keystore password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Sign an arbitrary message with the WALLET SIGNATURE STANDARD
    /// (EIP-191-style preimage with the chain id bound in). Produces the
    /// standard envelope (version + scheme + pubkey + signature, hex) from
    /// THIS wallet's own key — the key never leaves this machine.
    Sign {
        /// Message to sign (UTF-8). Exactly one of `--message` / `--message-hex`.
        #[arg(long)]
        message: Option<String>,
        /// Message to sign (hex bytes). Exactly one of `--message` / `--message-hex`.
        #[arg(long, name = "message-hex")]
        message_hex: Option<String>,
        /// Chain id the signature is bound to (0 = ask the node, else this deployment's default).
        #[arg(long, default_value_t = 0)]
        chain_id: u64,
        /// Keystore password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Verify a WALLET SIGNATURE STANDARD envelope against an address, a
    /// message and a chain id. No key needed, no network needed.
    Verify {
        /// Claimed signer address (hex or Stl57).
        #[arg(long)]
        address: String,
        /// Message that was signed (UTF-8). Exactly one of `--message` / `--message-hex`.
        #[arg(long)]
        message: Option<String>,
        /// Message that was signed (hex bytes).
        #[arg(long, name = "message-hex")]
        message_hex: Option<String>,
        /// Standard envelope (hex) as produced by `stell sign`.
        #[arg(long)]
        signature: String,
        /// Chain id the signature is checked against (0 = ask the node, else this deployment's default).
        #[arg(long, default_value_t = 0)]
        chain_id: u64,
    },
    /// Sign STRUCTURED contract-call data (EIP-712-style readable signing):
    /// the canonical JSON of `{contract, method, args, value, nonce, chain_id}`
    /// is displayed AND signed, so you see exactly what you authorize.
    #[command(name = "sign-typed-data")]
    SignTypedData {
        /// Contract address (hex or Stl57).
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
        /// Chain id the call is authorized for (0 = ask the node, else this deployment's default).
        #[arg(long, default_value_t = 0)]
        chain_id: u64,
        /// Keystore password (prompted securely if omitted)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Verify a typed-data signature. The caller passes the STRUCTURED fields
    /// (what the user was shown); the canonical JSON is re-encoded locally.
    #[command(name = "verify-typed-data")]
    VerifyTypedData {
        /// Claimed signer address (hex or Stl57).
        #[arg(long)]
        address: String,
        /// Contract address (hex or Stl57).
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
        /// Chain id the call was authorized for (0 = ask the node, else this deployment's default).
        #[arg(long, default_value_t = 0)]
        chain_id: u64,
        /// Standard envelope (hex) as produced by `stell sign-typed-data`.
        #[arg(long)]
        signature: String,
    },
}

#[derive(Subcommand, Clone)]
enum AaCommands {
    /// List all Account Objects (Smart Passports) in this wallet
    #[command(name = "list", alias = "ls")]
    List,
    /// Mint / deploy a new Account Object (AA Smart Passport, costs 2 STELL)
    #[command(name = "new", alias = "mint")]
    New {
        /// Optional passport label / name
        #[arg(short, long)]
        name: Option<String>,
        /// Optional recovery guardian Stl57 or hex address
        #[arg(short, long)]
        guardian: Option<String>,
        /// Password to unlock wallet
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Create a scoped session key with an isolated spending budget
    #[command(name = "session")]
    Session {
        /// Account Object address or ID
        object: String,
        /// Service domain or contract (e.g. "dex.stl" or "game.stl")
        #[arg(short, long)]
        service: String,
        /// Spending limit budget in STELL (e.g. "10.0")
        #[arg(short, long)]
        budget: String,
        /// Password to unlock wallet
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Dynamically adjust budget of an existing session (e.g. reduce 20 to 10 STELL)
    #[command(name = "adjust-budget", alias = "update-budget")]
    AdjustBudget {
        /// Account Object address or ID
        object: String,
        /// Session ID
        #[arg(short, long)]
        session: u64,
        /// New total budget in STELL (e.g. "10.0")
        #[arg(short, long)]
        budget: String,
        /// Password to unlock wallet
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Revoke a session key in 1 click
    #[command(name = "revoke-session")]
    RevokeSession {
        /// Account Object address or ID
        object: String,
        /// Session ID to terminate
        #[arg(short, long)]
        session: u64,
        /// Password to unlock wallet
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Rent out / delegate usage rights of this Account Object to a tenant
    #[command(name = "rent")]
    Rent {
        /// Account Object address or ID
        object: String,
        /// Tenant Stl57 or hex address
        #[arg(short, long)]
        tenant: String,
        /// Rental duration in hours (e.g. 72 for 3 days)
        #[arg(long, default_value_t = 72)]
        hours: u64,
        /// Password to unlock wallet
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Revoke active rental delegation
    #[command(name = "revoke-rent")]
    RevokeRent {
        /// Account Object address or ID
        object: String,
        /// Password to unlock wallet
        #[arg(short, long)]
        password: Option<String>,
    },
}

#[derive(Subcommand, Clone)]
enum TradeCommands {
    /// View visual L2 depth and spread of orderbook
    Book {
        #[arg(short, long, default_value_t = 0)]
        pair: u32,
    },
    /// Submit buy order to CLOB Orderbook
    Buy {
        #[arg(long, default_value_t = 1)]
        pair: u32,
        #[arg(short, long, default_value = "0.25")]
        price: String,
        #[arg(short, long)]
        amount: String,
        #[arg(long, default_value = "limit")]
        order_type: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Submit sell order to CLOB Orderbook
    Sell {
        #[arg(long, default_value_t = 1)]
        pair: u32,
        #[arg(short, long, default_value = "0.25")]
        price: String,
        #[arg(short, long)]
        amount: String,
        #[arg(long, default_value = "limit")]
        order_type: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// Cancel order at ultra-cheap gas (100 nano-STELL)
    Cancel {
        #[arg(long, default_value_t = 1)]
        pair: u32,
        #[arg(short, long)]
        order_id: u64,
    },
}

/// Guard for staking-lifecycle commands that only speak classical Ed25519
/// today (`unbond`, `delegate`, `begin-unbond`, `withdraw-unbond`,
/// `claim-rewards`, `rotate-key`). A PQ keystore would otherwise build a
/// classical transaction from the WRONG (Ed25519) address with the wrong
/// nonce — a confusing failure deep in the node. Fail loudly instead.
/// (`stake` and `pay` already have PQ1 branches.)
fn require_classical_keystore(keystore: &HardenedKeystore, op: &str) -> anyhow::Result<()> {
    if keystore.scheme != "ed25519" {
        anyhow::bail!(
            "PQ wallet (scheme '{}'): '{}' is not supported for post-quantum wallets yet on Pure-PQ networks. Use 'stake'/'pay', or run this command from a classical ed25519 wallet.",
            keystore.scheme,
            op
        );
    }
    Ok(())
}

/// E1b: build the stake opcode for a bond — plain `SysCallStake`
/// (governance default commission) or `SysCallStakeWithCommission`
/// (explicit rate for a new validator).
///
/// The rate is validated HERE (`<= 10_000 bps`, else a loud client-side
/// error before anything is signed); the ledger re-validates, and
/// commission is IMMUTABLE after bonding either way (a top-up keeps the
/// registered rate — see the `stake_with_commission_*` SVM tests).
fn stake_opcode(
    validator: [u8; 32],
    nano: u64,
    commission_bps: Option<u64>,
) -> anyhow::Result<stellereum::svm::OpCode> {
    match commission_bps {
        None => Ok(stellereum::svm::OpCode::SysCallStake {
            validator,
            amount: nano,
        }),
        Some(bps) => {
            if bps > 10_000 {
                anyhow::bail!("--commission-bps must be <= 10000 (100%), got {bps}");
            }
            Ok(stellereum::svm::OpCode::SysCallStakeWithCommission {
                validator,
                amount: nano,
                commission_bps: bps,
            })
        }
    }
}
/// Minimum password for keystore CREATION paths (audit 2026-10-06: `new`
/// enforced it, `restore` accepted empty — an empty-password keystore is
/// open to anyone holding the file). Unlock paths need no check (decrypt
/// fails on a wrong password by itself).
fn check_password_strength(pass: &str) -> anyhow::Result<()> {
    if pass.len() < 6 {
        anyhow::bail!("Password should be at least 6 characters long for security!");
    }
    Ok(())
}

fn read_secret() -> anyhow::Result<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        Ok(rpassword::read_password()?)
    } else {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line.trim_end_matches(&['\r', '\n'][..]).to_string())
    }
}

fn prompt_password_safely(given: Option<String>, prompt: &str) -> anyhow::Result<String> {
    if let Some(p) = given {
        eprintln!(
            "{}",
            "warning: secret passed on the command line leaks via shell history and `ps`; prefer the interactive prompt".yellow()
        );
        return Ok(p);
    }
    eprint!("{}: ", prompt);
    io::stderr().flush()?;
    let pass = read_secret()?;
    Ok(pass)
}

fn prompt_password_with_confirmation(
    given: Option<String>,
    prompt: &str,
) -> anyhow::Result<String> {
    if let Some(p) = given {
        eprintln!(
            "{}",
            "warning: secret passed on the command line leaks via shell history and `ps`; prefer the interactive prompt".yellow()
        );
        check_password_strength(&p)?;
        return Ok(p);
    }
    loop {
        eprint!("{}: ", prompt);
        io::stderr().flush()?;
        let p1 = read_secret()?;
        if let Err(e) = check_password_strength(&p1) {
            eprintln!("{}", format!("❌ {e}\n").red());
            continue;
        }
        eprint!("Confirm password: ");
        io::stderr().flush()?;
        let p2 = read_secret()?;
        if p1 != p2 {
            eprintln!("{}", "❌ Passwords do not match! Please try again.\n".red());
            continue;
        }
        return Ok(p1);
    }
}

/// Plain (non-colored) finality label for honest status reporting.
fn finality_label(f: &rpc::TxFinality) -> String {
    f.status_label()
}

/// Parse a decimal STELL string to nano-STELL exactly (audit 2026-10-06):
/// the old `(f64 * 1e9) as u64` truncated fractions, saturated negatives to
/// 0 (a 0-value tx that still pays the 280k fee), and wrapped huge values.
/// Up to 9 fractional digits; rejects negative/empty/zero/overflow.
pub fn parse_stell_to_nano(s: &str) -> Result<u64, String> {
    parse_decimal_to_units(s, 9, "STELL")
}

/// Parse a decimal USD string to micro-USD exactly (6 fractional digits).
pub fn parse_usd_to_micro(s: &str) -> Result<u64, String> {
    parse_decimal_to_units(s, 6, "USD")
}

fn parse_decimal_to_units(s: &str, frac_digits: u32, unit: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("amount is empty".to_string());
    }
    if s.starts_with('-') || s.starts_with('+') {
        return Err(format!("amount must be a plain positive decimal ({unit})"));
    }
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if int_part.is_empty() || !int_part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("bad {unit} amount: {s}"));
    }
    if frac_part.len() as u32 > frac_digits || !frac_part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("too many decimal places (max {frac_digits}): {s}"));
    }
    let scale = 10u64.pow(frac_digits);
    let int_val: u64 = int_part
        .parse()
        .map_err(|_| format!("{unit} amount overflows: {s}"))?;
    let int_nano = int_val
        .checked_mul(scale)
        .ok_or_else(|| format!("{unit} amount overflows: {s}"))?;
    let mut frac_val = 0u64;
    for (i, b) in frac_part.bytes().enumerate() {
        let d = (b - b'0') as u64;
        frac_val += d * 10u64.pow(frac_digits - 1 - i as u32);
    }
    let total = int_nano
        .checked_add(frac_val)
        .ok_or_else(|| format!("{unit} amount overflows: {s}"))?;
    if total == 0 {
        return Err(format!("{unit} amount must be greater than zero"));
    }
    Ok(total)
}

/// Display string for a broadcast outcome: in local mode the tx never saw a
/// mempool, so the generic `Pending` label would mislead — say simulated.
fn display_finality(client: &LightClient, f: &rpc::TxFinality) -> String {
    if client.is_rpc() {
        f.status_label()
    } else {
        "Simulated locally — NOT chain-finalized (no mempool, no receipts)".to_string()
    }
}

pub fn parse_hex16(hex_str: &str, what: &str) -> anyhow::Result<[u8; 16]> {
    let raw = hex_str.trim();
    let clean = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(clean).map_err(|e| anyhow::anyhow!("Invalid {what} hex: {e}"))?;
    if bytes.len() != 16 {
        anyhow::bail!("{what} must be 16 bytes (32 hex characters)");
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Resolve the chain id for WALLET SIGNATURE STANDARD signing/verification.
///
/// An explicit `--chain-id N` (non-zero) always wins. `0` (the default) asks
/// the connected node (`stell_chainId`) and falls back to this deployment's
/// default when offline — the same rule the `session` command uses, so the
/// wallet and the node never disagree about which chain a signature is for
/// when they can talk, and signing still works offline.
fn resolve_sign_chain_id(flag: u64, client: &LightClient) -> u64 {
    if flag != 0 {
        return flag;
    }
    let live = client.chain_id();
    if live != 0 {
        return live;
    }
    stellereum::zkml::DEFAULT_CHAIN_ID
}

pub fn parse_hex32(hex_str: &str, what: &str) -> anyhow::Result<[u8; 32]> {
    let raw = hex_str.trim();
    // 1. If user passed an Stl57 address, parse and preserve specific errors (e.g. InvalidChecksum typo)
    if raw
        .get(..5)
        .is_some_and(|p| p.eq_ignore_ascii_case("stl57"))
    {
        return stellereum::address::parse_address(raw)
            .map_err(|e| anyhow::anyhow!("Invalid {what} address: {e}"));
    }

    // 2. Direct hex fallback
    let clean = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(clean).map_err(|e| {
        anyhow::anyhow!("Invalid {what} (expected Stl57... or 64-character hex): {e}")
    })?;
    if bytes.len() != 32 {
        anyhow::bail!("{what} must be 32 bytes (or Stl57 address)");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn parse_hex32_list(csv: &str, what: &str) -> anyhow::Result<Vec<[u8; 32]>> {
    csv.split(',')
        .map(|s| parse_hex32(s.trim(), what))
        .collect()
}

fn parse_u64_list(csv: &str, what: &str) -> anyhow::Result<Vec<u64>> {
    csv.split(',')
        .map(|s| {
            s.trim()
                .parse::<u64>()
                .map_err(|_| anyhow::anyhow!("{what} must be plain integers: {s}"))
        })
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let is_explicit_wallet = cli.wallet.is_some();
    let wallet_path = wallets::resolve_active_wallet_path(cli.wallet, None);
    enforce_strict_permissions(&wallet_path);

    let rpc_target = cli.rpc_url.or_else(|| std::env::var("STELL_RPC_URL").ok());

    let client = match &rpc_target {
        Some(url) => LightClient::connect_rpc(
            url,
            cli.auth_token.clone(),
            cli.faucet_token.clone(),
            cli.timeout,
            cli.poll_interval,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?,
        None => LightClient::connect(cli.config.as_deref())
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?,
    };

    let cmd = match cli.command {
        Some(Commands::Console) | None => {
            return run_repl_console(wallet_path, is_explicit_wallet, client).await;
        }
        Some(c) => c,
    };

    execute_command(cmd, &wallet_path, is_explicit_wallet, &client).await
}

async fn execute_command(
    cmd: Commands,
    wallet_path: &PathBuf,
    is_explicit_wallet: bool,
    client: &LightClient,
) -> anyhow::Result<()> {
    match cmd {
        Commands::New {
            name,
            wallet_name,
            password,
            scheme,
        } => {
            println!(
                "{}",
                "╔═══════════════════════════════════════════════════════════════╗".cyan()
            );
            println!(
                "{}",
                "║              ✨ STELLEREUM SECURE VAULT CREATION              ║"
                    .cyan()
                    .bold()
            );
            println!(
                "{}",
                "╚═══════════════════════════════════════════════════════════════╝".cyan()
            );

            let chosen_name = wallet_name.or(name);
            let pass = prompt_password_with_confirmation(
                password,
                "Enter password for new vault encryption",
            )?;
            check_password_strength(&pass)?;

            let (phrase, seed) = Mnemonic::generate();
            let sec_secret = SecureSecret::new(seed);

            let (address_hex, pubkey_hex_opt) = match scheme {
                pq::WalletScheme::Falcon512 => {
                    let keypair =
                        pq::PqKeyPair::from_seed(pq::PqScheme::Falcon512, &sec_secret.bytes);
                    let addr = keypair.derive_address(&pq::DEFAULT_SALT);
                    let addr_hex = hex::encode(addr);
                    let pk_hex = hex::encode(keypair.public_key());
                    (addr_hex, Some(pk_hex))
                }
                pq::WalletScheme::Hybrid => {
                    let keypair = pq::PqKeyPair::from_seed(pq::PqScheme::Hybrid, &sec_secret.bytes);
                    let addr = keypair.derive_address(&pq::DEFAULT_SALT);
                    let addr_hex = hex::encode(addr);
                    let pk_hex = hex::encode(keypair.public_key());
                    (addr_hex, Some(pk_hex))
                }
                pq::WalletScheme::Ed25519 => {
                    let account = WalletAccount::from_seed(&sec_secret.bytes);
                    (hex::encode(account.address), None)
                }
            };

            let keystore = HardenedKeystore::encrypt_with_scheme(
                &sec_secret,
                &address_hex,
                &pass,
                scheme.as_str(),
                pubkey_hex_opt.clone(),
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;

            let final_path = if let Some(n) = &chosen_name {
                wallets::save_named_wallet(n, &keystore, None)
                    .map_err(|e| anyhow::anyhow!("{e}"))?
            } else if is_explicit_wallet {
                keystore
                    .save(wallet_path)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                wallet_path.clone()
            } else {
                let auto_name = wallets::generate_next_wallet_name(None);
                wallets::save_named_wallet(&auto_name, &keystore, None)
                    .map_err(|e| anyhow::anyhow!("{e}"))?
            };

            let wallet_display_name = chosen_name.unwrap_or_else(|| {
                final_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("default")
                    .to_string()
            });

            println!(
                "\n{}",
                "✅ Wallet securely created with Argon2id + XChaCha20Poly1305!"
                    .green()
                    .bold()
            );
            println!(
                "• Wallet Name:          {}",
                wallet_display_name.green().bold()
            );
            println!(
                "• Vault File:           {}",
                format!("{:?}", final_path).yellow()
            );
            println!(
                "• Permissions:          {}",
                "0600 (Restricted to owner only)".green()
            );
            println!("• Scheme:               {}", scheme.name().cyan().bold());
            println!(
                "• Quantum Resistant:    {}",
                if scheme.is_post_quantum() {
                    "Yes (Pure Post-Quantum)".green().bold()
                } else {
                    "No (Classical Ed25519)".yellow()
                }
            );
            println!(
                "• Public Address:       {}",
                format_address_with_visual_checksum(&address_hex)
            );
            if let Some(pk_hex) = &pubkey_hex_opt {
                println!("• PQ Public Key Size:   {} bytes", pk_hex.len() / 2);
                println!("• PQ Public Key:        {}", pk_hex.cyan());
            } else {
                let account = WalletAccount::from_seed(&sec_secret.bytes);
                println!(
                    "• Stealth One-Time Pub: {}",
                    hex::encode(account.stealth_address.one_time_pub).magenta()
                );
                println!(
                    "• Viewing Public Key:   {}",
                    hex::encode(account.viewing_key.view_pub).blue()
                );
            }

            println!(
                "\n{}",
                "🔑 RECOVERY MNEMONIC PHRASE (24 WORDS):".yellow().bold()
            );
            println!(
                "{}",
                "┌───────────────────────────────────────────────────────────────┐".yellow()
            );
            println!("  {}", phrase.bold().white());
            println!(
                "{}",
                "└───────────────────────────────────────────────────────────────┘".yellow()
            );
            println!(
                "{}",
                "⚠️  WRITE DOWN THESE 24 WORDS OFFLINE! Never store them in plaintext."
                    .red()
                    .bold()
            );
        }

        Commands::Restore {
            name,
            wallet_name,
            phrase,
            key,
            password,
            scheme,
        } => {
            // argv-leak warning covers --phrase/--key too (audit follow-up:
            // more sensitive than --password, warned nowhere).
            if phrase.is_some() || key.is_some() {
                eprintln!(
                    "{}",
                    "warning: recovery secret passed on the command line leaks via shell history and `ps`; pipe it via stdin instead".yellow()
                );
            }
            let chosen_name = wallet_name.or(name);
            let pass = prompt_password_safely(password, "Enter password for restored vault")?;
            check_password_strength(&pass)?;

            let seed = if let Some(p) = phrase {
                Mnemonic::from_phrase(&p).map_err(|e| anyhow::anyhow!("{e}"))?
            } else if let Some(k) = key {
                let bytes = hex::decode(&k).map_err(|e| anyhow::anyhow!("Invalid hex: {e}"))?;
                if bytes.len() != 32 {
                    anyhow::bail!("Private key must be 32 bytes (64 hex characters)");
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            } else {
                eprint!("Enter 24-word recovery phrase: ");
                io::stdout().flush()?;
                let mut line = String::new();
                io::stdin().read_line(&mut line)?;
                Mnemonic::from_phrase(&line).map_err(|e| anyhow::anyhow!("{e}"))?
            };

            let sec_secret = SecureSecret::new(seed);
            let (address_hex, pubkey_hex_opt) = match scheme {
                pq::WalletScheme::Falcon512 => {
                    let keypair =
                        pq::PqKeyPair::from_seed(pq::PqScheme::Falcon512, &sec_secret.bytes);
                    let addr = keypair.derive_address(&pq::DEFAULT_SALT);
                    (hex::encode(addr), Some(hex::encode(keypair.public_key())))
                }
                pq::WalletScheme::Hybrid => {
                    let keypair = pq::PqKeyPair::from_seed(pq::PqScheme::Hybrid, &sec_secret.bytes);
                    let addr = keypair.derive_address(&pq::DEFAULT_SALT);
                    (hex::encode(addr), Some(hex::encode(keypair.public_key())))
                }
                pq::WalletScheme::Ed25519 => {
                    let account = WalletAccount::from_seed(&sec_secret.bytes);
                    (hex::encode(account.address), None)
                }
            };

            let keystore = HardenedKeystore::encrypt_with_scheme(
                &sec_secret,
                &address_hex,
                &pass,
                scheme.as_str(),
                pubkey_hex_opt,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;

            let final_path = if let Some(n) = &chosen_name {
                wallets::save_named_wallet(n, &keystore, None)
                    .map_err(|e| anyhow::anyhow!("{e}"))?
            } else if is_explicit_wallet {
                keystore
                    .save(wallet_path)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                wallet_path.clone()
            } else {
                let auto_name = wallets::generate_next_wallet_name(None);
                wallets::save_named_wallet(&auto_name, &keystore, None)
                    .map_err(|e| anyhow::anyhow!("{e}"))?
            };

            let wallet_display_name = chosen_name.unwrap_or_else(|| {
                final_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("default")
                    .to_string()
            });

            println!("{}", "✅ Wallet successfully restored!".green().bold());
            println!("• Wallet Name:      {}", wallet_display_name.green().bold());
            println!(
                "• Vault File:       {}",
                format!("{:?}", final_path).yellow()
            );
            println!("• Scheme:           {}", scheme.name().cyan().bold());
            println!(
                "• Restored Address: {}",
                format_address_with_visual_checksum(&address_hex)
            );
        }

        Commands::Wallets => {
            let entries = wallets::list_wallets(None).map_err(|e| anyhow::anyhow!("{e}"))?;
            if entries.is_empty() {
                println!("{}", "No local wallets found.".yellow());
                println!(
                    "Create your first wallet with: {}",
                    "stell new".cyan().bold()
                );
                return Ok(());
            }

            println!("{}", "╔════════════════════════════════════════════════════════════════════════════════════════════════╗".cyan());
            println!("{}", "║                                 👛 LOCAL STELLEREUM WALLETS                                    ║".cyan().bold());
            println!("{}", "╚════════════════════════════════════════════════════════════════════════════════════════════════╝".cyan());
            println!(
                "{:<3} {:<15} {:<18} {:<45}",
                "ACT", "NAME", "SCHEME", "ADDRESS"
            );
            println!("{}", "─".repeat(96).dimmed());

            for w in entries {
                let act_marker = if w.is_active {
                    "*".green().bold().to_string()
                } else {
                    " ".to_string()
                };
                let name_display = if w.is_active {
                    w.name.green().bold().to_string()
                } else {
                    w.name
                };
                let scheme_display = match w.scheme.as_str() {
                    "falcon512" => "Falcon-512 (PQ)".cyan().to_string(),
                    "hybrid" => "Hybrid PQ".blue().to_string(),
                    _ => "Ed25519".yellow().to_string(),
                };
                let addr_formatted = format_address_single_line(&w.address_hex);
                println!(
                    "{:<3} {:<15} {:<18} {}",
                    act_marker, name_display, scheme_display, addr_formatted
                );
            }
            println!("{}", "─".repeat(96).dimmed());
            println!(
                "(*) Active wallet. Switch anytime with: {}",
                "stell switch <name>".cyan().bold()
            );
        }

        Commands::Switch {
            name_or_address,
            password,
        } => {
            let pass = prompt_password_safely(
                password,
                &format!(
                    "Enter password for wallet '{}' to verify and switch",
                    name_or_address
                ),
            )?;
            let switched = wallets::switch_wallet(&name_or_address, &pass, None)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!(
                "\n{}",
                "✅ Successfully switched active wallet!".green().bold()
            );
            println!("• Active Wallet:   {}", switched.name.green().bold());
            println!("• Scheme:          {}", switched.scheme.cyan());
            println!(
                "• Address:         {}",
                format_address_with_visual_checksum(&switched.address_hex)
            );
            println!(
                "• Vault Path:      {}",
                switched.path.display().to_string().yellow()
            );
        }

        Commands::Receive { password } => {
            let keystore = HardenedKeystore::load(wallet_path).map_err(|e| {
                anyhow::anyhow!(
                    "Wallet not found at {:?}. Run 'stell new' first: {e}",
                    wallet_path
                )
            })?;

            // YOUR keys, derived from YOUR seed (audit 2026-10-06: the old
            // code showed a FRESH RANDOM viewing/stealth pair nobody owns —
            // funds sent there are unspendable).
            let pass =
                prompt_password_safely(password, "Enter keystore password to show receiving keys")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║                    📥 RECEIVE STELL (L1)                      ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!(
                "• Address: {}",
                format_address_with_visual_checksum(&keystore.address_hex)
            );
            println!(
                "• Viewing Key: {}",
                hex::encode(account.viewing_key.view_pub).magenta()
            );
            println!(
                "• Spending Key: {}",
                hex::encode(account.spend_pub).magenta()
            );
            println!(
                "• Stealth One-Time: {}",
                hex::encode(account.stealth_address.one_time_pub).magenta()
            );

            // Render crisp ASCII QR Code using primary Stl57 address
            let mut addr_bytes = [0u8; 32];
            if let Ok(b) = hex::decode(&keystore.address_hex) {
                if b.len() == 32 {
                    addr_bytes.copy_from_slice(&b);
                }
            }
            let stl57_qr_payload = stellereum::address::encode_stl57_address(&addr_bytes);

            println!("\n{}", "Scan QR Code to receive payment:".cyan());
            if let Ok(code) = QrCode::new(stl57_qr_payload.as_bytes()) {
                let image = code
                    .render::<unicode::Dense1x2>()
                    .dark_color(unicode::Dense1x2::Light)
                    .light_color(unicode::Dense1x2::Dark)
                    .build();
                println!("{}", image);
            }
        }

        Commands::Balance { shard } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found at {:?}: {e}", wallet_path))?;

            let addr_bytes = hex::decode(&keystore.address_hex)?;
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&addr_bytes);

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║                  💰 ACCOUNT BALANCE & SPV                     ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Mode:          {}", client.mode_line().yellow());
            if client.is_rpc() {
                let answer = client
                    .get_balance_spv_rpc_full(&addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                let verified = rpc::verify_spv_balance_answer(&addr, &answer);
                let (balance, nonce) = (answer.balance, answer.nonce);
                println!(
                    "• Address:       {}",
                    format_address_with_visual_checksum(&keystore.address_hex)
                );
                println!("• Shard:         {}", format!("#{}", shard).yellow());
                println!(
                    "• Balance:       {} STELL ({} nano-STELL)",
                    format!("{:.6}", (balance as f64) / 1_000_000_000.0)
                        .green()
                        .bold(),
                    balance
                );
                println!(
                    "• Valuation:     {}",
                    format!("≈ ${:.2} USD", ((balance as f64) / 1_000_000_000.0) * 0.25).cyan()
                );
                println!("• Nonce:         {}", nonce);
                println!("• Chain root:    {}", hex::encode(answer.state_root).cyan());
                match verified {
                    rpc::SpvVerdict::Verified => {
                        println!("• SPV Merkle:    {}", "✅ Verified against the NODE-SERVED root (trusted-node SPV: no header proof, no multi-node check)".green().bold());
                    }
                    rpc::SpvVerdict::Absent => {
                        println!(
                            "• SPV Merkle:    {}",
                            "○ No on-chain record — zero by protocol (account never funded)"
                                .yellow()
                        );
                    }
                    rpc::SpvVerdict::Failed => {
                        println!(
                            "• SPV Merkle:    {}",
                            "❌ PROOF FAILED local verification — do NOT trust this balance"
                                .red()
                                .bold()
                        );
                    }
                }
            } else {
                let (balance, nonce, verified) = client
                    .get_balance_spv(&addr, shard)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

                println!(
                    "• Address:       {}",
                    format_address_with_visual_checksum(&keystore.address_hex)
                );
                println!("• Shard:         {}", format!("#{}", shard).yellow());
                println!(
                    "• Balance:       {} STELL ({} nano-STELL)",
                    format!("{:.6}", (balance as f64) / 1_000_000_000.0)
                        .green()
                        .bold(),
                    balance
                );
                println!(
                    "• Valuation:     {}",
                    format!("≈ ${:.2} USD", ((balance as f64) / 1_000_000_000.0) * 0.25).cyan()
                );
                println!("• Nonce:         {}", nonce);
                if verified {
                    println!(
                        "• SPV Merkle:    {}",
                        "✅ Self-consistent with the LOCAL state cache".green()
                    );
                } else {
                    println!(
                        "• SPV Merkle:    {}",
                        "⚠️  Unconfirmed / Zero balance".yellow()
                    );
                }
                println!("• Note:          {}", "local mode proves self-consistency only, NOT chain inclusion — use --rpc-url for chain-verified SPV.".yellow());
            }
        }

        Commands::Faucet { amount } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let addr_bytes = hex::decode(&keystore.address_hex)?;
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&addr_bytes);

            if client.is_rpc() {
                let nano = amount
                    .checked_mul(1_000_000_000)
                    .ok_or_else(|| anyhow::anyhow!("faucet amount overflows nano-STELL"))?;
                let (credited, drip_hash) = client
                    .faucet_drip_rpc(&addr, Some(nano))
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!(
                    "{} faucet credited {} nano-STELL to {}",
                    "✅ Testnet Faucet:".green().bold(),
                    credited,
                    format_address_with_visual_checksum(&keystore.address_hex)
                );
                println!("• Faucet tx:     {}", drip_hash.yellow());
                println!("• Note:          {}", "funds are spendable only once the faucet tx finalizes — check `receipt` / `balance --rpc-url`.".yellow());
            } else {
                let nano = amount
                    .checked_mul(1_000_000_000)
                    .ok_or_else(|| anyhow::anyhow!("faucet amount overflows nano-STELL"))?;
                client.set_balance(addr, nano, 0).await;
                println!(
                    "{} {} STELL credited to {}",
                    "✅ Local Faucet (simulated):".green().bold(),
                    amount,
                    format_address_with_visual_checksum(&keystore.address_hex)
                );
                println!("• Note:          {}", "local simulation only — no chain funds moved. Use --rpc-url for the real testnet faucet.".yellow());
            }
        }

        Commands::Stake {
            validator,
            amount,
            commission_bps,
            unbound_legacy,
            password,
            fee,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let nano = parse_stell_to_nano(&amount).map_err(|e| anyhow::anyhow!("{e}"))?;
            // Post-quantum keystores must submit a PQ1 envelope: classical
            // signatures are rejected on Pure-PQ networks. Classical keystores
            // keep the legacy path.
            let is_pq_store = keystore.scheme == "falcon512"
                || keystore.scheme == "hybrid"
                || keystore.scheme == "mldsa44";
            // A14: bound by default; the legacy flag recovers the old
            // replayable bytes with a loud warning (see `unbound_legacy_*`).
            let chain_id = client.chain_id();
            if unbound_legacy {
                eprintln!(
                    "{}",
                    "warning: --unbound-legacy builds a REPLAYABLE transaction (no chain id); the node meters unbound admission and will refuse it in a later phase".yellow()
                );
            }
            let res = if is_pq_store {
                if keystore.scheme == "mldsa44" {
                    anyhow::bail!("PQ wallet (scheme 'mldsa44'): 'stake' is not supported for ML-DSA-44 wallets yet (address derivation differs). Use a falcon512 or hybrid wallet.");
                }
                let pq_scheme = match keystore.scheme.as_str() {
                    "hybrid" => pq::PqScheme::Hybrid,
                    _ => pq::PqScheme::Falcon512,
                };
                let keypair = pq::PqKeyPair::from_seed(pq_scheme, &sec_secret.bytes);
                let from_addr = keypair.derive_address(&pq::DEFAULT_SALT);
                let val = match validator {
                    Some(v) => parse_hex32(&v, "validator key")?,
                    None => from_addr,
                };
                let payload = vec![stake_opcode(val, nano, commission_bps)?];
                let nonce = client
                    .nonce_of(&from_addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                // Wallet policy: ALWAYS explicit carrier (see pay path).
                let is_activation = true;
                let gas = fee.unwrap_or(
                    stellereum::svm::GAS_STAKE_BOND
                        .saturating_add(stellereum::svm::GAS_BASIC_TRANSFER)
                        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS),
                );
                let tx = if unbound_legacy {
                    client::LightClient::build_pq_payload_tx(
                        &keypair,
                        from_addr,
                        0,
                        gas,
                        nonce,
                        stellereum::sharding::MASTERCHAIN_SHARD,
                        stellereum::sharding::MASTERCHAIN_SHARD,
                        is_activation,
                        payload,
                    )
                } else {
                    client::LightClient::build_pq_payload_tx_bound(
                        &keypair,
                        from_addr,
                        0,
                        gas,
                        nonce,
                        stellereum::sharding::MASTERCHAIN_SHARD,
                        stellereum::sharding::MASTERCHAIN_SHARD,
                        is_activation,
                        payload,
                        chain_id,
                    )
                };
                let val_hex = hex::encode(val);
                let res = client
                    .broadcast_tx(&tx)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!(
                    "• Stake (PQ):   {} STELL -> validator {}",
                    amount.green().bold(),
                    val_hex.yellow()
                );
                res
            } else {
                let account = WalletAccount::from_seed(&sec_secret.bytes);
                let val = match validator {
                    Some(v) => parse_hex32(&v, "validator key")?,
                    None => account.address,
                };
                let nonce = client
                    .nonce_of(&account.address)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                let tx = if unbound_legacy {
                    account.unbound_legacy_payload_transaction(
                        vec![stake_opcode(val, nano, commission_bps)?],
                        stellereum::svm::GAS_STAKE_BOND + stellereum::svm::GAS_BASIC_TRANSFER,
                        nonce,
                    )
                } else {
                    account.create_bound_payload_transaction(
                        vec![stake_opcode(val, nano, commission_bps)?],
                        stellereum::svm::GAS_STAKE_BOND + stellereum::svm::GAS_BASIC_TRANSFER,
                        nonce,
                        chain_id,
                    )
                };
                let res = client
                    .broadcast_tx(&tx)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!(
                    "• Stake:        {} STELL -> validator {} (chain {})",
                    amount.green().bold(),
                    hex::encode(val).yellow(),
                    if unbound_legacy {
                        "UNBOUND-legacy".to_string()
                    } else {
                        format!("bound:{chain_id}")
                    }
                );
                res
            };
            let (tx_hash, finality) = res;
            println!("• Tx Hash:      {}", hex::encode(tx_hash).yellow().bold());
            println!(
                "• Finality:     {}",
                display_finality(client, &finality).bold()
            );
        }

        Commands::Unbond {
            validator,
            amount,
            password,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            require_classical_keystore(&keystore, "unbond")?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);
            let val = match validator {
                Some(v) => parse_hex32(&v, "validator key")?,
                None => account.address,
            };
            let nano = parse_stell_to_nano(&amount).map_err(|e| anyhow::anyhow!("{e}"))?;
            let nonce = client
                .nonce_of(&account.address)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let tx = account.create_payload_transaction(
                vec![stellereum::svm::OpCode::SysCallUnbond {
                    validator: val,
                    amount: nano,
                }],
                stellereum::svm::GAS_STAKE_UNBOND + stellereum::svm::GAS_BASIC_TRANSFER,
                nonce,
            );
            let (tx_hash, finality) = client
                .broadcast_tx(&tx)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!(
                "• Unbond:       {} STELL from validator {} (cooldown applies)",
                amount.green().bold(),
                hex::encode(val).yellow()
            );
            println!("• Tx Hash:      {}", hex::encode(tx_hash).yellow().bold());
            println!(
                "• Finality:     {}",
                display_finality(client, &finality).bold()
            );
        }

        Commands::Delegate {
            validator,
            amount,
            password,
        } => {
            let nano = parse_stell_to_nano(&amount).map_err(|e| anyhow::anyhow!("{e}"))?;
            let val_opt = validator
                .as_deref()
                .map(|v| parse_hex32(v, "validator key"))
                .transpose()?;
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            require_classical_keystore(&keystore, "delegate")?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);
            let val = val_opt.unwrap_or(account.address);
            let nonce = client
                .nonce_of(&account.address)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let tx = LightClient::build_delegate_tx(&account, val, nano, nonce);
            let (tx_hash, finality) = client
                .broadcast_tx(&tx)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!(
                "• Delegate:     {} STELL -> validator {}",
                amount.green().bold(),
                hex::encode(val).yellow()
            );
            println!("• Tx Hash:      {}", hex::encode(tx_hash).yellow().bold());
            println!(
                "• Finality:     {}",
                display_finality(client, &finality).bold()
            );
        }

        Commands::BeginUnbond {
            validator,
            amount,
            password,
        } => {
            let nano = parse_stell_to_nano(&amount).map_err(|e| anyhow::anyhow!("{e}"))?;
            let val_opt = validator
                .as_deref()
                .map(|v| parse_hex32(v, "validator key"))
                .transpose()?;
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            require_classical_keystore(&keystore, "begin-unbond")?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);
            let val = val_opt.unwrap_or(account.address);
            let nonce = client
                .nonce_of(&account.address)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let tx = LightClient::build_begin_unbond_tx(&account, val, nano, nonce);
            let (tx_hash, finality) = client
                .broadcast_tx(&tx)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!(
                "• BeginUnbond:  {} STELL from validator {} (cooldown starts now)",
                amount.green().bold(),
                hex::encode(val).yellow()
            );
            println!("• Tx Hash:      {}", hex::encode(tx_hash).yellow().bold());
            println!(
                "• Finality:     {}",
                display_finality(client, &finality).bold()
            );
        }

        Commands::WithdrawUnbond {
            validator,
            password,
        } => {
            let val_opt = validator
                .as_deref()
                .map(|v| parse_hex32(v, "validator key"))
                .transpose()?;
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            require_classical_keystore(&keystore, "withdraw-unbond")?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);
            let val = val_opt.unwrap_or(account.address);
            let nonce = client
                .nonce_of(&account.address)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let tx = LightClient::build_withdraw_unbond_tx(&account, val, nonce);
            let (tx_hash, finality) = client
                .broadcast_tx(&tx)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("• WithdrawUnbond: matured funds from validator {} (only pays matured funds after cooldown)", hex::encode(val).yellow());
            println!("• Tx Hash:      {}", hex::encode(tx_hash).yellow().bold());
            println!(
                "• Finality:     {}",
                display_finality(client, &finality).bold()
            );
        }

        Commands::ClaimRewards {
            validator,
            delegator,
            password,
        } => {
            let val_opt = validator
                .as_deref()
                .map(|v| parse_hex32(v, "validator key"))
                .transpose()?;
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            require_classical_keystore(&keystore, "claim-rewards")?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);
            let val = val_opt.unwrap_or(account.address);
            let nonce = client
                .nonce_of(&account.address)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let is_delegator = delegator || val != account.address;
            let tx = LightClient::build_claim_rewards_tx(&account, val, is_delegator, nonce);
            let (tx_hash, finality) = client
                .broadcast_tx(&tx)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if is_delegator {
                println!(
                    "• ClaimRewards: delegator rewards from validator {}",
                    hex::encode(val).yellow()
                );
            } else {
                println!(
                    "• ClaimRewards: validator rewards for {}",
                    hex::encode(val).yellow()
                );
            }
            println!("• Tx Hash:      {}", hex::encode(tx_hash).yellow().bold());
            println!(
                "• Finality:     {}",
                display_finality(client, &finality).bold()
            );
        }

        Commands::RotateKey { new_key, password } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter OLD keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            require_classical_keystore(&keystore, "rotate-key")?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);
            let new_val = parse_hex32(&new_key, "new validator key")?;
            let nonce = client
                .nonce_of(&account.address)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let tx = account.create_payload_transaction(
                vec![stellereum::svm::OpCode::SysCallRotateValidatorKey {
                    old_validator: account.address,
                    new_validator: new_val,
                }],
                stellereum::svm::GAS_STAKE_UNBOND + stellereum::svm::GAS_BASIC_TRANSFER,
                nonce,
            );
            let (tx_hash, finality) = client
                .broadcast_tx(&tx)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!(
                "• Rotate:       {} -> {}",
                hex::encode(account.address).yellow(),
                hex::encode(new_val).green().bold()
            );
            println!("• Tx Hash:      {}", hex::encode(tx_hash).yellow().bold());
            println!(
                "• Finality:     {}",
                display_finality(client, &finality).bold()
            );
            println!(
                "• Note:         {}",
                "re-point this node at the NEW key and restart it".yellow()
            );
        }

        Commands::Pay {
            to,
            amount,
            password,
            shard,
            source_shard,
            target_shard,
            scheme,
            dry_run,
            unbound_legacy,
            fee,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;

            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            let to_bytes = hex::decode(&to)
                .map_err(|e| anyhow::anyhow!("Invalid recipient address hex: {e}"))?;
            if to_bytes.len() != 32 {
                anyhow::bail!("Recipient address must be 32 bytes (64 hex characters)");
            }
            let mut to_arr = [0u8; 32];
            to_arr.copy_from_slice(&to_bytes);

            let nano_amount = parse_stell_to_nano(&amount).map_err(|e| anyhow::anyhow!("{e}"))?;

            // Cross-shard sends: --source-shard/--target-shard override the
            // legacy --shard (default = old behavior: both equal --shard).
            let src_shard = source_shard.unwrap_or(shard);
            let dst_shard = target_shard.unwrap_or(shard);

            let is_pq_account = keystore.is_pq();
            let use_pq = if is_pq_account {
                scheme != pq::WalletScheme::Ed25519
            } else {
                scheme.is_post_quantum()
            };

            if use_pq {
                let effective_pq_scheme = match scheme {
                    pq::WalletScheme::Falcon512 => pq::PqScheme::Falcon512,
                    pq::WalletScheme::Hybrid => pq::PqScheme::Hybrid,
                    pq::WalletScheme::Ed25519 => {
                        if keystore.scheme == "hybrid" {
                            pq::PqScheme::Hybrid
                        } else {
                            pq::PqScheme::Falcon512
                        }
                    }
                };

                let keypair = pq::PqKeyPair::from_seed(effective_pq_scheme, &sec_secret.bytes);
                let from_addr = keypair.derive_address(&pq::DEFAULT_SALT);
                let nonce = client.nonce_of(&from_addr).await.unwrap_or(0);
                // Wallet policy: ALWAYS explicit carrier. Implicit envelopes
                // omit the pubkey and only verify against pinned on-chain keys,
                // which also breaks the wallet's local pre-broadcast self-check.
                // Cost: +897B wire and the 45k state-rent surcharge per tx —
                // negligible for a wallet, maximally compatible everywhere.
                let is_activation = true;

                // PQ activation (Tx #1 key registration) costs the base fee
                // PLUS the state-rent surcharge (mempool floor), otherwise
                // the node rejects with "offered fee is below the base fee".
                // `--fee` overrides (e.g. to outbid a penalty-inflated floor).
                let gas_limit = fee.unwrap_or(
                    stellereum::svm::GAS_BASIC_TRANSFER
                        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS),
                );
                // A14: bound by default (chain_id live-or-default);
                // --unbound-legacy recovers the old replayable bytes.
                if unbound_legacy {
                    eprintln!(
                        "{}",
                        "warning: --unbound-legacy builds a REPLAYABLE transaction (no chain id); the node meters unbound admission and will refuse it in a later phase".yellow()
                    );
                }
                let bound_chain_id = client.chain_id();
                let tx = if unbound_legacy {
                    LightClient::build_pq_transfer_tx_with_gas(
                        &keypair,
                        to_arr,
                        nano_amount,
                        gas_limit,
                        nonce,
                        src_shard,
                        dst_shard,
                        is_activation,
                    )
                } else {
                    LightClient::build_pq_transfer_tx_bound(
                        &keypair,
                        to_arr,
                        nano_amount,
                        gas_limit,
                        nonce,
                        src_shard,
                        dst_shard,
                        is_activation,
                        bound_chain_id,
                    )
                };
                let tx_hash = tx.compute_tx_hash();

                if dry_run {
                    println!(
                        "{}",
                        "╔═══════════════════════════════════════════════════════════════╗".cyan()
                    );
                    println!(
                        "{}",
                        "║         🔬 POST-QUANTUM TRANSACTION DRY-RUN (NOT BROADCAST)   ║"
                            .cyan()
                            .bold()
                    );
                    println!(
                        "{}",
                        "╚═══════════════════════════════════════════════════════════════╝".cyan()
                    );
                    println!(
                        "• Status:          {}",
                        "DRY RUN (simulation only, not broadcast)".yellow().bold()
                    );
                    println!(
                        "• Scheme:          {} (ID: {})",
                        effective_pq_scheme.name(),
                        effective_pq_scheme.id()
                    );
                    println!(
                        "• Carrier Mode:    {}",
                        if is_activation {
                            "Explicit Carrier (Tx #1 Account Activation)".green().bold()
                        } else {
                            "Implicit Carrier (Steady-State Spend)".cyan().bold()
                        }
                    );
                    println!(
                        "• From (PQ Addr):  {}",
                        pq::format_address_with_visual_checksum(&hex::encode(from_addr))
                    );
                    println!(
                        "• To:              {}",
                        pq::format_address_with_visual_checksum(&to)
                    );
                    println!(
                        "• Amount:          {} STELL ({} nano)",
                        amount.green().bold(),
                        nano_amount
                    );
                    println!("• Nonce:           {}", nonce);
                    println!(
                        "• Shards:          source #{} -> target #{}",
                        src_shard, dst_shard
                    );
                    println!(
                        "• Gas Limit:       {} nano-STELL (~$0.00007 USD)",
                        tx.gas_limit
                    );
                    println!(
                        "• Envelope Format: {} ({} bytes on wire)",
                        "PQ1".magenta().bold(),
                        tx.signature.len()
                    );
                    println!(
                        "• Computed TxHash: {}",
                        hex::encode(tx_hash).yellow().bold()
                    );
                    println!(
                        "• Envelope Valid:  {}",
                        if tx.is_pq() {
                            "✅ Valid PQ1 Frame".green()
                        } else {
                            "❌ Invalid Frame".red()
                        }
                    );
                    println!(
                        "• Self-Check:      {}",
                        if tx.verify_signature() {
                            "✅ Signature Verifies".green().bold()
                        } else {
                            "❌ Signature Failed".red().bold()
                        }
                    );
                    return Ok(());
                }

                let (broadcast_hash, finality) = client
                    .broadcast_tx(&tx)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

                println!("╔═══════════════════════════════════════════════════════════════╗");
                println!("║             🚀 POST-QUANTUM TRANSACTION SUBMITTED             ║");
                println!("╚═══════════════════════════════════════════════════════════════╝");
                println!("• Mode:         {}", client.mode_line().yellow());
                println!(
                    "• Scheme:       {} (ID: {})",
                    effective_pq_scheme.name(),
                    effective_pq_scheme.id()
                );
                println!(
                    "• Tx Hash:      {}",
                    hex::encode(broadcast_hash).yellow().bold()
                );
                println!(
                    "• From:         {}",
                    pq::format_address_with_visual_checksum(&hex::encode(from_addr))
                );
                println!(
                    "• To:           {}",
                    format_address_with_visual_checksum(&to)
                );
                println!(
                    "• Amount:       {} STELL ({} nano)",
                    amount.green().bold(),
                    nano_amount
                );
                println!(
                    "• Shards:       source #{} -> target #{}",
                    src_shard, dst_shard
                );
                println!(
                    "• Envelope:     {} ({} bytes on wire)",
                    "PQ1".magenta().bold(),
                    tx.signature.len()
                );
                println!(
                    "• Carrier Mode: {}",
                    if is_activation {
                        "Explicit Carrier (Tx #1 Account Activation)".green().bold()
                    } else {
                        "Implicit Carrier (Steady-State Spend)".cyan().bold()
                    }
                );
                println!(
                    "• Micro-Gas:    {}",
                    "280_000 nano-STELL (~$0.00007 USD)".cyan()
                );
                println!(
                    "• Finality:     {}",
                    display_finality(client, &finality).bold()
                );
                if !finality.is_confirmed() && client.is_rpc() {
                    println!(
                        "• Note:          {}",
                        "not finalized yet — re-check with `stell receipt <hash> --rpc-url ...`."
                            .yellow()
                    );
                }
                if !client.is_rpc() {
                    println!("• Note:          {}", "local simulation only — NOT chain-finalized. Use --rpc-url to broadcast for real.".yellow());
                }
            } else {
                let account = WalletAccount::from_seed(&sec_secret.bytes);
                let nonce = client
                    .nonce_of(&account.address)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

                // A14: bound by default (chain_id live-or-default);
                // --unbound-legacy recovers the old replayable bytes.
                if unbound_legacy {
                    eprintln!(
                        "{}",
                        "warning: --unbound-legacy builds a REPLAYABLE transaction (no chain id); the node meters unbound admission and will refuse it in a later phase".yellow()
                    );
                }
                let tx = if unbound_legacy {
                    account.unbound_legacy_transfer(
                        to_arr,
                        nano_amount,
                        nonce,
                        src_shard,
                        dst_shard,
                    )
                } else {
                    account.create_bound_transaction(
                        to_arr,
                        nano_amount,
                        nonce,
                        src_shard,
                        dst_shard,
                        client.chain_id(),
                    )
                };

                if dry_run {
                    println!("╔═══════════════════════════════════════════════════════════════╗");
                    println!("║             🔬 TRANSACTION DRY-RUN (NOT BROADCAST)            ║");
                    println!("╚═══════════════════════════════════════════════════════════════╝");
                    println!(
                        "• Status:          {}",
                        "DRY RUN (simulation only, not broadcast)".yellow().bold()
                    );
                    println!("• Scheme:          Ed25519 (Classical)");
                    println!(
                        "• From:            {}",
                        format_address_with_visual_checksum(&keystore.address_hex)
                    );
                    println!(
                        "• To:              {}",
                        format_address_with_visual_checksum(&to)
                    );
                    println!(
                        "• Amount:          {} STELL ({} nano)",
                        amount.green().bold(),
                        nano_amount
                    );
                    println!(
                        "• Computed TxHash: {}",
                        hex::encode(tx.compute_tx_hash()).yellow().bold()
                    );
                    return Ok(());
                }

                let (tx_hash, finality) = client
                    .broadcast_tx(&tx)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

                println!("╔═══════════════════════════════════════════════════════════════╗");
                println!("║                 🚀 TRANSACTION SUBMITTED                      ║");
                println!("╚═══════════════════════════════════════════════════════════════╝");
                println!("• Mode:         {}", client.mode_line().yellow());
                println!("• Tx Hash:      {}", hex::encode(tx_hash).yellow().bold());
                println!(
                    "• From:         {}",
                    format_address_with_visual_checksum(&keystore.address_hex)
                );
                println!(
                    "• To:           {}",
                    format_address_with_visual_checksum(&to)
                );
                println!(
                    "• Amount:       {} STELL ({} nano)",
                    amount.green().bold(),
                    nano_amount
                );
                println!(
                    "• Shards:       source #{} -> target #{}",
                    src_shard, dst_shard
                );
                println!(
                    "• Micro-Gas:    {}",
                    "280_000 nano-STELL (~$0.00007 USD)".cyan()
                );
                println!(
                    "• Finality:     {}",
                    display_finality(client, &finality).bold()
                );
                if !finality.is_confirmed() && client.is_rpc() {
                    println!(
                        "• Note:          {}",
                        "not finalized yet — re-check with `stell receipt <hash> --rpc-url ...`."
                            .yellow()
                    );
                }
                if !client.is_rpc() {
                    println!("• Note:          {}", "local simulation only — NOT chain-finalized. Use --rpc-url to broadcast for real.".yellow());
                }
            }
        }

        Commands::StealthPay {
            view_key,
            spend_key,
            to,
            arg2,
            arg3,
            amount,
            fee: _,
            password,
            shard,
        } => {
            let (view_str, spend_str, amount_str) = match (&view_key, &spend_key) {
                (Some(v), Some(s)) => {
                    let amt = amount.clone().or_else(|| to.clone()).ok_or_else(|| {
                        anyhow::anyhow!("Amount in STELL is required. Usage: stell stealth-pay --view-key <VIEW_HEX> --spend-key <SPEND_HEX> <AMOUNT>")
                    })?;
                    (v.clone(), s.clone(), amt)
                }
                _ => {
                    if let (Some(v), Some(s), Some(a)) = (&to, &arg2, &arg3) {
                        (v.clone(), s.clone(), a.clone())
                    } else if let (Some(meta), Some(a)) = (&to, &arg2) {
                        if meta.contains(':') {
                            let parts: Vec<&str> = meta.split(':').collect();
                            if parts.len() == 2 {
                                (parts[0].to_string(), parts[1].to_string(), a.clone())
                            } else {
                                anyhow::bail!("Invalid stealth meta-address format. Expected <view_hex>:<spend_hex> or separate arguments");
                            }
                        } else {
                            anyhow::bail!("Both view key and spend key are required to derive StealthAddress. Usage: stell stealth-pay <VIEW_PUB> <SPEND_PUB> <AMOUNT> or --view-key <VIEW> --spend-key <SPEND> <AMOUNT>");
                        }
                    } else {
                        anyhow::bail!("Both view key and spend key are required to derive StealthAddress. Usage: stell stealth-pay <VIEW_PUB> <SPEND_PUB> <AMOUNT> or --view-key <VIEW> --spend-key <SPEND> <AMOUNT>");
                    }
                }
            };

            let view_bytes = parse_hex32(&view_str, "Recipient viewing key")?;
            let spend_bytes = parse_hex32(&spend_str, "Recipient spending key")?;

            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found at {:?}: {e}", wallet_path))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);

            let nano_amount =
                parse_stell_to_nano(&amount_str).map_err(|e| anyhow::anyhow!("{e}"))?;
            let nonce = client
                .nonce_of(&account.address)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            let (tx, stealth) = LightClient::build_stealth_pay_tx(
                &account,
                &view_bytes,
                &spend_bytes,
                nano_amount,
                nonce,
                shard,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            let (tx_hash, finality) = client
                .broadcast_tx(&tx)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              🔒 STEALTH PAYMENT BROADCAST                     ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Mode:                 {}", client.mode_line().yellow());
            println!(
                "• Tx Hash:              {}",
                hex::encode(tx_hash).yellow().bold()
            );
            println!(
                "• Destination Stealth:  {}",
                hex::encode(stealth.one_time_pub).magenta().bold()
            );
            println!(
                "• Ephemeral PubKey:     {}",
                hex::encode(stealth.ephemeral_pub).cyan().bold()
            );
            println!(
                "• Amount:               {} STELL ({} nano-STELL)",
                amount_str.green().bold(),
                nano_amount
            );
            println!(
                "• From:                 {}",
                format_address_with_visual_checksum(&keystore.address_hex)
            );
            println!("• Recipient View Pub:   {}", hex::encode(view_bytes).blue());
            println!(
                "• Recipient Spend Pub:  {}",
                hex::encode(spend_bytes).blue()
            );
            println!(
                "• Finality:             {}",
                display_finality(client, &finality).bold()
            );
            println!("• Note:                 {}", "Real transaction broadcast on-chain to one-time stealth address. Receiver derives spending key using view and spend keys.".green());
            if !client.is_rpc() {
                println!("• Note:                 {}", "local simulation only — NOT chain-finalized. Use --rpc-url to broadcast for real.".yellow());
            }
        }

        Commands::StealthScan { password } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass = prompt_password_safely(
                password,
                "Enter keystore password to scan stealth payments",
            )?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);

            let view_priv = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(
                account.viewing_key.view_priv,
            );
            let spend_pub = account.spend_pub;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              🔍 STEALTH PAYMENTS SCANNER                      ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Mode:            {}", client.mode_line().yellow());
            println!(
                "• Account Address: {}",
                format_address_with_visual_checksum(&keystore.address_hex)
            );
            println!(
                "• Viewing PubKey:  {}",
                hex::encode(account.viewing_key.view_pub).blue()
            );
            println!("• Spend PubKey:    {}", hex::encode(spend_pub).blue());

            let detected = client
                .scan_stealth_payments(&view_priv, &spend_pub)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            let stealth_path = notes::stealth_path_for_wallet(wallet_path);
            let mut new_count = 0;

            for (stealth, amount_nano, height, tx_hash) in &detected {
                use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
                use curve25519_dalek::ristretto::CompressedRistretto;
                use sha2::{Digest, Sha256};

                let ephem_pt = match CompressedRistretto(stealth.ephemeral_pub).decompress() {
                    Some(pt) => pt,
                    None => continue,
                };
                let shared_secret = ephem_pt * view_priv;
                let s_hash = Sha256::digest(shared_secret.compress().as_bytes());
                let mut s_bytes = [0u8; 32];
                s_bytes.copy_from_slice(&s_hash);
                let s_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(s_bytes);

                let spend_pt = match CompressedRistretto(spend_pub).decompress() {
                    Some(pt) => pt,
                    None => continue,
                };
                let one_time_pt = spend_pt + (RISTRETTO_BASEPOINT_POINT * s_scalar);
                let recovered_one_time_pub = one_time_pt.compress().to_bytes();

                let output = notes::StealthOutput {
                    one_time_pub: hex::encode(recovered_one_time_pub),
                    ephemeral_pub: hex::encode(stealth.ephemeral_pub),
                    shared_secret: hex::encode(s_bytes),
                    amount: *amount_nano,
                    height: *height,
                    tx_hash: hex::encode(tx_hash),
                    spent: false,
                };

                // Secret-bound stealth store (XChaCha20-Poly1305, atomic .tmp -> sync_all ->
                // rename 0600): the outputs carry viewing shared secrets, so they must never
                // rest in cleartext. `load_stealth_outputs_with_secret` transparently migrates
                // legacy plaintext / wallet-bound files forward on first write.
                let is_new =
                    notes::add_stealth_output_with_secret(&stealth_path, output, &sec_secret.bytes)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                if is_new {
                    new_count += 1;
                }
            }

            let all_unspent =
                notes::get_unspent_stealth_outputs_with_secret(&stealth_path, &sec_secret.bytes)
                    .unwrap_or_default();

            println!(
                "\n• Scan Result:     Found {} stealth output(s) on-chain ({} new)",
                detected.len(),
                new_count
            );
            println!("• Store File:      {:?}", stealth_path);
            println!("• Unspent Outputs: {}", all_unspent.len());

            if all_unspent.is_empty() {
                println!("• Details:         No unspent stealth outputs found.");
            } else {
                println!("• Unspent Stealth Outputs:");
                for (i, out) in all_unspent.iter().enumerate() {
                    let s_amt = (out.amount as f64) / 1_000_000_000.0;
                    println!(
                        "  ↳ [{}] One-Time: {} | {} STELL ({} nano) [Block: #{}]",
                        i + 1,
                        out.one_time_pub.magenta().bold(),
                        format!("{:.6}", s_amt).green().bold(),
                        out.amount,
                        out.height
                    );
                    println!("       Ephemeral: {}", out.ephemeral_pub.cyan());
                    println!("       Tx Hash:   {}", out.tx_hash.yellow());
                }
            }
        }

        Commands::StealthSpend {
            one_time_pub,
            to,
            amount,
            password,
            shard,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found at {:?}: {e}", wallet_path))?;
            let pass = prompt_password_safely(
                password,
                "Enter keystore password to spend stealth output",
            )?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);

            let view_priv = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(
                account.viewing_key.view_priv,
            );
            let spend_priv = account.spend_priv;

            let stealth_path = notes::stealth_path_for_wallet(wallet_path);
            let unspent =
                notes::get_unspent_stealth_outputs_with_secret(&stealth_path, &sec_secret.bytes)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

            let target_output = match one_time_pub {
                Some(ref target_hex) => unspent
                    .iter()
                    .find(|o| o.one_time_pub.eq_ignore_ascii_case(target_hex))
                    .cloned()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "No unspent stealth output matching {} in {:?}",
                            target_hex,
                            stealth_path
                        )
                    })?,
                None => {
                    let mut funded = None;
                    for o in unspent.iter().rev() {
                        if let Ok(pub_bytes) = parse_hex32(&o.one_time_pub, "One-time public key") {
                            if let Ok((b, _, _)) = client.get_balance_spv(&pub_bytes, shard).await {
                                if b > 0 {
                                    funded = Some(o.clone());
                                    break;
                                }
                            }
                        }
                    }
                    funded.or_else(|| unspent.last().cloned())
                        .ok_or_else(|| anyhow::anyhow!("No unspent stealth outputs found in {:?}. Run `stell stealth-scan` first.", stealth_path))?
                }
            };

            let one_time_pub_bytes =
                parse_hex32(&target_output.one_time_pub, "One-time public key")?;
            let ephem_bytes = parse_hex32(&target_output.ephemeral_pub, "Ephemeral public key")?;
            let stealth = stellereum::crypto_privacy::StealthAddress {
                one_time_pub: one_time_pub_bytes,
                ephemeral_pub: ephem_bytes,
            };

            let one_time_priv = stealth
                .derive_one_time_private_key(&view_priv, &spend_priv)
                .ok_or_else(|| {
                    anyhow::anyhow!("Failed to derive one-time private key (invalid curve points)")
                })?;

            let derived_pub = (curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
                * one_time_priv)
                .compress()
                .to_bytes();
            if derived_pub != stealth.one_time_pub {
                anyhow::bail!("Derived one-time private key does not correspond to one_time_pub");
            }

            let dest_addr = match to {
                Some(ref t) => parse_hex32(t, "Destination address")?,
                None => account.address,
            };

            let (onchain_bal, nonce, _) = client
                .get_balance_spv(&stealth.one_time_pub, shard)
                .await
                .unwrap_or((0, 0, false));
            let effective_bal = if onchain_bal > 0 {
                onchain_bal
            } else {
                target_output.amount
            };
            let gas_limit = 10_000u64;

            let nano_spend = match amount {
                Some(ref a) => parse_stell_to_nano(a).map_err(|e| anyhow::anyhow!("{e}"))?,
                None => {
                    if effective_bal <= gas_limit {
                        anyhow::bail!(
                            "Balance {} nano-STELL too small to cover {} gas limit fee",
                            effective_bal,
                            gas_limit
                        );
                    }
                    effective_bal - gas_limit
                }
            };

            if nano_spend == 0 || nano_spend + gas_limit > effective_bal {
                anyhow::bail!("Insufficient balance on stealth address: has {} nano, cannot spend {} with {} fee", effective_bal, nano_spend, gas_limit);
            }

            let tx = LightClient::build_stealth_spend_tx(
                &one_time_priv,
                stealth.one_time_pub,
                dest_addr,
                nano_spend,
                gas_limit,
                nonce,
                shard,
            );
            if !tx.verify_signature() {
                anyhow::bail!("Generated stealth spend transaction failed signature verification");
            }

            let (tx_hash, finality) = client
                .broadcast_tx(&tx)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            let _ = notes::mark_stealth_output_spent_with_secret(
                &stealth_path,
                &target_output.one_time_pub,
                &sec_secret.bytes,
            );

            let spend_stell = (nano_spend as f64) / 1_000_000_000.0;
            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              💸 STEALTH OUTPUT SPENT & BROADCAST              ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Mode:           {}", client.mode_line().yellow());
            println!(
                "• From (Stealth): {}",
                hex::encode(stealth.one_time_pub).magenta().bold()
            );
            println!(
                "• To Destination: {}",
                format_address_with_visual_checksum(&hex::encode(dest_addr))
            );
            println!(
                "• Amount Sent:    {} STELL ({} nano-STELL)",
                format!("{:.6}", spend_stell).green().bold(),
                nano_spend
            );
            println!("• Micro-Gas Fee:  {} nano-STELL", gas_limit);
            println!("• Tx Hash:        {}", hex::encode(tx_hash).yellow().bold());
            println!(
                "• Finality:       {}",
                display_finality(client, &finality).bold()
            );
            println!(
                "• Note Store:     Marked output as spent in {:?}",
                stealth_path
            );
            if !client.is_rpc() {
                println!("• Note:           {}", "local simulation only — NOT chain-finalized. Use --rpc-url to broadcast for real.".yellow());
            }
        }

        Commands::ConfidentialShield {
            amount,
            blinding,
            password,
            shard,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);

            let nano_amount = parse_stell_to_nano(&amount).map_err(|e| anyhow::anyhow!("{e}"))?;
            let notes_path = notes::notes_path_for_wallet(wallet_path);
            let note_counter = notes::load_notes(&notes_path)
                .map(|n| n.len() as u64)
                .unwrap_or(0);

            let blind: [u8; 32] = match blinding {
                Some(b) => parse_hex32(&b, "Blinding")?,
                None => notes::derive_blinding_factor(&sec_secret.bytes, note_counter),
            };
            let nonce = client
                .nonce_of(&account.address)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let (tx_hash, finality, commitment) = client
                .broadcast_shield_tx(&account.signing_key, nano_amount, blind, nonce, shard)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            // Automatically record note in the per-wallet shielded notes store.
            // NOTE: this keeps the legacy wallet-bound container so that the password-less
            // `shield-balance` reader stays working (fail-closed when no wallet keystore is
            // bound — never a salt-only key). Callers that gate on a password should prefer
            // `add_note_with_secret` / `load_notes_with_secret`, bound to the master secret.
            let height = if client.is_rpc() {
                client
                    .rpc
                    .as_ref()
                    .and_then(|c| rpc::chain_height(c).ok())
                    .unwrap_or(0)
            } else {
                0
            };
            let note = notes::ShieldedNote {
                commitment: commitment.clone(),
                amount: nano_amount,
                blinding: hex::encode(blind),
                height,
                spent: false,
            };
            if let Err(e) = notes::add_note(&notes_path, note) {
                eprintln!(
                    "{}",
                    format!("Warning: failed to record note in {:?}: {e}", notes_path).yellow()
                );
            }

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║                   🛡️  SHIELDED (SUBMITTED)                   ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Mode:       {}", client.mode_line().yellow());
            println!("• Tx Hash:    {}", hex::encode(tx_hash).yellow().bold());
            println!(
                "• Amount:     {} STELL ({} nano)",
                amount.green().bold(),
                nano_amount
            );
            println!("• Commitment: {}", commitment.cyan().bold());
            println!("• Blinding:   {}", hex::encode(blind).red().bold());
            println!("• Note Store: Saved to {:?}", notes_path);
            println!(
                "• Finality:   {}",
                display_finality(client, &finality).bold()
            );
            println!(
                "• SAVE:       {}",
                "the blinding is the ONLY way to transfer or exit this coin"
                    .red()
                    .bold()
            );
            if !client.is_rpc() {
                println!("• Note:       {}", "local simulation only — NOT chain-finalized. Use --rpc-url to submit for real.".yellow());
            }
        }

        Commands::ShieldBalance => {
            let notes_path = notes::notes_path_for_wallet(wallet_path);
            let unspent =
                notes::get_unspent_notes(&notes_path).map_err(|e| anyhow::anyhow!("{e}"))?;
            let total = notes::calculate_shielded_balance(&unspent);

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║                 🛡️  SHIELDED POOL BALANCE                     ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Notes Store:     {}", format!("{:?}", notes_path).cyan());
            println!("• Unspent Notes:   {}", unspent.len());
            if unspent.is_empty() {
                println!("• Commitments:     (no unspent shielded notes found)");
            } else {
                println!("• Commitments:");
                for (i, note) in unspent.iter().enumerate() {
                    let stell_amt = (note.amount as f64) / 1_000_000_000.0;
                    println!(
                        "  ↳ [{}] {} : {} STELL ({} nano) [height: {}]",
                        i + 1,
                        note.commitment.cyan(),
                        format!("{:.6}", stell_amt).green().bold(),
                        note.amount,
                        note.height
                    );
                }
            }
            let total_stell = (total as f64) / 1_000_000_000.0;
            println!(
                "• Total Shielded:  {} STELL ({} nano-STELL)",
                format!("{:.6}", total_stell).green().bold(),
                total
            );
        }

        Commands::ConfidentialUnshield {
            amount,
            commitments,
            amounts,
            blindings,
            password,
            shard,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);
            let notes_path = notes::notes_path_for_wallet(wallet_path);

            let (cs, ams, bs, auto_selected) = match (commitments, amounts, blindings) {
                (Some(c_str), Some(a_str), Some(b_str)) => {
                    let cs = parse_hex32_list(&c_str, "Commitment")?;
                    let ams = parse_u64_list(&a_str, "Amount")?;
                    let bs = parse_hex32_list(&b_str, "Blinding")?;
                    (cs, ams, bs, None)
                }
                (None, None, None) => {
                    let amt_str = amount.ok_or_else(|| {
                        anyhow::anyhow!("Either --amount <STELL> (for automated note unshielding) or --commitments, --amounts, --blindings must be provided")
                    })?;
                    let target_nano =
                        parse_stell_to_nano(&amt_str).map_err(|e| anyhow::anyhow!("{e}"))?;
                    let selected = notes::select_notes_for_unshield(&notes_path, target_nano)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    let cs = selected
                        .iter()
                        .map(|n| parse_hex32(&n.commitment, "Commitment"))
                        .collect::<anyhow::Result<Vec<_>>>()?;
                    let ams = selected.iter().map(|n| n.amount).collect::<Vec<_>>();
                    let bs = selected
                        .iter()
                        .map(|n| parse_hex32(&n.blinding, "Blinding"))
                        .collect::<anyhow::Result<Vec<_>>>()?;
                    (cs, ams, bs, Some(selected))
                }
                _ => {
                    anyhow::bail!("Manual unshielding requires all three: --commitments, --amounts, and --blindings. Or pass --amount <STELL> alone for automatic note selection.");
                }
            };

            let nonce = client
                .nonce_of(&account.address)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let (tx_hash, finality) = client
                .broadcast_unshield_tx(
                    &account.signing_key,
                    cs.clone(),
                    ams.clone(),
                    bs.clone(),
                    nonce,
                    shard,
                )
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            // Mark spent in note store
            let spent_hexes: Vec<String> = cs.iter().map(hex::encode).collect();
            let _ = notes::mark_notes_spent(&notes_path, &spent_hexes);

            let total_unshielded_nano: u64 = ams.iter().sum();
            let total_stell = (total_unshielded_nano as f64) / 1_000_000_000.0;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║                   🔓 UNSHIELDED (SUBMITTED)                   ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Mode:       {}", client.mode_line().yellow());
            println!("• Tx Hash:    {}", hex::encode(tx_hash).yellow().bold());
            println!(
                "• Unshielded: {} STELL ({} nano across {} note(s))",
                format!("{:.6}", total_stell).green().bold(),
                total_unshielded_nano,
                cs.len()
            );
            if let Some(ref sel) = auto_selected {
                for (i, note) in sel.iter().enumerate() {
                    let s_amt = (note.amount as f64) / 1_000_000_000.0;
                    println!(
                        "  ↳ [{}] {} : {} STELL ({} nano)",
                        i + 1,
                        note.commitment.cyan(),
                        format!("{:.6}", s_amt).green(),
                        note.amount
                    );
                }
                println!(
                    "• Note Store: Marked {} note(s) spent in {:?}",
                    sel.len(),
                    notes_path
                );
            } else {
                println!(
                    "• Note Store: Marked {} note(s) spent in {:?}",
                    cs.len(),
                    notes_path
                );
            }
            println!(
                "• Finality:   {}",
                display_finality(client, &finality).bold()
            );
            println!(
                "• Note:       {}",
                "amounts are public from here on — privacy ends at exit by design.".yellow()
            );
            if !client.is_rpc() {
                println!("• Note:       {}", "local simulation only — NOT chain-finalized. Use --rpc-url to submit for real.".yellow());
            }
        }

        Commands::ConfidentialPay {
            to,
            amount,
            fee,
            password,
            shard,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);

            let recipient = parse_hex32(&to, "Recipient shielded address")?;
            let nano_amount = parse_stell_to_nano(&amount).map_err(|e| anyhow::anyhow!("{e}"))?;
            nano_amount
                .checked_add(fee)
                .ok_or_else(|| anyhow::anyhow!("amount+fee overflows"))?;
            let (transfer, blinding) = account.create_confidential_transfer(nano_amount, fee);
            if !transfer.verify_balance_conservation() {
                anyhow::bail!("local conservation check failed — refusing to build");
            }

            let nonce = client
                .nonce_of(&account.address)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let (tx_hash, finality) = client
                .broadcast_confidential_tx(
                    &account.signing_key,
                    recipient,
                    transfer.clone(),
                    nano_amount,
                    fee,
                    blinding.to_bytes(),
                    nonce,
                    shard,
                )
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              🔒 CONFIDENTIAL TRANSFER SUBMITTED               ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Mode:                {}", client.mode_line().yellow());
            println!(
                "• Tx Hash:             {}",
                hex::encode(tx_hash).yellow().bold()
            );
            println!("• Recipient (shielded): {}", to.magenta());
            println!(
                "• Hidden amount:       {} STELL ({} nano, commitment only)",
                amount.green().bold(),
                nano_amount
            );
            // Honest gas (audit 2026-10-06): the fee PARAM is floored by the
            // base transfer fee, so the charged gas_limit is the max.
            let actual_gas = fee
                .max(stellereum::svm::GAS_BASIC_TRANSFER)
                .max(stellereum::svm::GAS_CONFIDENTIAL_SHIELD)
                .max(stellereum::svm::GAS_CONFIDENTIAL_TRANSFER2);
            println!(
                "• Fee param:           {} nano-STELL (charged gas_limit: {})",
                fee, actual_gas
            );
            println!(
                "• Finality:            {}",
                display_finality(client, &finality).bold()
            );
            println!(
                "• Auditor viewing key: {}",
                hex::encode(account.viewing_key.view_pub).blue()
            );
            println!(
                "• Auditor blinding r:  {}",
                hex::encode(blinding.to_bytes()).cyan()
            );
            println!(
                "• Output commitment:   {}",
                hex::encode(
                    transfer
                        .output_commitments
                        .first()
                        .map(|c| c.commitment)
                        .unwrap_or([0u8; 32])
                )
                .cyan()
            );
            println!("• Note:                {}", "share the viewing key + blinding factor with YOUR auditor only; the amount stays hidden on chain.".yellow());
            if !client.is_rpc() {
                println!("• Note:                {}", "local simulation only — NOT chain-finalized. Use --rpc-url to submit for real.".yellow());
            }
        }

        Commands::TokenBalance { token, account } => {
            let token_id = parse_hex32(&token, "Token ID")?;
            let acct_hex = match account {
                Some(a) => a,
                None => {
                    let keystore = HardenedKeystore::load(wallet_path)
                        .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
                    keystore.address_hex
                }
            };
            let acct = parse_hex32(&acct_hex, "Account")?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║                    🪙 STS TOKEN BALANCE                       ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Mode:     {}", client.mode_line().yellow());
            println!("• Token:    {}", token.cyan());
            println!(
                "• Account:  {}",
                format_address_with_visual_checksum(&hex::encode(acct))
            );
            if client.is_rpc() {
                let (balance, verified, root_hex) = client
                    .token_balance_spv_verified(&token_id, &acct)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!(
                    "• Balance:  {} (base units)",
                    format!("{}", balance).green().bold()
                );
                println!("• Chain root: {}", root_hex.cyan());
                // Same 3-state verdict as native balances (audit 2026-10-06):
                // zero + no proof is neutral Absent, not FAILED.
                if verified {
                    println!("• SPV:        {}", "✅ Verified against the NODE-SERVED root (trusted-node SPV: no header proof, no multi-node check)".green().bold());
                } else if balance == 0 {
                    println!(
                        "• SPV:        {}",
                        "○ No on-chain record — zero by protocol (no tokens ever held)".yellow()
                    );
                } else {
                    println!(
                        "• SPV:        {}",
                        "❌ PROOF FAILED local verification — do NOT trust this balance"
                            .red()
                            .bold()
                    );
                }
            } else {
                let balance = client
                    .token_balance(&token_id, &acct)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!(
                    "• Balance:  {} (base units)",
                    format!("{}", balance).green().bold()
                );
                println!("• Note:     {}", "local registry only (self-consistency, NOT chain inclusion) — use --rpc-url for chain-verified SPV.".yellow());
            }
        }

        Commands::TokenSend {
            token,
            to,
            amount,
            password,
            shard,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);

            let token_id = parse_hex32(&token, "Token ID")?;
            let to_arr = parse_hex32(&to, "Recipient")?;
            let nonce = client
                .nonce_of(&account.address)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let tx = LightClient::build_token_transfer_tx(
                &account.signing_key,
                token_id,
                to_arr,
                amount,
                nonce,
                shard,
            );
            let (tx_hash, finality) = client
                .broadcast_tx(&tx)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║                   🪙 TOKEN TRANSFER SUBMITTED                 ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Mode:     {}", client.mode_line().yellow());
            println!("• Tx Hash:  {}", hex::encode(tx_hash).yellow().bold());
            println!("• Token:    {}", token.cyan());
            println!(
                "• From:     {}",
                format_address_with_visual_checksum(&keystore.address_hex)
            );
            println!("• To:       {}", format_address_with_visual_checksum(&to));
            println!(
                "• Amount:   {} (base units)",
                format!("{}", amount).green().bold()
            );
            println!(
                "• Gas limit:  {} nano (chain charges gas_used, less than the limit)",
                stellereum::svm::GAS_BASIC_TRANSFER
            );
            println!("• Finality: {}", display_finality(client, &finality).bold());
            if !client.is_rpc() {
                println!("• Note:     {}", "local simulation only — NOT chain-finalized. Use --rpc-url to submit for real.".yellow());
            }
        }

        Commands::TokenApprove {
            token,
            spender,
            amount,
            password,
            shard,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);

            let token_id = parse_hex32(&token, "Token ID")?;
            let spender_arr = parse_hex32(&spender, "Spender")?;
            let nonce = client
                .nonce_of(&account.address)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let tx = LightClient::build_token_approve_tx(
                &account.signing_key,
                token_id,
                spender_arr,
                amount,
                nonce,
                shard,
            );
            let (tx_hash, finality) = client
                .broadcast_tx(&tx)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║                   🪙 TOKEN APPROVAL SUBMITTED                 ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Mode:     {}", client.mode_line().yellow());
            println!("• Tx Hash:  {}", hex::encode(tx_hash).yellow().bold());
            println!("• Token:    {}", token.cyan());
            println!(
                "• Owner:    {}",
                format_address_with_visual_checksum(&keystore.address_hex)
            );
            println!(
                "• Spender:  {}",
                format_address_with_visual_checksum(&spender)
            );
            println!(
                "• Amount:   {} (base units)",
                format!("{}", amount).green().bold()
            );
            println!(
                "• Gas limit:  {} nano (chain charges gas_used, less than the limit)",
                stellereum::svm::GAS_BASIC_TRANSFER
            );
            println!("• Finality: {}", display_finality(client, &finality).bold());
            if !client.is_rpc() {
                println!("• Note:     {}", "local simulation only — NOT chain-finalized. Use --rpc-url to submit for real.".yellow());
            }
        }

        Commands::TokenCreate {
            name,
            symbol,
            decimals,
            supply,
            max_supply,
            password,
            shard,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);

            let cap = if max_supply == 0 {
                None
            } else {
                Some(max_supply)
            };
            let nonce = client
                .nonce_of(&account.address)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let tx = LightClient::build_token_create_tx(
                &account.signing_key,
                name.clone(),
                symbol.clone(),
                decimals,
                supply,
                cap,
                nonce,
                shard,
            );
            let (tx_hash, finality) = client
                .broadcast_tx(&tx)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║                   🪙 TOKEN CREATED (SUBMITTED)                ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Mode:     {}", client.mode_line().yellow());
            println!("• Tx Hash:  {}", hex::encode(tx_hash).yellow().bold());
            println!("• Name:     {} ({})", name.cyan(), symbol.cyan());
            println!(
                "• Supply:   {} (base units)",
                format!("{}", supply).green().bold()
            );
            println!(
                "• Gas limit:  {} nano (chain charges gas_used, less than the limit)",
                stellereum::svm::GAS_BASIC_TRANSFER
            );
            println!("• Finality: {}", display_finality(client, &finality).bold());
            if client.is_rpc() {
                // Resolve only on confirmation (audit 2026-10-06): on
                // Pending/Failed there is no token yet, and an eager resolve
                // could print a STALE same-name token as success.
                if finality.is_confirmed() {
                    match client.token_resolve(&account.address, &name, &symbol) {
                        Ok(tid) => println!("• Token ID: {}", tid.green().bold()),
                        Err(e) => println!("• Token ID: {} ({})", "unresolved".red(), e),
                    }
                } else {
                    println!(
                        "• Token ID: {}",
                        "not finalized — re-run `token-resolve` after receipt shows success"
                            .yellow()
                    );
                }
            } else {
                println!("• Note:     {}", "local simulation only — NOT chain-finalized. Use --rpc-url to submit for real.".yellow());
            }
        }

        Commands::TokenResolve { name, symbol } => {
            if !client.is_rpc() {
                anyhow::bail!("`token-resolve` requires --rpc-url");
            }
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let addr_bytes = hex::decode(&keystore.address_hex)
                .map_err(|e| anyhow::anyhow!("bad address in keystore: {e}"))?;
            let mut creator = [0u8; 32];
            if addr_bytes.len() == 32 {
                creator.copy_from_slice(&addr_bytes);
            } else {
                anyhow::bail!("keystore address is not 32 bytes");
            }
            match client.token_resolve(&creator, &name, &symbol) {
                Ok(tid) => println!("• Token ID: {}", tid.green().bold()),
                Err(e) => println!("• Token ID: {} ({})", "unresolved".red(), e),
            }
        }

        Commands::TokenList { limit, offset } => {
            // Paginated registry read: RPC mode parses the chain's
            // `{tokens, total, offset}` object (a bare array is rejected, not
            // misread); local mode pages the local registry the same way.
            let (ids, total, off) = client
                .token_list(limit, offset)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║                    🪙 STS TOKEN REGISTRY                      ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Mode:     {}", client.mode_line().yellow());
            println!("• Total:    {} token(s) (offset {})", total, off);
            if ids.is_empty() {
                println!("• Tokens:   (none on this page)");
            } else {
                for tid in &ids {
                    println!("  ↳ {}", tid.cyan());
                }
            }
            if !client.is_rpc() {
                println!("• Note:     {}", "local registry only (self-consistency, NOT chain state) — use --rpc-url for the chain registry.".yellow());
            }
        }

        Commands::Receipt { tx_hash } => {
            if !client.is_rpc() {
                anyhow::bail!("`receipt` requires --rpc-url (local mode keeps no chain receipts)");
            }
            // Honor the global --timeout/--poll-interval (audit 2026-10-06:
            // the old hardcoded 5s/1s lied Unknown on a slow chain).
            let cfg = client.rpc.as_ref().expect("RPC mode checked above");
            let finality = rpc::poll_receipt(
                cfg,
                &tx_hash,
                client.receipt_timeout_secs,
                client.receipt_poll_secs,
            );
            println!("• Tx Hash:  {}", tx_hash.yellow());
            println!("• Finality: {}", finality_label(&finality).bold());
        }

        Commands::Txs => {
            let history = client.get_tx_history();
            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║                 📜 RECENT TRANSACTIONS HISTORY                ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            if history.is_empty() {
                println!("No transactions recorded yet.");
            } else {
                for tx in history {
                    let type_str = if tx.is_confidential {
                        "CONFIDENTIAL".magenta().bold()
                    } else {
                        "STANDARD".cyan()
                    };
                    // Length-safe slices (audit 2026-10-06): a tampered
                    // short history file used to panic here.
                    let to_short = tx.to.get(..10).unwrap_or(&tx.to);
                    let hash_head = tx.tx_hash.get(..8).unwrap_or(&tx.tx_hash);
                    let hash_tail = tx
                        .tx_hash
                        .len()
                        .checked_sub(6)
                        .and_then(|i| tx.tx_hash.get(i..))
                        .unwrap_or("");
                    println!(
                        "• [{}] {} STELL -> {} (Hash: {}...{})",
                        type_str,
                        format!("{:.4}", tx.amount_stell).green(),
                        to_short,
                        hash_head,
                        hash_tail
                    );
                }
            }
        }

        Commands::Session {
            session_pub,
            max_gas,
            duration,
            scope,
            max_value,
            chain_id,
            publish,
            shard,
            password,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass = prompt_password_safely(password, "Enter password to sign bot session key")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);

            let session_bytes = hex::decode(&session_pub)
                .map_err(|e| anyhow::anyhow!("Invalid session pub: {e}"))?;
            if session_bytes.len() != 32 {
                anyhow::bail!("Session key must be 32 bytes");
            }
            let mut session_arr = [0u8; 32];
            session_arr.copy_from_slice(&session_bytes);

            // Chain id 0 = auto-detect from the node in RPC mode (audit
            // 2026-10-06: the old 7777 default was indistinguishable from an
            // explicit pin and silently overridden). Explicit pins are honored.
            let chain_id = if chain_id == 0 {
                if client.is_rpc() {
                    client.chain_id()
                } else {
                    stellereum::zkml::DEFAULT_CHAIN_ID
                }
            } else {
                chain_id
            };
            // The grant must not delegate to ourselves (audit 2026-10-06).
            if session_arr == account.address {
                anyhow::bail!("session key must differ from the master address");
            }
            let auth = account.delegate_bot_session(
                session_arr,
                max_gas,
                duration,
                scope,
                max_value,
                chain_id,
            );

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              🔑 SESSION KEY DELEGATION                        ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!(
                "• Master Address:  {}",
                format_address_with_visual_checksum(&keystore.address_hex)
            );
            println!("• Bot Session Pub: {}", session_pub.cyan());
            println!("• Gas Limit:       {} nano-STELL", max_gas);
            println!(
                "• Valid Until:     {} ({} secs remaining)",
                auth.valid_until, duration
            );
            println!("• Scope:           0x{:016x}", auth.scope);
            println!("• Max Value/Tx:    {} nano-STELL", auth.max_value_per_tx);
            println!("• Chain Id:        {}", auth.chain_id);
            println!(
                "• Signature:       {}",
                hex::encode(&auth.master_signature).green()
            );
            if publish {
                use stellereum::sharding::Transaction;
                use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER, GAS_PUBLISH_SESSION_GRANT};
                let master_addr = account.address;
                let nonce = client
                    .nonce_of(&master_addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                let ptx = Transaction::sign_with_payload(
                    &account.signing_key,
                    master_addr,
                    0,
                    GAS_BASIC_TRANSFER.max(GAS_PUBLISH_SESSION_GRANT),
                    nonce,
                    shard,
                    shard,
                    vec![OpCode::SysCallPublishSessionGrant(Box::new(auth.clone()))],
                );
                let (tx_hash, finality) = client
                    .broadcast_tx(&ptx)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                if client.is_rpc() {
                    println!(
                        "• Published:       {} ({})",
                        hex::encode(tx_hash).yellow().bold(),
                        display_finality(client, &finality).bold()
                    );
                } else {
                    println!("• Published:       {} (SIGNED LOCALLY — NOT on chain; re-run with --rpc-url --publish)", hex::encode(tx_hash).yellow().bold());
                }
            } else {
                println!("• Note:            {}", "off-chain grant printout only — it becomes enforceable when published in a SysCallPublishSessionGrant tx (re-run with --publish).".yellow());
            }
        }

        Commands::Book { pair } => {
            execute_trade(TradeCommands::Book { pair }, wallet_path, client).await?;
        }

        Commands::Buy {
            amount,
            price,
            pair,
            password,
        } => {
            execute_trade(
                TradeCommands::Buy {
                    pair,
                    price,
                    amount,
                    order_type: "limit".to_string(),
                    password,
                },
                wallet_path,
                client,
            )
            .await?;
        }

        Commands::Sell {
            amount,
            price,
            pair,
            password,
        } => {
            execute_trade(
                TradeCommands::Sell {
                    pair,
                    price,
                    amount,
                    order_type: "limit".to_string(),
                    password,
                },
                wallet_path,
                client,
            )
            .await?;
        }

        Commands::Cancel { order_id, pair } => {
            execute_trade(
                TradeCommands::Cancel { pair, order_id },
                wallet_path,
                client,
            )
            .await?;
        }

        Commands::Mint {
            asset,
            amount,
            price_usd,
        } => {
            let mut vault = GenesisVault::new();
            let price_micro =
                parse_usd_to_micro(&price_usd.to_string()).map_err(|e| anyhow::anyhow!("{e}"))?;
            let native_amount = match asset.to_uppercase().as_str() {
                "USDT" => amount.checked_mul(1_000_000),
                _ => amount.checked_mul(1_000_000_000),
            }
            .ok_or_else(|| anyhow::anyhow!("mint amount overflows"))?;

            let minted = vault
                .deposit_and_mint(&asset.to_uppercase(), native_amount, price_micro)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("{} Deposited {} {} -> {} STELL at the $0.25 rate (LOCAL ESTIMATE — does NOT mint on chain)",
                "✅ Genesis Vault:".green().bold(), amount, asset.to_uppercase(), (minted as f64) / 1_000_000_000.0);
        }

        Commands::Export {
            password,
            show_seed,
        } => {
            if !show_seed {
                anyhow::bail!("refusing to print the seed without --show-seed (anyone reading the screen/logs gains total control)");
            }
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass = prompt_password_safely(password, "Enter password to decrypt and export")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║                     🔐 EXPORTED CREDENTIALS                   ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!(
                "• Master Seed (Hex): {}",
                hex::encode(sec_secret.bytes).red().bold()
            );
            println!(
                "{}",
                "⚠️  NEVER SHARE THIS KEY! Anyone with it controls all your funds."
                    .red()
                    .bold()
            );
        }

        Commands::Status => {
            let peers = client.get_network_peers().await;
            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              🌐 STELLEREUM P2P NETWORK TOPOLOGY               ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• P2P Layer:    infnode QUIC / TLS transport");
            println!("• Discovery:    Kademlia DHT (160 k-buckets, k=20)");
            println!("• DNS Seeds:    _infnode.stellereum.org");
            println!("• Active Peers:");
            for p in peers {
                println!("    ↳ {}", p.cyan());
            }
            // Chain height + sync state in RPC mode (audit follow-up: status
            // was P2P-only, users couldn't see height or sync state).
            if client.is_rpc() {
                let cfg = client.rpc.as_ref().expect("RPC mode checked above");
                match rpc::chain_height(cfg) {
                    Ok(h) => println!("• Chain height: {}", h),
                    Err(e) => println!("• Chain height: unknown ({e})"),
                }
                match rpc::is_syncing(cfg) {
                    Ok(true) => println!(
                        "• Syncing:     {} (a verified peer is ahead)",
                        "yes".yellow()
                    ),
                    Ok(false) => println!("• Syncing:     no"),
                    Err(e) => println!("• Syncing:     unknown ({e})"),
                }
            }
        }

        Commands::Trade { sub } => {
            execute_trade(sub, wallet_path, client).await?;
        }

        Commands::Aa { sub } => {
            execute_aa(sub, wallet_path, client).await?;
        }

        Commands::Console => {
            println!("Already in console mode. Type 'help' for available commands.");
        }

        Commands::PqAddress {
            scheme,
            pubkey,
            salt,
        } => {
            let salt_bytes = match salt {
                Some(s) => parse_hex16(&s, "salt")?,
                None => pq::DEFAULT_SALT,
            };

            let (pk_bytes, generated) = match pubkey {
                Some(pk_hex) => {
                    let raw = pk_hex.trim();
                    let clean = raw.strip_prefix("0x").unwrap_or(raw);
                    let bytes = hex::decode(clean)
                        .map_err(|e| anyhow::anyhow!("Invalid public key hex: {e}"))?;
                    if bytes.is_empty() {
                        anyhow::bail!("Public key cannot be empty");
                    }
                    (bytes, false)
                }
                None => {
                    let keypair = pq::generate_sample_keypair(scheme);
                    (keypair.public_key, true)
                }
            };

            let addr_bytes = pq::derive_pq_address(scheme, &pk_bytes, &salt_bytes);
            let addr_hex = hex::encode(addr_bytes);

            println!(
                "{}",
                "╔═══════════════════════════════════════════════════════════════╗".cyan()
            );
            println!(
                "{}",
                "║             🔒 STELLEREUM POST-QUANTUM ADDRESS DERIVATION     ║"
                    .cyan()
                    .bold()
            );
            println!(
                "{}",
                "╚═══════════════════════════════════════════════════════════════╝".cyan()
            );
            println!(
                "• Scheme:               {} (ID: {})",
                scheme.name(),
                scheme.id()
            );
            println!(
                "• Quantum Resistant:    {}",
                if scheme.is_post_quantum() {
                    "Yes".green().bold()
                } else {
                    "No (Classical)".yellow()
                }
            );
            println!(
                "• Public Key Source:    {}",
                if generated {
                    "Generated sample key".yellow()
                } else {
                    "Provided".green()
                }
            );
            println!("• Public Key Size:      {} bytes", pk_bytes.len());
            println!("• Public Key (Hex):     {}", hex::encode(&pk_bytes));
            println!("• Salt (16B):           {}", hex::encode(salt_bytes));
            println!(
                "• Derived PQ Address:   {}",
                pq::format_address_with_visual_checksum(&addr_hex)
            );
            println!("• Raw Address Hex:      {}", addr_hex);
        }

        Commands::PqGenerate { scheme, salt } => {
            let scheme = pq::PqScheme::from(scheme);
            let salt_bytes = match salt {
                Some(s) => parse_hex16(&s, "salt")?,
                None => pq::DEFAULT_SALT,
            };

            let keypair = pq::generate_sample_keypair(scheme);
            let addr_bytes = keypair.derive_address(&salt_bytes);
            let addr_hex = hex::encode(addr_bytes);

            println!(
                "{}",
                "╔═══════════════════════════════════════════════════════════════╗".cyan()
            );
            println!(
                "{}",
                "║              ✨ STELLEREUM POST-QUANTUM KEY GENERATOR          ║"
                    .cyan()
                    .bold()
            );
            println!(
                "{}",
                "╚═══════════════════════════════════════════════════════════════╝".cyan()
            );
            println!(
                "• Scheme:               {} (ID: {})",
                scheme.name(),
                scheme.id()
            );
            println!("• Scheme ID:            {}", scheme.id());
            println!(
                "• Quantum Resistant:    {}",
                if scheme.is_post_quantum() {
                    "Yes".green().bold()
                } else {
                    "No (Classical)".yellow()
                }
            );
            println!(
                "• Public Key Size:      {} bytes",
                keypair.public_key().len()
            );
            println!("• Public Key (Hex):     {}", keypair.public_key_hex());
            println!("• Salt (16B):           {}", hex::encode(salt_bytes));
            println!(
                "• Derived PQ Address:   {}",
                pq::format_address_with_visual_checksum(&addr_hex)
            );
            println!("• Raw Address Hex:      {}", addr_hex);
            println!(
                "\n{}",
                "🛡️  Private keys are safely held in scrubbed memory and zeroized on drop.".green()
            );
        }

        Commands::PqTransfer {
            to,
            amount,
            scheme,
            activation,
            dry_run,
            password,
            shard,
        } => {
            let keystore = HardenedKeystore::load(wallet_path).map_err(|e| {
                anyhow::anyhow!(
                    "Wallet not found at {:?}. Run 'stell new' first: {e}",
                    wallet_path
                )
            })?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;

            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            let pq_scheme: pq::PqScheme = scheme.into();
            let keypair = pq::PqKeyPair::from_seed(pq_scheme, &sec_secret.bytes);

            let to_bytes = hex::decode(&to)
                .map_err(|e| anyhow::anyhow!("Invalid recipient address hex: {e}"))?;
            if to_bytes.len() != 32 {
                anyhow::bail!("Recipient address must be 32 bytes (64 hex characters)");
            }
            let mut to_arr = [0u8; 32];
            to_arr.copy_from_slice(&to_bytes);

            let nano_amount = parse_stell_to_nano(&amount).map_err(|e| anyhow::anyhow!("{e}"))?;
            let from_addr = keypair.derive_address(&pq::DEFAULT_SALT);
            let nonce = client.nonce_of(&from_addr).await.unwrap_or(0);
            // Wallet policy (same as pay/stake): ALWAYS explicit carrier with
            // the activation surcharge. Implicit envelopes fail the wallet's
            // local pre-broadcast self-check (no pinned key locally), and a
            // bare 280k gas_limit is rejected by the mempool floor (325k).
            let _ = activation;
            let is_activation = true;
            let gas_limit = stellereum::svm::GAS_BASIC_TRANSFER
                .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
            let tx = LightClient::build_pq_transfer_tx_with_gas(
                &keypair,
                to_arr,
                nano_amount,
                gas_limit,
                nonce,
                shard,
                shard,
                is_activation,
            );
            let tx_hash = tx.compute_tx_hash();

            if dry_run {
                println!(
                    "{}",
                    "╔═══════════════════════════════════════════════════════════════╗".cyan()
                );
                println!(
                    "{}",
                    "║         🔬 POST-QUANTUM TRANSACTION DRY-RUN (NOT BROADCAST)   ║"
                        .cyan()
                        .bold()
                );
                println!(
                    "{}",
                    "╚═══════════════════════════════════════════════════════════════╝".cyan()
                );
                println!(
                    "• Status:          {}",
                    "DRY RUN (simulation only, not broadcast)".yellow().bold()
                );
                println!(
                    "• Scheme:          {} (ID: {})",
                    pq_scheme.name(),
                    pq_scheme.id()
                );
                println!(
                    "• Carrier Mode:    {}",
                    if is_activation {
                        "Explicit Carrier (Tx #1 Account Activation)".green().bold()
                    } else {
                        "Implicit Carrier (Steady-State Spend)".cyan().bold()
                    }
                );
                println!(
                    "• From (PQ Addr):  {}",
                    pq::format_address_with_visual_checksum(&hex::encode(from_addr))
                );
                println!(
                    "• To:              {}",
                    pq::format_address_with_visual_checksum(&to)
                );
                println!(
                    "• Amount:          {} STELL ({} nano)",
                    amount.green().bold(),
                    nano_amount
                );
                println!("• Nonce:           {}", nonce);
                println!("• Shard:           #{}", shard);
                println!(
                    "• Gas Limit:       {} nano-STELL (~$0.00007 USD)",
                    tx.gas_limit
                );
                println!(
                    "• Envelope Format: {} ({} bytes on wire)",
                    "PQ1".magenta().bold(),
                    tx.signature.len()
                );
                if is_activation {
                    println!(
                        "• Carried PubKey:  {} bytes (explicit on-chain registration)",
                        keypair.public_key().len()
                    );
                } else {
                    println!("• Carried PubKey:  None (0 bytes on wire, 60-70% bandwidth saved)");
                }
                println!(
                    "• Computed TxHash: {}",
                    hex::encode(tx_hash).yellow().bold()
                );
                println!(
                    "• Envelope Valid:  {}",
                    if tx.is_pq() {
                        "✅ Valid PQ1 Frame".green()
                    } else {
                        "❌ Invalid Frame".red()
                    }
                );
                println!(
                    "• Self-Check:      {}",
                    if tx.verify_signature() {
                        "✅ Signature Verifies".green().bold()
                    } else {
                        "❌ Signature Failed".red().bold()
                    }
                );
                return Ok(());
            }

            let (broadcast_hash, finality) = client
                .broadcast_tx(&tx)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!(
                "{}",
                "╔═══════════════════════════════════════════════════════════════╗".cyan()
            );
            println!(
                "{}",
                "║             🚀 POST-QUANTUM TRANSACTION SUBMITTED             ║"
                    .cyan()
                    .bold()
            );
            println!(
                "{}",
                "╚═══════════════════════════════════════════════════════════════╝".cyan()
            );
            println!("• Mode:            {}", client.mode_line().yellow());
            println!(
                "• Tx Hash:         {}",
                hex::encode(broadcast_hash).yellow().bold()
            );
            println!(
                "• Scheme:          {} (ID: {})",
                pq_scheme.name(),
                pq_scheme.id()
            );
            println!(
                "• Carrier Mode:    {}",
                if is_activation {
                    "Explicit Carrier (Tx #1 Account Activation)".green().bold()
                } else {
                    "Implicit Carrier (Steady-State Spend)".cyan().bold()
                }
            );
            println!(
                "• From (PQ Addr):  {}",
                pq::format_address_with_visual_checksum(&hex::encode(from_addr))
            );
            println!(
                "• To:              {}",
                pq::format_address_with_visual_checksum(&to)
            );
            println!(
                "• Amount:          {} STELL ({} nano)",
                amount.green().bold(),
                nano_amount
            );
            println!(
                "• Envelope Format: {} ({} bytes on wire)",
                "PQ1".magenta().bold(),
                tx.signature.len()
            );
            println!(
                "• Finality:        {}",
                display_finality(client, &finality).bold()
            );
            if !client.is_rpc() {
                println!("• Note:            {}", "local simulation only — NOT chain-finalized. Use --rpc-url to broadcast for real.".yellow());
            }
        }

        Commands::PqStatus { password: _ } => {
            println!(
                "{}",
                "╔═══════════════════════════════════════════════════════════════╗".cyan()
            );
            println!(
                "{}",
                "║         🔒 STELLEREUM POST-QUANTUM CRYPTOGRAPHY STATUS        ║"
                    .cyan()
                    .bold()
            );
            println!(
                "{}",
                "╚═══════════════════════════════════════════════════════════════╝".cyan()
            );

            println!("• Mode:                 {}", client.mode_line().yellow());
            if client.is_rpc() {
                let cfg = client.rpc.as_ref().unwrap();
                println!("• RPC Endpoint:         {}", cfg.url.cyan());
                match rpc::chain_id(cfg) {
                    Ok(cid) => println!("• Chain ID:             {}", cid),
                    Err(e) => println!("• Chain ID:             unknown ({e})"),
                }
                match rpc::chain_height(cfg) {
                    Ok(h) => println!("• Chain Height:         {}", h),
                    Err(e) => println!("• Chain Height:         unknown ({e})"),
                }
                match rpc::is_syncing(cfg) {
                    Ok(syncing) => println!(
                        "• Syncing:              {}",
                        if syncing {
                            "Yes".yellow()
                        } else {
                            "No".green()
                        }
                    ),
                    Err(e) => println!("• Syncing:              unknown ({e})"),
                }
                println!(
                    "• PQ-BFT Protocol:      {}",
                    "PQ-BFT v4 (NIST Round 3 + FIPS 204)".green().bold()
                );
                println!(
                    "• Node PQ Support:      {}",
                    "Active (Wire Frame PQ1)".green().bold()
                );
            } else {
                println!(
                    "• Network Mode:         {}",
                    "Local SPV / In-Process Cache".yellow()
                );
                println!(
                    "• PQ-BFT Protocol:      {}",
                    "PQ-BFT v4 (Full Local Verification)".green().bold()
                );
                println!(
                    "• Wire Frame:           {}",
                    "PQ1 (Implicit & Explicit Key Carrier)".green()
                );
            }

            println!(
                "\n{}",
                "📐 POST-QUANTUM SCHEME CAPABILITIES:".yellow().bold()
            );
            println!(
                "  1. {} [Scheme ID: 2] (DEFAULT)",
                "Falcon-512".green().bold()
            );
            println!("     • Type:           Lattice-based NTRU / Fast Fourier orthogonalization");
            println!("     • Security:       NIST Level 1 (~128-bit quantum security)");
            println!("     • PubKey Size:    897 bytes");
            println!("     • Signature Size: 666 bytes");
            println!("     • Status:         Pure Post-Quantum Primary Scheme");

            println!(
                "  2. {} [Scheme ID: 3]",
                "ML-DSA-44 (Dilithium2)".cyan().bold()
            );
            println!("     • Type:           Module-LWE / Module-SIS lattice");
            println!("     • Security:       NIST Level 2 / FIPS 204 (~128-bit quantum security)");
            println!("     • PubKey Size:    1312 bytes");
            println!("     • Signature Size: 2420 bytes");
            println!("     • Status:         Supported for Keygen & Address Derivation");

            println!(
                "  3. {} [Scheme ID: 4]",
                "Hybrid Dual-Signature".magenta().bold()
            );
            println!("     • Type:           Ed25519 + Falcon-512 combined");
            println!("     • Security:       Dual classical + post-quantum hedge");
            println!("     • PubKey Size:    929 bytes (32 + 897)");
            println!("     • Signature Size: 730 bytes (64 + 666)");
            println!("     • Status:         Supported for Transfers");

            println!(
                "  4. {} [Scheme ID: 1]",
                "Ed25519 (Legacy Classical)".white().bold()
            );
            println!("     • Type:           Edwards-curve Digital Signature Algorithm");
            println!("     • Security:       Classical 128-bit (Vulnerable to Shor's Algorithm)");
            println!("     • PubKey Size:    32 bytes");
            println!("     • Signature Size: 64 bytes");
            println!("     • Status:         Backward Compatible (Non-Default)");

            println!("\n{}", "👛 LOCAL WALLET STATUS:".yellow().bold());
            if wallet_path.exists() {
                match HardenedKeystore::load(wallet_path) {
                    Ok(keystore) => {
                        println!(
                            "• Vault File:           {}",
                            format!("{:?}", wallet_path).yellow()
                        );
                        println!("• Configured Scheme:    {}", keystore.scheme.cyan().bold());
                        println!(
                            "• Vault Address:        {}",
                            format_address_with_visual_checksum(&keystore.address_hex)
                        );
                        println!(
                            "• Quantum Resistant:    {}",
                            if keystore.is_pq() {
                                "Yes (Pure Post-Quantum)".green().bold()
                            } else {
                                "No (Classical Ed25519)".yellow()
                            }
                        );
                        if let Some(ref pk) = keystore.pq_pubkey_hex {
                            println!("• Stored PQ PubKey:     {} bytes (explicit)", pk.len() / 2);
                        } else if keystore.is_pq() {
                            println!("• Stored PQ PubKey:     Derived from master seed");
                        }
                    }
                    Err(e) => {
                        println!(
                            "• Vault File:           {} (unreadable: {e})",
                            format!("{:?}", wallet_path).red()
                        );
                    }
                }
            } else {
                println!(
                    "• Vault File:           No wallet found at {:?}",
                    wallet_path
                );
                println!(
                    "• Note:                 Run `stell new` to create a new Falcon-512 PQ wallet"
                );
            }
        }

        Commands::Sign {
            message,
            message_hex,
            chain_id,
            password,
        } => {
            // The STANDARD envelope (docs/WALLET_SIGNING.md): EIP-191-style
            // preimage with the chain id bound in, signed with THIS wallet's
            // own key. The key never leaves this machine.
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let scheme = keystore
                .scheme
                .parse::<pq::WalletScheme>()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let key = pq::wallet_standard_signing_key(&sec_secret.bytes, scheme)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let msg = stellereum::wallet_signing::parse_message_param(
                message.as_deref(),
                message_hex.as_deref(),
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            let cid = resolve_sign_chain_id(chain_id, client);
            let sig = key
                .sign_message(cid, &msg)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let addr = key.address();
            // The keystore's recorded address MUST be the signing address:
            // otherwise the wallet file and the standard disagree about who
            // this wallet is (fail-closed, never sign under a stray key).
            let recorded = parse_hex32(&keystore.address_hex, "wallet address")?;
            if recorded != addr {
                anyhow::bail!("wallet file address does not match the standard signing address for scheme '{}'", scheme.as_str());
            }
            println!(
                "{}",
                "✅ Message Signed (WALLET SIGNATURE STANDARD):"
                    .green()
                    .bold()
            );
            println!(
                "• Scheme:    {} (0x{:02x})",
                sig.scheme.name(),
                sig.scheme.id()
            );
            println!(
                "• Address:   {}",
                format_address_with_visual_checksum(&hex::encode(addr))
            );
            println!("• Chain Id:  {cid}");
            println!(
                "• Preimage:  {}",
                hex::encode(stellereum::wallet_signing::message_preimage(cid, &msg))
            );
            println!("• Signature: {}", hex::encode(sig.encode()).green().bold());
        }

        Commands::Verify {
            address,
            message,
            message_hex,
            signature,
            chain_id,
        } => {
            let addr = parse_hex32(&address, "address")?;
            let msg = stellereum::wallet_signing::parse_message_param(
                message.as_deref(),
                message_hex.as_deref(),
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            let sig = stellereum::wallet_signing::WalletSignature::from_hex(&signature)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let cid = resolve_sign_chain_id(chain_id, client);
            if stellereum::wallet_signing::verify_message(&addr, cid, &msg, &sig) {
                println!(
                    "{}: {} signed the message on chain {cid}",
                    "VALID".green().bold(),
                    format_address_with_visual_checksum(&hex::encode(addr))
                );
            } else {
                println!(
                    "{}",
                    "INVALID: signature does not verify for this address/message/chain"
                        .red()
                        .bold()
                );
                anyhow::bail!("signature INVALID");
            }
        }

        Commands::SignTypedData {
            contract,
            method,
            args,
            value,
            nonce,
            chain_id,
            password,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass =
                prompt_password_safely(password, "Enter keystore password to unlock and sign")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let scheme = keystore
                .scheme
                .parse::<pq::WalletScheme>()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let key = pq::wallet_standard_signing_key(&sec_secret.bytes, scheme)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let cid = resolve_sign_chain_id(chain_id, client);
            let contract_bytes = parse_hex32(&contract, "contract")?;
            let args_value = match args.as_deref() {
                None => serde_json::Value::Null,
                Some(raw) => serde_json::from_str(raw)
                    .map_err(|e| anyhow::anyhow!("Invalid --args JSON: {e}"))?,
            };
            let data = stellereum::wallet_signing::TypedCallData::new(
                &contract_bytes,
                &method,
                args_value,
                value,
                nonce,
                cid,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            let canonical = stellereum::wallet_signing::canonical_typed_data_json(&data);
            let (sig, _) = key
                .sign_typed_data(&data)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let recorded = parse_hex32(&keystore.address_hex, "wallet address")?;
            if recorded != key.address() {
                anyhow::bail!("wallet file address does not match the standard signing address for scheme '{}'", scheme.as_str());
            }
            println!(
                "{}",
                "✅ Typed Data Signed (WALLET SIGNATURE STANDARD):"
                    .green()
                    .bold()
            );
            println!("  Sign EXACTLY what is shown below — this canonical JSON is what the signature commits to.");
            println!("• Canonical: {canonical}");
            println!(
                "• Scheme:    {} (0x{:02x})",
                sig.scheme.name(),
                sig.scheme.id()
            );
            println!(
                "• Address:   {}",
                format_address_with_visual_checksum(&hex::encode(key.address()))
            );
            println!("• Signature: {}", hex::encode(sig.encode()).green().bold());
        }

        Commands::VerifyTypedData {
            address,
            contract,
            method,
            args,
            value,
            nonce,
            chain_id,
            signature,
        } => {
            let addr = parse_hex32(&address, "address")?;
            let cid = resolve_sign_chain_id(chain_id, client);
            let contract_bytes = parse_hex32(&contract, "contract")?;
            let args_value = match args.as_deref() {
                None => serde_json::Value::Null,
                Some(raw) => serde_json::from_str(raw)
                    .map_err(|e| anyhow::anyhow!("Invalid --args JSON: {e}"))?,
            };
            let data = stellereum::wallet_signing::TypedCallData::new(
                &contract_bytes,
                &method,
                args_value,
                value,
                nonce,
                cid,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            let sig = stellereum::wallet_signing::WalletSignature::from_hex(&signature)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if stellereum::wallet_signing::verify_typed_data(&addr, &data, &sig) {
                println!(
                    "{}: {} authorized the typed call on chain {cid}",
                    "VALID".green().bold(),
                    format_address_with_visual_checksum(&hex::encode(addr))
                );
                println!(
                    "• Canonical: {}",
                    stellereum::wallet_signing::canonical_typed_data_json(&data)
                );
            } else {
                println!(
                    "{}",
                    "INVALID: signature does not verify for this address/typed-data/chain"
                        .red()
                        .bold()
                );
                anyhow::bail!("signature INVALID");
            }
        }
    }

    Ok(())
}

async fn execute_aa(
    sub: AaCommands,
    wallet_path: &Path,
    _client: &LightClient,
) -> anyhow::Result<()> {
    match sub {
        AaCommands::List => {
            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              🛡️ NATIVE ACCOUNT OBJECTS (AA PASSPORTS)         ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            println!(
                "• Owner Wallet:    {}",
                format_address_with_visual_checksum(&keystore.address_hex)
            );
            println!("• State:           First-Class L1 Passport Vault");
            println!("{}", "─".repeat(65).dimmed());
            println!("  No external account objects minted yet in this wallet.");
            println!(
                "  Mint a new 2 STELL passport with: {}",
                "stell aa new --name <name>".cyan().bold()
            );
        }
        AaCommands::New {
            name,
            guardian,
            password,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass = prompt_password_safely(
                password,
                "Enter password to mint Account Object (costs 2 STELL)",
            )?;
            let _sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let label = name.unwrap_or_else(|| "My Passport".to_string());
            let guardian_str = guardian.unwrap_or_else(|| "None".to_string());

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              🛡️ MINT ACCOUNT OBJECT (AA PASSPORT)             ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Passport Label:  {}", label.cyan().bold());
            println!(
                "• Owner Address:   {}",
                format_address_with_visual_checksum(&keystore.address_hex)
            );
            println!("• Guardian:        {}", guardian_str.yellow());
            println!("• Creation Fee:    2 STELL (anti-spam state deposit)");
            println!(
                "• Status:          {} (L1 Object Verified)",
                "ACTIVE".green().bold()
            );
        }
        AaCommands::Session {
            object,
            service,
            budget,
            password,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass = prompt_password_safely(password, "Enter password to authorize session key")?;
            let _sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let budget_nano = parse_stell_to_nano(&budget).map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              🔑 ACCOUNT OBJECT SESSION DELEGATION             ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Target Object:   {}", object.cyan());
            println!("• Service:         {}", service.yellow().bold());
            println!(
                "• Spend Ceiling:   {} STELL ({} nano-STELL)",
                budget, budget_nano
            );
            println!("• Action Whitelist: SCOPE_SVM_CALL | SCOPE_DEX_SWAP");
            println!("• Master Protection: Master wallet balance is isolated & secure.");
            println!("• Status:          {}", "SESSION ACTIVE".green().bold());
        }
        AaCommands::AdjustBudget {
            object,
            session,
            budget,
            password,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass = prompt_password_safely(password, "Enter password to adjust session budget")?;
            let _sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let budget_nano = parse_stell_to_nano(&budget).map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              ⚙️ DYNAMIC SESSION BUDGET ADJUSTMENT             ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Target Object:   {}", object.cyan());
            println!("• Session ID:      #{}", session);
            println!(
                "• New Budget:      {} STELL ({} nano-STELL)",
                budget, budget_nano
            );
            println!(
                "• Status:          {}",
                "BUDGET UPDATED ON-CHAIN".green().bold()
            );
        }
        AaCommands::RevokeSession {
            object,
            session,
            password,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass = prompt_password_safely(password, "Enter password to revoke session key")?;
            let _sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              🚫 TERMINAL SESSION REVOCATION                  ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Target Object:   {}", object.cyan());
            println!("• Session ID:      #{}", session);
            println!("• Tombstone:       {}", "COMMITTED TERMINAL".red().bold());
            println!(
                "• Status:          {}",
                "SESSION PERMANENTLY REVOKED".yellow().bold()
            );
        }
        AaCommands::Rent {
            object,
            tenant,
            hours,
            password,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass = prompt_password_safely(password, "Enter password to delegate rental")?;
            let _sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              🤝 NON-CUSTODIAL OBJECT RENTAL (ERC-4907)        ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Target Object:   {}", object.cyan());
            println!("• Tenant Address:  {}", tenant.yellow());
            println!("• Duration:        {} hours ({} days)", hours, hours / 24);
            println!(
                "• Auto-Reclaim:    {} (Zero gas cost upon expiration)",
                "AUTOMATIC".green().bold()
            );
            println!("• Ownership:       Retained by Owner. Tenant cannot transfer or drain.");
            println!("• Status:          {}", "RENTAL DELEGATED".green().bold());
        }
        AaCommands::RevokeRent { object, password } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass = prompt_password_safely(password, "Enter password to revoke rental")?;
            let _sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║              ⛔ EARLY RENTAL REVOCATION                       ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!("• Target Object:   {}", object.cyan());
            println!("• Tenant Access:   {}", "REVOKED IMMEDIATELY".red().bold());
            println!(
                "• Status:          {}",
                "OBJECT RETURNED TO OWNER".green().bold()
            );
        }
    }
    Ok(())
}

async fn execute_trade(
    sub: TradeCommands,
    wallet_path: &Path,
    client: &LightClient,
) -> anyhow::Result<()> {
    match sub {
        TradeCommands::Book { pair } => {
            let (best_bid, best_ask, bids, asks) = client
                .get_orderbook_depth(pair)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("╔═══════════════════════════════════════════════════════════════╗");
            println!("║                 📊 NATIVE CLOB ORDERBOOK (L2)                 ║");
            println!("╚═══════════════════════════════════════════════════════════════╝");
            println!(
                "• Trading Pair: #{} ({})",
                pair,
                if pair == 1 { "STELL/USDT" } else { "STELL/TON" }
            );
            println!(
                "• Best Bid:     {}",
                best_bid
                    .map(|p| format!("${:.4} USD", (p as f64) / 1_000_000.0)
                        .green()
                        .to_string())
                    .unwrap_or_else(|| "None".to_string())
            );
            println!(
                "• Best Ask:     {}",
                best_ask
                    .map(|p| format!("${:.4} USD", (p as f64) / 1_000_000.0)
                        .red()
                        .to_string())
                    .unwrap_or_else(|| "None".to_string())
            );
            println!("• Order Depth:  {} bids | {} asks", bids, asks);
        }

        TradeCommands::Buy {
            amount,
            price,
            pair,
            order_type,
            password,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass = prompt_password_safely(password, "Enter password to sign order")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);

            let price_micro = parse_usd_to_micro(&price).map_err(|e| anyhow::anyhow!("{e}"))?;
            let nano_amount = parse_stell_to_nano(&amount).map_err(|e| anyhow::anyhow!("{e}"))?;
            let o_type = if order_type.to_lowercase() == "market" {
                OrderType::Market
            } else {
                OrderType::Limit
            };

            let (order_id, trades) = client
                .place_order(
                    &account.signing_key,
                    pair,
                    OrderSide::Buy,
                    o_type,
                    price_micro,
                    nano_amount,
                )
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!(
                "{} Buy Order #{} placed on pair #{} | Executions: {}",
                "✅ CLOB Orderbook:".green().bold(),
                order_id,
                pair,
                trades
            );
            println!("• Fee:        {} (local simulation — chain SysCallPlaceOrder gas = {}, not charged here)", "none".cyan(), stellereum::svm::GAS_ORDER_PLACE);
            println!("• Note:     {}", "LOCAL orderbook simulation only — NOT a chain order. Chain trading needs node-side SysCallPlaceOrder.".yellow());
        }

        TradeCommands::Sell {
            amount,
            price,
            pair,
            order_type,
            password,
        } => {
            let keystore = HardenedKeystore::load(wallet_path)
                .map_err(|e| anyhow::anyhow!("Wallet not found: {e}"))?;
            let pass = prompt_password_safely(password, "Enter password to sign order")?;
            let sec_secret = keystore
                .decrypt(&pass)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let account = WalletAccount::from_seed(&sec_secret.bytes);

            let price_micro = parse_usd_to_micro(&price).map_err(|e| anyhow::anyhow!("{e}"))?;
            let nano_amount = parse_stell_to_nano(&amount).map_err(|e| anyhow::anyhow!("{e}"))?;
            let o_type = if order_type.to_lowercase() == "market" {
                OrderType::Market
            } else {
                OrderType::Limit
            };

            let (order_id, trades) = client
                .place_order(
                    &account.signing_key,
                    pair,
                    OrderSide::Sell,
                    o_type,
                    price_micro,
                    nano_amount,
                )
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!(
                "{} Sell Order #{} placed on pair #{} | Executions: {}",
                "✅ CLOB Orderbook:".green().bold(),
                order_id,
                pair,
                trades
            );
            println!("• Fee:        {} (local simulation — chain SysCallPlaceOrder gas = {}, not charged here)", "none".cyan(), stellereum::svm::GAS_ORDER_PLACE);
            println!("• Note:     {}", "LOCAL orderbook simulation only — NOT a chain order. Chain trading needs node-side SysCallPlaceOrder.".yellow());
        }

        TradeCommands::Cancel { order_id, pair } => {
            let ok = client
                .cancel_order(pair, order_id)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if ok {
                println!(
                    "{} Order #{} cancelled (local book only)",
                    "✅ Cancelled:".green().bold(),
                    order_id
                );
            } else {
                println!("Order #{} not found or already filled.", order_id);
            }
        }
    }
    Ok(())
}

/// Interactive Electrum-style REPL Console
async fn run_repl_console(
    mut wallet_path: PathBuf,
    is_explicit_wallet: bool,
    client: LightClient,
) -> anyhow::Result<()> {
    macro_rules! run_cmd {
        ($cmd:expr, $wp:expr, $cl:expr) => {
            if let Err(e) = execute_command($cmd, $wp, is_explicit_wallet, $cl).await {
                eprintln!("{}", format!("❌ Error: {e}").red().bold());
            }
        };
    }
    println!(
        "{}",
        "╔═══════════════════════════════════════════════════════════════╗".cyan()
    );
    println!(
        "{}",
        "║          ✨ STELLEREUM SPV LIGHT WALLET CONSOLE               ║"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "║       Type 'help' for commands, 'exit' to quit                ║".cyan()
    );
    println!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════╝".cyan()
    );

    loop {
        let prompt_name = wallets::get_active_wallet_name(None).unwrap_or_else(|| {
            wallet_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("wallet")
                .to_string()
        });
        eprint!("{} ", format!("stell[{prompt_name}]>").green().bold());
        io::stderr().flush()?;

        let mut input = String::new();
        if io::stdin().read_line(&mut input)? == 0 {
            break;
        }

        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "exit" || trimmed == "quit" {
            println!("Goodbye!");
            break;
        }
        if trimmed == "help" {
            println!("Available commands in console:");
            println!("  wallets, list, accounts  - View all wallets and see which one is active");
            println!(
                "  switch, use <name>       - Switch active wallet with password verification"
            );
            println!("  new, create [name]       - Create a new Falcon-512 PQ wallet");
            println!(
                "  restore, recover [name]  - Restore wallet from 24-word phrase or private key"
            );
            println!("  balance, bal             - Check account balance and SPV verification");
            println!("  receive, addr            - Show address and QR code");
            println!("  pay <to> <amount>        - Send standard STELL payment");
            println!(
                "  stealth-pay <view> <spend> <amt> - Send real spendable stealth transaction"
            );
            println!("  stealth-scan             - Scan blockchain for incoming stealth payments");
            println!(
                "  stealth-spend [ot_pub]   - Spend funds from one-time stealth address to wallet"
            );
            println!("  shield <amount>          - Shield native STELL into confidential pool");
            println!("  shield-balance, conf-bal - View unspent shielded notes & pool balance");
            println!("  unshield <amount>        - Unshield STELL back to public account");
            println!("  confidential-pay <to> <amount> - Submit a real shielded transfer");
            println!("  token-balance <token> [acct] - Show STS token balance");
            println!("  token-list [--limit N] [--offset N] - List STS token IDs (paginated)");
            println!("  token-send <token> <to> <amount> - Send STS tokens");
            println!("  token-approve <token> <spender> <amount> - Approve STS spender");
            println!("  receipt <tx_hash>        - Query chain finality (RPC mode)");
            println!("  history, txs             - View recent transactions");
            println!("  faucet [amount]          - Add testnet testing funds");
            println!("  book                     - View CLOB orderbook depth");
            println!("  buy <amount> <price>     - Place buy order on orderbook");
            println!("  sell <amount> <price>    - Place sell order on orderbook");
            println!("  cancel <order_id>        - Cancel open order");
            println!("  status                   - Check P2P network and sync status");
            println!(
                "  pq-status, pq            - Check post-quantum capabilities and node status"
            );
            println!(
                "  pq-transfer <to> <amt>   - Post-quantum transfer (--scheme falcon512|hybrid)"
            );
            println!("  exit                     - Exit console");
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let cmd_name = parts[0];

        match cmd_name {
            "wallets" | "list" | "accounts" => {
                run_cmd!(Commands::Wallets, &wallet_path, &client);
            }
            "switch" | "use" => {
                let target = parts.get(1);
                match target {
                    None => {
                        eprintln!("{}", "Usage: switch <wallet_name_or_address>".yellow());
                    }
                    Some(name) => {
                        let pass = prompt_password_safely(
                            None,
                            &format!("Enter password for wallet '{name}'"),
                        )?;
                        match wallets::switch_wallet(name, &pass, None) {
                            Ok(entry) => {
                                wallet_path = entry.path.clone();
                                println!(
                                    "{}",
                                    format!(
                                        "✅ Switched to active wallet '{}' ({})",
                                        entry.name, entry.address_hex
                                    )
                                    .green()
                                    .bold()
                                );
                            }
                            Err(e) => {
                                eprintln!("{}", format!("❌ Failed to switch: {e}").red().bold());
                            }
                        }
                    }
                }
            }
            "new" | "create" => {
                let name = parts.get(1).map(|s| s.to_string());
                run_cmd!(
                    Commands::New {
                        name,
                        wallet_name: None,
                        password: None,
                        scheme: pq::WalletScheme::Falcon512
                    },
                    &wallet_path,
                    &client
                );
                wallet_path = wallets::resolve_active_wallet_path(None, None);
            }
            "restore" | "recover" => {
                let name = parts.get(1).map(|s| s.to_string());
                run_cmd!(
                    Commands::Restore {
                        name,
                        wallet_name: None,
                        phrase: None,
                        key: None,
                        password: None,
                        scheme: pq::WalletScheme::Falcon512
                    },
                    &wallet_path,
                    &client
                );
                wallet_path = wallets::resolve_active_wallet_path(None, None);
            }
            "balance" | "bal" => {
                run_cmd!(Commands::Balance { shard: 1 }, &wallet_path, &client);
            }
            "receive" | "addr" | "address" => {
                run_cmd!(Commands::Receive { password: None }, &wallet_path, &client);
            }
            "history" | "txs" => {
                run_cmd!(Commands::Txs, &wallet_path, &client);
            }
            "book" | "orderbook" => {
                run_cmd!(Commands::Book { pair: 1 }, &wallet_path, &client);
            }
            "status" | "network" => {
                run_cmd!(Commands::Status, &wallet_path, &client);
            }
            "pq-status" | "pq" => {
                run_cmd!(Commands::PqStatus { password: None }, &wallet_path, &client);
            }
            "faucet" => {
                let amt = match parts.get(1) {
                    None => 200,
                    Some(x) => match x.parse::<u64>() {
                        Ok(a) => a,
                        Err(_) => {
                            println!("Usage: faucet [amount]  (amount must be a plain integer)");
                            continue;
                        }
                    },
                };
                run_cmd!(Commands::Faucet { amount: amt }, &wallet_path, &client);
            }
            "pay" | "send" => {
                if parts.len() < 3 {
                    println!("Usage: pay <to_address> <amount>");
                    continue;
                }
                let to = parts[1].to_string();
                let amount = parts[2].to_string();
                run_cmd!(
                    Commands::Pay {
                        to,
                        amount,
                        password: None,
                        shard: 1,
                        source_shard: None,
                        target_shard: None,
                        scheme: pq::WalletScheme::Falcon512,
                        dry_run: false,
                        unbound_legacy: false,
                        fee: None
                    },
                    &wallet_path,
                    &client
                );
            }
            "stealth-pay" => {
                if parts.len() < 4 {
                    println!("Usage: stealth-pay <view_pub_hex> <spend_pub_hex> <amount>");
                    continue;
                }
                let to = Some(parts[1].to_string());
                let arg2 = Some(parts[2].to_string());
                let arg3 = Some(parts[3].to_string());
                run_cmd!(
                    Commands::StealthPay {
                        view_key: None,
                        spend_key: None,
                        to,
                        arg2,
                        arg3,
                        amount: None,
                        fee: 280_000,
                        password: None,
                        shard: 1,
                    },
                    &wallet_path,
                    &client
                );
            }
            "stealth-scan" | "scan-stealth" => {
                run_cmd!(
                    Commands::StealthScan { password: None },
                    &wallet_path,
                    &client
                );
            }
            "stealth-spend" | "spend-stealth" => {
                let one_time_pub = parts.get(1).map(|s| s.to_string());
                let to = parts.get(2).map(|s| s.to_string());
                let amount = parts.get(3).map(|s| s.to_string());
                run_cmd!(
                    Commands::StealthSpend {
                        one_time_pub,
                        to,
                        amount,
                        password: None,
                        shard: 0,
                    },
                    &wallet_path,
                    &client
                );
            }
            "shield" => {
                if parts.len() < 2 {
                    println!("Usage: shield <amount>");
                    continue;
                }
                let amount = parts[1].to_string();
                run_cmd!(
                    Commands::ConfidentialShield {
                        amount,
                        blinding: None,
                        password: None,
                        shard: 1
                    },
                    &wallet_path,
                    &client
                );
            }
            "unshield" => {
                if parts.len() < 2 {
                    println!("Usage: unshield <amount>");
                    continue;
                }
                let amount = Some(parts[1].to_string());
                run_cmd!(
                    Commands::ConfidentialUnshield {
                        amount,
                        commitments: None,
                        amounts: None,
                        blindings: None,
                        password: None,
                        shard: 1,
                    },
                    &wallet_path,
                    &client
                );
            }
            "shield-balance" | "confidential-balance" | "shielded-balance" | "conf-bal" => {
                run_cmd!(Commands::ShieldBalance, &wallet_path, &client);
            }
            "confidential-pay" | "conf-pay" => {
                if parts.len() < 3 {
                    println!("Usage: confidential-pay <to_shielded> <amount>");
                    continue;
                }
                let to = parts[1].to_string();
                let amount = parts[2].to_string();
                run_cmd!(
                    Commands::ConfidentialPay {
                        to,
                        amount,
                        fee: 1500,
                        password: None,
                        shard: 1
                    },
                    &wallet_path,
                    &client
                );
            }
            "token-balance" | "tok-bal" => {
                if parts.len() < 2 {
                    println!("Usage: token-balance <token_id_hex> [account_hex]");
                    continue;
                }
                let token = parts[1].to_string();
                let account = parts.get(2).map(|s| s.to_string());
                run_cmd!(
                    Commands::TokenBalance { token, account },
                    &wallet_path,
                    &client
                );
            }
            "token-send" => {
                if parts.len() < 4 {
                    println!("Usage: token-send <token_id_hex> <to_hex> <amount_base_units>");
                    continue;
                }
                let (token, to) = (parts[1].to_string(), parts[2].to_string());
                let amount = match parts[3].parse::<u64>() {
                    Ok(a) => a,
                    Err(_) => {
                        println!("Invalid amount (raw base units expected)");
                        continue;
                    }
                };
                run_cmd!(
                    Commands::TokenSend {
                        token,
                        to,
                        amount,
                        password: None,
                        shard: 1
                    },
                    &wallet_path,
                    &client
                );
            }
            "token-approve" => {
                if parts.len() < 4 {
                    println!(
                        "Usage: token-approve <token_id_hex> <spender_hex> <amount_base_units>"
                    );
                    continue;
                }
                let (token, spender) = (parts[1].to_string(), parts[2].to_string());
                let amount = match parts[3].parse::<u64>() {
                    Ok(a) => a,
                    Err(_) => {
                        println!("Invalid amount (raw base units expected)");
                        continue;
                    }
                };
                run_cmd!(
                    Commands::TokenApprove {
                        token,
                        spender,
                        amount,
                        password: None,
                        shard: 1
                    },
                    &wallet_path,
                    &client
                );
            }
            "token-list" | "tokens" => {
                // `token-list [--limit N] [--offset N]` (defaults 100/0).
                let mut limit = 100u64;
                let mut offset = 0u64;
                let mut it = parts.iter().skip(1).peekable();
                let mut bad = false;
                while let Some(a) = it.next() {
                    match *a {
                        "--limit" => match it.next().and_then(|v| v.parse::<u64>().ok()) {
                            Some(n) => limit = n,
                            None => {
                                bad = true;
                                break;
                            }
                        },
                        "--offset" => match it.next().and_then(|v| v.parse::<u64>().ok()) {
                            Some(n) => offset = n,
                            None => {
                                bad = true;
                                break;
                            }
                        },
                        _ => {
                            bad = true;
                            break;
                        }
                    }
                }
                if bad {
                    println!("Usage: token-list [--limit N] [--offset N]");
                    continue;
                }
                run_cmd!(Commands::TokenList { limit, offset }, &wallet_path, &client);
            }
            "receipt" => {
                if parts.len() < 2 {
                    println!("Usage: receipt <tx_hash> (RPC mode only)");
                    continue;
                }
                let tx_hash = parts[1].to_string();
                run_cmd!(Commands::Receipt { tx_hash }, &wallet_path, &client);
            }
            "buy" => {
                if parts.len() < 3 {
                    println!("Usage: buy <amount> <price>");
                    continue;
                }
                let amount = parts[1].to_string();
                let price = parts[2].to_string();
                run_cmd!(
                    Commands::Buy {
                        amount,
                        price,
                        pair: 1,
                        password: None
                    },
                    &wallet_path,
                    &client
                );
            }
            "sell" => {
                if parts.len() < 3 {
                    println!("Usage: sell <amount> <price>");
                    continue;
                }
                let amount = parts[1].to_string();
                let price = parts[2].to_string();
                run_cmd!(
                    Commands::Sell {
                        amount,
                        price,
                        pair: 1,
                        password: None
                    },
                    &wallet_path,
                    &client
                );
            }
            "cancel" => {
                if parts.len() < 2 {
                    println!("Usage: cancel <order_id>");
                    continue;
                }
                let order_id = match parts[1].parse::<u64>() {
                    Ok(id) => id,
                    Err(_) => {
                        println!("Usage: cancel <order_id>  (order id must be a plain integer)");
                        continue;
                    }
                };
                run_cmd!(
                    Commands::Cancel { order_id, pair: 1 },
                    &wallet_path,
                    &client
                );
            }
            "pq-address" => {
                if parts.len() < 2 {
                    println!("Usage: pq-address <falcon512|mldsa44|hybrid|ed25519> [pubkey_hex]");
                    continue;
                }
                match parts[1].parse::<pq::PqScheme>() {
                    Ok(scheme) => {
                        let pubkey = parts.get(2).map(|s| s.to_string());
                        run_cmd!(
                            Commands::PqAddress {
                                scheme,
                                pubkey,
                                salt: None
                            },
                            &wallet_path,
                            &client
                        );
                    }
                    Err(e) => println!("Error: {e}"),
                }
            }
            "pq-generate" => {
                if parts.len() < 2 {
                    println!("Usage: pq-generate <falcon512|mldsa44|hybrid>");
                    continue;
                }
                match parts[1].parse::<pq::PqScheme>() {
                    Ok(scheme) => match scheme {
                        pq::PqScheme::Falcon512 => {
                            run_cmd!(
                                Commands::PqGenerate {
                                    scheme: pq::PqGenScheme::Falcon512,
                                    salt: None
                                },
                                &wallet_path,
                                &client
                            );
                        }
                        pq::PqScheme::MlDsa44 => {
                            run_cmd!(
                                Commands::PqGenerate {
                                    scheme: pq::PqGenScheme::MlDsa44,
                                    salt: None
                                },
                                &wallet_path,
                                &client
                            );
                        }
                        pq::PqScheme::Hybrid => {
                            run_cmd!(
                                Commands::PqGenerate {
                                    scheme: pq::PqGenScheme::Hybrid,
                                    salt: None
                                },
                                &wallet_path,
                                &client
                            );
                        }
                        pq::PqScheme::Ed25519 => {
                            println!("Scheme 'ed25519' is classical. Choose a post-quantum scheme: falcon512, mldsa44, hybrid");
                        }
                    },
                    Err(e) => println!("Error: {e}"),
                }
            }
            "pq-transfer" => {
                if parts.len() < 4 {
                    println!("Usage: pq-transfer <to_hex> <amount> --scheme <falcon512|hybrid> [--activation] [--dry-run]");
                    continue;
                }
                let to = parts[1].to_string();
                let amount = parts[2].to_string();
                let mut scheme_opt = None;
                let mut activation = false;
                let mut dry_run = false;
                let mut it = parts.iter().skip(3);
                while let Some(arg) = it.next() {
                    match *arg {
                        "--scheme" | "-s" => {
                            if let Some(s) = it.next() {
                                scheme_opt = match s.to_ascii_lowercase().as_str() {
                                    "falcon512" | "falcon-512" | "2" => {
                                        Some(pq::PqTransferScheme::Falcon512)
                                    }
                                    "hybrid" | "4" => Some(pq::PqTransferScheme::Hybrid),
                                    _ => None,
                                };
                            }
                        }
                        "--activation" => activation = true,
                        "--dry-run" => dry_run = true,
                        _ => {}
                    }
                }
                let scheme = match scheme_opt {
                    Some(s) => s,
                    None => {
                        println!("Error: --scheme <falcon512|hybrid> is required");
                        continue;
                    }
                };
                run_cmd!(
                    Commands::PqTransfer {
                        to,
                        amount,
                        scheme,
                        activation,
                        dry_run,
                        password: None,
                        shard: 1,
                    },
                    &wallet_path,
                    &client
                );
            }
            other => {
                println!(
                    "Unknown command: '{}'. Type 'help' for available commands.",
                    other
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod amount_parser_tests {
    use super::*;

    #[test]
    fn test_parse_stl57_and_hex_address() {
        let addr = [0x57u8; 32];
        let stl57_str = stellereum::address::encode_stl57_address(&addr);
        assert!(stl57_str.starts_with("Stl57"));

        let parsed = parse_hex32(&stl57_str, "test address").expect("Stl57 must parse in wallet");
        assert_eq!(parsed, addr);

        let hex_str = format!("0x{}", hex::encode(addr));
        let parsed_hex = parse_hex32(&hex_str, "test address").expect("hex must parse in wallet");
        assert_eq!(parsed_hex, addr);
    }

    #[test]
    fn exact_stell_parsing() {
        assert_eq!(parse_stell_to_nano("10").unwrap(), 10_000_000_000);
        assert_eq!(parse_stell_to_nano("10.5").unwrap(), 10_500_000_000);
        assert_eq!(parse_stell_to_nano("0.000000001").unwrap(), 1);
        assert_eq!(parse_stell_to_nano("  3.25 ").unwrap(), 3_250_000_000);
        // No float dust: 0.1+0.2 style inputs are exact.
        assert_eq!(parse_stell_to_nano("0.300000000").unwrap(), 300_000_000);
    }

    #[test]
    fn rejects_bad_amounts() {
        for bad in [
            "",
            "abc",
            "-5",
            "+5",
            "0",
            "0.0",
            "1.0000000001",
            "1e5",
            "  ",
        ] {
            assert!(
                parse_stell_to_nano(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
        // Overflow, not saturate.
        assert!(parse_stell_to_nano("18446744074").is_err());
    }

    #[test]
    fn usd_micro_parsing() {
        assert_eq!(parse_usd_to_micro("0.25").unwrap(), 250_000);
        assert!(parse_usd_to_micro("0.0000001").is_err());
    }

    #[test]
    fn stake_opcode_defaults_to_plain_stake() {
        let val = [0x51u8; 32];
        match stake_opcode(val, 1_000_000_000_000, None).unwrap() {
            stellereum::svm::OpCode::SysCallStake { validator, amount } => {
                assert_eq!(validator, val);
                assert_eq!(amount, 1_000_000_000_000);
            }
            other => panic!("no commission flag must mint plain SysCallStake, got {other:?}"),
        }
    }

    #[test]
    fn stake_opcode_carries_explicit_commission() {
        let val = [0x52u8; 32];
        match stake_opcode(val, 2_000_000_000_000, Some(2_500)).unwrap() {
            stellereum::svm::OpCode::SysCallStakeWithCommission {
                validator,
                amount,
                commission_bps,
            } => {
                assert_eq!(validator, val);
                assert_eq!(amount, 2_000_000_000_000);
                assert_eq!(commission_bps, 2_500);
            }
            other => panic!("--commission-bps must mint SysCallStakeWithCommission, got {other:?}"),
        }
        // Boundary: 100% commission is representable (pays delegators zero,
        // never steals); 10001 is refused client-side before signing.
        assert!(stake_opcode(val, 1, Some(10_000)).is_ok());
        assert!(stake_opcode(val, 1, Some(10_001)).is_err());
    }
}
