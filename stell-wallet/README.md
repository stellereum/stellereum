> **⚠️ Unaudited testnet — do not use real funds.** This code has passed internal audits and penetration tests, but no independent external audit has been completed yet. It is published for testnet use and review only; do not trust it with real funds or mainnet keys until an external audit is done.

# 💳 Stell-Wallet (`stell`)

<p align="center">
  <strong>Lightweight CLI Wallet & SPV Client for Stellereum L1 Blockchain</strong><br/>
  <em>Local simulation by default • Chain-verified RPC mode with --rpc-url</em>
</p>

---

## ⚡ Modes (read this first)

`stell` runs in exactly one of two modes, shown on every command as `• Mode:`:

* **Local mode (default, no `--rpc-url`):** an in-process simulation against a
  local state cache (`~/.stellereum/state_cache.bin`, optional infnode P2P
  adapter via `--config`). Balances, transfers, token ops and orderbook views
  are SELF-CONSISTENT with this cache only. **This mode proves
  self-consistency, NOT chain inclusion, and nothing here is chain-finalized.**
  Every command output says so.
* **HTTP-RPC mode (`--rpc-url http://host:port`):** talks to a real Stellereum
  node over JSON-RPC (stdlib-only HTTP, no extra deps). Balances and token
  balances are fetched WITH Merkle proofs from the node
  (`stell_getBalanceSpv` / `stell_tokenBalanceSpv`) and the proofs are
  verified LOCALLY against the node-served state root. Submitted transactions
  are polled via `stell_getTransactionReceipt` until they are
  **Pending / Confirmed (finalized height N) / Failed / Unknown** — the wallet
  never reports `Confirmed` before a success receipt exists.

```bash
# Chain-verified balance + nonce (proof checked locally against node root)
stell --rpc-url http://127.0.0.1:8545 balance

# Write calls need the node's API token (env fallback STELL_RPC_AUTH_TOKEN)
export STELL_RPC_AUTH_TOKEN="<node token>"
stell --rpc-url http://127.0.0.1:8545 pay <ADDR_HEX> 10.5

# Faucet needs the faucet token (env fallback STELL_FAUCET_TOKEN)
export STELL_FAUCET_TOKEN="<faucet token>"
stell --rpc-url http://127.0.0.1:8545 faucet 500
```

Polling knobs (global flags): `--timeout 60` (seconds to wait for finality),
`--poll-interval 2` (seconds between receipt polls).

---

## 🛠 Command Reference

### 1. Create / Restore a Wallet

```bash
stell new
stell restore --phrase "word1 word2 ... (24 words)"   # or --key <hex32>
```

* Creates a 24-word recovery phrase (256-bit entropy + 8-bit SHA-256
  checksum, BIP-39-*style* structure but a **project wordlist and KDF** —
  it will NOT import into standard BIP-39 wallets).
* Vault file `~/.stellereum/wallet.json`, permissions forced to `0600`
  (parent dir `0700`).

### 2. Balance (SPV)

```bash
stell balance
stell --rpc-url http://127.0.0.1:8545 balance
```

* Local mode: verified against the LOCAL state root only (self-consistency).
* RPC mode: node-served root + proof, verified locally; a failed proof prints
  `❌ PROOF FAILED` and must not be trusted.

### 3. Receive / Address / QR

```bash
stell receive
```

Prints address, a freshly generated stealth one-time address (randomized per
call — it is a demo address, not derived from your seed), and an ASCII QR
code. Address coloring is visual highlighting only — it is NOT a checksum,
always verify the full string.

### 4. Send STELL

```bash
stell pay <RECIPIENT_HEX32> 15.5
# Cross-shard: --source-shard/--target-shard override --shard (default: both = --shard, old behavior)
stell pay <RECIPIENT_HEX32> 15.5 --source-shard 1 --target-shard 2
```

Signs a native transfer (fee = `GAS_BASIC_TRANSFER` = 280_000 nano-STELL) and
either applies it to the local cache (simulated) or submits it to the node
and polls the receipt. Finality is reported honestly, never `Confirmed`
before finality.

### 5. Confidential transfers

```bash
# Local commitment demo (NOT submitted anywhere):
stell stealth-pay <STEALTH_HEX32> 25.0
# Real shielded tx (SysCallConfidentialTransfer): conservation-checked,
# signed, submitted; prints tx hash + auditor viewing info:
stell confidential-pay <SHIELDED_ADDR_HEX32> 25.0 [--fee 1500]
stell --rpc-url http://127.0.0.1:8545 confidential-pay <ADDR> 25.0
```

Amounts are hidden in Pedersen commitments; conservation (`Σin − Σout = fee·G`)
is verified before signing. Forged transfers are rejected before signing.
The chain enforces conservation on inclusion; range proofs are not attached
yet, so these are *confidential (hidden-amount)* transfers, not full ZK
with inflation-proof range checks. For audits, `confidential-pay` prints your
viewing public key and the output blinding factor — share those with YOUR
auditor only.

### 6. STS tokens

```bash
stell token-balance <TOKEN_ID_HEX32> [ACCOUNT_HEX32]   # own address default
stell token-list [--limit 100] [--offset 0]            # paginated {tokens,total,offset}
stell token-send <TOKEN_ID> <TO_HEX32> <AMOUNT_BASE_UNITS>
stell token-approve <TOKEN_ID> <SPENDER_HEX32> <AMOUNT_BASE_UNITS>
```

* `SysCallTokenTransfer` / `SysCallTokenApprove` payloads, zero native amount,
  gas = max(token opcode gas, 280_000).
* Amounts are raw base units (u64, no decimals conversion).
* RPC mode verifies `stell_tokenBalanceSpv` proofs locally with a
  locally-recomputed namespaced key (a server-swapped key is rejected).
* Local mode executes against the local token registry (simulated).

### 7. Receipts / finality

```bash
stell --rpc-url http://127.0.0.1:8545 receipt <TX_HASH_HEX>
```

Single honest read of `stell_getTransactionReceipt`
(Pending / Confirmed @height / Failed / Unknown). Requires RPC mode — local
mode keeps no chain receipts.

### 8. History

```bash
stell history
```

Local record of submitted/simulated transactions with honest status strings.
History is a local log, not chain data.

### 9. CLOB orderbook (LOCAL SIMULATION)

```bash
stell book --pair 1
stell buy 500 0.25 --pair 1
stell sell 200 0.26 --pair 1
stell cancel 1 --pair 1
```

These operate on a **local cached orderbook**, not the chain's
Orderbook-Actors. They never place on-chain orders. (The node CLI submits
`SysCallPlaceOrder` over RPC; this wallet does not yet wire that path.)

### 10. Session delegation to AI bots

```bash
stell session --session-pub <BOT_PUB_HEX32> [--max-gas 50000] [--duration 3600] \
  [--scope 1] [--max-value 18446744073709551615] [--chain-id 7777]
```

Mints a 6-field delegation (`session_pub, max_gas, valid_until, scope,
max_value_per_tx, chain_id`; scope bit 0 = transfers, bit 1 = SVM payloads,
bit 2 = actor sends; default = transfers only (`--scope 1`, least privilege).
> **Migration note:** the scope default changed from `u64::MAX` (all scopes)
> to `1` (transfers only). Grants minted with the old default covered SVM
> payloads and actor sends; re-mint with an explicit `--scope` if the bot
> needs more than transfers. In RPC mode the node's live
`stell_chainId` overrides a default `--chain-id`, so the grant binds to the
chain it will be used on. Note: this prints an **off-chain grant** — it
becomes enforceable only when published in a `SysCallPublishSessionGrant`
transaction.

### 11. Genesis Vault quote (LOCAL ESTIMATE)

```bash
stell mint USDT 100 1.0
```

Runs the `GenesisVault` math locally at the initial $0.25 reference rate. It
does NOT mint on chain.

### 12. Network status / console

```bash
stell status
stell console   # or bare `stell` — REPL with help, pay, tokens, receipt, ...
```

`status` in RPC mode also prints the chain height (`stell_blockNumber`) and
whether the node is syncing (`stell_syncing`, both read-only).

### 13. Message signing (wallet signature standard)

Implements the node-repo standard (`docs/WALLET_SIGNING.md`): EIP-191-style
preimage with the chain id bound in, standard envelope
(version + scheme + pubkey + signature, hex). The wallet signs with its OWN
key — nothing is sent to a node.

```bash
# Sign with this wallet's key (password unlocks the vault locally):
stell sign --message "hello" [--chain-id 5757]
stell sign --message-hex 0xdeadbeef

# Verify offline (no key, no network; exit non-zero when INVALID):
stell verify --address <hex|Stl57> --message "hello" --signature <hex envelope>

# Structured contract calls (EIP-712-style): the canonical JSON is displayed
# AND signed, so you see exactly what you authorize. Key order in --args
# does not matter (it is re-encoded canonically).
stell sign-typed-data --contract <hex> --method transfer \
  --args '{"to":"alice","amount":100}' --value 1000 --nonce 7
stell verify-typed-data --address <hex> --contract <hex> --method transfer \
  --args '{"amount":100,"to":"alice"}' --value 1000 --nonce 7 \
  --signature <hex envelope>
```

`--chain-id 0` (the default) asks the connected node for `stell_chainId` and
falls back to the deployment default when offline. A signature minted for one
chain never verifies on another; any tampered byte fails.

---

## 🔒 Security Specifications (verified against `src/security.rs`)

* **Vault File:** `~/.stellereum/wallet.json` (`0600`, parent dir `0700`;
  best-effort `chmod` on each access, errors ignored).
* **KDF:** Argon2id (`m=65536` KiB ≈ 64 MiB, `t=3`, `p=4`, 32-byte output).
* **Cipher:** XChaCha20-Poly1305 (256-bit key, random 192-bit/24-byte nonce,
  128-bit Poly1305 tag; tampered ciphertext/tag is rejected).
* **Memory:** master secret lives in `SecureSecret` with `ZeroizeOnDrop`; an
  `mlock` is *attempted* but is best-effort only (return value unchecked, no
  unlock, and it does not cover every copy — e.g. password strings and
  intermediate buffers are not pinned/zeroized). Do not assume secrets never
  touch swap.
* **Mnemonic:** 24 words, 256-bit entropy + 8-bit checksum, project wordlist
  (NOT standard BIP-39 — restores only in Stellereum tooling).
* **Addresses:** color highlighting is cosmetic, not a checksum.

---

## ✅ What is tested here vs what needs the live stand

* `cargo test` runs 5 keystore/mnemonic/SPV unit tests plus 19 RPC/token/
  confidential/honesty tests — all against loopback stubs and the local
  engine. **No test touches the live stand.**
* Still requiring live verification (needs `STELL_RPC_AUTH_TOKEN` /
  `STELL_FAUCET_TOKEN` on the stand, loopback-only `127.0.0.1:8545/8546`):
  real `stell_getBalanceSpv` proof acceptance, real `stell_sendRawTransaction`
  admission + receipt finalization for native/token/confidential payloads,
  real `stell_faucet` drips, and `stell_chainId` agreement with session grants.
