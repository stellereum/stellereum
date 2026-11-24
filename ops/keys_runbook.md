# Stellereum Key Operations & Remote Signer Runbook

Covers the real key architecture in `stellereum/src/node_keys.rs`,
`stellereum/src/remote_signer.rs`, `stellereum/src/node/bootstrap.rs`, and
`stellereum/src/cli/`: key separation, encrypted-at-rest storage, running with
`RemoteSigner` / `PqSigner` (`RemotePqSigner`), key rotation procedures, and
4-eyes approval + audit logging for `validator unjail` and governance actions.

No secret material, passphrases, or private seeds belong in this runbook.

---

## 1. Key Architecture & Storage Policy

### 1.1 Key files & permissions (`stellereum/src/node_keys.rs`)

- **Keys directory** (`--keys-dir`, default `./keys`): must not be a symlink and
  must have mode `0700` (`verify_dir_perms` / `ensure_secure_dir`).
- **Key files**: must be regular files (never symlinks) with strict mode `0600`
  (`verify_file_perms` / `write_private_file`).
- **Per-node artifacts**:
  - `e2e.key`: 64-byte ML-KEM-768 seed (hex) for `infnode` P2P E2E transport.
    Legacy 32-byte X25519 `e2e.key` files are refused loudly.
  - `pq-identity.key`: Falcon-512 keypair for `infnode` P2P transport identity
    (`PqKeys`).
  - `validator.key`: consensus-only Ed25519 key (`CONSENSUS_KEY_FILE`, migrated
    once from legacy `identity.key` -> `identity.key.migrated`).
  - `falcon.key` (overridable via `STELL_FALCON_KEY_FILE` or `--falcon-file`):
    Falcon-512 consensus voting/proposal keypair (FULL-PQ).
  - Cold withdrawal key (operator-managed Falcon-512 key file, e.g.
    `withdrawal.key`): owns staking bond, unjailing, commission changes, voting
    key rotation, and reward claims.

### 1.2 At-rest encryption (`enc2:`)

Newly generated or saved keys are encrypted at rest as
`enc2:<salt>:<nonce>:<ct>` using Argon2id (`65536 KiB`, `t=3`, `p=4`) +
XChaCha20-Poly1305.

Passphrase environment variables checked by `get_passphrase()` (first non-empty
wins):
1. `STELL_NODE_PASSPHRASE` (`ENV_PASSPHRASE`)
2. `STELL_KEY_PASSPHRASE` (`ENV_PASSPHRASE_ALT`)
3. `INFNODE_KEY_PASSPHRASE` (`FALLBACK_ENV_PASSPHRASE`)

Optional storage env vars:
- `STELL_KEY_PLAINTEXT=1` (`1|true|yes|on`): explicit opt-out allowing plaintext
  writes. Without a passphrase and without this opt-out, key writes **fail
  closed**.
- `STELL_KEY_PROMPT`: opt-in interactive passphrase prompt on TTY.
- `STELL_FALCON_KEY_FILE`: overrides `<keys-dir>/falcon.key`.

Generate initial node keys idempotently and print the peer stanza:

```sh
stellereum keys init --keys-dir ./keys
stellereum keys peer-stanza --keys-dir ./keys --name <NODE_NAME> --endpoint <PUBLIC_IP:9410>
```

---

## 2. Offline-Cold vs Hot-Ops Separation

| Tier | Key / Identity | Where it lives | Allowed operations | Never allowed |
|---|---|---|---|---|
| **Hot-Ops (Transport)** | `e2e.key`, `pq-identity.key` | Validator node (`./keys`) | P2P QUIC identity & ML-KEM-768 E2E session setup | Signing consensus votes or staking/withdrawal txs |
| **Hot-Ops (Consensus)** | `falcon.key` (or `RemotePqSigner` v2 HSM/service), `validator.key` (legacy v1) | Remote signer service (preferred) or `./keys/falcon.key` | BFT prevotes, precommits, proposals (guarded by `ConsensusSafetyGuard` / `SafetyRecordStore`), co-signing one-time `claim-withdrawal` | Unbonding/withdrawing stake, unjailing (Ruleset v7), changing commission, rotating voting key |
| **Offline-Cold (Owner)** | Cold withdrawal Falcon-512 key (`--withdrawal-key-file`) | Offline / air-gapped workstation or cold HSM | `validator register-validator`, `stake`, `unbond`, `withdraw`, `claim-rewards`, `announce-commission`, `apply-commission`, `rotate-voting-key`, `change-withdrawal`, `claim-withdrawal`, `unjail`, governance (`gov propose` / `gov vote`) | Never placed in the hot validator's consensus signer loop or shared env files |

### Offline signing workflow for cold keys

All cold-key CLI commands (`validator ...`, `gov ...`, `wallet unjail`) support:
- `--dry-run`: prints the verified transaction hash, parameters, and `raw: <hex>`
  without submitting.
- `--nonce <N>` and `--chain-id <ID>`: allows building and signing the PQ1
  envelope on an air-gapped machine with zero RPC connectivity.

Transport the printed raw transaction hex from the air-gapped host to an online
host and submit via JSON-RPC `stell_sendRawTransaction` (`{"tx": "<hex>"}`).

---

## 3. Running with `RemoteSigner` / `PqSigner`

`stellereum/src/remote_signer.rs` provides two fail-closed remote signer paths:
- **v2 FULL-PQ (`PqSigner` / `RemotePqSigner` / `HttpPqSignerTransport`)**:
  Falcon-512 consensus votes & proposals with anti-oracle preimage checks and
  durable anti-equivocation (`ConsensusSafetyGuard` + `SafetyRecordStore`).
- **v1 Legacy (`Signer` / `RemoteSigner` / `HttpSignerTransport`)**:
  Ed25519 legacy path (`ValidatorSigner::Remote`).

### 3.1 Environment variables (`stellereum/src/remote_signer.rs`, `bootstrap.rs`)

- `STELL_REMOTE_SIGNER_URL` (`REMOTE_SIGNER_URL_ENV`): Base URL of the remote
  signing service (e.g. `https://signer.internal:8443` or loopback
  `http://127.0.0.1:8443`).
- `STELL_REMOTE_SIGNER_TOKEN` (`REMOTE_SIGNER_TOKEN_ENV`): Optional bearer token
  sent as `Authorization: Bearer <token>`.

### 3.2 Fail-closed guarantees enforced in code

1. **Zero local fallback**: When `STELL_REMOTE_SIGNER_URL` is non-empty,
   `bootstrap.rs` and `consensus_driver.rs` **never** open or generate
   `./keys/falcon.key` and never fall back to local key material. An unreachable
   or misconfigured signer aborts startup / refuses to sign.
2. **HTTPS enforced off loopback**: `HttpPqSignerTransport` permits plain
   `http://` only for `127.0.0.1`, `[::1]`, or `localhost`
   (`is_loopback_base_url`). Any non-loopback `http://` URL fails with
   `SignerError::PlainHttpForbiddenOnNonLoopback`.
3. **Pinned identity**: `RemotePqSigner::new` resolves `GET /v2/public_key` at
   startup, checks `scheme_id == 2` (`Falcon512`), `public_key.len() == 897`
   (header byte `0x09`), `validator_id == expected_validator_id`, and (when
   configured) committed public key match, then pins the key for the process
   lifetime. Every returned signature is re-verified locally.
4. **Anti-oracle & anti-equivocation (`PqSignerService`)**:
   - `POST /v2/sign` accepts `SignRequestV2` (`ConsensusSignRequest::Vote` or
     `Proposal`) and runs `verify_and_extract_preimage` against
     `STELLEREUM_BFT_VOTE_V3` / proposal bytes. Non-consensus or mismatched
     preimages are rejected with HTTP `400` (`InvalidRequest`).
   - `ConsensusSafetyGuard::reserve_and_sign` persists the monotonic
     height/round/lock watermark to `SafetyRecordStore` *before* signing and
     refuses equivocation with HTTP `409` (`SafetyViolation`) or `503`
     (`SafetyStoreQuarantined`).
5. **Transport hardening**: 5 s request timeout (`DEFAULT_TIMEOUT`), `redirects(0)`,
   `try_proxy_from_env(false)`, and `8 KiB` response cap (`MAX_RESPONSE_BYTES`).

### 3.3 Startup checklist with `RemotePqSigner`

1. On the remote signer host (`PqSignerService` / `serve_v2_http_connection`),
   bind to loopback or TLS/mTLS endpoint, configure `ConsensusSafetyGuard::from_durable`
   on a dedicated `SafetyRecordStore`, and set a strong bearer token.
2. Ensure all legacy validator processes and signers for this key are stopped
   and fenced. If initializing a fresh safety store on the node side:
   ```sh
   stellereum safety-init \
     --store-dir ./data/store \
     --keys-dir ./keys \
     --validator-pub <64-HEX-VALIDATOR-PUB> \
     --shard 0 \
     --i-fenced-all-signers
   ```
3. In the node's `0600` environment file (never in git or shell history):
   ```sh
   STELL_REMOTE_SIGNER_URL=https://signer.internal:8443
   STELL_REMOTE_SIGNER_TOKEN=<REDACT_TOKEN>
   ```
4. Remove or archive any stale `./keys/falcon.key` from the validator host after
   verifying the remote signer is active, and start the node (`stellereum run ...`).
   Confirm `[post-quantum] validator Falcon-512 pubkey (v2 signer): ...` in logs.

---

## 4. Key Rotation Procedures

### 4.1 Rotate hot Falcon-512 voting key on-chain (`OpCode 60: SysCallRotateVotingKey`)

Preserves the immutable 32-byte `validator_id`. Rotation takes effect after
`PQ_ROTATION_DELAY_HEIGHTS = 30_000` heights (`stellereum/src/pq_registry.rs`);
the current key continues voting until the effective height.

1. **Generate the new Falcon-512 key** into a separate staging file (do NOT
   overwrite the live `falcon.key` yet):
   ```sh
   STELL_KEY_PASSPHRASE='<passphrase>' stellereum keys init \
     --keys-dir ./keys-next \
     --falcon-file ./keys-next/falcon.key
   ```
2. **Inspect current validator state** to obtain `validator_id` and expected
   `PqKeyRecord::next_seq`:
   ```sh
   stellereum validator status --validator <64-HEX-VALIDATOR-ID> --rpc <RPC_URL>
   ```
3. **Announce rotation (signed by the cold withdrawal key)**:
   ```sh
   # Dry-run first for 4-eyes verification:
   stellereum validator rotate-voting-key \
     --withdrawal-key-file <COLD_WITHDRAWAL_KEY_FILE> \
     --validator-id <64-HEX-VALIDATOR-ID> \
     --rotation-seq <NEXT_SEQ> \
     --new-voting-key-file ./keys-next/falcon.key \
     --rpc <RPC_URL> \
     --dry-run

   # Broadcast after 4-eyes sign-off:
   stellereum validator rotate-voting-key \
     --withdrawal-key-file <COLD_WITHDRAWAL_KEY_FILE> \
     --validator-id <64-HEX-VALIDATOR-ID> \
     --rotation-seq <NEXT_SEQ> \
     --new-voting-key-file ./keys-next/falcon.key \
     --rpc <RPC_URL>
   ```
   To cancel an unmatured pending rotation before the effective height:
   ```sh
   stellereum validator rotate-voting-key \
     --withdrawal-key-file <COLD_WITHDRAWAL_KEY_FILE> \
     --validator-id <64-HEX-VALIDATOR-ID> \
     --rotation-seq <NEXT_SEQ> \
     --cancel \
     --rpc <RPC_URL>
   ```
4. **Cut over at maturity height** (`announced_height + 30_000`):
   - Pause `stell-node-guard.timer` before stopping the node or remote signer.
   - Install the new key in the remote signer (or replace `./keys/falcon.key`
     preserving `0600` perms and `enc2:` encryption), then restart and resume
     `stell-node-guard.timer`.

### 4.2 Rotate cold withdrawal key (`OpCode 61: SysCallChangeWithdrawal`)

```sh
# 1. Dry-run for 4-eyes review:
stellereum validator change-withdrawal \
  --withdrawal-key-file <CURRENT_COLD_KEY_FILE> \
  --validator-id <64-HEX-VALIDATOR-ID> \
  --new-withdrawal-key-file <NEW_COLD_KEY_FILE> \
  --rpc <RPC_URL> \
  --dry-run

# 2. Submit after 4-eyes approval:
stellereum validator change-withdrawal \
  --withdrawal-key-file <CURRENT_COLD_KEY_FILE> \
  --validator-id <64-HEX-VALIDATOR-ID> \
  --new-withdrawal-key-file <NEW_COLD_KEY_FILE> \
  --rpc <RPC_URL>
```

For a pre-W3 validator whose `withdrawal_address` is still `null`, perform the
one-time migration first (`OpCode 62`, co-signed by cold + hot voting keys; the
new cold address must be funded first to pay gas):

```sh
stellereum validator claim-withdrawal \
  --withdrawal-key-file <NEW_COLD_KEY_FILE> \
  --validator-id <64-HEX-VALIDATOR-ID> \
  --voting-key-file <HOT_VOTING_KEY_FILE> \
  --rpc <RPC_URL>
```

### 4.3 Local node Falcon key migration (`keys rotate-falcon`)

Used only when migrating a local key file to a complete FIPS 206 (FN-DSA) NTRU
`(f, g, F, G)` keypair where changing the derived address is intended (e.g.
pre-registration or re-staking under a new validator address). This backs up the
old file to `<file>.bak-<unix-ts>` (`0600`) and **changes** the derived
address:

```sh
stellereum keys rotate-falcon --keys-dir ./keys --force
```

Do **not** run `keys rotate-falcon` on an active staked validator expecting to
keep the same `validator_id`; use `validator rotate-voting-key` (§4.1) instead.

---

## 5. 4-Eyes Approval Workflow & Audit Log (`validator unjail` & Governance)

High-impact cold-key operations (`validator unjail`, `validator change-withdrawal`,
`validator rotate-voting-key`, `validator unbond`/`withdraw`, `gov propose`,
`gov vote`) require **two independent operators** (Proposer = Operator A,
Reviewer = Operator B) before broadcast.

### 5.1 Pre-flight & Dry-Run (Operator A)

1. **Inspect live validator / governance state**:
   ```sh
   stellereum status --rpc <RPC_URL> --expect 4
   stellereum validator status --validator <64-HEX-VALIDATOR-ID> --rpc <RPC_URL>
   # For governance:
   stellereum gov list --rpc <RPC_URL>
   stellereum gov params --rpc <RPC_URL>
   stellereum gov show --id <PROPOSAL_ID> --rpc <RPC_URL>
   ```
   For `unjail`, confirm `released: yes` (`current_height >= release_height`)
   and that the cold `withdrawal_address` has sufficient balance for gas + any
   `--top-up`.
2. **Generate a `--dry-run` artifact** (never pass or paste seeds/passphrases
   into chat or logs):
   ```sh
   # Example: validator unjail dry-run
   stellereum validator unjail \
     --withdrawal-key-file <COLD_WITHDRAWAL_KEY_FILE> \
     --validator-id <64-HEX-VALIDATOR-ID> \
     --rpc <RPC_URL> \
     --dry-run

   # Example: governance proposal / vote dry-run
   stellereum gov propose \
     --falcon-key-file <COLD_OR_GOV_KEY_FILE> \
     --title "<TITLE>" \
     --action <ACTION_TYPE> \
     --params '<JSON_PARAMS>' \
     --rpc <RPC_URL> \
     --dry-run

   stellereum gov vote \
     --falcon-key-file <COLD_OR_GOV_KEY_FILE> \
     --id <PROPOSAL_ID> \
     --choice <yes|no|abstain> \
     --rpc <RPC_URL> \
     --dry-run
   ```
3. Share with Operator B: the exact redacted command, `Hash`, `Validator ID` /
   `Proposal ID`, `Withdrawal` / signer address, `Top-up` or `Action`/`Params`,
   `Chain Id`, and `Nonce`.

### 5.2 Independent Verification (Operator B)

Operator B independently queries `<RPC_URL>` (from their own session) and
verifies:
1. Target `validator_id` / `proposal_id` and `chain_id` match the intended
   incident or governance decision.
2. For `unjail`: root cause of the 42-miss downtime is remediated (node synced,
   single PID, disk/inodes healthy, `stell-node-guard.timer` active) so it will
   not immediately re-jail.
3. For `gov propose` (`software_upgrade` or parameter changes): target height,
   SHA-256 digest, and parameters match the verified release artifact.
4. `Nonce` matches the current on-chain account nonce and no duplicate tx is
   pending.
5. Operator B records explicit written approval (incident ticket / signed chat
   message referencing the dry-run `Hash`).

### 5.3 Execution & Append-Only Audit Log

1. After Operator B's sign-off, Operator A executes the exact command without
   `--dry-run` (or submits the approved `raw` hex via `stell_sendRawTransaction`
   if signed offline) and confirms inclusion (`stellereum validator status`
   showing `jailed: false` or `stellereum gov show --id <ID>`).
2. Immediately append an entry to the operator audit log (e.g.
   `/var/log/stellereum/key-ops-audit.log`, `0600` or append-only):

   ```text
   utc=2026-11-24T12:00:00Z op_a=<operator_a> op_b=<operator_b> action=validator_unjail validator_id=<64-hex> chain_id=5757 nonce=<n> tx_hash=<64-hex> included_height=<h> ticket=<INC-XXXX> result=ok
   ```

   **Redaction rule**: NEVER record private keys, hex seeds, passphrases,
   `--token` values, or `STELL_REMOTE_SIGNER_TOKEN` in the audit log or shell
   command history (`HISTCONTROL=ignorespace` / env-file only).
