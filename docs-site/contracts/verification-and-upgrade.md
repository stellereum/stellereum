---
title: Verification and upgrade
description: 'Publish and verify contract source, understand what "verified" proves, and migrate to a new contract safely because in-place upgrades do not exist.'
---

# Verification and upgrade

Two questions decide how you ship a contract change: is this bytecode what the source says it is, and how do I replace code that cannot be upgraded in place? This page answers both. It documents source verification, states exactly what `verified: true` proves, and walks through a migration to a new address.

## Source verification

The node implements Sourcify-style verification for its canonical `.wat` pipeline
(`stellereum/src/contract_source.rs`). It recompiles the claimed source, hashes the rebuilt
bytecode, and compares it to the on-chain `code_hash`.

### RPC surface

| Method | Changes state? | Purpose |
| --- | --- | --- |
| `stell_verifyContractSource` | no | rebuild and compare; never writes |
| `stell_registerContractSource` | **yes** | creator-signed registration of a fingerprint |
| `stell_getContractSource` | no | read the registered fingerprint |
| `stell_getContractAbi` | no | read the manifest (if attached) |
| `stell_getContractReceipt` | no | read a call outcome |

### `stell_verifyContractSource`

```json
{
  "method": "stell_verifyContractSource",
  "params": {
    "contract": "0x<32-byte address>",
    "source": "(module …)",
    "compiler": "wat2wasm-1.0",
    "compiler_flags": ""
  }
}
```

`source` may be inline text, `source_hex` may carry the hex of the UTF-8 text, and `source_hash`
alone performs a **hash-only** check.

```json
{
  "contract": "<64 hex>",
  "contract_stl57": "Stl57…",
  "verified": true,
  "onchain_code_hash": "<64 hex>",
  "rebuilt_code_hash": "<64 hex>",
  "source_hash": "<64 hex>",
  "compiler": "wat2wasm-1.0",
  "compiler_flags": "",
  "reason": "ok",
  "registered": false,
  "registered_source_hash": ""
}
```

#### What the rebuild uses

- The canonical source form is **`.wat` text**, compiled with the Rust `wat` crate
  (`wat::parse_str`). Deployment itself accepts wasm **bytes**, not WAT, so the bytes you deploy
  must be exactly what this pipeline produces for verification to succeed.
- `source_hash = BLAKE3(source_text)`.
- The on-chain `code_hash` is ground truth. Verification accepts a match against either
  **BLAKE3(code)** or **SHA-256(code)**, because the registry has used SHA-256 while some
  historical deploy paths used BLAKE3. The stored hash is never recomputed or "corrected".
- Supported `compiler` labels: `wat-1.0`, `wat2wasm-1.0`, `wat`, `wat2wasm`, `wast-1.0`.
  Anything else is a **refusal**, not a guess.
- Supported `compiler_flags`: `""`, `default`, `canonical`, `--canonical`. The Rust pipeline has no
  flag surface, so only these no-op spellings are reproducible.
- Source text is capped at **1 MiB**.

::: danger `wat2wasm` on your machine is not the node's compiler
The accepted string `wat2wasm-1.0` labels the node's Rust `wat` pipeline; it does not run WABT.
WABT and `wat` can emit different but equivalent binaries. If you deployed WABT output, an honest
source can still answer `verified: false`. See [`/contracts/wat`](/contracts/wat#compile).
:::

#### Hash-only mode

If you provide only `source_hash`, the node answers whether it equals the **registered** hash. It
does not rebuild anything and it always returns `verified: false`:

```json
{
  "verified": false,
  "hash_matches_registered": true,
  "rebuilt_code_hash": null,
  "reason": "hash-only check: matches the registered source hash, but NO rebuild was performed — submit the source text to verify"
}
```

A hash claim is not a verification.

#### Failure shape

Bad source, a wrong compiler label, unsupported flags, invalid UTF-8 or a bytecode mismatch are all
**answers** with `verified: false` and a machine-readable `reason`. Only malformed parameters
(missing contract, bad address, missing source, oversize source) are RPC errors (`-32602`).

### `stell_registerContractSource`

Registration is the only state-changing half, and it is deliberately hard to earn.

```json
{
  "method": "stell_registerContractSource",
  "params": {
    "contract": "0x<32-byte address>",
    "source_hash": "<64 hex BLAKE3 of the source text>",
    "signature": "<hex PQ signature>",
    "pubkey": "<optional Falcon-512 public key hex>",
    "source": "(module …)",
    "compiler": "wat2wasm-1.0",
    "compiler_flags": ""
  }
}
```

Requirements, in order:

1. **The source must be submitted.** A hash-only registration is refused because the node cannot
   rebuild it.
2. **The claimed `source_hash` must equal `BLAKE3(source_text)`.** Otherwise the signature would
   authorize different text than the one being registered.
3. **The source must rebuild to the deployed `code_hash`.** If it does not, registration is
   refused.
4. **The signature must be the contract creator's**, over:

   ```text
   b"STELL_REGISTER_SOURCE" ‖ contract[32] ‖ source_hash[32]
   ```

   Supported forms: a `PQ1` envelope (explicit or implicit via the global PQ key registry), raw
   `pubkey ‖ signature`, or a raw Falcon-512 signature with a `pubkey` parameter. The legacy
   64-byte Ed25519 branch is **removed**: such a signature is refused with an explicit migration
   error.
5. **Only the creator may register.** The engine checks `contract.creator == caller`; a stranger
   gets `NotFound`.

On success the node stores the fingerprint in the contract registry and the trie under
`sha256("STELL_CONTRACT_SOURCE" || address)`. The fingerprint is committed to the state digest
**only when present**, so unverified contracts keep byte-identical legacy roots.

::: warning Registration is an RPC-side write, not a transaction
`stell_registerContractSource` mutates the node's contract registry and trie entry directly. It
does not enter the mempool and is not a `SysCall*` opcode. Do not assume it is replicated through
consensus the way a deploy or call is; treat it as a node-side attestation action. It is
self-authenticating (creator signature), so no RPC token is required.
:::

### `stell_getContractSource`

```json
{
  "method": "stell_getContractSource",
  "params": { "contract": "0x<address>" }
}
```

```json
{
  "contract": "<64 hex>",
  "contract_stl57": "Stl57…",
  "code_hash": "<64 hex>",
  "source_hash": "<64 hex or empty>",
  "verified": true,
  "verification": "rebuild_at_registration",
  "verified_means": "the node rebuilt the registered source and matched this code_hash; a hash claim alone is never verified"
}
```

The node stores only the **fingerprint**, never the source text. The text must be published out of
band; the RPC code comment points at the indexer path
`GET /api/v2/contract/:address/source`, but that endpoint is not part of the node crate. Treat the
fingerprint as the on-chain claim and your own source repository as the canonical text.

`verified: true` here means "a fingerprint was registered after a successful rebuild", not "the
source is safe".

### Trust model: what `verified` proves

`verified: true` proves exactly:

1. the on-chain bytes are byte-identical to what **this node's current build** of the `wat`
   compiler produces from the submitted text with the claimed flags;
2. `source_hash` is the BLAKE3 digest of exactly that text.

It does **not** prove:

- that the source is safe or bug-free (a verified backdoor is still a backdoor);
- that the source matches a different compiler version or build flags;
- that the contract behaved honestly in the past;
- that the deployer was honest about intent.

It is a transparency claim, like Sourcify or NEAR verification, not a safety certificate.

## Upgrade model

::: danger There is no in-place upgrade
`Contract.code` is immutable. There is no `SysCallUpgradeContract`, no proxy slot, no
`set_code`, and no admin opcode. A new implementation is a **new contract at a new address**.
:::

A "migration" is therefore a copy:

```text
old contract (address A, code V1, storage S1)
        │
        ├─ 1. snapshot S1 and any native balance
        ├─ 2. deploy V2 at address B = sha256("STELL_CONTRACT" || creator || new_nonce)
        ├─ 3. feed the snapshot into B through explicit, authenticated calls
        ├─ 4. verify B's source and ABI; update clients/indexers
        └─ 5. drain A's balance, then retire A (pause is engine-level, irreversible, no RPC)
```

### Step 1 — snapshot the old state

Use `stell_getProgramAccounts` with `program: "contract"`:

```json
{
  "method": "stell_getProgramAccounts",
  "params": {
    "program": "contract",
    "contract": "0x<old address>",
    "slot_from": 0,
    "slot_to": 9223372036854775807,
    "limit": 100
  }
}
```

Page with `cursor` (a strict keyset continuation on the slot key), and record:

- every `(slot, value)` pair — the schema, not just the values;
- the native balance with `stell_getBalance`;
- the code hash, ABI and registered source hash (`stell_getContractAbi`,
  `stell_getContractSource`);
- the event history you need for accounting.

Slots are returned sorted numerically. Storage is **not** per-slot provable: `with_proof` returns
`null` with a note, so this snapshot is only as trustworthy as the node you read it from. For
high-value migrations, read from multiple nodes or recompute from events.

### Step 2 — deploy the new code

Same deploy transaction as any other, with a **new nonce** (so a new address). Do not try to reuse
the old address: the nonce has advanced, and the address is `(creator, nonce)`-derived.

If the new contract needs constructor state, add an `init`/`import` method that accepts the
snapshot in bounded chunks. Remember:

- at most 8 `i64` arguments per call;
- at most 64 KiB of calldata per transaction;
- at most 4,096 storage keys per contract;
- the migrating account must authenticate every write (`caller_is`).

### Step 3 — migrate explicitly

A contract **cannot read another contract's storage**: there is no host import for it, and there
are no synchronous calls. Migration is therefore an off-chain loop:

```text
for each chunk of the snapshot:
    sign a call to B.import(chunk)
    submit via stell_sendRawTransaction
    confirm the receipt
```

Design `import` to be:

- **idempotent** — a retried chunk must not double-count;
- **monotonic** — reject writes for an already-finalized key;
- **bounded** — a chunk must fit calldata and gas;
- **auditable** — emit an event per imported key range.

::: warning There is no atomic cutover
Between "V2 deployed" and "all state imported", both contracts exist and neither is authoritative.
Choose one of:

- a **freeze-then-migrate** window (stop using V1 first: remove it from your clients and warn
  users; if your node exposes the engine-level `pause`, use it, but there is no RPC for it);
- a **dual-read** window (clients read V2 once its import is complete, while V1 stays live for
  old reads);
- a **generation pointer** in your own client/indexer that names the authoritative address.

The chain will not do this for you.
:::

### Step 4 — switch clients and indexers

- Update the address in your app config, SDK constants and indexer.
- If the ABI changed, update the shipped manifest — the node does not publish one for a
  block-deployed contract (see [`/contracts/abi`](/contracts/abi)).
- Keep event topic numbers stable where possible. If you must change them, version them explicitly
  and teach the indexer both.
- Keep the old address and its code hash documented; users will still find it.

### Step 5 — drain, then retire the old contract

`ContractRegistry::pause` is creator-only and **there is no unpause**. It is also **not exposed by
any RPC method or opcode today**: it exists at the engine level (used by tests). So "pause the old
contract" is an operator capability, not something a dApp can do through the public API.

Two rules still matter:

1. **Drain the native balance first.** A contract can move its balance with
   `host.send_message` (which debits immediately) or by a guarded withdrawal method. If you can
   pause, no method can run afterwards, so value left in the contract is stranded.
2. **Retire what you cannot pause at the client layer.** Remove the old address from your app,
   indexer and docs, emit a deprecation notice, and keep monitoring it for stray calls. Anyone can
   still call a contract you no longer control.

If the old contract has no withdrawal path, you cannot recover its balance after pausing. Add one
before you need it.

## Verification and upgrade checklist

| # | Check | Tool |
| --- | --- | --- |
| 1 | Old code hash and ABI recorded | `stell_getContractAbi` + `stell_getProgramAccounts` (`include_code`) |
| 2 | Full storage snapshot paged and stored | `stell_getProgramAccounts` with `cursor` |
| 3 | Native balance noted | `stell_getBalance` |
| 4 | New contract deployed at a new address | signed `SysCallDeployContract` |
| 5 | New source rebuilds to the new code hash | `stell_verifyContractSource` |
| 6 | New fingerprint registered by the creator | `stell_registerContractSource` |
| 7 | Import calls complete and idempotent | receipts + your own invariant checks |
| 8 | Read-back checks: balances, supply, owners, counters | `stell_runGetMethod` |
| 9 | Clients/indexers point at the new address | your deployment config |
| 10 | Old balance drained | `stell_getBalance` on old address |
| 11 | Old contract retired (paused only if engine-level pause is available) | node operator / your deployment config |
| 12 | Old address documented as deprecated | your docs/changelog |

## Common mistakes

| Mistake | Consequence |
| --- | --- |
| Treating `stell_deployContract` as a deploy | Nothing exists on chain |
| Reusing the old address for V2 | Impossible; address is `(creator, nonce)` |
| Pausing before draining | Balance stranded forever |
| Expecting `unpause` | Does not exist |
| Registering a hash without source | Refused |
| Signing registration with Ed25519 | Refused; use Falcon-512 |
| Deploying WABT output then verifying with the Rust pipeline | `verified: false` despite honest source |
| Migrating by "calling" the old contract from the new one | No synchronous call and no cross-contract storage read |
| Assuming `verified: true` means safe | It only means "the bytes match this source" |

## Next

Return to [Deploying and calling contracts](/contracts/deploy-and-call) for the transaction mechanics, or [Reference standards](/contracts/standards) for concrete contracts to fork.
