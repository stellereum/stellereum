# Classical / elliptic-curve excision — verified status

Status document, not a plan. Every row was produced by reading the tree and by running the
commands reproduced in **Appendix A**. Numbers come from that output, not from memory.
Anything I could not verify is marked **UNVERIFIED**.

## 2026-11-18 correction (read before the tables)

The tables below are a **17 Nov snapshot pinned to `HEAD 6e6384940`**. The
current tree (`HEAD 0fdf1eefc`) has moved further; where a row is now false,
the correction is here and inline in the row:

- `PQ_CLASSICAL_REFUSE_AFTER_HEIGHT` **no longer exists**. Classical PQ
  handshakes are refused at EVERY height, with no mixed window and no
  fallback counter (`infnode/crates/infnode/src/proto.rs:371-378`);
  `STELL_INF_PQ_HANDSHAKE` is parsed-and-ignored (`:352-368`). Treat the
  §1.2 row as historical.
- `PQ_TRANSPORT_H_ACTIVATION_HEIGHT` still exists but moved:
  `stellereum/src/mev_epoch.rs:995` (not `:1187`), and it no longer gates
  anything — `is_pq_transport_active` returns `true` at every height
  (`:1003-1006`). The row's "no longer gates the ingest" conclusion holds;
  only the line number moved.
- `PqScheme::Ed25519` / `Hybrid` are removed at the current HEAD:
  `from_id` refuses ids `1`/`4` (`stellereum/src/post_quantum.rs:184-197`),
  not only in the old working tree.
- The X25519 ephemeral transcript binding is gone from `proto.rs`: the
  transcript now carries ML-KEM init/response hashes plus freshness nonces
  (`proto.rs:394-416`). The §1.2 X25519 row is historical.
- `infnode` bucket storage no longer conflates obfuscation with encryption:
  `store_blob_boxed(.., Some(owner_ek))` now seals a per-publish random data
  key to the owner's ML-KEM-768 key (`key_box`, `seal = infnode-blob-seal-v1`,
  AAD = bucket/name/H(plaintext)) and `fetch_blob_owner` is the only reader; the
  content-derived `blob_key_nonce` path is documented as **at-rest
  obfuscation, not encryption** and is pinned by
  `infnode/crates/infnode/tests/storage_seal_tests.rs` (a third party with the
  full blob decrypts it). CLI/web callers that still pass no owner key must not
  be described as E2E-confidential.

## Snapshot (read this first)

| item | value |
|---|---|
| repository root | `/home/imm/stellereum-project` |
| `HEAD` | `6e6384940b955b1277e9cb5646b7d0e6769e7468` — "Wave 1a: convert every stale Ed25519 fixture to FULL-PQ (251 tests fixed)", 2026-11-17 16:06:12 +0300 |
| working tree | **DIRTY and moving during verification**: `git status --porcelain` reported 37 modified files + 1 untracked path at 17:05 MSK; the entry count changed (41 → 38) while the doc was being written |
| snapshot time | 2026-11-17 17:05 MSK |
| analysis baseline | **`HEAD`** (`6e6384940`) for every `live caller?` verdict. The working tree changed repeatedly while this was written and **does not currently build**; rows note where the working tree already differs. |

**Why the baseline is `HEAD` and not the dirty tree.** Two independent removal waves were landing
while this document was written, and both break the build in different crates. Chasing the dirty
tree would produce a document that is stale before it is read. So:

* `live caller?`, `gated?` and the "blocking chain" are evaluated against `HEAD`, the last state
  that is internally consistent;
* every place where the **working tree** already went further is called out explicitly
  ("working tree: …");
* the build timeline below is the evidence that the tree is in flux.

**Consequence you must not skip:** the excision of `PqScheme::Ed25519` / `PqScheme::Hybrid` from
`stellereum/src/post_quantum.rs` exists **only in the uncommitted working tree**. At `HEAD` the
variants still exist:

```
$ git show HEAD:stellereum/src/post_quantum.rs | rg -n "Ed25519 =|Hybrid =|pub enum PqScheme"
136:pub enum PqScheme {
138:    Ed25519 = 1,
156:    Hybrid = 4,
```

### Build states actually observed (same working tree, ~15 minutes apart)

| time (MSK) | command | result |
|---|---|---|
| 17:01 | `cargo check --lib` | **clean** (`Finished dev profile`) |
| 17:05 | `cargo check --lib --profile test` | **16 errors** (lib test target) |
| 17:05 | `cargo check --lib --tests` | **6 errors** (`tests/wallet_pq_tests.rs`) |
| 17:16 | `cargo check --lib --profile test` (re-run) | **53 errors in `infnode` lib** — a second removal wave started in the dependency crate |

The last row is the important one: by 17:16 the working tree no longer builds `infnode` at all
(`NodeKeys` lost `signing`/`verifying`, `PqMode::Classical` was removed, `NodeInfo` lost `ed_hex`).
That wave is **not** described by the `HEAD` line numbers in the tables; it is a preview of the
changes the tables say are required.

```
$ cargo check --lib                                # 17:01
    Finished `dev` profile [unoptimized] target(s) in 1m 23s
```

```
$ cargo check --lib --profile test                 # 17:05, lib with cfg(test)
src/wallet.rs:717:68: error[E0599]: no variant or associated item named `Ed25519` found for enum `post_quantum::PqScheme`
src/wallet.rs:1410:34: error[E0599]: no function or associated item named `sign_delegation` found for struct `SessionKeyAuthorization`
src/wallet.rs:1448:57: error[E0599]: no variant or associated item named `Ed25519` ...
src/wallet.rs:1479:61: error[E0599]: no variant or associated item named `Ed25519` ...
src/wallet.rs:1663:58: error[E0599]: no variant or associated item named `Ed25519` ...
src/wallet_signing.rs:343:32: error[E0599]: no variant or associated item named `Ed25519` ...
src/wallet_signing.rs:390:23: error[E0599]: no variant or associated item named `Ed25519` ...
src/wallet_signing.rs:395:45: error[E0599]: no variant or associated item named `Hybrid` ...
src/wallet_signing.rs:450:47: error[E0599]: no variant or associated item named `Ed25519` ...
src/wallet_signing.rs:452:46: error[E0599]: no variant or associated item named `Hybrid` ...
src/wallet_signing.rs:476:23: error[E0599]: no variant or associated item named `Ed25519` ...
src/wallet_signing.rs:698:42: error[E0599]: no variant or associated item named `Ed25519` ...
src/wallet_signing.rs:741:41: error[E0599]: no variant or associated item named `Hybrid` ...
src/wallet_signing.rs:746:42: error[E0599]: no variant or associated item named `Hybrid` ...
error: could not compile `stellereum` (lib test) due to 16 previous errors
```

```
$ cargo check --lib --tests                        # 17:05
tests/wallet_pq_tests.rs:95:39: error[E0599]: no variant or associated item named `Ed25519` found for enum `PqScheme`
tests/wallet_pq_tests.rs:109:41: error[E0599]: no variant or associated item named `Ed25519` ...
tests/wallet_pq_tests.rs:118:45: error[E0599]: no variant or associated item named `Ed25519` ...
tests/wallet_pq_tests.rs:173:23: error[E0599]: no variant or associated item named `Ed25519` ...
tests/wallet_pq_tests.rs:181:43: error[E0599]: no variant or associated item named `Hybrid` ...
tests/wallet_pq_tests.rs:191:23: error[E0599]: no variant or associated item named `Ed25519` ...
error: could not compile `stellereum` (test "wallet_pq_tests") due to 6 previous errors
```

```
$ cargo check --lib --profile test                 # 17:16, re-run
/home/imm/stellereum-project/infnode/crates/infnode/src/rewards.rs:261:18: error[E0609]: no field `ed_hex` on type `&NodeInfo`
/home/imm/stellereum-project/infnode/crates/infnode/src/node.rs:879:29: error[E0609]: no field `signing` on type `NodeKeys`
/home/imm/stellereum-project/infnode/crates/infnode/src/node.rs:8538:27: error[E0599]: no variant or associated item named `Classical` found for enum `PqMode`
/home/imm/stellereum-project/infnode/crates/infnode/src/node.rs:8773:9: error[E0061]: this function takes 3 arguments but 4 arguments were supplied
/home/imm/stellereum-project/infnode/crates/infnode/src/node.rs:8809:10: error[E0609]: no field `signing` on type `&NodeKeys`
error: could not compile `infnode` (lib) due to 53 previous errors
```

**Verification limit.** I did not check out `HEAD` in a worktree (that would disturb the live
working tree) and therefore did **not** run `cargo check` at `HEAD`. The `HEAD` claims in this
document are established by reading `git show HEAD:<path>`, not by compiling that snapshot.

**Gate conclusion.** At no point during verification was the mandatory gate
(`cargo clippy --all-targets -- -D warnings`, `AGENTS.md` §4) green: the 17:01 run covers only
the library target; the 17:05 and 17:16 runs are red. Treat the excision as **incomplete and
build-breaking**, not as a finished cleanup.

Downstream path-dependency crates also name the removed variants and were not built here:
`stellereum-sdk/src/lib.rs:87,105,127,129,146,420,423` and
`stell-wallet/src/pq.rs:74,94,174,175,184,185,193,196,204,207,408,455,494`
(`stellereum-sdk/Cargo.toml:10`, `stell-wallet/Cargo.toml:13`, `stellereum-indexer/Cargo.toml:20`
all use `stellereum = { path = "../stellereum" }`). **UNVERIFIED**: I did not run `cargo check`
in those three crates.

---

## 1. Status table

`live caller?` = does node code reach it on the running path at `HEAD` (not tests, benches,
examples). `gated?` = is there a height/env/const gate that prevents execution. Where the
**working tree** has already moved, the row says so.

### 1.1 `stellereum` — signature enums and wire constants

| primitive | file:line | live caller? | gated? | what removing it requires | blocker |
|---|---|---|---|---|---|
| `PqScheme::Ed25519` (id `0x01`) | at HEAD: enum `stellereum/src/post_quantum.rs:136-165`, `from_id` `:173-197`. Working tree: enum `:152-165`, `from_id` `:184-197` | **no in the working tree** — variant gone, `from_id(1)` returns `Err`; **yes at HEAD** | decode-time refusal | nothing further here; the removal must be finished in `wallet.rs` / `wallet_signing.rs` / sdk / stell-wallet | 16 lib-test + 6 integration-test errors observed at 17:05 |
| `PqScheme::Hybrid` (id `0x04`) | same lines | **no in the working tree** — same; **yes at HEAD** | decode-time refusal | same | same |
| `verify_ed25519` | **absent everywhere** — `rg -n "verify_ed25519" stellereum/src/` → exit 1 | **no** | n/a | none | none |
| `ED25519_PUBKEY_LEN = 32` | at HEAD `post_quantum.rs:117`; working tree `:126` | at HEAD: **yes** — `HYBRID_PUBKEY_LEN` (`:120`) and the Hybrid verify split (`:548-551`). Working tree: **no production use**, tests only (`:2845-2846`) | n/a | nothing once Hybrid is gone; keep `32` as the validator-id width | `ValidatorId` is 32 bytes (`consensus/types.rs:16`) |
| `ED25519_SIG_LEN = 64` | at HEAD `post_quantum.rs:123`; working tree `:135` | **yes** — `sharding/transaction.rs:586` uses it as the `SK1` session-tag length (both at HEAD and in the working tree) | n/a | keep as a wire-size constant until `SK1` decoding is retired | legacy `SK1` envelope decoder (`transaction.rs:1215-1225`) |
| classical-refusal tests using `ed25519_dalek` | working tree: `post_quantum.rs:2552-2569`, `:2828-2841` (added by the uncommitted removal; absent at HEAD) | test-only | n/a | none | none |

### 1.2 `infnode` — Ed25519 frame auth, TLS pins, X25519 remnants

**Working-tree status (17:16):** a removal wave is in progress in this crate. `NodeKeys` no
longer exposes `signing`/`verifying`, `PqMode::Classical` is gone, and `NodeInfo` no longer has
`ed_hex`; `cargo check` reports **53 errors**. The rows below describe `HEAD`, i.e. what is still
there and must be replaced, not what currently compiles.

| primitive | file:line | live caller? | gated? | what removing it requires | blocker |
|---|---|---|---|---|---|
| Ed25519 **frame signature** (64-byte field) | `infnode/crates/infnode/src/proto.rs:130` (`sig: [u8;64]`), `:166-180` (digest), `:266` (`verify_strict`) | **yes** — every frame: `node.rs:877-881` (`sign_frame`), `:1589`, `:2395`, `:2474`; verify at `:1608`, `:2526`, `:7380`, `:7440`, `:7579` | no | new frame-auth scheme + resize/version the frame header | fixed 64-byte slot in the wire struct; mixed-version peers cannot parse a different length |
| Ed25519 **TLS self-signed cert**, CN pin | `node.rs:8806-8815` (`rcgen::PKCS_ED25519`, CN `infnode-<ed_pub>`); verifier `node.rs:8846-8880` | **yes** — `build_tls` at `node.rs:670`, `:6665` | no | PQ TLS cert or raw-PubKey pin; both ends simultaneously | TLS identity + QUIC config |
| ephemeral **X25519** transcript binding | `node.rs:22` (import), `:1545-1546`, `:7453-7454`; transcript fields `proto.rs:387-390` | **yes** — fields `eph`/`ch_eph` are exchanged on every handshake (`node.rs:1560`, `:1572`) | no — comments state there is **no ECDH**, only freshness (`node.rs:1542-1544`, `:7451-7452`) | drop `eph_*` from `PqTranscript` and bump `PQ_TRANSCRIPT_VERSION` (`proto.rs:365`) | transcript is a wire contract; the digest feeds `pq_session_key` |
| static X25519 e2e key | `keyring.rs:161-163`, `:265-270`; `mailbox.rs:95-98` | **no** — 32-byte seeds are refused (`keyring.rs:266-270`) | refuse-always | delete the dead refusal arms (the `x25519-dalek` crate stays until the ephemeral-binding row is retired) | none (already inert) |
| ~~`PQ_CLASSICAL_REFUSE_AFTER_HEIGHT = 300_000`~~ | **DELETED at current HEAD** (`proto.rs:371-378`); this row is the `6e6384940` snapshot (`proto.rs:329`) | **no** — classical is refused at every height | n/a | none | none (retired by deletion) |
| `NodeKeys::id()` = `blake3(ed_pub)[..20]` | `keyring.rs:184-199`, `:209` | **partly** — one live caller: `main.rs:1357` (`announce`) through `id_hex()`. It is **not** the canonical node id: `resolve_node_id` returns the PQ id (`keyring.rs:537-542`) and `Node::new` uses `ceremony_local_id` (`node.rs:646-650`) | none (documented "NON-CANONICAL helper", `keyring.rs:185-190`) | delete it once `announce` publishes a PQ id | config `validators:` ids are derived from `blake3(ed_pub)[..20]` (`node/bootstrap.rs:266-296`) |
| `consensus.sign` Ed25519 sidecar | `node.rs:2855-2884` (sign at `:2874`) | **yes** — p2p service gated on `cfg.validators` (`node.rs:2857-2863`) | allow-list only | Falcon sign endpoint + client migration | sidecar protocol used by sub-validators |
| mailbox owner/sender Ed25519 signature | `mailbox.rs:12`, `:23-29`, `:131-141`; verify at `node.rs:6574` | **yes** — `mail.list` ownership check; CLI at `main.rs:967` | no | PQ owner signature + new mailbox key file | on-disk mailbox format `kem:`/`ed:` (`mailbox.rs:50`, `:90-98`) |
| `PeerConfig.ed_pub` mandatory pin | `config.rs:27-32`, deserialize `:89-106` | **yes** — required for every peer | "frozen auth/TLS pin" | PQ pin | config schema + TLS/auth migration |
| `x-pub` / `node-id` config fields | `config.rs:57`, `:92-103` | **no** — presence is a loud error | refuse-always | none (already refused) | none |
| federation `node_id = blake3(ed_pub)` | `federation.rs:8`, `:83-107` (`verify_record_selfconsistent`), TXT format `:149-165` | **yes** — `announce` (`main.rs:1357-1361`) and DNS verification | no | put a PQ id in the TXT record and in the verifier | public DNS format; operators publish these records |
| reputation keyed on peer identity | `reputation.rs:1-9` | **yes** — scoring, but the file contains **comments only** (`rg` finds zero crypto calls); the "ed25519 identity" wording is **stale**: the canonical node id is PQ (`keyring.rs:537-542`) | n/a | update the comment; no code change | depends on the id migration |
| `falcon-rust` dependency | `infnode/crates/infnode/Cargo.toml:42` | **yes** — `keyring.rs:4` uses `falcon512` | n/a | none | the Cargo comment at `:38-41` says "unwired / no code references these yet" — **stale**, `keyring.rs:4` contradicts it |

Not in the table because they are **symmetric**, not elliptic-curve, primitives: `xsalsa20poly1305`
(`node.rs:8019-8045`, used by `proton_box_data`/`proton_unbox_body` at `:8047`, `:8090`) and
`sha2`. They are listed in the dependency table for completeness only; they are not part of the
classical/EC excision.

### 1.3 `stellereum` — MEV sealing and order commitment

| primitive | file:line | live caller? | gated? | what removing it requires | blocker |
|---|---|---|---|---|---|
| `RistrettoPoint` epoch sealing (threshold key, Feldman VSS) | `stellereum/src/mev_epoch.rs:73`, `:226`, `:965-1050`; imported at `:72-74` | **yes** — `EpochSealManager` is in the mempool (`mempool.rs:655`) and `sync_epoch` runs on the consensus path (`runtime/mev_sync.rs:383` → `mev_epoch.rs:2962-3000`) | no | new threshold-sealing primitive over a PQ group; change the epoch key commitment | `Block::epoch_key_commitment` (`sharding/block.rs:349-350`) commits the Ristretto point |
| `encryption_secret_from_ed25519` | `mev_epoch.rs:1069` | **yes** — `mev_epoch.rs:2989` | no | derive from a PQ secret instead | committee is derived from validator ids (`mev_epoch.rs:2940-2950`) |
| `encryption_public_key_from_ed25519` | `mev_epoch.rs:1087` | **yes** — `mev_epoch.rs:2948`, `:3415` | no | same | same |
| X25519 share-package encryption | `mev_epoch.rs:81`, `:528-544`, `:1100-1145` | **partly** — the *ingest* of classical packages is refused at any height (`:1704-1717`), but the DKG still constructs/expects packages distinguished **by length** (`:1733-1743`) | ingest refuses; construction still classical | delete the 48-byte package type and the length discrimination | wire format has no scheme tag: legacy 48-byte vs 1136-byte packages are told apart by length only (`:1184-1186`) |
| `PQ_TRANSPORT_H_ACTIVATION_HEIGHT = 10_000` | `mev_epoch.rs:995` (current HEAD; `:1187` was the `6e6384940` snapshot) | **no** — schedule metadata only; `is_pq_transport_active` is `true` at every height (`:1003-1006`) | height const | none (historical gate; PQ leg is unconditional) | none — the const is below any live height and no longer gates ingest |
| `RistrettoPoint` in `mev_v4` | `mev_v4.rs:54` | **no** — zero callers outside the module (`rg -n "mev_v4" src/ --glob '!src/mev_v4.rs'` returns only `lib.rs:34`) | env `STELL_MEV_V4`, default OFF (`mev_v4.rs:71-81`) | delete the module | **owner directive forbids removal** (`mev_v4.rs:25-27`: "DEAD ENGINE — OFF BY DEFAULT, NOT WIRED, NOT REMOVED") |
| Ed25519 order commitment (`commit_block_order`) | `mev.rs:50`, `:686-700`; verify `:596-604`, `:734-754` | **yes** — signed at proposal build `runtime/mev_sync.rs:2005-2010`; checked at finalize `runtime/apply.rs:621-634` | no | sign the commitment with Falcon and change `BlindRoundCommitment` | verdict is **advisory** (a mismatch only warns, `runtime/apply.rs:626-633`), so consensus does not depend on it — but the type is public and carries Ed signatures |

### 1.4 `stellereum` — wallet, signer, oracle, bridge, contracts

**Working-tree status (17:05–17:15):** `WalletSigningKey` was reduced to a Falcon-only enum
(observed at `wallet_signing.rs:395-429` after the rewrite) and the Ed-specific decode guard was
deleted, but the surrounding doc comments and tests lagged behind and the lib test target failed.
The rows below describe `HEAD`; the working-tree deltas are noted in the row text.

| primitive | file:line | live caller? | gated? | what removing it requires | blocker |
|---|---|---|---|---|---|
| `WalletKeyMaterial::Ed25519` | at HEAD: `wallet.rs:12`, `:527-540` (enum), `:705-737` (`ed25519_from_seed`/`address`) | **yes** — key-file load (`:590-640`) and signing (`:787`, `:849`, `:905`, `:966`) | no | drop the variant, migrate key files, re-derive addresses | on-disk key blob scheme string `"ed25519"` (`:590`, `:631`) and the 32-byte-address rule |
| scheme mapping | at HEAD: `wallet.rs:714-719` maps `Ed25519 => PqScheme::Ed25519`. In the **working tree** the same line is `Ed25519 { .. } => PqScheme::MlDsa44, // TEMP-VERIFY` (`wallet.rs:717`) | **yes** | no | replace with a real PQ scheme or refuse the key | the working-tree edit maps an Ed key onto the *disabled* ML-DSA scheme; `wallet.rs:1454` carries a second `TEMP-VERIFY` marker. Both are compile bridges, not a design |
| `WalletSigningKey::{Ed25519, Hybrid}` + envelope schemes `0x01`/`0x04` | at HEAD: `wallet_signing.rs:259-272`, `:369-399`, `:413-423`, `:448-454`; envelope push at `:277-291` | **yes** — message signing used by governance (`governance.rs:1165`, `:2258-2260`, `:2365-2382`) | no | drop the two variants; governance must sign with Falcon | message-signature envelope + governance vote compatibility |
| `WalletSignature::decode` Ed key checks | at HEAD: `wallet_signing.rs:340-357` | **yes** | no | delete with the scheme | dead branch after removal |
| remote/HSM signer (Ed25519-only) | `remote_signer.rs:3`, `:104-105`, `:880-888` | **yes** — `node/bootstrap.rs:508-514` builds it at startup; `runtime/anchors.rs:2600-2642` signs votes/proposals through it | no | Falcon/HSM signer + a remote protocol that can return 666-byte signatures | `Signer` trait is Ed-typed (`remote_signer.rs:112-114`) and `ValidatorRuntime::id` is the Ed public key (`anchors.rs:23`) |
| oracle Ed25519 feed signer | `oracle.rs:7`, `:300-318` | public API; **no node caller** for `PriceFeedUpdate::sign` outside tests/CLI (`cli/handlers.rs:1024` uses the PQ type) | n/a | delete the type or keep the byte-frozen shell | `PriceFeedUpdate` is **frozen consensus wire** (`svm.rs:576`, `network.rs:9`, `:1857-1878`) |
| oracle Ed25519 verification | `oracle.rs:320-330` — `verify()` returns `false` unconditionally | **yes**, but it always refuses | always-refuse | none; it is already dead-but-honest | gossip still ships the type (`network.rs:1857`, `:1878`) |
| bridge "Ed identity" | `bridge.rs:562-573` (docs), `:574-580` (`verify_quorum_signatures`) | **yes** — ids are Ed public keys; signatures must be Falcon (`bridge.rs:555-558`) | signature path already PQ | PQ ids only | same `ValidatorId` blocker |
| contract host `ed25519_verify` | at HEAD `contract.rs:1350` (registration), `:128` (`FUEL_ED25519_VERIFY`); working tree `:1348-1378` | **yes** — the import is registered and callable; it charges fuel and returns `0` (`:1374-1377`) | always-false | remove the host function (breaks contracts importing it) | WASM ABI: `contract.rs:2594-2664` pins both the valid-and-refused behaviour |
| `FUEL_ED25519_VERIFY = 500` | `contract.rs:128` | **yes** — charged at `:1366` | no | delete with the host fn | same ABI blocker |
| legacy 64-byte Ed25519 contract-source signature | `contract_source.rs:340`, `:449-454` | **yes** — `stell_registerContractSource` → `rpc/contracts.rs:1478` → `verify_register_signature_with_pubkey` | no | refuse the final `64`-byte branch | clients/SDK must all sign with Falcon; the stored state (creator, source hash) is unchanged, so **no genesis change** |
| `k256` / `secp256k1` (EVM) | `evm_adapter/crypto.rs:2`; `evm_adapter/tx.rs:191-211`; RPC `rpc/eth.rs:797-812`, `rpc/reads.rs:338` | **yes at the RPC boundary** — `eth_sendRawTransaction` decodes, verifies `chain_id` + low-s + ecrecover (`tx.rs:195-198`) and files the tx into the mempool | **the mempool refuses every EVM envelope**: `sharding/transaction.rs:1250-1254` ("FULL-PQ: EVM settlement removed") | **KEEP** — see §1.5 | EVM/MetaMask compatibility surface, not consensus validity |

### 1.5 Why `k256` is kept (and what is *not* true about it)

`stellereum/src/evm_adapter/crypto.rs` implements secp256k1 ECDSA, `ecrecover`, low-s
normalisation and Ethereum address derivation (`crypto.rs:4-19`, `:75-104`, `:111-213`). It is
kept because the `eth_*` RPC surface and MetaMask-compatible transaction decoding are built on
it (`rpc/eth.rs:797-812`), and `evm_adapter::evm_to_stell_address` is used across the RPC.

It is **not** a consensus validity rule today. `Transaction::verify_evm_signature`
(`sharding/transaction.rs:741-781`) exists — and is deliberately **never called** on the
mempool/apply path: `rg -n "verify_evm_signature" src/` returns only its definition and two doc
references. Admission instead refuses the envelope outright at
`sharding/transaction.rs:1250-1254`. So:

* removing `k256` would remove the EVM compatibility API, not a consensus rule;
* the existing consensus-side re-verifier is currently unreachable, which is worth a separate
  decision (wire it or delete it) — **out of scope for this document**.

### 1.6 Cargo dependencies

| crate | dependency | file:line | code path that still needs it |
|---|---|---|---|
| `stellereum` | `ed25519-dalek` | `stellereum/Cargo.toml:13` | wallet keys (`wallet.rs:12`), message signing (`wallet_signing.rs:32`), order commitments (`mev.rs:50`), remote signer (`remote_signer.rs:104`), MEV DKG derivation (`mev_epoch.rs:75`), contract-source legacy branch (`contract_source.rs:340`), bridge ids (`bridge.rs:2218` tests) |
| `stellereum` | `x25519-dalek` | `stellereum/Cargo.toml:14` | only `mev_epoch.rs:81` (`XStaticSecret`) — the DKG package leg |
| `stellereum` | `curve25519-dalek` | `stellereum/Cargo.toml:31` | `mev_epoch.rs:72-74`, `mev_v4.rs:54`, `mev.rs:51` (`Scalar`) |
| `stellereum` | `k256` | `stellereum/Cargo.toml:40` | EVM adapter only (`evm_adapter/crypto.rs:2`) — **kept** |
| `stellereum` | `falcon-rust`, `pqcrypto-falcon`, `ml-kem` | `stellereum/Cargo.toml:42,46,50` | consensus signatures, FIPS-206 archive link (`post_quantum.rs:26`), MEV KEM leg |
| `infnode` | `ed25519-dalek` | `infnode/crates/infnode/Cargo.toml:15` | frame auth (`proto.rs:4`), identity (`keyring.rs:3`), TLS cert (`node.rs:8806-8815`), mailbox (`mailbox.rs:12`), `consensus.sign` (`node.rs:2874`) |
| `infnode` | `x25519-dalek` | `infnode/crates/infnode/Cargo.toml:33` | ephemeral transcript binding only (`node.rs:22,1545,7453`) |
| `infnode` | `rustls` / `rcgen` / `x509-parser` | `infnode/crates/infnode/Cargo.toml:21-22,34` | QUIC TLS (`node.rs:670,6665,8806-8880`) |
| `infnode` | `xsalsa20poly1305` | `infnode/crates/infnode/Cargo.toml:28` | Proton box helpers (`node.rs:8019-8102`) — symmetric, not EC |
| `infnode` | `falcon-rust` | `infnode/crates/infnode/Cargo.toml:42` | `keyring.rs:4` (the manifest comment calling it unwired is stale) |
| `infnode` | `sha2` | `infnode/crates/infnode/Cargo.toml:27` | handshake digests / TLS helpers; **UNVERIFIED** exact call sites (not enumerated) |

`sha2` is also used by `stellereum/src/mev_epoch.rs:80` (`Sha512` for the Ed25519→X25519
clamp), so it cannot be dropped with the Ed25519 removal alone if the DKG keeps any SHA-512 use.

---

## 2. Blocking chain

The primitives above are not independent. Five coupling clusters decide whether a removal is a
local edit or a network-wide event.

### Chain A — `ValidatorId` and the validator set (fresh genesis required)

1. `ValidatorRuntime::new` sets `id = key.verifying_key().to_bytes()`, i.e. the 32-byte
   **Ed25519 public key** (`runtime/anchors.rs:23`).
2. Membership in `validators:` is matched by `blake3(ed_pub)[..20]`
   (`node/bootstrap.rs:266-296`), so the on-disk config, the derived set and `id` are all tied to
   the Ed key.
3. The Falcon identity is a **separate** 32-byte value, `derive_pq_address(Falcon512, …)`
   (`post_quantum.rs:1947-1949`), registered as an *alias* of the Ed id
   (`runtime/anchors.rs:995-1002`). Two identities already coexist; consensus is keyed on the Ed
   one.
4. `ValidatorId` is the map key for staking (`staking.rs` validators map), the PQ key registry,
   CN-VRF commitment records (`cn_vrf.rs:107`, records keyed by `(ValidatorId, epoch)` at
   `cn_vrf.rs:1599`), bridge ids (`bridge.rs:562-577`) and the MEV committee
   (`mev_epoch.rs:2940-2950`).

Removing the Ed key therefore changes **every 32-byte id in consensus state**, which changes
balances/stakes and therefore the genesis state root. There is no in-place migration: key
rotation announcements are refused fail-closed because they were designed to be signed by the
Ed consensus key (`pq_registry.rs:575-619`, `verify_rotation_announcement` returns `false` at
`:614-619`). A coordinated upgrade needs either a PQ-signed rotation announcement (not
specified) or **fresh genesis**.

### Chain B — infnode wire identity (coordinated flag day)

Frame auth, TLS and the handshake transcript are one identity bundle:

* frame signature is a fixed 64-byte Ed25519 field (`proto.rs:130`, `:266`);
* TLS cert is Ed25519 with the public key in the CN (`node.rs:8806-8815`, pinned at `:8846-8880`);
* the handshake transcript binds `ed` and the ephemeral X25519 pubs (`node.rs:1556-1576`,
  `proto.rs:379-397`);
* the session key is derived from the ML-KEM secret plus that transcript digest
  (`proto.rs:112-118`).

Changing any one breaks decoding or session-key agreement with an un-upgraded peer. These must
ship together, as a new transcript version (`PQ_TRANSCRIPT_VERSION`, `proto.rs:365`), with all
peers provisioned with the new identity before `pq_classical_refused_at` can be relied on
(`proto.rs:333-335`).

### Chain C — vote / block signature layout (coordinated, no genesis change)

A vote's `signature` is `b"STELL_VOTEFAL_V1" || 64-byte_ed || 666-byte_falcon`
(`consensus/types.rs:175-177`, `:317-329`). The Ed half is produced (`runtime/consensus_step.rs:1209-1220`)
but **never verified**: `verify_unified_with_pq_keys_and_beacon_inner` returns after the PQ path
and unconditionally `false` otherwise (`consensus/types.rs:1519-1527`). The proposer also pushes
an Ed signature into `Block::validator_signatures` (`runtime/mev_sync.rs:1849-1860`).

Consequences:

* dropping the Ed half is **safe for validity**, but it changes the vote byte layout, so it is a
  coordinated wire change (mixed nodes would refuse each other's votes);
* it does not change the block hash (`compute_hash` excludes `validator_signatures`,
  `sharding/block.rs` — see the comment at `runtime/mev_sync.rs:1844-1848`), so it needs no new
  genesis by itself.

### Chain D — MEV epoch key commitment (wire + fresh epoch, not genesis)

`EpochSealManager::sync_epoch` derives the committee from validator ids, converts each Ed public
key to an X25519 key, and runs a Ristretto/Feldman DKG (`mev_epoch.rs:2940-3000`). The aggregate
key is committed to the block (`sharding/block.rs:349-350`), so changing the group changes the
commitment field and the sealing wire. This can be scheduled at an epoch boundary, but it cannot
be mixed: a Ristretto wallet ciphertext is unsealable by a PQ-only epoch.

### Chain E — storage decoders (must be handled per removal)

| decoder | file:line | what happens if the field is removed without migration |
|---|---|---|
| infnode `identity.key` (32-byte Ed seed) | `keyring.rs:255-263` | boot fails on the length check; node cannot start |
| infnode `e2e.key` (64-byte KEM seed; 32-byte refuses) | `keyring.rs:264-270` | already fail-closed for the legacy 32-byte value |
| node keys (Ed seed, `enc2:`) | `stellereum/src/node_keys.rs:667`, `:684-690` | validator identity lost if the file is not re-encrypted/migrated |
| wallet key file (`"ed25519"` scheme string) | `wallet.rs:590-640` | load refuses or falls through to raw-seed heuristics (`:649-684`) |
| `SK1` session envelope (64-byte Ed signature) | `sharding/transaction.rs:586`, `:1215-1225` | sessions minted under `SK1` stop verifying |
| CN-VRF secrets (`enc2:`) | `cn_vrf.rs:1735-1815` | unaffected by the Ed25519 work, but same custody discipline |

### Verdict: safe-alone vs coordinated

| removal | safe on its own? | reason |
|---|---|---|
| delete the dead `x25519` refusal arms / rename `reputation.rs` prose | **yes** | already unreachable (`keyring.rs:266-270`, `mailbox.rs:95-98`) |
| delete `mev_v4` | technically yes, **contractually no** | zero callers, but the owner directive forbids removal (`mev_v4.rs:25-27`) |
| drop the `PqScheme::{Ed25519,Hybrid}` variants | **no** | 22 compile errors in this crate alone (16 lib-test + 6 integration), plus unverified breakage in three downstream path-dependency crates (see §"Build state") |
| refuse the 64-byte branch in `contract_source.rs:449-454` | **yes, after clients migrate** | RPC-local verification; no consensus state change |
| remove the Ed half of the vote signature | **no** | vote wire layout (Chain C) |
| replace frame auth / node ids / TLS | **no** | infnode wire identity (Chain B) |
| remove the Ed consensus identity | **no** | `ValidatorId` + genesis root (Chain A); also blocks key rotation until a PQ-signed announcement exists |
| remove Ristretto/X25519 MEV sealing | **no** | epoch key commitment + sealing wire (Chain D) |
| remove `k256` | **no, and it should not be removed** | EVM/MetaMask compatibility surface (§1.5) |

---

## Appendix A — commands and raw output

Run from `/home/imm/stellereum-project`. Since the working tree was rewritten during
verification, the **evidence for the `HEAD`-anchored tables is taken from `git show HEAD:<path>`**
(stable and reproducible); the only working-tree commands are the build timeline in the Snapshot
section and the "working tree" deltas called out in the text. Output is verbatim except for `…`
where explicitly marked.

```
$ rg -n "verify_ed25519" stellereum/src/
(no output — exit 1)
```

```
$ git show HEAD:stellereum/src/post_quantum.rs | rg -n "^pub enum PqScheme|    Ed25519 = |    Hybrid = "
136:pub enum PqScheme {
138:    Ed25519 = 1,
156:    Hybrid = 4,
```

```
$ for f in proto node keyring mailbox reputation config federation; do n=$(git show HEAD:infnode/crates/infnode/src/$f.rs | rg -c "ed25519|Ed25519|x25519|X25519|X3DH" || true); echo "$f ${n:-0}"; done
proto 6
node 22
keyring 4
mailbox 6
reputation 3
config 3
federation 0
```

(`federation.rs` has **0** matches for the word `ed25519`; its classical binding is the
`ed_pub` string plus `blake3(ed_pub)` at `federation.rs:102-107`.)

```
$ git show HEAD:infnode/crates/infnode/src/proto.rs | rg -c "ed25519|Ed25519|x25519|X25519|X3DH"; git show HEAD:infnode/crates/infnode/src/node.rs | rg -c "ed25519|Ed25519|x25519|X25519|X3DH"
6
22
```

```
$ git show HEAD:infnode/crates/infnode/src/proto.rs | rg -n "PQ_CLASSICAL_REFUSE_AFTER_HEIGHT"
297:/// [`PQ_CLASSICAL_REFUSE_AFTER_HEIGHT`] classical is refused fail-closed
329:pub const PQ_CLASSICAL_REFUSE_AFTER_HEIGHT: u64 = 300_000;
334:    height >= PQ_CLASSICAL_REFUSE_AFTER_HEIGHT
360:        PQ_CLASSICAL_REFUSE_AFTER_HEIGHT
619:/// [`PQ_CLASSICAL_REFUSE_AFTER_HEIGHT`] classical is refused fail-closed —
631:        return Err("classical refused at/after PQ_CLASSICAL_REFUSE_AFTER_HEIGHT");
634:        return Err("classical refused at/after PQ_CLASSICAL_REFUSE_AFTER_HEIGHT");
650:/// at/after [`PQ_CLASSICAL_REFUSE_AFTER_HEIGHT`] classical is refused
664:        return Err("classical refused at/after PQ_CLASSICAL_REFUSE_AFTER_HEIGHT");
667:        return Err("classical refused at/after PQ_CLASSICAL_REFUSE_AFTER_HEIGHT");
```

```
$ rg -n "RistrettoPoint|ristretto|encryption_secret_from_ed25519|encryption_public_key_from_ed25519|XStaticSecret|XPublicKey" stellereum/src/mev_epoch.rs | wc -l
32
$ rg -c "RistrettoPoint|ristretto|encryption_secret_from_ed25519|encryption_public_key_from_ed25519|XStaticSecret|XPublicKey" stellereum/src/mev_epoch.rs stellereum/src/mev_v4.rs
stellereum/src/mev_v4.rs:3
stellereum/src/mev_epoch.rs:32
```

```
$ rg -n "mev_v4" stellereum/src/ --glob '!src/mev_v4.rs'
stellereum/src/lib.rs:34:pub mod mev_v4;
$ rg -n "mev_v4_enabled" stellereum/src/ --glob '!src/mev_v4.rs'
(no output)
```

```
$ for f in wallet wallet_signing remote_signer bridge; do printf "%s " "$f"; git show HEAD:stellereum/src/$f.rs | rg -c "ed25519|Ed25519"; done
wallet 37
wallet_signing 39
remote_signer 13
bridge 6
```

```
$ S=0; for f in wallet oracle contract_source contract; do n=$(git show HEAD:stellereum/src/$f.rs | rg -c "ed25519|Ed25519" || true); S=$((S+n)); echo "$f $n"; done; echo "total $S"
wallet 37
oracle 6
contract_source 5
contract 20
total 68
```

```
$ rg -n "ed25519-dalek|x25519-dalek|curve25519-dalek|^k256|falcon-rust|pqcrypto-falcon|ml-kem|^sha2" stellereum/Cargo.toml infnode/crates/infnode/Cargo.toml
infnode/crates/infnode/Cargo.toml:15:ed25519-dalek = { workspace = true }
infnode/crates/infnode/Cargo.toml:27:sha2 = { workspace = true }
infnode/crates/infnode/Cargo.toml:33:x25519-dalek = { workspace = true }
infnode/crates/infnode/Cargo.toml:37:ml-kem = "0.3"
infnode/crates/infnode/Cargo.toml:42:falcon-rust = "0.3.1"
infnode/crates/infnode/Cargo.toml:43:pqcrypto-falcon = "0.4.1"
stellereum/Cargo.toml:13:ed25519-dalek = { version = "2", features = ["pkcs8", "rand_core", "batch"] }
stellereum/Cargo.toml:14:x25519-dalek = { version = "2", features = ["static_secrets"] }
stellereum/Cargo.toml:18:sha2 = "0.10"
stellereum/Cargo.toml:31:curve25519-dalek = { version = "4", features = ["rand_core"] }
stellereum/Cargo.toml:40:k256 = { version = "0.13", default-features = false, features = ["ecdsa"] }
stellereum/Cargo.toml:42:falcon-rust = "0.3.1"
stellereum/Cargo.toml:46:pqcrypto-falcon = "0.4.1"
stellereum/Cargo.toml:50:ml-kem = "0.3"
```

```
$ rg -n "verify_evm_signature" stellereum/src/
src/evm_adapter/tx.rs:184:/// (`Transaction::verify_evm_signature`), so this mapping needs no trust:
src/sharding/transaction.rs:692:    /// [`Self::verify_evm_signature`]. The SVM payload stays empty: Phase-2
src/sharding/transaction.rs:741:    pub fn verify_evm_signature(&self) -> bool {
```

```
$ rg -n "PqScheme::(Ed25519|Hybrid)" stellereum-sdk/src stell-wallet/src stellereum-indexer/src
stellereum-sdk/src/lib.rs:87:            scheme: PqScheme::Ed25519,
stellereum-sdk/src/lib.rs:105:            scheme: PqScheme::Hybrid,
stellereum-sdk/src/lib.rs:127:            PqScheme::Ed25519 => ...
stellereum-sdk/src/lib.rs:129:            PqScheme::Hybrid => {
stellereum-sdk/src/lib.rs:146:            PqScheme::Ed25519 => {
stellereum-sdk/src/lib.rs:420:            PqScheme::Ed25519 => {
stellereum-sdk/src/lib.rs:423:            scheme @ (PqScheme::Falcon512 | PqScheme::Hybrid) => {
stell-wallet/src/pq.rs:74:            PqGenScheme::Hybrid => PqScheme::Hybrid,
stell-wallet/src/pq.rs:174:            WalletScheme::Hybrid => PqScheme::Hybrid,
stell-wallet/src/pq.rs:175:            WalletScheme::Ed25519 => PqScheme::Ed25519,
stell-wallet/src/pq.rs:184:            WalletScheme::Hybrid => stellereum::post_quantum::PqScheme::Hybrid,
stell-wallet/src/pq.rs:185:            WalletScheme::Ed25519 => stellereum::post_quantum::PqScheme::Ed25519,
stell-wallet/src/pq.rs:408:            PqScheme::Ed25519 => {
stell-wallet/src/pq.rs:455:            PqScheme::Hybrid => {
```

**UNVERIFIED**: the exact compile status of `stellereum-sdk`, `stell-wallet` and
`stellereum-indexer` against this working tree; and the `sha2` call-site inventory inside
`infnode`. Both are outside what was executed here and must be measured, not assumed.
