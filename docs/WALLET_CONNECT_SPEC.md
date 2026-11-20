# Stellereum Wallet and Connect Protocol — v1 contract

Status: **DESIGN ONLY**. This document is the fixed contract for the next
implementation wave. It ships no code and changes no consensus rule. Every
claim about *existing* behaviour carries a `file:line` citation; every
*new* identifier is marked **NEW** and is not claimed to exist yet.

Scope of the wave: the first-party wallet (seed phrase → Falcon-512 /
ML-KEM keys → balance → send/receive → history → export/import) and our own
dApp connect protocol (TON-Connect-shaped deeplink / QR, request to sign,
response). WalletConnect v2 is explicitly out of scope. The MetaMask bridge is
frozen as a compatibility path: EVM carrier + PQ sidecar, transfers only.

Hard constraints inherited from the operator:

* the first-party wallet is the primary path, hardware wallets and multisig are
  later;
* exactly one connect protocol exists at a time — ours first, WalletConnect v2
  only if ecosystem demand appears, never both;
* Falcon-512 is the only signing credential; ML-KEM is transport/KEM only;
* chain id `5757`; shards `{0,1}` today; the address layout must survive a
  future TON-like split/merge;
* one hard fork per wave.

---

## 0. What exists, what does not, and the one blocking defect

### 0.1 Exists today (cited)

| Capability | Where |
| --- | --- |
| 24-word mnemonic, 2048-word list, 8-bit SHA-256 checksum | `stellereum/src/wallet.rs:78`, `:297-327`, `:330-377` |
| Phrase → 32-byte master seed (custom SHA-256 KDF, not BIP-39) | `stellereum/src/wallet.rs:379-390` |
| Seed → Falcon-512 key (`BLAKE3` derive-key) | `stell-wallet/src/pq.rs:419-424`, `stellereum/src/post_quantum.rs:1896-1935` |
| 32-byte PQ address `BLAKE3("STL_ADDR_V4" ‖ 0x02 ‖ pk ‖ salt)` | `stellereum/src/post_quantum.rs:111`, `:262-270` |
| Stl57 text encoding (Base58 + 4-byte BLAKE3 checksum) | `stellereum/src/address.rs:43-62`, `:67-92` |
| Encrypted keystore (Argon2id 64 MiB / t=3 / p=4, XChaCha20-Poly1305, AAD-bound metadata) | `stell-wallet/src/security.rs:22-23`, `:126-188`, `:190-255` |
| Transaction type, signing preimage, PQ1 envelope, chain id | `stellereum/src/sharding/transaction.rs:58-113`, `:521-570`, `:1319-1385`; `stellereum/src/sharding/envelope.rs:17-190` |
| Fee / priority bid rules | `stellereum/src/mempool.rs:613`, `:892-930`, `:1111-1141` |
| RPC send path | `stellereum/src/rpc/writes.rs:695-806` |
| Wallet message / typed-data signature standard | `stellereum/src/wallet_signing.rs:47-560` |
| Session-key grants, publish, revoke | `stellereum/src/zkml.rs:302-760`; `stellereum/src/svm.rs:631-661`, `:2650-2685`, `:2819-2845` |
| EVM address binding + PQ carrier | `stellereum/src/evm_adapter/binding.rs:92-410`, `:536-582`; `stellereum/src/rpc/eth.rs:1117-1310` |
| Local signer JSON protocol (`SignRequest` / `SignResponse`) | `stellereum-sdk/src/signer.rs:306-338`; loopback server `stellereum-sdk/src/signer_server.rs:143-235` |

### 0.2 Does **not** exist (do not assume it)

1. **No derivation path.** `Mnemonic::from_phrase` returns one 32-byte seed
   (`stellereum/src/wallet.rs:330-343`); the Falcon seed is a single BLAKE3
   derive-key over it (`stell-wallet/src/pq.rs:419-424`). There is no index,
   account, or path parameter anywhere in the wallet code (a repo-wide search
   for derivation-path code finds only comments and unrelated state
   re-derivation). §1.2 defines it.
2. **No connect protocol, deeplink, relay, session, or QR request.** The only
   QR use is the receive address (`stell-wallet/src/main.rs:1533-1543`). There
   is no deeplink parser and no WalletConnect code.
3. **No account-level ML-KEM key and no on-chain account KEM registry.** The
   `ml-kem` crate is a node dependency (`stellereum/Cargo.toml:50`); its
   uses are validator MEV (`stellereum/src/mev_kem_registry.rs:1-60`),
   `hashpool`, and the unwired `silentpay` (`stellereum/src/silentpay.rs:1-10`).
   `MevKemRegistry` maps validator ids, not account addresses
   (`stellereum/src/mev_kem_registry.rs:225-260`).
4. **No address book / tx history by address RPC.** History is a local file
   (`stell-wallet/src/client.rs:66-76`, `:133`, `:230-236`); there is no
   address-indexed transaction-history RPC.
5. **No post-quantum contract-call command in the wallet CLI.** It has
   `pay`, `token-send`, staking commands, `sign-typed-data`, but no `call`.
6. **No account key rotation.** `pq_registry` rotation is for validator
   consensus keys only (`stellereum/src/pq_registry.rs:1-30`, `:257-470`).
7. **No `eth_sendTransaction`, `eth_signTransaction`, `eth_sign`, `wallet_*`
   on the node.** The dispatch table only has the read methods plus
   `eth_sendRawTransaction` (`stellereum/src/rpc/eth.rs:801-1117`). The JS
   provider deliberately refuses every EVM write
   (`sdk-js/src/provider.ts:38-52`).
8. **No finalized-header binding for SPV balance proofs.**
   `verify_spv_balance_answer` checks the Merkle proof against the
   node-supplied `state_root` (`stell-wallet/src/rpc.rs:533-567`); it never
   checks that root against a finalized header or QC. A node that fabricates
   both the root and the proof is undetected. Balance and history are
   advisory; payment is the receipt plus consensus finality.

### 0.3 The blocking defect: the in-tree wallet predates the PQ excision

`stell-wallet` still names schemes the node removed. It converts to
`stellereum::post_quantum::PqScheme::Hybrid` and `::Ed25519`
(`stell-wallet/src/pq.rs:174-175`, `:184-185`, `:193-208`) and calls
`SessionKeyAuthorization::sign_delegation_hybrid`
(`stell-wallet/src/main.rs:2989`). The node's enum has only
`Falcon512` and `MlDsa44` (`stellereum/src/post_quantum.rs:152-163`), refuses
ids `0x01` and `0x04` at parse time (`stellereum/src/post_quantum.rs:184-202`), and the hybrid constructor
was deleted (`stellereum/src/zkml.rs:603-609`). **The wallet crate cannot
link against HEAD as it stands.** The first task of the implementation wave is
a mechanical FULL-PQ reconciliation of `stell-wallet` (delete
Ed25519/Hybrid/ML-DSA arms, refuse non-Falcon keystores, move session
delegation to `sign_delegation_falcon512`). Nothing in this spec depends on the
stale arms; they must not be used as precedent.

There is a second, independent hazard: **two incompatible Falcon secret
containers** exist. The node uses an expanded polynomial layout
(`FalconKeypair::to_bytes`, `stellereum/src/post_quantum.rs:1741-1759`); the SDK
uses the PQClean 1281-byte `(f, g, F)` secret and states the node container is
not importable (`stellereum-sdk/src/key.rs:18-28`). The wallet must pick the
node container for its own keystore and treat an SDK `KeyFile` as a foreign
format requiring an explicit converter (see §5.3).

---

## 1. Key model

### 1.1 The seed

```
entropy          := 256 bits from OsRng
phrase           := 24 words, 11 bits per word, checksum = SHA-256(entropy)[0]
master_seed (32) := SHA-256( "STELLEREUM_MNEMONIC_SALT_V1" ‖ trim(phrase) )
                   then SHA-256( previous ‖ "STELLEREUM_DERIVATION_KEY" )
```

* Word list: 2048 entries (counted from `stellereum/src/wallet.rs:78`; the
  doc comment two lines above says "1024" and is stale). 24 words × 11 bits =
  264 bits = 256 entropy + 8 checksum, standard BIP-39 shape.
* The checksum is validated for 24 words only (`stellereum/src/wallet.rs:346-374`); 12-word
  phrases are accepted but never checksum-validated (`stellereum/src/wallet.rs:330-345`).
* `derive_seed` trims only the outer whitespace and hashes the raw phrase
  string (`stellereum/src/wallet.rs:379-390`). Internal spacing is **not** normalized, so
  `"a  b ..."` and `"a b ..."` produce different wallets.
* The phrase is **not** BIP-39: no PBKDF2, no optional 25th-word passphrase,
  and no normalization beyond `trim`. A standard BIP-39 wallet given the same
  phrase derives a different seed and a different address. Conversely, this
  wallet cannot restore a BIP-39 account from another product.

**v1 rule:** canonicalize the phrase to the 24 parsed words joined by exactly
one ASCII space before `derive_seed`, and pin a test vector. This changes
nothing for a wallet whose phrase was entered with single spaces (the stored
keystore holds the seed, not the phrase), and removes a silent
wrong-wallet-on-restore failure.

### 1.2 Derivation scheme (NEW; account 0 must stay byte-identical)

`BLAKE3_derive_key(domain, input)` in this document denotes
`blake3::Hasher::new_derive_key(domain)` fed with `input` (the exact API used at
`stell-wallet/src/pq.rs:420`), not a separate function.

The path is a **label**, not BIP-32. There is no xpub and no public derivation:
Falcon key generation is a one-way function of the seed, so a watch-only
wallet can only be given `(address, 897-byte public key)`, never a path.

| Path | Meaning | Formula |
| --- | --- | --- |
| `m/5757'/0'/0'/0` | account 0 Falcon key (the existing address) | `falcon_seed = BLAKE3_derive_key("STELL_PQ_FALCON512_SEED_V4", master_seed)` (`stell-wallet/src/pq.rs:419-424`) |
| `m/5757'/0'/0'/i`, i > 0 | account i Falcon key | `falcon_seed_i = BLAKE3_derive_key("STELL_WALLET_FALCON_PATH_V1", master_seed ‖ 0x00 ‖ be32(i))` |
| `m/5757'/1'/0'/i` | account i ML-KEM-768 key | `kem_seed_i = BLAKE3_derive_key("STELL_WALLET_KEM_V1", master_seed ‖ 0x01 ‖ be32(i))`, fill 64 bytes via XOF |

`STELL_WALLET_FALCON_PATH_V1` and `STELL_WALLET_KEM_V1` are the only new
domain strings introduced by this spec; they are not in the tree today. Every
`connect_tests::` / `wallet_tests::` / `evm_bridge_tests::` /
`topology_tests::` identifier in §6 is a **new test name**, not an existing
API.

Then, for every i:

```
falcon_key_i   := FalconKeypair::generate_from_seed_bytes(falcon_seed_i)   // stellereum/src/post_quantum.rs:1896
address_i      := derive_pq_address(Falcon512, falcon_key_i.public_key(), DEFAULT_SALT)
kem_keypair_i  := MlKem768::from_seed(kem_seed_i)                        // via stellereum/src/mev_epoch.rs:1131-1135
```

Why account 0 is special-cased: the in-tree address is already the direct
BLAKE3 derivation, and account 0 of every existing wallet must not move. A
path wrapper for index 0 would silently strand every balance. Record
`derivation: "legacy-v0"` in the keystore for existing files and
`derivation: "path-v1"` for new files; both resolve account 0 to the same
address, so the field only documents which formula produced the higher
indices.

The salt is always `DEFAULT_SALT` (16 zero bytes,
`stellereum/src/post_quantum.rs:117`). A non-zero salt is a *different*
address for the same key, and the wallet-signature verifier pins the zero salt
(`stellereum/src/wallet_signing.rs:62-66`), so a non-zero salt would make the
account unable to use the message-signing standard. Do not expose salt as a
user option.

### 1.3 Falcon-512 signing key

* Public key 897 bytes, signature 666 bytes
  (`stellereum/src/post_quantum.rs:127`, `:136`).
* Scheme id `0x02`; it is the only id `PqScheme::from_id` accepts
  (`stellereum/src/post_quantum.rs:184-202`). ML-DSA-44 (`0x03`) is kept in the enum only to
  compile to a refusal (`stellereum/src/post_quantum.rs:206-208`, `:546-549`).
* The secret is never a 32-byte Ed25519-shaped seed at rest: the keystore
  stores the 32-byte **master seed**, and the wallet re-derives the Falcon key
  on each unlock (`stell-wallet/src/pq.rs:406-430`). Signing re-derives the
  expanded key from the 32-byte Falcon seed (`stell-wallet/src/pq.rs:534-544`).
* Signature framing is consensus: `0x29` header, 40-byte nonce, compressed
  `s2`, zero-padded to 666 bytes (`stellereum/src/post_quantum.rs:2060-2094`). The SDK
  normalizes PQClean's `0x39` to `0x29` (`stellereum-sdk/src/key.rs:213-243`).
  A signature with the wrong header byte is invalid.
* Falcon signing is randomized per signature; two signatures over the same
  message differ (documented at `stellereum/src/post_quantum.rs:2004-2046`). Never dedupe by
  signature bytes; dedupe by `tx_hash` / `request_id`.

### 1.4 ML-KEM transport key

* ML-KEM-768 (FIPS 203), 1184-byte encapsulation key, 1088-byte ciphertext
  (`stellereum/src/mev_kem_registry.rs:111`;
  `stellereum/src/mev_epoch.rs:1120-1135`).
* The account key is **derived** (table above) and recomputed on demand; it is
  never written to the keystore, never exported, and **not published in this
  wave**. No on-chain account KEM registry exists (§0.2.3).
* Connect v1 uses **ephemeral** KEM keys per handshake, generated by OS
  entropy on both sides. Do not use the account KEM key for a session: a
  long-term KEM key used as a session key loses forward secrecy for every
  past session the moment it leaks. The account key is reserved for a future
  receive/encrypted-memo feature.
* Reuse `stellereum::mev_epoch::pq_kem_ek_from_seed`,
  `pq_kem_encapsulate_deterministic`, `pq_kem_decapsulate`
  (`stellereum/src/mev_epoch.rs:1131-1178`) rather than adding a second `ml-kem` version: the
  wallet already depends on the node crate (`stell-wallet/Cargo.toml:13`) and
  this keeps the KEM byte format in one place.

### 1.5 Account address, the shard prefix, and split/merge

**There is no shard id byte in the address.** The 32 bytes are the BLAKE3
digest of `("STL_ADDR_V4", scheme, public key, salt)`
(`stellereum/src/post_quantum.rs:262-270`). What the design calls the "shard
prefix" is the **routing prefix**: the leading `prefix_len` bits of those same
32 bytes.

```
address = 32 bytes, uniformly distributed hash output
routing prefix = the top prefix_len bits of bytes 0..8   (prefix_len <= 60)
                 bit 0 = MSB of byte 0
```

Facts:

* Only the first 8 bytes are addressable by the prefix; bit index ≥ 64 reads
  as 0 (`stellereum/src/sharding/topology.rs:714-722`). The prefix is capped at
  60 bits (`stellereum/src/sharding/topology.rs:680`), and at most 16 shards exist (`:669`).
* Today shard 0 is the masterchain and is **never** selected by prefix; it is
  addressed explicitly as `-1:<addr>` (`stellereum/src/sharding/topology.rs:699-706`, `:780-810`).
  Bare 32-byte addresses route to workchain shards only.
* Shard 1 (the base workchain) has `prefix_len = 0`, which means it contains
  every workchain address (`stellereum/src/sharding/topology.rs:490-499`, `:459-475`, `:1450-1460`).
  The initial topology is exactly `{0, 1}` (`stellereum/src/sharding/topology.rs:26`).
* Textual forms: bare hex / `Stl57...` is a workchain address; `-1:<addr>` is
  the masterchain; `N:<addr>` is an explicit shard pin
  (`stellereum/src/sharding/topology.rs:826-839`). The shard annotation is transport metadata, not
  part of the 32 bytes.

**Why it survives a split/merge.** A split adds exactly one routing bit at
depth `prefix_len`; the bit is read from the account's own address
(`stellereum/src/sharding/topology.rs:1066-1091`). A merge removes the deepest bit and restores the
parent prefix. The address itself is never rewritten, rehashed, or extended:

* a split's migration manifest moves trie keys between tries and is verified
  key-by-key, including "every parent key lands in exactly one child"
  (`stellereum/src/sharding/topology.rs:1043-1120`);
* the child shard's `contains_address` check is the same prefix test
  (`stellereum/src/sharding/topology.rs:459-475`);
* an account keeps the same 32 bytes, the same Stl57 string, the same key, and
  the same signature preimage before and after the transition.

This is TON's model, stated explicitly in the code: "the same definition TON
uses for its workchain shard prefixes" (`stellereum/src/sharding/topology.rs:733-739`). It also means
split placement is not a security boundary: because the address is a uniform
hash, an attacker can grind a key to land in a chosen shard, but that only
chooses which shard carries their state, not who controls the account. Do not
build security assumptions on shard placement.

### 1.6 What is never sent over the wire

Never, on any transport (RPC, relay, QR, logs):

* the 24-word phrase or the 32-byte master seed;
* the Falcon seed, `f`, `g`, `F`, `G`, the expanded private key, or the
  keystore plaintext;
* the ML-KEM decapsulation key or the 64-byte `kem_seed`;
* the keystore password or any KDF output;
* the keystore ciphertext file itself;
* a signature over a caller-supplied digest (see §3.8).

Sent, and only these:

* the 32-byte address and its Stl57 form;
* the 897-byte Falcon public key — in an **explicit** PQ1 envelope, or in a
  connect response (§3.5) so a dApp can verify an implicit envelope; the
  steady-state implicit transaction omits it from the chain bytes (`stellereum/src/sharding/envelope.rs:40-101`,
  `stellereum/src/sharding/envelope.rs:187-260`; first-spend pinning via `StatefulImplicitKeyRegistry`,
  `stellereum/src/post_quantum.rs:280-360`);
* the 666-byte signature and the envelope framing;
* transaction fields (§2.1);
* the ephemeral KEM encapsulation key/ciphertext and AEAD frames of a connect
  session (§3);
* the account ML-KEM key **only if a future wave adds a receive feature**;
  v1 does not publish it.

### 1.7 At rest

* Keystore v2: Argon2id `m=65536,t=3,p=4`, XChaCha20-Poly1305, random 16-byte
  salt and 24-byte nonce; AAD is
  `"v{version}|address:{hex}|scheme:{scheme}|pq_pk:{hex}"`
  (`stell-wallet/src/security.rs:22-45`, `:126-188`). Any tamper with the
  address, scheme, or public key fails decryption (`stell-wallet/src/security.rs:228-247`).
* Version / KDF / cipher strings are checked before decryption
  (`stell-wallet/src/security.rs:190-208`).
* Files are created atomically with mode `0600`, parent `0700`, and a wrong
  mode is a hard error (`stell-wallet/src/security.rs:257-295`).
* The 32-byte secret is `mlock`ed best-effort and zeroized on drop
  (`stell-wallet/src/security.rs:50-78`). `mlock` can fail (RLIMIT, container); do not claim it
  as a guarantee.
* New keystores must record `scheme: "falcon512"` only. A keystore tagged
  `ed25519`, `hybrid`, or `mldsa44` is **read-only migration material**: it
  cannot sign on this chain (`stellereum/src/wallet.rs:533-540`,
  `stellereum/src/wallet.rs:616-682`).

---

## 2. The transaction the wallet signs

### 2.1 Fields and wire encoding

`Transaction` (`stellereum/src/sharding/transaction.rs:58-89`) serializes
through `TransactionWire` (`:42-56`) with bincode 1.3 defaults: little-endian
fixed-width integers, `u64` little-endian length prefixes for `Vec`. The
canonical field order is:

| # | Field | Type | Signed? | Notes |
| --- | --- | --- | --- | --- |
| 1 | `from` | `[u8; 32]` | yes | must equal `derive_pq_address(Falcon512, pk, zero_salt)` |
| 2 | `to` | `[u8; 32]` | yes | recipient account; zero address is refused by the wallet |
| 3 | `amount` | `u64` | yes | nano-STELL; 1 STELL = 10⁹ |
| 4 | `gas_limit` | `u64` | yes | **fee charged and execution cap** (see §2.6) |
| 5 | `nonce` | `u64` | yes | sender's next account nonce |
| 6 | `source_shard` | `u32` | yes | the shard that debits the sender |
| 7 | `target_shard` | `u32` | yes | the shard that credits the recipient |
| 8 | `signature` | `Vec<u8>` | — | PQ1 envelope; the whole blob is hashed into the tx id |
| 9 | `payload` | `Vec<OpCode>` | yes (commitment) | empty for a plain transfer |
| 10 | `priority_fee_per_gas` | `u64` | yes (conditional) | explicit bid; travels as a trailing 16-byte suffix inside `signature` |

Wire note: the bid is not a struct field on the wire. It is
`signature ‖ "PRIORITY" ‖ bid_be8` appended when non-zero, split back off at
decode (`stellereum/src/sharding/transaction.rs:141-190`, `:25`). A zero bid is byte-identical to a
pre-bid transaction.

### 2.2 The PQ1 signature envelope

`signature` holds exactly:

```
"PQ1" (3) ‖ scheme_id (1) ‖ is_implicit (1)
  ‖ pubkey_len (u16 LE) ‖ pubkey (pubkey_len)
  ‖ [salt (16)]                       // only when explicit
  ‖ sig_len (u16 LE) ‖ signature
  ‖ [chain_id (8 BE)]                 // only when bound
```

(`stellereum/src/sharding/envelope.rs:103-136`; strict decode at `:187-260`).
For a wallet transfer: `scheme_id = 0x02`, explicit on first spend / activation,
implicit afterwards, `pubkey` 897 bytes, `salt` 16 zero bytes, `sig_len = 666`,
`chain_id = 5757`.

Sizes: explicit + bound = `3+1+1+2+897+16+2+666+8 = 1596` bytes. Implicit +
bound = 683 bytes. The `is_pq_activation` predicate (explicit key present)
drives the 45,000 surcharge (`stellereum/src/sharding/transaction.rs:929-933`;
`stellereum/src/mempool.rs:24`).

### 2.3 The exact signing preimage

For a plain, chain-bound transfer the wallet signs **these bytes and nothing
else**:

```
from[32] ‖ to[32]
‖ amount_be8 ‖ gas_limit_be8 ‖ nonce_be8
‖ source_shard_be4 ‖ target_shard_be4
‖ "PAYLOAD" ‖ payload_bincode_len_be4 ‖ payload_bincode
[ ‖ "PRIORITY" ‖ priority_fee_per_gas_be8 ]      // only if bid != 0
‖ "CHAIN_ID" ‖ chain_id_be8
```

(`base_signing_message`, `stellereum/src/sharding/transaction.rs:521-543`; payload commitment
`stellereum/src/sharding/transaction.rs:556-570`; priority commitment `:545-554`; chain commitment `:637-640`;
`signing_message_for_chain`, `:1357-1378`).

Important: the **wire** integers are little-endian (bincode), the **preimage**
integers are big-endian. Getting that backwards produces a valid-looking
transaction that never verifies.

No textual transaction domain tag exists. Separation from other signed objects
rests on:

1. the 32-byte `from` prefix, which is a hash output the signer cannot choose
   freely; and
2. the message-signing preimage starting with 27 ASCII bytes
   (`"Stellereum Signed Message:\n"`), which a 32-byte hash-derived address
   cannot be ground to match (≈2²¹⁶ work), plus a distinct domain tag and
   length framing.

This is sound but **brittle by construction**: it is exactly why the wallet
must never sign a caller-supplied preimage or digest. A future `STELL-TX-V1`
prefix would be a consensus change (new genesis) and is not part of this wave.

### 2.4 Domain separation inventory

| Signed object | Preimage | Domain tag | Code |
| --- | --- | --- | --- |
| Transaction | fields above | none; `PAYLOAD` / `PRIORITY` / `CHAIN_ID` markers | `stellereum/src/sharding/transaction.rs:521-570`, `:637-640` |
| Wallet message | `prefix ‖ tag ‖ chain_be8 ‖ len_be8 ‖ msg` | `"STELL-MSGSIG-V1"` (15 B) | `stellereum/src/wallet_signing.rs:47-51`, `:97-109` |
| Typed call data | same framing over canonical JSON | `"STELL-TYPEDDATA-V1"` (18 B) | `stellereum/src/wallet_signing.rs:56`, `:221-249` |
| Session grant | `tag ‖ chain ‖ master ‖ session ‖ valid_until ‖ max_gas ‖ scope ‖ max_value` | `"STELL_SESSKEY_V1"` | `stellereum/src/zkml.rs:206`, `:580-599` |
| EVM ↔ PQ binding | `keccak256(tag ‖ chain_be8 ‖ evm20 ‖ pq32)` | `"STELL_EVM_BIND_V1"` | `stellereum/src/evm_adapter/binding.rs:92`, `:134-141` |
| EVM intent authorization | `keccak256(raw EVM bytes)` | none (32-byte digest) | `stellereum/src/evm_adapter/binding.rs:144-146` |
| Mnemonic → seed | two SHA-256 rounds | `"STELLEREUM_MNEMONIC_SALT_V1"`, `"STELLEREUM_DERIVATION_KEY"` | `stellereum/src/wallet.rs:381-388` |
| Seed → Falcon seed | BLAKE3 derive-key | `"STELL_PQ_FALCON512_SEED_V4"` | `stell-wallet/src/pq.rs:420` |
| Falcon keygen | BLAKE3 derive-key | `"FALCON512_KEYGEN_V5"` | `stellereum/src/post_quantum.rs:1900-1905` |
| Falcon sign randomizer | BLAKE3 derive-key | `"FALCON512_SIGN_V5"` | `stellereum/src/post_quantum.rs:2034-2042` |
| Seed → account KEM seed (NEW) | BLAKE3 derive-key | `"STELL_WALLET_KEM_V1"` | this spec |

The EVM intent row is the weak one: it is a bare 32-byte digest, and the SDK's
loopback signer exposes `POST /sign-digest` which signs any 32-byte digest
(`stellereum-sdk/src/signer_server.rs:176-235`). An attacker who can reach that
endpoint (no bearer token is required unless `STELL_SDK_SIGNER_TOKEN` is
configured, `stellereum-sdk/src/signer_server.rs:13-16`, `:148-160`) can obtain the exact `evm_signature` a carrier needs. §3.8 forbids
any digest-signing surface in the wallet and connect protocol.

### 2.5 Replay protection

Layers, in order:

1. **Chain id in the preimage and the envelope.** The wallet always builds a
   bound envelope (`stell-wallet/src/main.rs:2173`,
   `stell-wallet/src/main.rs:2194-2204`; `stell-wallet/src/client.rs:742-798`). The node compares the bound id to its
   own (`stellereum/src/sharding/transaction.rs:1379-1393`; enforced at apply by
   `stellereum/src/state_engine/apply.rs:1246-1253`), and `EVM_CHAIN_ID` is compile-time pinned
   to the consensus id (`stellereum/src/sharding/envelope.rs:418-427`).
2. **Nonce equality at execution.** `tx.nonce != sender.nonce` refuses with
   "possible replay attack" (`stellereum/src/state_engine/apply.rs:1318-1321`).
3. **Duplicate hash at admission.** An identical transaction is
   `MempoolError::Duplicate` (`stellereum/src/mempool.rs:123`, `:382-386`).
4. **Transaction hash covers the PQ envelope** (`"PQ_ENV" ‖ signature`,
   `stellereum/src/sharding/transaction.rs:876-882`), so two envelopes over the same fields are
   different ids. This is identity, not replay protection; the nonce is.
5. **Shard ids are signed** (`base_signing_message`,
   `stellereum/src/sharding/transaction.rs:521-543`), so a cross-shard replay
   breaks the signature (routing predicates at
   `stellereum/src/sharding/topology.rs:384-401`; tests in
   `stellereum/tests/xshard_replay_tests.rs`).

What is **not** there: a plain transaction has no `valid_until`. A signed
transaction with an unused nonce can be included later. Treat a pending
transaction as dead after the pool's TTLs: future nonce 60 s, stuck 120 s
(`stellereum/src/mempool.rs:784-802`). Also note the unbound-envelope gate is **off** in
release builds: `CHAIN_BINDING_ACTIVATION_HEIGHT = CHAIN_BINDING_NEVER`
(`stellereum/src/chain_binding.rs:48`, `:86-116`), so the node still admits an unbound
envelope with a warning (`stellereum/src/rpc/writes.rs:120`, `:731-751`). The wallet must
never rely on the node to reject an unbound transaction; it must always bind.

### 2.6 Fee and tip, as they exist today

There is no EIP-1559-style fee market on the Stell transaction. The two
fields are:

* `gas_limit` — the amount charged **and** the execution cap. `effective_fee`
  returns `tx.gas_limit` (`stellereum/src/mempool.rs:1119-1121`).
* `priority_fee_per_gas` — an explicit bid that must be **covered by**
  `gas_limit`: admission requires
  `gas_limit >= effective_floor(sender) + surcharge(tx) + priority_fee_per_gas`
  (`stellereum/src/mempool.rs:1111-1116`).

Where:

```
effective_floor(sender) = base_fee + failed_penalty(sender)      // stellereum/src/mempool.rs:895-898
surcharge(tx)           = 45_000 if explicit PQ key, else 0
                        + 30_000 if EVM carrier                  // stellereum/src/mempool.rs:907-921
base_fee                = node-local policy, NOT consensus       // stellereum/src/mempool.rs:613
GAS_BASIC_TRANSFER      = 280_000 nano-STELL                     // stellereum/src/svm.rs:38
```

`base_fee` is node-local, so a wallet cannot compute the exact floor from
consensus data. The SDK's rule is the reference:
`max(opcode_gas, base_fee, 280_000) + 45_000 (explicit) + priority`
(`stellereum-sdk/src/tx.rs:628-646`). The CLI currently hardcodes
`280_000 + 45_000` (`stell-wallet/src/main.rs:2169-2172`), which fails when a
node raises `base_fee`; §7 Q9 addresses this.

The EVM surface's `eth_gasPrice` / `eth_maxPriorityFeePerGas` are fixed
constants for MetaMask compatibility and are **not** the Stell fee
(`stellereum/src/evm_adapter/adapter.rs:71-103`). Do not display them as the fee.

### 2.7 Transaction id and finality

* Id: `SHA-256` over `from, to, amount, gas_limit, nonce, source_shard,
  target_shard, "PAYLOAD", payload, [priority], [delegation], ["CHAIN_ID",
  chain], [sponsor], ["PQ_ENV", signature]`
  (`stellereum/src/sharding/transaction.rs:827-885`).
* Submission returns the id (`stellereum/src/rpc/writes.rs:783-806`).
* Finality is BFT single-block: `stell_getTransactionReceipt` returns
  `success|failed` with `height`, `block_hash`, `index`, `confirmations`
  (`stellereum/src/rpc/reads.rs:1967-2035`). The wallet must require **height and a non-empty
  block hash** before showing "confirmed"; a bare `success` is not finality
  (`stell-wallet/src/rpc.rs:753-776`; test
  `stell-wallet/tests/wallet_security_tests.rs:272`).
* The wallet's local history file is not chain evidence
  (`stell-wallet/src/client.rs:230-236`); always resolve a tx by hash through the node.

### 2.8 Signing algorithm (normative)

```
1. resolve account i from the master seed (§1.2); require Falcon-512 only;
2. from  = derive_pq_address(Falcon512, pk, zero_salt)
3. route = route_shard(node_topology, Workchain(to)) for the recipient,
           route_shard(..., Workchain(from)) for the sender;
           refuse if the node reports a shard the wallet cannot address;
4. nonce = max(chain nonce from stell_getBalance, local in-flight reservation)
           (stell-wallet/src/client.rs:249-282); refuse a caller-supplied different nonce;
5. gas_limit = max(GAS_BASIC_TRANSFER, stell_baseFee) + 45_000 + priority;
   clamp priority to the user cap; never sign below the floor;
6. build Transaction{from,to,amount,gas_limit,nonce,source,target,empty sig,
   payload=[], priority};
7. msg = tx.signing_message_for_chain(5757);
8. sig = FalconKeypair::sign(msg); require exactly 666 bytes (fail closed);
9. envelope = PqSignatureEnvelope::new_explicit_with_chain(
      Falcon512, pk, sig, zero_salt, 5757) on the first spend, or
      PqSignatureEnvelope::new_implicit_with_chain(Falcon512, sig, 5757) afterwards
      (`stellereum/src/sharding/envelope.rs:58-101`);
10. verify the finished tx locally with tx.verify_signature() before sending;
11. submit hex(bincode(tx)) via stell_sendRawTransaction; the returned hash
   MUST equal tx.compute_tx_hash() (stell-wallet/src/client.rs:395-402).
```

---

## 3. Connect protocol (ours, v1)

### 3.1 Roles and trust model

* **dApp**: untrusted. It chooses the recipient and amount it wants; it may
  lie about its name and origin.
* **Wallet**: trusted computing base. It decodes the request, shows the exact
  effect, applies policy, signs, broadcasts, and returns the result.
* **Relay**: untrusted store-and-forward. It sees ciphertext and routing
  metadata only. It can drop, delay, or replay; it cannot read, forge, or
  modify (AEAD + sequence numbers).
* **No node involvement** in the handshake. The node never signs for a wallet;
  its `stell_signMessage` arms are dev-only and fail closed without
  `STELL_DEV_UNSAFE_TESTKEY=1` plus a token plus a loopback peer
  (`stellereum/src/rpc/mod.rs:68-73`; `stellereum/src/rpc/auth.rs:306-360`).
* **Never both protocols.** A wallet build either speaks this protocol or
  WalletConnect v2, never both. v1 has no WC adapter.

### 3.2 Handshake (QR / deeplink)

The dApp generates an ephemeral ML-KEM-768 keypair and a 16-byte session id,
then registers the session with a relay:

```
POST {relay}/v1/session
{ "v":1, "sid":"<32 hex>", "ek":"<2368 hex, 1184 bytes>",
  "chain":"5757", "fork":"0x0f584a46",
  "origin":"https://app.example", "app":"Example DEX",
  "exp":"<unix seconds, now+300>" }
```

The QR / deeplink carries only a commitment to the KEM key, so it stays small
enough for any QR version:

```
stl://connect/v1?relay=https%3A%2F%2Frelay.example&sid=<32 hex>
  &ekh=<64 hex, BLAKE3-256(ek)>&chain=5757&fork=0x0f584a46
  &origin=https%3A%2F%2Fapp.example&app=Example%20DEX&exp=<unix>
```

Rules:

* `relay` MUST be `https://`; `http://127.0.0.1` / `http://localhost` is
  allowed only behind an explicit developer flag.
* The wallet fetches `GET {relay}/v1/session/{sid}` and MUST verify
  `BLAKE3(ek) == ekh` before encapsulating. A mismatch aborts the handshake;
  a relay that withholds the ek is a denial of service, nothing more.
* `app` is display-only, ≤64 UTF-8 bytes, sanitized for control characters.
* `origin` is whatever the dApp sent. It is **not authenticated** and MUST be
  rendered verbatim (no truncation of the host, no punycode-to-ASCII
  beautification that hides the real host); show a warning when it is not
  `https`.
* `exp` is the handshake deadline, ≤300 s. An expired QR is refused before any
  confirmation UI.
* The QR encodes the `stl://` URI in byte mode. Budget ≤2300 bytes; `ekh` (64
  hex) keeps it under 300 bytes.

Wallet enrollment:

```
POST {relay}/v1/session/{sid}/open
{ "v":1, "ct":"<2176 hex, 1088 bytes>", "wallet":"<64 hex>",
  "wallet_stl57":"Stl57...", "chain":"5757", "fork":"0x0f584a46",
  "confirm":"<64 hex>" }
```

```
ss      = ML-KEM-768.Decaps(dk_dapp, ct)                  // 32 bytes, both sides
salt    = sid_raw(16) ‖ ct(1088)
k_d2w   = BLAKE3_derive_key("STELL_CONNECT_V1_D2W", ss ‖ salt)
k_w2d   = BLAKE3_derive_key("STELL_CONNECT_V1_W2D", ss ‖ salt)
k_confirm = BLAKE3_derive_key("STELL_CONNECT_V1_CONFIRM", ss ‖ salt)
confirm = BLAKE3::keyed_hash(k_confirm, "session" ‖ sid_raw ‖ ct ‖ wallet_raw
                                          ‖ chain_be8 ‖ fork_be4)
```

`confirm` proves the responder decapsulated the dApp's ciphertext (only the
holder of `dk_dapp` can compute `ss`). It authenticates the **ephemeral
session**, not the wallet's long-term identity: the wallet address is only
authenticated once a Falcon signature from that address verifies. The first
`signData`/`transfer` response carries the 897-byte public key and the
signature, so the dApp can check it without asking a node.

### 3.3 Framed transport

Every frame after `open` is an AEAD box:

```json
{ "v":1, "sid":"<32 hex>", "seq":"<decimal>", "dir":"d2w"|"w2d",
  "nonce":"<48 hex, 24 bytes>", "ct":"<hex>" }
```

```
nonce   = random_prefix(16) ‖ counter_be8       // per direction, never reused
aad     = "STELL_CONNECT_V1" ‖ sid_raw(16) ‖ dir(1: 0=d2w, 1=w2d)
          ‖ seq_be8
plain   = XChaCha20-Poly1305.decrypt(k_dir, nonce, ct, aad)
```

* `seq` starts at 0 and increments by exactly 1 per direction. A gap or a
  repeat is a protocol error: drop the frame and close the session (do not
  "resync").
* The 16-byte random prefix is chosen once per direction per session; the
  8-byte counter makes every nonce unique within that session. Do not shorten
  the prefix, and never reuse a prefix with the same key (session keys are
  per-handshake, so this is belt-and-braces).
* Max plaintext per frame 64 KiB (matches the message-signing cap); max outer
  frame 96 KiB. The relay's body cap is 256 KiB.
* Relay endpoints:

```
POST /v1/session/{sid}/requests                 dApp -> relay
GET  /v1/session/{sid}/requests?after=<seq>     wallet long-poll (25 s hold)
POST /v1/session/{sid}/responses                wallet -> relay
GET  /v1/session/{sid}/responses?after=<seq>    dApp poll
POST /v1/session/{sid}/close                    either side
GET  /v1/session/{sid}/status                   dApp
```

### 3.4 Request frames (plaintext schemas)

All integers that can exceed 2⁵³ are **decimal strings**, matching the typed
data convention (`stellereum/src/wallet_signing.rs:122-165`). Unknown top-level keys are a
hard error (closed schema), so a dApp cannot smuggle semantics.

`transfer`:

```json
{
  "v": 1,
  "kind": "transfer",
  "request_id": "<32 hex>",
  "chain": "5757",
  "fork": "0x0f584a46",
  "from": "Stl57... or 64-hex",
  "to": "Stl57... or 64-hex",
  "amount": "1000000000",
  "fee": { "gas_limit": "325000", "priority_fee_per_gas": "0" },
  "nonce": "7",
  "shards": { "source": 1, "target": 1 },
  "expires": "1763000000",
  "memo": "<=128 UTF-8 bytes"
}
```

`signData`:

```json
{ "v":1, "kind":"signData", "request_id":"<32 hex>", "chain":"5757",
  "fork":"0x0f584a46", "domain":"message",
  "message_b64":"...", "expires":"..." }
```

`message_b64` decodes to at most 64 KiB (`MAX_MESSAGE_BYTES`,
`stellereum/src/wallet_signing.rs:70`); typed data is capped at 64 KiB of
canonical JSON (`:73`).

```json
{ "v":1, "kind":"signData", "request_id":"<32 hex>", "chain":"5757",
  "fork":"0x0f584a46", "domain":"typed_data",
  "typed_data": { "contract":"0x...", "method":"...", "args":{},
                  "value":"0", "nonce":"0", "chain_id":"5757" },
  "expires":"..." }
```

There is no `contract_call`, no `prepared`, no `digest`, no `stake`, no
`token_*`, no `session_grant`, and no `evm_*` request kind in v1. Unknown
`kind` is `unknown_kind`, never "best effort".

Why `prepared` is forbidden even though the SDK signer supports it: the SDK's
`TxIntent::Prepared` signs any unsigned bincode transaction whose `from` is
the key's address (`stellereum-sdk/src/signer.rs:201-206`, `:392-404`;
`stellereum-sdk/src/tx.rs:343-385`). That is an arbitrary-operation signing oracle (token
approvals, staking, session-grant publication). It has no place behind a dApp
deeplink.

### 3.5 Response frames (plaintext schemas)

Success:

```json
{
  "v": 1,
  "kind": "response",
  "request_id": "<32 hex>",
  "ok": true,
  "tx_hex": "0x<bincode(Transaction)>",
  "tx_hash": "<64 hex>",
  "from": "Stl57...",
  "pq_public_key": "<1794 hex, 897 bytes>",
  "nonce": "7",
  "gas_limit": "325000",
  "chain": "5757",
  "fork": "0x0f584a46",
  "envelope": "pq1-explicit" | "pq1-implicit",
  "request_digest": "<64 hex, BLAKE3-256 of the canonical request JSON>",
  "finality": "pending" | "confirmed" | "failed" | "unknown",
  "height": "123"
}
```

`signData` success replaces `tx_hex`/`tx_hash` with:

```json
{ "ok":true, "signature":"<1569-byte envelope hex>", "address":"Stl57...",
  "preimage":"<hex>", "request_digest":"<64 hex>" }
```

Error (shape matches `SignErrorBody`, `stellereum-sdk/src/signer.rs:334-338`):

```json
{ "v":1, "kind":"response", "request_id":"...", "ok":false,
  "error": { "code":"user_rejected", "message":"...", "retryable":false } }
```

`request_digest` is the binding that lets a dApp prove the wallet signed the
request it sent, byte for byte. Compute it over the canonical JSON (sorted
keys, no whitespace) of the request exactly as received; the wallet does not
rewrite `memo` or any other field.

### 3.6 Session lifecycle, expiry, idempotency

| Item | Value |
| --- | --- |
| Handshake `exp` | ≤300 s, single use |
| Session TTL | 30 min default, 24 h hard max for `signData`-only; a `transfer` always requires a fresh per-request confirmation |
| Request `expires` | 120 s default, 600 s max |
| Open sessions per wallet | 3 |
| Requests per origin | 6/min, 30/h |
| Idle close | 10 min without a frame, wallet lock, process exit |
| Relay retention | ciphertext only, ≤24 h after close |

Idempotency:

* The wallet persists `(sid, request_id) -> response` for the session lifetime
  (+24 h after close, bounded to 256 entries).
* A duplicate `request_id` returns the cached response and **never re-signs**,
  including when the cached result was an error.
* A dApp that wants a different transfer must use a new `request_id`. Retrying
  the same id after a timeout is safe.
* The wallet reserves the nonce *before* broadcasting and returns it; two
  parallel approvals can never reuse a nonce
  (`stell-wallet/src/client.rs:271-282`).

Replay:

* session keys are per handshake and bound to `sid`/`ct`; a frame from another
  session fails the AEAD (different key) and the AAD (`sid`);
* `seq` is strictly monotonic per direction;
* `expires` is checked against wall clock at decode and again at confirmation;
* the signed transaction itself is chain-bound and nonce-bound (§2.5);
* a replayed *response* is inert: the dApp already has it, and re-submitting
  the same `tx_hex` is a duplicate hash / consumed nonce.

### 3.7 Authorization policy (wallet-side, non-negotiable)

1. `from` MUST equal the active account. Otherwise `wrong_wallet`.
2. `chain` and `fork` MUST equal the session's and the wallet's compiled
   identity. Otherwise `wrong_chain` / `wrong_fork`, before any UI.
3. `to` MUST parse to 32 bytes; the zero address is refused; `to == from` is
   allowed only with an explicit `self_transfer` user confirmation.
4. `amount > 0`; per-request cap and per-session cap (defaults in §7 Q4).
5. `fee.gas_limit` is **clamped up** to the computed floor and **down** to the
   user's fee cap; a request below the floor is refused with
   `fee_below_floor` rather than silently raised past the cap.
6. `fee.priority_fee_per_gas` ≤ user cap (default 0: no bid).
7. `nonce` must be absent or equal the wallet's next nonce. A dApp can never
   choose a nonce that strands other transactions.
8. `shards.source`/`target` are **recomputed** from the node topology; a
   mismatching request is refused with `shard_route_mismatch`. The dApp cannot
   choose the shard.
9. The wallet displays: origin (verbatim), app name, recipient in Stl57 + raw
   hex with the color/split checksum, amount in STELL and nano, fee, shard,
   memo, and the fact that a transfer is irreversible.
10. The wallet signs only after an explicit per-request approval. A session
    never grants blanket signing.
11. The wallet broadcasts by default and returns finality. v1 has no
    "return unsigned bytes" mode.

### 3.8 What a malicious dApp can and cannot do

| Action | Possible? | Why |
| --- | --- | --- |
| Learn the wallet address | yes | it is in the `open` frame |
| Learn balance / history | no | the protocol has no read methods |
| Request a transfer to itself | yes (user sees recipient and amount) | social engineering is out of scope |
| Change recipient/amount after approval | no | the signed bytes are built from the decoded request; the response contains them; `request_digest` binds it |
| Make the wallet sign a contract call, stake, token approve, session grant, validator rotation | no | no such `kind`; unknown kinds refused |
| Make the wallet sign `prepared` bytes | no | kind forbidden (§3.4) |
| Make the wallet sign an arbitrary digest | no | no digest endpoint in the wallet; `/sign-digest` is not part of this protocol |
| Reuse a response on another chain/fork/session | no | chain/fork pinned; AEAD key per session; AAD binds `sid`/`dir`/`seq` |
| Force a fee above the user cap | no | clamped |
| Choose the nonce | no | must match the wallet's next nonce |
| Choose the shard | no | recomputed from topology |
| Replay an old request | no | `expires` + `request_id` cache |
| Suppress a signed transaction | no | the wallet broadcasts |
| Drain via an on-chain session grant | no | connect v1 never mints a grant; grants are a separate, user-initiated `stell session` |
| Spam / approval-fatigue the user | rate-limited, but still a social risk | 6/min, 30/h, per-origin display |
| Link the wallet to an origin (privacy) | yes | inherent to connecting |
| Impersonate another origin | yes (display only) | `origin` is unauthenticated; the wallet must say so |

### 3.9 dApp-side verification steps

Run these before treating a response as payment:

1. Verify the `open` frame's `confirm` (§3.2). Reject a session with a
   different `chain`/`fork` than the dApp configured (`5757`,
   `protocol::FORK_ID`, `stellereum/src/protocol.rs:226`,
   `docs/RULESET_V6.md:14`).
2. Decrypt the response with `k_w2d`, check `seq`, `sid`, `dir`, and
   `request_id`; compute the canonical request digest and compare with
   `request_digest`.
3. Decode `tx_hex` to the node's `Transaction` and recompute
   `compute_tx_hash()`; it MUST equal `tx_hash`
   (`stellereum/src/sharding/transaction.rs:813-825`).
4. Derive `from' = derive_pq_address(Falcon512, pq_public_key, zero_salt)` and
   require `from' == from == the session wallet`. Rebuild
   `signing_message_for_chain(5757)` from the decoded transaction and verify
   the 666-byte signature with `verify_pq_signature` (works for both explicit
   and implicit envelopes because the key comes from the response); for an
   explicit envelope, its embedded pubkey must equal `pq_public_key`, and for
   an implicit one the node checks the pinned registry. Check
   `chain_id() == 5757`, `to`/`amount`/`nonce`/`source_shard`/`target_shard`
   equal the request, and `payload` is empty.
5. The wallet broadcasts; if its response is `unknown`, or the dApp wants an
   independent submission, re-submit the same `tx_hex` with
   `stell_sendRawTransaction` (`stellereum/src/rpc/writes.rs:695`). The duplicate
   is idempotent at admission and cannot settle twice (nonce).
6. Poll `stell_getTransactionReceipt` until `status == "success"` **with** a
   `height` and non-empty `block_hash`. Do not treat a pending/mempool hash as
   paid.
7. For `signData`: rebuild the preimage with `message_preimage` /
   `typed_data_preimage` (`stellereum/src/wallet_signing.rs:97-109`, `:235-249`), call
   `verify_message` / `verify_typed_data` (`stellereum/src/wallet_signing.rs:494-545`), and check that the
   message/typed data contains the dApp's own request id or nonce. The wallet
   does not add one.
8. For an EVM-settled transfer, additionally check
   `stell_getEvmBinding` for both sides (`stellereum/src/rpc/eth.rs:1339-1400`) before
   constructing the carrier.

### 3.10 Error codes

| Code | Meaning | Retryable |
| --- | --- | --- |
| `user_rejected` | user declined | no (new request id needed) |
| `expired` | handshake or request past `exp` | yes, new handshake |
| `wrong_wallet` | `from` is not the active account | no |
| `wrong_chain` / `wrong_fork` | identity mismatch | no |
| `unknown_kind` | kind not in v1 | no |
| `amount_out_of_policy` | per-tx/session cap | no |
| `fee_below_floor` / `fee_out_of_policy` | fee outside policy | with a corrected request |
| `recipient_invalid` | bad/zero address | no |
| `nonce_mismatch` | caller nonce is not next | with the right nonce |
| `shard_route_mismatch` | shards do not match topology | no |
| `rate_limited` | origin quota | later |
| `session_closed` | closed/expired session | new handshake |
| `internal` | wallet bug/IO | maybe |

### 3.11 Versioning and the one-fork rule

* This protocol is **off-chain**. It adds no field, opcode, domain string, or
  constant to consensus, so it does **not** bump
  `CONSENSUS_RULESET_VERSION` (`stellereum/src/protocol.rs:101`) and does not
  move `FORK_ID` (`stellereum/src/protocol.rs:226`). It ships inside the wave's single fork without
  being the fork.
* Versioning is `v=1` / `"v":1`, independent of the fork id. A future v2
  handshake is `stl://connect/v2`, and a v1-only wallet must refuse it rather
  than guess.
* The wallet pins `chain="5757"` (`stellereum/src/zkml.rs:217`) and
  `fork="0x0f584a46"` (ruleset 6, `docs/RULESET_V6.md:14`). A node on another
  chain requires a different build, not a runtime toggle.
* Any change to the transaction preimage, envelope, address derivation, or
  signature framing is a consensus change and must ride the wave's hard fork
  with a new genesis. This document freezes those bytes.
* WalletConnect v2: not implemented; if adopted later it must be a build-time
  alternative, never a simultaneous second transport. Its useful surface here
  would be an `eth_sendTransaction`-shaped transfer, which the node already
  refuses without a carrier (§4), so the ecosystem value is low.

---

## 4. MetaMask bridge boundary

### 4.1 What works: binding + carrier, transfers only

The node accepts an EVM intent only as a **PQ carrier**: a normal Falcon-512
transaction whose `SysCallEvmCarrier` payload carries the EVM bytes, the EVM
sender, the bound Falcon public key, and a Falcon signature over
`keccak256(EVM raw)` (`stellereum/src/evm_adapter/binding.rs:22-58`,
`stellereum/src/evm_adapter/binding.rs:221-276`; `stellereum/src/svm.rs:1231-1250`).

Flow (all RPC names exist):

1. **Bind** the EVM address to the PQ account:
   `stell_evmBindingSubmit { pqPublicKey, evmAddress, bindingSignature,
   evmSignature, txSignature, nonce?, gasLimit? }`
   (`stellereum/src/rpc/eth.rs:1412-1530`). On a signature failure the error
   returns `claimSignThis`/`txSignThis` so the wallet can sign the exact bytes.
2. **Submit the EVM intent** with `eth_sendRawTransaction`:
   * call 1, `[raw]` → `-32000` with
     `error.data.reason = "pq-carrier-authorization-required"`,
     `error.data.intentSignThis = keccak(EVM raw)`, `next =
     "intent-signature"` (`stellereum/src/rpc/eth.rs:1293-1310`; `stellereum/src/evm_adapter/binding.rs:671-726`);
   * call 2, `[raw, {"carrier":{"pqPublicKey","intentSignature"}}]` → the
     same refusal with `error.data.signThis` (the carrier preimage), `next =
     "carrier-signature"`;
   * call 3, with both signatures → the carrier is built, verified, admitted,
     and the **EVM hash** is returned (`stellereum/src/rpc/eth.rs:1257-1310`).
3. The carrier's `from` is the bound PQ account, `to` is the recipient's bound
   PQ account, `amount = wei / 10⁹` nano-STELL, `nonce = EVM nonce`,
   `source_shard = target_shard = 0`, and `gas_limit ≥ 700_000`
   (`stellereum/src/evm_adapter/binding.rs:536-582`; `EVM_CARRIER_MIN_GAS`, `:102`).
4. Value conversion: 1 nano-STELL = 10⁹ wei; sub-nano values are refused, not
   truncated (`stellereum/src/evm_adapter/types.rs:1308-1320`;
   `stellereum/src/evm_adapter/binding.rs:181-193`).

The secp256k1 signature inside the EVM bytes is verified (chain id, low-s,
ecrecover) but is **advisory**: it routes and displays, it never authorizes
value (`stellereum/src/evm_adapter/binding.rs:46-58`, `:159-220`).

### 4.2 What never will work here

* **Contract calls and contract creation.** No EVM interpreter and no EVM state
  trie exist; `to == null` or any calldata is refused with
  `evm-contract-execution-unsupported` (`stellereum/src/evm_adapter/binding.rs:109-116`, `:159-220`;
  `stellereum/src/rpc/eth.rs:1-22`).
* **EVM accounts.** There is no EVM account state. An unbound 20-byte address
  cannot receive value: crediting it would burn the funds
  (`stellereum/src/evm_adapter/binding.rs:650-663`, `:740-760`).
* **`eth_sign`, `personal_sign`, `eth_signTypedData`, `eth_signTransaction`,
  `eth_sendTransaction`, `wallet_*`.** Not implemented on the node
  (`stellereum/src/rpc/eth.rs:801-1117` dispatch) and explicitly refused by the JS provider
  (`sdk-js/src/provider.ts:38-52`).
* **Using a secp256k1 signature as a consensus credential.** There is no mode
  that makes one: the EV1 envelope is refused
  (`stellereum/src/evm_adapter/tx.rs:274-282`; `stellereum/src/mempool.rs:48`), and the
  mempool requires a PQ1/SF1 envelope (`stellereum/src/rpc/eth.rs:29-46`).
* **Gasless EVM / ERC-20 / approvals / multicall.** No EVM execution, no
  state.

### 4.3 How the EVM–PQ binding is proven

Two independent signatures over one statement:

```
binding_message = keccak256("STELL_EVM_BIND_V1" ‖ chain_id_be8 ‖ evm(20) ‖ pq(32))
```

* Falcon-512 by the PQ account over `binding_message`
  (`stellereum/src/evm_adapter/binding.rs:134-141`, `:337-380`);
* secp256k1 proof of possession, `r || s || recovery_id` (65 bytes, low-s), by
  the EVM key, recovering exactly `evm` (`stellereum/src/evm_adapter/binding.rs:278-334`).

Without the second signature any PQ key could first-claim someone else's EVM
identity; the verifier refuses a missing/mismatched proof (`stellereum/src/evm_adapter/binding.rs:378-386`
and the conflict path at `stellereum/src/rpc/eth.rs:1457-1477`). The on-chain record is a
`SysCallBindEvmAddress` transaction (`stellereum/src/evm_adapter/binding.rs:584-640`); the read index is a
replay of **committed** records only, never mempool claims
(`stellereum/src/rpc/eth.rs:1363-1366`; `stellereum/src/state_engine/accounts.rs:2688`).

The carrier then adds a second, independent Falcon statement:
`evm_signature = Falcon(keccak256(EVM raw))` (`stellereum/src/evm_adapter/binding.rs:144-146`,
`stellereum/src/evm_adapter/binding.rs:221-276`). Both must verify: the envelope over the Stell signing message
(which commits to the whole payload, hence the EVM bytes) and the intent
signature over the EVM digest. A relayer cannot produce either.

### 4.4 Failure modes shown to the user

| Node signal (`error.data.reason`) | Meaning | UI copy / next action |
| --- | --- | --- |
| `full-pq-admission` | EVM address has no PQ binding, or no PQ auth covers the intent | "MetaMask cannot move funds on Stellereum by itself. Create a Stell wallet, bind this EVM address, then retry." Link to binding. (`stellereum/src/evm_adapter/tx.rs:199-264`) |
| `pq-carrier-authorization-required` | binding exists; Falcon signatures missing | Step 1/2: show `intentSignThis` and the exact `signThis`; explain that both are signed by the Stell wallet. (`stellereum/src/evm_adapter/binding.rs:643-726`) |
| `pq-key-not-the-bound-key` | supplied Falcon key is not the bound account | Show bound vs derived address; refuse to continue. (`stellereum/src/rpc/eth.rs:1232-1256`) |
| `evm-binding-conflict` | EVM address already bound to another PQ account | "First claim wins"; no override. (`stellereum/src/rpc/eth.rs:1457-1477`) |
| `evm-binding-signature-rejected` | Falcon or secp proof failed | Show `claimSignThis`; do not retry blindly. (`stellereum/src/rpc/eth.rs:1506-1535`) |
| `recipient-evm-address-unbound` | recipient has no PQ account | "Ask the recipient to bind first; sending would burn the funds." (`stellereum/src/evm_adapter/binding.rs:650-663`, `:740-760`) |
| `evm-contract-execution-unsupported` | calldata or contract creation | "Contracts are not supported on the EVM surface; use the native SVM." (`stellereum/src/evm_adapter/binding.rs:109-116`, `:646-648`) |
| `carrier nonce mismatch` | EVM nonce != Stell nonce | Rebuild from the current nonce; never hand-edit. (`stellereum/src/evm_adapter/binding.rs:478-493`; `stellereum/src/mempool.rs:2518-2524`) |
| `carrier amount mismatch` | amount does not match the intent | Refuse; do not submit. (`stellereum/src/mempool.rs:2525-2531`) |
| EVM chain id mismatch | MetaMask on the wrong network | "Switch to chain id 5757." (`stellereum/src/evm_adapter/types.rs:2355-2365`, `:2667-2679`; `EVM_CHAIN_ID` at `stellereum/src/sharding/envelope.rs:421`) |
| `eth_sendTransaction` unsupported | MetaMask's default send path | "Use `eth_sendRawTransaction` with the PQ carrier, or use the Stell wallet." |

### 4.5 The honest client-side gap

The node's carrier API is complete, but **nothing in-tree captures the
secp256k1-signed raw bytes from MetaMask**. MetaMask's normal send calls
`eth_sendRawTransaction` on its configured RPC; if that RPC is the Stell node,
the node returns the refusal above and MetaMask surfaces it, but the dApp
never receives the raw bytes and therefore cannot attach the carrier
signatures. There is no `eth_signTransaction` handler on the node and the
in-tree JS provider refuses all EVM writes. Consequences:

* a transfer initiated *inside MetaMask* against the Stell RPC cannot complete
  in this wave; it ends in an actionable refusal;
* a transfer initiated by a dApp page that can obtain the raw EVM bytes
  (programmatic secp signer, or a future local capture proxy) can complete via
  the three-step carrier flow;
* do not claim "MetaMask works" in user-facing copy until a capture mechanism
  ships. §7 Q8 records the decision.

---

## 5. Recovery and UX

### 5.1 Seed backup

* At creation the wallet prints the 24 words once and stores only the derived
  32-byte seed (`stell-wallet/src/main.rs:1207-1239`, `:1299-1310`).
* `stell export` prints the **hex master seed**, not the phrase, and refuses
  without `--show-seed` plus the keystore password
  (`stell-wallet/src/main.rs:3147-3173`). There is no seed→phrase encoder in-tree, so a user
  who lost the paper phrase but still has the keystore can recover with
  `stell restore --key <hex>` (`stell-wallet/src/main.rs:1320-1365`).
* Restore accepts a 24-word phrase, a 12-word phrase, or a 32-byte hex key
  (`stell-wallet/src/main.rs:1330-1352`). v1 policy: accept 24 words and 32-byte hex; accept 12
  words only behind `--legacy-12` with a loud warning (no checksum, no
  entropy reconstruction for 12 words, `stellereum/src/wallet.rs:330-345`).
* Backup checklist shown to the user: write the 24 words offline, never
  photograph them, verify by restoring into a second empty wallet *before*
  funding, and store the keystore file separately from the phrase.
* Because the KDF is custom, tell the user explicitly: "this phrase restores
  only in Stellereum wallets; a standard BIP-39 wallet will show a different,
  empty account."

### 5.2 Passphrase policy

* **Keystore password** is the only passphrase today. The code enforces a
  6-character minimum (`stell-wallet/src/main.rs:937-942`); v1 policy raises the UI requirement
  to 12 characters and rejects the top-1000 common passwords, while keeping
  the 6-character check for existing files.
* Argon2id cost is fixed at 64 MiB / 3 passes / 4 lanes
  (`stell-wallet/src/security.rs:23`, `:137`, `:209`); do not lower it, and do not make it
  user-tunable (a user who lowers it silently weakens every future file).
* Prefer the TTY prompt. `--password` on argv warns that it leaks through shell
  history and `ps` (`stell-wallet/src/main.rs:955-980`); keep the warning printable in scripts.
* **No 25th-word mnemonic passphrase in v1.** Adding one changes
  `Mnemonic::from_phrase` → every address changes. If the operator wants it,
  it must be a new derivation version plus a sweep migration (§7 Q2).
* No password recovery, no escrow, no "reset". State it at creation.

### 5.3 Export / import formats

| Format | Direction | Status |
| --- | --- | --- |
| 24-word phrase | export at creation only; import | existing (`stellereum/src/wallet.rs:297-377`) |
| 32-byte master seed hex | `stell export --show-seed`; `stell restore --key` | existing (`stell-wallet/src/main.rs:3147`, `:1330`) |
| Encrypted keystore JSON v2 | copy between machines | existing (`stell-wallet/src/security.rs:92-110`, `:257-310`) |
| Node `WalletKeyFileV1` `{"scheme":"falcon512","key_hex":...}` | library save/load | existing library (`stellereum/src/wallet.rs:583-682`); **not used by the CLI** |
| SDK `KeyFile` v1 (`pqcrypto` `(f,g,F)` secret) | import | **incompatible** with the node container (`stellereum-sdk/src/key.rs:18-28`); needs an explicit converter or re-signing, not a silent load |
| Plaintext private key / seed in a QR or a connect frame | — | forbidden |

Export hardening (v1): default export is the encrypted keystore; seed export
requires `--show-seed` **and** a typed confirmation ("I understand anyone
reading this controls my funds"); never write the seed to a file implicitly.

### 5.4 Session revocation

Two different things are called "session":

1. **Connect transport session** (§3): revocable locally by dropping the
   session key and posting `close`; on-chain state is untouched. Already
   signed transactions remain final.
2. **On-chain session-key grant** (`zkml::SessionKeyAuthorization`,
   `stellereum/src/zkml.rs:302-760`): scope, `valid_until`, `max_gas_spend`,
   `max_value_per_tx`, chain id, all signed by the master
   (`stellereum/src/zkml.rs:580-608`). Publishing it as
   `SysCallPublishSessionGrant` requires the master as sender
   (`stellereum/src/svm.rs:2819-2845`). Revocation is
   `SysCallRevokeSession { session_pubkey }`; only the master may revoke,
   `revoked` is terminal, and an **unused/unknown** key cannot be revoked
   pre-emptively because the registry has no record to authenticate against
   (`stellereum/src/svm.rs:2650-2685`). Test:
   `stellereum/tests/session_key_tests.rs:1705`.

The wallet's existing `stell session --publish` does broadcast the grant
(`stell-wallet/src/main.rs:3030-3065`), but `stell aa revoke-session` only
prints a tombstone message and sends nothing (`stell-wallet/src/main.rs:4047-4082`). v1 must
either implement the revocation transaction or remove the command; a printed
"PERMANENTLY REVOKED" that does not touch the chain is a funds-safety lie.

### 5.5 Compromised hot session

If a **connect session key** leaks (laptop malware, relay breach, dApp
compromise):

1. close the session locally and at the relay; delete the session file;
2. assume any request already approved is final; check the account nonce and
   recent transactions;
3. open no new session until the host is cleaned; rotate the wallet to a new
   account seed if the host compromise could have reached the keystore;
4. if an **on-chain grant** was published for a bot, send
   `SysCallRevokeSession` from the master (only works if the key has been
   registered by use; otherwise wait for `valid_until`);
5. keep hot wallets low-balance and per-origin; the master seed belongs on an
   offline machine until hardware wallets ship.

If the **master seed** leaks: there is no account key rotation on this chain.
Create a new wallet (new seed), sweep the balance, and accept that the old
address is permanently compromised. Validator key rotation
(`pq_registry`) does not help an account.

### 5.6 UX invariants

* Never ask for the seed phrase outside `new`/`restore`.
* Never accept a seed phrase in a deeplink, QR, or RPC parameter.
* Show the full recipient in Stl57 plus raw hex; use the visual checksum
  (`stell-wallet/src/pq.rs:309-360`) and never rely on color alone.
* Show the fee in STELL and nano, and the shard pair, before signing.
* After signing, show `tx_hash` and then the receipt state; "pending" is not
  "paid" (`stell-wallet/src/rpc.rs:43-60`).
* On any refusal, show the node's stable `reason` tag and the actionable next
  step; never a generic "transaction failed".

---

## 6. Threat model

"Test that must exist" means either an existing test that already pins it
(cited) or a named test the wave must add (**NEW**).

| # | Attacker capability | Mitigation | Test that must exist |
| --- | --- | --- | --- |
| T1 | Malicious dApp sends a transfer whose UI shows a different recipient/amount | Wallet builds the signed bytes from the decoded request; response echoes them; `request_digest` binds request↔response; display is generated from the same decoded values | **NEW** `connect_tests::request_recipient_and_amount_are_exactly_the_signed_fields` |
| T2 | Relay modifies a frame in flight | XChaCha20-Poly1305 with per-direction keys; AAD binds `sid`, `dir`, `seq` | **NEW** `connect_tests::tampered_ciphertext_is_rejected` (flip one byte in `ct`, `sid`, `seq`, `dir`) |
| T3 | Relay replays an old request/response | `seq` strict +1; `request_id` cache; `expires`; chain-bound tx | **NEW** `connect_tests::replayed_seq_is_rejected`; **NEW** `connect_tests::duplicate_request_id_returns_cached_response_without_resigning` |
| T4 | Relay substitutes the dApp's KEM key to read the session | QR carries `ekh = BLAKE3(ek)`; wallet verifies before encapsulating; `confirm` proves possession of `dk` | **NEW** `connect_tests::handshake_requires_matching_ek_hash`; `connect_tests::session_confirm_mac_authenticates_the_kem_secret` |
| T5 | Phishing QR claims a trusted origin | Origin is unauthenticated and rendered verbatim with a warning; no origin-based auto-approval | **NEW** `connect_tests::origin_is_displayed_verbatim`; `connect_tests::origin_never_grants_policy` |
| T6 | Expired deeplink replayed later | Handshake `exp` ≤300 s, single use; request `expires` checked twice | **NEW** `connect_tests::expired_handshake_refused`; `connect_tests::expired_request_never_reaches_confirmation` |
| T7 | Approval fatigue / request flood | Per-origin rate limit 6/min, 30/h; one open confirmation at a time | **NEW** `connect_tests::request_rate_limit_per_origin` |
| T8 | dApp asks for a digest / prepared bytes to authorize an EVM carrier | v1 has no `digest`/`prepared` kind; closed schema; unknown kind refused | **NEW** `connect_tests::digest_and_prepared_kinds_are_not_constructible`; `connect_tests::unknown_kind_is_refused` |
| T9 | dApp requests a contract call / stake / token approval / grant | No such kind; wallet has no contract-call builder | **NEW** `connect_tests::unsupported_kinds_have_no_builder` |
| T10 | dApp forces a nonce to strand other transactions | Nonce must equal the wallet's next; local reservation | **NEW** `connect_tests::nonce_cannot_be_chosen_by_dapp`; **NEW** `connect_tests::two_parallel_approvals_never_share_nonce` |
| T11 | dApp picks a shard to misroute/debit the wrong lane | Shards recomputed from topology; mismatch refused | **NEW** `connect_tests::shard_route_is_derived_from_topology` |
| T12 | dApp forces an excessive fee / wins priority at user expense | Fee clamped to floor and user cap; bid default 0 | **NEW** `connect_tests::fee_is_clamped_to_floor_and_user_cap` |
| T13 | Wallet signs on the wrong chain after a fork | `chain` + `fork` pinned at handshake; compiled identity; tx chain commitment | `stellereum/tests/wallet_chain_binding_tests.rs:65` (bound), `:143` (unbound refused), `:178` (cross-chain); **NEW** `connect_tests::chain_or_fork_mismatch_refuses_before_display` |
| T14 | Captured signed tx replayed on another chain | `CHAIN_ID` commitment in the preimage; envelope chain id; node strict match (`stellereum/src/sharding/transaction.rs:637-640`, `:1379-1393`) | `stellereum/tests/wallet_chain_binding_tests.rs`; **NEW** `connect_tests::response_is_never_reusable_on_another_chain` |
| T15 | Keystore stolen from disk | 0600/0700, Argon2id 64 MiB, XChaCha20-Poly1305, AAD binds address/scheme/pubkey | `stell-wallet/tests/wallet_security_tests.rs:30` (tamper), `:69` (wrong password), `:83` (permissions), `:184` (address/metadata binding) |
| T16 | Offline brute force of a weak keystore password | Memory-hard KDF + 12-char policy + common-password rejection | **NEW** `wallet_tests::weak_password_is_refused`; existing `test_wrong_password_rejection` |
| T17 | Process memory / swap scrape | `mlock` best-effort + zeroize on drop | `stell-wallet/tests/wallet_pq_tests.rs:236` memory-scrub test (note: that file is pre-excision; port it); **NEW** `wallet_tests::seed_is_zeroized_after_unlock` |
| T18 | Clipboard/address substitution | Stl57 checksum + visual split + raw hex display; homoglyph refusal | `stellereum/src/address.rs:291-300` (homoglyph prefix refused); **NEW** `wallet_tests::recipient_is_shown_in_two_forms` |
| T19 | Phishing page asks the user to paste a seed | Seed is never accepted outside `restore`; connect schema has no secret fields | **NEW** `connect_tests::frames_have_a_closed_field_set` (assert no seed/key field can parse) |
| T20 | Compromised connect session key spends beyond intent | No blanket signing; per-request confirmation; per-session caps; revoke on host compromise | **NEW** `connect_tests::compromised_session_cannot_spend_beyond_cap` |
| T21 | On-chain session grant abuse (bot key) | Scope + `valid_until` + gas budget + per-tx value cap; registry revocation is terminal | `stellereum/tests/session_key_tests.rs:1571`, `:1705`; `stellereum/tests/audit_closure_privacy_tests.rs:46`, `:71`, `:92`; `stellereum/tests/block_packing_scale_tests.rs:299` |
| T22 | `aa revoke-session` lies (prints but does not send) | v1 must broadcast `SysCallRevokeSession` or delete the command | **NEW** `wallet_tests::revoke_session_broadcasts_or_is_removed` |
| T23 | Untrusted node lies about balance/nonce | SPV proof verified locally against the **served** root (detects an inconsistent node; a node that fabricates root+proof is undetected until the root is header-anchored); receipt requires height+block hash | `stell-wallet/src/rpc.rs:533-567`; `stell-wallet/src/client.rs:302-345`; `stell-wallet/tests/wallet_security_tests.rs:272`; `stellereum/src/wallet.rs:1518` |
| T24 | Untrusted node forges "confirmed" | Bare `success` is Pending; both height and non-empty block hash required | `stell-wallet/tests/wallet_security_tests.rs:272` (`poc_receipt_bare_success_must_not_be_confirmed`) |
| T25 | Untrusted node withholds / censors | Wallet broadcasts to the configured node; a second node or manual resubmit is a user option; `tx_hash` is deterministic | **NEW** `wallet_tests::tx_hash_is_stable_across_nodes` |
| T26 | EVM key first-claims someone else's EVM address | 65-byte secp proof of possession over the binding digest | `stellereum/src/evm_adapter/binding.rs:337-380`; **NEW** `evm_bridge_tests::binding_requires_evm_proof` (negative: missing/wrong proof) |
| T27 | EVM intent signed by a foreign PQ key | Carrier builder/verifier derives `from` from the carried key and compares to the bound account | `stellereum/tests/evm_carrier_binding_tests.rs:456` |
| T28 | EVM carrier replay / rewrap with a fresh Stell nonce | EVM nonce committed in both the intent and the tx; admission refuses mismatch; nonce consumed at apply | `stellereum/tests/evm_carrier_binding_tests.rs:553` |
| T29 | EVM contract call disguised as a transfer | `evm_transfer_facts` refuses `to == null` and non-empty calldata | `stellereum/tests/evm_carrier_binding_tests.rs:659` |
| T30 | EVM recipient has no PQ account (funds burned) | Recipient binding required | `stellereum/tests/evm_carrier_binding_tests.rs:413` |
| T31 | EVM carrier underpays the Stell floor | `gas_limit ≥ floor + 30_000`, min 700_000 | `stellereum/tests/evm_carrier_binding_tests.rs:724` |
| T32 | Unbound (replayable) envelope slips through | Wallet always binds; the node gate is off in release, so the wallet cannot delegate this | `stellereum/tests/wallet_chain_binding_tests.rs:65`, `:178`; **NEW** `connect_tests::response_always_chain_bound` |
| T33 | Address grinding into a chosen shard | Accepted risk: shard placement is not an authorization boundary; document it | **NEW** `topology_tests::shard_placement_is_not_an_authz_boundary` (doc-level assertion test) |
| T34 | Split/merge orphans or changes an account | Routing prefix is a prefix of the address; migration verified key-by-key | `stellereum/src/sharding/tests/topology_tests.rs:78` (split), `:195` (merge), `:305` (prefix bit); **NEW** `wallet_tests::address_is_stable_across_split` |
| T35 | Two Falcon secret containers are confused on import | CLI accepts only the node container + seed/phrase; SDK KeyFile is refused or converted explicitly | **NEW** `wallet_tests::sdk_keyfile_is_not_silently_imported` |
| T36 | ML-KEM account key accidentally published / reused for sessions | v1 derives it but never publishes it; connect uses ephemeral keys | **NEW** `connect_tests::mlkem_account_key_is_never_published` |

---

## 7. Open questions for the operator (with recommended defaults)

**Q1. Derivation path freeze.** Account 0 must stay the existing direct
BLAKE3 derivation, or existing wallets move address. Recommended default:
freeze account 0 as the legacy formula; use
`STELL_WALLET_FALCON_PATH_V1` only for i > 0; record `derivation` in the
keystore.

**Q2. Mnemonic passphrase (25th word).** Recommended default: **no** in v1.
It changes the phrase→seed function and every address. If wanted later,
introduce `derivation: "v2"` and migrate by sweep, never silently.

**Q3. Relay ownership.** Recommended default: allow any HTTPS relay in the QR,
plus one official relay (`connect.stellereum.org`) for users who have no
relay; the wallet always displays the relay host and refuses plain HTTP except
loopback.

**Q4. Session limits.** Recommended default: 30-minute session TTL, 120-second
request expiry, per-tx cap 1,000 STELL, per-session cap 5,000 STELL, both
user-configurable downward only. Higher limits require a fresh QR handshake.

**Q5. `signData` in v1.** Recommended default: yes, message and typed data
only, using the existing `wallet_signing` standard; no raw-digest signing and
no `prepared` transactions.

**Q6. Contract calls in connect v1.** Recommended default: no. The wallet has
no contract-call UI or builder; adding one is a separate product wave with its
own review. The node's `stell_callContract` preview is not a signing path.

**Q7. Who broadcasts.** Recommended default: the wallet broadcasts and returns
finality; the dApp may re-submit the same `tx_hex` idempotently. This removes
the "signed but never sent" failure and stops a dApp from censoring an approved
transfer.

**Q8. MetaMask raw capture.** Recommended default: do not ship a capture
mechanism in this wave. Keep the carrier API for programmatic EVM signers and
show MetaMask users an actionable "use the Stell wallet" refusal. Revisit only
if MetaMask exposes `eth_signTransaction`, or approve a separate local capture
proxy with its own threat model.

**Q9. CLI shard defaults.** The wallet defaults `--shard 0` for `pay`/`balance`
(`stell-wallet/src/main.rs:151`, `stell-wallet/src/main.rs:129`) while shard 1 holds every workchain
address (`stellereum/src/sharding/topology.rs:1450-1460`); the SDK also defaults
`masterchain → masterchain` (`stellereum-sdk/src/tx.rs:610-615`). Recommended
default: derive `source_shard`/`target_shard` from `stell_getShardTopology`
and keep `--shard` as an explicit override with a warning. Shipping the
current default on a two-shard deployment produces foreign-shard refusals
(`stellereum/src/mempool.rs:2050-2072`).

**Q10. Multi-account storage.** Recommended default: one seed, N accounts in
one keystore metadata block (`accounts: [{index, address, pubkey}]`), rather
than one file per account. One file keeps the KDF cost paid once and makes
"restore the phrase → all accounts" true.

**Q11. Fee floor visibility.** There is no RPC for the per-sender penalty floor
(`effective_floor` is node-local, `stellereum/src/mempool.rs:892-898`). Recommended default:
add a read-only `stell_getFeeFloor { sender }` in this wave (no consensus
change) so the wallet stops guessing; until then, clamp to
`max(280_000, stell_baseFee) + 45_000` and surface a fee rejection verbatim.

**Q12. Revocation of unused session grants.** `SysCallRevokeSession` refuses an
unknown key (`stellereum/src/svm.rs:2650-2685`), so a grant that was published but never used
cannot be revoked before expiry. Recommended default: cap grant lifetime at
24 h for hot bots and do not add an opcode this wave (an opcode is a hard
fork); revisit with a pre-registration/tombstone opcode in a later wave.

**Q13. WalletConnect v2 trigger.** Recommended default: only if at least two
independent ecosystem dApps require it and are unwilling to integrate the
deeplink. If adopted, it is a build-time alternative, not a second transport,
and it can only express a `transfer`-shaped intent.

**Q14. SPV root anchoring.** `verify_spv_balance_answer` currently trusts the
node's `state_root` (`stell-wallet/src/rpc.rs:533-567`). Recommended default:
in this wave, label every balance/history view "node-reported, proof-checked,
not header-anchored"; add finalized-header/QC anchoring in the next wave, with
a test that a fabricated root is refused.

---

## Appendix A. Verified symbol index

Every symbol used above, with the exact line that defines it. This appendix
exists so the implementation wave can re-grep rather than trust prose.

| Symbol | File:line |
| --- | --- |
| `PQ_ADDRESS_DOMAIN` | `stellereum/src/post_quantum.rs:111` |
| `derive_pq_address` | `stellereum/src/post_quantum.rs:262` |
| `DEFAULT_SALT` | `stellereum/src/post_quantum.rs:117` |
| `PqScheme::Falcon512` / `MlDsa44` | `stellereum/src/post_quantum.rs:152-163` |
| `PqScheme::from_id` | `stellereum/src/post_quantum.rs:184` |
| `PqScheme::is_disabled` | `stellereum/src/post_quantum.rs:206` |
| `FALCON512_PUBKEY_LEN` / `FALCON512_SIG_LEN` | `stellereum/src/post_quantum.rs:127`, `:136` |
| `FalconKeypair` | `stellereum/src/post_quantum.rs:1618` |
| `FalconKeypair::generate_from_seed_bytes` | `stellereum/src/post_quantum.rs:1896` |
| `FalconKeypair::sign` | `stellereum/src/post_quantum.rs:1960` |
| `FalconKeypair::to_bytes` / `from_bytes` | `stellereum/src/post_quantum.rs:1741`, `:1761` |
| `verify_pq_signature` | `stellereum/src/post_quantum.rs:534` |
| `StatefulImplicitKeyRegistry` | `stellereum/src/post_quantum.rs:280` |
| `Mnemonic::generate` / `from_phrase` | `stellereum/src/wallet.rs:297`, `:330` |
| `Mnemonic::derive_seed` | `stellereum/src/wallet.rs:379` |
| `WORDLIST` | `stellereum/src/wallet.rs:78` |
| `WalletKeyMaterial` | `stellereum/src/wallet.rs:543` |
| `WalletKeyMaterial::from_seed` / `address` | `stellereum/src/wallet.rs:684`, `:708` |
| `WalletKeyMaterial::delegate_bot_session_falcon512` | `stellereum/src/wallet.rs:942` |
| `save_wallet_key` / `load_wallet_key` | `stellereum/src/wallet.rs:583`, `:616` |
| `CLASSICAL_WALLET_KEY_REFUSAL` | `stellereum/src/wallet.rs:533` |
| `PqKeyPair::from_seed` | `stell-wallet/src/pq.rs:406` |
| `sign_falcon512` | `stell-wallet/src/pq.rs:534` |
| `wallet_standard_signing_key` | `stell-wallet/src/pq.rs:574` |
| `STELL_MESSAGE_PREFIX` / domain tags | `stellereum/src/wallet_signing.rs:47-56` |
| `message_preimage` | `stellereum/src/wallet_signing.rs:97` |
| `TypedCallData` | `stellereum/src/wallet_signing.rs:122` |
| `canonical_typed_data_json` | `stellereum/src/wallet_signing.rs:221` |
| `typed_data_preimage` | `stellereum/src/wallet_signing.rs:235` |
| `WalletSignature` / `encode` / `decode` | `stellereum/src/wallet_signing.rs:277`, `:291`, `:310` |
| `WalletSigningKey::falcon_from_seed` | `stellereum/src/wallet_signing.rs:403` |
| `WalletSigningKey::sign_message` / `sign_typed_data` | `stellereum/src/wallet_signing.rs:437`, `:461` |
| `verify_message` / `verify_typed_data` | `stellereum/src/wallet_signing.rs:494`, `:521` |
| `Transaction` / `TransactionWire` | `stellereum/src/sharding/transaction.rs:58`, `:42` |
| `PRIORITY_FEE_COMMITMENT_TAG` | `stellereum/src/sharding/transaction.rs:25` |
| `base_signing_message` | `stellereum/src/sharding/transaction.rs:521` |
| `signing_message` / `_for_chain` | `stellereum/src/sharding/transaction.rs:1319`, `:1357` |
| `compute_tx_hash` | `stellereum/src/sharding/transaction.rs:813` |
| `PqSignatureEnvelope` (wire) | `stellereum/src/sharding/envelope.rs:17` |
| `PqSignatureEnvelope::encode` / `decode` | `stellereum/src/sharding/envelope.rs:106`, `:187` |
| `CHAIN_ID_COMMITMENT_TAG` | `stellereum/src/sharding/envelope.rs:436` |
| `EVM_CHAIN_ID` | `stellereum/src/sharding/envelope.rs:421` |
| `ShardId` / `MASTERCHAIN_SHARD` | `stellereum/src/sharding/topology.rs:7`, `:8` |
| `PUBLIC_SHARD_PAIR` | `stellereum/src/sharding/topology.rs:26` |
| `ROUTING_RULE` | `stellereum/src/sharding/topology.rs:699` |
| `address_prefix_bit` / `address_prefix_word` | `stellereum/src/sharding/topology.rs:714`, `:733` |
| `MAX_PREFIX_BITS` / `MAX_SHARDS` | `stellereum/src/sharding/topology.rs:680`, `:669` |
| `ShardAddress` | `stellereum/src/sharding/topology.rs:780` |
| `split_shard_prefix` | `stellereum/src/sharding/topology.rs:826` |
| `ShardDescriptor::contains_address` | `stellereum/src/sharding/topology.rs:459` |
| `ShardTopology::route` / `route_workchain` | `stellereum/src/sharding/topology.rs:1553`, `:1561` |
| `route_shard` | `stellereum/src/sharding/topology.rs:1966` |
| `tx_belongs_to_shard` / `tx_targets_shard` | `stellereum/src/sharding/topology.rs:399`, `:384` |
| `MigrationPlan` / `TrieMigration` | `stellereum/src/sharding/topology.rs:876`, `:1043` |
| `PQ_ACTIVATION_SURCHARGE_GAS` / `EVM_CARRIER_SURCHARGE_GAS` | `stellereum/src/mempool.rs:24`, `:37` |
| `Mempool::effective_floor` / `required_fee_for_tx` | `stellereum/src/mempool.rs:895`, `:1111` |
| `Mempool::surcharges_for_tx` | `stellereum/src/mempool.rs:907` |
| `GAS_BASIC_TRANSFER` | `stellereum/src/svm.rs:38` |
| `SysCallRevokeSession` / `SysCallPublishSessionGrant` | `stellereum/src/svm.rs:631`, `:661` |
| `SessionKeyAuthorization` | `stellereum/src/zkml.rs:302` |
| `SESSION_KEY_DOMAIN` | `stellereum/src/zkml.rs:206` |
| `SessionKeyAuthorization::grant_message` | `stellereum/src/zkml.rs:580` |
| `sign_delegation_falcon512` | `stellereum/src/zkml.rs:610` |
| `verify_at` / `grants_scope` | `stellereum/src/zkml.rs:740`, `:734` |
| `EVM_BINDING_DOMAIN` | `stellereum/src/evm_adapter/binding.rs:92` |
| `binding_message` | `stellereum/src/evm_adapter/binding.rs:134` |
| `evm_intent_digest` | `stellereum/src/evm_adapter/binding.rs:144` |
| `evm_transfer_facts` | `stellereum/src/evm_adapter/binding.rs:159` |
| `verify_carrier_intent` | `stellereum/src/evm_adapter/binding.rs:221` |
| `recover_binding_claim_signer` | `stellereum/src/evm_adapter/binding.rs:296` |
| `verify_binding_claim` | `stellereum/src/evm_adapter/binding.rs:337` |
| `build_carrier_transaction` / `build_binding_transaction` | `stellereum/src/evm_adapter/binding.rs:536`, `:594` |
| `EVM_CARRIER_AUTH_REASON` | `stellereum/src/evm_adapter/binding.rs:643` |
| `carrier_signing_message` | `stellereum/src/evm_adapter/binding.rs:765` |
| `EVM_WRITE_REFUSAL_REASON` / `evm_send_refusal` | `stellereum/src/evm_adapter/tx.rs:199`, `:217` |
| `WEI_PER_NANO` | `stellereum/src/evm_adapter/types.rs:1308` |
| `eth_chainId` handler (EVM view) | `stellereum/src/rpc/eth.rs:801` |
| `eth_sendRawTransaction` handler | `stellereum/src/rpc/eth.rs:1117` |
| `stell_evmBindingSubmit` | `stellereum/src/rpc/eth.rs:1412` |
| `stell_getEvmBinding` | `stellereum/src/rpc/eth.rs:1339` |
| `stell_sendRawTransaction` | `stellereum/src/rpc/writes.rs:695` |
| `stell_getBalance` / `getBalanceSpv` | `stellereum/src/rpc/reads.rs:1518`, `:1531` |
| `stell_getTransactionReceipt` | `stellereum/src/rpc/reads.rs:1967` |
| `stell_getShardTopology` | `stellereum/src/rpc/reads.rs:1276` |
| `stell_baseFee` / `stell_estimateFee` | `stellereum/src/rpc/reads.rs:2549`, `:2553` |
| `DEFAULT_CHAIN_ID` | `stellereum/src/zkml.rs:217` |
| `CONSENSUS_RULESET_VERSION` | `stellereum/src/protocol.rs:101` |
| `FORK_ID` | `stellereum/src/protocol.rs:226` |
| `CHAIN_BINDING_ACTIVATION_HEIGHT` | `stellereum/src/chain_binding.rs:48` |
| `HardenedKeystore` | `stell-wallet/src/security.rs:92` |
| `KEYSTORE_VERSION` / KDF string | `stell-wallet/src/security.rs:22-23` |
| `compute_keystore_aad` | `stell-wallet/src/security.rs:33` |
| `HardenedKeystore::encrypt_with_scheme` | `stell-wallet/src/security.rs:126` |
| `HardenedKeystore::decrypt` | `stell-wallet/src/security.rs:190` |
| `HardenedKeystore::save` / `load` | `stell-wallet/src/security.rs:257`, `:297` |
| `Commands::Pay` / `Balance` / `Receive` / `Txs` | `stell-wallet/src/main.rs:143`, `:128`, `:121`, `:486` |
| `Commands::Session` / `Export` / `Restore` | `stell-wallet/src/main.rs:488`, `:579`, `:88` |
| `Commands::New` | `stell-wallet/src/main.rs:73` |
| CLI fee default | `stell-wallet/src/main.rs:2169-2172` |
| CLI bound-by-default | `stell-wallet/src/main.rs:2173-2204` |
| `LightClient::chain_id` / `nonce_of` / `reserve_nonce` | `stell-wallet/src/client.rs:285`, `:249`, `:273` |
| `LightClient::get_balance_spv` | `stell-wallet/src/client.rs:302` |
| `LightClient::broadcast_tx` | `stell-wallet/src/client.rs:373` |
| `LightClient::get_tx_history` | `stell-wallet/src/client.rs:230` |
| `TxRecord` | `stell-wallet/src/client.rs:67` |
| `rpc::send_raw_transaction` | `stell-wallet/src/rpc.rs:741` |
| `rpc::parse_receipt_status` | `stell-wallet/src/rpc.rs:753` |
| `SignRequest` / `SignResponse` / `SignErrorBody` | `stellereum-sdk/src/signer.rs:306`, `:312`, `:334` |
| `TxIntent` / `TxCommon` | `stellereum-sdk/src/signer.rs:130`, `:57` |
| `sign_request` | `stellereum-sdk/src/signer.rs:381` |
| `SignerServer` | `stellereum-sdk/src/signer_server.rs:24` |
| `POST /sign-digest` | `stellereum-sdk/src/signer_server.rs:176` |
| SDK `KeyFile` / container incompatibility | `stellereum-sdk/src/key.rs:18-28`, `:336` |
| `TxBuilder::effective_gas_limit` | `stellereum-sdk/src/tx.rs:629` |
| `sign_unsigned` | `stellereum-sdk/src/tx.rs:343` |
| `Mempool::NONCE_FUTURE_WINDOW` / TTLs | `stellereum/src/mempool.rs:784`, `:792`, `:802` |
| `apply_transaction` nonce gate | `stellereum/src/state_engine/apply.rs:1318` |

## Appendix B. What the implementation wave must add (ordered)

1. Reconcile `stell-wallet` with FULL-PQ (§0.3): delete classical arms, refuse
   non-Falcon keystores, compiles against HEAD.
2. Account derivation (§1.2), multi-account keystore metadata, canonical
   phrase handling (§1.1).
3. `connect` crate/module: deeplink parser, relay client, ML-KEM handshake,
   AEAD framing, request/response schemas, session store, rate limits.
4. Wallet-side intent decoder + policy engine + confirmation UI; wallet
   broadcast; receipt finality.
5. `signData` on top of `wallet_signing`; no digest/prepared kinds.
6. Export/import (encrypted keystore + seed + explicit SDK converter), seed
   backup verification flow.
7. Revocation: implement `SysCallRevokeSession` in the wallet or delete
   `aa revoke-session`.
8. EVM binding/carrier helper in the wallet for the MetaMask sidecar (the node
   API already exists; the wallet signs the two preimages).
9. Tests from §6 (existing ones stay green; new ones named above).
10. Docs: user-facing recovery/backup page, dApp integration page with the
    frame schemas and verification checklist.

No item in 1–10 is a consensus change. If any item ends up touching the
transaction preimage, envelope, address derivation, or signature framing, it
must be pulled out of this wave and scheduled as the wave's hard fork.
