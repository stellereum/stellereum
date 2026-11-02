# CLASSICAL CRYPTOGRAPHY INVENTORY — Stellereum FULL-PQ Repo

Scope: every use of quantum-breakable (Shor-breakable) cryptography: ECDH/ECDSA/EdDSA
(ed25519, secp256k1, X25519, P-256), pairings (BLS12-381), RSA/DSA/classical-DH,
class groups. NOT classical (excluded except this note): SHA-2/SHA-3/SHAKE/BLAKE3
hashes (Grover only — still fine), OS randomness (OsRng), AES/ChaCha/poly1305
(symmetric, fine at 256-bit), HMAC/TOTP (symmetric), Argon2id KDF.

Method: exhaustive `grep` over `Cargo.toml`/`Cargo.lock` + `stellereum/src` +
`infnode/crates` + `stell-wallet` + `stellereum-sdk`. Every row has file:line or it
didn't happen. Enforcement status read off `is_pure_pq_enforced()` call sites
(`STELL_PURE_PQ=1` / `--pure-pq`); where unclear after reading, marked NEEDS-RUNTIME-CHECK.

Headline counts (raw grep hits, comments included):
- `stellereum/src`: **774 hits across 43 files**
- `infnode/crates`: **99 hits**
- Classical crates in tree: `ed25519-dalek`, `x25519-dalek`, `curve25519-dalek`,
  `k256`, `bls12_381` (direct deps, stellereum/Cargo.toml:13-14,31,41,49);
  `ed25519-dalek`+`x25519-dalek` in infnode workspace (infnode/Cargo.toml:17,40;
  infnode/crates/infnode/Cargo.toml:14,32), stell-wallet (:21-22), sdk (:15).
- PQ KEM (ML-KEM/Kyber) anywhere in tree: **NONE** (grep empty). PQ sigs present:
  `falcon-rust` + `pqcrypto-falcon` (stellereum/Cargo.toml:51,55), ML-DSA-44 path
  (disabled at node, `PqScheme::from_id` refuses 0x03).
- TLS: infnode uses `rustls:0.23` + `ring` + `quinn` (QUIC) (infnode/Cargo.toml:21-29)
  plus `native-tls` (infnode/Cargo.toml:21) and `lettre … tokio1-rustls-tls`
  (infnode/Cargo.toml:22). TLS 1.3 key exchange via ring defaults = classical
  X25519 ECDH — **flagged classical, no hybrid-KEM option wired**.

Enforcement primitive: `stellereum/src/post_quantum.rs:71`
`is_pure_pq_enforced()` (env `STELL_PURE_PQ=1` / `--pure-pq`, override fns :48-56).
Files that consult it (the ONLY gated files): `consensus.rs`, `sharding.rs`,
`mempool.rs`, `state_engine.rs`, `runtime.rs`, `zkml.rs`, `rpc.rs`, `main.rs`,
`post_quantum.rs`. **Every classical use in any other file verifies even in
pure-PQ mode = HOLE.** infnode has NO pure-PQ mode at all — all its classical
use is HOLE by construction.

## Table (algorithm | file:line | purpose | PQ-enforced? | hole?)

### A. Dependencies (all live, all classical)
| alg | file:line | purpose | enforced? | hole? |
|---|---|---|---|---|
| ed25519 | stellereum/Cargo.toml:13 | vote/tx/wallet/contract signatures | per-callsite | — |
| X25519 | stellereum/Cargo.toml:14 | MEV DKG transport (mev_epoch) | NO | HOLE |
| curve25519 | stellereum/Cargo.toml:31 | Ristretto privacy, VRF field, stealth | NO | HOLE |
| BLS12-381 | stellereum/Cargo.toml:41 | aggregate QC certs (default OFF) | YES (refused) | no |
| secp256k1/k256 | stellereum/Cargo.toml:49 | EVM settlement ecrecover | YES (admission) | no* |
| ed25519/x25519 | infnode/Cargo.toml:17,40 | node identity, frame auth, E2E | NO (no gate exists) | HOLE |
| TLS-X25519/rustls/quinn/native-tls | infnode/Cargo.toml:21,22,25,28,29 | QUIC transport, SMTP | NO | HOLE |
| ed25519/curve25519 | stell-wallet/Cargo.toml:21,22 | wallet signing, stealth | NO | HOLE |
| ed25519 | stellereum-sdk/Cargo.toml:15 | SDK `ed25519()` key ctor (sdk/lib.rs:32,78) | caller picks | HOLE-by-default |

### B. Consensus core — PQ-ENFORCED (refuses classical when STELL_PURE_PQ=1)
| alg | file:line | purpose | enforced? | hole? |
|---|---|---|---|---|
| ed25519 | consensus.rs:18 (use), :1589-1598 `Vote::sign`, :1621 `signed_with` | vote signing (always ed-signs; falcon attached :1836) | sign side: NO (dual) | signing-side HOLE |
| ed25519 | consensus.rs:1642-1726 `Vote::verify` + batch (`verify_batch` :1726,:1778) | vote verification | YES (:1646,:1708,:1752 mirror audits) | no |
| ed25519+BLS | consensus.rs:2851-2852,2928,2956,3489,3515 | QC verify: classical arms refused in pure-PQ | YES | no |
| ed25519 | sharding.rs:13 (use), :2485-2692 `Transaction::sign*` (6 ctors) | tx signing (wallet path) | NO (creates classical by default) | HOLE (Phase-2 default) |
| ed25519/secp | sharding.rs:3355-3430 `verify_signature*` (:3407 EVM refused, :3416 non-PQ refused), :4025,:4128,:4150 batch | tx verification | YES | no |
| ed25519 | sharding.rs:3649-3660 `check_session_policy` | session-grant policy gate | YES | no |
| ed25519 | mempool.rs:1846 admission (`pure_pq_enforced` field :610) | mempool refuses classical | YES | no |
| ed25519/PQ/secp | state_engine.rs:113,155 attestation binds `pure_pq_enforced` flag; :50 skips re-verify only if flag matches | verify-once cache can't cross modes | YES | no |
| ed25519 | runtime.rs:509 `key`, :5805-5813 `sign_bytes` (always ed; remote-or-local), :5836 `make_vote` (+falcon attach) | block/vote signing | sign side: NO | signing-side HOLE |
| ed25519 | runtime.rs:1099 `falcon_signing_key` errors in pure-PQ w/o falcon key | fail-closed missing PQ key | YES | no |
| BLS12-381 | bls.rs:61-62 (use), :204-223 sign/verify, :331 aggregate | aggregate QC (opt-in) | YES: `STELL_BLS_QC=1` hard-refused at startup (bls.rs:546; caller main.rs:7576); default OFF (:501,:588) | no |
| ed25519 | post_quantum.rs:125-126,141,161,188,191,198,208,226 scheme table (`Ed25519=0x01`, `is_post_quantum()=false`); :537-561 dispatch, :554-561 `verify_ed25519` | dual-stack dispatcher | per-caller | no (needed) |
| ed25519 | wallet_signing.rs:32 (use), :259-484 sign/verify (scheme-explicit `WalletSigningKey::{Ed25519,Falcon,Hybrid}` :417-454) | wallet signatures | YES (via verifier gates) | no |
| ed25519→Falcon | rpc.rs:783,853 faucet (account :299 `key: SigningKey`, PQ key :~300) | faucet drips switch to Falcon in pure-PQ | YES | no |
| ed25519 | zkml.rs:845-935 `verify_signature` (:846 gate), :936+ session verify; policy mirror in sharding | session-key grants | YES | no |
| ed25519 | zkml.rs:432 `default_scheme()=Ed25519`, :497 legacy default pair, :646-647 | **serde-missing fields default to classical** | PARTIAL (verify gates, but defaults classical) | HOLE (Phase-2 default) |

### C. Consensus-adjacent — HOLES (classical verifies in pure-PQ mode)
| alg | file:line | purpose | enforced? | hole? |
|---|---|---|---|---|
| ed25519 | staking.rs:2477-2484 `get_pq_key` falls back to `Ed25519(validator_id)` | unregistered validator = classical key | NO | **HOLE** |
| ed25519 | staking.rs:2698-2730 equiv-evidence verify under fallback scheme | slashing verify | NO | **HOLE** |
| ed25519 | staking.rs:2317 `a.verify()\|\|b.verify()` in `slash_equivocation_verified` | vote-slash verify | NO | **HOLE** |
| ed25519 | consensus.rs:394-432 `verify_proposer_signature` → `block.verify_proposer_signature()` (ed fallthrough) | proposal-slash verify (called staking, svm :1070, consensus_net :3895) | NO | **HOLE** |
| ed25519 | svm.rs:1005-1070 PQ-equiv report w/ ed fallback (:1025) | on-chain report verify | NO | **HOLE** |
| ed25519 | remote_signer.rs:104-105 (use), :326,:426,:454,:530,:827,:933 sign fns; :880 HSM-GAP note (ed-ONLY) | validator remote/HSM signing | NO | **HOLE** (signing) |
| ECVRF/edwards25519 | vrf.rs:84-86 (use), :1359 `vrf_prove`, :1397 `vrf_verify`, :228,:479 seed from ed seed | committee election VRF (RFC 9381) | NO | **HOLE** |
| Ristretto/Schnorr | crypto_privacy.rs:8-11 (use), :213,:232,:237 sign, :242,:277,:282,:293 verify | confidential transfers + stealth auth (§9) | NO | **HOLE** |
| ed25519 | mev.rs:50 (use), :504-520 `commit_blind_round` sign, :596 verify, :691 `commit_block_order` | blind order commitments | NO | **HOLE** |
| ed25519+X25519-DH | mev_epoch.rs:70-78 (use); :1060,:1078,:1086 ed→x25519 conversion; :1257 `seal_transaction` (DH+XChaCha); :1334,:1351,:1405 partials; :1458 sign, :1480 verify | threshold-MEV DKG + order commitments | NO | **HOLE** |
| ed25519 | light_client.rs:146 (use), :582-615 `verify_validator_quorum` (`verify_strict`), :624 `sign_with` | light-client QC trust | NO | **HOLE** |
| secp256k1 | evm_adapter.rs:26 (k256 use), :799-807 `verify_secp_settlement` | EVM settlement ecrecover | PARTIAL (sharding :3407 refuses EVM env in pure-PQ; primitive unguarded, no external callers found) | no* |
| ed25519 | contract.rs:1377-1386 WASM host `ed25519_verify` precompile | contracts verify ed25519 on-chain | NO | **HOLE** |
| ed25519 | contract_source.rs:290-296 `verify_register_signature` | contract registration sig | NO | **HOLE** |
| ed25519 | oracle.rs:6 (use), :146 sign, :151-162 `verify`, :242 admit, :622 pull-verify | price-feed oracle auth | NO | **HOLE** |
| ed25519 | bridge.rs:18 (use), :564-582 `verify_quorum_signatures` (callers :793,:1368,:1606; adapters share helper per bridge_adapters.rs:19) | bridge quorum evidence | NO | **HOLE** |
| ed25519 | pq_registry.rs:594-604 `verify_rotation_announcement` (ed-signed PQ-key rotation) | rotation bootstrap | NO (by design) | KEEP — never remove |

### D. Wallet / SDK / RPC defaults — HOLES (Phase 2)
| alg | file:line | purpose | enforced? | hole? |
|---|---|---|---|---|
| ed25519 | wallet.rs:15 (use), :495-506 `from_seed`, :548-654 `create_*` (all `Transaction::sign`), :894,:925 pinned-ed leaves | wallet defaults to ed25519 accounts | NO | **HOLE (default)** |
| ed25519 | main.rs:6921,6969 CLI `--scheme ed25519 (default)`; :739-780 scheme loader; :823-843 validator keys load (identity.key) | operator default = classical | NO | **HOLE (default)** |
| ed25519+Ristretto | stell-wallet/src/client.rs:15 (use), :601-687 stealth send, :763-933 sign fns | wallet tx creation (incl. Schnorr-stealth) | NO | **HOLE** |
| ed25519 | stellereum-sdk/src/lib.rs:32,78-114 key ctors | SDK caller-picks-scheme | NO | default-risk |

### E. Node identity / discovery / transport — HOLES (Phase 3, blast radius largest)
| alg | file:line | purpose | enforced? | hole? |
|---|---|---|---|---|
| ed25519+X25519 | node_keys.rs:627-630 (seed→`SigningKey`+`StaticSecret`); :558 doc | node identity.key + e2e key files | NO | **HOLE** |
| ed25519+X25519 | dns_seeds.rs:113-115 `DiscoveredPeer{ed_pub,x_pub}`; :20 doc | DNS-TXT peer discovery pins classical keys | NO | **HOLE** |
| ed25519 cert | infnode/crates/infnode/src/node.rs:7080-7105 `build_tls` (PKCS8 ed → rcgen `PKCS_ED25519` self-signed, CN=`infnode-<edhex>`) | QUIC TLS identity | NO (no PQ mode) | **HOLE** |
| ed25519 | node.rs:7108-7182 `PinnedVerifier` (SPKI-pin + CN + self-sig; TLS1.3 verify via ring :7167-7181) | TLS peer auth | NO | **HOLE** |
| X25519 (TLS1.3 KEX) | quinn+rustls+ring (Cargo :21-29); ephemeral per-conn :1126 | QUIC key exchange = classical ECDH | NO | **HOLE** |
| ed25519 | proto.rs:2 (use), :246 `Frame::verify` (blake3-sign-then-verify) | EVERY overlay frame authenticated classically | NO | **HOLE** |
| X25519 ECDH | proto.rs:104 E2E KDF (`X25519(shared)+NodeIDs→blake3`); node.rs:6806-6870 proton box/unbox | E2E payload encryption | NO | **HOLE** |
| ed25519 | node.rs:1139 CHALLENGE; :1168,:1696,:1987,:6242,:6311,:6394 handshake/frame auth; :1968 sub-validator state-hash sign; :1267 main sign | handshake + authorship | NO | **HOLE** |
| ed25519+X25519 | keyring.rs:3,7 (use); :178-181 `id()=blake3(ed_pub)[..20]`; :257-263 from-seed | **PeerId/NodeId DERIVED from ed25519 key** | NO | **HOLE (identity)** |
| ed25519+X25519 | mailbox.rs:8,10 (use); :114-121 `MailKeys::sign/verify` | mailbox ownership proofs | NO | **HOLE** |
| ed25519 | reputation.rs:1,8-9 identity-keyed reputation; rewards.rs:250 `ed_pub` filter; config.rs:27-28,60-77 `node_id/ed_pub/x_pub` | identity-keyed policy | NO | **HOLE** |
| ed25519 | infmail: nft/lsb.rs:12,56 + nft/derive.rs:9,11 + web.rs:5598-5622 (TON proof), :6640-6649 (NFT verify) | NFT authenticity + TON auth + x25519-from-ed derivation (derive.rs:16-20 warns pub-derived x-priv is public-computable) | NO | **HOLE** |

### F. Test-only / dead-code (Phase-1 removal candidates — verify each before deleting)
`consensus.rs` :5132+,:6057+,:6149+,:6363+,:6394+ test mods (incl. :6944 classical-QC compat test — KEEP as compat pin or delete w/ path);
`sharding.rs` :5925+,:7111+,:7472+,:8153+; `state_engine.rs` :12001+; `mempool.rs` :2755+,:4351+;
`storage.rs` :3600+,:4664+; `sync.rs` :1863+,:2744+,:2848+; `staking.rs` :3394+; `contract.rs` :1714+;
`svm.rs` :3433+ (incl. :3680+ ed helpers); `runtime.rs` :8322+,:10604+; `network.rs` :3019+,:3224+,:3280+,:3602+,:3940+;
`consensus_net.rs` :2216+,:3655+ (+:2221 use); `light_client.rs` :2081+ (:2389-2390,2594 Ristretto/signer fixtures);
`mev.rs` :757+; `mev_epoch.rs` :2352+; `vrf.rs` :1586+; `crypto_privacy.rs` :1670+,:2039+; `wallet.rs` :980+;
`bridge.rs` :2184+; `contract_source.rs` :314+; `address.rs` :200+ (:342,344-358 ed-addr tests);
`commitment.rs` :1916+ (ALL its ed hits — zero production hits); `chain.rs` :1008+; `simulator.rs` :1642+
(`derive_keypair` :313 production helper for devnets — Phase 1 w/ blast note); `parallel_exec.rs` :312+;
`xshard2pc.rs` :495+; `node_keys.rs` :696+; `dns_seeds.rs` :753+; `zkml.rs` :1926+; `native_api.rs` :3084+;
`rpc.rs` :7550+,:7557+,:7570+,:7580+,:8515+; `zkml_attestation.rs:11` (doc: "no pairings" — prose, no code);
`consensus_net.rs:2780,3840,3887-3889` prose/docs; `bls.rs` whole-file if BLS path deleted (see Phase 1);
infnode `tests/` (frame_fuzz, p2p_audit :404-405, accept_hardening :164-165, reputation :469-470 — eph X25519 fixtures).

## Ranked removal plan

### Phase 1 — test-only + dead code + docs (no consensus/wire impact)
1. Delete/gate classical fixtures in `#[cfg(test)]` mods (list in §F). Blast: none (test-only). Keep ONE compat pin
   (consensus.rs:6944 `test_backward_compatibility_classical_ed25519_qc`) until the ed QC path itself is deleted.
2. Delete BLS QC code (`bls.rs`, `bls_path_power`, `attach_legacy_micro_certificate`, VOTE_BLS_MAGIC envelope)
   now that `STELL_BLS_QC=1` is startup-refused (bls.rs:546, main.rs:7576) and default-OFF. Blast: none while refused;
   removes pairing attack surface + the "re-enable" temptation. KEEP the refusal gate until deletion lands.
3. Scrub classical-by-default doc strings/examples (native_api.rs:2381-2382 `"Ed25519"` examples,
   consensus_net.rs prose, wallet `create_*` docs preferring unbound). Blast: none.
4. `simulator.rs:313 derive_keypair` + devnet genesis scripts minting ed keys → PQ equivalents. Blast: low, but
   touches live-demo tooling — coordinate with demo runbooks first.

### Phase 2 — non-consensus paths: wallet/RPC defaults, gates on app-layer verifiers
5. CLI + wallet defaults → PQ: `main.rs:6921,6969` `--scheme` default `ed25519`→`falcon` (or `hybrid`);
   `wallet.rs:505 from_seed` PQ-first constructors; stell-wallet `client.rs` + sdk docs. Blast: medium — breaks
   operator scripts/wallet files assuming ed25519; needs migration note + dual-sign transition flag.
6. Gate app-layer verifiers on pure-PQ (mirroring zkml.rs:846): `contract.rs:1377` precompile,
   `contract_source.rs:290`, `oracle.rs:151` (+:242 admit), `bridge.rs:564`. Each needs a PQ-key story first
   (PQ oracle publisher keys, PQ bridge validator set, contract allowlist). Blast: medium — oracle/bridge
   operators must rotate keys; contracts using the precompile break under pure-PQ until migrated.
7. `zkml.rs:432,497` serde defaults: require explicit schemes (fail-closed) instead of silent Ed25519.
   Blast: low-medium — old serialized grants without scheme fields stop parsing; version the envelope.
8. `light_client.rs:582` `verify_validator_quorum`: refuse classical-only quorums in pure-PQ (+ checkpoint
   anchoring). Blast: medium — light clients must ship PQ keys; old checkpoints unverifiable in strict mode.

### Phase 3 — consensus / transport / identity (flag-day class, largest blast radius)
9. Vote/QC ed path: `runtime.rs:5805 sign_bytes` always ed-signs (dual-stack); `consensus.rs` ed verify arms;
   `staking.rs:2477` fallback + `staking.rs:2317,2698` + `consensus.rs:394` slash paths; `svm.rs:1025` fallback.
   Removal = ed-free votes + PQ-only slashing; fallback deletion changes slashing verdicts for unregistered keys.
   Blast: HIGH — consensus fork unless flag-gated by height/activation like the VRF rollout.
10. `remote_signer.rs` ed-only (+:880 HSM gap): add Falcon/Hybrid remote-signing before deleting ed path.
    Blast: HIGH — validator HSM integrations re-key.
11. VRF `vrf.rs:1359,1397` (ECVRF-Edwards25519) → PQ sortition/VRF. The `vrf_output_for_cert` legacy-draw fallback
    (consensus.rs:1098-1133) keeps mixed nets alive today. Blast: HIGHEST — leader/committee election changes.
12. Privacy `crypto_privacy.rs` (Ristretto Pedersen/stealth/Schnorr) + `mev.rs`/`mev_epoch.rs` (ed sigs + X25519 DH DKG)
    → PQ confidential + PQ DKG. Blast: HIGH — shielded balances + MEV pipeline re-ceremony.
13. secp256k1 EVM settlement (`evm_adapter.rs:799`, k256 :26): PQ settlement auth or drop EVM-settlement path
    (currently admission-gated sharding.rs:3407 — safe while gated). Blast: HIGH — EVM bridge compatibility.
14. Node identity + transport (infnode, no PQ mode exists): `keyring.rs:178` NodeId-from-ed, `node.rs:7080`
    ed TLS certs, `proto.rs:246` frame auth, X25519 KEX+E2E (`proto.rs:104`, `node.rs:6849`), `mailbox.rs:114`,
    `dns_seeds.rs:113` ed+x records, infmail NFT/TON ed paths. Requires: PQ node keys, PQ-TLS (ML-KEM hybrid KEX +
    PQ certs), PQ frame signatures, new NodeId derivation, DNS record version bump. Blast: HIGHEST — every
    `node.yaml`, peer pin, `inf1:` id, DNS TXT, and stored mail key changes = coordinated flag day.

## MUST NEVER be removed yet (with reasons)
- `post_quantum.rs:554 verify_ed25519` arm + `PqScheme::Ed25519` id: dual-stack verification + `Hybrid`'s ed half
  + `pq_registry.rs:594 verify_rotation_announcement` alias depend on it. Removing breaks Hybrid and rotation.
- `pq_registry.rs:594-604` ed-signed rotation announcements: rotation must survive PQ-key compromise; a validator
  with no PQ key yet can only announce via its consensus (ed) key. Replace ONLY with an equally compromise-resilient
  mechanism (e.g. multi-grant ceremony), never bare deletion.
- Consensus legacy-draw/VRF-missing fallbacks (`consensus.rs:1098-1133`, `vrf_output_for_cert` matrix): mixed-version
  nets fork without them. Remove only after a height-gated PQ-election activation proves universal.
- `staking.rs:2477` ed fallback + slash ed paths: deleting before every validator registers a PQ key bricks
  slashing for unregistered validators (equivocation goes unpunishable). Gate on registry coverage metrics first.
- BLS startup-refusal (`bls.rs:546`, `main.rs:7576`) + default-OFF: keep until BLS code is actually deleted (Phase-1
  item 2); the gate is the only thing making BLS safe today.
- Existing `identity.key` format / `inf1:` NodeIds / DNS TXT `ed`/`x` fields / pinned TLS SPKIs on live nodes:
  identity rotation = flag day; inventory first, ceremony second.
- `sharding.rs:3407` EVM-in-pure-PQ refusal + `mempool.rs:1846` + `state_engine.rs:113,155` flag-binding: these ARE the
  enforcement. Touch only to strengthen.
- Test compat pin `consensus.rs:6944` (classical QC verifies unchanged): keep until the ed QC path is deleted, so
  deletion is a deliberate, reviewed step.

## PQ-first appendix (2026-11-02, append-only — no rows changed above)

- `stellereum/src/simulator.rs` `derive_keypair` (§F / Phase-1 item 4) now
  has PQ-first companions sharing the SAME caller seeds: `derive_pq_seed`
  (domain `STELLEREUM_SIM_PQ_KEY_V1`) + `derive_falcon_keypair` (production
  `FalconKeypair::generate_from_seed_bytes`, deterministic, no OS
  randomness). The Ed25519 `derive_keypair` itself is byte-identical, so all
  simulator addresses, state roots, and existing examples are unchanged.
  Documented PQ-first in `docs/SIMULATOR.md` §6.
