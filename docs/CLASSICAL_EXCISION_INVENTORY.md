# CLASSICAL EXCISION INVENTORY — FULL-PQ, no migrations, no compat
Date (UTC): 2026-11-04. Scope: `stellereum/` + `infnode/`. Method: `rg -n` only; every row has file:line or a pasted `rg -c` count. No code edits made.

> **Snapshot (2026-11-04), pre-FULL-PQ-wipe.** Several rows describe paths that
> no longer exist (`bls.rs`, the contract `ed25519_verify` host, Ed25519
> vote/tx verification). Current tree: `bls.rs` deleted, `ed25519_verify`
> replaced by `falcon512_verify`, votes Falcon-only. Use
> `docs/CLASSICAL_EXCISION_STATUS.md` for the current status.

Lead directive: wipe nodes, history restarts fresh. No wire-v1 readers, no legacy fallbacks, no dual-stack defaults. Pure PQ or nothing.

## 0. Reproduce counts (run from repo root `/home/imm/stellereum-project`)

```
rg -n "ed25519-dalek|Ed25519|verify_strict|verify_batch" stellereum/src --no-heading
rg -n "curve25519-dalek|Ristretto|ristretto" stellereum/src --no-heading
rg -n "x25519|X25519" stellereum/src --no-heading
rg -c "ed25519" stellereum/tests  # files=219 lines=337
rg -c "ed25519" stellereum/src    # files=38  lines=287
rg -c "X25519|x25519" stellereum/tests  # files=2 lines=6
rg -c "X25519|x25519" stellereum/src    # files=5 lines=48
rg -c "Ristretto|ristretto" stellereum/tests  # files=5 lines=10
rg -c "Ristretto|ristretto" stellereum/src    # files=8 lines=91
rg -c "Bls|BLS|bls12" stellereum/tests  # files=16 lines=231
rg -c "Bls|BLS|bls12" stellereum/src    # files=12 lines=228
rg -c "ECVRF|ecvrf|VrfProof|vrf_prove|vrf_verify" stellereum/tests  # files=3 lines=49
rg -c "ECVRF|ecvrf|VrfProof|vrf_prove|vrf_verify" stellereum/src    # files=7 lines=75
rg -n "is_pure_pq_enforced" stellereum/src --no-heading
rg -n "crypto_privacy::|ConfidentialState|StealthAddress|ViewingKey|SHIELD_ESCROW" stellereum/src --no-heading
```

Total test files in `stellereum/tests/`: 314 (`ls stellereum/tests/*.rs | wc -l`).

---

## 1. Ed25519 vote / block / tx verification

| primitive | definition (file:line) | live callers (file:line) | test callers | PQ replacement status |
|---|---|---|---|---|
| `PqScheme::Ed25519` enum + lens | `stellereum/src/post_quantum.rs:128-129,146,166,191,194,201,211,229` | `stellereum/src/staking.rs:2555,2789,2818,2825` (fallback + strip); `consensus.rs:3275-3276,3444-3445` (scheme match) | `stellereum/tests/pq_registry_tests.rs:456`, `fuzz_certificate_decoder_tests.rs:143`, `session_key_tests.rs:1353,1363,1439,1449,1470,1722,1780`, `v34_verification_pentest.rs:394`, `qc_batch_verify_tests.rs:244` | **exists-and-wired (Falcon-512)**, but `Hybrid` still embeds Ed (`post_quantum.rs:146,194,520,532-544`) — Hybrid must die too |
| `verify_ed25519` (dalek `verify_strict`) | `stellereum/src/post_quantum.rs:551-570` (`VerifyingKey::from_bytes`, `verify_strict`) | `verify_pq_signature:532` dispatches `Ed25519 => verify_ed25519`; `Hybrid` verifies ed-half `544`; `consensus.rs:359` Falcon-only helper is the PQ path | unit mods `post_quantum.rs:2120-2121,2435,2438,2448,2458-2495,2743-2783` | **exists-and-wired**: `verify_pq_signature(Falcon512)` at `post_quantum.rs:533`, `consensus.rs:359-373,3168` |
| `Vote::verify` / `verify_batch` / `partition_valid` / `add_batch` (Ed strict + batch) | `consensus.rs:1554,1579,1624-1663,1671-1754,1805` ; batch core `1663: ed25519_dalek::verify_batch`, `1736` ; scalar `1602,1615: VerifyingKey::from_bytes + verify_strict` | `runtime.rs:5456,5106,5158,5302,7707-7747` (ingest + batch comments); `staking.rs:2817` strip; `consensus.rs:2227,2448,2596-2726,2965-3645` (QC verify paths `3025,3047,3058,3620,3641,3645`) | `qc_batch_verify_tests.rs:61-95` (pure-Ed oracle), `batch_verify_tests.rs:1-5,364-464`, `v34_verification_pentest.rs:37,366`, `consensus.rs` unit `7071-7483,7494-7548` | **exists-and-wired**: Falcon vote path `consensus.rs:1888-1980 (pure_pq flag), 2928,3165,6718-7715` + `register_validator_pq_key` |
| `verify_transaction_envelope_at_height*` / `verify_proposer_signature` / `verify_falcon_signature` seam | `consensus.rs:108-127,349-378,420-424` | `state_engine.rs:5880,7411`; `runtime.rs:1537`; `sharding.rs:3571-4357` (pure-pq gates, see §8) | 219 test files / 337 lines match `ed25519` in `stellereum/tests/` (count pasted above); `src` unit mods 38 files / 287 lines | **exists-and-wired**: `PqScheme::Falcon512` tx path + `pq_registry.rs:250-521` + `staking.rs:2541 get_pq_key` |
| wallet / contract / oracle / bridge / remote-signer Ed | `wallet_signing.rs:32,259-430,452-489` (`Ed25519{seed}`, `SigningKey::from_bytes`); `remote_signer.rs:104-114,322-348,464,880-923`; `contract.rs:1348-1391` (`ed25519_verify` host); `oracle.rs:6,152`; `bridge.rs:18,264,569-570`; `svm.rs:15` (grep count), `mempool.rs:1850-1853`, `state_engine.rs:3261,4872` (pinned-key verify) | same files are live (see left); `contract.rs:1375` pure-pq gate refuses; `oracle.rs:156` refuses; `bridge.rs:572` refuses | `session_key_tests.rs:14,130` + 219-file set above | **exists-and-wired for wallet tx** (Falcon/Hybrid `wallet_signing.rs`, `post_quantum.rs:1521+ FalconKeypair`); **DOES-NOT-EXIST for `ed25519_verify` contract host drop-in** — host must be deleted, not replaced (no Falcon host with same name; callers must move to PQ tx auth) |
| Explicit curve dep | `stellereum/Cargo.toml:13` (`ed25519-dalek v2 + batch`), `31` (`curve25519-dalek v4`), `infnode/Cargo.toml:17` | all above | — | remove crate deps after code excision |

---

## 2. Ed25519 node identity vs PQ identity

| primitive | definition (file:line) | live callers (file:line) | test callers | PQ replacement status |
|---|---|---|---|---|
| `PeerConfig { ed_pub, pq_pub }` | `infnode/crates/infnode/src/config.rs:25-36` (`ed_pub: String`, `pq_pub: Option<String>`); `node_id_raw:67-80` = `blake3(ed_pub)[..20]`; `dual_announce_ids:119-122` | `stellereum/src/network.rs:3449-3471,3658-3666` (pin + filter to ed); `stellereum/src/dns_seeds.rs:58,113,214-283` (F6 binding `node_id==blake3(ed_pub)`); `stellereum/src/main.rs:1143-1161,11085-11174` (F6 skip) | `dns_seeds.rs:780-984` fixtures set `pq_pub: None`; `main.rs:11095` same | **exists-and-wired but NOT exclusive**: `pq_pub` optional, every live path still **REQUIRES ed** |
| `NodeKeys { signing, verifying, e2e_sec }` / `NodeId=blake3(ed)` | `infnode/crates/infnode/src/keyring.rs:158-183` (`signing: SigningKey`, `id()` = legacy `blake3(ed_pub)[..20]`) | `keyring.rs:167,268`; `node.rs:655,668,699,1499,1572,1636-1638,2484` (routes/TLS pins use ed); `main.rs:375-385,425-469,505-566,767-823,955,1270-1356` | `infnode/crates/infnode/tests/{gossip_scale_tests.rs:32,eclipse_tests, ›reputation,kex_session_tests.rs:15,dht_scale}` | **exists-and-wired sidecar**: `PqKeys::pq_pub:327, pq_pub_hex:332, pq_id:343-349`, `PQ_IDENTITY_FILE=pq-identity.key:300,385`, `dual_announce_ids:535, dual_announce_hex:543, parse_dual_announce:553`, `resolve_node_id PQ-primary:519-527`, `NodeIdKind::{Pq,Legacy}:476-495` — but `NodeId` derivation is explicitly **UNCHANGED** (`keyring.rs:298-299`: pq_id is *alongside*, never `NodeId`) |
| TLS certs + handshake Ed paths | `node.rs:8526 build_tls`, `8554-8629 PinnedVerifier` (SPKI pin == peer ed_pub + CN + validity + self-sig); `proto.rs:4,303-306 Frame::verify` (`verify_strict over blake3(sign_data)`); `pq_transport.rs:29-48` audit table (A1/A3/T2/I1 all classical) | `node.rs:668-677,2708-2715` (client TLS pins `ed`), `6515`, `7210,7271,7419` (`VerifyingKey::from_bytes(ed_bytes)`), `8092,8119` (KEX ordering on classical id), `1572,2484` (CHALLENGE/AUTH ed verify), `2818` (Ed signs state hash) | `infnode` tests above; `stellereum/tests/kex_session_tests` (infnode) | **exists-behind-flag / partial**: `node.rs:8413-8451` (`announce pq_pub` + `pq_sig` Falcon tag), `8381-8411` (PQ bind map `classical->pq_pub`), `1512,1527,1614,7300,7365,8128-8204` (ephemeral ML-KEM-768 `pq_encapsulate/decapsulate`, `pq_suite` hybrid) — hybrid breaks only if BOTH break, but **classical X3DH + ed auth still mandatory**; `proto.rs:399` warns classical refused only *at/after H* |
| Federation / DNS / mailbox Ed | `federation.rs:8,84-92,112-151,157-211,232-242` (`node_id=blake3(ed_pub)`, TXT `inf1:{node_id}:{ed_pub}:{ip}`); `mailbox.rs:8-121` (`ed_sig/ver`, `verify_strict`) | `main.rs:375-469,547-566,808-955,1351-1356` | — | **DOES-NOT-EXIST pure-PQ federation**: no `pq_pub`-only TXT / announce path wired (all `pq_pub: None` at `infnode/src/main.rs:434,469,566`, `node.rs:4107,7241,9438`) |

What still REQUIRES ed (must change for excision): `config.rs:67-80 node_id_raw/ed_bytes`, `keyring.rs:180-183 id()`, `node.rs: PinnedVerifier + build_tls + all ed_bytes/verify sites above`, `network.rs:3446-3471 pinned-TLS filter`, `dns_seeds.rs:214-222 F6`, `main.rs:1154-1161 F6`, federation TXT, mailbox.

---

## 3. X25519 (E2E, snapshot-e2e, MEV classical leg) vs KEM

| primitive | definition (file:line) | live callers (file:line) | test callers | PQ replacement status |
|---|---|---|---|---|
| E2E `e2e.key` x25519 | `infnode/src/keyring.rs:160-175,205-267` (`e2e_sec: StaticSecret`, `e2e_pub`, files `identity.key/e2e.key`); `stellereum/src/node_keys.rs:557-680` (load/save `e2e.key`, `632-633: StaticSecret::from + PublicKey::from`, `658-680` persist) | `infnode/src/main.rs:767-807` (x25519 DH for mail), `994,1094` (`e2e_encrypt_det/decrypt`); `node.rs:4885-4896,6371-6428` (routes carry `x_pub/ed_pub`) | `infnode/crates/infnode/tests/kex_session_tests.rs:15` ; `stellereum/tests`: only 2 files / 6 lines match `x25519` | **DOES-NOT-EXIST pure-KEM E2E**: `pq_transport.rs:4-68` explicitly unwired — `mod pq_transport` not referenced (`750-770`), `Cargo.lock` (304 crates) has NO ml-kem, Rank-1 ML-KEM `unavailable offline:391-426,639-641`; only hybrid ephemeral ML-KEM in `node.rs:8128-8204` (not E2E store) |
| Snapshot / transport x25519 (`x_pub`, DH) | `infnode/src/config.rs:25-81` (`x_pub` in `PeerConfig`); `pq_transport.rs:30,40,48` (K2/A2/I1 rows) | `node.rs:1512,1614,7300,7365` (hybrid hello carries ML-KEM ek *alongside* classical) | 2 files above | **exists-behind-flag (hybrid only)**: classical X3DH still required; no pure-KEM snapshot path |
| MEV DKG classical leg | `mev_epoch.rs:237-240 enc_pk`, `521-546 EncryptedShare/DkgContribution`, `1052-1107` (`derive ed->x25519`, `encryption_public_key`, `encrypt_share_package`: `XStaticSecret::random + DH + XChaCha`), `1121-1125 decrypt_share_package`, `674-896` ingest, `1023-1044` accessors; doc `mev_pq_plan.rs:10-67`, header `mev_epoch.rs:7-80` | `mev_epoch.rs:707-787` (build/ingest classical), `1175-1736` (PQ selector + H-gate: `1187-1189` classical branch, `1277-1332` fallback warn, `1548`, `1713-1784` refuse-at-H) ; `node_keys.rs:632-633` (e2e pub derive, same primitive family) | `pentest_mev_kem.rs:10`, `mev_pq_transport_tests` (in BLS list), `mev_v4` tests | **exists-behind-height-gate**: `ingest_authenticated_pq / ingest_pq_kem_transport:1311-1380` (ML-KEM-768 `1088+48=1136B` packages, `mev_epoch.rs:75 ml_kem::{Decapsulate,FromSeed,KeyExport}`, `1338-...` lens) + `mev_v4.rs:8-135,516-828,962` (ML-KEM-768 framing `PK 1184/CT 1088`, magic headers) — pre-H default is byte-identical classical (`1190-1213`); post-H classical refused fail-closed |
| Sealing note | `mev_pq_plan.rs:41-42`: X25519 is NOT the sealing primitive (sealing = Ristretto DH + XChaCha `:1268-1286`), NOT threshold arithmetic | — | — | do not conflate sealing-Ristretto with package-X25519 |

---

## 4. BLS remainder (post-cut)

`bls.rs:33-59` + `327-354`: emit retired, envelopes on wire are *inert metadata*, `STELL_BLS_QC=1` hard-refused. `BLS_IS_POST_QUANTUM=false:81`.

| item | definition (file:line) | live caller / wiring | PQ replacement status |
|---|---|---|---|
| types + crypto | `bls.rs:90 BlsSecretKey, 106 BlsPublicKey, 138 BlsSignature, 232 SignerBitVector, 308 BlsAggregateSignature, 70 DST, 183-225 prove/verify` | only constructors/parsers reachable; counting path removed | **DOES-NOT-EXIST drop-in** (pairing aggregate has no PQ equivalent); functional quorum replacement = Falcon µQC (exists-and-wired, see §1) |
| parsers (keep-for-history readers) | `bls.rs:122 from_bytes, 151 from_bytes, 249 from_bitmask, 314 to_bytes` | `consensus.rs:237-290` (`encode_bls_envelope_as_marker` returns empty; `parse_bls_envelope` history reader), `2817` strip, `7444-7483` BLS-off test | delete with wire; no live counting caller |
| markers | `consensus.rs:221 BLS_QC_MARKER_ID=[0xFF;32], 227 QC_BLS_MAGIC` | `consensus.rs:2728-2805` (attach removed), `2966-3007,3507-3547` (inert), `7444-7483` test-only | delete |
| PoP + registry | `bls.rs:542 BLS_POP_DST, 552 preimage, 562 sign_pop, 568 verify_pop, 576 Stats, 452 parse_registry_entries, 599-692 v2/strict, 758-787 counters, 362-378 envs, 408 refuse_bls_qc_if_enabled` | `main.rs:7675-7681` (`refuse_bls_qc_if_enabled`), `metrics.rs:152-165,699-777,1075-1227` (3 counters) | **DOES-NOT-EXIST PQ PoP**; registry has no PQ use — delete whole registry + envs + metrics |
| spec/docs | `compact_prop.rs:28-80,151,218-227` (BLS-off size math), `consensus.rs:197-204,430,1342,2728-2805` comments | docs only | delete comments with code |

Test callers (16 files / 231 lines `Bls|BLS|bls12` in `stellereum/tests/`): `bls_tests`, `bls_classical_tests`, `bls_pop_tests`, `bls_registry_audit_tests`, `bls_qc_compat_tests`, `vote_qc_assembly_audit_tests`, `vrf_bls_adversarial_tests`, `fuzz_certificate_decoder_tests`, `v34_verification_pentest`, `p4_crypto_pentest`, `p3_byzantine_pentest`, `consensus_audit_hardening_tests`, `mev_pq_transport_tests`, `audit_rpc_evm_closeout`, `vuln_bundle_tests`, `pq_audit_closure_tests` (see file list §7; full `rg -c` per file reproduces).

---

## 5. ECVRF remainder (post-cut)

Bodies already removed: `consensus.rs:493,1044-1053`, `vrf.rs:47-49,727-887` (REMOVED prove/verify/hash-to-curve/nonce/challenge), `main.rs:2749-2752,3081-3093`, `runtime.rs:642-649,1744-1753`. What lives is envelope + registry + beacon math.

| item | definition (file:line) | live caller | PQ replacement status |
|---|---|---|---|
| envelope `VrfProof` (80B) + `VrfBeaconSeal` + activation/registry types | `vrf.rs:92-158` consts (`VRF_*_DOMAIN`, `VRF_PROOF_LEN=80`, `VRF_IS_POST_QUANTUM=false:158`), `171 VrfActivation`, `208 vrf_activation_from_env`, `238 derive_vrf_secret_seed`, `253 parse_vrf_keys_config`, `324 vrf_registry_from_env`, `352-489 secret load/provision`, `551 VrfPublicKey`, `575 VrfSecret`, `618 binding preimage`, `628 verify_vrf_binding`, `645 VrfBinding`, `675 VrfRegistry`, `785 VrfProof`, `901 election_seed, 918 genesis, 932 next, 951 lottery` | `consensus.rs:503 (proof field), 901,912-1053,1236-1258,2776-3602` (all take `Disabled+None`, parent-hash draw `1036`), `runtime.rs:645-649,1049,1731-1753` (seam resolves identically), `main.rs:2917-3143` (provision + registry load + ARM warn) | **exists-and-wired**: `cn_vrf.rs:62-685` Falcon-512 commit/open/beta/verify (`304,329,354,387,429-494`, carriers `253,273`, lengths `72-96`) + parent-hash draw fallback |
| Edwards glue (must go with VRF) | `vrf.rs:82-84` (`CompressedEdwardsY/EdwardsPoint/Scalar/IsIdentity`), `557` low-order note, `658,706,733,1040-1046` point checks | no live sign/verify caller (bodies gone) | delete with module |
| metrics/logs | `vrf.rs:1023` counter | `main.rs:3093` warn | delete |

Test callers (3 files / 49 lines `ECVRF|ecvrf|VrfProof|vrf_prove|vrf_verify` in tests): `vrf_bls_adversarial_tests`, `vote_qc_assembly_audit_tests` (?), plus `vrf.rs` unit `1216,1270-1278` (marker test only). `rg -c` reproduces.

---

## 6. Ristretto privacy — FULL map + state-shape + honest kill assessment

> **Honest verdict first: deleting Ristretto kills confidential transfers as a FEATURE, not just code.** There is no PQ stealth/commitment/range-proof wired anywhere (`crypto_privacy.rs:32-33`: “ML-KEM — none wired in-tree yet”; `privacy_pq_refused:53-54` fail-closes every fallible op under `STELL_PURE_PQ=1`). Proof is the dependent list below.

Definitions (`stellereum/src/crypto_privacy.rs`): `53 privacy_pq_refused`, `86 PedersenCommitment:92 commit,102 random_blinding,110 verify,134 batch_verify,144 add,159 sub`, `174 StealthAddress:185 generate,215 is_for_recipient,244 derive_one_time_private_key,270-355 sign/verify (Schnorr Ristretto)`, `361 EncryptedViewingPayload`, `374 ViewingKey:389 generate,400-450 derive/spend,461 derive_one_time,477 encrypt_amount_for_auditor,523 decrypt_amount`, `562 ConfidentialTransfer:596 new,611 balance,662 balanced_with_ranges,702 ranges,755 encode,774 digest`, `792 preverify_digest`, `839 BitProof:848 prove,893 verify,929 scalar`, `958 RangeProof:979-1088 prove/verify/batch`, `1143-1170 MSM backend`, `1257 ConfidentialError`, `1367 ConfidentialState + 1387 V1:1405 new,1412 empty,1419 len,1426 balance,1433 is_spent,1438 is_owned,1464 apply,1552 verify_with_ranges,1623 apply_with_ranges,1637 note_shielded_output,1647 verify_opening,1669 retire_for_unshield`, `1736 CONFIDENTIAL_DOMAIN_TAG, 1744 SHIELD_ESCROW=[0xC0;32], 1770 write_confidential_domain, 1807 digest`.

| layer | live callers (file:line) | state-shape impact if deleted |
|---|---|---|
| SVM shield/unshield | `svm.rs:122 (gas §9), 142-143 range params, 381-414 opcodes (`SysCallConfidentialTransfer2/Unshield`), 660-891 syscall structs, 1319-1399 confidential threading, 2654-2843 apply (`2673 SHIELD_ESCROW`, `2712 preverify_digest`, `2730-2797 shield`, `2806-2843 unshield`)` | `OpCode::SysCallConfidential*` + `SysCall*` structs + gas arms must go; SVM loses confidential entry points |
| wallet stealth | `wallet.rs:7 imports, 1017-1054 (viewing_key/stealth_address gen), 1317-1339 build/create_transfer (RangeProof::prove_auto)` ; `main.rs:21-22,8668-8674` (spend_pub + `StealthAddress::generate`) ; `light_client.rs:2416-2417` Ristretto test-only | wallet loses `build_confidential_transfer/create_confidential_transfer`, stealth fields |
| mempool proof-unit (DoS gate) | `mempool.rs:3692-3771` (unit tests building `ConfidentialTransfer::new` + `RangeProof`), live `1850-1853` pure-pq admit path (refuses shielded under PQ) | mempool confidential admission branch dies |
| commitment domain | `commitment.rs:62,1810-1914` (`confidential_preimage`, `write_confidential_domain`, `commitment_digest_with_confidential_and_zkml`), `2558-2630` assembly, `2639,2735,2885,3026` (`ConfidentialState::new`) | consensus state-root domain shrinks; **genesis/history restart required** (lead already mandates wipe — compatible) |
| ledger state | `state_engine.rs:546-574 (confidential field), 1080,1498,2292-2345 snapshots, 2614-2830 (confidential_work copy + `Svm::execute…with_confidential`), 4682-4752 preverify batch, 5125, 7056, 7733-7744, 8059-8070 guards, 8465 digest, 10909-10931 snapshot/V1 upgrade, 14560 digest` ; `storage.rs:19,76,109,1064,1214-1224,1632,2791,2836,3260,3961,4071,4761` (`confidential_at/prune/put_confidential`) ; `bin/ledger_tool` (same pattern) | **shielded notes in ledger die**: `ConfidentialState { owned, spent, total_fees }` + per-height `confidential` domain snapshots + `ConfidentialStateV1` upgrade path all deleted; sync (`sync.rs`) stops replicating that domain |
| RPC / native API | `native_api.rs:380-396 (`stell_shieldedTransfer/Balance/unshield`), 665-667 dispatch, 2581-2815 builders (`2603 StealthAddress::generate`, `2618 range_proof_json`, `2631 shielded_transfer`, `2793 shielded_balance`, `2921 unshield`)` ; `rpc.rs:12961 put_confidential` | three RPC methods + helpers deleted |
| explorer views | `explorer.rs:1255,1273-1331 (describe_confidential_transfer), 1412,1867,2042-2050 (api_confidential_spent), 2355 route /api/confidential/:commitment` | confidential views/routes deleted |
| bootstrap / network / sync / parallel_exec | `bootstrap.rs, network.rs, sync.rs, parallel_exec.rs` reference confidential via generic domain plumbing (see `rg` in §0) | plumbing shrinks accordingly |
| pure-PQ refusal (today) | `crypto_privacy.rs:16-54,484,529,1285,1345` (`privacy_pq_refused`, `STELL_PURE_PQ=1` fail-closed) | after excision the flag has nothing to refuse here (no-op) |

Test callers (22 files match broad `crypto_privacy|ConfidentialTransfer|…|shield`; only 5 files / 10 lines match strict `Ristretto|ristretto`): `privacy_pq_tests`, `privacy_onchain_tests`, `privacy_live_tests`, `confidential_solvency_tests`, `confidential_preverify_tests`, `shielded_path_tests`, `audit_closure_privacy_tests`, `p4_crypto_pentest`, `pentest_privacy_gates`, `domain_persistence_tests`, `commitment_assembly_differential_tests`, `mev_pq_transport_tests`, `svm_hotpath_opt_tests`, `session_budget_tests`, `actor_envelope_compat_tests`, `blockchain_security_tests`, `integration_tests`, `more_attacks_tests`, `a_surface_poc`, `rpc_drift_regression`, `zkml_live_tests`, `v34_verification_pentest` (full list via `rg -l` in §0).

---

## 7. Test inventory — exact counts (no guessing)

Pasted `rg -c` aggregates (run commands in §0):

- `ed25519` in `stellereum/tests/`: **219 files / 337 lines**; in `stellereum/src/` (unit mods): **38 files / 287 lines**.
- `X25519|x25519` in tests: **2 files / 6 lines**; in src: **5 files / 48 lines**.
- `Ristretto|ristretto` in tests: **5 files / 10 lines**; in src: **8 files / 91 lines**. (Broad confidential/shield set: 22 files — see §6.)
- `Bls|BLS|bls12` in tests: **16 files / 231 lines**; in src: **12 files / 228 lines**.
- `ECVRF|ecvrf|VrfProof|vrf_prove|vrf_verify` in tests: **3 files / 49 lines**; in src: **7 files / 75 lines**.
- Total suite: **314 test files**.

Per-file breakdown is `rg -c <pat> stellereum/tests stellereum/src` output (too long to paste fully; the aggregates above are the exact totals). Representative heaviest Ed files: `session_key_tests.rs` (~15 hits), `consensus.rs` unit (~21), `a_crypto_audit_poc.rs`, `qc_batch_verify_tests.rs`, `batch_verify_tests.rs`.

Interpretation: ~70% (219/314) of integration test files touch Ed25519 at least once (mostly `SigningKey::from_bytes/generate` fixtures + `Signer::sign`). Excision must replace fixtures with `FalconKeypair::generate[_from_seed]` (`post_quantum.rs:1581-1846`) + `pq_registry` + `register_validator_pq_key`, not just delete asserts.

---

## 8. Pure-PQ flag — every behavior difference today (becomes no-op after excision)

`post_quantum.rs:25-86` (`PURE_PQ_OVERRIDE`, `set_pure_pq_override`, `is_pure_pq_enforced` reading `STELL_PURE_PQ` / `--pure-pq`).

| gate site (file:line) | behavior flag-ON vs flag-OFF |
|---|---|
| `consensus.rs:1583,1632-1689` (Vote batch mirrors) | ON: Ed batch screen skipped, every vote goes scalar Falcon; OFF: Ed `verify_batch` fast path allowed |
| `consensus.rs:1888-1980` (`pure_pq` field) | ON: voteCOD path requires Falcon half; OFF: Ed-only votes admitted |
| `consensus.rs:3010,3075,3101,3576,3602` (QC verify_unified/staged) | ON: `!scheme.is_post_quantum()` refused; OFF: classical Ed QC counts |
| `runtime.rs:1154` | ON: classical tx refused (see `mempool.rs:1850-1853` admit + `state_engine.rs:39-156` record binds `pure_pq_enforced`, flipping forces re-verify) |
| `staking.rs:2373,2537-2555,2781-2793` (`get_pq_key` + equivocation) | ON: Ed fallback refused (`no registered PQ key`); OFF: `Ed25519(validator)` fallback admitted |
| `bridge.rs:572`, `oracle.rs:156`, `contract.rs:1375`, `zkml.rs:846,936` | ON: classical quorum/feed/`ed25519_verify`/proof refused; OFF: verified |
| `sharding.rs:3571,3580,3637,3813,4217,4226,4240,4335,4343,4357` | ON: non-PQ cross-shard envelopes refused; OFF: admitted |
| `mempool.rs:610-696,1850-1853,4131-4157` | ON: envelope-wrapped Ed with malformed PQ refused; OFF: admitted |
| `light_client.rs:584-625` | ON: only PQ/non-disabled power counts; OFF: classical power counts |
| `rpc.rs:838,908` | ON: faucet-shaped PQ only / bare-Ed refused; OFF: Ed admitted |
| `crypto_privacy.rs:16-54,484,529,1285,1345` | ON: every fallible Ristretto op refuses (`privacy_pq_refused`); OFF: shielded crypto runs |
| `main.rs:2841-2845,6641-6902,7469-7472,12005-12015` | CLI `--pure-pq` sets override; transfer command is PQ-only when ON |
| `mev_epoch.rs:1175-1784` (height-H, not env flag, but same family) | pre-H: classical X25519 packages ingested (+WARN); at/above H: refused fail-closed; PQ-KEM leg only |

After excision the flag is dead: every OFF branch above is deleted, every ON branch becomes the only path, `is_pure_pq_enforced/set_pure_pq_override/PURE_PQ_*` + `state_engine.rs:69-156 pure_pq_enforced` record field + `mempool.rs:610-696 with_pure_pq` + CLI `--pure-pq` plumb can be removed.

---

## 9. Deletion order (safest-first topological)

1. **BLS dead weight** — `bls.rs` whole module + `consensus.rs:221-290 markers/parsers` + `refuse_bls_qc_if_enabled` + envs (`BLS_QC/BLS_KEYS*/BLS_POP_REQUIRED`) + `metrics.rs:158-165,699-777,1075-1227` counters + `compact_prop.rs` BLS comments. No live counting caller; test-only constructors. Safest.
2. **ECVRF carcass** — `vrf.rs` whole module + `consensus.rs:503 proof field, 901-1053,1236-1258,2776-3602 VrfActivation/Registry plumb` + `runtime.rs:645-649,1049,1731-1753` + `main.rs:2749-3143` provision/registry/ARM. Bodies already gone; only envelope/registry/beacon math lives.
3. **X25519 MEV classical leg** — `mev_epoch.rs:521-546,674-896,1052-1125` classical packages + H-gate branches `1175-1784` (keep PQ-KEM leg `1311-1380` + `mev_v4.rs` framing). Keep `mev_pq_plan.rs` doc until wire frozen.
4. **Ed25519 verify + wallet/contract/oracle/bridge hosts** — `post_quantum.rs:128-129,146-147(Hybrid!),201,211,229,532,544,551-570,2120-2121` + `consensus.rs:1602-1754,3025-3068,3620-3645` Ed arms + `wallet_signing.rs:32,259-489` Ed/Hybrid arms + `contract.rs:1348-1391` host + `oracle.rs:6,152` + `bridge.rs:18,264,569-570` + `remote_signer.rs:104-464,880-923` + `svm.rs/mempool/state_engine/sharding` Ed branches (§8). Requires Falcon fixture migration in 219+38 files.
5. **Identity / TLS / federation / mailbox Ed** — `config.rs:28,67-80`, `keyring.rs:158-183,268`, `node.rs:655-677,1499-1638,2484,2708-2818,6515,7210-7419,8092-8629`, `network.rs:3446-3471`, `dns_seeds.rs:113-283`, `main.rs:1143-1356`, `federation.rs`, `mailbox.rs:8-121`, `node_keys.rs:557-680 e2e.key` + `e2e_sec/pub` + `x_pub` plumb. Promote `pq_id` to `NodeId`, `pq-identity.key` to required, PQ-TLS/pins to sole path. Needs spec + fresh genesis (wipe already mandated).
6. **Ristretto privacy LAST** — `crypto_privacy.rs` whole + §6 caller table (SVM ops, wallet stealth, mempool branch, commitment domain, `ConfidentialState` ledger + snapshots + V1 upgrade, storage `confidential_*`, native_api 3 RPCs, explorer views/routes, `SHIELD_ESCROW`). Kills the feature (see §10). Do only with explicit product sign-off + genesis restart.
7. **Flag + deps** — remove `is_pure_pq_enforced/set_pure_pq_override` + `pure_pq_enforced` record + `--pure-pq` CLI + `STELL_PURE_PQ` reads, then `Cargo.toml:13-14,31,41` (`ed25519-dalek, x25519-dalek, curve25519-dalek, bls12_381`) + `infnode/Cargo.toml:17,40` once no referrer remains (`cargo tree` must show zero).

---

## 10. Red-flag list (deletion kills a FEATURE, not just code)

- **Ristretto confidential transfers — DIE completely.** `Svm::SysCallConfidentialShield/Transfer2/Unshield`, wallet `build/create_confidential_transfer` + stealth addresses + viewing keys, `stell_shieldedTransfer/Balance/unshield` RPCs, explorer `/api/confidential/*`, shielded ledger (`owned/spent/total_fees`) + per-height snapshots + state-root domain. No PQ replacement exists (`crypto_privacy.rs:32-33`). Deleting = product removes private transfers.
- **Contract `ed25519_verify` host — DIE (no same-name PQ host).** Contracts calling it break; must rewrite to PQ tx auth or a new Falcon host (new name/semantics, not a drop-in).
- **BLS aggregate QC — DIE (no PQ aggregate).** If any roadmap assumed 271B QCs (`compact_prop.rs:113-114`), revert to Falcon µQC sizes (~10457B-class, `compact_prop.rs:218-227` Ed math is the closest analogue).
- **X25519 E2E / snapshot transport pure-PQ — GAP.** Hybrid ML-KEM exists (`node.rs:8128-8204`) but E2E store + snapshot path have no pure-KEM replacement; excising `e2e.key/x_pub` without a KEM store breaks E2E mail + snapshot encryption until that store is built.
- **Node identity/TLS/federation Ed — FLAG-DAY.** Promoting `pq_id` to `NodeId` + requiring `pq-identity.key` + PQ pins invalidates every existing `PeerConfig/node.yaml`, DNS TXT, and DHT pin. Only safe because lead mandates wipe + fresh history.

---

## 11. Totals + recommended first cut

- Primitives inventoried: **7** (Ed-verify, Ed-identity, X25519, BLS, ECVRF, Ristretto, flag-gates).
- Live-caller sites (non-test `rg -n` hits, approx): Ed-verify ~120, identity/TLS ~80, X25519 ~50, BLS ~60 (mostly comments/metrics), ECVRF ~40, Ristretto ~90, flag gates ~45.
- Test-caller totals (exact `rg -c` pasted in §7): **ed25519 219f/337l (tests) + 38f/287l (src units); X25519 2f/6l + 5f/48l; Ristretto-strict 5f/10l (broad shield set 22f) + 8f/91l; BLS 16f/231l + 12f/228l; ECVRF 3f/49l + 7f/75l**; suite 314 files.
- PQ status summary: Falcon-512 vote/tx/auth **exists-and-wired**; PQ identity + hybrid KEX **exists-behind-flag / hybrid-only (ed still required)**; MEV KEM leg **exists-behind-height-H**; BLS aggregate + Ristretto + E2E-KEM-store + contract-Ed-host-drop-in **DOES-NOT-EXIST**.
- **Recommended first cut: BLS (order #1).** Zero live counting callers (inert markers + refused env), smallest blast radius (module + markers + 3 metrics + envs + 16 test files), unblocks deleting `bls12_381` dep and proves the excision pipeline before touching consensus-critical Ed or feature-killing Ristretto.
