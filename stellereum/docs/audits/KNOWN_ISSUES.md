# KNOWN ISSUES — every known defect and every deferred feature

> **This is the document an auditor should read first.** It says, in one
> place, where the code is known to be weak, what the weakness costs, and who
> can pull the trigger. Everything here was read out of the tree — the
> `//!` headers, the `audit …` comments, the `deferred` / `TODO` markers and
> the `report_*` tests — not out of an audit report.
>
> **Exploitability vocabulary**
>
> | Tag | Who can trigger it |
> | --- | --- |
> | `REMOTE` | any unauthenticated peer that can reach the RPC or the P2P transport |
> | `VALIDATOR` | a validator that holds stake (or a quorum of them) |
> | `OPERATOR` | the node's operator (configuration, disk, deployment) |
> | `LOCAL` | only a process running on the node's own host |
>
> **Severity**
> `CRITICAL` (funds or consensus safety) → `HIGH` → `MEDIUM` → `LOW` (liveness,
> ergonomics, hardening) → `INFO` (a fact about the design, not a defect).
>
> **Anchor.** `file:line` plus the symbol; the symbol is the contract. See
> [`EXTERNAL_AUDIT_BRIEF.md`](EXTERNAL_AUDIT_BRIEF.md) §1 and §9 for the tree
> fingerprint this revision was read from (`4d0d539`, `9df243678628fa7d →
> 855bbc10fab92c46`, 2026-10-30) and the repro run that backs every
> "closed" claim below.
>
> **Nothing in this file is a to-do for the audit-prep work.** Other agents
> own the fixes; this package only records them. Items verified fixed in code
> *and* green in the repro run are moved out to §M (closed), not deleted, so
> the history stays readable.

---

## A. Cryptography

### KI-01 — ML-DSA-44 (scheme `0x03`) is **not real FIPS-204**

| | |
| --- | --- |
| **Severity** | CRITICAL *if the scheme is ever enabled*; INFO **as shipped** |
| **File** | `src/post_quantum.rs` — `verify_mldsa44` (≈ line 2326), `PqScheme::from_id` (≈ line 159), `PqScheme::is_disabled` |
| **Exploitability** | `REMOTE` (once enabled) — anyone holding the public key can forge a valid signature |
| **Status** | **Mitigated fail-closed, not fixed.** `from_id(3)` returns `Err`, `verify_pq_signature` returns `false`, and the variant is kept only so every `match` over `PqScheme` stays exhaustive. Every byte-driven admission path (envelope decode, session-grant decode, SVM opcode dispatch, storage reads) refuses `0x03` at parse time. |

The in-tree verifier is a home-grown "norm window + self-computed trailer"
construction, not the FIPS-204 algorithm. The code says so itself:

> *"the scheme MUST NOT verify … Re-enable ONLY behind a real FIPS-204
> implementation + coordinated all-validators upgrade."* — `src/post_quantum.rs`

**Audit action:** confirm that no code path can reach `verify_mldsa44` with a
non-refusing result, and confirm the upgrade procedure (a hard fork) is
documented.

---

### KI-02 — The legacy Falcon-512 key path had ~32 bits of effective entropy — **REMOVED 2026-11-04**

| | |
| --- | --- |
| **Severity** | Was CRITICAL for a key derived through this path; now **NONE on this vector** |
| **File** | `src/post_quantum.rs` — the *only* seed derivation left is `generate_from_seed_bytes` (`src/post_quantum.rs:1803`), full-entropy via `FALCON512_KEYGEN_V5` + `falcon512_keygen`; `grep src/` for `generate_from_seed_bytes_legacy`, `STELL_LEGACY_GENESIS_ROOT`, `warn_legacy_weak_entropy` returns **0 hits** |
| **Exploitability** | none — there is no legacy derivation left to observe or enumerate |
| **Status** | **REMOVED, not "open by design".** Commit `03bba5120` (2026-11-03, `stellereum/src/post_quantum.rs`: 9 insertions, 247 deletions) deleted: `generate_from_seed_bytes_legacy`, `warn_legacy_weak_entropy_key_once` (with its `LEGACY_WEAK_WARNED` static, the `tracing::error!` and the stderr `[ERROR]`), and the `STELL_LEGACY_GENESIS_ROOT=1` gate in the Falcon key derivation. The `≈ line 1626 / 1927` pointers below are pre-removal and no longer resolve. What below describes the *deleted* path is kept as history. |

The (deleted) legacy derivation was an automorphic image of the Falcon reference base
key: the 32-byte seed only picked `k ∈ {1,3,…,1023} × shift_f ∈ [0,1024) ×
shift_g ∈ [0,1024) × flags ∈ {neg_f, neg_g, swap}` — at most `2^32` distinct
keys, i.e. ~32 bits of effective entropy, **not 256**.

**Residual risk: NONE on this vector, stated plainly.** Setting
`STELL_LEGACY_GENESIS_ROOT=1` changes nothing — pinned by
`tests/a_crypto_audit_poc.rs:150` ("escape hatch changes NOTHING",
`:163-169`) and `tests/genesis_guard_tests.rs:60,74`. Not to be confused
with KI-03: the pre-FIPS-206 *on-disk NTRU repair* path
(`warn_legacy_ntru_key_once`, `src/post_quantum.rs:1473`; `rotate-falcon`,
`src/node_keys.rs:486`) is a different, live mechanism.

**Audit action:** ~~verify that no *live* deployment still runs with
`STELL_LEGACY_GENESIS_ROOT=1`, and that the rotation command is covered~~ —
superseded; confirm the three symbols are still absent from `src/`.

---

### KI-03 — Pre-FIPS-206 Falcon keys on disk are incomplete NTRU keys

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **File** | `src/post_quantum.rs` — the W6.1 repair path (≈ line 1464), `warn_legacy_ntru_key_once` (≈ line 1559) |
| **Exploitability** | `OPERATOR` / `LOCAL` — the signing path *refuses* a key with no NTRU partner `G`, so the key cannot sign; the **address is unchanged**, so a still-running legacy key keeps its identity |
| **Status** | Open by design (backward compatibility). The repair path reconstructs `G` when it can and refuses when it cannot. |

---

### KI-04 — BLS is real, but **off** on the deployed chain

| | |
| --- | --- |
| **Severity** | INFO (bandwidth, not safety) |
| **File** | `src/bls.rs` — `qc_bls_enabled` (≈ line 687); `src/consensus.rs` QC path |
| **Exploitability** | none |
| **Status** | The certificate path still produces Ed25519 signatures by default. The BLS12-381 pairing code (`e(sig,G1) == e(H(m),pk)`) is genuine and unit-tested; it is simply not the default. The `SignerBitVector` is mandatory because `apply_downtime_slashes` derives the signer set from `cert.signatures` — that derivation breaks the moment signatures aggregate, so the bitvector is load-bearing, not decoration. |

---

### KI-05 — The confidential pool has **no RingCT**: the sender is always visible

| | |
| --- | --- |
| **Severity** | MEDIUM (a design limit, not a bug) |
| **File** | `src/crypto_privacy.rs`; `src/svm.rs` |
| **Exploitability** | `REMOTE` (passive observer) |
| **Status** | Open by design. The sender of a shielded transfer is always public (`tx.from` + nonce + the public gas payment). Only the **amount** is hidden, and the **recipient** only behind a fresh one-time stealth address. There is no anonymity, and the passport explicitly forbids RingCT. |

The confidentiality is *selective* and is enabled per-transaction; the
default is transparent.

---

### KI-06 — A bare `apply_transfer` call is still reachable by a direct pool caller

| | |
| --- | --- |
| **Severity** | MEDIUM (latent) |
| **File** | `src/crypto_privacy.rs` — `apply_transfer` (the equation-only path) vs `apply_transfer_with_ranges` |
| **Exploitability** | `REMOTE` **only if** a new call site reaches the bare method |
| **Status** | Open by design; the method's own docs forbid it as a solvency gate. The live SVM handler runs `verify_balanced_with_ranges` before `apply_transfer` in the same synchronous handler, so the two-step verdict is identical to the atomic call. The hardening precondition (switching the handler to the single atomic call) is deferred by **one line** and lives in `src/svm.rs`. |

**Audit action:** grep every call site of `apply_transfer` and confirm each is
either the ranged wrapper or an explicitly-approved path.

---

## B. Consensus

### KI-07 — The sortition committee is **grindable**

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **File** | `src/consensus.rs` — `sortition_seed` (≈ line 826), `derive_sortition_committee` (≈ line 747) |
| **Exploitability** | `VALIDATOR` (a proposer) |
| **Status** | Open, structurally mitigated. The parent block hash is in the preimage (`STELL_SORTITION_V5`), so a committee is unknowable until its parent exists and a fork re-elects a different committee — but the parent hash is **not unforgeable**: the proposer of the parent block chooses the parent's bytes, hence its hash, hence the next committee, and can search for a favourable draw. |

Grinding only picks **which** honest validators are asked to sign; it cannot
manufacture the stake. The network-anchored quorum
(`max(floor(2·W_committee/3)+1, floor(W_network/2)+1)`) is what keeps the bar
high. A VRF-based selection is the structural fix and is out of scope.

---

### KI-08 — Equivocation evidence is **locally observed**

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **File** | `src/runtime.rs` — `apply_equivocation_slashes`; `src/consensus.rs` (evidence recording) |
| **Exploitability** | `VALIDATOR` |
| **Status** | Open, stated plainly in `PROTOCOL.md`. A node that was catching up observed nothing, so it cannot punish an equivocation it never saw. Full parity needs the evidence **shipped with the commit certificate** — a wire change, not a stricter local check. |

---

### KI-09 — A restarted node resumes a **stale round** — **MITIGATED**

| | |
| --- | --- |
| **Severity** | MEDIUM (liveness) |
| **File** | `src/storage.rs:1995` `ConsensusCheckpoint.round`; restore `src/main.rs:3449-3490`; breaker `src/consensus.rs:3855,4999` + `src/main.rs:6395-6477`; re-phase window `src/consensus.rs:3885`; drain `src/storage.rs:3488` + `src/main.rs:7975`; heal `src/main.rs:3516` |
| **Exploitability** | `OPERATOR` |
| **Status** | **Mitigated — automatic recovery, no wipe.** The "coordinated wipe of both data directories" below is superseded: four mechanisms, landed after this entry was written, cover the deadlocked-after-restart case. (1) **Capped restore** (`src/main.rs:3466-3468`): the persisted round is restored as `min(cp.round, MAX_RESTORED_ROUND=64)` while the lock is honoured unconditionally — safety kept, runaway view-change rounds (e.g. r806 vs r0, the exact stand incident named in the comment) capped back into convergence range. (2) **Bounded forward-only deadlock breaker** (`src/consensus.rs:3855` bound, `:4999` `deadlock_breaker_target`; `src/main.rs:6413`): after `STELL_DEADLOCK_TIMEOUT_SECS` (default 300) without finalization with verified peers ahead, one jump to max(peer rounds), once per window. (3) **Local re-phase with no peer ahead** (`src/main.rs:6423-6477`; `REPHASE_SCAN_WINDOW = 4096`, `src/consensus.rs:3885`; applied `:5174-5175`): advances the round (never rewinds — re-vote would be self-equivocation), widens the quorum-scan window, drops only a bodyless lock. (4) **Shutdown persist drain** (`wait_for_persist_drain`, `src/storage.rs:3488`, called `src/main.rs:7975`) plus **heal-to-head** (`heal_engine_to_head`, `src/main.rs:3516` — refuses to vote from unproven state, exit(1) over a fork) shrink the crash window that produces a stale checkpoint in the first place. Pins: `tests/consensus_rephase_tests.rs::rephase_widens_the_scan_window_and_never_rewinds`, `::rephase_lets_a_stuck_node_commit_the_quorum_the_network_formed`, `::rephase_is_idempotent_per_height`, `::rephase_never_touches_height_decided_or_the_qc`, `::breaker_closes_a_gap_larger_than_the_vote_acceptance_window`, `::breaker_needs_a_second_peer_to_corroborate_the_round`; `tests/deadlock_breaker_tests.rs::two_nodes_with_1200_round_desync_converge_without_restart`, `::breaker_fires_with_empty_peer_set`, `::breaker_never_moves_height_backward`. |

**Precise residual:** recovery is time-bounded, not instant — the breaker fires only after the 300 s no-finalization timeout (rate-limited to once per window), and the peer-ahead jump requires a corroborating second peer, so a two-node partition with unverified/empty peer rounds converges via the slower local re-phase path; further, conflicting *bodyful* locks at the same height are never dropped (safety half does not expire), so a partition that locked conflicting values still needs a quorum to unlock rather than converging bilaterally.

---

### KI-10 — The BLS/µQC decoder accepts a **non-canonical encoding** (deliberate)

| | |
| --- | --- |
| **Severity** | LOW |
| **File** | `src/consensus.rs` — the bincode fallback at the end of `decode_pq_micro_envelope` (≈ line 931, "Audit-consensus F9 … KEPT deliberately") |
| **Exploitability** | `REMOTE` (CPU only) |
| **Status** | Accepted. The fallback lets a peer make the decoder do a second parse; `verify_micro_cert` re-checks everything load-bearing (bitmask length, trailing-bit zero, out-of-range signer bits, per-signature fail-closed verify, power quorum), so a non-canonical blob can decode but never **verify** unless it names a real quorum. |

---

### KI-11 — `bincode` decoders accept **trailing bytes**

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **File** | `src/consensus_net.rs` (`ConsensusMsg::decode` uses `allow_trailing_bytes`); `src/consensus.rs`; `src/sharding.rs` |
| **Exploitability** | `REMOTE` |
| **Status** | Open and **documented by a test**: `tests/fuzz_decoder_tests.rs::report_trailing_bytes_are_accepted_by_bincode_decoders`. The same logical vote/transaction/block therefore has more than one valid byte form, which defeats any byte-based dedup or replay filter derived from the envelope bytes. Callers must not assume "decoded Ok" means "the input was exactly one message". |

---

### KI-12 — An **all-zero** peer payload decodes as a valid message

| | |
| --- | --- |
| **Severity** | LOW |
| **File** | `src/consensus_net.rs` — `ConsensusMsg::decode` |
| **Exploitability** | `REMOTE` |
| **Status** | Open, contained by downstream checks. An all-zero blob is a valid bincode encoding of `Proposal { height: 0, round: 0, .. }` with empty vectors. The impact is contained only because the height/proposer/signature checks reject it. **Any future decode-without-verify path would treat a zero blob as a live height-0 proposal.** Documented by `tests/fuzz_decoder_tests.rs::report_all_zero_payloads_decode_as_valid_messages`. |

---

### KI-13 — The validator set **cannot be derived at a historical height**

| | |
| --- | --- |
| **Severity** | LOW |
| **File** | `src/sync.rs` — `TODO(F5)` (line 592); `src/runtime.rs` — `TODO(F5)` (line 5232) |
| **Exploitability** | none directly (a historical-proof limitation) |
| **Status** | Open. The set-at-height is not derivable from the staking ledger as the chain is walked. |

---

### KI-14 — There is **no observer role** in the validator-set builder

| | |
| --- | --- |
| **Severity** | LOW (documented operational convention) |
| **File** | `src/consensus.rs` — `build_validator_set` |
| **Exploitability** | `OPERATOR` |
| **Status** | Open, and partly superseded: the *runtime* now has a fail-closed **observer** arm for a stale ledger (`src/runtime.rs`, "fail-closed to observer (no votes)"), but `build_validator_set` still always includes the local key, so a node cannot be configured as a pure observer at the set level. The config convention is "`validators:` lists the **others**". |

---

## C. Execution & state

### KI-15 — The commitment is **recomputed on every root read**

| | |
| --- | --- |
| **Severity** | LOW (performance / amplification) |
| **File** | `src/state_engine.rs` — `get_state_root`; `src/commitment.rs` |
| **Exploitability** | `REMOTE` (a peer that makes the node read the root often pays O(state) each time) |
| **Status** | Open by design: correctness first, optimisation later. The alternative (committing at each mutation site) is how the original gap opened — dozens of sites, each of which had to remember. |

---

### KI-16 — **Archive state is not committed per key**

| | |
| --- | --- |
| **Severity** | LOW |
| **File** | `src/commitment.rs` |
| **Exploitability** | none directly |
| **Status** | Partially closed. Per-key archive proofs now exist for every trie-resident slot (account leaves, STS balance/supply cells, contract code/ABI, the commitment digest leaf), served from the persisted snapshot history and authenticated by the anchoring block's QC (`stell_getArchiveProof` / `stell_getHistoricalRoot`, `PROTOCOL.md` §5.4). Still digest-only by design: the non-trie subsystems folded into the commitment digest (staking entries, orderbook levels, contract storage, ...) have no per-key proof — making them provable needs per-entry trie keys (P3, see D-02). |

---

### KI-17 — The **cross-shard commitment is not per-shard**

| | |
| --- | --- |
| **Severity** | MEDIUM in a multi-shard deployment; none in a single-shard one |
| **File** | `src/sharding.rs`, `src/xshard2pc.rs` (domain `XSHARD_REPLAY_V1`) |
| **Exploitability** | `OPERATOR` |
| **Status** | Open by design. The domain commits the replay sets of the whole **process**, so two shards of one process share one root rather than one root each. |

---

### KI-18 — The light client is **live**, and its trust anchor is the whole point

| | |
| --- | --- |
| **Severity** | MEDIUM (a design-level trust statement, not a defect) |
| **File** | `src/light_client.rs` (module header: "# LIVE (audit W8.3 / production blocker A10)"); `src/sync.rs:50` `verify_synced_blocks_against_anchor`; `src/light_client_cli.rs` |
| **Exploitability** | `REMOTE` for the *anchor* (a peer cannot forge a quorum certificate, but it CAN feed the node a chain the anchor does not cover) |
| **Status** | **Closed as a gap, open as a trust statement.** The light client is no longer a dead library: the node keeps one anchored at its own finalized head, every block it accepts from a peer during a sync is routed through `sync::verify_synced_blocks_against_anchor` (a peer chain is accepted only if it extends a quorum-certified anchor), the node serves its anchor and its finalized headers over RPC (`stell_getFinalizedCheckpoint`, `stell_getFinalizedHeader`), and `stellereum light-client --from <rpc> --verify <account>` is the external verifier. |

**What an auditor must not miss.** The light client does **not** remove the
trust assumption; it *relocates* it and makes it explicit:

* the **validator set is the entire trust anchor**. A light client that takes
  its validator set from the server it is verifying has no anchor at all, so
  the CLI **requires** an out-of-band set (`--validators`);
* the anchor is a **quorum certificate on a finalized header**, so a proof is
  only as good as the quorum that finalized the header it is checked against;
* the node still serves *its own* view: it can lie about a state it was never
  told about. The light client turns "the node says this root" into "a quorum
  committed to this root", which is a real improvement — and the residual
  (a quorum that finalized a wrong state) is a consensus problem, not a
  light-client problem.

**Audit action:** the interesting question is no longer "is it wired in?" but
"is the anchor's verification exactly as strict as the consensus path's?" —
i.e. does `verify_synced_blocks_against_anchor` apply the same quorum rules
as `consensus::ValidatorSet::quorum_power`, and can a peer steer the node
onto a chain that *does* extend the anchor but is not the canonical one?

---

## D. Networking & RPC

### KI-19 — The **RPC token** is the only gate on the write surface

| | |
| --- | --- |
| **Severity** | MEDIUM (deployment-dependent) |
| **File** | `src/rpc.rs` — `RpcState::auth_token` (≈ line 153); gates: `stell_mempoolDump` (fail-closed without a token), the signed-payload arms `stell_submitPriceFeed` / `stell_pmmBuy` / `stell_pmmSell` and `stell_deployContract` / `stell_callContract` (open when unset, require the token when set), the governance writes `stell_submitProposal` / `stell_vote` / `stell_executeProposal` (require the token when set; without a token: loopback bind stays open for dev, non-loopback bind refuses fail-closed), the SIGN arms `stell_signMessage` / `stell_signTypedData` (fail-closed without a token, loopback-only, dev key required); `stell_sendRawTransaction` / `eth_sendRawTransaction` stay OPEN by design. Token source `STELL_RPC_AUTH_TOKEN` (`src/main.rs`) |
| **Exploitability** | `REMOTE` |
| **Status** | Open by design: the token is **optional**. Without it, only `stell_mempoolDump` and the SIGN arms fail closed; the payload/contract arms stay open, and the governance writes stay open on a loopback bind while refusing on a non-loopback bind. A deployment that publishes the RPC port without a token therefore still exposes the open arms to anyone who can reach the port. The faucet has its own separate token (`STELL_FAUCET_TOKEN`) and refuses to dispense without it. |

**Audit action:** confirm the operator runbook requires `STELL_RPC_AUTH_TOKEN`
on a public deployment and that the RPC port is not exposed.

---

### KI-20 — Plaintext **legacy node keys** still load

| | |
| --- | --- |
| **Severity** | MEDIUM (operator hygiene) |
| **File** | `src/node_keys.rs` — `load_node_keys` / `load_or_generate_node_keys`; `ENV_PLAINTEXT` (`STELL_KEY_PLAINTEXT=1`) |
| **Exploitability** | `LOCAL` (read access to the key file) |
| **Status** | Open by design (backward compatibility). An **existing** plaintext key still loads and is transparently re-encrypted in place as soon as a passphrase is available. A **new** key is refused to be written without a passphrase. An **encrypted** key without a passphrase is a hard error (the node refuses to start). |

---

### KI-21 — Full block bodies are published on a **best-effort cadence**

| | |
| --- | --- |
| **Severity** | LOW (liveness) |
| **File** | `src/network.rs` (retro-publish pass), `src/main.rs` |
| **Exploitability** | `OPERATOR` |
| **Status** | Open. `broadcast_block` is called at genesis and the head pointer on every finalize, but bodies rely on the retro-publish pass (bounded, every 30 s, 128 per pass, 4096 deep). A node further behind than that depth cannot catch up from this node. |

---

### KI-22 — The `stell_estimateFee` budget is **per-IP**, not per-identity

| | |
| --- | --- |
| **Severity** | LOW |
| **File** | `src/rpc.rs` — `ESTIMATE_FEE_RATE_LIMIT_DEFAULT` (line 974), `STANDALONE_RATE_LIMIT_DEFAULT` (line 6530) |
| **Exploitability** | `REMOTE` (a distributed flood) |
| **Status** | Open. The per-IP budget is 5/s for `stell_estimateFee` and 300/s for the standalone RPC, with a 5,000,000-gas ceiling on the estimate. A distributed flood is not bounded by the per-IP budget. |

---

## E. Governance & economics

### KI-23 — Governance actions have **no timelock**

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **File** | `src/governance.rs` — the `NOTE (E5): no timelock by deferred design decision` comments (≈ lines 906 and 953) |
| **Exploitability** | `VALIDATOR` (a voting majority) |
| **Status** | Open by deferred design decision. A passed proposal executes immediately. There is a voting period (3 days) and a quorum, but no delay between "passed" and "executed". |

---

### KI-24 — The governance upgrade action's path safety is **code**, and the live migration is **disarmed by default**

| | |
| --- | --- |
| **Severity** | LOW |
| **File** | `src/governance.rs` (`upgrade_name_is_safe`, `upgrade_candidate_paths`, `stage_verified_upgrade_binary`, `auto_upgrade_armed`), `src/main.rs` (the exec site), `docs/OPERATIONS.md` §12 |
| **Exploitability** | `VALIDATOR` (a voting majority) + `OPERATOR` (the exec) |
| **Status** | **Closed as a code gap.** The staging + hashing before the exec is no longer procedure — it is `governance::stage_verified_upgrade_binary`, called by the exec site, and the properties the W6.7 re-audit asked for are enforced there and pinned by tests: a **path-traversal** name resolves to NO candidate path (`upgrade_candidate_paths` returns an empty list), a **symlinked candidate** and a **symlinked parent directory** are refused, a digest **mismatch** is refused, and the **TOCTOU** window is closed because the file that is EXECUTED is a private (0700) staged COPY of the bytes that were HASHED. |

**The arming is now operator-local, and the default is the safe one.** The live
`execve` of a new binary happens only when the operator has explicitly set
`STELL_AUTO_UPGRADE=1` (`true`) **on that node**; unset — the default — leaves
the live migration DISARMED, and the node halts at the upgrade height with
**exit code 42** (Cosmovisor-compatible) for the supervisor to restart. A typo
(`0`, `false`, `yes`, `2`, …) fails SAFE. When the switch IS armed the node
prints a banner on stderr and a `WARN` log line at start-up, so "why did my
node replace its own binary?" is answerable from the log.

**Audit action:** confirm the arming is still opt-in (the default must stay
OFF), that the banner is printed, and that the exit-42 path is intact for
the unarmed case.

---

### KI-25 — The oracle's anti-manipulation rule is a **per-publisher deviation cap**, not a median

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **File** | `src/oracle.rs` — the "FULL-FIX PRECONDITION (deferred, explicitly out of scope)" comment (≈ line 294) |
| **Exploitability** | `REMOTE` (an oracle publisher key, which itself costs a governance proposal + quorum) |
| **Status** | Open. The shipped rule: the **same** publisher key may move an asset at most 5% per feed (half the global 10%), and a >10% single step latches the global circuit breaker (a 3-day governance reset). The full fix — a multi-publisher median/quorum, or a TWAP-anchored commit guard — needs committed TWAP history or publisher stake, i.e. new consensus state. Tracked as open item **O1 (oracle TWAP anchor)** in monorepo-root `docs/ROADMAP.md`; the read-path TWAP calculator exists (`src/oracle.rs:458` `calculate_twap`, `TWAP_WINDOW_SECS` at `:34`) but the commit path is explicitly not TWAP-anchored (`src/oracle.rs:25`, `:288`). |

---

## F. Bridges

### KI-26 — The bridge is **relayer-based**, not native

| | |
| --- | --- |
| **Severity** | HIGH (bridge-specific, not consensus) |
| **File** | `src/bridge.rs`, `src/bridge_adapters.rs` |
| **Exploitability** | `REMOTE` — a coalition of 2/3 of the bridge signer set, or a compromised relayer set |
| **Status** | Open by design. The fact of a deposit is proven by **relayer signatures** (a strict 2/3 threshold over DISTINCT signers, fail-closed on an empty set) plus adapter evidence (TON BoC hashes, EVM MPT receipt proofs, binary SHA-256 Merkle proofs). There is **no light client** for TON/EVM/Solana and no on-chain header store, so the chain cannot be verified natively. |

**Audit action:** the bridge signer set, its rotation and the 2/3 threshold are
the highest-value target in this file.

---

### KI-27 — The bridge's **challenge window needs off-chain watchers**

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **File** | `src/bridge.rs` — the dispute window (`DISPUTE_WINDOW_SECS` = 1 h), the challenge bond (`CHALLENGE_BOND_NANO` = 1 STELL, `CHALLENGE_BOND_BPS` = 100) |
| **Exploitability** | `OPERATOR` (nobody is watching) |
| **Status** | Open. The consensus-side machinery is there (challenge, resolve, a bounded number of deferrals, a dispute reward), but a fraud proof must be **submitted by a watcher**. With no watchers deployed, a fraudulent release cannot be contested. |

---

### KI-28 — The bridge has **no per-sender / per-destination rate limit**

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **File** | `src/bridge.rs` — `HOURLY_RATE_LIMIT_NANO` (500k STELL/h), `HOURLY_DEPOSIT_LIMIT_NANO`, `BRIDGE_MINT_CAP_NANO` (100M STELL cumulative) |
| **Exploitability** | `REMOTE` |
| **Status** | Open by design (the passport lists per-sender limits, funding-graph clustering and destination binding as *not implemented*). What holds today: the **global** caps are unconditional — they hold regardless of how many addresses are used, so more addresses never leaks more than the cap. What does not hold: a patient, rich attacker with many clean, aged, staked addresses can still drip. |

---

### KI-29 — A **pre-F-H** bridge state restores with the mint counters at ZERO

| | |
| --- | --- |
| **Severity** | HIGH if the restore is mishandled |
| **File** | `src/state_engine.rs` — the restore path (line 8744): *"restored pre-F-H V1 state: mint counters start at ZERO — verify real minted supply out-of-band before trusting cap headroom (exact on fresh/test chains)"*; `src/bridge.rs` — the V1 → current upgrade (≈ line 1114) |
| **Exploitability** | `OPERATOR` |
| **Status** | Open and loud. A pre-F-H data directory is refused at startup; a **restored** pre-F-H V1 state starts the counters at zero, so the cap headroom must be re-derived out of band. |

---

## G. Sharding

### KI-30 — No **live-network** shard split has been performed

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **File** | `src/sharding.rs`, `docs/SHARDING.md` §0 |
| **Exploitability** | `OPERATOR` |
| **Status** | Open. What is **demonstrated**: the address→shard rule (longest-prefix match, `-1:` masterchain form), the split and merge state machines over a synthetic account set, the trie migration over a real `PatriciaTrie`, the convergence property, the published thresholds and the RPC surface. What is **designed but not performed**: a split driven by a live consensus event, and shipping the migrated state to the new shard's validators. |

The published shard space is `2^60`; the **shipped** cap is `MAX_SHARDS = 16`.
The distinction is stated in `docs/SHARDING.md` and in the
`stell_getShards` response, because the advertised number is not a capacity.

---

## H. zkML

### KI-31 — The zkML engine is **not zero-knowledge and not succinct**

| | |
| --- | --- |
| **Severity** | MEDIUM |
| **File** | `src/zkml.rs` — `ZkMlProof::verify_inference` (line 1694, structural check) and `verify_inference_against` (line 1634, sound check); `src/zkml_attestation.rs` (the attestation engine) |
| **Exploitability** | `REMOTE` (a prover who fabricates a proof) |
| **Status** | Open by design, and the code says so — `src/zkml_attestation.rs`'s own header: *"Read this before calling anything here a \"SNARK\", a \"STARK\" or \"zk\"."* There is no R1CS/AIR, no polynomial commitment, no FRI, no pairings. The claim that is actually proved is *"these outputs are what THIS model produces on THESE inputs"*, and it is proved by **re-execution** plus a BLAKE3 Merkle trace binding plus a Fiat-Shamir challenge. |

Three facts an auditor must keep apart:

* `verify_inference` (line 1694) checks the Fiat-Shamir binding and the ReLU
  constraints only — it **does not verify the matrix multiplication**, so a
  fabricated, ReLU-consistent trace with invented activations passes it. The
  in-tree regression `forged_proof_passes_structural_but_fails_sound_check`
  (`src/zkml.rs:1997`) pins exactly that.
* `verify_inference_against` (line 1634) re-runs the deterministic integer
  model and **is** sound. The live opcodes are
  `OpCode::SysCallVerifyZkMlReexec` (re-execution) and
  `OpCode::SysCallVerifyZkMlAttestation` (re-execution + model-spec
  attestation); both are the sound paths.
* The legacy `OpCode::SysCallVerifyZkMl` calls the structural check and
  therefore carries **no soundness at all**. It is unreachable on the block
  path (`VmContext.zkml_proof` is never supplied — `src/svm.rs:1494` says so
  in the handler) and stays fail-closed.

The naming trap: the old opcode names (`...VerifyZkMlIn`,
`...VerifyZkMlSnark`, `...RegisterZkMlVk`) promised zero-knowledge and
succinctness the code never delivered, and they were **renamed** in this
wave. The machine-readable statement is
`zkml::zkml_capabilities()` (`src/zkml.rs:98`), served as
`stell_zkmlCapabilities`; it reports `zero_knowledge: false`,
`succinct: false`, `hiding: false`, `sound: true`, `trusted_setup: false`.
Read that, not the module names.

**Audit action:** the sound path is the one that matters; confirm the legacy
opcode is still unreachable, and check that nothing outside the two sound
opcodes treats a zkML proof as evidence of anything.

---

### KI-32 — A zkML model-registry gating precondition is deferred

| | |
| --- | --- |
| **Severity** | LOW |
| **File** | `src/zkml.rs` — the "GATING PRECONDITION (deferred)" comment on the model-registration path (line 1839) |
| **Exploitability** | `REMOTE` (a model squatter) |
| **Status** | Open. |

---

### KI-33 — There is **no SNARK, no STARK and no trusted setup** — the "setup attestation" is a label

| | |
| --- | --- |
| **Severity** | MEDIUM (a naming/expectation risk rather than a code defect) |
| **File** | `src/zkml_attestation.rs` (the whole module header), `src/zkml.rs:98` `zkml_capabilities` |
| **Exploitability** | none today |
| **Status** | Open by design, and stated loudly in the code. The attestation engine is a **sound re-execution attestation with a hash binding** — not a proof system. There is therefore **no ceremony, no toxic waste and no Powers-of-Tau** to run: the registered "setup attestation" is a free-form operator **label** carried in committed state, and the chain only refuses the documented test-only prefix `TEST-ONLY-DETERMINISTIC-SETUP` (a deterministic, waste-derivable setup must never anchor a chain). |

Two residuals that remain real:

* the deployment exposes its **inputs and outputs publicly** — there is no
  hiding, so a "private inference" claim would be false;
* the model is effectively **one layer deep** because of the accumulator
  bounds, and verification cost is **linear in the model's parameter count**
  — the opposite of what a succinct proof buys.

**Audit action:** nothing to fix; what to check is that no wallet, indexer or
document claims "zk" for this subsystem. The RPC capability endpoint is the
contract, and the honest answer is "sound, not zero-knowledge, not succinct".

---

## I. MEV

### KI-34 — MEV preemption is **live as a threshold scheme**, but it does not stop a malicious proposer

| | |
| --- | --- |
| **Severity** | MEDIUM (economic, not safety) |
| **File** | `src/mev_epoch.rs` (the epoch seal: DKG, sealing, order-commit, share release, unseal); `src/runtime.rs:2129` `sync_mev_epoch`, `:2171` `on_mev_frame`, `:2281` `sealed_proposer_path`; `src/mempool.rs:859` `add_sealed`; `src/rpc.rs:3499` `stell_epochKey`, `:3540` `stell_sendSealedTransaction`, `:3570` `stell_mevStats`; `src/sharding.rs:4297` `Block::epoch_key_commitment` |
| **Exploitability** | `VALIDATOR` (the proposer front-runs with its own transaction, or withholds its reveal) |
| **Status** | **Live.** The node-local blind round of `src/mev.rs` is no longer the whole story. |

What is wired and enforced **today**:

* the **epoch seal** runs end to end: the node publishes its DKG contribution
  on the epoch boundary (`runtime::sync_mev_epoch`), ingests peers'
  contributions (`runtime::on_mev_frame`), and exposes the resulting **epoch
  public key** over RPC (`stell_epochKey`: the public key, the committee, the
  threshold, the transcript root);
* a wallet can submit an **asymmetrically sealed** transaction
  (`stell_sendSealedTransaction`); the node stores the **ciphertext only** and
  gossips the ciphertext;
* the proposer **commits the order first, reveals second**: the candidate order
  is signed and gossiped as an `OrderCommit` frame, and only then are the
  decryption partials released (`runtime::sealed_proposer_path`,
  `mev_epoch::commit_order` / `partials_for`);
* an unsealed transaction must **match its envelope hash**, **match its
  transparent metadata** and **carry a valid signature**, or it is dropped;
* fewer than `t` partials ⇒ the transaction is **dropped** (fee charged), so a
  member that withholds its share cannot stall the round;
* the **epoch key commitment is inside the block** (`Block::epoch_key_commitment`,
  `src/sharding.rs:4297`) and therefore inside the signed block hash
  (`src/sharding.rs:4689`), so the quorum commits to *which* epoch key was
  used;
* the older, **order-committing** path is still there and still
  consensus-enforced: the block carries the **order Merkle root** over the
  ordered transaction list (`mev::compute_order_merkle_root`), and a validator
  re-computes it from the proposed body and **refuses the proposal on a
  mismatch** (`runtime::check_order_commitment`).

What is **still not** true (the honest residual):

* it hides the transaction **content** from a passive observer and from a
  mempool snooper **until the ordering is committed**; it does **not** hide
  the *ordering* (the block lists the transactions in order);
* it does **not** stop a malicious proposer from **front-running with its own
  transaction**, nor from **withholding its reveal** — the module header says
  so explicitly ("it does not stop a malicious proposer from withholding its
  reveal, and it does not stop a malicious proposer from front-running with
  its OWN transaction");
* the `mev_v4` engine stays **parked and default-off**
  (`tests/mempool_mev_audit_closure_tests.rs::mev_v4_stays_parked_and_default_off`);
* the MEV suite still records the **vote gate as deferred**
  (`tests/mempool_mev_audit_closure_tests.rs::mev_seal_enforced_order_detected_vote_gate_deferred`).

**Audit action:** the interesting surface is now the *transition* between the
two paths — the node-local blind round (`src/mev.rs`) and the threshold epoch
seal (`src/mev_epoch.rs`) coexist, and a transaction can arrive through
either. Check that the two cannot disagree about what "sealed" means, that
the unseal gate is applied on both, and that an attacker cannot downgrade a
sealed transaction to the plain path to see it early.

### KI-35 — The BoC parser trusts two 32-bit length prefixes before it validates them

| | |
| --- | --- |
| **Severity** | LOW–MEDIUM (resource amplification; a hard abort where the allocation fails) |
| **File** | `src/cell.rs:153` `BagOfCells::from_boc_bytes` — `Vec::with_capacity(roots_len)` (line 165) and `HashMap::with_capacity(cells_len)` (line 176) |
| **Exploitability** | `VALIDATOR` (see the reachability note) — **not** an unauthenticated remote peer |
| **Status** | **Open.** Found while preparing this package; **not fixed here** (other agents own the fixes). |

`from_boc_bytes` reads `roots_len` and `cells_len` straight out of the blob
header (bytes 4..12) and passes them to `with_capacity` **before** checking
them against the number of bytes actually left in the blob. A 12-byte blob
whose two length fields are `0xFFFFFFFF` therefore asks for

* a `Vec<[u8; 32]>` with capacity 4,294,967,295 → **128 GiB**, and
* a `HashMap<CellHash, Cell>` with the same capacity → **≈370 GiB**,

and only then discovers the EOF and returns `Err`. On a host where that
allocation fails, the Rust allocator aborts the process
(`memory allocation of 137438953440 bytes failed` → `SIGABRT`); on a host
with overcommit it becomes a large virtual allocation that is never touched.

**Reachability (why this is not rated higher).** The parser is reached from
`bridge_adapters::TonAdapter::verify_deposit`
(`src/bridge_adapters.rs:761`), and the byte blob is carried **inside a
signed transaction** (`BridgeIntent::DepositProof { evidence }`). But the
adapter's *first* two checks are the BoC size cap (64 KiB), the
**quorum-attested header** (`check_header` → `verify_quorum_signatures`) and
the finality-depth check, and the BoC parse happens **after** them. So an
unauthenticated attacker cannot reach the allocation: it needs a 2/3 quorum
of the committed bridge-signer set to sign the TON header. That is a real
barrier — but it is also the reason the bug is easy to miss, and it is the
kind of thing that becomes remotely reachable the moment the bridge grows a
light client or a header store that trusts a single relayer.

**Reproduction** (standalone, does not touch the repository):

```rust
// 12 bytes: magic + roots_len=0xFFFFFFFF + cells_len=0xFFFFFFFF
let bytes = vec![0xb5,0xee,0x9c,0x72, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF];
let roots_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
let cells_len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
let roots = Vec::<[u8;32]>::with_capacity(roots_len);   // 128 GiB
let cells = HashMap::with_capacity(cells_len);            // ~370 GiB
```

**Audit action:** check every other raw-byte parser in the tree for the same
shape (a length prefix that reaches `with_capacity` before it is checked
against the remaining input), and check the memory limits the deployment
imposes (a container with a memory cgroup limit turns the allocation into a
hard abort).

---

## J. Deferred / not-started features (not defects)

| ID | Feature | Where it is described |
| --- | --- | --- |
| D-01 | **Real threshold preemption**: asymmetric round sealing, a share-release round gated on a quorum-signed ordering commitment, and sealed mempool gossip (needs wire slots — a hard fork). | `src/mev.rs` module header; `src/mev_epoch.rs` (the library half exists) |
| D-02 | **Per-entry archive proofs** (P3): per-key commitments so a light client can prove a staking entry or an orderbook level, not just a balance. Trie-resident per-key archive proofs + QC-authenticated historical roots are done (`PROTOCOL.md` §5.4); what remains is per-entry keys for the digest-folded domains. | `PROTOCOL.md` §5.4 + §7; `src/commitment.rs`; `src/storage.rs` (slot model) |
| D-03 | **Cross-node shard state migration**: shipping a migrated trie to the new shard's validators. | `docs/SHARDING.md` §0 |
| D-04 | **A native (light-client) bridge**: on-chain foreign headers, foreign validator sets, and consensus-level verification of their signatures. | `docs/handoff/STELLEREUM_REMAINING.txt` (bridge layers 2–3) |
| D-05 | **Per-sender / destination-cluster / funding-graph bridge limits**, and a TWAP-anchored oracle commit guard. | `src/bridge.rs`; `src/oracle.rs` |
| D-06 | **A real zero-knowledge proof system** for on-chain inference (a circuit + a polynomial commitment + a Fiat-Shamir transcript over it) and a private in/deployment wrapper. There is no ceremony to run: the current engine has no setup at all (see KI-33). | `src/zkml_attestation.rs` (module header); `src/zkml.rs:98` `zkml_capabilities` |
| D-07 | **A real ML-DSA-44 (FIPS-204) verifier** and the coordinated hard fork to re-enable scheme `0x03`. | `src/post_quantum.rs` |
| D-08 | **A VRF-based (ungrindable) sortition** selection. | `src/consensus.rs` `sortition_seed`; `PROTOCOL.md` §6.2 |
| D-09 | **Identity / reputation** (`name.stl` as an NFT object, Sybil resistance). | `docs/handoff/STELLEREUM_REMAINING.txt` |
| D-10 | **A real producer-side privacy entry/exit** (shield / unshield), deliberately blocked behind the range-proof work. | `src/crypto_privacy.rs`; `docs/handoff/STELLEREUM_REMAINING.txt` §9 |
| D-11 | **User-level multisig / threshold accounts: explicit non-goal.** There is no on-chain M-of-N account, no threshold-signature account, and no multisig wallet contract in this tree (verified: `multisig`/`threshold` appear only for the *bridge relayer* quorum — `quorum_threshold`/`bridge_threshold`, `src/bridge.rs:535-550` — and for TON-side deposit evidence, never for user accounts). Every transaction is authorized by exactly one ed25519 (`Transaction.from` + signature) or one session grant. **Custody workaround until/unless D-11 ships:** split funds across independent validator/delegator accounts (no shared key to lose); keep the master key cold and operate day-to-day through `DelegateSession` scoped grants (amount caps + expiry, `RPC.md` wallet surface); rotate a compromised validator key atomically with `SysCallRotateValidatorKey` (no merge, old-key-only authorization). Do not emulate multisig by sharing one seed across operators — a shared seed is single-factor with extra steps. | `src/svm.rs` (`SysCallStake`/`SysCallRotateValidatorKey`); `stell-wallet` (`rotate-key`, session delegation); `RPC.md` §5 |

---

## K. Stale claims in the in-tree documentation

These are **documentation** defects, not code defects, but an auditor will hit
them and should know they are stale.

| ID | Claim | Reality | Severity |
| --- | --- | --- | --- |
| SD-02 | `PROTOCOL.md`: *"the integration suites carry 65 pre-existing failures"*. | **Stale.** Measured 2026-10-30 (brief §9): the library suite (1,045 tests) is green; 77 of the 78 security-focused integration suites are green and the 1 red one (`audit_rpc_evm_closeout`, 2 tests) is a live code-vs-test contract mismatch, not a pre-existing background failure — see KI-37. | INFO |
| SD-03 | `PROTOCOL.md` §7: *"Restoring from a snapshot does not rebuild the commitment."* | **Stale.** The restore path now fetches and rebuilds every committed domain (`src/sync.rs`, the F-J follow-up; `tests/audit_state_sync_closeout_tests.rs`). | INFO |
| SD-04 | `PROTOCOL.md` §7: *"No live-network shard split."* | **Still true** (see KI-30). The split/merge state machine is demonstrated over a synthetic account set only. | — |
| SD-05 | The audit figures *"2043 fuzz corpus files"*. | **Superseded by growth.** At the old HEAD that count was exact; on the current tree the working-tree corpus is **4,427 files before the smoke run and 4,584 after it** (2,293 → 2,334 `consensus_msg_decode`, 633 → 681 `transaction_decode`, 594 → 633 `block_decode`, 9 `frame_decode`, plus the newer targets 5 / 350 → 353 / 543 → 569). The extra files are *untracked* seeds the smoke runs keep adding. The honest reading is unchanged: deepest on the consensus wire format, thinnest on the certificate envelopes (5 files). | INFO |
| SD-06 | `src/mev_epoch.rs`'s module header points at **`docs/MEV.md`** for "the full statement" of what the epoch seal does and does not protect against. | **Resolved — the file now exists.** `docs/MEV.md` ("MEV PROTECTION — THE EPOCH SEAL") was added alongside the live threshold scheme and carries the honest residual statement (§4.3); the module headers (`src/mev_epoch.rs:60`, `src/mev.rs:44`) resolve again. The authoritative statement is the module headers **plus** `docs/MEV.md`; KI-34 quotes both. | INFO |

*(SD-01 and SD-07 retired 2026-10-30 — the claims they tracked are fixed; see §M.)*

---

## L. Production blockers of wave W8.3 — closed, and what remains

Three items were listed as **OPEN production blockers** after the external
review. All three are now closed **as gaps**; each one leaves a residual that
is a *design statement*, not a defect, and the residual is written down
rather than papered over.

| ID | The blocker as it was stated | Status now | What remains (the honest residual) |
| --- | --- | --- | --- |
| **A10** | *"The light client is not wired into the sync path — «узел сам выдаёт корень, в который верит» is not a proof for an outside verifier."* | **Closed.** The node keeps a light client anchored at its OWN finalized head (the header carrying the precommit quorum certificate that decided it); every peer-supplied block in a sync goes through `sync::verify_synced_blocks_against_anchor` before a single transaction of it runs; the anchor and the finalized headers are served over RPC (`stell_getFinalizedCheckpoint`, `stell_getFinalizedHeader`); and `stellereum light-client --from <rpc> --verify <account> --validators <file>` is a real external verifier (Near `light_client` / Sui `sui_light_client` model). See KI-18. | The **validator set is the entire trust anchor**. A client that takes its set from the server it is verifying has no anchor at all, so the CLI refuses to run without an out-of-band set. There is no validator-set rotation story, and the client cannot check that the set was ever legitimately elected. |
| **A5** | *"The zk-SNARK opcode is not zero-knowledge — a repeated forward pass, no zero-knowledge, no compression."* | **Closed as a naming/claim defect.** The opcodes were renamed to what they do (`SysCallVerifyZkMlIn` → `SysCallVerifyZkMlReexec`, `SysCallVerifyZkMlSnark` → `SysCallVerifyZkMlAttestation`), the Groth16/arkworks claim was deleted from the code and from the docs, the attestation engine got an honest module header (`src/zkml_attestation.rs`), and the chain now serves a **machine-readable capability statement** (`stell_zkmlCapabilities` / `zkml::zkml_capabilities()`) in which `zero_knowledge: false`, `succinct: false`, `hiding: false`, `sound: true`, `trusted_setup: false`. See KI-31 and KI-33. | The subsystem is **verifiable inference by re-execution** — sound, and NOT zero-knowledge, NOT succinct, NOT hiding. A real ZK proof would need a circuit over the quantized forward pass, a polynomial commitment with a soundness argument and a Fiat-Shamir transcript over that commitment (D-06). Until then no wallet, indexer or document may call it "zk"; the RPC endpoint is the contract. |
| **A8** | *"`STELL_AUTO_UPGRADE` defaults to 1 — an on-chain proposal can make the node `execve` a new binary by default."* | **Closed.** The default is **OFF**: the live migration arms only when the operator explicitly sets `STELL_AUTO_UPGRADE=1`/`true` on that node; a typo fails safe; the unarmed node still halts at the upgrade height with **exit code 42** (Cosmovisor-compatible). When armed, the node prints a banner and a `WARN` line at start-up. The upgrade path was re-audited for the W6 residuals (path traversal, TOCTOU, symlink) and the fixes are in code and pinned by tests. See KI-24 and `docs/OPERATIONS.md` §12. | Arming the live migration is a **node-local operator decision** and must be made on every node or on none. The candidate path, the digest and the staged copy are still the operator's responsibility to stage correctly; the code refuses traversal names, symlinked candidates, symlinked parents and digest mismatches, and executes the staged copy of the hashed bytes. |

**How to check these three claims yourself** (all three are pinned by tests):

```bash
cargo test --lib governance::tests::            # the arming default + the path safety
cargo test --test light_client_wiring_tests     # the anchor, the CLI, the lying server
cargo test --lib zkml::tests::                  # the capability statement
```

---

## M. Open items recorded 2026-10-30 (AUDITPREP)

Five items entered or re-entered this file during the 2026-10-30 audit-prep
pass (repro run at brief §9). None of them is fixed by the audit-prep work —
other agents own the fixes; this section records them with the code anchor so
the next reader does not have to rediscover them.

### KI-37 — `eth_estimateGas` F4 contract is red: the "pure figure" comes back floored

| | |
| --- | --- |
| **Severity** | MEDIUM (gate-weakening + wallet-facing honesty; the failure direction itself is fail-safe) |
| **File** | `src/evm_adapter.rs` `eth_estimate_gas_amount` (the `.max(crate::svm::GAS_BASIC_TRANSFER)` floor); `tests/audit_rpc_evm_closeout.rs:387` `f4_estimate_serves_pure_figure_at_zero_floor`, `:413` `f4_estimate_never_below_admission_floor` |
| **Exploitability** | none directly (an over-estimate is admittable; no party gains) |
| **Status** | **Open, owned by other agents.** The floor-aware estimate change (audit B-VM) made `eth_estimate_gas_impl` return `max(pure, 280_000)` on every path, while the two F4 tests still pin the unfloored EVM arithmetic (`0x5208`/`0x5248`). Repro 2026-10-30: 28 passed, 2 failed (`left: "0x445c0"`). |

**Audit action:** settle the contract one way or the other — either the pure
figure stays pure and only `eth_estimate_gas_with_floor` applies the floor,
or the tests are updated to the floored values — and do it without deleting
the F4 pins. Until then `audit_rpc_evm_closeout` is the one red suite in an
otherwise green gate.

### KI-38 — The wasm contracts authenticate NOTHING (CT-P0 rewrite)

| | |
| --- | --- |
| **Severity** | HIGH for any deployment that uses them; INFO for the chain (they are demo-grade product code, not protocol) |
| **File** | `stellereum-contracts/contracts/sts20-token/src/lib.rs:2` (*"`owner`/`caller_id`/`admin_id` args are caller-supplied and replayable: the contract never reads the authenticated `host.caller`"*) and the sibling `liquidity-pool`, `stl-dns`, `account-object` contracts; PoCs `stellereum-contracts/contracts/sts20-token/tests/poc_p0_unauth_transfer.rs`, `poc_p0_forged_burn.rs` (*"This test FAILS on current code"*) |
| **Exploitability** | `REMOTE` (any caller) — a stranger crafts a transfer-from-admin and it succeeds; no allowance/spender check exists |
| **Status** | **Open, tracked as CT-P0 in monorepo-root `docs/ROADMAP.md`.** The SDK side landed (`stellereum-contract-sdk/src/lib.rs:66` `caller()`, `:76` `value()`, `:81` `host_mock` with `set_mock_caller`), but no contract reads `host.caller` yet. The failing `poc_p0_*` tests are the acceptance criteria for the rewrite. Contracts are marked demo-grade: DO NOT deploy with value. |

**Audit action:** confirm no live deployment funds these contracts, and review
the rewrite (host.caller-bound auth) when it lands — the PoCs, not this
document, are the verdict.

### KI-39 — Wallet notes UX migration (secret-bound store landed; the UX note is deferred)

| | |
| --- | --- |
| **Severity** | LOW |
| **File** | `stell-wallet/src/notes.rs:602` `migrate_notes_to_secret`, `:441`–`:474` (legacy plaintext fallback), `stell-wallet/src/main.rs:2947` (transparent migration on first read) |
| **Exploitability** | `LOCAL` (a stale plaintext notes file on a previously-used host) |
| **Status** | **Code landed, UX follow-through deferred** (ROADMAP: "wallet secret-bound migration (legacy decrypt removed)", with the "wallet notes UX migration note" deferred). Legacy files migrate transparently to the secret-bound store; passwordless reads of legacy files are refused. What remains is the user-facing migration note, not a cryptographic gap. |

### KI-40 — r0 rarely decides on slow-proposer slots (tempo residual, not a defect)

| | |
| --- | --- |
| **Severity** | LOW (liveness/tempo, deployment-specific) |
| **File** | `docs/specs/04_NETWORK_AND_CONSENSUS.md:29` (residual = WAN RTT floor + 1-vCPU members — "physics, not bugs"); tick 50 ms, base timeout 3500 ms, r0 fast path (`04_NETWORK_AND_CONSENSUS.md:11`) |
| **Exploitability** | none (no adversary gains; slow finality, not a fork) |
| **Status** | **Open ops observation.** VEL prebuild + vote pipeline (build `573d86f5`, rolling 2026-10-29) improved tempo 8.2 s/blk (dirty window) → ~2.5 s/blk sustained, rounds converging — but r0 still rarely decides on slow-proposer slots (members C/D, 1-vCPU) + WAN. The hour-tempo verdict (meter running, mean/p50/p99 + views/block, r0-decide rate) is pending in ROADMAP P0. |

**Audit action:** none on the consensus code — the question is operational
(slot scheduling on weak members), and the meter, not this document, settles
it. Revisit after the hour-tempo verdict lands.

### KI-41 — Workchain wedged/empty: PARK or fund (deployment decision, unverified here)

| | |
| --- | --- |
| **Severity** | MEDIUM (deployment completeness, not a code defect) |
| **File** | monorepo-root `docs/ROADMAP.md` P1 ("execute PARK (S4 runbook) or fund + serve shard-1 RPC (currently wedged/empty)"); `docs/SHARDING.md` §0 (what split/migration is demonstrated vs designed) |
| **Exploitability** | `OPERATOR` (deployment choice) |
| **Status** | **Open, unverified by this pass.** Live-cluster state was deliberately not probed (read-mostly ops rule), so this records the ROADMAP position, not a fresh measurement: shard-1 RPC is wedged/empty and the decision is PARK per the S4 runbook vs fund-and-serve. |

---

## N. Closed since the last brief (verified 2026-10-30, in code + in the repro run)

Items moved out of the open sections because the fix is **in the code**
(symbol located, line cited) **and** the pinning suite is **green in the
2026-10-30 repro run** (brief §9). History is kept here so a fixed item is
never mistaken for a dropped one.

| ID | What it was | Fix verified in code | Repro evidence |
| --- | --- | --- | --- |
| **KI-36** | The consensus round-window area carried a moving set of red tests while the network-anchor / polka-ledger liveness change landed. | `tests/consensus_rephase_tests.rs:118`–`:289` rewritten around the anchored semantics (10 tests); the anchor reasoning still stands — `src/consensus.rs:3776` `scan_floor` bounds with `MAX_SCAN_SPAN`, anchors on the maximum observed peer round. | `consensus_rephase` 10/10 green (216 ms). |
| **(build)** ex-SD-01 | Three `example`/`bench` targets called the pre-rename zkML API, reddening `cargo build --tests --all-targets`. | `examples/passport_audit.rs:154` and `examples/vuln_hunt2.rs:131` use the renamed API (`forge_structural_proof`); `benches/zkml_attestation.rs:4`–`:10` documents the `snark` removal in its own header. | `build (cargo build --tests --all-targets)` green (44.36 s). Ex-SD-01/SD-07 retired. |
| **(harness)** | `tests/support/live_stand.rs` did not compile (moved `block`), erroring `pq_equivocation_report`. | `tests/support/live_stand.rs:578` destructures `Msg::Proposal { round, block }` and borrows correctly. | `pq_equivocation_report` 4/4 green (77.42 s). |

**How to check these yourself:**

```bash
./scripts/audit-repro.sh --no-fuzz    # build + all 79 suites; expect only KI-37 red
cargo test --no-fail-fast --test consensus_rephase_tests
cargo test --no-fail-fast --test pq_equivocation_report_tests
```
