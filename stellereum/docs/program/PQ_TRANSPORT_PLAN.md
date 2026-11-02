# PQ Transport Plan — infnode flag-day migration (classical → PQ)

Status: DESIGN ONLY. Prototype: `infnode/crates/infnode/src/pq_transport.rs`
(UNWIRED — not referenced by `lib.rs`/`node.rs`; production behavior unchanged).
No new dependencies added. ML-KEM is UNAVAILABLE offline (see §2).

Audit anchor: current primitives are `ed25519-dalek 2.2.0`, `x25519-dalek 2.0.1`,
`blake3 1.8.6`, `rustls 0.23.45` on `ring 0.17.14`, `quinn 0.11.11`,
`rcgen 0.13.2` (versions from `infnode/Cargo.lock`). Full primitive map with
file:line lives in the header of `pq_transport.rs` (tables A/K/T/I).

---

## 1. Why a flag day (and not silent upgrade)

`NodeId = blake3(ed_pub)[..20]` is load-bearing identity: DHT routing
(`dht.rs:64`), peer pins (`config.rs:60-80`), TLS SPKI pins (`node.rs:7112-7156`),
federation TXT (`federation.rs:88-108`), TOFU binding (`node.rs:6238`). A PQ
key cannot silently replace the classical id — every peer, DNS record, and
`node.yaml` pin names the classical one. Hence: dual-announce window →
promotion ceremony → flag day → rollback plan. Mixed-net compat is a
first-class phase, not an afterthought (§5).

## 2. KEX verdict (honest, verified 2026-11-02 offline)

| Option | PQ? | Available offline | Rank | Disposition |
|---|---|---|---|---|
| ML-KEM-768 (FIPS 203) | yes | NO — absent from `Cargo.lock` (304 crates, zero hits for `ml-kem`/`kyber`/`dilithium`/`pqcrypto`/`oqs`); `cargo metadata --offline` fails; `~/.cargo` cache holds only stale non-graph `pqcrypto-falcon*`/`falcon-rust*` | 1 | FIRST CHOICE, blocked on lead vendoring |
| Falcon-auth + ephemeral-X25519 (signed-ephemeral interim) | auth only | yes | 2 | HONEST INTERIM — ship PQ peer auth first, KEX stays classical, flag says so (`PqPlanX25519Backend::PQPLAN_CLASSICAL = true`) |
| X25519 X3DH status quo (`node.rs:6970-7021`, `proto.rs:127-152`) | no | yes | 3 | pre-flag-day only |
| X25519 + symmetric-PSK bootstrap | no | — | REJECTED | no PSK-distribution story for TOFU strangers; fragility for zero PQ gain |

Machine-checked in `pqplan_kex_verdict_is_honest` (13/13 KATs green standalone).

## 3. PQ peer auth design (what gets wired later)

1. **Dual signature transition.** CHALLENGE/AUTH payloads gain `pq_pub`
   (Falcon-512 long-term key) + `pq_sig` over the SAME `sign_data()` bytes
   the Ed25519 signature covers (`proto.rs:170-184`). Verification order
   mirrors today: sig(s) BEFORE nonce-claim BEFORE session derivation
   (`node.rs:6309-6321`). Fail closed on any mismatch.
2. **Transcript binding.** At flag day, replace the JSON payload signature
   with a versioned, domain-separated, length-prefixed transcript binding
   `{pq_init, pq_resp, eph_init, eph_resp, channel_binding, nonce_init,
   nonce_resp}` — prototyped as `PqPlanTranscript` (`pqplan_encode` /
   `pqplan_digest`), tamper-covered by `tamper_anywhere_rejected` KAT
   (9 single-byte-flip cases: version, suite, every field).
3. **Channel binding.** 32 bytes from the QUIC/TLS exporter, covered by the
   Falcon signature. Until the rustls exporter label is pinned, the label
   MUST be part of the transcript domain string (`PQPLAN_DOMAIN` pattern).
4. **PQ long-term id.** `pq_id = blake3("infnode-pqid-v1" || falcon_pk)[..20]`,
   rendered `inf1:`-compatible. Resolution rule is `pqplan_resolve`:
   first-PQ-wins sticky binding; key-change without rollback ceremony →
   `Quarantined` (mirrors classical MITM rule `node.rs:6246-6259`).

## 4. Flag-day re-ceremony (operator checklist)

Do in order, per node. `node.yaml` = the file loaded by `config::load`
(`config.rs:142`); key files = `identity.key` (ed seed) + `e2e.key` (x seed)
(`keyring.rs:197-267`, 0600 files / 0700 dir, passphrase via
`STELL_NODE_PASSPHRASE`).

1. **Freeze.** Stop writes that bind identity: new TOFU accepts
   (`allow_unknown`), DHT republishes. Snapshot `node.yaml`, key dir,
   `routes.json`, DNS zone.
2. **Generate PQ keys (offline).** `infnode pq-keygen` (TO-BE-ADDED by lead):
   Falcon-512 keypair → `pq-identity.key` (0600, same `protect()` envelope).
   NEVER reuse classical seeds. Record fingerprint on paper.
3. **Dual-announce window (≥ 2× max peer `routes.json` TTL + DHT republish
   interval, suggested 48h).** Deploy build with dual-signature verify
   (accept classical-only AND dual) but classical-canonical routing.
   Peers gossip `(classical_id, pq_id, cross-signature)` — the classical key
   signs the PQ key and vice versa. Monitor: % peers with bound `pq_id`,
   `Quarantined` count (must be 0 before proceeding).
4. **Re-pin `node.yaml`.** For every static peer add `pq_pub` + `pq_id`
   alongside existing `ed_pub`/`x_pub`/`node_id` pins (`config.rs:25-42`
   extended by lead; old fields MUST stay until §6). Validate pins parse
   (`ed_bytes`-style accessors for the new fields).
5. **DNS TXT re-ceremony.** Publish new-format record
   `infnode-validator=inf1:{node}:{ed}:{pq}:{ip}` (extends
   `federation.rs:112-152` format) from the domain owner; keep the old
   record until flag day + TTL. `verify_domain_validator` must confirm
   BOTH records pre-cutover.
6. **TLS pins.** `build_tls` (`node.rs:7080-7105`) issues a hybrid handshake
   cert (classical Ed25519 + PQ signature over the same TBSCertificate
   bytes — exact mechanism TBD with vendored Falcon); `PinnedVerifier`
   (`node.rs:7112-7187`) learns the PQ SPKI pin as an AND-condition only
   at flag day, OR-condition during the window. TLS1.2 stays hard-disabled
   (`node.rs:7158-7165`).
7. **Flag day.** Config flag (e.g. `pq_only: true`) flips canonical identity
   to `pq_id` and REQUIRES `pq_sig` on CHALLENGE/AUTH; classical-only
   frames are refused at the accept gate (`node.rs:6153ff` pattern).
   Restart order: validators → storage seeds → edge nodes. Confirm mesh
   convergence (peer counts, DHT lookup success) before releasing freeze.
8. **Cleanup (one release later, never same-day).** Drop classical pins,
   legacy TXT, classical-only code paths.

## 5. Mixed-net compat window

- Window builds speak both: verify dual-or-classical, route by classical id.
- Classical-only nodes NEVER see PQ fields as errors: new payload fields are
  additive JSON (`challenge_fields`-style strict parsing at `node.rs:6944-6961`
  must TOLERATE unknown fields during the window, then strict-mode at flag
  day — lead decision, recorded here).
- `Quarantined` peers (PQ claim conflicts) are refused like MITM key-changes
  today, with the same loud `eprintln!` operator warning (`node.rs:6246-6259`).
- Metrics to add (lead): `pq_dual_announced_total`, `pq_bound_peers`,
  `pq_quarantined_total`, `pq_only_refusals_total`.

## 6. Rollback

- **Before flag day:** set `pq_only: false` (or redeploy previous binary);
  classical pins were never removed, so the mesh reconverges with zero
  re-ceremony. Delete `pq-identity.key` ONLY if compromise is suspected
  (otherwise keep for the next attempt).
- **After flag day (≤ rollback horizon, suggested 72h):** operator ceremony —
  set rollback flag per node, restart in dual-verify/classical-canonical
  mode (`PqPlanEffective::Classical` arm of `pqplan_resolve`, covered by
  `migration_rollback_returns_classical` KAT). Classical pins are still on
  disk (cleanup §4.8 hasn't run) — that invariant is what makes rollback
  possible. Announce rollback in DNS (restore legacy TXT as primary).
- **After cleanup:** rollback = full re-ceremony (§4) in reverse. This is why
  cleanup ships a release later.

## 7. Lead-gated dependencies (DO NOT add in this change)

- `ml-kem` (or `libcrux`/`pqcrypto` ML-KEM) for full-PQ KEX — REPORTED
  unavailable offline; lead must vendor + approve.
- Falcon-512 crate for `PqPlanSigner` production backend — same gate.
- Until both land, `PqPlanX25519ClassicalBackend` (classical, flagged) is the
  only honest backend, and this plan ships NO wire changes.
