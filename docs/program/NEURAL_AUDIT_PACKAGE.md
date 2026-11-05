# Neural-audit package — manifest (not the audit)

Source of truth: `docs/PUBLIC_TESTNET_CODE_GAPS.md` §3 (64 lines).
Status date: 2026-11-03. Rule: cite file:line or mark UNVERIFIED. No suites were
run for this manifest; states below are either present-at-path or cited.

## 1. Existence checklist (§3 items)

| # | §3 item | Path | Status | Lines / count |
|---|---|---|---|---|
| 1 | `docs/program/` (GitHub mirror) | `docs/program/` | ✗ MISSING at literal path — content exists only at `stellereum/docs/program/` (17 entries: `PQ_CN_VRF_SPEC.md`, `CLASSICAL_INVENTORY.md`, `PQ_VRF_FRONTIER_V2.md`, `PQ_TRANSPORT_PLAN.md`, `WORKCHAIN_DECISION.md`, `PUBLIC_TESTNET_CODE_GAPS.md`, `specs/`, `ops/`, …) | 17 entries (mirror) |
| 2 | `docs/specs/*_PHASE2` | `docs/specs/00_PROJECT_MAP_PHASE2.md`, `01_ARCHITECTURE_OVERVIEW_PHASE2.md`, `02_CRYPTO_AND_PQ_PHASE2.md`, `03_VM_AND_EXECUTION_PHASE2.md`, `04_NETWORK_AND_CONSENSUS_PHASE2.md` | ✓ all 5 present | 74 + 152 + 184 + 164 + 112 |
| 3 | CN-VRF spec | `docs/PQ_CN_VRF_SPEC.md` | ✓ | 701 |
| 4 | Classical inventory | `docs/CLASSICAL_INVENTORY.md` | ✓ | 204 |
| 5 | VRF frontier | `docs/PQ_VRF_FRONTIER_V2.md` | ✓ | 296 |
| 6 | Workchain decision | `docs/WORKCHAIN_DECISION.md` | ✓ | 203 |
| 7 | Matrix | `FEATURES.md` (repo root) | ✓ file, ✗ NOT 100% green: 104 rows, GREEN 102 / RED 1 / SKIP 1 (`FEATURES.md:113` footer). RED row = `pentest-net-api` (`FEATURES.md:107`: 12 passed, 1 failed) | 113 lines / 104 rows |
| 8 | Last `audit-repro` log | `stellereum/scripts/audit-repro.sh` ✓ (426 lines); log file itself ✗ NOT in repo | PASS state: CITED-AS-OF 2026-10-31 only — `docs/AUDIT_RED_CLOSURE.md:34-35` (`RESULT: PASS, EXIT=0, TOTAL 1845 passed / 0 failed`, log `/tmp/opencode/audit-repro-20261031.log`, ephemeral) + `:158-159` + cross-refs `docs/CONSISTENCY_AUDIT.md:69`, `docs/specs/01_ARCHITECTURE_OVERVIEW_PHASE2.md:151-152`. Current-tree PASS: UNVERIFIED (and contradicted by item 7 RED) | script 426 lines; log UNVERIFIED current |
| 9 | `docs/PENTEST_*` summary (all batteries + DEFEATED/FINDING table, residual "2× Low reputation accepted") | `docs/PENTEST_NET_API.md` ✓ (121 lines: 21-probe matrix, 13/13 tests green, 2 MEDIUM wontfix M1 STOP/CONT stall + M2 per-IP ban loopback blast) | ~ PARTIAL: one battery doc only; unified summary table NOT FOUND anywhere (grep `DEFEATED\|FINDING` hits only `PUBLIC_TESTNET_CODE_GAPS.md:45` — the claim itself). "2× Low reputation accepted": UNVERIFIED (no table, no file:line) | 121 |
| 10 | Out-of-scope list | `docs/PUBLIC_TESTNET_CODE_GAPS.md:46-47` | ✓ (text present; expanded in `NEURAL_AUDIT_QUESTIONS.md` §6) | — |

Score (strict, content-level): **6/10 fully present** (items 2,3,4,5,6,10).
Partial: 1 (mirror misplaced), 7 (file present, not green), 8 (script present, current PASS unverified), 9 (one doc present, table missing).

"Code 100%" criterion (`GAPS §3:40`): lib 0 failed — CITED-AS-OF 2026-10-28 (`docs/audits/COMPREHENSIVE_AUDIT_REPORT.md:1317`: 216 suites, 2884 passed / 0 failed; lib 1025/0; REP2 lib 1034/0 per `:1458`) / current UNVERIFIED; clippy 0/0 — cited per-battery only (e.g. `PENTEST_NET_API.md:107`), full-tree current UNVERIFIED; matrix 100% green — ✗ (102/104); audit-repro PASS — cited-as-of 2026-10-31, current UNVERIFIED; zero UNVERIFIED in `docs/specs/` — ✓ SUBSTANTIVELY (4 grep hits, all zero-bookkeeping: "UNVERIFIED static count added: 0" in `02_CRYPTO_AND_PQ_PHASE2.md:173`, `03_VM_AND_EXECUTION_PHASE2.md:107`, `00_PROJECT_MAP_PHASE2.md:60,73`; no open items); §1 executed — lead claim in GAPS §1 table (ИСПОЛНЕНО per-row), code pins verified for H constants only (see QUESTIONS §5).

## 2. Ordered reading list for auditor nets

Read in this order. Each entry: what it is + the question it answers.

1. `docs/PUBLIC_TESTNET_CODE_GAPS.md` (§0–§2, 64 lines) — freeze context. Answers: what is already decided/executed (5 decisions, 2 deletions) and what H means (classical death height + MEV-transport activation height).
2. `docs/specs/00_PROJECT_MAP_PHASE2.md` (74) → `01_ARCHITECTURE_OVERVIEW_PHASE2.md` (152) → `02_CRYPTO_AND_PQ_PHASE2.md` (184) → `03_VM_AND_EXECUTION_PHASE2.md` (164) → `04_NETWORK_AND_CONSENSUS_PHASE2.md` (112) — system map, contracts-audit residuals (`01:…:140-152`), crypto posture, execution, consensus/VRF-gate. Answers: where does the audited construction plug in (sortition gate `consensus.rs:971,1080`, `vrf_output_for_cert` fallback matrix `consensus.rs:1123-1147`).
3. `docs/PQ_CN_VRF_SPEC.md` (701) — THE audit target. Answers: is §2 sound under assumptions A1–A3 only (§2.1–§2.9), are byte layouts fail-closed (§1.6), are O1–O10 resolved safely (§6).
4. `docs/PQ_VRF_FRONTIER_V2.md` (296) — why nothing else was chosen. Answers: was rejection of MAYO/CROSS/LMS/XMSS/threshold/STARK/DeuringVRF correct, and does the "own-scheme" combiner warning (`:246-278`) also apply to CN-VRF's hash-and-sign shape.
5. `docs/CLASSICAL_INVENTORY.md` (204) — classical leftovers with file:line. Answers: which classical paths survive the PQ cut (§§C/D/E) and which MUST NEVER be removed yet (rotation bootstrap, legacy-draw fallbacks, enforcement gates).
6. `docs/WORKCHAIN_DECISION.md` (203) — why workchain is parked, not cut. Answers: is single-shard-by-default actually the boot path (gate `sharding.rs:379,424,439` + `main.rs:8111`), and does parking leak into the audited surface.
7. `FEATURES.md` (104 rows) + `stellereum/scripts/audit-repro.sh` (426) + `docs/AUDIT_RED_CLOSURE.md:32-38,154-160` + `docs/PENTEST_NET_API.md` (121) — evidence state. Answers: what is green/red right now (RED: `pentest-net-api`), what PASS claims exist and their dates, what the two MEDIUM wontfix findings are (M1 liveness stall, M2 ban blast radius).
8. `docs/NEURAL_AUDIT_QUESTIONS.md` (this package) — exact audit questions §§1–6 + out-of-scope list with reasons.

Supplementary (NOT §3, cite only if needed): `docs/audits/COMPREHENSIVE_AUDIT_REPORT.md` (1722 lines; findings registry 35 rows: 26 FIXED / 5 HOLDS-VERIFIED / 2 ACCEPTED / 1 ESCALATED, `01_ARCHITECTURE_OVERVIEW_PHASE2.md:140-145`).

## 3. Readiness verdict

**NOT-YET.** Missing list (brutal):

1. `docs/program/` at the literal §3 path (mirror content exists only under `stellereum/docs/program/`).
2. Matrix 100% green — currently 102/104 with `pentest-net-api` RED (`FEATURES.md:107`).
3. Current `audit-repro` PASS log committed in-repo — only a 2026-10-31 cited PASS with an ephemeral `/tmp` path; current-tree PASS is UNVERIFIED.
4. Unified `PENTEST_*` summary with the DEFEATED/FINDING table — the "2× Low reputation accepted" residual has no table and no file:line; UNVERIFIED.
5. `NEURAL_AUDIT_QUESTIONS.md` — delivered with this package (closes the §3 "questions" bullet only).

A premature audit run wastes the run: items 2–4 are evidence the auditor nets must be able to trust.
