# CORE_JUNK_AUDIT — stellereum public repo (read-only audit, 2026-11-04)

Scope: `stellereum/` mirror of github.com/stellereum/stellereum. Method: `git ls-files`, `rg`, file reads. No modifications made. `node/` dir does **not exist** (UNVERIFIED assumption in brief — absent).

## 1. Verdict table

| Item | Path(s) | Verdict | Evidence |
|---|---|---|---|
| Internal strategy doc | `LAUNCH_STRATEGY.txt` (545 lines, tracked) | **REMOVE urgently** | Line 7: `Статус: Внутренний стратегический документ (не для публикации как есть)`; contains CEX/bridge/PMM/tokenomics roadmap, vuln journal (§12b), cargo-audit table (§15) |
| Marketing site | `site/` (index, 404, 6 css, 4 js, img, webmanifest; all tracked) | **ASK-LEAD: MOVE to separate repo** | NOT served by node binary: gateway HTML is inline static string (`src/explorer.rs:9`), served via `serve()` (`src/main.rs:8315-8324`); `site/` is stellereum.org static content living in node repo |
| Dev compose | `docker-compose.yml` (tracked) | KEEP (example) | Loopback binds + commented `change-me-before-exposing` tokens (`docker-compose.yml:25,29`); live-usable, correctly warned |
| Dev node config | `docker/node.yaml`, `Dockerfile` (tracked) | KEEP + harden note | `allow-unknown: true` dev TOFU (`docker/node.yaml`); `ENV STELL_*=0.0.0.0` fail-open dev defaults (`Dockerfile:45-46`, warned in-file) |
| Testnet examples | `testnet/node-a.yaml`, `node-b.yaml`, `genesis.env`, `README.md` (tracked) | KEEP (example) | All identities `PLACEHOLDER_*`; `STELL_FAUCET_KEY=PLACEHOLDER_…` (`genesis.env:125`); `STELL_RPC_AUTH_TOKEN=` empty |
| 4-node templates | `scripts/four-node/*.template` (tracked) | KEEP (example) | `COPY-FROM-ENV.A_*` placeholders, no real secrets |
| Monitor/systemd/proxy examples | `scripts/monitor/*`, `scripts/systemd/*`, `scripts/backup/*`, `docs/integrations/nginx-rpc.conf` (tracked) | **MOVE to private ops** (keep `nginx-rpc.conf` as KEEP — pure example, `OPERATOR` stubs) | `monitor/RUNBOOK.md:5` hardcodes live host `ssh root@212.113.103.105`; `systemd/*.service` hardcodes `/root/env.A`, `/root/nodeA` (`stell-nodeA.service:21,24`); `chain_diag.sh:6` hardcodes `HOST=root@212.113.103.105` |
| Operator scripts (safe) | `scripts/join-network.sh`, `add-peer.sh`, `health_check.sh`, `cluster_health.sh`, `stell-node.sh`, `audit-repro.sh`, `stall_watchdog.sh`, `logrotate.stellereum` | KEEP | Loopback defaults, `join-network.sh:224` explicitly "Public keys only — no secrets here" |
| NFT/font clutter | `scripts/generate_stl_card.py`, `render_font_compare.py`, `test_centering.py`, `test_reference_style.py` | **DELETE** | Card-art/font test scripts, not node tooling |
| Load/probe tools | `scripts/tps_load.py`, `tvl_probe.py` | ASK-LEAD (KEEP vs MOVE) | `tps_load.py` imports live `Ed25519PrivateKey`, mints keys at runtime — legit load tool, but attack-adjacent in public tree |
| Attack/dev examples | `examples/` (34× `.rs`: `vuln_hunt*.rs`, `chaos_audit*.rs`, `attack_demo.rs`, `repro_fail.rs`, `p3_profile_tmp.rs`, …) | **ASK-LEAD: MOVE to private harness** | Adversarial/throwaway harnesses (`repro_fail`, `*_tmp`, `vuln_hunt2-5`) ship in public node repo |
| Contracts | `contracts/*.wat`, `sts20_token_abi.json` | KEEP (public-essential) | On-chain sources (e.g. `sts20_token.wat` header: host sload/sstore/emit) |
| Benches | `benches/*.rs` (9 files) | KEEP | Standard cargo benches |
| Fuzz harnesses | `fuzz/fuzz_targets/*.rs` (7 targets) | KEEP | Corpus/artifacts correctly gitignored (`.gitignore`: `fuzz/corpus/*`, `fuzz/artifacts/`) |
| User-facing docs | `README.md`, `NODE.md`, `PROTOCOL.md`, `VALIDATOR.md`, `SECURITY.md`, `docs/{RPC,OPERATIONS,VALIDATOR_ONBOARDING,RPC-adjacent}*.md`, `docs/audits/*`, `docs/brand/*` | KEEP | Public operator/user surface |
| **Leaked internal docs** | `docs/program/**` (incl. `specs/`, `ops/`) | **MOVE to private** | `specs/00_PROJECT_MAP.md:33,36`: live hosts `root@212.113.103.105`, `root@138.124.102.200`; `specs/01_ARCHITECTURE_OVERVIEW.md:26-27`: live IPs `212.113.103.105`, `77.110.96.68:2222`, `138.124.102.200`; `ops/` = runbooks (`backup_runbook`, `upgrade_rehearsal`, `status_page`, `LOCAL_VALIDATION`) |
| Integration drafts | `docs/integrations/chainlist.json`, `defillama-adapter.md` | ASK-LEAD: strip + submit, then clean | `chainlist.json:25` `_comment` = internal BLOCKER notes + `_temporary_rpc_fallback`, `_strip_before_pr` keys (must strip pre-PR per file's own instruction) |
| Build artifact (tracked!) | `scripts/__pycache__/tps_load.cpython-314.pyc` | **DELETE** | Compiled bytecode committed (`git ls-files scripts/` hits it) |

## 2. DELETE list (exact paths, lead to execute)

- `LAUNCH_STRATEGY.txt` (internal strategy — remove from public urgently; keep privately)
- `scripts/__pycache__/tps_load.cpython-314.pyc`
- `scripts/generate_stl_card.py`
- `scripts/render_font_compare.py`
- `scripts/test_centering.py`
- `scripts/test_reference_style.py`

## 3. Secrets / real-IP hits

**No real private keys, seeds, or API tokens in any TRACKED file — clean.** All secret-shaped hits are placeholders/empty/commented (`PLACEHOLDER_*`, `COPY-FROM-ENV.A_*`, `STELL_RPC_AUTH_TOKEN=` empty in `testnet/genesis.env:225` and `scripts/join-network.sh:341`, `change-me-before-exposing` commented in `docker-compose.yml:29`). `keys/*.key`, `data/*` exist on local disk but are gitignored (`.gitignore`: `/keys`, `/data`, `*.key`) and **not tracked** — never commit them.
**Real live-infra IPs in public tracked files (exposure, not key leak):**

- `scripts/chain_diag.sh:6` — `HOST="root@212.113.103.105"`
- `scripts/monitor/RUNBOOK.md:5` — `ssh root@212.113.103.105`
- `stellereum/docs/program/specs/00_PROJECT_MAP.md:33,36` — `root@212.113.103.105`, `root@138.124.102.200`
- `stellereum/docs/program/specs/01_ARCHITECTURE_OVERVIEW.md:26-27` — `212.113.103.105`, `77.110.96.68:2222`, `138.124.102.200`
- (Reference/test-net IPs `203.0.113.7`, `198.51.100.9`, `1.2.3.4`, `8.8.8.8` in tests/docs are RFC-5737 documentation ranges — not real.)
- `0.0.0.0` binds (`docker/node.yaml:3`, `testnet/node-a.yaml:53`, `Dockerfile:45-46`) are fail-open dev defaults with in-file warnings — config risk, not a leak.

## 4. ASK-LEAD list

1. `site/` — MOVE to dedicated web repo, or formally KEEP? (harmless, but not node code)
2. `examples/` (34 files, incl. `vuln_hunt*`, `chaos_audit*`, `attack_demo`, `repro_fail`, `p3_profile_tmp`) — MOVE whole dir to private security harness?
3. `scripts/tps_load.py`, `tvl_probe.py` — KEEP as public load tools or MOVE private?
4. `docs/integrations/chainlist.json` + `defillama-adapter.md` — strip `_`-keys and file PRs, then delete drafts from repo?
5. `scripts/{stell-node.sh,chain_diag.sh,monitor/,backup/,systemd/}`, `docs/program/**` — MOVE to private ops repo (they embed live host/IP + `/root/` layout)?
6. `docs/OPERATIONS.md:549`, `docs/RPC.md` staleness notes — confirm public accuracy after moves.
