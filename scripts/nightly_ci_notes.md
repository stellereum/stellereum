# Nightly CI notes (no .github/workflows in tree)

## Why no `nightly.yml`

- `/home/imm/stellereum-project/.github/` does not exist (verified `ls`:
  "No such file or directory"). There is no `.github/workflows/ci.yml`
  to match runner labels / Rust toolchain / sccache-mold conventions from,
  so a workflow file would invent conventions against the task rules.
- Per task fallback: document here instead of adding `.github/workflows/nightly.yml`.
- To enable GitHub-hosted nightly later, lead creates `.github/workflows/`
  plus `ci.yml` first; then a `nightly.yml` can mirror its toolchain/cache
  settings and run `scripts/nightly_gate.sh` on `0 2 * * *` (02:00 UTC).

## Cron alternative (runs the existing gate)

Verified gate script: `scripts/nightly_gate.sh` (executable, 5 stages).
Install as the owning user (`crontab -e`):

    0 2 * * * cd /home/imm/stellereum-project && ./scripts/nightly_gate.sh >> artifacts/nightly.log 2>&1

Budget: QUALITY gate, allow 60 min (stages 2-4 dominate: lib tests,
economics fuzz battery, feature matrix).

## What the gate runs (all paths verified present)

1. `cd stellereum && cargo clippy --all-targets -- -D warnings`
2. `cd stellereum && cargo test --lib --no-fail-fast`
3. `cd stellereum && cargo test --test fuzz_economics_ext --no-fail-fast`
   (`stellereum/tests/fuzz_economics_ext.rs` exists)
4. `./scripts/feature_matrix.sh` (no flags; rows carry own timeouts)
5. `./stellereum/scripts/audit-repro.sh --quick`
   (`--quick` verified flag, line 42 of that script)

Exit 0 = all green; any failure prints `[NIGHTLY FAIL]` and exits nonzero.
Logs: `artifacts/` directory exists; gate appends to `artifacts/nightly.log`
via the cron redirect above.

## Notification stub (lead configures)

No secrets are stored in-tree. Lead option: wrap the cron line with a
mailer hook, e.g. append `|| mail -s "nightly FAIL" <addr> < artifacts/nightly.log`
after choosing an MTA/recipient, or add a GitHub workflow later with a
commented notification step once secrets exist.
