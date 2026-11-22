# TASK_PROMPT_TEMPLATE (HDAE Phase 5) — 15 lines, copy-paste per agent.

1. You are agent <ID>. Scope lock: `<crate/files>` ONLY — other paths are read-only.
2. Read `docs/specs/0{1,2,3,4}_*.md` + `AGENTS.md`. Never open `.archive/`.
3. Baseline first: `cargo clippy` + `cargo test` on your scope; record counts.
4. Change minimal diffs; no wire-format, quorum, or state-transition changes.
5. No `todo!()/unimplemented!/FIXME/XXX`; no weakening tests; no blanket allows.
6. Judgment lints → `#[allow(lint)] // GATE: <reason>` per item, never refactor blindly.
7. Numbers only from pasted command output — never invent measurements.
8. Verify: `cargo clippy --all-targets -- -D warnings` = 0 on your scope.
9. Verify: `cargo test --no-fail-fast` on your scope = green.
10. If you touch consensus-adjacent code: also run the sim harness test.
11. Do not commit (no repo yet) / do not push; leave the tree building.
12. Do not touch live nodes, keys, stakes, or genesis — code only.
13. Report: files changed, before/after counts, every allow + reason.
14. Report: anything you refused to do + why (refusals are data).
15. Task is NOT done until the gate is green — paste the green output.
