# C2 — downgraded to docs-only (verifier-killed, test-only)

## Status

**CLOSED — no code change.** C2 was downgraded to docs-only: the agent-review
verifiers killed it as a test-only false positive, i.e. reachable only through
test helpers / deterministic setups, not through any production path.

## What C2 was (recovered record)

C2 belonged to the 2026-10-08 .. 2026-10-10 agent security review
(6 hunters + 3 verifiers). The single surviving in-repo record is the handoff
line in `docs/handoff/STELLEREUM_SESSION_2026-10-10.txt` §4:

> Верификаторы убили ложняки (B2, B3-test-only, B4, B6, **C2-test-only**,
> E11, F11, F12 + понижения).

Verification performed 2026-10-10 (branch `wip/passport-agents`):

* `grep -rn "C2" tests/` — no hunt test, no PoC, no `FINDING C2` block
  (only incidental byte-literals `0xC1/0xC2` in bridge tests).
* `git log --all --oneline --grep C2 -i` — empty; no commit ever mentions C2.
* Bridge/xshard fix commits (`c5a1883`, `70c8a08`) close C1/C3/C4/C5/C7/C8/C9
  and never reference C2 — consistent with "killed before it became a fix".

So there is **no surviving PoC to reproduce and nothing to re-verify in code**:
the C-series siblings that were real (C1 anchored inclusion, C3 revoke burn,
C4 mirror gate, C5 scaled bond, C7 shard gate, C8 chain tag, C9 BPS) all have
fix commits + tests; C2 does not, because the verifiers judged it
unreachable outside test scaffolding.

## What "test-only" means here (precedent)

Same bar as the F2 test-VK finding (`hunt_staking_grief.rs`, `svm.rs:2183`):
a claim that reproduces only via `setup_test_only` / hand-fed harness state —
never via `apply_block_transition`, gossip, or RPC on a live node — is a
harness artifact, not a chain vulnerability. C2 fell in that bucket.

## Standing rule

Reopen C2 as a code item iff someone produces a PoC that reaches the alleged
behavior through a production entry point (live block apply, consensus
message, or public RPC). Until then: docs-only, no tracking test, no fix.
