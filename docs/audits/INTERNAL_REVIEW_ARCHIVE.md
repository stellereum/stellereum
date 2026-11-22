# Internal Review Archive Note

In-tree review/pentest working logs (agent diaries, review-wave notes,
PENTEST/NEURAL_AUDIT drafts, junk-audit scratch files) were removed from the
public tree: **87 files** removed from disk/tree, plus `AGENTS.md` untracked but
kept on disk. Legacy notes remain in local git history only.

Authoritative public evidence:

- `SECURITY.md` — threat model, disclosure policy, security posture.
- `docs/audits/` — dated audit reports and findings.
- `docs/OPEN_DEFECTS.md` — current defect register (0 open defects).
- `docs/ROADMAP.md` and the test suite (`cargo test`, regression tests).

No finding was deleted without a fix or an explicit note in `OPEN_DEFECTS.md` / `ROADMAP.md`.
