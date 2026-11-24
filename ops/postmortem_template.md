# Postmortem: <short title>

> Copy this file to `docs/postmortems/YYYY-MM-DD-<slug>.md`, fill it in within
> 5 business days of the incident being closed, and link it from the release
> notes of the fixing version. Blameless: describe systems and decisions, not
> people. The value is in the "why it was possible", not in "who pressed it".

## Summary

One paragraph a non-engineer can follow: what broke, for whom, for how long.

## Impact

| Question | Answer |
|---|---|
| User-visible impact | e.g. public RPC down / chain halted / no block for N s |
| Duration | start (UTC) → detection → mitigation → full recovery |
| Blast radius | which validators / endpoints / clients |
| Data or funds at risk | none / bonded stake slashed by X / funds moved |
| Detection | alert name, or "a human noticed" (that is a finding too) |

## Timeline (UTC)

| Time | Event |
|---|---|
| 00:00 | first anomaly (from logs, not memory) |
| 00:00 | detected by (alert / operator / user report) |
| 00:00 | first mitigation attempt and its outcome |
| 00:00 | service restored |
| 00:00 | root cause confirmed |

## Root cause

The mechanism, not the trigger. "The store ran out of inodes because the chunk
sweeper's grace period exceeded the disk's inode budget" — not "nodeC crashed".

## What made it worse

The second-order effects: a guard restarting the node into a double instance, a
missing alert, a manual step that needed a key that was offline, a dashboard
that showed the wrong thing.

## What went well

Keep the things that should survive the next refactor.

## Action items

| Action | Owner | Type (prevent / detect / mitigate) | Tracked as |
|---|---|---|---|
| … | … | … | `docs/OPEN_DEFECTS.md` id or issue |

Every action item gets an id in `docs/OPEN_DEFECTS.md` (or an issue) before this
postmortem is merged — otherwise it is a wish, not a fix.

## Signals to add

Which metric or alert would have caught this earlier? Add it in the same PR as
the action items when it is cheap (the Wave 1 stack now carries efficiency,
apply p95, CPU per block, disk and inode rules).

## Related

- fixing commit(s):
- defect id(s):
- runbook used (or missing — if missing, that is an action item):
