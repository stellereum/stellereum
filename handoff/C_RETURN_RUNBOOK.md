C RETURN RUNBOOK (for the friend operator, server 77.110.96.68)
============================================================
Situation: nodeC stopped, still a set member (power ~1865, slowly slashed
for downtime). Chain lives without C (A+B finalize). Return = free 1/3
of slots back + tempo 0.7-1.6s. No hurry, no wipe needed.

SSH: ssh -p 2222 root@77.110.96.68

1. Fetch the unified binary (ask imm for the current URL/path, then):
   sha256sum /root/nodeC/stellereum   # must match the announced hash
   # deploy to the service ExecStart path (check: systemctl cat stell-nodeC)

2. Config check (do NOT change keys in /root/nodeC/keys/ — ever):
   grep -c . /root/nodeC/node.yaml    # peers A + B present
   env | grep -E "STELL_OBSERVER|STELL_NEW_CHAIN" || true
   # STELL_OBSERVER must be UNSET for a validator return.
   # If the node was an observer, unset it BEFORE starting.

3. Bond buffer: power ~1865, MIN 1000, floor 1100 for NEW bonds.
   Existing power is grandfathered — no top-up needed to vote.
   (Optional later: top up toward 2000 via stake for symmetry.)

4. Start: systemctl start stell-nodeC
   Watch: journalctl -u stell-nodeC -n 100
   Expect IN ORDER, ~2-5 min:
     a. "validator set refreshed ... -> [021776cd:..., 9c675ebc:..., c2313fba:...]"
     b. snapshot/sync lines, height climbing toward live tip
     c. "FINALIZED block #<live>" with roots matching the explorer
     d. propose-gate lines with scheduled=<own/others> rotating

5. Verify from outside (ask imm or check explorer):
   stell_getValidators shows 3 voters, chain tempo back under ~2s.

6. Red flags (stop and call imm, do NOT wipe):
   - "genesis state root mismatch" (wrong binary/config — check hash first)
   - "stale validator set" WARN persisting >10 min
   - height stuck >10 min while A/B advance
   - disk >85% (df -h /root) — prune: STELL_ARCHIVE=0 + KEEP_BLOCKS=4000
     must be set (check env file)

NEVER: wipe /root/nodeC/data to "fix" sync (protocol resyncs itself);
copy data dirs between machines; share keys; run two nodes on one key.
