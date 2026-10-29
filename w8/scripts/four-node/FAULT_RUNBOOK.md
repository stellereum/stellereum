# 4-validator fault-injection runbook (PREPARED, NOT EXECUTED)

Stand: single server root@`<VALIDATOR_HOST>` (operator-held address — not stored
in this repo), /root/nodeA/B/C/D, P2P 9410–9413,
RPC 127.0.0.1:8545–8548, control script /root/stell-node.sh
(+ `start4`/`stop4`/`status4`/`wipe4` from scripts/stell-node.sh in this repo —
copy it to /root/stell-node.sh in the maintenance window before use).
All commands below run over ssh on the server. Nothing below has been run.

## §0. Preconditions — read before touching anything

1. **The 2→4 change is a new genesis, unconditionally.** The validator set is
   funded into genesis state (`Genesis: funded N validator account(s)`), so
   adding C/D changes the genesis root even on the SAME binary. There is NO
   additive "just add C/D to the live chain" path: the window requires
   `stop` + wipe ALL data dirs + start all four. The live 2-node chain and its
   data will not survive the experiment; plan to rebuild it on rollback (§e).
2. **Deployed binary is behind repo HEAD.** The running binary predates several
   `COMMITMENT_VERSION` bumps (`src/commitment.rs` at HEAD says 5; the
   stand's genesis lineage is 2). A fresh HEAD deploy ALSO changes genesis and
   needs a wipe. Recommendation: run the fault-injection experiment FIRST on
   the CURRENT binary (isolates the fault-injection variables from the
   hard-fork change), then schedule the HEAD deploy+wipe as a SEPARATE step.
   Do not combine the two changes in one window — if genesis mismatches you
   will not know which change caused it.
3. **Live genesis root note (discrepancy on record).** The task brief cites
   genesis root `a927873a`; the live logs actually show
   `Genesis: funded 2 validator account(s); state root
   d0f01b289be22152df7c0479fae32a8989c251bb78a390522cda158e7bfccab4`
   (2026-09-26, both nodes, `Genesis fingerprint matches the persisted
   chain`). Trust the files: `d0f01b28…` is the deployed 2-node genesis root.
4. Back up `/root/nodeA/node.yaml`, `/root/nodeB/node.yaml`, `/root/env.A`,
   `/root/env.B` off-host before the window. Env files are mode 600 — keep
   them that way for env.C/env.D.
5. Quorum math (unit power, `floor(2*total/3)+1`): 4 validators → quorum 3.
   One node down MUST keep finalizing; two down MUST stall; stalling MUST NOT
   fork (both sides report the SAME last finalized hash).

## (a) Verify all four finalize the same root

```sh
ssh root@<VALIDATOR_HOST>
export PATH=$PATH:/root/.cargo/bin
/root/stell-node.sh status4
# per-node heights (expect four equal, non-zero hex values):
for p in 8545 8546 8547 8548; do
  printf "RPC %s: " "$p"
  curl -s -m 5 -X POST "http://127.0.0.1:$p" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}'
  echo
done
# per-node last finalized line (expect SAME block # + hash + state root ×4):
for n in A B C D; do grep -o 'FINALIZED block #[0-9]* [0-9a-f]* (state root [0-9a-f]*' "/root/node$n/current.log" | tail -1; done
sleep 5
/root/stell-node.sh status4   # run again: heights must have ADVANCED since the first run
```

Expected output: `status4` prints `HEALTHY: all four nodes agreed on the last
finalized block and root`; the four `FINALIZED` lines are identical; the
second `status4` shows HIGHER heights than the first (chain is advancing, not
just answering RPC — a stalled node answers RPC at a frozen height forever).
`grep -c FINALIZED` counts grow between polls on all four nodes.

Abort if: any node's last finalized hash/root differs from the others
(divergence = split, stop immediately, see §f); any node reports no FINALIZED
line 60 s after start (not joined — check its `validators:`/`peers:` and
`STELL_FAUCET_KEY` before proceeding); `lacks a validator quorum` in any log
(stale pre-quorum data dir — wipe that node and restart it).

## (b) Kill ONE node (STOP), verify the other three keep finalizing

```sh
# Identify nodeD's pid WITHOUT touching A/B/C (match by working directory):
ps -o pid,cwd -C stellereum | awk '$2=="/root/nodeD"{print $1}'
kill -STOP <nodeD-pid>          # freeze D; it stays alive but gets no CPU
sleep 10
/root/stell-node.sh status4
for p in 8545 8546 8547; do
  printf "RPC %s: " "$p"
  curl -s -m 5 -X POST "http://127.0.0.1:$p" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}'
  echo
done
grep -o 'FINALIZED block #[0-9]* [0-9a-f]* (state root [0-9a-f]*' /root/nodeD/current.log | tail -1
```

Expected output: A/B/C heights ADVANCE across two polls and agree on new
finalized roots; D's last FINALIZED line is FROZEN at the pre-STOP block; D's
RPC (8548) answers but its height does not move; no view-change storm in
A/B/C logs (occasional view changes are normal; a 3 s periodic loop on all
three is not — but with 3-of-4 alive you should see steady FINALIZED lines).

Abort if: A/B/C stall with one node stopped (quorum should be 3-of-4 — a
stall here means the validator set is NOT {A,B,C,D} on all nodes; stop the
experiment, compare the four derived sets via the `Consensus: N validator(s)`
startup lines, fix the yamls, wipe, restart).

## (c) Kill TWO nodes, verify the chain STALLS WITHOUT forking

```sh
ps -o pid,cwd -C stellereum | awk '$2=="/root/nodeC" || $2=="/root/nodeD"{print $1}'
kill -STOP <nodeC-pid> <nodeD-pid>   # D already STOPped from (b); now C too
sleep 12   # > 3× the 3 s view-change timeout, so a live chain would have moved
H1_A=$(grep -o 'FINALIZED block #[0-9]* [0-9a-f]* (state root [0-9a-f]*' /root/nodeA/current.log | tail -1)
H1_B=$(grep -o 'FINALIZED block #[0-9]* [0-9a-f]* (state root [0-9a-f]*' /root/nodeB/current.log | tail -1)
echo "A: $H1_A"; echo "B: $H1_B"
sleep 10
H2_A=$(grep -o 'FINALIZED block #[0-9]* [0-9a-f]* (state root [0-9a-f]*' /root/nodeA/current.log | tail -1)
H2_B=$(grep -o 'FINALIZED block #[0-9]* [0-9a-f]* (state root [0-9a-f]*' /root/nodeB/current.log | tail -1)
echo "A: $H2_A"; echo "B: $H2_B"
# A and B RPC heights should be frozen too:
for p in 8545 8546; do curl -s -m 5 -X POST "http://127.0.0.1:$p" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}'; echo; done
```

Expected output: `H1_A == H2_A` and `H1_B == H2_B` (nothing finalizes with
2-of-4 alive — power 2 < quorum 3); **and `H1_A == H1_B`** — both survivors
report the SAME last finalized hash (stall without fork). A/B logs show the
`view change -> height N round R` loop re-broadcasting votes (that loop IS the
healthy-stall signature); FINALIZED counts do NOT grow.

Abort if (this is the critical safety check): A and B report DIFFERENT last
finalized hashes — that is a FORK, not a stall. `kill -CONT` the stopped
nodes immediately, `stop` everything, preserve all four `current.log` files
off-host, and restore the 2-node stand (§e). Do not attempt to "heal" a fork
by restarting one side.

## (d) Restart the killed nodes, verify reconvergence

```sh
kill -CONT <nodeC-pid> <nodeD-pid>   # same pids as (b)/(c); STOP/CONT keeps process state
sleep 15
/root/stell-node.sh status4
for n in A B C D; do grep -o 'FINALIZED block #[0-9]* [0-9a-f]* (state root [0-9a-f]*' "/root/node$n/current.log" | tail -1; done
sleep 10
/root/stell-node.sh status4   # heights must advance past the §c stall point
```

Expected output: C/D catch up via headers/snapshot sync (no wipe needed —
STOP/CONT preserves their data dirs); `status4` returns to
`HEALTHY: all four nodes agreed…`; all four FINALIZED lines identical and
HIGHER than the §c stall height; per-node `grep -c FINALIZED` growing on all
four. (If a CONTed node never catches up within 120 s, `stop` just that node
— do NOT `kill -9` a running validator mid-write — wipe its data dir and
`start4` it; it re-syncs from genesis/snapshot. That is a test finding, not a
rollback trigger, provided the other three kept finalizing.)

## (e) Roll back: stop4, wipe4, restore the 2-node stand

```sh
/root/stell-node.sh stop4            # stops nodeC/D processes only (matched by cwd)
/root/stell-node.sh wipe4            # stops C/D if any linger + deletes nodeC/D data dirs
# Restore the backed-up 2-node configs (validators: back to [peer], peers back
# to the single peer entry each):
cp /backup/nodeA.node.yaml /root/nodeA/node.yaml
cp /backup/nodeB.node.yaml /root/nodeB/node.yaml
# The 4-node window ran a DIFFERENT genesis, so A/B data is unusable now:
/root/stell-node.sh stop
rm -rf /root/nodeA/data /root/nodeB/data
/root/stell-node.sh start
/root/stell-node.sh wait             # blocks until both nodes are advancing
/root/stell-node.sh status           # expect: HEALTHY, both agreed, 2 validators
# Optional: remove the C/D scaffolding entirely:
rm -rf /root/nodeC /root/nodeD /root/env.C /root/env.D
```

Expected output: `wait` prints `READY: both nodes are advancing`; `status`
prints `HEALTHY: both nodes agreed on the last finalized block and root` with
the ORIGINAL 2-node genesis (`funded 2 validator account(s)` in fresh logs).
Keep the §(a)–(d) logs off-host before wiping.

## (f) Abort criteria — stop the experiment and restore §e when ANY holds

1. **Divergence at any point**: two nodes report different last-finalized
   hashes/roots for the same height (or any height). That is a split/fork.
   Freeze (do not wipe yet), copy all logs + yamls + envs off-host, then §e.
2. **One STOP stalls the chain** (§b): quorum should be 3-of-4. Stall means
   the four nodes did not derive the same {A,B,C,D} set — a config error, not
   a consensus result. Restore §e, fix yamls per VALIDATOR_SET_PLAN.md.
3. **Two STOPs keep finalizing** (§c): progress with power 2/4 means quorum is
   misconfigured (or a partition healed oddly). Treat as criterion 1.
4. **`lacks a validator quorum` in any fresh log**: stale pre-quorum data dir
   mixed into the run. Wipe the affected node; if it persists after a full
   wipe-all + restart, abort to §e (binary/genesis mismatch — likely the
   COMMITMENT_VERSION 2-vs-5 split, see §0.2).
5. **Time budget**: any phase not reaching its expected output within 10 min
   of steady-state waiting (genesis/join 10 min; catch-up after CONT 10 min).
   Collect logs, restore §e, diagnose off the live box.
6. **Operator errors**: wrong pid STOPped/CONTinued (always match pids by
   `ps -o pid,cwd`, never by bare `pgrep`), env secret mismatch, or any
   restart of nodeA/B outside this runbook. When in doubt, §e first.
