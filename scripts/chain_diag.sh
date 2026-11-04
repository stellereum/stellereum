#!/usr/bin/env bash
# One-shot chain health diagnostic. Replaces ~50 ad-hoc greps: prints heights,
# rounds, vote alignment, mempool, blockers, transport errors, disk, procs.
# Usage: ./chain_diag.sh   (runs against the stand via ssh)
set -u
HOST="${STELL_HOST:-root@203.0.113.10}"
ssh -o ConnectTimeout=10 "$HOST" '
echo "===== processes/disk ====="
ps -eo args | grep -c "[s]tellereum run"
df -h / | tail -1 | awk "{print \$5 \" used\"}"
echo "===== heights (status) ====="
/root/stell-node.sh status 2>&1 | tail -6
for N in nodeA nodeB; do
  LOG=/root/$N/current.log
  echo "===== $N ====="
  echo -n "rounds: "; grep -h "view change" $LOG 2>/dev/null | tail -1 | grep -o "height [0-9]* round [0-9]*" || echo none
  echo -n "finalized: "; grep -h "FINALIZED" $LOG 2>/dev/null | tail -1 | grep -o "#[0-9]* [0-9a-f]*" || echo none
  echo -n "adopted: "; grep -h "adopted committed" $LOG 2>/dev/null | tail -1 | grep -o "#[0-9]* [0-9a-f]*" || echo none
  echo -n "proposes: "; grep -hc "proposed block" $LOG 2>/dev/null; grep -h "proposed block" $LOG 2>/dev/null | tail -1 | grep -o "r[0-9]* [0-9a-f]* txs=[0-9]*" || true
  echo -n "nils: "; grep -h "RX Prevote" $LOG 2>/dev/null | grep -c nil
  echo -n "blockers: "; grep -h "FINALIZE-BLOCKED" $LOG 2>/dev/null | tail -1 | grep -o "h=[0-9]* r=[0-9]*.*" || echo none
  echo -n "rejects: "; grep -h -c "rejected proposal" $LOG 2>/dev/null
  echo -n "timeouts/errs: "; grep -h -c "TIMEOUT after\|transport-err\|denied" $LOG 2>/dev/null
  echo -n "parse-fails: "; grep -h -c "unparseable" $LOG 2>/dev/null
  echo -n "propose-path: "; grep -h "propose h=" $LOG 2>/dev/null | tail -1 | grep -o "path=[a-z]* selected=[0-9]* mempool=[0-9]*.*" || echo none
done
echo "===== mempool/RPC ====="
curl -s -m 10 -X POST http://127.0.0.1:8545/ --header "Content-Type: application/json" --data "{\"jsonrpc\":\"2.0\",\"method\":\"stell_mempoolSize\",\"params\":[],\"id\":1}"; echo
curl -s -m 10 -X POST http://127.0.0.1:8545/ --header "Content-Type: application/json" --data "{\"jsonrpc\":\"2.0\",\"method\":\"stell_latestBlocks\",\"params\":[],\"id\":1}" | python3 -c "import sys,json; bs=json.load(sys.stdin)[\"result\"]; print(\"latest:\", [(b[\"height\"],b[\"txs\"]) for b in bs[:5]])" 2>/dev/null || echo "latestBlocks failed"
'
