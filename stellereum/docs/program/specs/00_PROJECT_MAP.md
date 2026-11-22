# 00 — Project Map (HDAE canonical, 2026-10-29)

The whole repo on one page. Details in `01-04_*.md`. Status in `STATUS.md`.
Work in `../ROADMAP.md`.

## Trees (only `stellereum/` is canonical — `stellereum_head/`, `w8/` are stale copies, never touch)

```
stellereum-project/
├── stellereum/               # CANONICAL NODE (60 src files, crate `stellereum`)
│   └── src/                  # consensus, runtime, main loop, sharding, state_engine,
│                             # cpat2 trie, staking, contract/VM, rpc, mempool, PQ
├── infnode/    # crates/infnode (QUIC+DHT) + crates/infmail (webmail)
├── stellereum-contracts/     # contracts/{stl-dns,sts20-token,liquidity-pool,account-object}
│                             # + crates/{stellereum-sdk,e2e-tests}
├── stellereum-indexer/       # SQLite indexer, /api/v2
├── stellereum-sdk/           # canonical client SDK
├── stell-wallet/             # wallet CLI + light client (lib+bin)
├── scripts/tools/stelops/    # operator CLI (checkpoints, divergence scan)
├── scripts/                  # verify_testnet_ideal.sh, harness_status.sh, stell-sync.sh,
│                             # watchdog, agents/{spawn,merge,TASK_PROMPT}
├── docs/specs/               # THIS MAP + 01-04 + CRATE_ISOLATION_PLAN (truth)
├── handoff/                    # ALL session handoffs, one folder (history only)
├── docs/audits/              # COMPREHENSIVE_AUDIT_REPORT.md (PART I byte-frozen)
├── .archive/                 # retired diaries (never read for truth)
└── multinode/                # LIVE node B data — DO NOT TOUCH
```

## Live cluster (read-mostly!)

| Node | Where | Role |
|---|---|---|
| A | `root@212.113.103.105` `/root/nodeA` | validator + snapshot server, `https://rpc.stellereum.org` |
| B | local `multinode/nodeB` `:8546` | validator (LIVE DATA — never delete) |
| C | `ssh -p 2222 root@77.110.96.68` `/root/nodeC` | validator, 1 vCPU (slow) |
| D | `root@138.124.102.200` `/root/nodeD` | validator, 1 vCPU (slow) |

N=4, set 4/4 non-fragile, quorum `(2n/3)+1` power. Tempo: p50 bursts ~0.5s, mean ~2-3s.

## Gates (the law)

`./scripts/verify_testnet_ideal.sh [--fast]` → scan + `clippy -D warnings` (7 ws) + tests + sim.
`./scripts/harness_status.sh` → regenerates `STATUS.md` + `artifacts/harness_status.json`.
`just gate-all / gate-fast / sim-local / status` (needs `just` installed).
