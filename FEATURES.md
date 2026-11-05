# FEATURES — E2E matrix (machine-generated, do not hand-edit)

Regenerate: `./scripts/feature_matrix.sh`. RED = missing/broken functionality,
owned work order. SKIP = environmental (reason in row), never a pass.

| feature | ws | status | secs | detail |
|---|---|---|---|---|
| pq-keygen-sign-verify | stell-wallet | ❌ RED | 63 |  |
| pq-chain-binding | stell-wallet | ❌ RED | 14 |  |
| pq-fee | stell-wallet | ❌ RED | 20 |  |
| wallet-rpc-token | stell-wallet | ❌ RED | 3 |  |
| wallet-security | stell-wallet | ❌ RED | 3 |  |
| wallet-privacy | stell-wallet | ❌ RED | 3 |  |
| wallet-multimgmt | stell-wallet | ❌ RED | 19 |  |
| wallet-delegation | stell-wallet | ❌ RED | 25 |  |
| wallet-live-node | stell-wallet | ❌ RED | 4 |  |
| pq-nondeterminism-pin | stellereum | ✅ GREEN | 65 | test result: ok. 41 passed; 0 failed; 0 ignored; 0 measured; 1052 filtered out; finished in 8.68s; |
| aa-session-keys | stellereum | ❌ RED | 51 |  |
| aa-session-budget | stellereum | ❌ RED | 38 |  |
| paymaster | stellereum | ❌ RED | 57 |  |
| evm-flows | stellereum | ❌ RED | 21 |  |
| contracts-node-side | stellereum | ❌ RED | 30 |  |
| clob-settle | stellereum | ❌ RED | 15 |  |
| one-call-order | stellereum | ❌ RED | 7 |  |
| bridge-attest | stellereum | ❌ RED | 10 |  |
| shielded | stellereum | ❌ RED | 0 |  |
| confidential-solvent | stellereum | ❌ RED | 0 |  |
| halt-not-fork | stellereum | ❌ RED | 14 |  |
| liveness-harness | stellereum | ❌ RED | 23 |  |
| 4node-adversarial | stellereum | ❌ RED | 46 | test result: FAILED. 0 passed; 5 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| slash-equivocation | stellereum | ❌ RED | 1 | test result: FAILED. 0 passed; 5 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| proposal-refire | stellereum | ✅ GREEN | 1 | test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| snapshot-resume | stellereum | ✅ GREEN | 1 | test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.82s; |
| mmr-epoch | stellereum | ✅ GREEN | 1 | test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s; |
| light-client | stellereum | ❌ RED | 1 | test result: FAILED. 0 passed; 18 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| xshard-2pc | stellereum | ❌ RED | 1 | test result: FAILED. 2 passed; 9 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| split | stellereum | ❌ RED | 1 | test result: FAILED. 0 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| vel-tempo | stellereum | ❌ RED | 39 | test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 37.44s; |
| tempo-lan | stellereum | ❌ RED | 28 | test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 11.46s; |
| mev-seal | stellereum | ❌ RED | 1 | test result: FAILED. 26 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s; |
| sts20-onchain | stellereum-contracts | ❌ RED | 110 | test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s; |
| dns-onchain | stellereum-contracts | ❌ RED | 0 | test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s; |
| pool-onchain | stellereum-contracts | ❌ RED | 0 | test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s; |
| account-object-onchain | stellereum-contracts | ❌ RED | 0 | test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s; |
| adversarial-e2e | stellereum-contracts | ❌ RED | 2 | test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| indexer-api | stellereum-indexer | ✅ GREEN | 112 | test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s; |
| verify-once | stellereum | ❌ RED | 1 | test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| p2p-reputation | infnode | ✅ GREEN | 9 | test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.01s; |
| validator-ux | stellereum | ✅ GREEN | 1 | test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| snapshot-set-binding | stellereum | ❌ RED | 1 | test result: FAILED. 7 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| fee-determinism | stellereum | ✅ GREEN | 0 | test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 1090 filtered out; finished in 0.00s; |
| pq-registry | stellereum | ✅ GREEN | 1 | test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s; |
| light-rotation | stellereum | ❌ RED | 0 | test result: FAILED. 0 passed; 6 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| chaos-n4 | stellereum | ❌ RED | 2 | test result: FAILED. 0 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.23s; |
| slash-drill | stellereum | ❌ RED | 2 | test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.34s; |
| tempo-recipe | stellereum | ❌ RED | 7 | test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.91s; |
| cn-vrf-kats | stellereum | ✅ GREEN | 1 | test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s; |
| bls-classical | stellereum | ❌ RED | 0 |  |
| vrf-marker | stellereum | ✅ GREEN | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1092 filtered out; finished in 0.00s; |
| explorer-ux | stellereum | ❌ RED | 2 | test result: FAILED. 2 passed; 13 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s; |
| wallet-pq | stellereum | ❌ RED | 1 | test result: FAILED. 5 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.43s; |
| faucet-pq | stellereum | ❌ RED | 1 | test result: FAILED. 0 passed; 6 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s; |
| fuzz-economics-ext | stellereum | ✅ GREEN | 6 | test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.67s; |
| byzantine | stellereum | ❌ RED | 3 | test result: FAILED. 0 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.46s; |
| liveness-breaker | stellereum | ❌ RED | 2 | test result: FAILED. 0 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.51s; |
| sync-adversarial | stellereum | ✅ GREEN | 2 | test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.81s; |
| staking-invariants | stellereum | ✅ GREEN | 1 | test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s; |
| storage-crash | stellereum | ✅ GREEN | 1 | test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s; |
| shard2-soak | stellereum | ❌ RED | 1 | test result: FAILED. 0 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| pq-gates | stellereum | ❌ RED | 1 | test result: FAILED. 13 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.19s; |
| light-cli | stellereum | ❌ RED | 1 | test result: FAILED. 0 passed; 6 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| rpc-ws | stellereum | ✅ GREEN | 8 | test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.67s; |
| fee-parity | stellereum | ❌ RED | 10 | test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s; |
| eclipse | infnode | ✅ GREEN | 5 | test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.31s; |
| privacy-pq | stellereum | ⏭️ SKIP | 0 | privacy_pq_tests.rs absent at runtime |
| kem-kat | infnode | ✅ GREEN | 0 | test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s; |
| mev-plan | stellereum | ✅ GREEN | 1 | test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 1084 filtered out; finished in 0.00s; |
| contracts-regression | stellereum-contracts | ✅ GREEN | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s;test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s;test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s;test result: ok. 3 |
| cpu-budget | stellereum | ❌ RED | 3 | test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s; |
| snapshot-cadence | stellereum | ✅ GREEN | 2 | test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s; |
| tempo-sustained | stellereum | ❌ RED | 20 | test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 17.56s; |
| sustained-06 | stellereum | ❌ RED | 14 | test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 11.99s; |
| tick-tuning | stellereum | ❌ RED | 2 | test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.37s; |
| propose-select | stellereum | ❌ RED | 1 | test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| block-cpu-budget | stellereum | ❌ RED | 1 | test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s; |
| block-cpu-budget-bench | stellereum | ⏭️ SKIP | 0 | no bench-row idiom in matrix; benches/block_cpu_budget.rs is report-only |
| commitment-assembly | stellereum | ✅ GREEN | 1 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.41s; |
| vote-verify-cache | stellereum | ❌ RED | 1 | test result: FAILED. 0 passed; 8 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| parallel-apply-parity | stellereum | ✅ GREEN | 117 | test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 116.96s; |
| light-e2e | stellereum | ❌ RED | 2 | test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| liveness-horizon | stellereum | ❌ RED | 41 | test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.16s; |
| rpc-batch | stellereum | ✅ GREEN | 40 | test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| gossip-scale | infnode | ✅ GREEN | 28 | test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 26.46s; |
| shard2-n3-soak | stellereum | ❌ RED | 31 | test result: FAILED. 0 passed; 6 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s; |
| storage-restore-perf | stellereum | ✅ GREEN | 12 | test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.44s; |
| qc-batch-verify | stellereum | ❌ RED | 6 | test result: FAILED. 1 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s; |
| mev-pq-transport | stellereum | ❌ RED | 1 | test result: FAILED. 13 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.27s; |
| pq-handshake | infnode | ✅ GREEN | 7 | test result: ok. 44 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.27s; |
| protocol-fuzz | stellereum | ✅ GREEN | 3 | test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s; |
| pentest-fees-intake | stellereum | ❌ RED | 4 | test result: FAILED. 3 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.14s; |
| pentest-light-shard2 | stellereum | ❌ RED | 2 | test result: FAILED. 5 passed; 6 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.89s; |
| pentest-mempool-dos | stellereum | ✅ GREEN | 13 | test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 12.60s; |
| pentest-mev-kem | stellereum | ✅ GREEN | 1 | test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s; |
| pentest-privacy-gates | stellereum | ⏭️ SKIP | 0 | pentest_privacy_gates.rs absent at runtime |
| pentest-rpc-surface | stellereum | ✅ GREEN | 2 | test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.34s; |
| pentest-ws-faucet | stellereum | ❌ RED | 16 | test result: FAILED. 5 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 15.33s; |
| pentest-net-api | stellereum | ❌ RED | 2 | test result: FAILED. 11 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s; |
| pentest-pq-downgrade | infnode | ✅ GREEN | 4 | test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.11s; |
| pentest-reputation-bypass | infnode | ✅ GREEN | 7 | test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.21s; |
| api-pentest | stellereum-indexer | ✅ GREEN | 24 | test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.34s; |
| econ-abuse | stellereum-contracts | ✅ GREEN | 0 | test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s;test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s;test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s;test result: ok. 4 |
| circuit-breaker | infnode | ✅ GREEN | 1 | test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.29s; |
| endpoint-hygiene | infnode | ✅ GREEN | 0 | test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| flood-bigchain | stellereum | ❌ RED | 0 | test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| kex-session | infnode | ✅ GREEN | 1 | test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s; |
| nodeid-ceremony | infnode | ✅ GREEN | 2 | test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.52s; |
| nshard-soak | stellereum | ❌ RED | 2 | test result: FAILED. 3 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| freeze-pins | stellereum | ✅ GREEN | 4 | test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| workchain-guard | stellereum | ✅ GREEN | 0 | test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| vrf-canonical-draw | stellereum | ✅ GREEN | 1 | test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |

GREEN 42 / RED 68 / SKIP 3 — 113 rows.
