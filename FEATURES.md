# FEATURES — E2E matrix (machine-generated, do not hand-edit)

Regenerate: `./scripts/feature_matrix.sh`. RED = missing/broken functionality,
owned work order. SKIP = environmental (reason in row), never a pass.

| feature | ws | status | secs | detail |
|---|---|---|---|---|
| pq-keygen-sign-verify | stell-wallet | ✅ GREEN | 102 | test result: ok. 29 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 11.98s; |
| pq-chain-binding | stell-wallet | ✅ GREEN | 2 | test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.27s; |
| pq-fee | stell-wallet | ✅ GREEN | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s; |
| wallet-rpc-token | stell-wallet | ✅ GREEN | 6 | test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.33s; |
| wallet-security | stell-wallet | ✅ GREEN | 29 | test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 28.38s; |
| wallet-privacy | stell-wallet | ❌ RED | 17 | test result: FAILED. 16 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 13.52s; |
| wallet-multimgmt | stell-wallet | ✅ GREEN | 14 | test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 13.28s; |
| wallet-delegation | stell-wallet | ✅ GREEN | 7 | test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.15s; |
| wallet-live-node | stell-wallet | ✅ GREEN | 10 | test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 8.57s; |
| pq-nondeterminism-pin | stellereum | ✅ GREEN | 34 | test result: ok. 38 passed; 0 failed; 0 ignored; 0 measured; 1000 filtered out; finished in 1.68s; |
| aa-session-keys | stellereum | ✅ GREEN | 77 | test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s; |
| aa-session-budget | stellereum | ✅ GREEN | 1 | test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.11s; |
| paymaster | stellereum | ✅ GREEN | 1 | test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| evm-flows | stellereum | ✅ GREEN | 2 | test result: ok. 88 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s; |
| contracts-node-side | stellereum | ✅ GREEN | 1 | test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s; |
| clob-settle | stellereum | ✅ GREEN | 1 | test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| one-call-order | stellereum | ✅ GREEN | 1 | test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| bridge-attest | stellereum | ✅ GREEN | 1 | test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| shielded | stellereum | ✅ GREEN | 1 | test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s; |
| confidential-solvent | stellereum | ✅ GREEN | 1 | test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s; |
| halt-not-fork | stellereum | ✅ GREEN | 2 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 22 filtered out; finished in 0.18s; |
| liveness-harness | stellereum | ✅ GREEN | 2 | test result: ok. 13 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.86s; |
| 4node-adversarial | stellereum | ✅ GREEN | 0 | test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| slash-equivocation | stellereum | ✅ GREEN | 1 | test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s; |
| proposal-refire | stellereum | ✅ GREEN | 1 | test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s; |
| snapshot-resume | stellereum | ✅ GREEN | 2 | test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.79s; |
| mmr-epoch | stellereum | ✅ GREEN | 3 | test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s; |
| light-client | stellereum | ✅ GREEN | 2 | test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s; |
| xshard-2pc | stellereum | ✅ GREEN | 3 | test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s; |
| split | stellereum | ✅ GREEN | 2 | test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s; |
| vel-tempo | stellereum | ✅ GREEN | 23 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 18.62s; |
| tempo-lan | stellereum | ✅ GREEN | 12 | test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.67s; |
| mev-seal | stellereum | ✅ GREEN | 1 | test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s; |
| sts20-onchain | stellereum-contracts | ✅ GREEN | 60 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.09s; |
| dns-onchain | stellereum-contracts | ✅ GREEN | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.15s; |
| pool-onchain | stellereum-contracts | ✅ GREEN | 1 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.13s; |
| account-object-onchain | stellereum-contracts | ✅ GREEN | 0 | test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.11s; |
| adversarial-e2e | stellereum-contracts | ✅ GREEN | 1 | test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.49s; |
| indexer-api | stellereum-indexer | ✅ GREEN | 123 | test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s; |

GREEN 38 / RED 1 / SKIP 0 — 39 rows.
