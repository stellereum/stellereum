# Glossary

One line per term; protocol terms first, resilience/ops terms after.

- **µQC (micro-certificate):** fast finality path — a small stake-weighted
  sample signs a block instead of the full Ed25519 set (`PROTOCOL.md` §6).
- **sortition:** parent-hash-seeded (`STELL_SORTITION_V5`) stake-weighted
  committee draw, size `min(N, 64)` (`src/consensus.rs:635`).
- **network-anchored quorum:** µQC needs `max(2/3 of committee, strict
  majority of whole-network stake)` (`PROTOCOL.md` §6.3).
- **Stl57:** branded Base58 address (`Stl57…` + 4-byte BLAKE3 checksum),
  same 32-byte key as hex (`src/address.rs`).
- **Falcon (-512 / FN-DSA):** post-quantum validator signature paired
  with Ed25519; pre-FIPS keys migrate via `keys rotate-falcon`.
- **2PC:** cross-shard two-phase commit (prepare / vote / commit,
  two-sided abort) replacing unilateral ack/bounce (`SHARDING.md` §6).
- **epoch seal:** threshold (Shamir) MEV scheme — DKG epoch key, sealed
  submission, commit-order-then-reveal (`src/mev_epoch.rs`; KI-34).
- **order commitment:** block's Merkle root over tx order (`ORDROOT1`),
  re-verified by every validator before voting.
- **shard-header commitment:** masterchain block's commits to workchain
  heads (`SHARDHDR`), TON `shard_hashes` model.
- **lock_hint:** the lock a node advertises alongside its vote so peers
  reason about its locked value (`src/main.rs:1028`).
- **polka:** 2/3+ prevotes for one block at a round — a network fact that
  compels precommits and unlocks stale locks (`src/consensus.rs:2853+`).
- **F1 (lazy) accumulator:** reward-per-token delegator payout state
  (`reward_per_token`, pools, checkpoints) in the state root.
- **F-01 failure fee:** attributable failures pay and advance nonce;
  uncoverable ones move nothing (`PROTOCOL.md` §4c).
- **D2 penalty:** per-sender admission-floor surcharge after apply
  failures, mirrored in consensus (`src/state_engine.rs:481`).
- **epoch / activation boundary:** height-gated rule switches (2PC
  `STELL_XPC_ACTIVATION_HEIGHT`); every node of a shard must agree.
- **commitment digest:** hash folding all non-trie subsystems into the
  single trie key `sha256("STELL_CONSENSUS_COMMITMENT_V1")`.
- **view change:** round-timeout advance (3 s default) when a height
  fails to decide — a flat tip + view-change storm = stall.
- **fork-choice:** canonical-head selection over unfinalised candidates;
  losers surface as invalidations, never as rolled-back finals.
- **invalidation:** signal naming orphaned candidate blocks tip-first +
  lowest orphaned height for re-sync (`MAX_INVALIDATION_WINDOW` = 64).
- **weak QC:** certificate below the in-force quorum — refused loudly
  (`stell_weak_qc_refused_total`), never finalised with.
- **persist queue:** bounded (8192) background store writer; overflow
  drops jobs and logs `[storage] persist queue full` on stderr.
- **checkpoint:** persisted consensus safety state (height/round/lock);
  a stale one after restart = stale-lock stall.
- **orphan chunk:** unreferenced P2P blob file; 463 589 of them once
  filled all inodes and silently removed a node from consensus.
- **preflight:** fail-closed pre-deploy config gate (`stell-sync.sh`).
- **doctor:** single-node diagnosis (drift, checkpoint, topic, keys).
- **watchdog:** interval supervisor that heals only safe cases.
- **quorum-jump stall:** finality refused after a set change moved the
  quorum mid-round (W10.5 race; sets now stage at H+1).
- **nil-storm stall:** repeated nil-quorum view changes that never
  converge on a proposal.
- **bounce:** TON-style auto-refund to sender on failed cross-shard
  delivery (legacy flow; 2PC transfers never bounce).
- **circuit breaker:** oracle freeze on >10 % price step (3-day
  governance reset); tiers: pull-oracle → TWAP → breaker.
