# Verifying Stellereum from genesis + checkpoints (third-party guide)

This is the recipe for checking the chain WITHOUT trusting any single full
node. Trust anchor: the validator set, pinned out-of-band. Everything else is
verified against it.

## 0. Pin the validator set (never skip this)

Fetch the set from **several independent sources** and require them to agree:

- the genesis configuration of the deployment you are verifying;
- `stell_getValidators` on multiple independent nodes (shape:
  `{"validators": [{"validator": "<64 hex>", "power": "1000"}, ...],
  "total_power": "...", "quorum": "..."}` — power may be a number or a string).

Write it to a file in the shape the CLI reads (both work):

```json
{"validators": [{"validator": "<64 hex>", "power": "1000"}]}
```

or a bare array `[{"validator": "<64 hex>", "power": 1000}]`.

A set the server you are verifying handed you is NOT an anchor — a server
that picks its own verifiers can certify its own chain. If the sets disagree,
stop: you do not have an anchor yet.

## 1. Anchor: genesis or a finalized checkpoint

**From genesis.** The genesis root is trusted BY CONSTRUCTION (your pinned
genesis configuration, height 0). Every header above it must carry a precommit
quorum certificate verified against your pinned set — the first unverified
link never exists.

**From a checkpoint.** Ask any node for `stell_getFinalizedCheckpoint`:

```json
{"height": H, "block_hash": "<hex>", "prev_hash": "<hex>",
 "state_root": "<hex>", "proposer": "<hex>", "timestamp": 1700000000,
 "cert": {"height": H, "round": 0, "kind": "Precommit",
          "block_hash": "<hex>",
          "signatures": [{"validator": "<hex>", "signature": "<hex>"}]}}
```

Verify it yourself before believing a byte of it:

1. `cert.kind` is `Precommit` (a prevote quorum is not finality — refuse it);
2. `cert.height == H` and `cert.block_hash == block_hash`;
3. signers with power in YOUR pinned set reach quorum
   (`quorum = floor(2*total/3) + 1`), each key counted once, outsiders ignored;
4. every counted signature verifies.

In code this is `Checkpoint::verify` / `LightClient::new`. A checkpoint that
fails any step is not an anchor — discard it and ask another node.

## 2. Follow the chain: header `h+1` against the anchored set

Fetch each successor with `stell_getFinalizedHeader {"height": h+1}` and
accept it only if ALL hold:

- height is exactly `tip + 1`, `prev_hash` is the tip hash (no gaps, rewinds, forks);
- its precommit QC verifies against the set in force (same four checks as above);
- its state root does not resurrect a root an earlier finalized header already
  superseded (a header may repeat its parent's root — empty blocks move no
  state — but never reach further back).

In code: `LightClient::apply_header`. The retained window is bounded
(`DEFAULT_MAX_HEADERS`); when full, re-anchor via step 1 at a newer
checkpoint instead of widening anything.

## 3. Rotations: the anchor is `(set, height)`

The set in force changes ONLY through a rotation point, and the rule is:

> **A supermajority of the OLD set must sign the rotation header.**
> The rotation header chains normally onto the tip (`tip + 1`, parent = tip
> hash) and carries a precommit QC (plus any block-signature quorum it claims)
> verifying under the CURRENT set. The new set takes effect AT the rotation
> header's height. Anything else fails closed.

Concretely (`LightClient::rotate_validator_set` with a
`ValidatorSetRotation { rotation, next_set }`):

- `next_set` must have power of its own (non-empty, reachable quorum) — a
  rotation to a powerless set would brick the client into trusting nothing;
- the rotation header must chain (gap/fork/full-window refused);
- the header's QC must verify under the OLD set — a forged point, a point
  with < quorum old power, and a new set signing its OWN adoption are all refused;
- after rotation, headers certified only by the superseded set are refused
  (verified against the new set + pinned to the rotated tip).

What the rule does NOT prove: the chain's block hash commits to
height/parent/state/transactions — NOT to the next validator set — so the
old-set quorum authenticates the rotation POINT, not the replacement set's
CONTENTS. Pin the new set exactly like the genesis set (out-of-band file,
cross-checked across nodes via `stell_getValidators`); never adopt a set from
the server you are verifying. `LightClient::validator_set_height` tells you
which set certified which header when replaying.

## 4. Verify state against a trusted root

Only now — with a root your anchor certified — check proofs:

- account/token balances: `stell_getBalanceSpv` / `stell_tokenBalanceSpv`,
  or the full form `stell_getProof` (inclusion AND exclusion proofs);
- historical keys: `stell_getHistoricalRoot` (adopt via
  `Checkpoint::from_historical_root_json` — refuses non-finalized answers and
  anchors that are not exactly `height + 1`) then `stell_getArchiveProof`;
- epoch coverage: `stell_getEpochRoot` (check the answer's internal
  consistency AND the root against the quorum-signed boundary header of the
  next epoch — an unchecked root is trust-in-the-serving-node).

Every answer names a root; the client reports the height IT finalized that
root at, and an unknown root is `RootUntrusted`, never a balance. An empty or
missing proof is `InvalidProof`, never evidence of absence.

## 5. Minimal third-party loop

```
pinned_set   = agree(genesis_config, stell_getValidators x N nodes)
client       = LightClient(pinned_set, trusted_checkpoint_or_genesis)
while tip < target:
    h = stell_getFinalizedHeader(tip + 1)
    if h signals rotation (operator-announced set change):
        client.rotate_validator_set(h, pinned_next_set)   # old-set QC required
    else:
        client.apply_header(h)                            # anchored-set QC required
proof        = stell_getProof(account, ...)
client.verify_proof_answer(proof)   # balance only if this succeeds
```

No step here contacts a privileged endpoint; every "follow-up" is just
re-running a step against another node until the evidence verifies.

## RPC follow-ups (lead)

None outstanding for this flow: `stell_getValidators`, `stell_getFinalizedHeader`,
`stell_getFinalizedCheckpoint`, `stell_getProof`, `stell_getHistoricalRoot`,
`stell_getArchiveProof`, `stell_getEpochRoot`, `stell_getBalanceSpv`,
`stell_tokenBalanceSpv` all exist in `rpc.rs` and are referenced above only
after confirming they are served. What the RPC layer does NOT serve (and this
flow does not need): a quorum-signed validator-set blob — sets stay
out-of-band by design, see step 3.
