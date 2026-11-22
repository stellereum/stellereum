# MEV PROTECTION — THE EPOCH SEAL (ES1)

> **Status:** implemented and wired end to end (the asymmetric sealing, the
> sealed gossip, the share release, the epoch-key commitment, the fail-closed
> admission, the timeout path).
> **Threat model:** the honest statement is at the bottom of this file. Read it
> before you describe this feature to anyone — the scheme protects the
> CONTENT of a transaction, not the ORDER, and it does not protect against a
> malicious proposer.

---

## 1. What the scheme is

Every MEV epoch (`EPOCH_BLOCKS = 128` blocks) has an **epoch key**: a
Ristretto255 public key `P_e` that only the epoch's committee can decrypt
to. A wallet encrypts its transaction to `P_e` and submits the CIPHERTEXT.
The network carries the ciphertext; the plaintext is revealed only after the
ordering of the round is committed.

The scheme has three parts:

| part | what it does | where |
| --- | --- | --- |
| **epoch key distribution** | a dealer-free, verifiable DKG over the committee; every member holds a Shamir SHARE of the epoch secret; the epoch key is COMMITTED to the block | `src/mev_epoch.rs`, `Block::epoch_key_commitment` |
| **sealed gossip** | the mempool, the gossip channel and the DHT carry the ciphertext; the plaintext never enters the pool | `src/mev_epoch.rs` (`MevFrame::Sealed`), `Mempool::sealed` |
| **share release** | after the signed order commitment, every member releases a decryption partial; `t` partials unseal | `src/mev_epoch.rs` (`ShareRelease`), `runtime.rs` (`release_sealed_partials`) |

### 1.1 The epoch key

* The **committee** is the current validator set, sorted by validator id. The
  index of a member (1-based) is its Shamir abscissa, so every node derives
  the same committee — and therefore the same shares — from the same set.
* Each member's **encryption key** is derived from its PUBLIC Ed25519 key
  (the standard Ed25519 → X25519 birational map), so the DKG needs no
  separate key-announcement round: a peer that knows the validator set can
  address a share package to anybody.
* The **contributor set** is DERIVED, not observed: the `threshold` members
  with the lowest `H(epoch ‖ committee hash ‖ validator id)` contribute
  their share polynomial. This is what makes the epoch key UNIQUE — see
  §5.1.
* The DKG is **verifiable**: every member publishes Feldman commitments to
  its polynomial and sends every other member its (encrypted) evaluation.
  A recipient checks the evaluation against the commitments, so a dishonest
  member can only make the epoch FAIL (a liveness loss, detected and
  attributable) — it can never bias the key towards a value it knows, and it
  never learns anybody else's share.
* The epoch key is committed to the block as
  `H(domain ‖ epoch ‖ P_e ‖ committee hash ‖ threshold)`
  (`Block::epoch_key_commitment`, inside the block hash). A wallet or a light
  client therefore does not have to trust the node it asks for the key: it
  checks the commitment against the chain.
* The committee also publishes an **announcement** (the epoch, the key, the
  committee hash, the DKG transcript root, the threshold, the contributors
  and the members' signatures over a domain-separated message). It is the
  committee's AGREEMENT on the key: a client collects the members'
  announcements, checks the quorum against the validator set, and checks the
  resulting commitment against the block.

### 1.2 Sealing (the wallet side)

```
shared   = e · P_e                          (e = the wallet's ephemeral scalar)
key      = SHA256("STELL_MEV_SEAL_KDF_V1" ‖ shared ‖ epoch ‖ tx_hash)
aad      = "STELL_MEV_SEAL_AAD_V1" ‖ epoch ‖ tx_hash ‖ committee_hash
cipher   = XChaCha20-Poly1305(key, nonce, plaintext, aad)
```

The envelope carries the ciphertext, the ephemeral public key, the nonce, the
transaction hash and the **transparent metadata** (sender, nonce, gas limit,
priority bid, shards). The amount, the recipient and the SVM program stay
hidden.

### 1.3 The round (the validator side)

1. The proposer picks the sealed transactions, **commits to their ORDER**
   (a signed order Merkle root over the sealed transaction hashes) and
   gossips the commitment. Nothing is decrypted yet.
2. Every member that has seen the commitment **releases its decryption
   partial** `C^x_i` for each committed transaction. A partial is a group
   element: publishing it does not reveal the share (discrete log) and does
   not decrypt any other ciphertext.
3. The proposer combines `t` partials (Lagrange interpolation **in the
   exponent**) into the shared point and unseals. The plaintext is checked
   against the envelope: the transaction hash must match, the transparent
   metadata must match, and the signature must verify. A transaction that
   fails any of these is dropped.

### 1.4 The wire format

All five frames are magic-prefixed, so the plain transaction encoding stays
byte-identical and a node that predates this feature refuses the frames it
cannot read (fail closed) instead of mis-reading them:

| frame | magic | body |
| --- | --- | --- |
| sealed transaction | `STX1` | `bincode(SealedEnvelope)` |
| DKG contribution | `STD1` | `bincode(DkgContribution)` |
| order commitment | `STC1` | `bincode(OrderCommitment)` |
| share release | `STR1` | `bincode(ShareRelease)` |
| epoch announcement | `STE1` | `bincode(EpochKeyAnnouncement)` |

The sealed transaction travels on the ordinary transaction-gossip channel
(`TxGossipPayload::Mev`), and the DHT mempool entry under
`PREFIX_MEMPOOL_TX` holds the magic-prefixed ciphertext.

---

## 2. How a wallet uses it

```
1. GET  stell_epochKey            -> { epoch, public_key, committee_hash,
                                       threshold, commitment, contributors }
2. build the sealed envelope      -> EpochPublicKey::from_rpc_json(answer)
                                     + wallet::seal_transaction_for_epoch(epoch_key, tx)
                                     (or WalletAccount::create_sealed_transaction, which
                                     signs, seals and hex-encodes in one step)
3. POST stell_sendSealedTransaction{ payload: hex("STX1" || bincode(envelope)) }
                                     (wallet::encode_sealed_for_submit builds this)
4. the node stores the CIPHERTEXT and gossips it
5. the proposer commits to the order, the committee releases the shares,
   the proposer unseals and includes the transaction
```

Before sealing anything of value, check the key against the chain: compare
the `commitment` from step 1 with the `epoch_key_commitment` of a VERIFIED
block of that epoch (`light_client::verify_epoch_key_against_block` — the
block itself must be hash-recomputed and quorum-verified first, otherwise
the check is trust in the serving node). A key no block committed to is a
key nobody can unseal — and the sender still pays the drop bond.

The wallet can check step 5's key against the chain: the `commitment` the
node returned must equal the `epoch_key_commitment` of the blocks of that
epoch.

---

## 3. The fail-closed rules

* **Admission.** A sealed envelope is refused unless it passes the
  structural check (non-empty payload, payload ≤ 1 MiB, a valid ephemeral
  curve point, a non-reserved transaction hash), its epoch is the pool's
  current epoch, the transaction hash is unknown, the per-sender quota
  allows it, and the pool has room. The refusal carries a clear reason.
* **Unseal.** A bounded attempt: the proposer waits at most
  `STELL_MEV_UNSEAL_WAIT_MS` (default 500 ms) for the peers' partials, then
  unseals what it can. A transaction that cannot be unsealed is DROPPED
  (evicted from the pool) and its sender is charged the failure bond.
* **Divergence.** A node whose epoch key differs from the committed one
  (a different validator view at the epoch boundary) stops releasing
  partials: its shares would reconstruct a different shared point.
* **The plain path is never broken.** A wallet that does not seal is served
  exactly as before.

---

## 4. What this protects against — and what it does NOT

### 4.1 It DOES protect against

* **A passive network observer.** The transaction's amount, recipient and
  program are ciphertext on the wire, in the mempool and in the DHT. A
  sniffer learns the sender, the nonce, the fee and the shards — the
  metadata every encrypted mempool has to expose — and nothing else.
* **A mempool snooper.** A node (or an operator with access to one) that
  reads the pool before the ordering is fixed cannot read the CONTENT of a
  sealed transaction. It can see that a transaction exists, who sent it and
  what it pays.
* **A front-runner that acts on the CONTENT.** To build a sandwich it must
  know the amount and the recipient of the victim transaction. With a
  sealed transaction it does not, until the transaction is in a block.

### 4.2 It does NOT protect against

* **A malicious proposer.** The proposer is the one who collects the
  partials and builds the block. It can:
  * withhold its own partial and stall the round (bounded: the timeout
    path drops the transaction — but the transaction is NOT included, and
    the sender pays the bond);
  * refuse to unseal a transaction it does not like (censorship of the
    CONTENT — the transaction is dropped and the sender is charged);
  * front-run with its OWN transaction: it knows the content of the
    transactions it unseals, and nothing in this scheme stops it from
    submitting its own transaction with a higher bid. **The scheme does not
    stop proposer front-running.**
  * reorder the transactions it unseals. The order commitment is signed and
    gossiped BEFORE the reveal, and the block's own order commitment
    (`Block::order_merkle_root`) is consensus-enforced — but a proposer that
    committed to order A and then builds order B is caught by the
    consensus check, and a proposer that commits to B in the first place
    has committed to B. The commitment removes the "reveal, then reorder"
    attack; it does not remove the "I decide the order" power.
* **The order itself.** The block lists the transactions in execution
  order. Even a sealed transaction is visible — and ordered — once it is
  in a block. The scheme hides the CONTENT before the ordering is fixed; it
  does not hide the ordering.
* **Traffic analysis.** The sender, the nonce, the fee, the gas limit, the
  shards and the transaction hash are public by construction (the pool has
  to order and deduplicate by them, and the fee is the price).
* **A compromised committee.** `t` committee members can decrypt every
  sealed transaction of the epoch. That is the threshold of the scheme.
* **The DKG's liveness.** The epoch key needs the contributor set to be
  online once per epoch (§5.2). The plain path is unaffected.

### 4.3 The honest residual gaps

1. **The fee of a dropped sealed transaction is not transferred on-chain.**
   The sender is charged the *admission bond* (the same node-local penalty
   an execution failure costs, `Mempool::penalize_sender`), and the
   transaction is evicted from the pool. A consensus-level charge would
   need a new block-level construct (a "sealed drop" record carrying a
   wallet-signed fee authorization) — it is NOT implemented, because a
   proposer-chosen charge is a censorship-with-extortion vector unless the
   drop itself is verifiable on chain.
2. **The committee is derived from the node's CURRENT validator view.** A
   node whose view differs at the epoch boundary derives a different
   committee, cannot complete the DKG, and is left without an epoch key. It
   then serves the plain path only, and (if it is the proposer) it does not
   touch the sealed path at all. The epoch-key commitment in the block is
   what resolves the disagreement: the chain's key wins, and a node that
   diverged from it stops releasing partials.
3. **The epoch key is derived from the validator set, not from a chain
   randomness beacon.** A committee that disagrees about the set at the
   boundary disagrees about the key. The commitment in the block is the
   mitigation, not a cure.
4. **The DKG round is a gossip round, not a consensus round.** It is
   self-healing (the contribution is re-published every 5 s until the key
   is ready), but it has no timeout that rotates the committee: a member
   that is offline for a whole epoch disables the private path for that
   epoch.

---

## 5. Design notes

### 5.1 Why the contributor set is DERIVED

An "observed" contributor set — "the first `t` contributions that arrived" —
lets two nodes of the SAME network finalize with DIFFERENT epoch keys: the
aggregate is over a different set of constant terms. A wallet's ciphertext
would then be unsealable on some nodes and not on others, and the share
reconstruction would mix incompatible shares.

Deriving the set from public data (`epoch ‖ committee hash ‖ validator id`)
makes "every contributor has contributed" the SAME condition on every node,
so the aggregate key is the same everywhere by construction.

### 5.2 Why the epoch key needs `t` contributors

The aggregate secret is the sum of the contributors' secrets and its sharing
has degree `t - 1`, so `t` contributors is exactly the number needed to
reconstruct it. A larger set would only add liveness requirements (more
contributors must be online); a smaller set would make the key
unreconstructable. The remaining committee members are SHARE HOLDERS: they
receive the contributors' evaluations, they can release decryption partials,
and they count towards the unsealing threshold.

### 5.3 Why the unsealing threshold is below the committee size

`threshold_for(n) = floor(2(n-1)/3) + 1` (clamped to `[2, n-1]` for `n ≥ 3`).
It is strictly below `n`, so ONE member may withhold its partial without
stalling the round: the proposer unseals with the others. For `n ≤ 2` the
threshold is `n` — a two-member committee has no majority that tolerates a
withholding member, and the timeout path (drop + charge) is the fallback.

### 5.4 Why Ristretto255 and not raw X25519

X25519 clamps its scalar input, and clamping is NOT a linear map: the
Shamir reconstruction `Σ λ_i · x_i` would not survive it. The threshold
arithmetic therefore runs in the prime-order Ristretto255 group, where
scalar multiplication is exactly linear. X25519 is still used for the one
place that needs a raw Diffie-Hellman (the encrypted key-share packages of
the DKG).

### 5.5 The node-local blind round (the plain path)

The plain path keeps the older, node-local admission seal
(`crate::mev::MevPreemptionEngine`): every admitted transaction is sealed
under a node-local round key and re-opened at block build, so a mutated
pool copy can never enter a block. It hides nothing from the node itself —
it is a tamper check, not a privacy mechanism. The epoch seal is the
privacy mechanism.

### 5.6 Shares delivery: pool messages, not vote-embedded (spec alignment)

The V5 master spec (§4, item 4, "Precommit Piggyback") says validators put
their decryption shares DIRECTLY INTO Precommit votes ("0 лишних хопов").
The shipped code does NOT do that: shares travel in pool gossip messages
(`MevFrame::Release`, via `broadcast_mev_frame`), released by
`EpochSealManager::release_partial` and ingested by
`EpochSealManager::ingest_release` (`src/mev_epoch.rs`, `src/runtime.rs`
`release_sealed_partials`). This section states WHY, what is equivalent,
what is lost, and what vote-embedding would take. It is the honest record:
where this document and the V5 spec file disagree, this document describes
the code.

WHY NOT VOTE-EMBEDDED (the real reasons, read off the code):

1. **The vote has no room — structurally, not just by size.** `Vote` is
   `{height, round, kind, block_hash, voter, signature}`
   (`consensus::Vote`), and `vote_sign_bytes` commits to exactly
   `(domain ‖ chain_id ‖ height ‖ round ‖ kind ‖ block_hash)`
   (`consensus::vote_sign_bytes`). A decryption partial is bound to
   `(epoch, height, round, order_root, tx_hash, validator_index)` — none of
   which the preimage names. Carrying a share in a vote means adding a
   payload field to `Vote` AND extending the preimage: a consensus-breaking
   change that touches `Vote::verify`, the remote-signer path (which signs
   the same preimage out of process), the QC aggregation and every
   certificate check. There is no "post-state binding room" to borrow.
2. **Per-transaction shares do not fit a per-block vote's size budget.** A
   shipped partial is a 32-byte Ristretto point plus a 4-byte committee
   index per sealed transaction (bincode; the release frame pairs each with
   its 32-byte tx hash). Votes gossip per validator per round; embedding
   shares multiplies EVERY vote — and every QC aggregating them — by the
   sealed-transaction count of the round. That breaks the certificate size
   story V5 itself promises (µQC: 16 × 666 B): one 1,000-tx sealed round
   would staple ~36 KB of shares onto every vote before a single signature
   is counted. (The spec's "384 bytes per share" figure does not match the
   shipped 36-byte partial either; the argument above uses shipped numbers.)
3. **The release and the vote run on different triggers.** A partial is
   released only AFTER the round's order commitment has been seen
   (`release_partial` refuses without the `(height, round)` commitment;
   `ingest_release` refuses a release matching no known commitment). Votes
   are cast on `block_hash` on the BFT schedule; the release runs on the
   order-commitment gossip schedule. Fusing them couples decryption
   availability to the BFT vote quorum and kills the timeout path: today a
   member that withholds its partial is routed around (threshold strictly
   below committee size for `n ≥ 3`, bounded 500 ms wait, then drop +
   failure bond). Vote-embedded shares make a vote-withholder a
   decryption-staller with no fallback.
4. **Certificates aggregate fixed-shape votes.** QCs (including the BLS
   envelope path) aggregate one signature context per vote. Variable-length
   per-transaction payloads do not aggregate and do not batch-verify; every
   certificate check would pay per-tx parsing for data that most verifiers
   (light clients, bridges) cannot use.

SECURITY EQUIVALENCE (what the pool path preserves): the property the
scheme exists for is the ORDER OF OPERATIONS — commit, then release, then
unseal — and it is enforced regardless of carrier. The order commitment is
signed and verified on receipt (`OrderCommitment::sign/verify`,
`note_commitment`); partials are released only for transactions IN a seen
commitment and ingested only against a matching `(order_root, epoch)`; `t`
partials reconstruct (Lagrange in the exponent) and the unsealed plaintext
is re-checked against the envelope (tx hash, transparent metadata,
signature) before inclusion. The BFT quorum still decides the block; shares
influence only unsealing liveness, never safety, ordering, or finality.
A release replayed into a different ordering is refused by the
`order_root` binding; a partial for an uncommitted transaction is never
emitted.

WHAT VOTE-EMBEDDING WOULD TAKE: a `Vote` payload field plus a new
`vote_sign_bytes` layout (coordinated consensus break); a per-vote cap on
carried shares (batch limit) with fragmentation/reassembly for large sealed
rounds; reworked QC aggregation and a new µQC size budget accounting for
the payload; reworked threshold semantics (shares arrive only with votes
for the same block — the t-of-n-across-gossip flexibility and the
timeout/drop path go away); and acceptance that every QC becomes archived
decrypting material.

OPEN GAPS (properties the spec's wording promises that the pool path does
NOT satisfy):

* **OPEN (Medium): "any node that collects 2f+1 precommits interpolates the
  slot key" does not hold.** The spec's timing table (§4) says that on
  collecting 2f+1 Precommit ANY node interpolates. Shares travel in
  `MevFrame::Release` pool gossip, not in votes, QCs, or blocks — so a node
  holding 2f+1 precommit votes but missing the release frames (late joiner,
  lossy gossip, restarted mid-round) cannot unseal, and NOTHING decrypting
  is ever persisted: no late joiner can reconstruct shares from chain data
  alone. Share availability is gossip-dependent, not quorum-evident. Safety
  is unaffected (order-before-reveal holds; the proposer path that matters
  works when the committee is live), but the "any node" availability claim
  is false as shipped. Closing it means either vote-embedding (above) or
  persisting release frames alongside blocks (new consensus data, same
  availability question one layer down).
* **OPEN (Low): withholding a partial leaves no consensus evidence.** A
  member that never releases is indistinguishable on-chain from a member
  that was never heard; a coalition of `n - t + 1` members can grief sealed
  senders (drop + failure bond, repeatably) with zero slashable trace,
  where vote-embedded shares would make the omission visible in the vote
  itself. Bounded per-tx grief, contained by the threshold and the timeout
  path — but unattributable as shipped.

---

## 6. Where the code is

| concern | file |
| --- | --- |
| the scheme (DKG, sealing, partials, framing) | `src/mev_epoch.rs` |
| the node-local admission seal and the order root | `src/mev.rs` |
| the sealed pool, the admission rules, the share drop | `src/mempool.rs` |
| the epoch sync, the release, the proposer path | `src/runtime.rs` |
| the gossip channel | `src/consensus_net.rs` |
| the block field | `src/sharding.rs` (`Block::epoch_key_commitment`) |
| the RPC | `src/rpc.rs` (`stell_epochKey`, `stell_sendSealedTransaction`, `stell_mevStats`) |
| the metrics | `src/metrics.rs` (`stell_mempool_sealed`, `stell_mempool_plain`, `stell_mev_unsealed_total`, `stell_mev_unseal_failed_total`) |
| the tests | `tests/mev_epoch_seal_tests.rs`, `src/mev_epoch.rs` (unit tests) |
