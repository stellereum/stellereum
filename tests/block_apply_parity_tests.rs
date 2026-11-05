//! Differential: the two block-apply paths must be byte-identical.
//!
//! Two code paths apply a block to state:
//!
//!   * LIVE - `ValidatorRuntime::try_finalize` (and `apply_and_advance` /
//!     `replay_historical_block`) -> `apply_block_fees_rewards` ->
//!     `InMemoryStateEngine::apply_block_transition`.
//!   * REORG - `ChainState::reorg` -> `ChainState::apply_block` -> the SAME
//!     `InMemoryStateEngine::apply_block_transition`.
//!
//! The reorg path used to loop `apply_transaction` over the transactions
//! instead. That diverged from the live path in five ways, every one of which
//! silently forks a reorg (same height, two states):
//!
//!   1. FEE RULE - `apply_transaction` charged the gas actually CONSUMED, the
//!      block path charges the DECLARED `gas_limit` (which admission reserved
//!      and which `fees_collected` credits to the proposer).
//!   2. PROPOSER FEES - the block path credited `fees_collected` to the
//!      proposer; the reorg path credited nobody, so the proposer's balance
//!      (and every later fee arithmetic) differed.
//!   3. BLOCK REWARD - `distribute_reward` ran live only.
//!   4. UNBONDING - `process_unbonding(block.timestamp)` ran live only, so a
//!      matured unbond became withdrawable on one path and not the other.
//!   5. DOWNTIME SLASH - `note_missed_heights` + the `STAKING_POOL` debit ran
//!      live only, so a missed quorum burned stake on one node and not the
//!      other (the ledger digest is in the state root).
//!
//! Payload-failure semantics and the token/orderbook/staking effects of a
//! rejected transaction were already shared (`execute_payload` is clone-commit,
//! `commit_native` is the shared commit point) - see `tests/hunt_atomicity.rs`.
//!
//! These tests pin the reconciliation: the same realistic blocks, applied
//! through both paths on two fresh engines, must agree on the state root, the
//! receipts vector and the applied counters - and the divergences that MUST
//! remain (the single-transaction fee rule, node-local mempool pruning) get
//! their own tests stating why.
//!
//! ## Divergence table (state AFTER this reconciliation)
//!
//! | Dimension | LIVE (`try_finalize` / adopt / walk / replay) | REORG (`ChainState::apply_block`) | Verdict |
//! |---|---|---|---|
//! | gas-fee rule | declared `tx.gas_limit` | declared `tx.gas_limit` | **UNIFIED** for both block paths. The single-tx API `apply_transaction` still charges gas *consumed* - **pinned** divergence, test 2 (unifying = charging users for gas they never burned). |
//! | payload-failure semantics | `execute_payload` clone-commit; `commit_native` atomic | same code | **UNIFIED** (pre-existing, `tests/hunt_atomicity.rs`). A rejected tx moves no coins; both report `status=false`. |
//! | proposer fee credit | `fees_collected` -> `credit_native(proposer)` | same | **UNIFIED** (was: reorg credited nobody). |
//! | block reward | `block_reward_for(gov, default)` -> `distribute_reward` | same helper, same call | **UNIFIED** (was: live only). |
//! | unbonding maturity | `process_unbonding(block.timestamp)` | same | **UNIFIED** (was: live only). |
//! | downtime slashing | `note_missed_heights` + pool debit from `block.precommit_qc` | same | **UNIFIED** (was: live only). Equivocation (F4) is applied on NEITHER path. |
//! | receipts / `applied_statuses` / `applied_txs` | recorded from `BlockTransitionOutcome` | same outcome | **UNIFIED**, asserted per height. |
//! | validator-set refresh | `refresh_validator_set_from_staking` (read-only) | `ChainState::validator_set` | Same derivation from the same committed ledger, asserted equal. |
//! | mempool pruning | always prunes included txs | prunes only when a pool is attached | **Node-local by definition** - not committed, cannot move the state root. Pinned, test 3. |

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use stellereum::consensus::{ValidatorSet, Vote, VoteKind};
use stellereum::mempool::Mempool;
use stellereum::runtime::{fund_genesis, ChainState, ValidatorRuntime};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::staking::{
    DOWNTIME_MISS_THRESHOLD, MIN_VALIDATOR_BOND, REWARDS_POOL, STAKING_POOL, STELL_MIN_BOND_BUFFER,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER};

/// Block reward paid per height on BOTH paths (must be non-zero, or the reward
/// leg of the transition is never exercised).
const REWARD: u64 = 1_000_000_000; // 1 STELL
/// Realistic block timestamp - never 0 (0 is exactly the hardcoded-clock bug).
const TS: u64 = 1_760_000_000;
/// Genesis balance per validator and per user account.
const BAL: u64 = 10_000 * 1_000_000_000;

/// Bond floor nova's block-2 bond must clear: bare-MIN bonds are refused.
fn floor() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn id_of(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

/// FULL-PQ transaction sender: implicit Falcon-512 (registered globally;
/// no surcharge), so fee assertions match the old classical fixtures.
/// Seeds live in 0xE0+ — DISJOINT from certify's validator Falcon seeds
/// (0xA0+i): the same seed derives the same keypair, and an overlapping
/// seed would alias a sender address onto a validator's Falcon address
/// (breaking µQC attribution).
static NEXT_PQ: AtomicU8 = AtomicU8::new(0xE0);

fn pq_user() -> u8 {
    NEXT_PQ.fetch_add(1, Ordering::Relaxed)
}

fn pq_id(seed: &u8) -> [u8; 32] {
    use stellereum::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};
    derive_pq_address(
        PqScheme::Falcon512,
        &Transaction::sample_falcon512_pubkey(*seed),
        &DEFAULT_SALT,
    )
}

fn tx(seed: &u8, to: [u8; 32], amount: u64, gas: u64, nonce: u64) -> Transaction {
    txp(seed, to, amount, gas, nonce, Vec::new())
}

fn txp(
    seed: &u8,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
    payload: Vec<stellereum::svm::OpCode>,
) -> Transaction {
    use stellereum::post_quantum::{PqScheme, PqSignatureEnvelope, DEFAULT_SALT};
    let pk = Transaction::sample_falcon512_pubkey(*seed);
    let from = pq_id(seed);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("PQ test key must register");
    let mut t = Transaction {
        from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = t.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, *seed);
    t.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    t
}

async fn balance(e: &InMemoryStateEngine, addr: &[u8; 32]) -> u64 {
    e.get_account(addr).await.map(|a| a.balance).unwrap_or(0)
}

/// `n` engines with byte-identical pre-state: genesis validators, funded user
/// accounts, a funded staking pool, and a silent validator parked one miss
/// short of the downtime threshold (so the FIRST certificate burns).
///
/// Everything that seeds them is a constant or a caller-provided key, so any
/// number of engines come out byte-identical - which is what a differential
/// test needs: the ONLY difference between them afterwards must be the code
/// path that applied the blocks.
async fn mirrored_engines(
    vs: &ValidatorSet,
    funding: &[([u8; 32], u64)],
    silent: &[u8; 32],
    n: usize,
) -> Vec<Arc<InMemoryStateEngine>> {
    let mut out = Vec::new();
    for _ in 0..n {
        let e = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&e, vs, BAL).await;
        for (addr, bal) in funding {
            e.update_account(AccountState::new(*addr, *bal)).await;
        }
        // The slash debits real coins out of the pool; fund it identically on
        // both engines so the debit actually happens (and is comparable).
        e.credit_native(&STAKING_POOL, 10 * MIN_VALIDATOR_BOND)
            .await
            .expect("pool credit");
        {
            let mut l = e.staking_write().await;
            let rec = l.validators.get_mut(silent).expect("silent is bonded");
            rec.missed = DOWNTIME_MISS_THRESHOLD - 1;
            rec.last_downtime_penalty = 0;
            // Pin the silent validator at bare MIN (grandfathered thin state):
            // the height-1 downtime slash (0.1%) must eject it at the boundary,
            // exactly as when genesis bonds were bare MIN. A floor bond would
            // survive the slash, grow the height-2 set to 5, and move the
            // quorum the `certify` precondition counts on. This test is about
            // live-vs-reorg parity, not the entry floor, so the scenario keeps
            // its original eject dynamics.
            rec.self_bond = MIN_VALIDATOR_BOND;
        }
        out.push(e);
    }
    let root0 = out[0].get_state_root().await;
    for (i, e) in out.iter().enumerate() {
        assert_eq!(
            e.get_state_root().await,
            root0,
            "precondition: engine {i} must start byte-identical to engine 0"
        );
    }
    out
}

/// Drive a genuine 3-of-4 precommit quorum for `blk` through the live runtime
/// and hand back the certificate that the block body must carry (the decision
/// proof is what `apply_block_transition` reads as downtime evidence).
/// FULL-PQ: votes carry the Falcon half; each validator's Falcon key is
/// registered (additive, keyed by the validator's ed id — no global wipe,
// so parallel tests cannot disturb each other).
async fn certify(live: &mut ValidatorRuntime, ks: &[SigningKey], blk: &mut Block) -> [u8; 32] {
    use stellereum::consensus::register_validator_pq_key;
    use stellereum::post_quantum::{FalconKeypair, PqScheme};
    let fks: Vec<FalconKeypair> = ks
        .iter()
        .enumerate()
        .map(|(i, _)| FalconKeypair::generate_from_seed(0xA0u8.wrapping_add(i as u8)))
        .collect();
    for (k, fk) in ks.iter().zip(fks.iter()) {
        register_validator_pq_key(id_of(k), PqScheme::Falcon512, fk.public_key.clone());
    }
    let bh = blk.compute_hash();
    let height = blk.height;
    for (k, fk) in ks.iter().zip(fks.iter()).take(3) {
        live.on_prevote(Vote::sign_with_falcon(k, fk, height, 0, VoteKind::Prevote, Some(bh)))
            .expect("prevote accepted");
        live.on_precommit(Vote::sign_with_falcon(k, fk, height, 0, VoteKind::Precommit, Some(bh)))
            .expect("precommit accepted");
    }
    assert_eq!(
        live.hc.try_precommit_quorum(),
        Some(bh),
        "precondition: 3 of 4 must form a quorum at height {height}"
    );
    let cert = live.hc.precommit_qc.clone().expect("QC exists");
    // `Block::compute_hash` excludes the QC, so attaching it cannot change bh.
    blk.precommit_qc = Some(cert);
    bh
}

fn mk_block(
    proposer: &SigningKey,
    height: u64,
    prev: [u8; 32],
    root: [u8; 32],
    txs: Vec<Transaction>,
) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    let mut blk = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root: root,
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: TS + height,
        proposer: id_of(proposer),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
    };
    blk.sign_block(proposer);
    blk
}

// ===========================================================================
// 1. The differential: realistic blocks through BOTH paths
// ===========================================================================

/// Three realistic blocks - plain transfer, payload transfer, a failing
/// transaction, a staking bond, a reward claim and an order placement - applied
/// through the live consensus path (engine A) and through `ChainState`
/// (engine B). Every height must agree on the state root, the receipts vector
/// and the applied counters, and the final accounts must be byte-identical.
#[tokio::test]
async fn realistic_blocks_match_byte_for_byte_on_live_and_reorg_paths() {
    let ks = keys(4);
    let vs = vset(&ks);
    let proposer_id = id_of(&ks[0]);
    let silent = id_of(&ks[3]);

    let alice = pq_user();
    let bob = [0xB0u8; 32];
    let carol = [0xC0u8; 32];
    let dave = pq_user();
    let nova = pq_user(); // bonds in block 2
    let trader = pq_user(); // places an order in block 2
    let claimer = pq_user(); // pays gas for the block-3 reward claim

    let funding: [([u8; 32], u64); 6] = [
        (pq_id(&alice), 2_000_000),
        (pq_id(&dave), 2_000_000),
        (pq_id(&nova), floor() + 2_000_000),
        (pq_id(&trader), 5_000_000),
        (pq_id(&claimer), 2_000_000),
        (bob, 0),
    ];
    let engines = mirrored_engines(&vs, &funding, &silent, 2).await;
    let (engine_live, engine_reorg) = (engines[0].clone(), engines[1].clone());

    let mut live = ValidatorRuntime::new(ks[0].clone(), vs.clone(), engine_live.clone(), 1)
        .with_block_reward(REWARD);
    let mut reorg = ChainState::new(engine_reorg.clone()).with_block_reward(REWARD);

    // --- block 1: plain transfer + payload transfer + one failing tx --------
    // gas_limit is DECLARED above the gas the payload actually consumes
    // (GAS_BASIC_TRANSFER) on purpose: that gap is exactly the fee-rule
    // divergence the reorg path used to lose on.
    let tx_plain = tx(&alice, bob, 1_000, 500_000, 0);
    let tx_payload = txp(
        &alice,
        bob,
        2_000,
        500_000,
        1,
        vec![OpCode::Transfer {
            recipient: carol,
            amount: 7_000,
        }],
    );
    // Valid signature, wrong nonce: admitted nowhere, payload never runs,
    // status false - the canonical "one failing tx" in a block.
    let tx_fail = tx(&dave, bob, 100, 500_000, 7);

    // --- block 2: staking bond + order placement ---------------------------
    // FULL-PQ: nova/trader are Falcon-512; the bond/validator ids are their
    // PQ addresses (the stake logic keys on addresses, not schemes).
    let tx_bond = txp(
        &nova,
        pq_id(&nova),
        0,
        500_000, // declared; GAS_STAKE_BOND = 2_000 is what the VM consumes
        0,
        vec![OpCode::SysCallStake {
            validator: pq_id(&nova),
            amount: floor(),
        }],
    );
    let tx_order = txp(
        &trader,
        [0u8; 32],
        0,
        500_000, // declared; GAS_ORDER_PLACE = 1_200 is what the VM consumes
        0,
        vec![OpCode::SysCallPlaceOrder {
            pair_id: 1,
            is_buy: true,
            price: 250_000,
            amount: 10,
        }],
    );

    // --- block 3: reward claim + another plain transfer --------------------
    // FULL-PQ: validator ids are still classical, and only the validator may
    // claim its own rewards — so an ed proposer's self-claim has no PQ path
    // (a PQ tx cannot be `from` an ed id; see the self-claim rule in
    // `svm.rs`). The claim is therefore submitted by a funded PQ third
    // party and REVERTS identically on both paths (attributable execution
    // failure: pays the floor, consumes the nonce, moves no rewards). The
    // uniform refusal is the parity property here; validator self-custody of
    // claims needs PQ validator ids (out of zone).
    let tx_claim = txp(
        &claimer,
        [0u8; 32],
        0,
        500_000, // declared; GAS_STAKE_CLAIM = 600 is consumed
        0,
        vec![OpCode::SysCallClaimRewards {
            validator: proposer_id,
        }],
    );
    let tx_plain2 = tx(&alice, bob, 500, 500_000, 2);

    let blocks: Vec<Vec<Transaction>> = vec![
        vec![tx_plain, tx_payload, tx_fail],
        vec![tx_bond, tx_order],
        vec![tx_claim, tx_plain2],
    ];
    let expected_status: Vec<Vec<bool>> =
        vec![vec![true, true, false], vec![true, true], vec![false, true]];

    // Pre-state proposer balance (genesis funding minus the escrowed bond):
    // no payout may reach anyone when the claim reverts.
    let proposer_before = balance(&engine_live, &id_of(&ks[0])).await;

    let mut prev_hash = [0u8; 32];
    // Canonical downtime evidence (W10.5): every block above the genesis
    // child carries the QC that decided its parent, exactly as production
    // proposers embed via `decided_parent_qc`. Without it the transition
    // attributes nothing on EITHER path (evidence `None` is a deterministic
    // skip), the height-1 slash never fires, the silent validator is never
    // ejected, nova's bond grows the height-3 set to 5, and the "3 of 4"
    // quorum below is unsatisfiable. Carrying it makes this test the
    // end-to-end live-vs-reorg parity proof under a rotation boundary.
    let mut parent_qc: Option<stellereum::consensus::QuorumCertificate> = None;
    for (i, txs) in blocks.into_iter().enumerate() {
        let height = (i + 1) as u64;
        let root = engine_live.get_state_root().await;
        assert_eq!(
            root,
            engine_reorg.get_state_root().await,
            "pre-state diverged before height {height}"
        );

        let mut blk = mk_block(&ks[0], height, prev_hash, root, txs);
        blk.last_qc = parent_qc.clone();
        let bh = certify(&mut live, &ks, &mut blk).await;

        // ---- LIVE ----
        live.blocks.insert(bh, blk.clone());
        assert_eq!(
            live.try_finalize().await,
            Some(bh),
            "live path must finalize height {height}"
        );
        // The decision just finalized is the next block's canonical
        // evidence (production `decided_parent_qc`, from local finalize AND
        // adopt alike).
        parent_qc = live.last_decision.clone().map(|(_, _, qc)| qc);
        // ---- REORG ----
        reorg.apply_block(&blk).await;

        assert_eq!(
            engine_live.get_state_root().await,
            engine_reorg.get_state_root().await,
            "STATE ROOT DIVERGED at height {height}: a reorg would fork here"
        );
        assert_eq!(
            live.applied_statuses, reorg.applied_statuses,
            "RECEIPTS DIVERGED at height {height}"
        );
        assert_eq!(
            live.applied_statuses, expected_status[i],
            "unexpected verdicts at height {height}"
        );
        assert_eq!(
            live.applied_fees, reorg.applied_fees,
            "CHARGED FEES DIVERGED at height {height}"
        );
        assert_eq!(
            live.applied_txs, reorg.applied_txs,
            "APPLIED TX COUNT DIVERGED at height {height}"
        );
        prev_hash = bh;
    }

    // Bookkeeping: 5 applied of 7 (the wrong-nonce tx failed on both
    // paths, and the non-validator claim reverts under FULL-PQ).
    assert_eq!(live.applied_txs, 5);
    assert_eq!(reorg.applied_txs, 5);

    // --- the fee rule: BOTH block paths charge the DECLARED limit ----------
    // alice: 1_000+500_000 (plain) + 2_000+500_000 (payload, declared) + the
    // payload's own Transfer of 7_000 to carol + 500+500_000. Charging the
    // consumed 280_000 instead of the declared 500_000 for the payload
    // transaction would leave her richer on exactly one of the two engines.
    let expected_alice =
        2_000_000 - (1_000 + 500_000) - (2_000 + 500_000) - 7_000 - (500 + 500_000);
    assert_eq!(balance(&engine_live, &pq_id(&alice)).await, expected_alice);
    assert_eq!(
        balance(&engine_reorg, &pq_id(&alice)).await,
        expected_alice,
        "the reorg path charged a different fee for the same block"
    );

    // Payload value movement on both paths.
    assert_eq!(balance(&engine_live, &carol).await, 7_000);
    assert_eq!(balance(&engine_reorg, &carol).await, 7_000);
    assert_eq!(balance(&engine_live, &bob).await, 1_000 + 2_000 + 500);
    assert_eq!(balance(&engine_reorg, &bob).await, 1_000 + 2_000 + 500);

    // The failed transaction moved nothing on either path.
    assert_eq!(balance(&engine_live, &pq_id(&dave)).await, 2_000_000);
    assert_eq!(balance(&engine_reorg, &pq_id(&dave)).await, 2_000_000);

    // The staking pool moved by EXACTLY three things, all of them state:
    //   + the genesis bonds (SEC-ECON-01: one bond per genesis validator is
    //     escrowed in the pool, not burned - so it is in the state root)
    //   + nova's bond (height 2)
    //   - the downtime burn (height 1's certificate)
    // E2: the (reverted) reward claim is paid out of NOTHING: a third party
    // cannot take the proposer's accrual, so the minted REWARDS_POOL is
    // untouched by it — never out of bonded principal either. A path that
    // debits the claim here, or skips the bond/burn, lands on a different
    // pool balance, and the pool balance is in the state root.
    let burned = engine_live.staking_read().await.total_burned;
    let genesis_bonds = vs.validators.len() as u64 * MIN_VALIDATOR_BOND;
    let expected_pool = genesis_bonds + 10 * MIN_VALIDATOR_BOND + floor() - burned;
    for e in [&engine_live, &engine_reorg] {
        assert_eq!(
            balance(e, &STAKING_POOL).await,
            expected_pool,
            "the pool must move by bond in and burn only - never by claims"
        );
        // The rewards pool moved by the mint (3 heights x REWARD); the
        // third-party claim reverted, so nothing was claimed, on both paths
        // identically.
        assert_eq!(
            balance(e, &REWARDS_POOL).await,
            3 * REWARD,
            "the rewards pool must hold the full mint when the claim reverts"
        );
        assert_eq!(
            e.staking_read().await.rewards_pool,
            3 * REWARD,
            "ledger pool accounting must match the native rewards pool"
        );
        assert_eq!(
            e.staking_read()
                .await
                .to_validator_set()
                .power_of(&pq_id(&nova)),
            floor(),
            "the bond must buy voting power"
        );
    }

    // No validator self-claim exists in FULL-PQ: the proposer's accrual from
    // heights 1-3 sits unclaimed, and the third-party claim reverted.
    // Height 3's OWN reward is distributed after the block's transactions
    // ran, so exactly 3 * REWARD is pending once the block is applied.
    for e in [&engine_live, &engine_reorg] {
        let pending = e.staking_read().await.validators[&proposer_id].pending_rewards;
        assert_eq!(
            pending,
            3 * REWARD,
            "with no valid self-claim, all three heights stay pending"
        );
        assert_eq!(
            balance(e, &id_of(&ks[0])).await,
            proposer_before + 3_000_000,
            "only the three blocks' declared fees (1M each) may credit the \
             proposer, never a claim payout"
        );
        // The reverted claim still paid the floor and consumed its nonce
        // (attributable execution failure), on both paths identically.
        let claimer_acct = e.get_account(&pq_id(&claimer)).await.unwrap();
        assert_eq!(
            claimer_acct.balance,
            2_000_000 - 500_000,
            "a reverted claim pays the declared floor"
        );
        assert_eq!(claimer_acct.nonce, 1, "a reverted claim consumes its nonce");
    }

    // The downtime slash ran - on BOTH paths, by the same amount.
    let burned_live = engine_live.staking_read().await.total_burned;
    let burned_reorg = engine_reorg.staking_read().await.total_burned;
    assert!(burned_live > 0, "precondition: the certificate must burn");
    assert_eq!(
        burned_live, burned_reorg,
        "DOWNTIME PARITY FAILURE: the reorg path burned {burned_reorg}, live {burned_live}"
    );
    assert_eq!(
        engine_live.staking_read().await.validators[&silent].missed,
        engine_reorg.staking_read().await.validators[&silent].missed,
        "miss counters must match"
    );
    assert_eq!(
        engine_live.staking_read().await.validators[&silent].last_downtime_penalty,
        engine_reorg.staking_read().await.validators[&silent].last_downtime_penalty,
        "the penalty must be stamped with the BLOCK height on both paths"
    );
    assert_eq!(
        engine_live.staking_read().await.validators[&silent].last_downtime_penalty,
        1,
        "the stamp is the height of the block whose certificate burned"
    );

    // Validator-set refresh: the live runtime re-derives its set from the
    // ledger after every height; the reorg path derives the same set from the
    // same committed ledger. Both must agree - including the ejection of the
    // slashed validator, whose bond fell below the minimum.
    let live_vs = live.validators.clone();
    let reorg_vs = reorg.validator_set().await;
    assert_eq!(
        live_vs.validators, reorg_vs.validators,
        "validator sets diverged"
    );
    assert!(
        !live_vs.contains(&silent),
        "precondition: the slash ejected the silent validator"
    );

    // The order actually landed in consensus state on both paths (the book is
    // part of the committed digest, so equal roots already imply this - this
    // names it).
    let books_live = engine_live.orderbooks_read().await;
    let books_reorg = engine_reorg.orderbooks_read().await;
    let book_live = books_live.get_book(1).expect("order book exists on live");
    let book_reorg = books_reorg.get_book(1).expect("order book exists on reorg");
    assert_eq!(book_live.depth(), book_reorg.depth(), "book depth diverged");
    let (bids, asks) = book_live.depth();
    assert!(bids + asks > 0, "the order must rest in the book");
}

// ===========================================================================
// 2. The divergence that MUST remain, pinned with its reason
// ===========================================================================

/// The single-transaction API (`InMemoryStateEngine::apply_transaction`) charges
/// the gas the payload actually CONSUMED; every BLOCK application charges the
/// DECLARED `gas_limit`.
///
/// WHY IT REMAINS: admission on the block path reserves exactly
/// `amount + gas_limit`, `fees_collected` (the sum of declared limits) is what
/// the proposer is credited with inside the shared transition, and the block
/// rule is what the chain has always charged. Flipping `apply_transaction` to
/// the declared limit would be an ECONOMIC change (it would start charging
/// unused gas), not a consistency fix - so it is pinned rather than unified:
///
///   * `bonding_moves_real_funds_and_grants_validator_power` pins the single-tx
///     rule (charges `GAS_STAKE_BOND`, not the 500_000 declared);
///   * `block_execution_runs_payloads_and_conserves_native_value` pins the
///     block rule (charges the declared limit, 500_000 here).
///
/// What WAS a bug is now closed: the REORG path used to sit on the single-tx
/// side of this line, so it charged a different fee for the same block than the
/// node that produced it. Both block paths are asserted equal below.
#[tokio::test]
async fn single_tx_api_charges_consumed_gas_while_both_block_paths_charge_declared() {
    let ks = keys(1);
    let claimer = pq_user();
    let to = [0x51u8; 32];
    let declared = 500_000u64;
    let mk_tx = || {
        txp(
            &claimer,
            to,
            1_000,
            declared,
            0,
            vec![OpCode::Transfer {
                recipient: [0x52u8; 32],
                amount: 3_000,
            }],
        )
    };

    // (a) single-transaction API: charges what the payload consumed.
    let single = Arc::new(InMemoryStateEngine::new());
    single
        .update_account(AccountState::new(pq_id(&claimer), 1_000_000))
        .await;
    single
        .apply_transaction(&mk_tx(), TS)
        .await
        .expect("applies");
    let single_sender = balance(&single, &pq_id(&claimer)).await;
    assert_eq!(
        single_sender,
        1_000_000 - 1_000 - 3_000 - GAS_BASIC_TRANSFER,
        "the single-tx API charges the consumed gas, not the declared limit"
    );

    // (b) block application: charges the declared limit. Run it through the
    //     shared core with a Block, i.e. the exact code both block paths call.
    let block_e = Arc::new(InMemoryStateEngine::new());
    block_e
        .update_account(AccountState::new(pq_id(&claimer), 1_000_000))
        .await;
    let blk = mk_block(&ks[0], 1, [0u8; 32], [0u8; 32], vec![mk_tx()]);
    let out = block_e.apply_block_transition(&blk, 0).await;
    assert_eq!(out.status, vec![true]);
    let block_sender = balance(&block_e, &pq_id(&claimer)).await;
    assert_eq!(
        block_sender,
        1_000_000 - 1_000 - 3_000 - declared,
        "every block application charges the DECLARED limit"
    );
    assert_eq!(
        out.fees_collected, declared,
        "fees_collected is the sum of declared limits - the proposer's credit"
    );

    // The divergence is real and DELIBERATE: unifying it is an economic change,
    // so the two rules are asserted to differ, on the record.
    assert_ne!(
        single_sender, block_sender,
        "PINNED DIVERGENCE: single-tx API charges consumed gas, blocks charge \
         the declared limit (admission reserved it and fees_collected is defined \
         as the sum of declared limits). Unifying would charge users for gas \
         they never burned."
    );

    // And the two BLOCK paths still cannot differ from each other.
    let reorg_e = Arc::new(InMemoryStateEngine::new());
    reorg_e
        .update_account(AccountState::new(pq_id(&claimer), 1_000_000))
        .await;
    let mut cs = ChainState::new(reorg_e.clone());
    cs.apply_block(&blk).await;
    assert_eq!(
        block_e.get_state_root().await,
        reorg_e.get_state_root().await
    );
    assert_eq!(cs.applied_statuses, out.status);
    assert_eq!(cs.applied_fees, out.tx_fees);
}

// ===========================================================================
// 3. Mempool pruning: node-local, and provably not state
// ===========================================================================

/// The live path prunes confirmed transactions from its mempool on every apply;
/// the reorg path only does so when a mempool is attached. That is the one
/// side effect outside the state engine, and this test pins both halves of it:
/// (a) attaching a mempool prunes exactly like the live path, and (b) pruning
/// cannot move the state root - a reorg with no mempool at all still lands on
/// the identical state.
#[tokio::test]
async fn mempool_pruning_is_node_local_and_cannot_move_the_state_root() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mempool_user = pq_user();
    let funding = [(pq_id(&mempool_user), 1_000_000u64)];
    let silent = id_of(&ks[3]);
    let engines = mirrored_engines(&vs, &funding, &silent, 3).await;
    let e_live = engines[0].clone();
    let e_reorg = engines[1].clone();
    // A THIRD engine: the no-mempool reorg must run on its own state, not
    // re-apply the block on top of the mempool-bearing engine's state.
    let e_nopool = engines[2].clone();

    let mut live = ValidatorRuntime::new(ks[0].clone(), vs.clone(), e_live.clone(), 1);
    let tx = tx(&mempool_user, [0x99u8; 32], 10, 100, 0);

    // The same transaction sits in both pools.
    let live_pool: Arc<tokio::sync::RwLock<Mempool>> =
        Arc::new(tokio::sync::RwLock::new(Mempool::default()));
    live = live.with_mempool(live_pool.clone());
    live_pool
        .write()
        .await
        .add_checked(tx.clone(), 1_000_000)
        .unwrap();

    let reorg_pool: Arc<tokio::sync::RwLock<Mempool>> =
        Arc::new(tokio::sync::RwLock::new(Mempool::default()));
    let mut cs = ChainState::new(e_reorg.clone()).with_mempool(reorg_pool.clone());
    reorg_pool
        .write()
        .await
        .add_checked(tx.clone(), 1_000_000)
        .unwrap();

    // And a third engine with NO mempool at all - the pure state comparison.
    let mut cs_nopool = ChainState::new(e_nopool.clone());

    let root = e_live.get_state_root().await;
    let mut blk = mk_block(&ks[0], 1, [0u8; 32], root, vec![tx.clone()]);
    let bh = certify(&mut live, &ks, &mut blk).await;

    live.blocks.insert(bh, blk.clone());
    assert_eq!(live.try_finalize().await, Some(bh));
    cs.apply_block(&blk).await;
    cs_nopool.apply_block(&blk).await;

    // (a) both attached pools dropped the confirmed transaction...
    assert!(live_pool.read().await.is_empty(), "live path must prune");
    assert!(
        reorg_pool.read().await.is_empty(),
        "the reorg path must prune when it is given a mempool"
    );
    // (b) ...and none of that is state: all three engines agree.
    assert_eq!(
        e_live.get_state_root().await,
        e_reorg.get_state_root().await,
        "a mempool cannot move the state root"
    );
    assert_eq!(
        e_live.get_state_root().await,
        e_nopool.get_state_root().await,
        "a reorg with no mempool lands on the identical state"
    );
    assert_eq!(live.applied_statuses, cs.applied_statuses);
    assert_eq!(live.applied_statuses, cs_nopool.applied_statuses);
    assert_eq!(live.applied_fees, cs.applied_fees);
    assert_eq!(live.applied_fees, cs_nopool.applied_fees);
}
