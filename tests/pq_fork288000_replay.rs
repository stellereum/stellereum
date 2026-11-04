//! Offline replay of live-testnet block #288000 (PQ fork anchor).
//!
//! On 2026-10-22 nodes B and C finalized the SAME block hash
//! `479dae...` with DIFFERENT post-state roots (B `e783...` failed/fee-0,
//! C `9f1e...` success/fee-395000) from byte-identical transactions.
//! This test replays the EXACT wire bytes of that transaction
//! (tx `6b096d17...`, dust self-transfer, explicit Falcon-512 envelope,
//! legacy no-salt framing) against a fresh engine in the live
//! pre-state shape and pins the canonical verdict: success, fee 395000.
//!
//! It also pins the consensus-safety property the fork violated:
//! two engines starting from identical pre-state that apply the same
//! block MUST reach identical verdicts and identical roots.

use stellereum::sharding::{Block, Transaction};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

/// Exact wire bytes of the block-#288000 transaction, captured from the
/// live cluster (identical on B and C, tx_hash 6b096d17...).
const RAW_TX_HEX: &str = concat!(
    "eff75acfeb416b7e7c48f0c2db79462073e20f86bbd34d2fba03158d80443ea3eff75acfeb416b7e7c48f0c2db79462073e2",
    "0f86bbd34d2fba03158d80443ea3010000000000000030570500000000000400000000000000000000000000000024060000",
    "0000000050513102008103092498c0f41e647356ad3cc2b9af024348a46aad08781a460437d7eafa08cab4fbc903088dc900",
    "e084cd919ff5ca0b8b1ab2b284368470418c22fe0b3b8e157b2731b743de610d2bf42b8298117757b586e3f781f670c6d694",
    "d4e1ad1718cd51965a092902d0f0b59230a8682bd84a2bbb0c78b86967a1395a761335b6a9a618797bfa6ad3541b4096194a",
    "49451a5ce79a0d19009e02e966c46c0064267839464ae30a4166a07d087930803f66d658315d4466180c0cd53a08f2f272d0",
    "290be86fa0c6a0aab088f28ae1c8d1502a74e1cc08960864cca12b23e28ee98580abca215fd8db92ea1e2d60dc9b4b262072",
    "a822b2880b524f7944cf317866ce3fde0812b1493131e8f528c4c25a92701c96506d0f735c884a6108ca08502353dbe7313a",
    "42d9118983a1675400b9bacb2d775c12b513666d240000ca2b6cc09d91dff79f5bec92d52fd09695a331e94f621d8c9b8702",
    "96b597ef030a18392a9e011e090485aa6c2f0d5964d83785a57c48c823b8bfecf538b55662054e150e5676f1f9022f38d526",
    "7156964ca35900b3b25444496dc549531a1983b908f620010242d90228355b018f18227917ceea8a7c156a93807739f23681",
    "28cec557086d83b9d9400bb8679368dd57643cdff99801b27990cb70f0c61e62518173bd888a5b10fba91cabfbb69a21b558",
    "081833891534484d0d25dd28267f94ba0f253441076c5b8dd8aca02d9b6863a4947b71ac64a288eca2348614a45d24747251",
    "863c685f1a62e51f910281d2160ff8648933695ae5241d14fc5342d6c48235c55a9dd1c97018bc0591a2dc58d815bba0ea1c",
    "36286502c944204e0876536992354246de0041adffb314b99afaa0429bc2c18aa29efb19f4830253210b72b6b3cb6f520952",
    "a190317f1cd162d233db3283c521c9d3f10a241655f0dcd2bd919f090c09407096421264f7540bd7e64fec4274c322b3bacd",
    "c702abac92ba51438a7ac4f669086c911ed22391c676e3a980a54acc32d00e238352aa99575711b78ba2cbf86b4f6b2d2551",
    "abad607936d64338fc177ca716f3520a909e6a116ad4d1ef6c501553600682876e8cd41bcd46ff6b9068d24a1f93b98988a6",
    "a0ab6515f5589be48a5c62e52ad9d0d8c1189039c95f0aec52e94972d446fa73609b4868d47b036587167110825941c0611d",
    "eb141e11ecf83d5b3d27f56720002b1bbac924454463f95e4ec6103b59e8a0d274ea379f3d1e263c63b015dcbe0a39b1cb88",
    "48243c85b2e5e7b19a0229719726ebab65fa13e2394c5476a7338f13e96a44950ab6eddc53f0ab1c9757fe10483184a6d335",
    "67b08514218f6db3508b5f93778226ed4308b795ad9971c324267f3bca436484846a618956af1b0a5a6e457226864060c4ff",
    "4ca05e204ab621a49ef2e2bb03e179ebf78b09a46ad416fd754b1af79a5c939c6be93a4bee754d820639f0aa42146d975d46",
    "beebe151f43735dea2b1fd295a9bc66f9e683e0bfd19bbc12511c425ca5bac88864e62ad68cc1aa9bd425f4c82c32469b107",
    "6dd4a5b33265c947bab47526091f287e18c7a59010596f8a3b4fe9c59869c678e9b68c73ec802d9e468f733c2bc84152d13a",
    "10d6a261e46a6d44bddf7cee527ee3de7e09097993312d1104b874abfb88e1404656a68eed5c9039719691d58656d874cab8",
    "c4e2998d1ed0d7ed99dfab9d8f9712d96c5b430cd9a07e8d134b81c9bc458ead15876ef4920dcc3c64f3d7c665d66a0ddc32",
    "de158dea3250b2478f29a64d28882688aa36ba58b61103f72822b3e6d6a2ade89cb7d1f74a83eef1f230cc010d795bc829f7",
    "665f89ec6b80cd2b36e73ff2eb5ad5de41bb5bf2edefc1e6c9e1540e39decf30daa1383810963277829122a9d163fa188a6c",
    "ce2b3ef96788fcc299a1b3d226a8da35274dcdd6355c61d5e441c654e08f9cee8f69cc5cacb225bd0ac0cf6709e6ae2d5be9",
    "e4557ab41d39735c794763ce8672fba91f08c58dd7a94e752e6d21a5dcea7f0cb5ff60589d0f7e84ec600a6e354dd334fcea",
    "5946a864568f8b21f1e1c1affb1caa488e336c44ed8efe2f34eeee68eab3589ccca9d373a66d5926aae4a3dbef7cc04b3a19",
    "438b4eee387d8f0476684b1c2986260eb4969b963a3794b9a3ed3e25457895f4a399c4aaf010d9f28ce8ff580642479422ea",
    "6d1d49c3d255cc4898c22516f5df5f27400000000000000000000000000000000000",
);

const FAUCET_HEX: &str = "eff75acfeb416b7e7c48f0c2db79462073e20f86bbd34d2fba03158d80443ea3";
const PROPOSER_HEX: &str = "9c675ebc6cd20c9226da2fcbf6c167647e4e948b78368f038058b6b419175fcd";
const BLOCK_TIMESTAMP: u64 = 1792705388;
/// Live post-state both nodes agree on for the faucet account.
const POST_BALANCE: u64 = 995_999_998_125_000;
const POST_NONCE: u64 = 5;
/// Success fee the canonical execution charges: declared 350_000 + PQ surcharge.
const CANONICAL_FEE: u64 = 350_000 + 45_000;

fn faucet() -> [u8; 32] {
    let v = hex::decode(FAUCET_HEX).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn proposer() -> [u8; 32] {
    let v = hex::decode(PROPOSER_HEX).unwrap();
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn decode_live_tx() -> Transaction {
    let bytes = hex::decode(RAW_TX_HEX).unwrap();
    let tx: Transaction = bincode::deserialize(&bytes).expect("live tx bytes must decode");
    assert!(tx.is_pq(), "the fork trigger is a PQ-envelope transaction");
    assert!(
        tx.is_pq_activation(),
        "explicit envelope => activation path (the pin check)"
    );
    assert_eq!(
        tx.from,
        faucet(),
        "dust self-transfer from the faucet account"
    );
    assert_eq!(tx.to, faucet());
    assert_eq!(tx.amount, 1);
    assert_eq!(tx.gas_limit, 350_000);
    assert_eq!(tx.nonce, 4);
    assert_eq!(
        hex::encode(tx.compute_tx_hash()),
        "6b096d17d5933a7ecf09cc7ebaa34e2debbf9e53a6f2fd6189a0fd92af8d9108"
    );
    tx
}

fn mk_block(tx: Transaction, proposer: [u8; 32]) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(std::slice::from_ref(&tx));
    Block {
        shard_id: 1,
        height: 288000,
        prev_hash: hex::decode("90ae6fd1adc95c29f78d660a74e6905b0daba1ed32280688f231bc4df4f0f545")
            .unwrap()
            .try_into()
            .unwrap(),
        state_root: [0u8; 32],
        transactions: vec![tx],
        cross_shard_out: vec![],
        timestamp: BLOCK_TIMESTAMP,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    }
}

/// Pre-state shape both live nodes had at #287999: the faucet funded at
/// nonce 4 with the Falcon-512 key already pinned (both post-state leaves
/// are the 49-byte pinned shape with the same pubkey hash).
async fn install_live_prestate(engine: &InMemoryStateEngine, tx: &Transaction) {
    let env = tx.pq_envelope().expect("explicit PQ envelope");
    assert!(!env.is_implicit);
    let pk = env.pubkey.clone().expect("activation carries the key");
    engine
        .pin_pubkey(tx.from, env.scheme, &pk, &env.salt)
        .await
        .expect("live key pins cleanly");
    let mut acc = AccountState::new(tx.from, POST_BALANCE + CANONICAL_FEE);
    acc.nonce = POST_NONCE - 1;
    engine.update_account(acc).await;
    // Re-pin after the funding write: funding must never strip the pin.
    engine
        .pin_pubkey(tx.from, env.scheme, &pk, &env.salt)
        .await
        .expect("pin survives funding");
    let stored = engine.get_account(&tx.from).await.unwrap();
    assert!(stored.pubkey_hash.is_some(), "pre-state carries the PQ pin");
    assert_eq!(stored.nonce, POST_NONCE - 1);
}

/// The canonical replay: the exact #288000 bytes apply cleanly as a success
/// charging gas_limit + PQ surcharge, leaving the exact live post-state leaf.
#[tokio::test]
async fn fork288000_replay_of_exact_bytes_is_a_success_charging_395000() {
    let tx = decode_live_tx();
    let engine = InMemoryStateEngine::new().with_parallel_exec(true);
    install_live_prestate(&engine, &tx).await;
    let prop = proposer();
    engine.update_account(AccountState::new(prop, 0)).await;

    let block = mk_block(tx.clone(), prop);
    let out = engine.apply_block_transition(&block, 0).await;

    assert_eq!(out.applied, 1, "canonical verdict: applied");
    assert_eq!(out.failed, 0, "canonical verdict: nothing failed");
    assert_eq!(out.status, vec![true]);
    assert_eq!(out.tx_fees, vec![CANONICAL_FEE]);
    assert_eq!(out.fees_collected, CANONICAL_FEE);

    let acc = engine.get_account(&faucet()).await.unwrap();
    assert_eq!(
        acc.balance, POST_BALANCE,
        "matches live post balance on BOTH nodes"
    );
    assert_eq!(
        acc.nonce, POST_NONCE,
        "matches live post nonce on BOTH nodes"
    );
    // The exact 49-byte pinned leaf both nodes serve for the faucet.
    assert_eq!(
        hex::encode(acc.to_trie_bytes()),
        "000389db5215a3c8000000000000000502caf5f20a4bb8940732616e39039278f51a3d10109342b831e07176e63ead7e6f"
    );
    let prop_acc = engine.get_account(&prop).await.unwrap();
    assert_eq!(prop_acc.balance, CANONICAL_FEE, "proposer credited the fee");
}

/// The safety property the fork violated: identical pre-state + identical
/// block bytes => identical verdicts, fees and post-state roots. Runs the
/// replay on two independent engines (one parallel, one sequential: the two
/// shapes the fleet runs) and demands bit-identical outcomes.
#[tokio::test]
async fn fork288000_identical_prestate_gives_identical_verdicts_and_roots() {
    let tx = decode_live_tx();
    let mut roots = Vec::new();
    let mut verdicts = Vec::new();
    for parallel in [true, false] {
        let engine = InMemoryStateEngine::new().with_parallel_exec(parallel);
        install_live_prestate(&engine, &tx).await;
        engine
            .update_account(AccountState::new(proposer(), 0))
            .await;
        let block = mk_block(tx.clone(), proposer());
        let out = engine.apply_block_transition(&block, 0).await;
        verdicts.push((out.applied, out.failed, out.tx_fees.clone()));
        roots.push(hex::encode(engine.get_state_root().await));
    }
    assert_eq!(
        verdicts[0], verdicts[1],
        "verdicts must not depend on the exec path"
    );
    assert_eq!(verdicts[0], (1, 0, vec![CANONICAL_FEE]));
    assert_eq!(
        roots[0], roots[1],
        "DIVERGENCE: same pre-state, same block, different roots"
    );
}

/// A conflicting PQ pin still refuses (fail-closed), and the refusal is
/// attributable: the failure fee is charged. Documents the boundary so a
/// future silent-success regression is caught.
///
/// NOTE: a conflicting pin cannot be installed via `pin_pubkey` (an address
/// mismatch refuses without mutating); it is simulated by writing the
/// divergent account leaf directly, i.e. the "invisibly different metadata"
/// shape from the incident hypothesis.
#[tokio::test]
async fn fork288000_conflicting_pin_refuses_with_failure_fee() {
    let tx = decode_live_tx();
    let engine = InMemoryStateEngine::new().with_parallel_exec(true);
    // Fund first, then install a DIVERGENT pin directly (same shape the
    // incident hypothesis ascribed to node B).
    let fake_hash = [0x99u8; 32];
    let mut acc = AccountState::new(tx.from, POST_BALANCE + CANONICAL_FEE);
    acc.nonce = POST_NONCE - 1;
    acc.scheme = stellereum::post_quantum::PqScheme::Falcon512;
    acc.pubkey_hash = Some(fake_hash);
    engine.update_account(acc).await;
    let block = mk_block(tx, proposer());
    let out = engine.apply_block_transition(&block, 0).await;
    assert_eq!((out.applied, out.failed), (0, 1));
    assert_eq!(
        out.tx_fees,
        vec![CANONICAL_FEE],
        "attributable failure pays the floor"
    );
}

/// An unpinned pre-state still succeeds: the activation pins the live key.
/// (Either pin shape converges to the same success verdict.)
#[tokio::test]
async fn fork288000_unpinned_prestate_still_succeeds() {
    let tx = decode_live_tx();
    let engine = InMemoryStateEngine::new().with_parallel_exec(true);
    let mut acc = AccountState::new(tx.from, POST_BALANCE + CANONICAL_FEE);
    acc.nonce = POST_NONCE - 1;
    assert!(acc.pubkey_hash.is_none());
    engine.update_account(acc).await;
    let block = mk_block(tx, proposer());
    let out = engine.apply_block_transition(&block, 0).await;
    assert_eq!((out.applied, out.failed), (1, 0));
    assert_eq!(out.tx_fees, vec![CANONICAL_FEE]);
    let stored = engine.get_account(&faucet()).await.unwrap();
    assert!(stored.pubkey_hash.is_some(), "activation pins the key");
}

/// Determinism sweep: the exact live bytes replayed 25x across fresh engines
/// (alternating parallel/sequential, polluted global registry) never flip the
/// verdict. A single flip would be the nondeterminism that split B and C.
#[tokio::test]
async fn fork288000_verdict_is_deterministic_across_runs() {
    let tx = decode_live_tx();
    // Pollute the process-global implicit registry the way a long-lived node
    // would be: a stale entry for the faucet must not move an explicit tx.
    let _ = stellereum::sharding::Transaction::global_implicit_registry().register(
        faucet(),
        stellereum::post_quantum::PqScheme::Falcon512,
        &vec![0xEEu8; 897],
        &stellereum::post_quantum::DEFAULT_SALT,
    );
    for i in 0..25 {
        let engine = InMemoryStateEngine::new().with_parallel_exec(i % 2 == 0);
        install_live_prestate(&engine, &tx).await;
        engine
            .update_account(AccountState::new(proposer(), 0))
            .await;
        let block = mk_block(tx.clone(), proposer());
        let out = engine.apply_block_transition(&block, 0).await;
        assert_eq!((out.applied, out.failed), (1, 0), "flip on iteration {i}");
        assert_eq!(
            out.tx_fees,
            vec![CANONICAL_FEE],
            "fee flip on iteration {i}"
        );
    }
}
