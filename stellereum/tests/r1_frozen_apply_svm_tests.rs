//! R1-D Frozen-Apply & SVM hardening integration tests.
//!
//! Covers:
//! - Default `u64::MAX` invariants (`FORK_ID == 0x0f584a46`, `COMMITMENT_VERSION == 5`, `EXPECTED_GENESIS_ROOT`).
//! - `EXEC_HARDENING_V1` (`H - 1 / H / H + 1`):
//!   * `OpCode::Halt` barrier in `bridge_intents`, `rotation_aliases`, `apply_cnvrf_v3`,
//!     `apply_staking_unjail_ops`, and `apply_equivocation_slash`;
//!   * `SysCallCallContractArgs` + `SysCallSubmitPqPriceFeed` rollback snapshots;
//!   * `[OpCode::Nop]` `TX_INTRINSIC_GAS = 280_000` floor vs pre-H `gas_limit = 10_000` stake;
//!   * `SysCallPlaceOrder` per-fill gas without `.min(64)` and `MAX_MATCH_FILLS_PER_ORDER = 256`;
//!   * `SysCallCancelOrder` read-only owner check without cloning + hardened gas.
//! - `WASM_XSHARD_PMM_HARDENING` (`H - 1 / H / H + 1`):
//!   * `outbound_messages` deferred after `commit_native` (no leak on failed CLOB or commit);
//!   * `sync_contract_balance` and 1:1 bounce balance conservation (zero free-minting);
//!   * `deploy_with_nonce(tx.nonce)` parity vs legacy `contracts.next_nonce`;
//!   * `SysCallPmmBuy` CEI (`wUSDT` checked before curve) + `ZeroMint` / `ZeroPayout`;
//!   * `PQ1` non-canonical `salt || key` accepted at `H - 1`, rejected at `H` / `H + 1`
//!     even with verify-once attestation cached.
//! - `parallel_exec == sequential` parity at `H - 1` and `H`, and
//!   `apply_transaction_at_height == block_apply`.

use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::sync::Arc;

use stellereum::bridge::{BridgeIntent, SupportedChain};
use stellereum::chain_spec::{
    exec_hardening_v1_active_at, set_exec_hardening_v1_activation_override,
    set_wasm_xshard_pmm_hardening_activation_override, wasm_xshard_pmm_hardening_active_at,
    EXEC_HARDENING_V1_ACTIVATION_HEIGHT, WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT,
};
use stellereum::cn_vrf::cnvrf_v3_commit;
use stellereum::commitment::COMMITMENT_VERSION;
use stellereum::consensus::{
    encode_pq_epoch_envelope, vote_sign_bytes, EquivocationEvidence, PqMicroCertificate,
    QuorumCertificate, ValidatorSet, Vote, VoteKind, PQ_QC_MARKER_ID,
};
use stellereum::contract::{contract_address, ContractCallContext, ContractRegistry};
use stellereum::oracle::PqPriceFeedUpdate;
use stellereum::orderbook::{OrderSide, OrderbookActor, MAX_MATCH_FILLS_PER_ORDER};
use stellereum::pmm::{PmmVmContext, PrimaryMarketMaker};
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN, PQ_ENVELOPE_MAGIC,
};
use stellereum::protocol::FORK_ID;
use stellereum::sharding::{Block, PqSignatureEnvelope, Transaction};
use stellereum::staking::{
    required_bond_floor_nano, DOWNTIME_MISS_THRESHOLD, JAIL_RELEASE_DELAY_HEIGHTS,
    MIN_VALIDATOR_BOND, STAKING_POOL,
};
use stellereum::state_engine::{
    record_verified_signature, verify_once_clear, AccountState, InMemoryStateEngine,
};
use stellereum::svm::{
    OpCode, Svm, VmContext, VmExecOptions, VmExecutionResult, GAS_ORDER_CANCEL,
    GAS_ORDER_CANCEL_HARDENED, GAS_PER_MATCH_LEVEL, GAS_STAKE_BOND, MAX_MATCH_LEVELS,
};
use stellereum::token::{TokenMetadata, TokenRegistry};

const H: u64 = 10;

struct GateResetGuard;
impl Drop for GateResetGuard {
    fn drop(&mut self) {
        set_exec_hardening_v1_activation_override(None);
        set_wasm_xshard_pmm_hardening_activation_override(None);
    }
}

fn sign_pq_tx(
    kp: &FalconKeypair,
    salt: &[u8; 16],
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    payload: Vec<OpCode>,
) -> Transaction {
    let dummy = vec![0u8; FALCON512_SIG_LEN];
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        dummy,
        to,
        amount,
        gas_limit,
        nonce,
        1,
        1,
        payload.clone(),
        salt,
    );
    let sig = kp.sign(&probe.signing_message());
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        sig,
        to,
        amount,
        gas_limit,
        nonce,
        1,
        1,
        payload,
        salt,
    )
}

fn sstore_contract_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (import "host" "sstore" (func $sstore (param i64 i64)))
          (import "host" "sload" (func $sload (param i64) (result i64)))
          (import "host" "caller" (func $caller (param i32)))
          (import "host" "origin" (func $origin (param i32)))
          (import "host" "return_data" (func $return_data (param i32 i32)))
          (import "host" "send_message" (func $send_message (param i64 i64 i64 i64 i64 i64) (result i64)))
          (memory (export "memory") 1)
          (func (export "set") (param $k i64) (param $v i64) (result i64)
            (call $sstore (local.get $k) (local.get $v))
            (local.get $v))
          (func (export "set1") (param $v i64) (result i64)
            (call $sstore (i64.const 1) (local.get $v))
            (local.get $v))
          (func (export "get") (param $k i64) (result i64)
            (call $sload (local.get $k)))
          (func (export "send_raw") (param $val i64) (result i64)
            (i64.store (i32.const 0) (i64.const 0x1111111111111111))
            (i64.store (i32.const 8) (i64.const 0x2222222222222222))
            (i64.store (i32.const 16) (i64.const 0x3333333333333333))
            (i64.store (i32.const 24) (i64.const 0x4444444444444444))
            (i32.store (i32.const 32) (i32.const 0x59414b4f))
            (call $send_message (i64.const 0) (i64.const 32) (local.get $val) (i64.const 32) (i64.const 4) (i64.const 1)))
          (func (export "send_empty") (param $val i64) (result i64)
            (i64.store (i32.const 0) (i64.const 0xAAAAAAAAAAAAAAAA))
            (i64.store (i32.const 8) (i64.const 0xBBBBBBBBBBBBBBBB))
            (i64.store (i32.const 16) (i64.const 0xCCCCCCCCCCCCCCCC))
            (i64.store (i32.const 24) (i64.const 0xDDDDDDDDDDDDDDDD))
            (call $send_message (i64.const 0) (i64.const 32) (local.get $val) (i64.const 32) (i64.const 0) (i64.const 1)))
          (func (export "send_empty_existing") (param $val i64) (result i64)
            (i64.store (i32.const 0) (i64.const 0x5555555555555555))
            (i64.store (i32.const 8) (i64.const 0x5555555555555555))
            (i64.store (i32.const 16) (i64.const 0x5555555555555555))
            (i64.store (i32.const 24) (i64.const 0x5555555555555555))
            (call $send_message (i64.const 0) (i64.const 32) (local.get $val) (i64.const 32) (i64.const 0) (i64.const 1)))
          (func (export "who") (param $x i64) (result i64)
            (call $caller (i32.const 0))
            (call $origin (i32.const 32))
            (call $return_data (i32.const 0) (i32.const 64))
            (local.get $x)))"#,
    )
    .expect("sstore_contract_wasm compiles")
}

#[tokio::test]
async fn default_u64_max_invariants_fork_id_commitment_and_genesis_root() {
    assert_eq!(EXEC_HARDENING_V1_ACTIVATION_HEIGHT, u64::MAX);
    assert_eq!(WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT, u64::MAX);
    assert!(!exec_hardening_v1_active_at(0));
    assert!(!exec_hardening_v1_active_at(u64::MAX));
    assert!(!wasm_xshard_pmm_hardening_active_at(0));
    assert!(!wasm_xshard_pmm_hardening_active_at(u64::MAX));
    assert_eq!(FORK_ID, 0x0f584a46);
    assert_eq!(COMMITMENT_VERSION, 5);

    let engine = Arc::new(InMemoryStateEngine::new());
    let vs = ValidatorSet::from_list(vec![([0x11u8; 32], 1), ([0x22u8; 32], 1)]);
    stellereum::runtime::fund_genesis(&engine, &vs, 100_000_000_000_000_000).await;
    let seed =
        hex::decode("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
    let faucet = stellereum::rpc::Faucet::new(
        <[u8; 32]>::try_from(seed.as_slice()).unwrap(),
        1,
        100 * 1_000_000_000,
        1_000 * 1_000_000_000,
    );
    let _ = engine
        .credit_native_transfer(&faucet.account(), 1_000_000_000_000_000)
        .await;
    assert_eq!(
        hex::encode(engine.get_state_root().await),
        "c07880e016dbb60dd84d9d1dd64bd141e4694d99ba919c288b9b08554f9373a5"
    );
}

#[tokio::test]
async fn halt_barrier_blocks_post_halt_bridge_rotate_unjail_and_equivocation_at_h_and_h_plus_1() {
    let _guard = GateResetGuard;
    set_exec_hardening_v1_activation_override(Some(H));

    // 1. Post-Halt SysCallBridge: settled on H-1, blocked on H and H+1.
    for (height, should_settle) in [(H - 1, true), (H, false), (H + 1, false)] {
        let engine = InMemoryStateEngine::new();
        let kp = FalconKeypair::generate_from_seed(0x12);
        let salt = DEFAULT_SALT;
        let sender = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &salt);
        engine
            .update_account(AccountState::new(sender, 10_000_000_000))
            .await;

        let withdraw = BridgeIntent::Withdraw {
            chain: SupportedChain::Ethereum,
            target_address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            amount: 5_000_000,
        };
        let tx = sign_pq_tx(
            &kp,
            &salt,
            [0u8; 32],
            0,
            1_000_000,
            0,
            vec![OpCode::Halt, OpCode::SysCallBridge(Box::new(withdraw))],
        );
        engine
            .apply_transaction_at_height(&tx, 1_700_000_000, height)
            .await
            .expect("tx applies");

        let escrow_bal = engine
            .get_account(&stellereum::bridge::BRIDGE_ESCROW)
            .await
            .map(|a| a.balance)
            .unwrap_or(0);
        if should_settle {
            assert_eq!(
                escrow_bal, 5_000_000,
                "pre-H ({height}) executes post-Halt SysCallBridge"
            );
        } else {
            assert_eq!(
                escrow_bal, 0,
                "hardened ({height} >= {H}) must ignore post-Halt SysCallBridge"
            );
        }
    }

    // 2. Post-Halt SysCallRotateValidatorKey in apply_cnvrf_v3, SysCallUnjail in
    //    apply_staking_unjail_ops, and SysCallReportEquivocation in apply_equivocation_slash.
    //    Use H_UNJAIL > JAIL_RELEASE_DELAY_HEIGHTS (4_000) so unjail is eligible on H_UNJAIL-1.
    let h_unjail: u64 = JAIL_RELEASE_DELAY_HEIGHTS + 500;
    set_exec_hardening_v1_activation_override(Some(h_unjail));

    for (height, legacy_leaks) in [
        (h_unjail - 1, true),
        (h_unjail, false),
        (h_unjail + 1, false),
    ] {
        let engine = InMemoryStateEngine::new();
        engine.set_cnvrf_v3_activation_height_for_tests(0);

        let signer_kp = FalconKeypair::generate_from_seed(0x21);
        let old_id = derive_pq_address(PqScheme::Falcon512, &signer_kp.public_key, &DEFAULT_SALT);
        let new_id = [0x99u8; 32];

        let sk_ed = SigningKey::from_bytes(&[0x33u8; 32]);
        let ed_id = sk_ed.verifying_key().to_bytes();
        let ed_fk = FalconKeypair::generate_from_seed(0x34);
        stellereum::consensus::register_validator_pq_key(
            ed_id,
            PqScheme::Falcon512,
            ed_fk.public_key.clone(),
        );

        let voter_kp = FalconKeypair::generate_from_seed(0x41);
        let voter_addr =
            derive_pq_address(PqScheme::Falcon512, &voter_kp.public_key, &DEFAULT_SALT);

        engine
            .update_account(AccountState::new(old_id, 10_000_000_000))
            .await;
        engine
            .update_account(AccountState::new(voter_addr, 10_000_000_000))
            .await;
        engine
            .update_account(AccountState::new(STAKING_POOL, 1_000_000_000_000_000))
            .await;

        {
            let mut ledger = engine.staking_write().await;
            ledger
                .bond(old_id, required_bond_floor_nano() * 2, 0)
                .unwrap();
            ledger.bond(ed_id, MIN_VALIDATOR_BOND * 2, 0).unwrap();
            ledger.bond(voter_addr, MIN_VALIDATOR_BOND * 2, 0).unwrap();
            ledger
                .register_pq_key(voter_addr, PqScheme::Falcon512, voter_kp.public_key.clone())
                .unwrap();

            // Trigger real downtime jail on `old_id` at height `DOWNTIME_MISS_THRESHOLD`,
            // so `release_height = DOWNTIME_MISS_THRESHOLD + JAIL_RELEASE_DELAY_HEIGHTS < h_unjail - 1`.
            for mh in 1..=DOWNTIME_MISS_THRESHOLD {
                let _ = ledger.note_missed_heights(mh as u64, &|v| *v != old_id, &[old_id, ed_id]);
            }
            assert!(ledger.is_jailed(&old_id), "precondition: old_id is jailed");
        }

        // Seed CN-VRF v3 commitment for `old_id` (epoch 1, admitted at height 0).
        {
            let mut cnvrf = engine.cnvrf_v3_write().await;
            let commit = cnvrf_v3_commit(&signer_kp, engine.chain_id, &old_id, 1, &[0xABu8; 48]);
            cnvrf
                .admit_commit(&commit, 0, engine.chain_id, &signer_kp.public_key)
                .expect("admit cnvrf commit");
        }

        let vote_a =
            Vote::sign_with_falcon(&sk_ed, &ed_fk, 1, 0, VoteKind::Prevote, Some([0x11u8; 32]));
        let vote_b =
            Vote::sign_with_falcon(&sk_ed, &ed_fk, 1, 0, VoteKind::Prevote, Some([0x22u8; 32]));
        let eq_ev = EquivocationEvidence::new(ed_id, vote_a, vote_b);

        let tx = sign_pq_tx(
            &signer_kp,
            &DEFAULT_SALT,
            [0u8; 32],
            0,
            1_000_000,
            0,
            vec![
                OpCode::Halt,
                OpCode::SysCallUnjail { validator: old_id },
                OpCode::SysCallRotateValidatorKey {
                    old_validator: old_id,
                    new_validator: new_id,
                },
                OpCode::SysCallReportEquivocation {
                    evidence: Box::new(eq_ev),
                },
            ],
        );

        let block = Block {
            height,
            timestamp: 1_700_000_000,
            proposer: voter_addr,
            transactions: vec![tx],
            ..Default::default()
        };

        let outcome = engine.apply_block_transition(&block, 0).await;
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.status, vec![true]);

        let ledger = engine.staking_read().await;
        let still_jailed = ledger.is_jailed(&old_id);
        let ed_bond = ledger.validators.get(&ed_id).unwrap().self_bond;
        drop(ledger);

        let cnvrf = engine.cnvrf_v3_read().await;
        let migrated = cnvrf.get_record(&new_id, 1).is_some();
        drop(cnvrf);

        if legacy_leaks {
            assert!(!still_jailed, "pre-H scans post-Halt SysCallUnjail");
            assert!(
                ed_bond < MIN_VALIDATOR_BOND * 2,
                "pre-H scans post-Halt SysCallReportEquivocation"
            );
            assert!(
                migrated,
                "pre-H scans post-Halt SysCallRotateValidatorKey in apply_cnvrf_v3"
            );
        } else {
            assert!(
                still_jailed,
                "hardened ({height} >= {h_unjail}) must ignore post-Halt SysCallUnjail"
            );
            assert_eq!(
                ed_bond,
                MIN_VALIDATOR_BOND * 2,
                "hardened ({height} >= {h_unjail}) must ignore post-Halt SysCallReportEquivocation"
            );
            assert!(
                !migrated,
                "hardened ({height} >= {h_unjail}) must ignore post-Halt SysCallRotateValidatorKey in apply_cnvrf_v3"
            );
        }
    }

    // 3. Post-Halt `rotation_aliases` in downtime slash attribution:
    //    `new_id` sits at `DOWNTIME_MISS_THRESHOLD - 1` misses; `old_id` is in `full_exits_at(height - 1)`.
    //    `tx` has `[OpCode::Halt, OpCode::SysCallRotateValidatorKey { old_validator: old_id, new_validator: new_id }]`.
    //    At `H - 1`: `rotation_aliases` aliases `old_id -> new_id`, slashing `new_id`.
    //    At `H`: `Halt` blocks `rotation_aliases`, so `new_id` is NOT slashed.
    set_exec_hardening_v1_activation_override(Some(H));
    for (height, expects_alias_slash) in [(H - 1, true), (H, false)] {
        let engine = InMemoryStateEngine::new();
        let kp_old = FalconKeypair::generate_from_seed(0x51);
        let old_id = derive_pq_address(PqScheme::Falcon512, &kp_old.public_key, &DEFAULT_SALT);
        // Ensure `new_id < old_id` in BTreeMap order so `new_id` is processed first
        // (signing QC -> missed drops to DOWNTIME_MISS_THRESHOLD - 1) and `old_id`
        // second (absent from QC -> increments `new_id.missed` iff aliased).
        let new_id = [0x01u8; 32];
        assert!(new_id < old_id, "test precondition: new_id < old_id");

        let fk_new = FalconKeypair::generate_from_seed(0x53);
        let fk_signer = FalconKeypair::generate_from_seed(0x52);
        let signer_id =
            derive_pq_address(PqScheme::Falcon512, &fk_signer.public_key, &DEFAULT_SALT);

        stellereum::consensus::register_validator_pq_key(
            new_id,
            PqScheme::Falcon512,
            fk_new.public_key.clone(),
        );
        stellereum::consensus::register_validator_pq_key(
            signer_id,
            PqScheme::Falcon512,
            fk_signer.public_key.clone(),
        );

        engine
            .update_account(AccountState::new(old_id, 10_000_000_000))
            .await;
        engine
            .update_account(AccountState::new(STAKING_POOL, 1_000_000_000_000_000))
            .await;

        {
            let mut ledger = engine.staking_write().await;
            ledger.bond(signer_id, MIN_VALIDATOR_BOND * 10, 0).unwrap();
            ledger.bond(new_id, MIN_VALIDATOR_BOND * 2, 0).unwrap();
            ledger
                .register_pq_key(new_id, PqScheme::Falcon512, fk_new.public_key.clone())
                .unwrap();
            ledger
                .register_pq_key(signer_id, PqScheme::Falcon512, fk_signer.public_key.clone())
                .unwrap();
            // Advance `new_id` to `DOWNTIME_MISS_THRESHOLD` misses directly on its record.
            ledger.validators.get_mut(&new_id).unwrap().missed = DOWNTIME_MISS_THRESHOLD;
            ledger.record_full_exits_at(&[(old_id, 1)], height - 1);
        }

        // Build an Epoch QC at `height - 1` signed by `signer_id` AND `new_id` (only `old_id` absent).
        let prev_set = {
            let l = engine.staking_read().await;
            let mut s = l.to_validator_set();
            s.add(old_id, 1);
            s
        };
        let mut ids: Vec<[u8; 32]> = prev_set.validators.keys().copied().collect();
        ids.sort_unstable();
        let target = Some([0xAAu8; 32]);
        let msg = vote_sign_bytes(height - 1, 0, VoteKind::Precommit, &target);
        let mut bitmask = vec![0u8; ids.len().div_ceil(8)];
        let mut sigs = Vec::new();
        for (idx, id) in ids.iter().enumerate() {
            if *id == new_id {
                bitmask[idx / 8] |= 1 << (idx % 8);
                sigs.push(fk_new.sign(&msg));
            } else if *id == signer_id {
                bitmask[idx / 8] |= 1 << (idx % 8);
                sigs.push(fk_signer.sign(&msg));
            }
        }
        let cert = PqMicroCertificate::new(
            PqScheme::Falcon512,
            height - 1,
            0,
            ids.len() as u32,
            bitmask,
            sigs,
            [0u8; 32],
        );
        let qc = QuorumCertificate {
            shard_id: 0,
            height: height - 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: target,
            signatures: vec![(PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&cert))],
        };
        assert!(qc.verify(&prev_set), "precondition: epoch QC verifies");

        let tx = sign_pq_tx(
            &kp_old,
            &DEFAULT_SALT,
            [0u8; 32],
            0,
            1_000_000,
            0,
            vec![
                OpCode::Halt,
                OpCode::SysCallRotateValidatorKey {
                    old_validator: old_id,
                    new_validator: new_id,
                },
            ],
        );
        let block = Block {
            height,
            timestamp: 1_700_000_000,
            proposer: signer_id,
            transactions: vec![tx],
            last_qc: Some(qc),
            ..Default::default()
        };
        let outcome = engine.apply_block_transition(&block, 0).await;
        if expects_alias_slash {
            assert!(
                outcome.slashed > 0,
                "pre-H ({height}) builds rotation_aliases across Halt and slashes new_id"
            );
        } else {
            assert_eq!(
                outcome.slashed, 0,
                "hardened ({height} >= {H}) must ignore post-Halt rotation_aliases"
            );
        }
    }
}

#[tokio::test]
async fn snapshot_rollback_covers_call_contract_args_and_submit_pq_price_feed_at_h_and_h_plus_1() {
    let _guard = GateResetGuard;
    set_exec_hardening_v1_activation_override(Some(H));

    // 1. SysCallCallContractArgs rollback on commit_native failure.
    for (height, should_rollback) in [(H - 1, false), (H, true), (H + 1, true)] {
        let engine = InMemoryStateEngine::new();
        let kp = FalconKeypair::generate_from_seed(0x61);
        let sender = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
        let contract_addr = engine
            .deploy_contract(sender, sstore_contract_wasm(), 1)
            .await
            .expect("deploy contract");

        // Sender holds 1_000_000: passes pre-check (gas_limit=600_000), passes VM,
        // fails commit_native (`required = fee + 800_000 > 1_000_000`).
        engine
            .update_account(AccountState::new(sender, 1_000_000))
            .await;

        let tx = sign_pq_tx(
            &kp,
            &DEFAULT_SALT,
            [0u8; 32],
            0,
            600_000,
            0,
            vec![
                OpCode::SysCallCallContractArgs {
                    contract: contract_addr,
                    method: b"set".to_vec(),
                    args: vec![7, 999],
                    calldata: Vec::new(),
                },
                OpCode::Transfer {
                    recipient: [0xBBu8; 32],
                    amount: 800_000,
                },
            ],
        );

        let res = engine
            .apply_transaction_at_height(&tx, 1_700_000_000, height)
            .await;
        assert!(res.is_err(), "commit_native must fail on combined debit");

        let stored = engine
            .contracts_read()
            .await
            .get(&contract_addr)
            .unwrap()
            .storage
            .get(&7)
            .copied();
        if should_rollback {
            assert_eq!(
                stored, None,
                "hardened ({height} >= {H}) must roll back SysCallCallContractArgs storage on commit failure"
            );
        } else {
            assert_eq!(
                stored,
                Some(999),
                "pre-H ({height}) missed SysCallCallContractArgs in snapshot_payload_domains"
            );
        }
    }

    // 2. SysCallSubmitPqPriceFeed rollback on commit_native failure.
    for (height, should_rollback) in [(H - 1, false), (H, true), (H + 1, true)] {
        let engine = InMemoryStateEngine::new();
        let kp = FalconKeypair::generate_from_seed(0x62);
        let sender = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
        let pub_kp = FalconKeypair::generate_from_seed(0x63);
        assert!(engine
            .oracle_write()
            .await
            .register_pq_publisher(&pub_kp.public_key));

        engine
            .update_account(AccountState::new(sender, 1_000_000))
            .await;

        let feed = PqPriceFeedUpdate::sign("STELL", 250_000, 1_700_000_000, &pub_kp);
        let tx = sign_pq_tx(
            &kp,
            &DEFAULT_SALT,
            [0u8; 32],
            0,
            600_000,
            0,
            vec![
                OpCode::SysCallSubmitPqPriceFeed(Box::new(feed)),
                OpCode::Transfer {
                    recipient: [0xBBu8; 32],
                    amount: 800_000,
                },
            ],
        );

        let res = engine
            .apply_transaction_at_height(&tx, 1_700_000_000, height)
            .await;
        assert!(res.is_err(), "commit_native must fail on combined debit");

        let committed_price = engine
            .oracle_read()
            .await
            .feeds
            .get("STELL")
            .map(|f| f.price_micro_usd);
        if should_rollback {
            assert_eq!(
                committed_price, None,
                "hardened ({height} >= {H}) must roll back SysCallSubmitPqPriceFeed on commit failure"
            );
        } else {
            assert_eq!(
                committed_price,
                Some(250_000),
                "pre-H ({height}) missed SysCallSubmitPqPriceFeed in oracle_before/snapshot"
            );
        }
    }
}

fn sign_pq_implicit_tx(
    kp: &FalconKeypair,
    from: [u8; 32],
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    payload: Vec<OpCode>,
) -> Transaction {
    let dummy = vec![0u8; FALCON512_SIG_LEN];
    let probe = Transaction::new_pq_implicit(
        from,
        PqScheme::Falcon512,
        dummy,
        to,
        amount,
        gas_limit,
        nonce,
        1,
        1,
        payload.clone(),
    );
    let sig = kp.sign(&probe.signing_message());
    Transaction::new_pq_implicit(
        from,
        PqScheme::Falcon512,
        sig,
        to,
        amount,
        gas_limit,
        nonce,
        1,
        1,
        payload,
    )
}

#[tokio::test]
async fn nop_billed_gas_280k_and_bonding_pre_h_gas_limit_10k_boundary() {
    let _guard = GateResetGuard;
    set_exec_hardening_v1_activation_override(Some(H));

    // [OpCode::Nop] at H-1 vs H vs H+1 (using pinned implicit tx so surcharge == 0)
    for (height, expected_fee) in [(H - 1, 1u64), (H, 280_000u64), (H + 1, 280_000u64)] {
        let engine = InMemoryStateEngine::new();
        let kp = FalconKeypair::generate_from_seed(0x71);
        let sender = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
        let initial = 10_000_000u64;
        engine
            .update_account(AccountState::new(sender, initial))
            .await;
        engine
            .pin_pubkey(sender, PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
            .await
            .unwrap();

        let tx = sign_pq_implicit_tx(&kp, sender, [0u8; 32], 0, 500_000, 0, vec![OpCode::Nop]);
        let (applied, failed, fees, status, tx_fees, _events) = engine
            .apply_block_parallel_fees_with_events_at_height(&[tx], 1_700_000_000, height)
            .await;
        assert_eq!(applied, 1);
        assert_eq!(failed, 0);
        assert_eq!(status, vec![true]);
        assert_eq!(tx_fees, vec![expected_fee]);
        assert_eq!(fees, expected_fee);
        assert_eq!(
            engine.get_account(&sender).await.unwrap().balance,
            initial - expected_fee
        );
    }

    // Expensive payload (gas_used > 280_000) does NOT double-add 280_000 on >= H.
    {
        let engine = InMemoryStateEngine::new();
        let kp = FalconKeypair::generate_from_seed(0x72);
        let sender = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
        let initial = 10_000_000u64;
        engine
            .update_account(AccountState::new(sender, initial))
            .await;
        engine
            .pin_pubkey(sender, PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
            .await
            .unwrap();
        let tx = sign_pq_implicit_tx(
            &kp,
            sender,
            [0u8; 32],
            0,
            1_000_000,
            0,
            vec![
                OpCode::Transfer {
                    recipient: [0x22u8; 32],
                    amount: 100,
                },
                OpCode::Transfer {
                    recipient: [0x22u8; 32],
                    amount: 100,
                },
            ],
        );
        let (_a, _f, fees, status, tx_fees, _) = engine
            .apply_block_parallel_fees_with_events_at_height(&[tx], 1_700_000_000, H)
            .await;
        assert_eq!(status, vec![true]);
        assert_eq!(tx_fees, vec![560_000]);
        assert_eq!(fees, 560_000);
    }

    // Pre-H (`H - 1`) preserves `SysCallStake` with `gas_limit = 10_000` billing 2_000 (`GAS_STAKE_BOND`).
    {
        let engine = InMemoryStateEngine::new();
        let kp = FalconKeypair::generate_from_seed(0x73);
        let sender = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
        let bond_amt = required_bond_floor_nano();
        let initial = bond_amt + 100_000;
        engine
            .update_account(AccountState::new(sender, initial))
            .await;
        engine
            .pin_pubkey(sender, PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
            .await
            .unwrap();
        let tx = sign_pq_implicit_tx(
            &kp,
            sender,
            [0u8; 32],
            0,
            10_000,
            0,
            vec![OpCode::SysCallStake {
                validator: sender,
                amount: bond_amt,
            }],
        );
        engine
            .apply_transaction_at_height(&tx, 1_700_000_000, H - 1)
            .await
            .expect("pre-H stake with gas_limit=10_000 succeeds");
        assert_eq!(
            engine.get_account(&sender).await.unwrap().balance,
            initial - bond_amt - GAS_STAKE_BOND
        );
    }
}

#[test]
fn clob_place_order_fills_gas_and_cancel_order_read_only_owner_check_at_h() {
    let mut base_books: HashMap<u32, OrderbookActor> = HashMap::new();
    let mut book = OrderbookActor::new(1, 1000);
    let maker = [0x11u8; 32];
    for _ in 0..100 {
        book.submit_order(maker, OrderSide::Sell, 1_000, 1, 1);
    }
    base_books.insert(1, book);

    let taker = [0x22u8; 32];
    let ops = vec![OpCode::SysCallPlaceOrder {
        pair_id: 1,
        is_buy: true,
        price: 1_000,
        amount: 100,
    }];

    // Pre-hardening (< H)
    {
        let mut books = base_books.clone();
        let mut ctx = VmContext {
            sender: taker,
            balance: 1_000_000,
            orderbooks: Some(&mut books),
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 10,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            pmm: None,
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        };
        let mut sends = Vec::new();
        let res = Svm::execute_with_confidential_and_sends_at(
            &ops,
            4_000,
            &mut ctx,
            &mut sends,
            None,
            &VmExecOptions {
                exec_hardening: false,
                ..Default::default()
            },
        );
        match res {
            VmExecutionResult::Success {
                gas_used, trades, ..
            } => {
                assert_eq!(trades.len(), 100);
                assert_eq!(
                    gas_used,
                    1_200 + (MAX_MATCH_LEVELS as u64) * GAS_PER_MATCH_LEVEL
                );
            }
            other => panic!("expected pre-H Success, got {other:?}"),
        }
    }

    // Hardened (>= H) with gas_limit = 4_000 -> OutOfGas
    {
        let mut books = base_books.clone();
        let mut ctx = VmContext {
            sender: taker,
            balance: 1_000_000,
            orderbooks: Some(&mut books),
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 10,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            pmm: None,
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        };
        let mut sends = Vec::new();
        let res = Svm::execute_with_confidential_and_sends_at(
            &ops,
            4_000,
            &mut ctx,
            &mut sends,
            None,
            &VmExecOptions {
                exec_hardening: true,
                ..Default::default()
            },
        );
        assert!(
            matches!(res, VmExecutionResult::OutOfGas),
            "hardened must hit OutOfGas at 4_000 for 100 fills, got {res:?}"
        );
    }

    // 300 maker orders on 1 price level -> capped at MAX_MATCH_FILLS_PER_ORDER (256) on >= H.
    {
        let mut books = HashMap::new();
        let mut big_book = OrderbookActor::new(1, 1000);
        for _ in 0..300 {
            big_book.submit_order(maker, OrderSide::Sell, 1_000, 1, 1);
        }
        books.insert(1, big_book);

        let mut ctx = VmContext {
            sender: taker,
            balance: 1_000_000,
            orderbooks: Some(&mut books),
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 10,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            pmm: None,
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        };
        let mut sends = Vec::new();
        let res = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallPlaceOrder {
                pair_id: 1,
                is_buy: true,
                price: 1_000,
                amount: 300,
            }],
            100_000,
            &mut ctx,
            &mut sends,
            None,
            &VmExecOptions {
                exec_hardening: true,
                ..Default::default()
            },
        );
        match res {
            VmExecutionResult::Success {
                trades, gas_used, ..
            } => {
                assert_eq!(trades.len(), MAX_MATCH_FILLS_PER_ORDER);
                assert_eq!(
                    gas_used,
                    1_200 + (MAX_MATCH_FILLS_PER_ORDER as u64) * GAS_PER_MATCH_LEVEL
                );
            }
            other => panic!("expected Success capped at 256 fills, got {other:?}"),
        }
    }

    // SysCallCancelOrder: stranger rejected cleanly, valid owner pays >= GAS_ORDER_CANCEL_HARDENED
    // on >= H while keeping GAS_ORDER_CANCEL (100) on < H.
    {
        let mut books_pre = base_books.clone();
        let mut ctx_stranger = VmContext {
            sender: [0x99u8; 32],
            balance: 1_000_000,
            orderbooks: Some(&mut books_pre),
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 10,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            pmm: None,
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        };
        let mut sends = Vec::new();
        let res_stranger = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallCancelOrder { order_id: 1 }],
            50_000,
            &mut ctx_stranger,
            &mut sends,
            None,
            &VmExecOptions {
                exec_hardening: true,
                ..Default::default()
            },
        );
        assert!(
            matches!(res_stranger, VmExecutionResult::Reverted(ref msg) if msg == "only the order owner may cancel it"),
            "unexpected stranger cancel result: {res_stranger:?}"
        );

        let mut books_owner_pre = base_books.clone();
        let mut ctx_owner_pre = VmContext {
            sender: maker,
            balance: 1_000_000,
            orderbooks: Some(&mut books_owner_pre),
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 10,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            pmm: None,
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        };
        let res_owner_pre = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallCancelOrder { order_id: 50 }],
            50_000,
            &mut ctx_owner_pre,
            &mut sends,
            None,
            &VmExecOptions {
                exec_hardening: false,
                ..Default::default()
            },
        );
        match res_owner_pre {
            VmExecutionResult::Success { gas_used, .. } => assert_eq!(gas_used, GAS_ORDER_CANCEL),
            other => panic!("expected pre-H cancel Success, got {other:?}"),
        }

        let mut books_owner_hard = base_books.clone();
        let mut ctx_owner_hard = VmContext {
            sender: maker,
            balance: 1_000_000,
            orderbooks: Some(&mut books_owner_hard),
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 10,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            pmm: None,
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        };
        let res_owner_hard = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallCancelOrder { order_id: 50 }],
            50_000,
            &mut ctx_owner_hard,
            &mut sends,
            None,
            &VmExecOptions {
                exec_hardening: true,
                ..Default::default()
            },
        );
        match res_owner_hard {
            VmExecutionResult::Success { gas_used, .. } => {
                assert!(gas_used >= GAS_ORDER_CANCEL_HARDENED);
            }
            other => panic!("expected hardened cancel Success, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn outbound_messages_rollback_bounce_conservation_and_sync_contract_balance() {
    let _guard = GateResetGuard;
    set_wasm_xshard_pmm_hardening_activation_override(Some(H));

    // 1. Outbound message emitted by contract must NOT leak to inbox when commit_native fails at >= H.
    {
        let engine = InMemoryStateEngine::new();
        let kp = FalconKeypair::generate_from_seed(0x81);
        let sender = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
        let recipient = [0x55u8; 32];
        engine
            .update_account(AccountState::new(recipient, 100))
            .await;

        let contract_addr = engine
            .deploy_contract(sender, sstore_contract_wasm(), 1)
            .await
            .unwrap();
        engine
            .update_account(AccountState::new(contract_addr, 500))
            .await;
        engine
            .update_account(AccountState::new(sender, 1_000_000))
            .await;

        let tx = sign_pq_tx(
            &kp,
            &DEFAULT_SALT,
            [0u8; 32],
            0,
            600_000,
            0,
            vec![
                OpCode::SysCallCallContract {
                    contract: contract_addr,
                    method: b"send_empty_existing".to_vec(),
                    arg: 50,
                },
                OpCode::Transfer {
                    recipient: [0xBBu8; 32],
                    amount: 800_000,
                },
            ],
        );

        let err = engine
            .apply_transaction_at_height(&tx, 1_700_000_000, H)
            .await
            .unwrap_err();
        assert!(!err.is_empty());
        assert!(
            engine
                .get_account(&recipient)
                .await
                .unwrap()
                .inbox
                .is_empty(),
            "failed commit_native at >= H must leave zero leaked outbound messages in inbox"
        );
        assert_eq!(
            engine.get_account(&contract_addr).await.unwrap().balance,
            500,
            "contract native balance must remain untouched after failed commit"
        );
    }

    // 2. Bounce conservation: contract with accounts[contract].balance == 0 and Contract.balance == 500
    //    sending raw non-ActorSendBody payload (or empty payload to missing recipient with bounce=true)
    //    MUST NOT mint free STELL via bounce on >= H.
    {
        let engine = InMemoryStateEngine::new();
        let kp = FalconKeypair::generate_from_seed(0x82);
        let sender = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
        let proposer = [0x77u8; 32];
        engine
            .update_account(AccountState::new(sender, 5_000_000))
            .await;
        engine.update_account(AccountState::new(proposer, 0)).await;

        let contract_addr = engine
            .deploy_contract(sender, sstore_contract_wasm(), 1)
            .await
            .unwrap();
        engine
            .contracts_write()
            .await
            .set_balance(&contract_addr, 500)
            .unwrap();

        let tx_raw = sign_pq_tx(
            &kp,
            &DEFAULT_SALT,
            [0u8; 32],
            0,
            1_000_000,
            0,
            vec![OpCode::SysCallCallContract {
                contract: contract_addr,
                method: b"send_raw".to_vec(),
                arg: 500,
            }],
        );
        let tx_empty = sign_pq_tx(
            &kp,
            &DEFAULT_SALT,
            [0u8; 32],
            0,
            1_000_000,
            1,
            vec![OpCode::SysCallCallContract {
                contract: contract_addr,
                method: b"send_empty".to_vec(),
                arg: 500,
            }],
        );
        let block = Block {
            height: H,
            timestamp: 1_700_000_000,
            proposer,
            transactions: vec![tx_raw, tx_empty],
            ..Default::default()
        };
        let outcome = engine.apply_block_transition(&block, 0).await;
        assert_eq!(outcome.applied, 2);

        let c_acct_bal = engine
            .get_account(&contract_addr)
            .await
            .map(|a| a.balance)
            .unwrap_or(0);
        assert_eq!(
            c_acct_bal, 0,
            "bounce at >= H must NEVER mint STELL out of thin air when accounts[contract] holds 0"
        );
        let sender_bal = engine.get_account(&sender).await.unwrap().balance;
        let prop_bal = engine.get_account(&proposer).await.unwrap().balance;
        assert_eq!(sender_bal + prop_bal, 5_000_000);
    }

    // 3. sync_contract_balance + pure-value delivery & bounce conservation with funded contract.
    {
        let engine = InMemoryStateEngine::new();
        let kp = FalconKeypair::generate_from_seed(0x83);
        let sender = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
        let recipient = [0x55u8; 32];
        let proposer = [0x77u8; 32];
        engine
            .update_account(AccountState::new(sender, 5_000_000))
            .await;
        engine
            .update_account(AccountState::new(recipient, 100))
            .await;
        engine.update_account(AccountState::new(proposer, 0)).await;

        let contract_addr = engine
            .deploy_contract(sender, sstore_contract_wasm(), 1)
            .await
            .unwrap();
        engine
            .update_account(AccountState::new(contract_addr, 1_000))
            .await;

        let tx1 = sign_pq_tx(
            &kp,
            &DEFAULT_SALT,
            [0u8; 32],
            0,
            1_000_000,
            0,
            vec![OpCode::SysCallCallContract {
                contract: contract_addr,
                method: b"send_empty_existing".to_vec(),
                arg: 400,
            }],
        );
        let tx2 = sign_pq_tx(
            &kp,
            &DEFAULT_SALT,
            [0u8; 32],
            0,
            1_000_000,
            1,
            vec![OpCode::SysCallCallContract {
                contract: contract_addr,
                method: b"send_empty".to_vec(),
                arg: 300,
            }],
        );
        let block = Block {
            height: H,
            timestamp: 1_700_000_000,
            proposer,
            transactions: vec![tx1, tx2],
            ..Default::default()
        };
        let outcome = engine.apply_block_transition(&block, 0).await;
        assert_eq!(outcome.applied, 2);

        assert_eq!(engine.get_account(&recipient).await.unwrap().balance, 500);
        assert_eq!(
            engine.get_account(&contract_addr).await.unwrap().balance,
            600
        );
        let total = engine.get_account(&sender).await.unwrap().balance
            + engine.get_account(&proposer).await.unwrap().balance
            + engine.get_account(&recipient).await.unwrap().balance
            + engine.get_account(&contract_addr).await.unwrap().balance;
        assert_eq!(total, 5_000_000 + 100 + 1_000);
    }
}

#[tokio::test]
async fn svm_caller_vs_origin_and_deploy_with_nonce_and_pmm_cei_zero_mint_payout() {
    let _guard = GateResetGuard;
    set_wasm_xshard_pmm_hardening_activation_override(Some(H));

    // 1. deploy_with_nonce at H vs legacy contracts.next_nonce at H-1.
    {
        let engine = InMemoryStateEngine::new();
        let kp_a = FalconKeypair::generate_from_seed(0x91);
        let kp_b = FalconKeypair::generate_from_seed(0x92);
        let sender_a = derive_pq_address(PqScheme::Falcon512, &kp_a.public_key, &DEFAULT_SALT);
        let sender_b = derive_pq_address(PqScheme::Falcon512, &kp_b.public_key, &DEFAULT_SALT);
        engine
            .update_account(AccountState::new(sender_a, 20_000_000))
            .await;
        engine
            .update_account(AccountState::new(sender_b, 20_000_000))
            .await;

        let code = sstore_contract_wasm();
        let tx_a = sign_pq_tx(
            &kp_a,
            &DEFAULT_SALT,
            [0u8; 32],
            0,
            5_000_000,
            0,
            vec![OpCode::SysCallDeployContract { code: code.clone() }],
        );
        let tx_b = sign_pq_tx(
            &kp_b,
            &DEFAULT_SALT,
            [0u8; 32],
            0,
            5_000_000,
            0,
            vec![OpCode::SysCallDeployContract { code: code.clone() }],
        );

        let (a, _, _, st, _, _) = engine
            .apply_block_parallel_fees_with_events_at_height(&[tx_a, tx_b], 100, H - 1)
            .await;
        assert_eq!(a, 2);
        assert_eq!(st, vec![true, true]);
        assert!(engine
            .get_contract(&contract_address(&sender_b, 1))
            .await
            .is_some());
        assert!(engine
            .get_contract(&contract_address(&sender_b, 0))
            .await
            .is_none());

        let tx_a_h = sign_pq_tx(
            &kp_a,
            &DEFAULT_SALT,
            [0u8; 32],
            0,
            5_000_000,
            1,
            vec![OpCode::SysCallDeployContract { code }],
        );
        let (a2, _, _, st2, _, _) = engine
            .apply_block_parallel_fees_with_events_at_height(&[tx_a_h], 101, H)
            .await;
        assert_eq!(a2, 1);
        assert_eq!(st2, vec![true]);
        assert!(
            engine
                .get_contract(&contract_address(&sender_a, 1))
                .await
                .is_some(),
            "hardened deploy at >= H must use tx.nonce (1), not contracts.next_nonce (2)"
        );
    }

    // 2. caller != origin in ContractRegistry + SVM top-level call.
    {
        let mut reg = ContractRegistry::new();
        let origin = [0xA1u8; 32];
        let intermediary = [0xB2u8; 32];
        let target = reg
            .deploy_with_nonce(origin, sstore_contract_wasm(), 0, 1)
            .unwrap();
        let ctx = ContractCallContext {
            caller: intermediary,
            value: 0,
            block_time: 10,
            block_hash: [0u8; 32],
        };
        let out = reg
            .call_with_context_hardened(
                &target,
                "who",
                42,
                50_000,
                &ctx,
                origin,
                intermediary,
                true,
            )
            .unwrap();
        assert_eq!(out.result, 42);
        assert_eq!(&out.return_data[0..32], &intermediary);
        assert_eq!(&out.return_data[32..64], &origin);
    }

    // 3. SysCallPmmBuy CEI (wUSDT checked BEFORE curve mutation) + ZeroMint / ZeroPayout.
    {
        let buyer = [0xC1u8; 32];
        let treasury = [0xC2u8; 32];
        let mut tokens = TokenRegistry::new();
        let usdt_id = tokens
            .create_token(
                treasury,
                TokenMetadata {
                    name: "wUSDT".to_string(),
                    symbol: "wUSDT".to_string(),
                    decimals: 6,
                    total_supply: 1_000_000_000,
                    max_supply: Some(u64::MAX),
                    minter: treasury,
                    paused: false,
                    description: String::new(),
                },
                1_000_000_000,
            )
            .unwrap();

        let pmm_init = PrimaryMarketMaker::new();
        let mut pmm = pmm_init.clone();
        let mut ctx = VmContext {
            sender: buyer,
            balance: 1_000_000,
            orderbooks: None,
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 10,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: Some(&mut tokens),
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            pmm: Some(PmmVmContext {
                state: &mut pmm,
                usdt_token: Some(usdt_id),
                treasury,
                redemption_buffer_bps: 1000,
                events: Vec::new(),
            }),
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        };
        let mut sends = Vec::new();
        let res_no_usdt = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallPmmBuy {
                usdt_micro: 1_000_000,
            }],
            100_000,
            &mut ctx,
            &mut sends,
            None,
            &VmExecOptions {
                wasm_pmm_hardening: true,
                ..Default::default()
            },
        );
        assert!(
            matches!(res_no_usdt, VmExecutionResult::Reverted(ref m) if m.contains("Insufficient wUSDT")),
            "expected CEI insufficient wUSDT revert, got {res_no_usdt:?}"
        );
        assert_eq!(pmm.minted_nano, pmm_init.minted_nano);

        // ZeroPayout on sell_stell_checked: 1 nano-STELL at base price rounds to 0 micro-USDT.
        let mut pmm_sell = PrimaryMarketMaker::new();
        pmm_sell.buy_with_buffer_checked(10_000_000, 1000).unwrap();
        let mut ctx_sell = VmContext {
            sender: buyer,
            balance: 1_000_000,
            orderbooks: None,
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 10,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: Some(&mut tokens),
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            pmm: Some(PmmVmContext {
                state: &mut pmm_sell,
                usdt_token: Some(usdt_id),
                treasury,
                redemption_buffer_bps: 1000,
                events: Vec::new(),
            }),
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        };
        let res_zero_payout = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallPmmSell { stell_nano: 1 }],
            100_000,
            &mut ctx_sell,
            &mut sends,
            None,
            &VmExecOptions {
                wasm_pmm_hardening: true,
                ..Default::default()
            },
        );
        assert!(
            matches!(res_zero_payout, VmExecutionResult::Reverted(ref m) if m.contains("sell would pay out zero USDT")),
            "expected ZeroPayout revert, got {res_zero_payout:?}"
        );

        // ZeroMint on buy_with_buffer_checked: fund buyer with wUSDT, set high curve supply
        // so `usdt_micro = 1` mints 0 nano-STELL -> "buy would mint zero STELL".
        tokens
            .execute(
                &usdt_id,
                treasury,
                stellereum::token::TokenOp::Mint {
                    to: buyer,
                    amount: 1_000,
                },
            )
            .unwrap();
        let mut pmm_buy_zero = PrimaryMarketMaker::new();
        pmm_buy_zero.base_price_micro = 2_000_000_000; // $2000/STELL -> 1 micro-USD buys < 1 nano-STELL = 0 (ZeroMint)
        let mut ctx_zero_mint = VmContext {
            sender: buyer,
            balance: 1_000_000,
            orderbooks: None,
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: 10,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: Some(&mut tokens),
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            pmm: Some(PmmVmContext {
                state: &mut pmm_buy_zero,
                usdt_token: Some(usdt_id),
                treasury,
                redemption_buffer_bps: 1000,
                events: Vec::new(),
            }),
            min_validator_bond: 1_000,
            default_commission_bps: 100,
            payouts: Vec::new(),
            oracle: None,
        };
        let res_zero_mint = Svm::execute_with_confidential_and_sends_at(
            &[OpCode::SysCallPmmBuy { usdt_micro: 1 }],
            100_000,
            &mut ctx_zero_mint,
            &mut sends,
            None,
            &VmExecOptions {
                wasm_pmm_hardening: true,
                ..Default::default()
            },
        );
        assert!(
            matches!(res_zero_mint, VmExecutionResult::Reverted(ref m) if m.contains("buy would mint zero STELL")),
            "expected ZeroMint revert, got {res_zero_mint:?}"
        );
    }
}

fn encode_legacy_salt_first_sig(env: &PqSignatureEnvelope) -> Vec<u8> {
    let pk = env.pubkey.as_ref().expect("explicit");
    let mut out = Vec::new();
    out.extend_from_slice(PQ_ENVELOPE_MAGIC);
    out.push(env.scheme.id());
    out.push(0);
    out.extend_from_slice(&env.salt);
    out.extend_from_slice(&(pk.len() as u16).to_le_bytes());
    out.extend_from_slice(pk);
    out.extend_from_slice(&(env.signature_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&env.signature_bytes);
    if let Some(cid) = env.chain_id {
        out.extend_from_slice(&cid.to_be_bytes());
    }
    out
}

#[tokio::test]
async fn pq1_non_canonical_salt_first_accepted_at_h_minus_1_rejected_at_h_and_h_plus_1() {
    let _guard = GateResetGuard;
    set_wasm_xshard_pmm_hardening_activation_override(Some(H));
    verify_once_clear();

    let kp = FalconKeypair::generate_from_seed(0xA5);
    let salt = [0x42u8; 16];
    let canonical_tx = sign_pq_tx(&kp, &salt, [0x11u8; 32], 100, 300_000, 0, Vec::new());
    let env = PqSignatureEnvelope::decode_canonical(&canonical_tx.signature).unwrap();
    let mut malleated_tx = canonical_tx.clone();
    malleated_tx.signature = encode_legacy_salt_first_sig(&env);
    let sender = malleated_tx.from;

    // Pre-H (H - 1): accepted in both block apply and apply_transaction_at_height.
    {
        let engine = InMemoryStateEngine::new();
        engine
            .update_account(AccountState::new(sender, 10_000_000))
            .await;
        let (applied, failed, _, status, _, _) = engine
            .apply_block_parallel_fees_with_events_at_height(
                std::slice::from_ref(&malleated_tx),
                100,
                H - 1,
            )
            .await;
        assert_eq!((applied, failed, status), (1, 0, vec![true]));

        let engine2 = InMemoryStateEngine::new();
        engine2
            .update_account(AccountState::new(sender, 10_000_000))
            .await;
        engine2
            .apply_transaction_at_height(&malleated_tx, 100, H - 1)
            .await
            .expect("pre-H single-tx accepts legacy salt||key PQ1");
    }

    // Even if `record_verified_signature` cached the malleated tx pre-H,
    // H and H + 1 MUST reject it fail-closed in BOTH block apply and single-tx apply.
    for height in [H, H + 1] {
        let engine = InMemoryStateEngine::new();
        engine
            .update_account(AccountState::new(sender, 10_000_000))
            .await;
        record_verified_signature(&malleated_tx, engine.chain_id);

        let (applied, failed, fees, status, tx_fees, _) = engine
            .apply_block_parallel_fees_with_events_at_height(
                std::slice::from_ref(&malleated_tx),
                100,
                height,
            )
            .await;
        assert_eq!(
            (applied, failed, fees, status, tx_fees),
            (0, 1, 0, vec![false], vec![0]),
            "height {height} >= {H} must reject non-canonical salt||key PQ1 even when cached"
        );

        let err = engine
            .apply_transaction_at_height(&malleated_tx, 100, height)
            .await
            .unwrap_err();
        assert!(
            err.contains("non-canonical") || err.contains("signature") || err.contains("PQ1"),
            "unexpected error at height {height}: {err}"
        );
    }

    verify_once_clear();
}

#[tokio::test]
async fn parallel_exec_equals_sequential_and_apply_tx_equals_block_apply_at_h_minus_1_and_h() {
    let _guard = GateResetGuard;
    set_exec_hardening_v1_activation_override(Some(H));
    set_wasm_xshard_pmm_hardening_activation_override(Some(H));

    for height in [H - 1, H] {
        let kp1 = FalconKeypair::generate_from_seed(0xB1);
        let kp2 = FalconKeypair::generate_from_seed(0xB2);
        let kp3 = FalconKeypair::generate_from_seed(0xB3);
        let a1 = derive_pq_address(PqScheme::Falcon512, &kp1.public_key, &DEFAULT_SALT);
        let a2 = derive_pq_address(PqScheme::Falcon512, &kp2.public_key, &DEFAULT_SALT);
        let a3 = derive_pq_address(PqScheme::Falcon512, &kp3.public_key, &DEFAULT_SALT);

        let seq = InMemoryStateEngine::new();
        let par = InMemoryStateEngine::new();
        seq.set_parallel_exec(false);
        par.set_parallel_exec(true);

        for eng in [&seq, &par] {
            eng.update_account(AccountState::new(a1, 50_000_000)).await;
            eng.update_account(AccountState::new(a2, 50_000_000)).await;
            eng.update_account(AccountState::new(a3, 50_000_000)).await;
        }

        let code = sstore_contract_wasm();
        let c1_seq = seq.deploy_contract(a1, code.clone(), 1).await.unwrap();
        let c1_par = par.deploy_contract(a1, code.clone(), 1).await.unwrap();
        assert_eq!(c1_seq, c1_par);

        let txs = vec![
            sign_pq_tx(
                &kp1,
                &DEFAULT_SALT,
                [0xCAu8; 32],
                1_000,
                300_000,
                0,
                Vec::new(),
            ),
            sign_pq_tx(
                &kp2,
                &DEFAULT_SALT,
                [0u8; 32],
                0,
                500_000,
                0,
                vec![OpCode::Nop],
            ),
            sign_pq_tx(
                &kp3,
                &DEFAULT_SALT,
                [0u8; 32],
                0,
                2_000_000,
                0,
                vec![OpCode::SysCallCallContractArgs {
                    contract: c1_seq,
                    method: b"set".to_vec(),
                    args: vec![5, 777],
                    calldata: Vec::new(),
                }],
            ),
            sign_pq_tx(
                &kp1,
                &DEFAULT_SALT,
                [0u8; 32],
                0,
                5_000_000,
                1,
                vec![OpCode::SysCallDeployContract { code }],
            ),
        ];

        let r_seq = seq
            .apply_block_parallel_fees_with_events_at_height(&txs, 1_700_000_000, height)
            .await;
        let r_par = par
            .apply_block_parallel_fees_with_events_at_height(&txs, 1_700_000_000, height)
            .await;
        assert_eq!(r_seq, r_par, "parallel != sequential at height {height}");
        assert_eq!(
            seq.get_state_root().await,
            par.get_state_root().await,
            "state_root mismatch between sequential and parallel at height {height}"
        );

        let single = InMemoryStateEngine::new();
        let batched = InMemoryStateEngine::new();
        for eng in [&single, &batched] {
            eng.update_account(AccountState::new(a2, 50_000_000)).await;
        }
        let nop_tx = sign_pq_tx(
            &kp2,
            &DEFAULT_SALT,
            [0u8; 32],
            0,
            500_000,
            0,
            vec![OpCode::Nop],
        );
        single
            .apply_transaction_at_height(&nop_tx, 1_700_000_000, height)
            .await
            .unwrap();
        batched
            .apply_block_parallel_fees_with_events_at_height(&[nop_tx], 1_700_000_000, height)
            .await;
        assert_eq!(
            single.get_account(&a2).await.unwrap().balance,
            batched.get_account(&a2).await.unwrap().balance,
            "single-tx vs block-apply balance mismatch at height {height}"
        );
        assert_eq!(
            single.get_state_root().await,
            batched.get_state_root().await,
            "single-tx vs block-apply state_root mismatch at height {height}"
        );
    }
}
