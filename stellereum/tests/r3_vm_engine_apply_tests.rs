//! R3-D VM, Mempool, StateEngine & Block-Apply integration tests for W3 PQ
//! validator lifecycle (`OpCode` 59..=64, `withdrawal_address` authorization,
//! `InMemoryStateEngine::pq_registry`, Step 0 adoption/due rotations, Step 5f
//! `apply_pq_registry_ops`, `parallel_exec == sequential`, and `H-1 / H / H+1`
//! / `E-1 / E / E+1` boundaries).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use stellereum::commitment::COMMITMENT_VERSION;
use stellereum::consensus::{vote_sign_bytes, VoteKind};
use stellereum::mempool::Mempool;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::pq_registry::{
    derive_validator_id, pq_lifecycle_active_at, pq_voting_key_pop_preimage,
    set_pq_lifecycle_activation_override, PQ_LIFECYCLE_ACTIVATION_HEIGHT,
    PQ_ROTATION_DELAY_HEIGHTS,
};
use stellereum::protocol::FORK_ID;
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::snapshot_v4::SnapStateV4;
use stellereum::staking::{
    pq_claim_withdrawal_preimage, pq_withdrawal_pop_preimage, required_bond_floor_nano,
    CompactPqEquivocationEvidence, JailRecord, COMMISSION_EFFECT_DELAY_HEIGHTS, REWARDS_POOL,
    STAKING_POOL, UNBONDING_PERIOD_SECS,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{load_full_state_into, DomainSnapshot, Storage};
use stellereum::svm::{
    opcode_gas, ChangeWithdrawalPayload, ClaimWithdrawalPayload, OpCode, RegisterValidatorPayload,
    RotateVotingKeyPayload,
};
use stellereum::zkml::effective_chain_id;

const TS: u64 = 1_760_000_000;
const GAS: u64 = 2_000_000;
const FUNDS: u64 = 20_000_000_000_000;

static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

struct PqLifecycleGateGuard;

impl PqLifecycleGateGuard {
    fn at(height: u64) -> Self {
        set_pq_lifecycle_activation_override(Some(height));
        Self
    }
}

impl Drop for PqLifecycleGateGuard {
    fn drop(&mut self) {
        set_pq_lifecycle_activation_override(None);
    }
}

fn falcon(seed: u8) -> FalconKeypair {
    let mut s = [0u8; 32];
    s[0] = seed;
    s[31] = seed.wrapping_mul(37).wrapping_add(11);
    FalconKeypair::generate_from_seed_bytes(&s)
}

fn pq_addr(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, kp.public_key(), &DEFAULT_SALT)
}

fn signed_pq_tx(kp: &FalconKeypair, nonce: u64, payload: Vec<OpCode>) -> Transaction {
    let pk = kp.public_key().to_vec();
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        [0u8; 32],
        0,
        GAS,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        payload.clone(),
        &DEFAULT_SALT,
    );
    let sig = kp.sign(&probe.signing_message());
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk,
        sig,
        [0u8; 32],
        0,
        GAS,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        payload,
        &DEFAULT_SALT,
    )
}

fn make_block(height: u64, txs: Vec<Transaction>) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: TS + height,
        proposer: SigningKey::from_bytes(&[0x5Au8; 32])
            .verifying_key()
            .to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        round: 0,
    }
}

fn register_validator_op(
    chain_id: u64,
    cold_addr: [u8; 32],
    hot_kp: &FalconKeypair,
    amount: u64,
    commission_bps: u64,
) -> OpCode {
    let validator_id = derive_validator_id(chain_id, &cold_addr, hot_kp.public_key());
    let pop_msg = pq_voting_key_pop_preimage(
        chain_id,
        &validator_id,
        &cold_addr,
        0,
        PqScheme::Falcon512,
        hot_kp.public_key(),
    );
    let pop_sig = hot_kp.sign(&pop_msg);
    OpCode::SysCallRegisterValidator(Box::new(RegisterValidatorPayload {
        amount,
        commission_bps,
        withdrawal_address: cold_addr,
        voting_scheme: PqScheme::Falcon512.id(),
        voting_pubkey: hot_kp.public_key().to_vec(),
        voting_pop: pop_sig,
    }))
}

fn rotate_voting_key_op(
    chain_id: u64,
    validator_id: [u8; 32],
    cold_addr: [u8; 32],
    rotation_seq: u64,
    new_hot_kp: &FalconKeypair,
) -> OpCode {
    let pop_msg = pq_voting_key_pop_preimage(
        chain_id,
        &validator_id,
        &cold_addr,
        rotation_seq,
        PqScheme::Falcon512,
        new_hot_kp.public_key(),
    );
    let pop_sig = new_hot_kp.sign(&pop_msg);
    OpCode::SysCallRotateVotingKey(Box::new(RotateVotingKeyPayload {
        validator_id,
        rotation_seq,
        new_scheme: PqScheme::Falcon512.id(),
        new_pubkey: new_hot_kp.public_key().to_vec(),
        pop_signature: pop_sig,
        cancel: false,
    }))
}

fn cancel_rotation_op(validator_id: [u8; 32], rotation_seq: u64) -> OpCode {
    OpCode::SysCallRotateVotingKey(Box::new(RotateVotingKeyPayload {
        validator_id,
        rotation_seq,
        new_scheme: PqScheme::Falcon512.id(),
        new_pubkey: Vec::new(),
        pop_signature: Vec::new(),
        cancel: true,
    }))
}

fn change_withdrawal_op(
    chain_id: u64,
    validator_id: [u8; 32],
    current_withdrawal: [u8; 32],
    new_cold_kp: &FalconKeypair,
) -> OpCode {
    let new_withdrawal = pq_addr(new_cold_kp);
    let pop_msg = pq_withdrawal_pop_preimage(
        chain_id,
        &validator_id,
        &current_withdrawal,
        &new_withdrawal,
    );
    let pop_sig = new_cold_kp.sign(&pop_msg);
    OpCode::SysCallChangeWithdrawal(Box::new(ChangeWithdrawalPayload {
        validator_id,
        new_withdrawal_address: new_withdrawal,
        new_withdrawal_scheme: PqScheme::Falcon512.id(),
        new_withdrawal_pubkey: new_cold_kp.public_key().to_vec(),
        new_withdrawal_salt: DEFAULT_SALT,
        new_withdrawal_pop: pop_sig,
    }))
}

fn claim_withdrawal_op(
    chain_id: u64,
    validator_id: [u8; 32],
    withdrawal_address: [u8; 32],
    voting_kp: &FalconKeypair,
) -> OpCode {
    let msg = pq_claim_withdrawal_preimage(chain_id, &validator_id, &withdrawal_address);
    let sig = voting_kp.sign(&msg);
    OpCode::SysCallClaimWithdrawal(Box::new(ClaimWithdrawalPayload {
        validator_id,
        withdrawal_address,
        voting_sig: sig,
    }))
}

#[test]
fn frozen_defaults_preserve_v5_commitment_and_fork_id() {
    assert_eq!(PQ_LIFECYCLE_ACTIVATION_HEIGHT, u64::MAX);
    assert!(!pq_lifecycle_active_at(0));
    assert!(!pq_lifecycle_active_at(1_000_000));
    assert!(!pq_lifecycle_active_at(u64::MAX));
    assert_eq!(COMMITMENT_VERSION, 5);
    assert_eq!(FORK_ID, 0x0f584a46);
}

#[tokio::test]
async fn parallel_exec_matches_sequential_on_mixed_w3_lifecycle_block() {
    let h = 100u64;
    let _gate = PqLifecycleGateGuard::at(h);
    let chain_id = effective_chain_id();
    let bond = required_bond_floor_nano();

    let cold_1 = falcon(0x01);
    let cold_1_addr = pq_addr(&cold_1);
    let hot_1 = falcon(0x02);
    let hot_1_next = falcon(0x03);
    let vid_1 = derive_validator_id(chain_id, &cold_1_addr, hot_1.public_key());

    let cold_2 = falcon(0x04);
    let cold_2_addr = pq_addr(&cold_2);
    let cold_2_new = falcon(0x05);
    let cold_2_new_addr = pq_addr(&cold_2_new);
    let hot_2 = falcon(0x06);
    let vid_2 = derive_validator_id(chain_id, &cold_2_addr, hot_2.public_key());

    // Pre-W3 validator (withdrawal_address == None) that will claim withdrawal at H.
    let legacy_hot = falcon(0x07);
    let legacy_id = [0xAAu8; 32];
    let legacy_cold = falcon(0x08);
    let legacy_cold_addr = pq_addr(&legacy_cold);

    let seq = InMemoryStateEngine::new().with_parallel_exec(false);
    let par = InMemoryStateEngine::new().with_parallel_exec(true);
    for eng in [&seq, &par] {
        eng.update_account(AccountState::new(cold_1_addr, FUNDS))
            .await;
        eng.update_account(AccountState::new(cold_2_addr, FUNDS))
            .await;
        eng.update_account(AccountState::new(cold_2_new_addr, FUNDS))
            .await;
        eng.update_account(AccountState::new(legacy_cold_addr, FUNDS))
            .await;
        let mut ledger = eng.staking_write().await;
        ledger.bond(legacy_id, bond, 500).expect("legacy bond");
        ledger
            .register_pq_key(
                legacy_id,
                PqScheme::Falcon512,
                legacy_hot.public_key().to_vec(),
            )
            .expect("legacy pq key");
    }

    // Block H: Register val1 + val2, claim legacy withdrawal, change val2 withdrawal, announce commission.
    let txs_h = vec![
        signed_pq_tx(
            &cold_1,
            0,
            vec![register_validator_op(
                chain_id,
                cold_1_addr,
                &hot_1,
                bond,
                500,
            )],
        ),
        signed_pq_tx(
            &cold_2,
            0,
            vec![register_validator_op(
                chain_id,
                cold_2_addr,
                &hot_2,
                bond,
                500,
            )],
        ),
        signed_pq_tx(
            &legacy_cold,
            0,
            vec![claim_withdrawal_op(
                chain_id,
                legacy_id,
                legacy_cold_addr,
                &legacy_hot,
            )],
        ),
        signed_pq_tx(
            &cold_2,
            1,
            vec![change_withdrawal_op(
                chain_id,
                vid_2,
                cold_2_addr,
                &cold_2_new,
            )],
        ),
        signed_pq_tx(
            &cold_1,
            1,
            vec![OpCode::SysCallAnnounceCommission {
                validator: vid_1,
                new_bps: 700,
            }],
        ),
    ];
    let blk_h = make_block(h, txs_h);
    let out_seq_h = seq.apply_block_transition(&blk_h, 0).await;
    let out_par_h = par.apply_block_transition(&blk_h, 0).await;
    assert_eq!(out_seq_h.status, vec![true, true, true, true, true]);
    assert_eq!(out_par_h.status, out_seq_h.status);
    assert_eq!(out_par_h.tx_fees, out_seq_h.tx_fees);
    assert_eq!(seq.get_state_root().await, par.get_state_root().await);

    // Block H + 1: val1 rotates voting key; val2 uses new withdrawal address to announce commission.
    let txs_h1 = vec![
        signed_pq_tx(
            &cold_1,
            2,
            vec![rotate_voting_key_op(
                chain_id,
                vid_1,
                cold_1_addr,
                1,
                &hot_1_next,
            )],
        ),
        signed_pq_tx(
            &cold_2_new,
            0,
            vec![OpCode::SysCallAnnounceCommission {
                validator: vid_2,
                new_bps: 600,
            }],
        ),
    ];
    let blk_h1 = make_block(h + 1, txs_h1);
    let out_seq_h1 = seq.apply_block_transition(&blk_h1, 0).await;
    let out_par_h1 = par.apply_block_transition(&blk_h1, 0).await;
    assert_eq!(out_seq_h1.status, vec![true, true]);
    assert_eq!(out_par_h1.status, out_seq_h1.status);
    assert_eq!(seq.get_state_root().await, par.get_state_root().await);

    // Block H + COMMISSION_EFFECT_DELAY_HEIGHTS: apply due commission & verify due rotation applied.
    let h_apply = h + COMMISSION_EFFECT_DELAY_HEIGHTS;
    let txs_apply = vec![signed_pq_tx(
        &cold_1,
        3,
        vec![OpCode::SysCallApplyCommission { validator: vid_1 }],
    )];
    let blk_apply = make_block(h_apply, txs_apply);
    let out_seq_apply = seq.apply_block_transition(&blk_apply, 0).await;
    let out_par_apply = par.apply_block_transition(&blk_apply, 0).await;
    assert_eq!(out_seq_apply.status, vec![true]);
    assert_eq!(out_par_apply.status, out_seq_apply.status);
    assert_eq!(seq.get_state_root().await, par.get_state_root().await);

    assert_eq!(
        seq.staking_read().await.validators[&vid_1].commission_bps,
        700
    );
    assert_eq!(
        seq.staking_read().await.withdrawal_address_of(&vid_2),
        Some(cold_2_new_addr)
    );
    assert_eq!(
        seq.staking_read().await.withdrawal_address_of(&legacy_id),
        Some(legacy_cold_addr)
    );
    assert_eq!(
        seq.pq_registry_read().await.records(),
        par.pq_registry_read().await.records()
    );
}

#[tokio::test]
async fn activation_boundary_h_minus_1_h_h_plus_1_and_key_separation() {
    let h = 100u64;
    let _gate = PqLifecycleGateGuard::at(h);
    let chain_id = effective_chain_id();
    let bond = required_bond_floor_nano();

    let cold_kp = falcon(0x11);
    let cold_addr = pq_addr(&cold_kp);
    let hot_kp = falcon(0x12);
    let hot_addr = pq_addr(&hot_kp);
    let outsider_kp = falcon(0x13);
    let outsider_addr = pq_addr(&outsider_kp);
    let new_cold_kp = falcon(0x14);
    let new_cold_addr = pq_addr(&new_cold_kp);

    let legacy_kp = falcon(0x15);
    let legacy_addr = pq_addr(&legacy_kp);
    let legacy_new_id = [0x55u8; 32];

    let eng = InMemoryStateEngine::new();
    for addr in [
        cold_addr,
        hot_addr,
        outsider_addr,
        new_cold_addr,
        legacy_addr,
    ] {
        eng.update_account(AccountState::new(addr, FUNDS)).await;
    }

    // 1. At H - 1 (99): opcodes 59..=64 revert; legacy SysCallStake & SysCallRotateValidatorKey succeed.
    let reg_op = register_validator_op(chain_id, cold_addr, &hot_kp, bond, 500);
    let rot_op = rotate_voting_key_op(chain_id, [0x22u8; 32], cold_addr, 1, &hot_kp);
    let chg_op = change_withdrawal_op(chain_id, [0x22u8; 32], cold_addr, &new_cold_kp);
    let clm_op = claim_withdrawal_op(chain_id, [0x22u8; 32], cold_addr, &hot_kp);
    let ann_op = OpCode::SysCallAnnounceCommission {
        validator: [0x22u8; 32],
        new_bps: 600,
    };
    let app_op = OpCode::SysCallApplyCommission {
        validator: [0x22u8; 32],
    };

    // Estimate wire bytes & gas for new opcodes cleanly.
    assert!(opcode_gas(&reg_op) > 0);
    assert!(
        Mempool::estimate_tx_wire_bytes(&signed_pq_tx(&cold_kp, 0, vec![reg_op.clone()])) > 256
    );

    let blk_pre = make_block(
        h - 1,
        vec![
            signed_pq_tx(&cold_kp, 0, vec![reg_op.clone()]),
            signed_pq_tx(&cold_kp, 1, vec![rot_op]),
            signed_pq_tx(&cold_kp, 2, vec![chg_op]),
            signed_pq_tx(&cold_kp, 3, vec![clm_op]),
            signed_pq_tx(&cold_kp, 4, vec![ann_op]),
            signed_pq_tx(&cold_kp, 5, vec![app_op]),
            // Legacy unknown-validator SysCallStake + SysCallRotateValidatorKey work at H - 1:
            signed_pq_tx(
                &legacy_kp,
                0,
                vec![
                    OpCode::SysCallStake {
                        validator: legacy_addr,
                        amount: bond,
                    },
                    OpCode::SysCallRotateValidatorKey {
                        old_validator: legacy_addr,
                        new_validator: legacy_new_id,
                    },
                ],
            ),
        ],
    );
    let out_pre = eng.apply_block_transition(&blk_pre, 0).await;
    assert_eq!(
        out_pre.status,
        vec![false, false, false, false, false, false, true]
    );
    assert!(eng.pq_registry_read().await.is_empty());
    assert!(eng
        .staking_read()
        .await
        .validators
        .contains_key(&legacy_new_id));

    // 2. At H (100):
    // - Legacy SysCallRotateValidatorKey (43) is disabled/reverted.
    // - SysCallStake / SysCallStakeWithCommission for unknown validator are reverted.
    // - Post-Halt SysCallRegisterValidator does not apply.
    // - Valid SysCallRegisterValidator registers validator_id deterministically.
    let vid = derive_validator_id(chain_id, &cold_addr, hot_kp.public_key());
    let blk_h = make_block(
        h,
        vec![
            signed_pq_tx(
                &legacy_kp,
                1,
                vec![OpCode::SysCallRotateValidatorKey {
                    old_validator: legacy_new_id,
                    new_validator: [0x66u8; 32],
                }],
            ),
            signed_pq_tx(
                &outsider_kp,
                0,
                vec![OpCode::SysCallStake {
                    validator: [0x77u8; 32],
                    amount: bond,
                }],
            ),
            signed_pq_tx(
                &outsider_kp,
                1,
                vec![OpCode::SysCallStakeWithCommission {
                    validator: [0x78u8; 32],
                    amount: bond,
                    commission_bps: 300,
                }],
            ),
            // Post-Halt register must not register!
            signed_pq_tx(
                &outsider_kp,
                2,
                vec![
                    OpCode::Nop,
                    OpCode::Halt,
                    register_validator_op(chain_id, outsider_addr, &falcon(0x1F), bond, 500),
                ],
            ),
            // Valid registration at H:
            signed_pq_tx(&cold_kp, 6, vec![reg_op]),
        ],
    );
    let out_h = eng.apply_block_transition(&blk_h, 0).await;
    // Tx 3 (`[Nop, Halt, SysCallRegisterValidator]`) halts cleanly with status=true,
    // while the post-Halt `SysCallRegisterValidator` must NOT execute or register.
    assert_eq!(out_h.status, vec![false, false, false, true, true]);
    let outsider_post_halt_vid =
        derive_validator_id(chain_id, &outsider_addr, falcon(0x1F).public_key());
    assert!(
        !eng.staking_read()
            .await
            .validators
            .contains_key(&outsider_post_halt_vid),
        "post-Halt SysCallRegisterValidator must not register"
    );
    assert!(eng.staking_read().await.validators.contains_key(&vid));
    assert_eq!(
        eng.staking_read().await.withdrawal_address_of(&vid),
        Some(cold_addr)
    );
    assert_eq!(
        eng.pq_registry_read()
            .await
            .record_of(&vid)
            .unwrap()
            .next_seq,
        1
    );

    // Give the validator pending rewards & a jail record to test ClaimRewards and Unjail auth.
    {
        let mut ledger = eng.staking_write().await;
        ledger.validators.get_mut(&vid).unwrap().pending_rewards = 50_000;
        // Claim pays out of the LEDGER's rewards pool backing (not just the
        // native REWARDS_POOL account), so back the claim 1:1 here.
        ledger.rewards_pool = ledger.rewards_pool.saturating_add(100_000);
        ledger.jail.insert(
            vid,
            JailRecord {
                jailed_at_height: h,
                release_height: h + 1,
            },
        );
    }
    eng.credit_native(&REWARDS_POOL, 100_000)
        .await
        .expect("fund rewards pool");

    // 3. At H + 1 (101):
    // - Hot key / outsider cannot unbond, unjail, claim rewards, or announce commission.
    // - Cold withdrawal_address CAN top-up (SysCallStake on existing validator), claim rewards (paid to cold_addr),
    //   unjail, and unbond.
    let cold_bal_before = eng.get_account(&cold_addr).await.unwrap().balance;
    let hot_bal_before = eng.get_account(&hot_addr).await.unwrap().balance;
    let blk_h1 = make_block(
        h + 1,
        vec![
            signed_pq_tx(
                &hot_kp,
                0,
                vec![OpCode::SysCallClaimRewards { validator: vid }],
            ),
            signed_pq_tx(&hot_kp, 1, vec![OpCode::SysCallUnjail { validator: vid }]),
            signed_pq_tx(
                &outsider_kp,
                3,
                vec![OpCode::SysCallUnbond {
                    validator: vid,
                    amount: 1_000,
                }],
            ),
            signed_pq_tx(
                &cold_kp,
                7,
                vec![
                    // A top-up must respect the governed minimum bond for a
                    // single `SysCallStake` (the opcode refuses dust amounts).
                    OpCode::SysCallStake {
                        validator: vid,
                        amount: bond,
                    },
                    OpCode::SysCallClaimRewards { validator: vid },
                    OpCode::SysCallUnjail { validator: vid },
                ],
            ),
        ],
    );
    let out_h1 = eng.apply_block_transition(&blk_h1, 0).await;
    assert_eq!(out_h1.status, vec![false, false, false, true]);
    assert!(!eng.staking_read().await.is_jailed(&vid));
    let cold_bal_after = eng.get_account(&cold_addr).await.unwrap().balance;
    let hot_bal_after = eng.get_account(&hot_addr).await.unwrap().balance;
    assert!(hot_bal_after <= hot_bal_before);
    // Cold address paid 100_000 top-up + tx fee, and received 50_000 pending_rewards.
    assert!(cold_bal_after < cold_bal_before);
    assert_eq!(eng.staking_read().await.validators[&vid].pending_rewards, 0);

    // 4. At H + 2 (102): ChangeWithdrawal rotates withdrawal_address to new_cold_addr;
    //    then old cold_addr is unauthorized and new_cold_addr can unbond.
    let blk_h2 = make_block(
        h + 2,
        vec![
            signed_pq_tx(
                &cold_kp,
                8,
                vec![change_withdrawal_op(chain_id, vid, cold_addr, &new_cold_kp)],
            ),
            signed_pq_tx(
                &cold_kp,
                9,
                vec![OpCode::SysCallUnbond {
                    validator: vid,
                    amount: 1_000,
                }],
            ),
            signed_pq_tx(
                &new_cold_kp,
                0,
                vec![OpCode::SysCallUnbond {
                    validator: vid,
                    amount: 1_000,
                }],
            ),
        ],
    );
    let out_h2 = eng.apply_block_transition(&blk_h2, 0).await;
    assert_eq!(out_h2.status, vec![true, false, true]);
    assert_eq!(
        eng.staking_read().await.withdrawal_address_of(&vid),
        Some(new_cold_addr)
    );

    // 5. Mature the unbonding from h + 2 and verify SysCallWithdrawSelfBond only
    //    accepts new_cold_kp (withdrawal_address) and rejects hot_kp / outsider.
    let mut blk_h3 = make_block(h + 3, vec![]);
    blk_h3.timestamp = TS + h + 2 + UNBONDING_PERIOD_SECS + 10;
    eng.apply_block_transition(&blk_h3, 0).await;

    let mut blk_h4 = make_block(
        h + 4,
        vec![
            signed_pq_tx(
                &hot_kp,
                2,
                vec![OpCode::SysCallWithdrawSelfBond { validator: vid }],
            ),
            signed_pq_tx(
                &outsider_kp,
                4,
                vec![OpCode::SysCallWithdrawSelfBond { validator: vid }],
            ),
            signed_pq_tx(
                &new_cold_kp,
                1,
                vec![OpCode::SysCallWithdrawSelfBond { validator: vid }],
            ),
        ],
    );
    blk_h4.timestamp = blk_h3.timestamp + 1;
    let out_h4 = eng.apply_block_transition(&blk_h4, 0).await;
    assert_eq!(out_h4.status, vec![false, false, true]);
    assert!(
        eng.staking_read()
            .await
            .withdrawable
            .get(&(vid, vid))
            .copied()
            .unwrap_or(0)
            == 0
    );
}

#[tokio::test]
async fn rotation_boundary_e_minus_1_e_e_plus_1_cancel_and_slash_retention() {
    let h = 100u64;
    let _gate = PqLifecycleGateGuard::at(h);
    let chain_id = effective_chain_id();
    let bond = required_bond_floor_nano();

    let cold_kp = falcon(0x21);
    let cold_addr = pq_addr(&cold_kp);
    let hot_1 = falcon(0x22);
    let hot_2 = falcon(0x23);
    let vid = derive_validator_id(chain_id, &cold_addr, hot_1.public_key());

    let reporter_kp = falcon(0x24);
    let reporter_addr = pq_addr(&reporter_kp);

    let eng = InMemoryStateEngine::new();
    eng.update_account(AccountState::new(cold_addr, FUNDS))
        .await;
    eng.update_account(AccountState::new(reporter_addr, FUNDS))
        .await;

    // Register at H = 100.
    let blk_reg = make_block(
        h,
        vec![signed_pq_tx(
            &cold_kp,
            0,
            vec![register_validator_op(
                chain_id, cold_addr, &hot_1, bond, 500,
            )],
        )],
    );
    assert_eq!(
        eng.apply_block_transition(&blk_reg, 0).await.status,
        vec![true]
    );

    // Announce rotation at H = 101 -> effective_height E = 101 + PQ_ROTATION_DELAY_HEIGHTS.
    let announce_h = h + 1;
    let e_height = announce_h + PQ_ROTATION_DELAY_HEIGHTS;
    let blk_ann = make_block(
        announce_h,
        vec![signed_pq_tx(
            &cold_kp,
            1,
            vec![rotate_voting_key_op(chain_id, vid, cold_addr, 1, &hot_2)],
        )],
    );
    assert_eq!(
        eng.apply_block_transition(&blk_ann, 0).await.status,
        vec![true]
    );

    // Branch A (clone_for_simulation): test cancel_rotation BEFORE E (at E - 1) succeeds.
    let sim = eng.clone_for_simulation().await;
    let blk_cancel_early = make_block(
        e_height - 1,
        vec![signed_pq_tx(&cold_kp, 2, vec![cancel_rotation_op(vid, 2)])],
    );
    let out_cancel = sim.apply_block_transition(&blk_cancel_early, 0).await;
    assert_eq!(out_cancel.status, vec![true]);
    assert!(sim.pq_registry_read().await.pending_of(&vid).is_none());
    // Live engine untouched by clone_for_simulation:
    assert!(eng.pq_registry_read().await.pending_of(&vid).is_some());

    // Branch B (live): E - 1 keeps hot_1 active.
    let blk_e_minus_1 = make_block(e_height - 1, vec![]);
    eng.apply_block_transition(&blk_e_minus_1, 0).await;
    assert_eq!(
        eng.pq_registry_read()
            .await
            .get_active_key(&vid, e_height - 1),
        Some((PqScheme::Falcon512, hot_1.public_key().to_vec()))
    );
    assert_eq!(
        eng.staking_read().await.get_pq_key(&vid),
        Some((PqScheme::Falcon512, hot_1.public_key().to_vec()))
    );

    // At E: Step 0 promotes pending rotation to hot_2, and cancel_rotation at E fails.
    let blk_e = make_block(
        e_height,
        vec![signed_pq_tx(&cold_kp, 2, vec![cancel_rotation_op(vid, 2)])],
    );
    let out_e = eng.apply_block_transition(&blk_e, 0).await;
    assert_eq!(out_e.status, vec![false]);
    assert_eq!(
        eng.pq_registry_read().await.get_active_key(&vid, e_height),
        Some((PqScheme::Falcon512, hot_2.public_key().to_vec()))
    );
    assert_eq!(
        eng.staking_read().await.get_pq_key(&vid),
        Some((PqScheme::Falcon512, hot_2.public_key().to_vec()))
    );

    // At E + 1: equivocation signed by superseded hot_1 at height `announce_h` STILL slashes!
    let msg_a = vote_sign_bytes(announce_h, 0, VoteKind::Prevote, &Some([0xA1u8; 32]));
    let msg_b = vote_sign_bytes(announce_h, 0, VoteKind::Prevote, &Some([0xB2u8; 32]));
    let ev = CompactPqEquivocationEvidence {
        voter: vid,
        height: announce_h,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash_a: Some([0xA1u8; 32]),
        signature_a: hot_1.sign(&msg_a),
        block_hash_b: Some([0xB2u8; 32]),
        signature_b: hot_1.sign(&msg_b),
    };
    let pool_before = eng.get_account(&STAKING_POOL).await.unwrap().balance;
    let blk_slash = make_block(
        e_height + 1,
        vec![signed_pq_tx(
            &reporter_kp,
            0,
            vec![OpCode::SysCallReportPqEquivocation {
                evidence: Box::new(ev),
            }],
        )],
    );
    let out_slash = eng.apply_block_transition(&blk_slash, 0).await;
    assert_eq!(out_slash.status, vec![true]);
    let pool_after = eng.get_account(&STAKING_POOL).await.unwrap().balance;
    assert!(
        pool_after < pool_before,
        "historical rotated key equivocation must slash STAKING_POOL"
    );
}

#[tokio::test]
async fn claim_withdrawal_and_step0_legacy_adoption() {
    let h = 50u64;
    let _gate = PqLifecycleGateGuard::at(h);
    let chain_id = effective_chain_id();
    let bond = required_bond_floor_nano();

    let legacy_hot = falcon(0x31);
    let legacy_id = [0x99u8; 32];
    let cold_kp = falcon(0x32);
    let cold_addr = pq_addr(&cold_kp);
    let wrong_kp = falcon(0x33);

    let eng = InMemoryStateEngine::new();
    eng.update_account(AccountState::new(cold_addr, FUNDS))
        .await;
    {
        let mut ledger = eng.staking_write().await;
        ledger.bond(legacy_id, bond, 500).expect("bond");
        ledger
            .register_pq_key(
                legacy_id,
                PqScheme::Falcon512,
                legacy_hot.public_key().to_vec(),
            )
            .expect("register legacy key");
    }

    // Wrong voting sig fails; valid voting sig claims withdrawal_address; second claim fails.
    let blk_h = make_block(
        h,
        vec![
            signed_pq_tx(
                &cold_kp,
                0,
                vec![claim_withdrawal_op(
                    chain_id, legacy_id, cold_addr, &wrong_kp,
                )],
            ),
            signed_pq_tx(
                &cold_kp,
                1,
                vec![claim_withdrawal_op(
                    chain_id,
                    legacy_id,
                    cold_addr,
                    &legacy_hot,
                )],
            ),
            signed_pq_tx(
                &cold_kp,
                2,
                vec![claim_withdrawal_op(
                    chain_id,
                    legacy_id,
                    cold_addr,
                    &legacy_hot,
                )],
            ),
        ],
    );
    let out = eng.apply_block_transition(&blk_h, 0).await;
    assert_eq!(out.status, vec![false, true, false]);
    assert_eq!(
        eng.staking_read().await.withdrawal_address_of(&legacy_id),
        Some(cold_addr)
    );
    // Step 0 adopted legacy_id into pq_registry with next_seq = 1.
    assert_eq!(
        eng.pq_registry_read()
            .await
            .record_of(&legacy_id)
            .unwrap()
            .next_seq,
        1
    );
}

#[tokio::test]
async fn storage_load_full_state_into_and_snap_v4_capture_pq_registry() {
    let dir = std::env::temp_dir().join(format!(
        "stell-r3d-restore-{}-{}",
        std::process::id(),
        TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let storage = Arc::new(Storage::open(&dir).expect("open storage"));

    let h = 10u64;
    let _gate = PqLifecycleGateGuard::at(h);
    let chain_id = effective_chain_id();
    let bond = required_bond_floor_nano();

    let cold_kp = falcon(0x41);
    let cold_addr = pq_addr(&cold_kp);
    let hot_kp = falcon(0x42);

    let src = InMemoryStateEngine::new();
    src.update_account(AccountState::new(cold_addr, FUNDS))
        .await;
    let blk = make_block(
        h,
        vec![signed_pq_tx(
            &cold_kp,
            0,
            vec![register_validator_op(
                chain_id, cold_addr, &hot_kp, bond, 500,
            )],
        )],
    );
    assert_eq!(src.apply_block_transition(&blk, 0).await.status, vec![true]);

    // SnapStateV4::capture_from_engine reads live pq_registry.
    let snap_v4 = SnapStateV4::capture_from_engine(&src, None, None, None)
        .await
        .expect("capture snap v4");
    assert_eq!(
        snap_v4.pq_registry.records(),
        src.pq_registry_read().await.records()
    );

    // Persist state + domains + pq_registry at height `h`, and verify load_full_state_into restores it.
    let state_bytes = src.create_snapshot().await;
    let staking = src.staking_read().await.clone();
    let gov = src.governance_read().await.clone();
    let dom = DomainSnapshot::capture(&src, &staking, &gov).await;
    let dom_bytes = bincode::serialize(&dom).expect("serialize domains");
    let pq_reg_bytes = src.pq_registry_snapshot().await;
    assert!(!pq_reg_bytes.is_empty());

    let root = src.get_state_root().await;
    storage.put_state(h, &state_bytes).unwrap();
    storage.put_domains(h, &dom_bytes).unwrap();
    storage.put_pq_registry(h, &pq_reg_bytes).unwrap();
    storage.put_finalized_post_root(h, root).unwrap();

    let restored = InMemoryStateEngine::new();
    let loaded = load_full_state_into(&storage, &restored)
        .await
        .expect("load_full_state_into succeeds");
    assert!(loaded.is_some());
    assert_eq!(
        restored.pq_registry_read().await.records(),
        src.pq_registry_read().await.records()
    );
    assert_eq!(restored.get_state_root().await, root);

    // Negative check: corrupt pq_registry fails verify_restored_root closed.
    storage.put_pq_registry(h, b"").unwrap();
    let bad = InMemoryStateEngine::new();
    assert!(
        load_full_state_into(&storage, &bad).await.is_err(),
        "empty/missing pq_registry with committed non-empty root must fail closed"
    );

    drop(storage);
    std::fs::remove_dir_all(&dir).ok();
}
