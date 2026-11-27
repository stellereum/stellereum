//! Wave 13a/13b scheduler tests for `AccessMode`, `ResourceKeyV2`,
//! `fill_access_keys_v2`, and `DisjointScheduler::schedule_v2`.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::orderbook::{PAIR_STELL_GRAM, PAIR_STELL_TON, PAIR_STELL_USDT};
use stellereum::parallel_exec::{
    fill_access_keys_v2, market_of_pair, AccessMode, DisjointScheduler, ResourceKeyV2,
};
use stellereum::sharding::Transaction;
use stellereum::svm::OpCode;

fn addr(tag: u8, idx: u16) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = tag;
    out[1..3].copy_from_slice(&idx.to_be_bytes());
    out
}

fn plain_tx(from: [u8; 32], to: [u8; 32], nonce: u64) -> Transaction {
    Transaction {
        from,
        to,
        amount: 100,
        gas_limit: 280_000,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    }
}

fn payload_tx(from: [u8; 32], to: [u8; 32], nonce: u64, payload: Vec<OpCode>) -> Transaction {
    Transaction {
        from,
        to,
        amount: 0,
        gas_limit: 500_000,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    }
}

#[test]
fn read_read_token_meta_100_disjoint_transfers_land_in_wave_0() {
    let token_id = [0xAA; 32];
    let txs: Vec<Transaction> = (0..100u16)
        .map(|i| {
            let sender = addr(0x10, i);
            let tx_to = addr(0x20, i);
            let token_to = addr(0x30, i);
            payload_tx(
                sender,
                tx_to,
                0,
                vec![OpCode::SysCallTokenTransfer {
                    token_id,
                    to: token_to,
                    amount: 50,
                }],
            )
        })
        .collect();

    let mut keys = Vec::new();
    fill_access_keys_v2(&txs[0], false, true, &mut keys);
    assert!(keys.contains(&(ResourceKeyV2::TokenMeta(token_id), AccessMode::Read)));
    assert!(keys.contains(&(
        ResourceKeyV2::TokenBalance(token_id, txs[0].from),
        AccessMode::Write
    )));
    assert!(keys.contains(&(
        ResourceKeyV2::TokenBalance(token_id, addr(0x30, 0)),
        AccessMode::Write
    )));

    let waves = DisjointScheduler::schedule_v2(&txs, false, true);
    assert_eq!(
        waves.len(),
        1,
        "100 disjoint TokenTransfers sharing TokenMeta(Read) must all share wave 0"
    );
    assert_eq!(waves[0], (0..100).collect::<Vec<_>>());
}

#[test]
fn read_read_token_balance_of_and_place_order_oracle_share_wave_0() {
    let token_id = [0xBB; 32];
    let shared_account = [0x44; 32];
    let txs = vec![
        payload_tx(
            addr(1, 1),
            addr(2, 1),
            0,
            vec![OpCode::SysCallTokenBalanceOf {
                token_id,
                account: shared_account,
            }],
        ),
        payload_tx(
            addr(1, 2),
            addr(2, 2),
            0,
            vec![OpCode::SysCallTokenBalanceOf {
                token_id,
                account: shared_account,
            }],
        ),
    ];

    let waves = DisjointScheduler::schedule_v2(&txs, false, true);
    assert_eq!(waves.len(), 1);
    assert_eq!(waves[0], vec![0, 1]);

    // Distinct markets both read Oracle and write disjoint Market(base, quote).
    let ob_txs = vec![
        payload_tx(
            addr(3, 1),
            addr(4, 1),
            0,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_USDT,
                is_buy: true,
                price: 100,
                amount: 10,
            }],
        ),
        payload_tx(
            addr(3, 2),
            addr(4, 2),
            0,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_TON,
                is_buy: false,
                price: 200,
                amount: 10,
            }],
        ),
        payload_tx(
            addr(3, 3),
            addr(4, 3),
            0,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_GRAM,
                is_buy: true,
                price: 300,
                amount: 10,
            }],
        ),
    ];

    let mut ob_keys = Vec::new();
    fill_access_keys_v2(&ob_txs[0], false, true, &mut ob_keys);
    let (b, q) = market_of_pair(PAIR_STELL_USDT);
    assert!(ob_keys.contains(&(ResourceKeyV2::Market(b, q), AccessMode::Write)));
    assert!(ob_keys.contains(&(ResourceKeyV2::Oracle, AccessMode::Read)));

    let ob_waves = DisjointScheduler::schedule_v2(&ob_txs, false, true);
    assert_eq!(ob_waves.len(), 1);
    assert_eq!(ob_waves[0], vec![0, 1, 2]);
}

#[test]
fn read_write_and_write_write_token_mint_vs_transfer_split() {
    let token_id = [0xCC; 32];

    let transfer_0 = payload_tx(
        addr(1, 0),
        addr(2, 0),
        0,
        vec![OpCode::SysCallTokenTransfer {
            token_id,
            to: addr(3, 0),
            amount: 10,
        }],
    );
    let mint = payload_tx(
        addr(1, 1),
        addr(2, 1),
        0,
        vec![OpCode::SysCallTokenMint {
            token_id,
            to: addr(3, 1),
            amount: 100,
        }],
    );
    let transfer_1 = payload_tx(
        addr(1, 2),
        addr(2, 2),
        0,
        vec![OpCode::SysCallTokenTransfer {
            token_id,
            to: addr(3, 2),
            amount: 20,
        }],
    );
    let transfer_2 = payload_tx(
        addr(1, 3),
        addr(2, 3),
        0,
        vec![OpCode::SysCallTokenTransfer {
            token_id,
            to: addr(3, 3),
            amount: 30,
        }],
    );

    let mut mint_keys = Vec::new();
    fill_access_keys_v2(&mint, false, true, &mut mint_keys);
    assert!(mint_keys.contains(&(ResourceKeyV2::TokenMeta(token_id), AccessMode::Write)));
    assert!(mint_keys.contains(&(
        ResourceKeyV2::TokenBalance(token_id, addr(3, 1)),
        AccessMode::Write
    )));

    // transfer_0 (Read) -> wave 0
    // mint (Write) -> wave 1 (Read + Write splits)
    // transfer_1, transfer_2 (Read) -> wave 2 (Write + Read splits, Read + Read shares wave 2)
    let waves =
        DisjointScheduler::schedule_v2(&[transfer_0, mint, transfer_1, transfer_2], false, true);
    assert_eq!(waves.len(), 3);
    assert_eq!(waves[0], vec![0]);
    assert_eq!(waves[1], vec![1]);
    assert_eq!(waves[2], vec![2, 3]);
}

#[test]
fn token_transfer_from_and_approve_conflict_on_allowance() {
    let token_id = [0xDD; 32];
    let owner = addr(5, 1);
    let spender = addr(5, 2);

    let approve = payload_tx(
        owner,
        addr(6, 1),
        0,
        vec![OpCode::SysCallTokenApprove {
            token_id,
            spender,
            amount: 500,
        }],
    );
    let transfer_from = payload_tx(
        spender,
        addr(6, 2),
        0,
        vec![OpCode::SysCallTokenTransferFrom {
            token_id,
            from: owner,
            to: addr(7, 1),
            amount: 100,
        }],
    );

    let mut approve_keys = Vec::new();
    fill_access_keys_v2(&approve, false, true, &mut approve_keys);
    assert!(approve_keys.contains(&(
        ResourceKeyV2::TokenAllowance(token_id, owner, spender),
        AccessMode::Write
    )));

    let mut tf_keys = Vec::new();
    fill_access_keys_v2(&transfer_from, false, true, &mut tf_keys);
    assert!(tf_keys.contains(&(ResourceKeyV2::TokenMeta(token_id), AccessMode::Read)));
    assert!(tf_keys.contains(&(
        ResourceKeyV2::TokenAllowance(token_id, owner, spender),
        AccessMode::Write
    )));
    assert!(tf_keys.contains(&(
        ResourceKeyV2::TokenBalance(token_id, owner),
        AccessMode::Write
    )));
    assert!(tf_keys.contains(&(
        ResourceKeyV2::TokenBalance(token_id, addr(7, 1)),
        AccessMode::Write
    )));

    let waves = DisjointScheduler::schedule_v2(&[approve, transfer_from], false, true);
    assert_eq!(waves.len(), 2);
    assert_eq!(waves[0], vec![0]);
    assert_eq!(waves[1], vec![1]);
}

#[test]
fn delegate_different_validators_share_wave_0_same_validator_splits() {
    let val_a = [0xA1; 32];
    let val_b = [0xB2; 32];

    let del_a0 = payload_tx(
        addr(1, 0),
        addr(2, 0),
        0,
        vec![OpCode::SysCallDelegate {
            validator: val_a,
            amount: 1_000,
        }],
    );
    let del_b = payload_tx(
        addr(1, 1),
        addr(2, 1),
        0,
        vec![OpCode::SysCallDelegate {
            validator: val_b,
            amount: 2_000,
        }],
    );
    let del_a1 = payload_tx(
        addr(1, 2),
        addr(2, 2),
        0,
        vec![OpCode::SysCallDelegate {
            validator: val_a,
            amount: 3_000,
        }],
    );

    let mut keys = Vec::new();
    fill_access_keys_v2(&del_a0, false, true, &mut keys);
    assert!(keys.contains(&(ResourceKeyV2::Validator(val_a), AccessMode::Write)));
    assert!(!keys.iter().any(|(k, _)| *k == ResourceKeyV2::Global));

    // Different validators share wave 0; same validator splits into wave 1.
    let waves_diff = DisjointScheduler::schedule_v2(&[del_a0.clone(), del_b.clone()], false, true);
    assert_eq!(waves_diff.len(), 1);
    assert_eq!(waves_diff[0], vec![0, 1]);

    let waves_same = DisjointScheduler::schedule_v2(&[del_a0, del_b, del_a1], false, true);
    assert_eq!(waves_same.len(), 2);
    assert_eq!(waves_same[0], vec![0, 1]);
    assert_eq!(waves_same[1], vec![2]);
}

#[test]
fn call_contract_args_stm_vs_non_stm_never_triggers_global_barrier() {
    let contract_a = [0xC1; 32];
    let contract_b = [0xC2; 32];

    let call_a0 = payload_tx(
        addr(1, 0),
        addr(1, 0),
        0,
        vec![OpCode::SysCallCallContractArgs {
            contract: contract_a,
            method: b"inc".to_vec(),
            args: vec![1, 2],
            calldata: Vec::new(),
        }],
    );
    let call_a1 = payload_tx(
        addr(1, 1),
        addr(1, 1),
        0,
        vec![OpCode::SysCallCallContractArgs {
            contract: contract_a,
            method: b"inc".to_vec(),
            args: vec![3, 4],
            calldata: Vec::new(),
        }],
    );
    let call_b = payload_tx(
        addr(1, 2),
        addr(1, 2),
        0,
        vec![OpCode::SysCallCallContractArgs {
            contract: contract_b,
            method: b"inc".to_vec(),
            args: vec![5],
            calldata: Vec::new(),
        }],
    );
    let trailing_transfer = plain_tx(addr(1, 3), addr(2, 3), 0);

    // stm_contracts = false: emits Contract(contract_a) Write, never Global.
    let mut keys_no_stm = Vec::new();
    fill_access_keys_v2(&call_a0, false, true, &mut keys_no_stm);
    assert!(keys_no_stm.contains(&(ResourceKeyV2::Contract(contract_a), AccessMode::Write)));
    assert!(!keys_no_stm.iter().any(|(k, _)| *k == ResourceKeyV2::Global));

    let waves_no_stm = DisjointScheduler::schedule_v2(
        &[
            call_a0.clone(),
            call_a1.clone(),
            call_b.clone(),
            trailing_transfer.clone(),
        ],
        false,
        true,
    );
    assert_eq!(waves_no_stm.len(), 2);
    assert_eq!(waves_no_stm[0], vec![0, 2, 3]);
    assert_eq!(waves_no_stm[1], vec![1]);

    // stm_contracts = true: omits Contract(*contract) so calls on contract_a share wave 0,
    // while keeping Account(from/to/sponsor).
    let mut keys_stm = Vec::new();
    fill_access_keys_v2(&call_a0, true, true, &mut keys_stm);
    assert!(!keys_stm
        .iter()
        .any(|(k, _)| matches!(k, ResourceKeyV2::Contract(_) | ResourceKeyV2::Global)));
    assert!(keys_stm.contains(&(ResourceKeyV2::Account(addr(1, 0)), AccessMode::Write)));

    let waves_stm =
        DisjointScheduler::schedule_v2(&[call_a0, call_a1, call_b, trailing_transfer], true, true);
    assert_eq!(waves_stm.len(), 1);
    assert_eq!(waves_stm[0], vec![0, 1, 2, 3]);

    // Verify sponsor Account(sponsor) is preserved even when stm_contracts = true.
    let u1 = SigningKey::generate(&mut OsRng);
    let u2 = SigningKey::generate(&mut OsRng);
    let sponsor = SigningKey::generate(&mut OsRng);
    let s_addr = sponsor.verifying_key().to_bytes();
    let call_payload = vec![OpCode::SysCallCallContractArgs {
        contract: contract_a,
        method: b"ping".to_vec(),
        args: vec![1],
        calldata: Vec::new(),
    }];
    let sp0 = Transaction::sign_with_sponsor(
        &u1,
        &sponsor,
        u1.verifying_key().to_bytes(),
        0,
        500_000,
        0,
        1,
        1,
        call_payload.clone(),
        0,
        500_000,
        u64::MAX,
        Vec::new(),
        1,
    );
    let sp1 = Transaction::sign_with_sponsor(
        &u2,
        &sponsor,
        u2.verifying_key().to_bytes(),
        0,
        500_000,
        0,
        1,
        1,
        call_payload,
        0,
        500_000,
        u64::MAX,
        Vec::new(),
        1,
    );
    let mut sp_keys = Vec::new();
    fill_access_keys_v2(&sp0, true, true, &mut sp_keys);
    assert!(sp_keys.contains(&(ResourceKeyV2::Account(s_addr), AccessMode::Write)));
    let sp_waves = DisjointScheduler::schedule_v2(&[sp0, sp1], true, true);
    assert_eq!(
        sp_waves.len(),
        2,
        "shared sponsor account must still split waves when stm_contracts=true"
    );
}

#[test]
fn halt_stops_trailing_opcode_barrier_when_exec_hardening_true() {
    let pre = plain_tx(addr(1, 0), addr(2, 0), 0);
    let halted_tx = payload_tx(
        addr(1, 1),
        addr(2, 1),
        0,
        vec![
            OpCode::Nop,
            OpCode::Halt,
            OpCode::SysCallDeployContract {
                code: vec![0x00, 0x61, 0x73, 0x6D],
            },
        ],
    );
    let post = plain_tx(addr(1, 2), addr(2, 2), 0);

    // With exec_hardening = true, scanning stops at OpCode::Halt so trailing DeployContract
    // never triggers a Global barrier.
    let mut keys_hardened = Vec::new();
    fill_access_keys_v2(&halted_tx, false, true, &mut keys_hardened);
    assert!(!keys_hardened
        .iter()
        .any(|(k, _)| *k == ResourceKeyV2::Global));

    let waves_hardened = DisjointScheduler::schedule_v2(
        &[pre.clone(), halted_tx.clone(), post.clone()],
        false,
        true,
    );
    assert_eq!(waves_hardened.len(), 1);
    assert_eq!(waves_hardened[0], vec![0, 1, 2]);

    // With exec_hardening = false, scanning continues past Halt and hits Global barrier.
    let mut keys_legacy = Vec::new();
    fill_access_keys_v2(&halted_tx, false, false, &mut keys_legacy);
    assert!(keys_legacy.iter().any(|(k, _)| *k == ResourceKeyV2::Global));

    let waves_legacy = DisjointScheduler::schedule_v2(&[pre, halted_tx, post], false, false);
    assert_eq!(waves_legacy.len(), 3);
    assert_eq!(waves_legacy[0], vec![0]);
    assert_eq!(waves_legacy[1], vec![1]);
    assert_eq!(waves_legacy[2], vec![2]);
}

#[test]
fn global_opcodes_trigger_barrier_and_never_share_wave() {
    let pre = plain_tx(addr(1, 0), addr(2, 0), 0);
    let cancel = payload_tx(
        addr(1, 1),
        addr(2, 1),
        0,
        vec![OpCode::SysCallCancelOrder { order_id: 42 }],
    );
    let post = plain_tx(addr(1, 2), addr(2, 2), 0);

    let mut keys = Vec::new();
    fill_access_keys_v2(&cancel, true, true, &mut keys);
    assert!(keys.contains(&(ResourceKeyV2::Global, AccessMode::Write)));

    let waves = DisjointScheduler::schedule_v2(&[pre, cancel, post], true, true);
    assert_eq!(waves.len(), 3);
    assert_eq!(waves[0], vec![0]);
    assert_eq!(waves[1], vec![1]);
    assert_eq!(waves[2], vec![2]);
}

#[test]
fn stm_contract_calls_never_reorder_across_waves() {
    let contract_a = [0xC3; 32];
    let sender_0 = addr(9, 1);
    let sender_1 = addr(9, 2);

    // tx 0 touches sender_0 (wave 0); tx 1 (same sender_0) calls contract_a
    // and must go to wave 1; tx 2 (disjoint sender_1) also calls contract_a
    // and MUST NOT jump ahead of tx 1 into wave 0 (both share wave 1 via STM).
    let tx0 = plain_tx(sender_0, addr(9, 9), 0);
    let tx1 = payload_tx(
        sender_0,
        sender_0,
        1,
        vec![OpCode::SysCallCallContract {
            contract: contract_a,
            method: b"inc".to_vec(),
            arg: 1,
        }],
    );
    let tx2 = payload_tx(
        sender_1,
        sender_1,
        0,
        vec![OpCode::SysCallCallContract {
            contract: contract_a,
            method: b"inc".to_vec(),
            arg: 1,
        }],
    );

    let waves = DisjointScheduler::schedule_v2(&[tx0, tx1, tx2], true, true);
    assert_eq!(waves.len(), 2);
    assert_eq!(waves[0], vec![0]);
    assert_eq!(waves[1], vec![1, 2]);
}
