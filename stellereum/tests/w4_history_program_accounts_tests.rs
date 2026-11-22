//! W4 E3 — history indexes and bounded `getProgramAccounts`-analogue.
//!
//! WHAT IS PINNED HERE (the contracts each test exists for):
//!   1. `tx_by_addr` / `events_by_contract` / `receipt_meta_v2` are written by
//!      the single real receipt-filing path, survive a `Storage` reopen, serve
//!      a STRICT keyset cursor (no duplicate/skip), and are removed together
//!      with the receipts by `prune_receipts_below`.
//!   2. `stell_listTokens` walks a >100-token registry deterministically under
//!      a cursor: every token appears exactly once, insertion between pages
//!      neither shifts nor duplicates a page.
//!   3. `stell_getProgramAccounts` enforces its documented bounds (system dump
//!      refusal, page cap, scan cap with `scan_truncated` + `next_cursor`,
//!      proof cap) and its filters (`token`, `contract`, `creator`), and
//!      `stell_getTokenAccountsByOwner` is a deterministic per-owner view.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use tokio::sync::RwLock;

use stellereum::contract::{Contract, ContractEvent};
use stellereum::mempool::Mempool;
use stellereum::rpc::{
    ReceiptIndex, RpcState, MAX_PROGRAM_ACCOUNTS_PROOFS, MAX_PROGRAM_ACCOUNTS_SCAN,
};
use stellereum::sharding::{Block, ShardRegistry, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{
    events_by_contract_key, events_by_contract_key_parts, tx_by_addr_key, tx_by_addr_key_parts,
    EventCursor, HistoryCursor, HistoryRole, Storage, EVENTS_BY_CONTRACT_KEY_LEN,
    TX_BY_ADDR_KEY_LEN,
};
use stellereum::token::{TokenActor, TokenMetadata};

const SENDER: [u8; 32] = [0xA1; 32];
const RECIPIENT: [u8; 32] = [0xB2; 32];
const EVENT_CONTRACT: [u8; 32] = [0xC3; 32];

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "stell_w4_history_{tag}_{}_{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn det_tx(height: u64) -> Transaction {
    Transaction {
        from: SENDER,
        to: RECIPIENT,
        amount: 100 + height,
        gas_limit: 280_000,
        nonce: height,
        source_shard: MASTERCHAIN_SHARD,
        target_shard: MASTERCHAIN_SHARD,
        signature: vec![0xAB; 64],
        payload: vec![],
        priority_fee_per_gas: 0,
    }
}

fn det_block(height: u64) -> Block {
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![det_tx(height)],
        cross_shard_out: Vec::new(),
        timestamp: 1_000 + height,
        proposer: [0x01u8; 32],
        validator_signatures: Vec::new(),
        shard_headers: Vec::new(),
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        round: 0,
    }
}

fn event(height: u64) -> ContractEvent {
    ContractEvent {
        contract: EVENT_CONTRACT,
        topic: 7,
        value: height as i64,
    }
}

fn heights(page: &stellereum::storage::AddressHistoryPage) -> Vec<u64> {
    page.items.iter().map(|i| i.height).collect()
}

fn event_heights(page: &stellereum::storage::ContractEventsPage) -> Vec<u64> {
    page.items.iter().map(|i| i.height).collect()
}

#[test]
fn storage_address_history_survives_restart_and_pruning() {
    let dir = temp_dir("storage");

    // 1. File six finalized blocks through the real receipt path.
    {
        let st = Storage::open(&dir).expect("open store");
        for height in 1..=6u64 {
            let block = det_block(height);
            let hash = st.put_block(&block).expect("put block");
            st.put_receipts_for_block_with_events(
                height,
                &hash,
                &block.transactions,
                &[true],
                &[280_000],
                &[vec![event(height)]],
            )
            .expect("file receipts");
        }
        st.flush().expect("flush");

        // Tip-first, strict cursor: page 1 = 6,5,4,3; page 2 = 2,1.
        let page = st
            .address_history(&SENDER, 0, u64::MAX, HistoryRole::All, None, 4)
            .expect("address history");
        assert_eq!(heights(&page), vec![6, 5, 4, 3]);
        assert!(page.has_more);
        let cursor = page.next_cursor.expect("cursor after page 1");

        let page2 = st
            .address_history(&SENDER, 0, u64::MAX, HistoryRole::All, Some(cursor), 4)
            .expect("address history page 2");
        assert_eq!(
            heights(&page2),
            vec![2, 1],
            "the cursor must resume strictly older: no duplicate, no skip"
        );
        assert!(!page2.has_more);

        // Role filtering uses `receipt_meta_v2`, not a guess from the key.
        let recipient_only = st
            .address_history(&RECIPIENT, 0, u64::MAX, HistoryRole::Sender, None, 10)
            .expect("role sender");
        assert!(recipient_only.items.is_empty());
        let recipient = st
            .address_history(&RECIPIENT, 0, u64::MAX, HistoryRole::Recipient, None, 10)
            .expect("role recipient");
        assert_eq!(heights(&recipient), vec![6, 5, 4, 3, 2, 1]);

        // Inclusive height window.
        let window = st
            .address_history(&SENDER, 2, 4, HistoryRole::All, None, 10)
            .expect("window");
        assert_eq!(heights(&window), vec![4, 3, 2]);

        // Per-transaction metadata: from/to/amount/shard/timestamp.
        let meta = st
            .receipt_meta(&det_tx(3).compute_tx_hash())
            .expect("receipt meta")
            .expect("meta present");
        assert_eq!(meta.from, SENDER);
        assert_eq!(meta.to, RECIPIENT);
        assert_eq!(meta.amount, 103);
        assert_eq!(meta.shard_id, MASTERCHAIN_SHARD);
        assert_eq!(meta.timestamp, 1_003);

        // Contract events, tip-first, with an event cursor.
        let events = st
            .events_by_contract_range(&EVENT_CONTRACT, 0, u64::MAX, None, None, 4)
            .expect("events");
        assert_eq!(event_heights(&events), vec![6, 5, 4, 3]);
        assert!(events.has_more);
        let ecursor = events.next_cursor.expect("event cursor");
        let events2 = st
            .events_by_contract_range(&EVENT_CONTRACT, 0, u64::MAX, None, Some(ecursor), 4)
            .expect("events page 2");
        assert_eq!(event_heights(&events2), vec![2, 1]);

        // Fixed-width key helpers round-trip (the formats the RPC cursors use).
        let key = tx_by_addr_key(&SENDER, 9, 2);
        assert_eq!(key.len(), TX_BY_ADDR_KEY_LEN);
        assert_eq!(
            tx_by_addr_key_parts(&key),
            Some((SENDER, 9, 2)),
            "44-byte tx_by_addr key must round-trip"
        );
        let ekey = events_by_contract_key(&EVENT_CONTRACT, 9, 2, 1);
        assert_eq!(ekey.len(), EVENTS_BY_CONTRACT_KEY_LEN);
        assert_eq!(
            events_by_contract_key_parts(&ekey),
            Some((EVENT_CONTRACT, 9, 2, 1)),
            "48-byte events_by_contract key must round-trip"
        );
        assert_eq!(
            EventCursor::from_hex(
                &EventCursor {
                    height: 9,
                    tx_index: 2,
                    log_index: 1,
                }
                .to_hex()
            ),
            Some(EventCursor {
                height: 9,
                tx_index: 2,
                log_index: 1,
            })
        );
        assert_eq!(
            HistoryCursor::from_hex(
                &HistoryCursor {
                    height: 9,
                    tx_index: 2,
                }
                .to_hex()
            ),
            Some(HistoryCursor {
                height: 9,
                tx_index: 2,
            })
        );
    }

    // 2. Restart: the additive trees reopen and serve the same window.
    {
        let st = Storage::open(&dir).expect("reopen store");
        let page = st
            .address_history(&SENDER, 0, u64::MAX, HistoryRole::All, None, 10)
            .expect("history after reopen");
        assert_eq!(
            heights(&page),
            vec![6, 5, 4, 3, 2, 1],
            "history indexes must survive a Storage reopen"
        );
    }

    // 3. Pruning removes receipts AND every history row below the window.
    {
        let st = Storage::open(&dir).expect("reopen for prune");
        let removed = st.prune_receipts_below(4).expect("prune");
        assert_eq!(removed, 3, "heights 1..=3 are below keep_from=4");

        let page = st
            .address_history(&SENDER, 0, u64::MAX, HistoryRole::All, None, 10)
            .expect("history after prune");
        assert_eq!(
            heights(&page),
            vec![6, 5, 4],
            "tx_by_addr rows for pruned heights must be gone"
        );
        assert!(st
            .receipt_meta(&det_tx(2).compute_tx_hash())
            .expect("meta read")
            .is_none());
        assert!(st
            .receipt_meta(&det_tx(5).compute_tx_hash())
            .expect("meta read")
            .is_some());

        let events = st
            .events_by_contract_range(&EVENT_CONTRACT, 0, u64::MAX, None, None, 10)
            .expect("events after prune");
        assert_eq!(
            event_heights(&events),
            vec![6, 5, 4],
            "events_by_contract rows for pruned heights must be gone"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn stell_list_tokens_deterministic_under_cursor() {
    let engine = Arc::new(InMemoryStateEngine::new());
    {
        let mut registry = engine.tokens_write().await;
        for i in 0..150u8 {
            let id = [i; 32];
            let meta = TokenMetadata {
                name: format!("Token-{i}"),
                symbol: format!("T{i}"),
                decimals: 6,
                total_supply: 0,
                max_supply: None,
                minter: [0x11; 32],
                paused: false,
                description: String::new(),
            };
            let actor = TokenActor::new(id, meta, 1_000_000).expect("valid token");
            registry.tokens.insert(id, actor);
        }
    }
    let st = test_rpc_state(engine.clone());

    // Page 1 twice: byte-identical, deterministic.
    let p1 = st.call("stell_listTokens", json!({ "limit": 50 })).await;
    let p1_again = st.call("stell_listTokens", json!({ "limit": 50 })).await;
    assert_eq!(p1, p1_again, "BTreeMap order must be deterministic");
    assert_eq!(p1["tokens"].as_array().unwrap().len(), 50);
    assert_eq!(p1["has_more"], json!(true));

    // Insert a SMALLER id between pages: a keyset cursor must not see it and
    // must not shift the remaining page.
    let inserted = {
        let mut id = [0u8; 32];
        id[31] = 1;
        id
    };
    {
        let mut registry = engine.tokens_write().await;
        let meta = TokenMetadata {
            name: "Inserted".to_string(),
            symbol: "INS".to_string(),
            decimals: 6,
            total_supply: 0,
            max_supply: None,
            minter: [0x11; 32],
            paused: false,
            description: String::new(),
        };
        registry.tokens.insert(
            inserted,
            TokenActor::new(inserted, meta, 1).expect("valid token"),
        );
    }

    let mut seen: Vec<String> = p1["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let mut cursor = p1["next_cursor"].as_str().map(str::to_string);
    while let Some(c) = cursor {
        let page = st
            .call("stell_listTokens", json!({ "limit": 50, "cursor": c }))
            .await;
        let batch: Vec<String> = page["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        seen.extend(batch);
        cursor = page["next_cursor"].as_str().map(str::to_string);
        if page["has_more"] == json!(false) {
            break;
        }
    }

    let mut expected: Vec<String> = (0..150u8).map(|i| hex::encode([i; 32])).collect();
    expected.sort();
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), seen.len(), "a page walk returned a duplicate");
    assert_eq!(
        unique, expected,
        "the cursor walk must return every original token exactly once"
    );
    assert!(
        !seen.contains(&hex::encode(inserted)),
        "an id inserted BEFORE the cursor must not appear after it"
    );

    // Hard page cap: asking for 1000 returns at most MAX_PAGE_LIMIT (200).
    let capped = st.call("stell_listTokens", json!({ "limit": 1000 })).await;
    assert!(
        capped["tokens"].as_array().unwrap().len() <= stellereum::rpc::MAX_PAGE_LIMIT,
        "limit must be clamped to MAX_PAGE_LIMIT"
    );
}

fn test_rpc_state(engine: Arc<InMemoryStateEngine>) -> Arc<RpcState> {
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(RwLock::new(Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(1_000)),
        node_id: "inf1:w4-history-program-accounts".to_string(),
        chain_id: 777,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

fn det_addr(tag: u8, i: u64) -> [u8; 32] {
    let mut addr = [tag; 32];
    addr[..8].copy_from_slice(&i.to_be_bytes());
    addr
}

#[tokio::test]
async fn stell_get_program_accounts_enforces_bounds_and_filters() {
    let engine = Arc::new(InMemoryStateEngine::new());

    // 120 native accounts with a positive balance (system program).
    for i in 0..120u64 {
        engine
            .update_account(AccountState::new(det_addr(0xE0, i), 5))
            .await;
    }
    let first_system = det_addr(0xE0, 0);

    // One token with 20 holders (token program).
    const TOKEN: [u8; 32] = [0x7A; 32];
    let holders: Vec<[u8; 32]> = (0..20u64).map(|i| det_addr(0x40, i)).collect();
    {
        let meta = TokenMetadata {
            name: "Holder Token".to_string(),
            symbol: "HLD".to_string(),
            decimals: 6,
            total_supply: 0,
            max_supply: None,
            minter: [0x11; 32],
            paused: false,
            description: String::new(),
        };
        let mut actor = TokenActor::new(TOKEN, meta, 0).expect("valid token");
        for holder in &holders {
            actor.balances.insert(*holder, 100);
        }
        engine.tokens_write().await.tokens.insert(TOKEN, actor);
    }

    // Two contracts: a big one for the scan cap, a small one for filters.
    const BIG_CONTRACT: [u8; 32] = [0xC1; 32];
    const SMALL_CONTRACT: [u8; 32] = [0xC2; 32];
    {
        let mut contracts = engine.contracts_write().await;
        let mut big_storage = HashMap::new();
        for slot in 0..BIG_SLOTS {
            big_storage.insert(slot, slot * 2);
        }
        contracts.contracts.insert(
            BIG_CONTRACT,
            Contract {
                address: BIG_CONTRACT,
                creator: [0xD1; 32],
                code_hash: [0xAA; 32],
                code: vec![0x00, 0x61, 0x73, 0x6D],
                storage: big_storage,
                created_at: 1,
                paused: false,
                balance: 0,
                abi: None,
                source_hash: None,
            },
        );
        let mut small_storage = HashMap::new();
        small_storage.insert(7i64, 70);
        small_storage.insert(-5i64, -50);
        small_storage.insert(0i64, 0);
        contracts.contracts.insert(
            SMALL_CONTRACT,
            Contract {
                address: SMALL_CONTRACT,
                creator: [0xD0; 32],
                code_hash: [0xBB; 32],
                code: vec![0x00, 0x61, 0x73, 0x6D],
                storage: small_storage,
                created_at: 2,
                paused: false,
                balance: 0,
                abi: None,
                source_hash: None,
            },
        );
    }
    // Re-commit token balances / contract code into the trie so proofs exist.
    engine.sync_aux_trie().await;

    let st = test_rpc_state(engine);

    // (a) Unfiltered system dump is REFUSED.
    let refused = st
        .call("stell_getProgramAccounts", json!({ "program": "system" }))
        .await;
    assert!(
        refused.get("error").is_some(),
        "an unfiltered system dump must be refused: {refused}"
    );

    // (b) owner filter returns exactly that account.
    let owner_view = st
        .call(
            "stell_getProgramAccounts",
            json!({ "program": "system", "owner": hex::encode(first_system) }),
        )
        .await;
    let items = owner_view["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["address"], json!(hex::encode(first_system)));
    assert_eq!(items[0]["balance"], json!("5"));

    // (c) page cap: 120 matches, limit 1000 -> 100 items + has_more + cursor.
    let bounded = st
        .call(
            "stell_getProgramAccounts",
            json!({ "program": "system", "min_balance": "1", "limit": 1000 }),
        )
        .await;
    let page_items = bounded["items"].as_array().expect("items");
    assert_eq!(page_items.len(), 100, "MAX_PROGRAM_ACCOUNTS_LIMIT hard cap");
    assert_eq!(bounded["has_more"], json!(true));
    let next = bounded["next_cursor"]
        .as_str()
        .expect("continuation cursor");
    let rest = st
        .call(
            "stell_getProgramAccounts",
            json!({ "program": "system", "min_balance": "1", "cursor": next, "limit": 1000 }),
        )
        .await;
    assert_eq!(
        rest["items"].as_array().unwrap().len(),
        20,
        "the continuation must serve the remaining accounts"
    );
    assert_eq!(rest["has_more"], json!(false));

    // (d) scan cap: a slot window that matches nothing still stops at 10_000
    //     inspected rows and reports truncation + a continuation cursor.
    let truncated = st
        .call(
            "stell_getProgramAccounts",
            json!({
                "program": "contract",
                "contract": hex::encode(BIG_CONTRACT),
                "slot_from": 1_000_000,
            }),
        )
        .await;
    assert!(truncated["items"].as_array().unwrap().is_empty());
    assert_eq!(truncated["scanned"], json!(MAX_PROGRAM_ACCOUNTS_SCAN));
    assert_eq!(truncated["scan_truncated"], json!(true));
    assert_eq!(truncated["has_more"], json!(true));
    assert!(
        truncated["next_cursor"].is_string(),
        "scan truncation must carry a continuation cursor"
    );

    // (e) contract storage: deterministic ascending i64 order.
    let slots = st
        .call(
            "stell_getProgramAccounts",
            json!({ "program": "contract", "contract": hex::encode(SMALL_CONTRACT) }),
        )
        .await;
    let slot_keys: Vec<String> = slots["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["slot"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(slot_keys, vec!["-5", "0", "7"]);

    // (f) creator filter: code-free projection by default.
    let by_creator = st
        .call(
            "stell_getProgramAccounts",
            json!({ "program": "contract", "creator": hex::encode([0xD0u8; 32]) }),
        )
        .await;
    let creator_items = by_creator["items"].as_array().unwrap();
    assert_eq!(creator_items.len(), 1);
    assert_eq!(
        creator_items[0]["contract"],
        json!(hex::encode(SMALL_CONTRACT))
    );
    assert!(
        creator_items[0].get("code").is_none(),
        "raw bytecode must be omitted unless include_code is requested"
    );

    // (g) token holders + proof cap (16 per page even if limit=100).
    let holders_view = st
        .call(
            "stell_getProgramAccounts",
            json!({ "program": "token", "token": hex::encode(TOKEN), "with_proof": true, "limit": 100 }),
        )
        .await;
    let proof_items = holders_view["items"].as_array().unwrap();
    assert_eq!(
        proof_items.len(),
        MAX_PROGRAM_ACCOUNTS_PROOFS,
        "with_proof pages are capped at MAX_PROGRAM_ACCOUNTS_PROOFS"
    );
    assert_eq!(holders_view["has_more"], json!(true));
    assert!(
        proof_items.iter().any(|i| !i["proof"].is_null()),
        "at least one token-balance proof must be present after sync_aux_trie"
    );

    // (h) token program without token/owner is refused.
    let token_refused = st
        .call("stell_getProgramAccounts", json!({ "program": "token" }))
        .await;
    assert!(token_refused.get("error").is_some());

    // (i) `stell_getTokenAccountsByOwner`: deterministic per-owner view.
    let by_owner = st
        .call(
            "stell_getTokenAccountsByOwner",
            json!({ "owner": hex::encode(holders[0]) }),
        )
        .await;
    let owner_items = by_owner["items"].as_array().unwrap();
    assert_eq!(owner_items.len(), 1);
    assert_eq!(owner_items[0]["token"], json!(hex::encode(TOKEN)));
    assert_eq!(owner_items[0]["balance"], json!("100"));
}

/// Big enough to exceed `MAX_PROGRAM_ACCOUNTS_SCAN` (10 000) with a window
/// that matches nothing, so the truncation branch is reached deterministically.
const BIG_SLOTS: i64 = 10_100;
