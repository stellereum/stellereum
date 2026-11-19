use super::types::{
    encode_actor_body, note_account_before, token_balance_key, token_supply_key, ActorSnapshot,
    BridgeSnapshot, ClobQuoteMode, EscrowRecord, NativeMove,
};
use super::{AccountState, ActorMessage, InMemoryStateEngine};
use crate::token::{TokenOp, TokenRegistry};
use std::collections::{HashMap, HashSet};

impl InMemoryStateEngine {
    // ==================== CLOB settlement (A7) ====================

    /// Quote value (wUSDT micro-units) for `base_nano` STELL at `price_micro` USD.
    fn clob_quote_value(price_micro: u64, base_nano: u64) -> u64 {
        ClobQuoteMode::Wusdt.quote(price_micro, base_nano)
    }

    /// Quote value in native nano-STELL under the SVM path's convention - the
    /// same number `SysCallPlaceOrder` calls `order_cost`.
    fn clob_quote_native(price_micro: u64, base_nano: u64) -> u64 {
        let prod = (price_micro as u128) * (base_nano as u128);
        (prod / 1_000_000u128).min(u64::MAX as u128) as u64
    }

    /// Place an order on the native CLOB and SETTLE matched trades against real
    /// balances: the buyer pays wUSDT and receives native STELL; the seller pays
    /// native STELL and receives wUSDT. It is all-or-nothing: if any counterparty
    /// cannot fund its side, the whole call reverts (no partial settlement, no
    /// free fills). Previously the orderbook matched orders without moving any
    /// funds at all (A7).
    ///
    /// Resting (unfilled) limit remainders ARE escrowed at placement time: a
    /// sell locks its base STELL, a buy locks its quote - burned out of the
    /// trader's wUSDT under this entry point's convention. The SVM path
    /// (`SysCallPlaceOrder` -> `settle_clob_effects`) locks the same way but
    /// prices the quote in native units, because that is what its affordability
    /// check sees; whichever entry point placed an order, its escrow is released
    /// in the asset it was locked in (see `EscrowRecord`).
    #[allow(clippy::too_many_arguments)]
    // GATE: order settlement needs full order context; splitting params risks mismatch.
    pub async fn place_order_settled(
        &self,
        pair: u32,
        trader: [u8; 32],
        side: crate::orderbook::OrderSide,
        order_type: crate::orderbook::OrderType,
        price: u64,
        amount: u64,
        now: u64,
    ) -> Result<(u64, usize), String> {
        // Priority gates, FIRST and unchanged from the SVM path: breaker
        // latch, USDT peg, deviation against the committed price. This entry
        // point used to be a way to place an order without ever consulting the
        // oracle, i.e. a bypass; `OracleState::gate_order` is the same call
        // `SysCallPlaceOrder` makes, so the two can no longer disagree.
        // Read-only since E3 (an order never latches the breaker).
        {
            let oracle = self.oracle.read().await;
            oracle.gate_order(pair, price)?;
        }

        let quote_id = self
            .pmm_usdt_token
            .read()
            .await
            .ok_or_else(|| "CLOB quote (wUSDT) token not configured".to_string())?;

        // 1) Match on a CLONE of the book so nothing commits until settled.
        let mut book = self
            .orderbooks
            .read()
            .await
            .books
            .get(&pair)
            .cloned()
            .unwrap_or_else(|| crate::orderbook::OrderbookActor::new(pair, 1000));
        let (order, trades) = book.submit_order_bounded(
            trader,
            side.clone(),
            order_type.clone(),
            price,
            amount,
            now,
            crate::svm::MAX_MATCH_LEVELS,
        );
        let taker_is_buyer = matches!(side, crate::orderbook::OrderSide::Buy);
        let is_limit = matches!(order_type, crate::orderbook::OrderType::Limit);
        let unfilled = order.amount.saturating_sub(order.filled);

        if trades.is_empty() {
            // Resting limit order without immediate fills locks escrow immediately.
            // The order is locked for exactly what the BOOK holds of it: a full
            // book can silently refuse the newcomer (see `submit_order_bounded`),
            // and an escrow record for an order that is not resting is the very
            // orphan `cancel_order_settled` can never release (it looks the order
            // up in the book and finds nothing).
            if is_limit && unfilled > 0 && book.find_order(order.order_id).is_some() {
                if taker_is_buyer {
                    let q_escrow = Self::clob_quote_value(price, unfilled);
                    let mut tokens = self.tokens_write().await;
                    tokens
                        .execute(
                            &quote_id,
                            trader,
                            crate::token::TokenOp::Burn {
                                from: trader,
                                amount: q_escrow,
                            },
                        )
                        .map_err(|e| format!("CLOB taker escrow lock failed: {e}"))?;
                    let new_bal = tokens.balance_of(&quote_id, &trader);
                    let mut trie = self.state_trie.write().await;
                    trie.insert(
                        &token_balance_key(&quote_id, &trader),
                        &new_bal.to_be_bytes(),
                    );
                    drop(trie);
                    drop(tokens);
                    self.order_escrow_write().await.insert(
                        (pair, order.order_id),
                        EscrowRecord {
                            trader,
                            locked_base_stell: 0,
                            locked_quote_wusdt: q_escrow,
                            locked_quote_native: 0,
                        },
                    );
                } else {
                    self.debit_native(&trader, unfilled).await?;
                    self.order_escrow_write().await.insert(
                        (pair, order.order_id),
                        EscrowRecord {
                            trader,
                            locked_base_stell: unfilled,
                            locked_quote_wusdt: 0,
                            locked_quote_native: 0,
                        },
                    );
                }
            }
            self.orderbooks_write().await.books.insert(pair, book);
            return Ok((order.order_id, 0));
        }

        // 2) Validate EVERY trade and resting order up-front so nothing fails midway.
        //    (A partial settlement would move funds but leave the book unfilled,
        //    enabling a re-match double spend.) Self-trades net to zero and are
        //    skipped; dust quote and a paused/missing quote token are rejected.
        {
            let tokens = self.tokens.read().await;
            match tokens.get(&quote_id) {
                Some(tok) if !tok.metadata.paused => {}
                _ => return Err("CLOB settlement: quote token missing or paused".to_string()),
            }
        }

        let escrows = self.order_escrow.read().await;
        let mut need_base: HashMap<[u8; 32], u64> = HashMap::new();
        let mut need_quote: HashMap<[u8; 32], u64> = HashMap::new();

        // Taker's resting unfilled remainder requires escrow up-front (only for
        // a remainder the book actually took - see step 1/4):
        let rests_in_book = is_limit && unfilled > 0 && book.find_order(order.order_id).is_some();
        if rests_in_book {
            if taker_is_buyer {
                let q_escrow = Self::clob_quote_value(price, unfilled);
                let e = need_quote.entry(trader).or_insert(0);
                *e = e.saturating_add(q_escrow);
            } else {
                let e = need_base.entry(trader).or_insert(0);
                *e = e.saturating_add(unfilled);
            }
        }

        for t in &trades {
            let (buyer, seller) = if taker_is_buyer {
                (t.taker, t.maker)
            } else {
                (t.maker, t.taker)
            };
            if buyer == seller {
                continue; // self-trade: no net transfer
            }
            let q = Self::clob_quote_value(t.price, t.amount);
            if q == 0 {
                return Err("CLOB settlement: zero quote value (dust)".to_string());
            }

            // A maker's OWN escrow funds its side of the trade - but only if it
            // actually holds enough of the asset this leg pays in. The old
            // `contains_key` test was an all-or-nothing assumption that every
            // record was a wUSDT record: a BUY locked in native (the SVM path)
            // passed the check with `locked_quote_wusdt == 0`, and the apply
            // step then `saturating_sub`'d zero and MINTED the quote out of
            // nothing. Coverage is now per asset.
            if taker_is_buyer {
                // Taker is buyer -> taker pays quote from live balance:
                let e = need_quote.entry(buyer).or_insert(0);
                *e = e.saturating_add(q);
                // Maker is seller -> base escrow covers it, else live balance:
                match escrows.get(&(pair, t.maker_order_id)) {
                    Some(r) if r.locked_base_stell > 0 => {
                        if r.locked_base_stell < t.amount {
                            return Err(format!(
                                "CLOB settlement: escrow for order {} cannot fund the base leg",
                                t.maker_order_id
                            ));
                        }
                    }
                    _ => {
                        let e = need_base.entry(seller).or_insert(0);
                        *e = e.saturating_add(t.amount);
                    }
                }
            } else {
                // Taker is seller -> taker pays base from live balance:
                let e = need_base.entry(seller).or_insert(0);
                *e = e.saturating_add(t.amount);
                // Maker is buyer -> its quote escrow covers it (in whichever
                // asset it locked), else the maker needs live wUSDT:
                let qn = Self::clob_quote_native(t.price, t.amount);
                match escrows.get(&(pair, t.maker_order_id)) {
                    Some(r) if r.locked_quote_wusdt > 0 || r.locked_quote_native > 0 => {
                        let covers =
                            r.locked_quote_wusdt >= q || (qn > 0 && r.locked_quote_native >= qn);
                        if !covers {
                            return Err(format!(
                                "CLOB settlement: escrow for order {} cannot fund the quote leg",
                                t.maker_order_id
                            ));
                        }
                    }
                    _ => {
                        let e = need_quote.entry(buyer).or_insert(0);
                        *e = e.saturating_add(q);
                    }
                }
            }
        }
        drop(escrows);

        for (a, need) in &need_base {
            let bal = self.get_account(a).await.map(|x| x.balance).unwrap_or(0);
            if bal < *need {
                return Err(format!("CLOB settlement: seller {a:?} lacks base STELL"));
            }
        }
        for (a, need) in &need_quote {
            let bal = self.token_balance(&quote_id, a).await;
            if bal < *need {
                return Err(format!("CLOB settlement: buyer {a:?} lacks wUSDT"));
            }
        }

        // 2b) Mint-budget pre-validation (audit P0): every wUSDT Mint below
        // releases previously-locked escrow, and a mid-loop Mint refusal
        // (cap / paused / renounced minter) AFTER earlier legs applied is a
        // partial settlement (moved funds + escrow/book desync). Refuse the
        // whole settlement upfront when the quote token cannot cover it.
        // The bound is EXACT from above, never estimated: every Mint take is
        // bounded by the escrow record it releases (take <= locked), so the
        // sum of touched records' locked wUSDT bounds total mints. It can
        // only OVER-refuse (fat escrows near a tight cap) with a clear
        // error — the safe direction. Mirrors `cancel_order_settled`'s
        // pre-validation discipline.
        {
            let escrows = self.order_escrow.read().await;
            let mut touched_locked: u128 = 0;
            for t in &trades {
                if let Some(rec) = escrows.get(&(pair, t.maker_order_id)) {
                    touched_locked += rec.locked_quote_wusdt as u128;
                }
            }
            drop(escrows);
            let tokens = self.tokens_read().await;
            let tok = tokens
                .get(&quote_id)
                .ok_or_else(|| "CLOB settlement: quote (wUSDT) token missing".to_string())?;
            if tok.metadata.minter == [0u8; 32] {
                return Err(
                    "CLOB settlement: quote token minter renounced, escrow cannot release"
                        .to_string(),
                );
            }
            if tok.metadata.paused {
                return Err(
                    "CLOB settlement: quote token paused, escrow cannot release".to_string()
                );
            }
            if let Some(cap) = tok.metadata.max_supply {
                let supply = tok.metadata.total_supply as u128;
                if supply + touched_locked > cap as u128 {
                    return Err(format!(
                        "CLOB settlement: wUSDT mint budget exceeded (supply {supply} + locked {touched_locked} > cap {cap})"
                    ));
                }
            }
        }

        // 3) Apply settlement per trade and update/release maker escrows:
        let mut escrow_map = self.order_escrow_write().await;
        for t in &trades {
            let (buyer, seller) = if taker_is_buyer {
                (t.taker, t.maker)
            } else {
                (t.maker, t.taker)
            };

            // Self-trade: release maker's locked escrow back to self (net zero).
            // `min` rather than a plain subtraction: the fill can never consume
            // more than the record holds, and releasing exactly what it holds is
            // what keeps a drained record from outliving its order.
            if buyer == seller {
                let key = (pair, t.maker_order_id);
                if taker_is_buyer {
                    if let Some(rec) = escrow_map.get_mut(&key) {
                        let take = rec.locked_base_stell.min(t.amount);
                        rec.locked_base_stell -= take;
                        // Escrow RELEASE (the value was locked earlier): a
                        // transfer, never new issuance — the capped mint path
                        // would strand it at the supply cap.
                        self.credit_native_transfer(&buyer, take).await?;
                    }
                } else {
                    let q = Self::clob_quote_value(t.price, t.amount);
                    let qn = Self::clob_quote_native(t.price, t.amount);
                    let take_wusdt = escrow_map
                        .get(&key)
                        .map(|r| r.locked_quote_wusdt.min(q))
                        .unwrap_or(0);
                    if take_wusdt > 0 {
                        escrow_map.get_mut(&key).unwrap().locked_quote_wusdt -= take_wusdt;
                        let mut tokens = self.tokens_write().await;
                        let token_minter = tokens
                            .get(&quote_id)
                            .map(|tok| tok.metadata.minter)
                            .unwrap_or([0u8; 32]);
                        tokens
                            .execute(
                                &quote_id,
                                token_minter,
                                crate::token::TokenOp::Mint {
                                    to: buyer,
                                    amount: take_wusdt,
                                },
                            )
                            .map_err(|e| format!("CLOB escrow self-refund failed: {e}"))?;
                        let new_bal = tokens.balance_of(&quote_id, &buyer);
                        let mut trie = self.state_trie.write().await;
                        trie.insert(
                            &token_balance_key(&quote_id, &buyer),
                            &new_bal.to_be_bytes(),
                        );
                    } else if let Some(rec) = escrow_map.get_mut(&key) {
                        let take = rec.locked_quote_native.min(qn);
                        rec.locked_quote_native -= take;
                        self.credit_native_transfer(&buyer, take).await?;
                    }
                }
                if let Some(rec) = escrow_map.get(&(pair, t.maker_order_id)) {
                    if rec.locked_base_stell == 0
                        && rec.locked_quote_wusdt == 0
                        && rec.locked_quote_native == 0
                    {
                        escrow_map.remove(&(pair, t.maker_order_id));
                    }
                }
                continue;
            }

            let q = Self::clob_quote_value(t.price, t.amount);

            // Handle quote payment (buyer -> seller):
            let maker_key = (pair, t.maker_order_id);
            // Only a maker that IS the buyer can fund this leg from escrow.
            let maker_escrowed_quote = if !taker_is_buyer {
                escrow_map
                    .get(&maker_key)
                    .is_some_and(|r| r.locked_quote_wusdt > 0 || r.locked_quote_native > 0)
            } else {
                false
            };
            if maker_escrowed_quote {
                // Maker buyer: pay seller from maker's locked quote escrow, in
                // whichever asset that record actually holds.
                let qn = Self::clob_quote_native(t.price, t.amount);
                let paid_wusdt = escrow_map.get(&maker_key).unwrap().locked_quote_wusdt >= q;
                if paid_wusdt {
                    let rec = escrow_map.get_mut(&maker_key).unwrap();
                    rec.locked_quote_wusdt -= q;
                    // Credit seller with wUSDT using minter authority:
                    let mut tokens = self.tokens_write().await;
                    let token_minter = tokens
                        .get(&quote_id)
                        .map(|tok| tok.metadata.minter)
                        .unwrap_or([0u8; 32]);
                    tokens
                        .execute(
                            &quote_id,
                            token_minter,
                            crate::token::TokenOp::Mint {
                                to: seller,
                                amount: q,
                            },
                        )
                        .map_err(|e| format!("CLOB escrow quote release failed: {e}"))?;
                    let seller_qbal = tokens.balance_of(&quote_id, &seller);
                    let mut trie = self.state_trie.write().await;
                    trie.insert(
                        &token_balance_key(&quote_id, &seller),
                        &seller_qbal.to_be_bytes(),
                    );
                } else if qn > 0 && escrow_map.get(&maker_key).unwrap().locked_quote_native >= qn {
                    let rec = escrow_map.get_mut(&maker_key).unwrap();
                    rec.locked_quote_native -= qn;
                    self.credit_native_transfer(&seller, qn).await?;
                } else {
                    // The record exists but cannot fund this fill. Refusing is
                    // the only safe answer: paying from live balance would take
                    // coins the trader already locked, and minting would print.
                    return Err(format!(
                        "CLOB settlement: escrow for order {} cannot fund the quote leg",
                        t.maker_order_id
                    ));
                }
            } else {
                // Taker buyer: transfers quote directly to seller
                let mut tokens = self.tokens_write().await;
                tokens
                    .execute(
                        &quote_id,
                        buyer,
                        crate::token::TokenOp::Transfer {
                            to: seller,
                            amount: q,
                        },
                    )
                    .map_err(|e| format!("CLOB quote settlement failed: {e}"))?;
                let buyer_qbal = tokens.balance_of(&quote_id, &buyer);
                let seller_qbal = tokens.balance_of(&quote_id, &seller);
                let mut trie = self.state_trie.write().await;
                trie.insert(
                    &token_balance_key(&quote_id, &buyer),
                    &buyer_qbal.to_be_bytes(),
                );
                trie.insert(
                    &token_balance_key(&quote_id, &seller),
                    &seller_qbal.to_be_bytes(),
                );
            }

            // Handle base payment (seller -> buyer):
            let maker_escrowed_base = if taker_is_buyer {
                escrow_map
                    .get(&maker_key)
                    .is_some_and(|r| r.locked_base_stell >= t.amount)
            } else {
                false
            };
            if maker_escrowed_base {
                // Maker seller: pay buyer from maker's locked base escrow
                let rec = escrow_map.get_mut(&maker_key).unwrap();
                rec.locked_base_stell -= t.amount;
                // Credit buyer with native STELL from the maker's escrow: a
                // release of locked value, not issuance.
                self.credit_native_transfer(&buyer, t.amount).await?;
            } else {
                // Taker seller or non-escrowed maker: debit seller, credit
                // buyer — a pure transfer.
                self.debit_native(&seller, t.amount).await?;
                self.credit_native_transfer(&buyer, t.amount).await?;
            }

            // If maker escrow is completely exhausted, clean it up:
            if let Some(rec) = escrow_map.get(&maker_key) {
                if rec.locked_base_stell == 0
                    && rec.locked_quote_wusdt == 0
                    && rec.locked_quote_native == 0
                {
                    escrow_map.remove(&maker_key);
                }
            }
        }

        // 4) If taker's limit order has an unfilled RESTING part, lock it into escrow:
        if rests_in_book {
            if taker_is_buyer {
                let q_escrow = Self::clob_quote_value(price, unfilled);
                // Burn/lock wUSDT from taker into escrow:
                let mut tokens = self.tokens_write().await;
                tokens
                    .execute(
                        &quote_id,
                        trader,
                        crate::token::TokenOp::Burn {
                            from: trader,
                            amount: q_escrow,
                        },
                    )
                    .map_err(|e| format!("CLOB taker escrow lock failed: {e}"))?;
                let new_bal = tokens.balance_of(&quote_id, &trader);
                let mut trie = self.state_trie.write().await;
                trie.insert(
                    &token_balance_key(&quote_id, &trader),
                    &new_bal.to_be_bytes(),
                );
                drop(trie);
                drop(tokens);
                escrow_map.insert(
                    (pair, order.order_id),
                    EscrowRecord {
                        trader,
                        locked_base_stell: 0,
                        locked_quote_wusdt: q_escrow,
                        locked_quote_native: 0,
                    },
                );
            } else {
                // Lock native STELL from taker into escrow:
                self.debit_native(&trader, unfilled).await?;
                escrow_map.insert(
                    (pair, order.order_id),
                    EscrowRecord {
                        trader,
                        locked_base_stell: unfilled,
                        locked_quote_wusdt: 0,
                        locked_quote_native: 0,
                    },
                );
            }
        }
        drop(escrow_map);

        // 5) Commit the matched book.
        self.orderbooks_write().await.books.insert(pair, book);
        Ok((order.order_id, trades.len()))
    }

    /// Cancel an active resting order from the CLOB and refund all escrowed funds.
    pub async fn cancel_order_settled(
        &self,
        pair: u32,
        order_id: u64,
        caller: [u8; 32],
    ) -> Result<Option<crate::orderbook::Order>, String> {
        // ---- Refund pre-validation: NOTHING is removed until it is known that
        // the whole refund can be paid. The wUSDT leg is the fallible one (no
        // token configured, paused, capped, minter gone) and it used to be
        // attempted AFTER the escrow record had already been removed and the
        // native part credited - a refusal then stranded the wUSDT half.
        //
        // The token is only needed when there IS wUSDT to give back: a purely
        // native escrow (base collateral, or the SVM path's native-locked
        // quote) must be refundable on a chain that never configured wUSDT.
        let quote_id = *self.pmm_usdt_token.read().await;
        let wusdt_refund = self
            .order_escrow
            .read()
            .await
            .get(&(pair, order_id))
            .map(|r| r.locked_quote_wusdt)
            .unwrap_or(0);
        if wusdt_refund > 0 {
            let qid = quote_id.ok_or_else(|| "CLOB quote token not configured".to_string())?;
            // Dry-run against a throwaway copy of the registry.
            let mut probe = self.tokens.read().await.clone();
            let minter = probe
                .get(&qid)
                .map(|t| t.metadata.minter)
                .ok_or_else(|| "CLOB quote token not configured".to_string())?;
            probe
                .execute(
                    &qid,
                    minter,
                    crate::token::TokenOp::Mint {
                        to: caller,
                        amount: wusdt_refund,
                    },
                )
                .map_err(|e| format!("CLOB cancel refund would fail: {e}"))?;
        }

        let mut books = self.orderbooks_write().await;
        // Ownership is checked BEFORE the order is pulled from the book: the
        // book guard is the live map (not a clone), so a check after the
        // removal would delete a foreign order and return Err with its escrow
        // still locked - exactly the orphan the escrow exists to prevent.
        let owner = books
            .books
            .get(&pair)
            .and_then(|b| b.find_order(order_id))
            .map(|o| o.trader);
        match owner {
            None => return Ok(None),
            Some(t) if t != caller => {
                return Err("Only the order owner may cancel and claim refund".to_string())
            }
            Some(_) => {}
        }
        let Some(book) = books.books.get_mut(&pair) else {
            return Ok(None);
        };
        let Some(cancelled) = book.cancel_order(order_id) else {
            return Ok(None);
        };
        drop(books);

        // Refund escrow: whatever the record holds goes back to its owner, in
        // the asset it was locked in (base, wUSDT or the SVM path's native
        // quote). A record can only release what was deposited into it.
        if let Some(escrow) = self.order_escrow_write().await.remove(&(pair, order_id)) {
            if escrow.locked_base_stell > 0 || escrow.locked_quote_native > 0 {
                // Cancel refund: releasing escrowed value, not minting.
                self.credit_native_transfer(
                    &caller,
                    escrow
                        .locked_base_stell
                        .saturating_add(escrow.locked_quote_native),
                )
                .await?;
            }
            if escrow.locked_quote_wusdt > 0 {
                let qid = quote_id.ok_or_else(|| "CLOB quote token not configured".to_string())?;
                let mut tokens = self.tokens_write().await;
                let token_minter = tokens
                    .get(&qid)
                    .map(|tok| tok.metadata.minter)
                    .unwrap_or([0u8; 32]);
                tokens
                    .execute(
                        &qid,
                        token_minter,
                        crate::token::TokenOp::Mint {
                            to: caller,
                            amount: escrow.locked_quote_wusdt,
                        },
                    )
                    .map_err(|e| format!("CLOB cancel refund mint failed: {e}"))?;
                let new_bal = tokens.balance_of(&qid, &caller);
                drop(tokens);
                let mut trie = self.state_trie.write().await;
                trie.insert(&token_balance_key(&qid, &caller), &new_bal.to_be_bytes());
            }
        }

        Ok(Some(cancelled))
    }

    /// Planned native movement bookkeeping: `proj[addr]` is what the account is
    /// EXPECTED to hold once the whole plan is applied, seeded lazily from the
    /// live map. A debit that would take it below zero aborts the plan before
    /// anything has moved.
    fn plan_native_debit(
        proj: &mut HashMap<[u8; 32], i128>,
        live: &HashMap<[u8; 32], AccountState>,
        moves: &mut Vec<NativeMove>,
        addr: [u8; 32],
        amount: u64,
        what: &str,
    ) -> Result<(), String> {
        if amount == 0 {
            return Ok(());
        }
        let cur = proj
            .entry(addr)
            .or_insert_with(|| live.get(&addr).map(|a| a.balance as i128).unwrap_or(0));
        if *cur < amount as i128 {
            return Err(format!(
                "CLOB settlement: {what} {} holds {} and needs {amount}",
                hex::encode(&addr[..6]),
                (*cur).max(0)
            ));
        }
        *cur -= amount as i128;
        moves.push(NativeMove::Debit(addr, amount));
        Ok(())
    }

    fn plan_native_credit(
        proj: &mut HashMap<[u8; 32], i128>,
        live: &HashMap<[u8; 32], AccountState>,
        moves: &mut Vec<NativeMove>,
        addr: [u8; 32],
        amount: u64,
        what: &str,
    ) -> Result<(), String> {
        if amount == 0 {
            return Ok(());
        }
        let cur = proj
            .entry(addr)
            .or_insert_with(|| live.get(&addr).map(|a| a.balance as i128).unwrap_or(0));
        *cur += amount as i128;
        if *cur > u64::MAX as i128 {
            return Err(format!("CLOB settlement: {what} native balance overflow"));
        }
        moves.push(NativeMove::Credit(addr, amount));
        Ok(())
    }

    /// Apply a planned set of native movements under the accounts write lock.
    ///
    /// Failure is atomic: an undo log keyed by "the value BEFORE this leg" is
    /// walked newest-first, so an account touched twice returns to its original
    /// value rather than to an intermediate one, and no coin is left moved.
    /// Returns every touched account with its FINAL (balance, nonce) for the
    /// caller to write into the state trie, plus the pre-move snapshot
    /// (`None` = the account did not exist) for a later rollback by the
    /// caller if the enclosing transaction is refused after this leg.
    #[allow(clippy::type_complexity)]
    // GATE: move list mirrors account tuple layout used by commit and rollback.
    async fn apply_native_moves(
        &self,
        moves: &[NativeMove],
    ) -> Result<
        (
            Vec<([u8; 32], u64, u64)>,
            Vec<([u8; 32], Option<(u64, u64)>)>,
        ),
        String,
    > {
        if moves.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let mut map = self.accounts.write().await;
        let mut undo: Vec<([u8; 32], Option<(u64, u64)>)> = Vec::with_capacity(moves.len());
        let mut failure: Option<String> = None;
        for m in moves {
            let (addr, amount, is_debit) = match m {
                NativeMove::Debit(a, n) => (*a, *n, true),
                NativeMove::Credit(a, n) => (*a, *n, false),
            };
            undo.push((addr, map.get(&addr).map(|a| (a.balance, a.nonce))));
            if is_debit {
                match map.get_mut(&addr) {
                    None => {
                        failure = Some(format!(
                            "CLOB settlement: account {} does not exist",
                            hex::encode(&addr[..6])
                        ));
                        break;
                    }
                    Some(acc) if acc.balance < amount => {
                        failure = Some(format!(
                            "CLOB settlement: account {} has {} but must pay {amount}",
                            hex::encode(&addr[..6]),
                            acc.balance
                        ));
                        break;
                    }
                    Some(acc) => acc.balance -= amount,
                }
            } else {
                let acc = map
                    .entry(addr)
                    .or_insert_with(|| AccountState::new(addr, 0));
                match acc.balance.checked_add(amount) {
                    Some(v) => acc.balance = v,
                    None => {
                        failure = Some("CLOB settlement: native balance overflow".to_string());
                        break;
                    }
                }
            }
        }
        if let Some(e) = failure {
            for (addr, prev) in undo.iter().rev() {
                match prev {
                    Some((balance, nonce)) => {
                        if let Some(acc) = map.get_mut(addr) {
                            acc.balance = *balance;
                            acc.nonce = *nonce;
                        }
                    }
                    None => {
                        map.remove(addr);
                    }
                }
            }
            return Err(e);
        }

        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut out = Vec::new();
        for m in moves {
            let addr = match m {
                NativeMove::Debit(a, _) | NativeMove::Credit(a, _) => *a,
            };
            if seen.insert(addr) {
                if let Some(acc) = map.get(&addr) {
                    out.push((addr, acc.balance, acc.nonce));
                }
            }
        }
        // First-touch pre-state per account (an account moved twice restores
        // to its original, not to an intermediate value).
        let mut snap_seen: HashSet<[u8; 32]> = HashSet::new();
        let mut snapshot = Vec::new();
        for (addr, prev) in undo {
            if snap_seen.insert(addr) {
                snapshot.push((addr, prev));
            }
        }
        Ok((out, snapshot))
    }

    /// Settle the value side of the SVM's order syscalls: lock escrow for what
    /// rests, move funds for what filled, refund what was cancelled.
    ///
    /// This is the hand-off from `OpCode::SysCallPlaceOrder` /
    /// `SysCallCancelOrder` - which mutate the book inside the VM but can see
    /// neither accounts, nor tokens, nor the escrow map - to consensus state.
    /// It runs inside `execute_payload`, the execution point `apply_transaction`
    /// AND the live block path (`apply_block_parallel_fees`) both go through, so
    /// both apply the IDENTICAL settlement; `ctx.trades` (the fills the VM
    /// recorded) reach it as `ClobEvent::Place::trades`.
    ///
    /// ALL-OR-NOTHING. Everything is planned against private copies first (the
    /// escrow working map, the staged token registry, projected native
    /// balances) and the whole plan is validated before a single balance moves;
    /// only then are the native movements applied under the accounts write lock
    /// with an undo log and the staged copies committed. A refused settlement
    /// therefore changes nothing anywhere - the caller only has to roll the
    /// BOOK back, because the VM already committed that (see `execute_payload`).
    ///
    /// Quote conventions: `mode` decides what a TAKER pays out of its live
    /// balance (the SVM path pays native, because that is what its `order_cost`
    /// affordability check prices), while a MAKER's own escrow always releases
    /// the asset it actually locked - a record can never pay out an asset
    /// nobody deposited into it.
    ///
    /// `reserve_floor` is what the sender must still hold once the plan is
    /// applied - the admission reservation plus the payload's own transfers -
    /// so the lock cannot leave a transaction whose payload already committed
    /// but whose `commit_native` then fails. See the call site in
    /// `execute_payload`.
    #[allow(clippy::too_many_arguments)]
    // GATE: CLOB settlement needs full market context; splitting params risks mismatch.
    pub(super) async fn settle_clob_effects(
        &self,
        events: &[crate::orderbook::ClobEvent],
        mode: ClobQuoteMode,
        quote_id: Option<[u8; 32]>,
        tokens: &mut TokenRegistry,
        escrow: &mut HashMap<(u32, u64), EscrowRecord>,
        sender: [u8; 32],
        reserve_floor: u64,
        order_absent: impl Fn(u32, u64) -> bool,
    ) -> Result<Vec<([u8; 32], Option<(u64, u64)>)>, String> {
        use crate::orderbook::{ClobEvent, OrderSide, OrderType};

        // ---- Phase 1: plan on private copies, validate the whole plan -------
        let mut work = escrow.clone();
        let mut staged = tokens.clone();
        let mut native_moves: Vec<NativeMove> = Vec::new();
        let mut token_touched: HashSet<[u8; 32]> = HashSet::new();
        let mut supply_dirty = false;
        let qid = quote_id;
        let minter: Option<[u8; 32]> = qid.and_then(|q| staged.get(&q).map(|t| t.metadata.minter));

        let live = self.accounts.read().await;
        let mut proj: HashMap<[u8; 32], i128> = HashMap::new();

        // Defined after the plan state so the identifiers they mention resolve.
        macro_rules! debit {
            ($addr:expr, $amount:expr, $what:expr) => {
                Self::plan_native_debit(&mut proj, &live, &mut native_moves, $addr, $amount, $what)?
            };
        }
        macro_rules! credit {
            ($addr:expr, $amount:expr, $what:expr) => {
                Self::plan_native_credit(
                    &mut proj,
                    &live,
                    &mut native_moves,
                    $addr,
                    $amount,
                    $what,
                )?
            };
        }

        // One token operation against the staged registry. Failures here happen
        // during planning, so the real registry has not been touched yet.
        let mut tok_op = |caller: [u8; 32], op: TokenOp| -> Result<(), String> {
            let q = qid.ok_or_else(|| "CLOB settlement: quote token not configured".to_string())?;
            match &op {
                TokenOp::Transfer { to, .. } => {
                    token_touched.insert(caller);
                    token_touched.insert(*to);
                }
                TokenOp::Mint { to, .. } => {
                    token_touched.insert(*to);
                    supply_dirty = true;
                }
                TokenOp::Burn { from, .. } => {
                    token_touched.insert(*from);
                    supply_dirty = true;
                }
                _ => {}
            }
            staged
                .execute(&q, caller, op)
                .map_err(|e| format!("CLOB settlement: token op failed: {e}"))?;
            Ok(())
        };
        let minter_or_err = || -> Result<[u8; 32], String> {
            minter.ok_or_else(|| "CLOB settlement: quote token not configured".to_string())
        };

        for ev in events {
            match ev {
                ClobEvent::Place {
                    pair_id,
                    order_id,
                    trader,
                    side,
                    order_type,
                    price,
                    amount,
                    filled,
                    trades,
                } => {
                    let taker_is_buyer = matches!(side, OrderSide::Buy);
                    let maker_is_buyer = !taker_is_buyer;

                    for t in trades {
                        let mkey = (*pair_id, t.maker_order_id);
                        let (buyer, seller) = if taker_is_buyer {
                            (t.taker, t.maker)
                        } else {
                            (t.maker, t.taker)
                        };
                        // Snapshot taken before this trade mutates the record;
                        // the quote leg only touches a maker-BUYER record and
                        // the base leg only a maker-SELLER one, so the snapshot
                        // cannot go stale for the leg that reads it.
                        let maker_rec = work.get(&mkey).cloned();

                        // ---- Self-trade: both sides are the same account ----
                        // Nothing moves between parties, but the maker's escrow
                        // must still give back exactly what the fill consumed,
                        // or the record would outlive the order it secures.
                        if buyer == seller {
                            if let Some(rec) = work.get_mut(&mkey) {
                                if !maker_is_buyer {
                                    let take = rec.locked_base_stell.min(t.amount);
                                    rec.locked_base_stell -= take;
                                    credit!(buyer, take, "self-trade escrow refund");
                                } else if rec.locked_quote_wusdt > 0 {
                                    let q = ClobQuoteMode::Wusdt.quote(t.price, t.amount);
                                    let take = rec.locked_quote_wusdt.min(q);
                                    rec.locked_quote_wusdt -= take;
                                    tok_op(
                                        minter_or_err()?,
                                        TokenOp::Mint {
                                            to: buyer,
                                            amount: take,
                                        },
                                    )?;
                                } else {
                                    let qn = ClobQuoteMode::NativeSvm.quote(t.price, t.amount);
                                    let take = rec.locked_quote_native.min(qn);
                                    rec.locked_quote_native -= take;
                                    credit!(buyer, take, "self-trade escrow refund");
                                }
                            }
                            if work.get(&mkey).is_some_and(|r| {
                                r.locked_base_stell == 0
                                    && r.locked_quote_wusdt == 0
                                    && r.locked_quote_native == 0
                            }) {
                                work.remove(&mkey);
                            }
                            continue;
                        }

                        // ---- Quote leg: buyer pays seller ----
                        let q_wusdt = ClobQuoteMode::Wusdt.quote(t.price, t.amount);
                        let q_native = ClobQuoteMode::NativeSvm.quote(t.price, t.amount);
                        let maker_escrowed_quote = maker_is_buyer
                            && maker_rec.as_ref().is_some_and(|r| {
                                r.locked_quote_wusdt > 0 || r.locked_quote_native > 0
                            });
                        let pays_wusdt = if maker_escrowed_quote {
                            let r = maker_rec.as_ref().unwrap();
                            if r.locked_quote_wusdt >= q_wusdt {
                                true
                            } else if q_native > 0 && r.locked_quote_native >= q_native {
                                false
                            } else {
                                return Err(format!(
                                    "CLOB settlement: escrow for order {} cannot fund the quote leg",
                                    t.maker_order_id
                                ));
                            }
                        } else {
                            matches!(mode, ClobQuoteMode::Wusdt)
                        };
                        let q = if pays_wusdt { q_wusdt } else { q_native };
                        if q == 0 {
                            return Err("CLOB settlement: zero quote value (dust)".to_string());
                        }
                        if maker_escrowed_quote {
                            if pays_wusdt {
                                work.get_mut(&mkey).unwrap().locked_quote_wusdt -= q;
                                tok_op(
                                    minter_or_err()?,
                                    TokenOp::Mint {
                                        to: seller,
                                        amount: q,
                                    },
                                )?;
                            } else {
                                work.get_mut(&mkey).unwrap().locked_quote_native -= q;
                                credit!(seller, q, "escrow quote release");
                            }
                        } else if pays_wusdt {
                            tok_op(
                                buyer,
                                TokenOp::Transfer {
                                    to: seller,
                                    amount: q,
                                },
                            )?;
                        } else {
                            debit!(buyer, q, "buyer");
                            credit!(seller, q, "quote settlement");
                        }

                        // ---- Base leg: seller pays buyer ----
                        let maker_escrowed_base = taker_is_buyer
                            && maker_rec.as_ref().is_some_and(|r| r.locked_base_stell > 0);
                        if maker_escrowed_base {
                            let r = maker_rec.as_ref().unwrap();
                            if r.locked_base_stell < t.amount {
                                return Err(format!(
                                    "CLOB settlement: escrow for order {} cannot fund the base leg",
                                    t.maker_order_id
                                ));
                            }
                            work.get_mut(&mkey).unwrap().locked_base_stell -= t.amount;
                            credit!(buyer, t.amount, "escrow base release");
                        } else {
                            debit!(seller, t.amount, "seller");
                            credit!(buyer, t.amount, "base settlement");
                        }

                        // Drop a record the fills have drained.
                        if work.get(&mkey).is_some_and(|r| {
                            r.locked_base_stell == 0
                                && r.locked_quote_wusdt == 0
                                && r.locked_quote_native == 0
                        }) {
                            work.remove(&mkey);
                        }
                    }

                    // ---- Lock what rests, exactly as place_order_settled does.
                    // The book the VM committed decides whether anything rests:
                    // a fully filled order holds nothing, and an order the book
                    // refused (depth saturation) must not be locked either, or
                    // its escrow would be unreachable by construction.
                    let unfilled = amount.saturating_sub(*filled);
                    if matches!(order_type, OrderType::Limit)
                        && unfilled > 0
                        && !order_absent(*pair_id, *order_id)
                    {
                        let rec =
                            work.entry((*pair_id, *order_id))
                                .or_insert_with(|| EscrowRecord {
                                    trader: *trader,
                                    locked_base_stell: 0,
                                    locked_quote_wusdt: 0,
                                    locked_quote_native: 0,
                                });
                        if taker_is_buyer {
                            let q = mode.quote(*price, unfilled);
                            if q > 0 {
                                debit!(*trader, q, "buyer escrow lock");
                                match mode {
                                    ClobQuoteMode::Wusdt => {
                                        rec.locked_quote_wusdt =
                                            rec.locked_quote_wusdt.saturating_add(q)
                                    }
                                    ClobQuoteMode::NativeSvm => {
                                        rec.locked_quote_native =
                                            rec.locked_quote_native.saturating_add(q)
                                    }
                                }
                            }
                        } else {
                            debit!(*trader, unfilled, "seller escrow lock");
                            rec.locked_base_stell = rec.locked_base_stell.saturating_add(unfilled);
                        }
                    }
                }
                ClobEvent::Cancel {
                    pair_id,
                    order_id,
                    trader,
                } => {
                    // The syscall removed the order from its clone of the book,
                    // and that clone is what got committed: if it is somehow
                    // still resting, refunding would hand back funds that are
                    // still collateralising an order anyone can match against.
                    if !order_absent(*pair_id, *order_id) {
                        return Err(format!(
                            "CLOB settlement: cancelled order {} is still in the book",
                            order_id
                        ));
                    }
                    if let Some(rec) = work.remove(&(*pair_id, *order_id)) {
                        let native = rec
                            .locked_base_stell
                            .saturating_add(rec.locked_quote_native);
                        credit!(*trader, native, "cancel refund");
                        if rec.locked_quote_wusdt > 0 {
                            tok_op(
                                minter_or_err()?,
                                TokenOp::Mint {
                                    to: *trader,
                                    amount: rec.locked_quote_wusdt,
                                },
                            )?;
                        }
                    }
                }
            }
        }
        // The escrow lock must never eat the transaction's own reservation.
        // `commit_native` runs AFTER this settlement and demands
        // `amount + declared gas limit + payload transfers` from the sender; if
        // the lock took any of it, the payload effects would already be
        // committed while the native commit refuses - and the two apply paths
        // would disagree about that, because they charge different fee numbers.
        // Requiring the stricter (block-path) reservation here makes the
        // transaction succeed or fail as a whole, identically on both.
        let sender_after = proj
            .get(&sender)
            .copied()
            .unwrap_or_else(|| live.get(&sender).map(|a| a.balance as i128).unwrap_or(0));
        if sender_after < reserve_floor as i128 {
            return Err(format!(
                "CLOB settlement: the sender would keep {} of the {reserve_floor} reserved for the transfer and the fee",
                sender_after.max(0)
            ));
        }

        drop(live);

        // ---- Phase 2: commit the plan -------------------------------------
        // 1) Native first: it is the only leg that can still fail (everything
        //    else was validated against a private copy and is infallible).
        //    The snapshot is the caller's undo record if the enclosing
        //    transaction is refused after this leg (same shape and purpose as
        //    `pmm_native_snapshot`).
        let (touched, clob_snapshot) = self.apply_native_moves(&native_moves).await?;
        // 2) Staged copies become the truth.
        *tokens = staged;
        *escrow = work;
        // 3) Trie writes. Nothing below can fail.
        let mut trie = self.state_trie.write().await;
        if let Some(q) = qid {
            for acct in &token_touched {
                let bal = tokens.balance_of(&q, acct);
                let key = token_balance_key(&q, acct);
                if bal == 0 {
                    trie.remove(&key);
                } else {
                    trie.insert(&key, &bal.to_be_bytes());
                }
            }
            if supply_dirty {
                if let Some(supply) = tokens.get(&q).map(|t| t.metadata.total_supply) {
                    trie.insert(&token_supply_key(&q), &supply.to_be_bytes());
                }
            }
        }
        let entries: Vec<([u8; 32], Vec<u8>)> = {
            let map = self.accounts.read().await;
            touched
                .into_iter()
                .map(|(addr, balance, nonce)| {
                    let data = if let Some(acc) = map.get(&addr) {
                        acc.to_trie_bytes()
                    } else {
                        let mut data = Vec::with_capacity(16);
                        data.extend_from_slice(&balance.to_be_bytes());
                        data.extend_from_slice(&nonce.to_be_bytes());
                        data
                    };
                    (addr, data)
                })
                .collect()
        };
        for (addr, data) in entries {
            trie.insert(&addr, &data);
        }
        Ok(clob_snapshot)
    }

    // ==================== Primary Market Maker (on-chain) ====================

    /// Read-only snapshot of the PMM for RPC (`stell_pmmState`).
    ///
    /// Returns `(curve, quote token id, treasury)`. The governed buffer is NOT
    /// part of this: it lives in governance (`stell_governanceParams`), so a
    /// reader sees the parameter and the curve separately rather than a
    /// possibly-stale copy of it baked into the PMM.
    pub async fn pmm_state(&self) -> (crate::pmm::PrimaryMarketMaker, Option<[u8; 32]>, [u8; 32]) {
        let pmm = self.pmm.read().await.clone();
        let usdt = *self.pmm_usdt_token.read().await;
        let treasury = *self.pmm_treasury.read().await;
        (pmm, usdt, treasury)
    }

    /// Register the bridged-USDT token used by the PMM as its quote asset and
    /// seed the reserve. Must be called once at genesis.
    ///
    /// SECURITY: idempotent-guarded — once initialised the quote token cannot be
    /// re-pointed, otherwise anyone could swap in a token they control (and thus
    /// mint the redemption payouts) after genesis.
    pub async fn pmm_init_usdt(&self, usdt_token_id: [u8; 32], reserve_micro: u64) {
        if self.pmm_usdt_token.read().await.is_some() {
            return;
        }
        // The wUSDT minter is the PMM treasury: redemptions mint wUSDT payouts
        // (purchases burn the buyer's wUSDT), so mint authority must belong to
        // the system PMM and never to a user account.
        let minter = self
            .tokens
            .read()
            .await
            .get(&usdt_token_id)
            .map(|t| t.metadata.minter)
            .unwrap_or([0u8; 32]);
        *self.pmm_treasury_write().await = minter;

        let mut pmm = self.pmm_write().await;
        *pmm = crate::pmm::PrimaryMarketMaker::with_reserve(reserve_micro);
        *self.pmm_usdt_token_write().await = Some(usdt_token_id);
    }

    /// Buy STELL with `usdt_micro` wUSDT. Atomically: debit the buyer's wUSDT
    /// (committed to the trie), advance the curve, mint native STELL to the
    /// buyer (committed to the trie). All-or-nothing.
    pub async fn pmm_buy(
        &self,
        buyer: [u8; 32],
        usdt_micro: u64,
    ) -> Result<crate::pmm::BuyReceipt, String> {
        // ATOMIC PMM TRANSITION: hold the op mutex across read-clone-commit so
        // two concurrent calls cannot both pass the reserve/supply check
        // against the same clone (reproduced reserve-cap violation; see
        // `pmm_op` in `state_engine/mod.rs`).
        let _pmm_op = self.pmm_op.lock().await;
        let usdt_id = self
            .pmm_usdt_token
            .read()
            .await
            .ok_or_else(|| "PMM USDT token not initialised".to_string())?;

        // 1. Dry-run the bonding curve on a clone so a rejected buy (dust /
        //    reserve / overflow) can never mutate state or move user funds.
        //    The buffer share comes from governance, read once here so the
        //    direct call path prices exactly like `SysCallPmmBuy` does inside
        //    a block (both read `applied.pmm_redemption_buffer_bps`, both fall
        //    back to the protocol default when nothing has been passed).
        let (trial_pmm, receipt) = {
            let buffer_bps = self
                .governance
                .read()
                .await
                .applied
                .pmm_redemption_buffer_bps
                .unwrap_or(crate::pmm::PMM_REDEMPTION_BUFFER_BPS);
            let pmm = self.pmm.read().await;
            let mut trial = pmm.clone();
            let receipt = trial
                .buy_with_buffer(usdt_micro, buffer_bps)
                .map_err(|e| e.to_string())?;
            (trial, receipt)
        };

        // 2. Debit (burn) the buyer's wUSDT via the token CEI path + trie sync.
        {
            let mut tokens = self.tokens_write().await;
            let bal = tokens.balance_of(&usdt_id, &buyer);
            if bal < usdt_micro {
                return Err("Insufficient wUSDT balance for PMM buy".to_string());
            }
            tokens
                .execute(
                    &usdt_id,
                    buyer,
                    crate::token::TokenOp::Burn {
                        from: buyer,
                        amount: usdt_micro,
                    },
                )
                .map_err(|e| format!("wUSDT debit failed: {e}"))?;
            let new_bal = tokens.balance_of(&usdt_id, &buyer);
            let mut trie = self.state_trie.write().await;
            let key = token_balance_key(&usdt_id, &buyer);
            if new_bal == 0 {
                trie.remove(&key);
            } else {
                trie.insert(&key, &new_bal.to_be_bytes());
            }
        }

        // 3. Mint native STELL to the buyer. If the credit fails (overflow),
        //    refund the burned wUSDT (as the minter) so the buy is all-or-nothing.
        if let Err(e) = self.credit_native(&buyer, receipt.stell_minted).await {
            let treasury = *self.pmm_treasury.read().await;
            let mut tokens = self.tokens_write().await;
            let _ = tokens.execute(
                &usdt_id,
                treasury,
                crate::token::TokenOp::Mint {
                    to: buyer,
                    amount: usdt_micro,
                },
            );
            return Err(e);
        }

        // 4. Commit the advanced curve only after every value movement succeeded.
        *self.pmm_write().await = trial_pmm;
        Ok(receipt)
    }

    /// Sell `stell_nano` STELL back to the PMM for wUSDT. Atomically: debit
    /// native STELL from the seller, pay out wUSDT bounded by the ring-fenced
    /// usable reserve. Refunds native STELL if the curve rejects the sale.
    pub async fn pmm_sell(
        &self,
        seller: [u8; 32],
        stell_nano: u64,
    ) -> Result<crate::pmm::SellReceipt, String> {
        // ATOMIC PMM TRANSITION: hold the op mutex across read-clone-commit so
        // two concurrent calls cannot both pass the reserve/supply check
        // against the same clone (reproduced reserve-cap violation; see
        // `pmm_op` in `state_engine/mod.rs`).
        let _pmm_op = self.pmm_op.lock().await;
        let usdt_id = self
            .pmm_usdt_token
            .read()
            .await
            .ok_or_else(|| "PMM USDT token not initialised".to_string())?;

        // 1. Dry-run the bonding curve on a clone so a rejected sell (dust /
        //    insufficient reserve) never debits the seller.
        let (trial_pmm, receipt) = {
            let pmm = self.pmm.read().await;
            let mut trial = pmm.clone();
            let receipt = trial.sell_stell(stell_nano).map_err(|e| e.to_string())?;
            (trial, receipt)
        };

        // 2. Debit native STELL from the seller (must have it).
        self.debit_native(&seller, stell_nano).await?;

        // 3. Pay wUSDT out of the PMM treasury — the wUSDT MINTER. The seller is
        //    NOT the minter, so the payout must be issued by the system treasury;
        //    otherwise the mint is rejected and the seller's STELL would be lost.
        //    If the payout cannot be minted, refund the native STELL (all-or-nothing).
        let treasury = *self.pmm_treasury.read().await;
        let paid = {
            let mut tokens = self.tokens_write().await;
            match tokens.execute(
                &usdt_id,
                treasury,
                crate::token::TokenOp::Mint {
                    to: seller,
                    amount: receipt.usdt_paid,
                },
            ) {
                Ok(_) => {
                    let new_bal = tokens.balance_of(&usdt_id, &seller);
                    let mut trie = self.state_trie.write().await;
                    trie.insert(
                        &token_balance_key(&usdt_id, &seller),
                        &new_bal.to_be_bytes(),
                    );
                    true
                }
                Err(_) => false,
            }
        };
        if !paid {
            // REFUND of the seller's already-debited STELL: a transfer, never a
            // mint (the capped path would strand the money at the supply cap).
            if let Err(e) = self.credit_native_transfer(&seller, stell_nano).await {
                tracing::error!(
                    "PMM sell: wUSDT payout failed AND the STELL refund failed for {}: {e}",
                    hex::encode(&seller[..8])
                );
            }
            return Err("wUSDT payout failed (PMM treasury lacks minter authority)".to_string());
        }

        // 4. Commit the advanced curve only after the payout succeeded.
        *self.pmm_write().await = trial_pmm;
        Ok(receipt)
    }

    /// Apply the native half of a PMM swap: mint STELL to buyers, burn it from
    /// sellers, and commit every touched account to the state trie.
    ///
    /// SUPPLY CAP (audit F5): every `Buy` is NEW issuance and reserves its
    /// `stell_minted` against the engine's global counter
    /// ([`InMemoryStateEngine::reserve_mint`]) BEFORE a single balance is
    /// written. At the cap the whole swap is refused (the payload does not
    /// apply, exactly like a direct `pmm_buy`), so the block path can no longer
    /// mint past `TOTAL_SUPPLY_CAP`. Sells move existing value and are never
    /// capped. The returned `u64` is the reservation the caller must release if
    /// a LATER leg of the same payload fails (see [`Self::restore_pmm_native`]).
    ///
    /// Validation runs BEFORE any write, so a refusal - an unaffordable sell,
    /// an overflowing buy, a swap that would eat the transaction's own
    /// `amount + gas + payload transfers` reservation, or a buy past the global
    /// supply cap - moves no coins at all.
    /// Returns the pre-swap snapshot (`None` = the account did not exist),
    /// which is what a failure later in the SAME payload needs in order to
    /// undo exactly this and nothing else (created accounts are removed, not
    /// zeroed, mirroring `commit_native`'s own undo).
    #[allow(clippy::type_complexity)]
    // GATE: PMM snapshot mirrors account tuple layout shared with commit path.
    pub(super) async fn settle_pmm_native(
        &self,
        events: &[crate::pmm::PmmEvent],
        payer: [u8; 32],
        floor: u64,
    ) -> Result<(Vec<([u8; 32], Option<(u64, u64)>)>, u64), String> {
        // Net native delta per account. Every PMM syscall acts on
        // `ctx.sender`, so in practice this is one entry, but the map keeps
        // the code correct if that ever changes. `minted_nano` is the GROSS
        // buy side: a burn does not restore headroom (the counter is gross
        // lifetime emission), so buy->sell in one payload still reserves the
        // buy exactly once.
        let mut delta: HashMap<[u8; 32], i128> = HashMap::new();
        let mut minted_nano: u64 = 0;
        for ev in events {
            let (addr, d) = match ev {
                crate::pmm::PmmEvent::Buy {
                    buyer,
                    stell_minted,
                    ..
                } => {
                    minted_nano = minted_nano
                        .checked_add(*stell_minted)
                        .ok_or_else(|| "PMM settlement: buy amount overflows u64".to_string())?;
                    (*buyer, *stell_minted as i128)
                }
                crate::pmm::PmmEvent::Sell {
                    seller, stell_nano, ..
                } => (*seller, -(*stell_nano as i128)),
            };
            *delta.entry(addr).or_insert(0) += d;
        }

        // Capture the pre-mint genesis baseline BEFORE the write lock: the
        // helper only reads the account set while the counter is still zero.
        let genesis_nano = self.genesis_allocation_nano().await;
        let mut map = self.accounts.write().await;

        // Pass 1: validate against one consistent view of the balances.
        let mut snapshot: Vec<([u8; 32], Option<(u64, u64)>)> = Vec::with_capacity(delta.len());
        for (addr, d) in &delta {
            let prev = map.get(addr).map(|a| (a.balance, a.nonce));
            let bal = prev.map(|(b, _)| b).unwrap_or(0);
            let after = (bal as i128) + *d;
            if after < 0 || after > u64::MAX as i128 {
                return Err(format!(
                    "PMM settlement: {} would hold {after} nano-STELL after the swap",
                    hex::encode(&addr[..6])
                ));
            }
            snapshot.push((*addr, prev));
        }
        // The swap may not eat what `commit_native` still has to charge for
        // this transaction - otherwise the transaction is refused AFTER the
        // coins moved. Only checked when the swap actually touches the payer
        // (and only where nothing else re-checks it: the escrow settlement
        // asserts the same floor for payloads that carry order syscalls).
        if delta.contains_key(&payer) {
            let after = map.get(&payer).map(|a| a.balance).unwrap_or(0) as i128
                + delta.get(&payer).copied().unwrap_or(0);
            if after < floor as i128 {
                return Err(format!(
                    "PMM swap would leave {after} nano-STELL, {floor} is reserved for amount + gas + payload transfers"
                ));
            }
        }

        // Supply cap BEFORE any balance write, under the SAME accounts lock as
        // the validation and the apply: a buy is issuance. A refusal moves
        // nothing (the map is still untouched) and the reservation is a pure
        // atomic CAS, so no lock ordering issue arises.
        if minted_nano > 0 {
            self.reserve_mint_nano(minted_nano, genesis_nano)
                .map_err(|e| format!("PMM settlement: {e}"))?;
        }

        // Pass 2: apply, then mirror into the trie in the same order
        // `credit_native`/`debit_native` do it, so the account map and the
        // state root never disagree about the swap.
        let mut touched: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(delta.len());
        for (addr, d) in &delta {
            let acc = map
                .entry(*addr)
                .or_insert_with(|| AccountState::new(*addr, 0));
            acc.balance = ((acc.balance as i128) + *d) as u64;
            touched.push((*addr, acc.to_trie_bytes()));
        }
        drop(map);

        let mut trie = self.state_trie.write().await;
        for (addr, data) in touched {
            trie.insert(&addr, &data);
        }
        Ok((snapshot, minted_nano))
    }

    /// Put back the native balances [`Self::settle_pmm_native`] moved, undoing
    /// the swap exactly. Called only when something AFTER the swap fails
    /// (the escrow settlement), where the swap must not survive a payload that
    /// is being rejected. Reverts in the VM never reach here: clone-commit
    /// already discarded them. Accounts the swap created (`None` pre-state)
    /// are removed with their trie entries, mirroring `commit_native`.
    #[allow(clippy::type_complexity)]
    // GATE: restore snapshot mirrors account tuple layout used across legs.
    pub(super) async fn restore_pmm_native(&self, snapshot: &[([u8; 32], Option<(u64, u64)>)]) {
        if snapshot.is_empty() {
            return;
        }
        let mut map = self.accounts.write().await;
        let mut touched: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(snapshot.len());
        let mut removed: Vec<[u8; 32]> = Vec::new();
        for (addr, prev) in snapshot.iter().rev() {
            match prev {
                Some((balance, nonce)) => {
                    if let Some(acc) = map.get_mut(addr) {
                        acc.balance = *balance;
                        acc.nonce = *nonce;
                        touched.push((*addr, acc.to_trie_bytes()));
                    }
                }
                None => {
                    map.remove(addr);
                    removed.push(*addr);
                }
            }
        }
        drop(map);

        let mut trie = self.state_trie.write().await;
        for (addr, data) in touched {
            trie.insert(&addr, &data);
        }
        for addr in removed {
            trie.remove(&addr);
        }
    }

    /// Put back the native balances [`Self::settle_clob_effects`] moved
    /// (Phase 2 `apply_native_moves`). Same shape and same rule as
    /// [`Self::restore_pmm_native`]: the CLOB leg settled last, so on a later
    /// `commit_native` refusal its snapshot is restored with the other legs
    /// via [`Self::rollback_payload`]. Created accounts are removed, not zeroed.
    #[allow(clippy::type_complexity)]
    // GATE: restore snapshot mirrors account tuple layout used across legs.
    pub(super) async fn restore_clob_native(&self, snapshot: &[([u8; 32], Option<(u64, u64)>)]) {
        self.restore_pmm_native(snapshot).await;
    }

    /// Apply the native half of one transaction's bridge intents AND the §8
    /// policy that gates them: relayer/validator quorum + source-tx replay for
    /// a deposit, the hourly rate limit and the time-lock for a withdrawal,
    /// maturity for a release.
    ///
    /// POLICY FIRST: [`crate::bridge::BridgeState::plan`] runs the intent list
    /// against the COMMITTED domain (pure - it writes nothing) using the
    /// `TeleportBridgeEngine` rules, so the live verdict cannot drift from the
    /// offline model. Only then does the coin half run, in the
    /// [`Self::settle_pmm_native`] shape: one consistent snapshot of the
    /// balances, a validation pass that moves nothing, an apply pass that
    /// mirrors every write into the trie, and finally the planned domain
    /// (replay set, queue, rate window, refreshed escrow mirror) under
    /// `bridge_write`. A refusal anywhere - sub-quorum, replayed source tx, a
    /// rate-limit breach, a time-locked release, or a withdrawal that would
    /// leave the payer below `floor` (the transaction's own `amount + gas +
    /// payload transfers`) - returns `Err` with NOTHING written.
    ///
    /// `now` is the BLOCK timestamp (PROTOCOL.md I12 - never a wall clock) and
    /// `validators` is the committed staking set the quorum counts DISTINCT
    /// signers from. An empty set fails closed: `plan` refuses deposits rather
    /// than computing a 2/3 threshold of zero.
    ///
    /// `Ok(None)` means no intent moved anything (a payload carrying only
    /// attestations), so there is nothing to restore later. `Ok(Some(_))`
    /// carries the pre-change accounts AND pre-change domain for rollback by a
    /// failure after this point.
    #[allow(clippy::type_complexity)]
    // GATE: bridge snapshot mirrors account tuple layout shared with commit path.
    pub(super) async fn settle_bridge_native(
        &self,
        intents: &[crate::bridge::BridgeIntent],
        payer: [u8; 32],
        floor: u64,
        now: u64,
        validators: &[[u8; 32]],
    ) -> Result<Option<BridgeSnapshot>, String> {
        // Policy pass: clone the committed domain, plan against it, write
        // nothing. Refusals here leave the accounts AND the domain untouched.
        let before = self.bridge.read().await.clone();
        let plan = before.plan(intents, validators, payer, now)?;
        if plan.effects.is_empty() && plan.state == before {
            // Nothing a block could commit (a payload with only attestations
            // is not state): no write guard, no generation bump, no movement.
            return Ok(None);
        }
        if plan.effects.is_empty() {
            // A policy-only state change: a RELEASE finalizes a parked
            // withdrawal (queue entry flips to executed) and moves no coins,
            // so there is no account pass - but the domain change IS consensus
            // state and must land (or a later failure must be able to undo it).
            let mut domain = self.bridge_write().await;
            *domain = plan.state;
            return Ok(Some(BridgeSnapshot {
                accounts: Vec::new(),
                domain: before,
                minted_nano: 0,
            }));
        }

        let mut delta: HashMap<[u8; 32], i128> = HashMap::new();
        // NEW issuance this settlement creates: every `Credit` is a deposit
        // mint (gross), never a move of existing value. `Unpark`/`Clawback`/
        // `Park` move value between the recipient/escrow and `Burn` destroys
        // escrowed funds, so none of them is counted here.
        let mut minted_nano: u64 = 0;
        for effect in &plan.effects {
            match effect {
                crate::bridge::BridgeEffect::Credit { recipient, amount } => {
                    minted_nano = minted_nano.checked_add(*amount).ok_or_else(|| {
                        "bridge settlement: credit amount overflows u64".to_string()
                    })?;
                    *delta.entry(*recipient).or_insert(0) += *amount as i128;
                }
                crate::bridge::BridgeEffect::Park { amount } => {
                    // The payer default keeps the map correct if a future
                    // caller allows a different sender.
                    *delta.entry(payer).or_insert(0) -= *amount as i128;
                    *delta.entry(crate::bridge::BRIDGE_ESCROW).or_insert(0) += *amount as i128;
                }
                crate::bridge::BridgeEffect::Unpark { recipient, amount } => {
                    // Refund (F-G): escrow back to the original depositor.
                    // Escrow sufficiency is enforced in Pass 1 below like
                    // every other debit (an underfunded escrow fails the
                    // whole tx — fail closed, never partial).
                    *delta.entry(crate::bridge::BRIDGE_ESCROW).or_insert(0) -= *amount as i128;
                    *delta.entry(*recipient).or_insert(0) += *amount as i128;
                }
                crate::bridge::BridgeEffect::Clawback { account, amount } => {
                    // Challenge: pull the credited funds back into escrow.
                    // Pass 1 below fails the whole tx if the account already
                    // moved them (after < 0) — fail closed, never partial.
                    *delta.entry(*account).or_insert(0) -= *amount as i128;
                    *delta.entry(crate::bridge::BRIDGE_ESCROW).or_insert(0) += *amount as i128;
                }
                crate::bridge::BridgeEffect::Burn { amount } => {
                    // Revoke: destroy escrowed funds (deflationary). Pass 1
                    // fails the whole tx if escrow cannot cover it — a burn
                    // of thin air is refused, never rounded to zero.
                    *delta.entry(crate::bridge::BRIDGE_ESCROW).or_insert(0) -= *amount as i128;
                }
            }
        }

        // Capture the pre-mint genesis baseline BEFORE the write lock: the
        // helper only reads the account set while the counter is still zero.
        let genesis_nano = self.genesis_allocation_nano().await;
        let mut map = self.accounts.write().await;

        // Pass 1: validate against one consistent view of the balances.
        let mut snapshot: Vec<([u8; 32], Option<(u64, u64)>)> = Vec::with_capacity(delta.len());
        for (addr, d) in &delta {
            let prev = map.get(addr).map(|a| (a.balance, a.nonce));
            let bal = prev.map(|(b, _)| b).unwrap_or(0);
            let after = (bal as i128) + *d;
            if after < 0 || after > u64::MAX as i128 {
                return Err(format!(
                    "bridge settlement: {} would hold {after} nano-STELL after the transfer",
                    hex::encode(&addr[..6])
                ));
            }
            snapshot.push((*addr, prev));
        }
        if delta.contains_key(&payer) {
            let after = map.get(&payer).map(|a| a.balance).unwrap_or(0) as i128
                + delta.get(&payer).copied().unwrap_or(0);
            if after < floor as i128 {
                return Err(format!(
                    "bridge withdrawal would leave {after} nano-STELL, {floor} is reserved for amount + gas + payload transfers"
                ));
            }
        }

        // GLOBAL SUPPLY CAP (audit F1): a deposit mint is issuance exactly like
        // `mint_native`, so reserve its gross amount under the same accounts
        // lock as the validation and the apply. The bridge's LOCAL caps
        // (`note_deposit_mint`: hourly window + 100M cumulative) are the first
        // line; THIS reservation bounds the sum across every subsystem.
        // Refusal moves nothing: the map is still untouched and the planned
        // domain (replay set, queue, rate window) was never committed.
        if minted_nano > 0 {
            self.reserve_mint_nano(minted_nano, genesis_nano)
                .map_err(|e| format!("bridge settlement: {e}"))?;
        }

        // Pass 2: apply, then mirror the trie so the account map and the state
        // root never disagree.
        let mut touched: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(delta.len());
        for (addr, d) in &delta {
            let acc = map
                .entry(*addr)
                .or_insert_with(|| AccountState::new(*addr, 0));
            acc.balance = ((acc.balance as i128) + *d) as u64;
            touched.push((*addr, acc.to_trie_bytes()));
        }
        // Refresh the committed escrow mirror from the account that is the
        // authority for it, so the digest and the trie can never disagree
        // about how much the bridge has parked.
        let mut state = plan.state;
        state.escrow_balance = map
            .get(&crate::bridge::BRIDGE_ESCROW)
            .map(|a| a.balance)
            .unwrap_or(0);
        drop(map);

        // Commit the policy state (replay set, queue, rate window, mirror).
        // Written under `mut_guard` so `commitment_generation` moves and the
        // very next root read folds it into the digest.
        {
            let mut domain = self.bridge_write().await;
            *domain = state;
        }

        let mut trie = self.state_trie.write().await;
        for (addr, data) in touched {
            trie.insert(&addr, &data);
        }
        Ok(Some(BridgeSnapshot {
            accounts: snapshot,
            domain: before,
            minted_nano,
        }))
    }

    /// Put back what [`Self::settle_bridge_native`] moved: the native balances
    /// AND the committed bridge domain. Called only when something AFTER the
    /// bridge leg fails (the escrow settlement), where neither the coins nor
    /// the replay set / withdrawal queue / rate window of a rejected payload
    /// may survive - a leftover replay-set entry would block a legitimate
    /// re-submission, a leftover queue entry would be a phantom withdrawal.
    /// Accounts the leg created (`None` pre-state) are removed with their
    /// trie entries, mirroring `commit_native`'s own undo.
    ///
    /// The deposit MINT reservation taken by the settlement
    /// ([`BridgeSnapshot::minted_nano`]) is released here too: a rolled-back
    /// payload must not permanently burn global supply headroom (that would be
    /// a cheap way to push the chain toward the cap with refused transactions).
    pub(super) async fn restore_bridge_native(&self, snap: Option<&BridgeSnapshot>) {
        let Some(snap) = snap else {
            return;
        };
        if snap.minted_nano > 0 {
            self.release_mint_nano(snap.minted_nano);
        }
        let mut map = self.accounts.write().await;
        let mut touched: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(snap.accounts.len());
        let mut removed: Vec<[u8; 32]> = Vec::new();
        for (addr, prev) in snap.accounts.iter().rev() {
            match prev {
                Some((balance, nonce)) => {
                    if let Some(acc) = map.get_mut(addr) {
                        acc.balance = *balance;
                        acc.nonce = *nonce;
                        touched.push((*addr, acc.to_trie_bytes()));
                    }
                }
                None => {
                    map.remove(addr);
                    removed.push(*addr);
                }
            }
        }
        // Re-derive the escrow mirror from the RESTORED account, the same way
        // settlement derived it from the applied one.
        let mut domain = snap.domain.clone();
        domain.escrow_balance = map
            .get(&crate::bridge::BRIDGE_ESCROW)
            .map(|a| a.balance)
            .unwrap_or(0);
        drop(map);

        {
            let mut g = self.bridge_write().await;
            *g = domain;
        }

        let mut trie = self.state_trie.write().await;
        for (addr, data) in touched {
            trie.insert(&addr, &data);
        }
        for addr in removed {
            trie.remove(&addr);
        }
    }

    /// Settle ONE payload's actor sends: debit the sender for the total value
    /// and enqueue one message per send into the RECIPIENT's inbox - or, when
    /// the recipient account does not exist, bounce it straight back into the
    /// sender's inbox (the rule the engine's direct `send_message` API has
    /// always applied, so value is never parked against an address nothing
    /// can ever deliver to).
    ///
    /// Two-phase on purpose: EVERYTHING is validated first (all sends
    /// bounceable, no value overflow, sender can afford `floor + total`),
    /// then applied infallibly - so a refusal leaves the map untouched and
    /// the caller needs no rollback for a failure of THIS leg, only the
    /// returned [`ActorSnapshot`] for a failure of a LATER one.
    ///
    /// `floor` is what `commit_native` will still demand from the same sender
    /// after this payload (`amount + declared gas + payload transfers`; 0
    /// when the CLOB escrow below re-asserts that itself): the debit must not
    /// eat into it, or the native commit would refuse a transaction whose
    /// messages are already queued.
    ///
    /// Deliberately does NOT write the trie: the sender's balance reaches the
    /// trie through `commit_native` (which runs only for a transaction that
    /// commits), and inboxes are not trie state at all. A rollback therefore
    /// only has to put the account map back.
    pub(super) async fn settle_actor_sends(
        &self,
        sends: &[crate::svm::ActorSendRequest],
        sender: [u8; 32],
        floor: u64,
    ) -> Result<Option<ActorSnapshot>, String> {
        if sends.is_empty() {
            return Ok(None);
        }
        // v1: every send must be bounceable. The VM already refuses one that
        // is not (before this leg, so the payload would have reverted) - this
        // is the settlement-side belt for the same rule, because refusing is
        // here exactly where value WOULD be destroyed.
        if sends.iter().any(|s| !s.bounce) {
            return Err("actor send rejected: bounce is required (v1)".to_string());
        }
        let total = sends
            .iter()
            .try_fold(0u64, |acc, s| acc.checked_add(s.value))
            .ok_or_else(|| "actor send: value overflow".to_string())?;
        let needed = floor
            .checked_add(total)
            .ok_or_else(|| "actor send: cost overflow".to_string())?;

        let mut map = self.accounts.write().await;
        {
            let snd = map
                .get(&sender)
                .ok_or_else(|| "actor send: sender account does not exist".to_string())?;
            if snd.balance < needed {
                return Err(format!(
                    "actor send: sender holds {} nano-STELL but {needed} is required \
                     ({floor} reserved for amount + gas + payload transfers)",
                    snd.balance
                ));
            }
        }

        // Pre-state of every account this settlement touches, for the caller's
        // rollback record. Recorded BEFORE each mutation; `noted` keeps the
        // FIRST (pre-settlement) value if an account is touched twice.
        let mut snapshot: Vec<([u8; 32], AccountState)> = Vec::with_capacity(sends.len() + 1);
        let mut noted: HashSet<[u8; 32]> = HashSet::with_capacity(sends.len() + 1);
        note_account_before(&map, &mut snapshot, &mut noted, sender);
        // One debit for the whole payload's sends (checked above).
        {
            let snd = map
                .get_mut(&sender)
                .expect("sender existence re-checked above");
            snd.balance -= total;
        }

        for s in sends {
            let encoded = encode_actor_body(&s.body, s.gas_budget);
            let msg = ActorMessage::new(sender, s.recipient, s.value, encoded, s.bounce);
            if map.contains_key(&s.recipient) {
                note_account_before(&map, &mut snapshot, &mut noted, s.recipient);
                // Enqueue is infallible; FIFO order for the recipient is the
                // payload's own program order.
                map.get_mut(&s.recipient)
                    .expect("recipient existence checked above")
                    .inbox
                    .push_back(msg);
            } else {
                // Missing recipient: the value is already debited above, and
                // the bounce below returns it - EXACTLY once, when the mailbox
                // pass delivers this message (never here, never again).
                let bounce = ActorMessage {
                    msg_id: msg.msg_id,
                    sender: s.recipient,
                    recipient: sender,
                    value: msg.value,
                    body: msg.body,
                    bounce: false,
                    bounced: true,
                };
                map.get_mut(&sender)
                    .expect("sender existence re-checked above")
                    .inbox
                    .push_back(bounce);
            }
        }

        Ok(Some(ActorSnapshot { accounts: snapshot }))
    }

    /// Put back what [`Self::settle_actor_sends`] moved: balances AND inboxes,
    /// for every account it touched. Called only when something AFTER the
    /// actor leg fails (the CLOB escrow), where neither the debit nor the
    /// queued messages of a refused payload may survive - a message left in an
    /// inbox would deliver value its transaction never paid for.
    ///
    /// No trie write: the settlement never wrote one (see
    /// `settle_actor_sends`), so the map is the only thing to restore.
    pub(super) async fn restore_actor_native(&self, snap: Option<&ActorSnapshot>) {
        let Some(snap) = snap else {
            return;
        };
        if snap.accounts.is_empty() {
            return;
        }
        let mut map = self.accounts.write().await;
        for (addr, acc) in &snap.accounts {
            map.insert(*addr, acc.clone());
        }
    }
}

// ============================================================================
// EVM carrier settlement: committed exactly-once nullifiers + index replay
// ============================================================================

impl InMemoryStateEngine {
    /// Committed trie key for a settled EVM intent nullifier.
    ///
    /// Namespaced and hashed so it can never collide with an account address,
    /// a token balance/supply leaf, a contract leaf or a HashPool nullifier.
    fn evm_settled_key(digest: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(24 + 32);
        buf.extend_from_slice(b"STELL_EVM_SETTLED_V1");
        buf.extend_from_slice(digest);
        crate::evm_adapter::keccak256(&buf)
    }

    /// True when this exact signed EVM intent has already settled in a
    /// COMMITTED block. Consensus-visible (the trie is part of the state
    /// root), so a restart/catch-up derives the same answer.
    pub async fn evm_intent_is_settled(&self, digest: &[u8; 32]) -> bool {
        let key = Self::evm_settled_key(digest);
        self.state_trie.read().await.get(&key).is_some()
    }

    /// Mark a signed EVM intent as settled. Called ONLY after the carrying
    /// transaction committed successfully, so a failed/reverted carrier never
    /// consumes the nullifier and a retry can still settle.
    pub async fn mark_evm_intent_settled(&self, digest: &[u8; 32]) {
        let key = Self::evm_settled_key(digest);
        let mut trie = self.state_trie.write().await;
        trie.insert(&key, &[1u8]);
        drop(trie);
        // The trie is folded into the state root; invalidate the cached
        // commitment exactly like any other committed-domain write.
        self.bump_commitment_generation();
    }

    /// Feed ONE committed-and-applied transaction into the deterministic
    /// routing/settlement indexes (PENTEST2 H1).
    ///
    /// * binding index (`EVM address → PQ account`): only an applied
    ///   transaction that proves both keys can insert;
    /// * settlement map (`keccak(EVM raw) ↔ Stell hash`): only a carrier that
    ///   really committed, never a pooled one;
    /// * `SC1` secp settlement envelopes are linked the same way the receipt
    ///   path links them.
    ///
    /// Pure function of the transaction: replaying the same committed block
    /// sequence reproduces the same maps on every node and after a restart.
    pub fn observe_committed_evm_tx(&self, tx: &crate::sharding::Transaction) {
        // Fast path: the overwhelmingly common transaction carries neither an
        // EVM payload nor a secp settlement envelope, and neither index can
        // learn anything from it.
        if crate::evm_adapter::classify_evm_payload(tx).is_none()
            && !crate::evm_adapter::is_secp_settlement_tx(tx)
        {
            return;
        }
        if let Ok(mut idx) = crate::evm_adapter::evm_binding_index().write() {
            let _ = idx.observe_transaction(tx);
        }
        if let Some(digest) = crate::evm_adapter::carrier_intent_digest(tx) {
            crate::evm_adapter::register_evm_settlement(
                &format!("0x{}", hex::encode(digest)),
                &tx.compute_tx_hash(),
            );
        }
        crate::evm_adapter::link_secp_settlement(tx);
    }

    /// Replay a committed block's APPLIED transactions in block order into
    /// both indexes. `status` parallels `block.transactions` (step-1
    /// receipts), so a refused transaction never claims a binding or a
    /// settlement.
    pub fn observe_committed_evm_block(
        &self,
        block: &crate::sharding::Block,
        status: &[bool],
    ) -> usize {
        let mut accepted = 0usize;
        for (i, tx) in block.transactions.iter().enumerate() {
            if !status.get(i).copied().unwrap_or(false) {
                continue;
            }
            if crate::evm_adapter::classify_evm_payload(tx).is_some() {
                accepted += 1;
            }
            self.observe_committed_evm_tx(tx);
        }
        accepted
    }

    /// Rebuild both process-local EVM indexes from a persisted, ordered window
    /// of committed blocks (startup replay, PENTEST2 H1).
    ///
    /// `successful` holds the tx hashes that committed with `success == true`
    /// (from the durable receipt store). The binding and settlement indexes
    /// are rebuilt from scratch in block order, so a restart derives the same
    /// maps as the node that applied the blocks live. Idempotent: replaying
    /// the same window twice gives the same maps.
    pub fn rebuild_evm_indexes_from_blocks(
        &self,
        blocks: &[crate::sharding::Block],
        successful: &HashSet<[u8; 32]>,
    ) -> usize {
        crate::evm_adapter::clear_evm_bindings();
        crate::evm_adapter::clear_evm_settlements();
        let mut replayed = 0usize;
        for block in blocks {
            for tx in &block.transactions {
                if !successful.contains(&tx.compute_tx_hash()) {
                    continue;
                }
                if crate::evm_adapter::classify_evm_payload(tx).is_some() {
                    replayed += 1;
                }
                self.observe_committed_evm_tx(tx);
            }
        }
        replayed
    }
}
