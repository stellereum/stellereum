//! Native Orderbook-Actor CLOB (Central Limit Order Book)
//! System exchange actor in SVM paradigm for high-speed matching.
//! Supports limit and market buy/sell orders, cancellation, partial fills,
//! depth bounds to prevent spam, and multi-pair OrderbookManager.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

pub const PAIR_STELL_USDT: u32 = 1;
pub const PAIR_STELL_TON: u32 = 2;
pub const PAIR_STELL_GRAM: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    Buy,
    Sell,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderType {
    Limit,
    Market,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Order {
    pub order_id: u64,
    pub trader: [u8; 32],
    pub side: OrderSide,
    pub order_type: OrderType,
    pub price: u64,
    pub amount: u64,
    pub filled: u64,
    pub timestamp: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TradeExecution {
    pub maker_order_id: u64,
    pub taker_order_id: u64,
    pub maker: [u8; 32],
    pub taker: [u8; 32],
    pub price: u64,
    pub amount: u64,
}

/// What an SVM order syscall did, so the state engine can settle escrow and
/// value for it on the live path (`execute_payload`, shared by
/// `apply_transaction` and `apply_block_parallel_fees`).
///
/// The VM mutates the book itself (clone-commit, so a later revert discards
/// it), but it has no access to accounts, tokens or the escrow map. These
/// events are the hand-off: placement carries its matched trades, and the
/// engine locks/releases escrow and moves the funds for every one of them in
/// the same transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClobEvent {
    /// A limit order was submitted on `pair_id` and is now (partly) in the
    /// book. `trades` are the fills this submission produced, already applied
    /// to the book; value for them has NOT moved yet.
    Place {
        pair_id: u32,
        order_id: u64,
        trader: [u8; 32],
        side: OrderSide,
        order_type: OrderType,
        price: u64,
        amount: u64,
        filled: u64,
        trades: Vec<TradeExecution>,
    },
    /// The trader cancelled their own resting order (ownership was already
    /// verified by the syscall); its escrow must be refunded.
    Cancel {
        pair_id: u32,
        order_id: u64,
        trader: [u8; 32],
    },
}

/// Actor representing an isolated orderbook for a specific asset pair
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrderbookActor {
    pub pair_id: u32,
    pub next_order_id: u64,
    /// Bids: sorted by price descending (Reverse key) -> list of orders at this price
    pub bids: BTreeMap<std::cmp::Reverse<u64>, Vec<Order>>,
    /// Asks: sorted by price ascending -> list of orders at this price
    pub asks: BTreeMap<u64, Vec<Order>>,
    pub max_depth: usize,
}

impl Default for OrderbookActor {
    fn default() -> Self {
        Self::new(1, 1000)
    }
}

impl OrderbookActor {
    pub fn new(pair_id: u32, max_depth: usize) -> Self {
        Self {
            pair_id,
            next_order_id: 1,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            max_depth,
        }
    }

    /// Match or insert a limit order
    pub fn submit_order(
        &mut self,
        trader: [u8; 32],
        side: OrderSide,
        price: u64,
        amount: u64,
        timestamp: u64,
    ) -> (Order, Vec<TradeExecution>) {
        self.submit_order_ext(trader, side, OrderType::Limit, price, amount, timestamp)
    }

    /// Insert a resting order into its price level in TIME-PRIORITY order:
    /// before the first order with a strictly later `timestamp`, so an equal
    /// timestamp keeps arrival (FIFO) order.
    ///
    /// Without this the timestamp was inert data: an order stamped `now` by an
    /// earlier block could sit behind one stamped later, and two orders with
    /// the same price would match in whatever order they were inserted. The
    /// stamp comes from `VmContext.timestamp` (`block.timestamp`) or from the
    /// `now` argument of `place_order_settled`, so this is what makes the
    /// block's clock decide who gets filled first.
    fn insert_time_priority(level: &mut Vec<Order>, order: &Order) {
        let pos = level
            .iter()
            .position(|o| o.timestamp > order.timestamp)
            .unwrap_or(level.len());
        level.insert(pos, order.clone());
    }

    /// Look up a resting order by id (price-time scan of both sides).
    pub fn find_order(&self, order_id: u64) -> Option<&Order> {
        self.bids
            .values()
            .chain(self.asks.values())
            .flatten()
            .find(|o| o.order_id == order_id)
    }

    /// Match or insert an order with specified type (Limit or Market).
    pub fn submit_order_ext(
        &mut self,
        trader: [u8; 32],
        side: OrderSide,
        order_type: OrderType,
        price: u64,
        amount: u64,
        timestamp: u64,
    ) -> (Order, Vec<TradeExecution>) {
        self.submit_order_bounded(trader, side, order_type, price, amount, timestamp, usize::MAX)
    }

    /// Like `submit_order_ext`, but caps how many price levels one order may
    /// cross (`max_levels`). Anti-DoS: bounds the matching work a single order
    /// can trigger, so gas griefing via deep books is impossible.
    pub fn submit_order_bounded(
        &mut self,
        trader: [u8; 32],
        side: OrderSide,
        order_type: OrderType,
        price: u64,
        amount: u64,
        timestamp: u64,
        max_levels: usize,
    ) -> (Order, Vec<TradeExecution>) {
        let order_id = self.next_order_id;
        self.next_order_id += 1;

        let mut order = Order {
            order_id,
            trader,
            side: side.clone(),
            order_type: order_type.clone(),
            price,
            amount,
            filled: 0,
            timestamp,
        };

        let mut trades = Vec::new();
        let mut levels_crossed = 0usize;

        match side {
            OrderSide::Buy => {
                // Match against asks where ask.price <= order.price (or always match if Market)
                let mut finished_prices = Vec::new();

                for (&ask_price, orders) in self.asks.iter_mut() {
                    if order_type == OrderType::Limit && ask_price > price {
                        break;
                    }
                    if order.filled >= order.amount {
                        break;
                    }
                    if levels_crossed >= max_levels {
                        break;
                    }
                    levels_crossed += 1;

                    for maker in orders.iter_mut() {
                        let remaining_order = order.amount - order.filled;
                        let remaining_maker = maker.amount - maker.filled;
                        let fill_amount = remaining_order.min(remaining_maker);

                        if fill_amount > 0 {
                            order.filled += fill_amount;
                            maker.filled += fill_amount;

                            trades.push(TradeExecution {
                                maker_order_id: maker.order_id,
                                taker_order_id: order.order_id,
                                maker: maker.trader,
                                taker: order.trader,
                                price: ask_price,
                                amount: fill_amount,
                            });
                        }

                        if order.filled >= order.amount {
                            break;
                        }
                    }

                    orders.retain(|o| o.filled < o.amount);
                    if orders.is_empty() {
                        finished_prices.push(ask_price);
                    }
                }

                for p in finished_prices {
                    self.asks.remove(&p);
                }

                // If Limit order not fully filled, insert remaining into bids
                // (subject to max_depth).
                if order_type == OrderType::Limit && order.filled < order.amount {
                    // Enforce max depth WITHOUT evicting a resting order.
                    //
                    // `pop_last` used to drop the worst price level here. An
                    // evicted order leaves its escrow record behind with no way
                    // to release it - every release path (`cancel_order_settled`,
                    // the SVM cancel, settlement itself) looks the order up in
                    // the book - so depth pressure was a one-transaction way to
                    // strand anybody's collateral: post 1000 levels, then one
                    // more, and the deepest funded order vanished. Refusing the
                    // NEWCOMER's rest instead keeps the memory bound, keeps
                    // every funded order reachable by its owner, and still lets
                    // the newcomer's fills stand (it already paid for those).
                    let can_rest = self.bids.contains_key(&std::cmp::Reverse(price))
                        || self.bids.len() < self.max_depth;
                    if can_rest {
                        let level = self
                            .bids
                            .entry(std::cmp::Reverse(price))
                            .or_insert_with(Vec::new);
                        Self::insert_time_priority(level, &order);
                    }
                }
            }
            OrderSide::Sell => {
                // Match against bids where bid.price >= order.price (or always match if Market)
                let mut finished_prices = Vec::new();

                for (&std::cmp::Reverse(bid_price), orders) in self.bids.iter_mut() {
                    if order_type == OrderType::Limit && bid_price < price {
                        break;
                    }
                    if order.filled >= order.amount {
                        break;
                    }
                    if levels_crossed >= max_levels {
                        break;
                    }
                    levels_crossed += 1;

                    for maker in orders.iter_mut() {
                        let remaining_order = order.amount - order.filled;
                        let remaining_maker = maker.amount - maker.filled;
                        let fill_amount = remaining_order.min(remaining_maker);

                        if fill_amount > 0 {
                            order.filled += fill_amount;
                            maker.filled += fill_amount;

                            trades.push(TradeExecution {
                                maker_order_id: maker.order_id,
                                taker_order_id: order.order_id,
                                maker: maker.trader,
                                taker: order.trader,
                                price: bid_price,
                                amount: fill_amount,
                            });
                        }

                        if order.filled >= order.amount {
                            break;
                        }
                    }

                    orders.retain(|o| o.filled < o.amount);
                    if orders.is_empty() {
                        finished_prices.push(std::cmp::Reverse(bid_price));
                    }
                }

                for p in finished_prices {
                    self.bids.remove(&p);
                }

                // If Limit order not fully filled, insert remaining into asks
                // (subject to max_depth). Same rule as the bid side: a full
                // book refuses the newcomer rather than evicting a funded
                // resting order (see the bid arm for why eviction orphaned
                // escrow).
                if order_type == OrderType::Limit && order.filled < order.amount {
                    let can_rest =
                        self.asks.contains_key(&price) || self.asks.len() < self.max_depth;
                    if can_rest {
                        let level = self.asks.entry(price).or_insert_with(Vec::new);
                        Self::insert_time_priority(level, &order);
                    }
                }
            }
        }

        (order, trades)
    }

    /// Cancel order by id
    pub fn cancel_order(&mut self, order_id: u64) -> Option<Order> {
        let mut cancelled = None;
        for orders in self.bids.values_mut() {
            if let Some(pos) = orders.iter().position(|o| o.order_id == order_id) {
                cancelled = Some(orders.remove(pos));
                break;
            }
        }
        if cancelled.is_some() {
            self.bids.retain(|_, orders| !orders.is_empty());
            return cancelled;
        }
        for orders in self.asks.values_mut() {
            if let Some(pos) = orders.iter().position(|o| o.order_id == order_id) {
                cancelled = Some(orders.remove(pos));
                break;
            }
        }
        if cancelled.is_some() {
            self.asks.retain(|_, orders| !orders.is_empty());
            return cancelled;
        }
        None
    }

    /// Get current best bid and ask prices
    pub fn get_best_bid_ask(&self) -> (Option<u64>, Option<u64>) {
        let best_bid = self.bids.keys().next().map(|std::cmp::Reverse(p)| *p);
        let best_ask = self.asks.keys().next().copied();
        (best_bid, best_ask)
    }

    /// Get depth: number of active price levels on (bids, asks)
    pub fn depth(&self) -> (usize, usize) {
        (self.bids.len(), self.asks.len())
    }
}

/// Orderbook Manager managing multiple trading pairs across the SVM system
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OrderbookManager {
    pub books: HashMap<u32, OrderbookActor>,
}

impl OrderbookManager {
    pub fn new() -> Self {
        let mut books = HashMap::new();
        books.insert(PAIR_STELL_USDT, OrderbookActor::new(PAIR_STELL_USDT, 1000));
        books.insert(PAIR_STELL_TON, OrderbookActor::new(PAIR_STELL_TON, 1000));
        books.insert(PAIR_STELL_GRAM, OrderbookActor::new(PAIR_STELL_GRAM, 1000));
        Self { books }
    }

    pub fn get_book_mut(&mut self, pair_id: u32) -> &mut OrderbookActor {
        self.books
            .entry(pair_id)
            .or_insert_with(|| OrderbookActor::new(pair_id, 1000))
    }

    pub fn get_book(&self, pair_id: u32) -> Option<&OrderbookActor> {
        self.books.get(&pair_id)
    }
}
