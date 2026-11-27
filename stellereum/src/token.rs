//! Stellereum Fungible Token Standard (STS-20)
//! TON Jetton / ERC-20 style fungible tokens implemented as native Actors.
//! Features:
//! - Deterministic token IDs (creator + metadata + nonce)
//! - Mint / Burn with minter authority and hard supply caps
//! - Transfer and delegated TransferFrom with allowances
//! - Emergency pause / unpause and minter renouncement
//! - Overflow-safe arithmetic and event emission for indexers
//!
//! This standard is the foundation for wSTELL (bridged STELL on external chains)
//! and wUSDT (bridged USDT inside Stellereum).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

/// Micro-gas costs for token operations (nano-STELL)
///
/// ONE RULE (audit W6.6, item 4): NO token operation may cost less than a
/// native value transfer. The fee a transaction pays is its DECLARED
/// `gas_limit`, so the gas table IS the price of the work: a table entry below
/// the native floor lets one paid transaction perform hundreds of token
/// operations, which is exactly the "500x cheaper spam" the transfer price
/// was raised to stop. The remaining entries (mint / burn / approve / create)
/// were still at the pre-raise scale (800 / 400 / 300 / 5,000) when the
/// transfer was moved to the floor, so a mint - which CREATES supply - was
/// 350x cheaper than a transfer that only moves it.
///
/// The mint is the sharpest edge: it is the only token operation that
/// increases the token supply, so leaving it cheap is an inflation/spam
/// lever, not just a price inconsistency.
pub const GAS_TOKEN_CREATE: u64 = crate::svm::GAS_BASIC_TRANSFER;
/// Gas consumed by `SysCallTokenTransfer` / `SysCallTokenTransferFrom`.
///
/// SAME unit and SAME `opcode_gas` table as [`crate::svm::GAS_BASIC_TRANSFER`].
/// Aligned with `GAS_BASIC_TRANSFER` (280,000 nano-STELL floor) so that custom
/// token transfers cannot be used for 500x cheaper spam attacks.
pub const GAS_TOKEN_TRANSFER: u64 = crate::svm::GAS_BASIC_TRANSFER;
pub const GAS_TOKEN_MINT: u64 = crate::svm::GAS_BASIC_TRANSFER;
pub const GAS_TOKEN_BURN: u64 = crate::svm::GAS_BASIC_TRANSFER;
pub const GAS_TOKEN_APPROVE: u64 = crate::svm::GAS_BASIC_TRANSFER;
pub const GAS_TOKEN_ADMIN: u64 = crate::svm::GAS_BASIC_TRANSFER;

/// COMPILE-TIME PIN of the rule above: no token operation is cheaper than a
/// native transfer. A future table edit that lowers one of these is a build
/// error, not a silent 350x spam discount (audit W6.6).
const _: () = {
    assert!(GAS_TOKEN_CREATE >= crate::svm::GAS_BASIC_TRANSFER);
    assert!(GAS_TOKEN_TRANSFER >= crate::svm::GAS_BASIC_TRANSFER);
    assert!(GAS_TOKEN_MINT >= crate::svm::GAS_BASIC_TRANSFER);
    assert!(GAS_TOKEN_BURN >= crate::svm::GAS_BASIC_TRANSFER);
    assert!(GAS_TOKEN_APPROVE >= crate::svm::GAS_BASIC_TRANSFER);
    assert!(GAS_TOKEN_ADMIN >= crate::svm::GAS_BASIC_TRANSFER);
};

/// The zero address represents "no one" (used for renounced minter)
pub const ZERO_ADDRESS: [u8; 32] = [0u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenError {
    NotMinter,
    Paused,
    ZeroAmount,
    SelfTransfer,
    ZeroAddress,
    InsufficientBalance,
    InsufficientAllowance,
    SupplyCapExceeded,
    Overflow,
    MinterRenounced,
    TokenNotFound,
    MetadataInvalid,
    AllowanceUnderflow,
    DuplicateToken,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            TokenError::NotMinter => "caller is not the token minter",
            TokenError::Paused => "token is paused",
            TokenError::ZeroAmount => "amount must be greater than zero",
            TokenError::SelfTransfer => "cannot transfer to self",
            TokenError::ZeroAddress => "operation on the zero address is forbidden",
            TokenError::InsufficientBalance => "insufficient token balance",
            TokenError::InsufficientAllowance => "insufficient allowance",
            TokenError::SupplyCapExceeded => "mint would exceed maximum supply cap",
            TokenError::Overflow => "arithmetic overflow",
            TokenError::MinterRenounced => "minter authority has been renounced",
            TokenError::TokenNotFound => "token not found in registry",
            TokenError::MetadataInvalid => "invalid token metadata",
            TokenError::DuplicateToken => "token id already registered",
            TokenError::AllowanceUnderflow => "cannot decrease allowance below zero",
        };
        write!(f, "{}", msg)
    }
}

/// Token metadata (immutable identity + mutable admin flags)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u64,
    pub max_supply: Option<u64>,
    pub minter: [u8; 32],
    pub paused: bool,
    /// Optional human description / URI
    pub description: String,
}

impl TokenMetadata {
    pub fn validate(&self) -> Result<(), TokenError> {
        if self.name.is_empty() || self.name.len() > 64 {
            return Err(TokenError::MetadataInvalid);
        }
        if self.symbol.is_empty() || self.symbol.len() > 16 {
            return Err(TokenError::MetadataInvalid);
        }
        if self.decimals > 18 {
            return Err(TokenError::MetadataInvalid);
        }
        if let Some(cap) = self.max_supply {
            if self.total_supply > cap {
                return Err(TokenError::MetadataInvalid);
            }
        }
        Ok(())
    }
}

/// Operations that can be sent to a token actor
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenOp {
    Transfer {
        to: [u8; 32],
        amount: u64,
    },
    TransferFrom {
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
    },
    Approve {
        spender: [u8; 32],
        amount: u64,
    },
    IncreaseAllowance {
        spender: [u8; 32],
        delta: u64,
    },
    DecreaseAllowance {
        spender: [u8; 32],
        delta: u64,
    },
    Mint {
        to: [u8; 32],
        amount: u64,
    },
    Burn {
        from: [u8; 32],
        amount: u64,
    },
    SetMinter {
        new_minter: [u8; 32],
    },
    RenounceMinter,
    Pause,
    Unpause,
}

/// Event emitted by token operations (for off-chain indexers)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenEvent {
    Transfer {
        token_id: [u8; 32],
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
    },
    Approval {
        token_id: [u8; 32],
        owner: [u8; 32],
        spender: [u8; 32],
        amount: u64,
    },
    Mint {
        token_id: [u8; 32],
        to: [u8; 32],
        amount: u64,
        new_total: u64,
    },
    Burn {
        token_id: [u8; 32],
        from: [u8; 32],
        amount: u64,
        new_total: u64,
    },
    MinterChanged {
        token_id: [u8; 32],
        new_minter: [u8; 32],
    },
    Paused {
        token_id: [u8; 32],
    },
    Unpaused {
        token_id: [u8; 32],
    },
}

/// A fungible token contract operating as an isolated Actor
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenActor {
    pub id: [u8; 32],
    pub metadata: TokenMetadata,
    pub balances: HashMap<[u8; 32], u64>,
    /// (owner, spender) -> allowance
    pub allowances: HashMap<([u8; 32], [u8; 32]), u64>,
}

impl TokenActor {
    /// Create a new token actor. `initial_supply` is credited to `metadata.minter`.
    pub fn new(
        id: [u8; 32],
        metadata: TokenMetadata,
        initial_supply: u64,
    ) -> Result<Self, TokenError> {
        metadata.validate()?;
        if let Some(cap) = metadata.max_supply {
            if initial_supply > cap {
                return Err(TokenError::SupplyCapExceeded);
            }
        }

        let mut token = Self {
            id,
            metadata: TokenMetadata {
                total_supply: initial_supply,
                ..metadata
            },
            balances: HashMap::new(),
            allowances: HashMap::new(),
        };

        if initial_supply > 0 {
            token.balances.insert(token.metadata.minter, initial_supply);
        }
        Ok(token)
    }

    pub fn balance_of(&self, account: &[u8; 32]) -> u64 {
        self.balances.get(account).copied().unwrap_or(0)
    }

    pub fn allowance(&self, owner: &[u8; 32], spender: &[u8; 32]) -> u64 {
        self.allowances
            .get(&(*owner, *spender))
            .copied()
            .unwrap_or(0)
    }

    pub fn is_minter(&self, caller: &[u8; 32]) -> bool {
        self.metadata.minter != ZERO_ADDRESS && self.metadata.minter == *caller
    }

    fn credit(&mut self, account: [u8; 32], amount: u64) -> Result<(), TokenError> {
        let entry = self.balances.entry(account).or_insert(0);
        *entry = entry.checked_add(amount).ok_or(TokenError::Overflow)?;
        Ok(())
    }

    fn debit(&mut self, account: &[u8; 32], amount: u64) -> Result<(), TokenError> {
        let entry = self
            .balances
            .get_mut(account)
            .ok_or(TokenError::InsufficientBalance)?;
        if *entry < amount {
            return Err(TokenError::InsufficientBalance);
        }
        *entry -= amount;
        if *entry == 0 {
            self.balances.remove(account);
        }
        Ok(())
    }

    /// Direct transfer by the token holder
    pub fn transfer(
        &mut self,
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
    ) -> Result<TokenEvent, TokenError> {
        if amount == 0 {
            return Err(TokenError::ZeroAmount);
        }
        if to == ZERO_ADDRESS || from == ZERO_ADDRESS {
            return Err(TokenError::ZeroAddress);
        }
        if from == to {
            return Err(TokenError::SelfTransfer);
        }
        if self.metadata.paused {
            return Err(TokenError::Paused);
        }
        self.debit(&from, amount)?;
        self.credit(to, amount)?;
        Ok(TokenEvent::Transfer {
            token_id: self.id,
            from,
            to,
            amount,
        })
    }

    /// Approve a spender to move funds on behalf of the owner.
    ///
    /// NOTE (audit 2026-10-06): approvals are NOT gated on `paused` —
    /// `pause` freezes VALUE MOVEMENT (transfer/transfer_from/mint/burn),
    /// not allowance bookkeeping (same as ERC-20 Pausable). Consequence to
    /// be aware of: allowances granted before (or during) a pause become
    /// usable the moment the token unpauses. Pinned by test.
    pub fn approve(
        &mut self,
        owner: [u8; 32],
        spender: [u8; 32],
        amount: u64,
    ) -> Result<TokenEvent, TokenError> {
        if owner == ZERO_ADDRESS || spender == ZERO_ADDRESS {
            return Err(TokenError::ZeroAddress);
        }
        if owner == spender {
            return Err(TokenError::SelfTransfer);
        }
        if amount == 0 {
            self.allowances.remove(&(owner, spender));
        } else {
            self.allowances.insert((owner, spender), amount);
        }
        Ok(TokenEvent::Approval {
            token_id: self.id,
            owner,
            spender,
            amount,
        })
    }

    /// Atomically increase an allowance (mitigates the ERC-20 approve race condition)
    pub fn increase_allowance(
        &mut self,
        owner: [u8; 32],
        spender: [u8; 32],
        delta: u64,
    ) -> Result<TokenEvent, TokenError> {
        if owner == ZERO_ADDRESS || spender == ZERO_ADDRESS {
            return Err(TokenError::ZeroAddress);
        }
        if owner == spender {
            return Err(TokenError::SelfTransfer);
        }
        if delta == 0 {
            return Err(TokenError::ZeroAmount);
        }
        let current = self.allowance(&owner, &spender);
        let new = current.checked_add(delta).ok_or(TokenError::Overflow)?;
        self.allowances.insert((owner, spender), new);
        Ok(TokenEvent::Approval {
            token_id: self.id,
            owner,
            spender,
            amount: new,
        })
    }

    /// Atomically decrease an allowance (mitigates the ERC-20 approve race condition)
    pub fn decrease_allowance(
        &mut self,
        owner: [u8; 32],
        spender: [u8; 32],
        delta: u64,
    ) -> Result<TokenEvent, TokenError> {
        if owner == ZERO_ADDRESS || spender == ZERO_ADDRESS {
            return Err(TokenError::ZeroAddress);
        }
        if owner == spender {
            return Err(TokenError::SelfTransfer);
        }
        let current = self.allowance(&owner, &spender);
        if delta > current {
            return Err(TokenError::AllowanceUnderflow);
        }
        let new = current - delta;
        if new == 0 {
            self.allowances.remove(&(owner, spender));
        } else {
            self.allowances.insert((owner, spender), new);
        }
        Ok(TokenEvent::Approval {
            token_id: self.id,
            owner,
            spender,
            amount: new,
        })
    }

    /// Spend an allowance to move funds.
    /// Atomicity: ALL checks are performed before ANY state mutation, so a failed
    /// transfer_from never consumes allowance or mutates balances (CEI pattern).
    pub fn transfer_from(
        &mut self,
        spender: [u8; 32],
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
    ) -> Result<TokenEvent, TokenError> {
        // ---- Checks ----
        if amount == 0 {
            return Err(TokenError::ZeroAmount);
        }
        if to == ZERO_ADDRESS || from == ZERO_ADDRESS {
            return Err(TokenError::ZeroAddress);
        }
        if from == to {
            return Err(TokenError::SelfTransfer);
        }
        if self.metadata.paused {
            return Err(TokenError::Paused);
        }
        let current = self.allowance(&from, &spender);
        if current < amount {
            return Err(TokenError::InsufficientAllowance);
        }
        if self.balance_of(&from) < amount {
            return Err(TokenError::InsufficientBalance);
        }

        // ---- Effects (only after all checks pass) ----
        let remaining = current - amount;
        if remaining == 0 {
            self.allowances.remove(&(from, spender));
        } else {
            self.allowances.insert((from, spender), remaining);
        }
        // Debit cannot fail here (balance already verified).
        self.debit(&from, amount)?;
        self.credit(to, amount)?;
        Ok(TokenEvent::Transfer {
            token_id: self.id,
            from,
            to,
            amount,
        })
    }

    /// Mint new tokens. Only callable by the current minter.
    /// Atomicity: supply counter is updated only after the balance credit succeeds.
    pub fn mint(
        &mut self,
        caller: [u8; 32],
        to: [u8; 32],
        amount: u64,
    ) -> Result<TokenEvent, TokenError> {
        if self.metadata.minter == ZERO_ADDRESS {
            return Err(TokenError::MinterRenounced);
        }
        if !self.is_minter(&caller) {
            return Err(TokenError::NotMinter);
        }
        if amount == 0 {
            return Err(TokenError::ZeroAmount);
        }
        if to == ZERO_ADDRESS {
            return Err(TokenError::ZeroAddress);
        }
        if self.metadata.paused {
            return Err(TokenError::Paused);
        }
        let new_total = self
            .metadata
            .total_supply
            .checked_add(amount)
            .ok_or(TokenError::Overflow)?;
        if let Some(cap) = self.metadata.max_supply {
            if new_total > cap {
                return Err(TokenError::SupplyCapExceeded);
            }
        }
        // Credit first; only commit the supply increase if the credit succeeded.
        self.credit(to, amount)?;
        self.metadata.total_supply = new_total;
        Ok(TokenEvent::Mint {
            token_id: self.id,
            to,
            amount,
            new_total,
        })
    }

    /// Burn tokens. Minter can burn from anyone; a holder can burn their own.
    pub fn burn(
        &mut self,
        caller: [u8; 32],
        from: [u8; 32],
        amount: u64,
    ) -> Result<TokenEvent, TokenError> {
        if amount == 0 {
            return Err(TokenError::ZeroAmount);
        }
        if from == ZERO_ADDRESS {
            return Err(TokenError::ZeroAddress);
        }
        if self.metadata.paused {
            return Err(TokenError::Paused);
        }
        let is_admin = self.is_minter(&caller);
        if caller != from && !is_admin {
            return Err(TokenError::NotMinter);
        }
        self.debit(&from, amount)?;
        self.metadata.total_supply = self
            .metadata
            .total_supply
            .checked_sub(amount)
            .ok_or(TokenError::Overflow)?;
        Ok(TokenEvent::Burn {
            token_id: self.id,
            from,
            amount,
            new_total: self.metadata.total_supply,
        })
    }

    /// Transfer minter authority (only current minter)
    pub fn set_minter(
        &mut self,
        caller: [u8; 32],
        new_minter: [u8; 32],
    ) -> Result<TokenEvent, TokenError> {
        if self.metadata.minter == ZERO_ADDRESS {
            return Err(TokenError::MinterRenounced);
        }
        if !self.is_minter(&caller) {
            return Err(TokenError::NotMinter);
        }
        // No silent renounce through the zero address (audit 2026-10-06): a
        // typo would burn mint authority irreversibly with the wrong event.
        // Use `renounce_minter` explicitly.
        if new_minter == ZERO_ADDRESS {
            return Err(TokenError::ZeroAddress);
        }
        self.metadata.minter = new_minter;
        Ok(TokenEvent::MinterChanged {
            token_id: self.id,
            new_minter,
        })
    }

    /// Permanently renounce minting (irreversible)
    pub fn renounce_minter(&mut self, caller: [u8; 32]) -> Result<TokenEvent, TokenError> {
        if !self.is_minter(&caller) {
            return Err(TokenError::NotMinter);
        }
        self.metadata.minter = ZERO_ADDRESS;
        Ok(TokenEvent::MinterChanged {
            token_id: self.id,
            new_minter: ZERO_ADDRESS,
        })
    }

    pub fn pause(&mut self, caller: [u8; 32]) -> Result<TokenEvent, TokenError> {
        if !self.is_minter(&caller) {
            return Err(TokenError::NotMinter);
        }
        self.metadata.paused = true;
        Ok(TokenEvent::Paused { token_id: self.id })
    }

    pub fn unpause(&mut self, caller: [u8; 32]) -> Result<TokenEvent, TokenError> {
        if !self.is_minter(&caller) {
            return Err(TokenError::NotMinter);
        }
        self.metadata.paused = false;
        Ok(TokenEvent::Unpaused { token_id: self.id })
    }

    /// Actor-message entry point: dispatch an operation from a caller
    pub fn execute(&mut self, caller: [u8; 32], op: TokenOp) -> Result<TokenEvent, TokenError> {
        match op {
            TokenOp::Transfer { to, amount } => self.transfer(caller, to, amount),
            TokenOp::TransferFrom { from, to, amount } => {
                self.transfer_from(caller, from, to, amount)
            }
            TokenOp::Approve { spender, amount } => self.approve(caller, spender, amount),
            TokenOp::IncreaseAllowance { spender, delta } => {
                self.increase_allowance(caller, spender, delta)
            }
            TokenOp::DecreaseAllowance { spender, delta } => {
                self.decrease_allowance(caller, spender, delta)
            }
            TokenOp::Mint { to, amount } => self.mint(caller, to, amount),
            TokenOp::Burn { from, amount } => self.burn(caller, from, amount),
            TokenOp::SetMinter { new_minter } => self.set_minter(caller, new_minter),
            TokenOp::RenounceMinter => self.renounce_minter(caller),
            TokenOp::Pause => self.pause(caller),
            TokenOp::Unpause => self.unpause(caller),
        }
    }
}

/// Deterministic token ID: hash(creator || name || symbol || nonce)
pub fn compute_token_id(creator: &[u8; 32], name: &str, symbol: &str, nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"STELLEREUM_TOKEN_V1");
    hasher.update(creator);
    hasher.update(name.as_bytes());
    hasher.update(symbol.as_bytes());
    hasher.update(nonce.to_be_bytes());
    hasher.finalize().into()
}

/// Registry managing all fungible tokens on the chain
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TokenRegistry {
    pub tokens: BTreeMap<[u8; 32], TokenActor>,
    pub next_nonce: u64,
}

/// Hard cap on the token-id snapshot materialised for LEGACY `offset`
/// pagination of `stell_listTokens`.
///
/// `tokens` is a `BTreeMap`, so a keyset page never needs a snapshot. The
/// legacy `offset` path is kept for old clients, but it is bounded: at most
/// this many ids are materialised, so an attacker-grown registry cannot turn
/// one RPC call into an unbounded allocation. Cursor clients are unaffected.
pub const MAX_TOKENS_SORT_CAP: usize = 50_000;

/// One `(token, holder) -> balance` cell returned by the deterministic
/// pagination helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenHolding {
    pub token_id: [u8; 32],
    pub holder: [u8; 32],
    pub balance: u64,
}

/// Deterministic keyset page over a `BTreeMap`-backed token view.
///
/// `items` are in ascending key order (token id, or holder address); the next
/// page continues STRICTLY after `next_cursor`, so concurrent inserts cannot
/// shift, duplicate or skip an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<[u8; 32]>,
    pub has_more: bool,
    /// The scan/offset budget was hit before the registry was exhausted.
    pub truncated: bool,
    /// Number of candidate keys inspected by this call.
    pub scanned: usize,
}

impl<T> TokenPage<T> {
    /// An empty page (the starting point of the registry helpers).
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
            has_more: false,
            truncated: false,
            scanned: 0,
        }
    }
}

impl TokenRegistry {
    /// Deterministic page of token ids.
    ///
    /// With `cursor` this is a pure keyset scan (`token_id > cursor`). Without
    /// a cursor the legacy `offset` semantics are preserved, but the walk is
    /// capped at [`MAX_TOKENS_SORT_CAP`] ids (`truncated` is set when the
    /// registry is larger) so an offset read stays bounded.
    pub fn token_ids_page(
        &self,
        cursor: Option<[u8; 32]>,
        offset: usize,
        limit: usize,
    ) -> TokenPage<[u8; 32]> {
        let limit = limit.max(1);
        let mut page: TokenPage<[u8; 32]> = TokenPage::empty();
        if let Some(cursor) = cursor {
            for id in self
                .tokens
                .range((
                    std::ops::Bound::Excluded(cursor),
                    std::ops::Bound::Unbounded,
                ))
                .map(|(id, _)| id)
            {
                page.scanned += 1;
                if page.items.len() >= limit {
                    page.has_more = true;
                    break;
                }
                page.items.push(*id);
            }
            page.next_cursor = page.items.last().copied().filter(|_| page.has_more);
            return page;
        }
        let total = self.tokens.len();
        let cap = total.min(MAX_TOKENS_SORT_CAP);
        page.truncated = total > MAX_TOKENS_SORT_CAP;
        for (index, id) in self.tokens.keys().take(cap).enumerate() {
            if index < offset {
                continue;
            }
            page.scanned += 1;
            if page.items.len() >= limit {
                page.has_more = true;
                break;
            }
            page.items.push(*id);
        }
        page.next_cursor = page.items.last().copied().filter(|_| page.has_more);
        page
    }

    /// Deterministic holders page of ONE token, sorted by holder address.
    ///
    /// `min_balance` / `include_zero` filter BEFORE the page is filled, so the
    /// returned cursor is still positioned on a real inspected holder. At most
    /// `scan_cap` holders are inspected (`truncated` when the cap is hit).
    #[allow(clippy::too_many_arguments)]
    // GATE: token id + the documented filters + cursor/limit/scan cap; the
    // grouping would only rename the same RPC parameters.
    pub fn token_holders_page(
        &self,
        token_id: &[u8; 32],
        min_balance: u64,
        include_zero: bool,
        cursor: Option<[u8; 32]>,
        limit: usize,
        scan_cap: usize,
    ) -> TokenPage<TokenHolding> {
        let limit = limit.max(1);
        let mut page: TokenPage<TokenHolding> = TokenPage::empty();
        let Some(actor) = self.tokens.get(token_id) else {
            return page;
        };
        let mut holders: Vec<[u8; 32]> = actor.balances.keys().copied().collect();
        holders.sort_unstable();
        let mut last_scanned: Option<[u8; 32]> = None;
        for holder in holders {
            if page.scanned >= scan_cap {
                page.truncated = true;
                break;
            }
            page.scanned += 1;
            last_scanned = Some(holder);
            if cursor.map(|c| holder <= c).unwrap_or(false) {
                continue;
            }
            let balance = actor.balance_of(&holder);
            if balance == 0 && !include_zero {
                continue;
            }
            if balance < min_balance {
                continue;
            }
            if page.items.len() >= limit {
                page.has_more = true;
                break;
            }
            page.items.push(TokenHolding {
                token_id: *token_id,
                holder,
                balance,
            });
        }
        page.has_more |= page.truncated;
        page.next_cursor = if page.has_more {
            page.items.last().map(|h| h.holder).or(last_scanned)
        } else {
            None
        };
        page
    }

    /// Deterministic page of one owner's token holdings, sorted by token id.
    ///
    /// With `token` the page is that single cell (empty when the owner holds
    /// nothing); otherwise every token id `> cursor` is inspected. Same
    /// filters and scan cap as [`Self::token_holders_page`].
    #[allow(clippy::too_many_arguments)]
    // GATE: owner + token filter + filters + cursor/limit/scan cap are the
    // documented RPC parameters.
    pub fn owner_token_page(
        &self,
        owner: &[u8; 32],
        token: Option<[u8; 32]>,
        include_zero: bool,
        cursor: Option<[u8; 32]>,
        limit: usize,
        scan_cap: usize,
    ) -> TokenPage<TokenHolding> {
        let limit = limit.max(1);
        let mut page: TokenPage<TokenHolding> = TokenPage::empty();
        let mut last_scanned: Option<[u8; 32]> = None;
        if let Some(id) = token {
            if let Some((token_id, actor)) = self.tokens.get_key_value(&id) {
                if page.scanned >= scan_cap {
                    page.truncated = true;
                } else {
                    page.scanned += 1;
                    last_scanned = Some(*token_id);
                    Self::push_owner_holding(
                        &mut page,
                        owner,
                        token_id,
                        actor,
                        include_zero,
                        cursor,
                        limit,
                    );
                }
            }
        } else {
            let start = match cursor {
                Some(c) => std::ops::Bound::Excluded(c),
                None => std::ops::Bound::Unbounded,
            };
            let iter = self.tokens.range((start, std::ops::Bound::Unbounded));
            for (token_id, actor) in iter {
                if page.scanned >= scan_cap {
                    page.truncated = true;
                    break;
                }
                page.scanned += 1;
                last_scanned = Some(*token_id);
                if Self::push_owner_holding(
                    &mut page,
                    owner,
                    token_id,
                    actor,
                    include_zero,
                    cursor,
                    limit,
                ) {
                    break;
                }
            }
        }
        page.has_more |= page.truncated;
        page.next_cursor = if page.has_more {
            page.items.last().map(|h| h.token_id).or(last_scanned)
        } else {
            None
        };
        page
    }

    /// One candidate of the owner page: returns `true` when the page is full
    /// and the caller must stop scanning.
    #[allow(clippy::too_many_arguments)]
    // GATE: one candidate + the page state it mutates; grouping would just
    // rename the same parameters.
    fn push_owner_holding(
        page: &mut TokenPage<TokenHolding>,
        owner: &[u8; 32],
        token_id: &[u8; 32],
        actor: &TokenActor,
        include_zero: bool,
        cursor: Option<[u8; 32]>,
        limit: usize,
    ) -> bool {
        if cursor.map(|c| *token_id <= c).unwrap_or(false) {
            return false;
        }
        let balance = actor.balance_of(owner);
        if balance == 0 && !include_zero {
            return false;
        }
        if page.items.len() >= limit {
            page.has_more = true;
            return true;
        }
        page.items.push(TokenHolding {
            token_id: *token_id,
            holder: *owner,
            balance,
        });
        false
    }
}

impl TokenRegistry {
    pub fn new() -> Self {
        Self {
            tokens: BTreeMap::new(),
            next_nonce: 1,
        }
    }

    /// Find a token by (creator/minter, name, symbol). Read-only discovery
    /// for wallets: the create-tx receipt carries no token id (receipts hold
    /// no events), and the id commits the registry nonce which no client can
    /// predict — so clients resolve it by the three values they chose.
    /// Deterministic across nodes (BTreeMap order: smallest id wins). Same
    /// triple created twice legitimately yields DISTINCT ids — callers with
    /// duplicates must disambiguate by other means (id in hand).
    pub fn find_by_creator_name(
        &self,
        creator: &[u8; 32],
        name: &str,
        symbol: &str,
    ) -> Option<[u8; 32]> {
        self.tokens.iter().find_map(|(id, t)| {
            (t.metadata.minter == *creator
                && t.metadata.name == name
                && t.metadata.symbol == symbol)
                .then_some(*id)
        })
    }

    /// Deploy a new token. Returns its deterministic ID.
    pub fn create_token(
        &mut self,
        creator: [u8; 32],
        mut metadata: TokenMetadata,
        initial_supply: u64,
    ) -> Result<[u8; 32], TokenError> {
        metadata.minter = creator;
        metadata.validate()?;
        let id = compute_token_id(&creator, &metadata.name, &metadata.symbol, self.next_nonce);
        if self.tokens.contains_key(&id) {
            return Err(TokenError::DuplicateToken);
        }
        let token = TokenActor::new(id, metadata, initial_supply)?;
        self.tokens.insert(id, token);
        // Nonce must never overflow; saturate at the maximum (practically unreachable)
        self.next_nonce = self.next_nonce.saturating_add(1);
        Ok(id)
    }

    pub fn get(&self, id: &[u8; 32]) -> Option<&TokenActor> {
        self.tokens.get(id)
    }

    pub fn get_mut(&mut self, id: &[u8; 32]) -> Option<&mut TokenActor> {
        self.tokens.get_mut(id)
    }

    pub fn exists(&self, id: &[u8; 32]) -> bool {
        self.tokens.contains_key(id)
    }

    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    pub fn all_token_ids(&self) -> Vec<[u8; 32]> {
        self.tokens.keys().copied().collect()
    }

    /// Dispatch an operation to a token by ID
    pub fn execute(
        &mut self,
        token_id: &[u8; 32],
        caller: [u8; 32],
        op: TokenOp,
    ) -> Result<TokenEvent, TokenError> {
        let token = self
            .tokens
            .get_mut(token_id)
            .ok_or(TokenError::TokenNotFound)?;
        token.execute(caller, op)
    }

    /// Convenience: balance of an account for a token
    pub fn balance_of(&self, token_id: &[u8; 32], account: &[u8; 32]) -> u64 {
        self.tokens
            .get(token_id)
            .map(|t| t.balance_of(account))
            .unwrap_or(0)
    }

    /// Plan a direct token transfer against an immutable `&TokenRegistry`
    /// without cloning the registry.
    pub fn plan_transfer(
        &self,
        token_id: &[u8; 32],
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
    ) -> Result<TokenTxDelta, TokenError> {
        let mut delta = TokenTxDelta::default();
        self.plan_transfer_into(&mut delta, token_id, from, to, amount)?;
        Ok(delta)
    }

    /// Plan a direct token transfer into an existing `TokenTxDelta` overlay.
    pub fn plan_transfer_into(
        &self,
        delta: &mut TokenTxDelta,
        token_id: &[u8; 32],
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
    ) -> Result<(), TokenError> {
        let token = self.tokens.get(token_id).ok_or(TokenError::TokenNotFound)?;
        if amount == 0 {
            return Err(TokenError::ZeroAmount);
        }
        if to == ZERO_ADDRESS || from == ZERO_ADDRESS {
            return Err(TokenError::ZeroAddress);
        }
        if from == to {
            return Err(TokenError::SelfTransfer);
        }
        if token.metadata.paused {
            return Err(TokenError::Paused);
        }
        let from_bal = delta.balance_of(self, token_id, &from);
        if from_bal < amount {
            return Err(TokenError::InsufficientBalance);
        }
        let to_bal = delta.balance_of(self, token_id, &to);
        let new_to = to_bal.checked_add(amount).ok_or(TokenError::Overflow)?;
        let new_from = from_bal - amount;
        delta.balances.insert((*token_id, from), new_from);
        delta.balances.insert((*token_id, to), new_to);
        delta.events.push(TokenEvent::Transfer {
            token_id: *token_id,
            from,
            to,
            amount,
        });
        Ok(())
    }

    /// Plan an allowance-backed `transfer_from` against an immutable
    /// `&TokenRegistry` without cloning the registry.
    pub fn plan_transfer_from(
        &self,
        token_id: &[u8; 32],
        spender: [u8; 32],
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
    ) -> Result<TokenTxDelta, TokenError> {
        let mut delta = TokenTxDelta::default();
        self.plan_transfer_from_into(&mut delta, token_id, spender, from, to, amount)?;
        Ok(delta)
    }

    /// Plan an allowance-backed `transfer_from` into an existing `TokenTxDelta`
    /// overlay.
    pub fn plan_transfer_from_into(
        &self,
        delta: &mut TokenTxDelta,
        token_id: &[u8; 32],
        spender: [u8; 32],
        from: [u8; 32],
        to: [u8; 32],
        amount: u64,
    ) -> Result<(), TokenError> {
        let token = self.tokens.get(token_id).ok_or(TokenError::TokenNotFound)?;
        if amount == 0 {
            return Err(TokenError::ZeroAmount);
        }
        if to == ZERO_ADDRESS || from == ZERO_ADDRESS {
            return Err(TokenError::ZeroAddress);
        }
        if from == to {
            return Err(TokenError::SelfTransfer);
        }
        if token.metadata.paused {
            return Err(TokenError::Paused);
        }
        let current_allowance = delta.allowance(self, token_id, &from, &spender);
        if current_allowance < amount {
            return Err(TokenError::InsufficientAllowance);
        }
        let from_bal = delta.balance_of(self, token_id, &from);
        if from_bal < amount {
            return Err(TokenError::InsufficientBalance);
        }
        let to_bal = delta.balance_of(self, token_id, &to);
        let new_to = to_bal.checked_add(amount).ok_or(TokenError::Overflow)?;
        let remaining = current_allowance - amount;
        let new_from = from_bal - amount;
        delta
            .allowances
            .insert((*token_id, from, spender), remaining);
        delta.balances.insert((*token_id, from), new_from);
        delta.balances.insert((*token_id, to), new_to);
        delta.events.push(TokenEvent::Transfer {
            token_id: *token_id,
            from,
            to,
            amount,
        });
        Ok(())
    }

    /// Plan an `approve` against an immutable `&TokenRegistry` without cloning
    /// the registry.
    pub fn plan_approve(
        &self,
        token_id: &[u8; 32],
        owner: [u8; 32],
        spender: [u8; 32],
        amount: u64,
    ) -> Result<TokenTxDelta, TokenError> {
        let mut delta = TokenTxDelta::default();
        self.plan_approve_into(&mut delta, token_id, owner, spender, amount)?;
        Ok(delta)
    }

    /// Plan an `approve` into an existing `TokenTxDelta` overlay.
    pub fn plan_approve_into(
        &self,
        delta: &mut TokenTxDelta,
        token_id: &[u8; 32],
        owner: [u8; 32],
        spender: [u8; 32],
        amount: u64,
    ) -> Result<(), TokenError> {
        let _token = self.tokens.get(token_id).ok_or(TokenError::TokenNotFound)?;
        if owner == ZERO_ADDRESS || spender == ZERO_ADDRESS {
            return Err(TokenError::ZeroAddress);
        }
        if owner == spender {
            return Err(TokenError::SelfTransfer);
        }
        delta.allowances.insert((*token_id, owner, spender), amount);
        delta.events.push(TokenEvent::Approval {
            token_id: *token_id,
            owner,
            spender,
            amount,
        });
        Ok(())
    }

    /// Plan a `mint` against an immutable `&TokenRegistry` without cloning the
    /// registry.
    pub fn plan_mint(
        &self,
        token_id: &[u8; 32],
        caller: [u8; 32],
        to: [u8; 32],
        amount: u64,
    ) -> Result<TokenTxDelta, TokenError> {
        let mut delta = TokenTxDelta::default();
        self.plan_mint_into(&mut delta, token_id, caller, to, amount)?;
        Ok(delta)
    }

    /// Plan a `mint` into an existing `TokenTxDelta` overlay.
    pub fn plan_mint_into(
        &self,
        delta: &mut TokenTxDelta,
        token_id: &[u8; 32],
        caller: [u8; 32],
        to: [u8; 32],
        amount: u64,
    ) -> Result<(), TokenError> {
        let token = self.tokens.get(token_id).ok_or(TokenError::TokenNotFound)?;
        if token.metadata.minter == ZERO_ADDRESS {
            return Err(TokenError::MinterRenounced);
        }
        if !token.is_minter(&caller) {
            return Err(TokenError::NotMinter);
        }
        if amount == 0 {
            return Err(TokenError::ZeroAmount);
        }
        if to == ZERO_ADDRESS {
            return Err(TokenError::ZeroAddress);
        }
        if token.metadata.paused {
            return Err(TokenError::Paused);
        }
        let cur_total = delta.total_supply(self, token_id);
        let new_total = cur_total.checked_add(amount).ok_or(TokenError::Overflow)?;
        if let Some(cap) = token.metadata.max_supply {
            if new_total > cap {
                return Err(TokenError::SupplyCapExceeded);
            }
        }
        let to_bal = delta.balance_of(self, token_id, &to);
        let new_to = to_bal.checked_add(amount).ok_or(TokenError::Overflow)?;
        delta.balances.insert((*token_id, to), new_to);
        delta.total_supply_overrides.insert(*token_id, new_total);
        delta.events.push(TokenEvent::Mint {
            token_id: *token_id,
            to,
            amount,
            new_total,
        });
        Ok(())
    }

    /// Plan a `burn` against an immutable `&TokenRegistry` without cloning the
    /// registry.
    pub fn plan_burn(
        &self,
        token_id: &[u8; 32],
        caller: [u8; 32],
        from: [u8; 32],
        amount: u64,
    ) -> Result<TokenTxDelta, TokenError> {
        let mut delta = TokenTxDelta::default();
        self.plan_burn_into(&mut delta, token_id, caller, from, amount)?;
        Ok(delta)
    }

    /// Plan a `burn` into an existing `TokenTxDelta` overlay.
    pub fn plan_burn_into(
        &self,
        delta: &mut TokenTxDelta,
        token_id: &[u8; 32],
        caller: [u8; 32],
        from: [u8; 32],
        amount: u64,
    ) -> Result<(), TokenError> {
        let token = self.tokens.get(token_id).ok_or(TokenError::TokenNotFound)?;
        if amount == 0 {
            return Err(TokenError::ZeroAmount);
        }
        if from == ZERO_ADDRESS {
            return Err(TokenError::ZeroAddress);
        }
        if token.metadata.paused {
            return Err(TokenError::Paused);
        }
        let is_admin = token.is_minter(&caller);
        if caller != from && !is_admin {
            return Err(TokenError::NotMinter);
        }
        let from_bal = delta.balance_of(self, token_id, &from);
        if from_bal < amount {
            return Err(TokenError::InsufficientBalance);
        }
        let new_from = from_bal - amount;
        let cur_total = delta.total_supply(self, token_id);
        let new_total = cur_total.checked_sub(amount).ok_or(TokenError::Overflow)?;
        delta.balances.insert((*token_id, from), new_from);
        delta.total_supply_overrides.insert(*token_id, new_total);
        delta.events.push(TokenEvent::Burn {
            token_id: *token_id,
            from,
            amount,
            new_total,
        });
        Ok(())
    }

    /// Commit a planned [`TokenTxDelta`] into this registry.
    ///
    /// Zero balances and zero allowances are removed from `actor.balances` /
    /// `actor.allowances` to stay bit-for-bit identical with sequential
    /// `TokenActor::debit` / `approve` / `transfer_from` and `tokens_digest`.
    pub fn apply_tx_delta(&mut self, delta: TokenTxDelta) {
        for ((token_id, account), bal) in delta.balances {
            if let Some(actor) = self.tokens.get_mut(&token_id) {
                if bal == 0 {
                    actor.balances.remove(&account);
                } else {
                    actor.balances.insert(account, bal);
                }
            }
        }
        for ((token_id, owner, spender), amt) in delta.allowances {
            if let Some(actor) = self.tokens.get_mut(&token_id) {
                if amt == 0 {
                    actor.allowances.remove(&(owner, spender));
                } else {
                    actor.allowances.insert((owner, spender), amt);
                }
            }
        }
        for (token_id, total_supply) in delta.total_supply_overrides {
            if let Some(actor) = self.tokens.get_mut(&token_id) {
                actor.metadata.total_supply = total_supply;
            }
        }
    }
}

/// `(token_id, account)` balance cell key used by the parallel-execution overlay.
pub type TokenBalanceKey = ([u8; 32], [u8; 32]);
/// `(token_id, owner, spender)` allowance cell key used by the overlay.
pub type TokenAllowanceKey = ([u8; 32], [u8; 32], [u8; 32]);

/// Per-key delta overlay for fungible token transactions planned against an
/// immutable `&TokenRegistry`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenTxDelta {
    /// `(token_id, account) -> new_balance` (`0` removes the entry on apply).
    pub balances: HashMap<TokenBalanceKey, u64>,
    /// `(token_id, owner, spender) -> new_allowance` (`0` removes the entry on apply).
    pub allowances: HashMap<TokenAllowanceKey, u64>,
    /// `token_id -> new_total_supply`.
    pub total_supply_overrides: HashMap<[u8; 32], u64>,
    /// Emitted token events in execution order.
    pub events: Vec<TokenEvent>,
}

impl TokenTxDelta {
    /// Read an account's effective balance with this overlay layered over `registry`.
    pub fn balance_of(
        &self,
        registry: &TokenRegistry,
        token_id: &[u8; 32],
        account: &[u8; 32],
    ) -> u64 {
        self.balances
            .get(&(*token_id, *account))
            .copied()
            .unwrap_or_else(|| registry.balance_of(token_id, account))
    }

    /// Read an allowance with this overlay layered over `registry`.
    pub fn allowance(
        &self,
        registry: &TokenRegistry,
        token_id: &[u8; 32],
        owner: &[u8; 32],
        spender: &[u8; 32],
    ) -> u64 {
        self.allowances
            .get(&(*token_id, *owner, *spender))
            .copied()
            .unwrap_or_else(|| {
                registry
                    .get(token_id)
                    .map(|t| t.allowance(owner, spender))
                    .unwrap_or(0)
            })
    }

    /// Read a token's effective total supply with this overlay layered over `registry`.
    pub fn total_supply(&self, registry: &TokenRegistry, token_id: &[u8; 32]) -> u64 {
        self.total_supply_overrides
            .get(token_id)
            .copied()
            .unwrap_or_else(|| {
                registry
                    .get(token_id)
                    .map(|t| t.metadata.total_supply)
                    .unwrap_or(0)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn meta(name: &str, symbol: &str) -> TokenMetadata {
        TokenMetadata {
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals: 6,
            total_supply: 0,
            max_supply: None,
            minter: ZERO_ADDRESS,
            paused: false,
            description: String::new(),
        }
    }

    #[test]
    fn test_create_and_initial_supply() {
        let mut reg = TokenRegistry::new();
        let creator = addr(1);
        let id = reg
            .create_token(creator, meta("Tether USD", "wUSDT"), 1_000_000)
            .unwrap();
        assert!(reg.exists(&id));
        assert_eq!(reg.balance_of(&id, &creator), 1_000_000);
        assert_eq!(reg.get(&id).unwrap().metadata.total_supply, 1_000_000);
        assert_eq!(reg.token_count(), 1);
    }

    #[test]
    fn test_token_ids_are_deterministic_and_unique() {
        let mut reg = TokenRegistry::new();
        let a = addr(1);
        let id1 = reg.create_token(a, meta("Token", "TKN"), 0).unwrap();
        let id2 = reg.create_token(a, meta("Token", "TKN"), 0).unwrap();
        assert_ne!(
            id1, id2,
            "same creator+name must yield different ids via nonce"
        );
        let expected = compute_token_id(&a, "Token", "TKN", 1);
        assert_eq!(id1, expected);
    }

    #[test]
    fn test_transfer_and_balance() {
        let mut reg = TokenRegistry::new();
        let alice = addr(1);
        let bob = addr(2);
        let id = reg.create_token(alice, meta("T", "T"), 1_000).unwrap();

        reg.execute(
            &id,
            alice,
            TokenOp::Transfer {
                to: bob,
                amount: 400,
            },
        )
        .unwrap();
        assert_eq!(reg.balance_of(&id, &alice), 600);
        assert_eq!(reg.balance_of(&id, &bob), 400);
    }

    #[test]
    fn test_transfer_insufficient_balance_rejected() {
        let mut reg = TokenRegistry::new();
        let alice = addr(1);
        let bob = addr(2);
        let id = reg.create_token(alice, meta("T", "T"), 100).unwrap();
        let res = reg.execute(
            &id,
            alice,
            TokenOp::Transfer {
                to: bob,
                amount: 101,
            },
        );
        assert_eq!(res, Err(TokenError::InsufficientBalance));
    }

    #[test]
    fn test_zero_and_self_transfer_rejected() {
        let mut reg = TokenRegistry::new();
        let alice = addr(1);
        let id = reg.create_token(alice, meta("T", "T"), 100).unwrap();
        assert_eq!(
            reg.execute(
                &id,
                alice,
                TokenOp::Transfer {
                    to: addr(2),
                    amount: 0
                }
            ),
            Err(TokenError::ZeroAmount)
        );
        assert_eq!(
            reg.execute(
                &id,
                alice,
                TokenOp::Transfer {
                    to: alice,
                    amount: 5
                }
            ),
            Err(TokenError::SelfTransfer)
        );
    }

    #[test]
    fn test_mint_authority_enforced() {
        let mut reg = TokenRegistry::new();
        let minter = addr(1);
        let attacker = addr(9);
        let id = reg.create_token(minter, meta("T", "T"), 0).unwrap();

        // Attacker cannot mint
        assert_eq!(
            reg.execute(
                &id,
                attacker,
                TokenOp::Mint {
                    to: attacker,
                    amount: 1_000_000
                }
            ),
            Err(TokenError::NotMinter)
        );

        // Minter can mint
        reg.execute(
            &id,
            minter,
            TokenOp::Mint {
                to: attacker,
                amount: 500,
            },
        )
        .unwrap();
        assert_eq!(reg.balance_of(&id, &attacker), 500);
        assert_eq!(reg.get(&id).unwrap().metadata.total_supply, 500);
    }

    #[test]
    fn test_supply_cap_enforced() {
        let mut reg = TokenRegistry::new();
        let minter = addr(1);
        let mut m = meta("Capped", "CAP");
        m.max_supply = Some(1_000);
        let id = reg.create_token(minter, m, 900).unwrap();

        reg.execute(
            &id,
            minter,
            TokenOp::Mint {
                to: minter,
                amount: 100,
            },
        )
        .unwrap();
        // Next mint exceeds cap
        assert_eq!(
            reg.execute(
                &id,
                minter,
                TokenOp::Mint {
                    to: minter,
                    amount: 1
                }
            ),
            Err(TokenError::SupplyCapExceeded)
        );
    }

    #[test]
    fn test_burn_by_holder_and_admin() {
        let mut reg = TokenRegistry::new();
        let minter = addr(1);
        let holder = addr(2);
        let id = reg.create_token(minter, meta("T", "T"), 1_000).unwrap();
        reg.execute(
            &id,
            minter,
            TokenOp::Transfer {
                to: holder,
                amount: 300,
            },
        )
        .unwrap();

        // Holder burns own tokens
        reg.execute(
            &id,
            holder,
            TokenOp::Burn {
                from: holder,
                amount: 100,
            },
        )
        .unwrap();
        assert_eq!(reg.balance_of(&id, &holder), 200);
        assert_eq!(reg.get(&id).unwrap().metadata.total_supply, 900);

        // Admin can burn from anyone
        reg.execute(
            &id,
            minter,
            TokenOp::Burn {
                from: holder,
                amount: 200,
            },
        )
        .unwrap();
        assert_eq!(reg.balance_of(&id, &holder), 0);

        // Non-admin cannot burn someone else's tokens
        assert_eq!(
            reg.execute(
                &id,
                holder,
                TokenOp::Burn {
                    from: minter,
                    amount: 1
                }
            ),
            Err(TokenError::NotMinter)
        );
    }

    #[test]
    fn test_approve_and_transfer_from() {
        let mut reg = TokenRegistry::new();
        let owner = addr(1);
        let spender = addr(2);
        let dest = addr(3);
        let id = reg.create_token(owner, meta("T", "T"), 1_000).unwrap();

        reg.execute(
            &id,
            owner,
            TokenOp::Approve {
                spender,
                amount: 500,
            },
        )
        .unwrap();
        assert_eq!(reg.get(&id).unwrap().allowance(&owner, &spender), 500);

        // Spender moves 300
        reg.execute(
            &id,
            spender,
            TokenOp::TransferFrom {
                from: owner,
                to: dest,
                amount: 300,
            },
        )
        .unwrap();
        assert_eq!(reg.balance_of(&id, &dest), 300);
        assert_eq!(reg.get(&id).unwrap().allowance(&owner, &spender), 200);

        // Spender tries to exceed remaining allowance
        assert_eq!(
            reg.execute(
                &id,
                spender,
                TokenOp::TransferFrom {
                    from: owner,
                    to: dest,
                    amount: 201
                }
            ),
            Err(TokenError::InsufficientAllowance)
        );
    }

    #[test]
    fn p5_allowance_double_spend_and_front_run_race() {
        // P5 ATTACK (allowance double-spend): a spender with allowance N must
        // not move more than N total no matter how transfers are sequenced.
        // `transfer_from` checks allowance AND balance BEFORE mutating either
        // (CEI), and consumes the allowance atomically, so a second
        // transfer_from for the full N fails and leaves balances untouched.
        let mut reg = TokenRegistry::new();
        let owner = addr(1);
        let spender = addr(2);
        let dest = addr(3);
        let id = reg.create_token(owner, meta("T", "T"), 1_000).unwrap();
        reg.execute(
            &id,
            owner,
            TokenOp::Approve {
                spender,
                amount: 500,
            },
        )
        .unwrap();
        reg.execute(
            &id,
            spender,
            TokenOp::TransferFrom {
                from: owner,
                to: dest,
                amount: 500,
            },
        )
        .unwrap();
        assert_eq!(reg.balance_of(&id, &dest), 500);
        assert_eq!(reg.get(&id).unwrap().allowance(&owner, &spender), 0);
        // Replay of the same full-allowance transfer: refused, nothing moves.
        assert_eq!(
            reg.execute(
                &id,
                spender,
                TokenOp::TransferFrom {
                    from: owner,
                    to: dest,
                    amount: 500
                }
            ),
            Err(TokenError::InsufficientAllowance)
        );
        assert_eq!(
            reg.balance_of(&id, &dest),
            500,
            "failed replay must not move funds"
        );
        assert_eq!(reg.balance_of(&id, &owner), 500);
        // The classic approve front-run (approve N -> spend N -> approve M is
        // raced so the spender gets N+M) is inherent to overwriting `approve`;
        // the ledger's answer is the atomic arms — pin that they exist and
        // behave: increase/decrease adjust by delta, and decrease past zero
        // fails instead of wrapping.
        reg.execute(
            &id,
            owner,
            TokenOp::Approve {
                spender,
                amount: 100,
            },
        )
        .unwrap();
        reg.execute(
            &id,
            owner,
            TokenOp::IncreaseAllowance { spender, delta: 50 },
        )
        .unwrap();
        assert_eq!(reg.get(&id).unwrap().allowance(&owner, &spender), 150);
        reg.execute(
            &id,
            owner,
            TokenOp::DecreaseAllowance { spender, delta: 50 },
        )
        .unwrap();
        assert_eq!(reg.get(&id).unwrap().allowance(&owner, &spender), 100);
        assert_eq!(
            reg.execute(
                &id,
                owner,
                TokenOp::DecreaseAllowance {
                    spender,
                    delta: 101
                }
            ),
            Err(TokenError::AllowanceUnderflow)
        );
    }

    #[test]
    fn p5_metadata_spoofing_same_symbol_is_a_different_token() {
        // P5 ATTACK (metadata spoofing): two tokens share name/symbol. The
        // ledger keys EVERYTHING (balances, allowances) by token id
        // (creator || name || symbol || nonce), never by symbol, so a lookup
        // by symbol alone can never confuse them. Pin: same symbol, distinct
        // ids, isolated balances.
        let mut reg = TokenRegistry::new();
        let honest = addr(1);
        let spoof = addr(9);
        let id_honest = reg
            .create_token(honest, meta("Stellereum", "STELL"), 1_000)
            .unwrap();
        let id_spoof = reg
            .create_token(spoof, meta("Stellereum", "STELL"), 1_000)
            .unwrap();
        assert_ne!(
            id_honest, id_spoof,
            "same symbol must still be distinct token ids"
        );
        assert_eq!(reg.balance_of(&id_honest, &honest), 1_000);
        assert_eq!(
            reg.balance_of(&id_spoof, &honest),
            0,
            "victim holds none of the spoof token"
        );
        assert_eq!(
            reg.balance_of(&id_honest, &spoof),
            0,
            "spoofer holds none of the real token"
        );
        // A transfer on the spoof token cannot touch the honest one.
        reg.execute(
            &id_spoof,
            spoof,
            TokenOp::Transfer {
                to: honest,
                amount: 10,
            },
        )
        .unwrap();
        assert_eq!(
            reg.balance_of(&id_honest, &honest),
            1_000,
            "honest balance untouched"
        );
        assert_eq!(reg.balance_of(&id_spoof, &honest), 10);
    }

    #[test]
    fn test_pause_blocks_operations() {
        let mut reg = TokenRegistry::new();
        let minter = addr(1);
        let user = addr(2);
        let id = reg.create_token(minter, meta("T", "T"), 1_000).unwrap();

        reg.execute(&id, minter, TokenOp::Pause).unwrap();
        assert_eq!(
            reg.execute(
                &id,
                minter,
                TokenOp::Transfer {
                    to: user,
                    amount: 10
                }
            ),
            Err(TokenError::Paused)
        );
        assert_eq!(
            reg.execute(
                &id,
                minter,
                TokenOp::Mint {
                    to: user,
                    amount: 10
                }
            ),
            Err(TokenError::Paused)
        );

        // Non-minter cannot unpause
        assert_eq!(
            reg.execute(&id, user, TokenOp::Unpause),
            Err(TokenError::NotMinter)
        );

        reg.execute(&id, minter, TokenOp::Unpause).unwrap();
        reg.execute(
            &id,
            minter,
            TokenOp::Transfer {
                to: user,
                amount: 10,
            },
        )
        .unwrap();
        assert_eq!(reg.balance_of(&id, &user), 10);
    }

    #[test]
    fn test_renounce_minter_is_irreversible() {
        let mut reg = TokenRegistry::new();
        let minter = addr(1);
        let id = reg.create_token(minter, meta("T", "T"), 1_000).unwrap();

        reg.execute(&id, minter, TokenOp::RenounceMinter).unwrap();
        assert_eq!(reg.get(&id).unwrap().metadata.minter, ZERO_ADDRESS);

        // No more minting possible
        assert_eq!(
            reg.execute(
                &id,
                minter,
                TokenOp::Mint {
                    to: minter,
                    amount: 1
                }
            ),
            Err(TokenError::MinterRenounced)
        );
        // Cannot set minter either
        assert_eq!(
            reg.execute(
                &id,
                minter,
                TokenOp::SetMinter {
                    new_minter: addr(5)
                }
            ),
            Err(TokenError::MinterRenounced)
        );
        // But transfers still work
        reg.execute(
            &id,
            minter,
            TokenOp::Transfer {
                to: addr(2),
                amount: 100,
            },
        )
        .unwrap();
    }

    #[test]
    fn test_set_minter_transfers_authority() {
        let mut reg = TokenRegistry::new();
        let old = addr(1);
        let new = addr(2);
        let id = reg.create_token(old, meta("T", "T"), 0).unwrap();

        reg.execute(&id, old, TokenOp::SetMinter { new_minter: new })
            .unwrap();
        assert_eq!(
            reg.execute(&id, old, TokenOp::Mint { to: old, amount: 1 }),
            Err(TokenError::NotMinter)
        );
        reg.execute(
            &id,
            new,
            TokenOp::Mint {
                to: new,
                amount: 42,
            },
        )
        .unwrap();
        assert_eq!(reg.balance_of(&id, &new), 42);
    }

    #[test]
    fn test_metadata_validation() {
        let mut reg = TokenRegistry::new();
        let creator = addr(1);
        assert_eq!(
            reg.create_token(creator, meta("", "T"), 0),
            Err(TokenError::MetadataInvalid)
        );
        assert_eq!(
            reg.create_token(creator, meta("N", ""), 0),
            Err(TokenError::MetadataInvalid)
        );

        let mut bad = meta("N", "T");
        bad.decimals = 19;
        assert_eq!(
            reg.create_token(creator, bad, 0),
            Err(TokenError::MetadataInvalid)
        );
    }

    #[test]
    fn test_execute_on_missing_token_fails() {
        let mut reg = TokenRegistry::new();
        let res = reg.execute(
            &addr(99),
            addr(1),
            TokenOp::Mint {
                to: addr(1),
                amount: 1,
            },
        );
        assert_eq!(res, Err(TokenError::TokenNotFound));
    }

    #[test]
    fn test_owner_token_page_advances_past_scan_cap() {
        let mut reg = TokenRegistry::new();
        let minter = addr(1);
        let holder = addr(2);
        let mut ids = Vec::new();
        for i in 0..5 {
            let name = format!("Token{i}");
            let sym = format!("TK{i}");
            ids.push(reg.create_token(minter, meta(&name, &sym), 1_000).unwrap());
        }
        ids.sort();
        let target_id = ids[4];
        reg.execute(
            &target_id,
            minter,
            TokenOp::Transfer {
                to: holder,
                amount: 250,
            },
        )
        .unwrap();

        let p1 = reg.owner_token_page(&holder, None, false, None, 10, 2);
        assert!(p1.items.is_empty());
        assert!(p1.truncated);
        assert!(p1.has_more);
        assert_eq!(p1.scanned, 2);
        assert_eq!(p1.next_cursor, Some(ids[1]));

        let p2 = reg.owner_token_page(&holder, None, false, p1.next_cursor, 10, 2);
        assert!(p2.items.is_empty());
        assert!(p2.truncated);
        assert!(p2.has_more);
        assert_eq!(p2.scanned, 2);
        assert_eq!(p2.next_cursor, Some(ids[3]));

        let p3 = reg.owner_token_page(&holder, None, false, p2.next_cursor, 10, 2);
        assert!(!p3.truncated);
        assert!(!p3.has_more);
        assert_eq!(p3.scanned, 1);
        assert_eq!(p3.next_cursor, None);
        assert_eq!(
            p3.items,
            vec![TokenHolding {
                token_id: target_id,
                holder,
                balance: 250,
            }]
        );
    }
}
