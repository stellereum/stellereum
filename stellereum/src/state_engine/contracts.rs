use super::types::{
    contract_abi_key, contract_key, contract_source_key, token_balance_key, token_supply_key,
};
use super::{compute_contract_address, ContractCallOutcome, DeployOutcome, InMemoryStateEngine};
use crate::cell::MerkleProof;
use crate::token::{TokenError, TokenEvent, TokenMetadata, TokenOp};

impl InMemoryStateEngine {
    // ==================== Fungible Token (STS) Integration ====================

    /// Deploy a new on-chain fungible token. Returns its deterministic token ID.
    /// Initial balances and total supply are committed into the state trie.
    pub async fn create_token(
        &self,
        creator: [u8; 32],
        metadata: TokenMetadata,
        initial_supply: u64,
    ) -> Result<[u8; 32], TokenError> {
        let mut tokens = self.tokens_write().await;
        let id = tokens.create_token(creator, metadata, initial_supply)?;

        // Commit initial balances + supply into the state trie so they become
        // part of the consensus state root and are SPV-provable.
        let mut trie = self.state_trie.write().await;
        if let Some(token) = tokens.get(&id) {
            let accounts: Vec<[u8; 32]> = token.balances.keys().copied().collect();
            for acct in accounts {
                let bal = token.balance_of(&acct);
                let key = token_balance_key(&id, &acct);
                trie.insert(&key, &bal.to_be_bytes());
            }
            trie.insert(
                &token_supply_key(&id),
                &token.metadata.total_supply.to_be_bytes(),
            );
        }
        Ok(id)
    }

    // ==================== WASM Contracts (on-chain) ====================

    /// Deploy a validated WASM contract and commit its code hash to the state
    /// trie (SPV-provable). Returns the deterministic contract address.
    pub async fn deploy_contract(
        &self,
        creator: [u8; 32],
        code: Vec<u8>,
        now: u64,
    ) -> Result<[u8; 32], crate::contract::ContractError> {
        let mut contracts = self.contracts_write().await;
        let address = contracts.deploy(creator, code, now)?;
        let code_hash = contracts
            .get(&address)
            .map(|c| c.code_hash)
            .unwrap_or([0u8; 32]);
        let mut trie = self.state_trie.write().await;
        trie.insert(&contract_key(&address), &code_hash);
        Ok(address)
    }

    /// Deploy a validated WASM contract with a typed ABI manifest attached.
    ///
    /// The manifest is committed to the state trie next to the code hash.
    pub async fn deploy_contract_with_abi(
        &self,
        creator: [u8; 32],
        code: Vec<u8>,
        now: u64,
        abi: crate::contract_abi::ContractAbi,
    ) -> Result<[u8; 32], crate::contract::ContractError> {
        let mut contracts = self.contracts_write().await;
        let address = contracts.deploy_with_abi(creator, code, now, abi.clone())?;
        let code_hash = contracts
            .get(&address)
            .map(|c| c.code_hash)
            .unwrap_or([0u8; 32]);
        let mut trie = self.state_trie.write().await;
        trie.insert(&contract_key(&address), &code_hash);
        trie.insert(&contract_abi_key(&address), abi.to_json().as_bytes());
        Ok(address)
    }

    /// Attach (or replace) the ABI manifest of a deployed contract and commit
    /// it to the state trie next to the code hash.
    pub async fn set_contract_abi(
        &self,
        address: &[u8; 32],
        abi: crate::contract_abi::ContractAbi,
    ) -> Result<(), crate::contract::ContractError> {
        {
            let mut contracts = self.contracts_write().await;
            contracts.set_abi(address, abi.clone())?;
        }
        let mut trie = self.state_trie.write().await;
        trie.insert(&contract_abi_key(address), abi.to_json().as_bytes());
        Ok(())
    }

    /// The ABI manifest of a deployed contract, if one is attached.
    pub async fn get_contract_abi(
        &self,
        address: &[u8; 32],
    ) -> Option<crate::contract_abi::ContractAbi> {
        self.contracts.read().await.abi(address).cloned()
    }

    /// The JSON ABI manifest of a deployed contract, if one is attached.
    pub async fn get_contract_abi_json(&self, address: &[u8; 32]) -> Option<String> {
        self.contracts.read().await.abi_json(address)
    }

    /// The on-chain code hash of a deployed contract, if it exists.
    pub async fn get_contract_code_hash(&self, address: &[u8; 32]) -> Option<[u8; 32]> {
        self.contracts
            .read()
            .await
            .get(address)
            .map(|c| c.code_hash)
    }

    /// The registered verified-source fingerprint of a deployed contract, if
    /// one was registered (`None` = unverified).
    pub async fn get_contract_source_hash(&self, address: &[u8; 32]) -> Option<[u8; 32]> {
        self.contracts.read().await.source_hash(address)
    }

    /// Register the verified-source fingerprint of a deployed contract and
    /// commit it to the state trie next to the code hash.
    ///
    /// Only the contract CREATOR may register (checked here); the RPC layer
    /// additionally requires the creator's signature over the registration
    /// message, so this state moves only by an explicit, signed action —
    /// never as a side effect of verification (which is read-only).
    pub async fn register_contract_source(
        &self,
        address: &[u8; 32],
        source_hash: [u8; 32],
        caller: [u8; 32],
    ) -> Result<(), crate::contract::ContractError> {
        {
            let mut contracts = self.contracts_write().await;
            contracts.register_source(address, source_hash, caller)?;
        }
        let mut trie = self.state_trie.write().await;
        trie.insert(&contract_source_key(address), &source_hash);
        Ok(())
    }

    /// Deploy a validated WASM contract with deterministic address derivation:
    /// BLAKE3("STELL_CONTRACT" || code_hash || salt).
    /// Deploys WASM code to state trie under contract address and commits code_hash.
    pub async fn deploy_contract_deterministic(
        &self,
        creator: [u8; 32],
        code: Vec<u8>,
        salt: &[u8],
        now: u64,
    ) -> Result<DeployOutcome, crate::contract::ContractError> {
        self.deploy_contract_deterministic_inner(creator, code, salt, now, None)
            .await
    }

    /// Deploy a validated WASM contract with deterministic address derivation
    /// and a typed ABI manifest attached.
    pub async fn deploy_contract_deterministic_with_abi(
        &self,
        creator: [u8; 32],
        code: Vec<u8>,
        salt: &[u8],
        now: u64,
        abi: crate::contract_abi::ContractAbi,
    ) -> Result<DeployOutcome, crate::contract::ContractError> {
        self.deploy_contract_deterministic_inner(creator, code, salt, now, Some(abi))
            .await
    }

    async fn deploy_contract_deterministic_inner(
        &self,
        creator: [u8; 32],
        code: Vec<u8>,
        salt: &[u8],
        now: u64,
        abi: Option<crate::contract_abi::ContractAbi>,
    ) -> Result<DeployOutcome, crate::contract::ContractError> {
        crate::contract::ContractRegistry::validate_code(&code)?;
        if let Some(a) = &abi {
            a.validate()
                .map_err(|e| crate::contract::ContractError::InvalidAbi(e.to_string()))?;
        }
        let code_hash: [u8; 32] = *blake3::hash(&code).as_bytes();
        let address = compute_contract_address(&code_hash, salt);

        let mut contracts = self.contracts_write().await;
        if contracts.contracts.contains_key(&address) {
            return Err(crate::contract::ContractError::AlreadyExists);
        }
        contracts.contracts.insert(
            address,
            crate::contract::Contract {
                address,
                creator,
                code_hash,
                code: code.clone(),
                storage: std::collections::HashMap::new(),
                created_at: now,
                paused: false,
                balance: 0,
                abi: abi.clone(),
                source_hash: None,
            },
        );
        drop(contracts);

        let mut trie = self.state_trie.write().await;
        // Deploy WASM code to state trie under contract address
        trie.insert(&address, &code);
        trie.insert(&contract_key(&address), &code_hash);
        match &abi {
            Some(a) => {
                trie.insert(&contract_abi_key(&address), a.to_json().as_bytes());
            }
            None => {
                trie.remove(&contract_abi_key(&address));
            }
        }
        drop(trie);

        let contract_address_stl57 = crate::address::encode_stl57_address(&address);
        Ok(DeployOutcome {
            contract_address: address,
            contract_address_stl57,
            code_hash,
        })
    }

    /// Retrieve WASM code deployed in state trie under contract address.
    pub async fn get_contract_code_from_trie(&self, address: &[u8; 32]) -> Option<Vec<u8>> {
        let trie = self.state_trie.read().await;
        trie.get(address).map(|b| b.to_vec())
    }

    /// Call an exported method on a deployed contract and return a structured outcome.
    /// Following the TON / Near receipt model: (status, return_value, gas_used, events).
    pub async fn call_contract_structured(
        &self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
    ) -> ContractCallOutcome {
        self.sync_contract_balance(address).await;
        let res = {
            let mut contracts = self.contracts_write().await;
            contracts.call(address, method, arg, fuel)
        };
        self.sync_account_balance_from_contract(address).await;
        match res {
            Ok((val, used, events, messages)) => {
                if !messages.is_empty() {
                    let _ = self.process_contract_outbound_messages(&messages).await;
                }
                ContractCallOutcome {
                    status: "success".to_string(),
                    return_value: Some(val),
                    gas_used: used,
                    events,
                    error: None,
                }
            }
            Err(e) => {
                let (gas_used, err_msg) = match &e {
                    crate::contract::ContractError::OutOfFuel => (fuel, e.to_string()),
                    _ => (0, e.to_string()),
                };
                ContractCallOutcome {
                    status: "failed".to_string(),
                    return_value: None,
                    gas_used,
                    events: Vec::new(),
                    error: Some(err_msg),
                }
            }
        }
    }

    /// Call an exported method with several `i64` parameters and return a
    /// structured outcome.
    pub async fn call_contract_args_structured(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        fuel: u64,
    ) -> ContractCallOutcome {
        self.sync_contract_balance(address).await;
        let res = {
            let mut contracts = self.contracts_write().await;
            contracts.call_args(address, method, args, fuel)
        };
        self.sync_account_balance_from_contract(address).await;
        match res {
            Ok((val, used, events, messages)) => {
                if !messages.is_empty() {
                    let _ = self.process_contract_outbound_messages(&messages).await;
                }
                ContractCallOutcome {
                    status: "success".to_string(),
                    return_value: Some(val),
                    gas_used: used,
                    events,
                    error: None,
                }
            }
            Err(e) => {
                let (gas_used, err_msg) = match &e {
                    crate::contract::ContractError::OutOfFuel => (fuel, e.to_string()),
                    _ => (0, e.to_string()),
                };
                ContractCallOutcome {
                    status: "failed".to_string(),
                    return_value: None,
                    gas_used,
                    events: Vec::new(),
                    error: Some(err_msg),
                }
            }
        }
    }

    /// Call an exported method with typed ABI arguments and return a
    /// structured outcome. The contract's ABI manifest is authoritative.
    pub async fn call_contract_abi_structured(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[crate::contract_abi::AbiValue],
        fuel: u64,
    ) -> ContractCallOutcome {
        self.sync_contract_balance(address).await;
        let res = {
            let mut contracts = self.contracts_write().await;
            contracts.call_abi(address, method, args, fuel)
        };
        self.sync_account_balance_from_contract(address).await;
        match res {
            Ok(outcome) => {
                if !outcome.outbound_messages.is_empty() {
                    let _ = self
                        .process_contract_outbound_messages(&outcome.outbound_messages)
                        .await;
                }
                ContractCallOutcome {
                    status: "success".to_string(),
                    return_value: Some(outcome.result),
                    gas_used: outcome.fuel_used,
                    events: outcome.events,
                    error: None,
                }
            }
            Err(e) => {
                let (gas_used, err_msg) = match &e {
                    crate::contract::ContractError::OutOfFuel => (fuel, e.to_string()),
                    _ => (0, e.to_string()),
                };
                ContractCallOutcome {
                    status: "failed".to_string(),
                    return_value: None,
                    gas_used,
                    events: Vec::new(),
                    error: Some(err_msg),
                }
            }
        }
    }

    /// Call a contract with structured outcome and optional value transfer.
    ///
    /// Preserves legacy (`< H`, `hardened == false`) behavior; hardened (`>= H`)
    /// callers should invoke [`Self::call_contract_structured_with_value_hardened`].
    pub async fn call_contract_structured_with_value(
        &self,
        caller: Option<[u8; 32]>,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
        value: u64,
    ) -> ContractCallOutcome {
        self.call_contract_structured_with_value_hardened(
            caller, address, method, arg, fuel, value, false,
        )
        .await
    }

    /// Call a contract with structured outcome, optional value transfer, and
    /// explicit `hardened` (`>= H`) rollback semantics.
    ///
    /// - When `hardened == false`: preserves pre-gate behavior.
    /// - When `hardened == true`: if the call fails (including `OutOfFuel`,
    ///   `Trapped`, `NotFound`, `Paused`, `NoSuchMethod`), any transferred `value`
    ///   is rolled back from both `Contract.balance` and `accounts[address]`
    ///   back to `accounts[caller]`.
    #[allow(clippy::too_many_arguments)]
    // GATE: hardened structured contract call mirrors call_contract_structured_with_value plus hardened toggle.
    pub async fn call_contract_structured_with_value_hardened(
        &self,
        caller: Option<[u8; 32]>,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
        value: u64,
        hardened: bool,
    ) -> ContractCallOutcome {
        let debited_caller: Option<[u8; 32]> = if value > 0 {
            // A value transfer needs a debited caller. The old body silently
            // ignored `value` when `caller` was None and swallowed a failed
            // credit; both are value-path bugs (no caller -> nothing may be
            // promised, a failed credit -> the debit must be undone).
            let Some(c) = caller else {
                return ContractCallOutcome {
                    status: "failed".to_string(),
                    return_value: None,
                    gas_used: 0,
                    events: Vec::new(),
                    error: Some("value transfer requires a caller (none was supplied)".to_string()),
                };
            };
            if let Err(e) = self.debit_native(&c, value).await {
                return ContractCallOutcome {
                    status: "failed".to_string(),
                    return_value: None,
                    gas_used: 0,
                    events: Vec::new(),
                    error: Some(format!("insufficient funds to transfer value: {e}")),
                };
            }
            // The debit already happened: this is a TRANSFER, never a mint
            // (the capped `credit_native` would consume supply headroom and
            // could drop the value at the cap).
            if let Err(e) = self.credit_native_transfer(address, value).await {
                // Undo the debit fail-closed. A refund failure here is
                // impossible in a consistent ledger (the account was just
                // debited), but never swallow it.
                if let Err(refund_err) = self.credit_native_transfer(&c, value).await {
                    tracing::error!(
                        "contract value transfer: credit to {} failed ({e}) AND the refund to {} failed ({refund_err}); value is not conserved",
                        hex::encode(&address[..8]),
                        hex::encode(&c[..8])
                    );
                    return ContractCallOutcome {
                        status: "failed".to_string(),
                        return_value: None,
                        gas_used: 0,
                        events: Vec::new(),
                        error: Some(format!(
                            "value credit failed ({e}) and refund failed ({refund_err})"
                        )),
                    };
                }
                return ContractCallOutcome {
                    status: "failed".to_string(),
                    return_value: None,
                    gas_used: 0,
                    events: Vec::new(),
                    error: Some(format!("value credit failed: {e}")),
                };
            }
            Some(c)
        } else {
            None
        };

        if !hardened {
            return self
                .call_contract_structured(address, method, arg, fuel)
                .await;
        }

        let prev_contract_balance = self.contracts.read().await.get(address).map(|c| c.balance);
        self.sync_contract_balance(address).await;
        let caller_addr = caller.unwrap_or([0u8; 32]);
        let call_ctx = crate::contract::ContractCallContext {
            caller: caller_addr,
            value,
            block_time: 0,
            block_hash: [0u8; 32],
        };
        let res = {
            let mut contracts = self.contracts_write().await;
            contracts.call_with_context_hardened(
                address,
                method,
                arg,
                fuel,
                &call_ctx,
                caller_addr,
                caller_addr,
                true,
            )
        };
        match res {
            Ok(outcome) => {
                self.sync_account_balance_from_contract(address).await;
                if !outcome.outbound_messages.is_empty() {
                    let _ = self
                        .process_contract_outbound_messages(&outcome.outbound_messages)
                        .await;
                }
                ContractCallOutcome {
                    status: "success".to_string(),
                    return_value: Some(outcome.result),
                    gas_used: outcome.fuel_used,
                    events: outcome.events,
                    error: None,
                }
            }
            Err(e) => {
                if let Some(prev) = prev_contract_balance {
                    let mut contracts = self.contracts_write().await;
                    if let Some(c) = contracts.contracts.get_mut(address) {
                        c.balance = prev;
                    }
                }
                let mut rollback_note: Option<String> = None;
                if let Some(c) = debited_caller {
                    if let Err(debit_err) = self.debit_native(address, value).await {
                        tracing::error!(
                            "hardened contract value rollback: failed to debit {} from {}: {debit_err}",
                            value,
                            hex::encode(&address[..8])
                        );
                        rollback_note = Some(format!("value rollback debit failed: {debit_err}"));
                    } else if let Err(refund_err) = self.credit_native_transfer(&c, value).await {
                        tracing::error!(
                            "hardened contract value rollback: debited {} from {} but refund to {} failed: {refund_err}",
                            value,
                            hex::encode(&address[..8]),
                            hex::encode(&c[..8])
                        );
                        rollback_note = Some(format!("value rollback refund failed: {refund_err}"));
                    }
                }
                let (gas_used, mut err_msg) = match &e {
                    crate::contract::ContractError::OutOfFuel => (fuel, e.to_string()),
                    _ => (0, e.to_string()),
                };
                if let Some(note) = rollback_note {
                    err_msg = format!("{err_msg}; {note}");
                }
                ContractCallOutcome {
                    status: "failed".to_string(),
                    return_value: None,
                    gas_used,
                    events: Vec::new(),
                    error: Some(err_msg),
                }
            }
        }
    }

    /// Process outbound contract messages:
    /// - If recipient is local, route to actor inbox (`inbox.push_back`).
    /// - If recipient is on another shard, route to `cross_shard_out` with bounce capability.
    pub async fn process_contract_outbound_messages(
        &self,
        messages: &[crate::contract::ContractMessage],
    ) -> Result<(), String> {
        if messages.is_empty() {
            return Ok(());
        }
        let my_shard = self.shard_id();
        let sharded = self.cross_shard_enabled();
        let topology = self.shard_topology.read().await.clone();
        let mut map = self.accounts.write().await;
        let mut xout = self.cross_shard_out.write().await;
        crate::svm::Svm::route_contract_messages_with_topology(
            messages, &mut map, &mut xout, my_shard, sharded, &topology,
        );
        Ok(())
    }

    /// Call an exported `(i64) -> i64` method on a deployed contract.
    pub async fn call_contract(
        &self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
    ) -> Result<(i64, u64), crate::contract::ContractError> {
        self.sync_contract_balance(address).await;
        let (val, used, _events, messages) = self
            .contracts_write()
            .await
            .call(address, method, arg, fuel)?;
        self.sync_account_balance_from_contract(address).await;
        if !messages.is_empty() {
            let _ = self.process_contract_outbound_messages(&messages).await;
        }
        Ok((val, used))
    }

    /// Call an exported method with several `i64` parameters on a deployed contract.
    pub async fn call_contract_args(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        fuel: u64,
    ) -> Result<(i64, u64), crate::contract::ContractError> {
        self.sync_contract_balance(address).await;
        let (val, used, _events, messages) = self
            .contracts_write()
            .await
            .call_args(address, method, args, fuel)?;
        self.sync_account_balance_from_contract(address).await;
        if !messages.is_empty() {
            let _ = self.process_contract_outbound_messages(&messages).await;
        }
        Ok((val, used))
    }

    /// Call a contract and return the emitted events.
    pub async fn call_contract_with_events(
        &self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
    ) -> Result<(i64, u64, Vec<crate::contract::ContractEvent>), crate::contract::ContractError>
    {
        self.sync_contract_balance(address).await;
        let (val, used, events, messages) = self
            .contracts_write()
            .await
            .call(address, method, arg, fuel)?;
        self.sync_account_balance_from_contract(address).await;
        if !messages.is_empty() {
            let _ = self.process_contract_outbound_messages(&messages).await;
        }
        Ok((val, used, events))
    }

    /// Call a contract and return events along with outbound messages.
    pub async fn call_contract_with_messages(
        &self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
    ) -> Result<
        (
            i64,
            u64,
            Vec<crate::contract::ContractEvent>,
            Vec<crate::contract::ContractMessage>,
        ),
        crate::contract::ContractError,
    > {
        self.sync_contract_balance(address).await;
        let (val, used, events, messages) = self
            .contracts_write()
            .await
            .call(address, method, arg, fuel)?;
        self.sync_account_balance_from_contract(address).await;
        if !messages.is_empty() {
            let _ = self.process_contract_outbound_messages(&messages).await;
        }
        Ok((val, used, events, messages))
    }

    pub async fn sync_contract_balance(&self, address: &[u8; 32]) {
        if let Some(acc) = self.accounts.read().await.get(address) {
            let mut reg = self.contracts_write().await;
            if let Some(c) = reg.contracts.get_mut(address) {
                if acc.balance > c.balance {
                    c.balance = acc.balance;
                }
            }
        }
    }

    pub async fn sync_account_balance_from_contract(&self, address: &[u8; 32]) {
        let reg = self.contracts.read().await;
        if let Some(c) = reg.get(address) {
            let mut map = self.accounts.write().await;
            if let Some(acc) = map.get_mut(address) {
                acc.balance = c.balance;
            }
        }
    }

    /// Read-only getter execution against a cloned working state of the contract (matching TON runGetMethod / Near call_function / MultiversX vm-values/query).
    ///
    /// - Read-only execution against a cloned working state of the contract.
    /// - Zero state changes: mutations to storage or balances are immediately discarded.
    /// - Zero gas fee charged to any account.
    /// - Bounded by a safety fuel limit (e.g. 5,000,000 fuel) to prevent infinite loops.
    pub async fn run_get_method(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        fuel_limit: Option<u64>,
    ) -> crate::contract::GetMethodResponse {
        let contracts = self.contracts.read().await;
        contracts.run_get_method(address, method, args, fuel_limit)
    }

    /// Read-only getter execution validated against the contract's ABI
    /// manifest: the method and its arguments must match the manifest, and
    /// the typed return value is decoded from the outcome.
    pub async fn run_get_method_typed(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[crate::contract_abi::AbiValue],
        fuel_limit: Option<u64>,
    ) -> crate::contract::GetMethodResponse {
        let contracts = self.contracts.read().await;
        contracts.run_get_method_typed(address, method, args, fuel_limit)
    }

    /// Read-only getter execution with a single `i64` argument.
    pub async fn run_get_method_single(
        &self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel_limit: Option<u64>,
    ) -> crate::contract::GetMethodResponse {
        self.run_get_method(address, method, &[arg], fuel_limit)
            .await
    }

    /// Read-only getter execution with optional block height pinning.
    pub async fn run_get_method_with_height(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        fuel_limit: Option<u64>,
        current_height: u64,
        pin_height: Option<u64>,
    ) -> crate::contract::GetMethodResponse {
        if let Some(pin) = pin_height {
            if pin > current_height {
                return crate::contract::GetMethodResponse::error(
                    format!("pinned block height {pin} exceeds current finalized height {current_height}"),
                    0,
                );
            }
        }
        self.run_get_method(address, method, args, fuel_limit).await
    }

    pub async fn get_contract(&self, address: &[u8; 32]) -> Option<crate::contract::Contract> {
        self.contracts.read().await.get(address).cloned()
    }

    pub async fn contract_count(&self) -> usize {
        self.contracts.read().await.contracts.len()
    }

    pub async fn all_contract_addresses(&self) -> Vec<[u8; 32]> {
        self.contracts
            .read()
            .await
            .contracts
            .keys()
            .copied()
            .collect()
    }

    /// Execute a token operation and commit every affected balance to the state trie.
    /// This is the canonical entry point for on-chain token activity.
    pub async fn token_execute(
        &self,
        token_id: &[u8; 32],
        caller: [u8; 32],
        op: TokenOp,
    ) -> Result<TokenEvent, TokenError> {
        let mut tokens = self.tokens_write().await;
        let event = tokens.execute(token_id, caller, op.clone())?;

        // Which accounts were affected? (used for trie synchronization)
        let affected: Vec<[u8; 32]> = match &op {
            TokenOp::Transfer { to, .. } => vec![caller, *to],
            TokenOp::TransferFrom { from, to, .. } => vec![*from, *to],
            TokenOp::Mint { to, .. } => vec![*to],
            TokenOp::Burn { from, .. } => vec![*from],
            TokenOp::Approve { .. }
            | TokenOp::IncreaseAllowance { .. }
            | TokenOp::DecreaseAllowance { .. }
            | TokenOp::SetMinter { .. }
            | TokenOp::RenounceMinter
            | TokenOp::Pause
            | TokenOp::Unpause => vec![],
        };

        let mut trie = self.state_trie.write().await;
        if let Some(token) = tokens.get(token_id) {
            for acct in affected {
                let bal = token.balance_of(&acct);
                let key = token_balance_key(token_id, &acct);
                if bal == 0 {
                    trie.remove(&key);
                } else {
                    trie.insert(&key, &bal.to_be_bytes());
                }
            }
            // Total supply changes on mint/burn
            if matches!(op, TokenOp::Mint { .. } | TokenOp::Burn { .. }) {
                trie.insert(
                    &token_supply_key(token_id),
                    &token.metadata.total_supply.to_be_bytes(),
                );
            }
        }
        Ok(event)
    }

    /// Query a token balance held by an account.
    pub async fn token_balance(&self, token_id: &[u8; 32], account: &[u8; 32]) -> u64 {
        self.tokens.read().await.balance_of(token_id, account)
    }

    pub async fn token_total_supply(&self, token_id: &[u8; 32]) -> Option<u64> {
        self.tokens
            .read()
            .await
            .get(token_id)
            .map(|t| t.metadata.total_supply)
    }

    pub async fn token_resolve(
        &self,
        creator: &[u8; 32],
        name: &str,
        symbol: &str,
    ) -> Option<[u8; 32]> {
        self.tokens
            .read()
            .await
            .find_by_creator_name(creator, name, symbol)
    }

    pub async fn all_token_ids(&self) -> Vec<[u8; 32]> {
        self.tokens.read().await.all_token_ids()
    }

    /// Generate an SPV Merkle proof for a token balance (proves holdings against
    /// the consensus state root, exactly like a native STELL balance).
    pub async fn get_token_balance_proof(
        &self,
        token_id: &[u8; 32],
        account: &[u8; 32],
    ) -> Option<MerkleProof> {
        let key = token_balance_key(token_id, account);
        self.state_trie.read().await.generate_merkle_proof(&key)
    }
}

#[cfg(test)]
mod value_helper_tests {
    use super::*;
    use crate::state_engine::AccountState;
    use crate::tokenomics::TOTAL_SUPPLY_CAP;

    /// REGRESSION (LOGIC_BUG_SWEEP §3.3 / §5.2): `call_contract_structured_with_value`
    /// moves EXISTING value from the caller. It used the capped mint primitive
    /// and swallowed its error, so at the global supply cap the caller was
    /// debited while the contract was never credited — value destroyed by a
    /// silent `let _ =`. A transfer must be uncapped and a failed credit must
    /// be undone or reported.
    #[tokio::test]
    async fn contract_value_credit_is_a_transfer_and_never_dropped_at_the_mint_cap() {
        let engine = InMemoryStateEngine::new();
        let caller = [0x11u8; 32];
        let contract = [0x22u8; 32];
        let sink = [0x99u8; 32];
        engine
            .update_account(AccountState::new(caller, 1_000))
            .await;
        // Fill the global counter exactly: the 1,000 nano caller balance is the
        // pre-mined baseline folded into this first reservation.
        engine
            .mint_native(&sink, TOTAL_SUPPLY_CAP - 1_000)
            .await
            .expect("fill the mint counter");
        assert_eq!(engine.total_minted_nano(), TOTAL_SUPPLY_CAP);

        let out = engine
            .call_contract_structured_with_value(Some(caller), &contract, "missing", 0, 10_000, 100)
            .await;
        assert_eq!(out.status, "failed", "the contract does not exist");
        assert_eq!(
            engine.get_account(&caller).await.map(|a| a.balance),
            Some(900),
            "the caller paid the value exactly once"
        );
        assert_eq!(
            engine.get_account(&contract).await.map(|a| a.balance),
            Some(100),
            "the value is a TRANSFER and must land at the contract even at the mint cap"
        );
    }
}
