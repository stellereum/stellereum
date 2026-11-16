use super::*;
use crate::mempool::AdmissionCtx;
use crate::network::decode_wire_limited;
use crate::sharding::Transaction;
use axum::Json;
use serde_json::{json, Value};

pub(super) fn note_unbound_admission(tx: &Transaction) {
    let global = crate::metrics::global();
    note_unbound_admission_into(tx, &global);
}

pub(super) fn note_unbound_admission_into(tx: &Transaction, reg: &crate::metrics::Registry) {
    if tx.chain_id().is_some() {
        return;
    }
    tracing::warn!(
        "[mempool] admitting UNBOUND (replayable, no chain id) tx from {} nonce={} gas={} — rollout phase 1: admitted + metered, will be refused in phase 3",
        hex::encode(&tx.from[..6]),
        tx.nonce,
        tx.gas_limit
    );
    reg.inc_unbound_tx();
}

/// A14 phase 3 (chain binding) enforcement at RPC ingress: `Some` carries the
/// stable [`crate::chain_binding::UNBOUND_REFUSED_ERR_PREFIX`] refusal the
/// wallet matches on. Call sites pass finalized-tip+1 as `next_height` (see
/// their `// GATE:` comments) and always refuse with this message verbatim —
/// no extra prefix, so the pinned string stays matchable. Default-off (the
/// activation env unset) always returns `None`.
pub(super) fn chain_binding_refusal(
    tx: &Transaction,
    next_height: u64,
    chain_id: u64,
) -> Option<String> {
    crate::chain_binding::check_admission_from_env(tx.chain_id().is_some(), next_height, chain_id)
        .err()
}

pub(super) async fn admit_signed_payload_tx(
    st: &RpcState,
    id: Value,
    params: &Value,
    header_token: Option<&str>,
    method: &str,
    carries: impl Fn(&crate::svm::OpCode) -> bool,
    wrong_payload: &str,
) -> Json<RpcResponse> {
    // Gated by the deployment's `auth_token` (when configured): pending
    // mempool contents are non-public, and these arms also tell a caller
    // what the payload is about to do. NOTE: this is NOT "the same gate as
    // sendRawTransaction" — the send paths (`stell_sendRawTransaction`,
    // `eth_sendRawTransaction`) are OPEN submission by design (self-
    // authenticating signed txs); only these introspection/payload arms plus
    // `stell_mempoolDump` take the token.
    if let Some(expected) = &st.auth_token {
        let provided = params["token"]
            .as_str()
            .or_else(|| params["apiKey"].as_str())
            .or(header_token);
        if !provided
            .map(|p| constant_time_eq(p, expected.as_str()))
            .unwrap_or(false)
        {
            return err(id, -32001, "unauthorized: missing or invalid API token");
        }
    }
    // params: { "tx": <hex of bincode(Transaction)> }
    let raw = match params["tx"].as_str() {
        Some(s) => s,
        None => return err(id, -32602, "missing tx"),
    };
    let s = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = match hex::decode(s) {
        Ok(b) => b,
        Err(e) => return err(id, -32602, format!("bad hex: {e}")),
    };
    if bytes.len() > MAX_RPC_BODY {
        return err(id, -32602, "transaction too large");
    }
    let tx: Transaction = match decode_wire_limited(&bytes, MAX_RPC_BODY as u64) {
        Ok(t) => t,
        Err(e) => return err(id, -32602, format!("decode: {e}")),
    };
    // FULL-PQ (no compat): classical envelopes refused at intake, before any
    // crypto. PQ verify/admission below is unchanged.
    {
        let pq_ok = match tx.pq_envelope() {
            Some(env) => env.scheme.is_post_quantum(),
            None => false,
        };
        if !pq_ok {
            return err(
                id,
                -32000,
                "Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope",
            );
        }
    }
    if !tx.verify_signature() {
        return err(id, -32000, "invalid transaction signature");
    }
    // A14 phase 3: refuse unbound envelopes at/after activation, with the
    // check's message verbatim. A refused tx is never admitted, so it counts
    // as refused (`stell_unbound_refused_total`), not as metered admission.
    // GATE: height is finalized-tip+1 — the earliest height this tx could be
    // included at — derived from COMMITTED `st.height`, never caller params.
    // Default-off (env unset) always passes, so phase-1 admit+meter below is
    // byte-identical.
    let next_height = st
        .height
        .load(std::sync::atomic::Ordering::Relaxed)
        .saturating_add(1);
    if let Some(reason) = chain_binding_refusal(&tx, next_height, st.chain_id) {
        crate::metrics::global().inc_unbound_refused();
        return err(id, -32000, reason);
    }
    // A14 phase 1: unbound admission is loud + metered, never silent.
    note_unbound_admission(&tx);
    if !tx.payload.iter().any(carries) {
        return err(id, -32602, wrong_payload);
    }
    let acct = st.engine.get_account(&tx.from).await;
    let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
    let onchain_nonce = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
    // PAYMASTER: a sponsored transaction funds its fee from the sponsor, so
    // admission carries the sponsor's balance head too (fail-closed: a
    // sponsored transaction with no head is refused). Legacy transactions
    // carry no head and behave exactly as before.
    let mut actx = AdmissionCtx::wall_now().with_chain_height(next_height);
    if let Some(sbal) = st.engine.sponsor_balance_of(&tx).await {
        actx = actx.with_sponsor_balance(sbal);
    }
    // The write guard must be released BEFORE `save_mempool_throttled`, which
    // takes the same lock for reading: keeping it as a `match` scrutinee
    // temporary would hold it for the whole body and self-deadlock on the first
    // admission of a fresh process (the throttle is only skipped once some
    // admission has already saved).
    let admitted = {
        let mut pool = st.mempool.write().await;
        // Nonce-gap fail-fast, same as `stell_sendRawTransaction` (audit:
        // blocks troubles): far-future nonces sat in the pool forever behind
        // an unreachable head.
        if let Some(gap) = pool.check_nonce_gap(&tx.from, tx.nonce, onchain_nonce) {
            tracing::warn!(
                "[mempool] rejecting gapped payload tx from {}: {gap}",
                hex::encode(&tx.from[..6])
            );
            return err(id, -32000, format!("rejected: {gap}"));
        }
        pool.add_checked_ctx(tx.clone(), balance, actx)
    };
    match admitted {
        Ok(hash) => {
            // Propagate verified transaction to P2P peers via gossip.
            if let Some(bcast) = &st.tx_broadcast {
                let _ = bcast.send(tx);
            }
            crate::evm_adapter::notify_pending_tx(crate::evm_adapter::stell_hash_to_evm(&hash));
            st.save_mempool_throttled().await;
            let _ = method;
            ok(id, json!(hex::encode(hash)))
        }
        Err(e) => err(id, -32000, format!("rejected: {e}")),
    }
}

pub(super) async fn dispatch_writes(
    st: &RpcState,
    id: Value,
    method: &str,
    params: &Value,
    header_token: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> Option<Json<RpcResponse>> {
    if !matches!(
        method,
        "stell_sendSealedTransaction"
            | "stell_faucet"
            | "stell_submitProposal"
            | "stell_vote"
            | "stell_executeProposal"
            | "stell_signMessage"
            | "stell_verifyMessage"
            | "stell_signTypedData"
            | "stell_verifyTypedData"
            | "stell_sendRawTransaction"
            | "stell_submitPriceFeed"
            | "stell_submitPqPriceFeed"
            | "stell_pmmBuy"
            | "stell_pmmSell"
    ) {
        return None;
    }
    Some(dispatch_writes_inner(st, id, method, params, header_token, peer_ip).await)
}

async fn dispatch_writes_inner(
    st: &RpcState,
    id: Value,
    method: &str,
    params: &Value,
    header_token: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> Json<RpcResponse> {
    match method {
        // Submit a SEALED transaction. The parameter is the hex-encoded
        // sealed envelope (the wire frame: MAGIC || bincode(envelope)); the
        // node stores the CIPHERTEXT only.
        "stell_sendSealedTransaction" => {
            let Some(hex_payload) = params["payload"]
                .as_str()
                .or_else(|| params["data"].as_str())
            else {
                return err(id, -32602, "missing payload");
            };
            let Ok(bytes) = hex::decode(hex_payload.trim_start_matches("0x")) else {
                return err(id, -32602, "payload is not valid hex");
            };
            let envelope = match crate::mev_epoch::decode_sealed_payload(&bytes) {
                Ok(e) => e,
                Err(e) => return err(id, -32602, format!("refusing the sealed transaction: {e}")),
            };
            let mut pool = st.mempool.write().await;
            match pool.add_sealed(envelope) {
                Ok(hash) => {
                    let hash_hex = hex::encode(hash);
                    // Gossip the sealed frame to the peers (the ciphertext
                    // only).
                    if let Some(gossip) = crate::consensus_net::global_tx_gossip().as_ref() {
                        if let Some(env) = pool.sealed_envelope(&hash).cloned() {
                            gossip.broadcast_sealed(&env).await;
                        }
                    }
                    ok(id, json!({ "tx_hash": hash_hex, "sealed": true }))
                }
                Err(e) => err(id, -32011, format!("sealed transaction refused: {e}")),
            }
        }
        // The sealed/plain share of the pool (the operator's view of how
        // much of the traffic takes the private path).
        "stell_mevStats" => {
            let pool = st.mempool.read().await;
            let manager = &pool.mev_seal;
            ok(
                id,
                json!({
                    "epoch": pool.sealed_epoch(),
                    "sealed": pool.sealed_count(),
                    "plain": pool.len(),
                    "sealed_share": pool.sealed_share(),
                    "unsealed": manager.unsealed,
                    "unseal_failures": manager.unseal_failures,
                    "threshold": manager.material().map(|m| m.threshold).unwrap_or(0),
                    "epoch_key": manager.public_key().map(|k| hex::encode(k.public_key)),
                    "epoch_key_commitment": manager.epoch_commitment().map(hex::encode),
                    "committed_epoch_key": manager.committed_epoch_key.map(hex::encode),
                    "diverged": manager.epoch_key_diverged,
                }),
            )
        }

        // ---- accounts ----
        "stell_faucet" => {
            let Some(faucet) = st.faucet.clone() else {
                return err(id, -32601, "faucet is disabled on this node");
            };
            // Fail-closed: the faucet mints money, so "no token configured" must
            // never degrade into "anyone who can reach this port may mint".
            // The faucet token is separate from the general write token so that
            // a public testnet can offer read-only queries freely while still
            // rationing who may draw from the treasury.
            let Some(expected) = st.faucet_token.as_deref() else {
                return err(
                    id,
                    -32001,
                    "faucet is enabled but STELL_FAUCET_TOKEN is not set; refusing to dispense",
                );
            };
            let provided = params["token"]
                .as_str()
                .or_else(|| params["apiKey"].as_str())
                .or(header_token);
            if !provided
                .map(|p| constant_time_eq(p, expected))
                .unwrap_or(false)
            {
                return err(id, -32001, "unauthorized: missing or invalid faucet token");
            }
            // A zero drip is meaningless but would still burn a faucet nonce,
            // IP-budget quota and a mempool slot. Refuse it before anything
            // is reserved or counted.
            if params["amount"].as_u64() == Some(0) {
                return err(id, -32602, "invalid amount: must be a positive integer");
            }
            let addr = match params["address"].as_str().or_else(|| params.as_str()) {
                Some(a) => a,
                None => return err(id, -32602, "missing address"),
            };
            // Shard scope BEFORE any nonce is reserved: a recipient that
            // routes to another shard is refused here (not queued), so the
            // refusal burns no nonce and touches no lifetime cap — the next
            // servable drip keeps the exact nonce it would have had.
            // Address validation also runs BEFORE the per-IP throttle below:
            // validation is free, quota is not — malformed requests must
            // never consume budget (same order as the public faucet path).
            let (a, drip_shard) = match resolve_faucet_recipient(st, &faucet, addr).await {
                Ok(v) => v,
                Err(e) => {
                    if e.starts_with("invalid address") {
                        return err(id, -32602, e);
                    }
                    return err(id, -32000, e);
                }
            };
            // Per-source throttle, same budget as the explorer path (audit
            // follow-up: this path skipped it entirely, so the token holder
            // could rotate addresses without limit here). Unattributed callers
            // share the fallback bucket — they are throttled, not exempt.
            {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if !faucet.check_ip_throttle(peer_ip, now_secs).await {
                    return err(id, -32000, "per-IP faucet budget exhausted for this hour");
                }
            }
            // Reconcile inputs for the atomic mex inside build_transfer: the
            // on-chain nonce plus our own pending nonces from the shared
            // mempool. Without this, reserved-but-never-executed drips (wiped
            // mempool across a restart) leave a permanent gap that new drips
            // wait behind forever.
            let faucet_addr = faucet.account();
            let onchain = st
                .engine
                .get_account(&faucet_addr)
                .await
                .map(|acc| acc.nonce)
                .unwrap_or(0);
            let pending: Vec<u64> = st
                .mempool
                .read()
                .await
                .all()
                .iter()
                .filter(|t| t.from == faucet_addr)
                .map(|t| t.nonce)
                .collect();
            let Some((tx, amount)) = faucet
                .build_transfer(a, params["amount"].as_u64(), Some((onchain, pending)))
                .await
            else {
                return err(id, -32000, "faucet limit reached for this address");
            };
            let balance = st
                .engine
                .get_account(&faucet.account())
                .await
                .map(|acc| acc.balance)
                .unwrap_or(0);
            let tx_hash = match st.mempool.write().await.add_checked_ctx(
                tx.clone(),
                balance,
                AdmissionCtx::wall_now(),
            ) {
                Ok(h) => h,
                Err(e) => {
                    faucet.rollback(&tx, a, amount).await;
                    return err(id, -32000, format!("faucet transfer rejected: {e}"));
                }
            };
            st.save_mempool_throttled().await;
            if let Some(bcast) = &st.tx_broadcast {
                let _ = bcast.send(tx);
            }
            ok(
                id,
                json!({
                    "credited_nano": amount.to_string(),
                    "recipient": hex::encode(a),
                    "tx_hash": hex::encode(tx_hash),
                    "shard": drip_shard,
                }),
            )
        }

        "stell_submitProposal" => {
            // GATE: N-02 — token required ALWAYS, on every bind (the old
            // loopback escape is deleted; sendRawTransaction stays open).
            if let Some(denied) = require_gov_write_auth(st, &id, params, header_token) {
                return denied;
            }
            // BLOCK FORM (primary, block-carried): the caller built the
            // sibling's opcode tx (`Governance::gov_propose_tx`, opcode by
            // NAME `SysCallGovPropose`) and PQ-signed it with their own key
            // via the session/PQ signing path. THIN admission, exactly like
            // `stell_pmmBuy` / `stell_submitPriceFeed`: verify the wrapping
            // transaction and admit it to the mempool — NEVER mutate
            // governance state here. The proposal opens when a proposer
            // includes the tx in a block and every node re-runs the opcode
            // (the `tx.from` signer is the proposer; the scan gates id,
            // height, stake and shape). No single-node guard here: admission
            // mutates nothing, so multi-node nodes admit freely.
            if params.get("tx").and_then(|v| v.as_str()).is_some() {
                return admit_signed_payload_tx(
                    st,
                    id,
                    params,
                    header_token,
                    method,
                    |op| matches!(op, crate::svm::OpCode::SysCallGovPropose { .. }),
                    "payload does not carry SysCallGovPropose",
                )
                .await;
            }
            // DIRECT FORM (solo-only): the legacy operator-signed params
            // mutate governance state in this process, so the single-node
            // write guard runs FIRST (multi-node without the documented
            // escape env refuses here, never as a downstream error).
            if let Some(body) = multinode_gov_write_refusal(st).await {
                return err(
                    id,
                    -32000,
                    format!(
                        "propose failed: {}",
                        crate::governance::GovError::MultiNodeRefused(body)
                    ),
                );
            }
            let title = match params["title"].as_str() {
                Some(t) => t.to_string(),
                None => return err(id, -32602, "missing proposal title"),
            };
            let action_type =
                match params["type"].as_str() {
                    Some(t) => t,
                    None => return err(
                        id,
                        -32602,
                        "missing action type (e.g. software_upgrade, set_min_gas_limit, signal)",
                    ),
                };
            // EXPLICIT, TYPED ACTIONS (audit W7.2): every `GovAction` variant
            // has exactly one canonical action string, and the mapping lives
            // next to the enum (`crate::governance::gov_action_from_params`).
            //
            // FAIL CLOSED: an unknown action string used to fall into a
            // catch-all arm that turned it into a `Signal` — a silent no-op
            // that made a typo look like an accepted proposal. It is now
            // refused, and the refusal names the known vocabulary.
            let action = match crate::governance::gov_action_from_params(action_type, params) {
                Ok(a) => a,
                Err(e) => return err(id, -32602, e),
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut g = gov_write(st).await;
            let mut ledger = st.engine.staking_write().await;
            // Operator-signed identity: the proposer MUST be explicit (no
            // default identity — a default would let any caller propose as
            // an address whose key they do not hold).
            let proposer = match params["proposer"].as_str().and_then(|s| parse_addr(s).ok()) {
                Some(p) => p,
                None => return err(id, -32602, "missing or invalid proposer address"),
            };
            // Unsigned legacy path: refused fail-closed unless the loopback
            // dev-test escape is armed (existing STELL_DEV_UNSAFE_TESTKEY=1
            // flag AND a loopback bind — no new knob).
            let sig_hex = params["signature"].as_str();
            if sig_hex.is_none() && gov_unsigned_dev_escape() {
                match g.propose(&mut ledger, proposer, title, action, now) {
                    Ok(pid) => return ok(id, json!({ "proposal_id": pid, "status": "Open" })),
                    Err(e) => return err(id, -32000, format!("propose failed: {e}")),
                }
            }
            let Some(sig_hex) = sig_hex else {
                return err(
                    id,
                    -32001,
                    "missing gov signature: stell_submitProposal requires an operator signature over (chain_id || proposer || title || action || nonce) verifiable against the proposer's staking key; pass 'signature' (wallet envelope hex) and 'nonce' (u64)",
                );
            };
            let nonce = match params.get("nonce") {
                Some(v) => match crate::wallet_signing::parse_u64_param(v) {
                    Ok(n) => n,
                    Err(e) => return err(id, -32602, format!("bad gov nonce: {e}")),
                },
                None => {
                    return err(
                        id,
                        -32602,
                        "missing gov nonce: pass 'nonce' (u64, fresh per proposer; consumed on success)",
                    )
                }
            };
            let sig = match crate::wallet_signing::WalletSignature::from_hex(sig_hex) {
                Ok(s) => s,
                Err(e) => return err(id, -32602, format!("bad gov signature envelope: {e}")),
            };
            if sig.claimed_address() != proposer {
                return err(
                    id,
                    -32000,
                    "gov signature wrong key: the envelope's claimed address is not the proposer",
                );
            }
            match g.propose_signed(
                &mut ledger,
                proposer,
                title,
                action,
                now,
                st.chain_id,
                nonce,
                &sig,
            ) {
                Ok(pid) => ok(id, json!({ "proposal_id": pid, "status": "Open" })),
                Err(e) => err(id, -32000, format!("propose failed: {e}")),
            }
        }
        "stell_vote" => {
            // GATE: N-02 — token required ALWAYS, on every bind (the old
            // loopback escape is deleted; sendRawTransaction stays open).
            if let Some(denied) = require_gov_write_auth(st, &id, params, header_token) {
                return denied;
            }
            // BLOCK FORM (primary, block-carried): the caller built the
            // sibling's opcode tx (`Governance::gov_vote_tx`, opcode by NAME
            // `SysCallGovVote`) and PQ-signed it with their own key. THIN
            // admission like the propose twin: verify + admit, never mutate.
            // The tally moves when a block applies the tx (`tx.from` is the
            // voter; the scan enforces window, one-vote and weight rules).
            // No single-node guard: admission mutates nothing.
            if params.get("tx").and_then(|v| v.as_str()).is_some() {
                return admit_signed_payload_tx(
                    st,
                    id,
                    params,
                    header_token,
                    method,
                    |op| matches!(op, crate::svm::OpCode::SysCallGovVote { .. }),
                    "payload does not carry SysCallGovVote",
                )
                .await;
            }
            // DIRECT FORM (solo-only): guard FIRST, same discipline as the
            // propose twin (multi-node refuses as multi-node, never as
            // UnknownProposal or a tally error).
            if let Some(body) = multinode_gov_write_refusal(st).await {
                return err(
                    id,
                    -32000,
                    format!(
                        "vote failed: {}",
                        crate::governance::GovError::MultiNodeRefused(body)
                    ),
                );
            }
            let pid = match params["id"].as_u64() {
                Some(p) => p,
                None => return err(id, -32602, "missing proposal id"),
            };
            let voter = match params["voter"].as_str().and_then(|s| parse_addr(s).ok()) {
                Some(v) => v,
                None => return err(id, -32602, "missing or invalid voter address"),
            };
            let choice = match params["choice"]
                .as_str()
                .unwrap_or("yes")
                .to_lowercase()
                .as_str()
            {
                "yes" | "y" | "1" => crate::governance::VoteChoice::Yes,
                "no" | "n" | "0" => crate::governance::VoteChoice::No,
                _ => crate::governance::VoteChoice::Abstain,
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mut g = gov_write(st).await;
            let mut ledger = st.engine.staking_write().await;
            // Operator-signed identity: the envelope must verify against the
            // claimed voter STAKING key (the same key whose stake is
            // locked/voted — checked by `vote_signed` against the ledger
            // snapshot, so a stakeless signature lands on NotStaker).
            // Unsigned legacy path: refused fail-closed unless the loopback
            // dev-test escape is armed (existing STELL_DEV_UNSAFE_TESTKEY=1
            // flag AND a loopback bind — no new knob).
            let sig_hex = params["signature"].as_str();
            if sig_hex.is_none() && gov_unsigned_dev_escape() {
                match g.vote(&mut ledger, voter, pid, choice, now) {
                    Ok(weight) => {
                        return ok(
                            id,
                            json!({ "voted": true, "proposal_id": pid, "weight": weight.to_string() }),
                        )
                    }
                    Err(e) => return err(id, -32000, format!("vote failed: {e}")),
                }
            }
            let Some(sig_hex) = sig_hex else {
                return err(
                    id,
                    -32001,
                    "missing gov signature: stell_vote requires an operator signature over (chain_id || proposal_id || choice) verifiable against the voter's staking key; pass 'signature' (wallet envelope hex)",
                );
            };
            let sig = match crate::wallet_signing::WalletSignature::from_hex(sig_hex) {
                Ok(s) => s,
                Err(e) => return err(id, -32602, format!("bad gov signature envelope: {e}")),
            };
            if sig.claimed_address() != voter {
                return err(
                    id,
                    -32000,
                    "gov signature wrong key: the envelope's claimed address is not the voter",
                );
            }
            match g.vote_signed(&mut ledger, voter, pid, choice, now, st.chain_id, &sig) {
                Ok(weight) => ok(
                    id,
                    json!({ "voted": true, "proposal_id": pid, "weight": weight.to_string() }),
                ),
                Err(e) => err(id, -32000, format!("vote failed: {e}")),
            }
        }
        "stell_executeProposal" => {
            // AUTH (audit W6.7): this arm was the ONLY governance write with
            // NO token gate. It applies the action of a PASSED proposal, and
            // one of the actions is `SoftwareUpgrade` — the path that ends
            // in an `execve` of a new binary. `stell_submitProposal` and
            // `stell_vote` are gated; this one was not. Same gate, same
            // token, same constant-time comparison.
            //
            // NOTE: the gate is on the CALLER, not on the proposal: the
            // proposal still needs its quorum (the ledger decides that), and
            // "anyone may execute" (no proposer-only rule) is preserved so a
            // lost proposer key cannot brick execution — the operator's
            // token is enough.
            // GATE: N-02 — same fail-closed rule as the sibling gov
            // writes: token required ALWAYS, on every bind.
            if let Some(denied) = require_gov_write_auth(st, &id, params, header_token) {
                return denied;
            }
            // DIRECT mutation (marks Executed + applies params in this
            // process only): same single-node guard as the propose/vote
            // twins — a multi-node execution without the documented escape
            // env refuses here instead of forking the state root.
            if let Some(body) = multinode_gov_write_refusal(st).await {
                return err(
                    id,
                    -32000,
                    format!(
                        "execute failed: {:?}",
                        crate::governance::GovError::MultiNodeRefused(body)
                    ),
                );
            }
            let pid = match params["id"].as_u64() {
                Some(p) => p,
                None => return err(id, -32602, "missing proposal id"),
            };
            let executor = params["executor"]
                .as_str()
                .and_then(|s| parse_addr(s).ok())
                .unwrap_or_default();
            let mut g = gov_write(st).await;
            // Height-aware execution (KI-23): legacy unscheduled passes
            // execute immediately (unchanged); proposals scheduled by the
            // live-path `finalize_at_height` enforce pass_height + 7200
            // maturity fail-closed. `st.height` is the finalized height.
            let cur_height = st.height.load(std::sync::atomic::Ordering::Relaxed);
            match g.execute_at_height(executor, pid, cur_height) {
                Ok(applied) => ok(id, json!({ "executed": true, "applied": applied })),
                Err(e) => err(id, -32000, format!("execute failed: {:?}", e)),
            }
        }

        // ---- wallet signature standard (docs/WALLET_SIGNING.md) ----
        // SIGN arms: fail-closed devnet-only (GATE: H-02) — separate ephemeral
        // dev key, configured `auth_token` required, loopback-only. Production
        // wallets must never use them. VERIFY arms: public, no auth
        // (verification is total and side-effect free). The node signs
        // Ed25519 only; VERIFY accepts all three live schemes (Ed25519,
        // Falcon-512, Hybrid).
        "stell_signMessage" => handle_sign_message(st, id, params, header_token, peer_ip),
        "stell_verifyMessage" => handle_verify_message(st, id, params),
        "stell_signTypedData" => handle_sign_typed_data(st, id, params, header_token, peer_ip),
        "stell_verifyTypedData" => handle_verify_typed_data(st, id, params),
        "stell_sendRawTransaction" => {
            // params: { "tx": <hex of bincode(Transaction)> }
            let raw = match params["tx"].as_str() {
                Some(s) => s,
                None => return err(id, -32602, "missing tx"),
            };
            let s = raw.strip_prefix("0x").unwrap_or(raw);
            let bytes = match hex::decode(s) {
                Ok(b) => b,
                Err(e) => return err(id, -32602, format!("bad hex: {e}")),
            };
            if bytes.len() > MAX_RPC_BODY {
                return err(id, -32602, "transaction too large");
            }
            let tx: Transaction = match decode_wire_limited(&bytes, MAX_RPC_BODY as u64) {
                Ok(t) => t,
                Err(e) => return err(id, -32602, format!("decode: {e}")),
            };
            // FULL-PQ (no compat): classical envelopes refused at intake,
            // before any crypto. PQ verify/admission below is unchanged.
            {
                let pq_ok = match tx.pq_envelope() {
                    Some(env) => env.scheme.is_post_quantum(),
                    None => false,
                };
                if !pq_ok {
                    return err(
                        id,
                        -32000,
                        "Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope",
                    );
                }
            }
            if !tx.verify_signature() {
                return err(id, -32000, "invalid transaction signature");
            }
            // A14 phase 3: refuse unbound envelopes at/after activation, with
            // the check's message verbatim (refused counts as refused, not as
            // metered admission).
            // GATE: height is finalized-tip+1 — the earliest height this tx
            // could be included at — derived from COMMITTED `st.height`,
            // never caller params. Default-off always passes: phase-1
            // admit+meter below is byte-identical.
            let next_height = st
                .height
                .load(std::sync::atomic::Ordering::Relaxed)
                .saturating_add(1);
            if let Some(reason) = chain_binding_refusal(&tx, next_height, st.chain_id) {
                crate::metrics::global().inc_unbound_refused();
                return err(id, -32000, reason);
            }
            // A14 phase 1: unbound admission is loud + metered, never silent.
            note_unbound_admission(&tx);
            let acct = st.engine.get_account(&tx.from).await;
            let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
            let onchain_nonce = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
            // PAYMASTER: carry the sponsor's balance head for sponsored
            // transactions (fail-closed without it); legacy ignores it.
            let mut actx = AdmissionCtx::wall_now().with_chain_height(next_height);
            if let Some(sbal) = st.engine.sponsor_balance_of(&tx).await {
                actx = actx.with_sponsor_balance(sbal);
            }
            // Release the mempool write guard before the throttled save, which
            // reads the same lock; a `match` scrutinee temporary would hold it
            // through the body and deadlock the first admission in a process.
            // (Engine reads happen ABOVE, outside the pool guard: pool-then-
            // engine nesting the other way would deadlock against paths that
            // take them in the opposite order.)
            let admitted = {
                let mut pool = st.mempool.write().await;
                // Nonce-gap fail-fast (audit: blocks troubles): far-future
                // nonces sat in the pool forever behind an unreachable head.
                if let Some(gap) = pool.check_nonce_gap(&tx.from, tx.nonce, onchain_nonce) {
                    tracing::warn!(
                        "[mempool] rejecting gapped tx from {}: {gap}",
                        hex::encode(&tx.from[..6])
                    );
                    return err(id, -32000, format!("rejected: {gap}"));
                }
                pool.add_checked_ctx(tx.clone(), balance, actx)
            };
            match admitted {
                Ok(hash) => {
                    // Propagate verified transaction to P2P peers via gossip:
                    if let Some(bcast) = &st.tx_broadcast {
                        let _ = bcast.send(tx);
                    }
                    crate::evm_adapter::notify_pending_tx(crate::evm_adapter::stell_hash_to_evm(
                        &hash,
                    ));
                    st.save_mempool_throttled().await;
                    ok(id, json!(hex::encode(hash)))
                }
                Err(e) => {
                    // Admission verdicts are node-local diagnostics gold (audit:
                    // blocks troubles — 76 silent rejections with no log line
                    // anywhere). Log every refusal with sender/nonce/fee.
                    tracing::warn!(
                        "[mempool] admission refused tx from {} nonce={} gas={}: {e}",
                        hex::encode(&tx.from[..6]),
                        tx.nonce,
                        tx.gas_limit
                    );
                    err(id, -32000, format!("rejected: {e}"))
                }
            }
        }
        // Submit a signed oracle price feed for block inclusion. THIN by
        // design: it decodes and verifies the wrapping transaction and admits
        // it to the mempool, nothing else. It does NOT write oracle state -
        // the price only becomes consensus state when a PROPOSER includes the
        // transaction in a block and every node re-runs
        // `OpCode::SysCallSubmitPriceFeed` against `block.timestamp`. Writing
        // here would make the price node-local (non-deterministic), which is
        // exactly the bug the block-time commit path exists to prevent.
        "stell_submitPriceFeed" | "stell_submitPqPriceFeed" => {
            admit_signed_payload_tx(
                st,
                id,
                params,
                header_token,
                method,
                |op| match op {
                    crate::svm::OpCode::SysCallSubmitPqPriceFeed(feed) => feed.verify(),
                    crate::svm::OpCode::SysCallSubmitPriceFeed(feed) => feed.verify(),
                    _ => false,
                },
                "payload does not carry a validly signed price feed",
            )
            .await
        }

        // ---- Primary Market Maker -------------------------------------
        // Both swap arms are the same THIN admission path as
        // `stell_submitPriceFeed`: verify the wrapping transaction, check it
        // actually carries the opcode the method name promises, admit it. The
        // swap itself is applied by `execute_payload` when a proposer includes
        // the transaction, so no node can mint STELL or burn wUSDT by asking
        // for it over RPC - and two nodes cannot disagree about the curve,
        // because neither of them moved it yet.
        "stell_pmmBuy" => {
            admit_signed_payload_tx(
                st,
                id,
                params,
                header_token,
                method,
                |op| matches!(op, crate::svm::OpCode::SysCallPmmBuy { .. }),
                "payload does not carry SysCallPmmBuy",
            )
            .await
        }
        "stell_pmmSell" => {
            admit_signed_payload_tx(
                st,
                id,
                params,
                header_token,
                method,
                |op| matches!(op, crate::svm::OpCode::SysCallPmmSell { .. }),
                "payload does not carry SysCallPmmSell",
            )
            .await
        }

        _ => unreachable!(),
    }
}
