use super::super::types::decode_actor_body;
use super::super::types::encode_actor_body;
use super::super::types::DeliveryCtx;
use super::super::types::MessageUndo;
use super::super::AccountState;
use super::super::ActorMessage;
use super::super::InMemoryStateEngine;
use super::super::MAX_ACTOR_MSGS_PER_BLOCK;
use super::super::MAX_ACTOR_ROUNDS;
use super::ACTOR_MAILBOX_READ_FAST_PATHS;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::Ordering;

impl InMemoryStateEngine {
    /// Asynchronously send a message to an actor's inbox
    pub async fn send_message(&self, msg: ActorMessage) -> Result<(), String> {
        let mut map = self.accounts.write().await;

        // SECURITY: a message MUST come from an existing actor. Otherwise a message
        // from a non-existent sender would credit the recipient without debiting
        // anyone — free money. (Previously the balance check was skipped when the
        // sender was absent, and the value was still enqueued.)
        let sender_acc = map
            .get_mut(&msg.sender)
            .ok_or_else(|| format!("Sender {:?} does not exist", msg.sender))?;
        if sender_acc.balance < msg.value {
            return Err(format!(
                "Sender {:?} has insufficient balance for message value {}",
                msg.sender, msg.value
            ));
        }
        sender_acc.balance -= msg.value;
        sender_acc.nonce += 1;

        // Enqueue to recipient inbox if recipient exists; otherwise handle bounce
        if let Some(recipient_acc) = map.get_mut(&msg.recipient) {
            recipient_acc.inbox.push_back(msg);
        } else if msg.bounce && !msg.bounced {
            // Bounce: return the value via a message in the sender's inbox.
            // The value is credited EXACTLY ONCE, when the execution step
            // processes this message (not immediately here — that caused a
            // double-credit and broke value conservation).
            if let Some(sender_acc) = map.get_mut(&msg.sender) {
                let bounce_msg = ActorMessage {
                    msg_id: msg.msg_id,
                    sender: msg.recipient,
                    recipient: msg.sender,
                    value: msg.value,
                    body: msg.body,
                    bounce: false,
                    bounced: true,
                };
                sender_acc.inbox.push_back(bounce_msg);
            }
        }

        Ok(())
    }

    /// Execute a discrete execution step across all actors processing inboxes
    /// Returns the number of messages successfully processed
    pub async fn step_actor_execution(&self) -> Result<usize, String> {
        let mut map = self.accounts.write().await;
        let mut processed = 0;
        let mut new_messages: Vec<ActorMessage> = Vec::new();

        let addresses: Vec<[u8; 32]> = map.keys().copied().collect();

        for addr in addresses {
            let mut messages_to_run = Vec::new();
            if let Some(actor) = map.get_mut(&addr) {
                while let Some(msg) = actor.inbox.pop_front() {
                    messages_to_run.push(msg);
                }
            }

            for msg in messages_to_run {
                if let Some(actor) = map.get_mut(&addr) {
                    actor.balance = actor.balance.saturating_add(msg.value);
                    processed += 1;

                    // If actor has generated outbox messages, collect them
                    while let Some(out) = actor.outbox.pop_front() {
                        new_messages.push(out);
                    }
                }
            }
        }

        // Route any newly generated outbox messages.
        // Value accounting: debit the emitting actor NOW, credit the recipient
        // when the message is processed in a later step. A bounce returns the
        // value via a message (credited once on the next step). This keeps
        // total value conserved (no double-credit, no free minting).
        for msg in new_messages {
            // SECURITY: refuse to route a message whose sender does not exist —
            // otherwise the recipient would be credited with value nobody paid.
            let Some(snd) = map.get_mut(&msg.sender) else {
                continue;
            };
            if snd.balance < msg.value {
                continue; // cannot fund the message -> drop
            }
            snd.balance -= msg.value;
            if let Some(rec) = map.get_mut(&msg.recipient) {
                rec.inbox.push_back(msg);
            } else if msg.bounce && !msg.bounced {
                if let Some(snd) = map.get_mut(&msg.sender) {
                    let bounce_msg = ActorMessage {
                        msg_id: msg.msg_id,
                        sender: msg.recipient,
                        recipient: msg.sender,
                        value: msg.value,
                        body: msg.body,
                        bounce: false,
                        bounced: true,
                    };
                    snd.inbox.push_back(bounce_msg);
                }
            }
        }

        // Update state trie for all accounts
        let mut trie = self.state_trie.write().await;
        for (addr, acc) in map.iter() {
            let data = acc.to_trie_bytes();
            trie.insert(addr, &data);
        }

        Ok(processed)
    }

    /// §1 ACTOR MAILBOX: deliver the messages queued in every inbox, once per
    /// block, and return how many were delivered.
    ///
    /// Called EXACTLY once per block from [`Self::apply_block_transition`],
    /// between the transactions step and the fee credit - the transactions
    /// QUEUE their sends (settlement at payload commit), this pass CONSUMES
    /// them, and Phase 1's policy is drain-to-empty: every queue is empty at
    /// the block boundary, so there is no mailbox state to persist, no
    /// account-encoding change and the genesis KAT cannot move.
    ///
    /// PHASE 2 (deliberately NOT done here): if a queued message ever has to
    /// SURVIVE a block boundary as committed state - a pending message that
    /// outlives the block that created it, rather than a defensive leftover
    /// from the round/cap bounds below - the queues would have to join the
    /// state commitment, and the way to do that without breaking anything
    /// that exists is a CONDITIONAL account encoding: an `ACTORQ1` leaf shape
    /// used only by accounts that actually hold messages, appended so every
    /// pre-Phase-2 account leaf (balance || nonce, and the node-snapshot
    /// `AccountState` bincode) keeps decoding byte-for-byte, and writing no
    /// extra bytes for the overwhelmingly common empty queue (the same
    /// conditional-domain trick `bridge`/`confidential` use in the
    /// commitment digest, so the root of a chain that never queued anything
    /// stays pinned to the genesis KAT). Phase 1 buys the simpler world
    /// instead: bounded block, guaranteed quiescence, inbox contents never in
    /// the root at a boundary - which is exactly what makes this pass free
    /// for legacy blocks.
    ///
    /// Algorithm, and why each piece is where it is:
    ///
    ///  * ONE accounts write lock for the whole DELIVERING pass, so a delivery
    ///    can never interleave with another block, an RPC apply or a direct
    ///    `send_message` and observe a half-updated inbox. A pass with nothing
    ///    queued (the common block) returns from a read-only check instead of
    ///    taking that exclusive lock at all (S4).
    ///  * Recipients are collected from the `HashMap` and then
    ///    `sort_unstable`-ed by ADDRESS. Iterating the map directly would
    ///    deliver in a per-process random order, and order is observable here:
    ///    a body reads and moves the balance another body just changed, so
    ///    two nodes applying the same block could derive different states.
    ///  * FIFO within a recipient (each round pops from the front), so a
    ///    sender's own ordering is preserved.
    ///  * Rounds: a body may enqueue further sends, and one whose recipient
    ///    was already visited this round is picked up by the next - which is
    ///    what bounds recursion together with [`MAX_ACTOR_ROUNDS`].
    ///  * [`MAX_ACTOR_MSGS_PER_BLOCK`] bounds the pass's total work. It is a
    ///    defensive clamp (the proposer-side block gas limit keeps real blocks
    ///    far below it); a message still queued when it or the rounds run out
    ///    is never dropped and never delivered out of order - it drains in a
    ///    later block.
    ///
    /// Per-message atomicity: the delivery snapshots every account it touches
    /// (lazily, so third parties a body reaches are covered too), runs the
    /// body in the VM - whose own clone-commit already discards registry
    /// mutations on a revert - and on ANY failure (revert, out of gas,
    /// undecodable body, unaffordable effect) rolls the account map back to
    /// the pre-message state and bounces the message to its sender: value
    /// returned EXACTLY once, no partial effect. A bounced message is a pure
    /// refund whose body is never re-run, so a bounce can never bounce again.
    ///
    /// `block` is the block being applied: its `timestamp` is the clock a
    /// delivered body runs against (never local wall time - every node must
    /// reach the same verdict).
    pub async fn apply_actor_messages_at(&self, block: &crate::sharding::Block) -> usize {
        // The two governed staking parameters a VmContext wants, read BEFORE
        // the accounts lock (this is the only lock order the pass takes part
        // in: governance, then accounts, then the trie - nothing in the tree
        // takes accounts and then governance, so no deadlock is possible).
        // Unreachable for a body today - staking is deliberately not wired
        // into the delivery context, so every staking syscall reverts - but
        // the fields are non-optional and a node-local default would be the
        // wrong value to hard-code if that ever changes.
        let (min_validator_bond, default_commission_bps) = {
            let gov = self.governance.read().await;
            (
                gov.applied
                    .min_validator_bond
                    .unwrap_or(crate::staking::MIN_VALIDATOR_BOND),
                gov.applied
                    .default_commission_bps
                    .unwrap_or(crate::staking::DEFAULT_COMMISSION_BPS),
            )
        };
        let dctx = DeliveryCtx {
            timestamp: block.timestamp,
            min_validator_bond,
            default_commission_bps,
        };

        // S4: READ-ONLY fast path first. The overwhelming majority of blocks
        // queue no actor message, and the pass used to take the exclusive
        // accounts lock (blocking every concurrent reader: RPC balance/state
        // reads, other applies' snapshots) just to discover that. A read guard
        // proves the same thing without excluding anybody; the write guard
        // below still re-checks, so a message enqueued concurrently is handled
        // exactly as before (it either lands before this pass reads, or after
        // the pass returns - in both versions it is a later block's work).
        {
            let map = self.accounts.read().await;
            if map.values().all(|acc| acc.inbox.is_empty()) {
                ACTOR_MAILBOX_READ_FAST_PATHS.fetch_add(1, Ordering::Relaxed);
                return 0;
            }
        }
        let mut map = self.accounts.write().await;
        // Same check again under the exclusive guard (a message may have landed
        // between the read guard above and this one): a block that queues
        // nothing must not take the trie lock or allocate a touched set.
        if map.values().all(|acc| acc.inbox.is_empty()) {
            return 0;
        }

        let mut touched: HashSet<[u8; 32]> = HashSet::new();
        let mut processed = 0usize;

        'rounds: for _round in 0..MAX_ACTOR_ROUNDS {
            // Every recipient with a queued message, in address order. The
            // collection is re-made each round because the previous round's
            // deliveries may have queued messages for accounts that were
            // empty when it started.
            let mut recipients: Vec<[u8; 32]> = map
                .iter()
                .filter(|(_, acc)| !acc.inbox.is_empty())
                .map(|(addr, _)| *addr)
                .collect();
            if recipients.is_empty() {
                break; // quiescent: drain-to-empty reached
            }
            recipients.sort_unstable();
            for recipient in recipients {
                loop {
                    if processed >= MAX_ACTOR_MSGS_PER_BLOCK {
                        break 'rounds;
                    }
                    let msg = match map
                        .get_mut(&recipient)
                        .and_then(|acc| acc.inbox.pop_front())
                    {
                        Some(m) => m,
                        None => break, // this recipient's queue is empty
                    };
                    processed += 1;
                    Self::deliver_actor_message(
                        &mut map,
                        &mut touched,
                        recipient,
                        msg,
                        &dctx,
                        block.height,
                    );
                }
            }
        }

        // Write ONLY the accounts the pass touched, with their final balances
        // (the same pattern as the transactions step): inboxes are not trie
        // state and nonces never move here.
        let mut trie = self.state_trie.write().await;
        for addr in &touched {
            if let Some(acc) = map.get(addr) {
                let data = acc.to_trie_bytes();
                trie.insert(addr, &data);
            }
        }
        processed
    }

    /// Deliver ONE queued message into the account whose inbox it sits in.
    ///
    /// Failure handling is the design's undo-then-bounce: every account the
    /// delivery touched is restored to its pre-message state (the lazy
    /// snapshot covers the recipient, the sender and any third party a body
    /// reached), and the message goes back to its SENDER marked `bounced` -
    /// where it is a pure refund, delivered later in this same pass.
    fn deliver_actor_message(
        map: &mut HashMap<[u8; 32], AccountState>,
        touched: &mut HashSet<[u8; 32]>,
        owner: [u8; 32],
        msg: ActorMessage,
        dctx: &DeliveryCtx,
        chain_height: u64,
    ) {
        // Invariant: every enqueue path pushes a message into ITS RECIPIENT's
        // inbox (settlement, `send_message`, and this pass's own bounces all
        // keep `owner == msg.recipient`), so the account it came out of is
        // the account to credit.
        debug_assert_eq!(owner, msg.recipient);

        if msg.bounced {
            // A bounce is a pure refund - its value was debited from the
            // sender when the original message was enqueued, so crediting it
            // here returns the value EXACTLY once. The original body is NOT
            // re-run: a failed body must not get a second attempt on the way
            // back, which is also why a bounce can never bounce again.
            if owner == msg.recipient {
                if let Some(acc) = map.get_mut(&owner) {
                    // `checked_add` cannot fail in practice: the sender paid
                    // exactly this amount out of a supply that fits in u64.
                    // Leaving the balance untouched rather than saturating is
                    // the fail-safe shape (no silent wrap).
                    if let Some(b) = acc.balance.checked_add(msg.value) {
                        acc.balance = b;
                    }
                    touched.insert(owner);
                }
            }
            return;
        }

        let mut undo = MessageUndo::default();
        if Self::try_deliver(map, &mut undo, touched, owner, &msg, dctx, chain_height).is_err() {
            undo.rollback(map);
            // Reversed message, queued in the SENDER's inbox (which is its
            // own `recipient` field, so the pass will deliver it below) -
            // exactly the bounce shape the engine's `send_message` has always
            // used.
            if let Some(snd) = map.get_mut(&msg.sender) {
                snd.inbox.push_back(ActorMessage {
                    msg_id: msg.msg_id,
                    sender: msg.recipient,
                    recipient: msg.sender,
                    value: msg.value,
                    body: msg.body,
                    bounce: false,
                    bounced: true,
                });
            }
        }
    }

    fn is_allowed_non_self_actor_opcode(op: &crate::svm::OpCode) -> bool {
        matches!(
            op,
            crate::svm::OpCode::Nop
                | crate::svm::OpCode::Push(_)
                | crate::svm::OpCode::Pop
                | crate::svm::OpCode::Add
                | crate::svm::OpCode::Sub
                | crate::svm::OpCode::Mul
                | crate::svm::OpCode::Div
                | crate::svm::OpCode::LoadBalance
                | crate::svm::OpCode::Halt
                | crate::svm::OpCode::SysCallVerifyPqSignature { .. }
                | crate::svm::OpCode::SysCallCallContract { .. }
                | crate::svm::OpCode::SysCallCallContractArgs { .. }
        )
    }

    /// The success path of one delivery: credit, run the prepaid body, settle
    /// its transfers and its sends. ANY `Err` means "the message failed" -
    /// the caller undoes the snapshot and bounces it; nothing here is allowed
    /// to half-apply.
    fn try_deliver(
        map: &mut HashMap<[u8; 32], AccountState>,
        undo: &mut MessageUndo,
        touched: &mut HashSet<[u8; 32]>,
        owner: [u8; 32],
        msg: &ActorMessage,
        dctx: &DeliveryCtx,
        chain_height: u64,
    ) -> Result<(), String> {
        // A message queued outside its recipient's inbox cannot be delivered
        // (and has no inbox to be put back into either). Unreachable by the
        // enqueue invariant above - fail closed if it is ever violated.
        if owner != msg.recipient {
            return Err("actor message queued outside its recipient's inbox".to_string());
        }

        // 1. Credit the delivered value. Snapshot FIRST, so a later failure
        //    takes the credit back with everything else - "delivery credits
        //    the recipient" only holds for a message that fully delivered.
        undo.note(map, owner);
        let balance = {
            let acc = map
                .get_mut(&owner)
                .ok_or_else(|| "actor recipient account does not exist".to_string())?;
            acc.balance = acc
                .balance
                .checked_add(msg.value)
                .ok_or_else(|| "actor delivery: recipient balance overflow".to_string())?;
            acc.balance
        };
        touched.insert(owner);

        // 2. The prepaid program + fuel the sender packed into the body.
        let body = decode_actor_body(&msg.body)?;

        let actor_hardening = crate::chain_spec::actor_mailbox_hardening_active_at(chain_height);
        if actor_hardening
            && msg.sender != owner
            && !body
                .program
                .iter()
                .all(Self::is_allowed_non_self_actor_opcode)
        {
            return Err(
                "actor body contains unauthorized opcode for non-self delivery".to_string(),
            );
        }

        // 3. Run the body. Below ACTOR_MAILBOX_HARDENING_HEIGHT, preserve
        //    100% byte-identical legacy behavior. At/above the gate, a non-self
        //    sender (`msg.sender != owner`) only sees `msg.value` (never
        //    `owner`'s pre-existing balance) and cannot produce transfers or
        //    outbound sends on behalf of `owner`.
        let mut sends: Vec<crate::svm::ActorSendRequest> = Vec::new();
        let mut ctx = crate::svm::VmContext {
            sender: msg.sender,
            balance: if actor_hardening && msg.sender != owner {
                msg.value
            } else {
                balance
            },
            orderbooks: None,
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            zkml_proof: None,
            timestamp: dctx.timestamp,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            pmm: None,
            min_validator_bond: dctx.min_validator_bond,
            default_commission_bps: dctx.default_commission_bps,
            payouts: Vec::new(),
            oracle: None,
        };
        // No registries wired by design (see the context above): in
        // particular `zkml_models` is `None`, so a delivered body can never
        // register or verify a model - all four zkML opcodes fail closed
        // there (both re-execution halves and both succinct halves).
        let res = if actor_hardening {
            let opts = crate::svm::VmExecOptions {
                chain_height,
                ..Default::default()
            };
            crate::svm::Svm::execute_with_confidential_and_sends_at(
                &body.program,
                body.gas_budget,
                &mut ctx,
                &mut sends,
                None,
                &opts,
            )
        } else {
            crate::svm::Svm::execute_with_confidential_and_sends(
                &body.program,
                body.gas_budget,
                &mut ctx,
                &mut sends,
                None,
            )
        };
        let (transfers, payouts) = match res {
            crate::svm::VmExecutionResult::Success {
                transfers, payouts, ..
            } => (transfers, payouts),
            crate::svm::VmExecutionResult::OutOfGas => {
                return Err("actor body ran out of gas".to_string())
            }
            crate::svm::VmExecutionResult::Reverted(e) => {
                return Err(format!("actor body reverted: {e}"))
            }
        };

        if actor_hardening && msg.sender != owner && !transfers.is_empty() {
            return Err("actor body cannot debit recipient on non-self delivery".to_string());
        }
        if actor_hardening && msg.sender != owner && !sends.is_empty() {
            return Err("actor body cannot enqueue sends on non-self delivery".to_string());
        }

        // 4. Settle the body's own value movements. The acting account pays;
        //    a recipient that does not exist yet is created, exactly like
        //    `commit_native` does for a payload transfer. The VM already
        //    priced these against its balance mirror (which started at the
        //    post-credit balance and cannot have drifted - this pass holds
        //    the accounts lock throughout), but this is where coins actually
        //    move, so the checks live here too.
        for (to, amount) in &transfers {
            undo.note(map, owner);
            {
                let from = map
                    .get_mut(&owner)
                    .ok_or_else(|| "actor recipient vanished mid-delivery".to_string())?;
                if from.balance < *amount {
                    return Err(format!(
                        "actor body transfer: {} holds {} but must pay {amount}",
                        hex::encode(&owner[..6]),
                        from.balance
                    ));
                }
                from.balance -= *amount;
            }
            undo.note(map, *to);
            match map.get_mut(to) {
                Some(acc) => {
                    acc.balance = acc.balance.checked_add(*amount).ok_or_else(|| {
                        "actor delivery: transfer recipient balance overflow".to_string()
                    })?;
                }
                None => {
                    map.insert(*to, AccountState::new(*to, *amount));
                }
            }
            touched.insert(*to);
        }
        // A delivered body has no staking ledger wired, so it cannot have
        // produced a payout; refuse rather than silently skip value that was
        // promised to somebody.
        if !payouts.is_empty() {
            return Err("actor body produced payouts with no payer wired".to_string());
        }

        // 5. Settle the sends the body enqueued - the recursion step. The
        //    acting account pays for each one (the VM debited its mirror), a
        //    missing recipient bounces immediately (value returns to the
        //    actor exactly once), and everything is snapshot-covered: a send
        //    that cannot be funded fails the WHOLE delivery, which then
        //    bounces the original message.
        for s in &sends {
            if !s.bounce {
                return Err("actor body produced a non-bounceable send".to_string());
            }
            undo.note(map, owner);
            {
                let from = map
                    .get_mut(&owner)
                    .ok_or_else(|| "actor recipient vanished mid-delivery".to_string())?;
                if from.balance < s.value {
                    return Err(format!(
                        "actor body cannot fund its own send of {} nano-STELL",
                        s.value
                    ));
                }
                from.balance -= s.value;
            }
            let encoded = encode_actor_body(&s.body, s.gas_budget);
            let nested = ActorMessage::new(owner, s.recipient, s.value, encoded, s.bounce);
            if map.contains_key(&s.recipient) {
                undo.note(map, s.recipient);
                map.get_mut(&s.recipient)
                    .expect("recipient existence checked above")
                    .inbox
                    .push_back(nested);
            } else {
                let bounce = ActorMessage {
                    msg_id: nested.msg_id,
                    sender: s.recipient,
                    recipient: owner,
                    value: nested.value,
                    body: nested.body,
                    bounce: false,
                    bounced: true,
                };
                map.get_mut(&owner)
                    .expect("owner exists (credited above)")
                    .inbox
                    .push_back(bounce);
            }
            touched.insert(owner);
        }

        touched.insert(owner);
        Ok(())
    }
}
