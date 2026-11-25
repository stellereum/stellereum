use super::super::types::hashpool_commitment_key;
use super::super::types::hashpool_nullifier_key;
use super::super::BlockTransitionOutcome;
use super::super::HashPoolApplyOutcome;
use super::super::HashPoolBlockOps;
use super::super::HashPoolOpError;
use super::super::InMemoryStateEngine;
use super::super::HASH_POOL_ENABLED;
use std::sync::atomic::Ordering;

impl InMemoryStateEngine {
    // -----------------------------------------------------------------------
    // HashPool note/nullifier apply wiring (default-OFF; see the section
    // above `HASH_POOL_ENABLED`). No other apply logic is touched: the
    // standard `apply_block_transition` body is unchanged, and the sidecar
    // below reuses it verbatim before applying pool ops.
    // -----------------------------------------------------------------------

    /// Whether the HashPool apply path is live on this instance: the const
    /// (always `false` in production builds) OR the test-only override.
    pub fn hashpool_enabled(&self) -> bool {
        HASH_POOL_ENABLED || self.hashpool_tests_on.load(Ordering::Relaxed)
    }

    /// Test-only switch: bind a FRESH empty pool to this engine's current
    /// `chain_id` and flip the per-instance gate on.
    ///
    /// Never called on the live path (only `tests/` call it). Rebinding on
    /// enable keeps the pool's chain binding exact even though `chain_id` is
    /// a plain public field: whatever chain this engine claims at enable
    /// time is what the pool commits to.
    pub async fn enable_hashpool_for_tests(&self) {
        *self.hashpool.write().await = crate::hashpool::HashPool::new(self.chain_id);
        self.hashpool_tests_on.store(true, Ordering::Release);
    }

    /// Real Falcon-512 owner-signature verifier for CoinJoin batches (the
    /// caller-supplied closure shape `coinjoin_verify` requires).
    fn hashpool_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        crate::post_quantum::verify_pq_signature(
            crate::post_quantum::PqScheme::Falcon512,
            pk,
            msg,
            sig,
        )
    }

    /// Number of deposited commitments (test accessor; no mutation).
    pub async fn hashpool_len(&self) -> usize {
        self.hashpool.read().await.len()
    }

    /// Number of spent nullifiers (test accessor; no mutation).
    pub async fn hashpool_spent_len(&self) -> usize {
        self.hashpool.read().await.spent_len()
    }

    /// True when `commitment` is registered (test accessor; no mutation).
    pub async fn hashpool_contains(&self, commitment: &[u8; 32]) -> bool {
        self.hashpool.read().await.contains(commitment)
    }

    /// True when `nullifier` is spent (test accessor; no mutation).
    pub async fn hashpool_is_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.hashpool.read().await.is_spent(nullifier)
    }

    /// Register one note deposit. Refuses [`HashPoolOpError::Disabled`]
    /// while the gate is off (nothing read, nothing written); otherwise
    /// registers via `HashPool::deposit` and mirrors the commitment leaf
    /// into the state trie so the state root moves deterministically.
    pub async fn apply_hashpool_deposit(
        &self,
        commitment: [u8; 32],
        stealth: [u8; 32],
        nullifier: [u8; 32],
    ) -> Result<(), HashPoolOpError> {
        if !self.hashpool_enabled() {
            return Err(HashPoolOpError::Disabled);
        }
        let mut pool = self.hashpool.write().await;
        pool.deposit(commitment, stealth, nullifier)?;
        let mut trie = self.state_trie.write().await;
        trie.insert(&hashpool_commitment_key(&commitment), &stealth);
        Ok(())
    }

    /// Consume one note by revealing its opening. Refuses
    /// [`HashPoolOpError::Disabled`] while the gate is off; otherwise spends
    /// via `HashPool::spend` (double-spend refused with
    /// `HpError::AlreadySpent`, wrong serial with `HpError::SerialMismatch`)
    /// and mirrors the spent nullifier leaf into the state trie.
    /// Returns the spent nullifier.
    pub async fn apply_hashpool_spend(
        &self,
        commitment: &[u8; 32],
        serial: &[u8; 32],
        value: u64,
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], HashPoolOpError> {
        if !self.hashpool_enabled() {
            return Err(HashPoolOpError::Disabled);
        }
        let mut pool = self.hashpool.write().await;
        let nf = pool.spend(commitment, serial, value, blinding)?;
        let mut trie = self.state_trie.write().await;
        trie.insert(&hashpool_nullifier_key(&nf), &[1u8]);
        Ok(nf)
    }

    /// Verify a CoinJoin batch with the REAL Falcon-512 verifier and, only
    /// on success, apply it: input nullifiers marked spent, output
    /// commitments registered, both mirrored into the state trie.
    /// Conservation (`sum_in == sum_out + fee`) is enforced by
    /// `coinjoin_verify`/`coinjoin_apply`; a refused batch leaves the pool
    /// and the trie untouched. Refuses [`HashPoolOpError::Disabled`] while
    /// the gate is off.
    pub async fn apply_hashpool_batch(
        &self,
        batch: &crate::hashpool::CoinJoinBatch,
    ) -> Result<(), HashPoolOpError> {
        if !self.hashpool_enabled() {
            return Err(HashPoolOpError::Disabled);
        }
        let mut pool = self.hashpool.write().await;
        crate::hashpool::coinjoin_verify(&pool, batch, &Self::hashpool_verify)?;
        crate::hashpool::coinjoin_apply(&mut pool, batch)?;
        let chain_id = pool.chain_id();
        let mut trie = self.state_trie.write().await;
        for inp in &batch.inputs {
            let nf = crate::hashpool::note_nullifier(&inp.opening.serial);
            trie.insert(&hashpool_nullifier_key(&nf), &[1u8]);
        }
        for out in &batch.outputs {
            let c = crate::hashpool::note_commit(chain_id, out.value, &out.blinding, &out.stealth);
            trie.insert(&hashpool_commitment_key(&c), &out.stealth);
        }
        Ok(())
    }

    /// Apply one explicit [`HashPoolBlockOps`] sidecar: deposits, then
    /// spends, then batches, each in order; refused ops are counted, never
    /// halting. While the gate is off the sidecar is skipped wholesale
    /// (`skipped_gate_off`, all counts zero, state untouched).
    pub async fn apply_hashpool_ops(&self, ops: &HashPoolBlockOps) -> HashPoolApplyOutcome {
        if !self.hashpool_enabled() {
            return HashPoolApplyOutcome {
                skipped_gate_off: true,
                ..Default::default()
            };
        }
        let mut out = HashPoolApplyOutcome::default();
        for d in &ops.deposits {
            match self
                .apply_hashpool_deposit(d.commitment, d.stealth, d.nullifier)
                .await
            {
                Ok(()) => out.deposits_applied += 1,
                Err(_) => out.deposits_refused += 1,
            }
        }
        for s in &ops.spends {
            match self
                .apply_hashpool_spend(&s.commitment, &s.serial, s.value, &s.blinding)
                .await
            {
                Ok(_) => out.spends_applied += 1,
                Err(_) => out.spends_refused += 1,
            }
        }
        for b in &ops.batches {
            match self.apply_hashpool_batch(b).await {
                Ok(()) => out.batches_applied += 1,
                Err(_) => out.batches_refused += 1,
            }
        }
        out
    }

    /// Block-apply entry point with an explicit HashPool sidecar: runs the
    /// UNCHANGED standard [`InMemoryStateEngine::apply_block_transition`]
    /// first (same outcome the live path records), then the gated
    /// [`HashPoolBlockOps`] sidecar. While the gate is off the second step
    /// is a proven no-op, so the returned base outcome and the resulting
    /// state root equal the plain path exactly.
    pub async fn apply_block_transition_with_hashpool(
        &self,
        block: &crate::sharding::Block,
        block_reward: u64,
        ops: &HashPoolBlockOps,
    ) -> (BlockTransitionOutcome, HashPoolApplyOutcome) {
        let base = self.apply_block_transition(block, block_reward).await;
        let hp = self.apply_hashpool_ops(ops).await;
        (base, hp)
    }
}
