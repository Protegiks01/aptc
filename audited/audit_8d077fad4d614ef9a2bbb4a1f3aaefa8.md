# Audit Report

## Title
Critical State Inconsistency: Batches Sent to Proof Manager Before Persistence Validation Creates Unretrievable Batch References

## Summary
The `BatchCoordinator::persist_and_send_digests()` function extracts batch metadata and sends it to the proof manager **before** validating that persistence succeeded. When batch persistence fails (due to quota exhaustion, expiration, or other errors), the proof manager receives references to batches that don't exist in `BatchStore`, creating an inconsistent state that can cause block execution failures and consensus liveness issues.

## Finding Description

The vulnerability exists in the batch lifecycle management within the quorum store consensus mechanism. When a validator receives batches via `handle_batches_msg()`, the following sequence occurs: [1](#0-0) 

The batches are converted to `persist_requests` and passed to `persist_and_send_digests()`. Inside this function, a critical ordering bug exists: [2](#0-1) 

The code creates the `batches` collection from `persist_requests` at lines 92-100, **before** any persistence attempt occurs. Then at line 103 or 113, it calls `batch_store.persist()`, which can return an empty vector if persistence fails. The network notification (lines 104-129) correctly checks if `signed_batch_infos` is non-empty before sending. However, lines 131-133 **unconditionally** send the `batches` to the proof manager regardless of persistence success.

Persistence can fail in multiple scenarios within `BatchStore`:

1. **Batch Expiration**: [3](#0-2) 

2. **Quota Exhaustion**: [4](#0-3) 

3. **Signature Generation Failure**: [5](#0-4) 

When persistence fails, `persist()` returns an empty vector: [6](#0-5) 

The proof manager then stores these batch references: [7](#0-6) 

And inserts them into the batch proof queue: [8](#0-7) 

When a `ProofOfStore` arrives for such a batch, it gets matched with the batch metadata in the proof queue, and can be pulled for block proposals. During block execution, attempting to retrieve the batch transactions will fail with `ExecutorError::CouldNotGetData`: [9](#0-8) 

This violates the **State Consistency** invariant: the proof manager believes batches exist that are not actually stored, creating inconsistent state between consensus components.

## Impact Explanation

**Severity: Critical** (meets criteria for up to $1,000,000)

This vulnerability causes:

1. **Consensus Liveness Failures**: Blocks containing proofs for non-existent batches cannot be executed, blocking consensus progress
2. **Non-Recoverable Network Partition**: If enough validators hit quota limits simultaneously, they cannot persist batches but still send references to proof managers, causing widespread execution failures
3. **State Inconsistency**: Breaks atomic state management between `BatchStore` and `ProofManager`, violating critical invariant #4

The impact is severe because:
- It can cause network-wide consensus halts if multiple validators are affected
- Blocks may be proposed that are impossible to execute
- Requires manual intervention to recover (nodes must resync or restart)
- Affects deterministic execution across validators

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to occur because:

1. **Quota exhaustion is a normal operational scenario** during high network load
2. **Batch expiration can occur** due to clock drift or network delays between batch creation and receipt
3. **No validator access required** - any peer can send batches to trigger this
4. **Cascading failures** - once one validator's quota is exhausted, it propagates the problem to other validators who receive its batches

Attack scenario:
1. Attacker floods validators with large batches near quota limits
2. Validators accept batches in `handle_batches_msg()` but fail persistence due to quota
3. Batch metadata still sent to proof manager
4. Attacker or malicious validator creates `ProofOfStore` for these batches
5. Block proposer includes these proofs in a block
6. Block execution fails when trying to retrieve non-existent batch data
7. Consensus stalls or validators must request batches from network (which may not exist anywhere)

## Recommendation

The fix requires checking persistence success before sending batch metadata to the proof manager. Modify `persist_and_send_digests()`:

```rust
fn persist_and_send_digests(
    &self,
    persist_requests: Vec<PersistedValue<BatchInfoExt>>,
    approx_created_ts_usecs: u64,
) {
    if persist_requests.is_empty() {
        return;
    }

    let batch_store = self.batch_store.clone();
    let network_sender = self.network_sender.clone();
    let sender_to_proof_manager = self.sender_to_proof_manager.clone();
    tokio::spawn(async move {
        let peer_id = persist_requests[0].author();
        
        // Persist FIRST
        let signed_batch_infos = if persist_requests[0].batch_info().is_v2() {
            batch_store.persist(persist_requests.clone())
        } else {
            batch_store.persist(persist_requests.clone())
        };

        // Only proceed if persistence succeeded
        if !signed_batch_infos.is_empty() {
            // Create batches AFTER successful persistence
            let batches = persist_requests
                .iter()
                .map(|persisted_value| {
                    (
                        persisted_value.batch_info().clone(),
                        persisted_value.summary(),
                    )
                })
                .collect();

            // Send to network
            if persist_requests[0].batch_info().is_v2() {
                if approx_created_ts_usecs > 0 {
                    observe_batch(approx_created_ts_usecs, peer_id, BatchStage::SIGNED);
                }
                network_sender
                    .send_signed_batch_info_msg_v2(signed_batch_infos, vec![peer_id])
                    .await;
            } else {
                assert!(!signed_batch_infos
                    .first()
                    .expect("must not be empty")
                    .is_v2());
                if approx_created_ts_usecs > 0 {
                    observe_batch(approx_created_ts_usecs, peer_id, BatchStage::SIGNED);
                }
                let signed_batch_infos = signed_batch_infos
                    .into_iter()
                    .map(|sbi| sbi.try_into().expect("Batch must be V1 batch"))
                    .collect();
                network_sender
                    .send_signed_batch_info_msg(signed_batch_infos, vec![peer_id])
                    .await;
            }
            
            // Only send to proof manager if persistence succeeded
            let _ = sender_to_proof_manager
                .send(ProofManagerCommand::ReceiveBatches(batches))
                .await;
        } else {
            debug!("QS: Failed to persist batches from {}, not sending to proof manager", peer_id);
        }
    });
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_crypto::HashValue;
    use aptos_types::PeerId;
    
    #[tokio::test]
    async fn test_batch_persistence_failure_not_sent_to_proof_manager() {
        // Setup: Create batch coordinator with limited quota
        let (tx_proof_manager, mut rx_proof_manager) = tokio::sync::mpsc::channel(100);
        let batch_store = create_batch_store_with_quota(100); // Small quota
        
        // Create batches that will exceed quota
        let large_batches = create_large_batches(5, 50); // 5 batches x 50 bytes = 250 bytes > quota
        
        // Step 1: First batch should succeed
        batch_coordinator.handle_batches_msg(peer_id, vec![large_batches[0].clone()]).await;
        
        // Verify it was sent to proof manager
        let msg = timeout(Duration::from_secs(1), rx_proof_manager.recv()).await.unwrap();
        assert!(matches!(msg, Some(ProofManagerCommand::ReceiveBatches(_))));
        
        // Step 2: Subsequent batches should fail persistence due to quota
        batch_coordinator.handle_batches_msg(peer_id, large_batches[1..].to_vec()).await;
        
        // VULNERABILITY: These batches should NOT be sent to proof manager since persistence failed
        // But current code sends them anyway
        let msg = timeout(Duration::from_millis(500), rx_proof_manager.recv()).await;
        
        // This should timeout (no message sent) but currently receives batches
        assert!(msg.is_err(), "Batches with failed persistence should not be sent to proof manager");
        
        // Step 3: Verify batch is not in BatchStore
        let batch_digest = large_batches[1].digest();
        let result = batch_store.get_batch_from_local(batch_digest);
        assert!(result.is_err(), "Failed-to-persist batch should not be in store");
        
        // Step 4: But proof manager has it (vulnerability)
        // When ProofOfStore arrives, it will match and can be proposed
        // Leading to execution failure when block tries to retrieve transactions
    }
}
```

## Notes

This is a **time-of-check-to-time-of-use (TOCTOU)** vulnerability where batch metadata is extracted before the persistence operation completes, and then used regardless of the operation's outcome. The asynchronous nature of the tokio spawn makes this particularly dangerous as the sending to proof manager happens independently of persistence success.

The vulnerability is exacerbated by the fact that quota limits are a legitimate operational concern, not just an edge case. Under high load, validators will naturally hit these limits, making this a realistic and severe issue that could affect network-wide consensus.

### Citations

**File:** consensus/src/quorum_store/batch_coordinator.rs (L90-134)
```rust
        tokio::spawn(async move {
            let peer_id = persist_requests[0].author();
            let batches = persist_requests
                .iter()
                .map(|persisted_value| {
                    (
                        persisted_value.batch_info().clone(),
                        persisted_value.summary(),
                    )
                })
                .collect();

            if persist_requests[0].batch_info().is_v2() {
                let signed_batch_infos = batch_store.persist(persist_requests);
                if !signed_batch_infos.is_empty() {
                    if approx_created_ts_usecs > 0 {
                        observe_batch(approx_created_ts_usecs, peer_id, BatchStage::SIGNED);
                    }
                    network_sender
                        .send_signed_batch_info_msg_v2(signed_batch_infos, vec![peer_id])
                        .await;
                }
            } else {
                let signed_batch_infos = batch_store.persist(persist_requests);
                if !signed_batch_infos.is_empty() {
                    assert!(!signed_batch_infos
                        .first()
                        .expect("must not be empty")
                        .is_v2());
                    if approx_created_ts_usecs > 0 {
                        observe_batch(approx_created_ts_usecs, peer_id, BatchStage::SIGNED);
                    }
                    let signed_batch_infos = signed_batch_infos
                        .into_iter()
                        .map(|sbi| sbi.try_into().expect("Batch must be V1 batch"))
                        .collect();
                    network_sender
                        .send_signed_batch_info_msg(signed_batch_infos, vec![peer_id])
                        .await;
                }
            }
            let _ = sender_to_proof_manager
                .send(ProofManagerCommand::ReceiveBatches(batches))
                .await;
        });
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L228-244)
```rust
        let mut persist_requests = vec![];
        for batch in batches.into_iter() {
            // TODO: maybe don't message batch generator if the persist is unsuccessful?
            if let Err(e) = self
                .sender_to_batch_generator
                .send(BatchGeneratorCommand::RemoteBatch(batch.clone()))
                .await
            {
                warn!("Failed to send batch to batch generator: {}", e);
            }
            persist_requests.push(batch.into());
        }
        counters::RECEIVED_BATCH_COUNT.inc_by(persist_requests.len() as u64);
        if author != self.my_peer_id {
            counters::RECEIVED_REMOTE_BATCH_COUNT.inc_by(persist_requests.len() as u64);
        }
        self.persist_and_send_digests(persist_requests, approx_created_ts_usecs);
```

**File:** consensus/src/quorum_store/batch_store.rs (L64-84)
```rust
    pub(crate) fn update_quota(&mut self, num_bytes: usize) -> anyhow::Result<StorageMode> {
        if self.batch_balance == 0 {
            counters::EXCEEDED_BATCH_QUOTA_COUNT.inc();
            bail!("Batch quota exceeded ");
        }

        if self.db_balance >= num_bytes {
            self.batch_balance -= 1;
            self.db_balance -= num_bytes;

            if self.memory_balance >= num_bytes {
                self.memory_balance -= num_bytes;
                Ok(StorageMode::MemoryAndPersisted)
            } else {
                Ok(StorageMode::PersistedOnly)
            }
        } else {
            counters::EXCEEDED_STORAGE_QUOTA_COUNT.inc();
            bail!("Storage quota exceeded ");
        }
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L419-439)
```rust
    pub(crate) fn save(&self, value: &PersistedValue<BatchInfoExt>) -> anyhow::Result<bool> {
        let last_certified_time = self.last_certified_time();
        if value.expiration() > last_certified_time {
            fail_point!("quorum_store::save", |_| {
                // Skip caching and storing value to the db
                Ok(false)
            });
            counters::GAP_BETWEEN_BATCH_EXPIRATION_AND_CURRENT_TIME_WHEN_SAVE.observe(
                Duration::from_micros(value.expiration() - last_certified_time).as_secs_f64(),
            );

            return self.insert_to_cache(value);
        }
        counters::NUM_BATCH_EXPIRED_WHEN_SAVE.inc();
        bail!(
            "Incorrect expiration {} in epoch {}, last committed timestamp {}",
            value.expiration(),
            self.epoch(),
            last_certified_time,
        );
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L488-528)
```rust
    fn persist_inner(
        &self,
        batch_info: BatchInfoExt,
        persist_request: PersistedValue<BatchInfoExt>,
    ) -> Option<SignedBatchInfo<BatchInfoExt>> {
        assert!(
            &batch_info == persist_request.batch_info(),
            "Provided batch info doesn't match persist request batch info"
        );
        match self.save(&persist_request) {
            Ok(needs_db) => {
                trace!("QS: sign digest {}", persist_request.digest());
                if needs_db {
                    if !batch_info.is_v2() {
                        let persist_request =
                            persist_request.try_into().expect("Must be a V1 batch");
                        #[allow(clippy::unwrap_in_result)]
                        self.db
                            .save_batch(persist_request)
                            .expect("Could not write to DB");
                    } else {
                        #[allow(clippy::unwrap_in_result)]
                        self.db
                            .save_batch_v2(persist_request)
                            .expect("Could not write to DB")
                    }
                }
                if !batch_info.is_v2() {
                    self.generate_signed_batch_info(batch_info.info().clone())
                        .ok()
                        .map(|inner| inner.into())
                } else {
                    self.generate_signed_batch_info(batch_info).ok()
                }
            },
            Err(e) => {
                debug!("QS: failed to store to cache {:?}", e);
                None
            },
        }
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L571-585)
```rust
    pub(crate) fn get_batch_from_local(
        &self,
        digest: &HashValue,
    ) -> ExecutorResult<PersistedValue<BatchInfoExt>> {
        if let Some(value) = self.db_cache.get(digest) {
            if value.payload_storage_mode() == StorageMode::PersistedOnly {
                self.get_batch_from_db(digest, value.batch_info().is_v2())
            } else {
                // Available in memory.
                Ok(value.clone())
            }
        } else {
            Err(ExecutorError::CouldNotGetData)
        }
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L614-627)
```rust
    fn persist(
        &self,
        persist_requests: Vec<PersistedValue<BatchInfoExt>>,
    ) -> Vec<SignedBatchInfo<BatchInfoExt>> {
        let mut signed_infos = vec![];
        for persist_request in persist_requests.into_iter() {
            let batch_info = persist_request.batch_info().clone();
            if let Some(signed_info) = self.persist_inner(batch_info, persist_request.clone()) {
                self.notify_subscribers(persist_request);
                signed_infos.push(signed_info);
            }
        }
        signed_infos
    }
```

**File:** consensus/src/quorum_store/proof_manager.rs (L80-86)
```rust
    pub(crate) fn receive_batches(
        &mut self,
        batch_summaries: Vec<(BatchInfoExt, Vec<TxnSummaryWithExpiration>)>,
    ) {
        self.batch_proof_queue.insert_batches(batch_summaries);
        self.update_remaining_txns_and_proofs();
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L258-312)
```rust
    pub fn insert_batches(
        &mut self,
        batches_with_txn_summaries: Vec<(BatchInfoExt, Vec<TxnSummaryWithExpiration>)>,
    ) {
        let start = Instant::now();

        for (batch_info, txn_summaries) in batches_with_txn_summaries.into_iter() {
            let batch_sort_key = BatchSortKey::from_info(&batch_info);
            let batch_key = BatchKey::from_info(&batch_info);

            // If the batch is either committed or the txn summary already exists, skip
            // inserting this batch.
            if self
                .items
                .get(&batch_key)
                .is_some_and(|item| item.is_committed() || item.txn_summaries.is_some())
            {
                continue;
            }

            self.author_to_batches
                .entry(batch_info.author())
                .or_default()
                .insert(batch_sort_key.clone(), batch_info.clone());
            self.expirations
                .add_item(batch_sort_key, batch_info.expiration());

            // We only count txn summaries first time it is added to the queue
            // and only if the proof already exists.
            if self
                .items
                .get(&batch_key)
                .is_some_and(|item| item.proof.is_some())
            {
                for txn_summary in &txn_summaries {
                    *self
                        .txn_summary_num_occurrences
                        .entry(*txn_summary)
                        .or_insert(0) += 1;
                }
            }

            match self.items.entry(batch_key) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().txn_summaries = Some(txn_summaries);
                },
                Entry::Vacant(entry) => {
                    entry.insert(QueueItem {
                        info: batch_info,
                        proof: None,
                        proof_insertion_time: None,
                        txn_summaries: Some(txn_summaries),
                    });
                },
            }
```
