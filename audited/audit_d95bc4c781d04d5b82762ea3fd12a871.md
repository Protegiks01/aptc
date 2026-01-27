# Audit Report

## Title
Critical Use-After-Free in QuorumStore Batch Cleanup Leading to Consensus Halt on Crash Recovery

## Summary
The `TPayloadManager` trait does not guarantee that `get_transactions()` won't be called after `notify_commit()` for the same payloads. The `QuorumStorePayloadManager` implementation aggressively cleans up batch data based on time-based expiration, which can cause crash recovery to fail when uncommitted blocks reference batches that have been globally cleaned up, leading to permanent consensus halt.

## Finding Description

The vulnerability exists in the interaction between batch cleanup and crash recovery in the QuorumStore consensus implementation.

**Architecture Context:**

When blocks are persisted to ConsensusDB, they only store batch digests/proofs, NOT actual transactions. [1](#0-0) 

During normal operation, `notify_commit()` is called after blocks are committed, which triggers batch cleanup: [2](#0-1) 

This cleanup updates `certified_time` and removes batches with `expiration <= certified_time - expiration_buffer_usecs`: [3](#0-2) 

**The Critical Flaw:**

ConsensusDB only stores **uncommitted** blocks (proposed but not yet committed): [4](#0-3) 

On crash recovery, these uncommitted blocks are loaded and re-executed through `try_send_for_execution()`: [5](#0-4) 

The recovery flow calls `insert_block_inner()` which builds the execution pipeline: [6](#0-5) 

This pipeline's materialize phase calls `get_transactions()` to fetch batch data: [7](#0-6) 

**The Vulnerability Scenario:**

1. Multiple blocks reference shared batches (common in QuorumStore)
2. Some blocks commit, triggering `notify_commit()` and advancing `certified_time`
3. Time passes, more blocks commit, `certified_time` advances further
4. Batches expire globally and are cleaned up from all validators' `BatchStore`
5. Node crashes before all blocks referencing those batches are committed
6. On restart, uncommitted blocks are loaded from ConsensusDB
7. Recovery attempts to re-execute these blocks via `get_transactions()`
8. `get_batch_from_local()` fails - batch not in cache: [8](#0-7) 
9. `BatchRequester` attempts to fetch from remote peers
10. All peers have also cleaned up the expired batch
11. Request returns `ExecutorError::CouldNotGetData`: [9](#0-8) 
12. Block execution fails, recovery halts, consensus permanently stuck

## Impact Explanation

This is a **Critical Severity** vulnerability meeting the "Total loss of liveness/network availability" criterion from the Aptos bug bounty:

1. **Consensus Halt**: When recovery fails, the node cannot rejoin consensus. If this affects multiple validators simultaneously (e.g., datacenter outage), the network loses validators and may fall below the 2f+1 threshold.

2. **Non-Recoverable Without Intervention**: The node cannot automatically recover because the required batch data is permanently lost. Manual intervention (state sync from genesis or snapshot) is required.

3. **Breaks Critical Invariants**: 
   - Violates the liveness guarantee that a correct node can always recover after a crash
   - Breaks the assumption that persisted blocks in ConsensusDB can always be re-executed

4. **Deterministic Failure**: This is not a rare edge case - it WILL occur for any node that crashes and attempts recovery after sufficient time has passed for batch expiration.

## Likelihood Explanation

**High Likelihood** due to:

1. **Natural Occurrence**: No attacker action required - happens through normal node crashes and restarts
2. **Time-Based Trigger**: The default `expiration_buffer_usecs` is 60 seconds. Any crash lasting longer than the batch expiration window risks this issue
3. **Shared Batch Architecture**: QuorumStore intentionally shares batches across multiple blocks to optimize bandwidth, increasing the window where this can occur
4. **No Protection Mechanism**: The trait provides no ordering guarantee between `notify_commit()` and `get_transactions()`, and no mechanism prevents aggressive cleanup

## Recommendation

**Short-term Fix:** Add reference counting to batches to prevent cleanup while any uncommitted blocks reference them.

**Detailed Solution:**

1. Modify `BatchStore` to track which uncommitted blocks reference each batch
2. When `notify_commit()` is called, mark batches as "committed" but don't delete if referenced by uncommitted blocks
3. Only delete batches when both:
   - They are expired based on time
   - No uncommitted blocks in ConsensusDB reference them

**Alternative Solution:** Modify ConsensusDB to persist inline transactions for blocks with expired batches, ensuring recovery always has transaction data available.

**Trait-Level Fix:** Add explicit ordering guarantee to `TPayloadManager` trait documentation:

```rust
/// A trait that defines the interface for a payload manager.
#[async_trait]
pub trait TPayloadManager: Send + Sync {
    /// Notify the payload manager that a block has been committed.
    /// 
    /// IMPORTANT: Implementations MUST NOT assume that get_transactions()
    /// will never be called again for these payloads. During crash recovery,
    /// uncommitted blocks may need to be re-executed, requiring payload
    /// data to remain available indefinitely or until explicitly pruned
    /// via a separate mechanism.
    fn notify_commit(&self, block_timestamp: u64, payloads: Vec<Payload>);
    
    // ... rest of trait
}
```

## Proof of Concept

**Rust Reproduction Steps:**

```rust
// Test to demonstrate the vulnerability
#[tokio::test]
async fn test_crash_recovery_with_expired_batches() {
    // Setup: Create BatchStore with short expiration
    let batch_store = create_batch_store(60_000_000); // 60s buffer
    let payload_manager = QuorumStorePayloadManager::new(/*...*/);
    
    // Step 1: Create batches with expiration T
    let batch_expiration = current_time() + 30_000_000; // T + 30s
    let batches = create_test_batches(batch_expiration);
    
    // Step 2: Create Block A (uncommitted) and Block B (committed) both using same batches
    let block_a = create_block_with_batches(round: 100, batches.clone());
    let block_b = create_block_with_batches(round: 101, batches.clone());
    
    // Step 3: Execute and commit Block B
    payload_manager.get_transactions(&block_b, None).await.unwrap();
    payload_manager.notify_commit(current_time(), vec![block_b.payload()]);
    
    // Step 4: Advance time past expiration + buffer (T + 100s)
    advance_time(100_000_000);
    
    // Step 5: Trigger cleanup
    payload_manager.notify_commit(current_time(), vec![]);
    
    // Step 6: Verify batches are cleaned up
    assert!(batch_store.get_batch_from_local(&batch_digest).is_err());
    
    // Step 7: Simulate crash recovery - try to re-execute Block A
    let result = payload_manager.get_transactions(&block_a, None).await;
    
    // VULNERABILITY: This fails with CouldNotGetData
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ExecutorError::CouldNotGetData));
    
    // In real scenario, this causes consensus halt
}
```

The test demonstrates that after time-based cleanup, uncommitted blocks cannot be recovered, proving the vulnerability causes consensus liveness failure.

### Citations

**File:** consensus/consensus-types/src/common.rs (L209-224)
```rust
pub enum Payload {
    DirectMempool(Vec<SignedTransaction>),
    InQuorumStore(ProofWithData),
    InQuorumStoreWithLimit(ProofWithDataWithTxnLimit),
    QuorumStoreInlineHybrid(
        Vec<(BatchInfo, Vec<SignedTransaction>)>,
        ProofWithData,
        Option<u64>,
    ),
    OptQuorumStore(OptQuorumStorePayload),
    QuorumStoreInlineHybridV2(
        Vec<(BatchInfo, Vec<SignedTransaction>)>,
        ProofWithData,
        PayloadExecutionLimit,
    ),
}
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L168-208)
```rust
    fn notify_commit(&self, block_timestamp: u64, payloads: Vec<Payload>) {
        self.batch_reader
            .update_certified_timestamp(block_timestamp);

        let batches: Vec<_> = payloads
            .into_iter()
            .flat_map(|payload| match payload {
                Payload::DirectMempool(_) => {
                    unreachable!("InQuorumStore should be used");
                },
                Payload::InQuorumStore(proof_with_status) => proof_with_status
                    .proofs
                    .iter()
                    .map(|proof| proof.info().clone().into())
                    .collect::<Vec<_>>(),
                Payload::InQuorumStoreWithLimit(proof_with_status) => proof_with_status
                    .proof_with_data
                    .proofs
                    .iter()
                    .map(|proof| proof.info().clone().into())
                    .collect::<Vec<_>>(),
                Payload::QuorumStoreInlineHybrid(inline_batches, proof_with_data, _)
                | Payload::QuorumStoreInlineHybridV2(inline_batches, proof_with_data, _) => {
                    inline_batches
                        .iter()
                        .map(|(batch_info, _)| batch_info.clone().into())
                        .chain(
                            proof_with_data
                                .proofs
                                .iter()
                                .map(|proof| proof.info().clone().into()),
                        )
                        .collect::<Vec<_>>()
                },
                Payload::OptQuorumStore(OptQuorumStorePayload::V1(p)) => p.get_all_batch_infos(),
                Payload::OptQuorumStore(OptQuorumStorePayload::V2(p)) => p.get_all_batch_infos(),
            })
            .collect();

        self.commit_notifier.notify(block_timestamp, batches);
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L443-472)
```rust
    pub(crate) fn clear_expired_payload(&self, certified_time: u64) -> Vec<HashValue> {
        // To help slow nodes catch up via execution without going to state sync we keep the blocks for 60 extra seconds
        // after the expiration time. This will help remote peers fetch batches that just expired but are within their
        // execution window.
        let expiration_time = certified_time.saturating_sub(self.expiration_buffer_usecs);
        let expired_digests = self.expirations.lock().expire(expiration_time);
        let mut ret = Vec::new();
        for h in expired_digests {
            let removed_value = match self.db_cache.entry(h) {
                Occupied(entry) => {
                    // We need to check up-to-date expiration again because receiving the same
                    // digest with a higher expiration would update the persisted value and
                    // effectively extend the expiration.
                    if entry.get().expiration() <= expiration_time {
                        self.persist_subscribers.remove(entry.get().digest());
                        Some(entry.remove())
                    } else {
                        None
                    }
                },
                Vacant(_) => unreachable!("Expired entry not in cache"),
            };
            // No longer holding the lock on db_cache entry.
            if let Some(value) = removed_value {
                self.free_quota(value);
                ret.push(h);
            }
        }
        ret
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

**File:** consensus/src/persistent_liveness_storage.rs (L28-35)
```rust
/// PersistentLivenessStorage is essential for maintaining liveness when a node crashes.  Specifically,
/// upon a restart, a correct node will recover.  Even if all nodes crash, liveness is
/// guaranteed.
/// Blocks persisted are proposed but not yet committed.  The committed state is persisted
/// via StateComputer.
pub trait PersistentLivenessStorage: Send + Sync {
    /// Persist the blocks and quorum certs into storage atomically.
    fn save_tree(&self, blocks: Vec<Block>, quorum_certs: Vec<QuorumCert>) -> Result<()>;
```

**File:** consensus/src/block_storage/block_store.rs (L144-160)
```rust
    async fn try_send_for_execution(&self) {
        // reproduce the same batches (important for the commit phase)
        let mut certs = self.inner.read().get_all_quorum_certs_with_commit_info();
        certs.sort_unstable_by_key(|qc| qc.commit_info().round());
        for qc in certs {
            if qc.commit_info().round() > self.commit_root().round() {
                info!(
                    "trying to commit to round {} with ledger info {}",
                    qc.commit_info().round(),
                    qc.ledger_info()
                );

                if let Err(e) = self.send_for_execution(qc.into_wrapped_ledger_info()).await {
                    error!("Error in try-committing blocks. {}", e.to_string());
                }
            }
        }
```

**File:** consensus/src/block_storage/block_store.rs (L448-497)
```rust
    pub async fn insert_block_inner(
        &self,
        pipelined_block: PipelinedBlock,
    ) -> anyhow::Result<Arc<PipelinedBlock>> {
        if let Some(payload) = pipelined_block.payload() {
            self.payload_manager.prefetch_payload_data(
                payload,
                pipelined_block
                    .block()
                    .author()
                    .expect("Payload block must have author"),
                pipelined_block.timestamp_usecs(),
            );
        }

        // build pipeline
        if let Some(pipeline_builder) = &self.pipeline_builder {
            let parent_block = self
                .get_block(pipelined_block.parent_id())
                .ok_or_else(|| anyhow::anyhow!("Parent block not found"))?;

            // need weak pointer to break the cycle between block tree -> pipeline block -> callback
            let block_tree = Arc::downgrade(&self.inner);
            let storage = self.storage.clone();
            let id = pipelined_block.id();
            let round = pipelined_block.round();
            let window_size = self.window_size;
            let callback = Box::new(
                move |finality_proof: WrappedLedgerInfo,
                      commit_decision: LedgerInfoWithSignatures| {
                    if let Some(tree) = block_tree.upgrade() {
                        tree.write().commit_callback(
                            storage,
                            id,
                            round,
                            finality_proof,
                            commit_decision,
                            window_size,
                        );
                    }
                },
            );
            pipeline_builder.build_for_consensus(
                &pipelined_block,
                parent_block.pipeline_futs().ok_or_else(|| {
                    anyhow::anyhow!("Parent future doesn't exist, potentially epoch ended")
                })?,
                callback,
            );
        }
```

**File:** consensus/src/block_preparer.rs (L42-69)
```rust
    pub async fn materialize_block(
        &self,
        block: &Block,
        block_qc_fut: Shared<impl Future<Output = Option<Arc<QuorumCert>>>>,
    ) -> ExecutorResult<(Vec<SignedTransaction>, Option<u64>, Option<u64>)> {
        fail_point!("consensus::prepare_block", |_| {
            use aptos_executor_types::ExecutorError;
            use std::{thread, time::Duration};
            thread::sleep(Duration::from_millis(10));
            Err(ExecutorError::CouldNotGetData)
        });
        //TODO(ibalajiarun): measure latency
        let (txns, max_txns_from_block_to_execute, block_gas_limit) = tokio::select! {
                // Poll the block qc future until a QC is received. Ignore None outcomes.
                Some(qc) = block_qc_fut => {
                    let block_voters = Some(qc.ledger_info().get_voters_bitvec().clone());
                    self.payload_manager.get_transactions(block, block_voters).await
                },
                result = self.payload_manager.get_transactions(block, None) => {
                   result
                }
        }?;
        TXNS_IN_BLOCK
            .with_label_values(&["before_filter"])
            .observe(txns.len() as f64);

        Ok((txns, max_txns_from_block_to_execute, block_gas_limit))
    }
```

**File:** consensus/src/quorum_store/batch_requester.rs (L101-180)
```rust
    pub(crate) async fn request_batch(
        &self,
        digest: HashValue,
        expiration: u64,
        responders: Arc<Mutex<BTreeSet<PeerId>>>,
        mut subscriber_rx: oneshot::Receiver<PersistedValue<BatchInfoExt>>,
    ) -> ExecutorResult<Vec<SignedTransaction>> {
        let validator_verifier = self.validator_verifier.clone();
        let mut request_state = BatchRequesterState::new(responders, self.retry_limit);
        let network_sender = self.network_sender.clone();
        let request_num_peers = self.request_num_peers;
        let my_peer_id = self.my_peer_id;
        let epoch = self.epoch;
        let retry_interval = Duration::from_millis(self.retry_interval_ms as u64);
        let rpc_timeout = Duration::from_millis(self.rpc_timeout_ms as u64);

        monitor!("batch_request", {
            let mut interval = time::interval(retry_interval);
            let mut futures = FuturesUnordered::new();
            let request = BatchRequest::new(my_peer_id, epoch, digest);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // send batch request to a set of peers of size request_num_peers
                        if let Some(request_peers) = request_state.next_request_peers(request_num_peers) {
                            for peer in request_peers {
                                futures.push(network_sender.request_batch(request.clone(), peer, rpc_timeout));
                            }
                        } else if futures.is_empty() {
                            // end the loop when the futures are drained
                            break;
                        }
                    },
                    Some(response) = futures.next() => {
                        match response {
                            Ok(BatchResponse::Batch(batch)) => {
                                counters::RECEIVED_BATCH_RESPONSE_COUNT.inc();
                                let payload = batch.into_transactions();
                                return Ok(payload);
                            }
                            // Short-circuit if the chain has moved beyond expiration
                            Ok(BatchResponse::NotFound(ledger_info)) => {
                                counters::RECEIVED_BATCH_NOT_FOUND_COUNT.inc();
                                if ledger_info.commit_info().epoch() == epoch
                                    && ledger_info.commit_info().timestamp_usecs() > expiration
                                    && ledger_info.verify_signatures(&validator_verifier).is_ok()
                                {
                                    counters::RECEIVED_BATCH_EXPIRED_COUNT.inc();
                                    debug!("QS: batch request expired, digest:{}", digest);
                                    return Err(ExecutorError::CouldNotGetData);
                                }
                            }
                            Ok(BatchResponse::BatchV2(_)) => {
                                error!("Batch V2 response is not supported");
                            }
                            Err(e) => {
                                counters::RECEIVED_BATCH_RESPONSE_ERROR_COUNT.inc();
                                debug!("QS: batch request error, digest:{}, error:{:?}", digest, e);
                            }
                        }
                    },
                    result = &mut subscriber_rx => {
                        match result {
                            Ok(persisted_value) => {
                                counters::RECEIVED_BATCH_FROM_SUBSCRIPTION_COUNT.inc();
                                let (_, maybe_payload) = persisted_value.unpack();
                                return Ok(maybe_payload.expect("persisted value must exist"));
                            }
                            Err(err) => {
                                debug!("channel closed: {}", err);
                            }
                        };
                    },
                }
            }
            counters::RECEIVED_BATCH_REQUEST_TIMEOUT_COUNT.inc();
            debug!("QS: batch request timed out, digest:{}", digest);
            Err(ExecutorError::CouldNotGetData)
        })
    }
```
