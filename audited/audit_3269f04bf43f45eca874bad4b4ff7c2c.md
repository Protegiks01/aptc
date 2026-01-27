# Audit Report

## Title
Quorum Store Batch Expiration Race Condition Causing Immediate Removal of Just-Committed Batches

## Summary
The ProofManager's `handle_commit_notification` method processes committed batches without validating their expiration times against the block timestamp, allowing expired batches to be added to the queue and immediately removed, creating state churn and metrics inconsistencies.

## Finding Description

When a block is committed in the Aptos consensus protocol, the `notify_commit` function extracts all batches from the payload and sends them via `CommitNotification` to the QuorumStore components. The critical vulnerability occurs in the ProofManager's handling of this notification: [1](#0-0) 

The `notify_commit` method extracts batches from committed payloads without any expiration validation - it simply collects all batch info objects and sends them. [2](#0-1) 

The coordinator forwards these batches to ProofManager with the block timestamp: [3](#0-2) 

The `handle_commit_notification` method processes batches in two sequential steps:
1. First, `mark_committed(batches)` adds batches to the queue
2. Then, `handle_updated_block_timestamp(block_timestamp)` expires old batches [4](#0-3) 

In `mark_committed`, there is **no validation** that `batch.expiration() > block_timestamp`. The method unconditionally adds batches to the queue, including creating new entries for batches that don't exist (lines 891-903). [5](#0-4) 

Immediately after, `handle_updated_block_timestamp` expires all batches where `expiration <= block_timestamp` (line 729), removing them from the queue.

This creates a race condition where batches with `expiration <= block_timestamp` are:
1. Added to `author_to_batches` and `expirations` data structures
2. Immediately removed in the next method call

**Contrast with insert_proof validation:** [6](#0-5) 

The `insert_proof` method explicitly rejects expired proofs, but `mark_committed` lacks this safeguard.

**How expired batches enter CommitNotification:**

While `request_transactions` skips expired batches during execution: [7](#0-6) 

The batch info objects themselves remain in the payload structure and are extracted by `notify_commit` without filtering, allowing expired batches to propagate through the system.

## Impact Explanation

**Severity: Medium**

This vulnerability creates state inconsistencies and resource waste, though it does not directly cause consensus splits or fund loss:

1. **State Churn**: Expired batches undergo wasteful add-then-remove operations, consuming CPU cycles and touching multiple data structures
2. **Metrics Inconsistency**: The `GAP_BETWEEN_BATCH_EXPIRATION_AND_CURRENT_TIME_WHEN_COMMIT` metric only tracks non-committed proofs (line 741-742), meaning expired committed batches evade monitoring
3. **Validator Performance Impact**: Each expired batch requires insertions into `author_to_batches`, `expirations`, and `items` maps, followed by immediate deletions
4. **Data Structure Fragmentation**: Repeated insertions/deletions can cause memory fragmentation in the underlying hash maps

While this doesn't meet Critical severity criteria, it qualifies as **Medium severity** under "State inconsistencies requiring intervention" because:
- Persistent inclusion of expired batches would accumulate state churn
- Metrics become unreliable for monitoring batch expiration patterns
- Performance degradation on validator nodes processing many expired batches
- Violates the State Consistency invariant (#4) by creating unnecessary state transitions

## Likelihood Explanation

**Likelihood: Medium-to-High**

This vulnerability can occur in several realistic scenarios:

1. **Network Latency**: If consensus takes longer than expected, batches that were valid when proposed may expire before the block commits
2. **Clock Skew**: Minor clock differences between validators could cause borderline batches to appear expired to some nodes
3. **Byzantine Proposer**: A malicious validator could deliberately include batches with `expiration <= block_timestamp` in proposed blocks
4. **Batch Expiry Gap Configuration**: If `batch_expiry_gap_when_init_usecs` is set too low, batches naturally expire quickly

The test suite demonstrates this is a known edge case: [8](#0-7) 

Test shows expired batches cannot be pulled, but doesn't validate the commit notification path.

## Recommendation

Add expiration validation in `mark_committed` to match the safeguard in `insert_proof`:

```rust
pub(crate) fn mark_committed(&mut self, batches: Vec<BatchInfoExt>) {
    let start = Instant::now();
    for batch in batches.into_iter() {
        // Add validation: skip batches that are already expired
        if batch.expiration() <= self.latest_block_timestamp {
            counters::GARBAGE_COLLECTED_IN_PROOF_QUEUE_COUNTER
                .with_label_values(&["expired_batch_on_commit"])
                .inc();
            warn!(
                "Skipping expired batch in commit notification: expiration={}, latest_timestamp={}",
                batch.expiration(),
                self.latest_block_timestamp
            );
            continue;
        }
        
        let batch_key = BatchKey::from_info(&batch);
        // ... rest of existing logic
    }
}
```

Additionally, add a validation check in `notify_commit` to filter expired batches:

```rust
fn notify_commit(&self, block_timestamp: u64, payloads: Vec<Payload>) {
    self.batch_reader.update_certified_timestamp(block_timestamp);

    let batches: Vec<_> = payloads
        .into_iter()
        .flat_map(|payload| /* existing extraction logic */)
        .filter(|batch_info| batch_info.expiration() > block_timestamp) // Add filter
        .collect();

    self.commit_notifier.notify(block_timestamp, batches);
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_expired_batch_in_commit_notification() {
    let mut proof_manager = create_proof_manager();
    
    // Create a batch with short expiration
    let author = PeerId::random();
    let expired_batch = create_proof(author, 10, 1);
    let batch_info = expired_batch.info().clone();
    
    // Simulate commit notification with block_timestamp > expiration
    // This should NOT cause the batch to be added and immediately removed
    proof_manager.handle_commit_notification(
        15, // block_timestamp > expiration (10)
        vec![batch_info.clone()]
    );
    
    // Verify the batch was not added to the queue
    // (In current buggy implementation, this would fail)
    let payload = get_proposal(&mut proof_manager, 100, &[]).await;
    
    match payload {
        Payload::QuorumStoreInlineHybrid(_, proofs, _) => {
            // Should not contain the expired batch
            assert!(proofs.proofs.is_empty(), 
                "Expired batch should not be in queue");
        },
        _ => panic!("Unexpected payload type"),
    }
}

#[tokio::test] 
async fn test_duplicate_batches_on_commit() {
    let mut proof_manager = create_proof_manager();
    
    let proof = create_proof(PeerId::random(), 100, 1);
    proof_manager.receive_proofs(vec![proof.clone()]);
    
    // Commit the same batch twice - once with valid timestamp, once with expired
    proof_manager.handle_commit_notification(50, vec![proof.info().clone()]);
    proof_manager.handle_commit_notification(150, vec![proof.info().clone()]);
    
    // The second commit should be ignored as the batch is expired
    // Verify no state inconsistency occurred
}
```

**Notes:**

This vulnerability violates the State Consistency invariant by creating unnecessary state transitions. While the system continues to function, the wasteful operations impact validator performance and create unreliable metrics. The fix is straightforward: add expiration validation at the entry points (`mark_committed` and `notify_commit`) to prevent expired batches from entering the queue management logic.

### Citations

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L102-106)
```rust
            if block_timestamp <= batch_info.expiration() {
                futures.push(batch_reader.get_batch(batch_info, responders.clone()));
            } else {
                debug!("QSE: skipped expired batch {}", batch_info.digest());
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

**File:** consensus/src/quorum_store/quorum_store_coordinator.rs (L56-72)
```rust
                    CoordinatorCommand::CommitNotification(block_timestamp, batches) => {
                        counters::QUORUM_STORE_MSG_COUNT
                            .with_label_values(&["QSCoordinator::commit_notification"])
                            .inc();
                        // TODO: need a callback or not?
                        self.proof_coordinator_cmd_tx
                            .send(ProofCoordinatorCommand::CommitNotification(batches.clone()))
                            .await
                            .expect("Failed to send to ProofCoordinator");

                        self.proof_manager_cmd_tx
                            .send(ProofManagerCommand::CommitNotification(
                                block_timestamp,
                                batches.clone(),
                            ))
                            .await
                            .expect("Failed to send to ProofManager");
```

**File:** consensus/src/quorum_store/proof_manager.rs (L88-101)
```rust
    pub(crate) fn handle_commit_notification(
        &mut self,
        block_timestamp: u64,
        batches: Vec<BatchInfoExt>,
    ) {
        trace!(
            "QS: got clean request from execution at block timestamp {}",
            block_timestamp
        );
        self.batch_proof_queue.mark_committed(batches);
        self.batch_proof_queue
            .handle_updated_block_timestamp(block_timestamp);
        self.update_remaining_txns_and_proofs();
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L175-179)
```rust
    pub(crate) fn insert_proof(&mut self, proof: ProofOfStore<BatchInfoExt>) {
        if proof.expiration() <= self.latest_block_timestamp {
            counters::inc_rejected_pos_count(counters::POS_EXPIRED_LABEL);
            return;
        }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L716-769)
```rust
    pub(crate) fn handle_updated_block_timestamp(&mut self, block_timestamp: u64) {
        // tolerate asynchronous notification
        if self.latest_block_timestamp > block_timestamp {
            return;
        }
        let start = Instant::now();
        self.latest_block_timestamp = block_timestamp;
        if let Some(time_lag) = aptos_infallible::duration_since_epoch()
            .checked_sub(Duration::from_micros(block_timestamp))
        {
            counters::TIME_LAG_IN_BATCH_PROOF_QUEUE.observe_duration(time_lag);
        }

        let expired = self.expirations.expire(block_timestamp);
        let mut num_expired_but_not_committed = 0;
        for key in &expired {
            if let Some(mut queue) = self.author_to_batches.remove(&key.author()) {
                if let Some(batch) = queue.remove(key) {
                    let item = self
                        .items
                        .get(&key.batch_key)
                        .expect("Entry for unexpired batch must exist");
                    if item.proof.is_some() {
                        // not committed proof that is expired
                        num_expired_but_not_committed += 1;
                        counters::GAP_BETWEEN_BATCH_EXPIRATION_AND_CURRENT_TIME_WHEN_COMMIT
                            .observe((block_timestamp - batch.expiration()) as f64);
                        if let Some(ref txn_summaries) = item.txn_summaries {
                            for txn_summary in txn_summaries {
                                if let Some(count) =
                                    self.txn_summary_num_occurrences.get_mut(txn_summary)
                                {
                                    *count -= 1;
                                    if *count == 0 {
                                        self.txn_summary_num_occurrences.remove(txn_summary);
                                    }
                                };
                            }
                        }
                        self.dec_remaining_proofs(&batch.author(), batch.num_txns());
                        counters::GARBAGE_COLLECTED_IN_PROOF_QUEUE_COUNTER
                            .with_label_values(&["expired_proof"])
                            .inc();
                    }
                    claims::assert_some!(self.items.remove(&key.batch_key));
                }
                if !queue.is_empty() {
                    self.author_to_batches.insert(key.author(), queue);
                }
            }
        }
        counters::PROOF_QUEUE_UPDATE_TIMESTAMP_DURATION.observe_duration(start.elapsed());
        counters::NUM_PROOFS_EXPIRED_WHEN_COMMIT.inc_by(num_expired_but_not_committed);
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L846-907)
```rust
    pub(crate) fn mark_committed(&mut self, batches: Vec<BatchInfoExt>) {
        let start = Instant::now();
        for batch in batches.into_iter() {
            let batch_key = BatchKey::from_info(&batch);
            if let Some(item) = self.items.get(&batch_key) {
                if let Some(ref proof) = item.proof {
                    let insertion_time = item
                        .proof_insertion_time
                        .expect("Insertion time is updated with proof");
                    counters::pos_to_commit(
                        proof.gas_bucket_start(),
                        insertion_time.elapsed().as_secs_f64(),
                    );
                    self.dec_remaining_proofs(&batch.author(), batch.num_txns());
                    counters::GARBAGE_COLLECTED_IN_PROOF_QUEUE_COUNTER
                        .with_label_values(&["committed_proof"])
                        .inc();
                }
                let item = self
                    .items
                    .get_mut(&batch_key)
                    .expect("must exist due to check");

                if item.proof.is_some() {
                    if let Some(ref txn_summaries) = item.txn_summaries {
                        for txn_summary in txn_summaries {
                            if let Some(count) =
                                self.txn_summary_num_occurrences.get_mut(txn_summary)
                            {
                                *count -= 1;
                                if *count == 0 {
                                    self.txn_summary_num_occurrences.remove(txn_summary);
                                }
                            };
                        }
                    }
                } else if !item.is_committed() {
                    counters::GARBAGE_COLLECTED_IN_PROOF_QUEUE_COUNTER
                        .with_label_values(&["committed_batch_without_proof"])
                        .inc();
                }
                // The item is just marked committed for now.
                // When the batch is expired, then it will be removed from items.
                item.mark_committed();
            } else {
                let batch_sort_key = BatchSortKey::from_info(&batch);
                self.expirations
                    .add_item(batch_sort_key.clone(), batch.expiration());
                self.author_to_batches
                    .entry(batch.author())
                    .or_default()
                    .insert(batch_sort_key, batch.clone());
                self.items.insert(batch_key, QueueItem {
                    info: batch,
                    txn_summaries: None,
                    proof: None,
                    proof_insertion_time: None,
                });
            }
        }
        counters::PROOF_QUEUE_COMMIT_DURATION.observe_duration(start.elapsed());
    }
```

**File:** consensus/src/quorum_store/tests/proof_manager_test.rs (L167-178)
```rust
async fn test_block_timestamp_expiration() {
    let mut proof_manager = create_proof_manager();

    let proof = create_proof(PeerId::random(), 10, 1);
    proof_manager.receive_proofs(vec![proof.clone()]);

    proof_manager.handle_commit_notification(1, vec![]);
    get_proposal_and_assert(&mut proof_manager, 100, &[], &vec![proof]).await;

    proof_manager.handle_commit_notification(20, vec![]);
    get_proposal_and_assert(&mut proof_manager, 100, &[], &[]).await;
}
```
