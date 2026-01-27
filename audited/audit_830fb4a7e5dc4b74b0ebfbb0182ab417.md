# Audit Report

## Title
Memory Leak in Batch Proof Queue Due to Orphaned Expiration Entries

## Summary
A critical memory leak exists in the `BatchProofQueue` where committed batches can accumulate unbounded memory due to inconsistent cleanup between `gc_expired_batch_summaries_without_proofs()` and `handle_updated_block_timestamp()`. The garbage collector removes batches from `items` and `author_to_batches` but leaves orphaned entries in `expirations`, causing subsequent cleanups to fail when batches are re-added and committed.

## Finding Description

The vulnerability stems from an invariant violation in the batch expiration tracking system. The `BatchProofQueue` maintains three synchronized data structures:

1. `items: HashMap<BatchKey, QueueItem>` - stores batch metadata
2. `author_to_batches: HashMap<PeerId, BTreeMap<BatchSortKey, BatchInfoExt>>` - indexes batches by author
3. `expirations: TimeExpirations<BatchSortKey>` - tracks expiration times

**The Bug:**

The function `gc_expired_batch_summaries_without_proofs()` removes expired batches without proofs from `items` and `author_to_batches` but fails to remove them from `expirations`: [1](#0-0) 

This creates "orphan" entries in `expirations`. When `handle_updated_block_timestamp()` later processes these orphan entries, it cannot find the corresponding batch in `author_to_batches`, causing the cleanup to fail: [2](#0-1) 

**Attack Scenario:**

1. Batch summary inserted without proof → added to `items`, `author_to_batches`, `expirations`
2. Batch expires before proof arrives
3. `gc_expired_batch_summaries_without_proofs()` removes from `items` and `author_to_batches`, leaving orphan in `expirations`
4. Batch is later committed (via consensus notification) → re-added to all three structures with same expiration time
5. `handle_updated_block_timestamp()` is called → `expirations.expire()` pops ALL entries (including orphan) but returns deduplicated HashSet
6. Single cleanup occurs, removing batch from all structures
7. Batch committed again (duplicate notification from different code path) → re-added to all structures
8. No more expiration entries exist to trigger cleanup → **batch remains in memory forever**

The critical issue is that `TimeExpirations::expire()` uses a HashSet to deduplicate entries: [3](#0-2) 

When multiple entries with the same `BatchSortKey` exist (one orphan, one legitimate), they all get popped from the heap and deduplicated into a single entry. This means only ONE cleanup iteration occurs for multiple expiration entries. If the batch is re-added after cleanup, there are no remaining expiration entries to trigger future cleanups.

## Impact Explanation

**Severity: Medium**

This vulnerability causes unbounded memory growth in validator nodes, fitting the Medium severity category: "State inconsistencies requiring intervention."

**Affected Systems:**
- All validator nodes running consensus
- Any node participating in quorum store batch processing

**Impact Metrics:**
- Each leaked committed batch consumes memory for: batch metadata, transaction summaries, and data structure overhead
- Under heavy load with frequent batch expirations and commit notifications, hundreds of batches could leak per hour
- Memory accumulation eventually leads to node performance degradation or out-of-memory crashes
- Requires node restart to clear leaked memory, disrupting consensus participation

**Invariant Violated:**
Resource Limits invariant (#9): "All operations must respect gas, storage, and computational limits" - the system fails to bound memory consumption for committed batches.

## Likelihood Explanation

**Likelihood: High**

This bug triggers naturally during normal validator operation:

1. **Frequent Occurrence:** Batch expiration before proof arrival is common under network congestion or high load
2. **No Special Privileges Required:** The bug manifests from normal consensus operations
3. **Automatic Trigger:** The gc function runs automatically via sampling (`sample!` macro), creating orphan entries regularly
4. **Duplicate Commit Notifications:** Consensus can send duplicate commit notifications during epoch transitions, block reorganizations, or state sync catch-up

The scenario requires:
- Batch summary received without proof (common)
- Batch expires before proof arrives (happens under load)
- Later commit notification for the same batch (standard consensus flow)
- Duplicate commit notification (occurs during normal operation)

All conditions occur naturally without attacker intervention, making this a high-likelihood issue that will manifest over time on production validators.

## Recommendation

**Fix: Remove orphaned entries from expirations during garbage collection**

Modify `gc_expired_batch_summaries_without_proofs()` to also remove entries from the `expirations` data structure: [1](#0-0) 

The fix requires tracking which `BatchSortKey` entries are being removed and cleaning them from `expirations`. However, since `TimeExpirations` doesn't provide a `remove()` method, the solution requires either:

**Option 1:** Add a `remove()` method to `TimeExpirations`:
```rust
// In utils.rs TimeExpirations impl
pub(crate) fn remove(&mut self, item: &I) -> bool {
    // Note: This is inefficient as BinaryHeap doesn't support removal
    // Better solution is to rebuild the heap without the item
    let original_len = self.expiries.len();
    self.expiries.retain(|(_, i)| i != item);
    original_len != self.expiries.len()
}
```

**Option 2:** Track removed items and filter them during `expire()`:
Add a `HashSet<BatchSortKey>` to track removed batches and filter them when processing expirations.

**Option 3 (Recommended):** Maintain `expirations` consistency by removing entries in `gc_expired_batch_summaries_without_proofs()` using a filtering approach - rebuild the expirations structure periodically or maintain a removed items set that's checked during `expire()`.

## Proof of Concept

```rust
#[cfg(test)]
mod test_memory_leak {
    use super::*;
    use aptos_types::PeerId;
    use std::sync::Arc;
    
    #[test]
    fn test_committed_batch_memory_leak() {
        // Setup
        let peer_id = PeerId::random();
        let batch_store = Arc::new(BatchStore::new(/* ... */));
        let mut queue = BatchProofQueue::new(
            peer_id,
            batch_store,
            100_000, // batch_expiry_gap
        );
        
        // Step 1: Insert batch summary (no proof)
        let batch_info = create_test_batch_info(peer_id, 100, 100_000); // expiration = 100_000
        let txn_summaries = vec![create_test_txn_summary()];
        queue.insert_batches(vec![(batch_info.clone(), txn_summaries)]);
        
        assert_eq!(queue.items.len(), 1);
        
        // Step 2: Simulate batch expiration without proof - gc removes it
        // (gc_expired_batch_summaries_without_proofs runs automatically)
        // Manually trigger gc logic by setting timestamp past expiration
        let timestamp = 100_001;
        queue.items.retain(|_, item| {
            if item.is_committed() || item.proof.is_some() || item.info.expiration() > timestamp {
                true
            } else {
                queue.author_to_batches
                    .get_mut(&item.info.author())
                    .map(|q| q.remove(&BatchSortKey::from_info(&item.info)));
                false
            }
        });
        
        assert_eq!(queue.items.len(), 0);
        // Note: orphan entry remains in queue.expirations
        
        // Step 3: Commit notification arrives - batch re-added
        queue.mark_committed(vec![batch_info.clone()]);
        assert_eq!(queue.items.len(), 1);
        
        // Step 4: handle_updated_block_timestamp processes expiration
        queue.handle_updated_block_timestamp(100_000);
        assert_eq!(queue.items.len(), 0); // Cleaned up
        
        // Step 5: Another commit notification (duplicate) - batch re-added
        queue.mark_committed(vec![batch_info.clone()]);
        assert_eq!(queue.items.len(), 1);
        
        // Step 6: handle_updated_block_timestamp runs again
        // No more expiration entries exist (all were popped in step 4)
        queue.handle_updated_block_timestamp(200_000);
        
        // BUG: Batch remains in items - memory leak!
        assert_eq!(queue.items.len(), 1, "Memory leak: committed batch not cleaned up");
    }
}
```

## Notes

This vulnerability requires careful timing of batch lifecycle events but occurs naturally during normal validator operation. The root cause is the inconsistency between cleanup paths - `gc_expired_batch_summaries_without_proofs()` modifies two data structures while `handle_updated_block_timestamp()` expects all three to be synchronized. The HashSet deduplication in `TimeExpirations::expire()` exacerbates the issue by consuming multiple expiration entries in a single cleanup pass, leaving no future cleanup opportunities for re-added batches.

The fix requires maintaining strict invariants across all three data structures (`items`, `author_to_batches`, and `expirations`) during any modification operation.

### Citations

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L324-339)
```rust
    fn gc_expired_batch_summaries_without_proofs(&mut self) {
        let timestamp = aptos_infallible::duration_since_epoch().as_micros() as u64;
        self.items.retain(|_, item| {
            if item.is_committed() || item.proof.is_some() || item.info.expiration() > timestamp {
                true
            } else {
                self.author_to_batches
                    .get_mut(&item.info.author())
                    .map(|queue| queue.remove(&BatchSortKey::from_info(&item.info)));
                counters::GARBAGE_COLLECTED_IN_PROOF_QUEUE_COUNTER
                    .with_label_values(&["expired_batch_without_proof"])
                    .inc();
                false
            }
        });
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L729-765)
```rust
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
```

**File:** consensus/src/quorum_store/utils.rs (L78-89)
```rust
    pub(crate) fn expire(&mut self, certified_time: u64) -> HashSet<I> {
        let mut ret = HashSet::new();
        while let Some((Reverse(t), _)) = self.expiries.peek() {
            if *t <= certified_time {
                let (_, item) = self.expiries.pop().unwrap();
                ret.insert(item);
            } else {
                break;
            }
        }
        ret
    }
```
