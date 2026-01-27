# Audit Report

## Title
State Synchronization Path Bypasses Block Timestamp Validation, Causing Premature Batch Expiration in Quorum Store

## Summary
The `sync_to_target` path in the state synchronization flow calls `update_certified_timestamp` without waiting for the local clock to reach the block timestamp, unlike the normal execution path. This allows a Byzantine validator proposing blocks with inflated timestamps (within the 5-minute validation bound) to trigger premature batch expiration on nodes with slower clocks, causing quorum store denial-of-service and state inconsistencies.

## Finding Description

The vulnerability exists in the interaction between block timestamp validation and quorum store batch expiration through two distinct code paths:

**Path 1 (Normal Execution - Safe):** When a block is inserted during normal consensus, the code waits until the local clock reaches the block timestamp: [1](#0-0) 

**Path 2 (State Sync - Vulnerable):** When a node synchronizes to a committed block via `sync_to_target`, it immediately calls `notify_commit` with the block timestamp WITHOUT waiting: [2](#0-1) 

The `notify_commit` call triggers batch expiration in the quorum store: [3](#0-2) 

This updates the certified timestamp, which expires batches: [4](#0-3) 

The `TimeExpirations::expire` method at line 78 removes all batches with expiration time <= certified_time: [5](#0-4) 

**Attack Scenario:**

1. Nodes create batches with expiration = current_time + 60 seconds (configured gap)
2. Byzantine validator proposes block with timestamp = current_time + 240 seconds (within 5-minute validation bound) [6](#0-5) 

3. Validators with clocks near 240 seconds vote on the block (after waiting), and it gets committed
4. Node with slower clock (e.g., 60 seconds behind) receives the LedgerInfo via `sync_to_target`
5. Node immediately calls `update_certified_timestamp(240)` without waiting for its local clock to catch up
6. Batches with expiration 60-240 seconds are prematurely expired and deleted from storage [7](#0-6) 

7. When the node tries to save new batches with reasonable expirations, they're rejected: [8](#0-7) 

8. Expired batches have their transactions removed from tracking, allowing potential re-inclusion: [9](#0-8) 

## Impact Explanation

This vulnerability meets **High Severity** criteria (up to $50,000) under "Significant protocol violations" because:

1. **Quorum Store Denial-of-Service**: Nodes with slower clocks cannot save new batches, disrupting the quorum store's ability to batch transactions
2. **State Inconsistency**: Different nodes have different views of which batches are valid, violating state consistency invariants
3. **Batch Unavailability**: Prematurely expired batches are deleted from persistent storage, making them unavailable when needed for block execution
4. **Validator Performance Degradation**: Affected validators experience significant slowdowns due to batch fetching failures and quorum store malfunction

While not directly causing fund loss, this breaks the consensus protocol's liveness guarantees and creates state divergence between validators.

## Likelihood Explanation

**Likelihood: Medium to High**

- **Attacker Requirements**: Requires being a validator proposer (block leader) and having clock drift or intentionally setting system time ahead
- **Clock Skew Reality**: Clock skew of 30-240 seconds can occur legitimately due to NTP failures, network partitions, or misconfigured time synchronization
- **Detection Difficulty**: The attack is subtle and may be attributed to legitimate network issues rather than malicious behavior
- **Exploitation Complexity**: Low - simply propose blocks with inflated timestamps within validation bounds
- **Affected Nodes**: Any node with negative clock skew relative to the proposer's timestamp will be affected

## Recommendation

Add a timestamp validation check in the `sync_to_target` path to wait until the local clock reaches the block timestamp before calling `notify_commit`, similar to the normal execution path:

```rust
// In consensus/src/state_computer.rs, sync_to_target method
if let Some(inner) = self.state.read().as_ref() {
    let block_timestamp = target.commit_info().timestamp_usecs();
    
    // ADD THIS: Wait until local time catches up to block timestamp
    let block_time = Duration::from_micros(block_timestamp);
    if let Some(wait_duration) = block_time.checked_sub(
        aptos_infallible::duration_since_epoch()
    ) {
        if wait_duration > Duration::from_secs(1) {
            warn!(
                "Waiting {}ms for block timestamp during sync",
                wait_duration.as_millis()
            );
        }
        tokio::time::sleep(wait_duration).await;
    }
    
    inner
        .payload_manager
        .notify_commit(block_timestamp, Vec::new());
}
```

Additionally, add validation in `update_certified_timestamp` to prevent timestamps too far in the future: [10](#0-9) 

## Proof of Concept

```rust
// Test demonstrating premature batch expiration via sync_to_target
#[tokio::test]
async fn test_premature_batch_expiration_via_sync() {
    // 1. Setup: Create batch store with current time = 0
    let current_time = 0u64;
    let batch_store = create_test_batch_store(current_time);
    
    // 2. Create batch with expiration = 60 seconds
    let batch_expiration = current_time + 60_000_000; // 60 seconds in microseconds
    let batch = create_test_batch_with_expiration(batch_expiration);
    batch_store.save(&batch).expect("Batch should be saved");
    
    // 3. Simulate Byzantine block with inflated timestamp = 240 seconds
    let inflated_timestamp = current_time + 240_000_000; // 240 seconds
    
    // 4. Simulate sync_to_target calling update_certified_timestamp immediately
    // (without waiting for local clock to catch up)
    batch_store.update_certified_timestamp(inflated_timestamp);
    
    // 5. Verify batch was prematurely expired
    assert!(batch_store.get_batch_from_local(&batch.digest()).is_err(),
           "Batch should be prematurely expired even though real time is still 0");
    
    // 6. Verify new batches are rejected
    let new_batch_expiration = current_time + 120_000_000; // 120 seconds
    let new_batch = create_test_batch_with_expiration(new_batch_expiration);
    assert!(batch_store.save(&new_batch).is_err(),
           "New batch should be rejected due to inflated certified_time");
}
```

## Notes

This vulnerability specifically affects the state synchronization path and demonstrates a discrepancy between how the normal execution flow and the sync flow handle block timestamps. The root cause is the missing temporal validation before updating the certified timestamp during state sync, allowing future-dated blocks to prematurely expire valid batches on nodes with slower clocks.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L499-511)
```rust
        // ensure local time past the block time
        let block_time = Duration::from_micros(pipelined_block.timestamp_usecs());
        let current_timestamp = self.time_service.get_current_timestamp();
        if let Some(t) = block_time.checked_sub(current_timestamp) {
            if t > Duration::from_secs(1) {
                warn!(
                    "Long wait time {}ms for block {}",
                    t.as_millis(),
                    pipelined_block
                );
            }
            self.time_service.wait_until(block_time).await;
        }
```

**File:** consensus/src/state_computer.rs (L199-204)
```rust
        if let Some(inner) = self.state.read().as_ref() {
            let block_timestamp = target.commit_info().timestamp_usecs();
            inner
                .payload_manager
                .notify_commit(block_timestamp, Vec::new());
        }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L168-170)
```rust
    fn notify_commit(&self, block_timestamp: u64, payloads: Vec<Payload>) {
        self.batch_reader
            .update_certified_timestamp(block_timestamp);
```

**File:** consensus/src/quorum_store/batch_store.rs (L419-438)
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
```

**File:** consensus/src/quorum_store/batch_store.rs (L530-539)
```rust
    pub fn update_certified_timestamp(&self, certified_time: u64) {
        trace!("QS: batch reader updating time {:?}", certified_time);
        self.last_certified_time
            .fetch_max(certified_time, Ordering::SeqCst);

        let expired_keys = self.clear_expired_payload(certified_time);
        if let Err(e) = self.db.delete_batches(expired_keys) {
            debug!("Error deleting batches: {:?}", e)
        }
    }
```

**File:** consensus/src/quorum_store/utils.rs (L75-89)
```rust
    /// Expire and return items corresponding to expiration <= given certified time.
    /// Unwrap is safe because peek() is called in loop condition.
    #[allow(clippy::unwrap_used)]
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

**File:** consensus/consensus-types/src/block.rs (L534-539)
```rust
            // we can say that too far is 5 minutes in the future
            const TIMEBOUND: u64 = 300_000_000;
            ensure!(
                self.timestamp_usecs() <= (current_ts.as_micros() as u64).saturating_add(TIMEBOUND),
                "Blocks must not be too far in the future"
            );
```

**File:** consensus/src/quorum_store/batch_generator.rs (L536-552)
```rust
                            for (author, batch_id) in self.batch_expirations.expire(block_timestamp) {
                                if let Some(batch_in_progress) = self.batches_in_progress.get(&(author, batch_id)) {
                                    // If there is an identical batch with higher expiry time, re-insert it.
                                    if batch_in_progress.expiry_time_usecs > block_timestamp {
                                        self.batch_expirations.add_item((author, batch_id), batch_in_progress.expiry_time_usecs);
                                        continue;
                                    }
                                }
                                if self.remove_batch_in_progress(author, batch_id) {
                                    counters::BATCH_IN_PROGRESS_EXPIRED.inc();
                                    debug!(
                                        "QS: logical time based expiration batch w. id {} from batches_in_progress, new size {}",
                                        batch_id,
                                        self.batches_in_progress.len(),
                                    );
                                }
                            }
```
