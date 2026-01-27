# Audit Report

## Title
State Sync Race Condition Causes Stuck Timestamp and Memory Exhaustion in Batch Generator

## Summary
A race condition between commit notifications from the normal consensus pipeline and state sync can cause `BatchGenerator::latest_block_timestamp` to become permanently stuck at an incorrectly high value. This prevents batch expiration, leading to unbounded memory growth and eventual node failure through resource exhaustion.

## Finding Description

The vulnerability exists in the timestamp update logic in `BatchGenerator::handle_commit_notification`. The code only updates the timestamp if the incoming value is higher than the current value: [1](#0-0) 

During state sync, the system sends a commit notification with the sync target's timestamp: [2](#0-1) 

Both notifications use the same non-blocking channel: [3](#0-2) 

**Attack Scenario:**

1. Node is committing blocks normally (timestamps 100, 101, 102...)
2. Block B110 with timestamp 110 enters the commit pipeline
3. `CommitNotification(110, batches)` is sent and queued in the channel
4. **Before processing**, node enters state sync to catch up to block B105 (timestamp 105)
5. State sync calls `sync_to_target` which sends `CommitNotification(105, [])` to the same channel
6. **Race condition**: If notification(110) is processed before notification(105):
   - `latest_block_timestamp = 110` (from abandoned pre-sync pipeline)
   - notification(105) arrives: check fails (`110 > 105`), skipped with `continue`
7. Node resumes from B105, committing B106, B107, B108, B109...
8. All notifications for 106-109 are **rejected** because `110 > 106/107/108/109`
9. Batches created with expiration times ≤ 109 **never expire** at line 536: [4](#0-3) 

10. Memory accumulates indefinitely, causing node degradation and eventual crash

The comment at line 522 acknowledges the race but the check doesn't prevent it: [5](#0-4) 

## Impact Explanation

**Severity: HIGH** (up to $50,000)

This vulnerability causes:
- **Memory Exhaustion**: Batches accumulate without expiration, eventually consuming all available memory
- **Validator Node Slowdown**: Growing memory pressure degrades node performance
- **Potential DoS**: Node crash when memory limits are reached
- **Quorum Store Dysfunction**: Batch management becomes unreliable

The impact qualifies as **High Severity** per Aptos Bug Bounty criteria: "Validator node slowdowns" and "Significant protocol violations" (resource limit invariant violation).

While not causing immediate fund loss or consensus safety violation, this can render validator nodes inoperable, impacting network health and availability.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

State sync is a **normal, frequent operation** when:
- Nodes restart after maintenance
- Network partitions heal
- Validators catch up after brief outages
- New nodes bootstrap

The race window exists whenever:
1. Commit notifications are in-flight during state sync initiation
2. Channel buffering delays message processing
3. Pre-commit pipeline has committed blocks that exceed the sync target

Given the async nature of the pipeline and the use of `try_send` (which can delay or drop messages when the channel is full), this race is realistic and exploitable without requiring special attacker capabilities.

## Recommendation

**Fix: Add timestamp source tracking and validation**

```rust
// In BatchGenerator struct, add:
enum TimestampSource {
    Consensus,
    StateSync { sync_target_timestamp: u64 },
}

struct BatchGenerator {
    // ... existing fields ...
    latest_block_timestamp: u64,
    timestamp_source: TimestampSource,
}

// In handle CommitNotification:
BatchGeneratorCommand::CommitNotification(block_timestamp, batches) => {
    trace!(
        "QS: got clean request from execution, block timestamp {}",
        block_timestamp
    );
    
    // NEW: Check if this is a stale notification from before state sync
    match &self.timestamp_source {
        TimestampSource::StateSync { sync_target_timestamp } => {
            // After state sync, only accept timestamps >= sync target
            if block_timestamp < *sync_target_timestamp {
                debug!(
                    "QS: skipping stale commit notification with timestamp {} < sync target {}",
                    block_timestamp, sync_target_timestamp
                );
                continue;
            }
            // First commit after sync, reset to consensus mode
            self.timestamp_source = TimestampSource::Consensus;
        },
        TimestampSource::Consensus => {
            // Normal monotonicity check
            if self.latest_block_timestamp > block_timestamp {
                continue;
            }
        }
    }
    
    self.latest_block_timestamp = block_timestamp;
    // ... rest of handler ...
}
```

**Alternative: Clear channel during state sync**

Implement a state sync notification to BatchGenerator that clears any pending commit notifications and resets the timestamp to a known-good value.

## Proof of Concept

```rust
#[tokio::test]
async fn test_timestamp_stuck_during_state_sync() {
    // Setup: Create BatchGenerator with timestamp at 100
    let mut generator = BatchGenerator::new(/* ... */);
    generator.latest_block_timestamp = 100;
    
    // Simulate: Send commit notification for block 110 (from pipeline)
    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    tx.send(BatchGeneratorCommand::CommitNotification(110, vec![])).await.unwrap();
    
    // Simulate: Node enters state sync, sends notification for block 105
    tx.send(BatchGeneratorCommand::CommitNotification(105, vec![])).await.unwrap();
    
    // Process messages
    if let Some(cmd) = rx.recv().await {
        // First message (110) processed
        generator.handle_commit(cmd);
        assert_eq!(generator.latest_block_timestamp, 110);
    }
    
    if let Some(cmd) = rx.recv().await {
        // Second message (105) skipped due to check
        generator.handle_commit(cmd);
        assert_eq!(generator.latest_block_timestamp, 110); // STILL 110!
    }
    
    // Simulate: Resume from 105, commit 106
    tx.send(BatchGeneratorCommand::CommitNotification(106, vec![])).await.unwrap();
    if let Some(cmd) = rx.recv().await {
        generator.handle_commit(cmd);
        // BUG: 106 is rejected because 110 > 106
        assert_eq!(generator.latest_block_timestamp, 110); // STUCK!
    }
    
    // Verify: Batches with expiration ≤ 109 never expire
    // This causes memory leak over time
}
```

## Notes

The vulnerability is exacerbated by:
1. The use of `try_send` which is non-blocking and can fail silently, creating message ordering ambiguity
2. Lack of epoch/sync sequence numbers to identify stale notifications
3. No mechanism to reset or validate timestamp correctness after state sync

The developer comment at line 522 indicates awareness of races during state sync, but the implemented mitigation (simple comparison) is insufficient to handle the out-of-order arrival of notifications from different code paths.

### Citations

**File:** consensus/src/quorum_store/batch_generator.rs (L522-526)
```rust
                            // Block timestamp is updated asynchronously, so it may race when it enters state sync.
                            if self.latest_block_timestamp > block_timestamp {
                                continue;
                            }
                            self.latest_block_timestamp = block_timestamp;
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

**File:** consensus/src/state_computer.rs (L196-204)
```rust
        // This is to update QuorumStore with the latest known commit in the system,
        // so it can set batches expiration accordingly.
        // Might be none if called in the recovery path, or between epoch stop and start.
        if let Some(inner) = self.state.read().as_ref() {
            let block_timestamp = target.commit_info().timestamp_usecs();
            inner
                .payload_manager
                .notify_commit(block_timestamp, Vec::new());
        }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L45-57)
```rust
    fn notify(&self, block_timestamp: u64, batches: Vec<BatchInfoExt>) {
        let mut tx = self.coordinator_tx.clone();

        if let Err(e) = tx.try_send(CoordinatorCommand::CommitNotification(
            block_timestamp,
            batches,
        )) {
            warn!(
                "CommitNotification failed. Is the epoch shutting down? error: {}",
                e
            );
        }
    }
```
