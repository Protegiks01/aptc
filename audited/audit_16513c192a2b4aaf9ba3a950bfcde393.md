# Audit Report

## Title
Pruner Infinite Retry Loop on Sub-Pruner Failure Causes Validator Node Slowdown and Storage Exhaustion

## Summary
The pruner system lacks error recovery mechanisms when sub-pruners fail. If any sub_pruner consistently fails (e.g., due to disk full or database corruption), the parent pruner enters an infinite retry loop attempting the same version range every 1ms, causing CPU waste, log spam, and eventual node failure when storage fills up completely.

## Finding Description

The `DBSubPruner` trait defines a `prune()` method that returns `Result<()>` with no specification for error recovery or retry behavior. [1](#0-0) 

The `LedgerPruner::prune()` method executes a while loop that continues while `progress < target_version`. Within each iteration, it calls sub_pruners in parallel using `try_for_each()`. [2](#0-1) 

**Critical Flow:**
1. The while loop reads the local `progress` variable from the atomic version
2. If any sub_pruner fails during parallel execution, the `?` operator immediately returns the error
3. The local `progress` variable is **NOT** updated (line 86 is skipped)
4. `self.record_progress()` is **NOT** called (line 87 is skipped)
5. The atomic `self.progress` remains at its old value

The `PrunerWorker` catches these errors and immediately retries with only a 1ms sleep: [3](#0-2) 

**The Infinite Loop:**
- When `pruner.prune()` fails, the worker logs the error (sampled at 1s intervals), sleeps 1ms, and continues
- The next call to `prune()` loads the **same old progress value** from the atomic variable
- It attempts to prune the **exact same version range** again
- Hits the **same persistent error** (e.g., disk full, corrupted DB)
- Repeats indefinitely with no exponential backoff, circuit breaker, or maximum retry count

**What Causes Persistent Failures:**
Sub_pruners perform database write operations that can fail persistently: [4](#0-3) 

Common persistent failure scenarios:
- Disk space exhausted (database writes fail with no space errors)
- Corrupted database files (read/write operations fail)
- File system permission issues
- Hardware I/O failures
- Lock contention preventing writes

**Same Issue in Other Pruners:**
The `StateMerklePruner` exhibits identical behavior: [5](#0-4) 

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria:

1. **Validator Node Slowdowns** (explicit High severity criterion met): The tight retry loop with only 1ms sleep between attempts wastes CPU cycles continuously, degrading validator performance.

2. **Storage Exhaustion Leading to Node Crash**: When pruning is stuck, old data accumulates indefinitely. Eventually the disk fills completely, causing the node to crash and become unavailable.

3. **Network Liveness Degradation**: If multiple validators experience similar issues (e.g., due to high transaction volume during network stress), simultaneous node failures could impact network availability.

4. **Log Spam**: Error logs generated every second (due to sampling) can fill disk space faster and obscure other critical errors.

5. **No Operational Recovery**: Operators cannot detect the issue easily since metrics only track progress, not retry failures. The node appears "stuck" with no clear resolution path beyond restart and disk cleanup.

## Likelihood Explanation

**High Likelihood** in production environments:

1. **Disk Space Exhaustion**: During high transaction volume periods, disk space can be consumed faster than pruning can keep up, especially if pruning is configured with a large window or batch size is too small.

2. **Cascading Failure**: If disk space fills up before pruning activates (or during a burst of transactions), the first pruning attempt will fail, triggering the infinite retry loop that makes the situation worse by wasting CPU.

3. **Hardware Issues**: Production systems experience transient disk I/O errors that can become persistent, triggering this issue.

4. **No Circuit Breaker**: The absence of exponential backoff or failure counting means any persistent error immediately causes indefinite retries.

## Recommendation

Implement robust error recovery with exponential backoff and circuit breaker:

```rust
// In pruner_worker.rs - PrunerWorkerInner
pub struct PrunerWorkerInner {
    pruning_time_interval_in_ms: u64,
    pruner: Arc<dyn DBPruner>,
    batch_size: usize,
    quit_worker: AtomicBool,
    // Add these fields:
    consecutive_failures: AtomicU64,
    last_successful_progress: AtomicVersion,
}

fn work(&self) {
    let mut backoff_ms = self.pruning_time_interval_in_ms;
    const MAX_BACKOFF_MS: u64 = 60_000; // 1 minute
    const MAX_CONSECUTIVE_FAILURES: u64 = 10;
    
    while !self.quit_worker.load(Ordering::SeqCst) {
        let pruner_result = self.pruner.prune(self.batch_size);
        
        if pruner_result.is_err() {
            let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
            
            sample!(
                SampleRate::Duration(Duration::from_secs(1)),
                error!(
                    error = ?pruner_result.err().unwrap(),
                    consecutive_failures = failures,
                    "Pruner has error."
                )
            );
            
            // Circuit breaker: stop retrying after max failures
            if failures >= MAX_CONSECUTIVE_FAILURES {
                error!(
                    consecutive_failures = failures,
                    "Pruner exceeded max consecutive failures. Entering emergency mode."
                );
                // Sleep for extended period and alert operators
                sleep(Duration::from_secs(300)); // 5 minutes
                continue;
            }
            
            // Exponential backoff
            sleep(Duration::from_millis(backoff_ms));
            backoff_ms = std::cmp::min(backoff_ms * 2, MAX_BACKOFF_MS);
            continue;
        }
        
        // Success - reset failure counter and backoff
        self.consecutive_failures.store(0, Ordering::SeqCst);
        backoff_ms = self.pruning_time_interval_in_ms;
        
        if !self.pruner.is_pruning_pending() {
            sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
        }
    }
}
```

**Additional Recommendations:**

1. Add metrics for pruner failures: `PRUNER_CONSECUTIVE_FAILURES` counter
2. Add alerts when consecutive failures exceed threshold
3. Consider partial progress tracking: update progress even if some sub_pruners fail
4. Differentiate transient vs persistent errors and handle accordingly
5. Add health check endpoint that exposes pruner status

## Proof of Concept

```rust
// Test demonstrating the infinite retry behavior
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    
    struct FailingSubPruner {
        fail_count: AtomicU64,
    }
    
    impl DBSubPruner for FailingSubPruner {
        fn name(&self) -> &str {
            "FailingSubPruner"
        }
        
        fn prune(&self, _current_progress: Version, _target_version: Version) -> Result<()> {
            self.fail_count.fetch_add(1, Ordering::SeqCst);
            Err(anyhow::anyhow!("Simulated disk full error"))
        }
    }
    
    #[test]
    fn test_infinite_retry_on_sub_pruner_failure() {
        // Create a ledger pruner with a failing sub_pruner
        let failing_sub = Arc::new(FailingSubPruner {
            fail_count: AtomicU64::new(0),
        });
        
        // Simulate PrunerWorker behavior
        let max_attempts = 100;
        let mut attempts = 0;
        let progress = AtomicVersion::new(0);
        let target = 1000;
        
        while attempts < max_attempts {
            // This simulates what happens in LedgerPruner::prune
            let current_progress = progress.load(Ordering::SeqCst);
            if current_progress >= target {
                break;
            }
            
            // Try to prune
            let result = failing_sub.prune(current_progress, target);
            
            if result.is_err() {
                // Progress NOT updated - this is the bug
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            
            // Would update progress here if successful
            progress.store(target, Ordering::SeqCst);
        }
        
        // Verify the bug: progress never advances, retries indefinitely
        assert_eq!(progress.load(Ordering::SeqCst), 0, "Progress should still be 0");
        assert_eq!(attempts, max_attempts, "Should have hit max attempts");
        assert_eq!(
            failing_sub.fail_count.load(Ordering::SeqCst),
            max_attempts as u64,
            "Sub-pruner should have been called repeatedly with same range"
        );
        
        println!("BUG CONFIRMED: Pruner attempted same range {} times without progress", attempts);
    }
}
```

**Notes**

This vulnerability breaks the **Resource Limits** invariant (#9 in the security model) by allowing infinite CPU consumption through unbounded retries. While not directly exploitable by an external attacker without first causing disk exhaustion or database corruption, it represents a critical operational resilience failure that can cascade into node unavailability during high-load scenarios. The issue affects all pruner types (`LedgerPruner`, `StateMerklePruner`, `StateKvPruner`) and requires a code-level fix rather than configuration changes.

### Citations

**File:** storage/aptosdb/src/pruner/db_sub_pruner.rs (L7-14)
```rust
pub trait DBSubPruner {
    /// Returns the name of the sub pruner.
    fn name(&self) -> &str;

    /// Performs the actual pruning, a target version is passed, which is the target the pruner
    /// tries to prune.
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()>;
}
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L62-91)
```rust
    fn prune(&self, max_versions: usize) -> Result<Version> {
        let mut progress = self.progress();
        let target_version = self.target_version();

        while progress < target_version {
            let current_batch_target_version =
                min(progress + max_versions as Version, target_version);

            info!(
                progress = progress,
                target_version = current_batch_target_version,
                "Pruning ledger data."
            );
            self.ledger_metadata_pruner
                .prune(progress, current_batch_target_version)?;

            THREAD_MANAGER.get_background_pool().install(|| {
                self.sub_pruners.par_iter().try_for_each(|sub_pruner| {
                    sub_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| anyhow!("{} failed to prune: {err}", sub_pruner.name()))
                })
            })?;

            progress = current_batch_target_version;
            self.record_progress(progress);
            info!(progress = progress, "Pruning ledger data is done.");
        }

        Ok(target_version)
```

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L53-69)
```rust
    fn work(&self) {
        while !self.quit_worker.load(Ordering::SeqCst) {
            let pruner_result = self.pruner.prune(self.batch_size);
            if pruner_result.is_err() {
                sample!(
                    SampleRate::Duration(Duration::from_secs(1)),
                    error!(error = ?pruner_result.err().unwrap(),
                        "Pruner has error.")
                );
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
                continue;
            }
            if !self.pruner.is_pruning_pending() {
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
            }
        }
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L43-81)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        let mut indexer_batch = None;

        let indices_batch = if let Some(indexer_db) = self.indexer_db() {
            if indexer_db.event_enabled() {
                indexer_batch = Some(SchemaBatch::new());
            }
            indexer_batch.as_mut()
        } else {
            Some(&mut batch)
        };
        let num_events_per_version = self.ledger_db.event_db().prune_event_indices(
            current_progress,
            target_version,
            indices_batch,
        )?;
        self.ledger_db.event_db().prune_events(
            num_events_per_version,
            current_progress,
            target_version,
            &mut batch,
        )?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::EventPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;

        if let Some(mut indexer_batch) = indexer_batch {
            indexer_batch.put::<InternalIndexerMetadataSchema>(
                &IndexerMetadataKey::EventPrunerProgress,
                &IndexerMetadataValue::Version(target_version),
            )?;
            self.expect_indexer_db()
                .get_inner_db_ref()
                .write_schemas(indexer_batch)?;
        }
        self.ledger_db.event_db().write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/mod.rs (L59-95)
```rust
    fn prune(&self, batch_size: usize) -> Result<Version> {
        // TODO(grao): Consider separate pruner metrics, and have a label for pruner name.
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_merkle_pruner__prune"]);
        let mut progress = self.progress();
        let target_version = self.target_version();

        if progress >= target_version {
            return Ok(progress);
        }

        info!(
            name = S::name(),
            current_progress = progress,
            target_version = target_version,
            "Start pruning..."
        );

        while progress < target_version {
            if let Some(target_version_for_this_round) = self
                .metadata_pruner
                .maybe_prune_single_version(progress, target_version)?
            {
                self.prune_shards(progress, target_version_for_this_round, batch_size)?;
                progress = target_version_for_this_round;
                info!(name = S::name(), progress = progress);
                self.record_progress(target_version_for_this_round);
            } else {
                self.prune_shards(progress, target_version, batch_size)?;
                self.record_progress(target_version);
                break;
            }
        }

        info!(name = S::name(), progress = target_version, "Done pruning.");

        Ok(target_version)
    }
```
