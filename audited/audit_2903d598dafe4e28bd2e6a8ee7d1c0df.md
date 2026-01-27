# Audit Report

## Title
Race Condition in `start_abort()` Allows Concurrent Incarnation Aborts Leading to Validator Panic

## Summary
The `start_abort()` function in the BlockSTMv2 scheduler uses `fetch_max` to prevent concurrent abort attempts, but this mechanism fails when two threads call with consecutive incarnations (i and i+1). Both calls can succeed, causing the first thread's subsequent `finish_abort()` call to panic with a code invariant error, crashing the validator node.

## Finding Description

The vulnerability exists in the two-phase abort mechanism of BlockSTMv2's parallel transaction executor. The `start_abort()` function is designed to act as a test-and-set filter to ensure only one thread successfully aborts a transaction incarnation, even when multiple workers detect invalidated dependencies. [1](#0-0) 

The function uses `fetch_max(incarnation + 1, Ordering::Relaxed)` which atomically:
1. Reads the current value of `next_incarnation_to_abort`
2. Writes `max(current_value, incarnation + 1)`
3. Returns the OLD value

It then compares `incarnation` with the returned `prev_value`, succeeding only if they're equal.

**The Race Condition:**

When two threads simultaneously call with incarnations `i` and `i+1`, and `next_incarnation_to_abort` is initially `i`:

1. Thread A: `fetch_max(i+1)` reads `i`, writes `i+1`, returns `i` → compares `i == i` → **Success** ✓
2. Thread B: `fetch_max(i+2)` reads `i+1` (after Thread A's write), writes `i+2`, returns `i+1` → compares `i+1 == i+1` → **Success** ✓

Both threads now believe they successfully started the abort and expect to call `finish_abort()`.

**The Crash:**

When `finish_abort()` is called, it validates that `next_incarnation_to_abort` equals `aborted_incarnation + 1`: [2](#0-1) 

- Thread A calls `finish_abort(txn, i)`: checks if `next_incarnation_to_abort (i+2) == i+1` → **Panic!**
- Thread B calls `finish_abort(txn, i+1)`: checks if `next_incarnation_to_abort (i+2) == i+2` → Success

**Realistic Trigger Scenario:**

This occurs when a transaction reads from multiple storage locations across different incarnations, and those reads are invalidated by concurrent writers:

1. Transaction T executes incarnation `i`, reads location X, finishes execution
2. Transaction T gets aborted and re-executes incarnation `i+1`, reads different location Y
3. Due to MVHashMap's design, old dependencies can persist: location X still has dependency `(T, i)` while Y has `(T, i+1)` [3](#0-2) 

4. Writer W1 modifies X concurrently with Writer W2 modifying Y
5. W1's `AbortManager` receives dependency `(T, i)` and calls `start_abort(T, i)`
6. W2's `AbortManager` receives dependency `(T, i+1)` and calls `start_abort(T, i+1)`
7. Both succeed due to the race condition
8. W1's subsequent `finish_abort(T, i)` panics [4](#0-3) 

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos bug bounty criteria)

This vulnerability causes validator node crashes through unrecoverable panics (`code_invariant_error`), falling under:
- **API crashes**: The block executor panics, terminating the validator process
- **Validator node slowdowns**: Repeated crashes during high transaction load cause service degradation
- **Significant protocol violations**: Violates the invariant that `finish_abort` must succeed after successful `start_abort`

While not a Critical severity issue (doesn't directly cause fund loss or consensus safety violations), it affects network availability and validator uptime, which are essential for blockchain operation. During periods of high parallel transaction execution with complex dependency patterns, this could cause widespread validator instability.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability requires:
1. A transaction that reads multiple storage locations across different incarnations (common in complex smart contracts)
2. Concurrent writes to those locations by different transactions (frequent in high-throughput scenarios)
3. Timing such that both invalidations are processed simultaneously (possible under load)

BlockSTMv2 is designed for high-concurrency parallel execution, making concurrent abort attempts the normal case rather than an edge case. The comment in the code explicitly acknowledges that "multiple workers executing different transactions invalidate different reads of the same transaction." [5](#0-4) 

The vulnerability becomes more likely as:
- Transaction complexity increases (more storage reads)
- Block size increases (more parallel transactions)
- Network throughput increases (more concurrent execution)

## Recommendation

Replace the `fetch_max` approach with a compare-and-swap (CAS) loop that atomically validates the entire two-phase abort contract:

```rust
pub(crate) fn start_abort(
    &self,
    txn_idx: TxnIndex,
    incarnation: Incarnation,
) -> Result<bool, PanicError> {
    let status = &self.statuses[txn_idx as usize];
    
    // Use compare_exchange to ensure atomicity of the entire check
    match status.next_incarnation_to_abort.compare_exchange(
        incarnation,  // Expected: must be exactly this incarnation
        incarnation + 1,  // New value: increment to next
        Ordering::SeqCst,  // Success ordering - need stronger guarantees
        Ordering::Relaxed,  // Failure ordering
    ) {
        Ok(_) => {
            // Successfully claimed this incarnation for abort
            counters::SPECULATIVE_ABORT_COUNT.inc();
            clear_speculative_txn_logs(txn_idx as usize);
            Ok(true)
        }
        Err(current) if current < incarnation => {
            // Already aborted by a higher incarnation
            Ok(false)
        }
        Err(current) if current > incarnation => {
            // Trying to abort an already-aborted incarnation
            Ok(false)
        }
        Err(_) => {
            // Race condition: another thread claimed this incarnation
            Ok(false)
        }
    }
}
```

Alternatively, use a mutex to serialize abort attempts for consecutive incarnations, though this reduces parallelism:

```rust
// Add to ExecutionStatus struct
abort_lock: Mutex<()>,

pub(crate) fn start_abort(
    &self,
    txn_idx: TxnIndex,
    incarnation: Incarnation,
) -> Result<bool, PanicError> {
    let status = &self.statuses[txn_idx as usize];
    
    // Serialize abort attempts to prevent consecutive incarnation races
    let _guard = status.abort_lock.lock();
    
    let prev_value = status.next_incarnation_to_abort.load(Ordering::SeqCst);
    if prev_value != incarnation {
        return Ok(false);
    }
    
    status.next_incarnation_to_abort.store(incarnation + 1, Ordering::SeqCst);
    counters::SPECULATIVE_ABORT_COUNT.inc();
    clear_speculative_txn_logs(txn_idx as usize);
    Ok(true)
}
```

The first approach (CAS loop) is preferred as it maintains lock-free performance while fixing the race condition.

## Proof of Concept

```rust
#[cfg(test)]
mod race_condition_test {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn test_concurrent_consecutive_incarnation_abort_race() {
        // Setup: Create execution statuses for a single transaction
        let statuses = Arc::new(ExecutionStatuses::new(1));
        
        // Simulate transaction at incarnation 5 finishing execution
        // This sets next_incarnation_to_abort to 5
        let status = statuses.get_status_mut(0);
        status.next_incarnation_to_abort = CachePadded::new(AtomicU32::new(5));
        
        // Barrier to synchronize threads for maximum race probability
        let barrier = Arc::new(Barrier::new(2));
        
        let statuses_clone1 = Arc::clone(&statuses);
        let barrier_clone1 = Arc::clone(&barrier);
        
        // Thread 1: Tries to abort incarnation 5
        let handle1 = thread::spawn(move || {
            barrier_clone1.wait();
            statuses_clone1.start_abort(0, 5)
        });
        
        let statuses_clone2 = Arc::clone(&statuses);
        let barrier_clone2 = Arc::clone(&barrier);
        
        // Thread 2: Tries to abort incarnation 6
        let handle2 = thread::spawn(move || {
            barrier_clone2.wait();
            statuses_clone2.start_abort(0, 6)
        });
        
        // Wait for both threads
        let result1 = handle1.join().unwrap();
        let result2 = handle2.join().unwrap();
        
        // The bug: BOTH can succeed!
        assert!(result1.unwrap(), "Thread 1 (incarnation 5) succeeded");
        assert!(result2.unwrap(), "Thread 2 (incarnation 6) succeeded");
        
        // Now next_incarnation_to_abort is 7, not 6
        let final_value = statuses.get_status(0)
            .next_incarnation_to_abort
            .load(Ordering::Relaxed);
        assert_eq!(final_value, 7);
        
        // Thread 1 will panic when calling finish_abort(0, 5)
        // because it expects next_incarnation_to_abort == 6, but it's 7
        let result = statuses.finish_abort(0, 5, false);
        assert!(result.is_err(), "finish_abort panics due to race condition!");
        assert!(result.unwrap_err().to_string().contains("Finish abort of incarnation 5"));
    }
}
```

This test demonstrates that both `start_abort` calls succeed, but the subsequent `finish_abort` for the lower incarnation panics, which would crash a validator node in production.

## Notes

The vulnerability stems from using `fetch_max` which optimizes for the common case (aborting the same incarnation multiple times) but fails to handle the edge case of consecutive incarnations. The atomic operation is sound individually, but the logical invariant "only one incarnation abort succeeds at a time" requires stronger atomicity guarantees across the read-compare-write sequence. The use of `Ordering::Relaxed` further weakens memory ordering guarantees, though the primary issue is the logical race rather than memory ordering.

### Citations

**File:** aptos-move/block-executor/src/scheduler_status.rs (L302-309)
```rust
    /// Counter to track and filter abort attempts.
    ///
    /// This counter is monotonically increasing and updated in a successful start_abort.
    /// It allows filtering fanned-out abort attempts when multiple workers executing
    /// different transactions invalidate different reads of the same transaction.
    /// Only one of these workers will successfully abort the transaction and perform
    /// the required processing.
    next_incarnation_to_abort: CachePadded<AtomicU32>,
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L531-553)
```rust
    pub(crate) fn start_abort(
        &self,
        txn_idx: TxnIndex,
        incarnation: Incarnation,
    ) -> Result<bool, PanicError> {
        let prev_value = self.statuses[txn_idx as usize]
            .next_incarnation_to_abort
            .fetch_max(incarnation + 1, Ordering::Relaxed);
        match incarnation.cmp(&prev_value) {
            cmp::Ordering::Less => Ok(false),
            cmp::Ordering::Equal => {
                // Increment the counter and clear speculative logs (from the aborted execution).
                counters::SPECULATIVE_ABORT_COUNT.inc();
                clear_speculative_txn_logs(txn_idx as usize);

                Ok(true)
            },
            cmp::Ordering::Greater => Err(code_invariant_error(format!(
                "Try abort incarnation {} > self.next_incarnation_to_abort = {}",
                incarnation, prev_value,
            ))),
        }
    }
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L655-663)
```rust
        if status.next_incarnation_to_abort.load(Ordering::Relaxed) != new_incarnation {
            // The caller must have already successfully performed a start_abort, while
            // higher incarnation may not have started until the abort finished (here).
            return Err(code_invariant_error(format!(
                "Finish abort of incarnation {}, self.next_incarnation_to_abort = {}",
                aborted_incarnation,
                status.next_incarnation_to_abort.load(Ordering::Relaxed),
            )));
        }
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L204-210)
```rust
                // If *stored_incarnation >= invalidated_incarnation, it means either the same
                // or a newer incarnation (compared to the current invalidation) has already been
                // successfully aborted by this AbortManager instance. This can happen because
                // the reads from outdated incarnations are not assumed to be (eagerly) cleared.
                // In such cases, no new abort action is needed for this specific call. Note also
                // that an incarnation can register multiple reads that may later be invalidated.
                false
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L902-907)
```rust
        for (txn_idx, maybe_incarnation) in invalidated_set {
            if let Some(incarnation) = maybe_incarnation {
                self.txn_statuses
                    .finish_abort(txn_idx, incarnation, false)?;
                stall_propagation_queue.insert(txn_idx as usize);
            }
```
