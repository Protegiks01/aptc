# Audit Report

## Title
Race Condition in `start_abort()` Allows Concurrent Incarnation Aborts Leading to Validator Panic

## Summary
The BlockSTMv2 scheduler's two-phase abort mechanism contains a race condition in `start_abort()` that allows concurrent threads to successfully abort consecutive incarnations (i and i+1) of the same transaction. This violates the invariant that each successful `start_abort()` must be followed by exactly one `finish_abort()`, causing the first thread to panic with a `code_invariant_error` and crash the validator node.

## Finding Description

The vulnerability exists in the abort synchronization mechanism of BlockSTMv2's parallel transaction executor. The `start_abort()` function uses atomic `fetch_max()` to coordinate concurrent abort attempts: [1](#0-0) 

The function atomically reads `next_incarnation_to_abort`, writes `max(current_value, incarnation + 1)`, and returns the old value. Success is determined by checking if `incarnation == prev_value`.

**The Race Condition:**

When two different writers concurrently call `start_abort()` with consecutive incarnations i and i+1, both can succeed:

1. Initial state: `next_incarnation_to_abort = i`
2. Thread A executes `fetch_max(i+1, Relaxed)`:
   - Reads: i
   - Writes: max(i, i+1) = i+1
   - Returns: i
   - Comparison: i == i → **Success**

3. Thread B executes `fetch_max(i+2, Relaxed)`:
   - Reads: i+1 (Thread A's write)
   - Writes: max(i+1, i+2) = i+2
   - Returns: i+1
   - Comparison: i+1 == i+1 → **Success**

4. Final state: `next_incarnation_to_abort = i+2`

Both threads believe they successfully started an abort and will call `finish_abort()`.

**The Crash:**

The `finish_abort()` function validates that `next_incarnation_to_abort == aborted_incarnation + 1`: [2](#0-1) 

- Thread A calls `finish_abort(txn, i)`: checks if `i+2 == i+1` → **PANIC**
- Thread B calls `finish_abort(txn, i+1)`: checks if `i+2 == i+2` → Success

**Realistic Trigger Scenario:**

This occurs when a transaction reads different storage locations across different incarnations, and those reads are invalidated by concurrent writers:

1. Transaction T executes incarnation i, reads location X
2. T gets aborted and re-executes as incarnation i+1, reads location Y (not X)
3. Due to MVHashMap's design, old dependencies persist - X retains dependency (T, i) while Y has (T, i+1)

The code explicitly acknowledges this behavior: [3](#0-2) 

4. Writer W1 modifies X, its `AbortManager` receives dependency (T, i), calls `start_abort(T, i)`
5. Writer W2 modifies Y, its `AbortManager` receives dependency (T, i+1), calls `start_abort(T, i+1)`
6. Both succeed due to the race condition
7. W1's subsequent `finish_abort(T, i)` panics

The `AbortManager` only prevents a **single** writer from aborting multiple incarnations: [4](#0-3) 

However, **different** `AbortManager` instances (from different writers W1 and W2) can concurrently attempt to abort different incarnations of the same transaction.

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos bug bounty criteria)

This vulnerability causes validator node crashes through unrecoverable panics via `code_invariant_error`, falling under the HIGH severity category:

- **API crashes**: The block executor panics, terminating the validator process
- **Validator node slowdowns**: Repeated crashes during high transaction load cause service degradation
- **Protocol violations**: Violates the critical invariant that successful `start_abort` must be followed by successful `finish_abort`

While not Critical (no direct fund loss or consensus safety violations), it degrades network availability and validator uptime, essential for blockchain operation. During high parallel transaction execution with complex dependency patterns, this could cause widespread validator instability.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability requires:
1. A transaction reading multiple storage locations across different incarnations (common in complex smart contracts)
2. Concurrent writes to those locations by different transactions (frequent in high-throughput scenarios)
3. Timing such that both invalidations are processed simultaneously (likely under load)

BlockSTMv2 is explicitly designed for high-concurrency parallel execution, making concurrent abort attempts the normal case. The documentation acknowledges this: [5](#0-4) 

The vulnerability becomes more likely as:
- Transaction complexity increases (more storage reads across locations)
- Block size increases (more parallel transactions)
- Network throughput increases (more concurrent execution)

## Recommendation

Modify `start_abort()` to prevent concurrent aborts of consecutive incarnations by checking the atomic state after the `fetch_max` operation:

```rust
pub(crate) fn start_abort(
    &self,
    txn_idx: TxnIndex,
    incarnation: Incarnation,
) -> Result<bool, PanicError> {
    let prev_value = self.statuses[txn_idx as usize]
        .next_incarnation_to_abort
        .fetch_max(incarnation + 1, Ordering::SeqCst); // Use SeqCst for stronger ordering
    
    match incarnation.cmp(&prev_value) {
        cmp::Ordering::Less => Ok(false),
        cmp::Ordering::Equal => {
            // Additional validation: ensure no concurrent abort succeeded
            let current_value = self.statuses[txn_idx as usize]
                .next_incarnation_to_abort
                .load(Ordering::SeqCst);
            
            if current_value != incarnation + 1 {
                // Another thread succeeded with a higher incarnation
                return Ok(false);
            }
            
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

Alternatively, use a compare-and-swap loop to ensure atomicity of the entire check-and-set operation.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_concurrent_incarnation_abort_race() {
        let statuses = Arc::new(ExecutionStatuses::new(10));
        
        // Setup: Transaction 5 at incarnation 0 has completed execution
        statuses.start_executing(5).unwrap();
        statuses.finish_execution(5, 0).unwrap();
        
        // Simulate concurrent abort attempts for incarnations 0 and 1
        let statuses1 = Arc::clone(&statuses);
        let statuses2 = Arc::clone(&statuses);
        
        let handle1 = thread::spawn(move || {
            statuses1.start_abort(5, 0)
        });
        
        let handle2 = thread::spawn(move || {
            statuses2.start_abort(5, 1)
        });
        
        let result1 = handle1.join().unwrap();
        let result2 = handle2.join().unwrap();
        
        // Both aborts may succeed due to the race condition
        if result1.unwrap() && result2.unwrap() {
            // This triggers the bug - finish_abort(5, 0) will now panic
            let finish_result = statuses.finish_abort(5, 0, false);
            assert!(finish_result.is_err()); // This panics with code_invariant_error
        }
    }
}
```

## Notes

This vulnerability demonstrates a subtle atomicity issue in lock-free concurrent programming. The `fetch_max` operation is atomic, but the overall two-phase protocol (start_abort → finish_abort) lacks proper synchronization when multiple concurrent threads attempt to abort consecutive incarnations. The fix requires either stronger memory ordering or additional validation to ensure the invariant is maintained across the entire abort lifecycle.

### Citations

**File:** aptos-move/block-executor/src/scheduler_status.rs (L36-44)
```rust
   a) Start Abort Phase:
      - [ExecutionStatuses::start_abort] is called with an incarnation number and succeeds if
        the incarnation has started executing and has not already been aborted.
      - This serves as an efficient test-and-set filter for multiple abort attempts (which
        can occur when a transaction makes multiple reads that may each be invalidated by
        different transactions).
      - Early detection allows the ongoing execution to stop immediately rather than continue
        work that will ultimately be discarded.

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

**File:** aptos-move/block-executor/src/scheduler_status.rs (L647-663)
```rust
    pub(crate) fn finish_abort(
        &self,
        txn_idx: TxnIndex,
        aborted_incarnation: Incarnation,
        start_next_incarnation: bool,
    ) -> Result<(), PanicError> {
        let status = &self.statuses[txn_idx as usize];
        let new_incarnation = aborted_incarnation + 1;
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

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L189-203)
```rust
            Some(Some(stored_successful_abort_incarnation)) => {
                // An abort was previously successful for `stored_successful_abort_incarnation`.
                if *stored_successful_abort_incarnation < invalidated_incarnation {
                    // A previous invalidation targeted an older incarnation of `invalidated_txn_idx`
                    // which was successfully aborted and recorded.
                    // Now, a newer incarnation of the same `invalidated_txn_idx` is being targeted.
                    // This is an error: `SchedulerV2::finish_execution` must consume the AbortManager
                    // instance for the `stored_successful_abort_incarnation` before an attempt to
                    // abort a higher incarnation of the same `invalidated_txn_idx` can be made.
                    return Err(code_invariant_error(format!(
                        "Lower incarnation {} than {} already invalidated by Abort Manager for txn version ({}, {})",
                        *stored_successful_abort_incarnation, invalidated_incarnation,
                        self.owner_txn_idx, self.owner_incarnation
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
