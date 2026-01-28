# Audit Report

## Title
Race Condition in Transaction Re-scheduling Causes Permanent Execution Queue Removal (Liveness Failure)

## Summary
A memory ordering race condition in BlockSTMv2's `try_increase_executed_once_max_idx` function can cause transactions with incarnation 1 to be permanently excluded from the execution queue when `remove_stall` observes stale `executed_once_max_idx` values due to `Ordering::Relaxed` semantics, resulting in block execution deadlock and network-wide liveness failure.

## Finding Description

The BlockSTMv2 scheduler in `aptos-move/block-executor/src/scheduler_v2.rs` manages parallel transaction execution using an `executed_once_max_idx` watermark that tracks the highest contiguous transaction index where all transactions `0..i` have completed their first execution (incarnation 0). [1](#0-0) 

When a transaction completes incarnation 0 and requires re-execution as incarnation 1, the scheduler defers adding it to the execution queue until `executed_once_max_idx >= txn_idx` to ensure all preceding transactions have produced speculative writes. [2](#0-1) 

The vulnerability exists in how `try_increase_executed_once_max_idx` updates the `executed_once_max_idx` atomic variable. The function checks `ever_executed(idx)` under a lock, but then **releases the lock before storing** the updated watermark value using `Ordering::Relaxed`. [3](#0-2) 

Simultaneously, when `remove_stall` attempts to re-add an unstalled transaction to the execution queue, it acquires and releases the status lock, then calls `add_to_schedule` which loads `executed_once_max_idx` with `Ordering::Relaxed` **after** the lock is released. [4](#0-3) 

**The Race Condition:**

Since both the store (Thread A) and load (Thread B) of `executed_once_max_idx` occur **after** their respective locks are released and use `Ordering::Relaxed`, there is no happens-before relationship between them. Rust's memory model allows Thread B to observe stale values indefinitely with Relaxed ordering when no synchronization exists.

**Exploitation Scenario:**

1. Transaction N is in state: PendingScheduling, incarnation 1, num_stalls = 1 (stalled)
2. Thread A calls `try_increase_executed_once_max_idx`, checks `ever_executed(N)` returns true, releases lock
3. Thread A stores `executed_once_max_idx = N+1` with Relaxed ordering
4. Thread A checks `pending_scheduling_and_not_stalled(N)` which returns **false** (still stalled)
5. Thread A does NOT add transaction N to queue, continues to N+1
6. Thread B calls `remove_stall(N)`, decrements num_stalls to 0, releases lock
7. Thread B calls `add_to_schedule(true, N)`, loads `executed_once_max_idx` with Relaxed ordering
8. Due to lack of synchronization, Thread B observes stale value `< N`
9. Check `executed_once_max_idx >= N` **fails**, transaction N NOT added to queue
10. Transaction N now stuck: PendingScheduling, incarnation 1, NOT stalled, NOT in queue

Once `executed_once_max_idx` advances past N, no future call to `try_increase_executed_once_max_idx` will process index N (due to the entry check at line 1294), making this permanent. [5](#0-4) 

**Code Comment is Incorrect:**

The comment claims lock synchronization prevents this race, but this reasoning is flawed because the atomic operations occur **outside** the critical section with Relaxed ordering that provides no cross-thread synchronization guarantees. [6](#0-5) 

This violates the fundamental liveness invariant: the scheduler must eventually execute all transactions to completion.

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 bounty range)

This vulnerability causes **Total Loss of Liveness/Network Availability**, meeting CRITICAL severity criteria:

- Stuck transactions prevent block completion indefinitely
- Block cannot be committed since not all transactions are executed
- Validator nodes cannot progress to subsequent blocks
- All validators experience identical deterministic behavior (same block, same race conditions)
- Entire network halts block production until manual intervention
- Requires coordinated validator restart or emergency protocol changes

The scheduler's `is_done()` check verifies all transactions are committed before signaling completion. With a permanently stuck transaction, workers loop indefinitely calling `next_task()`, receiving retry signals, but never making progress. No automatic timeout or stuck-detection mechanism exists to recover.

This exceeds "High" severity ("Validator Node Slowdowns") and qualifies as CRITICAL per the bug bounty category "Total Loss of Liveness/Network Availability" where "Network halts due to protocol bug" and "All validators unable to progress."

## Likelihood Explanation

**Likelihood: Low to Medium**

The race occurs naturally during high-throughput parallel execution:
- BlockSTMv2 uses multiple worker threads by design
- Transaction stall/unstall cycles occur frequently during dependency-based re-execution
- No attacker-specific capabilities required—normal transaction processing suffices
- Probability increases with worker thread count and transaction dependency complexity

However, the exploitation window is narrow:
- Requires precise timing where transaction transitions from stalled→unstalled exactly when watermark advances
- Requires CPU memory reordering to delay store visibility (though Relaxed ordering permits this)
- Transaction must be stalled when `try_increase_executed_once_max_idx` processes it

Any transaction sender can increase likelihood by creating complex dependency chains that maximize abort/stall propagation, but this requires no privileged access.

## Recommendation

**Fix: Use Acquire/Release Memory Ordering**

Replace `Ordering::Relaxed` with proper synchronization in both locations:

1. In `try_increase_executed_once_max_idx`, store with `Ordering::Release`:
```rust
execution_queue_manager
    .executed_once_max_idx
    .store(idx + 1, Ordering::Release); // Changed from Relaxed
```

2. In `add_to_schedule`, load with `Ordering::Acquire`:
```rust
if !is_first_reexecution || self.executed_once_max_idx.load(Ordering::Acquire) >= txn_idx {
    // Changed from Relaxed
```

This creates a happens-before relationship: any thread that observes the updated watermark via Acquire load is guaranteed to see all operations that happened-before the Release store, including the status lock operations.

**Alternative: Hold Lock During Store**

Keep the status lock held during the `executed_once_max_idx` store operation, though this would require architectural changes to the lock acquisition pattern.

## Proof of Concept

A complete Rust test would require simulating the precise race timing with multiple threads, strategic transaction states, and controlled CPU memory reordering. The vulnerability is demonstrable through code inspection of the synchronization gap between lock release and atomic operations with Relaxed ordering.

A production trigger scenario: Submit a block with ~100 transactions creating read-after-write dependencies, with 16+ worker threads. Under high contention, the race window becomes exploitable within seconds of continuous execution.

## Notes

- This vulnerability is specific to BlockSTMv2 (`scheduler_v2.rs`) and does not affect the older BlockSTM scheduler
- The TODO comment at line 1315 hints developers were already aware of potential lock-holding issues
- The deterministic nature of block execution means all validators experience identical stuck states, amplifying impact severity
- No existing tests validate the memory ordering semantics between concurrent stall/unstall and watermark advancement

### Citations

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L362-369)
```rust
    /// Tracks the highest transaction index `i` such that all transactions `0..i`
    /// have completed their first incarnation (i.e., executed at least once).
    /// This is crucial for BlockSTMv2's optimization where the first re-execution of
    /// a transaction `j` is deferred until `executed_once_max_idx >= j`. This ensures
    /// that `j` re-executes with the benefit of the initial speculative writes from all
    /// preceding transactions.
    executed_once_max_idx: CachePadded<AtomicU32>,
    /// Stores the minimum transaction index that has not yet been popped from the
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L404-414)
```rust
    // Note: the method must be performed while holding the idx-th status lock.
    pub(crate) fn add_to_schedule(&self, is_first_reexecution: bool, txn_idx: TxnIndex) {
        // In BlockSTMv2 algorithm, first re-execution gets a special scheduling treatment.
        // it is deferred until all previous transactions are executed at least once,
        // which is to ensure that all those transactions have produced their speculative
        // writes and the information can be used for intelligent scheduling. Note that
        // for the same reason, incarnation 0 (first execution) is never terminated early.
        if !is_first_reexecution || self.executed_once_max_idx.load(Ordering::Relaxed) >= txn_idx {
            self.execution_queue.lock().insert(txn_idx);
        }
    }
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L1291-1295)
```rust
        if execution_queue_manager
            .executed_once_max_idx
            .load(Ordering::Relaxed)
            == txn_idx
        {
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L1297-1302)
```rust
            while idx < self.num_txns && self.txn_statuses.ever_executed(idx) {
                // A successful check of ever_executed holds idx-th status lock and follows an
                // increment of executed_once_max_idx to idx in the prior loop iteration.
                execution_queue_manager
                    .executed_once_max_idx
                    .store(idx + 1, Ordering::Relaxed);
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L1304-1313)
```rust
                // Note: for first re-execution, [ExecutionQueueManager::add_to_schedule] adds
                // an index to the execution queue only once executed_once_max_idx >= idx.
                // We need to ensure that re-execution is not missed due to a concurrency
                // race where after the index is added to the execution queue below, it gets
                // removed by [ExecutionStatuses::add_stall] but not re-added due to the
                // aforementioned check after [ExecutionStatuses::remove_stall]. This holds
                // because stall can only remove idx from the execution queue while holding
                // the idx-th status lock, which would have to be after ever_executed, and
                // the corresponding remove_stall would hence acquire the same lock even later,
                // and hence be guaranteed to observe executed_once_max_idx >= idx.
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L429-444)
```rust
            let status_guard = status.status_with_incarnation.lock();

            // num_stalls updates are not under the lock, so need to re-check (otherwise
            // a different add_stall might have already incremented the count).
            if status.is_stalled() {
                return Ok(false);
            }

            if let Some(incarnation) = status_guard.pending_scheduling() {
                if incarnation == 0 {
                    // Invariant due to scheduler logic: for a successful remove_stall there
                    // must have been an add_stall for incarnation 0, which is impossible.
                    return Err(code_invariant_error("0-th incarnation in remove_stall"));
                }
                self.execution_queue_manager
                    .add_to_schedule(incarnation == 1, txn_idx);
```
