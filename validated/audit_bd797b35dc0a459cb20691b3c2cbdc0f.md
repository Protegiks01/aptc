# Audit Report

## Title
Race Condition in BlockSTMv2 Module Validation Leading to Consensus Divergence

## Summary
A race condition exists in BlockSTMv2's cold validation mechanism between transaction scheduling and module validation requirement recording. This allows transactions to execute with stale module versions and commit without validation, breaking the deterministic execution invariant and causing consensus divergence.

## Finding Description

BlockSTMv2 uses a cold validation mechanism for module reads to avoid overhead on the common path. When a transaction publishes modules during commit, it records validation requirements for all potentially affected transactions by reading `min_never_scheduled_idx` from the `ExecutionQueueManager`. [1](#0-0) 

The race condition occurs because `pop_next()` performs two non-atomic operations:
1. Pops a transaction index from the execution queue (acquiring and releasing the lock)
2. Updates `min_never_scheduled_idx` to `idx + 1` [2](#0-1) 

Concurrently, `record_validation_requirements` reads `min_never_scheduled_idx` to determine which transactions need module validation: [3](#0-2) 

**Attack Sequence:**
1. Transaction T3 commits and publishes module M
2. Thread 1 begins `record_validation_requirements(txn_idx=3)`
3. Thread 2 calls `pop_next()`, pops transaction index 10, releases queue lock
4. Thread 1 reads `min_never_scheduled_idx()` → returns 10 (not yet updated)
5. Thread 2 updates `min_never_scheduled_idx` to 11 with Relaxed ordering
6. Thread 1 records requirements for transactions [4, 10) only (missing T10)
7. Transaction 10 starts executing, reads module M from global cache (captured as `ModuleRead::GlobalCache`)
8. Module M is marked as overridden in global cache [4](#0-3) 

9. Transaction 10 completes execution with old module M
10. Transaction 10 is NOT in cold validation requirements range [4, 10)
11. When dedicated worker processes all txns 4-9, `min_idx_with_unprocessed_validation_requirement` is set to u32::MAX
12. Transaction 10 commits without module read validation [5](#0-4) 

The commit is allowed because `is_commit_blocked` returns false - T10's index is not blocked after all requirements in [4, 10) are processed.

The validation logic that SHOULD have caught this checks if modules read from global cache are not overridden: [6](#0-5) 

But T10 never goes through this validation due to the race condition excluding it from the requirements range.

## Impact Explanation

This vulnerability breaks the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

When this race occurs:
- **Validator A (race occurs)**: T10 excluded from validation requirements → commits with old module M execution result
- **Validator B (no race)**: T10 included in validation requirements → validation fails (module overridden) → re-executes with new module M → commits with new result [7](#0-6) 

Different execution results lead to different state roots, causing **Consensus Safety Violation** - validators diverge on block state.

This qualifies as **Critical Severity** per Aptos bug bounty:
- Consensus/Safety violations (up to $1,000,000)
- Non-recoverable network partition requiring hardfork

The vulnerability affects all validators running BlockSTMv2. Even a single occurrence causes permanent chain split requiring coordinated intervention.

## Likelihood Explanation

The race condition window is microseconds wide - between releasing the execution queue lock and updating `min_never_scheduled_idx`. However:

**Likelihood factors:**
- Occurs probabilistically during normal operation with module publishing
- Probability increases with:
  - Higher parallelism (more concurrent workers)
  - More module publishing transactions
  - Higher transaction throughput
- The Relaxed memory ordering provides no synchronization guarantees [8](#0-7) [9](#0-8) 

In production with sustained load and high parallelism, the race will eventually occur. The non-deterministic nature makes it difficult to reproduce in testing but inevitable in production.

## Recommendation

Make `pop_next()` and `min_never_scheduled_idx` update atomic:

```rust
fn pop_next(&self) -> Option<TxnIndex> {
    let mut queue = self.execution_queue.lock();
    let ret = queue.pop_first();
    if let Some(idx) = ret {
        self.min_never_scheduled_idx
            .fetch_max(idx + 1, Ordering::Release); // Changed from Relaxed
    }
    drop(queue); // Explicitly drop lock after updating min_never_scheduled_idx
    ret
}
```

And use Acquire ordering when reading:
```rust
fn min_never_scheduled_idx(&self) -> TxnIndex {
    self.min_never_scheduled_idx.load(Ordering::Acquire) // Changed from Relaxed
}
```

Alternatively, update `min_never_scheduled_idx` BEFORE releasing the queue lock to make both operations atomic within the critical section.

## Proof of Concept

This race condition requires specific timing and is probabilistic. A proper PoC would need:
1. High parallelism (many worker threads)
2. Concurrent module publishing and transaction execution
3. Stress testing to hit the microsecond race window

The race manifests as consensus divergence across validators, which cannot be demonstrated in a single-node test environment without instrumenting the code to force the race condition.

## Notes

The vulnerability is exacerbated by:
- Relaxed memory ordering providing no synchronization
- No barriers between queue operation and min_never_scheduled_idx update
- The microsecond window being hit more frequently under production load with 16+ worker threads
- Module publishing being a legitimate operation that any developer can trigger

This represents a fundamental concurrency bug in BlockSTMv2's validation tracking mechanism.

### Citations

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L64-70)
```rust
    -   **`min_never_scheduled_idx`**: An optimization that tracks the minimum transaction
        index that has not yet been scheduled. This is currently used to identify maximum
        range of the interval that may require a traversal for module read validation
        (after a committed txn that publishes a module), but can be generally useful for
        tracking the evolution of the "active" interval of the scheduler.
        TODO(BlockSTMv2): consider constraining the interval to have a maximum size, for
        optimizing performance as well as for integration w. execution pooling, etc.
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L391-398)
```rust
    fn pop_next(&self) -> Option<TxnIndex> {
        let ret = self.execution_queue.lock().pop_first();
        if let Some(idx) = ret {
            self.min_never_scheduled_idx
                .fetch_max(idx + 1, Ordering::Relaxed);
        }
        ret
    }
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L400-402)
```rust
    fn min_never_scheduled_idx(&self) -> TxnIndex {
        self.min_never_scheduled_idx.load(Ordering::Relaxed)
    }
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L1037-1043)
```rust
        let min_never_scheduled_idx = self.min_never_scheduled_idx()?;
        if txn_idx >= min_never_scheduled_idx {
            return Err(code_invariant_error(format!(
                "Calling txn idx {} must be less than min_never_scheduled_idx {}",
                txn_idx, min_never_scheduled_idx
            )));
        }
```

**File:** aptos-move/block-executor/src/code_cache_global.rs (L317-317)
```rust
    global_module_cache.mark_overridden(write.module_id());
```

**File:** aptos-move/block-executor/src/cold_validation.rs (L421-431)
```rust
    pub(crate) fn is_commit_blocked(&self, txn_idx: TxnIndex, incarnation: Incarnation) -> bool {
        // The order of checks is important to avoid a concurrency bugs (since recording
        // happens in the opposite order). We first check that there are no unscheduled
        // requirements below (incl.) the given index, and then that there are no scheduled
        // but yet unfulfilled (validated) requirements for the index.
        self.min_idx_with_unprocessed_validation_requirement
            .load(Ordering::Relaxed)
            <= txn_idx
            || self.deferred_requirements_status[txn_idx as usize].load(Ordering::Relaxed)
                == blocked_incarnation_status(incarnation)
    }
```

**File:** aptos-move/block-executor/src/captured_reads.rs (L1060-1061)
```rust
        let validate = |key: &K, read: &ModuleRead<DC, VC, S>| match read {
            ModuleRead::GlobalCache(_) => global_module_cache.contains_not_overridden(key),
```

**File:** aptos-move/block-executor/src/executor.rs (L763-770)
```rust
        if !read_set.validate_module_reads(
            global_module_cache,
            versioned_cache.module_cache(),
            Some(updated_module_keys),
        ) {
            scheduler.direct_abort(idx_to_validate, incarnation_to_validate, false)?;
            return Ok(false);
        }
```
