# Audit Report

## Title
Race Condition in Cold Validation Worker Assignment Causes Transaction Commit Liveness Failure

## Summary
A race condition exists in BlockSTMv2's cold validation system between `activate_pending_requirements()` releasing its lock and the caller resetting `dedicated_worker_id`. This can orphan pending validation requirements with no assigned worker, causing valid transactions to be blocked from committing until another module publication occurs.

## Finding Description

The cold validation requirements system in BlockSTMv2 uses a dedicated worker pattern to process module validation requirements. [1](#0-0) 

The vulnerability occurs in the narrow time window between when `activate_pending_requirements()` returns `Ok(true)` and releases its lock, and when the caller executes the store operation to reset `dedicated_worker_id`. [2](#0-1) 

**Attack Sequence:**

1. Worker A (current dedicated worker) calls `get_validation_requirement_to_process()` [3](#0-2) 

2. Worker A calls `activate_pending_requirements()` which drains pending requirements, finds no active requirements need validation, and returns `Ok(true)` at line 511 [4](#0-3) 

3. **Race Window**: The `pending_requirements` lock is released when the function returns. Before Worker A executes line 292 to reset `dedicated_worker_id`:

4. Worker B commits a transaction that publishes modules and calls `record_requirements()` [5](#0-4) 

5. Worker B acquires the `pending_requirements` lock and pushes new requirements [6](#0-5) 

6. Worker B attempts `compare_exchange(u32::MAX, worker_id, ...)` which fails because `dedicated_worker_id` still contains Worker A's ID [7](#0-6) 

7. Worker B still updates `min_idx_with_unprocessed_validation_requirement` to block commits [8](#0-7) 

8. Worker A resumes and executes line 292, resetting `dedicated_worker_id` to `u32::MAX` [9](#0-8) 

**Resulting State:**
- `dedicated_worker_id = u32::MAX` (no worker assigned)
- `pending_requirements` contains Worker B's requirements
- `min_idx_with_unprocessed_validation_requirement` is set to block commits
- No worker processes these orphaned requirements

The scheduler's commit check blocks all transactions at or above `min_idx_with_unprocessed_validation_requirement`: [10](#0-9) 

Transactions remain blocked until another transaction publishes modules, triggering a new `record_requirements()` call that successfully assigns a dedicated worker via `compare_exchange`, which then drains all pending requirements including the orphaned ones.

## Impact Explanation

**Medium Severity** - This meets the "Temporary liveness issues" and "State inconsistencies requiring intervention" criteria:

- **Liveness Failure**: Valid transactions are incorrectly prevented from committing
- **Temporary Blocking**: Transactions remain stuck until another module publication occurs
- **No Safety Violations**: No invalid transactions are committed; blockchain state remains consistent
- **Availability Impact**: Block production can be delayed if multiple transactions are blocked
- **Self-Recovery**: System recovers when another module publication assigns a new dedicated worker

This is not Critical severity because:
- No funds are lost or stolen
- No consensus safety violations occur
- System has self-recovery mechanism (albeit dependent on future module publications)
- State integrity is maintained

This is not Low severity because:
- Can affect multiple transactions simultaneously
- Impacts core transaction processing capabilities
- Can significantly degrade system performance during high-load periods

## Likelihood Explanation

**Medium to High Likelihood**:

- **Trigger Condition**: Occurs when transactions publish Move modules during contract deployment or upgrades
- **Race Window**: Narrow but exists in the critical section between lock release and atomic store
- **Concurrency**: BlockSTM's parallel execution with multiple workers increases race probability
- **High Throughput Amplification**: More likely under heavy load with many concurrent workers
- **No Privileges Required**: Any user can deploy contracts and inadvertently trigger this
- **Cumulative Probability**: With many module publications over time, occurrence becomes likely

The race is timing-dependent and may not occur frequently in low-load scenarios, but production blockchains with high transaction volumes will eventually encounter this condition.

## Recommendation

Move the `dedicated_worker_id` reset inside `activate_pending_requirements()` while holding the `pending_requirements` lock, similar to how it's done in `validation_requirement_processed()`: [11](#0-10) 

Modify `activate_pending_requirements()` to reset the dedicated worker atomically:

```rust
fn activate_pending_requirements(&self, statuses: &ExecutionStatuses) -> Result<bool, PanicError> {
    // ... existing drain and activation logic ...
    
    if active_reqs.versions.is_empty() {
        let pending_reqs_guard = self.pending_requirements.lock();
        if pending_reqs_guard.is_empty() {
            self.min_idx_with_unprocessed_validation_requirement
                .store(u32::MAX, Ordering::Relaxed);
            // Reset dedicated worker WHILE holding the lock
            self.dedicated_worker_id.store(u32::MAX, Ordering::Relaxed);
            return Ok(false); // Return false since we've already reset
        }
    }
    
    Ok(false)
}
```

And update the caller to not reset the worker:

```rust
pub(crate) fn get_validation_requirement_to_process<'a>(...) -> Result<...> {
    if !self.is_dedicated_worker(worker_id) {
        return Ok(None);
    }
    
    // activate_pending_requirements now handles worker reset internally
    if self.activate_pending_requirements(statuses)? {
        return Ok(None); // Worker was already reset inside the function
    }
    
    // ... rest of the logic ...
}
```

This ensures atomicity by holding the lock during both the check and the reset operations.

## Proof of Concept

While a full PoC requires complex multi-threaded Rust test infrastructure, the race condition can be demonstrated through the following sequence of operations that the code permits:

1. Thread A: Enters `get_validation_requirement_to_process()`, drains empty pending requirements
2. Thread A: `activate_pending_requirements()` returns `Ok(true)` and releases lock
3. Thread B: Enters `record_requirements()`, acquires lock, pushes requirements, updates min_idx
4. Thread B: Releases lock
5. Thread A: Executes line 292, resets `dedicated_worker_id` to `u32::MAX`
6. Result: Orphaned requirements with no dedicated worker

The code structure at [12](#0-11)  explicitly shows the reset happens outside the lock protection, creating the race window.

## Notes

The report's original description stated that Worker B's `compare_exchange` succeeds, but technically it fails because `dedicated_worker_id` still contains Worker A's ID at that point. However, the vulnerability outcome remains the same: Worker B adds pending requirements and updates `min_idx`, but no worker is assigned to process them after Worker A resets the dedicated worker ID. This is a valid race condition with real liveness impact.

### Citations

**File:** aptos-move/block-executor/src/cold_validation.rs (L14-61)
```rust
/**
 * In BlockSTMv2, validations are not scheduled in waves as separate tasks like
 * in BlockSTMv1. Instead normal validations occur granularly and on-demand, at
 * the time of particular updates. However, global code cache does not support
 * push validation by design. This because most blocks do not contain module
 * publishing, so the trade-off taken is to reduce the overhead on the common
 * read path. Instead, published modules become visible to other workers (executing
 * higher indexed txns) during a txn commit, and it is required that all txns
 * that are executed or executing to validate their module read set. This file
 * provides the primitives for BlockSTMv2 scheduler to manage such requirements.
 *
 * A high-level idea is that at any time, at most one worker is responsible for
 * fulfilling the module validation requirements for an interval of txns. The
 * interval starts at the index of a committed txn that published modules, and
 * ends at the first txn that has never been scheduled for execution. (Note: for
 * contended workloads, the scheduler currently may execute later txns early,
 * losing the benefits of this optimization for higher-indexed txns). The interval
 * induces a traversal of the interval to identify the set of txn versions
 * (txn index & incarnation pair) requiring module read set validation. In order
 * to reduce the time in critical (sequential) section of the code, the traversal
 * is performed after the txn is committed by the same worker if no requirements
 * were already active, or by the designated worker that may have already been
 * performing module validations. When this happens, the start of interval is
 * reset to the newly committed txn (which must be higher than recorded start
 * since txns can not be committed with unfulfilled requirements). The traversal
 * can be done locally, only needing access to the array of statuses. After the
 * traversal is finished and the requirements are properly recorded, the designated
 * worker may get module validation tasks to perform from scheduler's next_task
 * call - depending on a distance threshold from the committed prefix of the block.
 * The rationale for a distance threshold is to (a) prioritize more important
 * work and (b) avoid wasted work as txns that get re-executed after module
 * publishing (with higher incarnation) would no longer require module validation.
 *
 * When the interval is reset, the module requirements are combined together.
 * This might cause some txns to be validated against a module when strictly
 * speaking they would not require it. However, it allows a simpler implementation
 * that is easier to reason about, and is not expected to be a bottleneck.
 *
 * The implementation of ColdValidationRequirements is templated over the type of
 * the requirement. This allows easier testing, as well as future extensions to
 * other types of validation requirements that may be better offloaded to an uncommon
 * dedicated path for optimal performance. TODO(BlockSTMv2): a promising direction
 * is to enable caching use-cases in the VM, whereby cache invalidations might be
 * rare and infeasible to record every access for push validation.
 *
 * Finally, ColdValidationRequirements allows to cheaply check if a txn has
 * unfulfilled requirements, needed by the scheduler to avoid committing such txns.
 **/
```

**File:** aptos-move/block-executor/src/cold_validation.rs (L234-239)
```rust
        let mut pending_reqs = self.pending_requirements.lock();
        pending_reqs.push(PendingRequirement {
            requirements,
            from_idx: calling_txn_idx + 1,
            to_idx: min_never_scheduled_idx,
        });
```

**File:** aptos-move/block-executor/src/cold_validation.rs (L245-250)
```rust
        let _ = self.dedicated_worker_id.compare_exchange(
            u32::MAX,
            worker_id,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
```

**File:** aptos-move/block-executor/src/cold_validation.rs (L251-253)
```rust
        let prev_min_idx = self
            .min_idx_with_unprocessed_validation_requirement
            .swap(calling_txn_idx + 1, Ordering::Relaxed);
```

**File:** aptos-move/block-executor/src/cold_validation.rs (L281-295)
```rust
    pub(crate) fn get_validation_requirement_to_process<'a>(
        &self,
        worker_id: u32,
        idx_threshold: TxnIndex,
        statuses: &ExecutionStatuses,
    ) -> Result<Option<(TxnIndex, Incarnation, ValidationRequirement<'a, R>)>, PanicError> {
        if !self.is_dedicated_worker(worker_id) {
            return Ok(None);
        }

        if self.activate_pending_requirements(statuses)? {
            self.dedicated_worker_id.store(u32::MAX, Ordering::Relaxed);
            // If the worker id was reset, the worker can early return (no longer assigned).
            return Ok(None);
        }
```

**File:** aptos-move/block-executor/src/cold_validation.rs (L383-397)
```rust
        let active_reqs_is_empty = active_reqs.versions.is_empty();
        let pending_reqs = self.pending_requirements.lock();
        if pending_reqs.is_empty() {
            // Expected to be empty most of the time as publishes are rare and the requirements
            // are drained by the caller when getting the requirement. The check ensures that
            // the min_idx_with_unprocessed_validation_requirement is not incorrectly increased
            // if pending requirements exist for validated_idx. It also allows us to hold the
            // lock while updating the atomic variables.
            if active_reqs_is_empty {
                active_reqs.requirements.clear();
                self.min_idx_with_unprocessed_validation_requirement
                    .store(u32::MAX, Ordering::Relaxed);
                // Since we are holding the lock and pending requirements is empty, it
                // is safe to reset the dedicated worker id.
                self.dedicated_worker_id.store(u32::MAX, Ordering::Relaxed);
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

**File:** aptos-move/block-executor/src/cold_validation.rs (L501-512)
```rust
        if active_reqs.versions.is_empty() {
            // It is possible that the active versions map was empty, and no pending
            // requirements needed to be activated (i.e. not executing or executed).
            // In this case, we may update min_idx_with_unprocessed_validation_requirement
            // as validation_requirement_processed does so only when the pending
            // requirements are empty.
            let pending_reqs_guard = self.pending_requirements.lock();
            if pending_reqs_guard.is_empty() {
                self.min_idx_with_unprocessed_validation_requirement
                    .store(u32::MAX, Ordering::Relaxed);
                return Ok(true);
            }
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L572-576)
```rust
        if published {
            // Record validation requirements after the modules are published.
            global_module_cache.flush_layout_cache();
            scheduler.record_validation_requirements(txn_idx, module_ids_for_v2)?;
        }
```
