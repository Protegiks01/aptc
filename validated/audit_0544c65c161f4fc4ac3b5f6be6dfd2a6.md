# Audit Report

## Title
Race Condition in Cold Validation Worker Assignment Causes Transaction Commit Liveness Failure

## Summary
A race condition exists in the cold validation requirements system where `get_validation_requirement_to_process()` resets the dedicated worker ID without holding the pending_requirements lock, while `record_requirements()` updates the minimum index under the lock. This creates a window where pending validation requirements can be orphaned with no assigned worker, causing transactions to be blocked from committing until another module publication occurs.

## Finding Description

The cold validation requirements system in BlockSTMv2 uses a dedicated worker pattern to process module validation requirements. A critical race condition exists due to inconsistent locking behavior when resetting the dedicated worker ID.

**The Vulnerability:**

When `activate_pending_requirements()` determines all requirements are processed (active versions map is empty after processing), it re-acquires the lock to verify pending requirements are still empty, then stores `u32::MAX` to `min_idx_with_unprocessed_validation_requirement` and returns `Ok(true)` to signal the caller should reset the dedicated worker. [1](#0-0) 

The caller in `get_validation_requirement_to_process()` then resets `dedicated_worker_id` to `u32::MAX` **without holding the pending_requirements lock**: [2](#0-1) 

However, `record_requirements()` updates atomic variables **while holding the pending_requirements lock**: [3](#0-2) 

The comments explicitly state that updates should occur under the lock: [4](#0-3) 

**Race Condition Sequence:**

1. Worker A calls `activate_pending_requirements()` which returns `Ok(true)` after draining and processing all requirements
2. **Race Window**: Before Worker A executes line 292
3. Worker B calls `record_requirements()` and acquires the lock
4. Worker B pushes new pending requirements (lines 235-239)
5. Worker B updates `min_idx_with_unprocessed_validation_requirement` via `swap()` (lines 251-253) - this **always executes**
6. Worker B attempts `compare_exchange` on `dedicated_worker_id` (lines 245-250) - this **fails** because Worker A's ID is still set
7. Worker B releases the lock
8. Worker A executes line 292: sets `dedicated_worker_id = u32::MAX` **without holding the lock**

**Resulting Orphaned State:**
- `dedicated_worker_id = u32::MAX` (no worker assigned)
- `pending_requirements` contains Worker B's unprocessed requirements
- `min_idx_with_unprocessed_validation_requirement` is set to block commits
- No worker will process these requirements because `is_dedicated_worker()` returns false for all workers

The scheduler blocks transaction commits based on this state via `is_commit_blocked()`: [5](#0-4) 

The commit eligibility check in the scheduler prevents commits when validation requirements are unsatisfied: [6](#0-5) 

**Correct Pattern:**

The correct synchronization pattern is demonstrated in `validation_requirement_processed()`, which holds the lock when resetting the worker ID: [7](#0-6) 

The comment at lines 395-396 explicitly states: "Since we are holding the lock and pending requirements is empty, it is safe to reset the dedicated worker id."

## Impact Explanation

**Medium Severity** - This vulnerability causes state inconsistencies requiring intervention:

- **Liveness Failure**: Valid transactions are incorrectly blocked from committing despite being executable
- **Indefinite Blocking**: Transactions remain stuck until another module publication assigns a new dedicated worker
- **Availability Impact**: Multiple transactions can be simultaneously blocked, affecting transaction processing throughput
- **No Data Corruption**: Blockchain state remains consistent; no invalid state transitions occur
- **No Safety Violations**: No consensus safety violations, double-spending, or fund theft
- **Self-Recovery Possible**: System recovers when another transaction publishes modules and calls `record_requirements()`, which assigns a new dedicated worker

This aligns with **Medium Severity** per Aptos bug bounty categories (up to $10,000): "State inconsistencies requiring manual intervention" and "Temporary liveness issues." 

This is not Critical because no funds are lost, no consensus safety violations occur, and the system can self-recover. This is not Low because multiple transactions can be simultaneously blocked, affecting core transaction processing capabilities.

## Likelihood Explanation

**Medium to High Likelihood:**

- **Trigger Condition**: Any transaction that publishes Move modules (contract deployments, upgrades)
- **Race Window**: The vulnerable window exists in every module publication where all pending requirements result in no active requirements
- **Concurrency**: BlockSTM's parallel execution with multiple workers creates numerous concurrent operations
- **Timing Sensitive**: More likely under high transaction throughput when multiple workers are actively executing
- **No Privileges Required**: Any user deploying a contract can inadvertently trigger this
- **Cumulative Probability**: Over time with many module publications on production networks, occurrence becomes likely

The race is timing-dependent, so it may not occur on every execution, but given production blockchain transaction volumes and the specific condition where requirements are drained but result in no active requirements (e.g., transactions in PendingScheduling or Aborted states), it will eventually manifest.

## Recommendation

The fix is to hold the `pending_requirements` lock when resetting `dedicated_worker_id` in `get_validation_requirement_to_process()`, consistent with the pattern used in `validation_requirement_processed()`.

Modify lines 291-292 to:

```rust
if self.activate_pending_requirements(statuses)? {
    let _guard = self.pending_requirements.lock();
    self.dedicated_worker_id.store(u32::MAX, Ordering::Relaxed);
    // Guard released here
    return Ok(None);
}
```

This ensures atomicity between checking pending requirements are empty and resetting the dedicated worker ID, preventing the race condition.

## Proof of Concept

The race condition can be triggered through the following scenario:

1. Deploy a Move module (Transaction A) that gets committed
2. During commit, `record_requirements()` is called, creating pending requirements
3. The dedicated worker drains these requirements, but all affected transactions are in PendingScheduling or Aborted states
4. `activate_pending_requirements()` returns `Ok(true)` because no active requirements were created
5. Before the dedicated worker resets the worker ID (line 292), another transaction (Transaction B) publishes modules
6. Transaction B's `record_requirements()` pushes pending requirements and sets the minimum index, but fails to assign itself as dedicated worker
7. The original dedicated worker executes line 292, setting worker ID to `u32::MAX`
8. Result: Pending requirements orphaned, transactions at or above minimum index blocked from committing

While a complete PoC would require setting up the BlockSTM execution environment with precise timing control, the code evidence clearly demonstrates the race window and its consequences.

## Notes

This vulnerability demonstrates an inconsistency in the locking discipline of the cold validation requirements system. The code comments explicitly state that atomic variable updates should occur under the `pending_requirements` lock (lines 241-244), and `validation_requirement_processed()` correctly follows this pattern (lines 383-397). However, `get_validation_requirement_to_process()` violates this invariant at line 292, creating the race condition.

The self-recovering nature of this vulnerability (it resolves when another module publication occurs) prevents it from being Critical severity, but the impact on transaction processing liveness and the clear violation of stated synchronization invariants make it a valid Medium severity issue.

### Citations

**File:** aptos-move/block-executor/src/cold_validation.rs (L234-253)
```rust
        let mut pending_reqs = self.pending_requirements.lock();
        pending_reqs.push(PendingRequirement {
            requirements,
            from_idx: calling_txn_idx + 1,
            to_idx: min_never_scheduled_idx,
        });

        // Updates to atomic variables while recording pending requirements occur under the
        // pending_requirements lock to ensure atomicity versus draining to activate.
        // However, for simplicity and simpler invariants, all updates (including in
        // validation_requirement_processed) are under the same lock.
        let _ = self.dedicated_worker_id.compare_exchange(
            u32::MAX,
            worker_id,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        let prev_min_idx = self
            .min_idx_with_unprocessed_validation_requirement
            .swap(calling_txn_idx + 1, Ordering::Relaxed);
```

**File:** aptos-move/block-executor/src/cold_validation.rs (L291-292)
```rust
        if self.activate_pending_requirements(statuses)? {
            self.dedicated_worker_id.store(u32::MAX, Ordering::Relaxed);
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

**File:** aptos-move/block-executor/src/cold_validation.rs (L507-512)
```rust
            let pending_reqs_guard = self.pending_requirements.lock();
            if pending_reqs_guard.is_empty() {
                self.min_idx_with_unprocessed_validation_requirement
                    .store(u32::MAX, Ordering::Relaxed);
                return Ok(true);
            }
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L631-638)
```rust
            if self
                .cold_validation_requirements
                .is_commit_blocked(next_to_commit_idx, incarnation)
            {
                // May not commit a txn with an unsatisfied validation requirement. This will be
                // more rare than !is_executed in the common case, hence the order of checks.
                return Ok(None);
            }
```
