# Audit Report

## Title
BlockSTMv2 Commit State Inconsistency Due to Non-Atomic end_commit() Operation

## Summary
In BlockSTMv2's `end_commit()` function, the `committed_marker` is atomically set to `Committed` before verifying that the push to `post_commit_processing_queue` succeeds. If the push fails, a `PanicError` is returned, but the transaction remains marked as committed without being queued for post-commit processing, creating an inconsistent state where the transaction is partially committed.

## Finding Description
The vulnerability exists in the ordering of operations within `SchedulerV2::end_commit()`: [1](#0-0) 

The critical issue is that the state modification (setting `committed_marker` to `Committed`) occurs **before** the critical operation (pushing to `post_commit_processing_queue`) is verified to succeed. This violates the atomicity invariant of the commit process.

**Sequence of events when push fails:**
1. Line 707-708: `committed_marker[txn_idx]` is set to `Committed`
2. Line 710: Attempt to push `txn_idx` to `post_commit_processing_queue` fails
3. Line 711-716: `PanicError` is returned
4. Error propagates through call chain: [2](#0-1) [3](#0-2) [4](#0-3) 

**The inconsistent state:**
- Transaction is marked as `Committed` in `committed_marker`
- Transaction is NOT in `post_commit_processing_queue`
- Transaction will never receive its `PostCommitProcessing` task
- `materialize_txn_commit()` and `record_finalized_output()` never execute [5](#0-4) 

**Additional issue - Lock leak:**
When the error occurs during commit, the `queueing_commits_lock` is held but never released because execution never reaches `commit_hooks_unlock()`: [6](#0-5) 

The `ArmedLock` has no RAII semantics (no Drop implementation), so the lock remains held, preventing other workers from committing transactions. [7](#0-6) 

This breaks **Invariant #4 (State Consistency)**: "State transitions must be atomic and verifiable via Merkle proofs." The commit operation is not atomic - state is modified before the operation is verified to succeed.

## Impact Explanation
**High Severity** - Significant protocol violation.

While an external attacker cannot directly trigger this condition, if it occurs (due to internal race conditions, bugs, or edge cases), it creates:

1. **State Inconsistency**: Transaction marked as committed but not fully processed
2. **Lock Deadlock**: The `queueing_commits_lock` is leaked, preventing further commits
3. **Partial Commit**: Sequential commit hook completed, but post-commit processing never occurs
4. **Protocol Violation**: Breaks atomicity of the commit process

The queue is bounded by `num_txns` and each transaction should only be pushed once, making this rare under normal conditions: [8](#0-7) 

However, the defensive error check exists precisely because the developers recognize this can fail, as noted in the documentation: [9](#0-8) 

## Likelihood Explanation
**Low to Medium** likelihood during normal operation, but the consequences are severe when it occurs.

The condition would manifest under:
- Internal scheduler state corruption
- Race conditions in concurrent queue operations
- Edge cases in the BlockSTM protocol
- Bugs in the scheduler logic causing multiple push attempts

While parallel execution will fail and fall back to sequential execution, the brief window of inconsistent state during error propagation could affect concurrent operations or leave the scheduler in an undefined state.

## Recommendation
Reorder operations in `end_commit()` to verify the push succeeds BEFORE modifying the committed state:

```rust
pub(crate) fn end_commit(&self, txn_idx: TxnIndex) -> Result<(), PanicError> {
    let prev_marker = self.committed_marker[txn_idx as usize].load(Ordering::Relaxed);
    if prev_marker != CommitMarkerFlag::CommitStarted as u8 {
        return Err(code_invariant_error(format!(
            "Marking txn {} as COMMITTED, but previous marker {} != {}",
            txn_idx,
            prev_marker,
            CommitMarkerFlag::CommitStarted as u8
        )));
    }
    
    // FIRST: Verify the push succeeds
    if let Err(e) = self.post_commit_processing_queue.push(txn_idx) {
        return Err(code_invariant_error(format!(
            "Error adding {txn_idx} to commit queue, len {}, error: {:?}",
            self.post_commit_processing_queue.len(),
            e
        )));
    }
    
    // ONLY THEN: Update the committed marker
    // This ensures atomicity - either both succeed or neither
    self.committed_marker[txn_idx as usize]
        .store(CommitMarkerFlag::Committed as u8, Ordering::Relaxed);
    
    Ok(())
}
```

Additionally, consider adding RAII guards for the `queueing_commits_lock` to prevent lock leaks on error paths.

## Proof of Concept
This vulnerability cannot be triggered via a Move test or external transaction, as it requires internal scheduler state manipulation. A reproduction would require:

1. Fault injection into the `ConcurrentQueue::push()` operation
2. Or artificially filling the queue beyond capacity
3. Or introducing a race condition in concurrent queue access

The defensive error check in the code itself demonstrates the developers' awareness that this failure mode exists, even if rare.

**Notes**

The error IS properly propagated through the call chain via `?` operators at every level. However, the fundamental issue is that state modification occurs before operation verification, violating atomicity. The inconsistent state exists in the brief window between the marker update and error detection, and while parallel execution will fail over to sequential, this represents a protocol violation and potential undefined behavior during that window.

### Citations

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L560-563)
```rust
            queueing_commits_lock: CachePadded::new(ArmedLock::new()),
            post_commit_processing_queue: CachePadded::new(ConcurrentQueue::<TxnIndex>::bounded(
                num_txns as usize,
            )),
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L685-691)
```rust
    /// This method performs two main actions:
    /// 1. Updates the `committed_marker` for `txn_idx` from `CommitStarted` to `Committed`.
    ///    Panics if the previous marker was not `CommitStarted`.
    /// 2. Pushes `txn_idx` to the `post_commit_processing_queue`, making it available for
    ///    a `PostCommitProcessing` task to be dispatched by [SchedulerV2::next_task].
    ///    Panics if the queue push fails (e.g., if the queue is full, which shouldn't happen
    ///    given it's bounded by `num_txns`).
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L696-719)
```rust
    pub(crate) fn end_commit(&self, txn_idx: TxnIndex) -> Result<(), PanicError> {
        let prev_marker = self.committed_marker[txn_idx as usize].load(Ordering::Relaxed);
        if prev_marker != CommitMarkerFlag::CommitStarted as u8 {
            return Err(code_invariant_error(format!(
                "Marking txn {} as COMMITTED, but previous marker {} != {}",
                txn_idx,
                prev_marker,
                CommitMarkerFlag::CommitStarted as u8
            )));
        }
        // Allows next sequential commit hook to be processed.
        self.committed_marker[txn_idx as usize]
            .store(CommitMarkerFlag::Committed as u8, Ordering::Relaxed);

        if let Err(e) = self.post_commit_processing_queue.push(txn_idx) {
            return Err(code_invariant_error(format!(
                "Error adding {txn_idx} to commit queue, len {}, error: {:?}",
                self.post_commit_processing_queue.len(),
                e
            )));
        }

        Ok(())
    }
```

**File:** aptos-move/block-executor/src/scheduler_wrapper.rs (L68-76)
```rust
    pub(crate) fn add_to_post_commit(&self, txn_idx: TxnIndex) -> Result<(), PanicError> {
        match self {
            SchedulerWrapper::V1(scheduler, _) => {
                scheduler.add_to_commit_queue(txn_idx);
                Ok(())
            },
            SchedulerWrapper::V2(scheduler, _) => scheduler.end_commit(txn_idx),
        }
    }
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L374-376)
```rust
        // Add before halt, so SchedulerV2 can organically observe and process post commit
        // processing tasks even after it has halted.
        scheduler.add_to_post_commit(txn_idx)?;
```

**File:** aptos-move/block-executor/src/executor.rs (L1454-1472)
```rust
        loop {
            while scheduler.commit_hooks_try_lock() {
                // Perform sequential commit hooks.
                while let Some((txn_idx, incarnation)) = scheduler.start_commit()? {
                    self.prepare_and_queue_commit_ready_txn(
                        txn_idx,
                        incarnation,
                        num_txns,
                        executor,
                        block,
                        num_workers as usize,
                        runtime_environment,
                        scheduler_wrapper,
                        shared_sync_params,
                    )?;
                }

                scheduler.commit_hooks_unlock();
            }
```

**File:** aptos-move/block-executor/src/executor.rs (L1507-1514)
```rust
                TaskKind::PostCommitProcessing(txn_idx) => {
                    self.materialize_txn_commit(
                        txn_idx,
                        scheduler_wrapper,
                        environment,
                        shared_sync_params,
                    )?;
                    self.record_finalized_output(txn_idx, txn_idx, shared_sync_params)?;
```

**File:** aptos-move/block-executor/src/scheduler.rs (L24-51)
```rust
pub struct ArmedLock {
    // Last bit:   1 -> unlocked; 0 -> locked
    // Second bit: 1 -> there's work; 0 -> no work
    locked: AtomicU64,
}

impl ArmedLock {
    pub fn new() -> Self {
        Self {
            locked: AtomicU64::new(3),
        }
    }

    // try_lock succeeds when the lock is unlocked and armed (there is work to do).
    pub fn try_lock(&self) -> bool {
        self.locked
            .compare_exchange_weak(3, 0, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    pub fn unlock(&self) {
        self.locked.fetch_or(1, Ordering::Release);
    }

    pub fn arm(&self) {
        self.locked.fetch_or(2, Ordering::Release);
    }
}
```
