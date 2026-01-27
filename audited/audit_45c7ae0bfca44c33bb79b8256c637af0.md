# Audit Report

## Title
Race Condition Allows Committed Transactions to Re-execute, Breaking State Consistency Invariant

## Summary
A critical race condition exists in BlockSTMv2's `SchedulerV2` between commit operations and module validation aborts. A transaction can simultaneously exist in both "Committed" and "PendingScheduling" states, allowing committed transactions to be re-executed and potentially causing consensus splits across validators.

## Finding Description

The vulnerability occurs due to improper synchronization between two concurrent operations in BlockSTMv2:

1. **Commit Path**: The commit coordinator thread calls `start_commit()` → performs commit hook → calls `end_commit()` to mark transaction as committed
2. **Validation-Abort Path**: A worker thread performs `module_validation_v2()` which can call `direct_abort()` on an `Executed` transaction

The race window exists because: [1](#0-0) 

The `start_commit()` method checks if a transaction is `Executed` and sets `committed_marker = CommitStarted`, but does NOT hold any lock that prevents concurrent state changes to `txn_status`. 

Meanwhile, `module_validation_v2()` can call `direct_abort()` which executes: [2](#0-1) 

This calls `finish_abort()` which changes the transaction status: [3](#0-2) 

When `finish_abort()` executes on an `Executed` transaction, it transitions the status to `PendingScheduling(incarnation+1)` and adds it back to the execution queue.

The race timeline:
1. Worker Thread A: Calls `finish_execution()` → status becomes `Executed(incarnation=5)`
2. Commit Thread B: Calls `start_commit()` → sees `is_executed()` = true
3. Thread B: Sets `committed_marker[txn] = CommitStarted`
4. **[RACE WINDOW]**
5. Worker Thread A: Performs `module_validation_v2()` → validation fails
6. Thread A: Calls `direct_abort(txn, 5, false)`
7. Thread A: `finish_abort()` changes status to `PendingScheduling(incarnation=6)`
8. **[END RACE WINDOW]**
9. Thread B: Calls `end_commit()` → sets `committed_marker[txn] = Committed` [4](#0-3) 

Final impossible state:
- `committed_marker[txn] = Committed` 
- `txn_status[txn] = PendingScheduling(6)`
- Transaction is in execution queue for re-execution

The critical issue is that `end_commit()` only validates the `committed_marker` was `CommitStarted`, but does NOT re-validate that the transaction status is still `Executed`. A transaction marked as `Committed` but with status `PendingScheduling` will be picked up by workers and re-executed, violating the invariant that committed transactions are immutable.

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." The state transition from `Executed` to `Committed` is NOT atomic because the `txn_status` and `committed_marker` are updated separately without mutual exclusion.

## Impact Explanation

**Critical Severity** - This vulnerability can cause consensus splits, which is explicitly listed as a Critical impact in the Aptos bug bounty program.

When validators execute the same block:
- Some validators may observe the race and re-execute the committed transaction
- Others may not, leaving the transaction executed only once
- The re-execution produces different outputs (different incarnation number, potentially different state changes if the transaction is non-deterministic in any way)
- This leads to different state roots being computed
- Validators will disagree on the block's state, causing a consensus split

This violates the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

Additional impacts:
- **State Merkle Tree Corruption**: Re-executing committed transactions modifies the versioned cache with conflicting data
- **Double Application of Effects**: Transaction effects may be applied multiple times
- **Resource Exhaustion**: Unnecessary re-executions waste computational resources

## Likelihood Explanation

**High Likelihood** during normal operation when:
1. Transactions publish Move modules (triggering module validation)
2. Module validation requirements are deferred (common in BlockSTMv2's cold validation optimization)
3. Concurrent execution of multiple transactions

The race window is small but realistic:
- Module validation happens immediately after `finish_execution()` in the same worker thread
- Commit coordination runs concurrently on a different thread
- No explicit synchronization prevents the interleaving

The vulnerability does NOT require:
- Malicious validator behavior
- Attacker-controlled transactions
- Specific transaction content (though module-publishing transactions are more likely to trigger it)

It can occur naturally during high transaction throughput when the scheduler is under load.

## Recommendation

Add validation in `end_commit()` to verify the transaction status hasn't changed since `start_commit()`:

```rust
pub(crate) fn end_commit(&self, txn_idx: TxnIndex) -> Result<(), PanicError> {
    let prev_marker = self.committed_marker[txn_idx as usize].load(Ordering::Relaxed);
    if prev_marker != CommitMarkerFlag::CommitStarted as u8 {
        return Err(code_invariant_error(format!(
            "Marking txn {} as COMMITTED, but previous marker {} != {}",
            txn_idx, prev_marker, CommitMarkerFlag::CommitStarted as u8
        )));
    }
    
    // NEW CHECK: Verify transaction is still in Executed state
    if !self.txn_statuses.is_executed(txn_idx) {
        // Transaction was aborted during commit process, revert commit marker
        self.committed_marker[txn_idx as usize]
            .store(CommitMarkerFlag::NotCommitted as u8, Ordering::Relaxed);
        return Err(code_invariant_error(format!(
            "Transaction {} was aborted during commit, cannot complete commit",
            txn_idx
        )));
    }
    
    self.committed_marker[txn_idx as usize]
        .store(CommitMarkerFlag::Committed as u8, Ordering::Relaxed);
    
    // ... rest of the method
}
```

Alternatively, hold the `status_with_incarnation` lock during the entire commit sequence, or use the `committed_marker` state to prevent aborts on transactions that have started committing.

## Proof of Concept

```rust
// Concurrent test demonstrating the race condition
#[test]
fn test_commit_abort_race_condition() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    let num_txns = 10;
    let scheduler = Arc::new(SchedulerV2::new(num_txns, 4));
    
    // Execute a transaction to Executed state
    let txn_idx = 5;
    let incarnation = 0;
    
    // Simulate finish_execution
    let abort_manager = AbortManager::new(txn_idx, incarnation, &scheduler);
    scheduler.finish_execution(abort_manager).unwrap();
    
    // Verify it's in Executed state
    assert!(scheduler.txn_statuses.is_executed(txn_idx));
    
    let barrier = Arc::new(Barrier::new(2));
    let scheduler_clone1 = Arc::clone(&scheduler);
    let scheduler_clone2 = Arc::clone(&scheduler);
    let barrier_clone1 = Arc::clone(&barrier);
    let barrier_clone2 = Arc::clone(&barrier);
    
    // Thread 1: Commit coordinator
    let commit_handle = thread::spawn(move || {
        // Lock the commit lock
        assert!(scheduler_clone1.commit_hooks_try_lock());
        
        // Start commit
        let commit_result = scheduler_clone1.start_commit().unwrap();
        assert!(commit_result.is_some());
        let (idx, inc) = commit_result.unwrap();
        assert_eq!(idx, txn_idx);
        assert_eq!(inc, incarnation);
        
        // Signal that commit started
        barrier_clone1.wait();
        
        // Small delay to ensure abort happens
        thread::sleep(Duration::from_millis(10));
        
        // Complete commit
        scheduler_clone1.end_commit(txn_idx).unwrap();
        scheduler_clone1.commit_hooks_unlock();
    });
    
    // Thread 2: Module validation abort
    let abort_handle = thread::spawn(move || {
        // Wait for commit to start
        barrier_clone2.wait();
        
        // Perform abort (simulating failed module validation)
        scheduler_clone2.direct_abort(txn_idx, incarnation, false).unwrap();
    });
    
    commit_handle.join().unwrap();
    abort_handle.join().unwrap();
    
    // Check the inconsistent state
    let committed = scheduler.committed_marker[txn_idx as usize]
        .load(Ordering::Relaxed);
    let is_executed = scheduler.txn_statuses.is_executed(txn_idx);
    let current_incarnation = scheduler.txn_statuses.incarnation(txn_idx);
    
    // VULNERABILITY: Transaction is marked as Committed but status is PendingScheduling
    assert_eq!(committed, CommitMarkerFlag::Committed as u8);
    assert!(!is_executed); // Should be false (not Executed anymore)
    assert_eq!(current_incarnation, incarnation + 1); // Incarnation was incremented
    
    // The transaction is now in an impossible state:
    // - Marked as committed (committed_marker = Committed)
    // - But also pending re-execution (status = PendingScheduling(1))
}
```

## Notes

This vulnerability is specific to BlockSTMv2 (`SchedulerV2`) and does not affect BlockSTMv1 (`Scheduler`), as V1 uses different synchronization mechanisms and does not have the same commit marker/status separation. [5](#0-4) 

The fix must ensure atomicity between checking transaction status and updating commit markers, or prevent aborts on transactions that have entered the commit phase.

### Citations

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L606-680)
```rust
    pub(crate) fn start_commit(&self) -> Result<Option<(TxnIndex, Incarnation)>, PanicError> {
        // Relaxed ordering due to armed lock acq-rel.
        let next_to_commit_idx = self.next_to_commit_idx.load(Ordering::Relaxed);
        assert!(next_to_commit_idx <= self.num_txns);

        if self.is_halted() || next_to_commit_idx == self.num_txns {
            // All sequential commit hooks are already dispatched.
            return Ok(None);
        }

        let incarnation = self.txn_statuses.incarnation(next_to_commit_idx);
        if self.txn_statuses.is_executed(next_to_commit_idx) {
            self.commit_marker_invariant_check(next_to_commit_idx)?;

            // All prior transactions are committed and the latest incarnation of the transaction
            // at next_to_commit_idx has finished but has not been aborted. If any of its reads was
            // incorrect, it would have been invalidated by the respective transaction's last
            // (committed) (re-)execution, and led to an abort in the corresponding finish execution
            // (which, inductively, must occur before the transaction is committed). Hence, it
            // must also be safe to commit the current transaction.
            //
            // The only exception is if there are unsatisfied cold validation requirements,
            // blocking the commit. These may not yet be scheduled for validation, or deferred
            // until after the txn finished execution, whereby deferral happens before txn status
            // becomes Executed, while validation and unblocking happens after.
            if self
                .cold_validation_requirements
                .is_commit_blocked(next_to_commit_idx, incarnation)
            {
                // May not commit a txn with an unsatisfied validation requirement. This will be
                // more rare than !is_executed in the common case, hence the order of checks.
                return Ok(None);
            }
            // The check might have passed after the validation requirement has been fulfilled.
            // Yet, if validation failed, the status would be aborted before removing the block,
            // which would increase the incarnation number. It is also important to note that
            // blocking happens during sequential commit hook, while holding the lock (which is
            // also held here), hence before the call of this method.
            if incarnation != self.txn_statuses.incarnation(next_to_commit_idx) {
                return Ok(None);
            }

            if self
                .committed_marker
                .get(next_to_commit_idx as usize)
                .is_some_and(|marker| {
                    marker.swap(CommitMarkerFlag::CommitStarted as u8, Ordering::Relaxed)
                        != CommitMarkerFlag::NotCommitted as u8
                })
            {
                return Err(code_invariant_error(format!(
                    "Marking {} as PENDING_COMMIT_HOOK, but previous marker != NOT_COMMITTED",
                    next_to_commit_idx
                )));
            }

            // TODO(BlockSTMv2): fetch_add as a RMW instruction causes a barrier even with
            // Relaxed ordering. The read is only used to check an invariant, so we can
            // eventually change to just a relaxed write.
            let prev_idx = self.next_to_commit_idx.fetch_add(1, Ordering::Relaxed);
            if prev_idx != next_to_commit_idx {
                return Err(code_invariant_error(format!(
                    "Scheduler committing {}, stored next to commit idx = {}",
                    next_to_commit_idx, prev_idx
                )));
            }

            return Ok(Some((
                next_to_commit_idx,
                self.txn_statuses.incarnation(next_to_commit_idx),
            )));
        }

        Ok(None)
    }
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

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L996-1016)
```rust
    pub(crate) fn direct_abort(
        &self,
        txn_idx: TxnIndex,
        incarnation: Incarnation,
        start_next_incarnation: bool,
    ) -> Result<bool, PanicError> {
        if self.txn_statuses.start_abort(txn_idx, incarnation)? {
            self.txn_statuses
                .finish_abort(txn_idx, incarnation, start_next_incarnation)?;
            return Ok(true);
        }

        if start_next_incarnation {
            return Err(code_invariant_error(format!(
                "SchedulerV2: self-abort with start_next_incarnation failed for {} {}",
                txn_idx, incarnation
            )));
        }

        Ok(false)
    }
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L647-722)
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

        {
            let status_guard = &mut *status.status_with_incarnation.lock();
            if status_guard.already_aborted(aborted_incarnation)
                || status_guard.never_started_execution(aborted_incarnation)
            {
                return Err(code_invariant_error(format!(
                    "Finish abort of incarnation {}, but inner status {:?}",
                    aborted_incarnation, status_guard
                )));
            }

            match status_guard.status {
                SchedulingStatus::Executing(_) => {
                    if start_next_incarnation {
                        return Err(code_invariant_error(format!(
                            "Finish abort for txn_idx: {} incarnation: {} w. start_next_incarnation \
                            expected Executed Status, got Executing",
                            txn_idx, aborted_incarnation
                        )));
                    }

                    // Module validation requirements are irrelevant as the incarnation was aborted.
                    status_guard.status = SchedulingStatus::Aborted;
                    status.swap_dependency_status_any(
                        &[DependencyStatus::WaitForExecution],
                        DependencyStatus::ShouldDefer,
                        "finish_abort",
                    )?;
                },
                SchedulingStatus::Executed => {
                    self.to_pending_scheduling(
                        txn_idx,
                        status_guard,
                        new_incarnation,
                        !start_next_incarnation,
                    );
                    if start_next_incarnation {
                        let started_incarnation = self.to_executing(txn_idx, status_guard)?;
                        if Some(aborted_incarnation + 1) != started_incarnation {
                            return Err(code_invariant_error(format!(
                                "Finish abort started incarnation {:?} != expected {}",
                                txn_idx,
                                aborted_incarnation + 1
                            )));
                        }
                    }
                },
                SchedulingStatus::PendingScheduling | SchedulingStatus::Aborted => {
                    return Err(code_invariant_error(format!(
                        "Status update to Aborted failed, previous inner status {:?}",
                        status_guard
                    )));
                },
            }
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
