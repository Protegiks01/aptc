> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** aptos-move/block-executor/src/scheduler_status.rs (L417-461)
```rust
    pub(crate) fn remove_stall(&self, txn_idx: TxnIndex) -> Result<bool, PanicError> {
        let status = &self.statuses[txn_idx as usize];
        let prev_num_stalls = status.num_stalls.fetch_sub(1, Ordering::SeqCst);

        if prev_num_stalls == 0 {
            return Err(code_invariant_error(
                "remove_stall called when num_stalls == 0",
            ));
        }

        if prev_num_stalls == 1 {
            // Acquire write lock for (non-monitor) shortcut modifications.
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
            } else if status_guard.is_executed() {
                // TODO(BlockSMTv2): Here, when waiting is supported, if inner status is executed,
                // would need to notify waiting workers.

                // Status is Executed so the dependency status may not be WaitForExecution
                // (finish_execution sets ShouldDefer or IsSafe dependency status).
                status.swap_dependency_status_any(
                    &[DependencyStatus::ShouldDefer, DependencyStatus::IsSafe],
                    DependencyStatus::IsSafe,
                    "remove_stall",
                )?;
            }

            return Ok(true);
        }
        Ok(false)
    }
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L744-748)
```rust
    pub(crate) fn pending_scheduling_and_not_stalled(&self, txn_idx: TxnIndex) -> bool {
        let status = &self.statuses[txn_idx as usize];
        let guard = status.status_with_incarnation.lock();
        guard.pending_scheduling().is_some() && !status.is_stalled()
    }
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L959-961)
```rust
    pub(crate) fn is_stalled(&self) -> bool {
        self.num_stalls.load(Ordering::Relaxed) > 0
    }
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L1275-1341)
```rust
    #[test]
    fn stall_executed_status() {
        let statuses =
            ExecutionStatuses::new_for_test(ExecutionQueueManager::new_for_test(1), vec![
                ExecutionStatus::new_for_test(
                    StatusWithIncarnation::new_for_test(SchedulingStatus::Executed, 5),
                    0,
                ),
            ]);
        let executed_status = statuses.get_status(0);

        // Assert correct starting state - provided by new_for_test.
        executed_status
            .dependency_shortcut
            .store(DependencyStatus::IsSafe as u8, Ordering::Relaxed);
        assert_eq!(executed_status.num_stalls.load(Ordering::Relaxed), 0);

        assert_ok_eq!(statuses.add_stall(0), true);
        assert_eq!(
            executed_status.dependency_shortcut.load(Ordering::Relaxed),
            DependencyStatus::ShouldDefer as u8
        );
        assert_eq!(executed_status.num_stalls.load(Ordering::Relaxed), 1);

        // Adding stalls to an on already stalled status: return false.
        assert_ok_eq!(statuses.add_stall(0), false);
        assert_ok_eq!(statuses.add_stall(0), false);
        assert_ok_eq!(statuses.add_stall(0), false);
        assert_eq!(executed_status.num_stalls.load(Ordering::Relaxed), 4);

        assert_ok_eq!(statuses.remove_stall(0), false);
        assert_ok_eq!(statuses.remove_stall(0), false);
        assert_eq!(executed_status.num_stalls.load(Ordering::Relaxed), 2);
        assert_eq!(
            executed_status.dependency_shortcut.load(Ordering::Relaxed),
            DependencyStatus::ShouldDefer as u8
        );
        assert_ok_eq!(statuses.remove_stall(0), false);
        assert_ok_eq!(statuses.remove_stall(0), true);
        assert_eq!(
            executed_status.dependency_shortcut.load(Ordering::Relaxed),
            DependencyStatus::IsSafe as u8
        );
        assert_eq!(executed_status.num_stalls.load(Ordering::Relaxed), 0);

        assert_ok_eq!(statuses.add_stall(0), true);
        assert_eq!(
            executed_status.dependency_shortcut.load(Ordering::Relaxed),
            DependencyStatus::ShouldDefer as u8
        );
        assert_eq!(executed_status.num_stalls.load(Ordering::Relaxed), 1);
        assert_ok_eq!(statuses.remove_stall(0), true);
        assert_eq!(
            executed_status.dependency_shortcut.load(Ordering::Relaxed),
            DependencyStatus::IsSafe as u8
        );
        assert_ok_eq!(statuses.add_stall(0), true);
        assert_ok_eq!(statuses.add_stall(0), false);
        assert_eq!(
            executed_status.dependency_shortcut.load(Ordering::Relaxed),
            DependencyStatus::ShouldDefer as u8
        );
        assert_eq!(executed_status.num_stalls.load(Ordering::Relaxed), 2);
        assert_ok_eq!(statuses.remove_stall(0), false);
        assert_ok_eq!(statuses.remove_stall(0), true);
        assert_err!(statuses.remove_stall(0));
    }
```

**File:** aptos-move/block-executor/src/scheduler_status.rs (L1659-1695)
```rust
    fn remove_stall_err_senarios() {
        let mut statuses =
            ExecutionStatuses::new_for_test(ExecutionQueueManager::new_for_test(1), vec![
                ExecutionStatus::new(),
                ExecutionStatus::new_for_test(
                    StatusWithIncarnation::new_for_test(SchedulingStatus::PendingScheduling, 1),
                    0,
                ),
                ExecutionStatus::new_for_test(
                    StatusWithIncarnation::new_for_test(SchedulingStatus::PendingScheduling, 0),
                    1,
                ),
            ]);

        for wrong_shortcut in [DependencyStatus::WaitForExecution as u8, 100] {
            *statuses.get_status_mut(0) = ExecutionStatus::new_for_test(
                StatusWithIncarnation::new_for_test(SchedulingStatus::Executed, 0),
                2,
            );

            // remove_stall succeeds as it should.
            assert_ok_eq!(statuses.remove_stall(0), false);
            assert_eq!(statuses.get_status(0).num_stalls.load(Ordering::Relaxed), 1);

            statuses
                .get_status_mut(0)
                .dependency_shortcut
                .store(wrong_shortcut, Ordering::Relaxed);
            // Normal removal that would otherwise succeed should now return an error.
            assert_err!(statuses.remove_stall(0));
        }

        // Number of stalls = 0 for txn 1.
        assert_err!(statuses.remove_stall(1));
        // Incarnation 0 / err for txn 2.
        assert_err!(statuses.remove_stall(2));
    }
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L263-353)
```rust
/// Tracks downstream transactions previously aborted by an owner and manages stall propagation.
///
/// When an owner transaction T_owner (re-)executes and its write set changes, it might cause
/// other transactions (T_dep) that read T_owner's output to be aborted. This struct,
/// associated with T_owner, keeps a record of such T_dep transactions.
///
/// It also tracks which of these dependencies it has actively propagated stalls to (for later
/// removal) since such dependencies might be detected concurrently to stalls being added/removed
/// elsewhere. The primary purpose is to manage these "stalls". If T_owner itself is aborted or
/// stalled, it's likely that its previously aborted dependencies (T_dep) will also need to be
/// re-aborted if they re-execute. To prevent wasted work, a stall can be propagated from T_owner
/// to these T_dep transactions.
///
/// This struct distinguishes between dependencies for which a stall has been actively
/// propagated (`stalled_deps`) and those for which it has not (`not_stalled_deps`).
/// The `is_stalled` flag indicates whether the owner transaction itself is considered stalled
/// from the perspective of this [AbortedDependencies] instance, which then dictates whether
/// to propagate `add_stall` or `remove_stall` to its dependencies.
///
/// An invariant is maintained: `stalled_deps` and `not_stalled_deps` must always be disjoint.
struct AbortedDependencies {
    is_stalled: bool,
    not_stalled_deps: BTreeSet<TxnIndex>,
    stalled_deps: BTreeSet<TxnIndex>,
}

impl AbortedDependencies {
    fn new() -> Self {
        Self {
            is_stalled: false,
            not_stalled_deps: BTreeSet::new(),
            stalled_deps: BTreeSet::new(),
        }
    }

    fn record_dependencies(&mut self, dependencies: impl Iterator<Item = TxnIndex>) {
        for dep in dependencies {
            if !self.stalled_deps.contains(&dep) {
                self.not_stalled_deps.insert(dep);
            }
        }
    }

    // Calls add_stall on the status and adds all indices from not_stalled to stalled.
    // Inserts indices for which add_stall returned true into the propagation queue.
    fn add_stall(
        &mut self,
        statuses: &ExecutionStatuses,
        stall_propagation_queue: &mut BTreeSet<usize>,
    ) -> Result<(), PanicError> {
        for idx in &self.not_stalled_deps {
            // Assert the invariant in tests.
            #[cfg(test)]
            assert!(!self.stalled_deps.contains(idx));

            if statuses.add_stall(*idx)? {
                // May require recursive add_stalls.
                stall_propagation_queue.insert(*idx as usize);
            }
        }

        self.stalled_deps.append(&mut self.not_stalled_deps);
        self.is_stalled = true;
        Ok(())
    }

    // Calls [ExecutionStatuses::remove_stall] on the status and adds all indices from
    // stalled to not_stalled. Inserts indices for which remove_stall returned true into
    // the stall propagation queue. If such status is pending scheduling, ExecutionStatuses
    // uses execution queue manager to add the transaction to execution queue.
    fn remove_stall(
        &mut self,
        statuses: &ExecutionStatuses,
        stall_propagation_queue: &mut BTreeSet<usize>,
    ) -> Result<(), PanicError> {
        for idx in &self.stalled_deps {
            // Assert the invariant in tests.
            #[cfg(test)]
            assert!(!self.not_stalled_deps.contains(idx));

            if statuses.remove_stall(*idx)? {
                // May require recursive remove_stalls.
                stall_propagation_queue.insert(*idx as usize);
            }
        }

        self.not_stalled_deps.append(&mut self.stalled_deps);
        self.is_stalled = false;
        Ok(())
    }
}
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L1212-1237)
```rust
    fn propagate(&self, mut stall_propagation_queue: BTreeSet<usize>) -> Result<(), PanicError> {
        // Dependencies of each transaction always have higher indices than the transaction itself.
        // This means that the stall propagation queue is always processed in ascending order of
        // transaction indices, and that the processing loop is guaranteed to terminate.
        while let Some(task_idx) = stall_propagation_queue.pop_first() {
            // Make sure the conditions are checked under dependency lock.
            let mut aborted_deps_guard = self.aborted_dependencies[task_idx].lock();

            // Checks the current status to determine whether to propagate add / remove stall,
            // calling which only affects its currently not_stalled (or stalled) dependencies.
            // Allows to store indices in propagation queue (not add or remove commands) & avoids
            // handling corner cases such as merging commands (as propagation process is not atomic).
            if self
                .txn_statuses
                .shortcut_executed_and_not_stalled(task_idx)
            {
                // Still makes sense to propagate remove_stall.
                aborted_deps_guard
                    .remove_stall(&self.txn_statuses, &mut stall_propagation_queue)?;
            } else {
                // Not executed or stalled - still makes sense to propagate add_stall.
                aborted_deps_guard.add_stall(&self.txn_statuses, &mut stall_propagation_queue)?;
            }
        }
        Ok(())
    }
```
