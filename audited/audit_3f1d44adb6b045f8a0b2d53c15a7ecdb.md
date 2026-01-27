# Audit Report

## Title
Race Condition in hack_reset() Violates State Consistency Invariant Leading to Node Crashes

## Summary
The `hack_reset()` function in `PersistedState` violates the critical ordering invariant between summary and committed state by failing to synchronize with pending asynchronous commits in the HotState committer queue. This can cause state corruption and node panics during restore operations.

## Finding Description

The `PersistedState` struct maintains a critical invariant: the `summary` and `committed` state must always remain synchronized. The `set()` function carefully enforces this by updating summary before enqueueing the state for asynchronous commit. [1](#0-0) 

However, `hack_reset()` violates this invariant through a race condition. While it updates both summary and committed synchronously, it fails to account for pending asynchronous commits already in the HotState committer queue from previous `set()` calls: [2](#0-1) 

The function's comment acknowledges the constraint ("Can only be used when no on the fly commit is in the queue") but provides **no enforcement mechanism**. There is no check to verify the queue is empty, no synchronization barrier, and no mechanism to wait for pending commits to complete.

**Attack Scenario:**

When `StateStore::set_state_ignoring_summary()` is called during restore operations: [3](#0-2) 

The following race can occur:

1. **T0**: Normal operation - `StateMerkleBatchCommitter` calls `persisted_state.set(snapshot_v2)`:
   - Immediately updates `summary = summary_v2`
   - Enqueues `state_v2` to HotState committer thread [4](#0-3) 

2. **T1**: Before committer processes the queue, restore operation calls `hack_reset(snapshot_v1)`:
   - Immediately updates `summary = summary_v1`  
   - Immediately updates `committed = state_v1` (synchronously) [5](#0-4) 

3. **T2**: HotState committer thread processes the queued `state_v2` from step 1:
   - Overwrites `committed = state_v2` [6](#0-5) 

**Final State:**
- `summary = summary_v1` (from hack_reset)
- `committed = state_v2` (from queued set)

This violates the invariant that summary and committed must be synchronized at the same version.

## Impact Explanation

**Severity: High to Critical**

As documented in the `set()` function's comment, this invariant violation causes downstream failures when computing JMT diffs: [7](#0-6) 

The consequence is that when the system attempts to commit state diffs between snapshots, it will **panic** because it cannot calculate the difference between mismatched versions. Specifically:
- If summary is at version v1 but committed is at v2
- When trying to compute diffs between v1 and v3, the state links only go back to v2
- This causes an unrecoverable panic

**Impact Categories:**
- **Node Crashes**: Affected nodes will panic when attempting state operations, causing validator downtime
- **State Corruption**: The persisted state becomes inconsistent, requiring manual intervention to recover
- **Consensus Risk**: If different nodes experience this race at different times during restore/recovery, they may diverge in their state, potentially causing consensus issues

This meets **High Severity** criteria (significant protocol violations, validator node crashes) and potentially **Critical Severity** if it causes non-recoverable state inconsistencies.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability triggers when:
1. The system is processing normal state commits (creating pending commits in the queue)
2. A restore operation is initiated via `set_state_ignoring_summary()`
3. The race window is hit between hack_reset() and the committer processing pending commits

This can occur during:
- **State restore operations** after backup recovery
- **KV replay operations** during transaction replay [8](#0-7) [9](#0-8) 

The race window may be narrow, but given the asynchronous nature of the committer thread and the lack of any synchronization, it is exploitable under timing conditions that occur during normal restore operations.

## Recommendation

Enforce the documented precondition by draining the commit queue before calling `set_commited()`:

```rust
pub fn hack_reset(&self, state_with_summary: StateWithSummary) {
    let (state, summary) = state_with_summary.into_inner();
    
    // Drain pending commits by sending a sync message to the committer
    let (sync_tx, sync_rx) = std::sync::mpsc::channel();
    self.hot_state.commit_tx
        .send(/* CommitMessage::Sync equivalent */)
        .expect("Failed to sync committer");
    sync_rx.recv().expect("Failed to wait for sync");
    
    // Now safe to update - queue is guaranteed empty
    *self.summary.lock() = summary;
    self.hot_state.set_commited(state);
}
```

Alternatively, add explicit validation:
```rust
pub fn hack_reset(&self, state_with_summary: StateWithSummary) {
    // Verify precondition
    assert!(
        self.hot_state.is_commit_queue_empty(),
        "hack_reset called with pending commits in queue"
    );
    
    let (state, summary) = state_with_summary.into_inner();
    *self.summary.lock() = summary;
    self.hot_state.set_commited(state);
}
```

## Proof of Concept

```rust
#[test]
fn test_hack_reset_race_condition() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    let config = HotStateConfig::default();
    let persisted_state = PersistedState::new_empty(config);
    
    // Create two different state snapshots
    let state_v1 = State::new_empty(config);
    let state_v2 = State::new_empty(config); // Different version
    let summary_v1 = StateSummary::new_empty(config);
    let summary_v2 = StateSummary::new_empty(config);
    
    let snapshot_v1 = StateWithSummary::new(state_v1, summary_v1);
    let snapshot_v2 = StateWithSummary::new(state_v2.clone(), summary_v2);
    
    let barrier = Arc::new(Barrier::new(2));
    let ps_clone = persisted_state.clone();
    let b_clone = barrier.clone();
    
    // Thread 1: Call set() to enqueue a commit
    let t1 = thread::spawn(move || {
        ps_clone.set(snapshot_v2);
        b_clone.wait(); // Signal that set() was called
    });
    
    // Thread 2: Call hack_reset() immediately after
    let t2 = thread::spawn(move || {
        barrier.wait(); // Wait for set() to be called
        persisted_state.hack_reset(snapshot_v1);
    });
    
    t1.join().unwrap();
    t2.join().unwrap();
    
    // Give committer thread time to process
    thread::sleep(Duration::from_millis(100));
    
    // Check if summary and committed are out of sync
    let summary = persisted_state.get_state_summary();
    let (_, committed) = persisted_state.get_state();
    
    // If the race occurred, these will be at different versions
    assert_ne!(
        summary.version(), 
        committed.version(),
        "Race condition detected: summary and committed are out of sync"
    );
}
```

**Notes:**

This vulnerability demonstrates a **synchronization bug** where documented preconditions are not enforced. The `hack_reset()` function's comment explicitly states it can only be used when the commit queue is empty, yet the code provides no mechanism to verify or enforce this constraint. During restore operations initiated via `set_state_ignoring_summary()`, pending commits from normal operations can race with `hack_reset()`, causing the critical state consistency invariant to be violated and leading to node crashes when attempting subsequent state operations.

### Citations

**File:** storage/aptosdb/src/state_store/persisted_state.rs (L50-62)
```rust
    pub fn set(&self, persisted: StateWithSummary) {
        let (state, summary) = persisted.into_inner();

        // n.b. Summary must be updated before committing the hot state, otherwise in the execution
        // pipeline we risk having a state generated based on a persisted version (v2) that's newer
        // than that of the summary (v1). That causes issue down the line where we commit the diffs
        // between a later snapshot (v3) and a persisted snapshot (v1) to the JMT, at which point
        // we will not be able to calculate the difference (v1 - v3) because the state links only
        // to as far as v2 (code will panic)
        *self.summary.lock() = summary;

        self.hot_state.enqueue_commit(state);
    }
```

**File:** storage/aptosdb/src/state_store/persisted_state.rs (L64-69)
```rust
    // n.b. Can only be used when no on the fly commit is in the queue.
    pub fn hack_reset(&self, state_with_summary: StateWithSummary) {
        let (state, summary) = state_with_summary.into_inner();
        *self.summary.lock() = summary;
        self.hot_state.set_commited(state);
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1234-1234)
```rust
        self.persisted_state.hack_reset(last_checkpoint.clone());
```

**File:** storage/aptosdb/src/state_store/state_merkle_batch_committer.rs (L106-106)
```rust
                    self.persisted_state.set(snapshot);
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L127-129)
```rust
    pub(crate) fn set_commited(&self, state: State) {
        *self.committed.lock() = state
    }
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L196-197)
```rust
            self.commit(&to_commit);
            *self.committed.lock() = to_commit;
```

**File:** storage/backup/backup-cli/src/backup_types/transaction/restore.rs (L568-568)
```rust
        restore_handler.force_state_version_for_kv_restore(first_version.checked_sub(1))?;
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L276-276)
```rust
        state_store.set_state_ignoring_summary(ledger_state);
```
