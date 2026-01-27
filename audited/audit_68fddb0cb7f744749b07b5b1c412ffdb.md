# Audit Report

## Title
Race Condition in `hack_reset()` Allows Committed State Corruption During Concurrent HotState Commits

## Summary
The `hack_reset()` function in `PersistedState` directly overwrites the committed state without synchronizing with the asynchronous HotState committer thread. If commits are queued when `hack_reset()` is called, the committer thread can process those commits after the reset, overwriting and losing the intended reset state.

## Finding Description

The vulnerability exists in the state management layer where two concurrent operations can race to modify the committed state:

**The Race Condition:**

In `hack_reset()`, the function calls `set_commited()` to directly set the committed state: [1](#0-0) 

This calls `set_commited()` in HotState which writes directly to the committed state: [2](#0-1) 

Meanwhile, the HotState Committer thread processes queued commits asynchronously: [3](#0-2) 

At line 197, the committer thread also writes to `*self.committed.lock() = to_commit`, which can overwrite the state set by `hack_reset()`.

**The Precondition:**

The code explicitly documents this limitation: [4](#0-3) 

However, this precondition is **not enforced** by the code. There is no check to verify the queue is empty, no barrier to wait for pending commits, and no synchronization mechanism between `set_commited()` and the committer thread.

**Execution Flow:**

Normal state commits are queued via `enqueue_commit()`: [5](#0-4) 

These are sent to a channel and processed asynchronously by the Committer thread spawned here: [6](#0-5) 

**Where hack_reset() is Called:**

1. During BufferedState initialization: [7](#0-6) 

2. During restore operations: [8](#0-7) 

The restore path is particularly concerning because it's called during kv_replay with this comment acknowledging the timing issue: [9](#0-8) 

## Impact Explanation

**Severity: Medium**

While the race condition is real and the code lacks proper synchronization, I cannot identify a clear path for an **unprivileged external attacker** to exploit this vulnerability. The issue manifests as:

- **State Inconsistency**: If triggered, the reset state is lost and replaced with a stale queued commit, violating the State Consistency invariant
- **Potential Consensus Divergence**: If different nodes experience this race differently during restore, they could end up with divergent state roots
- **Administrative Operations Only**: `hack_reset()` is only called during initialization and restore operations, which are administrative functions not directly triggerable by external attackers

This meets **Medium Severity** criteria as a "State inconsistency requiring intervention" but falls short of High/Critical severity due to lack of external exploitability.

## Likelihood Explanation

**Likelihood: Low**

The race can only occur when:
1. The HotState committer thread has queued commits pending
2. `hack_reset()` is called (only during initialization or restore)
3. The timing aligns such that the committer processes the queue after the reset

In practice:
- Initialization happens at startup with no prior commits queued
- Restore operations are offline administrative procedures
- No external attacker control over triggering conditions

However, the race is **non-deterministic** and could manifest during complex multi-phase restore operations or if future code changes introduce new `hack_reset()` call sites.

## Recommendation

Add proper synchronization to ensure `hack_reset()` only executes when the commit queue is empty:

**Option 1: Drain the queue before reset**
```rust
pub fn hack_reset(&self, state_with_summary: StateWithSummary) {
    // Drain any pending commits before resetting
    self.drain_pending_commits();
    
    let (state, summary) = state_with_summary.into_inner();
    *self.summary.lock() = summary;
    self.hot_state.set_commited(state);
}

fn drain_pending_commits(&self) {
    // Send a sync marker and wait for it to be processed
    // This ensures all prior commits are completed
}
```

**Option 2: Add assertion to detect violations**
```rust
pub fn hack_reset(&self, state_with_summary: StateWithSummary) {
    // Assert the precondition
    assert!(
        self.hot_state.is_commit_queue_empty(),
        "hack_reset called with pending commits in queue"
    );
    
    let (state, summary) = state_with_summary.into_inner();
    *self.summary.lock() = summary;
    self.hot_state.set_commited(state);
}
```

**Option 3: Use atomic swap with version checking**
```rust
pub fn hack_reset(&self, state_with_summary: StateWithSummary) {
    let (state, summary) = state_with_summary.into_inner();
    *self.summary.lock() = summary;
    
    // Use a versioned atomic operation that fails if state was modified
    self.hot_state.set_commited_with_version_check(state);
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod race_condition_test {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    #[test]
    fn test_hack_reset_race_with_pending_commits() {
        let config = HotStateConfig::default();
        let persisted_state = PersistedState::new_empty(config);
        
        // Queue several commits
        for i in 0..10 {
            let state = State::new_at_version(Some(i), StateStorageUsage::zero(), config);
            persisted_state.set(StateWithSummary::new(
                state,
                StateSummary::new_empty(config)
            ));
        }
        
        // Small delay to let some commits start processing
        thread::sleep(std::time::Duration::from_millis(10));
        
        // Now call hack_reset while commits are being processed
        let reset_state = State::new_at_version(Some(100), StateStorageUsage::zero(), config);
        persisted_state.hack_reset(StateWithSummary::new(
            reset_state.clone(),
            StateSummary::new_empty(config)
        ));
        
        // Wait for all commits to finish
        thread::sleep(std::time::Duration::from_millis(100));
        
        // Check if the reset state survived or was overwritten
        let (_, final_state) = persisted_state.get_state();
        
        // If the race occurred, final_state.version() might be < 100
        // indicating the reset state was overwritten by a queued commit
        assert_eq!(
            final_state.version(),
            Some(100),
            "Reset state was overwritten by queued commit - race condition occurred"
        );
    }
}
```

**Note:** This PoC demonstrates the race condition exists in the code structure, but does **not** demonstrate external exploitability by an unprivileged attacker, as the attack surface requires administrative operations (restore/initialization) that are not user-controllable.

### Citations

**File:** storage/aptosdb/src/state_store/persisted_state.rs (L64-69)
```rust
    // n.b. Can only be used when no on the fly commit is in the queue.
    pub fn hack_reset(&self, state_with_summary: StateWithSummary) {
        let (state, summary) = state_with_summary.into_inner();
        *self.summary.lock() = summary;
        self.hot_state.set_commited(state);
    }
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L127-129)
```rust
    pub(crate) fn set_commited(&self, state: State) {
        *self.committed.lock() = state
    }
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L138-144)
```rust
    pub fn enqueue_commit(&self, to_commit: State) {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["hot_state_enqueue_commit"]);

        self.commit_tx
            .send(to_commit)
            .expect("Failed to queue for hot state commit.")
    }
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L173-178)
```rust
    fn spawn(base: Arc<HotStateBase>, committed: Arc<Mutex<State>>) -> SyncSender<State> {
        let (tx, rx) = std::sync::mpsc::sync_channel(MAX_HOT_STATE_COMMIT_BACKLOG);
        std::thread::spawn(move || Self::new(base, committed, rx).run());

        tx
    }
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L192-205)
```rust
    fn run(&mut self) {
        info!("HotState committer thread started.");

        while let Some(to_commit) = self.next_to_commit() {
            self.commit(&to_commit);
            *self.committed.lock() = to_commit;

            GAUGE.set_with(&["hot_state_items"], self.base.len() as i64);
            GAUGE.set_with(&["hot_state_key_bytes"], self.total_key_bytes as i64);
            GAUGE.set_with(&["hot_state_value_bytes"], self.total_value_bytes as i64);
        }

        info!("HotState committer quitting.");
    }
```

**File:** storage/aptosdb/src/state_store/buffered_state.rs (L67-67)
```rust
        out_persisted_state.hack_reset(last_snapshot.clone());
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1234-1234)
```rust
        self.persisted_state.hack_reset(last_checkpoint.clone());
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L275-276)
```rust
        // n.b. ideally this is set after the batches are committed
        state_store.set_state_ignoring_summary(ledger_state);
```
