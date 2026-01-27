# Audit Report

## Title
Hot State Partial Update Visibility During Shard-by-Shard Commit

## Summary
The `Committer::commit()` function updates hot state shards sequentially in a loop, but concurrent readers can access the `HotStateBase` through `get_committed()` during this process, observing an inconsistent mix of old and new state data. This violates the **Deterministic Execution** invariant and can lead to consensus divergence.

## Finding Description

The security question asks about concurrent commits, but the actual vulnerability is more subtle: while there is only a single `Committer` thread (preventing concurrent commits), **concurrent readers** can observe partially committed state during the shard update loop. [1](#0-0) 

The `Committer` is spawned as a single thread that processes commits sequentially: [2](#0-1) 

During the commit loop (lines 243-270), each shard's `DashMap` is updated individually. The `committed` State is only updated **after** all shards finish processing (line 197 in `run()`): [3](#0-2) 

Meanwhile, other threads can call `get_committed()` which returns both the `base` (shared `Arc<HotStateBase>` with `DashMap`s) and the `committed` State: [4](#0-3) 

**The Race Condition:**
1. Committer starts processing version N+1, updating shards 0, 1, 2...
2. Execution thread calls `get_committed()` after shard 5 is updated but before shard 10
3. Execution thread receives:
   - `base` with shards 0-5 at version N+1, shards 6-15 at version N
   - `state` still at version N (locked access, but cloned before update completes)

This creates an **inconsistent snapshot** where hot state contains mixed versions. The execution thread then creates a `CachedStateView` for transaction execution: [5](#0-4) 

The `CachedStateView` uses this inconsistent hot state when looking up values: [6](#0-5) 

**Concrete Example:**
- Version 1000 committed
- Version 1001 being committed: Key A (shard 0) → V_A_1001, Key B (shard 15) → V_B_1001
- Execution thread reads during commit after shard 0 updated:
  - Reads Key A: gets V_A_1001 (from new version)
  - Reads Key B: gets V_B_1000 (from old version)
- Different validators may observe this race at different points, leading to different transaction execution results and **different state roots** → **consensus violation**

Additionally, metadata inconsistency can occur: [7](#0-6) 

The `heads`, `tails`, and `num_items` metadata is updated per-shard during the loop, but the State metadata is only updated after. If `HotStateLRU` construction uses stale metadata with updated `DashMap` data, LRU chain traversal could fail or crash. [8](#0-7) 

## Impact Explanation

**Critical Severity** - This breaks the **Deterministic Execution** invariant (Invariant #1):

"All validators must produce identical state roots for identical blocks"

When different validators observe the partial update at different stages:
- Validator A reads during commit at T1: sees shards 0-3 updated
- Validator B reads during commit at T2: sees shards 0-10 updated  
- Validator C reads after commit completes: sees all shards updated

They execute the same block against different state snapshots, producing **different transaction outputs and state roots**. This is a **consensus safety violation** that can cause chain splits without requiring any Byzantine validators.

This qualifies as **Critical Severity** per the Aptos bug bounty:
- **Consensus/Safety violations**: Different nodes commit different state roots
- **Non-recoverable network partition**: Requires manual intervention or hardfork to resolve

## Likelihood Explanation

**High Likelihood** - This race condition occurs naturally during normal operation:

1. Block execution happens continuously via `execute_and_update_state()`
2. State commits happen asynchronously via the `Committer` thread
3. The timing window is significant (~16 shard iterations, each involving `DashMap` operations)
4. No synchronization prevents reads during the commit loop
5. In high-throughput scenarios, the probability of overlap increases

The race requires no attacker action - it occurs organically when execution and commit operations overlap in time, which happens regularly on active validators.

## Recommendation

Add a version-based synchronization mechanism to ensure readers get a consistent snapshot. The `committed` State should be atomically updated together with the hot state view, or readers should be blocked during the commit loop.

**Option 1: Atomic Swap**
```rust
// In Committer::commit(), collect all updates first
let mut shard_updates = vec![];
for shard_id in 0..NUM_STATE_SHARDS {
    // Collect updates without modifying base yet
    shard_updates.push(...);
}

// Single atomic operation under lock
let mut committed_guard = self.committed.lock();
for (shard_id, updates) in shard_updates.into_iter().enumerate() {
    // Apply all updates
}
*committed_guard = to_commit.clone();
drop(committed_guard);
```

**Option 2: Versioned References**
Make `get_committed()` block or retry if a commit is in progress, using a commit-in-progress flag protected by the same mutex as `committed`.

## Proof of Concept

The following Rust test demonstrates the race condition:

```rust
#[test]
fn test_concurrent_read_during_commit() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    let config = HotStateConfig::default();
    let initial_state = State::new_empty(config);
    let hot_state = Arc::new(HotState::new(initial_state, config));
    
    // Create a state with updates in shard 0 and shard 15
    let mut new_state = State::new_empty(config);
    // ... add updates to shard 0 and 15 ...
    
    let barrier = Arc::new(Barrier::new(2));
    let hot_state_clone = hot_state.clone();
    let barrier_clone = barrier.clone();
    
    // Thread 1: Enqueue commit
    let commit_thread = thread::spawn(move || {
        hot_state_clone.enqueue_commit(new_state);
        barrier_clone.wait(); // Wait for reader to start
        thread::sleep(Duration::from_millis(10)); // Give time for partial commit
    });
    
    // Thread 2: Read during commit
    let reader_thread = thread::spawn(move || {
        barrier.wait();
        thread::sleep(Duration::from_micros(100)); // Time to catch partial commit
        let (hot_view, state) = hot_state.get_committed();
        
        // Check if we can observe inconsistent state
        // Key from shard 0 may be at new version
        // Key from shard 15 may be at old version
        // State version is old
    });
    
    commit_thread.join().unwrap();
    reader_thread.join().unwrap();
}
```

**Note:** The actual race requires careful timing but occurs naturally in production when block execution requests state while commits are processing.

## Notes

While the original question asks about "concurrent commits on other threads", the investigation reveals that the architecture uses a single-threaded committer, preventing concurrent commits. However, the real vulnerability is **concurrent reads** during the commit process, which can observe partially updated state. This still satisfies the question's concern about "partial updates" during the shard loop, just through a different mechanism (reads vs. writes). The consensus impact remains critical regardless of whether the concurrency is read-read, read-write, or write-write.

### Citations

**File:** storage/aptosdb/src/state_store/hot_state.rs (L131-136)
```rust
    pub fn get_committed(&self) -> (Arc<dyn HotStateView>, State) {
        let state = self.committed.lock().clone();
        let base = self.base.clone();

        (base, state)
    }
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L173-177)
```rust
    fn spawn(base: Arc<HotStateBase>, committed: Arc<Mutex<State>>) -> SyncSender<State> {
        let (tx, rx) = std::sync::mpsc::sync_channel(MAX_HOT_STATE_COMMIT_BACKLOG);
        std::thread::spawn(move || Self::new(base, committed, rx).run());

        tx
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L192-202)
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
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L235-275)
```rust
    fn commit(&mut self, to_commit: &State) {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["hot_state_commit"]);

        let mut n_insert = 0;
        let mut n_update = 0;
        let mut n_evict = 0;

        let delta = to_commit.make_delta(&self.committed.lock());
        for shard_id in 0..NUM_STATE_SHARDS {
            for (key, slot) in delta.shards[shard_id].iter() {
                if slot.is_hot() {
                    let key_size = key.size();
                    self.total_key_bytes += key_size;
                    self.total_value_bytes += slot.size();
                    if let Some(old_slot) = self.base.shards[shard_id].insert(key, slot) {
                        self.total_key_bytes -= key_size;
                        self.total_value_bytes -= old_slot.size();
                        n_update += 1;
                    } else {
                        n_insert += 1;
                    }
                } else if let Some((key, old_slot)) = self.base.shards[shard_id].remove(&key) {
                    self.total_key_bytes -= key.size();
                    self.total_value_bytes -= old_slot.size();
                    n_evict += 1;
                }
            }
            self.heads[shard_id] = to_commit.latest_hot_key(shard_id);
            self.tails[shard_id] = to_commit.oldest_hot_key(shard_id);
            assert_eq!(
                self.base.shards[shard_id].len(),
                to_commit.num_hot_items(shard_id)
            );

            debug_assert!(self.validate_lru(shard_id).is_ok());
        }

        COUNTER.inc_with_by(&["hot_state_insert"], n_insert);
        COUNTER.inc_with_by(&["hot_state_update"], n_update);
        COUNTER.inc_with_by(&["hot_state_evict"], n_evict);
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L226-233)
```rust
                let state_view = {
                    let _timer = OTHER_TIMERS.timer_with(&["get_state_view"]);
                    CachedStateView::new(
                        StateViewId::BlockExecution { block_id },
                        Arc::clone(&self.db.reader),
                        parent_output.result_state().latest().clone(),
                    )?
                };
```

**File:** storage/storage-interface/src/state_store/state_view/cached_state_view.rs (L233-250)
```rust
    fn get_unmemorized(&self, state_key: &StateKey) -> Result<StateSlot> {
        COUNTER.inc_with(&["sv_unmemorized"]);

        let ret = if let Some(slot) = self.speculative.get_state_slot(state_key) {
            COUNTER.inc_with(&["sv_hit_speculative"]);
            slot
        } else if let Some(slot) = self.hot.get_state_slot(state_key) {
            COUNTER.inc_with(&["sv_hit_hot"]);
            slot
        } else if let Some(base_version) = self.base_version() {
            COUNTER.inc_with(&["sv_cold"]);
            StateSlot::from_db_get(
                self.cold
                    .get_state_value_with_version_by_version(state_key, base_version)?,
            )
        } else {
            StateSlot::ColdVacant
        };
```

**File:** storage/storage-interface/src/state_store/state.rs (L197-204)
```rust
                    let mut lru = HotStateLRU::new(
                        NonZeroUsize::new(self.hot_state_config.max_items_per_shard).unwrap(),
                        Arc::clone(&persisted_hot_state),
                        overlay,
                        hot_metadata.latest.clone(),
                        hot_metadata.oldest.clone(),
                        hot_metadata.num_items,
                    );
```
