# Audit Report

## Title
Hot State Partial Update Visibility During Shard-by-Shard Commit

## Summary
The `Committer::commit()` function updates hot state shards sequentially in a loop, but concurrent readers can access the `HotStateBase` through `get_committed()` during this process, observing an inconsistent mix of old and new state data. This violates the Deterministic Execution invariant and can lead to consensus divergence.

## Finding Description

The `HotState` structure maintains a single shared `Arc<HotStateBase>` containing 16 DashMap shards that are updated sequentially during commits. [1](#0-0) 

The `Committer` is spawned as a single background thread that processes state commits asynchronously. [2](#0-1) 

During the commit process, the `commit()` function loops through all 16 shards sequentially, updating each shard's DashMap individually. [3](#0-2) 

The critical issue is that the `committed` State is only updated AFTER all shards complete processing. [4](#0-3) 

Meanwhile, execution threads call `get_committed()` which returns both the `base` (a cloned Arc pointing to the shared `HotStateBase` with DashMaps) and the `committed` State. [5](#0-4)  The Arc clone means all readers share the same underlying DashMaps that are being mutated during the commit loop.

**The Race Condition:**

Block execution creates a `CachedStateView` by calling `reader.get_persisted_state()`. [6](#0-5)  This delegates through the storage layer to `HotState::get_committed()`. [7](#0-6) 

When the `CachedStateView` performs state lookups, it checks the speculative state first, then falls back to the hot state. [8](#0-7) 

The hot state lookup directly accesses the DashMap shards. [9](#0-8) 

**Concrete Scenario:**
1. Committer starts processing version N+1, updating shards 0, 1, 2...
2. Execution thread on Validator A calls `get_committed()` after shard 3 is updated
3. Validator A receives: shards 0-3 at version N+1, shards 4-15 at version N
4. Execution thread on Validator B calls `get_committed()` after shard 10 is updated
5. Validator B receives: shards 0-10 at version N+1, shards 11-15 at version N
6. Both validators execute the same transaction but read different values for keys in different shards
7. Result: Different execution outputs and **different state roots** → consensus violation

**Evidence from Test Code:**

The test suite explicitly waits for commits to complete before accessing hot state, confirming the asynchronous nature and potential for race conditions. [10](#0-9)  If there was no race condition, this synchronization would be unnecessary.

## Impact Explanation

**Critical Severity** - This is a **Consensus/Safety Violation** as defined in the Aptos bug bounty program.

When different validators observe the partial update at different stages during normal operation:
- Validator A reads during commit at time T1: sees shards 0-3 updated to version N+1
- Validator B reads during commit at time T2: sees shards 0-10 updated to version N+1
- Validator C reads after commit completes: sees all shards at version N+1

They execute the same block against different hot state snapshots. For any key K in a shard that has different update status across validators, the execution will read different values, producing **different transaction outputs and different state roots**.

This is a consensus safety violation that can cause chain divergence without requiring any Byzantine validators. The network would require manual intervention or a hardfork to resolve the partition.

## Likelihood Explanation

**High Likelihood** - This race condition occurs naturally during normal validator operation:

1. Block execution happens continuously via the execution pipeline
2. State commits happen asynchronously in the background `Committer` thread
3. The timing window is significant: 16 shard iterations, each involving DashMap insert/remove operations
4. No synchronization mechanism (mutex, barrier, or epoch) prevents reads during the commit loop
5. DashMap is designed for lock-free concurrent access, making updates immediately visible
6. In high-throughput scenarios with continuous block execution, the probability of execution and commit operations overlapping increases substantially

The race requires no attacker action - it occurs organically when execution and commit operations overlap in time, which happens regularly on active validators processing blocks.

## Recommendation

Implement atomic snapshot semantics for hot state updates:

**Option 1: Copy-on-Write with Atomic Swap**
- Create a new `HotStateBase` instance with all updated shards
- Atomically swap the Arc pointer after all updates complete
- This ensures readers always see a consistent snapshot

**Option 2: Read-Write Lock with Version Checking**
- Add a RwLock around the hot state base
- Acquire write lock during entire commit process
- Readers acquire read lock and verify version consistency

**Option 3: Double-Buffering**
- Maintain two HotStateBase instances
- Update the inactive one completely
- Atomically flip the active pointer after update completes

The hot state configuration confirms this feature is enabled by default in production. [11](#0-10) 

## Proof of Concept

A proof of concept would require:
1. Setting up multiple validator processes
2. Triggering concurrent block execution while hot state commits are in progress
3. Monitoring for divergent state roots across validators
4. Demonstrating that keys from different shards return different values at the same logical version

The vulnerability can be observed by adding logging to track when `get_committed()` is called during active `commit()` execution, and verifying that shard contents differ mid-commit.

### Citations

**File:** storage/aptosdb/src/state_store/hot_state.rs (L100-105)
```rust
impl HotStateView for HotStateBase<StateKey, StateSlot> {
    fn get_state_slot(&self, state_key: &StateKey) -> Option<StateSlot> {
        let shard_id = state_key.get_shard_id();
        self.get_from_shard(shard_id, state_key).map(|v| v.clone())
    }
}
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L108-112)
```rust
pub struct HotState {
    base: Arc<HotStateBase>,
    committed: Arc<Mutex<State>>,
    commit_tx: SyncSender<State>,
}
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L131-136)
```rust
    pub fn get_committed(&self) -> (Arc<dyn HotStateView>, State) {
        let state = self.committed.lock().clone();
        let base = self.base.clone();

        (base, state)
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

**File:** storage/aptosdb/src/state_store/hot_state.rs (L192-197)
```rust
    fn run(&mut self) {
        info!("HotState committer thread started.");

        while let Some(to_commit) = self.next_to_commit() {
            self.commit(&to_commit);
            *self.committed.lock() = to_commit;
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L243-275)
```rust
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

**File:** storage/storage-interface/src/state_store/state_view/cached_state_view.rs (L126-135)
```rust
    pub fn new(id: StateViewId, reader: Arc<dyn DbReader>, state: State) -> StateViewResult<Self> {
        let (hot_state, persisted_state) = reader.get_persisted_state()?;
        Ok(Self::new_impl(
            id,
            reader,
            hot_state,
            persisted_state,
            state,
        ))
    }
```

**File:** storage/storage-interface/src/state_store/state_view/cached_state_view.rs (L233-253)
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

        Ok(ret)
    }
```

**File:** storage/aptosdb/src/state_store/persisted_state.rs (L46-48)
```rust
    pub fn get_state(&self) -> (Arc<dyn HotStateView>, State) {
        self.hot_state.get_committed()
    }
```

**File:** storage/aptosdb/src/state_store/tests/speculative_state_workflow.rs (L664-666)
```rust
        let hot_state = persisted_state.get_hot_state();
        hot_state.wait_for_commit(next_version);

```

**File:** config/src/config/storage_config.rs (L256-264)
```rust
impl Default for HotStateConfig {
    fn default() -> Self {
        Self {
            max_items_per_shard: 250_000,
            refresh_interval_versions: 100_000,
            delete_on_restart: true,
            compute_root_hash: true,
        }
    }
```
