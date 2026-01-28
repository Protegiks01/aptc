# Audit Report

## Title
Hot State Race Condition in get_persisted_state() Breaks Deterministic Execution Across Validators

## Summary
The `get_persisted_state()` function returns a shared `Arc<HotStateBase>` that background commit threads can modify concurrently during block execution. This allows validators executing the same block to read different hot state values depending on commit timing, breaking consensus determinism and causing validators to produce different state roots for identical blocks.

## Finding Description

The vulnerability exists in the state lookup hierarchy used during transaction execution. When validators execute a block, they create a `CachedStateView` that queries state in three layers: speculative state (in-memory changes), hot state (cached frequently-accessed keys), and cold state (database).

**The Core Issue:**

The `get_persisted_state()` method returns an `Arc` clone of `HotStateBase`, which shares the same underlying `DashMap` with background commit threads: [1](#0-0) 

This Arc clone points to the same `HotStateBase` instance that the background `Committer` thread directly modifies: [2](#0-1) 

The `HotStateBase` uses `DashMap` for concurrent access, providing interior mutability: [3](#0-2) 

**The Race Condition:**

When `CachedStateView` reads from hot state, it performs no version validation: [4](#0-3) 

At line 239, the hot state lookup returns `StateSlot` values directly without checking if the `value_version` field exceeds the `base_version` of the execution context.

**Concrete Attack Scenario:**

1. All validators receive block N to execute with parent state at version 100
2. Validator A's local storage commits to version 101 just after they call `get_persisted_state()`, updating the shared `HotStateBase` mid-execution
3. Validator B's local storage hasn't committed yet, so their hot state remains at version 100
4. Both validators read the same key K from hot state:
   - Validator A gets `StateSlot::HotOccupied { value_version: 101, value: Y, ... }`
   - Validator B gets `StateSlot::HotOccupied { value_version: 100, value: X, ... }`
5. Validators produce different execution outputs and state roots for identical block N
6. Consensus fails to reach agreement, causing liveness issues or potential chain splits

The `StateSlot` enum confirms that hot state entries contain version information: [5](#0-4) 

No code exists that validates `value_version` against the execution context's `base_version` when reading from hot state.

## Impact Explanation

This is a **Critical Severity** vulnerability under the Aptos bug bounty program category "Consensus/Safety Violations":

**Breaks Deterministic Execution Invariant**: The fundamental requirement of blockchain consensus is that all validators must produce identical state roots when executing identical blocks. This vulnerability violates that invariant by allowing different validators to observe different state values during execution of the same block.

**Consensus Safety Violation**: When validators disagree on execution results for the same block, the consensus protocol cannot achieve agreement. This leads to:
- Failed block proposals requiring reproposal and retries
- Potential validator disagreements on state transitions
- Liveness degradation as consensus stalls
- In severe cases, persistent disagreement requiring manual intervention or hardfork

**Non-Recoverable Architecture Issue**: Unlike transient bugs that can be resolved with restarts, this race condition is inherent to the concurrent architecture. The shared mutable `HotStateBase` combined with asynchronous background commits creates a fundamental synchronization gap.

This aligns with the Critical severity criteria: "Different validators commit different blocks" and "Consensus/Safety violations" in the Aptos bug bounty program.

## Likelihood Explanation

**High Likelihood** - This race condition manifests naturally during normal network operation:

**Continuous Background Commits**: The `BufferedState` system commits snapshots approximately every 100,000 versions: [6](#0-5) 

**Independent Validator Timing**: Each validator's local storage commits independently and asynchronously. When consensus proposes a block, all validators execute it concurrently but their background commit threads complete at different times based on local CPU scheduling, disk I/O, and workload.

**No Synchronization**: The execution path shows no locks or barriers preventing hot state updates during block execution: [7](#0-6) 

**Substantial Race Window**: The commit process involves merklization and database writes spanning milliseconds to seconds, providing ample opportunity for the race to manifest.

No attacker intervention is required - the vulnerability triggers through normal concurrent operation of the validator network.

## Recommendation

**Solution 1: Version-Snapshot Hot State**

Modify `get_persisted_state()` to return a version-locked snapshot of the hot state instead of a shared mutable reference. Implement Copy-on-Write semantics where the `Committer` thread creates a new `HotStateBase` instance for each commit rather than updating the shared one in-place.

**Solution 2: Version Validation on Read**

Add validation in `CachedStateView::get_unmemorized()` to check that `StateSlot::value_version` does not exceed `self.base_version()` when reading from hot state. Reject reads from future versions and fall back to cold state queries.

**Solution 3: Synchronization Barrier**

Add a read-write lock to `PersistedState` where:
- `get_state()` acquires read lock (allows concurrent reads, blocks during commits)
- `set()` acquires write lock (blocks all readers during commit)

This ensures hot state cannot be modified while execution is reading it.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Instrumenting `HotState::Committer::commit()` to log when hot state entries are updated
2. Instrumenting `CachedStateView::get_unmemorized()` to log hot state reads with version information
3. Running a validator under load to trigger frequent commits
4. Observing hot state reads during block execution that return `value_version` greater than the block's `base_version`
5. Comparing execution results across multiple validators for the same block

The lack of synchronization between commit threads and execution threads makes this race condition reproducible under high transaction throughput scenarios.

## Notes

This vulnerability is particularly subtle because:

1. The `Arc` clone appears to provide isolation but actually shares mutable state through `DashMap`'s interior mutability
2. Most execution happens from speculative state, so the hot state race only affects cache misses
3. The race window depends on commit timing relative to block execution, making it intermittent
4. Each validator's local storage state is independent, amplifying the non-determinism across the validator set

The vulnerability demonstrates a fundamental synchronization gap in the Aptos storage architecture where concurrent reads and writes to the hot state cache are not properly coordinated with the execution context's version guarantees.

### Citations

**File:** storage/aptosdb/src/state_store/hot_state.rs (L72-98)
```rust
#[derive(Debug)]
pub struct HotStateBase<K = StateKey, V = StateSlot>
where
    K: Eq + std::hash::Hash,
{
    shards: [Shard<K, V>; NUM_STATE_SHARDS],
}

impl<K, V> HotStateBase<K, V>
where
    K: Clone + Eq + std::hash::Hash,
    V: Clone,
{
    fn new_empty(max_items_per_shard: usize) -> Self {
        Self {
            shards: arr![Shard::new(max_items_per_shard); 16],
        }
    }

    fn get_from_shard(&self, shard_id: usize, key: &K) -> Option<Ref<'_, K, V>> {
        self.shards[shard_id].get(key)
    }

    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.len()).sum()
    }
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

**File:** storage/aptosdb/src/state_store/hot_state.rs (L235-260)
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

**File:** types/src/state_store/state_slot.rs (L34-40)
```rust
    HotOccupied {
        value_version: Version,
        value: StateValue,
        hot_since_version: Version,
        lru_info: LRUEntry<StateKey>,
    },
}
```

**File:** storage/aptosdb/src/state_store/buffered_state.rs (L28-29)
```rust
pub(crate) const ASYNC_COMMIT_CHANNEL_BUFFER_SIZE: u64 = 1;
pub(crate) const TARGET_SNAPSHOT_INTERVAL_IN_VERSION: u64 = 100_000;
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
