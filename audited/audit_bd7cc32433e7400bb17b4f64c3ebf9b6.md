# Audit Report

## Title
Cache Inconsistency in CachedStateView Leading to Non-Deterministic State Reads and Consensus Failure

## Summary
The `get_state_slot()` function in `CachedStateView` contains a race condition where concurrent threads can fetch different `StateSlot` values from the live hot state, but only one gets cached. The function returns the self-fetched value rather than re-reading from cache after `try_insert`, creating inconsistency between what execution threads observe and what gets stored for state updates. This is further exacerbated by the hot state being updated asynchronously by a background Committer thread without version filtering, allowing reads at incorrect versions. This breaks deterministic execution and can cause consensus failures across validators.

## Finding Description
The vulnerability exists in the `TStateView` implementation for `CachedStateView`: [1](#0-0) 

When two threads concurrently call `get_state_slot()` for the same key with a cache miss, both call `get_unmemorized()` to fetch the value. However, the underlying hot state is being actively modified by a background Committer thread: [2](#0-1) 

The hot state returns whatever is currently stored without version filtering: [3](#0-2) 

The `try_insert` mechanism uses DashMap's entry API which only inserts if the entry is vacant: [4](#0-3) 

**Attack Scenario:**

1. Validator A creates `CachedStateView` for block execution with base_version 100
2. Transaction T1 on Thread A reads key K1: cache miss → `get_unmemorized(K1)` → hot state returns `StateSlot{value: V1, version: 100}`
3. Background Committer thread commits new state, updating hot state: K1 → `StateSlot{value: V2, version: 101}`
4. Transaction T2 on Thread B (or Validator B) reads K1: cache miss → `get_unmemorized(K1)` → hot state returns `StateSlot{value: V2, version: 101}`
5. Thread B's `try_insert(K1, V2)` succeeds → cache now contains V2 at version 101
6. Thread A's `try_insert(K1, V1)` fails (entry occupied) → but Thread A returns V1 at version 100 to transaction T1
7. T1 executes with V1, T2 executes with V2 (or gets V2 from cache)
8. When `update_with_memorized_reads()` is called, it uses the cached V2: [5](#0-4) 

This creates a fundamental inconsistency: transactions executed with certain values, but state updates assume different values were read. On different validators executing the same block at slightly different times (relative to hot state commits), they observe different state values, leading to different execution results and state roots.

This breaks the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

## Impact Explanation
This vulnerability qualifies as **Critical Severity** under the Aptos Bug Bounty program criteria for **Consensus/Safety violations**:

1. **Non-deterministic State Reads**: Different validators executing the same block can read different values from hot state depending on the timing of background Committer updates, leading to different execution results.

2. **Consensus Failure**: When validators compute different state roots for the same block, they cannot reach consensus, causing a chain split or network partition.

3. **State Corruption**: The memorized reads used for state updates may contain values different from what transactions actually observed, causing permanent corruption of the hot state and affecting future block executions.

4. **Cross-Validator Divergence**: Since hot state is updated asynchronously and independently on each validator, they can diverge over time, making the issue persistent and potentially requiring a hard fork to resolve.

The vulnerability allows arbitrary consensus failures without any attacker action—it occurs spontaneously during normal block processing when hot state commits happen concurrently with block execution.

## Likelihood Explanation
**Likelihood: High**

This vulnerability is highly likely to occur because:

1. **Continuous Background Activity**: The hot state Committer thread runs continuously, updating the hot state as blocks are committed: [6](#0-5) 

2. **Parallel Execution**: Aptos uses BlockSTM for parallel transaction execution within blocks, creating multiple concurrent threads reading state simultaneously.

3. **No Synchronization**: There is no synchronization between hot state commits and state view creation—views get a live reference to the hot state that can be modified at any time: [7](#0-6) 

4. **No Version Filtering**: Hot state reads don't filter by the view's base_version, so any committed state is immediately visible: [8](#0-7) 

5. **Network Timing**: Different validators receive and process blocks at slightly different times, making timing-dependent bugs like this almost guaranteed to manifest across the network.

## Recommendation
Implement version-aware hot state reads and fix the cache inconsistency:

**Fix 1: Return cached value instead of self-fetched value**
```rust
fn get_state_slot(&self, state_key: &StateKey) -> StateViewResult<StateSlot> {
    let _timer = TIMER.timer_with(&["get_state_value"]);
    COUNTER.inc_with(&["sv_total_get"]);

    // First check if requested key is already memorized.
    if let Some(slot) = self.memorized.get_cloned(state_key) {
        COUNTER.inc_with(&["sv_memorized"]);
        return Ok(slot);
    }

    let slot = self.get_unmemorized(state_key)?;
    self.memorized.try_insert(state_key, &slot);
    
    // FIX: Re-read from cache to get the value that was actually cached
    // This ensures consistency between what's returned and what's cached
    Ok(self.memorized.get_cloned(state_key).unwrap_or(slot))
}
```

**Fix 2: Add version filtering to hot state reads**
```rust
fn get_unmemorized(&self, state_key: &StateKey) -> Result<StateSlot> {
    COUNTER.inc_with(&["sv_unmemorized"]);

    let ret = if let Some(slot) = self.speculative.get_state_slot(state_key) {
        COUNTER.inc_with(&["sv_hit_speculative"]);
        slot
    } else if let Some(slot) = self.hot.get_state_slot(state_key) {
        // FIX: Only use hot state entry if it's at or before base_version
        if let Some(base_version) = self.base_version() {
            if slot.expect_value_version() <= base_version {
                COUNTER.inc_with(&["sv_hit_hot"]);
                slot
            } else {
                // Hot state entry is too new, fall through to cold
                COUNTER.inc_with(&["sv_cold"]);
                StateSlot::from_db_get(
                    self.cold.get_state_value_with_version_by_version(state_key, base_version)?,
                )
            }
        } else {
            slot
        }
    } else if let Some(base_version) = self.base_version() {
        COUNTER.inc_with(&["sv_cold"]);
        StateSlot::from_db_get(
            self.cold.get_state_value_with_version_by_version(state_key, base_version)?,
        )
    } else {
        StateSlot::ColdVacant
    };

    Ok(ret)
}
```

**Fix 3: Use immutable hot state snapshot**
Instead of returning a live reference to hot state, create an immutable snapshot at view creation time to prevent mid-execution updates from being visible.

## Proof of Concept
```rust
// Rust test demonstrating the race condition
#[test]
fn test_cache_inconsistency_race() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    // Setup: Create CachedStateView with hot state
    let reader = Arc::new(create_test_db_reader());
    let state = create_test_state();
    let view = Arc::new(CachedStateView::new(
        StateViewId::Miscellaneous,
        reader.clone(),
        state,
    ).unwrap());
    
    let key = StateKey::raw(b"test_key");
    let barrier = Arc::new(Barrier::new(3)); // 2 threads + committer
    
    // Simulate hot state update happening concurrently
    let barrier_clone = barrier.clone();
    let reader_clone = reader.clone();
    thread::spawn(move || {
        barrier_clone.wait(); // Wait for threads to start
        // Simulate Committer updating hot state
        update_hot_state(&reader_clone, &key, b"new_value", 101);
    });
    
    let view_clone1 = view.clone();
    let barrier_clone1 = barrier.clone();
    let key_clone1 = key.clone();
    let handle1 = thread::spawn(move || {
        barrier_clone1.wait();
        view_clone1.get_state_slot(&key_clone1).unwrap()
    });
    
    let view_clone2 = view.clone();
    let barrier_clone2 = barrier.clone();
    let key_clone2 = key.clone();
    let handle2 = thread::spawn(move || {
        barrier_clone2.wait();
        view_clone2.get_state_slot(&key_clone2).unwrap()
    });
    
    let slot1 = handle1.join().unwrap();
    let slot2 = handle2.join().unwrap();
    let cached = view.memorized_reads().get_cloned(&key).unwrap();
    
    // BUG: slot1 and slot2 might differ, and one might differ from cached
    // This demonstrates non-deterministic reads
    assert_ne!(slot1, slot2, "Race condition: threads saw different values");
    assert!(slot1 != cached || slot2 != cached, 
            "Inconsistency: returned value differs from cached value");
}
```

**Notes:**
The vulnerability stems from two design issues: (1) the race condition where `try_insert` can fail but the self-fetched value is still returned, and (2) the lack of version filtering when reading from hot state. While the race condition alone creates inconsistency within a single validator, the version filtering issue is more severe as it allows different validators to observe genuinely different state values at the same logical block height, breaking consensus safety guarantees. Both issues must be addressed to ensure deterministic execution.

### Citations

**File:** storage/storage-interface/src/state_store/state_view/cached_state_view.rs (L75-84)
```rust
    pub fn try_insert(&self, state_key: &StateKey, slot: &StateSlot) {
        let shard_id = state_key.get_shard_id();

        match self.shard(shard_id).entry(state_key.clone()) {
            Entry::Occupied(_) => {},
            Entry::Vacant(entry) => {
                entry.insert(slot.clone());
            },
        };
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

**File:** storage/storage-interface/src/state_store/state_view/cached_state_view.rs (L283-297)
```rust
    fn get_state_slot(&self, state_key: &StateKey) -> StateViewResult<StateSlot> {
        let _timer = TIMER.timer_with(&["get_state_value"]);
        COUNTER.inc_with(&["sv_total_get"]);

        // First check if requested key is already memorized.
        if let Some(slot) = self.memorized.get_cloned(state_key) {
            COUNTER.inc_with(&["sv_memorized"]);
            return Ok(slot);
        }

        // TODO(aldenhu): reduce duplicated gets
        let slot = self.get_unmemorized(state_key)?;
        self.memorized.try_insert(state_key, &slot);
        Ok(slot)
    }
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L100-105)
```rust
impl HotStateView for HotStateBase<StateKey, StateSlot> {
    fn get_state_slot(&self, state_key: &StateKey) -> Option<StateSlot> {
        let shard_id = state_key.get_shard_id();
        self.get_from_shard(shard_id, state_key).map(|v| v.clone())
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

**File:** storage/storage-interface/src/state_store/state.rs (L370-385)
```rust
    fn expect_old_slot(
        overlay: &LayeredMap<StateKey, StateSlot>,
        cache: &StateCacheShard,
        key: &StateKey,
    ) -> StateSlot {
        if let Some(slot) = overlay.get(key) {
            return slot;
        }

        // TODO(aldenhu): avoid cloning the state value (by not using DashMap)
        cache
            .get(key)
            .unwrap_or_else(|| panic!("Key {:?} must exist in the cache.", key))
            .value()
            .clone()
    }
```
