# Audit Report

## Title
Consensus Divergence via Asynchronous Hot State Commit Race Condition

## Summary
A race condition exists in the hot state commit mechanism where the background `Committer` thread updates the `HotStateBase` cache before updating the `committed` state reference. This allows different validators to observe inconsistent state snapshots during block execution, leading to non-deterministic execution and consensus divergence.

## Finding Description

The vulnerability stems from non-atomic state access in the hot state management system. When `HotState::get_committed()` is invoked, it performs two separate operations without atomicity guarantees: [1](#0-0) 

Meanwhile, the background `Committer` thread updates state in a specific sequence within its `run()` method: [2](#0-1) 

The `commit()` method called at line 196 updates the `HotStateBase` shards with new state data: [3](#0-2) 

**The Race Condition Window:**

When a block N commits, `PersistedState::set()` is invoked: [4](#0-3) 

The summary is updated synchronously (line 59), but the hot state commit is queued asynchronously (line 61). If block N+1 execution begins before the Committer completes line 197, the race occurs.

Block execution creates a `CachedStateView`: [5](#0-4) 

This calls `get_persisted_state()` which returns potentially inconsistent state:
- `committed` State at version N-1 (if Committer hasn't reached line 197)
- `base` HotStateBase with version N data (if Committer has completed line 196)

During transaction execution, state reads occur through the `CachedStateView`: [6](#0-5) 

When hot state returns a value (lines 239-241), it's extracted without version validation. The `StateSlot` contains a `value_version` field indicating when the value was last modified, but this is not validated: [7](#0-6) [8](#0-7) 

The `into_state_value_opt()` method extracts only the value, completely ignoring the `value_version` field. This means execution can read version N data from hot state while the base_version (from `committed` state) indicates version N-1, creating an inconsistent view.

**Critical Point:** The `execution_lock` in BlockExecutor only serializes block execution but does NOT synchronize with the background Committer thread: [9](#0-8) 

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos bug bounty program's "Consensus/Safety Violations" category:

1. **Consensus Divergence**: Different validators with different timing will observe different state snapshots (mixed version N-1 and N data), leading to different execution results and different state roots for identical blocks. This breaks the fundamental consensus safety guarantee that all honest validators must agree on state.

2. **Chain Halt Risk**: If validators cannot achieve 2f+1 agreement on state roots due to inconsistent execution results, the chain cannot progress beyond that block, causing network-wide liveness failure.

3. **Potential Network Partition**: In severe cases, validator sets could diverge into incompatible states, requiring hard fork intervention to resolve.

The impact is system-wide and affects the core consensus mechanism, not just individual transactions or accounts.

## Likelihood Explanation

**High Likelihood** - This race condition occurs naturally during normal network operation:

1. **Automatic Triggering**: Every block commit triggers the asynchronous hot state update mechanism, creating a race window with the next block's execution.

2. **Timing Variability**: Different validators operate on different hardware with varying CPU loads, network latency, and scheduling behavior. These natural variations create different timing relationships between the Committer thread and execution thread across validators.

3. **No Synchronization**: The execution lock prevents concurrent block execution but provides no coordination with the background Committer thread, which runs independently.

4. **Observable Partial State**: The `HotStateBase` uses `DashMap` for thread-safe concurrent access, but this allows reads to observe partial update states when the Committer is actively modifying entries.

The vulnerability is latent and may manifest intermittently based on system load and timing, making it particularly dangerous as it could go undetected in testing but cause consensus failures in production.

## Recommendation

Implement atomic state access by ensuring `get_committed()` returns a consistent snapshot. One approach:

1. Protect both `base` and `committed` updates under the same lock in the Committer's `run()` method
2. Use the same lock in `get_committed()` to ensure atomic reads
3. Alternatively, use sequence numbers or versioning to validate that hot state entries match the expected base_version

Example fix for `HotState::get_committed()`:
```rust
pub fn get_committed(&self) -> (Arc<dyn HotStateView>, State) {
    let committed_lock = self.committed.lock();
    let state = committed_lock.clone();
    let base = self.base.clone();
    drop(committed_lock);
    
    // Verify base version matches committed state
    // or use a versioned snapshot mechanism
    
    (base, state)
}
```

Additionally, add version validation when consuming hot state values to detect and handle version mismatches.

## Proof of Concept

A complete PoC would require a multi-validator test environment with precise timing control. The key elements to demonstrate:

1. Start multiple validator nodes processing the same blocks
2. Introduce variable delays in the Committer thread (via sleep or CPU load)
3. Execute blocks rapidly to create race conditions
4. Monitor state roots produced by different validators
5. Observe divergence when validators experience different Committer timing

The vulnerability can be reproduced by adding instrumentation to log when `get_committed()` is called relative to Committer updates, demonstrating that execution can observe partial update states.

**Notes**

This vulnerability represents a fundamental synchronization flaw in the hot state caching mechanism. While hot state is designed for performance optimization, the lack of proper synchronization between the async Committer thread and block execution creates a consensus safety violation. The issue is particularly insidious because it may not manifest consistently—different network conditions, hardware configurations, and load patterns will cause different validators to experience the race at different frequencies, leading to intermittent consensus failures that are difficult to diagnose.

### Citations

**File:** storage/aptosdb/src/state_store/hot_state.rs (L131-136)
```rust
    pub fn get_committed(&self) -> (Arc<dyn HotStateView>, State) {
        let state = self.committed.lock().clone();
        let base = self.base.clone();

        (base, state)
    }
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

**File:** execution/executor/src/block_executor/mod.rs (L97-113)
```rust
    fn execute_and_update_state(
        &self,
        block: ExecutableBlock,
        parent_block_id: HashValue,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> ExecutorResult<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "execute_and_state_checkpoint"]);

        self.maybe_initialize()?;
        // guarantee only one block being executed at a time
        let _guard = self.execution_lock.lock();
        self.inner
            .read()
            .as_ref()
            .expect("BlockExecutor is not reset")
            .execute_and_update_state(block, parent_block_id, onchain_config)
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

**File:** types/src/state_store/mod.rs (L64-69)
```rust
    /// Gets the state value for a given state key.
    fn get_state_value(&self, state_key: &Self::Key) -> StateViewResult<Option<StateValue>> {
        // if not implemented, delegate to get_state_slot.
        self.get_state_slot(state_key)
            .map(StateSlot::into_state_value_opt)
    }
```

**File:** types/src/state_store/state_slot.rs (L121-126)
```rust
    pub fn into_state_value_opt(self) -> Option<StateValue> {
        match self {
            ColdVacant | HotVacant { .. } => None,
            ColdOccupied { value, .. } | HotOccupied { value, .. } => Some(value),
        }
    }
```
