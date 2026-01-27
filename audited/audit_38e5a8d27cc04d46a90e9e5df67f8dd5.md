# Audit Report

## Title
Hot State Race Condition Causing Non-Deterministic Execution in CachedStateView

## Summary
The `get_state_slot()` function in `CachedStateView` has a race condition where concurrent threads can observe different versions of the hot state during block execution, leading to non-deterministic execution results and potential consensus failures across validators.

## Finding Description

The vulnerability exists in the non-atomic read-check-insert pattern in `get_state_slot()` [1](#0-0) 

The critical issue is that the `hot` field in `CachedStateView` references a shared `HotStateBase` that is concurrently modified by a background `Committer` thread [2](#0-1) 

When `CachedStateView` is created, it obtains the hot state reference via `get_persisted_state()` [3](#0-2) , which returns an `Arc` to the `HotStateBase` [4](#0-3) 

This `HotStateBase` is actively modified by the asynchronous `Committer` thread during state commits [5](#0-4) 

**Race Condition Timeline:**

1. Block N+1 execution begins, creates `CachedStateView` with hot state at version V1
2. Thread A calls `get_state_slot(key)` → cache miss → calls `get_unmemorized(key)` [6](#0-5) 
3. Thread A checks hot state at line 239 → returns `None` (key not yet in hot state)
4. **Background Committer updates hot state**, inserting `(key, value_new)` [7](#0-6) 
5. Thread B calls `get_state_slot(key)` → cache miss → calls `get_unmemorized(key)`
6. Thread B checks hot state at line 239 → returns `Some(value_new)` (now in hot state)
7. Thread A fetches from cold storage at line 244 → gets `value_old`
8. Thread A inserts `value_old` into cache and returns it
9. Thread B attempts to insert `value_new` but cache already has `value_old` (first writer wins) [8](#0-7) 
10. Thread B returns `value_new` to its transaction

**Result:** Different threads executing transactions in the same block observe different base state values, violating deterministic execution.

## Impact Explanation

This breaks **Critical Invariant #1: Deterministic Execution** - "All validators must produce identical state roots for identical blocks."

When different validators execute the same block at different times relative to their hot state commit queues, they can observe different hot state snapshots. This leads to:

1. **Consensus Failures**: Validators compute different state roots for identical blocks, causing AptosBFT to fail reaching consensus
2. **Potential Chain Splits**: If some validators accept a block while others reject it due to mismatched state roots
3. **Non-Recoverable State**: Once validators diverge on state, recovery requires manual intervention or hard fork

This qualifies as **Critical Severity** under Aptos Bug Bounty criteria: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)."

## Likelihood Explanation

**Medium-High Likelihood** under normal operating conditions:

- The hot state Committer runs asynchronously with a backlog queue limit of 10 [9](#0-8) 
- During high transaction throughput, commits queue up and process asynchronously
- Block execution can start while previous commits are still being processed [10](#0-9) 
- No synchronization mechanism waits for hot state commits before execution
- Parallel execution with BlockSTM uses multiple threads concurrently accessing the same `CachedStateView` [11](#0-10) 

The vulnerability triggers naturally without requiring attacker action, making it a systemic timing bug rather than an exploitable attack vector.

## Recommendation

Add synchronization to ensure hot state commits complete before creating `CachedStateView`:

```rust
// In CachedStateView::new()
pub fn new(id: StateViewId, reader: Arc<dyn DbReader>, state: State) -> StateViewResult<Self> {
    let (hot_state, persisted_state) = reader.get_persisted_state()?;
    
    // Ensure hot state is synchronized with persisted state version
    // before using it in execution
    hot_state.wait_until_version(persisted_state.version())?;
    
    Ok(Self::new_impl(id, reader, hot_state, persisted_state, state))
}
```

Alternatively, take a **snapshot** of the hot state at `CachedStateView` creation time instead of sharing a live reference, ensuring all threads see a consistent view.

## Proof of Concept

This is a timing-dependent race condition that manifests under concurrent execution. A Rust test demonstrating the issue:

```rust
#[test]
fn test_hot_state_race_condition() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    // Setup: Create a CachedStateView with initial hot state
    let db = setup_test_db();
    let state_view = Arc::new(CachedStateView::new(
        StateViewId::Miscellaneous,
        db.clone(),
        initial_state,
    ).unwrap());
    
    let key = StateKey::access_path(test_access_path());
    let barrier = Arc::new(Barrier::new(3));
    
    // Thread 1: Read from state view (will see old value)
    let sv1 = state_view.clone();
    let b1 = barrier.clone();
    let h1 = thread::spawn(move || {
        b1.wait(); // Sync start
        sv1.get_state_slot(&key).unwrap()
    });
    
    // Thread 2: Simulate hot state update
    let hot_state = db.get_hot_state();
    let b2 = barrier.clone();
    let key2 = key.clone();
    let h2 = thread::spawn(move || {
        b2.wait(); // Sync start
        thread::sleep(Duration::from_micros(100)); // Slight delay
        // Simulate committer updating hot state
        hot_state.insert(key2, new_value);
    });
    
    // Thread 3: Read from state view (may see new value)
    let sv3 = state_view.clone();
    let b3 = barrier.clone();
    let h3 = thread::spawn(move || {
        b3.wait(); // Sync start
        thread::sleep(Duration::from_micros(200)); // Read after update
        sv3.get_state_slot(&key).unwrap()
    });
    
    let value1 = h1.join().unwrap();
    h2.join().unwrap();
    let value3 = h3.join().unwrap();
    
    // This assertion can fail due to the race condition
    assert_eq!(value1, value3, "Different threads saw different base state values!");
}
```

## Notes

While the race condition exists and violates deterministic execution invariants, the specific question asks whether "a malicious actor can exploit the gap to inject incorrect values." Strictly speaking, **external malicious actors cannot directly inject values** into the cache or modify the hot state. The vulnerability is a **timing bug** in the implementation that occurs naturally during concurrent execution, not an attack vector requiring malicious input.

The values always originate from trusted sources (hot state or cold storage), but the timing of hot state updates can cause non-determinism. This represents a critical implementation flaw that should be fixed, but does not constitute a direct "injection" attack by external actors.

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

**File:** storage/aptosdb/src/state_store/hot_state.rs (L27-27)
```rust
const MAX_HOT_STATE_COMMIT_BACKLOG: usize = 10;
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L107-112)
```rust
#[derive(Debug)]
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

**File:** storage/aptosdb/src/state_store/hot_state.rs (L235-250)
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

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L196-201)
```rust
        let state_view_arc = Arc::new(state_view);
        let transaction_outputs = Self::execute_block_sharded::<V>(
            transactions.clone(),
            state_view_arc.clone(),
            onchain_config,
        )?;
```
