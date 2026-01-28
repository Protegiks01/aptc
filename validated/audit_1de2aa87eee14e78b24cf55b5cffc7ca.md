# Audit Report

## Title
Race Condition in Hot State Commit Causes Validator Node Panics via expect_hot_slot()

## Summary
A race condition exists in the `HotState` asynchronous commit mechanism where the base hot state data and the committed state metadata can become temporarily inconsistent. This inconsistency causes `HotStateLRU::expect_hot_slot()` to panic when metadata points to keys that were evicted or converted to cold slots, resulting in validator node crashes during normal operation.

## Finding Description

The vulnerability stems from a race condition in the `HotState` commit process where two updates occur non-atomically in the `Committer::run()` method: [1](#0-0) 

**Line 196** calls `self.commit(&to_commit)` which updates `self.base` (the shared `DashMap` containing actual hot state data) by inserting/removing entries: [2](#0-1) 

**Line 197** then updates `self.committed` with the new state metadata (head, tail, num_items).

**The Critical Race Window:** Between these two non-atomic updates, another thread can call `get_committed()`: [3](#0-2) 

This method returns an `Arc` to `self.base` (which is already updated with new data) alongside `self.committed` (which still contains old metadata). Since `self.base` is a shared `Arc<HotStateBase>` pointing to the same underlying `DashMap` instances, any modifications by the Committer thread are immediately visible to all threads holding references to it. [4](#0-3) 

When the inconsistent state is used to create a `HotStateLRU` in the execution pipeline: [5](#0-4) 

The LRU is initialized with metadata (head, tail, num_items) that references keys which either no longer exist in the base (were evicted) or exist but are now cold slots (were converted from hot to cold).

Later, when `HotStateLRU` operations access these keys, `expect_hot_slot()` panics: [6](#0-5) 

**Panic Locations:**

1. When inserting as head and accessing the old head pointer: [7](#0-6) 

2. When deleting entries and accessing prev/next pointers: [8](#0-7) 

**Execution Path:** The vulnerability is triggered during normal transaction execution when `CachedStateView::new()` calls `reader.get_persisted_state()`: [9](#0-8) 

This flows through to `HotState::get_committed()` via the `StateStore::get_persisted_state()` and `PersistedState::get_state()` chain: [10](#0-9) 

This breaks the **liveness invariant** - validators must remain operational to participate in consensus.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty criteria)

This vulnerability causes **validator node crashes** and qualifies as **API crashes** under the Aptos Bug Bounty High severity category. The concrete impact includes:

- Validator nodes panic unexpectedly during normal operation (no malicious input required)
- Loss of liveness for affected validators
- Downtime while nodes restart and resync
- Potential consensus disruption if multiple validators are affected simultaneously

The vulnerability does not reach Critical severity because it does not compromise consensus safety (no double-spending or chain splits), does not cause permanent damage (nodes can restart), and does not lead to fund theft or unauthorized minting. However, it significantly affects network availability and validator participation.

## Likelihood Explanation

**Likelihood: Medium-High**

This issue is likely to occur in production because:

1. **Normal Operation Trigger**: The race condition is triggered during routine hot state commits when processing transaction execution, not by malicious input. The asynchronous Committer thread runs continuously: [11](#0-10) 

2. **Concurrent Access Pattern**: The `get_persisted_state()` function is called frequently during state updates in the execution pipeline through `CachedStateView::new()`, creating many opportunities for the race condition to occur.

3. **Asynchronous Design**: The commit mechanism uses a separate thread with a backlog queue, increasing the probability of timing windows. Commits are enqueued asynchronously: [12](#0-11) 

4. **High Transaction Volume**: During periods of high transaction throughput, hot state updates occur more frequently, expanding the race window between the base update and metadata update.

The issue may have gone unnoticed due to the intermittent nature of race conditions and the hot state feature being relatively new with incomplete implementation (evidenced by TODO comments throughout the codebase).

## Recommendation

**Solution: Atomic Update of Base and Metadata**

The fix should ensure that `self.base` and `self.committed` are updated atomically from the perspective of `get_committed()`. This can be achieved by:

1. **Option A - Single Lock**: Place both `self.base` and `self.committed` under a single `RwLock`, ensuring reads see consistent state:

```rust
pub struct HotState {
    state: Arc<RwLock<HotStateInner>>,
    commit_tx: SyncSender<State>,
}

struct HotStateInner {
    base: Arc<HotStateBase>,
    committed: State,
}
```

2. **Option B - Copy-on-Write**: Update `self.base` atomically by creating a new `Arc<HotStateBase>` with the updated data, then update both atomically:

```rust
fn run(&mut self) {
    while let Some(to_commit) = self.next_to_commit() {
        // Create new base with updates
        let new_base = self.apply_commit_to_new_base(&to_commit);
        
        // Atomically update both base and committed
        let mut committed = self.committed.lock();
        self.base = new_base;
        *committed = to_commit;
    }
}
```

3. **Option C - Versioning**: Use a version counter to detect and retry when inconsistent state is detected in `get_committed()`.

The preferred solution depends on performance considerations and the frequency of commits vs. reads.

## Proof of Concept

While a complete PoC would require setting up a full Aptos validator environment with concurrent transaction execution, the race condition can be demonstrated through code inspection:

1. Thread 1 (Committer) executes `commit()` at line 196, modifying the shared `DashMap` in `self.base`
2. Before Thread 1 reaches line 197, Thread 2 (Executor) calls `get_committed()`
3. Thread 2 receives the updated `base` but old `committed` metadata
4. Thread 2 creates `HotStateLRU` with metadata pointing to evicted/cold keys
5. Later operations on the LRU call `expect_hot_slot()` with non-existent or cold keys
6. Panic occurs with message "Given key is expected to exist" or "Given key is expected to be hot"

The vulnerability is reproducible in any scenario where transaction execution and hot state commits occur concurrently under high load.

## Notes

This vulnerability represents a classic Time-Of-Check-Time-Of-Use (TOCTOU) race condition in concurrent code. The non-atomic update of related state (base data and metadata) creates a consistency window that can be exploited by concurrent readers. While the HotState feature appears to be under active development (as evidenced by TODO comments), it is integrated into the main execution pipeline and can cause production validator crashes. The fix requires careful synchronization to maintain both correctness and performance under high transaction throughput.

### Citations

**File:** storage/aptosdb/src/state_store/hot_state.rs (L108-125)
```rust
pub struct HotState {
    base: Arc<HotStateBase>,
    committed: Arc<Mutex<State>>,
    commit_tx: SyncSender<State>,
}

impl HotState {
    pub fn new(state: State, config: HotStateConfig) -> Self {
        let base = Arc::new(HotStateBase::new_empty(config.max_items_per_shard));
        let committed = Arc::new(Mutex::new(state));
        let commit_tx = Committer::spawn(base.clone(), committed.clone());

        Self {
            base,
            committed,
            commit_tx,
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

**File:** storage/aptosdb/src/state_store/hot_state.rs (L138-144)
```rust
    pub fn enqueue_commit(&self, to_commit: State) {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["hot_state_enqueue_commit"]);

        self.commit_tx
            .send(to_commit)
            .expect("Failed to queue for hot state commit.")
    }
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L172-178)
```rust
impl Committer {
    fn spawn(base: Arc<HotStateBase>, committed: Arc<Mutex<State>>) -> SyncSender<State> {
        let (tx, rx) = std::sync::mpsc::sync_channel(MAX_HOT_STATE_COMMIT_BACKLOG);
        std::thread::spawn(move || Self::new(base, committed, rx).run());

        tx
    }
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L196-197)
```rust
            self.commit(&to_commit);
            *self.committed.lock() = to_commit;
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

**File:** storage/storage-interface/src/state_store/hot_state.rs (L60-69)
```rust
    fn insert_as_head(&mut self, key: StateKey, mut slot: StateSlot) {
        match self.head.take() {
            Some(head) => {
                let mut old_head_slot = self.expect_hot_slot(&head);
                old_head_slot.set_prev(Some(key.clone()));
                slot.set_prev(None);
                slot.set_next(Some(head.clone()));
                self.pending.insert(head, old_head_slot);
                self.pending.insert(key.clone(), slot);
                self.head = Some(key);
```

**File:** storage/storage-interface/src/state_store/hot_state.rs (L109-143)
```rust
    fn delete(&mut self, key: &StateKey) -> Option<StateSlot> {
        // Fetch the slot corresponding to the given key. Note that `self.pending` and
        // `self.overlay` may contain cold slots, like the ones recently evicted, and we need to
        // ignore them.
        let old_slot = match self.get_slot(key) {
            Some(slot) if slot.is_hot() => slot,
            _ => return None,
        };

        match old_slot.prev() {
            Some(prev_key) => {
                let mut prev_slot = self.expect_hot_slot(prev_key);
                prev_slot.set_next(old_slot.next().cloned());
                self.pending.insert(prev_key.clone(), prev_slot);
            },
            None => {
                // There is no newer entry. The current key was the head.
                self.head = old_slot.next().cloned();
            },
        }

        match old_slot.next() {
            Some(next_key) => {
                let mut next_slot = self.expect_hot_slot(next_key);
                next_slot.set_prev(old_slot.prev().cloned());
                self.pending.insert(next_key.clone(), next_slot);
            },
            None => {
                // There is no older entry. The current key was the tail.
                self.tail = old_slot.prev().cloned();
            },
        }

        Some(old_slot)
    }
```

**File:** storage/storage-interface/src/state_store/hot_state.rs (L157-161)
```rust
    fn expect_hot_slot(&self, key: &StateKey) -> StateSlot {
        let slot = self.get_slot(key).expect("Given key is expected to exist.");
        assert!(slot.is_hot(), "Given key is expected to be hot.");
        slot
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

**File:** storage/aptosdb/src/state_store/persisted_state.rs (L46-48)
```rust
    pub fn get_state(&self) -> (Arc<dyn HotStateView>, State) {
        self.hot_state.get_committed()
    }
```
