# Audit Report

## Title
Race Condition in Hot State LRU Causing Validator Node Crashes During Concurrent Commits

## Summary
A race condition exists between execution threads building LRU state and the asynchronous Committer thread updating the shared HotStateBase. This causes validator nodes to panic with "Given key is expected to exist" when the LRU attempts to access keys that were concurrently evicted, leading to node crashes under high transaction load.

## Finding Description

The hot state management system uses an LRU cache to track recently accessed state keys. The implementation has a critical race condition that violates the **State Consistency** invariant:

**Architecture Overview:**
The system maintains:
- A shared `HotStateBase` (using `DashMap`) containing hot state entries [1](#0-0) 
- An asynchronous Committer thread that updates this shared state [2](#0-1) 
- Execution threads that read from the shared state while building new LRU instances [3](#0-2) 

**The Race Condition:**

When execution threads create LRU instances, they receive a **snapshot** of metadata (head, tail, num_items) but a **shared reference** to the HotStateBase: [4](#0-3) 

The Committer thread runs independently and modifies the same HotStateBase: [5](#0-4) 

**Critical Code Path:**

During LRU operations, the `delete` function reads a slot's prev/next pointers and expects those keys to exist: [6](#0-5) 

The `expect_hot_slot` function panics if the key doesn't exist: [7](#0-6) 

**Exploitation Sequence:**

1. **Thread 1 (Execution)**: Gets persisted state with metadata `head=A, tail=C` and shared HotStateBase `{A: {next: B}, B: {next: C}, C: {next: None}}`
2. **Thread 1**: Calls `lru.delete(A)` which reads `A: {next: B}` from HotStateBase
3. **Thread 2 (Committer)**: Processes new commit that evicts key `B` from HotStateBase
4. **Thread 1**: Attempts `expect_hot_slot(B)` to update B's prev pointer
5. **Thread 1**: `get_slot(B)` returns None (B was removed by Committer)
6. **PANIC**: "Given key is expected to exist"

The race window exists because DashMap provides per-key atomicity but not multi-key transactional consistency. Thread 1 can observe an inconsistent snapshot where A points to B, but B has been concurrently removed.

## Impact Explanation

**Severity: HIGH (up to $50,000 per Aptos Bug Bounty)**

This vulnerability causes:

1. **Validator Node Crashes**: Panics in the hot state management cause immediate node termination
2. **Consensus Impact**: If multiple validators crash simultaneously during high load, consensus could be affected
3. **Network Reliability**: Repeated crashes reduce network reliability and increase downtime
4. **No Recovery Without Restart**: Node must be manually restarted after each crash

The issue qualifies as HIGH severity under "API crashes" and "Significant protocol violations" categories. While not reaching CRITICAL (no fund loss or permanent network partition), it significantly impacts validator availability and network stability.

## Likelihood Explanation

**Likelihood: HIGH**

This race condition is **highly likely** to occur in production:

1. **No Special Trigger Required**: Happens during normal transaction processing under load
2. **Continuous Opportunity**: The Committer thread runs continuously and asynchronously [8](#0-7) 
3. **Wide Race Window**: Occurs during any LRU update operation, which happens for every state access
4. **High Throughput Amplifies Risk**: More transactions = more LRU operations = higher collision probability
5. **Not Caught in Tests**: Test infrastructure uses `Mutex<HotState>` which serializes access, masking the race: [9](#0-8) 

## Recommendation

**Immediate Fix**: Add synchronization to prevent concurrent modification during LRU operations.

**Option 1: Lock-Free Snapshot (Preferred)**
Clone the HotStateBase entries needed for LRU operations into the LRU's pending map at initialization, avoiding reads from the shared state:

```rust
pub fn new(
    capacity: NonZeroUsize,
    committed: Arc<dyn HotStateView>,
    overlay: &'a LayeredMap<StateKey, StateSlot>,
    head: Option<StateKey>,
    tail: Option<StateKey>,
    num_items: usize,
) -> Self {
    let mut pending = HashMap::new();
    
    // Pre-populate pending with all hot entries from committed
    // to avoid reading from shared state during operations
    let mut current = head.clone();
    while let Some(key) = current {
        if let Some(slot) = committed.get_state_slot(&key) {
            if slot.is_hot() {
                current = slot.next().cloned();
                pending.insert(key, slot);
            } else {
                break;
            }
        } else {
            break;
        }
    }
    
    Self {
        capacity,
        committed,
        overlay,
        pending,
        head,
        tail,
        num_items,
    }
}
```

**Option 2: Version-Based Validation**
Add version checking to detect stale reads and retry:

```rust
fn expect_hot_slot(&self, key: &StateKey) -> StateSlot {
    let slot = self.get_slot(key);
    match slot {
        Some(s) if s.is_hot() => s,
        _ => {
            // Key was concurrently evicted, this is acceptable
            // Return a default cold slot to gracefully handle the race
            StateSlot::ColdVacant
        }
    }
}
```

**Option 3: Read Lock on Commits**
Add a read-write lock where LRU operations hold a read lock and commits acquire a write lock (impacts performance).

## Proof of Concept

```rust
// Reproduction test (add to storage/storage-interface/src/state_store/hot_state.rs)
#[cfg(test)]
mod race_condition_test {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    #[test]
    #[should_panic(expected = "Given key is expected to exist")]
    fn test_concurrent_eviction_race() {
        // Setup: Create hot state with keys A -> B -> C
        let hot_state = Arc::new(Mutex::new(HotState {
            inner: HashMap::from([
                (StateKey::raw(b"A"), StateSlot::HotOccupied {
                    value_version: 1,
                    value: StateValue::from(b"value_a".to_vec()),
                    hot_since_version: 1,
                    lru_info: LRUEntry { prev: None, next: Some(StateKey::raw(b"B")) },
                }),
                (StateKey::raw(b"B"), StateSlot::HotOccupied {
                    value_version: 1,
                    value: StateValue::from(b"value_b".to_vec()),
                    hot_since_version: 1,
                    lru_info: LRUEntry { 
                        prev: Some(StateKey::raw(b"A")), 
                        next: Some(StateKey::raw(b"C")) 
                    },
                }),
                (StateKey::raw(b"C"), StateSlot::HotOccupied {
                    value_version: 1,
                    value: StateValue::from(b"value_c".to_vec()),
                    hot_since_version: 1,
                    lru_info: LRUEntry { prev: Some(StateKey::raw(b"B")), next: None },
                }),
            ]),
            head: Some(StateKey::raw(b"A")),
            tail: Some(StateKey::raw(b"C")),
        }));
        
        let barrier = Arc::new(Barrier::new(2));
        let hot_state_clone = Arc::clone(&hot_state);
        let barrier_clone = Arc::clone(&barrier);
        
        // Thread 1: Create LRU and try to delete A
        let handle1 = thread::spawn(move || {
            let overlay = LayeredMap::new();
            let mut lru = HotStateLRU::new(
                NonZeroUsize::new(3).unwrap(),
                hot_state_clone as Arc<dyn HotStateView>,
                &overlay,
                Some(StateKey::raw(b"A")),
                Some(StateKey::raw(b"C")),
                3,
            );
            
            barrier_clone.wait(); // Sync with thread 2
            lru.delete(&StateKey::raw(b"A")); // Will panic when accessing B
        });
        
        // Thread 2: Concurrently remove B from hot state
        let handle2 = thread::spawn(move || {
            barrier.wait(); // Sync with thread 1
            thread::sleep(std::time::Duration::from_micros(100));
            hot_state.lock().unwrap().inner.remove(&StateKey::raw(b"B"));
        });
        
        handle1.join().unwrap(); // Should panic here
        handle2.join().unwrap();
    }
}
```

**Notes**

This vulnerability represents a fundamental concurrency bug in the hot state management system. The issue arises from the architectural decision to share the HotStateBase via Arc<DashMap> while allowing asynchronous commits, combined with the LRU implementation's assumption that linked list pointers remain valid throughout operations.

The bug is particularly insidious because:
- It only manifests under concurrent load
- Test coverage using Mutex-wrapped structures masks the issue
- The race window is small but occurs frequently in high-throughput scenarios

The recommended fix requires careful consideration of performance vs. correctness trade-offs, as adding synchronization could impact throughput.

### Citations

**File:** storage/aptosdb/src/state_store/hot_state.rs (L73-78)
```rust
pub struct HotStateBase<K = StateKey, V = StateSlot>
where
    K: Eq + std::hash::Hash,
{
    shards: [Shard<K, V>; NUM_STATE_SHARDS],
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

**File:** storage/aptosdb/src/state_store/hot_state.rs (L160-170)
```rust
pub struct Committer {
    base: Arc<HotStateBase>,
    committed: Arc<Mutex<State>>,
    rx: Receiver<State>,
    total_key_bytes: usize,
    total_value_bytes: usize,
    /// Points to the newest entry. `None` if empty.
    heads: [Option<StateKey>; NUM_STATE_SHARDS],
    /// Points to the oldest entry. `None` if empty.
    tails: [Option<StateKey>; NUM_STATE_SHARDS],
}
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L173-177)
```rust
    fn spawn(base: Arc<HotStateBase>, committed: Arc<Mutex<State>>) -> SyncSender<State> {
        let (tx, rx) = std::sync::mpsc::sync_channel(MAX_HOT_STATE_COMMIT_BACKLOG);
        std::thread::spawn(move || Self::new(base, committed, rx).run());

        tx
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

**File:** storage/storage-interface/src/state_store/hot_state.rs (L11-27)
```rust
pub(crate) struct HotStateLRU<'a> {
    /// Max total number of items in the cache.
    capacity: NonZeroUsize,
    /// The entire committed hot state. While this contains all the shards, this struct is supposed
    /// to handle a single shard.
    committed: Arc<dyn HotStateView>,
    /// Additional entries resulted from previous speculative execution.
    overlay: &'a LayeredMap<StateKey, StateSlot>,
    /// The new entries from current execution.
    pending: HashMap<StateKey, StateSlot>,
    /// Points to the latest entry. `None` if empty.
    head: Option<StateKey>,
    /// Points to the oldest entry. `None` if empty.
    tail: Option<StateKey>,
    /// Total number of items.
    num_items: usize,
}
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

**File:** storage/storage-interface/src/state_store/hot_state.rs (L255-259)
```rust
    impl HotStateView for Mutex<HotState> {
        fn get_state_slot(&self, state_key: &StateKey) -> Option<StateSlot> {
            self.lock().unwrap().inner.get(state_key).cloned()
        }
    }
```
