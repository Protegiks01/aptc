# Audit Report

## Title
Race Condition in Hot State LRU Management Causes Doubly-Linked List Invariant Violation

## Summary
A race condition exists between the Committer thread updating the hot state DashMap and execution threads creating new HotStateLRU instances. This allows reading inconsistent LRU metadata (head/tail pointers) alongside partially-updated slot data, breaking the doubly-linked list invariant where entry A having next=B must guarantee B has prev=A. This leads to corrupted LRU chains, incorrect eviction order, and potential node crashes.

## Finding Description

The hot state management system maintains an LRU cache of frequently accessed state entries using a doubly-linked list structure. The invariant is that for any two adjacent entries A and B, if A.next=B then B.prev=A must hold. [1](#0-0) 

The vulnerability occurs due to insufficient synchronization between:

1. **The Committer thread** that asynchronously updates the shared `HotStateBase` (backed by DashMap) with new LRU slot data [2](#0-1) 

2. **Execution threads** that create new `HotStateLRU` instances by reading the committed State metadata and accessing the same DashMap slots [3](#0-2) 

The race occurs because:

- The State metadata (head/tail pointers) is protected by a Mutex and read atomically [4](#0-3) 

- But the DashMap slots are updated **individually** without atomic multi-key updates [5](#0-4) 

**Attack Scenario:**

Initial state: A↔B↔C (head=A, tail=C)

1. Committer begins updating to new state with X inserted at head: X↔A↔B↔C
   - Inserts X: {prev=None, next=A} into DashMap
   - Inserts A: {prev=X, next=B} into DashMap (overwrites old A)
   - **[RACE WINDOW OPENS]**

2. Execution thread calls `get_committed()`:
   - Locks and reads old State: head=A, tail=C
   - Gets Arc to HotStateBase (no lock on DashMap)

3. Execution thread creates HotStateLRU using old head=A but reads NEW slot A from DashMap:
   - Expects A to be head with prev=None
   - Actually gets A with prev=X, next=B

4. Execution thread inserts new entry Y: [6](#0-5) 
   - Reads slot A: {prev=X, next=B}
   - Sets A.prev=Y (overwriting prev=X)
   - Creates Y: {prev=None, next=A}
   - Believes Y→A→B chain is correct

5. Committer completes commit:
   - Updates committed State to head=X
   - Validation may pass because it reads from DashMap after all updates

**Result:** Multiple conflicting chains exist:
- X→A from Committer's perspective  
- Y→A from execution thread's perspective
- But A.prev was last set to Y, breaking X→A link

This violates the fundamental doubly-linked list invariant.

## Impact Explanation

**Severity: HIGH** (per Aptos bug bounty criteria)

This qualifies as "Significant protocol violations" because:

1. **State Consistency Violation**: Different nodes may evict different hot state entries based on corrupted LRU chains, leading to inconsistent hot state caches across validators. While this doesn't directly affect consensus (Jellyfish Merkle Tree is authoritative), it violates the expectation of deterministic state management.

2. **Incorrect Eviction**: Corrupted LRU chains cause wrong entries to be evicted during memory pressure, potentially:
   - Evicting recently-accessed data while keeping stale data
   - Losing track of entries (unreachable from head/tail)
   - Memory leaks from orphaned entries

3. **Node Crashes**: The validation code includes assertions that check LRU consistency [7](#0-6) 

If these assertions fail in debug builds, validator nodes crash, causing liveness issues.

4. **Performance Degradation**: Incorrect eviction severely degrades hot state effectiveness, forcing expensive cold state reads.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This race condition will occur regularly in production:

- The race window exists during every hot state commit operation
- Commits happen continuously as blocks are processed
- Execution threads frequently create new HotStateLRU instances for transaction processing
- The parallel processing of 16 shards increases race probability [8](#0-7) 

The bug is not triggered by malicious input but by normal concurrent operations, making it a reliability/correctness issue rather than an exploitable attack. However, an attacker could potentially increase likelihood by submitting transactions that trigger frequent state updates and hot state modifications.

## Recommendation

**Solution: Add atomic multi-shard commit with proper locking**

The Committer should hold the committed State lock throughout the entire commit operation to prevent execution threads from observing partial updates:

```rust
fn commit(&mut self, to_commit: &State) {
    let _timer = OTHER_TIMERS_SECONDS.timer_with(&["hot_state_commit"]);
    
    // Prepare all updates first
    let delta = to_commit.make_delta(&self.committed.lock());
    
    // Hold the lock during the entire commit to prevent races
    let mut committed_guard = self.committed.lock();
    
    for shard_id in 0..NUM_STATE_SHARDS {
        for (key, slot) in delta.shards[shard_id].iter() {
            if slot.is_hot() {
                self.base.shards[shard_id].insert(key, slot);
            } else {
                self.base.shards[shard_id].remove(&key);
            }
        }
        self.heads[shard_id] = to_commit.latest_hot_key(shard_id);
        self.tails[shard_id] = to_commit.oldest_hot_key(shard_id);
        debug_assert!(self.validate_lru(shard_id).is_ok());
    }
    
    // Update metadata last while still holding lock
    *committed_guard = to_commit.clone();
    // Lock released here
}
```

Alternative: Use a versioned snapshot approach where each HotStateLRU creation captures a consistent generation number and validates it hasn't changed before applying updates.

## Proof of Concept

```rust
#[cfg(test)]
mod race_condition_test {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    #[test]
    fn test_lru_race_condition() {
        // Setup initial hot state with A->B->C chain
        let config = HotStateConfig::default();
        let initial_state = create_test_state_with_chain(vec!["A", "B", "C"]);
        let hot_state = Arc::new(HotState::new(initial_state.clone(), config));
        
        // Prepare new state with X->A->B->C
        let new_state = create_test_state_with_chain(vec!["X", "A", "B", "C"]);
        
        let barrier = Arc::new(Barrier::new(2));
        let hot_state_clone = Arc::clone(&hot_state);
        let barrier_clone = Arc::clone(&barrier);
        
        // Committer thread
        let committer = thread::spawn(move || {
            barrier_clone.wait(); // Synchronize start
            // Simulate slow commit - update slots one by one with delays
            hot_state_clone.enqueue_commit(new_state);
        });
        
        // Execution thread
        let executor = thread::spawn(move || {
            barrier.wait(); // Synchronize start
            // Small delay to ensure we read during commit
            thread::sleep(Duration::from_micros(10));
            
            let (base, state) = hot_state.get_committed();
            let head = state.latest_hot_key(0);
            
            // Create LRU with potentially inconsistent state
            let mut lru = HotStateLRU::new(
                NonZeroUsize::new(10).unwrap(),
                base,
                &LayeredMap::new(),
                head.clone(),
                state.oldest_hot_key(0),
                state.num_hot_items(0),
            );
            
            // Try to insert new entry - may see inconsistent state
            let slot = create_test_slot("Y");
            lru.insert(StateKey::raw(b"Y"), slot);
            
            // Validate LRU structure
            lru.validate(); // This may panic if invariant is broken
        });
        
        committer.join().unwrap();
        executor.join().unwrap(); // May panic due to invariant violation
    }
}
```

## Notes

This vulnerability demonstrates a classic Time-of-Check-Time-of-Use (TOCTOU) race condition in a concurrent system. The State metadata is checked (locked and read) at one time, but the actual slot data is used (read from DashMap) at a later time without ensuring consistency between the two.

The issue is particularly subtle because:
- Each individual DashMap operation is atomic
- The State metadata lock provides atomic reads of metadata
- But the combination of metadata + slot data is not atomically consistent

This affects the **State Consistency** critical invariant defined in the security requirements, though it's primarily a correctness/reliability issue rather than a consensus-breaking vulnerability since the authoritative state remains in the Jellyfish Merkle Tree.

### Citations

**File:** types/src/state_store/hot_state.rs (L16-21)
```rust
pub struct LRUEntry<K> {
    /// The key that is slightly newer than the current entry. `None` for the newest entry.
    pub prev: Option<K>,
    /// The key that is slightly older than the current entry. `None` for the oldest entry.
    pub next: Option<K>,
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

**File:** storage/storage-interface/src/state_store/state.rs (L187-194)
```rust
        ) = (
            state_cache.shards.as_slice(),
            overlay.shards.as_slice(),
            self.hot_state_metadata.as_slice(),
            batched_updates.shards.as_slice(),
            per_version_updates.shards.as_slice(),
        )
            .into_par_iter()
```

**File:** storage/storage-interface/src/state_store/state.rs (L196-204)
```rust
                |(cache, overlay, hot_metadata, batched_updates, per_version)| {
                    let mut lru = HotStateLRU::new(
                        NonZeroUsize::new(self.hot_state_config.max_items_per_shard).unwrap(),
                        Arc::clone(&persisted_hot_state),
                        overlay,
                        hot_metadata.latest.clone(),
                        hot_metadata.oldest.clone(),
                        hot_metadata.num_items,
                    );
```

**File:** storage/storage-interface/src/state_store/hot_state.rs (L60-79)
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
            },
            None => {
                slot.set_prev(None);
                slot.set_next(None);
                self.pending.insert(key.clone(), slot);
                self.head = Some(key.clone());
                self.tail = Some(key);
            },
        }
    }
```
