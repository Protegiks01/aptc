# Audit Report

## Title
Hot State LRU Chain Desynchronization Causing Validator Panic via set_commited() Bypass

## Summary
The `Committer::validate_lru()` function panics when walking the hot state LRU chain if entries referenced by `next()`/`prev()` pointers don't exist in the shard DashMap. This occurs when `HotState::set_commited()` directly updates the committed State without synchronizing the Committer's shard, creating a desynchronization that violates the invariant that all LRU chain entries must exist in the shard.

## Finding Description

The vulnerability exists in the hot state commit mechanism within Aptos's storage layer. The `Committer` maintains two critical data structures that must remain synchronized: [1](#0-0) 

The `set_commited()` function bypasses the normal commit flow by directly updating the shared `committed` state without updating the Committer's `base.shards` DashMap or LRU metadata: [2](#0-1) 

This function is invoked via `PersistedState::hack_reset()`: [3](#0-2) 

Which is called by the public API `StateStore::set_state_ignoring_summary()` during database restore operations: [4](#0-3) 

The vulnerability manifests as follows:

1. When `set_commited()` is invoked with a State containing hot entries, it updates `self.committed` but the Committer thread's `base.shards` remains unchanged
2. When `commit()` subsequently processes a new State, it calculates the delta between `to_commit` and the modified `self.committed`
3. The delta only contains entries that changed between the two states, as the LayeredMap iterator filters based on layer: [5](#0-4) 

4. Unchanged entries in the LRU chain won't be in the delta and won't be inserted into the shard
5. However, `heads[shard_id]` and `tails[shard_id]` are set from `to_commit` to reference the full LRU chain: [6](#0-5) 

6. The `validate_lru()` function attempts to walk the entire chain and panics when encountering missing entries: [7](#0-6) 

**Attack Scenario:**
1. System initialized with empty HotState
2. During restore, `hack_reset()` called with State containing hot entries A→B→C
   - `self.committed` updated to {A, B, C} with proper LRU links
   - Committer's `self.base.shards` remains empty
3. New commit enqueued adding entry D: D→A→B→C
   - Delta contains {D (new), A (prev pointer modified)} only
   - B and C unchanged, not in delta
4. `commit()` processes the delta:
   - Inserts D and A into shard
   - Sets `heads[shard_id] = D`, `tails[shard_id] = C`
   - `validate_lru()` walks D→A→B
   - Line 288: `shard.get(&B).expect("Must exist.")` → **PANIC**

## Impact Explanation

**Severity: HIGH**

This vulnerability violates critical state consistency invariants in the storage layer:

1. **Debug Builds**: Immediate validator node crash when the `debug_assert!` on line 269 triggers `validate_lru()`, which panics at line 288. This causes validator unavailability and network liveness degradation. [8](#0-7) 

2. **Release Builds**: The `debug_assert!` is compiled out, so `validate_lru()` is never called. However, the hot state shard remains incomplete with missing entries, leading to:
   - Incorrect hot state queries via `HotStateView`
   - Potential consensus divergence if validators have different shard states
   - Unpredictable behavior when accessing hot state

This meets **HIGH Severity** criteria per Aptos Bug Bounty guidelines: "Validator node slowdowns" and "Significant protocol violations". A validator crash during state commit operations is a critical protocol violation affecting network liveness and validator availability.

## Likelihood Explanation

**Likelihood: MEDIUM**

While `hack_reset()` includes a warning comment "Can only be used when no on the fly commit is in the queue", this constraint is not enforced programmatically: [9](#0-8) 

The function is invoked by `set_state_ignoring_summary()`, which is part of the StateStore public API and called during database restore operations: [10](#0-9) 

The vulnerability requires:
1. Calling `set_commited()` with a non-empty State containing hot entries
2. Subsequent commit with partial LRU chain updates

While not trivially exploitable by external attackers, node operators or internal recovery mechanisms could inadvertently trigger this during:
- Database recovery operations
- State synchronization procedures
- System reinitialization after crashes

The MEDIUM likelihood reflects that this requires specific operational scenarios but doesn't require malicious intent or external attack vectors.

## Recommendation

Implement proper synchronization enforcement:

1. **Immediate Fix**: Add runtime validation in `hack_reset()` to ensure the commit queue is empty:
   ```rust
   pub fn hack_reset(&self, state_with_summary: StateWithSummary) {
       assert!(self.hot_state.commit_queue_is_empty(), 
               "hack_reset can only be called with empty commit queue");
       let (state, summary) = state_with_summary.into_inner();
       *self.summary.lock() = summary;
       self.hot_state.set_commited(state);
   }
   ```

2. **Long-term Fix**: Refactor `hack_reset()` to properly synchronize with the Committer thread by either:
   - Waiting for all pending commits to complete before updating
   - Sending a special message to the Committer to reset both `committed` and `base.shards` atomically
   - Replacing direct `set_commited()` with a proper reset protocol

3. **Additional Safety**: Add validation in release builds to detect shard inconsistencies during hot state queries.

## Proof of Concept

The vulnerability can be triggered through the following sequence:

1. Initialize a StateStore with hot state enabled
2. Trigger database restore via `save_transactions_impl()` with `kv_replay=true` where the calculated state contains hot entries
3. This calls `set_state_ignoring_summary()` → `hack_reset()` → `set_commited()`
4. Queue a subsequent state commit that modifies the head of the LRU chain
5. In debug builds, the validator will panic when `validate_lru()` is called
6. In release builds, the hot state shard will be incomplete

Note: A complete executable PoC would require setting up the full database restore infrastructure, which is complex. However, the logic path is traceable through the cited code locations and the vulnerability is demonstrable through code inspection.

## Notes

This is a critical state management bug that violates the synchronization invariant between the `committed` State and the Committer's internal data structures. The vulnerability is particularly concerning because:

1. It can cause validator crashes in debug builds during critical recovery operations
2. It creates silent data corruption in release builds that could lead to consensus divergence
3. The constraint preventing this issue is documented only as a comment, not enforced programmatically
4. The affected code path is reachable through legitimate operational procedures (database restore)

The fix requires careful coordination between the `PersistedState`, `HotState`, and `Committer` components to maintain consistency guarantees.

### Citations

**File:** storage/aptosdb/src/state_store/hot_state.rs (L127-129)
```rust
    pub(crate) fn set_commited(&self, state: State) {
        *self.committed.lock() = state
    }
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L160-169)
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
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L262-263)
```rust
            self.heads[shard_id] = to_commit.latest_hot_key(shard_id);
            self.tails[shard_id] = to_commit.oldest_hot_key(shard_id);
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L269-269)
```rust
            debug_assert!(self.validate_lru(shard_id).is_ok());
```

**File:** storage/aptosdb/src/state_store/hot_state.rs (L277-311)
```rust
    /// Traverses the entire map and checks if all the pointers are correctly linked.
    fn validate_lru(&self, shard_id: usize) -> Result<()> {
        let head = &self.heads[shard_id];
        let tail = &self.tails[shard_id];
        ensure!(head.is_some() == tail.is_some());
        let shard = &self.base.shards[shard_id];

        {
            let mut num_visited = 0;
            let mut current = head.clone();
            while let Some(key) = current {
                let entry = shard.get(&key).expect("Must exist.");
                num_visited += 1;
                ensure!(num_visited <= shard.len());
                ensure!(entry.is_hot());
                current = entry.next().cloned();
            }
            ensure!(num_visited == shard.len());
        }

        {
            let mut num_visited = 0;
            let mut current = tail.clone();
            while let Some(key) = current {
                let entry = shard.get(&key).expect("Must exist.");
                num_visited += 1;
                ensure!(num_visited <= shard.len());
                ensure!(entry.is_hot());
                current = entry.prev().cloned();
            }
            ensure!(num_visited == shard.len());
        }

        Ok(())
    }
```

**File:** storage/aptosdb/src/state_store/persisted_state.rs (L64-69)
```rust
    // n.b. Can only be used when no on the fly commit is in the queue.
    pub fn hack_reset(&self, state_with_summary: StateWithSummary) {
        let (state, summary) = state_with_summary.into_inner();
        *self.summary.lock() = summary;
        self.hot_state.set_commited(state);
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L1234-1234)
```rust
        self.persisted_state.hack_reset(last_checkpoint.clone());
```

**File:** experimental/storage/layered-map/src/node.rs (L29-38)
```rust
    pub fn into_iter(self, base_layer: u64) -> impl Iterator<Item = (K, V)> {
        match self {
            LeafContent::UniqueLatest { key, value } => Either::Left(std::iter::once((key, value))),
            LeafContent::Collision(map) => {
                Either::Right(map.into_iter().filter_map(move |(key, cell)| {
                    (cell.layer > base_layer).then_some((key, cell.value))
                }))
            },
        }
    }
```

**File:** storage/aptosdb/src/backup/restore_utils.rs (L269-276)
```rust
    if kv_replay && first_version > 0 && state_store.get_usage(Some(first_version - 1)).is_ok() {
        let (ledger_state, _hot_state_updates) = state_store.calculate_state_and_put_updates(
            &StateUpdateRefs::index_write_sets(first_version, write_sets, write_sets.len(), vec![]),
            &mut ledger_db_batch.ledger_metadata_db_batches, // used for storing the storage usage
            state_kv_batches,
        )?;
        // n.b. ideally this is set after the batches are committed
        state_store.set_state_ignoring_summary(ledger_state);
```
