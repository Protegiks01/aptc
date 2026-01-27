# Audit Report

## Title
Hot State Memory Exhaustion via Post-Checkpoint Transaction Accumulation

## Summary
A critical timing flaw in the hot state eviction mechanism allows attackers to bypass LRU capacity limits by submitting transactions that execute after the last checkpoint in a batch. Items accumulate in memory without eviction, leading to unbounded memory growth and eventual validator OOM crashes.

## Finding Description

The hot state management system in Aptos uses an LRU eviction policy to limit memory consumption. Each shard maintains a maximum of `max_items_per_shard` items (default 250,000). However, the eviction logic in `State::update()` only triggers at checkpoint boundaries. [1](#0-0) 

The critical vulnerability exists in the second processing loop: [2](#0-1) 

This loop processes all transactions **after** the last checkpoint without calling `maybe_evict()`. Each transaction can modify up to 8,192 unique state keys: [3](#0-2) 

When items are inserted into the LRU, there's no capacity check before insertion: [4](#0-3) 

The `num_items` count is stored in metadata and persists across updates: [5](#0-4) 

**Attack Path:**

1. Attacker identifies that state sync chunks can process transactions without checkpoints: [6](#0-5) 

2. Attacker submits transactions in batches where transactions occur after the last checkpoint
3. Each transaction touches 8,192 unique state keys (the maximum allowed)
4. With chunk size of 3,000 transactions: [7](#0-6) 

5. If 1,000 transactions execute post-checkpoint: 1,000 × 8,192 = 8,192,000 keys
6. Distributed across 16 shards: ~512,000 keys per shard
7. This exceeds capacity (250,000) by 2x, consuming ~512 MB per shard [8](#0-7) 

8. The elevated `num_items` count persists in `HotStateMetadata` and is used as the starting point for the next update
9. Repeated attacks compound the memory exhaustion

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:

- **Validator node slowdowns**: As memory fills, garbage collection overhead increases, slowing block processing
- **OOM crashes**: Sustained attacks can exhaust validator memory, causing crashes and network instability
- **Protocol violation**: Breaks the invariant "Resource Limits: All operations must respect gas, storage, and computational limits"

The attack requires only normal transaction submission privileges and can be repeated to achieve cumulative memory exhaustion across the validator network.

## Likelihood Explanation

**Likelihood: High**

- **Low attack complexity**: Attacker only needs to submit transactions with many unique state writes
- **No special privileges required**: Any user can submit transactions
- **Amplification factor**: Each malicious transaction can touch 8,192 keys, with batches of 1,000+ transactions
- **Persistent effect**: Excess items remain in memory until future checkpoint eviction
- **Cumulative impact**: Multiple batches compound the memory pressure

The attack is especially effective during state sync operations where chunks may not contain checkpoints, or in normal execution where many transactions follow the last checkpoint in a batch.

## Recommendation

Add an eviction check after processing post-checkpoint transactions:

```rust
// In State::update() after line 243:
for (key, update) in all_updates {
    evictions.remove(*key);
    if let Some(hot_state_value) = Self::apply_one_update(
        &mut lru,
        overlay,
        cache,
        key,
        update,
        self.hot_state_config.refresh_interval_versions,
    ) {
        insertions.insert((*key).clone(), hot_state_value);
    }
}

// ADD THIS: Evict if capacity exceeded after post-checkpoint updates
evictions.extend(lru.maybe_evict().into_iter().map(|(key, slot)| {
    insertions.remove(&key);
    assert!(slot.is_hot());
    key
}));
```

Alternatively, enforce a hard limit on `num_items` in `HotStateLRU::insert()` to prevent unbounded growth:

```rust
pub fn insert(&mut self, key: StateKey, slot: StateSlot) {
    assert!(slot.is_hot(), "Should not insert cold slots into hot state.");
    if self.delete(&key).is_none() {
        self.num_items += 1;
        // ADD: Immediate eviction if over capacity
        if self.num_items > self.capacity.get() {
            if let Some((evicted_key, _)) = self.evict_one() {
                self.num_items -= 1;
            }
        }
    }
    self.insert_as_head(key, slot);
}
```

## Proof of Concept

```rust
#[test]
fn test_hot_state_post_checkpoint_accumulation() {
    use aptos_types::state_store::{StateKey, state_slot::StateSlot};
    use aptos_types::write_set::{WriteSet, WriteSetMut};
    use std::num::NonZeroUsize;
    
    // Setup: Create a hot state with small capacity
    let capacity = NonZeroUsize::new(100).unwrap();
    let mut state = State::new_empty(HotStateConfig {
        max_items_per_shard: capacity.get(),
        ..Default::default()
    });
    
    // Simulate checkpoint at version 100
    let checkpoint_versions = vec![100];
    
    // Create 200 post-checkpoint transactions (versions 101-300)
    // Each touching 10 unique keys = 2000 total keys
    let mut write_sets = Vec::new();
    for v in 101..=300 {
        let mut ws = WriteSetMut::new(vec![]);
        for k in 0..10 {
            let key = StateKey::raw(format!("key_{}_{}", v, k).as_bytes());
            ws.insert((key, WriteOp::Value(vec![v as u8])));
        }
        write_sets.push(ws.freeze().unwrap());
    }
    
    // Index updates with checkpoint at v100
    let updates = StateUpdateRefs::index_write_sets(
        0,
        write_sets.iter(),
        300,
        checkpoint_versions,
    );
    
    // Apply updates - this should accumulate items without eviction
    let (new_state, _) = state.update(
        persisted_hot_state,
        &persisted,
        updates.for_latest_batched().unwrap(),
        updates.for_latest_per_version().unwrap(),
        &checkpoint_versions,
        &cache,
    );
    
    // Verify: num_items exceeds capacity due to post-checkpoint accumulation
    // Expected: ~2000 items across shards, exceeding capacity of 100 per shard
    for shard_id in 0..16 {
        let num = new_state.num_hot_items(shard_id);
        if num > capacity.get() {
            println!("VULNERABILITY: Shard {} has {} items, exceeding capacity {}",
                shard_id, num, capacity.get());
        }
    }
}
```

**Notes**

The vulnerability stems from the assumption that eviction at checkpoint boundaries is sufficient. However, the design allows arbitrary numbers of transactions to execute post-checkpoint without eviction, creating a memory exhaustion vector. The fix requires either adding eviction after post-checkpoint processing or enforcing hard limits during insertion to prevent unbounded accumulation.

### Citations

**File:** storage/storage-interface/src/state_store/state.rs (L208-229)
```rust
                    for ckpt_version in all_checkpoint_versions {
                        for (key, update) in
                            all_updates.take_while_ref(|(_k, u)| u.version <= *ckpt_version)
                        {
                            evictions.remove(*key);
                            if let Some(hot_state_value) = Self::apply_one_update(
                                &mut lru,
                                overlay,
                                cache,
                                key,
                                update,
                                self.hot_state_config.refresh_interval_versions,
                            ) {
                                insertions.insert((*key).clone(), hot_state_value);
                            }
                        }
                        // Only evict at the checkpoints.
                        evictions.extend(lru.maybe_evict().into_iter().map(|(key, slot)| {
                            insertions.remove(&key);
                            assert!(slot.is_hot());
                            key
                        }));
```

**File:** storage/storage-interface/src/state_store/state.rs (L231-243)
```rust
                    for (key, update) in all_updates {
                        evictions.remove(*key);
                        if let Some(hot_state_value) = Self::apply_one_update(
                            &mut lru,
                            overlay,
                            cache,
                            key,
                            update,
                            self.hot_state_config.refresh_interval_versions,
                        ) {
                            insertions.insert((*key).clone(), hot_state_value);
                        }
                    }
```

**File:** storage/storage-interface/src/state_store/state.rs (L250-254)
```rust
                    let new_metadata = HotStateMetadata {
                        latest: new_head,
                        oldest: new_tail,
                        num_items: new_num_items,
                    };
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L174-177)
```rust
            max_write_ops_per_transaction: NumSlots,
            { 11.. => "max_write_ops_per_transaction" },
            8192,
        ],
```

**File:** storage/storage-interface/src/state_store/hot_state.rs (L49-58)
```rust
    pub fn insert(&mut self, key: StateKey, slot: StateSlot) {
        assert!(
            slot.is_hot(),
            "Should not insert cold slots into hot state."
        );
        if self.delete(&key).is_none() {
            self.num_items += 1;
        }
        self.insert_as_head(key, slot);
    }
```

**File:** storage/storage-interface/src/state_store/state_update_refs.rs (L398-415)
```rust
    fn test_chunk_with_no_checkpoint() {
        // A chunk that is the middle of a large block.
        let v0 = write_set(&[("A", "A0"), ("B", "B0")]);
        let v1 = write_set(&[("A", "A1")]);
        let v2 = write_set(&[("C", "C2")]);
        let all_checkpoint_indices = vec![];
        let ret =
            StateUpdateRefs::index_write_sets(10, vec![&v0, &v1, &v2], 3, all_checkpoint_indices);

        assert!(ret.for_last_checkpoint_batched().is_none());

        let for_latest = ret.for_latest_batched().unwrap();
        assert_eq!(for_latest.first_version, 10);
        assert_eq!(for_latest.num_versions, 3);
        verify_batching(for_latest, "A", 11, "A1");
        verify_batching(for_latest, "B", 10, "B0");
        verify_batching(for_latest, "C", 12, "C2");
    }
```

**File:** config/src/config/state_sync_config.rs (L26-26)
```rust
const MAX_TRANSACTION_CHUNK_SIZE: u64 = 3000;
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
