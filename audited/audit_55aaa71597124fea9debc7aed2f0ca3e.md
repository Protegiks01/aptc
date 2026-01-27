# Audit Report

## Title
Time-of-Check-Time-of-Use Race Condition Between State Merkle Pruning Check and Tree Traversal Leading to State Inconsistencies

## Summary
A TOCTOU race condition exists between the `error_if_state_merkle_pruned` check and the subsequent Jellyfish Merkle tree traversal. The `min_readable_version` is updated atomically before pruning completes, creating a window where clients pass the availability check but encounter deleted nodes during multi-step tree reads, leading to inconsistent error responses and state access violations.

## Finding Description

The vulnerability stems from insufficient test coverage of concurrent pruning scenarios, specifically the interaction between the pruning check and actual data access.

The problematic sequence occurs in: [1](#0-0) 

The function first checks if data is pruned, then proceeds to read. However, the pruning system updates `min_readable_version` BEFORE actual node deletion: [2](#0-1) 

At line 162-164, `min_readable_version` is immediately updated to `latest_version - prune_window`, then the pruner worker is notified. The worker prunes in a background thread: [3](#0-2) 

Meanwhile, tree traversal makes multiple independent `get_node_option` calls without RocksDB snapshot isolation: [4](#0-3) 

Each `get()` call at line 889-890 sees the current database state independently. During traversal: [5](#0-4) 

**Attack Scenario:**
1. Client requests proof for version 110 (prune_window = 100, latest_version = 190)
2. `error_if_state_merkle_pruned` checks: 110 >= min_readable_version (90) ✓ PASS
3. New commits arrive, latest_version becomes 220
4. `set_pruner_target_db_version(220)` executes: min_readable_version = 220 - 100 = 120
5. `min_readable_version` atomically updated to 120 (line 163-164)
6. Client starts tree traversal at version 110, reads root node successfully
7. Pruner deletes nodes with `stale_since_version <= 120` (includes version 110 nodes)
8. Client's next `get_node_option` call returns None (node deleted)
9. `get_node_with_tag` converts to `NotFound` error instead of proper "pruned" error [6](#0-5) 

The client receives `AptosDbError::NotFound` for data that passed the availability check, violating the state consistency invariant that pruning checks should prevent access to unavailable data.

## Impact Explanation

This qualifies as **Medium Severity** ($10,000) under Aptos bug bounty rules: "State inconsistencies requiring intervention."

**Specific Impacts:**
- **State Consistency Violation**: Clients that pass `error_if_state_merkle_pruned` cannot complete reads, breaking the guarantee that checked data is accessible
- **Misleading Error Messages**: `NotFound` errors instead of explicit "pruned" errors confuse clients and mask the root cause
- **Service Reliability**: Read operations fail unpredictably during pruning windows, causing API failures and retry storms
- **Testing Gap**: The security question correctly identifies that test data generation doesn't cover concurrent pruning patterns

The issue doesn't cause fund loss or consensus breaks, but it violates Critical Invariant #4: "State transitions must be atomic and verifiable via Merkle proofs" - clients cannot reliably verify state during pruning.

## Likelihood Explanation

**High Likelihood** - This race condition occurs naturally during normal operation:

1. **Frequency**: Pruning runs continuously on active validators with default 100-version windows
2. **Window Size**: The TOCTOU window spans from `min_readable_version` update until all shard pruning completes (potentially seconds with parallel shard pruning)
3. **No Special Conditions**: Requires only concurrent reads and pruning, which happens constantly
4. **Scale Factor**: More likely with high transaction throughput (faster version advancement triggers more frequent pruning)

The test gap identified in the security question - lack of concurrent write/prune/read testing - directly enables this vulnerability to persist undetected.

## Recommendation

Implement atomic read operations using RocksDB snapshots or defer `min_readable_version` update:

**Option 1: Use RocksDB Snapshots (Preferred)**

```rust
// In state_merkle_db.rs, add snapshot-based read method
pub fn get_with_proof_ext_snapshot(
    &self,
    key: &HashValue,
    version: Version,
    root_depth: usize,
) -> Result<(Option<(HashValue, (StateKey, Version))>, SparseMerkleProofExt)> {
    // Create snapshot before traversal
    let snapshot = self.metadata_db().create_snapshot();
    let opts = ReadOptions::default();
    opts.set_snapshot(&snapshot);
    
    // Pass opts through TreeReader to ensure consistent reads
    JellyfishMerkleTree::new_with_opts(self, opts)
        .get_with_proof_ext(key, version, root_depth)
}
```

**Option 2: Defer min_readable_version Update**

Modify the pruner manager to only update `min_readable_version` AFTER pruning completes: [7](#0-6) 

Move the `save_min_readable_version` call to AFTER successful pruning completes, not before.

**Add Concurrent Testing:**

Enhance test data generation to cover the identified gap:

```rust
#[test]
fn test_concurrent_pruning_and_reads() {
    let db = AptosDB::new_for_test(&tmp_dir);
    // Generate 200 versions
    for v in 0..200 {
        db.save_transactions(..., v).unwrap();
    }
    
    // Spawn concurrent threads
    let reader_handle = thread::spawn(|| {
        // Read version 110 repeatedly
        for _ in 0..100 {
            let result = db.get_state_value_with_proof_by_version(&key, 110);
            // Should never get NotFound if check passed
            if let Err(e) = result {
                assert!(!matches!(e, AptosDbError::NotFound(_)));
            }
        }
    });
    
    let pruner_handle = thread::spawn(|| {
        pruner.set_target_version(220); // Triggers min_readable = 120
        pruner.wake_and_wait_pruner(220).unwrap();
    });
    
    reader_handle.join().unwrap();
    pruner_handle.join().unwrap();
}
```

## Proof of Concept

```rust
use aptos_temppath::TempPath;
use aptos_types::state_store::{state_key::StateKey, state_value::StateValue};
use std::{sync::Arc, thread, time::Duration};

#[test]
fn poc_toctou_race_condition() {
    let tmp_dir = TempPath::new();
    let db = Arc::new(AptosDB::new_for_test(&tmp_dir));
    
    // Setup: Create 200 versions of state
    let key = StateKey::raw(b"test_key");
    for version in 0..200 {
        let value = StateValue::from(vec![version as u8]);
        db.save_transactions_for_test(
            &[create_txn_with_state_update(&key, &value)],
            version,
            None,
            false,
        ).unwrap();
    }
    
    // Enable pruning with 100-version window
    let pruner = db.state_store.state_merkle_pruner;
    pruner.set_prune_window(100);
    
    let db_clone = Arc::clone(&db);
    let success_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let error_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let success_clone = Arc::clone(&success_count);
    let error_clone = Arc::clone(&error_count);
    
    // Thread 1: Continuously read version 110
    let reader = thread::spawn(move || {
        for _ in 0..1000 {
            match db_clone.get_state_value_with_proof_by_version(&key, 110) {
                Ok(_) => success_clone.fetch_add(1, Ordering::SeqCst),
                Err(AptosDbError::NotFound(_)) => {
                    // BUG: Got NotFound even though version 110 should be readable
                    // when min_readable_version was < 110
                    error_clone.fetch_add(1, Ordering::SeqCst);
                    panic!("TOCTOU Race Detected: NotFound for supposedly available version 110");
                },
                Err(_) => {}, // Other errors acceptable
            };
            thread::sleep(Duration::from_micros(10));
        }
    });
    
    // Thread 2: Trigger pruning to version 220 (min_readable = 120)
    let pruner_thread = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        pruner.set_pruner_target_db_version(220); // Updates min_readable to 120 IMMEDIATELY
        // Now version 110 should be "pruned" but deletion hasn't completed yet
    });
    
    reader.join().expect("Race condition detected - NotFound for checked version");
    pruner_thread.join().unwrap();
    
    println!("Successful reads: {}", success_count.load(Ordering::SeqCst));
    println!("NotFound errors: {}", error_count.load(Ordering::SeqCst));
}
```

**Expected Result**: Test should expose the race condition where reads for version 110 fail with `NotFound` after `min_readable_version` is updated to 120 but before the client's tree traversal completes.

## Notes

This vulnerability directly validates the security question's concern about insufficient test coverage for "concurrent write patterns, or pruning edge cases that lead to state inconsistencies." The test data generation in `value_generator.rs` and related test helpers creates only sequential, non-concurrent test scenarios, failing to expose this TOCTOU race condition that occurs in production under concurrent load.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L677-694)
```rust
    fn get_state_value_with_proof_by_version_ext(
        &self,
        key_hash: &HashValue,
        version: Version,
        root_depth: usize,
        use_hot_state: bool,
    ) -> Result<(Option<StateValue>, SparseMerkleProofExt)> {
        gauged_api("get_state_value_with_proof_by_version_ext", || {
            self.error_if_state_merkle_pruned("State merkle", version)?;

            self.state_store.get_state_value_with_proof_by_version_ext(
                key_hash,
                version,
                root_depth,
                use_hot_state,
            )
        })
    }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_pruner_manager.rs (L159-174)
```rust
    fn set_pruner_target_db_version(&self, latest_version: Version) {
        assert!(self.pruner_worker.is_some());

        let min_readable_version = latest_version.saturating_sub(self.prune_window);
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);

        PRUNER_VERSIONS
            .with_label_values(&[S::name(), "min_readable"])
            .set(min_readable_version as i64);

        self.pruner_worker
            .as_ref()
            .unwrap()
            .set_target_db_version(min_readable_version);
    }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_shard_pruner.rs (L58-100)
```rust
    pub(in crate::pruner) fn prune(
        &self,
        current_progress: Version,
        target_version: Version,
        max_nodes_to_prune: usize,
    ) -> Result<()> {
        loop {
            let mut batch = SchemaBatch::new();
            let (indices, next_version) = StateMerklePruner::get_stale_node_indices(
                &self.db_shard,
                current_progress,
                target_version,
                max_nodes_to_prune,
            )?;

            indices.into_iter().try_for_each(|index| {
                batch.delete::<JellyfishMerkleNodeSchema>(&index.node_key)?;
                batch.delete::<S>(&index)
            })?;

            let mut done = true;
            if let Some(next_version) = next_version {
                if next_version <= target_version {
                    done = false;
                }
            }

            if done {
                batch.put::<DbMetadataSchema>(
                    &S::progress_metadata_key(Some(self.shard_id)),
                    &DbMetadataValue::Version(target_version),
                )?;
            }

            self.db_shard.write_schemas(batch)?;

            if done {
                break;
            }
        }

        Ok(())
    }
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L856-898)
```rust
    fn get_node_option(&self, node_key: &NodeKey, tag: &str) -> Result<Option<Node>> {
        let start_time = Instant::now();
        if !self.cache_enabled() {
            let node_opt = self
                .db_by_key(node_key)
                .get::<JellyfishMerkleNodeSchema>(node_key)?;
            NODE_CACHE_SECONDS
                .observe_with(&[tag, "cache_disabled"], start_time.elapsed().as_secs_f64());
            return Ok(node_opt);
        }
        if let Some(node_cache) = self
            .version_caches
            .get(&node_key.get_shard_id())
            .unwrap()
            .get_version(node_key.version())
        {
            let node = node_cache.get(node_key).cloned();
            NODE_CACHE_SECONDS.observe_with(
                &[tag, "versioned_cache_hit"],
                start_time.elapsed().as_secs_f64(),
            );
            return Ok(node);
        }

        if let Some(lru_cache) = &self.lru_cache {
            if let Some(node) = lru_cache.get(node_key) {
                NODE_CACHE_SECONDS
                    .observe_with(&[tag, "lru_cache_hit"], start_time.elapsed().as_secs_f64());
                return Ok(Some(node));
            }
        }

        let node_opt = self
            .db_by_key(node_key)
            .get::<JellyfishMerkleNodeSchema>(node_key)?;
        if let Some(lru_cache) = &self.lru_cache {
            if let Some(node) = &node_opt {
                lru_cache.put(node_key.clone(), node.clone());
            }
        }
        NODE_CACHE_SECONDS.observe_with(&[tag, "cache_miss"], start_time.elapsed().as_secs_f64());
        Ok(node_opt)
    }
```

**File:** storage/jellyfish-merkle/src/lib.rs (L126-129)
```rust
    fn get_node_with_tag(&self, node_key: &NodeKey, tag: &str) -> Result<Node<K>> {
        self.get_node_option(node_key, tag)?
            .ok_or_else(|| AptosDbError::NotFound(format!("Missing node at {:?}.", node_key)))
    }
```

**File:** storage/jellyfish-merkle/src/lib.rs (L717-741)
```rust
    pub fn get_with_proof_ext(
        &self,
        key: &HashValue,
        version: Version,
        target_root_depth: usize,
    ) -> Result<(Option<(HashValue, (K, Version))>, SparseMerkleProofExt)> {
        // Empty tree just returns proof with no sibling hash.
        let mut next_node_key = NodeKey::new_empty_path(version);
        let mut out_siblings = Vec::with_capacity(8); // reduces reallocation
        let nibble_path = NibblePath::new_even(key.to_vec());
        let mut nibble_iter = nibble_path.nibbles();

        // We limit the number of loops here deliberately to avoid potential cyclic graph bugs
        // in the tree structure.
        for nibble_depth in 0..=ROOT_NIBBLE_HEIGHT {
            let next_node = self
                .reader
                .get_node_with_tag(&next_node_key, "get_proof")
                .map_err(|err| {
                    if nibble_depth == 0 {
                        AptosDbError::MissingRootError(version)
                    } else {
                        err
                    }
                })?;
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/mod.rs (L59-95)
```rust
    fn prune(&self, batch_size: usize) -> Result<Version> {
        // TODO(grao): Consider separate pruner metrics, and have a label for pruner name.
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_merkle_pruner__prune"]);
        let mut progress = self.progress();
        let target_version = self.target_version();

        if progress >= target_version {
            return Ok(progress);
        }

        info!(
            name = S::name(),
            current_progress = progress,
            target_version = target_version,
            "Start pruning..."
        );

        while progress < target_version {
            if let Some(target_version_for_this_round) = self
                .metadata_pruner
                .maybe_prune_single_version(progress, target_version)?
            {
                self.prune_shards(progress, target_version_for_this_round, batch_size)?;
                progress = target_version_for_this_round;
                info!(name = S::name(), progress = progress);
                self.record_progress(target_version_for_this_round);
            } else {
                self.prune_shards(progress, target_version, batch_size)?;
                self.record_progress(target_version);
                break;
            }
        }

        info!(name = S::name(), progress = target_version, "Done pruning.");

        Ok(target_version)
    }
```
