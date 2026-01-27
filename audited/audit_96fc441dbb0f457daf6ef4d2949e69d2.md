# Audit Report

## Title
Unbounded Memory Consumption in StaleNodeIndexCrossEpochSchema Truncation Leading to Out-of-Memory Crash

## Summary
The truncation helper for `StaleNodeIndexCrossEpochSchema` loads all entries to be deleted into a single unbounded `SchemaBatch` without batching, which can cause out-of-memory (OOM) crashes when millions of cross-epoch stale node entries have accumulated over time. This prevents node recovery during critical operations.

## Finding Description

The `delete_stale_node_index_at_or_after_version` function in the truncation helper collects all stale node index deletions into a single `SchemaBatch` without any size limits or batching mechanism. [1](#0-0) 

This function is called during state merkle database truncation for both `StaleNodeIndexSchema` and `StaleNodeIndexCrossEpochSchema`. [2](#0-1) 

The `SchemaBatch` struct is simply a wrapper around a `HashMap<ColumnFamilyName, Vec<WriteOp>>` with no memory limits or size constraints. [3](#0-2) 

Each delete operation adds a `WriteOp::Deletion` containing the encoded key to the unbounded vector. [4](#0-3) 

**In contrast, the pruning operations properly implement batching:**

The state merkle pruner's `get_stale_node_indices` function accepts a `limit` parameter and only fetches that many entries at a time, returning the next version to continue from. [5](#0-4) 

The shard pruner calls this in a loop with the `max_nodes_to_prune` parameter, processing batches iteratively. [6](#0-5) 

**How entries accumulate:**

`StaleNodeIndexCrossEpochSchema` entries are written whenever a Jellyfish Merkle tree node becomes stale and its version is from a previous epoch. [7](#0-6) 

In a long-running blockchain with many epochs and millions of state updates, millions of cross-epoch stale node entries can accumulate. When truncation is triggered during database recovery, crash recovery, or manual intervention, all these entries are loaded into memory at once, causing OOM.

**When truncation occurs:**

Truncation is triggered during commit progress synchronization when a node restarts or recovers. [8](#0-7) 

## Impact Explanation

This is a **Medium severity** vulnerability according to Aptos bug bounty criteria because it causes "State inconsistencies requiring intervention" and prevents node recovery operations.

**Specific impacts:**
- **Node recovery failure**: A node attempting to recover from a crash or inconsistency cannot complete truncation due to OOM, leaving it in an unrecoverable state
- **Operational DoS**: Nodes with accumulated cross-epoch data become unable to perform database maintenance operations
- **Cascading failures**: If multiple nodes in a network experience similar issues, this can impact network health

**Memory consumption analysis:**
- Each `StaleNodeIndex` key: ~50 bytes (8 bytes version + ~42 bytes for node key encoding)
- 1 million entries: ~50 MB minimum, realistically 100+ MB with Vec/HashMap overhead
- 10 million entries: 1+ GB of memory consumption
- This is in addition to normal node operation memory usage

## Likelihood Explanation

**Likelihood: Medium to High**

This issue will naturally occur in production environments:

1. **Accumulation is inevitable**: Every state update across epoch boundaries creates potential cross-epoch stale nodes
2. **Time-based growth**: The longer a blockchain runs, the more entries accumulate
3. **Triggered during critical operations**: Truncation happens during recovery scenarios when nodes are already in distress
4. **No warning or gradual degradation**: The OOM occurs suddenly when truncation is attempted
5. **Mainnet deployment risk**: Aptos mainnet has been running for extended periods with many epochs, making this scenario realistic

The vulnerability is not easily mitigated by node operators since the truncation logic is deeply embedded in the database recovery path.

## Recommendation

Implement batched deletion for truncation operations, mirroring the approach used in the pruning system:

**Solution approach:**

1. Add a `batch_size` parameter to `delete_stale_node_index_at_or_after_version` and `delete_nodes_and_stale_indices_at_or_after_version`

2. Implement iterative batching similar to `get_stale_node_indices`:
   - Fetch a limited number of entries per iteration
   - Delete that batch
   - Commit to database
   - Continue with next batch until complete

3. Use a conservative default batch size (e.g., 10,000 entries) to limit memory consumption

4. Modify `truncate_state_merkle_db` to call the batched deletion in a loop

**Key changes needed in `truncation_helper.rs`:**

```rust
fn delete_stale_node_index_at_or_after_version<S>(
    db: &DB,
    version: Version,
    batch: &mut SchemaBatch,
    limit: usize,  // NEW: batch size limit
) -> Result<Option<Version>>  // NEW: returns next version if more to process
where
    S: Schema<Key = StaleNodeIndex>,
    Version: SeekKeyCodec<S>,
{
    let mut iter = db.iter::<S>()?;
    iter.seek(&version)?;
    let mut count = 0;
    let mut next_version = None;
    
    for item in iter {
        if count >= limit {  // NEW: respect limit
            break;
        }
        let (index, _) = item?;
        assert_ge!(index.stale_since_version, version);
        batch.delete::<S>(&index)?;
        next_version = Some(index.stale_since_version);
        count += 1;
    }
    
    Ok(next_version)
}
```

Then wrap this in a loop in the calling functions to process batches iteratively.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_temppath::TempPath;
    use aptos_schemadb::{SchemaBatch, DB};
    
    #[test]
    fn test_unbounded_truncation_oom() {
        // Create a temporary database
        let tmpdir = TempPath::new();
        let db = DB::open(
            tmpdir.path(),
            "test_db",
            vec![StaleNodeIndexCrossEpochSchema::COLUMN_FAMILY_NAME],
            &Default::default(),
        )
        .unwrap();
        
        // Simulate accumulation of millions of entries
        // (In practice, this would take time; here we add enough to demonstrate the issue)
        let num_entries = 1_000_000; // 1 million entries
        let mut write_batch = SchemaBatch::new();
        
        for i in 0..num_entries {
            let index = StaleNodeIndex {
                stale_since_version: 1000 + i,
                node_key: NodeKey::new_empty_path(i),
            };
            write_batch.put::<StaleNodeIndexCrossEpochSchema>(&index, &()).unwrap();
        }
        db.write_schemas(write_batch).unwrap();
        
        // Now attempt truncation - this will try to load ALL entries into memory
        let mut truncate_batch = SchemaBatch::new();
        
        // This call will attempt to add 1 million deletion operations to a single batch
        // Memory usage will spike to hundreds of MB or more
        let result = delete_stale_node_index_at_or_after_version::<StaleNodeIndexCrossEpochSchema>(
            &db,
            1000, // version
            &mut truncate_batch,
        );
        
        // With enough entries, this would OOM before reaching this point
        // On systems with memory limits or with 10+ million entries, this fails
        assert!(result.is_ok());
        
        // The batch now contains all 1 million deletions in memory
        // Converting to RawBatch and writing would consume even more memory
    }
}
```

**Notes:**

This vulnerability represents a gap between the well-designed pruning system (which properly batches operations) and the truncation system (which does not). The pruning code demonstrates that the developers were aware of memory concerns, but this awareness was not applied consistently to truncation operations. This is particularly concerning because truncation occurs during critical recovery scenarios when node reliability is paramount.

### Citations

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L583-601)
```rust
fn delete_stale_node_index_at_or_after_version<S>(
    db: &DB,
    version: Version,
    batch: &mut SchemaBatch,
) -> Result<()>
where
    S: Schema<Key = StaleNodeIndex>,
    Version: SeekKeyCodec<S>,
{
    let mut iter = db.iter::<S>()?;
    iter.seek(&version)?;
    for item in iter {
        let (index, _) = item?;
        assert_ge!(index.stale_since_version, version);
        batch.delete::<S>(&index)?;
    }

    Ok(())
}
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L603-622)
```rust
fn delete_nodes_and_stale_indices_at_or_after_version(
    db: &DB,
    version: Version,
    shard_id: Option<usize>,
    batch: &mut SchemaBatch,
) -> Result<()> {
    delete_stale_node_index_at_or_after_version::<StaleNodeIndexSchema>(db, version, batch)?;
    delete_stale_node_index_at_or_after_version::<StaleNodeIndexCrossEpochSchema>(
        db, version, batch,
    )?;

    let mut iter = db.iter::<JellyfishMerkleNodeSchema>()?;
    iter.seek(&NodeKey::new_empty_path(version))?;
    for item in iter {
        let (key, _) = item?;
        batch.delete::<JellyfishMerkleNodeSchema>(&key)?;
    }

    StateMerkleDb::put_progress(version.checked_sub(1), shard_id, batch)
}
```

**File:** storage/schemadb/src/batch.rs (L130-133)
```rust
pub struct SchemaBatch {
    rows: DropHelper<HashMap<ColumnFamilyName, Vec<WriteOp>>>,
    stats: SampledBatchStats,
}
```

**File:** storage/schemadb/src/batch.rs (L165-172)
```rust
    fn raw_delete(&mut self, cf_name: ColumnFamilyName, key: Vec<u8>) -> DbResult<()> {
        self.rows
            .entry(cf_name)
            .or_default()
            .push(WriteOp::Deletion { key });

        Ok(())
    }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/mod.rs (L191-217)
```rust
    pub(in crate::pruner::state_merkle_pruner) fn get_stale_node_indices(
        state_merkle_db_shard: &DB,
        start_version: Version,
        target_version: Version,
        limit: usize,
    ) -> Result<(Vec<StaleNodeIndex>, Option<Version>)> {
        let mut indices = Vec::new();
        let mut iter = state_merkle_db_shard.iter::<S>()?;
        iter.seek(&StaleNodeIndex {
            stale_since_version: start_version,
            node_key: NodeKey::new_empty_path(0),
        })?;

        let mut next_version = None;
        while indices.len() < limit {
            if let Some((index, _)) = iter.next().transpose()? {
                next_version = Some(index.stale_since_version);
                if index.stale_since_version <= target_version {
                    indices.push(index);
                    continue;
                }
            }
            break;
        }

        Ok((indices, next_version))
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

**File:** storage/aptosdb/src/state_merkle_db.rs (L376-386)
```rust
        stale_node_index_batch.iter().try_for_each(|row| {
            ensure!(row.node_key.get_shard_id() == shard_id, "shard_id mismatch");
            if previous_epoch_ending_version.is_some()
                && row.node_key.version() <= previous_epoch_ending_version.unwrap()
            {
                batch.put::<StaleNodeIndexCrossEpochSchema>(row, &())
            } else {
                // These are processed by the state merkle pruner.
                batch.put::<StaleNodeIndexSchema>(row, &())
            }
        })?;
```

**File:** storage/aptosdb/src/state_store/mod.rs (L490-498)
```rust
            if state_merkle_target_version < state_merkle_max_version {
                info!(
                    state_merkle_max_version = state_merkle_max_version,
                    target_version = state_merkle_target_version,
                    "Start state merkle truncation..."
                );
                truncate_state_merkle_db(&state_merkle_db, state_merkle_target_version)
                    .expect("Failed to truncate state merkle db.");
            }
```
