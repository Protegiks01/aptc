# Audit Report

## Title
Permanent State Inconsistency in Sharded StateKv Pruner Due to Non-Atomic Progress Update

## Summary
The StateKv pruner in sharded mode has a critical atomicity gap where metadata progress is committed to disk before shard pruners complete their deletion work. If a process crash occurs between these operations, unpruned historical data remains permanently in affected shards due to a flawed recovery mechanism that assumes missing shard progress indicates first-time initialization rather than interrupted pruning.

## Finding Description

The vulnerability exists in the pruning coordination between `StateKvMetadataPruner` and `StateKvShardPruner`, involving a non-atomic two-phase update:

**Phase 1 - Metadata Progress Update (Premature Commit):**

In sharded mode, `StateKvMetadataPruner::prune()` iterates through all shards without performing any deletions, then immediately commits the metadata progress to disk. [1](#0-0)  The metadata progress is then persisted via a synchronous batch write. [2](#0-1) 

The write operation uses synchronous disk commits, ensuring durability before returning. [3](#0-2) [4](#0-3) 

**Phase 2 - Actual Shard Deletion (May Never Complete):**

After the metadata progress commit completes, `StateKvPruner::prune()` spawns parallel tasks to execute shard pruning. [5](#0-4) 

**The Atomicity Gap:**

If the process crashes after Phase 1 commits metadata progress (e.g., to version 200) but before Phase 2 completes shard deletion, the metadata indicates pruning is complete while shards still contain unpruned historical data.

**Broken Recovery Mechanism:**

On restart, `StateKvShardPruner::new()` invokes `get_or_initialize_subpruner_progress()` to determine shard progress. [6](#0-5) 

The recovery function has flawed logic: when shard progress is missing, it assumes first-time initialization and sets the shard progress to match the current metadata progress. [7](#0-6) 

After initialization, the code attempts a catch-up prune operation. [8](#0-7) 

**The No-op Prune:**

When both `progress` and `metadata_progress` equal 200 (due to incorrect initialization), `prune(200, 200)` is called. The pruning iterator seeks to version 200, but the `StaleStateValueIndexByKeyHashSchema` uses big-endian encoding with `stale_since_version` as the primary key field. [9](#0-8) 

The seek operation positions the iterator at entries with `stale_since_version >= 200`. [10](#0-9) [11](#0-10)  The loop only processes entries where `stale_since_version <= target_version` (200). [12](#0-11)  Entries with `stale_since_version < 200` are skipped by the seek operation and remain permanently unpruned.

**Invariant Violation:**

This breaks the state consistency invariant: the pruner's metadata claims data up to version 200 is pruned, while shards still contain unpruned historical entries for versions < 200. The pruning system will never revisit these versions.

## Impact Explanation

**Severity: Medium**

This vulnerability qualifies as **Medium severity** under Aptos bug bounty criteria: "State inconsistencies requiring manual intervention."

**Valid Impacts:**

1. **Storage Bloat**: Unpruned historical state values accumulate indefinitely across affected shards, eventually causing disk exhaustion and requiring manual cleanup or node replacement.

2. **Operational Complexity**: Each crash during pruning creates more orphaned data. Over time, the inconsistency compounds, making manual recovery increasingly difficult and requiring operator intervention.

3. **Production Reality**: This is triggered by normal operational events (crashes, OOM errors, hardware failures, upgrades) that occur regularly in production environments, not by adversarial actions.

4. **Systemic Issue**: Affects all nodes running with sharding enabled, making it a widespread operational concern.

**Important Clarifications:**

- **No Consensus Impact**: The pruner handles historical stale values (replaced state), not current state. State root calculations depend on current state only, so this does not affect consensus safety.
- **Limited Query Impact**: Queries for current state are unaffected. Only historical state queries would see inconsistency, which is a limited operational concern.

The debugging validation tool confirms no automated consistency check exists for pruner state. [13](#0-12) 

## Likelihood Explanation

**Likelihood: High**

This vulnerability has high probability of occurrence:

1. **Common Trigger**: Process crashes during pruning are common due to OOM errors, hardware failures, or system upgrades that interrupt ongoing operations.

2. **Significant Timing Window**: The vulnerable window spans from metadata commit (microseconds for the write) to shard pruning completion (potentially seconds to minutes for large batches processed in parallel).

3. **No Detection Mechanism**: There is no automated consistency check to detect orphaned data. Operators discover the issue only through disk space alerts or manual inspection.

4. **Cumulative Effect**: Each crash during pruning creates additional orphaned data without any self-healing mechanism.

5. **Growing Adoption**: As more operators enable sharding for performance, the affected population increases.

## Recommendation

Implement atomic progress tracking by deferring metadata progress updates until after all shard pruning completes:

1. **Reorder Operations**: Move metadata progress commit to occur AFTER all shard pruning tasks complete successfully.

2. **Transaction Coordinator**: Implement a two-phase commit coordinator that tracks all shard pruning completion before committing metadata progress.

3. **Recovery Enhancement**: Modify `get_or_initialize_subpruner_progress()` to detect interrupted pruning by checking if metadata progress exceeds shard progress, then trigger catch-up pruning from the actual shard progress (not metadata progress).

4. **Consistency Checker**: Add automated validation that compares metadata progress against actual shard content to detect and alert on inconsistencies.

## Proof of Concept

The vulnerability can be reproduced through crash injection testing:

1. Enable storage sharding on a test node
2. Allow pruner to start processing a batch (e.g., versions 0-200)
3. Inject a process kill immediately after `metadata_pruner.prune()` returns but before parallel shard pruning completes
4. Restart the node
5. Observe that metadata progress shows version 200, but shards contain unpruned entries for versions < 200
6. Verify that subsequent pruning operations never revisit these orphaned entries

**Notes:**

- This is a real operational issue affecting production deployments with sharding enabled
- The vulnerability requires no malicious actors - only normal operational crashes
- The state inconsistency is permanent and requires manual database repair or node replacement
- Each crash during pruning compounds the problem by creating more orphaned data across multiple version ranges

### Citations

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_metadata_pruner.rs (L35-50)
```rust
        if self.state_kv_db.enabled_sharding() {
            let num_shards = self.state_kv_db.num_shards();
            // NOTE: This can be done in parallel if it becomes the bottleneck.
            for shard_id in 0..num_shards {
                let mut iter = self
                    .state_kv_db
                    .db_shard(shard_id)
                    .iter::<StaleStateValueIndexByKeyHashSchema>()?;
                iter.seek(&current_progress)?;
                for item in iter {
                    let (index, _) = item?;
                    if index.stale_since_version > target_version {
                        break;
                    }
                }
            }
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_metadata_pruner.rs (L67-72)
```rust
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;

        self.state_kv_db.metadata_db().write_schemas(batch)
```

**File:** storage/schemadb/src/lib.rs (L307-309)
```rust
    pub fn write_schemas(&self, batch: impl IntoRawBatch) -> DbResult<()> {
        self.write_schemas_inner(batch, &sync_write_option())
    }
```

**File:** storage/schemadb/src/lib.rs (L374-377)
```rust
fn sync_write_option() -> rocksdb::WriteOptions {
    let mut opts = rocksdb::WriteOptions::default();
    opts.set_sync(true);
    opts
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L64-78)
```rust
            self.metadata_pruner
                .prune(progress, current_batch_target_version)?;

            THREAD_MANAGER.get_background_pool().install(|| {
                self.shard_pruners.par_iter().try_for_each(|shard_pruner| {
                    shard_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| {
                            anyhow!(
                                "Failed to prune state kv shard {}: {err}",
                                shard_pruner.shard_id(),
                            )
                        })
                })
            })?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L30-34)
```rust
        let progress = get_or_initialize_subpruner_progress(
            &db_shard,
            &DbMetadataKey::StateKvShardPrunerProgress(shard_id),
            metadata_progress,
        )?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L42-42)
```rust
        myself.prune(progress, metadata_progress)?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L57-57)
```rust
        iter.seek(&current_progress)?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L60-61)
```rust
            if index.stale_since_version > target_version {
                break;
```

**File:** storage/aptosdb/src/pruner/pruner_utils.rs (L50-57)
```rust
        if let Some(v) = sub_db.get::<DbMetadataSchema>(progress_key)? {
            v.expect_version()
        } else {
            sub_db.put::<DbMetadataSchema>(
                progress_key,
                &DbMetadataValue::Version(metadata_progress),
            )?;
            metadata_progress
```

**File:** storage/aptosdb/src/schema/stale_state_value_index_by_key_hash/mod.rs (L40-46)
```rust
    fn encode_key(&self) -> Result<Vec<u8>> {
        let mut encoded = vec![];
        encoded.write_u64::<BigEndian>(self.stale_since_version)?;
        encoded.write_u64::<BigEndian>(self.version)?;
        encoded.write_all(self.state_key_hash.as_ref())?;

        Ok(encoded)
```

**File:** storage/aptosdb/src/schema/stale_state_value_index_by_key_hash/mod.rs (L76-79)
```rust
impl SeekKeyCodec<StaleStateValueIndexByKeyHashSchema> for Version {
    fn encode_seek_key(&self) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
```

**File:** storage/aptosdb/src/db_debugger/validation.rs (L114-145)
```rust
pub fn verify_state_kvs(
    db_root_path: &Path,
    internal_db: &DB,
    target_ledger_version: u64,
) -> Result<()> {
    println!("Validating db statekeys");
    let storage_dir = StorageDirPaths::from_path(db_root_path);
    let state_kv_db =
        StateKvDb::open_sharded(&storage_dir, RocksdbConfig::default(), None, None, false)?;

    //read all statekeys from internal db and store them in mem
    let mut all_internal_keys = HashSet::new();
    let mut iter = internal_db.iter::<StateKeysSchema>()?;
    iter.seek_to_first();
    for (key_ind, state_key_res) in iter.enumerate() {
        let state_key = state_key_res?.0;
        let state_key_hash = state_key.hash();
        all_internal_keys.insert(state_key_hash);
        if key_ind % 10_000_000 == 0 {
            println!("Processed {} keys", key_ind);
        }
    }
    println!(
        "Number of state keys in internal db: {}",
        all_internal_keys.len()
    );
    for shard_id in 0..16 {
        let shard = state_kv_db.db_shard(shard_id);
        println!("Validating state_kv for shard {}", shard_id);
        verify_state_kv(shard, &all_internal_keys, target_ledger_version)?;
    }
    Ok(())
```
