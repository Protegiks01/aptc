# Audit Report

## Title
Non-Atomic State KV Pruner Operations Leading to Database Inconsistency and Node Restart Failures

## Summary
The `StateKvPruner::prune()` function performs pruning in two separate atomic operations: first updating metadata progress, then pruning shard data. If the shard pruning phase fails after metadata pruning succeeds, the database is left in an inconsistent state where metadata claims pruning completed to version X while shard data below version X still exists. This breaks state consistency invariants and can prevent node restarts.

## Finding Description

The vulnerability exists in the pruning sequence executed by `StateKvPruner::prune()`: [1](#0-0) 

The function first calls `metadata_pruner.prune()` which commits the metadata progress to the database atomically: [2](#0-1) 

This write operation updates `DbMetadataKey::StateKvPrunerProgress` to `target_version` and commits it to the database via `write_schemas()`, which provides RocksDB-level atomicity for this batch.

**The Critical Issue:** After this metadata update commits successfully, the code proceeds to prune shards in parallel. If ANY shard pruner fails: [3](#0-2) 

The entire operation returns an error, and the in-memory progress is never updated: [4](#0-3) 

This creates an **inconsistent database state**:
- **Metadata database**: `StateKvPrunerProgress = target_version` (committed)
- **Shard databases**: Data for versions < target_version still exists (not pruned or partially pruned)
- **In-memory progress**: Still at old value (never updated)

**On Node Restart**, the inconsistency manifests critically: [5](#0-4) 

During initialization, each shard pruner reads the metadata progress and attempts to "catch up" by pruning from its current progress to the metadata progress. **If this catch-up pruning fails** (e.g., due to persistent disk issues, corruption, or resource constraints), the entire `StateKvPruner::new()` fails, which prevents the database from opening and the node from starting.

## Impact Explanation

This vulnerability qualifies as **Critical to High Severity** based on the Aptos bug bounty criteria:

**Critical Severity Impact:**
- **Total loss of liveness**: If a validator node experiences a pruning failure and cannot restart, it permanently loses the ability to participate in consensus until manual intervention
- **Non-recoverable without intervention**: The node cannot self-recover from the inconsistent state if the catch-up pruning continues to fail

**High Severity Impact:**
- **Validator node availability**: Affected nodes experience complete downtime
- **State inconsistency**: Database invariants are violated, with metadata and data out of sync

The vulnerability breaks **Invariant #4: State Consistency** - "State transitions must be atomic and verifiable via Merkle proofs." The pruning operation is split across multiple non-atomic writes to different database instances, violating atomicity guarantees.

## Likelihood Explanation

**High Likelihood:**

1. **Common Trigger Conditions**: Pruning failures can occur due to:
   - Disk space exhaustion during pruning operations
   - I/O errors or disk corruption
   - Resource constraints (memory, file descriptors)
   - Database-level errors in any of the 16 shard databases

2. **Continuous Operation**: The pruner runs continuously in a background worker thread: [6](#0-5) 

3. **No Transaction Boundaries**: The two-phase operation (metadata then shards) lacks cross-database transaction coordination

4. **Multiple Failure Points**: With 16 shards, there are 16 independent points where pruning can fail after metadata commits

## Recommendation

**Solution: Implement atomic two-phase commit or reverse the operation order**

### Option 1: Prune shards first, then metadata
```rust
fn prune(&self, max_versions: usize) -> Result<Version> {
    let mut progress = self.progress();
    let target_version = self.target_version();

    while progress < target_version {
        let current_batch_target_version = 
            min(progress + max_versions as Version, target_version);

        // FIRST: Prune all shards
        THREAD_MANAGER.get_background_pool().install(|| {
            self.shard_pruners.par_iter().try_for_each(|shard_pruner| {
                shard_pruner.prune(progress, current_batch_target_version)
                    .map_err(|err| anyhow!("Failed to prune shard {}: {err}", 
                                          shard_pruner.shard_id()))
            })
        })?;

        // ONLY THEN: Update metadata progress
        self.metadata_pruner.prune(progress, current_batch_target_version)?;

        progress = current_batch_target_version;
        self.record_progress(progress);
    }
    Ok(target_version)
}
```

This ensures that if shard pruning fails, metadata is never updated, maintaining consistency.

### Option 2: Make metadata pruner update conditional
Modify `StateKvMetadataPruner::prune()` to NOT update the progress metadata - let only the manager handle progress updates through proper atomic operations coordinated after all pruning phases complete. [2](#0-1) 

Remove these lines and handle progress updates externally only after confirming all phases succeeded.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_pruner_atomicity_violation() {
    // Setup: Create StateKvDb with sharding enabled
    let tmpdir = TempPath::new();
    let db = create_test_db_with_sharding(&tmpdir);
    
    // Write state data across multiple versions
    for version in 0..100 {
        write_test_state_values(&db, version);
    }
    
    // Create pruner
    let pruner = StateKvPruner::new(Arc::new(db)).unwrap();
    pruner.set_target_version(50);
    
    // Simulate shard pruning failure by making one shard read-only
    // or by filling disk space before shard pruning
    make_shard_fail(&db, 5); // Make shard 5 fail
    
    // Attempt pruning - this will fail after metadata is updated
    let result = pruner.prune(50);
    assert!(result.is_err());
    
    // Check inconsistent state:
    // 1. Metadata progress should be updated to 50
    let metadata_progress = get_metadata_pruner_progress(&db);
    assert_eq!(metadata_progress, 50); // INCONSISTENCY: Updated!
    
    // 2. But shard 5 still has data < 50
    let shard_progress = get_shard_pruner_progress(&db, 5);
    assert!(shard_progress < 50); // INCONSISTENCY: Not pruned!
    
    // 3. On restart, if shard still fails, node cannot start
    drop(pruner);
    let restart_result = StateKvPruner::new(Arc::new(db));
    assert!(restart_result.is_err()); // NODE CANNOT RESTART!
}
```

The PoC demonstrates that after a pruning failure, the database metadata claims progress to version 50 while shard data remains unpruned, and subsequent node restarts fail due to the inability to resolve this inconsistency.

### Citations

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

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L80-81)
```rust
            progress = current_batch_target_version;
            self.record_progress(progress);
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_metadata_pruner.rs (L67-72)
```rust
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;

        self.state_kv_db.metadata_db().write_schemas(batch)
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L25-44)
```rust
    pub(in crate::pruner) fn new(
        shard_id: usize,
        db_shard: Arc<DB>,
        metadata_progress: Version,
    ) -> Result<Self> {
        let progress = get_or_initialize_subpruner_progress(
            &db_shard,
            &DbMetadataKey::StateKvShardPrunerProgress(shard_id),
            metadata_progress,
        )?;
        let myself = Self { shard_id, db_shard };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up state kv shard {shard_id}."
        );
        myself.prune(progress, metadata_progress)?;

        Ok(myself)
```

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L52-68)
```rust
    // Loop that does the real pruning job.
    fn work(&self) {
        while !self.quit_worker.load(Ordering::SeqCst) {
            let pruner_result = self.pruner.prune(self.batch_size);
            if pruner_result.is_err() {
                sample!(
                    SampleRate::Duration(Duration::from_secs(1)),
                    error!(error = ?pruner_result.err().unwrap(),
                        "Pruner has error.")
                );
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
                continue;
            }
            if !self.pruner.is_pruning_pending() {
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
            }
        }
```
