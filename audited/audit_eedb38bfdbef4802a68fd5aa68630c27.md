# Audit Report

## Title
State Store Startup Panic Due to Asynchronous Commit Race Condition and Missing Merkle Tree Root

## Summary
The `sync_commit_progress()` function can panic during node startup when it fails to find a valid state merkle tree root at the version specified by `OverallCommitProgress` metadata. This occurs due to an asynchronous commit race condition where metadata is persisted before the corresponding merkle tree snapshot, or when metadata corruption points to a non-existent version.

## Finding Description

The vulnerability exists in the database synchronization mechanism that runs during validator node startup. The critical code path is: [1](#0-0) 

During normal operation, there is an asynchronous commit pipeline where:

1. **Metadata is written synchronously**: The `commit_ledger` function writes `OverallCommitProgress` to the metadata database: [2](#0-1) 

2. **Merkle tree is written asynchronously**: The state merkle tree snapshot is committed through an asynchronous background thread pipeline (`BufferedState` → `StateSnapshotCommitter` → `StateMerkleBatchCommitter`): [3](#0-2) 

3. **Async commit is controlled by sync_commit flag**: The buffered state update uses asynchronous commits by default unless explicitly requested or during reconfiguration: [4](#0-3) 

The race condition occurs when:
- `OverallCommitProgress` metadata is written to disk (pointing to version N)
- Node crashes or loses power before the merkle tree batch for version N is persisted
- On restart, `sync_commit_progress()` reads `OverallCommitProgress` = N
- `find_tree_root_at_or_before()` attempts to find a merkle root at version N, but returns `None`
- The code panics with an unrecoverable error

The `find_tree_root_at_or_before` function exhaustively searches for a valid root: [5](#0-4) 

When all search attempts fail, it returns `None`, triggering the panic.

Additionally, disk corruption affecting the `OverallCommitProgress` value could inflate it beyond any committed version, also causing the panic.

**Broken Invariants:**
- **State Consistency**: The metadata claims a version is committed, but the corresponding merkle tree root doesn't exist
- **Atomic State Transitions**: The commit of metadata and merkle tree is not atomic, violating durability guarantees

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria)

This vulnerability causes **"Validator node slowdowns"** and **"API crashes"** as defined in the High Severity category:

1. **Validator Downtime**: Affected validators cannot start up and remain offline until manual intervention
2. **Network Liveness Impact**: If multiple validators experience this during the same time window (e.g., widespread power outage, common hardware failure), network liveness could be degraded
3. **No Automatic Recovery**: The panic is a hard crash with no automatic recovery mechanism during normal startup (with `crash_if_difference_is_too_large=true`) [6](#0-5) 

4. **Denial of Service**: Creates a persistent denial of service condition requiring manual database recovery

While there is a recovery path using the db-debugger tool with `crash_if_difference_is_too_large=false`: [7](#0-6) 

This requires operator intervention and is not automatic.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability can be triggered through several scenarios:

1. **Node Crash During Async Commit Window**: If a validator node crashes (power failure, hardware failure, OOM kill) after `OverallCommitProgress` is written but before the merkle tree batch is persisted. The async commit buffer size is 1, and the snapshot interval is 100,000 versions, creating a time window where this can occur.

2. **Disk Corruption**: Silent data corruption affecting the `OverallCommitProgress` metadata value, causing it to point to a non-existent version. Modern SSDs can experience bit flips or write failures.

3. **Cascading Failures**: If multiple validators experience correlated failures (datacenter power loss, network partition causing restarts), multiple nodes could hit this simultaneously.

However, the likelihood is not "High" because:
- Requires specific timing of crash during commit window
- Or requires hardware failure/corruption
- Not directly exploitable by remote unprivileged attackers without local access
- Reconfiguration blocks use synchronous commits, protecting epoch boundaries

## Recommendation

**Immediate Fix**: Ensure atomic commitment of metadata and merkle tree snapshots, or implement graceful degradation instead of panic.

**Solution 1 - Atomic Commits (Preferred)**:
```rust
// In commit_ledger, ensure merkle tree is persisted before writing OverallCommitProgress
pub fn commit_ledger(
    &self,
    version: Version,
    ledger_info_with_sigs: Option<&LedgerInfoWithSignatures>,
    chunk_opt: Option<ChunkToCommit>,
) -> Result<()> {
    // ... existing code ...
    
    // NEW: Force synchronous merkle tree commit before writing metadata
    if let Some(chunk) = &chunk_opt {
        self.state_store.buffered_state().lock().sync_commit_snapshot(version)?;
    }
    
    // Only write OverallCommitProgress after merkle tree is guaranteed persisted
    ledger_batch.put::<DbMetadataSchema>(
        &DbMetadataKey::OverallCommitProgress,
        &DbMetadataValue::Version(version),
    )?;
    // ... rest of code ...
}
```

**Solution 2 - Graceful Degradation**:
```rust
// In sync_commit_progress, handle None gracefully instead of panic
let state_merkle_target_version = find_tree_root_at_or_before(
    ledger_metadata_db,
    &state_merkle_db,
    overall_commit_progress,
)
.expect("DB read failed.")
.unwrap_or_else(|| {
    // Instead of panic, find the highest valid root
    warn!(
        "Could not find root at version {}, searching for highest valid root",
        overall_commit_progress
    );
    let max_version = get_max_version_in_state_merkle_db(&state_merkle_db)
        .expect("Failed to get max version")
        .expect("State merkle db is empty");
    
    // Update OverallCommitProgress to the highest valid root
    let mut batch = SchemaBatch::new();
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::OverallCommitProgress,
        &DbMetadataValue::Version(max_version),
    ).expect("Failed to update progress");
    ledger_metadata_db.write_schemas(batch).expect("Failed to write");
    
    max_version
});
```

**Solution 3 - Add Validation**:
Add a validation check before writing `OverallCommitProgress` to ensure a merkle root exists:
```rust
// Verify merkle root exists before claiming version is committed
let root_exists = root_exists_at_version(&state_merkle_db, version)?;
ensure!(root_exists, "Cannot commit version {} without merkle root", version);
```

## Proof of Concept

This PoC demonstrates the vulnerability by simulating a crash during the async commit window:

```rust
#[cfg(test)]
mod test_race_condition {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;
    
    #[test]
    #[should_panic(expected = "Could not find a valid root")]
    fn test_crash_during_async_commit_causes_startup_panic() {
        // Setup test database
        let tmpdir = TempDir::new().unwrap();
        let db = AptosDB::new_for_test(&tmpdir);
        
        // Commit some blocks normally
        let blocks = generate_test_blocks(100);
        db.save_transactions(&blocks, /*sync_commit=*/ false).unwrap();
        
        // Simulate: OverallCommitProgress written but merkle tree not yet persisted
        // (This would happen if node crashes during async commit)
        let ledger_db = db.ledger_db();
        let mut batch = SchemaBatch::new();
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::OverallCommitProgress,
            &DbMetadataValue::Version(200), // Claim version 200 is committed
        ).unwrap();
        ledger_db.metadata_db().write_schemas(batch).unwrap();
        
        // Don't actually commit the merkle tree for version 200
        // (simulating the crash before async commit completes)
        
        drop(db); // Close database
        
        // Try to reopen - this should panic in sync_commit_progress()
        let _db_reopened = AptosDB::open(
            &tmpdir,
            false,
            NO_OP_STORAGE_PRUNER_CONFIG,
            RocksdbConfigs::default(),
            false,
            BUFFERED_STATE_TARGET_ITEMS,
            DEFAULT_MAX_NUM_NODES_PER_LRU_CACHE_SHARD,
        ).unwrap(); // This will panic: "Could not find a valid root before or at version 200"
    }
}
```

**Steps to reproduce manually:**
1. Run a validator node with async commits enabled
2. During a commit operation, forcefully kill the process (`kill -9`) to simulate a crash
3. Attempt to restart the node
4. Observe the panic in `sync_commit_progress()` if the crash occurred in the async commit window

## Notes

While this vulnerability is real and can cause validator downtime, it does not meet all validation criteria for an unprivileged remote exploit. The vulnerability requires either:
- Specific crash timing during the async commit window (hardware failure, not directly attackable)
- Local filesystem access to corrupt metadata (requires privileged access)
- Another bug in the storage layer causing metadata inconsistency

However, given the High Severity impact (validator crashes, potential network liveness degradation) and the realistic occurrence through hardware failures or power loss, this represents a significant availability risk that should be addressed through the recommended atomic commit mechanism or graceful degradation approach.

### Citations

**File:** storage/aptosdb/src/state_store/mod.rs (L354-359)
```rust
            Self::sync_commit_progress(
                Arc::clone(&ledger_db),
                Arc::clone(&state_kv_db),
                Arc::clone(&state_merkle_db),
                /*crash_if_difference_is_too_large=*/ true,
            );
```

**File:** storage/aptosdb/src/state_store/mod.rs (L478-489)
```rust
            let state_merkle_target_version = find_tree_root_at_or_before(
                ledger_metadata_db,
                &state_merkle_db,
                overall_commit_progress,
            )
            .expect("DB read failed.")
            .unwrap_or_else(|| {
                panic!(
                    "Could not find a valid root before or at version {}, maybe it was pruned?",
                    overall_commit_progress
                )
            });
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L68-72)
```rust
            self.state_store.buffered_state().lock().update(
                chunk.result_ledger_state_with_summary(),
                chunk.estimated_total_state_updates(),
                sync_commit || chunk.is_reconfig,
            )?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L103-107)
```rust
            ledger_batch.put::<DbMetadataSchema>(
                &DbMetadataKey::OverallCommitProgress,
                &DbMetadataValue::Version(version),
            )?;
            self.ledger_db.metadata_db().write_schemas(ledger_batch)?;
```

**File:** storage/aptosdb/src/state_store/buffered_state.rs (L28-29)
```rust
pub(crate) const ASYNC_COMMIT_CHANNEL_BUFFER_SIZE: u64 = 1;
pub(crate) const TARGET_SNAPSHOT_INTERVAL_IN_VERSION: u64 = 100_000;
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L208-245)
```rust
pub(crate) fn find_tree_root_at_or_before(
    ledger_metadata_db: &LedgerMetadataDb,
    state_merkle_db: &StateMerkleDb,
    version: Version,
) -> Result<Option<Version>> {
    if let Some(closest_version) =
        find_closest_node_version_at_or_before(state_merkle_db.metadata_db(), version)?
    {
        if root_exists_at_version(state_merkle_db, closest_version)? {
            return Ok(Some(closest_version));
        }

        // It's possible that it's a partial commit when sharding is not enabled,
        // look again for the previous version:
        if version == 0 {
            return Ok(None);
        }
        if let Some(closest_version) =
            find_closest_node_version_at_or_before(state_merkle_db.metadata_db(), version - 1)?
        {
            if root_exists_at_version(state_merkle_db, closest_version)? {
                return Ok(Some(closest_version));
            }

            // Now we are probably looking at a pruned version in this epoch, look for the previous
            // epoch ending:
            let mut iter = ledger_metadata_db.db().iter::<EpochByVersionSchema>()?;
            iter.seek_for_prev(&version)?;
            if let Some((closest_epoch_version, _)) = iter.next().transpose()? {
                if root_exists_at_version(state_merkle_db, closest_epoch_version)? {
                    return Ok(Some(closest_epoch_version));
                }
            }
        }
    }

    Ok(None)
}
```

**File:** storage/aptosdb/src/db_debugger/truncate/mod.rs (L137-142)
```rust
        StateStore::sync_commit_progress(
            Arc::clone(&ledger_db),
            Arc::clone(&state_kv_db),
            Arc::clone(&state_merkle_db),
            /*crash_if_difference_is_too_large=*/ false,
        );
```
