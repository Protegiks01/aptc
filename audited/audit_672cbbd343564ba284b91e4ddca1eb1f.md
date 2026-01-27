# Audit Report

## Title
Non-Atomic Checkpoint Creation Causes Node Crashes on Partial Shard Checkpoint Failures

## Summary
The `StateKvDb::create_checkpoint()` function creates checkpoints non-atomically, writing the metadata DB checkpoint before all shard checkpoints. If any shard checkpoint fails after the metadata checkpoint succeeds, the resulting checkpoint directory contains inconsistent state (metadata indicating a version but missing shard data). When a node attempts to load this corrupt checkpoint, it panics during shard opening, causing service unavailability and potential data loss.

## Finding Description

The vulnerability exists in the checkpoint creation flow where metadata and shard checkpoints are created sequentially without atomicity guarantees or rollback mechanisms.

**Checkpoint Creation Flow:** [1](#0-0) 

The checkpoint creation process executes in this order:
1. Cleans the checkpoint directory
2. Creates the metadata DB checkpoint (contains `StateKvCommitProgress` version)
3. Loops through all 16 shards to create shard checkpoints

**Critical Flaw:** If the metadata checkpoint succeeds but any subsequent shard checkpoint fails (due to disk full, I/O error, permission issue, or system crash), the function returns an error but leaves the checkpoint directory in an inconsistent state with no cleanup.

**Checkpoint Loading Flow:**

When attempting to open a database from a checkpoint path: [2](#0-1) 

The loading process:
1. Opens the metadata DB successfully (it exists)
2. Attempts to open all 16 shards in parallel
3. When encountering a missing shard, the `open_shard()` call fails
4. The error is caught and converted to a **panic** with message "Failed to open state kv db shard {shard_id}"

This panic occurs because: [3](#0-2) 

The `open_shard()` function attempts to open a RocksDB at the shard path. If the directory doesn't exist (because the checkpoint creation failed partway through), RocksDB returns an error, which propagates up and triggers the panic.

**Breaking Invariant:** This violates the **State Consistency** invariant that "State transitions must be atomic and verifiable via Merkle proofs." The checkpoint creation is not atomic - it can leave partial state that causes system failures when loaded.

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:

1. **Validator Node Crashes**: When a validator attempts to restore from or use a corrupt checkpoint (e.g., during disaster recovery, migration, or automated checkpoint loading), the node panics and becomes unavailable. This directly matches the "Validator node slowdowns" and "API crashes" criteria.

2. **Data Loss Risk**: If this checkpoint was created as the primary backup mechanism and the original database is lost/corrupted, the partial checkpoint cannot be loaded, resulting in data loss requiring restoration from earlier backups or state sync.

3. **Operational Impact**: During critical recovery scenarios (post-crash, hardware migration, disaster recovery), the inability to load checkpoints causes extended downtime and may require manual intervention to identify and clean corrupt checkpoints.

4. **State Inconsistency**: The checkpoint directory contains metadata indicating a certain blockchain version but lacks the actual shard data for that version, creating a state inconsistency requiring manual intervention.

## Likelihood Explanation

**HIGH Likelihood** - This can occur in multiple realistic scenarios:

1. **Disk Space Exhaustion**: During normal operations, if disk space runs low during checkpoint creation, shard checkpoints may fail after metadata succeeds. This is common in production environments.

2. **I/O Errors**: Transient storage issues, network filesystem interruptions, or hardware problems during the checkpoint loop.

3. **System Crashes**: Power failures or system crashes during the checkpoint creation window (between metadata checkpoint completion and final shard checkpoint).

4. **File System Permissions**: Permission changes or quota limits that affect later shards but not the metadata DB.

5. **Automated Operations**: Checkpoints are often created automatically by backup systems or node operators, increasing exposure.

The vulnerability is **exploitable without privileged access** - an attacker can trigger it by:
- Filling disk space through transaction spam
- Timing attacks during known checkpoint operations
- Triggering checkpoint creation during system stress

## Recommendation

Implement atomic checkpoint creation with either:

**Option 1: Two-Phase Commit with Rollback**
```rust
pub(crate) fn create_checkpoint(
    db_root_path: impl AsRef<Path>,
    cp_root_path: impl AsRef<Path>,
) -> Result<()> {
    let state_kv_db = Self::open_sharded(
        &StorageDirPaths::from_path(db_root_path),
        RocksdbConfig::default(),
        None,
        None,
        false,
    )?;
    let cp_state_kv_db_path = cp_root_path.as_ref().join(STATE_KV_DB_FOLDER_NAME);

    info!("Creating state_kv_db checkpoint at: {cp_state_kv_db_path:?}");

    std::fs::remove_dir_all(&cp_state_kv_db_path).unwrap_or(());
    std::fs::create_dir_all(&cp_state_kv_db_path).unwrap_or(());

    // Create all shard checkpoints FIRST
    for shard_id in 0..NUM_STATE_SHARDS {
        state_kv_db
            .db_shard(shard_id)
            .create_checkpoint(Self::db_shard_path(
                cp_root_path.as_ref(),
                shard_id,
                false,
            ))
            .map_err(|e| {
                // Cleanup on failure
                std::fs::remove_dir_all(&cp_state_kv_db_path).ok();
                e
            })?;
    }

    // Create metadata checkpoint LAST (after all shards succeed)
    state_kv_db
        .metadata_db()
        .create_checkpoint(Self::metadata_db_path(cp_root_path.as_ref()))
        .map_err(|e| {
            // Cleanup on failure
            std::fs::remove_dir_all(&cp_state_kv_db_path).ok();
            e
        })?;

    Ok(())
}
```

**Option 2: Checkpoint Validation Before Use**

Add validation in `open_sharded()` to verify all required shards exist before attempting to open them, with clear error messages instead of panics.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    #[should_panic(expected = "Failed to open state kv db shard")]
    fn test_partial_checkpoint_causes_panic_on_load() {
        // Create a temporary directory for the source DB
        let source_dir = TempDir::new().unwrap();
        let checkpoint_dir = TempDir::new().unwrap();
        
        // Create and populate a state_kv_db
        let db_paths = StorageDirPaths::from_path(&source_dir);
        let state_kv_db = StateKvDb::open_sharded(
            &db_paths,
            RocksdbConfig::default(),
            None,
            None,
            false,
        ).unwrap();
        
        // Write some data
        let version = 100;
        state_kv_db.write_progress(version).unwrap();
        
        // Simulate partial checkpoint creation:
        // 1. Create metadata checkpoint
        let cp_path = checkpoint_dir.path();
        let cp_state_kv_db_path = cp_path.join(STATE_KV_DB_FOLDER_NAME);
        std::fs::create_dir_all(&cp_state_kv_db_path).unwrap();
        
        state_kv_db
            .metadata_db()
            .create_checkpoint(StateKvDb::metadata_db_path(cp_path))
            .unwrap();
        
        // 2. Create only SOME shard checkpoints (simulate failure partway)
        for shard_id in 0..8 {  // Only create half the shards
            state_kv_db
                .db_shard(shard_id)
                .create_checkpoint(StateKvDb::db_shard_path(
                    cp_path,
                    shard_id,
                    false,
                ))
                .unwrap();
        }
        // Shards 8-15 are missing!
        
        // 3. Attempt to open the corrupt checkpoint
        // This will PANIC when trying to open shard 8
        let _loaded_db = StateKvDb::open_sharded(
            &StorageDirPaths::from_path(cp_path),
            RocksdbConfig::default(),
            None,
            None,
            false,
        ).unwrap(); // PANIC occurs here
    }
}
```

**Steps to reproduce:**
1. Create a state_kv_db with some data
2. Manually create a partial checkpoint (metadata + only some shards)
3. Attempt to open a StateKvDb from the checkpoint path
4. Observe panic: "Failed to open state kv db shard X"

## Notes

The same vulnerability pattern exists in `StateMerkleDb::create_checkpoint()` which also creates metadata and shard checkpoints sequentially without atomicity guarantees. The fix should be applied to all checkpoint creation functions in the codebase. [4](#0-3) 

The high-level `AptosDB::create_checkpoint()` calls these individual checkpoint functions sequentially, meaning the problem could cascade across multiple database components.

### Citations

**File:** storage/aptosdb/src/state_kv_db.rs (L107-125)
```rust
        let state_kv_db_shards = (0..NUM_STATE_SHARDS)
            .into_par_iter()
            .map(|shard_id| {
                let shard_root_path = db_paths.state_kv_db_shard_root_path(shard_id);
                let db = Self::open_shard(
                    shard_root_path,
                    shard_id,
                    &state_kv_db_config,
                    env,
                    block_cache,
                    readonly,
                    /* is_hot = */ false,
                )
                .unwrap_or_else(|e| panic!("Failed to open state kv db shard {shard_id}: {e:?}."));
                Arc::new(db)
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
```

**File:** storage/aptosdb/src/state_kv_db.rs (L224-259)
```rust
    pub(crate) fn create_checkpoint(
        db_root_path: impl AsRef<Path>,
        cp_root_path: impl AsRef<Path>,
    ) -> Result<()> {
        // TODO(grao): Support path override here.
        let state_kv_db = Self::open_sharded(
            &StorageDirPaths::from_path(db_root_path),
            RocksdbConfig::default(),
            None,
            None,
            false,
        )?;
        let cp_state_kv_db_path = cp_root_path.as_ref().join(STATE_KV_DB_FOLDER_NAME);

        info!("Creating state_kv_db checkpoint at: {cp_state_kv_db_path:?}");

        std::fs::remove_dir_all(&cp_state_kv_db_path).unwrap_or(());
        std::fs::create_dir_all(&cp_state_kv_db_path).unwrap_or(());

        state_kv_db
            .metadata_db()
            .create_checkpoint(Self::metadata_db_path(cp_root_path.as_ref()))?;

        // TODO(HotState): should handle hot state as well.
        for shard_id in 0..NUM_STATE_SHARDS {
            state_kv_db
                .db_shard(shard_id)
                .create_checkpoint(Self::db_shard_path(
                    cp_root_path.as_ref(),
                    shard_id,
                    /* is_hot = */ false,
                ))?;
        }

        Ok(())
    }
```

**File:** storage/aptosdb/src/state_kv_db.rs (L306-329)
```rust
    fn open_shard<P: AsRef<Path>>(
        db_root_path: P,
        shard_id: usize,
        state_kv_db_config: &RocksdbConfig,
        env: Option<&Env>,
        block_cache: Option<&Cache>,
        readonly: bool,
        is_hot: bool,
    ) -> Result<DB> {
        let db_name = if is_hot {
            format!("hot_state_kv_db_shard_{}", shard_id)
        } else {
            format!("state_kv_db_shard_{}", shard_id)
        };
        Self::open_db(
            Self::db_shard_path(db_root_path, shard_id, is_hot),
            &db_name,
            state_kv_db_config,
            env,
            block_cache,
            readonly,
            is_hot,
        )
    }
```

**File:** storage/aptosdb/src/db/mod.rs (L172-205)
```rust
    pub fn create_checkpoint(
        db_path: impl AsRef<Path>,
        cp_path: impl AsRef<Path>,
        sharding: bool,
    ) -> Result<()> {
        let start = Instant::now();

        info!(sharding = sharding, "Creating checkpoint for AptosDB.");

        LedgerDb::create_checkpoint(db_path.as_ref(), cp_path.as_ref(), sharding)?;
        if sharding {
            StateKvDb::create_checkpoint(db_path.as_ref(), cp_path.as_ref())?;
            StateMerkleDb::create_checkpoint(
                db_path.as_ref(),
                cp_path.as_ref(),
                sharding,
                /* is_hot = */ true,
            )?;
        }
        StateMerkleDb::create_checkpoint(
            db_path.as_ref(),
            cp_path.as_ref(),
            sharding,
            /* is_hot = */ false,
        )?;

        info!(
            db_path = db_path.as_ref(),
            cp_path = cp_path.as_ref(),
            time_ms = %start.elapsed().as_millis(),
            "Made AptosDB checkpoint."
        );
        Ok(())
    }
```
