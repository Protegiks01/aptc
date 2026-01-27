# Audit Report

## Title
TOCTOU Race Condition Between StateKvPruner Initialization and save_min_readable_version() Causes Database Progress Metadata Corruption

## Summary
A time-of-check-time-of-use (TOCTOU) race condition exists between `StateKvPruner` initialization reading progress from the database and `save_min_readable_version()` writing to the same database key. During fast sync finalization, this causes the pruner's in-memory progress to become stale, leading to database metadata inconsistency when the pruner subsequently overwrites the correct progress value.

## Finding Description
The vulnerability occurs due to unsynchronized access to the `DbMetadataKey::StateKvPrunerProgress` database key by two separate code paths:

**Path 1: Pruner Initialization (Time-of-Check)** [1](#0-0) 

The `StateKvPruner::new()` reads the current progress from the database via `metadata_pruner.progress()`: [2](#0-1) 

This value is then used to initialize the in-memory atomic progress: [3](#0-2) 

**Path 2: Fast Sync Finalization (Time-of-Use)** [4](#0-3) 

After fast sync completes, `save_min_readable_version()` is called, which writes directly to the same database key: [5](#0-4) [6](#0-5) 

**The Race Condition:**

Both `StateKvMetadataPruner::prune()` and `save_min_readable_version()` write to `DbMetadataKey::StateKvPrunerProgress`, but they represent different semantic concepts:
- `metadata_pruner.prune()` writes actual pruning progress
- `save_min_readable_version()` writes the minimum readable version after fast sync [7](#0-6) 

**Exploitation Scenario:**

1. Node initializes: `StateKvPruner::new()` reads `progress = 0` from empty database
2. In-memory progress is set to 0
3. Fast sync completes at version 1,000,000
4. `finalize_state_snapshot()` calls `save_min_readable_version(1,000,000)`
5. Database now has `StateKvPrunerProgress = 1,000,000`
6. StateKvPruner's in-memory progress remains 0 (stale)
7. Normal operation begins, pruner target is set
8. Pruner runs using stale progress=0: [8](#0-7) 

9. `metadata_pruner.prune(0, batch_target)` writes a value < 1,000,000 to the database
10. Database progress is corrupted, now inconsistent with actual state

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs" - the database metadata no longer accurately reflects the true state of available versions.

## Impact Explanation
This qualifies as **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

**Specific Impacts:**
1. **Database Metadata Corruption:** The pruner progress in the database becomes inconsistent with the actual state, indicating versions are unpruned when they don't exist
2. **Storage Inefficiency:** The pruner repeatedly iterates over non-existent version ranges attempting to prune data that was never synced
3. **Operational Confusion:** Monitoring systems and debugging tools relying on pruner progress metrics receive incorrect information
4. **Potential Node Instability:** If other components query pruner progress to determine version availability, they may receive inconsistent information leading to unexpected behavior

The issue does not directly lead to consensus violations or fund loss, but it corrupts critical database metadata that tracks the health and state of the storage system.

## Likelihood Explanation
**Likelihood: High** - This occurs during every fast sync operation, which is common for:
- New validator nodes joining the network
- Nodes recovering from extended downtime
- Archive nodes syncing historical state

The race window exists between pruner initialization and fast sync finalization, which are sequential operations in the startup path but operate on shared database state without synchronization.

## Recommendation
Synchronize the in-memory and database progress after `save_min_readable_version()` is called. Add a method to update the pruner's in-memory progress:

```rust
// In StateKvPruner (mod.rs)
pub(crate) fn update_progress_from_db(&self) -> Result<()> {
    let db_progress = self.metadata_pruner.progress()?;
    self.progress.store(db_progress, Ordering::SeqCst);
    self.target_version.store(db_progress, Ordering::SeqCst);
    Ok(())
}

// In StateKvPrunerManager::save_min_readable_version()
fn save_min_readable_version(&self, min_readable_version: Version) -> Result<()> {
    self.min_readable_version.store(min_readable_version, Ordering::SeqCst);
    
    PRUNER_VERSIONS
        .with_label_values(&["state_kv_pruner", "min_readable"])
        .set(min_readable_version as i64);
    
    self.state_kv_db.write_pruner_progress(min_readable_version)?;
    
    // Synchronize the pruner worker's in-memory progress
    if let Some(worker) = &self.pruner_worker {
        worker.update_progress_from_db()?;
    }
    
    Ok(())
}
```

## Proof of Concept
```rust
// Rust reproduction test (add to storage/aptosdb/src/pruner/state_kv_pruner/mod.rs)

#[cfg(test)]
mod toctou_test {
    use super::*;
    use crate::AptosDB;
    use aptos_temppath::TempPath;
    
    #[test]
    fn test_toctou_progress_corruption() {
        let tmpdir = TempPath::new();
        let db = AptosDB::new_for_test(&tmpdir);
        let state_kv_db = db.state_store.state_kv_db.clone();
        
        // Step 1: Initialize pruner with empty database (progress = 0)
        let pruner = StateKvPruner::new(state_kv_db.clone()).unwrap();
        assert_eq!(pruner.progress(), 0);
        
        // Step 2: Simulate fast sync completion writing progress = 1,000,000
        state_kv_db.write_pruner_progress(1_000_000).unwrap();
        
        // Step 3: Verify database has correct progress
        let db_progress = state_kv_db.metadata_db()
            .get::<DbMetadataSchema>(&DbMetadataKey::StateKvPrunerProgress)
            .unwrap()
            .unwrap()
            .expect_version();
        assert_eq!(db_progress, 1_000_000);
        
        // Step 4: Pruner's in-memory progress is stale (still 0)
        assert_eq!(pruner.progress(), 0);
        
        // Step 5: Simulate pruner running with stale progress
        pruner.set_target_version(100);
        let _ = pruner.prune(100);
        
        // Step 6: Database progress is corrupted (overwritten with value < 1,000,000)
        let corrupted_progress = state_kv_db.metadata_db()
            .get::<DbMetadataSchema>(&DbMetadataKey::StateKvPrunerProgress)
            .unwrap()
            .unwrap()
            .expect_version();
        
        // BUG: corrupted_progress != 1_000_000
        assert_ne!(corrupted_progress, 1_000_000, "Progress was corrupted by TOCTOU race");
    }
}
```

**Notes:**

This vulnerability specifically affects the fast sync path where `save_min_readable_version()` is called after pruner initialization. The lack of synchronization between `StateKvPruner`'s in-memory `progress` atomic and the database `StateKvPrunerProgress` key creates a critical inconsistency window. While not exploitable by external attackers, it corrupts database metadata during normal node operation, qualifying as a state consistency issue requiring intervention.

### Citations

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L52-65)
```rust
        let mut progress = self.progress();
        let target_version = self.target_version();

        while progress < target_version {
            let current_batch_target_version =
                min(progress + max_versions as Version, target_version);

            info!(
                progress = progress,
                target_version = current_batch_target_version,
                "Pruning state kv data."
            );
            self.metadata_pruner
                .prune(progress, current_batch_target_version)?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L117-117)
```rust
        let metadata_progress = metadata_pruner.progress()?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L141-141)
```rust
            progress: AtomicVersion::new(metadata_progress),
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_metadata_pruner.rs (L67-70)
```rust
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_metadata_pruner.rs (L75-81)
```rust
    pub(in crate::pruner) fn progress(&self) -> Result<Version> {
        Ok(get_progress(
            self.state_kv_db.metadata_db(),
            &DbMetadataKey::StateKvPrunerProgress,
        )?
        .unwrap_or(0))
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L234-234)
```rust
                .save_min_readable_version(version)?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_pruner_manager.rs (L57-66)
```rust
    fn save_min_readable_version(&self, min_readable_version: Version) -> Result<()> {
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);

        PRUNER_VERSIONS
            .with_label_values(&["state_kv_pruner", "min_readable"])
            .set(min_readable_version as i64);

        self.state_kv_db.write_pruner_progress(min_readable_version)
    }
```

**File:** storage/aptosdb/src/state_kv_db.rs (L217-222)
```rust
    pub(crate) fn write_pruner_progress(&self, version: Version) -> Result<()> {
        self.state_kv_metadata_db.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvPrunerProgress,
            &DbMetadataValue::Version(version),
        )
    }
```
