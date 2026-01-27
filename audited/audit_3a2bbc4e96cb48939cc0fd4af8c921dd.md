# Audit Report

## Title
Missing Parameter Validation in StateKvShardPruner::prune() Enables Catastrophic Historical Data Deletion via Database Corruption

## Summary
The `StateKvShardPruner::prune()` function lacks validation of the invariant `current_progress ≤ target_version`, allowing catastrophic over-pruning of historical state data when database corruption causes the metadata pruner progress to be set to an excessively large value. During shard initialization, this can result in permanent deletion of all historical stale state, violating data retention policies and breaking state synchronization capabilities.

## Finding Description

The vulnerable function is located at: [1](#0-0) 

This function accepts two `Version` (u64) parameters without validating their ordering. The expected invariant is `current_progress ≤ target_version`, but this is never checked.

**Attack Path:**

1. **Database Corruption Trigger**: The `DbMetadataKey::StateKvPrunerProgress` value in the metadata database becomes corrupted to an extremely large value (e.g., due to disk corruption, memory bit flips, or bugs in other code paths writing this value): [2](#0-1) 

2. **Initialization Reads Corrupted Value**: On node restart, `StateKvPruner::new()` reads the corrupted metadata progress: [3](#0-2) 

3. **Shard Catch-Up with Corrupted Target**: For each shard, `StateKvShardPruner::new()` is called with the corrupted `metadata_progress` value: [4](#0-3) 

4. **Catastrophic Pruning Call**: In `StateKvShardPruner::new()`, the initialization logic calls prune with potentially catastrophic parameters: [5](#0-4) 

   If `progress = 100` (shard has low progress) and `metadata_progress = u64::MAX` (corrupted), the call becomes `prune(100, u64::MAX)`.

5. **Mass Deletion Executes**: The pruning logic seeks to `stale_since_version ≥ 100` and deletes ALL entries where `stale_since_version ≤ u64::MAX`: [6](#0-5) 

   This deletes the entire historical stale state from version 100 onwards, far exceeding the intended `prune_window` retention policy.

**Invariants Broken:**
- **State Consistency**: Data retention policies defined by `prune_window` are violated
- **State Synchronization Integrity**: Historical state needed for state sync is permanently deleted
- **Defensive Programming**: Function fails to validate critical preconditions despite operating on irreversible deletion operations

## Impact Explanation

This qualifies as **HIGH severity** under the Aptos bug bounty program for the following reasons:

**Significant Protocol Violation**: The pruning system is designed to maintain a configurable retention window (e.g., 10 million versions) for:
- State synchronization of new nodes
- Archival node operation  
- Historical query support
- Audit and compliance requirements

Over-pruning violates these guarantees, as evidenced by the retention policy enforcement: [7](#0-6) 

**State Inconsistency Requiring Intervention**: When historical state is deleted:
- New nodes cannot complete state synchronization from this node
- Archival functionality is permanently broken
- Recovery requires backup restoration or full network resync
- No in-protocol recovery mechanism exists

**Why Not Critical**: This is not Critical severity because:
- Does not affect current/live state (only historical stale values)
- Does not cause consensus failures or chain splits
- Does not result in fund theft or permanent fund freezing
- Requires database corruption as a trigger (not directly exploitable by external attacker)

## Likelihood Explanation

**Likelihood: Medium**

**Trigger Conditions:**
1. Database corruption affecting `DbMetadataKey::StateKvPrunerProgress` to an excessively large value
2. Node restart triggering re-initialization
3. Shard progress significantly lower than corrupted metadata progress

**Realistic Scenarios:**
- **Hardware Failures**: Disk corruption, memory bit flips in persistent storage
- **Software Bugs**: Bugs in pruner progress update logic writing incorrect values: [8](#0-7) 
  
  Note the lack of bounds checking before writing.

- **Crash Recovery Edge Cases**: Race conditions during partial database recovery after crashes
- **Malicious Node Operator** (lower probability): Validator operator with filesystem access could manually corrupt database files

**Frequency Assessment**: While database corruption is relatively rare in modern systems, the complete lack of defensive validation means ANY corruption event will trigger catastrophic consequences. Given the large number of Aptos validator nodes and the long-term operation requirements, this becomes a non-negligible risk.

## Recommendation

**Immediate Fix**: Add parameter validation at the start of `prune()`:

```rust
pub(in crate::pruner) fn prune(
    &self,
    current_progress: Version,
    target_version: Version,
) -> Result<()> {
    // Validate invariant: current_progress must not exceed target_version
    if current_progress > target_version {
        return Err(anyhow::anyhow!(
            "Invalid pruning parameters: current_progress ({}) > target_version ({}). \
             This indicates database corruption or a bug in the caller.",
            current_progress,
            target_version
        ));
    }
    
    let mut batch = SchemaBatch::new();
    // ... rest of existing implementation
}
```

**Additional Hardening**:

1. **Bounds Validation on Write**: Validate `target_version` against ledger state before writing:
```rust
pub(crate) fn write_pruner_progress(&self, version: Version) -> Result<()> {
    // Get latest committed version to validate against
    let latest_version = self.get_latest_version()?;
    if version > latest_version {
        return Err(anyhow::anyhow!(
            "Cannot set pruner progress ({}) beyond latest version ({})",
            version, latest_version
        ));
    }
    self.state_kv_metadata_db.put::<DbMetadataSchema>(
        &DbMetadataKey::StateKvPrunerProgress,
        &DbMetadataValue::Version(version),
    )
}
```

2. **Sanity Check on Read**: When reading metadata progress, validate it's within reasonable bounds of the actual chain height.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::db_metadata::{DbMetadataKey, DbMetadataSchema, DbMetadataValue};
    use aptos_temppath::TempPath;
    use aptos_schemadb::DB;
    
    #[test]
    fn test_catastrophic_pruning_with_corrupted_metadata() {
        // Setup: Create a test database
        let tmpdir = TempPath::new();
        let db = Arc::new(DB::open(
            tmpdir.path(),
            "test_db",
            vec![],
            &Default::default(),
        ).unwrap());
        
        // Simulate shard with low progress
        let shard_id = 0;
        db.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvShardPrunerProgress(shard_id),
            &DbMetadataValue::Version(100),
        ).unwrap();
        
        // Insert stale state entries from version 100 to 1000
        for version in 100..1000 {
            let index = StaleStateValueByKeyHashIndex {
                stale_since_version: version,
                version,
                state_key_hash: HashValue::random(),
            };
            db.put::<StaleStateValueIndexByKeyHashSchema>(&index, &()).unwrap();
        }
        
        // Simulate corrupted metadata progress (extremely large value)
        let corrupted_metadata_progress = u64::MAX;
        
        // This should fail with validation, but currently succeeds
        let pruner = StateKvShardPruner::new(
            shard_id,
            db.clone(),
            corrupted_metadata_progress,
        );
        
        // Expected: Function returns error due to invalid parameters
        // Actual: Function succeeds and deletes ALL historical data from 100 onwards
        assert!(pruner.is_err(), "Should reject corrupted metadata progress");
        
        // Verify data was NOT catastrophically deleted
        let remaining_count = db.iter::<StaleStateValueIndexByKeyHashSchema>()
            .unwrap()
            .count();
        assert_eq!(remaining_count, 900, "Historical data should be preserved");
    }
    
    #[test]
    fn test_reversed_parameters_scenario() {
        // Test what happens if parameters are accidentally reversed
        let tmpdir = TempPath::new();
        let db = Arc::new(DB::open(
            tmpdir.path(),
            "test_db",
            vec![],
            &Default::default(),
        ).unwrap());
        
        let pruner = StateKvShardPruner {
            shard_id: 0,
            db_shard: db.clone(),
        };
        
        // Reversed: current_progress > target_version
        let result = pruner.prune(1000, 100);
        
        // Expected: Should return error
        // Actual: Silently succeeds with no deletions but corrupts progress tracking
        assert!(result.is_err(), "Should reject reversed parameters");
    }
}
```

**Reproduction Steps:**
1. Start an Aptos node with state pruning enabled
2. Manually corrupt the `DbMetadataKey::StateKvPrunerProgress` value to `u64::MAX` using a database inspection tool
3. Restart the node
4. Observe that `StateKvShardPruner::new()` calls `prune(low_value, u64::MAX)`
5. Verify that all historical stale state is deleted beyond the intended retention window

---

**Notes:**

This vulnerability demonstrates a critical failure in defensive programming. Even though database corruption is the trigger, the complete absence of parameter validation in a function performing irreversible data deletion operations violates basic safety principles. The fix is trivial (3 lines of validation code), but the impact of the missing check is severe for node operators who experience database corruption events.

The issue is exacerbated by both parameters being the same type (`u64`), making them indistinguishable to the compiler if accidentally swapped by future code modifications. Type-safe wrappers (e.g., `CurrentProgress(u64)` vs `TargetVersion(u64)`) would provide additional compile-time protection against parameter confusion.

### Citations

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L30-42)
```rust
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
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L47-72)
```rust
    pub(in crate::pruner) fn prune(
        &self,
        current_progress: Version,
        target_version: Version,
    ) -> Result<()> {
        let mut batch = SchemaBatch::new();

        let mut iter = self
            .db_shard
            .iter::<StaleStateValueIndexByKeyHashSchema>()?;
        iter.seek(&current_progress)?;
        for item in iter {
            let (index, _) = item?;
            if index.stale_since_version > target_version {
                break;
            }
            batch.delete::<StaleStateValueIndexByKeyHashSchema>(&index)?;
            batch.delete::<StateValueByKeyHashSchema>(&(index.state_key_hash, index.version))?;
        }
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvShardPrunerProgress(self.shard_id),
            &DbMetadataValue::Version(target_version),
        )?;

        self.db_shard.write_schemas(batch)
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

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L115-117)
```rust
        let metadata_pruner = StateKvMetadataPruner::new(Arc::clone(&state_kv_db));

        let metadata_progress = metadata_pruner.progress()?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L128-132)
```rust
                shard_pruners.push(StateKvShardPruner::new(
                    shard_id,
                    state_kv_db.db_shard_arc(shard_id),
                    metadata_progress,
                )?);
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_pruner_manager.rs (L128-142)
```rust
    fn set_pruner_target_db_version(&self, latest_version: Version) {
        assert!(self.pruner_worker.is_some());
        let min_readable_version = latest_version.saturating_sub(self.prune_window);
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);

        PRUNER_VERSIONS
            .with_label_values(&["state_kv_pruner", "min_readable"])
            .set(min_readable_version as i64);

        self.pruner_worker
            .as_ref()
            .unwrap()
            .set_target_db_version(min_readable_version);
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
