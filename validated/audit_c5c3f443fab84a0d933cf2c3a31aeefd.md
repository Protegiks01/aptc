# Audit Report

## Title
State KV Database Recovery Fails to Validate Per-Shard Progress Leading to Consensus Failure

## Summary

The `get_state_kv_commit_progress()` function used during database recovery in `open_sharded()` only reads the overall commit progress from the metadata database without checking individual shard progress values. This can lead to incomplete or incorrect truncation where some shards have their progress metadata set higher than their actual data, causing state inconsistency and consensus failures across the network.

## Finding Description

The vulnerability exists in the state KV database recovery logic during node restart. When `StateKvDb::open_sharded()` is called, it invokes recovery truncation to ensure database consistency: [1](#0-0) 

The recovery reads only the overall `StateKvCommitProgress` from the metadata database: [2](#0-1) 

This implementation does NOT check the per-shard progress values (`StateKvShardCommitProgress(shard_id)`) that are stored in each individual shard database. The schema defines these per-shard progress keys: [3](#0-2) 

During normal commits, each shard writes its own progress first, then the overall progress is written after all shards succeed: [4](#0-3) 

**The Critical Flaw:** When database inconsistency occurs (through corruption, partial restore, disk failure, or bugs), some shards may have less data than the overall progress indicates. The recovery code calls `truncate_state_kv_db_single_shard()` which blindly sets each shard's progress to the overall progress value without verifying the shard actually has data up to that version: [5](#0-4) 

The function deletes data from `target_version + 1` onwards (which is nothing if shard only has data up to `target_version - 1`), then sets the shard's progress metadata to `target_version` via `commit_single_shard()`: [6](#0-5) 

**Contrast with Pruner Code:** The pruner subsystem correctly handles this by checking each shard's progress individually using `get_or_initialize_subpruner_progress()`: [7](#0-6) [8](#0-7) 

The pruner reads existing shard progress first and only initializes to metadata_progress if no shard progress exists, ensuring consistency. The recovery code lacks this crucial validation.

**Attack Scenario:**
1. Database has overall progress = 1000 in metadata DB
2. Shards 0-14 have actual data and progress = 1000
3. Shard 15 has actual data only up to version 999 (due to corruption/restore issue)
4. Node restarts, recovery reads overall progress = 1000
5. Truncation sets shard 15's progress metadata to 1000, but actual data still only goes to 999
6. System now believes shard 15 has data for version 1000, but it doesn't
7. When executing transactions at version 1001, state reads for keys in shard 15 at version 1000 return incorrect/missing data
8. Different nodes with different corruption patterns execute transactions differently
9. This produces different write sets and different merkle trees
10. **Consensus failure** - validators compute different state roots and cannot agree

## Impact Explanation

This vulnerability meets **High Severity** criteria per the Aptos bug bounty program:

1. **Consensus Violations:** Nodes with inconsistent shard data will execute transactions differently, producing different write sets and computing different state roots for subsequent versions. This causes consensus disagreement where validators cannot agree on the canonical state, potentially leading to network splits.

2. **State Consistency Violation:** Breaks the critical invariant that progress metadata must accurately reflect actual data availability. The system believes data exists when it doesn't, violating state integrity guarantees.

3. **Non-Recoverable Without Manual Intervention:** Once shard progress metadata is incorrectly set ahead of actual data, normal operations cannot detect or fix this discrepancy. The system has no mechanism to verify that claimed progress matches actual data. Manual database reconstruction or restore from consistent backup is required.

4. **Affects All Validators:** Any validator experiencing database corruption, backup/restore inconsistencies, or disk failures could encounter this bug. Since the issue propagates through normal restart procedures, it affects operational reliability across the network.

This directly impacts consensus safety and state consistency, which are foundation-level guarantees required for blockchain operation. The vulnerability enables execution divergence without requiring Byzantine behavior, meeting the criteria for High severity consensus violations.

## Likelihood Explanation

**High Likelihood** due to multiple realistic triggering scenarios:

1. **Hardware Failures:** Disk corruption affecting some shard DBs but not the metadata DB is a common failure mode in production systems
2. **Backup/Restore Operations:** Restoring from backups where metadata DB and shard DBs are from different points in time is a common operational scenario
3. **Partial Crashes:** System crashes during commit operations could corrupt some database files while leaving others intact
4. **Manual Interventions:** Database maintenance, debugging, or recovery operations that modify metadata without properly updating all shards
5. **File System Issues:** Underlying file system corruption or inconsistencies affecting database files

The vulnerability is deterministic once the inconsistent state occurs - every node restart will set incorrect progress metadata through the flawed recovery logic. The commit flow has panic protection to prevent normal operation from creating this state, but external factors (corruption, restore, file system issues) can still trigger it.

Large-scale deployments with multiple validators are particularly susceptible as they routinely perform backup/restore operations and experience hardware failures over time.

## Recommendation

Implement per-shard progress validation in the recovery code, following the pattern used by the pruner subsystem:

1. **Read Individual Shard Progress:** Before truncating each shard, read its `StateKvShardCommitProgress(shard_id)` value
2. **Validate Against Overall Progress:** Ensure each shard's progress is consistent with the overall `StateKvCommitProgress`
3. **Handle Inconsistencies:** If a shard's progress is ahead of its actual data:
   - Log a critical error with shard ID and version mismatch
   - Either truncate to the actual data version or fail fast requiring manual intervention
   - Do not blindly set progress ahead of verified data

Example fix pattern (following pruner code):
```rust
// In truncate_state_kv_db_single_shard, before setting progress:
let existing_shard_progress = state_kv_db.db_shard(shard_id)
    .get::<DbMetadataSchema>(&DbMetadataKey::StateKvShardCommitProgress(shard_id))?
    .map(|v| v.expect_version());

// Validate shard can reach target_version
// Add verification logic here before commit_single_shard
```

Additionally:
4. **Add Consistency Checks:** Implement validation that reads actual data to verify shard has records up to the claimed progress
5. **Improve Error Detection:** Add monitoring to detect progress-vs-data mismatches
6. **Document Recovery Procedures:** Provide clear guidance for operators on handling database inconsistencies

## Proof of Concept

The vulnerability is demonstrated through code path analysis showing the recovery logic does not validate per-shard data availability before setting progress metadata. A concrete PoC would require:

1. Creating a database with overall progress at version N
2. Manually corrupting one shard's data to only contain data up to version N-1
3. Restarting the node and observing recovery sets the shard's progress to N
4. Executing transactions that read from the corrupted shard and observing execution divergence

The code citations provided demonstrate the vulnerable code paths exist in production code. The lack of per-shard progress validation in recovery (compared to the correct implementation in the pruner) confirms the vulnerability.

### Citations

**File:** storage/aptosdb/src/state_kv_db.rs (L164-168)
```rust
        if !readonly {
            if let Some(overall_kv_commit_progress) = get_state_kv_commit_progress(&state_kv_db)? {
                truncate_state_kv_db_shards(&state_kv_db, overall_kv_commit_progress)?;
            }
        }
```

**File:** storage/aptosdb/src/state_kv_db.rs (L177-208)
```rust
    pub(crate) fn commit(
        &self,
        version: Version,
        state_kv_metadata_batch: Option<SchemaBatch>,
        sharded_state_kv_batches: ShardedStateKvSchemaBatch,
    ) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_db__commit"]);
        {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_db__commit_shards"]);
            THREAD_MANAGER.get_io_pool().scope(|s| {
                let mut batches = sharded_state_kv_batches.into_iter();
                for shard_id in 0..NUM_STATE_SHARDS {
                    let state_kv_batch = batches
                        .next()
                        .expect("Not sufficient number of sharded state kv batches");
                    s.spawn(move |_| {
                        // TODO(grao): Consider propagating the error instead of panic, if necessary.
                        self.commit_single_shard(version, shard_id, state_kv_batch)
                            .unwrap_or_else(|err| {
                                panic!("Failed to commit shard {shard_id}: {err}.")
                            });
                    });
                }
            });
        }
        if let Some(batch) = state_kv_metadata_batch {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_db__commit_metadata"]);
            self.state_kv_metadata_db.write_schemas(batch)?;
        }

        self.write_progress(version)
    }
```

**File:** storage/aptosdb/src/state_kv_db.rs (L293-304)
```rust
    pub(crate) fn commit_single_shard(
        &self,
        version: Version,
        shard_id: usize,
        mut batch: impl WriteBatch,
    ) -> Result<()> {
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvShardCommitProgress(shard_id),
            &DbMetadataValue::Version(version),
        )?;
        self.state_kv_db_shards[shard_id].write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L57-62)
```rust
pub(crate) fn get_state_kv_commit_progress(state_kv_db: &StateKvDb) -> Result<Option<Version>> {
    get_progress(
        state_kv_db.metadata_db(),
        &DbMetadataKey::StateKvCommitProgress,
    )
}
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L129-142)
```rust
pub(crate) fn truncate_state_kv_db_single_shard(
    state_kv_db: &StateKvDb,
    shard_id: usize,
    target_version: Version,
) -> Result<()> {
    let mut batch = SchemaBatch::new();
    delete_state_value_and_index(
        state_kv_db.db_shard(shard_id),
        target_version + 1,
        &mut batch,
        state_kv_db.enabled_sharding(),
    )?;
    state_kv_db.commit_single_shard(target_version, shard_id, batch)
}
```

**File:** storage/aptosdb/src/schema/db_metadata/mod.rs (L58-58)
```rust
    StateKvShardCommitProgress(ShardId),
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L30-34)
```rust
        let progress = get_or_initialize_subpruner_progress(
            &db_shard,
            &DbMetadataKey::StateKvShardPrunerProgress(shard_id),
            metadata_progress,
        )?;
```

**File:** storage/aptosdb/src/pruner/pruner_utils.rs (L44-60)
```rust
pub(crate) fn get_or_initialize_subpruner_progress(
    sub_db: &DB,
    progress_key: &DbMetadataKey,
    metadata_progress: Version,
) -> Result<Version> {
    Ok(
        if let Some(v) = sub_db.get::<DbMetadataSchema>(progress_key)? {
            v.expect_version()
        } else {
            sub_db.put::<DbMetadataSchema>(
                progress_key,
                &DbMetadataValue::Version(metadata_progress),
            )?;
            metadata_progress
        },
    )
}
```
