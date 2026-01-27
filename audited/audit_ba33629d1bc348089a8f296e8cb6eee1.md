# Audit Report

## Title
Orphaned Merkle Nodes and Recovery Failure Due to Disk Space Exhaustion in State Commit Process

## Summary
The state merkle commit process can leave orphaned merkle nodes when disk space exhaustion causes partial commit failures. If disk remains full, the automatic recovery mechanism itself fails, preventing validator node startup and causing prolonged unavailability.

## Finding Description

The vulnerability exists in the state merkle commit pipeline where merkle nodes are committed to multiple separate RocksDB instances non-atomically. [1](#0-0) 

The commit process follows this sequence:

1. **Hot state merkle commits** (if present) - writes to hot_state_merkle_db
2. **Cold state merkle commits** - writes to state_merkle_db shards and metadata [2](#0-1) 

The critical issue is that shard commits happen in parallel across 16 separate RocksDB instances, followed by the top level commit to the metadata database. These commits are **not atomic across databases**.

**Attack Scenario:**

1. Validator's disk is near capacity (through normal operations or attacker spam)
2. Transaction batch commits at version V
3. Shard commits succeed - merkle nodes written to shard databases
4. Disk space exhausts during parallel shard commits or before top level commit
5. Top level commit fails - no root node or progress marker written at version V
6. System panics with `.expect("State merkle nodes commit failed.")`
7. **Orphaned nodes now exist in shard databases at version V without a corresponding root node**

On restart, the recovery mechanism attempts to clean up: [3](#0-2) 

The recovery calls `sync_commit_progress()` which discovers the orphaned nodes and attempts truncation: [4](#0-3) 

**Critical Failure Point:**

The truncation itself requires disk writes to commit deletion batches: [5](#0-4) 

If disk remains full (or has insufficient space), the `write_schemas(batch)` call fails. Since the recovery uses `.expect()`, the node panics during startup and **cannot recover without manual disk space cleanup**.

This violates the **State Consistency** invariant: orphaned merkle nodes exist that are not referenced by any valid snapshot (no root node at version V), and the system cannot automatically recover from this inconsistent state.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:

1. **Validator node slowdowns/crashes** - The validator cannot start until manual intervention
2. **Significant protocol violations** - State consistency invariant is violated with orphaned data
3. **Availability impact** - Extended downtime affects consensus participation and validator rewards

While a single validator is affected (not network-wide), the attack can be:
- **Repeated** - Each commit failure adds more orphaned nodes, compounding the problem
- **Coordinated** - Multiple validators with insufficient disk space could be targeted simultaneously
- **Persistent** - Orphaned nodes remain until successful recovery or manual cleanup

The impact does not reach Critical severity because:
- No direct fund loss or theft
- Network continues with remaining validators (tolerates up to 1/3 failures)
- Recoverable with manual intervention (free disk space)
- Doesn't require hardfork

## Likelihood Explanation

**Likelihood: Medium-High**

**Prerequisites:**
- Validator with limited disk space (approaching capacity)
- Ongoing transaction processing during commit phase
- Disk exhaustion at critical timing window

**Exploitability:**
- **Attacker capability**: Submit large transactions or spam transactions to increase state growth
- **Environmental factor**: Validators with poor disk management are vulnerable
- **Timing**: Natural occurrence during high transaction volume, or induced by attacker

**Mitigating factors:**
- Monitoring alerts at <200GB and <50GB disk space (but requires operator response)
- Well-maintained validators should not reach capacity
- RocksDB may have internal disk space reserves

**Aggravating factors:**
- Orphaned nodes accumulate with each failure, accelerating disk exhaustion
- Recovery requires additional disk space, creating catch-22 if disk is full
- Attack can be repeated until validator is DoS'd

## Recommendation

Implement atomic commit guarantees and graceful disk space handling:

**1. Add pre-flight disk space checks:**
```rust
// Before commit, verify sufficient disk space
fn check_disk_space_available(&self, required_bytes: u64) -> Result<()> {
    let available = get_available_disk_space()?;
    ensure!(
        available > required_bytes + MINIMUM_RESERVE,
        "Insufficient disk space for commit"
    );
    Ok(())
}
```

**2. Implement transactional rollback on partial failure:**
```rust
// In state_merkle_db.rs commit()
pub(crate) fn commit(
    &self,
    version: Version,
    top_levels_batch: impl IntoRawBatch,
    batches_for_shards: Vec<impl IntoRawBatch + Send>,
) -> Result<()> {
    // Track successful shard commits for rollback
    let mut committed_shards = Vec::new();
    
    let shard_results: Vec<Result<()>> = THREAD_MANAGER.get_io_pool().install(|| {
        batches_for_shards
            .into_par_iter()
            .enumerate()
            .map(|(shard_id, batch)| {
                self.db_shard(shard_id).write_schemas(batch)
            })
            .collect()
    });
    
    // Check for failures before committing top level
    for (shard_id, result) in shard_results.iter().enumerate() {
        match result {
            Ok(()) => committed_shards.push(shard_id),
            Err(e) => {
                // Rollback successful shard commits
                warn!("Shard {} commit failed, rolling back", shard_id);
                self.rollback_shards(&committed_shards, version)?;
                return Err(anyhow!("Shard commit failed: {}", e));
            }
        }
    }
    
    // Only commit top level if all shards succeeded
    self.commit_top_levels(version, top_levels_batch)
}
```

**3. Add recovery safeguards:**
```rust
// In sync_commit_progress, handle truncation failure gracefully
match truncate_state_merkle_db(&state_merkle_db, state_merkle_target_version) {
    Ok(()) => info!("State merkle truncation successful"),
    Err(e) => {
        error!("State merkle truncation failed: {}. Manual intervention required.", e);
        // Instead of panic, enter safe mode or retry with backoff
        return Err(anyhow!("Recovery failed - insufficient disk space"));
    }
}
```

**4. Monitor and alert on orphaned nodes:**
Add metrics to detect orphaned nodes during startup and alert operators before attempting recovery.

## Proof of Concept

```rust
// Reproduction steps (conceptual - requires actual disk space manipulation):

#[test]
fn test_orphaned_nodes_on_disk_exhaustion() {
    // 1. Setup validator with limited disk space
    let temp_dir = TempPath::new();
    set_disk_quota(&temp_dir, SMALL_QUOTA);
    
    let db = AptosDB::new_for_test(&temp_dir);
    let state_store = &db.state_store;
    
    // 2. Fill disk near capacity
    for i in 0..1000 {
        let txn = create_large_transaction(i);
        db.save_transactions(&[txn], version, None).unwrap();
    }
    
    // 3. Attempt commit that will exceed disk space
    let large_state_commit = create_state_commit_exceeding_space();
    
    // 4. Trigger commit - should fail during shard or top level write
    let result = state_store.commit(large_state_commit);
    assert!(result.is_err());
    
    // 5. Verify orphaned nodes exist
    let max_version = get_max_version_in_state_merkle_db(&db.state_merkle_db).unwrap();
    let root_version = db.state_merkle_db
        .get_state_snapshot_version_before(max_version + 1)
        .unwrap();
    
    // max_version > root_version indicates orphaned nodes
    assert!(max_version > root_version, "Orphaned nodes detected");
    
    // 6. Attempt restart/recovery - should fail with full disk
    drop(db);
    let recovery_result = AptosDB::new_for_test(&temp_dir);
    assert!(recovery_result.is_err(), "Recovery failed as expected with full disk");
    
    // 7. Manual cleanup required
    free_disk_space(&temp_dir);
    let recovered_db = AptosDB::new_for_test(&temp_dir).unwrap();
    
    // Verify orphaned nodes were cleaned up
    let final_max = get_max_version_in_state_merkle_db(&recovered_db.state_merkle_db).unwrap();
    let final_root = recovered_db.state_merkle_db
        .get_state_snapshot_version_before(final_max + 1)
        .unwrap();
    assert_eq!(final_max, final_root, "No orphaned nodes after recovery");
}
```

## Notes

This vulnerability represents a **state consistency violation** where the atomic commit invariant is broken across multiple database instances. The compound effect of orphaned data and recovery failure creates a validator availability issue requiring manual intervention. The attack surface is expanded by the fact that disk space exhaustion can occur naturally or be induced by transaction spam, making this a realistic threat to validators with inadequate disk monitoring or capacity planning.

### Citations

**File:** storage/aptosdb/src/state_store/state_merkle_batch_committer.rs (L69-81)
```rust
                    if let Some(hot_state_merkle_batch) = hot_batch {
                        self.commit(
                            self.state_db
                                .hot_state_merkle_db
                                .as_ref()
                                .expect("Hot state merkle db must exist."),
                            current_version,
                            hot_state_merkle_batch,
                        )
                        .expect("Hot state merkle nodes commit failed.");
                    }
                    self.commit(&self.state_db.state_merkle_db, current_version, cold_batch)
                        .expect("State merkle nodes commit failed.");
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L147-171)
```rust
    pub(crate) fn commit(
        &self,
        version: Version,
        top_levels_batch: impl IntoRawBatch,
        batches_for_shards: Vec<impl IntoRawBatch + Send>,
    ) -> Result<()> {
        ensure!(
            batches_for_shards.len() == NUM_STATE_SHARDS,
            "Shard count mismatch."
        );
        THREAD_MANAGER.get_io_pool().install(|| {
            batches_for_shards
                .into_par_iter()
                .enumerate()
                .for_each(|(shard_id, batch)| {
                    self.db_shard(shard_id)
                        .write_schemas(batch)
                        .unwrap_or_else(|err| {
                            panic!("Failed to commit state merkle shard {shard_id}: {err}")
                        });
                })
        });

        self.commit_top_levels(version, top_levels_batch)
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L354-359)
```rust
            Self::sync_commit_progress(
                Arc::clone(&ledger_db),
                Arc::clone(&state_kv_db),
                Arc::clone(&state_merkle_db),
                /*crash_if_difference_is_too_large=*/ true,
            );
```

**File:** storage/aptosdb/src/state_store/mod.rs (L490-497)
```rust
            if state_merkle_target_version < state_merkle_max_version {
                info!(
                    state_merkle_max_version = state_merkle_max_version,
                    target_version = state_merkle_target_version,
                    "Start state merkle truncation..."
                );
                truncate_state_merkle_db(&state_merkle_db, state_merkle_target_version)
                    .expect("Failed to truncate state merkle db.");
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L193-206)
```rust
pub(crate) fn truncate_state_merkle_db_single_shard(
    state_merkle_db: &StateMerkleDb,
    shard_id: usize,
    target_version: Version,
) -> Result<()> {
    let mut batch = SchemaBatch::new();
    delete_nodes_and_stale_indices_at_or_after_version(
        state_merkle_db.db_shard(shard_id),
        target_version + 1,
        Some(shard_id),
        &mut batch,
    )?;
    state_merkle_db.db_shard(shard_id).write_schemas(batch)
}
```
