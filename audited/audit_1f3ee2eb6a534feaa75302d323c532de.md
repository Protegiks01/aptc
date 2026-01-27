# Audit Report

## Title
Metadata-Shard Desynchronization in StateKvPruner Causing Permanent Node Failure and State Inconsistency

## Summary
The `StateKvPruner` performs non-atomic pruning operations across multiple databases. When the metadata pruner succeeds but shard pruners fail, the metadata progress advances beyond shard progress, creating a permanent desynchronization that causes nodes to enter crash loops on restart and violates state consistency invariants.

## Finding Description

The `StateKvPruner::prune()` method executes pruning in two sequential, non-atomic phases: [1](#0-0) [2](#0-1) 

**Phase 1 (Line 64-65)**: The metadata pruner updates its progress marker to the target version and commits this to the metadata database. [3](#0-2) 

**Phase 2 (Line 67-78)**: Each shard pruner processes its data in parallel and commits progress to its respective shard database. [4](#0-3) 

**The Critical Flaw**: These are separate RocksDB instances with independent write operations. If Phase 1 succeeds but Phase 2 fails for any shard (due to disk I/O errors, corruption, out-of-space, etc.), the metadata progress advances while some shard progress remains behind.

**On Node Restart**: The initialization logic reads metadata progress and attempts to catch up all shards: [5](#0-4) [6](#0-5) 

If the underlying issue persists (e.g., corrupted data in the shard), the catch-up prune fails, and the initialization panics: [7](#0-6) 

**Invariant Violation**: This breaks the **State Consistency** invariant that "state transitions must be atomic and verifiable." The metadata claims data up to version X is pruned, but shard databases still contain data from earlier versions, creating an inconsistent view of the pruned state.

## Impact Explanation

**Critical Severity** - This vulnerability causes:

1. **Total Loss of Liveness/Network Availability**: Affected nodes enter permanent crash loops and cannot restart until manual database intervention. If multiple validators experience this simultaneously (e.g., during network-wide disk issues), the network loses consensus participants.

2. **Non-Recoverable State Inconsistency**: The metadata-shard desynchronization creates a state where:
   - The system believes data up to version X is pruned
   - Some shards still contain data from versions Y to X (where Y < X)
   - This violates pruning guarantees and storage invariants
   - Different nodes may have different pruning states if they fail at different points

3. **Consensus Safety Risk**: If different validators have different pruning states, they may serve different historical state queries, potentially affecting state sync and consensus verification.

Per the Aptos bug bounty criteria, this qualifies as **Critical Severity** due to "Total loss of liveness/network availability" and potentially requires hardfork-level intervention to recover affected nodes.

## Likelihood Explanation

**High Likelihood** - This vulnerability can be triggered by common operational failures:

- Disk I/O errors during pruning operations
- Out-of-disk-space conditions affecting one shard before others
- Filesystem corruption in a single shard database
- System crashes between Phase 1 and Phase 2 completion
- Hardware failures affecting specific disk partitions

The pruning operation runs periodically in production, and the 16-shard architecture means there are 16 independent failure points. The probability of at least one shard failing while metadata succeeds increases linearly with the number of shards.

## Recommendation

Implement atomic cross-database pruning using a two-phase commit protocol or consolidate progress tracking:

**Solution 1 - Defer Metadata Progress Update:**
Only update metadata progress after ALL shard pruners successfully complete. Modify the pruning logic to:

1. Execute all shard pruners first
2. Only update metadata progress if all shards succeed
3. Record main progress only after both phases complete

**Solution 2 - Implement Rollback on Failure:**
Add rollback logic to revert metadata progress if any shard fails:

1. Track initial metadata progress before pruning
2. If any shard fails, revert metadata progress to initial value
3. Ensure atomic cross-database consistency

**Solution 3 - Use Distributed Transaction Coordinator:**
Implement a proper distributed transaction protocol across all databases to ensure atomicity.

**Immediate Mitigation:**
Add retry logic with exponential backoff in the catch-up path, and implement alerts for metadata-shard desync detection to enable operator intervention before nodes enter crash loops.

## Proof of Concept

**Reproduction Steps:**

1. Set up an Aptos node with sharding enabled (16 shards)
2. Inject a fault into shard 8's database (simulate corruption or I/O error)
3. Trigger pruning operation:
   - Metadata pruner completes successfully (progress advances to version 1000)
   - Shards 0-7 complete successfully
   - Shard 8 fails with I/O error
   - Shards 9-15 may or may not complete
4. Observe: Main progress not updated due to error propagation
5. Restart the node
6. Observe: `StateKvPruner::new()` attempts to initialize
   - Reads metadata_progress = 1000
   - Attempts to catch up shard 8 from its old progress to 1000
   - Shard 8 catch-up fails again due to persistent fault
   - Node panics with "Failed to create state kv pruner."
7. Result: Node enters permanent crash loop

**Expected Behavior**: The node should either:
- Prune atomically across all databases, or
- Safely recover from partial failures without entering crash loops

**Actual Behavior**: Node permanently crashes and requires manual database repair.

## Notes

This vulnerability demonstrates a classic distributed systems problem: maintaining atomicity across multiple independent databases. The severity is amplified by the crash-on-failure design in the initialization path, which converts a transient failure into a permanent availability issue. The 16-shard architecture increases the attack surface by providing 16 independent failure points, any of which can trigger this condition.

### Citations

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L64-65)
```rust
            self.metadata_pruner
                .prune(progress, current_batch_target_version)?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L67-78)
```rust
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

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L117-117)
```rust
        let metadata_progress = metadata_pruner.progress()?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_metadata_pruner.rs (L67-72)
```rust
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;

        self.state_kv_db.metadata_db().write_schemas(batch)
```

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

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L66-71)
```rust
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::StateKvShardPrunerProgress(self.shard_id),
            &DbMetadataValue::Version(target_version),
        )?;

        self.db_shard.write_schemas(batch)
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_pruner_manager.rs (L114-115)
```rust
        let pruner =
            Arc::new(StateKvPruner::new(state_kv_db).expect("Failed to create state kv pruner."));
```
