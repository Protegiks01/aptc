# Audit Report

## Title
Non-Atomic Two-Database Write During Event Pruning Causes Unrecoverable Node Startup Failure on Disk Space Exhaustion

## Summary
A disk space exhaustion during `EventStorePruner::prune()` at line 80 can cause a split-brain metadata state between the Indexer DB and Event DB. The partial write success leaves databases in an inconsistent state, and the recovery logic during node restart requires disk writes that will fail if space remains insufficient, causing the node to panic during initialization and preventing startup indefinitely. [1](#0-0) 

## Finding Description
The vulnerability stems from a non-atomic two-database write operation in the event pruning logic. When `EventStorePruner::prune()` executes:

1. **First write** (line 78): Successfully writes to the Indexer DB, updating `EventPrunerProgress` metadata and deleting event indices [2](#0-1) 

2. **Second write** (line 80): Fails due to disk space exhaustion when writing to the Event DB, leaving event data and metadata un-updated [3](#0-2) 

This creates a **split-brain metadata state**:
- Indexer DB: `EventPrunerProgress` = target_version (e.g., 1100)
- Event DB: `EventPrunerProgress` = old value (e.g., 1000)
- Event data for versions 1000-1100: Indices deleted, but actual events remain

The critical failure occurs during node restart. The `EventStorePruner::new()` initialization attempts to reconcile this inconsistency by reading the Event DB progress and calling `prune()` to catch up: [4](#0-3) 

However, this catch-up operation requires writing to disk. If disk space remains insufficient, the write fails, causing the error to propagate through the initialization chain: [5](#0-4) 

The `.expect()` at line 148 causes a **panic** with message "Failed to create ledger pruner.", terminating node startup.

**Broken Invariants:**
1. **State Consistency**: The atomic state transition invariant is violated - metadata updates across two databases are not atomic
2. **Availability**: The node cannot recover automatically, violating operational reliability requirements

## Impact Explanation
This qualifies as **High Severity** under the Aptos bug bounty criteria:

- **"Validator node slowdowns"**: More severe - complete inability to start, not just slowdown
- **"State inconsistencies requiring intervention"**: Exact match - metadata split-brain requires manual disk space management or database repair

The impact includes:
1. **Validator Downtime**: Affected validators cannot participate in consensus, reducing network security if multiple validators are impacted
2. **Manual Intervention Required**: No automated recovery possible; operators must manually free disk space or disable pruning
3. **Persistent State**: The inconsistency persists across restart attempts until resolved
4. **Data Integrity Risk**: Event indices deleted but underlying data retained, causing query inconsistencies

This does NOT reach Critical severity because:
- No funds loss or consensus safety violation
- No network-wide partition (only affects nodes with full disks)
- Recovery is possible with manual intervention

## Likelihood Explanation
**Likelihood: Medium-High**

Disk space exhaustion is a common operational scenario:
1. Validators run on finite storage resources
2. Blockchain data growth is continuous and predictable
3. Pruning is designed to prevent disk exhaustion, but can fail when already at capacity
4. The failure window is narrow (between two write operations) but repeatedly attempted during normal pruning operations

Monitoring alerts exist for low disk space, but validators may not react quickly enough: [6](#0-5) 

The worker continuously retries failed prune operations, increasing the probability of hitting the failure condition during concurrent disk usage.

## Recommendation

Implement one of the following solutions:

**Option 1: Two-Phase Commit Protocol (Preferred)**
Implement a two-phase commit to ensure atomicity across databases:
1. Prepare phase: Validate both writes can succeed without committing
2. Commit phase: Commit both or rollback both
3. Add rollback capability to undo partial writes

**Option 2: Single Source of Truth**
Consolidate metadata into a single database and use references to track indexer state, eliminating split-brain possibility.

**Option 3: Graceful Startup Degradation**
Modify initialization to allow startup with degraded pruning:
- Detect metadata inconsistencies during startup
- Log critical warnings but continue initialization
- Allow pruner to retry reconciliation in background worker instead of blocking startup
- Implement idempotent catch-up logic that safely handles already-pruned data

Example fix for Option 3 (graceful degradation):

```rust
// In EventStorePruner::new()
pub(in crate::pruner) fn new(...) -> Result<Self> {
    let progress = get_or_initialize_subpruner_progress(...)?;
    
    let myself = EventStorePruner { ... };
    
    // Try catch-up, but don't fail initialization on disk errors
    if let Err(e) = myself.prune(progress, metadata_progress) {
        if is_disk_space_error(&e) {
            error!("EventStorePruner catch-up failed due to disk space: {:?}. Will retry in background.", e);
            // Mark for background retry
        } else {
            return Err(e);
        }
    }
    
    Ok(myself)
}
```

**Option 4: Pre-Write Validation**
Check available disk space before attempting writes:

```rust
fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
    // Check disk space before starting
    let estimated_size = self.estimate_prune_size(current_progress, target_version)?;
    self.validate_disk_space(estimated_size)?;
    
    // Proceed with two-database write...
}
```

## Proof of Concept

```rust
// Rust test to reproduce the vulnerability
#[test]
fn test_disk_space_exhaustion_during_event_pruning() {
    // Setup: Create a test node with two databases
    let (ledger_db, indexer_db) = create_test_dbs_with_events(0, 2000);
    
    // Step 1: Simulate normal pruning operation that partially succeeds
    let pruner = EventStorePruner::new(
        Arc::new(ledger_db.clone()),
        1100,
        Some(indexer_db.clone())
    ).unwrap();
    
    // Step 2: Mock disk space exhaustion for Event DB only
    let _guard = mock_disk_full_for_db(&ledger_db.event_db());
    
    // Step 3: Attempt prune - should fail on second write
    let result = pruner.prune(1000, 1100);
    assert!(result.is_err());
    
    // Step 4: Verify split-brain state
    let indexer_progress = indexer_db.get_event_pruner_progress().unwrap();
    let event_db_progress = ledger_db.event_db().get_pruner_progress().unwrap();
    
    assert_eq!(indexer_progress, 1100); // First write succeeded
    assert_eq!(event_db_progress, 1000); // Second write failed
    
    // Step 5: Simulate node restart with disk still full
    drop(pruner);
    
    // This should panic during initialization
    let result = std::panic::catch_unwind(|| {
        EventStorePruner::new(
            Arc::new(ledger_db),
            1100,
            Some(indexer_db)
        )
    });
    
    assert!(result.is_err(), "Node startup should panic when catch-up write fails");
}
```

**Steps to reproduce manually:**
1. Start an Aptos validator node with pruning enabled
2. Fill disk to near capacity
3. Trigger event pruning operation
4. While pruning is executing, consume remaining disk space (e.g., write large file)
5. Observe indexer DB write succeeds but event DB write fails
6. Restart node
7. Observe node fails to initialize with panic: "Failed to create ledger pruner."

## Notes

The root cause is architectural: splitting metadata across two separate RocksDB instances without distributed transaction support. While RocksDB provides atomic writes within a single instance, there is no atomicity guarantee across instances.

The issue affects all dual-database pruning operations in the codebase. Similar patterns may exist in:
- `TransactionPruner` with transaction indexing
- Other sub-pruners that write to multiple databases

The vulnerability is particularly insidious because:
1. It only manifests under resource exhaustion (disk full)
2. The failure is silent during runtime (logged but operation continues)
3. The actual failure occurs during next startup, potentially hours later
4. Recovery requires manual intervention that may not be immediately obvious to operators

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L71-81)
```rust
        if let Some(mut indexer_batch) = indexer_batch {
            indexer_batch.put::<InternalIndexerMetadataSchema>(
                &IndexerMetadataKey::EventPrunerProgress,
                &IndexerMetadataValue::Version(target_version),
            )?;
            self.expect_indexer_db()
                .get_inner_db_ref()
                .write_schemas(indexer_batch)?;
        }
        self.ledger_db.event_db().write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L90-106)
```rust
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.event_db_raw(),
            &DbMetadataKey::EventPrunerProgress,
            metadata_progress,
        )?;

        let myself = EventStorePruner {
            ledger_db,
            internal_indexer_db,
        };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up EventStorePruner."
        );
        myself.prune(progress, metadata_progress)?;
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L146-149)
```rust
        let pruner = Arc::new(
            LedgerPruner::new(ledger_db, internal_indexer_db)
                .expect("Failed to create ledger pruner."),
        );
```

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L53-64)
```rust
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
```
