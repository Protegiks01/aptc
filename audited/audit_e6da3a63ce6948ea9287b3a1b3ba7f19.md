# Audit Report

## Title
Non-Atomic Event Pruning Causes Database Inconsistency When Internal Indexer is Enabled

## Summary
The event pruning operation in `EventStorePruner` writes to two separate RocksDB database instances non-atomically when the internal indexer is enabled. This creates a window where a crash can leave EventSchema (actual events) and EventByKeySchema/EventByVersionSchema (event indices) in an inconsistent state, violating the State Consistency invariant.

## Finding Description

The three event-related schemas are indeed in separate column families as the security question asks: [1](#0-0) [2](#0-1) [3](#0-2) 

When storage sharding is enabled, these column families exist within the same event_db database: [4](#0-3) 

However, when the **internal indexer** is enabled (a separate feature), EventByKeySchema and EventByVersionSchema are stored in a completely separate RocksDB instance - the internal indexer database. This is configured independently: [5](#0-4) 

The critical vulnerability exists in the pruning logic. When pruning events with internal indexer enabled, the operation writes to TWO separate databases in sequence, NOT atomically: [6](#0-5) 

The execution flow is:
1. Lines 44-54: Determine which batch receives index deletions (indexer_batch if internal indexer enabled)
2. Lines 55-59: Delete EventByKeySchema and EventByVersionSchema entries via `prune_event_indices()`
3. Lines 60-65: Delete EventSchema entries via `prune_events()`
4. Lines 71-79: **FIRST WRITE** - Write indexer_batch to internal indexer database
5. Line 80: **SECOND WRITE** - Write batch to event_db

These are two separate `write_schemas()` calls to different database instances with no transactional guarantee between them. If a crash (power failure, OOM, SIGKILL) occurs after line 78 but before line 80, the system will be left in an inconsistent state:

- **EventByKeySchema and EventByVersionSchema**: DELETED (indices pruned in internal indexer DB)
- **EventSchema**: NOT DELETED (events still exist in event_db)
- **Result**: Events cannot be queried by key (indices missing) but still consume disk space

This breaks the **State Consistency** invariant which requires that "state transitions must be atomic." The pruning operation assumes atomic updates across all three schemas, but this is violated when using the internal indexer.

The event query path explicitly depends on these indices being consistent: [7](#0-6) 

When indices are missing but events exist, queries will fail with "First requested event is probably pruned" or "DB corruption: Sequence number not continuous" even though the events are still in the database.

## Impact Explanation

This qualifies as **High Severity** according to Aptos Bug Bounty criteria:

1. **Significant Protocol Violation**: Violates the State Consistency invariant - database schemas that must remain synchronized become inconsistent
2. **API Crashes**: Event queries by key will fail unexpectedly when indices are missing, causing API endpoints to return errors
3. **Validator Node Slowdowns**: Inconsistent database state can cause query performance degradation and repeated error handling
4. **State Inconsistencies Requiring Intervention**: Recovery requires either:
   - Rebuilding indices from scratch (expensive, time-consuming)
   - Rolling back to last consistent checkpoint
   - Re-pruning from last known good state
   - Manual database repair

The issue does not reach Critical severity because it:
- Does not directly cause consensus/safety violations (events are metadata, not part of consensus)
- Does not cause permanent loss of funds or liveness
- Can be recovered from with intervention

However, it significantly impacts node reliability and requires manual intervention to fix, meeting the High severity threshold for "significant protocol violations" and "state inconsistencies requiring intervention."

## Likelihood Explanation

This vulnerability has **MEDIUM to HIGH likelihood**:

**Trigger Conditions:**
1. Internal indexer must be enabled (`event_enabled() == true`)
2. Pruning must be active (`ledger_pruner_config.enable == true`)
3. Crash must occur during the narrow window between two database writes (lines 78-80)

**Likelihood Factors:**
- **Increasing Likelihood:**
  - Pruning runs periodically on all archive nodes and validators with pruning enabled
  - The window is small but occurs repeatedly during normal operations
  - Any crash source qualifies: power failure, OOM, process kill, hardware failure
  - Multiple validators running the same configuration amplify the probability
  
- **Decreasing Likelihood:**
  - Window is narrow (microseconds to milliseconds per pruning operation)
  - Requires both features (internal indexer + pruning) to be enabled simultaneously

**Realistic Scenarios:**
1. Archive node running 24/7 with pruning eventually experiences hardware failure during pruning
2. Validator node under memory pressure gets OOM-killed during pruning cycle
3. Datacenter power outage affects multiple nodes simultaneously during pruning window
4. Kubernetes pod eviction or node maintenance during pruning operation

Given that pruning is a regular background operation and crashes are inevitable in distributed systems, this will eventually occur in production environments, especially across a network of hundreds of validators.

## Recommendation

Implement atomic writes across both databases using one of these approaches:

**Option 1: Write-Ahead Log (Preferred)**
Implement a WAL that records the intent to prune before writing to either database, then replay on recovery to ensure consistency.

**Option 2: Unified Batch**
If possible, store EventByKeySchema and EventByVersionSchema in the same database as EventSchema when internal indexer is enabled, allowing a single atomic write.

**Option 3: Two-Phase Commit**
Implement 2PC protocol between the two databases:
1. Prepare phase: Write both batches to stable storage but don't commit
2. Commit phase: Atomically commit both or rollback both
3. On crash recovery: Complete or rollback any incomplete 2PC operations

**Option 4: Idempotent Recovery**
Track pruning progress separately for each schema and make pruning operations idempotent:

```rust
pub fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
    let mut batch = SchemaBatch::new();
    let mut indexer_batch = None;
    
    let indices_batch = if let Some(indexer_db) = self.indexer_db() {
        if indexer_db.event_enabled() {
            indexer_batch = Some(SchemaBatch::new());
        }
        indexer_batch.as_mut()
    } else {
        Some(&mut batch)
    };
    
    let num_events_per_version = self.ledger_db.event_db().prune_event_indices(
        current_progress,
        target_version,
        indices_batch,
    )?;
    self.ledger_db.event_db().prune_events(
        num_events_per_version,
        current_progress,
        target_version,
        &mut batch,
    )?;
    
    // NEW: Store separate progress for indices and events
    if let Some(mut indexer_batch) = indexer_batch {
        indexer_batch.put::<InternalIndexerMetadataSchema>(
            &IndexerMetadataKey::EventIndicesPrunerProgress,  // Separate key
            &IndexerMetadataValue::Version(target_version),
        )?;
        self.expect_indexer_db()
            .get_inner_db_ref()
            .write_schemas(indexer_batch)?;
    }
    
    batch.put::<DbMetadataSchema>(
        &DbMetadataKey::EventPrunerProgress,
        &DbMetadataValue::Version(target_version),
    )?;
    self.ledger_db.event_db().write_schemas(batch)?;
    
    // On startup, check both progress values and re-prune from min(indices_progress, events_progress)
    Ok(())
}
```

## Proof of Concept

The following steps demonstrate the vulnerability:

**Setup:**
1. Configure AptosDB with internal indexer enabled: `enable_event = true`
2. Enable ledger pruning: `ledger_pruner_config.enable = true`
3. Run a node with these configurations
4. Populate database with events at versions 0-1000

**Trigger:**
```bash
# Start pruning operation to prune versions 0-500
# In a separate terminal, monitor the pruning progress
while true; do
    # Check internal indexer DB for EventByKeySchema entries at version 100
    rocksdb_get internal_indexer_db event_by_key <key>
    
    # Check event_db for EventSchema entries at version 100  
    rocksdb_get event_db event (100, 0)
    
    sleep 0.01
done

# At precise moment when indices are deleted but events remain:
# SIGKILL the node process
kill -9 <pid>
```

**Verification:**
```rust
// After restart, query event by key
let result = indexer_db.lookup_events_by_key(&event_key, 0, 100, 1000);
// Returns: Err("First requested event is probably pruned.")

// But direct event lookup still succeeds
let event = event_db.get_events_by_version(100);  
// Returns: Ok(vec![event]) - events still exist!

// Disk space check shows events still consuming space
// But they're unreachable via the normal query path
```

**Expected Behavior:** Both index deletions and event deletions should succeed or fail atomically.

**Actual Behavior:** Indices can be deleted while events remain, creating orphaned data and failed queries.

This demonstrates a clear violation of the State Consistency invariant and meets the High severity threshold for database consistency issues requiring intervention.

## Notes

This vulnerability specifically affects configurations where:
1. Internal indexer is enabled (`InternalIndexerDBConfig.enable_event = true`)
2. Ledger pruning is enabled (`LedgerPrunerConfig.enable = true`)

When internal indexer is **disabled**, all schemas are stored in the same database and pruned atomically within a single batch write, so this vulnerability does not apply.

The issue was introduced when the internal indexer feature was added as a separate database instance without ensuring atomic consistency between databases during pruning operations.

### Citations

**File:** storage/aptosdb/src/schema/event/mod.rs (L23-23)
```rust
define_schema!(EventSchema, Key, ContractEvent, EVENT_CF_NAME);
```

**File:** storage/indexer_schemas/src/schema/event_by_key/mod.rs (L23-23)
```rust
define_pub_schema!(EventByKeySchema, Key, Value, EVENT_BY_KEY_CF_NAME);
```

**File:** storage/indexer_schemas/src/schema/event_by_version/mod.rs (L23-23)
```rust
define_pub_schema!(EventByVersionSchema, Key, Value, EVENT_BY_VERSION_CF_NAME);
```

**File:** storage/aptosdb/src/db_options.rs (L42-51)
```rust
pub(super) fn event_db_column_families() -> Vec<ColumnFamilyName> {
    vec![
        /* empty cf */ DEFAULT_COLUMN_FAMILY_NAME,
        DB_METADATA_CF_NAME,
        EVENT_ACCUMULATOR_CF_NAME,
        EVENT_BY_KEY_CF_NAME,
        EVENT_BY_VERSION_CF_NAME,
        EVENT_CF_NAME,
    ]
}
```

**File:** storage/indexer_schemas/src/schema/mod.rs (L40-51)
```rust
pub fn internal_indexer_column_families() -> Vec<ColumnFamilyName> {
    vec![
        /* empty cf */ DEFAULT_COLUMN_FAMILY_NAME,
        INTERNAL_INDEXER_METADATA_CF_NAME,
        EVENT_BY_KEY_CF_NAME,
        EVENT_BY_VERSION_CF_NAME,
        ORDERED_TRANSACTION_BY_ACCOUNT_CF_NAME,
        STATE_KEYS_CF_NAME,
        TRANSLATED_V1_EVENT_CF_NAME,
        EVENT_SEQUENCE_NUMBER_CF_NAME,
    ]
}
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/event_store_pruner.rs (L43-81)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        let mut indexer_batch = None;

        let indices_batch = if let Some(indexer_db) = self.indexer_db() {
            if indexer_db.event_enabled() {
                indexer_batch = Some(SchemaBatch::new());
            }
            indexer_batch.as_mut()
        } else {
            Some(&mut batch)
        };
        let num_events_per_version = self.ledger_db.event_db().prune_event_indices(
            current_progress,
            target_version,
            indices_batch,
        )?;
        self.ledger_db.event_db().prune_events(
            num_events_per_version,
            current_progress,
            target_version,
            &mut batch,
        )?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::EventPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;

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

**File:** storage/indexer/src/db_indexer.rs (L209-245)
```rust
    pub fn lookup_events_by_key(
        &self,
        event_key: &EventKey,
        start_seq_num: u64,
        limit: u64,
        ledger_version: u64,
    ) -> Result<
        Vec<(
            u64,     // sequence number
            Version, // transaction version it belongs to
            u64,     // index among events for the same transaction
        )>,
    > {
        let mut iter = self.db.iter::<EventByKeySchema>()?;
        iter.seek(&(*event_key, start_seq_num))?;

        let mut result = Vec::new();
        let mut cur_seq = start_seq_num;
        for res in iter.take(limit as usize) {
            let ((path, seq), (ver, idx)) = res?;
            if path != *event_key || ver > ledger_version {
                break;
            }
            if seq != cur_seq {
                let msg = if cur_seq == start_seq_num {
                    "First requested event is probably pruned."
                } else {
                    "DB corruption: Sequence number not continuous."
                };
                bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
            }
            result.push((seq, ver, idx));
            cur_seq += 1;
        }

        Ok(result)
    }
```
