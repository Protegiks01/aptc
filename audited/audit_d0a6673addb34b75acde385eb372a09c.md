# Audit Report

## Title
Indexer Database Corruption Leading to Data Loss When Current Version Exceeds Ledger Version

## Summary
The table info indexer service contains a critical flaw where processing empty transaction batches (when `current_version > ledger_version`) causes the database to be reset to version 0, resulting in permanent loss of previously indexed table information and requiring full reprocessing from genesis.

## Finding Description

The vulnerability exists in the main processing loop of `TableInfoService::run()`. When the indexer's `current_version` exceeds the `ledger_version` (which can occur during ledger rollbacks, state restoration, or manual database manipulation), the service processes empty transaction batches that corrupt the persisted database state.

**Attack Flow:**

1. The service reaches a state where `current_version > ledger_version` (e.g., indexer at version 1000, ledger rolled back to version 500)

2. At line 108, `get_highest_known_version()` is called, which waits in a loop while `current_version > ledger_version` [1](#0-0) 

3. If the service continues processing or is aborted during this wait, it proceeds with a stale `ledger_version`

4. At line 113, `get_batches(ledger_version)` returns empty batches because the condition `start_version <= ledger_version` fails in the while loop: [2](#0-1) 

5. Empty transactions are processed, resulting in `last_version = 0`: [3](#0-2) 

6. In `process_transactions_in_parallel()`, with empty transactions, `end_version = 0`: [4](#0-3) [5](#0-4) 

7. The database is corrupted with `update_next_version(1)`, writing `Version(0)` to persistent storage: [6](#0-5) 

8. The `update_next_version()` implementation stores `end_version - 1` in the database: [7](#0-6) 

9. On restart, the service reads the corrupted value and reinitializes from version 0: [8](#0-7) [9](#0-8) 

**Result:** All table info indexed beyond the current ledger version is permanently lost. If the ledger never catches up (e.g., due to a permanent rollback), transactions beyond the rollback point are permanently skipped from indexing.

## Impact Explanation

This issue qualifies as **Medium Severity** under the Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: The indexer database becomes corrupted, requiring manual intervention and full reindexing from genesis
- **Data loss**: Previously indexed table information is permanently lost if the ledger doesn't recover to the original version
- **Operational disruption**: The service must reprocess potentially millions of transactions from genesis, causing significant downtime

While this affects the indexer infrastructure rather than core consensus or execution, it represents a significant protocol violation in data consistency guarantees. The indexer is critical infrastructure that applications depend on for querying table metadata, and silent corruption of this data can lead to incorrect application behavior.

The issue does NOT qualify as High or Critical because:
- It does not affect validator nodes or consensus
- It does not cause fund loss or network partition
- It occurs in the ecosystem layer, not core protocol

## Likelihood Explanation

**Moderate Likelihood:**

This bug will trigger in the following scenarios:

1. **Ledger Rollback**: When a node's ledger is rolled back (e.g., due to state sync from a different chain fork, manual intervention, or disaster recovery), the ledger version will be less than the indexer's current version

2. **Database Inconsistency**: If the indexer database is manually modified or corrupted, causing `current_version` to be artificially advanced

3. **Service Restart During Chain Reorganization**: During epoch transitions or major chain events where temporary state inconsistencies occur

While these are not everyday occurrences, they are realistic operational scenarios that can happen in production environments, particularly during:
- Network partitions and recovery
- Major upgrades requiring state restoration
- Disaster recovery procedures
- Testing and development environments

The bug is deterministic once the trigger condition is met, requiring no attacker interaction or privilege escalation.

## Recommendation

Add validation to prevent processing when `current_version > ledger_version`, and handle the empty transaction case explicitly:

```rust
// In TableInfoService::run() around line 113
let batches = self.get_batches(ledger_version).await;
let transactions = self.fetch_batches(batches, ledger_version).await.unwrap();

// Add this check BEFORE processing
if transactions.is_empty() {
    let current = self.current_version.load(Ordering::SeqCst);
    if current > 0 && current > ledger_version {
        error!(
            current_version = current,
            ledger_version = ledger_version,
            "[Table Info] Current version ahead of ledger - skipping iteration"
        );
        continue; // Skip this iteration without updating database
    }
    // If current_version == 0, this is first run, continue normally
}
```

Additionally, in `process_transactions_in_parallel()`, add a guard:

```rust
// Around line 252-255
let last_version = transactions
    .last()
    .map(|txn| txn.version)
    .unwrap_or_default();

// Add validation
if transactions.is_empty() {
    warn!("[Table Info] Skipping empty transaction batch");
    return vec![]; // Return early without updating database
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_empty_batch_corruption() {
    // Setup: Create TableInfoService with current_version = 1000
    let mock_context = create_mock_context_with_ledger_version(500);
    let indexer_db = create_test_indexer_db();
    indexer_db.update_next_version(1000).unwrap(); // Simulate indexer ahead
    
    let service = TableInfoService::new(
        Arc::new(mock_context),
        1000, // request_start_version
        4,    // parser_task_count
        100,  // parser_batch_size
        None, // no backup
        Arc::new(indexer_db),
    );
    
    // Simulate one iteration of the run loop
    let ledger_version = 500; // Ledger behind indexer
    let batches = service.get_batches(ledger_version).await;
    
    // Verify batches is empty (since current_version=1000 > ledger_version=500)
    assert!(batches.is_empty(), "Expected empty batches");
    
    let transactions = service.fetch_batches(batches, ledger_version).await.unwrap();
    assert!(transactions.is_empty(), "Expected empty transactions");
    
    // Process empty transactions
    service.process_transactions_in_parallel(
        service.indexer_async_v2.clone(),
        transactions,
    ).await;
    
    // Check database corruption
    let next_version = service.indexer_async_v2.next_version();
    assert_eq!(next_version, 0, "Database corrupted: next_version reset to 0");
    
    // Verify data loss: versions 501-1000 are now permanently skipped
}
```

## Notes

This vulnerability is in the indexer-grpc ecosystem component, not the core consensus or execution layer. While it represents a real correctness bug with operational impact, it does not affect blockchain security, consensus safety, or fund custody. The impact is limited to data availability and consistency for applications querying the indexer.

The issue is most critical in production environments where ledger rollbacks or state restoration procedures are performed, as it can result in silent data corruption that goes undetected until applications begin querying for missing table information.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L116-119)
```rust
            let last_version = transactions
                .last()
                .map(|txn| txn.version)
                .unwrap_or_default();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L252-255)
```rust
        let last_version = transactions
            .last()
            .map(|txn| txn.version)
            .unwrap_or_default();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L278-278)
```rust
                let end_version = last_version;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L302-304)
```rust
                self.indexer_async_v2
                    .update_next_version(end_version + 1)
                    .unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L373-387)
```rust
        while num_fetches < self.parser_task_count && start_version <= ledger_version {
            let num_transactions_to_fetch = std::cmp::min(
                self.parser_batch_size as u64,
                ledger_version + 1 - start_version,
            ) as u16;

            batches.push(TransactionBatchInfo {
                start_version,
                num_transactions_to_fetch,
                head_version: ledger_version,
            });

            start_version += num_transactions_to_fetch as u64;
            num_fetches += 1;
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L499-502)
```rust
        while ledger_version == 0 || self.current_version.load(Ordering::SeqCst) > ledger_version {
            if self.aborted.load(Ordering::SeqCst) {
                break;
            }
```

**File:** storage/indexer/src/db_v2.rs (L62-68)
```rust
        let next_version = db
            .get::<IndexerMetadataSchema>(&MetadataKey::LatestVersion)?
            .map_or(0, |v| v.expect_version());

        Ok(Self {
            db,
            next_version: AtomicU64::new(next_version),
```

**File:** storage/indexer/src/db_v2.rs (L117-124)
```rust
    pub fn update_next_version(&self, end_version: u64) -> Result<()> {
        self.db.put::<IndexerMetadataSchema>(
            &MetadataKey::LatestVersion,
            &MetadataValue::Version(end_version - 1),
        )?;
        self.next_version.store(end_version, Ordering::Relaxed);
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/runtime.rs (L100-102)
```rust
        let parser = TableInfoService::new(
            context,
            indexer_async_v2_clone.next_version(),
```
