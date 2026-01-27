# Audit Report

## Title
Internal Indexer DB Service Version Mismatch Allows Permanent Transaction Skip and Data Loss

## Summary
The `InternalIndexerDBService::run()` function in `ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs` fails to validate that the indexer database's persisted version is compatible with the main database's synced version. When the indexer DB has a higher persisted version than the main DB's synced version (e.g., after database restoration or fast sync), the service silently skips processing a range of transactions, causing permanent data loss in the indexer without any error or warning.

## Finding Description

The vulnerability exists in the initialization and main loop logic of the `run()` method. [1](#0-0) 

The issue manifests through the following execution flow:

1. **Initialization Phase:** The `get_start_version()` method retrieves the indexer DB's persisted version and adds 1 to get `start_version`. [2](#0-1) 

2. **Version Mismatch:** The `target_version` is initialized from the main DB's synced version. [3](#0-2) 

3. **Critical Gap:** There is NO validation to ensure `start_version <= target_version` or that the main DB contains transactions starting from `start_version`.

4. **Silent Failure:** When `target_version <= start_version`, the service waits for channel updates. However, if the main DB is committing versions that are less than `start_version`, the `process()` method returns immediately without processing. [4](#0-3) 

The `get_num_of_transactions()` method explicitly handles the "recreated" scenario but returns 0 transactions instead of raising an error. [5](#0-4) 

**Attack Scenario:**

1. **Initial State:**
   - Indexer DB persisted version: 1000
   - Main DB synced version: 1500
   - System running normally

2. **Database Restoration Event:**
   - Main DB is restored from backup to version 500
   - Indexer DB is NOT restored (or restored from a different backup)
   - Service restarts

3. **Execution:**
   - `start_version` = 1001 (from indexer DB)
   - `target_version` = 500 (from main DB)
   - Condition `500 <= 1001` is TRUE, waits for updates
   - Main DB commits versions 501, 502, 503, ..., 1000, 1001, 1002
   - Each time, `process(1001, <version>)` is called where `<version>` < 1001
   - The `process()` method returns `start_version` unchanged (1001)
   - When main DB reaches version 1002, indexer processes 1001-1002
   - **Permanent Data Loss:** Versions 501-1000 are never indexed

## Impact Explanation

This vulnerability qualifies as **High Severity** (potentially **Critical** depending on deployment):

**Primary Impacts:**

1. **State Inconsistency Requiring Intervention:** The indexer database becomes permanently inconsistent with the main database. Missing transactions cannot be automatically recovered and require manual database rebuild. This aligns with **Medium Severity** criteria per Aptos bug bounty.

2. **API Service Degradation:** The internal indexer DB serves API queries for:
   - Account transaction history [6](#0-5) 
   - Event queries by key [7](#0-6) 
   - State key lookups
   
   Missing transactions mean missing events, account states, and transaction history, causing API queries to return incomplete data.

3. **No Automatic Recovery:** Unlike transient issues, this creates a permanent gap that persists across restarts until manual intervention (full indexer DB rebuild).

4. **Silent Failure:** No error, panic, or warning is emitted. The service continues running while silently skipping transactions, making detection difficult.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability triggers in the following realistic scenarios:

1. **Database Restoration from Backup:** Common operational procedure when recovering from hardware failure, data corruption, or migration. If main DB and indexer DB are restored from different backup points, the version mismatch occurs.

2. **Fast Sync Initialization:** During fast sync bootstrap, the main DB may start at version 0 or a snapshot version while an existing indexer DB has higher persisted versions. [8](#0-7) 

3. **Selective Database Wiping:** If an operator wipes the main DB but not the indexer DB (or vice versa) for troubleshooting, the mismatch occurs on restart.

4. **Database Migration Issues:** During upgrades or infrastructure changes, if databases are not synchronized properly.

The code comment explicitly acknowledges the "recreated" scenario, indicating developers are aware of this case but have not implemented proper handling. [9](#0-8) 

## Recommendation

**Immediate Fix:** Add validation in the `run()` method to detect and handle version mismatches:

```rust
pub async fn run(&mut self, node_config: &NodeConfig) -> Result<()> {
    let mut start_version = self.get_start_version(node_config).await?;
    let mut target_version = self.db_indexer.main_db_reader.ensure_synced_version()?;
    
    // NEW: Validate version compatibility
    if start_version > target_version + 1 {
        panic!(
            "Indexer DB version ({}) is ahead of main DB version ({}). \
            This indicates a database restoration mismatch. \
            Please rebuild the indexer DB or restore main DB to a compatible state. \
            start_version: {}, main_db_synced_version: {}",
            start_version - 1, target_version, start_version, target_version
        );
    }
    
    let mut step_timer = std::time::Instant::now();
    
    loop {
        // ... rest of implementation
    }
}
```

**Better Solution:** Implement automatic indexer DB reset on version mismatch:

```rust
pub async fn run(&mut self, node_config: &NodeConfig) -> Result<()> {
    let mut start_version = self.get_start_version(node_config).await?;
    let mut target_version = self.db_indexer.main_db_reader.ensure_synced_version()?;
    
    // Check for version mismatch and reset if necessary
    if start_version > target_version + 1 {
        warn!(
            "Indexer DB ahead of main DB (indexer: {}, main: {}). Resetting indexer DB.",
            start_version - 1, target_version
        );
        // Reset indexer DB to empty state
        self.db_indexer.indexer_db.reset_to_version(None)?;
        start_version = 0;
    }
    
    let mut step_timer = std::time::Instant::now();
    
    loop {
        // ... rest of implementation
    }
}
```

**Long-term Solution:** Add health monitoring to detect gaps and alert operators.

## Proof of Concept

```rust
#[cfg(test)]
mod test_version_mismatch {
    use super::*;
    use aptos_db::AptosDB;
    use aptos_temppath::TempPath;
    use std::sync::Arc;
    use tokio::sync::watch;
    
    #[tokio::test]
    async fn test_indexer_skips_transactions_on_version_mismatch() {
        // Setup: Create main DB with version 500
        let main_db_path = TempPath::new();
        let main_db = Arc::new(AptosDB::new_for_test(&main_db_path));
        
        // Commit transactions 0-500 to main DB
        for version in 0..=500 {
            // Simulate transaction commit
            main_db.save_transactions_for_test(version, /* ... */);
        }
        
        // Setup: Create indexer DB with persisted version 1000
        let indexer_db_path = TempPath::new();
        let indexer_db = InternalIndexerDB::new_for_test(&indexer_db_path);
        
        // Simulate indexer DB already processed up to version 1000
        indexer_db.save_metadata(MetadataKey::LatestVersion, 1000);
        
        // Create update channel
        let (update_sender, update_receiver) = watch::channel((Instant::now(), 500u64));
        
        // Create service
        let mut service = InternalIndexerDBService::new(
            main_db.clone(),
            indexer_db,
            update_receiver,
        );
        
        // Start service in background
        let handle = tokio::spawn(async move {
            service.run(&NodeConfig::default()).await
        });
        
        // Simulate main DB committing new transactions
        for version in 501..=1002 {
            main_db.save_transactions_for_test(version, /* ... */);
            update_sender.send((Instant::now(), version)).unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        // VULNERABILITY: Check indexer DB state
        let indexer_latest = service.db_indexer.indexer_db.get_persisted_version().unwrap();
        
        // Expected: indexer should have versions 501-1002
        // Actual: indexer only has versions 0-1000 and 1001-1002
        // GAP: versions 501-1000 are missing!
        assert_eq!(indexer_latest, Some(1002));
        
        // Verify the gap: transactions 501-1000 should exist in main DB
        // but NOT in indexer DB
        for version in 501..=1000 {
            let main_has_txn = main_db.get_transaction_by_version(version, version, false).is_ok();
            let indexer_has_txn = service.db_indexer.indexer_db
                .get_account_ordered_transactions(/* ... */, version, /* ... */)
                .is_ok();
            
            assert!(main_has_txn, "Main DB should have version {}", version);
            assert!(!indexer_has_txn, "Indexer DB should NOT have version {} (GAP)", version);
        }
    }
}
```

**Notes:**

This vulnerability is particularly insidious because:

1. **No Error Indication:** The system continues operating without any error logs or panics
2. **Data Loss is Permanent:** Once the gap is created, it persists indefinitely
3. **Difficult Detection:** Requires comparing main DB and indexer DB contents directly
4. **Affects Production Operations:** Database restoration is a common operational procedure
5. **Acknowledged but Unhandled:** The code comment at [9](#0-8)  shows developers are aware of the "recreated" scenario but chose to return 0 transactions instead of raising an error

The fix is straightforward: add validation to detect the mismatch and either panic (forcing manual intervention) or automatically reset the indexer DB to resync from scratch.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L89-100)
```rust
        let fast_sync_enabled = node_config
            .state_sync
            .state_sync_driver
            .bootstrapping_mode
            .is_fast_sync();
        let mut main_db_synced_version = self.db_indexer.main_db_reader.ensure_synced_version()?;

        // Wait till fast sync is done
        while fast_sync_enabled && main_db_synced_version == 0 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            main_db_synced_version = self.db_indexer.main_db_reader.ensure_synced_version()?;
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L102-106)
```rust
        let start_version = self
            .db_indexer
            .indexer_db
            .get_persisted_version()?
            .map_or(0, |v| v + 1);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L167-199)
```rust
    pub async fn run(&mut self, node_config: &NodeConfig) -> Result<()> {
        let mut start_version = self.get_start_version(node_config).await?;
        let mut target_version = self.db_indexer.main_db_reader.ensure_synced_version()?;
        let mut step_timer = std::time::Instant::now();

        loop {
            if target_version <= start_version {
                match self.update_receiver.changed().await {
                    Ok(_) => {
                        (step_timer, target_version) = *self.update_receiver.borrow();
                    },
                    Err(e) => {
                        panic!("Failed to get update from update_receiver: {}", e);
                    },
                }
            }
            let next_version = self.db_indexer.process(start_version, target_version)?;
            INDEXER_DB_LATENCY.set(step_timer.elapsed().as_millis() as i64);
            log_grpc_step(
                SERVICE_TYPE,
                IndexerGrpcStep::InternalIndexerDBProcessed,
                Some(start_version as i64),
                Some(next_version as i64),
                None,
                None,
                Some(step_timer.elapsed().as_secs_f64()),
                None,
                Some((next_version - start_version) as i64),
                None,
            );
            start_version = next_version;
        }
    }
```

**File:** storage/indexer/src/db_indexer.rs (L382-407)
```rust
    fn get_num_of_transactions(&self, version: Version, end_version: Version) -> Result<u64> {
        let highest_version = min(self.main_db_reader.ensure_synced_version()?, end_version);
        if version > highest_version {
            // In case main db is not synced yet or recreated
            return Ok(0);
        }
        // we want to include the last transaction since the iterator interface will is right exclusive.
        let num_of_transaction = min(
            self.indexer_db.config.batch_size as u64,
            highest_version + 1 - version,
        );
        Ok(num_of_transaction)
    }

    /// Process all transactions from `start_version` to `end_version`. Left inclusive, right exclusive.
    pub fn process(&self, start_version: Version, end_version: Version) -> Result<Version> {
        let mut version = start_version;
        while version < end_version {
            let next_version = self.process_a_batch(version, end_version)?;
            if next_version == version {
                break;
            }
            version = next_version;
        }
        Ok(version)
    }
```

**File:** storage/indexer/src/db_indexer.rs (L586-612)
```rust
    pub fn get_account_ordered_transactions(
        &self,
        address: AccountAddress,
        start_seq_num: u64,
        limit: u64,
        include_events: bool,
        ledger_version: Version,
    ) -> Result<AccountOrderedTransactionsWithProof> {
        self.indexer_db
            .ensure_cover_ledger_version(ledger_version)?;
        error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;

        let txns_with_proofs = self
            .indexer_db
            .get_account_ordered_transactions_iter(address, start_seq_num, limit, ledger_version)?
            .map(|result| {
                let (_seq_num, txn_version) = result?;
                self.main_db_reader.get_transaction_by_version(
                    txn_version,
                    ledger_version,
                    include_events,
                )
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(AccountOrderedTransactionsWithProof::new(txns_with_proofs))
    }
```

**File:** storage/indexer/src/db_indexer.rs (L644-724)
```rust
    pub fn get_events_by_event_key(
        &self,
        event_key: &EventKey,
        start_seq_num: u64,
        order: Order,
        limit: u64,
        ledger_version: Version,
    ) -> Result<Vec<EventWithVersion>> {
        self.indexer_db
            .ensure_cover_ledger_version(ledger_version)?;
        error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
        let get_latest = order == Order::Descending && start_seq_num == u64::MAX;

        let cursor = if get_latest {
            // Caller wants the latest, figure out the latest seq_num.
            // In the case of no events on that path, use 0 and expect empty result below.
            self.indexer_db
                .get_latest_sequence_number(ledger_version, event_key)?
                .unwrap_or(0)
        } else {
            start_seq_num
        };

        // Convert requested range and order to a range in ascending order.
        let (first_seq, real_limit) = get_first_seq_num_and_limit(order, cursor, limit)?;

        // Query the index.
        let mut event_indices = self.indexer_db.lookup_events_by_key(
            event_key,
            first_seq,
            real_limit,
            ledger_version,
        )?;

        // When descending, it's possible that user is asking for something beyond the latest
        // sequence number, in which case we will consider it a bad request and return an empty
        // list.
        // For example, if the latest sequence number is 100, and the caller is asking for 110 to
        // 90, we will get 90 to 100 from the index lookup above. Seeing that the last item
        // is 100 instead of 110 tells us 110 is out of bound.
        if order == Order::Descending {
            if let Some((seq_num, _, _)) = event_indices.last() {
                if *seq_num < cursor {
                    event_indices = Vec::new();
                }
            }
        }

        let mut events_with_version = event_indices
            .into_iter()
            .map(|(seq, ver, idx)| {
                let event = match self
                    .main_db_reader
                    .get_event_by_version_and_index(ver, idx)?
                {
                    event @ ContractEvent::V1(_) => event,
                    ContractEvent::V2(_) => ContractEvent::V1(
                        self.indexer_db
                            .get_translated_v1_event_by_version_and_index(ver, idx)?,
                    ),
                };
                let v0 = match &event {
                    ContractEvent::V1(event) => event,
                    ContractEvent::V2(_) => bail!("Unexpected module event"),
                };
                ensure!(
                    seq == v0.sequence_number(),
                    "Index broken, expected seq:{}, actual:{}",
                    seq,
                    v0.sequence_number()
                );

                Ok(EventWithVersion::new(ver, event))
            })
            .collect::<Result<Vec<_>>>()?;
        if order == Order::Descending {
            events_with_version.reverse();
        }

        Ok(events_with_version)
    }
```
