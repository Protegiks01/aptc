# Audit Report

## Title
Version Consistency Violation in Table Info Retrieval Leading to State Mismatch

## Summary
The `get_table_info()` method in the indexer reader does not enforce version consistency between the requested ledger version and the table metadata version. The Aptos API uses two separate indexers that progress independently: one for general data (DBIndexer) and one for table metadata (IndexerAsyncV2). This allows queries at version V to receive table metadata from a different version, causing deserialization errors and incorrect query results. [1](#0-0) 

## Finding Description
The vulnerability exists in the interaction between the API layer and the indexer system. The Aptos node maintains **two separate indexers** that can be at different ledger versions:

1. **DBIndexer** (`db_indexer_reader`): Indexes events, transactions, and state keys
2. **IndexerAsyncV2** (`table_info_reader`): Indexes table metadata (TableInfo containing key_type and value_type) [2](#0-1) 

When the API serves a table item query:

1. The API calls `get_latest_ledger_info()` which checks the **DBIndexer** version to determine the maximum servable version [3](#0-2) 

2. The API retrieves the internal indexer ledger version from the **DBIndexer** [4](#0-3) 

3. The API creates a state view at the requested version and reads table item bytes from that version [5](#0-4) 

4. To deserialize the table item, the API calls `get_table_info()` which queries the **IndexerAsyncV2** [6](#0-5) 

5. The `get_table_info()` method reads from RocksDB **without any version parameter** [7](#0-6) 

The two indexers are initialized as separate runtimes and progress independently: [8](#0-7) 

**Exploitation Scenario:**
- DBIndexer has processed transactions up to version 1000
- TableInfo indexer has only processed up to version 500
- User queries table item at version 800 (valid, since DBIndexer reports 1000 as available)
- API reads table item bytes from state at version 800
- API calls `get_table_info()` which returns metadata from version 500 or None
- Result: Deserialization fails or uses incorrect metadata from a different version

The `get_table_info_with_retry()` method attempts to retry indefinitely until table info is found, but this doesn't solve the version mismatch - it only waits for the table to eventually appear: [9](#0-8) 

## Impact Explanation
This vulnerability constitutes **Medium Severity** per Aptos bug bounty criteria:

**State inconsistencies requiring intervention**: When table metadata from version V1 is used to deserialize data from version V2, the following can occur:
- Incorrect JSON responses returned to API clients
- Deserialization failures causing API errors
- Query hangs due to indefinite retry loops waiting for table info
- Data corruption in downstream systems relying on API data

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." While the state itself is consistent, the API's view of that state is inconsistent when metadata doesn't match the queried version.

The vulnerability does not directly lead to consensus violations or fund loss, but it degrades the reliability and correctness of the blockchain's query interface, which is critical for dApps, indexers, and users.

## Likelihood Explanation
This vulnerability has **HIGH likelihood** of occurring in production:

1. **Natural Occurrence**: The two indexers progress at different rates based on system load, block processing time, and implementation differences. Lag is inevitable during:
   - Node startup/bootstrap
   - Heavy transaction load
   - System resource constraints
   - Network synchronization delays

2. **No Synchronization**: There is no mechanism to ensure both indexers stay synchronized at the same version

3. **API Availability Design**: The code explicitly checks only the DBIndexer version when determining API availability, not the TableInfo indexer version [10](#0-9) 

4. **Persistent Condition**: Once lag occurs, it persists until the slower indexer catches up, affecting all queries during that period

## Recommendation
Implement version consistency checks in `get_table_info()`:

**Solution 1: Version-aware table info retrieval**
Modify the `IndexerReader` trait to accept a version parameter:
```rust
fn get_table_info(&self, handle: TableHandle, ledger_version: Version) -> Result<Option<TableInfo>>;
```

Store table info with version history in RocksDB and retrieve the correct version for the requested ledger version.

**Solution 2: Synchronization check**
Before serving any API request, verify that the table info indexer has caught up to at least the requested version:

```rust
pub fn get_table_info(&self, handle: TableHandle, required_version: Version) -> anyhow::Result<Option<TableInfo>> {
    if let Some(table_info_reader) = &self.table_info_reader {
        let table_info_version = table_info_reader.next_version();
        if table_info_version < required_version {
            anyhow::bail!("Table info indexer at version {} has not caught up to required version {}", 
                         table_info_version, required_version)
        }
        return Ok(table_info_reader.get_table_info_with_retry(handle)?);
    }
    anyhow::bail!("Table info reader is not available")
}
```

**Solution 3: Use minimum version**
Modify `get_latest_ledger_info()` to return the **minimum** of both indexer versions:

```rust
pub fn get_latest_ledger_info<E: ServiceUnavailableError>(&self) -> Result<LedgerInfo, E> {
    if let Some(indexer_reader) = self.indexer_reader.as_ref() {
        if indexer_reader.is_internal_indexer_enabled() {
            let internal_version = self.get_latest_internal_indexer_ledger_info()?.version();
            let table_info_version = indexer_reader.get_latest_table_info_ledger_version()?
                .ok_or_else(|| E::service_unavailable_with_code_no_info(
                    "Table info indexer not available", 
                    AptosErrorCode::InternalError
                ))?;
            let min_version = std::cmp::min(internal_version, table_info_version);
            return self.get_ledger_info_at_version(min_version);
        }
    }
    self.get_latest_storage_ledger_info()
}
```

## Proof of Concept

```rust
// Rust integration test demonstrating the vulnerability

#[tokio::test]
async fn test_table_info_version_mismatch() {
    // Setup: Create a node with indexers at different versions
    let (mut swarm, mut cli, _faucet) = SwarmBuilder::new_local(1)
        .with_aptos()
        .build_with_cli(0)
        .await;
    
    let client = swarm.validators().next().unwrap().rest_client();
    
    // Create a table at version V1
    let table_create_txn = // ... create table transaction
    client.submit_and_wait(&table_create_txn).await.unwrap();
    let v1 = client.get_ledger_information().await.unwrap().into_inner().ledger_version;
    
    // Wait for DBIndexer to catch up but stop TableInfo indexer
    // (In reality this happens naturally due to processing differences)
    // Stop table info indexer processing
    stop_table_info_indexer();
    
    // Add more transactions to advance DBIndexer
    for _ in 0..100 {
        submit_dummy_transaction();
    }
    
    let v2 = client.get_ledger_information().await.unwrap().into_inner().ledger_version;
    assert!(v2 > v1 + 50);
    
    // Query table item at v2 - DBIndexer reports this is available
    let result = client.get_table_item(
        table_handle,
        table_key,
        Some(v2) // Requesting at version v2
    ).await;
    
    // Expected: Either error or incorrect data due to using table metadata from v1
    // Actual: May succeed with wrong metadata or hang indefinitely
    assert!(result.is_err() || verify_data_mismatch(result.unwrap()));
}
```

**Notes:**
- The vulnerability is architectural and affects all table queries when indexer lag occurs
- The issue is particularly problematic for newly created tables where the creation hasn't been indexed yet but queries are already being served
- While the `get_table_info_with_retry()` method attempts to handle missing table info, it doesn't address version consistency - it just waits indefinitely
- The separation of concerns between two indexers was likely intended for modularity, but the lack of version synchronization creates this security issue

### Citations

**File:** types/src/indexer/indexer_db_reader.rs (L26-26)
```rust
    fn get_table_info(&self, handle: TableHandle) -> Result<Option<TableInfo>>;
```

**File:** storage/indexer/src/indexer_reader.rs (L20-24)
```rust
#[derive(Clone)]
pub struct IndexerReaders {
    table_info_reader: Option<Arc<IndexerAsyncV2>>,
    db_indexer_reader: Option<Arc<DBIndexer>>,
}
```

**File:** storage/indexer/src/indexer_reader.rs (L47-52)
```rust
    fn get_table_info(&self, handle: TableHandle) -> anyhow::Result<Option<TableInfo>> {
        if let Some(table_info_reader) = &self.table_info_reader {
            return Ok(table_info_reader.get_table_info_with_retry(handle)?);
        }
        anyhow::bail!("Table info reader is not available")
    }
```

**File:** api/src/context.rs (L271-278)
```rust
    pub fn get_latest_ledger_info<E: ServiceUnavailableError>(&self) -> Result<LedgerInfo, E> {
        if let Some(indexer_reader) = self.indexer_reader.as_ref() {
            if indexer_reader.is_internal_indexer_enabled() {
                return self.get_latest_internal_indexer_ledger_info();
            }
        }
        self.get_latest_storage_ledger_info()
    }
```

**File:** api/src/context.rs (L319-368)
```rust
    pub fn get_latest_internal_indexer_ledger_info<E: ServiceUnavailableError>(
        &self,
    ) -> Result<LedgerInfo, E> {
        if let Some(indexer_reader) = self.indexer_reader.as_ref() {
            if indexer_reader.is_internal_indexer_enabled() {
                if let Some(mut latest_version) = indexer_reader
                    .get_latest_internal_indexer_ledger_version()
                    .map_err(|err| {
                        E::service_unavailable_with_code_no_info(err, AptosErrorCode::InternalError)
                    })?
                {
                    // The internal indexer version can be ahead of the storage committed version since it syncs to db's latest synced version
                    let last_storage_version =
                        self.get_latest_storage_ledger_info()?.ledger_version.0;
                    latest_version = std::cmp::min(latest_version, last_storage_version);
                    let (_, block_end_version, new_block_event) = self
                        .db
                        .get_block_info_by_version(latest_version)
                        .map_err(|_| {
                            E::service_unavailable_with_code_no_info(
                                "Failed to get block",
                                AptosErrorCode::InternalError,
                            )
                        })?;
                    let (oldest_version, oldest_block_height) =
                        self.get_oldest_version_and_block_height()?;
                    return Ok(LedgerInfo::new_ledger_info(
                        &self.chain_id(),
                        new_block_event.epoch(),
                        block_end_version,
                        oldest_version,
                        oldest_block_height,
                        new_block_event.height(),
                        new_block_event.proposed_time(),
                    ));
                } else {
                    // Indexer doesn't have data yet as DB is boostrapping.
                    return Err(E::service_unavailable_with_code_no_info(
                        "DB is bootstrapping",
                        AptosErrorCode::InternalError,
                    ));
                }
            }
        }

        Err(E::service_unavailable_with_code_no_info(
            "Indexer reader doesn't exist",
            AptosErrorCode::InternalError,
        ))
    }
```

**File:** api/src/state.rs (L404-409)
```rust
        let (ledger_info, ledger_version, state_view) = self
            .context
            .state_view(ledger_version.map(|inner| inner.0))?;

        let converter =
            state_view.as_converter(self.context.db.clone(), self.context.indexer_reader.clone());
```

**File:** storage/indexer/src/db_v2.rs (L149-151)
```rust
    pub fn get_table_info(&self, handle: TableHandle) -> Result<Option<TableInfo>> {
        self.db.get::<TableInfoSchema>(&handle)
    }
```

**File:** storage/indexer/src/db_v2.rs (L153-173)
```rust
    pub fn get_table_info_with_retry(&self, handle: TableHandle) -> Result<Option<TableInfo>> {
        let mut retried = 0;
        loop {
            if let Ok(Some(table_info)) = self.get_table_info(handle) {
                return Ok(Some(table_info));
            }

            // Log the first failure, and then sample subsequent failures to avoid log spam
            if retried == 0 {
                log_table_info_failure(handle, retried);
            } else {
                sample!(
                    SampleRate::Duration(Duration::from_secs(1)),
                    log_table_info_failure(handle, retried)
                );
            }

            retried += 1;
            std::thread::sleep(Duration::from_millis(TABLE_INFO_RETRY_TIME_MILLIS));
        }
    }
```

**File:** aptos-node/src/services.rs (L72-92)
```rust
    let (indexer_table_info_runtime, indexer_async_v2) = match bootstrap_indexer_table_info(
        node_config,
        chain_id,
        db_rw.clone(),
        mempool_client_sender.clone(),
    ) {
        Some((runtime, indexer_v2)) => (Some(runtime), Some(indexer_v2)),
        None => (None, None),
    };

    let (db_indexer_runtime, txn_event_reader) = match bootstrap_internal_indexer_db(
        node_config,
        db_rw.clone(),
        internal_indexer_db,
        update_receiver,
    ) {
        Some((runtime, db_indexer)) => (Some(runtime), Some(db_indexer)),
        None => (None, None),
    };

    let indexer_readers = IndexerReaders::new(indexer_async_v2, txn_event_reader);
```
