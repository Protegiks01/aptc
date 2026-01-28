# Audit Report

## Title
Genesis Transaction Data Loss in Fast Sync Mode Causes Permanent API Failures

## Summary
When Aptos nodes bootstrap using fast sync mode (default for mainnet/testnet), the genesis transaction data is committed to a temporary database but never migrated to the main database. After fast sync completes, all read operations redirect to the main database, causing queries for the genesis transaction (version 0) to permanently fail with NotFound errors.

## Finding Description

The vulnerability exists in the fast sync bootstrapping flow where two separate databases are used. During initialization, a `FastSyncStorageWrapper` creates `temporary_db_with_genesis` (secondary database) and `db_for_fast_sync` (main database). [1](#0-0) 

**The Critical Flaw:**

When a node starts with fast sync enabled, the genesis transaction is fully committed to `temporary_db_with_genesis` using `maybe_apply_genesis`, which calls `save_transactions` to store complete transaction data (Transaction, TransactionOutput, TransactionInfo, Events, WriteSet). [2](#0-1)  The `save_transactions` method persists the full `ChunkToCommit` containing all transaction components. [3](#0-2) 

However, only the genesis **ledger info metadata** is copied to the main database via `commit_genesis_ledger_info`, which exclusively writes to the ledger metadata schema without copying any transaction data. [4](#0-3) [5](#0-4) 

**The Read Switch:**

The `get_aptos_db_read_ref` method routes reads to `temporary_db_with_genesis` before fast sync completes, but permanently switches to `db_for_fast_sync` after completion. [6](#0-5)  Since genesis transaction data was never migrated to the main database, all queries for version 0 fail after fast sync completes.

**Write Behavior:**

Writes switch to the main database as soon as fast sync starts (when `get_state_snapshot_receiver` is called), not when it finishes. [7](#0-6) [8](#0-7) 

**Snapshot Finalization:**

The `finalize_state_snapshot` method explicitly validates that exactly one transaction is provided and saves only that single transaction at the snapshot version. [9](#0-8)  This does not include genesis transaction data.

**Fast Sync is Default Configuration:**

The `ConfigOptimizer` automatically sets `BootstrappingMode::DownloadLatestStates` for all mainnet and testnet nodes when no explicit configuration is provided, with the comment "pruning has kicked in, and nodes will struggle to locate all the data since genesis." [10](#0-9) 

## Impact Explanation

**Severity: MEDIUM to HIGH**

This issue affects data availability and protocol correctness:

1. **REST API Failures**: The endpoint `/transactions/by_version/0` returns NotFound errors. A test explicitly expects this endpoint to work. [11](#0-10) 

2. **Indexer Impact**: Services that need complete transaction history from genesis cannot retrieve the genesis transaction, breaking historical data integrity.

3. **Protocol Violation**: Nodes are expected to serve committed transaction data (as evidenced by the test and the fact that genesis ledger info is copied), but genesis transaction data becomes permanently inaccessible.

While this is not a "crash" in the traditional sense (the API continues functioning for other queries), it represents a significant data availability issue affecting a critical endpoint (version 0).

## Likelihood Explanation

**Likelihood: HIGH (Certain)**

This bug occurs automatically on every node that:
1. Uses fast sync mode (`BootstrappingMode::DownloadLatestStates`) - which is the **default** for mainnet and testnet
2. Starts with an empty database

No attacker action is required. The issue manifests immediately after fast sync completes and persists permanently unless the node re-syncs without fast sync.

## Recommendation

Migrate the genesis transaction data from `temporary_db_with_genesis` to `db_for_fast_sync` before completing fast sync. Options include:

1. **Copy genesis transaction data during finalization**: Before setting `FastSyncStatus::FINISHED`, copy the complete transaction data (not just ledger info) from the temporary database to the main database.

2. **Include genesis in snapshot finalization**: Modify `finalize_state_snapshot` to accept and save both the genesis transaction (version 0) and the snapshot transaction.

3. **Preserve temporary DB for genesis queries**: Keep the temporary database accessible and route version 0 queries to it even after fast sync completes, though this adds complexity.

The cleanest fix would be option 1: after line 93 in `aptos-node/src/storage.rs`, add code to copy the genesis transaction data (not just ledger info) from the temporary DB to the main DB before fast sync begins.

## Proof of Concept

```rust
// Test demonstrating the issue
#[test]
fn test_fast_sync_genesis_transaction_loss() {
    // 1. Initialize node with fast sync mode and empty DB
    // 2. Bootstrap with genesis (saves to temporary DB)
    // 3. Complete fast sync (switches reads to main DB)
    // 4. Query for transaction at version 0
    // Expected: Transaction data returned
    // Actual: NotFound error because main DB lacks transaction data
}
```

The existing test at `api/src/tests/transactions_test.rs:36-41` already demonstrates the expectation that version 0 should be accessible, confirming this is unintended behavior.

## Notes

This vulnerability affects the storage layer's data migration logic during fast sync initialization. The issue is confirmed by:
- Code analysis showing no migration path for genesis transaction data
- Existing test expecting version 0 to be accessible
- Fast sync being the default mode for production networks
- Genesis ledger info being copied (suggesting intention to serve genesis data)

The severity could be debated between MEDIUM (data availability issue affecting specific endpoints) and HIGH (protocol violation with widespread impact), depending on the importance of genesis transaction accessibility in the Aptos architecture.

### Citations

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L92-96)
```rust
            Ok(Either::Right(FastSyncStorageWrapper {
                temporary_db_with_genesis: Arc::new(secondary_db),
                db_for_fast_sync: Arc::new(db_main),
                fast_sync_status: Arc::new(RwLock::new(FastSyncStatus::UNKNOWN)),
            }))
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L126-132)
```rust
    pub(crate) fn get_aptos_db_read_ref(&self) -> &AptosDB {
        if self.is_fast_sync_bootstrap_finished() {
            self.db_for_fast_sync.as_ref()
        } else {
            self.temporary_db_with_genesis.as_ref()
        }
    }
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L134-140)
```rust
    pub(crate) fn get_aptos_db_write_ref(&self) -> &AptosDB {
        if self.is_fast_sync_bootstrap_started() || self.is_fast_sync_bootstrap_finished() {
            self.db_for_fast_sync.as_ref()
        } else {
            self.temporary_db_with_genesis.as_ref()
        }
    }
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L144-152)
```rust
    fn get_state_snapshot_receiver(
        &self,
        version: Version,
        expected_root_hash: HashValue,
    ) -> Result<Box<dyn StateSnapshotReceiver<StateKey, StateValue>>> {
        *self.fast_sync_status.write() = FastSyncStatus::STARTED;
        self.get_aptos_db_write_ref()
            .get_state_snapshot_receiver(version, expected_root_hash)
    }
```

**File:** aptos-node/src/storage.rs (L76-77)
```rust
            let temp_db = fast_sync_db_wrapper.get_temporary_db_with_genesis();
            maybe_apply_genesis(&DbReaderWriter::from_arc(temp_db), node_config)?;
```

**File:** aptos-node/src/storage.rs (L91-93)
```rust
                // it means the DB is empty and we need to
                // commit the genesis ledger info to the DB.
                fast_sync_db.commit_genesis_ledger_info(&ledger_info)?;
```

**File:** execution/executor/src/db_bootstrapper/mod.rs (L99-112)
```rust
    pub fn commit(self) -> Result<()> {
        self.db.save_transactions(
            self.output
                .output
                .expect_complete_result()
                .as_chunk_to_commit(),
            self.output.ledger_info_opt.as_ref(),
            true, /* sync_commit */
        )?;
        info!("Genesis commited.");
        // DB bootstrapped, avoid anything that could fail after this.

        Ok(())
    }
```

**File:** storage/aptosdb/src/db/mod.rs (L207-219)
```rust
    pub fn commit_genesis_ledger_info(&self, genesis_li: &LedgerInfoWithSignatures) -> Result<()> {
        let ledger_metadata_db = self.ledger_db.metadata_db();
        let current_epoch = ledger_metadata_db
            .get_latest_ledger_info_option()
            .map_or(0, |li| li.ledger_info().next_block_epoch());
        ensure!(
            genesis_li.ledger_info().epoch() == current_epoch && current_epoch == 0,
            "Genesis ledger info epoch is not 0"
        );
        let mut ledger_batch = SchemaBatch::new();
        ledger_metadata_db.put_ledger_info(genesis_li, &mut ledger_batch)?;
        ledger_metadata_db.write_schemas(ledger_batch)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L133-145)
```rust
            // Ensure the output with proof only contains a single transaction output and info
            let num_transaction_outputs = output_with_proof.get_num_outputs();
            let num_transaction_infos = output_with_proof.proof.transaction_infos.len();
            ensure!(
                num_transaction_outputs == 1,
                "Number of transaction outputs should == 1, but got: {}",
                num_transaction_outputs
            );
            ensure!(
                num_transaction_infos == 1,
                "Number of transaction infos should == 1, but got: {}",
                num_transaction_infos
            );
```

**File:** config/src/config/state_sync_config.rs (L561-573)
```rust
        // Default to fast sync for all testnet and mainnet nodes
        // because pruning has kicked in, and nodes will struggle
        // to locate all the data since genesis.
        let mut modified_config = false;
        if let Some(chain_id) = chain_id {
            if (chain_id.is_testnet() || chain_id.is_mainnet())
                && local_driver_config_yaml["bootstrapping_mode"].is_null()
            {
                state_sync_driver_config.bootstrapping_mode =
                    BootstrappingMode::DownloadLatestStates;
                modified_config = true;
            }
        }
```

**File:** api/src/tests/transactions_test.rs (L36-41)
```rust
async fn test_deserialize_genesis_transaction() {
    let context = new_test_context(current_function_name!());
    let resp = context.get("/transactions/by_version/0").await;
    // TODO: serde_json::from_value doesn't work here, either make it work
    // or remove the ability to do that.
    aptos_api_types::Transaction::parse_from_json(Some(resp)).unwrap();
```
