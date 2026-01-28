# Audit Report

## Title
Block Metadata Desynchronization After Database Truncation Causes API to Return Wrong Block Information

## Summary
The database truncation logic fails to delete `BlockInfoSchema` and `BlockByVersionSchema` entries during rollback operations. This causes stale block metadata to persist after crash recovery, leading to API queries returning NewBlockEvents from different blocks than requested when storage sharding is enabled.

## Finding Description

When an Aptos node crashes and restarts, the `sync_commit_progress` function is called during StateStore initialization to ensure database consistency by truncating uncommitted data. [1](#0-0) 

The truncation process has a critical flaw in block metadata cleanup. Two schemas store block metadata mappings:
- `BlockInfoSchema`: Maps block height to BlockInfo containing first_version, epoch, round, proposer, and timestamp [2](#0-1) 
- `BlockByVersionSchema`: Maps version to block height as an index [3](#0-2) 

During truncation, the `truncate_ledger_db_single_batch` function deletes various schemas but **completely omits** BlockInfoSchema and BlockByVersionSchema. [4](#0-3) 

The imports in the truncation helper confirm these schemas are not referenced. [5](#0-4) 

The `delete_per_version_data` function only cleans up specific version-keyed schemas (TransactionAccumulatorRootHashSchema, TransactionInfoSchema, TransactionSchema, VersionDataSchema, WriteSetSchema), and BlockByVersionSchema is **not included** despite using Version as its key. [6](#0-5) 

**Vulnerability Trigger:**

This vulnerability is triggered when `enable_storage_sharding` is enabled, which defaults to `true` in production configuration. [7](#0-6) 

When storage sharding is enabled, it is passed as the `skip_index_and_usage` parameter during database initialization. [8](#0-7) 

When `skip_index_and_usage` is true, the `get_raw_block_info_by_height` function retrieves BlockInfo directly from BlockInfoSchema instead of from event stores. [9](#0-8) 

**Attack Scenario:**

1. Node has committed blocks up to version 1000, with block height 51 containing versions 996-1000
2. Node crashes, database truncates to version 989 via `sync_commit_progress`
3. BlockInfoSchema[51] = {first_version: 996} remains in database (NOT deleted due to missing cleanup)
4. Blockchain re-executes with different blocks; version 996 now belongs to block 50
5. API call `get_block_info_by_height(51)` retrieves stale BlockInfo from BlockInfoSchema [10](#0-9) 
6. The `to_api_block_info` function fetches NewBlockEvent at the stale first_version [11](#0-10) 
7. Returns NewBlockEvent from the **new** block 50, not the queried block 51
8. API consumer receives inconsistent data where queried block height does not match returned event

## Impact Explanation

This is a **MEDIUM severity** vulnerability per Aptos bug bounty criteria as it causes "State inconsistencies requiring manual intervention."

**Concrete Impacts:**
1. **API Data Corruption**: REST API endpoints return wrong block metadata for block height queries
2. **Indexer Failures**: Blockchain indexers relying on block height queries will index incorrect data, potentially corrupting their databases
3. **External Service Issues**: Third-party services using block info may make incorrect decisions based on inconsistent data

**Affected Systems:**
- All nodes with storage sharding enabled (production default) that experience crashes requiring truncation
- External services querying block info by height
- Third-party indexers and analytics tools

This does NOT directly cause fund loss, consensus breaks, or network halts, placing it in MEDIUM rather than HIGH/CRITICAL severity.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers automatically in normal operations:
- Database truncation occurs during every node restart after an incomplete commit (crashes, power failures, OOM kills)
- No attacker action required - it's a deterministic bug in the cleanup logic
- Affects all nodes running Aptos with default storage configuration
- The `sync_commit_progress` function is explicitly called during StateStore initialization for all non-test environments [1](#0-0) 

## Recommendation

Add BlockInfoSchema and BlockByVersionSchema deletion to the `truncate_ledger_db_single_batch` function:

1. Import the missing schemas in `truncation_helper.rs`
2. Add deletion logic for BlockInfoSchema entries at or after the truncation point
3. Add deletion logic for BlockByVersionSchema entries at or after the truncation point

The fix should iterate through both schemas and delete all entries with keys >= start_version (for BlockByVersionSchema) or corresponding to blocks that start at or after start_version (for BlockInfoSchema).

## Proof of Concept

```rust
// This test would demonstrate the vulnerability:
// 1. Write BlockInfo entries for blocks 50-52
// 2. Simulate crash by calling truncate_ledger_db to version before block 51
// 3. Verify BlockInfoSchema[51] still exists (BUG)
// 4. Write new block at version where block 51 used to start
// 5. Call get_block_info_by_height(51) with skip_index_and_usage=true
// 6. Observe that stale BlockInfo is returned with wrong first_version
// 7. Verify to_api_block_info returns NewBlockEvent from wrong block
```

## Notes

This vulnerability demonstrates a critical gap in database consistency management. The truncation logic carefully deletes many schemas but overlooks the block metadata schemas that are only used when storage sharding is enabled. Since storage sharding is the default production configuration, this affects most Aptos nodes in practice. The bug requires manual database cleanup or full re-sync to recover from, making it a genuine MEDIUM severity issue that warrants fixing in the storage layer.

### Citations

**File:** storage/aptosdb/src/state_store/mod.rs (L353-359)
```rust
        if !hack_for_tests && !empty_buffered_state_for_restore {
            Self::sync_commit_progress(
                Arc::clone(&ledger_db),
                Arc::clone(&state_kv_db),
                Arc::clone(&state_merkle_db),
                /*crash_if_difference_is_too_large=*/ true,
            );
```

**File:** storage/aptosdb/src/schema/block_info/mod.rs (L4-25)
```rust
//! This module defines physical storage schema for block info.
//!
//! ```text
//! |<-----key----->|<---value--->|
//! |  block_height |  block_info |
//! ```

use crate::schema::{ensure_slice_len_eq, BLOCK_INFO_CF_NAME};
use anyhow::Result;
use aptos_schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use aptos_storage_interface::block_info::BlockInfo;
use aptos_types::block_info::BlockHeight;
use byteorder::{BigEndian, ReadBytesExt};
use std::mem::size_of;

type Key = BlockHeight;
type Value = BlockInfo;

define_schema!(BlockInfoSchema, Key, Value, BLOCK_INFO_CF_NAME);
```

**File:** storage/aptosdb/src/schema/block_by_version/mod.rs (L4-25)
```rust
//! This module defines physical storage schema for an index to help us fine out which block a
//! ledger version is in, by storing a block_start_version <-> block_height pair.
//!
//! ```text
//! |<--------key-------->|<---value---->|
//! | block_start_version | block_height |
//! ```

use crate::schema::{ensure_slice_len_eq, BLOCK_BY_VERSION_CF_NAME};
use anyhow::Result;
use aptos_schemadb::{
    define_schema,
    schema::{KeyCodec, ValueCodec},
};
use aptos_types::{block_info::BlockHeight, transaction::Version};
use byteorder::{BigEndian, ReadBytesExt};
use std::mem::size_of;

type Key = Version;
type Value = BlockHeight;

define_schema!(BlockByVersionSchema, Key, Value, BLOCK_BY_VERSION_CF_NAME);
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L11-29)
```rust
    schema::{
        db_metadata::{DbMetadataKey, DbMetadataSchema, DbMetadataValue},
        epoch_by_version::EpochByVersionSchema,
        jellyfish_merkle_node::JellyfishMerkleNodeSchema,
        ledger_info::LedgerInfoSchema,
        stale_node_index::StaleNodeIndexSchema,
        stale_node_index_cross_epoch::StaleNodeIndexCrossEpochSchema,
        stale_state_value_index::StaleStateValueIndexSchema,
        stale_state_value_index_by_key_hash::StaleStateValueIndexByKeyHashSchema,
        state_value::StateValueSchema,
        state_value_by_key_hash::StateValueByKeyHashSchema,
        transaction::TransactionSchema,
        transaction_accumulator::TransactionAccumulatorSchema,
        transaction_accumulator_root_hash::TransactionAccumulatorRootHashSchema,
        transaction_info::TransactionInfoSchema,
        transaction_summaries_by_account::TransactionSummariesByAccountSchema,
        version_data::VersionDataSchema,
        write_set::WriteSetSchema,
    },
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L325-361)
```rust
fn truncate_ledger_db_single_batch(
    ledger_db: &LedgerDb,
    transaction_store: &TransactionStore,
    start_version: Version,
) -> Result<()> {
    let mut batch = LedgerDbSchemaBatches::new();

    delete_transaction_index_data(
        ledger_db,
        transaction_store,
        start_version,
        &mut batch.transaction_db_batches,
    )?;
    delete_per_epoch_data(
        &ledger_db.metadata_db_arc(),
        start_version,
        &mut batch.ledger_metadata_db_batches,
    )?;
    delete_per_version_data(ledger_db, start_version, &mut batch)?;

    delete_event_data(ledger_db, start_version, &mut batch.event_db_batches)?;

    truncate_transaction_accumulator(
        ledger_db.transaction_accumulator_db_raw(),
        start_version,
        &mut batch.transaction_accumulator_db_batches,
    )?;

    let mut progress_batch = SchemaBatch::new();
    progress_batch.put::<DbMetadataSchema>(
        &DbMetadataKey::LedgerCommitProgress,
        &DbMetadataValue::Version(start_version - 1),
    )?;
    ledger_db.metadata_db().write_schemas(progress_batch)?;

    ledger_db.write_schemas(batch)
}
```

**File:** storage/aptosdb/src/utils/truncation_helper.rs (L430-461)
```rust
fn delete_per_version_data(
    ledger_db: &LedgerDb,
    start_version: Version,
    batch: &mut LedgerDbSchemaBatches,
) -> Result<()> {
    delete_per_version_data_impl::<TransactionAccumulatorRootHashSchema>(
        ledger_db.transaction_accumulator_db_raw(),
        start_version,
        &mut batch.transaction_accumulator_db_batches,
    )?;
    delete_per_version_data_impl::<TransactionInfoSchema>(
        ledger_db.transaction_info_db_raw(),
        start_version,
        &mut batch.transaction_info_db_batches,
    )?;
    delete_transactions_and_transaction_summary_data(
        ledger_db.transaction_db(),
        start_version,
        &mut batch.transaction_db_batches,
    )?;
    delete_per_version_data_impl::<VersionDataSchema>(
        &ledger_db.metadata_db_arc(),
        start_version,
        &mut batch.ledger_metadata_db_batches,
    )?;
    delete_per_version_data_impl::<WriteSetSchema>(
        ledger_db.write_set_db_raw(),
        start_version,
        &mut batch.write_set_db_batches,
    )?;

    Ok(())
```

**File:** config/src/config/storage_config.rs (L233-233)
```rust
            enable_storage_sharding: true,
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L157-157)
```rust
            rocksdb_configs.enable_storage_sharding,
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L317-338)
```rust
    pub(super) fn get_raw_block_info_by_height(&self, block_height: u64) -> Result<BlockInfo> {
        if !self.skip_index_and_usage {
            let (first_version, new_block_event) = self.event_store.get_event_by_key(
                &new_block_event_key(),
                block_height,
                self.ensure_synced_version()?,
            )?;
            let new_block_event = bcs::from_bytes(new_block_event.event_data())?;
            Ok(BlockInfo::from_new_block_event(
                first_version,
                &new_block_event,
            ))
        } else {
            Ok(self
                .ledger_db
                .metadata_db()
                .get_block_info(block_height)?
                .ok_or_else(|| {
                    AptosDbError::NotFound(format!("BlockInfo not found at height {block_height}"))
                })?)
        }
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L389-392)
```rust
        let new_block_event = self
            .ledger_db
            .event_db()
            .expect_new_block_event(block_info.first_version())?;
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L265-267)
```rust
    pub(crate) fn get_block_info(&self, block_height: u64) -> Result<Option<BlockInfo>> {
        self.db.get::<BlockInfoSchema>(&block_height)
    }
```
