# Audit Report

## Title
Infinite Retry Loop in Table Info Reader Causes API Thread Exhaustion

## Summary
The `get_table_info_with_retry()` function in `IndexerAsyncV2` contains an infinite retry loop with no timeout or maximum retry count. When table handles are queried that don't exist in the indexer database, API request threads block indefinitely, leading to thread pool exhaustion and API denial of service. However, this vulnerability does **not** affect consensus directly as claimed in the security question.

## Finding Description
The vulnerability exists in the table info retry mechanism used during transaction API retrieval: [1](#0-0) 

This function contains an infinite loop that only exits when `Ok(Some(table_info))` is returned. If a table handle doesn't exist in the indexer database (returning `Ok(None)`) or if there's a database error (returning `Err(_)`), the loop continues indefinitely with only a 10ms sleep between retries.

The attack path flows as follows:

1. **API Request**: Attacker calls GET `/transactions` endpoint [2](#0-1) 

2. **Transaction Rendering**: API converts transactions to JSON format [3](#0-2) 

3. **Write Set Conversion**: For each transaction, write sets are converted including table items [4](#0-3) 

4. **Table Info Lookup**: Table operations trigger table info lookups [5](#0-4) 

5. **Retry Mechanism**: The indexer reader delegates to the infinite retry loop [6](#0-5) 

**Conditions for Exploitation:**
- Table info indexer is behind the main ledger
- Table info indexer is stopped or disabled
- Race condition where new tables are queried before indexing completes
- Database corruption or missing table info entries

## Impact Explanation
This vulnerability causes **API Denial of Service** but does **NOT affect consensus**:

**Confirmed Impact:**
- API request threads block indefinitely in the retry loop
- With concurrent requests, this exhausts the tokio blocking thread pool spawned by `api_spawn_blocking` [7](#0-6) 

- API becomes unresponsive to legitimate queries
- Matches **High Severity** criteria: "Validator node slowdowns" (if API runs on validator node) or "API crashes"

**No Consensus Impact:**
My investigation confirms consensus does NOT use `IndexerReader` or call `get_table_info()`. The consensus execution path is completely independent from the API layer and table info indexer. Even with complete API thread exhaustion, validators can still:
- Participate in consensus voting
- Execute blocks
- Maintain blockchain state
- Perform state synchronization

The security question asks about "slowdowns affecting consensus" - this is **incorrect**. The vulnerability affects API availability only, not consensus safety or liveness.

## Likelihood Explanation
**High Likelihood** - This can occur naturally:

1. **Indexer Lag**: Table info indexer processes transactions asynchronously and can fall behind during high transaction volumes [8](#0-7) 

2. **No Attack Required**: Normal operation where users query recent transactions with table operations before indexer catches up will trigger blocking

3. **Amplification**: Attacker can deliberately:
   - Submit transactions creating new tables
   - Immediately query those transactions via API
   - Repeat to exhaust all API worker threads
   - No special privileges or validator access required

## Recommendation
Add a maximum retry count and timeout to the retry loop:

**Fixed Implementation:**
```rust
pub fn get_table_info_with_retry(&self, handle: TableHandle) -> Result<Option<TableInfo>> {
    const MAX_RETRIES: u64 = 100; // 100 * 10ms = 1 second max wait
    let mut retried = 0;
    
    loop {
        match self.get_table_info(handle) {
            Ok(Some(table_info)) => return Ok(Some(table_info)),
            Ok(None) if retried >= MAX_RETRIES => {
                // Table info not found after max retries, return None
                aptos_logger::warn!(
                    retry_count = retried,
                    table_handle = handle.0.to_canonical_string(),
                    "Table info not found after maximum retries"
                );
                return Ok(None);
            },
            Err(e) if retried >= MAX_RETRIES => {
                // Database error persists, propagate error
                return Err(e);
            },
            _ => {
                // Continue retrying
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
    }
}
```

**Alternative**: Replace with exponential backoff and configurable timeout, or make table info lookup best-effort (return `None` on first miss).

## Proof of Concept

```rust
#[cfg(test)]
mod test_infinite_retry {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use std::thread;
    
    #[test]
    fn test_get_table_info_with_retry_blocks_indefinitely() {
        // Create an IndexerAsyncV2 with empty database
        let tmpdir = aptos_temppath::TempPath::new();
        let db = DB::open(
            tmpdir.path(),
            "test_indexer",
            &[TableInfoSchema::column_family_name()],
            &Default::default(),
        ).unwrap();
        
        let indexer = IndexerAsyncV2::new(db).unwrap();
        
        // Create a non-existent table handle
        let fake_handle = TableHandle(aptos_types::account_address::AccountAddress::random());
        
        // Spawn thread that calls get_table_info_with_retry
        let indexer_clone = Arc::new(indexer);
        let indexer_ref = Arc::clone(&indexer_clone);
        
        let handle = thread::spawn(move || {
            let start = Instant::now();
            // This will block indefinitely
            let _result = indexer_ref.get_table_info_with_retry(fake_handle);
            start.elapsed()
        });
        
        // Wait 1 second
        thread::sleep(Duration::from_secs(1));
        
        // Thread should still be blocked (not finished)
        assert!(
            !handle.is_finished(),
            "Thread should still be blocked in infinite retry loop"
        );
        
        // Test demonstrates the vulnerability - thread never completes
        // In production, this would exhaust API thread pool
    }
}
```

## Notes

**Critical Distinction**: While this is a valid **API denial of service** vulnerability, it does **NOT** affect consensus as stated in the security question. The consensus layer operates independently of the API and table info indexer. This vulnerability should be classified as **High Severity** for "API crashes" or "Validator node slowdowns" (API component only), not as a consensus-affecting issue.

The table info indexer is an auxiliary service for API functionality - its failure or blocking does not impact the core blockchain consensus, execution, or state commitment operations.

### Citations

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

**File:** api/src/transactions.rs (L157-180)
```rust
    async fn get_transactions(
        &self,
        accept_type: AcceptType,
        /// Ledger version to start list of transactions
        ///
        /// If not provided, defaults to showing the latest transactions
        start: Query<Option<U64>>,
        /// Max number of transactions to retrieve.
        ///
        /// If not provided, defaults to default page size
        limit: Query<Option<u16>>,
    ) -> BasicResultWith404<Vec<Transaction>> {
        fail_point_poem("endpoint_get_transactions")?;
        self.context
            .check_api_output_enabled("Get transactions", &accept_type)?;
        let page = Page::new(
            start.0.map(|v| v.0),
            limit.0,
            self.context.max_transactions_page_size(),
        );

        let api = self.clone();
        api_spawn_blocking(move || api.list(&accept_type, page)).await
    }
```

**File:** api/src/context.rs (L737-768)
```rust
    pub fn render_transactions_sequential<E: InternalError>(
        &self,
        ledger_info: &LedgerInfo,
        data: Vec<TransactionOnChainData>,
        mut timestamp: u64,
    ) -> Result<Vec<aptos_api_types::Transaction>, E> {
        if data.is_empty() {
            return Ok(vec![]);
        }

        let state_view = self.latest_state_view_poem(ledger_info)?;
        let converter = state_view.as_converter(self.db.clone(), self.indexer_reader.clone());
        let txns: Vec<aptos_api_types::Transaction> = data
            .into_iter()
            .map(|t| {
                // Update the timestamp if the next block occurs
                if let Some(txn) = t.transaction.try_as_block_metadata_ext() {
                    timestamp = txn.timestamp_usecs();
                } else if let Some(txn) = t.transaction.try_as_block_metadata() {
                    timestamp = txn.timestamp_usecs();
                }
                let txn = converter.try_into_onchain_transaction(timestamp, t)?;
                Ok(txn)
            })
            .collect::<Result<_, anyhow::Error>>()
            .context("Failed to convert transaction data from storage")
            .map_err(|err| {
                E::internal_with_code(err, AptosErrorCode::InternalError, ledger_info)
            })?;

        Ok(txns)
    }
```

**File:** api/src/context.rs (L1645-1654)
```rust
pub async fn api_spawn_blocking<F, T, E>(func: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: InternalError + Send + 'static,
{
    tokio::task::spawn_blocking(func)
        .await
        .map_err(|err| E::internal_with_code_no_info(err, AptosErrorCode::InternalError))?
}
```

**File:** api/types/src/convert.rs (L244-271)
```rust
    pub fn into_transaction_info(
        &self,
        version: u64,
        info: &aptos_types::transaction::TransactionInfo,
        accumulator_root_hash: HashValue,
        write_set: aptos_types::write_set::WriteSet,
        txn_aux_data: Option<TransactionAuxiliaryData>,
    ) -> TransactionInfo {
        TransactionInfo {
            version: version.into(),
            hash: info.transaction_hash().into(),
            state_change_hash: info.state_change_hash().into(),
            event_root_hash: info.event_root_hash().into(),
            state_checkpoint_hash: info.state_checkpoint_hash().map(|h| h.into()),
            gas_used: info.gas_used().into(),
            success: info.status().is_success(),
            vm_status: self.explain_vm_status(info.status(), txn_aux_data),
            accumulator_root_hash: accumulator_root_hash.into(),
            // TODO: the resource value is interpreted by the type definition at the version of the converter, not the version of the tx: must be fixed before we allow module updates
            changes: write_set
                .into_write_op_iter()
                .filter_map(|(sk, wo)| self.try_into_write_set_changes(sk, wo).ok())
                .flatten()
                .collect(),
            block_height: None,
            epoch: None,
        }
    }
```

**File:** api/types/src/convert.rs (L519-553)
```rust
    pub fn try_table_item_into_write_set_change(
        &self,
        state_key_hash: String,
        handle: TableHandle,
        key: Vec<u8>,
        op: WriteOp,
    ) -> Result<WriteSetChange> {
        let hex_handle = handle.0.to_vec().into();
        let key: HexEncodedBytes = key.into();
        let ret = match op.bytes() {
            None => {
                let data = self.try_delete_table_item_into_deleted_table_data(handle, &key.0)?;

                WriteSetChange::DeleteTableItem(DeleteTableItem {
                    state_key_hash,
                    handle: hex_handle,
                    key,
                    data,
                })
            },
            Some(bytes) => {
                let data =
                    self.try_write_table_item_into_decoded_table_data(handle, &key.0, bytes)?;

                WriteSetChange::WriteTableItem(WriteTableItem {
                    state_key_hash,
                    handle: hex_handle,
                    key,
                    value: bytes.to_vec().into(),
                    data,
                })
            },
        };
        Ok(ret)
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

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L1-20)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{
    backup_restore::gcs::GcsBackupRestoreOperator, snapshot_folder_name, snapshot_folder_prefix,
};
use anyhow::{anyhow, Context, Error};
use aptos_api::context::Context as ApiContext;
use aptos_api_types::TransactionOnChainData;
use aptos_db_indexer::db_v2::IndexerAsyncV2;
use aptos_indexer_grpc_fullnode::stream_coordinator::{
    IndexerStreamCoordinator, TransactionBatchInfo,
};
use aptos_indexer_grpc_utils::counters::{log_grpc_step, IndexerGrpcStep};
use aptos_logger::{debug, error, info, sample, sample::SampleRate};
use itertools::Itertools;
use std::{
    cmp::Ordering as CmpOrdering,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
```
