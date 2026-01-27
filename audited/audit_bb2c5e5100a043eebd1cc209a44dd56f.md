# Audit Report

## Title
Indexer Panic Due to Unvalidated Table Handles in SharesInnerResource

## Summary
The indexer extracts table handles from `DelegationPoolResource.active_shares.shares.inner` without validating that table metadata is available. When table items arrive before their metadata is indexed, the API layer returns `data=None`, but the indexer unconditionally panics expecting data to always be present, causing service crashes.

## Finding Description

The `SharesInnerResource` struct contains a `Table` handle that the indexer extracts and uses to identify delegation pool share balances. [1](#0-0) 

The indexer builds mappings from `DelegationPoolResource` by extracting the active shares table handle without any validation that the table metadata exists: [2](#0-1) 

When the API layer processes `WriteTableItem` changes, it attempts to look up table metadata. If the metadata is not available (e.g., due to indexing lag or newly created tables), it gracefully returns `data=None` to avoid crashes: [3](#0-2) 

However, the indexer assumes that if a table handle matches a known delegation pool, the data field must be present, and unconditionally panics if it encounters `None`: [4](#0-3) 

The same vulnerable pattern exists for inactive shares: [5](#0-4) 

And in the gRPC fullnode indexer: [6](#0-5) 

**Attack Path:**
1. A delegation pool is created or an inactive shares pool is added at a new observed lockup cycle
2. A transaction contains both the `DelegationPoolResource` (with the new table handle) and `WriteTableItem` operations on that table
3. The table metadata hasn't been indexed yet (stored in the indexer's table info cache)
4. API layer calls `get_table_info()` which returns `None`: [7](#0-6) 
5. API layer returns `WriteTableItem` with `data: None`
6. Indexer builds mapping including the new table handle from the `DelegationPoolResource`
7. Indexer processes the `WriteTableItem`, finds the handle in its mapping
8. Indexer attempts to unwrap the `data` field and **panics**, crashing the indexer

The indexer has a retry mechanism for table info lookup that loops indefinitely, but this only helps for reads, not for the incoming write operations: [8](#0-7) 

## Impact Explanation

This is a **Medium Severity** vulnerability per the Aptos bug bounty criteria:

- **Service Availability Impact**: The indexer crashes and requires manual restart, causing service unavailability
- **State Inconsistencies**: Transactions may be partially processed, requiring manual intervention or database backfilling as evidenced by error messages in the code: [9](#0-8) 
- **No Direct Fund Loss**: The vulnerability affects the indexer (read-only infrastructure), not consensus or execution
- **No Consensus Impact**: Does not affect validator operations or blockchain state

While this doesn't reach High severity (which requires validator node issues), it exceeds Low severity by causing service crashes requiring intervention.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability triggers under specific but realistic conditions:

1. **Timing Window Required**: Table items must arrive before their metadata is fully indexed - this can occur during:
   - Initial indexer startup/catchup
   - Heavy load causing indexing lag
   - Network delays in metadata propagation
   
2. **Common Operations**: Delegation pool creation and stake operations are frequent on Aptos, increasing exposure

3. **Known Issue Pattern**: The code contains evidence this scenario is anticipated (retry mechanisms, "backfill" error messages), suggesting it occurs in practice

4. **Multiple Attack Surfaces**: The vulnerability exists in at least 3 code paths (active shares, inactive shares, gRPC indexer), multiplying the attack surface

## Recommendation

**Immediate Fix**: Replace `unwrap_or_else(|| panic!(...))` with graceful error handling that logs and skips items with missing table metadata:

```rust
pub fn get_active_share_from_write_table_item(
    write_table_item: &APIWriteTableItem,
    txn_version: i64,
    active_pool_to_staking_pool: &ShareToStakingPoolMapping,
) -> anyhow::Result<Option<Self>> {
    let table_handle = standardize_address(&write_table_item.handle.to_string());
    if let Some(pool_balance) = active_pool_to_staking_pool.get(&table_handle) {
        let pool_address = pool_balance.staking_pool_address.clone();
        let delegator_address = standardize_address(&write_table_item.key.to_string());
        
        // FIXED: Gracefully handle missing data instead of panic
        let data = match write_table_item.data.as_ref() {
            Some(d) => d,
            None => {
                aptos_logger::warn!(
                    transaction_version = txn_version,
                    table_handle = &table_handle,
                    "Table item data not available for active share item. Table info may not be indexed yet."
                );
                return Ok(None);
            }
        };
        
        // ... rest of processing
    }
    Ok(None)
}
```

**Long-term Solution**: Implement table handle validation before building mappings:

1. Validate table info exists for extracted handles before adding to mappings
2. Defer processing of items with unavailable table info to retry queue (similar to the `pending_on` mechanism): [10](#0-9) 
3. Add monitoring/alerting for frequent table info cache misses

## Proof of Concept

**Rust Reproduction Steps:**

1. Set up an indexer instance with an empty or limited table info cache
2. Submit a transaction that creates a new delegation pool:
   ```rust
   // Transaction creates DelegationPool resource with new table handles
   let pool_address = create_delegation_pool(&mut aptos, operator);
   ```
3. Immediately submit transactions that perform stake operations:
   ```rust
   add_stake(&mut aptos, delegator, pool_address, amount);
   ```
4. Process these transactions through the indexer before table info is fully indexed
5. Observe panic in logs: "This table item should be an active share item" followed by indexer crash

**Triggering Conditions:**
- Indexer processing lag > table item arrival time
- Fresh indexer instance catching up with existing chain state
- High transaction volume causing table info indexing delays

The vulnerability is deterministic once the timing conditions are met: if `data` is `None` and the handle matches a mapping, the panic is guaranteed.

## Notes

This vulnerability represents a mismatch in error handling philosophy between layers: the API layer treats missing table info as a recoverable condition warranting graceful degradation, while the indexer treats it as a fatal invariant violation. The table handle in `SharesInnerResource` is not validated to ensure corresponding metadata is available before use, violating the assumption that "handle in resource" implies "table info available in cache."

### Citations

**File:** crates/indexer/src/models/stake_models/stake_utils.rs (L35-38)
```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SharesInnerResource {
    pub inner: Table,
}
```

**File:** crates/indexer/src/models/stake_models/delegator_pools.rs (L140-141)
```rust
                active_share_table_handle: inner.active_shares.shares.inner.get_handle(),
                inactive_share_table_handle: inner.inactive_shares.get_handle(),
```

**File:** api/types/src/convert.rs (L561-566)
```rust
        let table_info = match self.get_table_info(handle)? {
            Some(ti) => ti,
            None => {
                log_missing_table_info(handle);
                return Ok(None); // if table item not found return None anyway to avoid crash
            },
```

**File:** api/types/src/convert.rs (L1060-1064)
```rust
    fn get_table_info(&self, handle: TableHandle) -> Result<Option<TableInfo>> {
        if let Some(indexer_reader) = self.indexer_reader.as_ref() {
            return Ok(indexer_reader.get_table_info(handle).unwrap_or(None));
        }
        Ok(None)
```

**File:** crates/indexer/src/models/stake_models/delegator_balances.rs (L72-77)
```rust
            let data = write_table_item.data.as_ref().unwrap_or_else(|| {
                panic!(
                    "This table item should be an active share item, table_item {:?}, version {}",
                    write_table_item, txn_version
                )
            });
```

**File:** crates/indexer/src/models/stake_models/delegator_balances.rs (L133-138)
```rust
            let data = write_table_item.data.as_ref().unwrap_or_else(|| {
                panic!(
                    "This table item should be an active share item, table_item {:?}, version {}",
                    write_table_item, txn_version
                )
            });
```

**File:** crates/indexer/src/models/stake_models/delegator_balances.rs (L216-220)
```rust
                            aptos_logger::error!(
                                transaction_version = txn_version,
                                lookup_key = &inactive_pool_handle,
                                "Failed to get staking pool address from inactive share handle. You probably should backfill db.",
                            );
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/convert.rs (L438-444)
```rust
            let data = write_table_item.data.as_ref().unwrap_or_else(|| {
                panic!(
                    "Could not extract data from DecodedTableData '{:?}' with handle '{:?}'",
                    write_table_item,
                    write_table_item.handle.to_string(),
                )
            });
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

**File:** storage/indexer/src/db_v2.rs (L175-181)
```rust
    pub fn is_indexer_async_v2_pending_on_empty(&self) -> bool {
        if !self.pending_on.is_empty() {
            let pending_keys: Vec<TableHandle> =
                self.pending_on.iter().map(|entry| *entry.key()).collect();
            aptos_logger::warn!(
                "There are still pending table items to parse due to unknown table info for table handles: {:?}",
                pending_keys
```
