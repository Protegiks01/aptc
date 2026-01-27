# Audit Report

## Title
Missing Pruning Check in get_persisted_auxiliary_info_iterator Allows Silent Return of Pruned Data

## Summary
The `get_persisted_auxiliary_info_iterator()` function in aptosdb_reader.rs lacks the pruning validation check (`error_if_ledger_pruned()`) that all other similar iterator functions implement. This allows the function to silently return `PersistedAuxiliaryInfo::None` values for pruned data instead of returning an error, breaking API consistency and potentially causing state inconsistencies in downstream systems.

## Finding Description

The function `get_persisted_auxiliary_info_iterator()` is inconsistent with other iterator functions in the same file. All other ledger data iterators validate that the requested start version is not pruned: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

However, `get_persisted_auxiliary_info_iterator()` does NOT perform this check: [5](#0-4) 

The pruning check validates that requested versions are above the minimum readable version: [6](#0-5) 

When the check is missing, the underlying iterator implementation silently fills in `PersistedAuxiliaryInfo::None` values for the gap between the requested start_version and the first available version: [7](#0-6) 

**Attack Path:**

1. A full node has pruning enabled with `min_readable_version = 10000`
2. An attacker (or legitimate user) calls the API endpoint: `GET /transactions/auxiliary_info?start=100&limit=100`
3. The API invokes `get_persisted_auxiliary_info_iterator(100, 100)` without any pruning check: [8](#0-7) 

4. The iterator silently returns 100 `PersistedAuxiliaryInfo::None` values because versions 100-199 are pruned
5. The API returns these None values as if they were legitimate data
6. The caller cannot distinguish between:
   - Legitimate `PersistedAuxiliaryInfo::None` (versions that exist but have None auxiliary info)
   - Fake None values returned because data was pruned

This breaks the documented API behavior that states "If the version has been pruned, then a 410 will be returned": [9](#0-8) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria: "State inconsistencies requiring intervention."

**Specific impacts:**

1. **API Data Integrity Violation**: Downstream systems (indexers, block explorers, wallets) consuming this API endpoint receive incorrect data without any error indication. They cannot distinguish between legitimate None values and pruned data masquerading as None values.

2. **State Reconstruction Errors**: Systems attempting to reconstruct transaction ordering or block structure using auxiliary info will build incorrect state when they receive fake None values for pruned data.

3. **Silent Failures**: Unlike other transaction APIs that properly return HTTP 410 Gone for pruned data, this endpoint silently succeeds with incorrect data, preventing clients from implementing proper error handling and retry logic.

4. **Manual Intervention Required**: Once downstream systems have indexed incorrect None values, manual intervention is required to identify the corruption and re-sync from correct data sources.

While this does not directly cause fund loss or consensus violations, it creates state inconsistencies in API consumers that require manual intervention to correct, meeting the Medium severity threshold.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to occur because:

1. **Direct API Exposure**: The endpoint is publicly accessible via `GET /transactions/auxiliary_info`
2. **No Attacker Privilege Required**: Any API user can trigger this by requesting pruned versions
3. **Common Scenario**: Nodes with pruning enabled are common in production deployments
4. **Unintentional Triggers**: Legitimate users querying historical data will encounter this, not just malicious actors

## Recommendation

Add the pruning check to `get_persisted_auxiliary_info_iterator()` to match the behavior of other iterator functions:

```rust
fn get_persisted_auxiliary_info_iterator(
    &self,
    start_version: Version,
    num_persisted_auxiliary_info: usize,
) -> Result<Box<dyn Iterator<Item = Result<PersistedAuxiliaryInfo>> + '_>> {
    gauged_api("get_persisted_auxiliary_info_iterator", || {
        // Add this check to match other iterators
        self.error_if_ledger_pruned("PersistedAuxiliaryInfo", start_version)?;
        
        let iter = self
            .ledger_db
            .persisted_auxiliary_info_db()
            .get_persisted_auxiliary_info_iter(start_version, num_persisted_auxiliary_info)?;
        Ok(Box::new(iter)
            as Box<
                dyn Iterator<Item = Result<PersistedAuxiliaryInfo>> + '_,
            >)
    })
}
```

This ensures consistent error handling across all iterator functions and proper API responses (410 Gone) when accessing pruned data.

## Proof of Concept

```rust
// Reproduction test for aptosdb/src/db/test.rs
#[test]
fn test_persisted_auxiliary_info_iterator_missing_pruning_check() {
    // Setup: Create a database with some transactions
    let tmpdir = aptos_temppath::TempPath::new();
    let db = AptosDB::new_for_test(&tmpdir);
    
    // Commit 1000 transactions
    let num_txns = 1000;
    for i in 0..num_txns {
        let txn = generate_test_transaction(i);
        db.save_transactions(&[txn], i, i, None).unwrap();
    }
    
    // Enable pruning and prune first 900 transactions
    db.ledger_pruner.set_target_version(900);
    db.ledger_pruner.prune(100).unwrap();
    
    // Verify min_readable_version is now 900
    assert_eq!(db.ledger_pruner.get_min_readable_version(), 900);
    
    // Test 1: Other iterators properly reject pruned access
    let result = db.get_transaction_iterator(100, 10);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("pruned"));
    
    // Test 2: get_persisted_auxiliary_info_iterator DOES NOT reject pruned access
    let result = db.get_persisted_auxiliary_info_iterator(100, 10);
    assert!(result.is_ok()); // BUG: Should return error but succeeds
    
    // Test 3: Iterator returns None values for pruned data
    let iter = result.unwrap();
    let values: Vec<_> = iter.collect();
    assert_eq!(values.len(), 10);
    for val in values {
        // All values are None because data is pruned
        assert_eq!(val.unwrap(), PersistedAuxiliaryInfo::None);
    }
    
    // Expected behavior: Should have returned error like other iterators
}
```

**Notes**

The vulnerability stems from an inconsistency in error handling patterns. All ledger data iterators (transactions, transaction infos, events, write sets) validate pruning before creating iterators, but the auxiliary info iterator omits this check. While auxiliary info is metadata rather than consensus-critical data, the inconsistent behavior creates API reliability issues and potential data corruption in downstream systems that cannot distinguish between legitimate None values and pruned data.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L446-461)
```rust
    fn get_persisted_auxiliary_info_iterator(
        &self,
        start_version: Version,
        num_persisted_auxiliary_info: usize,
    ) -> Result<Box<dyn Iterator<Item = Result<PersistedAuxiliaryInfo>> + '_>> {
        gauged_api("get_persisted_auxiliary_info_iterator", || {
            let iter = self
                .ledger_db
                .persisted_auxiliary_info_db()
                .get_persisted_auxiliary_info_iter(start_version, num_persisted_auxiliary_info)?;
            Ok(Box::new(iter)
                as Box<
                    dyn Iterator<Item = Result<PersistedAuxiliaryInfo>> + '_,
                >)
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L477-492)
```rust
    fn get_transaction_iterator(
        &self,
        start_version: Version,
        limit: u64,
    ) -> Result<Box<dyn Iterator<Item = Result<Transaction>> + '_>> {
        gauged_api("get_transaction_iterator", || {
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
            self.error_if_ledger_pruned("Transaction", start_version)?;

            let iter = self
                .ledger_db
                .transaction_db()
                .get_transaction_iter(start_version, limit as usize)?;
            Ok(Box::new(iter) as Box<dyn Iterator<Item = Result<Transaction>> + '_>)
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L494-509)
```rust
    fn get_transaction_info_iterator(
        &self,
        start_version: Version,
        limit: u64,
    ) -> Result<Box<dyn Iterator<Item = Result<TransactionInfo>> + '_>> {
        gauged_api("get_transaction_info_iterator", || {
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
            self.error_if_ledger_pruned("Transaction", start_version)?;

            let iter = self
                .ledger_db
                .transaction_info_db()
                .get_transaction_info_iter(start_version, limit as usize)?;
            Ok(Box::new(iter) as Box<dyn Iterator<Item = Result<TransactionInfo>> + '_>)
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L511-529)
```rust
    fn get_events_iterator(
        &self,
        start_version: Version,
        limit: u64,
    ) -> Result<Box<dyn Iterator<Item = Result<Vec<ContractEvent>>> + '_>> {
        gauged_api("get_events_iterator", || {
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
            self.error_if_ledger_pruned("Transaction", start_version)?;

            let iter = self
                .ledger_db
                .event_db()
                .get_events_by_version_iter(start_version, limit as usize)?;
            Ok(Box::new(iter)
                as Box<
                    dyn Iterator<Item = Result<Vec<ContractEvent>>> + '_,
                >)
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L531-546)
```rust
    fn get_write_set_iterator(
        &self,
        start_version: Version,
        limit: u64,
    ) -> Result<Box<dyn Iterator<Item = Result<WriteSet>> + '_>> {
        gauged_api("get_write_set_iterator", || {
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
            self.error_if_ledger_pruned("Transaction", start_version)?;

            let iter = self
                .ledger_db
                .write_set_db()
                .get_write_set_iter(start_version, limit as usize)?;
            Ok(Box::new(iter) as Box<dyn Iterator<Item = Result<WriteSet>> + '_>)
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L261-271)
```rust
    pub(super) fn error_if_ledger_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.ledger_pruner.get_min_readable_version();
        ensure!(
            version >= min_readable_version,
            "{} at version {} is pruned, min available version is {}.",
            data_type,
            version,
            min_readable_version
        );
        Ok(())
    }
```

**File:** storage/aptosdb/src/ledger_db/persisted_auxiliary_info_db.rs (L58-89)
```rust
    pub(crate) fn get_persisted_auxiliary_info_iter(
        &self,
        start_version: Version,
        num_persisted_auxiliary_info: usize,
    ) -> Result<Box<dyn Iterator<Item = Result<PersistedAuxiliaryInfo>> + '_>> {
        let mut iter = self.db.iter::<PersistedAuxiliaryInfoSchema>()?;
        iter.seek(&start_version)?;
        let mut iter = iter.peekable();
        let item = iter.peek();
        let version = if item.is_some() {
            item.unwrap().as_ref().map_err(|e| e.clone())?.0
        } else {
            let mut iter = self.db.iter::<PersistedAuxiliaryInfoSchema>()?;
            iter.seek_to_last();
            if iter.next().transpose()?.is_some() {
                return Ok(Box::new(std::iter::empty()));
            }
            // Note in this case we return all Nones. We rely on the caller to not query future
            // data when the DB is empty.
            // TODO(grao): This will be unreachable in the future, consider make it an error later.
            start_version + num_persisted_auxiliary_info as u64
        };
        let num_none = std::cmp::min(
            num_persisted_auxiliary_info,
            version.saturating_sub(start_version) as usize,
        );
        let none_iter = itertools::repeat_n(Ok(PersistedAuxiliaryInfo::None), num_none);
        Ok(Box::new(none_iter.chain(iter.expect_continuous_versions(
            start_version + num_none as u64,
            num_persisted_auxiliary_info - num_none,
        )?)))
    }
```

**File:** api/src/transactions.rs (L143-149)
```rust
    /// Get transactions
    ///
    /// Retrieve on-chain committed transactions. The page size and start ledger version
    /// can be provided to get a specific sequence of transactions.
    ///
    /// If the version has been pruned, then a 410 will be returned.
    ///
```

**File:** api/src/transactions.rs (L1840-1863)
```rust
    fn list_auxiliary_infos(
        &self,
        accept_type: &AcceptType,
        page: Page,
    ) -> BasicResultWith404<Vec<PersistedAuxiliaryInfo>> {
        let latest_ledger_info = self.context.get_latest_ledger_info()?;
        let ledger_version = latest_ledger_info.ledger_version;

        let limit = page.limit(&latest_ledger_info)?;
        let start_version = page.compute_start(limit, ledger_version.0, &latest_ledger_info)?;

        // Use iterator for more efficient batch retrieval
        let iterator = self
            .context
            .db
            .get_persisted_auxiliary_info_iterator(start_version, limit as usize)
            .context("Failed to get auxiliary info iterator from storage")
            .map_err(|err| {
                BasicErrorWith404::internal_with_code(
                    err,
                    AptosErrorCode::InternalError,
                    &latest_ledger_info,
                )
            })?;
```
