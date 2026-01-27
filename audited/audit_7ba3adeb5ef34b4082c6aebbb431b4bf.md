# Audit Report

## Title
Missing Transaction Continuity Validation in Indexer Data Service V2 Causes Cache Corruption

## Summary
The `indexer-grpc-data-service-v2` lacks validation to ensure transactions are consecutive, allowing cache corruption when upstream servers return non-sequential or partial transaction batches. This is a regression from v1 which explicitly validates and panics on gaps.

## Finding Description

The `fetch_and_update_cache()` function in `fetch_manager.rs` fetches transactions and updates the cache without validating transaction continuity. [1](#0-0) 

The `DataClient::fetch_transactions()` only validates that the first transaction's version matches the requested starting version, but does not verify that all transactions are consecutive. [2](#0-1) 

The `DataManager::update_data()` stores transactions assuming they are consecutive, calculating version as `start_version + i` without checking the actual `transaction.version` field. [3](#0-2) 

**Bug 1: No Transaction Continuity Validation**
If the upstream GRPC server returns transactions [v100, v101, v105, v106] (missing v102-v104), the code stores:
- Transaction v100 at cache slot 100 ✓
- Transaction v101 at cache slot 101 ✓  
- Transaction v105 at cache slot 102 ✗
- Transaction v106 at cache slot 103 ✗

**Bug 2: Enumerate/Skip Index Calculation Error**
When processing overlapping batches, the code has an indexing bug. [4](#0-3) 

After `enumerate()` then `skip()`, the index `i` retains its original position, but `start_version` was already adjusted upward by `num_to_skip`, causing incorrect version calculation.

**Contrast with V1 Service:**
The v1 service has `ensure_sequential_transactions()` which explicitly detects gaps and panics. [5](#0-4) 

This validation is completely absent in v2, making it a security regression.

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

The cache corruption affects the indexer ecosystem:
- Downstream clients (dapps, wallets, explorers) receive incorrect transaction data
- Users could be misled about balances, NFT ownership, or transaction status
- Could lead to incorrect financial decisions based on wrong data
- Requires manual intervention to detect and fix cache corruption

While this does not directly affect consensus or validator nodes, it impacts the broader Aptos ecosystem that relies on accurate indexer data for user-facing applications.

## Likelihood Explanation

**Likelihood: Medium to High**

This can occur through:
1. **Bugs in upstream server**: Natural software bugs causing non-consecutive responses
2. **Network corruption**: Packet loss or corruption causing incomplete batches
3. **Malicious upstream**: Users running indexers pointing to compromised GRPC servers
4. **Concurrent fetch race conditions**: Overlapping batch fetches triggering the enumerate/skip bug

The v2 service is actively used in production, and the lack of validation means any upstream inconsistency silently corrupts the cache.

## Recommendation

**Fix 1: Add Transaction Continuity Validation**
```rust
fn validate_transactions_sequential(transactions: &[Transaction], expected_start: u64) -> bool {
    if transactions.is_empty() {
        return true;
    }
    
    if transactions.first().unwrap().version != expected_start {
        return false;
    }
    
    for window in transactions.windows(2) {
        if window[0].version + 1 != window[1].version {
            return false;
        }
    }
    true
}

// In fetch_and_update_cache:
let transactions = data_client.fetch_transactions(version).await;
if !validate_transactions_sequential(&transactions, version) {
    error!("Non-sequential transactions detected, expected start: {}", version);
    return 0;
}
```

**Fix 2: Correct the Enumerate/Skip Bug**
```rust
// Move enumerate() AFTER skip()
for (i, transaction) in transactions
    .into_iter()
    .skip(num_to_skip as usize)
    .enumerate()  // enumerate after skip
{
    let version = start_version + i as u64;
    // ... rest of the code
}
```

**Fix 3: Validate Each Transaction's Version**
```rust
for (i, transaction) in transactions
    .into_iter()
    .skip(num_to_skip as usize)
    .enumerate()
{
    let expected_version = start_version + i as u64;
    if transaction.version != expected_version {
        error!("Transaction version mismatch: expected {}, got {}", 
               expected_version, transaction.version);
        break;
    }
    // ... store transaction
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_protos::transaction::v1::Transaction;

    #[test]
    fn test_non_consecutive_transactions_corrupt_cache() {
        let mut data_manager = DataManager::new(0, 1000, 1_000_000);
        
        // Simulate non-consecutive transactions from malicious/buggy upstream
        let mut transactions = vec![];
        transactions.push(Transaction { version: 100, ..Default::default() });
        transactions.push(Transaction { version: 101, ..Default::default() });
        transactions.push(Transaction { version: 105, ..Default::default() }); // Gap!
        transactions.push(Transaction { version: 106, ..Default::default() });
        
        // Update cache - will incorrectly store v105 at slot 102
        data_manager.update_data(100, transactions);
        
        // Verify corruption: slot 102 should have v102, but has v105
        let txn_at_102 = data_manager.get_data(102);
        assert!(txn_at_102.is_some());
        assert_eq!(txn_at_102.as_ref().unwrap().version, 105); // WRONG!
        
        // Clients requesting v102 will get v105's data
        println!("Cache corruption detected: version mismatch!");
    }
    
    #[test]
    fn test_enumerate_skip_bug() {
        let mut data_manager = DataManager::new(105, 1000, 1_000_000);
        
        // Cache has v105-110, fetch returns v100-109
        let mut transactions = vec![];
        for v in 100..110 {
            transactions.push(Transaction { version: v, ..Default::default() });
        }
        
        // This should skip first 5 and store v105-109
        // But due to bug, v105 gets stored at slot 110
        data_manager.update_data(100, transactions);
        
        let txn_at_110 = data_manager.get_data(110);
        assert!(txn_at_110.is_some());
        assert_eq!(txn_at_110.as_ref().unwrap().version, 105); // WRONG!
    }
}
```

## Notes

This vulnerability represents a significant data integrity regression from v1 to v2 of the indexer data service. While it does not affect core consensus or execution, it poses risks to the ecosystem applications that depend on accurate indexer data. The v1 service's fail-stop behavior (panic on gaps) is significantly safer than v2's silent corruption, as it prevents bad data from propagating to clients.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/fetch_manager.rs (L48-64)
```rust
    async fn fetch_and_update_cache(
        data_client: Arc<DataClient>,
        data_manager: Arc<RwLock<DataManager>>,
        version: u64,
    ) -> usize {
        let transactions = data_client.fetch_transactions(version).await;
        let len = transactions.len();

        if len > 0 {
            data_manager
                .write()
                .await
                .update_data(version, transactions);
        }

        len
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/data_client.rs (L18-43)
```rust
    pub(super) async fn fetch_transactions(&self, starting_version: u64) -> Vec<Transaction> {
        trace!("Fetching transactions from GrpcManager, start_version: {starting_version}.");

        let request = GetTransactionsRequest {
            starting_version: Some(starting_version),
            transactions_count: None,
            batch_size: None,
            transaction_filter: None,
        };
        loop {
            let mut client = self
                .connection_manager
                .get_grpc_manager_client_for_request();
            let response = client.get_transactions(request.clone()).await;
            if let Ok(response) = response {
                let transactions = response.into_inner().transactions;
                if transactions.is_empty() {
                    return vec![];
                }
                if transactions.first().unwrap().version == starting_version {
                    return transactions;
                }
            }
            // TODO(grao): Error handling.
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/data_manager.rs (L69-87)
```rust
        let num_to_skip = self.start_version.saturating_sub(start_version);
        let start_version = start_version.max(self.start_version);

        let mut size_increased = 0;
        let mut size_decreased = 0;

        for (i, transaction) in transactions
            .into_iter()
            .enumerate()
            .skip(num_to_skip as usize)
        {
            let version = start_version + i as u64;
            let slot_index = version as usize % self.num_slots;
            if let Some(transaction) = self.data[slot_index].take() {
                size_decreased += transaction.encoded_len();
            }
            size_increased += transaction.encoded_len();
            self.data[version as usize % self.num_slots] = Some(Box::new(transaction));
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L637-658)
```rust
            if prev_end + 1 != start_version {
                NUM_MULTI_FETCH_OVERLAPPED_VERSIONS
                    .with_label_values(&[SERVICE_TYPE, "gap"])
                    .inc_by(prev_end - start_version + 1);

                tracing::error!(
                    batch_first_version = first_version,
                    batch_last_version = last_version,
                    start_version = start_version,
                    end_version = end_version,
                    prev_start = ?prev_start,
                    prev_end = prev_end,
                    "[Filestore] Gaps or dupes in processing version data"
                );
                panic!("[Filestore] Gaps in processing data batch_first_version: {}, batch_last_version: {}, start_version: {}, end_version: {}, prev_start: {:?}, prev_end: {:?}",
                       first_version,
                       last_version,
                       start_version,
                       end_version,
                       prev_start,
                       prev_end,
                );
```
