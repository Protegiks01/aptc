# Audit Report

## Title
Incorrect Version Mapping in DataManager Creates Cache Gaps Due to Enumerate-Skip Bug

## Summary
The `update_data()` function in `DataManager` contains an off-by-one indexing bug when processing overlapping transaction ranges. When transactions are skipped using `.enumerate().skip()`, the enumeration indices are not adjusted, causing transactions to be stored at incorrect versions and creating gaps in the cache where valid versions return `None`.

## Finding Description
The vulnerability exists in the `update_data()` function's transaction processing loop. [1](#0-0) 

When `update_data()` is called with a `start_version` that precedes the cache's `start_version`, the function calculates `num_to_skip` to skip already-cached transactions. However, the loop uses `.enumerate().skip(num_to_skip)`, which preserves the original enumeration indices after skipping.

**Concrete Example:**
- Cache state: `start_version=102`, `end_version=110`
- Call: `update_data(100, [txn100, txn101, txn102, txn103, txn104])`
- Calculation: `num_to_skip = 102 - 100 = 2`, `start_version` reassigned to `102`
- After `.enumerate()`: `[(0, txn100), (1, txn101), (2, txn102), (3, txn103), (4, txn104)]`
- After `.skip(2)`: `[(2, txn102), (3, txn103), (4, txn104)]`
- **Loop iteration 1**: `i=2`, `version = 102 + 2 = 104` → txn102 stored at version 104 (should be 102)
- **Loop iteration 2**: `i=3`, `version = 102 + 3 = 105` → txn103 stored at version 105 (should be 103)  
- **Loop iteration 3**: `i=4`, `version = 102 + 4 = 106` → txn104 stored at version 106 (should be 104)
- **Result**: Versions 102 and 103 remain `None` (gaps), versions 104-106 contain wrong data

When clients request data through `get_data()` in `InMemoryCache`, the function checks for `None` values and either returns incomplete data or triggers unnecessary re-fetching. [2](#0-1) 

Additionally, when iterating through versions to build a response, the function breaks early upon encountering a `None` value. [3](#0-2) 

## Impact Explanation
This issue affects the **indexer-grpc data service**, which provides API access to blockchain transaction data. While this is not a consensus-layer vulnerability, it constitutes a **High Severity** issue under the "API crashes" or "Significant protocol violations" category because:

1. **Data Integrity**: The indexer serves incorrect or incomplete data for valid transaction versions
2. **Service Degradation**: Clients receive truncated responses when requesting consecutive transaction ranges
3. **Resource Waste**: Triggers unnecessary re-fetching loops that may hit the same bug repeatedly
4. **Client Impact**: Applications relying on the indexer API receive inconsistent data, potentially breaking downstream systems

While this doesn't affect blockchain consensus or validator operations, it breaks the critical guarantee that the indexer provides complete and accurate historical transaction data.

## Likelihood Explanation
**High Likelihood** - This bug triggers automatically during normal indexer operation when:
1. The indexer fetches historical data to backfill the cache (common during startup or when serving old queries)
2. Multiple concurrent fetch requests arrive for overlapping version ranges
3. The `fetch_past_data()` function is called for versions slightly before the current cache range

The scenario requires no attacker action - it occurs naturally whenever the cache receives overlapping transaction batches, which is a routine occurrence in the indexer's operation model. [4](#0-3) 

## Recommendation
Fix the enumeration index calculation by adjusting for skipped items. The correct approach is to track the actual version offset separately:

```rust
for (original_idx, transaction) in transactions
    .into_iter()
    .enumerate()
    .skip(num_to_skip as usize)
{
    let version = start_version + (original_idx as u64 - num_to_skip);
    let slot_index = version as usize % self.num_slots;
    if let Some(transaction) = self.data[slot_index].take() {
        size_decreased += transaction.encoded_len();
    }
    size_increased += transaction.encoded_len();
    self.data[slot_index] = Some(Box::new(transaction));
}
```

Alternatively, restructure to skip before enumerating:

```rust
for (i, transaction) in transactions
    .into_iter()
    .skip(num_to_skip as usize)
    .enumerate()
{
    let version = start_version + i as u64;
    // ... rest of logic
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_protos::transaction::v1::Transaction;

    #[test]
    fn test_version_gap_bug() {
        // Create a DataManager with cache starting at version 102
        let mut data_manager = DataManager::new(110, 1000, 1_000_000);
        data_manager.start_version = 102;
        data_manager.end_version = 110;

        // Create transactions for versions 100-104
        let mut transactions = vec![];
        for v in 100..=104 {
            let mut txn = Transaction::default();
            txn.version = v;
            transactions.push(txn);
        }

        // Update with overlapping range [100, 105)
        data_manager.update_data(100, transactions);

        // Check if versions 102 and 103 are None (the bug)
        assert!(
            data_manager.get_data(102).is_none(),
            "Version 102 should have data but is None due to bug"
        );
        assert!(
            data_manager.get_data(103).is_none(),
            "Version 103 should have data but is None due to bug"
        );

        // Check if versions 104-106 have data (incorrectly placed)
        assert!(
            data_manager.get_data(104).is_some(),
            "Version 104 has data (but it's actually txn102)"
        );
        assert!(
            data_manager.get_data(105).is_some(),
            "Version 105 has data (but it's actually txn103)"
        );
    }
}
```

## Notes

**Scope Clarification**: This vulnerability affects the indexer-grpc data service, which is an auxiliary component for querying blockchain data, not a core consensus component. While it doesn't impact consensus safety or validator operations, it represents a significant data integrity issue for the indexer API that applications depend on for accurate historical transaction data.

The bug is particularly insidious because it occurs silently during normal operation without obvious error signals, causing downstream applications to receive incomplete or incorrect data without realizing the service is malfunctioning.

### Citations

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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/in_memory_cache.rs (L73-77)
```rust
            if data_manager.get_data(starting_version).is_none() {
                drop(data_manager);
                self.fetch_manager.fetch_past_data(starting_version).await;
                continue;
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/in_memory_cache.rs (L88-97)
```rust
                if let Some(transaction) = data_manager.get_data(version).as_ref() {
                    // NOTE: We allow 1 more txn beyond the size limit here, for simplicity.
                    if filter.is_none() || filter.as_ref().unwrap().matches(transaction) {
                        total_bytes += transaction.encoded_len();
                        result.push(transaction.as_ref().clone());
                    }
                    version += 1;
                } else {
                    break;
                }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/fetch_manager.rs (L34-38)
```rust
    pub(super) async fn fetch_past_data(&self, version: u64) -> usize {
        let _timer = TIMER.with_label_values(&["fetch_past_data"]).start_timer();
        Self::fetch_and_update_cache(self.data_client.clone(), self.data_manager.clone(), version)
            .await
    }
```
