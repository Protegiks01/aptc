# Audit Report

## Title
File Processor Crash Due to Race Condition Between Version Read and Data Fetch in Indexer GRPC Cache

## Summary

The `get_latest_version()` function in the indexer-grpc cache operator does not guarantee atomic reads with subsequent data fetches. The file processor reads the latest cache version and assumes all transactions below this version are available, but cache eviction can occur concurrently, causing the file processor to crash when attempting to fetch already-evicted transactions.

## Finding Description

The vulnerability exists in the interaction between reading the latest version and fetching transaction data in the file processor: [1](#0-0) 

This function performs a simple Redis GET operation with no atomicity guarantees. The cache worker actively evicts transactions when adding new versions: [2](#0-1) 

When version V >= 300,000 is added, version (V - 300,000) is deleted. The file processor uses this pattern: [3](#0-2) 

The processor reads the latest version, then creates batches to fetch. The critical flaw is at the check on line 133: it only verifies `start_version + 1000 < cache_worker_latest` but doesn't verify `start_version >= (cache_worker_latest - 300,000)`, which is the actual cache retention window.

When the processor attempts to fetch these transactions: [4](#0-3) 

The `get_transactions` call performs an mget operation and validates all transactions are returned: [5](#0-4) 

If any transaction is evicted between the version read and data fetch, this check fails, causing a panic that propagates through `try_join_all`: [6](#0-5) 

The code acknowledges this non-atomicity issue but provides insufficient protection: [7](#0-6) 

## Impact Explanation

**High Severity** - This qualifies as an API crash per Aptos bug bounty categories. When exploited:

1. **Service Crash**: The file processor panics completely, halting transaction archival to file store
2. **Data Loss Risk**: Transactions evicted from cache before archival are permanently lost if the gap exceeds the cache window
3. **Service Unavailability**: The indexer-grpc data service loses its file store backup, degrading availability
4. **Recovery Complexity**: Manual intervention required to restart and potentially recover lost data

## Likelihood Explanation

**High Likelihood** - This can occur naturally in production:

1. **Slow File Store Operations**: Network latency or storage issues cause the file processor to lag
2. **Processor Restarts**: After maintenance or crashes, the processor must catch up from its last checkpoint
3. **High Transaction Rate**: During peak loads, the cache worker can advance 300,000+ transactions while file processor handles slow uploads
4. **Window Violation**: If `batch_start_version < (cache_worker_latest - 300,000)`, the attack triggers automatically

Example scenario:
- Cache worker at version 500,000
- File processor batch_start_version at 100,000 (lagging due to slow uploads)
- Versions 100,000-199,999 already evicted
- File processor attempts fetch → crash

## Recommendation

Add cache window validation before fetching:

```rust
// In processor.rs, around line 133
let cache_retention_window = cache_worker_latest.saturating_sub(CACHE_SIZE_EVICTION_LOWER_BOUND);

if batch_start_version < cache_retention_window {
    // Data is evicted - fetch from file store instead or handle gracefully
    tracing::error!(
        batch_start_version = batch_start_version,
        cache_worker_latest = cache_worker_latest,
        cache_retention_window = cache_retention_window,
        "Batch start version is outside cache retention window. Data may be lost."
    );
    // Option 1: Fetch from file store if available
    // Option 2: Panic with clear error for manual recovery
    // Option 3: Skip to next available version in cache
}

while start_version >= cache_retention_window 
    && start_version + (FILE_ENTRY_TRANSACTION_COUNT) < cache_worker_latest {
    // ... existing batch creation logic
}
```

Alternatively, use the data service pattern with cache coverage checking: [8](#0-7) 

This returns `CacheEvicted` status allowing graceful fallback to file store.

## Proof of Concept

```rust
// Reproduction steps (conceptual - would need full test harness):

// 1. Initialize file processor with batch_start_version = 100,000
// 2. Advance cache worker to version 500,000 (evicts everything < 200,000)
// 3. File processor reads latest_version = 500,000
// 4. File processor attempts to fetch 100,000-100,999
// 5. get_transactions fails: ensure! check fails (incomplete data)
// 6. Task panics at .unwrap()
// 7. File processor crashes with: "Error processing transaction batches: Failed to get all transactions from cache."

// The race window can be artificially widened by:
// - Adding sleep between get_latest_version and get_transactions
// - Rapidly advancing cache worker during this window
// - Setting batch_start_version outside retention window
```

**Notes**

This vulnerability is specific to the indexer-grpc file processor component. While it doesn't directly affect blockchain consensus or validator operations, it impacts the availability and reliability of the Aptos indexer infrastructure, which is critical for dApp developers and users querying historical blockchain data. The acknowledged non-atomic design requires proper bounds checking that is currently missing.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L22-23)
```rust
// reading latest version and actual data not atomic(two operations).
const CACHE_SIZE_EVICTION_LOWER_BOUND: u64 = 300_000_u64;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L145-147)
```rust
    pub async fn get_latest_version(&mut self) -> anyhow::Result<Option<u64>> {
        self.get_config_by_key(CACHE_KEY_LATEST_VERSION).await
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L193-219)
```rust
    pub async fn check_cache_coverage_status(
        &mut self,
        requested_version: u64,
    ) -> anyhow::Result<CacheCoverageStatus> {
        let latest_version: u64 = match self
            .conn
            .get::<&str, String>(CACHE_KEY_LATEST_VERSION)
            .await
        {
            Ok(v) => v
                .parse::<u64>()
                .expect("Redis latest_version is not a number."),
            Err(err) => return Err(err.into()),
        };

        if requested_version >= latest_version {
            Ok(CacheCoverageStatus::DataNotReady)
        } else if requested_version + CACHE_SIZE_ESTIMATION < latest_version {
            Ok(CacheCoverageStatus::CacheEvicted)
        } else {
            // TODO: rewrite this logic to surface this max fetch size better
            Ok(CacheCoverageStatus::CacheHit(std::cmp::min(
                latest_version - requested_version,
                FILE_ENTRY_TRANSACTION_COUNT,
            )))
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L282-289)
```rust
            if version >= CACHE_SIZE_EVICTION_LOWER_BOUND {
                let key = CacheEntry::build_key(
                    version - CACHE_SIZE_EVICTION_LOWER_BOUND,
                    self.storage_format,
                )
                .to_string();
                redis_pipeline.cmd("DEL").arg(key).ignore();
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L389-392)
```rust
        ensure!(
            transactions.len() == transaction_count as usize,
            "Failed to get all transactions from cache."
        );
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L128-139)
```rust
            let cache_worker_latest = self.cache_operator.get_latest_version().await?.unwrap();

            // batches tracks the start version of the batches to fetch. 1000 at the time
            let mut batches = vec![];
            let mut start_version = batch_start_version;
            while start_version + (FILE_ENTRY_TRANSACTION_COUNT) < cache_worker_latest {
                batches.push(start_version);
                start_version += FILE_ENTRY_TRANSACTION_COUNT;
                if batches.len() >= MAX_CONCURRENT_BATCHES {
                    break;
                }
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L162-165)
```rust
                    let transactions = cache_operator_clone
                        .get_transactions(start_version, FILE_ENTRY_TRANSACTION_COUNT)
                        .await
                        .unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/processor.rs (L243-243)
```rust
                    Err(err) => panic!("Error processing transaction batches: {:?}", err),
```
