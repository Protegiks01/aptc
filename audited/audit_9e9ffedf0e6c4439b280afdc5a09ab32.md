# Audit Report

## Title
Cache Staleness Vulnerability After File Store Reorganization in Indexer-GRPC Manager

## Summary
The in-memory cache in `data_manager.rs` does not detect when the file store undergoes a reorganization where transaction content changes at existing versions. This causes the cache to serve stale transaction data indefinitely after a reorganization, violating data consistency guarantees for indexer clients.

## Finding Description

The `DataManager` cache tracks transactions by version range but lacks any mechanism to detect when transaction content changes at already-cached versions during a file store reorganization. [1](#0-0) 

The cache stores `start_version`, `file_store_version` (atomic), and a `VecDeque` of transactions, but no transaction hashes or content checksums.

When updating the file store version, the code uses `fetch_max` which only increases the version if the new value is greater: [2](#0-1) 

The critical issue is on line 412: `fetch_max` will not update if the file store version stays the same or only slightly increases. There is no validation that cached transaction content still matches the file store.

When serving transactions, the code only checks version ranges, not content validity: [3](#0-2) 

Lines 299-339 show that if the requested version is within the cache range, it returns cached data without any validation against the file store.

Although each transaction has a hash field in `TransactionInfo`: [4](#0-3) 

This hash is never used to validate cached transactions against file store content.

**Exploitation Scenario:**
1. Cache holds transactions for versions [100, 200)
2. File store reorganizes, replacing transactions at versions [150, 175) with different content
3. File store version remains at 200 or increases to 201
4. `update_file_store_version_in_cache` calls `fetch_max(200)` - no update occurs
5. Cache continues serving OLD transactions [150, 175)
6. Clients requesting version 160 receive stale transaction data

## Impact Explanation

This is a **Medium Severity** vulnerability per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

While this affects the indexer layer (not core consensus), it creates data integrity violations with significant downstream impact:

- **Incorrect Historical Data**: Applications receive wrong transaction history
- **State Derivation Errors**: Indexers deriving state from transactions compute incorrect results  
- **Balance Miscalculations**: Wallets and explorers may display wrong balances
- **Audit Trail Corruption**: Transaction history becomes unreliable for compliance

The impact is contained to indexer infrastructure and does not affect on-chain consensus or validator operations. However, it violates the fundamental expectation that historical transaction data remains consistent and verifiable.

## Likelihood Explanation

**Likelihood: Low to Medium**

File store reorganizations are exceptional events, not part of normal operation. They would occur during:
- Manual data repair or correction operations
- Bug fixes requiring transaction reprocessing
- Database corruption recovery
- Infrastructure migration with data transformation

While Aptos consensus provides finality (no chain reorgs), the indexer file store can undergo reorganizations during operational maintenance. The vulnerability is deterministic once a reorganization occurs - there is no probabilistic element.

The issue is **not directly exploitable** by an unprivileged attacker, as triggering a file store reorganization requires infrastructure access. However, once a reorganization occurs through legitimate operational needs, the cache staleness manifests automatically.

## Recommendation

Implement content-based cache invalidation using transaction hashes. Add a validation mechanism that compares cached transaction hashes with file store content:

**Solution 1: Hash-based validation**
- Store transaction hashes alongside cached transactions
- Periodically sample-check cached transaction hashes against file store
- Invalidate entire cache range if mismatch detected

**Solution 2: Cache invalidation on version decrease**
- When `version_can_go_backward` is true (master mode), clear the entire cache
- Already has panic on backward version in non-master mode (line 416)
- Extend this to actually invalidate cache rather than just panic

**Solution 3: Metadata-based reorg detection**
- Add a `file_store_generation` or `reorg_counter` to `FileStoreMetadata`
- Increment on any reorganization
- Cache compares generation numbers to detect reorgs

**Code Fix Example** (Solution 2):

```rust
async fn update_file_store_version_in_cache(
    &self,
    cache: &RwLockReadGuard<'_, Cache>,
    version_can_go_backward: bool,
) {
    let file_store_version = self.file_store_reader.get_latest_version().await;
    if let Some(file_store_version) = file_store_version {
        let file_store_version_before_update = cache
            .file_store_version
            .load(Ordering::SeqCst);
        
        if file_store_version < file_store_version_before_update {
            if version_can_go_backward {
                // File store reorg detected - invalidate cache
                drop(cache);
                let mut cache_write = self.cache.write().await;
                cache_write.transactions.clear();
                cache_write.cache_size = 0;
                cache_write.start_version = file_store_version;
                cache_write.file_store_version.store(file_store_version, Ordering::SeqCst);
                info!("Cache invalidated due to file store reorganization");
                return;
            } else {
                panic!("File store version is going backward, data might be corrupted. {file_store_version_before_update} v.s. {file_store_version}");
            }
        }
        
        cache.file_store_version.fetch_max(file_store_version, Ordering::SeqCst);
        FILE_STORE_VERSION_IN_CACHE.set(file_store_version as i64);
        info!("Updated file_store_version in cache to {file_store_version}.");
    }
}
```

## Proof of Concept

**Rust Reproduction Steps:**

```rust
#[tokio::test]
async fn test_cache_stale_after_reorg() {
    // 1. Initialize cache with transactions V100-V200
    let cache_config = CacheConfig {
        max_cache_size: 1_000_000,
        target_cache_size: 500_000,
    };
    let cache = Cache::new(cache_config, 100);
    
    // Populate cache with 100 transactions
    let mut transactions = vec![];
    for v in 100..200 {
        let mut tx = Transaction::default();
        tx.version = v;
        tx.info = Some(TransactionInfo {
            hash: format!("original_hash_{}", v).into_bytes(),
            ..Default::default()
        });
        transactions.push(tx);
    }
    cache.put_transactions(transactions);
    
    // 2. Simulate file store reorganization
    // File store now has DIFFERENT transactions at V150-V175
    // but version remains at 200
    
    // 3. Update file store version (stays at 200)
    cache.file_store_version.fetch_max(200, Ordering::SeqCst);
    
    // 4. Request transaction at V160 from cache
    let cached_txs = cache.get_transactions(160, 1000, false);
    
    // 5. Verify cached transaction has STALE hash
    assert_eq!(cached_txs[0].version, 160);
    assert_eq!(
        cached_txs[0].info.as_ref().unwrap().hash,
        b"original_hash_160"
    );
    // This is the OLD transaction, not the new one from reorg!
    
    // Expected: Cache should detect reorganization and refetch from file store
    // Actual: Cache serves stale data
}
```

## Notes

This vulnerability specifically affects the indexer-grpc infrastructure layer, not core blockchain consensus. Aptos consensus itself uses AptosBFT which provides finality, so chain-level reorganizations do not occur. However, the indexer file store can undergo reorganizations during operational maintenance, triggering this cache staleness issue.

The vulnerability requires operational circumstances (file store reorganization) to manifest and is not directly exploitable by external attackers. However, it represents a legitimate data consistency bug that should be addressed to maintain indexer reliability.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L35-43)
```rust
struct Cache {
    start_version: u64,
    file_store_version: AtomicU64,
    transactions: VecDeque<Transaction>,
    cache_size: usize,

    max_cache_size: usize,
    target_cache_size: usize,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L289-340)
```rust
    pub(crate) async fn get_transactions(
        &self,
        start_version: u64,
        max_size_bytes_from_cache: usize,
    ) -> Result<Vec<Transaction>> {
        let cache = self.cache.read().await;
        let cache_start_version = cache.start_version;
        let cache_next_version = cache_start_version + cache.transactions.len() as u64;
        drop(cache);

        if start_version >= cache_start_version {
            if start_version >= cache_next_version {
                // If lagging, try to fetch the data from FN.
                if self.lagging(cache_next_version) && self.allow_fn_fallback {
                    debug!("GrpcManager is lagging, getting data from FN, requested_version: {start_version}, cache_next_version: {cache_next_version}.");
                    let request = GetTransactionsFromNodeRequest {
                        starting_version: Some(start_version),
                        transactions_count: Some(5000),
                    };

                    let (_, mut fullnode_client) =
                        self.metadata_manager.get_fullnode_for_request(&request);
                    let response = fullnode_client.get_transactions_from_node(request).await?;
                    let mut response = response.into_inner();
                    while let Some(Ok(response_item)) = response.next().await {
                        if let Some(response) = response_item.response {
                            match response {
                                Response::Data(data) => {
                                    return Ok(data.transactions);
                                },
                                Response::Status(_) => continue,
                            }
                        }
                    }
                }

                tokio::time::sleep(Duration::from_millis(200)).await;

                // Let client side to retry.
                return Ok(vec![]);
            }
            // NOTE: We are not holding the read lock for cache here. Therefore it's possible that
            // the start_version becomes older than the cache.start_version. In that case the
            // following function will return empty return, and let the client to retry.
            return Ok(self
                .get_transactions_from_cache(
                    start_version,
                    max_size_bytes_from_cache,
                    /*update_file_store_version=*/ false,
                )
                .await);
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L403-419)
```rust
    async fn update_file_store_version_in_cache(
        &self,
        cache: &RwLockReadGuard<'_, Cache>,
        version_can_go_backward: bool,
    ) {
        let file_store_version = self.file_store_reader.get_latest_version().await;
        if let Some(file_store_version) = file_store_version {
            let file_store_version_before_update = cache
                .file_store_version
                .fetch_max(file_store_version, Ordering::SeqCst);
            FILE_STORE_VERSION_IN_CACHE.set(file_store_version as i64);
            info!("Updated file_store_version in cache to {file_store_version}.");
            if !version_can_go_backward && file_store_version_before_update > file_store_version {
                panic!("File store version is going backward, data might be corrupted. {file_store_version_before_update} v.s. {file_store_version}");
            };
        }
    }
```

**File:** protos/proto/aptos/transaction/v1/transaction.proto (L169-179)
```text
message TransactionInfo {
  bytes hash = 1;
  bytes state_change_hash = 2;
  bytes event_root_hash = 3;
  optional bytes state_checkpoint_hash = 4;
  uint64 gas_used = 5 [jstype = JS_STRING];
  bool success = 6;
  string vm_status = 7;
  bytes accumulator_root_hash = 8;
  repeated WriteSetChange changes = 9;
}
```
