# Audit Report

## Title
Missing Transaction Version Validation in Indexer Cache Manager Enables Replay Attacks

## Summary
The `DataManager` in `indexer-grpc-manager` lacks validation when inserting transactions received from fullnodes into the cache. The `put_transactions` method blindly appends transactions without verifying that their version numbers match the expected sequence, allowing a compromised or buggy fullnode to inject old, duplicate, or out-of-order transactions into the cache that will be served to downstream indexer clients.

## Finding Description

The indexer-grpc-manager's `DataManager` maintains an in-memory cache of transactions to serve indexer clients. When fetching new transactions from fullnodes, it calculates the next expected version and requests transactions starting from that version: [1](#0-0) 

However, when the fullnode responds with transaction data, these transactions are inserted into the cache without any validation: [2](#0-1) 

The `put_transactions` method performs no verification: [3](#0-2) 

Each `Transaction` has a `version` field that uniquely identifies it: [4](#0-3) 

**Attack scenario**: A compromised fullnode could:
1. Return old transactions (with lower version numbers) when requested for new versions
2. Return duplicate transactions that were already processed
3. Return out-of-order transactions
4. Return transactions with incorrect version numbers

These malicious transactions would be inserted into the cache and served to all downstream indexer clients, causing them to:
- Process duplicate transactions multiple times
- Compute incorrect state
- Generate incorrect indexed data

While the data service has validation on the read side (`ensure_sequential_transactions`), this validation occurs AFTER the bad data is already in the cache: [5](#0-4) 

## Impact Explanation

This issue represents a **Medium to High severity** vulnerability:

**Medium Severity aspects**:
- Causes "State inconsistencies requiring intervention" in the indexer infrastructure
- Corrupts the cache with incorrect transaction data
- Requires manual intervention to clear corrupted cache and restart services

**High Severity aspects**:
- Could cause widespread "API crashes" when clients detect gaps/duplicates via `ensure_sequential_transactions` panics
- Affects ALL downstream indexer clients consuming data from this manager
- Represents a significant protocol violation in the indexer infrastructure data flow
- Could lead to validator node slowdowns if validators rely on indexer data for monitoring

However, this does NOT reach Critical severity because:
- Does not affect blockchain consensus itself
- Does not cause loss of funds on-chain
- Does not affect validator node consensus operations

## Likelihood Explanation

**Likelihood: Medium**

While this requires a compromised fullnode (trusted infrastructure), the likelihood is medium because:

1. **Defense-in-depth principle**: Even trusted infrastructure should be validated. Bugs in fullnode implementation could accidentally trigger this.

2. **Supply chain attacks**: If a fullnode operator's infrastructure is compromised, the attacker gains ability to corrupt indexer data.

3. **No detection mechanism**: The cache manager provides no alerts or detection when receiving unexpected version numbers, making attacks silent.

4. **Wide impact**: A single compromised fullnode affects ALL indexer clients connected to that manager.

5. **Operational errors**: Configuration mistakes or fullnode software bugs could trigger this accidentally.

## Recommendation

Add version validation in the `put_transactions` method:

```rust
fn put_transactions(&mut self, transactions: Vec<Transaction>) -> Result<()> {
    // Validate that transactions start at expected version
    let expected_version = self.start_version + self.transactions.len() as u64;
    
    if let Some(first_txn) = transactions.first() {
        if first_txn.version != expected_version {
            error!(
                expected_version = expected_version,
                received_version = first_txn.version,
                "Received transactions with unexpected starting version"
            );
            bail!(
                "Version mismatch: expected {}, got {}",
                expected_version,
                first_txn.version
            );
        }
    }
    
    // Validate that transactions are consecutive
    for window in transactions.windows(2) {
        if window[1].version != window[0].version + 1 {
            error!(
                prev_version = window[0].version,
                next_version = window[1].version,
                "Gap detected in transaction versions"
            );
            bail!(
                "Non-consecutive versions: {} followed by {}",
                window[0].version,
                window[1].version
            );
        }
    }
    
    // Original insertion logic
    self.cache_size += transactions
        .iter()
        .map(|transaction| transaction.encoded_len())
        .sum::<usize>();
    self.transactions.extend(transactions);
    CACHE_SIZE.set(self.cache_size as i64);
    CACHE_END_VERSION.set(self.start_version as i64 + self.transactions.len() as i64);
    
    Ok(())
}
```

Additionally, update the caller to handle validation errors: [6](#0-5) 

## Proof of Concept

To reproduce this vulnerability:

1. Set up an indexer-grpc-manager connecting to a fullnode
2. Modify the fullnode to return old transactions (e.g., versions 1000-1999) when requested for versions 2000+
3. Observe that the cache manager accepts and caches these old transactions
4. Query the cache through the data service API
5. Observe clients receiving duplicate/old transaction data

**Test case** (pseudo-code for unit test):

```rust
#[tokio::test]
async fn test_replay_attack_detection() {
    let mut cache = Cache::new(cache_config, 1000);
    
    // Simulate cache at version 2000
    cache.start_version = 2000;
    cache.transactions = create_test_transactions(2000..2100);
    
    // Attacker tries to inject old transactions
    let old_transactions = create_test_transactions(1000..1100);
    
    // This should fail with version validation
    let result = cache.put_transactions(old_transactions);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Version mismatch"));
}
```

## Notes

This vulnerability exists because the code trusts fullnodes implicitly without implementing defense-in-depth validation. While fullnodes are expected to be trustworthy, security best practices dictate validating all external inputs, especially when serving data to many downstream clients.

The validation on the read side (in `ensure_sequential_transactions`) provides some protection but occurs too late—after corrupted data is already in the cache and potentially served to some clients before gaps are detected.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L82-90)
```rust
    fn put_transactions(&mut self, transactions: Vec<Transaction>) {
        self.cache_size += transactions
            .iter()
            .map(|transaction| transaction.encoded_len())
            .sum::<usize>();
        self.transactions.extend(transactions);
        CACHE_SIZE.set(self.cache_size as i64);
        CACHE_END_VERSION.set(self.start_version as i64 + self.transactions.len() as i64);
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L207-210)
```rust
            let request = GetTransactionsFromNodeRequest {
                starting_version: Some(cache.start_version + cache.transactions.len() as u64),
                transactions_count: Some(100000),
            };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L257-279)
```rust
                match response_item {
                    Ok(r) => {
                        if let Some(response) = r.response {
                            match response {
                                Response::Data(data) => {
                                    trace!(
                                        "Putting data into cache, {} transaction(s).",
                                        data.transactions.len()
                                    );
                                    self.cache.write().await.put_transactions(data.transactions);
                                },
                                Response::Status(_) => continue,
                            }
                        } else {
                            warn!("Error when getting transactions from fullnode: no data.");
                            continue 'out;
                        }
                    },
                    Err(e) => {
                        warn!("Error when getting transactions from fullnode: {}", e);
                        continue 'out;
                    },
                }
```

**File:** protos/proto/aptos/transaction/v1/transaction.proto (L40-42)
```text
message Transaction {
  aptos.util.timestamp.Timestamp timestamp = 1;
  uint64 version = 2 [jstype = JS_STRING];
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L592-668)
```rust
fn ensure_sequential_transactions(mut batches: Vec<Vec<Transaction>>) -> Vec<Transaction> {
    // If there's only one, no sorting required
    if batches.len() == 1 {
        return batches.pop().unwrap();
    }

    // Sort by the first version per batch, ascending
    batches.sort_by(|a, b| a.first().unwrap().version.cmp(&b.first().unwrap().version));
    let first_version = batches.first().unwrap().first().unwrap().version;
    let last_version = batches.last().unwrap().last().unwrap().version;
    let mut transactions: Vec<Transaction> = vec![];

    let mut prev_start = None;
    let mut prev_end = None;
    for mut batch in batches {
        let mut start_version = batch.first().unwrap().version;
        let end_version = batch.last().unwrap().version;
        if let Some(prev_start) = prev_start {
            let prev_end = prev_end.unwrap();
            // If this batch is fully contained within the previous batch, skip it
            if prev_start <= start_version && prev_end >= end_version {
                NUM_MULTI_FETCH_OVERLAPPED_VERSIONS
                    .with_label_values(&[SERVICE_TYPE, "full"])
                    .inc_by(end_version - start_version);
                continue;
            }
            // If this batch overlaps with the previous batch, combine them
            if prev_end >= start_version {
                NUM_MULTI_FETCH_OVERLAPPED_VERSIONS
                    .with_label_values(&[SERVICE_TYPE, "partial"])
                    .inc_by(prev_end - start_version + 1);
                tracing::debug!(
                    batch_first_version = first_version,
                    batch_last_version = last_version,
                    start_version = start_version,
                    end_version = end_version,
                    prev_start = ?prev_start,
                    prev_end = prev_end,
                    "[Filestore] Overlapping version data"
                );
                batch.drain(0..(prev_end - start_version + 1) as usize);
                start_version = batch.first().unwrap().version;
            }

            // Otherwise there is a gap
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
            }
        }

        prev_start = Some(start_version);
        prev_end = Some(end_version);
        transactions.extend(batch);
    }

    transactions
}
```
