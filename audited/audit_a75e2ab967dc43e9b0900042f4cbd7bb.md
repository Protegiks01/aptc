# Audit Report

## Title
Cache Poisoning via Missing Transaction Version Validation in Indexer-GRPC Data Manager

## Summary
The `Cache::put_transactions()` function in the indexer-grpc-manager completely lacks validation of transaction versions, ordering, and continuity. A compromised or malicious fullnode can insert duplicate, out-of-order, or non-continuous transactions into the cache, breaking the critical assumption that the cache maintains continuous version ranges and causing clients to receive incorrect transaction data.

## Finding Description

The vulnerability exists in the `Cache::put_transactions()` function which blindly extends the cache deque with transactions received from fullnodes without any validation: [1](#0-0) 

This function makes NO checks to verify:
1. Transaction versions start at the expected `cache.start_version + cache.transactions.len()`
2. Transactions are in sequential order without gaps
3. No duplicate transactions are present
4. Transaction versions are continuous

The data manager's main loop receives transactions from fullnodes and directly inserts them without validation: [2](#0-1) 

Critically, the BatchEnd status messages that would enable validation are completely ignored (line 268: `Response::Status(_) => continue`), unlike the cache-worker implementation which properly validates batch boundaries: [3](#0-2) 

The `Cache::get_transactions()` function assumes transactions are stored sequentially by version, using arithmetic to locate transactions: [4](#0-3) 

This skip-based indexing assumes `cache.transactions[i]` contains version `cache.start_version + i`. When this assumption is violated due to out-of-order or duplicate transactions, clients receive incorrect transaction data.

**Attack Path:**
1. Attacker compromises a configured fullnode or performs MITM attack on gRPC connection
2. Data manager requests transactions starting at version X from the compromised fullnode
3. Malicious fullnode sends Response::Data frames with:
   - Transactions with incorrect version numbers (e.g., version Y ≠ X)
   - Duplicate transactions 
   - Out-of-order transactions
   - Gaps in version sequence
4. These transactions are blindly appended to the cache via `put_transactions()`
5. Cache end version metric is updated incorrectly based on deque length, not actual versions
6. When clients request specific versions, the skip arithmetic returns wrong transactions
7. Clients receive incorrect transaction data (wrong balances, events, state changes)

## Impact Explanation

**Severity: HIGH** - This qualifies as "Significant protocol violations" per the Aptos bug bounty criteria.

The indexer-grpc-manager is critical infrastructure serving transaction data to:
- Wallets displaying user balances and transaction history
- Block explorers providing public blockchain data
- Analytics platforms and indexing services
- Developer tools and APIs

Cache poisoning impacts:
1. **Data Integrity**: Clients receive incorrect transaction data, seeing wrong balances, events, and state transitions
2. **Service Reliability**: No detection or recovery mechanism exists once cache is poisoned
3. **Cascading Failures**: Downstream services consuming this data propagate incorrect information
4. **API Correctness**: The `get_transactions` API serves corrupted data

While this does not directly affect blockchain consensus or validator operations, it represents a significant protocol violation in the indexing layer that could undermine trust in the entire ecosystem and cause real harm to users relying on this data.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

Exploitation requires:
1. **Fullnode compromise**: Attacker must compromise one of the configured fullnodes
   - Fullnodes are semi-trusted infrastructure but can be compromised via software vulnerabilities, credential theft, or insider threat
   - Once compromised, exploitation is trivial as there's zero validation
   
2. **Alternative: MITM attack**: If gRPC connections lack proper authentication/encryption
   - Less likely but possible depending on deployment configuration

The attack is highly likely to succeed once initial access is gained because:
- No validation whatsoever exists in `put_transactions()`
- No detection mechanism to identify poisoned cache
- No recovery mechanism to fix corrupted state
- The inconsistency between cache-worker (which validates) and data-manager (which doesn't) suggests this is an oversight rather than intentional design

## Recommendation

Implement transaction version validation in `put_transactions()` similar to the cache-worker pattern:

```rust
fn put_transactions(&mut self, transactions: Vec<Transaction>) -> Result<()> {
    if transactions.is_empty() {
        return Ok(());
    }
    
    // Validate first transaction version matches expected next version
    let expected_version = self.start_version + self.transactions.len() as u64;
    let first_version = transactions.first().unwrap().version;
    
    ensure!(
        first_version == expected_version,
        "Transaction version mismatch: expected {}, got {}",
        expected_version,
        first_version
    );
    
    // Validate all transactions are sequential with no gaps or duplicates
    for i in 1..transactions.len() {
        let prev_version = transactions[i - 1].version;
        let curr_version = transactions[i].version;
        ensure!(
            curr_version == prev_version + 1,
            "Non-sequential transactions: {} followed by {}",
            prev_version,
            curr_version
        );
    }
    
    // Update cache
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

Additionally, process and validate BatchEnd status messages instead of ignoring them: [5](#0-4) 

Track expected version ranges per batch and validate that received transactions match the BatchEnd message's reported range.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_protos::transaction::v1::Transaction;
    
    #[test]
    fn test_cache_poisoning_out_of_order() {
        let mut cache = Cache::new(
            CacheConfig {
                max_cache_size: 1000000,
                target_cache_size: 500000,
            },
            0,
        );
        
        // Create transactions with wrong versions
        let mut txn1 = Transaction::default();
        txn1.version = 5; // Should be 0
        
        let mut txn2 = Transaction::default();
        txn2.version = 3; // Out of order
        
        // This should fail but currently succeeds
        cache.put_transactions(vec![txn1, txn2]);
        
        // Cache now contains version 5 at index 0 and version 3 at index 1
        // When a client requests version 0, they get skip(0) = transaction with version 5
        // This demonstrates the cache poisoning vulnerability
        
        assert_eq!(cache.transactions.len(), 2);
        // Cache believes it has versions [0, 1] but actually has [5, 3]
    }
    
    #[test]
    fn test_cache_poisoning_duplicates() {
        let mut cache = Cache::new(
            CacheConfig {
                max_cache_size: 1000000,
                target_cache_size: 500000,
            },
            0,
        );
        
        let mut txn1 = Transaction::default();
        txn1.version = 0;
        
        // Insert same transaction twice
        cache.put_transactions(vec![txn1.clone()]);
        cache.put_transactions(vec![txn1.clone()]);
        
        // Cache now has duplicate version 0 at indices 0 and 1
        // Metrics show 2 transactions but both are version 0
        assert_eq!(cache.transactions.len(), 2);
    }
}
```

## Notes

This vulnerability is particularly concerning because:

1. **Inconsistent validation**: The cache-worker implementation properly validates transaction continuity, demonstrating that this validation is considered necessary elsewhere in the codebase.

2. **Silent failure**: Cache poisoning occurs without any error indication, and the system continues serving corrupted data.

3. **No recovery path**: Once the cache is poisoned, there's no mechanism to detect or correct the issue without restarting the service.

4. **Scope clarification**: While this affects indexer infrastructure rather than core blockchain consensus, it still represents a significant vulnerability in critical data-serving infrastructure that applications depend on for accurate blockchain state information.

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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L114-118)
```rust
        for transaction in self
            .transactions
            .iter()
            .skip((start_version - self.start_version) as usize)
        {
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

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L433-443)
```rust
                    if current_version != start_version + num_of_transactions {
                        error!(
                            current_version = current_version,
                            actual_current_version = start_version + num_of_transactions,
                            "[Indexer Cache] End signal received with wrong version."
                        );
                        ERROR_COUNT
                            .with_label_values(&["data_end_wrong_version"])
                            .inc();
                        break;
                    }
```
