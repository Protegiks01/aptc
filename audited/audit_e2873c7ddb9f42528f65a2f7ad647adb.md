# Audit Report

## Title
Fullnode gRPC Stream Lacks Transaction Version Sequence Validation Enabling Indexer Database Corruption

## Summary
The fullnode gRPC stream consumer (`cache-worker`) fails to validate that individual transactions within DATA chunks contain sequential version numbers matching the expected range. A malicious fullnode can send transaction objects with manipulated version fields, causing these transactions to be stored at incorrect version keys in Redis, corrupting indexer databases and breaking state reconstruction.

## Finding Description

The security vulnerability exists in the fullnode data streaming protocol used by indexers to sync blockchain state. The system has three critical components:

**Server Side (Fullnode):** Sends transaction data via gRPC stream with DATA chunks and BATCH_END status messages. [1](#0-0) 

**Client Side (Cache Worker):** Receives and validates transaction batches. [2](#0-1) 

The client performs count-based validation: [3](#0-2) 

**Cache Storage:** Stores transactions in Redis using their version field as the key. [4](#0-3) 

**The Vulnerability:**

The cache worker validates only that the COUNT of transactions matches between DATA chunks and BATCH_END status (checking `current_version == start_version + num_of_transactions`). It does NOT validate that each transaction's version field is sequential and matches the expected position in the batch.

A malicious fullnode can exploit this by sending a DATA chunk where the transaction objects' version fields don't match the expected sequential range. For example:
- Server claims to send batch 100-102 (3 transactions)
- Server sends DATA chunk with 3 transaction objects, but with version fields: 500, 501, 502
- Cache worker receives 3 transactions, increments `current_version` by 3
- Transactions get stored in Redis at keys for versions 500, 501, 502 (not 100-102!)
- BATCH_END validation passes: count matches (3 == 3)
- Result: Gap at versions 100-102, corrupted data at 500-502

This violates the **State Consistency** invariant: downstream indexers reading from the cache will encounter gaps, receive wrong transaction data at specific versions, and fail to reconstruct blockchain state correctly.

**Comparison with Protected Components:**

Other indexer components DO validate sequential ordering: [5](#0-4) [6](#0-5) 

The cache-worker lacks these critical validations.

## Impact Explanation

**Severity: High to Critical** ($50,000 - $1,000,000 range)

**Impact:**
1. **Indexer Database Corruption:** Downstream indexers reading from corrupted cache receive incorrect transaction data, causing database inconsistencies
2. **State Reconstruction Failure:** Applications attempting to reconstruct blockchain state from the indexer will produce incorrect results
3. **Silent Data Corruption:** The attack succeeds without triggering errors, making detection difficult
4. **Permanent Damage:** Once wrong data enters the cache and propagates to downstream databases, it requires manual intervention and full re-sync to recover

This qualifies as **Critical** if it leads to permanent state inconsistency requiring intervention, or **High** for significant protocol violations affecting indexer reliability.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attack Requirements:**
- Attacker must control or compromise a fullnode that indexers connect to
- No validator-level access required (unprivileged attack)
- Simple to execute: modify server code or intercept/replay network traffic

**Feasibility:**
- Indexers typically connect to public fullnode endpoints
- An attacker can deploy malicious fullnodes
- If indexers don't verify fullnode authenticity, they may connect to malicious nodes
- The attack is deterministic: once malicious data is sent, corruption occurs with 100% success

**Detection Difficulty:**
- Count-based validation passes, hiding the attack
- Corruption may not be noticed until downstream applications fail
- No automatic alerts trigger

## Recommendation

Add explicit validation that each transaction's version field matches its expected sequential position:

```rust
// In cache_worker.rs, before calling update_cache_transactions
async fn validate_transaction_sequence(
    transactions: &[Transaction],
    expected_start_version: u64,
) -> Result<()> {
    for (idx, txn) in transactions.iter().enumerate() {
        let expected_version = expected_start_version + idx as u64;
        if txn.version != expected_version {
            bail!(
                "Transaction version mismatch: expected {}, got {} at position {}",
                expected_version,
                txn.version,
                idx
            );
        }
    }
    
    // Validate no gaps using windows
    if transactions.len() > 1 && transactions.windows(2).any(|w| w[0].version + 1 != w[1].version) {
        bail!("Gap detected in transaction versions");
    }
    
    Ok(())
}

// In process_transactions_from_node_response, before line 246:
validate_transaction_sequence(&data.transactions, current_version).await?;
```

Additionally, validate DATA chunk versions against BATCH_END expectations to ensure they fall within the claimed range.

## Proof of Concept

```rust
// Simulated attack demonstrating the vulnerability
#[tokio::test]
async fn test_version_corruption_attack() {
    use aptos_protos::transaction::v1::Transaction;
    
    // Malicious fullnode sends 3 transactions
    // Client expects versions 100-102
    // But server sends transactions with versions 500-502
    
    let mut malicious_transactions = vec![];
    for v in 500..503 {
        let mut txn = Transaction::default();
        txn.version = v;
        malicious_transactions.push(txn);
    }
    
    // Simulate cache worker processing
    let expected_start = 100u64;
    let num_transactions = malicious_transactions.len() as u64;
    let mut current_version = expected_start;
    
    // Cache worker increments by COUNT (no version validation)
    current_version += num_transactions; // Now 103
    
    // BATCH_END validation
    let batch_end_start = 100u64;
    let batch_end_count = 3u64;
    
    // This check PASSES (count-based only)
    assert_eq!(current_version, batch_end_start + batch_end_count);
    
    // But transactions are stored at WRONG versions in Redis:
    // Expected: keys 100, 101, 102
    // Actual: keys 500, 501, 502
    for txn in &malicious_transactions {
        println!("Transaction stored at version key: {}", txn.version);
        // Output: 500, 501, 502 (WRONG!)
    }
    
    // Gap at versions 100-102 causes indexer failures
    // Corruption at versions 500-502 causes incorrect state
}
```

## Notes

This vulnerability is particularly dangerous because:
1. It bypasses the existing count-based validation which appears secure but is insufficient
2. The corruption is silent - no errors are raised
3. It affects all indexers consuming from the compromised cache
4. Recovery requires full re-synchronization from trusted sources

The fix should be implemented in both the cache-worker and any other consumers of the fullnode gRPC stream to prevent this class of attack across the indexer infrastructure.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L160-168)
```rust
                // send end batch message (each batch) upon success of the entire batch
                // client can use the start and end version to ensure that there are no gaps
                // end loop if this message fails to send because otherwise the client can't validate
                let batch_end_status = get_status(
                    StatusType::BatchEnd,
                    coordinator.current_version,
                    Some(max_version),
                    ledger_chain_id,
                );
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L194-204)
```rust
                StatusType::BatchEnd => {
                    let start_version = status.start_version;
                    let num_of_transactions = status
                        .end_version
                        .expect("TransactionsFromNodeResponse status end_version is None")
                        - start_version
                        + 1;
                    Ok(GrpcDataStatus::BatchEnd {
                        start_version,
                        num_of_transactions,
                    })
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L433-442)
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
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L264-278)
```rust
        for transaction in transactions {
            let version = transaction.version;
            let cache_key = CacheEntry::build_key(version, self.storage_format).to_string();
            let timestamp_in_seconds = transaction.timestamp.map_or(0, |t| t.seconds as u64);
            let cache_entry: CacheEntry =
                CacheEntry::from_transaction(transaction, self.storage_format);
            let bytes = cache_entry.into_inner();
            size_in_bytes += bytes.len();
            redis_pipeline
                .cmd("SET")
                .arg(cache_key)
                .arg(bytes)
                .arg("EX")
                .arg(get_ttl_in_seconds(timestamp_in_seconds))
                .ignore();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/table_info_service.rs (L226-230)
```rust
        // Verify that the transactions are sorted with no gap.
        if result.windows(2).any(|w| w[0].version + 1 != w[1].version) {
            // get all the versions

            let versions: Vec<u64> = result.iter().map(|txn| txn.version).collect();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L636-658)
```rust
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
```
