# Audit Report

## Title
Missing Transaction Hash Verification in Fullnode gRPC Streaming API

## Summary
The fullnode gRPC streaming API (`GetTransactionsFromNode`) includes transaction hashes in the protobuf messages but does not verify these hashes against the actual transaction content on the client side. This allows a malicious fullnode to send tampered transaction data with unmodified hashes, which clients will accept and store without detecting the tampering.

## Finding Description

The fullnode gRPC service streams transactions via `GetTransactionsFromNode` RPC defined in the protobuf schema. Each transaction includes a hash in its `TransactionInfo` field: [1](#0-0) 

When the fullnode streams transactions, it converts them to protobuf format and includes the transaction hash: [2](#0-1) 

However, when clients (such as the cache worker) receive these transactions, they store them directly without verifying that the hash matches the transaction content: [3](#0-2) [4](#0-3) 

The vulnerability exists because:

1. **Hash is included but not verified**: The `TransactionInfo.hash` field contains the transaction hash, but clients never recompute this hash from the transaction data to verify integrity.

2. **Contrast with proven verification**: The codebase has proper hash verification for `TransactionListWithProof` structures: [5](#0-4) 

But the gRPC streaming API uses bare `Transaction` protobufs without proofs.

3. **Attack scenario**: A malicious fullnode can:
   - Modify transaction fields (events, write_set, gas_used, vm_status, etc.)
   - Keep the original `TransactionInfo.hash` value unchanged
   - Stream this tampered data to clients
   - Clients store and serve the incorrect data without detection

## Impact Explanation

**High Severity** - This vulnerability causes state inconsistencies requiring intervention:

- **Data Integrity Breach**: Clients receive and cache tampered transaction data that appears valid
- **Downstream Impact**: Indexers, explorers, and applications relying on cached data serve incorrect information to users
- **Trust Model Violation**: The system assumes fullnodes provide authentic data, but provides no cryptographic verification
- **Protocol Violation**: Breaks the fundamental guarantee that transaction hashes are cryptographic commitments to transaction content

While this doesn't directly affect consensus (validators use different mechanisms), it impacts the broader ecosystem's ability to reliably query historical transaction data.

## Likelihood Explanation

**Medium-High Likelihood**:

- **Attack Complexity**: Low - malicious fullnode only needs to modify protobuf messages before streaming
- **Attacker Requirements**: Control of a fullnode that clients connect to (possible for public fullnodes or through MITM attacks)
- **Detection Difficulty**: High - without verification, tampered data appears identical to authentic data
- **Current Deployment**: The cache worker and other indexer components actively use this unverified streaming API

## Recommendation

Implement transaction hash verification on the client side when receiving transactions from the gRPC stream:

```rust
// In cache_operator.rs update_cache_transactions function
pub async fn update_cache_transactions(
    &mut self,
    transactions: Vec<Transaction>,
) -> anyhow::Result<()> {
    // Add hash verification before storing
    for transaction in &transactions {
        if let Some(info) = &transaction.info {
            // Recompute hash from transaction data and verify
            let computed_hash = compute_transaction_hash_from_proto(transaction)?;
            let provided_hash = HashValue::from_slice(&info.hash)
                .context("Invalid hash in transaction info")?;
            
            ensure!(
                computed_hash == provided_hash,
                "Transaction hash mismatch: computed {:?}, provided {:?}",
                computed_hash,
                provided_hash
            );
        }
    }
    
    // ... rest of existing code
}

fn compute_transaction_hash_from_proto(txn: &Transaction) -> Result<HashValue> {
    // Convert protobuf Transaction back to native type and compute hash
    // Implementation needed to reconstruct the transaction for hashing
    // This requires converting proto format back to SignedTransaction/etc
    unimplemented!("Requires proto->native conversion implementation")
}
```

**Alternative solution**: Use `TransactionListWithProof` for the gRPC streaming API instead of bare `Transaction` objects, which provides cryptographic proof of authenticity.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[cfg(test)]
mod test_missing_hash_verification {
    use super::*;
    
    #[tokio::test]
    async fn test_tampered_transaction_accepted() {
        // Create a legitimate transaction
        let mut transaction = create_test_transaction();
        let original_hash = transaction.info.as_ref().unwrap().hash.clone();
        
        // Tamper with transaction data
        transaction.info.as_mut().unwrap().gas_used = 999999;
        transaction.info.as_mut().unwrap().vm_status = "TAMPERED".to_string();
        // Keep original hash unchanged
        transaction.info.as_mut().unwrap().hash = original_hash;
        
        // Current implementation accepts tampered transaction
        let mut cache_op = create_test_cache_operator().await;
        let result = cache_op.update_cache_transactions(vec![transaction]).await;
        
        // This should fail but currently succeeds
        assert!(result.is_ok(), "Tampered transaction was accepted without verification");
        
        // The tampered data is now in cache and will be served to users
    }
}
```

**Notes**:
- The vulnerability affects the trust boundary between fullnodes and clients
- Proper verification requires either cryptographic proofs (like `TransactionListWithProof`) or hash recomputation
- The issue is particularly critical for public indexers and data services that many applications depend on

### Citations

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

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/convert.rs (L570-586)
```rust
pub fn convert_transaction_info(
    transaction_info: &TransactionInfo,
) -> transaction::TransactionInfo {
    transaction::TransactionInfo {
        hash: transaction_info.hash.0.to_vec(),
        state_checkpoint_hash: transaction_info
            .state_checkpoint_hash
            .map(|hash| hash.0.to_vec()),
        state_change_hash: transaction_info.state_change_hash.0.to_vec(),
        event_root_hash: transaction_info.event_root_hash.0.to_vec(),
        gas_used: transaction_info.gas_used.0,
        success: transaction_info.success,
        vm_status: transaction_info.vm_status.to_string(),
        accumulator_root_hash: transaction_info.accumulator_root_hash.0.to_vec(),
        changes: convert_write_set_changes(&transaction_info.changes),
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L209-282)
```rust
        Response::Data(data) => {
            let transaction_len = data.transactions.len();
            let data_download_duration_in_secs = download_start_time.elapsed().as_secs_f64();
            let mut cache_operator_clone = cache_operator.clone();
            let task: JoinHandle<anyhow::Result<()>> = tokio::spawn({
                let first_transaction = data
                    .transactions
                    .first()
                    .context("There were unexpectedly no transactions in the response")?;
                let first_transaction_version = first_transaction.version;
                let last_transaction = data
                    .transactions
                    .last()
                    .context("There were unexpectedly no transactions in the response")?;
                let last_transaction_version = last_transaction.version;
                let start_version = first_transaction.version;
                let first_transaction_pb_timestamp = first_transaction.timestamp;
                let last_transaction_pb_timestamp = last_transaction.timestamp;

                log_grpc_step(
                    SERVICE_TYPE,
                    IndexerGrpcStep::CacheWorkerReceivedTxns,
                    Some(start_version as i64),
                    Some(last_transaction_version as i64),
                    first_transaction_pb_timestamp.as_ref(),
                    last_transaction_pb_timestamp.as_ref(),
                    Some(data_download_duration_in_secs),
                    Some(size_in_bytes),
                    Some((last_transaction_version + 1 - first_transaction_version) as i64),
                    None,
                );

                let cache_update_start_time = std::time::Instant::now();

                async move {
                    // Push to cache.
                    match cache_operator_clone
                        .update_cache_transactions(data.transactions)
                        .await
                    {
                        Ok(_) => {
                            log_grpc_step(
                                SERVICE_TYPE,
                                IndexerGrpcStep::CacheWorkerTxnsProcessed,
                                Some(first_transaction_version as i64),
                                Some(last_transaction_version as i64),
                                first_transaction_pb_timestamp.as_ref(),
                                last_transaction_pb_timestamp.as_ref(),
                                Some(cache_update_start_time.elapsed().as_secs_f64()),
                                Some(size_in_bytes),
                                Some(
                                    (last_transaction_version + 1 - first_transaction_version)
                                        as i64,
                                ),
                                None,
                            );
                            Ok(())
                        },
                        Err(e) => {
                            ERROR_COUNT
                                .with_label_values(&["failed_to_update_cache_version"])
                                .inc();
                            bail!("Update cache with version failed: {}", e);
                        },
                    }
                }
            });

            Ok(GrpcDataStatus::ChunkDataOk {
                num_of_transactions: transaction_len as u64,
                task,
            })
        },
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/cache_operator.rs (L252-313)
```rust
    pub async fn update_cache_transactions(
        &mut self,
        transactions: Vec<Transaction>,
    ) -> anyhow::Result<()> {
        let start_version = transactions.first().unwrap().version;
        let end_version = transactions.last().unwrap().version;
        let num_transactions = transactions.len();
        let start_txn_timestamp = transactions.first().unwrap().timestamp;
        let end_txn_timestamp = transactions.last().unwrap().timestamp;
        let mut size_in_bytes = 0;
        let mut redis_pipeline = redis::pipe();
        let start_time = std::time::Instant::now();
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
            // Actively evict the expired cache. This is to avoid using Redis
            // eviction policy, which is probabilistic-based and may evict the
            // cache that is still needed.
            if version >= CACHE_SIZE_EVICTION_LOWER_BOUND {
                let key = CacheEntry::build_key(
                    version - CACHE_SIZE_EVICTION_LOWER_BOUND,
                    self.storage_format,
                )
                .to_string();
                redis_pipeline.cmd("DEL").arg(key).ignore();
            }
        }
        // Note: this method is and should be only used by `cache_worker`.
        let service_type = "cache_worker";
        log_grpc_step(
            service_type,
            IndexerGrpcStep::CacheWorkerTxnEncoded,
            Some(start_version as i64),
            Some(end_version as i64),
            start_txn_timestamp.as_ref(),
            end_txn_timestamp.as_ref(),
            Some(start_time.elapsed().as_secs_f64()),
            Some(size_in_bytes),
            Some(num_transactions as i64),
            None,
        );

        let redis_result: RedisResult<()> =
            redis_pipeline.query_async::<_, _>(&mut self.conn).await;

        match redis_result {
            Ok(_) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
```

**File:** types/src/transaction/mod.rs (L2606-2614)
```rust
            // Verify the transaction hashes match those of the transaction infos
            let txn_hash = txn.hash();
            ensure!(
                txn_hash == txn_info.transaction_hash(),
                "The transaction hash does not match the hash in transaction info. \
                     Transaction hash: {:x}. Transaction hash in txn_info: {:x}.",
                txn_hash,
                txn_info.transaction_hash(),
            );
```
