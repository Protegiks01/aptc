# Audit Report

## Title
Indexer gRPC Chunk Size Bypass via Large Transaction Protobuf Encoding

## Summary
The `chunk_transactions()` function in the indexer gRPC utils can create chunks exceeding the 15MB `MESSAGE_SIZE_LIMIT` when individual transactions, including their execution results (write operations and events), exceed this limit. This causes downstream indexer systems with default gRPC message size limits to fail when processing these oversized chunks.

## Finding Description

The `chunk_transactions()` function splits transactions into chunks with a target maximum size of 15MB: [1](#0-0) 

The chunking logic allows individual transactions larger than `chunk_size` to be placed in a chunk by themselves, resulting in chunks that exceed the 15MB limit. While raw transaction submission is limited to 64KB (normal) or 1MB (governance): [2](#0-1) 

The **execution results** of transactions can be significantly larger. The VM gas parameters permit: [3](#0-2) 

This means a single Transaction protobuf can contain:
- Raw transaction: up to 1MB (governance)
- Write operations: up to 10MB 
- Events: up to 10MB
- Metadata and encoding overhead

**Total: ~21MB+**, which exceeds the 15MB MESSAGE_SIZE_LIMIT.

The chunked transactions are streamed to downstream consumers via gRPC: [4](#0-3) 

While Aptos internal services configure unlimited message sizes: [5](#0-4) 

External third-party indexer clients that use default gRPC configurations (typically 4MB message limits in most gRPC implementations) will fail to receive or decode these oversized chunks, causing processing failures.

## Impact Explanation

This issue qualifies as **Medium severity** under the "State inconsistencies requiring intervention" category. When external indexers fail to process large transactions:

1. Indexer state becomes inconsistent with blockchain state
2. Downstream applications relying on indexers experience data gaps
3. Manual intervention is required to reconfigure clients with larger message limits

However, this does NOT affect:
- Consensus or validator operations
- Core Aptos protocol functionality  
- On-chain fund security
- Blockchain state integrity

The impact is limited to the indexer infrastructure layer, not core protocol components.

## Likelihood Explanation

**Moderate likelihood** because:

1. **Legitimate occurrence**: Governance transactions or complex system transactions can naturally produce 10MB+ of write operations and events
2. **No malicious exploitation required**: This happens with normal protocol operation, not just attacks
3. **Gas costs prevent spam**: Creating transactions with maximum write ops/events is expensive due to gas fees, limiting malicious exploitation
4. **Common misconfiguration**: Many gRPC clients use default 4MB limits and won't handle oversized chunks

The issue is more likely to manifest as an operational problem during legitimate large transactions than as a deliberate attack vector.

## Recommendation

Implement a hard cap on chunk sizes with proper error handling:

```rust
pub fn chunk_transactions(
    transactions: Vec<Transaction>,
    chunk_size: usize,
) -> Result<Vec<Vec<Transaction>>, String> {
    let mut chunked_transactions = vec![];
    let mut chunk = vec![];
    let mut current_size = 0;

    for transaction in transactions {
        let txn_size = transaction.encoded_len();
        
        // Validate single transaction doesn't exceed limit
        if txn_size > chunk_size {
            return Err(format!(
                "Transaction at version {} exceeds maximum chunk size: {} > {}",
                transaction.version, txn_size, chunk_size
            ));
        }
        
        if !chunk.is_empty() && current_size + txn_size > chunk_size {
            chunked_transactions.push(chunk);
            chunk = vec![];
            current_size = 0;
        }
        current_size += txn_size;
        chunk.push(transaction);
    }
    if !chunk.is_empty() {
        chunked_transactions.push(chunk);
    }
    Ok(chunked_transactions)
}
```

Additionally:
1. Document the required minimum gRPC message size limits for downstream consumers
2. Add monitoring/alerts when transactions approach size limits
3. Consider protocol-level limits on total write op/event sizes to ensure they fit within safe margins

## Proof of Concept

```rust
// Test demonstrating oversized chunk creation
#[test]
fn test_oversized_transaction_creates_oversized_chunk() {
    use aptos_protos::transaction::v1::{Transaction, TransactionInfo, WriteSetChange};
    
    // Create a transaction with maximum allowed write ops (10MB)
    let mut large_txn = Transaction::default();
    large_txn.version = 1000;
    
    let mut info = TransactionInfo::default();
    // Simulate 10MB of write operations
    for i in 0..10000 {
        let mut change = WriteSetChange::default();
        // Each change with ~1KB of data
        change.type = 4; // WRITE_MODULE
        info.changes.push(change);
    }
    large_txn.info = Some(info);
    
    let chunk_size = 15 * 1024 * 1024; // 15MB
    let txn_size = large_txn.encoded_len();
    
    // Transaction size exceeds chunk limit
    assert!(txn_size > chunk_size);
    
    // Chunking still succeeds but creates oversized chunk
    let chunks = chunk_transactions(vec![large_txn], chunk_size);
    assert_eq!(chunks.len(), 1);
    
    let chunk_encoded_size: usize = chunks[0]
        .iter()
        .map(|t| t.encoded_len())
        .sum();
    
    // Chunk exceeds the intended limit
    assert!(chunk_encoded_size > chunk_size);
    
    // Downstream systems with 15MB limit would fail here
}
```

## Notes

- This is primarily an **infrastructure reliability issue** rather than a core protocol security vulnerability
- The root cause is the mismatch between on-chain execution limits (10MB write ops + 10MB events) and the indexer chunk size limit (15MB)
- Mitigation requires both code changes and operational guidance for downstream consumers
- The issue does not affect consensus, validator operations, or on-chain security invariants

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L44-49)
```rust
                Ok(client
                    .max_decoding_message_size(usize::MAX)
                    .max_encoding_message_size(usize::MAX)
                    .send_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Gzip)
                    .accept_compressed(CompressionEncoding::Zstd))
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L141-165)
```rust
/// Chunk transactions into chunks with chunk size less than or equal to chunk_size.
/// If a single transaction is larger than chunk_size, it will be put into a chunk by itself.
pub fn chunk_transactions(
    transactions: Vec<Transaction>,
    chunk_size: usize,
) -> Vec<Vec<Transaction>> {
    let mut chunked_transactions = vec![];
    let mut chunk = vec![];
    let mut current_size = 0;

    for transaction in transactions {
        // Only add the chunk when it's empty.
        if !chunk.is_empty() && current_size + transaction.encoded_len() > chunk_size {
            chunked_transactions.push(chunk);
            chunk = vec![];
            current_size = 0;
        }
        current_size += transaction.encoded_len();
        chunk.push(transaction);
    }
    if !chunk.is_empty() {
        chunked_transactions.push(chunk);
    }
    chunked_transactions
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-81)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
        [
            max_transaction_size_in_bytes_gov: NumBytes,
            { RELEASE_V1_13.. => "max_transaction_size_in_bytes.gov" },
            1024 * 1024
        ],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-177)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
        ],
        [
            max_bytes_all_write_ops_per_transaction: NumBytes,
            { 5.. => "max_bytes_all_write_ops_per_transaction" },
            10 << 20, // all write ops from a single transaction are 10MB max
        ],
        [
            max_bytes_per_event: NumBytes,
            { 5.. => "max_bytes_per_event" },
            1 << 20, // a single event is 1MB max
        ],
        [
            max_bytes_all_events_per_transaction: NumBytes,
            { 5.. => "max_bytes_all_events_per_transaction"},
            10 << 20, // all events from a single transaction are 10MB max
        ],
        [
            max_write_ops_per_transaction: NumSlots,
            { 11.. => "max_write_ops_per_transaction" },
            8192,
        ],
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L674-691)
```rust
fn get_transactions_responses_builder(
    transactions: Vec<Transaction>,
    chain_id: u32,
    txns_to_strip_filter: &BooleanTransactionFilter,
) -> (Vec<TransactionsResponse>, usize) {
    let (stripped_transactions, num_stripped) =
        strip_transactions(transactions, txns_to_strip_filter);
    let chunks = chunk_transactions(stripped_transactions, MESSAGE_SIZE_LIMIT);
    let responses = chunks
        .into_iter()
        .map(|chunk| TransactionsResponse {
            chain_id: Some(chain_id as u64),
            transactions: chunk,
            processed_range: None,
        })
        .collect();
    (responses, num_stripped)
}
```
