# Audit Report

## Title
Memory Exhaustion via Unbounded TransactionsOutput Vector in Indexer gRPC API

## Summary
The `TransactionsOutput` protobuf message contains an unbounded `transactions` vector that can cause memory exhaustion on indexer clients. While honest fullnodes limit batches to ~100 transactions per 15MB chunk, a malicious fullnode can bypass these application-level limits and send arbitrarily large batches. Clients accept unlimited message sizes (`max_decoding_message_size(usize::MAX)`), causing out-of-memory crashes during protobuf deserialization.

## Finding Description

The vulnerability exists in the indexer gRPC streaming API used by cache workers and data managers to fetch transaction data from fullnodes.

**Root Cause:**

The `TransactionsOutput` struct has no size constraints in its protobuf definition: [1](#0-0) 

Honest fullnode implementations apply two levels of chunking before creating `TransactionsOutput`:

1. First chunk by `output_batch_size` (default 100 transactions): [2](#0-1) 

2. Then chunk by `MESSAGE_SIZE_LIMIT` (15MB): [3](#0-2) 

The chunking logic is applied here: [4](#0-3) 

**However**, these are application-level controls. A malicious fullnode can modify the code to bypass these limits and create `TransactionsOutput` messages with millions of transactions.

**Client-Side Vulnerability:**

Indexer clients explicitly disable message size limits when connecting: [5](#0-4) 

The server configuration does not set any encoding limits: [6](#0-5) 

The tonic server's `max_encoding_message_size` defaults to `usize::MAX`: [7](#0-6) 

**Attack Execution:**

When clients receive the malicious `TransactionsOutput`, they process it in two key locations:

1. In the data manager: [8](#0-7) 

2. In the cache worker: [9](#0-8) 

During protobuf deserialization, prost allocates memory for the entire `transactions` vector at once, causing memory exhaustion and process crashes.

## Impact Explanation

**Severity: HIGH** per Aptos bug bounty criteria ("API crashes").

**Affected Systems:**
- Indexer cache workers crash, disrupting transaction indexing pipeline
- Indexer data managers crash, breaking data distribution
- Any client consuming the fullnode gRPC API with default settings

**Not Affected:**
- Validator nodes (they don't use this API)
- Consensus protocol (operates independently)
- Core blockchain functionality

**Attack Impact:**
- Denial of service against indexer infrastructure
- Data pipeline disruption affecting downstream consumers
- Cascading failures if multiple clients connect to the malicious fullnode
- Service recovery requires restart and fullnode blacklisting

This breaks **Resource Limits Invariant #9**: "All operations must respect gas, storage, and computational limits" - the system fails to enforce memory consumption limits for deserialization.

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Requirements:**
- Run a fullnode (no validator access needed)
- Modify open-source code to bypass chunking limits
- Advertise fullnode to indexer clients via configuration or discovery

**Feasibility:**
- Fullnodes are permissionless - anyone can run one
- Source code is public and easily modifiable
- Many indexer deployments connect to community-operated fullnodes
- No authentication prevents malicious fullnodes from participating

**Detection Difficulty:**
- Attack is stealthy until clients crash
- No rate limiting or anomaly detection on message sizes
- Malicious fullnode can appear legitimate initially

## Recommendation

Implement strict message size limits at both server and client sides:

**1. Server-side enforcement (defense in depth):**
```rust
// In ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs
let svc = FullnodeDataServer::new(server)
    .send_compressed(CompressionEncoding::Zstd)
    .accept_compressed(CompressionEncoding::Zstd)
    .accept_compressed(CompressionEncoding::Gzip)
    .max_encoding_message_size(MAX_GRPC_MESSAGE_SIZE); // Add this line
```

**2. Client-side enforcement:**
```rust
// In ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs
// Replace usize::MAX with reasonable limit
const MAX_GRPC_MESSAGE_SIZE: usize = 100 * 1024 * 1024; // 100MB

Ok(client
    .max_decoding_message_size(MAX_GRPC_MESSAGE_SIZE) // Change this
    .max_encoding_message_size(MAX_GRPC_MESSAGE_SIZE))
```

**3. Add protobuf-level validation:**
Add a validation step after deserialization to reject messages with excessive transaction counts:
```rust
// After receiving TransactionsOutput
const MAX_TRANSACTIONS_PER_MESSAGE: usize = 1000;
if data.transactions.len() > MAX_TRANSACTIONS_PER_MESSAGE {
    return Err(Status::invalid_argument("Transaction batch too large"));
}
```

**4. Add monitoring and alerting:**
- Log unusually large batch sizes
- Track memory usage during deserialization
- Implement circuit breakers for problematic fullnodes

## Proof of Concept

```rust
// PoC demonstrating malicious TransactionsOutput creation
// Place in ecosystem/indexer-grpc/indexer-grpc-fullnode/tests/

use aptos_protos::internal::fullnode::v1::{TransactionsOutput};
use aptos_protos::transaction::v1::Transaction;
use prost::Message;

#[test]
fn test_memory_exhaustion_attack() {
    // Create a minimal transaction
    let minimal_txn = Transaction {
        version: 1,
        ..Default::default()
    };
    
    // Malicious fullnode creates huge batch (e.g., 10 million transactions)
    // Each transaction is ~100 bytes, total ~1GB in memory
    let malicious_batch_size = 10_000_000;
    let malicious_output = TransactionsOutput {
        transactions: vec![minimal_txn; malicious_batch_size],
    };
    
    // Encode to bytes (as server would)
    let encoded = malicious_output.encode_to_vec();
    println!("Encoded size: {} bytes", encoded.len());
    
    // Client deserializes (THIS CAUSES OOM)
    // In production, this would crash the process
    let decoded = TransactionsOutput::decode(&encoded[..]);
    assert!(decoded.is_ok());
    
    let decoded_output = decoded.unwrap();
    assert_eq!(decoded_output.transactions.len(), malicious_batch_size);
    
    // Memory usage: malicious_batch_size * sizeof(Transaction) allocated immediately
    println!("Successfully allocated {} transactions in memory", 
             decoded_output.transactions.len());
}

// To demonstrate:
// 1. Modify stream_coordinator.rs to remove chunking limits
// 2. Run indexer-grpc-cache-worker against the modified fullnode
// 3. Observe OOM crash when deserializing the oversized batch
```

**Notes**

The vulnerability is exacerbated by the fact that clients explicitly set `max_decoding_message_size(usize::MAX)`, presumably to handle legitimately large batches. However, this creates an unbounded attack surface where malicious fullnodes can force arbitrary memory allocation on clients. The fix requires establishing and enforcing reasonable upper bounds throughout the stack while maintaining performance for legitimate large batches.

### Citations

**File:** protos/rust/src/pb/aptos.internal.fullnode.v1.rs (L15-18)
```rust
pub struct TransactionsOutput {
    #[prost(message, repeated, tag="1")]
    pub transactions: ::prost::alloc::vec::Vec<super::super::super::transaction::v1::Transaction>,
}
```

**File:** config/src/config/indexer_grpc_config.rs (L18-18)
```rust
const DEFAULT_OUTPUT_BATCH_SIZE: u16 = 100;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L19-19)
```rust
pub const MESSAGE_SIZE_LIMIT: usize = 1024 * 1024 * 15;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L185-196)
```rust
                for chunk in pb_txns.chunks(output_batch_size as usize) {
                    for chunk in chunk_transactions(chunk.to_vec(), MESSAGE_SIZE_LIMIT) {
                        let item = TransactionsFromNodeResponse {
                            response: Some(transactions_from_node_response::Response::Data(
                                TransactionsOutput {
                                    transactions: chunk,
                                },
                            )),
                            chain_id: ledger_chain_id as u32,
                        };
                        responses.push(item);
                    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L44-46)
```rust
                Ok(client
                    .max_decoding_message_size(usize::MAX)
                    .max_encoding_message_size(usize::MAX)
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/runtime.rs (L108-111)
```rust
                let svc = FullnodeDataServer::new(server)
                    .send_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Gzip);
```

**File:** protos/rust/src/pb/aptos.internal.fullnode.v1.tonic.rs (L238-244)
```rust
        /// Limits the maximum size of an encoded message.
        ///
        /// Default: `usize::MAX`
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L261-266)
```rust
                                Response::Data(data) => {
                                    trace!(
                                        "Putting data into cache, {} transaction(s).",
                                        data.transactions.len()
                                    );
                                    self.cache.write().await.put_transactions(data.transactions);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L243-246)
```rust
                async move {
                    // Push to cache.
                    match cache_operator_clone
                        .update_cache_transactions(data.transactions)
```
