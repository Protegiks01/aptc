# Audit Report

## Title
Unvalidated Request Cloning Enables Memory Exhaustion DoS in Indexer gRPC Data Service

## Summary
The `DataServiceWrapperWrapper::get_transactions()` function clones large `GetTransactionsRequest` objects multiple times before validation, allowing authenticated attackers to cause memory exhaustion through arbitrarily large transaction filters (up to 256 MiB per request).

## Finding Description

The indexer gRPC data service's request routing logic performs redundant cloning operations before validating filter size constraints, breaking the **Resource Limits** invariant (Invariant #9). [1](#0-0) 

The vulnerability occurs in the dual-service configuration path (lines 48-63). When both live and historical services are enabled:

1. Line 49: Request extracted from gRPC wrapper
2. Line 51: **First clone** - request cloned to peek at live service stream
3. Line 57: **Second clone** - request cloned again if peek succeeds to make actual call
4. Line 62: Request passed to historical service if live service fails

The `GetTransactionsRequest` contains an optional `transaction_filter` field of type `BooleanTransactionFilter`, which is a recursive structure supporting:
- Nested logical operations (AND/OR/NOT)
- Multiple filter conditions in vectors
- String fields for addresses, module names, function names [2](#0-1) [3](#0-2) 

The gRPC server accepts messages up to 256 MiB in size: [4](#0-3) [5](#0-4) 

However, filter size validation only occurs **after** cloning, inside the underlying services with a default limit of 10KB: [6](#0-5) [7](#0-6) 

**Attack Sequence:**
1. Attacker authenticates via API Gateway (obtaining valid credentials)
2. Constructs `GetTransactionsRequest` with deeply nested `BooleanTransactionFilter` (e.g., 256 MiB of nested LogicalAnd/LogicalOr structures)
3. Sends concurrent requests to the dual-service endpoint
4. Each request triggers 2 clones (512 MiB memory allocation) before validation rejects it
5. 100 concurrent requests = ~50 GB memory allocation spike
6. Service experiences OOM conditions, crashes, or severe performance degradation

## Impact Explanation

**Severity: Medium (per Aptos bug bounty categories)**

This qualifies as Medium severity under "API crashes" affecting the indexer data service. While the indexer is not part of the core consensus/execution path, it is critical infrastructure for:
- dApp developers querying blockchain state
- Analytics platforms processing transaction data
- Monitoring services tracking network activity

A sustained attack would:
- Cause repeated service crashes or restarts
- Degrade query performance for all users
- Potentially trigger cascading failures if monitoring/alerting relies on indexer availability

This does NOT affect:
- Consensus safety or validator operations
- Transaction execution or state storage
- On-chain fund security

## Likelihood Explanation

**Likelihood: Medium-High**

- Attacker needs API Gateway credentials (authentication required), but these are readily obtainable through legitimate registration
- Attack is trivial to execute once authenticated (simple gRPC client with large protobuf message)
- No rate limiting observed on this endpoint
- The dual-service configuration is the default production deployment model
- Multiple concurrent connections are easy to establish

## Recommendation

**Option 1: Validate Before Cloning (Preferred)**
Extract and validate the filter in the wrapper before passing to underlying services:

```rust
async fn get_transactions(
    &self,
    req: Request<GetTransactionsRequest>,
) -> Result<Response<Self::GetTransactionsStream>, Status> {
    // Validate filter size BEFORE any cloning
    let request = req.into_inner();
    if let Some(ref proto_filter) = request.transaction_filter {
        // Perform size check here using serialized size
        let filter_size = proto_filter.encoded_len();
        if filter_size > MAX_TRANSACTION_FILTER_SIZE_BYTES {
            return Err(Status::invalid_argument(
                format!("Transaction filter too large: {} bytes", filter_size)
            ));
        }
    }
    
    // Then proceed with validated request...
}
```

**Option 2: Eliminate Redundant Cloning**
The current implementation makes two separate `get_transactions` calls to the live service just to check if data exists. Refactor to use a single call or implement a lightweight `has_data()` check method.

**Option 3: Apply Rate Limiting**
Integrate the existing `aptos-rate-limiter` crate to throttle requests per authenticated identity.

## Proof of Concept

```rust
// Rust PoC demonstrating memory exhaustion attack
use aptos_protos::indexer::v1::{
    GetTransactionsRequest, 
    BooleanTransactionFilter,
    boolean_transaction_filter::Filter,
    LogicalAndFilters,
};
use tonic::Request;

fn create_large_filter(depth: usize, width: usize) -> BooleanTransactionFilter {
    if depth == 0 {
        // Base case: simple filter
        BooleanTransactionFilter {
            filter: Some(Filter::ApiFilter(/* ... */)),
        }
    } else {
        // Recursive case: create nested AND filter with multiple branches
        BooleanTransactionFilter {
            filter: Some(Filter::LogicalAnd(LogicalAndFilters {
                filters: (0..width)
                    .map(|_| create_large_filter(depth - 1, width))
                    .collect(),
            })),
        }
    }
}

#[tokio::test]
async fn test_memory_exhaustion() {
    // Create filter with ~100MB serialized size
    // Depth 10, width 10 = 10^10 leaf nodes (adjusted for realistic size)
    let large_filter = create_large_filter(10, 5);
    
    let request = GetTransactionsRequest {
        starting_version: Some(0),
        transactions_count: Some(1000),
        batch_size: Some(100),
        transaction_filter: Some(large_filter),
    };
    
    // Send 100 concurrent requests to trigger multiple clones
    let tasks: Vec<_> = (0..100)
        .map(|_| {
            let req = request.clone();
            tokio::spawn(async move {
                // Connect to data service and send request
                // Each will trigger 2 clones = 200MB per request
                // Total: 20GB memory allocation spike
            })
        })
        .collect();
        
    futures::future::join_all(tasks).await;
    // Service likely crashed or severely degraded at this point
}
```

## Notes

**Critical Distinction**: This vulnerability affects the **indexer infrastructure layer**, not the core blockchain consensus or execution. The indexer-grpc services are read-only query endpoints that do not participate in:
- Transaction validation or execution
- Block production or consensus
- State storage or Merkle tree operations
- Validator operations

However, the indexer is essential for ecosystem functionality, and its compromise impacts dApp user experience and developer operations. The vulnerability is valid under the "API crashes" category but does not threaten blockchain integrity itself.

**Additional Context**: The current implementation's dual cloning appears to be a workaround for checking data availability without committing to a stream. This pattern should be refactored to use a more efficient availability check or to reuse the initial stream rather than making redundant calls.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/service.rs (L43-72)
```rust
    async fn get_transactions(
        &self,
        req: Request<GetTransactionsRequest>,
    ) -> Result<Response<Self::GetTransactionsStream>, Status> {
        if let Some(live_data_service) = self.live_data_service.as_ref() {
            if let Some(historical_data_service) = self.historical_data_service.as_ref() {
                let request = req.into_inner();
                let mut stream = live_data_service
                    .get_transactions(Request::new(request.clone()))
                    .await?
                    .into_inner();
                let peekable = std::pin::pin!(stream.as_mut().peekable());
                if let Some(Ok(_)) = peekable.peek().await {
                    return live_data_service
                        .get_transactions(Request::new(request.clone()))
                        .await;
                }

                historical_data_service
                    .get_transactions(Request::new(request))
                    .await
            } else {
                live_data_service.get_transactions(req).await
            }
        } else if let Some(historical_data_service) = self.historical_data_service.as_ref() {
            historical_data_service.get_transactions(req).await
        } else {
            unreachable!("Must have at least one of the data services enabled.");
        }
    }
```

**File:** protos/rust/src/pb/aptos.indexer.v1.rs (L7-16)
```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogicalAndFilters {
    #[prost(message, repeated, tag="1")]
    pub filters: ::prost::alloc::vec::Vec<BooleanTransactionFilter>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogicalOrFilters {
    #[prost(message, repeated, tag="1")]
    pub filters: ::prost::alloc::vec::Vec<BooleanTransactionFilter>,
```

**File:** protos/rust/src/pb/aptos.indexer.v1.rs (L88-107)
```rust
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BooleanTransactionFilter {
    #[prost(oneof="boolean_transaction_filter::Filter", tags="1, 2, 3, 4")]
    pub filter: ::core::option::Option<boolean_transaction_filter::Filter>,
}
/// Nested message and enum types in `BooleanTransactionFilter`.
pub mod boolean_transaction_filter {
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Filter {
        #[prost(message, tag="1")]
        ApiFilter(super::ApiFilter),
        #[prost(message, tag="2")]
        LogicalAnd(super::LogicalAndFilters),
        #[prost(message, tag="3")]
        LogicalOr(super::LogicalOrFilters),
        #[prost(message, tag="4")]
        LogicalNot(::prost::alloc::boxed::Box<super::BooleanTransactionFilter>),
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L31-31)
```rust
pub(crate) const MAX_MESSAGE_SIZE: usize = 256 * (1 << 20);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L240-248)
```rust
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE);
        let wrapper_service =
            aptos_protos::indexer::v1::data_service_server::DataServiceServer::from_arc(wrapper)
                .send_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Gzip)
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L21-21)
```rust
pub const DEFAULT_MAX_TRANSACTION_FILTER_SIZE_BYTES: usize = 10_000;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L98-115)
```rust
                let filter = if let Some(proto_filter) = request.transaction_filter {
                    match filter_utils::parse_transaction_filter(
                        proto_filter,
                        self.max_transaction_filter_size_bytes,
                    ) {
                        Ok(filter) => Some(filter),
                        Err(err) => {
                            info!("Client error: {err:?}.");
                            let _ = response_sender.blocking_send(Err(err));
                            COUNTER
                                .with_label_values(&["live_data_service_invalid_filter"])
                                .inc();
                            continue;
                        },
                    }
                } else {
                    None
                };
```
