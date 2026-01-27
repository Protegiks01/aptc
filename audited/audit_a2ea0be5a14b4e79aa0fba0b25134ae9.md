# Audit Report

## Title
Missing batch_size Validation Allows Performance Degradation Through Cache Lock Starvation

## Summary
The indexer-grpc-data-service-v2 fails to validate the `batch_size` parameter from client requests, despite protobuf specification requiring rejection of values larger than 1000. This allows malicious clients to force excessive cache scanning while holding read locks, starving write operations and degrading performance for all clients waiting for new data.

## Finding Description

The vulnerability exists in the request handling flow of the LiveDataService. The protobuf specification explicitly states that batch_size values larger than 1000 should be rejected: [1](#0-0) 

However, the implementation in LiveDataService does not validate this constraint and blindly accepts any batch_size value provided by the client: [2](#0-1) 

When a client omits the `transactions_count` field, the `ending_version` is set to `u64::MAX`: [3](#0-2) 

The `get_data()` function then acquires a read lock on the shared `data_manager` and iterates through transactions: [4](#0-3) 

The iteration loop has three bounds - ending_version, max_bytes_per_batch, and max_num_transactions_per_batch: [5](#0-4) 

The max_bytes_per_batch is hardcoded to 20MB: [6](#0-5) 

**Attack Execution:**
1. Malicious client sends `GetTransactionsRequest` with:
   - `starting_version` = (current version - some offset still in cache)
   - `transactions_count` = None (omitted)
   - `batch_size` = u64::MAX

2. The service accepts these parameters without validation

3. Each call to `get_data()` holds a read lock while processing up to 20MB of transactions. With small transactions (~1KB each), this processes ~20,000 transactions versus the specified limit of 1000.

4. Multiple concurrent malicious clients create constant read lock acquisitions on the shared `data_manager`, which is protected by `tokio::sync::RwLock`: [7](#0-6) 

5. The `tokio::sync::RwLock` does not guarantee fairness between readers and writers. Constant reader activity starves write lock acquisition.

6. Write operations (cache updates via `update_data()`) cannot acquire the write lock: [8](#0-7) 

7. The background task that continuously fetches latest data gets blocked, preventing cache updates with new transactions.

8. All legitimate clients waiting for new data experience degraded performance as they wait for cache updates that never arrive: [9](#0-8) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per the Aptos bug bounty criteria:

- **Validator node slowdowns / API performance degradation**: The indexer-grpc data service experiences severe performance degradation when malicious clients exploit this vulnerability. All clients waiting for new transaction data will experience delays.

- **Service availability impact**: While not causing total loss of availability, the attack significantly degrades service quality for all users, as the cache cannot be updated with new data.

- **No funds at risk**: This is a performance/availability issue, not a funds theft vulnerability.

The impact falls into the "Validator node slowdowns" and "API crashes" categories under High Severity, though the actual severity is Medium as it affects the indexer service rather than core consensus nodes directly.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **No authentication required**: Any client can connect to the indexer-grpc service and send requests

2. **Trivial exploitation**: The attack requires only setting three parameters in a standard gRPC request - no special knowledge or tools needed

3. **No rate limiting**: There are no per-client connection limits or request rate limits specifically for the indexer-grpc-data-service-v2: [10](#0-9) 

4. **Multiplicative effect**: A single attacker can open multiple concurrent connections, each making repeated requests, amplifying the lock contention

5. **No detection**: There's no monitoring or alerting for abnormally large batch_size values

## Recommendation

**Immediate Fix:**
Add validation to enforce the batch_size limit specified in the protobuf definition. In `ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs`, after line 121, add:

```rust
let max_num_transactions_per_batch = if let Some(batch_size) = request.batch_size {
    if batch_size > 1000 {
        let err = Err(Status::invalid_argument(
            "batch_size cannot be larger than 1000.",
        ));
        info!("Client error: {err:?}.");
        let _ = response_sender.blocking_send(err);
        COUNTER
            .with_label_values(&["live_data_service_invalid_batch_size"])
            .inc();
        continue;
    }
    batch_size as usize
} else {
    1000  // Changed from 10000 to match proto spec
};
```

The same fix should be applied to `HistoricalDataService` at: [11](#0-10) 

**Additional Hardening:**
1. Add per-client connection limits
2. Implement rate limiting for requests
3. Consider using a fair RwLock implementation or adding backoff for readers
4. Add monitoring for abnormal request patterns

## Proof of Concept

```rust
// This PoC demonstrates the attack by showing the request parameters
// that would be sent to trigger the vulnerability

use aptos_protos::indexer::v1::GetTransactionsRequest;

#[test]
fn test_batch_size_validation_bypass() {
    // Malicious request parameters
    let malicious_request = GetTransactionsRequest {
        starting_version: Some(1000000), // Version still in cache
        transactions_count: None,         // Omit to get ending_version = u64::MAX
        batch_size: Some(u64::MAX),       // Bypass the 1000 limit
        transaction_filter: None,
    };
    
    // In the current implementation, this request is ACCEPTED without validation
    // It should be REJECTED with Status::invalid_argument
    
    // To reproduce:
    // 1. Start indexer-grpc-data-service-v2
    // 2. Open multiple gRPC connections (e.g., 10-20 clients)
    // 3. Each client sends the malicious_request repeatedly
    // 4. Observe:
    //    - Read locks held for extended periods (processing ~20k txns vs 1000)
    //    - Write operations (cache updates) get blocked
    //    - Legitimate clients experience delays waiting for new data
    //    - Metrics show NUM_CONNECTED_STREAMS increasing
    //    - Latency metrics (LATENCY_MS) show increasing delays
    
    // Expected fix behavior:
    // The service should reject the request with:
    // Status::invalid_argument("batch_size cannot be larger than 1000.")
}

// To measure the impact, monitor these metrics while attack is ongoing:
// - CACHE_END_VERSION (should stop advancing during attack)
// - NUM_CONNECTED_STREAMS (shows number of malicious streams)
// - cache_get_data timer (shows increased lock hold times)
```

**Notes:**
- This vulnerability affects the indexer infrastructure, not the core blockchain consensus
- The attack degrades service for all indexer clients but does not compromise blockchain safety
- The fix is straightforward and aligns the implementation with the documented specification
- The vulnerability exists in both LiveDataService and HistoricalDataService with identical root causes

### Citations

**File:** protos/proto/aptos/indexer/v1/raw_data.proto (L28-29)
```text
  // If not present, default to 1000. If larger than 1000, request will be rejected.
  optional uint64 batch_size = 3;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L28-28)
```rust
const MAX_BYTES_PER_BATCH: usize = 20 * (1 << 20);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L117-121)
```rust
                let max_num_transactions_per_batch = if let Some(batch_size) = request.batch_size {
                    batch_size as usize
                } else {
                    10000
                };
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L171-171)
```rust
        let ending_version = ending_version.unwrap_or(u64::MAX);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/in_memory_cache.rs (L17-17)
```rust
    pub(super) data_manager: Arc<RwLock<DataManager>>,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/in_memory_cache.rs (L50-63)
```rust
        while starting_version >= self.data_manager.read().await.end_version {
            trace!("Reached head, wait...");
            let num_transactions = self
                .fetch_manager
                .fetching_latest_data_task
                .read()
                .await
                .as_ref()
                .unwrap()
                .clone()
                .await;

            trace!("Done waiting, got {num_transactions} transactions at head.");
        }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/in_memory_cache.rs (L66-66)
```rust
            let data_manager = self.data_manager.read().await;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/in_memory_cache.rs (L84-87)
```rust
            while version < ending_version
                && total_bytes < max_bytes_per_batch
                && result.len() < max_num_transactions_per_batch
            {
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/fetch_manager.rs (L57-60)
```rust
            data_manager
                .write()
                .await
                .update_data(version, transactions);
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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L102-106)
```rust
                let max_num_transactions_per_batch = if let Some(batch_size) = request.batch_size {
                    batch_size as usize
                } else {
                    DEFAULT_MAX_NUM_TRANSACTIONS_PER_BATCH
                };
```
