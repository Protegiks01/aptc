# Audit Report

## Title
Integer Overflow in Indexer gRPC Data Service Known Latest Version Tracking

## Summary
The `DataServiceWrapper::ping()` function accepts a client-provided `known_latest_version` value without validation and uses it in arithmetic operations that can cause integer overflow. When a malicious client sends `u64::MAX` as the `known_latest_version`, subsequent arithmetic operations overflow in release mode, breaking version tracking logic and causing service disruption. [1](#0-0) 

## Finding Description
The vulnerability exists in the version tracking mechanism of the indexer gRPC data service. When a client sends a Ping request, the service extracts `known_latest_version` using the protobuf accessor method, which returns either the provided value or 0 (default for absent optional fields). This value is directly passed to `update_known_latest_version()` without any bounds checking or validation. [2](#0-1) 

The `update_known_latest_version` method uses `fetch_max` to atomically update the stored version to the maximum value seen. If an attacker sends `u64::MAX`, this value becomes the permanent known latest version (since no higher value exists).

This corrupted version value then propagates to multiple critical code paths:

**Overflow Point 1 - Future Version Check:** [3](#0-2) 

When `known_latest_version = u64::MAX`, the expression `known_latest_version + 10000` wraps to `9999` in release mode. This causes the validation check to fail for legitimate version numbers ≥ 10000, allowing clients to request data far beyond the actual chain tip without being rejected.

**Overflow Point 2 - Cache Initialization:** [4](#0-3) 

When creating a new `InMemoryCache`, the code computes `known_latest_version + 1` to initialize the `DataManager`. With `known_latest_version = u64::MAX`, this overflows to `0`, causing the cache to believe the blockchain is at version 0. [5](#0-4) 

The `DataManager` then initializes with `end_version = 0`, making it incapable of serving any actual blockchain data.

**Exploitation Path:**
1. Attacker sends a Ping request with `known_latest_version = Some(18446744073709551615)` (u64::MAX)
2. Service updates internal atomic version tracker to u64::MAX via `fetch_max`
3. Immediate impact: Version validation at line 86 breaks due to wraparound
4. Persistent impact: On service restart or cache reinitialization, cache logic completely fails
5. Service becomes unable to serve transaction data correctly

## Impact Explanation
This vulnerability falls under **Medium Severity** per Aptos bug bounty criteria as it causes "State inconsistencies requiring intervention." 

The impact includes:
- **Service Disruption**: The indexer data service cannot serve transaction data correctly
- **Data Integrity**: Clients may receive errors or incorrect version information
- **Availability**: The service requires manual intervention (restart) to restore functionality
- **No Consensus Impact**: This affects only the off-chain indexer service, not the blockchain consensus layer, validators, or on-chain state

While the indexer service is critical infrastructure for applications querying blockchain data, it does not affect blockchain security, consensus safety, or validator operations.

## Likelihood Explanation
**High Likelihood** - The attack is trivial to execute:
- No authentication is required on the Ping RPC endpoint
- A single malicious gRPC call is sufficient
- The attacker needs only network access to the indexer service
- The vulnerability is deterministic and will always succeed in release builds

The Ping endpoint appears to be designed for health checks and service discovery without access controls, making it accessible to any network client. [6](#0-5) 

## Recommendation
Implement validation on the `known_latest_version` parameter before using it in arithmetic operations:

```rust
async fn ping(
    &self,
    req: Request<PingDataServiceRequest>,
) -> Result<Response<PingDataServiceResponse>, Status> {
    let request = req.into_inner();
    if request.ping_live_data_service != self.is_live_data_service {
        if request.ping_live_data_service {
            return Err(Status::not_found("LiveDataService is not enabled."));
        } else {
            return Err(Status::not_found("HistoricalDataService is not enabled."));
        }
    }

    let known_latest_version = request.known_latest_version();
    
    // Add validation to prevent integer overflow
    const MAX_REASONABLE_VERSION: u64 = u64::MAX - 100_000;
    if known_latest_version > MAX_REASONABLE_VERSION {
        return Err(Status::invalid_argument(
            "known_latest_version exceeds maximum allowed value"
        ));
    }
    
    self.connection_manager
        .update_known_latest_version(known_latest_version);
    // ... rest of function
}
```

Additionally, use checked arithmetic operations in version calculations:

```rust
// In live_data_service/mod.rs
if let Some(max_allowed) = known_latest_version.checked_add(10000) {
    if starting_version > max_allowed {
        return Err(Status::failed_precondition(
            "starting_version cannot be set to a far future version.",
        ));
    }
}

// In in_memory_cache.rs
let end_version = known_latest_version.checked_add(1)
    .ok_or_else(|| anyhow!("Version overflow in cache initialization"))?;
```

## Proof of Concept

```rust
use aptos_protos::indexer::v1::{
    data_service_client::DataServiceClient,
    PingDataServiceRequest,
};
use tonic::Request;

#[tokio::test]
async fn test_version_overflow_exploit() {
    // Connect to the data service
    let mut client = DataServiceClient::connect("http://localhost:50051")
        .await
        .expect("Failed to connect to data service");
    
    // Send malicious ping with u64::MAX
    let request = PingDataServiceRequest {
        known_latest_version: Some(u64::MAX), // 18446744073709551615
        ping_live_data_service: true,
    };
    
    // This should succeed, corrupting the version tracker
    let response = client.ping(Request::new(request)).await;
    assert!(response.is_ok());
    
    // Now the service's known_latest_version is permanently set to u64::MAX
    // Any subsequent cache initialization or version checks will overflow
    
    // Verify the corruption by attempting to get transactions
    // with a starting_version that should be rejected but isn't
    let get_tx_request = GetTransactionsRequest {
        starting_version: Some(20000), // Should be rejected if check worked
        transactions_count: Some(10),
        batch_size: None,
        transaction_filter: None,
    };
    
    // This will exhibit broken behavior due to the overflow
    let stream = client.get_transactions(Request::new(get_tx_request)).await;
    // Service will malfunction or return errors
}
```

**Notes:**
- This vulnerability specifically affects the indexer gRPC data service, which is an off-chain component used for querying blockchain data
- It does NOT affect consensus, validator operations, Move VM execution, or on-chain state
- The impact is limited to service availability and data integrity for clients using the indexer API
- Rust's default integer overflow behavior (wrapping in release mode, panic in debug mode) is the underlying cause
- The security question correctly identifies this as Medium severity given its scope to the indexer service

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/service.rs (L164-166)
```rust
        let known_latest_version = request.known_latest_version();
        self.connection_manager
            .update_known_latest_version(known_latest_version);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L185-188)
```rust
    pub(crate) fn update_known_latest_version(&self, version: u64) {
        self.known_latest_version
            .fetch_max(version, Ordering::SeqCst);
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L86-89)
```rust
                if starting_version > known_latest_version + 10000 {
                    let err = Err(Status::failed_precondition(
                        "starting_version cannot be set to a far future version.",
                    ));
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/in_memory_cache.rs (L28-32)
```rust
        let data_manager = Arc::new(RwLock::new(DataManager::new(
            known_latest_version + 1,
            num_slots,
            size_limit_bytes,
        )));
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/data_manager.rs (L27-37)
```rust
    pub(super) fn new(end_version: u64, num_slots: usize, size_limit_bytes: usize) -> Self {
        CACHE_SIZE_LIMIT_BYTES.set(size_limit_bytes as i64);
        Self {
            start_version: end_version.saturating_sub(num_slots as u64),
            end_version,
            data: vec![None; num_slots],
            num_slots,
            size_limit_bytes,
            eviction_target: size_limit_bytes,
            total_size: 0,
        }
```

**File:** protos/proto/aptos/indexer/v1/grpc.proto (L82-86)
```text
message PingDataServiceRequest {
  optional uint64 known_latest_version = 1;
  // `true` for live data service, `false` for historical data service.
  bool ping_live_data_service = 2;
}
```
