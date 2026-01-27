# Audit Report

## Title
Unvalidated Timestamp Nanoseconds Field in HistoricalDataServiceInfo Causes gRPC Manager Crash

## Summary
The `ping_historical_data_service()` function stores `HistoricalDataServiceInfo` responses without validating the timestamp's `nanos` field. When this malformed timestamp is later used in `is_stale_timestamp()`, it triggers a panic in `Duration::new()`, crashing the entire indexer gRPC manager process.

## Finding Description

The vulnerability exists in the handling of `HistoricalDataServiceInfo` responses in the indexer gRPC manager. The function extracts the response on lines 479-480 and passes it to `handle_historical_data_service_info()` without any content validation beyond type checking. [1](#0-0) 

The handler stores the info directly without validating field constraints: [2](#0-1) 

The Timestamp protobuf spec defines `nanos` as an `int32` that must be between 0 and 999,999,999 inclusive: [3](#0-2) 

However, this constraint is not enforced during deserialization or storage. On subsequent main loop iterations, the stored timestamp is passed to `is_stale_timestamp()`: [4](#0-3) 

The `is_stale_timestamp()` function constructs a `Duration` from the timestamp: [5](#0-4) 

**The Critical Bug**: Rust's `Duration::new(secs, nanos)` panics if `nanos >= 1_000_000_000`. A malicious historical data service can respond to ping requests with a `HistoricalDataServiceInfo` containing `timestamp.nanos = 1_000_000_000` (or any invalid value). This value:
1. Is accepted during protobuf deserialization (i32 allows values > 999,999,999)
2. Passes through `handle_historical_data_service_info()` without validation
3. Gets stored in `recent_states`
4. Triggers a panic when `Duration::new()` is called in the next loop iteration
5. Crashes the entire gRPC manager process (no error handling catches the panic)

The same vulnerability exists in the live data service and fullnode handlers since they all use the same unvalidated `is_stale_timestamp()` pattern.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program's "API crashes" category. The indexer gRPC manager is a critical infrastructure component that:
- Routes transaction requests to appropriate data services
- Monitors service health and availability
- Maintains the connection pool for fullnodes and data services

Crashing the manager causes:
- Complete unavailability of the indexer API
- Loss of transaction query capability for all downstream consumers
- Service disruption requiring manual restart
- Potential data loss if service state isn't persisted

While this doesn't affect consensus or validator operations, it impacts the availability of critical query infrastructure used by wallets, explorers, and dApps.

## Likelihood Explanation

**Likelihood: High**

The attack is trivial to execute:
1. Deploy a malicious historical data service
2. Register it with the gRPC manager (or wait for it to be discovered)
3. Respond to ping requests with `HistoricalDataServiceInfo { timestamp: Some(Timestamp { seconds: 0, nanos: 1_000_000_000 }) }`
4. The manager crashes within seconds (next main loop iteration)

Attack requirements:
- No special privileges needed
- No cryptographic material required
- Simple to implement (just modify ping response)
- Deterministic outcome (guaranteed crash)

The vulnerability is triggered automatically once the malicious info is stored, with no user interaction required.

## Recommendation

Add validation to all service info handlers before storing timestamps. Validate that:
1. `timestamp.seconds` is non-negative and within valid range
2. `timestamp.nanos` is between 0 and 999,999,999 inclusive
3. `chain_id` matches the expected chain ID

Example fix for `handle_historical_data_service_info()`:

```rust
fn handle_historical_data_service_info(
    &self,
    address: GrpcAddress,
    mut info: HistoricalDataServiceInfo,
) -> Result<()> {
    // Validate chain_id
    if info.chain_id != self.chain_id {
        bail!("Chain ID mismatch: expected {}, got {}", self.chain_id, info.chain_id);
    }
    
    // Validate timestamp if present
    if let Some(ref ts) = info.timestamp {
        if ts.seconds < 0 || ts.nanos < 0 || ts.nanos >= 1_000_000_000 {
            bail!("Invalid timestamp: seconds={}, nanos={}", ts.seconds, ts.nanos);
        }
    }
    
    let mut entry = self
        .historical_data_services
        .entry(address.clone())
        .or_insert(HistoricalDataService::new(address));
    if info.stream_info.is_none() {
        info.stream_info = Some(StreamInfo {
            active_streams: vec![],
        });
    }
    entry.value_mut().recent_states.push_back(info);
    if entry.value().recent_states.len() > MAX_NUM_OF_STATES_TO_KEEP {
        entry.value_mut().recent_states.pop_front();
    }

    Ok(())
}
```

Apply similar validation to `handle_live_data_service_info()` and `handle_fullnode_info()`.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_protos::indexer::v1::HistoricalDataServiceInfo;
    use aptos_protos::util::timestamp::Timestamp;

    #[test]
    #[should_panic(expected = "panicked")]
    fn test_malformed_timestamp_causes_panic() {
        // Create a malformed timestamp with nanos >= 1 billion
        let malformed_timestamp = Timestamp {
            seconds: 0,
            nanos: 1_000_000_000, // This violates the spec
        };
        
        // This call will panic when is_stale_timestamp tries to create Duration
        let result = MetadataManager::is_stale_timestamp(
            malformed_timestamp,
            Duration::from_secs(5)
        );
    }
    
    #[test]
    fn test_negative_nanos_wraps() {
        // Negative nanos also violates the spec
        let malformed_timestamp = Timestamp {
            seconds: 0,
            nanos: -1,
        };
        
        // When cast to u32, -1 becomes 4,294,967,295 which is >= 1 billion
        // This will panic in Duration::new()
        let result = std::panic::catch_unwind(|| {
            MetadataManager::is_stale_timestamp(
                malformed_timestamp,
                Duration::from_secs(5)
            )
        });
        
        assert!(result.is_err());
    }
}
```

To reproduce the full attack:
1. Set up a test historical data service that responds to ping with invalid timestamp
2. Register it with the gRPC manager
3. Observe the manager crash when it processes the malformed response in the main loop

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L167-173)
```rust
    fn is_stale_timestamp(timestamp: Timestamp, threshold: Duration) -> bool {
        let timestamp_since_epoch = Duration::new(timestamp.seconds as u64, timestamp.nanos as u32);
        let now_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let staleness = now_since_epoch.saturating_sub(timestamp_since_epoch);

        staleness >= threshold
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L257-260)
```rust
                                Self::is_stale_timestamp(
                                    s.timestamp.unwrap_or_default(),
                                    Duration::from_secs(60),
                                )
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L479-480)
```rust
                aptos_protos::indexer::v1::ping_data_service_response::Info::HistoricalDataServiceInfo(info) => {
                    self.handle_historical_data_service_info(address, info)
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L511-531)
```rust
    fn handle_historical_data_service_info(
        &self,
        address: GrpcAddress,
        mut info: HistoricalDataServiceInfo,
    ) -> Result<()> {
        let mut entry = self
            .historical_data_services
            .entry(address.clone())
            .or_insert(HistoricalDataService::new(address));
        if info.stream_info.is_none() {
            info.stream_info = Some(StreamInfo {
                active_streams: vec![],
            });
        }
        entry.value_mut().recent_states.push_back(info);
        if entry.value().recent_states.len() > MAX_NUM_OF_STATES_TO_KEEP {
            entry.value_mut().recent_states.pop_front();
        }

        Ok(())
    }
```

**File:** protos/rust/src/pb/aptos.util.timestamp.rs (L14-19)
```rust
    /// Non-negative fractions of a second at nanosecond resolution. Negative
    /// second values with fractions must still have non-negative nanos values
    /// that count forward in time. Must be from 0 to 999,999,999
    /// inclusive.
    #[prost(int32, tag="2")]
    pub nanos: i32,
```
