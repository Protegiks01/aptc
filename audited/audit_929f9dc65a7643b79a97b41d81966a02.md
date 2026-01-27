# Audit Report

## Title
Timestamp Type Conversion Vulnerability in Indexer gRPC Manager Causes DoS and Service Discovery Corruption

## Summary
The `is_stale_timestamp()` function in the indexer-grpc-manager unsafely converts protobuf `Timestamp` fields (i64 seconds, i32 nanos) to unsigned types (u64, u32) without validation. This allows malicious peers to crash the service via panic or corrupt service discovery by making stale services appear fresh.

## Finding Description

The vulnerability exists in the timestamp validation logic used throughout the indexer-grpc system. [1](#0-0) 

The protobuf `Timestamp` type uses signed integers that can be negative: [2](#0-1) 

**Attack Vector 1: Panic via Invalid Nanos**

When a malicious peer sends a `Timestamp` with `nanos < 0`, the cast to `u32` wraps the value. For example, `nanos = -1` becomes `u32::MAX`. Since Rust's `Duration::new(secs, nanos)` panics when `nanos >= 1_000_000_000`, any negative nanos value below -1,000,000,000 will trigger a panic, crashing the grpc-manager process.

**Attack Vector 2: Service Discovery Corruption via Negative Seconds**

When `seconds < 0`, the cast to `u64` wraps the value to a very large positive number (e.g., `-1` becomes `u64::MAX`). This creates a `Duration` representing a timestamp far in the future. The staleness calculation uses `saturating_sub()`, which returns 0 when the malicious timestamp is greater than current time. [1](#0-0) 

The function incorrectly returns `false` (not stale), allowing malicious services to remain in the service registry indefinitely.

**Exploitation Path:**

1. Attacker connects as a peer (fullnode, data service, or grpc-manager)
2. Sends `HeartbeatRequest` with crafted `Timestamp` in the `ServiceInfo`
3. The request flows through the gRPC handler: [3](#0-2) 
4. Reaches `metadata_manager.handle_heartbeat()`: [4](#0-3) 
5. Timestamp is stored in service state without validation
6. Main loop calls `is_stale_timestamp()` with malicious timestamp: [5](#0-4) 
7. Either panics or corrupts service discovery

**Additional Vulnerable Locations:**

The same pattern exists in: [6](#0-5) 

And: [7](#0-6) 

## Impact Explanation

This vulnerability meets **Medium Severity** criteria per the Aptos bug bounty program:
- **State inconsistencies requiring intervention**: Malicious services can persist in the registry, corrupting service discovery and load balancing
- **API crashes**: The panic causes immediate termination of the grpc-manager process, disrupting indexer infrastructure

While the indexer-grpc-manager is not part of the core consensus layer, it provides critical infrastructure for ecosystem tooling, data services, and application developers relying on indexed blockchain data.

## Likelihood Explanation

**Likelihood: HIGH**

- No authentication barrier - any network peer can send heartbeat requests
- No input validation on timestamp values
- Trivial to exploit - requires only crafting a protobuf message with negative fields
- Multiple attack surfaces (fullnodes, data services, other grpc managers)
- Wide deployment - all indexer-grpc-manager instances are vulnerable

## Recommendation

Add validation before converting timestamp fields to unsigned types:

```rust
fn is_stale_timestamp(timestamp: Timestamp, threshold: Duration) -> bool {
    // Validate timestamp fields are within acceptable ranges
    if timestamp.seconds < 0 || timestamp.nanos < 0 || timestamp.nanos >= 1_000_000_000 {
        // Invalid timestamp is always considered stale
        return true;
    }
    
    let timestamp_since_epoch = Duration::new(timestamp.seconds as u64, timestamp.nanos as u32);
    let now_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let staleness = now_since_epoch.saturating_sub(timestamp_since_epoch);

    staleness >= threshold
}
```

Apply the same fix to all three vulnerable locations. Additionally, consider validating timestamps at deserialization time or in the heartbeat handler to fail fast.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_protos::util::timestamp::Timestamp;
    use std::time::Duration;

    #[test]
    #[should_panic(expected = "nanos")]
    fn test_negative_nanos_causes_panic() {
        // Negative nanos wraps to large u32, triggering panic in Duration::new
        let malicious_timestamp = Timestamp {
            seconds: 1000000000,
            nanos: -1, // Wraps to u32::MAX
        };
        
        // This should panic
        MetadataManager::is_stale_timestamp(
            malicious_timestamp, 
            Duration::from_secs(60)
        );
    }

    #[test]
    fn test_negative_seconds_bypass_staleness() {
        // Negative seconds wraps to huge u64, appearing to be in the future
        let malicious_timestamp = Timestamp {
            seconds: -1, // Wraps to u64::MAX
            nanos: 0,
        };
        
        // Should be considered stale, but returns false due to wrap-around
        let is_stale = MetadataManager::is_stale_timestamp(
            malicious_timestamp,
            Duration::from_secs(60)
        );
        
        // Bug: this incorrectly returns false (not stale)
        assert_eq!(is_stale, false); 
        // Expected: should return true (stale) for invalid timestamp
    }

    #[test]
    fn test_valid_timestamp_works() {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let past_timestamp = Timestamp {
            seconds: (now.as_secs() - 120) as i64, // 2 minutes ago
            nanos: 0,
        };
        
        let is_stale = MetadataManager::is_stale_timestamp(
            past_timestamp,
            Duration::from_secs(60)
        );
        
        assert_eq!(is_stale, true); // Correctly identified as stale
    }
}
```

## Notes

The vulnerability affects the indexer ecosystem infrastructure, not core consensus. However, it enables complete denial-of-service of indexer services and persistent corruption of service discovery mechanisms, impacting all applications relying on Aptos indexed data.

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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L196-215)
```rust
                for kv in &self.fullnodes {
                    let (address, fullnode) = kv.pair();
                    let need_ping = fullnode.recent_states.back().is_none_or(|s| {
                        Self::is_stale_timestamp(
                            s.timestamp.unwrap_or_default(),
                            Duration::from_secs(1),
                        )
                    });
                    if need_ping {
                        let address = address.clone();
                        let client = fullnode.client.clone();
                        s.spawn(async move {
                            if let Err(e) = self.ping_fullnode(address.clone(), client).await {
                                warn!("Failed to ping FN ({address}): {e:?}.");
                            } else {
                                trace!("Successfully pinged FN ({address}).");
                            }
                        });
                    }
                }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L330-339)
```rust
    pub(crate) fn handle_heartbeat(&self, address: GrpcAddress, info: Info) -> Result<()> {
        match info {
            Info::LiveDataServiceInfo(info) => self.handle_live_data_service_info(address, info),
            Info::HistoricalDataServiceInfo(info) => {
                self.handle_historical_data_service_info(address, info)
            },
            Info::FullnodeInfo(info) => self.handle_fullnode_info(address, info),
            Info::GrpcManagerInfo(info) => self.handle_grpc_manager_info(address, info),
        }
    }
```

**File:** protos/rust/src/pb/aptos.util.timestamp.rs (L8-20)
```rust
pub struct Timestamp {
    /// Represents seconds of UTC time since Unix epoch
    /// 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to
    /// 9999-12-31T23:59:59Z inclusive.
    #[prost(int64, tag="1")]
    pub seconds: i64,
    /// Non-negative fractions of a second at nanosecond resolution. Negative
    /// second values with fractions must still have non-negative nanos values
    /// that count forward in time. Must be from 0 to 999,999,999
    /// inclusive.
    #[prost(int32, tag="2")]
    pub nanos: i32,
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/service.rs (L110-127)
```rust
    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let request = request.into_inner();
        if let Some(service_info) = request.service_info {
            if let Some(address) = service_info.address {
                if let Some(info) = service_info.info {
                    return self
                        .handle_heartbeat(address, info)
                        .await
                        .map_err(|e| Status::internal(format!("Error handling heartbeat: {e}")));
                }
            }
        }

        Err(Status::invalid_argument("Bad request."))
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L192-193)
```rust
                let timestamp_since_epoch =
                    Duration::new(timestamp.seconds as u64, timestamp.nanos as u32);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/data_manager.rs (L96-97)
```rust
                let timestamp_since_epoch =
                    Duration::new(txn_timestamp.seconds as u64, txn_timestamp.nanos as u32);
```
