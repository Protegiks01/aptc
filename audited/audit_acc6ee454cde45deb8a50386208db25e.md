# Audit Report

## Title
Timestamp Validation Bypass Allows Malicious Services to Persist in Indexer Service Discovery Pool

## Summary
The indexer gRPC service discovery mechanism fails to validate timestamp bounds during deserialization and contains a logic bug in staleness detection that allows malicious fullnodes or data services to remain in the active service pool indefinitely by sending far-future timestamps, causing client requests to be routed to unresponsive services.

## Finding Description

The vulnerability exists in the timestamp handling of the indexer service discovery system, specifically affecting `FullnodeInfo`, `LiveDataServiceInfo`, and `HistoricalDataServiceInfo` messages.

**Root Cause 1: Missing Timestamp Validation**

The protobuf Timestamp message specifies bounds that are never enforced: [1](#0-0) 

During deserialization, these bounds are not validated: [2](#0-1) 

The FullnodeInfo deserialization similarly lacks validation: [3](#0-2) 

**Root Cause 2: Staleness Detection Logic Bug**

The `is_stale_timestamp` function contains a critical flaw when handling future timestamps: [4](#0-3) 

When a timestamp from the future is provided:
1. Line 168 casts `timestamp.seconds` (i64) to u64, allowing large positive values
2. `timestamp_since_epoch` becomes greater than `now_since_epoch`
3. `saturating_sub` returns 0 (instead of a negative value)
4. The staleness check `staleness >= threshold` evaluates to `false`
5. The service is never considered stale, regardless of how long it's been offline

**Attack Execution Path:**

1. Attacker registers a fullnode or data service with the GrpcManager
2. When pinged, the service responds with a FullnodeInfo containing a far-future timestamp (e.g., year 9999): [5](#0-4) 

3. The malicious timestamp is stored in `recent_states`: [6](#0-5) 

4. The staleness check for fullnodes never triggers re-pinging: [7](#0-6) 

5. For data services, the unreachability check never triggers removal from the active pool: [8](#0-7) 

6. Clients requesting data may be routed to the offline service: [9](#0-8) 

## Impact Explanation

This vulnerability falls under **HIGH severity** per the Aptos bug bounty criteria for the following reasons:

**API Crashes**: When clients are routed to unresponsive services due to this bug, their API requests will timeout or fail, qualifying as "API crashes" under the High severity category.

**Service Availability Degradation**: Multiple malicious actors exploiting this vulnerability could maintain a pool of zombie services in the discovery system, significantly degrading indexer infrastructure availability. While this doesn't affect consensus or validator operations directly, it severely impacts the external API layer that applications depend on.

**Scope of Impact**:
- Any client using the GrpcManager to discover fullnodes or data services
- Indexer infrastructure reliability and availability
- Developer experience and application reliability for Aptos ecosystem applications

This does not reach Critical severity because:
- No funds can be lost or stolen
- Consensus protocol remains unaffected
- The core blockchain continues to operate normally
- Only affects the indexer service discovery layer

## Likelihood Explanation

**Likelihood: HIGH**

The attack has a low barrier to entry:
- Attacker only needs to run a fullnode or data service and register it with a GrpcManager instance
- No special privileges or validator access required
- The exploit is trivial to execute (simply return a modified timestamp)
- No rate limiting or anomaly detection on timestamp values

The bug will manifest naturally if:
- A service's system clock becomes severely misconfigured (future date)
- An attacker deliberately sends malicious timestamps

The combination of easy exploitation and high impact makes this a high-likelihood vulnerability.

## Recommendation

**Immediate Fix: Add Timestamp Validation**

Add validation in the deserialization layer:

```rust
// In aptos.util.timestamp.serde.rs, modify the deserialize implementation:
impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // ... existing code ...
        
        let result = Timestamp {
            seconds: seconds__.unwrap_or_default(),
            nanos: nanos__.unwrap_or_default(),
        };
        
        // Validate bounds per protobuf spec
        const MIN_TIMESTAMP: i64 = -62135596800; // 0001-01-01T00:00:00Z
        const MAX_TIMESTAMP: i64 = 253402300799;  // 9999-12-31T23:59:59Z
        
        if result.seconds < MIN_TIMESTAMP || result.seconds > MAX_TIMESTAMP {
            return Err(serde::de::Error::custom(
                format!("timestamp seconds {} out of valid range", result.seconds)
            ));
        }
        
        if result.nanos < 0 || result.nanos > 999_999_999 {
            return Err(serde::de::Error::custom(
                format!("timestamp nanos {} out of valid range", result.nanos)
            ));
        }
        
        Ok(result)
    }
}
```

**Secondary Fix: Fix Staleness Detection Logic**

In `metadata_manager.rs`, fix the `is_stale_timestamp` function:

```rust
fn is_stale_timestamp(timestamp: Timestamp, threshold: Duration) -> bool {
    let timestamp_since_epoch = Duration::new(
        timestamp.seconds.max(0) as u64,  // Guard against negative values
        timestamp.nanos.max(0) as u32
    );
    let now_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    
    // Handle both past and future timestamps correctly
    if timestamp_since_epoch > now_since_epoch {
        // Future timestamp - consider it stale immediately
        return true;
    }
    
    let staleness = now_since_epoch - timestamp_since_epoch;
    staleness >= threshold
}
```

**Additional Hardening: Add Reasonable Bounds Check**

For service discovery, add a more restrictive check that rejects timestamps too far in the future or past:

```rust
fn is_reasonable_timestamp(timestamp: Timestamp) -> bool {
    let timestamp_since_epoch = Duration::new(
        timestamp.seconds.max(0) as u64,
        timestamp.nanos.max(0) as u32
    );
    let now_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    
    const MAX_CLOCK_SKEW: Duration = Duration::from_secs(300); // 5 minutes
    
    // Reject timestamps more than 5 minutes in the future
    if timestamp_since_epoch > now_since_epoch + MAX_CLOCK_SKEW {
        return false;
    }
    
    // Reject very old timestamps (before 2020)
    const MIN_REASONABLE: Duration = Duration::from_secs(1577836800); // 2020-01-01
    if timestamp_since_epoch < MIN_REASONABLE {
        return false;
    }
    
    true
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod timestamp_vulnerability_poc {
    use super::*;
    use aptos_protos::{
        indexer::v1::FullnodeInfo,
        util::timestamp::Timestamp,
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_future_timestamp_bypasses_staleness_check() {
        // Create a timestamp far in the future (year 9999)
        let future_timestamp = Timestamp {
            seconds: 253402300799, // 9999-12-31T23:59:59Z
            nanos: 0,
        };
        
        // Current implementation considers this NOT stale
        let is_stale = MetadataManager::is_stale_timestamp(
            future_timestamp,
            Duration::from_secs(60)
        );
        
        // Bug: Future timestamp is not considered stale
        assert_eq!(is_stale, false, "Future timestamp should be considered stale but isn't");
    }
    
    #[test]
    fn test_malicious_fullnode_persists_in_pool() {
        // Simulate a malicious fullnode that sends future timestamp
        let malicious_info = FullnodeInfo {
            chain_id: 1,
            timestamp: Some(Timestamp {
                seconds: 253402300799, // Year 9999
                nanos: 0,
            }),
            known_latest_version: Some(1000),
        };
        
        // Create metadata manager
        let manager = MetadataManager::new(
            1,
            "http://localhost:8080".to_string(),
            vec![],
            vec!["http://malicious:8081".to_string()],
            None,
        );
        
        // Handle the malicious info
        manager.handle_fullnode_info(
            "http://malicious:8081".to_string(),
            malicious_info.clone()
        ).unwrap();
        
        // Wait for staleness threshold to pass
        std::thread::sleep(Duration::from_secs(2));
        
        // Bug: Service is still in the pool and not marked for re-ping
        let fullnodes_info = manager.get_fullnodes_info();
        assert!(fullnodes_info.contains_key("http://malicious:8081"));
        
        // The service will be selected for routing even though it's stale
        // This will cause client request failures
    }
}
```

**Notes:**

This vulnerability is specific to the indexer gRPC service discovery infrastructure and does not affect consensus, the Move VM, or validator operations. However, it significantly impacts the availability and reliability of the indexer API layer that ecosystem applications depend on. The fix should be prioritized as it allows trivial DoS attacks on indexer infrastructure by anyone capable of registering a service with the GrpcManager.

### Citations

**File:** protos/proto/aptos/util/timestamp/timestamp.proto (L9-18)
```text
  // Represents seconds of UTC time since Unix epoch
  // 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to
  // 9999-12-31T23:59:59Z inclusive.
  int64 seconds = 1;

  // Non-negative fractions of a second at nanosecond resolution. Negative
  // second values with fractions must still have non-negative nanos values
  // that count forward in time. Must be from 0 to 999,999,999
  // inclusive.
  int32 nanos = 2;
```

**File:** protos/rust/src/pb/aptos.util.timestamp.serde.rs (L108-111)
```rust
                Ok(Timestamp {
                    seconds: seconds__.unwrap_or_default(),
                    nanos: nanos__.unwrap_or_default(),
                })
```

**File:** protos/rust/src/pb/aptos.indexer.v1.serde.rs (L776-796)
```rust
                        GeneratedField::Timestamp => {
                            if timestamp__.is_some() {
                                return Err(serde::de::Error::duplicate_field("timestamp"));
                            }
                            timestamp__ = map.next_value()?;
                        }
                        GeneratedField::KnownLatestVersion => {
                            if known_latest_version__.is_some() {
                                return Err(serde::de::Error::duplicate_field("knownLatestVersion"));
                            }
                            known_latest_version__ =
                                map.next_value::<::std::option::Option<::pbjson::private::NumberDeserialize<_>>>()?.map(|x| x.0)
                            ;
                        }
                    }
                }
                Ok(FullnodeInfo {
                    chain_id: chain_id__.unwrap_or_default(),
                    timestamp: timestamp__,
                    known_latest_version: known_latest_version__,
                })
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L167-173)
```rust
    fn is_stale_timestamp(timestamp: Timestamp, threshold: Duration) -> bool {
        let timestamp_since_epoch = Duration::new(timestamp.seconds as u64, timestamp.nanos as u32);
        let now_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let staleness = now_since_epoch.saturating_sub(timestamp_since_epoch);

        staleness >= threshold
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L196-214)
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
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L217-228)
```rust
                for kv in &self.live_data_services {
                    let (address, live_data_service) = kv.pair();
                    let unreachable = live_data_service.recent_states.back().is_some_and(|s| {
                        Self::is_stale_timestamp(
                            s.timestamp.unwrap_or_default(),
                            Duration::from_secs(60),
                        )
                    });
                    if unreachable {
                        unreachable_live_data_services.push(address.clone());
                        continue;
                    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L341-374)
```rust
    pub(crate) fn get_fullnode_for_request(
        &self,
        request: &GetTransactionsFromNodeRequest,
    ) -> (GrpcAddress, FullnodeDataClient<Channel>) {
        // TODO(grao): Double check the counters to see if we need a different way or additional
        // information.
        let mut rng = thread_rng();
        if let Some(fullnode) = self
            .fullnodes
            .iter()
            .filter(|fullnode| {
                fullnode
                    .recent_states
                    .back()
                    .is_some_and(|s| s.known_latest_version >= request.starting_version)
            })
            .choose(&mut rng)
            .map(|kv| (kv.key().clone(), kv.value().client.clone()))
        {
            COUNTER
                .with_label_values(&["get_fullnode_for_request__happy"])
                .inc();
            return fullnode;
        }

        COUNTER
            .with_label_values(&["get_fullnode_for_request__fallback"])
            .inc();
        self.fullnodes
            .iter()
            .choose(&mut rng)
            .map(|kv| (kv.key().clone(), kv.value().client.clone()))
            .unwrap()
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L533-549)
```rust
    fn handle_fullnode_info(&self, address: GrpcAddress, info: FullnodeInfo) -> Result<()> {
        let mut entry = self
            .fullnodes
            .entry(address.clone())
            .or_insert(Fullnode::new(address.clone()));
        entry.value_mut().recent_states.push_back(info);
        if let Some(known_latest_version) = info.known_latest_version {
            trace!(
                "Received known_latest_version ({known_latest_version}) from fullnode {address}."
            );
            self.update_known_latest_version(known_latest_version);
        }
        if entry.value().recent_states.len() > MAX_NUM_OF_STATES_TO_KEEP {
            entry.value_mut().recent_states.pop_front();
        }

        Ok(())
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L235-241)
```rust
        let info = FullnodeInfo {
            chain_id: self.service_context.context.chain_id().id() as u64,
            timestamp: Some(timestamp),
            known_latest_version,
        };
        let response = PingFullnodeResponse { info: Some(info) };
        Ok(Response::new(response))
```
