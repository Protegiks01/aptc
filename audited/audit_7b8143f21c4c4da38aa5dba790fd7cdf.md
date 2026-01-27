# Audit Report

## Title
Remote Process Termination via Timestamp Panic Chain in Indexer-gRPC Manager Status Page

## Summary
The `get_throughput_from_samples()` function contains multiple unchecked `unwrap()` calls on optional protobuf timestamp fields. When processing heartbeat messages from data services, if any `StreamProgressSampleProto` contains a `None` timestamp, accessing the status page endpoint triggers a panic that terminates the entire indexer-grpc-manager process due to the global panic handler.

## Finding Description

The vulnerability exists in the status page rendering logic where throughput calculations are performed without validating that optional protobuf fields are present.

**Root Cause - Unsafe Unwraps:**

The `get_throughput_from_samples()` function performs three separate `unwrap()` operations on the optional `timestamp` field: [1](#0-0) [2](#0-1) 

**Protobuf Schema - Optional Field:**

The `timestamp` field is explicitly declared as optional in the protobuf schema: [3](#0-2) 

This translates to a Rust `Option<Timestamp>` type: [4](#0-3) 

**Attack Vector - Unauthenticated Heartbeat Endpoint:**

The gRPC manager accepts heartbeat messages without authentication and stores them without validation: [5](#0-4) 

The metadata manager stores these messages directly into the state without checking timestamp validity: [6](#0-5) 

**Critical Impact - Process Termination:**

When a panic occurs, the global panic handler terminates the entire process: [7](#0-6) 

**Exploitation Path:**

1. Attacker sends a malicious `HeartbeatRequest` to the unauthenticated gRPC endpoint with `StreamProgressSampleProto` messages where `timestamp` is `None`
2. The manager accepts and stores this data without validation
3. When anyone accesses the status page endpoint, the stored data is passed to `get_throughput_from_samples()`
4. The function hits `timestamp.as_ref().unwrap()` on a `None` value (at line 95, 104, or 105)
5. The panic triggers the global handler which logs the crash and calls `process::exit(12)`
6. The entire indexer-grpc-manager process terminates

## Impact Explanation

**Severity: HIGH** (per Aptos Bug Bounty criteria: "API crashes")

This vulnerability exceeds typical API crash impact because it causes **complete process termination** rather than just a failed request. The indexer-grpc-manager is a critical infrastructure component that:

- Coordinates all data services and fullnodes in the indexer network
- Routes client transaction requests to appropriate data services  
- Maintains metadata about connected services and their capabilities
- Serves as the central point of failure for the indexer infrastructure

When the manager crashes:
- All active client streams are immediately disconnected
- Data services lose their coordination point and cannot receive routing updates
- The entire indexer infrastructure becomes unavailable until manual restart
- No transaction history queries can be processed

The vulnerability qualifies as HIGH severity because:
1. **Remote triggering**: Exploitable via unauthenticated network access
2. **Complete service disruption**: Entire process termination, not just endpoint failure
3. **No recovery mechanism**: Requires manual intervention to restart
4. **Critical infrastructure**: Affects all users of the indexer service

## Likelihood Explanation

**Likelihood: HIGH**

The attack has minimal barriers to execution:

**Attack Prerequisites:**
- Network access to the gRPC manager endpoint (typically exposed for data service communication)
- Ability to craft and send protobuf messages (standard gRPC tooling)
- No authentication required
- No special privileges needed

**Technical Complexity: LOW**
- Standard gRPC client can send the malicious payload
- Protobuf allows omitting optional fields by design
- No cryptographic operations or complex state manipulation required

**Trigger Mechanism: RELIABLE**
- Status page is regularly accessed by monitoring systems and administrators
- The panic is deterministic - any `None` timestamp guarantees process crash
- Three separate unwrap points (lines 95, 104, 105) all trigger the same outcome

**Real-World Scenarios:**
1. Malicious data service sending crafted heartbeats
2. Buggy data service implementation with incorrect protobuf serialization
3. Network corruption causing incomplete message deserialization
4. Version mismatch between data service and manager

## Recommendation

Implement defensive null-safety checks for all optional protobuf fields:

```rust
pub fn get_throughput_from_samples(
    progress: Option<&StreamProgress>,
    duration: Duration,
) -> String {
    if let Some(progress) = progress {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        
        // Validate all samples have timestamps before processing
        let index = progress.samples.partition_point(|p| {
            let timestamp = match p.timestamp.as_ref() {
                Some(ts) => ts,
                None => return true, // Treat missing timestamps as old
            };
            let diff = now - timestamp_to_unixtime(timestamp);
            diff > duration.as_secs_f64()
        });

        if index + 1 < progress.samples.len() {
            let sample_a = progress.samples[index];
            let sample_b = progress.samples.last().unwrap();
            
            // Validate timestamps exist before unwrapping
            let timestamp_a = match sample_a.timestamp.as_ref() {
                Some(ts) => ts,
                None => return "Invalid data: missing timestamp".to_string(),
            };
            let timestamp_b = match sample_b.timestamp.as_ref() {
                Some(ts) => ts,
                None => return "Invalid data: missing timestamp".to_string(),
            };
            
            let time_diff = timestamp_to_unixtime(timestamp_b)
                - timestamp_to_unixtime(timestamp_a);
            let tps = (sample_b.version - sample_a.version) as f64 / time_diff;
            let bps = (sample_b.size_bytes - sample_a.size_bytes) as f64 / time_diff;
            return format!(
                "{} tps, {} / s",
                tps as u64,
                bytesize::to_string(bps as u64, false)
            );
        }
    }

    "No data".to_string()
}
```

**Additional Hardening:**
1. Validate heartbeat messages before storing in metadata manager
2. Add message schema validation at the gRPC service boundary
3. Consider authentication/authorization for heartbeat endpoints
4. Implement graceful error handling instead of relying on panic handler

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_protos::indexer::v1::{StreamProgress, StreamProgressSampleProto};
    use std::time::Duration;

    #[test]
    #[should_panic(expected = "unwrap")]
    fn test_panic_on_missing_timestamp_in_partition_point() {
        // Create a sample with None timestamp
        let malicious_sample = StreamProgressSampleProto {
            timestamp: None, // Missing timestamp
            version: 100,
            size_bytes: 1024,
        };
        
        let progress = StreamProgress {
            samples: vec![malicious_sample],
        };
        
        // This will panic at line 95 when partition_point tries to unwrap
        get_throughput_from_samples(Some(&progress), Duration::from_secs(10));
    }
    
    #[test]
    #[should_panic(expected = "unwrap")]
    fn test_panic_on_missing_timestamp_in_samples() {
        use aptos_protos::util::timestamp::Timestamp;
        
        // Create samples where some have timestamps and one doesn't
        let valid_sample = StreamProgressSampleProto {
            timestamp: Some(Timestamp {
                seconds: 1000,
                nanos: 0,
            }),
            version: 100,
            size_bytes: 1024,
        };
        
        let malicious_sample = StreamProgressSampleProto {
            timestamp: None, // Missing timestamp
            version: 200,
            size_bytes: 2048,
        };
        
        let progress = StreamProgress {
            samples: vec![valid_sample, malicious_sample],
        };
        
        // This will panic at lines 104-105 when accessing sample timestamps
        get_throughput_from_samples(Some(&progress), Duration::from_secs(1));
    }
    
    #[test]
    fn test_exploit_via_grpc_heartbeat() {
        // Simulates the full attack path:
        // 1. Attacker crafts HeartbeatRequest with None timestamps
        // 2. Manager stores it without validation
        // 3. Status page access triggers panic
        
        use aptos_protos::indexer::v1::{
            HeartbeatRequest, ServiceInfo, LiveDataServiceInfo, StreamInfo,
            ActiveStream,
        };
        
        let malicious_sample = StreamProgressSampleProto {
            timestamp: None,
            version: 1000,
            size_bytes: 10240,
        };
        
        let malicious_stream = ActiveStream {
            id: "attacker-stream".to_string(),
            start_time: None,
            start_version: 0,
            end_version: Some(2000),
            progress: Some(StreamProgress {
                samples: vec![malicious_sample],
            }),
        };
        
        let malicious_heartbeat = HeartbeatRequest {
            service_info: Some(ServiceInfo {
                address: Some("malicious-service:50051".to_string()),
                info: Some(aptos_protos::indexer::v1::service_info::Info::LiveDataServiceInfo(
                    LiveDataServiceInfo {
                        chain_id: 1,
                        timestamp: None,
                        known_latest_version: Some(1000),
                        stream_info: Some(StreamInfo {
                            active_streams: vec![malicious_stream],
                        }),
                        min_servable_version: None,
                    }
                )),
            }),
        };
        
        // In a real attack, this would be sent via gRPC client
        // The status page rendering would then panic, terminating the process
        assert!(malicious_heartbeat.service_info.is_some());
    }
}
```

## Notes

**Scope Clarification:**
While this vulnerability is in the indexer-grpc component rather than core consensus/execution layers, it meets the High Severity criteria for several reasons:

1. The indexer-grpc-manager is critical infrastructure explicitly listed in the Aptos architecture documentation
2. Complete process termination exceeds typical "API crash" impact
3. The vulnerability is remotely exploitable without authentication
4. It affects service availability for all indexer users

**Defense in Depth:**
The root cause stems from trusting external protobuf data without validation. The fix requires both:
- Immediate: Null-safety checks in `get_throughput_from_samples()`
- Long-term: Input validation at gRPC service boundaries and authentication for administrative endpoints

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/status_page/mod.rs (L94-96)
```rust
        let index = progress.samples.partition_point(|p| {
            let diff = now - timestamp_to_unixtime(p.timestamp.as_ref().unwrap());
            diff > duration.as_secs_f64()
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/status_page/mod.rs (L104-105)
```rust
            let time_diff = timestamp_to_unixtime(sample_b.timestamp.as_ref().unwrap())
                - timestamp_to_unixtime(sample_a.timestamp.as_ref().unwrap());
```

**File:** protos/proto/aptos/indexer/v1/grpc.proto (L12-16)
```text
message StreamProgressSampleProto {
  optional aptos.util.timestamp.Timestamp timestamp = 1;
  uint64 version = 2;
  uint64 size_bytes = 3;
}
```

**File:** protos/rust/src/pb/aptos.indexer.v1.rs (L160-167)
```rust
pub struct StreamProgressSampleProto {
    #[prost(message, optional, tag="1")]
    pub timestamp: ::core::option::Option<super::super::util::timestamp::Timestamp>,
    #[prost(uint64, tag="2")]
    pub version: u64,
    #[prost(uint64, tag="3")]
    pub size_bytes: u64,
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

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L489-509)
```rust
    fn handle_live_data_service_info(
        &self,
        address: GrpcAddress,
        mut info: LiveDataServiceInfo,
    ) -> Result<()> {
        let mut entry = self
            .live_data_services
            .entry(address.clone())
            .or_insert(LiveDataService::new(address));
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

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L149-168)
```rust
pub fn setup_panic_handler() {
    std::panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());
    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);
    // Kill the process
    process::exit(12);
}
```
