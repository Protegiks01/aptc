# Audit Report

## Title
Post-Deserialization Size Validation Allows Memory Exhaustion in Peer Monitoring Service

## Summary
The peer monitoring service validates response sizes **after** deserializing messages, allowing malicious peers to cause memory exhaustion by sending responses with arbitrarily large `build_information` strings that bypass the intended 100 KB size limit.

## Finding Description

The `NodeInformationResponse` struct contains a `build_information` field populated from runtime environment variables without size validation: [1](#0-0) 

The server populates this field by calling `aptos_build_info::get_build_information()`: [2](#0-1) 

The `get_build_information()` function reads runtime environment variables (`GIT_SHA`, `GIT_BRANCH`, `GIT_TAG`, `BUILD_DATE`) without size limits: [3](#0-2) 

A malicious peer can set these environment variables to extremely large values (e.g., 20 MB each) when starting their node. The peer monitoring service allows messages up to 64 MiB: [4](#0-3) 

The critical vulnerability occurs in the validation order. The client deserializes responses before checking size: [5](#0-4) 

The response is **fully deserialized** at line 108-115, allocating memory for all strings in the `build_information` BTreeMap. Only **after** deserialization completes does the `sanity_check_response_size()` function check against the 100 KB limit at lines 135-142.

The size check itself re-serializes the entire response to calculate its size: [6](#0-5) 

**Attack Flow:**
1. Attacker starts malicious node with: `GIT_SHA=$(python3 -c "print('A'*20000000)") GIT_BRANCH=$(python3 -c "print('B'*20000000)") ./aptos-node`
2. Malicious node's `build_information` contains ~64 MB of data
3. Victim nodes automatically query this peer every 15 seconds (default interval)
4. Victim receives and deserializes the entire 64 MB response into memory
5. Size check rejects the response (exceeds 100 KB)
6. Memory is freed, attack repeats automatically

This breaks the **Resource Limits** invariant that all operations must respect computational limits, as unbounded memory allocation occurs before validation.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program:
- **Resource exhaustion**: Up to 64 MB allocated and freed per query per malicious peer
- **CPU waste**: Time spent deserializing + re-serializing for size validation
- **Network bandwidth**: 64 MB transmitted every 15 seconds per attacker
- **Scalable attack**: Multiple malicious peers amplify resource consumption
- **State inconsistencies**: Could require intervention if nodes become unstable under memory pressure

The default node info request interval is 15 seconds: [7](#0-6) 

With 10 malicious peers, this results in ~640 MB/15 seconds of wasted memory churn, potentially causing GC pressure and node slowdowns (approaching **High Severity**: "Validator node slowdowns").

## Likelihood Explanation

**Likelihood: High**
- **Attack barrier**: Low - attacker only needs to run one malicious node with modified environment variables
- **Automatic exploitation**: Peer monitoring queries happen automatically every 15 seconds
- **No authentication bypass needed**: Any network peer can exploit this
- **Realistic scenario**: Malicious peers are within the threat model as untrusted actors

The peer monitoring service has no per-peer rate limiting, only global concurrency limits: [8](#0-7) 

## Recommendation

**Fix 1: Validate size before deserialization**

Modify the network layer to enforce application-level message size limits before deserialization. The BCS protocol already supports limited deserialization: [9](#0-8) 

Change `PeerMonitoringServiceRpc` to use size-limited deserialization instead of just recursion limits.

**Fix 2: Add server-side validation**

Add size validation in `get_node_information()` before sending responses:
```rust
fn get_node_information(&self) -> Result<PeerMonitoringServiceResponse, Error> {
    let build_information = aptos_build_info::get_build_information();
    
    // Validate build_information size
    let build_info_size: usize = build_information
        .iter()
        .map(|(k, v)| k.len() + v.len())
        .sum();
    if build_info_size > MAX_BUILD_INFO_SIZE {
        return Err(Error::InvalidRequest("build_information too large".into()));
    }
    
    // ... rest of function
}
```

**Fix 3: Limit environment variable sizes**

Add size validation when reading environment variables:
```rust
if let Ok(git_sha) = std::env::var("GIT_SHA") {
    if git_sha.len() <= MAX_ENV_VAR_SIZE {
        build_information.insert(BUILD_COMMIT_HASH.into(), git_sha);
    }
}
```

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_oversized_build_information_memory_exhaustion() {
    use std::env;
    use aptos_peer_monitoring_service_client::PeerMonitoringServiceClient;
    
    // Simulate malicious node setting large env vars (attacker's node startup)
    unsafe {
        env::set_var("GIT_SHA", "A".repeat(20_000_000)); // 20 MB
        env::set_var("GIT_BRANCH", "B".repeat(20_000_000)); // 20 MB
        env::set_var("GIT_TAG", "C".repeat(20_000_000)); // 20 MB
    }
    
    // Start malicious peer monitoring server
    let (malicious_server, malicious_network_events) = setup_peer_monitoring_server();
    
    // Start victim client that queries the malicious peer
    let victim_client = setup_peer_monitoring_client();
    
    // Measure memory before attack
    let memory_before = get_process_memory();
    
    // Victim queries malicious peer for node information
    let response = victim_client
        .send_request(
            malicious_peer_id,
            PeerMonitoringServiceRequest::GetNodeInformation,
            Duration::from_secs(10),
        )
        .await;
    
    // Measure peak memory during deserialization
    let memory_peak = get_process_memory();
    
    // Response should be rejected for exceeding size limit
    assert!(response.is_err());
    
    // But memory was allocated during deserialization
    // Peak memory usage should show ~64 MB spike
    assert!(memory_peak - memory_before > 60_000_000); // 60 MB threshold
    
    // Attack repeats every 15 seconds automatically via peer monitoring loop
}
```

**Notes:**
- The vulnerability allows malicious peers to waste victim resources through repeated memory exhaustion
- No server-side validation prevents oversized responses from being sent
- Client-side validation occurs post-deserialization, defeating its purpose
- The issue affects all nodes running the peer monitoring service (validators and fullnodes)
- Multiple malicious peers can amplify the attack impact

### Citations

**File:** peer-monitoring-service/types/src/response.rs (L32-41)
```rust
    pub fn get_num_bytes(&self) -> Result<u64, UnexpectedResponseError> {
        let serialized_bytes = bcs::to_bytes(&self).map_err(|error| {
            UnexpectedResponseError(format!(
                "Failed to serialize response: {}. Error: {:?}",
                self.get_label(),
                error
            ))
        })?;
        Ok(serialized_bytes.len() as u64)
    }
```

**File:** peer-monitoring-service/types/src/response.rs (L94-102)
```rust
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeInformationResponse {
    pub build_information: BTreeMap<String, String>, // The build information of the node
    pub highest_synced_epoch: u64,                   // The highest synced epoch of the node
    pub highest_synced_version: u64,                 // The highest synced version of the node
    pub ledger_timestamp_usecs: u64, // The latest timestamp of the blockchain (in microseconds)
    pub lowest_available_version: u64, // The lowest stored version of the node (in storage)
    pub uptime: Duration,            // The amount of time the peer has been running
}
```

**File:** peer-monitoring-service/server/src/lib.rs (L259-281)
```rust
    fn get_node_information(&self) -> Result<PeerMonitoringServiceResponse, Error> {
        // Get the node information
        let build_information = aptos_build_info::get_build_information();
        let current_time: Instant = self.time_service.now();
        let uptime = current_time.duration_since(self.start_time);
        let (highest_synced_epoch, highest_synced_version) =
            self.storage.get_highest_synced_epoch_and_version()?;
        let ledger_timestamp_usecs = self.storage.get_ledger_timestamp_usecs()?;
        let lowest_available_version = self.storage.get_lowest_available_version()?;

        // Create and return the response
        let node_information_response = NodeInformationResponse {
            build_information,
            highest_synced_epoch,
            highest_synced_version,
            ledger_timestamp_usecs,
            lowest_available_version,
            uptime,
        };
        Ok(PeerMonitoringServiceResponse::NodeInformation(
            node_information_response,
        ))
    }
```

**File:** crates/aptos-build-info/src/lib.rs (L88-104)
```rust
    if let Ok(git_sha) = std::env::var("GIT_SHA") {
        build_information.insert(BUILD_COMMIT_HASH.into(), git_sha);
    }

    if let Ok(git_branch) = std::env::var("GIT_BRANCH") {
        build_information.insert(BUILD_BRANCH.into(), git_branch);
    }

    if let Ok(git_tag) = std::env::var("GIT_TAG") {
        build_information.insert(BUILD_TAG.into(), git_tag);
    }

    if let Ok(build_date) = std::env::var("BUILD_DATE") {
        build_information.insert(BUILD_TIME.into(), build_date);
    }

    build_information
```

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** peer-monitoring-service/client/src/peer_states/peer_state.rs (L106-142)
```rust
            // Send the request to the peer and wait for a response
            let request_id = request_id_generator.next();
            let monitoring_service_response = network::send_request_to_peer(
                peer_monitoring_client,
                &peer_network_id,
                request_id,
                monitoring_service_request.clone(),
                request_timeout_ms,
            )
            .await;

            // Stop the timer and calculate the duration
            let request_duration_secs = start_time.elapsed().as_secs_f64();

            // Mark the in-flight request as now complete
            request_tracker.write().request_completed();

            // Process any response errors
            let monitoring_service_response = match monitoring_service_response {
                Ok(monitoring_service_response) => monitoring_service_response,
                Err(error) => {
                    peer_state_value
                        .write()
                        .handle_monitoring_service_response_error(&peer_network_id, error);
                    return;
                },
            };

            // Verify the response respects the message size limits
            if let Err(error) =
                sanity_check_response_size(max_num_response_bytes, &monitoring_service_response)
            {
                peer_state_value
                    .write()
                    .handle_monitoring_service_response_error(&peer_network_id, error);
                return;
            }
```

**File:** config/src/config/peer_monitoring_config.rs (L21-36)
```rust
impl Default for PeerMonitoringServiceConfig {
    fn default() -> Self {
        Self {
            enable_peer_monitoring_client: true,
            latency_monitoring: LatencyMonitoringConfig::default(),
            max_concurrent_requests: 1000,
            max_network_channel_size: 1000,
            max_num_response_bytes: 100 * 1024, // 100 KB
            max_request_jitter_ms: 1000,        // Monitoring requests are very infrequent
            metadata_update_interval_ms: 5000,  // 5 seconds
            network_monitoring: NetworkMonitoringConfig::default(),
            node_monitoring: NodeMonitoringConfig::default(),
            peer_monitor_interval_usec: 1_000_000, // 1 second
        }
    }
}
```

**File:** config/src/config/peer_monitoring_config.rs (L82-87)
```rust
    fn default() -> Self {
        Self {
            node_info_request_interval_ms: 15_000, // 15 seconds
            node_info_request_timeout_ms: 10_000,  // 10 seconds
        }
    }
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L260-262)
```rust
    fn bcs_decode<T: DeserializeOwned>(&self, bytes: &[u8], limit: usize) -> anyhow::Result<T> {
        bcs::from_bytes_with_limit(bytes, limit).map_err(|e| anyhow!("{:?}", e))
    }
```
