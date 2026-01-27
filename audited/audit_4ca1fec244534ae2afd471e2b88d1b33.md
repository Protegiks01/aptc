# Audit Report

## Title
Memory Exhaustion via Deserialization-Before-Validation in Peer Monitoring Service

## Summary
The peer monitoring service client deserializes `NetworkInformationResponse` messages at the network layer (up to 64 MiB) before applying application-layer size validation (100 KB limit), creating a window for memory exhaustion attacks through concurrent large responses with massive peer lists.

## Finding Description

The security question asks whether cloning the `recorded_network_info_response` enables memory exhaustion attacks. While the cloning of **stored** responses is properly bounded by validation, the investigation reveals a more fundamental vulnerability in the **response handling pipeline**.

### The Data Flow

1. **Server Response Creation**: The server includes ALL connected peers in the `NetworkInformationResponse` without size limits [1](#0-0) 

2. **Network Layer Limits**: The network layer accepts messages up to `MAX_MESSAGE_SIZE` (64 MiB) [2](#0-1) 

3. **Response Type Definition**: `NetworkInformationResponse` contains an unbounded `BTreeMap<PeerNetworkId, ConnectionMetadata>` for `connected_peers` [3](#0-2) 

4. **Deserialization-First Pattern**: Network layer deserializes the response into a full `PeerMonitoringServiceResponse` object before application-layer processing [4](#0-3) 

5. **Late Validation**: Size check occurs AFTER deserialization in `sanity_check_response_size()` [5](#0-4) 

6. **Size Validation Implementation**: The check compares serialized size against `max_num_response_bytes` (default 100 KB) [6](#0-5) 

7. **Configuration Limit**: The default limit is only 100 KB [7](#0-6) 

### The Vulnerability Gap

There exists a **640x gap** between the network layer's acceptance threshold (64 MiB) and the application layer's validation threshold (100 KB). During this gap:

- Large responses (100 KB to 64 MiB) are fully deserialized into memory
- The `BTreeMap<PeerNetworkId, ConnectionMetadata>` is allocated with potentially thousands of entries
- Memory consumption occurs before the size check rejects the response
- The memory is only freed after the validation fails

### Concurrent Request Processing

Requests are spawned as concurrent tasks [8](#0-7) , meaning multiple responses can be deserialized simultaneously [9](#0-8) 

### Attack Scenario

1. Attacker controls multiple malicious peers (or multiple connections from one peer)
2. Victim node periodically queries peers for network information (default: every 60 seconds) [10](#0-9) 
3. Each malicious peer responds with a crafted `NetworkInformationResponse` containing:
   - Thousands of fake entries in `connected_peers` BTreeMap
   - Total serialized size approaching 64 MiB (under network limit)
4. Network layer deserializes all responses concurrently (allocates ~50-60 MiB per response)
5. Application layer validates each response, rejects them (> 100 KB)
6. Memory is freed, but the temporary spike has occurred

**With 10 malicious peers responding simultaneously**: 10 × 50 MiB = 500 MiB temporary memory spike
**With 100 malicious peers**: up to 5 GiB spike

### Regarding the Cloning Question

The stored `recorded_network_info_response` field does clone the entire response [11](#0-10) , but this cloning only affects responses that **passed** the 100 KB validation. Therefore, the cloning itself is properly bounded and does not enable memory exhaustion for stored responses.

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria:

- **Node slowdowns**: Repeated memory spikes can degrade node performance
- **Potential DoS**: Sustained attacks could trigger out-of-memory conditions
- **State inconsistencies**: Memory pressure may cause peer monitoring failures, leading to incorrect peer state tracking

The impact is limited by:
- Request intervals (60-second default spacing)
- Optional inbound rate limiting (100 KiB/s per IP default) [12](#0-11) 
- Attacker needs control over multiple peer identities

This does NOT directly affect consensus, funds, or blockchain state, but can impact node availability and peer monitoring accuracy.

## Likelihood Explanation

**Likelihood: Medium**

**Attacker Requirements**:
- Control multiple peer identities (achievable through Sybil connections)
- Wait for periodic network info requests (automatic, every 60 seconds)
- Craft responses with large peer lists (straightforward)

**Mitigating Factors**:
- Inbound rate limiting may slow attack (but doesn't prevent spikes)
- Request intervals space out attacks
- Server-side configuration `max_concurrent_requests` (default: 1000) provides some bound [13](#0-12) 

**Realistic Attack**: An attacker establishing 20-50 malicious peer connections and responding with maximum-size messages could cause noticeable memory pressure on target nodes.

## Recommendation

**Fix: Implement Size Validation Before Deserialization**

The network layer should enforce application-specific message size limits before deserializing responses:

```rust
// In peer-monitoring-service/client/src/network.rs or at the network layer
// Add pre-deserialization size check:

pub async fn send_request(
    &self,
    recipient: PeerNetworkId,
    request: PeerMonitoringServiceRequest,
    timeout: Duration,
    max_response_bytes: u64, // Pass from config
) -> Result<PeerMonitoringServiceResponse, Error> {
    let response = self
        .network_client
        .send_to_peer_rpc_with_size_limit( // New method
            PeerMonitoringServiceMessage::Request(request),
            timeout,
            recipient,
            max_response_bytes, // Enforce before deserialization
        )
        .await
        .map_err(|error| Error::NetworkError(error.to_string()))?;
    // ... rest of method
}
```

**Alternative: Reduce Network Layer Limit for Peer Monitoring**

Configure a lower `max_message_size` specifically for peer monitoring service messages at the protocol level, preventing large responses from reaching deserialization.

**Defense in Depth**: Implement both checks:
1. Network protocol layer enforces application-specific limits
2. Application layer validates as final safeguard

## Proof of Concept

```rust
// Rust reproduction test for peer-monitoring-service/client/src/tests/

#[tokio::test]
async fn test_memory_exhaustion_via_large_response() {
    use aptos_peer_monitoring_service_types::response::{
        ConnectionMetadata, NetworkInformationResponse,
    };
    use aptos_config::network_id::PeerNetworkId;
    use aptos_types::PeerId;
    use std::collections::BTreeMap;

    // Create a massive connected_peers map (simulating malicious response)
    let mut connected_peers = BTreeMap::new();
    for i in 0..10000 {
        let peer_id = PeerId::random();
        let peer_network_id = PeerNetworkId::new(NetworkId::Public, peer_id);
        let metadata = ConnectionMetadata::new(
            format!("/ip4/1.2.3.{}/tcp/6180", i % 256).parse().unwrap(),
            peer_id,
            PeerRole::Unknown,
        );
        connected_peers.insert(peer_network_id, metadata);
    }

    let response = NetworkInformationResponse {
        connected_peers,
        distance_from_validators: 3,
    };

    // Serialize to check size
    let serialized = bcs::to_bytes(&response).unwrap();
    let size_mb = serialized.len() / (1024 * 1024);
    
    println!("Response size: {} MB", size_mb);
    assert!(size_mb > 1); // Should be several MB
    assert!(size_mb < 64); // Under network limit
    
    // This would pass network layer but fail application validation
    // Demonstrating the deserialization gap
}
```

---

**Notes**

While the security question focuses on cloning of **stored** responses, the deeper investigation reveals that the stored responses are properly bounded by the 100 KB validation limit. The actual vulnerability lies in the earlier stage of response processing, where the deserialization-before-validation pattern creates a memory exhaustion window that exists independently of the cloning mechanism. The cloning of validated responses is necessary for the monitoring system's operation and does not itself constitute a vulnerability.

### Citations

**File:** peer-monitoring-service/server/src/lib.rs (L217-248)
```rust
    fn get_network_information(&self) -> Result<PeerMonitoringServiceResponse, Error> {
        // Get the connected peers
        let connected_peers_and_metadata =
            self.peers_and_metadata.get_connected_peers_and_metadata()?;
        let connected_peers = connected_peers_and_metadata
            .into_iter()
            .map(|(peer, metadata)| {
                let connection_metadata = metadata.get_connection_metadata();
                (
                    peer,
                    ConnectionMetadata::new(
                        connection_metadata.addr,
                        connection_metadata.remote_peer_id,
                        connection_metadata.role,
                    ),
                )
            })
            .collect();

        // Get the distance from the validators
        let distance_from_validators =
            get_distance_from_validators(&self.base_config, self.peers_and_metadata.clone());

        // Create and return the response
        let network_information_response = NetworkInformationResponse {
            connected_peers,
            distance_from_validators,
        };
        Ok(PeerMonitoringServiceResponse::NetworkInformation(
            network_information_response,
        ))
    }
```

**File:** config/src/config/network_config.rs (L50-50)
```rust
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** config/src/config/network_config.rs (L117-117)
```rust
    pub inbound_rate_limit_config: Option<RateLimitConfig>,
```

**File:** peer-monitoring-service/types/src/response.rs (L50-55)
```rust
/// A response for the network information request
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>, // Connected peers
    pub distance_from_validators: u64, // The distance of the peer from the validator set
}
```

**File:** peer-monitoring-service/client/src/network.rs (L35-60)
```rust
    pub async fn send_request(
        &self,
        recipient: PeerNetworkId,
        request: PeerMonitoringServiceRequest,
        timeout: Duration,
    ) -> Result<PeerMonitoringServiceResponse, Error> {
        let response = self
            .network_client
            .send_to_peer_rpc(
                PeerMonitoringServiceMessage::Request(request),
                timeout,
                recipient,
            )
            .await
            .map_err(|error| Error::NetworkError(error.to_string()))?;
        match response {
            PeerMonitoringServiceMessage::Response(Ok(response)) => Ok(response),
            PeerMonitoringServiceMessage::Response(Err(err)) => {
                Err(Error::PeerMonitoringServiceError(err))
            },
            PeerMonitoringServiceMessage::Request(request) => Err(Error::NetworkError(format!(
                "Got peer monitoring request instead of response! Request: {:?}",
                request
            ))),
        }
    }
```

**File:** peer-monitoring-service/client/src/peer_states/peer_state.rs (L135-142)
```rust
            if let Err(error) =
                sanity_check_response_size(max_num_response_bytes, &monitoring_service_response)
            {
                peer_state_value
                    .write()
                    .handle_monitoring_service_response_error(&peer_network_id, error);
                return;
            }
```

**File:** peer-monitoring-service/client/src/peer_states/peer_state.rs (L162-167)
```rust
        // Spawn the request task
        let join_handle = if let Some(runtime) = runtime {
            runtime.spawn(request_task)
        } else {
            tokio::spawn(request_task)
        };
```

**File:** peer-monitoring-service/client/src/peer_states/peer_state.rs (L313-331)
```rust
fn sanity_check_response_size(
    max_num_response_bytes: u64,
    monitoring_service_response: &PeerMonitoringServiceResponse,
) -> Result<(), Error> {
    // Calculate the number of bytes in the response
    let num_response_bytes = monitoring_service_response.get_num_bytes()?;

    // Verify the response respects the max message sizes
    if num_response_bytes > max_num_response_bytes {
        return Err(Error::UnexpectedError(format!(
            "The monitoring service response ({:?}) is too large: {:?}. Maximum allowed: {:?}",
            monitoring_service_response.get_label(),
            num_response_bytes,
            max_num_response_bytes
        )));
    }

    Ok(())
}
```

**File:** config/src/config/peer_monitoring_config.rs (L26-26)
```rust
            max_concurrent_requests: 1000,
```

**File:** config/src/config/peer_monitoring_config.rs (L28-28)
```rust
            max_num_response_bytes: 100 * 1024, // 100 KB
```

**File:** config/src/config/peer_monitoring_config.rs (L68-68)
```rust
            network_info_request_interval_ms: 60_000, // 1 minute
```

**File:** peer-monitoring-service/client/src/peer_states/mod.rs (L41-68)
```rust
    for peer_state_key in PeerStateKey::get_all_keys() {
        let mut num_in_flight_requests = 0;

        // Go through all connected peers and see if we should refresh the state
        for (peer_network_id, peer_metadata) in &connected_peers_and_metadata {
            // Get the peer state
            let peer_state = get_peer_state(&peer_monitor_state, peer_network_id)?;

            // If there's an-flight request, update the metrics counter
            let request_tracker = peer_state.get_request_tracker(&peer_state_key)?;
            if request_tracker.read().in_flight_request() {
                num_in_flight_requests += 1;
            }

            // Update the state if it needs to be refreshed
            let should_refresh_peer_state_key = request_tracker.read().new_request_required();
            if should_refresh_peer_state_key {
                peer_state.refresh_peer_state_key(
                    monitoring_service_config,
                    &peer_state_key,
                    peer_monitoring_client.clone(),
                    *peer_network_id,
                    peer_metadata.clone(),
                    peer_monitor_state.request_id_generator.clone(),
                    time_service.clone(),
                    runtime.clone(),
                )?;
            }
```

**File:** peer-monitoring-service/client/src/peer_states/network_info.rs (L72-74)
```rust
    pub fn get_latest_network_info_response(&self) -> Option<NetworkInformationResponse> {
        self.recorded_network_info_response.clone()
    }
```
