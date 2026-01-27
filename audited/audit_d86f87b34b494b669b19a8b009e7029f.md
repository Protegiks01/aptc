# Audit Report

## Title
Pre-Deserialization Size Check Bypass Allows Memory Exhaustion via Malicious NetworkInformationResponse

## Summary
A malicious peer can send a `NetworkInformationResponse` with an extremely large `BTreeMap` of `connected_peers` (up to 64 MiB when serialized) that bypasses the intended 100 KB application-level size limit. The size validation occurs AFTER full BCS deserialization and memory allocation, allowing attackers to cause memory exhaustion, heap fragmentation, and node slowdowns.

## Finding Description
The peer monitoring service implements a size limit (`max_num_response_bytes`, default 100 KB) to protect against oversized responses. However, this check is performed AFTER the response has been fully deserialized into memory, creating a time-of-check-time-of-use vulnerability.

**Attack Flow:**

1. **Malicious Response Creation**: A malicious peer constructs a `NetworkInformationResponse` with hundreds of thousands of entries in the `connected_peers` BTreeMap, serialized to ~60 MiB (under the 64 MiB network limit). [1](#0-0) 

2. **Network Layer Acceptance**: The network layer accepts the message because it's within `MAX_MESSAGE_SIZE` (64 MiB). [2](#0-1) 

3. **RPC Layer Forwarding**: The response bytes are forwarded to the application layer as opaque `Bytes`. [3](#0-2) 

4. **Premature Deserialization**: The application deserializes the entire response using BCS, allocating the full BTreeMap in memory. [4](#0-3) 

5. **Delayed Size Check**: Only AFTER deserialization does the peer monitoring client check the response size by re-serializing it. [5](#0-4) [6](#0-5) 

The `sanity_check_response_size` function calculates size by calling `get_num_bytes()`, which re-serializes the already-deserialized response: [7](#0-6) 

**Invariant Violation**: This breaks the "Resource Limits" invariant that "all operations must respect gas, storage, and computational limits." The size limit is ineffective because resource consumption occurs before validation.

## Impact Explanation
This qualifies as **High Severity** under Aptos Bug Bounty criteria ("Validator node slowdowns"):

1. **Memory Exhaustion**: With 100 connected peers, an attacker can trigger 100 concurrent deserializations of 60 MiB responses = 6 GB of memory consumption before rejection.

2. **CPU Exhaustion**: BCS deserialization of large nested structures is CPU-intensive, consuming cycles in blocking tasks.

3. **Heap Fragmentation**: Repeated allocation and deallocation of multi-megabyte BTreeMaps causes heap fragmentation, degrading performance over time.

4. **Node Slowdown**: Memory pressure can trigger swapping, and blocking task saturation can delay critical operations.

The peer monitoring config shows only basic concurrency limits that don't prevent this attack: [8](#0-7) 

## Likelihood Explanation
**High Likelihood**:
- Any connected peer can exploit this (no special privileges required)
- The attack requires only standard network connectivity
- Peer monitoring requests occur automatically and periodically
- No authentication or rate limiting prevents malicious responses
- Multiple malicious peers can amplify the impact

The BCS encoding allows efficient serialization of large maps, making it feasible to fit hundreds of thousands of entries within the 64 MiB network limit. [9](#0-8) [10](#0-9) 

The recursion limit (64) only protects against deeply nested structures, not large flat collections like BTreeMaps.

## Recommendation
Implement size validation BEFORE deserialization by checking the serialized byte length:

```rust
// In peer_states/peer_state.rs, modify the request task:
let monitoring_service_response = match monitoring_service_response {
    Ok(monitoring_service_response) => monitoring_service_response,
    Err(error) => {
        peer_state_value
            .write()
            .handle_monitoring_service_response_error(&peer_network_id, error);
        return;
    },
};

// NEW: Check serialized size BEFORE processing
if let Err(error) = sanity_check_response_size(max_num_response_bytes, &monitoring_service_response) {
    peer_state_value
        .write()
        .handle_monitoring_service_response_error(&peer_network_id, error);
    return;
}
```

However, this still requires deserialization first. A better solution is to check the raw bytes length at the RPC layer before deserialization:

```rust
// In network/framework/src/protocols/network/mod.rs, modify send_rpc_raw:
pub async fn send_rpc_raw(
    &self,
    recipient: PeerId,
    protocol: ProtocolId,
    req_msg: Bytes,
    timeout: Duration,
    max_response_size: Option<usize>,  // NEW parameter
) -> Result<TMessage, RpcError> {
    let res_data = self
        .peer_mgr_reqs_tx
        .send_rpc(recipient, protocol, req_msg, timeout)
        .await?;

    // NEW: Check size before deserialization
    if let Some(max_size) = max_response_size {
        if res_data.len() > max_size {
            return Err(RpcError::Error(anyhow!(
                "Response size {} exceeds limit {}", 
                res_data.len(), 
                max_size
            )));
        }
    }

    let res_msg = tokio::task::spawn_blocking(move || protocol.from_bytes(&res_data)).await??;
    Ok(res_msg)
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_oversized_network_info_response_memory_exhaustion() {
    use aptos_peer_monitoring_service_types::response::{
        ConnectionMetadata, NetworkInformationResponse, PeerMonitoringServiceResponse
    };
    use aptos_config::{config::PeerRole, network_id::{NetworkId, PeerNetworkId}};
    use aptos_types::{network_address::NetworkAddress, PeerId};
    use std::collections::BTreeMap;
    use std::str::FromStr;

    // Create a malicious response with 500,000 entries (~50+ MB serialized)
    let mut connected_peers = BTreeMap::new();
    for i in 0..500_000 {
        let peer_id = PeerId::random();
        let peer_network_id = PeerNetworkId::new(NetworkId::Public, peer_id);
        let metadata = ConnectionMetadata::new(
            NetworkAddress::from_str("/ip4/127.0.0.1/tcp/8080").unwrap(),
            peer_id,
            PeerRole::Unknown,
        );
        connected_peers.insert(peer_network_id, metadata);
    }

    let malicious_response = PeerMonitoringServiceResponse::NetworkInformation(
        NetworkInformationResponse {
            connected_peers,
            distance_from_validators: 1,
        }
    );

    // Verify it serializes under network limit but over application limit
    let serialized = bcs::to_bytes(&malicious_response).unwrap();
    println!("Serialized size: {} bytes", serialized.len());
    assert!(serialized.len() < 64 * 1024 * 1024, "Under network limit");
    
    // This would bypass the size check because deserialization happens first
    let _deserialized: PeerMonitoringServiceResponse = bcs::from_bytes(&serialized).unwrap();
    
    // The size check happens too late - memory already consumed
    let size_check = malicious_response.get_num_bytes().unwrap();
    println!("Size check result: {} bytes", size_check);
    assert!(size_check > 100 * 1024, "Exceeds application limit");
    
    // In production, this memory would be allocated before rejection
}
```

This demonstrates that a malicious response can be constructed that passes network-level validation but causes excessive memory allocation before application-level rejection.

### Citations

**File:** peer-monitoring-service/types/src/response.rs (L31-41)
```rust
    /// Returns the number of bytes in the serialized response
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

**File:** peer-monitoring-service/types/src/response.rs (L50-55)
```rust
/// A response for the network information request
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>, // Connected peers
    pub distance_from_validators: u64, // The distance of the peer from the validator set
}
```

**File:** config/src/config/network_config.rs (L47-50)
```rust
pub const MAX_APPLICATION_MESSAGE_SIZE: usize =
    (MAX_MESSAGE_SIZE - MAX_MESSAGE_METADATA_SIZE) - MESSAGE_PADDING_SIZE; /* The message size that applications should check against */
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** network/framework/src/protocols/rpc/mod.rs (L688-700)
```rust
    pub fn handle_inbound_response(&mut self, response: RpcResponse) {
        let network_context = &self.network_context;
        let peer_id = &self.remote_peer_id;
        let request_id = response.request_id;

        let is_canceled = if let Some((protocol_id, response_tx)) =
            self.pending_outbound_rpcs.remove(&request_id)
        {
            self.update_inbound_rpc_response_metrics(
                protocol_id,
                response.raw_response.len() as u64,
            );
            response_tx.send(response).is_err()
```

**File:** network/framework/src/protocols/network/mod.rs (L462-471)
```rust
        // Send the request and wait for the response
        let res_data = self
            .peer_mgr_reqs_tx
            .send_rpc(recipient, protocol, req_msg, timeout)
            .await?;

        // Deserialize the response using a blocking task
        let res_msg = tokio::task::spawn_blocking(move || protocol.from_bytes(&res_data)).await??;
        Ok(res_msg)
    }
```

**File:** peer-monitoring-service/client/src/peer_states/peer_state.rs (L134-142)
```rust
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

**File:** config/src/config/peer_monitoring_config.rs (L21-35)
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
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L38-39)
```rust
pub const USER_INPUT_RECURSION_LIMIT: usize = 32;
pub const RECURSION_LIMIT: usize = 64;
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L156-172)
```rust
    fn encoding(self) -> Encoding {
        match self {
            ProtocolId::ConsensusDirectSendJson | ProtocolId::ConsensusRpcJson => Encoding::Json,
            ProtocolId::ConsensusDirectSendCompressed | ProtocolId::ConsensusRpcCompressed => {
                Encoding::CompressedBcs(RECURSION_LIMIT)
            },
            ProtocolId::ConsensusObserver => Encoding::CompressedBcs(RECURSION_LIMIT),
            ProtocolId::DKGDirectSendCompressed | ProtocolId::DKGRpcCompressed => {
                Encoding::CompressedBcs(RECURSION_LIMIT)
            },
            ProtocolId::JWKConsensusDirectSendCompressed
            | ProtocolId::JWKConsensusRpcCompressed => Encoding::CompressedBcs(RECURSION_LIMIT),
            ProtocolId::MempoolDirectSend => Encoding::CompressedBcs(USER_INPUT_RECURSION_LIMIT),
            ProtocolId::MempoolRpc => Encoding::Bcs(USER_INPUT_RECURSION_LIMIT),
            _ => Encoding::Bcs(RECURSION_LIMIT),
        }
    }
```
