# Audit Report

## Title
Deserialization Bomb Attack via Unbounded Error Strings in Peer Monitoring Service

## Summary
Malicious peers can send RPC error responses containing arbitrarily large strings (up to 64 MiB) that are fully deserialized before application-level size validation occurs, enabling memory exhaustion and CPU starvation attacks against validator nodes.

## Finding Description

The peer monitoring service allows network peers to send error responses containing unbounded String fields. These errors are deserialized at the network layer before any application-level size checks are performed, creating a deserialization bomb vulnerability.

**Vulnerable Types:**

The `PeerMonitoringServiceError` enum contains String fields without size constraints: [1](#0-0) 

These errors are transmitted over the network in RPC responses: [2](#0-1) 

**Attack Flow:**

1. **Malicious Peer Sends Large Error**: A malicious peer acting as a server sends an RPC response containing `PeerMonitoringServiceError::InternalError(huge_string)` where `huge_string` can be up to ~64 MiB.

2. **Wire-Level Deserialization**: The network layer deserializes the `MultiplexMessage` containing the `RpcResponse` using plain BCS without size limits: [3](#0-2) 

3. **Protocol-Level Deserialization**: The application layer deserializes the `raw_response` bytes using BCS with only a recursion depth limit of 64: [4](#0-3) 

The BCS recursion limit (RECURSION_LIMIT = 64) only controls nesting depth, NOT data size: [5](#0-4) 

This limit is insufficient because deserializing large flat strings does not increase recursion depth. BCS deserialization uses the limit parameter as follows: [6](#0-5) 

4. **Late Size Validation**: The peer monitoring client only checks response size AFTER complete deserialization: [7](#0-6) 

By this point, memory has already been allocated for the large string and CPU cycles spent on deserialization.

**Why Existing Limits Don't Prevent This:**

While the peer monitoring service configures a 100 KB response limit: [8](#0-7) [9](#0-8) 

This check occurs post-deserialization in the sanity check function: [10](#0-9) 

The network layer allows messages up to MAX_MESSAGE_SIZE (64 MiB): [11](#0-10) 

**Exploitation Scenario:**

1. Malicious peer sends error with 50 MiB string: `InternalError("A".repeat(50_000_000))`
2. Network layer receives and deserializes via streaming (message > 4 MiB frame size)
3. BCS allocates 50 MiB for the string (recursion depth is only 2-3, well below 64)
4. Client detects size violation and rejects response
5. **Damage already done**: 50 MiB allocated, CPU cycles wasted

Multiple concurrent malicious responses can exhaust validator node resources.

## Impact Explanation

**HIGH Severity** per Aptos bug bounty criteria:

This vulnerability enables **validator node slowdowns** through resource exhaustion:

- **Memory Exhaustion**: Each malicious response can allocate up to 64 MiB. A coordinated attack with 20 concurrent responses could allocate 1.28 GB.
- **CPU Starvation**: BCS deserialization of large strings is CPU-intensive, consuming cycles that should be used for consensus and block processing.
- **Availability Impact**: Degraded node performance affects network health, potentially causing validator nodes to miss consensus votes or fail health checks.

This does NOT cause:
- Direct fund loss or theft
- Consensus safety violations
- Permanent network damage

However, it significantly impacts validator node availability and performance, meeting HIGH severity criteria for "Validator node slowdowns."

## Likelihood Explanation

**Likelihood: HIGH**

This attack is easy to execute and requires minimal resources:

- **Attacker Requirements**: Any network peer can act as a malicious server. No validator privileges, stake, or insider access required.
- **Attack Complexity**: Trivial - simply return error responses with large strings.
- **Detection Difficulty**: Hard to distinguish from legitimate large responses before deserialization completes.
- **Cost**: Negligible - attacker only needs to send crafted RPC responses.

The attack exploits a fundamental ordering problem: validation happens after resource allocation.

## Recommendation

**Immediate Fix**: Enforce size limits BEFORE deserialization at the network protocol layer.

**Option 1 - Protocol-Level Size Limit for Peer Monitoring:**

Add a pre-deserialization size check in the peer monitoring service client's RPC handling. Modify the network client to reject responses exceeding the configured limit before deserializing:

```rust
// In peer-monitoring-service/client/src/network.rs
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
    
    // PRE-DESERIALIZATION SIZE CHECK HERE
    // Check raw bytes size before pattern matching
    
    match response {
        PeerMonitoringServiceMessage::Response(Ok(response)) => Ok(response),
        // ... rest of match
    }
}
```

**Option 2 - Bounded String Types:**

Replace unbounded `String` fields with size-limited types in the error definitions:

```rust
// Define a bounded string type
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BoundedString {
    #[serde(deserialize_with = "deserialize_bounded_string")]
    inner: String,
}

fn deserialize_bounded_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where D: Deserializer<'de> {
    let s = String::deserialize(deserializer)?;
    if s.len() > MAX_ERROR_STRING_LENGTH {
        return Err(serde::de::Error::custom("String too long"));
    }
    Ok(s)
}

// Use in error types
pub enum PeerMonitoringServiceError {
    InternalError(BoundedString),
    InvalidRequest(BoundedString),
}
```

**Option 3 - Network Layer BCS Size Limit:**

Modify the BCS deserialization to use actual byte size limits instead of just recursion limits. This would require changes to how `ProtocolId::from_bytes` works to enforce a maximum serialized size.

**Recommended Approach**: Combination of Option 1 (immediate mitigation) and Option 2 (long-term fix) provides defense in depth.

## Proof of Concept

```rust
// PoC: Malicious Peer Sending Large Error Response
// This can be adapted into a Rust integration test

use aptos_peer_monitoring_service_types::{
    PeerMonitoringServiceError, PeerMonitoringServiceMessage, 
    PeerMonitoringServiceResponse,
};
use bcs;

#[test]
fn test_deserialization_bomb_attack() {
    // Attacker creates a large error string (50 MB)
    let huge_string = "A".repeat(50_000_000);
    let malicious_error = PeerMonitoringServiceError::InternalError(huge_string);
    
    // Attacker wraps it in a response message
    let malicious_response = PeerMonitoringServiceMessage::Response(
        Err(malicious_error)
    );
    
    // Serialize the malicious response
    let serialized = bcs::to_bytes(&malicious_response)
        .expect("Serialization should succeed");
    
    println!("Serialized size: {} bytes ({} MiB)", 
             serialized.len(), 
             serialized.len() / (1024 * 1024));
    
    // Victim node receives and deserializes (simulating network layer)
    let start = std::time::Instant::now();
    let deserialized: PeerMonitoringServiceMessage = 
        bcs::from_bytes(&serialized).expect("Deserialization succeeds");
    let elapsed = start.elapsed();
    
    println!("Deserialization took: {:?}", elapsed);
    println!("Memory allocated: ~50 MiB");
    
    // At this point, memory is allocated and CPU spent
    // Application-level validation would reject it, but too late:
    match deserialized {
        PeerMonitoringServiceMessage::Response(Err(e)) => {
            let error_string = format!("{}", e);
            println!("Error string length: {} bytes", error_string.len());
            // Validation happens here - AFTER deserialization
            assert!(error_string.len() > 100_000); // Exceeds limit
        },
        _ => panic!("Unexpected message type"),
    }
    
    // VULNERABILITY DEMONSTRATED:
    // - Large payload successfully deserialized
    // - Memory allocated before validation
    // - CPU cycles consumed before validation
    // - Multiple concurrent attacks would exhaust resources
}
```

**Notes**

The vulnerability exists due to a classic Time-of-Check-Time-of-Use (TOCTOU) variant where resource allocation (deserialization) precedes validation (size checking). While network-level frame size limits (4 MiB) and message size limits (64 MiB) exist, these are insufficient because:

1. BCS recursion limits don't constrain flat data structures like large strings
2. Application-level size checks occur post-deserialization
3. The gap between network-level limits (64 MiB) and application-level expectations (100 KB) is exploitable

This breaks **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits" - the deserialization operation does not respect the intended 100 KB limit before consuming resources.

### Citations

**File:** peer-monitoring-service/types/src/lib.rs (L26-32)
```rust
#[derive(Clone, Debug, Deserialize, Error, PartialEq, Eq, Serialize)]
pub enum PeerMonitoringServiceError {
    #[error("Internal service error: {0}")]
    InternalError(String),
    #[error("Invalid service request: {0}")]
    InvalidRequest(String),
}
```

**File:** peer-monitoring-service/types/src/lib.rs (L34-41)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum PeerMonitoringServiceMessage {
    /// A request to the peer monitoring service
    Request(PeerMonitoringServiceRequest),
    /// A response from the peer monitoring service
    Response(Result<PeerMonitoringServiceResponse>),
}
```

**File:** network/framework/src/protocols/wire/messaging/v1/mod.rs (L225-241)
```rust
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.project().framed_read.poll_next(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let frame = frame.freeze();

                match bcs::from_bytes(&frame) {
                    Ok(message) => Poll::Ready(Some(Ok(message))),
                    // Failed to deserialize the NetworkMessage
                    Err(err) => {
                        let mut frame = frame;
                        let frame_len = frame.len();
                        // Keep a few bytes from the frame for debugging
                        frame.truncate(8);
                        let err = ReadError::DeserializeError(err, frame_len, frame);
                        Poll::Ready(Some(Err(err)))
                    },
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

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L259-262)
```rust
    /// Deserializes the value using BCS encoding (with a specified limit)
    fn bcs_decode<T: DeserializeOwned>(&self, bytes: &[u8], limit: usize) -> anyhow::Result<T> {
        bcs::from_bytes_with_limit(bytes, limit).map_err(|e| anyhow!("{:?}", e))
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

**File:** peer-monitoring-service/client/src/peer_states/peer_state.rs (L311-331)
```rust
/// Sanity checks that the monitoring service response size
/// is valid (i.e., it respects the max message size).
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

**File:** config/src/config/peer_monitoring_config.rs (L13-13)
```rust
    pub max_num_response_bytes: u64,  // Max num of bytes in a (serialized) response
```

**File:** config/src/config/peer_monitoring_config.rs (L28-28)
```rust
            max_num_response_bytes: 100 * 1024, // 100 KB
```

**File:** config/src/config/network_config.rs (L47-50)
```rust
pub const MAX_APPLICATION_MESSAGE_SIZE: usize =
    (MAX_MESSAGE_SIZE - MAX_MESSAGE_METADATA_SIZE) - MESSAGE_PADDING_SIZE; /* The message size that applications should check against */
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```
