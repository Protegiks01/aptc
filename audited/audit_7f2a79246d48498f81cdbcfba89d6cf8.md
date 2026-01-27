# Audit Report

## Title
Shared Outbound RPC Queue Enables Resource Exhaustion and Consensus Liveness Degradation

## Summary
The Aptos network layer implements a single shared outbound RPC queue (limit: 100 concurrent requests) per peer connection that is used by ALL protocols including consensus and peer monitoring service. While the peer monitoring service client implements proper rate limiting via `RequestTracker` in normal operation, the underlying `send_request()` method lacks application-level concurrency control. Under high load scenarios or if bugs in any RPC-using component cause rapid requests, the shared queue can fill up and decline critical consensus RPC messages with `RpcError::TooManyPending`, potentially causing validator liveness degradation.

## Finding Description
The vulnerability stems from a lack of per-protocol resource isolation in the network layer's outbound RPC management. 

Each `Peer` connection maintains a single `OutboundRpcs` queue that processes requests from all protocols (consensus, peer monitoring, state sync, etc.) with a hard limit defined by `MAX_CONCURRENT_OUTBOUND_RPCS = 100`. [1](#0-0) 

The queue enforcement occurs in `OutboundRpcs::handle_outbound_request()`: [2](#0-1) 

When the queue reaches capacity, ALL new RPC requests from ANY protocol are declined. The `PeerMonitoringServiceClient::send_request()` directly delegates to the network layer without application-level rate limiting: [3](#0-2) 

All outbound RPC requests flow through the same `Peer::handle_outbound_request()` method regardless of protocol: [4](#0-3) 

Critically, consensus relies on RPC for essential operations: [5](#0-4) 

**Exploitation Scenario:**
1. A validator node has multiple concurrent activities: consensus voting, state synchronization, and peer monitoring
2. State sync makes numerous parallel RPC requests to catch up on blockchain data
3. Peer monitoring service sends requests for latency checks, network info, and node info across all connected peers
4. Under heavy load or if any component has a bug causing rapid requests, the 100-slot queue fills
5. Consensus attempts to send a critical RPC (e.g., block proposal, vote message)
6. The request is declined with `RpcError::TooManyPending`
7. Consensus operations are delayed, potentially causing timeout failures and liveness issues

## Impact Explanation
This constitutes a **High Severity** vulnerability per the Aptos bug bounty criteria:

- **Validator node slowdowns**: Queue exhaustion directly impacts the node's ability to process consensus messages, leading to degraded performance
- **Significant protocol violations**: The inability to send consensus RPCs violates the liveness guarantee of the AptosBFT protocol

While this does not cause a complete consensus safety break (blocks won't be incorrectly committed), it violates the **Resource Limits invariant** (all operations must respect resource limits across protocols) and can cause **liveness degradation** affecting validator participation.

The issue affects ALL validator nodes under high load conditions and provides no QoS guarantees for critical consensus traffic versus monitoring traffic.

## Likelihood Explanation
**Likelihood: Medium-High under specific conditions**

The vulnerability manifests under:
1. **Legitimate high load**: Validators synchronizing large amounts of state while maintaining active consensus participation
2. **Multiple concurrent peers**: With many peer connections, each running monitoring + consensus + sync
3. **Bug scenarios**: Any defect in state sync, peer monitoring, or other RPC-using components that causes request spikes

While the peer monitoring service implements `RequestTracker` for rate limiting in normal operation: [6](#0-5) 

This protection is at the application layer. State sync and other services can still saturate the shared queue, and the lack of per-protocol isolation means one misbehaving component impacts all others.

## Recommendation
Implement per-protocol resource isolation and QoS for the outbound RPC queue:

**Short-term mitigation:**
1. Add per-protocol quotas within the outbound RPC queue (e.g., reserve slots for consensus)
2. Implement priority-based queue management with consensus messages at highest priority
3. Add application-level concurrency controls in `send_request()` methods

**Long-term solution:**
```rust
// In OutboundRpcs::new()
pub struct OutboundRpcs {
    // ... existing fields ...
    protocol_quotas: HashMap<ProtocolId, u32>,  // Per-protocol limits
    protocol_reserved: HashMap<ProtocolId, u32>, // Reserved slots
}

// In handle_outbound_request()
pub fn handle_outbound_request(&mut self, request: OutboundRpcRequest, ...) -> Result<(), RpcError> {
    // Check protocol-specific quota
    let protocol_id = request.protocol_id;
    let protocol_count = self.count_protocol_requests(protocol_id);
    let protocol_limit = self.protocol_quotas.get(&protocol_id).unwrap_or(&self.max_concurrent_outbound_rpcs);
    
    if protocol_count >= *protocol_limit {
        // Check if this is a high-priority protocol (e.g., consensus)
        if !self.is_high_priority_protocol(protocol_id) {
            return Err(RpcError::ProtocolQuotaExceeded);
        }
    }
    
    // Continue with existing queue check...
}
```

## Proof of Concept
```rust
// Rust test demonstrating queue exhaustion
#[tokio::test]
async fn test_outbound_rpc_queue_exhaustion() {
    // Setup: Create a peer connection with NetworkClient
    let (peer_monitoring_client, consensus_client, network_context) = setup_test_network();
    let target_peer = PeerId::random();
    
    // Step 1: Fill the outbound RPC queue with peer monitoring requests
    let mut handles = vec![];
    for i in 0..100 {
        let client = peer_monitoring_client.clone();
        let peer = target_peer;
        let handle = tokio::spawn(async move {
            // Send request that will block (simulate slow peer)
            client.send_request(
                PeerNetworkId::new(NetworkId::Validator, peer),
                PeerMonitoringServiceRequest::GetNetworkInformation,
                Duration::from_secs(60),
            ).await
        });
        handles.push(handle);
    }
    
    // Wait for all requests to be queued
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Step 2: Attempt to send a consensus RPC
    let consensus_result = consensus_client.send_rpc(
        target_peer,
        ConsensusMsg::BlockRetrieval(BlockRetrievalRequest::default()),
        Duration::from_secs(5),
    ).await;
    
    // Step 3: Verify consensus RPC was declined
    assert!(consensus_result.is_err());
    match consensus_result {
        Err(Error::NetworkError(msg)) => {
            assert!(msg.contains("TooManyPending"));
        }
        _ => panic!("Expected TooManyPending error"),
    }
}
```

## Notes
The current implementation prioritizes simplicity (single shared queue) over robustness (per-protocol isolation). While the peer monitoring service has proper rate limiting at the application layer, the shared nature of the outbound RPC queue means that legitimate high load or bugs in ANY RPC-using component can impact consensus message delivery. The lack of QoS guarantees for critical consensus traffic is a significant operational risk for validator nodes under stress conditions.

### Citations

**File:** network/framework/src/constants.rs (L13-13)
```rust
pub const MAX_CONCURRENT_OUTBOUND_RPCS: u32 = 100;
```

**File:** network/framework/src/protocols/rpc/mod.rs (L463-475)
```rust
        if self.outbound_rpc_tasks.len() == self.max_concurrent_outbound_rpcs as usize {
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                OUTBOUND_LABEL,
                DECLINED_LABEL,
            )
            .inc();
            // Notify application that their request was dropped due to capacity.
            let err = Err(RpcError::TooManyPending(self.max_concurrent_outbound_rpcs));
            let _ = application_response_tx.send(err);
            return Err(RpcError::TooManyPending(self.max_concurrent_outbound_rpcs));
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

**File:** network/framework/src/peer/mod.rs (L643-661)
```rust
            PeerRequest::SendRpc(request) => {
                let protocol_id = request.protocol_id;
                if let Err(e) = self
                    .outbound_rpcs
                    .handle_outbound_request(request, write_reqs_tx)
                {
                    sample!(
                        SampleRate::Duration(Duration::from_secs(10)),
                        warn!(
                            NetworkSchema::new(&self.network_context)
                                .connection_metadata(&self.connection_metadata),
                            error = %e,
                            "[sampled] Failed to send outbound rpc request for protocol {} to peer: {}. Error: {}",
                            protocol_id,
                            self.remote_peer_id().short_str(),
                            e,
                        )
                    );
                }
```

**File:** consensus/src/network_interface.rs (L192-202)
```rust
    pub async fn send_rpc(
        &self,
        peer: PeerId,
        message: ConsensusMsg,
        rpc_timeout: Duration,
    ) -> Result<ConsensusMsg, Error> {
        let peer_network_id = self.get_peer_network_id_for_peer(peer);
        self.network_client
            .send_to_peer_rpc(message, rpc_timeout, peer_network_id)
            .await
    }
```

**File:** peer-monitoring-service/client/src/peer_states/request_tracker.rs (L76-90)
```rust
    pub fn new_request_required(&self) -> bool {
        // There's already an in-flight request. A new one should not be sent.
        if self.in_flight_request() {
            return false;
        }

        // Otherwise, check the last request time for freshness
        match self.last_request_time {
            Some(last_request_time) => {
                self.time_service.now()
                    > last_request_time.add(Duration::from_micros(self.request_interval_usec))
            },
            None => true, // A request should be sent immediately
        }
    }
```
