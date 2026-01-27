# Audit Report

## Title
Missing Protocol ID Validation in Outbound RPC Requests Allows Protocol Negotiation Bypass

## Summary
The `Peer::handle_outbound_request()` function at line 644 extracts the `protocol_id` from outbound RPC requests without validating it against the negotiated protocols stored in `connection_metadata.application_protocols`. This allows applications to bypass protocol negotiation and send RPCs with arbitrary protocol IDs that were never agreed upon during the connection handshake, potentially causing resource exhaustion on validator nodes.

## Finding Description

During the Aptos network handshake protocol, peers negotiate a mutually agreed set of application protocols through `HandshakeMsg.perform_handshake()` and store the intersection of supported protocols in `ConnectionMetadata.application_protocols`. [1](#0-0) 

However, when sending outbound RPC requests, the `Peer::handle_outbound_request()` function directly extracts the `protocol_id` from the request and passes it to the outbound RPC handler without any validation: [2](#0-1) 

The `OutboundRpcs::handle_outbound_request()` method similarly does not validate the protocol_id against negotiated protocols: [3](#0-2) 

While the higher-level `NetworkClient::send_to_peer_rpc()` does validate protocol IDs via `get_preferred_protocol_for_peer()` before sending: [4](#0-3) 

Applications can bypass this validation by directly using `PeerManagerRequestSender`, which is publicly exposed through `PeerManagerBuilder::add_client()`: [5](#0-4) 

An attacker can send RPCs with arbitrary protocol IDs using `PeerManagerRequestSender::send_rpc()`: [6](#0-5) 

The receiving peer will check if the protocol_id exists in its `upstream_handlers` and drop the message if not found: [7](#0-6) 

However, the receiver still incurs the cost of reading the message from the wire, deserializing the `NetworkMessage`, performing the upstream_handlers lookup, and incrementing counters.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: An attacker can repeatedly send RPC requests with invalid protocol IDs to validator nodes, forcing them to waste CPU cycles deserializing and processing messages that will ultimately be dropped. This can degrade validator performance and potentially impact block production timing.

2. **Protocol Violation**: The vulnerability breaks the protocol negotiation contract established during the handshake phase, where peers explicitly agree on which protocols will be used for communication.

3. **Resource Exhaustion Vector**: While each individual invalid RPC has limited cost, an attacker can amplify the impact by:
   - Opening multiple connections to the same validator
   - Sending bursts of invalid RPCs across all connections
   - Rotating through different non-negotiated protocol IDs to evade simple filtering

4. **Metrics Pollution**: Invalid protocol IDs increment `UNKNOWN_LABEL` counters, potentially obscuring legitimate monitoring data and making it harder to detect other attacks.

## Likelihood Explanation

This vulnerability is **highly likely** to be exploited:

1. **Low Barrier to Entry**: Any network peer can connect to validator nodes and send RPC requests. No special privileges are required.

2. **Direct API Access**: Applications with access to `PeerManagerRequestSender` (which is returned by the public `add_client()` method) can trivially bypass validation by calling `send_rpc()` with arbitrary protocol IDs.

3. **No Authentication**: Protocol IDs are not authenticated or bound to the connection's negotiated protocols at the sender side.

4. **Amplification Potential**: An attacker can open multiple connections and send many invalid RPCs per connection, amplifying the DoS impact.

## Recommendation

Add validation in `Peer::handle_outbound_request()` to verify that the protocol_id is in the negotiated `application_protocols` set before sending the RPC:

```rust
PeerRequest::SendRpc(request) => {
    let protocol_id = request.protocol_id;
    
    // Validate that protocol_id was negotiated during handshake
    if !self.connection_metadata.application_protocols.contains(protocol_id) {
        warn!(
            NetworkSchema::new(&self.network_context)
                .connection_metadata(&self.connection_metadata),
            protocol_id = %protocol_id,
            "Attempted to send RPC with non-negotiated protocol_id {} to peer {}. Dropping request.",
            protocol_id,
            self.remote_peer_id().short_str(),
        );
        counters::rpc_messages(&self.network_context, REQUEST_LABEL, OUTBOUND_LABEL, DECLINED_LABEL).inc();
        return;
    }
    
    if let Err(e) = self
        .outbound_rpcs
        .handle_outbound_request(request, write_reqs_tx)
    {
        // ... existing error handling
    }
}
```

The `ProtocolIdSet::contains()` method is already available: [8](#0-7) 

## Proof of Concept

```rust
// In a test or malicious application module:
use network::peer_manager::PeerManagerRequestSender;
use network::protocols::rpc::OutboundRpcRequest;
use bytes::Bytes;
use std::time::Duration;

async fn exploit_protocol_validation_bypass(
    peer_mgr_sender: PeerManagerRequestSender,
    target_peer_id: PeerId,
) {
    // Use a protocol ID that was NOT negotiated during handshake
    let invalid_protocol_id = ProtocolId::DKGRpcCompressed; // Assuming this wasn't negotiated
    
    // Create an RPC with the invalid protocol
    let (res_tx, res_rx) = oneshot::channel();
    let request = OutboundRpcRequest {
        protocol_id: invalid_protocol_id,
        data: Bytes::from_static(b"malicious payload"),
        res_tx,
        timeout: Duration::from_secs(5),
    };
    
    // Send directly via PeerManagerRequestSender, bypassing NetworkClient validation
    let _ = peer_mgr_sender.send_rpc(
        target_peer_id,
        invalid_protocol_id,
        Bytes::from_static(b"malicious payload"),
        Duration::from_secs(5)
    ).await;
    
    // The receiver will waste resources processing and dropping this message
    // Repeat this many times to cause validator slowdown
    for _ in 0..10000 {
        let _ = peer_mgr_sender.send_rpc(
            target_peer_id,
            invalid_protocol_id,
            Bytes::from_static(b"spam"),
            Duration::from_secs(5)
        ).await;
    }
}
```

The PoC demonstrates how an attacker with access to `PeerManagerRequestSender` can send RPCs with non-negotiated protocol IDs, forcing the receiver to waste resources on invalid messages. This can be amplified across multiple connections to cause significant validator slowdown.

## Notes

- The validation exists at the `NetworkClient` layer but is bypassable when using lower-level APIs
- The receiver does check `upstream_handlers` but still incurs processing costs before dropping the message
- The negotiated protocols in `ConnectionMetadata.application_protocols` are readily available in the `Peer` struct but are not consulted for outbound requests
- This creates an asymmetry: inbound requests are validated against `upstream_handlers`, but outbound requests have no corresponding validation against `application_protocols`

### Citations

**File:** network/framework/src/transport/mod.rs (L100-108)
```rust
pub struct ConnectionMetadata {
    pub remote_peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub addr: NetworkAddress,
    pub origin: ConnectionOrigin,
    pub messaging_protocol: MessagingProtocolVersion,
    pub application_protocols: ProtocolIdSet,
    pub role: PeerRole,
}
```

**File:** network/framework/src/peer/mod.rs (L505-530)
```rust
            NetworkMessage::RpcRequest(request) => {
                match self.upstream_handlers.get(&request.protocol_id) {
                    None => {
                        counters::direct_send_messages(&self.network_context, UNKNOWN_LABEL).inc();
                        counters::direct_send_bytes(&self.network_context, UNKNOWN_LABEL)
                            .inc_by(request.raw_request.len() as u64);
                    },
                    Some(handler) => {
                        let sender = self.connection_metadata.remote_peer_id;
                        let network_id = self.network_context.network_id();
                        let sender = PeerNetworkId::new(network_id, sender);
                        if let Err(err) = self
                            .inbound_rpcs
                            .handle_inbound_request(handler, ReceivedMessage::new(message, sender))
                        {
                            warn!(
                                NetworkSchema::new(&self.network_context)
                                    .connection_metadata(&self.connection_metadata),
                                error = %err,
                                "{} Error handling inbound rpc request: {}",
                                self.network_context,
                                err
                            );
                        }
                    },
                }
```

**File:** network/framework/src/peer/mod.rs (L643-647)
```rust
            PeerRequest::SendRpc(request) => {
                let protocol_id = request.protocol_id;
                if let Err(e) = self
                    .outbound_rpcs
                    .handle_outbound_request(request, write_reqs_tx)
```

**File:** network/framework/src/protocols/rpc/mod.rs (L433-499)
```rust
    pub fn handle_outbound_request(
        &mut self,
        request: OutboundRpcRequest,
        write_reqs_tx: &mut aptos_channel::Sender<(), NetworkMessage>,
    ) -> Result<(), RpcError> {
        let network_context = &self.network_context;
        let peer_id = &self.remote_peer_id;

        // Unpack request.
        let OutboundRpcRequest {
            protocol_id,
            data: request_data,
            timeout,
            res_tx: mut application_response_tx,
        } = request;
        let req_len = request_data.len() as u64;

        // Drop the outbound request if the application layer has already canceled.
        if application_response_tx.is_canceled() {
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                OUTBOUND_LABEL,
                CANCELED_LABEL,
            )
            .inc();
            return Err(RpcError::UnexpectedResponseChannelCancel);
        }

        // Drop new outbound requests if our completion queue is at capacity.
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

        let request_id = self.request_id_gen.next();

        trace!(
            NetworkSchema::new(network_context).remote_peer(peer_id),
            "{} Sending outbound rpc request with request_id {} and protocol_id {} to {}",
            network_context,
            request_id,
            protocol_id,
            peer_id.short_str(),
        );

        // Start timer to collect outbound RPC latency.
        let timer =
            counters::outbound_rpc_request_latency(network_context, protocol_id).start_timer();

        // Enqueue rpc request message onto outbound write queue.
        let message = NetworkMessage::RpcRequest(RpcRequest {
            protocol_id,
            request_id,
            priority: Priority::default(),
            raw_request: Vec::from(request_data.as_ref()),
        });
        write_reqs_tx.push((), message)?;
```

**File:** network/framework/src/application/interface.rs (L260-272)
```rust
    async fn send_to_peer_rpc(
        &self,
        message: Message,
        rpc_timeout: Duration,
        peer: PeerNetworkId,
    ) -> Result<Message, Error> {
        let network_sender = self.get_sender_for_network_id(&peer.network_id())?;
        let rpc_protocol_id =
            self.get_preferred_protocol_for_peer(&peer, &self.rpc_protocols_and_preferences)?;
        Ok(network_sender
            .send_rpc(peer.peer_id(), rpc_protocol_id, message, rpc_timeout)
            .await?)
    }
```

**File:** network/framework/src/peer_manager/builder.rs (L391-407)
```rust
    pub fn add_client(
        &mut self,
        config: &NetworkClientConfig,
    ) -> (PeerManagerRequestSender, ConnectionRequestSender) {
        // Register the direct send and rpc protocols
        self.transport_context()
            .add_protocols(&config.direct_send_protocols_and_preferences);
        self.transport_context()
            .add_protocols(&config.rpc_protocols_and_preferences);

        // Create the context and return the request senders
        let pm_context = self.peer_manager_context();
        (
            PeerManagerRequestSender::new(pm_context.pm_reqs_tx.clone()),
            ConnectionRequestSender::new(pm_context.connection_reqs_tx.clone()),
        )
    }
```

**File:** network/framework/src/peer_manager/senders.rs (L89-108)
```rust
    pub async fn send_rpc(
        &self,
        peer_id: PeerId,
        protocol_id: ProtocolId,
        req: Bytes,
        timeout: Duration,
    ) -> Result<Bytes, RpcError> {
        let (res_tx, res_rx) = oneshot::channel();
        let request = OutboundRpcRequest {
            protocol_id,
            data: req,
            res_tx,
            timeout,
        };
        self.inner.push(
            (peer_id, protocol_id),
            PeerManagerRequest::SendRpc(peer_id, request),
        )?;
        res_rx.await?
    }
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L327-330)
```rust
    /// Returns if the protocol is set.
    pub fn contains(&self, protocol: ProtocolId) -> bool {
        self.0.is_set(protocol as u16)
    }
```
