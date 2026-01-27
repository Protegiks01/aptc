# Audit Report

## Title
Consensus Publisher Accepts Unauthenticated Subscriptions on Fullnode Networks

## Summary
The `ConsensusPublisher` in the Aptos Core node implementation accepts subscription requests from any peer without verifying authorization, allowing unauthorized nodes on non-mutually-authenticated networks (e.g., VFN public networks) to receive real-time consensus data including ordered blocks, transaction payloads, and commit decisions before they are finalized on-chain.

## Finding Description

The vulnerability exists in the consensus publisher subscription mechanism, which fails to authenticate or authorize peers before granting them access to consensus data streams.

**Network Registration Without Authentication Boundaries:**

The consensus observer/publisher protocol is registered on ALL configured networks when enabled: [1](#0-0) 

**Mutual Authentication Only on Validator Networks:**

Fullnode networks do not enforce mutual authentication by default: [2](#0-1) 

**Unauthenticated Subscription Acceptance:**

When a `Subscribe` request is received, the publisher adds the peer to active subscribers without any authorization check: [3](#0-2) 

**Unrestricted Data Distribution:**

Once subscribed, peers receive all consensus messages without further validation: [4](#0-3) 

**Attack Path:**

1. Attacker identifies a Validator Fullnode (VFN) running the consensus publisher (enabled by default on VFNs)
2. Attacker connects to the VFN's public fullnode network (which has `mutual_authentication = false`)
3. Attacker sends a `ConsensusObserverRequest::Subscribe` RPC to the publisher
4. Publisher accepts the subscription without verifying the peer's authorization
5. Attacker receives real-time consensus data: ordered blocks, transaction payloads, and commit decisions

The network handler simply forwards subscription requests to the publisher without validation: [5](#0-4) 

## Impact Explanation

This vulnerability falls under **Medium Severity** per Aptos bug bounty criteria for the following reasons:

**Information Disclosure Impact:**
- Unauthorized access to pre-commitment consensus data including transaction ordering and validator decisions
- Potential for front-running attacks by observing transaction ordering before blocks are committed
- Exposure of validator voting patterns and consensus round progression
- Leakage of transaction payloads before public commitment

**Limited Direct Impact:**
- Does not directly break consensus safety or liveness
- Does not enable direct fund theft or minting
- Consensus data eventually becomes public after commitment
- No validator set manipulation or protocol violation

The vulnerability enables information-based attacks rather than direct protocol violations, placing it in the Medium severity category rather than Critical or High.

## Likelihood Explanation

**High Likelihood of Exploitation:**

1. **Widespread Exposure**: VFNs are commonly deployed in production with the publisher enabled by default: [6](#0-5) 

2. **No Special Privileges Required**: Any peer with network connectivity to a VFN's public network can exploit this vulnerability

3. **Simple Attack Vector**: Requires only sending a standard RPC request (Subscribe) over the network

4. **No Rate Limiting or Quotas**: The publisher accepts subscriptions up to `max_concurrent_subscriptions` (default 2) without per-peer restrictions

5. **Persistent Access**: Once subscribed, attackers maintain access until disconnected or the subscription times out

## Recommendation

Implement authorization checks for consensus publisher subscriptions to restrict access to trusted peers only. The fix should:

1. **Add Peer Authorization Check**: Before accepting subscriptions, verify the peer is in the trusted peer set or has appropriate authorization:

```rust
fn process_network_message(&self, network_message: ConsensusPublisherNetworkMessage) {
    let (peer_network_id, message, response_sender) = network_message.into_parts();
    
    match message {
        ConsensusObserverRequest::Subscribe => {
            // NEW: Verify peer is authorized before subscribing
            if !self.is_peer_authorized(&peer_network_id) {
                warn!(LogSchema::new(LogEntry::ConsensusPublisher)
                    .event(LogEvent::Subscription)
                    .message(&format!(
                        "Rejected unauthorized subscription request from peer: {:?}",
                        peer_network_id
                    )));
                response_sender.send(ConsensusObserverResponse::SubscriptionRejected);
                return;
            }
            
            self.add_active_subscriber(peer_network_id);
            // ... rest of existing code
        },
        // ... rest of match arms
    }
}

// NEW: Authorization check function
fn is_peer_authorized(&self, peer_network_id: &PeerNetworkId) -> bool {
    // Check if peer is in trusted peers set via PeersAndMetadata
    let peers_and_metadata = self.consensus_observer_client.get_peers_and_metadata();
    peers_and_metadata.is_trusted_peer(peer_network_id)
}
```

2. **Network-Specific Publisher Controls**: Add configuration to restrict publisher to specific networks (e.g., only validator network):

```rust
pub struct ConsensusObserverConfig {
    // ... existing fields
    
    /// Networks on which the publisher should be enabled (empty = all networks)
    pub publisher_allowed_networks: Vec<NetworkId>,
    
    /// Whether to require mutual authentication for publisher subscriptions
    pub publisher_require_trusted_peers: bool,
}
```

3. **Enhanced Logging**: Add metrics and alerts for unauthorized subscription attempts to detect exploitation attempts.

## Proof of Concept

**Rust-based exploitation steps:**

```rust
// 1. Connect to a VFN's public fullnode network
let vfn_address = "/ip4/VFN_IP/tcp/VFN_PORT"; // VFN's public network endpoint
let network_context = NetworkContext::new(NetworkId::Public, /* ... */);

// 2. Establish connection (no mutual auth required on public networks)
let peer_id = PeerId::random();
let connection = establish_connection(vfn_address, peer_id).await?;

// 3. Send Subscribe request to consensus publisher
let subscribe_request = ConsensusObserverRequest::Subscribe;
let response = send_rpc_request(
    connection,
    subscribe_request,
    ProtocolId::ConsensusObserverRpc,
    Duration::from_secs(10)
).await?;

// 4. Verify subscription accepted
assert!(matches!(response, ConsensusObserverResponse::SubscribeAck));

// 5. Receive consensus data stream
loop {
    let message = receive_direct_send(connection, ProtocolId::ConsensusObserver).await?;
    
    match message {
        ConsensusObserverDirectSend::OrderedBlock(blocks, ledger_info) => {
            println!("Received ordered block before commitment: {:?}", blocks);
            // Attacker can observe transaction ordering for front-running
        },
        ConsensusObserverDirectSend::CommitDecision(ledger_info) => {
            println!("Received commit decision: {:?}", ledger_info);
        },
        // ... other message types
    }
}
```

**Verification:**
1. Deploy a VFN with default configuration (publisher enabled)
2. Run the PoC from an unauthorized external node
3. Observe successful subscription and receipt of consensus data
4. Verify that the attacking node is NOT in the VFN's trusted peer set

## Notes

This vulnerability specifically affects Validator Fullnodes (VFNs) which have the consensus publisher enabled by default and operate on public networks without mutual authentication. Standard validators typically only expose the validator network (with mandatory mutual authentication), making them less susceptible unless they have additional fullnode networks configured. The fix should preserve the legitimate use case of VFNs sharing consensus data with their trusted downstream fullnodes while preventing unauthorized access.

### Citations

**File:** aptos-node/src/network.rs (L336-358)
```rust
        // Register consensus observer (both client and server) with the network
        if node_config
            .consensus_observer
            .is_observer_or_publisher_enabled()
        {
            // Create the network handle for this network type
            let network_handle = register_client_and_service_with_network(
                &mut network_builder,
                network_id,
                &network_config,
                consensus_observer_network_configuration(node_config),
                false,
            );

            // Add the network handle to the set of handles
            if let Some(consensus_observer_network_handles) =
                &mut consensus_observer_network_handles
            {
                consensus_observer_network_handles.push(network_handle);
            } else {
                consensus_observer_network_handles = Some(vec![network_handle]);
            }
        }
```

**File:** config/src/config/network_config.rs (L135-142)
```rust
    pub fn network_with_id(network_id: NetworkId) -> NetworkConfig {
        let mutual_authentication = network_id.is_validator_network();
        let mut config = Self {
            discovery_method: DiscoveryMethod::None,
            discovery_methods: Vec::new(),
            identity: Identity::None,
            listen_address: "/ip4/0.0.0.0/tcp/6180".parse().unwrap(),
            mutual_authentication,
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L181-193)
```rust
            ConsensusObserverRequest::Subscribe => {
                // Add the peer to the set of active subscribers
                self.add_active_subscriber(peer_network_id);
                info!(LogSchema::new(LogEntry::ConsensusPublisher)
                    .event(LogEvent::Subscription)
                    .message(&format!(
                        "New peer subscribed to consensus updates! Peer: {:?}",
                        peer_network_id
                    )));

                // Send a simple subscription ACK
                response_sender.send(ConsensusObserverResponse::SubscribeAck);
            },
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L212-232)
```rust
    pub fn publish_message(&self, message: ConsensusObserverDirectSend) {
        // Get the active subscribers
        let active_subscribers = self.get_active_subscribers();

        // Send the message to all active subscribers
        for peer_network_id in &active_subscribers {
            // Send the message to the outbound receiver for publishing
            let mut outbound_message_sender = self.outbound_message_sender.clone();
            if let Err(error) =
                outbound_message_sender.try_send((*peer_network_id, message.clone()))
            {
                // The message send failed
                warn!(LogSchema::new(LogEntry::ConsensusPublisher)
                        .event(LogEvent::SendDirectSendMessage)
                        .message(&format!(
                            "Failed to send outbound message to the receiver for peer {:?}! Error: {:?}",
                            peer_network_id, error
                    )));
            }
        }
    }
```

**File:** consensus/src/consensus_observer/network/network_handler.rs (L194-232)
```rust
    fn handle_publisher_message(
        &mut self,
        peer_network_id: PeerNetworkId,
        request: ConsensusObserverRequest,
        response_sender: Option<ResponseSender>,
    ) {
        // Drop the message if the publisher is not enabled
        if !self.consensus_observer_config.publisher_enabled {
            return;
        }

        // Ensure that the response sender is present
        let response_sender = match response_sender {
            Some(response_sender) => response_sender,
            None => {
                error!(
                    LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                        "Missing response sender for the RPC request: {:?}",
                        request
                    ))
                );
                return; // Something has gone wrong!
            },
        };

        // Create the consensus publisher message
        let network_message =
            ConsensusPublisherNetworkMessage::new(peer_network_id, request, response_sender);

        // Send the message to the consensus publisher
        if let Err(error) = self.publisher_message_sender.push((), network_message) {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to forward the publisher request to the consensus publisher! Error: {:?}",
                    error
                ))
            );
        }
    }
```

**File:** config/src/config/consensus_observer_config.rs (L119-128)
```rust
            NodeType::ValidatorFullnode => {
                if ENABLE_ON_VALIDATOR_FULLNODES
                    && !observer_manually_set
                    && !publisher_manually_set
                {
                    // Enable both the observer and the publisher for VFNs
                    consensus_observer_config.observer_enabled = true;
                    consensus_observer_config.publisher_enabled = true;
                    modified_config = true;
                }
```
