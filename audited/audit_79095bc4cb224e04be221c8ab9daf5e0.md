# Audit Report

## Title
ConsensusObserver Publisher Accepts Subscriptions from Unauthorized Public Nodes Without Access Control

## Summary
The ConsensusObserver publisher component accepts subscription requests from any connected peer without verifying peer role or authorization. This allows untrusted public fullnodes to subscribe to Validator Full Nodes (VFNs) and receive real-time consensus information including ordered blocks, commit decisions with validator signatures, and transaction payloads. [1](#0-0) 

## Finding Description
The vulnerability exists in the subscription request handling logic where ANY peer that sends a `ConsensusObserverRequest::Subscribe` is automatically added as an active subscriber without authorization checks.

**Attack Path:**

1. **VFN Configuration**: Validator Full Nodes automatically enable both `observer_enabled` and `publisher_enabled` by default: [2](#0-1) 

2. **Network Access**: VFNs accept connections on the Public network from Unknown/untrusted peers: [3](#0-2) 

3. **Protocol Registration**: ConsensusObserver protocols are registered on all configured networks: [4](#0-3) 

4. **Missing Authorization**: The subscription handler accepts requests without role verification - no check for Validator, ValidatorFullNode, or any trusted status: [5](#0-4) 

5. **Information Leakage**: Subscribers receive sensitive consensus data published during block ordering and commit phases:
   - OrderedBlock messages with consensus blocks and proofs: [6](#0-5) 
   
   - CommitDecision messages with validator signatures: [7](#0-6) 

**Sensitive Data Exposed:** [8](#0-7) 

This includes full PipelinedBlocks, LedgerInfoWithSignatures containing validator signatures, and block execution ordering information.

## Impact Explanation
**HIGH SEVERITY** per Aptos Bug Bounty criteria - "Significant protocol violations"

The vulnerability enables unauthorized access to consensus-critical information:

- **Consensus Information Disclosure**: Real-time access to block ordering decisions before public commitment
- **Validator Signature Exposure**: Premature disclosure of which validators signed blocks and their signatures
- **Timing Attack Vector**: Ability to observe consensus progress and validator behavior patterns
- **Front-running Potential**: Knowledge of transaction ordering before finalization
- **MEV Exploitation**: Early access to block contents enables extractable value attacks

This violates the Access Control invariant that consensus information should only be available to authorized participants.

## Likelihood Explanation
**HIGH LIKELIHOOD** - The vulnerability is easily exploitable:

**Attacker Requirements:**
- Ability to run a network node (trivial)
- Connection to any VFN on the Public network (open access)
- Implement ConsensusObserver protocol support (straightforward)

**No special privileges needed:**
- No validator key required
- No trusted peer set membership needed
- No stake or governance participation required

**Default Configuration Enables Attack:** [9](#0-8) 

VFNs automatically enable the publisher, making this exploitable against production deployments without configuration changes.

## Recommendation
Implement peer role-based authorization before accepting subscriptions:

```rust
fn process_network_message(&self, network_message: ConsensusPublisherNetworkMessage) {
    let (peer_network_id, message, response_sender) = network_message.into_parts();
    
    // Update the RPC request counter
    metrics::increment_counter(
        &metrics::PUBLISHER_RECEIVED_REQUESTS,
        message.get_label(),
        &peer_network_id,
    );
    
    match message {
        ConsensusObserverRequest::Subscribe => {
            // ADD AUTHORIZATION CHECK HERE
            // Verify peer is a trusted Validator or ValidatorFullNode
            let peers_and_metadata = self.consensus_observer_client.get_peers_and_metadata();
            let peer_metadata = match peers_and_metadata.get_metadata_for_peer(peer_network_id) {
                Some(metadata) => metadata,
                None => {
                    warn!("Subscription rejected: peer metadata not found for {:?}", peer_network_id);
                    response_sender.send(ConsensusObserverResponse::UnsubscribeAck);
                    return;
                }
            };
            
            let connection_metadata = peer_metadata.get_connection_metadata();
            let peer_role = connection_metadata.role;
            
            // Only allow Validators and ValidatorFullNodes to subscribe
            if !matches!(peer_role, PeerRole::Validator | PeerRole::ValidatorFullNode) {
                warn!("Subscription rejected: unauthorized peer role {:?} for {:?}", 
                      peer_role, peer_network_id);
                response_sender.send(ConsensusObserverResponse::UnsubscribeAck);
                return;
            }
            
            // Add the peer to the set of active subscribers
            self.add_active_subscriber(peer_network_id);
            info!(LogSchema::new(LogEntry::ConsensusPublisher)
                .event(LogEvent::Subscription)
                .message(&format!(
                    "New peer subscribed to consensus updates! Peer: {:?}",
                    peer_network_id
                )));
            
            response_sender.send(ConsensusObserverResponse::SubscribeAck);
        },
        // ... rest of the function
    }
}
```

**Additional Hardening:**
1. Restrict ConsensusObserver protocol registration to Validator and Vfn networks only (exclude Public network)
2. Add configuration option to disable publisher on Public network
3. Implement subscription rate limiting per peer
4. Add metrics to track subscription attempts by unauthorized peers

## Proof of Concept

**Reproduction Steps:**

1. **Setup VFN Node**: Deploy a Validator Full Node with default configuration (publisher automatically enabled)

2. **Attacker Node Setup**: Create a malicious public fullnode that:
   - Connects to the VFN on Public network
   - Advertises ConsensusObserver and ConsensusObserverRpc protocol support
   - Implements ConsensusObserverMessage deserialization

3. **Exploit Execution**:
```rust
// Attacker code snippet
async fn exploit_consensus_observer(vfn_peer: PeerNetworkId) {
    // Connect to VFN and complete handshake with ConsensusObserver protocols
    let consensus_observer_client = setup_observer_client(vfn_peer);
    
    // Send subscription request - NO AUTHORIZATION REQUIRED
    let subscribe_request = ConsensusObserverRequest::Subscribe;
    let response = consensus_observer_client
        .send_rpc_request_to_peer(&vfn_peer, subscribe_request, 5000)
        .await
        .expect("Subscription failed");
    
    // Response will be SubscribeAck - subscription accepted!
    assert_eq!(response, ConsensusObserverResponse::SubscribeAck);
    
    // Now receive real-time consensus messages
    loop {
        let message = receive_consensus_message().await;
        match message {
            ConsensusObserverDirectSend::OrderedBlock(ordered_block) => {
                // Access to ordered blocks with validator signatures
                println!("Received ordered block: {:?}", ordered_block.proof_block_info());
                println!("Block contains {} validators signatures", 
                         ordered_block.ordered_proof().signatures().len());
            },
            ConsensusObserverDirectSend::CommitDecision(commit_decision) => {
                // Access to commit decisions before public finalization
                println!("Received commit decision: {:?}", commit_decision.proof_block_info());
            },
            _ => {}
        }
    }
}
```

4. **Verification**: Monitor attacker node logs to confirm receipt of OrderedBlock and CommitDecision messages with validator signatures and consensus state.

**Expected Result**: Unauthorized public node successfully subscribes and receives real-time consensus information that should only be available to trusted validators and VFNs.

## Notes

The vulnerability is particularly severe because:

1. **Default Configuration**: VFNs automatically enable publishers without explicit configuration
2. **No Warning**: No logs or alerts indicate unauthorized subscription attempts
3. **Production Impact**: Affects all VFNs running with default configuration on public networks
4. **Wide Attack Surface**: Any public node can exploit this against any reachable VFN

The fix requires careful consideration of which peer roles should have access to consensus observer data and on which networks the publisher should operate.

### Citations

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L168-208)
```rust
    fn process_network_message(&self, network_message: ConsensusPublisherNetworkMessage) {
        // Unpack the network message
        let (peer_network_id, message, response_sender) = network_message.into_parts();

        // Update the RPC request counter
        metrics::increment_counter(
            &metrics::PUBLISHER_RECEIVED_REQUESTS,
            message.get_label(),
            &peer_network_id,
        );

        // Handle the message
        match message {
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
            ConsensusObserverRequest::Unsubscribe => {
                // Remove the peer from the set of active subscribers
                self.remove_active_subscriber(&peer_network_id);
                info!(LogSchema::new(LogEntry::ConsensusPublisher)
                    .event(LogEvent::Subscription)
                    .message(&format!(
                        "Peer unsubscribed from consensus updates! Peer: {:?}",
                        peer_network_id
                    )));

                // Send a simple unsubscription ACK
                response_sender.send(ConsensusObserverResponse::UnsubscribeAck);
            },
        }
    }
```

**File:** config/src/config/consensus_observer_config.rs (L11-14)
```rust
// Useful constants for enabling consensus observer on different node types
const ENABLE_ON_VALIDATORS: bool = true;
const ENABLE_ON_VALIDATOR_FULLNODES: bool = true;
const ENABLE_ON_PUBLIC_FULLNODES: bool = false;
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

**File:** config/src/network_id.rs (L189-199)
```rust
    pub fn downstream_roles(&self, role: &RoleType) -> &'static [PeerRole] {
        match self {
            NetworkId::Validator => &[PeerRole::Validator],
            // In order to allow fallbacks, we must allow for nodes to accept ValidatorFullNodes
            NetworkId::Public => &[
                PeerRole::ValidatorFullNode,
                PeerRole::Downstream,
                PeerRole::Known,
                PeerRole::Unknown,
            ],
            NetworkId::Vfn => match role {
```

**File:** aptos-node/src/network.rs (L170-189)
```rust
pub fn consensus_observer_network_configuration(
    node_config: &NodeConfig,
) -> NetworkApplicationConfig {
    let direct_send_protocols = vec![ProtocolId::ConsensusObserver];
    let rpc_protocols = vec![ProtocolId::ConsensusObserverRpc];
    let max_network_channel_size = node_config.consensus_observer.max_network_channel_size as usize;

    let network_client_config =
        NetworkClientConfig::new(direct_send_protocols.clone(), rpc_protocols.clone());
    let network_service_config = NetworkServiceConfig::new(
        direct_send_protocols,
        rpc_protocols,
        aptos_channel::Config::new(max_network_channel_size)
            .queue_style(QueueStyle::FIFO)
            .counters(
                &consensus_observer::common::metrics::PENDING_CONSENSUS_OBSERVER_NETWORK_EVENTS,
            ),
    );
    NetworkApplicationConfig::new(network_client_config, network_service_config)
}
```

**File:** consensus/src/pipeline/buffer_manager.rs (L400-406)
```rust
        if let Some(consensus_publisher) = &self.consensus_publisher {
            let message = ConsensusObserverMessage::new_ordered_block_message(
                ordered_blocks.clone(),
                ordered_proof.clone(),
            );
            consensus_publisher.publish_message(message);
        }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L514-518)
```rust
                if let Some(consensus_publisher) = &self.consensus_publisher {
                    let message =
                        ConsensusObserverMessage::new_commit_decision_message(commit_proof.clone());
                    consensus_publisher.publish_message(message);
                }
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L179-218)
```rust
/// OrderedBlock message contains the ordered blocks and the proof of the ordering
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrderedBlock {
    blocks: Vec<Arc<PipelinedBlock>>,
    ordered_proof: LedgerInfoWithSignatures,
}

impl OrderedBlock {
    pub fn new(blocks: Vec<Arc<PipelinedBlock>>, ordered_proof: LedgerInfoWithSignatures) -> Self {
        Self {
            blocks,
            ordered_proof,
        }
    }

    /// Returns a reference to the ordered blocks
    pub fn blocks(&self) -> &Vec<Arc<PipelinedBlock>> {
        &self.blocks
    }

    /// Returns a copy of the first ordered block
    pub fn first_block(&self) -> Arc<PipelinedBlock> {
        self.blocks
            .first()
            .cloned()
            .expect("At least one block is expected!")
    }

    /// Returns a copy of the last ordered block
    pub fn last_block(&self) -> Arc<PipelinedBlock> {
        self.blocks
            .last()
            .cloned()
            .expect("At least one block is expected!")
    }

    /// Returns a reference to the ordered proof
    pub fn ordered_proof(&self) -> &LedgerInfoWithSignatures {
        &self.ordered_proof
    }
```
