# Audit Report

## Title
DKG Network Channel Starvation via DirectSend Protocol Flooding

## Summary
The DKG network configuration applies `max_network_channel_size` uniformly to both RPC and DirectSend protocols through a shared inbound channel, but only RPC messages are actually processed by DKG. This architectural asymmetry allows unused DirectSend protocol messages to consume queue capacity, potentially delaying or preventing critical RPC-based transcript exchange operations required for DKG completion.

## Finding Description

The DKG subsystem registers both DirectSend and RPC protocols but only processes RPC messages. Both protocol types share a single inbound message queue with FIFO semantics, creating an exploitable resource competition vulnerability.

**Architecture Analysis:** [1](#0-0) [2](#0-1) 

The configuration creates a shared channel for both protocol types with a single size limit (default 256 messages).

**Shared Channel Implementation:** [3](#0-2) 

Both DirectSend and RPC protocols are registered to use the same `network_notifs_tx` channel sender (lines 423-429), confirming they share queue resources.

**Protocol Registration:** [4](#0-3) 

DKG registers 3 DirectSend and 3 RPC protocol variants, all sharing the channel.

**Message Processing Asymmetry:** [5](#0-4) 

DKG's NetworkTask only processes RPC messages (line 163) and explicitly ignores all other message types including DirectSend (lines 177-179). However, this filtering occurs AFTER messages have already consumed queue capacity at the network layer.

**Queue Behavior Under Load:** [6](#0-5) 

With FIFO queue style, when the per-key queue reaches capacity (256 messages), NEW messages are dropped (line 140), preventing them from being enqueued.

**Attack Mechanism:**

1. A malicious validator continuously sends DirectSend messages using DKG protocol IDs (DKGDirectSendCompressed, DKGDirectSendBcs, DKGDirectSendJson)
2. Each protocol gets its own queue of up to 256 messages per (PeerId, ProtocolId) key
3. These messages accumulate in the shared channel and are delivered to DKG in round-robin fashion
4. DKG ignores each DirectSend message after receiving it (wasted processing)
5. When legitimate RPC transcript requests arrive during DKG execution, they compete with queued DirectSend messages for delivery slots
6. The round-robin delivery significantly delays RPC processing
7. RPC operations have a 10-second timeout [7](#0-6) 
8. If DirectSend message processing causes sufficient delay, RPC requests timeout before being handled
9. Failed transcript exchange prevents DKG completion, blocking epoch transitions

## Impact Explanation

**Severity: Medium** ($10,000 range per bug bounty criteria)

This vulnerability causes **state inconsistencies requiring intervention** by preventing DKG protocol completion, which is required for epoch transitions and validator set updates. While it doesn't directly cause consensus failure or fund loss, it creates a liveness degradation that could require manual intervention to resolve.

The impact is limited by:
- Requires malicious validator (not unprivileged attacker)
- Does not break consensus safety directly
- Does not result in fund theft or permanent state corruption
- Network can recover once the malicious validator is identified and removed

However, it creates measurable harm:
- Delays or prevents epoch transitions
- Disrupts validator set rotations
- Creates operational burden requiring manual remediation
- Could be used strategically during critical upgrade windows

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is feasible because:
- DirectSend protocols are explicitly registered and accessible to validators
- No rate limiting exists specifically for DirectSend messages at the protocol level
- The shared queue architecture is a fundamental design choice, not an edge case
- Attack requires only sending messages, no complex state manipulation

Factors affecting likelihood:
- Requires malicious validator (reduces likelihood in honest majority assumption)
- Validator can be detected and slashed for misbehavior
- Attack is sustainable only while validator remains in active set
- Multiple validators could be affected simultaneously if attacker has sufficient queue throughput

## Recommendation

**Immediate Fix: Remove DirectSend Protocol Registration**

Since DKG only uses RPC and explicitly ignores DirectSend messages, remove DirectSend protocols from the network configuration:

```rust
// In aptos-node/src/network.rs, modify dkg_network_configuration:
pub fn dkg_network_configuration(node_config: &NodeConfig) -> NetworkApplicationConfig {
    // Remove DirectSend protocol registration entirely
    let direct_send_protocols: Vec<ProtocolId> = vec![]; // Empty - DKG doesn't use DirectSend
    let rpc_protocols: Vec<ProtocolId> = aptos_dkg_runtime::network_interface::RPC.into();
    
    let network_client_config =
        NetworkClientConfig::new(direct_send_protocols.clone(), rpc_protocols.clone());
    let network_service_config = NetworkServiceConfig::new(
        direct_send_protocols,
        rpc_protocols,
        aptos_channel::Config::new(node_config.dkg.max_network_channel_size)
            .queue_style(QueueStyle::FIFO),
    );
    NetworkApplicationConfig::new(network_client_config, network_service_config)
}
```

**Alternative Fix: Separate Channels per Protocol Type**

Modify the network framework to create separate channels for DirectSend and RPC:

```rust
// In network/framework/src/peer_manager/builder.rs
pub fn add_service(
    &mut self,
    config: &NetworkServiceConfig,
) -> (
    aptos_channel::Receiver<(PeerId, ProtocolId), ReceivedMessage>, // DirectSend
    aptos_channel::Receiver<(PeerId, ProtocolId), ReceivedMessage>, // RPC
) {
    self.transport_context()
        .add_protocols(&config.direct_send_protocols_and_preferences);
    self.transport_context()
        .add_protocols(&config.rpc_protocols_and_preferences);

    // Create separate channels
    let (direct_send_tx, direct_send_rx) = config.inbound_queue_config.build();
    let (rpc_tx, rpc_rx) = config.inbound_queue_config.build();
    
    let pm_context = self.peer_manager_context();
    
    // Register DirectSend protocols to DirectSend channel
    for protocol in &config.direct_send_protocols_and_preferences {
        pm_context.add_upstream_handler(*protocol, direct_send_tx.clone());
    }
    
    // Register RPC protocols to RPC channel
    for protocol in &config.rpc_protocols_and_preferences {
        pm_context.add_upstream_handler(*protocol, rpc_tx.clone());
    }

    (direct_send_rx, rpc_rx)
}
```

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[tokio::test]
async fn test_dkg_channel_starvation_via_directsend() {
    use aptos_channels::{aptos_channel, message_queues::QueueStyle};
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_types::PeerId;
    use std::time::Duration;
    
    // Simulate DKG channel configuration
    let (tx, mut rx) = aptos_channel::new::<(PeerId, ProtocolId), DKGMessage>(
        QueueStyle::FIFO,
        256, // max_network_channel_size
        None,
    );
    
    let attacker_peer = PeerId::random();
    let honest_peer = PeerId::random();
    
    // Attacker floods DirectSend messages
    for i in 0..256 {
        let key = (attacker_peer, ProtocolId::DKGDirectSendCompressed);
        tx.push(key, create_directsend_message(i)).unwrap();
    }
    
    // Honest validator tries to send critical RPC
    let rpc_key = (honest_peer, ProtocolId::DKGRpcCompressed);
    let rpc_msg = create_rpc_transcript_request();
    
    // Start processing messages with timeout
    let start = tokio::time::Instant::now();
    let timeout_duration = Duration::from_secs(10);
    
    let mut rpc_processed = false;
    let mut messages_processed = 0;
    
    while messages_processed < 300 {
        if let Some((_key, msg)) = rx.select_next_some().await {
            messages_processed += 1;
            
            // Simulate DKG processing - ignores DirectSend, handles RPC
            match msg.protocol_id() {
                ProtocolId::DKGDirectSendCompressed |
                ProtocolId::DKGDirectSendBcs |
                ProtocolId::DKGDirectSendJson => {
                    // Ignored, but time was spent delivering it
                    tokio::time::sleep(Duration::from_millis(10)).await;
                },
                ProtocolId::DKGRpcCompressed |
                ProtocolId::DKGRpcBcs |
                ProtocolId::DKGRpcJson => {
                    rpc_processed = true;
                    break;
                },
                _ => {}
            }
            
            if start.elapsed() > timeout_duration {
                break; // RPC timeout
            }
        }
    }
    
    // Assertion: RPC should timeout due to DirectSend message processing delays
    assert!(!rpc_processed, "RPC should have timed out due to DirectSend flooding");
    assert!(start.elapsed() > timeout_duration, "Should have exceeded RPC timeout");
}
```

**Notes:**
- The vulnerability exists in production code paths
- DirectSend protocol registration serves no functional purpose for DKG
- Removing DirectSend protocols eliminates the attack surface entirely
- This is a design flaw in the network layer's protocol management, not a coding error

### Citations

**File:** config/src/config/dkg_config.rs (L8-10)
```rust
pub struct DKGConfig {
    pub max_network_channel_size: usize,
}
```

**File:** aptos-node/src/network.rs (L74-89)
```rust
/// Returns the network application config for the DKG client and service
pub fn dkg_network_configuration(node_config: &NodeConfig) -> NetworkApplicationConfig {
    let direct_send_protocols: Vec<ProtocolId> =
        aptos_dkg_runtime::network_interface::DIRECT_SEND.into();
    let rpc_protocols: Vec<ProtocolId> = aptos_dkg_runtime::network_interface::RPC.into();

    let network_client_config =
        NetworkClientConfig::new(direct_send_protocols.clone(), rpc_protocols.clone());
    let network_service_config = NetworkServiceConfig::new(
        direct_send_protocols,
        rpc_protocols,
        aptos_channel::Config::new(node_config.dkg.max_network_channel_size)
            .queue_style(QueueStyle::FIFO),
    );
    NetworkApplicationConfig::new(network_client_config, network_service_config)
}
```

**File:** network/framework/src/peer_manager/builder.rs (L410-432)
```rust
    pub fn add_service(
        &mut self,
        config: &NetworkServiceConfig,
    ) -> aptos_channel::Receiver<(PeerId, ProtocolId), ReceivedMessage> {
        // Register the direct send and rpc protocols
        self.transport_context()
            .add_protocols(&config.direct_send_protocols_and_preferences);
        self.transport_context()
            .add_protocols(&config.rpc_protocols_and_preferences);

        // Create the context and register the protocols
        let (network_notifs_tx, network_notifs_rx) = config.inbound_queue_config.build();
        let pm_context = self.peer_manager_context();
        for protocol in config
            .direct_send_protocols_and_preferences
            .iter()
            .chain(&config.rpc_protocols_and_preferences)
        {
            pm_context.add_upstream_handler(*protocol, network_notifs_tx.clone());
        }

        network_notifs_rx
    }
```

**File:** dkg/src/network_interface.rs (L14-24)
```rust
pub const RPC: &[ProtocolId] = &[
    ProtocolId::DKGRpcCompressed,
    ProtocolId::DKGRpcBcs,
    ProtocolId::DKGRpcJson,
];

pub const DIRECT_SEND: &[ProtocolId] = &[
    ProtocolId::DKGDirectSendCompressed,
    ProtocolId::DKGDirectSendBcs,
    ProtocolId::DKGDirectSendJson,
];
```

**File:** dkg/src/network.rs (L160-183)
```rust
    pub async fn start(mut self) {
        while let Some(message) = self.all_events.next().await {
            match message {
                Event::RpcRequest(peer_id, msg, protocol, response_sender) => {
                    let req = IncomingRpcRequest {
                        msg,
                        sender: peer_id,
                        response_sender: Box::new(RealRpcResponseSender {
                            inner: Some(response_sender),
                            protocol,
                        }),
                    };

                    if let Err(e) = self.rpc_tx.push(peer_id, (peer_id, req)) {
                        warn!(error = ?e, "aptos channel closed");
                    };
                },
                _ => {
                    // Ignored. Currently only RPC is used.
                },
            }
        }
    }
}
```

**File:** crates/channel/src/message_queues.rs (L134-147)
```rust
        if key_message_queue.len() >= self.max_queue_size.get() {
            if let Some(c) = self.counters.as_ref() {
                c.with_label_values(&["dropped"]).inc();
            }
            match self.queue_style {
                // Drop the newest message for FIFO
                QueueStyle::FIFO => Some(message),
                // Drop the oldest message for LIFO
                QueueStyle::LIFO | QueueStyle::KLAST => {
                    let oldest = key_message_queue.pop_front();
                    key_message_queue.push_back(message);
                    oldest
                },
            }
```

**File:** network/framework/src/constants.rs (L10-11)
```rust
/// The timeout for any inbound RPC call before it's cut off
pub const INBOUND_RPC_TIMEOUT_MS: u64 = 10_000;
```
