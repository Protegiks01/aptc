# Audit Report

## Title
Consensus Observer Channel Flooding DoS via Unauthenticated Message Push

## Summary
An attacker can flood the consensus observer's bounded message channels with unauthenticated messages, causing legitimate consensus messages from subscribed peers to be silently dropped. This results in consensus observer liveness failures and forces nodes into repeated fallback mode.

## Finding Description

The consensus observer network handler creates bounded channels that accept messages from any connected peer **before** authentication occurs. The vulnerability exists in the message flow: [1](#0-0) 

The channel is created with `QueueStyle::FIFO` and a default capacity of 1000 messages. [2](#0-1) 

When network messages arrive, they are pushed to the channel **without any authentication check**: [3](#0-2) 

The authentication check via `verify_message_for_subscription()` only happens **after** messages are pulled from the channel: [4](#0-3) 

With FIFO queue style, when the channel is full, **new messages are silently dropped**: [5](#0-4) 

Critically, the `push()` operation returns `Ok(())` even when messages are dropped: [6](#0-5) 

The attack path is:
1. Attacker runs a public fullnode and connects to a VFN (which accepts public connections per the network design) [7](#0-6) 

2. Consensus observer is enabled on VFNs by default: [8](#0-7) 

3. No inbound rate limiting is configured by default: [9](#0-8) 

4. Attacker floods the VFN with consensus observer messages (OrderedBlock, CommitDecision, etc.)
5. The network handler pushes all messages to the bounded channel before authentication
6. When the channel fills (1000 messages), new legitimate messages from subscribed peers are silently dropped
7. The observer stops receiving critical consensus messages, progress checks fail, and the observer enters fallback mode [10](#0-9) 

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria, specifically "Validator node slowdowns" and "Significant protocol violations."

The attack causes:
- **Liveness degradation**: Consensus observer cannot make progress and repeatedly enters fallback mode
- **Performance impact**: Node must rely on slower state sync instead of efficient consensus observation
- **Protocol violation**: The consensus observer protocol design assumes authenticated message delivery

While not a complete loss of node availability (state sync provides fallback), it significantly degrades the performance and reliability of VFNs that depend on consensus observer.

## Likelihood Explanation

**High likelihood** - The attack is:
- **Easy to execute**: Attacker only needs to run a public fullnode and flood messages
- **Low cost**: No validator keys or stake required
- **No authentication barriers**: Messages are queued before authentication
- **Default configuration vulnerable**: No rate limiting enabled by default
- **Broad attack surface**: Any VFN with consensus observer enabled (default for VFNs) is vulnerable

## Recommendation

Implement authentication **before** pushing messages to internal channels. Apply per-peer rate limiting at the network handler level:

```rust
fn handle_observer_message(
    &mut self,
    peer_network_id: PeerNetworkId,
    message: ConsensusObserverDirectSend,
) {
    // Drop the message if the observer is not enabled
    if !self.consensus_observer_config.observer_enabled {
        return;
    }

    // ADD: Rate limiting per peer before channel push
    if !self.rate_limiter.check_and_update(&peer_network_id) {
        warn!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Rate limit exceeded for peer: {}",
                peer_network_id
            ))
        );
        return;
    }

    // ADD: Pre-authentication check for known subscribed peers
    // (requires passing subscription state to network handler)
    if !self.is_subscribed_peer(&peer_network_id) {
        warn!(
            LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                "Dropping message from non-subscribed peer: {}",
                peer_network_id
            ))
        );
        return;
    }

    // Create and send the message
    let network_message = ConsensusObserverNetworkMessage::new(peer_network_id, message);
    if let Err(error) = self.observer_message_sender.push((), network_message) {
        error!(/* ... */);
    }
}
```

Additionally:
1. Enable inbound rate limiting by default in NetworkConfig
2. Use bounded channels with backpressure (block sender) instead of silent drops
3. Add metrics to track dropped messages
4. Consider separate channels per peer to prevent cross-peer flooding

## Proof of Concept

```rust
#[tokio::test]
async fn test_channel_flooding_dos() {
    use consensus_observer::network::{
        network_handler::ConsensusObserverNetworkHandler,
        observer_message::ConsensusObserverDirectSend,
    };
    use aptos_config::config::ConsensusObserverConfig;
    
    // Create config with small channel size for testing
    let mut config = ConsensusObserverConfig::default();
    config.max_network_channel_size = 10; // Small capacity
    config.observer_enabled = true;
    
    // Create network handler with test events
    let (network_handler, mut receiver, _) = 
        ConsensusObserverNetworkHandler::new(config, test_network_events);
    tokio::spawn(network_handler.start());
    
    // Simulate attacker flooding with 100 messages
    let attacker_peer = create_attacker_peer();
    for i in 0..100 {
        send_observer_message(
            &attacker_peer,
            ConsensusObserverDirectSend::OrderedBlock(create_fake_block(i))
        );
    }
    
    // Wait for messages to be processed
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Now send legitimate message from subscribed peer
    let legitimate_peer = create_subscribed_peer();
    send_observer_message(
        &legitimate_peer,
        ConsensusObserverDirectSend::OrderedBlock(create_legitimate_block())
    );
    
    // Try to receive messages - legitimate message should be dropped
    let mut attacker_messages = 0;
    let mut legitimate_messages = 0;
    
    while let Ok(Some(msg)) = timeout(
        Duration::from_millis(100),
        receiver.next()
    ).await {
        if msg.peer_network_id == attacker_peer {
            attacker_messages += 1;
        } else if msg.peer_network_id == legitimate_peer {
            legitimate_messages += 1;
        }
    }
    
    // Verify: Channel was filled with attacker messages,
    // legitimate message was dropped
    assert_eq!(attacker_messages, 10); // Channel capacity
    assert_eq!(legitimate_messages, 0); // Legitimate message dropped!
}
```

## Notes

This vulnerability demonstrates a critical design flaw where denial-of-service protection (authentication, rate limiting) is applied **after** resource allocation (channel queueing). The proper defense-in-depth approach requires authentication and rate limiting **before** consuming bounded resources. While the consensus observer has fallback mechanisms, relying on state sync degrades performance and violates the protocol's design assumptions about timely consensus observation.

### Citations

**File:** consensus/src/consensus_observer/network/network_handler.rs (L94-98)
```rust
        let (observer_message_sender, observer_message_receiver) = aptos_channel::new(
            QueueStyle::FIFO,
            consensus_observer_config.max_network_channel_size as usize,
            None,
        );
```

**File:** consensus/src/consensus_observer/network/network_handler.rs (L169-191)
```rust
    fn handle_observer_message(
        &mut self,
        peer_network_id: PeerNetworkId,
        message: ConsensusObserverDirectSend,
    ) {
        // Drop the message if the observer is not enabled
        if !self.consensus_observer_config.observer_enabled {
            return;
        }

        // Create the consensus observer message
        let network_message = ConsensusObserverNetworkMessage::new(peer_network_id, message);

        // Send the message to the consensus observer
        if let Err(error) = self.observer_message_sender.push((), network_message) {
            error!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to forward the observer message to the consensus observer! Error: {:?}",
                    error
                ))
            );
        }
    }
```

**File:** config/src/config/consensus_observer_config.rs (L12-13)
```rust
const ENABLE_ON_VALIDATORS: bool = true;
const ENABLE_ON_VALIDATOR_FULLNODES: bool = true;
```

**File:** config/src/config/consensus_observer_config.rs (L68-68)
```rust
            max_network_channel_size: 1000,
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L578-594)
```rust
        // Verify the message is from the peers we've subscribed to
        if let Err(error) = self
            .subscription_manager
            .verify_message_for_subscription(peer_network_id)
        {
            // Update the rejected message counter
            increment_rejected_message_counter(&peer_network_id, &message);

            // Log the error and return
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Received message that was not from an active subscription! Error: {:?}",
                    error,
                ))
            );
            return;
        }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L1107-1147)
```rust
    pub async fn start(
        mut self,
        consensus_observer_config: ConsensusObserverConfig,
        mut consensus_observer_message_receiver: Receiver<(), ConsensusObserverNetworkMessage>,
        mut state_sync_notification_listener: tokio::sync::mpsc::UnboundedReceiver<
            StateSyncNotification,
        >,
    ) {
        // Create a progress check ticker
        let mut progress_check_interval = IntervalStream::new(interval(Duration::from_millis(
            consensus_observer_config.progress_check_interval_ms,
        )))
        .fuse();

        // Wait for the latest epoch to start
        self.wait_for_epoch_start().await;

        // Start the consensus observer loop
        info!(LogSchema::new(LogEntry::ConsensusObserver)
            .message("Starting the consensus observer loop!"));
        loop {
            tokio::select! {
                Some(network_message) = consensus_observer_message_receiver.next() => {
                    self.process_network_message(network_message).await;
                }
                Some(state_sync_notification) = state_sync_notification_listener.recv() => {
                    self.process_state_sync_notification(state_sync_notification).await;
                },
                _ = progress_check_interval.select_next_some() => {
                    self.check_progress().await;
                }
                else => {
                    break; // Exit the consensus observer loop
                }
            }
        }

        // Log the exit of the consensus observer loop
        error!(LogSchema::new(LogEntry::ConsensusObserver)
            .message("The consensus observer loop exited unexpectedly!"));
    }
```

**File:** crates/channel/src/message_queues.rs (L138-147)
```rust
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

**File:** crates/channel/src/aptos_channel.rs (L96-112)
```rust
    ) -> Result<()> {
        let mut shared_state = self.shared_state.lock();
        ensure!(!shared_state.receiver_dropped, "Channel is closed");
        debug_assert!(shared_state.num_senders > 0);

        let dropped = shared_state.internal_queue.push(key, (message, status_ch));
        // If this or an existing message had to be dropped because of the queue being full, we
        // notify the corresponding status channel if it was registered.
        if let Some((dropped_val, Some(dropped_status_ch))) = dropped {
            // Ignore errors.
            let _err = dropped_status_ch.send(ElementStatus::Dropped(dropped_val));
        }
        if let Some(w) = shared_state.waker.take() {
            w.wake();
        }
        Ok(())
    }
```

**File:** network/README.md (L36-39)
```markdown
In contrast, Validator Full Node (VFNs) servers will only prioritize connections
from more trusted peers in the on-chain discovery set; they will still service
any public clients. Public Full Nodes (PFNs) connecting to VFNs will always
authenticate the VFN server using the available discovery information.
```

**File:** config/src/config/network_config.rs (L158-158)
```rust
            inbound_rate_limit_config: None,
```
