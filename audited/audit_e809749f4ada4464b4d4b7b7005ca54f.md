# Audit Report

## Title
Consensus Observer Publisher Bandwidth Amplification via Unauthorized Subscription Abuse

## Summary
The `ConsensusPublisher` accepts subscription requests from any peer without authorization checks, allowing an attacker to create multiple malicious subscriptions that amplify each block payload broadcast, causing bandwidth exhaustion and denial of service to legitimate downstream observers.

## Finding Description

The vulnerability exists in the consensus observer publishing mechanism. When a Validator Full Node (VFN) operates as both an observer and publisher, it accepts consensus updates from upstream validators and re-publishes them to downstream observers.

**Attack Flow:**

1. **Subscription Phase:** An attacker establishes multiple network connections (up to `max_inbound_connections`, default 100) to a VFN with publishing enabled and sends `Subscribe` requests from each connection. [1](#0-0) 

The publisher accepts all subscriptions without authorization, simply adding each peer to the `active_subscribers` set.

2. **Amplification Phase:** When the VFN processes a block, `get_transactions_for_observer()` is called during block execution: [2](#0-1) 

This triggers publication of the block payload to all subscribers: [3](#0-2) 

3. **Bandwidth Multiplication:** The `publish_message()` function iterates through all active subscribers and sends the full block payload to each: [4](#0-3) 

**Root Cause:** No authorization check exists when processing `Subscribe` requests, and no limit exists on the number of subscribers beyond the network layer's `max_inbound_connections` limit. [5](#0-4) 

**Bandwidth Calculation:**
- Block payload size: ~100 KB to 1 MB (with transactions and proofs)
- Block rate: ~1 per second
- Malicious subscribers: Up to 100 (limited by `max_inbound_connections`)
- Amplified bandwidth: 100 KB × 100 = **10 MB/sec** to **100 MB/sec** outbound

This saturates the VFN's outbound bandwidth, preventing legitimate downstream observers from receiving timely consensus updates, forcing them into fallback mode (state synchronization).

## Impact Explanation

**Severity: Medium**

This vulnerability causes targeted denial of service against legitimate consensus observers by exploiting a protocol-layer amplification flaw. While it doesn't directly compromise consensus safety or validator operations, it violates the **Resource Limits** invariant by allowing unbounded bandwidth consumption through subscription abuse.

Impact categorization per Aptos bug bounty:
- **Not Critical:** Does not affect consensus safety, funds, or validator set
- **Not High:** Does not cause validator slowdowns or crashes (affects VFNs only)
- **Medium:** Causes "state inconsistencies requiring intervention" as downstream observers fall out of sync and must use state sync to recover

The attack specifically harms:
1. Legitimate downstream observers that cannot receive updates
2. VFN operators who incur unexpected bandwidth costs
3. Network observability and redundancy

## Likelihood Explanation

**Likelihood: Medium to High**

The attack is straightforward to execute:
- **Low Barrier:** Requires only standard network connections and protocol messages
- **No Authentication:** No credentials or privileged access needed
- **Bounded Scale:** Limited to `max_inbound_connections` (100) per VFN
- **Detection Difficulty:** Malicious subscriptions appear as legitimate protocol operations

Attack feasibility:
- Attacker establishes 100 TCP connections (trivial)
- Sends `Subscribe` RPC requests (standard protocol operation)
- Maintains connections (requires minimal resources)
- Amplification occurs automatically for each block

The attack is sustainable and difficult to distinguish from legitimate high-subscriber scenarios without additional monitoring.

## Recommendation

Implement multi-layered subscription access control:

**1. Add Peer Authorization Check:**
```rust
// In consensus_publisher.rs, process_network_message()
ConsensusObserverRequest::Subscribe => {
    // Verify peer is authorized to subscribe
    if !self.is_peer_authorized(&peer_network_id) {
        warn!("Rejected unauthorized subscription from {:?}", peer_network_id);
        response_sender.send(ConsensusObserverResponse::SubscriptionRejected);
        return;
    }
    
    // Check subscriber limit
    if self.active_subscribers.read().len() >= self.max_subscribers() {
        warn!("Rejected subscription - max subscribers reached");
        response_sender.send(ConsensusObserverResponse::SubscriptionRejected);
        return;
    }
    
    self.add_active_subscriber(peer_network_id);
    // ... rest of existing code
}
```

**2. Add Configuration for Maximum Subscribers:** [6](#0-5) 

Add field:
```rust
/// Maximum number of active subscribers for the publisher
pub max_publisher_subscribers: u64,
```

With default value of 10-20 for production environments.

**3. Implement Peer Allowlisting:**
Only allow subscriptions from:
- Known validator full nodes
- Peers in a configured allowlist
- Peers that meet minimum stake/reputation requirements

**4. Add Subscription Rate Limiting:**
Limit subscription attempts per peer per time window to prevent rapid reconnection abuse.

## Proof of Concept

```rust
#[tokio::test]
async fn test_subscription_amplification_attack() {
    // Setup: Create a consensus publisher
    let consensus_observer_config = ConsensusObserverConfig::default();
    let network_id = NetworkId::Public;
    let peers_and_metadata = PeersAndMetadata::new(&[network_id]);
    let network_client = NetworkClient::new(vec![], vec![], hashmap![], peers_and_metadata.clone());
    let consensus_observer_client = Arc::new(ConsensusObserverClient::new(network_client));
    
    let (consensus_publisher, mut outbound_message_receiver) = 
        ConsensusPublisher::new(consensus_observer_config, consensus_observer_client);
    
    // Attack Phase 1: Create 100 malicious subscriptions
    let mut malicious_peers = vec![];
    for i in 0..100 {
        let peer_network_id = PeerNetworkId::new(network_id, PeerId::random());
        
        // Send Subscribe request (no authorization check)
        let network_message = ConsensusPublisherNetworkMessage::new(
            peer_network_id,
            ConsensusObserverRequest::Subscribe,
            ResponseSender::new_for_test(),
        );
        consensus_publisher.process_network_message(network_message);
        malicious_peers.push(peer_network_id);
    }
    
    // Verify all 100 subscriptions were accepted
    let active_subscribers = consensus_publisher.get_active_subscribers();
    assert_eq!(active_subscribers.len(), 100);
    
    // Attack Phase 2: Trigger amplification
    let block_payload = BlockTransactionPayload::new_quorum_store_inline_hybrid(
        vec![/* transactions */],
        vec![/* proofs */],
        Some(1000),
        Some(100_000),
        vec![],
        true,
    );
    
    let message = ConsensusObserverMessage::new_block_payload_message(
        BlockInfo::empty(),
        block_payload,
    );
    
    // Single publish triggers 100 outbound messages
    consensus_publisher.publish_message(message.clone());
    
    // Verify amplification: 100 messages sent (one per malicious subscriber)
    for _ in 0..100 {
        let (peer_network_id, received_message) = outbound_message_receiver.next().await.unwrap();
        assert!(malicious_peers.contains(&peer_network_id));
        assert_eq!(received_message, message);
    }
    
    // Impact: Each legitimate block = 100x bandwidth amplification
    // With 100KB blocks at 1/sec = 10 MB/sec outbound bandwidth consumed
}
```

**Notes**

This vulnerability is distinct from network-level DoS attacks because it exploits an **application-layer protocol design flaw** (missing authorization on `Subscribe` requests) rather than network flooding. The amplification occurs within the consensus observer protocol itself due to the lack of subscriber access control. While the `max_inbound_connections` limit provides some bound (100 connections), this still allows significant bandwidth amplification that can effectively DoS legitimate downstream observers. The fix requires protocol-level changes to add proper authorization and subscriber limits.

### Citations

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L181-183)
```rust
            ConsensusObserverRequest::Subscribe => {
                // Add the peer to the set of active subscribers
                self.add_active_subscriber(peer_network_id);
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

**File:** consensus/src/payload_manager/co_payload_manager.rs (L62-68)
```rust
    if let Some(consensus_publisher) = consensus_publisher {
        let message = ConsensusObserverMessage::new_block_payload_message(
            block.gen_block_info(HashValue::zero(), 0, None),
            transaction_payload.clone(),
        );
        consensus_publisher.publish_message(message);
    }
```

**File:** consensus/src/payload_manager/co_payload_manager.rs (L113-119)
```rust
    async fn get_transactions(
        &self,
        block: &Block,
        _block_signers: Option<BitVec>,
    ) -> ExecutorResult<(Vec<SignedTransaction>, Option<u64>, Option<u64>)> {
        get_transactions_for_observer(block, &self.txns_pool, &self.consensus_publisher).await
    }
```

**File:** config/src/config/consensus_observer_config.rs (L19-61)
```rust
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsensusObserverConfig {
    /// Whether the consensus observer is enabled
    pub observer_enabled: bool,
    /// Whether the consensus publisher is enabled
    pub publisher_enabled: bool,

    /// Maximum number of pending network messages
    pub max_network_channel_size: u64,
    /// Maximum number of parallel serialization tasks for message sends
    pub max_parallel_serialization_tasks: usize,
    /// Timeout (in milliseconds) for network RPC requests
    pub network_request_timeout_ms: u64,

    /// Interval (in milliseconds) to garbage collect peer state
    pub garbage_collection_interval_ms: u64,
    /// Maximum number of blocks to keep in memory (e.g., pending blocks, ordered blocks, etc.)
    pub max_num_pending_blocks: u64,
    /// Interval (in milliseconds) to check progress of the consensus observer
    pub progress_check_interval_ms: u64,

    /// The maximum number of concurrent subscriptions
    pub max_concurrent_subscriptions: u64,
    /// Maximum timeout (in milliseconds) we'll wait for the synced version to
    /// increase before terminating the active subscription.
    pub max_subscription_sync_timeout_ms: u64,
    /// Maximum message timeout (in milliseconds) for active subscriptions
    pub max_subscription_timeout_ms: u64,
    /// Interval (in milliseconds) to check for subscription related peer changes
    pub subscription_peer_change_interval_ms: u64,
    /// Interval (in milliseconds) to refresh the subscription
    pub subscription_refresh_interval_ms: u64,

    /// Duration (in milliseconds) to require state sync to synchronize when in fallback mode
    pub observer_fallback_duration_ms: u64,
    /// Duration (in milliseconds) we'll wait on startup before considering fallback mode
    pub observer_fallback_startup_period_ms: u64,
    /// Duration (in milliseconds) we'll wait for syncing progress before entering fallback mode
    pub observer_fallback_progress_threshold_ms: u64,
    /// Duration (in milliseconds) of acceptable sync lag before entering fallback mode
    pub observer_fallback_sync_lag_threshold_ms: u64,
}
```

**File:** config/src/config/consensus_observer_config.rs (L68-68)
```rust
            max_network_channel_size: 1000,
```
