# Audit Report

## Title
Memory Exhaustion via Unbounded Message Cloning in Consensus Observer Publisher

## Summary
The `publish_message()` function in the consensus observer publisher clones large consensus messages for each subscriber without implementing subscriber limits or using Arc-based message sharing. An attacker can subscribe multiple malicious observer nodes to a validator and trigger memory allocation spikes through repeated message clones, causing validator performance degradation and potential crashes.

## Finding Description

The consensus observer publisher accepts subscription requests from any connected peer without authentication. The Subscribe request handler directly adds peers to the active subscribers set with no validation: [1](#0-0) 

The `add_active_subscriber` method performs no limit checking, unlike the storage service subscription system which enforces `max_num_active_subscriptions`: [2](#0-1) 

Compare this to the storage service which properly validates subscriber limits: [3](#0-2) 

When publishing messages, the `publish_message()` function clones the message for each active subscriber: [4](#0-3) 

The critical issue is that `ConsensusObserverDirectSend::BlockPayload` contains non-Arc-wrapped transaction vectors that are fully deep-copied on each clone: [5](#0-4) [6](#0-5) 

The network layer allows up to 100 inbound connections by default: [7](#0-6) 

The consensus observer publisher is enabled on validators by default: [8](#0-7) [9](#0-8) 

**Attack Execution:**

1. Attacker establishes connections from up to 100 malicious observer nodes to target validator
2. Each node sends a Subscribe request (no authentication required)
3. All 100 subscriptions are accepted without limit checking
4. When consensus publishes a BlockPayload message (potentially 10+ MB with many transactions), the publisher executes `message.clone()` 100 times
5. Memory allocation occurs before channel capacity check in `try_send()`, so even failed sends allocate memory
6. With blocks produced every 1-2 seconds, sustained memory allocation rate causes allocator contention and performance degradation

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty category "Validator Node Slowdowns" through "DoS via resource exhaustion." 

The memory exhaustion attack causes:

1. **Validator performance degradation**: Memory allocator contention from rapid allocation/deallocation cycles (potentially 1GB per block with 100 subscribers × 10MB messages)
2. **Consensus participation impact**: Slowdowns affect block processing and voting, potentially causing validators to fall behind
3. **Potential validator crashes**: Sustained memory pressure can trigger OOM conditions on validators with limited resources
4. **Targeted attacks**: Attackers can selectively target specific validators to manipulate leader election or block production

This is an implementation vulnerability in the consensus publisher code, not a pure network-layer DoS. The fix requires application-level changes (subscriber limits, Arc-based sharing) rather than network-layer mitigations.

## Likelihood Explanation

This attack is **highly likely** to succeed:

1. **No authentication barrier**: Any network peer can subscribe without credentials
2. **No subscriber limits**: Publisher accepts unlimited subscriptions (unlike storage service which has proper limits)
3. **Network allows sufficient amplification**: Default 100 inbound connections provide substantial amplification factor
4. **Legitimate large messages exist**: Blocks with many transactions naturally produce large payloads that get published
5. **Minimal attacker resources**: 100 lightweight observer processes require minimal infrastructure
6. **Repeatable attack**: Can be sustained as long as blocks are being produced

The attack path is straightforward and requires no insider access or special privileges.

## Recommendation

Implement the following protections:

1. **Add subscriber limit checking** similar to storage service:
```rust
fn add_active_subscriber(&self, peer_network_id: PeerNetworkId) -> Result<(), Error> {
    let mut subscribers = self.active_subscribers.write();
    if subscribers.len() >= self.consensus_observer_config.max_active_subscribers as usize {
        return Err(Error::TooManySubscribers);
    }
    subscribers.insert(peer_network_id);
    Ok(())
}
```

2. **Use Arc-based message sharing** to avoid expensive clones:
```rust
pub fn publish_message(&self, message: Arc<ConsensusObserverDirectSend>) {
    for peer_network_id in &self.get_active_subscribers() {
        let message_clone = Arc::clone(&message);
        // Send Arc clone instead of deep copy
    }
}
```

3. **Add message size validation** before publishing to prevent excessively large messages

4. **Implement rate limiting** on subscription requests to prevent rapid subscription attacks

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating 100 observer node connections to a validator
2. Sending Subscribe requests from each node
3. Monitoring validator memory usage as BlockPayload messages are published
4. Observing memory allocation spikes of ~1GB per block (100 clones × 10MB message)
5. Measuring validator performance degradation through increased latency and potential consensus timeout failures

### Citations

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L94-95)
```rust
    fn add_active_subscriber(&self, peer_network_id: PeerNetworkId) {
        self.active_subscribers.write().insert(peer_network_id);
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L181-192)
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

**File:** state-sync/storage-service/server/src/subscription.rs (L370-381)
```rust
        // Verify that the number of active subscriptions respects the maximum
        let max_num_active_subscriptions =
            storage_service_config.max_num_active_subscriptions as usize;
        if self.pending_subscription_requests.len() >= max_num_active_subscriptions {
            return Err((
                Error::InvalidRequest(format!(
                    "The maximum number of active subscriptions has been reached! Max: {:?}, found: {:?}",
                    max_num_active_subscriptions, self.pending_subscription_requests.len()
                )),
                subscription_request,
            ));
        }
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L379-390)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayloadWithProof {
    transactions: Vec<SignedTransaction>,
    proofs: Vec<ProofOfStore<BatchInfo>>,
}

impl PayloadWithProof {
    pub fn new(transactions: Vec<SignedTransaction>, proofs: Vec<ProofOfStore<BatchInfo>>) -> Self {
        Self {
            transactions,
            proofs,
        }
```

**File:** consensus/src/consensus_observer/network/observer_message.rs (L840-851)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockPayload {
    block: BlockInfo,
    transaction_payload: BlockTransactionPayload,
}

impl BlockPayload {
    pub fn new(block: BlockInfo, transaction_payload: BlockTransactionPayload) -> Self {
        Self {
            block,
            transaction_payload,
        }
```

**File:** config/src/config/network_config.rs (L44-44)
```rust
pub const MAX_INBOUND_CONNECTIONS: usize = 100;
```

**File:** config/src/config/consensus_observer_config.rs (L12-12)
```rust
const ENABLE_ON_VALIDATORS: bool = true;
```

**File:** config/src/config/consensus_observer_config.rs (L112-117)
```rust
            NodeType::Validator => {
                if ENABLE_ON_VALIDATORS && !publisher_manually_set {
                    // Only enable the publisher for validators
                    consensus_observer_config.publisher_enabled = true;
                    modified_config = true;
                }
```
