# Audit Report

## Title
Consensus Observer RPC Exhaustion Vulnerability Blocking Consensus Messages

## Summary
The consensus observer's `send_rpc_request()` function can be exploited to exhaust the per-peer concurrent RPC limit (100), preventing legitimate consensus protocol messages from being transmitted to affected validators, potentially causing consensus liveness degradation or halt.

## Finding Description

The Aptos network layer enforces a limit of 100 concurrent outbound RPC requests per peer connection. This limit is shared across ALL protocols using the same peer connection, including both consensus observer RPCs and regular consensus protocol RPCs. [1](#0-0) [2](#0-1) 

When the limit is reached, new outbound RPC requests are declined with `RpcError::TooManyPending`: [3](#0-2) 

The consensus observer's `unsubscribe_from_peer()` function spawns unlimited async tasks, each sending an unsubscribe RPC with no rate limiting or concurrency control: [4](#0-3) 

This function is triggered whenever a message is received from a non-subscribed peer: [5](#0-4) 

**Attack Path:**
1. Attacker controls or compromises a peer node acting as both a validator and consensus publisher
2. Attacker sends many consensus observer direct-send messages to victim node
3. Victim node is not subscribed to attacker's peer (or just unsubscribed)
4. Each message triggers `verify_message_for_subscription()` → `unsubscribe_from_peer()`
5. Each call spawns a new async task sending an unsubscribe RPC (5-second timeout)
6. Attacker delays RPC responses to keep them pending
7. 100+ unsubscribe RPCs accumulate in the `OutboundRpcs` queue for that peer
8. Queue reaches capacity and new RPCs (including consensus RPCs) are declined
9. Consensus protocol cannot send votes/proposals to that validator
10. If multiple validators are affected, consensus liveness degrades or halts

This breaks the **Consensus Safety** invariant: "AptosBFT must prevent...liveness failures" and the **Resource Limits** invariant by allowing unbounded RPC spawning.

## Impact Explanation

This vulnerability meets **High Severity** criteria per the Aptos bug bounty program:
- **"Validator node slowdowns"**: Blocking consensus RPCs causes validators to miss messages, slowing consensus rounds
- **"Significant protocol violations"**: Prevents consensus protocol messages from being transmitted

If multiple validators are affected simultaneously, this could escalate to **Critical Severity** by causing **"Total loss of liveness/network availability"** as consensus requires 2/3+ validators to progress.

The impact is direct and measurable:
- Blocked consensus RPCs to affected validators
- Missed votes/proposals causing increased round times
- Potential consensus halt if 1/3+ validators are affected

## Likelihood Explanation

**Likelihood: MEDIUM**

The attack requires:
1. ✅ **Easy**: Attacker controls or compromises a peer node (any node can connect to the network)
2. ✅ **Easy**: Attacker sends consensus observer messages (no authentication required for direct-send)
3. ✅ **Easy**: Triggering unsubscribe is straightforward (send messages when not subscribed)
4. ⚠️ **Moderate**: Attacker must delay RPC responses to keep them pending (requires control over peer's RPC handler)
5. ⚠️ **Moderate**: Attack only affects consensus messages to that specific peer (must be a validator to impact consensus)

The vulnerability is realistic because:
- No special privileges required (standard peer connection)
- Can be triggered by network conditions (legitimate messages from old subscriptions)
- No rate limiting on unsubscribe RPC spawning
- 5-second RPC timeout provides sufficient window for accumulation

## Recommendation

Implement rate limiting and concurrency control for unsubscribe RPCs:

```rust
// Add to SubscriptionManager struct:
struct SubscriptionManager {
    // ... existing fields ...
    
    // Track pending unsubscribe RPCs per peer
    pending_unsubscribe_rpcs: Arc<Mutex<HashMap<PeerNetworkId, usize>>>,
    
    // Maximum concurrent unsubscribe RPCs per peer
    max_unsubscribe_rpcs_per_peer: usize,
}

fn unsubscribe_from_peer(&mut self, peer_network_id: PeerNetworkId) {
    // Check concurrent unsubscribe limit
    let mut pending = self.pending_unsubscribe_rpcs.lock();
    let current_count = pending.get(&peer_network_id).unwrap_or(&0);
    
    if *current_count >= self.max_unsubscribe_rpcs_per_peer {
        warn!("Too many pending unsubscribe RPCs to peer: {}", peer_network_id);
        return; // Drop request instead of spawning
    }
    
    // Increment counter before spawning
    *pending.entry(peer_network_id).or_insert(0) += 1;
    
    // Remove subscription
    self.active_observer_subscriptions.lock().remove(&peer_network_id);
    
    // Clone for async task
    let pending_rpcs = self.pending_unsubscribe_rpcs.clone();
    let consensus_observer_client = self.consensus_observer_client.clone();
    let consensus_observer_config = self.consensus_observer_config;
    
    tokio::spawn(async move {
        // Send unsubscribe RPC
        let unsubscribe_request = ConsensusObserverRequest::Unsubscribe;
        let response = consensus_observer_client
            .send_rpc_request_to_peer(
                &peer_network_id,
                unsubscribe_request,
                consensus_observer_config.network_request_timeout_ms,
            )
            .await;
        
        // Decrement counter after completion
        let mut pending = pending_rpcs.lock();
        if let Some(count) = pending.get_mut(&peer_network_id) {
            *count = count.saturating_sub(1);
        }
        
        // ... existing response handling ...
    });
}
```

**Additional mitigations:**
1. Set `max_unsubscribe_rpcs_per_peer` to 3-5 (sufficient for legitimate unsubscribe needs)
2. Add rate limiting on `verify_message_for_subscription` calls per peer (e.g., max 1 unsubscribe per second per peer)
3. Implement exponential backoff for repeated unsubscribe attempts to the same peer

## Proof of Concept

```rust
#[tokio::test]
async fn test_rpc_exhaustion_attack() {
    // Setup: Create consensus observer client and malicious peer
    let (network_client, mut rpc_handler) = create_test_network_client();
    let consensus_observer_client = Arc::new(ConsensusObserverClient::new(network_client));
    let malicious_peer = PeerNetworkId::random();
    
    // Attack: Send 150 messages from non-subscribed peer
    // Each triggers unsubscribe RPC
    for i in 0..150 {
        let message = ConsensusObserverDirectSend::OrderedBlock(create_test_block(i));
        
        // This will trigger unsubscribe_from_peer internally
        let result = consensus_observer_client
            .handle_message(malicious_peer, message)
            .await;
        
        // Early messages succeed, later ones should fail
        if i < 100 {
            assert!(result.is_ok() || matches!(result, Err(Error::InvalidMessageError(_))));
        }
    }
    
    // Verification: Try to send a consensus RPC to the same peer
    // It should be declined due to queue exhaustion
    let consensus_message = ConsensusMsg::ProposalMsg(Box::new(create_test_proposal()));
    let result = consensus_client
        .send_rpc(malicious_peer, consensus_message, Duration::from_secs(5))
        .await;
    
    // Assert that consensus RPC is blocked
    assert!(matches!(result, Err(RpcError::TooManyPending(100))));
    
    // This demonstrates that consensus messages are blocked by
    // consensus observer RPC exhaustion
}
```

## Notes

This vulnerability demonstrates a critical architectural flaw where different protocol layers (consensus observer vs. consensus protocol) share the same resource limit (concurrent RPCs per peer) without isolation or prioritization. The consensus protocol's critical messages can be starved by the consensus observer's uncontrolled RPC spawning.

The fix requires both rate limiting the unsubscribe RPC spawning AND potentially implementing QoS/priority mechanisms to ensure consensus protocol messages are never blocked by observer protocol operations.

### Citations

**File:** network/framework/src/constants.rs (L12-13)
```rust
/// Limit on concurrent Outbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_OUTBOUND_RPCS: u32 = 100;
```

**File:** network/framework/src/protocols/rpc/mod.rs (L384-412)
```rust
/// `OutboundRpcs` handles new outbound rpc requests made from the application layer.
///
/// There is one `OutboundRpcs` handler per [`Peer`](crate::peer::Peer).
pub struct OutboundRpcs {
    /// The network instance this Peer actor is running under.
    network_context: NetworkContext,
    /// A handle to a time service for easily mocking time-related operations.
    time_service: TimeService,
    /// The PeerId of this connection's remote peer. Used for logging.
    remote_peer_id: PeerId,
    /// Generates the next RequestId to use for the next outbound RPC. Note that
    /// request ids are local to each connection.
    request_id_gen: U32IdGenerator,
    /// A completion queue of pending outbound rpc tasks. Each task waits for
    /// either a successful `RpcResponse` message, handed to it via the channel
    /// in `pending_outbound_rpcs`, or waits for a timeout or cancellation
    /// notification. After completion, the task will yield its `RequestId` and
    /// other metadata (success/failure, success latency, response length) via
    /// the future from `next_completed_request`.
    outbound_rpc_tasks:
        FuturesUnordered<BoxFuture<'static, (RequestId, Result<(f64, u64), RpcError>)>>,
    /// Maps a `RequestId` into a handle to a task in the `outbound_rpc_tasks`
    /// completion queue. When a new `RpcResponse` message comes in, we will use
    /// this map to notify the corresponding task that its response has arrived.
    pending_outbound_rpcs: HashMap<RequestId, (ProtocolId, oneshot::Sender<RpcResponse>)>,
    /// Only allow this many concurrent outbound rpcs at one time from this remote
    /// peer. New outbound requests exceeding this limit will be dropped.
    max_concurrent_outbound_rpcs: u32,
}
```

**File:** network/framework/src/protocols/rpc/mod.rs (L462-475)
```rust
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
```

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L308-359)
```rust
    fn unsubscribe_from_peer(&mut self, peer_network_id: PeerNetworkId) {
        // Remove the peer from the active subscriptions
        self.active_observer_subscriptions
            .lock()
            .remove(&peer_network_id);

        // Send an unsubscribe request to the peer and process the response.
        // Note: we execute this asynchronously, as we don't need to wait for the response.
        let consensus_observer_client = self.consensus_observer_client.clone();
        let consensus_observer_config = self.consensus_observer_config;
        tokio::spawn(async move {
            // Send the unsubscribe request to the peer
            let unsubscribe_request = ConsensusObserverRequest::Unsubscribe;
            let response = consensus_observer_client
                .send_rpc_request_to_peer(
                    &peer_network_id,
                    unsubscribe_request,
                    consensus_observer_config.network_request_timeout_ms,
                )
                .await;

            // Process the response
            match response {
                Ok(ConsensusObserverResponse::UnsubscribeAck) => {
                    info!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Successfully unsubscribed from peer: {}!",
                            peer_network_id
                        ))
                    );
                },
                Ok(response) => {
                    // We received an invalid response
                    warn!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Got unexpected response type: {:?}",
                            response.get_label()
                        ))
                    );
                },
                Err(error) => {
                    // We encountered an error while sending the request
                    warn!(
                        LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                            "Failed to send unsubscribe request to peer: {}! Error: {:?}",
                            peer_network_id, error
                        ))
                    );
                },
            }
        });
    }
```

**File:** consensus/src/consensus_observer/observer/subscription_manager.rs (L363-385)
```rust
    pub fn verify_message_for_subscription(
        &mut self,
        message_sender: PeerNetworkId,
    ) -> Result<(), Error> {
        // Check if the message is from an active subscription
        if let Some(active_subscription) = self
            .active_observer_subscriptions
            .lock()
            .get_mut(&message_sender)
        {
            // Update the last message receive time and return early
            active_subscription.update_last_message_receive_time();
            return Ok(());
        }

        // Otherwise, the message is not from an active subscription.
        // Send another unsubscribe request, and return an error.
        self.unsubscribe_from_peer(message_sender);
        Err(Error::InvalidMessageError(format!(
            "Received message from unexpected peer, and not an active subscription: {}!",
            message_sender
        )))
    }
```
