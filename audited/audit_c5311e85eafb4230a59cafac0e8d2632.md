# Audit Report

## Title
Malicious Publisher Timing Attack Causes Persistent Observer Liveness Degradation via ObserverFallingBehind

## Summary
A malicious consensus publisher can intentionally delay block propagation to trigger `ObserverFallingBehind` errors in consensus observers, forcing them into repeated fallback mode cycles and preventing them from maintaining synchronization with the chain. This creates a persistent liveness attack against observer nodes.

## Finding Description

The consensus observer mechanism relies on publishers to send blocks in a timely manner. The `ObserverFallingBehind` error is designed to detect when an observer has fallen too far behind the network by comparing the timestamp embedded in committed blocks against current wall-clock time. [1](#0-0) 

A malicious publisher can exploit this mechanism through a timing attack:

1. **Block Delay**: The publisher receives blocks from consensus with current timestamps (e.g., block created at time T has timestamp T embedded in it)

2. **Intentional Withholding**: Instead of immediately publishing blocks to subscribed observers, the malicious publisher delays sending them for 16+ seconds (exceeding the `observer_fallback_sync_lag_threshold_ms` of 15 seconds) [2](#0-1) 

3. **Timestamp Lag Detection**: When the observer finally receives and commits these delayed blocks to storage, the fallback manager's health check detects the timestamp lag between the block's embedded timestamp and current time

4. **Forced Fallback**: The `ObserverFallingBehind` error is triggered, causing the observer to:
   - Terminate all active subscriptions
   - Enter fallback mode and invoke state sync
   - Clear pending block state [3](#0-2) 

5. **Subscription Loop**: After fallback completes, the observer creates new subscriptions. If a malicious publisher (or coordinating group of malicious publishers) is selected again, the attack repeats, creating a persistent liveness degradation loop.

The publisher's `publish_message()` method is non-blocking and sends to all active subscribers through an asynchronous channel, making it trivial for a malicious publisher to introduce delays: [4](#0-3) 

**Partial Mitigation Exists But Can Be Bypassed**: The subscription selection logic excludes peers that are currently subscribed to the observer: [5](#0-4) 

However, this mitigation only applies when the observer is also running as a publisher (typical for VFNs). A malicious publisher can bypass this by:
- Not subscribing back to the victim observer
- Coordinating with multiple malicious publishers that rotate as subscribers
- Exploiting configurations where observers don't run publishers

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria for the following reasons:

1. **Validator/VFN Node Slowdowns**: Observer nodes (particularly Validator Full Nodes running in observer mode) experience persistent liveness degradation, unable to maintain synchronization with the chain

2. **Significant Protocol Violation**: The consensus observer mechanism is designed to provide efficient block propagation. This attack fundamentally breaks that guarantee by forcing observers into repeated fallback cycles

3. **Service Disruption**: Dependent services relying on observer nodes (APIs, indexers, etc.) experience degraded performance or complete unavailability as observers cannot keep up with the chain

4. **No Funds at Risk**: While this is a liveness attack, it does not directly lead to theft or loss of funds, preventing it from reaching Critical severity

The impact is amplified because:
- A single malicious publisher can affect multiple observers subscribed to it
- The attack is persistent and self-sustaining once initiated
- No automatic recovery mechanism exists (observers will continue selecting malicious publishers)

## Likelihood Explanation

**Likelihood: MEDIUM**

Requirements for exploitation:
1. **Compromised Publisher Node**: Attacker must control a validator or VFN running as a consensus publisher
2. **Network Positioning**: The malicious publisher must be selected as optimal by target observers (based on distance from validators and latency metrics)
3. **Coordination** (optional): Multiple malicious publishers can coordinate to maintain persistent attack even with rotation

Factors increasing likelihood:
- VFNs are commonly run by ecosystem participants and could be compromised
- No reputation system or blacklisting exists to avoid problematic publishers
- The attack is simple to execute (just delay message sending)
- Default configuration makes observers vulnerable (15-second threshold is easily exceeded)

Factors decreasing likelihood:
- Requires insider access (compromised validator/VFN)
- Partial mitigation exists when observers run as publishers
- Multiple concurrent subscriptions (default 2) provide some redundancy

## Recommendation

Implement multi-layered defenses:

1. **Block Recency Validation**: Before processing received blocks, verify that block timestamps are reasonably close to message arrival time:

```rust
// In consensus_observer.rs, before processing ordered blocks
fn validate_block_recency(
    &self,
    ordered_block: &OrderedBlock,
    message_received_time: Instant,
) -> Result<(), Error> {
    let block_timestamp_usecs = ordered_block.first_block().timestamp_usecs();
    let block_timestamp = Duration::from_micros(block_timestamp_usecs);
    let current_time = self.time_service.now_unix_time();
    
    // Allow some clock skew tolerance (e.g., 5 seconds)
    let max_acceptable_age = Duration::from_secs(5);
    let block_age = current_time.saturating_sub(block_timestamp);
    
    if block_age > max_acceptable_age {
        return Err(Error::InvalidMessageError(format!(
            "Block timestamp too old: block_timestamp={:?}, current_time={:?}, age={:?}",
            block_timestamp, current_time, block_age
        )));
    }
    Ok(())
}
```

2. **Publisher Reputation System**: Track publishers that repeatedly cause fallback and deprioritize them in subscription selection:

```rust
// Add to SubscriptionManager
struct PublisherReputation {
    peer: PeerNetworkId,
    fallback_count: u64,
    last_fallback_time: Instant,
}

// Maintain reputation scores and filter out publishers with poor reputation
// when sorting peers for subscription
```

3. **Adaptive Threshold**: Adjust `observer_fallback_sync_lag_threshold_ms` based on network conditions and publisher behavior

4. **Explicit Blacklisting**: When a subscription causes `ObserverFallingBehind`, temporarily blacklist that publisher from re-selection:

```rust
// In subscription_manager.rs
fn terminate_unhealthy_subscriptions(...) {
    for (peer_network_id, error) in terminated_subscriptions {
        if matches!(error, Error::ObserverFallingBehind(_)) {
            // Add to temporary blacklist with exponential backoff
            self.blacklist_publisher(peer_network_id, Duration::from_secs(300));
        }
    }
}
```

## Proof of Concept

```rust
#[tokio::test]
async fn test_malicious_publisher_timing_attack() {
    // Setup: Create observer and malicious publisher
    let (observer, publisher, mut message_receiver) = setup_observer_and_publisher();
    
    // Simulate consensus creating a block at time T with timestamp T
    let block_timestamp = TimeService::real().now_unix_time();
    let ordered_block = create_ordered_block_with_timestamp(block_timestamp);
    
    // Malicious publisher receives block but delays sending
    let delay = Duration::from_secs(20); // Exceeds 15-second threshold
    
    // Simulate the delay
    tokio::time::sleep(delay).await;
    
    // Publisher finally sends the delayed block
    publisher.publish_message(ordered_block);
    
    // Observer receives and processes the block
    let network_message = message_receiver.next().await.unwrap();
    observer.process_network_message(network_message).await;
    
    // Verify observer detects falling behind
    let check_result = observer.check_progress().await;
    
    // Assert that ObserverFallingBehind was triggered
    assert!(matches!(
        check_result,
        Err(Error::ObserverFallingBehind(_))
    ));
    
    // Verify observer entered fallback mode
    assert!(observer.state_sync_manager.in_fallback_mode());
    
    // Verify all subscriptions were terminated
    assert_eq!(observer.subscription_manager.get_active_subscription_peers().len(), 0);
}
```

## Notes

This vulnerability demonstrates a fundamental tension in distributed systems between liveness and safety. The `ObserverFallingBehind` detection mechanism is designed to protect observers from stale state, but becomes an attack vector when publishers can intentionally manipulate timing.

The attack is particularly concerning because:
- It exploits legitimate error handling mechanisms
- No authentication or authorization can prevent it (publishers are trusted)
- The impact compounds over time as observers repeatedly cycle through fallback
- Current mitigations are incomplete and can be circumvented

Organizations running observer nodes should monitor for repeated fallback events from the same publishers and implement manual blacklisting until systematic fixes are deployed.

### Citations

**File:** consensus/src/consensus_observer/observer/fallback_manager.rs (L119-154)
```rust
    /// Verifies that the sync lag is within acceptable limits. If not, an error is returned.
    fn verify_sync_lag_health(&self, latest_ledger_info_version: Version) -> Result<(), Error> {
        // Get the latest block timestamp from storage
        let latest_block_timestamp_usecs = match self
            .db_reader
            .get_block_timestamp(latest_ledger_info_version)
        {
            Ok(block_timestamp_usecs) => block_timestamp_usecs,
            Err(error) => {
                // Log a warning and return without entering fallback mode
                warn!(LogSchema::new(LogEntry::ConsensusObserver)
                    .message(&format!("Failed to read block timestamp: {:?}", error)));
                return Ok(());
            },
        };

        // Get the current time (in microseconds)
        let timestamp_now_usecs = self.time_service.now_unix_time().as_micros() as u64;

        // Calculate the block timestamp lag (saturating at 0)
        let timestamp_lag_usecs = timestamp_now_usecs.saturating_sub(latest_block_timestamp_usecs);
        let timestamp_lag_duration = Duration::from_micros(timestamp_lag_usecs);

        // Check if the sync lag is within acceptable limits
        let sync_lag_threshold_ms = self
            .consensus_observer_config
            .observer_fallback_sync_lag_threshold_ms;
        if timestamp_lag_duration > Duration::from_millis(sync_lag_threshold_ms) {
            return Err(Error::ObserverFallingBehind(format!(
                "Consensus observer is falling behind! Highest synced version: {}, sync lag: {:?}",
                latest_ledger_info_version, timestamp_lag_duration
            )));
        }

        Ok(())
    }
```

**File:** config/src/config/consensus_observer_config.rs (L59-60)
```rust
    /// Duration (in milliseconds) of acceptable sync lag before entering fallback mode
    pub observer_fallback_sync_lag_threshold_ms: u64,
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L191-201)
```rust
        if let Err(error) = self.observer_fallback_manager.check_syncing_progress() {
            // Log the error and enter fallback mode
            warn!(
                LogSchema::new(LogEntry::ConsensusObserver).message(&format!(
                    "Failed to make syncing progress! Entering fallback mode! Error: {:?}",
                    error
                ))
            );
            self.enter_fallback_mode().await;
            return;
        }
```

**File:** consensus/src/consensus_observer/publisher/consensus_publisher.rs (L210-232)
```rust
    /// Publishes a direct send message to all active subscribers. Note: this method
    /// is non-blocking (to avoid blocking callers during publishing, e.g., consensus).
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

**File:** consensus/src/consensus_observer/observer/subscription_utils.rs (L262-266)
```rust
    if let Some(consensus_publisher) = consensus_publisher {
        for peer_network_id in consensus_publisher.get_active_subscribers() {
            let _ = connected_peers_and_metadata.remove(&peer_network_id);
        }
    }
```
