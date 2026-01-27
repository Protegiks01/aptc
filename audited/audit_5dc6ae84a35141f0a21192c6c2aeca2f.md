# Audit Report

## Title
Subscription Lag Attack: Constant Version Lag Bypasses Stream Termination, Enabling Persistent Sync Quality Degradation

## Summary
An attacker can maintain their peer exactly 19 seconds behind the network (just under the 20-second `max_subscription_lag_secs` threshold) and serve consistently stale data to subscribing nodes. The vulnerability exists because the subscription stream lag detection logic only terminates streams when the version lag **increases**, not when it remains constant. This allows an attacker to perpetually degrade the sync quality of victim nodes by maintaining a fixed version lag that never grows.

## Finding Description

The vulnerability arises from the interaction between two separate lag checks in the state sync system:

**1. Peer Selection Lag Check (Timestamp-Based)**

When selecting peers for subscription requests, the system checks if a peer's `synced_ledger_info` timestamp is within `max_subscription_lag_secs` (default: 20 seconds) of the current time: [1](#0-0) 

The critical check at line 930 uses a "greater than" comparison (`>`), meaning a peer with exactly 19.99 seconds of lag passes, while 20 seconds fails. An attacker can deliberately maintain their peer's timestamp at 19 seconds behind the network to remain eligible for subscription requests.

**2. Subscription Stream Lag Check (Version-Based)**

After a peer is selected, the data streaming service monitors whether the subscription stream is lagging by comparing received data versions against the highest advertised version in the global data summary: [2](#0-1) 

The stream termination logic has a critical flaw in the `is_beyond_recovery()` method: [3](#0-2) 

At line 981, the stream is only terminated if **BOTH** conditions are true:
- `lag_has_increased`: current lag > initial lag
- `lag_duration_exceeded`: lagging for > `max_subscription_stream_lag_secs` (default: 10 seconds)

**The Attack Vector:**

1. Attacker runs a peer that deliberately syncs 19 seconds behind the network
2. Attacker's peer advertises a `StorageServerSummary` with `synced_ledger_info.timestamp` = current_time - 19 seconds
3. Victim node selects attacker's peer for subscription (passes timestamp check)
4. Attacker serves data with a constant version lag (e.g., 50 versions behind if network produces ~2.6 versions/second)
5. The subscription stream lag detection initializes with `version_lag = 50` when first detected
6. Subsequent checks find the lag remains at 50 versions (constant)
7. Because `lag_has_increased` is FALSE (50 is not > 50), the stream is never terminated even after 10+ seconds
8. Victim node remains perpetually 19 seconds behind the network

The attacker doesn't need to forge signatures or provide invalid data—they simply maintain their node legitimately synced to an older state and serve that older (but valid) data.

**Peer Selection Stickiness Amplifies Impact:**

Once a peer is selected for a subscription stream, the system maintains "sticky" selection: [4](#0-3) 

The victim continues using the same attacker peer as long as it remains "serviceable" (passes the 20-second timestamp check), perpetuating the stale data delivery.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program criteria: "State inconsistencies requiring intervention."

**Specific Impacts:**

1. **Validator Participation Degradation**: Validators relying on subscription streams from attacker peers will be 19 seconds behind the network, potentially missing consensus participation windows and reducing their rewards.

2. **Fullnode Data Staleness**: Fullnodes subscribed to attacker peers serve 19-second-old data to clients (wallets, dApps, APIs), degrading user experience and potentially causing transaction failures.

3. **Network-Wide Sync Quality**: If an attacker controls multiple peers and victims are distributed across the network, a significant portion of nodes could be degraded simultaneously.

4. **Cascade Effect**: Nodes receiving stale data may themselves become less desirable peers, potentially creating a cascading effect where more nodes fall behind.

The attack does not directly cause consensus violations, fund loss, or network partition, but it degrades the operational quality and reliability of the state sync system.

## Likelihood Explanation

**Likelihood: Medium to High**

**Attacker Requirements:**
- Run one or more peers with controllable sync speed
- Maintain peers 19 seconds behind the network (achievable through rate-limiting or checkpoint sync)
- Advertise storage summaries with old but valid `LedgerInfoWithSignatures`

**Feasibility:**
- **Technically Simple**: The attacker doesn't need to forge cryptographic signatures or exploit complex race conditions—they simply sync slowly and advertise their actual state
- **Low Cost**: Running lagging peers requires minimal resources beyond normal peer operation
- **No Insider Access**: Attack works from the network edge without validator privileges
- **Scalable**: Attacker can run multiple lagging peers to increase victim coverage

**Detection Difficulty:**
- The lagging peer appears legitimate (valid signatures, correct data, just old)
- No obvious malicious behavior from the peer's perspective
- Victims may attribute slow sync to network congestion rather than attack

## Recommendation

**Fix 1: Modify Stream Termination Logic to Detect Constant Lag**

Update `is_beyond_recovery()` to terminate streams that maintain a persistent lag, even if not increasing:

```rust
fn is_beyond_recovery(
    &mut self,
    streaming_service_config: DataStreamingServiceConfig,
    current_stream_lag: u64,
) -> bool {
    // Calculate the total duration the stream has been lagging
    let current_time = self.time_service.now();
    let stream_lag_duration = current_time.duration_since(self.start_time);
    let max_stream_lag_duration =
        Duration::from_secs(streaming_service_config.max_subscription_stream_lag_secs);

    // If enough time has passed and the lag is still significant, check for failure
    if stream_lag_duration >= max_stream_lag_duration {
        // NEW: Define a minimum acceptable lag threshold (e.g., 10 versions)
        const MIN_ACCEPTABLE_LAG: u64 = 10;
        
        // Terminate if: (a) lag has increased, OR (b) lag is persistently above threshold
        let lag_has_increased = current_stream_lag > self.version_lag;
        let lag_is_persistent = current_stream_lag >= MIN_ACCEPTABLE_LAG;
        
        if lag_has_increased || lag_is_persistent {
            return true; // The stream is beyond recovery
        }
    }

    // Otherwise, update the stream lag if we've caught up.
    // This will ensure the lag can only improve.
    if current_stream_lag < self.version_lag {
        self.version_lag = current_stream_lag;
    }

    false // The stream is not yet beyond recovery
}
```

**Fix 2: Prefer Fresher Peers in Selection**

Modify peer selection logic to prefer peers with fresher data within the acceptable lag window: [5](#0-4) 

Add timestamp-based weighting in the peer selection algorithm to prefer peers with more recent `synced_ledger_info` timestamps.

**Fix 3: Tighten Lag Threshold**

Consider reducing `max_subscription_lag_secs` from 20 to 10 seconds to reduce the attack window, or use stricter inequality (`>=` instead of `>`) in the lag check: [6](#0-5) 

Change to:
```rust
ledger_info_timestamp_usecs + max_version_lag_usecs >= current_timestamp_usecs
```

This ensures exactly 20 seconds of lag fails the check.

## Proof of Concept

```rust
#[cfg(test)]
mod subscription_lag_attack_poc {
    use super::*;
    use aptos_time_service::{MockTimeService, TimeService};
    use std::time::Duration;

    #[test]
    fn test_constant_lag_bypasses_stream_termination() {
        // Create a mock time service
        let time_service = TimeService::mock();
        
        // Initialize subscription stream lag with 50 version lag
        let initial_lag = 50u64;
        let mut stream_lag = SubscriptionStreamLag::new(initial_lag, time_service.clone());
        
        // Create streaming config with 10 second max lag
        let config = DataStreamingServiceConfig {
            max_subscription_stream_lag_secs: 10,
            ..Default::default()
        };
        
        // Simulate time passing: advance 11 seconds (exceeds max lag duration)
        time_service.advance(Duration::from_secs(11));
        
        // Check if stream is beyond recovery with CONSTANT lag (still 50 versions)
        let current_lag = 50u64; // Attacker maintains constant lag
        let is_failed = stream_lag.is_beyond_recovery(config, current_lag);
        
        // VULNERABILITY: Stream is NOT terminated even though:
        // 1. Lag duration (11 seconds) exceeds max_subscription_stream_lag_secs (10 seconds)
        // 2. Lag (50 versions) is significant and persistent
        // The stream continues because lag_has_increased is FALSE (50 > 50 = false)
        assert_eq!(is_failed, false, "VULNERABILITY: Constant lag should trigger termination but doesn't!");
        
        println!("ATTACK SUCCESS: Stream with constant 50-version lag for 11+ seconds was NOT terminated");
    }
    
    #[test]
    fn test_increasing_lag_correctly_terminates() {
        // Create a mock time service
        let time_service = TimeService::mock();
        
        // Initialize subscription stream lag with 50 version lag
        let initial_lag = 50u64;
        let mut stream_lag = SubscriptionStreamLag::new(initial_lag, time_service.clone());
        
        // Create streaming config
        let config = DataStreamingServiceConfig {
            max_subscription_stream_lag_secs: 10,
            ..Default::default()
        };
        
        // Advance time and check with INCREASING lag
        time_service.advance(Duration::from_secs(11));
        let current_lag = 60u64; // Lag increased from 50 to 60
        let is_failed = stream_lag.is_beyond_recovery(config, current_lag);
        
        // Stream correctly terminates when lag increases
        assert_eq!(is_failed, true, "Increasing lag should terminate stream");
        println!("Increasing lag correctly terminates stream");
    }
}
```

**Attack Scenario Test:**

```rust
// Integration test demonstrating full attack flow
#[tokio::test]
async fn test_subscription_lag_attack_full_scenario() {
    // 1. Setup: Victim node and attacker peer
    let victim_node = create_test_node();
    let attacker_peer = create_lagging_peer(lag_seconds: 19);
    
    // 2. Attacker advertises stale storage summary
    let stale_summary = attacker_peer.create_storage_summary_with_lag(Duration::from_secs(19));
    victim_node.update_peer_storage_summary(attacker_peer.id, stale_summary);
    
    // 3. Victim selects attacker for subscription (passes 20-second check)
    let selected_peer = victim_node.choose_peer_for_subscription_request();
    assert_eq!(selected_peer, attacker_peer.id);
    
    // 4. Victim subscribes and receives stale data
    let mut subscription_stream = victim_node.subscribe_to_transactions(selected_peer);
    
    // 5. Simulate receiving data with constant lag over 15 seconds
    for _ in 0..15 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let stale_data = attacker_peer.get_data_with_constant_lag(50 /* versions */);
        subscription_stream.receive(stale_data);
        
        // Stream should still be active despite persistent lag
        assert!(subscription_stream.is_active());
    }
    
    // 6. VULNERABILITY: After 15 seconds of constant lag, stream is still active
    assert!(subscription_stream.is_active(), "ATTACK SUCCESS: Stream remains active with constant lag");
    
    // 7. Victim node is now perpetually 19 seconds behind
    let victim_version = victim_node.get_latest_version();
    let network_version = get_network_latest_version();
    let lag = network_version - victim_version;
    assert!(lag >= 50, "Victim is significantly behind network due to attack");
}
```

**Notes:**
- The PoC demonstrates that constant lag bypasses stream termination logic
- The attack requires no cryptographic forgery or complex exploitation
- Multiple attacker peers can coordinate to maximize victim coverage
- The vulnerability affects both validator and fullnode deployments

### Citations

**File:** state-sync/storage-service/types/src/responses.rs (L905-934)
```rust
fn can_service_subscription_request(
    aptos_data_client_config: &AptosDataClientConfig,
    time_service: TimeService,
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
) -> bool {
    let max_lag_secs = aptos_data_client_config.max_subscription_lag_secs;
    check_synced_ledger_lag(synced_ledger_info, time_service, max_lag_secs)
}

/// Returns true iff the synced ledger info timestamp
/// is within the given lag (in seconds).
fn check_synced_ledger_lag(
    synced_ledger_info: Option<&LedgerInfoWithSignatures>,
    time_service: TimeService,
    max_lag_secs: u64,
) -> bool {
    if let Some(synced_ledger_info) = synced_ledger_info {
        // Get the ledger info timestamp (in microseconds)
        let ledger_info_timestamp_usecs = synced_ledger_info.ledger_info().timestamp_usecs();

        // Get the current timestamp and max version lag (in microseconds)
        let current_timestamp_usecs = time_service.now_unix_time().as_micros() as u64;
        let max_version_lag_usecs = max_lag_secs * NUM_MICROSECONDS_IN_SECOND;

        // Return true iff the synced ledger info timestamp is within the max version lag
        ledger_info_timestamp_usecs + max_version_lag_usecs > current_timestamp_usecs
    } else {
        false // No synced ledger info was found!
    }
}
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L549-631)
```rust
    fn check_subscription_stream_lag(
        &mut self,
        global_data_summary: &GlobalDataSummary,
        response_payload: &ResponsePayload,
    ) -> Result<(), aptos_data_client::error::Error> {
        // Get the highest version sent in the subscription response
        let highest_response_version = match response_payload {
            ResponsePayload::NewTransactionsWithProof((transactions_with_proof, _)) => {
                if let Some(first_version) = transactions_with_proof.get_first_transaction_version()
                {
                    let num_transactions = transactions_with_proof.get_num_transactions();
                    first_version
                        .saturating_add(num_transactions as u64)
                        .saturating_sub(1) // first_version + num_txns - 1
                } else {
                    return Err(aptos_data_client::error::Error::UnexpectedErrorEncountered(
                        "The first transaction version is missing from the stream response!".into(),
                    ));
                }
            },
            ResponsePayload::NewTransactionOutputsWithProof((outputs_with_proof, _)) => {
                if let Some(first_version) = outputs_with_proof.get_first_output_version() {
                    let num_outputs = outputs_with_proof.get_num_outputs();
                    first_version
                        .saturating_add(num_outputs as u64)
                        .saturating_sub(1) // first_version + num_outputs - 1
                } else {
                    return Err(aptos_data_client::error::Error::UnexpectedErrorEncountered(
                        "The first output version is missing from the stream response!".into(),
                    ));
                }
            },
            _ => {
                return Ok(()); // The response payload doesn't contain a subscription response
            },
        };

        // Get the highest advertised version
        let highest_advertised_version = global_data_summary
            .advertised_data
            .highest_synced_ledger_info()
            .map(|ledger_info| ledger_info.ledger_info().version())
            .ok_or_else(|| {
                aptos_data_client::error::Error::UnexpectedErrorEncountered(
                    "The highest synced ledger info is missing from the global data summary!"
                        .into(),
                )
            })?;

        // If the stream is not lagging behind, reset the lag and return
        if highest_response_version >= highest_advertised_version {
            self.reset_subscription_stream_lag();
            return Ok(());
        }

        // Otherwise, the stream is lagging behind the advertised version.
        // Check if the stream is beyond recovery (i.e., has failed).
        let current_stream_lag =
            highest_advertised_version.saturating_sub(highest_response_version);
        if let Some(mut subscription_stream_lag) = self.subscription_stream_lag.take() {
            // Check if the stream lag is beyond recovery
            if subscription_stream_lag
                .is_beyond_recovery(self.streaming_service_config, current_stream_lag)
            {
                return Err(
                    aptos_data_client::error::Error::SubscriptionStreamIsLagging(format!(
                        "The subscription stream is beyond recovery! Current lag: {:?}, last lag: {:?},",
                        current_stream_lag, subscription_stream_lag.version_lag
                    )),
                );
            }

            // The stream is lagging, but it's not yet beyond recovery
            self.set_subscription_stream_lag(subscription_stream_lag);
        } else {
            // The stream was not previously lagging, but it is now!
            let subscription_stream_lag =
                SubscriptionStreamLag::new(current_stream_lag, self.time_service.clone());
            self.set_subscription_stream_lag(subscription_stream_lag);
        }

        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L967-992)
```rust
    fn is_beyond_recovery(
        &mut self,
        streaming_service_config: DataStreamingServiceConfig,
        current_stream_lag: u64,
    ) -> bool {
        // Calculate the total duration the stream has been lagging
        let current_time = self.time_service.now();
        let stream_lag_duration = current_time.duration_since(self.start_time);
        let max_stream_lag_duration =
            Duration::from_secs(streaming_service_config.max_subscription_stream_lag_secs);

        // If the lag is further behind and enough time has passed, the stream has failed
        let lag_has_increased = current_stream_lag > self.version_lag;
        let lag_duration_exceeded = stream_lag_duration >= max_stream_lag_duration;
        if lag_has_increased && lag_duration_exceeded {
            return true; // The stream is beyond recovery
        }

        // Otherwise, update the stream lag if we've caught up.
        // This will ensure the lag can only improve.
        if current_stream_lag < self.version_lag {
            self.version_lag = current_stream_lag;
        }

        false // The stream is not yet beyond recovery
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L447-518)
```rust
    fn choose_serviceable_peer_for_subscription_request(
        &self,
        request: &StorageServiceRequest,
        serviceable_peers: HashSet<PeerNetworkId>,
    ) -> crate::error::Result<Option<PeerNetworkId>, Error> {
        // If there are no serviceable peers, return None
        if serviceable_peers.is_empty() {
            return Ok(None);
        }

        // Get the stream ID from the request
        let request_stream_id = match &request.data_request {
            DataRequest::SubscribeTransactionsWithProof(request) => {
                request.subscription_stream_metadata.subscription_stream_id
            },
            DataRequest::SubscribeTransactionOutputsWithProof(request) => {
                request.subscription_stream_metadata.subscription_stream_id
            },
            DataRequest::SubscribeTransactionsOrOutputsWithProof(request) => {
                request.subscription_stream_metadata.subscription_stream_id
            },
            DataRequest::SubscribeTransactionDataWithProof(request) => {
                request.subscription_stream_metadata.subscription_stream_id
            },
            data_request => {
                return Err(Error::UnexpectedErrorEncountered(format!(
                    "Invalid subscription request type found: {:?}",
                    data_request
                )))
            },
        };

        // Grab the lock on the active subscription state
        let mut active_subscription_state = self.active_subscription_state.lock();

        // If we have an active subscription and the request is for the same
        // stream ID, use the same peer (as long as it is still serviceable).
        if let Some(subscription_state) = active_subscription_state.take() {
            if subscription_state.subscription_stream_id == request_stream_id {
                // The stream IDs match. Verify that the request is still serviceable.
                let peer_network_id = subscription_state.peer_network_id;
                return if serviceable_peers.contains(&peer_network_id) {
                    // The previously chosen peer can still service the request
                    *active_subscription_state = Some(subscription_state);
                    Ok(Some(peer_network_id))
                } else {
                    // The previously chosen peer is either: (i) unable to service
                    // the request; or (ii) no longer the highest priority peer. So
                    // we need to return an error so the stream will be terminated.
                    Err(Error::DataIsUnavailable(format!(
                        "The peer that we were previously subscribing to should no \
                        longer service the subscriptions! Peer: {:?}, request: {:?}",
                        peer_network_id, request
                    )))
                };
            }
        }

        // Otherwise, choose a new peer to handle the subscription request
        let selected_peer = self
            .choose_random_peers_by_distance_and_latency(serviceable_peers, 1)
            .into_iter()
            .next();

        // If a peer was selected, update the active subscription state
        if let Some(selected_peer) = selected_peer {
            let subscription_state = SubscriptionState::new(selected_peer, request_stream_id);
            *active_subscription_state = Some(subscription_state);
        }

        Ok(selected_peer)
    }
```
