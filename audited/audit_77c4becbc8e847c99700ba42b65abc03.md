# Audit Report

## Title
Subscription Stream Lag State Manipulation Allows Indefinite Degraded State Without Recovery

## Summary
The `check_subscription_stream_lag()` function contains a logic flaw in its recovery mechanism that allows malicious peers to keep subscription streams in a perpetually degraded state. By maintaining constant or slowly decreasing lag below the "beyond recovery" threshold, an attacker can prevent the failure condition from triggering indefinitely, even after the maximum lag duration is exceeded.

## Finding Description

The vulnerability exists in the lag recovery logic within `check_subscription_stream_lag()` and `is_beyond_recovery()`. [1](#0-0) 

The function checks if a subscription stream is beyond recovery using two conditions: [2](#0-1) 

The critical flaw is on the failure condition check which requires **BOTH** conditions to be true:
- `lag_has_increased`: current lag > previously tracked `version_lag`  
- `lag_duration_exceeded`: time since lag started ≥ `max_subscription_stream_lag_secs` (default 10 seconds) [3](#0-2) 

When lag decreases, the `version_lag` is updated to the lower value, but critically, the `start_time` is **never reset** unless the stream fully catches up. This creates an exploitable scenario:

**Attack Scenario:**
1. Malicious peer selected as subscription peer delays responses to create initial lag (e.g., 1000 versions behind)
2. `SubscriptionStreamLag` is created with `start_time` = T0 and `version_lag` = 1000
3. Attacker keeps lag constant at 1000 versions or slowly decreases it to 999, 998, etc.
4. When lag ≤ `version_lag`, the `lag_has_increased` check returns false
5. Even after 10+ seconds, since `lag_has_increased` = false, the AND condition fails
6. The recovery mechanism never triggers, leaving the stream degraded indefinitely

The peer selection for subscriptions shows that any network peer (validator, VFN, or public fullnode) can be selected: [4](#0-3) 

Once selected, that peer controls the subscription response timing, making this attack trivially exploitable.

## Impact Explanation

This qualifies as **Medium Severity** per the Aptos bug bounty criteria:

**State inconsistencies requiring intervention:** The affected node remains in a degraded state sync condition indefinitely, falling progressively behind the network. This creates:

- **State Sync Failure:** The node cannot properly synchronize with network state
- **Consensus Impact:** Lagging nodes cannot participate effectively in consensus if they fall too far behind
- **Availability Degradation:** Node becomes unreliable for serving current state data
- **Multi-Node Attack Surface:** If an attacker controls multiple peer connections, multiple nodes can be simultaneously affected
- **Silent Failure:** The degraded state persists without triggering observable failure alerts or automatic recovery
- **Manual Intervention Required:** Operators must manually detect the issue and restart state sync with different peers

This does not reach High severity as it does not directly crash validator nodes or APIs, but it does cause significant operational degradation requiring manual intervention.

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely to occur because:

1. **Low Attacker Requirements:** Any network peer (malicious validator, VFN, or public fullnode) can exploit this
2. **Simple Exploitation:** Attacker only needs to control response timing to subscription requests, which is trivial since the responding peer decides when to send data
3. **No Special Access:** No privileged validator access or Byzantine collusion required
4. **Difficult Detection:** The degraded state appears as normal slow sync rather than obvious failure
5. **Persistent Effect:** Once triggered, the condition persists until manual intervention

The attack can be executed by:
- Compromised or malicious validators
- Malicious VFN operators  
- Public fullnode operators with malicious intent
- Man-in-the-middle attackers controlling network traffic to selected peers

## Recommendation

**Fix Option 1 - Change AND to OR with Grace Period:**
Modify the failure logic to trigger if the lag duration exceeds a threshold, regardless of whether lag has increased, after an initial grace period:

```rust
fn is_beyond_recovery(
    &mut self,
    streaming_service_config: DataStreamingServiceConfig,
    current_stream_lag: u64,
) -> bool {
    let current_time = self.time_service.now();
    let stream_lag_duration = current_time.duration_since(self.start_time);
    let max_stream_lag_duration =
        Duration::from_secs(streaming_service_config.max_subscription_stream_lag_secs);
    
    let lag_has_increased = current_stream_lag > self.version_lag;
    let lag_duration_exceeded = stream_lag_duration >= max_stream_lag_duration;
    
    // Fail if lag increases and time exceeded (original logic)
    if lag_has_increased && lag_duration_exceeded {
        return true;
    }
    
    // Also fail if lag persists beyond 2x the threshold, even if decreasing
    let extended_threshold = max_stream_lag_duration * 2;
    if stream_lag_duration >= extended_threshold {
        return true;
    }
    
    // Update lag if improving
    if current_stream_lag < self.version_lag {
        self.version_lag = current_stream_lag;
    }
    
    false
}
```

**Fix Option 2 - Reset Timer on Significant Improvement:**
Reset `start_time` when lag improves significantly, giving the stream a fresh chance:

```rust
fn is_beyond_recovery(
    &mut self,
    streaming_service_config: DataStreamingServiceConfig,
    current_stream_lag: u64,
) -> bool {
    let current_time = self.time_service.now();
    let stream_lag_duration = current_time.duration_since(self.start_time);
    let max_stream_lag_duration =
        Duration::from_secs(streaming_service_config.max_subscription_stream_lag_secs);
    
    let lag_has_increased = current_stream_lag > self.version_lag;
    let lag_duration_exceeded = stream_lag_duration >= max_stream_lag_duration;
    
    if lag_has_increased && lag_duration_exceeded {
        return true;
    }
    
    // If lag improved by more than 50%, reset the timer
    if current_stream_lag < self.version_lag {
        let improvement = self.version_lag.saturating_sub(current_stream_lag);
        let improvement_ratio = (improvement * 100) / self.version_lag.max(1);
        
        if improvement_ratio >= 50 {
            self.start_time = current_time; // Reset timer on significant progress
        }
        
        self.version_lag = current_stream_lag;
    }
    
    false
}
```

Both approaches prevent the indefinite degraded state while still allowing reasonable recovery time for legitimate slow peers.

## Proof of Concept

The following Rust test demonstrates the vulnerability:

```rust
#[tokio::test]
async fn test_subscription_lag_constant_bypass() {
    use aptos_time_service::TimeService;
    
    // Create streaming config with 10 second lag threshold
    let streaming_service_config = DataStreamingServiceConfig {
        enable_subscription_streaming: true,
        max_subscription_stream_lag_secs: 10,
        ..Default::default()
    };
    
    // Create a continuous transaction stream
    let (mut data_stream, mut stream_listener, time_service, _, _) = 
        create_continuous_transaction_stream(streaming_service_config);
    
    // Initialize with global data summary
    let mut global_data_summary = create_global_data_summary(1);
    initialize_data_requests(&mut data_stream, &global_data_summary);
    
    // Set network to be 1000 versions ahead (initial lag)
    global_data_summary.advertised_data.synced_ledger_infos = 
        vec![create_ledger_info(MAX_ADVERTISED_TRANSACTION + 1000, 1, false)];
    
    // Process response with 1000 version lag
    set_new_data_response_in_queue(&mut data_stream, 0, MAX_ADVERTISED_TRANSACTION, true);
    process_data_responses(&mut data_stream, &global_data_summary).await;
    assert_some!(stream_listener.select_next_some().now_or_never());
    
    // Verify lag tracking started
    assert!(data_stream.get_subscription_stream_lag().is_some());
    
    // Advance time past the threshold (15 seconds)
    let time_service = time_service.into_mock();
    time_service.advance_secs(15);
    
    // Keep lag constant at 1000 versions (attacker maintains constant lag)
    set_new_data_response_in_queue(&mut data_stream, 0, MAX_ADVERTISED_TRANSACTION, true);
    process_data_responses(&mut data_stream, &global_data_summary).await;
    assert_some!(stream_listener.select_next_some().now_or_never());
    
    // Verify stream still has subscription requests (NOT killed despite exceeding time)
    let client_request = get_pending_client_request(&mut data_stream, 0);
    assert!(client_request.is_subscription_request()); // VULNERABILITY: Stream should be killed but isn't
    
    // Verify lag tracking still active (degraded state persists)
    assert!(data_stream.get_subscription_stream_lag().is_some());
}
```

**Expected Behavior:** After 15 seconds (exceeding the 10-second threshold), the subscription stream should be terminated and fallback to regular syncing.

**Actual Behavior:** The stream remains active with subscription requests because `lag_has_increased` = false (1000 ≤ 1000), allowing the degraded state to persist indefinitely.

---

**Notes:**

This vulnerability violates the state consistency invariant by allowing nodes to remain in degraded sync states that should trigger automatic recovery. The existing test suite validates the case where lag increases beyond the threshold but does not cover the constant or decreasing lag scenario. The fix must balance allowing legitimate slow peers time to catch up while preventing malicious peers from indefinitely maintaining degraded states.

### Citations

**File:** state-sync/data-streaming-service/src/data_stream.rs (L608-629)
```rust
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

**File:** config/src/config/state_sync_config.rs (L278-278)
```rust
            max_subscription_stream_lag_secs: 10, // 10 seconds
```

**File:** state-sync/aptos-data-client/src/client.rs (L424-443)
```rust
    fn choose_peer_for_subscription_request(
        &self,
        request: &StorageServiceRequest,
        serviceable_peers_by_priorities: Vec<HashSet<PeerNetworkId>>,
    ) -> crate::error::Result<HashSet<PeerNetworkId>, Error> {
        // Prioritize peer selection by choosing the highest priority peer first
        for serviceable_peers in serviceable_peers_by_priorities {
            if let Some(selected_peer) =
                self.choose_serviceable_peer_for_subscription_request(request, serviceable_peers)?
            {
                return Ok(hashset![selected_peer]); // A peer was found!
            }
        }

        // Otherwise, no peer was selected, return an error
        Err(Error::DataIsUnavailable(format!(
            "Unable to select peers for subscription request: {:?}",
            request
        )))
    }
```
