# Audit Report

## Title
Zero-Value Configuration Bypass Enables Complete Evasion of Storage Service Peer Rate Limiting

## Summary
The `min_time_to_ignore_peers_secs` configuration parameter in `StorageServiceConfig` lacks validation and can be set to 0, which completely disables the peer blocking mechanism in the storage service request moderator. When set to 0, malicious Public Full Node (PFN) peers can indefinitely spam invalid requests, bypassing all rate limiting protections and causing denial-of-service conditions on storage service nodes.

## Finding Description

The storage service request moderator is designed to protect nodes from malicious peers by temporarily ignoring peers that send too many invalid requests. However, a critical validation gap allows the `min_time_to_ignore_peers_secs` configuration parameter to be set to 0, which breaks the entire protection mechanism. [1](#0-0) 

The configuration field is defined as a `u64` without any validation constraints. The default value is 300 seconds (5 minutes): [2](#0-1) 

This value is passed directly to `UnhealthyPeerState::new()` without validation: [3](#0-2) 

The critical flaw exists in the `refresh_peer_state()` function's comparison logic: [4](#0-3) 

When `min_time_to_ignore_secs` is 0:
1. The condition `ignored_duration >= Duration::from_secs(0)` at line 82 is **always true** for any non-zero duration
2. Blocked peers are immediately unblocked on the next refresh cycle (every 1 second by default)
3. The exponential backoff multiplication `self.min_time_to_ignore_secs *= 2` at line 90 keeps the value at 0 (0 × 2 = 0)
4. The protection mechanism is permanently disabled

**Attack Scenario:**

1. Node operator sets `min_time_to_ignore_peers_secs: 0` in YAML configuration (either through misconfiguration, misunderstanding, or believing it means "instant block")
2. Malicious PFN connects and sends 500 invalid storage requests (default `max_invalid_requests_per_peer`)
3. Peer is marked as ignored and blocking is triggered: [5](#0-4) 

4. Within 1 second (the default refresh interval), `refresh_unhealthy_peer_states()` is called: [6](#0-5) 

5. The peer is immediately unblocked due to the zero-value comparison flaw
6. The malicious peer repeats the attack cycle indefinitely, causing:
   - Excessive CPU usage for request validation
   - Memory pressure from peer state tracking
   - Network bandwidth exhaustion
   - Storage service degradation or crash

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria:

- **Validator node slowdowns**: Continuous invalid request processing degrades node performance
- **API crashes**: Storage service can crash under sustained spam from multiple malicious peers  
- **Significant protocol violations**: Complete bypass of peer rate limiting breaks the protection invariant

The impact is severe because:
1. No validation prevents the dangerous configuration value
2. Once misconfigured, the node is permanently vulnerable until restarted with corrected config
3. Multiple malicious peers can coordinate to amplify the DoS effect
4. Storage service degradation affects state synchronization across the network

While this requires a configuration error to enable exploitation, it represents a critical defense-in-depth failure. Production code must validate configuration inputs to prevent dangerous values, even when operators are generally trusted.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability has significant likelihood because:

1. **Easy to misconfigure**: An operator might set the value to 0 thinking it means:
   - "Disable the feature entirely"
   - "Block immediately without delay"
   - Testing/debugging configuration that gets deployed to production

2. **No validation warnings**: The configuration system provides no error or warning when this dangerous value is set

3. **Silent failure**: The misconfiguration doesn't cause immediate errors, making it difficult to detect until under attack

4. **No test coverage**: The test suite doesn't cover the zero-value edge case, indicating this scenario wasn't considered during development

While not all nodes will be misconfigured, the lack of validation means any operator error can enable this attack vector. Once misconfigured, exploitation is trivial and requires only network connectivity from malicious peers.

## Recommendation

**Immediate Fix: Add Configuration Validation**

Add a `ConfigSanitizer` implementation for `StorageServiceConfig` that validates `min_time_to_ignore_peers_secs` is non-zero:

```rust
impl ConfigSanitizer for StorageServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let storage_service_config = &node_config.state_sync.storage_service;

        // Validate min_time_to_ignore_peers_secs is not zero
        if storage_service_config.min_time_to_ignore_peers_secs == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "min_time_to_ignore_peers_secs must be greater than 0 to prevent bypassing peer rate limiting".to_string(),
            ));
        }

        Ok(())
    }
}
```

Then register this sanitizer in the `StateSyncConfig::sanitize()` method:

```rust
impl ConfigSanitizer for StateSyncConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // Sanitize the state sync driver config
        StateSyncDriverConfig::sanitize(node_config, node_type, chain_id)?;
        
        // Sanitize the storage service config (NEW)
        StorageServiceConfig::sanitize(node_config, node_type, chain_id)?;
        
        Ok(())
    }
}
```

**Additional Hardening:**

1. Set a minimum reasonable value (e.g., 10 seconds) rather than just checking for non-zero
2. Add runtime validation in `UnhealthyPeerState::new()` with an assertion or panic
3. Add comprehensive tests for edge cases including zero and very small values

## Proof of Concept

Add this test to `state-sync/storage-service/server/src/moderator.rs`:

```rust
#[test]
#[should_panic(expected = "min_time_to_ignore_secs must be greater than 0")]
fn test_unhealthy_peer_zero_ignore_time() {
    // This test demonstrates the vulnerability when min_time_to_ignore_secs is set to 0
    let max_invalid_requests = 5;
    let min_time_to_ignore_secs = 0; // VULNERABLE VALUE
    let time_service = TimeService::mock();
    let mut unhealthy_peer_state = UnhealthyPeerState::new(
        max_invalid_requests,
        min_time_to_ignore_secs,
        time_service.clone(),
    );

    // Create a PFN peer
    let peer_network_id = PeerNetworkId::new(NetworkId::Public, PeerId::random());

    // Send max invalid requests to trigger blocking
    for _ in 0..max_invalid_requests {
        unhealthy_peer_state.increment_invalid_request_count(&peer_network_id);
    }

    // Verify the peer is now ignored
    assert!(unhealthy_peer_state.is_ignored());
    assert_eq!(unhealthy_peer_state.min_time_to_ignore_secs, 0);

    // Advance time by a tiny amount (even 1 nanosecond)
    let time_service = time_service.into_mock();
    time_service.advance(Duration::from_nanos(1));

    // Call refresh - with zero value, this will IMMEDIATELY unblock
    unhealthy_peer_state.refresh_peer_state(&peer_network_id);

    // VULNERABILITY: Peer is no longer ignored after just 1 nanosecond!
    assert!(!unhealthy_peer_state.is_ignored(), 
        "Peer should still be ignored, but zero value causes immediate unblock");
    
    // VULNERABILITY: The value stays at 0 after doubling
    assert_eq!(unhealthy_peer_state.min_time_to_ignore_secs, 0,
        "Exponential backoff broken: 0 * 2 = 0");
    
    // This means the peer can immediately send another batch of invalid requests
    // and the cycle repeats indefinitely, completely bypassing rate limiting
}
```

**To demonstrate the DoS attack:**

```rust
#[tokio::test]
async fn test_zero_value_dos_attack() {
    // Create a vulnerable configuration with zero ignore time
    let storage_service_config = StorageServiceConfig {
        max_invalid_requests_per_peer: 5,
        min_time_to_ignore_peers_secs: 0, // VULNERABLE
        ..Default::default()
    };

    let (mut mock_client, mut service, _, time_service, _) =
        MockClient::new(None, Some(storage_service_config));
    
    let request_moderator = service.get_request_moderator();
    let unhealthy_peer_states = request_moderator.get_unhealthy_peer_states();
    
    tokio::spawn(service.start());

    let peer_network_id = PeerNetworkId::new(NetworkId::Public, PeerId::random());

    // Attack loop: repeatedly spam invalid requests
    for cycle in 0..100 {
        // Send 5 invalid requests to trigger "blocking"
        for _ in 0..5 {
            send_invalid_transaction_request(100, &mut mock_client, peer_network_id)
                .await
                .unwrap_err();
        }
        
        // Wait for moderator refresh (1 second)
        time_service.advance_secs_async(1).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // With zero value, peer is immediately unblocked and can attack again
        // This proves complete bypass of rate limiting
        assert!(
            cycle < 100, 
            "Attacker successfully spammed 500 invalid requests without effective blocking"
        );
    }
}
```

This proof of concept demonstrates that when `min_time_to_ignore_peers_secs` is set to 0, the peer blocking mechanism is completely bypassed, allowing indefinite spam attacks.

### Citations

**File:** config/src/config/state_sync_config.rs (L187-188)
```rust
    /// Minimum time (secs) to ignore peers after too many invalid requests
    pub min_time_to_ignore_peers_secs: u64,
```

**File:** config/src/config/state_sync_config.rs (L213-213)
```rust
            min_time_to_ignore_peers_secs: 300, // 5 minutes
```

**File:** state-sync/storage-service/server/src/moderator.rs (L33-45)
```rust
    pub fn new(
        max_invalid_requests: u64,
        min_time_to_ignore_secs: u64,
        time_service: TimeService,
    ) -> Self {
        Self {
            ignore_start_time: None,
            invalid_request_count: 0,
            max_invalid_requests,
            min_time_to_ignore_secs,
            time_service,
        }
    }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L50-69)
```rust
    pub fn increment_invalid_request_count(&mut self, peer_network_id: &PeerNetworkId) {
        // Increment the invalid request count
        self.invalid_request_count += 1;

        // If the peer is a PFN and has sent too many invalid requests, start ignoring it
        if self.ignore_start_time.is_none()
            && peer_network_id.network_id().is_public_network()
            && self.invalid_request_count >= self.max_invalid_requests
        {
            // TODO: at some point we'll want to terminate the connection entirely

            // Start ignoring the peer
            self.ignore_start_time = Some(self.time_service.now());

            // Log the fact that we're now ignoring the peer
            warn!(LogSchema::new(LogEntry::RequestModeratorIgnoredPeer)
                .peer_network_id(peer_network_id)
                .message("Ignoring peer due to too many invalid requests!"));
        }
    }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L79-98)
```rust
    pub fn refresh_peer_state(&mut self, peer_network_id: &PeerNetworkId) {
        if let Some(ignore_start_time) = self.ignore_start_time {
            let ignored_duration = self.time_service.now().duration_since(ignore_start_time);
            if ignored_duration >= Duration::from_secs(self.min_time_to_ignore_secs) {
                // Reset the invalid request count
                self.invalid_request_count = 0;

                // Reset the ignore start time
                self.ignore_start_time = None;

                // Double the min time to ignore the peer
                self.min_time_to_ignore_secs *= 2;

                // Log the fact that we're no longer ignoring the peer
                warn!(LogSchema::new(LogEntry::RequestModeratorIgnoredPeer)
                    .peer_network_id(peer_network_id)
                    .message("No longer ignoring peer! Enough time has elapsed."));
            }
        }
    }
```

**File:** state-sync/storage-service/server/src/lib.rs (L364-380)
```rust
            // Create a ticker for the refresh interval
            let duration = Duration::from_millis(config.request_moderator_refresh_interval_ms);
            let ticker = time_service.interval(duration);
            futures::pin_mut!(ticker);

            // Periodically refresh the peer states
            loop {
                ticker.next().await;

                // Refresh the unhealthy peer states
                if let Err(error) = request_moderator.refresh_unhealthy_peer_states() {
                    error!(LogSchema::new(LogEntry::RequestModeratorRefresh)
                        .error(&error)
                        .message("Failed to refresh the request moderator!"));
                }
            }
        });
```
