# Audit Report

## Title
Validator Set Discovery TOCTOU Vulnerability Allows Stale Peer Authorization During Epoch Transitions

## Summary
The validator discovery system suffers from a Time-of-Check-Time-of-Use (TOCTOU) vulnerability where on-chain state can change between extracting the validator set from a reconfiguration payload and the actual application of peer connection updates. Combined with non-blocking channel semantics that can drop updates, this allows removed validators to maintain network authentication beyond their authorized epoch.

## Finding Description

The vulnerability exists in the validator set discovery mechanism, specifically in how peer set updates flow from on-chain configuration to network connection authorization. [1](#0-0) 

The `extract_updates()` method extracts the `ValidatorSet` from the reconfiguration payload at lines 71-73 and converts it to a `PeerSet` at line 75. This extracted peer set is then returned and sent to the connectivity manager. [2](#0-1) 

The discovery listener uses **non-blocking `try_send`** at line 150 to deliver updates to the connectivity manager. When the channel is full (backlog scenario), the update is silently dropped with only a warning logged. There is no retry mechanism. [3](#0-2) 

The connectivity manager updates the trusted peers set at line 991-993, which is then used for network handshake authentication. [4](#0-3) 

During the Noise handshake in `Mutual` authentication mode, peers are validated against the `trusted_peers` set. If a peer is not in this set, connection is rejected with `UnauthenticatedClient` error.

**The TOCTOU Race Window:**

1. **T0**: Epoch N reconfiguration notification broadcast
2. **T0.1**: Discovery extracts ValidatorSet with malicious validator M (lines 71-73)
3. **T0.2**: PeerSet created with M included
4. **T0.5**: Epoch N+1 reconfiguration occurs (M removed from validator set)
5. **T0.6**: Consensus processes epoch N+1, updates ValidatorVerifier (M excluded)
6. **T0.7**: Discovery's epoch N update sent via `try_send` but **channel is full - update DROPPED**
7. **T1**: Discovery processes epoch N+1, sends update without M
8. **T1.1**: Connectivity manager processes epoch N+1 update (removes M from trusted_peers)
9. **BUT**: If epoch N update was never applied due to drop, and subsequent epoch N+1 update is ALSO dropped due to continued backlog, M remains authorized indefinitely

**State Inconsistency:**
- Consensus operates with epoch N+1 validator set (M excluded)
- Network authentication uses stale epoch N trusted peers (M included)
- M can establish and maintain connections, passing handshake authentication
- M's consensus messages fail signature verification, but M can still send network traffic

This violates **Invariant #4 (State Consistency)**: the network layer's view of authorized validators is inconsistent with consensus's view.

## Impact Explanation

This is a **Medium Severity** vulnerability per Aptos bug bounty criteria for the following reasons:

**State Inconsistency Requiring Intervention:**
- Removed validators can maintain network connections beyond their authorized epoch
- The trusted peers set can become permanently stale if multiple consecutive updates are dropped
- Manual intervention may be required to clear stale connections and resynchronize state

**Limited Attack Surface:**
- Removed validators cannot forge valid consensus messages (signatures verified against current epoch's `ValidatorVerifier`)
- Attack requires channel backlog conditions (high network load or slow processing)
- Does not break consensus safety (Byzantine fault tolerance maintained)

**Potential Impact:**
- Unauthorized validators consume network bandwidth and connection slots
- Stale validators can send invalid messages causing processing overhead
- Could degrade network performance during high load scenarios
- Multiple dropped updates could extend the inconsistency window across epoch boundaries

This does not reach **High Severity** because:
- No consensus safety violation (signatures still checked)
- No fund loss or theft possible
- Temporary performance degradation rather than complete node failure

## Likelihood Explanation

**Moderate Likelihood** due to:

**Favorable Conditions:**
- Channel backlog can occur during high network load or epoch transitions when many updates occur simultaneously
- The `try_send` operation provides no backpressure - it immediately fails rather than blocking
- Multiple discovery sources (validator set, file, REST) can overwhelm the channel
- Epoch transitions are predictable events that could be targeted [5](#0-4) 

The channel is created with a fixed `channel_size` parameter. During busy periods, the receiver may not process updates fast enough.

**Mitigating Factors:**
- Requires sustained channel saturation to drop multiple consecutive updates
- Periodic connectivity checks eventually detect some inconsistencies (though relying on the same stale trusted_peers data)
- Next successful epoch update will resynchronize state

**Attack Complexity:**
- Medium - attacker needs to be a removed validator or compromise one
- Medium - requires timing to exploit channel backlog conditions
- Can be triggered more reliably during coordinated epoch transitions

## Recommendation

Implement reliable delivery for critical validator set updates:

**1. Replace `try_send` with blocking `send` or implement retry logic:**

```rust
// In network/discovery/src/lib.rs, replace lines 149-156 with:
let request = ConnectivityRequest::UpdateDiscoveredPeers(discovery_source, update);

// Implement exponential backoff retry
let mut retry_count = 0;
const MAX_RETRIES: usize = 5;
const RETRY_DELAY_MS: u64 = 100;

while retry_count < MAX_RETRIES {
    match update_channel.try_send(request.clone()) {
        Ok(_) => break,
        Err(error) => {
            retry_count += 1;
            if retry_count >= MAX_RETRIES {
                error!(
                    NetworkSchema::new(&network_context),
                    "{} Failed to send update after {} retries: {:?}",
                    network_context, MAX_RETRIES, error
                );
                inc_by_with_context(&DISCOVERY_COUNTS, &network_context, "send_failure_permanent", 1);
            } else {
                warn!(
                    NetworkSchema::new(&network_context),
                    "{} Retrying update send (attempt {}): {:?}",
                    network_context, retry_count, error
                );
                tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS * retry_count as u64)).await;
            }
        }
    }
}
```

**2. Add epoch versioning to connectivity manager updates:**

Track the epoch number for each trusted peers update and reject out-of-order or stale updates to prevent TOCTOU races.

**3. Implement forced full refresh:**

Add a mechanism to force a complete resynchronization of trusted peers from current on-chain state periodically, independent of the event stream.

## Proof of Concept

```rust
// Reproduction scenario for TOCTOU vulnerability
// This demonstrates the race condition in a test environment

#[tokio::test]
async fn test_validator_discovery_toctou_race() {
    use aptos_channels::aptos_channel;
    use network::discovery::{DiscoveryChangeListener};
    use network::connectivity_manager::ConnectivityRequest;
    
    // Setup: Create a small channel that can be saturated
    let (conn_mgr_reqs_tx, mut conn_mgr_reqs_rx) = aptos_channels::new(
        1, // Small buffer - easily saturated
        &counters::PENDING_CONNECTIVITY_MANAGER_REQUESTS
    );
    
    // Create discovery listener
    let (mut reconfig_sender, reconfig_events) = aptos_channel::new(QueueStyle::LIFO, 10, None);
    let network_context = NetworkContext::mock_with_peer_id(peer_id);
    
    let listener = DiscoveryChangeListener::validator_set(
        network_context,
        conn_mgr_reqs_tx,
        pubkey,
        ReconfigNotificationListener { notification_receiver: reconfig_events },
    );
    
    // Spawn listener in background
    tokio::spawn(listener.run());
    
    // Scenario 1: Send epoch N update with malicious validator M
    let validator_set_n = create_validator_set_with_malicious(/* M included */);
    send_reconfig_event(&mut reconfig_sender, epoch_n, validator_set_n);
    
    // Scenario 2: Saturate channel before update is processed
    // Fill channel with dummy requests to create backlog
    for _ in 0..10 {
        let _ = conn_mgr_reqs_tx.try_send(ConnectivityRequest::UpdateAddresses(...));
    }
    
    // Scenario 3: Send epoch N+1 update with M removed
    let validator_set_n_plus_1 = create_validator_set_without_malicious(/* M removed */);
    send_reconfig_event(&mut reconfig_sender, epoch_n_plus_1, validator_set_n_plus_1);
    
    // Verify: Due to channel saturation, epoch N update may be dropped
    // If both updates dropped, M remains in trusted_peers indefinitely
    
    // Check connectivity manager's trusted peers state
    tokio::time::sleep(Duration::from_secs(1)).await;
    
    let trusted_peers = peers_and_metadata.get_trusted_peers(&network_id).unwrap();
    
    // BUG: M should NOT be in trusted_peers (removed in epoch N+1)
    // but may still be present if updates were dropped
    if trusted_peers.contains_key(&malicious_peer_id) {
        panic!("VULNERABILITY: Removed validator still in trusted peers!");
    }
}
```

**Notes:**
- This vulnerability requires specific timing and channel saturation conditions to trigger reliably
- The impact is mitigated by signature verification at the consensus layer
- However, it represents a clear violation of the state consistency invariant where network authorization diverges from consensus authorization
- The use of non-blocking `try_send` without retry logic is the root cause

### Citations

**File:** network/discovery/src/validator_set.rs (L68-91)
```rust
    fn extract_updates(&mut self, payload: OnChainConfigPayload<P>) -> PeerSet {
        let _process_timer = EVENT_PROCESSING_LOOP_BUSY_DURATION_S.start_timer();

        let node_set: ValidatorSet = payload
            .get()
            .expect("failed to get ValidatorSet from payload");

        let peer_set = extract_validator_set_updates(self.network_context, node_set);
        // Ensure that the public key matches what's onchain for this peer
        self.find_key_mismatches(
            peer_set
                .get(&self.network_context.peer_id())
                .map(|peer| &peer.keys),
        );

        inc_by_with_context(
            &DISCOVERY_COUNTS,
            &self.network_context,
            "new_nodes",
            peer_set.len() as u64,
        );

        peer_set
    }
```

**File:** network/discovery/src/lib.rs (L141-156)
```rust
        while let Some(update) = source_stream.next().await {
            if let Ok(update) = update {
                trace!(
                    NetworkSchema::new(&network_context),
                    "{} Sending update: {:?}",
                    network_context,
                    update
                );
                let request = ConnectivityRequest::UpdateDiscoveredPeers(discovery_source, update);
                if let Err(error) = update_channel.try_send(request) {
                    inc_by_with_context(&DISCOVERY_COUNTS, &network_context, "send_failure", 1);
                    warn!(
                        NetworkSchema::new(&network_context),
                        "{} Failed to send update {:?}", network_context, error
                    );
                }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L984-1001)
```rust
        // update eligible peers accordingly
        if keys_updated {
            // For each peer, union all of the pubkeys from each discovery source
            // to generate the new eligible peers set.
            let new_eligible = self.discovered_peers.read().get_eligible_peers();

            // Swap in the new eligible peers set
            if let Err(error) = self
                .peers_and_metadata
                .set_trusted_peers(&self.network_context.network_id(), new_eligible)
            {
                error!(
                    NetworkSchema::new(&self.network_context),
                    error = %error,
                    "Failed to update trusted peers set"
                );
            }
        }
```

**File:** network/framework/src/noise/handshake.rs (L368-383)
```rust
        let peer_role = match &self.auth_mode {
            HandshakeAuthMode::Mutual {
                peers_and_metadata, ..
            } => {
                let trusted_peers = peers_and_metadata.get_trusted_peers(&network_id)?;
                let trusted_peer = trusted_peers.get(&remote_peer_id).cloned();
                match trusted_peer {
                    Some(peer) => {
                        Self::authenticate_inbound(remote_peer_short, &peer, &remote_public_key)
                    },
                    None => Err(NoiseHandshakeError::UnauthenticatedClient(
                        remote_peer_short,
                        remote_peer_id,
                    )),
                }
            },
```

**File:** network/framework/src/connectivity_manager/builder.rs (L39-42)
```rust
        let (conn_mgr_reqs_tx, conn_mgr_reqs_rx) = aptos_channels::new(
            channel_size,
            &counters::PENDING_CONNECTIVITY_MANAGER_REQUESTS,
        );
```
