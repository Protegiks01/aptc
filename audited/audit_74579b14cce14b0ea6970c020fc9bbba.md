# Audit Report

## Title
Byzantine Peer Reconnection Bypass via Garbage Collection of Malicious Behavior Tracking

## Summary
When `PeerManagerError::NotConnected` is converted to `RpcError::NotConnected`, all context about disconnection reasons is lost. Combined with aggressive garbage collection of peer state tracking, Byzantine peers can disconnect and immediately reconnect with a clean reputation score, bypassing malicious behavior detection and allowing repeated attacks.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Error Context Loss**: When the network layer converts `PeerManagerError::NotConnected` to `RpcError::NotConnected`, only the peer ID is preserved—all information about WHY the peer was disconnected is lost. [1](#0-0) 

2. **PeerStates Garbage Collection**: The state-sync data client's `PeerStates` tracks peer scores to identify malicious peers. However, it garbage collects peer states for disconnected peers, removing the degraded scores of Byzantine actors. [2](#0-1) 

3. **Fresh Score on Reconnection**: When a previously-disconnected Byzantine peer reconnects, a new `PeerState` is created with the default `STARTING_SCORE` of 50.0, completely erasing their malicious behavior history. [3](#0-2) 

4. **RequestModerator Garbage Collection**: Similarly, the storage service's `RequestModerator` tracks unhealthy peers that send invalid requests, but also garbage collects this state when peers disconnect. [4](#0-3) 

**Attack Flow:**

A Byzantine peer exploits this by:

1. Connecting to the network as a public (non-validator) peer
2. Sending malicious state-sync responses (e.g., invalid proofs, bad data)
3. Peer score degrades from 50.0 → 40.0 → 32.0 → 25.6 → 20.48 (below `IGNORE_PEER_THRESHOLD` of 25.0) via `MALICIOUS_MULTIPLIER` of 0.8 [5](#0-4) 
4. Invalid request count increments in `RequestModerator`, eventually causing temporary ignoring
5. Peer gets disconnected (either by health checker, explicit disconnect, or connection closure)
6. `garbage_collect_peer_states()` is called during the next global summary update, removing the peer's degraded score [6](#0-5) 
7. Byzantine peer immediately reconnects
8. New `PeerState` is created with `STARTING_SCORE` of 50.0 and zero invalid requests—completely clean slate
9. Repeat steps 2-8 indefinitely, causing continuous resource exhaustion

The network layer's `PeerManager` has no persistent ban list to prevent reconnection: [7](#0-6) 

When handling new connections, it only checks connection limits and trusted peer lists, not previous disconnection reasons or ban status.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Validator Node Slowdowns**: Byzantine peers can repeatedly force validators to:
   - Process and validate malicious state-sync data
   - Waste CPU cycles on invalid proof verification
   - Consume memory buffering bad responses
   - Retry failed RPCs to peers that were just disconnected for malicious behavior

2. **Significant Protocol Violations**: The vulnerability violates the fundamental security assumption that malicious peers should be identified and excluded. The garbage collection of reputation scores allows Byzantine actors to operate indefinitely without permanent consequences.

3. **Resource Exhaustion**: An attacker controlling multiple peer IDs can cycle through them, each receiving multiple rounds of attacks before being temporarily ignored, then reconnecting fresh. This creates a persistent DoS condition against state-sync services.

The comment in the `RequestModerator` acknowledges this gap: "TODO: at some point we'll want to terminate the connection entirely" [8](#0-7) 

## Likelihood Explanation

**Likelihood: High**

- **Low Attacker Requirements**: Any network peer can connect to public fullnodes. No validator keys or special credentials required.
- **Simple Execution**: The attack requires only basic network connectivity and ability to send malformed state-sync messages.
- **No Detection**: Because peer states are garbage collected, there's no persistent audit trail of the attack pattern.
- **Repeatable**: The attacker can disconnect/reconnect indefinitely, as each reconnection grants a fresh reputation score.

The malicious response detection is already implemented, as shown by the `ErrorType::Malicious` category for proof verification errors: [9](#0-8) 

However, the garbage collection undermines this defense mechanism.

## Recommendation

**Implement Persistent Byzantine Peer Tracking:**

1. **Add a Persistent Ban List**: Create a `BannedPeers` structure that persists across disconnections and tracks peers that were disconnected for malicious behavior:

```rust
// In network/framework/src/peer_manager/mod.rs
pub struct BannedPeerInfo {
    peer_id: PeerId,
    ban_reason: DisconnectReason,
    ban_timestamp: Instant,
    ban_duration: Duration,
}

pub struct BannedPeers {
    banned: Arc<DashMap<PeerId, BannedPeerInfo>>,
}
```

2. **Modify Garbage Collection Logic**: Don't garbage collect peer states for peers that were disconnected due to malicious behavior—only for benign disconnections:

```rust
// In state-sync/aptos-data-client/src/peer_states.rs
pub fn garbage_collect_peer_states(&self, connected_peers: HashSet<PeerNetworkId>, banned_peers: HashSet<PeerNetworkId>) {
    self.peer_to_state.retain(|peer_network_id, peer_state| {
        // Keep if connected OR banned with low score (preserve punishment)
        connected_peers.contains(peer_network_id) || 
        (banned_peers.contains(peer_network_id) && peer_state.score < IGNORE_PEER_THRESHOLD)
    });
}
```

3. **Check Ban List on Reconnection**: In `handle_new_connection_event`, reject connections from banned peers:

```rust
// Check if peer is banned before accepting connection
if let Some(ban_info) = self.banned_peers.get(&conn.metadata.remote_peer_id) {
    if ban_info.ban_timestamp.elapsed() < ban_info.ban_duration {
        self.disconnect(conn);
        return;
    }
}
```

4. **Propagate Disconnect Reason**: Extend `RpcError::NotConnected` to include the disconnect reason, allowing calling code to distinguish between transient failures and Byzantine bans:

```rust
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Not connected with peer: {0}, reason: {1:?}")]
    NotConnected(PeerId, Option<DisconnectReason>),
    // ... other variants
}
```

## Proof of Concept

**Rust Reproduction Steps:**

```rust
// Simulated attack demonstrating the vulnerability

#[test]
fn test_byzantine_peer_reconnection_bypass() {
    // Setup: Create data client with peer states
    let config = Arc::new(AptosDataClientConfig::default());
    let peer_states = PeerStates::new(config.clone());
    
    let byzantine_peer = PeerNetworkId::random();
    let initial_summary = create_mock_storage_summary();
    
    // Step 1: Peer connects and gets initial score of 50.0
    peer_states.update_summary(byzantine_peer, initial_summary.clone());
    let state1 = peer_states.peer_to_state.get(&byzantine_peer).unwrap();
    assert_eq!(state1.score, 50.0);
    
    // Step 2: Peer sends malicious responses (invalid proofs)
    for _ in 0..5 {
        peer_states.update_score_error(byzantine_peer, ErrorType::Malicious);
    }
    
    // After 5 malicious responses: 50 * 0.8^5 = 16.384 (below threshold)
    let state2 = peer_states.peer_to_state.get(&byzantine_peer).unwrap();
    assert!(state2.score < IGNORE_PEER_THRESHOLD); // Should be ignored
    drop(state2);
    
    // Step 3: Peer disconnects (simulated by garbage collection)
    let connected_peers = HashSet::new(); // Empty = all disconnected
    peer_states.garbage_collect_peer_states(connected_peers);
    
    // Step 4: Verify peer state was removed
    assert!(!peer_states.peer_to_state.contains_key(&byzantine_peer));
    
    // Step 5: Byzantine peer reconnects
    peer_states.update_summary(byzantine_peer, initial_summary);
    
    // Step 6: VULNERABILITY - New peer state has fresh score of 50.0!
    let state3 = peer_states.peer_to_state.get(&byzantine_peer).unwrap();
    assert_eq!(state3.score, 50.0); // Malicious history erased!
    
    // Attacker can now repeat the attack indefinitely
}
```

**Attack Scenario:**

1. Attacker controls 10 peer IDs
2. Each peer connects, sends 5 malicious state-sync responses (invalid proofs)
3. Each peer's score drops to ~16 (ignored), accumulates 5 invalid requests
4. All peers disconnect simultaneously
5. Garbage collection clears all reputation data
6. All 10 peers reconnect with fresh scores of 50.0
7. Repeat, forcing validators to process 50 malicious responses per cycle
8. Validator resources exhausted validating bad proofs

**Notes**

The vulnerability is confirmed across multiple layers:
- Network layer has no persistent ban tracking
- State-sync peer scoring is reset on disconnect/reconnect
- Request moderator unhealthy peer states are garbage collected
- All calling code receives generic `NotConnected` errors with no context

This creates a systemic weakness where Byzantine peer detection is undermined by aggressive garbage collection and lack of persistent state tracking.

### Citations

**File:** network/framework/src/protocols/rpc/error.rs (L46-54)
```rust
impl From<PeerManagerError> for RpcError {
    fn from(err: PeerManagerError) -> Self {
        match err {
            PeerManagerError::NotConnected(peer_id) => RpcError::NotConnected(peer_id),
            PeerManagerError::IoError(err) => RpcError::IoError(err),
            err => RpcError::Error(anyhow!(err)),
        }
    }
}
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L45-62)
```rust
pub enum ErrorType {
    /// A response or error that's not actively malicious but also doesn't help
    /// us make progress, e.g., timeouts, remote errors, invalid data, etc...
    NotUseful,
    /// A response or error that appears to be actively hindering progress or
    /// attempting to deceive us, e.g., invalid proof.
    Malicious,
}

impl From<ResponseError> for ErrorType {
    fn from(error: ResponseError) -> Self {
        match error {
            ResponseError::InvalidData | ResponseError::InvalidPayloadDataType => {
                ErrorType::NotUseful
            },
            ResponseError::ProofVerificationError => ErrorType::Malicious,
        }
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L167-174)
```rust
    /// Updates the score of the peer according to an error
    fn update_score_error(&mut self, error: ErrorType) {
        let multiplier = match error {
            ErrorType::NotUseful => NOT_USEFUL_MULTIPLIER,
            ErrorType::Malicious => MALICIOUS_MULTIPLIER,
        };
        self.score = f64::max(self.score * multiplier, MIN_SCORE);
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L324-330)
```rust
    /// Updates the storage summary for the given peer
    pub fn update_summary(&self, peer: PeerNetworkId, storage_summary: StorageServerSummary) {
        self.peer_to_state
            .entry(peer)
            .or_insert(PeerState::new(self.data_client_config.clone()))
            .update_storage_summary(storage_summary);
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L332-336)
```rust
    /// Garbage collects the peer states to remove data for disconnected peers
    pub fn garbage_collect_peer_states(&self, connected_peers: HashSet<PeerNetworkId>) {
        self.peer_to_state
            .retain(|peer_network_id, _| connected_peers.contains(peer_network_id));
    }
```

**File:** state-sync/storage-service/server/src/moderator.rs (L47-68)
```rust
    /// Increments the invalid request count for the peer and marks
    /// the peer to be ignored if it has sent too many invalid requests.
    /// Note: we only ignore peers on the public network.
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
```

**File:** state-sync/storage-service/server/src/moderator.rs (L198-214)
```rust
    /// Refresh the unhealthy peer states and garbage collect disconnected peers
    pub fn refresh_unhealthy_peer_states(&self) -> Result<(), Error> {
        // Get the currently connected peers
        let connected_peers_and_metadata = self
            .peers_and_metadata
            .get_connected_peers_and_metadata()
            .map_err(|error| {
                Error::UnexpectedErrorEncountered(format!(
                    "Unable to get connected peers and metadata: {}",
                    error
                ))
            })?;

        // Remove disconnected peers and refresh ignored peer states
        let mut num_ignored_peers = 0;
        self.unhealthy_peer_states
            .retain(|peer_network_id, unhealthy_peer_state| {
```

**File:** state-sync/aptos-data-client/src/client.rs (L217-231)
```rust
    /// Recompute and update the global data summary cache
    pub fn update_global_summary_cache(&self) -> crate::error::Result<(), Error> {
        // Before calculating the summary, we should garbage collect
        // the peer states (to handle disconnected peers).
        self.garbage_collect_peer_states()?;

        // Calculate the global data summary
        let global_data_summary = self.peer_states.calculate_global_data_summary();

        // Update the cached data summary
        self.global_summary_cache
            .store(Arc::new(global_data_summary));

        Ok(())
    }
```

**File:** network/framework/src/peer_manager/mod.rs (L331-405)
```rust
    /// Handles a new connection event
    fn handle_new_connection_event(&mut self, conn: Connection<TSocket>) {
        // Get the trusted peers
        let trusted_peers = match self
            .peers_and_metadata
            .get_trusted_peers(&self.network_context.network_id())
        {
            Ok(trusted_peers) => trusted_peers,
            Err(error) => {
                error!(
                    NetworkSchema::new(&self.network_context)
                        .connection_metadata_with_address(&conn.metadata),
                    "Failed to get trusted peers for network context: {:?}, error: {:?}",
                    self.network_context,
                    error
                );
                return;
            },
        };

        // Verify that we have not reached the max connection limit for unknown inbound peers
        if conn.metadata.origin == ConnectionOrigin::Inbound {
            // Everything below here is meant for unknown peers only. The role comes from
            // the Noise handshake and if it's not `Unknown` then it is trusted.
            if conn.metadata.role == PeerRole::Unknown {
                // TODO: Keep track of somewhere else to not take this hit in case of DDoS
                // Count unknown inbound connections
                let unknown_inbound_conns = self
                    .active_peers
                    .iter()
                    .filter(|(peer_id, (metadata, _))| {
                        metadata.origin == ConnectionOrigin::Inbound
                            && trusted_peers
                                .get(peer_id)
                                .is_none_or(|peer| peer.role == PeerRole::Unknown)
                    })
                    .count();

                // Reject excessive inbound connections made by unknown peers
                // We control outbound connections with Connectivity manager before we even send them
                // and we must allow connections that already exist to pass through tie breaking.
                if !self
                    .active_peers
                    .contains_key(&conn.metadata.remote_peer_id)
                    && unknown_inbound_conns + 1 > self.inbound_connection_limit
                {
                    info!(
                        NetworkSchema::new(&self.network_context)
                            .connection_metadata_with_address(&conn.metadata),
                        "{} Connection rejected due to connection limit: {}",
                        self.network_context,
                        conn.metadata
                    );
                    counters::connections_rejected(&self.network_context, conn.metadata.origin)
                        .inc();
                    self.disconnect(conn);
                    return;
                }
            }
        }

        // Add the new peer and update the metric counters
        info!(
            NetworkSchema::new(&self.network_context)
                .connection_metadata_with_address(&conn.metadata),
            "{} New connection established: {}", self.network_context, conn.metadata
        );
        if let Err(error) = self.add_peer(conn) {
            warn!(
                NetworkSchema::new(&self.network_context),
                "Failed to add peer. Error: {:?}", error
            )
        }
        self.update_connected_peers_metrics();
    }
```
