# Audit Report

## Title
Stale Peer Metadata Causes False Reachability and Resource Exhaustion in JWK Consensus

## Summary
The JWK consensus network interface does not verify peer connection state before attempting RPCs, allowing stale peer metadata to cause validators to appear reachable when they are actually disconnected. This leads to wasted timeout periods, resource exhaustion through retry logic, and delayed consensus rounds.

## Finding Description
The vulnerability exists in how the network interface validates peer connectivity before sending RPC requests. The code path is:

1. **JWK Consensus Network Interface** calls `send_rpc` to broadcast messages to validators [1](#0-0) 

2. **NetworkClient** processes the RPC by calling `get_preferred_protocol_for_peer` to select the protocol [2](#0-1) 

3. **Protocol Selection** calls `get_supported_protocols` which internally uses `get_metadata_for_peer` [3](#0-2) 

4. **Critical Flaw**: `get_metadata_for_peer` returns peer metadata WITHOUT checking if `connection_state == Connected` [4](#0-3) 

5. **Connection State Tracking**: The `ConnectionState` enum includes a `Disconnected` state that is **currently unused** (as noted in comments) [5](#0-4) 

6. **Disconnection Handling**: When a peer is marked for disconnection, the health checker sets state to `Disconnecting` but metadata persists [6](#0-5) 

7. **Silent Failure**: When the RPC reaches the peer manager, it checks `active_peers` and silently drops the request if the peer isn't found [7](#0-6) 

8. **Timeout and Retry**: The RPC waits for the full timeout, then the reliable broadcast retry logic kicks in with exponential backoff [8](#0-7) 

**Comparison with Correct Implementation**: The `get_connected_peers_and_metadata` method correctly checks `is_connected()` before returning peers: [9](#0-8) 

However, JWK consensus uses ALL validators from the epoch state without filtering by connection status: [10](#0-9) 

## Impact Explanation
This vulnerability qualifies as **High Severity** per the Aptos bug bounty program criteria:

1. **Validator Node Slowdowns**: Each RPC to a disconnected peer waits for the full timeout duration (1000ms as configured). With exponential backoff retries starting at 5ms, this compounds over time.

2. **Resource Exhaustion**: The bounded executor spawns tasks for each retry attempt, consuming memory and CPU resources unnecessarily.

3. **Delayed Consensus Rounds**: JWK consensus broadcasts to all validators to achieve quorum. If multiple validators have persistent network issues, the time to reach quorum increases significantly due to timeout accumulation.

4. **False Reachability Signals**: The system incorrectly believes validators are reachable (because metadata exists), leading to suboptimal peer selection and routing decisions.

## Likelihood Explanation
This vulnerability has **HIGH likelihood** of occurrence:

1. **Network Instability**: Persistent network disconnections occur naturally in distributed systems due to routing issues, firewall changes, or temporary outages.

2. **Race Condition Window**: Between when `update_connection_state` sets state to `Disconnecting` and when `remove_peer_metadata` completes, all RPCs will encounter this issue.

3. **Health Checker Triggers**: The health checker actively disconnects unhealthy peers, creating a constant stream of peers in the `Disconnecting` state.

4. **No Mitigation**: There is no fast-fail mechanism - every RPC to a disconnected peer must wait the full timeout.

## Recommendation
Modify `get_preferred_protocol_for_peer` to verify the peer is actually connected before returning protocol information:

```rust
fn get_preferred_protocol_for_peer(
    &self,
    peer: &PeerNetworkId,
    preferred_protocols: &[ProtocolId],
) -> Result<ProtocolId, Error> {
    let peer_metadata = self.get_metadata_for_peer(*peer)?;
    
    // NEW: Check if peer is actually connected
    if !peer_metadata.is_connected() {
        return Err(Error::NetworkError(format!(
            "Peer is not connected: {:?}, state: {:?}",
            peer, peer_metadata.get_connection_state()
        )));
    }
    
    let protocols_supported_by_peer = peer_metadata.get_supported_protocols();
    for protocol in preferred_protocols {
        if protocols_supported_by_peer.contains(*protocol) {
            return Ok(*protocol);
        }
    }
    Err(Error::NetworkError(format!(
        "None of the preferred protocols are supported by this peer! \
        Peer: {:?}, supported protocols: {:?}",
        peer, protocols_supported_by_peer
    )))
}
```

Additionally, fix the peer manager to immediately fail RPCs instead of silently dropping them:

```rust
} else {
    // NEW: Return error through oneshot channel instead of just warning
    if let PeerManagerRequest::SendRpc(peer_id, req) = request {
        let _ = req.res_tx.send(Err(RpcError::NotConnected(peer_id)));
    }
    warn!(
        NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
        protocol_id = %protocol_id,
        "{} Can't send message to peer. Peer {} is currently not connected",
        self.network_context,
        peer_id.short_str()
    );
}
```

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_stale_metadata_causes_timeout() {
    // Setup: Create network with two validators
    let (mut network, mut peers_and_metadata) = setup_test_network();
    let peer_id = PeerId::random();
    let peer_network_id = PeerNetworkId::new(NetworkId::Validator, peer_id);
    
    // Step 1: Add peer with connection metadata
    let conn_metadata = ConnectionMetadata::mock(peer_id);
    peers_and_metadata.insert_connection_metadata(
        peer_network_id, 
        conn_metadata.clone()
    ).unwrap();
    
    // Step 2: Set peer to Disconnecting state (simulating health checker)
    peers_and_metadata.update_connection_state(
        peer_network_id,
        ConnectionState::Disconnecting
    ).unwrap();
    
    // Step 3: Attempt to send RPC via JWK consensus network interface
    let jwk_client = JWKConsensusNetworkClient::new(network.clone());
    let message = JWKConsensusMsg::test_message();
    
    let start = Instant::now();
    let result = jwk_client.send_rpc(
        peer_id,
        message,
        Duration::from_millis(1000)
    ).await;
    let elapsed = start.elapsed();
    
    // VULNERABLE: get_metadata_for_peer succeeds despite Disconnecting state
    // RPC times out after full 1000ms instead of failing fast
    assert!(result.is_err());
    assert!(elapsed >= Duration::from_millis(1000), 
        "Expected timeout, got fast fail in {:?}", elapsed);
    
    // Step 4: Verify retry logic compounds the problem
    // (This would continue retrying with exponential backoff)
}
```

## Notes

This vulnerability specifically affects the JWK consensus subsystem but the underlying issue exists in the `NetworkClient` implementation used across multiple consensus protocols. Other systems like the consensus observer correctly use `get_connected_peers_and_metadata()` which filters by connection state, but JWK consensus broadcasts to all validators without this check.

The `Disconnected` state is defined but marked as "Currently unused" in comments, indicating this connection state tracking mechanism is incomplete. A complete fix would ensure connection states are properly managed throughout the peer lifecycle.

### Citations

**File:** crates/aptos-jwk-consensus/src/network_interface.rs (L40-50)
```rust
    pub async fn send_rpc(
        &self,
        peer: PeerId,
        message: JWKConsensusMsg,
        rpc_timeout: Duration,
    ) -> Result<JWKConsensusMsg, Error> {
        let peer_network_id = self.get_peer_network_id_for_peer(peer);
        self.network_client
            .send_to_peer_rpc(message, rpc_timeout, peer_network_id)
            .await
    }
```

**File:** network/framework/src/application/interface.rs (L132-138)
```rust
    /// Identify the supported protocols from the specified peer's connection
    fn get_supported_protocols(&self, peer: &PeerNetworkId) -> Result<ProtocolIdSet, Error> {
        let peers_and_metadata = self.get_peers_and_metadata();
        peers_and_metadata
            .get_metadata_for_peer(*peer)
            .map(|peer_metadata| peer_metadata.get_supported_protocols())
    }
```

**File:** network/framework/src/application/interface.rs (L260-272)
```rust
    async fn send_to_peer_rpc(
        &self,
        message: Message,
        rpc_timeout: Duration,
        peer: PeerNetworkId,
    ) -> Result<Message, Error> {
        let network_sender = self.get_sender_for_network_id(&peer.network_id())?;
        let rpc_protocol_id =
            self.get_preferred_protocol_for_peer(&peer, &self.rpc_protocols_and_preferences)?;
        Ok(network_sender
            .send_rpc(peer.peer_id(), rpc_protocol_id, message, rpc_timeout)
            .await?)
    }
```

**File:** network/framework/src/application/storage.rs (L107-125)
```rust
    /// Returns metadata for all peers currently connected to the node
    pub fn get_connected_peers_and_metadata(
        &self,
    ) -> Result<HashMap<PeerNetworkId, PeerMetadata>, Error> {
        // Get the cached peers and metadata
        let cached_peers_and_metadata = self.cached_peers_and_metadata.load();

        // Collect all connected peers
        let mut connected_peers_and_metadata = HashMap::new();
        for (network_id, peers_and_metadata) in cached_peers_and_metadata.iter() {
            for (peer_id, peer_metadata) in peers_and_metadata.iter() {
                if peer_metadata.is_connected() {
                    let peer_network_id = PeerNetworkId::new(*network_id, *peer_id);
                    connected_peers_and_metadata.insert(peer_network_id, peer_metadata.clone());
                }
            }
        }
        Ok(connected_peers_and_metadata)
    }
```

**File:** network/framework/src/application/storage.rs (L150-169)
```rust
    /// Returns the metadata for the specified peer
    pub fn get_metadata_for_peer(
        &self,
        peer_network_id: PeerNetworkId,
    ) -> Result<PeerMetadata, Error> {
        // Get the cached peers and metadata
        let cached_peers_and_metadata = self.cached_peers_and_metadata.load();

        // Fetch the peers and metadata for the given network
        let network_id = peer_network_id.network_id();
        let peer_metadata_for_network = cached_peers_and_metadata
            .get(&network_id)
            .ok_or_else(|| missing_network_metadata_error(&network_id))?;

        // Get the metadata for the peer
        peer_metadata_for_network
            .get(&peer_network_id.peer_id())
            .cloned()
            .ok_or_else(|| missing_peer_metadata_error(&peer_network_id))
    }
```

**File:** network/framework/src/application/metadata.rs (L11-18)
```rust
/// The current connection state of a peer
/// TODO: Allow nodes that are unhealthy to stay connected
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ConnectionState {
    Connected,
    Disconnecting,
    Disconnected, // Currently unused (TODO: fix this!)
}
```

**File:** network/framework/src/protocols/health_checker/interface.rs (L65-81)
```rust
    pub async fn disconnect_peer(
        &mut self,
        peer_network_id: PeerNetworkId,
        disconnect_reason: DisconnectReason,
    ) -> Result<(), Error> {
        // Possibly already disconnected, but try anyways
        let _ = self.update_connection_state(peer_network_id, ConnectionState::Disconnecting);
        let result = self
            .network_client
            .disconnect_from_peer(peer_network_id, disconnect_reason)
            .await;
        let peer_id = peer_network_id.peer_id();
        if result.is_ok() {
            self.health_check_data.write().remove(&peer_id);
        }
        result
    }
```

**File:** network/framework/src/peer_manager/mod.rs (L528-546)
```rust
        if let Some((conn_metadata, sender)) = self.active_peers.get_mut(&peer_id) {
            if let Err(err) = sender.push(protocol_id, peer_request) {
                info!(
                    NetworkSchema::new(&self.network_context).connection_metadata(conn_metadata),
                    protocol_id = %protocol_id,
                    error = ?err,
                    "{} Failed to forward outbound message to downstream actor. Error: {:?}",
                    self.network_context, err
                );
            }
        } else {
            warn!(
                NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                protocol_id = %protocol_id,
                "{} Can't send message to peer.  Peer {} is currently not connected",
                self.network_context,
                peer_id.short_str()
            );
        }
```

**File:** crates/reliable-broadcast/src/lib.rs (L191-200)
```rust
                            Err(e) => {
                                log_rpc_failure(e, receiver);

                                let backoff_strategy = backoff_policies
                                    .get_mut(&receiver)
                                    .expect("should be present");
                                let duration = backoff_strategy.next().expect("should produce value");
                                rpc_futures
                                    .push(send_message(receiver, Some(duration)));
                            },
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L204-212)
```rust
            let rb = ReliableBroadcast::new(
                self.my_addr,
                epoch_state.verifier.get_ordered_account_addresses(),
                Arc::new(network_sender),
                ExponentialBackoff::from_millis(5),
                aptos_time_service::TimeService::real(),
                Duration::from_millis(1000),
                BoundedExecutor::new(8, tokio::runtime::Handle::current()),
            );
```
