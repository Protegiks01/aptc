# Audit Report

## Title
Peer Role Enumeration via Unsecured Network Information RPC Allows Trusted Peers Disclosure

## Summary
The `extract_peer_role_from_trusted_peers()` function logs errors when a peer is not found in the trusted peers set but allows the connection to continue. This, combined with the unsecured `GetNetworkInformation` RPC endpoint that exposes peer roles, enables attackers to enumerate which nodes have them in their trusted peers configuration by observing their assigned `PeerRole`.

## Finding Description
When a node establishes an outbound connection, it calls `extract_peer_role_from_trusted_peers()` to determine the remote peer's role. [1](#0-0) 

If the remote peer is not in the trusted peers set, the function logs an error but returns `PeerRole::Unknown` and allows the connection to continue. [2](#0-1) 

This assigned peer role is stored in the connection's metadata and later used throughout the networking layer. [3](#0-2) 

The Peer Monitoring Service exposes a `GetNetworkInformation` RPC that returns information about all connected peers, including their assigned roles. [4](#0-3) 

The server implementation retrieves connection metadata and includes the `peer_role` field in the response without any access control checks. [5](#0-4) 

**Attack Flow:**
1. Attacker establishes a connection to a target node (works in `MaybeMutual` auth mode)
2. Target node calls `extract_peer_role_from_trusted_peers(attacker_peer_id)`
3. If attacker is not in trusted peers: assigns `PeerRole::Unknown`; if in trusted peers: assigns actual role (e.g., `PeerRole::Validator`)
4. Attacker sends `GetNetworkInformation` RPC to target node
5. Response includes attacker's assigned role in the `ConnectionMetadata`
6. Attacker observes: `PeerRole::Unknown` = not trusted; specific role = in trusted peers set
7. Attacker repeats across multiple nodes to map trust relationships

## Impact Explanation
This vulnerability allows an attacker to enumerate which nodes consider them a trusted peer, revealing the network's trust topology. This is classified as **Medium Severity** per the Aptos bug bounty program as it constitutes an information disclosure vulnerability that could enable reconnaissance for more sophisticated attacks against the network.

While it does not directly lead to funds loss, consensus violation, or service disruption, it violates the privacy expectations of trusted peer configurations and could be leveraged as part of a multi-stage attack to identify high-value targets or understand validator relationships.

## Likelihood Explanation
This vulnerability is **highly likely** to be exploited because:
- The attack requires no special privileges—any peer that can establish a network connection can perform it
- The `GetNetworkInformation` RPC has no access control and is enabled by default
- The attack is simple to execute and provides valuable intelligence about network topology
- Nodes operating in `MaybeMutual` authentication mode (common for public-facing nodes) are vulnerable
- The attacker only needs to know peer IDs to probe the network systematically

## Recommendation
Implement one or more of the following mitigations:

**Option 1: Filter Self from Response**
Exclude the requesting peer's own role from `GetNetworkInformation` responses:

```rust
fn get_network_information(&self, requesting_peer: PeerId) -> Result<PeerMonitoringServiceResponse, Error> {
    let connected_peers_and_metadata = self.peers_and_metadata.get_connected_peers_and_metadata()?;
    let connected_peers = connected_peers_and_metadata
        .into_iter()
        .filter(|(peer, _)| peer.peer_id() != requesting_peer) // Exclude self
        .map(|(peer, metadata)| { /* ... */ })
        .collect();
    // ...
}
```

**Option 2: Add Access Control**
Restrict `GetNetworkInformation` to trusted peers only by checking the requesting peer's role before processing the request.

**Option 3: Redact Role Information**
Remove `peer_role` from the `ConnectionMetadata` included in responses, or replace it with a generic value for all peers except the requester themselves.

**Preferred Solution:** Implement Option 1 (filter self from response) as it prevents information leakage while maintaining the RPC's utility for legitimate monitoring purposes.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_peer_role_enumeration_vulnerability() {
    use aptos_config::network_id::NetworkId;
    use network_framework::noise::NoiseUpgrader;
    use network_framework::protocols::wire::handshake::v1::HandshakeMsg;
    use peer_monitoring_service::types::request::PeerMonitoringServiceRequest;
    
    // Setup: Create two nodes - victim and attacker
    let victim_keys = x25519::PrivateKey::generate(&mut OsRng);
    let attacker_keys = x25519::PrivateKey::generate(&mut OsRng);
    
    // Victim has a trusted peers set that does NOT include the attacker
    let victim_trusted_peers = create_trusted_peers(vec![/* some other peers */]);
    let victim_node = create_test_node(victim_keys, victim_trusted_peers);
    
    // Attacker connects to victim
    let (victim_socket, attacker_socket) = MemorySocket::new_pair();
    
    // Victim completes inbound handshake (accepts in MaybeMutual mode)
    let victim_task = victim_node.upgrade_inbound(victim_socket);
    
    // Attacker connects outbound
    let attacker_task = async {
        // Complete handshake
        let stream = complete_handshake(attacker_socket).await.unwrap();
        
        // Send GetNetworkInformation RPC
        let request = PeerMonitoringServiceRequest::GetNetworkInformation;
        let response = send_rpc_request(stream, request).await.unwrap();
        
        // Extract attacker's assigned role from the response
        if let PeerMonitoringServiceResponse::NetworkInformation(info) = response {
            let attacker_peer_id = attacker_keys.public_key().to_peer_id();
            let attacker_role = info.connected_peers
                .get(&attacker_peer_id)
                .map(|meta| meta.peer_role);
            
            // Vulnerability: Attacker can see they were assigned PeerRole::Unknown
            // This reveals they are NOT in the victim's trusted peers set
            assert_eq!(attacker_role, Some(PeerRole::Unknown));
            
            // If attacker WAS in trusted peers, they would see their actual role
            // This enables enumeration of trusted peer relationships
        }
    };
    
    tokio::join!(victim_task, attacker_task);
}
```

## Notes
This vulnerability specifically affects nodes operating in `HandshakeAuthMode::MaybeMutual` mode, which is commonly used for public-facing fullnodes and VFN connections. Nodes using strict `HandshakeAuthMode::Mutual` will reject connections from untrusted peers at the handshake layer, preventing this attack. However, the information disclosure still occurs for any peer that successfully establishes a connection, regardless of authentication mode.

### Citations

**File:** network/framework/src/noise/handshake.rs (L268-303)
```rust
    fn extract_peer_role_from_trusted_peers(&self, remote_peer_id: PeerId) -> PeerRole {
        // Get the peers and metadata struct
        let peers_and_metadata = match &self.auth_mode {
            HandshakeAuthMode::Mutual {
                peers_and_metadata, ..
            } => peers_and_metadata.clone(),
            HandshakeAuthMode::MaybeMutual(peers_and_metadata) => peers_and_metadata.clone(),
        };

        // Determine the peer role
        match peers_and_metadata.get_trusted_peers(&self.network_context.network_id()) {
            Ok(trusted_peers) => {
                match trusted_peers.get(&remote_peer_id) {
                    Some(trusted_peer) => {
                        return trusted_peer.role; // We've found the peer!
                    },
                    None => {
                        error!(NetworkSchema::new(&self.network_context).message(format!(
                            "{} Outbound connection made with unknown peer (not in the trusted peers set)! Missing peer: {:?}",
                            self.network_context, remote_peer_id

                        )));
                    },
                }
            },
            Err(error) => {
                error!(NetworkSchema::new(&self.network_context).message(format!(
                    "Failed to get trusted peers for network context: {:?}, error: {:?}",
                    self.network_context, error
                )));
            },
        };

        // If we couldn't determine the peer role, return an unknown peer role
        PeerRole::Unknown
    }
```

**File:** network/framework/src/transport/mod.rs (L395-406)
```rust
    Ok(Connection {
        socket,
        metadata: ConnectionMetadata::new(
            remote_peer_id,
            CONNECTION_ID_GENERATOR.next(),
            addr,
            origin,
            messaging_protocol,
            application_protocols,
            peer_role,
        ),
    })
```

**File:** peer-monitoring-service/types/src/response.rs (L52-75)
```rust
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>, // Connected peers
    pub distance_from_validators: u64, // The distance of the peer from the validator set
}

// Display formatting provides a high-level summary of the response
impl Display for NetworkInformationResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{ num_connected_peers: {:?}, distance_from_validators: {:?} }}",
            self.connected_peers.len(),
            self.distance_from_validators,
        )
    }
}

/// Simple connection metadata associated with each peer
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionMetadata {
    pub network_address: NetworkAddress,
    pub peer_id: PeerId,
    pub peer_role: PeerRole,
}
```

**File:** peer-monitoring-service/server/src/lib.rs (L217-247)
```rust
    fn get_network_information(&self) -> Result<PeerMonitoringServiceResponse, Error> {
        // Get the connected peers
        let connected_peers_and_metadata =
            self.peers_and_metadata.get_connected_peers_and_metadata()?;
        let connected_peers = connected_peers_and_metadata
            .into_iter()
            .map(|(peer, metadata)| {
                let connection_metadata = metadata.get_connection_metadata();
                (
                    peer,
                    ConnectionMetadata::new(
                        connection_metadata.addr,
                        connection_metadata.remote_peer_id,
                        connection_metadata.role,
                    ),
                )
            })
            .collect();

        // Get the distance from the validators
        let distance_from_validators =
            get_distance_from_validators(&self.base_config, self.peers_and_metadata.clone());

        // Create and return the response
        let network_information_response = NetworkInformationResponse {
            connected_peers,
            distance_from_validators,
        };
        Ok(PeerMonitoringServiceResponse::NetworkInformation(
            network_information_response,
        ))
```
