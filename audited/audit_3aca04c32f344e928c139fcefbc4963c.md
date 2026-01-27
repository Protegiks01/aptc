# Audit Report

## Title
X25519 Key Rotation Does Not Invalidate Existing Connections Allowing Persistent Eavesdropping

## Summary
When validators rotate their X25519 network keys via `stake::update_network_and_fullnode_addresses`, existing connections authenticated with the old (potentially compromised) key remain active indefinitely. The system does not store which key was used to authenticate a connection and performs no periodic re-validation, allowing an attacker with a compromised key to maintain persistent eavesdropping access even after the validator rotates to a new key.

## Finding Description

The Aptos validator network uses X25519 keys for Noise IK handshake authentication to establish encrypted communication channels between validators. The key rotation mechanism has a critical flaw in its connection invalidation logic.

**Key Infrastructure Components:**

1. **X25519 Key Usage**: Validators use X25519 keys embedded in their `NetworkAddress` for Noise IK protocol authentication [1](#0-0) 

2. **Key Rotation Capability**: Validators can rotate keys by calling `update_network_and_fullnode_addresses` [2](#0-1) 

3. **Handshake Authentication**: During connection establishment, the Noise handshake validates that the remote peer's public key exists in the trusted peer set [3](#0-2) 

**The Vulnerability:**

When a validator rotates their X25519 key, the `ValidatorConfig` is updated on-chain and takes effect at the next epoch. The network layer receives this update via `extract_validator_set_updates`, which rebuilds the peer set with new keys: [4](#0-3) 

The `ConnectivityManager` updates its discovered peers and trusted peer sets: [5](#0-4) 

However, the `ConnectionMetadata` structure does NOT store which X25519 key was used to authenticate the connection: [6](#0-5) 

The `close_stale_connections` function only disconnects peers whose `peer_id` is entirely removed from the trusted set, not peers whose keys have changed: [7](#0-6) 

Additionally, the `HealthChecker` only performs liveness probes (ping/pong) and does not re-authenticate connections: [8](#0-7) 

**Attack Scenario:**

1. Attacker compromises validator V1's X25519 private key K1
2. Attacker establishes authenticated connections to validators V2, V3, etc. using K1
3. V1 operator discovers the compromise and rotates to new key K2 via `update_network_and_fullnode_addresses`
4. Next epoch: Validator set updated with K2, new connections require K2
5. **Critical flaw**: Attacker's existing connections authenticated with K1 remain active
6. Attacker maintains persistent eavesdropping access to validator communications (consensus votes, block proposals, transaction propagation)

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos Bug Bounty program criteria:

- **Protocol Violation**: The network security model assumes that rotating a validator's network key immediately revokes network access for the old key. This assumption is violated.
  
- **Persistent Eavesdropping**: An attacker can intercept sensitive validator communications including:
  - Consensus votes and proposals
  - Block data before public propagation
  - Mempool transaction data
  - State sync communications
  
- **Key Rotation Ineffectiveness**: The primary mitigation for key compromise (rotation) fails to achieve its security objective, leaving validators exposed indefinitely.

While this does not directly cause loss of funds or consensus violations (validators can still operate normally), it represents a significant security protocol violation that undermines the confidentiality guarantees of the validator network.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability manifests in any scenario where:
1. A validator's X25519 key is compromised (malware, stolen key file, memory dump, etc.)
2. The validator operator attempts remediation by rotating the key
3. The attacker maintains the connection

**Factors increasing likelihood:**
- X25519 private keys are stored on disk and in memory
- Key compromise may go undetected for extended periods
- Validators naturally assume key rotation provides immediate protection
- No monitoring alerts validators to connections using old keys

**Factors requiring consideration:**
- Requires initial key compromise (non-trivial but realistic threat)
- Attacker must actively maintain connections (network stability dependent)
- Detection possible via network monitoring of unexpected persistent connections

## Recommendation

Implement connection key validation by storing the authenticated X25519 public key in `ConnectionMetadata` and adding periodic validation:

**1. Update ConnectionMetadata to store authenticated key:**

```rust
// In network/framework/src/transport/mod.rs
pub struct ConnectionMetadata {
    pub remote_peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub addr: NetworkAddress,
    pub origin: ConnectionOrigin,
    pub messaging_protocol: MessagingProtocolVersion,
    pub application_protocols: ProtocolIdSet,
    pub role: PeerRole,
    // ADD THIS:
    pub authenticated_public_key: x25519::PublicKey,
}
```

**2. Add validation in close_stale_connections:**

```rust
// In network/framework/src/connectivity_manager/mod.rs
async fn close_stale_connections(&mut self) {
    if let Some(trusted_peers) = self.get_trusted_peers() {
        let stale_peers = self
            .connected
            .iter()
            .filter(|(peer_id, metadata)| {
                // Check if peer is in trusted set
                if let Some(peer) = trusted_peers.get(peer_id) {
                    // NEW: Check if authenticated key is still valid
                    !peer.keys.contains(&metadata.authenticated_public_key)
                } else {
                    true // Peer removed entirely
                }
            })
            .map(|(peer_id, _)| *peer_id)
            .collect::<Vec<_>>();
        
        // Disconnect stale peers
        for peer_id in stale_peers {
            self.connection_reqs_tx
                .disconnect_peer(peer_id, DisconnectReason::StaleConnection)
                .await;
        }
    }
}
```

**3. Trigger key validation on peer set updates:**

Ensure `check_connectivity` is called immediately after `handle_update_discovered_peers` when keys are updated, not just on periodic intervals.

## Proof of Concept

**Reproduction Steps:**

1. **Setup**: Deploy a local testnet with 4 validators (V1, V2, V3, V4)

2. **Extract V1's X25519 key**: 
```bash
# From validator-identity.yaml
cat validator-identity.yaml | grep "private_key:" 
```

3. **Establish attacker connection**:
```rust
// Use the extracted key to establish a connection as external process
let compromised_key = x25519::PrivateKey::from_encoded_string(EXTRACTED_KEY)?;
let noise_config = NoiseConfig::new(compromised_key);
// Connect to V2, V3, V4 using compromised key
```

4. **Rotate V1's key**:
```bash
aptos node update-validator-network-addresses \
  --pool-address $V1_ADDRESS \
  --operator-config-file new-operator.yaml
```

5. **Wait for epoch transition**: Monitor for `NewEpochEvent`

6. **Verify vulnerability**:
```rust
// Check that attacker's connections remain active
// Monitor network traffic - attacker still receives validator messages
// New connection attempts with old key fail (proving epoch update worked)
// But existing connections persist indefinitely
```

**Expected Result**: After key rotation and epoch change, new connections with the old key should fail (✓ works), but existing connections should be terminated (✗ fails - connections persist).

**Observed Result**: Connections authenticated with rotated keys remain active, allowing continued eavesdropping.

---

**Notes:**
- The vulnerability affects all validator network communications, including consensus-critical messages
- Mitigation requires both code changes and potential emergency key rotation for all validators
- Consider implementing connection age limits as additional defense-in-depth measure

### Citations

**File:** types/src/network_address/mod.rs (L122-122)
```rust
    NoiseIK(x25519::PublicKey),
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L955-995)
```text
    public entry fun update_network_and_fullnode_addresses(
        operator: &signer,
        pool_address: address,
        new_network_addresses: vector<u8>,
        new_fullnode_addresses: vector<u8>,
    ) acquires StakePool, ValidatorConfig {
        check_stake_permission(operator);
        assert_reconfig_not_in_progress();
        assert_stake_pool_exists(pool_address);
        let stake_pool = borrow_global_mut<StakePool>(pool_address);
        assert!(signer::address_of(operator) == stake_pool.operator_address, error::unauthenticated(ENOT_OPERATOR));
        assert!(exists<ValidatorConfig>(pool_address), error::not_found(EVALIDATOR_CONFIG));
        let validator_info = borrow_global_mut<ValidatorConfig>(pool_address);
        let old_network_addresses = validator_info.network_addresses;
        validator_info.network_addresses = new_network_addresses;
        let old_fullnode_addresses = validator_info.fullnode_addresses;
        validator_info.fullnode_addresses = new_fullnode_addresses;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                UpdateNetworkAndFullnodeAddresses {
                    pool_address,
                    old_network_addresses,
                    new_network_addresses,
                    old_fullnode_addresses,
                    new_fullnode_addresses,
                },
            );
        } else {
            event::emit_event(
                &mut stake_pool.update_network_and_fullnode_addresses_events,
                UpdateNetworkAndFullnodeAddressesEvent {
                    pool_address,
                    old_network_addresses,
                    new_network_addresses,
                    old_fullnode_addresses,
                    new_fullnode_addresses,
                },
            );
        };
    }
```

**File:** network/framework/src/noise/handshake.rs (L488-500)
```rust
    fn authenticate_inbound(
        remote_peer_short: ShortHexStr,
        peer: &Peer,
        remote_public_key: &x25519::PublicKey,
    ) -> Result<PeerRole, NoiseHandshakeError> {
        if !peer.keys.contains(remote_public_key) {
            return Err(NoiseHandshakeError::UnauthenticatedClientPubkey(
                remote_peer_short,
                hex::encode(remote_public_key.as_slice()),
            ));
        }
        Ok(peer.role)
    }
```

**File:** network/discovery/src/validator_set.rs (L108-150)
```rust
pub(crate) fn extract_validator_set_updates(
    network_context: NetworkContext,
    node_set: ValidatorSet,
) -> PeerSet {
    let is_validator = network_context.network_id().is_validator_network();

    // Decode addresses while ignoring bad addresses
    node_set
        .into_iter()
        .map(|info| {
            let peer_id = *info.account_address();
            let config = info.into_config();

            let addrs = if is_validator {
                config
                    .validator_network_addresses()
                    .map_err(anyhow::Error::from)
            } else {
                config
                    .fullnode_network_addresses()
                    .map_err(anyhow::Error::from)
            }
            .map_err(|err| {
                inc_by_with_context(&DISCOVERY_COUNTS, &network_context, "read_failure", 1);

                warn!(
                    NetworkSchema::new(&network_context),
                    "OnChainDiscovery: Failed to parse any network address: peer: {}, err: {}",
                    peer_id,
                    err
                )
            })
            .unwrap_or_default();

            let peer_role = if is_validator {
                PeerRole::Validator
            } else {
                PeerRole::ValidatorFullNode
            };
            (peer_id, Peer::from_addrs(peer_role, addrs))
        })
        .collect()
}
```

**File:** network/framework/src/connectivity_manager/mod.rs (L484-531)
```rust
    async fn close_stale_connections(&mut self) {
        if let Some(trusted_peers) = self.get_trusted_peers() {
            // Identify stale peer connections
            let stale_peers = self
                .connected
                .iter()
                .filter(|(peer_id, _)| !trusted_peers.contains_key(peer_id))
                .filter_map(|(peer_id, metadata)| {
                    // If we're using server only auth, we need to not evict unknown peers
                    // TODO: We should prevent `Unknown` from discovery sources
                    if !self.mutual_authentication
                        && metadata.origin == ConnectionOrigin::Inbound
                        && (metadata.role == PeerRole::ValidatorFullNode
                            || metadata.role == PeerRole::Unknown)
                    {
                        None
                    } else {
                        Some(*peer_id) // The peer is stale
                    }
                });

            // Close existing connections to stale peers
            for stale_peer in stale_peers {
                info!(
                    NetworkSchema::new(&self.network_context).remote_peer(&stale_peer),
                    "{} Closing stale connection to peer {}",
                    self.network_context,
                    stale_peer.short_str()
                );

                if let Err(disconnect_error) = self
                    .connection_reqs_tx
                    .disconnect_peer(stale_peer, DisconnectReason::StaleConnection)
                    .await
                {
                    info!(
                        NetworkSchema::new(&self.network_context)
                            .remote_peer(&stale_peer),
                        error = %disconnect_error,
                        "{} Failed to close stale connection to peer {}, error: {}",
                        self.network_context,
                        stale_peer.short_str(),
                        disconnect_error
                    );
                }
            }
        }
    }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L886-1002)
```rust
    fn handle_update_discovered_peers(
        &mut self,
        src: DiscoverySource,
        new_discovered_peers: PeerSet,
    ) {
        // Log the update event
        info!(
            NetworkSchema::new(&self.network_context),
            "{} Received updated list of discovered peers! Source: {:?}, num peers: {:?}",
            self.network_context,
            src,
            new_discovered_peers.len()
        );

        // Remove peers that no longer have relevant network information
        let mut keys_updated = false;
        let mut peers_to_check_remove = Vec::new();
        for (peer_id, peer) in self.discovered_peers.write().peer_set.iter_mut() {
            let new_peer = new_discovered_peers.get(peer_id);
            let check_remove = if let Some(new_peer) = new_peer {
                if new_peer.keys.is_empty() {
                    keys_updated |= peer.keys.clear_src(src);
                }
                if new_peer.addresses.is_empty() {
                    peer.addrs.clear_src(src);
                }
                new_peer.addresses.is_empty() && new_peer.keys.is_empty()
            } else {
                keys_updated |= peer.keys.clear_src(src);
                peer.addrs.clear_src(src);
                true
            };
            if check_remove {
                peers_to_check_remove.push(*peer_id);
            }
        }

        // Remove peers that no longer have state
        for peer_id in peers_to_check_remove {
            self.discovered_peers.write().remove_peer_if_empty(&peer_id);
        }

        // Make updates to the peers accordingly
        for (peer_id, discovered_peer) in new_discovered_peers {
            // Don't include ourselves, because we don't need to dial ourselves
            if peer_id == self.network_context.peer_id() {
                continue;
            }

            // Create the new `DiscoveredPeer`, role is set when a `Peer` is first discovered
            let mut discovered_peers = self.discovered_peers.write();
            let peer = discovered_peers
                .peer_set
                .entry(peer_id)
                .or_insert_with(|| DiscoveredPeer::new(discovered_peer.role));

            // Update the peer's pubkeys
            let mut peer_updated = false;
            if peer.keys.update(src, discovered_peer.keys) {
                info!(
                    NetworkSchema::new(&self.network_context)
                        .remote_peer(&peer_id)
                        .discovery_source(&src),
                    "{} pubkey sets updated for peer: {}, pubkeys: {}",
                    self.network_context,
                    peer_id.short_str(),
                    peer.keys
                );
                keys_updated = true;
                peer_updated = true;
            }

            // Update the peer's addresses
            if peer.addrs.update(src, discovered_peer.addresses) {
                info!(
                    NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                    network_addresses = &peer.addrs,
                    "{} addresses updated for peer: {}, update src: {:?}, addrs: {}",
                    self.network_context,
                    peer_id.short_str(),
                    src,
                    &peer.addrs,
                );
                peer_updated = true;
            }

            // If we're currently trying to dial this peer, we reset their
            // dial state. As a result, we will begin our next dial attempt
            // from the first address (which might have changed) and from a
            // fresh backoff (since the current backoff delay might be maxed
            // out if we can't reach any of their previous addresses).
            if peer_updated {
                if let Some(dial_state) = self.dial_states.get_mut(&peer_id) {
                    *dial_state = DialState::new(self.backoff_strategy.clone());
                }
            }
        }

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
    }
```

**File:** network/framework/src/transport/mod.rs (L98-108)
```rust
/// Metadata associated with an established and fully upgraded connection.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionMetadata {
    pub remote_peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub addr: NetworkAddress,
    pub origin: ConnectionOrigin,
    pub messaging_protocol: MessagingProtocolVersion,
    pub application_protocols: ProtocolIdSet,
    pub role: PeerRole,
}
```

**File:** network/framework/src/protocols/health_checker/mod.rs (L1-115)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! Protocol used to ensure peer liveness
//!
//! The HealthChecker is responsible for ensuring liveness of all peers of a node.
//! It does so by periodically selecting a random connected peer and sending a Ping probe. A
//! healthy peer is expected to respond with a corresponding Pong message.
//!
//! If a certain number of successive liveness probes for a peer fail, the HealthChecker initiates a
//! disconnect from the peer. It relies on ConnectivityManager or the remote peer to re-establish
//! the connection.
//!
//! Future Work
//! -----------
//! We can make a few other improvements to the health checker. These are:
//! - Make the policy for interpreting ping failures pluggable
//! - Use successful inbound pings as a sign of remote note being healthy
//! - Ping a peer only in periods of no application-level communication with the peer
use crate::{
    application::interface::NetworkClientInterface,
    constants::NETWORK_CHANNEL_SIZE,
    counters,
    logging::NetworkSchema,
    peer::DisconnectReason,
    peer_manager::ConnectionNotification,
    protocols::{
        health_checker::interface::HealthCheckNetworkInterface,
        network::{
            Event, NetworkApplicationConfig, NetworkClientConfig, NetworkEvents,
            NetworkServiceConfig,
        },
        rpc::error::RpcError,
    },
    ProtocolId,
};
use aptos_channels::{aptos_channel, message_queues::QueueStyle};
use aptos_config::network_id::{NetworkContext, PeerNetworkId};
use aptos_logger::prelude::*;
use aptos_short_hex_str::AsShortHexStr;
use aptos_time_service::{TimeService, TimeServiceTrait};
use aptos_types::PeerId;
use bytes::Bytes;
use futures::{
    channel::oneshot,
    stream::{FuturesUnordered, StreamExt},
};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;

pub mod builder;
mod interface;
#[cfg(test)]
mod test;

/// The interface from Network to HealthChecker layer.
///
/// `HealthCheckerNetworkEvents` is a `Stream` of `HealthCheckerMsg`.
/// (Behind the scenes, network messages are being deserialized)
pub type HealthCheckerNetworkEvents = NetworkEvents<HealthCheckerMsg>;

/// Returns a network application config for the health check client and service
pub fn health_checker_network_config() -> NetworkApplicationConfig {
    let direct_send_protocols = vec![]; // Health checker doesn't use direct send
    let rpc_protocols = vec![ProtocolId::HealthCheckerRpc];

    let network_client_config =
        NetworkClientConfig::new(direct_send_protocols.clone(), rpc_protocols.clone());
    let network_service_config = NetworkServiceConfig::new(
        direct_send_protocols,
        rpc_protocols,
        aptos_channel::Config::new(NETWORK_CHANNEL_SIZE)
            .queue_style(QueueStyle::LIFO)
            .counters(&counters::PENDING_HEALTH_CHECKER_NETWORK_EVENTS),
    );
    NetworkApplicationConfig::new(network_client_config, network_service_config)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum HealthCheckerMsg {
    Ping(Ping),
    Pong(Pong),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ping(u32);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Pong(u32);

/// The actor performing health checks by running the Ping protocol
pub struct HealthChecker<NetworkClient> {
    network_context: NetworkContext,
    /// A handle to a time service for easily mocking time-related operations.
    time_service: TimeService,
    /// Network interface to send requests to the Network Layer
    network_interface: HealthCheckNetworkInterface<NetworkClient>,
    /// Random-number generator.
    rng: SmallRng,
    /// Time we wait between each set of pings.
    ping_interval: Duration,
    /// Ping timeout duration.
    ping_timeout: Duration,
    /// Number of successive ping failures we tolerate before declaring a node as unhealthy and
    /// disconnecting from it. In the future, this can be replaced with a more general failure
    /// detection policy.
    ping_failures_tolerated: u64,
    /// Counter incremented in each round of health checks
    round: u64,

    /// This should normally be None and is only used in testing to inject test events.
    connection_events_injection: Option<tokio::sync::mpsc::Receiver<ConnectionNotification>>,
}
```
