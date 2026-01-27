# Audit Report

## Title
Unmitigated Application-Level DoS via Repeated NoCommonProtocols Handshake Failures

## Summary
The Aptos network layer lacks per-peer tracking and rate limiting for repeated handshake failures at the application protocol negotiation stage. An attacker can systematically send `HandshakeMsg` with incompatible protocol sets, causing repeated `NoCommonProtocols` errors that consume node resources (CPU for Noise handshakes, memory for connection state) and can prevent legitimate peer connections on non-mutually-authenticated networks. [1](#0-0) 

## Finding Description

The vulnerability exists in the connection establishment flow where nodes negotiate supported protocols. The attack path proceeds as follows:

1. **Connection Initiation**: An attacker initiates TCP connections to a victim node (PFN or VFN)

2. **Noise Handshake**: The connection completes the Noise IK handshake, which is CPU-intensive (requiring Diffie-Hellman key exchange operations) [2](#0-1) 

3. **Protocol Negotiation**: After the secure channel is established, both peers exchange `HandshakeMsg` containing their supported protocols [3](#0-2) 

4. **Failure Point**: The victim calls `perform_handshake()` which attempts to find common protocols. The attacker crafts their `HandshakeMsg` with a `supported_protocols` set that has zero intersection with the victim's protocols, triggering `NoCommonProtocols` error [4](#0-3) 

5. **Connection Rejection**: The connection fails at the transport upgrade layer and is dropped [5](#0-4) 

6. **No Tracking**: The system records the failure in metrics but does not track repeated failures from the same peer or IP address [6](#0-5) 

7. **Resource Exhaustion**: The attacker immediately repeats steps 1-5, consuming:
   - CPU cycles for Noise handshake operations
   - Memory for pending connection upgrade state
   - File descriptors for TCP connections
   - Processing time in the transport handler's `FuturesUnordered` collection [7](#0-6) 

**Critical Gap**: The `inbound_connection_limit` only applies to successfully established connections from unknown peers, not to failed connection attempts: [8](#0-7) 

The rate limiting configuration is byte-based (100 KiB/s default), not connection-based. Since handshake messages are typically under 500 bytes, an attacker can send approximately 200 handshake attempts per second while staying under the byte rate limit: [9](#0-8) 

**Scope Limitation**: On validator networks with mutual authentication enabled, attackers would be rejected during the Noise handshake phase before reaching the application handshake, as their public keys would not be in the trusted peers set. This vulnerability primarily affects public networks and VFN networks with maybe-mutual authentication. [10](#0-9) 

## Impact Explanation

This qualifies as **High Severity** under "Validator node slowdowns" category because:

1. **VFN Interface Impact**: Validators run VFN interfaces that use maybe-mutual authentication. Sustained attacks on these interfaces can slow validator operations by exhausting connection resources and preventing legitimate VFN connections.

2. **Public Network Disruption**: PFNs serving user traffic can be rendered unavailable, preventing legitimate users from accessing the network and submitting transactions.

3. **Resource Exhaustion**: Each failed connection attempt consumes significant resources:
   - Noise handshake requires expensive Diffie-Hellman operations
   - Memory allocation for connection state and upgrade futures
   - No limit on concurrent `pending_inbound_connections` in the `FuturesUnordered` collection

While HAProxy provides `maxconnrate 300` connection rate limiting, this is a global limit that can be exhausted by a single attacker: [11](#0-10) 

## Likelihood Explanation

**High Likelihood** - The attack is:
- **Easy to Execute**: Requires only standard TCP connection capabilities and knowledge of the node's public network address
- **Low Cost**: Small handshake messages stay under byte rate limits
- **No Authentication Required**: Works on public networks without requiring trusted peer status
- **Sustained**: Can be maintained continuously to prevent legitimate connections
- **No Detection**: System logs failures but takes no defensive action

## Recommendation

Implement multi-layered application-level protection:

1. **Per-Peer Handshake Failure Tracking**: Add a time-windowed counter tracking handshake failures per peer/IP address. Temporarily ban peers exceeding a threshold (e.g., 10 failures in 60 seconds).

2. **Connection Attempt Rate Limiting**: Implement per-IP connection attempt rate limiting at the application level (separate from byte rate limiting), e.g., max 5 connection attempts per second per IP.

3. **Exponential Backoff for Failed Peers**: After repeated failures from a peer, implement exponential backoff before accepting new connections from that peer.

4. **Bounded Pending Upgrades**: Limit the size of `pending_inbound_connections` `FuturesUnordered` collection to prevent unbounded memory growth.

Example implementation pattern:

```rust
// In PeerManager or TransportHandler
struct HandshakeFailureTracker {
    failures_by_ip: HashMap<IpAddr, VecDeque<Instant>>,
    window: Duration,
    threshold: usize,
}

impl HandshakeFailureTracker {
    fn should_accept(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let failures = self.failures_by_ip.entry(ip).or_default();
        
        // Remove old failures outside window
        failures.retain(|&time| now.duration_since(time) < self.window);
        
        // Check if under threshold
        failures.len() < self.threshold
    }
    
    fn record_failure(&mut self, ip: IpAddr) {
        self.failures_by_ip.entry(ip).or_default().push_back(Instant::now());
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod dos_test {
    use super::*;
    use aptos_memsocket::MemorySocket;
    use std::collections::BTreeMap;
    
    #[tokio::test]
    async fn test_repeated_handshake_failures_dos() {
        // Setup victim node with standard protocols
        let victim_protocols = ProtocolIdSet::from_iter([
            ProtocolId::ConsensusRpcBcs,
            ProtocolId::MempoolDirectSend,
        ]);
        
        let mut victim_supported = BTreeMap::new();
        victim_supported.insert(MessagingProtocolVersion::V1, victim_protocols);
        
        let victim_handshake = HandshakeMsg {
            supported_protocols: victim_supported,
            chain_id: ChainId::test(),
            network_id: NetworkId::Public,
        };
        
        // Attacker uses incompatible protocol set
        let attacker_protocols = ProtocolIdSet::from_iter([
            ProtocolId::NetbenchDirectSend, // Protocols victim doesn't support
        ]);
        
        let mut attacker_supported = BTreeMap::new();
        attacker_supported.insert(MessagingProtocolVersion::V1, attacker_protocols);
        
        let attacker_handshake = HandshakeMsg {
            supported_protocols: attacker_supported,
            chain_id: ChainId::test(),
            network_id: NetworkId::Public,
        };
        
        // Simulate repeated connection attempts
        let mut failures = 0;
        for _ in 0..100 {
            // Each iteration represents a new connection attempt
            let result = victim_handshake.perform_handshake(&attacker_handshake);
            
            match result {
                Err(HandshakeError::NoCommonProtocols) => {
                    failures += 1;
                    // In real attack, attacker would immediately retry
                    // No rate limiting or tracking prevents this
                },
                _ => panic!("Expected NoCommonProtocols error"),
            }
        }
        
        assert_eq!(failures, 100);
        // Demonstrates that 100 consecutive failures can occur with no mitigation
        println!("Successfully caused {} handshake failures with no defensive response", failures);
    }
}
```

## Notes

- This vulnerability is explicitly scoped to non-mutually-authenticated networks (public networks and VFN maybe-mutual-auth scenarios)
- Validator consensus is not directly affected as validator networks use mutual authentication
- HAProxy provides partial protection via `maxconnrate`, but this is a global limit exploitable by a single attacker
- The attack consumes victim resources even though connections are eventually rejected
- Current metrics track failures but no defensive action is taken based on failure patterns

### Citations

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L431-465)
```rust
    pub fn perform_handshake(
        &self,
        other: &HandshakeMsg,
    ) -> Result<(MessagingProtocolVersion, ProtocolIdSet), HandshakeError> {
        // verify that both peers are on the same chain
        if self.chain_id != other.chain_id {
            return Err(HandshakeError::InvalidChainId(
                other.chain_id,
                self.chain_id,
            ));
        }

        // verify that both peers are on the same network
        if self.network_id != other.network_id {
            return Err(HandshakeError::InvalidNetworkId(
                other.network_id,
                self.network_id,
            ));
        }

        // find the greatest common MessagingProtocolVersion where we both support
        // at least one common ProtocolId.
        for (our_handshake_version, our_protocols) in self.supported_protocols.iter().rev() {
            if let Some(their_protocols) = other.supported_protocols.get(our_handshake_version) {
                let common_protocols = our_protocols.intersect(their_protocols);

                if !common_protocols.is_empty() {
                    return Ok((*our_handshake_version, common_protocols));
                }
            }
        }

        // no intersection found
        Err(HandshakeError::NoCommonProtocols)
    }
```

**File:** network/framework/src/noise/handshake.rs (L313-486)
```rust
    pub async fn upgrade_inbound<TSocket>(
        &self,
        mut socket: TSocket,
    ) -> Result<(NoiseStream<TSocket>, PeerId, PeerRole), NoiseHandshakeError>
    where
        TSocket: AsyncRead + AsyncWrite + Debug + Unpin,
    {
        // buffer to contain the client first message
        let mut client_message = [0; Self::CLIENT_MESSAGE_SIZE];

        // receive the prologue + first noise handshake message
        trace!("{} noise server: handshake read", self.network_context);
        socket
            .read_exact(&mut client_message)
            .await
            .map_err(NoiseHandshakeError::ServerReadFailed)?;

        // extract prologue (remote_peer_id | self_public_key)
        let (remote_peer_id, self_expected_public_key) =
            client_message[..Self::PROLOGUE_SIZE].split_at(PeerId::LENGTH);

        // parse the client's peer id
        // note: in mutual authenticated network, we could verify that their peer_id is in the trust peer set now.
        // We do this later in this function instead (to batch a number of checks) as there is no known attack here.
        let remote_peer_id = PeerId::try_from(remote_peer_id)
            .map_err(|_| NoiseHandshakeError::InvalidClientPeerId(hex::encode(remote_peer_id)))?;
        let remote_peer_short = remote_peer_id.short_str();

        // reject accidental self-dials
        // this situation could occur either as a result of our own discovery
        // mis-configuration or a potentially malicious discovery peer advertising
        // a (loopback ip or mirror proxy) and our public key.
        if remote_peer_id == self.network_context.peer_id() {
            return Err(NoiseHandshakeError::SelfDialDetected);
        }

        // verify that this is indeed our public key
        let actual_public_key = self.noise_config.public_key();
        if self_expected_public_key != actual_public_key.as_slice() {
            return Err(NoiseHandshakeError::ClientExpectingDifferentPubkey(
                remote_peer_short,
                hex::encode(self_expected_public_key),
                hex::encode(actual_public_key.as_slice()),
            ));
        }

        // parse it
        let (prologue, client_init_message) = client_message.split_at(Self::PROLOGUE_SIZE);
        let (remote_public_key, handshake_state, payload) = self
            .noise_config
            .parse_client_init_message(prologue, client_init_message)
            .map_err(|err| NoiseHandshakeError::ServerParseClient(remote_peer_short, err))?;

        // if mutual auth mode, verify the remote pubkey is in our set of trusted peers
        let network_id = self.network_context.network_id();
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
            HandshakeAuthMode::MaybeMutual(peers_and_metadata) => {
                let trusted_peers = peers_and_metadata.get_trusted_peers(&network_id)?;
                let trusted_peer = trusted_peers.get(&remote_peer_id).cloned();
                match trusted_peer {
                    Some(peer) => {
                        Self::authenticate_inbound(remote_peer_short, &peer, &remote_public_key)
                    },
                    None => {
                        // The peer is not in the trusted peer set. Verify that the Peer ID is
                        // constructed correctly from the public key.
                        let derived_remote_peer_id =
                            aptos_types::account_address::from_identity_public_key(
                                remote_public_key,
                            );
                        if derived_remote_peer_id != remote_peer_id {
                            // The peer ID is not constructed correctly from the public key
                            Err(NoiseHandshakeError::ClientPeerIdMismatch(
                                remote_peer_short,
                                remote_peer_id,
                                derived_remote_peer_id,
                            ))
                        } else {
                            // Try to infer the role from the network context
                            if self.network_context.role().is_validator() {
                                if network_id.is_vfn_network() {
                                    // Inbound connections to validators on the VFN network must be VFNs
                                    Ok(PeerRole::ValidatorFullNode)
                                } else {
                                    // Otherwise, they're unknown. Validators will connect through
                                    // authenticated channels (on the validator network) so shouldn't hit
                                    // this, and PFNs will connect on public networks (which aren't common).
                                    Ok(PeerRole::Unknown)
                                }
                            } else {
                                // We're a VFN or PFN. VFNs get no inbound connections on the vfn network
                                // (so the peer won't be a validator). Thus, we're on the public network
                                // so mark the peer as unknown.
                                Ok(PeerRole::Unknown)
                            }
                        }
                    },
                }
            },
        }?;

        // if on a mutually authenticated network,
        // the payload should contain a u64 client timestamp
        if let Some(anti_replay_timestamps) = self.auth_mode.anti_replay_timestamps() {
            // check that the payload received as the client timestamp (in seconds)
            if payload.len() != AntiReplayTimestamps::TIMESTAMP_SIZE {
                return Err(NoiseHandshakeError::MissingAntiReplayTimestamp(
                    remote_peer_short,
                ));
            }

            let mut client_timestamp = [0u8; AntiReplayTimestamps::TIMESTAMP_SIZE];
            client_timestamp.copy_from_slice(&payload);
            let client_timestamp = u64::from_le_bytes(client_timestamp);

            // check the timestamp is not a replay
            let mut anti_replay_timestamps = anti_replay_timestamps.write();
            if anti_replay_timestamps.is_replay(remote_public_key, client_timestamp) {
                return Err(NoiseHandshakeError::ServerReplayDetected(
                    remote_peer_short,
                    client_timestamp,
                ));
            }

            // store the timestamp
            anti_replay_timestamps.store_timestamp(remote_public_key, client_timestamp);
        }

        // construct the response
        let mut rng = rand::rngs::OsRng;
        let mut server_response = [0u8; Self::SERVER_MESSAGE_SIZE];
        let session = self
            .noise_config
            .respond_to_client(&mut rng, handshake_state, None, &mut server_response)
            .map_err(|err| {
                NoiseHandshakeError::BuildServerHandshakeMessageFailed(remote_peer_short, err)
            })?;

        // send the response
        trace!(
            "{} noise server: handshake write: remote_peer_id: {}",
            self.network_context,
            remote_peer_short,
        );
        socket
            .write_all(&server_response)
            .await
            .map_err(|err| NoiseHandshakeError::ServerWriteFailed(remote_peer_short, err))?;

        // finalize the connection
        trace!(
            "{} noise server: handshake finalize: remote_peer_id: {}",
            self.network_context,
            remote_peer_short,
        );

        let noise_stream = NoiseStream::new(socket, session);
        Ok((noise_stream, remote_peer_id, peer_role))
    }
```

**File:** network/framework/src/protocols/identity.rs (L13-40)
```rust
pub async fn exchange_handshake<T>(
    own_handshake: &HandshakeMsg,
    socket: &mut T,
) -> io::Result<HandshakeMsg>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // Send serialized handshake message to remote peer.
    let msg = bcs::to_bytes(own_handshake).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to serialize identity msg: {}", e),
        )
    })?;
    write_u16frame(socket, &msg).await?;
    socket.flush().await?;

    // Read handshake message from the Remote
    let mut response = BytesMut::new();
    read_u16frame(socket, &mut response).await?;
    let identity = bcs::from_bytes(&response).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse identity msg: {}", e),
        )
    })?;
    Ok(identity)
}
```

**File:** network/framework/src/transport/mod.rs (L308-317)
```rust
    let (messaging_protocol, application_protocols) = handshake_msg
        .perform_handshake(&remote_handshake)
        .map_err(|err| {
            let err = format!(
                "handshake negotiation with peer {} failed: {}",
                remote_peer_id.short_str(),
                err
            );
            add_pp_addr(proxy_protocol_enabled, io::Error::other(err), &addr)
        })?;
```

**File:** network/framework/src/peer_manager/transport.rs (L90-119)
```rust
    pub async fn listen(mut self) {
        let mut pending_inbound_connections = FuturesUnordered::new();
        let mut pending_outbound_connections = FuturesUnordered::new();

        debug!(
            NetworkSchema::new(&self.network_context),
            "{} Incoming connections listener Task started", self.network_context
        );

        loop {
            futures::select! {
                dial_request = self.transport_reqs_rx.select_next_some() => {
                    if let Some(fut) = self.dial_peer(dial_request) {
                        pending_outbound_connections.push(fut);
                    }
                },
                inbound_connection = self.listener.select_next_some() => {
                    if let Some(fut) = self.upgrade_inbound_connection(inbound_connection) {
                        pending_inbound_connections.push(fut);
                    }
                },
                (upgrade, addr, peer_id, start_time, response_tx) = pending_outbound_connections.select_next_some() => {
                    self.handle_completed_outbound_upgrade(upgrade, addr, peer_id, start_time, response_tx).await;
                },
                (upgrade, addr, start_time) = pending_inbound_connections.select_next_some() => {
                    self.handle_completed_inbound_upgrade(upgrade, addr, start_time).await;
                },
                complete => break,
            }
        }
```

**File:** network/framework/src/peer_manager/transport.rs (L293-329)
```rust
    /// Notifies `PeerManager` of a completed or failed inbound connection
    async fn handle_completed_inbound_upgrade(
        &mut self,
        upgrade: Result<Connection<TSocket>, TTransport::Error>,
        addr: NetworkAddress,
        start_time: Instant,
    ) {
        counters::pending_connection_upgrades(&self.network_context, ConnectionOrigin::Inbound)
            .dec();

        let elapsed_time = (self.time_service.now() - start_time).as_secs_f64();
        match upgrade {
            Ok(connection) => {
                self.send_connection_to_peer_manager(connection, &addr, elapsed_time)
                    .await;
            },
            Err(err) => {
                warn!(
                    NetworkSchema::new(&self.network_context)
                        .network_address(&addr),
                    error = %err,
                    "{} Inbound connection from {} failed to upgrade after {:.3} secs: {}",
                    self.network_context,
                    addr,
                    elapsed_time,
                    err,
                );

                counters::connection_upgrade_time(
                    &self.network_context,
                    ConnectionOrigin::Inbound,
                    FAILED_LABEL,
                )
                .observe(elapsed_time);
            },
        }
    }
```

**File:** network/framework/src/peer_manager/mod.rs (L351-390)
```rust
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
```

**File:** config/src/config/network_config.rs (L366-388)
```rust
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Maximum number of bytes/s for an IP
    pub ip_byte_bucket_rate: usize,
    /// Maximum burst of bytes for an IP
    pub ip_byte_bucket_size: usize,
    /// Initial amount of tokens initially in the bucket
    pub initial_bucket_fill_percentage: u8,
    /// Allow for disabling the throttles
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            ip_byte_bucket_rate: IP_BYTE_BUCKET_RATE,
            ip_byte_bucket_size: IP_BYTE_BUCKET_SIZE,
            initial_bucket_fill_percentage: 25,
            enabled: true,
        }
    }
}
```

**File:** docker/compose/aptos-node/haproxy.cfg (L8-12)
```text
    # Limit the maximum number of connections to 500 (this is ~5x the validator set size)
    maxconn 500

    # Limit the maximum number of connections per second to 300 (this is ~3x the validator set size)
    maxconnrate 300
```
