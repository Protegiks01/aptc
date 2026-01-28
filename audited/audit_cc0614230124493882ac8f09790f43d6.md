> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** network/framework/src/peer/mod.rs (L447-541)
```rust
    fn handle_inbound_network_message(
        &mut self,
        message: NetworkMessage,
    ) -> Result<(), PeerManagerError> {
        match &message {
            NetworkMessage::DirectSendMsg(direct) => {
                let data_len = direct.raw_msg.len();
                network_application_inbound_traffic(
                    self.network_context,
                    direct.protocol_id,
                    data_len as u64,
                );
                match self.upstream_handlers.get(&direct.protocol_id) {
                    None => {
                        counters::direct_send_messages(&self.network_context, UNKNOWN_LABEL).inc();
                        counters::direct_send_bytes(&self.network_context, UNKNOWN_LABEL)
                            .inc_by(data_len as u64);
                    },
                    Some(handler) => {
                        let key = (self.connection_metadata.remote_peer_id, direct.protocol_id);
                        let sender = self.connection_metadata.remote_peer_id;
                        let network_id = self.network_context.network_id();
                        let sender = PeerNetworkId::new(network_id, sender);
                        match handler.push(key, ReceivedMessage::new(message, sender)) {
                            Err(_err) => {
                                // NOTE: aptos_channel never returns other than Ok(()), but we might switch to tokio::sync::mpsc and then this would work
                                counters::direct_send_messages(
                                    &self.network_context,
                                    DECLINED_LABEL,
                                )
                                .inc();
                                counters::direct_send_bytes(&self.network_context, DECLINED_LABEL)
                                    .inc_by(data_len as u64);
                            },
                            Ok(_) => {
                                counters::direct_send_messages(
                                    &self.network_context,
                                    RECEIVED_LABEL,
                                )
                                .inc();
                                counters::direct_send_bytes(&self.network_context, RECEIVED_LABEL)
                                    .inc_by(data_len as u64);
                            },
                        }
                    },
                }
            },
            NetworkMessage::Error(error_msg) => {
                warn!(
                    NetworkSchema::new(&self.network_context)
                        .connection_metadata(&self.connection_metadata),
                    error_msg = ?error_msg,
                    "{} Peer {} sent an error message: {:?}",
                    self.network_context,
                    self.remote_peer_id().short_str(),
                    error_msg,
                );
            },
            NetworkMessage::RpcRequest(request) => {
                match self.upstream_handlers.get(&request.protocol_id) {
                    None => {
                        counters::direct_send_messages(&self.network_context, UNKNOWN_LABEL).inc();
                        counters::direct_send_bytes(&self.network_context, UNKNOWN_LABEL)
                            .inc_by(request.raw_request.len() as u64);
                    },
                    Some(handler) => {
                        let sender = self.connection_metadata.remote_peer_id;
                        let network_id = self.network_context.network_id();
                        let sender = PeerNetworkId::new(network_id, sender);
                        if let Err(err) = self
                            .inbound_rpcs
                            .handle_inbound_request(handler, ReceivedMessage::new(message, sender))
                        {
                            warn!(
                                NetworkSchema::new(&self.network_context)
                                    .connection_metadata(&self.connection_metadata),
                                error = %err,
                                "{} Error handling inbound rpc request: {}",
                                self.network_context,
                                err
                            );
                        }
                    },
                }
            },
            NetworkMessage::RpcResponse(_) => {
                // non-reference cast identical to this match case
                let NetworkMessage::RpcResponse(response) = message else {
                    unreachable!("NetworkMessage type changed between match and let")
                };
                self.outbound_rpcs.handle_inbound_response(response)
            },
        };
        Ok(())
    }
```

**File:** network/framework/src/transport/mod.rs (L98-161)
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

impl ConnectionMetadata {
    pub fn new(
        remote_peer_id: PeerId,
        connection_id: ConnectionId,
        addr: NetworkAddress,
        origin: ConnectionOrigin,
        messaging_protocol: MessagingProtocolVersion,
        application_protocols: ProtocolIdSet,
        role: PeerRole,
    ) -> ConnectionMetadata {
        ConnectionMetadata {
            remote_peer_id,
            connection_id,
            addr,
            origin,
            messaging_protocol,
            application_protocols,
            role,
        }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn mock(remote_peer_id: PeerId) -> ConnectionMetadata {
        Self::mock_with_role_and_origin(
            remote_peer_id,
            PeerRole::Unknown,
            ConnectionOrigin::Inbound,
        )
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn mock_with_role_and_origin(
        remote_peer_id: PeerId,
        role: PeerRole,
        origin: ConnectionOrigin,
    ) -> ConnectionMetadata {
        ConnectionMetadata {
            remote_peer_id,
            role,
            origin,
            connection_id: CONNECTION_ID_GENERATOR.next(),
            addr: NetworkAddress::mock(),
            messaging_protocol: MessagingProtocolVersion::V1,
            application_protocols: ProtocolIdSet::empty(),
        }
    }

    /// Returns true iff the connection origin is outbound
    pub fn is_outbound_connection(&self) -> bool {
        self.origin == ConnectionOrigin::Outbound
    }
}
```

**File:** network/framework/src/transport/mod.rs (L244-332)
```rust
/// Upgrade an inbound connection. This means we run a Noise IK handshake for
/// authentication and then negotiate common supported protocols. If
/// `ctxt.noise.auth_mode` is `HandshakeAuthMode::Mutual( anti_replay_timestamps , trusted_peers )`,
/// then we will only allow connections from peers with a pubkey in the `trusted_peers`
/// set. Otherwise, we will allow inbound connections from any pubkey.
async fn upgrade_inbound<T: TSocket>(
    ctxt: Arc<UpgradeContext>,
    fut_socket: impl Future<Output = io::Result<T>>,
    addr: NetworkAddress,
    proxy_protocol_enabled: bool,
) -> io::Result<Connection<NoiseStream<T>>> {
    let origin = ConnectionOrigin::Inbound;
    let mut socket = fut_socket.await?;

    // If we have proxy protocol enabled, process the event, otherwise skip it
    // TODO: This would make more sense to build this in at instantiation so we don't need to put the if statement here
    let addr = if proxy_protocol_enabled {
        proxy_protocol::read_header(&addr, &mut socket)
            .await
            .map_err(|err| {
                debug!(
                    network_address = addr,
                    error = %err,
                    "ProxyProtocol: Failed to read header: {}",
                    err
                );
                err
            })?
    } else {
        addr
    };

    // try authenticating via noise handshake
    let (mut socket, remote_peer_id, peer_role) =
        ctxt.noise.upgrade_inbound(socket).await.map_err(|err| {
            if err.should_security_log() {
                sample!(
                    SampleRate::Duration(Duration::from_secs(15)),
                    warn!(
                        SecurityEvent::NoiseHandshake,
                        NetworkSchema::new(&ctxt.noise.network_context)
                            .network_address(&addr)
                            .connection_origin(&origin),
                        error = %err,
                    )
                );
            }
            let err = io::Error::other(err);
            add_pp_addr(proxy_protocol_enabled, err, &addr)
        })?;
    let remote_pubkey = socket.get_remote_static();
    let addr = addr.append_prod_protos(remote_pubkey, HANDSHAKE_VERSION);

    // exchange HandshakeMsg
    let handshake_msg = HandshakeMsg {
        supported_protocols: ctxt.supported_protocols.clone(),
        chain_id: ctxt.chain_id,
        network_id: ctxt.network_id,
    };
    let remote_handshake = exchange_handshake(&handshake_msg, &mut socket)
        .await
        .map_err(|err| add_pp_addr(proxy_protocol_enabled, err, &addr))?;

    // try to negotiate common aptosnet version and supported application protocols
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

    // return successful connection
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
}
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L428-466)
```rust
    /// This function:
    /// 1. verifies that both HandshakeMsg are compatible and
    /// 2. finds out the intersection of protocols that is supported
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
}
```
