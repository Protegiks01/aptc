Audit Report

## Title
Transport Layer Protocol Upgrade Timing Side-Channel Reveals Authentication State and Peer Set Membership

## Summary
The AptosNet `TransportExt::and_then()` upgrade pathway exposes timing differences during Noise protocol authentication and handshake, allowing remote attackers to infer authentication mode, peer trust set membership, and replay protection state, resulting in a low-severity but concrete information leak.

## Finding Description
When using async upgrades with the `and_then()` combinator in the `aptos-core/network/netcore/src/transport/mod.rs` and `and_then.rs`, all protocol upgrade logic—specifically Aptos' Noise IK handshake—executes after the base transport is established. Examination of the handshake code path for inbound connections reveals multiple observable timing differences on authentication failures versus successful or replayed connections:

- Unauthenticated peers (not in trusted set) are rejected immediately, resulting in a short-lived TCP connection.
- Replay-attack attempts or repeated timestamps in mutual-auth scenarios cause an anti-replay check (with a locking and hash lookup), leading to medium latency rejection.
- Successful or fully authenticated peers experience the slowest path, including full cryptography and a returned Noise response.

An attacker can use round-trip time (RTT) measurements for multiple, tailored handshake attempts to infer:
- If a server is using Mutual or MaybeMutual authentication modes,
- If a particular peer ID is in the trusted set,
- How replay protection is functioning.

All of these checks are handled before a full Noise handshake completes, and the variance in rejection timing is observable on the network, leaking configuration and partial peer set state.

## Impact Explanation
This is a **Low** severity issue (per bug bounty criteria) as it enables a remote adversary to fingerprint authentication mode, peer set membership, and anti-replay state. No direct funds, consensus, or availability are impacted. The principal risk is in information leakage, which could help an adversary identify high-value targets or plan more focused attacks, especially if combined with other reconnaissance.

## Likelihood Explanation
The attack can be executed by any remote network peer without authentication and requires only RTT-style network measurements—no privileged access necessary. Noise in the network may add measurement ambiguity, but repeated probes can statistically distinguish short-circuit code paths. The timing difference between code paths (auth checks, anti-replay, success) is sufficient to be observable under typical conditions.

## Recommendation
To mitigate, refactor the handshake flow to make rejection latency uniform, regardless of the error cause—e.g. by always performing a constant-time chain of checks (using sleep/delays to artificially equalize response timing). Weigh the complexity/cost of such countermeasures against practical threat scenarios; document the limitation if the fix is not justified.

## Proof of Concept

1. Run an Aptos node with a known set of trusted peers on a local/private testnet.
2. Connect using raw TCP, initiating multiple handshake attempts with varying peer IDs (some trusted, some untrusted) and replayed timestamps.
3. Measure time to connection close for the following cases:
   - Known-trusted peer ID and valid timestamp.
   - Unknown peer ID (not in trusted set).
   - Known-trusted peer ID with replayed timestamp.
4. Observe consistent, statistically significant differences in rejection/timing between these three scenarios, proving the information leak.

---

Citations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

Notes:
- The earliest (shortest path) rejections occur before any cryptographic operations or I/O.
- The code's explicit comments and variable rejection flows support the analysis of a measurable side-channel.
- Impact is strictly information disclosure, not consensus or execution path violation.
- Changing the rejection code paths to obfuscate timing would introduce additional complexity and possible DoS risk (unacceptable CPU locks on the handshake path). This is a known and generally accepted tradeoff for protocol handshakes that authenticate unauthenticated peers.

### Citations

**File:** network/framework/src/noise/handshake.rs (L183-263)
```rust
    pub async fn upgrade_outbound<TSocket, F>(
        &self,
        mut socket: TSocket,
        remote_peer_id: PeerId,
        remote_public_key: x25519::PublicKey,
        time_provider: F,
    ) -> Result<(NoiseStream<TSocket>, PeerRole), NoiseHandshakeError>
    where
        TSocket: AsyncRead + AsyncWrite + Debug + Unpin,
        F: Fn() -> [u8; AntiReplayTimestamps::TIMESTAMP_SIZE],
    {
        // buffer to hold prologue + first noise handshake message
        let mut client_message = [0; Self::CLIENT_MESSAGE_SIZE];

        // craft prologue = self_peer_id | expected_public_key
        client_message[..PeerId::LENGTH].copy_from_slice(self.network_context.peer_id().as_ref());
        client_message[PeerId::LENGTH..Self::PROLOGUE_SIZE]
            .copy_from_slice(remote_public_key.as_slice());

        let (prologue_msg, client_noise_msg) = client_message.split_at_mut(Self::PROLOGUE_SIZE);

        // craft 8-byte payload as current timestamp (in milliseconds)
        let payload = time_provider();

        // craft first handshake message  (-> e, es, s, ss)
        let mut rng = rand::rngs::OsRng;
        let initiator_state = self
            .noise_config
            .initiate_connection(
                &mut rng,
                prologue_msg,
                remote_public_key,
                Some(&payload),
                client_noise_msg,
            )
            .map_err(NoiseHandshakeError::BuildClientHandshakeMessageFailed)?;

        // send the first handshake message
        trace!(
            "{} noise client: handshake write: remote_public_key: {}",
            self.network_context,
            remote_public_key,
        );
        socket
            .write_all(&client_message)
            .await
            .map_err(NoiseHandshakeError::ClientWriteFailed)?;
        socket
            .flush()
            .await
            .map_err(NoiseHandshakeError::ClientFlushFailed)?;

        // receive the server's response (<- e, ee, se)
        trace!(
            "{} noise client: handshake read: remote_public_key: {}",
            self.network_context,
            remote_public_key,
        );
        let mut server_response = [0u8; Self::SERVER_MESSAGE_SIZE];
        socket
            .read_exact(&mut server_response)
            .await
            .map_err(NoiseHandshakeError::ClientReadFailed)?;

        // parse the server's response
        trace!(
            "{} noise client: handshake finalize: remote_public_key: {}",
            self.network_context,
            remote_public_key,
        );
        let (_, session) = self
            .noise_config
            .finalize_connection(initiator_state, &server_response)
            .map_err(NoiseHandshakeError::ClientFinalizeFailed)?;

        // finalize the connection
        let noise_stream = NoiseStream::new(socket, session);
        let peer_role = self.extract_peer_role_from_trusted_peers(remote_peer_id);

        Ok((noise_stream, peer_role))
    }
```

**File:** network/framework/src/noise/handshake.rs (L314-486)
```rust
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

**File:** network/netcore/src/transport/and_then.rs (L157-178)
```rust
    fn poll(self: Pin<&mut Self>, context: &mut Context) -> Poll<Self::Output> {
        let mut this = self.project();
        loop {
            let (output, (f, addr, origin)) = match this.chain.as_mut().project() {
                // Step 1: Drive Fut1 to completion
                AndThenChainProj::First(fut1, data) => match fut1.poll(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(output)) => (output, data.take().expect("must be initialized")),
                },
                // Step 4: Drive Fut2 to completion
                AndThenChainProj::Second(fut2) => return fut2.poll(context),
                AndThenChainProj::Empty => unreachable!(),
            };

            // Step 2: Ensure that Fut1 is dropped
            this.chain.set(AndThenChain::Empty);
            // Step 3: Run F on the output of Fut1 to create Fut2
            let fut2 = f(output, addr, origin);
            this.chain.set(AndThenChain::Second(fut2));
        }
    }
```

**File:** network/framework/src/transport/mod.rs (L249-332)
```rust
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

**File:** network/framework/src/transport/mod.rs (L334-407)
```rust
/// Upgrade an outbound connection. This means we run a Noise IK handshake for
/// authentication and then negotiate common supported protocols.
pub async fn upgrade_outbound<T: TSocket>(
    ctxt: Arc<UpgradeContext>,
    fut_socket: impl Future<Output = io::Result<T>>,
    addr: NetworkAddress,
    remote_peer_id: PeerId,
    remote_pubkey: x25519::PublicKey,
) -> io::Result<Connection<NoiseStream<T>>> {
    let origin = ConnectionOrigin::Outbound;
    let socket = fut_socket.await?;

    // noise handshake
    let (mut socket, peer_role) = ctxt
        .noise
        .upgrade_outbound(
            socket,
            remote_peer_id,
            remote_pubkey,
            AntiReplayTimestamps::now,
        )
        .await
        .map_err(|err| {
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
            io::Error::other(err)
        })?;

    // sanity check: Noise IK should always guarantee this is true
    debug_assert_eq!(remote_pubkey, socket.get_remote_static());

    // exchange HandshakeMsg
    let handshake_msg = HandshakeMsg {
        supported_protocols: ctxt.supported_protocols.clone(),
        chain_id: ctxt.chain_id,
        network_id: ctxt.network_id,
    };
    let remote_handshake = exchange_handshake(&handshake_msg, &mut socket).await?;

    // try to negotiate common aptosnet version and supported application protocols
    let (messaging_protocol, application_protocols) = handshake_msg
        .perform_handshake(&remote_handshake)
        .map_err(|e| {
            let e = format!(
                "handshake negotiation with peer {} failed: {}",
                remote_peer_id, e
            );
            io::Error::other(e)
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
