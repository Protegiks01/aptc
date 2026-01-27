# Audit Report

## Title
Unauthenticated Inspection Service Endpoints Enable Targeted Resource Exhaustion Attacks on Validators

## Summary
The inspection service exposes validator network topology and connection metadata through unauthenticated HTTP endpoints that are enabled by default. This allows attackers to enumerate all validators, obtain their network addresses and authentication keys, and perform targeted handshake resource exhaustion attacks that can slow down validator operations.

## Finding Description

The Aptos inspection service provides several endpoints for monitoring node information, including `/identity_information` and `/peer_information`. These endpoints are:

1. **Enabled by default** with `expose_identity_information: true` and `expose_peer_information: true` [1](#0-0) 

2. **Bound to all network interfaces** (`0.0.0.0:9101`) by default [2](#0-1) 

3. **Lack any authentication mechanism** - requests are served without credential checks [3](#0-2) 

4. **Not blocked by sanitizers for mainnet validators** - unlike `expose_configuration`, there is no restriction preventing mainnet validators from exposing these endpoints [4](#0-3) 

The `/peer_information` endpoint exposes sensitive validator network topology including peer IDs, network addresses (IP/DNS + ports), x25519 public keys, connection states, and the complete trusted peer set with their roles: [5](#0-4) 

The `Peer` struct contains addresses, authentication keys, and roles: [6](#0-5) 

**Attack Flow:**

1. Attacker queries `http://validator-ip:9101/peer_information` (no authentication required)
2. Obtains complete validator network map including addresses and authentication keys
3. Initiates connection attempts to specific validators on their network ports
4. Each connection triggers a full Noise IK handshake including expensive Diffie-Hellman key exchanges
5. The handshake computation occurs **before** authentication checks: [7](#0-6) 

6. Connection limit enforcement only happens **after** the handshake completes: [8](#0-7) 

7. The transport upgrade (including handshake) executes before connection metadata is available for limit checks: [9](#0-8) 

This creates a resource exhaustion vulnerability where attackers can force validators to perform expensive cryptographic operations before connections are rejected.

## Impact Explanation

This vulnerability qualifies as **HIGH Severity** under Aptos bug bounty criteria for "Validator node slowdowns":

1. **Information Disclosure**: Exposes complete validator network topology beyond on-chain data, including connection states, internal metadata, and real-time peer information
2. **Targeted Attacks**: Enables adversaries to identify and specifically target critical validators (e.g., those with highest stake, specific operators, or consensus leaders)
3. **Resource Exhaustion**: Forces validators to perform Diffie-Hellman computations before authentication checks, enabling CPU exhaustion attacks
4. **Consensus Impact**: Targeting 1/3+ of validators simultaneously could cause liveness failures in AptosBFT consensus
5. **Default Misconfiguration**: Endpoints exposed by default without operator opt-in or awareness

While HAproxy provides connection rate limiting (300 conn/sec), an attacker using distributed sources can still impose significant computational load through handshake flooding.

## Likelihood Explanation

**Likelihood: HIGH**

- Endpoints are enabled by default on all Aptos validator nodes
- No authentication or authorization required
- Trivial to exploit with standard HTTP and TCP clients  
- Information gathering requires single HTTP GET request
- If HAproxy metrics port is enabled (`service.validator.enableMetricsPort: true`), endpoints become publicly accessible through load balancer: [10](#0-9) 

## Recommendation

Implement multiple defense layers:

1. **Disable by default for mainnet validators**:
```rust
// In config/src/config/inspection_service_config.rs
impl ConfigSanitizer for InspectionServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let inspection_service_config = &node_config.inspection_service;

        // Verify that mainnet validators do not expose configuration
        if let Some(chain_id) = chain_id {
            if node_type.is_validator() && chain_id.is_mainnet() {
                if inspection_service_config.expose_configuration {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Mainnet validators should not expose the node configuration!".to_string(),
                    ));
                }
                // ADD THIS CHECK
                if inspection_service_config.expose_peer_information {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Mainnet validators should not expose peer information!".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}
```

2. **Add authentication to inspection service endpoints** using JWT tokens or API keys

3. **Move handshake connection limits earlier** - reject connections before DH computation for unknown peers in mutual auth mode

4. **Bind to localhost by default** - change default address from `0.0.0.0` to `127.0.0.1`

## Proof of Concept

```bash
#!/bin/bash
# POC: Enumerate validator network and perform handshake flooding

# Step 1: Query inspection service endpoint
echo "=== Enumerating validator network ==="
curl -s http://VALIDATOR_IP:9101/peer_information | tee validator_topology.txt

# Step 2: Extract validator addresses and parse
echo "=== Extracted validator addresses ==="
grep -E "validator_network_addresses|Peer: Validator" validator_topology.txt

# Step 3: Handshake flooding attack (requires custom client)
# For each validator address, repeatedly initiate connections
# This forces DH computations before authentication fails

echo "=== Performing handshake flooding (example for one validator) ==="
for i in {1..1000}; do
  # Each connection attempt will:
  # 1. Complete TCP handshake
  # 2. Start Noise IK protocol  
  # 3. Perform DH key exchange on validator side
  # 4. Get rejected during authentication (after DH)
  timeout 1 nc VALIDATOR_IP 6180 < /dev/null &
done
wait

echo "=== Attack complete. Monitor validator CPU usage and latency ==="
```

A full Rust implementation would create TCP connections and initiate Noise handshakes with invalid credentials, forcing validators to perform expensive DH operations before rejecting the connections.

## Notes

While validator network addresses are technically available on-chain through the `ValidatorSet` configuration, the inspection service makes enumeration trivial and exposes additional real-time operational metadata not available on-chain (connection states, internal metrics, trusted peer configurations). The combination of unauthenticated access, default-enabled configuration, and handshake-before-validation creates a concrete attack vector for targeted validator disruption.

The vulnerability is particularly concerning because it enables precision targeting of specific validators rather than indiscriminate network flooding, and the computational cost of Diffie-Hellman operations provides significant amplification for resource exhaustion attacks.

### Citations

**File:** config/src/config/inspection_service_config.rs (L26-37)
```rust
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "0.0.0.0".to_string(),
            port: 9101,
            expose_configuration: false,
            expose_identity_information: true,
            expose_peer_information: true,
            expose_system_information: true,
        }
    }
}
```

**File:** config/src/config/inspection_service_config.rs (L45-68)
```rust
impl ConfigSanitizer for InspectionServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let inspection_service_config = &node_config.inspection_service;

        // Verify that mainnet validators do not expose the configuration
        if let Some(chain_id) = chain_id {
            if node_type.is_validator()
                && chain_id.is_mainnet()
                && inspection_service_config.expose_configuration
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Mainnet validators should not expose the node configuration!".to_string(),
                ));
            }
        }

        Ok(())
    }
```

**File:** crates/aptos-inspection-service/src/server/mod.rs (L104-109)
```rust
async fn serve_requests(
    req: Request<Body>,
    node_config: NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> Result<Response<Body>, hyper::Error> {
```

**File:** crates/aptos-inspection-service/src/server/peer_information.rs (L273-300)
```rust
/// Displays the entire set of trusted peers
fn display_trusted_peers(
    peer_information_output: &mut Vec<String>,
    registered_networks: Vec<NetworkId>,
    peers_and_metadata: &PeersAndMetadata,
) {
    peer_information_output.push("Trusted peers (validator set & seeds):".into());

    // Fetch and display the trusted peers for each network
    for network in registered_networks {
        peer_information_output.push(format!("\t- Network: {}", network));
        if let Ok(trusted_peers) = peers_and_metadata.get_trusted_peers(&network) {
            // Sort the peers before displaying them
            let mut sorted_trusted_peers = BTreeMap::new();
            for (peer_id, peer_info) in trusted_peers {
                sorted_trusted_peers.insert(peer_id, peer_info);
            }

            // Display the trusted peers
            for (peer_id, peer_info) in sorted_trusted_peers {
                peer_information_output.push(format!(
                    "\t\t- Peer: {:?}, peer information: {:?}",
                    peer_id, peer_info
                ));
            }
        }
    }
}
```

**File:** config/src/config/network_config.rs (L458-464)
```rust
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default)]
pub struct Peer {
    pub addresses: Vec<NetworkAddress>,
    pub keys: HashSet<x25519::PublicKey>,
    pub role: PeerRole,
}
```

**File:** network/framework/src/noise/handshake.rs (L359-383)
```rust
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

**File:** network/framework/src/transport/mod.rs (L244-293)
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
```

**File:** terraform/helm/aptos-node/files/haproxy.cfg (L93-108)
```text
frontend validator-metrics
    mode http
    option httplog
    bind :9102
    default_backend validator-metrics

    # Deny requests from blocked IPs
    tcp-request connection reject if { src -n -f /usr/local/etc/haproxy/blocked.ips }

    ## Add the forwarded header
    http-request add-header Forwarded "for=%ci"

## Specify the validator metrics backend
backend validator-metrics
    mode http
    server {{ include "aptos-validator.fullname" $ }}-{{ $.Values.i }}-validator {{ include "aptos-validator.fullname" $ }}-{{ $.Values.i }}-validator:9101
```
