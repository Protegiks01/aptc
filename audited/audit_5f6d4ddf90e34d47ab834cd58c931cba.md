# Audit Report

## Title
Inspection Service Default Configuration Exposes Sensitive Validator Information to External Networks

## Summary
The inspection service binds to `0.0.0.0` by default and exposes sensitive validator identity and peer information without authentication. Mainnet validators using default configurations expose critical network topology data to unauthorized parties, enabling targeted attacks.

## Finding Description

The `InspectionServiceConfig` struct defines the inspection service configuration with a default address binding of `0.0.0.0`, which listens on all network interfaces. [1](#0-0) 

By default, three sensitive endpoints are enabled:
- `expose_identity_information: true` - Exposes validator peer IDs
- `expose_peer_information: true` - Exposes complete peer topology
- `expose_system_information: true` - Exposes system details

The configuration sanitizer only validates that mainnet validators don't expose the `/configuration` endpoint, but **does not** validate the other sensitive endpoints. [2](#0-1) 

The inspection service binds directly to this configured address without any additional security controls. [3](#0-2) 

The `/identity_information` endpoint exposes validator and fullnode network peer IDs when enabled. [4](#0-3) 

The `/peer_information` endpoint exposes comprehensive network topology including all connected peers, trusted validator set, connection metadata, and state sync details. [5](#0-4) 

These endpoints have **no authentication mechanism** beyond configuration flags - anyone who can reach the HTTP port can access them. The service relies purely on external firewall rules or network policies for protection.

**Attack Scenario:**
1. Validator operator deploys mainnet validator using default or base configuration
2. Example configurations don't explicitly set inspection service address, inheriting the `0.0.0.0` default [6](#0-5) 
3. Operator fails to configure proper firewall rules or assumes service is localhost-only
4. Attacker scans for open port 9101 on validator nodes
5. Attacker sends `GET http://validator-ip:9101/identity_information` and `GET http://validator-ip:9101/peer_information`
6. Attacker obtains validator peer IDs, trusted peer set, connection states, and network topology

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria for the following reasons:

1. **Information Disclosure:** Exposes critical validator identity and network topology information that should remain private
2. **Enables Targeted Attacks:** Leaked peer IDs enable attackers to:
   - Launch targeted DDoS attacks against specific validators
   - Craft eclipse attacks by understanding peer relationships  
   - Identify which nodes are validators versus full nodes
   - Map the validator network topology
3. **Affects Network Security:** Compromises the security of the entire validator network by revealing internal structure
4. **No Authentication:** Complete lack of access controls makes exploitation trivial

While this doesn't directly cause consensus violations or fund loss, it significantly weakens validator security posture and enables attacks that could lead to network disruption.

## Likelihood Explanation

**HIGH LIKELIHOOD** of exploitation:

1. **Default Configuration Vulnerable:** The default `0.0.0.0` binding makes this exploitable out-of-the-box
2. **Example Configs Don't Override:** Official example configurations don't set inspection service address, inheriting the vulnerable default
3. **Operator Assumptions:** Operators may assume the service is localhost-only based on the docker-compose example that binds to `127.0.0.1` on the host side, not realizing the container still listens on `0.0.0.0`
4. **No Warnings:** No code-level warnings or documentation about the security implications
5. **Simple Exploitation:** Requires only network access and HTTP GET requests - no special tools or knowledge
6. **Widespread Scanning:** Attackers routinely scan for exposed admin interfaces on common ports

## Recommendation

Implement defense-in-depth protections:

### 1. Add Sanitizer Check for Mainnet Validators

Modify the sanitizer to prevent mainnet validators from exposing sensitive endpoints:

```rust
impl ConfigSanitizer for InspectionServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let inspection_service_config = &node_config.inspection_service;

        // Verify that mainnet validators do not expose sensitive endpoints
        if let Some(chain_id) = chain_id {
            if node_type.is_validator() && chain_id.is_mainnet() {
                if inspection_service_config.expose_configuration {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name.clone(),
                        "Mainnet validators should not expose the node configuration!".to_string(),
                    ));
                }
                if inspection_service_config.expose_identity_information {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name.clone(),
                        "Mainnet validators should not expose identity information!".to_string(),
                    ));
                }
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

### 2. Change Default Address Binding

Change the default address to `127.0.0.1` for localhost-only access:

```rust
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "127.0.0.1".to_string(), // Changed from "0.0.0.0"
            port: 9101,
            expose_configuration: false,
            expose_identity_information: true,
            expose_peer_information: true,
            expose_system_information: true,
        }
    }
}
```

### 3. Add Authentication Layer

Implement token-based authentication for inspection endpoints (similar to telemetry service) or restrict access to localhost only in production deployments.

## Proof of Concept

**Step 1:** Create a test to demonstrate the vulnerability:

```rust
#[test]
fn test_mainnet_validator_exposed_endpoints() {
    use aptos_config::config::{InspectionServiceConfig, NodeConfig};
    use aptos_types::chain_id::ChainId;
    use crate::config::{node_config_loader::NodeType, ConfigSanitizer};

    // Create a mainnet validator config with default inspection service settings
    let node_config = NodeConfig {
        inspection_service: InspectionServiceConfig::default(),
        ..Default::default()
    };

    // This should FAIL but currently PASSES - demonstrating the vulnerability
    let result = InspectionServiceConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    );
    
    // Currently this passes, but it should fail for security
    assert!(result.is_ok()); // This demonstrates the bug exists
    
    // The inspection service is configured to expose sensitive data:
    assert_eq!(node_config.inspection_service.address, "0.0.0.0");
    assert_eq!(node_config.inspection_service.expose_identity_information, true);
    assert_eq!(node_config.inspection_service.expose_peer_information, true);
}
```

**Step 2:** Exploitation demonstration (pseudocode):

```bash
# Scan for exposed validators
nmap -p 9101 --open validator-network-range

# For each exposed port, extract sensitive information
curl http://validator-ip:9101/identity_information
# Returns: "Validator network (Validator), peer ID: <VALIDATOR_PEER_ID>"

curl http://validator-ip:9101/peer_information  
# Returns: Full peer topology, trusted validator set, connection metadata
```

The vulnerability is confirmed by the fact that the default configuration binds to `0.0.0.0` with sensitive endpoints enabled, and the sanitizer does not prevent this for mainnet validators.

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

**File:** crates/aptos-inspection-service/src/server/mod.rs (L50-70)
```rust
pub fn start_inspection_service(
    node_config: NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) {
    // Fetch the service port and address
    let service_port = node_config.inspection_service.port;
    let service_address = node_config.inspection_service.address.clone();

    // Create the inspection service socket address
    let address: SocketAddr = (service_address.as_str(), service_port)
        .to_socket_addrs()
        .unwrap_or_else(|_| {
            panic!(
                "Failed to parse {}:{} as address",
                service_address, service_port
            )
        })
        .next()
        .unwrap();

```

**File:** crates/aptos-inspection-service/src/server/identity_information.rs (L29-52)
```rust
fn get_identity_information(node_config: &NodeConfig) -> String {
    let mut identity_information = Vec::<String>::new();
    identity_information.push("Identity Information:".into());

    // If the validator network is configured, fetch the identity information
    if let Some(validator_network) = &node_config.validator_network {
        identity_information.push(format!(
            "\t- Validator network ({}), peer ID: {}",
            validator_network.network_id,
            validator_network.peer_id()
        ));
    }

    // For each fullnode network, fetch the identity information
    for fullnode_network in &node_config.full_node_networks {
        identity_information.push(format!(
            "\t- Fullnode network ({}), peer ID: {}",
            fullnode_network.network_id,
            fullnode_network.peer_id()
        ));
    }

    identity_information.join("\n") // Separate each entry with a newline to construct the output
}
```

**File:** crates/aptos-inspection-service/src/server/peer_information.rs (L40-106)
```rust
/// Returns a simple text formatted string with peer and network information
fn get_peer_information(
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> String {
    // Get all registered networks
    let registered_networks: Vec<NetworkId> =
        peers_and_metadata.get_registered_networks().collect();

    // Get all peers (sorted by peer ID)
    let mut all_peers = peers_and_metadata.get_all_peers();
    all_peers.sort();

    // Display a summary of all peers and networks
    let mut peer_information_output = Vec::<String>::new();
    display_peer_information_summary(
        &mut peer_information_output,
        &all_peers,
        &registered_networks,
    );
    peer_information_output.push("\n".into());

    // Display connection metadata for each peer
    display_peer_connection_metadata(
        &mut peer_information_output,
        &all_peers,
        peers_and_metadata.deref(),
    );
    peer_information_output.push("\n".into());

    // Display the entire set of trusted peers
    display_trusted_peers(
        &mut peer_information_output,
        registered_networks,
        peers_and_metadata.deref(),
    );
    peer_information_output.push("\n".into());

    // Display basic peer metadata for each peer
    display_peer_monitoring_metadata(
        &mut peer_information_output,
        &all_peers,
        peers_and_metadata.deref(),
    );
    peer_information_output.push("\n".into());

    // Display state sync metadata for each peer
    display_state_sync_metadata(&mut peer_information_output, &all_peers, aptos_data_client);
    peer_information_output.push("\n".into());

    // Display detailed peer metadata for each peer
    display_detailed_monitoring_metadata(
        &mut peer_information_output,
        &all_peers,
        peers_and_metadata.deref(),
    );
    peer_information_output.push("\n".into());

    // Display the internal client state for each peer
    display_internal_client_state(
        &mut peer_information_output,
        &all_peers,
        peers_and_metadata.deref(),
    );

    peer_information_output.join("\n") // Separate each entry with a newline to construct the output
}
```

**File:** docker/compose/aptos-node/validator.yaml (L1-46)
```yaml
base:
  role: "validator"
  data_dir: "/opt/aptos/data"
  waypoint:
    from_file: "/opt/aptos/genesis/waypoint.txt"

consensus:
  safety_rules:
    service:
      type: "local"
    backend:
      type: "on_disk_storage"
      path: secure-data.json
      namespace: ~
    initial_safety_rules_config:
      from_file:
        waypoint:
          from_file: /opt/aptos/genesis/waypoint.txt
        identity_blob_path: /opt/aptos/genesis/validator-identity.yaml

execution:
  genesis_file_location: "/opt/aptos/genesis/genesis.blob"

storage:
  rocksdb_configs:
    enable_storage_sharding: true

validator_network:
  discovery_method: "onchain"
  mutual_authentication: true
  identity:
    type: "from_file"
    path: /opt/aptos/genesis/validator-identity.yaml

full_node_networks:
- network_id:
    private: "vfn"
  listen_address: "/ip4/0.0.0.0/tcp/6181"
  identity:
    type: "from_config"
    key: "b0f405a3e75516763c43a2ae1d70423699f34cd68fa9f8c6bb2d67aa87d0af69"
    peer_id: "00000000000000000000000000000000d58bc7bb154b38039bc9096ce04e1237"

api:
  enabled: true
  address: "0.0.0.0:8080"
```
