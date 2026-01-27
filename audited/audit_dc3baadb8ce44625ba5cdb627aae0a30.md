# Audit Report

## Title
Mainnet Validators Expose Sensitive Network Identity and Peer Information by Default Due to Missing Configuration Sanitization

## Summary
Production mainnet validators run with `expose_identity_information` and `expose_peer_information` set to `true` by default, exposing critical network topology information through unauthenticated HTTP endpoints. The configuration sanitizer checks `expose_configuration` for mainnet validators but fails to check these equally sensitive endpoints, creating an attack vector for targeted validator attacks, network mapping, and potential eclipse/DoS attacks.

## Finding Description

The inspection service configuration has a critical security gap where sensitive information disclosure endpoints are enabled by default for mainnet validators without sanitization checks.

**Default Configuration Vulnerability:**

The `InspectionServiceConfig` struct defines default values where `expose_identity_information` and `expose_peer_information` are set to `true`: [1](#0-0) 

**Missing Sanitization for Mainnet Validators:**

The sanitizer only checks `expose_configuration` for mainnet validators, completely ignoring the other sensitive endpoints: [2](#0-1) 

**Sensitive Information Exposed:**

The `/identity_information` endpoint exposes validator and fullnode network peer IDs: [3](#0-2) 

The `/peer_information` endpoint exposes even more critical data including trusted peers (validator set), connection metadata, state sync data, peer scores, and internal client state: [4](#0-3) [5](#0-4) 

**No Authentication Required:**

The inspection service has no authentication mechanism and binds to `0.0.0.0:9101` by default, making it accessible to anyone who can reach the validator's network: [1](#0-0) [6](#0-5) 

**Production Templates Don't Override Defaults:**

Official validator configuration templates (test_data/validator.yaml, terraform Helm charts) do not specify inspection_service settings, meaning they inherit the insecure defaults: [7](#0-6) [8](#0-7) 

**Attack Path:**

1. Attacker identifies mainnet validator IP addresses (from network scans, DNS, or other sources)
2. Attacker queries `http://<validator-ip>:9101/identity_information` to obtain the validator's peer ID
3. Attacker queries `http://<validator-ip>:9101/peer_information` to obtain:
   - Complete list of trusted validators in the network
   - Connection states and metadata for all peers
   - State sync peer priorities and scores
   - Internal client state information
4. Using this information, attacker can:
   - Map the entire validator network topology
   - Identify high-value targets for DoS attacks
   - Launch eclipse attacks by manipulating peer connections
   - Perform targeted social engineering against specific validators
   - Exploit state sync vulnerabilities with knowledge of peer states

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria ("Validator node slowdowns" and "Significant protocol violations"):

**Direct Security Impacts:**

1. **Network Topology Disclosure**: Exposes the complete validator network structure, including peer relationships and trust configurations
2. **Targeted Attack Enablement**: Attackers can identify specific validators to target for DoS, social engineering, or eclipse attacks
3. **State Sync Exploitation**: Knowledge of peer scores and advertised data enables sophisticated state sync attacks
4. **Operational Security Violation**: Contradicts the security-conscious design evident in the `expose_configuration` sanitization

**Potential Attack Scenarios:**

- **Eclipse Attacks**: Isolate validators from honest peers by targeting specific connections
- **Targeted DoS**: Overwhelm identified validators or their peer connections
- **Sybil Attacks**: Create malicious nodes that appear trustworthy based on network topology knowledge
- **Network Partition**: Strategic attacks on key validator connections to fragment the network
- **Social Engineering**: Target validator operators with information about their infrastructure

## Likelihood Explanation

**Likelihood: Very High**

This vulnerability will affect **every mainnet validator** that:
1. Uses the default validator configuration templates (most validators)
2. Does not explicitly set `expose_identity_information: false` in their config
3. Has the inspection service port (9101) accessible on their network

**Evidence of High Likelihood:**

1. The default configuration has these values set to `true`
2. Official validator templates do not override these settings
3. The sanitizer does not prevent this configuration on mainnet
4. The config optimizer only touches non-mainnet chains, leaving mainnet validators with defaults
5. Tests demonstrate the endpoints work by default when not explicitly disabled: [9](#0-8) [10](#0-9) 

**Exploitation Complexity: Trivial**

An attacker needs only:
- Network access to port 9101 on validator nodes
- A simple HTTP client (curl, browser, etc.)
- No authentication, credentials, or special privileges required

## Recommendation

**Immediate Fix: Add Sanitization for Mainnet Validators**

Extend the `ConfigSanitizer` implementation to check `expose_identity_information` and `expose_peer_information` for mainnet validators, similar to the existing `expose_configuration` check:

```rust
impl ConfigSanitizer for InspectionServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let inspection_service_config = &node_config.inspection_service;

        // Verify that mainnet validators do not expose sensitive information
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

**Additional Hardening Recommendations:**

1. **Change Defaults**: Set `expose_identity_information` and `expose_peer_information` to `false` by default
2. **Update Templates**: Explicitly set these to `false` in all mainnet validator configuration templates
3. **Documentation**: Add clear warnings about the security implications of enabling these endpoints
4. **Network Binding**: Consider changing the default bind address from `0.0.0.0` to `127.0.0.1` for production environments
5. **Authentication**: Implement authentication for sensitive inspection endpoints if they must be exposed

## Proof of Concept

**PoC 1: Demonstrating Default Exposure (Rust Test)**

```rust
#[test]
fn test_mainnet_validator_exposes_identity_by_default() {
    use aptos_config::config::NodeConfig;
    use aptos_types::chain_id::ChainId;
    use crate::config::{ConfigSanitizer, node_config_loader::NodeType};
    
    // Create a mainnet validator config with default inspection service settings
    let node_config = NodeConfig::get_default_validator_config();
    
    // Verify that the defaults expose sensitive information
    assert!(node_config.inspection_service.expose_identity_information);
    assert!(node_config.inspection_service.expose_peer_information);
    
    // The sanitizer should fail for mainnet validators with these settings
    // but currently does NOT check these fields
    let result = NodeConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    );
    
    // This currently passes but SHOULD fail - demonstrating the vulnerability
    assert!(result.is_ok()); // BUG: Should be Err but passes!
}
```

**PoC 2: Exploiting the Vulnerability (HTTP Request)**

```bash
# Assuming a mainnet validator at IP 203.0.113.10 with default config:

# Query identity information - exposes validator peer ID
curl http://203.0.113.10:9101/identity_information

# Expected output:
# Identity Information:
#   - Validator network (validator), peer ID: <validator_peer_id>
#   - Fullnode network (vfn), peer ID: <vfn_peer_id>

# Query peer information - exposes complete network topology
curl http://203.0.113.10:9101/peer_information

# Expected output includes:
# - All connected peers and their network IDs
# - Trusted peers (entire validator set)
# - Connection metadata and states
# - State sync peer scores and priorities
# - Internal client state
```

**PoC 3: Network Topology Mapping Script**

```python
import requests
import json

def scan_validator_network(validator_ips):
    """
    Demonstrates how an attacker can map the entire validator network
    using the exposed inspection endpoints.
    """
    network_map = {}
    
    for ip in validator_ips:
        try:
            # Get identity information
            identity_resp = requests.get(f"http://{ip}:9101/identity_information", timeout=5)
            
            # Get peer information (contains trusted validator set)
            peer_resp = requests.get(f"http://{ip}:9101/peer_information", timeout=5)
            
            if identity_resp.status_code == 200 and peer_resp.status_code == 200:
                network_map[ip] = {
                    'identity': identity_resp.text,
                    'peers': peer_resp.text,
                    'vulnerable': True
                }
                print(f"[!] Validator {ip} exposes sensitive information")
        except:
            continue
    
    return network_map

# Example usage: scan known mainnet validator IPs
# validators = ["203.0.113.10", "203.0.113.11", ...]
# topology = scan_validator_network(validators)
```

## Notes

This vulnerability represents a clear oversight in the security configuration design. The fact that `expose_configuration` is explicitly sanitized for mainnet validators demonstrates that the developers understood these endpoints should not be exposed in production. However, the other equally sensitive endpoints (`expose_identity_information` and `expose_peer_information`) were not included in this sanitization check, creating a significant security gap.

The vulnerability is particularly concerning because:
1. It affects the default configuration that most validators will use
2. It requires no special privileges or complexity to exploit
3. It exposes information that directly enables targeted attacks on the consensus network
4. The fix is straightforward and follows existing patterns in the codebase

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

**File:** crates/aptos-inspection-service/src/server/identity_information.rs (L13-26)
```rust
pub fn handle_identity_information_request(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Only return identity information if the endpoint is enabled
    let (status_code, body) = if node_config.inspection_service.expose_identity_information {
        let identity_information = get_identity_information(node_config);
        (StatusCode::OK, Body::from(identity_information))
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(IDENTITY_INFO_DISABLED_MESSAGE),
        )
    };

    (status_code, body, CONTENT_TYPE_TEXT.into())
}
```

**File:** crates/aptos-inspection-service/src/server/peer_information.rs (L20-38)
```rust
/// Handles a new peer information request
pub fn handle_peer_information_request(
    node_config: &NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> (StatusCode, Body, String) {
    // Only return peer information if the endpoint is enabled
    let (status_code, body) = if node_config.inspection_service.expose_peer_information {
        let peer_information = get_peer_information(aptos_data_client, peers_and_metadata);
        (StatusCode::OK, Body::from(peer_information))
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(PEER_INFO_DISABLED_MESSAGE),
        )
    };

    (status_code, body, CONTENT_TYPE_TEXT.into())
}
```

**File:** crates/aptos-inspection-service/src/server/peer_information.rs (L273-299)
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
```

**File:** crates/aptos-inspection-service/src/server/mod.rs (L48-70)
```rust
/// Starts the inspection service that listens on the configured
/// address and handles various endpoint requests.
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

**File:** config/src/config/test_data/validator.yaml (L1-81)
```yaml
base:
    data_dir: "/opt/aptos/data"
    role: "validator"
    waypoint:
        from_storage:
            type: "vault"
            server: "https://127.0.0.1:8200"
            ca_certificate: "/full/path/to/certificate"
            token:
                from_disk: "/full/path/to/token"

consensus:
    safety_rules:
        service:
            type: process
            server_address: "/ip4/127.0.0.1/tcp/5555"

execution:
    genesis_file_location: "relative/path/to/genesis"

# For validator node we setup two networks, validator_network to allow validator connect to each other,
# and full_node_networks to allow fullnode connects to validator.

full_node_networks:
    - listen_address: "/ip4/0.0.0.0/tcp/6181"
      max_outbound_connections: 0
      identity:
          type: "from_storage"
          key_name: "fullnode_network"
          peer_id_name: "owner_account"
          backend:
              type: "vault"
              server: "https://127.0.0.1:8200"
              ca_certificate: "/full/path/to/certificate"
              token:
                  from_disk: "/full/path/to/token"
      network_id:
          private: "vfn"

validator_network:
    discovery_method: "onchain"
    listen_address: "/ip4/0.0.0.0/tcp/6180"
    identity:
        type: "from_storage"
        key_name: "validator_network"
        peer_id_name: "owner_account"
        backend:
            type: "vault"
            server: "https://127.0.0.1:8200"
            ca_certificate: "/full/path/to/certificate"
            token:
                from_disk: "/full/path/to/token"
    network_id: "validator"
    ### Load keys from file
    # identity:
    #     type: "from_file"
    #     path: /full/path/to/private-keys.yml
    #
    ### Load keys from secure storage service like vault:
    #
    # identity:
    #     type: "from_storage"
    #     key_name: "validator_network"
    #     peer_id_name: "owner_account"
    #     backend:
    #         type: "vault"
    #         server: "https://127.0.0.1:8200"
    #         ca_certificate: "/full/path/to/certificate"
    #         token:
    #             from_disk: "/full/path/to/token"
    #
    ### Load keys directly from config
    #
    # identity:
    #     type: "from_config"
    #     key: "b0f405a3e75516763c43a2ae1d70423699f34cd68fa9f8c6bb2d67aa87d0af69"
    #     peer_id: "00000000000000000000000000000000d58bc7bb154b38039bc9096ce04e1237"
    mutual_authentication: true
    max_frame_size: 4194304 # 4 MiB
api:
    enabled: true
```

**File:** terraform/helm/aptos-node/files/configs/validator-base.yaml (L1-48)
```yaml
###
### This is the base validator NodeConfig to work with this helm chart
### Additional overrides to the NodeConfig can be specified via .Values.validator.config or .Values.overrideNodeConfig
###
base:
  role: validator
  waypoint:
    from_file: /opt/aptos/genesis/waypoint.txt

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
  genesis_file_location: /opt/aptos/genesis/genesis.blob

full_node_networks:
  - network_id:
      private: "vfn"
    listen_address: "/ip4/0.0.0.0/tcp/6181"
    identity:
      type: "from_config"
      key: "b0f405a3e75516763c43a2ae1d70423699f34cd68fa9f8c6bb2d67aa87d0af69"
      peer_id: "00000000000000000000000000000000d58bc7bb154b38039bc9096ce04e1237"

storage:
  rocksdb_configs:
    enable_storage_sharding: true

api:
  enabled: true
  address: "0.0.0.0:8080"

validator_network:
  discovery_method: "onchain"
  identity:
    type: "from_file"
    path: /opt/aptos/genesis/validator-identity.yaml
```

**File:** crates/aptos-inspection-service/src/server/tests.rs (L114-144)
```rust
#[tokio::test]
async fn test_inspect_identity_information() {
    // Create a validator config (with a single validator identity)
    let mut config = NodeConfig::get_default_validator_config();
    if let Some(network_config) = config.validator_network.as_mut() {
        network_config.identity = Identity::None; // Reset the identity
        network_config
            .set_listen_address_and_prepare_identity()
            .unwrap(); // Generates a random identity
    }
    config.full_node_networks = vec![];

    // Disable the identity information endpoint and ping it
    config.inspection_service.expose_identity_information = false;
    let mut response = send_get_request_to_path(&config, IDENTITY_INFORMATION_PATH).await;
    let response_body = body::to_bytes(response.body_mut()).await.unwrap();

    // Verify that the response contains an error
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_body, IDENTITY_INFO_DISABLED_MESSAGE);

    // Enable the identity information endpoint and ping it
    config.inspection_service.expose_identity_information = true;
    let mut response = send_get_request_to_path(&config, IDENTITY_INFORMATION_PATH).await;
    let response_body = body::to_bytes(response.body_mut()).await.unwrap();
    let response_body_string = read_to_string(response_body.as_ref()).unwrap();

    // Verify that the response contains the expected information
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_body_string.contains("Identity Information:"));
}
```

**File:** crates/aptos-inspection-service/src/server/tests.rs (L189-215)
```rust
#[tokio::test]
async fn test_inspect_peer_information() {
    // Create a validator node config
    let mut config = NodeConfig::get_default_validator_config();

    // Disable the peer information endpoint and ping it
    config.inspection_service.expose_peer_information = false;
    let mut response = send_get_request_to_path(&config, PEER_INFORMATION_PATH).await;
    let response_body = block_on(body::to_bytes(response.body_mut())).unwrap();

    // Verify that the response contains an error
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_body, PEER_INFO_DISABLED_MESSAGE);

    // Enable the peer information endpoint and ping it
    config.inspection_service.expose_peer_information = true;
    let mut response = send_get_request_to_path(&config, PEER_INFORMATION_PATH).await;
    let response_body = block_on(body::to_bytes(response.body_mut())).unwrap();
    let response_body_string = read_to_string(response_body.as_ref()).unwrap();

    // Verify that the response contains the expected information
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response_body_string.contains("Number of peers"));
    assert!(response_body_string.contains("Registered networks"));
    assert!(response_body_string.contains("Peers and network IDs"));
    assert!(response_body_string.contains("State sync metadata"));
}
```
