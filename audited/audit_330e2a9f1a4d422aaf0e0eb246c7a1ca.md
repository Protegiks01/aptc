# Audit Report

## Title
Inspection Service Binds to 0.0.0.0 by Default, Exposing Sensitive Validator Network Information to External Networks

## Summary
The Aptos inspection service binds to all network interfaces (`0.0.0.0`) by default and exposes sensitive validator network topology information including peer IDs, network identifiers, connection metadata, and trusted peer lists through unauthenticated HTTP endpoints. This configuration violates defense-in-depth principles and enables reconnaissance attacks against validator infrastructure.

## Finding Description

The inspection service has a critical network exposure issue stemming from its default configuration. The service binds to `"0.0.0.0"` (all network interfaces) and port `9101` by default, making it accessible from external networks. [1](#0-0) 

The service is started unconditionally on every Aptos node during initialization, with no authentication mechanism. [2](#0-1) 

The service exposes multiple sensitive endpoints that are enabled by default:

1. **Identity Information Endpoint** (`/identity_information`) - Exposes validator network peer IDs and network IDs. This endpoint is enabled by default (`expose_identity_information: true`). [3](#0-2)  The endpoint reveals critical network topology information. [4](#0-3) 

2. **Peer Information Endpoint** (`/peer_information`) - Exposes detailed connection metadata, trusted peers (validator set & seeds), internal client state, peer monitoring metadata, and state sync information. This endpoint is also enabled by default (`expose_peer_information: true`). [5](#0-4)  The endpoint provides comprehensive network reconnaissance data. [6](#0-5) 

3. **System Information Endpoint** (`/system_information`) - Exposes build information and system details, enabled by default (`expose_system_information: true`). [7](#0-6) 

The service creates a socket address from the configured address and port, then binds the HTTP server to that address without any IP filtering or authentication. [8](#0-7) 

**Attack Scenario:**
An external attacker can perform network reconnaissance by making HTTP GET requests to `http://<validator-ip>:9101/identity_information` and `http://<validator-ip>:9101/peer_information` to:
- Enumerate validator peer IDs and network topology
- Identify trusted peers and validator set composition
- Monitor connection states and peer metadata
- Discover build versions to identify nodes running vulnerable software versions
- Map the entire validator network structure for targeted attacks

While some production deployments may use HAProxy or Kubernetes NetworkPolicy for network-level protection, these are **optional deployment-specific configurations**, not enforced by the core codebase. Nodes deployed outside of the reference Kubernetes setup (local testnets, standalone validators, manual deployments) are directly exposed. [9](#0-8) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria for the following reasons:

1. **Significant Protocol Violation**: Exposing internal network topology violates the security principle that internal diagnostic services should not be accessible externally by default.

2. **Enables Targeted Attacks**: The exposed information allows attackers to:
   - Map validator network topology for eclipse attacks
   - Identify specific validators to target based on build versions
   - Monitor validator connectivity patterns
   - Discover validator peer relationships to plan network-level attacks

3. **Information Disclosure at Scale**: Unlike minor information leaks (Low severity), this exposes comprehensive network intelligence that can be used to compromise consensus security and validator availability.

4. **No Authentication Required**: Any network-accessible attacker can exploit this without credentials, validator access, or social engineering.

While this does not directly cause fund loss or consensus violations, it significantly aids in reconnaissance for attacks that could lead to "Validator node slowdowns" or "Significant protocol violations" (both High severity categories).

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Default Configuration**: Every Aptos node starts with `address: "0.0.0.0"` unless explicitly reconfigured. [10](#0-9) 

2. **No Manual Intervention Required**: Operators who deploy nodes outside the reference Kubernetes configuration may not be aware of the network exposure risk.

3. **Low Attack Complexity**: Exploitation requires only HTTP GET requests—no authentication, no special privileges, and no complex attack chains.

4. **Production Impact**: The ConfigOptimizer does not restrict these endpoints on mainnet (unlike the configuration endpoint which is explicitly sanitized for mainnet validators). [11](#0-10) 

5. **Wide Attack Surface**: Any attacker with network connectivity to a validator can perform reconnaissance, including nation-state actors, competing validators, or opportunistic attackers.

## Recommendation

Implement defense-in-depth with the following changes:

**1. Change Default Binding Address to Localhost:**
```rust
// config/src/config/inspection_service_config.rs
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "127.0.0.1".to_string(), // Changed from "0.0.0.0"
            port: 9101,
            expose_configuration: false,
            expose_identity_information: false, // Changed from true
            expose_peer_information: false, // Changed from true
            expose_system_information: false, // Changed from true
        }
    }
}
```

**2. Add Explicit Warning in Configuration Sanitizer:**
```rust
// config/src/config/inspection_service_config.rs
impl ConfigSanitizer for InspectionServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let inspection_service_config = &node_config.inspection_service;

        // Warn if binding to 0.0.0.0 with sensitive endpoints enabled
        if inspection_service_config.address == "0.0.0.0" 
            && (inspection_service_config.expose_identity_information
                || inspection_service_config.expose_peer_information) {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Inspection service bound to 0.0.0.0 with sensitive endpoints enabled. \
                 Change address to 127.0.0.1 or disable expose_identity_information \
                 and expose_peer_information.".to_string(),
            ));
        }

        // Existing mainnet configuration check...
        Ok(())
    }
}
```

**3. Document Network Exposure in Node Operator Guides:**
Add explicit warnings in operator documentation about the inspection service and recommend using firewalls or HAProxy for production deployments if external access is needed for monitoring.

## Proof of Concept

**Setup:**
1. Deploy an Aptos validator node with default configuration (no Kubernetes, no HAProxy)
2. Ensure port 9101 is not blocked by host firewall

**Exploitation:**
```bash
# From an external attacker machine with network access to the validator

# Enumerate validator identity
curl http://<validator-ip>:9101/identity_information

# Expected output exposes peer IDs:
# Identity Information:
#   - Validator network (Validator), peer ID: <peer_id_hex>
#   - Fullnode network (Public), peer ID: <peer_id_hex>

# Enumerate detailed peer information
curl http://<validator-ip>:9101/peer_information

# Expected output exposes:
# - Number of peers
# - Registered networks
# - Trusted peers (validator set)
# - Connection metadata with IP addresses
# - Internal client states
# - State sync metadata

# Enumerate system information
curl http://<validator-ip>:9101/system_information

# Expected output exposes build version and system details

# This information enables targeted attacks:
# 1. Map validator network topology
# 2. Identify vulnerable build versions
# 3. Plan eclipse attacks against specific validators
# 4. Monitor validator availability patterns
```

**Rust Test Demonstration:**
```rust
#[test]
fn test_inspection_service_default_exposure() {
    use aptos_config::config::InspectionServiceConfig;
    
    let config = InspectionServiceConfig::default();
    
    // Verify the vulnerability exists
    assert_eq!(config.address, "0.0.0.0", "Inspection service binds to all interfaces");
    assert!(config.expose_identity_information, "Identity info exposed by default");
    assert!(config.expose_peer_information, "Peer info exposed by default");
    assert!(config.expose_system_information, "System info exposed by default");
    
    println!("VULNERABILITY CONFIRMED: Inspection service exposes sensitive data on 0.0.0.0:9101");
}
```

## Notes

This vulnerability represents a defense-in-depth failure where the core codebase relies on optional deployment-specific protections (HAProxy, Kubernetes NetworkPolicy) rather than enforcing secure defaults at the application layer. While production deployments using the reference Kubernetes setup may have additional network protections, the insecure default configuration affects:

- Local testnet nodes
- Standalone validators
- Development environments
- Manual deployments outside Kubernetes
- Any deployment where NetworkPolicy is not explicitly enabled

The principle of "secure by default" dictates that sensitive diagnostic services should bind to localhost unless explicitly configured otherwise, with clear warnings about the security implications of external exposure.

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

**File:** config/src/config/inspection_service_config.rs (L45-69)
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
}
```

**File:** aptos-node/src/lib.rs (L771-776)
```rust
    // Start the node inspection service
    services::start_node_inspection_service(
        &node_config,
        aptos_data_client,
        peers_and_metadata.clone(),
    );
```

**File:** crates/aptos-inspection-service/src/server/identity_information.rs (L29-51)
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

**File:** crates/aptos-inspection-service/src/server/mod.rs (L55-96)
```rust
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

    // Create a runtime for the inspection service
    let runtime = aptos_runtimes::spawn_named_runtime("inspection".into(), None);

    // Spawn the inspection service
    thread::spawn(move || {
        // Create the service function that handles the endpoint requests
        let make_service = make_service_fn(move |_conn| {
            let node_config = node_config.clone();
            let aptos_data_client = aptos_data_client.clone();
            let peers_and_metadata = peers_and_metadata.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |request| {
                    serve_requests(
                        request,
                        node_config.clone(),
                        aptos_data_client.clone(),
                        peers_and_metadata.clone(),
                    )
                }))
            }
        });

        // Start and block on the server
        runtime
            .block_on(async {
                let server = Server::bind(&address).serve(make_service);
```

**File:** terraform/helm/aptos-node/templates/networkpolicy.yaml (L1-1)
```yaml
{{- if .Values.validator.enableNetworkPolicy }}
```
