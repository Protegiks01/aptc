# Audit Report

## Title
Information Disclosure via Inspection Service Enables Validator Network Topology Enumeration

## Summary
The Aptos inspection service exposes network topology information including network IDs, peer IDs, and connection metadata through unauthenticated HTTP endpoints that bind to all network interfaces by default. This allows external attackers to enumerate validator network configurations, identify validator nodes, and map network connections, facilitating reconnaissance for targeted attacks.

## Finding Description
The inspection service implements two critical endpoints that leak network topology information: [1](#0-0) [2](#0-1) 

The service binds to all network interfaces by default: [3](#0-2) 

An attacker can query `/identity_information` to learn:
- All configured network IDs (Validator, Public, Vfn)
- Peer IDs for each network
- Whether a node is a validator (presence of Validator network)

Additionally, the `/peer_information` endpoint exposes significantly more detailed topology data: [4](#0-3) [5](#0-4) 

This reveals connection metadata including IP addresses, connection states, and the complete list of connected peers and trusted validators.

The security sanitizer only restricts the configuration endpoint for mainnet validators, but does NOT enforce restrictions on identity or peer information disclosure: [6](#0-5) 

## Impact Explanation
This vulnerability falls under **Low Severity** per Aptos bug bounty criteria as a "Minor information leak." While the question categorizes it as "High," the actual impact does not meet High severity requirements:

- **Not High Severity**: Does not cause validator slowdowns, API crashes, or direct protocol violations
- **Not Medium Severity**: Does not cause funds loss or state inconsistencies  
- **Low Severity**: Information disclosure that enables reconnaissance

The leaked information facilitates but does not directly enable:
- Network topology mapping for eclipse attack preparation
- Validator identification for targeted reconnaissance
- Peer connection analysis for network-level attacks (though DDoS is explicitly out of scope)

However, this represents poor security defaults where operational controls (firewalls/HAProxy) are required to secure what should be restricted at the application level.

## Likelihood Explanation
**Moderate likelihood** in misconfigured deployments:

- Default configuration exposes the service to all network interfaces (0.0.0.0:9101)
- No authentication mechanism exists at the application level
- Production deployments use HAProxy with IP blocking, but this is an operational control that may be bypassed or misconfigured
- Validators without proper firewall rules directly expose this information
- The service is designed for debugging/monitoring but lacks security-first defaults

The vulnerability is exploitable with a simple HTTP GET request if the service is network-accessible.

## Recommendation
Implement defense-in-depth by addressing this at multiple layers:

1. **Change default binding to localhost**:
```yaml
# config/src/config/inspection_service_config.rs
address: "127.0.0.1".to_string(),  // Instead of "0.0.0.0"
```

2. **Add mainnet validator sanitization for identity/peer endpoints**:
```rust
// In ConfigSanitizer::sanitize
if let Some(chain_id) = chain_id {
    if node_type.is_validator() && chain_id.is_mainnet() {
        if inspection_service_config.expose_identity_information {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
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
```

3. **Disable sensitive endpoints by default for validators**:
```yaml
expose_identity_information: false,  // For validator nodes
expose_peer_information: false,      // For validator nodes
```

4. **Add authentication mechanism** for production environments

5. **Document security implications** in configuration templates

## Proof of Concept
```bash
# Enumerate validator network topology (if inspection service is accessible)

# Step 1: Scan for nodes running inspection service
nmap -p 9101 <network_range>

# Step 2: Query identity information
curl http://<target_node>:9101/identity_information

# Expected output reveals:
# Identity Information:
#   - Validator network (Validator), peer ID: <validator_peer_id>
#   - Fullnode network (vfn), peer ID: <vfn_peer_id>

# Step 3: Query detailed peer information
curl http://<target_node>:9101/peer_information

# Expected output reveals:
# - All connected peer IDs and network IDs
# - Connection metadata with IP addresses
# - Trusted peers (validator set)
# - Connection states and roles

# Step 4: Correlate data to map validator network topology
# - Identify which nodes are validators
# - Map peer-to-peer connections
# - Identify VFN relationships
# - Build network graph for attack planning
```

## Notes

This information disclosure vulnerability enables network enumeration but requires additional attack vectors to cause direct harm. The primary security failure is insecure defaults (binding to 0.0.0.0 and enabling endpoints by default) rather than a protocol-level vulnerability. Production deployments typically mitigate this through operational controls (HAProxy, firewalls), but the application code itself lacks security-first design.

The vulnerability is valid and exploitable in misconfigured environments, but the severity is **Low** rather than the "High" claimed in the security question, as it does not directly violate consensus safety, cause fund loss, or impact network availability—it merely facilitates reconnaissance for other potential attacks.

### Citations

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

**File:** config/src/config/inspection_service_config.rs (L26-36)
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

**File:** crates/aptos-inspection-service/src/server/peer_information.rs (L21-38)
```rust
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

**File:** crates/aptos-inspection-service/src/server/peer_information.rs (L148-168)
```rust
/// Displays connection metadata for each peer
fn display_peer_connection_metadata(
    peer_information_output: &mut Vec<String>,
    all_peers: &Vec<PeerNetworkId>,
    peers_and_metadata: &PeersAndMetadata,
) {
    peer_information_output.push("Connection metadata for each peer:".into());

    // Fetch and display the connection metadata for each peer
    for peer in all_peers {
        if let Ok(peer_metadata) = peers_and_metadata.get_metadata_for_peer(*peer) {
            let connection_metadata = peer_metadata.get_connection_metadata();
            peer_information_output.push(format!(
                "\t- Peer: {}, connection state: {:?}, connection metadata: {}",
                peer,
                peer_metadata.get_connection_state(),
                serde_json::to_string(&connection_metadata).unwrap_or_default()
            ));
        }
    }
}
```
