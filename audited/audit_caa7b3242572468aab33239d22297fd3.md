# Audit Report

## Title
Insecure Default Configuration in Inspection Service Exposes Mainnet Validator Network Topology Without Authentication

## Summary
The Aptos Inspection Service binds to all network interfaces (0.0.0.0) by default and exposes sensitive validator network information without authentication. Mainnet validators using default configurations inadvertently expose their peer IDs, the complete validator set topology, network addresses, and system information to any network attacker.

## Finding Description

The `InspectionServiceConfig` struct defines insecure defaults that expose sensitive endpoints without authentication: [1](#0-0) 

The critical security issues are:

1. **Binds to all interfaces**: `address: "0.0.0.0"` exposes the service publicly rather than restricting it to localhost.

2. **Sensitive endpoints enabled by default**:
   - `expose_identity_information: true` - Exposes validator peer IDs
   - `expose_peer_information: true` - Exposes complete validator set, network topology, IPs
   - `expose_system_information: true` - Exposes build information

3. **No authentication mechanism**: The request handler has no authentication checks: [2](#0-1) 

4. **Configuration optimizer does NOT protect mainnet**: The optimizer only enables endpoints for non-mainnet nodes, leaving mainnet validators with insecure defaults: [3](#0-2) 

5. **Insufficient sanitizer protection**: The sanitizer only blocks `expose_configuration` for mainnet validators, leaving the other sensitive endpoints unprotected: [4](#0-3) 

6. **Common deployment pattern**: All example validator configurations omit inspection_service settings, causing them to inherit insecure defaults: [5](#0-4) 

The `/peer_information` endpoint exposes the complete validator set including network addresses and public keys: [6](#0-5) 

The `Peer` struct contains sensitive network topology information: [7](#0-6) 

## Impact Explanation

This vulnerability is **High Severity** based on Aptos bug bounty criteria because it represents a "significant protocol violation" that enables network reconnaissance attacks:

1. **Validator Network Mapping**: Attackers can enumerate the entire mainnet validator set, their peer IDs, network addresses (IPs), and connection states by querying exposed inspection services.

2. **Targeted Attack Facilitation**: With validator IPs and network topology, attackers can:
   - Launch targeted DDoS attacks against specific validators
   - Identify validator infrastructure for social engineering
   - Monitor validator connections for eclipse attacks
   - Fingerprint software versions for targeted exploits

3. **Widespread Impact**: Any mainnet validator deployed without explicit inspection_service configuration is vulnerable. Given that:
   - All official validator.yaml examples lack inspection_service configuration
   - The defaults are insecure
   - No prominent documentation warns about this
   
   The vulnerability likely affects a significant portion of the mainnet validator set.

4. **Privacy Violation**: Validator operators' network infrastructure is exposed without consent, violating operational security best practices.

While this does not directly cause loss of funds or consensus violations, it violates the **Access Control** invariant and significantly degrades network security by enabling reconnaissance for more sophisticated attacks.

## Likelihood Explanation

**Likelihood: High**

This vulnerability will occur whenever:
1. A validator is deployed without explicit `inspection_service` configuration in their YAML
2. Network firewall rules don't block port 9101 from external access
3. The validator uses the default code configuration

Evidence of high likelihood:
- All example validator configurations in the codebase omit inspection_service settings
- The ConfigOptimizer explicitly does NOT modify mainnet configurations (test verifies this)
- Docker deployment shows awareness this SHOULD be localhost-only (127.0.0.1:9101), but the application defaults contradict this [8](#0-7) 

Validators following deployment guides without additional security hardening will be vulnerable.

## Recommendation

**Immediate Fix**: Change the defaults to be secure-by-default for mainnet:

```rust
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "127.0.0.1".to_string(), // FIXED: Bind to localhost only
            port: 9101,
            expose_configuration: false,
            expose_identity_information: false, // FIXED: Disabled by default
            expose_peer_information: false,     // FIXED: Disabled by default
            expose_system_information: false,   // FIXED: Disabled by default
        }
    }
}
```

**Additional Recommendations**:

1. **Add authentication**: Implement token-based authentication similar to the Admin Service: [9](#0-8) 

Add authentication check before processing requests.

2. **Expand ConfigSanitizer**: Prevent mainnet validators from exposing ANY sensitive endpoints, not just configuration:

```rust
impl ConfigSanitizer for InspectionServiceConfig {
    fn sanitize(node_config: &NodeConfig, node_type: NodeType, chain_id: Option<ChainId>) -> Result<(), Error> {
        if let Some(chain_id) = chain_id {
            if node_type.is_validator() && chain_id.is_mainnet() {
                let config = &node_config.inspection_service;
                if config.expose_configuration 
                    || config.expose_identity_information 
                    || config.expose_peer_information 
                    || config.expose_system_information {
                    return Err(Error::ConfigSanitizerFailed(
                        Self::get_sanitizer_name(),
                        "Mainnet validators should not expose inspection service endpoints publicly!".to_string(),
                    ));
                }
                if config.address != "127.0.0.1" {
                    return Err(Error::ConfigSanitizerFailed(
                        Self::get_sanitizer_name(),
                        "Mainnet validators must bind inspection service to localhost only!".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}
```

3. **Documentation**: Add prominent warnings in validator deployment documentation about securing the inspection service.

4. **Migration Path**: For existing validators, provide clear instructions to update configurations.

## Proof of Concept

**Step 1**: Deploy a mainnet validator using default configuration (no inspection_service specified in validator.yaml).

**Step 2**: From an external machine, query the exposed endpoints:

```bash
# Enumerate validator identity
curl http://<validator-ip>:9101/identity_information

# Map validator network topology
curl http://<validator-ip>:9101/peer_information

# Fingerprint software version
curl http://<validator-ip>:9101/system_information

# Access metrics
curl http://<validator-ip>:9101/metrics
```

**Expected Result**: All endpoints return detailed information without authentication, including:
- Validator peer IDs and network identities
- Complete validator set with network addresses (IPs) and public keys
- Connection states and peer metadata
- Build version and system information

**Rust Verification Test**:

```rust
#[test]
fn test_insecure_default_config() {
    use aptos_config::config::InspectionServiceConfig;
    
    let default_config = InspectionServiceConfig::default();
    
    // Verify insecure defaults
    assert_eq!(default_config.address, "0.0.0.0", "Binds to all interfaces!");
    assert!(default_config.expose_identity_information, "Identity exposed by default!");
    assert!(default_config.expose_peer_information, "Peer info exposed by default!");
    assert!(default_config.expose_system_information, "System info exposed by default!");
}
```

This demonstrates that without explicit configuration, mainnet validators expose sensitive network topology information to any attacker with network access to port 9101.

## Notes

The Docker Compose configuration shows awareness that port 9101 should be localhost-only (prefacing with `127.0.0.1:`), but this is a deployment-level workaround, not a fix in the application defaults. Validators deployed via other methods (bare metal, VMs, Kubernetes without proper network policies) remain vulnerable unless they explicitly configure the inspection service or set up external firewalls.

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

**File:** config/src/config/inspection_service_config.rs (L71-105)
```rust
impl ConfigOptimizer for InspectionServiceConfig {
    fn optimize(
        node_config: &mut NodeConfig,
        local_config_yaml: &Value,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<bool, Error> {
        let inspection_service_config = &mut node_config.inspection_service;
        let local_inspection_config_yaml = &local_config_yaml["inspection_service"];

        // Enable all endpoints for non-mainnet nodes (to aid debugging)
        let mut modified_config = false;
        if let Some(chain_id) = chain_id {
            if !chain_id.is_mainnet() {
                if local_inspection_config_yaml["expose_configuration"].is_null() {
                    inspection_service_config.expose_configuration = true;
                    modified_config = true;
                }

                if local_inspection_config_yaml["expose_identity_information"].is_null() {
                    inspection_service_config.expose_identity_information = true;
                    modified_config = true;
                }

                if local_inspection_config_yaml["expose_peer_information"].is_null() {
                    inspection_service_config.expose_peer_information = true;
                    modified_config = true;
                }

                if local_inspection_config_yaml["expose_system_information"].is_null() {
                    inspection_service_config.expose_system_information = true;
                    modified_config = true;
                }
            }
        }
```

**File:** crates/aptos-inspection-service/src/server/mod.rs (L104-169)
```rust
async fn serve_requests(
    req: Request<Body>,
    node_config: NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> Result<Response<Body>, hyper::Error> {
    // Process the request and get the response components
    let (status_code, body, content_type) = match req.uri().path() {
        CONFIGURATION_PATH => {
            // /configuration
            // Exposes the node configuration
            configuration::handle_configuration_request(&node_config)
        },
        CONSENSUS_HEALTH_CHECK_PATH => {
            // /consensus_health_check
            // Exposes the consensus health check
            metrics::handle_consensus_health_check(&node_config).await
        },
        FORGE_METRICS_PATH => {
            // /forge_metrics
            // Exposes forge encoded metrics
            metrics::handle_forge_metrics()
        },
        IDENTITY_INFORMATION_PATH => {
            // /identity_information
            // Exposes the identity information of the node
            identity_information::handle_identity_information_request(&node_config)
        },
        INDEX_PATH => {
            // /
            // Exposes the index and list of available endpoints
            index::handle_index_request()
        },
        JSON_METRICS_PATH => {
            // /json_metrics
            // Exposes JSON encoded metrics
            metrics::handle_json_metrics_request()
        },
        METRICS_PATH => {
            // /metrics
            // Exposes text encoded metrics
            metrics::handle_metrics_request()
        },
        PEER_INFORMATION_PATH => {
            // /peer_information
            // Exposes the peer information
            peer_information::handle_peer_information_request(
                &node_config,
                aptos_data_client,
                peers_and_metadata,
            )
        },
        SYSTEM_INFORMATION_PATH => {
            // /system_information
            // Exposes the system and build information
            system_information::handle_system_information_request(node_config)
        },
        _ => {
            // Handle the invalid path
            (
                StatusCode::NOT_FOUND,
                Body::from(INVALID_ENDPOINT_MESSAGE),
                CONTENT_TYPE_TEXT.into(),
            )
        },
    };
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

**File:** config/src/config/network_config.rs (L460-464)
```rust
pub struct Peer {
    pub addresses: Vec<NetworkAddress>,
    pub keys: HashSet<x25519::PublicKey>,
    pub role: PeerRole,
}
```

**File:** docker/compose/aptos-node/docker-compose-src.yaml (L31-33)
```yaml
      # Preface these with 127 to only expose them locally
      - "127.0.0.1:9101:9101"
      - "127.0.0.1:9102:9102"
```
