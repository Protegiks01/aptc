# Audit Report

## Title
Insecure Default Configuration in Inspection Service Exposes Critical Validator Information on Mainnet

## Summary
The inspection service uses insecure defaults that expose sensitive validator information (identity, peer network topology, and system details) on mainnet deployments. The configuration sanitizer only validates `expose_configuration` but fails to check the three other information exposure flags, allowing validators who deploy with default settings to inadvertently leak critical network intelligence to potential attackers.

## Finding Description
The `InspectionServiceConfig::default()` function sets three security-sensitive flags to `true` by default: [1](#0-0) 

Additionally, the service binds to `0.0.0.0` (all network interfaces) by default, making it accessible from any network interface if firewall rules permit.

The configuration sanitizer (`ConfigSanitizer::sanitize`) only validates that mainnet validators do not expose the configuration endpoint: [2](#0-1) 

**Critical Gap**: The sanitizer does NOT validate the three other exposure flags (`expose_identity_information`, `expose_peer_information`, `expose_system_information`), creating a false sense of security.

### Information Leakage Vectors

**1. Identity Information Endpoint** exposes validator network peer IDs: [3](#0-2) 

**2. Peer Information Endpoint** exposes the complete validator set, network topology, and connection states: [4](#0-3) 

This endpoint reveals:
- All validator peer IDs and network addresses from the trusted peer set
- Connection states and metadata for all connected peers
- State sync information and peer performance scores
- Complete network topology

**3. System Information Endpoint** exposes build metadata: [5](#0-4) 

The build information includes git commit hash, branch, build time, and OS details: [6](#0-5) 

### Exploitation Scenario

1. **Deployment**: A validator operator deploys on bare metal or uses a custom deployment method without explicitly configuring the inspection service
2. **Default Binding**: The inspection service binds to `0.0.0.0:9101` as per defaults
3. **Firewall Misconfiguration**: The operator's firewall rules allow external access to port 9101 (either through misconfiguration or intentional monitoring access)
4. **Information Harvest**: An attacker queries:
   - `http://validator-ip:9101/identity_information` → Gets validator peer ID
   - `http://validator-ip:9101/peer_information` → Gets complete validator set with addresses, keys, and topology
   - `http://validator-ip:9101/system_information` → Gets git commit hash and build details

5. **Attack Enablement**: With this intelligence, the attacker can:
   - Map the complete validator network topology for eclipse attack planning
   - Identify validators running outdated or debug builds with known vulnerabilities
   - Target specific validators with DDoS attacks knowing their network addresses
   - Correlate peer performance scores to identify weak validators
   - Time attacks based on connection state information

The inspection service starts with no authentication: [7](#0-6) 

## Impact Explanation
This qualifies as **High Severity** under the Aptos bug bounty criteria:
- **"Validator node slowdowns"**: The exposed information enables targeted network attacks that could degrade validator performance
- **"Significant protocol violations"**: Exposing the complete validator set and network topology violates security-by-obscurity principles that protect consensus networks

The vulnerability enables:
1. **Reconnaissance for Consensus Attacks**: Complete validator network topology allows attackers to plan sophisticated eclipse or network partition attacks
2. **Targeted Exploitation**: Git commit hash exposure allows attackers to identify validators running specific versions with known vulnerabilities
3. **Network Mapping**: Peer information reveals which validators are connected to which, enabling strategic attack planning
4. **Performance-Based Targeting**: Exposed peer scores allow attackers to identify and target validators with degraded performance

While this doesn't directly compromise funds or consensus safety, it provides critical intelligence that enables more sophisticated attacks on the consensus network.

## Likelihood Explanation
**Likelihood: Medium-to-High**

**Factors Increasing Likelihood:**
1. All example configurations (validator.yaml, validator-base.yaml) omit inspection_service settings, meaning operators rely on defaults: [8](#0-7) 

2. The incomplete sanitizer creates false confidence that mainnet validators are protected
3. Bare metal or custom deployments may not implement network-level protections
4. Port 9101 is commonly opened for monitoring infrastructure access

**Mitigating Factors:**
1. Docker Compose deployments bind to localhost only: [9](#0-8) 

2. Kubernetes deployments use NetworkPolicy restrictions: [10](#0-9) 

3. Proper firewall configuration would block external access

However, relying on external protections rather than secure defaults is a security anti-pattern.

## Recommendation

**Immediate Fix**: Update the default configuration to disable information exposure for production deployments:

```rust
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "127.0.0.1".to_string(), // Bind to localhost by default
            port: 9101,
            expose_configuration: false,
            expose_identity_information: false, // Changed from true
            expose_peer_information: false,     // Changed from true
            expose_system_information: false,   // Changed from true
        }
    }
}
```

**Enhanced Validation**: Extend the sanitizer to validate all exposure flags for mainnet validators:

```rust
impl ConfigSanitizer for InspectionServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let inspection_service_config = &node_config.inspection_service;

        if let Some(chain_id) = chain_id {
            if node_type.is_validator() && chain_id.is_mainnet() {
                // Check all exposure flags for mainnet validators
                if inspection_service_config.expose_configuration {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Mainnet validators should not expose the node configuration!".to_string(),
                    ));
                }
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
                if inspection_service_config.expose_system_information {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Mainnet validators should not expose system information!".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}
```

**Defense in Depth**: Update the ConfigOptimizer to explicitly disable endpoints for mainnet validators:

```rust
// In the optimize function, add:
if let Some(chain_id) = chain_id {
    if chain_id.is_mainnet() && node_type.is_validator() {
        // Explicitly disable all information endpoints for mainnet validators
        inspection_service_config.expose_identity_information = false;
        inspection_service_config.expose_peer_information = false;
        inspection_service_config.expose_system_information = false;
        modified_config = true;
    }
}
```

## Proof of Concept

**Step 1**: Create a minimal mainnet validator configuration without inspection_service settings:

```yaml
# minimal-validator.yaml
base:
  role: "validator"
  data_dir: "/opt/aptos/data"
  waypoint:
    from_file: "/opt/aptos/genesis/waypoint.txt"

validator_network:
  discovery_method: "onchain"
  identity:
    type: "from_file"
    path: /opt/aptos/genesis/validator-identity.yaml

execution:
  genesis_file_location: "/opt/aptos/genesis/genesis.blob"
```

**Step 2**: Start validator with this configuration:
```bash
aptos-node -f minimal-validator.yaml
```

**Step 3**: Query the exposed endpoints (from another machine on the network):
```bash
# Get validator identity
curl http://validator-ip:9101/identity_information

# Get complete validator set and network topology
curl http://validator-ip:9101/peer_information

# Get build information and git commit hash
curl http://validator-ip:9101/system_information
```

**Expected Result**: All three endpoints return sensitive information because:
1. The configuration uses default values (all exposure flags true)
2. The sanitizer only checks `expose_configuration`, allowing this through
3. The service binds to `0.0.0.0` by default, making it network-accessible

**Actual Security Guarantee**: Mainnet validators should have minimal information disclosure to prevent reconnaissance attacks on the consensus network.

## Notes

This vulnerability demonstrates a critical gap between intended security (evidenced by the partial sanitizer) and actual implementation (insecure defaults). While production-grade deployment methods (Docker Compose, Kubernetes) provide network-level protections, the code-level defaults remain insecure, creating risk for validators using non-standard deployment methods or misconfigured firewalls.

The exposed information—particularly the complete validator set with network addresses and the current network topology—provides attackers with intelligence necessary for sophisticated attacks on the AptosBFT consensus protocol, including eclipse attacks, targeted denial-of-service, and exploitation of validators running vulnerable software versions.

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

**File:** config/src/config/inspection_service_config.rs (L54-65)
```rust
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

**File:** crates/aptos-inspection-service/src/server/system_information.rs (L31-42)
```rust
/// Returns a simple JSON formatted string with system information
fn get_system_information_json() -> String {
    // Get the system and build information
    let mut system_information = aptos_telemetry::system_information::get_system_information();
    system_information.extend(build_information!());

    // Return the system information as a JSON string
    match serde_json::to_string(&system_information) {
        Ok(system_information) => system_information,
        Err(error) => format!("Failed to get system information! Error: {}", error),
    }
}
```

**File:** crates/aptos-build-info/src/lib.rs (L59-105)
```rust
pub fn get_build_information() -> BTreeMap<String, String> {
    shadow!(build);

    let mut build_information = BTreeMap::new();

    // Get Git metadata from shadow_rs crate.
    // This is applicable for native builds where the cargo has
    // access to the .git directory.
    build_information.insert(BUILD_BRANCH.into(), build::BRANCH.into());
    build_information.insert(BUILD_CARGO_VERSION.into(), build::CARGO_VERSION.into());
    build_information.insert(BUILD_CLEAN_CHECKOUT.into(), build::GIT_CLEAN.to_string());
    build_information.insert(BUILD_COMMIT_HASH.into(), build::COMMIT_HASH.into());
    build_information.insert(BUILD_TAG.into(), build::TAG.into());
    build_information.insert(BUILD_TIME.into(), build::BUILD_TIME.into());
    build_information.insert(BUILD_OS.into(), build::BUILD_OS.into());
    build_information.insert(BUILD_RUST_CHANNEL.into(), build::RUST_CHANNEL.into());
    build_information.insert(BUILD_RUST_VERSION.into(), build::RUST_VERSION.into());

    // Compilation information
    build_information.insert(BUILD_IS_RELEASE_BUILD.into(), is_release().to_string());
    build_information.insert(BUILD_PROFILE_NAME.into(), get_build_profile_name());
    build_information.insert(
        BUILD_USING_TOKIO_UNSTABLE.into(),
        std::env!("USING_TOKIO_UNSTABLE").to_string(),
    );

    // Get Git metadata from environment variables set during build-time.
    // This is applicable for docker based builds  where the cargo cannot
    // access the .git directory, or to override shadow_rs provided info.
    if let Ok(git_sha) = std::env::var("GIT_SHA") {
        build_information.insert(BUILD_COMMIT_HASH.into(), git_sha);
    }

    if let Ok(git_branch) = std::env::var("GIT_BRANCH") {
        build_information.insert(BUILD_BRANCH.into(), git_branch);
    }

    if let Ok(git_tag) = std::env::var("GIT_TAG") {
        build_information.insert(BUILD_TAG.into(), git_tag);
    }

    if let Ok(build_date) = std::env::var("BUILD_DATE") {
        build_information.insert(BUILD_TIME.into(), build_date);
    }

    build_information
}
```

**File:** crates/aptos-inspection-service/src/server/mod.rs (L48-101)
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
                server.await
            })
            .unwrap();
    });
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

**File:** docker/compose/aptos-node/docker-compose-src.yaml (L27-35)
```yaml
    ports:
      # Expose these to the outside
      - "6180:6180"
      - "6181:6181"
      # Preface these with 127 to only expose them locally
      - "127.0.0.1:9101:9101"
      - "127.0.0.1:9102:9102"
      # Disable access to rest API port 80 for validator by default
      # - 8180:8180
```

**File:** terraform/helm/aptos-node/templates/networkpolicy.yaml (L38-46)
```yaml
  # Monitoring metrics port
  - from:
    - namespaceSelector: {}
    - podSelector:
        matchLabels:
          app.kubernetes.io/name: monitoring
    ports:
    - protocol: TCP
      port: 9101
```
