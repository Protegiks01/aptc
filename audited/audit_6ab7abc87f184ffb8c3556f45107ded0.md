# Audit Report

## Title
Node Fingerprinting via Unrestricted GetNodeInformation Responses Enables Targeted Exploitation

## Summary
The peer monitoring service exposes detailed build information (commit hash, version, build time, OS, uptime) to any connected peer without authentication or rate limiting, enabling attackers to fingerprint nodes and identify targets running vulnerable software versions for targeted attacks.

## Finding Description

The `GetNodeInformation` RPC endpoint in the peer monitoring service returns comprehensive build metadata to any peer that requests it. [1](#0-0)  The response includes a `build_information` field populated by `aptos_build_info::get_build_information()`, which exposes: [2](#0-1) 

This information includes the exact commit hash, git branch, tag/version, build timestamp, operating system, Rust version, and whether it's a release build. Additionally, the response includes node uptime.

**Attack Path:**

1. **No Access Control**: The peer monitoring service is registered on all network types (validator and full node networks). [3](#0-2) 

2. **Public Network Exposure**: Full node networks use "maybe mutual" authentication that accepts connections from any peer. [4](#0-3) 

3. **No Request Authentication**: The `get_node_information()` handler returns build information to any requesting peer without checking peer identity or trust level. [5](#0-4) 

4. **Insufficient Rate Limiting**: Only global concurrency limits exist (`max_concurrent_requests: 1000`), with no per-peer throttling. [6](#0-5) 

**Exploitation Scenario:**
- Attacker connects as a peer to multiple Aptos nodes (full nodes accept any connection)
- Sends `GetNodeInformation` requests to enumerate versions across the network
- Identifies nodes running specific vulnerable versions (by exact commit hash)
- Launches targeted exploits against identified vulnerable nodes
- Monitors uptime to track patch deployment timing

**Contrast with Inspection Service**: The inspection service provides similar information via HTTP but includes a configuration flag to disable exposure. [7](#0-6)  The peer monitoring service has no such protection.

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria as it enables reconnaissance that facilitates more serious attacks:

- **Targeted Exploitation**: Attackers can identify nodes running versions with known vulnerabilities (CVEs) and target them specifically
- **Attack Surface Mapping**: Precise version information allows attackers to prepare exploits for the exact codebase being run
- **Patch Deployment Tracking**: Uptime monitoring reveals when nodes restart (likely after patching), helping attackers identify unpatched nodes
- **Network-Wide Impact**: Affects all public full nodes, which constitute the majority of the Aptos network

While this doesn't directly cause fund loss or consensus violations, it materially increases the likelihood and effectiveness of such attacks by enabling precise targeting. This violates defense-in-depth principles by unnecessarily exposing sensitive operational information to untrusted parties.

## Likelihood Explanation

**High Likelihood** - The attack is trivial to execute:
- No special privileges required (just peer connectivity)
- No cryptographic breaks needed
- Simple RPC call with guaranteed response
- Scalable across thousands of nodes
- Difficult to detect or prevent with current architecture

Attackers routinely perform network reconnaissance. Version fingerprinting is a standard first step in exploit development and deployment.

## Recommendation

Implement multi-layered protections:

1. **Add Configuration Flag**: Similar to `expose_system_information` in inspection service, add `expose_node_information_to_untrusted_peers` config (default: false)

2. **Implement Per-Peer Rate Limiting**: Add token bucket rate limiter per peer for GetNodeInformation requests

3. **Sanitize Responses**: For untrusted peers, return only high-level version info (e.g., major.minor) without commit hash or build timestamp

4. **Network-Based Access Control**: Restrict detailed build information to validator networks only

**Code Fix Example** (in `peer-monitoring-service/server/src/lib.rs`):

```rust
fn get_node_information(&self, peer_network_id: PeerNetworkId) -> Result<PeerMonitoringServiceResponse, Error> {
    let build_information = if self.should_expose_detailed_build_info(peer_network_id) {
        aptos_build_info::get_build_information()
    } else {
        self.get_sanitized_build_information()
    };
    // ... rest of implementation
}

fn should_expose_detailed_build_info(&self, peer_network_id: PeerNetworkId) -> bool {
    // Only expose to trusted peers on validator networks
    peer_network_id.network_id().is_validator_network() &&
    self.peers_and_metadata.is_trusted_peer(peer_network_id)
}
```

## Proof of Concept

```rust
// Rust client demonstrating the vulnerability
use aptos_network::ProtocolId;
use aptos_peer_monitoring_service_types::{
    request::PeerMonitoringServiceRequest,
    response::PeerMonitoringServiceResponse,
};

async fn fingerprint_node(target_peer: PeerNetworkId) -> Result<NodeInformationResponse> {
    // Connect to target node as a peer
    let network_client = setup_network_connection(target_peer).await?;
    
    // Send GetNodeInformation request
    let request = PeerMonitoringServiceRequest::GetNodeInformation;
    let response = network_client
        .send_rpc_request(
            target_peer,
            ProtocolId::PeerMonitoringServiceRpc,
            bcs::to_bytes(&request)?,
            Duration::from_secs(10),
        )
        .await?;
    
    // Extract build information
    let node_info: NodeInformationResponse = bcs::from_bytes(&response)?;
    
    println!("Target Node Version Info:");
    println!("  Commit Hash: {}", node_info.build_information.get("build_commit_hash"));
    println!("  Build Tag: {}", node_info.build_information.get("build_tag"));
    println!("  Build Time: {}", node_info.build_information.get("build_time"));
    println!("  Uptime: {:?}", node_info.uptime);
    
    // Check against known vulnerable versions
    if is_vulnerable_version(&node_info.build_information) {
        println!("⚠️ Node is running vulnerable version - launching exploit...");
        launch_targeted_exploit(target_peer, &node_info).await?;
    }
    
    Ok(node_info)
}
```

**Notes:**
- This vulnerability enables reconnaissance for more sophisticated attacks
- The exposed information materially increases attack success rates
- No mitigations exist in current implementation
- Affects network-wide security posture by enabling targeted exploitation

### Citations

**File:** peer-monitoring-service/types/src/response.rs (L93-102)
```rust
/// A response for the node information request
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeInformationResponse {
    pub build_information: BTreeMap<String, String>, // The build information of the node
    pub highest_synced_epoch: u64,                   // The highest synced epoch of the node
    pub highest_synced_version: u64,                 // The highest synced version of the node
    pub ledger_timestamp_usecs: u64, // The latest timestamp of the blockchain (in microseconds)
    pub lowest_available_version: u64, // The lowest stored version of the node (in storage)
    pub uptime: Duration,            // The amount of time the peer has been running
}
```

**File:** crates/aptos-build-info/src/lib.rs (L59-104)
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
```

**File:** aptos-node/src/network.rs (L217-228)
```rust
/// Extracts all network configs from the given node config
fn extract_network_configs(node_config: &NodeConfig) -> Vec<NetworkConfig> {
    let mut network_configs: Vec<NetworkConfig> = node_config.full_node_networks.to_vec();
    if let Some(network_config) = node_config.validator_network.as_ref() {
        // Ensure that mutual authentication is enabled by default!
        if !network_config.mutual_authentication {
            panic!("Validator networks must always have mutual_authentication enabled!");
        }
        network_configs.push(network_config.clone());
    }
    network_configs
}
```

**File:** aptos-node/src/network.rs (L370-378)
```rust
        // Register the peer monitoring service (both client and server) with the network
        let peer_monitoring_service_network_handle = register_client_and_service_with_network(
            &mut network_builder,
            network_id,
            &network_config,
            peer_monitoring_network_configuration(node_config),
            true,
        );
        peer_monitoring_service_network_handles.push(peer_monitoring_service_network_handle);
```

**File:** peer-monitoring-service/server/src/lib.rs (L259-281)
```rust
    fn get_node_information(&self) -> Result<PeerMonitoringServiceResponse, Error> {
        // Get the node information
        let build_information = aptos_build_info::get_build_information();
        let current_time: Instant = self.time_service.now();
        let uptime = current_time.duration_since(self.start_time);
        let (highest_synced_epoch, highest_synced_version) =
            self.storage.get_highest_synced_epoch_and_version()?;
        let ledger_timestamp_usecs = self.storage.get_ledger_timestamp_usecs()?;
        let lowest_available_version = self.storage.get_lowest_available_version()?;

        // Create and return the response
        let node_information_response = NodeInformationResponse {
            build_information,
            highest_synced_epoch,
            highest_synced_version,
            ledger_timestamp_usecs,
            lowest_available_version,
            uptime,
        };
        Ok(PeerMonitoringServiceResponse::NodeInformation(
            node_information_response,
        ))
    }
```

**File:** config/src/config/peer_monitoring_config.rs (L21-36)
```rust
impl Default for PeerMonitoringServiceConfig {
    fn default() -> Self {
        Self {
            enable_peer_monitoring_client: true,
            latency_monitoring: LatencyMonitoringConfig::default(),
            max_concurrent_requests: 1000,
            max_network_channel_size: 1000,
            max_num_response_bytes: 100 * 1024, // 100 KB
            max_request_jitter_ms: 1000,        // Monitoring requests are very infrequent
            metadata_update_interval_ms: 5000,  // 5 seconds
            network_monitoring: NetworkMonitoringConfig::default(),
            node_monitoring: NodeMonitoringConfig::default(),
            peer_monitor_interval_usec: 1_000_000, // 1 second
        }
    }
}
```

**File:** crates/aptos-inspection-service/src/server/system_information.rs (L14-29)
```rust
pub fn handle_system_information_request(node_config: NodeConfig) -> (StatusCode, Body, String) {
    // Only return system information if the endpoint is enabled
    if node_config.inspection_service.expose_system_information {
        (
            StatusCode::OK,
            Body::from(get_system_information_json()),
            CONTENT_TYPE_JSON.into(),
        )
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(SYS_INFO_DISABLED_MESSAGE),
            CONTENT_TYPE_TEXT.into(),
        )
    }
}
```
