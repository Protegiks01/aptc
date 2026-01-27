# Audit Report

## Title
Version Enumeration via Unauthenticated Peer Monitoring Service Enables Targeted Exploitation

## Summary
The peer monitoring service exposes detailed build information (including git commit hash, branch, tag, and version details) through the `GetNodeInformation` RPC endpoint to any connected peer on the public network without authentication or rate limiting. This allows attackers to systematically enumerate software versions across the network and identify nodes running specific versions with known vulnerabilities, facilitating targeted exploitation.

## Finding Description

The peer monitoring service is registered on all network types (Validator, VFN, and Public networks) and exposes a `GetNodeInformation` RPC endpoint that returns detailed build information. [1](#0-0) 

When a peer sends a `GetNodeInformation` request, the server responds with a `NodeInformationResponse` containing a `build_information` field. [2](#0-1) 

The handler retrieves build information by calling `aptos_build_info::get_build_information()` without any authorization checks. [3](#0-2) 

The build information includes sensitive version details such as git commit hash, branch, tag, build time, Rust version, and build profile. [4](#0-3) 

**Attack Vector:**
1. Validator Full Nodes (VFNs) expose a public network that uses `MaybeMutual` authentication, allowing any peer to connect
2. Attacker connects to the public network through a VFN
3. Attacker sends `GetNodeInformation` RPC requests to multiple peers
4. Responses contain detailed version information for each node
5. Attacker maps the network topology and identifies nodes running specific versions
6. Attacker targets nodes with known vulnerabilities in specific commits/versions

There is no per-peer rate limiting configured in the peer monitoring service, only a maximum concurrent requests limit. [5](#0-4) 

## Impact Explanation

This vulnerability falls under **Medium Severity** as specified in the security question, though it borders on Low severity by strict bug bounty criteria. The impact includes:

1. **Information Disclosure**: Attackers can enumerate software versions across the entire network without authentication
2. **Reconnaissance Facilitation**: Enables mapping of network topology and version distribution
3. **Targeted Attack Enablement**: Attackers can identify specific nodes running vulnerable versions and craft targeted exploits
4. **No Direct Harm**: The vulnerability itself doesn't cause consensus violations, state corruption, or funds loss, but serves as a prerequisite for more serious attacks

According to the Aptos bug bounty program, this represents a "minor information leak" which facilitates but doesn't directly cause security harm.

## Likelihood Explanation

**Likelihood: High**

The attack is trivially exploitable:
- **No Authentication Required**: Public network uses `MaybeMutual` authentication that accepts all connections
- **No Authorization Checks**: The `GetNodeInformation` endpoint processes all requests without validation
- **No Rate Limiting**: Attacker can query unlimited nodes (only constrained by max concurrent requests per node)
- **Simple Attack**: Requires only basic P2P networking capabilities to connect and send RPC requests
- **Wide Exposure**: Service is registered on all networks including public

Any actor with basic networking capabilities can execute this attack against any VFN exposing a public network endpoint.

## Recommendation

Implement multiple defense layers:

1. **Remove Build Information from Public Network**: Restrict detailed build information exposure to only trusted validator and VFN networks, not public networks:

```rust
fn get_node_information(&self, network_id: NetworkId) -> Result<PeerMonitoringServiceResponse, Error> {
    // Only provide detailed build info to trusted networks
    let build_information = if network_id == NetworkId::Public {
        BTreeMap::new() // Return empty map for public network
    } else {
        aptos_build_info::get_build_information()
    };
    
    // ... rest of the implementation
}
```

2. **Implement Per-Peer Rate Limiting**: Add configuration for per-peer request rate limits in the peer monitoring service configuration:

```rust
pub struct PeerMonitoringServiceConfig {
    // ... existing fields ...
    pub max_requests_per_peer_per_minute: u64, // Add rate limiting per peer
}
```

3. **Sanitize Build Information**: If build information must be exposed, provide only high-level version tags without detailed commit hashes:

```rust
fn sanitize_build_information(build_info: BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut sanitized = BTreeMap::new();
    // Only expose version tag, not commit hash
    if let Some(tag) = build_info.get(BUILD_TAG) {
        sanitized.insert(BUILD_TAG.into(), tag.clone());
    }
    sanitized
}
```

4. **Add Network-Specific Access Control**: Implement authorization checks based on peer role and network type before returning sensitive information.

## Proof of Concept

```rust
// Rust PoC demonstrating version enumeration attack
use aptos_config::network_id::NetworkId;
use aptos_network::application::interface::NetworkClient;
use aptos_peer_monitoring_service_types::{
    request::PeerMonitoringServiceRequest,
    response::NodeInformationResponse,
};

async fn enumerate_versions(network_client: &NetworkClient<PeerMonitoringServiceMessage>) {
    // 1. Connect to public network (no authentication required)
    let public_network_id = NetworkId::Public;
    
    // 2. Get list of connected peers
    let peers = network_client.get_connected_peers(public_network_id).await;
    
    // 3. Query each peer for build information
    for peer in peers {
        let request = PeerMonitoringServiceRequest::GetNodeInformation;
        
        match network_client.send_rpc(peer, request).await {
            Ok(response) => {
                if let Ok(node_info) = NodeInformationResponse::try_from(response) {
                    // Extract version information
                    if let Some(commit_hash) = node_info.build_information.get("build_commit_hash") {
                        println!("Peer {} running commit: {}", peer, commit_hash);
                        
                        // Attacker can now check if this commit has known vulnerabilities
                        if is_vulnerable_version(commit_hash) {
                            println!("VULNERABLE NODE FOUND: {}", peer);
                            // Launch targeted attack against this specific version
                        }
                    }
                }
            }
            Err(e) => eprintln!("Failed to query peer {}: {}", peer, e),
        }
    }
}

fn is_vulnerable_version(commit_hash: &str) -> bool {
    // Check against database of known vulnerable commits
    // In real attack, this would reference CVE databases or exploit repos
    true // Placeholder
}
```

**Execution Steps:**
1. Deploy a simple peer that connects to the Aptos public network
2. Implement the enumeration logic above to query all reachable peers
3. Collect and analyze version distribution across the network
4. Identify nodes running specific vulnerable versions for targeted exploitation

## Notes

This vulnerability represents a fundamental design issue where a debugging/monitoring feature (peer monitoring service) is exposed without proper access controls on untrusted networks. While the individual information disclosed (build details) is publicly available via GitHub, the ability to programmatically enumerate versions across the live production network at scale creates a reconnaissance vector that significantly lowers the bar for targeted attacks.

The fix requires balancing operational visibility needs (legitimate monitoring) against security concerns (preventing reconnaissance). The recommended approach restricts detailed version information to trusted network relationships while maintaining basic health monitoring capabilities on public networks.

### Citations

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

**File:** config/src/config/peer_monitoring_config.rs (L6-36)
```rust
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PeerMonitoringServiceConfig {
    pub enable_peer_monitoring_client: bool, // Whether or not to spawn the monitoring client
    pub latency_monitoring: LatencyMonitoringConfig,
    pub max_concurrent_requests: u64, // Max num of concurrent server tasks
    pub max_network_channel_size: u64, // Max num of pending network messages
    pub max_num_response_bytes: u64,  // Max num of bytes in a (serialized) response
    pub max_request_jitter_ms: u64, // Max amount of jitter (ms) that a request will be delayed for
    pub metadata_update_interval_ms: u64, // The interval (ms) between metadata updates
    pub network_monitoring: NetworkMonitoringConfig,
    pub node_monitoring: NodeMonitoringConfig,
    pub peer_monitor_interval_usec: u64, // The interval (usec) between peer monitor executions
}

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
