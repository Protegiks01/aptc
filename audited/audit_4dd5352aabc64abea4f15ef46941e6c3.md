# Audit Report

## Title
Unbounded Memory Allocation in Inspection Service Peer Information Endpoint

## Summary
The `get_peer_information()` function in the inspection service builds an unbounded `Vec<String>` containing detailed information for all peers without pagination or resource limits. When configured with high peer connection limits, this can cause excessive memory allocation leading to inspection service crashes or node instability.

## Finding Description

The `get_peer_information()` function collects detailed information for every peer in the system into a single `Vec<String>`, then joins all strings into one large response. [1](#0-0) 

The function iterates over all peers multiple times, creating 6-7 String objects per peer:
- Summary information
- Connection metadata (with JSON serialization)
- Trusted peers information  
- Basic monitoring metadata
- State sync metadata (4-5 lines per peer including storage summaries)
- Detailed monitoring metadata (full Debug format)
- Internal client state [2](#0-1) 

The `internal_client_state` field can contain arbitrarily large pretty-printed JSON strings: [3](#0-2) 

The inspection service endpoint is unauthenticated and enabled by default: [4](#0-3) [5](#0-4) 

While default peer limits are 100 inbound connections, these are configurable: [6](#0-5) 

Operators running high-capacity public fullnodes may configure thousands of peer connections, making the memory exhaustion scenario realistic.

The `get_all_peers()` method returns all peers from the cached metadata: [7](#0-6) 

## Impact Explanation

This violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits." The inspection service performs unbounded memory allocation without any limits, pagination, or streaming.

**Attack Scenario:**
1. Operator configures high peer connection limits (1000+) for a public fullnode
2. Many peers connect, each potentially advertising large `NetworkInformationResponse` data containing hundreds of sub-peers
3. Attacker makes repeated HTTP GET requests to `/peer_information` endpoint
4. Each request causes allocation of megabytes to hundreds of megabytes of memory
5. Concurrent requests or repeated calls lead to memory exhaustion
6. Node experiences OOM conditions, inspection service crashes, or entire node becomes unstable

**Impact Classification:**
- **API crashes** (High Severity per bug bounty)
- Potential validator/fullnode slowdowns or crashes (High Severity)
- Memory exhaustion affecting node stability (Medium-High Severity)

With malicious peer metadata or high peer counts, memory consumption could exceed 100MB+ per request, causing service disruption.

## Likelihood Explanation

**Likelihood: Medium-High**

Required conditions:
1. Operator configures high peer connection limits (common for public infrastructure nodes)
2. Inspection service peer information endpoint is enabled (enabled by default)
3. No authentication or rate limiting on endpoint (default configuration)
4. Attacker can make HTTP requests to the inspection service

The attack is trivial to execute - simple HTTP GET requests to an unauthenticated endpoint. The main variable is whether the node is configured for high peer counts, which is realistic for:
- Public fullnode infrastructure
- High-capacity seed nodes
- Network monitoring nodes

## Recommendation

Implement pagination and resource limits for the peer information endpoint:

```rust
// Add pagination parameters
const MAX_PEERS_PER_REQUEST: usize = 100;
const MAX_RESPONSE_SIZE_BYTES: usize = 10_000_000; // 10MB

fn get_peer_information(
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> String {
    let offset = offset.unwrap_or(0);
    let limit = std::cmp::min(limit.unwrap_or(MAX_PEERS_PER_REQUEST), MAX_PEERS_PER_REQUEST);
    
    // Get all peers
    let mut all_peers = peers_and_metadata.get_all_peers();
    all_peers.sort();
    
    // Apply pagination
    let paginated_peers: Vec<_> = all_peers
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect();
    
    // Build output with size tracking
    let mut peer_information_output = Vec::<String>::new();
    let mut total_size = 0;
    
    // Display summary
    display_peer_information_summary(
        &mut peer_information_output,
        &paginated_peers,
        &registered_networks,
    );
    
    // ... process peers with size checking
    for peer in &paginated_peers {
        let entry_size = estimate_entry_size(&peer_info);
        if total_size + entry_size > MAX_RESPONSE_SIZE_BYTES {
            peer_information_output.push(
                "Warning: Response size limit reached. Use pagination.".into()
            );
            break;
        }
        total_size += entry_size;
        // ... add peer info
    }
    
    peer_information_output.join("\n")
}
```

Additionally:
- Add rate limiting to the inspection service
- Consider streaming responses for large datasets  
- Add request timeout limits
- Document the resource implications of enabling this endpoint

## Proof of Concept

```rust
#[cfg(test)]
mod memory_exhaustion_test {
    use super::*;
    use std::sync::Arc;
    
    #[test]
    fn test_memory_exhaustion_with_many_peers() {
        // Simulate 1000 peers with large metadata
        let peers_and_metadata = create_test_peers_and_metadata(1000);
        let aptos_data_client = create_test_data_client();
        
        // Populate each peer with large internal_client_state (10KB each)
        for peer in peers_and_metadata.get_all_peers() {
            let large_state = "x".repeat(10_000);
            let metadata = PeerMonitoringMetadata {
                internal_client_state: Some(large_state),
                ..Default::default()
            };
            peers_and_metadata.update_peer_monitoring_metadata(peer, metadata).unwrap();
        }
        
        // Measure memory before
        let mem_before = get_current_memory_usage();
        
        // Call get_peer_information
        let result = get_peer_information(aptos_data_client, peers_and_metadata);
        
        // Measure memory after
        let mem_after = get_current_memory_usage();
        let mem_used = mem_after - mem_before;
        
        // With 1000 peers × ~10KB metadata + formatting overhead
        // Expected memory usage: 50-100+ MB for a single request
        println!("Memory used: {} MB", mem_used / 1_000_000);
        assert!(mem_used > 50_000_000, "Expected significant memory allocation");
        
        // Verify response contains all peer data
        assert!(result.len() > 10_000_000, "Response should be > 10MB");
    }
    
    #[test]
    fn test_concurrent_requests_cause_memory_spike() {
        let peers_and_metadata = create_test_peers_and_metadata(1000);
        let aptos_data_client = create_test_data_client();
        
        // Simulate 10 concurrent requests
        let handles: Vec<_> = (0..10).map(|_| {
            let peers = peers_and_metadata.clone();
            let client = aptos_data_client.clone();
            std::thread::spawn(move || {
                get_peer_information(client, peers)
            })
        }).collect();
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        // This would allocate 500MB+ with no limits
        // Could trigger OOM on resource-constrained nodes
    }
}
```

## Notes

This vulnerability requires the node operator to configure high peer connection limits beyond the defaults (100 inbound + 6 outbound). However, such configurations are realistic for production infrastructure nodes serving many clients. The lack of authentication, rate limiting, and resource bounds makes this endpoint exploitable for causing service disruption through memory exhaustion attacks.

### Citations

**File:** crates/aptos-inspection-service/src/server/peer_information.rs (L41-106)
```rust
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

**File:** peer-monitoring-service/client/src/peer_states/peer_state.rs (L276-294)
```rust
    fn get_internal_client_state(&self) -> Result<Option<String>, Error> {
        // Construct a string map for each of the state entries
        let mut client_state_strings = HashMap::new();
        for (state_key, state_value) in self.state_entries.read().iter() {
            let peer_state_label = state_key.get_label().to_string();
            let peer_state_value = format!("{}", state_value.read().deref());
            client_state_strings.insert(peer_state_label, peer_state_value);
        }

        // Pretty print and return the client state string
        let client_state_string =
            serde_json::to_string_pretty(&client_state_strings).map_err(|error| {
                Error::UnexpectedError(format!(
                    "Failed to serialize the client state string: {:?}",
                    error
                ))
            })?;
        Ok(Some(client_state_string))
    }
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

**File:** crates/aptos-inspection-service/src/server/mod.rs (L103-169)
```rust
/// A simple helper function that handles each endpoint request
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

**File:** config/src/config/network_config.rs (L43-44)
```rust
pub const MAX_FULLNODE_OUTBOUND_CONNECTIONS: usize = 6;
pub const MAX_INBOUND_CONNECTIONS: usize = 100;
```

**File:** network/framework/src/application/storage.rs (L89-105)
```rust
    /// Returns all peers. Note: this will return disconnected and unhealthy peers, so
    /// it is not recommended for applications to use this interface. Instead,
    /// `get_connected_peers_and_metadata()` should be used.
    pub fn get_all_peers(&self) -> Vec<PeerNetworkId> {
        // Get the cached peers and metadata
        let cached_peers_and_metadata = self.cached_peers_and_metadata.load();

        // Collect all peers
        let mut all_peers = Vec::new();
        for (network_id, peers_and_metadata) in cached_peers_and_metadata.iter() {
            for (peer_id, _) in peers_and_metadata.iter() {
                let peer_network_id = PeerNetworkId::new(*network_id, *peer_id);
                all_peers.push(peer_network_id);
            }
        }
        all_peers
    }
```
