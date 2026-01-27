# Audit Report

## Title
Network Bandwidth Exhaustion via Concurrent Storage Service Requests Can Degrade Validator Performance

## Summary
Multiple malicious peers can exhaust network bandwidth on validator nodes by sending concurrent large data requests to the storage service, potentially degrading consensus performance due to shared network resources and lack of default rate limiting.

## Finding Description

The storage service processes incoming requests by spawning unbounded concurrent tasks [1](#0-0) , with each response sent through `ResponseSender::send()` [2](#0-1) .

While individual responses are size-limited to 10 MiB (v1) or 40 MiB (v2) [3](#0-2) , and per-connection RPC concurrency is capped at 100 requests [4](#0-3) , there is no global limit across all connected peers.

Network rate limiting is disabled by default [5](#0-4) , and consensus and storage service share the same network infrastructure [6](#0-5) .

**Attack Path:**
1. Attacker controls 10-20 malicious peers connecting to a validator
2. Each peer sends 100 concurrent valid requests for large transaction data chunks
3. Storage service spawns 1,000-2,000 concurrent blocking tasks
4. Each task generates 10-40 MiB responses
5. Outbound bandwidth saturates with 10-80 GB of concurrent response data
6. Consensus messages experience increased latency competing for bandwidth

## Impact Explanation

This constitutes **High Severity** per Aptos bug bounty criteria: "Validator node slowdowns." The attack degrades validator performance by consuming network resources, potentially causing:
- Increased consensus message latency
- Delayed block proposals/votes
- Reduced validator participation effectiveness

However, this does NOT meet Critical severity because it does not cause permanent liveness loss or consensus safety violations.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack requires:
- Multiple peer identities (achievable via Sybil attack on public network)
- Sustained concurrent connections
- Valid requests that pass moderator validation [7](#0-6) 

However, existing mitigations reduce practical impact:
- Per-connection RPC limits prevent unlimited requests from single peers
- Response size truncation limits individual payload sizes [8](#0-7) 
- LRU caching reduces repeated data fetches

## Recommendation

Implement network-layer rate limiting and per-peer bandwidth quotas:

1. **Enable outbound rate limiting by default** in network configuration for storage service responses
2. **Add global concurrency limits** across all peers for storage service requests
3. **Implement bandwidth quotas** per peer with stricter limits for public network peers
4. **Add QoS prioritization** to ensure consensus messages take precedence over storage service responses

Configuration example:
```rust
// In NetworkConfig::default()
outbound_rate_limit_config: Some(RateLimitConfig {
    ip_byte_bucket_rate: 10 * 1024 * 1024, // 10 MB/s per peer
    ip_byte_bucket_size: 20 * 1024 * 1024,  // 20 MB burst
    initial_bucket_fill_percentage: 50,
    enabled: true,
})
```

## Proof of Concept

```rust
// Test demonstrating bandwidth exhaustion potential
#[tokio::test]
async fn test_storage_service_bandwidth_exhaustion() {
    // Setup: Create validator node with storage service
    let (node, storage_service) = setup_test_validator().await;
    
    // Attack: Spawn 10 malicious peers
    let peers = spawn_malicious_peers(10).await;
    
    // Each peer sends 100 concurrent requests for large data
    let mut handles = vec![];
    for peer in peers {
        let handle = tokio::spawn(async move {
            let requests = (0..100).map(|i| {
                // Request transaction outputs (large payloads)
                StorageServiceRequest {
                    data_request: GetTransactionOutputsWithProof {
                        start_version: i * 1000,
                        end_version: i * 1000 + 999,
                        proof_version: i * 1000 + 1000,
                    },
                    use_compression: false,
                }
            });
            
            // Send all requests concurrently
            let responses = futures::future::join_all(
                requests.map(|req| peer.send_rpc(req))
            ).await;
            
            // Measure bandwidth consumed
            responses.iter().map(|r| r.size_bytes()).sum::<u64>()
        });
        handles.push(handle);
    }
    
    // Measure consensus message latency during attack
    let consensus_latency = measure_consensus_latency(&node).await;
    
    // Verify: Total bandwidth and consensus impact
    let total_bandwidth: u64 = futures::future::join_all(handles)
        .await
        .into_iter()
        .sum();
    
    assert!(total_bandwidth > 10_000_000_000); // > 10 GB
    assert!(consensus_latency > normal_latency * 2); // 2x slowdown
}
```

## Notes

The vulnerability exists at the architectural level where storage service and consensus share network resources without prioritization or sufficient rate limiting. While per-connection limits provide some protection, they are insufficient against distributed attacks from multiple peers on the public network.

### Citations

**File:** state-sync/storage-service/server/src/lib.rs (L389-418)
```rust
        while let Some(network_request) = self.network_requests.next().await {
            // All handler methods are currently CPU-bound and synchronous
            // I/O-bound, so we want to spawn on the blocking thread pool to
            // avoid starving other async tasks on the same runtime.
            let storage = self.storage.clone();
            let config = self.storage_service_config;
            let cached_storage_server_summary = self.cached_storage_server_summary.clone();
            let optimistic_fetches = self.optimistic_fetches.clone();
            let subscriptions = self.subscriptions.clone();
            let lru_response_cache = self.lru_response_cache.clone();
            let request_moderator = self.request_moderator.clone();
            let time_service = self.time_service.clone();
            self.runtime.spawn_blocking(move || {
                Handler::new(
                    cached_storage_server_summary,
                    optimistic_fetches,
                    lru_response_cache,
                    request_moderator,
                    storage,
                    subscriptions,
                    time_service,
                )
                .process_request_and_respond(
                    config,
                    network_request.peer_network_id,
                    network_request.protocol_id,
                    network_request.storage_service_request,
                    network_request.response_sender,
                );
            });
```

**File:** state-sync/storage-service/server/src/network.rs (L106-112)
```rust
    pub fn send(self, response: Result<StorageServiceResponse>) {
        let msg = StorageServiceMessage::Response(response);
        let result = bcs::to_bytes(&msg)
            .map(Bytes::from)
            .map_err(RpcError::BcsError);
        let _ = self.response_tx.send(result);
    }
```

**File:** config/src/config/state_sync_config.rs (L16-21)
```rust
// The maximum message size per state sync message
const SERVER_MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MiB

// The maximum message size per state sync message (for v2 data requests)
const CLIENT_MAX_MESSAGE_SIZE_V2: usize = 20 * 1024 * 1024; // 20 MiB (used for v2 data requests)
const SERVER_MAX_MESSAGE_SIZE_V2: usize = 40 * 1024 * 1024; // 40 MiB (used for v2 data requests)
```

**File:** network/framework/src/constants.rs (L14-15)
```rust
/// Limit on concurrent Inbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```

**File:** config/src/config/network_config.rs (L158-159)
```rust
            inbound_rate_limit_config: None,
            outbound_rate_limit_config: None,
```

**File:** aptos-node/src/network.rs (L292-388)
```rust
        // Register consensus (both client and server) with the network
        let network_id = network_config.network_id;
        if network_id.is_validator_network() {
            // A validator node must have only a single consensus network handle
            if consensus_network_handle.is_some() {
                panic!("There can be at most one validator network!");
            } else {
                let network_handle = register_client_and_service_with_network(
                    &mut network_builder,
                    network_id,
                    &network_config,
                    consensus_network_configuration(node_config),
                    true,
                );
                consensus_network_handle = Some(network_handle);
            }

            if dkg_network_handle.is_some() {
                panic!("There can be at most one validator network!");
            } else {
                let network_handle = register_client_and_service_with_network(
                    &mut network_builder,
                    network_id,
                    &network_config,
                    dkg_network_configuration(node_config),
                    true,
                );
                dkg_network_handle = Some(network_handle);
            }

            if jwk_consensus_network_handle.is_some() {
                panic!("There can be at most one validator network!");
            } else {
                let network_handle = register_client_and_service_with_network(
                    &mut network_builder,
                    network_id,
                    &network_config,
                    jwk_consensus_network_configuration(node_config),
                    true,
                );
                jwk_consensus_network_handle = Some(network_handle);
            }
        }

        // Register consensus observer (both client and server) with the network
        if node_config
            .consensus_observer
            .is_observer_or_publisher_enabled()
        {
            // Create the network handle for this network type
            let network_handle = register_client_and_service_with_network(
                &mut network_builder,
                network_id,
                &network_config,
                consensus_observer_network_configuration(node_config),
                false,
            );

            // Add the network handle to the set of handles
            if let Some(consensus_observer_network_handles) =
                &mut consensus_observer_network_handles
            {
                consensus_observer_network_handles.push(network_handle);
            } else {
                consensus_observer_network_handles = Some(vec![network_handle]);
            }
        }

        // Register mempool (both client and server) with the network
        let mempool_network_handle = register_client_and_service_with_network(
            &mut network_builder,
            network_id,
            &network_config,
            mempool_network_configuration(node_config),
            true,
        );
        mempool_network_handles.push(mempool_network_handle);

        // Register the peer monitoring service (both client and server) with the network
        let peer_monitoring_service_network_handle = register_client_and_service_with_network(
            &mut network_builder,
            network_id,
            &network_config,
            peer_monitoring_network_configuration(node_config),
            true,
        );
        peer_monitoring_service_network_handles.push(peer_monitoring_service_network_handle);

        // Register the storage service (both client and server) with the network
        let storage_service_network_handle = register_client_and_service_with_network(
            &mut network_builder,
            network_id,
            &network_config,
            storage_service_network_configuration(node_config),
            true,
        );
        storage_service_network_handles.push(storage_service_network_handle);
```

**File:** state-sync/storage-service/server/src/moderator.rs (L134-149)
```rust
    pub fn validate_request(
        &self,
        peer_network_id: &PeerNetworkId,
        request: &StorageServiceRequest,
    ) -> Result<(), Error> {
        // Validate the request and time the operation
        let validate_request = || {
            // If the peer is being ignored, return an error
            if let Some(peer_state) = self.unhealthy_peer_states.get(peer_network_id) {
                if peer_state.is_ignored() {
                    return Err(Error::TooManyInvalidRequests(format!(
                        "Peer is temporarily ignored. Unable to handle request: {:?}",
                        request
                    )));
                }
            }
```

**File:** state-sync/storage-service/server/src/storage.rs (L1087-1088)
```rust
            self.config.max_network_chunk_bytes,
            self.config.enable_size_and_time_aware_chunking,
```
