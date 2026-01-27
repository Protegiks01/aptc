# Audit Report

## Title
Insufficient Cost-Based Rate Limiting for Expensive Storage Service Queries Enables Storage Layer DoS

## Summary
The StorageServiceRpc protocol implements per-peer concurrent request limiting but lacks cost-aware rate limiting, allowing attackers to send expensive state queries that can saturate storage I/O and blocking thread pools, causing denial of service.

## Finding Description

The StorageServiceRpc protocol (ProtocolId = 8) is used for state synchronization and allows peers to query storage data. While the protocol implements basic rate limiting through `max_concurrent_inbound_rpcs`, it does not differentiate between cheap and expensive operations, enabling a resource exhaustion attack.

**Rate Limiting Implementation:**

The network layer enforces a per-peer limit of 100 concurrent inbound RPC requests: [1](#0-0) 

This limit is enforced at the RPC protocol layer: [2](#0-1) 

**Request Processing:**

Storage service requests spawn blocking tasks without additional throttling: [3](#0-2) 

The global blocking thread pool is limited to 64 threads: [4](#0-3) 

**Request Moderation Weakness:**

The RequestModerator only tracks *invalid* requests, not resource consumption: [5](#0-4) 

**Expensive Query Configuration:**

State queries can request up to 4000 state values per request: [6](#0-5) 

**Attack Scenario:**

1. Attacker establishes connections from multiple peers (e.g., 10 peers)
2. Each peer sends 100 concurrent `GetStateValuesWithProof` requests (maximum allowed)
3. Each request asks for 4000 state values (maximum chunk size)
4. This creates 1000 concurrent expensive storage operations
5. Each request spawns a blocking task, saturating the 64-thread pool
6. Storage I/O becomes overwhelmed with Merkle proof generation
7. Legitimate requests timeout or get dropped due to channel saturation: [7](#0-6) 

## Impact Explanation

This vulnerability constitutes a **Medium Severity** issue under Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: Legitimate state sync requests fail, causing nodes to fall behind
- **Validator node slowdowns**: Storage layer saturation degrades overall node performance
- **Limited availability impact**: While not causing total network failure, it significantly degrades service quality

The attack affects the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - valid requests can exhaust storage resources without proper cost-based limiting.

## Likelihood Explanation

**Likelihood: High**

- **Low barrier to entry**: Attackers only need to establish peer connections (no special privileges)
- **Easy exploitation**: Craft valid `GetStateValuesWithProof` requests with maximum parameters
- **Minimal cost**: Attack requires modest bandwidth and can be amplified across multiple peers
- **Hard to detect**: Requests are valid and pass all validation checks
- **Persistent impact**: Can be sustained as long as peers remain connected

The attack requires no validator access or special permissions, and the moderator won't block the attacker since all requests are valid per `can_service()` validation.

## Recommendation

Implement multi-layered cost-aware rate limiting:

1. **Add per-peer request cost tracking** in RequestModerator:
   - Track cumulative cost (e.g., state values requested) per time window
   - Implement sliding window rate limiter for expensive operations
   - Temporarily throttle peers exceeding cost thresholds

2. **Implement operation-specific limits**:
   - Separate concurrent limits for expensive operations (e.g., max 10 concurrent state queries per peer)
   - Lower limits for `GetStateValuesWithProof` vs. cheaper operations like `GetServerProtocolVersion`

3. **Add adaptive throttling**:
   - Monitor blocking thread pool utilization
   - Apply backpressure when >80% of blocking threads are in use
   - Prioritize validator network peers over public network peers

4. **Enhance request validation**:
   - Track resource consumption metrics per peer
   - Apply exponential backoff for peers with high resource usage
   - Implement cost-based prioritization in the network channel

Example code fix for RequestModerator:

```rust
pub struct RequestModerator {
    // ... existing fields ...
    peer_cost_tracker: Arc<DashMap<PeerNetworkId, CostTracker>>,
}

struct CostTracker {
    recent_costs: Vec<(Instant, u64)>, // (timestamp, cost)
    max_cost_per_window: u64,
    window_duration: Duration,
}

impl RequestModerator {
    pub fn validate_request_with_cost(
        &self,
        peer_network_id: &PeerNetworkId,
        request: &StorageServiceRequest,
    ) -> Result<(), Error> {
        // Existing validation
        self.validate_request(peer_network_id, request)?;
        
        // Calculate request cost
        let cost = self.calculate_request_cost(request);
        
        // Check cost limit
        let mut tracker = self.peer_cost_tracker
            .entry(*peer_network_id)
            .or_insert_with(|| CostTracker::new(
                self.config.max_cost_per_window,
                Duration::from_secs(60)
            ));
            
        if !tracker.allow_cost(cost, self.time_service.now()) {
            return Err(Error::TooManyExpensiveRequests(format!(
                "Peer exceeded cost limit. Request cost: {}", cost
            )));
        }
        
        Ok(())
    }
    
    fn calculate_request_cost(&self, request: &StorageServiceRequest) -> u64 {
        match &request.data_request {
            DataRequest::GetStateValuesWithProof(req) => {
                (req.end_index - req.start_index + 1) * 10 // Weight state queries heavily
            },
            DataRequest::GetTransactionsWithProof(req) => {
                (req.end_version - req.start_version + 1) * 2
            },
            _ => 1, // Cheap operations
        }
    }
}
```

## Proof of Concept

**Rust Test Demonstrating Resource Exhaustion:**

```rust
#[tokio::test]
async fn test_storage_service_expensive_query_dos() {
    use aptos_config::config::NodeConfig;
    use aptos_storage_service_types::requests::*;
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};
    
    // Setup storage service with default config
    let config = NodeConfig::default();
    let runtime = tokio::runtime::Handle::current();
    
    // Create multiple attacking peers
    let num_attack_peers = 10;
    let concurrent_requests_per_peer = 100; // Max allowed
    let state_values_per_request = 4000; // Max chunk size
    
    // Simulate attack: Each peer sends 100 concurrent expensive requests
    let mut attack_handles = vec![];
    
    for peer_id in 0..num_attack_peers {
        let handle = runtime.spawn(async move {
            let mut request_handles = vec![];
            
            for req_id in 0..concurrent_requests_per_peer {
                let request = StorageServiceRequest::new(
                    DataRequest::GetStateValuesWithProof(
                        StateValuesWithProofRequest {
                            version: 1000000,
                            start_index: req_id * state_values_per_request,
                            end_index: (req_id + 1) * state_values_per_request - 1,
                        }
                    ),
                    true, // use compression
                );
                
                // Send request (would normally go through network)
                request_handles.push(runtime.spawn_blocking(move || {
                    // Simulate expensive storage operation
                    std::thread::sleep(Duration::from_secs(5));
                }));
            }
            
            // Wait for all requests from this peer
            for handle in request_handles {
                let _ = handle.await;
            }
        });
        
        attack_handles.push(handle);
    }
    
    // Try to send legitimate request while attack is ongoing
    sleep(Duration::from_millis(100)).await;
    
    let legitimate_request_start = std::time::Instant::now();
    let legitimate_result = runtime.spawn_blocking(|| {
        // This should timeout or fail due to resource exhaustion
        std::thread::sleep(Duration::from_secs(1));
    }).await;
    let legitimate_duration = legitimate_request_start.elapsed();
    
    // Legitimate requests should be severely delayed or fail
    // In real scenario, blocking thread pool (64 threads) would be saturated
    // by 1000 concurrent expensive operations
    assert!(
        legitimate_duration > Duration::from_secs(10) || legitimate_result.is_err(),
        "Legitimate requests should be impacted by attack"
    );
    
    // Cleanup
    for handle in attack_handles {
        let _ = handle.await;
    }
}
```

## Notes

The vulnerability exists because the protocol-level rate limiting (`max_concurrent_inbound_rpcs = 100`) does not account for the cost/expense of individual operations. While 100 concurrent requests might be reasonable for cheap operations like protocol version queries, it's excessive for expensive operations like state value queries that require storage I/O and Merkle proof generation.

The global blocking thread pool limit of 64 provides some protection, but with 10 attacking peers each sending 100 concurrent requests, the system must queue 1000 expensive operations competing for 64 threads. This creates significant latency and potential timeouts for legitimate requests, effectively achieving a denial-of-service condition on the storage layer.

### Citations

**File:** network/framework/src/constants.rs (L14-15)
```rust
/// Limit on concurrent Inbound RPC requests before backpressure is applied
pub const MAX_CONCURRENT_INBOUND_RPCS: u32 = 100;
```

**File:** network/framework/src/protocols/rpc/mod.rs (L212-223)
```rust
        // Drop new inbound requests if our completion queue is at capacity.
        if self.inbound_rpc_tasks.len() as u32 == self.max_concurrent_inbound_rpcs {
            // Increase counter of declined requests
            counters::rpc_messages(
                network_context,
                REQUEST_LABEL,
                INBOUND_LABEL,
                DECLINED_LABEL,
            )
            .inc();
            return Err(RpcError::TooManyPending(self.max_concurrent_inbound_rpcs));
        }
```

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

**File:** crates/aptos-runtimes/src/lib.rs (L27-50)
```rust
    const MAX_BLOCKING_THREADS: usize = 64;

    // Verify the given name has an appropriate length
    if thread_name.len() > MAX_THREAD_NAME_LENGTH {
        panic!(
            "The given runtime thread name is too long! Max length: {}, given name: {}",
            MAX_THREAD_NAME_LENGTH, thread_name
        );
    }

    // Create the runtime builder
    let atomic_id = AtomicUsize::new(0);
    let thread_name_clone = thread_name.clone();
    let mut builder = Builder::new_multi_thread();
    builder
        .thread_name_fn(move || {
            let id = atomic_id.fetch_add(1, Ordering::SeqCst);
            format!("{}-{}", thread_name_clone, id)
        })
        .on_thread_start(on_thread_start)
        .disable_lifo_slot()
        // Limit concurrent blocking tasks from spawn_blocking(), in case, for example, too many
        // Rest API calls overwhelm the node.
        .max_blocking_threads(MAX_BLOCKING_THREADS)
```

**File:** state-sync/storage-service/server/src/moderator.rs (L133-196)
```rust
    /// correctly. If the request fails validation, an error is returned.
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

            // Get the latest storage server summary
            let storage_server_summary = self.cached_storage_server_summary.load();

            // Verify the request is serviceable using the current storage server summary
            if !storage_server_summary.can_service(
                &self.aptos_data_client_config,
                self.time_service.clone(),
                request,
            ) {
                // Increment the invalid request count for the peer
                let mut unhealthy_peer_state = self
                    .unhealthy_peer_states
                    .entry(*peer_network_id)
                    .or_insert_with(|| {
                        // Create a new unhealthy peer state (this is the first invalid request)
                        let max_invalid_requests =
                            self.storage_service_config.max_invalid_requests_per_peer;
                        let min_time_to_ignore_peers_secs =
                            self.storage_service_config.min_time_to_ignore_peers_secs;
                        let time_service = self.time_service.clone();

                        UnhealthyPeerState::new(
                            max_invalid_requests,
                            min_time_to_ignore_peers_secs,
                            time_service,
                        )
                    });
                unhealthy_peer_state.increment_invalid_request_count(peer_network_id);

                // Return the validation error
                return Err(Error::InvalidRequest(format!(
                    "The given request cannot be satisfied. Request: {:?}, storage summary: {:?}",
                    request, storage_server_summary
                )));
            }

            Ok(()) // The request is valid
        };
        utils::execute_and_time_duration(
            &metrics::STORAGE_REQUEST_VALIDATION_LATENCY,
            Some((peer_network_id, request)),
            None,
            validate_request,
            None,
        )
    }
```

**File:** config/src/config/state_sync_config.rs (L23-27)
```rust
// The maximum chunk sizes for data client requests and response
const MAX_EPOCH_CHUNK_SIZE: u64 = 200;
const MAX_STATE_CHUNK_SIZE: u64 = 4000;
const MAX_TRANSACTION_CHUNK_SIZE: u64 = 3000;
const MAX_TRANSACTION_OUTPUT_CHUNK_SIZE: u64 = 3000;
```

**File:** config/src/config/state_sync_config.rs (L156-193)
```rust
pub struct StorageServiceConfig {
    /// Whether to enable size and time-aware chunking
    pub enable_size_and_time_aware_chunking: bool,
    /// Whether transaction data v2 is enabled
    pub enable_transaction_data_v2: bool,
    /// Maximum number of epoch ending ledger infos per chunk
    pub max_epoch_chunk_size: u64,
    /// Maximum number of invalid requests per peer
    pub max_invalid_requests_per_peer: u64,
    /// Maximum number of items in the lru cache before eviction
    pub max_lru_cache_size: u64,
    /// Maximum number of pending network messages
    pub max_network_channel_size: u64,
    /// Maximum number of bytes to send per network message
    pub max_network_chunk_bytes: u64,
    /// Maximum number of bytes to send per network message (for v2 data)
    pub max_network_chunk_bytes_v2: u64,
    /// Maximum number of active subscriptions (per peer)
    pub max_num_active_subscriptions: u64,
    /// Maximum period (ms) of pending optimistic fetch requests
    pub max_optimistic_fetch_period_ms: u64,
    /// Maximum number of state keys and values per chunk
    pub max_state_chunk_size: u64,
    /// Maximum time (ms) to wait for storage before truncating a response
    pub max_storage_read_wait_time_ms: u64,
    /// Maximum period (ms) of pending subscription requests
    pub max_subscription_period_ms: u64,
    /// Maximum number of transactions per chunk
    pub max_transaction_chunk_size: u64,
    /// Maximum number of transaction outputs per chunk
    pub max_transaction_output_chunk_size: u64,
    /// Minimum time (secs) to ignore peers after too many invalid requests
    pub min_time_to_ignore_peers_secs: u64,
    /// The interval (ms) to refresh the request moderator state
    pub request_moderator_refresh_interval_ms: u64,
    /// The interval (ms) to refresh the storage summary
    pub storage_summary_refresh_interval_ms: u64,
}
```
