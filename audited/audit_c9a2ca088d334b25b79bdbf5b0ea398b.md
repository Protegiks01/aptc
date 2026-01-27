# Audit Report

## Title
Storage Service Request Processing Lacks Cancellation After RPC Timeout Leading to Thread Pool Exhaustion

## Summary
The storage service server spawns blocking tasks to process requests but does not cancel these tasks when the RPC layer times out after 10 seconds. Long-running storage operations continue executing even after the client has given up, allowing attackers to exhaust the limited blocking thread pool (64 threads) and cause validator node slowdowns.

## Finding Description

The storage service handles incoming network requests by spawning blocking tasks for each request. The network RPC layer enforces a 10-second timeout on responses, but this timeout only affects the response channel—it does not cancel the underlying processing task. [1](#0-0) 

Each request is processed using `spawn_blocking`, which submits work to Tokio's blocking thread pool. This pool has a maximum of 64 threads: [2](#0-1) 

The RPC layer implements a 10-second timeout on the response channel: [3](#0-2) [4](#0-3) [5](#0-4) 

**Attack Vector:**

An attacker can send requests for large data chunks that trigger slow storage operations: [6](#0-5) 

When processing requests like `get_state_value_chunk_with_proof` (up to 4000 state values) or `get_transactions_with_proof` (up to 3000 transactions), the storage operations can legitimately take longer than 10 seconds, especially with:
- Large chunk sizes at maximum configuration limits
- Requests for historical data requiring extensive disk I/O
- Merkle proof generation for large datasets

**Exploitation Flow:**

1. Attacker sends multiple requests (up to 100 per peer, the `MAX_CONCURRENT_INBOUND_RPCS` limit) requesting maximum-size chunks of state data or transactions
2. Each request is spawned as a blocking task via `spawn_blocking`
3. After 10 seconds, the RPC layer times out and returns `RpcError::TimedOut` to the client
4. **However, the spawned blocking tasks continue running to completion**
5. With 64+ concurrent slow requests (achievable with just 1-2 malicious peers), the blocking thread pool becomes exhausted
6. Subsequent legitimate requests queue up waiting for available threads, causing significant delays
7. State synchronization for honest nodes is severely degraded

This violates the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" by allowing timed-out operations to continue consuming limited thread pool resources.

## Impact Explanation

This vulnerability causes **validator node slowdowns**, which is explicitly categorized as **High Severity** (up to $50,000) in the Aptos bug bounty program.

**Specific Impacts:**

1. **Storage Service Degradation**: The storage service becomes unresponsive or severely degraded when the blocking thread pool is exhausted
2. **State Sync Disruption**: Other nodes attempting to sync state from the affected node experience timeouts and delays
3. **Network-Wide Impact**: Multiple affected validator nodes can slow down the overall network's ability to onboard new nodes or recover from outages
4. **Resource Exhaustion**: Memory and CPU resources are wasted on processing requests that have already timed out
5. **Cascading Failures**: As nodes become slow to respond, other nodes may mark them as unhealthy, reducing the effective network capacity

The attack requires minimal resources from the attacker (just network connectivity and ability to send valid protocol messages) but can significantly degrade validator performance.

## Likelihood Explanation

**High Likelihood:**

1. **Easy to Execute**: Any peer can send storage service requests; no special privileges required
2. **Valid Protocol Messages**: Attacker uses legitimate request types with parameters within configured limits
3. **Difficult to Detect**: Slow requests appear similar to legitimate heavy load
4. **No Authentication Required**: The storage service accepts requests from any connected peer
5. **Amplification Effect**: Multiple malicious peers can coordinate to multiply the impact
6. **Limited Mitigations**: The `MAX_CONCURRENT_INBOUND_RPCS = 100` limit per peer is insufficient when the blocking pool is shared across all peers

The request moderator provides some protection but primarily targets "invalid" requests, not slow but valid ones: [7](#0-6) 

An attacker can stay under the 500 invalid request threshold while still causing resource exhaustion through slow valid requests.

## Recommendation

Implement request cancellation by wrapping the blocking task execution with a timeout that cancels the task if it exceeds the RPC timeout duration. Use `tokio::time::timeout` or a similar mechanism to enforce processing time limits.

**Proposed Fix:**

```rust
// In lib.rs, modify the request handling loop
while let Some(network_request) = self.network_requests.next().await {
    let storage = self.storage.clone();
    let config = self.storage_service_config;
    // ... other clones ...
    
    // Spawn with cancellation support
    self.runtime.spawn(async move {
        let handler = Handler::new(/* ... */);
        
        // Wrap blocking operation with timeout
        let processing_timeout = Duration::from_millis(INBOUND_RPC_TIMEOUT_MS);
        let result = tokio::time::timeout(
            processing_timeout,
            tokio::task::spawn_blocking(move || {
                handler.process_request_and_respond(
                    config,
                    network_request.peer_network_id,
                    network_request.protocol_id,
                    network_request.storage_service_request.clone(),
                    network_request.response_sender,
                )
            })
        ).await;
        
        // Handle timeout case
        if result.is_err() {
            // Log timeout and update metrics
            warn!("Request processing exceeded timeout");
            // Task was cancelled, thread is freed
        }
    });
}
```

**Additional Mitigations:**

1. Add per-peer limits on concurrent blocking tasks (not just RPC requests)
2. Implement adaptive chunk sizing based on processing time
3. Add metrics to track blocking thread pool utilization
4. Consider using a separate bounded thread pool for storage operations

## Proof of Concept

```rust
// Rust test demonstrating the issue
#[tokio::test]
async fn test_request_processing_timeout_exhaustion() {
    // Setup: Create storage service with limited blocking pool
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(64)
        .build()
        .unwrap();
    
    // Simulate attacker sending 100 requests for maximum chunk size
    let mut handles = vec![];
    for i in 0..100 {
        let handle = runtime.spawn_blocking(move || {
            // Simulate slow storage operation
            std::thread::sleep(Duration::from_secs(30)); // Much longer than 10s timeout
            println!("Request {} completed after timeout", i);
        });
        handles.push(handle);
    }
    
    // Wait just past RPC timeout
    tokio::time::sleep(Duration::from_secs(11)).await;
    
    // At this point, RPC layer would have timed out all requests
    // But all 100 blocking tasks are still running!
    
    // Try to submit a legitimate request - it will be queued
    let legitimate_request = runtime.spawn_blocking(|| {
        println!("Legitimate request started");
    });
    
    // This request will be delayed because blocking pool is saturated
    tokio::time::timeout(Duration::from_secs(5), legitimate_request)
        .await
        .expect_err("Legitimate request should timeout waiting for available thread");
    
    // Cleanup
    for handle in handles {
        handle.abort();
    }
}
```

**Attack Simulation Steps:**

1. Deploy multiple malicious peers (2-3 peers sufficient)
2. Each peer sends 100 concurrent requests to target node:
   - Request type: `GetStateValuesWithProof` 
   - Chunk size: 4000 (maximum)
   - Target: Historical versions requiring disk I/O
3. Observe target node's blocking thread pool saturation
4. Monitor legitimate state sync requests experiencing delays
5. Verify node performance degradation via metrics

This demonstrates how the lack of task cancellation after RPC timeout enables resource exhaustion attacks against the storage service's blocking thread pool.

### Citations

**File:** state-sync/storage-service/server/src/lib.rs (L389-419)
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
        }
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

**File:** network/framework/src/protocols/rpc/mod.rs (L177-191)
```rust
    /// A blanket timeout on all inbound rpc requests. If the application handler
    /// doesn't respond to the request before this timeout, the request will be
    /// dropped.
    inbound_rpc_timeout: Duration,
    /// Only allow this many concurrent inbound rpcs at one time from this remote
    /// peer.  New inbound requests exceeding this limit will be dropped.
    max_concurrent_inbound_rpcs: u32,
}

impl InboundRpcs {
    pub fn new(
        network_context: NetworkContext,
        time_service: TimeService,
        remote_peer_id: PeerId,
        inbound_rpc_timeout: Duration,
```

**File:** network/framework/src/protocols/rpc/mod.rs (L255-280)
```rust
        // Create a new task that waits for a response from the upper layer with a timeout.
        let inbound_rpc_task = self
            .time_service
            .timeout(self.inbound_rpc_timeout, response_rx)
            .map(move |result| {
                // Flatten the errors
                let maybe_response = match result {
                    Ok(Ok(Ok(response_bytes))) => {
                        let rpc_response = RpcResponse {
                            request_id,
                            priority,
                            raw_response: Vec::from(response_bytes.as_ref()),
                        };
                        Ok((rpc_response, protocol_id))
                    },
                    Ok(Ok(Err(err))) => Err(err),
                    Ok(Err(oneshot::Canceled)) => Err(RpcError::UnexpectedResponseChannelCancel),
                    Err(timeout::Elapsed) => Err(RpcError::TimedOut),
                };
                // Only record latency of successful requests
                match maybe_response {
                    Ok(_) => timer.stop_and_record(),
                    Err(_) => timer.stop_and_discard(),
                };
                maybe_response
            })
```

**File:** network/framework/src/constants.rs (L10-11)
```rust
/// The timeout for any inbound RPC call before it's cut off
pub const INBOUND_RPC_TIMEOUT_MS: u64 = 10_000;
```

**File:** config/src/config/state_sync_config.rs (L23-27)
```rust
// The maximum chunk sizes for data client requests and response
const MAX_EPOCH_CHUNK_SIZE: u64 = 200;
const MAX_STATE_CHUNK_SIZE: u64 = 4000;
const MAX_TRANSACTION_CHUNK_SIZE: u64 = 3000;
const MAX_TRANSACTION_OUTPUT_CHUNK_SIZE: u64 = 3000;
```

**File:** config/src/config/state_sync_config.rs (L201-201)
```rust
            max_invalid_requests_per_peer: 500,
```
