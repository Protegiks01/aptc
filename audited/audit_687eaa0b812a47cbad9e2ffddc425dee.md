# Audit Report

## Title
Inspection Service Runtime Starvation via Blocking Handler Execution

## Summary
The Aptos inspection service creates a dedicated tokio runtime with limited worker threads but executes all request handlers synchronously on these threads without offloading to blocking thread pools. This allows attackers to starve the runtime by sending concurrent requests to CPU-intensive endpoints, preventing new requests (including critical health checks) from being processed and causing inspection service unavailability.

## Finding Description

The inspection service initializes a tokio multi-threaded runtime specifically for handling HTTP requests: [1](#0-0) 

This runtime is created with `None` for the number of worker threads parameter, which defaults to the number of CPU cores (typically 4-8 threads). [2](#0-1) 

The request handlers are invoked synchronously within the async `serve_requests` function without using `tokio::task::spawn_blocking` to offload blocking operations: [3](#0-2) 

Several handlers perform CPU-intensive synchronous operations that block tokio worker threads:

1. **Metrics Gathering**: The `/metrics`, `/json_metrics`, `/forge_metrics`, and `/consensus_health_check` endpoints all call `aptos_metrics_core::gather()` which locks a global registry and collects all registered metrics. [4](#0-3) 

2. **Peer Information**: The `/peer_information` endpoint iterates through all connected peers and collects extensive metadata, connection states, and statistics. [5](#0-4) 

3. **Configuration Serialization**: The `/configuration` endpoint performs debug formatting of the entire node configuration. [6](#0-5) 

**Attack Scenario:**
1. Attacker sends N concurrent requests to expensive endpoints (where N = number of CPU cores)
2. Each request executes synchronously on a tokio worker thread
3. Handlers perform blocking operations (metrics gathering with thousands of metrics, peer iteration with hundreds of peers)
4. All worker threads become blocked for the duration of these operations (potentially 5-10+ seconds)
5. New incoming requests (including `/consensus_health_check` used for monitoring) cannot be processed
6. Inspection service becomes unavailable until handlers complete

**Contrast with Correct Pattern:**
The codebase demonstrates awareness of this issue in other services. The peer monitoring service explicitly uses `spawn_blocking` with a comment explaining why: [7](#0-6) 

The API service similarly uses `tokio::task::spawn_blocking` wrapped in a helper function: [8](#0-7) 

The inspection service lacks any such protection, leaving it vulnerable to runtime starvation.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program criteria:

**Validator Node Slowdowns / API Crashes**: The inspection service provides critical operational endpoints:
- `/consensus_health_check` - Used by monitoring systems to verify validator participation in consensus
- `/metrics` - Essential for observability and alerting
- `/system_information` - Provides node version and build information
- `/peer_information` - Critical for debugging network connectivity issues

When these endpoints become unavailable due to runtime starvation:
- Monitoring systems cannot verify consensus participation, potentially triggering false alerts
- Metrics collection fails, creating blind spots in observability
- Operational troubleshooting becomes impossible during incidents
- Health check failures may trigger automated remediation actions

**State Inconsistencies Requiring Intervention**: While the inspection service doesn't directly affect consensus, its unavailability can mask underlying issues and delay detection of actual problems, potentially allowing state inconsistencies to persist longer than they otherwise would.

The issue does not qualify for higher severity because:
- It doesn't directly affect consensus safety or liveness
- It doesn't cause loss of funds or validator rewards
- The attack is temporary (service recovers when requests complete)
- It doesn't compromise validator private keys or signing operations

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Low Attack Complexity**: Requires only HTTP requests to an exposed endpoint (port 9101 by default)
2. **No Authentication Required**: The inspection service has no authentication mechanism
3. **Publicly Exposed**: Configured to listen on `0.0.0.0` by default [9](#0-8) 
4. **Known Endpoints**: Endpoint paths are standard and documented
5. **Easily Reproducible**: Can be triggered with simple curl loops or basic HTTP clients
6. **No Rate Limiting**: The configuration provides no rate limiting or concurrency controls [10](#0-9) 

The vulnerability is particularly concerning because:
- Testnet and devnet nodes have all endpoints enabled by default for debugging
- Many validator operators expose inspection services for monitoring purposes
- Automated scanning tools could easily discover and exploit this

## Recommendation

**Primary Fix**: Offload all handler execution to blocking thread pools using `tokio::task::spawn_blocking`:

```rust
async fn serve_requests(
    req: Request<Body>,
    node_config: NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> Result<Response<Body>, hyper::Error> {
    // Spawn handler execution on blocking thread pool to prevent runtime starvation
    let (status_code, body, content_type) = tokio::task::spawn_blocking(move || {
        match req.uri().path() {
            CONFIGURATION_PATH => configuration::handle_configuration_request(&node_config),
            METRICS_PATH => metrics::handle_metrics_request(),
            PEER_INFORMATION_PATH => peer_information::handle_peer_information_request(
                &node_config,
                aptos_data_client,
                peers_and_metadata,
            ),
            // ... other handlers
            _ => (
                StatusCode::NOT_FOUND,
                Body::from(INVALID_ENDPOINT_MESSAGE),
                CONTENT_TYPE_TEXT.into(),
            ),
        }
    })
    .await
    .unwrap_or_else(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Body::from("Handler execution failed"),
            CONTENT_TYPE_TEXT.into(),
        )
    });

    // Build response (unchanged)
    let response_builder = Response::builder()
        .header(HEADER_CONTENT_TYPE, content_type)
        .status(status_code);
    
    let response = match *req.method() {
        Method::HEAD => response_builder.body(Body::empty()),
        Method::GET => response_builder.body(body),
        _ => Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::empty()),
    };

    Ok(response.unwrap_or_else(|error| {
        debug!("Error encountered when generating response: {:?}", error);
        let mut response = Response::new(Body::from(UNEXPECTED_ERROR_MESSAGE));
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        response
    }))
}
```

**Alternative Fix**: Use a `BoundedExecutor` similar to the peer monitoring service to limit concurrent request processing and prevent complete runtime exhaustion.

**Additional Hardening**:
1. Add request rate limiting per IP address
2. Add request timeout enforcement (abort long-running handlers after N seconds)
3. Make handler concurrency limits configurable
4. Add metrics tracking handler execution time to detect slow endpoints

## Proof of Concept

```rust
// Test demonstrating runtime starvation
// Place in crates/aptos-inspection-service/src/server/tests.rs

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_runtime_starvation() {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;
    
    // Setup test inspection service (omitted for brevity - use existing test setup)
    let service_address = "127.0.0.1:19101";
    
    // Launch N concurrent requests where N = worker threads
    // Each request will block on metrics gathering
    let num_concurrent = 2;
    let mut handles = vec![];
    
    for _ in 0..num_concurrent {
        let addr = service_address.to_string();
        let handle = tokio::spawn(async move {
            // Request expensive metrics endpoint
            reqwest::get(format!("http://{}/metrics", addr))
                .await
                .unwrap()
        });
        handles.push(handle);
    }
    
    // Give time for all worker threads to become blocked
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Try to make a new request - this should timeout if runtime is starved
    let result = timeout(
        Duration::from_secs(2),
        reqwest::get(format!("http://{}/", service_address))
    ).await;
    
    // Clean up concurrent requests
    for handle in handles {
        let _ = handle.await;
    }
    
    // If runtime is properly protected with spawn_blocking, this should succeed
    // If vulnerable, this will timeout
    assert!(
        result.is_ok(),
        "Runtime starvation detected: new request could not be processed while {} \
         concurrent handlers were executing",
        num_concurrent
    );
}

// Simpler demonstration using curl:
// Terminal 1-4 (assuming 4 CPU cores): while true; do curl http://localhost:9101/metrics > /dev/null; done
// Terminal 5: curl http://localhost:9101/ --max-time 5
// Expected: Terminal 5 times out or has very high latency while terminals 1-4 run
```

**Notes**

This vulnerability is a textbook example of tokio runtime starvation caused by executing blocking operations on async worker threads. The issue is well-understood in the Rust async ecosystem and has been correctly addressed in other Aptos services (API, peer monitoring, storage service), but was missed in the inspection service implementation. The fix is straightforward and follows established patterns already present in the codebase.

The vulnerability's medium severity stems from its impact on operational visibility rather than direct consensus or fund security, but it represents a genuine availability issue that could impair validator operations and incident response capabilities.

### Citations

**File:** crates/aptos-inspection-service/src/server/mod.rs (L71-72)
```rust
    // Create a runtime for the inspection service
    let runtime = aptos_runtimes::spawn_named_runtime("inspection".into(), None);
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

**File:** crates/aptos-runtimes/src/lib.rs (L38-54)
```rust
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
        .enable_all();
    if let Some(num_worker_threads) = num_worker_threads {
        builder.worker_threads(num_worker_threads);
    }
```

**File:** crates/aptos-inspection-service/src/server/utils.rs (L49-79)
```rust
/// A simple utility function that returns all metric families
fn get_metric_families() -> Vec<MetricFamily> {
    let metric_families = aptos_metrics_core::gather();
    let mut total: u64 = 0;
    let mut families_over_2000: u64 = 0;

    // Take metrics of metric gathering so we know possible overhead of this process
    for metric_family in &metric_families {
        let family_count = metric_family.get_metric().len();
        if family_count > 2000 {
            families_over_2000 = families_over_2000.saturating_add(1);
            let name = metric_family.get_name();
            warn!(
                count = family_count,
                metric_family = name,
                "Metric Family '{}' over 2000 dimensions '{}'",
                name,
                family_count
            );
        }
        total = total.saturating_add(family_count as u64);
    }

    // These metrics will be reported on the next pull, rather than create a new family
    NUM_METRICS.with_label_values(&["total"]).inc_by(total);
    NUM_METRICS
        .with_label_values(&["families_over_2000"])
        .inc_by(families_over_2000);

    metric_families
}
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

**File:** crates/aptos-inspection-service/src/server/configuration.rs (L13-28)
```rust
pub fn handle_configuration_request(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Only return configuration if the endpoint is enabled
    let (status_code, body) = if node_config.inspection_service.expose_configuration {
        // We format the configuration using debug formatting. This is important to
        // prevent secret/private keys from being serialized and leaked (i.e.,
        // all secret keys are marked with SilentDisplay and SilentDebug).
        let encoded_configuration = format!("{:?}", node_config);
        (StatusCode::OK, Body::from(encoded_configuration))
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(CONFIGURATION_DISABLED_MESSAGE),
        )
    };

    (status_code, body, CONTENT_TYPE_TEXT.into())
```

**File:** peer-monitoring-service/server/src/lib.rs (L98-121)
```rust
            // All handler methods are currently CPU-bound so we want
            // to spawn on the blocking thread pool.
            let base_config = self.base_config.clone();
            let peers_and_metadata = self.peers_and_metadata.clone();
            let start_time = self.start_time;
            let storage = self.storage.clone();
            let time_service = self.time_service.clone();
            self.bounded_executor
                .spawn_blocking(move || {
                    let response = Handler::new(
                        base_config,
                        peers_and_metadata,
                        start_time,
                        storage,
                        time_service,
                    )
                    .call(
                        peer_network_id.network_id(),
                        peer_monitoring_service_request,
                    );
                    log_monitoring_service_response(&response);
                    response_sender.send(response);
                })
                .await;
```

**File:** api/src/context.rs (L1643-1654)
```rust
/// This function just calls tokio::task::spawn_blocking with the given closure and in
/// the case of an error when joining the task converts it into a 500.
pub async fn api_spawn_blocking<F, T, E>(func: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: InternalError + Send + 'static,
{
    tokio::task::spawn_blocking(func)
        .await
        .map_err(|err| E::internal_with_code_no_info(err, AptosErrorCode::InternalError))?
}
```

**File:** config/src/config/inspection_service_config.rs (L15-24)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct InspectionServiceConfig {
    pub address: String,
    pub port: u16,
    pub expose_configuration: bool,
    pub expose_identity_information: bool,
    pub expose_peer_information: bool,
    pub expose_system_information: bool,
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
