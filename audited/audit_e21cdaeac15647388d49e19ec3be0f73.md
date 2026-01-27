# Audit Report

## Title
HTTP Method Validation Occurs After Expensive Operations in Inspection Service

## Summary
The Aptos inspection service validates HTTP methods (HEAD/GET) after executing expensive handler functions, allowing POST/PUT/DELETE requests to trigger resource-intensive operations like metrics gathering and peer information collection before being rejected with METHOD_NOT_ALLOWED.

## Finding Description
The `serve_requests()` function in the inspection service processes requests in the following order: [1](#0-0) 

The path-based routing executes handler functions that perform expensive operations:

1. **Metrics gathering** - Calls `aptos_metrics_core::gather()` to collect all system metrics: [2](#0-1) 

2. **Peer information collection** - Iterates through all peers, fetches metadata, connection states, and state sync data: [3](#0-2) 

3. **System telemetry** - Gathers system information and build data: [4](#0-3) 

**Only after** these operations complete does the code check the HTTP method: [5](#0-4) 

This means POST, PUT, DELETE, or any other HTTP method will execute the full handler logic, generate the complete response body, and only then check if the method is allowed. An attacker can send repeated invalid method requests to force the node to waste CPU and memory on operations that should be rejected immediately.

The inspection service has no rate limiting and binds to `0.0.0.0:9101` by default, making it publicly accessible: [6](#0-5) 

## Impact Explanation
This is a **Low Severity** issue as marked in the security question. While it allows resource exhaustion through repeated invalid requests, the impact is limited because:

1. The inspection service runs on a separate thread with its own runtime
2. It's an auxiliary service, not critical to consensus operations  
3. The service does not directly affect block production or transaction processing
4. No funds, consensus safety, or state integrity is compromised

The issue could potentially cause validator node slowdowns through resource exhaustion, but would require sustained attack traffic. According to Aptos Bug Bounty criteria, this falls under "Non-critical implementation bugs" (Low Severity - up to $1,000).

## Likelihood Explanation
**High Likelihood** - The vulnerability is trivial to exploit:
- Requires only network access to port 9101 (publicly exposed by default)
- No authentication or special privileges needed
- Simple HTTP requests (POST/PUT/DELETE) to any endpoint trigger the issue
- Attack can be automated with basic tools like `curl` or scripting

## Recommendation
Move the HTTP method validation to occur **before** path routing and handler execution. The method check should be the first validation step after receiving the request:

```rust
async fn serve_requests(
    req: Request<Body>,
    node_config: NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> Result<Response<Body>, hyper::Error> {
    // Validate HTTP method FIRST
    if !matches!(*req.method(), Method::HEAD | Method::GET) {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::empty())
            .unwrap());
    }

    // Now process the request path and call handlers
    let (status_code, body, content_type) = match req.uri().path() {
        // ... existing handler routing ...
    };

    // Build response based on method
    let response = match *req.method() {
        Method::HEAD => Response::builder()
            .header(HEADER_CONTENT_TYPE, content_type)
            .status(status_code)
            .body(Body::empty()),
        Method::GET => Response::builder()
            .header(HEADER_CONTENT_TYPE, content_type)
            .status(status_code)
            .body(body),
        _ => unreachable!(), // Already validated above
    };

    Ok(response.unwrap_or_else(|error| {
        debug!("Error encountered when generating response: {:?}", error);
        let mut response = Response::new(Body::from(UNEXPECTED_ERROR_MESSAGE));
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        response
    }))
}
```

Additionally, consider implementing rate limiting on the inspection service endpoints to prevent abuse.

## Proof of Concept

```bash
#!/bin/bash
# PoC: Trigger expensive operations with invalid HTTP methods

INSPECTION_SERVICE="http://localhost:9101"

echo "Sending invalid method requests to expensive endpoints..."

# These requests will execute full metrics gathering before being rejected
for i in {1..10}; do
    echo "Request $i: POST to /metrics"
    curl -X POST "$INSPECTION_SERVICE/metrics" -w "\nStatus: %{http_code}\n" -s -o /dev/null &
    
    echo "Request $i: PUT to /peer_information"  
    curl -X PUT "$INSPECTION_SERVICE/peer_information" -w "\nStatus: %{http_code}\n" -s -o /dev/null &
    
    echo "Request $i: DELETE to /system_information"
    curl -X DELETE "$INSPECTION_SERVICE/system_information" -w "\nStatus: %{http_code}\n" -s -o /dev/null &
done

wait

echo "All requests completed. Each triggered full handler execution before METHOD_NOT_ALLOWED."
echo "Check node logs for metrics gathering and peer iteration happening on invalid methods."
```

To observe the issue, monitor CPU usage and logs while running this script. You'll see the handler functions execute (metrics gathering, peer iteration) even though all requests return HTTP 405 METHOD_NOT_ALLOWED.

## Notes
This vulnerability confirms the security question's premise: HTTP method validation occurs **after** expensive operations are performed, allowing invalid method requests to waste node resources before being rejected. While the impact is limited to resource exhaustion of an auxiliary service, the fix is straightforward - validate the method before executing any handler logic.

### Citations

**File:** crates/aptos-inspection-service/src/server/mod.rs (L111-169)
```rust
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

**File:** crates/aptos-inspection-service/src/server/mod.rs (L177-186)
```rust
    let response = match *req.method() {
        Method::HEAD => response_builder.body(Body::empty()), // Return only the headers
        Method::GET => response_builder.body(body),           // Include the response body
        _ => {
            // Invalid method found
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::empty())
        },
    };
```

**File:** crates/aptos-inspection-service/src/server/utils.rs (L50-78)
```rust
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

**File:** crates/aptos-inspection-service/src/server/system_information.rs (L32-42)
```rust
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
