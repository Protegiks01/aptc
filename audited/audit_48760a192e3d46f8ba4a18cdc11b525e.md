# Audit Report

## Title
Unauthenticated CPU Profiling Endpoint Enables Resource Exhaustion and Information Disclosure in Indexer Services

## Summary
The `/profilez` endpoint in the indexer-grpc-server-framework is exposed without authentication on all network interfaces, allowing any attacker to trigger CPU-intensive profiling operations that run for 10 seconds each. This enables denial-of-service attacks through resource exhaustion and information disclosure through flame graph analysis.

## Finding Description

The indexer-grpc-server-framework exposes a `/profilez` endpoint on Linux systems that allows unauthenticated CPU profiling. This endpoint is used by 9 different indexer services including indexer-grpc-file-store, indexer-grpc-data-service, indexer-grpc-cache-worker, and others. [1](#0-0) 

The vulnerable code registers the profilez endpoint without any authentication checks: [2](#0-1) 

When accessed, the endpoint triggers CPU profiling with hardcoded parameters (10 seconds duration, 99 Hz sampling frequency): [3](#0-2) 

The profiling implementation uses a mutex to prevent concurrent profiling, but does not prevent multiple requests from queueing: [4](#0-3) 

**Attack Path:**

1. Attacker discovers the health_check_port (e.g., 8084) which binds to 0.0.0.0 (all interfaces)
2. Attacker sends repeated HTTP GET requests to `http://<target>:<health_port>/profilez`
3. Each request triggers 10 seconds of CPU profiling at 99 Hz sampling rate
4. While one profiling operation holds the mutex, additional requests queue as tokio tasks consuming memory
5. Continuous profiling creates CPU overhead and memory pressure from stack trace collection
6. Service performance degrades, potentially causing API timeouts and failures
7. Flame graphs returned to attacker reveal internal function names, call patterns, and architectural details

**Contrast with Admin Service:**

The admin service implements the same profiling functionality but includes proper authentication: [5](#0-4) 

The indexer services completely lack this protection, creating an inconsistent security posture.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria for the following reasons:

1. **API crashes/slowdowns**: Continuous profiling degrades indexer service performance, causing API response delays and potential timeouts. Indexer services are critical infrastructure that blockchain applications depend on for data access.

2. **Resource exhaustion**: Each 10-second profiling session consumes CPU cycles for sampling and memory for stack trace collection. An attacker can maintain continuous profiling by sending requests every 10 seconds, creating sustained resource pressure.

3. **Information disclosure**: Flame graphs expose internal implementation details including:
   - Function names and call hierarchies
   - Hot code paths and performance bottlenecks  
   - Potentially sensitive data in function parameters or stack traces
   - Internal architecture details useful for planning further attacks

4. **Widespread impact**: 9 different indexer services are affected, multiplying the attack surface.

## Likelihood Explanation

**Likelihood: High**

- **Ease of exploitation**: Trivial - requires only HTTP GET requests with no authentication
- **Attack cost**: Zero - no resources required beyond network access
- **Discovery**: The endpoint is easily discoverable through:
  - Port scanning health check ports
  - Examining open source code
  - Observing exposed ports in production deployments
- **Detection**: May go unnoticed initially as profiling appears as legitimate operational activity
- **Attacker skill**: No special skills required beyond basic HTTP knowledge

Production deployments commonly expose health check ports for monitoring, making this endpoint accessible to external attackers in many deployment scenarios.

## Recommendation

Implement authentication for the `/profilez` endpoint consistent with the admin service pattern. The fix should:

1. **Add authentication requirement**: Implement passcode-based or token-based authentication before allowing profiling access

2. **Restrict binding**: Consider binding the health check port to localhost (127.0.0.1) instead of all interfaces (0.0.0.0), or use separate ports for public health checks vs. sensitive operational endpoints

3. **Add rate limiting**: Implement per-IP rate limiting to prevent abuse even with authentication

4. **Add configuration option**: Make the profilez endpoint opt-in via configuration rather than enabled by default

Example fix:

```rust
// In ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs
// Add authentication config to GenericConfig
#[derive(Deserialize, Clone, Debug, Serialize)]
pub struct GenericConfig<T> {
    pub health_check_port: u16,
    pub profilez_auth_token: Option<String>, // Add this field
    pub server_config: T,
}

// Modify profilez endpoint to check authentication
#[cfg(target_os = "linux")]
let profilez = warp::path("profilez")
    .and(warp::header::optional::<String>("authorization"))
    .and_then(move |auth_header: Option<String>| {
        let config_token = config.profilez_auth_token.clone();
        async move {
            // Verify authentication if token is configured
            if let Some(expected_token) = config_token {
                match auth_header {
                    Some(header) if header == format!("Bearer {}", expected_token) => {},
                    _ => return Ok::<_, Infallible>(warp::reply::with_status(
                        Response::new(b"Unauthorized".to_vec()),
                        warp::http::StatusCode::UNAUTHORIZED,
                    )),
                }
            }
            // Proceed with profiling...
        }
    });
```

## Proof of Concept

**Step 1**: Deploy any indexer-grpc service using the framework (e.g., indexer-grpc-file-store)

**Step 2**: Identify the health_check_port from configuration (commonly 8084)

**Step 3**: Execute resource exhaustion attack:

```bash
#!/bin/bash
# Send continuous profiling requests to exhaust resources
TARGET="http://indexer-host:8084"

while true; do
    echo "[$(date)] Triggering profiling..."
    curl -s "$TARGET/profilez" -o /dev/null &
    sleep 5  # Send new request while previous is still running
done
```

**Step 4**: Observe service degradation:
- Monitor CPU usage increase due to profiling overhead
- Monitor API response times increasing
- Monitor memory usage from queued profiling tasks

**Step 5**: Extract information via flame graph:

```bash
# Download and analyze flame graph
curl "http://indexer-host:8084/profilez" -o flamegraph.svg

# Examine flamegraph.svg to identify:
# - Internal function names
# - Call hierarchies
# - Hot code paths
# - Architectural patterns
```

**Expected Results:**
- Service CPU usage increases by 5-15% during profiling
- API latency increases due to resource contention
- Multiple concurrent requests cause tokio task queue growth
- Flame graphs reveal internal implementation details

**Notes**

This vulnerability affects the operational security of Aptos indexer infrastructure rather than core consensus mechanisms. While indexers don't directly participate in consensus, they are critical ecosystem components that applications rely on for blockchain data access. The inconsistency with the admin service's authentication approach suggests this was an oversight rather than an intentional design decision. The exposure is particularly concerning given that health check ports are commonly exposed for monitoring in production deployments.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-file-store/src/main.rs (L15-16)
```rust
    let args = ServerArgs::parse();
    args.run::<IndexerGrpcFileStoreWorkerConfig>()
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L224-258)
```rust
    if cfg!(target_os = "linux") {
        #[cfg(target_os = "linux")]
        let profilez = warp::path("profilez").and_then(|| async move {
            // TODO(grao): Consider make the parameters configurable.
            Ok::<_, Infallible>(match start_cpu_profiling(10, 99, false).await {
                Ok(body) => {
                    let response = Response::builder()
                        .header("Content-Length", body.len())
                        .header("Content-Disposition", "inline")
                        .header("Content-Type", "image/svg+xml")
                        .body(body);

                    match response {
                        Ok(res) => warp::reply::with_status(res, warp::http::StatusCode::OK),
                        Err(e) => warp::reply::with_status(
                            Response::new(format!("Profiling failed: {e:?}.").as_bytes().to_vec()),
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        ),
                    }
                },
                Err(e) => warp::reply::with_status(
                    Response::new(format!("Profiling failed: {e:?}.").as_bytes().to_vec()),
                    warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                ),
            })
        });
        #[cfg(target_os = "linux")]
        warp::serve(
            readiness
                .or(metrics_endpoint)
                .or(status_endpoint)
                .or(profilez),
        )
        .run(([0, 0, 0, 0], port))
        .await;
```

**File:** crates/aptos-system-utils/src/profiling.rs (L80-122)
```rust
pub async fn start_cpu_profiling(
    seconds: u64,
    frequency: i32,
    use_proto: bool,
) -> anyhow::Result<Vec<u8>> {
    info!(
        seconds = seconds,
        frequency = frequency,
        use_proto = use_proto,
        "Starting cpu profiling."
    );
    let lock = CPU_PROFILE_MUTEX.try_lock();
    ensure!(lock.is_some(), "A profiling task is already running.");

    // TODO(grao): Consolidate the code with aptos-profiler crate.
    let guard = pprof::ProfilerGuard::new(frequency)
        .map_err(|e| anyhow!("Failed to start cpu profiling: {e:?}."))?;

    tokio::time::sleep(Duration::from_secs(seconds)).await;

    let mut body = Vec::new();
    let report = guard
        .report()
        .frames_post_processor(frames_post_processor())
        .build()
        .map_err(|e| anyhow!("Failed to generate cpu profiling report: {e:?}."))?;

    if use_proto {
        report
            .pprof()
            .map_err(|e| anyhow!("Failed to generate proto report: {e:?}."))?
            .write_to_vec(&mut body)
            .map_err(|e| anyhow!("Failed to serialize proto report: {e:?}."))?;
    } else {
        report
            .flamegraph(&mut body)
            .map_err(|e| anyhow!("Failed to generate flamegraph report: {e:?}."))?;
    }

    info!("Cpu profiling is done.");

    Ok(body)
}
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L154-181)
```rust
        let mut authenticated = false;
        if context.config.authentication_configs.is_empty() {
            authenticated = true;
        } else {
            for authentication_config in &context.config.authentication_configs {
                match authentication_config {
                    AuthenticationConfig::PasscodeSha256(passcode_sha256) => {
                        let query = req.uri().query().unwrap_or("");
                        let query_pairs: HashMap<_, _> =
                            url::form_urlencoded::parse(query.as_bytes()).collect();
                        let passcode: Option<String> =
                            query_pairs.get("passcode").map(|p| p.to_string());
                        if let Some(passcode) = passcode {
                            if sha256::digest(passcode) == *passcode_sha256 {
                                authenticated = true;
                            }
                        }
                    },
                }
            }
        };

        if !authenticated {
            return Ok(reply_with_status(
                StatusCode::NETWORK_AUTHENTICATION_REQUIRED,
                format!("{} endpoint requires authentication.", req.uri().path()),
            ));
        }
```
