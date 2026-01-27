# Audit Report

## Title
Unauthenticated CPU Profiling Endpoint Exposes Sensitive Execution Patterns in Indexer-GRPC Services

## Summary
The `/profilez` endpoint in the indexer-grpc-server-framework lacks any authentication or access control, allowing any network attacker to request CPU profiles that expose sensitive execution patterns, timing information, and internal implementation details. The endpoint is bound to all network interfaces (`0.0.0.0`), making it accessible from any network that can reach the health check port.

## Finding Description
The `register_probes_and_metrics_handler()` function in the indexer-grpc-server-framework creates a `/profilez` endpoint on Linux systems that directly calls `start_cpu_profiling(10, 99, false)` without any authentication checks. [1](#0-0) 

The endpoint is served on all network interfaces: [2](#0-1) 

When accessed, the endpoint performs CPU profiling for 10 seconds at 99 Hz frequency and returns a flamegraph SVG containing detailed call stacks and execution timing information: [3](#0-2) 

This breaks the **Access Control** security invariant - sensitive administrative endpoints must be properly protected. In contrast, the `aptos-admin-service` implements proper authentication for its `/profilez` endpoint using SHA256 passcode verification: [4](#0-3) 

**Affected Services:** All services using the indexer-grpc-server-framework are vulnerable:
- indexer-grpc-cache-worker
- indexer-grpc-data-service (v1 and v2)
- indexer-grpc-file-store and backfiller services
- indexer-grpc-gateway
- indexer-grpc-manager
- nft-metadata-crawler

## Impact Explanation
This vulnerability meets **High Severity** criteria per the Aptos bug bounty program:

1. **Information Disclosure**: Attackers obtain detailed execution patterns including:
   - Function call hierarchies and precise timing information
   - Hot code paths revealing critical business logic
   - Cryptographic operation timing (potential side-channel attack vectors)
   - Database query patterns and optimization opportunities
   - Internal architecture and implementation details

2. **Service Degradation**: While a mutex prevents concurrent profiling, attackers can:
   - Repeatedly trigger 10-second profiling sessions, adding CPU overhead
   - Block legitimate profiling attempts by holding the mutex
   - Cause periodic slowdowns during profiling windows

3. **Protocol Violation**: Violates security best practices by exposing administrative functionality without authentication, contrary to the pattern established in `aptos-admin-service`.

## Likelihood Explanation
**Likelihood: High**

- **Attack Complexity: Trivial** - Requires only a simple HTTP GET request
- **Attacker Requirements: Minimal** - Any network access to the health check port
- **Discovery: Easy** - Endpoint is well-known and openly documented in code
- **Exploitation: Immediate** - No rate limiting or protective measures beyond the mutex

The vulnerability is exploitable by any attacker who can reach the indexer service's health check port, which is typically exposed for monitoring purposes.

## Recommendation
Implement authentication for the `/profilez` endpoint following the pattern established in `aptos-admin-service`. Add configuration options to:

1. **Add Authentication**: Implement passcode-based authentication similar to `AuthenticationConfig::PasscodeSha256`
2. **Restrict Network Binding**: Allow configuration to bind only to localhost (`127.0.0.1`) instead of all interfaces
3. **Add Rate Limiting**: Implement request throttling to prevent abuse
4. **Make Endpoint Optional**: Add configuration flag to disable the endpoint entirely in production environments

Example fix pattern:

```rust
// Add to GenericConfig
pub authentication_configs: Vec<AuthenticationConfig>,
pub bind_address: String, // default "127.0.0.1"

// In register_probes_and_metrics_handler, add authentication check
let profilez = warp::path("profilez")
    .and(warp::query::<HashMap<String, String>>())
    .and_then(move |query_params| {
        let config = config.clone();
        async move {
            // Verify authentication
            if !verify_auth(&config.authentication_configs, &query_params) {
                return Ok(warp::reply::with_status(
                    Response::new(b"Authentication required".to_vec()),
                    warp::http::StatusCode::UNAUTHORIZED,
                ));
            }
            // ... existing profiling logic
        }
    });

// Bind to configured address instead of 0.0.0.0
let bind_addr: IpAddr = config.bind_address.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
warp::serve(...).run((bind_addr, port)).await;
```

## Proof of Concept

**Step 1: Start any indexer-grpc service** (e.g., indexer-grpc-data-service) with default configuration

**Step 2: From any machine with network access, execute:**
```bash
# Request CPU profile
curl http://<service-host>:<health_check_port>/profilez -o profile.svg

# The request succeeds without authentication and returns a flamegraph
# containing detailed execution patterns and timing information
```

**Step 3: Observe the flamegraph SVG** containing:
- Complete call stack hierarchies
- Execution time percentages for each function
- Hot paths and performance bottlenecks
- Internal implementation details

**Step 4: Demonstrate service degradation:**
```bash
# Repeatedly trigger profiling to cause CPU overhead
while true; do 
    curl http://<service-host>:<health_check_port>/profilez -o /dev/null &
    sleep 1
done
```

This demonstrates both information disclosure and service impact without any authentication requirement.

## Notes
The vulnerability is particularly concerning because:
1. Health check ports are often exposed for monitoring and load balancer health checks
2. The endpoint returns detailed flamegraphs that reveal internal architecture
3. Multiple production indexer services are affected
4. The `aptos-admin-service` already implements proper authentication, showing this is an oversight rather than intentional design
5. The TODO comment at line 227 suggests awareness that parameters should be configurable but doesn't address the fundamental authentication issue

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L226-249)
```rust
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
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L251-258)
```rust
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
