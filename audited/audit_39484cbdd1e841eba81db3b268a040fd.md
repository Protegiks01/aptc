# Audit Report

## Title
Unauthenticated Public Exposure of Indexer-GRPC Prometheus Metrics Leaking User PII and Operational Intelligence

## Summary
The indexer-grpc services expose Prometheus metrics endpoints without authentication, bound to all network interfaces (0.0.0.0), allowing any network-accessible attacker to enumerate user emails, application names, processing progress, and operational performance data.

## Finding Description
The `register_probes_and_metrics_handler` function in the indexer-grpc-server-framework binds the metrics endpoint to all network interfaces without any authentication or authorization mechanism. [1](#0-0) 

The metrics endpoint exposes several categories of sensitive information:

**1. User Personally Identifiable Information (PII):**
Multiple metrics include user email addresses as labels, directly exposing PII to unauthorized parties. [2](#0-1) 

**2. Application Usage Patterns:**
Metrics track which applications are consuming the indexer, their identifiers, and usage patterns. [3](#0-2) 

**3. Operational Intelligence:**
Real-time version progression, processing latency, transaction counts, and performance bottlenecks are all exposed. [4](#0-3) 

**4. Public Deployment Configuration:**
The docker-compose deployment explicitly exposes the health check port (which includes metrics) publicly. [5](#0-4) 

The metrics are gathered from all registered Prometheus metrics and served via HTTP without any filtering or authentication. [6](#0-5) 

## Impact Explanation
This vulnerability constitutes a **Low Severity** information disclosure issue according to Aptos bug bounty criteria ("Minor information leaks"). While it exposes:

- User email addresses (PII/GDPR violation)
- Application identification and usage patterns
- Real-time processing state and performance metrics
- Potential reconnaissance data for targeted attacks

It does **not** directly lead to:
- Loss or manipulation of funds
- Consensus violations or state inconsistencies
- Network availability issues
- Protocol security violations

The indexer-grpc is an auxiliary indexing service, not part of the core consensus, execution, or state management layer. Exposure of its metrics does not break any of the critical blockchain invariants (Consensus Safety, Deterministic Execution, State Consistency, etc.).

## Likelihood Explanation
**Likelihood: High**

The vulnerability is trivially exploitable - any attacker with network access can retrieve the metrics via a simple HTTP GET request. In production deployments where the health_check_port is exposed (as shown in the docker-compose configuration), this is immediately accessible without any credentials or special tools.

## Recommendation
Implement authentication and authorization for the metrics endpoint. Options include:

1. **Add bearer token authentication** similar to the data service's whitelisted tokens approach
2. **Restrict network binding** to localhost (127.0.0.1) instead of all interfaces (0.0.0.0)
3. **Implement IP allowlisting** for authorized monitoring infrastructure only
4. **Remove PII from metric labels** - use opaque identifiers instead of email addresses
5. **Deploy behind authenticated proxy** (e.g., HAProxy with IP blocking as used for validator metrics)

Example fix for binding to localhost only:
```rust
// Change from [0, 0, 0, 0] to [127, 0, 0, 1]
warp::serve(readiness.or(metrics_endpoint).or(status_endpoint))
    .run(([127, 0, 0, 1], port))
    .await;
```

## Proof of Concept
```bash
# Access publicly exposed metrics endpoint
curl http://<indexer-host>:18084/metrics

# Result: Unauthenticated access to all Prometheus metrics including:
# - indexer_grpc_data_service_with_user_latest_processed_version{email="user@example.com",...}
# - indexer_grpc_data_service_connection_count_v2{email="user@example.com",...}
# - indexer_grpc_latest_processed_version{...}
# - And all other operational metrics
```

## Notes
While this is a legitimate information disclosure vulnerability exposing user PII and operational data, it does **not** meet the Medium severity threshold defined in the Aptos bug bounty program. The bug bounty criteria classify this as **Low Severity** ("Minor information leaks") rather than Medium Severity ("Limited funds loss or manipulation, State inconsistencies requiring intervention").

The vulnerability exists in the indexer-grpc auxiliary services, not in the core blockchain consensus, execution, or state management components, and therefore does not violate any of the critical blockchain invariants.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L196-264)
```rust
async fn register_probes_and_metrics_handler<C>(config: GenericConfig<C>, port: u16)
where
    C: RunnableConfig,
{
    let readiness = warp::path("readiness")
        .map(move || warp::reply::with_status("ready", warp::http::StatusCode::OK));

    let metrics_endpoint = warp::path("metrics").map(|| {
        // Metrics encoding.
        let metrics = aptos_metrics_core::gather();
        let mut encode_buffer = vec![];
        let encoder = TextEncoder::new();
        // If metrics encoding fails, we want to panic and crash the process.
        encoder
            .encode(&metrics, &mut encode_buffer)
            .context("Failed to encode metrics")
            .unwrap();

        Response::builder()
            .header("Content-Type", "text/plain")
            .body(encode_buffer)
    });

    let status_endpoint = warp::path::end().and_then(move || {
        let config = config.clone();
        async move { config.status_page().await }
    });

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
    } else {
        warp::serve(readiness.or(metrics_endpoint).or(status_endpoint))
            .run(([0, 0, 0, 0], port))
            .await;
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/metrics.rs (L14-27)
```rust
pub static LATEST_PROCESSED_VERSION_PER_PROCESSOR: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "indexer_grpc_data_service_with_user_latest_processed_version",
        "Latest processed transaction version",
        &[
            "identifier_type",
            "identifier",
            "email",
            "application_name",
            "processor"
        ],
    )
    .unwrap()
});
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L40-69)
```rust
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct IndexerGrpcRequestMetadata {
    pub processor_name: String,
    /// See `REQUEST_HEADER_APTOS_IDENTIFIER_TYPE` for more information.
    pub request_identifier_type: String,
    /// See `REQUEST_HEADER_APTOS_IDENTIFIER` for more information.
    pub request_identifier: String,
    /// See `REQUEST_HEADER_APTOS_EMAIL` for more information.
    pub request_email: String,
    /// See `REQUEST_HEADER_APTOS_APPLICATION_NAME` for more information.
    pub request_application_name: String,
    pub request_connection_id: String,
    // Token is no longer needed behind api gateway.
    #[deprecated]
    pub request_token: String,
}

impl IndexerGrpcRequestMetadata {
    /// Get the label values for use with metrics that use these labels. Note, the
    /// order must match the order in metrics.rs.
    pub fn get_label_values(&self) -> Vec<&str> {
        vec![
            &self.request_identifier_type,
            &self.request_identifier,
            &self.request_email,
            &self.request_application_name,
            &self.processor_name,
        ]
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/counters.rs (L149-177)
```rust
/// Latest processed transaction version.
pub static LATEST_PROCESSED_VERSION: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "indexer_grpc_latest_processed_version",
        "Latest processed transaction version",
        &["service_type", "step", "message"],
    )
    .unwrap()
});

/// Transactions' total size in bytes at each step
pub static TOTAL_SIZE_IN_BYTES: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "indexer_grpc_total_size_in_bytes_v2",
        "Total size in bytes at this step",
        &["service_type", "step", "message"],
    )
    .unwrap()
});

/// Number of transactions at each step
pub static NUM_TRANSACTIONS_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "indexer_grpc_num_transactions_count_v2",
        "Total count of transactions at this step",
        &["service_type", "step", "message"],
    )
    .unwrap()
});
```

**File:** docker/compose/indexer-grpc/docker-compose.yaml (L103-106)
```yaml
    ports:
      - "50052:50052" # GRPC non-secure
      - "50053:50053" # GRPC secure
      - "18084:8084" # health
```
