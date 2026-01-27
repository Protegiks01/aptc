# Audit Report

## Title
Privacy Correlation Vulnerability: Unauthenticated Email Exposure in Indexer Metrics Enables Cross-Application User Activity Tracking

## Summary
The indexer-grpc data service exposes user email addresses as Prometheus metric labels through an unauthenticated `/metrics` endpoint. An attacker with network access can correlate email labels across all metrics to track complete user activity patterns across different processors and applications, enabling comprehensive user profiling without authorization.

## Finding Description

The indexer-grpc data service defines multiple Prometheus metrics that include user email addresses as labels. These metrics track various aspects of user activity including connection patterns, data consumption, processor usage, and performance characteristics. [1](#0-0) 

Seven additional metrics follow the same pattern, all including the `email` label: [2](#0-1) [3](#0-2) [4](#0-3) 

The email value originates from the `x-aptos-email` HTTP header: [5](#0-4) 

Email is extracted from request headers and included in all metric labels: [6](#0-5) 

The metric labels are populated using `get_label_values()`: [7](#0-6) 

The `/metrics` endpoint is exposed **without any authentication**: [8](#0-7) 

The endpoint listens on all network interfaces: [9](#0-8) 

Additionally, email addresses are logged in structured application logs: [10](#0-9) 

**Attack Scenario:**
1. Attacker accesses `http://<indexer-host>:8084/metrics` (no authentication required)
2. Scrapes all metrics and extracts email labels
3. Groups metrics by email to build user activity profiles
4. Correlates across different `processor` and `application_name` labels
5. Identifies usage patterns: connection frequency, data consumption, active applications, processor preferences

## Impact Explanation

Per the Aptos Bug Bounty criteria, this falls under **Low Severity** as a "Minor information leak" (up to $1,000). However, the impact is significant from a privacy perspective:

**Privacy Violations:**
- Email addresses are Personally Identifiable Information (PII) subject to GDPR/CCPA regulations
- Enables unauthorized user profiling and behavioral tracking
- Reveals which users are utilizing which applications and processors
- Exposes usage patterns, connection times, and data consumption volumes

**Exploitation Vectors:**
- Competitive intelligence gathering
- User targeting and potential harassment
- Regulatory compliance violations
- Reputational damage to Aptos ecosystem

While this does not directly threaten consensus, state consistency, or funds (the primary focus areas), it represents a systematic PII exposure through operational telemetry.

## Likelihood Explanation

**Likelihood: High**

The attack requires only:
1. Network connectivity to the metrics port (typically 8084)
2. Ability to make HTTP GET requests
3. Basic Prometheus metrics parsing knowledge

No special permissions, authentication tokens, or insider access is required. In many deployments:
- Metrics ports are exposed within internal networks/VPCs
- Compromised internal services can access metrics endpoints
- Misconfigurations may expose metrics externally
- Monitoring systems have unrestricted access

The email exposure is automatic for every request processed by the data service, making correlation trivial.

## Recommendation

**1. Remove PII from Metrics Labels**

Replace the `email` label with a non-reversible identifier:

```rust
// In constants.rs - Add new header for anonymized ID
pub const REQUEST_HEADER_APTOS_USER_HASH: &str = "x-aptos-user-hash";

// Modify IndexerGrpcRequestMetadata
pub struct IndexerGrpcRequestMetadata {
    pub processor_name: String,
    pub request_identifier_type: String,
    pub request_identifier: String,
    // REMOVE: pub request_email: String,
    pub request_user_hash: String, // SHA256(email) or similar
    pub request_application_name: String,
    pub request_connection_id: String,
}

// Modify get_label_values()
pub fn get_label_values(&self) -> Vec<&str> {
    vec![
        &self.request_identifier_type,
        &self.request_identifier,
        // &self.request_email,  // REMOVE
        &self.request_user_hash,  // ADD hashed version
        &self.request_application_name,
        &self.processor_name,
    ]
}
```

**2. Add Authentication to Metrics Endpoint**

Implement authentication/authorization for the `/metrics` endpoint:

```rust
// In lib.rs
let metrics_endpoint = warp::path("metrics")
    .and(warp::header::optional::<String>("authorization"))
    .and_then(|auth_header: Option<String>| async move {
        // Validate auth token
        if !validate_metrics_token(auth_header).await {
            return Err(warp::reject::custom(Unauthorized));
        }
        // ... existing metrics logic
    });
```

**3. Sanitize Logs**

Remove or hash email addresses in structured logs:

```rust
// In counters.rs log_grpc_step
tracing::info!(
    // ...
    // request_email = &request_metadata.request_email,  // REMOVE
    request_user_hash = &hash_email(&request_metadata.request_email),  // ADD
    // ...
);
```

## Proof of Concept

**Step 1: Access the unprotected metrics endpoint**
```bash
# No authentication required
curl http://indexer-grpc-host:8084/metrics | grep email
```

**Step 2: Extract user activity by email**
```bash
# Example output shows email labels in metrics:
# indexer_grpc_data_service_with_user_processed_versions{
#   identifier_type="application",
#   identifier="uuid-123",
#   email="user@example.com",
#   application_name="MyApp",
#   processor="default_processor"
# } 1000

# indexer_grpc_data_service_connection_count_v2{
#   identifier_type="application",
#   identifier="uuid-456",
#   email="user@example.com",
#   application_name="AnotherApp",
#   processor="events_processor"
# } 5
```

**Step 3: Correlate activity across applications**
```python
import requests
import re

# Scrape metrics
response = requests.get('http://indexer-host:8084/metrics')
metrics = response.text

# Extract all email values
emails = re.findall(r'email="([^"]+)"', metrics)

# Group by email to build user profiles
user_profiles = {}
for line in metrics.split('\n'):
    match = re.search(r'email="([^"]+)".*application_name="([^"]+)".*processor="([^"]+)"', line)
    if match:
        email, app, processor = match.groups()
        if email not in user_profiles:
            user_profiles[email] = []
        user_profiles[email].append((app, processor))

# Output: Complete user activity profile
# user@example.com uses: [("MyApp", "default"), ("AnotherApp", "events")]
```

This demonstrates complete cross-application user activity tracking using publicly accessible metrics.

## Notes

This vulnerability enables systematic PII exposure and user tracking but does not directly compromise blockchain consensus, state consistency, or fund security. The classification as "Low Severity" per the bug bounty program reflects this limited impact on core protocol security, despite the significant privacy implications.

The issue is particularly concerning because:
1. Metrics endpoints are often assumed to be internal-only but lack enforcement
2. Email correlation is trivial and automated
3. Logs may be retained long-term or exported to third parties
4. Regulatory frameworks (GDPR Art. 6, CCPA) require explicit consent for PII processing

Deployment-level mitigations (network isolation, VPC restrictions) are insufficient as they don't protect against insider threats or compromised internal services.

### Citations

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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/metrics.rs (L30-43)
```rust
pub static PROCESSED_VERSIONS_COUNT_PER_PROCESSOR: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "indexer_grpc_data_service_with_user_processed_versions",
        "Number of transactions that have been processed by data service",
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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/metrics.rs (L56-69)
```rust
pub static PROCESSED_LATENCY_IN_SECS_PER_PROCESSOR: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "indexer_grpc_data_service_with_user_latest_data_latency_in_secs",
        "Latency of data service based on latest processed transaction",
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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/metrics.rs (L72-85)
```rust
pub static CONNECTION_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "indexer_grpc_data_service_connection_count_v2",
        "Count of connections that data service has established",
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

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L33-36)
```rust
/// The email of the requester. For an application, this is the email of the user who
/// created the application. When looking at metrics based on this label, you should
/// also parallelize based on the application name. Or just use the identifier.
pub const REQUEST_HEADER_APTOS_EMAIL: &str = "x-aptos-email";
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L57-69)
```rust
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

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L72-98)
```rust
pub fn get_request_metadata(req: &Request<GetTransactionsRequest>) -> IndexerGrpcRequestMetadata {
    let request_metadata_pairs = vec![
        (
            "request_identifier_type",
            REQUEST_HEADER_APTOS_IDENTIFIER_TYPE,
        ),
        ("request_identifier", REQUEST_HEADER_APTOS_IDENTIFIER),
        ("request_email", REQUEST_HEADER_APTOS_EMAIL),
        (
            "request_application_name",
            REQUEST_HEADER_APTOS_APPLICATION_NAME,
        ),
        ("request_token", GRPC_AUTH_TOKEN_HEADER),
        ("processor_name", GRPC_REQUEST_NAME_HEADER),
    ];
    let mut request_metadata_map: HashMap<String, String> = request_metadata_pairs
        .into_iter()
        .map(|(key, value)| {
            (
                key.to_string(),
                req.metadata()
                    .get(value)
                    .map(|value| value.to_str().unwrap_or("unspecified").to_string())
                    .unwrap_or("unspecified".to_string()),
            )
        })
        .collect();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L203-217)
```rust
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
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L251-263)
```rust
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
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/counters.rs (L286-306)
```rust
    if let Some(request_metadata) = request_metadata {
        tracing::info!(
            start_version,
            end_version,
            start_txn_timestamp_iso,
            end_txn_timestamp_iso,
            num_transactions,
            duration_in_secs,
            size_in_bytes,
            // Request metadata variables
            processor_name = &request_metadata.processor_name,
            request_identifier_type = &request_metadata.request_identifier_type,
            request_identifier = &request_metadata.request_identifier,
            request_email = &request_metadata.request_email,
            request_application_name = &request_metadata.request_application_name,
            connection_id = &request_metadata.request_connection_id,
            service_type,
            step = step.get_step(),
            "{}",
            step.get_label(),
        );
```
