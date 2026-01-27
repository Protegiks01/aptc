# Audit Report

## Title
API Gateway Bypass via Direct Connection to Indexer-GRPC Backend Services Without Authentication

## Summary
The indexer-grpc-data-service and indexer-grpc-data-service-v2 expose gRPC endpoints without enforcing any authentication, allowing attackers to bypass the external API Gateway entirely by connecting directly to backend services. This circumvents all rate limits, authentication, access controls, and attribution mechanisms enforced by the gateway.

## Finding Description

The indexer-grpc data services are designed to operate behind an external API Gateway (https://github.com/aptos-labs/api-gateway) that enforces authentication, rate limiting, and access controls. However, the backend services themselves perform **no authentication validation** despite exposing direct network endpoints.

### Evidence of Missing Authentication:

1. **Deprecated Authentication Fields**: The configuration contains `whitelisted_auth_tokens` and `disable_auth_check` fields marked as deprecated with no replacement implementation: [1](#0-0) 

2. **No Authentication Interceptor**: Despite a misleading comment claiming "The request is already authenticated by the interceptor," no interceptor is added to the gRPC server: [2](#0-1) 

3. **Server Created Without Interceptor**: The server is instantiated and exposed without any authentication middleware: [3](#0-2) 

4. **Headers Extracted Only For Metrics**: The `get_request_metadata` function extracts authentication headers including `GRPC_AUTH_TOKEN_HEADER` but only uses them for logging/metrics, not validation: [4](#0-3) 

5. **V2 Service Also Unprotected**: The v2 data service similarly lacks authentication: [5](#0-4) 

### Attack Path:

1. Attacker discovers the IP address and port of a backend indexer-grpc-data-service (e.g., via network scanning, DNS enumeration, or leaked configuration)
2. Attacker connects directly to the service endpoint (port 50051 non-TLS or 50052 TLS as per README)
3. Attacker omits all authentication headers including `authorization` and `x-aptos-data-authorization`
4. Service accepts and processes the request without validation
5. Attacker successfully bypasses all API Gateway protections

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria for the following reasons:

1. **API Crashes**: Attackers can overwhelm backend services by bypassing gateway rate limits, potentially causing service degradation or crashes for legitimate users

2. **Access Control Bypass**: Complete circumvention of the API Gateway's authentication and authorization mechanisms

3. **Attribution Loss**: Attackers can access services anonymously without proper tracking via gateway-injected headers (`REQUEST_HEADER_APTOS_IDENTIFIER`, `REQUEST_HEADER_APTOS_EMAIL`, etc.)

4. **Infrastructure Exposure**: Direct access to backend services that were designed to be internal-only, violating defense-in-depth principles

While the indexer data itself is public blockchain information, the bypass enables:
- Unmetered resource consumption
- Infrastructure reconnaissance
- Potential pivoting to other internal services
- Operational cost attacks (bandwidth, compute)

## Likelihood Explanation

**Likelihood: High**

- **Attacker Requirements**: Only requires network access to discover backend service IPs/ports
- **Complexity**: Trivial - standard gRPC client connection without authentication headers
- **Detection Difficulty**: Low - direct connections bypass gateway monitoring and logging
- **Common Misconfiguration**: Backend services may be unintentionally exposed via misconfigured firewalls, cloud security groups, or Kubernetes services

The comment in the code claiming authentication by interceptor suggests developers may falsely believe the service is protected, increasing the likelihood of insecure deployments.

## Recommendation

Implement defense-in-depth by adding authentication validation at the service level:

**Option 1: Add gRPC Interceptor** (Recommended)
```rust
// In config.rs, add authentication interceptor
use tonic::service::Interceptor;

fn check_auth(req: Request<()>) -> Result<Request<()>, Status> {
    // Validate API Gateway headers are present
    let identifier = req.metadata()
        .get(REQUEST_HEADER_APTOS_IDENTIFIER)
        .ok_or_else(|| Status::unauthenticated("Missing authentication headers"))?;
    
    // Additional validation as needed
    Ok(req)
}

// When building the server:
let svc = RawDataServer::new(server)
    .with_interceptor(check_auth) // Add this line
    .send_compressed(CompressionEncoding::Zstd)
    // ... rest of configuration
```

**Option 2: Network-Level Isolation**
- Deploy backend services on private networks only accessible from API Gateway
- Document and enforce network security requirements
- Add health checks that verify gateway-injected headers are present

**Option 3: Restore Token Authentication**
- Re-implement the deprecated `whitelisted_auth_tokens` validation
- Require shared secrets between gateway and backend services

**Critical: Remove Misleading Comment** [6](#0-5) 

This comment falsely claims authentication is enforced and should be removed or corrected.

## Proof of Concept

```rust
// Direct connection bypassing API Gateway
use aptos_protos::indexer::v1::{
    raw_data_client::RawDataClient, GetTransactionsRequest,
};
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect directly to backend service (bypassing gateway)
    let mut client = RawDataClient::connect("http://backend-service-ip:50051").await?;
    
    // Create request WITHOUT any authentication headers
    let request = Request::new(GetTransactionsRequest {
        starting_version: Some(0),
        transactions_count: Some(100),
        ..Default::default()
    });
    
    // Request succeeds despite missing all authentication!
    let mut stream = client.get_transactions(request).await?.into_inner();
    
    while let Some(response) = stream.message().await? {
        println!("Received {} transactions", response.transactions.len());
        // Successfully bypassed API Gateway authentication
    }
    
    Ok(())
}
```

## Notes

This vulnerability represents a **defense-in-depth failure** where the backend service relies entirely on perimeter security (API Gateway) without enforcing authentication itself. The presence of deprecated authentication fields and the misleading comment suggest this is a **security regression** where authentication was previously implemented but removed without adequate replacement protections.

The external API Gateway reference indicates a multi-repository architecture where security boundaries must be carefully coordinated: [7](#0-6)

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs (L58-63)
```rust
    /// Deprecated: a list of auth tokens that are allowed to access the service.
    #[serde(default)]
    pub whitelisted_auth_tokens: Vec<String>,
    /// Deprecated: if set, don't check for auth tokens.
    #[serde(default)]
    pub disable_auth_check: bool,
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/config.rs (L180-192)
```rust
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
        println!(">>>> Starting gRPC server: {:?}", &svc);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L145-150)
```rust
    async fn get_transactions(
        &self,
        req: Request<GetTransactionsRequest>,
    ) -> Result<Response<Self::GetTransactionsStream>, Status> {
        // Get request identity. The request is already authenticated by the interceptor.
        let request_metadata = get_request_metadata(&req);
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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/config.rs (L236-248)
```rust
            aptos_protos::indexer::v1::raw_data_server::RawDataServer::from_arc(wrapper.clone())
                .send_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Gzip)
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE);
        let wrapper_service =
            aptos_protos::indexer::v1::data_service_server::DataServiceServer::from_arc(wrapper)
                .send_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Zstd)
                .accept_compressed(CompressionEncoding::Gzip)
                .max_decoding_message_size(MAX_MESSAGE_SIZE)
                .max_encoding_message_size(MAX_MESSAGE_SIZE);
```
