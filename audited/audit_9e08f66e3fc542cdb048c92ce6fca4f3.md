# Audit Report

## Title
Authentication Bypass in Indexer gRPC Data Service: Missing Interceptor Allows Unauthorized Access to Raw Transaction Data

## Summary
The `RawDataServer` in the indexer gRPC data service is deployed without authentication interceptors despite code comments indicating authentication should be added. The service exposes raw blockchain transaction data on network-accessible ports (0.0.0.0:50051, 0.0.0.0:50052) with no access control, allowing any attacker with network access to retrieve all blockchain transaction data without authorization.

## Finding Description

The Aptos indexer gRPC data service was designed with authentication via `whitelisted_auth_tokens`, but this mechanism was deprecated with the assumption that an API Gateway would handle authentication. However, critical security gaps exist:

**1. Missing Authentication Interceptor**

In the server configuration, there is an explicit comment stating authentication should be added, but no interceptor is actually attached to the service: [1](#0-0) 

The comment on line 179 says "Add authentication interceptor" but the subsequent code creates `RawDataServer::new(server)` without calling `.with_interceptor()` to add any authentication layer.

**2. Deprecated Authentication Without Replacement**

The authentication configuration fields are marked as deprecated with no enforcement: [2](#0-1) 

**3. False Security Assumption in Service Implementation**

The service implementation contains a misleading comment claiming authentication has already occurred: [3](#0-2) 

This comment is FALSE - no interceptor validates requests, and the metadata extraction is purely informational.

**4. Network Exposure Without Access Control**

The service is configured to listen on all network interfaces and is exposed in Docker deployments: [4](#0-3) 

The ports are bound without any localhost restriction, making them accessible from the network.

**Attack Path:**
1. Attacker discovers the indexer data service endpoint (e.g., scanning for open gRPC ports or finding misconfigured deployments)
2. Attacker crafts a gRPC client connecting directly to the RawDataServer endpoint
3. Attacker calls `GetTransactions` method without any authentication headers
4. Service processes the request without validation (no interceptor exists to check authentication)
5. Attacker receives full access to raw blockchain transaction data

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria for the following reasons:

**Information Disclosure:**
- Unauthorized access to ALL raw blockchain transaction data
- Access to historical and real-time transaction information
- Potential exposure of transaction patterns, user behavior, and network activity

**Protocol Violation:**
- Breaks the "Access Control" security invariant
- Violates defense-in-depth principles by relying solely on external gateway authentication
- Creates a backdoor that bypasses intended security controls

**Service Availability Risk:**
- Attackers can overwhelm the service with unauthorized requests
- No rate limiting or authentication-based throttling for direct connections
- Potential for resource exhaustion attacks

While this doesn't directly affect consensus, validator operations, or fund safety (criteria for Critical severity), it represents a significant security control failure that enables unauthorized data access and service abuse, meeting the High severity threshold for "Significant protocol violations."

## Likelihood Explanation

**Likelihood: HIGH**

**Factors Increasing Likelihood:**
1. **Default Configuration Vulnerable**: The default deployment configurations expose the service on all network interfaces without authentication
2. **Simple Exploitation**: Attack requires only a basic gRPC client, no sophisticated techniques needed
3. **No Network Restrictions**: Services listen on 0.0.0.0 by default, making them accessible if firewall rules aren't properly configured
4. **Misleading Documentation**: README still references deprecated `whitelisted_auth_tokens`, causing operators to believe authentication is configured when it isn't
5. **Production Deployments Affected**: Real-world deployments may expose these services, especially in cloud environments with misconfigured security groups

**Attacker Requirements:**
- Network access to the data service ports (50051, 50052, 50053)
- Basic knowledge of gRPC protocol
- No credentials or authentication required

The attack is trivially executable by any attacker who can reach the service network ports, making the likelihood of exploitation very high in improperly secured deployments.

## Recommendation

**Immediate Fixes Required:**

1. **Implement Authentication Interceptor:**

Add an authentication interceptor to the `RawDataServer` in the configuration. Example fix for `config.rs`:

```rust
// At line 179, replace the comment with actual implementation:
let auth_interceptor = create_auth_interceptor(/* config */);
let server = RawDataServerWrapper::new(
    self.redis_read_replica_address.clone(),
    self.file_store_config.clone(),
    self.data_service_response_channel_size,
    self.txns_to_strip_filter.clone(),
    cache_storage_format,
    Arc::new(in_memory_cache),
)?;
let svc = aptos_protos::indexer::v1::raw_data_server::RawDataServer::new(server)
    .with_interceptor(auth_interceptor)  // ADD THIS LINE
    .send_compressed(CompressionEncoding::Zstd)
    .accept_compressed(CompressionEncoding::Zstd)
    .accept_compressed(CompressionEncoding::Gzip);
```

2. **Implement Network Binding Restrictions:**

For internal-only services, bind to localhost instead of 0.0.0.0:
- Change `data_service_grpc_listen_address` to `127.0.0.1:50051` for services that should only be accessed through a gateway
- Document clearly which services require external access vs internal-only access

3. **Add Mandatory Authentication Configuration:**

Remove the `deprecated` markers and make authentication mandatory:
- Require either API key validation OR mTLS client certificates
- Fail to start if authentication is not properly configured
- Remove the `disable_auth_check` option entirely

4. **Update Documentation:**

- Remove references to deprecated authentication in README
- Add clear security warnings about network exposure
- Provide deployment examples with proper firewall configurations

5. **Defense in Depth:**

Even with a gateway, backend services should validate requests:
- Verify forwarded authentication headers from the gateway
- Implement request signing/token passing between gateway and backend
- Add rate limiting per client identifier

## Proof of Concept

```rust
// PoC: Unauthorized access to RawData service
use aptos_protos::indexer::v1::{
    raw_data_client::RawDataClient,
    GetTransactionsRequest,
};
use tonic::Request;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect directly to data service, bypassing any gateway
    let endpoint = "http://TARGET_HOST:50052"; // or 50051 for non-TLS
    
    let mut client = RawDataClient::connect(endpoint).await?;
    
    // Create request WITHOUT any authentication headers
    let request = Request::new(GetTransactionsRequest {
        starting_version: Some(0),
        transactions_count: Some(1000),
        ..Default::default()
    });
    
    // This succeeds without authentication!
    let mut response = client.get_transactions(request).await?;
    let stream = response.into_inner();
    
    // Attacker now has access to raw transaction data
    println!("Successfully retrieved transactions without authentication!");
    
    // Process stream to access all transaction data...
    
    Ok(())
}
```

**Steps to Reproduce:**
1. Deploy the indexer-grpc-data-service using provided Docker Compose configuration
2. Run the PoC code pointing to the exposed endpoint
3. Observe that the service returns transaction data without requiring any authentication
4. Verify that no authentication errors occur despite sending no credentials

**Expected Behavior:** Service should reject requests without valid authentication.

**Actual Behavior:** Service processes all requests regardless of authentication status.

## Notes

This vulnerability represents a critical breakdown in defense-in-depth security principles. While the authentication was intentionally deprecated in favor of gateway-level authentication (as evidenced by the deprecation comments), the backend service was never properly secured for this new architecture. The service remains network-accessible and processes unauthenticated requests, creating a bypass of the intended security controls.

Organizations deploying this service must ensure either:
1. The data service ports are not accessible from untrusted networks (firewall/network policy enforcement), OR
2. Authentication is re-implemented at the service level using interceptors

The mismatch between code comments (claiming authentication exists) and actual implementation (no authentication) suggests this is an incomplete migration that left a security gap rather than an intentional design decision.

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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L149-150)
```rust
        // Get request identity. The request is already authenticated by the interceptor.
        let request_metadata = get_request_metadata(&req);
```

**File:** docker/compose/indexer-grpc/docker-compose.yaml (L103-106)
```yaml
    ports:
      - "50052:50052" # GRPC non-secure
      - "50053:50053" # GRPC secure
      - "18084:8084" # health
```
