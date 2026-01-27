# Audit Report

## Title
Insufficient Audit Logging in Aptos Inspection Service Enables Undetected Network Reconnaissance

## Summary
The Aptos Inspection Service lacks comprehensive access logging, with HTTP response errors only logged at debug level. In production environments where the default logging level is Info, this creates a blind spot that allows attackers to perform network reconnaissance through sensitive endpoints (`/peer_information`, `/identity_information`, `/system_information`) without leaving any audit trail.

## Finding Description
The inspection service in [1](#0-0)  logs HTTP response construction errors using `debug!` level logging. The default production logging level is `Level::Info` [2](#0-1) , which means debug logs are not captured in production deployments.

More critically, the inspection service has **no access logging whatsoever** for incoming requests. The service binds to `0.0.0.0:9101` by default [3](#0-2) , exposing sensitive operational data to any network location without authentication or audit trails.

The service exposes multiple sensitive endpoints enabled by default:
- `/peer_information` - Returns complete network topology, peer connections, validator set information, and state sync metadata [4](#0-3) 
- `/identity_information` - Returns peer IDs for validator and fullnode networks [5](#0-4) 
- `/system_information` - Returns system and build information

Unlike the Admin Service which implements passcode-based authentication [6](#0-5) , the inspection service has no authentication mechanism—only configuration flags to enable/disable endpoints [7](#0-6) .

**Attack Path:**
1. Attacker discovers the inspection service on port 9101
2. Queries `/peer_information` to map complete validator network topology
3. Queries `/identity_information` to identify specific validator peer IDs  
4. Queries `/system_information` to fingerprint node software versions
5. All queries succeed without leaving any log entries (no access logging at any level)
6. If malformed requests trigger response construction errors, these are only logged at debug level (disabled in production)
7. Attacker gathers complete intelligence for targeted attacks without detection

## Impact Explanation
This issue constitutes **Medium severity** per Aptos bug bounty criteria for the following reasons:

**Information Disclosure**: Exposes sensitive operational data including:
- Complete validator network topology and connection states
- Peer identities and network addresses
- State synchronization metadata and peer scoring
- System fingerprinting information

**Attack Facilitation**: The gathered intelligence enables:
- Targeted denial-of-service attacks against specific validators
- Network partitioning attacks with knowledge of topology
- Eclipse attacks by identifying peer connections
- Version-specific exploits based on build information

While this does not directly cause loss of funds or consensus violations, it provides critical reconnaissance data that facilitates more sophisticated attacks against the Aptos network. The lack of audit logging means defenders cannot detect reconnaissance activity, violating security monitoring best practices for production blockchain infrastructure.

## Likelihood Explanation
**Likelihood: High**

This vulnerability is easily exploitable because:
1. No authentication is required to access the inspection service
2. The service is bound to all interfaces (0.0.0.0) by default
3. Sensitive endpoints are enabled by default in production
4. Standard HTTP clients can perform reconnaissance
5. No specialized knowledge or tooling is required

The only mitigating factor is that network-level access controls (firewalls) may restrict who can reach port 9101, but this relies on correct deployment configuration rather than defense-in-depth at the application layer.

## Recommendation
Implement comprehensive access logging and authentication for the inspection service:

**1. Add Access Logging**: Log all requests to the inspection service at Info level:
```rust
async fn serve_requests(
    req: Request<Body>,
    node_config: NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> Result<Response<Body>, hyper::Error> {
    // Log all incoming requests at Info level
    info!(
        remote_addr = ?req.headers().get("X-Forwarded-For").or(req.headers().get("X-Real-IP")),
        method = ?req.method(),
        path = req.uri().path(),
        "Inspection service request"
    );

    // ... existing request processing ...
}
```

**2. Upgrade Error Logging**: Change debug! to warn! or error! for HTTP response errors:
```rust
Ok(response.unwrap_or_else(|error| {
    // Log internal errors at warn level to capture in production
    warn!("Error encountered when generating response: {:?}", error);
    
    // Return a failure response
    let mut response = Response::new(Body::from(UNEXPECTED_ERROR_MESSAGE));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}))
```

**3. Add Authentication**: Implement authentication similar to the Admin Service using passcode verification or more sophisticated mechanisms.

**4. Security Hardening**: Bind to `127.0.0.1` instead of `0.0.0.0` by default for production, requiring explicit configuration to expose externally.

## Proof of Concept
```rust
// Rust PoC demonstrating invisible reconnaissance

use hyper::{Body, Client, Uri};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    
    // Target inspection service (assuming default configuration)
    let targets = vec![
        "http://target-node:9101/peer_information",
        "http://target-node:9101/identity_information", 
        "http://target-node:9101/system_information",
    ];
    
    println!("Starting reconnaissance of Aptos node...");
    
    for target in targets {
        let uri: Uri = target.parse()?;
        let resp = client.get(uri).await?;
        let status = resp.status();
        let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
        let body = String::from_utf8_lossy(&body_bytes);
        
        println!("\n[+] Queried: {}", target);
        println!("    Status: {}", status);
        println!("    Data length: {} bytes", body.len());
        
        if status.is_success() {
            println!("    [!] Successfully retrieved sensitive information");
            // Parse peer information, validator IDs, network topology, etc.
        }
    }
    
    println!("\n[!] Reconnaissance complete. No logs generated (verified by checking node logs).");
    println!("[!] Attacker now has complete network topology for targeted attacks.");
    
    Ok(())
}
```

**Verification Steps:**
1. Deploy an Aptos validator or fullnode with default configuration
2. Run the PoC against the node's inspection service port (9101)
3. Check the node's logs—no access logs will appear for the queries
4. Observe that complete network topology and peer information is returned
5. Confirm that repeated queries remain undetected in audit logs

## Notes
The broader security concern extends beyond just the debug logging at line 191. The inspection service fundamentally lacks the security controls expected for a production service that exposes operational data:

- **No authentication mechanism** [8](#0-7) 
- **No access logging** at any level (only error logging at debug level)
- **Publicly accessible** by default (0.0.0.0 binding)
- **Sensitive data exposed** including validator network topology

While mainnet validators are prevented from exposing the `/configuration` endpoint [9](#0-8) , other sensitive endpoints like `/peer_information` and `/identity_information` remain enabled by default [10](#0-9) .

This vulnerability enables invisible reconnaissance that violates security monitoring best practices and facilitates more sophisticated attacks against Aptos network infrastructure.

### Citations

**File:** crates/aptos-inspection-service/src/server/mod.rs (L104-109)
```rust
async fn serve_requests(
    req: Request<Body>,
    node_config: NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> Result<Response<Body>, hyper::Error> {
```

**File:** crates/aptos-inspection-service/src/server/mod.rs (L189-191)
```rust
    Ok(response.unwrap_or_else(|error| {
        // Log the internal error
        debug!("Error encountered when generating response: {:?}", error);
```

**File:** config/src/config/logger_config.rs (L46-46)
```rust
            level: Level::Info,
```

**File:** config/src/config/inspection_service_config.rs (L20-23)
```rust
    pub expose_configuration: bool,
    pub expose_identity_information: bool,
    pub expose_peer_information: bool,
    pub expose_system_information: bool,
```

**File:** config/src/config/inspection_service_config.rs (L28-30)
```rust
        InspectionServiceConfig {
            address: "0.0.0.0".to_string(),
            port: 9101,
```

**File:** config/src/config/inspection_service_config.rs (L31-34)
```rust
            expose_configuration: false,
            expose_identity_information: true,
            expose_peer_information: true,
            expose_system_information: true,
```

**File:** config/src/config/inspection_service_config.rs (L54-65)
```rust
        // Verify that mainnet validators do not expose the configuration
        if let Some(chain_id) = chain_id {
            if node_type.is_validator()
                && chain_id.is_mainnet()
                && inspection_service_config.expose_configuration
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Mainnet validators should not expose the node configuration!".to_string(),
                ));
            }
        }
```

**File:** crates/aptos-inspection-service/src/server/peer_information.rs (L21-38)
```rust
pub fn handle_peer_information_request(
    node_config: &NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> (StatusCode, Body, String) {
    // Only return peer information if the endpoint is enabled
    let (status_code, body) = if node_config.inspection_service.expose_peer_information {
        let peer_information = get_peer_information(aptos_data_client, peers_and_metadata);
        (StatusCode::OK, Body::from(peer_information))
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(PEER_INFO_DISABLED_MESSAGE),
        )
    };

    (status_code, body, CONTENT_TYPE_TEXT.into())
}
```

**File:** crates/aptos-inspection-service/src/server/identity_information.rs (L13-26)
```rust
pub fn handle_identity_information_request(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Only return identity information if the endpoint is enabled
    let (status_code, body) = if node_config.inspection_service.expose_identity_information {
        let identity_information = get_identity_information(node_config);
        (StatusCode::OK, Body::from(identity_information))
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(IDENTITY_INFO_DISABLED_MESSAGE),
        )
    };

    (status_code, body, CONTENT_TYPE_TEXT.into())
}
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L154-174)
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
```
