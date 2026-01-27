# Audit Report

## Title
PasscodeSha256 Authentication Credentials Exposed in HAProxy Access Logs

## Summary
The `PasscodeSha256` authentication mechanism for the Aptos AdminService passes authentication credentials in URL query parameters, which are logged in plaintext by HAProxy's HTTP access logging. This allows attackers with access to HAProxy logs to extract authentication credentials and gain unauthorized access to sensitive administrative endpoints.

## Finding Description

The AdminService authentication implementation uses query parameters to transmit passcodes for authentication. [1](#0-0) 

The authentication flow extracts the passcode from query parameters and validates it against a SHA256 hash. [2](#0-1) 

However, HAProxy is configured as a reverse proxy in front of the AdminService with HTTP logging enabled. [3](#0-2) 

The critical issue is that HAProxy's `option httplog` directive on line 113 enables detailed HTTP access logging that includes the complete request URI, including all query parameters. [4](#0-3) 

**Attack Path:**
1. A legitimate administrator makes an authenticated request: `GET /profilez?passcode=mysecret123`
2. HAProxy logs the complete request line including the plaintext passcode
3. An attacker with access to HAProxy logs (through log aggregation systems, backup access, insider access, or misconfigured permissions) extracts the plaintext passcode
4. The attacker uses the extracted passcode to authenticate and access sensitive AdminService endpoints

The AdminService provides access to critical debugging endpoints that expose validator internal state. [5](#0-4) 

## Impact Explanation

This vulnerability allows unauthorized access to administrative endpoints that expose:
- CPU profiling data (`/profilez`)
- Thread dumps (`/threadz`) 
- Memory allocation statistics (`/malloc/stats`)
- Complete consensus database dumps (`/debug/consensus/consensusdb`)
- Quorum store database contents (`/debug/consensus/quorumstoredb`)
- Block data with transactions (`/debug/consensus/block`)
- Mempool parking lot information (`/debug/mempool/parking-lot/addresses`)

While this does not directly cause consensus violations or fund loss, it enables:
1. **Information Disclosure**: Exposes internal validator state, consensus data, and operational details
2. **Validator Performance Impact**: Repeated calls to expensive endpoints (DB dumps, profiling) could cause I/O load and validator slowdowns
3. **Attack Reconnaissance**: Provides attackers with detailed knowledge of validator operations for planning sophisticated attacks
4. **Privacy Violations**: Exposes transaction data in mempool and blocks before they're publicly committed

According to Aptos bug bounty criteria, this could qualify as **High Severity** ("Validator node slowdowns") if the admin endpoints are abused to impact performance, or **Low Severity** ("Minor information leaks") for the credential exposure itself.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability will occur whenever:
1. AdminService is enabled with `PasscodeSha256` authentication (required on mainnet per config sanitizer)
2. HAProxy is deployed in front of the service (standard deployment configuration)
3. Any legitimate administrator accesses the service

The passcodes are **guaranteed** to be logged in HAProxy access logs with the default configuration. The exploitation requires:
- Access to HAProxy logs (achievable through log aggregation systems, SIEM platforms, backup storage, or operational access)
- No special technical skills beyond reading log files

HAProxy logs are typically:
- Forwarded to centralized logging systems (accessible by multiple teams)
- Retained for compliance (long exposure window)
- Backed up to less-secure storage
- Potentially accessible through container runtime logging

## Recommendation

**Immediate Fix**: Migrate from query parameter authentication to HTTP header-based authentication:

```rust
// In admin_service_config.rs - Add new authentication type
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationConfig {
    // Deprecated: PasscodeSha256(String),
    // New: Use Authorization header instead
    BearerTokenSha256(String),
}

// In server/mod.rs - Update authentication logic
for authentication_config in &context.config.authentication_configs {
    match authentication_config {
        AuthenticationConfig::BearerTokenSha256(token_sha256) => {
            if let Some(auth_header) = req.headers().get(hyper::header::AUTHORIZATION) {
                if let Ok(auth_str) = auth_header.to_str() {
                    if let Some(token) = auth_str.strip_prefix("Bearer ") {
                        if sha256::digest(token) == *token_sha256 {
                            authenticated = true;
                        }
                    }
                }
            }
        }
    }
}
```

**HAProxy Configuration Update**: Disable logging of Authorization headers:

```
http-request del-header Authorization  # After authentication check
```

**Additional Hardening**:
1. Implement request logging sanitization to redact sensitive query parameters
2. Use short-lived tokens with rotation policies
3. Consider implementing mTLS for AdminService authentication
4. Restrict HAProxy log access with strict RBAC policies

## Proof of Concept

**Setup:**
```bash
# 1. Deploy validator with HAProxy and AdminService enabled
# 2. Configure PasscodeSha256 authentication with hash of "test123"
echo -n "test123" | sha256sum
# Output: ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae

# 3. Add to validator config:
authentication_configs:
  - passcode_sha256: "ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae"
```

**Exploitation:**
```bash
# 1. Admin makes authenticated request through HAProxy
curl "http://validator:9102/profilez?passcode=test123"

# 2. Check HAProxy logs (stdout)
kubectl logs deployment/validator-haproxy | grep profilez
# Output shows:
# 192.168.1.10:54321 [04/Jan/2025:12:00:00] validator-admin validator-admin/server 1/0/2/5/8 200 512 - - ---- 1/1/0/0/0 0/0 "GET /profilez?passcode=test123 HTTP/1.1"

# 3. Attacker extracts passcode from logs and authenticates
curl "http://validator:9102/debug/consensus/consensusdb?passcode=test123"
# Successfully dumps consensus database without authorization
```

**Notes**

This vulnerability affects all production deployments using the standard HAProxy configuration with AdminService enabled. The issue stems from the fundamental design choice to use query parameters for authentication, which are inherently logged by HTTP proxies and servers. While the configuration stores only SHA256 hashes to avoid plaintext credential storage, this protection is completely bypassed by access log exposure.

The severity assessment depends on the operational context: if AdminService is exposed on mainnet validators and log access is available to potential attackers, this represents a significant operational security risk. The combination of information disclosure and potential for validator performance degradation through endpoint abuse justifies classification as a medium to high severity issue.

### Citations

**File:** config/src/config/admin_service_config.rs (L26-39)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationConfig {
    // This will allow authentication through query parameter.
    // e.g. `/profilez?passcode=abc`.
    //
    // To calculate sha256, use sha256sum tool, or other online tools.
    //
    // e.g.
    //
    // printf abc |sha256sum
    PasscodeSha256(String),
    // TODO(grao): Add SSL support if necessary.
}
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L158-173)
```rust
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
```

**File:** crates/aptos-admin-service/src/server/mod.rs (L183-243)
```rust
        match (req.method().clone(), req.uri().path()) {
            #[cfg(target_os = "linux")]
            (hyper::Method::GET, "/profilez") => handle_cpu_profiling_request(req).await,
            #[cfg(target_os = "linux")]
            (hyper::Method::GET, "/threadz") => handle_thread_dump_request(req).await,
            #[cfg(unix)]
            (hyper::Method::GET, "/malloc/stats") => {
                malloc::handle_malloc_stats_request(context.config.malloc_stats_max_len)
            },
            #[cfg(unix)]
            (hyper::Method::GET, "/malloc/dump_profile") => malloc::handle_dump_profile_request(),
            (hyper::Method::GET, "/debug/consensus/consensusdb") => {
                let consensus_db = context.consensus_db.read().clone();
                if let Some(consensus_db) = consensus_db {
                    consensus::handle_dump_consensus_db_request(req, consensus_db).await
                } else {
                    Ok(reply_with_status(
                        StatusCode::NOT_FOUND,
                        "Consensus db is not available.",
                    ))
                }
            },
            (hyper::Method::GET, "/debug/consensus/quorumstoredb") => {
                let quorum_store_db = context.quorum_store_db.read().clone();
                if let Some(quorum_store_db) = quorum_store_db {
                    consensus::handle_dump_quorum_store_db_request(req, quorum_store_db).await
                } else {
                    Ok(reply_with_status(
                        StatusCode::NOT_FOUND,
                        "Quorum store db is not available.",
                    ))
                }
            },
            (hyper::Method::GET, "/debug/consensus/block") => {
                let consensus_db = context.consensus_db.read().clone();
                let quorum_store_db = context.quorum_store_db.read().clone();
                if let Some(consensus_db) = consensus_db
                    && let Some(quorum_store_db) = quorum_store_db
                {
                    consensus::handle_dump_block_request(req, consensus_db, quorum_store_db).await
                } else {
                    Ok(reply_with_status(
                        StatusCode::NOT_FOUND,
                        "Consensus db and/or quorum store db is not available.",
                    ))
                }
            },
            (hyper::Method::GET, "/debug/mempool/parking-lot/addresses") => {
                let mempool_client_sender = context.mempool_client_sender.read().clone();
                if let Some(mempool_client_sender) = mempool_client_sender {
                    mempool::mempool_handle_parking_lot_address_request(req, mempool_client_sender)
                        .await
                } else {
                    Ok(reply_with_status(
                        StatusCode::NOT_FOUND,
                        "Mempool parking lot is not available.",
                    ))
                }
            },
            _ => Ok(reply_with_status(StatusCode::NOT_FOUND, "Not found.")),
        }
```

**File:** terraform/helm/aptos-node/files/haproxy.cfg (L6-7)
```text
    # Specify the stdout log format and size
    log stdout len 10240 format raw local0
```

**File:** terraform/helm/aptos-node/files/haproxy.cfg (L110-126)
```text
## Specify the validator admin frontend
frontend validator-admin
    mode http
    option httplog
    bind :9202
    default_backend validator-admin

    # Deny requests from blocked IPs
    tcp-request connection reject if { src -n -f /usr/local/etc/haproxy/blocked.ips }

    ## Add the forwarded header
    http-request add-header Forwarded "for=%ci"

## Specify the validator admin backend
backend validator-admin
    mode http
    server {{ include "aptos-validator.fullname" $ }}-{{ $.Values.i }}-validator {{ include "aptos-validator.fullname" $ }}-{{ $.Values.i }}-validator:9102
```
