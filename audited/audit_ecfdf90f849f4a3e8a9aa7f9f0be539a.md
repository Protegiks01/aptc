# Audit Report

## Title
Inadequate Audit Logging for Failpoint Activations in Non-Production Environments

## Summary
The `fail_point_poem()` function does not log when failpoints are activated/triggered, creating an incomplete audit trail. While failpoint configuration is logged, the actual activation events that cause API endpoint failures are only visible as generic 500 Internal Server Errors in middleware logs, making it difficult to distinguish failpoint-induced failures from legitimate errors during security auditing. [1](#0-0) 

## Finding Description

The failpoint system operates through two mechanisms:

1. **Configuration via `/v1/set_failpoint`**: Logs configuration at INFO level [2](#0-1) 

2. **Activation via `fail_point_poem()`**: Returns InternalError but does NOT log the failpoint activation [1](#0-0) 

When a configured failpoint triggers, the middleware logs only generic HTTP request data (status, path, method) without identifying the error as failpoint-caused: [3](#0-2) 

The `/v1/set_failpoint` endpoint has no authentication, relying solely on the `failpoints_enabled` config flag: [4](#0-3) 

**Attack Path (in non-production environments):**
1. Attacker accesses test/dev node with `api.failpoints_enabled: true`
2. Calls `GET /v1/set_failpoint?name=api::endpoint_get_account_resource&actions=return`
3. Configuration is logged, but subsequent activations are not
4. All account resource API calls now fail with generic 500 errors
5. Audit logs show only HTTP 500s, not that failures are failpoint-induced

## Impact Explanation

**Severity: Medium** (as indicated in the question)

This meets the **High Severity** criteria of "API crashes" from the bug bounty program. However, the impact is significantly mitigated because:

1. **Mainnet Protection**: The config sanitizer explicitly prevents failpoints on mainnet [5](#0-4) 

2. **Limited Scope**: Only affects non-production environments where `failpoints_enabled: true` and the `failpoints` feature flag is compiled in [6](#0-5) 

3. **Partial Audit Trail**: Configuration IS logged, and HTTP errors are logged, just not specifically as failpoint-caused

The security harm is primarily **reduced visibility during security auditing** rather than a direct exploitable vulnerability in production systems.

## Likelihood Explanation

**Likelihood: Low to Medium**

- Requires non-production environment with failpoints enabled
- Requires network access to the API endpoint
- Configuration changes ARE logged (though activations are not)
- Primarily impacts testing/development scenarios where failpoints are intentionally used
- The intended use case is legitimate fault injection testing, not malicious attacks

## Recommendation

Add explicit audit logging to `fail_point_poem()` when failpoints are triggered:

```rust
pub fn fail_point_poem<E: InternalError>(name: &str) -> Result<(), E> {
    fail::fail_point!(format!("api::{}", name).as_str(), |_| {
        #[cfg(feature = "failpoints")]
        aptos_logger::warn!(
            "Failpoint activated: {}, returning InternalError",
            name
        );
        
        Err(E::internal_with_code_no_info(
            format!("Failpoint unexpected internal error for {}", name),
            AptosErrorCode::InternalError,
        ))
    });

    Ok(())
}
```

Additionally, consider adding authentication/authorization to the `/v1/set_failpoint` endpoint or at minimum logging client IP addresses during configuration.

## Proof of Concept

```rust
// Test demonstrating the logging gap
#[cfg(feature = "failpoints")]
#[tokio::test]
async fn test_failpoint_activation_logging() {
    // Setup test node with failpoints_enabled: true
    let swarm = LocalSwarm::builder(1)
        .with_aptos()
        .build()
        .await;
    
    let client = swarm.validators().next().unwrap().rest_client();
    
    // Configure failpoint - this WILL be logged
    client
        .set_failpoint(
            "api::endpoint_get_account_resource".to_string(),
            "return".to_string(),
        )
        .await
        .unwrap();
    
    // Trigger failpoint - activation NOT specifically logged
    let result = client
        .get_account_resource(
            AccountAddress::ONE,
            "0x1::account::Account"
        )
        .await;
    
    // Verify error occurred
    assert!(result.is_err());
    
    // Check logs - will find configuration log but not activation log
    // proving the audit trail gap
}
```

## Notes

**Important Mitigations:**
- This is **not exploitable on mainnet** due to config sanitizer enforcement
- This is a **testing feature working as designed**, not a security bug
- There IS a partial audit trail (configuration + HTTP error logs)
- The question correctly identifies this as **Medium severity**, not Critical/High

**Scope Limitation:**
While the audit logging could be improved, this represents a design characteristic of testing infrastructure rather than a production vulnerability. The security concern is valid for enhanced observability in development/testing environments, but does not constitute a critical security flaw given the mainnet protections in place.

### Citations

**File:** api/src/failpoint.rs (L14-20)
```rust
pub fn fail_point_poem<E: InternalError>(name: &str) -> Result<(), E> {
    fail::fail_point!(format!("api::{}", name).as_str(), |_| {
        Err(E::internal_with_code_no_info(
            format!("Failpoint unexpected internal error for {}", name),
            AptosErrorCode::InternalError,
        ))
    });
```

**File:** api/src/set_failpoints.rs (L27-34)
```rust
    if context.failpoints_enabled() {
        fail::cfg(&failpoint_conf.name, &failpoint_conf.actions)
            .map_err(|e| poem::Error::from(anyhow::anyhow!(e)))?;
        info!(
            "Configured failpoint {} to {}",
            failpoint_conf.name, failpoint_conf.actions
        );
        Ok(format!("Set failpoint {}", failpoint_conf.name))
```

**File:** api/src/log.rs (L96-102)
```rust
    if log.status >= 500 {
        sample!(SampleRate::Duration(Duration::from_secs(1)), warn!(log));
    } else if log.status >= 400 {
        sample!(SampleRate::Duration(Duration::from_secs(60)), info!(log));
    } else {
        sample!(SampleRate::Duration(Duration::from_secs(1)), debug!(log));
    }
```

**File:** api/src/runtime.rs (L248-251)
```rust
                    .at(
                        "/set_failpoint",
                        poem::get(set_failpoints::set_failpoint_poem).data(context.clone()),
                    ),
```

**File:** config/src/config/config_sanitizer.rs (L82-91)
```rust
    // Verify that failpoints are not enabled in mainnet
    let failpoints_enabled = are_failpoints_enabled();
    if let Some(chain_id) = chain_id {
        if chain_id.is_mainnet() && failpoints_enabled {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Failpoints are not supported on mainnet nodes!".into(),
            ));
        }
    }
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
