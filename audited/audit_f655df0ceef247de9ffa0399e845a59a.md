# Audit Report

## Title
Missing reCAPTCHA v3 Action Field Validation in Aptos Faucet Service

## Summary
The Google reCAPTCHA checker in the Aptos faucet does not validate the 'action' field in Google's reCAPTCHA v3 API response, allowing attackers to bypass the intended protection mechanism by reusing captcha tokens solved for different actions.

## Finding Description
The `check()` function in `CaptchaChecker` only validates the `success` field from Google's reCAPTCHA verification response, without verifying the `action`, `score`, or `hostname` fields that are critical for reCAPTCHA v3 security. [1](#0-0) 

When a reCAPTCHA v3 verification request is made to Google's API, the response includes:
- `success`: boolean indicating if the token is valid
- `action`: the action name specified when the captcha was executed client-side
- `score`: a risk score from 0.0 to 1.0
- `hostname`: the domain where the captcha was solved

The current implementation accepts any valid reCAPTCHA v3 token regardless of what action it was solved for. An attacker can:
1. Execute `grecaptcha.execute()` client-side with a low-value action (e.g., "newsletter", "contact")
2. Submit the resulting token in the `COMPLETED_CAPTCHA_TOKEN` header to the `/fund` endpoint
3. The server verifies the token with Google and receives `success: true` along with `action: "newsletter"`
4. The server approves the request because it only checks the `success` field [2](#0-1) 

## Impact Explanation
**Severity: Medium** - While this is a legitimate security issue, the impact is limited to testnet faucet abuse. The Aptos faucet is explicitly designed for test networks and distributes test tokens with no real economic value. [3](#0-2) 

The vulnerability allows:
- Bypassing reCAPTCHA-based rate limiting by solving captchas for multiple different actions
- Draining testnet faucet funds faster than intended
- Potential denial of service to legitimate testnet users

However, this does NOT affect:
- Mainnet operations or real funds
- Blockchain consensus or validator operations
- Core protocol security
- Production smart contracts or user assets

## Likelihood Explanation
**Likelihood: High** - The attack is straightforward to execute:
- Requires only basic HTTP client skills
- No special access or privileges needed
- Public reCAPTCHA v3 documentation describes the action field
- Attack can be automated

## Recommendation
Modify the `check()` function to validate all critical reCAPTCHA v3 response fields:

```rust
// Define expected action and minimum score as configuration
const EXPECTED_ACTION: &str = "fund_request";
const MIN_SCORE: f64 = 0.5;

// After parsing the response (line 102-104)
if resp["success"].as_bool().unwrap_or(false) {
    // Validate action field matches expected value
    let action = resp["action"].as_str().unwrap_or("");
    if action != EXPECTED_ACTION {
        debug!(
            message = "Captcha action mismatch",
            expected = EXPECTED_ACTION,
            actual = action
        );
        return Ok(vec![RejectionReason::new(
            format!("Invalid captcha action: expected '{}', got '{}'", EXPECTED_ACTION, action),
            RejectionReasonCode::CaptchaInvalid,
        )]);
    }
    
    // Validate score is above threshold (v3 only)
    let score = resp["score"].as_f64().unwrap_or(0.0);
    if score < MIN_SCORE {
        debug!(
            message = "Captcha score too low",
            score = score,
            threshold = MIN_SCORE
        );
        return Ok(vec![RejectionReason::new(
            format!("Captcha score {} below threshold {}", score, MIN_SCORE),
            RejectionReasonCode::CaptchaInvalid,
        )]);
    }
    
    // Optionally validate hostname matches expected domain
    
    return Ok(vec![]);
}
```

Also update `GoogleCaptchaCheckerConfig` to include the expected action and minimum score as configurable parameters.

## Proof of Concept

```bash
#!/bin/bash
# PoC: Abuse faucet with wrong-action captcha token

# Step 1: Get a reCAPTCHA v3 token for a different action (e.g., from a contact form)
# Client-side JS would execute: grecaptcha.execute('SITE_KEY', {action: 'contact'})
WRONG_ACTION_TOKEN="03AGdBq24..." # Token obtained for 'contact' action

# Step 2: Use this token to request faucet funds
curl -X POST https://faucet.testnet.aptoslabs.com/fund \
  -H "Content-Type: application/json" \
  -H "COMPLETED_CAPTCHA_TOKEN: $WRONG_ACTION_TOKEN" \
  -d '{
    "address": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "amount": 100000000
  }'

# Expected behavior (current): Request succeeds despite wrong action
# Expected behavior (after fix): Request fails with "Invalid captcha action" error
```

**Notes**

While this is a valid implementation flaw in the reCAPTCHA integration, its security impact is constrained to testnet faucet service abuse. This does not constitute a critical blockchain vulnerability affecting consensus, mainnet funds, or core protocol security. Organizations deploying production instances of the faucet should implement proper action field validation, score thresholds, and hostname verification for reCAPTCHA v3.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/google_captcha.rs (L77-93)
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

        let status_code = verify_result.status();
        let resp = verify_result
            .text()
            .await
            .map_err(|e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError))?;
```

**File:** crates/aptos-faucet/core/src/checkers/google_captcha.rs (L106-107)
```rust
            if resp["success"].as_bool().unwrap_or(false) {
                return Ok(vec![]);
```

**File:** crates/aptos-faucet/README.md (L1-3)
```markdown
# Aptos Faucet

The Aptos Faucet is a service that runs alongside a test network and mints coins for users to test and develop on Aptos.
```
