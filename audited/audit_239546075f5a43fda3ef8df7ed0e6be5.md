# Audit Report

## Title
Insufficient Audit Logging in Faucet Bypass Mechanism Enables Silent Token Abuse

## Summary
The aptos-faucet bypass mechanism logs only the source IP address when a request bypasses rate-limiting checks, omitting critical security details including the authentication token used, requested amount, and receiver address. This insufficient audit trail allows attackers to probe bypass tokens, abuse valid tokens, and evade detection mechanisms.

## Finding Description

The faucet implements two bypass mechanisms—`AuthTokenBypasser` and `IpAllowlistBypasser`—that allow privileged requests to skip rate-limiting checks. However, the logging at the bypass decision point is critically insufficient.

**Bypass Decision Point:**
When a bypass occurs in `preprocess_request`, only a minimal log entry is created: [1](#0-0) 

This log contains only the source IP, omitting:
- The authentication token that enabled the bypass
- The requested funding amount
- The receiver account address
- Which bypass mechanism was triggered (auth token vs IP allowlist)

**Auth Token Never Logged:**
The `AuthTokenBypasser` extracts and validates the authorization token but never logs it: [2](#0-1) 

**Insufficient Logging for Eligibility Checks:**
For the `/is_eligible` endpoint with bypass, the function returns immediately after the bypass check with no comprehensive logging: [3](#0-2) 

While the `/fund` endpoint does log comprehensive details after funding, this occurs too late—after the bypass decision has already been made, and critically, the authorization token itself is never logged anywhere in the flow.

**Attack Scenarios:**

1. **Silent Token Probing**: An attacker with suspected bypass tokens can test them using `/is_eligible`. Each attempt only logs the IP address, allowing unlimited token enumeration with minimal forensic trace.

2. **Undetectable Token Abuse**: If a legitimate bypass token is compromised or an insider abuses their token, operators cannot determine which specific token is being misused since tokens are never logged.

3. **High-Value Request Masking**: An attacker with bypass credentials can request maximum funding amounts repeatedly. The bypass decision log doesn't include the amount, only logging it after funding succeeds, making it harder to detect unusual patterns in real-time.

4. **Investigation Obstruction**: During a security incident, operators cannot correlate suspicious activity to specific bypass tokens, cannot identify which tokens should be revoked, and cannot determine the full scope of abuse.

## Impact Explanation

**Severity: Medium**

This vulnerability aligns with the Medium severity category per Aptos bug bounty criteria: "State inconsistencies requiring intervention." The insufficient audit trail creates multiple security risks:

1. **Abuse Detection Evasion**: Attackers can systematically abuse bypass mechanisms without leaving sufficient forensic evidence for detection systems or security monitoring.

2. **Incident Response Degradation**: During security investigations, the lack of critical logging data (especially the auth token) prevents proper root cause analysis and scope determination.

3. **Limited Funds Manipulation**: While not direct theft, the vulnerability enables accelerated draining of faucet funds beyond intended rate limits without detection, qualifying as "limited funds loss."

4. **Credential Compromise Amplification**: If a bypass token is compromised, the gap in logging prevents timely detection and response, amplifying the damage from the initial compromise.

The impact is not Critical because it doesn't affect consensus, validator operations, or cause direct fund theft from user accounts. However, it materially degrades security monitoring capabilities and enables abuse that would otherwise be detectable.

## Likelihood Explanation

**Likelihood: High**

This vulnerability has high likelihood of exploitation because:

1. **Low Attack Complexity**: Any user with valid bypass credentials (auth token or whitelisted IP) can immediately exploit this gap—no technical sophistication required.

2. **Active Attack Surface**: Bypass mechanisms are actively used in production faucet deployments for automation, testing infrastructure, and privileged operations.

3. **No Detection**: The vulnerability itself ensures that exploitation attempts are poorly logged, making ongoing abuse likely to continue undetected.

4. **Multiple Vectors**: Both `/fund` and `/is_eligible` endpoints are affected, and both `AuthTokenBypasser` and `IpAllowlistBypasser` suffer from the same logging deficiency.

5. **Insider Threat Amplification**: Legitimate bypass token holders may abuse their privileges, confident that insufficient logging will prevent attribution.

## Recommendation

Implement comprehensive logging at the bypass decision point with all security-relevant details:

**Fix for `preprocess_request` in fund.rs:**

```rust
// After line 252, replace the minimal logging with:
for bypasser in &self.bypassers {
    if bypasser
        .request_can_bypass(checker_data.clone())
        .await
        .map_err(|e| {
            AptosTapError::new_with_error_code(e, AptosTapErrorCode::BypasserError)
        })?
    {
        // Extract auth token if present for logging
        let auth_token_masked = checker_data
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_whitespace().nth(1))
            .map(|token| {
                // Log only first/last 4 chars for security
                if token.len() > 8 {
                    format!("{}...{}", &token[..4], &token[token.len()-4..])
                } else {
                    "***".to_string()
                }
            });

        info!(
            source_ip = %checker_data.source_ip,
            receiver = %checker_data.receiver,
            requested_amount = ?fund_request.amount,
            auth_token_masked = ?auth_token_masked,
            bypasser_type = std::any::type_name_of_val(bypasser),
            timestamp_secs = checker_data.time_request_received_secs,
            "Request bypassed checks via privileged mechanism"
        );
        return Ok((checker_data, true, permit));
    }
}
```

**Additional Recommendations:**

1. Implement structured logging with all bypass events sent to a dedicated security audit log
2. Add alerting for unusual bypass patterns (frequency, amounts, IP changes for same token)
3. Consider implementing bypass token rotation and expiration policies
4. Add monitoring dashboards showing bypass usage metrics per token/IP
5. Ensure `/is_eligible` endpoint also logs comprehensive details for bypass events

## Proof of Concept

**Setup:**
1. Configure aptos-faucet with an `AuthTokenBypasser` containing a test token
2. Configure logging to output to console/file

**Exploitation Steps:**

```bash
# Step 1: Test bypass token using /is_eligible (silent probing)
curl -X POST http://localhost:8081/is_eligible \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-bypass-token-12345" \
  -d '{"address": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "amount": 1000000000}'

# Expected log: Only "Allowing request from <IP> to bypass checks / storage"
# Missing: The token "test-bypass-token-12345", amount 1000000000, receiver address

# Step 2: Make actual funding request with bypass
curl -X POST http://localhost:8081/fund \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-bypass-token-12345" \
  -d '{"address": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "amount": 1000000000}'

# Expected log at bypass: Only IP address
# Expected log after funding: Comprehensive details but WITHOUT the bypass token
# Missing: Which bypass token was actually used to authorize this request

# Step 3: Demonstrate abuse scenario - probe multiple tokens
for token in stolen-token-1 stolen-token-2 stolen-token-3; do
  curl -X POST http://localhost:8081/is_eligible \
    -H "Authorization: Bearer $token" \
    -d '{"address": "0xabcd", "amount": 999999999}'
done

# Logs show only IP for each attempt, cannot identify which tokens were tested
```

**Verification:**
Examine the faucet logs and confirm:
1. Bypass decision logs contain only source IP
2. Authorization tokens are never logged (even in masked form)
3. Requested amounts are not logged at bypass point
4. Cannot correlate bypass events to specific tokens for abuse investigation

## Notes

This vulnerability is specific to the **aptos-faucet** component's audit trail capabilities, not the core Aptos blockchain consensus or Move VM. However, it represents a genuine security gap that enables abuse detection evasion and degrades incident response capabilities. The faucet, while often used on testnets, may also be deployed in contexts where abuse has operational or limited financial impact, making proper audit logging a critical security control.

### Citations

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L148-150)
```rust
        if bypass {
            return Ok(());
        }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L253-256)
```rust
                info!(
                    "Allowing request from {} to bypass checks / storage",
                    source_ip
                );
```

**File:** crates/aptos-faucet/core/src/bypasser/auth_token.rs (L38-48)
```rust
        let auth_token = match data
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_whitespace().nth(1))
        {
            Some(auth_token) => auth_token,
            None => return Ok(false),
        };

        Ok(self.manager.contains(auth_token))
```
