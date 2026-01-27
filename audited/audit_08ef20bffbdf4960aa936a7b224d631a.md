# Audit Report

## Title
Magic Header Authentication Bypass via Empty String Configuration

## Summary
The `MagicHeaderChecker` in the Aptos Faucet accepts an empty string as a valid `magic_header_value` configuration without validation, allowing attackers to trivially bypass this authentication mechanism by sending requests with the header key present but with an empty value. [1](#0-0) 

## Finding Description
The `MagicHeaderChecker` is designed as a shared-secret authentication mechanism for the Aptos Faucet API. It validates that incoming HTTP requests contain a specific header key-value pair before allowing token distribution. However, the implementation fails to validate that the configured `magic_header_value` is non-empty.

When an administrator configures `magic_header_value` as an empty string (either accidentally or assuming it disables the check), the security mechanism becomes bypassable. The comparison logic works correctly but accepts an insecure value: [2](#0-1) 

**Attack Flow:**
1. Administrator configures: `magic_header_value: ""` in the faucet configuration
2. The `new()` function accepts this configuration without validation
3. Attacker discovers or guesses the `magic_header_key` from documentation or configuration files
4. Attacker sends HTTP POST request to `/fund` endpoint with the header key set to empty value: `magic_header_key: `
5. Line 33-40: Header exists, passes first check
6. Line 42: Comparison `"" == ""` succeeds, passes second check
7. Line 51: Returns `Ok(vec![])` - request is allowed to proceed
8. Attacker successfully bypasses this authentication layer and receives tokens [3](#0-2) 

## Impact Explanation
This vulnerability allows bypassing an authentication/authorization layer in the Aptos Faucet, leading to unauthorized token distribution. According to the Aptos Bug Bounty severity criteria, this qualifies as **High Severity** due to:

- **API Abuse**: Attackers can abuse the faucet API to request tokens without proper authorization
- **Resource Exhaustion**: Repeated unauthorized requests can drain the faucet's token supply or overwhelm the service
- **Defense-in-Depth Bypass**: While other checkers (rate limiting, IP blocking) may still apply, this defeats one security layer

The faucet distributes substantial amounts per request: [4](#0-3) 

With configurable maximum amounts: [5](#0-4) 

While this affects testnet/devnet tokens (not mainnet funds), it represents a significant operational security issue that enables unauthorized access to faucet resources.

## Likelihood Explanation
**Likelihood: Medium to High**

This vulnerability is likely to occur because:
1. **Easy to Misconfigure**: Administrators might set empty string thinking it disables the check or as a placeholder
2. **No Validation Feedback**: The system accepts the configuration without warning
3. **Simple to Exploit**: Attacker only needs to know the header key and send empty value
4. **Common HTTP Pattern**: Empty header values are standard HTTP and easy to craft

Example misconfiguration: [6](#0-5) 

An administrator changing line 16 to `magic_header_value: ""` would enable this vulnerability with no error or warning.

## Recommendation
Add validation in the `MagicHeaderChecker::new()` function to reject empty or whitespace-only values:

```rust
pub fn new(config: MagicHeaderCheckerConfig) -> Result<Self> {
    if config.magic_header_key.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "magic_header_key cannot be empty or whitespace-only"
        ));
    }
    if config.magic_header_value.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "magic_header_value cannot be empty or whitespace-only"
        ));
    }
    Ok(Self { config })
}
```

Additionally, consider adding minimum length requirements (e.g., 16+ characters) to enforce strong secret values.

## Proof of Concept

**Setup**: Configure faucet with empty magic header value in `config.yaml`:
```yaml
checker_configs:
  - type: "MagicHeader"
    magic_header_key: "X-Faucet-Auth"
    magic_header_value: ""
```

**Exploit**: Send HTTP request with empty header value:
```bash
curl -X POST https://faucet.testnet.aptoslabs.com/fund \
  -H "X-Faucet-Auth: " \
  -H "Content-Type: application/json" \
  -d '{
    "address": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "amount": 100000000000
  }'
```

**Expected Result**: Request should be rejected due to invalid/empty magic header value.

**Actual Result**: Request is accepted and tokens are distributed because `"" == ""` comparison succeeds.

**Rust Unit Test**:
```rust
#[tokio::test]
async fn test_empty_magic_header_value_rejection() {
    let config = MagicHeaderCheckerConfig {
        magic_header_key: "X-Auth".to_string(),
        magic_header_value: "".to_string(),
    };
    
    // This should fail with the fix
    let result = MagicHeaderChecker::new(config);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot be empty"));
}
```

## Notes
While the magic header checker is only one component of the faucet's security stack, proper input validation on configuration prevents misconfigurations that could lead to unauthorized access. This finding emphasizes the importance of defense-in-depth and validating security-critical configuration parameters at initialization time.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/magic_header.rs (L20-23)
```rust
impl MagicHeaderChecker {
    pub fn new(config: MagicHeaderCheckerConfig) -> Result<Self> {
        Ok(Self { config })
    }
```

**File:** crates/aptos-faucet/core/src/checkers/magic_header.rs (L28-52)
```rust
    async fn check(
        &self,
        data: CheckerData,
        _dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError> {
        let header_value = match data.headers.get(&self.config.magic_header_key) {
            Some(header_value) => header_value,
            None => {
                return Ok(vec![RejectionReason::new(
                    format!("Magic header {} not found", self.config.magic_header_key),
                    RejectionReasonCode::MagicHeaderIncorrect,
                )])
            },
        };
        if header_value != &self.config.magic_header_value {
            return Ok(vec![RejectionReason::new(
                format!(
                    "Magic header value wrong {} not found",
                    self.config.magic_header_key
                ),
                RejectionReasonCode::MagicHeaderIncorrect,
            )]);
        }
        Ok(vec![])
    }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L261-278)
```rust
        // Ensure request passes checkers.
        let mut rejection_reasons = Vec::new();
        for checker in &self.checkers {
            rejection_reasons.extend(checker.check(checker_data.clone(), dry_run).await.map_err(
                |e| AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError),
            )?);
            if !rejection_reasons.is_empty() && self.return_rejections_early {
                break;
            }
        }

        if !rejection_reasons.is_empty() {
            return Err(AptosTapError::new(
                format!("Request rejected by {} checkers", rejection_reasons.len()),
                AptosTapErrorCode::Rejected,
            )
            .rejection_reasons(rejection_reasons));
        }
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L46-47)
```rust
/// Default amount of coins to fund in OCTA.
pub const DEFAULT_AMOUNT_TO_FUND: u64 = 100_000_000_000;
```

**File:** crates/aptos-faucet/core/src/funder/common.rs (L93-103)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionSubmissionConfig {
    /// Maximum amount of OCTA to give an account.
    maximum_amount: Option<u64>,

    /// With this it is possible to set a different maximum amount for requests that
    /// were allowed to skip the Checkers by a Bypasser. This can be helpful for CI,
    /// where we might need to mint a greater amount than is normally required in the
    /// standard case. If not given, maximum_amount is used whether the request
    /// bypassed the checks or not.
    maximum_amount_with_bypass: Option<u64>,
```

**File:** crates/aptos-faucet/configs/testing_checkers.yaml (L14-16)
```yaml
  - type: "MagicHeader"
    magic_header_key: "what_wallet_my_guy"
    magic_header_value: "the_wallet_that_rocks"
```
