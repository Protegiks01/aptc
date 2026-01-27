# Audit Report

## Title
Missing Validation for Trivially Bypassable IP Allowlist Configuration in Faucet Bypasser

## Summary
The `BypasserConfig::build()` function and underlying `IpRangeManager::new()` implementation fail to validate that IP allowlist ranges are not overly permissive. An administrator can misconfigure the faucet with ranges like `0.0.0.0/0` or `::/0`, which would allow ALL requests to bypass security controls including rate limiting, CAPTCHA verification, IP blocklists, and fraud prevention mechanisms. [1](#0-0) 

## Finding Description
The faucet's bypasser system allows certain trusted requests to skip all security checks. When configured with an `IpAllowlist` bypasser, the system loads IP ranges from a file and checks if incoming requests match these ranges.

The vulnerability exists in the configuration validation chain:

1. **No validation in build()**: The `BypasserConfig::build()` function simply delegates to `IpAllowlistBypasser::new()` without any validation of the configuration parameters.

2. **No validation in IpRangeManager**: The `IpRangeManager::new()` function accepts any valid CIDR notation, including dangerously broad ranges like `0.0.0.0/0` (all IPv4 addresses) or `::/0` (all IPv6 addresses). [2](#0-1) 

3. **Complete bypass of security controls**: When a bypasser matches a request, the `preprocess_request()` function returns early, skipping all checker validation. [3](#0-2) 

4. **No rate limiting or storage tracking**: Bypassed requests also skip the completion steps where checkers would normally track requests in storage for rate limiting. [4](#0-3) 

5. **Potential for unlimited fund drainage**: If `maximum_amount_with_bypass` is not configured in `TransactionSubmissionConfig`, the `get_amount()` function will allow ANY requested amount without limits. [5](#0-4) 

**Attack Scenario:**
1. Administrator misconfigures faucet with IP allowlist file containing `0.0.0.0/0`
2. Fails to configure `maximum_amount_with_bypass` parameter
3. Attacker sends unlimited funding requests from any IP address
4. All requests bypass: rate limiting, CAPTCHA, IP blocklist, referer blocklist, auth token checks
5. Each request can specify arbitrarily large amounts (if no bypass limit configured)
6. Faucet account is rapidly drained

## Impact Explanation
This qualifies as **HIGH severity** per Aptos bug bounty criteria:

- **Significant protocol violations**: Complete bypass of all faucet security controls designed to prevent abuse
- **API service disruption**: Faucet can be drained, rendering it unavailable for legitimate users
- **Potential fund loss**: If `maximum_amount_with_bypass` is not configured, attackers can drain the entire faucet balance

Even with amount limits configured, the complete bypass of rate limiting means attackers can:
- Make unlimited requests without CAPTCHA verification
- Bypass IP blocklists designed to stop known malicious actors
- Circumvent memory/Redis-based rate limiting mechanisms
- Avoid referer blocklist checks

This transforms the faucet's security model from defense-in-depth to completely open access.

## Likelihood Explanation
**Likelihood: MEDIUM to HIGH**

The vulnerability requires administrator misconfiguration, but this is realistic because:

1. **No validation feedback**: The system accepts the dangerous configuration silently without warnings or errors
2. **Easy to misconfigure**: Administrators might use `0.0.0.0/0` for testing and forget to restrict it in production
3. **No documentation warnings**: There are no clear warnings about the dangers of overly broad IP ranges
4. **Multiple failure points**: The vulnerability manifests if either the IP range is too broad OR the amount limits are not configured

Similar configuration errors are common in production systems when operators don't fully understand the security implications of allowlist configurations.

## Recommendation

Add validation to `BypasserConfig::build()` and `IpRangeManager::new()` to reject overly permissive IP ranges:

```rust
// In crates/aptos-faucet/core/src/common/ip_range_manager.rs

impl IpRangeManager {
    pub fn new(config: IpRangeManagerConfig) -> Result<Self> {
        let file = File::open(&config.file)
            .with_context(|| format!("Failed to open {}", config.file.to_string_lossy()))?;

        let mut ipv4_list = IpRange::<Ipv4Net>::new();
        let mut ipv6_list = IpRange::<Ipv6Net>::new();
        for line in std::io::BufReader::new(file).lines() {
            let line = line?;
            if line.starts_with('#') || line.starts_with("//") || line.is_empty() {
                continue;
            }
            match line.parse::<Ipv4Net>() {
                Ok(ipv4_net) => {
                    // VALIDATION: Reject overly permissive ranges
                    if ipv4_net.prefix_len() < 8 {
                        bail!("IP range too broad (prefix < 8): {}. This would bypass security for too many IPs.", line);
                    }
                    // Reject ranges that would match all IPs
                    if ipv4_net.addr().is_unspecified() && ipv4_net.prefix_len() == 0 {
                        bail!("Rejecting 0.0.0.0/0 - this would bypass security for ALL IPv4 addresses");
                    }
                    ipv4_list.add(ipv4_net);
                },
                Err(_) => match line.parse::<Ipv6Net>() {
                    Ok(ipv6_net) => {
                        // VALIDATION: Reject overly permissive IPv6 ranges
                        if ipv6_net.prefix_len() < 64 {
                            bail!("IPv6 range too broad (prefix < 64): {}. This would bypass security for too many IPs.", line);
                        }
                        if ipv6_net.addr().is_unspecified() && ipv6_net.prefix_len() == 0 {
                            bail!("Rejecting ::/0 - this would bypass security for ALL IPv6 addresses");
                        }
                        ipv6_list.add(ipv6_net);
                    },
                    Err(_) => {
                        bail!("Failed to parse line as IPv4 or IPv6 range: {}", line);
                    },
                },
            }
        }
        Ok(Self {
            ipv4_list,
            ipv6_list,
        })
    }
}
```

Additionally, add validation in `BypasserConfig::build()` to ensure that if bypassers are configured, amount limits must also be configured:

```rust
// In crates/aptos-faucet/core/src/bypasser/mod.rs or configuration loading

// Validate that if bypassers exist, appropriate limits are configured
// This should be done at server startup in the configuration validation
```

## Proof of Concept

**Step 1**: Create a malicious IP allowlist configuration file:
```bash
# /tmp/malicious_allowlist.txt
0.0.0.0/0
```

**Step 2**: Configure the faucet with this allowlist:
```yaml
# configs/malicious_config.yaml
bypassers:
  - type: IpAllowlist
    file: /tmp/malicious_allowlist.txt

transaction_submission_config:
  # Note: maximum_amount_with_bypass is NOT configured
  maximum_amount: 100000000  # 0.1 APT for normal requests
```

**Step 3**: Rust test to demonstrate the issue:
```rust
#[tokio::test]
async fn test_overly_permissive_bypasser_accepted() {
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    // Create a temp file with 0.0.0.0/0
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "0.0.0.0/0").unwrap();
    
    let config = IpRangeManagerConfig {
        file: temp_file.path().to_path_buf(),
    };
    
    // This should FAIL but currently SUCCEEDS
    let result = IpRangeManager::new(config);
    assert!(result.is_ok(), "VULNERABILITY: Overly permissive range accepted!");
    
    let manager = result.unwrap();
    
    // Verify that ANY IP address matches
    assert!(manager.contains_ip(&"1.2.3.4".parse().unwrap()));
    assert!(manager.contains_ip(&"8.8.8.8".parse().unwrap()));
    assert!(manager.contains_ip(&"192.168.1.1".parse().unwrap()));
    assert!(manager.contains_ip(&"10.0.0.1".parse().unwrap()));
    
    println!("CONFIRMED: All IP addresses bypass security checks!");
}
```

**Expected Behavior**: The configuration should be rejected with a clear error message.

**Actual Behavior**: The configuration is accepted, and all requests from any IP address bypass all security controls.

### Citations

**File:** crates/aptos-faucet/core/src/bypasser/mod.rs (L37-45)
```rust
    pub fn build(self) -> Result<Bypasser> {
        Ok(match self {
            BypasserConfig::AuthToken(config) => Bypasser::from(AuthTokenBypasser::new(config)?),

            BypasserConfig::IpAllowlist(config) => {
                Bypasser::from(IpAllowlistBypasser::new(config)?)
            },
        })
    }
```

**File:** crates/aptos-faucet/core/src/common/ip_range_manager.rs (L24-53)
```rust
    pub fn new(config: IpRangeManagerConfig) -> Result<Self> {
        let file = File::open(&config.file)
            .with_context(|| format!("Failed to open {}", config.file.to_string_lossy()))?;

        let mut ipv4_list = IpRange::<Ipv4Net>::new();
        let mut ipv6_list = IpRange::<Ipv6Net>::new();
        for line in std::io::BufReader::new(file).lines() {
            let line = line?;
            if line.starts_with('#') || line.starts_with("//") || line.is_empty() {
                continue;
            }
            match line.parse::<Ipv4Net>() {
                Ok(ipv4_net) => {
                    ipv4_list.add(ipv4_net);
                },
                Err(_) => match line.parse::<Ipv6Net>() {
                    Ok(ipv6_net) => {
                        ipv6_list.add(ipv6_net);
                    },
                    Err(_) => {
                        bail!("Failed to parse line as IPv4 or IPv6 range: {}", line);
                    },
                },
            }
        }
        Ok(Self {
            ipv4_list,
            ipv6_list,
        })
    }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L244-259)
```rust
        // See if this request meets the criteria to bypass checkers / storage.
        for bypasser in &self.bypassers {
            if bypasser
                .request_can_bypass(checker_data.clone())
                .await
                .map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::BypasserError)
                })?
            {
                info!(
                    "Allowing request from {} to bypass checks / storage",
                    source_ip
                );
                return Ok((checker_data, true, permit));
            }
        }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L332-347)
```rust
        if !bypass {
            let response_is_500 = match &fund_result {
                Ok(_) => false,
                Err(e) => e.error_code.status().is_server_error(),
            };
            let complete_data = CompleteData {
                checker_data,
                txn_hashes: txn_hashes.clone(),
                response_is_500,
            };
            for checker in &self.checkers {
                checker.complete(complete_data.clone()).await.map_err(|e| {
                    AptosTapError::new_with_error_code(e, AptosTapErrorCode::CheckerError)
                })?;
            }
        }
```

**File:** crates/aptos-faucet/core/src/funder/mint.rs (L540-550)
```rust
    fn get_amount(&self, amount: Option<u64>, did_bypass_checkers: bool) -> u64 {
        match (
            amount,
            self.txn_config.get_maximum_amount(did_bypass_checkers),
        ) {
            (Some(amount), Some(maximum_amount)) => std::cmp::min(amount, maximum_amount),
            (Some(amount), None) => amount,
            (None, Some(maximum_amount)) => std::cmp::min(self.amount_to_fund, maximum_amount),
            (None, None) => self.amount_to_fund,
        }
    }
```
