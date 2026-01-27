# Audit Report

## Title
Complete Security Bypass via Overly Permissive IP Allowlist Configuration in Aptos Faucet

## Summary
The Aptos Faucet's IP allowlist bypasser lacks validation for overly permissive CIDR ranges. If an administrator configures the allowlist with `0.0.0.0/0` (all IPv4) or `::/0` (all IPv6), every request from any IP address will bypass all security checks, including rate limiting, captcha validation, IP blocklists, and storage tracking. This enables complete drainage of faucet funds through unlimited requests.

## Finding Description

The `IpRangeManager` accepts any valid CIDR notation without validating the permissiveness of the range. [1](#0-0) 

When `IpAllowlistBypasser` checks if a request can bypass security checks, it delegates to `IpRangeManager::contains_ip`. [2](#0-1) 

If any bypasser returns `true`, the request skips all checkers entirely. [3](#0-2) 

The bypassed checkers include critical security controls:
- `IpBlocklistChecker` - IP blocklist validation
- `MemoryRatelimitChecker` and `RedisRatelimitChecker` - Rate limiting
- `GoogleCaptchaChecker` and `TapCaptchaChecker` - Captcha validation  
- `AuthTokenChecker` - Token validation
- `MagicHeaderChecker` - Header validation
- `RefererBlocklistChecker` - Referer validation

Additionally, bypassed requests skip the `complete()` step that tracks requests in storage. [4](#0-3) 

Bypassed requests can also use the higher `maximum_amount_with_bypass` funding limit. [5](#0-4) 

## Impact Explanation

**Critical Severity** - This qualifies as "Loss of Funds" under the Aptos bug bounty program. An attacker can:

1. **Drain the faucet completely** through unlimited requests without rate limiting
2. **Bypass all security controls** including captcha, blocklists, and authentication
3. **Avoid detection** as requests are not tracked in storage when bypassed
4. **Request maximum amounts** using the `maximum_amount_with_bypass` configuration

The faucet is a critical infrastructure component for Aptos testnets and developer onboarding. Complete drainage would:
- Halt all developer testing activities
- Block new user onboarding
- Require manual intervention and service restoration
- Potentially expose the misconfiguration to other attackers who monitor faucet activity

## Likelihood Explanation

**High Likelihood** - This vulnerability has a realistic attack path:

1. **Common configuration error**: An administrator testing the allowlist feature might add `0.0.0.0/0` to temporarily "allow all IPs" during debugging and forget to remove it before production deployment.

2. **No validation warnings**: The code provides no warnings, errors, or safeguards against overly permissive ranges. [1](#0-0) 

3. **Silent failure**: The misconfiguration doesn't cause any errors—it silently opens the faucet to all requesters.

4. **Easy exploitation**: Once misconfigured, any attacker can exploit it immediately by making multiple requests from any IP address, even from different IPs to avoid suspicion.

## Recommendation

Add validation in `IpRangeManager::new()` to reject or warn about overly permissive CIDR ranges:

```rust
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
                    // Reject overly permissive IPv4 ranges (e.g., /0 to /8)
                    if ipv4_net.prefix_len() < 16 {
                        bail!("IPv4 range {} is too permissive (prefix length < 16). This would allow too many addresses.", line);
                    }
                    ipv4_list.add(ipv4_net);
                },
                Err(_) => match line.parse::<Ipv6Net>() {
                    Ok(ipv6_net) => {
                        // Reject overly permissive IPv6 ranges (e.g., /0 to /48)
                        if ipv6_net.prefix_len() < 64 {
                            bail!("IPv6 range {} is too permissive (prefix length < 64). This would allow too many addresses.", line);
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

Additionally, consider:
1. **Configuration validation on startup** - Reject service startup if dangerous ranges are detected
2. **Monitoring and alerting** - Log warnings when wide ranges are configured  
3. **Documentation** - Clearly document the security implications of allowlist configuration

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_overly_permissive_ipv4_allowlist() {
        // Create a temporary file with 0.0.0.0/0
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "0.0.0.0/0").unwrap();
        
        let config = IpRangeManagerConfig {
            file: temp_file.path().to_path_buf(),
        };
        
        // This should succeed but creates a security vulnerability
        let manager = IpRangeManager::new(config).unwrap();
        
        // Verify that ANY IPv4 address matches
        assert!(manager.contains_ip(&"1.2.3.4".parse().unwrap()));
        assert!(manager.contains_ip(&"8.8.8.8".parse().unwrap()));
        assert!(manager.contains_ip(&"192.168.1.1".parse().unwrap()));
        assert!(manager.contains_ip(&"255.255.255.255".parse().unwrap()));
        
        // This means ALL requests would bypass security checks!
    }

    #[test]
    fn test_overly_permissive_ipv6_allowlist() {
        // Create a temporary file with ::/0
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "::/0").unwrap();
        
        let config = IpRangeManagerConfig {
            file: temp_file.path().to_path_buf(),
        };
        
        let manager = IpRangeManager::new(config).unwrap();
        
        // Verify that ANY IPv6 address matches
        assert!(manager.contains_ip(&"::1".parse().unwrap()));
        assert!(manager.contains_ip(&"2001:4860:4860::8888".parse().unwrap()));
        assert!(manager.contains_ip(&"fe80::1".parse().unwrap()));
        
        // This means ALL requests would bypass security checks!
    }
}
```

## Notes

This vulnerability is particularly critical because:

1. **Silent failure mode**: The misconfiguration produces no errors or warnings, making it easy to deploy to production accidentally

2. **Complete security bypass**: All faucet security mechanisms are disabled, not just rate limiting

3. **No audit trail**: Bypassed requests skip storage tracking, making post-incident investigation difficult

4. **Realistic scenario**: Configuration errors are common in production systems, especially during initial setup or testing phases

The fix should be implemented at the `IpRangeManager` level so it protects both the allowlist bypasser and any future uses of the IP range manager in blocklist contexts.

### Citations

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

**File:** crates/aptos-faucet/core/src/bypasser/ip_allowlist.rs (L24-29)
```rust
#[async_trait]
impl BypasserTrait for IpAllowlistBypasser {
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
        Ok(self.manager.contains_ip(&data.source_ip))
    }
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

**File:** crates/aptos-faucet/core/src/funder/common.rs (L176-185)
```rust
    pub fn get_maximum_amount(
        &self,
        // True if a Bypasser let the request bypass the Checkers.
        did_bypass_checkers: bool,
    ) -> Option<u64> {
        match (self.maximum_amount_with_bypass, did_bypass_checkers) {
            (Some(max), true) => Some(max),
            _ => self.maximum_amount,
        }
    }
```
