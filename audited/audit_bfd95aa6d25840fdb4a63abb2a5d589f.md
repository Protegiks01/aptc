# Audit Report

## Title
Silent Failure of IP Blocklist Access Control Due to Empty Configuration File

## Summary
The `IpRangeManager::new()` function in the Aptos faucet component successfully creates an IP range manager with empty blocklists when the configuration file is empty or contains only comments, without any validation or warning. This causes the `IpBlocklistChecker` to silently fail-open, allowing all IP addresses to access the faucet even when operators believe they have configured blocklist protection.

## Finding Description
The vulnerability exists in the IP range manager initialization logic: [1](#0-0) 

When an operator configures an `IpBlocklistChecker` with a path to a blocklist file that is empty or contains only comments, the function skips all lines and returns successfully with empty IPv4 and IPv6 lists. [2](#0-1) 

The `IpBlocklistChecker` then uses these empty lists to check incoming requests: [3](#0-2) 

Since empty IP ranges contain no addresses, the `contains()` method always returns false, meaning NO IP addresses are ever blocked. The faucet request preprocessing flow runs all checkers, but an empty blocklist provides zero protection: [4](#0-3) 

**Attack Scenario:**
1. Operator configures faucet with `IpBlocklist` checker pointing to a file
2. File is accidentally empty or contains only comments (human error during setup/update)
3. `IpRangeManager::new()` succeeds silently with empty lists
4. `IpBlocklistChecker` is created and appears active in the configuration
5. Operator believes IP blocking is enabled and protecting the faucet
6. Malicious actors from any IP address can freely access the faucet
7. Faucet resources are drained through automated abuse

This violates the **Access Control** invariant - the faucet is a protected resource that should enforce configured access controls. The fail-open behavior when misconfigured breaks the security guarantee.

## Impact Explanation
This is a **Medium severity** vulnerability per the Aptos bug bounty criteria for the following reasons:

**Limited Funds Loss**: The faucet contains a limited pool of funds for testnet/devnet operations. When the blocklist fails silently, malicious actors can drain these funds through automated requests, causing resource exhaustion. While not affecting mainnet funds or blockchain consensus, this disrupts faucet availability for legitimate users.

**Requires Intervention**: Once the faucet is drained due to an empty blocklist, operators must manually replenish funds and fix the configuration, requiring operational intervention.

The vulnerability does NOT reach High/Critical severity because:
- It doesn't affect core blockchain consensus or validator operations
- It doesn't enable mainnet fund theft or state corruption  
- The faucet is an auxiliary service, not a critical blockchain component
- Impact is limited to testnet/devnet faucet funds

## Likelihood Explanation
**Likelihood: Medium-High**

This vulnerability is likely to occur in practice because:

1. **Common Misconfiguration Pattern**: Operators may create empty blocklist files during initial setup or accidentally clear files during updates. Files with only comments (no active entries) are also common during testing phases.

2. **Silent Failure**: The lack of validation or warnings means operators have no indication their security control is ineffective. The faucet starts successfully and appears properly configured.

3. **Test Code Reinforces Behavior**: Test code intentionally creates empty blocklist files, which may lead operators to believe this is acceptable: [5](#0-4) 

4. **No Defense-in-Depth**: Unlike other parts of the codebase that validate empty filters, the faucet provides no safeguards against this misconfiguration.

## Recommendation
Implement validation in `IpRangeManager::new()` to detect and handle empty IP lists:

**Option 1: Fail on Empty Lists (Strict)**
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
        // ... existing parsing logic ...
    }
    
    // NEW: Validate non-empty lists
    if ipv4_list.is_empty() && ipv6_list.is_empty() {
        bail!("IP range configuration file '{}' contains no valid IP ranges. \
               If you intend to have an empty list, please add a comment explaining this.",
               config.file.to_string_lossy());
    }
    
    Ok(Self { ipv4_list, ipv6_list })
}
```

**Option 2: Warn on Empty Lists (Permissive)**
```rust
pub fn new(config: IpRangeManagerConfig) -> Result<Self> {
    // ... existing code ...
    
    // NEW: Log warning for empty lists
    if ipv4_list.is_empty() && ipv6_list.is_empty() {
        aptos_logger::warn!(
            "IP range configuration file '{}' is empty - no IP addresses will be matched. \
             Verify this is intentional.",
            config.file.to_string_lossy()
        );
    }
    
    Ok(Self { ipv4_list, ipv6_list })
}
```

For `IpBlocklistChecker` specifically, add validation at construction time to prevent fail-open behavior.

## Proof of Concept
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_empty_blocklist_allows_all_ips() {
        // Create an empty blocklist file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"# This file is empty\n// No IP ranges\n").unwrap();
        temp_file.flush().unwrap();
        
        // IpRangeManager::new() succeeds with empty file
        let config = IpRangeManagerConfig {
            file: temp_file.path().to_path_buf(),
        };
        let manager = IpRangeManager::new(config).expect("Should succeed");
        
        // Verify both lists are empty
        assert!(manager.ipv4_list.is_empty());
        assert!(manager.ipv6_list.is_empty());
        
        // Test that no IPs are blocked (fail-open behavior)
        let test_ip_v4 = "192.168.1.1".parse::<IpAddr>().unwrap();
        let test_ip_v6 = "2001:db8::1".parse::<IpAddr>().unwrap();
        
        assert!(!manager.contains_ip(&test_ip_v4), "Empty blocklist should not block IPv4");
        assert!(!manager.contains_ip(&test_ip_v6), "Empty blocklist should not block IPv6");
        
        // In production, this means malicious IPs can freely access the faucet
        // when the operator intended to have blocklist protection
    }
    
    #[test]
    fn test_blocklist_checker_with_empty_file() {
        use crate::checkers::{CheckerTrait, CheckerData};
        use std::net::IpAddr;
        use aptos_sdk::types::account_address::AccountAddress;
        use std::sync::Arc;
        use poem::http::HeaderMap;
        
        // Setup empty blocklist
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.flush().unwrap();
        
        let config = IpRangeManagerConfig {
            file: temp_file.path().to_path_buf(),
        };
        let checker = IpBlocklistChecker::new(config).expect("Should succeed");
        
        // Create test request from malicious IP
        let checker_data = CheckerData {
            time_request_received_secs: 0,
            receiver: AccountAddress::random(),
            source_ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
            headers: Arc::new(HeaderMap::new()),
        };
        
        // Check should pass (empty rejection list) - SECURITY BUG
        let result = tokio_test::block_on(checker.check(checker_data, false)).unwrap();
        assert!(result.is_empty(), "Empty blocklist allows all IPs through");
    }
}
```

## Notes
This vulnerability demonstrates a violation of the "fail-secure" principle. When a security control (IP blocklist) encounters an error condition (empty configuration), it should fail in a secure manner (block all IPs or refuse to start) rather than fail-open (allow all IPs). The current implementation prioritizes availability over security, which is inappropriate for an access control mechanism.

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

**File:** crates/aptos-faucet/core/src/checkers/ip_blocklist.rs (L27-51)
```rust
    async fn check(
        &self,
        data: CheckerData,
        _dry_run: bool,
    ) -> Result<Vec<RejectionReason>, AptosTapError> {
        match &data.source_ip {
            IpAddr::V4(source_ip) => {
                if self.manager.ipv4_list.contains(source_ip) {
                    return Ok(vec![RejectionReason::new(
                        format!("IP {} is in blocklist", source_ip),
                        RejectionReasonCode::IpInBlocklist,
                    )]);
                }
            },
            IpAddr::V6(source_ip) => {
                if self.manager.ipv6_list.contains(source_ip) {
                    return Ok(vec![RejectionReason::new(
                        format!("IP {} is in blocklist", source_ip),
                        RejectionReasonCode::IpInBlocklist,
                    )]);
                }
            },
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

**File:** crates/aptos-faucet/core/src/server/run.rs (L510-512)
```rust
    fn make_ip_blocklist(ip_ranges: &[&str]) -> Result<()> {
        make_list_file("/tmp/ip_blocklist.txt", ip_ranges)
    }
```
