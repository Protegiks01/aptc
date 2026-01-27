# Audit Report

## Title
IPv4-Mapped IPv6 Address Bypass in Faucet IP Range Manager

## Summary
The `IpRangeManager` in the Aptos faucet fails to normalize IPv4-mapped IPv6 addresses (format `::ffff:x.x.x.x`), allowing attackers to bypass IP blocklists and preventing legitimate users from utilizing IP allowlists when connecting via dual-stack configurations.

## Finding Description

The `IpRangeManager` maintains separate lists for IPv4 and IPv6 address ranges and checks incoming requests against only the matching protocol version. [1](#0-0) 

However, IPv4-mapped IPv6 addresses (e.g., `::ffff:192.0.2.1`) are valid IPv6 addresses that represent IPv4 addresses. When a request arrives with such an address, it is parsed as `IpAddr::V6` by Rust's standard library and the poem framework's `RealIp` extractor. [2](#0-1) 

The `IpBlocklistChecker` then checks IPv6 addresses only against the IPv6 blocklist, missing any IPv4 blocklist entries. [3](#0-2) 

**Attack Scenario:**
1. Operator blocks abusive IPv4 address `192.0.2.1` in blocklist file
2. Attacker connects using IPv4-mapped IPv6 form `::ffff:192.0.2.1`
3. Address is parsed as `IpAddr::V6` variant
4. Checker only examines IPv6 blocklist
5. IPv4 blocklist entry is never checked
6. Attacker bypasses blocklist completely

The same issue affects `IpAllowlistBypasser` in reverse - legitimate users connecting via IPv6 won't match IPv4 allowlist entries. [4](#0-3) 

## Impact Explanation

**Severity Assessment: Low**

While this is a genuine security control bypass, it affects only the Aptos faucet service, which distributes testnet/devnet tokens with no real-world value. The impact is limited to:

- Potential faucet abuse and service degradation
- Inconsistent rate limiting across IPv4/IPv6
- Operator inability to effectively block malicious actors

This does **not** affect:
- Blockchain consensus mechanisms
- Move VM execution
- On-chain state or validator operations  
- Mainnet funds or assets

Per Aptos bug bounty criteria, this qualifies as **Low Severity** ("non-critical implementation bugs") rather than Medium or High severity, as no real funds are at risk and core blockchain functionality is unaffected.

## Likelihood Explanation

**Likelihood: High** among knowledgeable attackers

- IPv4-mapped IPv6 addresses are well-documented and widely known
- Many networks and proxies support dual-stack configurations
- Exploitation requires only basic networking knowledge
- No special privileges or insider access needed
- Simple to test and verify

However, exploitation is limited by:
- Attacker must first be blocklisted (or seek allowlist bypass)
- Requires IPv6 connectivity or proxy access
- Limited impact reduces attacker motivation

## Recommendation

Implement IPv4-mapped IPv6 address normalization in `IpRangeManager.contains_ip()`:

```rust
pub fn contains_ip(&self, ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => self.ipv4_list.contains(ipv4),
        IpAddr::V6(ipv6) => {
            // Check for IPv4-mapped IPv6 addresses (::ffff:0:0/96)
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                self.ipv4_list.contains(&ipv4)
            } else {
                self.ipv6_list.contains(ipv6)
            }
        }
    }
}
```

This ensures IPv4-mapped IPv6 addresses are checked against the IPv4 list, maintaining consistent security controls regardless of connection protocol.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_ipv4_mapped_ipv6_bypass() {
        // Create blocklist with IPv4 address
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "192.0.2.1/32").unwrap();
        
        let config = IpRangeManagerConfig {
            file: file.path().to_path_buf(),
        };
        let manager = IpRangeManager::new(config).unwrap();
        
        // IPv4 address is correctly blocked
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert!(manager.contains_ip(&ipv4), "IPv4 should be blocked");
        
        // IPv4-mapped IPv6 address BYPASSES the blocklist (vulnerability)
        let ipv4_mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201));
        assert!(!manager.contains_ip(&ipv4_mapped), 
            "BUG: IPv4-mapped IPv6 bypasses blocklist - should be blocked!");
    }
}
```

---

## Notes

**Important Clarification**: While this is a real implementation bug with a clear exploitation path, it does **not** meet the severity threshold required for this security audit exercise. The validation checklist requires "Impact meets Critical, High, or Medium severity criteria," but this issue only qualifies as Low severity since it:

1. Affects only the faucet service (not core blockchain components)
2. Involves test tokens with no real-world value
3. Does not impact consensus, execution, storage, governance, or staking
4. Cannot be escalated to compromise blockchain integrity

The original security question itself was marked as "(Low)" severity and focused on test coverage rather than core protocol vulnerabilities. Per the strict validation requirements emphasizing consensus, Move VM, and state management components, this finding falls below the required threshold.

### Citations

**File:** crates/aptos-faucet/core/src/common/ip_range_manager.rs (L55-60)
```rust
    pub fn contains_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => self.ipv4_list.contains(ipv4),
            IpAddr::V6(ipv6) => self.ipv6_list.contains(ipv6),
        }
    }
```

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L217-225)
```rust
        let source_ip = match source_ip.0 {
            Some(ip) => ip,
            None => {
                return Err(AptosTapError::new(
                    "No source IP found in the request".to_string(),
                    AptosTapErrorCode::SourceIpMissing,
                ))
            },
        };
```

**File:** crates/aptos-faucet/core/src/checkers/ip_blocklist.rs (L41-47)
```rust
            IpAddr::V6(source_ip) => {
                if self.manager.ipv6_list.contains(source_ip) {
                    return Ok(vec![RejectionReason::new(
                        format!("IP {} is in blocklist", source_ip),
                        RejectionReasonCode::IpInBlocklist,
                    )]);
                }
```

**File:** crates/aptos-faucet/core/src/bypasser/ip_allowlist.rs (L26-28)
```rust
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
        Ok(self.manager.contains_ip(&data.source_ip))
    }
```
