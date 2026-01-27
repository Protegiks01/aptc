# Audit Report

## Title
IPv4-Mapped IPv6 Address Bypass in Faucet IP Blocklist

## Summary
The `IpRangeManager::contains_ip()` method does not normalize IPv4-mapped IPv6 addresses (e.g., `::ffff:192.0.2.1`) to their IPv4 equivalents before checking IP range lists. This allows attackers to bypass IP blocklists by representing their IPv4 address in IPv4-mapped IPv6 format, as the method only checks IPv6 addresses against the IPv6 list and IPv4 addresses against the IPv4 list separately.

## Finding Description
The faucet service uses `IpRangeManager` to maintain IP blocklists and allowlists for access control. The core issue is in the `contains_ip()` method: [1](#0-0) 

This method performs a simple pattern match on `IpAddr::V4` vs `IpAddr::V6` without checking if an IPv6 address is actually an IPv4-mapped IPv6 address. IPv4-mapped IPv6 addresses use the format `::ffff:x.x.x.x` to represent IPv4 addresses in IPv6 notation.

**Attack Scenario:**
1. Administrator adds `192.0.2.1/32` to the IP blocklist file (IPv4 format)
2. The `IpRangeManager` loads this into the `ipv4_list` during initialization [2](#0-1) 
3. Attacker connects from IP `192.0.2.1` via an IPv6-enabled path (dual-stack server or IPv6 reverse proxy)
4. The connection appears to the application as `::ffff:192.0.2.1` (IPv4-mapped IPv6)
5. When `IpAllowlistBypasser` checks the IP: [3](#0-2) 
6. The `contains_ip()` method matches `IpAddr::V6` branch and checks only `ipv6_list`
7. Since `::ffff:192.0.2.1` was never added to the IPv6 list, it returns `false`
8. The blocklist check is bypassed

The vulnerability also affects `IpBlocklistChecker`, which uses the same logic pattern: [4](#0-3) 

## Impact Explanation
This vulnerability allows attackers to bypass IP-based access controls on the faucet service. While the faucet is an auxiliary service for test networks, this represents a **Low to Medium severity** issue because:

- **Not blockchain-critical**: The faucet distributes test tokens and is not part of the core blockchain protocol (consensus, execution, storage, or governance)
- **Limited scope**: Only affects faucet access control, not blockchain security invariants
- **Potential abuse**: Allows blocklisted users to request test tokens, potentially enabling rate limit bypass or repeated abuse
- **DoS potential**: In production faucets, this could enable resource exhaustion attacks

The impact does not meet High or Critical severity criteria per the Aptos bug bounty program, as it does not affect validator nodes, consensus safety, blockchain funds, or network availability.

## Likelihood Explanation  
**Medium likelihood** in real-world deployments:

1. **Common in production**: Many faucets run behind IPv6-capable reverse proxies (nginx, HAProxy, Cloudflare) that may represent IPv4 clients as IPv4-mapped IPv6 addresses
2. **Dual-stack servers**: When the faucet binds to `::` (IPv6 any), IPv4 connections appear as IPv4-mapped IPv6 [5](#0-4) 
3. **Framework behavior**: The `poem` framework's `RealIp` extractor preserves the IP format from headers/sockets without normalization [6](#0-5) 

## Recommendation
Normalize IPv4-mapped IPv6 addresses before checking IP ranges:

```rust
pub fn contains_ip(&self, ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => self.ipv4_list.contains(ipv4),
        IpAddr::V6(ipv6) => {
            // Check if this is an IPv4-mapped IPv6 address
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                // Check against IPv4 list for IPv4-mapped addresses
                self.ipv4_list.contains(&ipv4)
            } else {
                self.ipv6_list.contains(ipv6)
            }
        }
    }
}
```

Additionally, consider normalizing IPs when loading from the configuration file to support both notations in the blocklist.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    
    #[test]
    fn test_ipv4_mapped_bypass() {
        // Create temporary blocklist file with IPv4 address
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "192.0.2.1/32").unwrap();
        
        // Initialize IpRangeManager
        let config = IpRangeManagerConfig {
            file: file.path().to_path_buf(),
        };
        let manager = IpRangeManager::new(config).unwrap();
        
        // IPv4 address is correctly blocked
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert!(manager.contains_ip(&ipv4), "IPv4 should be blocked");
        
        // IPv4-mapped IPv6 representation bypasses the blocklist
        let ipv4_mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201));
        assert!(!manager.contains_ip(&ipv4_mapped), 
                "BUG: IPv4-mapped IPv6 bypasses blocklist!");
    }
}
```

This test demonstrates that `192.0.2.1` in IPv4 format is blocked, but the same address in IPv4-mapped IPv6 format (`::ffff:192.0.2.1` = `::ffff:c000:0201`) bypasses the blocklist.

## Notes

While this is a **real vulnerability in the code**, it affects only the faucet service (an auxiliary development/testing tool) and does not impact the core Aptos blockchain security guarantees related to consensus, execution, storage, or governance. The severity is limited because the faucet distributes test tokens rather than assets with real value, and the service is not critical to blockchain operation.

### Citations

**File:** crates/aptos-faucet/core/src/common/ip_range_manager.rs (L35-38)
```rust
            match line.parse::<Ipv4Net>() {
                Ok(ipv4_net) => {
                    ipv4_list.add(ipv4_net);
                },
```

**File:** crates/aptos-faucet/core/src/common/ip_range_manager.rs (L55-60)
```rust
    pub fn contains_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => self.ipv4_list.contains(ipv4),
            IpAddr::V6(ipv6) => self.ipv6_list.contains(ipv6),
        }
    }
```

**File:** crates/aptos-faucet/core/src/bypasser/ip_allowlist.rs (L26-28)
```rust
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
        Ok(self.manager.contains_ip(&data.source_ip))
    }
```

**File:** crates/aptos-faucet/core/src/checkers/ip_blocklist.rs (L32-49)
```rust
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
```

**File:** crates/aptos-faucet/core/src/server/server_args.rs (L22-24)
```rust
    fn default_listen_address() -> String {
        "0.0.0.0".to_string()
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
