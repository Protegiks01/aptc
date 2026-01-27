# Audit Report

## Title
IPv4-Mapped IPv6 Address Blocklist Bypass in Aptos Faucet

## Summary
The Aptos faucet's IP blocklist implementation fails to handle IPv4-mapped IPv6 addresses (e.g., `::ffff:192.0.2.1`), allowing attackers to bypass IP-based blocking by switching between IPv4 and IPv6 representations of the same address.

## Finding Description

The IP blocklist checker maintains separate lists for IPv4 and IPv6 addresses and checks them independently based on the IpAddr enum variant. [1](#0-0) 

When an IP address is checked, the code matches on the enum variant and only searches the corresponding list: [2](#0-1) 

The vulnerability occurs because:

1. **Pure IPv6 notation variations are NOT vulnerable**: Different representations like `::1` vs `0:0:0:0:0:0:0:1` parse to identical internal representations in Rust's `Ipv6Addr` and compare as equal - this works correctly.

2. **IPv4-mapped IPv6 addresses ARE vulnerable**: An IPv4 address `192.0.2.1` and its IPv4-mapped IPv6 equivalent `::ffff:192.0.2.1` are stored in separate lists (`ipv4_list` and `ipv6_list`) and never cross-checked.

**Attack Scenario 1 - IPv4 Blocklisted, Attacker Uses IPv6:**
- Admin adds `192.0.2.1` to blocklist → stored in `ipv4_list` [3](#0-2) 
- Attacker connects from `::ffff:192.0.2.1` (IPv4-mapped IPv6)
- Checker receives `IpAddr::V6` variant and only checks `ipv6_list` [4](#0-3) 
- Address not found in `ipv6_list` → **Bypass successful**

**Attack Scenario 2 - IPv6 Blocklisted, Attacker Uses IPv4:**
- Admin adds `::ffff:192.0.2.1` to blocklist → stored in `ipv6_list`
- Attacker connects from `192.0.2.1` (pure IPv4)
- Checker receives `IpAddr::V4` variant and only checks `ipv4_list`
- Address not found in `ipv4_list` → **Bypass successful**

The faucet explicitly supports proxy headers (X-Forwarded-For, X-Real-IP) which are parsed by the poem framework's RealIp extractor: [5](#0-4) 

In dual-stack network deployments, when a server binds to an IPv6 socket with `IPV6_V6ONLY=0` (common default), IPv4 connections are presented as IPv4-mapped IPv6 addresses by the operating system. An attacker can exploit this by:
- Connecting via IPv4 protocol (appears as IPv4-mapped IPv6 to application)
- Or connecting via IPv6 protocol if they have dual-stack connectivity
- Or manipulating proxy headers if the proxy doesn't normalize IPv4-mapped addresses

## Impact Explanation

This vulnerability allows attackers to completely bypass the IP blocklist, undermining a critical security control for the faucet service. The impact includes:

- **Abuse Prevention Bypass**: Attackers can continue requesting faucet funds after being blocklisted
- **Rate Limiting Evasion**: Combined with other rate limiting bypasses, this enables sustained abuse
- **Resource Exhaustion**: Blocked malicious actors can drain faucet funds intended for legitimate users

While the faucet itself is not part of the core blockchain consensus, per Aptos bug bounty criteria, this constitutes a **High Severity** issue as it represents a "significant protocol violation" of the faucet's security controls and could lead to API service degradation through abuse.

## Likelihood Explanation

**Likelihood: High**

The vulnerability is highly likely to be exploited because:

1. **Common Network Configuration**: Dual-stack IPv4/IPv6 deployments are standard for modern cloud infrastructure and Kubernetes environments
2. **OS Default Behavior**: Most operating systems present IPv4 connections on IPv6 sockets as IPv4-mapped addresses by default
3. **Attacker Control**: Attackers with dual-stack connectivity can trivially choose which protocol to use
4. **Proxy Complications**: The faucet's proxy support adds another vector if proxies don't normalize addresses
5. **No Detection**: The current implementation has no logging or alerting for this bypass pattern

## Recommendation

Implement IPv4-mapped IPv6 address normalization before checking the blocklist. Add this method to `IpRangeManager`:

```rust
impl IpRangeManager {
    // Normalize IPv4-mapped IPv6 addresses to pure IPv4
    fn normalize_ip(ip: &IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => {
                // Check if this is an IPv4-mapped IPv6 address (::ffff:0:0/96)
                if let Some(v4) = v6.to_ipv4_mapped() {
                    IpAddr::V4(v4)
                } else {
                    IpAddr::V6(*v6)
                }
            },
            IpAddr::V4(v4) => IpAddr::V4(*v4),
        }
    }

    pub fn contains_ip(&self, ip: &IpAddr) -> bool {
        let normalized_ip = Self::normalize_ip(ip);
        match normalized_ip {
            IpAddr::V4(ipv4) => self.ipv4_list.contains(&ipv4),
            IpAddr::V6(ipv6) => self.ipv6_list.contains(&ipv6),
        }
    }
}
```

Additionally, normalize addresses when loading the blocklist file to ensure consistency:

```rust
// In IpRangeManager::new(), after parsing each line:
match line.parse::<Ipv6Net>() {
    Ok(ipv6_net) => {
        // Check if this is an IPv4-mapped IPv6 range
        let addr = ipv6_net.addr();
        if let Some(ipv4) = addr.to_ipv4_mapped() {
            // Convert to IPv4 range and add to ipv4_list
            let prefix = ipv6_net.prefix_len() - 96; // Adjust prefix length
            if let Ok(ipv4_net) = Ipv4Net::new(ipv4, prefix as u8) {
                ipv4_list.add(ipv4_net);
            }
        } else {
            ipv6_list.add(ipv6_net);
        }
    },
    // ... rest of error handling
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_ipv4_mapped_ipv6_bypass() {
        // Create a temporary blocklist file with an IPv4 address
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "192.0.2.1/32").unwrap();
        
        let config = IpRangeManagerConfig {
            file: file.path().to_path_buf(),
        };
        
        let manager = IpRangeManager::new(config).unwrap();
        
        // IPv4 address should be blocked
        let ipv4_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert!(manager.contains_ip(&ipv4_addr), "IPv4 address should be blocked");
        
        // IPv4-mapped IPv6 representation of the same address should also be blocked
        // ::ffff:192.0.2.1 = ::ffff:c000:0201
        let ipv4_mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0201));
        
        // VULNERABILITY: This assertion FAILS in current implementation
        assert!(
            manager.contains_ip(&ipv4_mapped),
            "IPv4-mapped IPv6 address should be blocked but bypasses the check"
        );
    }
    
    #[test]
    fn test_reverse_ipv4_mapped_bypass() {
        // Create a temporary blocklist file with IPv4-mapped IPv6
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "::ffff:192.0.2.1/128").unwrap();
        
        let config = IpRangeManagerConfig {
            file: file.path().to_path_buf(),
        };
        
        let manager = IpRangeManager::new(config).unwrap();
        
        // IPv4-mapped IPv6 should be blocked
        let ipv4_mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0201));
        assert!(manager.contains_ip(&ipv4_mapped), "IPv4-mapped address should be blocked");
        
        // Pure IPv4 representation should also be blocked
        let ipv4_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        
        // VULNERABILITY: This assertion FAILS in current implementation  
        assert!(
            manager.contains_ip(&ipv4_addr),
            "Pure IPv4 address should be blocked but bypasses the check"
        );
    }
    
    #[test]
    fn test_compressed_ipv6_notation_no_bypass() {
        // Verify that pure IPv6 notation variations work correctly (no vulnerability)
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "::1/128").unwrap();
        
        let config = IpRangeManagerConfig {
            file: file.path().to_path_buf(),
        };
        
        let manager = IpRangeManager::new(config).unwrap();
        
        // Both notations should be blocked (this works correctly)
        let compressed = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert!(manager.contains_ip(&compressed), "Compressed IPv6 should be blocked");
        
        // Rust normalizes IPv6 addresses, so different string representations
        // parse to the same internal value - no bypass possible here
    }
}
```

**Notes:**

The vulnerability specifically affects IPv4-mapped IPv6 addresses, not pure IPv6 notation variations. Rust's standard library correctly normalizes different IPv6 string representations (e.g., `::1` vs `0:0:0:0:0:0:0:1`) to identical internal representations, preventing bypasses for pure IPv6 addresses. The issue only manifests when IPv4 and IPv4-mapped IPv6 representations of the same address are treated as separate entities across the ipv4_list and ipv6_list boundaries.

### Citations

**File:** crates/aptos-faucet/core/src/common/ip_range_manager.rs (L18-21)
```rust
pub struct IpRangeManager {
    pub ipv4_list: IpRange<Ipv4Net>,
    pub ipv6_list: IpRange<Ipv6Net>,
}
```

**File:** crates/aptos-faucet/core/src/common/ip_range_manager.rs (L35-38)
```rust
            match line.parse::<Ipv4Net>() {
                Ok(ipv4_net) => {
                    ipv4_list.add(ipv4_net);
                },
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

**File:** crates/aptos-faucet/core/src/endpoints/fund.rs (L106-108)
```rust
        // This automagically uses FromRequest to get this data from the request.
        // It takes into things like X-Forwarded-IP and X-Real-IP.
        source_ip: RealIp,
```
