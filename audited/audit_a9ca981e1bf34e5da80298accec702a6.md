# Audit Report

## Title
DNS Name Case Sensitivity Violation in NetworkAddress Equality Checks Causes Peer Deduplication Failures

## Summary
The `NetworkAddress` type derives `PartialEq`, `Eq`, and `Hash` traits, which perform case-sensitive comparison on DNS names contained within the address. However, DNS names are case-insensitive per RFC 1035. This semantic mismatch causes logically equivalent addresses with different DNS capitalizations (e.g., `/dns/Example.com/tcp/80` vs `/dns/example.com/tcp/80`) to be treated as distinct addresses, leading to deduplication failures in HashSets, unnecessary peer reconnections, and potential network connectivity issues.

## Finding Description
The vulnerability exists in the derived equality implementations for `NetworkAddress` and its constituent `DnsName` type: [1](#0-0) [2](#0-1) 

The `DnsName` struct wraps a `String` and derives `PartialEq`, `Eq`, and `Hash`. Rust's `String` comparison is case-sensitive, but DNS names are case-insensitive according to RFC 1035. There is no normalization (e.g., `to_lowercase()`) performed on DNS names during parsing or comparison: [3](#0-2) 

This semantic mismatch propagates throughout the system wherever `NetworkAddress` equality is checked. The most critical impact occurs in the connectivity manager's address deduplication logic: [4](#0-3) 

When addresses from multiple discovery sources are combined via `union()`, a `HashSet<NetworkAddress>` is used for deduplication. Since `NetworkAddress` uses case-sensitive DNS comparison, addresses differing only in DNS capitalization will NOT be deduplicated, resulting in duplicate entries.

**Attack Scenario:**
1. Validator A registers their address on-chain as `/dns/VALIDATOR.example.com/tcp/6180/noise-ik/<key>/handshake/0`
2. Validator B has the same peer configured via local seed config as `/dns/validator.example.com/tcp/6180/noise-ik/<key>/handshake/0`
3. When the connectivity manager processes these addresses:
   - The `union()` function creates a HashSet to deduplicate
   - Both addresses hash differently due to case-sensitive DNS comparison
   - No deduplication occurs
   - Multiple dial attempts are made to the same logical peer

Additional impact points:

**Address Update Detection:** [5](#0-4) 

When addresses are updated, case-only changes trigger unnecessary reconnections.

**Vector Contains Checks:** [6](#0-5) 

Address presence checks fail for case variations, potentially causing configuration validation issues.

## Impact Explanation
**Severity: MEDIUM** (per Aptos Bug Bounty criteria: "State inconsistencies requiring intervention")

This vulnerability causes network layer reliability issues:

1. **Deduplication Failures**: The same logical peer appears multiple times in address collections, causing redundant connection attempts and wasted network resources.

2. **Connection Instability**: When addresses differ only by DNS capitalization across discovery sources, the system treats them as updates, triggering unnecessary peer reconnections.

3. **Potential Liveness Impact**: If validators cannot reliably connect to each other due to address mismatches, consensus liveness could be affected, especially during epoch transitions when validator sets change.

4. **State Inconsistency**: Different nodes may have inconsistent views of peer addresses based on capitalization variations from different sources (on-chain vs config vs DNS resolution).

This does NOT directly break consensus safety (voting uses BLS public keys, not network addresses), but it degrades network reliability and could contribute to liveness issues in edge cases. The impact aligns with Medium severity: "State inconsistencies requiring intervention."

## Likelihood Explanation
**Likelihood: MEDIUM-HIGH**

This issue is likely to occur in production because:

1. **Multiple Configuration Sources**: Validators receive addresses from on-chain discovery, local config files, and file/REST discovery. Each source may use different DNS capitalizations.

2. **Human Error**: When operators manually configure DNS names, inconsistent capitalization is a common occurrence (e.g., "example.com" vs "Example.com" vs "EXAMPLE.COM").

3. **DNS Resolution**: Some DNS resolvers may return names in different capitalizations, especially for CNAMEs or after following redirects.

4. **No Validation**: The validator address update path has no normalization: [7](#0-6) 

Addresses are stored as BCS-encoded `Vec<NetworkAddress>` without case normalization.

5. **Already Deployed**: The issue affects existing validator configurations, not just future deployments.

## Recommendation
Normalize DNS names to lowercase during parsing to ensure case-insensitive comparison while maintaining RFC 1035 compliance:

```rust
impl FromStr for DnsName {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Normalize to lowercase for case-insensitive DNS comparison per RFC 1035
        let normalized = s.to_ascii_lowercase();
        DnsName::validate(&normalized).map(|_| DnsName(normalized))
    }
}

impl TryFrom<String> for DnsName {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        // Normalize to lowercase for case-insensitive DNS comparison per RFC 1035
        let normalized = s.to_ascii_lowercase();
        DnsName::validate(&normalized).map(|_| DnsName(normalized))
    }
}
```

Additionally, update the validation function to ensure normalized storage:

```rust
impl DnsName {
    fn validate(s: &str) -> Result<(), ParseError> {
        if s.is_empty() {
            Err(ParseError::EmptyDnsNameString)
        } else if s.len() > MAX_DNS_NAME_SIZE {
            Err(ParseError::DnsNameTooLong(s.len()))
        } else if s.contains('/') {
            Err(ParseError::InvalidDnsNameCharacter)
        } else if !s.is_ascii() {
            Err(ParseError::DnsNameNonASCII(s.into()))
        } else {
            Ok(())
        }
    }
}
```

This ensures all DNS names are stored in lowercase form, making equality checks case-insensitive without changing the derived implementations.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_dns_name_case_sensitivity_vulnerability() {
        // Create two NetworkAddresses with same DNS name but different capitalization
        let addr1 = NetworkAddress::from_str("/dns/Example.com/tcp/80").unwrap();
        let addr2 = NetworkAddress::from_str("/dns/example.com/tcp/80").unwrap();

        // BUG: These should be equal (DNS is case-insensitive per RFC 1035)
        // but are NOT equal due to case-sensitive String comparison
        assert_ne!(addr1, addr2, "Addresses with different DNS capitalization should be equal but are not");

        // Demonstrate HashSet deduplication failure
        let mut addr_set = HashSet::new();
        addr_set.insert(addr1.clone());
        addr_set.insert(addr2.clone());

        // BUG: HashSet should contain only 1 entry (deduplicated) but contains 2
        assert_eq!(addr_set.len(), 2, "HashSet failed to deduplicate logically equivalent addresses");

        // This affects the Addresses::union() function used in connectivity_manager
        println!("VULNERABILITY CONFIRMED: DNS case sensitivity causes deduplication failures");
        println!("Address 1: {}", addr1);
        println!("Address 2: {}", addr2);
        println!("Equal: {}", addr1 == addr2);
        println!("HashSet size: {} (expected: 1, actual: 2)", addr_set.len());
    }

    #[test]
    fn test_connectivity_manager_impact() {
        // Simulate the Addresses::union() behavior
        let addresses1 = vec![NetworkAddress::from_str("/dns/VALIDATOR.com/tcp/6180").unwrap()];
        let addresses2 = vec![NetworkAddress::from_str("/dns/validator.com/tcp/6180").unwrap()];

        // Combine and deduplicate as done in Addresses::union()
        let mut combined: HashSet<NetworkAddress> = HashSet::new();
        combined.extend(addresses1.into_iter());
        combined.extend(addresses2.into_iter());

        // BUG: Should have 1 unique address, but has 2 due to case sensitivity
        assert_eq!(combined.len(), 2, "Connectivity manager will fail to deduplicate peers");
        println!("IMPACT: Connectivity manager will attempt to dial the same peer {} times", combined.len());
    }
}
```

This PoC demonstrates that:
1. DNS names with different capitalizations are treated as distinct addresses
2. HashSet deduplication fails for logically equivalent addresses
3. The connectivity manager's `union()` function will not deduplicate such addresses
4. Multiple connection attempts will be made to the same logical peer

**Notes**

The issue is exacerbated by the fact that DNS resolution itself is case-insensitive - resolving "Example.com" and "example.com" returns the same IP addresses. However, Aptos treats these as different network addresses at the protocol level, causing unnecessary network churn and potential connectivity issues. This violates the principle of semantic correctness where the protocol-level representation should match the underlying DNS semantics.

### Citations

**File:** types/src/network_address/mod.rs (L107-108)
```rust
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct NetworkAddress(Vec<Protocol>);
```

**File:** types/src/network_address/mod.rs (L148-149)
```rust
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct DnsName(String);
```

**File:** types/src/network_address/mod.rs (L666-679)
```rust
impl DnsName {
    fn validate(s: &str) -> Result<(), ParseError> {
        if s.is_empty() {
            Err(ParseError::EmptyDnsNameString)
        } else if s.len() > MAX_DNS_NAME_SIZE {
            Err(ParseError::DnsNameTooLong(s.len()))
        } else if s.contains('/') {
            Err(ParseError::InvalidDnsNameCharacter)
        } else if !s.is_ascii() {
            Err(ParseError::DnsNameNonASCII(s.into()))
        } else {
            Ok(())
        }
    }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L1254-1262)
```rust
    fn update(&mut self, src: DiscoverySource, addrs: Vec<NetworkAddress>) -> bool {
        let src_idx = src.as_usize();
        if self.0[src_idx] != addrs {
            self.0[src_idx] = addrs;
            true
        } else {
            false
        }
    }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L1272-1276)
```rust
    /// The Union isn't stable, and order is completely disregarded
    fn union(&self) -> Vec<NetworkAddress> {
        let set: HashSet<_> = self.0.iter().flatten().cloned().collect();
        set.into_iter().collect()
    }
```

**File:** config/src/config/config_optimizer.rs (L426-429)
```rust
            assert!(seed_peer
                .addresses
                .contains(&NetworkAddress::from_str(network_address).unwrap()));
            assert!(seed_peer
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L161-168)
```text
    struct ValidatorConfig has key, copy, store, drop {
        consensus_pubkey: vector<u8>,
        network_addresses: vector<u8>,
        // to make it compatible with previous definition, remove later
        fullnode_addresses: vector<u8>,
        // Index in the active set if the validator corresponding to this stake pool is active.
        validator_index: u64,
    }
```
