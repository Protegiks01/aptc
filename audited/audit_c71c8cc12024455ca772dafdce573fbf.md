# Audit Report

## Title
Log Injection Vulnerability via Unsanitized DNS Names in Network Address Logging

## Summary
The `DnsName` type in Aptos Core's network address handling does not sanitize ASCII control characters (newlines, carriage returns, etc.) before logging, allowing malicious peers to inject arbitrary log entries that can manipulate validator logs and monitoring dashboards.

## Finding Description

The vulnerability exists in the DNS name validation and display logic used throughout the network layer. When a validator logs network addresses (during connection attempts, peer discovery, etc.), malicious DNS names containing ASCII control characters are output directly without escaping.

**Vulnerability Flow:**

1. A malicious peer advertises a `NetworkAddress` with a DNS name containing control characters (e.g., newlines)
2. The `DnsName::validate()` function only checks that the string is ASCII, non-empty, <255 bytes, and doesn't contain '/' [1](#0-0) 
3. **Crucially, it does NOT filter ASCII control characters** like `\n` (0x0A), `\r` (0x0D), or `\t` (0x09)
4. When logged, `DnsName::Display` directly outputs the raw string without escaping [2](#0-1) 
5. The malicious DNS name propagates through `Protocol::Display` [3](#0-2)  and `NetworkAddress::Display` [4](#0-3) 
6. In the logging infrastructure, `NetworkSchema` marks `network_address` with `#[schema(display)]` [5](#0-4) , causing it to use `Value::Display` [6](#0-5) 
7. When formatted, the Display trait outputs control characters directly [7](#0-6) 

**Example Attack Locations:**

The vulnerability manifests in multiple logging locations, such as in connectivity manager where connection results are logged with the network address formatted using Display [8](#0-7) , and in error logging [9](#0-8) .

**Attack Example:**
A DNS name like: `"evil.com\n[INFO] Fake validator connected\n"` would pass all validation checks and inject a fake log line when logged.

## Impact Explanation

This is classified as **Low Severity** per the Aptos bug bounty program criteria: "Minor information leaks, Non-critical implementation bugs."

The vulnerability allows:
- Injection of fake log entries that appear legitimate
- Manipulation of log-based monitoring and alerting systems
- Potential confusion during incident response
- Exploitation of log processing tools that parse validator logs

It does **NOT** allow:
- Direct theft or minting of funds
- Consensus safety violations
- Network availability disruption
- State corruption
- Any direct protocol-level attack

## Likelihood Explanation

**Likelihood: High** - The attack is trivial to execute:
- Any peer can advertise a malicious `NetworkAddress` via peer discovery
- No special permissions or insider access required
- Validators will automatically attempt connections and log the addresses
- ASCII control characters are valid in the current validation logic

The only requirement is that the attacker can participate in the peer-to-peer network, which is permissionless.

## Recommendation

**Fix 1: Sanitize control characters in DnsName validation**

Modify the validation to reject ASCII control characters:

```rust
fn validate(s: &str) -> Result<(), ParseError> {
    if s.is_empty() {
        Err(ParseError::EmptyDnsNameString)
    } else if s.len() > MAX_DNS_NAME_SIZE {
        Err(ParseError::DnsNameTooLong(s.len()))
    } else if s.contains('/') {
        Err(ParseError::InvalidDnsNameCharacter)
    } else if !s.is_ascii() {
        Err(ParseError::DnsNameNonASCII(s.into()))
    } else if s.chars().any(|c| c.is_control()) {
        Err(ParseError::InvalidDnsNameCharacter)
    } else {
        Ok(())
    }
}
```

**Fix 2: Escape control characters in Display implementation**

Alternatively, escape control characters when displaying:

```rust
impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.0.chars() {
            if c.is_control() {
                write!(f, "\\x{:02x}", c as u8)?;
            } else {
                write!(f, "{}", c)?;
            }
        }
        Ok(())
    }
}
```

**Recommendation: Implement Fix 1** (validation-time rejection) as it's cleaner and prevents malicious DNS names from entering the system at all.

## Proof of Concept

```rust
use aptos_types::network_address::{NetworkAddress, Protocol};
use std::str::FromStr;

#[test]
fn test_log_injection_via_dns_name() {
    // Craft a malicious DNS name with newline characters
    let malicious_dns = "evil.com\n[2024-01-01T00:00:00Z INFO] INJECTED LOG LINE\n";
    
    // This should fail but currently passes validation
    let addr_str = format!("/dns/{}/tcp/6180", malicious_dns);
    
    // Parse the network address - this succeeds because validation
    // doesn't check for control characters
    let network_addr = NetworkAddress::from_str(&addr_str).expect("Should parse");
    
    // When logged, this will inject fake log entries
    println!("Connection attempt to: {}", network_addr);
    // Output will contain the injected newline and fake log entry
    
    // Verify the DNS name contains control characters
    if let Some(Protocol::Dns(dns_name)) = network_addr.as_slice().first() {
        let dns_str: String = dns_name.clone().into();
        assert!(dns_str.contains('\n'), "DNS name should contain newline");
    }
}
```

When validators log this address (e.g., during connection attempts), the output will be:
```
Connection attempt to: /dns/evil.com
[2024-01-01T00:00:00Z INFO] INJECTED LOG LINE
/tcp/6180
```

This demonstrates how an attacker can inject arbitrary log entries.

## Notes

While this vulnerability has **Low severity** per the bug bounty classification and does not directly impact consensus, funds, or availability, it represents a real security issue that should be addressed to maintain operational security and log integrity for validator operators.

### Citations

**File:** types/src/network_address/mod.rs (L514-520)
```rust
impl fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for protocol in self.0.iter() {
            protocol.fmt(f)?;
        }
        Ok(())
    }
```

**File:** types/src/network_address/mod.rs (L598-618)
```rust
impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Protocol::*;
        match self {
            Ip4(addr) => write!(f, "/ip4/{}", addr),
            Ip6(addr) => write!(f, "/ip6/{}", addr),
            Dns(domain) => write!(f, "/dns/{}", domain),
            Dns4(domain) => write!(f, "/dns4/{}", domain),
            Dns6(domain) => write!(f, "/dns6/{}", domain),
            Tcp(port) => write!(f, "/tcp/{}", port),
            Memory(port) => write!(f, "/memory/{}", port),
            NoiseIK(pubkey) => write!(
                f,
                "/noise-ik/{}",
                pubkey
                    .to_encoded_string()
                    .expect("ValidCryptoMaterialStringExt::to_encoded_string is infallible")
            ),
            Handshake(version) => write!(f, "/handshake/{}", version),
        }
    }
```

**File:** types/src/network_address/mod.rs (L667-679)
```rust
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

**File:** types/src/network_address/mod.rs (L710-713)
```rust
impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
```

**File:** network/framework/src/logging.rs (L40-41)
```rust
    #[schema(display)]
    network_address: Option<&'a NetworkAddress>,
```

**File:** crates/aptos-logger/src/kv.rs (L38-39)
```rust
    Debug(&'v dyn fmt::Debug),
    Display(&'v dyn fmt::Display),
```

**File:** crates/aptos-logger/src/kv.rs (L47-47)
```rust
            Value::Display(d) => fmt::Display::fmt(d, f),
```

**File:** network/framework/src/connectivity_manager/mod.rs (L1073-1076)
```rust
                "{} Successfully connected to peer: {} at address: {}",
                network_context,
                peer_id.short_str(),
                addr
```

**File:** network/framework/src/connectivity_manager/mod.rs (L1105-1109)
```rust
                    "{} Failed to connect to peer: {} at address: {}; error: {}",
                    network_context,
                    peer_id.short_str(),
                    addr,
                    e
```
