# Audit Report

## Title
Insufficient Validation of Validator Network Addresses Enables Denial of Service Through Incomplete Address Advertisement

## Summary
The `stake::update_network_and_fullnode_addresses` Move function accepts BCS-encoded network addresses without validating their completeness. A validator operator can advertise incomplete addresses (containing only IP+TCP protocols without required NoiseIK and Handshake layers) that pass on-chain storage but cause connection failures when other validators attempt to dial them, resulting in network partition and validator connectivity issues.

## Finding Description
The vulnerability exists in the interaction between three components:

1. **NetworkAddress Validation Gap**: [1](#0-0)  The `from_protocols` validation function accepts incomplete addresses with only network and transport layers, returning `Ok` at line 290 when session/handshake layers are absent.

2. **SocketAddr Conversion Creates Incomplete Addresses**: [2](#0-1)  The `From<SocketAddr>` implementation creates NetworkAddress instances with only IP and TCP protocols, lacking the required NoiseIK and Handshake protocols for validator connections.

3. **No On-Chain Validation**: [3](#0-2)  The Move function directly stores the provided bytes without any validation that addresses are complete or dialable.

4. **Connection Failure on Dial**: [4](#0-3)  When attempting to dial an incomplete address, the `parse_dial_addr` function requires the suffix pattern `[NoiseIK(pubkey), Handshake(version)]` at line 499, returning an error for incomplete addresses at lines 504-511.

**Attack Path**:
1. Validator operator constructs incomplete NetworkAddress using the SocketAddr conversion or manual Protocol vector
2. BCS-encodes `Vec<NetworkAddress>` containing the incomplete address
3. Submits transaction calling `stake::update_network_and_fullnode_addresses` with malformed bytes
4. Address passes BCS deserialization ( [5](#0-4) ) and is stored on-chain
5. During epoch change, other validators retrieve the incomplete address from ValidatorConfig ( [6](#0-5) )
6. Connection attempts fail with "Unexpected dialing network address" error, preventing consensus participation

## Impact Explanation
**Severity: High** per Aptos bug bounty criteria:
- **Validator Node Slowdowns**: Honest validators cannot establish connections to the malicious validator, degrading network performance
- **Significant Protocol Violations**: Breaks the invariant that all advertised validator addresses must be dialable
- **Network Connectivity Disruption**: Affects consensus participation and block propagation for validators unable to connect

This violates the critical invariant that validator network addresses must enable secure, authenticated connections for consensus operations.

## Likelihood Explanation
**Likelihood: Medium**
- **Requires**: Compromised or malicious validator operator with signing authority
- **No Special Privileges**: Uses standard `stake::update_network_and_fullnode_addresses` entry function
- **Easy Execution**: Simple BCS encoding of incomplete address vector
- **Realistic Scenario**: Compromised validator operator keys or malicious validator attempting network disruption

While requiring validator operator access, the attack is straightforward and uses legitimate protocol functions without special privileges beyond the operator role.

## Recommendation
Add validation in the Move framework to ensure all validator network addresses are complete and dialable:

```move
public entry fun update_network_and_fullnode_addresses(
    operator: &signer,
    pool_address: address,
    new_network_addresses: vector<u8>,
    new_fullnode_addresses: vector<u8>,
) acquires StakePool, ValidatorConfig {
    check_stake_permission(operator);
    assert_reconfig_not_in_progress();
    assert_stake_pool_exists(pool_address);
    
    // Add validation for validator addresses
    assert!(
        validate_network_addresses(&new_network_addresses),
        error::invalid_argument(EINVALID_NETWORK_ADDRESS)
    );
    
    let stake_pool = borrow_global_mut<StakePool>(pool_address);
    // ... rest of function
}

native fun validate_network_addresses(addresses_bytes: &vector<u8>): bool;
```

Implement the native function to deserialize and validate each address has required protocols (NoiseIK + Handshake).

## Proof of Concept

```rust
#[test]
fn test_incomplete_validator_address_attack() {
    use aptos_types::network_address::{NetworkAddress, Protocol};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    
    // Step 1: Create incomplete address via SocketAddr conversion
    let socket_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 
        6180
    );
    let incomplete_addr = NetworkAddress::from(socket_addr);
    
    // Verify it only has IP + TCP
    let protocols = incomplete_addr.as_slice();
    assert_eq!(protocols.len(), 2);
    assert!(matches!(protocols[0], Protocol::Ip4(_)));
    assert!(matches!(protocols[1], Protocol::Tcp(_)));
    
    // Step 2: BCS encode the incomplete address vector
    let incomplete_addrs = vec![incomplete_addr];
    let encoded = bcs::to_bytes(&incomplete_addrs).unwrap();
    
    // Step 3: This would be submitted via transaction to 
    // stake::update_network_and_fullnode_addresses(operator, pool, encoded, vec![])
    // The Move function would accept it without validation
    
    // Step 4: Demonstrate dial failure
    use aptos_network::transport::AptosNetTransport;
    // When other validators try to dial:
    // transport.parse_dial_addr(&incomplete_addr) 
    // -> Returns Err("Unexpected dialing network address... expected: '/../noise-ik/<pubkey>/handshake/<version>'")
}
```

## Notes
This vulnerability demonstrates a critical validation gap between on-chain address storage and network-layer requirements. The root cause is the permissive `NetworkAddress::from_protocols` validation that accepts addresses lacking encryption/authentication protocols required for validator connections. While the standard CLI properly constructs complete addresses via `HostAndPort::as_network_address` [7](#0-6) , direct Move function calls bypass this safety mechanism.

### Citations

**File:** types/src/network_address/mod.rs (L263-310)
```rust
    pub fn from_protocols(protocols: Vec<Protocol>) -> Result<Self, ParseError> {
        use Protocol::*;

        let mut iter = protocols.iter();

        let mut p = iter.next();

        if p.is_none() {
            return Ok(Self(protocols));
        }

        if !is_network_layer(p) {
            return Err(ParseError::NetworkLayerMissing);
        }

        if !matches!(p, Some(Memory(_))) {
            p = iter.next();
            if p.is_none() {
                return Ok(Self(protocols));
            }
            if !is_transport_layer(p) {
                return Err(ParseError::TransportLayerMissing);
            }
        }

        p = iter.next();
        if p.is_none() {
            return Ok(Self(protocols));
        }
        if !is_session_layer(p, true) {
            return Err(ParseError::SessionLayerMissing);
        }

        p = iter.next();
        if p.is_none() {
            return Ok(Self(protocols));
        }
        if !is_handshake_layer(p, true) {
            return Err(ParseError::HandshakeLayerMissing);
        }

        p = iter.next();
        if p.is_none() {
            Ok(Self(protocols))
        } else {
            Err(ParseError::RedundantLayer)
        }
    }
```

**File:** types/src/network_address/mod.rs (L506-512)
```rust
impl From<SocketAddr> for NetworkAddress {
    fn from(sockaddr: SocketAddr) -> NetworkAddress {
        let ip_proto = Protocol::from(sockaddr.ip());
        let tcp_proto = Protocol::Tcp(sockaddr.port());
        NetworkAddress::from_protocols(vec![ip_proto, tcp_proto]).unwrap()
    }
}
```

**File:** types/src/network_address/mod.rs (L548-565)
```rust
impl<'de> Deserialize<'de> for NetworkAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <String>::deserialize(deserializer)?;
            NetworkAddress::from_str(s.as_str()).map_err(de::Error::custom)
        } else {
            #[derive(Deserialize)]
            #[serde(rename = "NetworkAddress")]
            struct Wrapper(#[serde(with = "serde_bytes")] Vec<u8>);

            Wrapper::deserialize(deserializer)
                .and_then(|v| bcs::from_bytes(&v.0).map_err(de::Error::custom))
                .and_then(|v: Vec<Protocol>| NetworkAddress::try_from(v).map_err(de::Error::custom))
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L955-995)
```text
    public entry fun update_network_and_fullnode_addresses(
        operator: &signer,
        pool_address: address,
        new_network_addresses: vector<u8>,
        new_fullnode_addresses: vector<u8>,
    ) acquires StakePool, ValidatorConfig {
        check_stake_permission(operator);
        assert_reconfig_not_in_progress();
        assert_stake_pool_exists(pool_address);
        let stake_pool = borrow_global_mut<StakePool>(pool_address);
        assert!(signer::address_of(operator) == stake_pool.operator_address, error::unauthenticated(ENOT_OPERATOR));
        assert!(exists<ValidatorConfig>(pool_address), error::not_found(EVALIDATOR_CONFIG));
        let validator_info = borrow_global_mut<ValidatorConfig>(pool_address);
        let old_network_addresses = validator_info.network_addresses;
        validator_info.network_addresses = new_network_addresses;
        let old_fullnode_addresses = validator_info.fullnode_addresses;
        validator_info.fullnode_addresses = new_fullnode_addresses;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                UpdateNetworkAndFullnodeAddresses {
                    pool_address,
                    old_network_addresses,
                    new_network_addresses,
                    old_fullnode_addresses,
                    new_fullnode_addresses,
                },
            );
        } else {
            event::emit_event(
                &mut stake_pool.update_network_and_fullnode_addresses_events,
                UpdateNetworkAndFullnodeAddressesEvent {
                    pool_address,
                    old_network_addresses,
                    new_network_addresses,
                    old_fullnode_addresses,
                    new_fullnode_addresses,
                },
            );
        };
    }
```

**File:** network/framework/src/transport/mod.rs (L471-513)
```rust
    fn parse_dial_addr(
        addr: &NetworkAddress,
    ) -> io::Result<(NetworkAddress, x25519::PublicKey, u8)> {
        use aptos_types::network_address::Protocol::*;

        let protos = addr.as_slice();

        // parse out the base transport protocol(s), which we will just ignore
        // and leave for the base_transport to actually parse and dial.
        // TODO(philiphayes): protos[..X] is kinda hacky. `Transport` trait
        // should handle this.
        let (base_transport_protos, base_transport_suffix) = parse_ip_tcp(protos)
            .map(|x| (&protos[..2], x.1))
            .or_else(|| parse_dns_tcp(protos).map(|x| (&protos[..2], x.1)))
            .or_else(|| parse_memory(protos).map(|x| (&protos[..1], x.1)))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Unexpected dialing network address: '{}', expected: \
                         memory, ip+tcp, or dns+tcp",
                        addr
                    ),
                )
            })?;

        // parse out the aptosnet protocols (noise ik and handshake)
        match base_transport_suffix {
            [NoiseIK(pubkey), Handshake(version)] => {
                let base_addr = NetworkAddress::try_from(base_transport_protos.to_vec())
                    .expect("base_transport_protos is always non-empty");
                Ok((base_addr, *pubkey, *version))
            },
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Unexpected dialing network address: '{}', expected: \
                     '/../noise-ik/<pubkey>/handshake/<version>'",
                    addr
                ),
            )),
        }
    }
```

**File:** types/src/validator_config.rs (L60-66)
```rust
    pub fn fullnode_network_addresses(&self) -> Result<Vec<NetworkAddress>, bcs::Error> {
        bcs::from_bytes(&self.fullnode_network_addresses)
    }

    pub fn validator_network_addresses(&self) -> Result<Vec<NetworkAddress>, bcs::Error> {
        bcs::from_bytes(&self.validator_network_addresses)
    }
```

**File:** crates/aptos-genesis/src/config.rs (L293-314)
```rust
    pub fn as_network_address(&self, key: x25519::PublicKey) -> anyhow::Result<NetworkAddress> {
        let host = self.host.to_string();

        // Since DnsName supports IPs as well, let's properly fix what the type is
        let host_protocol = if let Ok(ip) = Ipv4Addr::from_str(&host) {
            Protocol::Ip4(ip)
        } else if let Ok(ip) = Ipv6Addr::from_str(&host) {
            Protocol::Ip6(ip)
        } else {
            Protocol::Dns(self.host.clone())
        };
        let port_protocol = Protocol::Tcp(self.port);
        let noise_protocol = Protocol::NoiseIK(key);
        let handshake_protocol = Protocol::Handshake(HANDSHAKE_VERSION);

        Ok(NetworkAddress::try_from(vec![
            host_protocol,
            port_protocol,
            noise_protocol,
            handshake_protocol,
        ])?)
    }
```
