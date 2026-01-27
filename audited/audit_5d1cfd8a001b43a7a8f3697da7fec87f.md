# Audit Report

## Title
Network Partition via DNS4/DNS6 Split Registration Enabling Validator Equivocation

## Summary
A malicious validator can register both `Dns4` and `Dns6` network addresses pointing to the same domain but resolving to different physical servers, causing different validators to connect to different endpoints while believing they are communicating with the same logical peer. This enables network partitions and consensus safety violations.

## Finding Description

The Aptos network address protocol supports separate `Dns4` and `Dns6` protocol variants that enforce IPv4-only and IPv6-only DNS resolution respectively. [1](#0-0) 

When validators register their network addresses on-chain, there is no validation preventing registration of multiple addresses, including both DNS4 and DNS6 variants for the same domain name. [2](#0-1) 

The validator network address field is stored as a BCS-serialized `Vec<NetworkAddress>`, allowing multiple addresses per validator. [3](#0-2) 

During DNS resolution, the `IpFilter` differentiates between protocols: `Dns4` filters to IPv4 only, while `Dns6` filters to IPv6 only. [4](#0-3) 

When the ConnectivityManager attempts to dial a peer with multiple addresses, it uses round-robin selection via the `DialState::next_addr()` function, cycling through all available addresses. [5](#0-4) 

**Critical Issue:** Once a validator successfully connects to ANY address of a peer, it stops attempting other addresses and removes the peer from the dial queue. [6](#0-5) 

**Attack Scenario:**

1. Malicious validator registers two network addresses:
   - `/dns4/validator.evil.com/tcp/6180/noise-ik/<key>/handshake/0`
   - `/dns6/validator.evil.com/tcp/6180/noise-ik/<key>/handshake/0`

2. Attacker controls DNS records:
   - A record (IPv4): `192.0.2.1` → Server A
   - AAAA record (IPv6): `2001:db8::1` → Server B

3. Both servers run validator software with identical cryptographic keys (network key, consensus key)

4. Different validators in the network will dial addresses in different orders based on their `addr_idx` state:
   - Some validators try Dns4 first → successfully connect to Server A via IPv4 → stop dialing
   - Other validators try Dns6 first → successfully connect to Server B via IPv6 → stop dialing

5. The network is now partitioned: some validators communicate with Server A, others with Server B, all believing they're talking to the same logical validator

6. The attacker can make Server A and Server B behave differently:
   - Send conflicting proposals to different validator subsets
   - Equivocate by signing different blocks with the same consensus key
   - Selectively relay or drop messages to manipulate consensus

This violates the fundamental assumption that each `PeerId` corresponds to a single physical node and breaks the Byzantine fault tolerance guarantee.

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under Aptos bug bounty criteria:

- **Consensus/Safety violations**: The attacker can equivocate and send different proposals to different validators, potentially causing safety breaks in the consensus protocol
- **Non-recoverable network partition**: The network splits into disjoint subsets that believe they're communicating with all validators but are actually isolated, requiring manual intervention or hardfork to resolve
- **Byzantine tolerance bypass**: A single malicious validator effectively operates as two distinct nodes while consuming only one validator slot's voting power, undermining the < 1/3 Byzantine assumption

The attack enables a malicious validator with `X` voting power to behave as if they control `2X` voting power by strategically sending different messages to different validator subsets. This can facilitate:
- Double-spending through consensus safety violations
- Chain forks where different validators commit different blocks
- Liveness failures if the partition prevents quorum formation

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

**Attack Requirements:**
- Attacker must be a registered validator (requires staking tokens, significant but achievable)
- Attacker must control DNS for their domain (trivial - they choose their own domain)
- Attacker must run two servers with identical keys (straightforward operational setup)
- No special exploits or race conditions required

**Detection Difficulty:**
- The partition appears as normal network behavior (different DNS resolution results)
- No immediate alarms would trigger since all connections authenticate correctly
- Validators would only detect issues when consensus messages diverge
- Network monitoring tools would show "normal" connectivity patterns

**Ease of Execution:**
- Attack can be executed passively during validator onboarding
- No need to compromise other validators
- DNS-based approach is operationally simple and reliable
- Can be maintained indefinitely without detection

The attack is particularly insidious because it exploits legitimate protocol features (multiple addresses, DNS resolution) rather than code bugs, making it hard to detect through traditional security monitoring.

## Recommendation

**Immediate Mitigations:**

1. **Restrict to Single Network Layer Protocol**: Validate that validators register at most ONE network-layer address (either IP4, IP6, DNS, DNS4, or DNS6), preventing mixed DNS4/DNS6 registration:

```rust
// In stake.move or network address validation
pub fn validate_network_addresses(addresses: &[NetworkAddress]) -> Result<(), Error> {
    let mut has_dns4 = false;
    let mut has_dns6 = false;
    let mut has_dns = false;
    
    for addr in addresses {
        match addr.as_slice().first() {
            Some(Protocol::Dns4(_)) => {
                if has_dns6 || has_dns {
                    return Err(Error::ConflictingDnsProtocols);
                }
                has_dns4 = true;
            }
            Some(Protocol::Dns6(_)) => {
                if has_dns4 || has_dns {
                    return Err(Error::ConflictingDnsProtocols);
                }
                has_dns6 = true;
            }
            Some(Protocol::Dns(_)) => {
                if has_dns4 || has_dns6 {
                    return Err(Error::ConflictingDnsProtocols);
                }
                has_dns = true;
            }
            _ => {}
        }
    }
    Ok(())
}
```

2. **DNS Resolution Verification**: Before accepting a connection, verify that all registered DNS addresses for a peer resolve to the same IP address set, rejecting validators with inconsistent DNS records.

3. **Connection Endpoint Tracking**: Track the actual connected IP address for each peer and log warnings when different validators report connecting to different IPs for the same PeerId.

**Long-term Solutions:**

1. **Deprecate DNS4/DNS6 Separation**: Remove `Dns4` and `Dns6` protocols entirely, keeping only `Dns` which accepts both IPv4 and IPv6 results, letting the OS networking stack handle IP version selection consistently.

2. **Single Canonical Address Enforcement**: Require validators to register exactly ONE primary network address, with optional fallback addresses that must resolve to the same physical server (verified through IP consistency checks).

3. **Peer Identity Binding**: Enhance the consensus protocol to include IP address attestations where validators sign statements about which IP they connected from, enabling detection of split-view attacks.

## Proof of Concept

```rust
// PoC demonstrating the vulnerability (pseudo-code for testing framework)

#[test]
fn test_dns4_dns6_partition_attack() {
    // Setup: Create malicious validator with both DNS4 and DNS6 addresses
    let malicious_validator_key = generate_validator_key();
    let network_addresses = vec![
        NetworkAddress::from_str("/dns4/evil.com/tcp/6180/noise-ik/<key>/handshake/0").unwrap(),
        NetworkAddress::from_str("/dns6/evil.com/tcp/6180/noise-ik/<key>/handshake/0").unwrap(),
    ];
    
    // Register validator on-chain with multiple addresses
    stake::update_network_and_fullnode_addresses(
        &operator_signer,
        pool_address,
        bcs::to_bytes(&network_addresses).unwrap(),
        vec![],
    );
    
    // Simulate DNS resolution
    // Mock DNS server returns:
    // - A record (IPv4): 192.0.2.1 (Server A)
    // - AAAA record (IPv6): 2001:db8::1 (Server B)
    
    // Validator 1 attempts connection
    let validator1 = TestValidator::new();
    let conn1 = validator1.connect_to_peer(malicious_validator_key);
    // validator1 tries Dns4 first (addr_idx=0), connects to 192.0.2.1
    assert_eq!(conn1.remote_ip(), "192.0.2.1");
    
    // Validator 2 attempts connection
    let validator2 = TestValidator::new();
    // Force validator2 to try Dns6 first (addr_idx=1)
    validator2.set_dial_state_addr_idx(malicious_validator_key, 1);
    let conn2 = validator2.connect_to_peer(malicious_validator_key);
    // validator2 tries Dns6 first, connects to 2001:db8::1
    assert_eq!(conn2.remote_ip(), "2001:db8::1");
    
    // VULNERABILITY: validator1 and validator2 are connected to DIFFERENT servers
    // but both believe they're connected to the same logical peer
    assert_ne!(conn1.remote_ip(), conn2.remote_ip());
    assert_eq!(conn1.peer_id(), conn2.peer_id()); // Same PeerId!
    
    // Attacker can now send different consensus messages through each server
    server_a.send_proposal(proposal_1);
    server_b.send_proposal(proposal_2); // Conflicting proposal
    
    // Network is partitioned with validators seeing different proposals
}
```

## Notes

This vulnerability is particularly severe because:

1. **Silent Failure Mode**: The partition occurs transparently during normal operation with no error messages or alerts

2. **Authentication Bypass Not Required**: Both servers authenticate correctly using the same keys, so mutual authentication doesn't prevent the attack

3. **Scales with Network Size**: As more validators join, the partition probability increases since each new validator independently resolves DNS

4. **Persistent Attack**: Once established, the partition persists across epochs until validators restart or addresses are updated

5. **Defence in Depth Failure**: Multiple layers (DNS, networking, authentication) all pass while the fundamental security property (single logical peer = single physical node) is violated

The fix requires both protocol-level changes (restricting address registration) and operational monitoring (detecting IP inconsistencies) to fully mitigate the attack vector.

### Citations

**File:** types/src/network_address/mod.rs (L117-119)
```rust
    Dns4(DnsName),
    Dns6(DnsName),
    Tcp(u16),
```

**File:** types/src/network_address/mod.rs (L807-821)
```rust
pub fn parse_dns_tcp(protos: &[Protocol]) -> Option<((IpFilter, &DnsName, u16), &[Protocol])> {
    use Protocol::*;

    if protos.len() < 2 {
        return None;
    }

    let (prefix, suffix) = protos.split_at(2);
    match prefix {
        [Dns(name), Tcp(port)] => Some(((IpFilter::Any, name, *port), suffix)),
        [Dns4(name), Tcp(port)] => Some(((IpFilter::OnlyIp4, name, *port), suffix)),
        [Dns6(name), Tcp(port)] => Some(((IpFilter::OnlyIp6, name, *port), suffix)),
        _ => None,
    }
}
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L955-972)
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

```

**File:** types/src/validator_config.rs (L36-43)
```rust
pub struct ValidatorConfig {
    pub consensus_public_key: bls12381::PublicKey,
    /// This is an bcs serialized `Vec<NetworkAddress>`
    pub validator_network_addresses: Vec<u8>,
    /// This is an bcs serialized `Vec<NetworkAddress>`
    pub fullnode_network_addresses: Vec<u8>,
    pub validator_index: u64,
}
```

**File:** network/framework/src/connectivity_manager/mod.rs (L1011-1019)
```rust
            peer_manager::ConnectionNotification::NewPeer(metadata, _network_id) => {
                let peer_id = metadata.remote_peer_id;
                counters::peer_connected(&self.network_context, &peer_id, 1);
                self.connected.insert(peer_id, metadata);

                // Cancel possible queued dial to this peer.
                self.dial_states.remove(&peer_id);
                self.dial_queue.remove(&peer_id);
            },
```

**File:** network/framework/src/connectivity_manager/mod.rs (L1363-1369)
```rust
    /// Returns the current address to dial for this peer and updates
    /// the internal state to point to the next address.
    fn next_addr<'a>(&mut self, addrs: &'a Addresses) -> Option<&'a NetworkAddress> {
        let curr_addr = self.get_addr_at_index(self.addr_idx, addrs);
        self.addr_idx = self.addr_idx.wrapping_add(1);
        curr_addr
    }
```
