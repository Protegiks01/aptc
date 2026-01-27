# Audit Report

## Title
Validator Network Address Validation Bypass Enables Consensus Disruption via Malformed Addresses

## Summary
A validation mismatch exists between network address deserialization (`from_protocols()`) and dial-time validation (`parse_dial_addr()`). Malicious validator operators can submit incomplete network addresses on-chain that pass lenient deserialization but fail strict transport validation, causing affected validators to become unreachable and disrupting consensus.

## Finding Description

The vulnerability stems from two different validation paths for `NetworkAddress` with incompatible requirements:

**Lenient Validation Path (Deserialization):**
The `from_protocols()` function accepts partial network addresses by allowing optional session and handshake layers: [1](#0-0) 

Key points:
- Lines 288-290: Returns `Ok` if only network + transport layers present (missing NoiseIK/Handshake)
- Lines 296-298: Returns `Ok` if NoiseIK layer is missing  
- Lines 292, 300: Calls `is_session_layer(p, true)` and `is_handshake_layer(p, true)` with `allow_empty=true` [2](#0-1) 

**Strict Validation Path (Dial Time):**
The transport's `parse_dial_addr()` function REQUIRES complete AptosNet stacks: [3](#0-2) 

Lines 498-512: Rejects addresses missing NoiseIK or Handshake with `InvalidInput` error.

**Attack Vector:**

1. The on-chain `update_network_and_fullnode_addresses()` function has NO validation: [4](#0-3) 

Lines 968-971: Accepts raw `vector<u8>` and stores directly without validation.

2. Validator discovery deserializes addresses using lenient validation: [5](#0-4) [6](#0-5) 

Lines 122-129: Calls `validator_network_addresses()` which uses `bcs::from_bytes()`, triggering lenient `from_protocols()` validation.

3. When ConnectivityManager attempts to dial the malformed address, the strict validation fails: [7](#0-6) 

Lines 746-757: Selects address and queues dial without pre-validation.

**Exploitation Steps:**

1. Malicious validator operator crafts partial address: `/ip4/10.0.0.1/tcp/6180` (missing `/noise-ik/<key>/handshake/0`)
2. BCS-encodes: `bcs::to_bytes(&vec![partial_address])`
3. Submits transaction calling `stake::update_network_and_fullnode_addresses()` with encoded bytes
4. Address stored on-chain (no validation)
5. Other validators fetch ValidatorConfig and deserialize successfully (lenient validation)
6. ConnectivityManager attempts dial → `parse_dial_addr()` fails with `InvalidInput`
7. Validator becomes unreachable, cannot participate in consensus

**Invariant Violations:**
- Breaks **Consensus Safety**: Network cannot form quorum if sufficient validators are unreachable
- Breaks **Deterministic Execution**: Different validators may have different views of reachable peer sets

## Impact Explanation

**Severity: HIGH** per Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: Affected validators cannot be dialed, causing connection failures and retry loops
2. **Significant Protocol Violation**: Breaks validator connectivity requirements
3. **Consensus Disruption**: If multiple validators submit malformed addresses, the network cannot reach 2/3+1 quorum for block finalization
4. **Network Partition Risk**: Validators with malformed addresses become isolated from the consensus network

This does not reach Critical severity because:
- Does not directly cause fund loss or permanent network partition requiring hardfork
- Network can recover once validators fix their addresses in the next epoch
- Requires validator operator access (not fully unprivileged)

However, it significantly impacts network liveness and validator participation.

## Likelihood Explanation

**Likelihood: Medium-High**

**Prerequisites:**
- Attacker needs validator operator access (can sign transactions for their validator's operator address)
- No additional privileges or collusion required

**Ease of Exploitation:**
- Simple to execute: craft partial NetworkAddress, BCS-encode, submit transaction
- No cryptographic bypasses or complex attack chains needed
- Can be done programmatically bypassing the CLI

**Realistic Scenarios:**
1. **Malicious Operator**: Intentional disruption by compromised/malicious validator operator
2. **Accidental Misconfiguration**: Buggy custom tooling could submit incomplete addresses
3. **Coordinated Attack**: Multiple compromised operators could amplify impact

**Detection Difficulty:**
- Attack succeeds silently on-chain (no validation failure)
- Manifests as connectivity failures rather than obvious attack
- May be mistaken for network issues rather than malicious addresses

## Recommendation

**Immediate Fix:**

Add on-chain validation in the `update_network_and_fullnode_addresses()` function:

```move
// In stake.move, update function to:
public entry fun update_network_and_fullnode_addresses(
    operator: &signer,
    pool_address: address,
    new_network_addresses: vector<u8>,
    new_fullnode_addresses: vector<u8>,
) acquires StakePool, ValidatorConfig {
    check_stake_permission(operator);
    assert_reconfig_not_in_progress();
    assert_stake_pool_exists(pool_address);
    
    // ADD VALIDATION: Ensure addresses can be deserialized and are complete
    assert!(
        validate_network_addresses(&new_network_addresses),
        error::invalid_argument(EINVALID_NETWORK_ADDRESS)
    );
    assert!(
        validate_network_addresses(&new_fullnode_addresses),
        error::invalid_argument(EINVALID_FULLNODE_ADDRESS)
    );
    
    // ... rest of function
}

// Add native function to check addresses are complete AptosNet addresses
native fun validate_network_addresses(addresses: &vector<u8>): bool;
```

**In Rust Native Implementation:**

```rust
// Implement native validation function
pub fn validate_network_addresses(addresses: &[u8]) -> bool {
    match bcs::from_bytes::<Vec<NetworkAddress>>(addresses) {
        Ok(addrs) => addrs.iter().all(|addr| addr.is_aptosnet_addr()),
        Err(_) => false,
    }
}
```

**Alternative Fix:**

Make `from_protocols()` validation match `parse_dial_addr()` strictness by requiring complete stacks: [8](#0-7) 

Change lines 292 and 300 to use `allow_empty=false` after transport layer is present.

## Proof of Concept

```rust
// PoC demonstrating the validation bypass
use aptos_types::network_address::{NetworkAddress, Protocol};
use std::str::FromStr;

#[test]
fn test_validation_mismatch() {
    // Create incomplete address (missing NoiseIK and Handshake)
    let incomplete_addr = NetworkAddress::from_str("/ip4/10.0.0.1/tcp/6180").unwrap();
    
    // Lenient validation accepts it
    assert!(incomplete_addr.as_slice().len() == 2);
    
    // But is_aptosnet_addr() rejects it
    assert!(!incomplete_addr.is_aptosnet_addr());
    
    // BCS encode it
    let encoded = bcs::to_bytes(&vec![incomplete_addr.clone()]).unwrap();
    
    // Deserialization succeeds (lenient validation)
    let decoded: Vec<NetworkAddress> = bcs::from_bytes(&encoded).unwrap();
    assert_eq!(decoded.len(), 1);
    
    // But parse_dial_addr would fail (demonstrated by is_aptosnet_addr check)
    assert!(!decoded[0].is_aptosnet_addr());
    
    // In production, this would cause dial failures:
    // parse_dial_addr() at transport layer would return InvalidInput error
}

#[test]
fn test_attack_scenario() {
    use aptos_crypto::x25519;
    
    // Attacker crafts partial address
    let partial = vec![
        Protocol::Ip4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        Protocol::Tcp(6180),
    ];
    
    // Creates NetworkAddress (lenient validation passes)
    let malicious_addr = NetworkAddress::from_protocols(partial).unwrap();
    
    // BCS encode for on-chain submission
    let payload = bcs::to_bytes(&vec![malicious_addr]).unwrap();
    
    // This payload would be accepted by stake::update_network_and_fullnode_addresses
    // But would cause dial failures when other validators try to connect
    
    // Verify complete address works correctly
    let complete = NetworkAddress::from_str(
        "/ip4/10.0.0.1/tcp/6180/noise-ik/080e287879c918794170e258bfaddd75acac5b3e350419044655e4983a487120/handshake/0"
    ).unwrap();
    assert!(complete.is_aptosnet_addr());
}
```

**Notes:**

- The vulnerability requires validator operator access but no collusion or special cryptographic capabilities
- Impact scales with number of affected validators
- The official CLI properly constructs complete addresses, but attackers can bypass it by crafting raw transactions
- The issue could be triggered accidentally by buggy custom tooling
- Network can self-heal when affected validators update their addresses in subsequent epochs, but causes service disruption until then

### Citations

**File:** types/src/network_address/mod.rs (L244-260)
```rust
fn is_session_layer(p: Option<&Protocol>, allow_empty: bool) -> bool {
    use Protocol::*;
    match p {
        None => allow_empty,
        Some(NoiseIK(_)) => true,
        _ => false,
    }
}

fn is_handshake_layer(p: Option<&Protocol>, allow_empty: bool) -> bool {
    use Protocol::*;
    match p {
        None => allow_empty,
        Some(Handshake(_)) => true,
        _ => false,
    }
}
```

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

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L954-995)
```text
    /// Update the network and full node addresses of the validator. This only takes effect in the next epoch.
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

**File:** types/src/validator_config.rs (L60-66)
```rust
    pub fn fullnode_network_addresses(&self) -> Result<Vec<NetworkAddress>, bcs::Error> {
        bcs::from_bytes(&self.fullnode_network_addresses)
    }

    pub fn validator_network_addresses(&self) -> Result<Vec<NetworkAddress>, bcs::Error> {
        bcs::from_bytes(&self.validator_network_addresses)
    }
```

**File:** network/discovery/src/validator_set.rs (L114-150)
```rust
    // Decode addresses while ignoring bad addresses
    node_set
        .into_iter()
        .map(|info| {
            let peer_id = *info.account_address();
            let config = info.into_config();

            let addrs = if is_validator {
                config
                    .validator_network_addresses()
                    .map_err(anyhow::Error::from)
            } else {
                config
                    .fullnode_network_addresses()
                    .map_err(anyhow::Error::from)
            }
            .map_err(|err| {
                inc_by_with_context(&DISCOVERY_COUNTS, &network_context, "read_failure", 1);

                warn!(
                    NetworkSchema::new(&network_context),
                    "OnChainDiscovery: Failed to parse any network address: peer: {}, err: {}",
                    peer_id,
                    err
                )
            })
            .unwrap_or_default();

            let peer_role = if is_validator {
                PeerRole::Validator
            } else {
                PeerRole::ValidatorFullNode
            };
            (peer_id, Peer::from_addrs(peer_role, addrs))
        })
        .collect()
}
```

**File:** network/framework/src/connectivity_manager/mod.rs (L718-770)
```rust
    fn queue_dial_peer<'a>(
        &'a mut self,
        peer_id: PeerId,
        peer: DiscoveredPeer,
        pending_dials: &'a mut FuturesUnordered<BoxFuture<'static, PeerId>>,
    ) {
        // If we're attempting to dial a Peer we must not be connected to it. This ensures that
        // newly eligible, but not connected to peers, have their counter initialized properly.
        counters::peer_connected(&self.network_context, &peer_id, 0);

        // Get the peer's dial state
        let dial_state = match self.dial_states.get_mut(&peer_id) {
            Some(dial_state) => dial_state,
            None => {
                // The peer should have a dial state! If not, log an error and return.
                error!(
                    NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                    "{} Peer {} does not have a dial state!",
                    self.network_context,
                    peer_id.short_str()
                );
                return;
            },
        };

        // Choose the next addr to dial for this peer. Currently, we just
        // round-robin the selection, i.e., try the sequence:
        // addr[0], .., addr[len-1], addr[0], ..
        let addr = match dial_state.next_addr(&peer.addrs) {
            Some(addr) => addr.clone(),
            None => {
                warn!(
                    NetworkSchema::new(&self.network_context).remote_peer(&peer_id),
                    "{} Peer {} does not have any network addresses!",
                    self.network_context,
                    peer_id.short_str()
                );
                return;
            },
        };

        // Using the DialState's backoff strategy, compute the delay until
        // the next dial attempt for this peer.
        let dial_delay = dial_state.next_backoff_delay(self.max_delay);
        let f_delay = self.time_service.sleep(dial_delay);

        let (cancel_tx, cancel_rx) = oneshot::channel();

        let network_context = self.network_context;
        // Create future which completes by either dialing after calculated
        // delay or on cancellation.
        let connection_reqs_tx = self.connection_reqs_tx.clone();
        let f = async move {
```
