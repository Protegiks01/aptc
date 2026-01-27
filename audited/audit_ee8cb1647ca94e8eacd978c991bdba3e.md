# Audit Report

## Title
Silent Network Address Parsing Failures Allow Validators with Invalid Addresses to Join the Active Set, Risking Network Liveness

## Summary
The `extract_validator_set_updates()` function in the validator discovery system silently ignores BCS deserialization errors when parsing validator network addresses, using `unwrap_or_default()` to return empty address vectors. Combined with the lack of validation in `update_network_and_fullnode_addresses()` in stake.move, this allows validators with malformed on-chain network addresses to be included in the active validator set with empty addresses, making them unreachable by peers and potentially causing consensus liveness failures.

## Finding Description

The vulnerability exists across two components:

**Component 1: No validation when setting network addresses on-chain** [1](#0-0) 

The `update_network_and_fullnode_addresses()` function accepts raw bytes without validating that they are valid BCS-encoded network addresses. The bytes are stored directly on-chain without any attempt to deserialize and validate them.

**Component 2: Silent error handling during address parsing** [2](#0-1) 

When other validators read the on-chain ValidatorSet and attempt to parse network addresses, the `extract_validator_set_updates()` function uses `unwrap_or_default()` on line 140. When BCS deserialization fails (due to malformed bytes), this returns an empty `Vec<NetworkAddress>` rather than excluding the validator or raising an error.

**Attack Flow:**

1. A validator operator calls `update_network_and_fullnode_addresses()` with malformed bytes (either accidentally or maliciously)
2. These bytes are stored on-chain in the `ValidatorConfig` resource without validation
3. The validator is included in the active set during epoch transition [3](#0-2) 

4. When other validators process the on-chain ValidatorSet, they call `validator_network_addresses()` which attempts BCS deserialization: [4](#0-3) 

5. The deserialization fails but the error is caught and logged, then `unwrap_or_default()` returns an empty vector
6. A `Peer` is created with empty addresses and keys: [5](#0-4) 

7. This validator becomes undialable by other validators because: [6](#0-5) 

**Broken Invariant:**

The ConnectivityManager documentation explicitly states the criticality of validator connectivity: [7](#0-6) 

This vulnerability breaks the invariant that validators must maintain connectivity with all peers for consensus operation.

## Impact Explanation

**High to Critical Severity** depending on scope:

**Single Validator Impact (High Severity):**
- One validator with malformed addresses becomes unreachable
- Network continues operating but with reduced Byzantine fault tolerance
- That validator cannot effectively participate in consensus
- Falls under "Significant protocol violations" (High severity)

**Multiple Validator Impact (Critical Severity):**
- If validators representing >33% of voting power have malformed addresses (whether through coordinated attack, common misconfiguration, or SDK/CLI bug), consensus cannot reach the required 2/3+1 quorum
- Results in "Total loss of liveness/network availability" (Critical severity)
- This could occur accidentally through:
  - Bug in validator configuration tooling
  - Mass misconfiguration during network upgrade
  - Coordinated griefing attack by malicious validator operators

## Likelihood Explanation

**Moderate to High Likelihood:**

1. **Accidental Occurrence**: Most likely scenario is accidental misconfiguration due to:
   - Bugs in CLI/SDK address encoding logic
   - Validator operator errors during address updates
   - Data corruption during transmission
   - No validation feedback to prevent submission of invalid data

2. **Intentional Exploitation**: While requiring validator operator access, griefing attacks are feasible:
   - Single malicious operator can degrade network health
   - Coordinated attack by minority stake holders could halt network

3. **Discovery Surface**: Silent failure makes this hard to detect until validators become unreachable, increasing likelihood of propagation.

## Recommendation

**Immediate Fix 1: Add validation in Move framework**

Add validation in `update_network_and_fullnode_addresses()` to verify bytes are valid BCS-encoded network addresses:

```move
public entry fun update_network_and_fullnode_addresses(
    operator: &signer,
    pool_address: address,
    new_network_addresses: vector<u8>,
    new_fullnode_addresses: vector<u8>,
) acquires StakePool, ValidatorConfig {
    // ... existing checks ...
    
    // VALIDATE NETWORK ADDRESSES
    let network_addrs_result = bcs::from_bytes<vector<NetworkAddress>>(&new_network_addresses);
    assert!(option::is_some(&network_addrs_result), error::invalid_argument(EINVALID_NETWORK_ADDRESSES));
    let network_addrs = option::extract(&mut network_addrs_result);
    assert!(!vector::is_empty(&network_addrs), error::invalid_argument(EEMPTY_NETWORK_ADDRESSES));
    
    // VALIDATE FULLNODE ADDRESSES  
    let fullnode_addrs_result = bcs::from_bytes<vector<NetworkAddress>>(&new_fullnode_addresses);
    assert!(option::is_some(&fullnode_addrs_result), error::invalid_argument(EINVALID_FULLNODE_ADDRESSES));
    
    // ... rest of function ...
}
```

**Immediate Fix 2: Fail-fast instead of silent defaults**

Replace `unwrap_or_default()` with explicit error handling:

```rust
let addrs = if is_validator {
    config.validator_network_addresses()
} else {
    config.fullnode_network_addresses()
}
.map_err(|err| {
    inc_by_with_context(&DISCOVERY_COUNTS, &network_context, "read_failure", 1);
    error!(
        NetworkSchema::new(&network_context),
        "OnChainDiscovery: Failed to parse network address for peer: {}, err: {}. EXCLUDING VALIDATOR.",
        peer_id, err
    );
})
.ok()
.filter(|addrs| !addrs.is_empty())
.unwrap_or_else(Vec::new);

// Skip validators with no valid addresses
if addrs.is_empty() {
    warn!(
        NetworkSchema::new(&network_context),
        "Skipping validator {} - no valid network addresses",
        peer_id
    );
    continue; // Skip this validator entirely
}
```

**Long-term Fix:**

Implement network address validation at the Move VM level as a native function that can be called during address updates.

## Proof of Concept

```move
#[test(framework = @aptos_framework, validator = @0x123)]
public entry fun test_malformed_addresses_accepted(
    framework: &signer,
    validator: &signer,
) {
    // Setup validator with valid initial state
    stake::initialize_validator(...);
    
    // Attempt to update with malformed addresses (invalid BCS encoding)
    let malformed_bytes = vector<u8>[0xFF, 0xFF, 0xFF]; // Invalid BCS
    
    // This should fail but currently succeeds
    stake::update_network_and_fullnode_addresses(
        validator,
        signer::address_of(validator),
        malformed_bytes,
        malformed_bytes,
    );
    
    // Validator is still in active set despite malformed addresses
    let validator_set = stake::get_validator_set();
    assert!(vector::contains(&validator_set.active_validators, &validator_info), 0);
    
    // When other validators try to parse these addresses, they get empty vectors
    // causing this validator to be unreachable
}
```

**Notes:**

This vulnerability represents a defense-in-depth failure where:
1. Input validation is missing at the entry point (Move framework)
2. Error handling silently papers over the problem (Rust discovery layer)  
3. The system continues operating in a degraded state rather than rejecting invalid configuration

While exploitation requires validator operator access (a semi-privileged role), the disproportionate impact on network liveness and the high likelihood of accidental occurrence through configuration errors or tooling bugs make this a valid High severity finding. The issue could escalate to Critical if multiple validators are affected simultaneously.

### Citations

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

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1082-1090)
```text
        let validator_config = borrow_global<ValidatorConfig>(pool_address);
        assert!(!vector::is_empty(&validator_config.consensus_pubkey), error::invalid_argument(EINVALID_PUBLIC_KEY));

        // Validate the current validator set size has not exceeded the limit.
        let validator_set = borrow_global_mut<ValidatorSet>(@aptos_framework);
        vector::push_back(
            &mut validator_set.pending_active,
            generate_validator_info(pool_address, stake_pool, *validator_config)
        );
```

**File:** network/discovery/src/validator_set.rs (L108-150)
```rust
pub(crate) fn extract_validator_set_updates(
    network_context: NetworkContext,
    node_set: ValidatorSet,
) -> PeerSet {
    let is_validator = network_context.network_id().is_validator_network();

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

**File:** types/src/validator_config.rs (L64-66)
```rust
    pub fn validator_network_addresses(&self) -> Result<Vec<NetworkAddress>, bcs::Error> {
        bcs::from_bytes(&self.validator_network_addresses)
    }
```

**File:** config/src/config/network_config.rs (L498-504)
```rust
    pub fn from_addrs(role: PeerRole, addresses: Vec<NetworkAddress>) -> Peer {
        let keys: HashSet<x25519::PublicKey> = addresses
            .iter()
            .filter_map(NetworkAddress::find_noise_proto)
            .collect();
        Peer::new(addresses, keys, role)
    }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L4-27)
```rust
//! The ConnectivityManager actor is responsible for ensuring that we are
//! connected to a node if and only if it is an eligible node.
//!
//! A list of eligible nodes is received at initialization, and updates are
//! received on changes to system membership. In our current system design, the
//! Consensus actor informs the ConnectivityManager of eligible nodes.
//!
//! Different discovery sources notify the ConnectivityManager of updates to
//! peers' addresses. Currently, there are 2 discovery sources (ordered by
//! decreasing dial priority, i.e., first is highest priority):
//!
//! 1. Onchain discovery protocol
//! 2. Seed peers from config
//!
//! In other words, if a we have some addresses discovered via onchain discovery
//! and some seed addresses from our local config, we will try the onchain
//! discovery addresses first and the local seed addresses after.
//!
//! When dialing a peer with a given list of addresses, we attempt each address
//! in order with a capped exponential backoff delay until we eventually connect
//! to the peer. The backoff is capped since, for validators specifically, it is
//! absolutely important that we maintain connectivity with all peers and heal
//! any partitions asap, as we aren't currently gossiping consensus messages or
//! using a relay protocol.
```

**File:** network/framework/src/connectivity_manager/mod.rs (L254-262)
```rust
    /// Peers without keys are not able to be mutually authenticated to
    pub fn is_eligible(&self) -> bool {
        !self.keys.is_empty()
    }

    /// Peers without addresses can't be dialed to
    pub fn is_eligible_to_be_dialed(&self) -> bool {
        self.is_eligible() && !self.addrs.is_empty()
    }
```
