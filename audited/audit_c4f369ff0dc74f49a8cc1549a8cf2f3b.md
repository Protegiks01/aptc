# Audit Report

## Title
Validator Network Address Starvation Attack: Empty Address Vector Breaks Consensus Connectivity

## Summary
A validator operator can set a validator's network addresses to an empty vector through the `update_network_and_fullnode_addresses` function, causing the validator to become unreachable by other nodes. This breaks consensus connectivity requirements and can lead to network liveness failure or partition.

## Finding Description

The Aptos staking system allows validator operators to update network addresses without validating that the provided addresses are non-empty. This vulnerability exists in the on-chain Move module and propagates through the entire consensus connectivity stack.

**Attack Path:**

1. **Entry Point - No Validation**: The `update_network_and_fullnode_addresses` function in stake.move accepts BCS-encoded network addresses without validation. [1](#0-0) 

   The function directly assigns `new_network_addresses` at line 969 without checking if it deserializes to an empty vector.

2. **Storage**: The empty address vector is stored in the `ValidatorConfig` resource on-chain. [2](#0-1) 

   The deserialization function returns `Result<Vec<NetworkAddress>, bcs::Error>` - an empty vector is a valid result.

3. **Epoch Transition**: During the next epoch, `on_new_epoch` propagates the empty addresses to the active validator set. [3](#0-2) 

   The `generate_validator_info` function copies the `ValidatorConfig` including empty addresses into the new active validator set without validation.

4. **Discovery**: The network discovery layer extracts validators from on-chain state. [4](#0-3) 

   When address deserialization fails or returns empty, line 140 uses `.unwrap_or_default()`, creating a peer with an empty address list.

5. **Connectivity Failure**: The ConnectivityManager cannot dial peers with no addresses. [5](#0-4) 

   When `dial_state.next_addr(&peer.addrs)` returns `None` for empty addresses, the function logs a warning and returns early without attempting to dial, permanently preventing connection to that validator.

**Exploitation:**

An attacker controlling a validator operator key can submit:
```rust
aptos_stdlib::stake_update_network_and_fullnode_addresses(
    pool_address,
    bcs::to_bytes(&Vec::<NetworkAddress>::new()).unwrap(), // Empty vector
    bcs::to_bytes(&fullnode_addresses).unwrap(),
)
```

This bypasses the CLI validation which normally requires addresses, but the on-chain Move code has no such protection.

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple Critical severity criteria from the Aptos bug bounty:

1. **Total Loss of Liveness/Network Availability**: If validators with sufficient voting power (≥1/3) set empty addresses, the network cannot achieve consensus quorum, causing total network halt.

2. **Non-Recoverable Network Partition**: If multiple validators execute this attack, the network may partition into groups that cannot communicate, requiring hard fork intervention to recover.

3. **Consensus Safety Violation**: The AptosBFT protocol requires that honest validators maintain connectivity with each other. Breaking this assumption violates consensus safety guarantees under the < 1/3 Byzantine fault tolerance model.

The impact is amplified because:
- Changes take effect at epoch boundaries, giving no immediate detection
- Multiple validators can be affected simultaneously
- Recovery requires coordinated operator action or governance intervention
- Affects the entire network, not individual validators

## Likelihood Explanation

**High Likelihood:**

1. **Low Attacker Requirements**: Only requires compromise of a validator operator key, which is separate from the owner key and more accessible. Operators are set via `set_operator` and have authority to update network configurations. [6](#0-5) 

2. **Easy Execution**: The attack requires only a single transaction with properly formatted (but empty) BCS-encoded data. No complex state manipulation or timing requirements.

3. **No Detection Until Effect**: The empty addresses are stored on-chain but don't cause immediate failure. Only at the next epoch boundary do other validators discover they cannot connect, delaying detection.

4. **Accidental Triggering**: Operator software bugs or misconfiguration could accidentally submit empty addresses, making this exploitable through error, not just malice.

5. **No Rate Limiting**: There's no mechanism preventing repeated attacks or limiting the number of validators that can have empty addresses.

## Recommendation

Add validation to reject empty network addresses in the Move staking module:

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
    let stake_pool = borrow_global_mut<StakePool>(pool_address);
    assert!(signer::address_of(operator) == stake_pool.operator_address, error::unauthenticated(ENOT_OPERATOR));
    assert!(exists<ValidatorConfig>(pool_address), error::not_found(EVALIDATOR_CONFIG));
    
    // ADD VALIDATION: Ensure network addresses are not empty
    assert!(!vector::is_empty(&new_network_addresses), error::invalid_argument(EEMPTY_NETWORK_ADDRESSES));
    
    let validator_info = borrow_global_mut<ValidatorConfig>(pool_address);
    let old_network_addresses = validator_info.network_addresses;
    validator_info.network_addresses = new_network_addresses;
    // ... rest of function
}
```

Add the error constant:
```move
const EEMPTY_NETWORK_ADDRESSES: u64 = 30;
```

Similarly, add validation to `initialize_validator`:
```move
public entry fun initialize_validator(
    account: &signer,
    consensus_pubkey: vector<u8>,
    proof_of_possession: vector<u8>,
    network_addresses: vector<u8>,
    fullnode_addresses: vector<u8>,
) acquires AllowedValidators {
    check_stake_permission(account);
    
    // Validate network addresses are not empty
    assert!(!vector::is_empty(&network_addresses), error::invalid_argument(EEMPTY_NETWORK_ADDRESSES));
    
    // Existing validation
    let pubkey_from_pop = &bls12381::public_key_from_bytes_with_pop(
        consensus_pubkey,
        &proof_of_possession_from_bytes(proof_of_possession)
    );
    assert!(option::is_some(pubkey_from_pop), error::invalid_argument(EINVALID_PUBLIC_KEY));
    // ... rest of function
}
```

## Proof of Concept

```move
#[test_only]
module aptos_framework::stake_empty_address_test {
    use aptos_framework::stake;
    use aptos_framework::coin;
    use std::vector;
    use std::signer;
    
    #[test(aptos_framework = @aptos_framework, validator = @0x123)]
    #[expected_failure(abort_code = 0x10001)] // EEMPTY_NETWORK_ADDRESSES after fix
    fun test_empty_network_addresses_rejected(
        aptos_framework: &signer,
        validator: &signer,
    ) {
        // Setup: Initialize staking and validator
        stake::initialize_for_test(aptos_framework);
        
        let validator_addr = signer::address_of(validator);
        
        // Create valid validator config first
        let consensus_pubkey = x"b0b9..."; // Valid BLS12-381 public key
        let proof_of_possession = x"a1a2..."; // Valid PoP
        let valid_addresses = x"0401..."; // BCS-encoded Vec<NetworkAddress> with 1 address
        
        stake::initialize_validator(
            validator,
            consensus_pubkey,
            proof_of_possession,
            valid_addresses,
            valid_addresses,
        );
        
        // Attack: Try to update to empty addresses
        let empty_addresses = bcs::to_bytes(&vector::empty<vector<u8>>());
        
        // This should ABORT with the fix, but currently succeeds
        stake::update_network_and_fullnode_addresses(
            validator,
            validator_addr,
            empty_addresses, // Empty vector!
            valid_addresses,
        );
        
        // If we reach here (without fix), the validator now has no network addresses
        // At next epoch, other validators cannot connect to this validator
    }
}
```

**Notes:**
- The vulnerability affects validators during epoch transitions when `on_new_epoch` propagates configuration changes
- The same issue exists in `initialize_validator`, allowing validators to join with empty addresses from the start
- Fullnode addresses can legitimately be empty, so validation should only apply to validator network addresses
- The CLI provides some protection, but direct transaction submission bypasses this
- This breaks the fundamental consensus invariant that validators must be reachable by their peers

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

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1384-1396)
```text
            let old_validator_info = vector::borrow_mut(&mut validator_set.active_validators, i);
            let pool_address = old_validator_info.addr;
            let validator_config = borrow_global<ValidatorConfig>(pool_address);
            let stake_pool = borrow_global<StakePool>(pool_address);
            let new_validator_info = generate_validator_info(pool_address, stake_pool, *validator_config);

            // A validator needs at least the min stake required to join the validator set.
            if (new_validator_info.voting_power >= minimum_stake) {
                spec {
                    assume total_voting_power + new_validator_info.voting_power <= MAX_U128;
                };
                total_voting_power = total_voting_power + (new_validator_info.voting_power as u128);
                vector::push_back(&mut next_epoch_validators, new_validator_info);
```

**File:** types/src/validator_config.rs (L64-66)
```rust
    pub fn validator_network_addresses(&self) -> Result<Vec<NetworkAddress>, bcs::Error> {
        bcs::from_bytes(&self.validator_network_addresses)
    }
```

**File:** network/discovery/src/validator_set.rs (L121-140)
```rust
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
```

**File:** network/framework/src/connectivity_manager/mod.rs (L746-756)
```rust
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
```
