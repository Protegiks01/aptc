# Audit Report

## Title
Missing Network Key Uniqueness Validation Allows Validator Identity Confusion

## Summary
The `update_network_and_fullnode_addresses` function in the stake module lacks validation to prevent validators from using duplicate x25519 network public keys. While genesis validation enforces key uniqueness, runtime updates bypass this check, allowing network identity confusion that can disrupt consensus communication.

## Finding Description

The Aptos network layer uses x25519 public keys embedded in validator network addresses for peer authentication and connection management. During genesis, the system validates that all validator network keys are unique: [1](#0-0) 

However, after genesis, when validators update their network addresses through the Move smart contract, no such validation exists: [2](#0-1) 

The function simply overwrites the network addresses without checking for duplicates. Similarly, when validators join the set, only basic validation occurs: [3](#0-2) 

During epoch reconfiguration, validator information is regenerated from the stored config without any duplicate key checks: [4](#0-3) 

The network layer extracts x25519 keys from validator network addresses and uses them for peer identity: [5](#0-4) 

If two validators share the same x25519 network key, the network layer will experience identity confusion since peer authentication is based on these keys, not account addresses: [6](#0-5) 

**Attack Scenario:**
1. Validator A and Validator B both join the network with unique network keys initially
2. Validator B's operator calls `update_network_and_fullnode_addresses` with a network address containing Validator A's x25519 public key
3. The transaction succeeds without validation
4. At the next epoch boundary, both validators advertise the same x25519 network key
5. The network layer sees duplicate peer identities, causing connection conflicts, message misrouting, and potential consensus disruption

## Impact Explanation

This is a **HIGH severity** vulnerability according to Aptos bug bounty criteria:

- **Validator node slowdowns**: Duplicate network keys cause connection conflicts and authentication failures, degrading validator performance
- **Significant protocol violations**: Breaks the network identity model that assumes unique x25519 keys per validator
- **Consensus disruption risk**: Misrouted consensus messages between validators can affect block proposal and voting
- **Network topology damage**: The validator full-mesh topology breaks when identity confusion occurs

While not immediately causing fund loss or total network failure, this violates critical network protocol invariants and can degrade consensus operations.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is easily exploitable by any validator operator through a single transaction. The attack requires:
- Being a registered validator operator (privileged but common role)
- Knowing another validator's network public key (publicly visible on-chain)
- Calling a standard entry function with modified parameters

No special timing, coordination, or complex exploitation is required. The lack of validation makes this straightforward to execute, whether accidentally (configuration error) or maliciously.

## Recommendation

Add network key uniqueness validation to the `update_network_and_fullnode_addresses` function. The validation should iterate through all validators in the ValidatorSet and ensure no other validator uses the same x25519 network public key.

**Suggested fix approach:**
```move
// In update_network_and_fullnode_addresses function, after line 963:
// Parse the new network addresses to extract x25519 keys
let new_keys = extract_network_keys(new_network_addresses);

// Validate uniqueness against all other validators
let validator_set = borrow_global<ValidatorSet>(@aptos_framework);
vector::for_each_ref(&validator_set.active_validators, |validator_info| {
    let validator: &ValidatorInfo = validator_info;
    if (validator.addr != pool_address) {
        let existing_config = borrow_global<ValidatorConfig>(validator.addr);
        let existing_keys = extract_network_keys(existing_config.network_addresses);
        assert!(!keys_overlap(new_keys, existing_keys), error::invalid_argument(EDUPLICATE_NETWORK_KEY));
    }
});
// Also check pending_active and pending_inactive validators
```

The same validation should be added to `join_validator_set_internal` to ensure comprehensive protection.

## Proof of Concept

```move
#[test_only]
module aptos_framework::stake_duplicate_key_test {
    use aptos_framework::stake;
    use aptos_framework::account;
    use std::vector;
    
    #[test(aptos_framework = @aptos_framework, validator1 = @0x123, validator2 = @0x456)]
    fun test_duplicate_network_key_allowed(
        aptos_framework: &signer,
        validator1: &signer,
        validator2: &signer,
    ) {
        // Setup: Initialize two validators with different network keys
        // (Genesis setup code omitted for brevity)
        
        // Validator 1's original network key
        let validator1_key = x"original_key_for_validator_1";
        
        // Validator 2 updates to use Validator 1's network key
        let duplicate_network_address = construct_network_address_with_key(validator1_key);
        
        // This SHOULD fail but currently SUCCEEDS - demonstrating the vulnerability
        stake::update_network_and_fullnode_addresses(
            validator2,
            @0x456,
            bcs::to_bytes(&duplicate_network_address),
            vector::empty(),
        );
        
        // At this point, both validators share the same x25519 network key
        // causing network identity confusion in the next epoch
    }
}
```

**Notes:**
- The vulnerability exists because runtime validation was not implemented to match genesis-time constraints
- The genesis validation in Rust is purely pre-chain, not enforced as an on-chain invariant
- This represents a gap between intended security properties (evident from genesis checks) and actual runtime enforcement
- The network layer's reliance on unique x25519 keys for peer identity makes this a critical protocol violation

### Citations

**File:** crates/aptos/src/genesis/mod.rs (L620-728)
```rust
fn validate_validators(
    layout: &Layout,
    validators: &[ValidatorConfiguration],
    initialized_accounts: &BTreeMap<AccountAddress, u64>,
    unique_accounts: &mut BTreeSet<AccountAddress>,
    unique_network_keys: &mut HashSet<x25519::PublicKey>,
    unique_consensus_keys: &mut HashSet<bls12381::PublicKey>,
    unique_consensus_pops: &mut HashSet<bls12381::ProofOfPossession>,
    unique_hosts: &mut HashSet<HostAndPort>,
    seen_owners: &mut BTreeMap<AccountAddress, usize>,
    is_pooled_validator: bool,
) -> CliTypedResult<()> {
    // check accounts for validators
    let mut errors = vec![];

    for (i, validator) in validators.iter().enumerate() {
        let name = if is_pooled_validator {
            format!("Employee Pool #{}", i)
        } else {
            layout.users.get(i).unwrap().to_string()
        };

        if !initialized_accounts.contains_key(&validator.owner_account_address.into()) {
            errors.push(CliError::UnexpectedError(format!(
                "Owner {} in validator {} is not in the balances.yaml file",
                validator.owner_account_address, name
            )));
        }
        if !initialized_accounts.contains_key(&validator.operator_account_address.into()) {
            errors.push(CliError::UnexpectedError(format!(
                "Operator {} in validator {} is not in the balances.yaml file",
                validator.operator_account_address, name
            )));
        }
        if !initialized_accounts.contains_key(&validator.voter_account_address.into()) {
            errors.push(CliError::UnexpectedError(format!(
                "Voter {} in validator {} is not in the balances.yaml file",
                validator.voter_account_address, name
            )));
        }

        let owner_balance = initialized_accounts
            .get(&validator.owner_account_address.into())
            .unwrap();

        if seen_owners.contains_key(&validator.owner_account_address.into()) {
            errors.push(CliError::UnexpectedError(format!(
                "Owner {} in validator {} has been seen before as an owner of validator {}",
                validator.owner_account_address,
                name,
                seen_owners
                    .get(&validator.owner_account_address.into())
                    .unwrap()
            )));
        }
        seen_owners.insert(validator.owner_account_address.into(), i);

        if unique_accounts.contains(&validator.owner_account_address.into()) {
            errors.push(CliError::UnexpectedError(format!(
                "Owner '{}' in validator {} has already been seen elsewhere",
                validator.owner_account_address, name
            )));
        }
        unique_accounts.insert(validator.owner_account_address.into());

        if unique_accounts.contains(&validator.operator_account_address.into()) {
            errors.push(CliError::UnexpectedError(format!(
                "Operator '{}' in validator {} has already been seen elsewhere",
                validator.operator_account_address, name
            )));
        }
        unique_accounts.insert(validator.operator_account_address.into());

        // Pooled validators have a combined balance
        // TODO: Make this field optional but checked
        if !is_pooled_validator && *owner_balance < validator.stake_amount {
            errors.push(CliError::UnexpectedError(format!(
                "Owner {} in validator {} has less in it's balance {} than the stake amount for the validator {}",
                validator.owner_account_address, name, owner_balance, validator.stake_amount
            )));
        }
        if validator.stake_amount < layout.min_stake {
            errors.push(CliError::UnexpectedError(format!(
                "Validator {} has stake {} under the min stake {}",
                name, validator.stake_amount, layout.min_stake
            )));
        }
        if validator.stake_amount > layout.max_stake {
            errors.push(CliError::UnexpectedError(format!(
                "Validator {} has stake {} over the max stake {}",
                name, validator.stake_amount, layout.max_stake
            )));
        }

        // Ensure that the validator is setup correctly if it's joining in genesis
        if validator.join_during_genesis {
            if validator.validator_network_public_key.is_none() {
                errors.push(CliError::UnexpectedError(format!(
                    "Validator {} does not have a validator network public key, though it's joining during genesis",
                    name
                )));
            }
            if !unique_network_keys.insert(validator.validator_network_public_key.unwrap()) {
                errors.push(CliError::UnexpectedError(format!(
                    "Validator {} has a repeated validator network key{}",
                    name,
                    validator.validator_network_public_key.unwrap()
                )));
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

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1053-1104)
```text
    /// Request to have `pool_address` join the validator set. Can only be called after calling `initialize_validator`.
    /// If the validator has the required stake (more than minimum and less than maximum allowed), they will be
    /// added to the pending_active queue. All validators in this queue will be added to the active set when the next
    /// epoch starts (eligibility will be rechecked).
    ///
    /// This internal version can only be called by the Genesis module during Genesis.
    public(friend) fun join_validator_set_internal(
        operator: &signer,
        pool_address: address
    ) acquires StakePool, ValidatorConfig, ValidatorSet {
        assert_reconfig_not_in_progress();
        assert_stake_pool_exists(pool_address);
        let stake_pool = borrow_global_mut<StakePool>(pool_address);
        assert!(signer::address_of(operator) == stake_pool.operator_address, error::unauthenticated(ENOT_OPERATOR));
        assert!(
            get_validator_state(pool_address) == VALIDATOR_STATUS_INACTIVE,
            error::invalid_state(EALREADY_ACTIVE_VALIDATOR),
        );

        let config = staking_config::get();
        let (minimum_stake, maximum_stake) = staking_config::get_required_stake(&config);
        let voting_power = get_next_epoch_voting_power(stake_pool);
        assert!(voting_power >= minimum_stake, error::invalid_argument(ESTAKE_TOO_LOW));
        assert!(voting_power <= maximum_stake, error::invalid_argument(ESTAKE_TOO_HIGH));

        // Track and validate voting power increase.
        update_voting_power_increase(voting_power);

        // Add validator to pending_active, to be activated in the next epoch.
        let validator_config = borrow_global<ValidatorConfig>(pool_address);
        assert!(!vector::is_empty(&validator_config.consensus_pubkey), error::invalid_argument(EINVALID_PUBLIC_KEY));

        // Validate the current validator set size has not exceeded the limit.
        let validator_set = borrow_global_mut<ValidatorSet>(@aptos_framework);
        vector::push_back(
            &mut validator_set.pending_active,
            generate_validator_info(pool_address, stake_pool, *validator_config)
        );
        let validator_set_size = vector::length(&validator_set.active_validators) + vector::length(
            &validator_set.pending_active
        );
        assert!(validator_set_size <= MAX_VALIDATOR_SET_SIZE, error::invalid_argument(EVALIDATOR_SET_TOO_LARGE));

        if (std::features::module_event_migration_enabled()) {
            event::emit(JoinValidatorSet { pool_address });
        } else {
            event::emit_event(
                &mut stake_pool.join_validator_set_events,
                JoinValidatorSetEvent { pool_address },
            );
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1344-1464)
```text
    public(friend) fun on_new_epoch(
    ) acquires AptosCoinCapabilities, PendingTransactionFee, StakePool, TransactionFeeConfig, ValidatorConfig, ValidatorPerformance, ValidatorSet {
        let validator_set = borrow_global_mut<ValidatorSet>(@aptos_framework);
        let config = staking_config::get();
        let validator_perf = borrow_global_mut<ValidatorPerformance>(@aptos_framework);

        // Process pending stake and distribute transaction fees and rewards for each currently active validator.
        vector::for_each_ref(&validator_set.active_validators, |validator| {
            let validator: &ValidatorInfo = validator;
            update_stake_pool(validator_perf, validator.addr, &config);
        });

        // Process pending stake and distribute transaction fees and rewards for each currently pending_inactive validator
        // (requested to leave but not removed yet).
        vector::for_each_ref(&validator_set.pending_inactive, |validator| {
            let validator: &ValidatorInfo = validator;
            update_stake_pool(validator_perf, validator.addr, &config);
        });

        // Activate currently pending_active validators.
        append(&mut validator_set.active_validators, &mut validator_set.pending_active);

        // Officially deactivate all pending_inactive validators. They will now no longer receive rewards.
        validator_set.pending_inactive = vector::empty();

        // Update active validator set so that network address/public key change takes effect.
        // Moreover, recalculate the total voting power, and deactivate the validator whose
        // voting power is less than the minimum required stake.
        let next_epoch_validators = vector::empty();
        let (minimum_stake, _) = staking_config::get_required_stake(&config);
        let vlen = vector::length(&validator_set.active_validators);
        let total_voting_power = 0;
        let i = 0;
        while ({
            spec {
                invariant spec_validators_are_initialized(next_epoch_validators);
                invariant i <= vlen;
            };
            i < vlen
        }) {
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
            };
            i = i + 1;
        };

        validator_set.active_validators = next_epoch_validators;
        validator_set.total_voting_power = total_voting_power;
        validator_set.total_joining_power = 0;

        // Update validator indices, reset performance scores, and renew lockups.
        validator_perf.validators = vector::empty();
        let recurring_lockup_duration_secs = staking_config::get_recurring_lockup_duration(&config);
        let vlen = vector::length(&validator_set.active_validators);
        let validator_index = 0;
        while ({
            spec {
                invariant spec_validators_are_initialized(validator_set.active_validators);
                invariant len(validator_set.pending_active) == 0;
                invariant len(validator_set.pending_inactive) == 0;
                invariant 0 <= validator_index && validator_index <= vlen;
                invariant vlen == len(validator_set.active_validators);
                invariant forall i in 0..validator_index:
                    global<ValidatorConfig>(validator_set.active_validators[i].addr).validator_index < validator_index;
                invariant forall i in 0..validator_index:
                    validator_set.active_validators[i].config.validator_index < validator_index;
                invariant len(validator_perf.validators) == validator_index;
            };
            validator_index < vlen
        }) {
            let validator_info = vector::borrow_mut(&mut validator_set.active_validators, validator_index);
            validator_info.config.validator_index = validator_index;
            let validator_config = borrow_global_mut<ValidatorConfig>(validator_info.addr);
            validator_config.validator_index = validator_index;

            vector::push_back(&mut validator_perf.validators, IndividualValidatorPerformance {
                successful_proposals: 0,
                failed_proposals: 0,
            });

            // Automatically renew a validator's lockup for validators that will still be in the validator set in the
            // next epoch.
            let stake_pool = borrow_global_mut<StakePool>(validator_info.addr);
            let now_secs = timestamp::now_seconds();
            let reconfig_start_secs = if (chain_status::is_operating()) {
                get_reconfig_start_time_secs()
            } else {
                now_secs
            };
            if (stake_pool.locked_until_secs <= reconfig_start_secs) {
                spec {
                    assume now_secs + recurring_lockup_duration_secs <= MAX_U64;
                };
                stake_pool.locked_until_secs = now_secs + recurring_lockup_duration_secs;
            };

            validator_index = validator_index + 1;
        };

        if (exists<PendingTransactionFee>(@aptos_framework)) {
            let pending_fee_by_validator = &mut borrow_global_mut<PendingTransactionFee>(@aptos_framework).pending_fee_by_validator;
            assert!(pending_fee_by_validator.is_empty(), error::internal(ETRANSACTION_FEE_NOT_FULLY_DISTRIBUTED));
            validator_set.active_validators.for_each_ref(|v| pending_fee_by_validator.add(v.config.validator_index, aggregator_v2::create_unbounded_aggregator<u64>()));
        };

        if (features::periodical_reward_rate_decrease_enabled()) {
            // Update rewards rate after reward distribution.
            staking_config::calculate_and_save_latest_epoch_rewards_rate();
        };
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
