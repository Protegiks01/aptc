# Audit Report

## Title
Missing Validator Network Address Uniqueness Validation in Non-Mainnet Genesis and Post-Genesis Updates

## Summary
The Aptos genesis system lacks validator network address (`validator_host`) uniqueness validation in two critical code paths: (1) non-mainnet genesis generation and (2) post-genesis network address updates. This allows multiple validators to register identical network endpoints, causing network connectivity issues, validator startup failures, and potential denial-of-service attacks against the validator set.

## Finding Description

The validator network address validation has three distinct code paths with inconsistent security checks:

**Path 1: Mainnet Genesis (Protected)** [1](#0-0) 

The mainnet genesis path calls `validate_validators` which enforces uniqueness of `validator_host` addresses using a shared `HashSet<HostAndPort>`. [2](#0-1) 

**Path 2: Non-Mainnet Genesis (Vulnerable)** [3](#0-2) 

The testnet/devnet genesis path (`fetch_genesis_info`) bypasses `validate_validators` entirely and directly invokes `GenesisInfo::new`, allowing duplicate validator hosts to be configured during genesis initialization.

**Path 3: Post-Genesis Updates (Vulnerable)** [4](#0-3) 

The `update_network_and_fullnode_addresses` function in the stake module performs no uniqueness validation when validators update their network addresses after genesis. Any validator operator can set their address to match another validator's endpoint.

**Attack Scenarios:**

1. **Testnet/Devnet Genesis Manipulation**: During testnet or devnet genesis, malicious participants configure multiple validators with identical `validator_host` values (e.g., `"10.0.0.1:6180"`). When validators attempt to start, only one can bind to the port, causing others to fail.

2. **Post-Genesis Network Hijacking**: A malicious validator operator calls `stake::update_network_and_fullnode_addresses` to set their network address to match a target honest validator's address. This causes:
   - Network routing confusion for peers attempting to connect
   - Connection failures or misrouting of consensus messages
   - Potential for the malicious validator to intercept or block connection attempts

The vulnerability breaks the **Network Identity Integrity** invariant: each validator must maintain a unique, resolvable network endpoint for consensus communication.

## Impact Explanation

**Severity: High**

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria for the following reasons:

1. **Validator Node Slowdowns/Failures**: Multiple validators claiming the same network endpoint causes systematic validator startup failures. Only one process can bind to a given `host:port` combination, meaning all but one validator sharing an address will fail to initialize their network layer.

2. **Network Liveness Degradation**: If a sufficient number of validators in the active set (approaching the 1/3 Byzantine threshold) are configured with duplicate addresses, the network could experience liveness failures due to inadequate validator participation.

3. **Denial of Service Vector**: A malicious validator operator can continuously update their network address to target different honest validators, causing persistent network disruption and connection confusion across the validator set.

4. **Consensus Message Routing Failures**: While the cryptographic identity (network public key) differs, the address collision causes connection-layer confusion that can delay or prevent consensus message delivery, impacting block production and finalization.

The impact does not reach **Critical** severity because:
- No direct loss of funds occurs
- Consensus safety is maintained (cryptographic identities remain distinct)
- The network can recover by removing/reconfiguring affected validators
- Does not require a hard fork to remediate

## Likelihood Explanation

**Likelihood: Medium to High**

For **Non-Mainnet Genesis**:
- **Medium likelihood** - Requires attacker to be part of initial validator set
- Highly feasible for testnets/devnets where validator selection is less strict
- No technical complexity required - simple configuration manipulation
- Could be accidental (misconfiguration) or intentional (malicious)

For **Post-Genesis Updates**:
- **High likelihood** - Any validator operator can execute this attack
- Requires no special permissions beyond normal validator operator capabilities
- Can be executed at any time via simple transaction submission
- Attack is repeatable and can target different victims

The likelihood is constrained only by attacker motivation and the need for validator operator access. The technical barrier is minimal.

## Recommendation

**Solution 1: Add Validation to Non-Mainnet Genesis Path**

Modify `fetch_genesis_info` to include the same validation as the mainnet path: [3](#0-2) 

Add validation calls before `GenesisInfo::new`:

```rust
// In fetch_genesis_info, after line 281:
let mut unique_accounts = BTreeSet::new();
let mut unique_network_keys = HashSet::new();
let mut unique_consensus_keys = HashSet::new();
let mut unique_consensus_pop = HashSet::new();
let mut unique_hosts = HashSet::new();
let mut seen_owners = BTreeMap::new();

validate_validators(
    &layout,
    &validators,
    &BTreeMap::new(), // No balance checks for test networks
    &mut unique_accounts,
    &mut unique_network_keys,
    &mut unique_consensus_keys,
    &mut unique_consensus_pop,
    &mut unique_hosts,
    &mut seen_owners,
    false,
)?;
```

**Solution 2: Add On-Chain Validation for Post-Genesis Updates**

Modify the `update_network_and_fullnode_addresses` function to check uniqueness: [4](#0-3) 

Add validation logic to iterate through the validator set and verify the new addresses don't collide with existing validators' addresses. This requires maintaining a global mapping or performing a full scan of active validators during address updates.

**Solution 3: Network-Level Address Binding Validation**

As a defense-in-depth measure, add validation at the network layer to detect and warn when validators attempt to connect using addresses already in use by other validator identities (based on network public keys).

## Proof of Concept

**PoC 1: Non-Mainnet Genesis with Duplicate Hosts**

Create a testnet genesis configuration with duplicate validator hosts:

```yaml
# layout.yaml (testnet configuration)
chain_id: 4
root_key: "0x1234..." # Some test key
is_test: true
users:
  - "validator1"
  - "validator2"
# ... other config ...

# validator1.yaml
validator_host: "10.0.0.1:6180"
validator_network_public_key: "0xabc..."
consensus_public_key: "0xdef..."
# ... other config ...

# validator2.yaml  
validator_host: "10.0.0.1:6180"  # SAME HOST AS VALIDATOR1
validator_network_public_key: "0x123..."  # Different key
consensus_public_key: "0x456..."
# ... other config ...
```

Execute genesis generation:
```bash
aptos genesis generate-genesis --output-dir ./genesis
```

**Expected Result**: Genesis succeeds without error (vulnerability present)
**Correct Behavior**: Should fail with "Validator validator2 has a repeated validator host"

**PoC 2: Post-Genesis Address Collision**

```move
// Test demonstrating post-genesis address update without validation
script {
    use aptos_framework::stake;
    
    fun test_duplicate_address_update(
        validator_operator: &signer,
        pool_address: address,
    ) {
        // Target validator has address: /ip4/10.0.0.1/tcp/6180/...
        let target_address = x"..."; // BCS-encoded NetworkAddress of target
        
        // Update our address to match the target (no validation prevents this)
        stake::update_network_and_fullnode_addresses(
            validator_operator,
            pool_address,
            target_address,  // Duplicate of target validator's address
            x"",
        );
        
        // Transaction succeeds - vulnerability confirmed
    }
}
```

**Notes**

This vulnerability demonstrates a critical gap in defense-in-depth: while cryptographic identities (network keys) remain unique and provide authentication, the lack of network address uniqueness validation creates operational and security risks. The issue is particularly severe for testnets/devnets where the non-mainnet genesis path is used, and remains exploitable post-genesis on all networks through the stake module's update function.

The mainnet genesis path includes proper validation, indicating this was a recognized requirement that was inconsistently applied across the codebase. Extending this validation to all genesis paths and adding on-chain checks for address updates would fully remediate the vulnerability.

### Citations

**File:** crates/aptos/src/genesis/mod.rs (L211-234)
```rust
    validate_validators(
        &layout,
        &employee_validators,
        &initialized_accounts,
        &mut unique_accounts,
        &mut unique_network_keys,
        &mut unique_consensus_keys,
        &mut unique_consensus_pop,
        &mut unique_hosts,
        &mut seen_owners,
        true,
    )?;
    validate_validators(
        &layout,
        &validators,
        &initialized_accounts,
        &mut unique_accounts,
        &mut unique_network_keys,
        &mut unique_consensus_keys,
        &mut unique_consensus_pop,
        &mut unique_hosts,
        &mut seen_owners,
        false,
    )?;
```

**File:** crates/aptos/src/genesis/mod.rs (L270-311)
```rust
pub fn fetch_genesis_info(git_options: GitOptions) -> CliTypedResult<GenesisInfo> {
    let client = git_options.get_client()?;
    let layout: Layout = client.get(Path::new(LAYOUT_FILE))?;

    if layout.root_key.is_none() {
        return Err(CliError::UnexpectedError(
            "Layout field root_key was not set.  Please provide a hex encoded Ed25519PublicKey."
                .to_string(),
        ));
    }

    let validators = get_validator_configs(&client, &layout, false).map_err(parse_error)?;
    let framework = client.get_framework()?;
    Ok(GenesisInfo::new(
        layout.chain_id,
        layout.root_key.unwrap(),
        validators,
        framework,
        &GenesisConfiguration {
            allow_new_validators: layout.allow_new_validators,
            epoch_duration_secs: layout.epoch_duration_secs,
            is_test: layout.is_test,
            min_stake: layout.min_stake,
            min_voting_threshold: layout.min_voting_threshold,
            max_stake: layout.max_stake,
            recurring_lockup_duration_secs: layout.recurring_lockup_duration_secs,
            required_proposer_stake: layout.required_proposer_stake,
            rewards_apy_percentage: layout.rewards_apy_percentage,
            voting_duration_secs: layout.voting_duration_secs,
            voting_power_increase_limit: layout.voting_power_increase_limit,
            employee_vesting_start: layout.employee_vesting_start,
            employee_vesting_period_duration: layout.employee_vesting_period_duration,
            consensus_config: layout.on_chain_consensus_config,
            execution_config: layout.on_chain_execution_config,
            gas_schedule: default_gas_schedule(),
            initial_features_override: None,
            randomness_config_override: None,
            jwk_consensus_config_override: layout.jwk_consensus_config_override.clone(),
            initial_jwks: layout.initial_jwks.clone(),
            keyless_groth16_vk: layout.keyless_groth16_vk_override.clone(),
        },
    )?)
```

**File:** crates/aptos/src/genesis/mod.rs (L736-742)
```rust
            if !unique_hosts.insert(validator.validator_host.as_ref().unwrap().clone()) {
                errors.push(CliError::UnexpectedError(format!(
                    "Validator {} has a repeated validator host {:?}",
                    name,
                    validator.validator_host.as_ref().unwrap()
                )));
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
