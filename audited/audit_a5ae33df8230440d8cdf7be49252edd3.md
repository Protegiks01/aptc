# Audit Report

## Title
Genesis Validator Consensus Key Duplication Allows Byzantine Fault Tolerance Threshold Bypass

## Summary
The genesis initialization process lacks on-chain validation to prevent duplicate consensus public keys across validators. While the Aptos CLI performs client-side validation, the Move framework and Rust genesis encoding do not enforce uniqueness of consensus keys, allowing multiple validators with different owner addresses but identical consensus keys to join the genesis validator set. This enables a single entity controlling one BLS private key to control multiple validator slots and exceed the Byzantine fault tolerance threshold.

## Finding Description
The vulnerability exists in the genesis validator initialization flow across three layers:

**Layer 1 - Rust Genesis Creation**: In the `GenesisInfo::new()` function, validator configurations are converted to `Validator` structs without any duplication checks: [1](#0-0) 

**Layer 2 - Genesis Transaction Encoding**: The `encode_genesis_change_set()` function serializes validators and calls Move genesis functions without validation: [2](#0-1) 

**Layer 3 - Move Genesis Execution**: The `create_initialize_validators()` function processes each validator sequentially without checking for duplicate consensus keys: [3](#0-2) 

Each validator calls `create_initialize_validator()` which creates separate accounts and stake pools: [4](#0-3) 

The `rotate_consensus_key()` function only validates proof-of-possession, not uniqueness across validators: [5](#0-4) 

Finally, `join_validator_set_internal()` adds validators to the ValidatorSet without checking if their consensus public key already exists: [6](#0-5) 

**Attack Scenario**: An attacker with access to the genesis creation process can:
1. Generate a single BLS key pair (SK, PK) with proof-of-possession PoP
2. Create N validator configurations with different owner addresses but the same consensus_pubkey=PK and proof_of_possession=PoP
3. Bypass the CLI validation (which checks for duplicates) by directly calling the Rust genesis encoding functions
4. All N validators pass on-chain validation because PoP is cryptographically valid
5. The attacker controls N validators with a single private key SK, multiplying their voting power by N

**Critical Note**: The only protection is CLI-side validation in `crates/aptos/src/genesis/mod.rs`: [7](#0-6) 

However, this is **client-side validation** that can be bypassed.

## Impact Explanation
**Severity: Critical** - This vulnerability breaks the fundamental Byzantine fault tolerance guarantee:

1. **Consensus Safety Violation**: AptosBFT assumes each validator is controlled by a distinct entity. If one entity controls multiple validator slots through duplicate consensus keys, they can exceed the 1/3 Byzantine threshold and:
   - Force arbitrary state transitions
   - Double-spend transactions
   - Prevent legitimate transactions from committing
   - Create chain forks

2. **Voting Power Multiplication**: With each duplicate validator slot, the attacker's effective voting power multiplies. If they create 4 validators with the same consensus key and each has 10% stake, they control 40% of voting power with a single private key—exceeding the 33% Byzantine threshold.

3. **Network Compromise**: Once the Byzantine threshold is exceeded, the attacker can:
   - Violate safety by committing conflicting blocks
   - Halt the network by refusing to participate
   - Mint arbitrary amounts of tokens (loss of funds)

This meets the **Critical Severity** criteria: "Consensus/Safety violations" and potentially "Loss of Funds (theft or minting)".

## Likelihood Explanation
**Likelihood: Low (but High Impact)**

This vulnerability requires:
1. **Genesis Creation Access**: Only network founders/operators who create the genesis transaction can exploit this
2. **Intentional Bypass**: Must deliberately bypass CLI validation by directly using lower-level APIs
3. **One-Time Window**: Only exploitable during genesis creation, not during normal network operation

However, the likelihood increases in scenarios where:
- A malicious insider has access to genesis creation infrastructure
- The CLI validation has implementation bugs allowing bypass
- Alternative genesis creation tools are developed without proper validation
- Someone forks Aptos to create a new network and makes this mistake

The **lack of defense-in-depth** (no on-chain enforcement) makes this a protocol-level weakness even though exploitation requires privileged access.

## Recommendation
Implement on-chain validation in the Move genesis framework to enforce consensus key uniqueness:

**Fix Location**: `aptos-move/framework/aptos-framework/sources/genesis.move`

Add a duplicate check in `create_initialize_validators_with_commission()` before processing validators:

```move
fun create_initialize_validators_with_commission(
    aptos_framework: &signer,
    use_staking_contract: bool,
    validators: vector<ValidatorConfigurationWithCommission>,
) {
    // NEW: Check for duplicate consensus keys
    let unique_consensus_keys = vector::empty();
    vector::for_each_ref(&validators, |validator_config| {
        let validator_config: &ValidatorConfigurationWithCommission = validator_config;
        let pubkey = &validator_config.validator_config.consensus_pubkey;
        assert!(
            !vector::contains(&unique_consensus_keys, pubkey),
            error::invalid_argument(EDUPLICATE_CONSENSUS_KEY)
        );
        vector::push_back(&mut unique_consensus_keys, *pubkey);
    });
    
    // Existing code
    vector::for_each_ref(&validators, |validator| {
        let validator: &ValidatorConfigurationWithCommission = validator;
        create_initialize_validator(aptos_framework, validator, use_staking_contract);
    });
    
    aptos_coin::destroy_mint_cap(aptos_framework);
    stake::on_new_epoch();
}
```

Add the error constant:
```move
const EDUPLICATE_CONSENSUS_KEY: u64 = 3;
```

## Proof of Concept
```rust
// Rust PoC demonstrating genesis creation with duplicate consensus keys
use aptos_crypto::bls12381;
use aptos_vm_genesis::Validator;
use aptos_types::account_address::AccountAddress;

fn create_malicious_genesis() {
    // Generate a single BLS key pair
    let consensus_key = bls12381::PrivateKey::generate(&mut rand::thread_rng());
    let consensus_pubkey = consensus_key.public_key().to_bytes().to_vec();
    let proof_of_possession = bls12381::ProofOfPossession::create(&consensus_key)
        .to_bytes()
        .to_vec();
    
    // Create multiple validators with DIFFERENT addresses but SAME consensus key
    let validators = vec![
        Validator {
            owner_address: AccountAddress::from_hex_literal("0x1").unwrap(),
            operator_address: AccountAddress::from_hex_literal("0x1").unwrap(),
            voter_address: AccountAddress::from_hex_literal("0x1").unwrap(),
            stake_amount: 1_000_000,
            consensus_pubkey: consensus_pubkey.clone(),
            proof_of_possession: proof_of_possession.clone(),
            network_addresses: vec![],
            full_node_network_addresses: vec![],
        },
        Validator {
            owner_address: AccountAddress::from_hex_literal("0x2").unwrap(),
            operator_address: AccountAddress::from_hex_literal("0x2").unwrap(),
            voter_address: AccountAddress::from_hex_literal("0x2").unwrap(),
            stake_amount: 1_000_000,
            consensus_pubkey: consensus_pubkey.clone(), // DUPLICATE!
            proof_of_possession: proof_of_possession.clone(), // DUPLICATE!
            network_addresses: vec![],
            full_node_network_addresses: vec![],
        },
    ];
    
    // This would pass on-chain validation because:
    // 1. Different owner addresses (0x1 vs 0x2) - no EALREADY_REGISTERED error
    // 2. Valid proof-of-possession for both - cryptographically correct
    // 3. No uniqueness check for consensus_pubkey in Move code
    
    // Result: Attacker controls 2 validators with 1 private key
    // If each has 20% stake, effective voting power = 40% > 33% Byzantine threshold
}
```

## Notes
- This vulnerability requires **genesis creation access**, making it an **insider threat** or **genesis infrastructure compromise** scenario rather than an external attacker exploit
- The CLI validation provides protection in normal workflows, but defense-in-depth requires protocol-level enforcement
- The same issue applies to duplicate proof-of-possession values, network keys, and validator host addresses
- Runtime validator joins after genesis use the standard `join_validator_set()` entry function which is subject to different constraints and governance

### Citations

**File:** crates/aptos-genesis/src/lib.rs (L86-98)
```rust
    pub fn new(
        chain_id: ChainId,
        root_key: Ed25519PublicKey,
        configs: Vec<ValidatorConfiguration>,
        framework: ReleaseBundle,
        genesis_config: &GenesisConfiguration,
    ) -> anyhow::Result<GenesisInfo> {
        let mut validators = Vec::new();

        for config in configs {
            validators.push(config.try_into()?)
        }

```

**File:** aptos-move/vm-genesis/src/lib.rs (L262-302)
```rust
pub fn encode_genesis_change_set(
    core_resources_key: &Ed25519PublicKey,
    validators: &[Validator],
    framework: &ReleaseBundle,
    chain_id: ChainId,
    genesis_config: &GenesisConfiguration,
    consensus_config: &OnChainConsensusConfig,
    execution_config: &OnChainExecutionConfig,
    gas_schedule: &GasScheduleV2,
) -> ChangeSet {
    validate_genesis_config(genesis_config);

    let mut state_view = GenesisStateView::new();
    for (module_bytes, module) in framework.code_and_compiled_modules() {
        state_view.add_module(&module.self_id(), module_bytes);
    }

    let genesis_runtime_builder = GenesisRuntimeBuilder::new(chain_id);
    let genesis_runtime_environment = genesis_runtime_builder.build_genesis_runtime_environment();

    let module_storage = state_view.as_aptos_code_storage(&genesis_runtime_environment);
    let resolver = state_view.as_move_resolver();

    let genesis_vm = genesis_runtime_builder.build_genesis_vm();
    let genesis_change_set_configs = genesis_vm.genesis_change_set_configs();
    let mut session = genesis_vm.new_genesis_session(&resolver, HashValue::zero());

    let traversal_storage = TraversalStorage::new();
    let mut traversal_context = TraversalContext::new(&traversal_storage);

    // On-chain genesis process.
    initialize(
        &mut session,
        &module_storage,
        &mut traversal_context,
        chain_id,
        genesis_config,
        consensus_config,
        execution_config,
        gas_schedule,
    );
```

**File:** aptos-move/framework/aptos-framework/sources/genesis.move (L324-336)
```text
    fun create_initialize_validators(aptos_framework: &signer, validators: vector<ValidatorConfiguration>) {
        let validators_with_commission = vector::empty();
        vector::for_each_reverse(validators, |validator| {
            let validator_with_commission = ValidatorConfigurationWithCommission {
                validator_config: validator,
                commission_percentage: 0,
                join_during_genesis: true,
            };
            vector::push_back(&mut validators_with_commission, validator_with_commission);
        });

        create_initialize_validators_with_commission(aptos_framework, false, validators_with_commission);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/genesis.move (L338-373)
```text
    fun create_initialize_validator(
        aptos_framework: &signer,
        commission_config: &ValidatorConfigurationWithCommission,
        use_staking_contract: bool,
    ) {
        let validator = &commission_config.validator_config;

        let owner = &create_account(aptos_framework, validator.owner_address, validator.stake_amount);
        create_account(aptos_framework, validator.operator_address, 0);
        create_account(aptos_framework, validator.voter_address, 0);

        // Initialize the stake pool and join the validator set.
        let pool_address = if (use_staking_contract) {
            staking_contract::create_staking_contract(
                owner,
                validator.operator_address,
                validator.voter_address,
                validator.stake_amount,
                commission_config.commission_percentage,
                x"",
            );
            staking_contract::stake_pool_address(validator.owner_address, validator.operator_address)
        } else {
            stake::initialize_stake_owner(
                owner,
                validator.stake_amount,
                validator.operator_address,
                validator.voter_address,
            );
            validator.owner_address
        };

        if (commission_config.join_during_genesis) {
            initialize_validator(pool_address, validator);
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L910-932)
```text
    public entry fun rotate_consensus_key(
        operator: &signer,
        pool_address: address,
        new_consensus_pubkey: vector<u8>,
        proof_of_possession: vector<u8>,
    ) acquires StakePool, ValidatorConfig {
        check_stake_permission(operator);
        assert_reconfig_not_in_progress();
        assert_stake_pool_exists(pool_address);

        let stake_pool = borrow_global_mut<StakePool>(pool_address);
        assert!(signer::address_of(operator) == stake_pool.operator_address, error::unauthenticated(ENOT_OPERATOR));

        assert!(exists<ValidatorConfig>(pool_address), error::not_found(EVALIDATOR_CONFIG));
        let validator_info = borrow_global_mut<ValidatorConfig>(pool_address);
        let old_consensus_pubkey = validator_info.consensus_pubkey;
        // Checks the public key has a valid proof-of-possession to prevent rogue-key attacks.
        let pubkey_from_pop = &bls12381::public_key_from_bytes_with_pop(
            new_consensus_pubkey,
            &proof_of_possession_from_bytes(proof_of_possession)
        );
        assert!(option::is_some(pubkey_from_pop), error::invalid_argument(EINVALID_PUBLIC_KEY));
        validator_info.consensus_pubkey = new_consensus_pubkey;
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1081-1090)
```text
        // Add validator to pending_active, to be activated in the next epoch.
        let validator_config = borrow_global<ValidatorConfig>(pool_address);
        assert!(!vector::is_empty(&validator_config.consensus_pubkey), error::invalid_argument(EINVALID_PUBLIC_KEY));

        // Validate the current validator set size has not exceeded the limit.
        let validator_set = borrow_global_mut<ValidatorSet>(@aptos_framework);
        vector::push_back(
            &mut validator_set.pending_active,
            generate_validator_info(pool_address, stake_pool, *validator_config)
        );
```

**File:** crates/aptos/src/genesis/mod.rs (L750-758)
```rust
            if !unique_consensus_keys
                .insert(validator.consensus_public_key.as_ref().unwrap().clone())
            {
                errors.push(CliError::UnexpectedError(format!(
                    "Validator {} has a repeated a consensus public key {}",
                    name,
                    validator.consensus_public_key.as_ref().unwrap()
                )));
            }
```
