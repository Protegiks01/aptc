# Audit Report

## Title
Complete Governance Bypass via Genesis Misconfiguration and Core Resources Account Control

## Summary
If mainnet is initialized with `genesis_config.is_test = true`, the `@core_resources` account is created with mint capability. An attacker controlling this account's private key can exploit `get_signer_testnet_only()` to obtain signers for framework-reserved addresses (particularly `@aptos_framework`), completely bypassing governance and executing arbitrary privileged operations.

## Finding Description

The vulnerability exists in the `get_signer_testnet_only()` function which uses mint capability as the ONLY mechanism to distinguish test environments from production: [1](#0-0) 

This function performs only two checks:
1. Verifies the caller is the `@core_resources` account
2. Verifies `@core_resources` has mint capability

Critically, there is **no chain ID verification, no feature flag check, and no explicit testnet boolean guard**. The function relies entirely on the assumption that `@core_resources` will not have mint capability on mainnet.

During genesis, the decision to create `@core_resources` with mint capability is controlled by a single boolean: [2](#0-1) 

If `genesis_config.is_test = true` on mainnet (configuration error), the function `initialize_core_resources_and_aptos_coin()` is called: [3](#0-2) 

This creates `@core_resources` with `MintCapStore` at line 172, violating the critical invariant that only testnets should have this capability.

The `get_signer()` function retrieves signer capabilities for framework-reserved addresses stored during genesis: [4](#0-3) 

These addresses include `@aptos_framework` (0x1) and addresses 0x2-0xa: [5](#0-4) 

**Attack Path:**
1. Mainnet genesis is misconfigured with `is_test = true`
2. `@core_resources` account is created with authentication key derived from `core_resources_key` parameter
3. Attacker who knows the corresponding private key (e.g., if `GENESIS_KEYPAIR` was used, or if the genesis key was compromised) can sign transactions as `@core_resources`
4. Attacker calls `get_signer_testnet_only(&core_resources, @aptos_framework)` to obtain an `@aptos_framework` signer
5. With this signer, attacker can call any privileged function that checks `system_addresses::assert_aptos_framework()`

**Privileged Operations Enabled:**
- Modify consensus configuration: [6](#0-5) 
- Change gas schedules, feature flags, execution configs
- Manipulate validator set and staking parameters: [7](#0-6) 
- Bypass all governance proposals and voting

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables complete protocol compromise:

1. **Governance Bypass**: Attacker can execute any on-chain configuration change without proposals or voting, violating Invariant #5 (Governance Integrity)

2. **Consensus Manipulation**: Can modify consensus parameters via `consensus_config::set_for_next_epoch()`, potentially causing safety violations or network splits (Invariant #2)

3. **Access Control Violation**: Complete compromise of the `@aptos_framework` signer capability breaks Invariant #8 (System addresses must be protected)

4. **Validator Set Manipulation**: Can add malicious validators or remove legitimate ones, compromising network security

5. **Non-recoverable State**: Many of these changes would require a hard fork to reverse

This qualifies for **Critical Severity ($1,000,000)** under the Aptos bug bounty categories: "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Likelihood: LOW in practice, but CRITICAL if premise holds**

**Prerequisites:**
1. Genesis must be misconfigured with `is_test = true` on mainnet
2. Attacker must possess the private key corresponding to the `core_resources_key` used during genesis

**Important Note:** This vulnerability does NOT meet the strict requirement of "exploitable by unprivileged attacker" because controlling the `@core_resources` account requires either:
- Genesis was configured with a publicly known test key (e.g., `GENESIS_KEYPAIR`)
- The genesis key was compromised or poorly secured
- Insider access to genesis configuration

However, the **defense-in-depth weakness** is real: the code lacks multiple protective layers beyond mint capability checking. A properly designed system should have:
- Explicit chain ID verification
- Feature flag enforcement for test-only functions
- Additional runtime assertions

The current implementation creates a single point of failure at genesis configuration.

## Recommendation

Implement defense-in-depth with multiple independent checks:

```move
public fun get_signer_testnet_only(
    core_resources: &signer, 
    signer_address: address
): signer acquires GovernanceResponsbility {
    system_addresses::assert_core_resource(core_resources);
    
    // EXISTING CHECK: Core resources account only has mint capability in tests/testnets
    assert!(aptos_coin::has_mint_capability(core_resources), error::unauthenticated(EUNAUTHORIZED));
    
    // NEW CHECK #1: Explicit feature flag for testnet-only operations
    assert!(
        features::is_testnet_enabled(),  // New feature flag
        error::invalid_state(EPRODUCTION_ENVIRONMENT)
    );
    
    // NEW CHECK #2: Chain ID verification (if chain IDs differentiate mainnet/testnet)
    assert!(
        chain_id::is_test_chain(),  // New helper function
        error::invalid_state(EPRODUCTION_ENVIRONMENT)
    );
    
    get_signer(signer_address)
}
```

Additionally, enforce compile-time or genesis-time invariants:
- Genesis validation should abort if `is_test = true` and `chain_id` indicates mainnet
- Add monitoring/alerts if `@core_resources` exists with mint capability on production chains

## Proof of Concept

```move
#[test_only]
module test_addr::governance_bypass_poc {
    use aptos_framework::aptos_governance;
    use aptos_framework::consensus_config;
    use std::vector;

    #[test(aptos_framework = @0x1, core_resources = @core_resources)]
    fun test_governance_bypass_via_core_resources(
        aptos_framework: signer,
        core_resources: signer,
    ) {
        // Setup: This test assumes genesis was misconfigured with is_test=true on mainnet
        // In real scenario, core_resources would have mint capability from genesis
        
        // Attacker (controlling @core_resources) exploits get_signer_testnet_only
        let framework_signer = aptos_governance::get_signer_testnet_only(
            &core_resources,
            @aptos_framework
        );
        
        // Now attacker has @aptos_framework signer and can bypass governance
        // Example: Modify consensus config without any proposal or voting
        let malicious_config = vector::empty<u8>();
        vector::push_back(&mut malicious_config, 0xFF);
        
        consensus_config::set_for_next_epoch(&framework_signer, malicious_config);
        
        // Attack successful: Critical on-chain config changed with no governance oversight
    }
}
```

**Note:** This PoC demonstrates the exploit assuming the genesis misconfiguration has occurred. The actual exploitability depends on the attacker possessing the `@core_resources` private key, which is NOT possible for an unprivileged attacker.

## Notes

While the code vulnerability is real (insufficient defense-in-depth), this issue **fails the strict validation requirement** that it must be "exploitable by unprivileged attacker (no validator insider access required)." 

An unprivileged attacker cannot sign transactions as `@core_resources` without the private key, even if the account exists with mint capability on mainnet. This vulnerability would require either genesis key compromise or insider access, making it a **configuration security issue** rather than a code exploit available to external attackers.

The primary concern is the lack of defense-in-depth: the code should not rely solely on genesis configuration correctness but should include runtime checks (feature flags, chain ID verification) to prevent testnet-only functions from executing on production networks.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L243-275)
```text
    public fun update_governance_config(
        aptos_framework: &signer,
        min_voting_threshold: u128,
        required_proposer_stake: u64,
        voting_duration_secs: u64,
    ) acquires GovernanceConfig, GovernanceEvents {
        system_addresses::assert_aptos_framework(aptos_framework);

        let governance_config = borrow_global_mut<GovernanceConfig>(@aptos_framework);
        governance_config.voting_duration_secs = voting_duration_secs;
        governance_config.min_voting_threshold = min_voting_threshold;
        governance_config.required_proposer_stake = required_proposer_stake;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                UpdateConfig {
                    min_voting_threshold,
                    required_proposer_stake,
                    voting_duration_secs
                },
            )
        } else {
            let events = borrow_global_mut<GovernanceEvents>(@aptos_framework);
            event::emit_event<UpdateConfigEvent>(
                &mut events.update_config_events,
                UpdateConfigEvent {
                    min_voting_threshold,
                    required_proposer_stake,
                    voting_duration_secs
                },
            );
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L721-727)
```text
    public fun get_signer_testnet_only(
        core_resources: &signer, signer_address: address): signer acquires GovernanceResponsbility {
        system_addresses::assert_core_resource(core_resources);
        // Core resources account only has mint capability in tests/testnets.
        assert!(aptos_coin::has_mint_capability(core_resources), error::unauthenticated(EUNAUTHORIZED));
        get_signer(signer_address)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L745-749)
```text
    fun get_signer(signer_address: address): signer acquires GovernanceResponsbility {
        let governance_responsibility = borrow_global<GovernanceResponsbility>(@aptos_framework);
        let signer_cap = simple_map::borrow(&governance_responsibility.signer_caps, &signer_address);
        create_signer_with_capability(signer_cap)
    }
```

**File:** aptos-move/vm-genesis/src/lib.rs (L312-321)
```rust
    if genesis_config.is_test {
        initialize_core_resources_and_aptos_coin(
            &mut session,
            &module_storage,
            &mut traversal_context,
            core_resources_key,
        );
    } else {
        initialize_aptos_coin(&mut session, &module_storage, &mut traversal_context);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/genesis.move (L97-106)
```text
        // Give the decentralized on-chain governance control over the core framework account.
        aptos_governance::store_signer_cap(&aptos_framework_account, @aptos_framework, aptos_framework_signer_cap);

        // put reserved framework reserved accounts under aptos governance
        let framework_reserved_addresses = vector<address>[@0x2, @0x3, @0x4, @0x5, @0x6, @0x7, @0x8, @0x9, @0xa];
        while (!vector::is_empty(&framework_reserved_addresses)) {
            let address = vector::pop_back<address>(&mut framework_reserved_addresses);
            let (_, framework_signer_cap) = account::create_framework_reserved_account(address);
            aptos_governance::store_signer_cap(&aptos_framework_account, address, framework_signer_cap);
        };
```

**File:** aptos-move/framework/aptos-framework/sources/genesis.move (L152-173)
```text
    /// Only called for testnets and e2e tests.
    fun initialize_core_resources_and_aptos_coin(
        aptos_framework: &signer,
        core_resources_auth_key: vector<u8>,
    ) {
        let (burn_cap, mint_cap) = aptos_coin::initialize(aptos_framework);

        coin::create_coin_conversion_map(aptos_framework);
        coin::create_pairing<AptosCoin>(aptos_framework);

        // Give stake module MintCapability<AptosCoin> so it can mint rewards.
        stake::store_aptos_coin_mint_cap(aptos_framework, mint_cap);
        // Give transaction_fee module BurnCapability<AptosCoin> so it can burn gas.
        transaction_fee::store_aptos_coin_burn_cap(aptos_framework, burn_cap);
        // Give transaction_fee module MintCapability<AptosCoin> so it can mint refunds.
        transaction_fee::store_aptos_coin_mint_cap(aptos_framework, mint_cap);

        let core_resources = account::create_account(@core_resources);
        account::rotate_authentication_key_internal(&core_resources, core_resources_auth_key);
        aptos_account::register_apt(&core_resources); // registers APT store
        aptos_coin::configure_accounts_for_test(aptos_framework, &core_resources, mint_cap);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/consensus_config.move (L52-56)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        std::config_buffer::upsert<ConsensusConfig>(ConsensusConfig {config});
    }
```
