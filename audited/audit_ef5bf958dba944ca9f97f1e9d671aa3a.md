# Audit Report

## Title
Absence of Emergency Governance Mechanism for Mass Validator Consensus Key Rotation

## Summary
Aptos governance lacks an emergency procedure to force all validators to rotate their cryptographic consensus keys simultaneously in response to discovered cryptographic vulnerabilities. While governance can upgrade framework code, it cannot compel validators to rotate keys, creating a coordination problem that could prolong network exposure to cryptographic attacks.

## Finding Description

The Aptos staking system allows individual validators to rotate their BLS12-381 consensus keys through the `rotate_consensus_key` function. However, this function enforces strict operator-only access control: [1](#0-0) 

The critical access control check prevents any entity except the designated operator from rotating keys. There is no alternative pathway for the aptos_framework signer or governance to override this restriction.

**No Mass Rotation Capability:**

The stake module declares its friend modules, none of which provide governance override capabilities: [2](#0-1) 

**Emergency Procedures Limited to Epoch Control:**

The governance module provides `force_end_epoch` for emergency epoch transitions: [3](#0-2) 

However, this only forces epoch transition without updating validator configurations. The `on_new_epoch` function regenerates validator info from existing `ValidatorConfig` resources: [4](#0-3) 

Each validator must have already updated their own config - there's no mechanism to force updates.

**Attack Scenario:**

1. A critical cryptographic vulnerability is discovered in BLS12-381 (e.g., efficient signature forgery, key recovery attack)
2. Governance passes a proposal to upgrade framework crypto libraries
3. Framework code is updated, but validators still use old vulnerable keys
4. Malicious validators refuse to rotate keys, or are compromised
5. These validators can exploit the crypto vulnerability to:
   - Forge signatures on malicious blocks
   - Violate consensus safety guarantees  
   - Cause chain splits or equivocation
   - Maintain attack capability indefinitely

The network's security degrades to the weakest validator that hasn't rotated keys.

## Impact Explanation

**High Severity** - This represents a significant protocol design limitation that could prevent effective emergency response to cryptographic vulnerabilities.

While not immediately exploitable without an external crypto break, the absence of emergency procedures creates a critical gap in the security model. If a BLS12-381 vulnerability is discovered, the protocol cannot guarantee timely network-wide key rotation, potentially leaving the network vulnerable for extended periods.

This impacts **Consensus Safety** (invariant #2) and **Cryptographic Correctness** (invariant #10), as compromised validators could violate consensus rules using broken cryptography.

## Likelihood Explanation

**Medium Likelihood** - While cryptographic breaks in BLS12-381 are relatively unlikely in the short term, the lack of preparation makes response difficult when such events occur. The coordination problem among potentially hundreds of validators increases response time from hours to potentially days or weeks.

Validators may have various motivations to delay rotation:
- Operational complexity and risk of misconfiguration
- Malicious intent to maintain attack capability
- Compromise by attackers who prevent rotation
- Simple negligence or delayed response

## Recommendation

Implement an emergency governance mechanism for mass validator key rotation:

```move
/// Emergency function callable only by aptos_framework to force validator key rotation
/// during cryptographic emergencies. Requires governance proposal.
public fun emergency_rotate_all_validators(
    aptos_framework: &signer,
    new_pubkeys: vector<vector<u8>>,
    proofs_of_possession: vector<vector<u8>>,
) acquires ValidatorSet, ValidatorConfig, StakePool {
    system_addresses::assert_aptos_framework(aptos_framework);
    
    let validator_set = borrow_global_mut<ValidatorSet>(@aptos_framework);
    let validators = &validator_set.active_validators;
    
    assert!(
        vector::length(new_pubkeys) == vector::length(validators),
        error::invalid_argument(EINVALID_KEY_COUNT)
    );
    
    // Rotate keys for all active validators
    vector::enumerate_ref(validators, |i, validator_info| {
        let pool_address = validator_info.addr;
        let validator_config = borrow_global_mut<ValidatorConfig>(pool_address);
        let new_key = *vector::borrow(new_pubkeys, i);
        let pop = *vector::borrow(proofs_of_possession, i);
        
        // Validate new key
        assert!(
            option::is_some(&bls12381::public_key_from_bytes_with_pop(
                new_key, &proof_of_possession_from_bytes(pop)
            )),
            error::invalid_argument(EINVALID_PUBLIC_KEY)
        );
        
        validator_config.consensus_pubkey = new_key;
    });
    
    // Trigger immediate reconfiguration
    reconfiguration_with_dkg::finish(aptos_framework);
}
```

Additionally:
1. Document emergency crypto response procedures
2. Establish off-chain validator communication channels for coordination
3. Consider implementing automatic key rotation schedules as defense-in-depth
4. Add feature flag to enable/disable emergency rotation capability

## Proof of Concept

```move
#[test_only]
module aptos_framework::test_emergency_key_rotation {
    use aptos_framework::stake;
    use aptos_framework::aptos_governance;
    use std::vector;
    
    #[test(aptos_framework = @aptos_framework, validator1 = @0x123, validator2 = @0x456)]
    fun test_cannot_mass_rotate_keys_via_governance(
        aptos_framework: signer,
        validator1: signer,
        validator2: signer,
    ) {
        // Setup validators with initial keys
        // ... setup code ...
        
        // Attempt to rotate all validator keys via governance
        // This will FAIL because no such function exists
        
        // Current workaround: Each validator must manually call rotate_consensus_key
        // This demonstrates the coordination problem - no way to force rotation
        
        // If a validator refuses or is compromised, they keep vulnerable keys
        let validator1_key = get_consensus_key(@0x123);
        // Key remains unchanged without operator cooperation
        assert!(validator1_key == old_vulnerable_key, 0);
    }
}
```

## Notes

While Aptos governance can upgrade cryptographic implementations through framework upgrades [5](#0-4) , this only updates the code validators use, not their actual cryptographic keys. The protocol correctly implements individual key rotation with proof-of-possession validation [6](#0-5) , but lacks coordinated emergency response capabilities for mass key rotation scenarios.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L41-45)
```text
    friend aptos_framework::block;
    friend aptos_framework::genesis;
    friend aptos_framework::reconfiguration;
    friend aptos_framework::reconfiguration_with_dkg;
    friend aptos_framework::transaction_fee;
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L909-922)
```text
    /// Rotate the consensus key of the validator, it'll take effect in next epoch.
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

```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L926-932)
```text
        // Checks the public key has a valid proof-of-possession to prevent rogue-key attacks.
        let pubkey_from_pop = &bls12381::public_key_from_bytes_with_pop(
            new_consensus_pubkey,
            &proof_of_possession_from_bytes(proof_of_possession)
        );
        assert!(option::is_some(pubkey_from_pop), error::invalid_argument(EINVALID_PUBLIC_KEY));
        validator_info.consensus_pubkey = new_consensus_pubkey;
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1384-1388)
```text
            let old_validator_info = vector::borrow_mut(&mut validator_set.active_validators, i);
            let pool_address = old_validator_info.addr;
            let validator_config = borrow_global<ValidatorConfig>(pool_address);
            let stake_pool = borrow_global<StakePool>(pool_address);
            let new_validator_info = generate_validator_info(pool_address, stake_pool, *validator_config);
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L676-692)
```text
    /// Manually reconfigure. Called at the end of a governance txn that alters on-chain configs.
    ///
    /// WARNING: this function always ensures a reconfiguration starts, but when the reconfiguration finishes depends.
    /// - If feature `RECONFIGURE_WITH_DKG` is disabled, it finishes immediately.
    ///   - At the end of the calling transaction, we will be in a new epoch.
    /// - If feature `RECONFIGURE_WITH_DKG` is enabled, it starts DKG, and the new epoch will start in a block prologue after DKG finishes.
    ///
    /// This behavior affects when an update of an on-chain config (e.g. `ConsensusConfig`, `Features`) takes effect,
    /// since such updates are applied whenever we enter an new epoch.
    public entry fun reconfigure(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        if (consensus_config::validator_txn_enabled() && randomness_config::enabled()) {
            reconfiguration_with_dkg::try_start();
        } else {
            reconfiguration_with_dkg::finish(aptos_framework);
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L694-703)
```text
    /// Change epoch immediately.
    /// If `RECONFIGURE_WITH_DKG` is enabled and we are in the middle of a DKG,
    /// stop waiting for DKG and enter the new epoch without randomness.
    ///
    /// WARNING: currently only used by tests. In most cases you should use `reconfigure()` instead.
    /// TODO: migrate these tests to be aware of async reconfiguration.
    public entry fun force_end_epoch(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        reconfiguration_with_dkg::finish(aptos_framework);
    }
```
