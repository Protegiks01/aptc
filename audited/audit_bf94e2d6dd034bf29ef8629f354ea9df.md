# Audit Report

## Title
Feature Flag Activation Timing Attack via DKG Reconfiguration Window

## Summary
When DKG-based reconfiguration is enabled, feature flag changes approved by governance are staged in `PendingFeatures` but not immediately applied to `Features`. This creates a timing window during which attackers can execute transactions using vulnerable cryptographic operations (such as hash-to-curve) even after governance has voted to disable them, defeating emergency security responses.

## Finding Description

The vulnerability exists in the interaction between the feature flag system and the asynchronous DKG (Distributed Key Generation) reconfiguration mechanism.

**Feature Flag Check Flow:**

The `hash_to_internal` native function checks feature flags using the `abort_unless_hash_to_structure_enabled!` macro: [1](#0-0) 

This macro ultimately calls `is_enabled()` which only checks the `Features` resource, not `PendingFeatures`: [2](#0-1) 

**Governance Activation Flow:**

When governance executes `toggle_features()` to disable a vulnerable feature: [3](#0-2) 

The changes are staged via `change_feature_flags_for_next_epoch()`: [4](#0-3) 

Then `reconfigure()` is called, which behaves differently based on DKG status: [5](#0-4) 

**The Vulnerability:**

When DKG is enabled, `try_start()` initiates DKG but does NOT apply the feature flag changes: [6](#0-5) 

Changes only apply when `finish()` is called after DKG completes: [7](#0-6) 

**Attack Scenario:**

1. A vulnerability is discovered in BLS12-381 hash-to-curve operations
2. Governance creates and approves a proposal to disable `BLS12_381_STRUCTURES` feature flag
3. The governance transaction executes, staging the disable in `PendingFeatures`
4. If DKG is enabled, reconfiguration starts asynchronously via `try_start()`
5. **Timing Window Opens:** Feature appears enabled in `Features` but is staged for disable in `PendingFeatures`
6. Attackers submit transactions calling hash-to-curve operations
7. The feature flag check passes because `is_enabled()` checks `Features`, not `PendingFeatures`
8. Attackers successfully exploit the vulnerability during the DKG window (multiple blocks/rounds)
9. DKG eventually completes, `on_new_epoch()` applies the staged changes, feature is disabled
10. Attack window closes, but exploitation has already occurred

Unlike staking operations which block during reconfiguration: [8](#0-7) 

Cryptographic native functions have no such protection and continue operating with stale feature flag state.

## Impact Explanation

**Severity: Medium**

This vulnerability qualifies as Medium severity under the Aptos bug bounty criteria because it enables:

1. **State inconsistencies requiring intervention**: Emergency governance decisions don't take effect immediately, creating inconsistent security posture
2. **Defeats emergency security responses**: When a critical vulnerability is discovered, governance cannot immediately disable the vulnerable feature
3. **Exploitation of known vulnerabilities**: Attackers can exploit vulnerabilities that governance has already voted to patch

The impact is limited to the DKG reconfiguration window (multiple blocks but typically not catastrophic duration), and requires a pre-existing vulnerability in the cryptographic operations to be exploitable. However, it fundamentally undermines the governance system's ability to respond to security emergencies.

## Likelihood Explanation

**Likelihood: Medium**

The attack is likely to occur under specific conditions:

**Required Conditions:**
- DKG-based reconfiguration must be enabled (typical on mainnet)
- A security vulnerability must exist in a feature-flagged operation
- Governance must respond by disabling/modifying the feature flag
- Attackers must monitor governance proposals and act during the window

**Attacker Requirements:**
- Monitor on-chain governance proposals (publicly visible)
- Submit transactions quickly after governance execution
- Understand the timing window mechanics
- Have an exploit ready for the underlying vulnerability

**Complexity: Low-Medium**
- No special privileges required
- Straightforward transaction submission
- Window duration depends on DKG completion time (variable but measurable)

The likelihood is not "High" because it requires a confluence of circumstances (existing vulnerability + governance response + attacker awareness), but it's not "Low" because all these conditions can realistically occur and the attack is technically simple to execute.

## Recommendation

Implement one or more of the following mitigations:

**Option 1: Immediate feature flag application for security-critical changes**

Add a separate fast-path mechanism that bypasses DKG for emergency security updates:

```move
public fun toggle_features_immediate(aptos_framework: &signer, enable: vector<u64>, disable: vector<u64>) {
    system_addresses::assert_aptos_framework(aptos_framework);
    features::change_feature_flags_internal(aptos_framework, enable, disable);
    // Note: This should only be used for emergency security responses
}
```

**Option 2: Check PendingFeatures in addition to Features**

Modify `is_enabled()` to also check if a feature is pending disable:

```move
public fun is_enabled(feature: u64): bool acquires Features, PendingFeatures {
    let currently_enabled = exists<Features>(@std) && contains(&Features[@std].features, feature);
    
    // If feature is currently enabled, check if it's pending disable
    if (currently_enabled && exists<PendingFeatures>(@std)) {
        let pending_enabled = contains(&PendingFeatures[@std].features, feature);
        return pending_enabled  // Only enabled if not staged for disable
    };
    
    currently_enabled
}
```

**Option 3: Legitimize force_end_epoch for production**

Document and support `force_end_epoch()` as the official emergency bypass mechanism: [9](#0-8) 

Update its documentation to indicate it's the appropriate response for security emergencies.

**Recommended Approach:** Option 2 is the most comprehensive fix as it closes the timing window entirely while maintaining the benefits of async reconfiguration for non-security changes.

## Proof of Concept

```move
#[test_only]
module std::feature_flag_timing_attack_test {
    use std::features;
    use aptos_framework::reconfiguration_with_dkg;
    use aptos_framework::aptos_governance;
    
    #[test(framework = @std)]
    fun test_feature_flag_timing_attack(framework: &signer) {
        // Setup: Enable a feature flag
        features::change_feature_flags_for_testing(
            framework, 
            vector[features::get_bls12_381_strutures_feature()], 
            vector[]
        );
        
        // Verify feature is enabled
        assert!(features::bls12_381_structures_enabled(), 1);
        
        // Governance votes to disable the feature (simulating security response)
        features::change_feature_flags_for_next_epoch(
            framework,
            vector[],
            vector[features::get_bls12_381_strutures_feature()]
        );
        
        // VULNERABILITY: Feature is still enabled in Features resource
        // even though it's staged for disable in PendingFeatures
        assert!(features::bls12_381_structures_enabled(), 2);
        
        // Attacker can still use the feature during this window
        // (In real scenario, this would be hash-to-curve operations)
        
        // Only after on_new_epoch() is called does the change apply
        features::on_new_epoch(framework);
        assert!(!features::bls12_381_structures_enabled(), 3);
    }
}
```

**Notes:**
- The actual DKG completion time varies based on network conditions and validator participation
- This vulnerability is explicitly documented as expected behavior in the WARNING comment, but the security implications of front-running are not addressed
- The existence of `force_end_epoch()` suggests awareness of the issue, but it's marked as test-only with no production guidance
- No other on-chain configs (ConsensusConfig, ExecutionConfig, etc.) implement checks against `PendingFeatures`, indicating this is a systemic design issue affecting all async reconfiguration scenarios

### Citations

**File:** aptos-move/framework/src/natives/cryptography/algebra/hash_to_structure.rs (L40-45)
```rust
macro_rules! abort_unless_hash_to_structure_enabled {
    ($context:ident, $structure_opt:expr, $suite_opt:expr) => {
        let flag_opt = feature_flag_of_hash_to_structure($structure_opt, $suite_opt);
        abort_unless_feature_flag_enabled!($context, flag_opt);
    };
}
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L805-828)
```text
    public fun change_feature_flags_for_next_epoch(
        framework: &signer,
        enable: vector<u64>,
        disable: vector<u64>
    ) acquires PendingFeatures, Features {
        assert!(signer::address_of(framework) == @std, error::permission_denied(EFRAMEWORK_SIGNER_NEEDED));

        // Figure out the baseline feature vec that the diff will be applied to.
        let new_feature_vec = if (exists<PendingFeatures>(@std)) {
            // If there is a buffered feature vec, use it as the baseline.
            let PendingFeatures { features } = move_from<PendingFeatures>(@std);
            features
        } else if (exists<Features>(@std)) {
            // Otherwise, use the currently effective feature flag vec as the baseline, if it exists.
            Features[@std].features
        } else {
            // Otherwise, use an empty feature vec.
            vector[]
        };

        // Apply the diff and save it to the buffer.
        apply_diff(&mut new_feature_vec, enable, disable);
        move_to(framework, PendingFeatures { features: new_feature_vec });
    }
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L848-851)
```text
    public fun is_enabled(feature: u64): bool acquires Features {
        exists<Features>(@std) &&
            contains(&Features[@std].features, feature)
    }
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

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L700-703)
```text
    public entry fun force_end_epoch(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        reconfiguration_with_dkg::finish(aptos_framework);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L714-718)
```text
    public fun toggle_features(aptos_framework: &signer, enable: vector<u64>, disable: vector<u64>) {
        system_addresses::assert_aptos_framework(aptos_framework);
        features::change_feature_flags_for_next_epoch(aptos_framework, enable, disable);
        reconfigure(aptos_framework);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L24-40)
```text
    public(friend) fun try_start() {
        let incomplete_dkg_session = dkg::incomplete_session();
        if (option::is_some(&incomplete_dkg_session)) {
            let session = option::borrow(&incomplete_dkg_session);
            if (dkg::session_dealer_epoch(session) == reconfiguration::current_epoch()) {
                return
            }
        };
        reconfiguration_state::on_reconfig_start();
        let cur_epoch = reconfiguration::current_epoch();
        dkg::start(
            cur_epoch,
            randomness_config::current(),
            stake::cur_validator_consensus_infos(),
            stake::next_validator_consensus_infos(),
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L46-61)
```text
    public(friend) fun finish(framework: &signer) {
        system_addresses::assert_aptos_framework(framework);
        dkg::try_clear_incomplete_session(framework);
        consensus_config::on_new_epoch(framework);
        execution_config::on_new_epoch(framework);
        gas_schedule::on_new_epoch(framework);
        std::version::on_new_epoch(framework);
        features::on_new_epoch(framework);
        jwk_consensus_config::on_new_epoch(framework);
        jwks::on_new_epoch(framework);
        keyless_account::on_new_epoch(framework);
        randomness_config_seqnum::on_new_epoch(framework);
        randomness_config::on_new_epoch(framework);
        randomness_api_v0_config::on_new_epoch(framework);
        reconfiguration::reconfigure();
    }
```

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1910-1912)
```text
    fun assert_reconfig_not_in_progress() {
        assert!(!reconfiguration_state::is_in_progress(), error::invalid_state(ERECONFIGURATION_IN_PROGRESS));
    }
```
