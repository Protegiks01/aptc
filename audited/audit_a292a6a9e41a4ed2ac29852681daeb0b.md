# Audit Report

## Title
Mismatched Signature Checker Configuration Causes Validator Crash on Scripts with Many Type Parameters

## Summary
A configuration mismatch between two signature checker fixes can cause validators to crash when processing scripts with more than 16 type parameters. The vulnerability occurs when `sig_checker_v2_fix_script_ty_param_count` (controlled by FeatureFlag) is disabled while `sig_checker_v2_fix_function_signatures` (controlled by gas_feature_version) remains enabled, leading to insufficient bitset allocation and a panic during verification.

## Finding Description
The `aptos_prod_verifier_config()` function creates verifier configuration with two independent signature checker fixes controlled by different on-chain parameters: [1](#0-0) 

These two flags can become mismatched through governance actions since they are controlled by different mechanisms:
- `sig_checker_v2_fix_script_ty_param_count` depends on `FeatureFlag::SIGNATURE_CHECKER_V2_SCRIPT_FIX` which can be disabled via governance
- `sig_checker_v2_fix_function_signatures` depends on `gas_feature_version >= RELEASE_V1_34` [2](#0-1) 

When `sig_checker_v2_fix_script_ty_param_count = false`, the script verification logic fails to include `script.type_parameters.len()` in the capacity calculation: [3](#0-2) 

This causes insufficient `BitsetTypeParameterConstraints` allocation. When the verifier later creates an ability context from all script type parameters, it attempts to insert constraints for type parameter indices that exceed the allocated capacity: [4](#0-3) 

The `BitsetTypeParameterConstraints::insert` method has a hard assertion that panics on out-of-bounds access: [5](#0-4) 

**Attack Scenario:**
1. Governance proposal disables `SIGNATURE_CHECKER_V2_SCRIPT_FIX` feature (flag 29) while `gas_feature_version` stays >= 38
2. Attacker submits a transaction containing a script with >16 type parameters (e.g., 20 type parameters: `<T0, T1, ..., T19>`)
3. Most type parameters are unused in signatures, so `max_num_of_ty_params_or_args()` returns ≤16
4. Verifier allocates `BitsetTypeParameterConstraints<1>` (capacity: 16 parameters)
5. During verification, `BitsetTypeParameterConstraints::from()` attempts to create context for all 20 parameters
6. Insert operation panics when processing type parameter index ≥16
7. **Validator process crashes**

## Impact Explanation
**Critical Severity - Total Loss of Network Liveness ($1,000,000 category)**

This vulnerability causes a complete network halt:
- All validators with the mismatched configuration will crash when processing the malicious script
- The network cannot progress as validators repeatedly crash on the same transaction in the mempool
- Recovery requires emergency governance intervention to fix the configuration mismatch
- Meets "Total loss of liveness/network availability" criteria from the Aptos bug bounty program

The vulnerability breaks the **Deterministic Execution** invariant - validators should either accept or reject transactions uniformly, not crash. It also violates **Move VM Safety** by causing unhandled panics instead of proper error handling.

## Likelihood Explanation
**Medium-High Likelihood**

The vulnerability can be triggered in several realistic scenarios:

1. **Governance Configuration Error**: Administrators might disable `SIGNATURE_CHECKER_V2_SCRIPT_FIX` for testing or rollback purposes while forgetting that `gas_feature_version` remains at a high value. The feature flag system explicitly allows disabling flags: [6](#0-5) 

2. **Upgrade Race Condition**: During coordinated upgrades, different validators might temporarily have different configurations at epoch boundaries

3. **Malicious Governance**: An attacker with governance access could deliberately create this state to DoS the network

The attack itself is trivial - any user can submit a script transaction with many type parameters. The `SIGNATURE_CHECKER_V2_SCRIPT_FIX` flag is marked as "transient" and has no prevention against being disabled: [7](#0-6) 

## Recommendation
Implement configuration consistency validation to prevent mismatched states:

1. **Add Configuration Validation**: In `aptos_prod_verifier_config()`, add a check that enforces: if `gas_feature_version >= RELEASE_V1_34`, then `SIGNATURE_CHECKER_V2_SCRIPT_FIX` must be enabled.

2. **Make Flag Non-Disableable**: Mark `SIGNATURE_CHECKER_V2_SCRIPT_FIX` as permanently enabled by returning an error on disable attempts (similar to `AGGREGATOR_V2_API` flag).

3. **Safe Degradation**: Modify `verify_script()` to always include `script.type_parameters.len()` in max_num calculation regardless of the flag state, treating the flag as optimization-only.

**Fixed Code Approach (Option 3 - Safest):**
```rust
pub fn verify_script(config: &VerifierConfig, script: &CompiledScript) -> VMResult<()> {
    let mut max_num = max_num_of_ty_params_or_args(BinaryIndexedView::Script(script));
    // Always account for script type parameters to prevent crashes
    // Even if the fix flag is disabled, this ensures safety
    max_num = max_num.max(script.type_parameters.len());
    
    // Rest of function...
}
```

## Proof of Concept

**Move Script (malicious_script.move):**
```move
script {
    fun main<T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19>() {
        // Declare 20 type parameters but only use T0
        // This ensures max_num_of_ty_params_or_args returns 1
        let _x: vector<T0> = vector::empty<T0>();
    }
}
```

**Reproduction Steps:**
1. Set up Aptos testnet with governance access
2. Submit governance proposal to disable feature flag 29:
   ```move
   features::change_feature_flags_for_next_epoch(@std, vector[], vector[29]);
   ```
3. Wait for epoch boundary for change to take effect
4. Verify configuration state: `sig_checker_v2_fix_script_ty_param_count = false`, `gas_feature_version >= 38`
5. Compile and submit the malicious script transaction
6. Observe validator crash with panic: "Type parameter index out of bounds"

**Expected Result:** Validator crashes with assertion failure when processing the script.

**Validation:** Check validator logs for panic in `BitsetTypeParameterConstraints::insert` at the specified assertion.

### Citations

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L145-149)
```rust
pub fn aptos_prod_verifier_config(gas_feature_version: u64, features: &Features) -> VerifierConfig {
    let sig_checker_v2_fix_script_ty_param_count =
        features.is_enabled(FeatureFlag::SIGNATURE_CHECKER_V2_SCRIPT_FIX);
    let sig_checker_v2_fix_function_signatures = gas_feature_version >= RELEASE_V1_34;
    let enable_enum_types = features.is_enabled(FeatureFlag::ENABLE_ENUM_TYPES);
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L271-273)
```text
    /// Whether the fix for a counting bug in the script path of the signature checker pass is enabled.
    /// Lifetime: transient
    const SIGNATURE_CHECKER_V2_SCRIPT_FIX: u64 = 29;
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

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L874-881)
```text
    fun apply_diff(features: &mut vector<u8>, enable: vector<u64>, disable: vector<u64>) {
        enable.for_each(|feature| {
            set(features, feature, true);
        });
        disable.for_each(|feature| {
            set(features, feature, false);
        });
    }
```

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L70-77)
```rust
    fn insert(&mut self, ty_param_idx: TypeParameterIndex, required_abilities: AbilitySet) {
        assert!(
            (ty_param_idx as usize) < N * NUM_PARAMS_PER_WORD,
            "Type parameter index out of bounds. \
             The current Bitset implementation is only configured to handle \
             {} type parameters at max.",
            N * NUM_PARAMS_PER_WORD
        );
```

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L1190-1195)
```rust
    checker.verify_signature_in_context(
        &BitsetTypeParameterConstraints::from(script.type_parameters.as_slice()),
        script.parameters,
        // Script parameters can be signer references.
        true,
    )?;
```

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L1273-1277)
```rust
pub fn verify_script(config: &VerifierConfig, script: &CompiledScript) -> VMResult<()> {
    let mut max_num = max_num_of_ty_params_or_args(BinaryIndexedView::Script(script));
    if config.sig_checker_v2_fix_script_ty_param_count {
        max_num = max_num.max(script.type_parameters.len());
    }
```
